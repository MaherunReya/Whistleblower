/**
 * Registration / login / 2FA verification.
 * Password hashing: from-scratch salted+iterated SHA-256 (crypto/hash.js) —
 * no bcrypt, no Node `crypto` hash functions, consistent with the rest of
 * this project's from-scratch rule.
 */
import { authenticator } from "otplib";
import { hashPassword, verifyPassword } from "../crypto/hash.js";
import { encryptPlatformField } from "../crypto/keyManager.js";
import { createSessionToken } from "../middleware/auth.js";
import { computeMAC, verifyMAC } from "../crypto/mac.js";
import User from "../models/User.js";

const PENDING_2FA_TTL_MS = 5 * 60 * 1000; // 5 minutes to enter the TOTP code

function setSessionCookie(res, token, ttlMs) {
  res.cookie("session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: ttlMs,
  });
}

export async function register(req, res) {
  try {
    const { username, password, email, contactInfo } = req.body;
    if (!username || !password || !email) {
      return res.status(400).json({ error: "username, password, and email are required" });
    }

    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ error: "Username already taken" });

    // 1. hash + salt password (from-scratch)
    const { hash, salt } = hashPassword(password);

    // 2. encrypt PII before storing (RSA, via the platform keypair)
    const emailEncrypted = await encryptPlatformField(email);
    const contactInfoEncrypted = await encryptPlatformField(contactInfo ?? null);

    // 3. Self-registration always creates a "reporter" — reviewer/admin
    //    accounts are provisioned separately by an admin (adminController),
    //    which also runs provisionKeysForReviewer for them. This prevents
    //    a client from just POSTing { role: "admin" } to escalate privilege.
    const user = await User.create({
      username,
      passwordHash: hash,
      passwordSalt: salt,
      emailEncrypted,
      contactInfoEncrypted,
      role: "reporter",
    });

    res.status(201).json({
      id: user._id,
      username: user.username,
      role: user.role,
    });
  } catch (err) {
    res.status(500).json({ error: "Registration failed", details: err.message });
  }
}

export async function login(req, res) {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required" });
    }

    const user = await User.findOne({ username });
    // Same error for "no such user" and "wrong password" — don't leak which one
    if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    if (user.is2FAEnabled) {
      // Don't issue a full session yet — issue a short-lived, MAC-signed
      // "pending" token that only proves password step passed, and only
      // identifies which user must now supply a TOTP code.
      const pendingToken = createSessionToken(
        { sub: user._id.toString(), stage: "pending2fa" },
        PENDING_2FA_TTL_MS
      );
      return res.json({ requires2FA: true, pendingToken });
    }

    const sessionToken = createSessionToken({
      sub: user._id.toString(),
      username: user.username,
      role: user.role,
    });
    setSessionCookie(res, sessionToken);
    res.json({ id: user._id, username: user.username, role: user.role, is2FAEnabled: user.is2FAEnabled });
  } catch (err) {
    res.status(500).json({ error: "Login failed", details: err.message });
  }
}

export async function verify2FA(req, res) {
  try {
    const { pendingToken, code } = req.body;
    if (!pendingToken || !code) {
      return res.status(400).json({ error: "pendingToken and code are required" });
    }

    const [payloadB64, tag] = pendingToken.split(".");
    if (!payloadB64 || !tag || !verifyMAC(payloadB64, process.env.SESSION_SECRET, tag)) {
      return res.status(401).json({ error: "Invalid or expired pending token" });
    }
    const payload = JSON.parse(Buffer.from(payloadB64, "base64").toString());
    if (payload.stage !== "pending2fa" || payload.exp < Date.now()) {
      return res.status(401).json({ error: "Invalid or expired pending token" });
    }

    const user = await User.findById(payload.sub);
    if (!user || !user.is2FAEnabled || !user.totpSecret) {
      return res.status(401).json({ error: "2FA not set up for this account" });
    }

    const valid = authenticator.verify({ token: code, secret: user.totpSecret });
    if (!valid) return res.status(401).json({ error: "Invalid 2FA code" });

    const sessionToken = createSessionToken({
      sub: user._id.toString(),
      username: user.username,
      role: user.role,
    });
    setSessionCookie(res, sessionToken);
    res.json({ id: user._id, username: user.username, role: user.role, is2FAEnabled: user.is2FAEnabled });
  } catch (err) {
    res.status(500).json({ error: "2FA verification failed", details: err.message });
  }
}

/**
 * Start enabling 2FA for the currently logged-in user (reviewers/admins
 * should call this right after their account is provisioned). Returns an
 * otpauth:// URL the client turns into a QR code. The secret is stashed in
 * totpSecretPending — it does NOT become active, and is2FAEnabled stays
 * false, until the user proves they scanned it correctly via confirm2FA.
 */
export async function setup2FA(req, res) {
  try {
    const secret = authenticator.generateSecret();
    const user = await User.findByIdAndUpdate(
      req.user.sub,
      { totpSecretPending: secret },
      { new: true }
    );
    const otpauthUrl = authenticator.keyuri(user.username, "WhistleblowerTool", secret);
    res.json({ otpauthUrl });
  } catch (err) {
    res.status(500).json({ error: "2FA setup failed", details: err.message });
  }
}

/**
 * Confirm 2FA setup: the user submits a code generated from the pending
 * secret. Only on success does the secret become active and 2FA get
 * actually enforced on future logins.
 */
export async function confirm2FA(req, res) {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "code is required" });

    const user = await User.findById(req.user.sub);
    if (!user?.totpSecretPending) {
      return res.status(400).json({ error: "No pending 2FA setup — call setup-2fa first" });
    }

    const valid = authenticator.verify({ token: code, secret: user.totpSecretPending });
    if (!valid) return res.status(401).json({ error: "Invalid 2FA code" });

    user.totpSecret = user.totpSecretPending;
    user.totpSecretPending = undefined;
    user.is2FAEnabled = true;
    await user.save();

    res.json({ ok: true, is2FAEnabled: true });
  } catch (err) {
    res.status(500).json({ error: "2FA confirmation failed", details: err.message });
  }
}

/** Restores a session on page load/refresh — the client calls this once on
 *  mount to find out who's logged in (if anyone) without re-submitting credentials. */
export async function getMe(req, res) {
  try {
    const user = await User.findById(req.user.sub).select("username role is2FAEnabled");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ id: user._id, username: user.username, role: user.role, is2FAEnabled: user.is2FAEnabled });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch current user", details: err.message });
  }
}

export async function logout(req, res) {
  res.clearCookie("session");
  res.json({ ok: true });
}