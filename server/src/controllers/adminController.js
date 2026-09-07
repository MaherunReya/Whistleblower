/**
 * Admin-only: create reviewers, rotate their keys, view audit logs.
 * Admin must NOT be able to decrypt report content — enforced by never
 * routing report private keys through any admin-accessible endpoint (only
 * reportController ever calls getPrivateKeysForDecryption).
 */
import User from "../models/User.js";
import AuditLog from "../models/AuditLog.js";
import Report from "../models/Report.js";
import { hashPassword } from "../crypto/hash.js";
import { encryptPlatformField, provisionKeysForReviewer, rotateKeys } from "../crypto/keyManager.js";
import { appendChainedEntry } from "../crypto/mac.js";

const GENESIS_MAC = "GENESIS";

function getAuditMacSecret() {
  const secret = process.env.AUDIT_LOG_SECRET;
  if (!secret) {
    throw new Error("AUDIT_LOG_SECRET is not set in .env — required to MAC-chain the audit log");
  }
  return secret;
}

/** Appends one MAC-chained audit entry. Chained the same way as
 *  Report.statusLog: each entry's MAC covers the previous entry's MAC plus
 *  its own contents, so no entry can be edited, deleted, or reordered
 *  afterward without breaking the chain from that point on. */
/** Appends one MAC-chained audit entry — exported so other controllers
 *  (e.g. report reassignment) can log into the same tamper-evident chain. */
export async function logAudit(action, performedBy, targetId, details) {
  const last = await AuditLog.findOne().sort({ timestamp: -1 });
  const previousMac = last ? last.mac : GENESIS_MAC;

  const { entry, mac } = appendChainedEntry(
    previousMac,
    { action, performedBy, targetId, details, timestamp: new Date().toISOString() },
    getAuditMacSecret()
  );

  await AuditLog.create({
    action: entry.action,
    performedBy: entry.performedBy,
    targetId: entry.targetId,
    details: entry.details,
    mac,
    timestamp: entry.timestamp,
  });
}

export async function createReviewer(req, res) {
  try {
    const { username, password, email, contactInfo } = req.body;
    if (!username || !password || !email) {
      return res.status(400).json({ error: "username, password, and email are required" });
    }

    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ error: "Username already taken" });

    const { hash, salt } = hashPassword(password);
    const emailEncrypted = await encryptPlatformField(email);
    const contactInfoEncrypted = await encryptPlatformField(contactInfo ?? null);

    const user = await User.create({
      username,
      passwordHash: hash,
      passwordSalt: salt,
      emailEncrypted,
      contactInfoEncrypted,
      role: "reviewer",
      // Admin knows this initial password, so force the reviewer to set
      // their own on first login.
      mustChangePassword: true,
    });

    // Every reviewer needs their own RSA + ECC keypair before any report
    // can be assigned to them.
    await provisionKeysForReviewer(user._id.toString());

    await logAudit("REVIEWER_CREATED", req.user.sub, user._id, { username });

    res.status(201).json({ id: user._id, username: user.username, role: user.role });
  } catch (err) {
    res.status(500).json({ error: "Failed to create reviewer", details: err.message });
  }
}

/** So the admin doesn't have to know a reviewer's Mongo _id by heart —
 *  needed both for the "rotate keys" form and for report reassignment. */
export async function listReviewers(req, res) {
  try {
    const reviewers = await User.find({ role: "reviewer" }).select("username createdAt").sort({ username: 1 });

    const counts = await Report.aggregate([
      { $match: { status: { $in: ["Open", "Investigating"] } } },
      { $group: { _id: "$assignedReviewer", count: { $sum: 1 } } },
    ]);
    const countMap = new Map(counts.map((c) => [String(c._id), c.count]));

    res.json(
      reviewers.map((r) => ({
        id: r._id,
        username: r.username,
        createdAt: r.createdAt,
        openReportCount: countMap.get(String(r._id)) ?? 0,
      }))
    );
  } catch (err) {
    res.status(500).json({ error: "Failed to list reviewers", details: err.message });
  }
}

export async function rotateReviewerKeys(req, res) {
  try {
    const { id } = req.params;
    const reviewer = await User.findOne({ _id: id, role: "reviewer" });
    if (!reviewer) return res.status(404).json({ error: "Reviewer not found" });

    const { rsaPublicKey, eccPublicKey } = await rotateKeys(id);
    await logAudit("KEYS_ROTATED", req.user.sub, reviewer._id, {});

    res.json({
      id: reviewer._id,
      rsaPublicKey: { e: rsaPublicKey.e.toString(), n: rsaPublicKey.n.toString() },
      eccPublicKey: { x: eccPublicKey.x.toString(), y: eccPublicKey.y.toString() },
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to rotate reviewer keys", details: err.message });
  }
}

export async function getAuditLogs(req, res) {
  try {
    const logs = await AuditLog.find().sort({ timestamp: 1 });

    // Walk the chain to prove nothing in the log was edited, deleted, or
    // reordered after the fact.
    let previousMac = GENESIS_MAC;
    let chainIntact = true;
    let brokenAt = null;

    const verified = logs.map((log) => {
      const expectedMac = appendChainedEntry(
        previousMac,
        {
          action: log.action,
          performedBy: log.performedBy ? String(log.performedBy) : null,
          targetId: log.targetId ? String(log.targetId) : null,
          details: log.details,
          timestamp: log.timestamp.toISOString(),
        },
        getAuditMacSecret()
      ).mac;

      const macValid = expectedMac === log.mac;
      if (!macValid && chainIntact) {
        chainIntact = false;
        brokenAt = log._id;
      }
      previousMac = log.mac; // keep walking so every entry gets checked, not just the first break

      return { ...log.toObject(), macValid };
    });

    res.json({ chainIntact, brokenAt, logs: verified });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch audit logs", details: err.message });
  }
}