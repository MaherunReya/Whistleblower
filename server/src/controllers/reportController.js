/**
 * Report submission, status lookup by tracking ID, reviewer read/update.
 *
 * MAC strategy: the integrity tag is computed over the CIPHERTEXT bundle
 * (not the plaintext), using a server-wide secret (REPORT_INTEGRITY_SECRET).
 * That means tampering with a stored report can be detected on every read
 * without needing the reviewer's private key at all — useful for e.g. an
 * admin integrity sweep that should never be able to decrypt content.
 */
import Report from "../models/Report.js";
import User from "../models/User.js";
import * as rsa from "../crypto/rsa.js";
import * as ecc from "../crypto/ecc.js";
import { computeMAC, verifyMAC, appendChainedEntry } from "../crypto/mac.js";
import { generateTrackingId } from "../utils/trackingId.js";
import { getPublicKeysWithVersion, getPrivateKeysForDecryption } from "../crypto/keyManager.js";
import { logAudit } from "./adminController.js";

const GENESIS_MAC = "GENESIS";
const STATUSES = ["Open", "Investigating", "Resolved"];

function getReportMacSecret() {
  const secret = process.env.REPORT_INTEGRITY_SECRET;
  if (!secret) {
    throw new Error(
      "REPORT_INTEGRITY_SECRET is not set in .env — required to MAC report ciphertext"
    );
  }
  return secret;
}

/** Fixed field order so the MAC is reproducible on every read. */
function macPayload(fields) {
  return [
    fields.trackingId,
    fields.titleEncrypted,
    fields.descriptionEncrypted,
    fields.categoryEncrypted || "",
    fields.evidenceEncrypted || "",
    fields.reporterIdentityEncrypted || "",
  ].join("|");
}

/** Auto-assignment: give the new report to whichever reviewer currently has
 *  the fewest open (Open/Investigating) reports on their plate. */
async function pickLeastLoadedReviewer() {
  const reviewers = await User.find({ role: "reviewer" }).select("_id");
  if (reviewers.length === 0) return null;

  const counts = await Report.aggregate([
    { $match: { status: { $in: ["Open", "Investigating"] } } },
    { $group: { _id: "$assignedReviewer", count: { $sum: 1 } } },
  ]);
  const countMap = new Map(counts.map((c) => [String(c._id), c.count]));

  let best = reviewers[0];
  let bestCount = countMap.get(String(best._id)) ?? 0;
  for (const r of reviewers.slice(1)) {
    const c = countMap.get(String(r._id)) ?? 0;
    if (c < bestCount) {
      best = r;
      bestCount = c;
    }
  }
  return best._id;
}

export async function submitReport(req, res) {
  try {
    const { title, description, category, evidence, identity, assignedReviewerId } = req.body;
    if (!title || !description) {
      return res.status(400).json({ error: "title and description are required" });
    }

    let reviewerId = assignedReviewerId;
    if (reviewerId) {
      const reviewer = await User.findOne({ _id: reviewerId, role: "reviewer" });
      if (!reviewer) {
        return res.status(400).json({ error: "assignedReviewerId is not a valid reviewer" });
      }
    } else {
      reviewerId = await pickLeastLoadedReviewer();
      if (!reviewerId) {
        return res.status(503).json({ error: "No reviewers are currently available" });
      }
    }

    const keys = await getPublicKeysWithVersion(reviewerId);
    if (!keys) {
      return res.status(503).json({ error: "Assigned reviewer has no active encryption keys" });
    }
    const { rsaPublicKey, eccPublicKey, version } = keys;

    const trackingId = generateTrackingId();

    // Title/description/category/evidence: RSA (algorithm #1)
    const titleEncrypted = rsa.encrypt(title, rsaPublicKey);
    const descriptionEncrypted = rsa.encrypt(description, rsaPublicKey);
    const categoryEncrypted = category ? rsa.encrypt(category, rsaPublicKey) : undefined;
    const evidenceEncrypted = evidence ? rsa.encrypt(evidence, rsaPublicKey) : undefined;

    // Reporter identity: ECC (algorithm #2) — kept separate so a compromised
    // reviewer RSA key alone can never unmask who filed the report.
    const reporterIdentityEncrypted = identity ? ecc.encrypt(identity, eccPublicKey) : null;

    const mac = computeMAC(
      macPayload({
        trackingId,
        titleEncrypted,
        descriptionEncrypted,
        categoryEncrypted,
        evidenceEncrypted,
        reporterIdentityEncrypted,
      }),
      getReportMacSecret()
    );

    await Report.create({
      trackingId,
      titleEncrypted,
      descriptionEncrypted,
      categoryEncrypted,
      evidenceEncrypted,
      reporterIdentityEncrypted,
      mac,
      assignedReviewer: reviewerId,
      reviewerKeyVersion: version,
      status: "Open",
    });

    // Shown to the reporter exactly once — there's no login to recover it
    // from later, so the client must prompt them to save it.
    res.status(201).json({ trackingId });
  } catch (err) {
    res.status(500).json({ error: "Failed to submit report", details: err.message });
  }
}

export async function getReportByTrackingId(req, res) {
  try {
    const { trackingId } = req.params;
    const report = await Report.findOne({ trackingId }).select(
      "status createdAt updatedAt statusLog.status statusLog.timestamp"
    );
    if (!report) return res.status(404).json({ error: "No report found for that tracking ID" });

    // Only status + timestamps — never decrypted content, per spec.
    res.json({
      status: report.status,
      submittedAt: report.createdAt,
      lastUpdatedAt: report.updatedAt,
      history: report.statusLog.map((entry) => ({
        status: entry.status,
        timestamp: entry.timestamp,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to look up report", details: err.message });
  }
}

export async function getAssignedReports(req, res) {
  try {
    const reports = await Report.find({ assignedReviewer: req.user.sub }).sort({ createdAt: -1 });

    const results = [];
    for (const report of reports) {
      const macValid = verifyMAC(
        macPayload({
          trackingId: report.trackingId,
          titleEncrypted: report.titleEncrypted,
          descriptionEncrypted: report.descriptionEncrypted,
          categoryEncrypted: report.categoryEncrypted,
          evidenceEncrypted: report.evidenceEncrypted,
          reporterIdentityEncrypted: report.reporterIdentityEncrypted,
        }),
        getReportMacSecret(),
        report.mac
      );

      if (!macValid) {
        // Surface tampering rather than silently decrypting suspect data.
        results.push({
          id: report._id,
          trackingId: report.trackingId,
          status: report.status,
          integrityError: "MAC verification failed — this report may have been tampered with",
        });
        continue;
      }

      const { rsaPrivateKey, eccPrivateKey } = await getPrivateKeysForDecryption(
        req.user.sub,
        report.reviewerKeyVersion
      );

      const title = rsa.decrypt(report.titleEncrypted, rsaPrivateKey);
      const description = rsa.decrypt(report.descriptionEncrypted, rsaPrivateKey);
      const category = report.categoryEncrypted
        ? rsa.decrypt(report.categoryEncrypted, rsaPrivateKey)
        : null;
      const evidence = report.evidenceEncrypted
        ? rsa.decrypt(report.evidenceEncrypted, rsaPrivateKey)
        : null;
      const identity = report.reporterIdentityEncrypted
        ? ecc.decrypt(report.reporterIdentityEncrypted, eccPrivateKey)
        : null;

      report.readReceipts.push({ reviewer: req.user.sub, openedAt: new Date() });
      await report.save();

      results.push({
        id: report._id,
        trackingId: report.trackingId,
        status: report.status,
        title,
        description,
        category,
        evidence,
        identity, // null when submitted anonymously
        createdAt: report.createdAt,
      });
    }

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch assigned reports", details: err.message });
  }
}

export async function updateReportStatus(req, res) {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!STATUSES.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${STATUSES.join(", ")}` });
    }

    const report = await Report.findById(id);
    if (!report) return res.status(404).json({ error: "Report not found" });

    if (String(report.assignedReviewer) !== String(req.user.sub)) {
      return res.status(403).json({ error: "You are not the assigned reviewer for this report" });
    }

    const previousMac =
      report.statusLog.length > 0 ? report.statusLog[report.statusLog.length - 1].mac : GENESIS_MAC;

    const { entry, mac } = appendChainedEntry(
      previousMac,
      {
        reportId: String(report._id),
        newStatus: status,
        changedBy: req.user.sub,
        timestamp: new Date().toISOString(),
      },
      getReportMacSecret()
    );

    report.status = status;
    report.statusLog.push({
      status: entry.newStatus,
      changedBy: entry.changedBy,
      timestamp: entry.timestamp,
      mac,
    });
    await report.save();

    res.json({ id: report._id, status: report.status, statusLog: report.statusLog });
  } catch (err) {
    res.status(500).json({ error: "Failed to update report status", details: err.message });
  }
}

/**
 * Admin-only reassignment. Decrypts under the OLD reviewer's private key
 * and re-encrypts under the NEW reviewer's public key, entirely server-side
 * — the plaintext is never included in this endpoint's response, so the
 * admin triggering a reassignment still never gets to read report content.
 */
export async function reassignReport(req, res) {
  try {
    const { id } = req.params;
    const { reviewerId } = req.body;
    if (!reviewerId) return res.status(400).json({ error: "reviewerId is required" });

    const report = await Report.findById(id);
    if (!report) return res.status(404).json({ error: "Report not found" });

    const newReviewer = await User.findOne({ _id: reviewerId, role: "reviewer" });
    if (!newReviewer) return res.status(400).json({ error: "reviewerId is not a valid reviewer" });

    if (String(report.assignedReviewer) === String(reviewerId)) {
      return res.status(400).json({ error: "Report is already assigned to this reviewer" });
    }

    const macValid = verifyMAC(
      macPayload({
        trackingId: report.trackingId,
        titleEncrypted: report.titleEncrypted,
        descriptionEncrypted: report.descriptionEncrypted,
        categoryEncrypted: report.categoryEncrypted,
        evidenceEncrypted: report.evidenceEncrypted,
        reporterIdentityEncrypted: report.reporterIdentityEncrypted,
      }),
      getReportMacSecret(),
      report.mac
    );
    if (!macValid) {
      return res.status(409).json({ error: "Cannot reassign — report failed integrity verification" });
    }

    const { rsaPrivateKey: oldRsaPriv, eccPrivateKey: oldEccPriv } = await getPrivateKeysForDecryption(
      report.assignedReviewer,
      report.reviewerKeyVersion
    );

    const title = rsa.decrypt(report.titleEncrypted, oldRsaPriv);
    const description = rsa.decrypt(report.descriptionEncrypted, oldRsaPriv);
    const category = report.categoryEncrypted ? rsa.decrypt(report.categoryEncrypted, oldRsaPriv) : null;
    const evidence = report.evidenceEncrypted ? rsa.decrypt(report.evidenceEncrypted, oldRsaPriv) : null;
    const identity = report.reporterIdentityEncrypted
      ? ecc.decrypt(report.reporterIdentityEncrypted, oldEccPriv)
      : null;

    const newKeys = await getPublicKeysWithVersion(reviewerId);
    if (!newKeys) return res.status(503).json({ error: "New reviewer has no active encryption keys" });

    report.titleEncrypted = rsa.encrypt(title, newKeys.rsaPublicKey);
    report.descriptionEncrypted = rsa.encrypt(description, newKeys.rsaPublicKey);
    report.categoryEncrypted = category ? rsa.encrypt(category, newKeys.rsaPublicKey) : undefined;
    report.evidenceEncrypted = evidence ? rsa.encrypt(evidence, newKeys.rsaPublicKey) : undefined;
    report.reporterIdentityEncrypted = identity ? ecc.encrypt(identity, newKeys.eccPublicKey) : null;
    report.reviewerKeyVersion = newKeys.version;

    report.mac = computeMAC(
      macPayload({
        trackingId: report.trackingId,
        titleEncrypted: report.titleEncrypted,
        descriptionEncrypted: report.descriptionEncrypted,
        categoryEncrypted: report.categoryEncrypted,
        evidenceEncrypted: report.evidenceEncrypted,
        reporterIdentityEncrypted: report.reporterIdentityEncrypted,
      }),
      getReportMacSecret()
    );

    const previousReviewer = report.assignedReviewer;
    report.assignedReviewer = reviewerId;
    await report.save();

    await logAudit("REPORT_REASSIGNED", req.user.sub, report._id, {
      from: String(previousReviewer),
      to: String(reviewerId),
    });

    res.json({ id: report._id, trackingId: report.trackingId, assignedReviewer: reviewerId });
  } catch (err) {
    res.status(500).json({ error: "Failed to reassign report", details: err.message });
  }
}