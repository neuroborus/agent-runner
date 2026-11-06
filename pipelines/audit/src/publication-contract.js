import { createHash } from "node:crypto";
import { join } from "node:path";

import {
  assertAudit,
  exact,
  fingerprint,
  isHash,
  same,
} from "./discovery-contract.js";
import { acceptsCleanDiscovery } from "./cycles.js";
import { normalizeAuditReport } from "./findings.js";
import { renderAuditReport } from "./report.js";

export const REPORT_FILENAME = "audit.md";
// Match the Runner artifact publisher without importing root runtime policy.
const MAX_REPORT_BYTES = 32 * 1024 * 1024;
export const reportPaths = (taskPath) => [
  join(taskPath, REPORT_FILENAME),
  join(taskPath, `.${REPORT_FILENAME}.tmp`),
];

/** Only the current, exactly accepted version may appear as confirmed. */
export function projectAuditReport(state) {
  const findings = [];
  const hypotheses = new Map(
    state.report.hypotheses.map((item) => [item.id, item]),
  );
  const pending = [];
  for (const entry of state.ledger) {
    const receipt = state.acceptedBatches.findLast(({ batch }) =>
      batch.entries.some((item) => same(item, entry)),
    );
    const disposition = receipt?.batch.dispositions.find(
      ({ id }) => id === entry.finding.id,
    );
    const awaiting = state.pendingBatch?.entries.some(
      ({ finding }) => finding.id === entry.finding.id,
    );
    if (awaiting || !disposition) {
      pending.push(entry.finding);
      hypotheses.delete(entry.finding.id);
    } else if (["confirm", "correct"].includes(disposition.kind)) {
      findings.push(entry.finding);
      hypotheses.delete(entry.finding.id);
    } else if (disposition.kind === "hypothesis")
      hypotheses.set(entry.finding.id, disposition.hypothesis);
    else hypotheses.delete(entry.finding.id);
  }
  return {
    report: normalizeAuditReport({
      ...state.report,
      findings,
      hypotheses: [...hypotheses.values()],
    }),
    pending,
  };
}

export function publicationContent(state) {
  const { report, pending } = projectAuditReport(state);
  const complete =
    state.history.at(-1)?.outcome === "clean" &&
    acceptsCleanDiscovery(state) &&
    state.pendingBatch === null;
  const content = renderAuditReport(report, {
    status: complete ? "complete" : "in-progress",
    pending,
    exclusions: state.inputs.exclusions,
    references: state.inputs.references,
    sourceScope: state.settings.sourceScope,
    excludePaths: state.settings.excludePaths ?? [],
  });
  assertAudit(
    Buffer.byteLength(content) <= MAX_REPORT_BYTES,
    "Audit report exceeds the 32-MiB publication limit.",
  );
  return {
    content,
    binding: {
      snapshotFingerprint: state.repositoryBaseline.contentFingerprint,
      reportFingerprint: fingerprint({
        report,
        pending,
        inputs: state.inputsFingerprint,
        ...(state.settings.sourceScope === undefined
          ? {}
          : {
              sourceSelection: {
                sourceScope: state.settings.sourceScope,
                excludePaths: state.settings.excludePaths,
                fingerprint:
                  state.repositoryBaseline.sourceSelection?.fingerprint ?? null,
              },
            }),
      }),
      contentHash: createHash("sha256").update(content).digest("hex"),
      complete,
    },
  };
}

export function assertPublication(run) {
  const { publication, workflowState } = run.pipelineState;
  exact(publication, ["pending", "published", "temporary"]);
  if (publication.temporary !== null) {
    exact(publication.temporary, ["phase", "identity"]);
    const { phase, identity } = publication.temporary;
    exact(identity, ["device", "inode", "mode", "birthtimeNs"]);
    assertAudit(
      publication.pending !== null &&
        ["writing", "prepared"].includes(phase) &&
        Object.values(identity).every(
          (value) => typeof value === "string" && /^\d{1,30}$/u.test(value),
        ),
      "Invalid audit publication temporary ownership.",
    );
  }
  for (const record of [publication.pending, publication.published]) {
    if (record === null) continue;
    exact(record, [
      "snapshotFingerprint",
      "reportFingerprint",
      "contentHash",
      "complete",
    ]);
    assertAudit(
      isHash(record.snapshotFingerprint) &&
        isHash(record.reportFingerprint) &&
        isHash(record.contentHash) &&
        typeof record.complete === "boolean",
      "Invalid audit publication binding.",
    );
    assertAudit(
      record.snapshotFingerprint ===
        run.pipelineState.repositoryBaseline?.contentFingerprint,
      "Audit publication snapshot changed.",
    );
  }
  if (publication.pending !== null)
    assertAudit(
      same(publication.pending, publicationContent(run.pipelineState).binding),
      "Pending audit publication is stale.",
    );
  if (workflowState === "DONE")
    assertAudit(
      publication.pending === null &&
        publication.published?.complete === true &&
        same(
          publication.published,
          publicationContent(run.pipelineState).binding,
        ),
      "Audit completion requires the exact published report.",
    );
}
