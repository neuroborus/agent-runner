import { acceptsCleanRecheck, recheckRole } from "./cycles.js";
import { assertCorrectionFeedback } from "./correction-feedback.js";
import {
  assertAudit,
  assertAuditResult,
  assertDiscoveryRun,
  exact,
  fingerprint,
  isHash,
  same,
  sessionContextKey,
} from "./discovery-contract.js";
import {
  normalizeAuditReport,
  normalizeFinding,
  normalizeHypothesis,
  text,
} from "./findings.js";
import { assertPublication } from "./publication-contract.js";

const KINDS = ["confirm", "correct", "reject", "merge", "hypothesis"];
const OUTCOMES = [
  "running",
  "interrupted",
  "invalid",
  "incomplete",
  "corrected",
  "clean",
];

function normalizeDecision(value, entry, path = "recheck.decisions[0]") {
  exact(
    value,
    ["id", "kind", "rationale", "finding", "targetId", "hypothesis"],
    path,
  );
  assertAuditResult(
    value.id === entry.finding.id,
    `${path}.id`,
    "candidate-mismatch",
  );
  assertAuditResult(
    KINDS.includes(value.kind),
    `${path}.kind`,
    "unsupported-value",
  );
  const rationale = text(value.rationale, `${path}.rationale`);
  let finding = null;
  let hypothesis = null;
  if (value.kind === "correct") {
    finding = normalizeFinding(value.finding, `${path}.finding`);
    assertAuditResult(
      finding.id === value.id && finding.causeId === entry.finding.causeId,
      `${path}.finding`,
      "identity-mismatch",
    );
  } else
    assertAuditResult(
      value.finding === null,
      `${path}.finding`,
      "invalid-payload",
    );
  if (value.kind === "hypothesis") {
    hypothesis = normalizeHypothesis(value.hypothesis, `${path}.hypothesis`);
    assertAuditResult(
      hypothesis.id === value.id,
      `${path}.hypothesis.id`,
      "identity-mismatch",
    );
  } else
    assertAuditResult(
      value.hypothesis === null,
      `${path}.hypothesis`,
      "invalid-payload",
    );
  assertAuditResult(
    value.kind === "merge"
      ? typeof value.targetId === "string" && value.targetId !== value.id
      : value.targetId === null,
    `${path}.targetId`,
    "invalid-merge",
  );
  return {
    id: value.id,
    kind: value.kind,
    rationale,
    finding,
    targetId: value.targetId,
    hypothesis,
  };
}

function assertBatch(state, batch) {
  exact(batch, [
    "sourcePass",
    "snapshotFingerprint",
    "reportFingerprint",
    "entries",
    "version",
    "dispositions",
  ]);
  assertAudit(
    Number.isSafeInteger(batch.sourcePass) &&
      state.history[batch.sourcePass - 1]?.outcome === "findings" &&
      batch.snapshotFingerprint ===
        state.repositoryBaseline.contentFingerprint &&
      isHash(batch.reportFingerprint) &&
      Number.isSafeInteger(batch.version) &&
      batch.version > 0 &&
      batch.version <= state.recheckHistory.length + 1 &&
      Array.isArray(batch.entries) &&
      batch.entries.length > 0 &&
      Array.isArray(batch.dispositions),
    "Audit finding batch provenance is invalid.",
  );
  const ids = new Set();
  for (const entry of batch.entries) {
    exact(entry, ["finding", "version", "sourcePass"]);
    assertAudit(
      same(entry.finding, normalizeFinding(entry.finding)) &&
        !ids.has(entry.finding.id) &&
        Number.isSafeInteger(entry.version) &&
        entry.version > 0 &&
        Number.isSafeInteger(entry.sourcePass) &&
        entry.sourcePass > 0 &&
        entry.sourcePass <= batch.sourcePass &&
        state.history[entry.sourcePass - 1]?.outcome === "findings",
      "Audit batch entries are invalid.",
    );
    ids.add(entry.finding.id);
  }
  const reviewed = new Set();
  for (const decision of batch.dispositions) {
    const entry = batch.entries.find(
      ({ finding }) => finding.id === decision.id,
    );
    assertAudit(
      entry && !reviewed.has(decision.id),
      "Audit dispositions must be unique batch members.",
    );
    assertAudit(
      same(decision, normalizeDecision(decision, entry)),
      "Audit disposition is not normalized.",
    );
    assertAudit(
      decision.kind !== "correct" || same(decision.finding, entry.finding),
      "Audit correction is stale.",
    );
    if (decision.kind === "merge") {
      const target = batch.dispositions.find(
        ({ id }) => id === decision.targetId,
      );
      assertAuditResult(
        ids.has(decision.targetId) &&
          (!target || ["confirm", "correct"].includes(target.kind)),
        "recheck.decisions",
        "invalid-merge",
      );
    }
    reviewed.add(decision.id);
  }
}

/** Validate both discovery and exact, independently budgeted batch acceptance provenance. */
export function assertAuditRun(run) {
  const state = run.pipelineState;
  assertAudit(
    Array.isArray(state?.recheckHistory) &&
      Array.isArray(state?.acceptedBatches),
    "Audit recheck history is required.",
  );
  assertDiscoveryRun(run);
  if (Object.hasOwn(run.pause ?? {}, "diagnosticClass")) {
    // The common run envelope owns registry membership; audit owns disposition.
    exact(run.pause, ["reason", "code", "diagnosticClass"]);
    assertAudit(
      state.workflowState === "FAILED" &&
        run.pause.reason === "internal_failure" &&
        typeof run.pause.code === "string" &&
        /^[A-Z0-9_]{1,64}$/u.test(run.pause.code) &&
        typeof run.pause.diagnosticClass === "string" &&
        /^[a-z][a-z0-9_]{0,63}$/u.test(run.pause.diagnosticClass),
      "Audit terminal provider diagnostic is invalid.",
    );
  }
  assertCorrectionFeedback(run);
  assertPublication(run);
  assertAudit(
    state.recheckHistory.length <= state.settings.maxFindingRecheckPasses &&
      (state.inputs !== null || state.recheckHistory.length === 0),
    "Audit rechecks require frozen inputs and the original finite budget.",
  );
  for (const [index, pass] of state.recheckHistory.entries()) {
    exact(pass, [
      "number",
      "contextKey",
      "sourcePass",
      "batchVersion",
      "batchFingerprint",
      "snapshotFingerprint",
      "reportFingerprint",
      "outcome",
      "resultFingerprint",
      "dispositions",
    ]);
    assertAudit(
      pass.number === index + 1 &&
        pass.contextKey === sessionContextKey(run, "recheck", pass.number) &&
        Number.isSafeInteger(pass.sourcePass) &&
        pass.sourcePass > 0 &&
        state.history[pass.sourcePass - 1]?.outcome === "findings" &&
        Number.isSafeInteger(pass.batchVersion) &&
        pass.batchVersion > 0 &&
        pass.batchVersion <= pass.number &&
        (index === 0 ||
          pass.sourcePass >= state.recheckHistory[index - 1].sourcePass) &&
        pass.snapshotFingerprint ===
          state.repositoryBaseline.contentFingerprint &&
        isHash(pass.reportFingerprint) &&
        isHash(pass.batchFingerprint) &&
        OUTCOMES.includes(pass.outcome) &&
        Array.isArray(pass.dispositions) &&
        (pass.outcome !== "running" ||
          index === state.recheckHistory.length - 1) &&
        (["corrected", "clean"].includes(pass.outcome)
          ? isHash(pass.resultFingerprint) &&
            pass.dispositions.length > 0 &&
            run.sessionLineage.children.some(
              (child) =>
                child.role === recheckRole(state, pass.number) &&
                child.contextKey === pass.contextKey,
            )
          : pass.resultFingerprint === null && pass.dispositions.length === 0),
      "Audit recheck history is invalid.",
    );
    if (pass.outcome === "clean" && acceptsCleanRecheck(state, pass.number)) {
      assertAudit(
        state.recheckHistory[index + 1]?.sourcePass !== pass.sourcePass,
        "Audit verification continued after batch acceptance.",
      );
    }
    const ids = new Set();
    for (const decision of pass.dispositions) {
      const entry = state.ledger.find(
        ({ finding }) => finding.id === decision?.id,
      );
      assertAudit(
        entry && !ids.has(decision.id),
        "Audit recheck decisions require unique ledger identities.",
      );
      assertAudit(
        same(decision, normalizeDecision(decision, entry)),
        "Audit historical decision is invalid.",
      );
      ids.add(decision.id);
    }
  }
  const acceptedPasses = new Set();
  for (const receipt of state.acceptedBatches) {
    exact(receipt, ["batch", "recheckPass"]);
    assertBatch(state, receipt.batch);
    const pass = state.recheckHistory[receipt.recheckPass - 1];
    assertAudit(
      Number.isSafeInteger(receipt.recheckPass) &&
        receipt.recheckPass > 0 &&
        pass?.outcome === "clean" &&
        acceptsCleanRecheck(state, receipt.recheckPass) &&
        !acceptedPasses.has(receipt.recheckPass) &&
        pass.sourcePass === receipt.batch.sourcePass &&
        pass.batchVersion === receipt.batch.version &&
        pass.reportFingerprint === receipt.batch.reportFingerprint &&
        pass.resultFingerprint === fingerprint(receipt.batch) &&
        same(pass.dispositions, receipt.batch.dispositions) &&
        receipt.batch.dispositions.length === receipt.batch.entries.length,
      "Audit batch acceptance is stale or lacks a clean recheck.",
    );
    acceptedPasses.add(receipt.recheckPass);
  }
  assertAudit(
    state.recheckHistory.filter(
      ({ outcome, number }) =>
        outcome === "clean" && acceptsCleanRecheck(state, number),
    ).length === acceptedPasses.size,
    "Audit clean rechecks require durable batch receipts.",
  );
  if (state.pendingBatch !== null) {
    assertBatch(state, state.pendingBatch);
    const pass = state.recheckHistory.at(-1);
    if (pass?.sourcePass === state.pendingBatch.sourcePass) {
      assertAudit(
        pass.outcome !== "clean" || !acceptsCleanRecheck(state, pass.number),
        "An accepted audit batch cannot remain pending verification.",
      );
      assertAudit(
        ["corrected", "clean"].includes(pass.outcome)
          ? pass.resultFingerprint === fingerprint(state.pendingBatch)
          : pass.batchFingerprint === fingerprint(state.pendingBatch) &&
              pass.outcome !== "clean",
        "Audit pending batch differs from its reserved or corrected version.",
      );
    }
  }
  for (const entry of state.ledger) {
    assertAudit(
      [
        state.pendingBatch,
        ...state.acceptedBatches.map(({ batch }) => batch),
      ].some((batch) =>
        batch?.entries.some((recorded) => same(recorded, entry)),
      ),
      "Audit ledger entries require pending verification or exact acceptance.",
    );
  }
}

export function reserveRecheck(run) {
  const state = run.pipelineState;
  const batch = state.pendingBatch;
  const number = state.recheckHistory.length + 1;
  return {
    ...state,
    recheckHistory: [
      ...state.recheckHistory,
      {
        number,
        contextKey: sessionContextKey(run, "recheck", number),
        sourcePass: batch.sourcePass,
        batchVersion: batch.version,
        batchFingerprint: fingerprint(batch),
        snapshotFingerprint: batch.snapshotFingerprint,
        reportFingerprint: batch.reportFingerprint,
        outcome: "running",
        resultFingerprint: null,
        dispositions: [],
      },
    ],
  };
}

export function finishRecheck(state, outcome) {
  return {
    ...state,
    recheckHistory: [
      ...state.recheckHistory.slice(0, -1),
      {
        ...state.recheckHistory.at(-1),
        outcome,
      },
    ],
  };
}

/** Adopt a whole response atomically; every substantive change needs another distinct recheck. */
export function acceptRecheck(state, value) {
  exact(
    value,
    [
      "status",
      "snapshotFingerprint",
      "reportFingerprint",
      "batchFingerprint",
      "decisions",
      "additions",
    ],
    "recheck",
  );
  const batch = state.pendingBatch;
  assertAuditResult(
    ["COMPLETE", "INCOMPLETE"].includes(value.status),
    "recheck.status",
    "unsupported-value",
  );
  for (const [field, expected] of Object.entries({
    snapshotFingerprint: batch.snapshotFingerprint,
    reportFingerprint: batch.reportFingerprint,
    batchFingerprint: fingerprint(batch),
  }))
    assertAuditResult(
      value[field] === expected,
      `recheck.${field}`,
      "binding-mismatch",
    );
  for (const field of ["decisions", "additions"])
    assertAuditResult(
      Array.isArray(value[field]),
      `recheck.${field}`,
      "required-items",
    );
  const decisions = batch.entries.map((entry) => {
    const matches = value.decisions.filter(
      (decision) => decision?.id === entry.finding.id,
    );
    assertAuditResult(
      matches.length === 1,
      "recheck.decisions",
      "candidate-mismatch",
    );
    return normalizeDecision(
      matches[0],
      entry,
      `recheck.decisions[${value.decisions.indexOf(matches[0])}]`,
    );
  });
  assertAuditResult(
    decisions.length === value.decisions.length,
    "recheck.decisions",
    "candidate-mismatch",
  );
  const additions = value.additions.map((finding, index) =>
    normalizeFinding(finding, `recheck.additions[${index}]`),
  );
  if (value.status !== "COMPLETE") return finishRecheck(state, "incomplete");

  const ledger = [...state.ledger];
  const entries = [...batch.entries];
  function adopt(finding, path) {
    const previous = ledger.find(
      (entry) =>
        entry.finding.id === finding.id ||
        entry.finding.causeId === finding.causeId,
    );
    assertAuditResult(
      !previous ||
        (previous.finding.id === finding.id &&
          previous.finding.causeId === finding.causeId),
      path,
      "identity-mismatch",
    );
    const entry =
      previous && same(previous.finding, finding)
        ? previous
        : {
            finding,
            version: (previous?.version ?? 0) + 1,
            sourcePass: batch.sourcePass,
          };
    if (previous) ledger[ledger.indexOf(previous)] = entry;
    else ledger.push(entry);
    const index = entries.findIndex((item) => item.finding.id === finding.id);
    if (index < 0) entries.push(entry);
    else entries[index] = entry;
  }
  for (const decision of decisions)
    if (decision.kind === "correct")
      adopt(decision.finding, "recheck.decisions");
  for (const [index, finding] of additions.entries()) {
    const existing = entries.find((entry) => entry.finding.id === finding.id);
    assertAuditResult(
      !existing || same(existing.finding, finding),
      `recheck.additions[${index}]`,
      "identity-mismatch",
    );
    // Exact unchanged repeats add neither a candidate nor a new batch version.
    if (!ledger.some((entry) => same(entry.finding, finding)))
      adopt(finding, `recheck.additions[${index}]`);
  }
  for (const decision of decisions.filter(({ kind }) => kind === "merge")) {
    const target = ledger.find(
      ({ finding }) => finding.id === decision.targetId,
    );
    assertAuditResult(target, "recheck.decisions", "invalid-merge");
    if (!entries.some(({ finding }) => finding.id === decision.targetId))
      entries.push(target);
  }
  assertAuditResult(
    ledger.length <= 10_000,
    "recheck.additions",
    "collection-limit",
  );
  normalizeAuditReport(
    {
      ...state.report,
      findings: ledger.map(({ finding }) => finding),
      hypotheses: [],
    },
    { findings: "recheck.additions", ids: "recheck" },
  );
  const unchanged =
    same(entries, batch.entries) &&
    decisions.every((decision) => {
      const previous = batch.dispositions.find(({ id }) => id === decision.id);
      return previous ? same(decision, previous) : decision.kind === "confirm";
    });
  const nextBatch = {
    ...batch,
    entries,
    dispositions: decisions,
    version: batch.version + (unchanged ? 0 : 1),
  };
  assertBatch({ ...state, ledger }, nextBatch);
  const pass = {
    ...state.recheckHistory.at(-1),
    outcome: unchanged ? "clean" : "corrected",
    resultFingerprint: fingerprint(nextBatch),
    dispositions: decisions,
  };
  const accepted = unchanged && acceptsCleanRecheck(state);
  return {
    ...state,
    ledger,
    pendingBatch: accepted ? null : nextBatch,
    workflowState: accepted ? "DISCOVER" : "VERIFY_FINDINGS",
    acceptedBatches: accepted
      ? [
          ...state.acceptedBatches,
          { batch: nextBatch, recheckPass: pass.number },
        ]
      : state.acceptedBatches,
    recheckHistory: [...state.recheckHistory.slice(0, -1), pass],
  };
}
