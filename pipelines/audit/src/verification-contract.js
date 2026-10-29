import {
  assertAudit,
  assertDiscoveryRun,
  exact,
  fingerprint,
  isHash,
  same,
  sessionContextKey,
} from "./discovery-contract.js";
import { normalizeAuditReport, texts } from "./findings.js";

const KINDS = ["confirm", "correct", "reject", "merge", "hypothesis"];
const OUTCOMES = [
  "running",
  "interrupted",
  "invalid",
  "incomplete",
  "corrected",
  "clean",
];

function normalizeFinding(state, finding) {
  return normalizeAuditReport({
    ...state.report,
    findings: [finding],
    hypotheses: [],
  }).findings[0];
}

function normalizeDecision(state, value, entry) {
  exact(value, [
    "id",
    "kind",
    "rationale",
    "finding",
    "targetId",
    "hypothesis",
  ]);
  assertAudit(
    value.id === entry.finding.id && KINDS.includes(value.kind),
    "Audit disposition must identify its exact candidate.",
  );
  const rationale = texts([value.rationale], "disposition.rationale", 1)[0];
  let finding = null;
  let hypothesis = null;
  if (value.kind === "correct") {
    finding = normalizeFinding(state, value.finding);
    assertAudit(
      finding.id === value.id && finding.causeId === entry.finding.causeId,
      "Audit corrections must preserve finding and cause identities.",
    );
  } else
    assertAudit(value.finding === null, "Only corrections carry a finding.");
  if (value.kind === "hypothesis") {
    hypothesis = normalizeAuditReport({
      ...state.report,
      findings: [],
      hypotheses: [value.hypothesis],
    }).hypotheses[0];
    assertAudit(
      hypothesis.id === value.id,
      "Audit hypothesis must retain its candidate ID.",
    );
  } else
    assertAudit(
      value.hypothesis === null,
      "Only hypotheses carry uncertainty.",
    );
  assertAudit(
    value.kind === "merge"
      ? typeof value.targetId === "string" && value.targetId !== value.id
      : value.targetId === null,
    "Audit merge must name a distinct retained finding.",
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
      same(entry.finding, normalizeFinding(state, entry.finding)) &&
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
      same(decision, normalizeDecision(state, decision, entry)),
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
      assertAudit(
        ids.has(decision.targetId) &&
          (!target || ["confirm", "correct"].includes(target.kind)),
        "Audit merges must retain a confirmed or corrected target, without chains.",
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
                child.role ===
                  (state.settings.mode === "lazy" ? "auditor" : "reviewer") &&
                child.contextKey === pass.contextKey,
            )
          : pass.resultFingerprint === null && pass.dispositions.length === 0),
      "Audit recheck history is invalid.",
    );
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
        same(decision, normalizeDecision(state, decision, entry)),
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
    state.recheckHistory.filter(({ outcome }) => outcome === "clean").length ===
      acceptedPasses.size,
    "Audit clean rechecks require durable batch receipts.",
  );
  if (state.pendingBatch !== null) {
    assertBatch(state, state.pendingBatch);
    const pass = state.recheckHistory.at(-1);
    if (pass?.sourcePass === state.pendingBatch.sourcePass) {
      assertAudit(
        pass.outcome === "corrected"
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
  exact(value, [
    "status",
    "snapshotFingerprint",
    "reportFingerprint",
    "batchFingerprint",
    "decisions",
    "additions",
  ]);
  const batch = state.pendingBatch;
  assertAudit(
    ["COMPLETE", "INCOMPLETE"].includes(value.status) &&
      value.snapshotFingerprint === batch.snapshotFingerprint &&
      value.reportFingerprint === batch.reportFingerprint &&
      value.batchFingerprint === fingerprint(batch) &&
      Array.isArray(value.decisions) &&
      Array.isArray(value.additions),
    "Audit recheck output has stale or incomplete bindings.",
  );
  const decisions = batch.entries.map((entry) => {
    const matches = value.decisions.filter(
      (decision) => decision?.id === entry.finding.id,
    );
    assertAudit(
      matches.length === 1,
      "Audit recheck must decide every candidate exactly once.",
    );
    return normalizeDecision(state, matches[0], entry);
  });
  assertAudit(
    decisions.length === value.decisions.length,
    "Audit recheck cannot decide unknown candidates.",
  );
  const additions = value.additions.map((finding) =>
    normalizeFinding(state, finding),
  );
  if (value.status !== "COMPLETE") return finishRecheck(state, "incomplete");

  const ledger = [...state.ledger];
  const entries = [...batch.entries];
  function adopt(finding) {
    const previous = ledger.find(
      (entry) =>
        entry.finding.id === finding.id ||
        entry.finding.causeId === finding.causeId,
    );
    assertAudit(
      !previous ||
        (previous.finding.id === finding.id &&
          previous.finding.causeId === finding.causeId),
      "Audit recheck additions conflict with established identities.",
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
    if (decision.kind === "correct") adopt(decision.finding);
  for (const finding of additions) {
    const existing = entries.find((entry) => entry.finding.id === finding.id);
    assertAudit(
      !existing || same(existing.finding, finding),
      "Use a correction to revise a current batch member.",
    );
    // Exact unchanged repeats add neither a candidate nor a new batch version.
    if (!ledger.some((entry) => same(entry.finding, finding))) adopt(finding);
  }
  for (const decision of decisions.filter(({ kind }) => kind === "merge")) {
    const target = ledger.find(
      ({ finding }) => finding.id === decision.targetId,
    );
    assertAudit(target, "Audit merge target must exist in the ledger.");
    if (!entries.some(({ finding }) => finding.id === decision.targetId))
      entries.push(target);
  }
  assertAudit(
    ledger.length <= 10_000,
    "Audit ledger exceeds the persistent collection limit.",
  );
  normalizeAuditReport({
    ...state.report,
    findings: ledger.map(({ finding }) => finding),
    hypotheses: [],
  });
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
  return {
    ...state,
    ledger,
    pendingBatch: unchanged ? null : nextBatch,
    workflowState: unchanged ? "DISCOVER" : "VERIFY_FINDINGS",
    acceptedBatches: unchanged
      ? [
          ...state.acceptedBatches,
          { batch: nextBatch, recheckPass: pass.number },
        ]
      : state.acceptedBatches,
    recheckHistory: [...state.recheckHistory.slice(0, -1), pass],
  };
}
