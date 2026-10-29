import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import { normalizeAuditReport, texts } from "./findings.js";

export const MAX_DISCOVERY_PASSES = 20;
export const MAX_CLARIFICATION_ROUNDS = 3;
const MAX_STRUCTURED_RESULT_BYTES = 2 * 1024 * 1024;
// Match the enclosing run store's field limits without importing root policy.
const MAX_STRING_LENGTH = 100_000;
const MAX_COLLECTION_LENGTH = 10_000;
export const AUDIT_MODES = Object.freeze(["independent", "lazy", "combined"]);
export const validDiscoveryBudget = (value) =>
  Number.isSafeInteger(value) && value > 0 && value <= MAX_DISCOVERY_PASSES;
const STAGES = [
  "CLARIFY",
  "DISCOVER",
  "VERIFY_FINDINGS",
  "DISCOVERY_CLEAN",
  "WAITING_FOR_USER",
  "FAILED",
];
const OUTCOMES = [
  "running",
  "interrupted",
  "invalid",
  "incomplete",
  "findings",
  "report-correction",
  "clean",
];

export class AuditWorkflowError extends Error {
  constructor(message, code = "ERR_INVALID_AUDIT_STATE") {
    super(message);
    this.name = "AuditWorkflowError";
    this.code = code;
  }
}

export function assertAudit(condition, message) {
  if (!condition) throw new AuditWorkflowError(message);
}

export function assertAuditResultSize(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new AuditWorkflowError("Audit role result must be serializable.");
  }
  assertAudit(
    typeof serialized === "string" &&
      Buffer.byteLength(serialized) <= MAX_STRUCTURED_RESULT_BYTES,
    "Audit role result exceeds the two-MiB limit.",
  );
  function assertFields(item, depth = 0) {
    assertAudit(
      depth < 20,
      "Audit result exceeds the persistent nesting limit.",
    );
    if (typeof item === "string") {
      assertAudit(
        item.length <= MAX_STRING_LENGTH,
        "Audit text exceeds the persistent field limit.",
      );
    } else if (Array.isArray(item)) {
      assertAudit(
        item.length <= MAX_COLLECTION_LENGTH,
        "Audit list exceeds the persistent collection limit.",
      );
      item.forEach((entry) => assertFields(entry, depth + 1));
    } else if (item !== null && typeof item === "object") {
      Object.values(item).forEach((entry) => assertFields(entry, depth + 1));
    }
  }
  assertFields(value);
}

export function exact(value, fields) {
  assertAudit(
    value !== null &&
      typeof value === "object" &&
      [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
      Object.keys(value).length === fields.length &&
      fields.every((key) => Object.hasOwn(value, key)),
    "Audit record has missing or unsupported fields.",
  );
}

export const fingerprint = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
export const isHash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
export const same = isDeepStrictEqual;

export function sessionContextKey(
  run,
  phase,
  number = run.pipelineState.history.length,
) {
  const state = run.pipelineState;
  const lazy = state.settings.mode === "lazy";
  return fingerprint({
    role: "auditor",
    task: run.hashes.task,
    context: run.hashes.context,
    snapshot: state.repositoryBaseline.contentFingerprint,
    checkpoint: lazy
      ? "audit:auditor"
      : phase === "clarify"
        ? "audit:clarify"
        : `audit:discovery:${number}`,
    ...(!lazy && phase === "discovery"
      ? { inputs: state.inputsFingerprint }
      : {}),
  });
}

export function emptyReport(inputs, snapshot) {
  return normalizeAuditReport({
    scope: inputs.scope,
    criteria: inputs.criteria,
    snapshot,
    findings: [],
    limitations: [],
    hypotheses: [],
  });
}

export function normalizeAuditInputs(value) {
  exact(value, ["scope", "references", "exclusions", "criteria"]);
  return {
    scope: texts(value.scope, "inputs.scope", 1),
    references: texts(value.references, "inputs.references"),
    exclusions: texts(value.exclusions, "inputs.exclusions"),
    criteria: texts(value.criteria, "inputs.criteria", 1),
  };
}

export function normalizeClarification(value) {
  exact(value, ["status", "inputs", "questions", "reason"]);
  assertAudit(
    Array.isArray(value.questions) && typeof value.reason === "string",
    "Invalid audit clarification response.",
  );
  if (value.status === "READY") {
    assertAudit(
      value.questions.length === 0 && value.reason === "",
      "READY cannot ask questions or block.",
    );
    return { ...value, inputs: normalizeAuditInputs(value.inputs) };
  }
  assertAudit(value.inputs === null, "Only READY may freeze audit inputs.");
  const concise = (text) =>
    typeof text === "string" &&
    text.trim().length > 0 &&
    text.length <= 4000 &&
    !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(text);
  if (value.status === "BLOCKED") {
    assertAudit(
      value.questions.length === 0 && concise(value.reason),
      "BLOCKED requires a concise reason without questions.",
    );
    return { ...value, reason: value.reason.trim() };
  }
  assertAudit(
    value.status === "QUESTIONS" &&
      value.questions.length > 0 &&
      value.questions.length <= 32 &&
      value.reason === "",
    "Invalid audit clarification outcome.",
  );
  for (const question of value.questions) {
    exact(question, ["question", "whyItMatters"]);
    assertAudit(
      concise(question.question) && concise(question.whyItMatters),
      "Audit questions must be concise plain text.",
    );
  }
  return value;
}

export function createAuditState({ settings = {} } = {}) {
  const resolved = {
    mode: "independent",
    maxDiscoveryPasses: MAX_DISCOVERY_PASSES,
    ...settings,
  };
  exact(resolved, ["mode", "maxDiscoveryPasses"]);
  assertAudit(
    AUDIT_MODES.includes(resolved.mode) &&
      validDiscoveryBudget(resolved.maxDiscoveryPasses),
    "Audit settings must preserve the finite discovery budget.",
  );
  return {
    workflowState: "CLARIFY",
    settings: resolved,
    repositoryBaseline: null,
    inputs: null,
    inputsFingerprint: null,
    clarificationHash: null,
    clarificationRounds: 0,
    pendingEdit: null,
    sourceForkConsumed: false,
    sourceForkRecovery: null,
    report: null,
    reportFingerprint: null,
    ledger: [],
    pendingBatch: null,
    history: [],
  };
}

/** Validate persisted discovery provenance without inventing acceptance evidence. */
export function assertAuditRun(run) {
  assertAudit(
    run.pipelineId === "audit",
    "Audit run has the wrong pipeline owner.",
  );
  const state = run.pipelineState;
  exact(state, Object.keys(createAuditState()));
  createAuditState({ settings: state.settings });
  assertAudit(
    STAGES.includes(state.workflowState) &&
      Array.isArray(state.history) &&
      state.history.length <= state.settings.maxDiscoveryPasses &&
      Array.isArray(state.ledger) &&
      typeof state.sourceForkConsumed === "boolean" &&
      Number.isSafeInteger(state.clarificationRounds) &&
      state.clarificationRounds >= 0 &&
      state.clarificationRounds <= MAX_CLARIFICATION_ROUNDS,
    "Audit stage or accounting is invalid.",
  );
  assertAudit(
    state.sourceForkRecovery === null ||
      (isHash(state.sourceForkRecovery) && run.sessionLineage.source !== null),
    "Audit source-fork recovery is invalid.",
  );
  if (state.inputs !== null) {
    assertAudit(
      same(state.inputs, normalizeAuditInputs(state.inputs)) &&
        isHash(state.clarificationHash) &&
        state.workflowState !== "CLARIFY" &&
        state.pendingEdit === null &&
        run.hashes.clarifications === state.clarificationHash &&
        state.inputsFingerprint ===
          fingerprint({
            inputs: state.inputs,
            clarificationHash: state.clarificationHash,
          }) &&
        isHash(state.repositoryBaseline?.contentFingerprint),
      "Audit frozen inputs are invalid.",
    );
    const report = normalizeAuditReport(state.report);
    assertAudit(
      report.findings.length === 0 &&
        same(report, state.report) &&
        state.reportFingerprint === fingerprint(report) &&
        same(report.scope, state.inputs.scope) &&
        same(report.criteria, state.inputs.criteria) &&
        report.snapshot.fingerprint ===
          state.repositoryBaseline.contentFingerprint,
      "Audit report binding is invalid.",
    );
  } else {
    assertAudit(
      ["CLARIFY", "WAITING_FOR_USER", "FAILED"].includes(state.workflowState) &&
        state.report === null &&
        state.reportFingerprint === null &&
        state.history.length === 0 &&
        state.ledger.length === 0 &&
        state.pendingBatch === null &&
        state.clarificationHash === null &&
        state.inputsFingerprint === null,
      "Audit discovery requires frozen clarification inputs.",
    );
  }
  assertAudit(
    state.pendingEdit === null ||
      (state.workflowState === "WAITING_FOR_USER" &&
        state.inputs === null &&
        state.pendingEdit.suspendedState === "CLARIFY" &&
        state.pendingEdit.preEditorHash === run.hashes.clarifications),
    "Audit clarification authorization is inconsistent.",
  );
  const ids = new Set();
  const causes = new Set();
  for (const entry of state.ledger) {
    exact(entry, ["finding", "version", "sourcePass"]);
    const finding = normalizeAuditReport({
      ...state.report,
      findings: [entry.finding],
      hypotheses: [],
    }).findings[0];
    assertAudit(
      same(finding, entry.finding) &&
        !ids.has(finding.id) &&
        !causes.has(finding.causeId) &&
        Number.isSafeInteger(entry.version) &&
        entry.version > 0 &&
        Number.isSafeInteger(entry.sourcePass) &&
        entry.sourcePass > 0 &&
        entry.sourcePass <= state.history.length &&
        entry.version <= entry.sourcePass &&
        state.history[entry.sourcePass - 1]?.outcome === "findings",
      "Audit finding ledger is inconsistent.",
    );
    ids.add(finding.id);
    causes.add(finding.causeId);
  }
  for (const [index, pass] of state.history.entries()) {
    exact(pass, [
      "number",
      "contextKey",
      "outcome",
      "reportFingerprint",
      "candidateIds",
    ]);
    assertAudit(
      pass.number === index + 1 &&
        typeof pass.contextKey === "string" &&
        pass.contextKey.length > 0 &&
        OUTCOMES.includes(pass.outcome) &&
        isHash(pass.reportFingerprint) &&
        Array.isArray(pass.candidateIds) &&
        pass.candidateIds.every((id) => ids.has(id)) &&
        (pass.outcome !== "clean" || pass.candidateIds.length === 0) &&
        (pass.outcome !== "running" || index === state.history.length - 1),
      "Audit discovery history is invalid.",
    );
    const expectedKey = sessionContextKey(run, "discovery", pass.number);
    assertAudit(
      pass.contextKey === expectedKey &&
        (!["clean", "findings", "report-correction"].includes(pass.outcome) ||
          run.sessionLineage.children.some(
            (child) =>
              child.role === "auditor" && child.contextKey === pass.contextKey,
          )),
      "Audit discovery session provenance is invalid.",
    );
  }
  if (state.pendingBatch !== null) {
    const batch = state.pendingBatch;
    exact(batch, [
      "sourcePass",
      "snapshotFingerprint",
      "reportFingerprint",
      "entries",
    ]);
    assertAudit(
      ["VERIFY_FINDINGS", "WAITING_FOR_USER"].includes(state.workflowState) &&
        Array.isArray(batch.entries) &&
        batch.entries.length > 0 &&
        batch.sourcePass === state.history.length &&
        state.history.at(-1)?.outcome === "findings" &&
        batch.snapshotFingerprint ===
          state.repositoryBaseline.contentFingerprint &&
        batch.reportFingerprint === state.reportFingerprint &&
        same(
          batch.entries,
          state.ledger.filter((entry) => entry.sourcePass === batch.sourcePass),
        ),
      "Audit pending verification binding is invalid.",
    );
  }
  assertAudit(
    state.workflowState === "WAITING_FOR_USER" ||
      (state.workflowState === "VERIFY_FINDINGS") ===
        (state.pendingBatch !== null),
    "Audit pending verification must block discovery.",
  );
  if (state.workflowState === "DISCOVERY_CLEAN") {
    assertAudit(
      state.history.at(-1)?.outcome === "clean" &&
        state.history.at(-1).reportFingerprint === state.reportFingerprint,
      "Audit clean discovery lacks current evidence.",
    );
  }
}

/** Normalize each candidate before duplicate comparison; conflicting shared causes fail closed. */
export function acceptDiscovery(state, value) {
  exact(value, [
    "status",
    "snapshotFingerprint",
    "candidates",
    "limitations",
    "hypotheses",
    "reportCorrections",
  ]);
  assertAudit(
    ["COMPLETE", "INCOMPLETE"].includes(value.status) &&
      value.snapshotFingerprint ===
        state.repositoryBaseline.contentFingerprint &&
      Array.isArray(value.candidates),
    "Audit discovery output is incomplete or bound to a different snapshot.",
  );
  const report = normalizeAuditReport({
    ...state.report,
    limitations: value.limitations,
    hypotheses: value.hypotheses,
  });
  const corrections = texts(
    value.reportCorrections,
    "discovery.reportCorrections",
  );
  const candidates = value.candidates.map(
    (finding) =>
      normalizeAuditReport({ ...report, findings: [finding], hypotheses: [] })
        .findings[0],
  );
  // Deduplicate exact repeats, but never silently merge conflicting accounts.
  const unique = [
    ...new Map(
      candidates.map((finding) => [fingerprint(finding), finding]),
    ).values(),
  ];
  normalizeAuditReport({ ...report, findings: unique });
  // An incomplete pass cannot publish a partial candidate batch or report update.
  if (value.status !== "COMPLETE") return finishPass(state, "incomplete");
  const ledger = [...state.ledger];
  const entries = [];
  const number = state.history.length;
  for (const finding of unique) {
    const previous = ledger.find(
      (entry) =>
        entry.finding.id === finding.id ||
        entry.finding.causeId === finding.causeId,
    );
    if (previous && same(previous.finding, finding)) continue;
    assertAudit(
      !previous ||
        (previous.finding.id === finding.id &&
          previous.finding.causeId === finding.causeId),
      "Audit revisions must preserve finding and cause identities.",
    );
    const entry = {
      finding,
      version: (previous?.version ?? 0) + 1,
      sourcePass: number,
    };
    if (previous) ledger[ledger.indexOf(previous)] = entry;
    else ledger.push(entry);
    entries.push(entry);
  }
  assertAudit(
    ledger.length <= MAX_COLLECTION_LENGTH,
    "Audit ledger exceeds the persistent collection limit.",
  );
  const reportFingerprint = fingerprint(report);
  const outcome =
    candidates.length > 0
      ? "findings"
      : corrections.length > 0 || reportFingerprint !== state.reportFingerprint
        ? "report-correction"
        : "clean";
  return {
    ...state,
    report,
    reportFingerprint,
    ledger,
    workflowState:
      entries.length > 0
        ? "VERIFY_FINDINGS"
        : outcome === "clean"
          ? "DISCOVERY_CLEAN"
          : "DISCOVER",
    pendingBatch:
      entries.length === 0
        ? null
        : {
            sourcePass: number,
            snapshotFingerprint: state.repositoryBaseline.contentFingerprint,
            reportFingerprint,
            entries: ledger.filter((entry) => entry.sourcePass === number),
          },
    history: [
      ...state.history.slice(0, -1),
      {
        ...state.history.at(-1),
        outcome,
        reportFingerprint,
        candidateIds: unique.map(({ id }) => id),
      },
    ],
  };
}

export function finishPass(state, outcome) {
  return {
    ...state,
    history: [
      ...state.history.slice(0, -1),
      { ...state.history.at(-1), outcome, candidateIds: [] },
    ],
  };
}
