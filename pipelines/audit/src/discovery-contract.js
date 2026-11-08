import { createHash } from "node:crypto";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  acceptsCleanDiscovery,
  cyclePosition,
  findingRecheckCycle,
} from "./cycles.js";
import {
  MAX_COLLECTION_LENGTH,
  MAX_QUESTION_LENGTH,
  MAX_QUESTIONS,
  MAX_STRING_LENGTH,
} from "./constraints.js";
import { auditDiagnostic, diagnosticIssues } from "./diagnostics.js";
import { normalizeAuditReport, normalizeFinding, texts } from "./findings.js";
import { assertSourceSettings } from "./source-scope.js";

export const MAX_DISCOVERY_PASSES = 20;
export const MAX_FINDING_RECHECK_PASSES = 20;
export const MAX_CLARIFICATION_ROUNDS = 3;
const MAX_STRUCTURED_RESULT_BYTES = 2 * 1024 * 1024;
export const AUDIT_MODES = Object.freeze(["independent", "lazy", "combined"]);
export const validDiscoveryBudget = (value) =>
  Number.isSafeInteger(value) && value > 0 && value <= MAX_DISCOVERY_PASSES;
const STAGES = [
  "CLARIFY",
  "DISCOVER",
  "VERIFY_FINDINGS",
  "DISCOVERY_CLEAN",
  "DONE",
  "CANCELED",
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
  constructor(message, code = "ERR_INVALID_AUDIT_STATE", diagnostic) {
    super(message);
    this.name = "AuditWorkflowError";
    this.code = code;
    if (diagnostic !== undefined) {
      this.diagnostics = Object.freeze([
        auditDiagnostic(diagnostic.field, diagnostic.code),
      ]);
    }
  }
}

export function assertAudit(condition, message) {
  if (!condition) throw new AuditWorkflowError(message);
}

export function assertAuditResult(condition, field, code) {
  if (!condition) {
    const diagnostic = auditDiagnostic(field, code);
    throw new AuditWorkflowError(
      diagnosticIssues(diagnostic)[0],
      "ERR_INVALID_AUDIT_STATE",
      diagnostic,
    );
  }
}

export function assertAuditResultSize(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    assertAuditResult(false, "result", "unserializable");
  }
  assertAuditResult(
    typeof serialized === "string" &&
      Buffer.byteLength(serialized) <= MAX_STRUCTURED_RESULT_BYTES,
    "result",
    "result-size",
  );
  function assertFields(item, depth = 0) {
    assertAuditResult(depth < 20, "result", "nesting-limit");
    if (typeof item === "string") {
      assertAuditResult(
        item.length <= MAX_STRING_LENGTH,
        "result",
        "field-limit",
      );
    } else if (Array.isArray(item)) {
      assertAuditResult(
        item.length <= MAX_COLLECTION_LENGTH,
        "result",
        "collection-limit",
      );
      item.forEach((entry) => assertFields(entry, depth + 1));
    } else if (item !== null && typeof item === "object") {
      Object.values(item).forEach((entry) => assertFields(entry, depth + 1));
    }
  }
  assertFields(value);
}

export function exact(value, fields, path) {
  if (path !== undefined) {
    assertAuditResult(
      value !== null &&
        typeof value === "object" &&
        [Object.prototype, null].includes(Object.getPrototypeOf(value)),
      path,
      "invalid-record",
    );
    assertAuditResult(
      Object.keys(value).every((key) => fields.includes(key)),
      path,
      "unsupported-fields",
    );
    assertAuditResult(
      fields.every((key) => Object.hasOwn(value, key)),
      path,
      "required-fields",
    );
    return;
  }
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
  const combined = state.settings.mode === "combined";
  let checkpoint = lazy
    ? "audit:auditor"
    : phase === "clarify"
      ? "audit:clarify"
      : `audit:${phase}:${number}`;
  if (combined) {
    if (phase === "recheck") {
      const { sourcePass, cycle } = findingRecheckCycle(state, number);
      if (cycle === 1) return state.history[sourcePass - 1].contextKey;
      checkpoint = `audit:recheck:${sourcePass}:cycle:${cycle - 1}`;
    } else {
      const cycle =
        phase === "clarify" ? 1 : cyclePosition(state.history, number).cycle;
      checkpoint = `audit:auditor:cycle:${cycle}`;
    }
  }
  const bindInputs =
    !lazy &&
    phase !== "clarify" &&
    !(combined && checkpoint === "audit:auditor:cycle:1");
  return fingerprint({
    role: phase === "recheck" && !lazy ? "reviewer" : "auditor",
    task: run.hashes.task,
    context: run.hashes.context,
    snapshot: state.repositoryBaseline.contentFingerprint,
    checkpoint,
    ...(bindInputs ? { inputs: state.inputsFingerprint } : {}),
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
  exact(
    value,
    ["scope", "references", "exclusions", "criteria"],
    "clarification.inputs",
  );
  return {
    scope: texts(value.scope, "clarification.inputs.scope", 1),
    references: texts(value.references, "clarification.inputs.references"),
    exclusions: texts(value.exclusions, "clarification.inputs.exclusions"),
    criteria: texts(value.criteria, "clarification.inputs.criteria", 1),
  };
}

export function normalizeClarification(value) {
  exact(value, ["status", "inputs", "questions", "reason"], "clarification");
  assertAuditResult(
    Array.isArray(value.questions),
    "clarification.questions",
    "required-items",
  );
  assertAuditResult(
    typeof value.reason === "string",
    "clarification.reason",
    "invalid-outcome",
  );
  if (value.status === "READY") {
    assertAuditResult(
      value.questions.length === 0 && value.reason === "",
      "clarification",
      "invalid-outcome",
    );
    return { ...value, inputs: normalizeAuditInputs(value.inputs) };
  }
  assertAuditResult(
    value.inputs === null,
    "clarification.inputs",
    "invalid-outcome",
  );
  const concise = (text) =>
    typeof text === "string" &&
    text.trim().length > 0 &&
    text.length <= MAX_QUESTION_LENGTH &&
    !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(text);
  if (value.status === "BLOCKED") {
    assertAuditResult(
      value.questions.length === 0 && concise(value.reason),
      "clarification",
      "invalid-outcome",
    );
    return { ...value, reason: value.reason.trim() };
  }
  assertAuditResult(
    value.status === "QUESTIONS" &&
      value.questions.length > 0 &&
      value.questions.length <= MAX_QUESTIONS &&
      value.reason === "",
    "clarification",
    "invalid-outcome",
  );
  for (const [index, question] of value.questions.entries()) {
    const path = `clarification.questions[${index}]`;
    exact(question, ["question", "whyItMatters"], path);
    for (const field of ["question", "whyItMatters"])
      assertAuditResult(
        concise(question[field]),
        `${path}.${field}`,
        "invalid-text",
      );
  }
  return value;
}

export function createAuditState({
  settings = {},
  proactiveClarification = false,
} = {}) {
  assertAudit(
    typeof proactiveClarification === "boolean",
    "proactiveClarification must be a boolean.",
  );
  const resolved = {
    mode: "independent",
    sourceScope: "directory",
    excludePaths: [],
    maxDiscoveryPasses: MAX_DISCOVERY_PASSES,
    maxFindingRecheckPasses: MAX_FINDING_RECHECK_PASSES,
    ...settings,
  };
  exact(resolved, [
    "mode",
    "sourceScope",
    "excludePaths",
    "maxDiscoveryPasses",
    "maxFindingRecheckPasses",
  ]);
  try {
    assertSourceSettings(resolved);
  } catch {
    assertAudit(false, "Audit source selection settings are invalid.");
  }
  assertAudit(
    AUDIT_MODES.includes(resolved.mode) &&
      validDiscoveryBudget(resolved.maxDiscoveryPasses) &&
      validDiscoveryBudget(resolved.maxFindingRecheckPasses),
    "Audit settings must preserve both finite pass budgets.",
  );
  return {
    workflowState: "CLARIFY",
    settings: resolved,
    proactiveClarification,
    proactiveClarificationComplete: !proactiveClarification,
    repositoryBaseline: null,
    inputs: null,
    inputsFingerprint: null,
    clarificationHash: null,
    clarificationRounds: 0,
    pendingEdit: null,
    sourceForkConsumed: false,
    sourceForkRecovery: null,
    sourceForkContexts: [],
    report: null,
    reportFingerprint: null,
    ledger: [],
    pendingBatch: null,
    history: [],
    recheckHistory: [],
    acceptedBatches: [],
    correctionFeedback: null,
    publication: { pending: null, published: null, temporary: null },
  };
}

/** Validate persisted discovery provenance without inventing acceptance evidence. */
export function assertDiscoveryRun(run) {
  assertAudit(
    run.pipelineId === "audit",
    "Audit run has the wrong pipeline owner.",
  );
  const state = run.pipelineState;
  exact(state, Object.keys(createAuditState()));
  createAuditState({ settings: state.settings });
  const binding = run.workspacePreparation ?? run.workspace;
  if (binding?.kind === "directory" || run.workspacePreparation != null) {
    assertAudit(
      (binding.sourceSelection?.kind ?? "directory") ===
        (state.settings.sourceScope ?? "directory") &&
        same(
          binding.policy.excludePaths ?? [],
          state.settings.excludePaths ?? [],
        ),
      "Audit source selection must match its frozen settings.",
    );
    if (
      state.repositoryBaseline !== null &&
      binding.sourceSelection !== undefined
    )
      assertAudit(
        same(state.repositoryBaseline.sourceSelection, binding.sourceSelection),
        "Audit snapshot must retain its frozen source selection.",
      );
  }
  assertAudit(
    STAGES.includes(state.workflowState) &&
      Array.isArray(state.history) &&
      state.history.length <= state.settings.maxDiscoveryPasses &&
      Array.isArray(state.ledger) &&
      typeof state.sourceForkConsumed === "boolean" &&
      typeof state.proactiveClarification === "boolean" &&
      typeof state.proactiveClarificationComplete === "boolean" &&
      (state.proactiveClarification || state.proactiveClarificationComplete) &&
      (state.proactiveClarificationComplete ||
        (state.inputs === null &&
          state.history.length === 0 &&
          ["CLARIFY", "WAITING_FOR_USER", "FAILED", "CANCELED"].includes(
            state.workflowState,
          ))) &&
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
  assertAudit(
    Array.isArray(state.sourceForkContexts) &&
      state.sourceForkContexts.length <=
        1 +
          state.settings.maxDiscoveryPasses +
          state.settings.maxFindingRecheckPasses &&
      state.sourceForkContexts.every(isHash) &&
      new Set(state.sourceForkContexts).size ===
        state.sourceForkContexts.length &&
      (state.sourceForkContexts.length === 0 ||
        (state.settings.mode === "combined" &&
          run.sessionLineage.source !== null)) &&
      (state.settings.mode !== "combined" ||
        state.sourceForkRecovery === null ||
        state.sourceForkContexts.includes(state.sourceForkRecovery)),
    "Audit combined source-fork consumption is invalid.",
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
      ["CLARIFY", "WAITING_FOR_USER", "FAILED", "CANCELED"].includes(
        state.workflowState,
      ) &&
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
      (["WAITING_FOR_USER", "CANCELED"].includes(state.workflowState) &&
        state.inputs === null &&
        state.pendingEdit.suspendedState === "CLARIFY" &&
        state.pendingEdit.preEditorHash === run.hashes.clarifications),
    "Audit clarification authorization is inconsistent.",
  );
  if (state.pendingEdit !== null) {
    const edit = state.pendingEdit;
    exact(edit, [
      "schemaVersion",
      "id",
      "artifactRoot",
      "transcriptPath",
      "action",
      "suspendedState",
      "preEditorHash",
    ]);
    assertAudit(
      edit.schemaVersion === 1 &&
        typeof edit.id === "string" &&
        edit.id.length > 0 &&
        edit.id.length <= 256 &&
        edit.id === edit.id.trim() &&
        !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(edit.id) &&
        edit.artifactRoot === run.taskPath &&
        edit.transcriptPath === join(run.taskPath, "clarifications.md") &&
        ["proactive-clarification", "clarification-answers"].includes(
          edit.action,
        ) &&
        (edit.action === "proactive-clarification") ===
          (state.proactiveClarification &&
            !state.proactiveClarificationComplete),
      "Audit pending edit is invalid.",
    );
  }
  const request = run.pause?.inputRequest;
  if (request !== undefined) {
    assertAudit(
      state.workflowState === "WAITING_FOR_USER" && state.pendingEdit !== null,
      "Audit input request requires a pending edit.",
    );
    assertAudit(
      request.id === state.pendingEdit.id &&
        request.kind === "clarification" &&
        request.artifactPath === state.pendingEdit.transcriptPath &&
        Array.isArray(request.questions) &&
        (state.pendingEdit.action === "proactive-clarification"
          ? request.questions.length === 0
          : request.questions.length > 0 &&
            request.questions.every(
              (question, index) =>
                question.id === `q${index + 1}` &&
                Array.isArray(question.options) &&
                question.options.length === 0 &&
                typeof question.rationale === "string",
            )),
      "Audit input request does not match its edit authorization.",
    );
  }
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
        entry.version <= entry.sourcePass + state.recheckHistory.length &&
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
    if (
      state.settings.mode === "combined" &&
      pass.outcome === "clean" &&
      acceptsCleanDiscovery(state, pass.number)
    ) {
      assertAudit(
        index === state.history.length - 1 &&
          [
            "DISCOVERY_CLEAN",
            "DONE",
            "CANCELED",
            "WAITING_FOR_USER",
            "FAILED",
          ].includes(state.workflowState),
        "Audit discovery continued after its combined clean-first successor gate.",
      );
    }
  }
  if (state.pendingBatch !== null) {
    const batch = state.pendingBatch;
    assertAudit(
      ["VERIFY_FINDINGS", "WAITING_FOR_USER", "FAILED", "CANCELED"].includes(
        state.workflowState,
      ) &&
        Array.isArray(batch.entries) &&
        batch.entries.length > 0 &&
        batch.sourcePass === state.history.length &&
        state.history.at(-1)?.outcome === "findings" &&
        batch.snapshotFingerprint ===
          state.repositoryBaseline.contentFingerprint &&
        batch.reportFingerprint === state.reportFingerprint &&
        batch.entries.every((entry) =>
          state.ledger.some((recorded) => same(recorded, entry)),
        ),
      "Audit pending verification binding is invalid.",
    );
  }
  assertAudit(
    ["WAITING_FOR_USER", "FAILED", "CANCELED"].includes(state.workflowState) ||
      (state.workflowState === "VERIFY_FINDINGS") ===
        (state.pendingBatch !== null),
    "Audit pending verification must block discovery.",
  );
  if (["DISCOVERY_CLEAN", "DONE"].includes(state.workflowState)) {
    assertAudit(
      state.history.at(-1)?.outcome === "clean" &&
        state.history.at(-1).reportFingerprint === state.reportFingerprint &&
        acceptsCleanDiscovery(state),
      "Audit clean discovery lacks current evidence.",
    );
  }
}

/** Normalize each candidate before duplicate comparison; conflicting shared causes fail closed. */
export function acceptDiscovery(state, value) {
  exact(
    value,
    [
      "status",
      "snapshotFingerprint",
      "candidates",
      "limitations",
      "hypotheses",
      "reportCorrections",
    ],
    "discovery",
  );
  assertAuditResult(
    ["COMPLETE", "INCOMPLETE"].includes(value.status),
    "discovery.status",
    "unsupported-value",
  );
  assertAuditResult(
    value.snapshotFingerprint === state.repositoryBaseline.contentFingerprint,
    "discovery.snapshotFingerprint",
    "binding-mismatch",
  );
  assertAuditResult(
    Array.isArray(value.candidates),
    "discovery.candidates",
    "required-items",
  );
  const fields = {
    findings: "discovery.candidates",
    limitations: "discovery.limitations",
    hypotheses: "discovery.hypotheses",
    ids: "discovery",
  };
  const report = normalizeAuditReport(
    {
      ...state.report,
      limitations: value.limitations,
      hypotheses: value.hypotheses,
    },
    fields,
  );
  const corrections = texts(
    value.reportCorrections,
    "discovery.reportCorrections",
  );
  const candidates = value.candidates.map((finding, index) =>
    normalizeFinding(finding, `discovery.candidates[${index}]`),
  );
  // Deduplicate exact repeats, but never silently merge conflicting accounts.
  const unique = [
    ...new Map(
      candidates.map((finding) => [fingerprint(finding), finding]),
    ).values(),
  ];
  normalizeAuditReport({ ...report, findings: unique }, fields);
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
    assertAuditResult(
      !previous ||
        (previous.finding.id === finding.id &&
          previous.finding.causeId === finding.causeId),
      `discovery.candidates[${candidates.indexOf(finding)}]`,
      "identity-mismatch",
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
  assertAuditResult(
    ledger.length <= MAX_COLLECTION_LENGTH,
    "discovery.candidates",
    "collection-limit",
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
        : outcome === "clean" && acceptsCleanDiscovery(state)
          ? "DISCOVERY_CLEAN"
          : "DISCOVER",
    pendingBatch:
      entries.length === 0
        ? null
        : {
            sourcePass: number,
            snapshotFingerprint: state.repositoryBaseline.contentFingerprint,
            reportFingerprint,
            entries,
            version: 1,
            dispositions: [],
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
