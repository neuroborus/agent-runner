import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  CommitPlanValidationError,
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";

import {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_CORRECTION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CHECK_AND_FIX_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  CLEAN_CONFIRM_INSTRUCTIONS,
  COMMIT_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_CORRECTION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  finalizationBootstrapInstructions,
  finalizationGuidanceInstructions,
  FINDING_ARBITRATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  IMPLEMENTATION_INSTRUCTIONS,
  NO_DELEGATION_INSTRUCTIONS,
  PLAN_COMPATIBILITY_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_CORRECTION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
  STAGNATION_INSTRUCTIONS,
} from "./prompts.js";
import {
  BOOTSTRAP_ARBITRATION_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  CLARIFICATION_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  DISPUTE_RECONSIDERATION_SCHEMA,
  FINALIZATION_SCHEMA,
  FINDING_ARBITRATION_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  IMPLEMENTATION_SCHEMA,
  PLAN_COMPATIBILITY_SCHEMA,
  REVIEW_SCHEMA,
  STAGNATION_SCHEMA,
} from "./schemas.js";
import {
  CONVENTIONAL_FINALIZATION_SKILL_PATHS,
  INVALID_EXECUTION_INPUT_CODE,
  MAX_CLARIFICATION_ROUNDS,
  MAX_DIAGNOSTIC_ITEMS,
  MAX_FINALIZATION_CORRECTION_ATTEMPTS,
  MAX_PLAN_LENGTH,
  MAX_VALIDATION_ITEMS,
  PlanExecutionWorkflowError,
  WORKFLOW_STATES,
  assertRun,
  assertRuntime,
  assertSettings,
  createPlanExecutionState,
  isRecord,
  isOutputDiagnostic,
  normalizeAdapterCapabilities,
  normalizeBootstrapArbitration,
  normalizeBootstrapResultCandidate,
  normalizeCheckAndFixResult,
  normalizeClarificationResult,
  normalizeCleanConfirmationResult,
  normalizeCompatibilityResult,
  normalizeFinalizationResult,
  normalizeFindingArbitration,
  normalizeInputSnapshot,
  normalizeImplementationResult,
  normalizePipelineState,
  normalizeReconsiderationResult,
  normalizeReconciliationResult,
  normalizeResolutionResult,
  normalizeResumeAction,
  normalizeReviewResult,
  normalizeStagnationResult,
  normalizedCounters,
  sha256,
  workflowError,
} from "./workflow-contract.js";

export {
  MAX_CLARIFICATION_ROUNDS,
  PlanExecutionWorkflowError,
  WORKFLOW_STATES,
  createPlanExecutionState,
};

const INPUT_DRIFT_ERROR_CODES = new Set([
  "EACCES",
  "EISDIR",
  "ELOOP",
  "ENOENT",
  "ENOTDIR",
  "EPERM",
]);
const RETRYABLE_PAUSE_REASONS = new Set([
  "backend_unavailable",
  "environment_blocked",
  "finalization_cannot_pass",
  "finalization_skill_invalid",
  "finalization_skill_missing",
  "local_artifacts_not_ignored",
  "review_output_invalid",
  "unsafe_git_state",
]);
const GIT_PREFLIGHT_CODES = new Set([
  "ERR_GIT_IDENTITY_REQUIRED",
  "ERR_GIT_UNAVAILABLE",
  "ERR_NOT_GIT_REPOSITORY",
  "ERR_REPOSITORY_NOT_CLEAN",
  "ERR_UNSAFE_REPOSITORY_PATH",
  "ERR_UNSUPPORTED_GIT_CONFIGURATION",
]);
const INVALID_VALIDATION_PATH_CODES = new Set([
  "ERR_UNSAFE_REPOSITORY_PATH",
  "ERR_UNSUPPORTED_GIT_PATH",
]);
const STRUCTURED_OUTPUT_FAILURE_CLASS = "structured-output";
const ADAPTER_DIAGNOSTIC_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u;

function activity(actor, phase, kind, message) {
  return Object.freeze({ actor, phase, kind, message });
}

function rolePrompt(prompt) {
  return `${prompt}\n\n${NO_DELEGATION_INSTRUCTIONS}`;
}

function adapterDiagnosticClass(cause) {
  return ADAPTER_DIAGNOSTIC_CLASS_PATTERN.test(cause?.diagnosticClass)
    ? cause.diagnosticClass
    : undefined;
}

function deriveValidationInventory(...validations) {
  const commands = [];
  const commandSet = new Set();
  const paths = [];
  const pathSet = new Set();
  for (const validation of validations.filter((value) => value !== null)) {
    for (const { command } of validation.requiredChecks) {
      if (!commandSet.has(command)) {
        commandSet.add(command);
        commands.push(command);
      }
    }
    for (const path of validation.validationInfrastructure) {
      if (!pathSet.has(path)) {
        pathSet.add(path);
        paths.push(path);
      }
    }
  }
  return Object.freeze({
    requiredChecks: Object.freeze(
      commands.map((command, index) =>
        Object.freeze({ id: `C${index + 1}`, command }),
      ),
    ),
    validationInfrastructure: Object.freeze(paths),
  });
}

function activeTurn(role, workflowState) {
  return Object.freeze({
    role,
    phase: workflowState.toLowerCase().replaceAll("_", "-"),
  });
}

function isWithin(parentPath, childPath) {
  const pathFromParent = relative(parentPath, childPath);
  return (
    pathFromParent === "" ||
    (!pathFromParent.startsWith(`..${sep}`) &&
      pathFromParent !== ".." &&
      !isAbsolute(pathFromParent))
  );
}

function inputEvidence(inputs, canonicalPlan, clarification) {
  const taskClarifications =
    inputs.taskClarifications?.content.length > 0
      ? inputs.taskClarifications.content
      : "(not provided)";
  const context =
    inputs.context?.content.length > 0 ? inputs.context.content : "(not provided)";
  const executionClarifications =
    clarification.content.length > 0 ? clarification.content : "(empty)";
  return `Task (${inputs.task.path}):
${inputs.task.content}

Validated plan (${inputs.plan.path}):
${canonicalPlan}

Plan-authoring clarifications (${inputs.taskClarifications?.path ?? join(dirname(inputs.task.path), "clarifications.md")}):
${taskClarifications}

Context (${inputs.context?.path ?? join(dirname(inputs.task.path), "context.md")}):
${context}

Execution clarifications (${clarification.transcriptPath}):
${executionClarifications}`;
}

function durableContext(evidence, recoveryContext) {
  return recoveryContext.length === 0
    ? evidence
    : `${evidence}\n\n${recoveryContext}`;
}

function contextKeyFor(role, checkpoint, context) {
  if (typeof checkpoint !== "string" || checkpoint.length === 0) {
    throw workflowError("Plan-execution session checkpoint is invalid.");
  }
  return sha256(`${role}\0${checkpoint}\0${context}`);
}

function canonicalPlan(source) {
  if (typeof source === "string" && source.length > MAX_PLAN_LENGTH) {
    throw new PlanExecutionWorkflowError(
      `plan.md must not exceed ${MAX_PLAN_LENGTH} characters.`,
      { code: "ERR_INVALID_EXECUTION_PLAN" },
    );
  }
  let plan;
  try {
    plan = serializeCommitPlan(parseCommitPlan(source));
  } catch (cause) {
    if (!(cause instanceof CommitPlanValidationError)) {
      throw cause;
    }
    throw new PlanExecutionWorkflowError("plan.md is invalid.", {
      cause,
      code: "ERR_INVALID_EXECUTION_PLAN",
    });
  }
  if (plan.length > MAX_PLAN_LENGTH) {
    throw new PlanExecutionWorkflowError(
      `plan.md must not exceed ${MAX_PLAN_LENGTH} characters.`,
      { code: "ERR_INVALID_EXECUTION_PLAN" },
    );
  }
  return plan;
}

function diagnosticCode(cause, fallback) {
  return typeof cause?.code === "string" && /^[A-Z0-9_]{1,64}$/u.test(cause.code)
    ? cause.code
    : fallback;
}

function outputDiagnostic(cause, context) {
  const field = cause?.diagnostic?.field;
  const constraint = cause?.diagnostic?.constraint;
  const candidate = Object.freeze({
    ...context,
    field,
    constraint,
  });
  return isOutputDiagnostic(candidate)
    ? candidate
    : Object.freeze({
        ...context,
        field: "result",
        constraint: "semantic-contract",
      });
}

function outputDiagnostics(cause, context) {
  const candidates =
    Array.isArray(cause?.diagnostics)
      ? cause.diagnostics.length !== 0 || cause?.diagnostic === undefined
        ? cause.diagnostics
        : [cause.diagnostic]
      : [cause?.diagnostic];
  const diagnostics = candidates.map((diagnostic) =>
    outputDiagnostic({ diagnostic }, context),
  );
  return Object.freeze(
    diagnostics.filter(
      (diagnostic, index) =>
        diagnostics.findIndex((candidate) =>
          isDeepStrictEqual(candidate, diagnostic),
        ) === index,
    ),
  );
}

function bootstrapOutputContext(role, phase = "bootstrap") {
  return Object.freeze({ role, phase, contract: "bootstrap" });
}

function reconciliationOutputContext(phase = "bootstrap") {
  return Object.freeze({
    role: "worker",
    phase,
    contract: "bootstrap-reconciliation",
  });
}

function arbitrationOutputContext(phase = "bootstrap") {
  return Object.freeze({
    role: "arbiter",
    phase,
    contract: "bootstrap-arbitration",
  });
}

function finalizationOutputContext() {
  return Object.freeze({
    role: "worker",
    phase: "finalization",
    contract: "finalization",
  });
}

function reviewOutputContext() {
  return Object.freeze({
    role: "reviewer",
    phase: "review",
    contract: "review",
  });
}

function roleOutputContextFor(role, schema, checkpoint) {
  const phase =
    checkpoint === "validation-migration" ? checkpoint : "bootstrap";
  if (schema === BOOTSTRAP_SCHEMA) {
    return bootstrapOutputContext(role, phase);
  }
  if (schema === BOOTSTRAP_RECONCILIATION_SCHEMA) {
    return reconciliationOutputContext(phase);
  }
  if (schema === BOOTSTRAP_ARBITRATION_SCHEMA) {
    return arbitrationOutputContext(phase);
  }
  if (schema === FINALIZATION_SCHEMA && role === "worker") {
    return finalizationOutputContext();
  }
  if (schema === REVIEW_SCHEMA && role === "reviewer") {
    return reviewOutputContext();
  }
  return undefined;
}

function invalidRoleOutput(message, context, diagnostic) {
  return new PlanExecutionWorkflowError(message, {
    code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
    diagnostic: outputDiagnostic({ diagnostic }, context),
  });
}

function invalidRoleOutputBatch(message, context, diagnostics) {
  const normalized = outputDiagnostics({ diagnostics }, context).slice(
    0,
    MAX_VALIDATION_ITEMS,
  );
  return new PlanExecutionWorkflowError(message, {
    code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
    diagnostic: normalized[0],
    diagnostics: normalized,
  });
}

function persistedOutputDiagnostic(value) {
  return isOutputDiagnostic(value)
    ? Object.freeze({ ...value })
    : undefined;
}

function normalizeRoleOutput(normalize, output, context) {
  try {
    if (
      !isRecord(output) ||
      Object.keys(output).length !== 1 ||
      !isRecord(output.result)
    ) {
      throw invalidRoleOutput(
        "Structured bootstrap role result must contain one result object.",
        context,
        { field: "result", constraint: "single-object-wrapper" },
      );
    }
    return normalize(output.result);
  } catch (cause) {
    if (cause?.code !== "ERR_INVALID_PLAN_EXECUTION_OUTPUT") {
      throw cause;
    }
    const diagnostics = outputDiagnostics(cause, context);
    throw new PlanExecutionWorkflowError(
      "Structured bootstrap role result violates its contract.",
      {
        code: cause.code,
        diagnostic: diagnostics[0],
        diagnostics,
      },
    );
  }
}

function normalizeBootstrapRoleOutputCandidate(
  output,
  role,
  phase = "bootstrap",
) {
  return normalizeRoleOutput(
    (value) => normalizeBootstrapResultCandidate(value, role),
    output,
    bootstrapOutputContext(role, phase),
  );
}

function normalizeBootstrapReconciliationOutput(
  output,
  phase = "bootstrap",
) {
  return normalizeRoleOutput(
    normalizeReconciliationResult,
    output,
    reconciliationOutputContext(phase),
  );
}

function normalizeBootstrapArbitrationOutput(output, phase = "bootstrap") {
  return normalizeRoleOutput(
    normalizeBootstrapArbitration,
    output,
    arbitrationOutputContext(phase),
  );
}

function normalizeValidationMigrationRoleOutput(output, role) {
  const candidate = normalizeBootstrapRoleOutputCandidate(
    output,
    role,
    "validation-migration",
  );
  const { result } = candidate;
  if (!["READY", "CAPACITY_EXHAUSTED"].includes(result.status)) {
    throw invalidRoleOutput(
      "Validation migration requires a ready inventory.",
      bootstrapOutputContext(role, "validation-migration"),
      { field: "status", constraint: "validation-migration-status" },
    );
  }
  return candidate;
}

function normalizeValidationMigrationReconciliationOutput(output) {
  const result = normalizeBootstrapReconciliationOutput(
    output,
    "validation-migration",
  );
  if (!["RESOLVED", "DISAGREEMENT"].includes(result.status)) {
    throw invalidRoleOutput(
      "Validation migration requires an inventory resolution.",
      reconciliationOutputContext("validation-migration"),
      { field: "status", constraint: "validation-migration-status" },
    );
  }
  return result;
}

function normalizeValidationMigrationArbitrationOutput(output) {
  const result = normalizeBootstrapArbitrationOutput(
    output,
    "validation-migration",
  );
  if (
    !["USE_WORKER", "USE_REVIEWER", "SYNTHESIZE"].includes(
      result.direction,
    )
  ) {
    throw invalidRoleOutput(
      "Validation migration requires an inventory direction.",
      arbitrationOutputContext("validation-migration"),
      {
        field: "direction",
        constraint: "validation-migration-direction",
      },
    );
  }
  return result;
}

function normalizeFinalizationRoleOutput(output, trustedCommands) {
  const context = finalizationOutputContext();
  try {
    return normalizeFinalizationResult(output, { trustedCommands });
  } catch (cause) {
    if (cause?.code !== "ERR_INVALID_PLAN_EXECUTION_OUTPUT") {
      throw cause;
    }
    const diagnostics = outputDiagnostics(cause, context);
    throw new PlanExecutionWorkflowError(
      "Structured finalization result violates its contract.",
      {
        code: cause.code,
        diagnostic: diagnostics[0],
        diagnostics,
      },
    );
  }
}

function normalizeReviewRoleOutput(
  output,
  previousFindings,
  validationChanged,
) {
  const context = reviewOutputContext();
  let result;
  try {
    result = normalizeReviewResult(output, previousFindings);
  } catch (cause) {
    if (cause?.code !== "ERR_INVALID_PLAN_EXECUTION_OUTPUT") {
      throw cause;
    }
    const diagnostics = outputDiagnostics(cause, context);
    throw new PlanExecutionWorkflowError(
      "Structured review result violates its contract.",
      {
        code: cause.code,
        diagnostic: diagnostics[0],
        diagnostics,
      },
    );
  }
  if (result.status === "PRODUCT_DECISION_REQUIRED") {
    return result;
  }
  const diagnostics = [
    ...(validationChanged && result.validationChange === "UNCHANGED"
      ? [
          {
            field: "validationChange",
            constraint: "matches-finalization-change",
          },
        ]
      : []),
    ...(!validationChanged && result.validationChange !== "UNCHANGED"
      ? [
          {
            field: "validationChange",
            constraint: "matches-finalization-change",
          },
        ]
      : []),
    ...(result.validationChange === "REJECTED" &&
    result.status !== "FINDINGS"
      ? [
          {
            field: "status",
            constraint: "findings-when-validation-rejected",
          },
        ]
      : []),
  ];
  if (diagnostics.length !== 0) {
    throw invalidRoleOutputBatch(
      "Reviewer returned an inconsistent validation-change decision.",
      context,
      diagnostics,
    );
  }
  return result;
}

export async function runPlanExecution({ action, run, runtime, settings }) {
  assertRun(run);
  assertRuntime(runtime, Object.keys(run.roles));
  const resumeAction = normalizeResumeAction(action);
  if (run.pipelineState.settings === null) {
    assertSettings(settings);
  }

  let currentRun = run;
  let interruptedTurn = run.activeTurn;
  let interruptedRepositoryReconciled = false;

  function state() {
    return normalizePipelineState(currentRun.pipelineState);
  }

  function counters() {
    return normalizedCounters(currentRun.counters);
  }

  function resolvedContext() {
    const summary = state().resolvedSummary;
    if (summary === null || state().validationMigrationPending) {
      return "";
    }
    return `Resolved bootstrap context:
${summary}

Phase ownership: the established required-check inventory is input only to FINALIZE. Staging, staged/index-relative inspection, alternate-index workarounds, staged handoff, and commit-message drafting belong only to COMMIT.`;
  }

  function trustedValidationInstructions() {
    const commands = state().trustedValidation.commands.map(
      ({ alias, command, identity }) => ({ alias, command, identity }),
    );
    if (commands.length === 0) {
      return "No runner-trusted validation commands are selected for this run.";
    }
    return `Runner-trusted validation commands selected before agent work:
${JSON.stringify(commands, null, 2)}
Include every listed command exactly once in requiredChecks. Do not execute these commands in an agent turn. During finalization, return NOT_RUN for only these checks with evidence that each is reserved for the runner; the runner will execute their persisted exact vectors outside the agent turn.`;
  }

  async function transition(
    nextPipelineState,
    {
      nextCounters = counters(),
      nextHashes = currentRun.hashes,
      pause = currentRun.pause,
      publicActivity,
    } = {},
  ) {
    const patch = {
      counters: nextCounters,
      hashes: nextHashes,
      pause,
      pipelineState: nextPipelineState,
    };
    assertRun({ ...currentRun, ...patch });
    currentRun = await runtime.transition(patch, { activity: publicActivity });
    assertRun(currentRun);
    return currentRun;
  }

  async function pause(reason, details = {}) {
    await transition(
      { ...state(), workflowState: "WAITING_FOR_USER" },
      {
        pause: { ...details, reason },
        publicActivity: activity(
          "runner",
          "plan-execution",
          "paused",
          `Plan execution paused: ${reason}.`,
        ),
      },
    );
    return currentRun;
  }

  async function pauseForBootstrapCapacity(role, result) {
    const field = result.capacityField;
    const limit = result.capacityLimit;
    await pause("bootstrap_inventory_capacity_exhausted", {
      code: "ERR_BOOTSTRAP_INVENTORY_CAPACITY_EXHAUSTED",
      explanation: `The ${role} bootstrap reported that the complete ${field} inventory exceeds the supported per-role limit of ${limit} items. Increase the bounded Runner contract or reduce the validation-controlling surface, then start a new run.`,
      evidence: [
        `Bootstrap role: ${role}.`,
        `Inventory field: ${field}.`,
        `Per-role item limit: ${limit}.`,
      ],
    });
    return false;
  }

  async function pausePreEffectCommitRejection(rejection) {
    const reason =
      rejection.recoverable ? "backend_unavailable" : "commit_failed";
    await transition(
      {
        ...state(),
        workflowState: "WAITING_FOR_USER",
        pendingCommit: null,
      },
      {
        pause: {
          reason,
          code: rejection.code,
          resumeState: "COMMIT",
        },
        publicActivity: activity(
          "runner",
          "commit",
          "authorization-retired",
          `Commit authorization retired before effect: ${reason}.`,
        ),
      },
    );
    return currentRun;
  }

  async function fail(cause) {
    const code = diagnosticCode(cause, "ERR_PLAN_EXECUTION_FAILED");
    const diagnostic =
      cause?.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT"
        ? persistedOutputDiagnostic(cause.diagnostic)
        : undefined;
    const diagnosticClass = adapterDiagnosticClass(cause);
    const message =
      diagnostic !== undefined
        ? `Plan execution failed: ${code} (${diagnostic.role}/${diagnostic.phase} ${diagnostic.field}: ${diagnostic.constraint}).`
        : diagnosticClass === undefined
          ? `Plan execution failed: ${code}.`
          : `Plan execution failed: ${code} (${diagnosticClass}).`;
    try {
      await transition(
        { ...state(), workflowState: "FAILED" },
        {
          pause: {
            reason: "internal_failure",
            code,
            ...(diagnostic === undefined ? {} : { diagnostic }),
            ...(diagnosticClass === undefined ? {} : { diagnosticClass }),
          },
          publicActivity: activity(
            "runner",
            "plan-execution",
            "failed",
            message,
          ),
        },
      );
    } catch {}
    throw cause;
  }

  async function invalidateInputs(
    reason,
    {
      code,
      message = "Plan-execution input changed outside an authorized window.",
      phase = "inputs",
    } = {},
  ) {
    const current = state();
    await transition(
      {
        ...current,
        workflowState: "WAITING_FOR_USER",
        clarificationFrozen: false,
        pendingEdit: null,
        workerSummary: null,
        reviewerSummary: null,
        workerValidation: null,
        reviewerValidation: null,
        resolvedSummary: null,
        bootstrapDisagreement: null,
        bootstrapArbitrationUsed: false,
        pendingBootstrapCorrection: null,
        finalizationCorrections: [],
        pendingFinalizationCorrection: null,
        reviewCorrection: null,
        pendingReviewCorrection: null,
        cleanConfirmationFingerprint: null,
        compatibilityCheckRequired: false,
        currentStep: null,
        reviewerStep: null,
        implementationDirection: null,
        finalizationResult: null,
        finalizedFingerprint: null,
        requiredChecks: null,
        validationInfrastructure: null,
        validationInfrastructureFingerprint: null,
        validationMigrationPending: false,
        reviewResult: null,
        reviewedFingerprint: null,
        findings: [],
        previousFindings: [],
        pendingDisputes: [],
        disputeCounts: {},
        disputeHistory: [],
        findingArbitrations: [],
        correctionHistory: [],
        sameFindingRounds: {},
        pendingCorrection: false,
        blockedSinceStagnation: 0,
        stagnationArbitrationUsed: false,
        stagnationDirection: null,
        reviewReconsideration: [],
        additionalFixRounds: 0,
        findingOverrides: [],
        pendingCommit: null,
      },
      {
        nextCounters: {
          ...counters(),
          fixRounds: 0,
          correctionRounds: 0,
        },
        pause: { reason, ...(code === undefined ? {} : { code }) },
        publicActivity: activity("runner", phase, "changed", message),
      },
    );
    return currentRun;
  }

  async function readInputs() {
    const inputs = normalizeInputSnapshot(
      await runtime.readInputs({ taskPath: currentRun.taskPath }),
      currentRun.taskPath,
    );
    return Object.freeze({
      inputs,
      canonicalPlan: canonicalPlan(inputs.plan.content),
    });
  }

  async function readCurrentInputs() {
    let input;
    try {
      input = await readInputs();
    } catch (cause) {
      if (
        !INPUT_DRIFT_ERROR_CODES.has(cause?.code) &&
        cause?.code !== INVALID_EXECUTION_INPUT_CODE &&
        cause?.code !== "ERR_INVALID_EXECUTION_PLAN"
      ) {
        throw cause;
      }
      await invalidateInputs("task_input_changed");
      return null;
    }
    let clarification;
    try {
      clarification = await runtime.clarifications.inspectTranscript({
        artifactRoot: state().repositoryBaseline.projectPath,
        transcriptPath: state().clarificationPath,
      });
    } catch (cause) {
      if (!INPUT_DRIFT_ERROR_CODES.has(cause?.code)) {
        throw cause;
      }
      await invalidateInputs("clarifications_changed");
      return null;
    }
    const nextHashes = {
      task: input.inputs.task.hash,
      plan: input.inputs.plan.hash,
      taskClarifications: input.inputs.taskClarifications?.hash ?? null,
      context: input.inputs.context?.hash ?? null,
      executionClarifications: clarification.hash,
    };
    const changedField = Object.keys(nextHashes).find(
      (field) => currentRun.hashes[field] !== nextHashes[field],
    );
    if (
      changedField !== undefined ||
      input.canonicalPlan !== state().canonicalPlan
    ) {
      await invalidateInputs(
        changedField === "executionClarifications"
          ? "clarifications_changed"
          : "task_input_changed",
      );
      return null;
    }
    return Object.freeze({ ...input, clarification });
  }

  async function verifyPersistedRepository() {
    try {
      await runtime.git.assertUnchanged(state().repositoryBaseline);
    } catch (cause) {
      if (cause?.code !== "ERR_READ_ONLY_REPOSITORY_CHANGED") {
        throw cause;
      }
      await pause("unsafe_git_state", { code: cause.code });
      return false;
    }
    return true;
  }

  async function recordSession(
    role,
    sessionId,
    continuedSessionId,
    contextKey,
  ) {
    if (typeof sessionId !== "string" || sessionId.length === 0) {
      throw workflowError(
        `${role} returned no session ID.`,
        "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      );
    }
    if (sessionId === currentRun.sessionLineage.source) {
      throw workflowError(
        `${role} returned the source session ID instead of a child session.`,
        "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      );
    }
    if (sessionId === continuedSessionId) {
      return;
    }
    if (
      currentRun.sessionLineage.children.some(
        (child) => child.sessionId === sessionId,
      )
    ) {
      throw workflowError(
        `${role} returned an existing session ID for a fresh turn.`,
        "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      );
    }
    currentRun = await runtime.recordChildSession(
      { role, sessionId, contextKey },
      {
        activity: activity(role, "session", "started", `${role} session recorded.`),
      },
    );
    assertRun(currentRun);
  }

  async function ensureRoleCapabilities(role) {
    if (state().backendVersions[role] !== null) {
      return;
    }
    let capabilities;
    try {
      capabilities = normalizeAdapterCapabilities(
        await runtime.adapters[role].probe(),
        role,
        currentRun.sessionLineage.source,
      );
    } catch (cause) {
      throw new PlanExecutionWorkflowError(`${role} backend is unavailable.`, {
        cause,
        code: "ERR_PLAN_EXECUTION_BACKEND_UNAVAILABLE",
      });
    }
    await transition(
      {
        ...state(),
        backendVersions: {
          ...state().backendVersions,
          [role]: capabilities.version,
        },
      },
      {
        publicActivity: activity(
          role,
          "preflight",
          "backend-ready",
          `${role} backend is ready.`,
        ),
      },
    );
  }

  function workspaceControlChange(before, after) {
    if (
      before.projectPath !== after.projectPath ||
      before.head !== after.head ||
      before.branch !== after.branch ||
      before.detached !== after.detached ||
      before.refsFingerprint !== after.refsFingerprint
    ) {
      return "unexpected_git_ref_change";
    }
    if (
      before.remoteConfigurationFingerprint !==
      after.remoteConfigurationFingerprint
    ) {
      return "unexpected_remote_configuration_change";
    }
    if (before.identityFingerprint !== after.identityFingerprint) {
      return "unexpected_git_identity_change";
    }
    return null;
  }

  function interruptedControlChange(cause) {
    if (cause?.changes?.includes("remote-configuration")) {
      return "unexpected_remote_configuration_change";
    }
    if (cause?.changes?.includes("identity")) {
      return "unexpected_git_identity_change";
    }
    return "unexpected_git_ref_change";
  }

  function interruptedTurnIsWritable(turn) {
    if (turn.role !== "worker") {
      return false;
    }
    if (turn.phase === "implement") {
      return true;
    }
    if (turn.phase === "finalize") {
      return state().pendingFinalizationCorrection === null;
    }
    if (turn.phase === "check-and-fix") {
      return true;
    }
    return (
      turn.phase === "resolve-findings" &&
      counters().fixRounds < fixBudget()
    );
  }

  function interruptedCorrectionWasReconciled(turn) {
    const current = state();
    return (
      turn.role === "worker" &&
      ((turn.phase === "check-and-fix" &&
        ["FINALIZE", "CLEAN_CONFIRM"].includes(current.workflowState)) ||
        (turn.phase === "resolve-findings" &&
          current.workflowState === "FINALIZE" &&
          current.pendingCorrection))
    );
  }

  async function recoverInterruptedTurn() {
    if (
      interruptedTurn === null ||
      (interruptedTurn.phase === "commit" &&
        state().pendingCommit?.status === "consumed")
    ) {
      return true;
    }
    if ((await readCurrentInputs()) === null) {
      return false;
    }
    const correctionWasReconciled =
      interruptedCorrectionWasReconciled(interruptedTurn);
    const supersededByValidationMigration =
      state().validationMigrationPending;
    const allowWorkspaceChanges = interruptedTurnIsWritable(interruptedTurn);
    let reconciledRepository;
    try {
      reconciledRepository = await runtime.git.reconcileInterrupted(
        state().repositoryBaseline,
        {
          allowWorkspaceChanges,
        },
      );
    } catch (cause) {
      if (cause?.code !== "ERR_INTERRUPTED_REPOSITORY_CONTROL_CHANGED") {
        throw cause;
      }
      await pause(interruptedControlChange(cause), { code: cause.code });
      return false;
    }
    interruptedRepositoryReconciled = true;
    const interruptedLazyCheckChanged =
      interruptedTurn.phase === "check-and-fix" &&
      state().workflowState === "CHECK_AND_FIX" &&
      state().repositoryBaseline.contentFingerprint !==
        reconciledRepository.contentFingerprint;
    if (supersededByValidationMigration) {
      const current = state();
      const contentChanged =
        current.repositoryBaseline.contentFingerprint !==
        reconciledRepository.contentFingerprint;
      const changedCorrection =
        interruptedTurn.phase === "resolve-findings" && contentChanged;
      if (!isDeepStrictEqual(reconciledRepository, current.repositoryBaseline)) {
        await transition(
          {
            ...current,
            repositoryBaseline: reconciledRepository,
            ...(contentChanged
              ? {
                  finalizationResult: null,
                  finalizedFingerprint: null,
                  reviewCorrection: null,
                  pendingReviewCorrection: null,
                  cleanConfirmationFingerprint: null,
                  reviewResult: null,
                  reviewedFingerprint: null,
                  previousFindings:
                    current.findings.length === 0
                      ? current.previousFindings
                      : current.findings,
                  findings: [],
                  reviewReconsideration: [],
                  ...(changedCorrection ? { pendingCorrection: true } : {}),
                }
              : {}),
          },
          changedCorrection
            ? {
                nextCounters: {
                  ...counters(),
                  fixRounds:
                    counters().fixRounds +
                    (current.pendingCorrection ? 0 : 1),
                },
              }
            : {},
        );
      }
      currentRun = await runtime.finishAgentTurn(interruptedTurn);
      assertRun(currentRun);
      interruptedTurn = null;
      interruptedRepositoryReconciled = false;
    } else if (interruptedLazyCheckChanged) {
      const current = state();
      await transition(
        {
          ...current,
          workflowState: "FINALIZE",
          repositoryBaseline: reconciledRepository,
          finalizationResult: null,
          finalizedFingerprint: null,
          reviewCorrection: null,
          pendingReviewCorrection: null,
          cleanConfirmationFingerprint: null,
          reviewResult: null,
          reviewedFingerprint: null,
          previousFindings:
            current.findings.length === 0
              ? current.previousFindings
              : current.findings,
          findings: [],
          pendingCorrection: true,
          reviewReconsideration: [],
        },
        {
          nextCounters: {
            ...counters(),
            fixRounds: counters().fixRounds + 1,
          },
        },
      );
      currentRun = await runtime.finishAgentTurn(interruptedTurn);
      assertRun(currentRun);
      interruptedTurn = null;
      interruptedRepositoryReconciled = false;
    } else if (correctionWasReconciled) {
      currentRun = await runtime.finishAgentTurn(interruptedTurn);
      assertRun(currentRun);
      interruptedTurn = null;
      interruptedRepositoryReconciled = false;
    }
    return true;
  }

  async function runRole(
    role,
    schema,
    buildPrompt,
    {
      access = "read-only",
      checkpoint,
      freshSession = false,
      recoveryContext = "",
    } = {},
  ) {
    const turn = activeTurn(role, state().workflowState);
    const recovering = interruptedTurn !== null;
    if (recovering && !isDeepStrictEqual(interruptedTurn, turn)) {
      throw workflowError(
        "Persisted agent turn does not match plan-execution recovery.",
        "ERR_INVALID_PLAN_EXECUTION_STATE",
      );
    }
    const outputContext = roleOutputContextFor(role, schema, checkpoint);
    await ensureRoleCapabilities(role);
    const evidence = await readCurrentInputs();
    if (evidence === null) {
      return null;
    }
    const baseline = state().repositoryBaseline;
    if (
      (!recovering || !interruptedRepositoryReconciled) &&
      !(await verifyPersistedRepository())
    ) {
      return null;
    }
    const turnSnapshot = await runtime.git.snapshot({
      allowedPaths: [],
      projectPath: baseline.projectPath,
    });
    const evidenceContext = inputEvidence(
      evidence.inputs,
      evidence.canonicalPlan,
      evidence.clarification,
    );
    const context = durableContext(evidenceContext, recoveryContext);
    const contextKey = contextKeyFor(role, checkpoint, evidenceContext);
    const latestSession = [...currentRun.sessionLineage.children]
      .reverse()
      .find((child) => child.role === role);
    const lazyPrimary = state().settings.mode === "lazy" && role === "worker";
    const previousSession =
      !recovering &&
      role !== "arbiter" &&
      (lazyPrimary || latestSession?.contextKey === contextKey) &&
      latestSession !== undefined
        ? latestSession.sessionId
        : undefined;
    const sourceSession = currentRun.sessionLineage.source;
    const session =
      freshSession
        ? undefined
        : previousSession !== undefined
          ? { id: previousSession, mode: "continue" }
          : !recovering &&
              sourceSession !== null &&
              role !== "arbiter" &&
              (!lazyPrimary || !state().lazySourceForkConsumed)
            ? { id: sourceSession, mode: "fork" }
            : undefined;
    const roleConfiguration = currentRun.roles[role];
    const recoveryPrompt = rolePrompt(buildPrompt(context));
    const executionPreferences = Object.fromEntries(
      ["profile", "model", "contextSize"].flatMap((field) =>
        typeof roleConfiguration[field] === "string" &&
        roleConfiguration[field] !== "current"
          ? [[field, roleConfiguration[field]]]
          : [],
      ),
    );
    const request = {
      access,
      cwd: currentRun.projectPath,
      prompt:
        session?.mode === "continue"
          ? rolePrompt(buildPrompt(""))
          : recoveryPrompt,
      recoveryPrompt,
      schema,
      ...executionPreferences,
      ...(session === undefined ? {} : { session }),
    };
    let response;
    let agentError;
    currentRun = await runtime.startAgentTurn(
      turn,
      lazyPrimary && session?.mode === "fork"
        ? {
            pipelineState: {
              ...state(),
              lazySourceForkConsumed: true,
            },
          }
        : undefined,
    );
    assertRun(currentRun);
    interruptedTurn = null;
    interruptedRepositoryReconciled = false;
    try {
      try {
        response = await runtime.adapters[role].run(request);
      } catch (cause) {
        agentError = cause;
      }
      let nextRepositoryBaseline = baseline;
      if (access === "read-only") {
        await runtime.git.assertUnchanged(turnSnapshot);
        await runtime.git.assertUnchanged(baseline);
      } else {
        nextRepositoryBaseline = await runtime.git.snapshot({
          allowedPaths: baseline.allowedPaths,
          projectPath: baseline.projectPath,
        });
        const reason = workspaceControlChange(
          turnSnapshot,
          nextRepositoryBaseline,
        );
        if (reason !== null) {
          await pause(reason);
          return null;
        }
      }
      if ((await readCurrentInputs()) === null) {
        return null;
      }
      if (access !== "read-only") {
        const current = state();
        const contentChanged =
          baseline.contentFingerprint !==
          nextRepositoryBaseline.contentFingerprint;
        const changedCorrection =
          current.workflowState === "RESOLVE_FINDINGS" &&
          contentChanged;
        const changedLazyCheck =
          current.workflowState === "CHECK_AND_FIX" && contentChanged;
        if (
          changedCorrection ||
          changedLazyCheck ||
          !isDeepStrictEqual(nextRepositoryBaseline, baseline)
        ) {
          await transition(
            changedCorrection || changedLazyCheck
              ? {
                  ...current,
                  workflowState: "FINALIZE",
                  repositoryBaseline: nextRepositoryBaseline,
                  finalizationResult: null,
                  finalizedFingerprint: null,
                  reviewCorrection: null,
                  pendingReviewCorrection: null,
                  cleanConfirmationFingerprint: null,
                  reviewResult: null,
                  reviewedFingerprint: null,
                  previousFindings:
                    current.findings.length === 0
                      ? current.previousFindings
                      : current.findings,
                  findings: [],
                  pendingCorrection: true,
                  reviewReconsideration: [],
                }
              : {
                  ...current,
                  repositoryBaseline: nextRepositoryBaseline,
                  ...(contentChanged
                    ? {
                        finalizationResult: null,
                        finalizedFingerprint: null,
                        reviewCorrection: null,
                        pendingReviewCorrection: null,
                        cleanConfirmationFingerprint: null,
                        reviewResult: null,
                        reviewedFingerprint: null,
                        previousFindings:
                          current.findings.length === 0
                            ? current.previousFindings
                            : current.findings,
                        findings: [],
                        reviewReconsideration: [],
                      }
                    : {}),
                },
            changedCorrection
              ? {
                  nextCounters: {
                    ...counters(),
                    fixRounds:
                      counters().fixRounds +
                      (current.pendingCorrection ? 0 : 1),
                  },
                }
              : changedLazyCheck
                ? {
                    nextCounters: {
                      ...counters(),
                      fixRounds: counters().fixRounds + 1,
                    },
                  }
              : {},
          );
        }
      }
    } finally {
      currentRun = await runtime.finishAgentTurn(turn);
      assertRun(currentRun);
    }
    if (agentError !== undefined) {
      if (
        outputContext !== undefined &&
        agentError?.failureClass === STRUCTURED_OUTPUT_FAILURE_CLASS
      ) {
        throw invalidRoleOutput(
          `${role} returned invalid structured output.`,
          outputContext,
          outputContext.contract === "review"
            ? {
                field: "result",
                constraint: "provider-structured-output",
              }
            : undefined,
        );
      }
      throw agentError;
    }
    if (!isRecord(response)) {
      throw outputContext === undefined
        ? workflowError(
            `${role} returned no response.`,
            "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
          )
        : invalidRoleOutput(`${role} returned no response.`, outputContext);
    }
    await recordSession(
      role,
      response.sessionId,
      previousSession,
      contextKey,
    );
    if (!isRecord(response.structured)) {
      throw outputContext === undefined
        ? workflowError(
            `${role} returned no structured result.`,
            "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
          )
        : invalidRoleOutput(
            `${role} returned no structured result.`,
            outputContext,
          );
    }
    return response.structured;
  }

  async function persistEdit(
    authorization,
    reason,
    {
      nextPipelineState = state(),
      nextCounters = counters(),
      nextHashes = currentRun.hashes,
      inputRequest: requestedInputRequest,
      publicActivity = activity(
        "runner",
        "clarification",
        "input-required",
        "Clarification input is required.",
      ),
    } = {},
  ) {
    const inputRequest = {
      id: authorization.id,
      kind: requestedInputRequest?.kind ?? "clarification",
      questions: requestedInputRequest?.questions ?? [],
      rationale:
        requestedInputRequest?.rationale ??
        "Optional task clarification before agent work begins.",
      artifactPath: authorization.transcriptPath,
    };
    await transition(
      {
        ...nextPipelineState,
        workflowState: "WAITING_FOR_USER",
        pendingEdit: authorization,
      },
      {
        nextCounters,
        nextHashes,
        pause: { reason, authorizationId: authorization.id, inputRequest },
        publicActivity,
      },
    );
  }

  async function prepareEdit(action, suspendedState, reason, options) {
    return runtime.clarifications.prepareEdit({
      artifactRoot: state().repositoryBaseline.projectPath,
      transcriptPath: state().clarificationPath,
      expectedHash: options?.expectedHash ?? currentRun.hashes.executionClarifications,
      suspendedState,
      action,
      persistPendingEdit: (authorization) =>
        persistEdit(authorization, reason, options),
    });
  }

  async function consumeEdit(result) {
    const current = state();
    if (!result.changed && result.action !== "proactive-clarification") {
      await prepareEdit(
        result.action,
        result.suspendedState,
        currentRun.pause.reason,
        {
          expectedHash: result.hash,
          inputRequest: currentRun.pause.inputRequest,
          nextPipelineState: { ...current, clarificationFrozen: false },
          nextHashes: {
            ...currentRun.hashes,
            executionClarifications: result.hash,
          },
        },
      );
      return;
    }
    const productDecision = result.action === "product-decision";
    const bootstrapDecision =
      productDecision && result.suspendedState === "BOOTSTRAP";
    await transition(
      {
        ...current,
        workflowState: result.suspendedState,
        pendingEdit: null,
        proactiveClarificationComplete:
          result.action === "proactive-clarification"
            ? true
            : current.proactiveClarificationComplete,
        clarificationFrozen: false,
        workerSummary: bootstrapDecision ? null : current.workerSummary,
        reviewerSummary: bootstrapDecision ? null : current.reviewerSummary,
        resolvedSummary: bootstrapDecision ? null : current.resolvedSummary,
        bootstrapDisagreement: bootstrapDecision
          ? null
          : current.bootstrapDisagreement,
        bootstrapArbitrationUsed: bootstrapDecision
          ? false
          : current.bootstrapArbitrationUsed,
        compatibilityCheckRequired:
          productDecision &&
          ["BOOTSTRAP", "IMPLEMENT"].includes(result.suspendedState),
        currentStep: bootstrapDecision ? null : current.currentStep,
      },
      {
        nextHashes: {
          ...currentRun.hashes,
          executionClarifications: result.hash,
        },
        pause: null,
        publicActivity: activity(
          "runner",
          "clarification",
          "accepted",
          "Authorized clarification input accepted.",
        ),
      },
    );
  }

  async function requestEdit(action, suspendedState, reason, options) {
    const authorization = await prepareEdit(
      action,
      suspendedState,
      reason,
      options,
    );
    const editorResult = await runtime.clarifications.openEditor(authorization, {
      consumePendingEdit: consumeEdit,
    });
    if (editorResult.status === "WAITING_FOR_USER") {
      return false;
    }
    return editorResult.result.changed || action === "proactive-clarification";
  }

  async function resumeEdit() {
    const authorization = state().pendingEdit;
    if (authorization === null) {
      return false;
    }
    const result = await runtime.clarifications.acceptEdit(authorization, {
      consumePendingEdit: consumeEdit,
    });
    return result.changed || result.action === "proactive-clarification";
  }

  async function productDecision(decision, suspendedState) {
    const count = counters().productDecisions + 1;
    const transcript = await runtime.clarifications.appendProductDecision({
      artifactRoot: state().repositoryBaseline.projectPath,
      transcriptPath: state().clarificationPath,
      expectedHash: currentRun.hashes.executionClarifications,
      number: count,
      ...decision,
    });
    const current = state();
    const bootstrapDecision = suspendedState === "BOOTSTRAP";
    return requestEdit(
      "product-decision",
      suspendedState,
      "product_decision_required",
      {
        expectedHash: transcript.hash,
        inputRequest: {
          kind: "product-decision",
          questions: [
            {
              id: "decision",
              question: decision.question,
              options: decision.options,
            },
          ],
          rationale: decision.whyBlocked,
        },
        nextPipelineState: {
          ...current,
          clarificationFrozen: false,
          workerSummary: bootstrapDecision ? null : current.workerSummary,
          reviewerSummary: bootstrapDecision ? null : current.reviewerSummary,
          workerValidation: bootstrapDecision ? null : current.workerValidation,
          reviewerValidation: bootstrapDecision
            ? null
            : current.reviewerValidation,
          resolvedSummary: bootstrapDecision ? null : current.resolvedSummary,
          bootstrapDisagreement: bootstrapDecision
            ? null
            : current.bootstrapDisagreement,
          bootstrapArbitrationUsed: bootstrapDecision
            ? false
            : current.bootstrapArbitrationUsed,
          compatibilityCheckRequired: false,
          currentStep: bootstrapDecision ? null : current.currentStep,
          implementationDirection: null,
          finalizationResult: null,
          finalizedFingerprint: null,
          reviewCorrection: null,
          pendingReviewCorrection: null,
          cleanConfirmationFingerprint: null,
          requiredChecks: bootstrapDecision ? null : current.requiredChecks,
          validationInfrastructure: bootstrapDecision
            ? null
            : current.validationInfrastructure,
          validationInfrastructureFingerprint: bootstrapDecision
            ? null
            : current.validationInfrastructureFingerprint,
          validationMigrationPending: bootstrapDecision
            ? false
            : current.validationMigrationPending,
          reviewResult: null,
          reviewedFingerprint: null,
          findings: [],
          previousFindings:
            current.findings.length === 0
              ? current.previousFindings
              : current.findings,
          pendingDisputes: [],
          disputeCounts: {},
          disputeHistory: [],
          findingArbitrations: [],
          sameFindingRounds: {},
          pendingCorrection: false,
          blockedSinceStagnation: 0,
          stagnationArbitrationUsed: false,
          stagnationDirection: null,
          reviewReconsideration: [],
        },
        nextCounters: { ...counters(), productDecisions: count },
        nextHashes: {
          ...currentRun.hashes,
          executionClarifications: transcript.hash,
        },
        publicActivity: activity(
          "runner",
          "clarification",
          "product-decision",
          "Blocking product decision recorded; user input is required.",
        ),
      },
    );
  }

  async function pauseForPlanRevision(result) {
    return pause("plan_revision_required", {
      explanation: result.reason,
      evidence: result.evidence,
    });
  }

  async function writeContext(path, content) {
    await runtime.writeRunArtifact({ path, content: `${content.trim()}\n` });
  }

  function planStep() {
    return parseCommitPlan(state().canonicalPlan).steps[state().currentStep - 1];
  }

  function fixBudget() {
    return state().settings.maxFixRoundsPerStep + state().additionalFixRounds;
  }

  function activeBlockers() {
    if (state().finalizationResult?.status === "FAIL") {
      return state().finalizationResult.issues.map((issue) => ({
        ...issue,
        source: "finalization",
      }));
    }
    return state().findings.map((finding) => ({
      ...finding,
      source: "review",
    }));
  }

  async function contentFingerprint() {
    return runtime.git.contentFingerprint({
      allowedPaths: [state().clarificationPath],
      projectPath: state().repositoryBaseline.projectPath,
    });
  }

  async function validationInfrastructureFingerprint(paths) {
    return runtime.git.validationInfrastructureFingerprint({
      paths,
      projectPath: state().repositoryBaseline.projectPath,
    });
  }

  function diagnosticMatchesContext(diagnostic, context) {
    return (
      diagnostic.role === context.role &&
      diagnostic.phase === context.phase &&
      diagnostic.contract === context.contract
    );
  }

  function correctionMatchesContext(correction, context) {
    return correction.diagnostics.every((diagnostic) =>
      diagnosticMatchesContext(diagnostic, context),
    );
  }

  function bootstrapCorrectionAttempt(context) {
    return state().bootstrapCorrections.find((correction) =>
      correctionMatchesContext(correction, context),
    );
  }

  function pendingBootstrapCorrection(context) {
    const correction = state().pendingBootstrapCorrection;
    return correction !== null && correctionMatchesContext(correction, context)
      ? correction
      : undefined;
  }

  function finalizationCorrectionAttempts(context) {
    return state().finalizationCorrections.filter(
      (correction) =>
        correction.step === state().currentStep &&
        correction.diagnostics.every((diagnostic) =>
          diagnosticMatchesContext(diagnostic, context),
        ),
    );
  }

  function pendingFinalizationCorrection(context, guidance) {
    const correction = state().pendingFinalizationCorrection;
    return correction !== null &&
      correction.step === state().currentStep &&
      correction.guidance === guidance &&
      correction.diagnostics.every((diagnostic) =>
        diagnosticMatchesContext(diagnostic, context),
      )
      ? correction
      : undefined;
  }

  function reviewCorrectionScope(current = state()) {
    return Object.freeze({
      attempt: 1,
      step: current.currentStep,
      contentFingerprint: current.finalizedFingerprint,
      validationInfrastructureFingerprint:
        current.finalizationResult.validationInfrastructureFingerprint,
    });
  }

  function reviewCorrectionMatchesScope(correction, scope) {
    return (
      correction !== null &&
      correction.attempt === scope.attempt &&
      correction.step === scope.step &&
      correction.contentFingerprint === scope.contentFingerprint &&
      correction.validationInfrastructureFingerprint ===
        scope.validationInfrastructureFingerprint
    );
  }

  async function validationInfrastructureDiagnostics(result, context) {
    if (!Array.isArray(result.validationInfrastructure)) {
      return Object.freeze([]);
    }
    const diagnostics = [];
    for (const [index, path] of result.validationInfrastructure.entries()) {
      let inspection;
      try {
        inspection = await runtime.git.inspectPath({
          path,
          projectPath: state().repositoryBaseline.projectPath,
        });
      } catch (cause) {
        if (!INVALID_VALIDATION_PATH_CODES.has(cause?.code)) {
          throw cause;
        }
        diagnostics.push(
          outputDiagnostic(
            {
              diagnostic: {
                field: `validationInfrastructure[${index}]`,
                constraint: "existing-canonical-repository-file",
              },
            },
            context,
          ),
        );
        continue;
      }
      if (
        !isRecord(inspection) ||
        inspection.exists !== true ||
        inspection.kind !== "file" ||
        inspection.relativePath !== path
      ) {
        diagnostics.push(
          outputDiagnostic(
            {
              diagnostic: {
                field: `validationInfrastructure[${index}]`,
                constraint: "existing-canonical-repository-file",
              },
            },
            context,
          ),
        );
      }
    }
    return outputDiagnostics({ diagnostics }, context);
  }

  async function inspectValidationInfrastructure(result, context, phase) {
    const diagnostics = await validationInfrastructureDiagnostics(
      result,
      context,
    );
    if (diagnostics.length !== 0) {
      throw invalidRoleOutputBatch(
        `${phase} validation infrastructure contains invalid paths.`,
        context,
        diagnostics,
      );
    }
    return result;
  }

  async function validateBootstrapInventory(
    result,
    context,
    candidateDiagnostics = [],
  ) {
    if (!Array.isArray(result.validationInfrastructure)) {
      return result;
    }
    const resolvedInventory =
      ["READY", "RESOLVED"].includes(result.status) ||
      ["USE_WORKER", "USE_REVIEWER", "SYNTHESIZE"].includes(
        result.direction,
      );
    const omitsTrustedCommand =
      resolvedInventory &&
      state().trustedValidation.commands.some(
        ({ command }) =>
          !result.requiredChecks.some(
            (required) => required.command === command,
          ),
      );
    const diagnostics = outputDiagnostics(
      {
        diagnostics: [
          ...candidateDiagnostics,
          ...(await validationInfrastructureDiagnostics(result, context)),
          ...(omitsTrustedCommand
            ? [
                outputDiagnostic(
                  {
                    diagnostic: {
                      field: "requiredChecks",
                      constraint: "includes-runner-trusted-commands",
                    },
                  },
                  context,
                ),
              ]
            : []),
        ],
      },
      context,
    ).slice(0, MAX_VALIDATION_ITEMS);
    if (diagnostics.length !== 0) {
      throw invalidRoleOutputBatch(
        "Bootstrap result violates its validation-inventory contract.",
        context,
        diagnostics,
      );
    }
    return result;
  }

  async function runBootstrapContract({
    role,
    schema,
    checkpoint,
    recoveryContext = "",
    buildPrompt,
    normalize,
    deferredDiagnostics = false,
  }) {
    const context = roleOutputContextFor(role, schema, checkpoint);
    while (true) {
      const correction = pendingBootstrapCorrection(context);
      try {
        const output = await runRole(
          role,
          schema,
          (evidence) => {
            const prompt = buildPrompt(evidence);
            return correction === undefined
              ? prompt
              : `${prompt}\n\n${BOOTSTRAP_CORRECTION_INSTRUCTIONS}\n\nCorrection diagnostic batch:\n${JSON.stringify(correction, null, 2)}`;
          },
          { checkpoint, recoveryContext },
        );
        if (output === null) {
          return null;
        }
        const normalized = normalize(output);
        const result = await validateBootstrapInventory(
          deferredDiagnostics ? normalized.result : normalized,
          context,
          deferredDiagnostics ? normalized.diagnostics : [],
        );
        if (correction !== undefined) {
          await transition({
            ...state(),
            pendingBootstrapCorrection: null,
          });
        }
        return result;
      } catch (cause) {
        if (
          cause?.code !== "ERR_INVALID_PLAN_EXECUTION_OUTPUT" ||
          !isOutputDiagnostic(cause.diagnostic)
        ) {
          throw cause;
        }
        if (bootstrapCorrectionAttempt(context) !== undefined) {
          throw cause;
        }
        const diagnostics = outputDiagnostics(cause, context).slice(
          0,
          MAX_VALIDATION_ITEMS,
        );
        const correction = { attempt: 1, diagnostics };
        const violationLabel =
          diagnostics.length === 1 ? "violation" : "violations";
        await transition(
          {
            ...state(),
            bootstrapCorrections: [
              ...state().bootstrapCorrections,
              correction,
            ],
            pendingBootstrapCorrection: correction,
          },
          {
            publicActivity: activity(
              context.role,
              context.phase,
              "bootstrap-correction",
              `${context.role} must correct ${diagnostics.length} ` +
                `${context.contract} contract ${violationLabel}.`,
            ),
          },
        );
      }
    }
  }

  async function establishedValidation() {
    const result = deriveValidationInventory(
      state().workerValidation,
      state().reviewerValidation,
    );
    return {
      requiredChecks: result.requiredChecks,
      validationInfrastructure: result.validationInfrastructure,
      validationInfrastructureFingerprint:
        await validationInfrastructureFingerprint(
          result.validationInfrastructure,
        ),
      validationMigrationPending: false,
    };
  }

  function invalidatedLegacyValidation(current) {
    return {
      ...current,
      finalizationCorrections: [],
      pendingFinalizationCorrection: null,
      reviewCorrection: null,
      pendingReviewCorrection: null,
      cleanConfirmationFingerprint: null,
      finalizationResult: null,
      finalizedFingerprint: null,
      reviewResult: null,
      reviewedFingerprint: null,
      previousFindings:
        current.findings.length === 0
          ? current.previousFindings
          : current.findings,
      findings: [],
      pendingDisputes: [],
      reviewReconsideration: [],
      pendingCommit: null,
    };
  }

  async function prepareValidationMigrationResume() {
    const current = state();
    if (
      !current.validationMigrationPending ||
      current.workflowState !== "WAITING_FOR_USER" ||
      current.pendingEdit !== null
    ) {
      return false;
    }
    const verifyConsumedCommit =
      current.pendingCommit?.status === "consumed" &&
      (["commit_failed", "commit_contract_violated"].includes(
        currentRun.pause?.reason,
      ) || currentRun.pause?.resumeState === "COMMIT");
    const resumeImplementation =
      currentRun.pause?.resumeState === "IMPLEMENT" &&
      current.finalizationResult === null;
    const additionalFixRounds =
      resumeAction?.type === "extra-fix-rounds"
        ? current.additionalFixRounds + resumeAction.amount
        : current.additionalFixRounds;
    await transition(
      verifyConsumedCommit
        ? { ...current, workflowState: "COMMIT", additionalFixRounds }
        : {
            ...invalidatedLegacyValidation(current),
            workflowState: resumeImplementation ? "IMPLEMENT" : "FINALIZE",
            additionalFixRounds,
          },
      {
        pause: null,
        publicActivity: activity(
          "runner",
          "migration",
          "validation-invalidated",
          verifyConsumedCommit
            ? "Legacy commit authorization retained for verification."
            : "Legacy validation evidence invalidated before resume.",
        ),
      },
    );
    return resumeAction !== null;
  }

  async function rediscoverValidationRole(role) {
    const result = await runBootstrapContract({
      role,
      schema: BOOTSTRAP_SCHEMA,
      checkpoint: "validation-migration",
      deferredDiagnostics: true,
      buildPrompt: (evidence) => `${BOOTSTRAP_INSTRUCTIONS}

This is a versioned-state migration checkpoint. Treat every persisted legacy summary, resolved context, check, path, fingerprint, and aggregate validation result as provisional. Independently re-establish the complete phase-safe summary and current validation inventory from repository evidence before work can advance.

${finalizationBootstrapInstructions(state().settings.finalization)}

${trustedValidationInstructions()}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}`,
      normalize: (output) =>
        normalizeValidationMigrationRoleOutput(output, role),
    });
    if (result === null) {
      return false;
    }
    if (result.status === "CAPACITY_EXHAUSTED") {
      return pauseForBootstrapCapacity(role, result);
    }
    await writeContext(`context/${role}.md`, result.summary);
    await transition(
      {
        ...state(),
        [`${role}Summary`]: result.summary,
        [`${role}Validation`]: {
          requiredChecks: result.requiredChecks,
          validationInfrastructure: result.validationInfrastructure,
        },
      },
      {
        publicActivity: activity(
          role,
          "migration",
          "validation-rediscovered",
          `${role} independently rediscovered validation requirements.`,
        ),
      },
    );
    return true;
  }

  async function completeValidationMigration(
    actor,
    summary,
    bootstrapArbitrationUsed,
  ) {
    const validation = await establishedValidation();
    await writeContext("context/resolved.md", summary);
    await transition(
      {
        ...state(),
        ...validation,
        finalizationCorrections: [],
        pendingFinalizationCorrection: null,
        resolvedSummary: summary,
        bootstrapDisagreement: null,
        bootstrapArbitrationUsed,
      },
      {
        publicActivity: activity(
          actor,
          "migration",
          "validation-established",
          "Legacy validation evidence was replaced with independent current evidence.",
        ),
      },
    );
    return true;
  }

  async function reconcileValidationMigration() {
    const result = await runBootstrapContract({
      role: "worker",
      schema: BOOTSTRAP_RECONCILIATION_SCHEMA,
      checkpoint: "validation-migration",
      buildPrompt: (evidence) => `${BOOTSTRAP_RECONCILIATION_INSTRUCTIONS}

Reconcile the independently re-established summaries and validation requirements. Every legacy summary, resolved context, and validation result is provisional and must not be selected.

${trustedValidationInstructions()}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Independent validation evidence:
${JSON.stringify(
  {
    worker: state().workerValidation,
    reviewer: state().reviewerValidation,
  },
  null,
  2,
)}`,
      normalize: normalizeValidationMigrationReconciliationOutput,
    });
    if (result === null) {
      return false;
    }
    if (result.status === "RESOLVED") {
      return completeValidationMigration("worker", result.summary, false);
    }
    const arbitration = await runBootstrapContract({
      role: "arbiter",
      schema: BOOTSTRAP_ARBITRATION_SCHEMA,
      checkpoint: "validation-migration",
      buildPrompt: (evidence) => `${BOOTSTRAP_ARBITRATION_INSTRUCTIONS}

Resolve only this summary and validation-inventory migration disagreement. Legacy summary, resolved context, and validation evidence is provisional and must not be selected.

${trustedValidationInstructions()}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Recorded disagreement:
${JSON.stringify(result.disagreement, null, 2)}

Independent validation evidence:
${JSON.stringify(
  {
    worker: state().workerValidation,
    reviewer: state().reviewerValidation,
  },
  null,
  2,
)}`,
      normalize: normalizeValidationMigrationArbitrationOutput,
    });
    if (arbitration === null) {
      return false;
    }
    return completeValidationMigration("arbiter", arbitration.summary, true);
  }

  async function runValidationMigration() {
    if (state().workerValidation === null) {
      return rediscoverValidationRole("worker");
    }
    if (state().reviewerValidation === null) {
      return rediscoverValidationRole("reviewer");
    }
    return reconcileValidationMigration();
  }

  async function resolveFinalizationGuidance() {
    const policy = state().settings.finalization;
    if (policy === "none") {
      return Object.freeze({ required: false, skillPath: null });
    }
    const candidates =
      policy === "auto"
        ? CONVENTIONAL_FINALIZATION_SKILL_PATHS
        : [policy];
    for (const skillPath of candidates) {
      let inspection;
      try {
        inspection = await runtime.git.inspectPath({
          path: skillPath,
          projectPath: state().repositoryBaseline.projectPath,
        });
      } catch (cause) {
        if (policy === "auto") {
          continue;
        }
        await pause("finalization_skill_invalid", {
          code: diagnosticCode(cause, "ERR_FINALIZATION_SKILL_INVALID"),
          explanation:
            "The explicitly configured finalization skill path is not safely confined to the repository.",
          evidence: [skillPath],
          resumeState: "FINALIZE",
          skillPath,
        });
        return null;
      }
      if (inspection.exists) {
        return Object.freeze({
          required: policy !== "auto",
          skillPath: inspection.relativePath,
        });
      }
    }
    if (policy !== "auto") {
      await pause("finalization_skill_missing", {
        explanation: "The explicitly configured finalization skill is missing.",
        evidence: [policy],
        resumeState: "FINALIZE",
        skillPath: policy,
      });
      return null;
    }
    return Object.freeze({ required: false, skillPath: null });
  }

  function correctionUpdate({ fingerprint, finalizationIssueIds, findingIds }) {
    const current = state();
    const currentCounters = counters();
    if (!current.pendingCorrection) {
      return Object.freeze({
        counters: currentCounters,
        history: current.correctionHistory,
        sameFindingRounds: current.sameFindingRounds,
        blockedSinceStagnation: current.blockedSinceStagnation,
      });
    }
    const correctionRounds = currentCounters.correctionRounds + 1;
    return Object.freeze({
      counters: {
        ...currentCounters,
        correctionRounds,
      },
      history: [
        ...current.correctionHistory,
        {
          round: correctionRounds,
          fingerprint,
          finalizationIssueIds,
          findingIds,
        },
      ].slice(-MAX_DIAGNOSTIC_ITEMS),
      sameFindingRounds: Object.fromEntries(
        findingIds.map((id) => [id, (current.sameFindingRounds[id] ?? 0) + 1]),
      ),
      blockedSinceStagnation: current.blockedSinceStagnation + 1,
    });
  }

  function exhaustedStableFindingIds() {
    return state().findings
      .map(({ id }) => id)
      .filter(
        (id) =>
          (state().sameFindingRounds[id] ?? 0) >=
          state().settings.maxSameFindingRounds,
      );
  }

  function latestDispute(findingId) {
    return [...state().disputeHistory]
      .reverse()
      .find((entry) => entry.findingId === findingId);
  }

  function priorFindingDecisions(findingIds) {
    const relevantIds =
      findingIds === undefined ? null : new Set(findingIds);
    return {
      disputes: state().disputeHistory.filter(({ findingId }) =>
        relevantIds === null || relevantIds.has(findingId),
      ),
      arbitrations: state().findingArbitrations.filter(({ findingId }) =>
        relevantIds === null || relevantIds.has(findingId),
      ),
      overrides: state().findingOverrides.filter(({ findingId }) =>
        relevantIds === null || relevantIds.has(findingId),
      ),
    };
  }

  function findingOverrideApplies(
    findingId,
    fingerprint,
    overrides = state().findingOverrides,
  ) {
    return overrides.some(
      (entry) =>
        entry.findingId === findingId && entry.fingerprint === fingerprint,
    );
  }

  function validationRejectionIsOverridden(
    findings,
    fingerprint,
    overrides = state().findingOverrides,
  ) {
    return (
      findings.length > 0 &&
      findings.every(({ id }) =>
        findingOverrideApplies(id, fingerprint, overrides),
      )
    );
  }

  function disputeNeedsArbitration(dispute) {
    const count = state().disputeCounts[dispute.findingId] ?? 0;
    const latest = latestDispute(dispute.findingId);
    return (
      count >= state().settings.maxDisputesPerFinding &&
      latest?.attempt === count &&
      latest.direction === "UPHOLD"
    );
  }

  async function initializeInputs() {
    const input = await readInputs();
    const discoveryOptions = {
      allowedPaths: [],
      projectPath: currentRun.projectPath,
      requireClean: true,
      requireIdentity: true,
      requiredIgnoredPaths: [],
    };
    let discovery;
    try {
      discovery = await runtime.git.preflight(discoveryOptions);
    } catch (cause) {
      if (GIT_PREFLIGHT_CODES.has(cause?.code)) {
        await pause("unsafe_git_state", { code: cause.code });
        return false;
      }
      throw cause;
    }
    const repositoryPath = discovery?.snapshot?.projectPath;
    if (
      !isRecord(discovery?.snapshot) ||
      typeof repositoryPath !== "string" ||
      !isAbsolute(repositoryPath) ||
      resolve(repositoryPath) !== repositoryPath ||
      !isWithin(repositoryPath, currentRun.projectPath)
    ) {
      throw workflowError("Git preflight returned an invalid repository root.");
    }
    const clarificationPath = join(
      repositoryPath,
      state().artifactRoot,
      "agent-runner",
      currentRun.runId,
      "clarifications.md",
    );
    let preflight;
    try {
      preflight = await runtime.git.preflight({
        allowedPaths: [clarificationPath],
        projectPath: repositoryPath,
        requireClean: true,
        requireIdentity: true,
        requiredIgnoredPaths: [clarificationPath],
      });
    } catch (cause) {
      if (cause?.code === "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED") {
        await pause("local_artifacts_not_ignored", { path: clarificationPath });
        return false;
      }
      if (GIT_PREFLIGHT_CODES.has(cause?.code)) {
        await pause("unsafe_git_state", { code: cause.code });
        return false;
      }
      throw cause;
    }
    if (preflight?.snapshot?.projectPath !== repositoryPath) {
      throw workflowError("Git preflight returned an unstable repository root.");
    }
    const preflightRoles = Object.keys(currentRun.roles).filter(
      (role) => role !== "arbiter",
    );
    let capabilitiesByRole;
    try {
      capabilitiesByRole = Object.fromEntries(
        await Promise.all(
          preflightRoles.map(async (role) => [
            role,
            normalizeAdapterCapabilities(
              await runtime.adapters[role].probe(),
              role,
              currentRun.sessionLineage.source,
            ),
          ]),
        ),
      );
    } catch (cause) {
      await pause("backend_unavailable", {
        code: diagnosticCode(cause, "ERR_BACKEND_UNAVAILABLE"),
      });
      return false;
    }
    const clarification = await runtime.clarifications.ensureTranscript({
      artifactRoot: repositoryPath,
      transcriptPath: clarificationPath,
    });
    await transition(
      {
        ...state(),
        preflightComplete: true,
        repositoryBaseline: preflight.snapshot,
        backendVersions: Object.fromEntries(
          Object.keys(currentRun.roles).map((role) => [
            role,
            role === "arbiter" ? null : capabilitiesByRole[role].version,
          ]),
        ),
        clarificationPath,
        canonicalPlan: input.canonicalPlan,
      },
      {
        nextHashes: {
          task: input.inputs.task.hash,
          plan: input.inputs.plan.hash,
          taskClarifications: input.inputs.taskClarifications?.hash ?? null,
          context: input.inputs.context?.hash ?? null,
          executionClarifications: clarification.hash,
        },
        publicActivity: activity(
          "runner",
          "preflight",
          "passed",
          "Plan-execution preflight passed and inputs were recorded.",
        ),
      },
    );
    return true;
  }

  async function bootstrapRole(role) {
    const result = await runBootstrapContract({
      role,
      schema: BOOTSTRAP_SCHEMA,
      checkpoint: "bootstrap",
      deferredDiagnostics: true,
      buildPrompt: (evidence) => `${BOOTSTRAP_INSTRUCTIONS}${
        role === "reviewer"
          ? "\nAs Reviewer, also state what you intend to verify."
          : ""
      }

${finalizationBootstrapInstructions(state().settings.finalization)}

${trustedValidationInstructions()}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}`,
      normalize: (output) =>
        normalizeBootstrapRoleOutputCandidate(output, role),
    });
    if (result === null) {
      return false;
    }
    if (result.status === "CAPACITY_EXHAUSTED") {
      return pauseForBootstrapCapacity(role, result);
    }
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    if (result.status === "PLAN_REVISION_REQUIRED") {
      await pauseForPlanRevision(result);
      return false;
    }
    await writeContext(`context/${role}.md`, result.summary);
    await transition(
      {
        ...state(),
        [`${role}Summary`]: result.summary,
        [`${role}Validation`]: {
          requiredChecks: result.requiredChecks,
          validationInfrastructure: result.validationInfrastructure,
        },
      },
      {
        publicActivity: activity(
          role,
          "bootstrap",
          "completed",
          `${role} bootstrap completed.`,
        ),
      },
    );
    return true;
  }

  async function completeLazyBootstrap() {
    const current = state();
    await writeContext("context/resolved.md", current.workerSummary);
    const validation = await establishedValidation();
    await transition(
      {
        ...current,
        workflowState: "IMPLEMENT",
        resolvedSummary: current.workerSummary,
        ...validation,
        currentStep: 1,
      },
      {
        publicActivity: activity(
          "worker",
          "bootstrap",
          "resolved",
          "Worker bootstrap context established for lazy execution.",
        ),
      },
    );
    return true;
  }

  async function reconcileBootstrap() {
    const result = await runBootstrapContract({
      role: "worker",
      schema: BOOTSTRAP_RECONCILIATION_SCHEMA,
      checkpoint: "bootstrap",
      buildPrompt: (evidence) => `${BOOTSTRAP_RECONCILIATION_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Worker bootstrap summary:
${state().workerSummary}

Reviewer bootstrap summary:
${state().reviewerSummary}

The runner will derive validation inventories from the independently accepted role evidence.`,
      normalize: normalizeBootstrapReconciliationOutput,
    });
    if (result === null) {
      return false;
    }
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    if (result.status === "PLAN_REVISION_REQUIRED") {
      await pauseForPlanRevision(result);
      return false;
    }
    if (result.status === "DISAGREEMENT") {
      await transition(
        { ...state(), bootstrapDisagreement: result.disagreement },
        {
          publicActivity: activity(
            "worker",
            "bootstrap",
            "disagreement",
            "Material bootstrap disagreement requires arbitration.",
          ),
        },
      );
      return true;
    }
    await writeContext("context/resolved.md", result.summary);
    const validation = await establishedValidation();
    await transition(
      {
        ...state(),
        workflowState: "IMPLEMENT",
        resolvedSummary: result.summary,
        ...validation,
        currentStep: 1,
      },
      {
        publicActivity: activity(
          "worker",
          "bootstrap",
          "resolved",
          "Bootstrap context resolved.",
        ),
      },
    );
    return true;
  }

  async function arbitrateBootstrap() {
    const result = await runBootstrapContract({
      role: "arbiter",
      schema: BOOTSTRAP_ARBITRATION_SCHEMA,
      checkpoint: "arbitration",
      buildPrompt: (evidence) => `${BOOTSTRAP_ARBITRATION_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Worker bootstrap summary:
${state().workerSummary}

Reviewer bootstrap summary:
${state().reviewerSummary}

Recorded disagreement:
${JSON.stringify(state().bootstrapDisagreement, null, 2)}

The runner will derive validation inventories from the independently accepted role evidence.`,
      normalize: normalizeBootstrapArbitrationOutput,
    });
    if (result === null) {
      return false;
    }
    if (result.direction === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    if (result.direction === "PLAN_REVISION_REQUIRED") {
      await pauseForPlanRevision(result);
      return false;
    }
    await writeContext("context/resolved.md", result.summary);
    const validation = await establishedValidation();
    await transition(
      {
        ...state(),
        workflowState: "IMPLEMENT",
        resolvedSummary: result.summary,
        ...validation,
        bootstrapDisagreement: null,
        bootstrapArbitrationUsed: true,
        currentStep: 1,
      },
      {
        publicActivity: activity(
          "arbiter",
          "bootstrap",
          "resolved",
          `Bootstrap Arbiter selected ${result.direction}.`,
        ),
      },
    );
    return true;
  }

  async function applyResumeAction() {
    if (resumeAction === null) {
      return true;
    }
    if (
      state().workflowState !== "WAITING_FOR_USER" ||
      state().pendingEdit !== null
    ) {
      throw workflowError("Resume action is not applicable to this run.");
    }
    if (
      (await readCurrentInputs()) === null ||
      !(await verifyPersistedRepository())
    ) {
      return false;
    }
    if (resumeAction.type === "extra-fix-rounds") {
      if (
        currentRun.pause.reason !== "fix_limit_reached" ||
        !["IMPLEMENT", "CHECK_AND_FIX", "RESOLVE_FINDINGS"].includes(
          currentRun.pause.resumeState,
        )
      ) {
        throw workflowError("Additional fix rounds are not applicable.");
      }
      const additionalFixRounds =
        state().additionalFixRounds + resumeAction.amount;
      if (
        !Number.isSafeInteger(additionalFixRounds) ||
        !Number.isSafeInteger(
          state().settings.maxFixRoundsPerStep + additionalFixRounds,
        )
      ) {
        throw workflowError("Additional fix-round budget is too large.");
      }
      await transition(
        {
          ...state(),
          workflowState: currentRun.pause.resumeState,
          additionalFixRounds,
        },
        {
          pause: null,
          publicActivity: activity(
            "runner",
            "resolution",
            "extra-fix-rounds",
            `${resumeAction.amount} additional fix rounds granted.`,
          ),
        },
      );
      return true;
    }
    if (
      state().settings.mode === "lazy" ||
      !["fix_limit_reached", "no_progress", "dispute_limit_reached"].includes(
        currentRun.pause.reason,
      ) ||
      state().finalizationResult?.status !== "PASS" ||
      state().reviewedFingerprint === null
    ) {
      throw workflowError("Finding override is not applicable.");
    }
    const finding = state().findings.find(
      ({ id }) => id === resumeAction.findingId,
    );
    if (
      finding === undefined ||
      (await contentFingerprint()) !== state().reviewedFingerprint ||
      findingOverrideApplies(
        resumeAction.findingId,
        state().reviewedFingerprint,
      )
    ) {
      throw workflowError("Finding override is stale or inapplicable.");
    }
    const findings = state().findings.filter(
      ({ id }) => id !== resumeAction.findingId,
    );
    const pendingDisputes = state().pendingDisputes.filter(
      ({ findingId }) => findingId !== resumeAction.findingId,
    );
    const findingOverrides = [
      ...state().findingOverrides,
      {
        findingId: resumeAction.findingId,
        fingerprint: state().reviewedFingerprint,
      },
    ].slice(-MAX_DIAGNOSTIC_ITEMS);
    const rejectedValidationResolved =
      state().reviewResult?.validationChange === "REJECTED" &&
      validationRejectionIsOverridden(
        state().previousFindings,
        state().reviewedFingerprint,
        findingOverrides,
      );
    await transition(
      {
        ...state(),
        workflowState:
          findings.length === 0 && pendingDisputes.length === 0
            ? state().reviewResult?.validationChange === "REJECTED" &&
              !rejectedValidationResolved
              ? "REVIEW"
              : "COMMIT"
            : "RESOLVE_FINDINGS",
        findings,
        pendingDisputes,
        reviewReconsideration: state().reviewReconsideration.filter(
          (id) => id !== resumeAction.findingId,
        ),
        findingOverrides,
      },
      {
        pause: null,
        publicActivity: activity(
          "runner",
          "resolution",
          "finding-overridden",
          `Finding ${resumeAction.findingId} explicitly overridden.`,
        ),
      },
    );
    return true;
  }

  async function runImplementationTurn() {
    const current = state();
    const correction = current.implementationDirection !== null;
    if (correction && counters().fixRounds >= fixBudget()) {
      await pause("fix_limit_reached", {
        fixRounds: counters().fixRounds,
        resumeState: "IMPLEMENT",
      });
      return false;
    }
    const step = planStep();
    const output = await runRole(
      "worker",
      IMPLEMENTATION_SCHEMA,
      (evidence) => `${IMPLEMENTATION_INSTRUCTIONS}

${evidence}

Current planned commit:
## Commit ${step.number}: ${step.subject}

${step.body}${
        current.implementationDirection === null
          ? ""
          : `\n\nRequired rework direction:\n${JSON.stringify(current.implementationDirection, null, 2)}\n\nPersisted correction context:\n${JSON.stringify(
              {
                previousFindings: current.previousFindings,
                pendingDisputes: current.pendingDisputes,
                correctionHistory: current.correctionHistory,
                priorDecisions: priorFindingDecisions(),
              },
              null,
              2,
            )}`
      }`,
      {
        access: "workspace-write",
        checkpoint: `commit:${current.currentStep}`,
        recoveryContext: resolvedContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeImplementationResult(output);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    if (result.status === "BLOCKED") {
      await pause("environment_blocked", {
        explanation: result.reason,
        evidence: result.evidence,
        resumeState: "IMPLEMENT",
      });
      return false;
    }
    const nextCounters = correction
      ? { ...counters(), fixRounds: counters().fixRounds + 1 }
      : counters();
    await transition(
      {
        ...state(),
        workflowState: "FINALIZE",
        implementationDirection: null,
        finalizationResult: null,
        finalizedFingerprint: null,
        reviewCorrection: null,
        pendingReviewCorrection: null,
        cleanConfirmationFingerprint: null,
        reviewResult: null,
        reviewedFingerprint: null,
        findings: [],
        pendingDisputes: correction ? current.pendingDisputes : [],
        pendingCorrection: correction,
        reviewReconsideration: [],
      },
      {
        nextCounters,
        publicActivity: activity(
          "worker",
          "implementation",
          correction ? "reworked" : "completed",
          correction
            ? "Implementation rework completed."
            : "Planned implementation completed.",
        ),
      },
    );
    return true;
  }

  async function runFinalizationTurn() {
    const step = planStep();
    let persistedCorrection = state().pendingFinalizationCorrection;
    const beforeFingerprint =
      persistedCorrection?.contentFingerprint ?? (await contentFingerprint());
    if (
      persistedCorrection === null &&
      state().finalizationCorrections.length !== 0 &&
      state().finalizationCorrections[0].contentFingerprint !==
        beforeFingerprint
    ) {
      await transition({
        ...state(),
        finalizationCorrections: [],
      });
      persistedCorrection = null;
    }
    const fallbackGuidance = Object.freeze({
      required: false,
      skillPath: null,
    });
    const guidance =
      persistedCorrection?.guidance === "fallback"
        ? fallbackGuidance
        : await resolveFinalizationGuidance();
    if (guidance === null) {
      return false;
    }
    async function requestFinalization(selectedGuidance, guidanceScope) {
      const context = finalizationOutputContext();
      while (true) {
        const correction = pendingFinalizationCorrection(
          context,
          guidanceScope,
        );
        try {
          const output = await runRole(
            "worker",
            FINALIZATION_SCHEMA,
            (evidence) => `${FINALIZATION_INSTRUCTIONS}

${finalizationGuidanceInstructions(selectedGuidance)}

${trustedValidationInstructions()}

${evidence}

Current planned commit:
## Commit ${step.number}: ${step.subject}

${step.body}${
              state().settings.mode === "lazy" &&
              state().previousFindings.length > 0
                ? `\n\nLazy clean-confirmation findings requiring correction:\n${JSON.stringify(state().previousFindings, null, 2)}`
                : ""
            }
${
              correction === undefined
                ? ""
                : `\n${FINALIZATION_CORRECTION_INSTRUCTIONS}\n\n` +
                  `Correction diagnostic batch:\n${JSON.stringify(correction, null, 2)}`
            }`,
            {
              access:
                correction === undefined ? "workspace-write" : "read-only",
              checkpoint:
                correction === undefined
                  ? `commit:${state().currentStep}`
                  : `finalization-correction:${state().currentStep}`,
              freshSession: correction !== undefined,
              recoveryContext: resolvedContext(),
            },
          );
          if (output === null) {
            return null;
          }
          const result = normalizeFinalizationRoleOutput(
            output,
            state().trustedValidation.commands.map(({ command }) => command),
          );
          await inspectValidationInfrastructure(
            result,
            context,
            "Finalization",
          );
          if (
            selectedGuidance.skillPath === null &&
            ["SKILL_MISSING", "SKILL_INVALID"].includes(result.status)
          ) {
            throw invalidRoleOutput(
              "Worker returned a skill availability status without selected finalization skill guidance.",
              context,
              {
                field: "status",
                constraint: "selected-finalization-guidance",
              },
            );
          }
          if (
            result.status !== "PRODUCT_DECISION_REQUIRED" &&
            result.skillPath !== selectedGuidance.skillPath
          ) {
            throw invalidRoleOutput(
              "Worker returned a finalization result for the wrong skill path.",
              context,
              {
                field: "skillPath",
                constraint: "resolved-finalization-skill",
              },
            );
          }
          if (
            !["SKILL_MISSING", "SKILL_INVALID"].includes(result.status) &&
            state().trustedValidation.commands.some(
              ({ command }) =>
                !result.requiredChecks.some(
                  (required) => required.command === command,
                ),
            )
          ) {
            throw invalidRoleOutput(
              "Worker omitted a runner-trusted finalization command.",
              context,
              {
                field: "requiredChecks",
                constraint: "includes-runner-trusted-commands",
              },
            );
          }
          if (correction !== undefined) {
            await transition({
              ...state(),
              pendingFinalizationCorrection: null,
            });
          }
          return result;
        } catch (cause) {
          if (
            cause?.code !== "ERR_INVALID_PLAN_EXECUTION_OUTPUT" ||
            !isOutputDiagnostic(cause.diagnostic)
          ) {
            throw cause;
          }
          const diagnostics = outputDiagnostics(cause, context);
          const attempts = finalizationCorrectionAttempts(context);
          const previousDiagnostics = attempts.flatMap(
            (attempt) => attempt.diagnostics,
          );
          if (
            attempts.length >= MAX_FINALIZATION_CORRECTION_ATTEMPTS ||
            diagnostics.some((diagnostic) =>
              previousDiagnostics.some((previous) =>
                isDeepStrictEqual(previous, diagnostic),
              ),
            )
          ) {
            throw cause;
          }
          const correction = {
            attempt: attempts.length + 1,
            step: state().currentStep,
            guidance: guidanceScope,
            contentFingerprint: beforeFingerprint,
            diagnostics,
          };
          const violationLabel =
            diagnostics.length === 1 ? "violation" : "violations";
          const correctionMessage =
            `${context.role} must correct ${diagnostics.length} ` +
            `${context.contract} contract ${violationLabel}.`;
          await transition(
            {
              ...state(),
              finalizationCorrections: [
                ...state().finalizationCorrections,
                correction,
              ],
              pendingFinalizationCorrection: correction,
            },
            {
              publicActivity: activity(
                context.role,
                context.phase,
                "finalization-correction",
                correctionMessage,
              ),
            },
          );
        }
      }
    }
    let result = await requestFinalization(
      guidance,
      persistedCorrection?.guidance ?? "resolved",
    );
    if (result === null) {
      return false;
    }
    if (
      guidance.skillPath !== null &&
      !guidance.required &&
      ["SKILL_MISSING", "SKILL_INVALID"].includes(result.status)
    ) {
      if ((await contentFingerprint()) !== beforeFingerprint) {
        await pause("finalization_cannot_pass", {
          code: "ERR_FINALIZATION_MODIFIED_BEFORE_VALIDATION",
          explanation: result.reason,
          evidence: result.evidence,
          ...(result.skillPath === null ? {} : { skillPath: result.skillPath }),
          resumeState: "FINALIZE",
        });
        return false;
      }
      result = await requestFinalization(fallbackGuidance, "fallback");
      if (result === null) {
        return false;
      }
    }
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    if (result.status === "BLOCKED") {
      await pause("environment_blocked", {
        explanation: result.reason,
        evidence: result.evidence,
        ...(result.skillPath === null ? {} : { skillPath: result.skillPath }),
        resumeState: "FINALIZE",
      });
      return false;
    }
    if (["SKILL_MISSING", "SKILL_INVALID"].includes(result.status)) {
      const modifiedBeforeValidation =
        (await contentFingerprint()) !== beforeFingerprint;
      const reasons = {
        SKILL_MISSING: "finalization_skill_missing",
        SKILL_INVALID: "finalization_skill_invalid",
      };
      await pause(
        modifiedBeforeValidation
          ? "finalization_cannot_pass"
          : reasons[result.status],
        {
          explanation: result.reason,
          evidence: result.evidence,
          ...(modifiedBeforeValidation
            ? { code: "ERR_FINALIZATION_MODIFIED_BEFORE_VALIDATION" }
            : {}),
          ...(result.skillPath === null ? {} : { skillPath: result.skillPath }),
          resumeState: "FINALIZE",
        },
      );
      return false;
    }
    const fingerprint = await contentFingerprint();
    const candidateValidationFingerprint =
      await validationInfrastructureFingerprint(
        result.validationInfrastructure,
      );
    const trustedByCommand = new Map(
      state().trustedValidation.commands.map((command) => [
        command.command,
        command,
      ]),
    );
    const bindings = Object.freeze({
      contentFingerprint: fingerprint,
      validationInfrastructureFingerprint: candidateValidationFingerprint,
      commandFingerprint: state().trustedValidation.commandFingerprint,
      configurationFingerprint:
        state().trustedValidation.configurationFingerprint,
    });
    const checks = [];
    const issues = [...result.issues];
    const issueIds = new Set(issues.map(({ id }) => id));
    let nextIssue = 1;
    for (const [index, required] of result.requiredChecks.entries()) {
      const reported = result.checks[index];
      const trusted = trustedByCommand.get(required.command);
      if (trusted === undefined) {
        checks.push({
          ...reported,
          executor: "agent",
          commandIdentity: null,
          exitCode: null,
          signal: null,
          timedOut: false,
        });
        continue;
      }
      let executed;
      try {
        executed = await runtime.trustedValidation.execute({
          bindings,
          commandIdentity: trusted.identity,
          projectPath: state().repositoryBaseline.projectPath,
          snapshot: state().trustedValidation,
        });
      } catch (cause) {
        if (
          ![
            "ERR_TRUSTED_VALIDATION_BINDING_CHANGED",
            "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY",
            "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE",
          ].includes(cause?.code)
        ) {
          throw cause;
        }
        await pause("unsafe_git_state", {
          code: cause.code,
        });
        return false;
      }
      const completedValidationFingerprint =
        await validationInfrastructureFingerprint(
          result.validationInfrastructure,
        );
      if (completedValidationFingerprint !== candidateValidationFingerprint) {
        await pause("unsafe_git_state", {
          code: "ERR_TRUSTED_VALIDATION_INFRASTRUCTURE_CHANGED",
        });
        return false;
      }
      if (executed.status === "BLOCKED") {
        await pause("environment_blocked", {
          code: "ERR_TRUSTED_VALIDATION_BLOCKED",
          explanation:
            "A selected runner-trusted validation command could not complete in the host environment.",
          evidence: executed.evidence,
          resumeState: "FINALIZE",
        });
        return false;
      }
      checks.push({
        checkId: required.id,
        command: required.command,
        status: executed.status,
        evidence: executed.evidence,
        executor: "runner",
        commandIdentity: executed.commandIdentity,
        exitCode: executed.exitCode,
        signal: executed.signal,
        timedOut: executed.timedOut,
      });
      if (executed.status === "FAIL") {
        while (issueIds.has(`F${nextIssue}`)) {
          nextIssue += 1;
        }
        const id = `F${nextIssue}`;
        issueIds.add(id);
        nextIssue += 1;
        issues.push({
          id,
          command: required.command,
          problem: "A runner-trusted validation command failed.",
          evidence: executed.evidence,
        });
      }
    }
    const finalStatus = issues.length === 0 ? "PASS" : "FAIL";
    const validationChanged =
      !isDeepStrictEqual(result.requiredChecks, state().requiredChecks) ||
      !isDeepStrictEqual(
        result.validationInfrastructure,
        state().validationInfrastructure,
      ) ||
      candidateValidationFingerprint !==
        state().validationInfrastructureFingerprint;
    const finalizationResult = {
      ...result,
      status: finalStatus,
      summary:
        finalStatus === result.status
          ? result.summary
          : "The project finalization procedure found blocking failures.",
      issues,
      checks,
      validationInfrastructureFingerprint: candidateValidationFingerprint,
      trustedCommandFingerprint:
        state().trustedValidation.commandFingerprint,
      trustedConfigurationFingerprint:
        state().trustedValidation.configurationFingerprint,
      validationChanged,
      fingerprint,
    };
    if (finalStatus === "FAIL") {
      const correction = correctionUpdate({
        fingerprint,
        finalizationIssueIds: issues.map(({ id }) => id),
        findingIds: [],
      });
      await transition(
        {
          ...state(),
          workflowState: "RESOLVE_FINDINGS",
          finalizationResult,
          finalizedFingerprint: null,
          reviewCorrection: null,
          pendingReviewCorrection: null,
          cleanConfirmationFingerprint: null,
          reviewResult: null,
          reviewedFingerprint: null,
          findings: [],
          pendingDisputes: state().pendingDisputes,
          correctionHistory: correction.history,
          sameFindingRounds: correction.sameFindingRounds,
          pendingCorrection: false,
          blockedSinceStagnation: correction.blockedSinceStagnation,
          reviewReconsideration: [],
        },
        {
          nextCounters: correction.counters,
          publicActivity: activity(
            "worker",
            "finalization",
            "failed",
            `Finalization reported ${issues.length} blocking issues.`,
          ),
        },
      );
      return true;
    }
    await transition(
      {
        ...state(),
        workflowState:
          state().settings.mode === "lazy" ? "CHECK_AND_FIX" : "REVIEW",
        finalizationResult,
        finalizedFingerprint: fingerprint,
        cleanConfirmationFingerprint: null,
        reviewResult: null,
        reviewedFingerprint: null,
        findings: [],
        pendingDisputes: state().pendingDisputes,
        reviewReconsideration: [],
      },
      {
        publicActivity: activity(
          "worker",
          "finalization",
          "passed",
          "Project finalization passed.",
        ),
      },
    );
    return true;
  }

  function lazyValidationPrompt(current) {
    return `Established validation tuple:
${JSON.stringify(
  {
    requiredChecks: current.requiredChecks,
    validationInfrastructure: current.validationInfrastructure,
    validationInfrastructureFingerprint:
      current.validationInfrastructureFingerprint,
    trustedCommandFingerprint:
      current.trustedValidation.commandFingerprint,
    trustedConfigurationFingerprint:
      current.trustedValidation.configurationFingerprint,
  },
  null,
  2,
)}

Candidate validation tuple and finalization evidence:
${JSON.stringify(current.finalizationResult, null, 2)}`;
  }

  async function runCheckAndFixTurn() {
    const current = state();
    if (counters().fixRounds >= fixBudget()) {
      await pause("fix_limit_reached", {
        fixRounds: counters().fixRounds,
        resumeState: "CHECK_AND_FIX",
      });
      return false;
    }
    const stableFindingIds = exhaustedStableFindingIds();
    if (stableFindingIds.length > 0) {
      await pause("no_progress", {
        findingIds: stableFindingIds,
        reason: "stable_findings",
        resumeState: "CHECK_AND_FIX",
      });
      return false;
    }
    if (
      current.blockedSinceStagnation >=
      current.settings.stagnationWindowRounds
    ) {
      await pause("no_progress", {
        correctionRounds: counters().correctionRounds,
        reason: "recurrent_stagnation",
        resumeState: "CHECK_AND_FIX",
      });
      return false;
    }
    const step = planStep();
    const beforeFingerprint = await contentFingerprint();
    const output = await runRole(
      "worker",
      CHECK_AND_FIX_SCHEMA,
      (evidence) => `${CHECK_AND_FIX_INSTRUCTIONS}

${evidence}

Current planned commit:
## Commit ${step.number}: ${step.subject}

${step.body}

${lazyValidationPrompt(state())}

Concrete findings from the preceding clean confirmation:
${JSON.stringify(state().findings, null, 2)}`,
      {
        access: "workspace-write",
        checkpoint: `lazy-commit:${current.currentStep}`,
        recoveryContext: resolvedContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeCheckAndFixResult(output);
    const changed = (await contentFingerprint()) !== beforeFingerprint;
    if (
      (result.status === "CHANGED") !== changed &&
      !["BLOCKED", "PRODUCT_DECISION_REQUIRED"].includes(result.status)
    ) {
      throw workflowError(
        "Worker check/fix status does not match the repository change.",
        "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      );
    }
    if (result.status === "REFINALIZE" && current.findings.length === 0) {
      throw workflowError(
        "Worker requested re-finalization without a clean-confirmation finding.",
        "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      );
    }
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    if (result.status === "BLOCKED") {
      await pause("environment_blocked", {
        explanation: result.reason,
        evidence: result.evidence,
        resumeState: changed ? "FINALIZE" : "CHECK_AND_FIX",
      });
      return false;
    }
    if (changed) {
      await transition(
        { ...state() },
        {
          publicActivity: activity(
            "worker",
            "check-and-fix",
            "changed",
            "Worker check/fix changed content; full finalization is required again.",
          ),
        },
      );
      return true;
    }
    if (result.status === "REFINALIZE") {
      await transition(
        {
          ...state(),
          workflowState: "FINALIZE",
          finalizationResult: null,
          finalizedFingerprint: null,
          reviewCorrection: null,
          pendingReviewCorrection: null,
          cleanConfirmationFingerprint: null,
          reviewResult: null,
          reviewedFingerprint: null,
          previousFindings:
            current.findings.length === 0
              ? current.previousFindings
              : current.findings,
          findings: [],
          pendingCorrection: true,
          reviewReconsideration: [],
        },
        {
          nextCounters: {
            ...counters(),
            fixRounds: counters().fixRounds + 1,
          },
          publicActivity: activity(
            "worker",
            "check-and-fix",
            "refinalize",
            "Worker requested corrected finalization evidence without a content change.",
          ),
        },
      );
      return true;
    }
    const fixingConfirmationFindings = current.findings.length > 0;
    await transition(
      {
        ...state(),
        workflowState: "CLEAN_CONFIRM",
        reviewResult: null,
        reviewedFingerprint: null,
        previousFindings: fixingConfirmationFindings
          ? current.findings
          : current.previousFindings,
        findings: [],
        pendingCorrection:
          current.pendingCorrection || fixingConfirmationFindings,
      },
      {
        nextCounters: {
          ...counters(),
          fixRounds: counters().fixRounds + 1,
        },
        publicActivity: activity(
          "worker",
          "check-and-fix",
          "unchanged",
          "Worker check/fix reported unchanged content; clean confirmation is required.",
        ),
      },
    );
    return true;
  }

  async function runCleanConfirmTurn() {
    const current = state();
    const step = planStep();
    const inspectedFingerprint = current.finalizedFingerprint;
    const inspectedValidationFingerprint =
      current.finalizationResult.validationInfrastructureFingerprint;
    const output = await runRole(
      "worker",
      CLEAN_CONFIRM_SCHEMA,
      (evidence) => `${CLEAN_CONFIRM_INSTRUCTIONS}

${evidence}

Current planned commit:
## Commit ${step.number}: ${step.subject}

${step.body}

Finalized content fingerprint: ${inspectedFingerprint}
Validation-infrastructure fingerprint: ${inspectedValidationFingerprint}

${lazyValidationPrompt(state())}

Previous clean-confirmation findings for this step:
${JSON.stringify(state().previousFindings, null, 2)}`,
      {
        checkpoint: `lazy-commit:${current.currentStep}`,
        recoveryContext: resolvedContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeCleanConfirmationResult(
      output,
      current.previousFindings,
    );
    const confirmedFingerprint = await contentFingerprint();
    const confirmedValidationFingerprint =
      await validationInfrastructureFingerprint(
        current.finalizationResult.validationInfrastructure,
      );
    if (
      confirmedFingerprint !== inspectedFingerprint ||
      confirmedValidationFingerprint !== inspectedValidationFingerprint
    ) {
      await pause("unsafe_git_state", {
        code: "ERR_CLEAN_CONFIRMATION_FINGERPRINT_CHANGED",
      });
      return false;
    }
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    const validationChanged = current.finalizationResult.validationChanged;
    if (
      (validationChanged && result.validationChange === "UNCHANGED") ||
      (!validationChanged && result.validationChange !== "UNCHANGED")
    ) {
      throw workflowError(
        "Clean confirmation returned an inconsistent validation-change decision.",
        "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      );
    }
    const reviewResult = {
      status: result.status === "CLEAN" ? "APPROVED" : "FINDINGS",
      validationChange: result.validationChange,
      validationEvidence: result.validationEvidence,
      fingerprint: confirmedFingerprint,
    };
    const acceptedValidation =
      result.validationChange === "ACCEPTED"
        ? {
            requiredChecks: current.finalizationResult.requiredChecks,
            validationInfrastructure:
              current.finalizationResult.validationInfrastructure,
            validationInfrastructureFingerprint:
              current.finalizationResult.validationInfrastructureFingerprint,
          }
        : {};
    if (result.status === "FINDINGS") {
      const correction = correctionUpdate({
        fingerprint: confirmedFingerprint,
        finalizationIssueIds: [],
        findingIds: result.findings.map(({ id }) => id),
      });
      await transition(
        {
          ...state(),
          ...acceptedValidation,
          workflowState: "CHECK_AND_FIX",
          reviewResult,
          reviewedFingerprint: confirmedFingerprint,
          findings: result.findings,
          previousFindings: result.findings,
          correctionHistory: correction.history,
          sameFindingRounds: correction.sameFindingRounds,
          pendingCorrection: false,
          blockedSinceStagnation: correction.blockedSinceStagnation,
        },
        {
          nextCounters: correction.counters,
          publicActivity: activity(
            "worker",
            "clean-confirm",
            "findings",
            `Clean confirmation returned ${result.findings.length} blocking findings.`,
          ),
        },
      );
      return true;
    }
    await transition(
      {
        ...state(),
        ...acceptedValidation,
        workflowState: "COMMIT",
        reviewResult,
        reviewedFingerprint: confirmedFingerprint,
        cleanConfirmationFingerprint: confirmedFingerprint,
        findings: [],
        previousFindings: [],
        pendingCorrection: false,
      },
      {
        publicActivity: activity(
          "worker",
          "clean-confirm",
          "clean",
          "Worker clean confirmation accepted for unchanged finalized content.",
        ),
      },
    );
    return true;
  }

  async function runReviewTurn() {
    const step = planStep();
    const context = reviewOutputContext();

    async function pauseForReviewScopeDrift(code) {
      await transition(
        {
          ...state(),
          workflowState: "WAITING_FOR_USER",
          reviewCorrection: null,
          pendingReviewCorrection: null,
        },
        {
          pause: { reason: "unsafe_git_state", code },
          publicActivity: activity(
            "runner",
            "review",
            "paused",
            "Plan execution paused: unsafe_git_state.",
          ),
        },
      );
      return null;
    }

    async function verifiedReviewScope() {
      const current = state();
      try {
        await runtime.git.assertUnchanged(current.repositoryBaseline);
      } catch (cause) {
        if (cause?.code !== "ERR_READ_ONLY_REPOSITORY_CHANGED") {
          throw cause;
        }
        return pauseForReviewScopeDrift(cause.code);
      }
      const fingerprint = await contentFingerprint();
      if (fingerprint !== current.finalizedFingerprint) {
        return pauseForReviewScopeDrift(
          "ERR_REVIEW_CONTENT_FINGERPRINT_CHANGED",
        );
      }
      const infrastructureFingerprint =
        await validationInfrastructureFingerprint(
          current.finalizationResult.validationInfrastructure,
        );
      if (
        infrastructureFingerprint !==
        current.finalizationResult.validationInfrastructureFingerprint
      ) {
        return pauseForReviewScopeDrift(
          "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
        );
      }
      const correctionScope = reviewCorrectionScope(current);
      if (
        current.reviewCorrection !== null &&
        !reviewCorrectionMatchesScope(
          current.reviewCorrection,
          correctionScope,
        )
      ) {
        await transition({
          ...current,
          reviewCorrection: null,
          pendingReviewCorrection: null,
        });
      }
      return Object.freeze({ correctionScope, fingerprint });
    }

    function reviewPrompt(evidence, correction) {
      const current = state();
      return `${REVIEW_INSTRUCTIONS}

Reuse an existing ID for an unchanged finding. Use FINDINGS with every actionable blocker.

${evidence}

Current planned commit:
## Commit ${step.number}: ${step.subject}

${step.body}

Established validation tuple:
${JSON.stringify(
  {
    requiredChecks: current.requiredChecks,
    validationInfrastructure: current.validationInfrastructure,
    validationInfrastructureFingerprint:
      current.validationInfrastructureFingerprint,
    trustedCommandFingerprint:
      current.trustedValidation.commandFingerprint,
    trustedConfigurationFingerprint:
      current.trustedValidation.configurationFingerprint,
  },
  null,
  2,
)}

Candidate validation tuple and finalization evidence:
${JSON.stringify(current.finalizationResult, null, 2)}

The Reviewer must return ACCEPTED only when any validation inventory or infrastructure change is authorized by this planned commit and remains complete; return REJECTED with a finding for evasive, omitted, substituted, or weakened validation. Return UNCHANGED only when finalizationResult.validationChanged is false.

Previous findings for this step:
${JSON.stringify(current.previousFindings, null, 2)}${
        current.reviewReconsideration.length === 0
          ? ""
          : `\n\nReconsider these current finding IDs as requested by the Arbiter:\n${current.reviewReconsideration.join(", ")}`
      }

Prior decisions for this step:
${JSON.stringify(priorFindingDecisions(), null, 2)}

User overrides are runner-owned audit decisions. Do not describe an override as Reviewer acceptance.${
        correction === null
          ? ""
          : `\n\n${REVIEW_CORRECTION_INSTRUCTIONS}\n\nPending correction diagnostic batch:\n${JSON.stringify(correction, null, 2)}`
      }`;
    }

    let scope;
    let result;
    while (true) {
      scope = await verifiedReviewScope();
      if (scope === null) {
        return false;
      }
      const current = state();
      const correction = current.pendingReviewCorrection;
      try {
        const output = await runRole(
          "reviewer",
          REVIEW_SCHEMA,
          (evidence) => reviewPrompt(evidence, correction),
          {
            checkpoint:
              correction === null
                ? `commit:${current.currentStep}`
                : `review-correction:${current.currentStep}`,
            freshSession: correction !== null,
            recoveryContext: resolvedContext(),
          },
        );
        if (output === null) {
          return false;
        }
        result = normalizeReviewRoleOutput(
          output,
          current.previousFindings,
          current.finalizationResult.validationChanged,
        );
        scope = await verifiedReviewScope();
        if (scope === null) {
          return false;
        }
        break;
      } catch (cause) {
        if (
          cause?.code !== "ERR_INVALID_PLAN_EXECUTION_OUTPUT" ||
          !isOutputDiagnostic(cause.diagnostic)
        ) {
          throw cause;
        }
        const diagnostics = outputDiagnostics(cause, context).slice(
          0,
          MAX_DIAGNOSTIC_ITEMS,
        );
        const pendingCorrection = {
          ...scope.correctionScope,
          diagnostics,
        };
        if (state().reviewCorrection === null) {
          const violationLabel =
            diagnostics.length === 1 ? "violation" : "violations";
          await transition(
            {
              ...state(),
              reviewCorrection: pendingCorrection,
              pendingReviewCorrection: pendingCorrection,
            },
            {
              publicActivity: activity(
                "reviewer",
                "review",
                "review-correction",
                `reviewer must correct ${diagnostics.length} review contract ${violationLabel}.`,
              ),
            },
          );
          continue;
        }
        await transition(
          {
            ...state(),
            workflowState: "WAITING_FOR_USER",
            pendingReviewCorrection: pendingCorrection,
          },
          {
            pause: {
              reason: "review_output_invalid",
              code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
              explanation:
                "The bounded automatic final Reviewer correction remains invalid. Retry the same read-only correction after the backend can satisfy the unchanged contract.",
              evidence: diagnostics.map(
                ({ field, constraint }) =>
                  `Reviewer field ${field} violated ${constraint}.`,
              ),
              resumeState: "REVIEW",
            },
            publicActivity: activity(
              "runner",
              "review",
              "paused",
              "Plan execution paused: review_output_invalid.",
            ),
          },
        );
        return false;
      }
    }
    const current = state();
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    const reviewedFingerprint = await contentFingerprint();
    if (reviewedFingerprint !== scope.fingerprint) {
      await pauseForReviewScopeDrift(
        "ERR_REVIEW_CONTENT_FINGERPRINT_CHANGED",
      );
      return false;
    }
    const reviewResult = {
      status: result.status,
      validationChange: result.validationChange,
      validationEvidence: result.validationEvidence,
      fingerprint: reviewedFingerprint,
    };
    const findings =
      result.status === "FINDINGS"
        ? result.findings.filter(
            ({ id }) => !findingOverrideApplies(id, reviewedFingerprint),
          )
        : [];
    if (findings.length > 0) {
      const correction = correctionUpdate({
        fingerprint: reviewedFingerprint,
        finalizationIssueIds: [],
        findingIds: findings.map(({ id }) => id),
      });
      const pendingDisputes = findings.flatMap(({ id }) => {
        const latest = latestDispute(id);
        return latest?.direction === "UPHOLD" &&
          latest.attempt === current.disputeCounts[id] &&
          current.disputeCounts[id] >= current.settings.maxDisputesPerFinding &&
          !current.findingArbitrations.some(
            ({ findingId }) => findingId === id,
          )
          ? [
              {
                findingId: id,
                reason: latest.workerReason,
                evidence: latest.workerEvidence,
              },
            ]
          : [];
      });
      await transition(
        {
          ...state(),
          ...(result.validationChange === "ACCEPTED"
            ? {
                requiredChecks: current.finalizationResult.requiredChecks,
                validationInfrastructure:
                  current.finalizationResult.validationInfrastructure,
                validationInfrastructureFingerprint:
                  current.finalizationResult
                    .validationInfrastructureFingerprint,
              }
            : {}),
          workflowState: "RESOLVE_FINDINGS",
          reviewedFingerprint,
          reviewResult,
          findings,
          previousFindings: result.findings,
          pendingDisputes,
          correctionHistory: correction.history,
          sameFindingRounds: correction.sameFindingRounds,
          pendingCorrection: false,
          blockedSinceStagnation: correction.blockedSinceStagnation,
          reviewerStep: current.currentStep,
          reviewReconsideration: [],
          pendingReviewCorrection: null,
        },
        {
          nextCounters: correction.counters,
          publicActivity: activity(
            "reviewer",
            "review",
            "findings",
            `Review left ${findings.length} non-overridden blocking findings.`,
          ),
        },
      );
      return true;
    }
    await transition(
      {
        ...state(),
        workflowState: "COMMIT",
        ...(result.validationChange === "ACCEPTED"
          ? {
              requiredChecks: current.finalizationResult.requiredChecks,
              validationInfrastructure:
                current.finalizationResult.validationInfrastructure,
              validationInfrastructureFingerprint:
                current.finalizationResult
                  .validationInfrastructureFingerprint,
            }
          : {}),
        reviewResult,
        reviewedFingerprint,
        findings: [],
        previousFindings:
          result.status === "FINDINGS" ? result.findings : [],
        pendingDisputes: [],
        pendingCorrection: false,
        reviewerStep: current.currentStep,
        reviewReconsideration: [],
        pendingReviewCorrection: null,
      },
      {
        publicActivity: activity(
          "reviewer",
          "review",
          result.status === "APPROVED" ? "approved" : "overrides-applied",
          result.status === "APPROVED"
            ? "Review approved the finalized content."
            : "Review completed with only fingerprint-bound overridden findings.",
        ),
      },
    );
    return true;
  }

  async function reconsiderDisputes() {
    const current = state();
    const disputedFindings =
      current.findings.length === 0
        ? current.previousFindings.filter((finding) =>
            current.pendingDisputes.some(
              ({ findingId }) => findingId === finding.id,
            ),
          )
        : current.findings;
    const output = await runRole(
      "reviewer",
      DISPUTE_RECONSIDERATION_SCHEMA,
      (evidence) => `${DISPUTE_RECONSIDERATION_INSTRUCTIONS}

${evidence}

Current findings:
${JSON.stringify(disputedFindings, null, 2)}

Worker disputes:
${JSON.stringify(current.pendingDisputes, null, 2)}`,
      {
        checkpoint: `commit:${current.currentStep}`,
        recoveryContext: resolvedContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeReconsiderationResult(
      output,
      current.pendingDisputes,
    );
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    const decisions = new Map(
      result.decisions.map((decision) => [decision.findingId, decision]),
    );
    const reviewPending =
      current.reviewedFingerprint === null ||
      current.reviewResult?.validationChange === "REJECTED";
    const findings = disputedFindings.filter((finding) => {
      return decisions.get(finding.id)?.direction !== "WITHDRAW";
    });
    const pendingDisputes = current.pendingDisputes.filter((dispute) => {
      const decision = decisions.get(dispute.findingId);
      return (
        decision.direction === "UPHOLD" &&
        current.disputeCounts[dispute.findingId] >=
          current.settings.maxDisputesPerFinding
      );
    });
    const history = [
      ...current.disputeHistory,
      ...current.pendingDisputes.map((dispute) => {
        const decision = decisions.get(dispute.findingId);
        return {
          findingId: dispute.findingId,
          attempt: current.disputeCounts[dispute.findingId],
          direction: decision.direction,
          workerReason: dispute.reason,
          workerEvidence: dispute.evidence,
          reviewerReason: decision.reason,
          reviewerEvidence: decision.evidence,
        };
      }),
    ].slice(-MAX_DIAGNOSTIC_ITEMS);
    await transition(
      {
        ...current,
        workflowState: reviewPending
          ? "REVIEW"
          : findings.length === 0 && pendingDisputes.length === 0
            ? "COMMIT"
            : "RESOLVE_FINDINGS",
        findings: reviewPending ? [] : findings,
        pendingDisputes: reviewPending ? [] : pendingDisputes,
        disputeHistory: history,
      },
      {
        publicActivity: activity(
          "reviewer",
          "resolution",
          "disputes-reconsidered",
          "Reviewer reconsidered the Worker disputes.",
        ),
      },
    );
    return true;
  }

  async function arbitrateFinding(dispute) {
    const current = state();
    const finding = current.findings.find(
      ({ id }) => id === dispute.findingId,
    );
    const reviewerResponse = latestDispute(dispute.findingId);
    const output = await runRole(
      "arbiter",
      FINDING_ARBITRATION_SCHEMA,
      (evidence) => `${FINDING_ARBITRATION_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Finding:
${JSON.stringify(finding, null, 2)}

Worker dispute:
${JSON.stringify(dispute, null, 2)}

Reviewer response:
${JSON.stringify(reviewerResponse, null, 2)}

Prior decisions for this finding:
${JSON.stringify(priorFindingDecisions([dispute.findingId]), null, 2)}`,
      {
        checkpoint: "arbitration",
        recoveryContext: resolvedContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeFindingArbitration(output);
    if (result.direction === "REQUIREMENT_AMBIGUOUS") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    const findings =
      result.direction === "WORKER_CORRECT"
        ? current.findings.filter(({ id }) => id !== dispute.findingId)
        : current.findings;
    const pendingDisputes = current.pendingDisputes.filter(
      ({ findingId }) => findingId !== dispute.findingId,
    );
    await transition(
      {
        ...state(),
        workflowState:
          findings.length === 0 && pendingDisputes.length === 0
            ? current.reviewResult?.validationChange === "REJECTED"
              ? "REVIEW"
              : "COMMIT"
            : "RESOLVE_FINDINGS",
        findings,
        pendingDisputes,
        findingArbitrations: [
          ...current.findingArbitrations,
          {
            findingId: dispute.findingId,
            direction: result.direction,
            rationale: result.rationale,
          },
        ].slice(-MAX_DIAGNOSTIC_ITEMS),
      },
      {
        publicActivity: activity(
          "arbiter",
          "resolution",
          "finding-arbitrated",
          `Arbiter selected ${result.direction} for ${dispute.findingId}.`,
        ),
      },
    );
    return true;
  }

  async function arbitrateStagnation() {
    const current = state();
    const output = await runRole(
      "arbiter",
      STAGNATION_SCHEMA,
      (evidence) => `${STAGNATION_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}
Do not modify the repository. This result cannot approve the implementation or satisfy review.
Name only current Reviewer finding IDs for RECONSIDER_FINDINGS.

${evidence}

Current blockers and compact correction history:
${JSON.stringify(
  {
    currentStep: current.currentStep,
    finalizationResult: current.finalizationResult,
    findings: current.findings,
    pendingDisputes: current.pendingDisputes,
    correctionHistory: current.correctionHistory,
  },
  null,
  2,
)}`,
      {
        checkpoint: "arbitration",
        recoveryContext: resolvedContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeStagnationResult(output, current);
    if (result.direction === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    if (result.direction === "PLAN_REVISION_REQUIRED") {
      await pauseForPlanRevision(result);
      return false;
    }
    const direction = {
      direction: result.direction,
      rationale: result.rationale,
    };
    if (result.direction === "REWORK_IMPLEMENTATION") {
      const nextState = {
        ...state(),
        implementationDirection: direction,
        finalizationResult: null,
        finalizedFingerprint: null,
        reviewCorrection: null,
        pendingReviewCorrection: null,
        cleanConfirmationFingerprint: null,
        reviewResult: null,
        reviewedFingerprint: null,
        previousFindings:
          current.findings.length === 0
            ? current.previousFindings
            : current.findings,
        findings: [],
        pendingDisputes: current.pendingDisputes,
        pendingCorrection: false,
        blockedSinceStagnation: 0,
        stagnationArbitrationUsed: true,
        stagnationDirection: direction,
        reviewReconsideration: [],
      };
      if (counters().fixRounds >= fixBudget()) {
        await transition(
          { ...nextState, workflowState: "WAITING_FOR_USER" },
          {
            pause: {
              reason: "fix_limit_reached",
              fixRounds: counters().fixRounds,
              resumeState: "IMPLEMENT",
            },
            publicActivity: activity(
              "runner",
              "resolution",
              "paused",
              "Plan execution paused: fix_limit_reached.",
            ),
          },
        );
        return false;
      }
      await transition(
        {
          ...nextState,
          workflowState: "IMPLEMENT",
        },
        {
          publicActivity: activity(
            "arbiter",
            "resolution",
            "rework-implementation",
            "Stagnation Arbiter requested implementation rework.",
          ),
        },
      );
      return true;
    }
    if (result.direction === "RECONSIDER_FINDINGS") {
      await transition(
        {
          ...state(),
          workflowState: "REVIEW",
          blockedSinceStagnation: 0,
          stagnationArbitrationUsed: true,
          stagnationDirection: direction,
          reviewReconsideration: result.findingIds,
        },
        {
          publicActivity: activity(
            "arbiter",
            "resolution",
            "reconsider-findings",
            "Stagnation Arbiter requested Reviewer reconsideration.",
          ),
        },
      );
      return true;
    }
    await transition(
      {
        ...state(),
        blockedSinceStagnation: 0,
        stagnationArbitrationUsed: true,
        stagnationDirection: direction,
      },
      {
        publicActivity: activity(
          "arbiter",
          "resolution",
          "continue-fixes",
          "Stagnation Arbiter requested continued fixes.",
        ),
      },
    );
    return true;
  }

  async function runResolutionTurn() {
    const current = state();
    if (current.finalizationResult?.status === "PASS") {
      const arbitration = current.pendingDisputes.find(
        disputeNeedsArbitration,
      );
      if (arbitration !== undefined) {
        return arbitrateFinding(arbitration);
      }
      if (current.pendingDisputes.length > 0) {
        return reconsiderDisputes();
      }
    }
    const stableFindingIds = exhaustedStableFindingIds();
    if (stableFindingIds.length > 0) {
      await pause("no_progress", {
        findingIds: stableFindingIds,
        reason: "stable_findings",
        resumeState: "RESOLVE_FINDINGS",
      });
      return false;
    }
    if (
      current.blockedSinceStagnation >=
      current.settings.stagnationWindowRounds
    ) {
      if (
        current.settings.mode === "lazy" ||
        current.stagnationArbitrationUsed
      ) {
        await pause("no_progress", {
          correctionRounds: counters().correctionRounds,
          reason: "recurrent_stagnation",
          resumeState: "RESOLVE_FINDINGS",
        });
        return false;
      }
      return arbitrateStagnation();
    }
    const budgetExhausted = counters().fixRounds >= fixBudget();
    const blockers = activeBlockers();
    const disputableFindingIds = new Set(
      current.findings
        .filter(
          ({ id }) =>
            !current.findingArbitrations.some(
              (entry) =>
                entry.findingId === id &&
                entry.direction === "REVIEWER_CORRECT",
            ),
        )
        .map(({ id }) => id),
    );
    if (budgetExhausted && disputableFindingIds.size === 0) {
      await pause("fix_limit_reached", {
        fixRounds: counters().fixRounds,
        resumeState: "RESOLVE_FINDINGS",
      });
      return false;
    }
    const beforeFingerprint = await contentFingerprint();
    const output = await runRole(
      "worker",
      FINDING_RESOLUTION_SCHEMA,
      (evidence) => `${FINDING_RESOLUTION_INSTRUCTIONS}

Finalization failures must be fixed and cannot be disputed. A finding already upheld by the Arbiter must be fixed.${
        budgetExhausted
          ? "\nThe fix budget is exhausted: do not modify the repository and return DISPUTE only where supported by evidence; a required FIX will pause for additional budget."
          : ""
      }

${evidence}

Current blockers:
${JSON.stringify(blockers, null, 2)}${
        current.stagnationDirection?.direction === "CONTINUE_FIXES"
          ? `\n\nStagnation Arbiter direction:\n${JSON.stringify(current.stagnationDirection, null, 2)}`
          : ""
      }

Prior decisions for these blockers:
${JSON.stringify(
  priorFindingDecisions(blockers.map(({ id }) => id)),
  null,
  2,
)}`,
      {
        access: budgetExhausted ? "read-only" : "workspace-write",
        checkpoint: `commit:${current.currentStep}`,
        recoveryContext: resolvedContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const fixRoundAlreadyCounted = state().pendingCorrection;
    const result = normalizeResolutionResult(
      output,
      blockers,
      new Set(
        [
          ...current.findingArbitrations
            .filter(({ direction }) => direction === "REVIEWER_CORRECT")
            .map(({ findingId }) => findingId),
          ...Object.entries(current.disputeCounts)
            .filter(
              ([, count]) => count >= current.settings.maxDisputesPerFinding,
            )
            .map(([findingId]) => findingId),
        ],
      ),
    );
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    if (result.status === "BLOCKED") {
      await pause("environment_blocked", {
        explanation: result.reason,
        evidence: result.evidence,
        resumeState:
          state().workflowState === "FINALIZE"
            ? "FINALIZE"
            : "RESOLVE_FINDINGS",
      });
      return false;
    }
    if (
      budgetExhausted &&
      result.decisions.some(({ decision }) => decision === "FIX")
    ) {
      const disputes = result.decisions
        .filter(({ decision }) => decision === "DISPUTE")
        .map((decision) => ({
          findingId: decision.id,
          reason: decision.reason,
          evidence: decision.evidence,
        }));
      const disputeCounts = { ...current.disputeCounts };
      for (const { findingId } of disputes) {
        disputeCounts[findingId] = (disputeCounts[findingId] ?? 0) + 1;
      }
      await transition(
        {
          ...state(),
          workflowState: "WAITING_FOR_USER",
          pendingDisputes: disputes,
          disputeCounts,
        },
        {
          pause: {
            reason: "fix_limit_reached",
            fixRounds: counters().fixRounds,
            resumeState: "RESOLVE_FINDINGS",
          },
          publicActivity: activity(
            "runner",
            "resolution",
            "paused",
            "Plan execution paused: fix_limit_reached.",
          ),
        },
      );
      return false;
    }
    const changed = (await contentFingerprint()) !== beforeFingerprint;
    const correction =
      changed || result.decisions.some(({ decision }) => decision === "FIX");
    if (correction) {
      const newDisputes = result.decisions
        .filter(({ decision }) => decision === "DISPUTE")
        .map((decision) => ({
          findingId: decision.id,
          reason: decision.reason,
          evidence: decision.evidence,
        }));
      const disputes = [
        ...new Map(
          [...current.pendingDisputes, ...newDisputes].map((dispute) => [
            dispute.findingId,
            dispute,
          ]),
        ).values(),
      ];
      const disputeCounts = { ...current.disputeCounts };
      for (const { findingId } of newDisputes) {
        disputeCounts[findingId] = (disputeCounts[findingId] ?? 0) + 1;
      }
      await transition(
        {
          ...state(),
          workflowState: "FINALIZE",
          finalizationResult: null,
          finalizedFingerprint: null,
          reviewCorrection: null,
          pendingReviewCorrection: null,
          cleanConfirmationFingerprint: null,
          reviewResult: null,
          reviewedFingerprint: null,
          previousFindings:
            current.findings.length === 0
              ? current.previousFindings
              : current.findings,
          findings: [],
          pendingDisputes: disputes,
          disputeCounts,
          pendingCorrection: true,
          reviewReconsideration: [],
        },
        {
          nextCounters: {
            ...counters(),
            fixRounds:
              counters().fixRounds +
              (fixRoundAlreadyCounted ? 0 : 1),
          },
          publicActivity: activity(
            "worker",
            "resolution",
            "fixed",
            "Worker completed a finding-resolution fix round.",
          ),
        },
      );
      return true;
    }
    const disputes = result.decisions.map((decision) => ({
      findingId: decision.id,
      reason: decision.reason,
      evidence: decision.evidence,
    }));
    const disputeCounts = { ...current.disputeCounts };
    for (const { findingId } of disputes) {
      disputeCounts[findingId] = (disputeCounts[findingId] ?? 0) + 1;
    }
    await transition(
      {
        ...state(),
        pendingDisputes: disputes,
        disputeCounts,
      },
      {
        publicActivity: activity(
          "worker",
          "resolution",
          "disputed",
          `Worker disputed ${disputes.length} findings with evidence.`,
        ),
      },
    );
    return true;
  }

  async function runCommitTurn() {
    const current = state();
    const step = planStep();
    let pendingCommit = current.pendingCommit;

    if (pendingCommit === null) {
      if ((await readCurrentInputs()) === null) {
        return false;
      }
      const fingerprint = await contentFingerprint();
      if (
        fingerprint !== current.finalizedFingerprint ||
        fingerprint !== current.reviewedFingerprint ||
        !(await verifyPersistedRepository())
      ) {
        if (state().workflowState !== "WAITING_FOR_USER") {
          await pause("unsafe_git_state", {
            code: "ERR_COMMIT_GATE_CHANGED",
          });
        }
        return false;
      }
      let authorization;
      try {
        authorization = await runtime.git.prepareCommit({
          expectedSnapshot: current.repositoryBaseline,
          subject: step.subject,
          persistPendingCommit: async (preparedAuthorization) => {
            await transition(
              {
                ...state(),
                pendingCommit: {
                  status: "prepared",
                  authorization: preparedAuthorization,
                  preEffectRejection: null,
                },
              },
              {
                publicActivity: activity(
                  "runner",
                  "commit",
                  "authorized",
                  `Commit ${current.currentStep} authorized.`,
                ),
              },
            );
          },
        });
      } catch (cause) {
        if (cause?.code === "ERR_COMMIT_GATE_CHANGED") {
          await pause("unsafe_git_state", { code: cause.code });
          return false;
        }
        throw cause;
      }
      pendingCommit = {
        status: "prepared",
        authorization,
        preEffectRejection: null,
      };
    }

    let agentError;
    const commitTurn = activeTurn("worker", "COMMIT");
    let commitTurnNeedsReconciliation =
      currentRun.activeTurn !== undefined &&
      currentRun.activeTurn !== null;
    if (
      commitTurnNeedsReconciliation &&
      !isDeepStrictEqual(currentRun.activeTurn, commitTurn)
    ) {
      throw workflowError(
        "Persisted agent turn does not match commit verification.",
        "ERR_INVALID_PLAN_EXECUTION_STATE",
      );
    }
    async function finishCommitTurn() {
      if (!commitTurnNeedsReconciliation) {
        return;
      }
      currentRun = await runtime.finishAgentTurn(commitTurn);
      assertRun(currentRun);
      commitTurnNeedsReconciliation = false;
    }
    if (pendingCommit.status === "prepared") {
      const previousSession = [...currentRun.sessionLineage.children]
        .reverse()
        .find((child) => child.role === "worker")?.sessionId;
      let baseRequest;
      try {
        baseRequest = await runtime.git.consumeCommit(
          pendingCommit.authorization,
          {
            consumePendingCommit: async () => {
              await transition(
                {
                  ...state(),
                  pendingCommit: {
                    status: "consumed",
                    authorization: pendingCommit.authorization,
                    preEffectRejection: null,
                  },
                },
                {
                  publicActivity: activity(
                    "runner",
                    "commit",
                    "started",
                    `Commit ${current.currentStep} authorization consumed.`,
                  ),
                },
              );
            },
          },
        );
      } catch (cause) {
        if (cause?.code === "ERR_COMMIT_GATE_CHANGED") {
          await transition(
            {
              ...state(),
              workflowState: "WAITING_FOR_USER",
              pendingCommit: null,
            },
            {
              pause: { reason: "unsafe_git_state", code: cause.code },
              publicActivity: activity(
                "runner",
                "commit",
                "paused",
                "Plan execution paused: unsafe_git_state.",
              ),
            },
          );
          return false;
        }
        throw cause;
      }
      const roleConfiguration = currentRun.roles.worker;
      const executionPreferences = Object.fromEntries(
        ["profile", "model", "contextSize"].flatMap((field) =>
          typeof roleConfiguration[field] === "string" &&
          roleConfiguration[field] !== "current"
            ? [[field, roleConfiguration[field]]]
            : [],
        ),
      );
      const request = {
        ...baseRequest,
        prompt: rolePrompt(`${COMMIT_INSTRUCTIONS}

Authorized planned commit:
${step.subject}`),
        ...executionPreferences,
        ...(previousSession === undefined
          ? {}
          : { session: { id: previousSession, mode: "continue" } }),
      };
      currentRun = await runtime.startAgentTurn(commitTurn);
      assertRun(currentRun);
      commitTurnNeedsReconciliation = true;
      try {
        await runtime.adapters.worker.run(request);
      } catch (cause) {
        agentError = cause;
      }
      const preEffectRejection =
        agentError?.effectStarted === false
          ? Object.freeze({
              code: diagnosticCode(
                agentError,
                "ERR_COMMIT_ADAPTER_REJECTED",
              ),
              recoverable: agentError?.recoverable === true,
            })
          : null;
      pendingCommit = {
        status: "consumed",
        authorization: pendingCommit.authorization,
        preEffectRejection,
      };
      if (preEffectRejection !== null) {
        await transition(
          { ...state(), pendingCommit },
          {
            publicActivity: activity(
              "runner",
              "commit",
              "pre-effect-rejection-recorded",
              `Commit ${current.currentStep} pre-effect rejection recorded.`,
            ),
          },
        );
      }
    }

    let verified;
    try {
      verified = await runtime.git.verifyCommit(pendingCommit.authorization);
      await finishCommitTurn();
    } catch (cause) {
      if (
        ![
          "ERR_COMMIT_NOT_CREATED",
          "ERR_COMMIT_CONTRACT_VIOLATED",
        ].includes(cause?.code)
      ) {
        throw cause;
      }
      await finishCommitTurn();
      if (
        cause.code === "ERR_COMMIT_NOT_CREATED" &&
        pendingCommit.preEffectRejection !== null
      ) {
        await pausePreEffectCommitRejection(
          pendingCommit.preEffectRejection,
        );
        return false;
      }
      const contractViolation =
        cause?.code === "ERR_COMMIT_CONTRACT_VIOLATED";
      await pause(
        contractViolation ? "commit_contract_violated" : "commit_failed",
        {
          code: diagnosticCode(cause, "ERR_COMMIT_FAILED"),
          ...(Array.isArray(cause?.changes)
            ? { changes: cause.changes }
            : {}),
          ...(agentError === undefined
            ? {}
            : {
                adapterCode: diagnosticCode(
                  agentError,
                  "ERR_COMMIT_ADAPTER_FAILED",
                ),
              }),
        },
      );
      return false;
    }

    const nextRepositoryBaseline = await runtime.git.snapshot({
      allowedPaths: current.repositoryBaseline.allowedPaths,
      projectPath: current.repositoryBaseline.projectPath,
    });
    if (
      nextRepositoryBaseline.head !== verified.head ||
      nextRepositoryBaseline.clean !== true
    ) {
      await pause("commit_contract_violated", {
        code: "ERR_COMMIT_CONTRACT_VIOLATED",
      });
      return false;
    }
    const completedCommits = [...current.completedCommits, verified.head];
    const stepCount = parseCommitPlan(current.canonicalPlan).steps.length;
    const done = current.currentStep === stepCount;
    const nextStepState = done
      ? {}
      : {
          implementationDirection: null,
          finalizationResult: null,
          finalizedFingerprint: null,
          reviewCorrection: null,
          pendingReviewCorrection: null,
          cleanConfirmationFingerprint: null,
          reviewResult: null,
          reviewedFingerprint: null,
          findings: [],
          previousFindings: [],
          pendingDisputes: [],
          disputeCounts: {},
          disputeHistory: [],
          findingArbitrations: [],
          correctionHistory: [],
          sameFindingRounds: {},
          pendingCorrection: false,
          blockedSinceStagnation: 0,
          stagnationArbitrationUsed: false,
          stagnationDirection: null,
          reviewReconsideration: [],
          additionalFixRounds: 0,
          findingOverrides: [],
        };
    await transition(
      {
        ...state(),
        ...nextStepState,
        workflowState: done ? "DONE" : "IMPLEMENT",
        validationMigrationPending:
          done ? false : current.validationMigrationPending,
        repositoryBaseline: nextRepositoryBaseline,
        currentStep: done ? null : current.currentStep + 1,
        reviewerStep: null,
        finalizationCorrections: [],
        pendingFinalizationCorrection: null,
        reviewCorrection: null,
        pendingReviewCorrection: null,
        pendingCommit: null,
        completedCommits,
      },
      {
        nextCounters: done
          ? counters()
          : {
              ...counters(),
              fixRounds: 0,
              correctionRounds: 0,
            },
        publicActivity: activity(
          "worker",
          "commit",
          "created",
          `Commit ${current.currentStep} created: ${verified.head}.`,
        ),
      },
    );
    return true;
  }

  try {
    if (state().settings === null) {
      await transition({ ...state(), settings }, { pause: null });
    }
    if (!(await recoverInterruptedTurn())) {
      return currentRun;
    }
    const resumeActionSuperseded = await prepareValidationMigrationResume();
    if (!resumeActionSuperseded && !(await applyResumeAction())) {
      return currentRun;
    }
    if (state().workflowState === "WAITING_FOR_USER") {
      if (state().pendingEdit !== null) {
        if (!(await resumeEdit())) {
          return currentRun;
        }
      } else if (
        currentRun.pause.reason === "commit_failed" &&
        (state().pendingCommit?.status === "consumed" ||
          (state().pendingCommit === null &&
            currentRun.pause.resumeState === "COMMIT"))
      ) {
        await transition(
          { ...state(), workflowState: "COMMIT" },
          { pause: null },
        );
      } else if (
        RETRYABLE_PAUSE_REASONS.has(currentRun.pause.reason) &&
        (!state().preflightComplete ||
          ([
            "backend_unavailable",
            "environment_blocked",
            "finalization_cannot_pass",
            "finalization_skill_invalid",
            "finalization_skill_missing",
            "review_output_invalid",
          ].includes(currentRun.pause.reason) &&
            [
              "CLARIFY",
              "BOOTSTRAP",
              "IMPLEMENT",
              "FINALIZE",
              "CHECK_AND_FIX",
              "CLEAN_CONFIRM",
              "REVIEW",
              "RESOLVE_FINDINGS",
              "COMMIT",
            ].includes(currentRun.pause.resumeState)))
      ) {
        await transition(
          {
            ...state(),
            workflowState: state().preflightComplete
              ? currentRun.pause.resumeState
              : "CLARIFY",
          },
          { pause: null },
        );
      } else {
        return currentRun;
      }
    }
    if (["DONE", "FAILED"].includes(state().workflowState)) {
      return currentRun;
    }
    const commitVerificationPending =
      state().workflowState === "COMMIT" &&
      state().pendingCommit?.status === "consumed";
    if (
      state().preflightComplete &&
      !interruptedRepositoryReconciled &&
      !["WAITING_FOR_USER", "FAILED", "DONE"].includes(state().workflowState) &&
      (!commitVerificationPending &&
        ((await readCurrentInputs()) === null ||
          !(await verifyPersistedRepository())))
    ) {
      return currentRun;
    }

    while (true) {
      const current = state();

      if (
        current.validationMigrationPending &&
        !current.compatibilityCheckRequired &&
        !(
          current.workflowState === "COMMIT" &&
          current.pendingCommit?.status === "consumed"
        )
      ) {
        if (!(await runValidationMigration())) {
          return currentRun;
        }
        continue;
      }

      if (current.compatibilityCheckRequired) {
        const output = await runRole(
          "worker",
          PLAN_COMPATIBILITY_SCHEMA,
          (evidence) => `${PLAN_COMPATIBILITY_INSTRUCTIONS}

${evidence}`,
          { checkpoint: "compatibility" },
        );
        if (output === null) {
          return currentRun;
        }
        const result = normalizeCompatibilityResult(output);
        if (result.status === "PLAN_REVISION_REQUIRED") {
          return pauseForPlanRevision(result);
        }
        const frozen = await runtime.clarifications.freezeTranscript({
          artifactRoot: state().repositoryBaseline.projectPath,
          transcriptPath: state().clarificationPath,
          expectedHash: currentRun.hashes.executionClarifications,
        });
        await transition(
          {
            ...state(),
            clarificationFrozen: true,
            compatibilityCheckRequired: false,
          },
          {
            nextHashes: {
              ...currentRun.hashes,
              executionClarifications: frozen.hash,
            },
            publicActivity: activity(
              "worker",
              "clarification",
              "compatible",
              "Product decision remains compatible with the plan.",
            ),
          },
        );
        continue;
      }

      if (current.workflowState === "CLARIFY") {
        if (!current.preflightComplete && !(await initializeInputs())) {
          return currentRun;
        }
        if (
          state().proactiveClarification &&
          !state().proactiveClarificationComplete
        ) {
          if (
            !(await requestEdit(
              "proactive-clarification",
              "CLARIFY",
              "proactive_clarification",
            ))
          ) {
            return currentRun;
          }
        }
        const output = await runRole(
          "worker",
          CLARIFICATION_SCHEMA,
          (evidence) => `${CLARIFICATION_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}`,
          { checkpoint: "clarification" },
        );
        if (output === null) {
          return currentRun;
        }
        const result = normalizeClarificationResult(output);
        if (result.status === "PLAN_REVISION_REQUIRED") {
          return pauseForPlanRevision(result);
        }
        if (result.status === "PRODUCT_DECISION_REQUIRED") {
          if (!(await productDecision(result.decision, "CLARIFY"))) {
            return currentRun;
          }
          continue;
        }
        if (result.status === "READY") {
          const frozen = await runtime.clarifications.freezeTranscript({
            artifactRoot: state().repositoryBaseline.projectPath,
            transcriptPath: state().clarificationPath,
            expectedHash: currentRun.hashes.executionClarifications,
          });
          await transition(
            {
              ...state(),
              workflowState: "BOOTSTRAP",
              clarificationFrozen: true,
            },
            {
              nextHashes: {
                ...currentRun.hashes,
                executionClarifications: frozen.hash,
              },
              publicActivity: activity(
                "worker",
                "clarification",
                "ready",
                "Execution clarification completed.",
              ),
            },
          );
          continue;
        }
        if (counters().clarificationRounds >= MAX_CLARIFICATION_ROUNDS) {
          return pause("clarification_limit_reached", {
            questions: result.questions,
          });
        }
        const round = counters().clarificationRounds + 1;
        const transcript = await runtime.clarifications.appendQuestionRound({
          artifactRoot: state().repositoryBaseline.projectPath,
          transcriptPath: state().clarificationPath,
          expectedHash: currentRun.hashes.executionClarifications,
          round,
          questions: result.questions,
        });
        if (
          !(await requestEdit(
            "clarification-answers",
            "CLARIFY",
            "clarification_answers_required",
            {
              expectedHash: transcript.hash,
              inputRequest: {
                kind: "clarification",
                questions: result.questions.map((question, index) => ({
                  id: `q${index + 1}`,
                  question: question.question,
                  options: [],
                  rationale: question.whyItMatters,
                })),
                rationale: "Answer every material clarification question.",
              },
              nextCounters: { ...counters(), clarificationRounds: round },
              nextHashes: {
                ...currentRun.hashes,
                executionClarifications: transcript.hash,
              },
            },
          ))
        ) {
          return currentRun;
        }
        continue;
      }

      if (current.workflowState === "BOOTSTRAP") {
        if (current.workerSummary === null) {
          if (!(await bootstrapRole("worker"))) {
            return currentRun;
          }
          continue;
        }
        if (current.settings.mode === "lazy") {
          if (!(await completeLazyBootstrap())) {
            return currentRun;
          }
          continue;
        }
        if (current.reviewerSummary === null) {
          if (!(await bootstrapRole("reviewer"))) {
            return currentRun;
          }
          continue;
        }
        if (current.bootstrapDisagreement !== null) {
          if (!(await arbitrateBootstrap())) {
            return currentRun;
          }
          continue;
        }
        if (!(await reconcileBootstrap())) {
          return currentRun;
        }
        continue;
      }

      if (current.workflowState === "IMPLEMENT") {
        if (!(await runImplementationTurn())) {
          return currentRun;
        }
        continue;
      }

      if (current.workflowState === "FINALIZE") {
        if (!(await runFinalizationTurn())) {
          return currentRun;
        }
        continue;
      }

      if (current.workflowState === "CHECK_AND_FIX") {
        if (!(await runCheckAndFixTurn())) {
          return currentRun;
        }
        continue;
      }

      if (current.workflowState === "CLEAN_CONFIRM") {
        if (!(await runCleanConfirmTurn())) {
          return currentRun;
        }
        continue;
      }

      if (current.workflowState === "REVIEW") {
        if (current.pendingDisputes.length > 0) {
          if (!(await reconsiderDisputes())) {
            return currentRun;
          }
          continue;
        }
        if (!(await runReviewTurn())) {
          return currentRun;
        }
        continue;
      }

      if (current.workflowState === "RESOLVE_FINDINGS") {
        if (!(await runResolutionTurn())) {
          return currentRun;
        }
        continue;
      }

      if (current.workflowState === "COMMIT") {
        if (!(await runCommitTurn())) {
          return currentRun;
        }
        continue;
      }

      if (
        [
          "WAITING_FOR_USER",
          "DONE",
          "FAILED",
        ].includes(current.workflowState)
      ) {
        return currentRun;
      }

      throw workflowError(`Unsupported workflow state: ${current.workflowState}.`);
    }
  } catch (cause) {
    const preflightComplete = state().preflightComplete;
    const causePath = cause?.path ?? cause?.cause?.path;
    const filesystemDrift =
      INPUT_DRIFT_ERROR_CODES.has(cause?.code) ||
      INPUT_DRIFT_ERROR_CODES.has(cause?.cause?.code);
    const inputPaths = [
      join(currentRun.taskPath, "task.md"),
      join(currentRun.taskPath, "plan.md"),
      join(currentRun.taskPath, "clarifications.md"),
      join(currentRun.taskPath, "context.md"),
    ];
    if (
      state().workflowState === "COMMIT" &&
      state().pendingCommit?.status === "consumed"
    ) {
      return pause("commit_failed", {
        code: diagnosticCode(cause, "ERR_COMMIT_VERIFICATION_FAILED"),
      });
    }
    if (cause?.code === "ERR_READ_ONLY_REPOSITORY_CHANGED") {
      return invalidateInputs("read_only_agent_mutated_repository", {
        code: cause.code,
        phase: "repository",
        message: "Repository changed during a read-only plan-execution turn.",
      });
    }
    if (
      cause?.code === "ERR_PLAN_EXECUTION_BACKEND_UNAVAILABLE" ||
      cause?.recoverable === true
    ) {
      return pause("backend_unavailable", {
        code: diagnosticCode(cause, "ERR_BACKEND_UNAVAILABLE"),
        resumeState: state().workflowState,
      });
    }
    if (
      preflightComplete &&
      ([
        "ERR_CLARIFICATIONS_CHANGED",
        "ERR_CLARIFICATION_NOT_FOUND",
        "ERR_INVALID_CLARIFICATION",
        "ERR_UNSAFE_CLARIFICATION_PATH",
      ].includes(cause?.code) ||
        (filesystemDrift && causePath === state().clarificationPath))
    ) {
      return invalidateInputs("clarifications_changed");
    }
    if (preflightComplete && filesystemDrift && inputPaths.includes(causePath)) {
      return invalidateInputs("task_input_changed");
    }
    return fail(cause);
  }
}
