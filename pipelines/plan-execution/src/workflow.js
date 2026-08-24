import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  CommitPlanValidationError,
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";

import {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  COMMIT_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  finalizationBootstrapInstructions,
  finalizationGuidanceInstructions,
  FINDING_ARBITRATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  IMPLEMENTATION_INSTRUCTIONS,
  PLAN_COMPATIBILITY_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
  STAGNATION_INSTRUCTIONS,
} from "./prompts.js";
import {
  BOOTSTRAP_ARBITRATION_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_SCHEMA,
  CLARIFICATION_SCHEMA,
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
  MAX_PLAN_LENGTH,
  PlanExecutionWorkflowError,
  WORKFLOW_STATES,
  assertRun,
  assertRuntime,
  assertSettings,
  createPlanExecutionState,
  isRecord,
  normalizeAdapterCapabilities,
  normalizeBootstrapArbitration,
  normalizeBootstrapResult,
  normalizeClarificationResult,
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

function activity(actor, phase, kind, message) {
  return Object.freeze({ actor, phase, kind, message });
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

export async function runPlanExecution({ action, run, runtime, settings }) {
  assertRun(run);
  assertRuntime(runtime);
  const resumeAction = normalizeResumeAction(action);
  if (run.pipelineState.settings === null) {
    assertSettings(settings);
  }

  let currentRun = run;

  function state() {
    return normalizePipelineState(currentRun.pipelineState);
  }

  function counters() {
    return normalizedCounters(currentRun.counters);
  }

  function resolvedContext() {
    const summary = state().resolvedSummary;
    return summary === null ? "" : `Resolved bootstrap context:\n${summary}`;
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

  async function pauseRejectedCommit(cause) {
    await transition(
      {
        ...state(),
        workflowState: "WAITING_FOR_USER",
        pendingCommit: null,
      },
      {
        pause: {
          reason: "backend_unavailable",
          code: diagnosticCode(cause, "ERR_BACKEND_UNAVAILABLE"),
          resumeState: "COMMIT",
        },
        publicActivity: activity(
          "runner",
          "plan-execution",
          "paused",
          "Plan execution paused: backend_unavailable.",
        ),
      },
    );
    return currentRun;
  }

  async function fail(cause) {
    const code = diagnosticCode(cause, "ERR_PLAN_EXECUTION_FAILED");
    try {
      await transition(
        { ...state(), workflowState: "FAILED" },
        {
          pause: { reason: "internal_failure", code },
          publicActivity: activity(
            "runner",
            "plan-execution",
            "failed",
            `Plan execution failed: ${code}.`,
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
        resolvedSummary: null,
        bootstrapDisagreement: null,
        bootstrapArbitrationUsed: false,
        compatibilityCheckRequired: false,
        currentStep: null,
        reviewerStep: null,
        implementationDirection: null,
        finalizationResult: null,
        finalizedFingerprint: null,
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

  async function runRole(
    role,
    schema,
    buildPrompt,
    {
      access = "read-only",
      checkpoint,
      recoveryContext = "",
    } = {},
  ) {
    await ensureRoleCapabilities(role);
    const evidence = await readCurrentInputs();
    if (evidence === null) {
      return null;
    }
    const baseline = state().repositoryBaseline;
    if (!(await verifyPersistedRepository())) {
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
    const previousSession =
      role !== "arbiter" && latestSession?.contextKey === contextKey
        ? latestSession.sessionId
        : undefined;
    const sourceSession = currentRun.sessionLineage.source;
    const session =
      previousSession !== undefined
        ? { id: previousSession, mode: "continue" }
        : sourceSession !== null && role !== "arbiter"
          ? { id: sourceSession, mode: "fork" }
          : undefined;
    const roleConfiguration = currentRun.roles[role];
    const recoveryPrompt = buildPrompt(context);
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
        session?.mode === "continue" ? buildPrompt("") : recoveryPrompt,
      recoveryPrompt,
      schema,
      ...executionPreferences,
      ...(session === undefined ? {} : { session }),
    };
    let response;
    let agentError;
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
      const changedCorrection =
        current.workflowState === "RESOLVE_FINDINGS" &&
        turnSnapshot.contentFingerprint !==
          nextRepositoryBaseline.contentFingerprint;
      if (
        changedCorrection ||
        !isDeepStrictEqual(nextRepositoryBaseline, baseline)
      ) {
        await transition(
          changedCorrection
            ? {
                ...current,
                workflowState: "FINALIZE",
                repositoryBaseline: nextRepositoryBaseline,
                finalizationResult: null,
                finalizedFingerprint: null,
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
              },
          changedCorrection
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
    if (agentError !== undefined) {
      throw agentError;
    }
    if (!isRecord(response)) {
      throw workflowError(
        `${role} returned no response.`,
        "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      );
    }
    await recordSession(
      role,
      response.sessionId,
      previousSession,
      contextKey,
    );
    if (!isRecord(response.structured)) {
      throw workflowError(
        `${role} returned no structured result.`,
        "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
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
    };
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
    let workerCapabilities;
    let reviewerCapabilities;
    try {
      [workerCapabilities, reviewerCapabilities] = await Promise.all([
        runtime.adapters.worker
          .probe()
          .then((value) =>
            normalizeAdapterCapabilities(
              value,
              "worker",
              currentRun.sessionLineage.source,
            ),
          ),
        runtime.adapters.reviewer
          .probe()
          .then((value) =>
            normalizeAdapterCapabilities(
              value,
              "reviewer",
              currentRun.sessionLineage.source,
            ),
          ),
      ]);
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
        backendVersions: {
          worker: workerCapabilities.version,
          reviewer: reviewerCapabilities.version,
          arbiter: null,
        },
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
    const output = await runRole(
      role,
      BOOTSTRAP_SCHEMA,
      (evidence) => `${BOOTSTRAP_INSTRUCTIONS}${
        role === "reviewer"
          ? "\nAs Reviewer, also state what you intend to verify."
          : ""
      }

${finalizationBootstrapInstructions(state().settings.finalization)}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}`,
      { checkpoint: "bootstrap" },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeBootstrapResult(output, role);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    if (result.status === "PLAN_REVISION_REQUIRED") {
      await pauseForPlanRevision(result);
      return false;
    }
    await writeContext(`context/${role}.md`, result.summary);
    await transition(
      { ...state(), [`${role}Summary`]: result.summary },
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

  async function reconcileBootstrap() {
    const output = await runRole(
      "worker",
      BOOTSTRAP_RECONCILIATION_SCHEMA,
      (evidence) => `${BOOTSTRAP_RECONCILIATION_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Worker bootstrap summary:
${state().workerSummary}

Reviewer bootstrap summary:
${state().reviewerSummary}`,
      { checkpoint: "bootstrap" },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeReconciliationResult(output);
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
    await transition(
      {
        ...state(),
        workflowState: "IMPLEMENT",
        resolvedSummary: result.summary,
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
    const output = await runRole(
      "arbiter",
      BOOTSTRAP_ARBITRATION_SCHEMA,
      (evidence) => `${BOOTSTRAP_ARBITRATION_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Worker bootstrap summary:
${state().workerSummary}

Reviewer bootstrap summary:
${state().reviewerSummary}

Recorded disagreement:
${JSON.stringify(state().bootstrapDisagreement, null, 2)}`,
      { checkpoint: "arbitration" },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeBootstrapArbitration(output);
    if (result.direction === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    if (result.direction === "PLAN_REVISION_REQUIRED") {
      await pauseForPlanRevision(result);
      return false;
    }
    await writeContext("context/resolved.md", result.summary);
    await transition(
      {
        ...state(),
        workflowState: "IMPLEMENT",
        resolvedSummary: result.summary,
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
        !["IMPLEMENT", "RESOLVE_FINDINGS"].includes(
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
      (await contentFingerprint()) !== state().reviewedFingerprint
    ) {
      throw workflowError("Finding override is stale or inapplicable.");
    }
    const findings = state().findings.filter(
      ({ id }) => id !== resumeAction.findingId,
    );
    const pendingDisputes = state().pendingDisputes.filter(
      ({ findingId }) => findingId !== resumeAction.findingId,
    );
    await transition(
      {
        ...state(),
        workflowState:
          findings.length === 0 && pendingDisputes.length === 0
            ? "COMMIT"
            : "RESOLVE_FINDINGS",
        findings,
        pendingDisputes,
        reviewReconsideration: state().reviewReconsideration.filter(
          (id) => id !== resumeAction.findingId,
        ),
        findingOverrides: [
          ...state().findingOverrides,
          {
            findingId: resumeAction.findingId,
            fingerprint: state().reviewedFingerprint,
          },
        ].slice(-MAX_DIAGNOSTIC_ITEMS),
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

Use BLOCKED only for an external environment blocker.

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
    const beforeFingerprint = await contentFingerprint();
    const guidance = await resolveFinalizationGuidance();
    if (guidance === null) {
      return false;
    }
    async function requestFinalization(selectedGuidance) {
      const output = await runRole(
        "worker",
        FINALIZATION_SCHEMA,
        (evidence) => `${FINALIZATION_INSTRUCTIONS}

${finalizationGuidanceInstructions(selectedGuidance)}

${evidence}

Current planned commit:
## Commit ${step.number}: ${step.subject}

${step.body}
`,
        {
          access: "workspace-write",
          checkpoint: `commit:${state().currentStep}`,
          recoveryContext: resolvedContext(),
        },
      );
      if (output === null) {
        return null;
      }
      const result = normalizeFinalizationResult(output);
      if (
        selectedGuidance.skillPath === null &&
        ["SKILL_MISSING", "SKILL_INVALID"].includes(result.status)
      ) {
        throw workflowError(
          "Worker returned a skill availability status without selected finalization skill guidance.",
          "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
        );
      }
      if (
        result.status !== "PRODUCT_DECISION_REQUIRED" &&
        result.skillPath !== selectedGuidance.skillPath
      ) {
        throw workflowError(
          "Worker returned a finalization result for the wrong skill path.",
          "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
        );
      }
      return result;
    }
    let result = await requestFinalization(guidance);
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
      result = await requestFinalization(
        Object.freeze({ required: false, skillPath: null }),
      );
      if (result === null) {
        return false;
      }
    }
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    if (["SKILL_MISSING", "SKILL_INVALID", "BLOCKED"].includes(result.status)) {
      const modifiedBeforeValidation =
        result.status !== "BLOCKED" &&
        (await contentFingerprint()) !== beforeFingerprint;
      const reasons = {
        SKILL_MISSING: "finalization_skill_missing",
        SKILL_INVALID: "finalization_skill_invalid",
        BLOCKED: "finalization_cannot_pass",
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
    const finalizationResult = { ...result, fingerprint };
    if (result.status === "FAIL") {
      const correction = correctionUpdate({
        fingerprint,
        finalizationIssueIds: result.issues.map(({ id }) => id),
        findingIds: [],
      });
      await transition(
        {
          ...state(),
          workflowState: "RESOLVE_FINDINGS",
          finalizationResult,
          finalizedFingerprint: null,
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
            `Finalization reported ${result.issues.length} blocking issues.`,
          ),
        },
      );
      return true;
    }
    await transition(
      {
        ...state(),
        workflowState: "REVIEW",
        finalizationResult,
        finalizedFingerprint: fingerprint,
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

  async function runReviewTurn() {
    const current = state();
    const fingerprint = await contentFingerprint();
    if (fingerprint !== current.finalizedFingerprint) {
      throw workflowError("Finalized content changed before review.");
    }
    const step = planStep();
    const output = await runRole(
      "reviewer",
      REVIEW_SCHEMA,
      (evidence) => `${REVIEW_INSTRUCTIONS}

Reuse an existing ID for an unchanged finding. Use FINDINGS with every actionable blocker.

${evidence}

Current planned commit:
## Commit ${step.number}: ${step.subject}

${step.body}

Finalization result:
${JSON.stringify(current.finalizationResult, null, 2)}

Previous findings for this step:
${JSON.stringify(current.previousFindings, null, 2)}${
        current.reviewReconsideration.length === 0
          ? ""
          : `\n\nReconsider these current finding IDs as requested by the Arbiter:\n${current.reviewReconsideration.join(", ")}`
      }

Prior decisions for this step:
${JSON.stringify(priorFindingDecisions(), null, 2)}`,
      {
        checkpoint: `commit:${current.currentStep}`,
        recoveryContext: resolvedContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeReviewResult(output, current.previousFindings);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "IMPLEMENT");
    }
    const reviewedFingerprint = await contentFingerprint();
    if (reviewedFingerprint !== fingerprint) {
      throw workflowError("Reviewed content fingerprint changed unexpectedly.");
    }
    if (result.status === "FINDINGS") {
      const correction = correctionUpdate({
        fingerprint,
        finalizationIssueIds: [],
        findingIds: result.findings.map(({ id }) => id),
      });
      const pendingDisputes = result.findings.flatMap(({ id }) => {
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
          workflowState: "RESOLVE_FINDINGS",
          reviewedFingerprint,
          findings: result.findings,
          previousFindings: result.findings,
          pendingDisputes,
          correctionHistory: correction.history,
          sameFindingRounds: correction.sameFindingRounds,
          pendingCorrection: false,
          blockedSinceStagnation: correction.blockedSinceStagnation,
          reviewerStep: current.currentStep,
          reviewReconsideration: [],
        },
        {
          nextCounters: correction.counters,
          publicActivity: activity(
            "reviewer",
            "review",
            "findings",
            `Review reported ${result.findings.length} blocking findings.`,
          ),
        },
      );
      return true;
    }
    await transition(
      {
        ...state(),
        workflowState: "COMMIT",
        reviewedFingerprint,
        findings: [],
        previousFindings: [],
        pendingDisputes: [],
        pendingCorrection: false,
        reviewerStep: current.currentStep,
        reviewReconsideration: [],
      },
      {
        publicActivity: activity(
          "reviewer",
          "review",
          "approved",
          "Review approved the finalized content.",
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
    const reviewPending = current.reviewedFingerprint === null;
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
            ? "COMMIT"
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
      if (current.stagnationArbitrationUsed) {
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
            fixRounds: counters().fixRounds + (changed ? 0 : 1),
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
      pendingCommit = { status: "prepared", authorization };
    }

    let agentError;
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
        prompt: `${COMMIT_INSTRUCTIONS}

Authorized planned commit:
${step.subject}`,
        ...executionPreferences,
        ...(previousSession === undefined
          ? {}
          : { session: { id: previousSession, mode: "continue" } }),
      };
      try {
        await runtime.adapters.worker.run(request);
      } catch (cause) {
        agentError = cause;
      }
      pendingCommit = {
        status: "consumed",
        authorization: pendingCommit.authorization,
      };
    }

    let verified;
    try {
      verified = await runtime.git.verifyCommit(pendingCommit.authorization);
    } catch (cause) {
      if (
        ![
          "ERR_COMMIT_NOT_CREATED",
          "ERR_COMMIT_CONTRACT_VIOLATED",
        ].includes(cause?.code)
      ) {
        throw cause;
      }
      if (
        cause.code === "ERR_COMMIT_NOT_CREATED" &&
        agentError?.recoverable === true &&
        agentError?.ambiguous === false
      ) {
        await pauseRejectedCommit(agentError);
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
        repositoryBaseline: nextRepositoryBaseline,
        currentStep: done ? null : current.currentStep + 1,
        reviewerStep: null,
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
    if (!(await applyResumeAction())) {
      return currentRun;
    }
    if (state().workflowState === "WAITING_FOR_USER") {
      if (state().pendingEdit !== null) {
        if (!(await resumeEdit())) {
          return currentRun;
        }
      } else if (
        currentRun.pause.reason === "commit_failed" &&
        state().pendingCommit?.status === "consumed"
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
          ].includes(currentRun.pause.reason) &&
            [
              "CLARIFY",
              "BOOTSTRAP",
              "IMPLEMENT",
              "FINALIZE",
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
      !["WAITING_FOR_USER", "FAILED", "DONE"].includes(state().workflowState) &&
      (!commitVerificationPending &&
        ((await readCurrentInputs()) === null ||
          !(await verifyPersistedRepository())))
    ) {
      return currentRun;
    }

    while (true) {
      const current = state();

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
