import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

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
  PLAN_COMPATIBILITY_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
} from "./prompts.js";
import {
  BOOTSTRAP_ARBITRATION_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_SCHEMA,
  CLARIFICATION_SCHEMA,
  PLAN_COMPATIBILITY_SCHEMA,
} from "./schemas.js";
import {
  INVALID_EXECUTION_INPUT_CODE,
  MAX_CLARIFICATION_ROUNDS,
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
  normalizeInputSnapshot,
  normalizePipelineState,
  normalizeReconciliationResult,
  normalizedCounters,
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
const RETRYABLE_PREFLIGHT_REASONS = new Set([
  "backend_unavailable",
  "local_artifacts_not_ignored",
  "unsafe_git_state",
]);
const GIT_PREFLIGHT_CODES = new Set([
  "ERR_GIT_IDENTITY_REQUIRED",
  "ERR_GIT_UNAVAILABLE",
  "ERR_NOT_GIT_REPOSITORY",
  "ERR_REPOSITORY_NOT_CLEAN",
  "ERR_TRACKED_RUNNER_CONFIGURATION",
  "ERR_UNIGNORED_RUNNER_CONFIGURATION",
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

export async function runPlanExecution({ run, runtime, settings }) {
  assertRun(run);
  assertRuntime(runtime);
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

  async function transition(
    nextPipelineState,
    {
      nextCounters = counters(),
      nextHashes = currentRun.hashes,
      pause = currentRun.pause,
      publicActivity,
    } = {},
  ) {
    currentRun = await runtime.transition(
      {
        counters: nextCounters,
        hashes: nextHashes,
        pause,
        pipelineState: nextPipelineState,
      },
      { activity: publicActivity },
    );
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
      },
      {
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

  async function recordSession(role, sessionId, continuedSessionId) {
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
      { role, sessionId },
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

  async function runRole(
    role,
    schema,
    buildPrompt,
    { freshSession = false } = {},
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
    const previousSession = freshSession
      ? undefined
      : [...currentRun.sessionLineage.children]
          .reverse()
          .find((child) => child.role === role)?.sessionId;
    const sourceSession = currentRun.sessionLineage.source;
    const session =
      previousSession !== undefined
        ? { id: previousSession, mode: "continue" }
        : sourceSession !== null && role !== "arbiter"
          ? { id: sourceSession, mode: "fork" }
          : undefined;
    const roleConfiguration = currentRun.roles[role];
    const request = {
      access: "read-only",
      cwd: currentRun.projectPath,
      prompt: buildPrompt(
        inputEvidence(evidence.inputs, evidence.canonicalPlan, evidence.clarification),
      ),
      schema,
      ...(roleConfiguration.model === null
        ? {}
        : { model: roleConfiguration.model }),
      ...(session === undefined ? {} : { session }),
    };
    let response;
    let agentError;
    try {
      response = await runtime.adapters[role].run(request);
    } catch (cause) {
      agentError = cause;
    }
    await runtime.git.assertUnchanged(turnSnapshot);
    await runtime.git.assertUnchanged(baseline);
    if ((await readCurrentInputs()) === null) {
      return null;
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
    await recordSession(role, response.sessionId, previousSession);
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
      publicActivity = activity(
        "runner",
        "clarification",
        "input-required",
        "Clarification input is required.",
      ),
    } = {},
  ) {
    await transition(
      {
        ...nextPipelineState,
        workflowState: "WAITING_FOR_USER",
        pendingEdit: authorization,
      },
      {
        nextCounters,
        nextHashes,
        pause: { reason, authorizationId: authorization.id },
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
        workerSummary: productDecision ? null : current.workerSummary,
        reviewerSummary: productDecision ? null : current.reviewerSummary,
        resolvedSummary: productDecision ? null : current.resolvedSummary,
        bootstrapDisagreement: productDecision
          ? null
          : current.bootstrapDisagreement,
        bootstrapArbitrationUsed: productDecision
          ? false
          : current.bootstrapArbitrationUsed,
        compatibilityCheckRequired:
          productDecision && result.suspendedState === "BOOTSTRAP",
        currentStep: productDecision ? null : current.currentStep,
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
    return requestEdit(
      "product-decision",
      suspendedState,
      "product_decision_required",
      {
        expectedHash: transcript.hash,
        nextPipelineState: {
          ...current,
          clarificationFrozen: false,
          workerSummary: null,
          reviewerSummary: null,
          resolvedSummary: null,
          bootstrapDisagreement: null,
          bootstrapArbitrationUsed: false,
          compatibilityCheckRequired: false,
          currentStep: null,
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
      "LOCAL_ARTIFACTS",
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
    const restartIndependentBootstrap = currentRun.sessionLineage.children.some(
      (child) => child.role === "reviewer",
    );
    const output = await runRole(
      role,
      BOOTSTRAP_SCHEMA,
      (evidence) => `${BOOTSTRAP_INSTRUCTIONS}${
        role === "reviewer"
          ? "\nAs Reviewer, also state what you intend to verify."
          : ""
      }

${PRODUCT_DECISION_INSTRUCTIONS}
Use READY with a concise summary and empty blocking fields, PLAN_REVISION_REQUIRED with concise reason and evidence, or PRODUCT_DECISION_REQUIRED with an empty summary and reason.

${evidence}`,
      { freshSession: restartIndependentBootstrap },
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
Use empty fields that do not apply to the selected status.

${evidence}

Worker bootstrap summary:
${state().workerSummary}

Reviewer bootstrap summary:
${state().reviewerSummary}`,
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
Use empty fields that do not apply to the selected direction.

${evidence}

Worker bootstrap summary:
${state().workerSummary}

Reviewer bootstrap summary:
${state().reviewerSummary}

Recorded disagreement:
${JSON.stringify(state().bootstrapDisagreement, null, 2)}`,
      { freshSession: true },
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

  try {
    if (state().settings === null) {
      await transition({ ...state(), settings }, { pause: null });
    }
    if (state().workflowState === "WAITING_FOR_USER") {
      if (state().pendingEdit !== null) {
        if (!(await resumeEdit())) {
          return currentRun;
        }
      } else if (
        RETRYABLE_PREFLIGHT_REASONS.has(currentRun.pause.reason) &&
        (!state().preflightComplete ||
          (currentRun.pause.reason === "backend_unavailable" &&
            currentRun.pause.resumeState === "BOOTSTRAP"))
      ) {
        await transition(
          {
            ...state(),
            workflowState: state().preflightComplete ? "BOOTSTRAP" : "CLARIFY",
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
    if (
      state().preflightComplete &&
      !["WAITING_FOR_USER", "FAILED", "DONE"].includes(state().workflowState) &&
      ((await readCurrentInputs()) === null ||
        !(await verifyPersistedRepository()))
    ) {
      return currentRun;
    }

    while (true) {
      const current = state();

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
Use empty fields that do not apply to the selected status.

${evidence}`,
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
        if (current.compatibilityCheckRequired) {
          const output = await runRole(
            "worker",
            PLAN_COMPATIBILITY_SCHEMA,
            (evidence) => `${PLAN_COMPATIBILITY_INSTRUCTIONS}

${evidence}`,
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
        if (state().workflowState === "IMPLEMENT") {
          return currentRun;
        }
        continue;
      }

      if (
        [
          "IMPLEMENT",
          "FINALIZE",
          "REVIEW",
          "RESOLVE_FINDINGS",
          "COMMIT",
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
    if (cause?.code === "ERR_READ_ONLY_REPOSITORY_CHANGED") {
      return invalidateInputs("read_only_agent_mutated_repository", {
        code: cause.code,
        phase: "repository",
        message: "Repository changed during a read-only plan-execution turn.",
      });
    }
    if (cause?.code === "ERR_PLAN_EXECUTION_BACKEND_UNAVAILABLE") {
      return pause("backend_unavailable", {
        code: cause.code,
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
