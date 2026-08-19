import { realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
} from "./prompts.js";
import {
  BOOTSTRAP_ARBITRATION_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_SCHEMA,
  CLARIFICATION_SCHEMA,
} from "./schemas.js";
import {
  activity,
  assertRun,
  assertRuntime,
  assertSettings,
  createPolishingState,
  diagnosticCode,
  INVALID_POLISHING_INPUT_CODE,
  isRecord,
  MAX_CLARIFICATION_ROUNDS,
  normalizeAdapterCapabilities,
  normalizeBootstrapArbitration,
  normalizeBootstrapResult,
  normalizeClarificationResult,
  normalizeInputSnapshot,
  normalizePipelineState,
  normalizeReconciliationResult,
  normalizedCounters,
  PolishingWorkflowError,
  workflowError,
  WORKFLOW_STATES,
} from "./workflow-contract.js";

export {
  createPolishingState,
  MAX_CLARIFICATION_ROUNDS,
  PolishingWorkflowError,
  WORKFLOW_STATES,
};

const INPUT_DRIFT_CODES = new Set([
  "ENOENT",
  "EISDIR",
  "ENOTDIR",
  "ERR_INVALID_POLISHING_INPUT",
]);
const SAFE_PREFLIGHT_PAUSE_CODES = new Set([
  "ERR_GIT_UNAVAILABLE",
  "ERR_NOT_GIT_REPOSITORY",
  "ERR_UNSAFE_GIT_STATE",
  "ERR_UNSAFE_REPOSITORY_PATH",
  "ERR_UNSUPPORTED_GIT_CONFIGURATION",
  "ERR_UNSUPPORTED_GIT_PATH",
  "ERR_GIT_SNAPSHOT_RACE",
]);

function isWithin(parentPath, childPath) {
  const pathFromParent = relative(parentPath, childPath);
  return (
    pathFromParent === "" ||
    (!pathFromParent.startsWith(`..${sep}`) &&
      pathFromParent !== ".." &&
      !isAbsolute(pathFromParent))
  );
}

function inputEvidence(inputs, clarification) {
  const taskClarifications =
    inputs.taskClarifications === null
      ? "(not provided)"
      : inputs.taskClarifications.content;
  const context =
    inputs.context === null ? "(not provided)" : inputs.context.content;
  const executionClarifications =
    clarification.content.length === 0 ? "(empty)" : clarification.content;
  return `Task (${inputs.task.path}):
${inputs.task.content}

Task-level clarifications:
${taskClarifications}

Context:
${context}

Execution clarifications (${clarification.transcriptPath}):
${executionClarifications}`;
}

export async function runPolishing({ action, run, runtime, settings }) {
  assertRun(run);
  assertRuntime(runtime);
  if (action !== undefined && action !== null) {
    throw workflowError("Resume actions are not available before polishing begins.");
  }
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
          "polishing",
          "paused",
          `Polishing paused: ${reason}.`,
        ),
      },
    );
    return currentRun;
  }

  async function fail(cause) {
    const code = diagnosticCode(cause, "ERR_POLISHING_FAILED");
    try {
      await transition(
        { ...state(), workflowState: "FAILED" },
        {
          pause: { reason: "internal_failure", code },
          publicActivity: activity(
            "runner",
            "polishing",
            "failed",
            `Polishing failed: ${code}.`,
          ),
        },
      );
    } catch {}
    throw cause;
  }

  async function invalidateInputs(reason, message) {
    await transition(
      {
        ...state(),
        workflowState: "WAITING_FOR_USER",
        clarificationFrozen: false,
        pendingEdit: null,
        refreezeRequired: false,
        workerSummary: null,
        reviewerSummary: null,
        resolvedSummary: null,
        bootstrapDisagreement: null,
        bootstrapArbitrationUsed: false,
      },
      {
        pause: { reason },
        publicActivity: activity("runner", "inputs", "changed", message),
      },
    );
    return currentRun;
  }

  async function readInputs() {
    return normalizeInputSnapshot(
      await runtime.readInputs({ taskPath: currentRun.taskPath }),
      currentRun.taskPath,
    );
  }

  async function readCurrentInputs() {
    let inputs;
    try {
      inputs = await readInputs();
    } catch (cause) {
      if (
        !INPUT_DRIFT_CODES.has(cause?.code) &&
        cause?.code !== INVALID_POLISHING_INPUT_CODE
      ) {
        throw cause;
      }
      await invalidateInputs(
        "task_input_changed",
        "Polishing task input changed outside an authorized window.",
      );
      return null;
    }
    let clarification;
    try {
      clarification = await runtime.clarifications.inspectTranscript({
        artifactRoot: state().repositoryBaseline.projectPath,
        transcriptPath: state().clarificationPath,
      });
    } catch (cause) {
      if (
        !INPUT_DRIFT_CODES.has(cause?.code) &&
        !cause?.code?.startsWith("ERR_CLARIFICATION")
      ) {
        throw cause;
      }
      await invalidateInputs(
        "clarifications_changed",
        "Polishing clarification changed outside an authorized window.",
      );
      return null;
    }
    const nextHashes = {
      task: inputs.task.hash,
      taskClarifications: inputs.taskClarifications?.hash ?? null,
      context: inputs.context?.hash ?? null,
      executionClarifications: clarification.hash,
    };
    const changed = Object.keys(nextHashes).find(
      (field) => nextHashes[field] !== currentRun.hashes[field],
    );
    if (changed !== undefined) {
      await invalidateInputs(
        changed === "executionClarifications"
          ? "clarifications_changed"
          : "task_input_changed",
        changed === "executionClarifications"
          ? "Polishing clarification changed outside an authorized window."
          : "Polishing task input changed outside an authorized window.",
      );
      return null;
    }
    return Object.freeze({ inputs, clarification });
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
        "ERR_INVALID_POLISHING_OUTPUT",
      );
    }
    if (sessionId === currentRun.sessionLineage.source) {
      throw workflowError(
        `${role} returned the source session ID instead of a child session.`,
        "ERR_INVALID_POLISHING_OUTPUT",
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
        "ERR_INVALID_POLISHING_OUTPUT",
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
      throw new PolishingWorkflowError(`${role} backend is unavailable.`, {
        cause,
        code: "ERR_POLISHING_BACKEND_UNAVAILABLE",
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
    if (evidence === null || !(await verifyPersistedRepository())) {
      return null;
    }
    const baseline = state().repositoryBaseline;
    const turnSnapshot = await runtime.git.snapshot({
      allowedPaths: baseline.allowedPaths,
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
    const configuration = currentRun.roles[role];
    const request = {
      access: "read-only",
      cwd: currentRun.projectPath,
      prompt: buildPrompt(inputEvidence(evidence.inputs, evidence.clarification)),
      schema,
      ...(configuration.model === null ? {} : { model: configuration.model }),
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
    if (!isRecord(response) || !isRecord(response.structured)) {
      throw workflowError(
        `${role} returned no structured result.`,
        "ERR_INVALID_POLISHING_OUTPUT",
      );
    }
    await recordSession(role, response.sessionId, previousSession);
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

  async function prepareEdit(actionName, suspendedState, reason, options) {
    return runtime.clarifications.prepareEdit({
      artifactRoot: state().repositoryBaseline.projectPath,
      transcriptPath: state().clarificationPath,
      expectedHash:
        options?.expectedHash ?? currentRun.hashes.executionClarifications,
      suspendedState,
      action: actionName,
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
        refreezeRequired: bootstrapDecision,
        workerSummary: bootstrapDecision ? null : current.workerSummary,
        reviewerSummary: bootstrapDecision ? null : current.reviewerSummary,
        resolvedSummary: bootstrapDecision ? null : current.resolvedSummary,
        bootstrapDisagreement: bootstrapDecision
          ? null
          : current.bootstrapDisagreement,
        bootstrapArbitrationUsed: bootstrapDecision
          ? false
          : current.bootstrapArbitrationUsed,
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

  async function requestEdit(actionName, suspendedState, reason, options) {
    const authorization = await prepareEdit(
      actionName,
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
    return editorResult.result.changed || actionName === "proactive-clarification";
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
    const number = counters().productDecisions + 1;
    const transcript = await runtime.clarifications.appendProductDecision({
      artifactRoot: state().repositoryBaseline.projectPath,
      transcriptPath: state().clarificationPath,
      expectedHash: currentRun.hashes.executionClarifications,
      number,
      ...decision,
    });
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
          ...state(),
          clarificationFrozen: false,
          refreezeRequired: false,
          workerSummary: bootstrapDecision ? null : state().workerSummary,
          reviewerSummary: bootstrapDecision ? null : state().reviewerSummary,
          resolvedSummary: null,
          bootstrapDisagreement: null,
          bootstrapArbitrationUsed: false,
        },
        nextCounters: { ...counters(), productDecisions: number },
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

  async function writeContext(path, content) {
    await runtime.writeRunArtifact({ path, content: `${content.trim()}\n` });
  }

  async function initializeInputs() {
    const inputs = await readInputs();
    let discovery;
    try {
      discovery = await runtime.git.preflight({
        allowedPaths: [],
        projectPath: currentRun.projectPath,
        requireClean: false,
        requireIdentity: false,
        requiredIgnoredPaths: [],
      });
    } catch (cause) {
      if (SAFE_PREFLIGHT_PAUSE_CODES.has(cause?.code)) {
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
    for (const input of [
      inputs.task,
      inputs.taskClarifications,
      inputs.context,
    ]) {
      const resolvedInputPath =
        input === null ? null : await realpath(input.path);
      if (
        resolvedInputPath !== null &&
        isWithin(repositoryPath, resolvedInputPath)
      ) {
        const inspection = await runtime.git.inspectPath({
          path: resolvedInputPath,
          projectPath: repositoryPath,
        });
        if (inspection.changed) {
          await pause("task_input_overlaps_changes", { path: input.path });
          return false;
        }
      }
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
        requireClean: false,
        requireIdentity: false,
        requiredIgnoredPaths: [clarificationPath],
      });
    } catch (cause) {
      if (cause?.code === "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED") {
        await pause("local_artifacts_not_ignored", { path: clarificationPath });
        return false;
      }
      if (SAFE_PREFLIGHT_PAUSE_CODES.has(cause?.code)) {
        await pause("unsafe_git_state", { code: cause.code });
        return false;
      }
      throw cause;
    }
    if (preflight?.snapshot?.projectPath !== repositoryPath) {
      throw workflowError("Git preflight returned an unstable repository root.");
    }
    if (preflight.snapshot.clean) {
      await pause("no_changes");
      return false;
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
        settings:
          state().settings === null
            ? Object.freeze({ ...settings })
            : state().settings,
        repositoryBaseline: preflight.snapshot,
        backendVersions: {
          worker: workerCapabilities.version,
          reviewer: reviewerCapabilities.version,
          arbiter: null,
        },
        clarificationPath,
      },
      {
        nextHashes: {
          task: inputs.task.hash,
          taskClarifications: inputs.taskClarifications?.hash ?? null,
          context: inputs.context?.hash ?? null,
          executionClarifications: clarification.hash,
        },
        publicActivity: activity(
          "runner",
          "preflight",
          "passed",
          "Polishing preflight passed and dirty inputs were recorded.",
        ),
      },
    );
    return true;
  }

  async function bootstrapRole(role) {
    const restartIndependentReviewer =
      role === "reviewer" &&
      currentRun.sessionLineage.children.some(
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

${evidence}`,
      { freshSession: restartIndependentReviewer },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeBootstrapResult(output, role);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
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
    );
    if (output === null) {
      return false;
    }
    const result = normalizeReconciliationResult(output);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
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
        workflowState: "POLISH",
        resolvedSummary: result.summary,
      },
      {
        publicActivity: activity(
          "worker",
          "bootstrap",
          "resolved",
          "Bootstrap context resolved; workspace is prepared for polishing.",
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
      { freshSession: true },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeBootstrapArbitration(output);
    if (result.direction === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    await writeContext("context/resolved.md", result.summary);
    await transition(
      {
        ...state(),
        workflowState: "POLISH",
        resolvedSummary: result.summary,
        bootstrapDisagreement: null,
        bootstrapArbitrationUsed: true,
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
    if (state().workflowState === "FAILED") {
      return currentRun;
    }
    if (state().workflowState === "WAITING_FOR_USER") {
      if (state().pendingEdit !== null) {
        if (!(await resumeEdit())) {
          return currentRun;
        }
      } else if (currentRun.pause.reason === "backend_unavailable") {
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
    if (state().workflowState === "POLISH") {
      return currentRun;
    }
    if (
      state().preflightComplete &&
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

${evidence}`,
        );
        if (output === null) {
          return currentRun;
        }
        const result = normalizeClarificationResult(output);
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
                "Polishing clarification completed.",
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
        if (current.refreezeRequired) {
          const frozen = await runtime.clarifications.freezeTranscript({
            artifactRoot: current.repositoryBaseline.projectPath,
            transcriptPath: current.clarificationPath,
            expectedHash: currentRun.hashes.executionClarifications,
          });
          await transition(
            {
              ...current,
              clarificationFrozen: true,
              refreezeRequired: false,
            },
            {
              nextHashes: {
                ...currentRun.hashes,
                executionClarifications: frozen.hash,
              },
              publicActivity: activity(
                "runner",
                "clarification",
                "refrozen",
                "Product decision was accepted and clarification refrozen.",
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
        continue;
      }

      if (
        ["POLISH", "WAITING_FOR_USER", "FAILED"].includes(
          current.workflowState,
        )
      ) {
        return currentRun;
      }
      throw workflowError(`Unsupported polishing state: ${current.workflowState}.`);
    }
  } catch (cause) {
    if (cause?.code === "ERR_READ_ONLY_REPOSITORY_CHANGED") {
      return invalidateInputs(
        "read_only_agent_mutated_repository",
        "Repository changed during a read-only polishing turn.",
      );
    }
    if (
      cause?.code === "ERR_POLISHING_BACKEND_UNAVAILABLE" ||
      cause?.recoverable === true
    ) {
      return pause("backend_unavailable", {
        code: diagnosticCode(cause, "ERR_BACKEND_UNAVAILABLE"),
        ...(state().preflightComplete
          ? { resumeState: state().workflowState }
          : {}),
      });
    }
    return fail(cause);
  }
}
