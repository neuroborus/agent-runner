import { realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  finalizationBootstrapInstructions,
  finalizationGuidanceInstructions,
  FINDING_ARBITRATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  POLISH_INSTRUCTIONS,
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
  POLISH_SCHEMA,
  REVIEW_SCHEMA,
  STAGNATION_SCHEMA,
} from "./schemas.js";
import {
  activity,
  assertRun,
  assertRuntime,
  assertSettings,
  createPolishingState,
  CONVENTIONAL_FINALIZATION_SKILL_PATHS,
  diagnosticCode,
  disputeHistoryCapacity,
  disputeHistoryFits,
  INVALID_POLISHING_INPUT_CODE,
  isRecord,
  MAX_DIAGNOSTIC_ITEMS,
  MAX_CLARIFICATION_ROUNDS,
  normalizeAdapterCapabilities,
  normalizeBootstrapArbitration,
  normalizeBootstrapResult,
  normalizeClarificationResult,
  normalizeFinalizationResult,
  normalizeFindingArbitration,
  normalizeInputSnapshot,
  normalizePipelineState,
  normalizePolishResult,
  normalizeReconciliationResult,
  normalizeReconsiderationResult,
  normalizeResolutionResult,
  normalizeResumeAction,
  normalizeReviewResult,
  normalizeStagnationResult,
  normalizedCounters,
  PolishingWorkflowError,
  sha256,
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

function durableContext(evidence, recoveryContext) {
  return recoveryContext.length === 0
    ? evidence
    : `${evidence}\n\n${recoveryContext}`;
}

function contextKeyFor(role, checkpoint, context) {
  if (typeof checkpoint !== "string" || checkpoint.length === 0) {
    throw workflowError("Polishing session checkpoint is invalid.");
  }
  return sha256(`${role}\0${checkpoint}\0${context}`);
}

export async function runPolishing({ action, run, runtime, settings }) {
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

  function workContext({ includePolishSummary = false } = {}) {
    const current = state();
    return [
      current.resolvedSummary === null
        ? ""
        : `Resolved bootstrap context:\n${current.resolvedSummary}`,
      includePolishSummary && current.polishSummary !== null
        ? `Worker polishing summary:\n${current.polishSummary}`
        : "",
    ]
      .filter((part) => part.length > 0)
      .join("\n\n");
  }

  function clearedWorkState(current, { clearBootstrap = false } = {}) {
    return {
      ...current,
      ...(clearBootstrap
        ? {
            workerSummary: null,
            reviewerSummary: null,
            workerValidation: null,
            reviewerValidation: null,
            resolvedSummary: null,
            bootstrapDisagreement: null,
            bootstrapArbitrationUsed: false,
            requiredChecks: null,
            validationInfrastructure: null,
            validationInfrastructureFingerprint: null,
            validationMigrationPending: false,
          }
        : {}),
      polishSummary: null,
      finalizationResult: null,
      finalizedFingerprint: null,
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
      additionalFixRounds: clearBootstrap ? 0 : current.additionalFixRounds,
      findingOverrides: [],
    };
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
    assertRun({
      ...currentRun,
      ...patch,
      revision: currentRun.revision + 1,
    });
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
        ...clearedWorkState(state(), { clearBootstrap: true }),
        workflowState: "WAITING_FOR_USER",
        clarificationFrozen: false,
        pendingEdit: null,
        refreezeRequired: false,
      },
      {
        nextCounters: {
          ...counters(),
          fixRounds: 0,
          correctionRounds: 0,
        },
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

  async function recordSession(
    role,
    sessionId,
    continuedSessionId,
    contextKey,
  ) {
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
    assertRun({
      ...currentRun,
      revision: currentRun.revision + 1,
      sessionLineage: {
        ...currentRun.sessionLineage,
        children: [
          ...currentRun.sessionLineage.children,
          { role, sessionId, contextKey },
        ],
      },
    });
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
      reportWorkspaceChange = false,
    } = {},
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
    const evidenceContext = inputEvidence(
      evidence.inputs,
      evidence.clarification,
    );
    const checkpointContext =
      checkpoint === "clarification"
        ? recoveryContext
        : durableContext(
            `Change-set fingerprint before this turn:\n${turnSnapshot.contentFingerprint}`,
            recoveryContext,
          );
    const context = durableContext(evidenceContext, checkpointContext);
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
    const configuration = currentRun.roles[role];
    const recoveryPrompt = buildPrompt(context);
    const executionPreferences = Object.fromEntries(
      ["profile", "model", "contextSize"].flatMap((field) =>
        typeof configuration[field] === "string" &&
        configuration[field] !== "current"
          ? [[field, configuration[field]]]
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
      const reason = workspaceControlChange(turnSnapshot, nextRepositoryBaseline);
      if (reason !== null) {
        await pause(reason);
        return null;
      }
      const contentChanged =
        baseline.contentFingerprint !== nextRepositoryBaseline.contentFingerprint;
      const workspaceChanged = [
        "clean",
        "trackedContentFingerprint",
        "untrackedContentFingerprint",
        "contentFingerprint",
        "indexFingerprint",
      ].some((field) => baseline[field] !== nextRepositoryBaseline[field]);
      if (workspaceChanged) {
        const current = state();
        const contentChangingCorrection =
          contentChanged && current.workflowState === "RESOLVE_FINDINGS";
        await transition(
          contentChangingCorrection
            ? {
                ...current,
                workflowState: "FINALIZE",
                repositoryBaseline: nextRepositoryBaseline,
                finalizationResult: null,
                finalizedFingerprint: null,
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
                      reviewResult: null,
                      reviewedFingerprint: null,
                      findings: [],
                      reviewReconsideration: [],
                    }
                  : {}),
              },
          contentChangingCorrection
            ? {
                nextCounters: {
                  ...counters(),
                  fixRounds: counters().fixRounds + 1,
                },
              }
            : undefined,
        );
      }
    }
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
    await recordSession(
      role,
      response.sessionId,
      previousSession,
      contextKey,
    );
    return reportWorkspaceChange
      ? Object.freeze({
          output: response.structured,
          workspaceChanged:
            baseline.contentFingerprint !==
            nextRepositoryBaseline.contentFingerprint,
        })
      : response.structured;
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
    const resumedState = bootstrapDecision
      ? clearedWorkState(current, { clearBootstrap: true })
      : current;
    await transition(
      {
        ...resumedState,
        workflowState: result.suspendedState,
        pendingEdit: null,
        proactiveClarificationComplete:
          result.action === "proactive-clarification"
            ? true
            : current.proactiveClarificationComplete,
        clarificationFrozen: false,
        refreezeRequired: bootstrapDecision,
        workerSummary: bootstrapDecision ? null : resumedState.workerSummary,
        reviewerSummary: bootstrapDecision ? null : resumedState.reviewerSummary,
        resolvedSummary: bootstrapDecision ? null : resumedState.resolvedSummary,
        bootstrapDisagreement: bootstrapDecision
          ? null
          : resumedState.bootstrapDisagreement,
        bootstrapArbitrationUsed: bootstrapDecision
          ? false
          : resumedState.bootstrapArbitrationUsed,
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
          ...clearedWorkState(state(), { clearBootstrap: bootstrapDecision }),
          clarificationFrozen: false,
          refreezeRequired: false,
          resolvedSummary: null,
          bootstrapDisagreement: null,
          bootstrapArbitrationUsed: false,
        },
        nextCounters: {
          ...counters(),
          productDecisions: number,
          ...(bootstrapDecision
            ? { fixRounds: 0, correctionRounds: 0 }
            : {}),
        },
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

  async function establishedValidation(result) {
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
    const resumePolishing =
      currentRun.pause?.resumeState === "POLISH" &&
      current.finalizationResult === null;
    const additionalFixRounds =
      resumeAction?.type === "extra-fix-rounds"
        ? current.additionalFixRounds + resumeAction.amount
        : current.additionalFixRounds;
    await transition(
      {
        ...invalidatedLegacyValidation(current),
        workflowState: resumePolishing ? "POLISH" : "FINALIZE",
        additionalFixRounds,
      },
      {
        pause: null,
        publicActivity: activity(
          "runner",
          "migration",
          "validation-invalidated",
          "Legacy validation evidence invalidated before resume.",
        ),
      },
    );
    return resumeAction !== null;
  }

  async function rediscoverValidationRole(role) {
    const output = await runRole(
      role,
      BOOTSTRAP_SCHEMA,
      (evidence) => `${BOOTSTRAP_INSTRUCTIONS}

This is a versioned-state migration checkpoint. Treat every persisted legacy check, path, fingerprint, and aggregate validation result as provisional. Independently rediscover the complete current validation inventory from repository evidence before work can advance.

${finalizationBootstrapInstructions(state().settings.finalization)}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}`,
      {
        checkpoint: "validation-migration",
        recoveryContext: workContext({ includePolishSummary: true }),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeBootstrapResult(output, role);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      throw workflowError(
        "Validation migration cannot require a product decision.",
        "ERR_INVALID_POLISHING_OUTPUT",
      );
    }
    await transition(
      {
        ...state(),
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

  async function completeValidationMigration(result, actor) {
    const validation = await establishedValidation(result);
    await transition(
      {
        ...state(),
        ...validation,
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
    const output = await runRole(
      "worker",
      BOOTSTRAP_RECONCILIATION_SCHEMA,
      (evidence) => `${BOOTSTRAP_RECONCILIATION_INSTRUCTIONS}

Reconcile only the independently rediscovered validation requirements. Legacy validation evidence is provisional and must not be selected.

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
      {
        checkpoint: "validation-migration",
        recoveryContext: workContext({ includePolishSummary: true }),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeReconciliationResult(output);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      throw workflowError(
        "Validation migration cannot require a product decision.",
        "ERR_INVALID_POLISHING_OUTPUT",
      );
    }
    if (result.status === "RESOLVED") {
      return completeValidationMigration(result, "worker");
    }
    const arbitrationOutput = await runRole(
      "arbiter",
      BOOTSTRAP_ARBITRATION_SCHEMA,
      (evidence) => `${BOOTSTRAP_ARBITRATION_INSTRUCTIONS}

Resolve only this validation-inventory migration disagreement. Legacy validation evidence is provisional and must not be selected.

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
      {
        checkpoint: "validation-migration",
        recoveryContext: workContext({ includePolishSummary: true }),
      },
    );
    if (arbitrationOutput === null) {
      return false;
    }
    const arbitration = normalizeBootstrapArbitration(arbitrationOutput);
    if (arbitration.direction === "PRODUCT_DECISION_REQUIRED") {
      throw workflowError(
        "Validation migration cannot require a product decision.",
        "ERR_INVALID_POLISHING_OUTPUT",
      );
    }
    return completeValidationMigration(arbitration, "arbiter");
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

  function fixBudget() {
    return state().settings.maxFixRounds + state().additionalFixRounds;
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

  function priorFindingDecisions(ids) {
    const wanted = ids === undefined ? null : new Set(ids);
    const includes = ({ findingId }) =>
      wanted === null || wanted.has(findingId);
    return {
      disputes: state().disputeHistory.filter(includes),
      arbitrations: state().findingArbitrations.filter(includes),
      overrides: state().findingOverrides.filter(includes),
    };
  }

  function latestFindingEntries(entries) {
    const byFinding = new Map();
    for (const entry of entries) {
      byFinding.delete(entry.findingId);
      byFinding.set(entry.findingId, entry);
    }
    return [...byFinding.values()];
  }

  function compactFindingDecisions(
    current,
    updates = {},
    { additionalDisputeHistory = [], overflowCode } = {},
  ) {
    const next = { ...current, ...updates };
    const disputeCounts = { ...next.disputeCounts };
    let disputeHistory = [...next.disputeHistory];
    let findingArbitrations = latestFindingEntries(next.findingArbitrations);
    let findingOverrides = latestFindingEntries(next.findingOverrides);
    const protectedIds = new Set([
      ...next.findings.map(({ id }) => id),
      ...next.previousFindings.map(({ id }) => id),
      ...next.pendingDisputes.map(({ findingId }) => findingId),
      ...next.reviewReconsideration,
    ]);
    const recordedIds = new Set([
      ...protectedIds,
      ...disputeHistory.map(({ findingId }) => findingId),
      ...findingArbitrations.map(({ findingId }) => findingId),
      ...findingOverrides.map(({ findingId }) => findingId),
    ]);
    for (const findingId of Object.keys(disputeCounts)) {
      if (!recordedIds.has(findingId)) {
        delete disputeCounts[findingId];
      }
    }
    const orderedIds = [
      ...new Set([
        ...Object.keys(disputeCounts),
        ...disputeHistory.map(({ findingId }) => findingId),
        ...findingArbitrations.map(({ findingId }) => findingId),
        ...findingOverrides.map(({ findingId }) => findingId),
      ]),
    ];
    const historyCapacity = disputeHistoryCapacity(next.settings);
    const capacityExceeded = () =>
      orderedIds.length > MAX_DIAGNOSTIC_ITEMS ||
      Object.keys(disputeCounts).length > MAX_DIAGNOSTIC_ITEMS ||
      disputeHistory.length + additionalDisputeHistory.length >
        historyCapacity ||
      !disputeHistoryFits([
        ...disputeHistory,
        ...additionalDisputeHistory,
      ]) ||
      findingArbitrations.length > MAX_DIAGNOSTIC_ITEMS ||
      findingOverrides.length > MAX_DIAGNOSTIC_ITEMS;
    while (capacityExceeded()) {
      const removableIndex = orderedIds.findIndex(
        (findingId) => !protectedIds.has(findingId),
      );
      if (removableIndex === -1) {
        throw workflowError(
          overflowCode === "ERR_INVALID_POLISHING_OUTPUT"
            ? "Polishing dispute evidence exceeds its durable history limit."
            : "Polishing finding-decision capacity is exhausted.",
          overflowCode,
        );
      }
      const [findingId] = orderedIds.splice(removableIndex, 1);
      delete disputeCounts[findingId];
      disputeHistory = disputeHistory.filter(
        (entry) => entry.findingId !== findingId,
      );
      findingArbitrations = findingArbitrations.filter(
        (entry) => entry.findingId !== findingId,
      );
      findingOverrides = findingOverrides.filter(
        (entry) => entry.findingId !== findingId,
      );
    }
    return {
      disputeCounts,
      disputeHistory,
      findingArbitrations,
      findingOverrides,
    };
  }

  function correctionUpdate({ fingerprint, finalizationIssueIds, findingIds }) {
    const current = state();
    if (!current.pendingCorrection) {
      return Object.freeze({
        counters: counters(),
        history: current.correctionHistory,
        sameFindingRounds: current.sameFindingRounds,
        blockedSinceStagnation: current.blockedSinceStagnation,
      });
    }
    const correctionRounds = counters().correctionRounds + 1;
    const findingSet = new Set(findingIds);
    const sameFindingRounds = Object.fromEntries(
      findingIds.map((id) => [id, (current.sameFindingRounds[id] ?? 0) + 1]),
    );
    for (const id of Object.keys(current.sameFindingRounds)) {
      if (!findingSet.has(id)) {
        delete sameFindingRounds[id];
      }
    }
    return Object.freeze({
      counters: { ...counters(), correctionRounds },
      history: [
        ...current.correctionHistory,
        { round: correctionRounds, fingerprint, finalizationIssueIds, findingIds },
      ].slice(-MAX_DIAGNOSTIC_ITEMS),
      sameFindingRounds,
      blockedSinceStagnation: current.blockedSinceStagnation + 1,
    });
  }

  async function completeIfReady() {
    const current = state();
    if (
      current.finalizationResult?.status !== "PASS" ||
      current.findings.length !== 0 ||
      current.pendingDisputes.length !== 0 ||
      current.finalizedFingerprint === null ||
      current.reviewedFingerprint !== current.finalizedFingerprint
    ) {
      return false;
    }
    if ((await contentFingerprint()) !== current.finalizedFingerprint) {
      await transition({
        ...current,
        workflowState: "FINALIZE",
        finalizationResult: null,
        finalizedFingerprint: null,
        reviewResult: null,
        reviewedFingerprint: null,
        previousFindings: current.previousFindings,
        pendingCorrection: true,
      });
      return false;
    }
    if (!(await verifyPersistedRepository())) {
      return false;
    }
    await transition(
      { ...current, workflowState: "DONE" },
      {
        publicActivity: activity(
          "runner",
          "polishing",
          "completed",
          "Polishing completed with finalized, reviewed, uncommitted changes.",
        ),
      },
    );
    return true;
  }

  async function applyResumeAction() {
    if (resumeAction === null) {
      return;
    }
    const current = state();
    if (current.workflowState !== "WAITING_FOR_USER" || current.pendingEdit !== null) {
      throw workflowError("Polishing resume action is not applicable.");
    }
    if (resumeAction.type === "extra-fix-rounds") {
      const additionalFixRounds =
        current.additionalFixRounds + resumeAction.amount;
      const totalFixRounds =
        current.settings.maxFixRounds + additionalFixRounds;
      if (
        currentRun.pause.reason !== "fix_limit_reached" ||
        !["POLISH", "RESOLVE_FINDINGS"].includes(
          currentRun.pause.resumeState,
        )
      ) {
        throw workflowError("Additional fix rounds are not applicable.");
      }
      if (
        !Number.isSafeInteger(additionalFixRounds) ||
        !Number.isSafeInteger(totalFixRounds)
      ) {
        throw workflowError("Additional fix-round budget is too large.");
      }
      await transition(
        {
          ...current,
          workflowState: currentRun.pause.resumeState,
          additionalFixRounds,
        },
        {
          pause: null,
          publicActivity: activity(
            "runner",
            "resolution",
            "budget-extended",
            `Added ${resumeAction.amount} polishing fix rounds.`,
          ),
        },
      );
      return;
    }
    const finding = current.findings.find(
      ({ id }) => id === resumeAction.findingId,
    );
    if (
      finding === undefined ||
      current.reviewedFingerprint === null ||
      !["fix_limit_reached", "no_progress"].includes(currentRun.pause.reason)
    ) {
      throw workflowError("Finding override is not applicable.");
    }
    if (!(await verifyPersistedRepository())) {
      return;
    }
    if ((await contentFingerprint()) !== current.reviewedFingerprint) {
      await pause("unsafe_git_state", {
        code: "ERR_OVERRIDE_FINGERPRINT_CHANGED",
      });
      return;
    }
    const findings = current.findings.filter(({ id }) => id !== finding.id);
    const pendingDisputes = current.pendingDisputes.filter(
      ({ findingId }) => findingId !== finding.id,
    );
    const findingDecisions = compactFindingDecisions(current, {
      findings,
      pendingDisputes,
      findingOverrides: [
        ...current.findingOverrides.filter(
          ({ findingId }) => findingId !== finding.id,
        ),
        { findingId: finding.id, fingerprint: current.reviewedFingerprint },
      ],
    });
    await transition(
      {
        ...current,
        workflowState:
          findings.length === 0 &&
          pendingDisputes.length === 0 &&
          current.reviewResult?.validationChange === "REJECTED"
            ? "REVIEW"
            : "RESOLVE_FINDINGS",
        findings,
        pendingDisputes,
        ...findingDecisions,
      },
      {
        pause: null,
        publicActivity: activity(
          "runner",
          "resolution",
          "finding-overridden",
          `Finding ${finding.id} explicitly overridden.`,
        ),
      },
    );
  }

  function assertResumeActionApplicable() {
    if (resumeAction?.type !== "extra-fix-rounds") {
      return;
    }
    const current = state();
    const additionalFixRounds =
      current.additionalFixRounds + resumeAction.amount;
    const totalFixRounds =
      (current.settings?.maxFixRounds ?? 0) + additionalFixRounds;
    if (
      current.workflowState !== "WAITING_FOR_USER" ||
      current.pendingEdit !== null ||
      currentRun.pause?.reason !== "fix_limit_reached" ||
      !["POLISH", "RESOLVE_FINDINGS"].includes(
        currentRun.pause?.resumeState,
      )
    ) {
      throw workflowError("Additional fix rounds are not applicable.");
    }
    if (
      !Number.isSafeInteger(additionalFixRounds) ||
      !Number.isSafeInteger(totalFixRounds)
    ) {
      throw workflowError("Additional fix-round budget is too large.");
    }
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
      { checkpoint: "bootstrap", recoveryContext: workContext() },
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
${state().reviewerSummary}

Independent validation evidence:
${JSON.stringify(
  {
    worker: state().workerValidation,
    reviewer: state().reviewerValidation,
  },
  null,
  2,
)}`,
      { checkpoint: "bootstrap", recoveryContext: workContext() },
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
    const validation = await establishedValidation(result);
    await transition(
      {
        ...state(),
        workflowState: "POLISH",
        resolvedSummary: result.summary,
        ...validation,
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
${JSON.stringify(state().bootstrapDisagreement, null, 2)}

Independent validation evidence:
${JSON.stringify(
  {
    worker: state().workerValidation,
    reviewer: state().reviewerValidation,
  },
  null,
  2,
)}`,
      {
        checkpoint: "arbitration",
        recoveryContext: workContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeBootstrapArbitration(output);
    if (result.direction === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    await writeContext("context/resolved.md", result.summary);
    const validation = await establishedValidation(result);
    await transition(
      {
        ...state(),
        workflowState: "POLISH",
        resolvedSummary: result.summary,
        ...validation,
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

  async function runPolishTurn() {
    const current = state();
    if (current.pendingCorrection && counters().fixRounds >= fixBudget()) {
      await pause("fix_limit_reached", {
        fixRounds: counters().fixRounds,
        resumeState: "POLISH",
      });
      return false;
    }
    const output = await runRole(
      "worker",
      POLISH_SCHEMA,
      (evidence) => `${POLISH_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}${
        current.stagnationDirection?.direction === "REWORK_IMPLEMENTATION"
          ? `\n\nStagnation Arbiter direction:\n${JSON.stringify(current.stagnationDirection, null, 2)}`
          : ""
      }`,
      {
        access: "workspace-write",
        checkpoint: "work",
        recoveryContext: workContext(),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizePolishResult(output);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    if (result.status === "BLOCKED") {
      await pause("environment_blocked", {
        explanation: result.reason,
        evidence: result.evidence,
        resumeState: "POLISH",
      });
      return false;
    }
    await transition(
      {
        ...state(),
        workflowState: "FINALIZE",
        polishSummary: result.summary,
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
        pendingCorrection: current.pendingCorrection,
        reviewReconsideration: [],
      },
      {
        nextCounters: current.pendingCorrection
          ? { ...counters(), fixRounds: counters().fixRounds + 1 }
          : counters(),
        publicActivity: activity(
          "worker",
          "polishing",
          "completed",
          "Worker polishing and self-review completed.",
        ),
      },
    );
    return true;
  }

  async function runFinalizationTurn() {
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

${PRODUCT_DECISION_INSTRUCTIONS}
${finalizationGuidanceInstructions(selectedGuidance)}

${evidence}

Established required-check inventory:
${JSON.stringify(state().requiredChecks, null, 2)}

Established validation infrastructure:
${JSON.stringify(
  {
    paths: state().validationInfrastructure,
    fingerprint: state().validationInfrastructureFingerprint,
  },
  null,
  2,
)}`,
        {
          access: "workspace-write",
          checkpoint: "work",
          recoveryContext: workContext({ includePolishSummary: true }),
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
          "ERR_INVALID_POLISHING_OUTPUT",
        );
      }
      if (
        result.status !== "PRODUCT_DECISION_REQUIRED" &&
        result.skillPath !== selectedGuidance.skillPath
      ) {
        throw workflowError(
          "Worker returned a finalization result for the wrong skill path.",
          "ERR_INVALID_POLISHING_OUTPUT",
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
      return productDecision(result.decision, "BOOTSTRAP");
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
      validationInfrastructureFingerprint: candidateValidationFingerprint,
      validationChanged,
      fingerprint,
    };
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
          reviewResult: null,
          reviewedFingerprint: null,
          findings: [],
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
        reviewResult: null,
        reviewedFingerprint: null,
        findings: [],
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
      await transition({
        ...current,
        workflowState: "FINALIZE",
        finalizationResult: null,
        finalizedFingerprint: null,
        reviewResult: null,
        reviewedFingerprint: null,
        findings: [],
        pendingCorrection: true,
      });
      return true;
    }
    const output = await runRole(
      "reviewer",
      REVIEW_SCHEMA,
      (evidence) => `${REVIEW_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Established validation tuple:
${JSON.stringify(
  {
    requiredChecks: current.requiredChecks,
    validationInfrastructure: current.validationInfrastructure,
    validationInfrastructureFingerprint:
      current.validationInfrastructureFingerprint,
  },
  null,
  2,
)}

Candidate validation tuple and finalization evidence:
${JSON.stringify(current.finalizationResult, null, 2)}

The Reviewer must return ACCEPTED only when any validation inventory or infrastructure change is authorized by the task and remains complete; return REJECTED with a finding for evasive, omitted, substituted, or weakened validation. Return UNCHANGED only when finalizationResult.validationChanged is false.

Previous findings:
${JSON.stringify(current.previousFindings, null, 2)}${
        current.reviewReconsideration.length === 0
          ? ""
          : `\n\nReconsider these current finding IDs as requested by the Arbiter:\n${current.reviewReconsideration.join(", ")}`
      }

Prior decisions:
${JSON.stringify(priorFindingDecisions(), null, 2)}`,
      {
        checkpoint: "review",
        recoveryContext: workContext({ includePolishSummary: true }),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeReviewResult(output, current.previousFindings);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    const reviewedFingerprint = await contentFingerprint();
    if (reviewedFingerprint !== fingerprint) {
      throw workflowError("Reviewed content fingerprint changed unexpectedly.");
    }
    if (
      (current.finalizationResult.validationChanged &&
        result.validationChange === "UNCHANGED") ||
      (!current.finalizationResult.validationChanged &&
        result.validationChange !== "UNCHANGED") ||
      (result.validationChange === "REJECTED" &&
        result.status !== "FINDINGS")
    ) {
      throw workflowError(
        "Reviewer returned an inconsistent validation-change decision.",
        "ERR_INVALID_POLISHING_OUTPUT",
      );
    }
    const reviewResult = {
      status: result.status,
      validationChange: result.validationChange,
      validationEvidence: result.validationEvidence,
      fingerprint: reviewedFingerprint,
    };
    if (result.status === "FINDINGS") {
      const correction = correctionUpdate({
        fingerprint,
        finalizationIssueIds: [],
        findingIds: result.findings.map(({ id }) => id),
      });
      const findingIds = new Set(result.findings.map(({ id }) => id));
      const pendingDisputes = current.pendingDisputes.filter(({ findingId }) =>
        findingIds.has(findingId),
      );
      const findingDecisions = compactFindingDecisions(current, {
        findings: result.findings,
        previousFindings: result.findings,
        pendingDisputes,
        reviewReconsideration: [],
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
          findings: result.findings,
          previousFindings: result.findings,
          pendingDisputes,
          ...findingDecisions,
          correctionHistory: correction.history,
          sameFindingRounds: correction.sameFindingRounds,
          pendingCorrection: false,
          blockedSinceStagnation: correction.blockedSinceStagnation,
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
    const findingDecisions = compactFindingDecisions(current, {
      findings: [],
      previousFindings: [],
      pendingDisputes: [],
      reviewReconsideration: [],
    });
    await transition(
      {
        ...state(),
        workflowState: "RESOLVE_FINDINGS",
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
        previousFindings: [],
        pendingDisputes: [],
        ...findingDecisions,
        pendingCorrection: false,
        reviewReconsideration: [],
      },
      {
        publicActivity: activity(
          "reviewer",
          "review",
          "approved",
          "Independent review approved the finalized content.",
        ),
      },
    );
    return true;
  }

  async function reconsiderDisputes() {
    const current = state();
    const output = await runRole(
      "reviewer",
      DISPUTE_RECONSIDERATION_SCHEMA,
      (evidence) => `${DISPUTE_RECONSIDERATION_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Current findings:
${JSON.stringify(current.findings, null, 2)}

Worker disputes:
${JSON.stringify(current.pendingDisputes, null, 2)}`,
      {
        checkpoint: "review",
        recoveryContext: workContext({ includePolishSummary: true }),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeReconsiderationResult(output, current.pendingDisputes);
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    const decisions = new Map(
      result.decisions.map((decision) => [decision.findingId, decision]),
    );
    const findings = current.findings.filter(
      ({ id }) => decisions.get(id)?.direction !== "WITHDRAW",
    );
    const pendingDisputes = current.pendingDisputes.filter((dispute) => {
      const decision = decisions.get(dispute.findingId);
      return (
        decision.direction === "UPHOLD" &&
        current.disputeCounts[dispute.findingId] >=
          current.settings.maxDisputesPerFinding
      );
    });
    const disputeHistory = [
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
    ];
    const findingDecisions = compactFindingDecisions(
      current,
      {
        findings,
        pendingDisputes,
        disputeHistory,
      },
      { overflowCode: "ERR_INVALID_POLISHING_OUTPUT" },
    );
    await transition(
      {
        ...current,
        findings,
        pendingDisputes,
        ...findingDecisions,
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
    const finding = current.findings.find(({ id }) => id === dispute.findingId);
    const reviewerResponse = [...current.disputeHistory]
      .reverse()
      .find(({ findingId }) => findingId === dispute.findingId);
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

Prior decisions:
${JSON.stringify(priorFindingDecisions([dispute.findingId]), null, 2)}`,
      {
        checkpoint: "arbitration",
        recoveryContext: workContext({ includePolishSummary: true }),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeFindingArbitration(output);
    if (result.direction === "REQUIREMENT_AMBIGUOUS") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    const findings =
      result.direction === "WORKER_CORRECT"
        ? current.findings.filter(({ id }) => id !== dispute.findingId)
        : current.findings;
    const pendingDisputes = current.pendingDisputes.filter(
      ({ findingId }) => findingId !== dispute.findingId,
    );
    const findingDecisions = compactFindingDecisions(current, {
      findings,
      pendingDisputes,
      findingArbitrations: [
        ...current.findingArbitrations,
        {
          findingId: dispute.findingId,
          direction: result.direction,
          rationale: result.rationale,
        },
      ],
    });
    await transition(
      {
        ...state(),
        workflowState:
          findings.length === 0 &&
          pendingDisputes.length === 0 &&
          current.reviewResult?.validationChange === "REJECTED"
            ? "REVIEW"
            : state().workflowState,
        findings,
        pendingDisputes,
        ...findingDecisions,
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

${evidence}

Current blockers and correction history:
${JSON.stringify(
  {
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
        recoveryContext: workContext({ includePolishSummary: true }),
      },
    );
    if (output === null) {
      return false;
    }
    const result = normalizeStagnationResult(output, current);
    if (result.direction === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
    }
    const direction = { direction: result.direction, rationale: result.rationale };
    if (result.direction === "REWORK_IMPLEMENTATION") {
      await transition(
        {
          ...current,
          workflowState: "POLISH",
          finalizationResult: null,
          finalizedFingerprint: null,
          reviewResult: null,
          reviewedFingerprint: null,
          previousFindings: current.findings,
          findings: [],
          pendingDisputes: [],
          pendingCorrection: true,
          blockedSinceStagnation: 0,
          stagnationArbitrationUsed: true,
          stagnationDirection: direction,
          reviewReconsideration: [],
        },
        {
          publicActivity: activity(
            "arbiter",
            "resolution",
            "rework-polishing",
            "Stagnation Arbiter requested full polishing rework.",
          ),
        },
      );
      return true;
    }
    if (result.direction === "RECONSIDER_FINDINGS") {
      await transition(
        {
          ...current,
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
        ...current,
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
    if (current.findings.length === 0 && current.finalizationResult?.status === "PASS") {
      if (await completeIfReady()) {
        return false;
      }
      return true;
    }
    if (current.finalizationResult?.status !== "FAIL") {
      const arbitration = current.pendingDisputes.find(({ findingId }) => {
        const latest = [...current.disputeHistory]
          .reverse()
          .find((entry) => entry.findingId === findingId);
        return (
          current.disputeCounts[findingId] >=
            current.settings.maxDisputesPerFinding &&
          latest?.attempt === current.disputeCounts[findingId] &&
          latest.direction === "UPHOLD"
        );
      });
      if (arbitration !== undefined) {
        return arbitrateFinding(arbitration);
      }
      if (current.pendingDisputes.length > 0) {
        return reconsiderDisputes();
      }
    }
    const stableFindingIds = current.findings
      .filter(
        ({ id }) =>
          (current.sameFindingRounds[id] ?? 0) >=
          current.settings.maxSameFindingRounds,
      )
      .map(({ id }) => id);
    if (stableFindingIds.length > 0) {
      await pause("no_progress", {
        findingIds: stableFindingIds,
        reason: "stable_findings",
        resumeState: "RESOLVE_FINDINGS",
      });
      return false;
    }
    if (
      current.blockedSinceStagnation >= current.settings.stagnationWindowRounds
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
    const blockerIds = new Set(blockers.map(({ id }) => id));
    const nonDisputableIds = new Set([
      ...current.findingArbitrations
        .filter(
          ({ findingId, direction }) =>
            blockerIds.has(findingId) && direction === "REVIEWER_CORRECT",
        )
        .map(({ findingId }) => findingId),
      ...Object.entries(current.disputeCounts)
        .filter(
          ([findingId, count]) =>
            blockerIds.has(findingId) &&
            count >= current.settings.maxDisputesPerFinding,
        )
        .map(([findingId]) => findingId),
    ]);
    if (
      budgetExhausted &&
      blockers.every(
        ({ id }) => id.startsWith("F") || nonDisputableIds.has(id),
      )
    ) {
      await pause("fix_limit_reached", {
        fixRounds: counters().fixRounds,
        resumeState: "RESOLVE_FINDINGS",
      });
      return false;
    }
    const beforeFingerprint = await contentFingerprint();
    const turn = await runRole(
      "worker",
      FINDING_RESOLUTION_SCHEMA,
      (evidence) => `${FINDING_RESOLUTION_INSTRUCTIONS}${
        budgetExhausted
          ? "\nThe fix budget is exhausted: do not modify the repository and return DISPUTE only where valid; a required FIX will pause for additional budget."
          : ""
      }

${PRODUCT_DECISION_INSTRUCTIONS}

${evidence}

Current blockers:
${JSON.stringify(blockers, null, 2)}${
        nonDisputableIds.size === 0
          ? ""
          : `\n\nThese finding IDs cannot be disputed and must be fixed:\n${[
              ...nonDisputableIds,
            ].join(", ")}`
      }${
        current.stagnationDirection?.direction === "CONTINUE_FIXES"
          ? `\n\nStagnation Arbiter direction:\n${JSON.stringify(current.stagnationDirection, null, 2)}`
          : ""
      }

Prior decisions:
${JSON.stringify(priorFindingDecisions(blockers.map(({ id }) => id)), null, 2)}`,
      {
        access: budgetExhausted ? "read-only" : "workspace-write",
        checkpoint: "work",
        recoveryContext: workContext({ includePolishSummary: true }),
        reportWorkspaceChange: true,
      },
    );
    if (turn === null) {
      return false;
    }
    const { output, workspaceChanged } = turn;
    const result = normalizeResolutionResult(
      output,
      blockers,
      nonDisputableIds,
    );
    if (result.status === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(result.decision, "BOOTSTRAP");
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
    const requiresFix = result.decisions.some(({ decision }) => decision === "FIX");
    const newDisputes = result.decisions
      .filter(({ decision }) => decision === "DISPUTE")
      .map((decision) => ({
        findingId: decision.id,
        reason: decision.reason,
        evidence: decision.evidence,
      }));
    const pendingDisputes =
      current.finalizationResult?.status === "FAIL"
        ? current.pendingDisputes
        : newDisputes;
    const disputeCounts = { ...current.disputeCounts };
    for (const { findingId } of newDisputes) {
      disputeCounts[findingId] = (disputeCounts[findingId] ?? 0) + 1;
    }
    const reservedDisputeHistory = newDisputes.map((dispute) => ({
      findingId: dispute.findingId,
      attempt: disputeCounts[dispute.findingId],
      direction: "UPHOLD",
      workerReason: dispute.reason,
      workerEvidence: dispute.evidence,
      reviewerReason: ".",
      reviewerEvidence: [],
    }));
    const findingDecisions = compactFindingDecisions(
      current,
      {
        pendingDisputes,
        disputeCounts,
      },
      {
        additionalDisputeHistory: reservedDisputeHistory,
        overflowCode: "ERR_INVALID_POLISHING_OUTPUT",
      },
    );
    if (budgetExhausted && requiresFix) {
      await transition(
        {
          ...state(),
          workflowState: "WAITING_FOR_USER",
          pendingDisputes,
          ...findingDecisions,
        },
        {
          pause: {
            reason: "fix_limit_reached",
            fixRounds: counters().fixRounds,
            resumeState: "RESOLVE_FINDINGS",
          },
          publicActivity: activity(
            "runner",
            "polishing",
            "paused",
            "Polishing paused: fix_limit_reached.",
          ),
        },
      );
      return false;
    }
    const changed = (await contentFingerprint()) !== beforeFingerprint;
    if (workspaceChanged) {
      if (newDisputes.length > 0) {
        await transition({
          ...state(),
          pendingDisputes,
          ...findingDecisions,
        });
      }
      return true;
    }
    if (requiresFix || changed) {
      await transition(
        {
          ...state(),
          workflowState: "FINALIZE",
          finalizationResult: null,
          finalizedFingerprint: null,
          reviewResult: null,
          reviewedFingerprint: null,
          previousFindings:
            current.findings.length === 0
              ? current.previousFindings
              : current.findings,
          findings: [],
          pendingDisputes,
          ...findingDecisions,
          pendingCorrection: true,
          reviewReconsideration: [],
        },
        {
          nextCounters: { ...counters(), fixRounds: counters().fixRounds + 1 },
          publicActivity: activity(
            "worker",
            "resolution",
            "fixed",
            "Worker completed a batched blocker fix round.",
          ),
        },
      );
      return true;
    }
    await transition(
      {
        ...state(),
        pendingDisputes,
        ...findingDecisions,
      },
      {
        publicActivity: activity(
          "worker",
          "resolution",
          "disputed",
          `Worker disputed ${newDisputes.length} findings with evidence.`,
        ),
      },
    );
    return true;
  }

  assertResumeActionApplicable();
  try {
    const resumeActionSuperseded = await prepareValidationMigrationResume();
    if (["DONE", "FAILED"].includes(state().workflowState)) {
      if (resumeAction !== null) {
        throw workflowError("Polishing resume action is not applicable.");
      }
      return currentRun;
    }
    if (resumeAction !== null && !resumeActionSuperseded) {
      await applyResumeAction();
    }
    if (state().workflowState === "WAITING_FOR_USER") {
      if (state().pendingEdit !== null) {
        if (!(await resumeEdit())) {
          return currentRun;
        }
      } else if (
        (!state().preflightComplete &&
          [
            "backend_unavailable",
            "local_artifacts_not_ignored",
            "unsafe_git_state",
          ].includes(currentRun.pause.reason)) ||
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
            "POLISH",
            "FINALIZE",
            "REVIEW",
            "RESOLVE_FINDINGS",
          ].includes(currentRun.pause.resumeState))
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
    if (
      state().preflightComplete &&
      ((await readCurrentInputs()) === null ||
        !(await verifyPersistedRepository()))
    ) {
      return currentRun;
    }

    while (true) {
      const current = state();
      if (current.validationMigrationPending) {
        if (!(await runValidationMigration())) {
          return currentRun;
        }
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

      if (current.workflowState === "POLISH") {
        if (!(await runPolishTurn())) {
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

      if (
        ["WAITING_FOR_USER", "DONE", "FAILED"].includes(
          current.workflowState,
        )
      ) {
        return currentRun;
      }
      throw workflowError(`Unsupported polishing state: ${current.workflowState}.`);
    }
  } catch (cause) {
    if (cause?.code === "ERR_READ_ONLY_REPOSITORY_CHANGED") {
      return pause("read_only_agent_mutated_repository", {
        code: cause.code,
      });
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
