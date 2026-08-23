import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  CommitPlanValidationError,
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";

import {
  CLARIFICATION_INSTRUCTIONS,
  DRAFT_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
  STAGNATION_INSTRUCTIONS,
} from "./prompts.js";
import {
  CLARIFICATION_SCHEMA,
  PLANNER_SCHEMA,
  REVIEW_SCHEMA,
  STAGNATION_SCHEMA,
} from "./schemas.js";
import {
  MAX_CLARIFICATION_ROUNDS,
  MAX_DIAGNOSTIC_ITEMS,
  PlanAuthoringWorkflowError,
  WORKFLOW_STATES,
  assertRun,
  assertRuntime,
  assertSettings,
  createPlanAuthoringState,
  isRecord,
  normalizeArbiterResult,
  normalizeInputSnapshot,
  normalizePipelineState,
  normalizePlannerResult,
  normalizeQuestions,
  normalizeReviewResult,
  normalizedCounters,
  sha256,
  workflowError,
} from "./workflow-contract.js";

export {
  MAX_CLARIFICATION_ROUNDS,
  PlanAuthoringWorkflowError,
  WORKFLOW_STATES,
  createPlanAuthoringState,
};

const INPUT_DRIFT_ERROR_CODES = new Set([
  "EACCES",
  "EISDIR",
  "ELOOP",
  "ENOENT",
  "ENOTDIR",
  "EPERM",
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

function evidencePrompt(inputs, clarification) {
  const context = inputs.context?.content ?? "(not provided)";
  const clarifications =
    clarification.content.length === 0
      ? "(empty)"
      : clarification.content;
  return `Task (${inputs.task.path}):
${inputs.task.content}

Context (${inputs.context?.path ?? join(dirname(inputs.task.path), "context.md")}):
${context}

Clarifications (${clarification.transcriptPath}):
${clarifications}`;
}

function contextKeyFor(role, checkpoint, context) {
  if (typeof checkpoint !== "string" || checkpoint.length === 0) {
    throw workflowError("Plan-authoring session checkpoint is invalid.");
  }
  return sha256(`${role}\0${checkpoint}\0${context}`);
}

function findingPrompt(pipelineState) {
  return JSON.stringify(
    {
      findings: pipelineState.findings,
      validationIssues: pipelineState.validationIssues,
      arbiterDirection: pipelineState.arbiterDirection,
    },
    null,
    2,
  );
}

function reviewDirectionPrompt(pipelineState) {
  if (pipelineState.arbiterDirection === null) {
    return "";
  }
  return `

Arbiter-directed review context:
${JSON.stringify(
  {
    arbiterDirection: pipelineState.arbiterDirection,
    findings: pipelineState.findings,
  },
  null,
  2,
)}`;
}

export async function runPlanAuthoring({ run, runtime, settings }) {
  assertRun(run);
  assertRuntime(runtime);
  if (!run.pipelineState.preflightComplete) {
    assertSettings(settings);
  }

  let currentRun = run;
  const clarificationPath = join(run.taskPath, "clarifications.md");
  const planPath = join(run.taskPath, "plan.md");

  function pipelineState() {
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
      { ...pipelineState(), workflowState: "WAITING_FOR_USER" },
      {
        pause: { reason, ...details },
        publicActivity: activity(
          "runner",
          "plan-authoring",
          "paused",
          `Plan authoring paused: ${reason}.`,
        ),
      },
    );
    return currentRun;
  }

  async function fail(cause) {
    const code =
      typeof cause?.code === "string" && /^[A-Z0-9_]{1,64}$/u.test(cause.code)
        ? cause.code
        : "ERR_PLAN_AUTHORING_FAILED";
    try {
      await transition(
        { ...pipelineState(), workflowState: "FAILED" },
        {
          pause: { reason: "internal_failure", code },
          publicActivity: activity(
            "runner",
            "plan-authoring",
            "failed",
            `Plan authoring failed: ${code}.`,
          ),
        },
      );
    } catch {}
    throw cause;
  }

  async function invalidateDependentWork(
    reason,
    {
      details = {},
      phase = "inputs",
      message = "Plan-authoring input changed outside an authorized window.",
    } = {},
  ) {
    const state = pipelineState();
    await transition(
      {
        ...state,
        workflowState: "WAITING_FOR_USER",
        clarificationFrozen: false,
        pendingEdit: null,
        draft: null,
        draftFingerprint: null,
        findings: [],
        validationIssues: [],
        blockerKind: null,
        reviewApproved: false,
        lastCountedRevision: counters().revisionRounds,
        blockedSinceArbitration: 0,
        arbiterDirection: null,
        correctionHistory: [],
        canonicalPlan: null,
      },
      {
        pause: { reason, ...details },
        publicActivity: activity(
          "runner",
          phase,
          "changed",
          message,
        ),
      },
    );
    return currentRun;
  }

  async function readCurrentInputs() {
    let inputSnapshot;
    try {
      inputSnapshot = await runtime.readInputs({
        taskPath: currentRun.taskPath,
      });
    } catch (cause) {
      if (!INPUT_DRIFT_ERROR_CODES.has(cause?.code)) {
        throw cause;
      }
      await invalidateDependentWork("input_changed");
      return null;
    }
    const inputs = normalizeInputSnapshot(inputSnapshot, currentRun.taskPath);
    const clarification = await runtime.clarifications.inspectTranscript({
      artifactRoot: currentRun.taskPath,
      transcriptPath: clarificationPath,
    });
    const nextHashes = {
      ...currentRun.hashes,
      task: inputs.task.hash,
      context: inputs.context?.hash ?? null,
      clarifications: clarification.hash,
    };
    const changed =
      currentRun.hashes.task !== nextHashes.task ||
      currentRun.hashes.context !== nextHashes.context ||
      currentRun.hashes.clarifications !== nextHashes.clarifications;
    if (changed) {
      const clarificationChanged =
        currentRun.hashes.clarifications !== nextHashes.clarifications;
      await invalidateDependentWork(
        clarificationChanged ? "clarifications_changed" : "input_changed",
      );
      return null;
    }
    return Object.freeze({ inputs, clarification });
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
        "ERR_INVALID_PLAN_AUTHORING_OUTPUT",
      );
    }
    if (sessionId === currentRun.sessionLineage.source) {
      throw workflowError(
        `${role} returned the source session ID instead of a child session.`,
        "ERR_INVALID_PLAN_AUTHORING_OUTPUT",
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
        "ERR_INVALID_PLAN_AUTHORING_OUTPUT",
      );
    }
    currentRun = await runtime.recordChildSession(
      { role, sessionId, contextKey },
      {
        activity: activity(
          role,
          "session",
          "started",
          `${role} session recorded.`,
        ),
      },
    );
    assertRun(currentRun);
  }

  async function runRole(role, schema, buildPrompt, { checkpoint }) {
    const evidence = await readCurrentInputs();
    if (evidence === null) {
      return null;
    }
    await runtime.git.assertUnchanged(pipelineState().repositoryBaseline);
    const snapshot = await runtime.git.snapshot({
      allowedPaths: [],
      projectPath: currentRun.projectPath,
    });
    const evidenceContext = evidencePrompt(
      evidence.inputs,
      evidence.clarification,
    );
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
    const recoveryPrompt = buildPrompt(evidenceContext);
    const request = {
      access: "read-only",
      cwd: currentRun.projectPath,
      prompt:
        session?.mode === "continue" ? buildPrompt("") : recoveryPrompt,
      recoveryPrompt,
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
    await runtime.git.assertUnchanged(snapshot);
    await runtime.git.assertUnchanged(pipelineState().repositoryBaseline);
    if (agentError !== undefined) {
      throw agentError;
    }
    if (!isRecord(response)) {
      throw workflowError(
        `${role} returned no response.`,
        "ERR_INVALID_PLAN_AUTHORING_OUTPUT",
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
        "ERR_INVALID_PLAN_AUTHORING_OUTPUT",
      );
    }
    return response.structured;
  }

  async function persistEdit(
    authorization,
    reason,
    {
      nextPipelineState = pipelineState(),
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

  async function consumeEdit(result) {
    const state = pipelineState();
    if (!result.changed && result.action !== "proactive-clarification") {
      await prepareEdit(
        result.action,
        result.suspendedState,
        currentRun.pause.reason,
        {
          expectedHash: result.hash,
          inputRequest: currentRun.pause.inputRequest,
          nextPipelineState: { ...state, clarificationFrozen: false },
          nextHashes: {
            ...currentRun.hashes,
            clarifications: result.hash,
          },
        },
      );
      return;
    }
    await transition(
      {
        ...state,
        workflowState: result.suspendedState,
        pendingEdit: null,
        clarificationFrozen: false,
        proactiveClarificationComplete:
          result.action === "proactive-clarification"
            ? true
            : state.proactiveClarificationComplete,
      },
      {
        nextHashes: {
          ...currentRun.hashes,
          clarifications: result.hash,
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

  async function prepareEdit(action, suspendedState, reason, options) {
    return runtime.clarifications.prepareEdit({
      artifactRoot: currentRun.taskPath,
      transcriptPath: clarificationPath,
      expectedHash:
        options?.expectedHash ?? currentRun.hashes.clarifications,
      suspendedState,
      action,
      persistPendingEdit: (authorization) =>
        persistEdit(authorization, reason, options),
    });
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
    return (
      editorResult.result.changed || action === "proactive-clarification"
    );
  }

  async function resumeEdit() {
    const authorization = pipelineState().pendingEdit;
    if (authorization === null) {
      return false;
    }
    const result = await runtime.clarifications.acceptEdit(authorization, {
      consumePendingEdit: consumeEdit,
    });
    return result.changed || result.action === "proactive-clarification";
  }

  async function productDecision(decision, statePatch = {}) {
    const count = counters().productDecisions + 1;
    const snapshot = await runtime.clarifications.appendProductDecision({
      artifactRoot: currentRun.taskPath,
      transcriptPath: clarificationPath,
      expectedHash: currentRun.hashes.clarifications,
      number: count,
      ...decision,
    });
    const state = pipelineState();
    return requestEdit(
      "product-decision",
      "ANALYZE",
      "product_decision_required",
      {
        expectedHash: snapshot.hash,
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
          ...state,
          ...statePatch,
          clarificationFrozen: false,
          draft: null,
          draftFingerprint: null,
          findings: [],
          validationIssues: [],
          blockerKind: null,
          reviewApproved: false,
          lastCountedRevision: counters().revisionRounds,
          blockedSinceArbitration: 0,
          arbiterDirection: null,
          correctionHistory: [],
          canonicalPlan: null,
        },
        nextCounters: { ...counters(), productDecisions: count },
        nextHashes: {
          ...currentRun.hashes,
          clarifications: snapshot.hash,
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

  async function arbitrateStagnation() {
    const output = await runRole(
      "arbiter",
      STAGNATION_SCHEMA,
      (evidence) => `${STAGNATION_INSTRUCTIONS}

${PRODUCT_DECISION_INSTRUCTIONS}

Do not modify the repository or artifact files. This result cannot approve the plan.

${evidence}

Current plan, blockers, and correction history:
${JSON.stringify(
  {
    currentPlan: pipelineState().draft,
    blockerKind: pipelineState().blockerKind,
    findings: pipelineState().findings,
    validationIssues: pipelineState().validationIssues,
    correctionHistory: pipelineState().correctionHistory,
  },
  null,
  2,
)}`,
      { checkpoint: "arbitration" },
    );
    if (output === null) {
      return false;
    }
    const decision = normalizeArbiterResult(output, pipelineState());
    if (decision.direction === "PRODUCT_DECISION_REQUIRED") {
      return productDecision(decision.decision, {
        arbitrationUsed: true,
      });
    }
    if (decision.direction === "RECONSIDER_FINDINGS") {
      await transition(
        {
          ...pipelineState(),
          workflowState: "REVIEW",
          arbitrationUsed: true,
          blockedSinceArbitration: 0,
          arbiterDirection: {
            direction: decision.direction,
            rationale: decision.rationale,
          },
        },
        {
          publicActivity: activity(
            "arbiter",
            "revision",
            "reconsider-findings",
            "Arbiter requested Reviewer reconsideration.",
          ),
        },
      );
      return true;
    }
    await transition(
      {
        ...pipelineState(),
        workflowState: "REVISE",
        arbitrationUsed: true,
        blockedSinceArbitration: 0,
        arbiterDirection: {
          direction: decision.direction,
          rationale: decision.rationale,
        },
      },
      {
        publicActivity: activity(
          "arbiter",
          "revision",
          "direction",
          `Arbiter selected ${decision.direction}.`,
        ),
      },
    );
    return true;
  }

  async function registerBlock(blockerKind, values) {
    const state = pipelineState();
    const currentCounters = counters();
    const isCorrection =
      currentCounters.revisionRounds > state.lastCountedRevision;
    const nextCorrectionRounds =
      currentCounters.correctionRounds + (isCorrection ? 1 : 0);
    const nextBlocked =
      state.blockedSinceArbitration + (isCorrection ? 1 : 0);
    const history = isCorrection
      ? [
          ...state.correctionHistory,
          {
            round: nextCorrectionRounds,
            draftFingerprint: state.draftFingerprint,
            findingIds:
              blockerKind === "findings"
                ? values.findings.map(({ id }) => id)
                : [],
            validationIssues:
              blockerKind === "validation" ? values.validationIssues : [],
          },
        ].slice(-MAX_DIAGNOSTIC_ITEMS)
      : state.correctionHistory;
    await transition(
      {
        ...state,
        workflowState: "REVISE",
        findings: values.findings ?? [],
        validationIssues: values.validationIssues ?? [],
        blockerKind,
        reviewApproved: false,
        lastCountedRevision: isCorrection
          ? currentCounters.revisionRounds
          : state.lastCountedRevision,
        blockedSinceArbitration: nextBlocked,
        arbiterDirection: null,
        correctionHistory: history,
        canonicalPlan: null,
      },
      {
        nextCounters: {
          ...currentCounters,
          correctionRounds: nextCorrectionRounds,
        },
        publicActivity: activity(
          blockerKind === "validation" ? "runner" : "reviewer",
          "revision",
          "blocked",
          `Plan blocked by ${blockerKind}.`,
        ),
      },
    );
  }

  async function initializeInputs() {
    const inputs = normalizeInputSnapshot(
      await runtime.readInputs({ taskPath: currentRun.taskPath }),
      currentRun.taskPath,
    );
    const repositoryPathFrom = (preflight) => {
      const repositoryPath = preflight?.snapshot?.projectPath;
      if (
        !isRecord(preflight?.snapshot) ||
        typeof repositoryPath !== "string" ||
        !isAbsolute(repositoryPath) ||
        resolve(repositoryPath) !== repositoryPath ||
        !isWithin(repositoryPath, currentRun.projectPath)
      ) {
        throw workflowError("Git preflight returned an invalid repository root.");
      }
      return repositoryPath;
    };
    const preflightAt = (projectPath) =>
      runtime.git.preflight({
        allowedPaths: [clarificationPath, planPath].filter((path) =>
          isWithin(projectPath, path),
        ),
        projectPath,
        requireClean: false,
        requireIdentity: false,
        requiredIgnoredPaths: isWithin(projectPath, clarificationPath)
          ? [clarificationPath]
          : [],
      });
    let preflight = await preflightAt(currentRun.projectPath);
    const repositoryPath = repositoryPathFrom(preflight);
    if (repositoryPath !== currentRun.projectPath) {
      preflight = await preflightAt(repositoryPath);
      if (repositoryPathFrom(preflight) !== repositoryPath) {
        throw workflowError(
          "Git preflight returned an unstable repository root.",
        );
      }
    }
    const clarification = await runtime.clarifications.ensureTranscript({
      artifactRoot: currentRun.taskPath,
      transcriptPath: clarificationPath,
    });
    await transition(
      {
        ...pipelineState(),
        preflightComplete: true,
        settings,
        repositoryBaseline: preflight.snapshot,
      },
      {
        nextHashes: {
          ...currentRun.hashes,
          task: inputs.task.hash,
          context: inputs.context?.hash ?? null,
          clarifications: clarification.hash,
        },
        publicActivity: activity(
          "runner",
          "preflight",
          "passed",
          "Plan-authoring preflight passed and inputs were recorded.",
        ),
      },
    );
  }

  try {
    if (pipelineState().workflowState === "WAITING_FOR_USER") {
      if (pipelineState().pendingEdit !== null) {
        if (!(await resumeEdit())) {
          return currentRun;
        }
      } else if (currentRun.pause.reason === "backend_unavailable") {
        await transition(
          {
            ...pipelineState(),
            workflowState: currentRun.pause.resumeState,
          },
          { pause: null },
        );
      } else {
        return currentRun;
      }
    }
    if (["DONE", "FAILED"].includes(pipelineState().workflowState)) {
      return currentRun;
    }

    while (true) {
      const state = pipelineState();

      if (state.workflowState === "CLARIFY") {
        if (!state.preflightComplete) {
          await initializeInputs();
        }
        if (
          pipelineState().proactiveClarification &&
          !pipelineState().proactiveClarificationComplete
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
          "planner",
          CLARIFICATION_SCHEMA,
          (evidence) => `${CLARIFICATION_INSTRUCTIONS}

${evidence}`,
          { checkpoint: "clarification" },
        );
        if (output === null) {
          return currentRun;
        }
        const clarification = normalizeQuestions(output);
        if (clarification.status === "READY") {
          const frozen = await runtime.clarifications.freezeTranscript({
            artifactRoot: currentRun.taskPath,
            transcriptPath: clarificationPath,
            expectedHash: currentRun.hashes.clarifications,
          });
          await transition(
            {
              ...pipelineState(),
              workflowState: "ANALYZE",
              clarificationFrozen: true,
            },
            {
              nextHashes: {
                ...currentRun.hashes,
                clarifications: frozen.hash,
              },
              publicActivity: activity(
                "planner",
                "clarification",
                "ready",
                "Clarification completed.",
              ),
            },
          );
          continue;
        }
        if (counters().clarificationRounds >= MAX_CLARIFICATION_ROUNDS) {
          return pause("clarification_limit_reached", {
            questions: clarification.questions,
          });
        }
        const round = counters().clarificationRounds + 1;
        const transcript = await runtime.clarifications.appendQuestionRound({
          artifactRoot: currentRun.taskPath,
          transcriptPath: clarificationPath,
          expectedHash: currentRun.hashes.clarifications,
          round,
          questions: clarification.questions,
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
                questions: clarification.questions.map((question, index) => ({
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
                clarifications: transcript.hash,
              },
            },
          ))
        ) {
          return currentRun;
        }
        continue;
      }

      if (state.workflowState === "ANALYZE") {
        const evidence = await readCurrentInputs();
        if (evidence === null) {
          return currentRun;
        }
        if (!state.clarificationFrozen) {
          const frozen = await runtime.clarifications.freezeTranscript({
            artifactRoot: currentRun.taskPath,
            transcriptPath: clarificationPath,
            expectedHash: currentRun.hashes.clarifications,
          });
          await transition(
            {
              ...pipelineState(),
              clarificationFrozen: true,
              workflowState: "DRAFT",
            },
            {
              nextHashes: {
                ...currentRun.hashes,
                clarifications: frozen.hash,
              },
            },
          );
        } else {
          await transition(
            { ...state, workflowState: "DRAFT" },
            {
              publicActivity: activity(
                "planner",
                "analysis",
                "completed",
                "Planner analysis context prepared.",
              ),
            },
          );
        }
        continue;
      }

      if (state.workflowState === "DRAFT") {
        const output = await runRole(
          "planner",
          PLANNER_SCHEMA,
          (evidence) => `${DRAFT_INSTRUCTIONS}

${evidence}`,
          { checkpoint: "planning" },
        );
        if (output === null) {
          return currentRun;
        }
        const result = normalizePlannerResult(output);
        if (result.status === "PRODUCT_DECISION_REQUIRED") {
          if (!(await productDecision(result.decision))) {
            return currentRun;
          }
          continue;
        }
        await transition(
          {
            ...pipelineState(),
            workflowState: "REVIEW",
            draft: result.plan,
            draftFingerprint: sha256(result.plan),
            findings: [],
            validationIssues: [],
            blockerKind: null,
            reviewApproved: false,
            arbiterDirection: null,
            canonicalPlan: null,
          },
          {
            publicActivity: activity(
              "planner",
              "draft",
              "created",
              "Initial commit plan drafted.",
            ),
          },
        );
        continue;
      }

      if (state.workflowState === "REVIEW") {
        const output = await runRole(
          "reviewer",
          REVIEW_SCHEMA,
          (evidence) => `${REVIEW_INSTRUCTIONS}

${evidence}

Plan under review:
${pipelineState().draft}${reviewDirectionPrompt(pipelineState())}`,
          { checkpoint: "planning" },
        );
        if (output === null) {
          return currentRun;
        }
        const result = normalizeReviewResult(output);
        if (result.status === "PRODUCT_DECISION_REQUIRED") {
          if (!(await productDecision(result.decision))) {
            return currentRun;
          }
          continue;
        }
        if (result.status === "FINDINGS") {
          await registerBlock("findings", { findings: result.findings });
          continue;
        }
        await transition(
          {
            ...pipelineState(),
            workflowState: "VALIDATE",
            findings: [],
            validationIssues: [],
            blockerKind: null,
            reviewApproved: true,
            arbiterDirection: null,
          },
          {
            publicActivity: activity(
              "reviewer",
              "review",
              "approved",
              "Plan review approved.",
            ),
          },
        );
        continue;
      }

      if (state.workflowState === "REVISE") {
        if (counters().revisionRounds >= state.settings.maxRevisionRounds) {
          return pause("plan_revision_limit_reached", {
            revisionRounds: counters().revisionRounds,
          });
        }
        if (
          state.blockedSinceArbitration >=
          state.settings.stagnationWindowRounds
        ) {
          if (state.arbitrationUsed) {
            return pause("plan_revision_not_converging", {
              correctionRounds: counters().correctionRounds,
            });
          }
          if (!(await arbitrateStagnation())) {
            return currentRun;
          }
          continue;
        }
        const output = await runRole(
          "planner",
          PLANNER_SCHEMA,
          (evidence) => `${FINDING_RESOLUTION_INSTRUCTIONS}

Treat deterministic validation issues as blocking correction input; do not waive or rewrite the validation rules.

${evidence}

Current plan:
${pipelineState().draft}

Blocking correction input:
${findingPrompt(pipelineState())}`,
          { checkpoint: "planning" },
        );
        if (output === null) {
          return currentRun;
        }
        const result = normalizePlannerResult(output);
        if (result.status === "PRODUCT_DECISION_REQUIRED") {
          if (!(await productDecision(result.decision))) {
            return currentRun;
          }
          continue;
        }
        const revisionRounds = counters().revisionRounds + 1;
        await transition(
          {
            ...pipelineState(),
            workflowState: "REVIEW",
            draft: result.plan,
            draftFingerprint: sha256(result.plan),
            findings: [],
            validationIssues: [],
            blockerKind: null,
            reviewApproved: false,
            arbiterDirection: null,
            canonicalPlan: null,
          },
          {
            nextCounters: { ...counters(), revisionRounds },
            publicActivity: activity(
              "planner",
              "revision",
              "completed",
              `Plan revision ${revisionRounds} completed.`,
            ),
          },
        );
        continue;
      }

      if (state.workflowState === "VALIDATE") {
        let canonicalPlan;
        try {
          canonicalPlan = serializeCommitPlan(parseCommitPlan(state.draft));
        } catch (cause) {
          if (!(cause instanceof CommitPlanValidationError)) {
            throw cause;
          }
          await registerBlock("validation", {
            validationIssues: cause.issues.slice(0, MAX_DIAGNOSTIC_ITEMS),
          });
          continue;
        }
        await transition(
          {
            ...state,
            workflowState: "WRITE_PLAN",
            canonicalPlan,
          },
          {
            publicActivity: activity(
              "runner",
              "validation",
              "passed",
              "Commit plan validation passed.",
            ),
          },
        );
        continue;
      }

      if (state.workflowState === "WRITE_PLAN") {
        if ((await readCurrentInputs()) === null) {
          return currentRun;
        }
        await runtime.git.assertUnchanged(state.repositoryBaseline);
        const canonicalPlan = serializeCommitPlan(parseCommitPlan(state.draft));
        if (canonicalPlan !== state.canonicalPlan) {
          throw workflowError("Canonical plan does not match the reviewed draft.");
        }
        const writtenPath = await runtime.writePlan({
          artifactRoot: currentRun.taskPath,
          path: planPath,
          content: canonicalPlan,
        });
        if (writtenPath !== planPath) {
          throw workflowError("Plan writer returned an unexpected path.");
        }
        if ((await readCurrentInputs()) === null) {
          return currentRun;
        }
        await runtime.git.assertUnchanged(state.repositoryBaseline);
        await transition(
          {
            ...state,
            workflowState: "DONE",
            planPath: writtenPath,
          },
          {
            pause: null,
            publicActivity: activity(
              "runner",
              "plan",
              "written",
              "Validated plan written.",
            ),
          },
        );
        return currentRun;
      }

      if (["WAITING_FOR_USER", "DONE", "FAILED"].includes(state.workflowState)) {
        return currentRun;
      }

      throw workflowError(`Unsupported workflow state: ${state.workflowState}.`);
    }
  } catch (cause) {
    const preflightComplete = pipelineState().preflightComplete;
    const causePath = cause?.path ?? cause?.cause?.path;
    const filesystemDrift =
      INPUT_DRIFT_ERROR_CODES.has(cause?.code) ||
      INPUT_DRIFT_ERROR_CODES.has(cause?.cause?.code);
    const clarificationPathDrift =
      causePath === clarificationPath && filesystemDrift;
    const inputPathDrift =
      filesystemDrift &&
      [
        join(currentRun.taskPath, "task.md"),
        join(currentRun.taskPath, "context.md"),
      ].includes(causePath);
    if (cause?.code === "ERR_READ_ONLY_REPOSITORY_CHANGED") {
      return invalidateDependentWork("read_only_mutation", {
        details: { code: cause.code },
        phase: "repository",
        message: "Repository changed during a read-only plan-authoring turn.",
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
        clarificationPathDrift)
    ) {
      return invalidateDependentWork("clarifications_changed");
    }
    if (preflightComplete && inputPathDrift) {
      return invalidateDependentWork("input_changed");
    }
    if (cause?.recoverable === true) {
      const code =
        typeof cause.code === "string" && /^[A-Z0-9_]{1,64}$/u.test(cause.code)
          ? cause.code
          : "ERR_BACKEND_UNAVAILABLE";
      return pause("backend_unavailable", {
        code,
        resumeState: pipelineState().workflowState,
      });
    }
    return fail(cause);
  }
}
