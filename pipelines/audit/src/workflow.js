import { join } from "node:path";

import { recheckRole } from "./cycles.js";
import {
  acceptDiscovery,
  assertAudit,
  assertAuditResultSize,
  AuditWorkflowError,
  emptyReport,
  fingerprint,
  finishPass,
  MAX_CLARIFICATION_ROUNDS,
  normalizeClarification,
  sessionContextKey,
} from "./discovery-contract.js";
import {
  AUDIT_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  COMBINED_INSTRUCTIONS,
  DISCOVERY_INSTRUCTIONS,
  RECHECK_INSTRUCTIONS,
} from "./prompts.js";
import { publicationContent, reportPaths } from "./publication-contract.js";
import {
  CLARIFICATION_SCHEMA,
  DISCOVERY_SCHEMA,
  RECHECK_SCHEMA,
} from "./schemas.js";
import {
  acceptRecheck,
  assertAuditRun,
  finishRecheck,
  reserveRecheck,
} from "./verification-contract.js";

const STRUCTURED_OUTPUT_FAILURE_CLASS = "structured-output";

function isOwnershipFailure(cause) {
  return (
    cause?.executionResourceRetained === true ||
    [
      "ERR_EXECUTION_PROCESS_ACTIVE",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      "ERR_EXECUTION_RESOURCE_UNVERIFIABLE",
    ].includes(cause?.code)
  );
}

/** Discovery and finding verification; public completion is owned by runAudit. */
export async function runAuditDiscovery({
  run,
  runtime,
  operatorStop = false,
}) {
  assertAuditRun(run);
  let current = run;
  const state = () => current.pipelineState;
  const transcript = {
    artifactRoot: run.taskPath,
    transcriptPath: join(run.taskPath, "clarifications.md"),
  };
  const save = async (pipelineState, patch = {}) => {
    current = await runtime.transition({ pipelineState, ...patch });
    assertAuditRun(current);
  };
  const pause = async (
    reason,
    resumeState = state().workflowState,
    details = {},
  ) => {
    await save(
      { ...state(), workflowState: "WAITING_FOR_USER" },
      { pause: { reason, resumeState, ...details } },
    );
    return current;
  };
  async function inspectInputs() {
    const inputs = await runtime.readInputs({ taskPath: run.taskPath });
    const clarification =
      await runtime.clarifications.inspectTranscript(transcript);
    const hashes = {
      task: inputs.task.hash,
      context: inputs.context?.hash ?? null,
      clarifications: clarification.hash,
    };
    if (
      current.hashes.task !== undefined &&
      Object.keys(hashes).some((key) => current.hashes[key] !== hashes[key])
    ) {
      await pause("input_changed");
      return null;
    }
    return { inputs, clarification, hashes };
  }
  async function prepareEdit(
    action,
    reason,
    {
      expectedHash = current.hashes.clarifications,
      round = state().clarificationRounds,
      inputRequest = action === "proactive-clarification"
        ? {
            kind: "clarification",
            questions: [],
            rationale: "Optional task clarification before agent work begins.",
          }
        : undefined,
    } = {},
  ) {
    return runtime.clarifications.prepareEdit({
      ...transcript,
      expectedHash,
      action,
      suspendedState: "CLARIFY",
      persistPendingEdit: async (authorization) =>
        save(
          {
            ...state(),
            workflowState: "WAITING_FOR_USER",
            clarificationRounds: round,
            pendingEdit: authorization,
          },
          {
            hashes: { ...current.hashes, clarifications: expectedHash },
            pause: {
              reason,
              resumeState: "CLARIFY",
              authorizationId: authorization.id,
              ...(inputRequest === undefined
                ? {}
                : {
                    inputRequest: {
                      ...inputRequest,
                      id: authorization.id,
                      artifactPath: authorization.transcriptPath,
                    },
                  }),
            },
          },
        ),
    });
  }
  async function consumeEdit(result) {
    assertAudit(
      result.authorizationId === state().pendingEdit.id,
      "Audit edit authorization changed.",
    );
    if (!result.changed && result.action !== "proactive-clarification") {
      // Unanswered material questions retain their round and receive a new one-shot window.
      await prepareEdit(result.action, current.pause.reason, {
        expectedHash: result.hash,
        inputRequest: current.pause.inputRequest,
      });
      return;
    }
    await save(
      {
        ...state(),
        workflowState: "CLARIFY",
        pendingEdit: null,
        proactiveClarificationComplete:
          result.action === "proactive-clarification"
            ? true
            : state().proactiveClarificationComplete,
      },
      {
        hashes: { ...current.hashes, clarifications: result.hash },
        pause: null,
      },
    );
  }
  async function requestEdit(action, reason, options) {
    const authorization = await prepareEdit(action, reason, options);
    const result = await runtime.clarifications.openEditor(authorization, {
      consumePendingEdit: consumeEdit,
    });
    return result.status !== "WAITING_FOR_USER" && state().pendingEdit === null;
  }
  const retry = Symbol("retry");
  async function turn(phase, evidence) {
    for (;;) {
      const result = await attempt(phase, evidence);
      if (result !== retry) return result;
    }
  }
  async function attempt(phase, evidence) {
    const recheck = phase === "recheck";
    const role = recheck ? recheckRole(state()) : "auditor";
    const resumeState = recheck
      ? "VERIFY_FINDINGS"
      : phase === "clarify"
        ? "CLARIFY"
        : "DISCOVER";
    const invalid = recheck ? "invalid_recheck" : "invalid_discovery";
    const finishReserved = async (outcome) => {
      if (recheck) await save(finishRecheck(state(), outcome));
      else if (phase === "discovery") await save(finishPass(state(), outcome));
    };
    try {
      await runtime.workspace.assertUnchanged(state().repositoryBaseline);
    } catch {
      await finishReserved("interrupted");
      return { failure: "workspace_changed" };
    }
    const lazy = state().settings.mode === "lazy";
    const combined = state().settings.mode === "combined";
    const key = sessionContextKey(
      current,
      phase,
      recheck ? state().recheckHistory.length : state().history.length,
    );
    const checkpoint = `audit:${phase}:read-only:${recheck ? state().recheckHistory.length : phase === "discovery" ? state().history.length : state().clarificationRounds}`;
    const repository = state().repositoryBaseline;
    try {
      if (
        current.availabilityRetry != null &&
        runtime.availability !== undefined
      ) {
        current = await runtime.availability.before({
          role,
          checkpoint,
          repository,
        });
      }
      if (runtime.inactivity !== undefined) {
        current = await runtime.inactivity.before({
          role,
          checkpoint,
          repository,
        });
      }
    } catch (cause) {
      if (cause?.recoverable !== true) throw cause;
      return {
        failure: "backend_unavailable",
        details: { code: safeCode(cause) },
      };
    }
    const previous = [...current.sessionLineage.children]
      .reverse()
      .find((child) => child.role === role && child.contextKey === key);
    const source = current.sessionLineage.source;
    const reconstructing = current.inactivityRecovery != null;
    const session =
      !reconstructing && previous
        ? { mode: "continue", id: previous.sessionId }
        : !reconstructing &&
            state().sourceForkRecovery !== key &&
            source !== null &&
            (!lazy || !state().sourceForkConsumed) &&
            (!combined || !state().sourceForkContexts.includes(key))
          ? { mode: "fork", id: source }
          : undefined;
    const activeTurn = { role, phase };
    current = await runtime.startAgentTurn(activeTurn, {
      pipelineState: {
        ...state(),
        sourceForkConsumed:
          state().sourceForkConsumed || (lazy && session?.mode === "fork"),
        sourceForkRecovery:
          session?.mode === "fork" ? key : state().sourceForkRecovery,
        sourceForkContexts:
          combined && session?.mode === "fork"
            ? [...state().sourceForkContexts, key]
            : state().sourceForkContexts,
      },
    });
    const prompt = `${AUDIT_INSTRUCTIONS}\n\n${phase === "clarify" ? CLARIFICATION_INSTRUCTIONS : recheck ? RECHECK_INSTRUCTIONS : DISCOVERY_INSTRUCTIONS}${combined ? `\n\n${COMBINED_INSTRUCTIONS}` : ""}\n\n${JSON.stringify(evidence)}`;
    const configuration = current.roles[role];
    let response;
    let agentError;
    const acknowledgedSessions = new Set();
    try {
      response = await runtime.adapters[role].run({
        onSessionCreated: async (sessionId) => {
          if (
            sessionId === source ||
            sessionId === previous?.sessionId ||
            current.sessionLineage.children.some(
              (child) => child.sessionId === sessionId,
            )
          )
            throw new Error("Audit created child session identity is invalid.");
          current = await runtime.recordChildSession({
            role,
            sessionId,
            contextKey: key,
          });
          acknowledgedSessions.add(sessionId);
        },
        access: "read-only",
        cwd: current.projectPath,
        prompt,
        recoveryPrompt: prompt,
        schema:
          phase === "clarify"
            ? CLARIFICATION_SCHEMA
            : recheck
              ? RECHECK_SCHEMA
              : DISCOVERY_SCHEMA,
        ...Object.fromEntries(
          ["profile", "model", "contextSize", "effort"].flatMap((key) =>
            typeof configuration[key] === "string" &&
            configuration[key] !== "current"
              ? [[key, configuration[key]]]
              : [],
          ),
        ),
        ...(session ? { session } : {}),
      });
    } catch (cause) {
      if (isOwnershipFailure(cause)) throw cause;
      agentError = cause;
    }
    try {
      await runtime.workspace.assertUnchanged(state().repositoryBaseline);
    } catch (cause) {
      if (isOwnershipFailure(cause)) throw cause;
      current = await runtime.finishAgentTurn(activeTurn, {
        repositoryReconciled: false,
      });
      await finishReserved("interrupted");
      return { failure: "workspace_changed" };
    }
    if ((await inspectInputs()) === null) {
      current = await runtime.finishAgentTurn(activeTurn, {
        repositoryReconciled: false,
      });
      return { paused: true };
    }
    if (agentError !== undefined) {
      const exhausted = runtime.outputExhaustion?.eligible(agentError) === true;
      const authentication =
        runtime.authentication?.eligible(agentError) === true;
      if (exhausted || authentication) {
        const policy = exhausted
          ? runtime.outputExhaustion
          : runtime.authentication;
        // Only proof about this original fork can restore its unused allowance.
        const noForkEffect =
          acknowledgedSessions.size === 0 &&
          session?.mode === "fork" &&
          !policy.hasPossibleEffect(agentError);
        await save(
          {
            ...state(),
            workflowState: "WAITING_FOR_USER",
            sourceForkConsumed:
              noForkEffect && lazy ? false : state().sourceForkConsumed,
            sourceForkRecovery:
              acknowledgedSessions.size > 0 || noForkEffect
                ? null
                : state().sourceForkRecovery,
            sourceForkContexts: noForkEffect
              ? state().sourceForkContexts.filter((context) => context !== key)
              : state().sourceForkContexts,
          },
          {
            activeTurn: null,
            pause: {
              reason: exhausted
                ? "output_exhausted"
                : "authentication_required",
              code: exhausted
                ? "ERR_OUTPUT_EXHAUSTED"
                : "ERR_AUTHENTICATION_REQUIRED",
              resumeState,
              ...(exhausted ? { role, checkpoint } : {}),
            },
          },
        );
        return { paused: true };
      }
      current = await runtime.finishAgentTurn(activeTurn);
      if (agentError.failureClass === STRUCTURED_OUTPUT_FAILURE_CLASS) {
        await finishReserved("invalid");
        return { failure: invalid };
      }
      if (
        runtime.inactivity?.eligible(agentError) &&
        (await runtime.inactivity.retry({ repository }))
      )
        return retry;
      if (runtime.availability?.eligible(agentError)) {
        current = await runtime.availability.schedule({
          cause: agentError,
          role,
          checkpoint,
          repository,
        });
        return retry;
      }
      if (agentError.recoverable === true) {
        if (
          acknowledgedSessions.size === 0 &&
          session?.mode === "fork" &&
          ["spawn", "initialize"].includes(
            agentError.launchRecovery?.checkpoint,
          )
        ) {
          await save({
            ...state(),
            sourceForkConsumed: lazy ? false : state().sourceForkConsumed,
            sourceForkRecovery: null,
            sourceForkContexts: state().sourceForkContexts.filter(
              (context) => context !== key,
            ),
          });
        }
        return {
          failure: "backend_unavailable",
          details: { code: safeCode(agentError) },
        };
      }
      await finishReserved("interrupted");
      await save(
        { ...state(), workflowState: "FAILED" },
        { pause: { reason: "internal_failure", code: safeCode(agentError) } },
      );
      throw agentError;
    }
    if (
      typeof response?.sessionId !== "string" ||
      response.sessionId.trim().length === 0 ||
      response.sessionId.length > 1024 ||
      /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(response.sessionId) ||
      response.sessionId === source ||
      (!acknowledgedSessions.has(response.sessionId) &&
        response.sessionId !== previous?.sessionId &&
        current.sessionLineage.children.some(
          (child) => child.sessionId === response.sessionId,
        ))
    ) {
      current = await runtime.finishAgentTurn(activeTurn);
      await finishReserved("invalid");
      return { failure: invalid };
    }
    if (
      !acknowledgedSessions.has(response.sessionId) &&
      response.sessionId !== previous?.sessionId
    ) {
      current = await runtime.recordChildSession({
        role,
        sessionId: response.sessionId,
        contextKey: key,
      });
    }
    if (state().sourceForkRecovery === key)
      await save({ ...state(), sourceForkRecovery: null });
    current = await runtime.finishAgentTurn(activeTurn);
    try {
      assertAuditResultSize(response.structured);
    } catch (cause) {
      if (!(cause instanceof AuditWorkflowError)) throw cause;
      await finishReserved("invalid");
      return { failure: invalid };
    }
    return { output: response.structured };
  }

  function assertUpdateSize(pipelineState) {
    assertAudit(
      Buffer.byteLength(JSON.stringify({ ...current, pipelineState })) <=
        32 * 1024 * 1024,
      "Audit result exceeds the enclosing persistent run limit.",
    );
    // Markdown escaping can exceed the publisher's bound even when JSON fits.
    publicationContent(pipelineState);
  }

  function safeCode(cause) {
    return typeof cause?.code === "string" &&
      /^[A-Z0-9_]{1,64}$/u.test(cause.code)
      ? cause.code
      : "ERR_AUDIT_PROVIDER_FAILED";
  }

  if (["FAILED", "CANCELED"].includes(state().workflowState)) return current;

  if (operatorStop) {
    if (state().repositoryBaseline !== null) {
      try {
        await runtime.workspace.assertUnchanged(state().repositoryBaseline);
      } catch {
        return pause("workspace_changed");
      }
      if (state().pendingEdit === null) await inspectInputs();
    }
    return current;
  }
  if (state().pendingEdit !== null) {
    // An edit window authorizes only the transcript, never changed task inputs or sources.
    try {
      await runtime.workspace.assertUnchanged(state().repositoryBaseline);
    } catch {
      return pause("workspace_changed");
    }
    const inputs = await runtime.readInputs({ taskPath: run.taskPath });
    if (
      inputs.task.hash !== current.hashes.task ||
      (inputs.context?.hash ?? null) !== current.hashes.context
    ) {
      return pause("input_changed");
    }
    if (["workspace_changed", "input_changed"].includes(current.pause?.reason))
      return current;
    await runtime.clarifications.acceptEdit(state().pendingEdit, {
      consumePendingEdit: consumeEdit,
    });
    if (state().pendingEdit !== null) return current;
  } else if (state().workflowState === "WAITING_FOR_USER") {
    if (
      ![
        "audit_scope_blocked",
        "discovery_interrupted",
        "invalid_discovery",
        "discovery_incomplete",
        "invalid_recheck",
        "recheck_incomplete",
        "authentication_required",
        "output_exhausted",
        "backend_unavailable",
      ].includes(current.pause?.reason)
    )
      return current;
    await save(
      { ...state(), workflowState: current.pause.resumeState },
      { pause: null },
    );
  }
  if (state().repositoryBaseline === null) {
    const clarification =
      await runtime.clarifications.ensureTranscript(transcript);
    const inputs = await runtime.readInputs({ taskPath: run.taskPath });
    await save(
      {
        ...state(),
        repositoryBaseline: await runtime.workspace.snapshot({
          allowedPaths: [
            transcript.transcriptPath,
            ...reportPaths(run.taskPath),
          ],
        }),
      },
      {
        hashes: {
          ...current.hashes,
          task: inputs.task.hash,
          context: inputs.context?.hash ?? null,
          clarifications: clarification.hash,
        },
      },
    );
  }
  try {
    await runtime.workspace.assertUnchanged(state().repositoryBaseline);
  } catch {
    return pause("workspace_changed");
  }
  if ((await inspectInputs()) === null) return current;
  const recovering =
    current.inactivityRecovery != null ||
    current.availabilityRetry != null ||
    [
      "authentication_required",
      "output_exhausted",
      "backend_unavailable",
    ].includes(run.pause?.reason);
  if (state().history.at(-1)?.outcome === "running" && !recovering) {
    await save(finishPass(state(), "interrupted"));
  }
  if (state().recheckHistory.at(-1)?.outcome === "running" && !recovering) {
    await save(finishRecheck(state(), "interrupted"));
  }
  if (current.activeTurn !== null && !recovering)
    current = await runtime.finishAgentTurn(current.activeTurn, {
      repositoryReconciled: false,
    });

  while (state().workflowState === "CLARIFY") {
    if (
      state().proactiveClarification &&
      !state().proactiveClarificationComplete
    ) {
      if (
        !(await requestEdit(
          "proactive-clarification",
          "proactive_clarification",
        ))
      )
        return current;
    }
    const evidence = await inspectInputs();
    if (evidence === null) return current;
    const result = await turn("clarify", {
      task: evidence.inputs.task.content,
      context: evidence.inputs.context?.content ?? "",
      clarifications: evidence.clarification.content,
    });
    if (result.paused) return current;
    if (result.failure) return pause(result.failure, "CLARIFY", result.details);
    if ((await inspectInputs()) === null) return current;
    let output;
    try {
      output = normalizeClarification(result.output);
    } catch (cause) {
      if (
        !(cause instanceof AuditWorkflowError) &&
        cause?.code !== "ERR_INVALID_AUDIT_REPORT"
      )
        throw cause;
      return pause("invalid_discovery", "CLARIFY");
    }
    if (output.status === "READY") {
      const inputs = output.inputs;
      const frozen = await runtime.clarifications.freezeTranscript({
        ...transcript,
        expectedHash: current.hashes.clarifications,
      });
      const report = emptyReport(inputs, {
        fingerprint: state().repositoryBaseline.contentFingerprint,
        description: "Inspected audit workspace",
      });
      await save({
        ...state(),
        workflowState: "DISCOVER",
        inputs,
        clarificationHash: frozen.hash,
        inputsFingerprint: fingerprint({
          inputs,
          clarificationHash: frozen.hash,
        }),
        report,
        reportFingerprint: fingerprint(report),
      });
      break;
    }
    if (output.status === "BLOCKED") {
      return pause("audit_scope_blocked", "CLARIFY", {
        explanation: output.reason,
      });
    }
    if (state().clarificationRounds >= MAX_CLARIFICATION_ROUNDS)
      return pause("clarification_limit_reached");
    const round = state().clarificationRounds + 1;
    const appended = await runtime.clarifications.appendQuestionRound({
      ...transcript,
      expectedHash: current.hashes.clarifications,
      round,
      questions: output.questions,
    });
    if (
      !(await requestEdit(
        "clarification-answers",
        "clarification_answers_required",
        {
          expectedHash: appended.hash,
          round,
          inputRequest: {
            kind: "clarification",
            questions: output.questions.map((question, index) => ({
              id: `q${index + 1}`,
              question: question.question,
              options: [],
              rationale: question.whyItMatters,
            })),
            rationale: "Answer every material clarification question.",
          },
        },
      ))
    )
      return current;
  }

  while (["DISCOVER", "VERIFY_FINDINGS"].includes(state().workflowState)) {
    if (state().workflowState === "VERIFY_FINDINGS") {
      if (
        recheckRole(state(), state().recheckHistory.length + 1) ===
          "reviewer" &&
        current.roles.reviewer === undefined
      )
        return pause("audit_reviewer_required", "VERIFY_FINDINGS", {
          code: "ERR_AUDIT_REVIEWER_REQUIRED",
          explanation:
            "This run has no frozen finding Reviewer. Start a new independent audit run to verify findings.",
        });
      const reserved = state().recheckHistory.at(-1)?.outcome === "running";
      if (
        !reserved &&
        state().recheckHistory.length >=
          state().settings.maxFindingRecheckPasses
      )
        return pause("finding_recheck_limit_reached");
      const evidence = await inspectInputs();
      if (evidence === null) return current;
      if (!reserved) await save(reserveRecheck(current));
      const result = await turn("recheck", {
        task: evidence.inputs.task.content,
        context: evidence.inputs.context?.content ?? "",
        clarifications: evidence.clarification.content,
        inputs: state().inputs,
        inputsFingerprint: state().inputsFingerprint,
        clarificationHash: state().clarificationHash,
        report: {
          limitations: state().report.limitations,
          hypotheses: state().report.hypotheses,
        },
        batch: state().pendingBatch,
        batchFingerprint: fingerprint(state().pendingBatch),
        accumulatedFindings: state().ledger,
        priorDecisions: state().recheckHistory.filter(({ outcome }) =>
          ["corrected", "clean"].includes(outcome),
        ),
      });
      if (result.paused) return current;
      if (result.failure)
        return pause(result.failure, "VERIFY_FINDINGS", result.details);
      let accepted;
      try {
        accepted = acceptRecheck(state(), result.output);
        assertUpdateSize(accepted);
      } catch (cause) {
        if (
          !(cause instanceof AuditWorkflowError) &&
          cause?.code !== "ERR_INVALID_AUDIT_REPORT"
        )
          throw cause;
        await save(finishRecheck(state(), "invalid"));
        return pause("invalid_recheck", "VERIFY_FINDINGS");
      }
      await save(accepted);
      if (state().recheckHistory.at(-1).outcome === "incomplete")
        return pause("recheck_incomplete", "VERIFY_FINDINGS");
      continue;
    }
    const reserved = state().history.at(-1)?.outcome === "running";
    if (
      !reserved &&
      state().history.length >= state().settings.maxDiscoveryPasses
    )
      return pause("discovery_limit_reached");
    const evidence = await inspectInputs();
    if (evidence === null) return current;
    const number = state().history.length + 1;
    const contextKey = sessionContextKey(current, "discovery", number);
    // Write-ahead reservation charges interrupted launches exactly once.
    if (!reserved)
      await save({
        ...state(),
        history: [
          ...state().history,
          {
            number,
            contextKey,
            outcome: "running",
            reportFingerprint: state().reportFingerprint,
            candidateIds: [],
          },
        ],
      });
    const result = await turn("discovery", {
      task: evidence.inputs.task.content,
      context: evidence.inputs.context?.content ?? "",
      clarifications: evidence.clarification.content,
      inputs: state().inputs,
      clarificationHash: state().clarificationHash,
      inputsFingerprint: state().inputsFingerprint,
      snapshotFingerprint: state().repositoryBaseline.contentFingerprint,
      report: {
        limitations: state().report.limitations,
        hypotheses: state().report.hypotheses,
      },
      accumulatedFindings: state().ledger.map(({ finding, version }) => ({
        ...finding,
        version,
      })),
      acceptedDispositions: state().acceptedBatches.map(({ batch }) => ({
        entries: batch.entries.map(({ finding, version }) => ({
          id: finding.id,
          version,
        })),
        dispositions: batch.dispositions,
      })),
    });
    if (result.paused) return current;
    if (result.failure)
      return pause(result.failure, "DISCOVER", result.details);
    if ((await inspectInputs()) === null) return current;
    let accepted;
    try {
      accepted = acceptDiscovery(state(), result.output);
      assertUpdateSize(accepted);
    } catch (cause) {
      if (
        !(cause instanceof AuditWorkflowError) &&
        cause?.code !== "ERR_INVALID_AUDIT_REPORT"
      )
        throw cause;
      await save(finishPass(state(), "invalid"));
      return pause("invalid_discovery", "DISCOVER");
    }
    await save(accepted);
    if (state().history.at(-1).outcome === "incomplete")
      return pause("discovery_incomplete", "DISCOVER");
  }
  // Clean discovery remains separate from public completion/publication.
  return current;
}
