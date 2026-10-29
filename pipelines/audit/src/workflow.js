import { join } from "node:path";

import {
  acceptDiscovery,
  assertAudit,
  assertAuditResultSize,
  assertAuditRun,
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
  DISCOVERY_INSTRUCTIONS,
} from "./prompts.js";
import { CLARIFICATION_SCHEMA, DISCOVERY_SCHEMA } from "./schemas.js";

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

/** Unregistered discovery lifecycle. The runner supplies all persistence and read-only effects. */
export async function runAuditDiscovery({
  run,
  runtime,
  operatorStop = false,
}) {
  assertAuditRun(run);
  if (run.pipelineState.settings.mode === "combined") {
    throw new AuditWorkflowError(
      "Combined audit discovery is not available yet.",
      "ERR_AUDIT_MODE_UNAVAILABLE",
    );
  }
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
  async function requestEdit(questions) {
    const round = state().clarificationRounds + 1;
    const appended = await runtime.clarifications.appendQuestionRound({
      ...transcript,
      expectedHash: current.hashes.clarifications,
      round,
      questions,
    });
    await runtime.clarifications.prepareEdit({
      ...transcript,
      expectedHash: appended.hash,
      action: "clarification-answers",
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
            hashes: { ...current.hashes, clarifications: appended.hash },
            pause: {
              reason: "clarification_answers_required",
              resumeState: "CLARIFY",
            },
          },
        ),
    });
    // The common CLI/MCP clarification boundary can consume this persisted one-shot edit.
    return current;
  }
  const retry = Symbol("retry");
  async function turn(phase, evidence) {
    for (;;) {
      const result = await attempt(phase, evidence);
      if (result !== retry) return result;
    }
  }
  async function attempt(phase, evidence) {
    try {
      await runtime.workspace.assertUnchanged(state().repositoryBaseline);
    } catch {
      if (phase === "discovery") await save(finishPass(state(), "interrupted"));
      return { failure: "workspace_changed" };
    }
    const lazy = state().settings.mode === "lazy";
    const key = sessionContextKey(current, phase);
    const checkpoint = `audit:${phase}:read-only:${phase === "discovery" ? state().history.length : state().clarificationRounds}`;
    const repository = state().repositoryBaseline;
    try {
      if (
        current.availabilityRetry != null &&
        runtime.availability !== undefined
      ) {
        current = await runtime.availability.before({
          role: "auditor",
          checkpoint,
          repository,
        });
      }
      if (runtime.inactivity !== undefined) {
        current = await runtime.inactivity.before({
          role: "auditor",
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
      .find((child) => child.role === "auditor" && child.contextKey === key);
    const source = current.sessionLineage.source;
    const reconstructing = current.inactivityRecovery != null;
    const session =
      !reconstructing && previous
        ? { mode: "continue", id: previous.sessionId }
        : !reconstructing &&
            state().sourceForkRecovery !== key &&
            source !== null &&
            (!lazy || !state().sourceForkConsumed)
          ? { mode: "fork", id: source }
          : undefined;
    const activeTurn = { role: "auditor", phase };
    current = await runtime.startAgentTurn(activeTurn, {
      pipelineState: {
        ...state(),
        sourceForkConsumed:
          state().sourceForkConsumed || (lazy && session?.mode === "fork"),
        sourceForkRecovery:
          session?.mode === "fork" ? key : state().sourceForkRecovery,
      },
    });
    const prompt = `${AUDIT_INSTRUCTIONS}\n\n${phase === "clarify" ? CLARIFICATION_INSTRUCTIONS : DISCOVERY_INSTRUCTIONS}\n\n${JSON.stringify(evidence)}`;
    const configuration = current.roles.auditor;
    let response;
    let agentError;
    try {
      response = await runtime.adapters.auditor.run({
        access: "read-only",
        cwd: current.projectPath,
        prompt,
        recoveryPrompt: prompt,
        schema: phase === "clarify" ? CLARIFICATION_SCHEMA : DISCOVERY_SCHEMA,
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
      if (phase === "discovery") await save(finishPass(state(), "interrupted"));
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
          session?.mode === "fork" && !policy.hasPossibleEffect(agentError);
        await save(
          {
            ...state(),
            workflowState: "WAITING_FOR_USER",
            sourceForkConsumed:
              noForkEffect && lazy ? false : state().sourceForkConsumed,
            sourceForkRecovery: noForkEffect
              ? null
              : state().sourceForkRecovery,
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
              resumeState: phase === "clarify" ? "CLARIFY" : "DISCOVER",
              ...(exhausted ? { role: "auditor", checkpoint } : {}),
            },
          },
        );
        return { paused: true };
      }
      current = await runtime.finishAgentTurn(activeTurn);
      if (agentError.failureClass === STRUCTURED_OUTPUT_FAILURE_CLASS) {
        if (phase === "discovery") await save(finishPass(state(), "invalid"));
        return { failure: "invalid_discovery" };
      }
      if (
        runtime.inactivity?.eligible(agentError) &&
        (await runtime.inactivity.retry({ repository }))
      )
        return retry;
      if (runtime.availability?.eligible(agentError)) {
        current = await runtime.availability.schedule({
          cause: agentError,
          role: "auditor",
          checkpoint,
          repository,
        });
        return retry;
      }
      if (agentError.recoverable === true) {
        if (
          session?.mode === "fork" &&
          ["spawn", "initialize"].includes(
            agentError.launchRecovery?.checkpoint,
          )
        ) {
          await save({
            ...state(),
            sourceForkConsumed: lazy ? false : state().sourceForkConsumed,
            sourceForkRecovery: null,
          });
        }
        return {
          failure: "backend_unavailable",
          details: { code: safeCode(agentError) },
        };
      }
      if (phase === "discovery") await save(finishPass(state(), "interrupted"));
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
      (response.sessionId !== previous?.sessionId &&
        current.sessionLineage.children.some(
          (child) => child.sessionId === response.sessionId,
        ))
    ) {
      current = await runtime.finishAgentTurn(activeTurn);
      if (phase === "discovery") await save(finishPass(state(), "invalid"));
      return { failure: "invalid_discovery" };
    }
    if (response.sessionId !== previous?.sessionId) {
      current = await runtime.recordChildSession({
        role: "auditor",
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
      if (phase === "discovery") await save(finishPass(state(), "invalid"));
      return { failure: "invalid_discovery" };
    }
    return { output: response.structured };
  }

  function safeCode(cause) {
    return typeof cause?.code === "string" &&
      /^[A-Z0-9_]{1,64}$/u.test(cause.code)
      ? cause.code
      : "ERR_AUDIT_PROVIDER_FAILED";
  }

  if (state().workflowState === "FAILED") return current;

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
      consumePendingEdit: async (result) => {
        assertAudit(
          result.authorizationId === state().pendingEdit.id,
          "Audit edit authorization changed.",
        );
        await save(
          { ...state(), workflowState: "CLARIFY", pendingEdit: null },
          {
            hashes: { ...current.hashes, clarifications: result.hash },
            pause: null,
          },
        );
      },
    });
  } else if (state().workflowState === "WAITING_FOR_USER") {
    if (
      ![
        "audit_scope_blocked",
        "discovery_interrupted",
        "invalid_discovery",
        "discovery_incomplete",
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
          allowedPaths: [transcript.transcriptPath],
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
  if (current.activeTurn !== null && !recovering)
    current = await runtime.finishAgentTurn(current.activeTurn, {
      repositoryReconciled: false,
    });

  while (state().workflowState === "CLARIFY") {
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
    return requestEdit(output.questions);
  }

  while (state().workflowState === "DISCOVER") {
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
    });
    if (result.paused) return current;
    if (result.failure)
      return pause(result.failure, "DISCOVER", result.details);
    if ((await inspectInputs()) === null) return current;
    let accepted;
    try {
      accepted = acceptDiscovery(state(), result.output);
      assertAudit(
        Buffer.byteLength(
          JSON.stringify({ ...current, pipelineState: accepted }),
        ) <=
          32 * 1024 * 1024,
        "Audit result exceeds the enclosing persistent run limit.",
      );
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
  // Finding verification and public completion/publication are deliberately unavailable here.
  return current;
}
