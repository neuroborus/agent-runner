import { createHash, randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

import packageMetadata from "../../package.json" with { type: "json" };
import { PROVIDER_REGISTRY } from "../agents/index.js";
import { createClarificationService } from "../clarifications/index.js";
import { loadRunnerConfiguration } from "../config/index.js";
import { createGitService } from "../git/index.js";
import {
  createGuidanceService,
  MAX_GUIDANCE_BYTES,
} from "../guidance/index.js";
import {
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  getPipeline,
  listPipelines,
} from "../pipeline-registry.js";
import {
  createConfiguredRunStore,
  createRunner,
  pipelineRequiresWorktreeLease,
} from "../runner/index.js";
import {
  projectAvailabilityRetry,
  projectInactivityRecovery,
  projectLaunchRecovery,
  projectOperatorStop,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  RunStoreError,
  normalizeRecoveryDispatch,
} from "../state/index.js";
import { projectTrustedFailureDiagnostics } from "../trusted-validation/index.js";
import { createUnexpectedIssueReporter } from "./reporting.js";
import { launchDetachedRun } from "./detached.js";
export {
  awaitDetachedDispatch,
  createDetachedLauncher,
  launchDetachedRun,
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  DETACHED_STOP_CHECKPOINT_ENV,
} from "./detached.js";

const MAX_WAIT_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_WAIT_MS = 30_000;
const DISPATCH_TIMEOUT_MS = 30_000;
const MAX_DISPATCH_INSPECTIONS = 64;
const RUN_INSTRUCTIONS = `Use run_start to start a durable pipeline, then use one run_wait call for the desired waiting interval. Use run_activity only for explicit or historical reads; do not poll status, activity, or wait at a fixed cadence. Stop timing defaults to immediate; use after-current-commit only for a selected plan-execution step. A blocked or interrupted step stops at its reconciled checkpoint without extra work. Use run_pause or run_cancel with the exact inspected revision and a unique idempotency key; retry the same logical request with the same values and never refresh a stale revision silently. Cancellation is terminal. For an ownerless applicable stop, use run_resume with action: null, its exact inspected revision, and a new idempotency key; the original stop key is unnecessary. Recovery follows its correlated child until durable stop settlement or child exit. Action-free process-proof failures retain their checkpoint. Bounded ownership results preserve the intent: retry the identical key. Cancellation and disconnect end only the wait; reconciliation and receipt publication continue. independent is the default and recommended mode because it provides genuinely independent semantic review, but it uses more provider context and tokens. lazy is opt-in, reduces consumption, and does not provide independent review; never select it automatically to save tokens. combined is available for all three pipelines and adds primary convergence and clean confirmation before independent review. Leave sourceSession unset unless the user deliberately chooses to fork a compatible current native session after being offered a fresh start. Offer its known trusted profile with the fork choice; when the profile is unknown, offer only current profile inheritance and never guess an alias. In independent and combined modes the primary and review roles fork the complete source context independently; in lazy mode the primary role forks it once. Recommend a fresh start for a long, multi-topic, or uncertain source session. Keep native session IDs opaque; never inspect provider-private storage or infer or fabricate an ID. Answer pending input from explicit user context when sufficient; otherwise ask the user. Never invent a material product decision.`;
const ISSUE_REPORTING_INSTRUCTIONS = `Use unexpected_issue_report only when you, as the supervising client agent, explicitly conclude that Agent Runner behaved genuinely unexpectedly or contrary to its documented contract. Expected completion, exhausted configured budgets, usage limits, expected user pauses, documented environment blockers, and invalid user or configuration input are not reportable issues. Supply concise English Markdown deliberately; the server never collects or attaches logs, transcripts, prompts, environment values, credentials, secrets, or other diagnostics automatically.`;
const GUIDANCE_INSTRUCTIONS =
  "Call guidance_read once before first managing a run for each project and follow the combined operator guide.";
const SUPERVISION_INSTRUCTIONS = `${GUIDANCE_INSTRUCTIONS} ${RUN_INSTRUCTIONS}`;
export const MCP_INSTRUCTIONS = `${SUPERVISION_INSTRUCTIONS} ${ISSUE_REPORTING_INSTRUCTIONS}`;

function boundedSingleLine(maximumLength) {
  return z
    .string()
    .min(1)
    .max(maximumLength)
    .refine(
      (value) =>
        value.trim().length > 0 && !/[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value),
    );
}

const identifier = boundedSingleLine(256);
const sessionReference = boundedSingleLine(1_024);
const runId = z.uuid();
const pipelineModeValues = Object.freeze([
  ...new Set(
    listPipelines().flatMap((pipeline) => pipeline.settings.mode.values),
  ),
]);
const pipelineMode = z
  .enum(pipelineModeValues)
  .describe(
    "independent is the default and recommended mode with genuinely independent review and higher context/token use. lazy is an explicit lower-consumption choice without independent review; never select it automatically. combined adds primary convergence before independent review and is supported by all three pipelines.",
  );
const idempotencyKey = boundedSingleLine(1_024).describe(
  "Opaque key unique to this logical mutation.",
);
const guidanceReadSchema = z
  .object({
    projectPath: boundedSingleLine(4_096),
    projectConfigurationPath: boundedSingleLine(4_096).optional(),
  })
  .strict();
const guidanceUpdateSchema = guidanceReadSchema
  .extend({
    idempotencyKey,
    localContent: z
      .string()
      .max(MAX_GUIDANCE_BYTES)
      .describe(
        "The complete non-sensitive operator-authored local Markdown, at most 64 KiB in UTF-8. Empty content removes all local additions.",
      ),
    expectedHash: z
      .string()
      .regex(/^[a-f0-9]{64}$/u)
      .nullable()
      .describe(
        "The localHash from guidance_read; null requires the local file to be absent.",
      ),
  })
  .strict();
const resumeAction = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("extra-fix-rounds"),
      amount: z.number().int().positive().safe(),
    })
    .strict(),
  z
    .object({
      type: z.literal("override-finding"),
      findingId: identifier,
    })
    .strict(),
]);
function createRunStartSchema(providers) {
  const backend = z.enum(providers.ids);
  const sourceBackend =
    providers.sourceSessionIds.length === 0
      ? z.never()
      : z.enum(providers.sourceSessionIds);
  const effort = z
    .enum(["current", "low", "medium", "high", "xhigh"])
    .describe(
      "Portable effort, separate from model. current retains the effective provider default. Role overrides win over run-wide, project, and runner selections; resume preserves saved effort.",
    );
  const roleOverride = z
    .object({
      backend: backend.optional(),
      profile: z.string().min(1).max(4_096).optional(),
      model: z.string().min(1).max(256).optional(),
      contextSize: z.string().min(1).max(64).optional(),
      effort: effort.optional(),
    })
    .strict()
    .refine((value) =>
      Object.values(value).some((entry) => entry !== undefined),
    );
  const sourceSession = z
    .object({
      backend: sourceBackend.describe(
        "Backend that owns the deliberately selected source session.",
      ),
      id: sessionReference.describe(
        "Opaque native session ID supplied only after the user chooses a fork.",
      ),
      profile: z
        .string()
        .min(1)
        .max(4_096)
        .optional()
        .describe(
          'Known trusted source profile alias, or "current" inheritance when unknown; never guess an alias.',
        ),
    })
    .strict()
    .describe(
      "Compatible current session deliberately selected for complete-context forks: independently by primary and review roles in independent or combined mode, or once by the primary role in lazy mode. Leave unset for a fresh start.",
    );
  return z
    .object({
      idempotencyKey,
      pipelineId: identifier,
      projectPath: z.string().min(1),
      projectConfigurationPath: z.string().min(1).optional(),
      taskPath: z.string().min(1),
      proactiveClarification: z.boolean().default(false),
      mode: pipelineMode.optional(),
      profile: z.string().min(1).max(4_096).optional(),
      model: z.string().min(1).max(256).optional(),
      contextSize: z.string().min(1).max(64).optional(),
      effort: effort.optional(),
      roleOverrides: z.record(identifier, roleOverride).default({}),
      sourceSession: sourceSession.nullable().default(null),
    })
    .strict();
}
const runRespondSchema = z
  .object({
    idempotencyKey,
    runId,
    requestId: identifier,
    expectedRevision: z.number().int().positive().safe(),
    answers: z
      .array(
        z
          .object({
            questionId: identifier,
            answer: z.string().min(1).max(100_000),
          })
          .strict(),
      )
      .max(32),
  })
  .strict();
const runResumeSchema = z
  .object({
    idempotencyKey,
    runId,
    expectedRevision: z.number().int().positive().safe(),
    action: resumeAction.nullable().default(null),
  })
  .strict();
const runStopSchema = z
  .object({
    idempotencyKey,
    runId,
    expectedRevision: z.number().int().positive().safe(),
    timing: z.enum(["immediate", "after-current-commit"]).optional(),
  })
  .strict();
const markdownContent = (maximumLength) =>
  z
    .string()
    .min(1)
    .max(maximumLength)
    .refine(
      (value) =>
        value.trim().length > 0 &&
        !/[\0\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F\p{Zl}\p{Zp}]/u.test(
          value,
        ),
    )
    .describe("Concise English Markdown supplied explicitly by the caller.");
const unexpectedIssueReportSchema = z
  .object({
    idempotencyKey,
    projectPath: z.string().min(1).max(16_384),
    summary: markdownContent(1_000),
    expectedBehavior: markdownContent(4_000),
    actualBehavior: markdownContent(4_000),
    occurrence: markdownContent(4_000),
    unexpectedReason: markdownContent(4_000),
    details: markdownContent(16_000).optional(),
    runId: runId.optional(),
    errorCode: z
      .string()
      .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u)
      .optional(),
    projectConfigurationPath: z.string().min(1).max(16_384).optional(),
  })
  .strict();

function result(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    structuredContent: value,
  };
}

function actionArguments(input) {
  const { idempotencyKey: _idempotencyKey, ...argumentsWithoutKey } = input;
  return argumentsWithoutKey;
}

function runnerStartInput(input) {
  const {
    idempotencyKey: _idempotencyKey,
    profile,
    model,
    contextSize,
    effort,
    mode,
    ...runInput
  } = input;
  return {
    ...runInput,
    executionOverrides: {
      ...(profile === undefined ? {} : { profile }),
      ...(model === undefined ? {} : { model }),
      ...(contextSize === undefined ? {} : { contextSize }),
      ...(effort === undefined ? {} : { effort }),
    },
    settingOverrides: mode === undefined ? {} : { mode },
  };
}

function resolvedMode(run) {
  const definition = getPipeline(run.pipelineId).settings.mode;
  const mode = run.pipelineState.settings?.mode ?? definition.defaultValue;
  if (!definition.validate(mode)) {
    throw new Error(`Run ${run.runId} has an invalid resolved mode.`);
  }
  return mode;
}

function publicSettings(pipeline) {
  return Object.fromEntries(
    Object.entries(pipeline.settings).map(([name, definition]) => [
      name,
      {
        defaultValue: definition.defaultValue,
        ...(definition.recommendedValue === undefined
          ? {}
          : { recommendedValue: definition.recommendedValue }),
        ...(definition.values === undefined
          ? {}
          : { values: definition.values }),
      },
    ]),
  );
}

function pendingInput(run) {
  const request = run.pause?.inputRequest;
  if (
    run.pipelineState.workflowState !== "WAITING_FOR_USER" ||
    request === undefined ||
    request === null ||
    run.pause?.inputResponse !== undefined
  ) {
    return null;
  }
  return {
    id: request.id,
    kind: request.kind,
    questions: request.questions,
    rationale: request.rationale,
    artifactPath: request.artifactPath,
    revision: run.revision,
  };
}

function shortFingerprint(value) {
  return typeof value === "string" ? value.slice(0, 12) : null;
}

function executionProjection(run, leaseOwner) {
  const leaseOwnerStatus = leaseOwner?.status ?? "none";
  const state = ["live", "unverifiable"].includes(leaseOwnerStatus)
    ? "running"
    : run.activeTurn === null && run.executionProcess === null
      ? "idle"
      : "interrupted";
  return {
    state,
    leaseOwner: leaseOwnerStatus,
    processRecord: run.executionProcess === null ? "none" : "persisted",
    role: run.activeTurn?.role ?? null,
    phase: run.activeTurn?.phase ?? null,
  };
}

function statusProjection({ directoryPath, run }, leaseOwner) {
  const pipeline = getPipeline(run.pipelineId);
  const status = pipeline.projections.status(run);
  const clarification = pipeline.projections.clarification(run);
  const pause = projectTrustedFailureDiagnostics(
    run,
    pipeline.projections.pause(run),
  );
  return {
    runId: run.runId,
    pipelineId: run.pipelineId,
    mode: resolvedMode(run),
    revision: run.revision,
    activityCursor: run.revision,
    status: run.pipelineState.workflowState,
    launchRecovery: projectLaunchRecovery(run),
    availabilityRetry: projectAvailabilityRetry(run),
    inactivityRecovery: projectInactivityRecovery(run),
    stop: projectOperatorStop(run),
    pendingStop:
      run.stopRequest?.reconciledRevision === null
        ? {
            kind: run.stopRequest.kind,
            revision: run.stopRequest.acceptedRevision,
            timing: run.stopRequest.timing,
            effectiveTiming: run.stopRequest.effectiveTiming,
            targetStep: run.stopRequest.targetBoundary?.step ?? null,
          }
        : null,
    execution: executionProjection(run, leaseOwner),
    currentStep: status.currentStep,
    pause,
    clarificationPath: clarification.path,
    planPath: status.planPath,
    pendingInput: pendingInput(run),
    findings: status.findings,
    completedCommits: status.completedCommits,
    stagnationDirection: status.stagnationDirection,
    finalizedFingerprint: shortFingerprint(status.finalizedFingerprint),
    reviewedFingerprint: shortFingerprint(status.reviewedFingerprint),
    stateDirectory: directoryPath,
  };
}

function waitIsTerminal(run) {
  const state = run.pipelineState.workflowState;
  return (
    ["DONE", "FAILED", "CANCELED"].includes(state) ||
    (state === "WAITING_FOR_USER" && run.pause?.inputResponse === undefined)
  );
}

function clarificationHash(run) {
  return getPipeline(run.pipelineId).projections.clarification(run).hash;
}

function waitForClient(operation, signal) {
  if (signal === undefined) return operation;
  return new Promise((resolve, reject) => {
    const abort = () =>
      reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
    signal.addEventListener("abort", abort, { once: true });
    operation
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abort();
  });
}

export function createMcpControlPlane(options = {}) {
  const providers = options.providers ?? PROVIDER_REGISTRY;
  const detachedCompatibilityToken =
    options.detachedCompatibilityToken ?? DETACHED_RUNTIME_COMPATIBILITY_TOKEN;
  const loadConfiguration =
    options.loadConfiguration ?? (() => loadRunnerConfiguration(providers));
  const runStore =
    options.runStore ??
    createConfiguredRunStore({
      providers,
      loadConfiguration,
    });
  let guidance = options.guidance;
  function guidanceService() {
    guidance ??= createGuidanceService({
      runStore,
      loadConfiguration:
        options.loadConfiguration ?? (() => loadRunnerConfiguration(providers)),
    });
    return guidance;
  }
  const runner =
    options.runner ??
    createRunner({
      clarifications: createClarificationService({ interactive: false }),
      providers,
      runStore,
      loadConfiguration,
    });
  const launchRun = options.launchRun ?? launchDetachedRun;
  const dispatchClock = options.dispatchClock ?? (() => performance.now());
  const pending = new Map();
  function detachedAction(tool, operation, input, context) {
    const previous = pending.get(input.idempotencyKey);
    if (previous?.tool === tool && isDeepStrictEqual(previous.input, input))
      return waitForClient(previous.promise, context?.signal);
    const entry = {
      tool,
      input: structuredClone(input),
      promise: operation(input),
    };
    pending.set(input.idempotencyKey, entry);
    void entry.promise
      .finally(() => {
        if (pending.get(input.idempotencyKey) === entry)
          pending.delete(input.idempotencyKey);
      })
      .catch(() => {});
    return waitForClient(entry.promise, context?.signal);
  }

  const runIdFactory = options.runIdFactory ?? randomUUID;
  const reportingGit = options.reportingOptions?.git ?? createGitService();
  const issueReporter =
    options.issueReporter ??
    createUnexpectedIssueReporter({
      ...options.reportingOptions,
      git: reportingGit,
      loadConfiguration:
        options.reportingOptions?.loadConfiguration ??
        options.loadConfiguration ??
        (() => loadRunnerConfiguration(providers)),
      providers,
    });

  async function projectStatus(current) {
    const leaseOwner = await runStore.inspectRunLeaseOwner(current.run.runId);
    return statusProjection(current, leaseOwner);
  }

  async function dispatchIsReady(context, runId) {
    const { dispatch, stopCheckpointRevision } = context;
    if (dispatch === undefined || stopCheckpointRevision !== undefined)
      return false;
    const proof = await runStore.inspectRecoveryDispatch(runId, {
      id: dispatch.id,
      expectedRevision: dispatch.expectedRevision,
    });
    return proof.ready;
  }

  async function completeReadyDispatch(intent, receipt) {
    if (!(await dispatchIsReady(intent.record.context, receipt.runId)))
      return false;
    // Readiness already accepted this request. Later pauses or input changes
    // cannot turn receipt repair into another continuation or a stale request.
    await intent.complete(receipt);
    return true;
  }

  async function launchIfNeeded(
    runIdValue,
    baselineRevision,
    {
      action = null,
      allowWaiting = false,
      intent,
      stopCheckpointRevision = null,
      rejectLiveOwner = false,
    } = {},
  ) {
    const deadline = dispatchClock() + DISPATCH_TIMEOUT_MS;
    const exited = Promise.withResolvers();
    let exitCode;
    let launched = false;
    let dispatch = intent.record.context.dispatch;
    if (dispatch !== undefined) {
      normalizeRecoveryDispatch({
        id: dispatch.id,
        expectedRevision: dispatch.expectedRevision,
      });
      if (
        Object.keys(dispatch).length !== 3 ||
        !Object.hasOwn(dispatch, "owner")
      )
        throw new RunStoreError("Detached intent is invalid.", {
          code: "ERR_INVALID_MCP_ACTION",
        });
    }
    for (let inspected = 0; inspected < MAX_DISPATCH_INSPECTIONS; inspected++) {
      const remaining = Math.ceil(deadline - dispatchClock());
      if (!Number.isFinite(remaining) || remaining <= 0) break;
      const exitedBeforeInspection = exitCode !== undefined;
      const run = (await runner.status(runIdValue)).run;
      if (
        stopCheckpointRevision !== null &&
        (run.stopRequest === null ||
          run.stopRequest.reconciledRevision !== null ||
          run.stopRequest.checkpoint.revision !== stopCheckpointRevision)
      )
        return;
      let proof = { started: false, ready: false };
      if (dispatch !== undefined)
        proof = await runStore.inspectRecoveryDispatch(runIdValue, {
          id: dispatch.id,
          expectedRevision: dispatch.expectedRevision,
        });
      if (proof.ready && stopCheckpointRevision === null) return;
      if (exitCode !== undefined) {
        if (!exitedBeforeInspection) continue;
        const skew = exitCode === RUNTIME_VERSION_SKEW_EXIT_CODE;
        const owner =
          !skew && pipelineRequiresWorktreeLease(run.pipelineId)
            ? await runStore.worktreeLeaseOwner(run.projectPath, runIdValue)
            : null;
        throw new RunStoreError(
          `Detached ${stopCheckpointRevision === null ? "continuation" : "stop reconciliation"} for run ${runIdValue} exited before durable ${stopCheckpointRevision === null ? "acknowledgement" : "stop settlement"}; retry the same idempotency key.` +
            (skew
              ? " The runtime is incompatible; restart the Agent Runner MCP server."
              : "") +
            (owner !== null && owner !== runIdValue
              ? ` The conflicting canonical worktree lease belongs to run ${owner}.`
              : ""),
          {
            code: skew
              ? "ERR_RUNTIME_VERSION_SKEW"
              : "ERR_DETACHED_START_FAILED",
          },
        );
      }
      const live = await runStore.runLeaseOwnerIsLive(runIdValue);
      if (dispatch === undefined) {
        if (rejectLiveOwner && live)
          throw new RunStoreError(
            `Run ${runIdValue} already has a live execution owner.`,
            { code: "ERR_RUN_LEASED" },
          );
        if (run.revision !== baselineRevision)
          throw new RunStoreError("Resume request revision is stale.", {
            code: "ERR_RUN_REVISION_CHANGED",
          });
        if (
          stopCheckpointRevision === null &&
          (["DONE", "CANCELED"].includes(run.pipelineState.workflowState) ||
            (!allowWaiting &&
              run.pipelineState.workflowState === "WAITING_FOR_USER"))
        )
          return;
      }
      if (
        pipelineRequiresWorktreeLease(run.pipelineId) &&
        stopCheckpointRevision === null
      ) {
        const owner = await runStore.worktreeLeaseOwner(
          run.projectPath,
          runIdValue,
        );
        if (owner !== null && owner !== runIdValue)
          throw new RunStoreError(
            `Run ${runIdValue} remains durable; retry the same idempotency key after worktree owner ${owner} releases ownership.`,
            { code: "ERR_WORKTREE_LEASED" },
          );
      }
      const ownerStatus =
        dispatch?.owner == null
          ? null
          : await runStore.inspectDispatchOwner(dispatch.owner);
      if (ownerStatus === "unverifiable") break;
      if (!launched && !live && ownerStatus !== "live") {
        // No started event means the child never passed exact-revision admission.
        if (
          (proof.started && !proof.retryable) ||
          (!proof.started &&
            run.revision !== (dispatch?.expectedRevision ?? baselineRevision))
        ) {
          throw new RunStoreError(
            "Run changed without correlated dispatch evidence.",
            { code: "ERR_RUN_REVISION_CHANGED" },
          );
        }
        dispatch = {
          id: randomUUID(),
          expectedRevision: run.revision,
          owner: null,
        };
        await intent.updateContext({ ...intent.record.context, dispatch });
        await launchRun(runIdValue, action, {
          expectedRuntimeCompatibility: detachedCompatibilityToken,
          stopCheckpointRevision,
          dispatch: {
            id: dispatch.id,
            expectedRevision: dispatch.expectedRevision,
          },
          async onSpawn(owner) {
            await runStore.inspectDispatchOwner(owner);
            dispatch = { ...dispatch, owner };
            await intent.updateContext({ ...intent.record.context, dispatch });
          },
          onExit(code) {
            exitCode = code ?? 1;
            exited.resolve();
          },
        });
        launched = true;
        continue;
      }
      // Filesystem notifications and child exit are observations, never proof.
      const wait = new AbortController();
      const changed = runStore.waitForRunChange(runIdValue, {
        afterRevision: run.revision,
        timeoutMs: remaining,
        signal: wait.signal,
        includeOwnership: true,
      });
      try {
        await Promise.race([changed, exited.promise]);
      } finally {
        wait.abort();
        await changed.catch(() => {});
      }
    }
    throw new RunStoreError(
      "Detached ownership recovery remains pending; retry the same idempotency key.",
      { code: "ERR_DETACHED_OWNERSHIP_PENDING" },
    );
  }

  async function pipelinesList() {
    return {
      pipelines: listPipelines().map((pipeline) => ({
        id: pipeline.id,
        description: pipeline.description,
        roles: pipeline.roles,
        settings: publicSettings(pipeline),
        taskInputs: pipeline.taskInputs,
        runOptions: pipeline.runOptions,
        requiredRunOptions: pipeline.requiredRunOptions,
      })),
    };
  }

  async function runStart(input) {
    const identity = {
      key: input.idempotencyKey,
      tool: "run_start",
      arguments: actionArguments(input),
    };
    const existing = await runStore.readAction(identity);
    if (existing?.status === "completed") {
      return existing.result;
    }
    let boundary =
      existing &&
      (await dispatchIsReady(existing.context, existing.context.runId))
        ? null
        : await runner.validateBoundary({
            projectPath: input.projectPath,
            taskPath: input.taskPath,
          });
    const context = { runId: runIdFactory() };
    const action = await runStore.beginAction({
      ...identity,
      context,
    });
    try {
      if (action.record.status === "completed") {
        return action.record.result;
      }
      const reservedRunId = action.record.context.runId;
      const completedReceipt = { runId: reservedRunId };
      if (await completeReadyDispatch(action, completedReceipt))
        return completedReceipt;
      boundary ??= await runner.validateBoundary({
        projectPath: input.projectPath,
        taskPath: input.taskPath,
      });
      let run;
      try {
        ({ run } = await runner.status(reservedRunId));
      } catch (cause) {
        if (cause?.code !== "ERR_RUN_NOT_FOUND") {
          throw cause;
        }
        ({ run } = await runner.create(runnerStartInput(input), {
          runId: reservedRunId,
        }));
      }
      if (
        run.pipelineId !== input.pipelineId ||
        run.projectPath !== boundary.projectPath ||
        run.taskPath !== boundary.taskPath ||
        run.sessionLineage.source !== (input.sourceSession?.id ?? null) ||
        run.sessionLineage.sourceProfile !==
          (input.sourceSession?.profile === undefined ||
          input.sourceSession.profile === "current"
            ? null
            : input.sourceSession.profile) ||
        run.pipelineState.proactiveClarification !==
          input.proactiveClarification ||
        (input.mode !== undefined && resolvedMode(run) !== input.mode)
      ) {
        throw new Error("Reserved run does not match its MCP action intent.");
      }
      await launchIfNeeded(run.runId, run.revision, { intent: action });
      const receipt = { runId: run.runId };
      await action.complete(receipt);
      return receipt;
    } finally {
      await action.release();
    }
  }

  async function runStatus(input) {
    return projectStatus(await runner.status(input.runId));
  }

  async function runActivity(input) {
    const { run } = await runner.status(input.runId);
    const page = await runStore.readPublicActivity(input.runId, {
      afterRevision: input.cursor,
      limit: input.limit,
    });
    return { runId: input.runId, mode: resolvedMode(run), ...page };
  }

  async function runWait(input, context = {}) {
    const deadline = Date.now() + input.timeoutMs;
    let cursor = input.cursor;

    while (true) {
      let current = await runner.status(input.runId);
      let { run } = current;
      if (cursor > run.revision) {
        throw new Error("Public activity cursor is ahead of the run.");
      }
      while (cursor < run.revision) {
        const page = await runStore.readPublicActivity(input.runId, {
          afterRevision: cursor,
          limit: 100,
        });
        cursor = page.cursor;
        if (input.progress && context.progressToken !== undefined) {
          for (const activity of page.activities) {
            await context.notify({
              method: "notifications/progress",
              params: {
                progressToken: context.progressToken,
                progress: activity.revision,
                message: `[${activity.actor}/${activity.phase}] ${activity.message}`,
              },
            });
          }
        }
        if (page.cursor === run.revision || page.activities.length < 100) {
          break;
        }
      }
      current = await runner.status(input.runId);
      ({ run } = current);
      if (cursor < run.revision) {
        continue;
      }
      if (waitIsTerminal(run)) {
        return { ...(await projectStatus(current)), timedOut: false };
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return { ...(await projectStatus(current)), timedOut: true };
      }
      const changed = await runStore.waitForRunChange(input.runId, {
        afterRevision: run.revision,
        timeoutMs: remaining,
        signal: context.signal,
      });
      if (changed.revision === run.revision && Date.now() >= deadline) {
        return { ...(await projectStatus(current)), timedOut: true };
      }
    }
  }

  async function runRespond(input) {
    const identity = {
      key: input.idempotencyKey,
      tool: "run_respond",
      arguments: actionArguments(input),
    };
    const existing = await runStore.readAction(identity);
    if (existing?.status === "completed") {
      return existing.result;
    }
    await runner.status(input.runId);
    const action = await runStore.beginAction({
      ...identity,
      context: {
        runId: input.runId,
        requestId: input.requestId,
        expectedRevision: input.expectedRevision,
        responseHash: null,
        submittedRevision: null,
      },
    });
    try {
      if (action.record.status === "completed") {
        return action.record.result;
      }
      let context = action.record.context;
      const completedReceipt = {
        runId: input.runId,
        requestId: input.requestId,
      };
      if (await completeReadyDispatch(action, completedReceipt))
        return completedReceipt;
      if (context.responseHash === null) {
        const preview = await runner.previewInput(actionArguments(input));
        context = {
          ...context,
          responseHash: preview.responseHash,
        };
        await action.updateContext(context);
      }

      let run = (await runner.status(input.runId)).run;
      let submittedRevision = context.submittedRevision;
      if (
        run.pause?.inputResponse?.requestId === input.requestId &&
        run.pause.inputResponse.transcriptHash === context.responseHash
      ) {
        submittedRevision = run.revision;
      } else if (
        run.revision === input.expectedRevision &&
        run.pause?.inputResponse === undefined
      ) {
        ({ run } = await runner.submitInput({
          ...actionArguments(input),
          responseHash: context.responseHash,
        }));
        submittedRevision = run.revision;
      } else if (
        !action.created &&
        run.revision > input.expectedRevision &&
        clarificationHash(run) === context.responseHash
      ) {
        submittedRevision ??= input.expectedRevision + 1;
      } else {
        throw new Error("Pending input request is stale.");
      }
      if (context.submittedRevision === null) {
        context = { ...context, submittedRevision };
        await action.updateContext(context);
      }
      await launchIfNeeded(input.runId, submittedRevision, {
        allowWaiting: true,
        intent: action,
      });
      const receipt = { runId: input.runId, requestId: input.requestId };
      await action.complete(receipt);
      return receipt;
    } finally {
      await action.release();
    }
  }

  async function runResume(input) {
    const identity = {
      key: input.idempotencyKey,
      tool: "run_resume",
      arguments: actionArguments(input),
    };
    const existing = await runStore.readAction(identity);
    if (existing?.status === "completed") {
      return existing.result;
    }
    await runner.status(input.runId);
    const action = await runStore.beginAction({
      ...identity,
      context: {
        runId: input.runId,
        expectedRevision: input.expectedRevision,
      },
    });
    try {
      if (action.record.status === "completed") {
        return action.record.result;
      }
      const completedReceipt = { runId: input.runId };
      if (await completeReadyDispatch(action, completedReceipt))
        return completedReceipt;
      const run = (await runner.status(input.runId)).run;
      let stopCheckpointRevision = action.record.context.stopCheckpointRevision;
      if (
        stopCheckpointRevision !== undefined &&
        (!Number.isSafeInteger(stopCheckpointRevision) ||
          stopCheckpointRevision < 1)
      ) {
        throw new RunStoreError("Stop recovery intent is invalid.", {
          code: "ERR_INVALID_MCP_ACTION",
        });
      }
      const applicableStop = projectOperatorStop(run)?.state === "applicable";
      if (stopCheckpointRevision !== undefined) {
        if (input.action !== null || run.revision < input.expectedRevision) {
          throw new Error("Stop recovery request is invalid or stale.");
        }
      } else if (run.revision === input.expectedRevision && applicableStop) {
        if (input.action !== null) {
          throw new Error("A pending stop accepts only an action-free resume.");
        }
        if (await runStore.runLeaseOwnerIsLive(run.runId)) {
          throw new RunStoreError(
            `Run ${run.runId} already has a live execution owner.`,
            { code: "ERR_RUN_LEASED" },
          );
        }
        stopCheckpointRevision = run.stopRequest.checkpoint.revision;
        await action.updateContext({
          ...action.record.context,
          stopCheckpointRevision,
        });
      } else if (run.revision === input.expectedRevision) {
        const interrupted =
          run.pause === null &&
          !["DONE", "FAILED", "CANCELED"].includes(
            run.pipelineState.workflowState,
          );
        if (interrupted) {
          if (input.action !== null) {
            throw new Error(
              "An interrupted run accepts only an action-free resume.",
            );
          }
          if (await runStore.runLeaseOwnerIsLive(run.runId)) {
            throw new RunStoreError(
              `Run ${run.runId} already has a live execution owner.`,
              { code: "ERR_RUN_LEASED" },
            );
          }
        } else {
          getPipeline(run.pipelineId).validateResumeAction(run, input.action);
        }
      } else if (
        applicableStop ||
        action.created ||
        run.revision < input.expectedRevision
      ) {
        throw new Error("Resume request revision is stale.");
      }
      await launchIfNeeded(input.runId, input.expectedRevision, {
        action: input.action,
        allowWaiting: true,
        intent: action,
        stopCheckpointRevision: stopCheckpointRevision ?? null,
        rejectLiveOwner: action.created,
      });
      const receipt = { runId: input.runId };
      await action.complete(receipt);
      return receipt;
    } finally {
      await action.release();
    }
  }

  async function reconcileDetachedStop(receipt) {
    const run = (await runner.status(receipt.runId)).run;
    const stop = run.stopRequest;
    if (
      stop === null ||
      stop.reconciledRevision !== null ||
      stop.requestId !== receipt.requestId
    )
      return;
    if (await runStore.runLeaseOwnerIsLive(receipt.runId)) return;
    const identity = {
      key: `stop-recovery-${createHash("sha256").update(receipt.requestId).digest("hex")}`,
      tool: "run_resume",
      arguments: {
        runId: receipt.runId,
        stopCheckpointRevision: stop.checkpoint.revision,
      },
      context: {
        runId: receipt.runId,
        expectedRevision: run.revision,
        stopCheckpointRevision: stop.checkpoint.revision,
      },
    };
    const intent = await runStore.beginAction(identity);
    try {
      if (intent.record.status === "completed") return;
      await launchIfNeeded(
        receipt.runId,
        intent.record.context.expectedRevision,
        {
          allowWaiting: true,
          intent,
          stopCheckpointRevision: stop.checkpoint.revision,
        },
      );
      await intent.complete({ runId: receipt.runId });
    } finally {
      await intent.release();
    }
  }

  async function runStop(input, kind) {
    input = runStopSchema.parse(input);
    const receipt = await runner.requestOperatorStop({
      runId: input.runId,
      kind,
      expectedRevision: input.expectedRevision,
      idempotencyKey: input.idempotencyKey,
      ...(input.timing === undefined ? {} : { timing: input.timing }),
    });
    await reconcileDetachedStop(receipt);
    return receipt;
  }

  async function unexpectedIssueReport(input) {
    const projectPath = await reportingGit.resolveProject(input.projectPath);
    const boundary = await runStore.validateStateBoundary({
      projectPath,
      taskPath: projectPath,
    });
    const argumentsValue = {
      ...actionArguments(input),
      projectPath: boundary.projectPath,
    };
    const identity = {
      key: input.idempotencyKey,
      tool: "unexpected_issue_report",
      arguments: argumentsValue,
    };
    const existing = await runStore.readAction(identity);
    if (existing?.status === "completed") {
      return existing.result;
    }
    const action = await runStore.beginAction({
      ...identity,
      context: {
        issuesPath: null,
        publicationPhase: null,
        projectPath: null,
        reportPath: null,
        temporaryPath: null,
      },
    });
    try {
      if (action.record.status === "completed") {
        return action.record.result;
      }
      const reportPath = await issueReporter.report(argumentsValue, {
        reservedIssuesPath: action.record.context.issuesPath,
        reservedPath: action.record.context.reportPath,
        reservedPublicationPhase: action.record.context.publicationPhase,
        reservedProjectPath: action.record.context.projectPath,
        reservedTemporaryPath: action.record.context.temporaryPath,
        async prepare(identityValue) {
          await action.updateContext({
            ...action.record.context,
            ...identityValue,
          });
        },
        async publish(identityValue) {
          await action.updateContext({
            ...action.record.context,
            ...identityValue,
          });
        },
        async reserve(identityValue) {
          await action.updateContext({
            ...action.record.context,
            ...identityValue,
          });
        },
      });
      const receipt = { reportPath };
      await action.complete(receipt);
      return receipt;
    } finally {
      await action.release();
    }
  }

  return Object.freeze({
    guidanceRead: (input) => guidanceService().read(input),
    guidanceUpdate: (input) => guidanceService().update(input),
    pipelinesList,
    runActivity,
    runRespond: (input, context) =>
      detachedAction("run_respond", runRespond, input, context),
    runResume: (input, context) =>
      detachedAction("run_resume", runResume, input, context),
    runPause: (input, context) =>
      detachedAction(
        "run_pause",
        (value) => runStop(value, "pause_requested"),
        input,
        context,
      ),
    runCancel: (input, context) =>
      detachedAction(
        "run_cancel",
        (value) => runStop(value, "cancel_requested"),
        input,
        context,
      ),
    runStart: (input, context) =>
      detachedAction("run_start", runStart, input, context),
    runStatus,
    runWait,
    unexpectedIssueReport,
  });
}

export function createMcpServer(options = {}) {
  const providers = options.providers ?? PROVIDER_REGISTRY;
  const runStartSchema = createRunStartSchema(providers);
  const issueReportingEnabled =
    options.issueReportingEnabled ??
    options.runnerConfiguration?.issueReporting ??
    true;
  const control = options.control ?? createMcpControlPlane(options);
  const server = new McpServer(
    { name: "agent-runner", version: packageMetadata.version },
    {
      instructions: issueReportingEnabled
        ? MCP_INSTRUCTIONS
        : SUPERVISION_INSTRUCTIONS,
    },
  );
  const readOnly = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  };
  const mutating = {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: false,
  };
  const localCreation = {
    ...mutating,
    destructiveHint: false,
  };

  server.registerTool(
    "guidance_read",
    {
      description:
        "Read the complete common operator guide, local additions, and local editing metadata for a project.",
      inputSchema: guidanceReadSchema,
      annotations: readOnly,
    },
    async (input) => result(await control.guidanceRead(input)),
  );
  server.registerTool(
    "guidance_update",
    {
      description:
        "Replace the complete local operator Markdown using its expected hash. Never replaces the common guide. Retry the same logical mutation with the same idempotency key and arguments.",
      inputSchema: guidanceUpdateSchema,
      annotations: mutating,
    },
    async (input) => result(await control.guidanceUpdate(input)),
  );
  server.registerTool(
    "pipelines_list",
    {
      description: "List the built-in Agent Runner pipelines.",
      inputSchema: z.object({}).strict(),
      annotations: readOnly,
    },
    async () => result(await control.pipelinesList()),
  );
  server.registerTool(
    "run_start",
    {
      description:
        "Start a durable pipeline. Set effort separately from model using current|low|medium|high|xhigh; roleOverrides effort wins over run-wide effort, and current retains the provider default. independent is default and recommended for genuinely independent semantic review but uses more provider context and tokens; lazy is opt-in for lower consumption and has no independent review, so never select it automatically. combined adds primary convergence before independent review and is available for all three pipelines. Leave sourceSession unset unless the user deliberately selects a compatible current session after being offered a fresh start. independent and combined fork its complete context into primary and review roles; lazy forks it once into the primary role. Recommend fresh for a long, multi-topic, or uncertain session. Include its known trusted profile, use only current inheritance when unknown, keep native IDs opaque, and never inspect private storage or infer an ID or alias.",
      inputSchema: runStartSchema,
      annotations: mutating,
    },
    async (input, context) =>
      result(await control.runStart(input, { signal: context.mcpReq.signal })),
  );
  server.registerTool(
    "run_status",
    {
      description: "Read the concise current state of one durable run.",
      inputSchema: z.object({ runId }).strict(),
      annotations: readOnly,
    },
    async (input) => result(await control.runStatus(input)),
  );
  server.registerTool(
    "run_pause",
    {
      description:
        "Request a durable operator pause at the exact inspected revision. Timing defaults to immediate; after-current-commit is supported only for a selected execution step, including suspended steps. It settles after verification or at a reconciled quiescent checkpoint on pause, failure, or interruption, without extra work. Retry the same logical request with the same idempotency key and revision and unchanged timing; never refresh a stale request silently.",
      inputSchema: runStopSchema,
      annotations: mutating,
    },
    async (input, context) =>
      result(await control.runPause(input, { signal: context.mcpReq.signal })),
  );
  server.registerTool(
    "run_cancel",
    {
      description:
        "Request terminal cancellation at the exact inspected revision. Timing defaults to immediate; after-current-commit is supported only for a selected execution step, including suspended steps. It settles after verification or at a reconciled quiescent checkpoint on pause, failure, or interruption, without extra work. Retry the same logical request with the same idempotency key and revision and unchanged timing; never refresh a stale request silently.",
      inputSchema: runStopSchema,
      annotations: mutating,
    },
    async (input, context) =>
      result(await control.runCancel(input, { signal: context.mcpReq.signal })),
  );
  server.registerTool(
    "run_activity",
    {
      description:
        "Read bounded explicit or historical public activity after a cursor. This is not a polling primitive.",
      inputSchema: z
        .object({
          runId,
          cursor: z.number().int().nonnegative().safe().default(0),
          limit: z.number().int().min(1).max(100).default(50),
        })
        .strict(),
      annotations: readOnly,
    },
    async (input) => result(await control.runActivity(input)),
  );
  server.registerTool(
    "run_wait",
    {
      description:
        "Wait once for user input, completion, cancellation, failure, or timeout. Do not call at a fixed cadence; a timeout leaves the run available for a later explicit call.",
      inputSchema: z
        .object({
          runId,
          cursor: z.number().int().nonnegative().safe().default(0),
          timeoutMs: z
            .number()
            .int()
            .min(0)
            .max(MAX_WAIT_MS)
            .default(DEFAULT_WAIT_MS),
          progress: z.boolean().default(false),
        })
        .strict(),
      annotations: readOnly,
    },
    async (input, context) =>
      result(
        await control.runWait(input, {
          notify: context.mcpReq.notify,
          progressToken: context.mcpReq._meta?.progressToken,
          signal: context.mcpReq.signal,
        }),
      ),
  );
  server.registerTool(
    "run_respond",
    {
      description:
        "Answer the exact pending input request and continue the durable run. Use explicit user context for material product decisions.",
      inputSchema: runRespondSchema,
      annotations: mutating,
    },
    async (input, context) =>
      result(
        await control.runRespond(input, { signal: context.mcpReq.signal }),
      ),
  );
  server.registerTool(
    "run_resume",
    {
      description:
        "Resume a persisted pause with its valid action, or recover an ownerless applicable stop or nonterminal checkpoint with action: null. Use the exact inspected revision and a unique idempotency key; stop recovery does not require the original stop key and waits for durable settlement or child exit. Action-free process-proof failures preserve the checkpoint; bounded event-driven dispatch returns retryable ownership results without clearing reservations. Disconnect cancels only observation, not reconciliation or receipt completion. Reject stale revisions, non-null stop-recovery actions, and live execution owners.",
      inputSchema: runResumeSchema,
      annotations: mutating,
    },
    async (input, context) =>
      result(await control.runResume(input, { signal: context.mcpReq.signal })),
  );
  if (issueReportingEnabled) {
    server.registerTool(
      "unexpected_issue_report",
      {
        description:
          "Create one deliberate local report only after the supervising client agent explicitly concludes Agent Runner behaved genuinely unexpectedly or contrary to its documented contract. Expected completion, exhausted configured budgets, usage limits, expected user pauses, documented environment blockers, and invalid user or configuration input are not reportable. Supply only concise English Markdown explicitly; no logs, transcripts, prompts, environment values, credentials, secrets, or other diagnostics are collected automatically.",
        inputSchema: unexpectedIssueReportSchema,
        annotations: localCreation,
      },
      async (input, context) =>
        result(
          await control.unexpectedIssueReport(input, {
            signal: context.mcpReq.signal,
          }),
        ),
    );
  }

  return server;
}

export async function serveMcp(options = {}) {
  const stderr = options.stderr ?? process.stderr;
  const providers = options.providers ?? PROVIDER_REGISTRY;
  const configuration =
    options.runnerConfiguration ??
    (await (
      options.loadConfiguration ?? (() => loadRunnerConfiguration(providers))
    )());
  const createServer =
    options.createServer ??
    (() =>
      createMcpServer({
        ...options,
        issueReportingEnabled: configuration.issueReporting,
        runnerConfiguration: configuration,
      }));
  return serveStdio(createServer, {
    ...(options.transport === undefined
      ? {}
      : { transport: options.transport }),
    onerror(error) {
      const code =
        typeof error?.code === "string" && /^[A-Z0-9_]{1,64}$/u.test(error.code)
          ? error.code
          : "ERR_MCP_PROTOCOL";
      stderr.write(`Agent Runner MCP error: ${code}.\n`);
    },
  });
}
