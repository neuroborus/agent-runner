import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

import packageMetadata from "../package.json" with { type: "json" };
import { createClarificationService } from "./clarifications.js";
import { loadRunnerConfiguration } from "./config.js";
import { createGitService } from "./git.js";
import { createUnexpectedIssueReporter } from "./mcp-reporting.js";
import { getPipeline, listPipelines } from "./pipeline-registry.js";
import {
  createRunner,
  pipelineRequiresWorktreeLease,
} from "./runner.js";
import {
  createRunStore,
  RUNTIME_COMPATIBILITY_TOKEN,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  RunStoreError,
} from "./state.js";

const MAX_WAIT_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_WAIT_MS = 30_000;
const RETRY_DELAY_MS = 25;
const EXECUTABLE_PATH = fileURLToPath(
  new URL("../bin/agent-run.js", import.meta.url),
);
export const DETACHED_RUNTIME_COMPATIBILITY_ENV =
  "AGENT_RUNNER_PARENT_RUNTIME_COMPATIBILITY";

const RUN_INSTRUCTIONS = `Use run_start to start a durable pipeline, then use one run_wait call for the desired waiting interval. Use run_activity only for explicit or historical reads; do not poll status, activity, or wait at a fixed cadence. Leave sourceSession unset unless the user deliberately chooses to fork a compatible current native session after being offered a fresh start. Offer its known trusted profile with the fork choice; when the profile is unknown, offer only current profile inheritance and never guess an alias. Primary and review roles fork the complete source context independently, which can spend provider context and quota twice. Recommend a fresh start for a long, multi-topic, or uncertain source session. Keep native session IDs opaque; never inspect provider-private storage or infer or fabricate an ID. Answer pending input from explicit user context when sufficient; otherwise ask the user. Never invent a material product decision.`;
const ISSUE_REPORTING_INSTRUCTIONS = `Use unexpected_issue_report only when you, as the supervising client agent, explicitly conclude that Agent Runner behaved genuinely unexpectedly or contrary to its documented contract. Expected completion, exhausted configured budgets, usage limits, expected user pauses, documented environment blockers, and invalid user or configuration input are not reportable issues. Supply concise English Markdown deliberately; the server never collects or attaches logs, transcripts, prompts, environment values, credentials, secrets, or other diagnostics automatically.`;
export const MCP_INSTRUCTIONS =
  `${RUN_INSTRUCTIONS} ${ISSUE_REPORTING_INSTRUCTIONS}`;

function boundedSingleLine(maximumLength) {
  return z
    .string()
    .min(1)
    .max(maximumLength)
    .refine(
      (value) =>
        value.trim().length > 0 &&
        !/[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value),
    );
}

const identifier = boundedSingleLine(256);
const sessionReference = boundedSingleLine(1_024);
const runId = z.uuid();
const idempotencyKey = boundedSingleLine(1_024)
  .describe("Opaque key unique to this logical mutation.");
const roleOverride = z
  .object({
    backend: z.enum(["codex", "claude"]).optional(),
    profile: z.string().min(1).max(4_096).optional(),
    model: z.string().min(1).max(256).optional(),
    contextSize: z.string().min(1).max(64).optional(),
  })
  .strict()
  .refine((value) => Object.values(value).some((entry) => entry !== undefined));
const sourceSession = z
  .object({
    backend: z
      .enum(["codex", "claude"])
      .describe("Backend that owns the deliberately selected source session."),
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
    "Compatible current session deliberately selected for independent primary and review forks of its complete context. Leave unset for a fresh start.",
  );
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
const runStartSchema = z
  .object({
    idempotencyKey,
    pipelineId: identifier,
    projectPath: z.string().min(1),
    projectConfigurationPath: z.string().min(1).optional(),
    taskPath: z.string().min(1),
    proactiveClarification: z.boolean().default(false),
    profile: z.string().min(1).max(4_096).optional(),
    model: z.string().min(1).max(256).optional(),
    contextSize: z.string().min(1).max(64).optional(),
    roleOverrides: z.record(identifier, roleOverride).default({}),
    sourceSession: sourceSession.nullable().default(null),
  })
  .strict();
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
    ...runInput
  } = input;
  return {
    ...runInput,
    executionOverrides: {
      ...(profile === undefined ? {} : { profile }),
      ...(model === undefined ? {} : { model }),
      ...(contextSize === undefined ? {} : { contextSize }),
    },
  };
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

function statusProjection({ directoryPath, run }) {
  const pipeline = getPipeline(run.pipelineId);
  const status = pipeline.projections.status(run);
  const clarification = pipeline.projections.clarification(run);
  const pause = pipeline.projections.pause(run);
  return {
    runId: run.runId,
    pipelineId: run.pipelineId,
    revision: run.revision,
    activityCursor: run.revision,
    status: run.pipelineState.workflowState,
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
    ["DONE", "FAILED"].includes(state) ||
    (state === "WAITING_FOR_USER" && run.pause?.inputResponse === undefined)
  );
}

function clarificationHash(run) {
  return getPipeline(run.pipelineId).projections.clarification(run).hash;
}

function delay(milliseconds, signal) {
  return new Promise((resolvePromise, rejectPromise) => {
    if (signal?.aborted) {
      rejectPromise(signal.reason ?? new DOMException("Aborted", "AbortError"));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      rejectPromise(signal.reason ?? new DOMException("Aborted", "AbortError"));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolvePromise();
    }, milliseconds);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
    }
  });
}

export function launchDetachedRun(runIdValue, action = null, options = {}) {
  return createDetachedLauncher()(runIdValue, action, options);
}

function detachedArguments(executablePath, runIdValue, action) {
  const args = [executablePath, "resume", "--run", runIdValue];
  if (action?.type === "extra-fix-rounds") {
    args.push("--extra-fix-rounds", String(action.amount));
  } else if (action?.type === "override-finding") {
    args.push("--override-finding", action.findingId);
  } else if (action !== null) {
    throw new Error("Detached resume action is invalid.");
  }
  return args;
}

export function createDetachedLauncher({
  spawnProcess = spawn,
  executablePath = EXECUTABLE_PATH,
  environment = process.env,
} = {}) {
  return (
    runIdValue,
    action = null,
    {
      expectedRuntimeCompatibility = RUNTIME_COMPATIBILITY_TOKEN,
      onExit,
    } = {},
  ) =>
    new Promise((resolvePromise, rejectPromise) => {
      if (expectedRuntimeCompatibility !== RUNTIME_COMPATIBILITY_TOKEN) {
        rejectPromise(
          new RunStoreError(
            "Detached continuation runtime does not match this launcher; " +
              "restart the Agent Runner MCP server and retry.",
            { code: "ERR_RUNTIME_VERSION_SKEW" },
          ),
        );
        return;
      }
      const child = spawnProcess(
        process.execPath,
        detachedArguments(executablePath, runIdValue, action),
        {
          detached: true,
          env: {
            ...environment,
            [DETACHED_RUNTIME_COMPATIBILITY_ENV]:
              expectedRuntimeCompatibility,
          },
          stdio: "ignore",
        },
      );
      child.once("error", rejectPromise);
      if (typeof onExit === "function") {
        child.once("exit", onExit);
      }
      child.once("spawn", () => {
        child.unref();
        resolvePromise(child.pid);
      });
    });
}

export function createMcpControlPlane(options = {}) {
  const runStore = options.runStore ?? createRunStore();
  const runner =
    options.runner ??
    createRunner({
      clarifications: createClarificationService({ interactive: false }),
      runStore,
    });
  const launchRun = options.launchRun ?? launchDetachedRun;
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
        loadRunnerConfiguration,
    });

  async function beginAction(input, signal) {
    while (true) {
      try {
        return await runStore.beginAction(input);
      } catch (cause) {
        if (cause?.code !== "ERR_MCP_ACTION_IN_PROGRESS") {
          throw cause;
        }
        await delay(RETRY_DELAY_MS, signal);
      }
    }
  }

  async function launchIfNeeded(
    runIdValue,
    baselineRevision,
    {
      action = null,
      allowWaiting = false,
      signal,
      waitForLease = false,
    } = {},
  ) {
    let dispatchedChildExitCode = null;
    let dispatchedChildExited = false;
    let dispatchStarted = false;
    while (true) {
      const run = (await runner.status(runIdValue)).run;
      if (
        ["DONE", "FAILED"].includes(run.pipelineState.workflowState) ||
        (!allowWaiting &&
          run.pipelineState.workflowState === "WAITING_FOR_USER") ||
        run.revision > baselineRevision
      ) {
        return;
      }
      if (dispatchedChildExitCode === RUNTIME_VERSION_SKEW_EXIT_CODE) {
        throw new RunStoreError(
          `Detached continuation for run ${run.runId} rejected an ` +
            "incompatible runtime; restart the Agent Runner MCP server " +
            "and retry this request with the same idempotency key.",
          { code: "ERR_RUNTIME_VERSION_SKEW" },
        );
      }
      if (dispatchedChildExited) {
        throw new RunStoreError(
          `Detached continuation for run ${run.runId} exited before the ` +
            "run advanced or acquired its execution lease; retry this MCP " +
            "request with the same idempotency key.",
          { code: "ERR_DETACHED_START_FAILED" },
        );
      }
      const runIsLeased = await runStore.runIsLeased(runIdValue);
      if (pipelineRequiresWorktreeLease(run.pipelineId)) {
        const worktreeLeaseOwner = await runStore.worktreeLeaseOwner(
          run.projectPath,
          run.runId,
        );
        if (
          worktreeLeaseOwner !== null &&
          worktreeLeaseOwner !== run.runId
        ) {
          throw new RunStoreError(
            `Run ${run.runId} is durable, but its Git worktree is already ` +
              "owned by another mutating run; retry this MCP request with " +
              "the same idempotency key after that run releases it.",
            { code: "ERR_WORKTREE_LEASED" },
          );
        }
        if (
          worktreeLeaseOwner === run.runId &&
          (!waitForLease || dispatchStarted)
        ) {
          return;
        }
        if (!runIsLeased && !dispatchStarted) {
          await launchRun(runIdValue, action, {
            expectedRuntimeCompatibility: RUNTIME_COMPATIBILITY_TOKEN,
            onExit(code) {
              dispatchedChildExited = true;
              dispatchedChildExitCode = code;
            },
          });
          dispatchStarted = true;
        }
        await delay(RETRY_DELAY_MS, signal);
        continue;
      }
      if (runIsLeased && (!waitForLease || dispatchStarted)) {
        return;
      }
      if (!runIsLeased && !dispatchStarted) {
        await launchRun(runIdValue, action, {
          expectedRuntimeCompatibility: RUNTIME_COMPATIBILITY_TOKEN,
          onExit(code) {
            dispatchedChildExited = true;
            dispatchedChildExitCode = code;
          },
        });
        dispatchStarted = true;
      }
      await delay(RETRY_DELAY_MS, signal);
    }
  }

  async function pipelinesList() {
    return {
      pipelines: listPipelines().map((pipeline) => ({
        id: pipeline.id,
        description: pipeline.description,
        roles: pipeline.roles,
        taskInputs: pipeline.taskInputs,
        runOptions: pipeline.runOptions,
        requiredRunOptions: pipeline.requiredRunOptions,
      })),
    };
  }

  async function runStart(input, { signal } = {}) {
    const identity = {
      key: input.idempotencyKey,
      tool: "run_start",
      arguments: actionArguments(input),
    };
    const existing = await runStore.readAction(identity);
    if (existing?.status === "completed") {
      return existing.result;
    }
    const boundary = await runner.validateBoundary({
      projectPath: input.projectPath,
      taskPath: input.taskPath,
    });
    const context = { runId: runIdFactory() };
    const action = await beginAction(
      {
        ...identity,
        context,
      },
      signal,
    );
    try {
      if (action.record.status === "completed") {
        return action.record.result;
      }
      const reservedRunId = action.record.context.runId;
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
          input.proactiveClarification
      ) {
        throw new Error("Reserved run does not match its MCP action intent.");
      }
      await launchIfNeeded(run.runId, run.revision, { signal });
      const receipt = { runId: run.runId };
      await action.complete(receipt);
      return receipt;
    } finally {
      await action.release();
    }
  }

  async function runStatus(input) {
    return statusProjection(await runner.status(input.runId));
  }

  async function runActivity(input) {
    const page = await runStore.readPublicActivity(input.runId, {
      afterRevision: input.cursor,
      limit: input.limit,
    });
    return { runId: input.runId, ...page };
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
        return { ...statusProjection(current), timedOut: false };
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return { ...statusProjection(current), timedOut: true };
      }
      const changed = await runStore.waitForRunChange(input.runId, {
        afterRevision: run.revision,
        timeoutMs: remaining,
        signal: context.signal,
      });
      if (changed.revision === run.revision && Date.now() >= deadline) {
        return { ...statusProjection(current), timedOut: true };
      }
    }
  }

  async function runRespond(input, { signal } = {}) {
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
    const action = await beginAction(
      {
        ...identity,
        context: {
          runId: input.runId,
          requestId: input.requestId,
          expectedRevision: input.expectedRevision,
          responseHash: null,
          submittedRevision: null,
        },
      },
      signal,
    );
    try {
      if (action.record.status === "completed") {
        return action.record.result;
      }
      let context = action.record.context;
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
        signal,
      });
      const receipt = { runId: input.runId, requestId: input.requestId };
      await action.complete(receipt);
      return receipt;
    } finally {
      await action.release();
    }
  }

  async function runResume(input, { signal } = {}) {
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
    const action = await beginAction(
      {
        ...identity,
        context: {
          runId: input.runId,
          expectedRevision: input.expectedRevision,
        },
      },
      signal,
    );
    try {
      if (action.record.status === "completed") {
        return action.record.result;
      }
      const run = (await runner.status(input.runId)).run;
      if (run.revision === input.expectedRevision) {
        getPipeline(run.pipelineId).validateResumeAction(run, input.action);
      } else if (action.created || run.revision < input.expectedRevision) {
        throw new Error("Resume request revision is stale.");
      }
      await launchIfNeeded(input.runId, input.expectedRevision, {
        action: input.action,
        allowWaiting: true,
        signal,
        waitForLease: true,
      });
      const receipt = { runId: input.runId };
      await action.complete(receipt);
      return receipt;
    } finally {
      await action.release();
    }
  }

  async function unexpectedIssueReport(input, { signal } = {}) {
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
    const action = await beginAction(
      {
        ...identity,
        context: {
          issuesPath: null,
          publicationPhase: null,
          projectPath: null,
          reportPath: null,
          temporaryPath: null,
        },
      },
      signal,
    );
    try {
      if (action.record.status === "completed") {
        return action.record.result;
      }
      const reportPath = await issueReporter.report(argumentsValue, {
        reservedIssuesPath: action.record.context.issuesPath,
        reservedPath: action.record.context.reportPath,
        reservedPublicationPhase:
          action.record.context.publicationPhase,
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
    pipelinesList,
    runActivity,
    runRespond,
    runResume,
    runStart,
    runStatus,
    runWait,
    unexpectedIssueReport,
  });
}

export function createMcpServer(options = {}) {
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
        : RUN_INSTRUCTIONS,
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
        "Start a durable pipeline. Leave sourceSession unset unless the user deliberately selects a compatible current session after being offered a fresh start. Primary and review roles fork its complete context independently and can spend provider quota twice, so recommend fresh for a long, multi-topic, or uncertain session. Include its known trusted profile, use only current inheritance when unknown, keep native IDs opaque, and never inspect private storage or infer an ID or alias.",
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
        "Wait once for user input, completion, failure, or timeout. Do not call at a fixed cadence; a timeout leaves the run available for a later explicit call.",
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
      result(await control.runRespond(input, { signal: context.mcpReq.signal })),
  );
  server.registerTool(
    "run_resume",
    {
      description:
        "Resume one persisted paused run with only an action valid for that pause.",
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
  const configuration =
    options.runnerConfiguration ??
    (await (options.loadConfiguration ?? loadRunnerConfiguration)());
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
