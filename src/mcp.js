import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

import packageMetadata from "../package.json" with { type: "json" };
import { createClarificationService } from "./clarifications.js";
import { getPipeline, listPipelines } from "./pipeline-registry.js";
import { createRunner } from "./runner.js";
import { createRunStore } from "./state.js";

const MAX_WAIT_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_WAIT_MS = 30_000;
const RETRY_DELAY_MS = 25;
const EXECUTABLE_PATH = fileURLToPath(
  new URL("../bin/agent-run.js", import.meta.url),
);

export const MCP_INSTRUCTIONS = `Use run_start to start a durable pipeline, then use one run_wait call for the desired waiting interval. Use run_activity only for explicit or historical reads; do not poll status, activity, or wait at a fixed cadence. When a compatible current native session ID is available, pass it to run_start by default so the pipeline forks its primary and review roles independently; omit it only for an explicit fresh start and never infer or fabricate an ID. Answer pending input from explicit user context when sufficient; otherwise ask the user. Never invent a material product decision.`;

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
    backend: z.enum(["codex", "claude"]),
    id: sessionReference,
    profile: z.string().min(1).max(4_096).optional(),
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
const runStartSchema = z
  .object({
    idempotencyKey,
    pipelineId: identifier,
    projectPath: z.string().min(1),
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
  return {
    runId: run.runId,
    pipelineId: run.pipelineId,
    revision: run.revision,
    activityCursor: run.revision,
    status: run.pipelineState.workflowState,
    currentStep: status.currentStep,
    pause: run.pause?.reason ?? null,
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

export function launchDetachedRun(runIdValue, action = null) {
  return createDetachedLauncher()(runIdValue, action);
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
  return (runIdValue, action = null) =>
    new Promise((resolvePromise, rejectPromise) => {
      const child = spawnProcess(
        process.execPath,
        detachedArguments(executablePath, runIdValue, action),
        {
          detached: true,
          env: environment,
          stdio: "ignore",
        },
      );
      child.once("error", rejectPromise);
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
      if (!(await runStore.runIsLeased(runIdValue))) {
        await launchRun(runIdValue, action);
        return;
      }
      if (!waitForLease) {
        return;
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
      await launchIfNeeded(run.runId, run.revision);
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
        return {
          ...statusProjection({
            directoryPath: await runStore.getRunDirectory(input.runId),
            run: changed,
          }),
          timedOut: true,
        };
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

  return Object.freeze({
    pipelinesList,
    runActivity,
    runRespond,
    runResume,
    runStart,
    runStatus,
    runWait,
  });
}

export function createMcpServer(options = {}) {
  const control = options.control ?? createMcpControlPlane(options);
  const server = new McpServer(
    { name: "agent-runner", version: packageMetadata.version },
    { instructions: MCP_INSTRUCTIONS },
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
        "Start a durable pipeline. Pass the controlling agent's compatible current native session by default when its ID is available so primary and review roles fork independently; use null only for an explicit fresh start and never invent an ID.",
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

  return server;
}

export function serveMcp(options = {}) {
  const stderr = options.stderr ?? process.stderr;
  const createServer = options.createServer ?? (() => createMcpServer(options));
  return serveStdio(createServer, {
    onerror(error) {
      const code =
        typeof error?.code === "string" && /^[A-Z0-9_]{1,64}$/u.test(error.code)
          ? error.code
          : "ERR_MCP_PROTOCOL";
      stderr.write(`Agent Runner MCP error: ${code}.\n`);
    },
  });
}
