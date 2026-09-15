import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";

import packageMetadata from "../package.json" with { type: "json" };
import { createGuidanceService } from "./guidance/index.js";
import { DETACHED_RUNTIME_COMPATIBILITY_ENV, serveMcp } from "./mcp/index.js";
import { getPipeline, listPipelines } from "./pipeline-registry.js";
import { createRunner, parseSourceSession } from "./runner/index.js";
import {
  projectOperatorStop,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
} from "./state/index.js";

const COMMAND_OPTIONS = Object.freeze({
  guidance: Object.freeze(["project", "project-config"]),
  pause: Object.freeze([
    "run",
    "expected-revision",
    "idempotency-key",
    "timing",
  ]),
  cancel: Object.freeze([
    "run",
    "expected-revision",
    "idempotency-key",
    "timing",
  ]),
  resume: Object.freeze(["run", "extra-fix-rounds", "override-finding"]),
  status: Object.freeze(["run"]),
  pipelines: Object.freeze([]),
  mcp: Object.freeze([]),
});
const COMMON_RUN_OPTIONS = Object.freeze([
  "clarify",
  "context-size",
  "fork-from",
  "fork-profile",
  "model",
  "profile",
  "project-config",
]);
const REQUIRED_COMMAND_OPTIONS = Object.freeze({
  guidance: Object.freeze(["project"]),
  pause: Object.freeze(["run"]),
  cancel: Object.freeze(["run"]),
  resume: Object.freeze(["run"]),
  status: Object.freeze(["run"]),
  pipelines: Object.freeze([]),
  mcp: Object.freeze([]),
});

const COMMANDS = new Set(["run", ...Object.keys(COMMAND_OPTIONS)]);
const GLOBAL_OPTIONS = new Set(["help", "version"]);
const PIPELINES = listPipelines();
const PIPELINE_RUN_OPTIONS = new Set(
  PIPELINES.flatMap((pipeline) => [
    ...pipeline.runOptions,
    ...pipeline.roles.map((role) => `${role}-context-size`),
    ...pipeline.roles.map((role) => `${role}-model`),
    ...pipeline.roles.map((role) => `${role}-profile`),
  ]),
);

const OPTIONS = Object.freeze({
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
  run: { type: "string" },
  "expected-revision": { type: "string" },
  "idempotency-key": { type: "string" },
  timing: { type: "string" },
  "extra-fix-rounds": { type: "string" },
  "override-finding": { type: "string" },
  "fork-from": { type: "string" },
  "fork-profile": { type: "string" },
  "context-size": { type: "string" },
  model: { type: "string" },
  profile: { type: "string" },
  "project-config": { type: "string" },
  ...Object.fromEntries(
    [...PIPELINE_RUN_OPTIONS].map((option) => [option, { type: "string" }]),
  ),
  clarify: { type: "boolean" },
});

const PIPELINE_USAGE = PIPELINES.map(
  (pipeline) => `  ${pipeline.id}  ${pipeline.description}`,
).join("\n");

const USAGE = `Agent Runner

Usage:
  agent-run run <pipeline> --project <repo> --task <task-dir> [--mode <independent|lazy|combined>] [--clarify] [--profile <alias>] [--fork-from <backend>:<session-id>]
  agent-run resume --run <run-id> [--extra-fix-rounds <count> | --override-finding <finding-id>]
  agent-run pause --run <run-id> [--timing immediate|after-current-commit] [--expected-revision <revision> --idempotency-key <key>]
  agent-run cancel --run <run-id> [--timing immediate|after-current-commit] [--expected-revision <revision> --idempotency-key <key>]
  agent-run status --run <run-id>
  agent-run guidance --project <repo> [--project-config <path>]
  agent-run guidance edit --project <repo> [--project-config <path>]
  agent-run pipelines
  agent-run mcp

Pipelines:
${PIPELINE_USAGE}

Options:
      --clarify            Open the clarification editor before agent questions
      --mode               Select a mode supported by the pipeline descriptor
                           independent is default and recommended for genuinely
                           independent review, but uses more context and tokens;
                           lazy is opt-in, uses less, and has no independent review;
                           combined adds primary convergence before independent review
                           and is available for all three pipelines
      --fork-from          Fork a compatible backend session into active roles
                           independent and combined fork primary and review roles separately;
                           lazy forks once into the primary role
      --fork-profile       Trusted profile alias used by the source session
      --profile            Set the run-wide trusted profile alias
      --project-config     Load an explicit ignored project configuration
      --model              Set the run-wide backend-native model
      --context-size       Set the run-wide decimal token context size
      --<role>             Override a role backend
      --<role>-profile     Override a role trusted profile alias
      --<role>-model       Override a role model
      --<role>-context-size Override a role decimal token context size
      --extra-fix-rounds   Grant a positive additional fix budget on resume
      --override-finding   Override one applicable open finding on resume
      --expected-revision  Bind an explicit pause or cancel request revision
      --idempotency-key    Bind an explicit pause or cancel retry identity
      --timing             immediate (default) or after-current-commit for pause/cancel
                           Deferred stops require a selected execution step; pauses,
                           failures, or interruptions settle without extra work
  -h, --help               Show this help
  -v, --version            Show version
`;

function writeActivity(stdout, activity) {
  const runReference =
    activity.actor === "runner" &&
    activity.phase === "run" &&
    activity.kind === "created"
      ? ` Run: ${activity.runId}.`
      : "";
  stdout.write(
    `[${activity.actor}/${activity.phase}] ${activity.message}${runReference}\n`,
  );
}

function shortFingerprint(value) {
  return typeof value === "string" ? value.slice(0, 12) : null;
}

function pauseActionLine(runId, action) {
  if (action.type === "respond") {
    return `  Respond to pending input ${action.requestId} through MCP, or edit the clarification artifact and resume.`;
  }
  if (action.type === "start-new-run") {
    if (action.requirement === "revised-plan") {
      return "  Revise the plan and start a fresh plan-execution run.";
    }
    if (action.requirement === "resolved-finalization-blockers") {
      return "  Resolve the reported finalization blockers, restore a clean baseline, prepare a plan for the remaining work, and start a fresh plan-execution run.";
    }
    return "  Abandon this run and start a fresh run from an uncontaminated worktree.";
  }
  if (action.action === null) {
    return `  Retry with: agent-run resume --run ${runId}`;
  }
  if (action.action.type === "extra-fix-rounds") {
    return `  Grant another fix round with: agent-run resume --run ${runId} --extra-fix-rounds ${action.action.amount}`;
  }
  return `  Override finding ${action.action.findingId} with: agent-run resume --run ${runId} --override-finding ${action.action.findingId}`;
}

function stopTimingLines(stop) {
  return [
    `Stop timing: ${stop.timing ?? "immediate"}`,
    `Effective stop timing: ${stop.effectiveTiming ?? "immediate"}`,
    ...(stop.targetStep == null
      ? []
      : [`Stop target step: ${stop.targetStep}`]),
  ];
}

function runSummary({ directoryPath, run }) {
  const state = run.pipelineState;
  const pipeline = getPipeline(run.pipelineId);
  const status = pipeline.projections.status(run);
  const clarification = pipeline.projections.clarification(run);
  const pause = pipeline.projections.pause(run);
  const lines = [
    `Run: ${run.runId}`,
    `Pipeline: ${run.pipelineId}`,
    `Mode: ${state.settings?.mode ?? pipeline.settings.mode.defaultValue}`,
    `State: ${state.workflowState}`,
  ];
  if (status.currentStep !== null) {
    lines.push(`Step: ${status.currentStep}`);
  }
  const stop = projectOperatorStop(run);
  if (stop !== null) {
    lines.push(
      `Stop ${stop.state === "settled" ? "settled" : "pending"}: ${stop.kind === "cancel_requested" ? "cancel" : "pause"}`,
      `Stop state: ${stop.state}`,
      ...stopTimingLines(stop),
    );
    if (stop.settlement !== null)
      lines.push(
        `Stop settlement: ${stop.settlement.kind}${stop.settlement.commit === null ? "" : ` ${stop.settlement.commit}`}`,
      );
  }
  if (pause !== null) {
    lines.push(`Pause: ${pause.reason}`);
    if (pause.code !== null) {
      lines.push(`Pause code: ${pause.code}`);
    }
    lines.push(`Explanation: ${pause.explanation}`);
    if (pause.evidence.length > 0) {
      lines.push("Evidence:");
      for (const entry of pause.evidence) {
        lines.push(`  ${entry}`);
      }
    }
    if (pause.resumeState !== null) {
      lines.push(`Resume state: ${pause.resumeState}`);
    }
    if (pause.nextActions.length > 0) {
      lines.push("Next actions:");
      for (const action of pause.nextActions) {
        lines.push(pauseActionLine(run.runId, action));
      }
    }
  }
  if (clarification.path !== null) {
    lines.push(`Clarifications: ${clarification.path}`);
  }
  if (status.planPath !== null) {
    lines.push(`Plan: ${status.planPath}`);
  }
  if (status.findings.length > 0) {
    lines.push("Open findings:");
    for (const finding of status.findings) {
      lines.push(`  ${finding.id}: ${finding.summary}`);
    }
  }
  if (status.stagnationDirection !== null) {
    lines.push(`Stagnation direction: ${status.stagnationDirection}`);
  }
  const finalized = shortFingerprint(status.finalizedFingerprint);
  const reviewed = shortFingerprint(status.reviewedFingerprint);
  if (finalized !== null) {
    lines.push(`Finalized fingerprint: ${finalized}`);
  }
  if (reviewed !== null) {
    lines.push(`Reviewed fingerprint: ${reviewed}`);
  }
  if (status.completedCommits.length > 0) {
    lines.push(
      `Commits: ${status.completedCommits.map(shortFingerprint).join(", ")}`,
    );
  }
  lines.push(`State directory: ${directoryPath}`);
  return `${lines.join("\n")}\n`;
}

function workflowExitCode(run) {
  if (run.pipelineState.workflowState === "WAITING_FOR_USER") {
    return 2;
  }
  return run.pipelineState.workflowState === "FAILED" ? 1 : 0;
}

function explicitStopIdentity(values) {
  const revision = values["expected-revision"];
  const key = values["idempotency-key"];
  if ((revision === undefined) !== (key === undefined)) {
    throw new Error(
      "Use --expected-revision and --idempotency-key together, or omit both.",
    );
  }
  if (revision === undefined) return null;
  if (!/^[1-9][0-9]*$/u.test(revision)) {
    throw new Error("--expected-revision must be a positive integer.");
  }
  const expectedRevision = Number(revision);
  if (!Number.isSafeInteger(expectedRevision)) {
    throw new Error("--expected-revision is too large.");
  }
  return { expectedRevision, idempotencyKey: key };
}

function roleOverrides(pipeline, values) {
  return Object.fromEntries(
    pipeline.roles.flatMap((role) => {
      const backend = values[role];
      const profile = values[`${role}-profile`];
      const model = values[`${role}-model`];
      const contextSize = values[`${role}-context-size`];
      if (
        backend === undefined &&
        profile === undefined &&
        model === undefined &&
        contextSize === undefined
      ) {
        return [];
      }
      return [
        [
          role,
          {
            ...(backend === undefined ? {} : { backend }),
            ...(profile === undefined ? {} : { profile }),
            ...(model === undefined ? {} : { model }),
            ...(contextSize === undefined ? {} : { contextSize }),
          },
        ],
      ];
    }),
  );
}

function executionOverrides(values) {
  return Object.freeze({
    ...(values.profile === undefined ? {} : { profile: values.profile }),
    ...(values.model === undefined ? {} : { model: values.model }),
    ...(values["context-size"] === undefined
      ? {}
      : { contextSize: values["context-size"] }),
  });
}

function settingOverrides(pipeline, values) {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(pipeline.settings).flatMap(([name, definition]) => {
        if (!pipeline.runOptions.includes(name) || values[name] === undefined) {
          return [];
        }
        if (!definition.validate(values[name])) {
          throw new Error(`--${name} ${definition.errorMessage}.`);
        }
        return [[name, values[name]]];
      }),
    ),
  );
}

function resumeAction(values) {
  const additionalRounds = values["extra-fix-rounds"];
  const findingId = values["override-finding"];
  if (additionalRounds !== undefined && findingId !== undefined) {
    throw new Error(
      "Use either --extra-fix-rounds or --override-finding, not both.",
    );
  }
  if (additionalRounds !== undefined) {
    if (!/^[1-9][0-9]*$/u.test(additionalRounds)) {
      throw new Error("--extra-fix-rounds must be a positive integer.");
    }
    const amount = Number(additionalRounds);
    if (!Number.isSafeInteger(amount)) {
      throw new Error("--extra-fix-rounds is too large.");
    }
    return Object.freeze({ type: "extra-fix-rounds", amount });
  }
  return findingId === undefined
    ? null
    : Object.freeze({ type: "override-finding", findingId });
}

export async function main(
  args = process.argv.slice(2),
  {
    stdout = process.stdout,
    stderr = process.stderr,
    runner,
    createCommandRunner = createRunner,
    guidance,
    createCommandGuidance = createGuidanceService,
    startMcp = serveMcp,
    environment = process.env,
    idempotencyKeyFactory = randomUUID,
  } = {},
) {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      strict: true,
      tokens: true,
      options: OPTIONS,
    });
  } catch (error) {
    if (
      error instanceof Error &&
      typeof error.code === "string" &&
      error.code.startsWith("ERR_PARSE_ARGS")
    ) {
      stderr.write(`${error.message}\n\n${USAGE}`);
      return 1;
    }

    throw error;
  }

  const { values, positionals } = parsed;

  if (values.version) {
    stdout.write(`${packageMetadata.version}\n`);
    return 0;
  }

  if (values.help || args.length === 0) {
    stdout.write(USAGE);
    return 0;
  }

  if (positionals.length === 0) {
    stderr.write(`Missing command.\n\n${USAGE}`);
    return 1;
  }

  const [command] = positionals;
  if (!COMMANDS.has(command)) {
    stderr.write(`Unknown command: ${command}\n\n${USAGE}`);
    return 1;
  }

  const maximumPositionals = ["run", "guidance"].includes(command) ? 2 : 1;
  if (positionals.length > maximumPositionals) {
    stderr.write(
      `Unexpected argument: ${positionals[maximumPositionals]}\n\n${USAGE}`,
    );
    return 1;
  }

  let pipeline;
  let supportedOptions = COMMAND_OPTIONS[command];
  let requiredOptions = REQUIRED_COMMAND_OPTIONS[command];
  let commandLabel = command;

  if (command === "guidance") {
    if (positionals[1] !== undefined && positionals[1] !== "edit") {
      stderr.write(`Unknown guidance action: ${positionals[1]}\n\n${USAGE}`);
      return 1;
    }
    const seen = new Set();
    for (const token of parsed.tokens.filter(
      (token) => token.kind === "option",
    )) {
      if (seen.has(token.name)) {
        stderr.write(`Option '--${token.name}' may be supplied only once.\n`);
        return 1;
      }
      seen.add(token.name);
    }
  }

  if (command === "run") {
    const pipelineId = positionals[1];
    if (!pipelineId) {
      stderr.write(`Missing pipeline.\n\n${USAGE}`);
      return 1;
    }

    pipeline = getPipeline(pipelineId);
    if (!pipeline) {
      stderr.write(`Unknown pipeline: ${pipelineId}\n\n${USAGE}`);
      return 1;
    }

    supportedOptions = [
      ...COMMON_RUN_OPTIONS,
      ...pipeline.runOptions,
      ...pipeline.roles.map((role) => `${role}-context-size`),
      ...pipeline.roles.map((role) => `${role}-model`),
      ...pipeline.roles.map((role) => `${role}-profile`),
    ];
    requiredOptions = pipeline.requiredRunOptions;
    commandLabel = `${command} ${pipelineId}`;
  }

  const unsupportedOption = Object.keys(values).find(
    (option) =>
      !GLOBAL_OPTIONS.has(option) && !supportedOptions.includes(option),
  );
  if (unsupportedOption) {
    stderr.write(
      `Option '--${unsupportedOption}' is not valid for ${commandLabel}.\n\n${USAGE}`,
    );
    return 1;
  }

  const missingOption = requiredOptions.find(
    (option) => values[option] === undefined,
  );
  if (missingOption) {
    stderr.write(
      `Missing required option '--${missingOption}' for ${commandLabel}.\n\n${USAGE}`,
    );
    return 1;
  }

  if (command === "pipelines") {
    const output = PIPELINES.map(
      (entry) =>
        `${entry.id}\t${entry.description}\n  Settings (defaults): ${Object.entries(
          entry.settings,
        )
          .map(
            ([name, definition]) =>
              `${name}=${JSON.stringify(definition.defaultValue)}`,
          )
          .join(", ")}`,
    ).join("\n");
    stdout.write(`${output}\n`);
    return 0;
  }
  if (command === "mcp") {
    try {
      await startMcp({ stderr });
      return 0;
    } catch {
      stderr.write("Agent Runner MCP failed to start.\n");
      return 1;
    }
  }

  try {
    if (command === "guidance") {
      const service = guidance ?? createCommandGuidance({ env: environment });
      const input = {
        projectPath: values.project,
        ...(values["project-config"] === undefined
          ? {}
          : { projectConfigurationPath: values["project-config"] }),
      };
      if (positionals[1] === "edit") {
        const receipt = await service.edit(input);
        stdout.write(
          receipt.updated
            ? "Local guidance updated.\n"
            : "Local guidance unchanged.\n",
        );
      } else {
        const { combinedContent } = await service.read(input);
        stdout.write(
          combinedContent.endsWith("\n")
            ? combinedContent
            : `${combinedContent}\n`,
        );
      }
      return 0;
    }
    const commandRunner =
      runner ??
      createCommandRunner({
        onActivity(activity) {
          writeActivity(stdout, activity);
        },
      });
    if (command === "run") {
      if (
        values["fork-profile"] !== undefined &&
        values["fork-from"] === undefined
      ) {
        throw new Error("--fork-profile requires --fork-from.");
      }
      const parsedSource =
        values["fork-from"] === undefined
          ? null
          : parseSourceSession(values["fork-from"]);
      const result = await commandRunner.run({
        pipelineId: pipeline.id,
        projectPath: values.project,
        taskPath: values.task,
        proactiveClarification: values.clarify ?? false,
        projectConfigurationPath: values["project-config"],
        roleOverrides: roleOverrides(pipeline, values),
        executionOverrides: executionOverrides(values),
        settingOverrides: settingOverrides(pipeline, values),
        sourceSession:
          parsedSource === null
            ? null
            : {
                ...parsedSource,
                ...(values["fork-profile"] === undefined
                  ? {}
                  : { profile: values["fork-profile"] }),
              },
      });
      stdout.write(runSummary(result));
      return workflowExitCode(result.run);
    }
    if (command === "resume") {
      const result = await commandRunner.resume({
        runId: values.run,
        action: resumeAction(values),
        ...(environment[DETACHED_RUNTIME_COMPATIBILITY_ENV] === undefined
          ? {}
          : {
              expectedRuntimeCompatibility:
                environment[DETACHED_RUNTIME_COMPATIBILITY_ENV],
            }),
      });
      stdout.write(runSummary(result));
      return workflowExitCode(result.run);
    }
    if (["pause", "cancel"].includes(command)) {
      if (
        values.timing !== undefined &&
        !["immediate", "after-current-commit"].includes(values.timing)
      ) {
        throw new Error("--timing must be immediate or after-current-commit.");
      }
      const explicit = explicitStopIdentity(values);
      const identity = explicit ?? {
        expectedRevision: (await commandRunner.status(values.run)).run.revision,
        idempotencyKey: idempotencyKeyFactory(),
      };
      const receipt = await commandRunner.requestOperatorStop({
        runId: values.run,
        kind: command === "pause" ? "pause_requested" : "cancel_requested",
        ...identity,
        ...(values.timing === undefined ? {} : { timing: values.timing }),
      });
      stdout.write(
        `${command === "pause" ? "Pause" : "Cancellation"} requested for run ${receipt.runId} at revision ${receipt.revision}.\n`,
      );
      stdout.write(
        `${stopTimingLines({
          ...receipt,
          targetStep: receipt.targetBoundary?.step ?? null,
        }).join("\n")}\n`,
      );
      return 0;
    }
    const result = await commandRunner.status(values.run);
    stdout.write(runSummary(result));
    return 0;
  } catch (error) {
    stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return error?.code === "ERR_RUNTIME_VERSION_SKEW"
      ? RUNTIME_VERSION_SKEW_EXIT_CODE
      : 1;
  }
}
