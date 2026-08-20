import { parseArgs } from "node:util";

import packageMetadata from "../package.json" with { type: "json" };
import { serveMcp } from "./mcp.js";
import { getPipeline, listPipelines } from "./pipeline-registry.js";
import { createRunner, parseSourceSession } from "./runner.js";

const COMMAND_OPTIONS = Object.freeze({
  resume: Object.freeze(["run", "extra-fix-rounds", "override-finding"]),
  status: Object.freeze(["run"]),
  pipelines: Object.freeze([]),
  mcp: Object.freeze([]),
});
const COMMON_RUN_OPTIONS = Object.freeze(["clarify", "fork-from"]);
const REQUIRED_COMMAND_OPTIONS = Object.freeze({
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
    ...pipeline.roles.map((role) => `${role}-model`),
  ]),
);

const OPTIONS = Object.freeze({
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
  run: { type: "string" },
  "extra-fix-rounds": { type: "string" },
  "override-finding": { type: "string" },
  "fork-from": { type: "string" },
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
  agent-run run <pipeline> --project <repo> --task <task-dir> [--clarify] [--fork-from <backend>:<session-id>]
  agent-run resume --run <run-id> [--extra-fix-rounds <count> | --override-finding <finding-id>]
  agent-run status --run <run-id>
  agent-run pipelines
  agent-run mcp

Pipelines:
${PIPELINE_USAGE}

Options:
      --clarify            Open the clarification editor before agent questions
      --fork-from          Fork primary and review roles from a backend session
      --<role>             Override a role backend
      --<role>-model       Override a role model
      --extra-fix-rounds   Grant a positive additional fix budget on resume
      --override-finding   Override one applicable open finding on resume
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

function runSummary({ directoryPath, run }) {
  const state = run.pipelineState;
  const pipeline = getPipeline(run.pipelineId);
  const status = pipeline.projections.status(run);
  const clarification = pipeline.projections.clarification(run);
  const lines = [
    `Run: ${run.runId}`,
    `Pipeline: ${run.pipelineId}`,
    `State: ${state.workflowState}`,
  ];
  if (status.currentStep !== null) {
    lines.push(`Step: ${status.currentStep}`);
  }
  if (run.pause?.reason !== undefined) {
    lines.push(`Pause: ${run.pause.reason}`);
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
  if (
    status.completedCommits.length > 0
  ) {
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

function roleOverrides(pipeline, values) {
  return Object.fromEntries(
    pipeline.roles.flatMap((role) => {
      const backend = values[role];
      const model = values[`${role}-model`];
      if (backend === undefined && model === undefined) {
        return [];
      }
      return [
        [
          role,
          {
            ...(backend === undefined ? {} : { backend }),
            ...(model === undefined ? {} : { model }),
          },
        ],
      ];
    }),
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
    startMcp = serveMcp,
  } = {},
) {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      strict: true,
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

  const maximumPositionals = command === "run" ? 2 : 1;
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
      ...pipeline.roles.map((role) => `${role}-model`),
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
    const output = PIPELINES
      .map((entry) => `${entry.id}\t${entry.description}`)
      .join("\n");
    stdout.write(`${output}\n`);
    return 0;
  }
  if (command === "mcp") {
    try {
      startMcp({ stderr });
      return 0;
    } catch {
      stderr.write("Agent Runner MCP failed to start.\n");
      return 1;
    }
  }

  try {
    const commandRunner =
      runner ??
      createRunner({
        onActivity(activity) {
          writeActivity(stdout, activity);
        },
      });
    if (command === "run") {
      const result = await commandRunner.run({
        pipelineId: pipeline.id,
        projectPath: values.project,
        taskPath: values.task,
        proactiveClarification: values.clarify ?? false,
        roleOverrides: roleOverrides(pipeline, values),
        sourceSession:
          values["fork-from"] === undefined
            ? null
            : parseSourceSession(values["fork-from"]),
      });
      stdout.write(runSummary(result));
      return workflowExitCode(result.run);
    }
    if (command === "resume") {
      const result = await commandRunner.resume({
        runId: values.run,
        action: resumeAction(values),
      });
      stdout.write(runSummary(result));
      return workflowExitCode(result.run);
    }
    const result = await commandRunner.status(values.run);
    stdout.write(runSummary(result));
    return 0;
  } catch (error) {
    stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}
