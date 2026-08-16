import { parseArgs } from "node:util";

import packageMetadata from "../package.json" with { type: "json" };
import { getPipeline, listPipelines } from "./pipeline-registry.js";

const COMMAND_OPTIONS = Object.freeze({
  resume: Object.freeze(["run", "extra-fix-rounds"]),
  status: Object.freeze(["run"]),
  pipelines: Object.freeze([]),
});
const COMMON_RUN_OPTIONS = Object.freeze(["clarify"]);
const REQUIRED_COMMAND_OPTIONS = Object.freeze({
  resume: Object.freeze(["run"]),
  status: Object.freeze(["run"]),
  pipelines: Object.freeze([]),
});

const COMMANDS = new Set(["run", ...Object.keys(COMMAND_OPTIONS)]);
const GLOBAL_OPTIONS = new Set(["help", "version"]);
const PIPELINES = listPipelines();
const PIPELINE_RUN_OPTIONS = new Set(
  PIPELINES.flatMap((pipeline) => pipeline.runOptions),
);

const OPTIONS = Object.freeze({
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
  run: { type: "string" },
  "extra-fix-rounds": { type: "string" },
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
  agent-run run <pipeline> --project <repo> --task <task-dir> [--clarify]
  agent-run resume --run <run-id>
  agent-run status --run <run-id>
  agent-run pipelines

Pipelines:
${PIPELINE_USAGE}

Options:
      --clarify  Open the clarification editor before agent questions
  -h, --help     Show this help
  -v, --version  Show version
`;

export async function main(
  args = process.argv.slice(2),
  { stdout = process.stdout, stderr = process.stderr } = {},
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

  let supportedOptions = COMMAND_OPTIONS[command];
  let requiredOptions = REQUIRED_COMMAND_OPTIONS[command];
  let commandLabel = command;

  if (command === "run") {
    const pipelineId = positionals[1];
    if (!pipelineId) {
      stderr.write(`Missing pipeline.\n\n${USAGE}`);
      return 1;
    }

    const pipeline = getPipeline(pipelineId);
    if (!pipeline) {
      stderr.write(`Unknown pipeline: ${pipelineId}\n\n${USAGE}`);
      return 1;
    }

    supportedOptions = [...COMMON_RUN_OPTIONS, ...pipeline.runOptions];
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
      .map((pipeline) => `${pipeline.id}\t${pipeline.description}`)
      .join("\n");
    stdout.write(`${output}\n`);
    return 0;
  }

  stderr.write(
    `The ${command} command is not implemented in the initial scaffold.\n`,
  );
  return 1;
}
