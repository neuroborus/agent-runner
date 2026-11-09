import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";

import packageMetadata from "../package.json" with { type: "json" };
import { migrateRunnerConfiguration } from "./config/index.js";
import { createGuidanceService } from "./guidance/index.js";
import { createIssueService } from "./issues/index.js";
import {
  awaitDetachedDispatch,
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  DETACHED_STOP_CHECKPOINT_ENV,
  serveMcp,
} from "./mcp/index.js";
import { getPipeline, listPipelines } from "./pipeline-registry.js";
import { createRunner, parseSourceSession } from "./runner/index.js";
import { createRuntimeAdmission } from "./runtime/index.js";
import { createUpdateService, isUpdateVersion } from "./update/index.js";
import {
  createRunStore,
  projectAvailabilityRetry,
  projectInactivityRecovery,
  projectLaunchRecovery,
  projectOperatorStop,
  projectObservations,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  recoveryFailureDetails,
} from "./state/index.js";

const COMMAND_OPTIONS = Object.freeze({
  config: Object.freeze(["from"]),
  update: Object.freeze(["check", "release", "idempotency-key"]),
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
  resume: Object.freeze([
    "run",
    "extra-fix-rounds",
    "override-finding",
    "expected-revision",
  ]),
  status: Object.freeze(["run"]),
  pipelines: Object.freeze([]),
  mcp: Object.freeze([]),
});
const COMMON_RUN_OPTIONS = Object.freeze([
  "clarify",
  "context-size",
  "effort",
  "fork-from",
  "fork-profile",
  "model",
  "profile",
  "project-config",
]);
const REQUIRED_COMMAND_OPTIONS = Object.freeze({
  update: Object.freeze([]),
  config: Object.freeze(["from"]),
  guidance: Object.freeze(["project"]),
  pause: Object.freeze(["run"]),
  cancel: Object.freeze(["run"]),
  resume: Object.freeze(["run"]),
  status: Object.freeze(["run"]),
  pipelines: Object.freeze([]),
  mcp: Object.freeze([]),
});

// Issue management is a thin projection; deliberate creation stays MCP-only.
const ISSUE_ACTIONS = Object.freeze({
  list: Object.freeze({
    options: Object.freeze(["origin", "status", "limit", "cursor"]),
    required: Object.freeze([]),
  }),
  read: Object.freeze({
    options: Object.freeze(["issue"]),
    required: Object.freeze(["issue"]),
  }),
  update: Object.freeze({
    options: Object.freeze([
      "issue",
      "expected-revision",
      "expected-hash",
      "idempotency-key",
      "status",
      "plan-reference",
      "clear-plan-references",
      "commit-reference",
      "clear-commit-references",
      "note",
      "clear-note",
    ]),
    required: Object.freeze(["issue", "expected-revision", "expected-hash"]),
  }),
});

const COMMANDS = new Set(["run", "issues", ...Object.keys(COMMAND_OPTIONS)]);
const GLOBAL_OPTIONS = new Set(["help", "version"]);
const PIPELINES = listPipelines();
const PIPELINE_RUN_OPTIONS = new Set(
  PIPELINES.flatMap((pipeline) => [
    ...pipeline.runOptions,
    ...pipeline.roles.map((role) => `${role}-context-size`),
    ...pipeline.roles.map((role) => `${role}-effort`),
    ...pipeline.roles.map((role) => `${role}-model`),
    ...pipeline.roles.map((role) => `${role}-profile`),
  ]),
);

const OPTIONS = Object.freeze({
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
  from: { type: "string" },
  check: { type: "boolean" },
  release: { type: "string" },
  run: { type: "string" },
  "expected-revision": { type: "string" },
  "idempotency-key": { type: "string" },
  timing: { type: "string" },
  "extra-fix-rounds": { type: "string" },
  "override-finding": { type: "string" },
  "fork-from": { type: "string" },
  "fork-profile": { type: "string" },
  "context-size": { type: "string" },
  effort: { type: "string" },
  model: { type: "string" },
  profile: { type: "string" },
  "project-config": { type: "string" },
  origin: { type: "string" },
  status: { type: "string", multiple: true },
  limit: { type: "string" },
  cursor: { type: "string" },
  issue: { type: "string" },
  "expected-hash": { type: "string" },
  "plan-reference": { type: "string", multiple: true },
  "clear-plan-references": { type: "boolean" },
  "commit-reference": { type: "string", multiple: true },
  "clear-commit-references": { type: "boolean" },
  note: { type: "string" },
  "clear-note": { type: "boolean" },
  ...Object.fromEntries(
    [...PIPELINE_RUN_OPTIONS].map((option) => [option, { type: "string" }]),
  ),
  ...Object.fromEntries(
    PIPELINES.flatMap((pipeline) =>
      Object.entries(pipeline.settings).flatMap(([, definition]) =>
        definition.option
          ? [
              [
                definition.option,
                {
                  type: "string",
                  ...(definition.multiple ? { multiple: true } : {}),
                },
              ],
            ]
          : [],
      ),
    ),
  ),
  clarify: { type: "boolean" },
});

const PIPELINE_USAGE = PIPELINES.map(
  (pipeline) => `  ${pipeline.id}  ${pipeline.description}`,
).join("\n");

const USAGE = `Agent Runner

Usage:
  agent-run run <pipeline> --project <workspace> --task <task-dir> [--mode <independent|lazy|combined>] [--clarify] [--profile <alias>] [--fork-from <backend>:<session-id>]
  agent-run resume --run <run-id> [--expected-revision <revision>] [--extra-fix-rounds <count> | --override-finding <finding-id>]
  agent-run pause --run <run-id> [--timing immediate|after-current-commit] [--expected-revision <revision> --idempotency-key <key>]
  agent-run cancel --run <run-id> [--timing immediate|after-current-commit] [--expected-revision <revision> --idempotency-key <key>]
  agent-run status --run <run-id>
  agent-run guidance --project <directory> [--project-config <path>]
  agent-run guidance edit --project <directory> [--project-config <path>]
  agent-run config migrate --from <legacy-file>
  agent-run update [--check] [--release <exact-version>] [--idempotency-key <key>]
  agent-run issues list [--origin <recorded-path>] [--status <status>]... [--limit <count>] [--cursor <cursor>]
  agent-run issues read --issue <issue-id>
  agent-run issues update --issue <issue-id> --expected-revision <revision> --expected-hash <hash> [--status <status>] [--plan-reference <text>]... [--commit-reference <text>]... [--note <markdown>] [--clear-plan-references] [--clear-commit-references] [--clear-note] [--idempotency-key <key>]
  agent-run pipelines
  agent-run mcp

Pipelines:
${PIPELINE_USAGE}

Options:
      --check              Check the approved official release without installing
      --release            Select an exact version, required for prereleases
                           update apply is managing-operator-only; never restarts clients
      --from               Validate and copy legacy settings to the user location
                           Only an absent destination is created; conflicts fail
      --plan-kind          Select commit (default) or custom authoring/execution
      --criteria           Read user criteria from a local Markdown file
      --source             Declare a source path or reference (repeatable; no retrieval)
      --output             Declare an intended output path (repeatable; no authoring writes)
      --clarify            Open the clarification editor before agent questions
      --mode               Select a mode supported by the pipeline descriptor
                           independent is default and recommended for genuinely
                           independent review, but uses more context and tokens;
                           lazy is opt-in, uses less, and has no independent review;
                           combined adds primary convergence before independent review
                           and is available for all registered pipelines;
                           audit uses separate discovery and finding recheck cycles
      --source-scope       Audit sources: directory (default) or git
      --exclude-path       Literal directory-scope subtree to exclude; repeatable
      --placement          Init placement: integrated or external; separate from mode
      --fork-from          Fork a compatible backend session into active roles
                           independent and combined fork primary and review roles separately;
                           lazy forks once into the primary role
      --fork-profile       Trusted profile alias used by the source session
      --profile            Set the run-wide trusted profile alias
      --project-config     Select integrated or target-bound external configuration
      --model              Set the run-wide backend-native model
      --effort             Set run-wide effort: current|low|medium|high|xhigh|max
                           current retains the provider default
      --context-size       Set the run-wide decimal token context size
      --<role>             Override a role backend
      --<role>-profile     Override a role trusted profile alias
      --<role>-model       Override a role model
      --<role>-effort      Override a role effort (same portable values)
      --<role>-context-size Override a role decimal token context size
      --extra-fix-rounds   Grant a positive additional fix budget on resume
      --override-finding   Override one applicable open finding on resume
      --expected-revision  Bind a resume, pause, cancel, or issues update revision
      --expected-hash      Bind an issues update to the inspected documentHash
      --idempotency-key    Bind an explicit pause, cancel, update, or issues update retry identity
      --origin             Filter issues by exact recorded origin path; never inspected
      --status             Filter issues by status (repeatable), or set one on update:
                           open|queued|in_progress|resolved|dismissed
      --limit              Issue page size from 1 to 100 (default 50)
      --cursor             Continue an issue list from its opaque nextCursor
      --issue              Select one issue ID from the global issue store
      --plan-reference     Replace plan references (repeatable; never retrieved)
      --commit-reference   Replace resolving commit references (repeatable; never retrieved)
      --note               Replace the concise disposition note
      --clear-plan-references, --clear-commit-references, --clear-note
                           Clear that optional tracking metadata
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
  if (runReference && activity.workspacePreparation != null)
    stdout.write(
      `Workspace preparation pending. Observe with: agent-run status --run ${activity.runId}\n` +
        `Pause with: agent-run pause --run ${activity.runId}; cancel with: agent-run cancel --run ${activity.runId}\n`,
    );
}

function refinementProgressLines(progress) {
  if (progress == null) return [];
  const line = (text) => text.replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, " ");
  return [
    `Plan progress: ${progress.artifactPath}`,
    `Effective revision: ${progress.effectiveRevision}; advisory planning target: ${progress.preferredCommitLineLimit}; execution assessment threshold: >${progress.threshold}`,
    ...progress.originalSteps.flatMap((entry) => [
      `Original step ${entry.originalStep}: ${entry.subject}; ${entry.status}${entry.refinement ? `; refinement ${entry.refinement}` : ""}${entry.head ? `; verified SHA: ${entry.head}` : ""}`,
      ...(entry.measurement
        ? [
            `  Measured: ${entry.measurement.changedLines} changed text lines; ${entry.measurement.binaryFiles} binary files; ${entry.measurement.gitlinks} gitlinks; decision: ${entry.decision ?? "pending"}`,
            `  Reason: ${line(entry.reason ?? "No size decision recorded")}`,
          ]
        : []),
      ...entry.replacements.map(
        (replacement) =>
          `  ${replacement.label} (effective Commit ${replacement.step}): ${replacement.subject}; ${replacement.status}; verified SHA: ${replacement.head ?? "pending"}`,
      ),
      ...entry.proposedReplacements.map(
        (replacement) =>
          `  Proposed ${replacement.label}: ${replacement.subject}; pending; verified SHA: pending`,
      ),
    ]),
  ];
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
    if (action.requirement === "resolved-finalization-guidance") {
      return "  Repair the reported finalization guidance and start a fresh plan-execution run.";
    }
    if (action.requirement === "resolved-commit-readiness") {
      return "  Preserve the reviewed candidate and resolve readiness through separately authorized follow-up before starting a fresh run. This run cannot retry COMMIT.";
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
  if (run.workspacePreparation != null)
    lines.push("Workspace preparation: pending");
  if (status.auditSource) {
    lines.push(`Audit source scope: ${status.auditSource.sourceScope}`);
    for (const path of status.auditSource.excludePaths)
      lines.push(`Excluded path: ${path}`);
  }
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
  const launchRecovery = projectLaunchRecovery(run);
  const inactivity = projectInactivityRecovery(run);
  if (inactivity !== null)
    lines.push(
      `Provider ${inactivity.expiryProven === false ? "reconstruction" : "inactivity"}: ${inactivity.role} ${inactivity.checkpoint}; ${inactivity.status}; attempt ${inactivity.attempt} of 2`,
    );
  const retry = projectAvailabilityRetry(run);
  const observations = projectObservations(run);
  if (observations !== null) {
    const latest = observations.attempts.at(-1);
    const known = (value) => value ?? "unknown";
    const measured = latest.measurements;
    lines.push(
      `Observations: attempt ${latest.id}; ${latest.role} ${latest.checkpoint}; ${latest.status}; accounting ${latest.accounting}; omitted attempts ${observations.omittedAttempts}`,
      `Supplied context bytes: prompt ${known(measured?.promptBytes)}; reconstruction prompt ${known(measured?.recoveryPromptBytes)}; schema ${known(measured?.schemaBytes)}`,
      `Result bytes: output ${known(measured?.resultBytes)}; structured JSON ${known(measured?.structuredResultBytes)}; referenced file bytes/count unknown`,
    );
    for (const value of latest.observations) {
      lines.push(
        `  Native attempt ${value.attempt} turn ${value.turn} (${value.kind}): ${value.outcome}; accounting ${value.accounting}; commands ${value.commandCompletions}; compactions ${value.compactions}; facts incomplete ${value.factsIncomplete}`,
        `  Tokens (last request / cumulative ${value.cumulativeScope}): input ${known(value.last?.inputTokens)}/${known(value.cumulative?.inputTokens)}; output ${known(value.last?.outputTokens)}/${known(value.cumulative?.outputTokens)}; context capacity ${known(value.contextCapacity)}`,
      );
    }
  }
  if (retry !== null) {
    lines.push(
      `Availability retry: ${retry.role} ${retry.checkpoint}; ${retry.reason}; attempt ${retry.attempt}; delay ${retry.delayMs}ms; deadline ${retry.nextRetryAt}`,
    );
  }
  if (launchRecovery !== null) {
    lines.push(
      `Launch recovery: ${launchRecovery.checkpoint} (${launchRecovery.failureClass})`,
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
  if (status.auditReport) {
    lines.push(
      `Audit report: ${status.auditReport.path} (${status.auditReport.status})`,
      `Audit findings: ${status.auditReport.confirmedFindings} confirmed; ${status.auditReport.pendingCandidates} pending (unverified)`,
    );
  }
  if (status.setup) {
    lines.push(
      `Setup: ${status.setup.placement}`,
      `Target: ${status.setup.projectPath}`,
      `Project configuration: ${status.setup.configurationPath}`,
      `Artifacts: ${status.setup.artifactPath}`,
      `Working directory: ${status.setup.workingDirectory}`,
      "Configured checks:",
      ...status.setup.checks.map((command) => `  ${command}`),
      "Resources:",
      ...status.setup.resources.map(
        ({ path, status }) => `  ${status}: ${path}`,
      ),
    );
  }
  lines.push(...refinementProgressLines(status.refinementProgress));
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
  if (status.planKind === "custom") {
    lines.push(`Accepted steps: ${status.acceptedSteps.length}`);
    for (const { step, receipt, result } of status.acceptedSteps) {
      lines.push(
        `Step ${step} receipt: ${shortFingerprint(receipt)}`,
        result.analysis,
      );
    }
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
  return {
    expectedRevision: parseExpectedRevision(revision),
    idempotencyKey: key,
  };
}

function positiveInteger(value, option) {
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new Error(`--${option} must be a positive integer.`);
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    throw new Error(`--${option} is too large.`);
  }
  return number;
}

function parseExpectedRevision(revision) {
  return positiveInteger(revision, "expected-revision");
}

function issueListInput(values) {
  return {
    ...(values.origin === undefined ? {} : { projectPath: values.origin }),
    ...(values.status === undefined ? {} : { statuses: values.status }),
    ...(values.limit === undefined
      ? {}
      : { limit: positiveInteger(values.limit, "limit") }),
    ...(values.cursor === undefined ? {} : { cursor: values.cursor }),
  };
}

// Omitted fields stay unchanged; explicit clear flags map to MCP's empty
// arrays and null so both projections share one tracking contract.
function issueUpdateInput(values, idempotencyKey) {
  if (values.status?.length > 1) {
    throw new Error("--status may be supplied only once for issues update.");
  }
  const changes = {};
  for (const [option, clear, field, cleared] of [
    ["plan-reference", "clear-plan-references", "planReferences", []],
    ["commit-reference", "clear-commit-references", "commitReferences", []],
    ["note", "clear-note", "note", null],
  ]) {
    if (values[option] !== undefined && values[clear]) {
      throw new Error(`Use either --${option} or --${clear}, not both.`);
    }
    if (values[clear]) changes[field] = cleared;
    else if (values[option] !== undefined) changes[field] = values[option];
  }
  return {
    idempotencyKey,
    issueId: values.issue,
    expectedRevision: parseExpectedRevision(values["expected-revision"]),
    expectedHash: values["expected-hash"],
    ...(values.status === undefined ? {} : { status: values.status[0] }),
    ...changes,
  };
}

function effortSelection(value, option) {
  if (
    value !== undefined &&
    !["current", "low", "medium", "high", "xhigh", "max"].includes(value)
  ) {
    throw new Error(
      `--${option} must be current, low, medium, high, xhigh, or max.`,
    );
  }
  return value;
}

function roleOverrides(pipeline, values) {
  return Object.fromEntries(
    pipeline.roles.flatMap((role) => {
      const backend = values[role];
      const profile = values[`${role}-profile`];
      const model = values[`${role}-model`];
      const contextSize = values[`${role}-context-size`];
      const effort = effortSelection(
        values[`${role}-effort`],
        `${role}-effort`,
      );
      if (
        backend === undefined &&
        profile === undefined &&
        model === undefined &&
        contextSize === undefined &&
        effort === undefined
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
            ...(effort === undefined ? {} : { effort }),
          },
        ],
      ];
    }),
  );
}

function executionOverrides(values) {
  const effort = effortSelection(values.effort, "effort");
  return Object.freeze({
    ...(effort === undefined ? {} : { effort }),
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
        const option = definition.option ?? name;
        if (
          !pipeline.runOptions.includes(option) ||
          values[option] === undefined
        ) {
          return [];
        }
        if (!definition.validate(values[option])) {
          throw new Error(`--${option} ${definition.errorMessage}.`);
        }
        return [[name, values[option]]];
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

function detachedStopCheckpoint(environment) {
  const value = environment[DETACHED_STOP_CHECKPOINT_ENV];
  if (value === undefined) return undefined;
  if (
    environment[DETACHED_RUNTIME_COMPATIBILITY_ENV] === undefined ||
    !/^[1-9][0-9]*$/u.test(value) ||
    !Number.isSafeInteger(Number(value))
  ) {
    throw new Error("Detached stop checkpoint is invalid.");
  }
  return Number(value);
}

export async function main(args = process.argv.slice(2), options = {}) {
  let parsed;
  try {
    parsed = parseCommand(args);
  } catch {
    return runCommand(args, options);
  }
  const admission =
    options.runtimeAdmission ??
    createRuntimeAdmission({ runStore: createRunStore() });
  try {
    return await admission.withAdmission(
      parsed.positionals[0] === "mcp" ? "mcp" : "cli",
      () => runCommand(args, options, parsed),
      async () =>
        [parsed.values.project, parsed.values.task].filter(
          (path) => typeof path === "string",
        ),
    );
  } catch (error) {
    if (
      typeof error?.code !== "string" ||
      !error.code.startsWith("ERR_RUNTIME_")
    )
      throw error;
    (options.stderr ?? process.stderr).write(
      `${runtimeDiagnostic(error.code)}\n`,
    );
    return 1;
  }
}

// Closed code-to-fixed-text map: unrecognized codes, messages, causes and other
// properties are never projected. The outer catch cannot know which effects
// already happened, so no line attributes a stage or certifies their absence.
const RUNTIME_DIAGNOSTICS = new Map([
  [
    "ERR_RUNTIME_RESTART_REQUIRED",
    "The runtime selection does not admit this process's payload now; another payload is selected or activation is deferred while associated users remain. If this installation is obsolete, start a new process from the selected installation; otherwise retry later.",
  ],
  [
    "ERR_RUNTIME_OWNER_UNVERIFIABLE",
    "A runtime owner, possibly this process, could not be verified; no ownership was taken over. Check that process identity is available before retrying.",
  ],
  [
    "ERR_RUNTIME_RECONCILIATION_REQUIRED",
    "An earlier runtime operation was interrupted and its recorded intent could not be reconciled with the current runtime state. Inspect runtime state before retrying.",
  ],
  [
    "ERR_RUNTIME_PAYLOAD",
    "The pinned application payload or Node identity is invalid or changed. Start a new process from a verified installation.",
  ],
  [
    "ERR_RUNTIME_SELECTION_VERSION",
    "The runtime selection version is unsupported. Use a compatible installation.",
  ],
  ["ERR_RUNTIME_VERSION_SKEW", "The runtime is incompatible."],
  ["ERR_RUNTIME_MIGRATION_REQUIRED", "The run requires a runtime migration."],
  [
    "ERR_RUNTIME_ADMISSION",
    "Runtime admission or retirement state could not be verified; the specific cause is unavailable.",
  ],
]);

function runtimeDiagnostic(code) {
  const explanation = RUNTIME_DIAGNOSTICS.get(code);
  return explanation === undefined
    ? "Runtime verification failed (unrecognized): the specific cause is unavailable."
    : `Runtime verification failed (${code}): ${explanation}`;
}

function parseCommand(args) {
  return parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    tokens: true,
    options: OPTIONS,
  });
}

async function runCommand(
  args = process.argv.slice(2),
  {
    stdout = process.stdout,
    stderr = process.stderr,
    runner,
    createCommandRunner = createRunner,
    createCommandRunStore = createRunStore,
    guidance,
    createCommandGuidance = createGuidanceService,
    issues,
    createCommandIssues = createIssueService,
    migrateConfiguration = migrateRunnerConfiguration,
    updateService,
    createCommandUpdate = createUpdateService,
    startMcp = serveMcp,
    environment = process.env,
    idempotencyKeyFactory = randomUUID,
  } = {},
  previouslyParsed,
) {
  let parsed;
  try {
    parsed = previouslyParsed ?? parseCommand(args);
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

  const maximumPositionals = ["run", "guidance", "config", "issues"].includes(
    command,
  )
    ? 2
    : 1;
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

  if (command === "config" && positionals[1] !== "migrate") {
    stderr.write(`Expected config migrate.\n\n${USAGE}`);
    return 1;
  }

  if (command === "issues" && !Object.hasOwn(ISSUE_ACTIONS, positionals[1])) {
    stderr.write(`Expected issues list, read, or update.\n\n${USAGE}`);
    return 1;
  }

  if (["guidance", "config", "update", "issues"].includes(command)) {
    if (
      command === "guidance" &&
      positionals[1] !== undefined &&
      positionals[1] !== "edit"
    ) {
      stderr.write(`Unknown guidance action: ${positionals[1]}\n\n${USAGE}`);
      return 1;
    }
    const seen = new Set();
    for (const token of parsed.tokens.filter(
      (token) => token.kind === "option",
    )) {
      if (seen.has(token.name) && !OPTIONS[token.name]?.multiple) {
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
      ...pipeline.roles.map((role) => `${role}-effort`),
      ...pipeline.roles.map((role) => `${role}-model`),
      ...pipeline.roles.map((role) => `${role}-profile`),
    ];
    requiredOptions = pipeline.requiredRunOptions;
    commandLabel = `${command} ${pipelineId}`;
  }

  if (command === "issues") {
    ({ options: supportedOptions, required: requiredOptions } =
      ISSUE_ACTIONS[positionals[1]]);
    commandLabel = `${command} ${positionals[1]}`;
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
      const server = await startMcp({ stderr });
      await server?.closed;
      return 0;
    } catch {
      stderr.write("Agent Runner MCP failed to start.\n");
      return 1;
    }
  }

  let recoveryDispatch;
  let recoveryStarted = false;
  let recoveryStage = "runtime-compatibility";
  try {
    if (command === "update") {
      if (values.check && values["idempotency-key"] !== undefined)
        throw new Error("--idempotency-key requires update apply.");
      if (values.release !== undefined && !isUpdateVersion(values.release))
        throw new Error("--release requires an exact version.");
      try {
        const request =
          values.release === undefined ? {} : { version: values.release };
        const key = values.check
          ? undefined
          : (values["idempotency-key"] ?? idempotencyKeyFactory());
        if (
          !values.check &&
          (typeof key !== "string" ||
            key.length > 1024 ||
            !key.trim() ||
            /[\p{Cc}\p{Zl}\p{Zp}]/u.test(key))
        )
          throw new Error("Invalid update retry identity.");
        const service = updateService ?? createCommandUpdate();
        if (!values.check && values["idempotency-key"] === undefined)
          stderr.write(`Update retry key: ${key}\n`);
        const result = values.check
          ? await service.check(request)
          : await service.apply({ ...request, idempotencyKey: key });
        stdout.write(
          `${JSON.stringify(values.check ? result : { ...result, idempotencyKey: key })}\n`,
        );
        return result.status === "blocked" ? 1 : 0;
      } catch {
        stderr.write("Update could not be verified.\n");
        return 1;
      }
    }
    if (command === "config") {
      const receipt = await migrateConfiguration({
        from: values.from,
        env: environment,
      });
      stdout.write(
        receipt.migrated
          ? "User configuration migrated.\n"
          : "User configuration unchanged.\n",
      );
      return 0;
    }
    if (command === "issues") {
      const action = positionals[1];
      const input =
        action === "list"
          ? issueListInput(values)
          : action === "read"
            ? { issueId: values.issue }
            : issueUpdateInput(
                values,
                values["idempotency-key"] ?? idempotencyKeyFactory(),
              );
      const service = issues ?? createCommandIssues({ env: environment });
      if (action === "update" && values["idempotency-key"] === undefined)
        stderr.write(`Issue update retry key: ${input.idempotencyKey}\n`);
      const result = await service[action](input);
      stdout.write(
        `${JSON.stringify(
          action === "update"
            ? { ...result, idempotencyKey: input.idempotencyKey }
            : result,
        )}\n`,
      );
      return 0;
    }
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
    let lastRefinementProgress;
    const commandRunner =
      runner ??
      createCommandRunner({
        onActivity(activity) {
          writeActivity(stdout, activity);
          const progress = JSON.stringify(activity.refinementProgress);
          if (progress !== lastRefinementProgress) {
            const lines = refinementProgressLines(activity.refinementProgress);
            if (lines.length) stdout.write(`${lines.join("\n")}\n`);
            lastRefinementProgress = progress;
          }
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
      const dispatch = await awaitDetachedDispatch(environment);
      recoveryDispatch = dispatch;
      const expectedRevision =
        values["expected-revision"] === undefined
          ? undefined
          : parseExpectedRevision(values["expected-revision"]);
      const resumeInput = {
        runId: values.run,
        action: resumeAction(values),
        ...(dispatch === undefined ? {} : { dispatch }),
        ...(expectedRevision === undefined ? {} : { expectedRevision }),
        ...(environment[DETACHED_STOP_CHECKPOINT_ENV] === undefined
          ? {}
          : {
              stopCheckpointRevision: detachedStopCheckpoint(environment),
            }),
        ...(environment[DETACHED_RUNTIME_COMPATIBILITY_ENV] === undefined
          ? {}
          : {
              expectedRuntimeCompatibility:
                environment[DETACHED_RUNTIME_COMPATIBILITY_ENV],
            }),
      };
      recoveryStarted = true;
      const result = await commandRunner.resume(resumeInput, {
        onRecoveryStage(stage) {
          recoveryStage = stage;
        },
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
    const details = recoveryStarted
      ? recoveryFailureDetails(recoveryStage, error)
      : null;
    if (
      details !== null &&
      (details.code !== null ||
        recoveryDispatch !== undefined ||
        environment[DETACHED_RUNTIME_COMPATIBILITY_ENV] !== undefined)
    ) {
      if (recoveryDispatch !== undefined) {
        try {
          await createCommandRunStore().recordRecoveryFailure(
            values.run,
            recoveryDispatch,
            { stage: recoveryStage, error },
          );
        } catch {
          // Diagnostics cannot replace the original failure or grant recovery.
        }
      }
      stderr.write(
        `Recovery failed at ${details.stage} (${details.code ?? "unavailable"}): ${details.explanation}\n`,
      );
      if (error?.code === "ERR_RUNTIME_VERSION_SKEW")
        stderr.write(
          "Restart the Agent Runner MCP server and retry the same idempotency key.\n",
        );
    } else {
      stderr.write(
        `${error instanceof Error ? error.message : String(error)}\n`,
      );
    }
    return error?.code === "ERR_RUNTIME_VERSION_SKEW"
      ? RUNTIME_VERSION_SKEW_EXIT_CODE
      : 1;
  }
}
