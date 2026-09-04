import { createHash, randomUUID } from "node:crypto";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import {
  BACKEND_IDS,
  createClaudeAdapter,
  createCodexAdapter,
  normalizeAdapterFailure,
} from "./agents/index.js";
import { createClarificationService } from "./clarifications.js";
import {
  loadProjectConfiguration,
  loadRunnerConfiguration,
  resolvePipelineConfiguration,
} from "./config.js";
import { createGitService } from "./git.js";
import {
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  getPipeline,
} from "./pipeline-registry.js";
import { deepFreeze } from "./state-validation.js";
import {
  createRunStore,
  RUNTIME_COMPATIBILITY,
  RUNTIME_COMPATIBILITY_TOKEN,
  RUN_STATE_SCHEMA_VERSION,
} from "./state.js";
import { createTrustedValidationService } from "./trusted-validation.js";

const BACKENDS = new Set(BACKEND_IDS);
const WORKTREE_LEASE_PIPELINES = new Set(["plan-execution", "polishing"]);
const RUN_FIELDS = new Set([
  "pipelineId",
  "projectPath",
  "taskPath",
  "proactiveClarification",
  "roleOverrides",
  "executionOverrides",
  "settingOverrides",
  "projectConfigurationPath",
  "sourceSession",
]);
const RESUME_FIELDS = new Set([
  "runId",
  "action",
  "expectedRuntimeCompatibility",
]);
const CREATE_OPTIONS_FIELDS = new Set(["runId"]);
const INPUT_FIELDS = new Set([
  "runId",
  "requestId",
  "expectedRevision",
  "answers",
  "responseHash",
]);
const ANSWER_FIELDS = new Set(["questionId", "answer"]);
const SOURCE_SESSION_FIELDS = new Set(["backend", "id", "profile"]);
const RUNNER_OPTION_FIELDS = new Set([
  "adapters",
  "clarifications",
  "git",
  "loadConfiguration",
  "onActivity",
  "runStore",
  "trustedValidation",
]);

export class RunnerError extends Error {
  constructor(message, { cause, code = "ERR_RUNNER" } = {}) {
    super(message, { cause });
    this.name = "RunnerError";
    this.code = code;
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function rejectUnknownFields(value, fields, name) {
  if (!isRecord(value)) {
    throw new RunnerError(`${name} must be an object.`, {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
  const unknown = Object.keys(value).find((field) => !fields.has(field));
  if (unknown !== undefined) {
    throw new RunnerError(`${name}.${unknown} is not supported.`, {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
}

function assertNonEmptyString(value, name) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new RunnerError(`${name} must be a non-empty string.`, {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
  return value;
}

export function parseSourceSession(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new RunnerError(
      `Source session must use <${BACKEND_IDS.join("|")}>:<session-id>.`,
      { code: "ERR_INVALID_SOURCE_SESSION" },
    );
  }
  const separator = value.indexOf(":");
  const backend = value.slice(0, separator);
  const id = value.slice(separator + 1);
  if (
    separator < 1 ||
    !BACKENDS.has(backend) ||
    id.trim().length === 0 ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(id)
  ) {
    throw new RunnerError(
      `Source session must use <${BACKEND_IDS.join("|")}>:<session-id>.`,
      { code: "ERR_INVALID_SOURCE_SESSION" },
    );
  }
  return Object.freeze({ backend, id });
}

function normalizeSourceSession(value) {
  if (value === undefined || value === null) {
    return null;
  }
  rejectUnknownFields(value, SOURCE_SESSION_FIELDS, "sourceSession");
  if (
    !BACKENDS.has(value.backend) ||
    typeof value.id !== "string" ||
    value.id.trim().length === 0 ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value.id)
  ) {
    throw new RunnerError("sourceSession is invalid.", {
      code: "ERR_INVALID_SOURCE_SESSION",
    });
  }
  if (
    value.profile !== undefined &&
    (typeof value.profile !== "string" || value.profile.trim().length === 0)
  ) {
    throw new RunnerError("sourceSession is invalid.", {
      code: "ERR_INVALID_SOURCE_SESSION",
    });
  }
  return Object.freeze({
    backend: value.backend,
    id: value.id,
    ...(value.profile === undefined ? {} : { profile: value.profile }),
  });
}

function fileHash(content) {
  return createHash("sha256").update(content).digest("hex");
}

async function inputFile(path, { optional = false } = {}) {
  let content;
  try {
    content = await readFile(path, "utf8");
  } catch (cause) {
    if (optional && cause?.code === "ENOENT") {
      return null;
    }
    throw cause;
  }
  return Object.freeze({ path, content, hash: fileHash(content) });
}

async function readInputs(pipeline, taskPath) {
  return Object.freeze(
    Object.fromEntries(
      await Promise.all(
        Object.entries(pipeline.taskInputs).map(async ([name, definition]) => [
          name,
          await inputFile(join(taskPath, definition.filename), {
            optional: definition.optional,
          }),
        ]),
      ),
    ),
  );
}

async function writePlan(taskPath, options) {
  const expectedPath = join(taskPath, "plan.md");
  if (
    !isRecord(options) ||
    options.artifactRoot !== taskPath ||
    options.path !== expectedPath ||
    typeof options.content !== "string"
  ) {
    throw new RunnerError("Plan write is outside the task boundary.", {
      code: "ERR_UNSAFE_PLAN_WRITE",
    });
  }
  const temporaryPath = join(taskPath, `.plan-${randomUUID()}.tmp`);
  try {
    await writeFile(temporaryPath, options.content, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporaryPath, expectedPath);
  } finally {
    await rm(temporaryPath, { force: true });
  }
  return expectedPath;
}

function defaultAdapters() {
  return Object.freeze({
    codex: createCodexAdapter(),
    claude: createClaudeAdapter(),
  });
}

function resolveAdapter(adapters, pipelineId, role, backend) {
  const adapter = adapters[backend];
  if (
    !isRecord(adapter) ||
    typeof adapter.probe !== "function" ||
    typeof adapter.run !== "function"
  ) {
    throw new RunnerError(
      `Backend is unavailable for ${pipelineId}.${role}: ${backend}.`,
      { code: "ERR_BACKEND_UNAVAILABLE" },
    );
  }
  return adapter;
}

function validateCapabilities(
  capabilities,
  { backend, pipelineId, role, sourceSession },
) {
  if (
    !isRecord(capabilities) ||
    typeof capabilities.version !== "string" ||
    capabilities.version.trim().length === 0 ||
    capabilities.structuredOutput !== true ||
    capabilities.readOnly !== true ||
    capabilities.remoteWriteBlocked !== true
  ) {
    throw new RunnerError(
      `Backend cannot safely run ${pipelineId}.${role}: ${backend}.`,
      { code: "ERR_UNSUPPORTED_BACKEND" },
    );
  }
  if (sourceSession !== null && capabilities.nativeSessionFork !== true) {
    throw new RunnerError(
      `Backend cannot fork the supplied source: ${backend}.`,
      {
        code: "ERR_UNSUPPORTED_SOURCE_SESSION",
      },
    );
  }
  return capabilities;
}

function executionOptions(configuration) {
  return Object.freeze({
    profile: configuration.profile,
    model: configuration.model,
    contextSize: configuration.contextSize,
  });
}

async function runAdapter(adapter, backend, request) {
  try {
    return await adapter.run(request);
  } catch (cause) {
    throw normalizeAdapterFailure(backend, cause);
  }
}

function lazyArbiterAdapter(run, configuration, adapters) {
  let adapter;
  let capabilitiesPromise;
  const resolve = () => {
    adapter ??= resolveAdapter(
      adapters,
      run.pipelineId,
      "arbiter",
      configuration.backend,
    );
    return adapter;
  };
  const resolveCapabilities = async () => {
    capabilitiesPromise ??= Promise.resolve()
      .then(() => resolve().probe(executionOptions(configuration)))
      .then((capabilities) =>
        validateCapabilities(capabilities, {
          backend: configuration.backend,
          pipelineId: run.pipelineId,
          role: "arbiter",
          sourceSession: null,
        }),
      );
    try {
      return await capabilitiesPromise;
    } catch (error) {
      capabilitiesPromise = undefined;
      throw error;
    }
  };
  return Object.freeze({
    probe: resolveCapabilities,
    async run(request) {
      await resolveCapabilities();
      return runAdapter(resolve(), configuration.backend, request);
    },
  });
}

function configuredAdapter(run, role, configuration, adapters) {
  const adapter = resolveAdapter(
    adapters,
    run.pipelineId,
    role,
    configuration.backend,
  );
  return Object.freeze({
    probe: () => adapter.probe(executionOptions(configuration)),
    run: (request) => runAdapter(adapter, configuration.backend, request),
  });
}

function roleAdapters(run, adapters) {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(run.roles).map(([role, configuration]) => [
        role,
        role === "arbiter"
          ? lazyArbiterAdapter(run, configuration, adapters)
          : configuredAdapter(run, role, configuration, adapters),
      ]),
    ),
  );
}

function validateSourceRoles(pipeline, roles, sourceSession) {
  if (sourceSession === null) {
    return;
  }
  const incompatibleRole = Object.keys(roles)
    .filter((role) => role !== "arbiter")
    .find((role) => roles[role].backend !== sourceSession.backend);
  if (incompatibleRole !== undefined) {
    throw new RunnerError(
      `Source backend ${sourceSession.backend} does not match ${pipeline.id}.${incompatibleRole}.`,
      { code: "ERR_SOURCE_BACKEND_MISMATCH" },
    );
  }
}

async function probeRequiredRoles(pipeline, roles, adapters, sourceSession) {
  const requiredRoles = Object.keys(roles).filter((role) => role !== "arbiter");
  const capabilitiesByConfiguration = new Map();
  for (const role of requiredRoles) {
    const configuration = roles[role];
    const backend = configuration.backend;
    const key = JSON.stringify(configuration);
    if (!capabilitiesByConfiguration.has(key)) {
      const adapter = resolveAdapter(adapters, pipeline.id, role, backend);
      capabilitiesByConfiguration.set(
        key,
        await adapter.probe(executionOptions(configuration)),
      );
    }
    validateCapabilities(capabilitiesByConfiguration.get(key), {
      backend,
      pipelineId: pipeline.id,
      role,
      sourceSession,
    });
  }
}

function normalizeRunInput(input) {
  rejectUnknownFields(input, RUN_FIELDS, "run");
  return Object.freeze({
    pipelineId: assertNonEmptyString(input.pipelineId, "run.pipelineId"),
    projectPath: assertNonEmptyString(input.projectPath, "run.projectPath"),
    taskPath: assertNonEmptyString(input.taskPath, "run.taskPath"),
    proactiveClarification:
      input.proactiveClarification === undefined
        ? false
        : input.proactiveClarification,
    roleOverrides: input.roleOverrides ?? {},
    executionOverrides: input.executionOverrides ?? {},
    settingOverrides: input.settingOverrides ?? {},
    projectConfigurationPath:
      input.projectConfigurationPath === undefined
        ? undefined
        : assertNonEmptyString(
            input.projectConfigurationPath,
            "run.projectConfigurationPath",
          ),
    sourceSession: normalizeSourceSession(input.sourceSession),
  });
}

function normalizeResumeInput(input) {
  rejectUnknownFields(input, RESUME_FIELDS, "resume");
  if (
    input.expectedRuntimeCompatibility !== undefined &&
    input.expectedRuntimeCompatibility !== DETACHED_RUNTIME_COMPATIBILITY_TOKEN
  ) {
    throw new RunnerError(
      "Detached continuation runtime is incompatible with the process that " +
        "dispatched it; restart the Agent Runner MCP server and retry with " +
        "the same idempotency key.",
      { code: "ERR_RUNTIME_VERSION_SKEW" },
    );
  }
  return Object.freeze({
    runId: assertNonEmptyString(input.runId, "resume.runId"),
    action: input.action ?? null,
    ...(input.expectedRuntimeCompatibility === undefined
      ? {}
      : {
          expectedRuntimeCompatibility: input.expectedRuntimeCompatibility,
        }),
  });
}

function normalizeCreateOptions(options) {
  rejectUnknownFields(options, CREATE_OPTIONS_FIELDS, "createOptions");
  return Object.freeze({
    runId:
      options.runId === undefined
        ? undefined
        : assertNonEmptyString(options.runId, "createOptions.runId"),
  });
}

function normalizeInputSubmission(input, { requireResponseHash = false } = {}) {
  rejectUnknownFields(input, INPUT_FIELDS, "input");
  if (
    !Number.isSafeInteger(input.expectedRevision) ||
    input.expectedRevision < 1 ||
    !Array.isArray(input.answers)
  ) {
    throw new RunnerError("Input response is invalid.", {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
  const answers = input.answers.map((answer, index) => {
    rejectUnknownFields(answer, ANSWER_FIELDS, `input.answers[${index}]`);
    return Object.freeze({
      questionId: assertNonEmptyString(
        answer.questionId,
        `input.answers[${index}].questionId`,
      ),
      answer: assertNonEmptyString(
        answer.answer,
        `input.answers[${index}].answer`,
      ),
    });
  });
  if (
    requireResponseHash &&
    (typeof input.responseHash !== "string" ||
      !/^[a-f0-9]{64}$/u.test(input.responseHash))
  ) {
    throw new RunnerError("Input response hash is invalid.", {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
  return Object.freeze({
    runId: assertNonEmptyString(input.runId, "input.runId"),
    requestId: assertNonEmptyString(input.requestId, "input.requestId"),
    expectedRevision: input.expectedRevision,
    answers: Object.freeze(answers),
    responseHash: input.responseHash,
  });
}

function orderedInputAnswers(run, input) {
  const request = run.pause?.inputRequest;
  if (
    run.pipelineState.workflowState !== "WAITING_FOR_USER" ||
    run.pipelineState.pendingEdit === null ||
    request === null ||
    typeof request !== "object" ||
    request.id !== input.requestId ||
    !Array.isArray(request.questions)
  ) {
    throw new RunnerError("Pending input request does not match.", {
      code: "ERR_STALE_INPUT_REQUEST",
    });
  }
  if (run.revision !== input.expectedRevision) {
    throw new RunnerError("Pending input request revision is stale.", {
      code: "ERR_STALE_INPUT_REQUEST",
    });
  }
  if (run.pause.inputResponse !== undefined) {
    throw new RunnerError("Pending input request was already answered.", {
      code: "ERR_INPUT_ALREADY_SUBMITTED",
    });
  }
  const expectedIds = request.questions.map((question) => question.id);
  const byId = new Map(
    input.answers.map(({ questionId, answer }) => [questionId, answer]),
  );
  if (
    byId.size !== input.answers.length ||
    byId.size !== expectedIds.length ||
    expectedIds.some((id) => !byId.has(id))
  ) {
    throw new RunnerError("One answer is required for every question.", {
      code: "ERR_INCOMPLETE_INPUT_RESPONSE",
    });
  }
  return Object.freeze(expectedIds.map((id) => byId.get(id)));
}

export function preparePipelineMigration(run, pipeline) {
  if (run.pipelineStateVersion > pipeline.stateVersion) {
    throw new RunnerError(
      `Run ${run.runId} uses newer ${pipeline.id} state version ` +
        `${run.pipelineStateVersion}; this runtime supports version ` +
        `${pipeline.stateVersion}. Use a compatible Agent Runner version.`,
      { code: "ERR_PIPELINE_VERSION_SKEW" },
    );
  }

  const originalVersion = run.pipelineStateVersion;
  let migrated = run;
  while (migrated.pipelineStateVersion < pipeline.stateVersion) {
    const migration = pipeline.migrations?.[migrated.pipelineStateVersion];
    if (typeof migration !== "function") {
      throw new RunnerError(
        `Run ${run.runId} requires an unavailable ${pipeline.id} migration ` +
          `from state version ${migrated.pipelineStateVersion}. Use an ` +
          "Agent Runner version with that migration.",
        { code: "ERR_PIPELINE_VERSION_SKEW" },
      );
    }
    let pipelineState;
    try {
      pipelineState = migration(migrated);
    } catch (cause) {
      throw new RunnerError(
        `Run ${run.runId} could not migrate ${pipeline.id} state version ` +
          `${migrated.pipelineStateVersion}.`,
        { cause, code: "ERR_PIPELINE_MIGRATION_FAILED" },
      );
    }
    if (!isRecord(pipelineState)) {
      throw new RunnerError(
        `${pipeline.id} migration from state version ` +
          `${migrated.pipelineStateVersion} returned invalid state.`,
        { code: "ERR_PIPELINE_MIGRATION_FAILED" },
      );
    }
    migrated = deepFreeze({
      ...migrated,
      pipelineStateVersion: migrated.pipelineStateVersion + 1,
      pipelineState,
    });
  }
  try {
    pipeline.workflow.validateRun(migrated);
  } catch (cause) {
    if (migrated.pipelineStateVersion === originalVersion) {
      throw cause;
    }
    throw new RunnerError(
      `Run ${run.runId} produced invalid ${pipeline.id} state after ` +
        `migration from version ${originalVersion}.`,
      { cause, code: "ERR_PIPELINE_MIGRATION_FAILED" },
    );
  }
  return migrated;
}

function pipelineForRun(run, knownPipeline, { allowMigration = false } = {}) {
  const pipeline = knownPipeline ?? getPipeline(run.pipelineId);
  if (pipeline === undefined) {
    throw new RunnerError(`Unknown pipeline: ${run.pipelineId}.`, {
      code: "ERR_UNKNOWN_PIPELINE",
    });
  }
  const compatibleRun = preparePipelineMigration(run, pipeline);
  if (
    !allowMigration &&
    compatibleRun.pipelineStateVersion !== run.pipelineStateVersion
  ) {
    throw new RunnerError(
      `Run ${run.runId} requires a persisted ${pipeline.id} state migration.`,
      { code: "ERR_PIPELINE_MIGRATION_REQUIRED" },
    );
  }
  return Object.freeze({ pipeline, run: compatibleRun });
}

export function pipelineRequiresWorktreeLease(pipelineId) {
  return WORKTREE_LEASE_PIPELINES.has(pipelineId);
}

export function createRunner(options = {}) {
  rejectUnknownFields(options, RUNNER_OPTION_FIELDS, "runnerOptions");
  const adapters = options.adapters ?? defaultAdapters();
  const clarifications = options.clarifications ?? createClarificationService();
  const git = options.git ?? createGitService();
  const loadConfiguration =
    options.loadConfiguration ?? loadRunnerConfiguration;
  const onActivity = options.onActivity ?? (async () => {});
  const runStore = options.runStore ?? createRunStore();
  const trustedValidation =
    options.trustedValidation ?? createTrustedValidationService({ git });
  if (
    !isRecord(adapters) ||
    !isRecord(clarifications) ||
    !isRecord(git) ||
    typeof loadConfiguration !== "function" ||
    typeof onActivity !== "function" ||
    !isRecord(runStore) ||
    !isRecord(trustedValidation) ||
    typeof trustedValidation.preflight !== "function" ||
    typeof trustedValidation.execute !== "function"
  ) {
    throw new RunnerError("Runner services are invalid.", {
      code: "ERR_INVALID_RUNNER_OPTIONS",
    });
  }

  async function publish(activity, run) {
    if (activity === undefined || activity === null) {
      return;
    }
    await onActivity(
      Object.freeze({
        runId: run.runId,
        revision: run.revision,
        recordedAt: run.updatedAt,
        ...activity,
      }),
    );
  }

  function runtimeFor(pipeline, lease, run, selectedAdapters) {
    return Object.freeze({
      adapters: selectedAdapters,
      clarifications,
      git,
      trustedValidation,
      readInputs: ({ taskPath }) => readInputs(pipeline, taskPath),
      async startAgentTurn(activeTurn, { pipelineState } = {}) {
        const current = await runStore.loadRun(run.runId);
        pipeline.workflow.validateRun(
          deepFreeze({
            ...current,
            ...(pipelineState === undefined ? {} : { pipelineState }),
            activeTurn,
            revision: current.revision + 1,
          }),
        );
        const activity = {
          actor: activeTurn?.role,
          phase: activeTurn?.phase,
          kind: "turn-started",
          message: `${activeTurn?.role} ${activeTurn?.phase} turn started.`,
        };
        const next = await runStore.startAgentTurn(lease, activeTurn, {
          activity,
          ...(pipelineState === undefined ? {} : { pipelineState }),
        });
        await publish(activity, next);
        return next;
      },
      finishAgentTurn: (activeTurn) =>
        runStore.finishAgentTurn(lease, activeTurn),
      async recordChildSession(child, { activity } = {}) {
        const next = await runStore.recordChildSession(lease, child, {
          activity,
        });
        await publish(activity, next);
        return next;
      },
      async transition(patch, { activity } = {}) {
        const next = await runStore.transitionRun(lease, patch, { activity });
        await publish(activity, next);
        return next;
      },
      writePlan: (writeOptions) => writePlan(run.taskPath, writeOptions),
      writeRunArtifact: ({ path, content }) =>
        runStore.writeRunArtifact(lease, path, content),
    });
  }

  async function execute(pipeline, run, lease, action = null) {
    if (
      run.schemaVersion !== RUN_STATE_SCHEMA_VERSION ||
      run.runtimeCompatibility?.runnerVersion !==
        RUNTIME_COMPATIBILITY.runnerVersion ||
      run.runtimeCompatibility?.runStateVersion !==
        RUNTIME_COMPATIBILITY.runStateVersion
    ) {
      throw new RunnerError(
        `Run ${run.runId} requires a persisted runtime migration.`,
        { code: "ERR_RUNTIME_MIGRATION_REQUIRED" },
      );
    }
    pipelineForRun(run, pipeline);
    const settings = run.pipelineState.settings;
    if (!isRecord(settings)) {
      throw new RunnerError(`Run ${run.runId} has no resolved settings.`, {
        code: "ERR_MISSING_RUN_SETTINGS",
      });
    }
    return pipeline.workflow.run({
      action,
      run,
      runtime: runtimeFor(pipeline, lease, run, roleAdapters(run, adapters)),
      settings,
    });
  }

  async function withWorktreeLease(run, operation) {
    if (!pipelineRequiresWorktreeLease(run.pipelineId)) {
      return operation();
    }
    const worktreeLease = await runStore.acquireWorktreeLease(
      run.projectPath,
      run.runId,
    );
    try {
      return await operation();
    } finally {
      await worktreeLease.release();
    }
  }

  async function validateBoundary(input) {
    const projectPath = assertNonEmptyString(
      input?.projectPath,
      "run.projectPath",
    );
    const taskPath = assertNonEmptyString(input?.taskPath, "run.taskPath");
    const discovery = await git.preflight({
      allowedPaths: [],
      projectPath,
      requireClean: false,
      requireIdentity: false,
      requiredIgnoredPaths: [],
    });
    const repositoryPath = discovery?.snapshot?.projectPath;
    if (
      typeof repositoryPath !== "string" ||
      resolve(repositoryPath) !== repositoryPath
    ) {
      throw new RunnerError("Git preflight returned an invalid project root.", {
        code: "ERR_INVALID_PROJECT_ROOT",
      });
    }
    return runStore.validateStateBoundary({
      projectPath: repositoryPath,
      taskPath,
    });
  }

  async function result(run) {
    return Object.freeze({
      directoryPath: await runStore.getRunDirectory(run.runId),
      run,
    });
  }

  async function recoverCompatibleRun(
    lease,
    runId,
    { validatePreparedRun } = {},
  ) {
    const storedRun = await runStore.loadRun(runId);
    const prepared = pipelineForRun(storedRun, undefined, {
      allowMigration: true,
    });
    const boundary = await validateBoundary(storedRun);
    if (
      boundary.projectPath !== storedRun.projectPath ||
      boundary.taskPath !== storedRun.taskPath
    ) {
      throw new RunnerError(
        `Run ${runId} canonical project or task path changed.`,
        { code: "ERR_RUN_PATH_CHANGED" },
      );
    }
    validatePreparedRun?.(prepared.run);
    const runtimeMigrationRequired =
      storedRun.schemaVersion !== RUN_STATE_SCHEMA_VERSION ||
      storedRun.runtimeCompatibility?.runnerVersion !==
        RUNTIME_COMPATIBILITY.runnerVersion ||
      storedRun.runtimeCompatibility?.runStateVersion !==
        RUNTIME_COMPATIBILITY.runStateVersion;
    const pipelineMigrationRequired =
      storedRun.pipelineStateVersion !== prepared.run.pipelineStateVersion;
    let run;
    if (runtimeMigrationRequired || pipelineMigrationRequired) {
      const activity = {
        actor: "runner",
        phase: "runtime",
        kind: "migrated",
        message:
          `Migrated run state for ${prepared.pipeline.id} to runtime ` +
          `${RUNTIME_COMPATIBILITY_TOKEN} and pipeline state ` +
          `${prepared.run.pipelineStateVersion}.`,
      };
      run = await runStore.migrateRun(
        lease,
        {
          pipelineState: prepared.run.pipelineState,
          pipelineStateVersion: prepared.run.pipelineStateVersion,
        },
        { activity },
      );
      await publish(activity, run);
    } else {
      run = await runStore.recoverRun(lease);
    }
    pipelineForRun(run, prepared.pipeline);
    return Object.freeze({ pipeline: prepared.pipeline, run });
  }

  async function prepare(input, options = {}) {
    const normalized = normalizeRunInput(input);
    const createOptions = normalizeCreateOptions(options);
    if (typeof normalized.proactiveClarification !== "boolean") {
      throw new RunnerError("run.proactiveClarification must be a boolean.", {
        code: "ERR_INVALID_RUNNER_INPUT",
      });
    }
    if (!isRecord(normalized.roleOverrides)) {
      throw new RunnerError("run.roleOverrides must be an object.", {
        code: "ERR_INVALID_RUNNER_INPUT",
      });
    }
    if (!isRecord(normalized.executionOverrides)) {
      throw new RunnerError("run.executionOverrides must be an object.", {
        code: "ERR_INVALID_RUNNER_INPUT",
      });
    }
    if (!isRecord(normalized.settingOverrides)) {
      throw new RunnerError("run.settingOverrides must be an object.", {
        code: "ERR_INVALID_RUNNER_INPUT",
      });
    }
    const pipeline = getPipeline(normalized.pipelineId);
    if (pipeline === undefined) {
      throw new RunnerError(`Unknown pipeline: ${normalized.pipelineId}.`, {
        code: "ERR_UNKNOWN_PIPELINE",
      });
    }
    const { projectPath, taskPath } = await validateBoundary(normalized);
    const configuration = await loadConfiguration();
    const projectConfiguration = await loadProjectConfiguration({
      configurationPath: normalized.projectConfigurationPath,
      inspectPath: (options) => git.inspectPath(options),
      projectPath,
      runnerConfiguration: configuration,
    });
    let resolved;
    try {
      resolved = resolvePipelineConfiguration(
        pipeline.id,
        configuration,
        normalized.roleOverrides,
        normalized.executionOverrides,
        normalized.sourceSession,
        projectConfiguration?.configuration ?? null,
        normalized.settingOverrides,
      );
    } catch (cause) {
      if (cause?.code !== "ERR_SOURCE_BACKEND_MISMATCH") {
        throw cause;
      }
      throw new RunnerError(cause.message, {
        cause,
        code: "ERR_SOURCE_BACKEND_MISMATCH",
      });
    }
    validateSourceRoles(pipeline, resolved.roles, normalized.sourceSession);
    if ((resolved.trustedValidation?.commands.length ?? 0) > 0) {
      await trustedValidation.preflight({ projectPath });
    }
    await probeRequiredRoles(
      pipeline,
      resolved.roles,
      adapters,
      normalized.sourceSession,
    );
    const pipelineState = pipeline.workflow.createState({
      artifactRoot: resolved.artifactRoot,
      proactiveClarification: normalized.proactiveClarification,
      settings: resolved.settings,
      ...(resolved.trustedValidation === undefined
        ? {}
        : { trustedValidation: resolved.trustedValidation }),
    });
    const created = await runStore.createRun({
      ...(createOptions.runId === undefined
        ? {}
        : { runId: createOptions.runId }),
      pipelineId: pipeline.id,
      pipelineStateVersion: pipeline.stateVersion,
      projectPath,
      taskPath,
      roles: resolved.roles,
      sourceSession: normalized.sourceSession?.id ?? null,
      sourceProfile: resolved.sourceProfile,
      pipelineState,
      activity: {
        actor: "runner",
        phase: "run",
        kind: "created",
        message: `${pipeline.id} run created.`,
      },
    });
    try {
      await publish(
        {
          actor: "runner",
          phase: "run",
          kind: "created",
          message: `${pipeline.id} run created.`,
        },
        created.state,
      );
    } catch (cause) {
      await created.lease.release();
      throw cause;
    }
    return Object.freeze({ created, pipeline });
  }

  async function create(input, options = {}) {
    const { created } = await prepare(input, options);
    try {
      return await result(created.state);
    } finally {
      await created.lease.release();
    }
  }

  async function run(input) {
    const { created, pipeline } = await prepare(input);
    try {
      return await result(
        await withWorktreeLease(created.state, () =>
          execute(pipeline, created.state, created.lease),
        ),
      );
    } finally {
      await created.lease.release();
    }
  }

  async function resume(input) {
    const normalized = normalizeResumeInput(input);
    const lease = await runStore.acquireRunLease(normalized.runId);
    try {
      const { pipeline, run: recovered } = await recoverCompatibleRun(
        lease,
        normalized.runId,
      );
      if (
        (recovered.pipelineState.trustedValidation?.commands.length ?? 0) > 0
      ) {
        await trustedValidation.preflight({
          projectPath: recovered.projectPath,
        });
      }
      if (
        recovered.pipelineState.workflowState === "WAITING_FOR_USER" ||
        normalized.action !== null
      ) {
        try {
          pipeline.validateResumeAction(recovered, normalized.action);
        } catch (cause) {
          throw new RunnerError(cause.message, {
            cause,
            code: "ERR_INAPPLICABLE_RESUME_ACTION",
          });
        }
      }
      return await result(
        await withWorktreeLease(recovered, () =>
          execute(pipeline, recovered, lease, normalized.action),
        ),
      );
    } finally {
      await lease.release();
    }
  }

  async function status(runId) {
    assertNonEmptyString(runId, "runId");
    const storedRun = await runStore.loadRun(runId);
    const { run } = pipelineForRun(storedRun, undefined, {
      allowMigration: true,
    });
    return result(run);
  }

  async function previewInput(input) {
    const normalized = normalizeInputSubmission(input);
    const { run } = await status(normalized.runId);
    const answers = orderedInputAnswers(run, normalized);
    const preview = await clarifications.previewEditAnswers(
      run.pipelineState.pendingEdit,
      answers,
    );
    return Object.freeze({
      runId: run.runId,
      requestId: normalized.requestId,
      revision: run.revision,
      responseHash: preview.hash,
    });
  }

  async function submitInput(input) {
    const normalized = normalizeInputSubmission(input, {
      requireResponseHash: true,
    });
    const lease = await runStore.acquireRunLease(normalized.runId);
    try {
      let answers;
      const { run } = await recoverCompatibleRun(lease, normalized.runId, {
        validatePreparedRun(preparedRun) {
          answers = orderedInputAnswers(preparedRun, normalized);
        },
      });
      return await withWorktreeLease(run, async () => {
        const transcript = await clarifications.writeEditAnswers(
          run.pipelineState.pendingEdit,
          answers,
          { expectedHash: normalized.responseHash },
        );
        const next = await runStore.transitionRun(
          lease,
          {
            pause: {
              ...run.pause,
              inputResponse: {
                requestId: normalized.requestId,
                transcriptHash: transcript.hash,
              },
            },
          },
          {
            activity: {
              actor: "runner",
              phase: "clarification",
              kind: "submitted",
              message: "Pending user input was recorded.",
            },
          },
        );
        await publish(
          {
            actor: "runner",
            phase: "clarification",
            kind: "submitted",
            message: "Pending user input was recorded.",
          },
          next,
        );
        return result(next);
      });
    } finally {
      await lease.release();
    }
  }

  return Object.freeze({
    create,
    previewInput,
    resume,
    run,
    status,
    submitInput,
    validateBoundary,
  });
}
