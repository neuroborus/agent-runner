import { createHash, randomUUID } from "node:crypto";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { PROVIDER_REGISTRY } from "../agents/index.js";
import { createClarificationService } from "../clarifications/index.js";
import {
  loadProjectConfiguration,
  loadRunnerConfiguration,
  resolvePipelineConfiguration,
} from "../config/index.js";
import { createGitService } from "../git/index.js";
import { getPipeline } from "../pipeline-registry.js";
import {
  createRunStore,
  deepFreeze,
  RUNTIME_COMPATIBILITY,
  RUNTIME_COMPATIBILITY_TOKEN,
  RUN_STATE_SCHEMA_VERSION,
} from "../state/index.js";
import { createTrustedValidationService } from "../trusted-validation/index.js";

import {
  assertNonEmptyString,
  isRecord,
  normalizeCreateOptions,
  normalizeInputSubmission,
  normalizeResumeInput,
  normalizeRunInput,
  orderedInputAnswers,
  rejectUnknownFields,
  RunnerError,
} from "./input.js";
import { pipelineForRun } from "./migration.js";
import {
  defaultAdapters,
  probeRequiredRoles,
  roleAdapters,
  validateSourceRoles,
} from "./roles.js";

const WORKTREE_LEASE_PIPELINES = new Set(["plan-execution", "polishing"]);
const RUNNER_OPTION_FIELDS = new Set([
  "adapters",
  "clarifications",
  "git",
  "loadConfiguration",
  "onActivity",
  "providers",
  "runStore",
  "trustedValidation",
]);

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

export function pipelineRequiresWorktreeLease(pipelineId) {
  return WORKTREE_LEASE_PIPELINES.has(pipelineId);
}

export function createRunner(options = {}) {
  rejectUnknownFields(options, RUNNER_OPTION_FIELDS, "runnerOptions");
  const providers = options.providers ?? PROVIDER_REGISTRY;
  if (
    !isRecord(providers) ||
    !Array.isArray(providers.ids) ||
    !Array.isArray(providers.sourceSessionIds) ||
    typeof providers.get !== "function" ||
    typeof providers.createAdapters !== "function" ||
    typeof providers.validateExecutionOptions !== "function" ||
    typeof providers.supportsSourceSessionFork !== "function" ||
    typeof providers.normalizeDiagnosticClass !== "function" ||
    typeof providers.isDiagnosticClass !== "function"
  ) {
    throw new RunnerError("Runner services are invalid.", {
      code: "ERR_INVALID_RUNNER_OPTIONS",
    });
  }
  const adapters = options.adapters ?? defaultAdapters(providers);
  const clarifications = options.clarifications ?? createClarificationService();
  const git = options.git ?? createGitService();
  const loadConfiguration =
    options.loadConfiguration ?? (() => loadRunnerConfiguration(providers));
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
      runtime: runtimeFor(
        pipeline,
        lease,
        run,
        roleAdapters(run, adapters, providers),
      ),
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
    const normalized = normalizeRunInput(input, providers);
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
      providers,
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
        providers,
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
    validateSourceRoles(
      pipeline,
      resolved.roles,
      normalized.sourceSession,
      providers,
    );
    if ((resolved.trustedValidation?.commands.length ?? 0) > 0) {
      await trustedValidation.preflight({ projectPath });
    }
    await probeRequiredRoles(
      pipeline,
      resolved.roles,
      adapters,
      normalized.sourceSession,
      providers,
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
