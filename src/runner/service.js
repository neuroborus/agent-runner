import { createHash, randomUUID } from "node:crypto";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { PROVIDER_REGISTRY, terminateOwnedProcess } from "../agents/index.js";
import { createClarificationService } from "../clarifications/index.js";
import {
  assertProjectConfigurationProtected,
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
  createStopMonitor,
  reconcileOperatorStop,
  restoreOperatorPause,
  stopPending,
  stopSettlement,
} from "./stops.js";
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

  async function guardProjectConfiguration(run) {
    await assertProjectConfigurationProtected({
      inspectPath: (input) => git.inspectPath(input),
      projectPath: run.projectPath,
      protection: run.projectConfigurationProtection,
    });
  }

  async function pauseForProjectConfiguration(run, lease) {
    if (run.pause?.reason === "project_configuration_changed") return run;
    const activity = {
      actor: "runner",
      phase: "configuration",
      kind: "changed",
      message: "Resolved project configuration changed; execution stopped.",
    };
    const next = await runStore.transitionRun(
      lease,
      {
        pipelineState: {
          ...run.pipelineState,
          workflowState: "WAITING_FOR_USER",
        },
        pause: {
          reason: "project_configuration_changed",
          code: "ERR_PROJECT_CONFIGURATION_CHANGED",
        },
        activeTurn: null,
      },
      { activity },
    );
    await publish(activity, next);
    return next;
  }

  function runtimeFor(
    pipeline,
    lease,
    run,
    selectedAdapters,
    monitor,
    onConfigurationFailure = () => {},
  ) {
    async function checkConfiguration() {
      try {
        await guardProjectConfiguration(run);
      } catch (cause) {
        onConfigurationFailure(cause);
        throw cause;
      }
    }
    return Object.freeze({
      adapters:
        monitor === undefined
          ? selectedAdapters
          : Object.fromEntries(
              Object.entries(selectedAdapters).map(([role, adapter]) => [
                role,
                {
                  probe: async () => {
                    await monitor.check();
                    return adapter.probe();
                  },
                  async run(request) {
                    await checkConfiguration();
                    try {
                      return await monitor.invoke(
                        (value) => adapter.run(value),
                        request,
                      );
                    } finally {
                      await checkConfiguration();
                    }
                  },
                },
              ]),
            ),
      clarifications,
      git:
        monitor === undefined
          ? git
          : {
              ...git,
              stagePolishingHandoff: async (value) => {
                await monitor.check();
                await checkConfiguration();
                return git.stagePolishingHandoff(value);
              },
              prepareCommit: async (value) => {
                await monitor.check();
                await checkConfiguration();
                return git.prepareCommit(value);
              },
              consumeCommit: async (...args) => {
                try {
                  await monitor.check();
                  await checkConfiguration();
                  return await git.consumeCommit(...args);
                } catch (cause) {
                  monitor.rejectBeforeCommit(cause);
                  throw cause;
                }
              },
            },
      trustedValidation:
        monitor === undefined
          ? trustedValidation
          : {
              preflight: async (value) => {
                await checkConfiguration();
                return trustedValidation.preflight(value);
              },
              execute: async (request) => {
                await checkConfiguration();
                return monitor.invoke(
                  (value) => trustedValidation.execute(value),
                  request,
                );
              },
            },
      readInputs: ({ taskPath }) => readInputs(pipeline, taskPath),
      async startAgentTurn(activeTurn, { pipelineState } = {}) {
        try {
          await monitor?.check();
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
        } catch (cause) {
          if (activeTurn?.phase === "commit")
            monitor?.rejectBeforeCommit(cause);
          throw cause;
        }
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
      async settleVerifiedCommit(patch, { activity, expectedPipelineState }) {
        let configurationFailure = null;
        try {
          await checkConfiguration();
        } catch (cause) {
          if (cause?.code !== "ERR_PROJECT_CONFIGURATION_CHANGED") throw cause;
          configurationFailure = cause;
        }
        // Drain any already detected stop activity before taking the lease.
        try {
          await monitor?.check();
        } catch (cause) {
          if (cause?.code !== "ERR_OPERATOR_STOP_BEFORE_COMMIT") throw cause;
        }
        let settlementActivity;
        const next = await runStore.settleCheckpoint(
          lease,
          (latest) => {
            if (
              !isDeepStrictEqual(latest.pipelineState, expectedPipelineState)
            ) {
              throw new RunnerError(
                "Commit checkpoint changed before settlement.",
                { code: "ERR_RUN_REVISION_CHANGED" },
              );
            }
            const settlement = stopSettlement(
              latest,
              patch,
              activity,
              configurationFailure,
            );
            settlementActivity = settlement.activity;
            return settlement;
          },
          { validate: pipeline.workflow.validateRun },
        );
        await publish(settlementActivity, next);
        return next;
      },
      async transition(patch, { activity, expectedRevision } = {}) {
        const next = await runStore.transitionRun(lease, patch, {
          activity,
          expectedRevision,
        });
        await publish(activity, next);
        return next;
      },
      writePlan: async (writeOptions) => {
        await monitor?.check();
        return writePlan(run.taskPath, writeOptions);
      },
      writeRunArtifact: ({ path, content }) =>
        runStore.writeRunArtifact(lease, path, content),
    });
  }

  async function execute(pipeline, run, lease, action = null) {
    if (run.pipelineState.workflowState === "CANCELED") return run;
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
    let configurationFailure = null;
    try {
      await guardProjectConfiguration(run);
    } catch (cause) {
      if (cause?.code !== "ERR_PROJECT_CONFIGURATION_CHANGED") throw cause;
      configurationFailure = cause;
    }
    if (
      configurationFailure !== null &&
      !stopPending(run) &&
      run.activeTurn === null &&
      run.executionProcess === null
    ) {
      return pauseForProjectConfiguration(run, lease);
    }
    if (pipeline.prepareRecovery !== undefined && runStore.loadRunHistory) {
      const history = await runStore.loadRunHistory(run.runId);
      if (!isDeepStrictEqual(history.run, run)) {
        throw new RunnerError("Run changed before recovery inspection.", {
          code: "ERR_RUN_REVISION_CHANGED",
        });
      }
      pipeline.prepareRecovery(run, history);
    }
    const settings = run.pipelineState.settings;
    if (!isRecord(settings)) {
      throw new RunnerError(`Run ${run.runId} has no resolved settings.`, {
        code: "ERR_MISSING_RUN_SETTINGS",
      });
    }
    const selected = roleAdapters(run, adapters, providers);
    const baseRuntime = runtimeFor(pipeline, lease, run, selected);
    if (stopPending(run))
      return reconcileOperatorStop({
        run,
        pipeline,
        lease,
        runStore,
        runtime: baseRuntime,
        publish,
        configurationFailure,
      });
    // Recover an orphaned supervised process before examining or replaying work.
    if (run.executionProcess !== null) {
      const owner = await runStore.inspectExecutionProcess(run.runId);
      await terminateOwnedProcess(owner.pid, () =>
        runStore.inspectExecutionProcess(run.runId),
      );
      run = await runStore.recordExecutionProcess(lease, null);
      try {
        await guardProjectConfiguration(run);
      } catch (cause) {
        if (cause?.code !== "ERR_PROJECT_CONFIGURATION_CHANGED") throw cause;
        configurationFailure = cause;
      }
      if (
        configurationFailure !== null &&
        !stopPending(run) &&
        run.activeTurn === null
      ) {
        return pauseForProjectConfiguration(run, lease);
      }
    }
    const monitor = createStopMonitor({
      runId: run.runId,
      lease,
      runStore,
      publish,
    });
    let completed;
    try {
      await monitor.check();
      completed = await pipeline.workflow.run({
        action,
        run,
        settings,
        runtime: runtimeFor(
          pipeline,
          lease,
          run,
          selected,
          monitor,
          (cause) => {
            if (cause?.code === "ERR_PROJECT_CONFIGURATION_CHANGED") {
              configurationFailure = cause;
            }
          },
        ),
      });
    } catch (cause) {
      if (cause?.code === "ERR_PROJECT_CONFIGURATION_CHANGED") {
        configurationFailure = cause;
      } else if (!stopPending(await runStore.loadRun(run.runId))) {
        throw cause;
      }
    } finally {
      await monitor.close();
    }
    const latest = await runStore.loadRun(run.runId);
    if (stopPending(latest)) {
      return reconcileOperatorStop({
        run: latest,
        pipeline,
        lease,
        runStore,
        runtime: baseRuntime,
        publish,
        preEffectRejection: monitor.preEffectRejection,
        configurationFailure,
      });
    }
    if (
      configurationFailure !== null &&
      latest.pipelineState.workflowState !== "CANCELED" &&
      latest.pause?.reason !== "operator_paused"
    ) {
      return pauseForProjectConfiguration(latest, lease);
    }
    return completed;
  }

  async function reconcilePendingStop(lease, runId) {
    const current = await runStore.loadRun(runId);
    const { pipeline } = pipelineForRun(current);
    let configurationFailure = null;
    try {
      await guardProjectConfiguration(current);
    } catch (cause) {
      if (cause?.code !== "ERR_PROJECT_CONFIGURATION_CHANGED") throw cause;
      configurationFailure = cause;
    }
    return reconcileOperatorStop({
      run: current,
      pipeline,
      lease,
      runStore,
      publish,
      runtime: runtimeFor(
        pipeline,
        lease,
        current,
        roleAdapters(current, adapters, providers),
      ),
      configurationFailure,
    });
  }

  async function releaseRunLease(lease, runId) {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        await lease.release();
        return;
      } catch (cause) {
        if (cause?.code !== "ERR_STOP_RECONCILIATION_REQUIRED") throw cause;
        const current = await runStore.loadRun(runId);
        await withWorktreeLease(
          current,
          () => reconcilePendingStop(lease, runId),
          lease,
        );
      }
    }
    throw new RunnerError("Operator stop reconciliation is still pending.", {
      code: "ERR_STOP_RECONCILIATION_REQUIRED",
    });
  }

  async function withWorktreeLease(run, operation, executionLease) {
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
      for (let attempt = 0; ; attempt += 1) {
        try {
          await worktreeLease.release();
          break;
        } catch (cause) {
          if (
            cause?.code !== "ERR_STOP_RECONCILIATION_REQUIRED" ||
            executionLease === undefined ||
            attempt >= 4
          )
            throw cause;
          await reconcilePendingStop(executionLease, run.runId);
        }
      }
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

  async function validatePersistedBoundary(run) {
    const boundary = await validateBoundary(run);
    if (
      boundary.projectPath !== run.projectPath ||
      boundary.taskPath !== run.taskPath
    ) {
      throw new RunnerError(
        `Run ${run.runId} canonical project or task path changed.`,
        { code: "ERR_RUN_PATH_CHANGED" },
      );
    }
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
    let configurationChanged = false;
    if (storedRun.pipelineState.workflowState !== "CANCELED") {
      try {
        await guardProjectConfiguration(storedRun);
      } catch (cause) {
        if (cause?.code !== "ERR_PROJECT_CONFIGURATION_CHANGED") throw cause;
        configurationChanged = true;
      }
      if (
        configurationChanged &&
        !stopPending(storedRun) &&
        storedRun.activeTurn === null &&
        storedRun.executionProcess === null
      ) {
        const pipeline = getPipeline(storedRun.pipelineId);
        if (pipeline === undefined) {
          throw new RunnerError(`Unknown pipeline: ${storedRun.pipelineId}.`, {
            code: "ERR_UNKNOWN_PIPELINE",
          });
        }
        return Object.freeze({
          pipeline,
          run: await pauseForProjectConfiguration(storedRun, lease),
          configurationBlocked: true,
          configurationChanged: true,
        });
      }
    }
    const prepared = pipelineForRun(storedRun, undefined, {
      allowMigration: true,
    });
    await validatePersistedBoundary(storedRun);
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
    return Object.freeze({
      pipeline: prepared.pipeline,
      run,
      configurationBlocked: false,
      configurationChanged,
    });
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
      projectConfigurationProtection: projectConfiguration?.protection ?? null,
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
      await releaseRunLease(created.lease, created.state.runId);
      throw cause;
    }
    return Object.freeze({ created, pipeline });
  }

  async function create(input, options = {}) {
    const { created } = await prepare(input, options);
    await releaseRunLease(created.lease, created.state.runId);
    return result(await runStore.loadRun(created.state.runId));
  }

  async function run(input) {
    const { created, pipeline } = await prepare(input);
    try {
      await withWorktreeLease(
        created.state,
        () => execute(pipeline, created.state, created.lease),
        created.lease,
      );
    } finally {
      await releaseRunLease(created.lease, created.state.runId);
    }
    return result(await runStore.loadRun(created.state.runId));
  }

  async function resumeLeased(normalized, lease) {
    const {
      pipeline,
      run: loaded,
      configurationBlocked,
      configurationChanged,
    } = await recoverCompatibleRun(lease, normalized.runId);
    if (configurationBlocked) return loaded;
    let recovered = loaded;
    if (recovered.pause?.reason === "project_configuration_changed") {
      return recovered;
    }
    if (recovered.pipelineState.workflowState === "CANCELED") {
      throw new RunnerError("Canceled runs cannot resume.", {
        code: "ERR_RUN_CANCELED",
      });
    }
    if (stopPending(recovered)) {
      return withWorktreeLease(
        recovered,
        () => execute(pipeline, recovered, lease),
        lease,
      );
    }
    if (configurationChanged) {
      return withWorktreeLease(
        recovered,
        () => execute(pipeline, recovered, lease),
        lease,
      );
    }
    let operatorRestore = null;
    if (recovered.pause?.reason === "operator_paused") {
      operatorRestore = restoreOperatorPause(recovered);
      if (normalized.action !== null)
        throw new RunnerError("Resume an operator pause with a null action.", {
          code: "ERR_INAPPLICABLE_RESUME_ACTION",
        });
      if (operatorRestore.pipelineState.workflowState === "WAITING_FOR_USER") {
        return runStore.transitionRun(
          lease,
          {
            pipelineState: operatorRestore.pipelineState,
            pause: operatorRestore.pause,
            activeTurn: operatorRestore.activeTurn,
          },
          {
            activity: {
              actor: "runner",
              phase: "stop",
              kind: "resumed",
              message: "Operator pause resumed at its preserved checkpoint.",
            },
          },
        );
      }
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
    return withWorktreeLease(
      recovered,
      async () => {
        if (operatorRestore !== null) {
          recovered = await runStore.transitionRun(
            lease,
            {
              pipelineState: operatorRestore.pipelineState,
              pause: operatorRestore.pause,
              activeTurn: operatorRestore.activeTurn,
            },
            {
              activity: {
                actor: "runner",
                phase: "stop",
                kind: "resumed",
                message: "Operator pause resumed at its preserved checkpoint.",
              },
            },
          );
        }
        if (
          (recovered.pipelineState.trustedValidation?.commands.length ?? 0) > 0
        ) {
          await guardProjectConfiguration(recovered);
          await trustedValidation.preflight({
            projectPath: recovered.projectPath,
          });
        }
        await validatePersistedBoundary(recovered);
        return execute(pipeline, recovered, lease, normalized.action);
      },
      lease,
    );
  }

  async function resume(input) {
    const normalized = normalizeResumeInput(input);
    const lease = await runStore.acquireRunLease(normalized.runId);
    try {
      await resumeLeased(normalized, lease);
    } finally {
      await releaseRunLease(lease, normalized.runId);
    }
    return result(await runStore.loadRun(normalized.runId));
  }

  async function status(runId) {
    assertNonEmptyString(runId, "runId");
    const history = runStore.loadRunHistory
      ? await runStore.loadRunHistory(runId)
      : { run: await runStore.loadRun(runId), events: [] };
    const { pipeline, run } = pipelineForRun(history.run, undefined, {
      allowMigration: true,
    });
    pipeline.prepareRecovery?.(run, history);
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
      const { run, configurationBlocked, configurationChanged } =
        await recoverCompatibleRun(lease, normalized.runId, {
          validatePreparedRun(preparedRun) {
            answers = orderedInputAnswers(preparedRun, normalized);
          },
        });
      if (configurationBlocked || configurationChanged) {
        throw new RunnerError(
          "The resolved project configuration changed during the run.",
          { code: "ERR_PROJECT_CONFIGURATION_CHANGED" },
        );
      }
      if (stopPending(run) || run.pipelineState.workflowState === "CANCELED") {
        throw new RunnerError("Stopped runs cannot accept input mutations.", {
          code: "ERR_STOP_RECONCILIATION_REQUIRED",
        });
      }
      await withWorktreeLease(
        run,
        async () => {
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
        },
        lease,
      );
    } finally {
      await releaseRunLease(lease, normalized.runId);
    }
    return result(await runStore.loadRun(normalized.runId));
  }

  return Object.freeze({
    requestOperatorStop: (input) => runStore.requestOperatorStop(input),
    create,
    previewInput,
    resume,
    run,
    status,
    submitInput,
    validateBoundary,
  });
}
