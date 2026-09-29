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
import { getPipeline, resolveStopBoundary } from "../pipeline-registry.js";
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
import { createAvailabilityCoordinator } from "./availability.js";
import { inspectTrustedRequirements } from "./trusted-requirements.js";
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
  "availabilityClock",
  "availabilityWait",
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

function isProcessContainmentFailure(cause) {
  return [
    "ERR_EXECUTION_PROCESS_ACTIVE",
    "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  ].includes(cause?.code);
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
    typeof providers.classifyFailure !== "function" ||
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
  const runStore = options.runStore ?? createRunStore({ resolveStopBoundary });
  const trustedValidation =
    options.trustedValidation ?? createTrustedValidationService({ git });
  // Stop recovery must reuse the exact in-process reservation; failed
  // reconciliation keeps its handle for same-owner retry and its durable
  // lease for safe reclamation after owner loss.
  const heldWorktreeLeases = new Map();
  if (
    !isRecord(adapters) ||
    !isRecord(clarifications) ||
    !isRecord(git) ||
    typeof loadConfiguration !== "function" ||
    typeof onActivity !== "function" ||
    (options.availabilityClock !== undefined &&
      typeof options.availabilityClock !== "function") ||
    (options.availabilityWait !== undefined &&
      typeof options.availabilityWait !== "function") ||
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

  function storageForbiddenPaths(run) {
    return [run.projectPath, run.taskPath, runStore.rootPath].filter(
      (path) => typeof path === "string",
    );
  }

  async function cleanupExecutionResource(run, lease) {
    if (run.executionResource == null) return run;
    if (
      run.executionProcess !== null ||
      typeof trustedValidation.recoverResources !== "function"
    ) {
      throw new RunnerError(
        "Execution storage cleanup requires verified process retirement.",
        { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
      );
    }
    await trustedValidation.recoverResources({
      resource: run.executionResource,
      projectPath: run.projectPath,
      storageForbiddenPaths: storageForbiddenPaths(run),
      onResource: (value) => runStore.recordExecutionResource(lease, value),
    });
    return runStore.loadRun(run.runId);
  }

  function runtimeFor(
    pipeline,
    lease,
    run,
    selectedAdapters,
    monitor,
    onConfigurationFailure = () => {},
  ) {
    let providerResponseRole = null;
    const availability =
      monitor === undefined
        ? undefined
        : createAvailabilityCoordinator({
            runId: run.runId,
            lease,
            runStore,
            providers,
            git,
            publish,
            monitor,
            clock: options.availabilityClock,
            wait: options.availabilityWait,
            validateRun: pipeline.workflow.validateRun,
            initialRun: run,
          });
    async function reconcileProviderResponse(options) {
      if (providerResponseRole === null) return undefined;
      const next = await availability.completed(providerResponseRole, options);
      providerResponseRole = null;
      return next;
    }
    async function checkConfiguration() {
      try {
        await guardProjectConfiguration(run);
      } catch (cause) {
        onConfigurationFailure(cause);
        throw cause;
      }
    }
    return Object.freeze({
      availability,
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
                      const response = await monitor.invoke(
                        (value) => adapter.run(value),
                        request,
                      );
                      providerResponseRole = role;
                      return response;
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
                await trustedValidation.preflight({
                  ...value,
                  storageForbiddenPaths: storageForbiddenPaths(run),
                });
                await validatePersistedBoundary(run);
              },
              inspectRequirements: (request) =>
                inspectTrustedRequirements(
                  {
                    trustedValidation,
                    runStore,
                    lease,
                    run,
                    monitor,
                    checkConfiguration,
                    validatePersistedBoundary,
                    storageForbiddenPaths,
                  },
                  request,
                ),
              execute: async (request) => {
                await checkConfiguration();
                return monitor.invoke(
                  (value) =>
                    trustedValidation.execute({
                      ...value,
                      storageForbiddenPaths: storageForbiddenPaths(run),
                      onResource: (resource) =>
                        runStore.recordExecutionResource(lease, resource),
                    }),
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
      async finishAgentTurn(activeTurn) {
        await reconcileProviderResponse();
        return runStore.finishAgentTurn(lease, activeTurn);
      },
      async recordChildSession(child, { activity } = {}) {
        const next = await runStore.recordChildSession(lease, child, {
          activity,
        });
        await publish(activity, next);
        return next;
      },
      async settleVerifiedCommit(
        patch,
        { activity, expectedPipelineState, verifiedCommit },
      ) {
        await reconcileProviderResponse();
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
            return {
              ...settlement,
              settlement: { kind: "commit", commit: verifiedCommit },
            };
          },
          { validate: pipeline.workflow.validateRun },
        );
        await publish(settlementActivity, next);
        return next;
      },
      async transition(patch, { activity, expectedRevision } = {}) {
        // Reconcile safe content and correction accounting atomically with the
        // response reset, so owner loss cannot turn a retry into a second fix.
        const reconciled = await reconcileProviderResponse({
          patch,
          expectedRevision,
        });
        if (reconciled !== undefined && activity == null) return reconciled;
        const next = await runStore.transitionRun(lease, patch, {
          activity,
          expectedRevision: reconciled?.revision ?? expectedRevision,
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

  function selectedRoleAdapters(pipeline, run, lease) {
    const currentPolicies = { ...run.providerPolicies };
    let pendingPolicyReceipt = Promise.resolve();
    return roleAdapters(run, pipeline, adapters, providers, (role, receipt) => {
      const operation = pendingPolicyReceipt.then(async () => {
        const expected = currentPolicies[role];
        if (expected !== null) {
          if (!isDeepStrictEqual(expected, receipt)) {
            throw new RunnerError(`Provider policy changed for role ${role}.`, {
              code: "ERR_PROVIDER_POLICY_CHANGED",
            });
          }
          return;
        }
        const next = await runStore.recordProviderPolicy(lease, role, receipt);
        currentPolicies[role] = next.providerPolicies[role];
        await publish(
          {
            actor: "runner",
            phase: "runtime",
            kind: "provider-policy-recorded",
            message: `Recorded immutable provider policy for ${role}.`,
          },
          next,
        );
      });
      pendingPolicyReceipt = operation.catch(() => {});
      return operation;
    });
  }

  async function execute(
    pipeline,
    run,
    lease,
    action = null,
    verifyProviderPolicies = false,
  ) {
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
      run.executionProcess === null &&
      run.executionResource == null
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
    const selected = selectedRoleAdapters(pipeline, run, lease);
    const baseRuntime = runtimeFor(pipeline, lease, run, selected);
    if (stopPending(run))
      return reconcileOperatorStop({
        cleanupResources: (current) => cleanupExecutionResource(current, lease),
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
    }
    run = await cleanupExecutionResource(run, lease);
    if (
      configurationFailure !== null &&
      !stopPending(run) &&
      run.activeTurn === null
    ) {
      return pauseForProjectConfiguration(run, lease);
    }
    if (verifyProviderPolicies && run.pause?.reason !== "environment_blocked") {
      const migrationRequired = Object.entries(run.providerPolicies).some(
        ([role, receipt]) => role !== "arbiter" && receipt === null,
      );
      for (const [role, adapter] of Object.entries(selected)) {
        if (role !== "arbiter") await adapter.probe();
      }
      if (migrationRequired) {
        run = await runStore.loadRun(run.runId);
        if (pipeline.prepareRecovery !== undefined && runStore.loadRunHistory) {
          const history = await runStore.loadRunHistory(run.runId);
          if (!isDeepStrictEqual(history.run, run)) {
            throw new RunnerError(
              "Run changed before provider policy recovery inspection.",
              { code: "ERR_RUN_REVISION_CHANGED" },
            );
          }
          pipeline.prepareRecovery(run, history);
        }
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
        cleanupResources: (current) => cleanupExecutionResource(current, lease),
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
      cleanupResources: (current) => cleanupExecutionResource(current, lease),
      run: current,
      pipeline,
      lease,
      runStore,
      publish,
      runtime: runtimeFor(
        pipeline,
        lease,
        current,
        selectedRoleAdapters(pipeline, current, lease),
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
        await withStopReconciliationLease(
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

  async function withStopReconciliationLease(run, operation, executionLease) {
    const current = await runStore.loadRun(run.runId);
    const { pipeline } = pipelineForRun(current);
    let ownership = heldWorktreeLeases.get(current.runId);
    if (
      stopPending(current) &&
      pipeline.classifyStopCheckpoint?.(
        current,
        await runStore.loadStopCheckpoint(current.runId),
      ) === "pre-work" &&
      ownership === undefined
    ) {
      return operation(current);
    }
    if (!pipelineRequiresWorktreeLease(current.pipelineId)) {
      return operation(current);
    }
    if (ownership === undefined) {
      ownership = {
        lease: await runStore.acquireWorktreeLease(
          current.projectPath,
          current.runId,
        ),
        projectPath: current.projectPath,
        runId: current.runId,
      };
      heldWorktreeLeases.set(current.runId, ownership);
    } else if (ownership.projectPath !== current.projectPath) {
      throw new RunnerError("Held worktree lease boundary changed.", {
        code: "ERR_RUN_PATH_CHANGED",
      });
    }
    return withHeldWorktreeLease(
      ownership,
      () => operation(current),
      executionLease,
    );
  }

  async function releaseWorktreeLease(ownership, executionLease) {
    for (let attempt = 0; ; attempt += 1) {
      try {
        await releaseHeldWorktreeLease(ownership);
        return;
      } catch (cause) {
        if (
          cause?.code !== "ERR_STOP_RECONCILIATION_REQUIRED" ||
          executionLease === undefined ||
          attempt >= 4
        ) {
          throw cause;
        }
        try {
          await reconcilePendingStop(executionLease, ownership.runId);
        } catch (reconciliationCause) {
          // Settlement may have committed before its public activity failed.
          // Release only if durable state now permits it, then retain the
          // reconciliation failure as the operation's primary result.
          try {
            await releaseHeldWorktreeLease(ownership);
          } catch {}
          throw reconciliationCause;
        }
      }
    }
  }

  async function releaseHeldWorktreeLease(ownership) {
    await ownership.lease.release();
    if (heldWorktreeLeases.get(ownership.runId) === ownership) {
      heldWorktreeLeases.delete(ownership.runId);
    }
  }

  async function withWorktreeLease(run, operation, executionLease) {
    if (!pipelineRequiresWorktreeLease(run.pipelineId)) {
      return operation();
    }
    const ownership = {
      lease: await runStore.acquireWorktreeLease(run.projectPath, run.runId),
      projectPath: run.projectPath,
      runId: run.runId,
    };
    heldWorktreeLeases.set(run.runId, ownership);
    return withHeldWorktreeLease(ownership, operation, executionLease);
  }

  async function withHeldWorktreeLease(ownership, operation, executionLease) {
    let operationFailure = null;
    try {
      return await operation();
    } catch (cause) {
      operationFailure = cause;
      throw cause;
    } finally {
      try {
        await releaseWorktreeLease(ownership, executionLease);
      } catch (cause) {
        if (isProcessContainmentFailure(operationFailure)) {
          throw operationFailure;
        }
        throw cause;
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
        storedRun.executionProcess === null &&
        storedRun.executionResource == null
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
    let capabilityFailure = null;
    if ((resolved.trustedValidation?.commands.length ?? 0) > 0) {
      try {
        await trustedValidation.preflight({
          projectPath,
          snapshot: resolved.trustedValidation,
          storageForbiddenPaths: storageForbiddenPaths({
            projectPath,
            taskPath,
          }),
        });
      } catch (cause) {
        if (
          ![
            "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
            "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE",
          ].includes(cause?.code)
        )
          throw cause;
        capabilityFailure = cause;
      }
    }
    let providerPolicies = Object.fromEntries(
      Object.keys(resolved.roles).map((role) => [role, null]),
    );
    if (capabilityFailure === null) {
      providerPolicies = await probeRequiredRoles(
        pipeline,
        resolved.roles,
        adapters,
        normalized.sourceSession,
        providers,
      );
    }
    const pipelineState = pipeline.workflow.createState({
      artifactRoot: resolved.artifactRoot,
      proactiveClarification: normalized.proactiveClarification,
      settings: resolved.settings,
      ...(resolved.trustedValidation === undefined
        ? {}
        : { trustedValidation: resolved.trustedValidation }),
    });
    let created = await runStore.createRun({
      ...(createOptions.runId === undefined
        ? {}
        : { runId: createOptions.runId }),
      pipelineId: pipeline.id,
      pipelineStateVersion: pipeline.stateVersion,
      projectPath,
      taskPath,
      projectConfigurationProtection: projectConfiguration?.protection ?? null,
      roles: resolved.roles,
      providerPolicies,
      availabilityPolicy: resolved.availabilityPolicy,
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
      if (capabilityFailure !== null) {
        const state = await runStore.transitionRun(created.lease, {
          pipelineState: {
            ...created.state.pipelineState,
            workflowState: "WAITING_FOR_USER",
          },
          pause: {
            reason: "environment_blocked",
            code: capabilityFailure.code,
            explanation:
              "The frozen trusted execution request is unavailable. Repair the environment and resume; changing declarations requires a new run.",
            evidence: [
              "Trusted execution preflight failed before provider work.",
            ],
          },
        });
        created = { ...created, state };
      }
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
    let executionFailure = null;
    try {
      if (created.state.pause?.reason !== "environment_blocked") {
        await withWorktreeLease(
          created.state,
          () => execute(pipeline, created.state, created.lease),
          created.lease,
        );
      }
    } catch (cause) {
      executionFailure = cause;
      throw cause;
    } finally {
      try {
        await releaseRunLease(created.lease, created.state.runId);
      } catch (cause) {
        if (isProcessContainmentFailure(executionFailure)) {
          throw executionFailure;
        }
        throw cause;
      }
    }
    return result(await runStore.loadRun(created.state.runId));
  }

  async function resumeLeased(normalized, lease) {
    if (normalized.stopCheckpointRevision !== null) {
      const current = await runStore.loadRun(normalized.runId);
      if (
        !stopPending(current) ||
        current.stopRequest.checkpoint.revision !==
          normalized.stopCheckpointRevision
      ) {
        return current;
      }
    }
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
    if (
      normalized.stopCheckpointRevision !== null &&
      (!stopPending(recovered) ||
        recovered.stopRequest.checkpoint.revision !==
          normalized.stopCheckpointRevision)
    ) {
      return recovered;
    }
    if (stopPending(recovered)) {
      return withStopReconciliationLease(
        recovered,
        (current) => execute(pipeline, current, lease, null, true),
        lease,
      );
    }
    if (configurationChanged) {
      return withWorktreeLease(
        recovered,
        () => execute(pipeline, recovered, lease, null, true),
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
        await validatePersistedBoundary(recovered);
        return execute(pipeline, recovered, lease, normalized.action, true);
      },
      lease,
    );
  }

  async function resume(input) {
    const normalized = normalizeResumeInput(input);
    const lease = await runStore.acquireRunLease(normalized.runId);
    let executionFailure = null;
    try {
      await resumeLeased(normalized, lease);
    } catch (cause) {
      executionFailure = cause;
      throw cause;
    } finally {
      try {
        await releaseRunLease(lease, normalized.runId);
      } catch (cause) {
        if (isProcessContainmentFailure(executionFailure)) {
          throw executionFailure;
        }
        throw cause;
      }
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
