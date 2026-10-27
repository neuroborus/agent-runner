import { createHash, randomUUID } from "node:crypto";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  inspectOwnedSessionProcesses,
  OUTPUT_EXHAUSTED_DISPOSITION,
  PROVIDER_REGISTRY,
  terminateOwnedProcess,
} from "../agents/index.js";
import { createClarificationService } from "../clarifications/index.js";
import {
  assertProjectConfigurationProtected,
  DEFAULT_ARTIFACT_ROOT,
  loadProjectConfiguration,
  loadRunnerConfiguration,
  PROJECT_CONFIG_FILENAME,
  resolvePipelineConfiguration,
  resolvePipelineSettings,
} from "../config/index.js";
import { createGitService } from "../git/index.js";
import {
  getPipeline as registeredPipeline,
  resolveStopBoundary,
} from "../pipeline-registry.js";
import { createWorkspaceService } from "../workspace/index.js";
import {
  createRunStore,
  deepFreeze,
  projectObservations,
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
import { createDispositionPolicy } from "./dispositions.js";
import { createAuthenticationPolicy } from "./authentication.js";
import { createInactivityCoordinator } from "./inactivity.js";
import { createAvailabilityCoordinator } from "./availability.js";
import { pipelineForRun as resolvePipelineForRun } from "./migration.js";
import {
  bindWorkspace,
  directorySafety,
  inspectBoundWorkspace,
  workspaceSelection,
} from "./workspace.js";
import { inspectTrustedRequirements } from "./trusted-requirements.js";
import { createPlanProgressPublisher } from "./plan-progress.js";
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

const RUNNER_OPTION_FIELDS = new Set([
  "inactivityTimers",
  "availabilityClock",
  "availabilityWait",
  "adapters",
  "clarifications",
  "git",
  "workspace",
  "getPipeline",
  "inspectSessionProcesses",
  "loadConfiguration",
  "onActivity",
  "providers",
  "runStore",
  "trustedValidation",
]);

function fileHash(content) {
  return createHash("sha256").update(content).digest("hex");
}

async function inputFile(path, { optional = false, workspace, taskPath } = {}) {
  let content;
  try {
    content = workspace
      ? await workspace.readFile({ path, projectPath: taskPath, optional })
      : await readFile(path, "utf8");
  } catch (cause) {
    if (optional && cause?.code === "ENOENT") {
      return null;
    }
    throw cause;
  }
  return content === null
    ? null
    : Object.freeze({ path, content, hash: fileHash(content) });
}

async function readInputs(
  pipeline,
  taskPath,
  directoryWorkspace,
  { workspace, settings, projectPath, stateRoot } = {},
) {
  const extra =
    pipeline.resolveTaskInputs?.({ settings, projectPath, taskPath }) ?? {};
  const inputs = Object.fromEntries(
    await Promise.all(
      Object.entries(extra).map(async ([name, definition]) => [
        name,
        await inputFile(definition.path, {
          optional: definition.optional,
          workspace,
          taskPath: dirname(definition.path),
        }),
      ]),
    ),
  );
  const selection = pipeline.resolveWorkspace?.({
    settingOverrides: settings ?? {},
    projectPath,
    taskPath,
  });
  if (
    selection &&
    (selection.inputPaths?.length ?? 0) + (selection.sourcePaths?.length ?? 0) >
      0
  ) {
    const snapshot = await workspace.snapshotInputs({
      paths: [
        ...(selection.inputPaths ?? []),
        ...(selection.sourcePaths ?? []),
      ],
      stateRoot: resolve(stateRoot),
    });
    inputs.declaredInputsHash = fileHash(
      JSON.stringify({
        bindings: snapshot.bindings,
        entries: snapshot.entries,
      }),
    );
  }
  return Object.freeze({
    ...inputs,
    ...Object.fromEntries(
      await Promise.all(
        Object.entries(pipeline.taskInputs).map(async ([name, definition]) => [
          name,
          await inputFile(join(taskPath, definition.filename), {
            optional: definition.optional,
            workspace: directoryWorkspace,
            taskPath,
          }),
        ]),
      ),
    ),
  });
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

export function pipelineRequiresWorktreeLease(pipelineId, workspace) {
  return (
    (workspace ?? registeredPipeline(pipelineId)?.workspace)?.lease ===
    "exclusive"
  );
}

function isResourceOwnershipFailure(cause) {
  return (
    cause?.executionResourceRetained === true ||
    cause?.code === "ERR_EXECUTION_RESOURCE_UNVERIFIABLE"
  );
}

function isExecutionOwnershipFailure(cause) {
  return (
    isResourceOwnershipFailure(cause) ||
    [
      "ERR_EXECUTION_PROCESS_ACTIVE",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    ].includes(cause?.code)
  );
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
    typeof providers.supportsClientAttribution !== "function" ||
    typeof providers.validateExecutionOptions !== "function" ||
    typeof providers.supportsSourceSessionFork !== "function" ||
    typeof providers.classifyFailure !== "function" ||
    typeof providers.isDiagnosticClass !== "function"
  ) {
    throw new RunnerError("Runner services are invalid.", {
      code: "ERR_INVALID_RUNNER_OPTIONS",
    });
  }
  const adapters = options.adapters;
  const clarifications = options.clarifications ?? createClarificationService();
  const git = options.git ?? createGitService();
  const workspace = options.workspace ?? createWorkspaceService();
  const getPipeline = options.getPipeline ?? registeredPipeline;
  const pipelineForRun = (run, pipeline, settings) =>
    resolvePipelineForRun(
      run,
      pipeline ?? getPipeline(run.pipelineId),
      settings,
    );
  const requiresLease = (run) =>
    run.workspace?.lease === "exclusive" ||
    (run.workspace == null &&
      getPipeline(run.pipelineId)?.workspace?.lease === "exclusive");
  const leasePath = (run) => run.workspace?.leasePath ?? run.projectPath;
  const publishPlanProgress = createPlanProgressPublisher({ git });
  const inspectSessionProcesses =
    options.inspectSessionProcesses ?? inspectOwnedSessionProcesses;
  const loadConfiguration =
    options.loadConfiguration ?? (() => loadRunnerConfiguration(providers));
  const onActivity = options.onActivity ?? (async () => {});
  const runStore = options.runStore ?? createRunStore({ resolveStopBoundary });
  const trustedValidation =
    options.trustedValidation ??
    createTrustedValidationService({ git, workspace });
  // Stop recovery must reuse the exact in-process reservation; failed
  // reconciliation keeps its handle for same-owner retry and its durable
  // lease for safe reclamation after owner loss.
  const heldWorktreeLeases = new Map();
  const retainedRunLeases = new Map();
  const defaultAdapterSets = new Map();
  if (
    (adapters !== undefined && !isRecord(adapters)) ||
    !isRecord(clarifications) ||
    !isRecord(git) ||
    !isRecord(workspace) ||
    typeof getPipeline !== "function" ||
    typeof inspectSessionProcesses !== "function" ||
    typeof loadConfiguration !== "function" ||
    typeof onActivity !== "function" ||
    (options.inactivityTimers !== undefined &&
      (!isRecord(options.inactivityTimers) ||
        typeof options.inactivityTimers.setTimeout !== "function" ||
        typeof options.inactivityTimers.clearTimeout !== "function")) ||
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

  function validateClientAttribution(run) {
    const unsupportedBackend = Object.values(run.roles)
      .map(({ backend }) => backend)
      .find(
        (backend) =>
          !providers.supportsClientAttribution(backend, run.clientAttribution),
      );
    if (unsupportedBackend !== undefined) {
      throw new RunnerError(
        `Client attribution is not supported by active backend: ${unsupportedBackend}.`,
        { code: "ERR_UNSUPPORTED_CLIENT_ATTRIBUTION" },
      );
    }
  }

  function adaptersFor(run) {
    validateClientAttribution(run);
    if (adapters !== undefined) return adapters;
    let selected = defaultAdapterSets.get(run.clientAttributionFingerprint);
    if (selected === undefined) {
      selected = defaultAdapters(run.clientAttribution, providers);
      defaultAdapterSets.set(run.clientAttributionFingerprint, selected);
    }
    return selected;
  }

  async function publish(activity, run) {
    const pipeline = getPipeline(run.pipelineId);
    // Derived output cannot interrupt stop reconciliation. Regenerate after
    // durable settlement; consumed effects also defer publication below.
    if (!stopPending(run))
      await publishPlanProgress(
        run,
        pipeline.projections.planProgress?.(run) ?? null,
      );
    if (activity === undefined || activity === null) {
      return;
    }
    await onActivity(
      Object.freeze({
        runId: run.runId,
        revision: run.revision,
        recordedAt: run.updatedAt,
        ...activity,
        ...(pipeline.projections.planProgress === undefined
          ? {}
          : {
              refinementProgress: deepFreeze(
                pipeline.projections.status(run).refinementProgress,
              ),
            }),
      }),
    );
  }

  async function guardProjectConfiguration(run) {
    await assertProjectConfigurationProtected({
      inspectPath: (input) =>
        (run.workspace?.kind === "directory" ? workspace : git).inspectPath(
          input,
        ),
      workspaceKind: run.workspace?.kind ?? "git",
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

  async function pauseForWorkspaceDrift(run, lease) {
    if (run.pause?.reason === "workspace_changed") return run;
    const activity = {
      actor: "runner",
      phase: "workspace",
      kind: "changed",
      message:
        "Frozen workspace inputs or controls changed; execution stopped.",
    };
    const next = await runStore.transitionRun(
      lease,
      {
        pipelineState: {
          ...run.pipelineState,
          workflowState: "WAITING_FOR_USER",
        },
        pause: { reason: "workspace_changed", code: "ERR_WORKSPACE_DRIFT" },
        activeTurn: null,
      },
      { activity },
    );
    await publish(activity, next);
    return next;
  }

  function storageForbiddenPaths(run) {
    const base = [run.projectPath, run.taskPath, runStore.rootPath].filter(
      (path) => typeof path === "string",
    );
    if (run.workspace?.policy == null) return base;
    const roots = [
      ...new Set(
        [
          ...base,
          ...Object.values(run.workspace.policy).flatMap((value) =>
            Array.isArray(value) ? value : [],
          ),
        ].filter((path) => typeof path === "string"),
      ),
    ];
    return roots.filter(
      (path) =>
        !roots.some((root) => {
          if (root === path) return false;
          const name = relative(root, path);
          return (
            !isAbsolute(name) && name !== ".." && !name.startsWith(`..${sep}`)
          );
        }),
    );
  }

  async function recordAdapterCleanupPending(run, lease) {
    if (
      run.executionResource === null ||
      run.preparation != null ||
      run.executionProcess !== null ||
      stopPending(run)
    )
      return;
    const activity = {
      actor: "runner",
      phase: "environment",
      kind: "cleanup-pending",
      message:
        "Agent environment_cleanup remains pending before checkpoint acceptance.",
    };
    const next = await runStore.transitionRun(
      lease,
      {},
      { activity, expectedRevision: run.revision },
    );
    await publish(activity, next);
  }

  async function cleanupExecutionResource(run, lease) {
    if (run.executionResource == null) return run;
    const adapterRecovery = providers.ids
      .map((id) => providers.get(id).resources)
      .find(
        (owner) => owner?.identity === run.executionResource.commandIdentity,
      )?.recover;
    const recover = adapterRecovery ?? trustedValidation.recoverResources;
    if (
      run.preparation != null ||
      run.executionProcess !== null ||
      typeof recover !== "function"
    ) {
      throw new RunnerError(
        "Execution storage cleanup requires verified process retirement.",
        { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
      );
    }
    try {
      const forbiddenPaths = storageForbiddenPaths(run);
      if (
        adapterRecovery !== undefined &&
        run.workspace?.kind === "directory"
      ) {
        const { kind: _kind, ...declarations } = run.workspace.policy;
        // Cleanup protects current controls without accepting frozen inputs.
        // Deleted inputs still contribute their paths and discovered controls.
        const inspection = await workspace.inspect({
          ...declarations,
          inputPaths: [],
          sourcePaths: [],
          configurationPaths: [],
          artifactPaths: [
            ...declarations.artifactPaths,
            ...declarations.inputPaths,
            ...declarations.sourcePaths,
            ...declarations.configurationPaths,
          ],
        });
        forbiddenPaths.push(...inspection.controlPaths);
      }
      await recover({
        resource: run.executionResource,
        projectPath: run.projectPath,
        workspacePolicy: run.workspace?.policy ?? undefined,
        storageForbiddenPaths: forbiddenPaths,
        onResource: (value) => runStore.recordExecutionResource(lease, value),
      });
    } catch (cause) {
      try {
        if (adapterRecovery !== undefined)
          await recordAdapterCleanupPending(
            await runStore.loadRun(run.runId),
            lease,
          );
      } finally {
        throw cause;
      }
    }
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
    const safety =
      run.workspace?.kind === "directory"
        ? directorySafety(run.workspace, workspace)
        : git;
    const authentication = createAuthenticationPolicy({ providers });
    const outputExhaustion = createDispositionPolicy({
      providers,
      disposition: OUTPUT_EXHAUSTED_DISPOSITION,
    });
    const availability =
      monitor === undefined
        ? undefined
        : createAvailabilityCoordinator({
            runId: run.runId,
            lease,
            runStore,
            providers,
            git: safety,
            publish,
            monitor,
            clock: options.availabilityClock,
            wait: options.availabilityWait,
            validateRun: pipeline.workflow.validateRun,
            initialRun: run,
          });
    const inactivity =
      monitor === undefined
        ? undefined
        : createInactivityCoordinator({
            runId: run.runId,
            lease,
            runStore,
            git: safety,
            monitor,
            publish,
            initialRun: run,
            timers: options.inactivityTimers,
          });
    async function reconcileProviderResponse(options) {
      if (providerResponseRole === null) return undefined;
      const recovered = await inactivity.completed(
        providerResponseRole,
        options,
      );
      const next = await availability.completed(
        providerResponseRole,
        recovered === undefined
          ? options
          : { expectedRevision: recovered.revision },
      );
      providerResponseRole = null;
      return next ?? recovered;
    }
    async function checkConfiguration() {
      try {
        await guardProjectConfiguration(run);
      } catch (cause) {
        onConfigurationFailure(cause);
        throw cause;
      }
    }
    async function withResourceRetention(operation) {
      try {
        return await operation();
      } catch (cause) {
        // Post-operation drift checks may replace a cleanup failure. Preserve
        // durable ownership on the final error so lease handles remain usable.
        const current = await runStore.loadRun(run.runId);
        if (current.executionResource !== null)
          cause.executionResourceRetained = true;
        throw cause;
      }
    }
    return Object.freeze({
      authentication,
      outputExhaustion,
      availability,
      inactivity,
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
                  canReadFiles: async (request) => {
                    await monitor.check();
                    return adapter.canReadFiles(request);
                  },
                  async run(request) {
                    await checkConfiguration();
                    const directory = run.workspace?.kind === "directory";
                    const before = directory ? await safety.snapshot() : null;
                    if (directory && request.access === "local-commit")
                      throw new RunnerError(
                        "Directory workflows cannot request Git effects.",
                        { code: "ERR_UNSAFE_WORKSPACE_ACCESS" },
                      );
                    try {
                      const response = await monitor.invoke(
                        (value) =>
                          inactivity.invoke(
                            role,
                            (attempt) => adapter.run(attempt),
                            value,
                          ),
                        {
                          ...request,
                          ...(directory
                            ? { workspacePolicy: run.workspace.policy }
                            : {}),
                          storageForbiddenPaths: storageForbiddenPaths(run),
                          onResource: (value) =>
                            runStore.recordExecutionResource(lease, value),
                        },
                      );
                      providerResponseRole = role;
                      return response;
                    } catch (cause) {
                      if (
                        authentication.eligible(cause) ||
                        outputExhaustion.eligible(cause)
                      ) {
                        providerResponseRole = role;
                      }
                      // Keep stronger provider failures intact while preventing
                      // fingerprints or turn settlement over retained storage.
                      const current = await runStore.loadRun(run.runId);
                      if (current.executionResource !== null) {
                        cause.executionResourceRetained = true;
                        try {
                          await recordAdapterCleanupPending(current, lease);
                        } finally {
                          throw cause;
                        }
                      }
                      throw cause;
                    } finally {
                      await checkConfiguration();
                      const retired = directory
                        ? await runStore.loadRun(run.runId)
                        : null;
                      if (
                        directory &&
                        retired.executionResource === null &&
                        retired.executionProcess === null &&
                        retired.preparation == null
                      ) {
                        const after = await safety.snapshot();
                        workspace.assertUnchanged({
                          before,
                          after,
                          allowOutputs: request.access === "workspace-write",
                        });
                      }
                    }
                  },
                },
              ]),
            ),
      clarifications:
        run.workspace?.kind !== "directory"
          ? clarifications
          : Object.freeze({
              ...clarifications,
              async ensureTranscript(request) {
                const root = await workspace.exclusionPath({
                  workspacePath: request.artifactRoot,
                });
                const marker = await workspace.inspectPath({
                  projectPath: root,
                  path: join(root, ".git"),
                });
                if (marker.exists) {
                  const artifact = await git.inspectPath({
                    projectPath: root,
                    path: request.transcriptPath,
                  });
                  if (artifact.tracked || !artifact.ignored)
                    throw new RunnerError(
                      "Repository-local artifact path must be ignored and untracked.",
                      { code: "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED" },
                    );
                }
                return clarifications.ensureTranscript(request);
              },
            }),
      workspace: Object.freeze({
        kind: run.workspace?.kind ?? "git",
        policy: run.workspace?.policy ?? null,
        snapshot: (...args) => safety.snapshot(...args),
        assertUnchanged: (...args) => safety.assertUnchanged(...args),
        inspectPath: (...args) => safety.inspectPath(...args),
      }),
      git:
        run.workspace?.kind === "directory"
          ? undefined
          : monitor === undefined
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
                  projectPath: run.projectPath,
                  workspacePolicy: run.workspace?.policy ?? undefined,
                  storageForbiddenPaths: storageForbiddenPaths(run),
                });
                await validatePersistedBoundary(run);
              },
              inspectRequirements: (request) =>
                withResourceRetention(() =>
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
                ),
              execute: (request) =>
                withResourceRetention(async () => {
                  await checkConfiguration();
                  if (run.workspace?.kind === "directory")
                    await validatePersistedBoundary(run);
                  try {
                    return await monitor.invoke(
                      (value) =>
                        trustedValidation.execute({
                          ...value,
                          projectPath: run.projectPath,
                          workspacePolicy: run.workspace?.policy ?? undefined,
                          storageForbiddenPaths: storageForbiddenPaths(run),
                          onResource: (resource) =>
                            runStore.recordExecutionResource(lease, resource),
                        }),
                      request,
                    );
                  } finally {
                    await checkConfiguration();
                    await validatePersistedBoundary(run);
                  }
                }),
            },
      preservation:
        run.workspace?.kind === "directory"
          ? undefined
          : Object.freeze({
              async capture(request) {
                await monitor?.check();
                await checkConfiguration();
                const current = await runStore.loadRun(run.runId);
                const saved = current.preservationRecords.some(
                  ({ id }) => id === request.preservationId,
                )
                  ? await runStore.readPreservation(
                      run.runId,
                      request.preservationId,
                    )
                  : null;
                const capture = (value) =>
                  runStore.capturePreservation(lease, {
                    ...value,
                    expectedRevision:
                      saved?.binding.revision ?? current.revision,
                    worktreeLease: heldWorktreeLeases.get(run.runId)?.lease,
                    git,
                  });
                if (monitor === undefined) await capture(request);
                else await monitor.invoke(capture, request);
                return runStore.loadRun(run.runId);
              },
              async restore(request) {
                await monitor?.check();
                await checkConfiguration();
                const restore = (value) =>
                  runStore.restorePreservation(lease, {
                    ...value,
                    worktreeLease: heldWorktreeLeases.get(run.runId)?.lease,
                    git,
                  });
                const receipt =
                  monitor === undefined
                    ? await restore(request)
                    : await monitor.invoke(restore, request);
                return { run: await runStore.loadRun(run.runId), receipt };
              },
              async reconcile(request) {
                const receipt = await runStore.reconcilePreservation(lease, {
                  ...request,
                  worktreeLease: heldWorktreeLeases.get(run.runId)?.lease,
                  git,
                });
                return { run: await runStore.loadRun(run.runId), receipt };
              },
              read: (preservationId) =>
                runStore.readPreservation(run.runId, preservationId, {
                  includeSources: true,
                }),
            }),
      readInputs: ({ taskPath }) =>
        readInputs(
          pipeline,
          taskPath,
          run.workspace?.kind === "directory" ? workspace : undefined,
          {
            workspace,
            settings: run.pipelineState.settings,
            projectPath: run.projectPath,
            stateRoot: runStore.rootPath,
          },
        ),
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
      async finishAgentTurn(activeTurn, { repositoryReconciled = true } = {}) {
        await reconcileProviderResponse({ repositoryReconciled });
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
        if (run.workspace?.kind === "directory")
          throw new RunnerError(
            "Directory workflows cannot settle Git effects.",
            { code: "ERR_UNSAFE_WORKSPACE_ACCESS" },
          );
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
              latest.stopRequest?.effectiveTiming === "after-current-commit" &&
                isDeepStrictEqual(
                  pipeline.resolveStopBoundary?.(
                    deepFreeze({ ...latest, ...patch }),
                  ),
                  latest.stopRequest.targetBoundary,
                ),
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
    return roleAdapters(
      run,
      pipeline,
      adaptersFor(run),
      providers,
      (role, receipt) => {
        const operation = pendingPolicyReceipt.then(async () => {
          const expected = currentPolicies[role];
          if (expected !== null) {
            if (!isDeepStrictEqual(expected, receipt)) {
              throw new RunnerError(
                `Provider policy changed for role ${role}.`,
                { code: "ERR_PROVIDER_POLICY_CHANGED" },
              );
            }
            return;
          }
          const next = await runStore.recordProviderPolicy(
            lease,
            role,
            receipt,
          );
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
      },
    );
  }

  async function execute(
    pipeline,
    run,
    lease,
    action = null,
    verifyProviderPolicies = false,
    dispatch = null,
    onRecoveryStage = () => {},
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
      run.preparation == null &&
      run.executionProcess === null &&
      run.executionResource == null
    ) {
      return pauseForProjectConfiguration(run, lease);
    }
    if (
      stopPending(run) &&
      pipeline.prepareRecovery !== undefined &&
      runStore.loadRunHistory
    ) {
      const history = await runStore.loadRunHistory(run.runId, {
        stream: true,
      });
      if (!isDeepStrictEqual(history.run, run)) {
        throw new RunnerError("Run changed before recovery inspection.", {
          code: "ERR_RUN_REVISION_CHANGED",
        });
      }
      await pipeline.prepareRecovery(run, history);
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
        onRecoveryStage,
        inspectSessionProcesses,
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
    if (run.preparation != null) {
      onRecoveryStage("process-recovery");
      run = await runStore.recoverPreparation(lease, (owner, inspect) =>
        terminateOwnedProcess(owner.pid, inspect, { inspectSessionProcesses }),
      );
    }
    if (run.executionProcess !== null) {
      onRecoveryStage("process-recovery");
      const owner = await runStore.inspectExecutionProcess(run.runId);
      await terminateOwnedProcess(
        owner.pid,
        () => runStore.inspectExecutionProcess(run.runId),
        { inspectSessionProcesses },
      );
      run = await runStore.recordExecutionProcess(lease, null);
      try {
        await guardProjectConfiguration(run);
      } catch (cause) {
        if (cause?.code !== "ERR_PROJECT_CONFIGURATION_CHANGED") throw cause;
        configurationFailure = cause;
      }
    }
    onRecoveryStage("resource-recovery");
    run = await cleanupExecutionResource(run, lease);
    onRecoveryStage("state-recovery");
    if (run.observations?.attempts.at(-1).status === "active")
      run = await runStore.recoverRun(lease);
    if (
      ["project_configuration_changed", "workspace_changed"].includes(
        run.pause?.reason,
      ) &&
      !stopPending(run)
    ) {
      // Saved safety blockers permit owned cleanup, never checkpoint replay.
      return run;
    }
    if (
      configurationFailure !== null &&
      !stopPending(run) &&
      (run.activeTurn === null || run.workspace?.kind === "directory")
    ) {
      return pauseForProjectConfiguration(run, lease);
    }
    if (run.workspace?.kind === "directory") {
      try {
        await validatePersistedBoundary(run);
      } catch (cause) {
        if (!cause?.code?.startsWith("ERR_WORKSPACE_")) throw cause;
        return pauseForWorkspaceDrift(run, lease);
      }
    }
    onRecoveryStage("checkpoint-continuation");
    if (verifyProviderPolicies && run.pause?.reason !== "environment_blocked") {
      const migrationRequired = Object.entries(run.providerPolicies).some(
        ([role, receipt]) => role !== "arbiter" && receipt === null,
      );
      for (const [role, adapter] of Object.entries(selected)) {
        if (role !== "arbiter") await adapter.probe();
      }
      if (migrationRequired) {
        run = await runStore.loadRun(run.runId);
      }
    }
    if (dispatch !== null)
      run = await runStore.recordRecoveryDispatch(lease, dispatch, true);
    if (pipeline.prepareRecovery !== undefined && runStore.loadRunHistory) {
      const history = await runStore.loadRunHistory(run.runId, {
        stream: true,
      });
      if (!isDeepStrictEqual(history.run, run)) {
        throw new RunnerError("Run changed before checkpoint continuation.", {
          code: "ERR_RUN_REVISION_CHANGED",
        });
      }
      await pipeline.prepareRecovery(run, history);
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
      await publishPlanProgress(
        run,
        pipeline.projections.planProgress?.(run) ?? null,
      );
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
        onRecoveryStage,
        inspectSessionProcesses,
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
      inspectSessionProcesses,
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
        try {
          await withStopReconciliationLease(
            current,
            () => reconcilePendingStop(lease, runId),
            lease,
          );
        } catch (reconciliationCause) {
          // Publication may fail after durable settlement. The state-owned
          // release still rejects any pending stop or uncertain execution.
          try {
            await lease.release();
          } catch {}
          throw reconciliationCause;
        }
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
    if (!requiresLease(current)) {
      return operation(current);
    }
    if (ownership === undefined) {
      ownership = {
        lease: await runStore.acquireWorktreeLease(
          leasePath(current),
          current.runId,
        ),
        projectPath: leasePath(current),
        runId: current.runId,
      };
      heldWorktreeLeases.set(current.runId, ownership);
    } else if (ownership.projectPath !== leasePath(current)) {
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
    if (!requiresLease(run)) {
      return operation();
    }
    const ownership = heldWorktreeLeases.get(run.runId) ?? {
      lease: await runStore.acquireWorktreeLease(leasePath(run), run.runId),
      projectPath: leasePath(run),
      runId: run.runId,
    };
    if (ownership.projectPath !== leasePath(run))
      throw new RunnerError("Held worktree boundary changed.", {
        code: "ERR_RUN_PATH_CHANGED",
      });
    heldWorktreeLeases.set(run.runId, ownership);
    return withHeldWorktreeLease(
      ownership,
      async () => {
        if (run.workspace?.kind === "directory")
          await validatePersistedBoundary(run, { frozenContent: false });
        return operation();
      },
      executionLease,
    );
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
        if (isExecutionOwnershipFailure(operationFailure)) {
          throw operationFailure;
        }
        throw cause;
      }
    }
  }

  async function discoverWorkspaceBoundary(pipeline, input, configuration) {
    const boundary = await runStore.validateStateBoundary(input);
    const settings = resolvePipelineSettings(
      pipeline.id,
      configuration,
      input.settingOverrides,
      providers,
    );
    const selection = workspaceSelection(pipeline, {
      ...input,
      ...boundary,
      settingOverrides: settings,
    });
    if (selection.kind === "directory") return boundary;
    const configurationPath = resolve(
      boundary.projectPath,
      input.projectConfigurationPath ??
        join(DEFAULT_ARTIFACT_ROOT, PROJECT_CONFIG_FILENAME),
    );
    const localPath = relative(boundary.projectPath, configurationPath);
    if (
      localPath !== "" &&
      !isAbsolute(localPath) &&
      localPath !== ".." &&
      !localPath.startsWith(`..${sep}`) &&
      (
        await workspace.inspectPath({
          projectPath: boundary.projectPath,
          path: configurationPath,
        })
      ).exists
    )
      return boundary;
    return runStore.validateStateBoundary({
      ...boundary,
      projectPath: await workspace.exclusionPath({
        workspacePath: boundary.projectPath,
      }),
    });
  }

  async function validateBoundary(input, selection) {
    const projectPath = assertNonEmptyString(
      input?.projectPath,
      "run.projectPath",
    );
    const taskPath = assertNonEmptyString(input?.taskPath, "run.taskPath");
    if (
      selection === undefined &&
      getPipeline(input.pipelineId)?.resolveWorkspace
    ) {
      const normalized = normalizeRunInput(input, providers);
      const pipeline = getPipeline(input.pipelineId);
      const configuration = await loadConfiguration();
      const boundary = await discoverWorkspaceBoundary(
        pipeline,
        normalized,
        configuration,
      );
      const project = await loadProjectConfiguration({
        configurationPath: normalized.projectConfigurationPath,
        inspectPath: (request) => workspace.inspectPath(request),
        workspaceKind: "directory",
        projectPath: boundary.projectPath,
        providers,
        runnerConfiguration: configuration,
      });
      const resolved = resolvePipelineConfiguration(
        pipeline.id,
        configuration,
        normalized.roleOverrides,
        normalized.executionOverrides,
        normalized.sourceSession,
        project?.configuration ?? null,
        normalized.settingOverrides,
        providers,
      );
      selection = workspaceSelection(pipeline, {
        ...normalized,
        ...boundary,
        settingOverrides: resolved.settings,
      });
      return validateBoundary(
        selection.kind === "directory"
          ? normalized
          : { ...normalized, ...boundary },
        selection,
      );
    }
    selection ??=
      input.pipelineId === undefined
        ? { kind: "git" }
        : workspaceSelection(
            getPipeline(input.pipelineId),
            normalizeRunInput(input, providers),
          );
    if (selection.kind === "directory") {
      const boundary = await runStore.validateStateBoundary({
        projectPath,
        taskPath,
      });
      await workspace.inspect({
        workspacePath: boundary.projectPath,
        taskPath: boundary.taskPath,
        stateRoot: resolve(runStore.rootPath),
      });
      await runStore.validateStateBoundary({
        projectPath: await workspace.exclusionPath({
          workspacePath: boundary.projectPath,
        }),
        taskPath: boundary.taskPath,
      });
      return boundary;
    }
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

  async function validatePersistedBoundary(run, { frozenContent = true } = {}) {
    const boundary = await validateBoundary(
      run,
      run.workspace ?? { kind: "git" },
    );
    if (
      boundary.projectPath !== run.projectPath ||
      boundary.taskPath !== run.taskPath
    ) {
      throw new RunnerError(
        `Run ${run.runId} canonical project or task path changed.`,
        { code: "ERR_RUN_PATH_CHANGED" },
      );
    }
    if (run.workspace?.kind === "directory") {
      if (resolve(runStore.rootPath) !== run.workspace.policy.stateRoot)
        throw new RunnerError("Workspace state binding changed.", {
          code: "ERR_RUN_PATH_CHANGED",
        });
      if (
        (await workspace.exclusionPath({ workspacePath: run.projectPath })) !==
        run.workspace.leasePath
      )
        throw new RunnerError("Workspace exclusion key changed.", {
          code: "ERR_RUN_PATH_CHANGED",
        });
      // Retirement needs canonical paths and current control confinement, not
      // acceptance of the inspected bytes. Frozen inputs are checked after
      // verified process/resource recovery and before any new provider work.
      if (frozenContent) await inspectBoundWorkspace(run.workspace, workspace);
    }
  }

  async function result(run) {
    return Object.freeze({
      directoryPath: await runStore.getRunDirectory(run.runId),
      run,
      observations: deepFreeze(projectObservations(run)),
    });
  }

  async function recoverCompatibleRun(
    lease,
    runId,
    { validatePreparedRun, onRecoveryStage = () => {} } = {},
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
        storedRun.preparation == null &&
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
    await validatePersistedBoundary(storedRun, { frozenContent: false });
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
      // Custody binds the issued envelope and original journal prefix. Settle
      // it under that contract before publishing either kind of migration.
      if (storedRun.preparation != null) {
        onRecoveryStage("process-recovery");
        await runStore.recoverPreparation(lease, (owner, inspect) =>
          terminateOwnedProcess(owner.pid, inspect, {
            inspectSessionProcesses,
          }),
        );
        onRecoveryStage("state-recovery");
      }
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
    }
    run = await runStore.recoverRun(lease);
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
    let selection = pipeline.resolveWorkspace
      ? { kind: "directory" }
      : workspaceSelection(pipeline, normalized);
    const initialBoundary = pipeline.resolveWorkspace
      ? null
      : await validateBoundary(normalized, selection);
    const configuration = await loadConfiguration();
    const boundary =
      initialBoundary ??
      (await discoverWorkspaceBoundary(pipeline, normalized, configuration));
    let { projectPath, taskPath } = boundary;
    let projectConfiguration = await loadProjectConfiguration({
      configurationPath: normalized.projectConfigurationPath,
      inspectPath: (options) =>
        (selection.kind === "directory" ? workspace : git).inspectPath(options),
      workspaceKind: selection.kind,
      projectPath,
      providers,
      runnerConfiguration: configuration,
    });
    let resolved;
    const resolveConfiguration = () =>
      resolvePipelineConfiguration(
        pipeline.id,
        configuration,
        normalized.roleOverrides,
        normalized.executionOverrides,
        normalized.sourceSession,
        projectConfiguration?.configuration ?? null,
        normalized.settingOverrides,
        providers,
      );
    try {
      resolved = resolveConfiguration();
      selection = workspaceSelection(pipeline, {
        ...normalized,
        projectPath,
        taskPath,
        settingOverrides: resolved.settings,
      });
      const selectedBoundary = await validateBoundary(
        selection.kind === "directory"
          ? normalized
          : { ...normalized, ...boundary },
        selection,
      );
      projectPath = selectedBoundary.projectPath;
      taskPath = selectedBoundary.taskPath;
      if (
        pipeline.resolveWorkspace &&
        (selection.kind === "git" ||
          (projectConfiguration !== null &&
            projectConfiguration.protection.projectPath !== projectPath))
      ) {
        projectConfiguration = await loadProjectConfiguration({
          configurationPath:
            projectConfiguration?.path ?? normalized.projectConfigurationPath,
          inspectPath: (request) =>
            (selection.kind === "directory" ? workspace : git).inspectPath(
              request,
            ),
          workspaceKind: selection.kind,
          projectPath,
          providers,
          runnerConfiguration: configuration,
        });
        resolved = resolveConfiguration();
        selection = workspaceSelection(pipeline, {
          ...normalized,
          projectPath,
          taskPath,
          settingOverrides: resolved.settings,
        });
        const rebound = await validateBoundary(
          selection.kind === "directory"
            ? normalized
            : { ...normalized, ...boundary },
          selection,
        );
        projectPath = rebound.projectPath;
        taskPath = rebound.taskPath;
      }
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
    const boundWorkspace = await bindWorkspace({
      selection,
      projectPath,
      taskPath,
      taskInputs: pipeline.taskInputs,
      configurationPath: projectConfiguration?.path,
      stateRoot: runStore.rootPath,
      workspace,
    });
    if (boundWorkspace.kind === "directory")
      await runStore.validateStateBoundary({
        projectPath: boundWorkspace.leasePath,
        taskPath,
      });
    let capabilityFailure = null;
    if ((resolved.trustedValidation?.commands.length ?? 0) > 0) {
      try {
        await trustedValidation.preflight({
          projectPath,
          workspacePolicy: boundWorkspace.policy ?? undefined,
          snapshot: resolved.trustedValidation,
          storageForbiddenPaths: storageForbiddenPaths({
            projectPath,
            taskPath,
            workspace: boundWorkspace,
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
        adaptersFor(resolved),
        normalized.sourceSession,
        providers,
        boundWorkspace.policy ?? undefined,
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
      workspace: boundWorkspace,
      projectConfigurationProtection: projectConfiguration?.protection ?? null,
      clientAttribution: resolved.clientAttribution,
      clientAttributionFingerprint: resolved.clientAttributionFingerprint,
      roles: resolved.roles,
      providerPolicies,
      providerInactivityTimeoutMs: resolved.providerInactivityTimeoutMs,
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
        // Process, preparation or resource ownership can prevent release even
        // when another failure replaced the original ownership diagnosis.
        if (
          isExecutionOwnershipFailure(executionFailure) ||
          isExecutionOwnershipFailure(cause) ||
          (await runStore.loadRun(created.state.runId)).executionResource !==
            null
        ) {
          retainedRunLeases.set(created.state.runId, created.lease);
          if (executionFailure !== null) throw executionFailure;
        }
        throw cause;
      }
    }
    return result(await runStore.loadRun(created.state.runId));
  }

  async function resumeLeased(normalized, lease, onRecoveryStage) {
    onRecoveryStage("state-recovery");
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
    } = await recoverCompatibleRun(lease, normalized.runId, {
      onRecoveryStage,
    });
    if (configurationBlocked) return loaded;
    let recovered = loaded;
    const safetyPaused = [
      "project_configuration_changed",
      "workspace_changed",
    ].includes(recovered.pause?.reason);
    if (
      safetyPaused &&
      !stopPending(recovered) &&
      recovered.preparation == null &&
      recovered.executionProcess === null &&
      recovered.executionResource === null
    ) {
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
      onRecoveryStage("worktree-lease");
      return withStopReconciliationLease(
        recovered,
        (current) => {
          onRecoveryStage("checkpoint-continuation");
          return execute(
            pipeline,
            current,
            lease,
            null,
            true,
            null,
            onRecoveryStage,
          );
        },
        lease,
      );
    }
    if (configurationChanged || safetyPaused) {
      onRecoveryStage("worktree-lease");
      return withWorktreeLease(
        recovered,
        () => {
          onRecoveryStage("checkpoint-continuation");
          return execute(
            pipeline,
            recovered,
            lease,
            null,
            true,
            null,
            onRecoveryStage,
          );
        },
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
    onRecoveryStage("worktree-lease");
    return withWorktreeLease(
      recovered,
      async () => {
        onRecoveryStage("checkpoint-continuation");
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
        await validatePersistedBoundary(recovered, { frozenContent: false });
        return execute(
          pipeline,
          recovered,
          lease,
          normalized.action,
          true,
          normalized.dispatch,
          onRecoveryStage,
        );
      },
      lease,
    );
  }

  async function resume(input, { onRecoveryStage = () => {} } = {}) {
    onRecoveryStage("runtime-compatibility");
    const normalized = normalizeResumeInput(input);
    const retained = retainedRunLeases.get(normalized.runId);
    // Taking the private handle synchronously excludes concurrent resumes; all
    // other callers still encounter the live durable lease and are rejected.
    retainedRunLeases.delete(normalized.runId);
    let lease;
    onRecoveryStage("execution-lease");
    try {
      lease = await runStore.acquireRunLease(normalized.runId, retained);
    } catch (cause) {
      // Revalidation never releases a retained handle. Keep it for a later
      // verified retry even when reading the lease or snapshot fails.
      if (retained !== undefined)
        retainedRunLeases.set(normalized.runId, retained);
      throw cause;
    }
    let executionFailure = null;
    try {
      onRecoveryStage("state-recovery");
      const inspected = await runStore.loadRun(normalized.runId);
      if (
        normalized.expectedRevision !== null &&
        inspected.revision !== normalized.expectedRevision
      ) {
        throw new RunnerError("Resume request revision is stale.", {
          code: "ERR_RUN_REVISION_CHANGED",
        });
      }
      if (normalized.dispatch !== null)
        await runStore.recordRecoveryDispatch(lease, normalized.dispatch);
      await resumeLeased(normalized, lease, onRecoveryStage);
      if (
        normalized.dispatch !== null &&
        normalized.stopCheckpointRevision === null &&
        !stopPending(inspected)
      ) {
        await runStore.recordRecoveryDispatch(lease, normalized.dispatch, true);
      }
    } catch (cause) {
      executionFailure = cause;
      // Directory boundary inspection can fail before cleanup marks retained
      // storage. Preserve its owner for same-instance recovery in that case.
      const current = await runStore.loadRun(normalized.runId);
      if (
        current.workspace?.kind === "directory" &&
        current.executionResource !== null
      )
        cause.executionResourceRetained = true;
      throw cause;
    } finally {
      try {
        await releaseRunLease(lease, normalized.runId);
      } catch (cause) {
        // Process or preparation ownership can prevent release before boundary
        // inspection reaches cleanup. Keep the handle and the original failure.
        if (
          retained !== undefined ||
          isExecutionOwnershipFailure(executionFailure) ||
          isExecutionOwnershipFailure(cause)
        ) {
          retainedRunLeases.set(normalized.runId, lease);
          if (executionFailure !== null) throw executionFailure;
        }
        throw cause;
      }
    }
    return result(await runStore.loadRun(normalized.runId));
  }

  async function status(runId) {
    assertNonEmptyString(runId, "runId");
    const history = runStore.loadRunHistory
      ? await runStore.loadRunHistory(runId, { stream: true })
      : { run: await runStore.loadRun(runId), events: [] };
    const { pipeline, run } = pipelineForRun(history.run, undefined, {
      allowMigration: true,
    });
    await pipeline.prepareRecovery?.(run, history);
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
          if (run.workspace?.kind === "directory")
            await validatePersistedBoundary(run);
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
