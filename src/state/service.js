import { createHash, randomUUID } from "node:crypto";
import { watch } from "node:fs";
import { lstat, mkdir, readdir, realpath, rm, rmdir } from "node:fs/promises";
import { homedir, hostname } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  clientAttributionFingerprint,
  DEFAULT_CLIENT_ATTRIBUTION,
  normalizeSessionNamingDiagnostic,
} from "../agents/index.js";
import { openRuntimeStorage } from "../runtime/index.js";

import { createActionStore } from "./actions.js";
import { resolveStateLocation } from "./location/index.js";
import { createRuntimeAdmissionStore } from "./runtime-admission.js";
import {
  dispatchActivity,
  isRecoveryPreparation,
  normalizeDispatchOwner,
  normalizeRecoveryDispatch,
} from "./dispatch.js";
import {
  availabilityActivity,
  availabilityDelayMs,
  DEFAULT_AVAILABILITY_POLICY,
} from "./availability.js";
import {
  atomicWriteFile,
  publishExclusiveFile,
  readOptionalPublishedText,
  resolveRunArtifactPath,
} from "./files.js";
import {
  DEFAULT_PROVIDER_INACTIVITY_TIMEOUT_MS,
  providerInactivityFingerprint,
  inactivityActivity,
} from "./inactivity.js";
import { createStateJournal } from "./journal.js";
import { createLeaseManager } from "./lease.js";
import { createMutationBoundary } from "./mutation.js";
import {
  createPreparationService,
  hasPreparationCustody,
} from "./preparation.js";
import {
  beginObservationAttempt,
  interruptObservations,
  recordObservations,
  observationActivity,
} from "./observations.js";
import { inspectProcessOwner, readProcessIdentity } from "./process-owner.js";
import { createPreservationStore } from "./preservation.js";
import { createRecoveryFailureStore } from "./recovery-failures.js";
import { createStopService } from "./stops.js";
import {
  assertRunCanAdvance,
  assertStopProgress,
  assertRunCanReleaseOwnership,
  runRetainsOwnership,
  stopIsPending,
} from "./stop-policy.js";
import {
  assertRunId,
  deepFreeze,
  normalizeChildSession,
  normalizeExecutionResource,
  normalizePublicActivity,
  normalizeRunState,
  normalizeRoles,
  normalizeTransitionPatch,
  validateProcessIdentity,
  RUNTIME_COMPATIBILITY,
  RUNTIME_COMPATIBILITY_TOKEN,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  RUN_STATE_SCHEMA_VERSION,
  RunStoreError,
} from "./validation.js";

export {
  RUNTIME_COMPATIBILITY,
  RUNTIME_COMPATIBILITY_TOKEN,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  RUN_STATE_SCHEMA_VERSION,
  RunStoreError,
};

const RUNS_DIRECTORY = "runs";
const WORKTREES_DIRECTORY = "worktrees";
const CREATE_RUN_FIELDS = new Set([
  "runId",
  "pipelineId",
  "pipelineStateVersion",
  "projectPath",
  "taskPath",
  "projectConfigurationProtection",
  "workspace",
  "clientAttribution",
  "clientAttributionFingerprint",
  "roles",
  "providerPolicies",
  "providerInactivityTimeoutMs",
  "availabilityPolicy",
  "counters",
  "hashes",
  "pause",
  "sourceSession",
  "sourceProfile",
  "childSessions",
  "pipelineState",
  "activity",
]);
const MAX_RUN_ARTIFACT_BYTES = 1024 * 1024;
const DEFAULT_ACTIVITY_LIMIT = 50;
const MAX_ACTIVITY_LIMIT = 100;
const LEASE_OWNER_STATUSES = Object.freeze([
  "none",
  "live",
  "unverifiable",
  "dead",
  "replaced",
]);

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function rejectUnknownFields(value, fields, path) {
  const unknownField = Object.keys(value).find((field) => !fields.has(field));
  if (unknownField !== undefined) {
    throw new RunStoreError(`${path}.${unknownField} is not supported.`, {
      code: "ERR_INVALID_RUN_STATE",
    });
  }
}

function isWithin(parentPath, childPath) {
  const pathFromParent = relative(parentPath, childPath);
  return (
    pathFromParent === "" ||
    (!pathFromParent.startsWith(`..${sep}`) &&
      pathFromParent !== ".." &&
      !isAbsolute(pathFromParent))
  );
}

async function canonicalDirectory(directoryPath, name) {
  if (typeof directoryPath !== "string" || directoryPath.trim().length === 0) {
    throw new RunStoreError(`${name} must be a non-empty path.`, {
      code: "ERR_INVALID_RUN_PATH",
    });
  }

  try {
    const canonicalPath = await realpath(resolve(directoryPath));
    if (!(await lstat(canonicalPath)).isDirectory()) {
      throw new RunStoreError(`${name} must be a directory.`, {
        code: "ERR_INVALID_RUN_PATH",
      });
    }
    return canonicalPath;
  } catch (cause) {
    if (cause instanceof RunStoreError) {
      throw cause;
    }
    throw new RunStoreError(`Cannot resolve ${name.toLowerCase()}.`, {
      cause,
      code: "ERR_INVALID_RUN_PATH",
    });
  }
}

async function canonicalPotentialPath(path) {
  const missingComponents = [];
  let currentPath = resolve(path);

  while (true) {
    try {
      const canonicalParent = await realpath(currentPath);
      return resolve(canonicalParent, ...missingComponents.reverse());
    } catch (cause) {
      if (cause?.code !== "ENOENT") {
        throw cause;
      }
      try {
        const metadata = await lstat(currentPath);
        // Another creator may have made this directory after realpath failed.
        // Resolve it again so containment still uses its canonical path.
        if (metadata.isDirectory()) continue;
        throw new RunStoreError(
          "State path cannot resolve through a dangling link.",
          {
            code: "ERR_UNSAFE_STATE_ROOT",
          },
        );
      } catch (inspectionCause) {
        if (inspectionCause?.code !== "ENOENT") throw inspectionCause;
      }
      const parentPath = dirname(currentPath);
      if (parentPath === currentPath) {
        throw cause;
      }
      missingComponents.push(currentPath.slice(parentPath.length + 1));
      currentPath = parentPath;
    }
  }
}

function assertDisjointStateRoot(stateRoot, projectPath, taskPath) {
  for (const [boundaryPath, name] of [
    [projectPath, "project"],
    [taskPath, "task directory"],
  ]) {
    if (
      isWithin(boundaryPath, stateRoot) ||
      isWithin(stateRoot, boundaryPath)
    ) {
      throw new RunStoreError(
        `State root and ${name} must remain disjoint: ${stateRoot}.`,
        { code: "ERR_UNSAFE_STATE_ROOT" },
      );
    }
  }
}

function defaultProcessIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    if (cause?.code === "ESRCH") {
      return false;
    }
    if (cause?.code === "EPERM") {
      return true;
    }
    throw cause;
  }
}

export function resolveStateRoot({
  env = process.env,
  homeDirectory = homedir(),
} = {}) {
  const location = resolveStateLocation({ env, homeDirectory });
  if (location === null) {
    throw new RunStoreError("State-directory base path must be absolute.", {
      code: "ERR_INVALID_STATE_ROOT",
    });
  }

  return location;
}

export function createRunStore({
  stateRoot = resolveStateRoot(),
  clock = () => new Date(),
  runIdFactory = randomUUID,
  leaseTokenFactory = randomUUID,
  hostName = hostname(),
  processId = process.pid,
  processIsAlive = defaultProcessIsAlive,
  processIdentity = readProcessIdentity,
  runtimeProcessNamespace,
  onLeasePublicationBoundary = async () => {},
  onRecoveryFailurePublicationBoundary = async () => {},
  onPreservationBoundary = async () => {},
  onTransitionBoundary = async () => {},
  onPreparationBoundary = async () => {},
  onRuntimeBoundary = async () => {},
  resolveStopBoundary = null,
  ownerProbeIntervalMs = 1000,
} = {}) {
  if (typeof stateRoot !== "string" || !isAbsolute(stateRoot)) {
    throw new RunStoreError("State root must be an absolute path.", {
      code: "ERR_INVALID_STATE_ROOT",
    });
  }
  if (
    (resolveStopBoundary !== null &&
      typeof resolveStopBoundary !== "function") ||
    typeof clock !== "function" ||
    typeof runIdFactory !== "function" ||
    typeof leaseTokenFactory !== "function" ||
    typeof processIsAlive !== "function" ||
    typeof processIdentity !== "function" ||
    (runtimeProcessNamespace !== undefined &&
      typeof runtimeProcessNamespace !== "function") ||
    typeof onLeasePublicationBoundary !== "function" ||
    typeof onRecoveryFailurePublicationBoundary !== "function" ||
    typeof onPreservationBoundary !== "function" ||
    typeof onTransitionBoundary !== "function" ||
    typeof onPreparationBoundary !== "function" ||
    typeof onRuntimeBoundary !== "function" ||
    typeof hostName !== "string" ||
    hostName.length === 0 ||
    hostName.length > 255 ||
    /[\p{Cc}\p{Zl}\p{Zp}]/u.test(hostName) ||
    !Number.isSafeInteger(processId) ||
    processId < 1 ||
    !Number.isSafeInteger(ownerProbeIntervalMs) ||
    ownerProbeIntervalMs < 1 ||
    ownerProbeIntervalMs > 2_147_483_647
  ) {
    throw new RunStoreError("Run-store options are invalid.", {
      code: "ERR_INVALID_RUN_STORE_OPTIONS",
    });
  }

  const requestedStateRoot = resolve(stateRoot);
  let rootInitialization;

  function currentDate() {
    let date;
    try {
      date = new Date(clock());
    } catch (cause) {
      throw new RunStoreError("Run-store clock returned an invalid date.", {
        cause,
        code: "ERR_INVALID_RUN_STORE_OPTIONS",
      });
    }
    if (Number.isNaN(date.valueOf())) {
      throw new RunStoreError("Run-store clock returned an invalid date.", {
        code: "ERR_INVALID_RUN_STORE_OPTIONS",
      });
    }
    return date;
  }

  function timestamp(notBefore) {
    const currentTimestamp = currentDate().toISOString();
    return notBefore !== undefined && currentTimestamp < notBefore
      ? notBefore
      : currentTimestamp;
  }

  const journal = createStateJournal({
    onTransitionBoundary,
    resolveStopBoundary,
  });
  const mutate = createMutationBoundary({
    hostName,
    processId,
    processIsAlive,
    processIdentity,
    onPublicationBoundary: onLeasePublicationBoundary,
  });
  async function withRunMutation(record, operation, leaseDirectory) {
    let directory;
    try {
      directory = await getRunDirectory(record.runId);
    } catch (cause) {
      if (cause?.code !== "ERR_RUN_NOT_FOUND") throw cause;
      // Guidance owners have no run; serialize their writes in the lease directory.
      directory = leaseDirectory;
    }
    return mutate(directory, operation);
  }
  async function beforeRelease(record) {
    let run;
    try {
      run = await loadRun(record.runId);
    } catch (cause) {
      if (cause?.code === "ERR_RUN_NOT_FOUND") return;
      throw cause;
    }
    assertRunCanReleaseOwnership(run);
  }
  const runLeases = createLeaseManager({
    withMutation: withRunMutation,
    beforeRelease,
    hostName,
    processId,
    processIsAlive,
    processIdentity,
    onPublicationBoundary: onLeasePublicationBoundary,
    timestamp,
    tokenFactory: leaseTokenFactory,
  });
  const worktreeLeases = createLeaseManager({
    withMutation: withRunMutation,
    beforeRelease,
    async canReclaim(record, requestingRunId) {
      if (record.runId === requestingRunId) return true;
      try {
        const current = await loadRun(record.runId);
        return !runRetainsOwnership(current);
      } catch (cause) {
        if (cause?.code === "ERR_RUN_NOT_FOUND") return true;
        throw cause;
      }
    },
    activeLeaseDescription: "Worktree lease",
    conflictCode: "ERR_WORKTREE_LEASED",
    hostName,
    invalidLeaseCode: "ERR_INVALID_WORKTREE_LEASE",
    leaseDescription: "Worktree lease",
    leaseSubject: (runId, ownerRunId = runId) =>
      ownerRunId === runId
        ? `Run ${runId}'s Git worktree`
        : `Git worktree requested by run ${runId} (recorded lease owner: run ${ownerRunId})`,
    processId,
    processIsAlive,
    processIdentity,
    onPublicationBoundary: onLeasePublicationBoundary,
    reclaimingLeaseDescription: "Reclaiming worktree lease",
    requireMatchingRunId: false,
    timestamp,
    tokenFactory: leaseTokenFactory,
  });
  const actions = createActionStore({
    clock,
    hostName,
    processId,
    processIsAlive,
    processIdentity,
    onPublicationBoundary: onLeasePublicationBoundary,
    stateRoot: requestedStateRoot,
    tokenFactory: leaseTokenFactory,
  });
  const recoveryFailures = createRecoveryFailureStore({
    getRunDirectory,
    hostName,
    processId,
    processIdentity,
    onPublicationBoundary: onRecoveryFailurePublicationBoundary,
  });
  const preservation = createPreservationStore({
    getRunDirectory,
    loadRun,
    onBoundary: onPreservationBoundary,
    withLease: (lease, worktreeLease, operation, recoveryId = null) =>
      runLeases.runExclusive(lease, ({ record, runDirectory }) =>
        worktreeLeases.holdCurrent(worktreeLease, async (worktree) => {
          let snapshot = await loadSnapshot(runDirectory, record.runId);
          const state = snapshot.state;
          if (
            worktree.record.runId !== state.runId ||
            worktree.runDirectory !==
              (await getWorktreeLeaseDirectory(state.projectPath))
          )
            throw new RunStoreError(
              "Preservation requires the run's worktree lease.",
              { code: "ERR_INVALID_PRESERVATION" },
            );
          // Stop recovery may settle an existing preservation intent, never
          // create one or acquire additional workspace authority.
          if (!(recoveryId !== null && stopIsPending(state)))
            assertRunCanAdvance(state, resolveStopBoundary);
          if (
            state.schemaVersion !== RUN_STATE_SCHEMA_VERSION ||
            state.activeTurn !== null ||
            state.executionProcess !== null ||
            state.executionResource !== null ||
            state.preparation != null
          )
            throw new RunStoreError(
              "Preservation requires a migrated, reconciled checkpoint.",
              { code: "ERR_INVALID_PRESERVATION" },
            );
          return operation({
            runDirectory,
            state,
            async publish(reference) {
              const records = [...snapshot.state.preservationRecords];
              const index = records.findIndex(({ id }) => id === reference.id);
              if (index === -1) records.push(reference);
              else records[index] = reference;
              const next = normalizeRunState(
                {
                  ...snapshot.state,
                  preservationRecords: records,
                  revision: snapshot.state.revision + 1,
                  updatedAt: timestamp(snapshot.state.updatedAt),
                },
                record.runId,
              );
              await journal.appendTransition(runDirectory, next, snapshot, {
                actor: "runner",
                phase: "preservation",
                kind: "preservation-recorded",
                message: "Durable unfinished-work authority recorded.",
              });
              snapshot = await loadSnapshot(runDirectory, record.runId);
            },
          });
        }),
      ),
  });

  const runtimeAdmission = createRuntimeAdmissionStore({
    rootPath: requestedStateRoot,
    openStorage: openRuntimeStorage,
    ensureRoot,
    ensureDirectory: ensureManagedDirectory,
    actions,
    hostName,
    processId,
    processIdentity,
    processIsAlive,
    processNamespace: runtimeProcessNamespace,
    onPublicationBoundary: onLeasePublicationBoundary,
    onBoundary: onRuntimeBoundary,
  });

  async function inspectRoot() {
    const canonicalRoot = await realpath(requestedStateRoot);
    const runsPath = join(canonicalRoot, RUNS_DIRECTORY);
    const metadata = await lstat(runsPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new RunStoreError("State runs path must be a real directory.", {
        code: "ERR_UNSAFE_STATE_ROOT",
      });
    }
    return { rootPath: canonicalRoot, runsPath };
  }

  async function ensureRoot() {
    if (rootInitialization === undefined) {
      rootInitialization = (async () => {
        await mkdir(requestedStateRoot, { recursive: true, mode: 0o700 });
        const canonicalRoot = await realpath(requestedStateRoot);
        const runsPath = join(canonicalRoot, RUNS_DIRECTORY);
        await mkdir(runsPath, { recursive: true, mode: 0o700 });
      })().catch((error) => {
        rootInitialization = undefined;
        throw error;
      });
    }
    await rootInitialization;
    return inspectRoot();
  }

  async function ensureManagedDirectory(directoryPath, description) {
    try {
      await mkdir(directoryPath, { mode: 0o700 });
    } catch (cause) {
      if (cause?.code !== "EEXIST") {
        throw cause;
      }
    }
    const metadata = await lstat(directoryPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new RunStoreError(`${description} must be a real directory.`, {
        code: "ERR_UNSAFE_STATE_ROOT",
      });
    }
    return directoryPath;
  }

  async function getWorktreeLeaseDirectory(projectPath, allowMissing = false) {
    const [canonicalProjectPath, potentialStateRoot] = await Promise.all([
      allowMissing
        ? canonicalPotentialPath(projectPath)
        : canonicalDirectory(projectPath, "Project path"),
      canonicalPotentialPath(requestedStateRoot),
    ]);
    assertDisjointStateRoot(
      potentialStateRoot,
      canonicalProjectPath,
      canonicalProjectPath,
    );
    const { rootPath } = await ensureRoot();
    assertDisjointStateRoot(
      rootPath,
      canonicalProjectPath,
      canonicalProjectPath,
    );
    const worktreesPath = await ensureManagedDirectory(
      join(rootPath, WORKTREES_DIRECTORY),
      "State worktrees path",
    );
    const key = createHash("sha256").update(canonicalProjectPath).digest("hex");
    return ensureManagedDirectory(
      join(worktreesPath, key),
      "Worktree lease path",
    );
  }

  async function getRunDirectory(runId) {
    assertRunId(runId);
    let runsPath;
    try {
      ({ runsPath } = await inspectRoot());
    } catch (cause) {
      if (cause?.code === "ENOENT") {
        throw new RunStoreError(`Run not found: ${runId}.`, {
          cause,
          code: "ERR_RUN_NOT_FOUND",
        });
      }
      throw cause;
    }
    const runDirectory = join(runsPath, runId);
    try {
      const metadata = await lstat(runDirectory);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw new RunStoreError("Run path must be a real directory.", {
          code: "ERR_INVALID_RUN_STATE",
        });
      }
    } catch (cause) {
      if (cause?.code === "ENOENT") {
        throw new RunStoreError(`Run not found: ${runId}.`, {
          cause,
          code: "ERR_RUN_NOT_FOUND",
        });
      }
      throw cause;
    }
    return runDirectory;
  }

  async function createRun(input) {
    if (!isRecord(input)) {
      throw new RunStoreError("Run input must be an object.", {
        code: "ERR_INVALID_RUN_STATE",
      });
    }
    rejectUnknownFields(input, CREATE_RUN_FIELDS, "runInput");

    const [projectPath, taskPath, potentialStateRoot] = await Promise.all([
      canonicalDirectory(input.projectPath, "Project path"),
      canonicalDirectory(input.taskPath, "Task path"),
      canonicalPotentialPath(requestedStateRoot),
    ]);
    assertDisjointStateRoot(potentialStateRoot, projectPath, taskPath);

    const { rootPath, runsPath } = await ensureRoot();
    assertDisjointStateRoot(rootPath, projectPath, taskPath);

    let runId = input.runId;
    let runDirectory;
    const attempts = runId === undefined ? 10 : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      runId ??= runIdFactory();
      assertRunId(runId);
      runDirectory = join(runsPath, runId);
      try {
        await mkdir(runDirectory, { mode: 0o700 });
        break;
      } catch (cause) {
        if (cause?.code !== "EEXIST") {
          throw cause;
        }
        if (input.runId !== undefined) {
          throw new RunStoreError(`Run already exists: ${runId}.`, {
            cause,
            code: "ERR_RUN_ID_COLLISION",
          });
        }
        runDirectory = undefined;
        runId = undefined;
      }
    }
    if (runDirectory === undefined) {
      throw new RunStoreError("Cannot allocate a unique run ID.", {
        code: "ERR_RUN_ID_COLLISION",
      });
    }

    let lease;
    try {
      lease = await runLeases.acquire(runDirectory, runId);
      const createdAt = timestamp();
      const clientAttribution =
        input.clientAttribution === undefined
          ? DEFAULT_CLIENT_ATTRIBUTION
          : input.clientAttribution;
      let attributionFingerprint = input.clientAttributionFingerprint;
      if (attributionFingerprint === undefined) {
        try {
          attributionFingerprint =
            clientAttributionFingerprint(clientAttribution);
        } catch (cause) {
          throw new RunStoreError("run.clientAttribution is invalid.", {
            cause,
            code: "ERR_INVALID_RUN_STATE",
          });
        }
      }
      const state = normalizeRunState(
        {
          schemaVersion: RUN_STATE_SCHEMA_VERSION,
          revision: 1,
          runId,
          pipelineId: input.pipelineId,
          pipelineStateVersion: input.pipelineStateVersion,
          runtimeCompatibility: RUNTIME_COMPATIBILITY,
          projectPath,
          taskPath,
          workspace: input.workspace ?? null,
          projectConfigurationProtection:
            input.projectConfigurationProtection === undefined
              ? null
              : input.projectConfigurationProtection,
          clientAttribution,
          clientAttributionFingerprint: attributionFingerprint,
          roles: normalizeRoles(input.roles),
          availabilityPolicy:
            input.availabilityPolicy === undefined
              ? DEFAULT_AVAILABILITY_POLICY
              : input.availabilityPolicy,
          providerInactivityTimeoutMs:
            input.providerInactivityTimeoutMs === undefined
              ? DEFAULT_PROVIDER_INACTIVITY_TIMEOUT_MS
              : input.providerInactivityTimeoutMs,
          providerInactivityFingerprint: providerInactivityFingerprint(
            input.providerInactivityTimeoutMs === undefined
              ? DEFAULT_PROVIDER_INACTIVITY_TIMEOUT_MS
              : input.providerInactivityTimeoutMs,
          ),
          inactivityRecovery: null,
          observations: null,
          availabilityRetry: null,
          providerPolicies:
            input.providerPolicies === undefined
              ? Object.fromEntries(
                  Object.keys(input.roles).map((role) => [role, null]),
                )
              : input.providerPolicies,
          counters: input.counters === undefined ? {} : input.counters,
          hashes: input.hashes === undefined ? {} : input.hashes,
          pause: input.pause === undefined ? null : input.pause,
          sessionLineage: {
            source:
              input.sourceSession === undefined ? null : input.sourceSession,
            sourceProfile:
              input.sourceProfile === undefined ? null : input.sourceProfile,
            children:
              input.childSessions === undefined ? [] : input.childSessions,
          },
          activeTurn: null,
          executionProcess: null,
          executionResource: null,
          preparation: null,
          preservationRecords: [],
          stopRequest: null,
          pipelineState:
            input.pipelineState === undefined ? {} : input.pipelineState,
          createdAt,
          updatedAt: createdAt,
        },
        runId,
      );
      const activity = normalizePublicActivity(
        input.activity === undefined
          ? {
              actor: "runner",
              phase: "run",
              kind: "created",
              message: "Run created.",
            }
          : input.activity,
      );
      await journal.appendTransition(
        runDirectory,
        state,
        { lastEvent: null, hasPartialTail: false, validByteLength: 0 },
        activity,
      );

      return Object.freeze({
        directoryPath: runDirectory,
        lease,
        state: deepFreeze(state),
      });
    } catch (cause) {
      if (lease === undefined) {
        try {
          await rmdir(runDirectory);
        } catch (cleanupCause) {
          if (!["EEXIST", "ENOENT", "ENOTEMPTY"].includes(cleanupCause?.code)) {
            throw cleanupCause;
          }
        }
      } else {
        await rm(runDirectory, { recursive: true, force: true });
      }
      throw cause;
    }
  }

  async function validateStateBoundary({ projectPath, taskPath }) {
    const [project, task, potentialStateRoot] = await Promise.all([
      canonicalDirectory(projectPath, "Project path"),
      canonicalDirectory(taskPath, "Task path"),
      canonicalPotentialPath(requestedStateRoot),
    ]);
    assertDisjointStateRoot(potentialStateRoot, project, task);
    return Object.freeze({ projectPath: project, taskPath: task });
  }

  async function assertRuntimeBoundary(paths) {
    if (
      !Array.isArray(paths) ||
      paths.some((path) => typeof path !== "string" || !path)
    )
      throw new RunStoreError("Runtime boundaries are invalid.", {
        code: "ERR_UNSAFE_STATE_ROOT",
      });
    const root = await canonicalPotentialPath(requestedStateRoot);
    for (const path of paths) {
      const boundary = await canonicalPotentialPath(resolve(path));
      assertDisjointStateRoot(root, boundary, boundary);
    }
  }

  async function acquireRunLease(runId, retainedLease) {
    if (retainedLease !== undefined && retainedLease?.runId !== runId) {
      throw new RunStoreError(
        "Retained execution lease belongs to another run.",
        { code: "ERR_INVALID_RUN_LEASE" },
      );
    }
    const runDirectory = await getRunDirectory(runId);
    await loadSnapshot(runDirectory, runId);
    const lease =
      retainedLease ?? (await runLeases.acquire(runDirectory, runId));
    try {
      await runLeases.runExclusive(lease, () =>
        loadSnapshot(runDirectory, runId),
      );
      return lease;
    } catch (cause) {
      if (retainedLease === undefined) await lease.release();
      throw cause;
    }
  }

  // Custody and state-root checks every service snapshot passes. Only a caller
  // supplying `reload` may reread once before rejecting unmerged custody.
  async function authorizeSnapshot(runDirectory, snapshot, reload = null) {
    if (
      snapshot.state.preparation === null &&
      (await hasPreparationCustody(runDirectory))
    ) {
      if (reload === null)
        throw new RunStoreError(
          "Unmerged preparation custody has no authority.",
          { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
        );
      // A lock-free read may precede reservation publication. Reload before
      // rejecting custody whose canonical authority was lost or rolled back.
      return authorizeSnapshot(runDirectory, await reload());
    }
    assertDisjointStateRoot(
      runDirectory,
      snapshot.state.projectPath,
      snapshot.state.taskPath,
    );
    return snapshot;
  }

  async function loadSnapshot(runDirectory, runId) {
    const load = () => journal.loadSnapshot(runDirectory, runId);
    return authorizeSnapshot(runDirectory, await load(), load);
  }

  async function loadRun(runId) {
    const runDirectory = await getRunDirectory(runId);
    return deepFreeze((await loadSnapshot(runDirectory, runId)).state);
  }

  // Internal runtime evidence from one validated prefix. Runtime recovery uses
  // replay rather than retaining complete historical state copies in memory.
  async function loadRunHistory(runId, { stream = false } = {}) {
    const runDirectory = await getRunDirectory(runId);
    const snapshot = await loadSnapshot(runDirectory, runId);
    const events = {
      async *[Symbol.asyncIterator]() {
        for await (const event of journal.replaySnapshot(
          runDirectory,
          snapshot,
        ))
          yield deepFreeze(event);
      },
    };
    return deepFreeze({
      run: snapshot.state,
      events: stream ? events : await Array.fromAsync(events),
    });
  }

  async function runIsLeased(runId) {
    const runDirectory = await getRunDirectory(runId);
    const current = (await loadSnapshot(runDirectory, runId)).state;
    return (
      runRetainsOwnership(current) || runLeases.isLeased(runDirectory, runId)
    );
  }

  async function runLeaseOwnerIsLive(runId) {
    const runDirectory = await getRunDirectory(runId);
    return runLeases.ownerIsLive(runDirectory, runId);
  }

  async function acquireWorktreeLease(
    projectPath,
    runId,
    allowMissing = false,
  ) {
    assertRunId(runId);
    const worktreeDirectory = await getWorktreeLeaseDirectory(
      projectPath,
      allowMissing,
    );
    const scope = allowMissing
      ? await canonicalPotentialPath(projectPath)
      : await canonicalDirectory(projectPath, "Project path");
    // Serialize admission, rather than check then acquire: parent and child
    // scopes have distinct keys but must never both gain exclusive ownership.
    return mutate(dirname(worktreeDirectory), async () => {
      const scopePath = join(worktreeDirectory, "scope.json");
      const source = `${JSON.stringify({ schemaVersion: 1, path: scope })}\n`;
      const saved = await readOptionalPublishedText(scopePath);
      if (saved === null) await publishExclusiveFile(scopePath, source);
      else if (saved !== source)
        throw new RunStoreError("Workspace lease scope changed.", {
          code: "ERR_INVALID_WORKTREE_LEASE",
        });
      const owner = await overlappingWorktreeOwner(
        worktreeDirectory,
        scope,
        runId,
      );
      if (owner !== null)
        throw new RunStoreError("An overlapping workspace is already leased.", {
          code: "ERR_WORKTREE_LEASED",
        });
      return worktreeLeases.acquire(worktreeDirectory, runId);
    });
  }

  async function overlappingWorktreeOwner(directory, scope, runId) {
    const within = (root, path) => {
      const name = relative(root, path);
      return (
        name === "" ||
        (!isAbsolute(name) && name !== ".." && !name.startsWith(`..${sep}`))
      );
    };
    for (const key of await readdir(dirname(directory))) {
      if (
        !/^[a-f0-9]{64}$/u.test(key) ||
        join(dirname(directory), key) === directory
      )
        continue;
      const candidate = await ensureManagedDirectory(
        join(dirname(directory), key),
        "Workspace lease path",
      );
      const source = await readOptionalPublishedText(
        join(candidate, "scope.json"),
      );
      if (source === null) continue; // Legacy Git keys still use exact exclusion.
      let binding;
      try {
        binding = JSON.parse(source);
      } catch {}
      if (
        binding?.schemaVersion !== 1 ||
        Object.keys(binding).sort().join() !== "path,schemaVersion" ||
        typeof binding.path !== "string" ||
        !isAbsolute(binding.path) ||
        resolve(binding.path) !== binding.path ||
        createHash("sha256").update(binding.path).digest("hex") !== key
      )
        throw new RunStoreError("Workspace lease scope is invalid.", {
          code: "ERR_INVALID_WORKTREE_LEASE",
        });
      if (!within(scope, binding.path) && !within(binding.path, scope))
        continue;
      const owner = await worktreeLeases.reservationOwner(candidate, runId);
      if (owner !== null) return owner;
    }
    return null;
  }

  async function worktreeIsLeased(projectPath, runId) {
    return (await worktreeLeaseOwner(projectPath, runId)) !== null;
  }

  async function worktreeLeaseOwner(projectPath, runId) {
    assertRunId(runId);
    const worktreeDirectory = await getWorktreeLeaseDirectory(projectPath);
    return (
      (await worktreeLeases.owner(worktreeDirectory, runId)) ??
      (await overlappingWorktreeOwner(
        worktreeDirectory,
        await canonicalDirectory(projectPath, "Project path"),
        runId,
      ))
    );
  }

  async function withGuidanceLease(projectPath, operation) {
    if (typeof operation !== "function") {
      throw new RunStoreError("Guidance publication requires an operation.", {
        code: "ERR_INVALID_RUN_STORE_OPTIONS",
      });
    }
    await validateStateBoundary({ projectPath, taskPath: projectPath });
    const lease = await acquireWorktreeLease(projectPath, randomUUID());
    const assertOwnership = () =>
      worktreeLeases.runExclusive(lease, async () => {});
    try {
      await assertOwnership();
      return await operation(assertOwnership);
    } finally {
      await lease.release();
    }
  }

  async function assertWorkspaceLease(lease, workspaceLease, projectPath) {
    return runLeases.runExclusive(lease, ({ record }) =>
      worktreeLeases.holdCurrent(workspaceLease, async (owner) => {
        if (
          owner.record.runId !== record.runId ||
          owner.runDirectory !==
            (await getWorktreeLeaseDirectory(projectPath, true))
        )
          throw new RunStoreError(
            "Setup requires the current workspace lease.",
            { code: "ERR_INVALID_WORKTREE_LEASE" },
          );
      }),
    );
  }

  async function waitForRunChange(
    runId,
    {
      afterRevision,
      timeoutMs,
      signal,
      includeOwnership = false,
      ownerBaseline,
    } = {},
  ) {
    if (
      !Number.isSafeInteger(afterRevision) ||
      afterRevision < 0 ||
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 0 ||
      typeof includeOwnership !== "boolean" ||
      (ownerBaseline !== undefined &&
        (!includeOwnership || !LEASE_OWNER_STATUSES.includes(ownerBaseline))) ||
      (signal !== undefined && !(signal instanceof AbortSignal))
    ) {
      throw new RunStoreError("Run wait options are invalid.", {
        code: "ERR_INVALID_RUN_WAIT",
      });
    }

    const initial = await loadRun(runId);
    if (initial.revision > afterRevision || timeoutMs === 0) {
      return initial;
    }
    if (signal?.aborted) {
      throw signal.reason ?? new DOMException("Aborted", "AbortError");
    }

    const runDirectory = await getRunDirectory(runId);
    const directories = includeOwnership
      ? [
          runDirectory,
          await getWorktreeLeaseDirectory(
            initial.workspace?.leasePath ?? initial.projectPath,
          ),
        ]
      : [runDirectory];
    return new Promise((resolvePromise, rejectPromise) => {
      let settled = false;
      let timer;
      let ownerProbe;
      let probing = false;
      let baseline = ownerBaseline;
      const watchers = [];
      let ownershipChanged = false;
      let loading = false;
      let reload = false;

      const finish = (operation, value) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        clearInterval(ownerProbe);
        signal?.removeEventListener("abort", onAbort);
        for (const watcher of watchers) watcher.close();
        operation(value);
      };
      const load = async () => {
        if (settled) return;
        if (loading) {
          reload = true;
          return;
        }
        loading = true;
        try {
          const current = await loadRun(runId);
          if (current.revision > afterRevision || ownershipChanged) {
            finish(resolvePromise, current);
          }
        } catch (cause) {
          finish(rejectPromise, cause);
        } finally {
          loading = false;
          if (reload && !settled) {
            reload = false;
            void load();
          }
        }
      };
      const onAbort = () =>
        finish(
          rejectPromise,
          signal.reason ?? new DOMException("Aborted", "AbortError"),
        );
      // Node cannot observe the exit of a non-child owner, and its death need
      // not change any file. Classify the lease owner read-only; only a
      // positive loss that differs from the baseline ends the wait.
      const probe = async () => {
        if (settled || probing) return;
        probing = true;
        try {
          const owner = await runLeases.inspect(runDirectory, runId);
          const status = owner?.status ?? "none";
          baseline ??= status;
          if (["dead", "replaced"].includes(status) && status !== baseline) {
            ownershipChanged = true;
            void load();
          }
        } catch {
          // An unreadable owner is not evidence of loss; the timeout bounds it.
        } finally {
          probing = false;
        }
      };

      try {
        for (const directory of directories) {
          const watcher = watch(
            directory,
            { persistent: false },
            (_eventType, filename) => {
              if (
                includeOwnership &&
                (filename === null ||
                  [".lease", ".lease-reclaiming"].includes(filename.toString()))
              )
                ownershipChanged = true;
              if (
                ownershipChanged ||
                filename === null ||
                filename.toString() === "state.json" ||
                /^events(?:-[0-9]+)?\.jsonl$/u.test(filename.toString())
              ) {
                void load();
              }
            },
          );
          watchers.push(watcher);
          watcher.on("error", (cause) => finish(rejectPromise, cause));
        }
      } catch (cause) {
        finish(rejectPromise, cause);
        return;
      }
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) {
        onAbort();
        return;
      }
      timer = setTimeout(async () => {
        try {
          finish(resolvePromise, await loadRun(runId));
        } catch (cause) {
          finish(rejectPromise, cause);
        }
      }, timeoutMs);
      void load();
      if (includeOwnership) {
        ownerProbe = setInterval(probe, ownerProbeIntervalMs);
        void probe();
      }
    });
  }

  async function recoverRun(lease) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await journal.recover(
        runDirectory,
        await loadSnapshot(runDirectory, record.runId),
      );
      // Diagnostic retirement cannot precede proof that owned work is settled.
      if (
        snapshot.state.preparation != null ||
        snapshot.state.executionProcess !== null ||
        snapshot.state.executionResource !== null
      )
        return deepFreeze(snapshot.state);
      return persistObservations(
        runDirectory,
        snapshot,
        interruptObservations(snapshot.state.observations),
        {
          actor: "runner",
          phase: "runtime",
          kind: "observations-interrupted",
          message: "Interrupted attempt accounting remains incomplete.",
        },
      );
    });
  }

  async function persistObservations(
    runDirectory,
    snapshot,
    observations,
    activity = null,
  ) {
    if (isDeepStrictEqual(snapshot.state.observations, observations))
      return deepFreeze(snapshot.state);
    const next = normalizeRunState(
      {
        ...snapshot.state,
        observations,
        revision: snapshot.state.revision + 1,
        updatedAt: timestamp(snapshot.state.updatedAt),
      },
      snapshot.state.runId,
    );
    await journal.appendTransition(runDirectory, next, snapshot, activity);
    return deepFreeze(next);
  }

  async function startObservationAttempt(lease, identity, measurements) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      const observations = beginObservationAttempt(
        snapshot.state,
        identity,
        measurements,
      );
      return persistObservations(
        runDirectory,
        snapshot,
        observations,
        observationActivity(observations.attempts.at(-1)),
      );
    });
  }

  async function recordObservationBatch(
    lease,
    identity,
    records,
    {
      status = "active",
      incomplete = false,
      resultBytes,
      structuredResultBytes,
    } = {},
  ) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      // Terminal diagnostics may flush during a stop or process cleanup. This
      // operation changes no workflow, process, retry, or effect authority.
      const observations = recordObservations(
        snapshot.state,
        identity,
        records,
        status,
        incomplete,
        { resultBytes, structuredResultBytes },
      );
      return persistObservations(
        runDirectory,
        snapshot,
        observations,
        observations === null
          ? null
          : observationActivity(observations.attempts.at(-1)),
      );
    });
  }

  async function inspectRecoveryDispatch(runId, value) {
    const dispatch = normalizeRecoveryDispatch(value);
    const history = await loadRunHistory(runId, { stream: true });
    let started = false;
    let ready = false;
    let retryable = true;
    let previous = null;
    for await (const event of history.events) {
      if (event.revision === dispatch.expectedRevision + 1) {
        started = isDeepStrictEqual(event.activity, dispatchActivity(dispatch));
      }
      if (event.revision > dispatch.expectedRevision) {
        ready ||= isDeepStrictEqual(
          event.activity,
          dispatchActivity(dispatch, true),
        );
      }
      if (event.revision > dispatch.expectedRevision + 1) {
        retryable &&= isRecoveryPreparation(previous, event);
      }
      previous = event.state;
    }
    ready &&= started;
    retryable &&= started && !ready;
    return { started, ready, retryable };
  }

  async function recordRecoveryDispatch(lease, value, ready = false) {
    const dispatch = normalizeRecoveryDispatch(value);
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      let started = false;
      let alreadyReady = false;
      for await (const event of journal.replaySnapshot(
        runDirectory,
        snapshot,
      )) {
        if (event.revision === dispatch.expectedRevision + 1)
          started = isDeepStrictEqual(
            event.activity,
            dispatchActivity(dispatch),
          );
        alreadyReady ||= isDeepStrictEqual(
          event.activity,
          dispatchActivity(dispatch, true),
        );
      }
      if (
        typeof ready !== "boolean" ||
        (ready
          ? !started
          : snapshot.state.revision !== dispatch.expectedRevision)
      ) {
        throw new RunStoreError("Detached recovery revision is stale.", {
          code: "ERR_RUN_REVISION_CHANGED",
        });
      }
      if (
        ready &&
        (snapshot.state.preparation != null ||
          snapshot.state.executionProcess !== null ||
          snapshot.state.executionResource !== null)
      ) {
        throw new RunStoreError(
          "Detached recovery retains execution resources.",
          { code: "ERR_EXECUTION_PROCESS_ACTIVE" },
        );
      }
      const activity = dispatchActivity(dispatch, ready);
      if (ready && alreadyReady) return deepFreeze(snapshot.state);
      const next = normalizeRunState(
        {
          ...snapshot.state,
          revision: snapshot.state.revision + 1,
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      // This records admission before potentially long process/worktree recovery.
      await journal.appendTransition(runDirectory, next, snapshot, activity);
      return deepFreeze(next);
    });
  }

  async function inspectDispatchOwner(record) {
    return inspectProcessOwner(normalizeDispatchOwner(record), {
      hostName,
      processIsAlive,
      processIdentity,
    });
  }

  async function migrateRun(
    lease,
    { pipelineState, pipelineStateVersion },
    { activity } = {},
  ) {
    const normalizedActivity = normalizePublicActivity(activity);
    if (
      normalizedActivity?.actor !== "runner" ||
      normalizedActivity.phase !== "runtime" ||
      normalizedActivity.kind !== "migrated"
    ) {
      throw new RunStoreError("Run migration activity is invalid.", {
        code: "ERR_INVALID_RUN_MIGRATION",
      });
    }

    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      if (
        snapshot.state.preparation != null ||
        !Number.isSafeInteger(pipelineStateVersion) ||
        pipelineStateVersion < snapshot.state.pipelineStateVersion ||
        pipelineStateVersion < 1 ||
        (snapshot.state.schemaVersion === RUN_STATE_SCHEMA_VERSION &&
          snapshot.state.runtimeCompatibility?.runnerVersion ===
            RUNTIME_COMPATIBILITY.runnerVersion &&
          snapshot.state.runtimeCompatibility?.runStateVersion ===
            RUNTIME_COMPATIBILITY.runStateVersion &&
          pipelineStateVersion === snapshot.state.pipelineStateVersion)
      ) {
        throw new RunStoreError("Run migration target is invalid.", {
          code: "ERR_INVALID_RUN_MIGRATION",
        });
      }
      const nextState = normalizeRunState(
        {
          ...snapshot.state,
          schemaVersion: RUN_STATE_SCHEMA_VERSION,
          revision: snapshot.state.revision + 1,
          pipelineStateVersion,
          runtimeCompatibility: RUNTIME_COMPATIBILITY,
          pipelineState,
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      await journal.appendTransition(
        runDirectory,
        nextState,
        snapshot,
        normalizedActivity,
      );
      return deepFreeze(nextState);
    });
  }

  async function transitionRun(
    lease,
    patch,
    { activity, expectedRevision } = {},
  ) {
    if (
      expectedRevision !== undefined &&
      (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1)
    ) {
      throw new RunStoreError("Expected run revision is invalid.", {
        code: "ERR_RUN_REVISION_CHANGED",
      });
    }
    const normalizedPatch = normalizeTransitionPatch(patch);
    const normalizedActivity = normalizePublicActivity(activity);
    if (
      Object.keys(normalizedPatch).length === 0 &&
      normalizedActivity === null
    ) {
      throw new RunStoreError(
        "A transition must change state or publish activity.",
        { code: "ERR_EMPTY_RUN_TRANSITION" },
      );
    }

    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      assertRunCanAdvance(snapshot.state, resolveStopBoundary);
      if (
        expectedRevision !== undefined &&
        snapshot.state.revision !== expectedRevision
      ) {
        throw new RunStoreError("Run changed before transition.", {
          code: "ERR_RUN_REVISION_CHANGED",
        });
      }
      if (
        normalizedActivity === null &&
        Object.entries(normalizedPatch).every(([field, value]) =>
          isDeepStrictEqual(snapshot.state[field], value),
        )
      ) {
        throw new RunStoreError(
          "A transition must change state or publish activity.",
          { code: "ERR_EMPTY_RUN_TRANSITION" },
        );
      }
      const nextState = normalizeRunState(
        {
          ...snapshot.state,
          ...normalizedPatch,
          revision: snapshot.state.revision + 1,
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      assertStopProgress(snapshot.state, nextState, resolveStopBoundary);
      await journal.appendTransition(
        runDirectory,
        nextState,
        snapshot,
        normalizedActivity,
      );
      return deepFreeze(nextState);
    });
  }

  async function scheduleAvailabilityRetry(
    lease,
    input,
    { pipelineState } = {},
  ) {
    if (!isRecord(input)) {
      throw new RunStoreError("Availability retry input is invalid.", {
        code: "ERR_INVALID_RUN_STATE",
      });
    }
    rejectUnknownFields(
      input,
      new Set([
        "role",
        "checkpoint",
        "reason",
        "contentFingerprint",
        "expectedRevision",
      ]),
      "availabilityRetry",
    );
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      const state = snapshot.state;
      assertRunCanAdvance(state, resolveStopBoundary);
      if (input.expectedRevision !== state.revision) {
        throw new RunStoreError("Run changed before availability scheduling.", {
          code: "ERR_RUN_REVISION_CHANGED",
        });
      }
      if (
        state.schemaVersion !== RUN_STATE_SCHEMA_VERSION ||
        state.activeTurn !== null ||
        state.preparation != null ||
        state.executionProcess !== null ||
        state.executionResource !== null
      ) {
        throw new RunStoreError(
          "Availability scheduling requires a migrated, reconciled checkpoint.",
          { code: "ERR_INVALID_RUN_STATE" },
        );
      }
      const previous = state.availabilityRetry;
      const attempt =
        previous === null
          ? 1
          : Math.min(Number.MAX_SAFE_INTEGER, previous.attempt + 1);
      const delayMs = availabilityDelayMs(state.availabilityPolicy, attempt);
      const scheduledAt = timestamp(state.updatedAt);
      const nextState = normalizeRunState(
        {
          ...state,
          ...(pipelineState === undefined ? {} : { pipelineState }),
          revision: state.revision + 1,
          updatedAt: scheduledAt,
          availabilityRetry: {
            id: previous?.id ?? randomUUID(),
            role: input.role,
            checkpoint: input.checkpoint,
            reason: input.reason,
            attempt,
            delayMs,
            scheduledAt,
            nextRetryAt: new Date(
              Date.parse(scheduledAt) + delayMs,
            ).toISOString(),
            contentFingerprint: input.contentFingerprint,
            reconciledRevision: state.revision,
          },
        },
        record.runId,
      );
      await journal.appendTransition(
        runDirectory,
        nextState,
        snapshot,
        normalizePublicActivity(
          availabilityActivity(nextState.availabilityRetry, "retry-scheduled"),
        ),
      );
      return deepFreeze(nextState);
    });
  }

  async function recordInactivity(lease, recovery, kind) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      const state = snapshot.state;
      if (recovery?.status !== "expired")
        assertRunCanAdvance(state, resolveStopBoundary);
      if (
        state.schemaVersion !== RUN_STATE_SCHEMA_VERSION ||
        (state.activeTurn?.role !== recovery?.role &&
          recovery?.status === "expired")
      ) {
        throw new RunStoreError(
          "Inactivity expiry requires a current active turn.",
          { code: "ERR_INVALID_AGENT_TURN" },
        );
      }
      // Expiry is evidence about still-owned execution, not workflow advancement.
      // Keep every other field unchanged while journaling before termination.
      const next = normalizeRunState(
        {
          ...state,
          inactivityRecovery: {
            ...recovery,
            expiryRevision:
              kind === "expired"
                ? state.revision + 1
                : (state.inactivityRecovery?.expiryRevision ?? null),
            reconstructionRevision:
              kind === "reconstructing"
                ? state.revision + 1
                : (state.inactivityRecovery?.reconstructionRevision ?? null),
          },
          revision: state.revision + 1,
          updatedAt: timestamp(state.updatedAt),
        },
        record.runId,
      );
      await journal.appendTransition(
        runDirectory,
        next,
        snapshot,
        normalizePublicActivity(inactivityActivity(recovery, kind)),
      );
      return deepFreeze(next);
    });
  }

  function completeAvailabilityTurn(lease, role, options) {
    return completeProviderRecovery(
      lease,
      role,
      "availabilityRetry",
      availabilityActivity,
      options,
    );
  }

  function completeInactivityTurn(lease, role, options) {
    return completeProviderRecovery(
      lease,
      role,
      "inactivityRecovery",
      inactivityActivity,
      options,
    );
  }

  async function completeProviderRecovery(
    lease,
    role,
    field,
    activityFor,
    { patch = {}, expectedRevision } = {},
  ) {
    const normalizedPatch = normalizeTransitionPatch(patch);
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      const state = snapshot.state;
      if (state[field] === null) return deepFreeze(state);
      if (
        expectedRevision !== undefined &&
        state.revision !== expectedRevision
      ) {
        throw new RunStoreError("Run changed before transition.", {
          code: "ERR_RUN_REVISION_CHANGED",
        });
      }
      if (Object.keys(normalizedPatch).length > 0) {
        assertRunCanAdvance(state, resolveStopBoundary);
      }
      if (
        state.activeTurn?.role !== role ||
        state[field].role !== role ||
        state.preparation != null ||
        state.executionProcess !== null ||
        state.executionResource !== null
      ) {
        throw new RunStoreError(
          "Provider recovery completion requires a retired provider response.",
          {
            code: "ERR_INVALID_AGENT_TURN",
          },
        );
      }
      // A response-only reset can race a stop. Reconciliation patches still
      // obey normal advancement rules; the supervisor owns stop settlement.
      const next = normalizeRunState(
        {
          ...state,
          ...normalizedPatch,
          [field]: null,
          revision: state.revision + 1,
          updatedAt: timestamp(state.updatedAt),
        },
        record.runId,
      );
      assertStopProgress(state, next, resolveStopBoundary);
      await journal.appendTransition(
        runDirectory,
        next,
        snapshot,
        normalizePublicActivity(activityFor(state[field], "recovered")),
      );
      return deepFreeze(next);
    });
  }

  async function recordProviderPolicy(lease, role, receipt) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      if (!Object.hasOwn(snapshot.state.providerPolicies, role)) {
        throw new RunStoreError(`Run role is unavailable: ${role}.`, {
          code: "ERR_INVALID_PROVIDER_POLICY",
        });
      }
      const normalizedPolicies = normalizeRunState(
        {
          ...snapshot.state,
          providerPolicies: {
            ...snapshot.state.providerPolicies,
            [role]: receipt,
          },
        },
        record.runId,
      ).providerPolicies;
      if (normalizedPolicies[role] === null) {
        throw new RunStoreError("Provider policy receipt is unavailable.", {
          code: "ERR_INVALID_PROVIDER_POLICY",
        });
      }
      const previous = snapshot.state.providerPolicies[role];
      if (previous !== null) {
        if (!isDeepStrictEqual(previous, normalizedPolicies[role])) {
          throw new RunStoreError(`Provider policy changed for role ${role}.`, {
            code: "ERR_PROVIDER_POLICY_CHANGED",
          });
        }
        return deepFreeze(snapshot.state);
      }
      assertRunCanAdvance(snapshot.state, resolveStopBoundary);
      const nextState = normalizeRunState(
        {
          ...snapshot.state,
          providerPolicies: normalizedPolicies,
          revision: snapshot.state.revision + 1,
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      await journal.appendTransition(runDirectory, nextState, snapshot, {
        actor: "runner",
        phase: "runtime",
        kind: "provider-policy-recorded",
        message: `Recorded immutable provider policy for ${role}.`,
      });
      return deepFreeze(nextState);
    });
  }

  // A pipeline may bind additional exact read trees before its inputs close.
  // Ordinary transitions cannot replace workspace or provider-policy bindings.
  async function bindWorkspaceReads(
    lease,
    {
      workspace,
      providerPolicies,
      expectedRevision,
      worktreeLease,
      assertAuthorized,
    },
  ) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) =>
      worktreeLeases.holdCurrent(worktreeLease, async (owner) => {
        const snapshot = await loadSnapshot(runDirectory, record.runId);
        const state = snapshot.state;
        assertRunCanAdvance(state, resolveStopBoundary);
        const old = state.workspace;
        const { infrastructurePaths: previousReads, ...previousPolicy } =
          old.policy ?? {};
        const { infrastructurePaths: nextReads, ...nextPolicy } =
          workspace.policy ?? {};
        if (
          state.revision !== expectedRevision ||
          old.kind !== "directory" ||
          workspace.kind !== "directory" ||
          state.activeTurn !== null ||
          state.preparation != null ||
          state.executionProcess !== null ||
          state.executionResource !== null ||
          owner.record.runId !== state.runId ||
          owner.runDirectory !==
            (await getWorktreeLeaseDirectory(old.leasePath)) ||
          workspace.leasePath !== old.leasePath ||
          !isDeepStrictEqual(previousPolicy, nextPolicy) ||
          !Array.isArray(nextReads) ||
          !previousReads.every((path) => nextReads.includes(path)) ||
          !isDeepStrictEqual(
            workspace.absentInputPaths,
            old.absentInputPaths,
          ) ||
          !isDeepStrictEqual(
            workspace.retrievalPermissions,
            old.retrievalPermissions,
          ) ||
          typeof assertAuthorized !== "function"
        )
          throw new RunStoreError(
            "Workspace read rebinding is not authorized.",
            { code: "ERR_UNSAFE_WORKSPACE_ACCESS" },
          );
        await assertAuthorized(deepFreeze(state));
        const next = normalizeRunState(
          {
            ...state,
            workspace,
            providerPolicies,
            revision: state.revision + 1,
            updatedAt: timestamp(state.updatedAt),
          },
          record.runId,
        );
        await journal.appendTransition(runDirectory, next, snapshot, {
          actor: "runner",
          phase: "clarify",
          kind: "read-scopes-bound",
          message:
            "Bound additional inspected setup read scopes before clarification closed.",
        });
        return deepFreeze(next);
      }),
    );
  }

  async function startAgentTurn(
    lease,
    activeTurn,
    { activity, pipelineState } = {},
  ) {
    const normalizedPatch = normalizeTransitionPatch({
      activeTurn,
      ...(pipelineState === undefined ? {} : { pipelineState }),
    });
    const normalizedActivity = normalizePublicActivity(activity);
    if (
      normalizedPatch.activeTurn === null ||
      normalizedActivity?.actor !== normalizedPatch.activeTurn.role ||
      normalizedActivity.phase !== normalizedPatch.activeTurn.phase ||
      normalizedActivity.kind !== "turn-started"
    ) {
      throw new RunStoreError("Agent turn activity is invalid.", {
        code: "ERR_INVALID_AGENT_TURN",
      });
    }
    return transitionRun(lease, normalizedPatch, {
      activity: normalizedActivity,
    });
  }

  async function finishAgentTurn(lease, activeTurn) {
    const normalized = normalizeTransitionPatch({ activeTurn }).activeTurn;
    if (normalized === null) {
      throw new RunStoreError("Active agent turn is invalid.", {
        code: "ERR_INVALID_AGENT_TURN",
      });
    }
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      assertRunCanAdvance(snapshot.state, resolveStopBoundary);
      if (!isDeepStrictEqual(snapshot.state.activeTurn, normalized)) {
        throw new RunStoreError("Active agent turn does not match.", {
          code: "ERR_INVALID_AGENT_TURN",
        });
      }
      const nextState = normalizeRunState(
        {
          ...snapshot.state,
          activeTurn: null,
          observations: interruptObservations(snapshot.state.observations),
          revision: snapshot.state.revision + 1,
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      await journal.appendTransition(runDirectory, nextState, snapshot, null);
      return deepFreeze(nextState);
    });
  }

  async function recordChildSession(lease, childSession, { activity } = {}) {
    const normalizedChild = normalizeChildSession(childSession);
    const normalizedActivity = normalizePublicActivity(activity);

    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      assertRunCanAdvance(snapshot.state, resolveStopBoundary, {
        childRole: normalizedChild.role,
      });
      if (
        snapshot.state.sessionLineage.children.some(
          (child) => child.sessionId === normalizedChild.sessionId,
        )
      ) {
        throw new RunStoreError("Child session ID is already recorded.", {
          code: "ERR_DUPLICATE_CHILD_SESSION",
        });
      }

      const nextState = normalizeRunState(
        {
          ...snapshot.state,
          revision: snapshot.state.revision + 1,
          sessionLineage: {
            ...snapshot.state.sessionLineage,
            children: [
              ...snapshot.state.sessionLineage.children,
              normalizedChild,
            ],
          },
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      await journal.appendTransition(
        runDirectory,
        nextState,
        snapshot,
        normalizedActivity,
      );
      return deepFreeze(nextState);
    });
  }

  async function recordSessionNaming(lease, input) {
    if (!isRecord(input)) {
      throw new RunStoreError("Session naming input is invalid.", {
        code: "ERR_INVALID_RUN_STATE",
      });
    }
    rejectUnknownFields(
      input,
      new Set(["role", "sessionId", "status"]),
      "sessionNaming",
    );
    const { role, sessionId } = normalizeChildSession(
      { role: input.role, sessionId: input.sessionId },
      "sessionNaming",
    );
    let status;
    try {
      ({ status } = normalizeSessionNamingDiagnostic({ status: input.status }));
    } catch {
      throw new RunStoreError("Session naming status is invalid.", {
        code: "ERR_INVALID_RUN_STATE",
      });
    }
    const activity = normalizePublicActivity({
      actor: role,
      phase: "session",
      kind: "session-naming",
      message: `Session naming: ${status}.`,
    });

    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      assertRunCanAdvance(snapshot.state, resolveStopBoundary, {
        childRole: role,
      });
      if (
        snapshot.state.activeTurn?.role !== role ||
        !snapshot.state.sessionLineage.children.some(
          (child) => child.role === role && child.sessionId === sessionId,
        )
      ) {
        throw new RunStoreError("Session naming requires a recorded child.", {
          code: "ERR_INVALID_CHILD_SESSION",
        });
      }

      const nextState = normalizeRunState(
        {
          ...snapshot.state,
          revision: snapshot.state.revision + 1,
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      await journal.appendTransition(
        runDirectory,
        nextState,
        snapshot,
        activity,
      );
      return deepFreeze(nextState);
    });
  }

  async function writeRunArtifact(lease, relativePath, content) {
    if (
      !(typeof content === "string" || content instanceof Uint8Array) ||
      Buffer.byteLength(content) > MAX_RUN_ARTIFACT_BYTES
    ) {
      throw new RunStoreError(
        `Run artifact must not exceed ${MAX_RUN_ARTIFACT_BYTES} bytes.`,
        { code: "ERR_INVALID_RUN_ARTIFACT" },
      );
    }

    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      assertRunCanAdvance(
        (await loadSnapshot(runDirectory, record.runId)).state,
        resolveStopBoundary,
      );
      const artifactPath = await resolveRunArtifactPath(
        runDirectory,
        relativePath,
      );
      await atomicWriteFile(artifactPath, content);
      return artifactPath;
    });
  }

  async function readPublicActivity(
    runId,
    { afterRevision = 0, limit = DEFAULT_ACTIVITY_LIMIT } = {},
  ) {
    if (
      !Number.isSafeInteger(afterRevision) ||
      afterRevision < 0 ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > MAX_ACTIVITY_LIMIT
    ) {
      throw new RunStoreError("Public activity cursor or limit is invalid.", {
        code: "ERR_INVALID_ACTIVITY_CURSOR",
      });
    }

    const runDirectory = await getRunDirectory(runId);
    const snapshot = await loadSnapshot(runDirectory, runId);
    if (afterRevision > snapshot.state.revision) {
      throw new RunStoreError("Public activity cursor is ahead of the run.", {
        code: "ERR_INVALID_ACTIVITY_CURSOR",
      });
    }
    const drain = async (source) => {
      const activities = [];
      let cursor = source.state.revision;
      for await (const activity of journal.publicActivities(
        runDirectory,
        source,
        afterRevision,
      )) {
        // Drain the certified prefix even after filling the bounded page.
        if (activities.length === limit) continue;
        activities.push(activity);
        if (activities.length === limit) {
          cursor = activity.revision;
        }
      }
      return deepFreeze({ activities, cursor });
    };

    try {
      return await drain(snapshot);
    } catch (cause) {
      if (
        !(cause instanceof RunStoreError) ||
        cause.code !== "ERR_INVALID_EVENT_LOG"
      )
        throw cause;
      // The owner may publish during this lock-free drain. Stream observations
      // cannot distinguish that from an edit, so reread once only after the
      // original certified prefix is proven unchanged and validly extended.
      const extended = await journal.extendSnapshot(runDirectory, snapshot);
      if (extended === null) throw cause;
      return drain(await authorizeSnapshot(runDirectory, extended));
    }
  }

  const preparation = createPreparationService({
    runLeases,
    journal,
    loadSnapshot,
    timestamp,
    hostName,
    processId,
    processIdentity,
    processIsAlive,
    resolveStopBoundary,
    onBoundary: onPreparationBoundary,
    gate: createMutationBoundary({
      hostName,
      processId,
      processIsAlive,
      processIdentity,
      onPublicationBoundary: onLeasePublicationBoundary,
      prefix: ".custody-",
    }),
  });
  const stops = createStopService({
    preparation,
    resolveStopBoundary,
    actions,
    getRunDirectory,
    loadSnapshot,
    journal,
    mutate,
    runLeases,
    timestamp,
  });
  async function inspectRunLeaseOwner(runId) {
    return runLeases.inspect(await getRunDirectory(runId), runId);
  }
  async function recordExecutionProcess(lease, pid, proof = null) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      if (pid !== null) {
        assertRunCanAdvance(snapshot.state, resolveStopBoundary);
        if (snapshot.state.executionProcess !== null) {
          throw new RunStoreError(
            "The preceding execution process must stop first.",
            {
              code: "ERR_EXECUTION_PROCESS_ACTIVE",
            },
          );
        }
      } else if (snapshot.state.executionProcess === null)
        return snapshot.state;
      const identity = pid === null ? null : await processIdentity(pid);
      const launchCutoff = identity === null ? null : { ...identity };
      const ancestryBaseline =
        pid === null ||
        proof === null ||
        !Object.hasOwn(proof, "ancestryBaseline")
          ? null
          : proof.ancestryBaseline;
      if (
        proof !== null &&
        (!isDeepStrictEqual(identity, proof.processIdentity) ||
          (Object.hasOwn(proof, "launchCutoff") &&
            !isDeepStrictEqual(launchCutoff, proof.launchCutoff)))
      ) {
        throw new RunStoreError(
          "Execution identity changed before registration.",
          {
            code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          },
        );
      }
      const next = normalizeRunState(
        {
          ...snapshot.state,
          executionProcess:
            pid === null
              ? null
              : {
                  pid,
                  hostname: hostName,
                  processIdentity: identity,
                  namespaceId: proof?.namespaceId ?? null,
                  launchCutoff,
                  ancestryBaseline,
                  controlGroup: proof?.controlGroup ?? null,
                },
          revision: snapshot.state.revision + 1,
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      await journal.appendTransition(runDirectory, next, snapshot, {
        actor: "runner",
        phase: "execution",
        kind: pid === null ? "stopped" : "started",
        message:
          pid === null
            ? "Owned execution process stopped."
            : "Owned execution process recorded before launch.",
      });
      return deepFreeze(next);
    });
  }
  async function recordExecutionResource(lease, resource) {
    const normalized = normalizeExecutionResource(resource);
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      if (snapshot.state.preparation != null) {
        throw new RunStoreError(
          "Preparation custody must settle before storage changes.",
          { code: "ERR_EXECUTION_PROCESS_ACTIVE" },
        );
      }
      const previous = snapshot.state.executionResource;
      const { owner: previousOwner, ...withoutOwner } = previous ?? {};
      const settlesAcquisition =
        previous?.phase === "acquiring" &&
        isDeepStrictEqual(normalized, { ...withoutOwner, phase: "allocated" });
      if (["allocating", "acquiring"].includes(normalized?.phase))
        assertRunCanAdvance(snapshot.state, resolveStopBoundary);
      if (
        (normalized?.phase === "allocating" && previous !== null) ||
        (normalized?.phase === "acquiring" &&
          (previous?.phase !== "allocated" ||
            snapshot.state.executionProcess !== null ||
            !isDeepStrictEqual(
              { ...previous, phase: "acquiring", owner: normalized.owner },
              normalized,
            ))) ||
        (normalized?.phase === "allocated" &&
          !settlesAcquisition &&
          (previous?.phase !== "allocating" ||
            !isDeepStrictEqual(
              { ...normalized, phase: "allocating", directory: null },
              previous,
            ))) ||
        (normalized === null && snapshot.state.executionProcess !== null)
      ) {
        throw new RunStoreError("Execution resource transition is unsafe.", {
          code: "ERR_EXECUTION_RESOURCE_ACTIVE",
        });
      }
      if (normalized === null && previous === null) return snapshot.state;
      const next = normalizeRunState(
        {
          ...snapshot.state,
          executionResource: normalized,
          revision: snapshot.state.revision + 1,
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      await journal.appendTransition(runDirectory, next, snapshot, {
        actor: "runner",
        phase: "execution",
        kind: normalized === null ? "resource-cleaned" : "resource-recorded",
        message:
          normalized === null
            ? "Owned execution storage cleaned."
            : "Execution storage ownership recorded before launch.",
      });
      return deepFreeze(next);
    });
  }
  async function inspectExecutionProcess(runId) {
    const record = (await loadRun(runId)).executionProcess;
    const localIdentity =
      record?.hostname === hostName ? await processIdentity(processId) : null;
    return record === null
      ? null
      : deepFreeze({
          ...record,
          status: await inspectProcessOwner(record, {
            hostName,
            processIsAlive,
            processIdentity,
          }),
          previousBoot:
            record.processIdentity !== null &&
            localIdentity !== null &&
            record.processIdentity.bootId !== localIdentity.bootId,
        });
  }
  return Object.freeze({
    capturePreservation: preservation.capture,
    restorePreservation: preservation.restore,
    reconcilePreservation: preservation.reconcile,
    readPreservation: preservation.read,
    reservePreparation: preparation.reserve,
    recordPreparationProcess: preparation.record,
    settlePreparation: preparation.settle,
    recoverPreparation: preparation.recover,
    startObservationAttempt,
    recordObservationBatch,
    recordExecutionResource,
    recordExecutionProcess,
    inspectExecutionProcess,
    requestOperatorStop: stops.request,
    recordStopActivity: stops.activity,
    completeOperatorStop: stops.complete,
    settleCheckpoint: stops.settleCheckpoint,
    loadStopCheckpoint: stops.checkpoint,
    inspectRunLeaseOwner,
    beginAction: actions.begin,
    admitRuntime: runtimeAdmission.admit,
    assertRuntimeBoundary,
    activateRuntime: runtimeAdmission.activate,
    readRuntime: runtimeAdmission.read,
    releaseRuntime: runtimeAdmission.release,
    rootPath: requestedStateRoot,
    acquireRunLease,
    acquireWorktreeLease,
    acquireInfrastructureLease: (path, runId) =>
      acquireWorktreeLease(path, runId, true),
    assertWorkspaceLease,
    bindWorkspaceReads,
    createRun,
    getRunDirectory,
    finishAgentTurn,
    loadRun,
    loadRunHistory,
    migrateRun,
    readPublicActivity,
    readAction: actions.read,
    recordChildSession,
    recordProviderPolicy,
    recordSessionNaming,
    scheduleAvailabilityRetry,
    completeAvailabilityTurn,
    completeInactivityTurn,
    recordInactivity,
    recoverRun,
    inspectRecoveryDispatch,
    recordRecoveryDispatch,
    recordRecoveryFailure: recoveryFailures.record,
    readRecoveryFailure: recoveryFailures.read,
    inspectDispatchOwner,
    runIsLeased,
    runLeaseOwnerIsLive,
    startAgentTurn,
    transitionRun,
    validateStateBoundary,
    waitForRunChange,
    worktreeIsLeased,
    worktreeLeaseOwner,
    withGuidanceLease,
    writeRunArtifact,
  });
}
