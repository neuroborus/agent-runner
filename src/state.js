import { createHash, randomUUID } from "node:crypto";
import { watch } from "node:fs";
import { lstat, mkdir, realpath, rm, rmdir } from "node:fs/promises";
import { homedir, hostname } from "node:os";
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { isDeepStrictEqual } from "node:util";

import { createActionStore } from "./state-actions.js";
import { atomicWriteFile, resolveRunArtifactPath } from "./state-files.js";
import { createStateJournal } from "./state-journal.js";
import { createLeaseManager } from "./state-lease.js";
import {
  assertRunId,
  deepFreeze,
  normalizeChildSession,
  normalizePublicActivity,
  normalizeRunState,
  normalizeTransitionPatch,
  RUNTIME_COMPATIBILITY,
  RUNTIME_COMPATIBILITY_TOKEN,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  RUN_STATE_SCHEMA_VERSION,
  RunStoreError,
} from "./state-validation.js";

export {
  RUNTIME_COMPATIBILITY,
  RUNTIME_COMPATIBILITY_TOKEN,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  RUN_STATE_SCHEMA_VERSION,
  RunStoreError,
};

const DEFAULT_LEASE_STALE_MS = 5 * 60 * 1_000;

const RUNS_DIRECTORY = "runs";
const WORKTREES_DIRECTORY = "worktrees";
const CREATE_RUN_FIELDS = new Set([
  "runId",
  "pipelineId",
  "pipelineStateVersion",
  "projectPath",
  "taskPath",
  "roles",
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
      const parentPath = dirname(currentPath);
      if (parentPath === currentPath) {
        throw cause;
      }
      missingComponents.push(currentPath.slice(parentPath.length + 1));
      currentPath = parentPath;
    }
  }
}

function assertStateRootOutside(stateRoot, projectPath, taskPath) {
  for (const [boundaryPath, name] of [
    [projectPath, "project"],
    [taskPath, "task directory"],
  ]) {
    if (isWithin(boundaryPath, stateRoot)) {
      throw new RunStoreError(
        `State root must remain outside the ${name}: ${stateRoot}.`,
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
  const xdgStateHome = env?.XDG_STATE_HOME;
  let basePath;
  if (typeof xdgStateHome === "string" && isAbsolute(xdgStateHome)) {
    basePath = xdgStateHome;
  } else if (
    typeof homeDirectory === "string" &&
    isAbsolute(homeDirectory)
  ) {
    basePath = join(homeDirectory, ".local", "state");
  }

  if (basePath === undefined) {
    throw new RunStoreError("State-directory base path must be absolute.", {
      code: "ERR_INVALID_STATE_ROOT",
    });
  }

  return resolve(basePath, "agent-runner");
}

export function createRunStore({
  stateRoot = resolveStateRoot(),
  clock = () => new Date(),
  runIdFactory = randomUUID,
  leaseTokenFactory = randomUUID,
  hostName = hostname(),
  processId = process.pid,
  processIsAlive = defaultProcessIsAlive,
  leaseStaleMs = DEFAULT_LEASE_STALE_MS,
  onLeasePublicationBoundary = async () => {},
  onTransitionBoundary = async () => {},
} = {}) {
  if (typeof stateRoot !== "string" || !isAbsolute(stateRoot)) {
    throw new RunStoreError("State root must be an absolute path.", {
      code: "ERR_INVALID_STATE_ROOT",
    });
  }
  if (
    typeof clock !== "function" ||
    typeof runIdFactory !== "function" ||
    typeof leaseTokenFactory !== "function" ||
    typeof processIsAlive !== "function" ||
    typeof onLeasePublicationBoundary !== "function" ||
    typeof onTransitionBoundary !== "function" ||
    typeof hostName !== "string" ||
    hostName.length === 0 ||
    hostName.length > 255 ||
    /[\p{Cc}\p{Zl}\p{Zp}]/u.test(hostName) ||
    !Number.isSafeInteger(processId) ||
    processId < 1 ||
    !Number.isSafeInteger(leaseStaleMs) ||
    leaseStaleMs < 0
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

  const journal = createStateJournal({ onTransitionBoundary });
  const runLeases = createLeaseManager({
    currentDate,
    hostName,
    processId,
    processIsAlive,
    onPublicationBoundary: onLeasePublicationBoundary,
    staleMs: leaseStaleMs,
    timestamp,
    tokenFactory: leaseTokenFactory,
  });
  const worktreeLeases = createLeaseManager({
    activeLeaseDescription: "Worktree lease",
    conflictCode: "ERR_WORKTREE_LEASED",
    currentDate,
    hostName,
    invalidLeaseCode: "ERR_INVALID_WORKTREE_LEASE",
    leaseDescription: "Worktree lease",
    leaseSubject: (runId) => `Run ${runId}'s Git worktree`,
    processId,
    processIsAlive,
    onPublicationBoundary: onLeasePublicationBoundary,
    reclaimingLeaseDescription: "Reclaiming worktree lease",
    requireMatchingRunId: false,
    staleMs: leaseStaleMs,
    timestamp,
    tokenFactory: leaseTokenFactory,
  });
  const actions = createActionStore({
    clock,
    hostName,
    processId,
    processIsAlive,
    onPublicationBoundary: onLeasePublicationBoundary,
    stateRoot: requestedStateRoot,
    tokenFactory: leaseTokenFactory,
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

  async function getWorktreeLeaseDirectory(projectPath) {
    const [canonicalProjectPath, potentialStateRoot] = await Promise.all([
      canonicalDirectory(projectPath, "Project path"),
      canonicalPotentialPath(requestedStateRoot),
    ]);
    assertStateRootOutside(
      potentialStateRoot,
      canonicalProjectPath,
      canonicalProjectPath,
    );
    const { rootPath } = await ensureRoot();
    assertStateRootOutside(
      rootPath,
      canonicalProjectPath,
      canonicalProjectPath,
    );
    const worktreesPath = await ensureManagedDirectory(
      join(rootPath, WORKTREES_DIRECTORY),
      "State worktrees path",
    );
    const key = createHash("sha256")
      .update(canonicalProjectPath)
      .digest("hex");
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
    assertStateRootOutside(potentialStateRoot, projectPath, taskPath);

    const { rootPath, runsPath } = await ensureRoot();
    assertStateRootOutside(rootPath, projectPath, taskPath);

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
          roles: input.roles,
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
        { events: [], hasPartialTail: false, validByteLength: 0 },
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
          if (
            !["EEXIST", "ENOENT", "ENOTEMPTY"].includes(cleanupCause?.code)
          ) {
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
    assertStateRootOutside(potentialStateRoot, project, task);
    return Object.freeze({ projectPath: project, taskPath: task });
  }

  async function acquireRunLease(runId) {
    const runDirectory = await getRunDirectory(runId);
    await loadSnapshot(runDirectory, runId);
    const lease = await runLeases.acquire(runDirectory, runId);
    try {
      await runLeases.runExclusive(lease, () =>
        loadSnapshot(runDirectory, runId),
      );
      return lease;
    } catch (cause) {
      await lease.release();
      throw cause;
    }
  }

  async function loadSnapshot(runDirectory, runId) {
    const snapshot = await journal.loadSnapshot(runDirectory, runId);
    assertStateRootOutside(
      runDirectory,
      snapshot.state.projectPath,
      snapshot.state.taskPath,
    );
    return snapshot;
  }

  async function loadRun(runId) {
    const runDirectory = await getRunDirectory(runId);
    return deepFreeze((await loadSnapshot(runDirectory, runId)).state);
  }

  async function runIsLeased(runId) {
    const runDirectory = await getRunDirectory(runId);
    return runLeases.isLeased(runDirectory, runId);
  }

  async function acquireWorktreeLease(projectPath, runId) {
    assertRunId(runId);
    const worktreeDirectory = await getWorktreeLeaseDirectory(projectPath);
    return worktreeLeases.acquire(worktreeDirectory, runId);
  }

  async function worktreeIsLeased(projectPath, runId) {
    assertRunId(runId);
    const worktreeDirectory = await getWorktreeLeaseDirectory(projectPath);
    return worktreeLeases.isLeased(worktreeDirectory, runId);
  }

  async function worktreeLeaseOwner(projectPath, runId) {
    assertRunId(runId);
    const worktreeDirectory = await getWorktreeLeaseDirectory(projectPath);
    return worktreeLeases.owner(worktreeDirectory, runId);
  }

  async function waitForRunChange(
    runId,
    { afterRevision, timeoutMs, signal } = {},
  ) {
    if (
      !Number.isSafeInteger(afterRevision) ||
      afterRevision < 0 ||
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 0 ||
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
    return new Promise((resolvePromise, rejectPromise) => {
      let settled = false;
      let timer;
      let watcher;

      const finish = (operation, value) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        watcher?.close();
        operation(value);
      };
      const load = async () => {
        try {
          const current = await loadRun(runId);
          if (current.revision > afterRevision) {
            finish(resolvePromise, current);
          }
        } catch (cause) {
          finish(rejectPromise, cause);
        }
      };
      const onAbort = () =>
        finish(
          rejectPromise,
          signal.reason ?? new DOMException("Aborted", "AbortError"),
        );

      try {
        watcher = watch(
          runDirectory,
          { persistent: false },
          (_eventType, filename) => {
            if (
              filename === null ||
              ["events.jsonl", "state.json"].includes(filename.toString())
            ) {
              void load();
            }
          },
        );
        watcher.on("error", (cause) => finish(rejectPromise, cause));
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
    });
  }

  async function recoverRun(lease) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      await journal.recover(runDirectory, snapshot);
      return deepFreeze(snapshot.state);
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

  async function transitionRun(lease, patch, { activity } = {}) {
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
      await journal.appendTransition(
        runDirectory,
        nextState,
        snapshot,
        normalizedActivity,
      );
      return deepFreeze(nextState);
    });
  }

  async function recordChildSession(
    lease,
    childSession,
    { activity } = {},
  ) {
    const normalizedChild = normalizeChildSession(childSession);
    const normalizedActivity = normalizePublicActivity(activity);

    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
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

    return runLeases.runExclusive(lease, async ({ runDirectory }) => {
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
    const { events } = await loadSnapshot(runDirectory, runId);
    if (afterRevision > events.at(-1).revision) {
      throw new RunStoreError("Public activity cursor is ahead of the run.", {
        code: "ERR_INVALID_ACTIVITY_CURSOR",
      });
    }
    const activities = [];
    let cursor = afterRevision;

    for (const event of events) {
      if (event.revision <= afterRevision) {
        continue;
      }
      cursor = event.revision;
      if (event.activity !== null) {
        activities.push({
          revision: event.revision,
          recordedAt: event.recordedAt,
          ...event.activity,
        });
        if (activities.length === limit) {
          break;
        }
      }
    }

    return deepFreeze({ activities, cursor });
  }

  return Object.freeze({
    beginAction: actions.begin,
    rootPath: requestedStateRoot,
    acquireRunLease,
    acquireWorktreeLease,
    createRun,
    getRunDirectory,
    loadRun,
    migrateRun,
    readPublicActivity,
    readAction: actions.read,
    recordChildSession,
    recoverRun,
    runIsLeased,
    transitionRun,
    validateStateBoundary,
    waitForRunChange,
    worktreeIsLeased,
    worktreeLeaseOwner,
    writeRunArtifact,
  });
}
