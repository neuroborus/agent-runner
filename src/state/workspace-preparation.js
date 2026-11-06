import { createHash } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { createWorkspaceService } from "../workspace/index.js";
import { assertRunCanAdvance } from "./stop-policy.js";
import {
  deepFreeze,
  MAX_WORKSPACE_PREPARATION_BYTES,
  normalizeDirectoryPolicy,
  normalizeRunState,
  normalizeWorkspacePreparation,
  RunStoreError,
  workspacePreparationInputFingerprint,
} from "./validation.js";

const workspace = createWorkspaceService();
const hash = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (path) =>
  typeof path === "string" &&
  path.length <= 4096 &&
  isAbsolute(path) &&
  resolve(path) === path &&
  !/[\0\r\n]/u.test(path);
const exact = (value, keys) =>
  value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join() === keys;
const sha = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const identity = (stat) => ({
  device: String(stat.dev),
  inode: String(stat.ino),
  mode: String(stat.mode),
});
const fileIdentity = (stat) => ({
  ...identity(stat),
  size: String(stat.size),
  modifiedNs: String(stat.mtimeNs),
  changedNs: String(stat.ctimeNs),
});

function invalid() {
  throw new RunStoreError(
    "Frozen workspace preparation is invalid or changed.",
    {
      code: "ERR_WORKSPACE_PREPARATION_CHANGED",
    },
  );
}

function absentInputPaths(preparation) {
  return preparation.inputs
    .filter(({ contentHash }) => contentHash === null)
    .map(({ path }) => path);
}

async function directoryBindings(paths) {
  const bindings = new Map();
  for (const path of paths) {
    if (!canonical(path)) invalid();
    for (let current = path; ; current = dirname(current)) {
      if (bindings.has(current)) break;
      if (bindings.size >= 4096) invalid();
      const stat = await lstat(current, { bigint: true });
      if (!stat.isDirectory() || (await realpath(current)) !== current)
        invalid();
      bindings.set(current, { path: current, ...identity(stat) });
      if (current === dirname(current)) break;
    }
  }
  return [...bindings.values()].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
}

async function readInput(input) {
  let before;
  try {
    before = await lstat(input.path, { bigint: true });
  } catch (cause) {
    if (cause?.code === "ENOENT" && input.contentHash === null)
      return { ...input, identity: null };
    throw cause;
  }
  if (input.contentHash === null || !before.isFile() || before.nlink !== 1n)
    invalid();
  const source = await workspace.readFile({
    path: input.path,
    projectPath: dirname(input.path),
    maxBytes: MAX_WORKSPACE_PREPARATION_BYTES,
  });
  const after = await lstat(input.path, { bigint: true });
  if (
    !isDeepStrictEqual(fileIdentity(before), fileIdentity(after)) ||
    hash(source) !== input.contentHash
  )
    invalid();
  return { ...input, identity: fileIdentity(after) };
}

// Admission reads only bounded exact text inputs and real routing directories.
// It does not discover controls or descend into any source tree.
export async function createWorkspacePreparation(request, run, stateRoot) {
  if (request == null) return null;
  if (
    !exact(request, "inputs,leasePath,policy") ||
    Buffer.byteLength(JSON.stringify(request)) >
      MAX_WORKSPACE_PREPARATION_BYTES ||
    !Array.isArray(request.inputs) ||
    request.inputs.length > 256 ||
    request.inputs.some(
      (input) =>
        !exact(input, "contentHash,path") ||
        !canonical(input.path) ||
        (input.contentHash !== null && !sha(input.contentHash)),
    ) ||
    new Set(request.inputs.map(({ path }) => path)).size !==
      request.inputs.length
  )
    invalid();
  const policy = normalizeDirectoryPolicy(request.policy, run);
  const configuration = run.projectConfigurationProtection;
  if (
    policy.stateRoot !== stateRoot ||
    run.pipelineState.workflowState !== "CLARIFY" ||
    run.pause !== null ||
    (configuration != null &&
      !request.inputs.some(
        ({ path, contentHash }) =>
          path === configuration.path &&
          contentHash === configuration.contentHash,
      )) ||
    !canonical(request.leasePath) ||
    request.inputs.some(
      ({ path }) =>
        !(
          path.startsWith(`${run.taskPath}${sep}`) ||
          [...policy.inputPaths, ...policy.configurationPaths].includes(path)
        ),
    )
  )
    invalid();
  const paths = [
    run.projectPath,
    run.taskPath,
    stateRoot,
    request.leasePath,
    ...request.inputs.map(({ path }) => dirname(path)),
  ];
  const rootBindings = await directoryBindings(paths);
  const inputs = [];
  for (const input of [...request.inputs].sort((a, b) =>
    a.path < b.path ? -1 : 1,
  ))
    inputs.push(await readInput(input));
  const value = {
    schemaVersion: 1,
    leasePath: request.leasePath,
    policy,
    rootBindings,
    inputs,
    inputFingerprint: workspacePreparationInputFingerprint(run),
  };
  normalizeWorkspacePreparation(value, { ...run, schemaVersion: 25 });
  await verifyWorkspacePreparation(value);
  return value;
}

async function verifyWorkspacePreparation(value) {
  if (
    !isDeepStrictEqual(
      value.rootBindings,
      await directoryBindings(value.rootBindings.map(({ path }) => path)),
    )
  )
    invalid();
  for (const { identity: expected, ...input } of value.inputs) {
    if (!isDeepStrictEqual((await readInput(input)).identity, expected))
      invalid();
  }
  if (
    !isDeepStrictEqual(
      value.rootBindings,
      await directoryBindings(value.rootBindings.map(({ path }) => path)),
    )
  )
    invalid();
}

// The root supplies a fresh verified capture. It runs outside the short state
// mutation boundary so stops remain publishable; no partial result is stored.
export function createWorkspacePreparationService({
  runLeases,
  worktreeLeases,
  getWorktreeLeaseDirectory,
  loadSnapshot,
  journal,
  timestamp,
  resolveStopBoundary,
}) {
  async function capture(
    lease,
    { worktreeLease, expectedRevision, signal, capture: inspect },
  ) {
    if (
      typeof inspect !== "function" ||
      !Number.isSafeInteger(expectedRevision) ||
      expectedRevision < 1
    )
      invalid();
    return runLeases.withCurrentOwner(lease, async ({ assertOwner }) =>
      worktreeLeases.holdCurrent(worktreeLease, async (owner) =>
        worktreeLeases.withCurrentOwner(
          worktreeLease,
          async ({ assertOwner: assertWorkspaceOwner }) => {
            async function inspectCurrent(record, runDirectory) {
              signal?.throwIfAborted();
              const snapshot = await loadSnapshot(runDirectory, record.runId);
              const state = snapshot.state;
              assertRunCanAdvance(state, resolveStopBoundary, {
                allowWorkspacePreparation: true,
              });
              const pending = state.workspacePreparation;
              if (state.revision !== expectedRevision)
                throw new RunStoreError(
                  "Run changed during workspace preparation.",
                  { code: "ERR_RUN_REVISION_CHANGED" },
                );
              if (
                pending == null ||
                state.pause !== null ||
                state.pipelineState.workflowState !== "CLARIFY" ||
                owner.record.runId !== state.runId ||
                owner.runDirectory !==
                  (await getWorktreeLeaseDirectory(pending.leasePath))
              )
                invalid();
              await verifyWorkspacePreparation(pending);
              await assertOwner();
              await assertWorkspaceOwner();
              signal?.throwIfAborted();
              return snapshot;
            }
            const initial = await runLeases.runExclusive(
              lease,
              async ({ record, runDirectory }) =>
                inspectCurrent(record, runDirectory),
            );
            const workspace = await inspect(
              deepFreeze(structuredClone(initial.state.workspacePreparation)),
              { signal },
            );
            signal?.throwIfAborted();
            return runLeases.runExclusive(
              lease,
              async ({ record, runDirectory }) => {
                const snapshot = await inspectCurrent(record, runDirectory);
                const pending = snapshot.state.workspacePreparation;
                if (
                  workspace?.kind !== "directory" ||
                  workspace.leasePath !== pending.leasePath ||
                  !isDeepStrictEqual(workspace.policy, pending.policy) ||
                  !isDeepStrictEqual(
                    workspace.absentInputPaths,
                    absentInputPaths(pending),
                  )
                )
                  invalid();
                const next = normalizeRunState(
                  {
                    ...snapshot.state,
                    workspacePreparation: null,
                    workspace,
                    revision: snapshot.state.revision + 1,
                    updatedAt: timestamp(snapshot.state.updatedAt),
                  },
                  record.runId,
                );
                await journal.appendTransition(runDirectory, next, snapshot, {
                  actor: "runner",
                  phase: "workspace-preparation",
                  kind: "captured",
                  message: "Verified workspace preparation completed.",
                });
                return deepFreeze(next);
              },
            );
          },
        ),
      ),
    );
  }
  return Object.freeze({ capture });
}

export function assertWorkspacePreparationContinuity(
  previous,
  current,
  activity,
) {
  const before = previous.workspacePreparation;
  const after = current.workspacePreparation;
  if (isDeepStrictEqual(before, after)) return false;
  // Absence is completed historical preparation, never an invitation to admit
  // a new selection. Only the exact pending selection can publish once.
  const stationary = ({
    workspacePreparation,
    workspace,
    revision,
    updatedAt,
    ...state
  }) => state;
  if (
    before == null ||
    after !== null ||
    current.workspace?.kind !== "directory" ||
    current.workspace.leasePath !== before.leasePath ||
    !isDeepStrictEqual(current.workspace.policy, before.policy) ||
    !isDeepStrictEqual(
      current.workspace.absentInputPaths,
      absentInputPaths(before),
    ) ||
    activity?.actor !== "runner" ||
    activity.phase !== "workspace-preparation" ||
    activity.kind !== "captured" ||
    previous.pause !== null ||
    previous.pipelineState.workflowState !== "CLARIFY" ||
    (previous.stopRequest != null &&
      previous.stopRequest.reconciledRevision === null) ||
    !isDeepStrictEqual(stationary(previous), stationary(current))
  )
    invalid();
  return true;
}
