import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  normalizeDispatchOwner,
  normalizeRecoveryDispatch,
} from "./dispatch.js";
import { publishExclusiveFile, readOptionalPublishedText } from "./files.js";
import { assertRunId, deepFreeze, RunStoreError } from "./validation.js";

const MAX_FAILURE_BYTES = 4_096;
const STAGES = new Set([
  "runtime-compatibility",
  "execution-lease",
  "state-recovery",
  "process-recovery",
  "resource-recovery",
  "worktree-lease",
  "checkpoint-continuation",
]);
const EXPLANATIONS = new Map([
  ["ERR_RUNTIME_VERSION_SKEW", "The recovery runtime is incompatible."],
  ["ERR_RUNTIME_MIGRATION_REQUIRED", "The run requires a runtime migration."],
  ["ERR_RUN_LEASED", "Execution ownership could not be acquired."],
  ["ERR_INVALID_RUN_LEASE", "Execution lease evidence is invalid."],
  ["ERR_RUN_LEASE_BUSY", "Execution lease mutation is still in progress."],
  ["ERR_RUN_MUTATION_BUSY", "A state mutation is still in progress."],
  ["ERR_INVALID_RUN_MUTATION", "State mutation evidence is invalid."],
  ["ERR_WORKTREE_LEASED", "Worktree ownership could not be acquired."],
  ["ERR_INVALID_WORKTREE_LEASE", "Worktree lease evidence is invalid."],
  ["ERR_EXECUTION_PROCESS_ACTIVE", "An execution process remains active."],
  [
    "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    "Execution process ownership could not be verified.",
  ],
  [
    "ERR_EXECUTION_RESOURCE_UNVERIFIABLE",
    "Execution resource ownership could not be verified.",
  ],
  [
    "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE",
    "Trusted validation resource ownership could not be verified.",
  ],
  ["ERR_RUN_REVISION_CHANGED", "The recovery revision is stale."],
  ["ERR_INVALID_RUN_STATE", "The saved run state is invalid."],
  ["ERR_INVALID_EVENT_LOG", "The saved run journal is invalid."],
  ["ERR_UNSAFE_STATE_FILE", "A managed state file is unsafe."],
  [
    "ERR_PROJECT_CONFIGURATION_CHANGED",
    "Frozen project configuration changed.",
  ],
  ["ERR_RUN_PATH_CHANGED", "A frozen run path changed."],
  ["ERR_PROVIDER_POLICY_CHANGED", "The frozen provider policy changed."],
]);
const UNAVAILABLE = "The recovery cause is unavailable.";
const FIELDS = [
  "schemaVersion",
  "runId",
  "dispatch",
  "owner",
  "stage",
  "code",
  "explanation",
];

function invalid() {
  throw new RunStoreError("Detached recovery failure is invalid.", {
    code: "ERR_INVALID_RECOVERY_FAILURE",
  });
}

function hasFields(value, fields) {
  return (
    value !== null &&
    typeof value === "object" &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function parseFailure(source) {
  if (Buffer.byteLength(source) > MAX_FAILURE_BYTES) invalid();
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    invalid();
  }
  if (
    !hasFields(value, FIELDS) ||
    value.schemaVersion !== 1 ||
    !STAGES.has(value.stage) ||
    (value.code !== null && !EXPLANATIONS.has(value.code)) ||
    value.explanation !== (EXPLANATIONS.get(value.code) ?? UNAVAILABLE)
  )
    invalid();
  assertRunId(value.runId);
  normalizeRecoveryDispatch(value.dispatch);
  normalizeDispatchOwner(value.owner);
  return value;
}

async function readFailure(path) {
  try {
    const source = await readOptionalPublishedText(path, {
      maxBytes: MAX_FAILURE_BYTES,
    });
    return source === null ? null : parseFailure(source);
  } catch (cause) {
    if (cause?.code === "ERR_STATE_FILE_TOO_LARGE") invalid();
    throw cause;
  }
}

// Each dispatch has its own immutable sidecar: a late child cannot replace a
// later dispatch's cause. Neither publication nor inspection needs a run lease.
export function createRecoveryFailureStore({
  getRunDirectory,
  hostName,
  processId,
  processIdentity,
  onPublicationBoundary,
}) {
  async function failurePath(runId, dispatch) {
    return join(
      await getRunDirectory(runId),
      `.recovery-failure-${dispatch.id}.json`,
    );
  }

  async function record(runId, value, failure) {
    assertRunId(runId);
    const dispatch = normalizeRecoveryDispatch(value);
    if (!hasFields(failure, ["stage", "error"]) || !STAGES.has(failure.stage))
      invalid();
    const owner = normalizeDispatchOwner({
      pid: processId,
      hostname: hostName,
      processIdentity: await processIdentity(processId),
    });
    const code = EXPLANATIONS.has(failure.error?.code)
      ? failure.error.code
      : null;
    const diagnostic = {
      schemaVersion: 1,
      runId,
      dispatch,
      owner,
      stage: failure.stage,
      code,
      explanation: EXPLANATIONS.get(code) ?? UNAVAILABLE,
    };
    const source = `${JSON.stringify(diagnostic)}\n`;
    parseFailure(source);
    const path = await failurePath(runId, dispatch);
    try {
      await publishExclusiveFile(path, source, { onPublicationBoundary });
    } catch (cause) {
      if (cause?.code !== "EEXIST") throw cause;
      const existing = await readFailure(path);
      if (existing === null || !isDeepStrictEqual(existing, diagnostic))
        throw new RunStoreError("Detached recovery failure already differs.", {
          code: "ERR_RECOVERY_FAILURE_CONFLICT",
        });
    }
    return deepFreeze(diagnostic);
  }

  // The caller supplies the child identity already saved in the action intent.
  // Missing historical causes and evidence for any other dispatch stay absent.
  async function read(runId, value) {
    assertRunId(runId);
    if (!hasFields(value, ["id", "expectedRevision", "owner"])) invalid();
    const dispatch = normalizeRecoveryDispatch({
      id: value.id,
      expectedRevision: value.expectedRevision,
    });
    // Legacy/unregistered children have no usable identity to correlate.
    if (value.owner === null) return null;
    const owner = normalizeDispatchOwner(value.owner);
    const diagnostic = await readFailure(await failurePath(runId, dispatch));
    if (diagnostic === null) return null;
    return diagnostic.runId === runId &&
      isDeepStrictEqual(diagnostic.dispatch, dispatch) &&
      isDeepStrictEqual(diagnostic.owner, owner)
      ? deepFreeze(diagnostic)
      : null;
  }

  return Object.freeze({ record, read });
}
