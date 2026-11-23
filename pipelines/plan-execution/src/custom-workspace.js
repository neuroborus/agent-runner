import { isAbsolute, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { PlanExecutionWorkflowError } from "./errors.js";
import { validationEvidenceFingerprint as hash } from "./validation-schedule.js";

// Equal to the run-state collection limit that legacy full baselines must fit.
const LEGACY_BASELINE_CAPACITY = 10_000;
const SCOPE = ["workspacePath", "outputPaths", "allowedPaths", "projectPath"];
const FILTERED = [
  "entryCount",
  "entriesHash",
  "remainderCount",
  "remainderHash",
];

const within = (root, path) =>
  path === root || path.startsWith(`${root}${sep}`);
const changed = () =>
  new PlanExecutionWorkflowError("Inspected custom workspace changed.", {
    code: "ERR_READ_ONLY_REPOSITORY_CHANGED",
  });
const equalFields = (before, after, fields) =>
  fields.every((field) => isDeepStrictEqual(before[field], after[field]));

// Adapt only inspection operations. There are no Git effects in this facade.
// A run keeps the representation of its persisted baseline: legacy full
// snapshots stay full, while new runs persist the bounded output projection.
export function customWorkspace(workspace, projectPath, baseline = null) {
  const legacy = baseline !== null && Object.hasOwn(baseline, "entries");
  async function inspect({ allowedPaths = [] } = {}) {
    const { snapshot, baseline: projected } = await workspace.outputBaseline({
      allowedPaths,
    });
    const contentFingerprint = hash(
      snapshot.entries.map(({ path, kind, mode, size, hash }) => ({
        path,
        kind,
        mode,
        size,
        hash,
      })),
    );
    const complete = {
      ...snapshot,
      schemaVersion: 1,
      projectPath,
      allowedPaths,
      contentFingerprint,
    };
    return {
      complete,
      projected: {
        ...projected,
        projectPath,
        allowedPaths,
        contentFingerprint,
      },
    };
  }
  // Return the run's persisted representation before any transition uses it.
  async function persisted(options) {
    const { complete, projected } = await inspect(options);
    if (!legacy) return projected;
    if (
      complete.entries.length > LEGACY_BASELINE_CAPACITY ||
      complete.linkResolutions.length > LEGACY_BASELINE_CAPACITY
    )
      throw new PlanExecutionWorkflowError(
        "The legacy full custom baseline exceeds the run-state capacity.",
        { code: "ERR_CUSTOM_BASELINE_CAPACITY" },
      );
    return complete;
  }
  function assertRepresentation(before) {
    if (Object.hasOwn(before ?? {}, "entries") !== legacy)
      throw new PlanExecutionWorkflowError(
        "Custom workspace baselines cannot change representation.",
        { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
      );
  }
  async function completeSnapshot(options) {
    return (await inspect(options)).complete;
  }
  async function assertUnchanged(before) {
    try {
      await workspace.assertUnchanged(before);
    } catch (cause) {
      if (
        !["ERR_WORKSPACE_DRIFT", "ERR_WORKSPACE_CHANGED"].includes(cause?.code)
      )
        throw cause;
      throw changed();
    }
  }
  // Legacy preparation compares the filtered entries directly.
  function legacyPrepared(before, after, { intent, prepared }) {
    if (intent.before.exists)
      return isDeepStrictEqual(before.entries, after.entries);
    const prior = before.entries.find(({ path }) => path === intent.path);
    const created = after.entries.find(({ path }) => path === intent.path);
    return (
      (!prior || prior.kind === "missing") &&
      created?.kind === "directory" &&
      isDeepStrictEqual(created.identity, prepared.identity) &&
      !after.entries.some(
        ({ path }) => path !== intent.path && within(intent.path, path),
      ) &&
      isDeepStrictEqual(
        before.entries.filter(({ path }) => path !== intent.path),
        after.entries.filter(({ path }) => path !== intent.path),
      )
    );
  }
  // Compact preparation compares scope and filtered-entry evidence only. The
  // identity fingerprint also covers authorized artifacts, such as an edited
  // clarification transcript, so it is never part of this comparison.
  function compactPrepared(before, after, { intent, prepared }) {
    if (!equalFields(before, after, SCOPE)) return false;
    if (intent.before.exists)
      return (
        equalFields(before, after, FILTERED) &&
        isDeepStrictEqual(before.outputs, after.outputs)
      );
    const prior = before.outputs?.find(({ path }) => path === intent.path);
    const created = after.outputs?.find(({ path }) => path === intent.path);
    return (
      prior !== undefined &&
      created !== undefined &&
      equalFields(before, after, ["remainderCount", "remainderHash"]) &&
      prior.entry.kind === "missing" &&
      prior.descendantCount === 0 &&
      created.entry.kind === "directory" &&
      isDeepStrictEqual(created.entry.identity, prepared.identity) &&
      created.descendantCount === 0 &&
      isDeepStrictEqual(
        before.outputs.filter(({ path }) => path !== intent.path),
        after.outputs.filter(({ path }) => path !== intent.path),
      )
    );
  }
  return Object.freeze({
    snapshot: persisted,
    completeSnapshot,
    assertUnchanged,
    async preparationSnapshot(before, preparation) {
      assertRepresentation(before);
      const after = await persisted({ allowedPaths: before.allowedPaths });
      if (
        !(legacy ? legacyPrepared : compactPrepared)(before, after, preparation)
      )
        throw changed();
      return after;
    },
    contentFingerprint: async (options) =>
      (await completeSnapshot(options)).contentFingerprint,
    async inspectPath(request) {
      const inspected = await workspace.inspectPath(request);
      return {
        ...inspected,
        relativePath: relative(projectPath, inspected.path),
      };
    },
    async validationInfrastructureFingerprint({ paths }) {
      const inspected = await completeSnapshot();
      const roots = paths.map((path) => {
        const root = resolve(projectPath, path);
        if (
          isAbsolute(relative(projectPath, root)) ||
          !within(projectPath, root)
        )
          throw changed();
        return root;
      });
      if (
        roots.some(
          (root) =>
            !inspected.entries.some(
              (entry) => entry.path === root && entry.kind !== "missing",
            ),
        )
      )
        throw changed();
      return hash(
        inspected.entries.filter(({ path }) =>
          roots.some((root) => within(root, path)),
        ),
      );
    },
    async reconcileInterrupted(before, { allowWorkspaceChanges }) {
      assertRepresentation(before);
      const after = await persisted({ allowedPaths: before.allowedPaths });
      // The bound root capability checks frozen controls and disallows writes
      // outside outputs before returning either snapshot.
      if (
        !allowWorkspaceChanges &&
        !(legacy
          ? isDeepStrictEqual(before.entries, after.entries)
          : equalFields(before, after, ["entryCount", "entriesHash"]))
      )
        throw changed();
      return after;
    },
  });
}
