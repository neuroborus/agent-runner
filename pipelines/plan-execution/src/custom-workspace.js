import { isAbsolute, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { PlanExecutionWorkflowError } from "./errors.js";
import { validationEvidenceFingerprint as hash } from "./validation-schedule.js";

const within = (root, path) =>
  path === root || path.startsWith(`${root}${sep}`);
const changed = () =>
  new PlanExecutionWorkflowError("Inspected custom workspace changed.", {
    code: "ERR_READ_ONLY_REPOSITORY_CHANGED",
  });

// Adapt only inspection operations. There are no Git effects in this facade.
export function customWorkspace(workspace, projectPath) {
  async function snapshot({ allowedPaths = [] } = {}) {
    const inspected = await workspace.snapshot({ allowedPaths });
    return {
      ...inspected,
      schemaVersion: 1,
      projectPath,
      allowedPaths,
      contentFingerprint: hash(
        inspected.entries.map(({ path, kind, mode, size, hash }) => ({
          path,
          kind,
          mode,
          size,
          hash,
        })),
      ),
    };
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
  return Object.freeze({
    snapshot,
    assertUnchanged,
    async preparationSnapshot(before, { intent, prepared }) {
      const after = await snapshot({ allowedPaths: before.allowedPaths });
      if (intent.before.exists) {
        if (!isDeepStrictEqual(before.entries, after.entries)) throw changed();
      } else {
        const prior = before.entries.find(({ path }) => path === intent.path);
        const created = after.entries.find(({ path }) => path === intent.path);
        if (
          (prior && prior.kind !== "missing") ||
          created?.kind !== "directory" ||
          !isDeepStrictEqual(created.identity, prepared.identity) ||
          after.entries.some(
            ({ path }) => path !== intent.path && within(intent.path, path),
          ) ||
          !isDeepStrictEqual(
            before.entries.filter(({ path }) => path !== intent.path),
            after.entries.filter(({ path }) => path !== intent.path),
          )
        )
          throw changed();
      }
      return after;
    },
    contentFingerprint: async (options) =>
      (await snapshot(options)).contentFingerprint,
    async inspectPath(request) {
      const inspected = await workspace.inspectPath(request);
      return {
        ...inspected,
        relativePath: relative(projectPath, inspected.path),
      };
    },
    async validationInfrastructureFingerprint({ paths }) {
      const inspected = await snapshot();
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
      const after = await snapshot({ allowedPaths: before.allowedPaths });
      // The bound root capability checks frozen controls and disallows writes
      // outside outputs before returning either snapshot.
      if (
        !allowWorkspaceChanges &&
        !isDeepStrictEqual(before.entries, after.entries)
      )
        throw changed();
      return after;
    },
  });
}
