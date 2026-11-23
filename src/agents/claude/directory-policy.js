import { createHash } from "node:crypto";
import { lstat } from "node:fs/promises";

import { createWorkspaceService } from "../../workspace/index.js";
import { deepFreeze } from "../adapter-contract.js";

export function directoryPolicyError(AdapterError) {
  return new AdapterError(
    "Claude declared workspace policy could not be enforced.",
    {
      code: "ERR_CLAUDE_ISOLATION",
      diagnosticClass: "isolation_workspace_policy",
    },
  );
}

function assertLiteralPermissionPaths(paths, AdapterError) {
  if (paths.some((path) => /[\\*?[\]{}]/u.test(path)))
    throw directoryPolicyError(AdapterError);
}

export async function assertDirectoryOutputSupport(request, AdapterError) {
  if (request.access !== "workspace-write" || !request.workspacePolicy) return;
  assertLiteralPermissionPaths(
    request.workspacePolicy.outputPaths,
    AdapterError,
  );
  for (const path of request.workspacePolicy.outputPaths) {
    try {
      await lstat(path);
    } catch (cause) {
      if (cause.code !== "ENOENT") throw directoryPolicyError(AdapterError);
      // Read-only discovery may precede Runner-owned directory preparation.
      if (
        request.preparableOutputPaths === undefined ||
        request.preparableOutputPaths.includes(path)
      )
        continue;
      throw new AdapterError(
        "Claude output mount root is missing; exact-file creation requires an existing mount root. " +
          "Declare a directory with a trailing / or select a supported backend in an authorized fresh run.",
        {
          code: "ERR_UNSUPPORTED_CLAUDE_CAPABILITY",
          diagnosticClass: "output_root_missing",
        },
      );
    }
  }
}

// Bash is the sole directory writer. Native Edit/Write do not cross the
// authenticated command namespace and therefore cannot receive this authority.
export async function prepareDirectoryPolicy(request, AdapterError) {
  if (request.workspacePolicy === undefined) return undefined;
  await assertDirectoryOutputSupport(
    { ...request, preparableOutputPaths: [] },
    AdapterError,
  );
  try {
    const service = createWorkspaceService();
    const { kind: _kind, ...declarations } = request.workspacePolicy;
    const inspection = await service.inspect(declarations);
    const writablePaths =
      request.access === "workspace-write" ? inspection.outputPaths : [];
    const protectedPaths = [];
    for (const path of inspection.protectedPaths) {
      try {
        await lstat(path);
        protectedPaths.push(path);
      } catch (cause) {
        if (cause.code !== "ENOENT") throw cause;
      }
    }
    // A bind needs an existing target; never widen to an output's parent or
    // materialize ambiguous file/directory declarations during preparation.
    for (const path of writablePaths) await lstat(path);
    assertLiteralPermissionPaths(
      [
        inspection.workspacePath,
        ...inspection.protectedPaths,
        ...writablePaths,
      ],
      AdapterError,
    );
    const before = await service.snapshot({ inspection });
    const mounts = deepFreeze({ writablePaths, protectedPaths });
    async function verify() {
      try {
        const after = await service.snapshot({ inspection });
        service.assertUnchanged({
          before,
          after,
          allowOutputs: request.access === "workspace-write",
        });
        return after;
      } catch {
        throw directoryPolicyError(AdapterError);
      }
    }
    return Object.freeze({
      mounts,
      forbiddenPaths: Object.freeze([
        inspection.stateRoot,
        ...inspection.protectedPaths,
      ]),
      fingerprint: createHash("sha256")
        .update(
          JSON.stringify({
            contract: "claude-declared-directory-v1",
            access: request.access,
            inspection: {
              ...inspection,
              bindings: inspection.bindings.filter(
                ({ path }) =>
                  path !== inspection.stateRoot &&
                  !inspection.outputPaths.includes(path) &&
                  (!inspection.artifactPaths.includes(path) ||
                    [
                      inspection.workspacePath,
                      inspection.taskPath,
                      ...inspection.inputPaths,
                      ...inspection.sourcePaths,
                      ...inspection.configurationPaths,
                      ...inspection.infrastructurePaths,
                    ].includes(path)),
              ),
            },
          }),
        )
        .digest("hex"),
      async bindMounts() {
        const snapshot = await verify();
        const entries = new Map(
          snapshot.entries.map((entry) => [entry.path, entry]),
        );
        return deepFreeze({
          ...mounts,
          bindings: [
            ...new Set([
              inspection.workspacePath,
              ...writablePaths,
              ...protectedPaths,
            ]),
          ].map((path) => {
            // A scoped capture need not contain cwd. Snapshot verification pins
            // its inspection binding without traversing unselected children.
            const entry =
              entries.get(path) ??
              (path === inspection.workspacePath
                ? inspection.bindings.find((binding) => binding.path === path)
                : undefined);
            if (!["file", "directory"].includes(entry?.kind))
              throw directoryPolicyError(AdapterError);
            return {
              path,
              realpath: path,
              dev: entry.identity.device,
              ino: entry.identity.inode,
            };
          }),
        });
      },
      verify,
    });
  } catch {
    throw directoryPolicyError(AdapterError);
  }
}
