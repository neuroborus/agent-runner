import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { createWorkspaceService } from "../../workspace/index.js";
import { deepFreeze } from "../adapter-contract.js";

const PROFILE = "agent_runner_directory";
const CONTRACT = "codex-declared-directory-v1";

function assertLiteralPermissionPaths(paths, AdapterError) {
  // Native filesystem keys interpret glob syntax, including backslash escapes.
  // Reject ambiguous keys to preserve literal directory bindings.
  if (paths.some((path) => /[\\*?[\]{}]/u.test(path)))
    throw directoryPolicyError(AdapterError);
}

function within(parent, path) {
  const name = relative(parent, path);
  return (
    name === "" ||
    (!isAbsolute(name) && name !== ".." && !name.startsWith(`..${sep}`))
  );
}

export function directoryPolicyError(AdapterError) {
  return new AdapterError(
    "Codex declared workspace policy could not be enforced.",
    {
      code: "ERR_CODEX_ISOLATION",
      diagnosticClass: "isolation_workspace_policy",
    },
  );
}

// The workspace capability owns path/control validation and race-safe content
// inspection. Native permissions narrow writes; snapshots also guard commands
// and any unexpected provider-side effects before acceptance or reconstruction.
export async function prepareDirectoryPolicy(request, AdapterError) {
  if (request.workspacePolicy === undefined) return undefined;
  const service = createWorkspaceService();
  try {
    const { kind: _kind, ...declarations } = request.workspacePolicy;
    const inspection = await service.inspect(declarations);
    const writable = request.access === "workspace-write";
    assertLiteralPermissionPaths(
      [
        ...(writable ? inspection.outputPaths : []),
        ...inspection.protectedPaths,
      ],
      AdapterError,
    );
    const before = await service.snapshot({ inspection });
    const fingerprint = createHash("sha256")
      .update(
        JSON.stringify({
          contract: CONTRACT,
          access: request.access,
          inspection: {
            ...inspection,
            // These declarations remain bound by path, but their contents and
            // identities can change through authorized output/state effects.
            bindings: inspection.bindings.filter(
              ({ path }) =>
                path !== inspection.stateRoot &&
                !inspection.outputPaths.includes(path),
            ),
          },
        }),
      )
      .digest("hex");
    return Object.freeze({
      fingerprint,
      permissions(storage) {
        assertLiteralPermissionPaths(
          storage ? [storage.rootPath] : [],
          AdapterError,
        );
        if (
          storage &&
          [
            inspection.workspacePath,
            inspection.stateRoot,
            ...inspection.protectedPaths,
            ...(request.storageForbiddenPaths ?? []),
          ].some(
            (path) =>
              within(path, storage.rootPath) || within(storage.rootPath, path),
          )
        )
          throw directoryPolicyError(AdapterError);
        const filesystem = {
          ":root": "read",
          ":workspace_roots": { ".": "read" },
          ...Object.fromEntries(
            (writable ? inspection.outputPaths : []).map((path) => [
              path,
              "write",
            ]),
          ),
          ...(storage ? { [storage.rootPath]: "write" } : {}),
          ...Object.fromEntries(
            inspection.protectedPaths.map((path) => [path, "read"]),
          ),
        };
        return deepFreeze({
          default_permissions: PROFILE,
          permissions: {
            [PROFILE]: { filesystem, network: { enabled: false } },
          },
        });
      },
      async verify() {
        try {
          service.assertUnchanged({
            before,
            after: await service.snapshot({ inspection }),
            allowOutputs: writable,
          });
        } catch {
          throw directoryPolicyError(AdapterError);
        }
      },
      allowsChange(change) {
        const paths = [
          change?.path,
          ...(change?.kind?.move_path == null ? [] : [change.kind.move_path]),
        ];
        return (
          writable &&
          paths.every(
            (path) =>
              typeof path === "string" &&
              inspection.outputPaths.some((output) =>
                within(output, resolve(request.cwd, path)),
              ),
          )
        );
      },
    });
  } catch {
    throw directoryPolicyError(AdapterError);
  }
}

export function directoryPermissionArguments(permissions) {
  if (permissions === undefined) return [];
  const policy = permissions.permissions[PROFILE];
  const filesystem = Object.entries(policy.filesystem)
    .map(
      ([path, access]) =>
        `${JSON.stringify(path)}=${typeof access === "string" ? JSON.stringify(access) : '{"."="read"}'}`,
    )
    .join(",");
  return [
    "-c",
    `default_permissions=${JSON.stringify(PROFILE)}`,
    "-c",
    `permissions.${PROFILE}={filesystem={${filesystem}},network={enabled=false}}`,
  ];
}

export function assertDirectoryConfiguration(
  config,
  permissions,
  AdapterError,
) {
  if (
    permissions !== undefined &&
    (config?.default_permissions !== PROFILE ||
      !isDeepStrictEqual(
        config?.permissions?.[PROFILE],
        permissions.permissions[PROFILE],
      ))
  )
    throw directoryPolicyError(AdapterError);
}

export function assertDirectorySelection(result, request, AdapterError) {
  if (
    request.directoryPermissions !== undefined &&
    (result?.activePermissionProfile?.id !== PROFILE ||
      result.activePermissionProfile.extends != null ||
      result.cwd !== request.cwd)
  )
    throw directoryPolicyError(AdapterError);
}
