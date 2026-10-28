import { createHash } from "node:crypto";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import { spawnOwnedProcess } from "../agents/index.js";
import { deepFreeze } from "../state/index.js";
import { WorkspaceSafetyError } from "../workspace/index.js";
import { RunnerError, rejectUnknownFields } from "./input.js";

const PATH_FIELDS = [
  "inputPaths",
  "sourcePaths",
  "outputPaths",
  "configurationPaths",
  "artifactPaths",
  "infrastructurePaths",
];
const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const within = (root, path) => {
  const name = relative(root, path);
  return (
    name === "" ||
    (!isAbsolute(name) && name !== ".." && !name.startsWith(`..${sep}`))
  );
};

// Node's directory rename can replace an arriving empty root. GNU mv's
// no-clobber/no-copy contract supplies a no-replace move, never an EXDEV copy.
export async function publishOutputDirectory(
  request,
  { signal, onProcess, cwd, spawn = spawnOwnedProcess },
) {
  const child = spawn(
    "/usr/bin/mv",
    [
      "--no-clobber",
      "--no-copy",
      "--no-target-directory",
      "--",
      `/proc/self/fd/3/${request.sourceName}`,
      `/proc/self/fd/4/${request.destinationName}`,
    ],
    {
      cwd,
      signal,
      onProcess,
      stdio: [
        "ignore",
        "ignore",
        "ignore",
        request.sourceParent,
        request.destinationParent,
      ],
    },
  );
  const { outcome } = await child.ownedCompletion;
  if (outcome?.type !== "close" || outcome.exitCode !== 0)
    throw new WorkspaceSafetyError(
      "Output directory publication is unavailable or incomplete.",
      {
        code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
      },
    );
}

function assertArtifactSeparation(artifacts, protectedPaths) {
  if (
    artifacts.some((artifact) =>
      protectedPaths.some(
        (path) => within(path, artifact) || within(artifact, path),
      ),
    )
  )
    throw new RunnerError(
      "Runner artifacts must not overlap protected inputs, configuration or controls.",
      { code: "ERR_UNSAFE_WORKSPACE_ACCESS" },
    );
}

export function workspaceSelection(pipeline, input) {
  if (pipeline === undefined)
    throw new RunnerError("Unknown pipeline.", {
      code: "ERR_UNKNOWN_PIPELINE",
    });
  const selection = pipeline.resolveWorkspace?.(input) ?? pipeline.workspace;
  rejectUnknownFields(
    selection,
    new Set(["kind", "lease", ...PATH_FIELDS]),
    "pipeline.workspace",
  );
  if (
    !["git", "directory"].includes(selection.kind) ||
    !["none", "exclusive"].includes(selection.lease) ||
    (selection.kind === "directory" && selection.lease !== "exclusive")
  ) {
    throw new RunnerError("Pipeline workspace requirements are invalid.", {
      code: "ERR_INVALID_PIPELINE",
    });
  }
  return selection;
}

function bindingFingerprint(inspection) {
  const mutable = new Set([
    ...inspection.outputPaths,
    ...inspection.artifactPaths.filter(
      (path) =>
        ![
          inspection.workspacePath,
          inspection.taskPath,
          ...inspection.inputPaths,
          ...inspection.sourcePaths,
          ...inspection.configurationPaths,
          ...inspection.infrastructurePaths,
        ].includes(path),
    ),
    inspection.stateRoot,
  ]);
  return hash({
    ...inspection,
    bindings: inspection.bindings.filter(({ path }) => !mutable.has(path)),
  });
}

function ancestorBindings(inspection) {
  return [
    ...new Map(
      inspection.bindings
        .flatMap(({ ancestors }) => ancestors)
        .map((binding) => [binding.path, binding]),
    ).values(),
  ].sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
}

function protectedFingerprint(inspection, snapshot) {
  const mutable = [...inspection.outputPaths, ...inspection.artifactPaths];
  const frozen = [
    ...inspection.inputPaths,
    ...inspection.sourcePaths,
    ...inspection.configurationPaths,
    ...inspection.infrastructurePaths,
    ...inspection.controlPaths,
  ];
  return hash(
    snapshot.entries.filter(
      ({ path, kind }) =>
        frozen.some((root) => within(root, path)) ||
        (!mutable.some((root) => within(root, path)) &&
          !(
            kind === "directory" && mutable.some((root) => within(path, root))
          )),
    ),
  );
}

async function assertAbsentInputs(paths, taskPath, workspace) {
  for (const path of paths) {
    if ((await workspace.inspectPath({ path, projectPath: taskPath })).exists)
      throw new RunnerError("An absent optional task input appeared.", {
        code: "ERR_WORKSPACE_DRIFT",
      });
  }
}

export async function bindWorkspace({
  selection,
  projectPath,
  taskPath,
  taskInputs,
  configurationPath,
  stateRoot,
  workspace,
}) {
  assertArtifactSeparation(
    (selection.artifactPaths ?? []).map((path) => resolve(projectPath, path)),
    [
      ...(selection.inputPaths ?? []),
      ...(selection.sourcePaths ?? []),
      ...(configurationPath ? [configurationPath] : []),
    ].map((path) => resolve(projectPath, path)),
  );
  if (selection.kind === "git")
    return deepFreeze({
      schemaVersion: 1,
      kind: "git",
      lease: selection.lease,
      leasePath: projectPath,
      policy: null,
      bindingFingerprint: null,
      protectedFingerprint: null,
      ancestorBindings: [],
      absentInputPaths: [],
      retrievalPermissions: [],
    });
  const inputs = Object.fromEntries(
    await Promise.all(
      Object.entries(taskInputs).map(async ([name, definition]) => {
        const path = join(taskPath, definition.filename);
        const binding = await workspace.inspectPath({
          path,
          projectPath: taskPath,
        });
        if (
          binding.kind !== "file" &&
          !(definition.optional && !binding.exists)
        )
          throw new RunnerError("Task inputs must be regular files.", {
            code: "ERR_WORKSPACE_PATH",
          });
        return [name, binding.exists ? { path } : null];
      }),
    ),
  );
  const absentInputPaths = [
    ...new Set(
      Object.entries(inputs)
        .filter(([, value]) => value === null)
        .map(([name]) => join(taskPath, taskInputs[name].filename)),
    ),
  ].sort();
  await assertAbsentInputs(absentInputPaths, taskPath, workspace);
  const declarations = Object.fromEntries(
    PATH_FIELDS.map((name) => [name, selection[name] ?? []]),
  );
  declarations.inputPaths = [
    ...declarations.inputPaths,
    ...Object.values(inputs)
      .filter(Boolean)
      .map(({ path }) => path),
  ];
  declarations.configurationPaths = [
    ...declarations.configurationPaths,
    ...(configurationPath ? [configurationPath] : []),
  ];
  const inspection = await workspace.inspect({
    ...declarations,
    workspacePath: projectPath,
    taskPath,
    stateRoot: resolve(stateRoot),
  });
  assertArtifactSeparation(inspection.artifactPaths, [
    ...inspection.inputPaths,
    ...inspection.sourcePaths,
    ...inspection.configurationPaths,
    ...inspection.infrastructurePaths,
    ...inspection.controlPaths,
  ]);
  const policy = {
    kind: "directory",
    workspacePath: projectPath,
    taskPath,
    stateRoot: inspection.stateRoot,
    ...Object.fromEntries(PATH_FIELDS.map((name) => [name, inspection[name]])),
  };
  return deepFreeze({
    schemaVersion: 1,
    kind: "directory",
    lease: selection.lease,
    leasePath: await workspace.exclusionPath({ workspacePath: projectPath }),
    policy,
    ancestorBindings: ancestorBindings(inspection),
    absentInputPaths,
    bindingFingerprint: bindingFingerprint(inspection),
    protectedFingerprint: protectedFingerprint(
      inspection,
      await workspace.snapshot({ inspection }),
    ),
    retrievalPermissions: [],
  });
}

export async function inspectBoundWorkspace(binding, workspace) {
  const { kind: _kind, ...declarations } = binding.policy;
  const inspection = await workspace.inspect(declarations);
  const snapshot = await workspace.snapshot({ inspection });
  await assertAbsentInputs(
    binding.absentInputPaths,
    inspection.taskPath,
    workspace,
  );
  const ancestors = new Map(
    ancestorBindings(inspection).map((entry) => [entry.path, entry]),
  );
  if (
    binding.ancestorBindings.some(
      (entry) => hash(entry) !== hash(ancestors.get(entry.path) ?? null),
    ) ||
    bindingFingerprint(inspection) !== binding.bindingFingerprint ||
    protectedFingerprint(inspection, snapshot) !==
      binding.protectedFingerprint ||
    (await workspace.exclusionPath({
      workspacePath: inspection.workspacePath,
    })) !== binding.leasePath
  ) {
    throw new RunnerError("Frozen workspace inputs or controls changed.", {
      code: "ERR_WORKSPACE_DRIFT",
    });
  }
  return { inspection, snapshot };
}

// Recovery coordinators consume the same snapshot/guard interface in either
// workspace. A directory capability deliberately contains no Git effects.
export function directorySafety(binding, workspace) {
  function inspectedSnapshot(snapshot, allowedPaths) {
    if (
      !Array.isArray(allowedPaths) ||
      allowedPaths.some((path) => !binding.policy.artifactPaths.includes(path))
    )
      throw new RunnerError(
        "Only declared runner artifacts may be excluded from directory inspection.",
        { code: "ERR_UNSAFE_WORKSPACE_ACCESS" },
      );
    return Object.freeze({
      ...snapshot,
      allowedPaths,
      entries: snapshot.entries.filter(
        ({ path }) => !allowedPaths.some((root) => within(root, path)),
      ),
      projectPath: binding.policy.workspacePath,
    });
  }
  return Object.freeze({
    async snapshot({ allowedPaths = [] } = {}) {
      const { snapshot } = await inspectBoundWorkspace(binding, workspace);
      return inspectedSnapshot(snapshot, allowedPaths);
    },
    async assertUnchanged(before) {
      const { snapshot: after } = await inspectBoundWorkspace(
        binding,
        workspace,
      );
      workspace.assertUnchanged({
        before,
        after: inspectedSnapshot(after, before.allowedPaths ?? []),
      });
    },
    inspectPath: (request) => workspace.inspectPath(request),
    async inspectOutputDirectory(path) {
      const { inspection } = await inspectBoundWorkspace(binding, workspace);
      return workspace.inspectOutputDirectory({ inspection, path });
    },
    async prepareOutputDirectory(intent, options = {}) {
      const { inspection } = await inspectBoundWorkspace(binding, workspace);
      return workspace.prepareOutputDirectory({
        inspection,
        intent,
        ...options,
      });
    },
  });
}
