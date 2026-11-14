import { createHash } from "node:crypto";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { spawnOwnedProcess } from "../platform/index.js";
import { deepFreeze, MAX_WORKSPACE_PREPARATION_BYTES } from "../state/index.js";
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

export async function workspaceSelection(pipeline, input, workspace) {
  if (pipeline === undefined)
    throw new RunnerError("Unknown pipeline.", {
      code: "ERR_UNKNOWN_PIPELINE",
    });
  const selection =
    (await pipeline.resolveWorkspace?.({
      ...input,
      readTaskInput: (filename) => {
        if (
          !Object.values(pipeline.taskInputs).some(
            (entry) => entry.filename === filename,
          )
        )
          throw new RunnerError("Undeclared task input.");
        return workspace.readFile({
          path: join(input.taskPath, filename),
          projectPath: input.taskPath,
        });
      },
    })) ?? pipeline.workspace;
  rejectUnknownFields(
    selection,
    new Set([
      "kind",
      "lease",
      "preparation",
      "sourceScope",
      "excludePaths",
      ...PATH_FIELDS,
    ]),
    "pipeline.workspace",
  );
  if (
    !["git", "directory"].includes(selection.kind) ||
    !["none", "exclusive"].includes(selection.lease) ||
    (selection.kind === "directory" && selection.lease !== "exclusive") ||
    (selection.preparation !== undefined &&
      (selection.preparation !== "deferred" ||
        selection.kind !== "directory")) ||
    (selection.sourceScope !== undefined &&
      (selection.kind !== "directory" ||
        !["directory", "git"].includes(selection.sourceScope))) ||
    (selection.excludePaths !== undefined &&
      !Array.isArray(selection.excludePaths))
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

// Admission freezes exact inputs and declarations, without discovering controls
// or traversing sources. State verifies their bytes and routing identities.
export async function declareWorkspacePreparation({
  selection,
  projectPath,
  taskPath,
  taskInputs,
  configuration,
  stateRoot,
  workspace,
}) {
  const inputs = [];
  for (const definition of Object.values(taskInputs)) {
    const path = join(taskPath, definition.filename);
    const content = await workspace.readFile({
      path,
      projectPath: taskPath,
      optional: definition.optional,
      maxBytes: MAX_WORKSPACE_PREPARATION_BYTES,
    });
    inputs.push({
      path,
      contentHash:
        content === null
          ? null
          : createHash("sha256").update(content).digest("hex"),
    });
  }
  if (configuration != null)
    inputs.push({
      path: configuration.path,
      contentHash: configuration.protection.contentHash,
    });
  const declarations = Object.fromEntries(
    PATH_FIELDS.map((name) => [name, [...(selection[name] ?? [])]]),
  );
  declarations.inputPaths.push(
    ...inputs
      .filter(
        ({ contentHash, path }) =>
          contentHash !== null && path !== configuration?.path,
      )
      .map(({ path }) => path),
  );
  if (configuration != null)
    declarations.configurationPaths.push(configuration.path);
  for (const name of PATH_FIELDS) {
    const paths = [
      ...new Set(declarations[name].map((path) => resolve(projectPath, path))),
    ].sort();
    declarations[name] = paths.filter(
      (path) =>
        !paths.some((parent) => parent !== path && within(parent, path)),
    );
  }
  assertArtifactSeparation(declarations.artifactPaths, [
    ...declarations.inputPaths,
    ...declarations.sourcePaths,
    ...declarations.configurationPaths,
    ...declarations.infrastructurePaths,
  ]);
  return {
    leasePath: await workspace.exclusionPath({ workspacePath: projectPath }),
    policy: {
      kind: "directory",
      workspacePath: projectPath,
      taskPath,
      stateRoot: resolve(stateRoot),
      ...declarations,
      ...(selection.excludePaths?.length
        ? { excludePaths: [...selection.excludePaths] }
        : {}),
    },
    inputs,
    ...(selection.sourceScope === "git"
      ? { sourceSelection: { kind: "git", fingerprint: null } }
      : {}),
  };
}

// Git owns membership/provenance. The state service journals this result before
// filesystem capture; reconstruction may verify it, never select a replacement.
export async function selectWorkspacePreparation(pending, git, signal) {
  let selected;
  try {
    selected = await git.selectSources({
      projectPath: pending.policy.workspacePath,
      signal,
    });
  } catch (cause) {
    signal?.throwIfAborted();
    throw new RunnerError("Git source selection is unavailable or unsafe.", {
      cause,
      code: "ERR_WORKSPACE_SOURCE_SELECTION",
    });
  }
  if (selected.projectPath !== pending.policy.workspacePath)
    throw new RunnerError("Git source root changed before capture.", {
      code: "ERR_WORKSPACE_DRIFT",
    });
  return {
    policy: { ...pending.policy, ...selected.inspection },
    sourceSelection: {
      kind: "git",
      fingerprint: selected.selectionFingerprint,
    },
  };
}

async function assertSourceSelection(binding, git, signal) {
  if (binding.sourceSelection == null) return;
  let selected;
  try {
    selected = await git.selectSources({
      projectPath: binding.policy.workspacePath,
      expectedSelectionFingerprint: binding.sourceSelection.fingerprint,
      signal,
    });
  } catch (cause) {
    signal?.throwIfAborted();
    throw new RunnerError(
      "Frozen Git source selection changed or is unavailable.",
      { cause, code: "ERR_WORKSPACE_DRIFT" },
    );
  }
  if (
    selected.projectPath !== binding.policy.workspacePath ||
    selected.inspection.inspectionFilesOnly !== true ||
    !isDeepStrictEqual(
      selected.inspection.inspectionPaths,
      binding.policy.inspectionPaths,
    ) ||
    binding.policy.inspectionFilesOnly !== true
  )
    throw new RunnerError("Frozen Git source selection changed.", {
      code: "ERR_WORKSPACE_DRIFT",
    });
}

export async function captureWorkspacePreparation(
  pending,
  workspace,
  signal,
  git,
) {
  await assertSourceSelection(pending, git, signal);
  const { kind: _kind, ...declarations } = pending.policy;
  const inspection = await workspace.inspect(declarations, { signal });
  assertArtifactSeparation(inspection.artifactPaths, [
    ...inspection.inputPaths,
    ...inspection.sourcePaths,
    ...inspection.configurationPaths,
    ...inspection.infrastructurePaths,
    ...inspection.controlPaths,
  ]);
  const snapshot = await workspace.snapshot({ inspection, signal });
  await assertSourceSelection(pending, git, signal);
  if (
    (await workspace.exclusionPath({
      workspacePath: inspection.workspacePath,
    })) !== pending.leasePath
  )
    throw new RunnerError("Workspace exclusion key changed during capture.", {
      code: "ERR_WORKSPACE_DRIFT",
    });
  return deepFreeze({
    schemaVersion: 1,
    kind: "directory",
    lease: "exclusive",
    leasePath: pending.leasePath,
    policy: pending.policy,
    ancestorBindings: ancestorBindings(inspection),
    absentInputPaths: pending.inputs
      .filter(({ contentHash }) => contentHash === null)
      .map(({ path }) => path),
    bindingFingerprint: bindingFingerprint(inspection),
    protectedFingerprint: protectedFingerprint(inspection, snapshot),
    retrievalPermissions: [],
    ...(pending.sourceSelection === undefined
      ? {}
      : { sourceSelection: pending.sourceSelection }),
  });
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
  if (selection.excludePaths?.length)
    declarations.excludePaths = [...selection.excludePaths];
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
    ...(declarations.excludePaths === undefined
      ? {}
      : { excludePaths: declarations.excludePaths }),
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

export async function inspectBoundWorkspace(binding, workspace, git) {
  await assertSourceSelection(binding, git);
  const { kind: _kind, ...declarations } = binding.policy;
  const inspection = await workspace.inspect(declarations);
  const snapshot = await workspace.snapshot({ inspection });
  await assertSourceSelection(binding, git);
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
  return {
    inspection,
    snapshot:
      binding.sourceSelection === undefined
        ? snapshot
        : deepFreeze({
            ...snapshot,
            sourceSelection: binding.sourceSelection,
            contentFingerprint: hash({
              sourceSelection: binding.sourceSelection,
              content: snapshot.contentFingerprint,
            }),
            identityFingerprint: hash({
              sourceSelection: binding.sourceSelection,
              identity: snapshot.identityFingerprint,
            }),
          }),
  };
}

// Recovery coordinators consume the same snapshot/guard interface in either
// workspace. A directory capability deliberately contains no Git effects.
export function directorySafety(
  binding,
  workspace,
  inspect = () => inspectBoundWorkspace(binding, workspace, git),
  git,
) {
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
      const { snapshot } = await inspect();
      return inspectedSnapshot(snapshot, allowedPaths);
    },
    async assertUnchanged(before) {
      const { snapshot: after } = await inspect();
      workspace.assertUnchanged({
        before,
        after: inspectedSnapshot(after, before.allowedPaths ?? []),
      });
    },
    inspectPath: (request) => workspace.inspectPath(request),
    async reportArtifact(request, options) {
      const { inspection } = await inspectBoundWorkspace(
        binding,
        workspace,
        git,
      );
      return workspace.reportArtifact({ inspection, ...request }, options);
    },
    async inspectOutputDirectory(path) {
      const { inspection } = await inspectBoundWorkspace(
        binding,
        workspace,
        git,
      );
      return workspace.inspectOutputDirectory({ inspection, path });
    },
    async prepareOutputDirectory(intent, options = {}) {
      const { inspection } = await inspectBoundWorkspace(
        binding,
        workspace,
        git,
      );
      return workspace.prepareOutputDirectory({
        inspection,
        intent,
        ...options,
      });
    },
  });
}
