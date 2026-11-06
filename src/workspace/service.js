import * as filesystem from "node:fs/promises";
import { basename, dirname, join, relative, sep } from "node:path";

import {
  assertBindings,
  assertSafe,
  compactPaths,
  identity,
  inspectPath,
  location,
  metadata,
  overlaps,
  same,
  within,
  WorkspaceSafetyError,
} from "./paths.js";
import { CONTROL_NAMES, discoverControls } from "./controls.js";
import { exclusions, inspectScope } from "./scope.js";
import { traversalCheckpoints } from "./traversal.js";
import { capture, fingerprints, readTextFile } from "./snapshot.js";
import { reportArtifact } from "./artifact.js";
import {
  inspectInfrastructure,
  inspectInfrastructureDirectory,
  publishInfrastructureDirectory,
  publishInfrastructureFile,
} from "./infrastructure.js";
import {
  inspectOutputDirectory,
  prepareOutputDirectory,
} from "./output-directory.js";

const DECLARATIONS = [
  "workspacePath",
  "inputPaths",
  "sourcePaths",
  "outputPaths",
  "configurationPaths",
  "artifactPaths",
  "taskPath",
  "infrastructurePaths",
  "stateRoot",
  "inspectionPaths",
  "inspectionFilesOnly",
  "excludePaths",
];

function freeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Filesystem inspection and confined output preparation; no provider authority. */
export function createWorkspaceService({ fileSystem = filesystem } = {}) {
  const fs = fileSystem;
  async function boundary(action, signal) {
    try {
      return await action();
    } catch (cause) {
      if (
        cause instanceof WorkspaceSafetyError ||
        (signal?.aborted && cause === signal.reason)
      )
        throw cause;
      throw new WorkspaceSafetyError(
        "Cannot safely inspect the declared workspace.",
        { cause, code: "ERR_WORKSPACE_INSPECTION" },
      );
    }
  }

  async function inspect(options, traversal = {}) {
    return boundary(async () => {
      const checkpoint = traversalCheckpoints(traversal);
      const inspection = await inspectDeclarations(options, checkpoint);
      traversal.signal?.throwIfAborted();
      return inspection;
    }, traversal.signal);
  }

  async function inspectDeclarations(options, checkpoint) {
    await checkpoint("controls");
    assertSafe(
      options && typeof options === "object",
      "Workspace declarations are required.",
    );
    assertSafe(
      Object.keys(options).every((key) => DECLARATIONS.includes(key)),
      "Unknown workspace declaration.",
    );
    const workspacePath = location(process.cwd(), options.workspacePath);
    const workspace = await inspectPath(fs, workspacePath);
    assertSafe(
      workspace.kind === "directory",
      "Workspace must be an existing ordinary directory.",
    );
    function paths(name) {
      const values = options[name] === undefined ? [] : options[name];
      assertSafe(
        Array.isArray(values),
        "Workspace path declarations must be arrays.",
      );
      return compactPaths(
        values.map((value) => location(workspacePath, value)),
      );
    }
    const inputPaths = paths("inputPaths");
    const sourcePaths = paths("sourcePaths");
    const outputPaths = paths("outputPaths");
    const configurationPaths = paths("configurationPaths");
    const artifactPaths = paths("artifactPaths");
    const infrastructurePaths = paths("infrastructurePaths");
    const taskPath =
      options.taskPath === undefined
        ? null
        : location(workspacePath, options.taskPath);
    const stateRoot = location(workspacePath, options.stateRoot);
    const declarations = {
      workspacePath,
      inputPaths,
      sourcePaths,
      outputPaths,
      configurationPaths,
      artifactPaths,
      infrastructurePaths,
      taskPath,
      stateRoot,
    };
    for (const output of outputPaths)
      assertSafe(
        output !== workspacePath &&
          within(workspacePath, output) &&
          !relative(workspacePath, output)
            .split(sep)
            .some((part) => CONTROL_NAMES.includes(part)),
        "Outputs must remain confined outside control paths.",
      );
    const scope = await inspectScope(
      fs,
      {
        ...declarations,
        inspectionPaths: options.inspectionPaths,
        inspectionFilesOnly: options.inspectionFilesOnly,
        excludePaths: options.excludePaths,
      },
      CONTROL_NAMES,
      checkpoint,
    );
    Object.assign(declarations, scope.declarations);
    assertSafe(
      [
        workspacePath,
        taskPath,
        ...inputPaths,
        ...sourcePaths,
        ...configurationPaths,
        ...artifactPaths,
        ...infrastructurePaths,
      ]
        .filter(Boolean)
        .every((path) => !overlaps(path, stateRoot)),
      "State storage must be disjoint from workspace, task, infrastructure and declared read trees.",
    );
    const controls = await discoverControls(fs, declarations, { checkpoint });
    // Inspection bindings feed provider projections, which never follow aliases.
    for (const path of controls)
      assertSafe(
        !(await metadata(fs, path))?.isSymbolicLink(),
        "Workspace inspection cannot bind provider control aliases.",
      );
    assertSafe(
      !controls.some((path) => within(path, workspacePath)),
      "Workspace cannot be inside a control tree.",
    );
    const protectedPaths = compactPaths([
      ...inputPaths,
      ...sourcePaths,
      ...configurationPaths,
      ...artifactPaths,
      ...infrastructurePaths,
      ...(taskPath ? [taskPath] : []),
      ...controls,
    ]);
    const nestedWorktrees = controls
      .filter(
        (path) =>
          basename(path) === ".git" &&
          within(workspacePath, path) &&
          dirname(path) !== workspacePath,
      )
      .map((path) => dirname(path));
    for (const output of outputPaths) {
      assertSafe(
        !protectedPaths.some((path) => overlaps(path, output)),
        "Outputs overlap protected inputs, references, configuration, artifacts or controls.",
      );
      assertSafe(
        !nestedWorktrees.some((path) => within(path, output)),
        "Outputs cannot enter a nested Git worktree with a different exclusion key.",
      );
    }
    const bindings = [workspace, ...scope.bindings];
    for (const path of [
      ...inputPaths,
      ...sourcePaths,
      ...configurationPaths,
      ...(taskPath ? [taskPath] : []),
    ])
      bindings.push(await inspectPath(fs, path));
    for (const path of [
      ...artifactPaths,
      ...infrastructurePaths,
      ...controls,
      ...outputPaths,
      stateRoot,
    ])
      bindings.push(await inspectPath(fs, path, { missing: true }));
    await checkpoint("verify");
    await assertBindings(fs, bindings);
    return freeze({
      schemaVersion: 1,
      ...declarations,
      controlPaths: controls,
      protectedPaths,
      readPaths: compactPaths([
        ...(declarations.inspectionPaths ?? [workspacePath]),
        ...inputPaths,
        ...sourcePaths,
        ...configurationPaths,
      ]),
      bindings,
    });
  }

  async function inspectLocalPath({ path, projectPath }) {
    return boundary(async () => {
      const root = location(process.cwd(), projectPath);
      const resolved = location(root, path);
      assertSafe(
        resolved !== root && within(root, resolved),
        "Path must remain inside the workspace.",
      );
      const binding = await inspectPath(fs, resolved, { missing: true });
      return freeze({ ...binding, relativePath: relative(root, resolved) });
    });
  }

  // Exact infrastructure destinations need ancestor controls, including Git
  // pointer/shared metadata, without traversing unrelated project content.
  async function inspectControls({ workspacePath, paths, stateRoot }) {
    return boundary(async () => {
      workspacePath = location(process.cwd(), workspacePath);
      assertSafe(Array.isArray(paths), "Control paths must be an array.");
      assertSafe(
        (await inspectPath(fs, workspacePath)).kind === "directory",
        "Workspace must be an ordinary directory.",
      );
      return freeze(
        await discoverControls(
          fs,
          {
            workspacePath,
            stateRoot: location(process.cwd(), stateRoot),
            inputPaths: [],
            sourcePaths: [],
            configurationPaths: [],
            artifactPaths: [],
            infrastructurePaths: paths.map((path) =>
              location(workspacePath, path),
            ),
            outputPaths: [],
          },
          { recursive: false },
        ),
      );
    });
  }

  async function readFile({
    path,
    projectPath,
    optional = false,
    maxBytes = Number.MAX_SAFE_INTEGER,
  }) {
    return boundary(async () => {
      assertSafe(
        Number.isSafeInteger(maxBytes) && maxBytes >= 0,
        "Input read limit must be a non-negative safe integer.",
      );
      const binding = await inspectLocalPath({ path, projectPath });
      if (!binding.exists && optional) return null;
      assertSafe(binding.kind === "file", "Input must be a regular file.");
      return readTextFile(fs, binding.path, maxBytes);
    });
  }

  // Match the canonical worktree exclusion key without invoking Git. Linked
  // worktrees have their own .git pointer and therefore their own key.
  async function exclusionPath({ workspacePath }) {
    return boundary(async () => {
      workspacePath = location(process.cwd(), workspacePath);
      assertSafe(
        (await inspectPath(fs, workspacePath)).kind === "directory",
        "Workspace must be an ordinary directory.",
      );
      for (let path = workspacePath; ; path = dirname(path)) {
        const marker = await metadata(fs, join(path, ".git"));
        if (marker) {
          assertSafe(
            marker.isDirectory() || marker.isFile(),
            "Git controls must be ordinary paths.",
          );
          if (marker.isFile()) return path;
          const [head, objects, refs, common] = await Promise.all([
            metadata(fs, join(path, ".git", "HEAD")),
            metadata(fs, join(path, ".git", "objects")),
            metadata(fs, join(path, ".git", "refs")),
            metadata(fs, join(path, ".git", "commondir")),
          ]);
          // Discovery and snapshots enforce confinement for control aliases.
          if (
            (head?.isFile() || head?.isSymbolicLink()) &&
            (((objects?.isDirectory() || objects?.isSymbolicLink()) &&
              (refs?.isDirectory() || refs?.isSymbolicLink())) ||
              common?.isFile())
          )
            return path;
        }
        if (path === dirname(path)) return workspacePath;
      }
    });
  }

  async function assertInspectionBindings(inspection) {
    await assertBindings(fs, inspection.bindings);
    for (const binding of inspection.bindings) {
      if (
        binding.identity === null ||
        inspection.outputPaths.includes(binding.path) ||
        binding.path === inspection.stateRoot
      )
        continue;
      const current = await metadata(fs, binding.path);
      assertSafe(
        current && same(binding.identity, identity(current)),
        "A bound workspace path was replaced.",
        "ERR_WORKSPACE_DRIFT",
      );
    }
  }

  async function snapshot({ inspection, signal, onProgress }) {
    return boundary(async () => {
      const checkpoint = traversalCheckpoints({ signal, onProgress });
      await checkpoint("controls");
      assertSafe(
        inspection?.schemaVersion === 1,
        "A workspace inspection is required.",
      );
      await assertInspectionBindings(inspection);
      const current = await inspectDeclarations(
        Object.fromEntries(
          DECLARATIONS.filter(
            (name) =>
              inspection[name] !== null && inspection[name] !== undefined,
          ).map((name) => [name, inspection[name]]),
        ),
        checkpoint,
      );
      assertSafe(
        same(current.controlPaths, inspection.controlPaths),
        "Workspace control bindings changed.",
        "ERR_WORKSPACE_DRIFT",
      );
      const roots = compactPaths([
        ...(current.inspectionPaths ?? [current.workspacePath]),
        ...current.outputPaths,
        ...current.protectedPaths,
      ]);
      const linkResolutions = [];
      const entries = await capture(
        fs,
        roots,
        current.outputPaths,
        current.protectedPaths,
        async () => {
          await assertInspectionBindings(inspection);
          assertSafe(
            same(
              await discoverControls(fs, inspection, { checkpoint }),
              inspection.controlPaths,
            ),
            "Workspace controls changed during snapshot.",
            "ERR_WORKSPACE_SNAPSHOT_RACE",
          );
        },
        linkResolutions,
        {
          excludePaths: exclusions(current),
          checkpoint,
          linkPaths: current.inspectionPaths,
          inspectionFilesOnly: current.inspectionFilesOnly,
        },
      );
      const scope =
        current.inspectionPaths === undefined
          ? {}
          : {
              inspectionPaths: current.inspectionPaths,
              ...(current.inspectionFilesOnly === undefined
                ? {}
                : { inspectionFilesOnly: current.inspectionFilesOnly }),
              excludePaths: current.excludePaths,
            };
      signal?.throwIfAborted();
      return freeze({
        schemaVersion: 1,
        workspacePath: inspection.workspacePath,
        outputPaths: current.outputPaths,
        ...scope,
        entries,
        linkResolutions: linkResolutions.sort((left, right) =>
          left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
        ),
        ...fingerprints(
          entries,
          current.inspectionPaths === undefined ? undefined : scope,
        ),
      });
    }, signal);
  }

  // Supplemental reads must not impose directory-workspace rules on unrelated
  // Git content, including ignored dependencies and their external links.
  async function snapshotInputs({ paths, stateRoot }) {
    return boundary(async () => {
      assertSafe(Array.isArray(paths), "Input paths must be an array.");
      const roots = compactPaths(
        paths.map((path) => location(process.cwd(), path)),
      );
      const statePath = location(process.cwd(), stateRoot);
      assertSafe(
        roots.every((path) => !overlaps(path, statePath)),
        "Declared read trees must be disjoint from state storage.",
      );
      const bindings = await Promise.all(
        roots.map((path) => inspectPath(fs, path)),
      );
      const entries = await capture(fs, roots, [], roots, async () => {
        await assertBindings(fs, bindings);
        for (const binding of bindings)
          assertSafe(
            same(binding, await inspectPath(fs, binding.path)),
            "Declared input bindings changed during snapshot.",
            "ERR_WORKSPACE_SNAPSHOT_RACE",
          );
      });
      return freeze({ bindings, entries });
    });
  }

  function assertUnchanged({ before, after, allowOutputs = false }) {
    assertSafe(
      typeof allowOutputs === "boolean" &&
        before?.schemaVersion === 1 &&
        after?.schemaVersion === 1 &&
        before.workspacePath === after.workspacePath &&
        same(before.outputPaths, after.outputPaths) &&
        same(before.inspectionPaths, after.inspectionPaths) &&
        before.inspectionFilesOnly === after.inspectionFilesOnly &&
        same(before.excludePaths, after.excludePaths),
      "Workspace snapshots do not share the same scope.",
      "ERR_WORKSPACE_DRIFT",
    );
    const priorPaths = new Set(before.entries.map((entry) => entry.path));
    const filter = (snapshot) =>
      snapshot.entries.filter(
        (entry) =>
          !allowOutputs ||
          (!snapshot.outputPaths.some((path) => within(path, entry.path)) &&
            !(
              entry.kind === "directory" &&
              !priorPaths.has(entry.path) &&
              snapshot.outputPaths.some((path) => within(entry.path, path))
            )),
      );
    assertSafe(
      same(filter(before), filter(after)),
      "Workspace content or identity changed outside authorized outputs.",
      "ERR_WORKSPACE_DRIFT",
    );
  }

  return Object.freeze({
    inspect,
    inspectPath: inspectLocalPath,
    inspectControls,
    readFile,
    exclusionPath,
    snapshot,
    snapshotInputs,
    assertUnchanged,
    inspectInfrastructure: (request) =>
      boundary(() => inspectInfrastructure(fs, request)),
    inspectInfrastructureDirectory: (request) =>
      boundary(() => inspectInfrastructureDirectory(fs, request)),
    publishInfrastructureDirectory: (request) =>
      boundary(() => publishInfrastructureDirectory(fs, request)),
    publishInfrastructureFile: (request) =>
      boundary(() => publishInfrastructureFile(fs, request)),
    reportArtifact: ({ inspection, ...request }, options) =>
      boundary(async () => {
        await snapshot({ inspection });
        return reportArtifact(fs, inspection, request, options);
      }),
    inspectOutputDirectory: ({ inspection, path }) =>
      boundary(async () => {
        await snapshot({ inspection });
        return freeze(await inspectOutputDirectory(fs, inspection, path));
      }),
    prepareOutputDirectory: ({
      inspection,
      intent,
      signal,
      beforeCreate,
      publishDirectory,
    }) =>
      boundary(async () => {
        await snapshot({ inspection });
        const result = await prepareOutputDirectory(fs, inspection, intent, {
          signal,
          beforeCreate,
          publishDirectory,
        });
        await snapshot({ inspection });
        return freeze(result);
      }),
  });
}
