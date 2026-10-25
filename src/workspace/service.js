import * as filesystem from "node:fs/promises";
import { relative, sep } from "node:path";

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
import { capture, fingerprints } from "./snapshot.js";

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
];

function freeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Filesystem-only inspection; this service grants no provider or write authority. */
export function createWorkspaceService({ fileSystem = filesystem } = {}) {
  const fs = fileSystem;
  async function boundary(action) {
    try {
      return await action();
    } catch (cause) {
      if (cause instanceof WorkspaceSafetyError) throw cause;
      throw new WorkspaceSafetyError(
        "Cannot safely inspect the declared workspace.",
        { cause, code: "ERR_WORKSPACE_INSPECTION" },
      );
    }
  }

  async function inspect(options) {
    return boundary(async () => {
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
      const controls = await discoverControls(fs, declarations);
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
      for (const output of outputPaths) {
        assertSafe(
          output !== workspacePath &&
            within(workspacePath, output) &&
            !relative(workspacePath, output)
              .split(sep)
              .some((part) => CONTROL_NAMES.includes(part)),
          "Outputs must remain confined outside control paths.",
        );
        assertSafe(
          !protectedPaths.some((path) => overlaps(path, output)),
          "Outputs overlap protected inputs, references, configuration, artifacts or controls.",
        );
      }
      const bindings = [workspace];
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
      await assertBindings(fs, bindings);
      return freeze({
        schemaVersion: 1,
        ...declarations,
        controlPaths: controls,
        protectedPaths,
        readPaths: compactPaths([
          workspacePath,
          ...inputPaths,
          ...sourcePaths,
          ...configurationPaths,
        ]),
        bindings,
      });
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

  async function snapshot({ inspection }) {
    return boundary(async () => {
      assertSafe(
        inspection?.schemaVersion === 1,
        "A workspace inspection is required.",
      );
      await assertInspectionBindings(inspection);
      const current = await inspect(
        Object.fromEntries(
          DECLARATIONS.filter((name) => inspection[name] !== null).map(
            (name) => [name, inspection[name]],
          ),
        ),
      );
      assertSafe(
        same(current.controlPaths, inspection.controlPaths),
        "Workspace control bindings changed.",
        "ERR_WORKSPACE_DRIFT",
      );
      const roots = compactPaths([
        current.workspacePath,
        ...current.protectedPaths,
      ]);
      const entries = await capture(
        fs,
        roots,
        current.outputPaths,
        current.protectedPaths,
        async () => {
          await assertInspectionBindings(inspection);
          assertSafe(
            same(
              await discoverControls(fs, inspection),
              inspection.controlPaths,
            ),
            "Workspace controls changed during snapshot.",
            "ERR_WORKSPACE_SNAPSHOT_RACE",
          );
        },
      );
      return freeze({
        schemaVersion: 1,
        workspacePath: inspection.workspacePath,
        outputPaths: current.outputPaths,
        entries,
        ...fingerprints(entries),
      });
    });
  }

  function assertUnchanged({ before, after, allowOutputs = false }) {
    assertSafe(
      typeof allowOutputs === "boolean" &&
        before?.schemaVersion === 1 &&
        after?.schemaVersion === 1 &&
        before.workspacePath === after.workspacePath &&
        same(before.outputPaths, after.outputPaths),
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

  return Object.freeze({ inspect, snapshot, assertUnchanged });
}
