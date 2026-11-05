import { dirname, isAbsolute, relative, sep } from "node:path";

import {
  assertSafe,
  compactPaths,
  inspectPath,
  location,
  overlaps,
  within,
} from "./paths.js";

export function isExcluded(path, excludePaths = []) {
  return excludePaths.some((excluded) => within(excluded, path));
}

// Scope restricts inspection only; protected reads and outputs retain their
// separate declarations. Excluded leaves and their descendants stay opaque.
export async function inspectScope(fs, options, controlNames, checkpoint) {
  const { workspacePath } = options;
  const declared =
    options.inspectionPaths !== undefined || options.excludePaths !== undefined;
  if (!declared) return { declarations: {}, bindings: [] };
  const selected =
    options.inspectionPaths === undefined
      ? [workspacePath]
      : options.inspectionPaths;
  const exclusions =
    options.excludePaths === undefined ? [] : options.excludePaths;
  assertSafe(
    Array.isArray(selected) && Array.isArray(exclusions),
    "Inspection scope declarations must be arrays.",
  );
  const selectedPaths = [
    ...new Set(
      selected.map((value) => {
        const path = location(workspacePath, value);
        assertSafe(
          within(workspacePath, path) && !value.split(sep).includes(".."),
          "Inspection paths must remain confined to the workspace.",
        );
        return path;
      }),
    ),
  ].sort();
  const inspectionPaths = compactPaths(selectedPaths);
  const excludePaths = compactPaths(
    exclusions.map((value) => {
      const path = location(workspacePath, value);
      assertSafe(
        !isAbsolute(value) &&
          !value.split(sep).includes("..") &&
          path !== workspacePath &&
          within(workspacePath, path),
        "Exclusions must be literal workspace-relative subtrees.",
      );
      assertSafe(
        !relative(workspacePath, path)
          .split(sep)
          .some((part) => controlNames.includes(part)),
        "Exclusions cannot hide reserved control paths.",
      );
      return path;
    }),
  );
  assertSafe(
    selectedPaths.every((path) => !isExcluded(path, excludePaths)),
    "An explicitly selected path cannot be excluded.",
  );
  const required = [
    ...options.inputPaths,
    ...options.sourcePaths,
    ...options.outputPaths,
    ...options.configurationPaths,
    ...options.artifactPaths,
    ...options.infrastructurePaths,
    ...(options.taskPath ? [options.taskPath] : []),
  ];
  assertSafe(
    excludePaths.every((excluded) =>
      required.every((path) => !overlaps(excluded, path)),
    ),
    "Exclusions overlap required declarations or authorized outputs.",
  );
  const bindings = [];
  for (const path of selectedPaths) {
    await checkpoint("controls");
    bindings.push(
      await inspectPath(fs, path, { missing: true, allowLink: true }),
    );
  }
  for (const path of new Set(excludePaths.map((path) => dirname(path)))) {
    await checkpoint("controls");
    const binding = await inspectPath(fs, path, { missing: true });
    assertSafe(
      binding.kind === "directory" || binding.kind === "missing",
      "Excluded subtree ancestors must be real directories.",
    );
    bindings.push(binding);
  }
  return {
    // Relative exclusions can be passed back to inspect without expanding scope.
    declarations: {
      inspectionPaths,
      excludePaths: excludePaths.map((path) => relative(workspacePath, path)),
    },
    bindings,
  };
}

export function exclusions(declarations) {
  return (declarations.excludePaths ?? []).map((path) =>
    location(declarations.workspacePath, path),
  );
}
