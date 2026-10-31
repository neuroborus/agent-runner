import { basename, dirname, join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  assertInit,
  assertInspection,
  assertInspectionExtension,
  digest,
  exact,
  hashText,
  isPath,
  within,
} from "./proposal.js";

const GROUPS = ["instructions", "checks", "skills", "guidance"];

// All filesystem/configuration work stays in the supplied public capabilities.
// Destination configuration is inspected, never used to configure this run.
export async function inspectInitSetup(
  {
    projectPath,
    taskPath,
    stateRoot,
    artifactRoot,
    placement = null,
    configurationPath = null,
    configurationPaths = [],
    candidatePaths = [],
    documents,
    previousInspection = null,
  },
  { workspace, loadProjectConfiguration, inspectConfigurationPath },
) {
  exact(documents, GROUPS);
  assertInit(
    Array.isArray(configurationPaths) && Array.isArray(candidatePaths),
    "Init configuration inventories must be arrays.",
  );
  for (const group of GROUPS)
    assertInit(
      Array.isArray(documents[group]) && documents[group].every(isPath),
      "Init inspection documents must be exact paths.",
    );
  if (previousInspection !== null) {
    assertInspection(previousInspection);
    candidatePaths = [
      ...candidatePaths,
      ...previousInspection.candidates.map(
        (candidate) => candidate.configurationPath,
      ),
    ];
    documents = Object.fromEntries(
      GROUPS.map((group) => [
        group,
        [
          ...documents[group],
          ...previousInspection.documents[group].map(
            (document) => document.path,
          ),
        ],
      ]),
    );
  }
  assertInit(
    [
      projectPath,
      taskPath,
      stateRoot,
      ...configurationPaths,
      ...candidatePaths,
    ].every(isPath),
    "Init inspection needs canonical absolute paths.",
  );
  assertInit(
    !within(projectPath, taskPath),
    "Init proposal artifacts must be outside the target before setup.",
  );
  assertInit(
    typeof artifactRoot === "string" &&
      artifactRoot.length > 0 &&
      !artifactRoot.startsWith("/") &&
      !artifactRoot
        .split(/[\\/]/u)
        .some((part) => ["", ".", ".."].includes(part)),
    "Init artifact root must be a confined relative path.",
  );
  const paths = GROUPS.flatMap((group) => documents[group]);
  const candidates = [];
  for (const configurationPath of [...new Set(candidatePaths)]) {
    const loaded = await loadProjectConfiguration({
      projectPath,
      configurationPath,
      inspectPath: inspectConfigurationPath,
    });
    assertInit(
      loaded !== null && loaded.protection.projectPath === projectPath,
      "Init configuration belongs to another target.",
    );
    candidates.push({
      configurationPath: loaded.path,
      placement: loaded.infrastructure.placement,
      rootPath: loaded.infrastructure.rootPath,
      artifactPath: loaded.artifactPath,
      protectionHash: digest(loaded.protection),
    });
  }
  const roots = [
    ...new Set([
      projectPath,
      ...candidates.map((candidate) => candidate.rootPath),
      ...(previousInspection?.roots ?? []),
    ]),
  ];
  const matches = matchingCandidates(candidates, {
    placement,
    configurationPath,
  });
  let missingExternalRoot = null;
  if (placement === "external" && matches.length === 0) {
    const externalRoot = defaultExternalRoot(projectPath);
    if (!roots.includes(externalRoot)) {
      const binding = await workspace.inspectPath({
        path: externalRoot,
        projectPath: dirname(externalRoot),
      });
      if (!binding.exists) {
        missingExternalRoot = binding;
        roots.push(externalRoot);
      }
    }
  }
  const inspection = await workspace.inspect({
    workspacePath: projectPath,
    taskPath,
    stateRoot,
    inputPaths: paths,
    configurationPaths,
    infrastructurePaths: roots.filter((root) => root !== projectPath),
  });
  if (missingExternalRoot !== null) {
    const binding = inspection.bindings.find(
      (binding) => binding.path === missingExternalRoot.path,
    );
    assertInit(
      binding?.exists === false &&
        isDeepStrictEqual(binding.ancestors, missingExternalRoot.ancestors),
      "Init destination or its ancestors changed during inspection.",
    );
  }
  const before = await workspace.snapshot({ inspection });
  const evidence = {};
  for (const group of GROUPS) {
    evidence[group] = [];
    for (const path of [...new Set(documents[group])].sort()) {
      const content = await workspace.readFile({
        path,
        projectPath: dirname(path),
      });
      evidence[group].push({ path, hash: hashText(content) });
    }
  }
  const after = await workspace.snapshot({ inspection });
  workspace.assertUnchanged({ before, after });
  // A snapshot of an enclosing task tree omits absent children.
  if (missingExternalRoot !== null)
    assertInit(
      !after.entries.some(
        (entry) =>
          entry.path === missingExternalRoot.path && entry.kind !== "missing",
      ),
      "Init destination is occupied by unbound infrastructure.",
    );
  for (const candidate of candidates) {
    const loaded = await loadProjectConfiguration({
      projectPath,
      configurationPath: candidate.configurationPath,
      inspectPath: inspectConfigurationPath,
    });
    assertInit(
      digest(loaded.protection) === candidate.protectionHash,
      "Init destination configuration changed during inspection.",
    );
  }
  // The clarification capability owns its mutable transcript and editor windows.
  const entries = after.entries.filter(
    ({ path }) => path !== join(taskPath, "clarifications.md"),
  );
  const scopeBindings = [
    ...new Map(
      inspection.bindings.map((binding) => [
        binding.path,
        {
          path: binding.path,
          hash: digest({
            binding,
            entries: entries.filter((entry) =>
              within(binding.path, entry.path),
            ),
            linkResolutions: after.linkResolutions.filter((link) =>
              within(binding.path, link.path),
            ),
            controls: inspection.controlPaths.filter((path) =>
              within(binding.path, path),
            ),
          }),
        },
      ]),
    ).values(),
  ].sort((a, b) => a.path.localeCompare(b.path));
  const result = {
    schemaVersion: 1,
    projectPath,
    taskPath,
    artifactRoot,
    configurationPaths: [...new Set(configurationPaths)].sort(),
    candidates: candidates.sort((a, b) =>
      a.configurationPath.localeCompare(b.configurationPath),
    ),
    documents: evidence,
    controlPaths: [...inspection.controlPaths],
    roots: roots.sort(),
    entries: entries.map(({ path, kind, hash }) => ({ path, kind, hash })),
    scopeBindings,
    // Bind missing paths, real ancestors, controls and file identities, not just bytes.
    snapshotHash: digest({
      inspection,
      entries,
      linkResolutions: after.linkResolutions,
    }),
  };
  assertInspection(result);
  if (previousInspection !== null)
    assertInspectionExtension(previousInspection, result);
  return result;
}

function defaultExternalRoot(projectPath) {
  const safeName =
    basename(projectPath)
      .replace(/[^a-zA-Z0-9-]/gu, "-")
      .slice(0, 48) || "project";
  return join(
    dirname(projectPath),
    `.agent-runner-${safeName}-${hashText(projectPath).slice(0, 12)}`,
  );
}

function matchingCandidates(
  candidates,
  { placement = null, configurationPath = null },
) {
  assertInit(
    placement === null || ["integrated", "external"].includes(placement),
    "Init placement must be integrated or external.",
  );
  assertInit(
    configurationPath === null || isPath(configurationPath),
    "Init configuration selection must be an exact absolute path.",
  );
  const matches = candidates.filter(
    (candidate) =>
      (configurationPath === null ||
        candidate.configurationPath === configurationPath) &&
      (placement === null || candidate.placement === placement),
  );
  if (configurationPath !== null) {
    assertInit(
      matches.length === 1,
      "Explicit init selections disagree or are not inspected.",
    );
  }
  return matches;
}

export function selectInitPlacement(
  inspection,
  { placement = null, configurationPath = null } = {},
) {
  assertInspection(inspection);
  const matches = matchingCandidates(inspection.candidates, {
    placement,
    configurationPath,
  });
  if (matches.length > 1) return null;
  if (matches.length === 1) return { ...matches[0] };
  const selected = placement ?? "integrated";
  const rootPath =
    selected === "integrated"
      ? inspection.projectPath
      : defaultExternalRoot(inspection.projectPath);
  assertInit(
    inspection.roots.includes(rootPath),
    "Init destination is occupied by unbound infrastructure.",
  );
  return {
    placement: selected,
    rootPath,
    artifactPath: resolve(rootPath, inspection.artifactRoot),
    configurationPath: join(
      rootPath,
      ...(selected === "integrated" ? [inspection.artifactRoot] : []),
      "agent-runner.json",
    ),
    protectionHash: null,
  };
}
