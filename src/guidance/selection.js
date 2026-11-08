import { join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  ConfigurationError,
  loadProjectConfiguration,
} from "../config/index.js";
import { WorkspaceSafetyError } from "../workspace/index.js";
import {
  contentHash,
  GuidanceError,
  unsafeControls,
  unsafePath,
} from "./content.js";
import { isWithin } from "./contract.js";
import { openLocalDirectory } from "./files.js";

const CONTROLS = [".git", ".agents", ".codex", ".claude", ".claude.json"];

export function resolveConfigurationPath(input, projectPath) {
  if (input.projectConfigurationPath === undefined) return undefined;
  const requestedPath = resolve(
    input.projectPath,
    input.projectConfigurationPath,
  );
  // External selectors belong to the supplied directory, before Git rebasing.
  // Integrated selectors retain their established worktree-relative semantics.
  return isWithin(resolve(input.projectPath), requestedPath)
    ? resolve(projectPath, input.projectConfigurationPath)
    : requestedPath;
}

// Configuration owns placement. Guidance owns only the exact local document and
// keeps directory workspaces on the enclosing worktree's exclusion key.
export function createGuidanceSelection({
  git,
  workspace,
  loadConfiguration,
  commonPath,
  stateRoot,
}) {
  async function target(path, preserveDirectory = false) {
    const projectPath = resolve(path);
    if (projectPath.split(sep).some((part) => CONTROLS.includes(part)))
      throw unsafePath();
    const leasePath = await workspace.exclusionPath({
      workspacePath: projectPath,
    });
    const marker = await workspace.inspectPath({
      projectPath: leasePath,
      path: join(leasePath, ".git"),
    });
    return {
      projectPath:
        marker.exists && !preserveDirectory ? leasePath : projectPath,
      leasePath,
      workspaceKind: marker.exists ? "git" : "directory",
    };
  }

  async function inspectDestination(
    selection,
    path,
    { allowAbsent = false } = {},
  ) {
    if (
      !isWithin(selection.basePath, path) ||
      path.split(sep).some((part) => CONTROLS.includes(part))
    )
      throw unsafePath();
    let controls;
    try {
      controls = await workspace.inspectControls({
        workspacePath: selection.projectPath,
        paths: [path],
        stateRoot,
      });
    } catch (cause) {
      if (cause instanceof WorkspaceSafetyError) throw unsafeControls(cause);
      throw cause;
    }
    if (controls.some((control) => isWithin(control, path))) throw unsafePath();
    const inspection = await workspace.inspectPath({
      projectPath: selection.basePath,
      path,
    });
    if (
      selection.basePath === selection.projectPath &&
      selection.workspaceKind === "git"
    ) {
      const safety = await git.inspectPath({
        projectPath: selection.leasePath,
        path,
      });
      const isAbsent = inspection.exists === false && safety.exists === false;
      if (
        safety.path !== path ||
        safety.tracked ||
        (!safety.ignored && !(allowAbsent && isAbsent))
      ) {
        throw new GuidanceError(
          "Local guidance and its temporary files must be ignored, untracked, and confined.",
          { code: "ERR_GUIDANCE_NOT_IGNORED" },
        );
      }
    }
    return inspection;
  }

  async function selection(input, projectPath, options) {
    let resolved = await target(projectPath);
    const configuration = await loadConfiguration();
    async function loadSelected(selected) {
      return loadProjectConfiguration({
        configurationPath: resolveConfigurationPath(
          input,
          selected.projectPath,
        ),
        projectPath: selected.projectPath,
        workspaceKind: selected.workspaceKind,
        runnerConfiguration: configuration,
        async inspectPath({ path }) {
          const inspection = await workspace.inspectPath({
            projectPath: selected.projectPath,
            path,
          });
          if (selected.workspaceKind !== "git") return inspection;
          const safety = await git.inspectPath({
            projectPath: selected.leasePath,
            path,
          });
          return {
            ...safety,
            relativePath: relative(selected.projectPath, path),
          };
        },
      });
    }
    let projectConfiguration;
    try {
      projectConfiguration = await loadSelected(resolved);
    } catch (cause) {
      if (
        input.projectConfigurationPath === undefined ||
        resolved.projectPath === resolve(projectPath) ||
        !(cause instanceof ConfigurationError) ||
        ![
          "ERR_PROJECT_CONFIGURATION_BINDING",
          "ERR_PROJECT_CONFIGURATION_READ",
          "ERR_PROJECT_CONFIGURATION_NOT_IGNORED",
        ].includes(cause.code)
      )
        throw cause;
      // A Git selector ordinarily names its worktree. Only an explicit target
      // binding may instead select the supplied directory within that worktree.
      const directory = await target(projectPath, true);
      const selected = await loadSelected(directory);
      if (
        selected?.configuration.infrastructure?.projectPath !==
        directory.projectPath
      )
        throw cause;
      resolved = directory;
      projectConfiguration = selected;
    }
    projectPath = resolved.projectPath;
    const basePath =
      projectConfiguration?.infrastructure.rootPath ?? projectPath;
    const localPath = join(
      projectConfiguration?.artifactPath ??
        join(projectPath, configuration.artifactRoot),
      "agent-runner",
      "rules.md",
    );
    if (
      localPath === commonPath ||
      (projectConfiguration !== null &&
        (isWithin(localPath, projectConfiguration.path) ||
          isWithin(projectConfiguration.path, localPath)))
    )
      throw unsafePath();
    const selected = {
      ...resolved,
      basePath,
      localPath,
      projectConfigurationPath: projectConfiguration?.path ?? null,
      configurationHash: contentHash(
        JSON.stringify({ configuration, projectConfiguration }),
      ),
    };
    const inspection = await inspectDestination(selected, localPath, options);
    const directory = await openLocalDirectory(basePath, localPath, {
      ancestors: inspection.ancestors,
    });
    try {
      await directory.verify();
    } finally {
      await directory.close();
    }
    return {
      ...selected,
      binding: {
        schemaVersion: 1,
        basePath,
        leasePath: resolved.leasePath,
        ancestors: inspection.ancestors,
      },
    };
  }

  async function assertSelection(input, context, options) {
    const current = await selection(input, context.projectPath, options);
    const binding = context.binding;
    if (
      current.localPath !== context.localPath ||
      current.configurationHash !== context.configurationHash ||
      (binding !== undefined &&
        (binding.basePath !== current.basePath ||
          binding.leasePath !== current.leasePath ||
          !binding.ancestors.every((ancestor, index) =>
            isDeepStrictEqual(ancestor, current.binding.ancestors[index]),
          )))
    ) {
      throw new GuidanceError(
        "Guidance configuration changed. The reserved destination cannot be redirected.",
        { code: "ERR_GUIDANCE_CONFIGURATION_CHANGED" },
      );
    }
    return current;
  }

  return { target, selection, assertSelection, inspectDestination };
}
