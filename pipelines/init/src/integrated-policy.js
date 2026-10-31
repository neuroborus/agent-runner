import { dirname, join, relative } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  assertInit,
  assertOutsideBareGitMetadata,
  hashText,
  within,
} from "./proposal.js";

export function integratedFinalizationPath(state) {
  const roots = [".agents", ".claude"].map((name) =>
    join(state.selection.rootPath, name, "skills", "finalization"),
  );
  for (const { path } of state.inspection.documents.skills) {
    if (
      within(state.selection.rootPath, path) &&
      path.endsWith("/finalization/SKILL.md") &&
      !roots.includes(dirname(path))
    )
      roots.push(dirname(path));
  }
  const existing = roots.find((root) =>
    state.inspection.entries.some(
      (entry) => entry.path === join(root, "SKILL.md") && entry.kind === "file",
    ),
  );
  const root =
    existing ??
    roots.find((root) =>
      state.inspection.entries.some(
        (entry) => entry.kind === "directory" && entry.path === dirname(root),
      ),
    ) ??
    roots[0];
  const path = join(root, existing ? "RUNNER.md" : "SKILL.md");
  assertOutsideBareGitMetadata(state.inspection, path);
  return path;
}

// Render before review. Publication never silently rewrites an accepted draft.
export function integratedFinalizationContent(state, checks) {
  const path = integratedFinalizationPath(state);
  const original = path.endsWith("/RUNNER.md")
    ? `Read and follow the adjacent SKILL.md, preserving every substantive check.\n\n`
    : "---\nname: finalization\ndescription: Validate this project's accepted changes before handoff.\n---\n\n";
  return finalizationContent(state, checks, original);
}

export function finalizationContent(state, checks, original) {
  const relativePath = (path) => relative(state.inspection.projectPath, path);
  return `${original}# Runner finalization\n\nWork from the project root. Read the current project instructions${
    state.inspection.documents.instructions.length
      ? `: ${state.inspection.documents.instructions.map(({ path }) => relativePath(path)).join(", ")}`
      : "."
  }\n\nRun the actual project checks in this order:\n\n${checks.map((command) => `- ${command}`).join("\n")}\n\nFix applicable failures and review the resulting content. Selected runner-trusted\ncommands are reserved for Runner execution after the FINALIZE turn.\n\nInside a pipeline, defer all staging, index-relative inspection and commit-message\npreparation to its owning COMMIT or HANDOFF boundary. Translate applicable staged\nchecks to HEAD-relative or explicit-tree content checks during FINALIZE, preserving\ntheir substantive validation. Never create a commit in FINALIZE. Outside a pipeline,\nfollow the project's manual handoff instructions and require explicit commit authority.\n`;
}

export const temporaryPath = (path) =>
  join(dirname(path), `.agent-runner-init-${hashText(path).slice(0, 24)}.tmp`);

// Literal anchored rules; preserve all original bytes, including negations.
function ignoreLiteral(path) {
  return `/${path.replace(/[\\*?\[\]#! ]/gu, "\\$&")}`;
}
export function integratedIgnorePaths(state) {
  const resources = state.proposal.resources.filter(
    ({ action, kind, content, beforeHash }) =>
      action !== "reuse" &&
      hashText(content) !== beforeHash &&
      !["artifacts", "guidance"].includes(kind),
  );
  return [
    ...new Set([
      state.selection.artifactPath,
      state.selection.configurationPath,
      join(state.selection.artifactPath, "agent-runner", "rules.md"),
      ...resources.map(({ path }) => temporaryPath(path)),
    ]),
  ];
}

export function integratedIgnoreContent(original, projectPath, paths) {
  if (paths.length === 0) return original;
  // Callers select paths not currently ignored. Reassert a literal exclusion
  // when a later negation cancelled it, adding each requested path only once.
  const additions = [
    ...new Set(paths.map((path) => ignoreLiteral(relative(projectPath, path)))),
  ];
  return (
    original +
    (original && !original.endsWith("\n") ? "\n" : "") +
    additions.map((line) => `${line}\n`).join("")
  );
}

function unrelatedSettings(value) {
  const result = structuredClone(value);
  delete result.infrastructure;
  delete result.artifactRoot;
  for (const id of ["plan-execution", "polishing"]) {
    if (result.pipelines?.[id]) {
      delete result.pipelines[id].finalization;
      if (Object.keys(result.pipelines[id]).length === 0)
        delete result.pipelines[id];
    }
  }
  if (result.pipelines && Object.keys(result.pipelines).length === 0)
    delete result.pipelines;
  return result;
}

export async function assertIntegratedPolicy(state, runtime) {
  const { workspace } = runtime;
  const projectPath = state.selection.rootPath;
  const resources = state.proposal.resources;
  const finalizationPath = integratedFinalizationPath(state);
  const procedure = resources.find(({ path }) => path === finalizationPath);
  assertInit(
    procedure?.kind === "finalization" &&
      (procedure.beforeHash === null || procedure.action === "reuse") &&
      procedure.content ===
        integratedFinalizationContent(state, state.proposal.checks) &&
      resources
        .filter(
          ({ kind, action }) => kind === "finalization" && action !== "reuse",
        )
        .every(({ path }) => path === finalizationPath),
    "Integrated finalization must preserve existing skills and derive its procedure from reviewed checks.",
  );
  await assertInitConfiguration(state, runtime, finalizationPath);
  const ignorePath = join(projectPath, ".gitignore");
  const ignoreDocument = await workspace.readFile({
    path: ignorePath,
    projectPath,
    optional: true,
  });
  const originalIgnore = ignoreDocument ?? "";
  const needed = [];
  for (const path of integratedIgnorePaths(state)) {
    assertInit(
      within(projectPath, path),
      "Integrated ignore path escaped its target.",
    );
    const evidence = await runtime.inspectIgnored(path);
    assertInit(
      !evidence.tracked,
      "Integrated infrastructure must be untracked.",
    );
    if (!evidence.ignored && !needed.some((parent) => within(parent, path)))
      needed.push(path);
  }
  const ignore = resources.find(({ kind }) => kind === "ignore");
  const expected = needed.length
    ? integratedIgnoreContent(originalIgnore, projectPath, needed)
    : originalIgnore;
  assertInit(
    ignore
      ? ignore.content === expected
      : needed.length === 0 && ignoreDocument !== null,
    "Integrated ignore changes must append only necessary nonduplicate exclusions.",
  );
}

export async function assertInitConfiguration(
  state,
  runtime,
  finalizationPath,
) {
  const { rootPath } = state.selection;
  const configuration = state.proposal.resources.find(
    ({ kind }) => kind === "configuration",
  );
  await runtime.validateConfiguration(configuration.content);
  const proposed = JSON.parse(configuration.content);
  const original = await runtime.workspace.readFile({
    path: configuration.path,
    projectPath: rootPath,
    optional: true,
  });
  assertInit(
    isDeepStrictEqual(
      unrelatedSettings(proposed),
      unrelatedSettings(
        original === null ? { schemaVersion: 1 } : JSON.parse(original),
      ),
    ) &&
      proposed.artifactRoot ===
        relative(rootPath, state.selection.artifactPath) &&
      isDeepStrictEqual(proposed.infrastructure, {
        schemaVersion: 1,
        placement: state.selection.placement,
        projectPath: state.inspection.projectPath,
        rootPath,
      }) &&
      ["plan-execution", "polishing"].every(
        (id) =>
          proposed.pipelines?.[id]?.finalization ===
          relative(rootPath, finalizationPath),
      ),
    "Setup must preserve unrelated settings and explicitly select its finalization procedure.",
  );
}
