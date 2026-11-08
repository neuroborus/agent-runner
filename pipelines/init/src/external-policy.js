import { join, relative } from "node:path";
import { inspectInitOperation } from "./inspection-failure.js";

import { assertInit, isFinalizationRepair, within } from "./proposal.js";
import {
  assertInitConfiguration,
  finalizationContent,
} from "./integrated-policy.js";

export const externalFinalizationPath = (state) =>
  join(state.selection.rootPath, "finalization", "SKILL.md");

// Refer to the actual target procedures without copying or editing them.
export function externalFinalizationContent(state, checks) {
  const skills = state.inspection.documents.skills.filter(
    ({ path }) =>
      within(state.inspection.projectPath, path) &&
      path.endsWith("/finalization/SKILL.md"),
  );
  const original =
    "---\nname: finalization\ndescription: Validate this project's accepted changes before handoff.\n---\n\n" +
    (skills.length
      ? `Read and follow these existing project finalization skills from the project root, preserving every substantive check:\n\n${skills.map(({ path }) => `- ${relative(state.inspection.projectPath, path)}`).join("\n")}\n\n`
      : "");
  return finalizationContent(state, checks, original);
}

// General workspace snapshots omit unrelated ancestor provider storage.
export async function assertExternalControls(
  state,
  { workspace, stateRoot },
  inspectionPhase = "publication-preparation",
) {
  const paths = [
    state.selection.rootPath,
    ...state.proposal.resources.map(({ path }) => path),
  ];
  const controls = await inspectInitOperation(inspectionPhase, () =>
    workspace.inspectControls({
      workspacePath: state.inspection.projectPath,
      paths,
      stateRoot,
    }),
  );
  assertInit(
    !paths.some((path) => controls.some((control) => within(control, path))),
    "External setup cannot publish inside Git or provider controls.",
  );
}

export async function assertExternalPolicy(
  state,
  runtime,
  inspectionPhase = "publication-preparation",
) {
  await assertExternalControls(state, runtime, inspectionPhase);
  const { rootPath, configurationPath, artifactPath, protectionHash } =
    state.selection;
  const projectPath = state.inspection.projectPath;
  assertInit(
    !within(projectPath, rootPath) &&
      !within(rootPath, projectPath) &&
      (protectionHash !== null ||
        (state.inspection.schemaVersion === 1
          ? !state.inspection.entries.some(
              ({ path, kind }) => path === rootPath && kind !== "missing",
            )
          : state.inspection.entries.some(
              ({ path, kind }) => path === rootPath && kind === "missing",
            ))),
    "External setup must reuse a target-bound root or prepare an absent destination.",
  );
  const finalizationPath = externalFinalizationPath(state);
  const paths = {
    artifacts: artifactPath,
    configuration: configurationPath,
    finalization: finalizationPath,
    guidance: join(artifactPath, "agent-runner", "rules.md"),
  };
  assertInit(
    state.proposal.resources.length === Object.keys(paths).length &&
      state.proposal.resources.every(({ kind, path }) => paths[kind] === path),
    "External publication permits only selected infrastructure prerequisites and deferred guidance.",
  );
  const procedure = state.proposal.resources.find(
    ({ kind }) => kind === "finalization",
  );
  assertInit(
    (procedure.beforeHash === null ||
      procedure.action === "reuse" ||
      isFinalizationRepair(state, procedure)) &&
      procedure.content ===
        externalFinalizationContent(state, state.proposal.checks),
    "External finalization must preserve existing skills and derive its procedure from reviewed checks.",
  );
  await assertInitConfiguration(
    state,
    runtime,
    finalizationPath,
    inspectionPhase,
  );
}
