import { assertInit } from "./proposal.js";

// Only this delimited managed section is replaced. Other operator text survives.
export function initGuidanceContent(state) {
  const resource = state.proposal.resources.find(
    ({ kind }) => kind === "guidance",
  );
  const finalization = state.proposal.resources.find(
    ({ kind }) => kind === "finalization",
  );
  const original = resource.content
    .replace(
      /\n*<!-- agent-runner:init:start -->\n[\s\S]*?\n<!-- agent-runner:init:end -->\n?/gu,
      "",
    )
    .trimEnd();
  const content = `${original}\n\n<!-- agent-runner:init:start -->\n## Runner setup\n\nPlacement: ${state.selection.placement}\nTarget: ${state.inspection.projectPath}\nProject configuration: ${state.selection.configurationPath}\nArtifacts: ${state.selection.artifactPath}\nFinalization: ${finalization.path}\nWorking directory: ${state.inspection.projectPath}\nChecks:\n${state.proposal.checks.map((check) => `- ${check}`).join("\n")}\n<!-- agent-runner:init:end -->\n`;
  assertInit(
    Buffer.byteLength(content) <= 65_536,
    "Merged init guidance exceeds the complete document limit.",
    "guidance_size",
  );
  return content;
}
