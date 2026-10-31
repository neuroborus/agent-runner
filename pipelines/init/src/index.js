import { join } from "node:path";

import { assertInit, within } from "./proposal.js";
import { assertInitState, createInitState, INIT_MODES } from "./workflow.js";

export { inspectInitSetup, selectInitPlacement } from "./inspection.js";
export { InitProposalError } from "./proposal.js";
export {
  acceptInitEdit,
  acceptInitQuestionAppend,
  acceptInitResult,
  assertInitState,
  authorizeInitEdit,
  closeInitClarification,
  createInitState,
  prepareInitTurn,
} from "./workflow.js";

const ROLES = Object.freeze(["planner", "reviewer"]);
// Proposal foundation only. Deliberately absent from the built-in registry and
// root dependencies until runner-owned publication and completion are available.
export const initPipeline = Object.freeze({
  id: "init",
  stateVersion: 1,
  description: "Review infrastructure setup proposals without publishing them.",
  roles: ROLES,
  resolveActiveRoles: (settings) =>
    settings?.mode === "lazy" ? Object.freeze(["planner"]) : ROLES,
  roleAccess: Object.freeze({
    planner: Object.freeze(["read-only"]),
    reviewer: Object.freeze(["read-only"]),
  }),
  workspace: Object.freeze({ kind: "directory", lease: "exclusive" }),
  resolveWorkspace({ projectPath, taskPath }) {
    assertInit(
      !within(projectPath, taskPath),
      "Init needs external task artifacts before setup exists.",
    );
    return {
      kind: "directory",
      lease: "exclusive",
      artifactPaths: [join(taskPath, "clarifications.md")],
    };
  },
  settings: Object.freeze({
    mode: Object.freeze({
      defaultValue: "independent",
      recommendedValue: "independent",
      values: INIT_MODES,
      validate: (value) => INIT_MODES.includes(value),
      errorMessage: "must be independent, lazy, or combined",
    }),
    placement: Object.freeze({
      defaultValue: null,
      option: "placement",
      values: Object.freeze(["integrated", "external"]),
      validate: (value) =>
        value === null || ["integrated", "external"].includes(value),
      errorMessage: "must be integrated or external",
    }),
    maxRevisionRounds: Object.freeze({
      defaultValue: 20,
      validate: (value) =>
        Number.isSafeInteger(value) && value > 0 && value <= 20,
      errorMessage: "must be an integer from 1 to 20",
    }),
  }),
  taskInputs: Object.freeze({
    task: Object.freeze({ filename: "task.md", optional: false }),
    context: Object.freeze({ filename: "context.md", optional: true }),
  }),
  runOptions: Object.freeze(["project", "task", "mode", "placement", ...ROLES]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  workflow: Object.freeze({
    createState: createInitState,
    validateRun: (run) => {
      assertInit(
        run.pipelineId === "init",
        "Init state belongs to another pipeline.",
      );
      assertInitState(run.pipelineState);
    },
  }),
});
