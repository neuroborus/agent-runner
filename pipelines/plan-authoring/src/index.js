export {
  CLARIFICATION_INSTRUCTIONS,
  DRAFT_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
} from "./prompts.js";
export { MAX_CLARIFICATION_ROUNDS, WORKFLOW_STATES } from "./workflow.js";

export const PLAN_AUTHORING_PIPELINE_ID = "plan-authoring";

export const planAuthoringPipeline = Object.freeze({
  id: PLAN_AUTHORING_PIPELINE_ID,
  stateVersion: 1,
  runOptions: Object.freeze([
    "project",
    "task",
    "planner",
    "reviewer",
  ]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Analyze a task, draft a commit plan, review it, and write plan.md.",
});
