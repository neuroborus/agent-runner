export {
  CLARIFICATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  IMPLEMENTATION_INSTRUCTIONS,
  PLAN_COMPATIBILITY_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
} from "./prompts.js";
export { MAX_CLARIFICATION_ROUNDS, WORKFLOW_STATES } from "./workflow.js";

export const PLAN_EXECUTION_PIPELINE_ID = "plan-execution";

export const planExecutionPipeline = Object.freeze({
  id: PLAN_EXECUTION_PIPELINE_ID,
  stateVersion: 1,
  runOptions: Object.freeze([
    "project",
    "task",
    "worker",
    "reviewer",
    "arbiter",
  ]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Execute, finalize, review, and commit each step of a commit plan.",
});
