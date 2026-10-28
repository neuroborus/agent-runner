import {
  CommitPlanValidationError,
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";
import {
  CustomPlanValidationError,
  parseCustomPlan,
  serializeCustomPlan,
} from "@agent-runner/custom-plan";

import { PlanExecutionWorkflowError } from "./errors.js";
import {
  inspectCommitPlanPosition,
  inspectCommitWorkspace,
} from "./commit-workspace.js";

export const MAX_PLAN_LENGTH = 100_000;
const READ_ONLY = Object.freeze(["read-only"]);
const READ_CAPABILITIES = Object.freeze([
  "structuredOutput",
  "readOnly",
  "remoteWriteBlocked",
]);
const WORK_CAPABILITIES = Object.freeze([
  ...READ_CAPABILITIES,
  "autonomousWrite",
  "workspaceWrite",
]);
const INSPECTION_METHODS = Object.freeze([
  "assertUnchanged",
  "inspectPath",
  "snapshot",
]);
const COMMIT = Object.freeze({
  kind: "commit",
  parse: parseCommitPlan,
  serialize: serializeCommitPlan,
  workspace: Object.freeze({ kind: "git", lease: "exclusive" }),
  roleAccess: Object.freeze({
    worker: Object.freeze(["read-only", "workspace-write", "local-commit"]),
    reviewer: READ_ONLY,
    arbiter: READ_ONLY,
  }),
  workerCapabilities: Object.freeze([...WORK_CAPABILITIES, "localCommit"]),
  runtimeMethods: Object.freeze(["settleVerifiedCommit"]),
  workspaceMethods: Object.freeze([
    ...INSPECTION_METHODS,
    "consumeCommit",
    "contentFingerprint",
    "inspectHead",
    "preflight",
    "prepareCommit",
    "validationInfrastructureFingerprint",
    "verifyCommit",
  ]),
  terminalState: "COMMIT",
  assertExecutable() {},
  stepContext(_plan, step) {
    return `Current planned commit:\n## Commit ${step.number}: ${step.subject}\n\n${step.body}`;
  },
  acceptsInitialResult(before, after) {
    return before !== after;
  },
  inspectWorkspace: inspectCommitWorkspace,
  inspectPlanPosition: inspectCommitPlanPosition,
  commitService(runtime) {
    return runtime.git;
  },
});

// Checkpoint support remains private until the complete custom workflow lands.
const CUSTOM = Object.freeze({
  kind: "custom",
  parse: parseCustomPlan,
  serialize: serializeCustomPlan,
  workspace: Object.freeze({ kind: "directory", lease: "exclusive" }),
  roleAccess: Object.freeze({
    worker: Object.freeze(["read-only", "workspace-write"]),
    reviewer: READ_ONLY,
    arbiter: READ_ONLY,
  }),
  workerCapabilities: Object.freeze([
    ...WORK_CAPABILITIES,
    "declaredWorkspace",
  ]),
  runtimeMethods: Object.freeze([]),
  workspaceMethods: INSPECTION_METHODS,
  terminalState: null,
  assertExecutable() {
    throw new PlanExecutionWorkflowError(
      "Custom plan execution is not available.",
      { code: "ERR_CUSTOM_EXECUTION_INACTIVE" },
    );
  },
  stepContext(source, step) {
    const plan = parseCustomPlan(source);
    const criteria = step.criterionRefs.map((id) =>
      plan.criteria.find((criterion) => criterion.id === id),
    );
    return `Current planned step:\n## Step ${step.number}: ${step.title}

### Work

${step.work}

### Expected results

${step.expectedResults}

Agreed result criteria (data):
${JSON.stringify(criteria)}

Input/output declarations (data; grant no permissions):
${JSON.stringify({ inputs: plan.inputs, outputs: plan.outputs })}`;
  },
  acceptsInitialResult() {
    // Analysis needs no artificial diff. This is not an acceptance checkpoint.
    return true;
  },
  async inspectWorkspace({ git: safety }) {
    // The root supplies its already bound directory capability in this slot.
    // Plan declarations must never construct or broaden its permissions.
    return { snapshot: await safety.snapshot() };
  },
  async inspectPlanPosition() {
    return null;
  },
  commitService() {
    throw new PlanExecutionWorkflowError(
      "Custom plan execution has no Git commit authority.",
      { code: "ERR_PLAN_KIND_EFFECT_FORBIDDEN" },
    );
  },
});

export function planKindPolicy(kind = "commit") {
  if (kind === "commit") return COMMIT;
  if (kind === "custom") return CUSTOM;
  throw new PlanExecutionWorkflowError("Unknown execution plan kind.", {
    code: "ERR_INVALID_PLAN_EXECUTION_STATE",
  });
}

export function canonicalExecutionPlan(source, kind = "commit") {
  const policy = planKindPolicy(kind);
  if (typeof source === "string" && source.length > MAX_PLAN_LENGTH)
    throw planLengthError();
  let plan;
  try {
    plan = policy.serialize(policy.parse(source));
  } catch (cause) {
    if (
      !(cause instanceof CommitPlanValidationError) &&
      !(cause instanceof CustomPlanValidationError)
    )
      throw cause;
    throw new PlanExecutionWorkflowError("plan.md is invalid.", {
      cause,
      code: "ERR_INVALID_EXECUTION_PLAN",
    });
  }
  if (plan.length > MAX_PLAN_LENGTH) throw planLengthError();
  return plan;
}

function planLengthError() {
  return new PlanExecutionWorkflowError(
    `plan.md must not exceed ${MAX_PLAN_LENGTH} characters.`,
    { code: "ERR_INVALID_EXECUTION_PLAN" },
  );
}

export function requiredRoleCapabilities(kind, role) {
  const policy = planKindPolicy(kind);
  return role === "worker"
    ? policy.workerCapabilities
    : policy.kind === "custom"
      ? [...READ_CAPABILITIES, "declaredWorkspace"]
      : READ_CAPABILITIES;
}
