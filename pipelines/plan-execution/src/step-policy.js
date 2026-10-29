import { join, resolve } from "node:path";

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
  runtimeMethods: Object.freeze([]),
  workspaceMethods: INSPECTION_METHODS,
  terminalState: "ACCEPT",
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
  async inspectWorkspace({ git: safety, projectPath, artifactRoot, runId }) {
    // The root supplies its already bound directory capability in this slot.
    // Plan declarations must never construct or broaden its permissions.
    const clarificationPath = executionClarificationPath(
      projectPath,
      artifactRoot,
      runId,
    );
    return {
      snapshot: await safety.snapshot({ allowedPaths: [clarificationPath] }),
      clarificationPath,
    };
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

export const PLAN_KIND_SETTING = Object.freeze({
  defaultValue: "commit",
  option: "plan-kind",
  values: Object.freeze(["commit", "custom"]),
  errorMessage: "must be commit or custom",
  validate: (value) => ["commit", "custom"].includes(value),
});

export function completedStepCount(state) {
  return state.planKind === "custom"
    ? (state.customResults?.accepted.length ?? 0)
    : state.completedCommits.length;
}

export const stepLabel = (step) => (step.subject ?? step.title).slice(0, 256);

export async function resolveExecutionWorkspace({
  settingOverrides: settings = {},
  projectPath,
  runId,
  artifactRoot = "LOCAL_ARTIFACTS",
  readTaskInput,
  preliminary = false,
}) {
  const policy = planKindPolicy(settings.planKind);
  if (policy.kind === "commit" || preliminary) return policy.workspace;
  const plan = policy.parse(
    canonicalExecutionPlan(await readTaskInput("plan.md"), "custom"),
  );
  if (plan.outputs.some((path) => /^[a-z][a-z0-9+.-]*:/iu.test(path)))
    throw new PlanExecutionWorkflowError("Custom outputs must be local paths.");
  return {
    ...policy.workspace,
    sourcePaths: plan.inputs
      .filter((source) => !/^[a-z][a-z0-9+.-]*:/iu.test(source))
      .map((source) => resolve(projectPath, source)),
    outputPaths: plan.outputs,
    infrastructurePaths:
      settings.finalization && !["auto", "none"].includes(settings.finalization)
        ? [resolve(projectPath, settings.finalization)]
        : [],
    artifactPaths: runId
      ? [executionClarificationPath(projectPath, artifactRoot, runId)]
      : [],
  };
}

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
  return role === "worker" && policy.kind === "commit"
    ? policy.workerCapabilities
    : policy.kind === "custom"
      ? [...READ_CAPABILITIES, "declaredWorkspace"]
      : READ_CAPABILITIES;
}

function executionClarificationPath(projectPath, artifactRoot, runId) {
  return join(
    projectPath,
    artifactRoot,
    "agent-runner",
    runId,
    "clarifications.md",
  );
}
