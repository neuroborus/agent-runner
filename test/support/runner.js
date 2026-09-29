import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import {
  createClarificationService,
  createGitService,
  createRunner,
  createRunStore,
  parseRunnerConfiguration,
} from "../../src/index.js";

export const executeFile = promisify(execFile);
export const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
export const PLANNER_SESSION = "22222222-2222-4222-8222-222222222222";
export const POST_CLARIFICATION_PLANNER_SESSION = `${PLANNER_SESSION}:1`;
export const PLANNING_SESSION = `${PLANNER_SESSION}:2`;
export const REVIEWER_SESSION = "33333333-3333-4333-8333-333333333333";
const ARBITER_SESSION = "44444444-4444-4444-8444-444444444444";
export const PREPARED_RUN = "55555555-5555-4555-8555-555555555555";
export const RUNNER_CONFIGURATION = {
  schemaVersion: 1,
  defaultBackend: "codex",
};
export const PLAN = `## Commit 1: feat(test): add behavior

Implement the requested behavior.`;

export function requestedStepAssessment(request) {
  const matched = /Runner-selected plan position[^\n]*\n([^\n]+)/u.exec(
    request.prompt,
  );
  if (!matched) return undefined;
  const { step, subject } = JSON.parse(matched[1]);
  return { step, subject, disposition: "CURRENT", evidence: [] };
}

function questions() {
  return {
    status: "QUESTIONS",
    questions: [
      {
        question: "Which behavior is required?",
        whyItMatters: "The answer changes the commit plan.",
      },
    ],
  };
}

function ready() {
  return { status: "READY", questions: [] };
}

function draft() {
  return {
    status: "DRAFT",
    plan: PLAN,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function approved() {
  return {
    status: "APPROVED",
    findings: [],
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function unchangedPlan() {
  return {
    status: "UNCHANGED",
    plan: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function cleanPlan() {
  return {
    status: "CLEAN",
    findings: [],
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

export function createAdapter({ fork = true, questionFirst = false } = {}) {
  const calls = [];
  const probes = [];
  let clarificationCalls = 0;
  let freshPlannerSessions = 0;
  function plannerSession() {
    const sessionId =
      freshPlannerSessions === 0
        ? PLANNER_SESSION
        : `${PLANNER_SESSION}:${freshPlannerSessions}`;
    freshPlannerSessions += 1;
    return sessionId;
  }
  return {
    calls,
    probes,
    async probe(options) {
      probes.push(options);
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        autonomousWrite: true,
        gitMetadataWriteBlocked: true,
        workspaceWrite: true,
        localCommit: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: fork,
      };
    },
    async run(request) {
      calls.push(request);
      let structured;
      let sessionId =
        request.session?.mode === "continue" ? request.session.id : undefined;
      if (request.prompt.includes("Study the task, existing clarifications")) {
        clarificationCalls += 1;
        structured =
          questionFirst && clarificationCalls === 1 ? questions() : ready();
        sessionId ??= plannerSession();
      } else if (
        request.prompt.includes("Write a concise commit-by-commit plan")
      ) {
        structured = draft();
        sessionId ??= plannerSession();
      } else if (request.prompt.includes("Return CLEAN only")) {
        structured = cleanPlan();
        sessionId ??= plannerSession();
      } else if (
        request.prompt.includes(
          "If you find any problems, fix the plan idiomatically and minimally",
        )
      ) {
        structured = unchangedPlan();
        sessionId ??= plannerSession();
      } else if (
        request.prompt.includes("Review the plan and verify that it is correct")
      ) {
        structured = approved();
        sessionId =
          request.session?.mode === "continue"
            ? request.session.id
            : REVIEWER_SESSION;
      } else {
        throw new Error("Unexpected fake adapter turn.");
      }
      return { output: "structured", structured, sessionId };
    },
  };
}

export function createExecutionAdapter({ bootstrapDisagreement = false } = {}) {
  const calls = [];
  const contextCalls = [];
  const probes = [];
  let freshSessionCount = 0;
  function freshSession() {
    const index = freshSessionCount;
    freshSessionCount += 1;
    return index === 0 ? PLANNER_SESSION : `${PLANNER_SESSION}:${index}`;
  }
  return {
    calls,
    contextCalls,
    probes,
    async probe(options) {
      probes.push(options);
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        autonomousWrite: true,
        gitMetadataWriteBlocked: true,
        workspaceWrite: true,
        localCommit: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: true,
      };
    },
    async run(request) {
      if (request.prompt.startsWith("Validate the proposed context")) {
        contextCalls.push(request);
        return {
          structured: { stepAssessment: requestedStepAssessment(request) },
          sessionId: request.session?.id ?? freshSession(),
        };
      }
      calls.push(request);
      if (request.access === "local-commit") {
        await executeFile("git", ["-C", request.cwd, "add", "-A"]);
        await executeFile("git", [
          "-C",
          request.cwd,
          "commit",
          "-qm",
          request.commit.message,
        ]);
        return {
          output: "committed",
          structured: { ready: true },
          sessionId: request.session.id,
        };
      }
      let structured;
      let sessionId =
        request.session?.mode === "continue" ? request.session.id : undefined;
      if (
        request.prompt.includes("Study the task, validated plan") ||
        request.prompt.includes("Study the task, existing changes")
      ) {
        structured = {
          status: "READY",
          questions: [],
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Provide a concise bootstrap summary") ||
        request.prompt.includes("Return a concise bootstrap summary")
      ) {
        const reviewer = request.prompt.includes("As Reviewer");
        structured = {
          status: "READY",
          summary:
            `${reviewer ? "Reviewer" : "Worker"} understands the task, ` +
            "plan, risks, and finalization procedure.",
          requiredChecks: [
            {
              id: "C1",
              command: "git diff --check HEAD",
              ...(request.schema?.properties?.result?.anyOf?.[0]?.properties
                ?.requiredChecks?.items?.properties?.steps
                ? {
                    steps: [
                      ...new Set(
                        [
                          ...request.prompt.matchAll(/^## Commit ([0-9]+):/gm),
                        ].map((match) => Number(match[1])),
                      ),
                    ].sort((a, b) => a - b),
                  }
                : {}),
            },
          ],
          validationInfrastructure: [],
          ...((request.schema?.properties?.result?.anyOf?.[0]?.properties
            ?.capabilityRequirements ??
          request.schema?.properties?.capabilityRequirements)
            ? { capabilityRequirements: [], environmentBlockers: [] }
            : {}),
          capacityField: "",
          capacityLimit: 0,
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Reconcile the independent Worker and Reviewer")
      ) {
        structured = bootstrapDisagreement
          ? {
              status: "DISAGREEMENT",
              summary: "",
              disagreement: "The roles selected different module boundaries.",
              reason: "",
              question: "",
              options: [],
              whyBlocked: "",
              evidence: ["The summaries name different owning modules."],
            }
          : {
              status: "RESOLVED",
              summary: "The roles agree on the minimal implementation.",
              disagreement: "",
              reason: "",
              question: "",
              options: [],
              whyBlocked: "",
              evidence: [],
            };
      } else if (
        request.prompt.includes("Implement the changes described") ||
        request.prompt.includes("Polish the existing local repository changes")
      ) {
        await writeFile(
          join(request.cwd, "feature.js"),
          "export const value = 1;\n",
        );
        structured = {
          status: "COMPLETED",
          summary: "Implemented and self-reviewed the planned change.",
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        structured = {
          status: "PASS",
          skillPath: "",
          summary: "The repository finalization procedure passed.",
          issues: [],
          requiredChecks: [{ id: "C1", command: "git diff --check HEAD" }],
          validationInfrastructure: [],
          checks: [
            {
              checkId: "C1",
              command: "git diff --check HEAD",
              status: "PASS",
              evidence: ["git diff --check HEAD exited successfully."],
            },
          ],
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (request.prompt.includes("semantic candidate")) {
        structured = {
          status: "APPROVED",
          findings: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Confirm the finalized changes") ||
        request.prompt.includes("Confirm the finalized change set") ||
        request.prompt.includes("Review the complete current change set")
      ) {
        structured = {
          status: "APPROVED",
          findings: [],
          validationChange: "UNCHANGED",
          validationEvidence: [],
          ...(request.prompt.includes("Confirm the finalized changes") ||
          request.prompt.includes("Confirm the finalized change set")
            ? { finalizationFindingIds: [] }
            : {}),
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else {
        throw new Error("Unexpected fake execution turn.");
      }
      sessionId ??= freshSession();
      if (
        (
          request.schema?.properties?.result?.anyOf?.[0]?.properties ??
          request.schema?.properties
        )?.stepAssessment
      )
        structured.stepAssessment = requestedStepAssessment(request);
      return {
        output: "structured",
        structured:
          request.schema?.properties?.result?.anyOf === undefined
            ? structured
            : { result: structured },
        sessionId,
      };
    },
  };
}

export function createArbiterAdapter() {
  let probeCalls = 0;
  const calls = [];
  return {
    calls,
    get probeCalls() {
      return probeCalls;
    },
    async probe() {
      probeCalls += 1;
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        remoteWriteBlocked: true,
      };
    },
    async run(request) {
      if (request.prompt.startsWith("Validate the proposed context"))
        return {
          structured: { stepAssessment: requestedStepAssessment(request) },
          sessionId: request.session.id,
        };
      assert.equal(probeCalls, 1);
      calls.push(request);
      assert.match(request.prompt, /^Resolve the bootstrap disagreement/u);
      return {
        output: "structured",
        structured: {
          result: {
            stepAssessment: requestedStepAssessment(request),
            direction: "SYNTHESIZE",
            summary: "Use the existing minimal module boundary.",
            rationale: "Repository ownership supports that boundary.",
            reason: "",
            question: "",
            options: [],
            whyBlocked: "",
            evidence: [],
          },
        },
        sessionId: ARBITER_SESSION,
      };
    },
  };
}

export async function createFixture(t) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-runtime-"));
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  await executeFile("git", ["init", "-q", projectPath]);
  await writeFile(
    join(taskPath, "task.md"),
    "Implement the requested behavior.\n",
  );
  t.after(() => rm(workspace, { recursive: true, force: true }));
  return { projectPath, stateRoot, taskPath, workspace };
}

export function configurationLoader(configuration = RUNNER_CONFIGURATION) {
  return async () => parseRunnerConfiguration(JSON.stringify(configuration));
}

export async function operatorFixture(t, pipelineId) {
  const fixture = await createFixture(t);
  await writeFile(
    join(fixture.projectPath, ".gitignore"),
    "/LOCAL_ARTIFACTS/\n",
  );
  await writeFile(
    join(fixture.projectPath, "source.js"),
    "export const value = 0;\n",
  );
  for (const args of [
    ["config", "user.name", "Test"],
    ["config", "user.email", "test@example.com"],
    ["add", "."],
    ["commit", "-qm", "chore(test): initialize"],
  ]) {
    await executeFile("git", ["-C", fixture.projectPath, ...args]);
  }
  if (pipelineId === "plan-execution")
    await writeFile(join(fixture.taskPath, "plan.md"), PLAN);
  if (pipelineId === "polishing")
    await writeFile(
      join(fixture.projectPath, "source.js"),
      "export const value = 1;\n",
    );
  return fixture;
}

export async function strandedPreWorkOwner(fixture) {
  const options = {
    stateRoot: fixture.stateRoot,
    hostName: "stop-recovery-host",
    processId: 100,
    processIsAlive: () => true,
    processIdentity: (pid) => ({
      bootId: SOURCE_SESSION,
      startTicks: String(pid),
    }),
  };
  const store = createRunStore(options);
  const input = {
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  };
  const { run } = await runnerFor(
    fixture,
    { codex: createExecutionAdapter() },
    { runStore: store },
  ).create(input);
  await store.acquireRunLease(run.runId);
  await store.acquireWorktreeLease(fixture.projectPath, run.runId);
  await store.requestOperatorStop({
    runId: run.runId,
    kind: "cancel_requested",
    expectedRevision: run.revision,
    idempotencyKey: "older-stranded-stop",
  });
  const recovery = createRunStore({
    ...options,
    processId: 200,
    processIsAlive: (pid) => pid !== 100,
  });
  assert.equal(await recovery.runLeaseOwnerIsLive(run.runId), false);
  return { store: recovery, olderRunId: run.runId, input };
}

export function runnerFor(
  fixture,
  adapters,
  {
    activities = [],
    configuration = RUNNER_CONFIGURATION,
    git = createGitService(),
    inspectSessionProcesses,
    runStore = createRunStore({ stateRoot: fixture.stateRoot }),
    trustedValidation,
  } = {},
) {
  return createRunner({
    adapters,
    clarifications: createClarificationService({ interactive: false }),
    git,
    inspectSessionProcesses,
    loadConfiguration: configurationLoader(configuration),
    onActivity(activity) {
      activities.push(activity);
    },
    runStore,
    ...(trustedValidation === undefined ? {} : { trustedValidation }),
  });
}
