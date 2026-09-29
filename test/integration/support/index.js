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
} from "../../../src/index.js";

const executeFile = promisify(execFile);

export const TWO_STEP_PLAN = `## Commit 1: feat(feature): add value

Add the requested value.

## Commit 2: test(feature): cover value

Cover the requested value.`;

export const ONE_STEP_PLAN = TWO_STEP_PLAN.split("\n## Commit 2:")[0];

function capabilities() {
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
}

function readyForExecution() {
  return {
    status: "READY",
    questions: [],
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

export function createBackend(
  backend,
  { failExecutionClarification = false, implementationGate = null } = {},
) {
  const calls = [];
  let executionClarifications = 0;
  let implementationCalls = 0;
  let sessionSequence = 0;

  function sessionId(request, role) {
    if (request.session?.mode === "continue") {
      return request.session.id;
    }
    sessionSequence += 1;
    return `${backend}-${role}-${sessionSequence}`;
  }

  async function implement(request) {
    implementationCalls += 1;
    if (implementationGate !== null && implementationCalls === 1) {
      implementationGate.entered.resolve();
      await implementationGate.release.promise;
    }
    if (
      request.prompt.includes(
        "Current planned commit:\n## Commit 1: feat(feature): add value",
      )
    ) {
      await mkdir(join(request.cwd, "src"), { recursive: true });
      await writeFile(
        join(request.cwd, "src", "feature.js"),
        "export const value = 1;\n",
      );
    } else {
      throw new Error("Unexpected planned commit.");
    }
    return {
      status: "COMPLETED",
      summary: "Implemented and self-reviewed the planned change.",
      reason: "",
      question: "",
      options: [],
      whyBlocked: "",
      evidence: [],
    };
  }

  return {
    backend,
    calls,
    async probe() {
      return capabilities();
    },
    async run(request) {
      const position = /Runner-selected plan position[^\n]*\n([^\n]+)/u.exec(
        request.prompt,
      );
      const assessment = position && {
        ...JSON.parse(position[1]),
        disposition: "CURRENT",
        evidence: [],
      };
      if (assessment) delete assessment.completed;
      if (request.prompt.startsWith("Validate the proposed context"))
        return {
          structured: { stepAssessment: assessment },
          sessionId: sessionId(request, "worker"),
        };
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
          sessionId: sessionId(request, "worker"),
        };
      }

      let role = "worker";
      let structured;
      if (
        request.prompt.includes(
          "Return the complete revised plan only when content changed.",
        ) ||
        request.prompt.includes(
          "Concrete findings from the preceding clean confirmation:",
        )
      ) {
        const authoring = request.prompt.includes(
          "Return the complete revised plan",
        );
        role = authoring ? "planner" : "worker";
        structured = {
          status: "UNCHANGED",
          ...(authoring
            ? { plan: "" }
            : { summary: "The candidate needs no repair.", reason: "" }),
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes(
          "A CLEAN result confirms primary convergence",
        ) ||
        request.prompt.includes("Inspected candidate fingerprint:")
      ) {
        role = request.prompt.includes("primary convergence")
          ? "planner"
          : "worker";
        structured = {
          status: "CLEAN",
          findings: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Study the task, existing clarifications")
      ) {
        role = "planner";
        structured = { status: "READY", questions: [] };
      } else if (
        request.prompt.includes("Write a concise commit-by-commit plan")
      ) {
        role = "planner";
        structured = {
          status: "DRAFT",
          plan: TWO_STEP_PLAN,
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Review the plan and verify that it is correct")
      ) {
        role = "reviewer";
        structured = {
          status: "APPROVED",
          findings: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (request.prompt.includes("Study the task, validated plan")) {
        executionClarifications += 1;
        if (failExecutionClarification && executionClarifications === 1) {
          const error = new Error("Temporary backend failure.");
          error.recoverable = true;
          throw error;
        }
        structured = readyForExecution();
      } else if (
        request.prompt.includes(
          "Study the task, existing changes, task-level clarifications",
        )
      ) {
        structured = readyForExecution();
      } else if (
        request.prompt.includes("Provide a concise bootstrap summary") ||
        request.prompt.includes("Return a concise bootstrap summary")
      ) {
        const reviewer = request.prompt.includes("As Reviewer");
        role = reviewer ? "reviewer" : "worker";
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
        structured = {
          status: "RESOLVED",
          summary: "Use the existing minimal module boundary.",
          disagreement: "",
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (request.prompt.includes("Implement the changes described")) {
        structured = await implement(request);
      } else if (
        request.prompt.includes("Polish the existing local repository changes")
      ) {
        structured = {
          status: "COMPLETED",
          summary:
            "The existing dirty change is already idiomatic and minimal.",
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
        role = "reviewer";
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
        role = "reviewer";
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
        throw new Error("Unexpected fake backend turn.");
      }

      if (
        (
          request.schema?.properties?.result?.anyOf?.[0]?.properties ??
          request.schema?.properties
        )?.stepAssessment
      )
        structured.stepAssessment = assessment;
      return {
        output: "structured",
        structured:
          request.schema?.properties?.result?.anyOf === undefined
            ? structured
            : { result: structured },
        sessionId: sessionId(request, role),
      };
    },
  };
}

export async function fixture(
  t,
  { autoCleanup = true, plan = TWO_STEP_PLAN } = {},
) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-workflows-"));
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await Promise.all([
    mkdir(join(projectPath, "src"), { recursive: true }),
    mkdir(taskPath),
  ]);
  await executeFile("git", ["init", "-q", projectPath]);
  await executeFile("git", [
    "-C",
    projectPath,
    "config",
    "user.name",
    "Test User",
  ]);
  await executeFile("git", [
    "-C",
    projectPath,
    "config",
    "user.email",
    "test@example.com",
  ]);
  await Promise.all([
    writeFile(join(projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(join(projectPath, "src", "base.js"), "export const base = 1;\n"),
    writeFile(join(taskPath, "task.md"), "Implement the requested value.\n"),
  ]);
  if (plan !== null) {
    await writeFile(join(taskPath, "plan.md"), plan);
  }
  await executeFile("git", ["-C", projectPath, "add", ".gitignore", "src"]);
  await executeFile("git", [
    "-C",
    projectPath,
    "commit",
    "-qm",
    "chore(test): initialize",
  ]);
  await executeFile("git", [
    "-C",
    projectPath,
    "remote",
    "add",
    "origin",
    "https://example.invalid/repository.git",
  ]);
  const cleanup = () => rm(workspace, { recursive: true, force: true });
  if (autoCleanup) {
    t.after(cleanup);
  }
  return { cleanup, projectPath, stateRoot, taskPath };
}

export function runtime(paths, adapters, configuration) {
  const runStore = createRunStore({ stateRoot: paths.stateRoot });
  const runner = createRunner({
    adapters,
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: async () =>
      parseRunnerConfiguration(JSON.stringify(configuration)),
    runStore,
  });
  return { runner, runStore };
}

export async function gitOutput(projectPath, args) {
  const { stdout } = await executeFile("git", ["-C", projectPath, ...args]);
  return stdout.trim();
}
