import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { createGitService } from "../../../src/git/index.js";
import { planExecutionPipeline, runPlanExecution } from "../src/index.js";
import { resolveStopBoundary } from "../src/commit-checkpoint.js";
import {
  bootstrapReady,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createRealGitFixture,
  executeFile,
  finalizationPassed,
  implementationCompleted,
  reconciliationResolved,
  trustedValidationSnapshot,
} from "./support/index.js";

const subject = "feat(test): add behavior";
const plan = `## Commit 1: ${subject}\n\nImplement behavior.\n\n## Commit 2: feat(test): extend behavior\n\nExtend behavior.`;
const turns = (mode) => [
  implementationCompleted(),
  ...(mode === "independent" ? [] : [checkAndFix(), cleanConfirmation()]),
  finalizationPassed(),
];
const calls = (fixture) => Object.values(fixture.calls).flat();
const git = (fixture, ...args) =>
  executeFile("git", ["-C", fixture.projectPath, ...args]);
const head = async (fixture) =>
  (await git(fixture, "rev-parse", "HEAD")).stdout.trim();
function useHeadInspection(fixture) {
  fixture.runtime.git.inspectHead = createGitService().inspectHead;
}
function assertRevision(run, baseline) {
  assert.equal(run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(run.pause.reason, "plan_revision_required");
  assert.equal(run.pipelineState.currentStep, 1);
  assert.deepEqual(run.pipelineState.completedCommits, []);
  if (baseline)
    assert.deepEqual(run.pipelineState.repositoryBaseline, baseline);
  const status = planExecutionPipeline.projections.status(run);
  assert.equal(status.currentStep, 1);
  assert.equal(
    planExecutionPipeline.projections.pause(run).reason,
    "plan_revision_required",
  );
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} HEAD already contains step one despite bootstrap proposing step two`, async (t) => {
    const fixture = await createRealGitFixture(t, {
      mode,
      plan,
      worker: [
        clarificationReady(),
        {
          ...bootstrapReady("Worker"),
          summary:
            "The first commit already landed. Implement commit two next.",
        },
        reconciliationResolved(),
      ],
    });
    useHeadInspection(fixture);
    await git(fixture, "commit", "--allow-empty", "-qm", subject);
    const before = await head(fixture);
    const paused = await fixture.run();
    assertRevision(paused);
    assert.equal(paused.pipelineState.resolvedSummary, null);
    assert.equal(resolveStopBoundary(paused), null);
    assert.equal(calls(fixture).length, 0);
    assert.equal(await head(fixture), before);
    assertRevision(
      await fixture.run(),
      paused.pipelineState.repositoryBaseline,
    );
    assert.equal(calls(fixture).length, 0);
  });

  for (const interrupted of [false, true]) {
    test(`${mode} ${interrupted ? "interrupted" : "paused"} implementation rejects an external commit`, async (t) => {
      const fixture = await createRealGitFixture(t, {
        mode,
        plan,
        workWorker: turns(mode),
        onRequirementInspection: () => ({
          status: "BLOCKED",
          blockers: [{ command: "npm test", reason: "unavailable" }],
        }),
      });
      useHeadInspection(fixture);
      const paused = await fixture.run();
      assert.equal(paused.pause.resumeState, "IMPLEMENT");
      const baseline = structuredClone(paused.pipelineState.repositoryBaseline);
      if (interrupted)
        Object.assign(fixture.currentRun, {
          activeTurn: { role: "worker", phase: "implement" },
          pause: null,
          pipelineState: {
            ...paused.pipelineState,
            workflowState: "IMPLEMENT",
          },
        });
      await writeFile(
        join(fixture.projectPath, "external.txt"),
        "External content\n",
      );
      await git(fixture, "add", "external.txt");
      await git(
        fixture,
        "commit",
        "-qm",
        "fix(test): externally change behavior",
      );
      const before = await head(fixture);
      const count = calls(fixture).length;
      const rejected = await fixture.run();
      assertRevision(rejected, baseline);
      assert.equal(calls(fixture).length, count);
      assert.equal(await head(fixture), before);
      assert.equal(
        calls(fixture).some(({ access }) => access !== "read-only"),
        false,
      );
      if (interrupted)
        assert.deepEqual(rejected.activeTurn, {
          role: "worker",
          phase: "implement",
        });
    });
  }

  test(`${mode} consumed commit recovery precedes stale-subject inspection and resumes the next step`, async (t) => {
    let unavailable = true;
    const fixture = await createRealGitFixture(t, {
      mode,
      plan,
      workWorker: [...turns(mode), ...turns(mode)],
      onCommitVerify() {
        if (unavailable) {
          unavailable = false;
          throw Object.assign(new Error("Verification interrupted"), {
            code: "ERR_FAKE_COMMIT_VERIFICATION",
          });
        }
      },
    });
    useHeadInspection(fixture);
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "commit_failed");
    assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
    assert.equal(
      (
        await fixture.runtime.git.inspectHead({
          projectPath: fixture.projectPath,
        })
      ).subject,
      subject,
    );
    const inspect = fixture.runtime.git.inspectHead;
    fixture.runtime.git.inspectHead = (options) => {
      assert.notEqual(
        fixture.currentRun.pipelineState.pendingCommit?.status,
        "consumed",
      );
      return inspect(options);
    };
    const completed = await fixture.run();
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.pipelineState.completedCommits.length, 2);
    assert.equal(
      calls(fixture).filter(({ access }) => access === "local-commit").length,
      2,
    );
    assert.equal(
      (await inspect({ projectPath: fixture.projectPath })).subject,
      "feat(test): extend behavior",
    );
  });
}

test("stop recovery never inspects stale plans or starts providers", async (t) => {
  const fixture = await createRealGitFixture(t, {
    onRequirementInspection: () => ({ status: "BLOCKED", blockers: [] }),
  });
  const paused = await fixture.run();
  const count = calls(fixture).length;
  fixture.runtime.git.inspectHead = () =>
    assert.fail("No plan inspection during stop recovery");
  fixture.runtime.trustedValidation.preflight = () =>
    assert.fail("No preparation during stop recovery");
  const stopped = await runPlanExecution({
    run: paused,
    runtime: fixture.runtime,
    operatorStop: true,
  });
  assert.deepEqual(stopped.pipelineState.completedCommits, []);
  assert.equal(calls(fixture).length, count);
});

for (const [name, args, reason] of [
  [
    "identity",
    ["config", "user.name", "Changed Test Identity"],
    "unexpected_git_identity_change",
  ],
  [
    "remote",
    ["remote", "add", "fixture", "https://example.com/fixture.git"],
    "unexpected_remote_configuration_change",
  ],
  ["ref", ["branch", "external-ref"], "unexpected_git_ref_change"],
]) {
  test(`unrelated interrupted ${name} changes retain existing diagnostics`, async (t) => {
    const fixture = await createRealGitFixture(t, {
      onRequirementInspection: () => ({ status: "BLOCKED", blockers: [] }),
    });
    const paused = await fixture.run();
    Object.assign(fixture.currentRun, {
      activeTurn: { role: "worker", phase: "implement" },
      pause: null,
      pipelineState: { ...paused.pipelineState, workflowState: "IMPLEMENT" },
    });
    await git(fixture, ...args);
    assert.equal((await fixture.run()).pause.reason, reason);
  });
}

test("similar HEAD subjects are not treated as the exact current step", async (t) => {
  const fixture = await createRealGitFixture(t, {
    onRequirementInspection: () => ({ status: "BLOCKED", blockers: [] }),
  });
  useHeadInspection(fixture);
  await git(fixture, "commit", "--allow-empty", "-qm", `${subject} later`);
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");
  assert.notEqual(paused.pipelineState.resolvedSummary, null);
});

test("interrupted stale plans are classified before capability preparation", async (t) => {
  const settings = { trustedChecks: ["service-check"] };
  const fixture = await createRealGitFixture(t, {
    trustedValidation: trustedValidationSnapshot("service-check", "npm test"),
    modeSettings: settings,
    onRequirementInspection: () => ({ status: "BLOCKED", blockers: [] }),
  });
  const paused = await fixture.run(settings);
  assert.equal(paused.pause.resumeState, "IMPLEMENT");
  Object.assign(fixture.currentRun, {
    activeTurn: { role: "worker", phase: "implement" },
    pause: null,
    pipelineState: { ...paused.pipelineState, workflowState: "IMPLEMENT" },
  });
  await git(fixture, "commit", "--allow-empty", "-qm", subject);
  fixture.runtime.trustedValidation.preflight = () =>
    assert.fail("Classify HEAD before preparation");
  assertRevision(
    await fixture.run(settings),
    paused.pipelineState.repositoryBaseline,
  );
});

for (const interrupted of [false, true]) {
  test(`HEAD drift racing ${interrupted ? "interrupted" : "ordinary"} reconciliation still requires plan revision`, async (t) => {
    const fixture = await createRealGitFixture(t, {
      onRequirementInspection: () => ({ status: "BLOCKED", blockers: [] }),
    });
    const paused = await fixture.run();
    if (interrupted)
      Object.assign(fixture.currentRun, {
        activeTurn: { role: "worker", phase: "implement" },
        pause: null,
        pipelineState: { ...paused.pipelineState, workflowState: "IMPLEMENT" },
      });
    fixture.runtime.git[
      interrupted ? "reconcileInterrupted" : "assertUnchanged"
    ] = async () => {
      await git(
        fixture,
        "commit",
        "--allow-empty",
        "-qm",
        "fix(test): external race",
      );
      throw Object.assign(new Error("HEAD changed"), {
        code: interrupted
          ? "ERR_INTERRUPTED_REPOSITORY_CONTROL_CHANGED"
          : "ERR_READ_ONLY_REPOSITORY_CHANGED",
        changes: ["head", "refs"],
      });
    };
    const count = calls(fixture).length;
    assertRevision(
      await fixture.run(),
      paused.pipelineState.repositoryBaseline,
    );
    assert.equal(calls(fixture).length, count);
  });
}
