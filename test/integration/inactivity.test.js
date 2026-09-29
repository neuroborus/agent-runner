import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import * as execution from "../../pipelines/plan-execution/test/support/index.js";
import * as polishing from "../../pipelines/polishing/test/support/index.js";
import { attachInactivity } from "../support/index.js";

test("both writable pipelines reconcile partial inactivity and preserve one source fork and correction charge", async (t) => {
  for (const support of [execution, polishing]) {
    let recovery;
    const requests = [];
    const fixture = await support.createFixture(t, {
      mode: "lazy",
      sourceSession: support.SOURCE_SESSION,
      workWorker: [
        execution.implementationCompleted(),
        execution.checkAndFix(),
        execution.finalizationPassed(),
      ],
      ...(support === polishing
        ? {
            worker: [
              polishing.clarificationReady(),
              polishing.bootstrapReady("Worker"),
              polishing.polishingCompleted(),
              polishing.finalizationPassed(),
              polishing.checkAndFix(),
              polishing.cleanConfirmation(),
            ],
          }
        : {}),
      async onRoleRun(role, request) {
        if (
          role !== "worker" ||
          fixture.currentRun.activeTurn.phase !== "check-and-fix"
        )
          return;
        requests.push(request);
        if (requests.length === 1) {
          await writeFile(join(request.cwd, "partial.js"), "preserved\n");
          return recovery.expire(request);
        }
      },
    });
    recovery = await attachInactivity(fixture);
    const result = await fixture.run();
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(result.counters.fixRounds, 1);
    assert.equal(result.inactivityRecovery, null);
    assert.equal(requests[1].session, undefined);
    assert.equal(
      fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
        .length,
      1,
    );
    assert.deepEqual(
      recovery.events.map(({ kind }) => kind),
      ["expired", "reconstructing", "recovered"],
    );
  }
});

test("repeated writable expiry pauses at the same checkpoint without an availability loop", async (t) => {
  for (const support of [execution, polishing]) {
    let recovery,
      calls = 0;
    const fixture = await support.createFixture(t, {
      async onRoleRun(role, request) {
        if (role !== "worker" || request.access !== "workspace-write") return;
        calls++;
        await writeFile(
          join(request.cwd, "partial.js"),
          `preserved ${calls}\n`,
        );
        return recovery.expire(request);
      },
    });
    recovery = await attachInactivity(fixture);
    const result = await fixture.run();
    assert.equal(
      result.pause.reason,
      "backend_unavailable",
      JSON.stringify(result.pause),
    );
    assert.equal(result.pause.code, "ERR_PROVIDER_INACTIVE");
    assert.equal(calls, 2);
    assert.equal(result.inactivityRecovery.attempt, 2);
    assert.equal(
      result.inactivityRecovery.contentFingerprint,
      result.pipelineState.repositoryBaseline.contentFingerprint,
    );
    assert.equal(result.availabilityRetry ?? null, null);
  }
});

test("commit readiness retries only with pre-executor proof and a new authorization", async (t) => {
  let recovery,
    calls = 0;
  const fixture = await execution.createFixture(t, {
    onRoleRun(_role, request) {
      if (request.access === "local-commit" && calls++ === 0)
        return recovery.expire(request, { commit: true });
    },
  });
  recovery = await attachInactivity(fixture);
  const result = await fixture.run();
  assert.equal(
    result.pipelineState.workflowState,
    "DONE",
    JSON.stringify(result.pause),
  );
  assert.deepEqual(
    fixture.calls.worker
      .filter(({ access }) => access === "local-commit")
      .map(({ authorizationId }) => authorizationId),
    ["commit-1", "commit-2"],
  );
  assert.equal(result.inactivityRecovery, null);
});

test("an interrupted expiry publication preserves a charged writable checkpoint for reconstruction", async (t) => {
  let recovery,
    fail = true;
  const fixture = await execution.createFixture(t, {
    mode: "lazy",
    modeSettings: { maxFixRoundsPerStep: 1 },
    workWorker: [
      execution.implementationCompleted(),
      execution.checkAndFix(),
      execution.finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        fixture.currentRun.activeTurn.phase === "check-and-fix" &&
        fail
      ) {
        await writeFile(join(request.cwd, "partial.js"), "retained\n");
        return recovery.expire(request);
      }
    },
  });
  recovery = await attachInactivity(fixture, {
    onRecord() {
      if (fail) {
        fail = false;
        throw new Error("publication interrupted");
      }
    },
  });
  await assert.rejects(fixture.run(), { code: "ERR_INACTIVITY_RECOVERY" });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "CHECK_AND_FIX");
  assert.equal(fixture.currentRun.counters.fixRounds, 1);
  const result = await fixture.run();
  assert.equal(
    result.pipelineState.workflowState,
    "DONE",
    JSON.stringify(result.pause),
  );
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.inactivityRecovery, null);
});

test("a returned recovery response cannot hide read-only mutation or clear its recovery evidence", async (t) => {
  for (const support of [execution, polishing]) {
    let recovery,
      attempts = 0;
    const fixture = await support.createFixture(t, {
      async onRoleRun(role, request) {
        if (
          role !== "worker" ||
          fixture.currentRun.activeTurn.phase !== "bootstrap"
        )
          return;
        if (++attempts === 1) return recovery.expire(request);
        await writeFile(join(request.cwd, "forbidden.js"), "mutation\n");
      },
    });
    recovery = await attachInactivity(fixture);
    const result = await fixture.run();
    assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
    assert.equal(result.inactivityRecovery.attempt, 2);
    assert.equal(result.activeTurn, null);
    assert.equal(attempts, 2);
    assert.equal(
      recovery.events.some(({ kind }) => kind === "recovered"),
      false,
    );
  }
});

test("unsafe writable recovery pauses for the original repository-control change", async (t) => {
  let recovery,
    attempts = 0;
  const fixture = await execution.createFixture(t, {
    onRoleRun(role, request, _count, repository) {
      if (role !== "worker" || request.access !== "workspace-write") return;
      if (++attempts === 1) return recovery.expire(request);
      repository.changeIdentity();
    },
  });
  recovery = await attachInactivity(fixture);
  const result = await fixture.run();
  assert.equal(result.pause.reason, "unexpected_git_identity_change");
  assert.equal(result.inactivityRecovery.attempt, 2);
  assert.equal(result.activeTurn, null);
  assert.equal(attempts, 2);
  assert.equal(
    recovery.events.some(({ kind }) => kind === "recovered"),
    false,
  );
});
