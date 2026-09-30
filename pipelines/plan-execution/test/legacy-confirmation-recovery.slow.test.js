import assert from "node:assert/strict";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { REVIEW_SCHEMA } from "../src/schemas.js";
import { createLegacyRecoveryFixture } from "./support/index.js";

test("legacy confirmation recovers through one verified commit", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    mode: "independent",
    pendingCorrection: false,
    steps: 1,
  });
  const { failed } = fixture;
  assert.equal(failed.pipelineState.pendingCorrection, false);
  assert.equal(failed.pipelineState.finalizationResult.status, "PASS");
  assert.deepEqual(failed.pipelineState.completedCommits, []);
  const bytes = await fixture.bytes();
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  assert.deepEqual(await fixture.bytes(), bytes, "status is read-only");

  const callsBefore = fixture.calls.length;
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });

  assert.equal(run.pipelineState.workflowState, "DONE");
  const calls = fixture.calls.slice(callsBefore);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].access, "read-only");
  assert.equal(calls[0].schema, REVIEW_SCHEMA);
  assert.equal(calls[1].access, "local-commit");
  const { events } = await fixture.history();
  const recovered = events.find(
    ({ activity }) => activity?.kind === "recovered",
  );
  assert.ok(recovered);
  assert.equal(recovered.state.pipelineState.workflowState, "CONFIRM");
  assert.deepEqual(recovered.state.counters, failed.counters);
  assert.deepEqual(recovered.state.sessionLineage, failed.sessionLineage);
  assert.deepEqual(recovered.state.pipelineState, {
    ...failed.pipelineState,
    workflowState: "CONFIRM",
  });
  const head = (await fixture.git("rev-parse", "HEAD")).stdout.trim();
  assert.deepEqual(run.pipelineState.completedCommits, [head]);
  assert.equal(
    (await fixture.git("log", "-1", "--pretty=%s")).stdout.trim(),
    "feat(test): add behavior 1",
  );
  assert.doesNotMatch(
    JSON.stringify(events),
    /PRIVATE_LEGACY_PROVIDER_PAYLOAD/u,
  );

  const completedCalls = fixture.calls.length;
  await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(
    fixture.calls.length,
    completedCalls,
    "completed effects are never replayed",
  );
});

test("legacy confirmation rejects ineligible failures and invalid journal proof", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    pendingCorrection: false,
    steps: 1,
  });
  const original = await fixture.bytes();
  const restore = () =>
    Promise.all(
      ["state.json", "events.jsonl", "progress.md"].map((name, index) =>
        writeFile(join(fixture.directoryPath, name), original[index]),
      ),
    );

  await t.test("historical server overload", async () => {
    await fixture.rewrite(({ events }) => {
      events.at(-1).state.pause.diagnosticClass = "turn_server_overloaded";
    });
    const calls = fixture.calls.length;
    try {
      assert.deepEqual(await fixture.recoveryAction(), []);
      const { run } = await fixture.openRunner().resume({
        runId: fixture.runId,
      });
      assert.equal(run.pipelineState.workflowState, "FAILED");
      assert.equal(run.pause.diagnosticClass, "turn_server_overloaded");
      assert.equal(fixture.calls.length, calls);
    } finally {
      await restore();
    }
  });

  for (const [name, mutate] of [
    ["missing journal", () => rm(join(fixture.directoryPath, "events.jsonl"))],
    [
      "discontinuous journal",
      () =>
        fixture.rewrite(({ events }) => {
          events.splice(5, 1);
        }),
    ],
    [
      "tampered finalization evidence",
      () =>
        fixture.rewrite(({ events }) => {
          events.at(
            -1,
          ).state.pipelineState.finalizationResult.checks[0].evidence = [
            "Altered attestation",
          ];
        }),
    ],
  ])
    await t.test(name, async () => {
      await mutate();
      const calls = fixture.calls.length;
      try {
        try {
          assert.deepEqual(await fixture.recoveryAction(), []);
        } catch (error) {
          assert.ok(
            ["ERR_INVALID_EVENT_LOG", "ERR_INVALID_RUN_STATE"].includes(
              error.code,
            ),
          );
          assert.doesNotMatch(
            error.message,
            /PRIVATE_LEGACY_PROVIDER_PAYLOAD|Altered attestation/u,
          );
        }
        try {
          await fixture.openRunner().resume({ runId: fixture.runId });
        } catch (error) {
          assert.ok(
            ["ERR_INVALID_EVENT_LOG", "ERR_INVALID_RUN_STATE"].includes(
              error.code,
            ),
          );
        }
        assert.equal(fixture.calls.length, calls);
      } finally {
        await restore();
      }
    });
});

test("legacy confirmation recovers each journal publication boundary exactly once", async (t) => {
  for (const boundary of [
    "event-appended",
    "state-replaced",
    "progress-replaced",
  ])
    await t.test(boundary, async (t) => {
      const fixture = await createLegacyRecoveryFixture(t, {
        pendingCorrection: false,
        steps: 1,
      });
      const error = new Error("Simulated recovery persistence interruption");
      let armed = true;
      const store = fixture.openStore({
        onTransitionBoundary(phase) {
          if (armed && phase === boundary) {
            armed = false;
            throw error;
          }
        },
      });
      await assert.rejects(
        fixture.openRunner(store).resume({ runId: fixture.runId }),
        (cause) => cause === error,
      );
      assert.equal(
        (await fixture.store.loadRun(fixture.runId)).pipelineState
          .workflowState,
        "CONFIRM",
      );
      assert.equal(
        (await fixture.openRunner().resume({ runId: fixture.runId })).run
          .pipelineState.workflowState,
        "DONE",
      );
      assert.equal(
        (await fixture.history()).events.filter(
          ({ activity }) => activity?.kind === "recovered",
        ).length,
        1,
      );
    });
});

test("legacy confirmation respects run and worktree execution leases", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    pendingCorrection: false,
    steps: 1,
  });
  const before = await fixture.bytes();
  const runLease = await fixture.store.acquireRunLease(fixture.runId);
  try {
    await assert.rejects(
      fixture.openRunner().resume({ runId: fixture.runId }),
      { code: "ERR_RUN_LEASED" },
    );
  } finally {
    await runLease.release();
  }

  const worktreeLease = await fixture.store.acquireWorktreeLease(
    fixture.projectPath,
    "99999999-9999-4999-8999-999999999999",
  );
  try {
    await assert.rejects(
      fixture.openRunner().resume({ runId: fixture.runId }),
      { code: "ERR_WORKTREE_LEASED" },
    );
    assert.equal(await fixture.store.runIsLeased(fixture.runId), false);
    assert.deepEqual(await fixture.bytes(), before);
  } finally {
    await worktreeLease.release();
  }
});
