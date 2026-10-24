import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { CHECK_AND_FIX_SCHEMA, REVIEW_SCHEMA } from "../src/schemas.js";
import { planExecutionPipeline } from "../src/index.js";
import { createLegacyRecoveryFixture } from "./support/index.js";

test("diagnosed check/fix reconstruction preserves durable content, commits and charges", async (t) => {
  let rejectAcquisition = true;
  const fixture = await createLegacyRecoveryFixture(t, {
    source: true,
    pendingCorrection: false,
    settings: { maxFixRoundsPerStep: 1 },
    failureCode: "ERR_CODEX_PROTOCOL",
    async onCheckAndFix(_request, { step, projectPath }) {
      if (step !== 2 || !rejectAcquisition) return;
      rejectAcquisition = false;
      await writeFile(
        join(projectPath, "feature-2.js"),
        "export const preserved = 2;\n",
      );
      throw Object.assign(new Error("PRIVATE_ACQUISITION_PAYLOAD"), {
        code: "ERR_CODEX_PROTOCOL",
        failure: {
          failureClass: "protocol_history_unavailable",
          checkpoint: "turn",
          outcome: "rejected",
          effect: "possible",
          retry: "terminal",
          reconstruction: {
            schemaVersion: 1,
            kind: "completed_turn_acquisition",
          },
        },
      });
    },
  });
  const { failed } = fixture;
  assert.equal(failed.counters.fixRounds, 1);
  assert.equal(failed.pipelineState.completedCommits.length, 1);
  assert.equal(failed.pipelineState.diagnosedCheckpoint.fixRoundCharged, true);
  assert.equal(failed.executionProcess, null);
  assert.equal(failed.executionResource, null);
  const original = await fixture.history();
  const bytes = await fixture.bytes();
  const restarted = fixture.openRunner();
  const status = await restarted.status(fixture.runId);
  const projected = planExecutionPipeline.projections.pause(status.run);
  assert.equal(projected.resumeState, "CHECK_AND_FIX");
  assert.match(projected.explanation, /protocol_history_unavailable/u);
  assert.deepEqual(projected.nextActions, [{ type: "resume", action: null }]);
  assert.deepEqual(await fixture.bytes(), bytes);

  // These refusals are pure descriptor validation over the one durable chain.
  for (const [name, mutate] of [
    [
      "missing provenance",
      (history) => {
        history.events = [];
      },
    ],
    [
      "discontinuous provenance",
      (history) => {
        history.events.splice(2, 1);
      },
    ],
    [
      "snapshot alone",
      (history) => {
        history.events.at(
          -1,
        ).state.pipelineState.diagnosedCheckpoint.turnRevision = 1;
      },
    ],
    [
      "diagnostic alone",
      (history) => {
        history.events.at(-1).state.pipelineState.diagnosedCheckpoint = null;
      },
    ],
    [
      "stronger failure",
      (history) => {
        history.events.at(-1).state.pause.diagnosticClass = "policy_violation";
      },
    ],
    [
      "ambiguous effect",
      (history) => {
        history.events.at(
          -1,
        ).state.pipelineState.diagnosedCheckpoint.failure.outcome = "ambiguous";
      },
    ],
    [
      "pending effect",
      (history) => {
        history.events.at(-1).state.pipelineState.pendingCommit = {};
      },
    ],
    [
      "unretired process",
      (history) => {
        history.events.at(-1).state.executionProcess = {};
      },
    ],
    [
      "unretired resource",
      (history) => {
        history.events.at(-1).state.executionResource = {};
      },
    ],
    [
      "wrong checkpoint",
      (history) => {
        history.events.at(
          -1,
        ).state.pipelineState.diagnosedCheckpoint.failure.checkpoint = "commit";
      },
    ],
    [
      "different turn",
      (history) => {
        const revision =
          history.events.at(-1).state.pipelineState.diagnosedCheckpoint
            .turnRevision;
        history.events[revision - 1].state.activeTurn.phase = "plan-context";
      },
    ],
    [
      "changed frozen roles",
      (history) => {
        history.events.at(-1).state.roles.worker.model = "another-model";
      },
    ],
    [
      "changed content after retirement",
      (history) => {
        history.events.at(
          -1,
        ).state.pipelineState.repositoryBaseline.contentFingerprint =
          "a".repeat(64);
      },
    ],
    [
      "changed budget",
      (history) => {
        history.events.at(-1).state.pipelineState.additionalFixRounds += 1;
      },
    ],
    [
      "invented charge",
      (history) => {
        history.events.at(-1).state.counters.fixRounds = 0;
      },
    ],
    [
      "different mode",
      (history) => {
        history.events.at(-1).state.pipelineState.settings.mode = "combined";
      },
    ],
    [
      "changed inputs",
      (history) => {
        history.events.at(-1).state.hashes.task = "b".repeat(64);
      },
    ],
    ...[
      "head",
      "refsFingerprint",
      "indexFingerprint",
      "remoteConfigurationFingerprint",
      "identityFingerprint",
    ].map((field) => [
      `changed ${field}`,
      (history) => {
        history.events.at(-1).state.pipelineState.repositoryBaseline[field] =
          "b".repeat(field === "head" ? 40 : 64);
      },
    ]),
    [
      "uncharged exhausted work",
      (history) => {
        const checkpoint =
          history.events.at(-1).state.pipelineState.diagnosedCheckpoint;
        const baseline =
          history.events.at(-1).state.pipelineState.repositoryBaseline;
        for (const event of history.events.slice(checkpoint.turnRevision - 2)) {
          event.state.counters.fixRounds = 1;
          event.state.pipelineState.repositoryBaseline =
            structuredClone(baseline);
        }
        checkpoint.fixRoundCharged = false;
      },
    ],
  ]) {
    const history = structuredClone(original);
    mutate(history);
    const run = history.events.at(-1)?.state ?? structuredClone(failed);
    history.run = run;
    planExecutionPipeline.prepareRecovery(run, history);
    assert.throws(
      () => planExecutionPipeline.validateResumeAction(run, null),
      undefined,
      name,
    );
  }
  const migrated = planExecutionPipeline.migrations[26]({
    pipelineState: failed.pipelineState,
  });
  assert.equal(
    migrated.diagnosedCheckpoint,
    null,
    "migration never invents evidence",
  );

  const dispatch = { id: randomUUID(), expectedRevision: failed.revision };
  // Exercise the state-owned admission used by detached CLI/MCP continuation.
  const lease = await fixture.store.acquireRunLease(fixture.runId);
  try {
    await fixture.store.recordRecoveryDispatch(lease, dispatch);
    await fixture.store.recordRecoveryDispatch(lease, dispatch, true);
  } finally {
    await lease.release();
  }
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  const admitted = structuredClone(await fixture.history());
  admitted.events.at(-1).state.pipelineState.additionalFixRounds += 1;
  admitted.run = admitted.events.at(-1).state;
  planExecutionPipeline.prepareRecovery(admitted.run, admitted);
  assert.throws(
    () => planExecutionPipeline.validateResumeAction(admitted.run, null),
    undefined,
    "dispatch cannot change saved state",
  );

  let publicationInterrupted = false;
  const interrupted = fixture.openRunner(
    fixture.openStore({
      onTransitionBoundary(phase) {
        if (!publicationInterrupted && phase === "event-appended") {
          publicationInterrupted = true;
          throw new Error("Reconstruction publication interrupted.");
        }
      },
    }),
  );
  const callsBefore = fixture.calls.length;
  await assert.rejects(
    interrupted.resume({ runId: fixture.runId }),
    /publication interrupted/u,
  );
  assert.equal(fixture.calls.length, callsBefore);

  const unavailable = fixture.openRunner(fixture.openStore(), {
    trustedValidation: {
      async preflight() {},
      async execute() {
        assert.fail("no fixture check was requested");
      },
      async inspectRequirements() {
        return {
          status: "BLOCKED",
          blockers: [{ command: "npm test", reason: "scratch unavailable" }],
        };
      },
    },
  });
  const { run: paused } = await unavailable.resume({ runId: fixture.runId });
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.deepEqual(
    paused.pipelineState.diagnosedCheckpoint,
    failed.pipelineState.diagnosedCheckpoint,
    "capability pause retains the pending fresh request",
  );
  assert.equal(fixture.calls.length, callsBefore);
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(run.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    run.pipelineState.completedCommits.slice(0, 1),
    failed.pipelineState.completedCommits,
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "feature-2.js"), "utf8"),
    "export const preserved = 2;\n",
  );
  const history = await fixture.history();
  const recovered = history.events.find(
    ({ activity }) => activity?.kind === "recovered",
  );
  assert.deepEqual(recovered.state.counters, failed.counters);
  assert.deepEqual(recovered.state.hashes, failed.hashes);
  assert.deepEqual(recovered.state.sessionLineage, failed.sessionLineage);
  const fresh = fixture.calls[callsBefore];
  assert.equal(fresh.schema, CHECK_AND_FIX_SCHEMA);
  assert.equal(
    fresh.session,
    undefined,
    "failed session is reconstructed freshly",
  );
  assert.equal(
    fixture.calls.filter(({ session }) => session?.mode === "fork").length,
    1,
  );
  const beforeCommit = history.events.findLast(
    ({ state }) => state.activeTurn?.phase === "commit",
  );
  assert.equal(
    beforeCommit.state.counters.fixRounds,
    1,
    "already charged correction is not charged twice",
  );
  assert.doesNotMatch(JSON.stringify(history), /PRIVATE_ACQUISITION_PAYLOAD/u);
});

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
