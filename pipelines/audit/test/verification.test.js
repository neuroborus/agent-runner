import assert from "node:assert/strict";
import test from "node:test";

import {
  auditPipeline,
  createAuditState,
  MAX_FINDING_RECHECK_PASSES,
} from "../src/index.js";
import { fingerprint } from "../src/discovery-contract.js";
import { acceptRecheck, reserveRecheck } from "../src/verification-contract.js";
import {
  complete,
  decision,
  finding,
  fixture,
  pendingRun,
  recheck,
} from "./support/index.js";

test("recheck semantic diagnostics retain exact bindings and payload field locations", async () => {
  const saved = await pendingRun();
  const state = reserveRecheck(saved);
  const before = structuredClone(state);
  const valid = {
    status: "COMPLETE",
    snapshotFingerprint: state.pendingBatch.snapshotFingerprint,
    reportFingerprint: state.pendingBatch.reportFingerprint,
    batchFingerprint: fingerprint(state.pendingBatch),
    decisions: [decision("negative-count")],
    additions: [],
  };
  const cases = [
    ...["snapshotFingerprint", "reportFingerprint", "batchFingerprint"].map(
      (field) => [
        { [field]: "b".repeat(64) },
        `recheck.${field}`,
        "binding-mismatch",
      ],
    ),
    [{ decisions: [] }, "recheck.decisions", "candidate-mismatch"],
    [
      { decisions: [decision("negative-count", { rationale: " " })] },
      "recheck.decisions[0].rationale",
      "invalid-text",
    ],
    [
      {
        decisions: [
          decision("negative-count", {
            kind: "correct",
            finding: finding({ impact: "" }),
          }),
        ],
      },
      "recheck.decisions[0].finding.impact",
      "invalid-text",
    ],
    [
      { additions: [finding({ id: "a".repeat(65) })] },
      "recheck.additions[0].id",
      "invalid-id",
    ],
  ];
  for (const [patch, field, code] of cases) {
    assert.throws(
      () => acceptRecheck(state, { ...valid, ...patch }),
      (error) => {
        assert.deepEqual(error.diagnostics, [{ field, code }]);
        return true;
      },
    );
    assert.deepEqual(state, before);
  }
  assert.equal(acceptRecheck(state, valid).acceptedBatches.length, 1);
});

test("every disposition is rechecked, with fresh independent Reviewers after material changes", async () => {
  const candidate = (id) => finding({ id, causeId: `${id}-cause` });
  const candidates = [
    "confirmed",
    "corrected",
    "rejected",
    "merged",
    "uncertain",
  ].map(candidate);
  const corrected = candidate("corrected");
  corrected.severity = "High";
  corrected.recommendation = "Validate the count before allocation";
  const decisions = [
    decision("confirmed"),
    decision("corrected", {
      kind: "correct",
      finding: corrected,
      rationale: "The failure also affects valid callers",
    }),
    decision("rejected", {
      kind: "reject",
      rationale: "The caller already rejects negative counts before parsing",
    }),
    decision("merged", {
      kind: "merge",
      targetId: "confirmed",
      rationale:
        "The retained finding already contains the same evidence and example",
    }),
    decision("uncertain", {
      kind: "hypothesis",
      rationale: "The runtime allocation path is unavailable",
      hypothesis: {
        id: "uncertain",
        title: "Allocation may reject counts",
        evidence: [],
        uncertainty: "The allocator implementation could not be inspected",
      },
    }),
  ];
  const saved = await pendingRun(candidates, { source: "source-session" });
  const f = fixture(
    [(request) => recheck(request, { decisions }), recheck, complete()],
    { saved },
  );
  const result = await f.execute();
  const state = result.pipelineState;
  assert.equal(f.calls[0].schema.properties.decisions.minItems, 1);
  assert.equal(state.workflowState, "DISCOVERY_CLEAN");
  assert.deepEqual(
    state.recheckHistory.map(({ outcome }) => outcome),
    ["corrected", "clean"],
  );
  assert.deepEqual(
    state.history.map(({ outcome }) => outcome),
    ["findings", "clean"],
  );
  assert.equal(state.acceptedBatches.length, 1);
  assert.equal(state.acceptedBatches[0].batch.version, 2);
  assert.deepEqual(state.acceptedBatches[0].batch.dispositions, decisions);
  assert.equal(
    state.ledger.find(({ finding }) => finding.id === "corrected").version,
    2,
  );
  assert.deepEqual(
    f.calls.map(({ session }) => session),
    Array(3).fill({ mode: "fork", id: "source-session" }),
  );
  assert.deepEqual(
    result.sessionLineage.children.slice(-3).map(({ role }) => role),
    ["reviewer", "reviewer", "auditor"],
  );
  assert.notEqual(
    state.recheckHistory[0].contextKey,
    state.recheckHistory[1].contextKey,
  );
  const evidence = JSON.parse(f.calls[2].prompt.split("\n").at(-1));
  assert.deepEqual(evidence.acceptedDispositions[0].dispositions, decisions);
});

test("lazy rechecks continue the discovering Auditor and acceptance alone cannot clean discovery", async () => {
  const saved = await pendingRun(undefined, {
    mode: "lazy",
    source: "source-session",
  });
  const reject = decision("negative-count", {
    kind: "reject",
    rationale: "The caller validates before allocation",
  });
  const f = fixture(
    [(request) => recheck(request, { decisions: [reject] }), recheck],
    { saved },
  );
  f.stopAt("DISCOVER");
  await assert.rejects(f.execute(), /gate response loss/u);
  const state = f.run().pipelineState;
  assert.equal(state.pendingBatch, null);
  assert.equal(state.workflowState, "DISCOVER");
  assert.equal(state.history[0].outcome, "findings");
  assert.equal(state.report.findings.length, 0);
  assert.deepEqual(
    f.calls.map(({ session }) => session),
    Array(2).fill({ mode: "continue", id: "child-1" }),
  );
  assert.ok(
    f.run().sessionLineage.children.every(({ role }) => role === "auditor"),
  );
  const resumed = fixture([complete({ candidates: [finding()] }), complete()], {
    saved: f.run(),
  });
  const result = await resumed.execute();
  assert.equal(result.pipelineState.recheckHistory.length, 2);
  assert.deepEqual(
    result.pipelineState.history.map(({ outcome }) => outcome),
    ["findings", "findings", "clean"],
  );
  assert.equal(
    result.pipelineState.acceptedBatches[0].batch.dispositions[0].kind,
    "reject",
  );
});

test("review additions and later reversals require verification and retain rejected decisions", async () => {
  const added = finding({ id: "other-count", causeId: "other-parser" });
  const reject = decision("negative-count", {
    kind: "reject",
    rationale: "A range check appears to protect this caller",
  });
  const saved = await pendingRun();
  const f = fixture(
    [
      (request) =>
        recheck(request, { decisions: [reject], additions: [added] }),
      (request) =>
        recheck(request, {
          decisions: [decision("negative-count"), decision(added.id)],
        }),
      recheck,
    ],
    { saved },
  );
  f.stopAt("DISCOVER");
  await assert.rejects(f.execute(), /gate response loss/u);
  const state = f.run().pipelineState;
  assert.deepEqual(
    state.recheckHistory.map(({ outcome }) => outcome),
    ["corrected", "corrected", "clean"],
  );
  assert.equal(state.acceptedBatches[0].batch.entries.length, 2);
  assert.equal(state.acceptedBatches[0].batch.version, 3);
  assert.equal(state.recheckHistory[0].dispositions[0].kind, "reject");
  assert.equal(state.recheckHistory[1].dispositions[0].kind, "confirm");
  assert.match(
    f.calls[1].prompt,
    /A range check appears to protect this caller/u,
  );
});

test("a material discovery revision invalidates the old version's acceptance", async () => {
  const saved = await pendingRun();
  const first = fixture([recheck], { saved });
  first.stopAt("DISCOVER");
  await assert.rejects(first.execute(), /gate response loss/u);
  const revision = finding({
    impact: "The operation exits before returning any result",
  });
  const next = fixture([complete({ candidates: [revision] })], {
    saved: first.run(),
  });
  next.stopAt("VERIFY_FINDINGS");
  await assert.rejects(next.execute(), /gate response loss/u);
  const state = next.run().pipelineState;
  assert.equal(state.ledger[0].version, 2);
  assert.equal(state.pendingBatch.entries[0].version, 2);
  assert.equal(state.acceptedBatches[0].batch.entries[0].version, 1);
  const forged = structuredClone(next.run());
  forged.pipelineState.pendingBatch = null;
  forged.pipelineState.workflowState = "DISCOVER";
  assert.throws(() => auditPipeline.workflow.validateRun(forged));
});

test("merging into an accepted finding brings its target back into distinct verification", async () => {
  const saved = await pendingRun();
  const first = fixture([recheck], { saved });
  first.stopAt("DISCOVER");
  await assert.rejects(first.execute(), /gate response loss/u);
  const duplicate = finding({ id: "same-failure", causeId: "same-parse-path" });
  const f = fixture(
    [
      complete({ candidates: [duplicate] }),
      (request) =>
        recheck(request, {
          decisions: [
            decision(duplicate.id, {
              kind: "merge",
              targetId: "negative-count",
              rationale:
                "The retained finding already covers this exact failure and location",
            }),
          ],
        }),
      recheck,
    ],
    { saved: first.run() },
  );
  f.stopAt("DISCOVER");
  await assert.rejects(f.execute(), /gate response loss/u);
  const state = f.run().pipelineState;
  assert.deepEqual(
    state.recheckHistory.map(({ outcome }) => outcome),
    ["clean", "corrected", "clean"],
  );
  assert.deepEqual(
    state.acceptedBatches[1].batch.entries.map(({ finding }) => finding.id),
    ["same-failure", "negative-count"],
  );
  assert.equal(state.history[1].outcome, "findings");
});

test("recheck drift, oversized output and unsettled ownership never publish acceptance", async () => {
  const saved = await pendingRun();
  for (const mutate of ["drift", "inputDrift"]) {
    const f = fixture(
      [
        (request) => {
          f[mutate]();
          return recheck(request);
        },
      ],
      { saved },
    );
    const result = await f.execute();
    assert.equal(
      result.pause.reason,
      mutate === "drift" ? "workspace_changed" : "input_changed",
    );
    assert.equal(result.pipelineState.acceptedBatches.length, 0);
    assert.deepEqual(
      result.pipelineState.pendingBatch,
      saved.pipelineState.pendingBatch,
    );
    await f.execute();
    assert.equal(f.calls.length, 1);
  }
  const oversized = fixture(
    [
      (request) =>
        recheck(request, {
          decisions: [
            decision("negative-count", {
              rationale: "x".repeat(2 * 1024 * 1024),
            }),
          ],
        }),
    ],
    { saved },
  );
  const rejected = await oversized.execute();
  assert.equal(rejected.pause.reason, "invalid_recheck");
  assert.equal(rejected.pipelineState.recheckHistory[0].outcome, "invalid");
  assert.equal(rejected.pipelineState.acceptedBatches.length, 0);
  const cause = Object.assign(new Error("Unsettled ownership"), {
    code: "ERR_EXECUTION_RESOURCE_UNVERIFIABLE",
  });
  const retained = fixture([cause], { saved });
  await assert.rejects(retained.execute(), (error) => error === cause);
  assert.deepEqual(retained.run().activeTurn, {
    role: "reviewer",
    phase: "recheck",
  });
  assert.equal(
    retained.run().pipelineState.recheckHistory[0].outcome,
    "running",
  );
});

test("stale, malformed, incomplete and invalid merge responses cannot accept a batch", async () => {
  const saved = await pendingRun();
  for (const patch of [
    { snapshotFingerprint: "f".repeat(64) },
    { reportFingerprint: "f".repeat(64) },
    { batchFingerprint: "f".repeat(64) },
    { decisions: [] },
    { decisions: [null] },
    { unsupported: true },
    {
      decisions: [
        decision("negative-count", {
          kind: "merge",
          targetId: "missing-target",
        }),
      ],
    },
    {
      decisions: [
        decision("negative-count", {
          kind: "correct",
          finding: finding({ id: "renamed" }),
        }),
      ],
    },
    { status: "INCOMPLETE" },
  ]) {
    const f = fixture([(request) => recheck(request, patch)], { saved });
    const result = await f.execute();
    assert.equal(
      result.pause.reason,
      patch.status === "INCOMPLETE" ? "recheck_incomplete" : "invalid_recheck",
    );
    assert.equal(result.pipelineState.acceptedBatches.length, 0);
    assert.deepEqual(
      result.pipelineState.pendingBatch,
      saved.pipelineState.pendingBatch,
    );
    assert.equal(result.pipelineState.history[0].outcome, "findings");
  }
});

test("checkpoint feedback retains pending dispositions and obeys lazy and independent recheck ownership", async () => {
  for (const mode of ["lazy", "independent"]) {
    const saved = await pendingRun(undefined, {
      mode,
      source: "source-session",
    });
    const f = fixture(
      [
        (request) =>
          recheck(request, {
            decisions: [
              decision("negative-count", {
                kind: "reject",
                rationale: "The caller already enforces the required range",
              }),
            ],
          }),
        (request) => recheck(request, { batchFingerprint: "f".repeat(64) }),
      ],
      { saved },
    );
    const waiting = await f.execute();
    const feedback = waiting.pipelineState.correctionFeedback;
    assert.equal(feedback.phase, "recheck");
    assert.equal(feedback.number, 2);
    assert.deepEqual(feedback.diagnostics, [
      { field: "recheck.batchFingerprint", code: "binding-mismatch" },
    ]);
    assert.equal(waiting.pipelineState.acceptedBatches.length, 0);
    assert.equal(
      waiting.pipelineState.pendingBatch.dispositions[0].kind,
      "reject",
    );
    const resumed = fixture([recheck], {
      saved: JSON.parse(JSON.stringify(waiting)),
    });
    resumed.stopAt("DISCOVER");
    await assert.rejects(resumed.execute(), /gate response loss/u);
    const result = resumed.run();
    const evidence = JSON.parse(resumed.calls[0].prompt.split("\n").at(-1));
    assert.deepEqual(evidence.correctionFeedback, feedback);
    assert.deepEqual(
      evidence.priorDecisions,
      waiting.pipelineState.recheckHistory.slice(0, 1),
    );
    assert.deepEqual(
      result.pipelineState.recheckHistory.map(({ outcome }) => outcome),
      ["corrected", "invalid", "clean"],
    );
    assert.deepEqual(
      result.pipelineState.recheckHistory.slice(0, 2),
      waiting.pipelineState.recheckHistory,
    );
    assert.deepEqual(
      result.pipelineState.acceptedBatches[0].batch,
      waiting.pipelineState.pendingBatch,
    );
    assert.equal(result.pipelineState.correctionFeedback, null);
    assert.deepEqual(
      resumed.calls[0].session,
      mode === "lazy"
        ? {
            mode: "continue",
            id: waiting.sessionLineage.children.at(-1).sessionId,
          }
        : { mode: "fork", id: "source-session" },
    );

    const legacy = structuredClone(result);
    delete legacy.pipelineState.correctionFeedback;
    const migrated = auditPipeline.migrations[5](legacy);
    assert.deepEqual(migrated, {
      ...legacy.pipelineState,
      correctionFeedback: null,
    });
    assert.doesNotThrow(() =>
      auditPipeline.workflow.validateRun({
        ...legacy,
        pipelineState: migrated,
      }),
    );
  }
});

test("terminal recheck failures preserve a valid failed run without replaying verification", async () => {
  const saved = await pendingRun();
  const cause = Object.assign(new Error("Synthetic provider safety failure"), {
    code: "ERR_AUDIT_SYNTHETIC_SAFETY",
  });
  const f = fixture([cause], { saved });
  await assert.rejects(f.execute(), (error) => error === cause);
  const failed = f.run();
  assert.equal(failed.pipelineState.workflowState, "FAILED");
  assert.equal(failed.activeTurn, null);
  assert.equal(failed.pause.code, cause.code);
  assert.equal(failed.pipelineState.recheckHistory[0].outcome, "interrupted");
  assert.deepEqual(
    failed.pipelineState.pendingBatch,
    saved.pipelineState.pendingBatch,
  );
  assert.equal(failed.pipelineState.acceptedBatches.length, 0);
  assert.doesNotThrow(() => auditPipeline.workflow.validateRun(failed));
  const resumed = fixture([], { saved: failed });
  assert.equal((await resumed.execute()).pipelineState.workflowState, "FAILED");
  assert.equal(resumed.calls.length, 0);
});

test("interruption consumes a recheck reservation and saved acceptance never replays", async () => {
  const saved = await pendingRun();
  const interrupted = fixture([], { saved });
  interrupted.stopAfterReservation();
  await assert.rejects(interrupted.execute(), /persistence response loss/u);
  assert.equal(
    interrupted.run().pipelineState.recheckHistory[0].outcome,
    "running",
  );
  const resumed = fixture([recheck], { saved: interrupted.run() });
  resumed.stopAt("DISCOVER");
  await assert.rejects(resumed.execute(), /gate response loss/u);
  assert.deepEqual(
    resumed.run().pipelineState.recheckHistory.map(({ outcome }) => outcome),
    ["interrupted", "clean"],
  );
  const accepted = fixture([complete()], { saved: resumed.run() });
  const result = await accepted.execute();
  assert.equal(accepted.calls.length, 1);
  assert.equal(result.pipelineState.recheckHistory.length, 2);
  for (const mutate of [
    (state) => {
      state.acceptedBatches[0].batch.entries[0].version += 1;
    },
    (state) => {
      state.acceptedBatches[0].batch.reportFingerprint = "f".repeat(64);
    },
    (state) => {
      state.recheckHistory[1].outcome = "invalid";
    },
    (state) => {
      state.recheckHistory[1].contextKey = "f".repeat(64);
    },
  ]) {
    const altered = structuredClone(result);
    mutate(altered.pipelineState);
    assert.throws(() => auditPipeline.workflow.validateRun(altered));
  }
});

test("the finite recheck budget is run-wide across accepted batches and reconstruction", async () => {
  const saved = await pendingRun();
  const outputs = [
    recheck,
    complete({
      candidates: [finding({ impact: "A revised impact needs review" })],
    }),
    ...Array.from(
      { length: MAX_FINDING_RECHECK_PASSES - 1 },
      (_, index) => (request) =>
        recheck(request, {
          decisions: [
            decision("negative-count", {
              kind: "reject",
              rationale: `Caller evidence revision ${index + 1}`,
            }),
          ],
        }),
    ),
  ];
  const f = fixture(outputs, { saved });
  const result = await f.execute();
  assert.equal(result.pause.reason, "finding_recheck_limit_reached");
  assert.equal(result.pipelineState.recheckHistory.length, 20);
  assert.equal(result.pipelineState.history.length, 2);
  assert.equal(result.pipelineState.acceptedBatches.length, 1);
  assert.ok(result.pipelineState.pendingBatch);
  const resumed = fixture([], { saved: result });
  assert.equal(
    (await resumed.execute()).pause.reason,
    "finding_recheck_limit_reached",
  );
  assert.equal(resumed.calls.length, 0);
  assert.throws(() =>
    createAuditState({ settings: { maxFindingRecheckPasses: 21 } }),
  );
});

test("auditor-only version-1 snapshots preserve roles and pause before independent verification", async () => {
  for (const mode of ["independent", "lazy"]) {
    const legacy = await pendingRun(undefined, {
      mode,
      source: "source-session",
    });
    // Version 1 declared only the Auditor, including in independent mode.
    delete legacy.roles.reviewer;
    delete legacy.pipelineState.recheckHistory;
    delete legacy.pipelineState.acceptedBatches;
    delete legacy.pipelineState.settings.maxFindingRecheckPasses;
    delete legacy.pipelineState.pendingBatch.version;
    delete legacy.pipelineState.pendingBatch.dispositions;
    delete legacy.pipelineState.sourceForkContexts;
    const roles = structuredClone(legacy.roles);
    const version2 = auditPipeline.migrations[1](legacy);
    const migrated = auditPipeline.migrations[2]({
      ...legacy,
      pipelineState: version2,
    });
    assert.equal(migrated.settings.maxFindingRecheckPasses, 20);
    assert.deepEqual(migrated.recheckHistory, []);
    assert.deepEqual(migrated.acceptedBatches, []);
    assert.deepEqual(migrated.sourceForkContexts, []);
    assert.deepEqual(migrated.history, legacy.pipelineState.history);
    assert.equal(migrated.history[0].outcome, "findings");
    const saved = { ...legacy, pipelineState: migrated };
    assert.doesNotThrow(() => auditPipeline.workflow.validateRun(saved));
    const f = fixture(mode === "lazy" ? [recheck, complete()] : [], { saved });
    delete f.runtime.adapters.reviewer;
    const result = await f.execute();
    assert.deepEqual(result.roles, roles);
    if (mode === "independent") {
      assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(result.pause.reason, "audit_reviewer_required");
      assert.equal(result.pause.resumeState, "VERIFY_FINDINGS");
      assert.deepEqual(
        result.pipelineState.pendingBatch,
        migrated.pendingBatch,
      );
      assert.deepEqual(result.pipelineState.recheckHistory, []);
      assert.deepEqual(result.pipelineState.acceptedBatches, []);
      assert.equal(result.activeTurn, null);
      assert.equal((await f.execute()).pause.reason, "audit_reviewer_required");
      assert.equal(f.calls.length, 0);
    } else {
      assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
      assert.equal(result.pipelineState.acceptedBatches.length, 1);
      assert.ok(
        f.calls.every(
          ({ session }) =>
            session.mode === "continue" && session.id === "child-1",
        ),
      );
    }
  }
  assert.deepEqual(auditPipeline.resolveActiveRoles({ mode: "lazy" }), [
    "auditor",
  ]);
  assert.deepEqual(auditPipeline.resolveActiveRoles(), ["auditor", "reviewer"]);
});
