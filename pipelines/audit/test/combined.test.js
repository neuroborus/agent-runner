import assert from "node:assert/strict";
import test from "node:test";

import { auditPipeline } from "../src/index.js";
import {
  READY,
  complete,
  decision,
  finding,
  fixture,
  pendingRun,
  recheck,
} from "./support/index.js";

const outcomes = (history) => history.map(({ outcome }) => outcome);

test("even initially clean combined discovery needs a fresh clean-first successor", async () => {
  const f = fixture([READY, complete(), complete()], {
    mode: "combined",
    source: "source-session",
  });
  f.stopAfterAcceptance();
  await assert.rejects(f.execute(), /acceptance response loss/u);
  const saved = f.run();
  assert.equal(saved.pipelineState.workflowState, "DISCOVERY_CLEAN");
  assert.deepEqual(outcomes(saved.pipelineState.history), ["clean", "clean"]);
  assert.deepEqual(
    f.calls.map(({ session }) => session),
    [
      { mode: "fork", id: "source-session" },
      { mode: "continue", id: "child-1" },
      { mode: "fork", id: "source-session" },
    ],
  );
  assert.deepEqual(
    saved.sessionLineage.children.map(({ role }) => role),
    ["auditor", "auditor"],
  );
  assert.equal(saved.pipelineState.sourceForkContexts.length, 2);
  const resumed = fixture([], { saved });
  assert.equal(
    (await resumed.execute()).pipelineState.workflowState,
    "DISCOVERY_CLEAN",
  );
  assert.equal(resumed.calls.length, 0);

  const forged = structuredClone(saved);
  forged.pipelineState.history.pop();
  assert.throws(() => auditPipeline.workflow.validateRun(forged));
});

test("finding-producing fresh Auditors finish their own series, including duplicates and report corrections", async () => {
  const report = { limitations: ["Runtime checks were unavailable"] };
  const rejected = decision("negative-count", {
    kind: "reject",
    rationale: "The caller checks the count before allocation",
  });
  const revised = finding({
    impact: "A separate caller still reaches allocation",
  });
  const f = fixture(
    [
      READY,
      complete({ candidates: [finding()] }),
      (request) => recheck(request, { decisions: [rejected] }),
      recheck,
      recheck,
      complete(),
      complete({ candidates: [finding()] }),
      complete(report),
      complete(report),
      complete({ ...report, candidates: [revised] }),
      recheck,
      recheck,
      complete(report),
      complete(report),
    ],
    { mode: "combined" },
  );
  const result = await f.execute();
  const state = result.pipelineState;
  assert.deepEqual(outcomes(state.history), [
    "findings",
    "clean",
    "findings",
    "report-correction",
    "clean",
    "findings",
    "clean",
    "clean",
  ]);
  const keys = state.history.map(({ contextKey }) => contextKey);
  assert.equal(keys[0], keys[1]);
  assert.equal(keys[2], keys[3]);
  assert.equal(keys[3], keys[4]);
  assert.equal(keys[5], keys[6]);
  assert.equal(new Set(keys).size, 4);
  assert.deepEqual(outcomes(state.recheckHistory), [
    "corrected",
    "clean",
    "clean",
    "clean",
    "clean",
  ]);
  assert.equal(state.acceptedBatches.length, 2);
  assert.deepEqual(state.acceptedBatches[0].batch.dispositions, [rejected]);
  assert.equal(state.acceptedBatches[1].batch.entries[0].version, 2);
  assert.equal(state.history[2].outcome, "findings");
  assert.equal(state.workflowState, "DISCOVERY_CLEAN");
});

test("correcting Reviewers retain exact versions across interruption before replacement and discovery resumes its owner", async () => {
  const saved = await pendingRun(undefined, {
    mode: "combined",
    source: "source-session",
  });
  const corrected = finding({ severity: "High" });
  const addition = finding({ id: "missing-limit", causeId: "unbounded-count" });
  const revisedAddition = {
    ...addition,
    impact: "An excessive count exhausts allocation",
  };
  const f = fixture(
    [
      recheck,
      (request) =>
        recheck(request, {
          decisions: [
            decision("negative-count", { kind: "correct", finding: corrected }),
          ],
          additions: [addition],
        }),
      (request) => {
        const output = recheck(request);
        output.decisions[1] = decision("missing-limit", {
          kind: "correct",
          finding: revisedAddition,
        });
        f.stopAfterReservation();
        return output;
      },
    ],
    { saved },
  );
  await assert.rejects(f.execute(), /persistence response loss/u);
  const pending = f.run();
  assert.equal(pending.pipelineState.pendingBatch.version, 3);
  const resumed = fixture([recheck, recheck, complete(), complete()], {
    saved: pending,
  });
  const result = await resumed.execute();
  const calls = [...f.calls, ...resumed.calls];
  const state = result.pipelineState;
  assert.deepEqual(outcomes(state.recheckHistory), [
    "clean",
    "corrected",
    "corrected",
    "interrupted",
    "clean",
    "clean",
  ]);
  assert.deepEqual(
    calls.map(({ session }) => session),
    [
      { mode: "continue", id: "child-1" },
      { mode: "fork", id: "source-session" },
      { mode: "continue", id: "child-2" },
      { mode: "continue", id: "child-2" },
      { mode: "fork", id: "source-session" },
      { mode: "continue", id: "child-1" },
      { mode: "fork", id: "source-session" },
    ],
  );
  assert.equal(
    state.recheckHistory[1].contextKey,
    state.recheckHistory[4].contextKey,
  );
  assert.notEqual(
    state.recheckHistory[4].contextKey,
    state.recheckHistory[5].contextKey,
  );
  const restoredBatch = JSON.parse(
    resumed.calls[0].prompt.split("\n").at(-1),
  ).batch;
  assert.deepEqual(restoredBatch, pending.pipelineState.pendingBatch);
  const receipt = state.acceptedBatches[0];
  assert.equal(receipt.recheckPass, 6);
  assert.equal(receipt.batch.version, 3);
  assert.deepEqual(
    receipt.batch.entries.map(({ version }) => version),
    [2, 2],
  );
  assert.deepEqual(outcomes(state.history), ["findings", "clean", "clean"]);
  const evidence = JSON.parse(calls[5].prompt.split("\n").at(-1));
  assert.deepEqual(
    evidence.acceptedDispositions[0].dispositions,
    receipt.batch.dispositions,
  );

  const forged = structuredClone(result);
  forged.pipelineState.acceptedBatches[0].recheckPass = 5;
  assert.throws(() => auditPipeline.workflow.validateRun(forged));
});

test("invalid or incomplete discovery cannot become a clean-first successor through reconstruction", async () => {
  for (const [outcome, output] of [
    ["invalid", complete({ unsupported: true })],
    ["incomplete", complete({ status: "INCOMPLETE" })],
  ]) {
    const f = fixture([READY, complete(), output], {
      mode: "combined",
      source: "source-session",
    });
    const saved = await f.execute();
    const key = saved.pipelineState.history[1].contextKey;
    // A lost native child changes neither the logical cycle nor its consumed fork.
    saved.sessionLineage.children = saved.sessionLineage.children.filter(
      (child) => child.contextKey !== key,
    );
    const resumed = fixture([complete(), complete()], { saved });
    const result = await resumed.execute();
    assert.deepEqual(outcomes(result.pipelineState.history), [
      "clean",
      outcome,
      "clean",
      "clean",
    ]);
    assert.equal(resumed.calls[0].session, undefined);
    assert.deepEqual(resumed.calls[1].session, {
      mode: "fork",
      id: "source-session",
    });
    assert.equal(result.pipelineState.history[2].contextKey, key);
    assert.notEqual(result.pipelineState.history[3].contextKey, key);
    assert.equal(result.pipelineState.sourceForkContexts.length, 3);
  }
});

test("invalid Reviewer output keeps verification pending until a later fresh clean-first review", async () => {
  const saved = await pendingRun(undefined, { mode: "combined" });
  const f = fixture(
    [
      recheck,
      (request) => recheck(request, { batchFingerprint: "f".repeat(64) }),
    ],
    { saved },
  );
  const invalid = await f.execute();
  assert.equal(invalid.pause.reason, "invalid_recheck");
  assert.equal(invalid.pipelineState.acceptedBatches.length, 0);
  const resumed = fixture([recheck, recheck], { saved: invalid });
  resumed.stopAt("DISCOVER");
  await assert.rejects(resumed.execute(), /gate response loss/u);
  const state = resumed.run().pipelineState;
  assert.deepEqual(outcomes(state.recheckHistory), [
    "clean",
    "invalid",
    "clean",
    "clean",
  ]);
  assert.equal(
    state.recheckHistory[1].contextKey,
    state.recheckHistory[2].contextKey,
  );
  assert.notEqual(
    state.recheckHistory[2].contextKey,
    state.recheckHistory[3].contextKey,
  );
  assert.equal(state.acceptedBatches[0].recheckPass, 4);
  assert.deepEqual(outcomes(state.history), ["findings"]);
  const stale = structuredClone(resumed.run());
  stale.pipelineState.pendingBatch = structuredClone(
    state.acceptedBatches[0].batch,
  );
  stale.pipelineState.workflowState = "VERIFY_FINDINGS";
  assert.throws(() => auditPipeline.workflow.validateRun(stale));
});

test("interrupted discovery and Reviewer reservations preserve cycle provenance across resume", async () => {
  const discovery = fixture(
    [
      READY,
      () => {
        discovery.stopAfterReservation();
        return complete();
      },
    ],
    { mode: "combined" },
  );
  await assert.rejects(discovery.execute(), /persistence response loss/u);
  const resumed = fixture([complete(), complete()], { saved: discovery.run() });
  const result = await resumed.execute();
  assert.deepEqual(outcomes(result.pipelineState.history), [
    "clean",
    "interrupted",
    "clean",
    "clean",
  ]);
  assert.equal(
    result.pipelineState.history[1].contextKey,
    result.pipelineState.history[2].contextKey,
  );

  const saved = await pendingRun(undefined, { mode: "combined" });
  const verification = fixture(
    [
      (request) => {
        verification.stopAfterReservation();
        return recheck(request);
      },
    ],
    { saved },
  );
  await assert.rejects(verification.execute(), /persistence response loss/u);
  const pending = verification.run();
  assert.deepEqual(outcomes(pending.pipelineState.recheckHistory), [
    "clean",
    "running",
  ]);
  const forged = structuredClone(pending);
  forged.pipelineState.recheckHistory.pop();
  forged.pipelineState.acceptedBatches.push({
    batch: forged.pipelineState.pendingBatch,
    recheckPass: 1,
  });
  forged.pipelineState.pendingBatch = null;
  forged.pipelineState.workflowState = "DISCOVER";
  assert.throws(() => auditPipeline.workflow.validateRun(forged));
  const reviewed = fixture([recheck, recheck], { saved: pending });
  reviewed.stopAt("DISCOVER");
  await assert.rejects(reviewed.execute(), /gate response loss/u);
  const state = reviewed.run().pipelineState;
  assert.deepEqual(outcomes(state.recheckHistory), [
    "clean",
    "interrupted",
    "clean",
    "clean",
  ]);
  assert.equal(state.acceptedBatches[0].recheckPass, 4);
  assert.equal(
    state.recheckHistory[1].contextKey,
    state.recheckHistory[2].contextKey,
  );
});

test("both twenty-pass budgets survive combined owner replacement, batches and exhausted resume", async () => {
  const f = fixture(
    [
      READY,
      complete(),
      ...Array.from({ length: 18 }, () =>
        complete({ reportCorrections: ["A substantive correction remains"] }),
      ),
      complete(),
    ],
    { mode: "combined" },
  );
  const exhausted = await f.execute();
  assert.equal(exhausted.pause.reason, "discovery_limit_reached");
  assert.equal(exhausted.pipelineState.history.length, 20);
  assert.equal(exhausted.pipelineState.history.at(-1).outcome, "clean");
  const resumed = fixture([], { saved: exhausted });
  assert.equal(
    (await resumed.execute()).pause.reason,
    "discovery_limit_reached",
  );
  assert.equal(resumed.calls.length, 0);

  const saved = await pendingRun(undefined, { mode: "combined" });
  const batches = fixture(
    [
      recheck,
      recheck,
      complete({ candidates: [finding({ severity: "High" })] }),
      recheck,
      ...Array.from(
        { length: 16 },
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
      recheck,
    ],
    { saved },
  );
  const stopped = await batches.execute();
  assert.equal(stopped.pause.reason, "finding_recheck_limit_reached");
  assert.equal(stopped.pipelineState.recheckHistory.length, 20);
  assert.equal(stopped.pipelineState.history.length, 2);
  assert.equal(stopped.pipelineState.acceptedBatches.length, 1);
  assert.equal(stopped.pipelineState.pendingBatch.version, 17);
  const retained = fixture([], { saved: stopped });
  assert.equal(
    (await retained.execute()).pause.reason,
    "finding_recheck_limit_reached",
  );
  assert.equal(retained.calls.length, 0);
  assert.deepEqual(retained.run().pipelineState, stopped.pipelineState);
});
