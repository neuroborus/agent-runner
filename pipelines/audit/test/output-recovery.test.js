import assert from "node:assert/strict";
import test from "node:test";

import {
  attachOutputExhaustion,
  outputExhaustion,
} from "../../../test/support/output-exhaustion.js";
import { auditPipeline } from "../src/index.js";
import { publicationContent } from "../src/publication-contract.js";
import {
  READY,
  complete,
  decision,
  finding,
  fixture,
  pendingRun,
  recheck,
} from "./support/index.js";

const reload = (run) => JSON.parse(JSON.stringify(run));
const evidence = (request) => JSON.parse(request.prompt.split("\n").at(-1));
const confirmed = (run) =>
  auditPipeline.projections.status(run).auditReport.confirmedFindings;

test("explicit exhaustion recovery replaces the child without replacing the combined reservation or owner", async () => {
  const f = fixture([READY, outputExhaustion()], {
    mode: "combined",
    source: "source-session",
  });
  attachOutputExhaustion(f);
  const waiting = await f.execute();
  // The failed request continued the clarification child. Resuming it used to
  // select this same child and repeat the identical discovery request.
  assert.deepEqual(f.calls[1].session, { mode: "continue", id: "child-1" });
  assert.equal(waiting.pause.reason, "output_exhausted");
  assert.equal(waiting.activeTurn, null);
  assert.equal(waiting.pipelineState.history[0].outcome, "running");
  assert.deepEqual(waiting.pipelineState.outputRecovery, {
    phase: "discovery",
    number: 1,
    contextKey: waiting.pipelineState.history[0].contextKey,
    retiredChildren: 1,
  });
  const before = publicationContent(waiting.pipelineState);
  const unlaunched = fixture([], { saved: reload(waiting) });
  const transition = unlaunched.runtime.transition;
  unlaunched.runtime.transition = async (patch) => {
    const next = await transition(patch);
    if (patch.pause === null)
      throw new Error("Lost pause-clear acknowledgement");
    return next;
  };
  await assert.rejects(unlaunched.execute(), /pause-clear acknowledgement/u);
  assert.equal(unlaunched.calls.length, 0);
  const saved = reload(unlaunched.run());
  assert.equal(saved.pause, null);
  assert.deepEqual(
    saved.pipelineState.outputRecovery,
    waiting.pipelineState.outputRecovery,
  );
  assert.deepEqual(publicationContent(saved.pipelineState), before);
  const resumed = fixture([complete(), complete()], { saved });
  const result = await resumed.execute();
  assert.equal(resumed.calls[0].session, undefined);
  assert.notEqual(resumed.calls[0].prompt, f.calls[1].prompt);
  const request = evidence(resumed.calls[0]);
  const original = evidence(f.calls[1]);
  for (const field of Object.keys(original))
    assert.deepEqual(request[field], original[field]);
  assert.deepEqual(
    request.outputRecovery.discoveryHistory,
    saved.pipelineState.history,
  );
  assert.deepEqual(result.hashes, waiting.hashes);
  assert.deepEqual(result.pipelineState.inputs, waiting.pipelineState.inputs);
  assert.deepEqual(
    result.pipelineState.settings,
    waiting.pipelineState.settings,
  );
  assert.equal(result.pipelineState.history.length, 2);
  assert.equal(
    result.pipelineState.history[0].contextKey,
    waiting.pipelineState.history[0].contextKey,
  );
  assert.notEqual(
    result.pipelineState.history[1].contextKey,
    waiting.pipelineState.history[0].contextKey,
  );
  assert.deepEqual(resumed.calls[1].session, {
    mode: "fork",
    id: "source-session",
  });
  assert.equal(result.pipelineState.sourceForkContexts.length, 2);
  assert.equal(result.pipelineState.outputRecovery, null);
});

test("pending verification survives exhaustion and reload until the complete selected gate accepts exact versions", async () => {
  const saved = await pendingRun([finding()], {
    mode: "combined",
    source: "source-session",
  });
  const f = fixture([outputExhaustion()], { saved });
  attachOutputExhaustion(f);
  const waiting = await f.execute();
  const batch = reload(waiting.pipelineState.pendingBatch);
  assert.equal(confirmed(waiting), 0);
  const recovered = fixture(
    [
      recheck,
      (request) => {
        assert.equal(confirmed(recovered.run()), 0);
        assert.deepEqual(
          recovered.run().pipelineState.pendingBatch.entries,
          batch.entries,
        );
        return recheck(request, { decisions: [] });
      },
    ],
    { saved: reload(waiting) },
  );
  const invalid = await recovered.execute();
  assert.equal(recovered.calls[0].session, undefined);
  const request = evidence(recovered.calls[0]);
  assert.deepEqual(request.batch, batch);
  assert.deepEqual(request.accumulatedFindings, waiting.pipelineState.ledger);
  assert.deepEqual(
    request.outputRecovery.recheckHistory,
    waiting.pipelineState.recheckHistory,
  );
  assert.equal(invalid.pause.reason, "invalid_recheck");
  assert.equal(confirmed(invalid), 0);
  assert.deepEqual(invalid.pipelineState.acceptedBatches, []);
  const unfinished = fixture(
    [(request) => recheck(request, { status: "INCOMPLETE" })],
    { saved: reload(invalid) },
  );
  const incomplete = await unfinished.execute();
  assert.equal(incomplete.pause.reason, "recheck_incomplete");
  assert.equal(confirmed(incomplete), 0);
  assert.deepEqual(
    incomplete.pipelineState.pendingBatch,
    invalid.pipelineState.pendingBatch,
  );
  const accepted = fixture(
    [
      recheck,
      (request) => {
        // The correcting Reviewer's later clean pass is still insufficient.
        assert.equal(confirmed(accepted.run()), 0);
        return recheck(request);
      },
      complete(),
      complete(),
    ],
    { saved: reload(incomplete) },
  );
  const result = await accepted.execute();
  assert.equal(confirmed(result), 1);
  assert.equal(result.pipelineState.pendingBatch, null);
  assert.equal(result.pipelineState.acceptedBatches.length, 1);
  assert.deepEqual(
    result.pipelineState.acceptedBatches[0].batch.entries,
    batch.entries,
  );
  assert.deepEqual(
    result.pipelineState.recheckHistory.map(({ outcome }) => outcome),
    ["clean", "invalid", "incomplete", "clean", "clean"],
  );
  assert.equal(result.pipelineState.acceptedBatches[0].recheckPass, 5);
  assert.equal(result.pipelineState.history[0].outcome, "findings");
});

test("lazy clarification retains an acknowledged replacement after response loss and never reforks its source", async () => {
  const f = fixture(
    [
      async (request) => {
        await request.onSessionCreated("retired-child");
        throw outputExhaustion();
      },
    ],
    { mode: "lazy", source: "source-session" },
  );
  attachOutputExhaustion(f);
  const waiting = await f.execute();
  const replacement = fixture(
    [
      async (request) => {
        assert.equal(request.session, undefined);
        await request.onSessionCreated("replacement-child");
        throw Object.assign(new Error("Controlled response loss"), {
          recoverable: true,
        });
      },
    ],
    { saved: reload(waiting) },
  );
  const lost = await replacement.execute();
  assert.equal(lost.pause.reason, "backend_unavailable");
  assert.deepEqual(
    lost.pipelineState.outputRecovery,
    waiting.pipelineState.outputRecovery,
  );
  assert.equal(lost.sessionLineage.children.length, 2);
  const resumed = fixture([READY, complete()], { saved: reload(lost) });
  const result = await resumed.execute();
  assert.ok(
    resumed.calls.every(
      ({ session }) =>
        session.mode === "continue" && session.id === "replacement-child",
    ),
  );
  assert.equal(result.pipelineState.sourceForkConsumed, true);
  assert.equal(result.pipelineState.history.length, 1);
  assert.equal(result.pipelineState.clarificationRounds, 0);
  assert.equal(result.pipelineState.outputRecovery, null);
});

test("repeated exhaustion advances retirement and requires another explicit resume of the same reservation", async () => {
  const f = fixture([READY, outputExhaustion()], { mode: "lazy" });
  attachOutputExhaustion(f);
  const waiting = await f.execute();
  const repeated = fixture(
    [
      async (request) => {
        assert.equal(request.session, undefined);
        await request.onSessionCreated("second-exhausted-child");
        throw outputExhaustion();
      },
    ],
    { saved: reload(waiting) },
  );
  attachOutputExhaustion(repeated);
  const paused = await repeated.execute();
  assert.equal(repeated.calls.length, 1);
  assert.equal(paused.pause.reason, "output_exhausted");
  assert.equal(paused.pipelineState.outputRecovery.retiredChildren, 2);
  assert.deepEqual(paused.pipelineState.history, waiting.pipelineState.history);
  const resumed = fixture([complete()], { saved: reload(paused) });
  const result = await resumed.execute();
  assert.equal(resumed.calls[0].session, undefined);
  assert.equal(result.pipelineState.history.length, 1);
  assert.equal(result.pipelineState.outputRecovery, null);
});

test("a retired identity cannot return a result or become selectable after invalid-result correction", async () => {
  const f = fixture([READY, outputExhaustion()], { mode: "lazy" });
  attachOutputExhaustion(f);
  const waiting = await f.execute();
  const invalid = fixture([complete()], { saved: reload(waiting) });
  const run = invalid.runtime.adapters.auditor.run;
  invalid.runtime.adapters.auditor.run = async (request) => ({
    ...(await run(request)),
    sessionId: waiting.sessionLineage.children[0].sessionId,
  });
  const rejected = await invalid.execute();
  assert.equal(rejected.pause.reason, "invalid_discovery");
  assert.equal(rejected.pipelineState.history[0].outcome, "invalid");
  assert.deepEqual(
    rejected.pipelineState.outputRecovery,
    waiting.pipelineState.outputRecovery,
  );
  const resumed = fixture([complete()], { saved: reload(rejected) });
  const result = await resumed.execute();
  assert.equal(resumed.calls[0].session, undefined);
  assert.equal(result.pipelineState.history.length, 2);
  assert.deepEqual(
    evidence(resumed.calls[0]).correctionFeedback,
    rejected.pipelineState.correctionFeedback,
  );
  assert.equal(result.pipelineState.outputRecovery, null);
});

test("legacy exhaustion migration preserves bindings, report bytes, dispositions and old-version invalidation", async () => {
  const dismissed = finding({ id: "dismissed", causeId: "checked-caller" });
  const uncertain = finding({ id: "uncertain", causeId: "unknown-caller" });
  const rejected = decision(dismissed.id, {
    kind: "reject",
    rationale: "The caller enforces the precondition",
  });
  const hypothesis = decision(uncertain.id, {
    kind: "hypothesis",
    hypothesis: {
      id: uncertain.id,
      title: uncertain.title,
      evidence: [],
      uncertainty: "The caller's input range is unknown",
    },
  });
  const f = fixture([
    READY,
    complete({ candidates: [finding(), dismissed, uncertain] }),
    (request) =>
      recheck(request, {
        decisions: [decision(finding().id), rejected, hypothesis],
      }),
    recheck,
    complete({
      candidates: [
        finding({ impact: "Another caller aborts before allocation" }),
      ],
    }),
    outputExhaustion(),
  ]);
  attachOutputExhaustion(f);
  const waiting = await f.execute();
  assert.equal(confirmed(waiting), 0);
  assert.equal(waiting.pipelineState.ledger[0].version, 2);
  const legacy = reload(waiting);
  delete legacy.pipelineState.outputRecovery;
  const migrated = auditPipeline.migrations[7](legacy);
  assert.deepEqual(migrated, waiting.pipelineState);
  assert.doesNotThrow(() =>
    auditPipeline.workflow.validateRun({ ...legacy, pipelineState: migrated }),
  );
  assert.deepEqual(
    publicationContent(migrated),
    publicationContent(waiting.pipelineState),
  );
  const resumed = fixture(
    [
      (request) => {
        assert.equal(confirmed(resumed.run()), 0);
        assert.equal(request.session, undefined);
        const current = evidence(request);
        assert.deepEqual(
          current.outputRecovery.acceptedBatches[0].dispositions,
          [decision(finding().id), rejected, hypothesis],
        );
        assert.deepEqual(current.batch, migrated.pendingBatch);
        return recheck(request);
      },
      complete(),
    ],
    { saved: { ...legacy, pipelineState: migrated } },
  );
  const result = await resumed.execute();
  assert.equal(confirmed(result), 1);
  assert.equal(
    result.pipelineState.acceptedBatches.at(-1).batch.entries[0].version,
    2,
  );
  assert.match(
    publicationContent(result.pipelineState).content,
    /input range is unknown/u,
  );
  for (const mutate of [
    (run) => {
      run.pause.role = "auditor";
    },
    (run) => {
      run.pause.code = "ERR_OTHER";
    },
    (run) => {
      run.pause.checkpoint = "audit:recheck:read-only:99";
    },
    (run) => {
      run.pause.resumeState = "DISCOVER";
    },
    (run) => {
      run.pipelineState.recheckHistory.at(-1).outcome = "interrupted";
    },
  ]) {
    const invalid = reload(legacy);
    mutate(invalid);
    assert.throws(() => auditPipeline.migrations[7](invalid));
  }
  for (const mutate of [
    (state) => {
      state.outputRecovery = null;
    },
    (state) => {
      state.outputRecovery.number++;
    },
    (state) => {
      state.outputRecovery.contextKey = "b".repeat(64);
    },
    (state) => {
      state.outputRecovery.retiredChildren = -1;
    },
    (state) => {
      state.outputRecovery.retiredChildren++;
    },
    (state) => {
      state.outputRecovery.sessionId = "forbidden-native-id";
    },
  ]) {
    const invalid = reload(waiting);
    mutate(invalid.pipelineState);
    assert.throws(() => auditPipeline.workflow.validateRun(invalid));
  }
});

test("legacy absence outside an exhaustion pause creates no work or recovery allowance", async () => {
  const f = fixture([READY, complete()]);
  const completed = await f.executePublic();
  for (const state of [
    "DONE",
    "FAILED",
    "CANCELED",
    "DISCOVER",
    "WAITING_FOR_USER",
  ]) {
    const legacy = reload(completed);
    legacy.pipelineState.workflowState = state;
    legacy.pause =
      state === "WAITING_FOR_USER"
        ? { reason: "operator_paused", resumeState: "DISCOVER" }
        : null;
    delete legacy.pipelineState.outputRecovery;
    const migrated = auditPipeline.migrations[7](legacy);
    assert.equal(migrated.outputRecovery, null);
    const { outputRecovery, ...unchanged } = migrated;
    assert.deepEqual(unchanged, legacy.pipelineState);
    if (["DONE", "FAILED", "CANCELED"].includes(state)) {
      const inert = fixture([], {
        saved: { ...legacy, pipelineState: migrated },
      });
      assert.equal((await inert.execute()).pipelineState.workflowState, state);
      assert.equal(inert.calls.length, 0);
    }
  }
});
