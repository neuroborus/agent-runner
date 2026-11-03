import assert from "node:assert/strict";
import test from "node:test";
import {
  attachAuthentication,
  authenticationFailure,
} from "../../../test/support/authentication.js";

import {
  auditPipeline,
  createAuditState,
  MAX_DISCOVERY_PASSES,
  runAuditDiscovery,
} from "../src/index.js";

import {
  HASH,
  INPUTS,
  READY,
  complete,
  finding,
  fixture,
  pendingRun,
  recheck,
} from "./support/index.js";

test("independent discovery freezes full scope and starts a fresh Auditor for each pass", async () => {
  const corrected = { limitations: ["Live checks unavailable"] };
  const context = { content: "Assess the count parser", hash: "f".repeat(64) };
  const clarificationContent = "Include unchanged sources";
  const f = fixture([READY, complete(corrected), complete(corrected)], {
    source: "opaque-source",
    context,
    clarificationContent,
  });
  const result = await f.execute();
  const state = result.pipelineState;
  assert.equal(state.workflowState, "DISCOVERY_CLEAN");
  assert.deepEqual(
    state.history.map(({ outcome }) => outcome),
    ["report-correction", "clean"],
  );
  assert.equal(state.report.findings.length, 0);
  assert.deepEqual(state.inputs, INPUTS);
  assert.ok(
    f.events.findIndex(({ type }) => type === "freeze") <
      f.events.findIndex(
        ({ type, passes }) => type === "turn-start" && passes === 1,
      ),
  );
  assert.deepEqual(
    f.calls.map(({ session }) => session),
    Array(3).fill({ mode: "fork", id: "opaque-source" }),
  );
  assert.equal(
    new Set(result.sessionLineage.children.map(({ sessionId }) => sessionId))
      .size,
    3,
  );
  assert.match(f.calls[2].prompt, /Live checks unavailable/u);
  const evidence = JSON.parse(f.calls[2].prompt.split("\n").at(-1));
  assert.equal(evidence.task, "Audit the project");
  assert.equal(evidence.context, context.content);
  assert.equal(evidence.clarifications, clarificationContent);
  assert.doesNotMatch(f.calls[2].prompt, /preceding conversations/u);
  assert.equal(
    (await f.execute()).pipelineState.workflowState,
    "DISCOVERY_CLEAN",
  );
  assert.equal(f.calls.length, 3);
});

test("lazy retains one logical Auditor and its consumed source fork after child loss", async () => {
  const f = fixture(
    [
      READY,
      Object.assign(new Error("private provider payload"), {
        recoverable: true,
      }),
    ],
    { mode: "lazy", source: "opaque-source" },
  );
  await f.execute();
  assert.equal(f.run().pipelineState.sourceForkConsumed, true);
  assert.deepEqual(
    f.calls.map(({ session }) => session),
    [
      { mode: "fork", id: "opaque-source" },
      { mode: "continue", id: "child-1" },
    ],
  );
  const saved = structuredClone(f.run());
  // Loss of a disposable child never renews the logical role's consumed source fork.
  saved.sessionLineage.children = [];
  const resumed = fixture([complete()], { saved });
  const result = await resumed.execute();
  assert.equal(resumed.calls[0].session, undefined);
  assert.deepEqual(
    result.pipelineState.history.map(({ outcome }) => outcome),
    ["clean"],
  );
  assert.doesNotMatch(JSON.stringify(result), /private provider payload/u);
});

test("an acknowledged Audit child survives interruption without another source fork or owner cycle", async () => {
  for (const cause of [
    Object.assign(new Error("controlled post-creation interruption"), {
      recoverable: true,
      launchRecovery: { checkpoint: "spawn" },
    }),
    authenticationFailure({ effect: "none" }),
  ]) {
    const f = fixture(
      [
        async (request) => {
          await request.onSessionCreated("early-child");
          throw cause;
        },
      ],
      { mode: "lazy", source: "opaque-source" },
    );
    attachAuthentication(f);
    await f.execute();
    const saved = structuredClone(f.run());
    assert.equal(saved.sessionLineage.children[0].sessionId, "early-child");
    assert.equal(saved.pipelineState.sourceForkConsumed, true);
    const later = fixture([READY, complete()], { saved });
    const result = await later.execute();
    assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
    assert.ok(
      later.calls.every(
        (request) =>
          request.session.mode === "continue" &&
          request.session.id === "early-child",
      ),
    );
    assert.equal(result.sessionLineage.children.length, 1);
    assert.equal(result.pipelineState.history.length, 1);
  }
});

test("new candidates are deduplicated into a durable pending batch that blocks discovery", async () => {
  const result = await pendingRun([finding(), finding()]);
  const state = result.pipelineState;
  assert.equal(state.workflowState, "VERIFY_FINDINGS");
  assert.equal(state.ledger.length, 1);
  assert.equal(state.ledger[0].version, 1);
  assert.equal(state.pendingBatch.entries.length, 1);
  assert.equal(state.pendingBatch.reportFingerprint, state.reportFingerprint);
  assert.equal(state.pendingBatch.snapshotFingerprint, HASH);
  assert.deepEqual(state.report.findings, []);
  assert.deepEqual(state.history[0].candidateIds, ["negative-count"]);
  const resumed = fixture([recheck, complete()], { saved: result });
  const accepted = await resumed.execute();
  assert.equal(accepted.pipelineState.acceptedBatches.length, 1);
  assert.equal(accepted.pipelineState.history[0].outcome, "findings");
  assert.equal(resumed.calls.length, 2);
});

test("unchanged and revised ledger findings preserve discovery cleanliness and stable identities", async () => {
  const recorded = finding({
    recommendation: "Reject negative counts before allocation",
  });
  const saved = await pendingRun([recorded]);
  const verified = fixture([recheck], { saved });
  verified.stopAt("DISCOVER");
  await assert.rejects(verified.execute(), /gate response loss/u);
  const pending = verified.run();
  const duplicate = fixture(
    [complete({ candidates: [recorded] }), complete()],
    { saved: pending },
  );
  const clean = await duplicate.execute();
  const evidence = JSON.parse(duplicate.calls[0].prompt.split("\n").at(-1));
  assert.equal(duplicate.calls[0].session, undefined);
  assert.deepEqual(evidence.accumulatedFindings, [{ ...recorded, version: 1 }]);
  assert.deepEqual(
    clean.pipelineState.history.map(({ outcome }) => outcome),
    ["findings", "findings", "clean"],
  );
  assert.equal(clean.pipelineState.ledger[0].version, 1);
  const revised = fixture(
    [
      complete({
        candidates: [
          {
            ...recorded,
            impact: "The operation exits before returning its result",
          },
        ],
      }),
    ],
    { saved: pending },
  );
  revised.stopAt("VERIFY_FINDINGS");
  await assert.rejects(revised.execute(), /gate response loss/u);
  const result = revised.run();
  assert.equal(result.pipelineState.workflowState, "VERIFY_FINDINGS");
  assert.equal(result.pipelineState.ledger[0].version, 2);
  assert.equal(result.pipelineState.ledger[0].finding.id, "negative-count");
  assert.equal(result.pipelineState.history[0].outcome, "findings");
});

test("malformed and incomplete passes never become clean evidence on reload", async (t) => {
  for (const [outcome, output] of [
    ["invalid", { ...complete(), unsupported: true }],
    ["invalid", complete({ snapshotFingerprint: "f".repeat(64) })],
    [
      "invalid",
      complete({ candidates: [finding(), finding({ id: "other-id" })] }),
    ],
    ["incomplete", complete({ status: "INCOMPLETE", candidates: [finding()] })],
  ])
    await t.test(
      `${outcome}: ${typeof output.status === "string" ? output.status : "failure"}`,
      async () => {
        const f = fixture([READY, output]);
        const stopped = await f.execute();
        assert.equal(stopped.pipelineState.workflowState, "WAITING_FOR_USER");
        assert.equal(stopped.pipelineState.history[0].outcome, outcome);
        assert.equal(stopped.pipelineState.ledger.length, 0);
        const resumed = fixture([complete()], { saved: stopped });
        const result = await resumed.execute();
        assert.equal(result.pipelineState.history.length, 2);
        assert.equal(result.pipelineState.history[0].outcome, outcome);
        assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
      },
    );
});

test("oversized clarification and discovery results cannot enter durable audit content", async () => {
  const oversized = "é".repeat(1024 * 1024);
  const clarification = fixture([
    { ...READY, inputs: { ...INPUTS, scope: [oversized] } },
  ]);
  const scopeResult = await clarification.execute();
  assert.equal(scopeResult.pause.reason, "invalid_discovery");
  assert.equal(scopeResult.pipelineState.inputs, null);
  assert.equal(scopeResult.pipelineState.history.length, 0);
  assert.equal(clarification.calls.length, 1);

  const discovery = fixture([READY, complete({ limitations: [oversized] })]);
  const result = await discovery.execute();
  assert.equal(result.pause.reason, "invalid_discovery");
  assert.equal(result.pipelineState.history[0].outcome, "invalid");
  assert.deepEqual(result.pipelineState.report.limitations, []);
  assert.equal(discovery.calls.length, 2);
});

test("unsettled execution ownership propagates without retiring or reclassifying the turn", async () => {
  for (const code of [
    "ERR_EXECUTION_PROCESS_ACTIVE",
    "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    "ERR_EXECUTION_RESOURCE_UNVERIFIABLE",
  ]) {
    const cause = Object.assign(
      new Error("Execution ownership remains unresolved"),
      { code },
    );
    const f = fixture([READY, cause]);
    await assert.rejects(f.execute(), (error) => error === cause);
    assert.equal(f.run().pipelineState.workflowState, "DISCOVER");
    assert.equal(f.run().pipelineState.history[0].outcome, "running");
    assert.deepEqual(f.run().activeTurn, {
      role: "auditor",
      phase: "discovery",
    });
  }
});

test("workspace or input mutation rejects clean output and remains blocking", async () => {
  for (const mutate of ["drift", "inputDrift"]) {
    const f = fixture([
      READY,
      () => {
        f[mutate]();
        return complete();
      },
    ]);
    const result = await f.execute();
    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.notEqual(result.pipelineState.history[0].outcome, "clean");
    assert.equal(
      result.pause.reason,
      mutate === "drift" ? "workspace_changed" : "input_changed",
    );
    await f.execute();
    assert.equal(f.calls.length, 2);
  }
});

test("write-ahead recovery charges an interrupted reservation and never replays saved acceptance", async () => {
  const f = fixture([READY]);
  f.stopAfterReservation();
  await assert.rejects(f.execute(), /persistence response loss/u);
  const resumed = fixture([complete()], { saved: f.run() });
  const result = await resumed.execute();
  assert.deepEqual(
    result.pipelineState.history.map(({ outcome }) => outcome),
    ["interrupted", "clean"],
  );
  assert.equal(resumed.calls.length, 1);
  const accepted = fixture([READY, complete()]);
  accepted.stopAfterAcceptance();
  await assert.rejects(accepted.execute(), /acceptance response loss/u);
  const settled = fixture([], { saved: accepted.run() });
  assert.equal(
    (await settled.execute()).pipelineState.workflowState,
    "DISCOVERY_CLEAN",
  );
  assert.equal(settled.calls.length, 0);
});

test("run-wide exhaustion survives reconstruction and cannot be renewed by mode or settings", async () => {
  const f = fixture([
    READY,
    ...Array.from({ length: MAX_DISCOVERY_PASSES }, () =>
      complete({
        reportCorrections: ["A substantive report correction remains"],
      }),
    ),
  ]);
  const exhausted = await f.execute();
  assert.equal(exhausted.pause.reason, "discovery_limit_reached");
  assert.equal(exhausted.pipelineState.history.length, 20);
  const resumed = fixture([], { saved: exhausted });
  assert.equal(
    (await resumed.execute()).pause.reason,
    "discovery_limit_reached",
  );
  assert.equal(resumed.calls.length, 0);
  assert.throws(() =>
    createAuditState({ settings: { maxDiscoveryPasses: 21 } }),
  );
  assert.equal(createAuditState().settings.mode, "independent");
});

test("clarification edits persist authorization before waiting and empty closes consume no extra round", async () => {
  const questions = [
    {
      question: "Which source tree is in scope?",
      whyItMatters: "Scope changes the inspected material",
    },
  ];
  const f = fixture([
    { status: "QUESTIONS", inputs: null, questions, reason: "" },
  ]);
  const waiting = await f.execute();
  assert.equal(waiting.pipelineState.clarificationRounds, 1);
  assert.equal(waiting.pipelineState.pendingEdit.id, "edit-1");
  assert.equal(
    waiting.pause.inputRequest.id,
    waiting.pipelineState.pendingEdit.id,
  );
  assert.deepEqual(
    waiting.pause.inputRequest.questions.map(({ id }) => id),
    ["q1"],
  );
  assert.equal(f.events.at(-1).type, "editor-authorized");
  assert.equal(f.events.at(-2).stage, "WAITING_FOR_USER");
  const stopped = await runAuditDiscovery({
    run: waiting,
    runtime: f.runtime,
    operatorStop: true,
  });
  assert.deepEqual(
    stopped.pipelineState.pendingEdit,
    waiting.pipelineState.pendingEdit,
  );
  assert.equal(stopped.pipelineState.clarificationRounds, 1);
  const changed = fixture([], { saved: waiting });
  changed.inputDrift();
  const blocked = await changed.execute();
  assert.equal(blocked.pause.reason, "input_changed");
  assert.deepEqual(
    blocked.pipelineState.pendingEdit,
    waiting.pipelineState.pendingEdit,
  );
  const unanswered = fixture([], { saved: waiting });
  const stillWaiting = await unanswered.execute();
  assert.equal(stillWaiting.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(stillWaiting.pipelineState.clarificationRounds, 1);
  assert.notEqual(
    stillWaiting.pipelineState.pendingEdit.id,
    waiting.pipelineState.pendingEdit.id,
  );
  assert.equal(unanswered.calls.length, 0);
  const resumed = fixture([READY, complete()], { saved: waiting });
  resumed.editTranscript();
  const result = await resumed.execute();
  assert.equal(result.pipelineState.clarificationRounds, 1);
  assert.equal(result.pipelineState.pendingEdit, null);
  assert.equal(result.pipelineState.clarificationHash, "f".repeat(64));
  const atLimit = structuredClone(waiting);
  atLimit.pipelineState = {
    ...atLimit.pipelineState,
    workflowState: "CLARIFY",
    pendingEdit: null,
    clarificationRounds: 3,
  };
  atLimit.pause = null;
  const limited = fixture(
    [{ status: "QUESTIONS", inputs: null, questions, reason: "" }],
    { saved: atLimit },
  );
  assert.equal(
    (await limited.execute()).pause.reason,
    "clarification_limit_reached",
  );
  assert.equal(limited.run().pipelineState.clarificationRounds, 3);
});

test("proactive clarification waits before the first turn and accepts an unchanged optional close", async () => {
  const f = fixture([READY, complete()], { proactiveClarification: true });
  const waiting = await f.execute();
  assert.equal(waiting.pause.reason, "proactive_clarification");
  assert.deepEqual(waiting.pause.inputRequest.questions, []);
  assert.equal(waiting.pipelineState.proactiveClarificationComplete, false);
  assert.equal(f.calls.length, 0);
  const result = await f.execute();
  assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
  assert.equal(result.pipelineState.proactiveClarification, true);
  assert.equal(result.pipelineState.proactiveClarificationComplete, true);
  assert.equal(result.pipelineState.clarificationRounds, 0);
  assert.equal(result.pipelineState.pendingEdit, null);
});

test("scope blockers retain a bounded explanation and resume clarification without consuming questions", async () => {
  const f = fixture([
    {
      status: "BLOCKED",
      inputs: null,
      questions: [],
      reason: "The requested source tree is unavailable",
    },
  ]);
  const waiting = await f.execute();
  assert.equal(waiting.pause.reason, "audit_scope_blocked");
  assert.equal(
    waiting.pause.explanation,
    "The requested source tree is unavailable",
  );
  assert.equal(waiting.pipelineState.clarificationRounds, 0);
  assert.equal(waiting.pipelineState.inputs, null);
  const resumed = fixture([READY, complete()], { saved: waiting });
  assert.equal(
    (await resumed.execute()).pipelineState.workflowState,
    "DISCOVERY_CLEAN",
  );
});

test("persisted bindings reject substituted reports, inputs, batch provenance and clean history", async () => {
  const result = await pendingRun();
  for (const mutate of [
    (state) => {
      state.report.scope = ["Another scope"];
    },
    (state) => {
      state.inputs.references = ["another-reference.md"];
    },
    (state) => {
      state.pendingBatch.sourcePass = 0;
    },
    (state) => {
      state.history[0].outcome = "clean";
    },
    (state) => {
      state.history[0].contextKey = "another-role";
    },
  ]) {
    const altered = structuredClone(result);
    mutate(altered.pipelineState);
    assert.throws(() => auditPipeline.workflow.validateRun(altered));
  }
});
