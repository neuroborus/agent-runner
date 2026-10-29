import assert from "node:assert/strict";
import test from "node:test";

import {
  auditPipeline,
  createAuditState,
  MAX_DISCOVERY_PASSES,
  runAuditDiscovery,
} from "../src/index.js";

const HASH = "a".repeat(64);
const INPUTS = {
  scope: ["Inspect the complete workspace"],
  references: ["docs/limits.md"],
  exclusions: ["Generated artifacts"],
  criteria: ["Counts must be nonnegative"],
};
const READY = { status: "READY", inputs: INPUTS, questions: [], reason: "" };
const complete = (patch = {}) => ({
  status: "COMPLETE",
  snapshotFingerprint: HASH,
  candidates: [],
  limitations: [],
  hypotheses: [],
  reportCorrections: [],
  ...patch,
});
const finding = (patch = {}) => ({
  id: "negative-count",
  causeId: "unchecked-count",
  title: "Negative counts reach allocation",
  severity: "Medium",
  category: "Correctness",
  locations: ["src/count.js:8"],
  evidence: ["parseCount returns negative integers without a range check"],
  impact: "The requested operation aborts during allocation",
  severityRationale: "Only invalid explicit counts trigger this failure",
  examples: [
    {
      kind: "behavioral",
      basis: "code-derived",
      conditions: "Count is -1",
      action: "Parse the count and allocate",
      expected: "Reject before allocation",
      actual: "Allocation receives -1",
    },
  ],
  ...patch,
});

// Lightweight root capabilities: no providers, Git, filesystem or clock effects.
function fixture(
  outputs = [],
  {
    mode = "independent",
    source = null,
    saved,
    context = null,
    clarificationContent = "",
  } = {},
) {
  let current = saved
    ? structuredClone(saved)
    : {
        pipelineId: "audit",
        runId: "synthetic-run",
        projectPath: "/workspace/project",
        taskPath: "/state/task",
        roles: { auditor: {} },
        hashes: {},
        pause: null,
        activeTurn: null,
        sessionLineage: { source, children: [] },
        pipelineState: createAuditState({ settings: { mode } }),
      };
  let sequence = current.sessionLineage.children.length;
  let transcriptHash = current.hashes.clarifications ?? "c".repeat(64);
  let taskHash = current.hashes.task ?? "b".repeat(64);
  let changed = false;
  let stopAfterReservation = false;
  let stopAfterAcceptance = false;
  const calls = [];
  const events = [];
  const runtime = {
    transition: async (patch) => {
      current = { ...current, ...structuredClone(patch) };
      events.push({
        type: "persist",
        stage: current.pipelineState.workflowState,
        passes: current.pipelineState.history.length,
      });
      if (
        stopAfterReservation &&
        current.pipelineState.history.at(-1)?.outcome === "running"
      ) {
        stopAfterReservation = false;
        throw new Error("Simulated persistence response loss");
      }
      if (
        stopAfterAcceptance &&
        current.pipelineState.workflowState === "DISCOVERY_CLEAN"
      ) {
        stopAfterAcceptance = false;
        throw new Error("Simulated acceptance response loss");
      }
      return current;
    },
    workspace: {
      snapshot: async () => ({ contentFingerprint: HASH }),
      assertUnchanged: async () => {
        if (changed) throw new Error("Workspace changed");
      },
    },
    readInputs: async () => ({
      task: { content: "Audit the project", hash: taskHash },
      context,
    }),
    clarifications: {
      ensureTranscript: async () => ({
        content: clarificationContent,
        hash: transcriptHash,
      }),
      inspectTranscript: async () => ({
        content: clarificationContent,
        hash: transcriptHash,
      }),
      freezeTranscript: async ({ expectedHash }) => {
        assert.equal(expectedHash, transcriptHash);
        events.push({ type: "freeze" });
        return { hash: transcriptHash };
      },
      appendQuestionRound: async () => {
        transcriptHash = "d".repeat(64);
        return { hash: transcriptHash };
      },
      prepareEdit: async (request) => {
        const authorization = {
          id: "edit-one",
          action: request.action,
          suspendedState: request.suspendedState,
          preEditorHash: transcriptHash,
        };
        await request.persistPendingEdit(authorization);
        events.push({ type: "editor-authorized" });
        return authorization;
      },
      acceptEdit: async (authorization, { consumePendingEdit }) =>
        consumePendingEdit({
          authorizationId: authorization.id,
          hash: transcriptHash,
          changed: false,
        }),
    },
    startAgentTurn: async (activeTurn, { pipelineState }) => {
      current = { ...current, activeTurn, pipelineState };
      events.push({ type: "turn-start", passes: pipelineState.history.length });
      return current;
    },
    finishAgentTurn: async () => (current = { ...current, activeTurn: null }),
    recordChildSession: async (child) => {
      current = {
        ...current,
        sessionLineage: {
          ...current.sessionLineage,
          children: [...current.sessionLineage.children, child],
        },
      };
      return current;
    },
    adapters: {
      auditor: {
        run: async (request) => {
          calls.push(request);
          assert.equal(request.access, "read-only");
          assert.equal(request.cwd, "/workspace/project");
          assert.ok(outputs.length > 0, "Unexpected Auditor invocation");
          let output = outputs.shift();
          if (typeof output === "function") output = await output(request);
          if (output instanceof Error) throw output;
          return {
            structured: output,
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : `child-${++sequence}`,
          };
        },
      },
    },
  };
  return {
    calls,
    events,
    runtime,
    run: () => current,
    execute: () => runAuditDiscovery({ run: current, runtime }),
    drift: () => {
      changed = true;
    },
    inputDrift: () => {
      taskHash = "e".repeat(64);
    },
    stopAfterReservation: () => {
      stopAfterReservation = true;
    },
    stopAfterAcceptance: () => {
      stopAfterAcceptance = true;
    },
  };
}

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

test("new candidates are deduplicated into a durable pending batch that blocks discovery", async () => {
  const f = fixture([READY, complete({ candidates: [finding(), finding()] })]);
  const result = await f.execute();
  const state = result.pipelineState;
  assert.equal(state.workflowState, "VERIFY_FINDINGS");
  assert.equal(state.ledger.length, 1);
  assert.equal(state.ledger[0].version, 1);
  assert.equal(state.pendingBatch.entries.length, 1);
  assert.equal(state.pendingBatch.reportFingerprint, state.reportFingerprint);
  assert.equal(state.pendingBatch.snapshotFingerprint, HASH);
  assert.deepEqual(state.report.findings, []);
  assert.deepEqual(state.history[0].candidateIds, ["negative-count"]);
  const resumed = fixture([], { saved: result });
  assert.equal(
    (await resumed.execute()).pipelineState.workflowState,
    "VERIFY_FINDINGS",
  );
  assert.equal(resumed.calls.length, 0);
});

test("unchanged and revised ledger findings preserve discovery cleanliness and stable identities", async () => {
  const recorded = finding({
    recommendation: "Reject negative counts before allocation",
  });
  const f = fixture([READY, complete({ candidates: [recorded] })]);
  const pending = await f.execute();
  // A later verification owner may release a batch; it cannot rewrite discovery history.
  pending.pipelineState.pendingBatch = null;
  pending.pipelineState.workflowState = "DISCOVER";
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
  const result = await revised.execute();
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
  await assert.rejects(fixture([], { mode: "combined" }).execute(), {
    code: "ERR_AUDIT_MODE_UNAVAILABLE",
  });
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
  assert.equal(waiting.pipelineState.pendingEdit.id, "edit-one");
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
  const resumed = fixture([READY, complete()], { saved: waiting });
  const result = await resumed.execute();
  assert.equal(result.pipelineState.clarificationRounds, 1);
  assert.equal(result.pipelineState.pendingEdit, null);
  assert.equal(result.pipelineState.clarificationHash, "d".repeat(64));
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
  const f = fixture([READY, complete({ candidates: [finding()] })]);
  const result = await f.execute();
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
