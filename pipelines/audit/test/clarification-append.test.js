import assert from "node:assert/strict";
import test from "node:test";

import { auditPipeline, runAuditDiscovery } from "../src/index.js";
import { fixture } from "./support/index.js";

const QUESTIONS = {
  status: "QUESTIONS",
  inputs: null,
  questions: [
    {
      question: " Which  scope? ",
      whyItMatters: " Scope  determines coverage. ",
    },
  ],
  reason: "",
};
const PRIOR = "c".repeat(64);
const RESULT = "d".repeat(64);

async function interruptedAppend(boundary, mode = "independent") {
  const f = fixture([structuredClone(QUESTIONS)], { mode });
  const append = f.runtime.clarifications.appendQuestionRound;
  const transition = f.runtime.transition;
  if (boundary === "intent") {
    f.runtime.transition = async (patch) => {
      const saved = await transition(patch);
      if (saved.pipelineState.pendingClarificationAppend !== null)
        throw new Error("Lost intent receipt");
      return saved;
    };
  } else if (boundary === "replacement") {
    f.runtime.clarifications.appendQuestionRound = async (request) => {
      await append(request);
      throw new Error("Lost append readback");
    };
  } else {
    f.runtime.transition = async (patch) => {
      if (patch.pipelineState.pendingEdit !== null) {
        if (boundary === "publication") await transition(patch);
        throw new Error("Lost edit publication");
      }
      return transition(patch);
    };
  }
  await assert.rejects(f.execute(), /Lost /u);
  return f;
}

test("journaled questions recover without another role turn or duplicate round at every append boundary", async () => {
  for (const [boundary, mode] of [
    ["intent", "independent"],
    ["replacement", "lazy"],
    ["before-publication", "combined"],
    ["publication", "independent"],
  ]) {
    const first = await interruptedAppend(boundary, mode);
    const saved = JSON.parse(JSON.stringify(first.run()));
    const hash = boundary === "intent" ? PRIOR : RESULT;
    const pending = saved.pipelineState.pendingClarificationAppend;
    if (boundary !== "publication") {
      assert.deepEqual(pending.questions, [
        {
          question: "Which scope?",
          whyItMatters: "Scope determines coverage.",
        },
      ]);
      assert.equal(pending.expectedHash, PRIOR);
      assert.equal(pending.resultHash, RESULT);
      assert.equal(saved.pipelineState.clarificationRounds, 0);
      assert.equal(saved.pipelineState.pendingEdit, null);
    }
    const resumed = fixture([], { saved, transcriptHash: hash });
    const waiting = await resumed.execute();
    assert.equal(waiting.pause.reason, "clarification_answers_required");
    assert.equal(waiting.pipelineState.pendingClarificationAppend, null);
    assert.equal(waiting.pipelineState.clarificationRounds, 1);
    assert.equal(waiting.hashes.clarifications, RESULT);
    assert.equal(waiting.pipelineState.pendingEdit.preEditorHash, RESULT);
    assert.deepEqual(waiting.sessionLineage, saved.sessionLineage);
    assert.deepEqual(
      waiting.pipelineState.settings,
      saved.pipelineState.settings,
    );
    assert.equal(
      waiting.pause.inputRequest.questions[0].question,
      "Which scope?",
    );
    const repeated = fixture([], {
      saved: JSON.parse(JSON.stringify(waiting)),
    });
    const stillWaiting = await repeated.execute();
    assert.equal(stillWaiting.pipelineState.clarificationRounds, 1);
    assert.equal(stillWaiting.pipelineState.pendingClarificationAppend, null);
    assert.deepEqual(
      stillWaiting.pause.inputRequest.questions,
      waiting.pause.inputRequest.questions,
    );
    assert.equal(resumed.calls.length + repeated.calls.length, 0);
    assert.equal(
      resumed.events.filter(({ type }) => type === "append").length,
      boundary === "intent" ? 1 : 0,
    );
  }
});

test("failed initial intent publication leaves transcript bytes untouched", async () => {
  const f = fixture([QUESTIONS]);
  const transition = f.runtime.transition;
  f.runtime.transition = async (patch) => {
    if (patch.pipelineState.pendingClarificationAppend !== null)
      throw new Error("Intent not published");
    return transition(patch);
  };
  await assert.rejects(f.execute(), /Intent not published/u);
  assert.equal(
    (await f.runtime.clarifications.inspectTranscript()).hash,
    PRIOR,
  );
  assert.equal(f.run().pipelineState.pendingClarificationAppend, null);
  assert.equal(
    f.events.some(({ type }) => type === "append"),
    false,
  );
});

test("pending append rejects third-party bytes and protected input or workspace drift before replay", async () => {
  const first = await interruptedAppend("intent");
  for (const drift of ["editTranscript", "inputDrift", "drift"]) {
    const resumed = fixture([], { saved: first.run() });
    resumed[drift]();
    const result = await resumed.execute();
    assert.equal(
      result.pause.reason,
      drift === "drift" ? "workspace_changed" : "input_changed",
    );
    assert.deepEqual(
      result.pipelineState.pendingClarificationAppend,
      first.run().pipelineState.pendingClarificationAppend,
    );
    assert.equal(result.pipelineState.pendingEdit, null);
    assert.equal(result.pipelineState.clarificationRounds, 0);
    assert.equal(
      resumed.events.some(({ type }) =>
        ["append", "editor-authorized"].includes(type),
      ),
      false,
    );
    assert.throws(() => auditPipeline.validateResumeAction(result, null));
  }
});

test("operator stop only verifies prior or exact result proof and retains intent through repeated inspection", async () => {
  const first = await interruptedAppend("replacement");
  for (const hash of [PRIOR, RESULT]) {
    const stopped = fixture([], { saved: first.run(), transcriptHash: hash });
    for (let index = 0; index < 2; index += 1) {
      const result = await runAuditDiscovery({
        run: stopped.run(),
        runtime: stopped.runtime,
        operatorStop: true,
      });
      assert.deepEqual(result, first.run());
    }
    assert.equal(stopped.events.length, 0);
    assert.equal(stopped.calls.length, 0);
  }
});

test("operator stop cannot replace a rejected append's frozen-input blocker with resumable read recovery", async () => {
  const first = await interruptedAppend("intent");
  const changed = fixture([], { saved: first.run() });
  changed.editTranscript();
  const blocked = await changed.execute();
  assert.equal(blocked.pause.reason, "input_changed");
  const stopped = fixture([], { saved: blocked });
  stopped.runtime.clarifications.inspectTranscript = async () => {
    throw Object.assign(new Error("Transcript temporarily unreadable"), {
      code: "ERR_CLARIFICATION_READ",
    });
  };
  const result = await runAuditDiscovery({
    run: stopped.run(),
    runtime: stopped.runtime,
    operatorStop: true,
  });
  assert.deepEqual(result, blocked);
  assert.throws(() => auditPipeline.validateResumeAction(result, null));
  assert.equal(stopped.calls.length, 0);
  assert.equal(stopped.events.length, 0);
});

test("unsafe or malformed transcript replacement blocks append recovery without consuming intent", async () => {
  const first = await interruptedAppend("intent");
  for (const [boundary, code] of [
    ["inspectTranscript", "ERR_INVALID_CLARIFICATION"],
    ["appendQuestionRound", "ERR_UNSAFE_CLARIFICATION_PATH"],
    ["prepareEdit", "ERR_CLARIFICATION_NOT_FOUND"],
    ["prepareEdit", "ERR_CLARIFICATIONS_CHANGED"],
  ]) {
    const resumed = fixture([], {
      saved: first.run(),
      transcriptHash: boundary === "prepareEdit" ? RESULT : PRIOR,
    });
    resumed.runtime.clarifications[boundary] = async () => {
      throw Object.assign(new Error("Invalid transcript"), { code });
    };
    const result = await resumed.execute();
    assert.equal(result.pause.reason, "input_changed");
    assert.deepEqual(
      result.pipelineState.pendingClarificationAppend,
      first.run().pipelineState.pendingClarificationAppend,
    );
    assert.equal(result.pipelineState.clarificationRounds, 0);
    assert.equal(result.pipelineState.pendingEdit, null);
    assert.equal(
      resumed.events.some(({ type }) =>
        ["append", "editor-authorized"].includes(type),
      ),
      false,
    );
    assert.equal(resumed.calls.length, 0);
    assert.throws(() => auditPipeline.validateResumeAction(result, null));
  }
});

test("append read/write interruption has bounded resumable diagnostics without retiring intent", async () => {
  const first = await interruptedAppend("intent");
  const resumed = fixture([], { saved: first.run() });
  resumed.runtime.clarifications.appendQuestionRound = async () => {
    throw Object.assign(new Error("Private filesystem detail"), {
      code: "ERR_CLARIFICATION_WRITE",
    });
  };
  const paused = await resumed.execute();
  const projection = auditPipeline.projections.pause(paused);
  assert.equal(projection.reason, "clarification_append_interrupted");
  assert.deepEqual(projection.nextActions, [{ type: "resume", action: null }]);
  assert.equal(
    JSON.stringify(projection).includes("Private filesystem detail"),
    false,
  );
  assert.deepEqual(
    paused.pipelineState.pendingClarificationAppend,
    first.run().pipelineState.pendingClarificationAppend,
  );
  const unreadable = fixture([], { saved: paused });
  unreadable.runtime.clarifications.inspectTranscript = async () => {
    throw Object.assign(new Error("Private read detail"), {
      code: "ERR_CLARIFICATION_READ",
    });
  };
  const readPaused = await unreadable.execute();
  assert.equal(readPaused.pause.reason, "clarification_append_interrupted");
  assert.deepEqual(
    readPaused.pipelineState.pendingClarificationAppend,
    paused.pipelineState.pendingClarificationAppend,
  );
  assert.equal(
    unreadable.events.some(({ type }) => type === "append"),
    false,
  );
  const unpublished = fixture([], {
    saved: first.run(),
    transcriptHash: RESULT,
  });
  unpublished.runtime.clarifications.prepareEdit = async () => {
    throw Object.assign(new Error("Private publication read detail"), {
      code: "ERR_CLARIFICATION_READ",
    });
  };
  const publicationPaused = await unpublished.execute();
  assert.equal(
    publicationPaused.pause.reason,
    "clarification_append_interrupted",
  );
  assert.deepEqual(
    publicationPaused.pipelineState.pendingClarificationAppend,
    first.run().pipelineState.pendingClarificationAppend,
  );
  assert.equal(publicationPaused.pipelineState.pendingEdit, null);
  assert.equal(publicationPaused.pipelineState.clarificationRounds, 0);
  assert.equal(
    unpublished.events.some(({ type }) =>
      ["append", "editor-authorized"].includes(type),
    ),
    false,
  );
  const recovered = fixture([], {
    saved: publicationPaused,
    transcriptHash: RESULT,
  });
  assert.equal(
    (await recovered.execute()).pipelineState.clarificationRounds,
    1,
  );
  assert.equal(unpublished.calls.length + recovered.calls.length, 0);
});

test("pending append validation is closed and checkpoint-bound; legacy absence grants no intent", async () => {
  const first = await interruptedAppend("intent");
  for (const mutate of [
    (run) => {
      run.pipelineState.pendingClarificationAppend.extra = true;
    },
    (run) => {
      run.pipelineState.pendingClarificationAppend.kind = "product-decision";
    },
    (run) => {
      run.pipelineState.pendingClarificationAppend.round += 1;
    },
    (run) => {
      run.pipelineState.pendingClarificationAppend.expectedHash = RESULT;
    },
    (run) => {
      run.pipelineState.pendingClarificationAppend.resultHash = "invalid";
    },
    (run) => {
      run.pipelineState.pendingClarificationAppend.questions[0].question =
        " Which scope?";
    },
    (run) => {
      run.pipelineState.pendingClarificationAppend.checkpoint.workflowState =
        "DISCOVER";
    },
    (run) => {
      run.pipelineState.pendingClarificationAppend.checkpoint.contextKey =
        PRIOR;
    },
    (run) => {
      run.pipelineState.pendingClarificationAppend.checkpoint.snapshotFingerprint =
        PRIOR;
    },
    (run) => {
      run.pipelineState.pendingClarificationAppend.checkpoint.settlementFingerprint =
        PRIOR;
    },
    (run) => {
      run.pipelineState.clarificationRounds = 3;
    },
    (run) => {
      run.pipelineState.pendingEdit = {};
    },
    (run) => {
      run.sessionLineage.children = [];
    },
  ]) {
    const invalid = structuredClone(first.run());
    mutate(invalid);
    assert.throws(() => auditPipeline.workflow.validateRun(invalid));
  }
  const legacy = structuredClone(first.run());
  delete legacy.pipelineState.pendingClarificationAppend;
  assert.throws(() => auditPipeline.workflow.validateRun(legacy));
  const migrated = auditPipeline.migrations[9](legacy);
  assert.throws(() => auditPipeline.migrations[9](first.run()));
  assert.deepEqual(migrated, {
    ...legacy.pipelineState,
    pendingClarificationAppend: null,
  });
  assert.doesNotThrow(() =>
    auditPipeline.workflow.validateRun({ ...legacy, pipelineState: migrated }),
  );
});
