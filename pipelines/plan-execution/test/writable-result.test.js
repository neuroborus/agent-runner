import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { customExecutionFixture } from "../../../test/support/index.js";
import {
  attachAvailability,
  availabilityFailure,
} from "../../../test/support/availability.js";
import {
  attachOutputExhaustion,
  outputExhaustion,
} from "../../../test/support/output-exhaustion.js";
import { createClarificationService } from "../../../src/clarifications/index.js";
import { planExecutionPipeline, runPlanExecution } from "../src/index.js";
import { writableResultDiagnostic } from "../src/writable-result.js";
import {
  IMPLEMENTATION_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
} from "../src/schemas.js";
import {
  createFixture,
  implementationCompleted,
  finalizationPassed,
  finalizationFailed,
  resolution,
  reviewFindings,
  reviewApproved,
  checkAndFix,
  cleanConfirmation,
  implementationBlocked,
  implementationProductDecision,
  SOURCE_SESSION,
  stagnation,
} from "./support/index.js";

const malformed = () => ({
  ...implementationCompleted(),
  reason: "PRIVATE_REJECTED_VALUE",
});
const resultCalls = (fixture, schema = IMPLEMENTATION_SCHEMA) =>
  fixture.calls.worker.filter((request) => request.schema === schema);

for (const phase of ["IMPLEMENT", "RESOLVE_FINDINGS"]) {
  test(`${phase} registration failure reuses the unstarted reservation without a result correction`, async (t) => {
    const schema =
      phase === "IMPLEMENT" ? IMPLEMENTATION_SCHEMA : FINDING_RESOLUTION_SCHEMA;
    const fixture = await createFixture(t, {
      workWorker: [
        implementationCompleted(),
        ...(phase === "IMPLEMENT"
          ? []
          : [resolution({ id: "R1", decision: "FIX" })]),
        finalizationPassed(),
      ],
      workReviewer:
        phase === "IMPLEMENT"
          ? [reviewApproved()]
          : [reviewFindings("R1"), reviewApproved()],
      async onRoleRun(_role, request) {
        if (request.schema === FINDING_RESOLUTION_SCHEMA)
          await writeFile(join(request.cwd, "repair.txt"), "repaired\n");
      },
    });
    const start = fixture.runtime.startAgentTurn.bind(fixture.runtime);
    let failed = false;
    fixture.runtime.startAgentTurn = async (turn, options) => {
      if (!failed && turn.phase === phase.toLowerCase().replaceAll("_", "-")) {
        failed = true;
        throw new Error("Registration publication failed");
      }
      return start(turn, options);
    };
    await assert.rejects(fixture.run(), /Registration publication failed/u);
    const prepared = structuredClone(
      fixture.currentRun.pipelineState.writableResult,
    );
    assert.equal(prepared.stage, "prepared");
    assert.equal(prepared.attempts, 0);
    assert.equal(fixture.currentRun.activeTurn, null);
    assert.equal(resultCalls(fixture, schema).length, 0);
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.deepEqual(
      resultCalls(fixture, schema).map(({ access }) => access),
      ["workspace-write"],
    );
    assert.equal(done.counters.fixRounds, phase === "IMPLEMENT" ? 0 : 1);
    assert.equal(done.pipelineState.completedCommits.length, 1);
    assert.ok(
      fixture.transitions.some(
        ({ patch }) =>
          patch?.pipelineState.writableResult?.factsFingerprint ===
            prepared.factsFingerprint &&
          patch.pipelineState.writableResult.stage === "ready" &&
          patch.pipelineState.writableResult.attempts === 0,
      ),
    );
  });

  test(`${phase} legacy continuation binds its reconciled baseline and charges partial fixes once`, async (t) => {
    const schema =
      phase === "IMPLEMENT" ? IMPLEMENTATION_SCHEMA : FINDING_RESOLUTION_SCHEMA;
    let interrupted = false;
    const fixture = await createFixture(t, {
      modeSettings: { maxFixRoundsPerStep: 1 },
      workWorker: [
        implementationCompleted(),
        ...(phase === "IMPLEMENT"
          ? []
          : [resolution({ id: "R1", decision: "FIX" })]),
        finalizationPassed(),
      ],
      workReviewer:
        phase === "IMPLEMENT"
          ? [reviewApproved()]
          : [reviewFindings("R1"), reviewApproved()],
      async onRoleRun(_role, request) {
        if (request.schema !== schema) return;
        if (!interrupted) {
          interrupted = true;
          throw Object.assign(new Error("Legacy provider unavailable"), {
            recoverable: true,
          });
        }
        assert.equal(request.access, "workspace-write");
        await rm(join(request.cwd, "legacy-partial.txt"));
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "backend_unavailable");
    assert.equal(paused.pipelineState.writableResult, null);
    const original = structuredClone(paused.pipelineState.stepImplementation);
    await writeFile(
      join(fixture.projectPath, "legacy-partial.txt"),
      "owned legacy partial work\n",
    );
    Object.assign(fixture.currentRun, {
      activeTurn: {
        role: "worker",
        phase: phase.toLowerCase().replaceAll("_", "-"),
      },
      pause: null,
      pipelineState: { ...paused.pipelineState, workflowState: phase },
    });
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.equal(done.counters.fixRounds, phase === "IMPLEMENT" ? 0 : 1);
    assert.equal(done.pipelineState.completedCommits.length, 1);
    const checkpoint = fixture.transitions.find(
      ({ patch }) =>
        patch?.pipelineState.writableResult?.phase === phase &&
        patch.pipelineState.writableResult.originalContentFingerprint !==
          original.contentFingerprint,
    );
    assert.ok(checkpoint);
    assert.equal(
      checkpoint.patch.pipelineState.stepImplementation.contentFingerprint,
      original.contentFingerprint,
    );
    assert.equal(checkpoint.patch.pipelineState.writableResult.attempts, 0);
  });
}

test("repeated operator-stop reconciliation preserves the result checkpoint and original blocker", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [implementationCompleted(), finalizationFailed("F1")],
    async onRoleRun(_role, request) {
      if (request.schema === FINDING_RESOLUTION_SCHEMA) {
        await writeFile(join(request.cwd, "partial.txt"), "owned repair\n");
        throw Object.assign(new Error("Ownership unresolved"), {
          code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        });
      }
    },
  });
  await assert.rejects(fixture.run(), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
  const calls = fixture.calls.worker.length;
  const options = [];
  const reconcile = fixture.runtime.git.reconcileInterrupted.bind(
    fixture.runtime.git,
  );
  fixture.runtime.git.reconcileInterrupted = async (baseline, input) => {
    options.push(input);
    return reconcile(baseline, input);
  };
  const stopped = await runPlanExecution({
    run: fixture.currentRun,
    runtime: fixture.runtime,
    operatorStop: true,
  });
  const repeated = await runPlanExecution({
    run: stopped,
    runtime: fixture.runtime,
    operatorStop: true,
  });
  assert.equal(repeated.pipelineState.workflowState, "RESOLVE_FINDINGS");
  assert.equal(repeated.pipelineState.writableResult.stage, "ready");
  assert.equal(repeated.pipelineState.writableResult.blockers[0].id, "F1");
  assert.equal(repeated.pipelineState.finalizationResult.status, "FAIL");
  assert.equal(repeated.counters.fixRounds, 1);
  assert.equal(repeated.activeTurn, null);
  assert.equal(fixture.calls.worker.length, calls);
  assert.deepEqual(options, [
    { allowWorkspaceChanges: true, allowIndexChanges: false },
    { allowWorkspaceChanges: false, allowIndexChanges: false },
  ]);
});

for (const [phase, restatement, boundary] of [
  ["IMPLEMENT", false, "intent"],
  ["IMPLEMENT", true, "append-reserved"],
  ["IMPLEMENT", true, "appended"],
  ["RESOLVE_FINDINGS", false, "before-suspension"],
  ["RESOLVE_FINDINGS", true, "suspended"],
]) {
  test(`${phase} product decision survives ${boundary} interruption without writable replay`, async (t) => {
    const schema =
      phase === "IMPLEMENT" ? IMPLEMENTATION_SCHEMA : FINDING_RESOLUTION_SCHEMA;
    const product = implementationProductDecision();
    const { summary: _summary, ...decisionFields } = product;
    const reported =
      phase === "IMPLEMENT" ? product : { ...decisionFields, decisions: [] };
    const invalid =
      phase === "IMPLEMENT"
        ? malformed()
        : {
            ...resolution({ id: "R1", decision: "FIX" }),
            reason: "PRIVATE_REJECTED_VALUE",
          };
    const interruption = new Error("Decision settlement response interrupted");
    let stopped = false;
    const fixture = await createFixture(t, {
      workWorker: [
        ...(phase === "IMPLEMENT" ? [] : [implementationCompleted()]),
        ...(restatement ? [invalid] : []),
        reported,
      ],
      workReviewer: phase === "IMPLEMENT" ? [] : [reviewFindings("R1")],
      async onRoleRun(_role, request) {
        if (request.schema === schema && request.access === "workspace-write")
          await writeFile(
            join(request.cwd, "candidate.txt"),
            "preserved candidate\n",
          );
      },
      onTransition(run) {
        const pending = run.pipelineState.writableResult?.productDecision;
        const reached =
          boundary === "intent"
            ? pending?.resultHash === null
            : boundary === "append-reserved"
              ? pending?.resultHash != null
              : boundary === "suspended" &&
                run.pause?.reason === "product_decision_required";
        if (!stopped && reached) {
          stopped = true;
          throw interruption;
        }
      },
    });
    // The real confined service proves journaled append replay against actual
    // bytes; the remaining cases use its existing lightweight capability fixture.
    const clarifications =
      boundary === "appended"
        ? createClarificationService({ interactive: false })
        : fixture.runtime.clarifications;
    fixture.runtime.clarifications = {
      ...clarifications,
      async appendProductDecision(options) {
        const result = await clarifications.appendProductDecision(options);
        if (!stopped && boundary === "appended") {
          stopped = true;
          throw interruption;
        }
        return result;
      },
      async prepareEdit(options) {
        if (
          !stopped &&
          boundary === "before-suspension" &&
          options.action === "product-decision"
        ) {
          stopped = true;
          throw interruption;
        }
        return clarifications.prepareEdit(options);
      },
    };
    await assert.rejects(fixture.run(), (cause) => cause === interruption);
    assert.ok(stopped);
    const saved = fixture.currentRun;
    if (boundary === "suspended") {
      assert.equal(saved.pipelineState.writableResult, null);
      assert.equal(
        saved.pause.inputRequest.questions[0].question,
        product.question,
      );
    } else {
      assert.equal(
        saved.pipelineState.writableResult.productDecision.decision.question,
        product.question,
      );
      assert.equal(
        saved.pipelineState.writableResult.attempts,
        restatement ? 1 : 0,
      );
      assert.equal(saved.counters.productDecisions, 0);
    }
    if (boundary === "intent") {
      for (const mutate of [
        (intent) => {
          intent.number += 1;
        },
        (intent) => {
          intent.expectedHash = "0".repeat(64);
        },
        (intent) => {
          intent.resultHash = intent.expectedHash;
        },
        (intent) => {
          intent.decision.evidence = [];
        },
        (intent) => {
          intent.decision.response = "PRIVATE_REJECTED_VALUE";
        },
      ]) {
        const rejected = structuredClone(saved);
        mutate(rejected.pipelineState.writableResult.productDecision);
        assert.throws(
          () => planExecutionPipeline.workflow.validateRun(rejected),
          { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
        );
      }
    }
    const calls = fixture.calls.worker.length;
    const fingerprint =
      saved.pipelineState.repositoryBaseline.contentFingerprint;
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "product_decision_required");
    assert.equal(paused.pipelineState.writableResult, null);
    assert.equal(paused.pipelineState.pendingEdit.action, "product-decision");
    assert.equal(
      paused.pause.inputRequest.questions[0].question,
      product.question,
    );
    assert.equal(paused.counters.productDecisions, 1);
    assert.equal(paused.counters.fixRounds, phase === "IMPLEMENT" ? 0 : 1);
    assert.equal(
      paused.pipelineState.repositoryBaseline.contentFingerprint,
      fingerprint,
    );
    assert.equal(fixture.calls.worker.length, calls);
    assert.deepEqual(paused.pipelineState.completedCommits, []);
    assert.equal(
      await readFile(join(fixture.projectPath, "candidate.txt"), "utf8"),
      "preserved candidate\n",
    );
    const transcript = await fixture.runtime.clarifications.inspectTranscript({
      artifactRoot: paused.pipelineState.repositoryBaseline.projectPath,
      transcriptPath: paused.pipelineState.clarificationPath,
    });
    assert.equal(transcript.content.split(product.question).length - 1, 1);
    assert.equal(transcript.hash, paused.hashes.executionClarifications);
    assert.doesNotMatch(
      JSON.stringify(fixture.transitions),
      /PRIVATE_REJECTED_VALUE/u,
    );
  });
}

for (const phase of ["IMPLEMENT", "RESOLVE_FINDINGS"]) {
  test(`${phase} restatement output exhaustion preserves its consumed read-only checkpoint`, async (t) => {
    const schema =
      phase === "IMPLEMENT" ? IMPLEMENTATION_SCHEMA : FINDING_RESOLUTION_SCHEMA;
    const valid =
      phase === "IMPLEMENT"
        ? implementationCompleted()
        : resolution({ id: "R1", decision: "FIX" });
    const invalid = { ...valid, reason: "PRIVATE_REJECTED_VALUE" };
    let exhausted = false;
    let publicationInterrupted = false;
    const fixture = await createFixture(t, {
      workWorker: [
        ...(phase === "IMPLEMENT" ? [] : [implementationCompleted()]),
        invalid,
        valid,
        finalizationPassed(),
      ],
      workReviewer:
        phase === "IMPLEMENT"
          ? [reviewApproved()]
          : [reviewFindings("R1"), reviewApproved()],
      async onRoleRun(_role, request) {
        if (request.schema !== schema) return;
        if (request.access === "workspace-write")
          await writeFile(
            join(request.cwd, "candidate.txt"),
            "preserved candidate\n",
          );
        else if (!exhausted) {
          exhausted = true;
          throw outputExhaustion();
        }
      },
      onTransition(run) {
        if (
          phase === "IMPLEMENT" &&
          run.pause?.reason === "output_exhausted" &&
          !publicationInterrupted
        ) {
          publicationInterrupted = true;
          throw new Error("Exhaustion publication response interrupted");
        }
      },
    });
    attachOutputExhaustion(fixture);
    if (phase === "IMPLEMENT")
      await assert.rejects(
        fixture.run(),
        /Exhaustion publication response interrupted/u,
      );
    else await fixture.run();
    const saved = fixture.currentRun;
    assert.equal(saved.pause.reason, "output_exhausted");
    assert.equal(saved.pause.resumeState, phase);
    assert.equal(saved.pause.checkpoint, "writable-result:read-only:commit:1");
    assert.equal(saved.pause.role, "worker");
    assert.equal(saved.activeTurn, null);
    assert.equal(saved.pipelineState.writableResult.attempts, 1);
    assert.equal(saved.pipelineState.writableResult.additionalAttempts, 0);
    assert.doesNotThrow(() =>
      planExecutionPipeline.workflow.validateRun(saved),
    );
    for (const mutate of [
      (run) => {
        run.pause.role = "reviewer";
      },
      (run) => {
        run.pause.resumeState =
          phase === "IMPLEMENT" ? "RESOLVE_FINDINGS" : "IMPLEMENT";
      },
      (run) => {
        run.pause.checkpoint = "writable-result:read-only:commit:2";
      },
      (run) => {
        run.pause.checkpoint = "writable-result:workspace-write:commit:1";
      },
      (run) => {
        run.pause.checkpoint = `${phase.toLowerCase().replaceAll("_", "-")}:read-only:commit:1`;
      },
      (run) => {
        run.pipelineState.writableResult.attempts = 0;
      },
      (run) => {
        run.pipelineState.writableResult = null;
      },
    ]) {
      const rejected = structuredClone(saved);
      mutate(rejected);
      assert.throws(
        () => planExecutionPipeline.workflow.validateRun(rejected),
        { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
      );
    }
    const calls = fixture.calls.worker.length;
    const fingerprint = saved.pipelineState.writableResult.candidateFingerprint;
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "writable_output_invalid");
    assert.equal(paused.pipelineState.writableResult.attempts, 1);
    assert.equal(paused.pipelineState.writableResult.additionalAttempts, 0);
    assert.equal(
      paused.pipelineState.writableResult.candidateFingerprint,
      fingerprint,
    );
    assert.equal(fixture.calls.worker.length, calls);
    const done = await fixture.run();
    assert.equal(done.pipelineState.workflowState, "DONE");
    assert.equal(done.counters.fixRounds, phase === "IMPLEMENT" ? 0 : 1);
    assert.equal(done.pipelineState.completedCommits.length, 1);
    assert.deepEqual(
      resultCalls(fixture, schema).map(({ access }) => access),
      ["workspace-write", "read-only", "read-only"],
    );
    assert.equal(
      await readFile(join(fixture.projectPath, "candidate.txt"), "utf8"),
      "preserved candidate\n",
    );
  });
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} corrects an implementation result read-only before its original gates`, async (t) => {
    const fixture = await createFixture(t, {
      mode,
      sourceSession: SOURCE_SESSION,
      workWorker: [
        malformed(),
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix(), cleanConfirmation()]),
        finalizationPassed(),
      ],
    });
    const done = await fixture.run();
    assert.equal(done.pipelineState.workflowState, "DONE");
    assert.deepEqual(
      resultCalls(fixture).map(({ access }) => access),
      ["workspace-write", "read-only"],
    );
    assert.match(resultCalls(fixture)[1].prompt, /not another implementation/u);
    assert.equal(resultCalls(fixture)[1].session, undefined);
    if (mode === "lazy")
      assert.equal(
        fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
          .length,
        1,
      );
    assert.equal(done.pipelineState.completedCommits.length, 1);
    assert.equal(done.pipelineState.writableResult, null);
    assert.equal(done.counters.fixRounds, mode === "independent" ? 0 : 1);
    assert.doesNotMatch(
      JSON.stringify(fixture.transitions),
      /PRIVATE_REJECTED_VALUE/u,
    );
  });
}

test("provider structured-output failure preserves candidate work for a read-only restatement", async (t) => {
  let failed = false;
  const fixture = await createFixture(t, {
    async onRoleRun(_role, request) {
      if (request.schema !== IMPLEMENTATION_SCHEMA || failed) return;
      failed = true;
      await writeFile(join(request.cwd, "candidate.txt"), "candidate bytes\n");
      throw Object.assign(new Error("PRIVATE_NATIVE_VALUE"), {
        failureClass: "structured-output",
      });
    },
  });
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(
    await readFile(join(fixture.projectPath, "candidate.txt"), "utf8"),
    "candidate bytes\n",
  );
  assert.deepEqual(
    resultCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
  assert.doesNotMatch(
    JSON.stringify(fixture.transitions),
    /PRIVATE_NATIVE_VALUE/u,
  );
});

test("availability recovery within restatement retains its one consumed output attempt", async (t) => {
  let failed = false;
  const fixture = await createFixture(t, {
    workWorker: [malformed(), implementationCompleted(), finalizationPassed()],
    onRoleRun(_role, request) {
      if (
        request.schema === IMPLEMENTATION_SCHEMA &&
        request.access === "read-only" &&
        !failed
      ) {
        failed = true;
        throw availabilityFailure();
      }
    },
  });
  const availability = attachAvailability(fixture);
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(availability.delays.length, 1);
  assert.deepEqual(
    resultCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "read-only"],
  );
  const pending = fixture.transitions.filter(
    ({ patch }) => patch?.pipelineState?.writableResult?.stage === "correcting",
  );
  assert.ok(pending.length > 0);
  assert.ok(
    pending.every(
      ({ patch }) => patch.pipelineState.writableResult.attempts === 1,
    ),
  );
});

test("frozen input and native-policy changes stop correction before invoking it", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [malformed(), malformed()],
  });
  await fixture.run();
  const calls = fixture.calls.worker.length;
  await writeFile(join(fixture.taskPath, "task.md"), "Changed frozen input.\n");
  const changed = await fixture.run();
  assert.equal(changed.pause.reason, "task_input_changed");
  assert.equal(fixture.calls.worker.length, calls);

  const policyFixture = await createFixture(t, { workWorker: [malformed()] });
  const probe = policyFixture.runtime.adapters.worker.probe;
  policyFixture.runtime.adapters.worker.probe = async (options) => {
    if (options?.access === "read-only")
      throw Object.assign(new Error("PRIVATE_POLICY_VALUE"), {
        code: "ERR_PROVIDER_POLICY_CHANGED",
      });
    return probe(options);
  };
  await assert.rejects(policyFixture.run(), {
    code: "ERR_PROVIDER_POLICY_CHANGED",
  });
  assert.equal(resultCalls(policyFixture).length, 1);
  assert.equal(
    policyFixture.currentRun.pipelineState.writableResult.attempts,
    0,
  );
  assert.equal(
    policyFixture.currentRun.pipelineState.writableResult.stage,
    "ready",
  );
  assert.doesNotMatch(
    JSON.stringify(policyFixture.transitions),
    /PRIVATE_POLICY_VALUE/u,
  );
});

test("exhaustion offers one explicit read-only retry without renewing the automatic allowance", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      malformed(),
      malformed(),
      malformed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });
  const first = await fixture.run();
  assert.equal(first.pause.reason, "writable_output_invalid");
  assert.equal(first.pipelineState.writableResult.attempts, 1);
  assert.equal(first.pipelineState.writableResult.additionalAttempts, 0);
  for (const mutate of [
    (run) => {
      run.pipelineStateVersion += 1;
    },
    (run) => {
      run.pipelineState.writableResult.attempts = 0;
    },
    (run) => {
      run.pipelineState.writableResult.response = "PRIVATE_REJECTED_VALUE";
    },
    (run) => {
      run.pipelineState.writableResult.diagnostic.field =
        "PRIVATE_REJECTED_VALUE";
    },
    (run) => {
      run.counters.fixRounds += 1;
    },
  ]) {
    const rejected = structuredClone(first);
    mutate(rejected);
    assert.throws(() => planExecutionPipeline.workflow.validateRun(rejected), {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
  }
  const projected = planExecutionPipeline.projections.pause(first);
  assert.deepEqual(projected.nextActions, [{ type: "resume", action: null }]);
  assert.match(projected.explanation, /one additional read-only/u);
  assert.deepEqual(projected.evidence, [
    "implementation: reason (empty-string).",
  ]);
  const fingerprint = first.pipelineState.repositoryBaseline.contentFingerprint;
  const second = await fixture.run();
  assert.equal(second.pause.reason, "writable_output_invalid");
  assert.equal(second.pipelineState.writableResult.attempts, 2);
  assert.equal(second.pipelineState.writableResult.additionalAttempts, 1);
  assert.equal(
    second.pipelineState.repositoryBaseline.contentFingerprint,
    fingerprint,
  );
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    resultCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "read-only", "read-only"],
  );
  assert.equal(done.counters.fixRounds, 0);
  assert.equal(done.pipelineState.completedCommits.length, 1);
});

test("rejected recovery cannot adopt intervening candidate edits", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [malformed(), malformed()],
  });
  await fixture.run();
  const count = fixture.calls.worker.length;
  await writeFile(
    join(fixture.projectPath, "outside-edit.txt"),
    "preserve this\n",
  );
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "unsafe_git_state");
  assert.equal(fixture.calls.worker.length, count);
  assert.equal(paused.pipelineState.writableResult.additionalAttempts, 0);
  assert.equal(
    await readFile(join(fixture.projectPath, "outside-edit.txt"), "utf8"),
    "preserve this\n",
  );
});

test("result restatement cannot mutate the candidate", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [malformed(), implementationCompleted()],
    async onRoleRun(_role, request) {
      if (
        request.schema === IMPLEMENTATION_SCHEMA &&
        request.access === "read-only"
      )
        await writeFile(
          join(request.cwd, "unsafe.txt"),
          "preserved contamination\n",
        );
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(paused.pipelineState.completedCommits.length, 0);
  assert.equal(paused.pipelineState.writableResult, null);
});

test("a validated blocker after malformed output remains a read-only checkpoint on resume", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      malformed(),
      implementationBlocked(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pipelineState.writableResult.stage, "blocked");
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    resultCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "read-only"],
  );
});

test("custom recovery retains earlier receipts and validates criterion evidence and exact output authority", async (t) => {
  let restatements = 0;
  let writes = 0;
  const fixture = await customExecutionFixture(t, "independent", {
    async beforeTurn({ saved, request, output }) {
      if (
        saved.pipelineState.currentStep !== 2 ||
        !["implement", "writable-result"].includes(saved.activeTurn.phase)
      )
        return;
      const customResult = {
        analysis: "The conclusion is supported by the supplied source.",
        evidence: [
          {
            criterionId: "traceability",
            observations: ["The conclusion cites source.md."],
          },
        ],
        outputPaths: [output],
      };
      const value = { ...implementationCompleted(), customResult };
      if (request.access === "workspace-write") {
        writes++;
        await writeFile(output, "preserved custom candidate\n");
        return { ...value, reason: "PRIVATE_REJECTED_VALUE" };
      }
      restatements++;
      return restatements === 1
        ? {
            ...value,
            customResult: { ...customResult, outputPaths: [saved.taskPath] },
          }
        : value;
    },
  });
  const paused = (await fixture.run()).run;
  assert.equal(paused.pause.reason, "writable_output_invalid");
  assert.equal(paused.pause.diagnostic.field, "customResult");
  const receipt = paused.pipelineState.customResults.accepted[0].receipt;
  const done = (await fixture.run()).run;
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(done.pipelineState.customResults.accepted[0].receipt, receipt);
  assert.equal(done.pipelineState.customResults.accepted.length, 2);
  assert.equal(
    await readFile(fixture.output, "utf8"),
    "preserved custom candidate\n",
  );
  assert.equal(writes, 1);
  assert.equal(restatements, 2);
  assert.deepEqual(done.pipelineState.completedCommits, []);
});

test("malformed resolution retains original blockers and charges its mutation once", async (t) => {
  const badResolution = {
    ...resolution({ id: "R1", decision: "FIX" }),
    evidence: ["PRIVATE_REJECTED_VALUE"],
  };
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      badResolution,
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
    async onRoleRun(_role, request) {
      if (
        request.schema === FINDING_RESOLUTION_SCHEMA &&
        request.access === "workspace-write"
      )
        await writeFile(join(request.cwd, "fixed.txt"), "fixed candidate\n");
    },
  });
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(done.counters.fixRounds, 1);
  assert.deepEqual(
    resultCalls(fixture, FINDING_RESOLUTION_SCHEMA).map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
  assert.equal(
    fixture.calls.reviewer.filter(({ access }) => access === "read-only")
      .length > 1,
    true,
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "fixed.txt"), "utf8"),
    "fixed candidate\n",
  );
  const charged = fixture.transitions.filter(
    ({ patch }) => patch?.pipelineState?.writableResult?.fixCharged,
  );
  assert.ok(charged.length > 0);
  assert.ok(charged.every(({ patch }) => patch.counters.fixRounds === 1));
  assert.doesNotMatch(
    JSON.stringify(fixture.transitions),
    /PRIVATE_REJECTED_VALUE/u,
  );
});

test("interrupted resolution reconciliation preserves its charged fix and original blockers", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      resolution({ id: "R1", decision: "FIX" }),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
    async onRoleRun(_role, request) {
      if (
        request.schema === FINDING_RESOLUTION_SCHEMA &&
        request.access === "workspace-write"
      )
        await writeFile(join(request.cwd, "fixed.txt"), "preserved fix\n");
    },
    onTransition(run) {
      if (
        !interrupted &&
        run.pipelineState.writableResult?.phase === "RESOLVE_FINDINGS" &&
        run.pipelineState.writableResult.stage === "ready"
      ) {
        interrupted = true;
        throw Object.assign(new Error("Reconciliation response interrupted"), {
          code: "ERR_RUN_REVISION_CHANGED",
        });
      }
    },
  });
  await assert.rejects(fixture.run(), { code: "ERR_RUN_REVISION_CHANGED" });
  assert.equal(fixture.currentRun.counters.fixRounds, 1);
  assert.equal(
    fixture.currentRun.pipelineState.writableResult.blockers[0].id,
    "R1",
  );
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(done.counters.fixRounds, 1);
  assert.deepEqual(
    resultCalls(fixture, FINDING_RESOLUTION_SCHEMA).map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("rework mutation is charged once even when its result requires restatement", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      resolution({ id: "R1", decision: "FIX" }),
      malformed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
    async onRoleRun(_role, request) {
      if (
        request.schema === IMPLEMENTATION_SCHEMA &&
        request.access === "workspace-write" &&
        request.prompt.includes("Required rework direction")
      )
        await writeFile(
          join(request.cwd, "rework.txt"),
          "reworked candidate\n",
        );
    },
  });
  const done = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(done.counters.fixRounds, 2);
  assert.deepEqual(
    resultCalls(fixture).map(({ access }) => access),
    ["workspace-write", "workspace-write", "read-only"],
  );
});

test("restatement does not invent or dispute finalization blocker dispositions", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      {
        ...resolution({ id: "F1", decision: "FIX" }),
        reason: "PRIVATE_REJECTED_VALUE",
      },
      resolution({ id: "F1", decision: "DISPUTE" }),
    ],
    async onRoleRun(_role, request) {
      if (
        request.schema === FINDING_RESOLUTION_SCHEMA &&
        request.access === "workspace-write"
      )
        await writeFile(
          join(request.cwd, "finalization-fix.txt"),
          "preserved fix\n",
        );
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "writable_output_invalid");
  assert.equal(paused.pipelineState.writableResult.blockers[0].id, "F1");
  assert.equal(paused.pause.diagnostic.constraint, "disputable-blocker-only");
  assert.deepEqual(paused.pipelineState.pendingDisputes, []);
});

for (const boundary of ["invoking", "ready", "correcting", "accepted"]) {
  test(`interruption at ${boundary} neither replays a writable turn nor renews correction accounting`, async (t) => {
    let interrupted = false;
    let observedWritable = false;
    const fixture = await createFixture(t, {
      workWorker: [
        malformed(),
        implementationCompleted(),
        finalizationPassed(),
      ],
      onTransition(run, patch) {
        const stage = run.pipelineState.writableResult?.stage;
        const matches =
          boundary === "accepted"
            ? observedWritable &&
              run.pipelineState.writableResult === null &&
              run.pipelineState.workflowState === "REVIEW"
            : stage === boundary;
        if (stage !== undefined) observedWritable = true;
        if (matches && !interrupted) {
          interrupted = true;
          throw Object.assign(new Error("Publication response interrupted"), {
            code: "ERR_RUN_REVISION_CHANGED",
          });
        }
      },
    });
    if (boundary === "invoking") {
      // startAgentTurn owns this boundary rather than ordinary transitions.
      const start = fixture.runtime.startAgentTurn.bind(fixture.runtime);
      fixture.runtime.startAgentTurn = async (...args) => {
        const run = await start(...args);
        if (
          !interrupted &&
          run.pipelineState.writableResult?.stage === "invoking"
        ) {
          interrupted = true;
          await writeFile(
            join(fixture.projectPath, "partial.txt"),
            "partial work\n",
          );
          throw Object.assign(new Error("Turn response interrupted"), {
            code: "ERR_RUN_REVISION_CHANGED",
          });
        }
        return run;
      };
      // The interrupted native turn yielded no output; restatement supplies
      // the first queued response, then the explicitly authorized replacement.
    }
    await assert.rejects(fixture.run(), { code: "ERR_RUN_REVISION_CHANGED" });
    assert.ok(interrupted);
    let resumed = await fixture.run();
    if (boundary === "correcting") {
      assert.equal(resumed.pause.reason, "writable_output_invalid");
      assert.equal(resumed.pipelineState.writableResult.attempts, 1);
      resumed = await fixture.run();
    } else if (
      boundary === "invoking" &&
      resumed.pause?.reason === "writable_output_invalid"
    ) {
      resumed = await fixture.run();
    }
    assert.equal(resumed.pipelineState.workflowState, "DONE");
    assert.ok(
      resultCalls(fixture).filter(({ access }) => access === "workspace-write")
        .length <= 1,
    );
    assert.equal(resumed.pipelineState.completedCommits.length, 1);
    assert.equal(
      fixture.calls.worker.filter(({ access }) => access === "local-commit")
        .length,
      1,
    );
  });
}

test("lost session publication preserves the retired writable checkpoint for restatement", async (t) => {
  const interrupted = new Error("Session publication response interrupted");
  const fixture = await createFixture(t, {
    workWorker: [malformed(), implementationCompleted(), finalizationPassed()],
  });
  const record = fixture.runtime.recordChildSession.bind(fixture.runtime);
  let stopped = false;
  fixture.runtime.recordChildSession = async (...args) => {
    const run = await record(...args);
    if (!stopped && run.pipelineState.writableResult?.stage === "ready") {
      stopped = true;
      throw interrupted;
    }
    return run;
  };
  await assert.rejects(fixture.run(), (cause) => cause === interrupted);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "IMPLEMENT");
  assert.equal(fixture.currentRun.pipelineState.writableResult.stage, "ready");
  assert.equal(fixture.currentRun.activeTurn, null);
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    resultCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
});

test("new recovery diagnostics accept identities only and migration grants no recovery authority", () => {
  const candidate = {
    field: "decisions[31].reason",
    constraint: "empty-string",
  };
  assert.equal(
    writableResultDiagnostic({ diagnostic: candidate }, "RESOLVE_FINDINGS")
      .field,
    candidate.field,
  );
  for (const diagnostic of [
    { field: "decisions[32].reason", constraint: "empty-string" },
    { field: "reason", constraint: "PRIVATE_VALUE" },
    { field: "PRIVATE_VALUE", constraint: "empty-string" },
  ])
    assert.equal(
      writableResultDiagnostic({ diagnostic }, "IMPLEMENT").constraint,
      "semantic-contract",
    );
  const state = planExecutionPipeline.workflow.createState();
  const legacy = { ...state };
  delete legacy.writableResult;
  assert.deepEqual(
    planExecutionPipeline.migrations[37]({ pipelineState: legacy }),
    state,
  );
});
