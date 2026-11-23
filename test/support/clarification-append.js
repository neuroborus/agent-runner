import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  createClarificationService,
  createMcpControlPlane,
  createRunner,
  createRunStore,
  getPipeline,
  main,
} from "../../src/index.js";
import { restoredAppendReadback } from "./clarification-readback.js";
import {
  configurationLoader,
  createExecutionAdapter,
  operatorFixture,
  requestedStepAssessment,
} from "./runner.js";

export const APPEND_QUESTIONS = [
  {
    question: "Which public behavior is required?",
    whyItMatters: "The alternatives produce different public results.",
  },
];

export function appendReadFailure() {
  return Object.assign(new Error("Controlled transcript read interruption."), {
    code: "ERR_CLARIFICATION_READ",
  });
}

// Real Runner, transcript service, journals and Git; only role replies and the
// explicitly selected interruption boundary are injected by each owning test.
export async function clarificationAppendFixture(
  t,
  pipelineId,
  {
    mode = "combined",
    kind = "questions",
    external = false,
    questionFirst = false,
    artifactRoot = "LOCAL_ARTIFACTS",
  } = {},
) {
  const paths = await operatorFixture(t, pipelineId);
  const rootPath = external
    ? join(paths.workspace, "infrastructure")
    : paths.projectPath;
  const configurationPath = external
    ? join(rootPath, "agent-runner.json")
    : null;
  if (external) {
    await mkdir(rootPath);
    await writeFile(
      configurationPath,
      JSON.stringify({
        schemaVersion: 1,
        artifactRoot,
        infrastructure: {
          schemaVersion: 1,
          placement: "external",
          projectPath: paths.projectPath,
          rootPath,
        },
      }),
    );
  }
  const calls = [];
  const probes = [];
  const adapter = {
    ...createExecutionAdapter(),
    async probe(request) {
      probes.push(request);
      return createExecutionAdapter().probe(request);
    },
    async run(request) {
      if (request.prompt.startsWith("Validate the proposed context"))
        return {
          structured: { stepAssessment: requestedStepAssessment(request) },
          sessionId: request.session?.id ?? "append-context",
        };
      calls.push(request);
      assert.equal(request.access, "read-only");
      let structured;
      const emptyDecision = {
        reason: "",
        question: "",
        options: [],
        whyBlocked: "",
        evidence: [],
      };
      if (kind === "questions" || (questionFirst && calls.length === 1)) {
        assert.equal(calls.length, 1, "Append recovery must not replay a role");
        structured = { status: "QUESTIONS", questions: APPEND_QUESTIONS };
        if (pipelineId !== "plan-authoring")
          Object.assign(structured, emptyDecision);
      } else if (calls.length === (questionFirst ? 2 : 1)) {
        structured = { status: "READY", questions: [], ...emptyDecision };
      } else {
        assert.equal(
          calls.length,
          questionFirst ? 3 : 2,
          "Decision recovery must not replay a role",
        );
        structured = {
          status: "PRODUCT_DECISION_REQUIRED",
          summary: "",
          requiredChecks: [],
          validationInfrastructure: [],
          capabilityRequirements: [],
          environmentBlockers: [],
          capacityField: "",
          capacityLimit: 0,
          reason: "",
          question: APPEND_QUESTIONS[0].question,
          options: ["Behavior A", "Behavior B"],
          whyBlocked: APPEND_QUESTIONS[0].whyItMatters,
          evidence: ["The task leaves the public behavior unspecified."],
          ...(pipelineId === "plan-execution"
            ? { stepAssessment: requestedStepAssessment(request) }
            : {}),
        };
      }
      if (
        (
          request.schema?.properties?.result?.anyOf?.[0]?.properties ??
          request.schema?.properties
        )?.stepAssessment
      )
        structured.stepAssessment = requestedStepAssessment(request);
      return {
        structured:
          request.schema?.properties?.result?.anyOf === undefined
            ? structured
            : { result: structured },
        sessionId: request.session?.id ?? `append-${calls.length}`,
      };
    },
  };
  function open({
    store = createRunStore({ stateRoot: paths.stateRoot }),
    clarifications = createClarificationService({ interactive: false }),
    adapters = { codex: adapter },
  } = {}) {
    return {
      store,
      runner: createRunner({
        adapters,
        runStore: store,
        clarifications,
        loadConfiguration: configurationLoader({
          schemaVersion: 1,
          defaultBackend: "codex",
          artifactRoot,
          pipelines: { [pipelineId]: { mode } },
        }),
      }),
    };
  }
  return {
    ...paths,
    calls,
    rootPath,
    probes,
    open,
    input: {
      pipelineId,
      projectPath: paths.projectPath,
      taskPath: paths.taskPath,
      ...(external ? { projectConfigurationPath: configurationPath } : {}),
    },
    async transcript(run) {
      const path =
        run.pipelineState.clarificationPath ??
        join(paths.taskPath, "clarifications.md");
      return readFile(path, "utf8");
    },
  };
}

export const transcriptHash = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

// Cold journal proof, distinct from workflow-only reconstruction: every reopen
// discards the store cache, transcript service and Runner. Only replies and the
// finite native replacement interleaving are injected.
export async function assertColdReadbackRejection(t, f, kind = "questions") {
  const pipelineId = f.input.pipelineId;
  const operation =
    kind === "questions" ? "appendQuestionRound" : "appendProductDecision";
  const service = createClarificationService({ interactive: false });
  let proof;
  let producing;
  let runId;
  const noEditor = {
    prepareEdit() {
      assert.fail("Rejected readback cannot authorize an editor");
    },
    openEditor() {
      assert.fail("Rejected readback cannot open an editor");
    },
    acceptEdit() {
      assert.fail("Rejected readback cannot accept an answer");
    },
  };
  const initial = f.open({
    clarifications: {
      ...service,
      ...noEditor,
      [operation]: restoredAppendReadback(
        t,
        service,
        operation,
        async (bytes) => {
          proof = bytes;
          producing = await initial.store.loadRun(runId);
        },
      ),
    },
  });
  runId = (await initial.runner.create(f.input)).run.runId;
  const blocked = (await initial.runner.resume({ runId })).run;
  const reason =
    pipelineId === "audit" ? "input_changed" : "clarifications_changed";
  assert.equal(blocked.pause.reason, reason);
  const intent = producing.pipelineState.pendingClarificationAppend;
  assert.ok(intent);
  assert.equal(intent.expectedHash, transcriptHash(proof.priorBytes));
  assert.equal(intent.resultHash, transcriptHash(proof.resultBytes));
  assert.deepEqual(blocked.pipelineState, {
    ...producing.pipelineState,
    workflowState: "WAITING_FOR_USER",
  });
  assert.deepEqual(blocked.counters, producing.counters);
  assert.deepEqual(blocked.hashes, producing.hashes);
  assert.deepEqual(blocked.sessionLineage, producing.sessionLineage);
  assert.equal(blocked.pipelineState.pendingEdit, null);
  assert.equal(
    pipelineId === "audit"
      ? blocked.pipelineState.clarificationRounds
      : blocked.counters[
          kind === "questions" ? "clarificationRounds" : "productDecisions"
        ],
    0,
  );
  const calls = f.calls.length;
  const probes = f.probes.length;
  const reopen = () =>
    f.open({
      clarifications: {
        ...createClarificationService({ interactive: false }),
        ...noEditor,
        appendQuestionRound() {
          assert.fail("Rejected append cannot replay questions");
        },
        appendProductDecision() {
          assert.fail("Rejected append cannot replay a decision");
        },
      },
    });
  const projection = getPipeline(pipelineId).projections.pause(blocked);
  assert.deepEqual(projection.nextActions, []);
  for (const bytes of [proof.priorBytes, proof.resultBytes]) {
    await writeFile(proof.transcriptPath, bytes);
    const cold = reopen();
    assert.deepEqual(await cold.store.loadRun(runId), blocked);
    await assert.rejects(cold.runner.resume({ runId }), {
      code: "ERR_INAPPLICABLE_RESUME_ACTION",
    });
    const control = createMcpControlPlane({
      runner: cold.runner,
      runStore: cold.store,
    });
    const status = await control.runStatus({ runId });
    assert.deepEqual(status.pause, projection);
    assert.deepEqual(
      (await control.runWait({ runId, cursor: 0, timeoutMs: 0 })).pause,
      status.pause,
    );
    let output = "";
    assert.equal(
      await main(["status", "--run", runId], {
        runner: cold.runner,
        stdout: {
          write(chunk) {
            output += chunk;
          },
        },
        stderr: {
          write(chunk) {
            assert.fail(chunk);
          },
        },
      }),
      0,
    );
    assert.ok(output.includes(status.pause.explanation));
    assert.doesNotMatch(output, /Retry with:/u);
    for (const privateValue of [
      intent.expectedHash,
      intent.resultHash,
      ...(kind === "questions"
        ? intent.questions.map(({ question }) => question)
        : [intent.decision.question]),
    ])
      assert.equal(JSON.stringify(status.pause).includes(privateValue), false);
    assert.deepEqual(await reopen().store.loadRun(runId), blocked);
    assert.deepEqual(await readFile(proof.transcriptPath), bytes);
  }
  // The real stop settlement must retain the rejection as its suspended pause,
  // with the complete intent and unsettled checkpoint, even at the result hash.
  const cold = reopen();
  await cold.store.requestOperatorStop({
    runId,
    kind: "pause_requested",
    expectedRevision: blocked.revision,
    idempotencyKey: "readback-rejection-stop",
  });
  const stopped = (await cold.runner.resume({ runId })).run;
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.deepEqual(stopped.pause.operatorResume.pause, blocked.pause);
  assert.deepEqual(stopped.pipelineState, blocked.pipelineState);
  assert.deepEqual(stopped.counters, blocked.counters);
  assert.deepEqual(stopped.hashes, blocked.hashes);
  assert.equal(stopped.stopRequest.reconciledRevision, stopped.revision);
  assert.deepEqual(await reopen().store.loadRun(runId), stopped);
  const restored = (await reopen().runner.resume({ runId })).run;
  assert.deepEqual(restored.pause, blocked.pause);
  assert.deepEqual(restored.pipelineState, blocked.pipelineState);
  assert.deepEqual(restored.counters, blocked.counters);
  assert.deepEqual(restored.hashes, blocked.hashes);
  await assert.rejects(reopen().runner.resume({ runId }), {
    code: "ERR_INAPPLICABLE_RESUME_ACTION",
  });
  const history = await reopen().store.loadRunHistory(runId);
  const intents = history.events
    .map(({ state }) => state.pipelineState.pendingClarificationAppend)
    .filter((value) => value !== null);
  assert.ok(intents.length > 1);
  for (const retained of intents) assert.deepEqual(retained, intent);
  assert.equal(
    history.events.some(
      ({ state }) => state.pipelineState.pendingEdit !== null,
    ),
    false,
  );
  assert.equal(f.calls.length, calls);
  assert.equal(f.probes.length, probes);
}
