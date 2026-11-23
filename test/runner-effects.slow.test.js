import assert from "node:assert/strict";
import {
  cp,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";

import {
  createClarificationService,
  createGitService,
  createMcpControlPlane,
  createRunner,
  createRunStore,
  main,
} from "../src/index.js";
import { ClaudeAdapterError } from "../src/agents/index.js";
import { resolveStopBoundary } from "../src/pipeline-registry.js";
import {
  CHECK_AND_FIX_SCHEMA,
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CANDIDATE_REVIEW_SCHEMA,
  FINALIZATION_SCHEMA,
  REVIEW_SCHEMA,
} from "../pipelines/plan-execution/src/schemas.js";
import {
  checkAndFix,
  cleanConfirmation,
  cleanConfirmationFindings,
} from "../pipelines/plan-execution/test/support/index.js";
import {
  appendReadFailure,
  clarificationAppendFixture,
  configurationLoader,
  createArbiterAdapter,
  createExecutionAdapter,
  createFixture,
  executeFile,
  operatorFixture,
  PLAN,
  requestedStepAssessment,
  runnerFor,
  RUNNER_CONFIGURATION,
  transcriptHash,
} from "./support/index.js";

import { availabilityFailure } from "./support/availability.js";
import {
  modelCatalogMiss,
  withModelCompletion,
} from "./support/model-catalog.js";
import { outputExhaustion } from "./support/output-exhaustion.js";

test("configuration drift after a proven no-effect miss preserves writable reservations", async (t) => {
  for (const pipelineId of ["plan-execution", "polishing"]) {
    const implementing = pipelineId === "plan-execution";
    const fixture = await operatorFixture(t, pipelineId);
    const configurationDirectory = join(fixture.projectPath, "LOCAL_ARTIFACTS");
    const configurationPath = join(configurationDirectory, "agent-runner.json");
    await mkdir(configurationDirectory);
    await writeFile(configurationPath, '{"schemaVersion":1}\n');
    const store = createRunStore({ stateRoot: fixture.stateRoot });
    const git = createGitService();
    const adapter = createExecutionAdapter();
    let configuredPathAvailable = true;
    let before;
    let runId;
    const runner = runnerFor(
      fixture,
      {
        codex: {
          ...adapter,
          async run(request) {
            if (
              request.access === "workspace-write" &&
              request.prompt.includes(
                implementing
                  ? "Implement the changes described"
                  : "Resolve every current blocker",
              )
            ) {
              before = await store.loadRun(runId);
              assert.ok(before.modelCompletionReceipts.worker);
              await writeFile(join(request.cwd, "concurrent.txt"), "drift\n");
              configuredPathAvailable = false;
              throw modelCatalogMiss(request);
            }
            const response = await adapter.run(request);
            if (
              !implementing &&
              request.prompt.includes("semantic candidate")
            ) {
              return {
                ...response,
                structured: {
                  ...response.structured,
                  status: "FINDINGS",
                  findings: [
                    {
                      id: "R1",
                      file: "source.js",
                      problem: "The candidate needs a repair.",
                      reason: "The repair is required by the task.",
                      suggestedAction: "Add the repair.",
                    },
                  ],
                },
              };
            }
            return withModelCompletion(response, request);
          },
        },
      },
      {
        git: {
          ...git,
          async inspectPath(input) {
            const inspected = await git.inspectPath(input);
            return input.path === configurationPath && !configuredPathAvailable
              ? { ...inspected, exists: false }
              : inspected;
          },
        },
        runStore: store,
      },
    );
    const { run: created } = await runner.create({
      pipelineId,
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: { worker: { model: "test-model" } },
    });
    runId = created.runId;
    const { run: paused } = await runner.resume({ runId });
    assert.ok(before, pipelineId);
    assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.deepEqual(paused.pause, {
      reason: "project_configuration_changed",
      code: "ERR_PROJECT_CONFIGURATION_CHANGED",
    });
    assert.equal(paused.activeTurn, null);
    assert.equal(paused.modelCatalogResume, null);
    const field = implementing ? "writableResult" : "resolutionCorrection";
    assert.equal(before.pipelineState[field].stage, "invoking");
    for (const key of [field, "repositoryBaseline", "findings"]) {
      assert.deepEqual(paused.pipelineState[key], before.pipelineState[key]);
    }
    assert.deepEqual(paused.counters, before.counters);
  }
});

test("catalog resume retains narrative availability through the rebuilt prerequisite", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  let now = Date.parse("2026-09-29T10:00:00.000Z");
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    clock: () => new Date(now),
  });
  const adapter = createExecutionAdapter();
  const runRole = adapter.run.bind(adapter);
  let reviews = 0;
  let runId;
  let retriedEpisode;
  adapter.run = async (request) => {
    if (request.prompt.startsWith("Validate the proposed context")) {
      reviews++;
      assert.ok(reviews <= 4, "The fourth narrative attempt must pause.");
      if (reviews === 2) throw modelCatalogMiss(request);
      if (reviews === 4) {
        retriedEpisode = (await store.loadRun(runId)).availabilityRetry;
        throw outputExhaustion();
      }
      throw availabilityFailure();
    }
    return withModelCompletion(await runRole(request), request);
  };
  const runner = () =>
    createRunner({
      adapters: { codex: adapter },
      clarifications: createClarificationService({ interactive: false }),
      loadConfiguration: configurationLoader(),
      runStore: store,
      availabilityClock: () => now,
      availabilityWait: async (delay) => {
        now += delay;
      },
    });
  const { run: paused } = await runner().run({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: { worker: { model: "worker-model" } },
  });
  assert.equal(paused.pause.code, "ERR_MODEL_CATALOG_RETRY");
  assert.equal(paused.availabilityRetry.attempt, 1);
  runId = paused.runId;
  const { run: exhausted } = await runner().resume({ runId });
  assert.equal(exhausted.pause.reason, "output_exhausted");
  assert.equal(reviews, 4);
  assert.equal(retriedEpisode.id, paused.availabilityRetry.id);
  assert.equal(retriedEpisode.attempt, 2);
});

for (const published of [true, false]) {
  test(`a ${published ? "journaled" : "missing"} model receipt preserves completed writable work`, async (t) => {
    const fixture = await operatorFixture(t, "plan-execution");
    const lost = new Error("Model receipt publication was interrupted.");
    let runId;
    let interrupted = false;
    const store = createRunStore({
      stateRoot: fixture.stateRoot,
      async onTransitionBoundary(point) {
        if (
          published &&
          !interrupted &&
          point === "event-appended" &&
          runId !== undefined &&
          (await store.loadRun(runId)).modelCompletionReceipts.worker != null
        ) {
          interrupted = true;
          throw lost;
        }
      },
    });
    const candidateReached = Object.assign(new Error("Candidate reached."), {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    const delegate = createExecutionAdapter();
    let implementation;
    let writes = 0;
    let restatements = 0;
    const adapters = {
      codex: {
        ...delegate,
        async run(request) {
          if (request.prompt.includes("Original turn facts (runner data)")) {
            assert.equal(request.access, "read-only");
            restatements++;
            return { ...implementation, sessionId: "restated-worker" };
          }
          if (request.prompt.includes("Implement the changes described")) {
            assert.equal(request.access, "workspace-write");
            writes++;
            implementation = await delegate.run(request);
            return withModelCompletion(implementation, request);
          }
          if (writes > 0) throw candidateReached;
          return delegate.run(request);
        },
      },
    };
    const runner = runnerFor(fixture, adapters, {
      runStore: published
        ? store
        : {
            ...store,
            async recordModelCompletion() {
              interrupted = true;
              throw lost;
            },
          },
    });
    const { run } = await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: { worker: { model: "test-model" } },
    });
    runId = run.runId;
    if (!published) {
      await assert.rejects(runner.resume({ runId }), {
        code: "ERR_EXECUTION_RECEIPT_UNPUBLISHED",
        cause: lost,
      });
      const pending = await store.loadRun(runId);
      assert.equal(pending.pipelineState.writableResult.stage, "invoking");
      assert.equal(pending.activeTurn.phase, "implement");
    }
    const reopened = runnerFor(fixture, adapters);
    await assert.rejects((published ? runner : reopened).resume({ runId }), {
      code: candidateReached.code,
    });
    const candidate = await store.loadRun(runId);
    assert.equal(interrupted, true);
    assert.equal(
      Object.hasOwn(candidate.modelCompletionReceipts, "worker"),
      published,
    );
    assert.equal(candidate.pipelineState.writableResult, null);
    assert.equal(writes, 1);
    assert.equal(restatements, published ? 0 : 1);
  });
}

test("cold coding restatements retain the consumed attempt across a catalog pause", async (t) => {
  for (const pipelineId of ["plan-execution", "polishing"]) {
    const execution = pipelineId === "plan-execution";
    const fixture = await operatorFixture(t, pipelineId);
    const adapter = createExecutionAdapter();
    const runRole = adapter.run.bind(adapter);
    let findings = !execution;
    let writes = 0;
    let restatements = 0;
    adapter.run = async (request) => {
      const respond = (result) =>
        withModelCompletion(
          {
            structured:
              request.schema.properties.result === undefined
                ? result
                : { result },
            sessionId: `catalog-${writes}-${restatements}`,
          },
          request,
        );
      if (
        findings &&
        request.prompt.includes("Confirm the finalized change set")
      ) {
        findings = false;
        return respond({
          status: "FINDINGS",
          findings: [
            {
              id: "R1",
              file: "source.js",
              problem: "The candidate needs a repair.",
              reason: "The repair is required by the task.",
              suggestedAction: "Add the repair.",
            },
          ],
          validationChange: "UNCHANGED",
          validationEvidence: [],
          finalizationFindingIds: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        });
      }
      const original =
        request.access === "workspace-write" &&
        request.prompt.includes(
          execution
            ? "Implement the changes described"
            : "Resolve every current blocker",
        );
      if (original) {
        writes++;
        await writeFile(
          join(fixture.projectPath, "repair.txt"),
          "preserved bytes\n",
        );
        if (execution) assert.equal(await request.onFreshSession(), true);
        throw modelCatalogMiss({ recovery: true });
      }
      if (
        request.access === "read-only" &&
        (request.prompt.includes("Original turn facts (runner data)") ||
          request.prompt.includes("Finding-resolution report diagnostic batch"))
      ) {
        if (++restatements === 1) throw modelCatalogMiss();
        const inactiveFields = {
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
        return respond(
          execution
            ? {
                ...inactiveFields,
                status: "COMPLETED",
                summary: "Implemented the candidate.",
              }
            : {
                ...inactiveFields,
                status: "RESOLVED",
                decisions: [
                  {
                    id: "R1",
                    decision: "FIX",
                    reason: "Added the repair.",
                    evidence: [],
                  },
                ],
              },
        );
      }
      return withModelCompletion(await runRole(request), request);
    };
    const adapters = { codex: adapter };
    const runner = runnerFor(fixture, adapters);
    const { run: created } = await runner.create({
      pipelineId,
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: { worker: { model: "worker-model" } },
    });
    const { run: paused } = await runner.resume({ runId: created.runId });
    const field = execution ? "writableResult" : "resolutionCorrection";
    assert.equal(paused.pause?.reason, "backend_unavailable", pipelineId);
    assert.equal(paused.pipelineState[field].attempts, 1);
    assert.equal(paused.activeTurn, null);
    if (execution) assert.equal(paused.inactivityRecovery.attempt, 2);
    const store = createRunStore({ stateRoot: fixture.stateRoot });
    const interrupted = Object.assign(
      new Error("Resume acknowledgement was lost."),
      {
        code: "ERR_RUN_REVISION_CHANGED",
      },
    );
    const interruptedStore = {
      ...store,
      async transitionRun(lease, patch, options) {
        const next = await store.transitionRun(lease, patch, options);
        if (
          patch.pause === null &&
          patch.pipelineState?.workflowState === paused.pause.resumeState
        )
          throw interrupted;
        return next;
      },
    };
    await assert.rejects(
      runnerFor(fixture, adapters, { runStore: interruptedStore }).resume({
        runId: created.runId,
      }),
      (cause) => cause === interrupted,
    );
    assert.equal(restatements, 1);
    const resumed = await store.loadRun(created.runId);
    assert.equal(resumed.activeTurn, null);
    assert.equal(resumed.pause, null);
    assert.equal(resumed.pipelineState[field].attempts, 1);
    const { run: done } = await runnerFor(fixture, adapters, {
      runStore: createRunStore({ stateRoot: fixture.stateRoot }),
    }).resume({ runId: created.runId });
    assert.equal(done.pipelineState.workflowState, "DONE");
    assert.equal(writes, 1);
    assert.equal(restatements, 2);
    assert.equal(done.counters.fixRounds, execution ? 0 : 1);
    assert.equal(done.inactivityRecovery, null);
    assert.equal(
      await readFile(join(fixture.projectPath, "repair.txt"), "utf8"),
      "preserved bytes\n",
    );
    const history = await store.loadRunHistory(created.runId);
    assert.ok(
      history.events.every(
        ({ state }) => (state.pipelineState[field]?.attempts ?? 0) <= 1,
      ),
    );
    if (execution)
      assert.equal(
        history.events.filter(
          ({ activity }) => activity?.kind === "reconstructing",
        ).length,
        1,
      );
  }
});

for (const [pipelineId, kind, boundary, mode] of [
  ["plan-execution", "questions", "readback", "independent"],
  ["polishing", "questions", "publication", "combined"],
  ["plan-execution", "product-decision", "replacement", "combined"],
]) {
  test(`cold clarification append ${pipelineId} ${kind} survives ${boundary} loss`, async (t) => {
    const external =
      pipelineId === "plan-execution" && kind === "product-decision";
    const f = await clarificationAppendFixture(t, pipelineId, {
      kind,
      mode,
      external,
      questionFirst: external,
    });
    const service = createClarificationService({ interactive: false });
    const operation =
      kind === "questions" ? "appendQuestionRound" : "appendProductDecision";
    const failure = new Error("Controlled atomic editor publication loss.");
    let lost = false;
    const store = createRunStore({ stateRoot: f.stateRoot });
    const initial = f.open({
      store: {
        ...store,
        async transitionRun(lease, patch, options) {
          if (
            !lost &&
            boundary === "publication" &&
            patch.pipelineState?.pendingEdit != null &&
            patch.pipelineState.pendingClarificationAppend === null
          ) {
            lost = true;
            throw failure;
          }
          return store.transitionRun(lease, patch, options);
        },
      },
      clarifications: {
        ...service,
        async [operation](options) {
          if (boundary === "replacement") {
            return service[operation]({
              ...options,
              async persistAppend(proof) {
                await options.persistAppend(proof);
                lost = true;
                throw appendReadFailure();
              },
            });
          }
          const result = await service[operation](options);
          if (boundary === "readback") {
            lost = true;
            throw appendReadFailure();
          }
          return result;
        },
        openEditor(...args) {
          if (external && !lost) return service.openEditor(...args);
          assert.fail("No editor before atomic publication");
        },
      },
    });
    const runId = (await initial.runner.create(f.input)).run.runId;
    let answeredHash;
    if (external) {
      const questions = (await initial.runner.resume({ runId })).run;
      assert.equal(questions.pause.reason, "clarification_answers_required");
      const response = {
        runId,
        requestId: questions.pause.inputRequest.id,
        expectedRevision: questions.revision,
        answers: [{ questionId: "q1", answer: "Use behavior A." }],
      };
      const cold = f.open();
      const preview = await cold.runner.previewInput(response);
      const submitted = (
        await cold.runner.submitInput({
          ...response,
          responseHash: preview.responseHash,
        })
      ).run;
      answeredHash = submitted.pause.inputResponse.transcriptHash;
      assert.equal(answeredHash, preview.responseHash);
    }
    if (boundary === "publication")
      await assert.rejects(
        initial.runner.resume({ runId }),
        (error) => error === failure,
      );
    else
      assert.equal(
        (await initial.runner.resume({ runId })).run.pause.reason,
        "clarification_append_interrupted",
      );
    assert.equal(lost, true);
    const cold = f.open();
    const retained = await cold.store.loadRun(runId);
    const intent = retained.pipelineState.pendingClarificationAppend;
    assert.ok(intent);
    if (external) {
      assert.equal(retained.pipelineState.clarificationRoot, f.rootPath);
      assert.equal(
        retained.pipelineState.clarificationPath,
        join(
          f.rootPath,
          "LOCAL_ARTIFACTS",
          "agent-runner",
          runId,
          "clarifications.md",
        ),
      );
      assert.deepEqual(
        retained.pipelineState.repositoryBaseline.allowedPaths,
        [],
      );
      assert.equal(retained.hashes.executionClarifications, answeredHash);
      assert.equal(retained.pipelineState.clarificationFrozen, true);
      assert.equal(retained.counters.clarificationRounds, 1);
      assert.equal(
        (await readdir(f.projectPath)).includes("LOCAL_ARTIFACTS"),
        false,
      );
    }
    assert.equal(retained.pipelineState.pendingEdit, null);
    const counter =
      kind === "questions" ? "clarificationRounds" : "productDecisions";
    assert.equal(retained.counters[counter], 0);
    const priorBytes = await f.transcript(retained);
    assert.equal(
      transcriptHash(priorBytes),
      boundary === "replacement" ? intent.expectedHash : intent.resultHash,
    );
    const calls = f.calls.length;
    const waiting = (await cold.runner.resume({ runId })).run;
    assert.equal(
      waiting.pause.reason,
      kind === "questions"
        ? "clarification_answers_required"
        : "product_decision_required",
    );
    assert.equal(waiting.pipelineState.pendingClarificationAppend, null);
    assert.equal(waiting.counters[counter], 1);
    assert.equal(
      waiting.pipelineState.pendingEdit.preEditorHash,
      intent.resultHash,
    );
    assert.equal(
      waiting.pause.inputRequest.id,
      waiting.pipelineState.pendingEdit.id,
    );
    assert.equal(
      transcriptHash(await f.transcript(waiting)),
      intent.resultHash,
    );
    const repeated = (await f.open().runner.resume({ runId })).run;
    assert.equal(repeated.counters[counter], 1);
    assert.equal(
      transcriptHash(await f.transcript(repeated)),
      intent.resultHash,
    );
    assert.deepEqual(
      repeated.pipelineState.workReports,
      waiting.pipelineState.workReports,
    );
    assert.deepEqual(repeated.sessionLineage, waiting.sessionLineage);
    assert.equal(f.calls.length, calls);
    const history = await cold.store.loadRunHistory(runId);
    const publications = history.events.filter(
      ({ state }, index, events) =>
        index > 0 &&
        events[index - 1].state.pipelineState.pendingClarificationAppend
          ?.expectedHash === intent.expectedHash &&
        state.pipelineState.pendingClarificationAppend === null,
    );
    assert.equal(
      publications.length,
      1,
      "Only one transition may settle the append",
    );
    const published = publications[0].state;
    assert.equal(published.counters[counter], 1);
    assert.equal(
      published.pause.inputRequest.id,
      published.pipelineState.pendingEdit.id,
    );
    assert.equal(
      published.pipelineState.pendingEdit.preEditorHash,
      intent.resultHash,
    );
  });
}

const SECOND_PLAN = `${PLAN}

## Commit 2: fix(test): refine behavior

Refine the behavior.
`;

test("combined changed BLOCKED pauses atomically and cold-resumes without replaying accepted work", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  await writeFile(join(fixture.taskPath, "plan.md"), SECOND_PLAN);
  const adapter = createExecutionAdapter();
  const original = adapter.run.bind(adapter);
  let step = 0;
  let repairs = 0;
  let confirmations = 0;
  let sessions = 0;
  let beforeRepair;
  let runId;
  const runStore = createRunStore({ stateRoot: fixture.stateRoot });
  const turns = [];
  adapter.run = async (request) => {
    if (request.prompt.includes("Implement the changes described"))
      step = requestedStepAssessment(request).step;
    turns.push([step, request.schema, request.access]);
    const respond = (result) => ({
      structured: result,
      sessionId: request.session?.id ?? `combined-${++sessions}`,
    });
    if (request.schema === CHECK_AND_FIX_SCHEMA) {
      if (step === 2 && confirmations === 1 && repairs === 0) {
        beforeRepair = await runStore.loadRun(runId);
        repairs++;
        await writeFile(
          join(fixture.projectPath, "candidate.txt"),
          "candidate repair\n",
        );
        return respond({
          status: "BLOCKED",
          summary: "",
          reason: "A required external resource is unavailable.",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: ["The synthetic resource is offline."],
        });
      }
      return respond(checkAndFix());
    }
    if (request.schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA) {
      assert.equal(request.access, "read-only");
      const {
        validationChange,
        validationEvidence,
        finalizationFindingIds,
        ...candidate
      } =
        step === 2 && ++confirmations === 1
          ? cleanConfirmationFindings("R1", "R2")
          : cleanConfirmation();
      return respond(candidate);
    }
    const response = await original(request);
    if (
      step === 2 &&
      request.prompt.includes("Implement the changes described")
    )
      await writeFile(
        join(fixture.projectPath, "feature.js"),
        "export const value = 2;\n",
      );
    return response;
  };
  const configuration = {
    ...RUNNER_CONFIGURATION,
    pipelines: { "plan-execution": { mode: "combined" } },
  };
  const runner = runnerFor(
    fixture,
    { codex: adapter },
    { configuration, runStore },
  );
  const { run: created } = await runner.create({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
  });
  runId = created.runId;
  const paused = (await runner.resume({ runId: created.runId })).run;
  assert.equal(
    paused.pause.reason,
    "environment_blocked",
    JSON.stringify(paused.pause),
  );
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.equal(paused.pipelineState.completedCommits.length, 1);
  const [accepted] = paused.pipelineState.completedCommits;
  assert.equal(paused.pipelineState.repositoryBaseline.head, accepted);
  assert.equal(beforeRepair.counters.fixRounds, 1);
  assert.equal(paused.pipelineState.pendingCorrection, true);
  for (const field of [
    "completedCommits",
    "stepImplementation",
    "correctionHistory",
    "sameFindingRounds",
    "disputeHistory",
    "findingArbitrations",
    "replacementExecution",
    "settings",
  ])
    assert.deepEqual(
      paused.pipelineState[field],
      beforeRepair.pipelineState[field],
      field,
    );
  assert.notEqual(
    paused.pipelineState.repositoryBaseline.contentFingerprint,
    beforeRepair.pipelineState.repositoryBaseline.contentFingerprint,
  );
  assert.equal(paused.counters.fixRounds, beforeRepair.counters.fixRounds + 1);
  assert.equal(
    paused.counters.correctionRounds,
    beforeRepair.counters.correctionRounds,
  );
  assert.deepEqual(paused.pipelineState.primaryFindings, []);
  const findingReport = paused.pipelineState.workReports.findLast(
    ({ phase }) => phase === "CLEAN_CONFIRM",
  );
  assert.deepEqual(
    findingReport.findings.map(({ id }) => id),
    ["R1", "R2"],
  );
  for (const field of [
    "candidateConfirmationFingerprint",
    "candidateReviewResult",
    "finalizationResult",
    "reviewResult",
  ])
    assert.equal(paused.pipelineState[field], null, field);
  const blockedReport = paused.pipelineState.workReports.at(-1);
  assert.equal(blockedReport.phase, "CHECK_AND_FIX");
  assert.equal(blockedReport.status, "BLOCKED");
  assert.equal(blockedReport.reason, paused.pause.explanation);
  assert.deepEqual(blockedReport.evidence, paused.pause.evidence);
  assert.equal(
    await readFile(join(fixture.projectPath, "candidate.txt"), "utf8"),
    "candidate repair\n",
  );

  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const saved = await store.loadRun(created.runId);
  assert.equal(saved.activeTurn, null);
  assert.equal(await store.runIsLeased(saved.runId), false);
  assert.deepEqual(saved, paused);
  const history = await store.loadRunHistory(saved.runId);
  const publication = history.events.find(
    ({ state }) => state.pause?.reason === "environment_blocked",
  );
  assert.deepEqual(
    publication.state.pipelineState.workReports.at(-1),
    blockedReport,
  );
  const beforeResume = turns.length;
  const cold = runnerFor(
    fixture,
    { codex: adapter },
    { configuration, runStore: store },
  );
  const done = (await cold.resume({ runId: saved.runId, action: null })).run;
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.deepEqual(done.roles, saved.roles);
  assert.deepEqual(done.hashes, saved.hashes);
  assert.deepEqual(done.pipelineState.settings, saved.pipelineState.settings);
  assert.deepEqual(
    done.pipelineState.correctionHistory.slice(
      0,
      saved.pipelineState.correctionHistory.length,
    ),
    saved.pipelineState.correctionHistory,
  );
  assert.deepEqual(
    done.pipelineState.workReports.find(({ status }) => status === "BLOCKED"),
    blockedReport,
  );
  assert.equal(done.pipelineState.completedCommits.length, 2);
  assert.equal(done.pipelineState.completedCommits[0], accepted);
  // A renewed unchanged check/fix is a new round; recovery never recharges the repair.
  assert.equal(done.counters.fixRounds, saved.counters.fixRounds + 1);
  assert.equal(done.counters.correctionRounds, saved.counters.correctionRounds);
  assert.equal(repairs, 1);
  const resumedGates = turns
    .slice(beforeResume)
    .filter(
      ([, schema, access]) =>
        access === "local-commit" ||
        [
          CHECK_AND_FIX_SCHEMA,
          CANDIDATE_CLEAN_CONFIRM_SCHEMA,
          CANDIDATE_REVIEW_SCHEMA,
          FINALIZATION_SCHEMA,
          REVIEW_SCHEMA,
        ].includes(schema),
    );
  assert.deepEqual(
    resumedGates.map(([, schema, access]) =>
      access === "local-commit" ? "commit" : schema,
    ),
    [
      CHECK_AND_FIX_SCHEMA,
      CANDIDATE_CLEAN_CONFIRM_SCHEMA,
      CANDIDATE_REVIEW_SCHEMA,
      FINALIZATION_SCHEMA,
      REVIEW_SCHEMA,
      "commit",
    ],
  );
  const completedHistory = await store.loadRunHistory(saved.runId);
  const commitGate = completedHistory.events.findLast(
    ({ state }) => state.pipelineState.workflowState === "COMMIT",
  ).state;
  assert.deepEqual(
    commitGate.pipelineState.stepImplementation,
    saved.pipelineState.stepImplementation,
  );
  assert.equal(
    commitGate.pipelineState.candidateConfirmationFingerprint,
    saved.pipelineState.repositoryBaseline.contentFingerprint,
  );
  assert.equal(
    commitGate.pipelineState.candidateReviewedFingerprint,
    commitGate.pipelineState.candidateConfirmationFingerprint,
  );
  assert.equal(
    commitGate.pipelineState.reviewedFingerprint,
    commitGate.pipelineState.finalizedFingerprint,
  );
  assert.equal(
    turns.filter(([, , access]) => access === "local-commit").length,
    2,
  );
  const git = (...args) =>
    executeFile("git", ["-C", fixture.projectPath, ...args]);
  assert.equal((await git("rev-parse", "HEAD^")).stdout.trim(), accepted);
  assert.equal((await git("rev-list", "--count", "HEAD")).stdout.trim(), "3");
  assert.equal(
    await readFile(join(fixture.projectPath, "candidate.txt"), "utf8"),
    "candidate repair\n",
  );
});

test("reconstructed readiness rejection preserves work and agrees across CLI and MCP", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const git = createGitService();
  const before = await git.snapshot({ projectPath: fixture.projectPath });
  const adapter = createExecutionAdapter();
  const run = adapter.run.bind(adapter);
  let readinessTurns = 0;
  adapter.run = async (request) => {
    if (request.access !== "local-commit") return run(request);
    readinessTurns += 1;
    throw new ClaudeAdapterError("PRIVATE_READINESS_VALUE", {
      code: "ERR_CLAUDE_LOCAL_COMMIT_POLICY",
      diagnosticClass: "commit_readiness_extra_fields",
      effectStarted: false,
    });
  };
  let verifications = 0;
  const runtimeGit = {
    ...git,
    async verifyCommit(authorization) {
      if (++verifications === 1)
        throw Object.assign(new Error("Verification interrupted."), {
          code: "ERR_TEST_COMMIT_VERIFICATION",
        });
      return git.verifyCommit(authorization);
    },
  };
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const openRunner = () =>
    runnerFor(
      fixture,
      { claude: adapter },
      {
        configuration: { schemaVersion: 1, defaultBackend: "claude" },
        git: runtimeGit,
        runStore: store,
      },
    );
  const runner = openRunner();
  const { run: created } = await runner.create({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
  });
  const runId = created.runId;
  const interrupted = (await runner.resume({ runId })).run;
  assert.equal(interrupted.pause.code, "ERR_TEST_COMMIT_VERIFICATION");
  assert.equal(interrupted.pipelineState.pendingCommit.status, "consumed");
  const candidate = await git.snapshot({ projectPath: fixture.projectPath });
  const paused = (await openRunner().resume({ runId })).run;
  assert.equal(paused.pause.diagnosticClass, "commit_readiness_extra_fields");
  assert.equal(paused.pipelineState.pendingCommit, null);
  for (const field of ["finalizedFingerprint", "reviewedFingerprint"]) {
    assert.equal(paused.pipelineState[field], interrupted.pipelineState[field]);
  }
  assert.deepEqual(paused.counters, interrupted.counters);
  assert.equal(candidate.head, before.head);
  assert.deepEqual(
    await git.snapshot({ projectPath: fixture.projectPath }),
    candidate,
  );

  const control = createMcpControlPlane({
    runner: openRunner(),
    runStore: store,
  });
  const status = await control.runStatus({ runId });
  const waited = await control.runWait({ runId, cursor: 0, timeoutMs: 0 });
  assert.deepEqual(waited.pause, status.pause);
  assert.deepEqual(status.pause.nextActions, [
    { type: "start-new-run", requirement: "resolved-commit-readiness" },
  ]);
  assert.equal(status.pause.resumeState, null);
  let output = "";
  assert.equal(
    await main(["status", "--run", runId], {
      runner: openRunner(),
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
  assert.match(output, /This run cannot retry COMMIT/u);
  assert.doesNotMatch(
    output,
    /Retry with:|uncontaminated worktree|PRIVATE_READINESS/u,
  );
  const activity = await control.runActivity({ runId, cursor: 0, limit: 100 });
  assert.ok(
    activity.activities.some(
      ({ kind, message }) =>
        kind === "authorization-retired" &&
        message.includes("commit_readiness_extra_fields"),
    ),
  );
  const saved = JSON.stringify(await store.loadRunHistory(runId));
  assert.doesNotMatch(saved, /PRIVATE_READINESS/u);
  const turns = adapter.calls.length;
  const probes = adapter.probes.length;
  await assert.rejects(openRunner().resume({ runId }), {
    code: "ERR_INAPPLICABLE_RESUME_ACTION",
  });
  assert.equal(adapter.calls.length, turns);
  assert.equal(adapter.probes.length, probes);
  assert.equal(readinessTurns, 1);
  assert.equal(verifications, 2);
  assert.equal((await store.loadRun(runId)).revision, paused.revision);
});

test("durable writable-result recovery preserves an accepted commit and candidate without replay", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  await writeFile(join(fixture.taskPath, "plan.md"), SECOND_PLAN);
  const adapter = createExecutionAdapter();
  const run = adapter.run.bind(adapter);
  let writes = 0;
  let restatements = 0;
  adapter.run = async (request) => {
    const writableSchema = request.schema?.properties?.result?.anyOf?.some(
      (branch) => branch.properties.status?.enum?.includes("COMPLETED"),
    );
    if (!writableSchema || requestedStepAssessment(request)?.step !== 2)
      return run(request);
    const result = {
      status: "COMPLETED",
      summary: "Implemented the second step.",
      reason: "",
      question: "",
      options: [],
      whyBlocked: "",
      evidence: [],
    };
    if (request.access === "workspace-write") {
      writes++;
      await writeFile(
        join(fixture.projectPath, "candidate.txt"),
        "preserved candidate bytes\n",
      );
      result.reason = "PRIVATE_REJECTED_VALUE";
    } else {
      restatements++;
      if (restatements === 1) result.reason = "PRIVATE_REJECTED_VALUE";
    }
    return {
      structured: { result },
      sessionId: `result-${writes}-${restatements}`,
    };
  };
  const adapters = { codex: adapter };
  const runner = runnerFor(fixture, adapters);
  const runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
    })
  ).run.runId;
  const paused = (await runner.resume({ runId })).run;
  assert.equal(paused.pause.reason, "writable_output_invalid");
  assert.equal(paused.pipelineState.completedCommits.length, 1);
  const [accepted] = paused.pipelineState.completedCommits;
  assert.equal(
    (
      await executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"])
    ).stdout.trim(),
    accepted,
  );
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const saved = await store.loadRun(runId);
  assert.equal(saved.pipelineState.writableResult.attempts, 1);
  assert.equal(saved.pipelineState.writableResult.additionalAttempts, 0);
  assert.equal(saved.activeTurn, null);
  assert.equal(saved.pipelineState.pendingCommit, null);
  assert.equal(
    await readFile(join(fixture.projectPath, "candidate.txt"), "utf8"),
    "preserved candidate bytes\n",
  );
  assert.doesNotMatch(JSON.stringify(saved), /PRIVATE_REJECTED_VALUE/u);
  const reconstructed = runnerFor(fixture, adapters, { runStore: store });
  const done = (
    await reconstructed.resume({ runId, expectedRevision: saved.revision })
  ).run;
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(done.pipelineState.completedCommits.length, 2);
  assert.equal(done.pipelineState.completedCommits[0], accepted);
  assert.equal(done.counters.fixRounds, 0);
  assert.equal(done.pipelineState.writableResult, null);
  assert.equal(writes, 1);
  assert.equal(restatements, 2);
  assert.equal(
    (
      await executeFile("git", [
        "-C",
        fixture.projectPath,
        "rev-list",
        "--count",
        "HEAD",
      ])
    ).stdout.trim(),
    "3",
  );
});

test("durable finding-resolution recovery restates a lost writable report without replay", async (t) => {
  const fixture = await operatorFixture(t, "polishing");
  const git = (...args) =>
    executeFile("git", ["-C", fixture.projectPath, ...args]);
  const initialHead = (await git("rev-parse", "HEAD")).stdout.trim();
  const snapshot = join(fixture.workspace, "captured-state");
  const original = createRunStore({ stateRoot: fixture.stateRoot });
  const adapter = createExecutionAdapter();
  const run = adapter.run.bind(adapter);
  const decision = (reason) => ({
    status: "RESOLVED",
    decisions: [{ id: "R1", decision: "FIX", reason, evidence: [] }],
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  });
  let runId;
  let terminalReviews = 0;
  let writes = 0;
  let restatements = 0;
  adapter.run = async (request) => {
    const respond = (result) => ({
      structured:
        request.schema?.properties?.result?.anyOf === undefined
          ? result
          : { result },
      sessionId: `resolution-${writes}-${restatements}`,
    });
    if (
      request.prompt.includes("Confirm the finalized change set") &&
      ++terminalReviews === 1
    )
      return respond({
        status: "FINDINGS",
        findings: [
          {
            id: "R1",
            file: "source.js",
            problem: "The change lacks a required repair.",
            reason: "The repair keeps the change complete.",
            suggestedAction: "Add the repair.",
          },
        ],
        validationChange: "UNCHANGED",
        validationEvidence: [],
        finalizationFindingIds: [],
        question: "",
        options: [],
        whyBlocked: "",
        evidence: [],
      });
    if (!request.prompt.includes("Resolve every current blocker"))
      return run(request);
    if (request.access === "read-only") {
      restatements++;
      return respond(
        decision(
          restatements === 1
            ? "First line PRIVATE_RESTATED_VALUE.\nSecond line."
            : "Added the repair.",
        ),
      );
    }
    assert.equal(request.access, "workspace-write");
    writes++;
    await writeFile(
      join(fixture.projectPath, "repair.txt"),
      "repaired candidate bytes\n",
    );
    const stopped = new Promise((resolve, reject) =>
      request.signal.addEventListener(
        "abort",
        () => reject(request.signal.reason),
        { once: true },
      ),
    );
    // Attach rejection handling before the stop can abort this call.
    stopped.catch(() => {});
    // Capture the journal while the writable original is still in progress.
    await cp(fixture.stateRoot, snapshot, { recursive: true });
    await removeCopiedLeases(snapshot);
    await original.requestOperatorStop({
      runId,
      kind: "pause_requested",
      expectedRevision: (await original.loadRun(runId)).revision,
      idempotencyKey: "resolution-capture",
    });
    return stopped;
  };
  const adapters = { codex: adapter };
  const runner = runnerFor(fixture, adapters, { runStore: original });
  runId = (
    await runner.create({
      pipelineId: "polishing",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
    })
  ).run.runId;
  const stopped = (await runner.resume({ runId, action: null })).run;
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.equal(writes, 1);
  assert.equal(restatements, 0);

  await rm(fixture.stateRoot, { recursive: true, force: true });
  await cp(snapshot, fixture.stateRoot, { recursive: true });
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  });
  const restored = await store.loadRun(runId);
  assert.equal(restored.pipelineState.workflowState, "RESOLVE_FINDINGS");
  assert.notEqual(restored.activeTurn, null);
  assert.equal(await store.runIsLeased(runId), false);
  assert.equal(restored.pipelineState.resolutionCorrection.stage, "invoking");
  assert.equal(restored.counters.fixRounds, 0);
  const reconstructed = runnerFor(fixture, adapters, { runStore: store });
  const paused = (await reconstructed.resume({ runId, action: null })).run;
  assert.equal(paused.pause.reason, "resolution_output_invalid");
  assert.equal(writes, 1);
  assert.equal(restatements, 1);
  const saved = await store.loadRun(runId);
  assert.equal(saved.pipelineState.resolutionCorrection.attempts, 1);
  assert.equal(saved.counters.fixRounds, 1);
  assert.equal(saved.activeTurn, null);
  assert.equal(
    await readFile(join(fixture.projectPath, "repair.txt"), "utf8"),
    "repaired candidate bytes\n",
  );
  assert.doesNotMatch(JSON.stringify(saved), /PRIVATE_RESTATED_VALUE/u);

  const done = (
    await reconstructed.resume({
      runId,
      action: null,
      expectedRevision: saved.revision,
    })
  ).run;
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(done.pipelineState.resolutionCorrection, null);
  assert.equal(done.counters.fixRounds, 1);
  assert.equal(writes, 1);
  assert.equal(restatements, 2);
  assert.equal((await git("rev-parse", "HEAD")).stdout.trim(), initialHead);
  assert.equal(
    (await git("diff", "--cached", "--name-only")).stdout,
    "feature.js\nrepair.txt\nsource.js\n",
  );
  assert.equal((await git("diff", "--name-only")).stdout, "");
});

const checkpointWorkspaces = [];
let oneStepCheckpoint;
let twoStepCheckpoint;

async function removeCopiedLeases(directoryPath) {
  const entries = await readdir(directoryPath, { withFileTypes: true });
  await Promise.all(
    entries.map(async (entry) => {
      const path = join(directoryPath, entry.name);
      if (entry.isDirectory()) {
        await removeCopiedLeases(path);
      } else if ([".lease", ".lease-reclaiming"].includes(entry.name)) {
        await rm(path, { force: true });
      }
    }),
  );
}

async function createCommitCheckpoint(plan) {
  const workspace = await mkdtemp(
    join(tmpdir(), "agent-runner-effect-checkpoint-"),
  );
  checkpointWorkspaces.push(workspace);
  const fixture = {
    projectPath: join(workspace, "project"),
    stateRoot: join(workspace, "state"),
    taskPath: join(workspace, "task"),
    workspace,
  };
  const stateSnapshot = join(workspace, "prepared-state");
  const configPath = join(
    fixture.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner.json",
  );
  await Promise.all([
    mkdir(join(fixture.projectPath, "LOCAL_ARTIFACTS"), { recursive: true }),
    mkdir(fixture.taskPath),
  ]);
  await executeFile("git", ["init", "-q", fixture.projectPath]);
  await Promise.all([
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(
      join(fixture.projectPath, "source.js"),
      "export const value = 0;\n",
    ),
    writeFile(configPath, '{"schemaVersion":1}\n'),
    writeFile(join(fixture.taskPath, "task.md"), "Implement the behavior.\n"),
    writeFile(join(fixture.taskPath, "plan.md"), plan),
  ]);
  for (const args of [
    ["config", "user.name", "Test"],
    ["config", "user.email", "test@example.com"],
    ["add", ".gitignore", "source.js"],
    ["commit", "-qm", "chore(test): initialize"],
  ]) {
    await executeFile("git", ["-C", fixture.projectPath, ...args]);
  }
  const initialHead = (
    await executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"])
  ).stdout.trim();
  const git = createGitService();
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  });
  let captured = false;
  const runner = runnerFor(
    fixture,
    { codex: createExecutionAdapter() },
    {
      runStore: store,
      git: {
        ...git,
        async prepareCommit(options) {
          return git.prepareCommit({
            ...options,
            persistPendingCommit: async (authorization) => {
              await options.persistPendingCommit(authorization);
              if (!captured) {
                captured = true;
                // Reuse the real workflow's durable commit boundary without
                // replaying its clarification, bootstrap, and review turns.
                await cp(fixture.stateRoot, stateSnapshot, {
                  recursive: true,
                });
                const current = await store.loadRun(runId);
                await store.requestOperatorStop({
                  runId,
                  kind: "pause_requested",
                  timing: "after-current-commit",
                  expectedRevision: current.revision,
                  idempotencyKey: "checkpoint-capture",
                });
              }
            },
          });
        },
      },
    },
  );
  const runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  const completed = (await runner.resume({ runId, action: null })).run;
  assert.equal(completed.pause.reason, "operator_paused");
  assert.equal(completed.pipelineState.completedCommits.length, 1);
  assert.equal(captured, true);
  await removeCopiedLeases(stateSnapshot);

  return {
    async restore() {
      await executeFile("git", [
        "-C",
        fixture.projectPath,
        "reset",
        "--hard",
        initialHead,
      ]);
      await rm(join(fixture.projectPath, "feature.js"), { force: true });
      await writeFile(
        join(fixture.projectPath, "feature.js"),
        "export const value = 1;\n",
      );
      await rm(fixture.stateRoot, { recursive: true, force: true });
      await cp(stateSnapshot, fixture.stateRoot, { recursive: true });
      const restored = await createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
      }).loadRun(runId);
      assert.equal(restored.pipelineState.workflowState, "COMMIT");
      assert.equal(restored.pipelineState.pendingCommit.status, "prepared");
      assert.equal(restored.pipelineState.currentStep, 1);
      assert.deepEqual(restored.pipelineState.completedCommits, []);
      assert.equal(restored.stopRequest, null);
      assert.equal(restored.activeTurn, null);
      assert.equal(restored.executionProcess, null);
      assert.equal(restored.executionResource, null);
      return { ...fixture, configPath, runId };
    },
  };
}

before(async () => {
  oneStepCheckpoint = await createCommitCheckpoint(PLAN);
  twoStepCheckpoint = await createCommitCheckpoint(SECOND_PLAN);
});

after(async () => {
  await Promise.all(
    checkpointWorkspaces.map((workspace) =>
      rm(workspace, { recursive: true, force: true }),
    ),
  );
});

test("dispatches plan execution through the root Git and state services", async (t) => {
  const fixture = await createFixture(t);
  await Promise.all([
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(
      join(fixture.projectPath, "source.js"),
      "export const value = 0;\n",
    ),
    writeFile(join(fixture.taskPath, "plan.md"), PLAN),
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.name",
    "Test User",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.email",
    "test@example.com",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "add",
    ".gitignore",
    "source.js",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "commit",
    "-qm",
    "chore(test): initialize",
  ]);
  const adapter = createExecutionAdapter({ bootstrapDisagreement: true });
  const arbiter = createArbiterAdapter();
  const activities = [];
  const runner = runnerFor(
    fixture,
    { codex: adapter, claude: arbiter },
    {
      activities,
      configuration: {
        ...RUNNER_CONFIGURATION,
        profiles: {
          "codex-work": { backend: "codex", profile: "work" },
        },
        pipelines: {
          "plan-execution": {
            roles: { arbiter: { backend: "claude" } },
          },
        },
      },
    },
  );

  const result = await runner.run({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: { arbiter: { profile: "current" } },
    executionOverrides: {
      profile: "codex-work",
      model: "execution-model",
      contextSize: "200000",
    },
    sourceSession: null,
  });
  const { stdout } = await executeFile("git", [
    "-C",
    fixture.projectPath,
    "log",
    "-1",
    "--pretty=%s",
  ]);

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.pipelineState.completedCommits.length, 1);
  assert.equal(stdout.trim(), "feat(test): add behavior");
  assert.equal(arbiter.probeCalls, 1);
  assert.equal(arbiter.calls.length, 1);
  assert.ok(adapter.calls.some(({ access }) => access === "local-commit"));
  assert.deepEqual(
    adapter.probes,
    Array.from({ length: 3 }, () => ({
      profile: "work",
      model: "execution-model",
      contextSize: "200000",
      effort: "current",
    })),
  );
  assert.ok(
    activities.some(
      ({ actor, phase, kind }) =>
        actor === "worker" && phase === "commit" && kind === "created",
    ),
  );
});

async function assertVerifiedCommitSettlement(t) {
  for (const drift of [false, true]) {
    await t.test(drift ? "configuration drift" : "next step", async () => {
      const checkpoint = drift ? oneStepCheckpoint : twoStepCheckpoint;
      const fixture = await checkpoint.restore();
      const store = createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
      });
      const git = createGitService();
      const delegate = createExecutionAdapter();
      let verifiedCalls = 0,
        commits = 0,
        callsAfterVerification = 0;
      let control, stopInput, receipt;
      const runner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run(request) {
              if (verifiedCalls > 0) callsAfterVerification += 1;
              if (request.access === "local-commit") {
                assert.equal(request.signal.aborted, false);
                commits += 1;
              }
              return delegate.run(request);
            },
          },
        },
        {
          runStore: store,
          git: {
            ...git,
            async consumeCommit(authorization, options) {
              const current = await store.loadRun(fixture.runId);
              stopInput = {
                runId: fixture.runId,
                timing: "after-current-commit",
                expectedRevision: current.revision,
                idempotencyKey: `deferred-stop-${drift}`,
              };
              receipt = await control.runPause(stopInput);
              return git.consumeCommit(authorization, options);
            },
            async verifyCommit(authorization) {
              const verified = await git.verifyCommit(authorization);
              verifiedCalls += 1;
              if (drift)
                await writeFile(
                  fixture.configPath,
                  '{"schemaVersion":1,"artifactRoot":"changed"}\n',
                );
              return verified;
            },
          },
        },
      );
      control = createMcpControlPlane({ runner, runStore: store });

      const stopped = (
        await runner.resume({ runId: fixture.runId, action: null })
      ).run;
      assert.deepEqual(await control.runPause(stopInput), receipt);
      assert.equal(stopped.pause.reason, "operator_paused");
      assert.equal(
        stopped.pause.operatorResume.workflowState,
        drift ? "WAITING_FOR_USER" : "IMPLEMENT",
      );
      if (drift)
        assert.equal(
          stopped.pause.operatorResume.pause.reason,
          "project_configuration_changed",
        );
      assert.equal(stopped.pipelineState.currentStep, drift ? null : 2);
      assert.equal(stopped.pipelineState.completedCommits.length, 1);
      assert.equal(
        stopped.pipelineState.repositoryBaseline.head,
        stopped.pipelineState.completedCommits[0],
      );
      assert.equal(stopped.pipelineState.pendingCommit, null);
      assert.equal(stopped.activeTurn, null);
      assert.equal(stopped.stopRequest.targetBoundary.step, 1);
      assert.equal(stopped.stopRequest.effectiveTiming, "after-current-commit");
      assert.equal(stopped.stopRequest.reconciledRevision, stopped.revision);
      assert.deepEqual(stopped.stopRequest.settlement, {
        kind: "commit",
        commit: stopped.pipelineState.completedCommits[0],
      });
      const status = await control.runStatus({ runId: fixture.runId });
      assert.equal(status.stop.state, "settled");
      assert.deepEqual(status.stop.settlement, stopped.stopRequest.settlement);
      const waited = await control.runWait({
        runId: fixture.runId,
        cursor: 0,
        timeoutMs: 0,
      });
      assert.deepEqual(waited.stop, status.stop);
      const activity = await control.runActivity({
        runId: fixture.runId,
        cursor: 0,
        limit: 100,
      });
      assert.ok(
        activity.activities.some((entry) => entry.stop?.state === "settled"),
      );
      assert.equal(verifiedCalls, 1);
      assert.equal(commits, 1);
      assert.equal(callsAfterVerification, 0);
      const history = await store.loadRunHistory(fixture.runId);
      const progress = history.events.filter(
        (event) => event.state.pipelineState.completedCommits.length > 0,
      );
      assert.ok(progress.length > 0);
      assert.equal(
        progress[0].state.stopRequest.reconciledRevision,
        progress[0].revision,
      );
    });
  }
}

test("interrupted verified checkpoint publication preserves progress without replaying the commit", async () => {
  const fixture = await oneStepCheckpoint.restore();
  let interrupt = true;
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    onTransitionBoundary: async (point) => {
      if (
        interrupt &&
        point === "event-appended" &&
        (await store.loadRun(fixture.runId)).pipelineState.completedCommits
          .length === 1
      ) {
        interrupt = false;
        throw new Error("verified publication interrupted");
      }
    },
  });
  const delegate = createExecutionAdapter();
  let commits = 0;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (request.access === "local-commit") commits += 1;
          return delegate.run(request);
        },
      },
    },
    { runStore: store },
  );
  await assert.rejects(
    runner.resume({ runId: fixture.runId, action: null }),
    /verified publication interrupted/u,
  );
  const persisted = await store.loadRun(fixture.runId);
  assert.equal(persisted.pipelineState.workflowState, "DONE");
  assert.equal(persisted.pipelineState.completedCommits.length, 1);
  assert.equal(persisted.pipelineState.pendingCommit, null);
  assert.equal(
    (await runner.resume({ runId: fixture.runId, action: null })).run
      .pipelineState.workflowState,
    "DONE",
  );
  assert.equal(commits, 1);
});

test("version-18 consumed-commit recovery retires interrupted observations without another provider turn", async () => {
  const fixture = await oneStepCheckpoint.restore();
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const directoryPath = await store.getRunDirectory(fixture.runId);
  const eventsPath = join(directoryPath, "events.jsonl");
  const delegate = createExecutionAdapter();
  let interruptedEvents;
  const completed = await runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          const response = await delegate.run(request);
          // Capture a crash after the effect but before observation settlement.
          interruptedEvents = (await readFile(eventsPath, "utf8"))
            .trimEnd()
            .split("\n")
            .map(JSON.parse);
          return response;
        },
      },
    },
    { runStore: store },
  ).resume({ runId: fixture.runId, action: null });
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  for (const event of interruptedEvents) {
    event.schemaVersion = event.state.schemaVersion = 18;
    event.state.runtimeCompatibility.runStateVersion = 18;
    if (event.state.observations !== null) {
      event.state.observations.schemaVersion = 1;
      for (const attempt of event.state.observations.attempts)
        delete attempt.ownershipDiagnostic;
    }
    delete event.state.workspace;
    for (const attempt of event.state.observations?.attempts ?? [])
      delete attempt.measurements;
  }
  const interrupted = interruptedEvents.at(-1).state;
  const attempt = interrupted.observations.attempts.at(-1);
  assert.equal(interrupted.pipelineState.pendingCommit.status, "consumed");
  assert.deepEqual(interrupted.activeTurn, { role: "worker", phase: "commit" });
  assert.equal(attempt.status, "active");
  const source = interruptedEvents.map(JSON.stringify).join("\n") + "\n";
  await writeFile(eventsPath, source);
  await writeFile(
    join(directoryPath, "state.json"),
    JSON.stringify(interrupted),
  );

  const recovered = await runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run() {
          assert.fail("Consumed-commit recovery must only verify the effect.");
        },
      },
    },
    { runStore: store },
  ).resume({ runId: fixture.runId, action: null });
  assert.equal(recovered.run.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    recovered.run.pipelineState.completedCommits,
    completed.run.pipelineState.completedCommits,
  );
  assert.equal(recovered.run.pipelineState.pendingCommit, null);
  assert.equal(recovered.run.activeTurn, null);
  assert.deepEqual(recovered.run.observations, {
    ...interrupted.observations,
    attempts: [
      ...interrupted.observations.attempts.slice(0, -1),
      { ...attempt, status: "interrupted", accounting: "incomplete" },
    ],
  });
  assert.equal(recovered.observations.attempts.at(-1).status, "interrupted");
  assert.equal(recovered.observations.attempts.at(-1).measurements, null);
  assert.ok((await readFile(eventsPath, "utf8")).startsWith(source));
});

test("commit-boundary capability requires a selected plan-execution step", async () => {
  // State-store coverage owns the stop kind, timing, rejection, and quiescent
  // matrix; runner stop coverage owns writable-content reconstruction.
  // Keep the pipeline-owned boundary policy at its direct deterministic seam.
  const fixture = await oneStepCheckpoint.restore();
  const run = await createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  }).loadRun(fixture.runId);
  assert.deepEqual(resolveStopBoundary(run), {
    capability: "verified-commit-v1",
    step: 1,
    completedCommits: 0,
    baselineHead: run.pipelineState.repositoryBaseline.head,
  });
  assert.equal(
    resolveStopBoundary({
      ...run,
      pipelineState: { ...run.pipelineState, currentStep: null },
    }),
    null,
  );
  assert.equal(resolveStopBoundary({ ...run, pipelineId: "polishing" }), null);
});

test("deferred settlement publication recovers the final checkpoint without another commit", async () => {
  // The state-store suite owns the equivalent publication-boundary products.
  const fixture = await oneStepCheckpoint.restore();
  let interrupt = true;
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    onTransitionBoundary: async (point) => {
      if (
        interrupt &&
        point === "event-appended" &&
        (await store.loadRun(fixture.runId)).pipelineState.completedCommits
          .length === 1
      ) {
        interrupt = false;
        throw new Error("verified publication interrupted");
      }
    },
  });
  const git = createGitService();
  const delegate = createExecutionAdapter();
  let commits = 0,
    stopInput,
    receipt;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (request.access === "local-commit") commits += 1;
          return delegate.run(request);
        },
      },
    },
    {
      runStore: store,
      git: {
        ...git,
        async consumeCommit(authorization, options) {
          const current = await store.loadRun(fixture.runId);
          stopInput = {
            runId: fixture.runId,
            kind: "pause_requested",
            timing: "after-current-commit",
            expectedRevision: current.revision,
            idempotencyKey: "publish-stop",
          };
          receipt = await store.requestOperatorStop(stopInput);
          return git.consumeCommit(authorization, options);
        },
      },
    },
  );
  await assert.rejects(
    runner.resume({ runId: fixture.runId, action: null }),
    /verified publication interrupted/u,
  );
  const persisted = await store.loadRun(fixture.runId);
  assert.deepEqual(await store.requestOperatorStop(stopInput), receipt);
  assert.equal(persisted.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(persisted.pause.operatorResume.workflowState, "DONE");
  assert.deepEqual(persisted.stopRequest.settlement, {
    kind: "commit",
    commit: persisted.pipelineState.completedCommits[0],
  });
  assert.equal(persisted.pipelineState.completedCommits.length, 1);
  assert.equal(persisted.pipelineState.pendingCommit, null);
  assert.equal(
    (await runner.resume({ runId: fixture.runId, action: null })).run
      .pipelineState.workflowState,
    "DONE",
  );
  assert.equal(commits, 1);
});

test("deferred cancellation recovers interrupted commit verification without invoking another effect", async () => {
  const fixture = await oneStepCheckpoint.restore();
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  });
  const git = createGitService();
  let verifications = 0;
  const delegate = createExecutionAdapter();
  let commits = 0;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (request.access === "local-commit") commits += 1;
          return delegate.run(request);
        },
      },
    },
    {
      runStore: store,
      git: {
        ...git,
        async consumeCommit(authorization, options) {
          const current = await store.loadRun(fixture.runId);
          await store.requestOperatorStop({
            runId: fixture.runId,
            kind: "cancel_requested",
            timing: "after-current-commit",
            expectedRevision: current.revision,
            idempotencyKey: "cancel-commit",
          });
          return git.consumeCommit(authorization, options);
        },
        async verifyCommit(authorization) {
          verifications += 1;
          if (verifications === 1)
            throw new Error("Verification interrupted after effect");
          return git.verifyCommit(authorization);
        },
      },
    },
  );
  const stopped = (await runner.resume({ runId: fixture.runId, action: null }))
    .run;
  assert.equal(stopped.pipelineState.workflowState, "CANCELED");
  assert.equal(stopped.pipelineState.completedCommits.length, 1);
  assert.equal(stopped.pipelineState.pendingCommit, null);
  assert.equal(stopped.pause.operatorResume.workflowState, "DONE");
  assert.equal(
    (
      await executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"])
    ).stdout.trim(),
    stopped.pipelineState.completedCommits[0],
  );
  await assert.rejects(runner.resume({ runId: fixture.runId, action: null }), {
    code: "ERR_RUN_CANCELED",
  });
  assert.equal(commits, 1);
  assert.equal(verifications, 2);
  assert.deepEqual(stopped.stopRequest.settlement, {
    kind: "commit",
    commit: stopped.pipelineState.completedCommits[0],
  });
});

test("deferred commit faults preserve authorization and account for effects exactly once", async (t) => {
  for (const [kind, fault] of [
    ["cancel_requested", "consumed"],
    ["pause_requested", "absent"],
    ["cancel_requested", "invalid"],
    ["pause_requested", "verification"],
  ]) {
    await t.test(`${kind}/${fault}`, async () => {
      const fixture = await oneStepCheckpoint.restore();
      const git = createGitService();
      const before = await git.snapshot({ projectPath: fixture.projectPath });
      let stopInput, receipt, retainedAuthorization;
      let publicationInterrupted = false,
        commits = 0,
        verifications = 0,
        forbidTurns = false;
      const store = createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
        async onTransitionBoundary(point) {
          if (
            publicationInterrupted ||
            point !== "event-appended" ||
            fault !== "consumed"
          )
            return;
          const current = await store.loadRun(fixture.runId);
          if (current.pipelineState.pendingCommit?.status === fault) {
            publicationInterrupted = true;
            retainedAuthorization =
              current.pipelineState.pendingCommit.authorization;
            throw new Error(`Interrupted ${fault} publication`);
          }
        },
      });
      const delegate = createExecutionAdapter();
      const adapter = {
        ...delegate,
        async run(request) {
          assert.equal(
            forbidTurns,
            false,
            "Recovery must not invoke another provider turn.",
          );
          if (request.access === "local-commit") {
            commits += 1;
            const current = await store.loadRun(fixture.runId);
            assert.equal(
              current.pipelineState.pendingCommit.status,
              "consumed",
            );
            if (fault === "absent")
              return {
                output: "No effect",
                structured: { ready: true },
                sessionId: request.session.id,
              };
            if (fault === "invalid")
              return delegate.run({
                ...request,
                commit: {
                  ...request.commit,
                  message: "fix(test): wrong authorized subject",
                },
              });
          }
          return delegate.run(request);
        },
      };
      const runtimeGit = {
        ...git,
        async consumeCommit(authorization, options) {
          if (stopInput === undefined) {
            const current = await store.loadRun(fixture.runId);
            stopInput = {
              runId: fixture.runId,
              kind,
              timing: "after-current-commit",
              expectedRevision: current.revision,
              idempotencyKey: "fault-stop",
            };
            receipt = await store.requestOperatorStop(stopInput);
          }
          return git.consumeCommit(authorization, options);
        },
        async verifyCommit(authorization) {
          verifications += 1;
          if (fault === "verification" && verifications === 1)
            throw new Error("Interrupted verification after effect");
          return git.verifyCommit(authorization);
        },
      };
      const openRunner = () =>
        runnerFor(
          fixture,
          { codex: adapter },
          {
            runStore: store,
            git: runtimeGit,
          },
        );
      const runner = openRunner();
      const stopped = (
        await runner.resume({ runId: fixture.runId, action: null })
      ).run;
      forbidTurns = true;
      const canceled = kind === "cancel_requested";
      assert.equal(
        stopped.pause.reason,
        canceled ? "operator_canceled" : "operator_paused",
      );
      assert.equal(stopped.stopRequest.reconciledRevision, stopped.revision);
      assert.deepEqual(await store.requestOperatorStop(stopInput), receipt);
      assert.equal(stopped.activeTurn, null);
      assert.equal(stopped.executionProcess, null);
      const after = await git.snapshot({ projectPath: fixture.projectPath });
      assert.equal(
        after.remoteConfigurationFingerprint,
        before.remoteConfigurationFingerprint,
      );
      assert.equal(after.identityFingerprint, before.identityFingerprint);
      if (fault === "consumed") {
        assert.equal(publicationInterrupted, true);
        assert.equal(commits, 0);
        assert.equal(after.head, before.head);
        assert.equal(stopped.pipelineState.pendingCommit.status, fault);
        assert.deepEqual(
          stopped.pipelineState.pendingCommit.authorization,
          retainedAuthorization,
        );
      } else {
        assert.equal(commits, 1);
        assert.equal(after.head === before.head, fault === "absent");
      }
      const verified = fault === "verification";
      assert.equal(
        stopped.pipelineState.completedCommits.length,
        verified ? 1 : 0,
      );
      assert.deepEqual(stopped.stopRequest.settlement, {
        kind: verified ? "commit" : "quiescent",
        commit: verified ? after.head : null,
      });
      if (verified) {
        assert.equal(verifications, 2);
        assert.equal(stopped.pipelineState.pendingCommit, null);
        assert.equal(stopped.pause.operatorResume.workflowState, "DONE");
      } else {
        assert.equal(stopped.pipelineState.pendingCommit.status, "consumed");
        assert.equal(
          stopped.pause.operatorResume.pause.reason,
          fault === "invalid" ? "commit_contract_violated" : "commit_failed",
        );
      }
      const history = await store.loadRunHistory(fixture.runId);
      const completed = history.events.filter(
        (event) => event.state.pipelineState.completedCommits.length > 0,
      );
      if (verified)
        assert.equal(
          completed[0].state.stopRequest.reconciledRevision,
          completed[0].revision,
        );
      const control = createMcpControlPlane({
        runner: openRunner(),
        runStore: store,
      });
      const publicState = await control.runStatus({ runId: fixture.runId });
      assert.doesNotMatch(
        JSON.stringify(publicState),
        /requestId|fault-stop|startTicks|bootId/u,
      );
      if (canceled) {
        await assert.rejects(
          openRunner().resume({ runId: fixture.runId, action: null }),
          {
            code: "ERR_RUN_CANCELED",
          },
        );
      } else {
        const restored = (
          await openRunner().resume({ runId: fixture.runId, action: null })
        ).run;
        if (verified)
          assert.equal(restored.pipelineState.workflowState, "DONE");
        else
          assert.deepEqual(restored.pause, stopped.pause.operatorResume.pause);
      }
      assert.equal(commits, fault === "consumed" ? 0 : 1);
    });
  }
});

// Configuration drift changes protected file identity, so this shared
// checkpoint is intentionally consumed only after every other restore.
test(
  "verified commit settlement stops before the next Worker and retains configuration blockers",
  assertVerifiedCommitSettlement,
);
