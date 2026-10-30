import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { createWorkspaceService } from "../src/workspace/index.js";
import {
  createExecutionAdapter,
  createFixture,
  customExecutionFixture as fixture,
  PLAN,
  runnerFor,
} from "./support/index.js";

test("project commit selection overrides a runner custom default before execution plan discovery", async (t) => {
  const f = await createFixture(t);
  const configurationPath = join(
    f.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner.json",
  );
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(
    configurationPath,
    JSON.stringify({
      schemaVersion: 1,
      pipelines: { "plan-execution": { planKind: "commit" } },
    }),
  );
  await writeFile(join(f.taskPath, "plan.md"), PLAN);
  const workspace = createWorkspaceService();
  const adapter = createExecutionAdapter();
  const runner = runnerFor(
    f,
    { codex: adapter },
    {
      configuration: {
        schemaVersion: 1,
        defaultBackend: "codex",
        pipelines: { "plan-execution": { planKind: "custom" } },
      },
      git: {
        async preflight() {
          return { snapshot: { projectPath: f.projectPath } };
        },
        async inspectPath(request) {
          return {
            ...(await workspace.inspectPath(request)),
            ignored: true,
            tracked: false,
          };
        },
      },
    },
  );
  const input = {
    pipelineId: "plan-execution",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  };
  assert.equal(
    (await runner.validateBoundary(input)).projectPath,
    f.projectPath,
  );
  const { run } = await runner.create(input);
  assert.equal(run.workspace.kind, "git");
  assert.equal(run.pipelineState.settings.planKind, "commit");
  assert.equal(run.projectConfigurationProtection.path, configurationPath);
  assert.deepEqual(adapter.calls, []);
});

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} executes sequential analysis and output steps without Git or automatic coding checks`, async (t) => {
    const f = await fixture(t, mode);
    const { run } = await f.run();
    assert.equal(
      run.pipelineState.workflowState,
      "DONE",
      JSON.stringify(run.pause),
    );
    assert.deepEqual(run.pipelineState.completedCommits, []);
    assert.deepEqual(run.pipelineState.requiredChecks, []);
    assert.equal(run.pipelineState.customResults.accepted.length, 2);
    assert.equal(
      run.pipelineState.customResults.accepted[0].result.outputPaths.length,
      0,
    );
    assert.equal(
      run.pipelineState.customResults.accepted[1].previous,
      run.pipelineState.customResults.accepted[0].receipt,
    );
    assert.equal(await readFile(join(f.taskPath, "plan.md"), "utf8"), f.plan);
    assert.match(await readFile(f.output, "utf8"), /source.md/u);
    for (const step of [1, 2]) {
      const phases = f.calls
        .filter((call) => call.step === step)
        .map((call) => call.phase);
      assert.equal(phases.filter((phase) => phase === "implement").length, 1);
      assert.ok(phases.includes("finalize") && phases.includes("confirm"));
      if (mode !== "independent")
        assert.ok(
          phases.includes("check-and-fix") && phases.includes("clean-confirm"),
        );
      if (mode !== "lazy") assert.ok(phases.includes("review"));
    }
    assert.ok(
      f.calls.every(({ request }) => request.access !== "local-commit"),
    );
    assert.ok(f.probes.every((probe) => probe.access !== "local-commit"));
    if (mode === "lazy")
      assert.ok(f.calls.every(({ role }) => role === "worker"));
  });
}

test("custom reconstruction retains earlier acceptance and retries only the interrupted confirmation", async (t) => {
  let interrupt = true;
  const f = await fixture(t, "combined", {
    beforeTurn({ saved }) {
      if (
        interrupt &&
        saved.pipelineState.currentStep === 2 &&
        saved.activeTurn.phase === "confirm"
      ) {
        interrupt = false;
        throw Object.assign(new Error("Provider temporarily unavailable"), {
          recoverable: true,
        });
      }
    },
  });
  const paused = await f.run();
  assert.equal(paused.run.pipelineState.customResults.accepted.length, 1);
  assert.equal(paused.run.pause.reason, "backend_unavailable");
  const resumed = await f.run();
  assert.equal(
    resumed.run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(resumed.run.pause),
  );
  assert.equal(f.calls.filter((call) => call.phase === "implement").length, 2);
});

test("custom reconstruction rejects writable policy drift before another turn", async (t) => {
  let interrupted = false;
  let policy = "initial";
  const f = await fixture(t, "combined", {
    writablePolicy: () => policy,
    beforeTurn({ saved, request }) {
      if (request.access === "workspace-write")
        assert.deepEqual(
          saved.pipelineState.customWritePolicy.supportedAccess,
          ["workspace-write"],
        );
      if (
        !interrupted &&
        saved.pipelineState.currentStep === 2 &&
        saved.activeTurn.phase === "implement"
      ) {
        interrupted = true;
        throw Object.assign(new Error("Provider temporarily unavailable"), {
          recoverable: true,
        });
      }
    },
  });
  const { run: paused } = await f.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pipelineState.customResults.accepted.length, 1);
  const receipt = structuredClone(paused.pipelineState.customWritePolicy);
  assert.deepEqual(receipt.supportedAccess, ["workspace-write"]);
  const calls = f.calls.length;
  policy = "changed";
  await assert.rejects(f.run(), { code: "ERR_PROVIDER_POLICY_CHANGED" });
  const run = f.currentRun;
  assert.equal(f.calls.length, calls);
  assert.deepEqual(run.pipelineState.customWritePolicy, receipt);
  assert.deepEqual(run.providerPolicies, paused.providerPolicies);
  assert.deepEqual(run.workspace, paused.workspace);
  assert.deepEqual(
    run.pipelineState.customResults.accepted,
    paused.pipelineState.customResults.accepted,
  );
});

for (const decisionStep of [1, 2]) {
  test(`compatible custom product decision at step ${decisionStep} resumes without replacing earlier receipts`, async (t) => {
    let asked = false;
    let priorFingerprint;
    let compatibilityCalls = 0;
    const f = await fixture(t, "combined", {
      beforeTurn({ saved, request }) {
        if (
          saved.pipelineState.compatibilityCheckRequired &&
          saved.activeTurn.phase !== "plan-context"
        ) {
          compatibilityCalls += 1;
          assert.equal(request.access, "read-only");
          for (const field of [
            "candidateReviewResult",
            "candidateConfirmationFingerprint",
            "finalizationResult",
            "reviewResult",
          ])
            assert.equal(saved.pipelineState[field], null);
          return {
            status: "READY",
            reason: "",
            evidence: [],
            stepAssessment: {
              step: decisionStep,
              subject:
                decisionStep === 1 ? "Analyze evidence" : "Write summary",
              disposition: "CURRENT",
              evidence: [],
            },
          };
        }
        if (
          !asked &&
          saved.activeTurn.phase ===
            (decisionStep === 1 ? "implement" : "confirm") &&
          saved.pipelineState.currentStep === decisionStep
        ) {
          asked = true;
          priorFingerprint = saved.pipelineState.finalizedFingerprint;
          return {
            status: "PRODUCT_DECISION_REQUIRED",
            ...(decisionStep === 1
              ? { summary: "", reason: "", result: null }
              : {
                  findings: [],
                  finalizationFindingIds: [],
                  validationChange: "UNCHANGED",
                  validationEvidence: [],
                }),
            question:
              "Which supplied source should resolve conflicting evidence?",
            whyBlocked:
              "The agreed traceability criterion needs a source priority.",
            options: ["Use the catalog", "Use the appendix"],
            evidence: ["The sources disagree on the same conclusion."],
          };
        }
      },
    });
    const { run: paused } = await f.run();
    assert.equal(paused.pause.reason, "product_decision_required");
    const earlier = structuredClone(
      paused.pipelineState.customResults.accepted,
    );
    assert.equal(earlier.length, decisionStep - 1);
    const path = paused.pipelineState.clarificationPath;
    await writeFile(
      path,
      `${await readFile(path, "utf8")}\nUse the catalog.\n`,
    );
    const { run } = await f.run();
    assert.equal(
      run.pipelineState.workflowState,
      "DONE",
      JSON.stringify(run.pause),
    );
    assert.deepEqual(
      run.pipelineState.customResults.accepted.slice(0, earlier.length),
      earlier,
    );
    assert.equal(run.pipelineState.customResults.accepted.length, 2);
    assert.equal(run.counters.productDecisions, 1);
    assert.equal(compatibilityCalls, 1);
    assert.deepEqual(run.workspace.policy, paused.workspace.policy);
    assert.deepEqual(
      run.pipelineState.customResults.binding,
      paused.pipelineState.customResults.binding,
    );
    if (earlier.length) {
      assert.notEqual(
        run.pipelineState.customResults.accepted.at(-1)
          .clarificationFingerprint,
        earlier[0].clarificationFingerprint,
      );
      assert.notEqual(
        run.pipelineState.customResults.accepted.at(-1).resultFingerprint,
        priorFingerprint,
      );
      for (const phase of ["clean-confirm", "review", "finalize", "confirm"])
        assert.equal(
          f.calls.filter(
            (call) => call.step === decisionStep && call.phase === phase,
          ).length,
          2,
        );
    }
  });
}

test("unauthorized clarification drift preserves earlier custom receipts and prevents another turn", async (t) => {
  let interrupted = false;
  const f = await fixture(t, "combined", {
    beforeTurn({ saved }) {
      if (
        !interrupted &&
        saved.pipelineState.currentStep === 2 &&
        saved.activeTurn.phase === "implement"
      ) {
        interrupted = true;
        throw Object.assign(new Error("Provider unavailable"), {
          recoverable: true,
        });
      }
    },
  });
  const { run: paused } = await f.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  const earlier = structuredClone(paused.pipelineState.customResults.accepted);
  assert.equal(earlier.length, 1);
  await writeFile(
    paused.pipelineState.clarificationPath,
    "Unauthorized replacement.\n",
  );
  const calls = f.calls.length;
  const { run } = await f.run();
  assert.equal(run.pause.reason, "clarifications_changed");
  assert.equal(f.calls.length, calls);
  assert.deepEqual(run.pipelineState.customResults.accepted, earlier);
  assert.deepEqual(run.workspace.policy, paused.workspace.policy);
});

test("an authorized decision invalidating an accepted result requires revised planning", async (t) => {
  const f = await fixture(t, "combined", {
    beforeTurn({ saved }) {
      if (
        saved.pipelineState.compatibilityCheckRequired &&
        saved.activeTurn.phase !== "plan-context"
      )
        return {
          status: "PLAN_REVISION_REQUIRED",
          reason: "The answer invalidates the accepted source analysis.",
          evidence: [
            "The plan requires the accepted analysis as the summary's basis.",
          ],
          stepAssessment: {
            step: 2,
            subject: "Write summary",
            disposition: "CURRENT",
            evidence: [],
          },
        };
      if (
        saved.pipelineState.currentStep === 2 &&
        saved.activeTurn.phase === "implement"
      )
        return {
          status: "PRODUCT_DECISION_REQUIRED",
          summary: "",
          reason: "",
          result: null,
          question: "Which source governs the disputed conclusion?",
          whyBlocked: "The available sources support incompatible conclusions.",
          options: ["Use the accepted source", "Replace the accepted source"],
          evidence: ["The summary depends on the governing source."],
        };
    },
  });
  const { run: paused } = await f.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  const earlier = structuredClone(paused.pipelineState.customResults.accepted);
  await writeFile(
    paused.pipelineState.clarificationPath,
    `${await readFile(paused.pipelineState.clarificationPath, "utf8")}\nReplace the accepted source.\n`,
  );
  const { run } = await f.run();
  assert.equal(run.pause.reason, "plan_revision_required");
  assert.deepEqual(run.pipelineState.customResults.accepted, earlier);
  assert.deepEqual(run.workspace.policy, paused.workspace.policy);
  assert.equal(
    f.calls.filter(
      (call) =>
        call.phase === "implement" &&
        call.step === 2 &&
        call.request.access === "workspace-write",
    ).length,
    1,
  );
});

test("result-only corrections restart combined convergence and count one fix", async (t) => {
  let finding = false;
  let fixed = false;
  let fixRoundsBeforeRepair = 0;
  let repairFixRounds = 0;
  const empty = { question: "", whyBlocked: "", options: [], evidence: [] };
  const f = await fixture(t, "combined", {
    afterTransition(saved) {
      if (
        fixed &&
        saved.pipelineState.currentStep === 1 &&
        saved.pipelineState.workflowState === "CHECK_AND_FIX"
      )
        repairFixRounds = saved.counters.fixRounds - fixRoundsBeforeRepair;
    },
    beforeTurn({ saved }) {
      const state = saved.pipelineState;
      if (state.currentStep !== 1) return;
      if (state.workflowState === "REVIEW" && !finding) {
        finding = true;
        return {
          status: "FINDINGS",
          findings: [
            {
              id: "R1",
              file: "source.md",
              problem: "The analysis omits a source citation.",
              reason: "The traceability criterion requires the citation.",
              suggestedAction: "Include the source citation in the analysis.",
            },
          ],
          ...empty,
        };
      }
      if (state.workflowState === "RESOLVE_FINDINGS" && !fixed) {
        fixed = true;
        fixRoundsBeforeRepair = saved.counters.fixRounds;
        return {
          status: "RESOLVED",
          reason: "",
          decisions: [
            {
              id: "R1",
              decision: "FIX",
              reason: "Cited source.md in the analysis.",
              evidence: [],
            },
          ],
          result: {
            ...state.customCandidate,
            analysis:
              "The conclusion follows source.md; the unavailable remote evidence remains explicit.",
          },
          ...empty,
        };
      }
    },
  });
  const { run } = await f.run();
  assert.equal(
    run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(run.pause),
  );
  assert.ok(fixed);
  assert.equal(repairFixRounds, 1);
  assert.match(
    run.pipelineState.customResults.accepted[0].result.analysis,
    /source.md/u,
  );
  assert.equal(
    f.calls.filter(({ phase, step }) => phase === "review" && step === 1)
      .length,
    2,
  );
  assert.equal(
    f.calls.filter(({ phase, step }) => phase === "clean-confirm" && step === 1)
      .length,
    2,
  );
});

test("semantic-only finalization failure survives reconstruction and requires a result repair and fresh combined gates", async (t) => {
  let failed = false;
  let interrupted = false;
  let fixRoundsBeforeRepair;
  let repairFixRounds;
  let repairedContentFingerprint;
  const empty = { question: "", whyBlocked: "", options: [], evidence: [] };
  const f = await fixture(t, "combined", {
    afterTransition(saved) {
      if (
        fixRoundsBeforeRepair !== undefined &&
        saved.pipelineState.currentStep === 1 &&
        saved.pipelineState.workflowState === "CHECK_AND_FIX"
      ) {
        repairFixRounds = saved.counters.fixRounds - fixRoundsBeforeRepair;
        repairedContentFingerprint =
          saved.pipelineState.repositoryBaseline.contentFingerprint;
      }
    },
    beforeTurn({ saved }) {
      const state = saved.pipelineState;
      if (state.currentStep !== 1) return;
      if (state.workflowState === "FINALIZE" && !failed) {
        failed = true;
        return {
          status: "FAIL",
          skillPath: "",
          summary: "The analysis does not identify the cited source.",
          issues: [
            {
              id: "F1",
              command: "criterion:traceability",
              problem: "The analysis omits the source citation.",
              evidence: ["The analysis does not name source.md."],
            },
          ],
          requiredChecks: [],
          validationInfrastructure: [],
          checks: [],
          reason: "",
          ...empty,
        };
      }
      if (state.workflowState === "RESOLVE_FINDINGS") {
        if (!interrupted) {
          interrupted = true;
          throw Object.assign(new Error("Provider temporarily unavailable"), {
            recoverable: true,
          });
        }
        fixRoundsBeforeRepair = saved.counters.fixRounds;
        return {
          status: "RESOLVED",
          decisions: [
            {
              id: "F1",
              decision: "FIX",
              reason: "Cited source.md in the analysis.",
              evidence: [],
            },
          ],
          result: {
            ...state.customCandidate,
            analysis: "Conclusion from source.md.",
          },
          reason: "",
          ...empty,
        };
      }
    },
  });
  const { run: paused } = await f.run();
  assert.equal(paused.pause?.reason, "backend_unavailable");
  assert.equal(paused.pipelineState.finalizationResult.status, "FAIL");
  assert.deepEqual(paused.pipelineState.finalizationResult.checks, []);
  assert.equal(paused.pipelineState.customResults.accepted.length, 0);
  const failedFingerprint = paused.pipelineState.finalizationResult.fingerprint;
  const { run } = await f.run();
  assert.equal(
    run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(run.pause),
  );
  assert.equal(repairFixRounds, 1);
  const accepted = run.pipelineState.customResults.accepted[0];
  assert.equal(accepted.result.analysis, "Conclusion from source.md.");
  assert.notEqual(accepted.resultFingerprint, failedFingerprint);
  assert.equal(
    repairedContentFingerprint,
    paused.pipelineState.repositoryBaseline.contentFingerprint,
  );
  for (const phase of ["check-and-fix", "clean-confirm", "review", "finalize"])
    assert.equal(
      f.calls.filter((call) => call.step === 1 && call.phase === phase).length,
      2,
    );
  assert.equal(
    f.calls.filter((call) => call.step === 1 && call.phase === "confirm")
      .length,
    1,
  );
  assert.ok(f.calls.every(({ role }) => role !== "arbiter"));
});

test("interrupted accepted-result publication advances without repeating implementation or confirmation", async (t) => {
  let interrupted = false;
  const failure = new Error("Acceptance response lost");
  const f = await fixture(t, "combined", {
    afterTransition(saved) {
      if (
        !interrupted &&
        saved.pipelineState.workflowState === "ACCEPT" &&
        saved.pipelineState.customResults.accepted.length === 1
      ) {
        interrupted = true;
        throw failure;
      }
    },
  });
  await assert.rejects(f.run(), (error) => error === failure);
  const firstStepCalls = f.calls.filter(({ step }) => step === 1).length;
  const resumed = await f.run();
  assert.equal(
    resumed.run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(resumed.run.pause),
  );
  assert.equal(f.calls.filter(({ step }) => step === 1).length, firstStepCalls);
  assert.equal(resumed.run.pipelineState.customResults.accepted.length, 2);
});

test("output preparation saves its verified baseline with the identity before interrupted recovery", async (t) => {
  let interrupted = false;
  const failure = new Error("Prepared identity response lost");
  const f = await fixture(t, "combined", {
    missingOutputRoot: true,
    afterTransition(saved) {
      if (
        !interrupted &&
        saved.pipelineState.customResults?.preparation?.prepared
      ) {
        interrupted = true;
        throw failure;
      }
    },
  });
  await assert.rejects(f.run(), (error) => error === failure);
  const state = f.currentRun.pipelineState;
  const prepared = state.customResults.preparation.prepared;
  assert.deepEqual(
    state.repositoryBaseline.entries.find(({ path }) => path === prepared.path)
      .identity,
    prepared.identity,
  );
  assert.equal(
    f.calls.some(({ phase }) => phase === "implement"),
    false,
  );
  const { run } = await f.run();
  assert.equal(
    run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(run.pause),
  );
  assert.equal(run.pipelineState.customResults.accepted.length, 2);
  assert.equal(f.calls.filter(({ phase }) => phase === "implement").length, 2);
});

test("custom resume prepares missing outputs after ledger initialization was interrupted", async (t) => {
  let interrupted = false;
  const failure = new Error("Ledger initialization response lost");
  const f = await fixture(t, "combined", {
    missingOutputRoot: true,
    afterTransition(saved) {
      const ledger = saved.pipelineState.customResults;
      if (
        !interrupted &&
        ledger !== null &&
        ledger.preparation === null &&
        ledger.preparedRoots.length === 0
      ) {
        interrupted = true;
        throw failure;
      }
    },
  });
  await assert.rejects(f.run(), (error) => error === failure);
  assert.equal(
    f.calls.some(({ phase }) => phase === "implement"),
    false,
  );
  const { run } = await f.run();
  assert.equal(
    run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(run.pause),
  );
  assert.equal(run.pipelineState.customResults.preparedRoots.length, 1);
  assert.equal(run.pipelineState.customResults.accepted.length, 2);
});

test("output preparation cannot adopt content added before its identity checkpoint", async (t) => {
  const f = await fixture(t, "combined", {
    missingOutputRoot: true,
    afterOutputPreparation: ({ output }) =>
      writeFile(output, "Unexpected content.\n"),
  });
  await assert.rejects(f.run(), { code: "ERR_READ_ONLY_REPOSITORY_CHANGED" });
  assert.equal(
    f.currentRun.pipelineState.customResults.preparation.prepared,
    null,
  );
  assert.equal(
    f.calls.some(({ phase }) => phase === "implement"),
    false,
  );
  assert.equal(await readFile(f.output, "utf8"), "Unexpected content.\n");
});

test("terminal confirmation cannot mutate outputs or accept changed content", async (t) => {
  let changed = false;
  const f = await fixture(t, "combined", {
    async beforeTurn({ saved, output }) {
      if (
        saved.pipelineState.currentStep === 2 &&
        saved.activeTurn.phase === "confirm" &&
        !changed
      ) {
        changed = true;
        await writeFile(output, "Unexpected replacement.\n");
      }
    },
  });
  const stopped = await f.run();
  assert.equal(stopped.run.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(f.calls.filter(({ phase }) => phase === "implement").length, 2);
  assert.equal(f.currentRun.pipelineState.customResults.accepted.length, 1);
});

test("custom trusted validation binds the workspace bytes while semantic gates bind the result", async (t) => {
  const f = await fixture(t, "combined", { trusted: true });
  const { run } = await f.run();
  assert.equal(
    run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(run.pause),
  );
  assert.equal(f.trustedCalls.length, 2);
  const command = run.pipelineState.trustedValidation.commands[0];
  for (const request of f.trustedCalls) {
    assert.equal(request.commandIdentity, command.identity);
    assert.deepEqual(request.snapshot.commands[0].arguments, [
      "verify-result.js",
    ]);
    assert.notEqual(
      request.bindings.contentFingerprint,
      run.pipelineState.customResults.accepted[0].resultFingerprint,
    );
  }
  assert.equal(
    run.pipelineState.finalizationResult.checks[0].executor,
    "runner",
  );
  assert.equal(
    run.pipelineState.finalizationResult.checks[0].commandIdentity,
    command.identity,
  );
});

test("misreported result-only edits consume bounded output correction without accepting new analysis", async (t) => {
  let checks = 0;
  const f = await fixture(t, "lazy", {
    beforeTurn({ saved }) {
      if (saved.pipelineState.workflowState !== "CHECK_AND_FIX") return;
      checks += 1;
      return {
        status: "UNCHANGED",
        summary: "Claimed unchanged analysis.",
        reason: "",
        question: "",
        whyBlocked: "",
        options: [],
        evidence: [],
        result: {
          ...saved.pipelineState.customCandidate,
          analysis: `Different proposed analysis ${checks}.`,
        },
      };
    },
  });
  const { run } = await f.run();
  assert.equal(run.pause.reason, "lazy_output_invalid");
  assert.equal(checks, 2);
  assert.equal(run.pipelineState.customResults.accepted.length, 0);
  assert.equal(
    run.pipelineState.customCandidate.analysis,
    f.result(1).analysis,
  );
});

test("inactive custom results receive bounded output correction without accepting result data", async (t) => {
  let attempts = 0;
  const f = await fixture(t, "lazy", {
    beforeTurn({ saved }) {
      if (saved.pipelineState.workflowState !== "CHECK_AND_FIX") return;
      attempts += 1;
      return {
        status: "BLOCKED",
        summary: "",
        reason: "A fixture dependency is unavailable.",
        question: "",
        whyBlocked: "",
        options: [],
        evidence: ["The fixture dependency could not be opened."],
        result: {
          ...saved.pipelineState.customCandidate,
          analysis: "Result data cannot be accepted from a blocked outcome.",
        },
      };
    },
  });
  const { run } = await f.run();
  assert.equal(run.pause.reason, "lazy_output_invalid");
  assert.equal(attempts, 2);
  assert.equal(run.pipelineState.customResults.accepted.length, 0);
  assert.equal(
    run.pipelineState.customCandidate.analysis,
    f.result(1).analysis,
  );
  assert.equal(
    run.pipelineState.pendingLazyCorrection.diagnostics[0].constraint,
    "null-for-inactive-status",
  );
});

test("repository-contained custom execution shares canonical exclusion and leaves Git controls untouched", async (t) => {
  const f = await fixture(t, "combined", { contained: true });
  const paths = ["HEAD", "config"].map((name) =>
    join(f.repositoryPath, ".git", name),
  );
  const before = await Promise.all(paths.map((path) => readFile(path, "utf8")));
  assert.equal(f.currentRun.workspace.leasePath, f.repositoryPath);
  assert.equal(f.currentRun.workspace.policy.workspacePath, f.projectPath);
  const { run } = await f.run();
  assert.equal(
    run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(run.pause),
  );
  assert.deepEqual(
    await Promise.all(paths.map((path) => readFile(path, "utf8"))),
    before,
  );
  await assert.rejects(readFile(join(f.repositoryPath, ".git", "index")), {
    code: "ENOENT",
  });
  assert.deepEqual(run.pipelineState.completedCommits, []);
  assert.deepEqual(run.pipelineState.requiredChecks, []);
});

test("explicit custom finalization guidance is frozen and reviewed without automatic coding gates", async (t) => {
  const f = await fixture(t, "combined", { finalization: "review/SKILL.md" });
  const { run } = await f.run();
  assert.equal(
    run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(run.pause),
  );
  assert.equal(
    run.pipelineState.finalizationGuidance.skillPath,
    "review/SKILL.md",
  );
  assert.deepEqual(run.workspace.policy.infrastructurePaths, [
    join(f.projectPath, "review/SKILL.md"),
  ]);
  assert.deepEqual(
    run.pipelineState.finalizationResult.validationInfrastructure,
    ["review/SKILL.md"],
  );
  assert.deepEqual(run.pipelineState.requiredChecks, []);
  assert.equal(run.pipelineState.customResults.accepted.length, 2);
});

for (const phase of ["bootstrap", "finalize"]) {
  test(`custom ${phase} corrects an unselected external guidance label before workspace inspection`, async (t) => {
    let injected = false;
    let correction;
    const f = await fixture(t, "combined", {
      finalization: "review/SKILL.md",
      afterTransition({ pipelineState }) {
        const corrections =
          phase === "bootstrap"
            ? pipelineState.bootstrapCorrections
            : pipelineState.finalizationCorrections;
        if (corrections.length) correction = corrections.at(-1);
      },
      beforeTurn({ saved }) {
        if (injected || saved.activeTurn.phase !== phase) return;
        injected = true;
        const skillPath = saved.pipelineState.finalizationGuidance.skillPath;
        const inventory = {
          requiredChecks: [],
          validationInfrastructure: [skillPath, "finalization://other.md"],
        };
        if (phase === "bootstrap")
          return {
            result: {
              stepAssessment: {
                step: 1,
                subject: "Analyze evidence",
                disposition: "CURRENT",
                evidence: [],
              },
              summary: "Inspect the result against the traceability criterion.",
              ...inventory,
              capabilityRequirements: [],
              environmentBlockers: [],
            },
          };
        return {
          status: "PASS",
          summary: "Inspected the result against its criterion.",
          skillPath,
          ...inventory,
          checks: [],
          issues: [],
          reason: "",
          question: "",
          whyBlocked: "",
          options: [],
          evidence: [],
        };
      },
    });
    const { run } = await f.run();
    assert.equal(
      run.pipelineState.workflowState,
      "DONE",
      JSON.stringify(run.pause),
    );
    assert.ok(injected);
    assert.equal(correction.attempt, 1);
    assert.deepEqual(
      correction.diagnostics.map(({ field, constraint }) => ({
        field,
        constraint,
      })),
      [
        {
          field: "validationInfrastructure[1]",
          constraint: "existing-canonical-repository-file",
        },
      ],
    );
    assert.deepEqual(run.pipelineState.validationInfrastructure, [
      "review/SKILL.md",
    ]);
    assert.equal(run.pipelineState.customResults.accepted.length, 2);
  });
}
