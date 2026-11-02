import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  attachOutputExhaustion,
  outputExhaustion,
} from "../../../test/support/output-exhaustion.js";
import { attachInactivity } from "../../../test/support/inactivity.js";
import {
  attachAvailability,
  availabilityFailure,
} from "../../../test/support/availability.js";

import {
  AgentBoundaryError,
  normalizeAdapterFailure,
  normalizeFailureRecord,
} from "../../../src/agents/index.js";
import { planExecutionPipeline, runPlanExecution } from "../src/index.js";
import {
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  CLARIFICATION_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  FINALIZATION_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  IMPLEMENTATION_SCHEMA,
  REVIEW_SCHEMA,
} from "../src/schemas.js";
import {
  PLAN,
  REQUIRED_CHECKS,
  SOURCE_SESSION,
  arbitrationResolved,
  bootstrapReady,
  checkAndFix,
  checkResults,
  clarificationReady,
  cleanConfirmation,
  createFixture,
  createRealGitFixture,
  createRevision55Fixture,
  environmentBlocked,
  executeFile,
  finalizationFailed,
  finalizationPassed,
  implementationBlocked,
  implementationCompleted,
  reconciliationDisagreement,
  reconciliationResolved,
  resolution,
  reviewApproved,
  reviewFindings,
  terminalConfirmation,
  terminalLazyConfirmation,
  trustedValidationSnapshot,
} from "./support/index.js";

function exhaustedCodexTurnFailure(diagnosticClass = "turn_other") {
  return normalizeAdapterFailure(
    "codex",
    Object.assign(new Error("DO_NOT_RETAIN_NATIVE_MESSAGE"), {
      code: "ERR_CODEX_TURN_FAILED",
      diagnosticClass,
      recoverable: true,
      additionalDetails: "DO_NOT_RETAIN_ADDITIONAL_DETAILS",
    }),
  );
}

function blockedLateSourceForkFailure(checkpoint) {
  const error = new AgentBoundaryError(
    { code: "ERR_FIXTURE_UNAVAILABLE" },
    normalizeFailureRecord({
      failureClass: "launch_process_exited",
      checkpoint,
      outcome: "exited",
      effect: "none",
      retry: "transient",
    }),
  );
  delete error.launchRecovery;
  error.recoverable = false;
  return error;
}

test("local Codex schema and structured bad-request failures stay terminal at CONFIRM", async (t) => {
  for (const mode of ["independent", "lazy"]) {
    for (const [code, diagnosticClass] of [
      ["ERR_INVALID_CODEX_SCHEMA", undefined],
      ["ERR_CODEX_TURN_FAILED", "turn_bad_request"],
    ]) {
      await t.test(`${mode}/${code}`, async (t) => {
        let failures = 0;
        const fixture = await createFixture(t, {
          mode,
          workWorker: [
            implementationCompleted(),
            checkAndFix(),
            cleanConfirmation(),
            finalizationPassed(),
          ],
          onRoleRun(_role, request) {
            if (
              [REVIEW_SCHEMA, CLEAN_CONFIRM_SCHEMA].includes(request.schema)
            ) {
              failures += 1;
              throw normalizeAdapterFailure(
                "codex",
                Object.assign(new Error("DO_NOT_RETAIN_NATIVE_MESSAGE"), {
                  code,
                  diagnosticClass,
                  recoverable: false,
                  additionalDetails: "DO_NOT_RETAIN_ADDITIONAL_DETAILS",
                }),
              );
            }
          },
        });

        await assert.rejects(fixture.run(), (error) => {
          assert.equal(error.code, code);
          assert.equal(error.diagnosticClass, diagnosticClass);
          assert.equal(error.recoverable, false);
          assert.equal(error.failureClass, undefined);
          assert.equal(error.cause, undefined);
          return true;
        });
        assert.equal(failures, 1);
        assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
        assert.deepEqual(fixture.currentRun.pause, {
          reason: "internal_failure",
          code,
          ...(diagnosticClass === undefined ? {} : { diagnosticClass }),
        });
        assert.equal(fixture.currentRun.activeTurn, null);
        assert.equal(fixture.currentRun.counters.correctionRounds, 0);
        assert.equal(fixture.currentRun.pipelineState.pendingCommit, null);
        assert.equal(
          fixture.calls.worker.filter(({ access }) => access === "local-commit")
            .length,
          0,
        );
        assert.equal(
          fixture.calls.worker.filter(
            ({ schema }) => schema === FINALIZATION_SCHEMA,
          ).length,
          1,
        );
        assert.doesNotMatch(
          JSON.stringify({
            run: fixture.currentRun,
            transitions: fixture.transitions,
          }),
          /DO_NOT_RETAIN|backend_unavailable|provider-structured-output/u,
        );
        if (mode === "lazy") {
          assert.equal(fixture.calls.reviewer.length, 0);
          assert.equal(fixture.calls.arbiter.length, 0);
        }
      });
    }
  }
});

test("repeated recoverable Codex failures pause at terminal CONFIRM without replaying finalized work", async (t) => {
  for (const mode of ["independent", "lazy"]) {
    for (const diagnosticClass of ["turn_other", "turn_server_overloaded"]) {
      await t.test(`${mode}/${diagnosticClass}`, async (t) => {
        let failures = 0;
        const fixture = await createFixture(t, {
          mode,
          workWorker: [
            implementationCompleted(),
            checkAndFix(),
            cleanConfirmation(),
            finalizationPassed(),
          ],
          onRoleRun(_role, request) {
            if (
              [REVIEW_SCHEMA, CLEAN_CONFIRM_SCHEMA].includes(request.schema) &&
              failures < 2
            ) {
              failures += 1;
              throw exhaustedCodexTurnFailure(diagnosticClass);
            }
          },
        });

        const firstPause = await fixture.run();
        const secondPause = await fixture.run();
        for (const paused of [firstPause, secondPause]) {
          assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
          assert.deepEqual(paused.pause, {
            code: "ERR_CODEX_TURN_FAILED",
            resumeState: "CONFIRM",
            reason: "backend_unavailable",
          });
          assert.equal(paused.activeTurn, null);
          assert.equal(paused.pipelineState.finalizationResult.status, "PASS");
          assert.equal(
            paused.pipelineState.finalizedFingerprint,
            paused.pipelineState.repositoryBaseline.contentFingerprint,
          );
          assert.equal(paused.pipelineState.reviewedFingerprint, null);
          assert.equal(paused.pipelineState.pendingCommit, null);
          assert.deepEqual(paused.counters, firstPause.counters);
          assert.deepEqual(
            paused.pipelineState.finalizationResult,
            firstPause.pipelineState.finalizationResult,
          );
        }
        assert.equal(failures, 2);
        assert.equal(
          fixture.calls.worker.filter(({ access }) => access === "local-commit")
            .length,
          0,
        );
        const completed = await fixture.run();
        assert.equal(completed.pipelineState.workflowState, "DONE");
        assert.equal(
          fixture.calls.worker.filter(({ prompt }) =>
            prompt.includes("Implement the changes"),
          ).length,
          1,
        );
        assert.equal(
          fixture.calls.worker.filter(
            ({ schema }) => schema === FINALIZATION_SCHEMA,
          ).length,
          1,
        );
        assert.equal(
          fixture.calls.worker.filter(({ access }) => access === "local-commit")
            .length,
          1,
        );
        assert.doesNotMatch(
          JSON.stringify(fixture.transitions),
          /DO_NOT_RETAIN/u,
        );
        if (mode === "lazy") {
          assert.equal(fixture.calls.reviewer.length, 0);
          assert.equal(fixture.calls.arbiter.length, 0);
        }
      });
    }
  }
});

test("reconciles safe writable content before pausing an opaque Codex failure", async (t) => {
  let rejected = false;
  const fixture = await createFixture(t, {
    async onRoleRun(_role, request) {
      if (request.prompt.includes("Implement the changes") && !rejected) {
        rejected = true;
        await writeFile(
          join(request.cwd, "partial.txt"),
          "safe partial progress\n",
        );
        throw exhaustedCodexTurnFailure();
      }
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");
  assert.equal(paused.pipelineState.repositoryBaseline.clean, false);
  assert.equal(
    await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
    "safe partial progress\n",
  );
  assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  assert.equal(
    await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
    "safe partial progress\n",
  );
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_RETAIN/u);
});

test("repository safety violations take precedence over opaque Codex failures", async (t) => {
  for (const violation of ["read-only-content", "refs", "remote", "identity"]) {
    await t.test(violation, async (t) => {
      const fixture = await createFixture(t, {
        async onRoleRun(_role, request, _count, repository) {
          const applies =
            violation === "read-only-content"
              ? request.schema === REVIEW_SCHEMA
              : request.prompt.includes("Implement the changes");
          if (!applies) {
            return;
          }
          if (violation === "read-only-content") {
            await writeFile(
              join(request.cwd, "unexpected.txt"),
              "unsafe mutation\n",
            );
          } else if (violation === "refs") {
            repository.changeRefs();
          } else if (violation === "remote") {
            repository.changeRemote();
          } else {
            repository.changeIdentity();
          }
          throw exhaustedCodexTurnFailure();
        },
      });
      const paused = await fixture.run();
      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(
        paused.pause.reason,
        {
          "read-only-content": "read_only_agent_mutated_repository",
          refs: "unexpected_git_ref_change",
          remote: "unexpected_remote_configuration_change",
          identity: "unexpected_git_identity_change",
        }[violation],
      );
      assert.equal(
        fixture.calls.worker.filter(({ access }) => access === "local-commit")
          .length,
        0,
      );
      assert.equal(
        fixture.transitions.some(
          ({ patch }) => patch?.pause?.reason === "backend_unavailable",
        ),
        false,
      );
      assert.doesNotMatch(
        JSON.stringify(fixture.transitions),
        /DO_NOT_RETAIN/u,
      );
    });
  }
});

test("reconstructs an interrupted writable turn with partial content and staging", async (t) => {
  let interrupt = true;
  let recovering = false;
  const fixture = await createRealGitFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        if (interrupt) {
          interrupt = false;
          const error = new Error("Provider interrupted.");
          error.recoverable = true;
          throw error;
        }
        if (recovering) {
          assert.equal(request.session, undefined);
          assert.equal(request.prompt, request.recoveryPrompt);
          assert.equal(
            await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
            "partial implementation\n",
          );
          const { stdout } = await executeFile("git", [
            "-C",
            fixture.projectPath,
            "diff",
            "--cached",
            "--name-only",
          ]);
          assert.match(stdout, /^partial\.txt$/mu);
          recovering = false;
        }
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.resumeState, "IMPLEMENT");
  await writeFile(
    join(fixture.projectPath, "partial.txt"),
    "partial implementation\n",
  );
  await executeFile("git", ["-C", fixture.projectPath, "add", "partial.txt"]);
  Object.assign(fixture.currentRun, {
    activeTurn: { role: "worker", phase: "implement" },
    pause: null,
    pipelineState: { ...paused.pipelineState, workflowState: "IMPLEMENT" },
  });
  recovering = true;

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.activeTurn, null);
});

test("rejects task and Git-control drift before interrupted writable recovery", async (t) => {
  for (const drift of ["plan", "identity"]) {
    await t.test(drift, async (t) => {
      let interrupt = true;
      const fixture = await createFixture(t, {
        onRoleRun(role, request) {
          if (
            role === "worker" &&
            request.prompt.includes("Implement the changes") &&
            interrupt
          ) {
            interrupt = false;
            const error = new Error("Provider interrupted.");
            error.recoverable = true;
            throw error;
          }
        },
      });
      const paused = await fixture.run();
      Object.assign(fixture.currentRun, {
        activeTurn: { role: "worker", phase: "implement" },
        pause: null,
        pipelineState: {
          ...paused.pipelineState,
          workflowState: "IMPLEMENT",
        },
      });
      if (drift === "plan") {
        await writeFile(join(fixture.taskPath, "plan.md"), `${PLAN}\nDrift.\n`);
      } else {
        fixture.repository.changeIdentity();
      }

      const rejected = await fixture.run();
      assert.equal(
        rejected.pause.reason,
        drift === "plan"
          ? "task_input_changed"
          : "unexpected_git_identity_change",
      );
      assert.deepEqual(rejected.activeTurn, {
        role: "worker",
        phase: "implement",
      });
    });
  }
});

test("counts a recovered correction that removes partial content", async (t) => {
  let interrupt = true;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below") &&
        interrupt
      ) {
        interrupt = false;
        const error = new Error("Provider interrupted.");
        error.recoverable = true;
        throw error;
      }
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        await rm(join(request.cwd, "partial-fix.txt"));
      }
    },
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
  await writeFile(
    join(fixture.projectPath, "partial-fix.txt"),
    "partial fix\n",
  );
  Object.assign(fixture.currentRun, {
    activeTurn: { role: "worker", phase: "resolve-findings" },
    pause: null,
    pipelineState: {
      ...paused.pipelineState,
      workflowState: "RESOLVE_FINDINGS",
    },
  });

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
  await assert.rejects(readFile(join(fixture.projectPath, "partial-fix.txt")), {
    code: "ENOENT",
  });
});

test("clears a reconciled correction marker without replaying the turn", async (t) => {
  const processLoss = new Error(
    "Process stopped after correction reconciliation.",
  );
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        await writeFile(
          join(fixture.projectPath, "reconciled-fix.txt"),
          "reconciled fix\n",
        );
      }
    },
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });
  const transition = fixture.runtime.transition;
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  let processStopped = false;
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    const next = await transition(patch, options);
    if (
      next.activeTurn?.phase === "resolve-findings" &&
      next.pipelineState.workflowState === "REVIEW" &&
      next.pipelineState.pendingCorrection
    ) {
      processStopped = true;
    }
    return next;
  };
  fixture.runtime.finishAgentTurn = async (turn) => {
    if (processStopped) {
      throw processLoss;
    }
    return finishAgentTurn(turn);
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.deepEqual(fixture.currentRun.activeTurn, {
    role: "worker",
    phase: "resolve-findings",
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "REVIEW");
  assert.equal(fixture.currentRun.pipelineState.pendingCorrection, true);
  assert.equal(fixture.currentRun.counters.fixRounds, 1);
  const resolutionTurns = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("For each finding below"),
  ).length;

  processStopped = false;
  fixture.runtime.transition = transition;
  fixture.runtime.finishAgentTurn = finishAgentTurn;
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.activeTurn, null);
  assert.equal(completed.counters.fixRounds, 1);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("For each finding below"),
    ).length,
    resolutionTurns,
  );
});

test("treats emptied required inputs as drift on resume", async (t) => {
  for (const file of ["task.md", "plan.md"]) {
    await t.test(file, async (t) => {
      let changed = false;
      const fixture = await createFixture(t, {
        async onTransition(run) {
          if (!changed && run.pipelineState.workflowState === "IMPLEMENT") {
            changed = true;
            await writeFile(join(run.taskPath, file), "");
          }
        },
      });

      const result = await fixture.run();

      assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(result.pause.reason, "task_input_changed");
      assert.equal(result.pipelineState.currentStep, null);
      assert.equal(result.pipelineState.resolvedSummary, null);
    });
  }
});

test("pauses when the repository changes at the implementation boundary", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onTransition(run) {
      if (!changed && run.pipelineState.workflowState === "IMPLEMENT") {
        changed = true;
        await writeFile(
          join(run.projectPath, "source.js"),
          "externally changed\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unsafe_git_state");
  assert.equal(result.pause.code, "ERR_READ_ONLY_REPOSITORY_CHANGED");
  assert.notEqual(result.pipelineState.resolvedSummary, null);
});

test("retries an unavailable bootstrap Arbiter without repeating bootstrap", async (t) => {
  const arbiterCapabilities = { readOnly: false };
  const fixture = await createFixture(t, {
    arbiter: [arbitrationResolved()],
    capabilities: { arbiter: arbiterCapabilities },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "BOOTSTRAP");
  assert.equal(
    paused.pipelineState.bootstrapDisagreement.description.length > 0,
    true,
  );
  assert.equal(fixture.calls.worker.length, 3);
  arbiterCapabilities.readOnly = true;

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(fixture.calls.worker.length, 6);
  assert.equal(fixture.calls.reviewer.length, 3);
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.probeCalls.arbiter, 2);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Provide a concise bootstrap summary"),
    ).length,
    1,
  );
});

test("pauses and explicitly resumes an exhausted lazy correction without recounting", async (t) => {
  const invalid = { ...checkAndFix(), DO_NOT_PERSIST: "private output" };
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      invalid,
      invalid,
      checkAndFix(),
      cleanConfirmation(),
    ],
  });

  const paused = await fixture.run();
  const projected = planExecutionPipeline.projections.pause(paused);

  assert.equal(paused.pause.reason, "lazy_output_invalid");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.equal(paused.pipelineState.pendingLazyCorrection.attempt, 1);
  assert.equal(paused.pipelineState.lazyCorrections.length, 1);
  assert.equal(paused.counters.fixRounds, 0);
  assert.doesNotMatch(JSON.stringify(paused), /private output/u);
  assert.doesNotMatch(
    JSON.stringify(projected),
    /DO_NOT_PERSIST|private output/u,
  );
  assert.deepEqual(projected.nextActions, [{ type: "resume", action: null }]);

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Pending correction diagnostic batch"),
    ).length,
    2,
  );
});

test("reconstructs an interrupted pending lazy correction without recounting", async (t) => {
  const processLoss = new Error("Process stopped during lazy correction.");
  let interrupted = false;
  let processStopped = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      { ...checkAndFix(), unexpected: "rejected" },
      checkAndFix(),
      cleanConfirmation(),
    ],
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Pending correction diagnostic batch") &&
        !interrupted
      ) {
        interrupted = true;
        processStopped = true;
        throw processLoss;
      }
    },
  });
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  const transition = fixture.runtime.transition;
  fixture.runtime.finishAgentTurn = async (turn) => {
    if (processStopped) {
      throw processLoss;
    }
    return finishAgentTurn(turn);
  };
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    return transition(patch, options);
  };

  await assert.rejects(fixture.run(), (cause) => cause === processLoss);
  assert.deepEqual(fixture.currentRun.activeTurn, {
    role: "worker",
    phase: "check-and-fix",
  });
  assert.equal(fixture.currentRun.pipelineState.lazyCorrections.length, 1);
  assert.equal(
    fixture.currentRun.pipelineState.pendingLazyCorrection.attempt,
    1,
  );
  assert.equal(fixture.currentRun.counters.fixRounds ?? 0, 0);

  processStopped = false;
  fixture.runtime.finishAgentTurn = finishAgentTurn;
  fixture.runtime.transition = transition;
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
  const correctionCalls = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Pending correction diagnostic batch"),
  );
  assert.equal(correctionCalls.length, 2);
  assert.ok(correctionCalls.every(({ session }) => session === undefined));
});

test("resumes repeated lazy finalization after an interrupted evidence transition", async (t) => {
  const processLoss = new Error(
    "Process stopped before finalization advancement.",
  );
  const { fixture, trustedOutcomes } = await createRevision55Fixture(t, {
    resumeFinalization: true,
    trustedOutcomes: ["PASS", "PASS", "PASS"],
  });
  const transition = fixture.runtime.transition;
  let interrupted = false;
  let stopped = false;
  fixture.runtime.transition = async (patch, options) => {
    if (stopped) {
      throw processLoss;
    }
    if (
      !interrupted &&
      options.activity?.phase === "finalization" &&
      patch.pipelineState.workflowState === "CONFIRM" &&
      patch.pipelineState.finalizationCorrections.length === 1 &&
      patch.pipelineState.finalizationResult !== null
    ) {
      interrupted = true;
      stopped = true;
      throw processLoss;
    }
    return transition(patch, options);
  };

  await assert.rejects(
    fixture.run({ trustedChecks: ["service-check"] }),
    (cause) => cause === processLoss,
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FINALIZE");
  assert.equal(fixture.currentRun.pipelineState.finalizationResult, null);
  assert.equal(
    fixture.currentRun.pipelineState.pendingFinalizationCorrection,
    null,
  );
  assert.equal(
    fixture.currentRun.pipelineState.finalizationCorrections.length,
    1,
  );

  stopped = false;
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(trustedOutcomes.length, 3);
  assert.equal(
    fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "finalization-correction",
    ).length,
    1,
  );
});

test("resumes a reconciled lazy check/fix without replay or recounting", async (t) => {
  const processLoss = new Error(
    "Process stopped after lazy fix reconciliation.",
  );
  let changed = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    sourceSession: SOURCE_SESSION,
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix("CHANGED"),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("If you find any problems, fix them") &&
        !changed
      ) {
        changed = true;
        await writeFile(
          join(request.cwd, "reconciled-lazy-fix.txt"),
          "fixed\n",
        );
      }
    },
  });
  const snapshot = fixture.runtime.git.snapshot;
  const transition = fixture.runtime.transition;
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  let processStopped = false;
  fixture.runtime.git.snapshot = async (options) => {
    if (
      changed &&
      !processStopped &&
      fixture.currentRun.activeTurn?.phase === "check-and-fix"
    ) {
      processStopped = true;
      throw processLoss;
    }
    return snapshot(options);
  };
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    return transition(patch, options);
  };
  fixture.runtime.finishAgentTurn = async (turn) => {
    if (processStopped) {
      throw processLoss;
    }
    return finishAgentTurn(turn);
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.deepEqual(fixture.currentRun.activeTurn, {
    role: "worker",
    phase: "check-and-fix",
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "CHECK_AND_FIX");
  assert.equal(fixture.currentRun.counters.fixRounds, 0);
  const callsBeforeResume = fixture.calls.worker.length;

  processStopped = false;
  fixture.runtime.git.snapshot = snapshot;
  fixture.runtime.transition = transition;
  fixture.runtime.finishAgentTurn = finishAgentTurn;
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.activeTurn, null);
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("If you find any problems, fix them"),
    ).length,
    2,
  );
  assert.ok(fixture.calls.worker.length > callsBeforeResume);
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
});

test("resumes a checkpointed unchanged lazy check without replay", async (t) => {
  const processLoss = new Error("Process stopped after lazy check checkpoint.");
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
  });
  const transition = fixture.runtime.transition;
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  let processStopped = false;
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    const next = await transition(patch, options);
    if (next.pipelineState.workflowState === "CLEAN_CONFIRM") {
      processStopped = true;
      throw processLoss;
    }
    return next;
  };
  fixture.runtime.finishAgentTurn = async (turn) => {
    if (processStopped) {
      throw processLoss;
    }
    return finishAgentTurn(turn);
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.equal(fixture.currentRun.activeTurn, null);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "CLEAN_CONFIRM");
  assert.equal(fixture.currentRun.counters.fixRounds, 1);

  processStopped = false;
  fixture.runtime.transition = transition;
  fixture.runtime.finishAgentTurn = finishAgentTurn;
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("If you find any problems, fix them"),
    ).length,
    1,
  );
});

test("reconstructs an ownerless lazy candidate confirmation without recounting", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    sourceSession: SOURCE_SESSION,
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Return CLEAN only") &&
        !interrupted
      ) {
        interrupted = true;
        const error = new Error("Provider interrupted during confirmation.");
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "CLEAN_CONFIRM");
  Object.assign(fixture.currentRun, {
    activeTurn: { role: "worker", phase: "clean-confirm" },
    pause: null,
    pipelineState: {
      ...paused.pipelineState,
      workflowState: "CLEAN_CONFIRM",
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.counters.correctionRounds, 0);
  const confirmationCalls = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Return CLEAN only"),
  );
  assert.equal(confirmationCalls.length, 3);
  assert.equal(confirmationCalls[1].session, undefined);
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("restores an eligible lazy source fork before resumable launch recovery", async (t) => {
  let rejectBeforeSpawn = true;
  let successfulForks = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    sourceSession: SOURCE_SESSION,
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    onRoleRun(role, request) {
      if (role !== "worker" || request.session?.mode !== "fork") return;
      if (rejectBeforeSpawn) {
        rejectBeforeSpawn = false;
        throw Object.assign(
          new Error("Provider process exited before spawn."),
          {
            code: "ERR_BACKEND_UNAVAILABLE",
            recoverable: true,
            launchRecovery: Object.freeze({
              failureClass: "launch_process_exited",
              checkpoint: "spawn",
            }),
          },
        );
      }
      successfulForks += 1;
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(paused.pause, {
    code: "ERR_BACKEND_UNAVAILABLE",
    resumeState: "CLARIFY",
    launchRecovery: {
      failureClass: "launch_process_exited",
      checkpoint: "spawn",
    },
    reason: "backend_unavailable",
  });
  assert.equal(paused.activeTurn, null);
  assert.equal(paused.pipelineState.lazySourceForkConsumed, false);
  assert.deepEqual(paused.sessionLineage.children, []);
  assert.equal(paused.counters.fixRounds, 0);
  assert.equal(paused.counters.correctionRounds, 0);
  assert.equal(paused.pipelineState.pendingCommit, null);
  assert.deepEqual(paused.pipelineState.completedCommits, []);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    0,
  );

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(successfulForks, 1);
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    2,
  );
  assert.equal(completed.pipelineState.lazySourceForkConsumed, true);
  assert.equal(completed.sessionLineage.children.length, 1);
  assert.equal(completed.counters.fixRounds, 1);
  assert.equal(completed.counters.correctionRounds, 0);
  assert.equal(completed.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("does not resume a late source-fork launch failure", async (t) => {
  for (const [mode, checkpoint] of [
    ["independent", "session"],
    ["combined", "turn_start"],
  ]) {
    await t.test(`${mode}/${checkpoint}`, async (t) => {
      let forkAttempts = 0;
      const fixture = await createFixture(t, {
        mode,
        sourceSession: SOURCE_SESSION,
        onRoleRun(_role, request) {
          if (request.session?.mode !== "fork") return;
          forkAttempts += 1;
          throw blockedLateSourceForkFailure(checkpoint);
        },
      });

      await assert.rejects(fixture.run(), (error) => {
        assert.equal(error.code, "ERR_FIXTURE_UNAVAILABLE");
        assert.equal(error.recoverable, false);
        assert.equal(error.launchRecovery, undefined);
        return true;
      });
      assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
      assert.deepEqual(fixture.currentRun.pause, {
        reason: "internal_failure",
        code: "ERR_FIXTURE_UNAVAILABLE",
        diagnosticClass: "launch_process_exited",
      });
      assert.deepEqual(fixture.currentRun.sessionLineage.children, []);
      assert.equal(forkAttempts, 1);

      const terminal = await fixture.run();
      assert.equal(terminal.pipelineState.workflowState, "FAILED");
      assert.equal(forkAttempts, 1);
    });
  }
});

test("does not restore a lazy source fork for a later fresh launch failure", async (t) => {
  let confirmationFailures = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    sourceSession: SOURCE_SESSION,
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    onRoleRun(role, request) {
      if (
        role !== "worker" ||
        request.schema !== CANDIDATE_CLEAN_CONFIRM_SCHEMA
      ) {
        return;
      }
      confirmationFailures += 1;
      if (confirmationFailures === 1) {
        throw Object.assign(new Error("Provider is unavailable."), {
          code: "ERR_BACKEND_UNAVAILABLE",
          recoverable: true,
        });
      }
      assert.equal(request.session, undefined);
      throw Object.assign(new Error("Fresh provider process exited."), {
        code: "ERR_BACKEND_UNAVAILABLE",
        recoverable: true,
        launchRecovery: Object.freeze({
          failureClass: "launch_process_exited",
          checkpoint: "spawn",
        }),
      });
    },
  });

  const firstPause = await fixture.run();
  assert.equal(firstPause.pipelineState.lazySourceForkConsumed, true);
  assert.equal(firstPause.sessionLineage.children.length, 1);
  Object.assign(fixture.currentRun, {
    sessionLineage: { ...firstPause.sessionLineage, children: [] },
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.deepEqual(paused.pause.launchRecovery, {
    failureClass: "launch_process_exited",
    checkpoint: "spawn",
  });
  assert.equal(paused.pipelineState.lazySourceForkConsumed, true);
  assert.deepEqual(paused.sessionLineage.children, []);
});

test("resumes lazy CLEAN_CONFIRM after Codex usage exhaustion", async (t) => {
  const plan = `## Commit 1: feat(test): add first behavior

Implement the first behavior.

## Commit 2: fix(test): add second behavior

Implement the second behavior.`;
  let secondStepCheckRounds = 0;
  let usageLimitRejected = false;
  let resumedConfirmation;
  const fixture = await createFixture(t, {
    mode: "lazy",
    plan,
    sourceSession: SOURCE_SESSION,
    worker: [clarificationReady(), bootstrapReady("Worker", [1, 2])],
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      cleanConfirmation(),
      finalizationPassed(),
      terminalLazyConfirmation(cleanConfirmation()),
      implementationCompleted(),
      checkAndFix("CHANGED"),
      checkAndFix("CHANGED"),
      checkAndFix("CHANGED"),
      checkAndFix(),
      cleanConfirmation(),
      finalizationPassed(),
      terminalLazyConfirmation(cleanConfirmation()),
    ],
    async onRoleRun(role, request) {
      if (
        role !== "worker" ||
        !request.prompt.includes("Current planned commit:\n## Commit 2:")
      ) {
        return;
      }
      if (request.schema === CHECK_AND_FIX_SCHEMA) {
        secondStepCheckRounds += 1;
        if (secondStepCheckRounds <= 3) {
          await writeFile(
            join(request.cwd, "pending-step-2.txt"),
            `pending round ${secondStepCheckRounds}\n`,
          );
        }
        return;
      }
      if (request.schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA) {
        if (!usageLimitRejected) {
          usageLimitRejected = true;
          const error = new Error("Codex usage capacity is unavailable.");
          error.code = "ERR_CODEX_USAGE_LIMIT";
          error.recoverable = true;
          throw error;
        }
        resumedConfirmation = request;
      }
    },
  });

  const paused = await fixture.run();
  const firstCompletedCommit = paused.pipelineState.completedCommits[0];

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pipelineState.currentStep, 2);
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CODEX_USAGE_LIMIT");
  assert.equal(paused.pause.resumeState, "CLEAN_CONFIRM");
  assert.deepEqual(paused.pipelineState.completedCommits, [
    firstCompletedCommit,
  ]);
  assert.equal(
    paused.pipelineState.repositoryBaseline.head,
    firstCompletedCommit,
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "implementation-1.txt"), "utf8"),
    "implemented step 1\n",
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "implementation-2.txt"), "utf8"),
    "implemented step 2\n",
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "pending-step-2.txt"), "utf8"),
    "pending round 3\n",
  );
  assert.equal(paused.counters.fixRounds, 4);
  assert.equal(paused.counters.correctionRounds, 0);
  assert.deepEqual(
    fixture.transitions.findLast(
      ({ patch }) => patch?.pause?.reason === "backend_unavailable",
    ).patch.pause,
    {
      code: "ERR_CODEX_USAGE_LIMIT",
      resumeState: "CLEAN_CONFIRM",
      reason: "backend_unavailable",
    },
  );
  const implementationCalls = () =>
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Implement the changes"),
    );
  const secondStepCheckCalls = () =>
    fixture.calls.worker.filter(
      ({ prompt, schema }) =>
        schema === CHECK_AND_FIX_SCHEMA &&
        prompt.includes("Current planned commit:\n## Commit 2:"),
    );
  assert.equal(implementationCalls().length, 2);
  assert.equal(secondStepCheckCalls().length, 4);
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
  assert.equal(paused.pipelineState.lazySourceForkConsumed, true);
  assert.equal(paused.sessionLineage.children.length, 1);
  // Model disposal of the failed native child while retaining source-fork state.
  Object.assign(fixture.currentRun, {
    sessionLineage: { ...paused.sessionLineage, children: [] },
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.completedCommits.length, 2);
  assert.equal(
    completed.pipelineState.completedCommits[0],
    firstCompletedCommit,
  );
  assert.equal(completed.counters.fixRounds, 4);
  assert.equal(completed.counters.correctionRounds, 0);
  assert.equal(implementationCalls().length, 2);
  assert.equal(secondStepCheckCalls().length, 4);
  assert.equal(
    await readFile(join(fixture.projectPath, "implementation-1.txt"), "utf8"),
    "implemented step 1\n",
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "implementation-2.txt"), "utf8"),
    "implemented step 2\n",
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "pending-step-2.txt"), "utf8"),
    "pending round 3\n",
  );
  assert.notEqual(resumedConfirmation, undefined);
  assert.equal(resumedConfirmation.access, "read-only");
  assert.equal(resumedConfirmation.session, undefined);
  assert.equal(resumedConfirmation.prompt, resumedConfirmation.recoveryPrompt);
  assert.match(resumedConfirmation.prompt, /## Commit 2:/u);
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("preserves workspace changes after a Claude usage rejection", async (t) => {
  let interruptImplementation = true;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes") &&
        interruptImplementation
      ) {
        interruptImplementation = false;
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
        const error = new Error("Claude usage capacity is unavailable.");
        error.code = "ERR_CLAUDE_USAGE_LIMIT";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_USAGE_LIMIT");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(
    await readFile(join(fixture.projectPath, "source.js"), "utf8"),
    "export const value = 2;\n",
  );
});

test("re-finalizes a partial correction after provider unavailability", async (t) => {
  let interruptResolution = true;
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below") &&
        interruptResolution
      ) {
        interruptResolution = false;
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_PROVIDER_UNAVAILABLE");
  assert.equal(paused.pause.resumeState, "REVIEW");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.deepEqual(paused.pipelineState.findings, []);
  assert.equal(paused.pipelineState.previousFindings[0].id, "R1");
  assert.equal(paused.counters.fixRounds, 1);

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.match(
    fixture.calls.worker.findLast(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /Run the complete project finalization procedure/u,
  );
  assert.match(
    fixture.calls.reviewer.findLast(({ prompt }) =>
      prompt.includes("Previous candidate findings for this step"),
    ).prompt,
    /Previous candidate findings for this step:[\s\S]*"id": "R1"/u,
  );
});

test("invalidates retained finalization after content-changing interrupted terminal resolution", async (t) => {
  let interruptResolution = true;
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewApproved(),
      terminalConfirmation(reviewFindings("R1")),
      reviewApproved(),
      terminalConfirmation(reviewApproved()),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below") &&
        interruptResolution
      ) {
        interruptResolution = false;
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "REVIEW");
  assert.equal(paused.pipelineState.finalizationResult, null);

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    2,
  );
});

test("fails closed after an ambiguous writable Claude process failure", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes") &&
        !interrupted
      ) {
        interrupted = true;
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
        const error = new Error("provider-native secret text");
        error.code = "ERR_CLAUDE_PROCESS_INTERRUPTED";
        error.ambiguous = true;
        throw error;
      }
    },
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_CLAUDE_PROCESS_INTERRUPTED",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pause.reason, "internal_failure");
  assert.equal(fixture.currentRun.pause.code, "ERR_CLAUDE_PROCESS_INTERRUPTED");
  assert.equal(
    await readFile(join(fixture.projectPath, "source.js"), "utf8"),
    "export const value = 2;\n",
  );
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /provider-native/u);
});

test("retries implementation after an environment blocker clears", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationBlocked(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("retries unchanged loopback-blocked finding resolution", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      environmentBlocked(
        "The required loopback endpoint is unavailable.",
        "The validation client could not connect to its loopback service.",
      ),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(paused.pipelineState.finalizationResult.status, "FAIL");
  assert.deepEqual(paused.pause.evidence, [
    "The validation client could not connect to its loopback service.",
  ]);

  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("preserves a partial fix before sandbox-blocked validation", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      environmentBlocked(
        "The validation sandbox rejected a required operation.",
        "The sandbox denied the validation subprocess before it could run.",
      ),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "REVIEW");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.equal(
    await readFile(join(fixture.projectPath, "source.js"), "utf8"),
    "export const value = 2;\n",
  );

  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

for (const mode of ["independent", "lazy"]) {
  for (const [schema, checkpoint] of [
    [IMPLEMENTATION_SCHEMA, "IMPLEMENT"],
    ...(mode === "lazy" ? [[CHECK_AND_FIX_SCHEMA, "CHECK_AND_FIX"]] : []),
    [FINDING_RESOLUTION_SCHEMA, "RESOLVE_FINDINGS"],
  ]) {
    for (const stopKind of [
      "blocked",
      "interrupted",
      ...(checkpoint === "RESOLVE_FINDINGS" ? ["partial-blocked"] : []),
    ]) {
      test(`retains trusted delegation across ${mode} ${checkpoint} ${stopKind} recovery`, async (t) => {
        const command = "npm run test:service";
        const snapshot = trustedValidationSnapshot("service-check", command);
        const requiredChecks = [...REQUIRED_CHECKS, { id: "C2", command }];
        const bootstrap = (role) => ({
          ...bootstrapReady(role),
          requiredChecks,
        });
        const finalization = {
          ...finalizationPassed(),
          requiredChecks,
          checks: [
            ...checkResults("PASS"),
            {
              checkId: "C2",
              command,
              status: "NOT_RUN",
              evidence: ["Reserved for the runner."],
            },
          ],
        };
        const needsResolution = checkpoint === "RESOLVE_FINDINGS";
        const processLoss = new Error(
          "Simulated process loss before a role response.",
        );
        let stopped = false;
        let attempts = 0;
        let trustedCalls = 0;
        const targetCalls = [];
        const fixture = await createFixture(t, {
          mode,
          modeSettings: { trustedChecks: ["service-check"] },
          trustedValidation: snapshot,
          worker: [
            clarificationReady(),
            bootstrap("Worker"),
            ...(mode === "independent" ? [reconciliationResolved()] : []),
          ],
          reviewer: [bootstrap("Reviewer")],
          workWorker: [implementationCompleted(), finalization, finalization],
          onTrustedValidation(options) {
            trustedCalls += 1;
            assert.equal(
              fixture.currentRun.pipelineState.workflowState,
              "FINALIZE",
            );
            assert.deepEqual(options.snapshot, snapshot);
            const failed = needsResolution && trustedCalls === 1;
            return {
              ...options.bindings,
              commandIdentity: options.commandIdentity,
              status: failed ? "FAIL" : "PASS",
              exitCode: failed ? 1 : 0,
              signal: null,
              timedOut: false,
              evidence: ["The runner executed the persisted vector."],
            };
          },
        });
        const runWorker = fixture.runtime.adapters.worker.run;
        fixture.runtime.adapters.worker.run = async (request) => {
          if (request.schema === schema) {
            targetCalls.push(request);
            attempts += 1;
            for (const prompt of [request.prompt, request.recoveryPrompt]) {
              const match =
                /Exact runner-trusted commands reserved for FINALIZE:\n([^\n]+)/u.exec(
                  prompt,
                );
              const delegated = JSON.parse(match?.[1] ?? "[]");
              assert.deepEqual(delegated, [command]);
              assert.ok(!delegated.includes(`${command} -- --generate`));
              assert.ok(!delegated.includes("npm  run test:service"));
              assert.match(
                prompt,
                /work not delegated to a selected runner-trusted command/u,
              );
            }
            if (attempts === 1) {
              fixture.calls.worker.push(request);
              if (stopKind === "interrupted") {
                stopped = true;
                throw processLoss;
              }
              if (stopKind === "partial-blocked") {
                await writeFile(
                  join(request.cwd, "partial-repair.txt"),
                  "safe partial repair\n",
                );
              }
              const blocked = {
                status: "BLOCKED",
                ...(schema === FINDING_RESOLUTION_SCHEMA
                  ? { decisions: [] }
                  : { summary: "" }),
                reason:
                  "An additional generation step requires an unavailable local service.",
                evidence: [
                  `${command} -- --generate is not delegated to the runner.`,
                ],
                question: "",
                whyBlocked: "",
                options: [],
              };
              return {
                sessionId: request.session?.id ?? "blocked-worker",
                structured:
                  schema === CHECK_AND_FIX_SCHEMA
                    ? blocked
                    : { result: blocked },
              };
            }
          }
          if (
            [CHECK_AND_FIX_SCHEMA, FINDING_RESOLUTION_SCHEMA].includes(
              request.schema,
            )
          ) {
            fixture.calls.worker.push(request);
            return {
              sessionId: request.session?.id ?? "recovered-worker",
              structured:
                request.schema === CHECK_AND_FIX_SCHEMA
                  ? checkAndFix()
                  : { result: resolution({ id: "F1", decision: "FIX" }) },
            };
          }
          return runWorker(request);
        };
        const transition = fixture.runtime.transition;
        const finishAgentTurn = fixture.runtime.finishAgentTurn;
        fixture.runtime.transition = async (...args) => {
          if (stopped) throw processLoss;
          return transition(...args);
        };
        fixture.runtime.finishAgentTurn = async (...args) => {
          if (stopped) throw processLoss;
          return finishAgentTurn(...args);
        };

        if (stopKind === "interrupted") {
          await assert.rejects(
            fixture.run({ trustedChecks: ["service-check"] }),
            (error) => error === processLoss,
          );
          assert.notEqual(fixture.currentRun.activeTurn, null);
          assert.equal(
            fixture.currentRun.pipelineState.workflowState,
            checkpoint,
          );
        } else {
          const paused = await fixture.run({
            trustedChecks: ["service-check"],
          });
          assert.equal(paused.pause.reason, "environment_blocked");
          assert.equal(
            paused.pause.resumeState,
            stopKind === "partial-blocked"
              ? mode === "lazy"
                ? "CHECK_AND_FIX"
                : "REVIEW"
              : checkpoint,
          );
          assert.equal(paused.pipelineState.cleanConfirmationFingerprint, null);
          if (stopKind === "partial-blocked") {
            assert.equal(paused.pipelineState.finalizationResult, null);
            assert.equal(
              await readFile(
                join(fixture.projectPath, "partial-repair.txt"),
                "utf8",
              ),
              "safe partial repair\n",
            );
          }
        }
        assert.equal(trustedCalls, needsResolution ? 1 : 0);
        stopped = false;
        fixture.runtime.transition = transition;
        fixture.runtime.finishAgentTurn = finishAgentTurn;

        const completed = await fixture.run();

        assert.equal(completed.pipelineState.workflowState, "DONE");
        assert.deepEqual(completed.pipelineState.trustedValidation, snapshot);
        assert.equal(trustedCalls, needsResolution ? 2 : 1);
        if (stopKind === "interrupted") {
          assert.equal(targetCalls.length, 2);
          if (schema === CHECK_AND_FIX_SCHEMA) {
            assert.equal(targetCalls[1].session?.mode, "continue");
          } else {
            assert.equal(targetCalls[1].session, undefined);
            assert.equal(targetCalls[1].prompt, targetCalls[1].recoveryPrompt);
          }
        }
      });
    }
  }
}

for (const phase of ["prerequisite", "review"]) {
  test(`interrupted narrative availability recovery bounds repeated ${phase} inactivity`, async (t) => {
    let reviewAttempts = 0;
    let expiries = 0;
    let interrupt = true;
    let expire = false;
    let inactivity;
    function expireAttempt(request) {
      expiries++;
      assert.ok(expiries <= 2, "Recovery retry is bounded.");
      return inactivity.expire(request);
    }
    const fixture = await createFixture(t, {
      worker: [
        clarificationReady(),
        clarificationReady(),
        ...(phase === "review" ? [clarificationReady()] : []),
        bootstrapReady("Worker"),
        reconciliationResolved(),
      ],
      onContextReview(_role, request) {
        if (++reviewAttempts === 1) throw availabilityFailure();
        if (expire && phase === "review") return expireAttempt(request);
      },
      onRoleRun(_role, request) {
        if (
          expire &&
          phase === "prerequisite" &&
          request.schema === CLARIFICATION_SCHEMA
        ) {
          return expireAttempt(request);
        }
      },
    });
    attachAvailability(fixture, {
      onWait() {
        if (interrupt) {
          interrupt = false;
          throw new Error("Availability wait interrupted");
        }
      },
    });
    inactivity = await attachInactivity(fixture);
    await assert.rejects(fixture.run(), { code: "ERR_AVAILABILITY_RECOVERY" });
    assert.match(
      fixture.currentRun.availabilityRetry.checkpoint,
      /^plan-context:read-only:/u,
    );
    inactivity.restart();
    expire = true;

    const paused = await fixture.run();

    assert.equal(paused.pause.reason, "backend_unavailable");
    assert.equal(paused.pause.code, "ERR_PROVIDER_INACTIVE");
    assert.equal(expiries, 2);
    assert.equal(reviewAttempts, phase === "prerequisite" ? 1 : 3);
    assert.equal(paused.activeTurn, null);
    assert.equal(paused.inactivityRecovery.attempt, 2);
    assert.ok(paused.inactivityRecovery.reconstructionRevision > 0);
    assert.ok(paused.inactivityRecovery.expiryRevision > 0);
    assert.match(
      paused.inactivityRecovery.checkpoint,
      /^plan-context:read-only:/u,
    );
    expire = false;
    inactivity.restart();
    assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
    assert.equal(fixture.currentRun.inactivityRecovery, null);
  });
}

test("narrative review retains its consumed recovery allowance across repeated output exhaustion", async (t) => {
  let reviewAttempts = 0;
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      clarificationReady(),
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
    async onContextReview(_role, request) {
      if (reviewAttempts < 3) {
        reviewAttempts++;
        assert.equal(request.session?.mode, "continue");
        assert.equal(await request.onFreshSession(), reviewAttempts === 1);
        if (reviewAttempts < 3) throw outputExhaustion();
      }
    },
  });
  attachOutputExhaustion(fixture);
  const inactivity = await attachInactivity(fixture);
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "output_exhausted");
  assert.equal(paused.pause.resumeState, "CLARIFY");
  assert.match(paused.pause.checkpoint, /^plan-context:read-only:/u);
  assert.equal(paused.activeTurn, null);
  assert.equal(fixture.calls.worker.length, 1);
  assert.equal(paused.inactivityRecovery.expiryRevision, null);
  assert.equal(paused.inactivityRecovery.attempt, 2);
  inactivity.restart();
  const repeated = await fixture.run();
  assert.equal(reviewAttempts, 2);
  assert.deepEqual(repeated.pause, paused.pause);
  assert.equal(fixture.calls.worker.length, 2);
  assert.equal(repeated.inactivityRecovery.expiryRevision, null);
  assert.equal(repeated.inactivityRecovery.attempt, 2);
  inactivity.restart();
  assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  assert.equal(reviewAttempts, 3);
  assert.equal(fixture.currentRun.inactivityRecovery, null);
});

for (const checkpoint of ["IMPLEMENT", "FINALIZE", "CONFIRM"]) {
  test(`output exhaustion pauses ${checkpoint} without replay and preserves progress`, async (t) => {
    let failures = 0;
    const fixture = await createFixture(t, {
      async onRoleRun(_role, request) {
        const matches =
          checkpoint === "IMPLEMENT"
            ? request.schema === IMPLEMENTATION_SCHEMA
            : checkpoint === "FINALIZE"
              ? request.schema === FINALIZATION_SCHEMA
              : request.schema === REVIEW_SCHEMA;
        if (matches && failures < 2) {
          failures++;
          if (request.access === "workspace-write") {
            await writeFile(
              join(request.cwd, "partial.txt"),
              `Progress ${failures}\n`,
            );
          }
          throw outputExhaustion();
        }
      },
    });
    attachOutputExhaustion(fixture);
    const first = await fixture.run();
    assert.equal(failures, 1);
    assert.equal(first.pause.reason, "output_exhausted");
    assert.equal(first.pause.resumeState, checkpoint);
    assert.equal(first.activeTurn, null);
    assert.equal(first.pipelineState.pendingCommit, null);
    assert.equal(first.pipelineState.reviewedFingerprint, null);
    const second = await fixture.run();
    assert.equal(failures, 2);
    assert.deepEqual(second.pause, first.pause);
    assert.deepEqual(second.counters, first.counters);
    if (checkpoint !== "CONFIRM") {
      assert.equal(
        await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
        "Progress 2\n",
      );
      assert.equal(second.pipelineState.finalizationResult, null);
    } else {
      assert.equal(second.pipelineState.finalizationResult.status, "PASS");
    }
    const pause = planExecutionPipeline.projections.pause(second);
    assert.deepEqual(pause.nextActions, [{ type: "resume", action: null }]);
    assert.equal(pause.evidence.length, 2);
    assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  });
}

test("combined output-exhausted check/fix charges partial corrections once", async (t) => {
  let failures = 0;
  let publicationInterrupted = false;
  const fixture = await createFixture(t, {
    mode: "combined",
    modeSettings: { maxFixRoundsPerStep: 1 },
    onTransition(_run, patch) {
      if (
        patch.pause?.reason === "output_exhausted" &&
        !publicationInterrupted
      ) {
        publicationInterrupted = true;
        throw Object.assign(new Error("Pause publication interrupted"), {
          code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        });
      }
    },
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      cleanConfirmation(),
      finalizationPassed(),
    ],
    async onRoleRun(_role, request) {
      if (request.schema === CHECK_AND_FIX_SCHEMA && failures < 2) {
        failures++;
        await writeFile(
          join(request.cwd, "partial.txt"),
          `Correction ${failures}\n`,
        );
        throw outputExhaustion();
      }
    },
  });
  attachOutputExhaustion(fixture);
  await assert.rejects(fixture.run(), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
  const first = fixture.currentRun;
  const second = await fixture.run();
  for (const run of [first, second]) {
    assert.equal(run.pause.reason, "output_exhausted");
    assert.equal(run.pause.resumeState, "CHECK_AND_FIX");
    assert.equal(run.counters.fixRounds, 1);
    assert.equal(run.activeTurn, null);
    assert.equal(run.pipelineState.candidateConfirmationFingerprint, null);
    assert.equal(run.pipelineState.candidateReviewedFingerprint, null);
    assert.equal(run.pipelineState.finalizationResult, null);
  }
  await fixture.runtime.transition({
    pipelineState: {
      ...second.pipelineState,
      workflowState: "CHECK_AND_FIX",
    },
    pause: null,
  });
  await fixture.runtime.startAgentTurn({
    role: "worker",
    phase: "check-and-fix",
  });
  await writeFile(join(fixture.projectPath, "partial.txt"), "Stopped repair\n");
  const calls = fixture.calls.worker.length;
  const stopped = await runPlanExecution({
    run: fixture.currentRun,
    runtime: fixture.runtime,
    operatorStop: true,
  });
  assert.equal(stopped.counters.fixRounds, 1);
  assert.equal(fixture.calls.worker.length, calls);
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
});

for (const recovery of ["paused", "interrupted", "validation-migration"]) {
  test(`output exhaustion preserves a malformed check/fix charge at the one-round boundary (${recovery})`, async (t) => {
    const processLoss = new Error("Process stopped before reconciliation.");
    let processStopped = false;
    let attempts = 0;
    const fixture = await createFixture(t, {
      mode: "combined",
      modeSettings: { maxFixRoundsPerStep: 1 },
      workWorker: [
        implementationCompleted(),
        { ...checkAndFix("CHANGED"), unexpected: "rejected" },
        ...(recovery === "validation-migration"
          ? [bootstrapReady("Migrating Worker"), reconciliationResolved()]
          : []),
        checkAndFix(),
        cleanConfirmation(),
        finalizationPassed(),
      ],
      workReviewer:
        recovery === "validation-migration"
          ? [bootstrapReady("Migrating Reviewer"), reviewApproved()]
          : [reviewApproved()],
      async onRoleRun(_role, request) {
        if (request.schema !== CHECK_AND_FIX_SCHEMA || ++attempts > 2) return;
        await writeFile(
          join(request.cwd, "partial.txt"),
          `Correction ${attempts}\n`,
        );
        if (attempts === 2) {
          assert.equal(fixture.currentRun.counters.fixRounds, 1);
          assert.equal(
            fixture.currentRun.pipelineState.pendingLazyCorrection
              .fixRoundCharged,
            true,
          );
          processStopped = recovery !== "paused";
          throw outputExhaustion();
        }
      },
    });
    attachOutputExhaustion(fixture);
    for (const [owner, method] of [
      [fixture.runtime.git, "snapshot"],
      [fixture.runtime, "transition"],
      [fixture.runtime, "finishAgentTurn"],
    ]) {
      const operation = owner[method].bind(owner);
      owner[method] = (...args) => {
        if (processStopped) throw processLoss;
        return operation(...args);
      };
    }

    if (recovery !== "paused") {
      await assert.rejects(fixture.run(), (cause) => cause === processLoss);
      assert.deepEqual(fixture.currentRun.activeTurn, {
        role: "worker",
        phase: "check-and-fix",
      });
      processStopped = false;
      if (recovery === "validation-migration") {
        fixture.persistPipelineState({
          ...fixture.currentRun.pipelineState,
          validationMigrationPending: true,
          validationScopeLegacy: true,
          validationSchedule: null,
          workerValidation: null,
          reviewerValidation: null,
        });
      }
    } else {
      const paused = await fixture.run();
      assert.equal(paused.pause.reason, "output_exhausted");
      assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
      assert.equal(paused.activeTurn, null);
      assert.equal(paused.pipelineState.candidateConfirmationFingerprint, null);
      assert.equal(paused.pipelineState.candidateReviewedFingerprint, null);
      assert.equal(paused.pipelineState.finalizationResult, null);
    }
    assert.equal(fixture.currentRun.counters.fixRounds, 1);
    assert.equal(
      await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
      "Correction 2\n",
    );
    const completed = await fixture.run();
    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    assert.equal(completed.counters.fixRounds, 1);
  });
}

test("output exhaustion retries the charged finding fix at the correction boundary", async (t) => {
  let failures = 0;
  const fixture = await createFixture(t, {
    modeSettings: { maxFixRoundsPerStep: 1 },
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
    async onRoleRun(_role, request) {
      if (request.schema === FINDING_RESOLUTION_SCHEMA) {
        assert.equal(request.access, "workspace-write");
        if (failures < 2) {
          failures++;
          await writeFile(
            join(request.cwd, "partial.txt"),
            `Repair ${failures}\n`,
          );
          throw outputExhaustion();
        }
      }
    },
  });
  attachOutputExhaustion(fixture);
  for (let attempt = 0; attempt < 2; attempt++) {
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "output_exhausted");
    assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
    assert.equal(paused.counters.fixRounds, 1);
    assert.equal(paused.pipelineState.finalizationResult, null);
  }
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
});
