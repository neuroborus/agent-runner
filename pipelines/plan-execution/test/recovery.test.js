import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { planExecutionPipeline } from "../src/index.js";
import {
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  FINALIZATION_SCHEMA,
} from "../src/schemas.js";
import {
  PLAN,
  SOURCE_SESSION,
  arbitrationResolved,
  bootstrapReady,
  checkAndFix,
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
  resolution,
  reviewApproved,
  reviewFindings,
  terminalConfirmation,
  terminalLazyConfirmation,
} from "./support/index.js";

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
    worker: [clarificationReady(), bootstrapReady("Worker")],
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
