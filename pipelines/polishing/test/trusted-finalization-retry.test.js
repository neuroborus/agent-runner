import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  bootstrapReady,
  candidateApproved,
  candidateClean,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createFixture,
  environmentBlocked,
  finalizationPassed,
  polishingCompleted,
  reconciliationResolved,
  reviewApproved,
  reviewFindings,
  trustedValidationSnapshot,
} from "./support/index.js";

async function retryFixture(
  t,
  {
    mode = "lazy",
    outcomes = ["FAIL", "FAIL", "PASS"],
    agentFailure = false,
    formatOnSuccess = false,
  } = {},
) {
  const trusted = trustedValidationSnapshot(
    "service-check",
    "npm run test:service",
    { sourceProjection: true },
  );
  const command = trusted.commands[0];
  const finalization = finalizationPassed();
  finalization.requiredChecks = [
    ...finalization.requiredChecks,
    { id: "C2", command: command.command },
  ];
  finalization.validationInfrastructure = [
    ...finalization.validationInfrastructure,
    "package.json",
  ];
  finalization.checks = [
    ...finalization.checks,
    {
      checkId: "C2",
      command: command.command,
      status: "NOT_RUN",
      evidence: ["Reserved for Runner execution."],
    },
  ];
  if (agentFailure) {
    finalization.status = "FAIL";
    finalization.checks[0].status = "FAIL";
    finalization.issues = [
      {
        id: "F1",
        // Naming the trusted command cannot make a Worker issue eligible.
        command: command.command,
        problem: "The Worker identified a content defect.",
        evidence: ["The implementation mishandles absent input."],
      },
    ];
  }
  const bootstrap = (role) => ({
    ...bootstrapReady(role),
    requiredChecks: finalization.requiredChecks,
    validationInfrastructure: finalization.validationInfrastructure,
  });
  const blocked = () =>
    environmentBlocked(
      "The available evidence does not identify a safe content repair.",
      "A complete finalization retry needs explicit authorization.",
    );
  const executions = [];
  const events = [];
  const handoffs = [];
  const fixture = await createFixture(t, {
    mode,
    modeSettings: { trustedChecks: [command.alias] },
    trustedValidation: trusted,
    async prepareProject(projectPath) {
      await writeFile(join(projectPath, "package.json"), "{}\n");
    },
    worker: [
      clarificationReady(),
      bootstrap("Worker"),
      ...(mode === "lazy" ? [] : [reconciliationResolved()]),
      polishingCompleted(),
      ...(mode === "independent" ? [] : [checkAndFix(), candidateClean()]),
      ...outcomes.flatMap((status) => [
        structuredClone(finalization),
        ...(status === "FAIL" || agentFailure ? [blocked()] : []),
      ]),
      ...(outcomes.at(-1) === "PASS" && !agentFailure
        ? mode === "lazy"
          ? [cleanConfirmation()]
          : []
        : [blocked()]),
    ],
    reviewer: [bootstrap("Reviewer"), candidateApproved(), reviewApproved()],
    async onRoleRun(role, request) {
      const phase = fixture.currentRun.activeTurn.phase;
      events.push([role, phase, request.access]);
      if (
        formatOnSuccess &&
        phase === "finalize" &&
        outcomes[executions.length] === "PASS"
      ) {
        await writeFile(join(fixture.projectPath, "change.txt"), "formatted\n");
      }
    },
    onTrustedValidation(options) {
      const status = outcomes[executions.length];
      assert.notEqual(status, undefined, "Unexpected trusted execution.");
      executions.push(options);
      events.push(["runner", "trusted", options.commandIdentity]);
      return {
        ...options.bindings,
        status,
        commandIdentity: options.commandIdentity,
        exitCode: status === "FAIL" ? 7 : 0,
        signal: null,
        timedOut: false,
        evidence: [
          `Runner-trusted command exited with code ${status === "FAIL" ? 7 : 0}.`,
          ...(status === "FAIL" && executions.length > 1
            ? ["Trusted check error class: ERR_ASSERTION."]
            : []),
        ],
      };
    },
  });
  const stage = fixture.runtime.git.stagePolishingHandoff;
  fixture.runtime.git.stagePolishingHandoff = async (options) => {
    events.push(["runner", "handoff"]);
    handoffs.push(options);
    return stage.call(fixture.runtime.git, options);
  };
  return { fixture, trusted, executions, events, handoffs };
}

function preserved(run) {
  const state = run.pipelineState;
  return {
    counters: run.counters,
    ...Object.fromEntries(
      [
        "settings",
        "additionalFixRounds",
        "correctionHistory",
        "sameFindingRounds",
        "blockedSinceStagnation",
        "finalizationRecovery",
        "candidateReviewResult",
        "candidateReviewedFingerprint",
        "candidateConfirmationFingerprint",
        "lazyCorrections",
        "findingOverrides",
      ].map((field) => [field, state[field]]),
    ),
  };
}

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} requires a separate explicit resume for each complete trusted finalization retry`, async (t) => {
    const { fixture, trusted, executions, events, handoffs } =
      await retryFixture(t, { mode, formatOnSuccess: true });
    const first = await fixture.run();
    assert.equal(first.pause.reason, "environment_blocked");
    assert.equal(first.pause.resumeState, "RESOLVE_FINDINGS");
    assert.equal(executions.length, 1);
    assert.equal(handoffs.length, 0);
    const historical = fixture.transitions.filter(
      ({ patch }) => patch.pipelineState?.finalizationResult?.status === "FAIL",
    );
    const savedHistory = structuredClone(historical);
    const seeded = await fixture.persistPipelineState(
      {
        ...first.pipelineState,
        additionalFixRounds: 2,
        blockedSinceStagnation: 1,
        sameFindingRounds: { R1: 1 },
        correctionHistory: [
          {
            round: 1,
            fingerprint: first.pipelineState.finalizationResult.fingerprint,
            finalizationIssueIds: [],
            findingIds: ["R1"],
          },
        ],
      },
      { ...first.counters, fixRounds: 2, correctionRounds: 1 },
    );
    const accepted = structuredClone(preserved(seeded));
    const before = events.length;
    await fixture.recover();
    const repeated = await fixture.run(null);
    assert.equal(repeated.pause.reason, "environment_blocked");
    assert.equal(repeated.pause.resumeState, "RESOLVE_FINDINGS");
    assert.equal(executions.length, 2);
    assert.equal(handoffs.length, 0);
    assert.deepEqual(events.slice(before), [
      ["worker", "finalize", "workspace-write"],
      ["runner", "trusted", trusted.commands[0].identity],
      ["worker", "resolve-findings", "workspace-write"],
    ]);
    assert.deepEqual(preserved(repeated), accepted);
    assert.equal(repeated.pipelineState.finalizedFingerprint, null);
    assert.equal(repeated.pipelineState.reviewResult, null);
    assert.match(
      fixture.calls.worker.at(-1).prompt,
      /Trusted check error class: ERR_ASSERTION\./u,
    );
    assert.deepEqual(executions[1].bindings, executions[0].bindings);

    const retryStart = events.length;
    const completed = await fixture.run(null);
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(executions.length, 3);
    assert.deepEqual(events.slice(retryStart), [
      ["worker", "finalize", "workspace-write"],
      ["runner", "trusted", trusted.commands[0].identity],
      [mode === "lazy" ? "worker" : "reviewer", "confirm", "read-only"],
      ["runner", "handoff"],
    ]);
    assert.deepEqual(preserved(completed), accepted);
    assert.deepEqual(historical, savedHistory);
    assert.equal(handoffs.length, 1);
    const state = completed.pipelineState;
    const evidence = state.finalizationResult;
    assert.equal(evidence.status, "PASS");
    assert.notEqual(evidence.fingerprint, state.candidateReviewedFingerprint);
    assert.deepEqual(executions[2].bindings, {
      contentFingerprint: evidence.fingerprint,
      validationInfrastructureFingerprint:
        evidence.validationInfrastructureFingerprint,
      commandFingerprint: trusted.commandFingerprint,
      configurationFingerprint: trusted.configurationFingerprint,
    });
    assert.deepEqual(
      evidence.checks.map(({ executor }) => executor),
      ["agent", "runner"],
    );
    assert.equal(
      evidence.checks[1].commandIdentity,
      trusted.commands[0].identity,
    );
    assert.equal(state.reviewResult.fingerprint, evidence.fingerprint);
    const confirmation =
      fixture.calls[mode === "lazy" ? "worker" : "reviewer"].at(-1);
    assert.ok(confirmation.prompt.includes(JSON.stringify(evidence, null, 2)));
    assert.equal(handoffs[0].finalizedFingerprint, evidence.fingerprint);
    assert.equal(handoffs[0].reviewedFingerprint, evidence.fingerprint);
    assert.equal(
      state.repositoryBaseline.head,
      first.pipelineState.repositoryBaseline.head,
    );
    for (const execution of executions) {
      assert.deepEqual(execution.snapshot, trusted);
      assert.equal(execution.commandIdentity, trusted.commands[0].identity);
      assert.equal(
        execution.sourceHead,
        first.pipelineState.repositoryBaseline.head,
      );
    }
    const authorizations = fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "trusted-retry-authorized",
    );
    assert.equal(authorizations.length, 2);
    for (const { patch } of authorizations) {
      assert.equal(patch.pause, null);
      assert.equal(patch.pipelineState.workflowState, "FINALIZE");
      assert.equal(patch.pipelineState.finalizationResult, null);
      assert.equal(patch.pipelineState.finalizedFingerprint, null);
      assert.equal(patch.pipelineState.reviewResult, null);
      assert.deepEqual(preserved({ ...completed, ...patch }), accepted);
    }
    const settledEvents = events.length;
    await fixture.run(null);
    assert.equal(events.length, settledEvents);
    assert.equal(handoffs.length, 1);
    assert.equal(fixture.calls.arbiter.length, 0);
    if (mode === "lazy") assert.equal(fixture.calls.reviewer.length, 0);
  });
}

for (const outcome of ["PASS", "FAIL"]) {
  test(`agent failure with trusted ${outcome} stays in ordinary resolution`, async (t) => {
    const { fixture, executions, events } = await retryFixture(t, {
      outcomes: [outcome],
      agentFailure: true,
    });
    const first = await fixture.run();
    assert.equal(
      first.pipelineState.finalizationResult.issues.length,
      outcome === "FAIL" ? 2 : 1,
    );
    const before = events.length;
    const resumed = await fixture.run(null);
    assert.deepEqual(events.slice(before), [
      ["worker", "resolve-findings", "workspace-write"],
    ]);
    assert.equal(executions.length, 1);
    assert.equal(resumed.pause.resumeState, "RESOLVE_FINDINGS");
    assert.deepEqual(
      resumed.pipelineState.finalizationResult,
      first.pipelineState.finalizationResult,
    );
  });
}

for (const field of ["additional", "id", "command", "problem", "evidence"]) {
  test(`${field} generated-issue mismatch excludes trusted retry`, async (t) => {
    const { fixture, executions, events } = await retryFixture(t, {
      outcomes: ["FAIL"],
    });
    const first = await fixture.run();
    const failed = structuredClone(first.pipelineState.finalizationResult);
    if (field === "additional") {
      failed.issues.push({ ...failed.issues[0], id: "F2" });
    } else {
      failed.issues[0][field] = {
        id: "F2",
        command: "npm run other-check",
        problem: "An independent content issue remains.",
        evidence: ["Different evidence."],
      }[field];
    }
    await fixture.persistPipelineState({
      ...first.pipelineState,
      finalizationResult: failed,
    });
    const before = events.length;
    const resumed = await fixture.run(null);
    assert.equal(resumed.pause.resumeState, "RESOLVE_FINDINGS");
    assert.equal(executions.length, 1);
    assert.deepEqual(events.slice(before), [
      ["worker", "resolve-findings", "workspace-write"],
    ]);
    assert.deepEqual(resumed.pipelineState.finalizationResult, failed);
  });
}

for (const blocker of ["candidate", "finding", "dispute", "reconsideration"]) {
  test(`pending ${blocker} evidence prevents trusted retry`, async (t) => {
    const { fixture, executions, events } = await retryFixture(t, {
      mode: "independent",
      outcomes: ["FAIL"],
    });
    const first = await fixture.run();
    const finding = reviewFindings().findings[0];
    const patches = {
      candidate: {
        candidateReviewResult: null,
        candidateReviewedFingerprint: null,
      },
      finding: { findings: [finding] },
      dispute: {
        previousFindings: [finding],
        pendingDisputes: [
          {
            findingId: finding.id,
            reason: "The finding remains disputed.",
            evidence: ["Review is pending."],
          },
        ],
        disputeCounts: { [finding.id]: 1 },
      },
      reconsideration: {
        previousFindings: [finding],
        reviewReconsideration: [finding.id],
      },
    };
    await fixture.persistPipelineState({
      ...first.pipelineState,
      ...patches[blocker],
    });
    const before = events.length;
    if (blocker === "reconsideration") {
      // This checkpoint cannot enter resolution with pending reconsideration.
      await assert.rejects(
        fixture.run(null),
        /review reconsideration is inapplicable/u,
      );
    } else {
      await fixture.run(null);
    }
    assert.equal(executions.length, 1);
    assert.ok(
      events.slice(before).every(([, phase]) => phase === "resolve-findings"),
    );
  });
}

for (const drift of ["content", "infrastructure", "inputs", "guidance"]) {
  test(`${drift} drift fails closed before retry effects`, async (t) => {
    const { fixture, executions, events, handoffs } = await retryFixture(t);
    const first = await fixture.run();
    if (drift === "content") {
      await writeFile(join(fixture.projectPath, "external.txt"), "changed\n");
    } else if (drift === "infrastructure") {
      const inspect = fixture.runtime.git.validationInfrastructureFingerprint;
      fixture.runtime.git.validationInfrastructureFingerprint = async (
        options,
      ) =>
        options.paths.includes("package.json")
          ? "f".repeat(64)
          : inspect(options);
    } else if (drift === "inputs") {
      await writeFile(join(fixture.taskPath, "task.md"), "Changed task.\n");
    } else {
      await writeFile(
        join(fixture.projectPath, ".agents/skills/finalization/SKILL.md"),
        "Changed guidance.\n",
      );
    }
    const before = events.length;
    const resumed = await fixture.run(null);
    assert.equal(
      resumed.pause.reason,
      {
        content: "unsafe_git_state",
        infrastructure: "unsafe_git_state",
        inputs: "task_input_changed",
        guidance: "finalization_skill_invalid",
      }[drift],
    );
    if (drift === "infrastructure") {
      assert.equal(
        resumed.pause.code,
        "ERR_TRUSTED_VALIDATION_BINDING_CHANGED",
      );
      assert.equal(
        resumed.pipelineState.repositoryBaseline.contentFingerprint,
        first.pipelineState.repositoryBaseline.contentFingerprint,
      );
    }
    assert.equal(events.length, before);
    assert.equal(executions.length, 1);
    assert.equal(handoffs.length, 0);
  });
}
