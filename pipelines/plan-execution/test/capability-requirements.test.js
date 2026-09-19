import assert from "node:assert/strict";
import test from "node:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { createTrustedValidationService } from "../../../src/trusted-validation/index.js";
import { migratePlanExecutionStateV17 } from "../src/index.js";
import {
  normalizeBootstrapResult,
  normalizePipelineState,
} from "../src/workflow-contract.js";
import {
  REQUIRED_CHECKS,
  checkAndFix,
  bootstrapReady,
  clarificationReady,
  reconciliationResolved,
  reconciliationDisagreement,
  arbitrationResolved,
  createFixture,
  createLegacyRecoveryFixture,
  implementationBlocked,
  implementationCompleted,
  finalizationPassed,
  finalizationFailed,
  finalizationWithTrustedCheck,
  resolution,
  trustedValidationSnapshot,
} from "./support/index.js";

const command = REQUIRED_CHECKS[0].command;
const requirement = (target = command) => ({
  command: target,
  commandIdentity: null,
  capabilities: { scratch: true, cache: false, artifacts: [] },
  unsupported: [],
});
const blocked = (target = command) => ({
  status: "BLOCKED",
  blockers: [
    { command: target, reason: "unavailable", evidence: ["Unavailable."] },
  ],
});
const ready = { status: "READY", blockers: [] };
const writes = (fixture) =>
  Object.values(fixture.calls)
    .flat()
    .filter(({ access }) => access !== "read-only");
const bootstrapTurns = (mode, worker = bootstrapReady("Worker")) => [
  clarificationReady(),
  worker,
  ...(mode === "lazy" ? [] : [reconciliationResolved()]),
];
function legacy(run) {
  const pipelineState = structuredClone(run.pipelineState);
  for (const role of ["worker", "reviewer"]) {
    const value = pipelineState[`${role}Validation`];
    if (value) {
      delete value.capabilityRequirements;
      delete value.environmentBlockers;
    }
  }
  return migratePlanExecutionStateV17({ ...run, pipelineState });
}

test("capability reports reject malformed parameters and noninventory commands", () => {
  const result = bootstrapReady("Worker");
  for (const report of [
    { ...requirement(), command: "node undeclared" },
    { ...requirement(), commandIdentity: "private value" },
    {
      ...requirement(),
      capabilities: { ...requirement().capabilities, scratch: "/tmp" },
    },
    { ...requirement(), unsupported: ["secret\ntext"] },
    {
      ...requirement(),
      capabilities: {
        scratch: true,
        cache: false,
        artifacts: [{ url: "https://localhost/file", sha256: "a".repeat(64) }],
      },
    },
  ]) {
    assert.throws(
      () =>
        normalizeBootstrapResult(
          { ...result, capabilityRequirements: [report] },
          "worker",
        ),
      { code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT" },
    );
  }
  assert.throws(() =>
    normalizeBootstrapResult(
      { ...result, capabilityRequirements: Array(257).fill(requirement()) },
      "worker",
    ),
  );
  assert.throws(() =>
    normalizeBootstrapResult(
      {
        ...result,
        environmentBlockers: [
          { command, source: "host", evidence: ["Unavailable"] },
        ],
      },
      "worker",
    ),
  );
  const normalized = normalizeBootstrapResult(
    { ...result, capabilityRequirements: [requirement()] },
    "worker",
  );
  assert.ok(Object.isFrozen(normalized.capabilityRequirements[0].capabilities));
});

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} persists accepted requirements and blocks unselected needs before writing`, async (t) => {
    const report = {
      ...bootstrapReady("Worker"),
      capabilityRequirements: [requirement()],
    };
    const malformed = {
      ...report,
      capabilityRequirements: [requirement("node outside-inventory")],
    };
    const root = createTrustedValidationService();
    let inspections = 0;
    const fixture = await createFixture(t, {
      mode,
      worker: [
        clarificationReady(),
        malformed,
        report,
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
      ],
      async onRequirementInspection(input) {
        inspections++;
        assert.deepEqual(
          fixture.currentRun.pipelineState.workerValidation
            .capabilityRequirements,
          report.capabilityRequirements,
        );
        return root.inspectRequirements(input);
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "environment_blocked");
    assert.equal(paused.pause.resumeState, "IMPLEMENT");
    assert.match(paused.pause.evidence[0], /not-selected/u);
    assert.equal(paused.pipelineState.bootstrapCorrections.length, 1);
    assert.equal(writes(fixture).length, 0);
    assert.deepEqual(paused.pipelineState.completedCommits, []);
    const snapshot = structuredClone(paused.pipelineState.trustedValidation);
    await fixture.run();
    assert.equal(inspections, 2);
    assert.equal(writes(fixture).length, 0);
    assert.deepEqual(
      fixture.currentRun.pipelineState.trustedValidation,
      snapshot,
    );
  });

  test(`${mode} exact delegated sandbox reports retry saved availability without running checks early`, async (t) => {
    const snapshot = trustedValidationSnapshot();
    const target = snapshot.commands[0].command;
    const finalization = finalizationWithTrustedCheck(snapshot);
    const report = {
      ...bootstrapReady("Worker"),
      requiredChecks: finalization.requiredChecks,
      environmentBlockers: [
        {
          command: target,
          source: "agent-sandbox",
          evidence: ["Agent cannot access isolation."],
        },
      ],
    };
    let available = false;
    let checked = 0;
    const requests = [];
    const fixture = await createFixture(t, {
      mode,
      trustedValidation: snapshot,
      modeSettings: { trustedChecks: ["service-check"] },
      worker: bootstrapTurns(mode, report),
      reviewer: [
        {
          ...bootstrapReady("Reviewer"),
          requiredChecks: finalization.requiredChecks,
        },
      ],
      workWorker: [
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        finalization,
      ],
      onRequirementInspection(input) {
        requests.push(structuredClone(input));
        return available ? ready : blocked(target);
      },
      onTrustedValidation(input) {
        checked++;
        assert.equal(
          fixture.currentRun.pipelineState.workflowState,
          "FINALIZE",
        );
        return {
          status: "PASS",
          commandIdentity: input.commandIdentity,
          exitCode: 0,
          signal: null,
          timedOut: false,
          evidence: ["Fake required check passed."],
          ...input.bindings,
        };
      },
    });
    const settings = { trustedChecks: ["service-check"] };
    const paused = await fixture.run(settings);
    assert.equal(paused.pause.reason, "environment_blocked");
    assert.equal(checked, 0);
    assert.equal(writes(fixture).length, 0);
    available = true;
    const completed = await fixture.run(settings);
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(checked, 1);
    assert.ok(requests.length >= 4); // blocked implementation, retry, finalize, commit
    assert.ok(
      requests.every(
        (input) => JSON.stringify(input) === JSON.stringify(requests[0]),
      ),
    );
    assert.deepEqual(completed.pipelineState.trustedValidation, snapshot);
    if (mode === "lazy") assert.equal(fixture.calls.reviewer.length, 0);
  });

  test(`${mode} legacy requirement discovery stays read-only before resumed content work`, async (t) => {
    let unavailable = false;
    const fixture = await createFixture(t, {
      mode,
      worker: bootstrapTurns(mode),
      workWorker: [
        implementationBlocked(),
        bootstrapReady("Migrating Worker"),
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        finalizationPassed(),
      ],
      workReviewer: [bootstrapReady("Migrating Reviewer")],
      onRequirementInspection() {
        return unavailable ? blocked() : ready;
      },
    });
    const paused = await fixture.run();
    const migrated = legacy(paused);
    assert.equal(migrated.workerValidation.capabilityRequirements, null);
    fixture.persistPipelineState(migrated);
    const before = writes(fixture).length;
    unavailable = true;
    const blockedRun = await fixture.run();
    assert.equal(blockedRun.pause.reason, "environment_blocked");
    assert.equal(writes(fixture).length, before);
    const discovery = Object.values(fixture.calls)
      .flat()
      .filter(({ prompt }) =>
        prompt.includes("versioned-state migration checkpoint"),
      );
    assert.equal(discovery.length, mode === "lazy" ? 1 : 2);
    assert.ok(discovery.every(({ access }) => access === "read-only"));
    assert.equal(blockedRun.pipelineState.validationMigrationPending, false);
    unavailable = false;
    assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  });

  test(`${mode} consumed legacy commit verification bypasses inspection`, async (t) => {
    let interrupted = true;
    const fixture = await createFixture(t, {
      mode,
      worker: bootstrapTurns(mode),
      workWorker: [
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        finalizationPassed(),
      ],
      onCommitVerify() {
        if (interrupted)
          throw new Error("Verification temporarily unavailable");
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
    const migrated = legacy(paused);
    assert.deepEqual(
      migrated.pendingCommit,
      paused.pipelineState.pendingCommit,
    );
    fixture.persistPipelineState(migrated);
    const calls = Object.values(fixture.calls).flat().length;
    fixture.runtime.trustedValidation.inspectRequirements = () =>
      assert.fail("Consumed settlement cannot prepare capabilities");
    interrupted = false;
    const completed = await fixture.run();
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.pipelineState.completedCommits.length, 1);
    assert.equal(Object.values(fixture.calls).flat().length, calls);
  });
}

test("reconciliation and arbitration preserve Reviewer-only blocker reports", async (t) => {
  const root = createTrustedValidationService();
  const report = {
    command,
    source: "agent-sandbox",
    evidence: ["Not delegated."],
  };
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
    reviewer: [
      { ...bootstrapReady("Reviewer"), environmentBlockers: [report] },
    ],
    arbiter: [arbitrationResolved()],
    onRequirementInspection: (input) => root.inspectRequirements(input),
  });
  const paused = await fixture.run();
  assert.equal(paused.pipelineState.bootstrapArbitrationUsed, true);
  assert.deepEqual(
    paused.pipelineState.reviewerValidation.environmentBlockers,
    [report],
  );
  assert.match(paused.pause.evidence[0], /not-selected/u);
  assert.equal(writes(fixture).length, 0);
});

for (const [mode, checkpoint] of [
  ["independent", "FINALIZE"],
  ["lazy", "CHECK_AND_FIX"],
  ["combined", "RESOLVE_FINDINGS"],
  ["independent", "COMMIT"],
]) {
  test(`${mode} availability loss blocks ${checkpoint} in the same invocation and retries`, async (t) => {
    let unavailable = true;
    const fixture = await createFixture(t, {
      mode,
      worker: bootstrapTurns(mode),
      workWorker: [
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        ...(checkpoint === "RESOLVE_FINDINGS"
          ? [
              finalizationFailed("F1"),
              resolution({ id: "F1", decision: "FIX" }),
              checkAndFix(),
            ]
          : []),
        finalizationPassed(),
      ],
      onRequirementInspection() {
        return unavailable &&
          fixture.currentRun.pipelineState.workflowState === checkpoint
          ? blocked()
          : ready;
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "environment_blocked");
    assert.equal(paused.pause.resumeState, checkpoint);
    assert.deepEqual(paused.pipelineState.completedCommits, []);
    const turns = Object.values(fixture.calls).flat().length;
    await fixture.run();
    assert.equal(Object.values(fixture.calls).flat().length, turns);
    unavailable = false;
    assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
    assert.doesNotThrow(() =>
      normalizePipelineState(fixture.currentRun.pipelineState),
    );
  });
}

test("reports cannot add authority to frozen selected commands", async (t) => {
  const snapshot = trustedValidationSnapshot();
  const target = snapshot.commands[0].command;
  const needs = requirement(target);
  const base = {
    ...bootstrapReady("Worker"),
    requiredChecks: finalizationWithTrustedCheck(snapshot).requiredChecks,
  };
  const root = createTrustedValidationService();
  for (const [fields, reason] of [
    [{ capabilityRequirements: [needs] }, "insufficient-authority"],
    [
      {
        capabilityRequirements: [{ ...needs, commandIdentity: "a".repeat(64) }],
      },
      "insufficient-authority",
    ],
    [
      {
        capabilityRequirements: [
          {
            ...needs,
            capabilities: {
              scratch: false,
              cache: false,
              artifacts: [
                {
                  url: "https://downloads.example.com/tool",
                  sha256: "a".repeat(64),
                },
              ],
            },
          },
        ],
      },
      "insufficient-authority",
    ],
    [
      { capabilityRequirements: [{ ...needs, unsupported: ["network"] }] },
      "unsupported",
    ],
    [
      {
        environmentBlockers: [
          {
            command,
            source: "agent-sandbox",
            evidence: ["Another command is confined."],
          },
        ],
      },
      "not-selected",
    ],
  ]) {
    const fixture = await createFixture(t, {
      trustedValidation: snapshot,
      worker: bootstrapTurns("independent", { ...base, ...fields }),
      reviewer: [base],
      onRequirementInspection: (input) => root.inspectRequirements(input),
    });
    const paused = await fixture.run({ trustedChecks: ["service-check"] });
    assert.equal(paused.pause.reason, "environment_blocked");
    assert.ok(paused.pause.evidence.some((item) => item.endsWith(reason)));
    assert.equal(writes(fixture).length, 0);
    assert.deepEqual(paused.pipelineState.trustedValidation, snapshot);
  }
});

test("unavailable root inspection remains a redacted resumable environment blocker", async (t) => {
  let unavailable = true;
  const fixture = await createFixture(t, {
    onRequirementInspection() {
      if (unavailable)
        throw Object.assign(new Error("PRIVATE_NATIVE_OUTPUT"), {
          code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
        });
      return ready;
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.doesNotMatch(JSON.stringify(paused), /PRIVATE_NATIVE_OUTPUT/u);
  assert.equal(writes(fixture).length, 0);
  unavailable = false;
  assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
});

test("legacy terminal proof survives requirement migration and rediscovery precedes new work", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  await fixture.rewrite(({ events }) => {
    for (const event of events) {
      event.state.pipelineStateVersion = 17;
      for (const role of ["worker", "reviewer"]) {
        const value = event.state.pipelineState[`${role}Validation`];
        if (value) {
          delete value.capabilityRequirements;
          delete value.environmentBlockers;
        }
      }
    }
  });
  const before = await fixture.bytes();
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  assert.deepEqual(await fixture.bytes(), before);
  const calls = fixture.calls.length;
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(run.pipelineState.workflowState, "DONE");
  const resumed = fixture.calls.slice(calls);
  assert.match(resumed[0].prompt, /versioned-state migration checkpoint/u);
  assert.equal(resumed[0].access, "read-only");
  assert.deepEqual(
    run.pipelineState.workerValidation.capabilityRequirements,
    [],
  );
});

test("unfinished legacy bootstrap discards provisional disagreement before rediscovery", async (t) => {
  const interrupted = new Error("Stop before bootstrap arbitration");
  let captured;
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
      bootstrapReady("Fresh Worker"),
      reconciliationResolved(),
    ],
    reviewer: [bootstrapReady("Reviewer"), bootstrapReady("Fresh Reviewer")],
    onTransition(run) {
      if (!captured && run.pipelineState.bootstrapDisagreement !== null) {
        captured = structuredClone(run);
        throw interrupted;
      }
    },
  });
  await assert.rejects(fixture.run(), (cause) => cause === interrupted);
  fixture.persistPipelineState(legacy(captured), { pause: null });
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.bootstrapDisagreement, null);
  assert.match(completed.pipelineState.workerSummary, /Fresh Worker/u);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("legacy requirement discovery cannot replace a safety pause", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [implementationBlocked()],
  });
  const paused = await fixture.run();
  const pause = { reason: "unsafe_git_state", code: "ERR_TEST_UNSAFE_STATE" };
  fixture.persistPipelineState(legacy(paused), { pause });
  const before = structuredClone(fixture.currentRun.pipelineState);
  const calls = Object.values(fixture.calls).flat().length;
  fixture.runtime.trustedValidation.inspectRequirements = () =>
    assert.fail("A safety pause cannot prepare new effects");
  const resumed = await fixture.run();
  assert.deepEqual(resumed.pause, pause);
  assert.deepEqual(resumed.pipelineState, before);
  assert.equal(Object.values(fixture.calls).flat().length, calls);
});

for (const mode of ["lazy", "combined"]) {
  test(`${mode} legacy discovery charges an interrupted content correction once`, async (t) => {
    const interrupted = new Error("Stopped before correction");
    let captured;
    const fixture = await createFixture(t, {
      mode,
      worker: bootstrapTurns(mode),
      workWorker: [
        implementationCompleted(),
        bootstrapReady("Migrating Worker"),
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
        checkAndFix(),
        finalizationPassed(),
      ],
      workReviewer: [bootstrapReady("Migrating Reviewer")],
      onTransition(run) {
        if (!captured && run.pipelineState.workflowState === "CHECK_AND_FIX") {
          captured = structuredClone(run);
          throw interrupted;
        }
      },
    });
    await assert.rejects(fixture.run(), (cause) => cause === interrupted);
    fixture.persistPipelineState(legacy(captured), { pause: null });
    fixture.currentRun.activeTurn = { role: "worker", phase: "check-and-fix" };
    await writeFile(
      join(fixture.projectPath, "partial-correction.txt"),
      "corrected content\n",
    );
    fixture.runtime.trustedValidation.inspectRequirements = () => {
      assert.equal(
        fixture.currentRun.counters.fixRounds,
        1,
        "Reconcile the interrupted content change before new writable work",
      );
      return blocked();
    };
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "environment_blocked");
    assert.equal(paused.counters.fixRounds, 1);
    assert.equal(paused.activeTurn, null);
    assert.equal((await fixture.run()).counters.fixRounds, 1);
  });
}
