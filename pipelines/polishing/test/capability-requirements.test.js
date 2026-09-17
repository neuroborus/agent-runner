import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { createTrustedValidationService } from "../../../src/trusted-validation/index.js";
import { migratePolishingStateV13 } from "../src/index.js";
import {
  normalizeBootstrapResult,
  normalizePipelineState,
} from "../src/workflow-contract.js";
import {
  bootstrapReady,
  candidateApproved,
  candidateClean,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createFixture,
  finalizationPassed,
  finalizationFailed,
  resolution,
  polishingCompleted,
  reconciliationDisagreement,
  reconciliationResolved,
  arbitrationResolved,
  trustedValidationSnapshot,
} from "./support/index.js";

const command = bootstrapReady("Worker").requiredChecks[0].command;
const requirement = (target = command) => ({
  command: target,
  commandIdentity: null,
  capabilities: { scratch: true, cache: false, artifacts: [] },
  unsupported: [],
});
const blocked = () => ({
  status: "BLOCKED",
  blockers: [{ command, reason: "unavailable" }],
});
const ready = { status: "READY", blockers: [] };
const bootstrap = (mode, report = bootstrapReady("Worker")) => [
  clarificationReady(),
  report,
  ...(mode === "lazy" ? [] : [reconciliationResolved()]),
];
const finish = (mode, finalization = finalizationPassed()) => [
  polishingCompleted(),
  ...(mode === "independent" ? [] : [checkAndFix(), candidateClean()]),
  finalization,
  ...(mode === "lazy" ? [cleanConfirmation()] : []),
];
const writes = (fixture) =>
  Object.values(fixture.calls)
    .flat()
    .filter(({ access }) => access !== "read-only");
function legacy(run) {
  const pipelineState = structuredClone(run.pipelineState);
  for (const role of ["worker", "reviewer"]) {
    const value = pipelineState[`${role}Validation`];
    if (value) {
      delete value.capabilityRequirements;
      delete value.environmentBlockers;
    }
  }
  return migratePolishingStateV13({ ...run, pipelineState });
}

test("polishing capability contracts reject malformed reports and preserve immutable needs", () => {
  const base = bootstrapReady("Worker");
  for (const report of [
    { ...requirement(), command: "node outside-inventory" },
    { ...requirement(), commandIdentity: "invalid" },
    {
      ...requirement(),
      capabilities: { scratch: "/tmp", cache: false, artifacts: [] },
    },
    { ...requirement(), unsupported: ["network", "network"] },
  ])
    assert.throws(
      () =>
        normalizeBootstrapResult(
          { ...base, capabilityRequirements: [report] },
          "worker",
        ),
      { code: "ERR_INVALID_POLISHING_OUTPUT" },
    );
  assert.throws(() =>
    normalizeBootstrapResult(
      {
        ...base,
        environmentBlockers: [
          { command, source: "host", evidence: ["Unavailable"] },
        ],
      },
      "worker",
    ),
  );
  assert.throws(() =>
    normalizeBootstrapResult(
      { ...base, capabilityRequirements: Array(257).fill(requirement()) },
      "worker",
    ),
  );
  assert.ok(
    Object.isFrozen(
      normalizeBootstrapResult(
        { ...base, capabilityRequirements: [requirement()] },
        "worker",
      ).capabilityRequirements[0].capabilities,
    ),
  );
});

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} persists corrected reports and blocks unselected needs without content or index mutation`, async (t) => {
    const root = createTrustedValidationService();
    const report = {
      ...bootstrapReady("Worker"),
      capabilityRequirements: [requirement()],
    };
    const fixture = await createFixture(t, {
      mode,
      worker: [
        clarificationReady(),
        { ...report, capabilityRequirements: [requirement("unknown")] },
        report,
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
      ],
      onRequirementInspection(input) {
        assert.deepEqual(
          fixture.currentRun.pipelineState.workerValidation
            .capabilityRequirements,
          report.capabilityRequirements,
        );
        return root.inspectRequirements(input);
      },
    });
    const before = await fixture.runtime.git.snapshot({
      projectPath: fixture.projectPath,
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "environment_blocked");
    assert.match(paused.pause.evidence[0], /not-selected/u);
    assert.equal(paused.pipelineState.bootstrapCorrections.length, 1);
    assert.equal(writes(fixture).length, 0);
    await fixture.run();
    assert.equal(writes(fixture).length, 0);
    const after = await fixture.runtime.git.snapshot({
      projectPath: fixture.projectPath,
    });
    assert.equal(after.contentFingerprint, before.contentFingerprint);
    assert.equal(after.indexFingerprint, before.indexFingerprint);
  });

  test(`${mode} delegated sandbox limitations retry frozen requirements and execute checks only in FINALIZE`, async (t) => {
    const snapshot = trustedValidationSnapshot();
    const target = snapshot.commands[0].command;
    const requiredChecks = [
      ...finalizationPassed().requiredChecks,
      { id: "C2", command: target },
    ];
    const finalization = {
      ...finalizationPassed(),
      requiredChecks,
      checks: [
        ...finalizationPassed().checks,
        {
          checkId: "C2",
          command: target,
          status: "NOT_RUN",
          evidence: ["Reserved for runner"],
        },
      ],
    };
    const report = {
      ...bootstrapReady("Worker"),
      requiredChecks,
      environmentBlockers: [
        {
          command: target,
          source: "agent-sandbox",
          evidence: ["Agent isolation is unavailable"],
        },
      ],
    };
    let available = false,
      executed = 0;
    const requests = [];
    const fixture = await createFixture(t, {
      mode,
      trustedValidation: snapshot,
      modeSettings: { trustedChecks: ["service-check"] },
      worker: [...bootstrap(mode, report), ...finish(mode, finalization)],
      reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
      onRequirementInspection(input) {
        requests.push(structuredClone(input));
        return available ? ready : blocked();
      },
      onTrustedValidation(input) {
        assert.equal(
          fixture.currentRun.pipelineState.workflowState,
          "FINALIZE",
        );
        executed++;
        return {
          ...input.bindings,
          commandIdentity: input.commandIdentity,
          status: "PASS",
          exitCode: 0,
          signal: null,
          timedOut: false,
          evidence: ["Passed"],
        };
      },
    });
    assert.equal((await fixture.run()).pause.reason, "environment_blocked");
    assert.equal(executed, 0);
    assert.equal(writes(fixture).length, 0);
    available = true;
    const done = await fixture.run();
    assert.equal(done.pipelineState.workflowState, "DONE");
    assert.equal(executed, 1);
    assert.deepEqual(done.pipelineState.trustedValidation, snapshot);
    assert.ok(requests.length >= 4);
    assert.ok(
      requests.every(
        (value) => JSON.stringify(value) === JSON.stringify(requests[0]),
      ),
    );
    if (mode === "lazy") assert.equal(fixture.calls.reviewer.length, 0);
  });

  test(`${mode} legacy discovery is read-only and saved availability is rechecked on resume`, async (t) => {
    let available = false;
    const fixture = await createFixture(t, {
      mode,
      worker: [
        ...bootstrap(mode),
        bootstrapReady("Migrating Worker"),
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
        ...finish(mode),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        bootstrapReady("Migrating Reviewer"),
      ],
      onRequirementInspection: () => (available ? ready : blocked()),
    });
    const paused = await fixture.run();
    await fixture.persistPipelineState(legacy(paused));
    const migrated = await fixture.run();
    assert.equal(migrated.pause.reason, "environment_blocked");
    assert.equal(migrated.pipelineState.validationMigrationPending, false);
    assert.equal(writes(fixture).length, 0);
    const discovery = Object.values(fixture.calls)
      .flat()
      .filter(({ prompt }) =>
        prompt.includes("versioned-state migration checkpoint"),
      );
    assert.equal(discovery.length, mode === "lazy" ? 1 : 2);
    assert.ok(discovery.every(({ access }) => access === "read-only"));
    available = true;
    assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  });

  test(`${mode} capability loss after bootstrap blocks the next writable checkpoint`, async (t) => {
    const checkpoint = mode === "independent" ? "FINALIZE" : "CHECK_AND_FIX";
    let unavailable = true;
    const fixture = await createFixture(t, {
      mode,
      worker: [...bootstrap(mode), ...finish(mode)],
      onRequirementInspection: () =>
        unavailable &&
        fixture.currentRun.pipelineState.workflowState === checkpoint
          ? blocked()
          : ready,
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.resumeState, checkpoint);
    const before = await fixture.runtime.git.snapshot({
      projectPath: fixture.projectPath,
    });
    const calls = writes(fixture).length;
    await fixture.run();
    assert.equal(writes(fixture).length, calls);
    const after = await fixture.runtime.git.snapshot({
      projectPath: fixture.projectPath,
    });
    assert.equal(after.contentFingerprint, before.contentFingerprint);
    assert.equal(after.indexFingerprint, before.indexFingerprint);
    unavailable = false;
    assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  });
}

test("arbitration cannot drop Reviewer-only requirements or grant frozen authority", async (t) => {
  const root = createTrustedValidationService();
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
    reviewer: [
      {
        ...bootstrapReady("Reviewer"),
        environmentBlockers: [
          { command, source: "agent-sandbox", evidence: ["Not delegated"] },
        ],
      },
    ],
    arbiter: [arbitrationResolved()],
    onRequirementInspection: (input) => root.inspectRequirements(input),
  });
  assert.equal((await fixture.run()).pause.reason, "environment_blocked");
  assert.equal(writes(fixture).length, 0);
  assert.equal(
    fixture.currentRun.pipelineState.reviewerValidation.environmentBlockers
      .length,
    1,
  );
});

test("legacy requirement discovery preserves a safety pause", async (t) => {
  const fixture = await createFixture(t, { onRequirementInspection: blocked });
  const paused = await fixture.run();
  const pause = { reason: "unsafe_git_state", code: "ERR_TEST_UNSAFE" };
  await fixture.persistPipelineState(legacy(paused), paused.counters, pause);
  const before = structuredClone(fixture.currentRun.pipelineState);
  const calls = Object.values(fixture.calls).flat().length;
  assert.deepEqual((await fixture.run()).pause, pause);
  assert.deepEqual(fixture.currentRun.pipelineState, before);
  assert.equal(Object.values(fixture.calls).flat().length, calls);
});

for (const reason of [
  "unsafe_git_state",
  "bootstrap_inventory_capacity_exhausted",
]) {
  test(`pending legacy discovery preserves ${reason} on resume`, async (t) => {
    const fixture = await createFixture(t, {
      onRequirementInspection: blocked,
    });
    const paused = await fixture.run();
    const pause = { reason, code: "ERR_TEST_PAUSE" };
    await fixture.persistPipelineState(
      { ...legacy(paused), validationMigrationPending: true },
      paused.counters,
      pause,
    );
    const before = structuredClone(fixture.currentRun.pipelineState);
    const calls = Object.values(fixture.calls).flat().length;
    fixture.runtime.trustedValidation.preflight = () =>
      assert.fail("No preparation while paused");
    fixture.runtime.trustedValidation.inspectRequirements = () =>
      assert.fail("No inspection while paused");
    assert.deepEqual((await fixture.run()).pause, pause);
    assert.deepEqual(fixture.currentRun.pipelineState, before);
    assert.equal(Object.values(fixture.calls).flat().length, calls);
  });
}

test("interrupted legacy bootstrap settles the old role before rediscovering both inventories", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Old Worker"),
      bootstrapReady("New Worker"),
      reconciliationResolved(),
    ],
    onRequirementInspection: blocked,
  });
  const transition = fixture.runtime.transition;
  const interruption = new Error("Before Reviewer bootstrap");
  let captured;
  fixture.runtime.transition = async (patch, options) => {
    const run = await transition(patch, options);
    if (
      patch.pipelineState.workerValidation !== null &&
      patch.pipelineState.reviewerValidation === null
    ) {
      captured = structuredClone(run);
      throw interruption;
    }
    return run;
  };
  await assert.rejects(fixture.run(), (cause) => cause === interruption);
  fixture.runtime.transition = transition;
  await fixture.persistPipelineState(legacy(captured), captured.counters, null);
  fixture.currentRun.activeTurn = { role: "reviewer", phase: "bootstrap" };
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.activeTurn, null);
  assert.match(paused.pipelineState.workerSummary, /New Worker/u);
  assert.equal(writes(fixture).length, 0);
});

for (const applied of [true, false]) {
  test(`${applied ? "completed" : "untouched"} legacy handoff is inspected before discovery or preparation`, async (t) => {
    const fixture = await createFixture(t);
    const git = fixture.runtime.git;
    if (!applied)
      fixture.runtime.git = {
        ...git,
        stagePolishingHandoff: async ({ expectedSnapshot }) => expectedSnapshot,
      };
    const transition = fixture.runtime.transition;
    const interruption = new Error("Interrupted handoff");
    fixture.runtime.transition = async (patch, options) => {
      if (["DONE", "FAILED"].includes(patch.pipelineState.workflowState))
        throw interruption;
      return transition(patch, options);
    };
    await assert.rejects(fixture.run(), (cause) => cause === interruption);
    fixture.runtime.transition = transition;
    fixture.runtime.git = git;
    await fixture.persistPipelineState(legacy(fixture.currentRun));
    fixture.runtime.trustedValidation.inspectRequirements = () =>
      assert.fail("No new preparation before handoff reconciliation");
    const calls = Object.values(fixture.calls).flat().length;
    if (applied) {
      assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
      assert.equal(Object.values(fixture.calls).flat().length, calls);
    } else {
      fixture.runtime.adapters.worker.run = async (request) => {
        assert.match(request.prompt, /versioned-state migration checkpoint/u);
        assert.equal(request.access, "read-only");
        throw interruption;
      };
      await assert.rejects(fixture.run(), (cause) => cause === interruption);
    }
  });
}

for (const mode of ["lazy", "combined"]) {
  test(`${mode} interrupted legacy correction is charged once before migrated writable entry`, async (t) => {
    const fixture = await createFixture(t, {
      mode,
      worker: [
        ...bootstrap(mode),
        polishingCompleted(),
        bootstrapReady("Migrating Worker"),
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        bootstrapReady("Migrating Reviewer"),
      ],
    });
    const transition = fixture.runtime.transition;
    const interruption = new Error("Before correction");
    let captured;
    fixture.runtime.transition = async (patch, options) => {
      const run = await transition(patch, options);
      if (patch.pipelineState.workflowState === "CHECK_AND_FIX") {
        captured = structuredClone(run);
        throw interruption;
      }
      return run;
    };
    await assert.rejects(fixture.run(), (cause) => cause === interruption);
    fixture.runtime.transition = transition;
    await fixture.persistPipelineState(
      legacy(captured),
      captured.counters,
      null,
    );
    fixture.currentRun.activeTurn = { role: "worker", phase: "check-and-fix" };
    await writeFile(join(fixture.projectPath, "partial.txt"), "correction\n");
    fixture.runtime.trustedValidation.inspectRequirements = () => {
      assert.equal(fixture.currentRun.counters.fixRounds, 1);
      return blocked();
    };
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "environment_blocked");
    assert.equal(paused.activeTurn, null);
    assert.equal((await fixture.run()).counters.fixRounds, 1);
    assert.doesNotThrow(() =>
      normalizePipelineState(fixture.currentRun.pipelineState),
    );
  });
}

for (const checkpoint of ["RESOLVE_FINDINGS", "HANDOFF"]) {
  test(`availability loss blocks ${checkpoint} without new writes or staging`, async (t) => {
    let unavailable = true;
    const fixture = await createFixture(t, {
      worker: [
        ...bootstrap("independent"),
        polishingCompleted(),
        ...(checkpoint === "RESOLVE_FINDINGS"
          ? [finalizationFailed(), resolution("FIX")]
          : []),
        finalizationPassed(),
      ],
      onRequirementInspection: () =>
        unavailable &&
        fixture.currentRun.pipelineState.workflowState === checkpoint
          ? blocked()
          : ready,
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.resumeState, checkpoint);
    const before = await fixture.runtime.git.snapshot({
      projectPath: fixture.projectPath,
    });
    const count = writes(fixture).length;
    await fixture.run();
    assert.equal(writes(fixture).length, count);
    const after = await fixture.runtime.git.snapshot({
      projectPath: fixture.projectPath,
    });
    assert.equal(after.contentFingerprint, before.contentFingerprint);
    assert.equal(after.indexFingerprint, before.indexFingerprint);
    unavailable = false;
    assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  });
}

for (const changed of [false, true]) {
  test(`legacy interrupted read-only finalization correction ${changed ? "rejects mutation" : "rediscovers requirements"}`, async (t) => {
    const fixture = await createFixture(t, {
      worker: [
        ...bootstrap("independent"),
        polishingCompleted(),
        { ...finalizationPassed(), checks: [] },
        bootstrapReady("Migrating Worker"),
        reconciliationResolved(),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        bootstrapReady("Migrating Reviewer"),
        candidateApproved(),
      ],
    });
    const transition = fixture.runtime.transition;
    const interruption = new Error("Before read-only correction");
    let captured;
    fixture.runtime.transition = async (patch, options) => {
      const run = await transition(patch, options);
      if (patch.pipelineState.pendingFinalizationCorrection !== null) {
        captured = structuredClone(run);
        throw interruption;
      }
      return run;
    };
    await assert.rejects(fixture.run(), (cause) => cause === interruption);
    fixture.runtime.transition = transition;
    await fixture.persistPipelineState(
      legacy(captured),
      captured.counters,
      null,
    );
    fixture.currentRun.activeTurn = { role: "worker", phase: "finalize" };
    if (changed) {
      const finishTurn = fixture.runtime.finishAgentTurn;
      let stopped = false;
      fixture.runtime.finishAgentTurn = async () => {
        stopped = true;
        throw interruption;
      };
      fixture.runtime.transition = (patch, options) => {
        if (stopped) throw interruption;
        return transition(patch, options);
      };
      await assert.rejects(fixture.run(), (cause) => cause === interruption);
      fixture.runtime.transition = transition;
      fixture.runtime.finishAgentTurn = finishTurn;
      assert.notEqual(
        fixture.currentRun.pipelineState.pendingFinalizationCorrection,
        null,
      );
      await writeFile(join(fixture.projectPath, "unauthorized.txt"), "edit\n");
    }
    const calls = Object.values(fixture.calls).flat().length;
    const writableCalls = writes(fixture).length;
    fixture.runtime.trustedValidation.inspectRequirements = () => {
      assert.equal(
        changed,
        false,
        "Reconcile read-only permissions before acquisition",
      );
      return blocked();
    };
    const paused = await fixture.run();
    assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(writes(fixture).length, writableCalls);
    if (changed) {
      assert.notEqual(paused.pause.reason, "environment_blocked");
      assert.equal(Object.values(fixture.calls).flat().length, calls);
    } else {
      assert.equal(paused.pause.reason, "environment_blocked");
      assert.equal(paused.activeTurn, null);
      assert.equal(paused.pipelineState.pendingFinalizationCorrection, null);
      assert.doesNotThrow(() => normalizePipelineState(paused.pipelineState));
    }
  });
}

test("saved needs cannot expand selected frozen authority and diagnostics stay bounded", async (t) => {
  const snapshot = trustedValidationSnapshot();
  const target = snapshot.commands[0].command;
  const requiredChecks = [
    ...bootstrapReady("Worker").requiredChecks,
    { id: "C2", command: target },
  ];
  const root = createTrustedValidationService();
  const fixture = await createFixture(t, {
    trustedValidation: snapshot,
    modeSettings: { trustedChecks: ["service-check"] },
    worker: bootstrap("independent", {
      ...bootstrapReady("Worker"),
      requiredChecks,
      capabilityRequirements: [requirement(target)],
    }),
    reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
    onRequirementInspection: (input) => root.inspectRequirements(input),
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.match(paused.pause.evidence[0], /insufficient-authority/u);
  assert.deepEqual(paused.pipelineState.trustedValidation, snapshot);
  assert.equal(writes(fixture).length, 0);
  fixture.runtime.trustedValidation.inspectRequirements = () => {
    throw Object.assign(new Error("PRIVATE_DIAGNOSTIC"), {
      code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE",
    });
  };
  assert.doesNotMatch(
    JSON.stringify(await fixture.run()),
    /PRIVATE_DIAGNOSTIC/u,
  );
});
