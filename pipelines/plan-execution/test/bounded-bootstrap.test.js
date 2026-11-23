import assert from "node:assert/strict";
import test from "node:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { migratePlanExecutionStateV27 } from "../src/index.js";
import {
  APPLICABILITY_BATCH_SCHEMA,
  REPOSITORY_DISCOVERY_SCHEMA,
} from "../src/bootstrap-unit-schemas.js";
import {
  assertExecutionRun,
  normalizeExecutionState,
} from "../src/bootstrap-progress.js";
import {
  canRecoverLegacyConfirmation,
  prepareLegacyConfirmationRecovery,
} from "../src/legacy-confirmation-recovery.js";
import { REVIEW_SCHEMA } from "../src/schemas.js";
import {
  createFixture,
  bootstrapReady,
  checkAndFix,
  clarificationReady,
  finalizationPassed,
  implementationCompleted,
  reconciliationResolved,
  trustedValidationSnapshot,
} from "./support/index.js";
import {
  attachOutputExhaustion,
  outputExhaustion,
} from "../../../test/support/output-exhaustion.js";
import {
  attachAvailability,
  availabilityFailure,
} from "../../../test/support/availability.js";
import { attachInactivity } from "../../../test/support/inactivity.js";

const plan = Array.from(
  { length: 6 },
  (_, index) =>
    `## Commit ${index + 1}: feat(test): add part ${index + 1}\n\nImplement part ${index + 1}.`,
).join("\n\n");
const stop = Object.assign(new Error("Interrupted durable checkpoint."), {
  code: "ERR_RUN_REVISION_CHANGED",
});
const supplied = (request) =>
  JSON.parse(
    /Applicability request \(data\):\n([^\n]+)/u.exec(request.prompt)[1],
  );
const ready = (unit) => ({
  result: {
    status: "READY",
    unitId: unit.unitId,
    assignments: unit.discovery.requiredChecks.map(({ id }) => ({
      checkId: id,
      steps: unit.steps.map(({ number }) => number),
    })),
    missingCommands: [],
    missingInfrastructure: [],
    capabilityRequirements: [],
    environmentBlockers: [],
  },
});
const pauseBeforeWrites = (run) => {
  if (run.pipelineState.resolvedSummary !== null) throw stop;
};

test("discovery batches omitted trusted commands with staging and path diagnostics", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const corrected = {
    ...bootstrapReady("Corrected Worker"),
    requiredChecks: [
      { id: "C1", command: trustedValidation.commands[0].command },
    ],
  };
  const fixture = await createFixture(t, {
    trustedValidation,
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks: [{ id: "C1", command: "git diff --cached --check" }],
        validationInfrastructure: ["missing-validation.js"],
      },
      corrected,
      reconciliationResolved(),
    ],
    reviewer: [corrected],
    onTransition: pauseBeforeWrites,
  });
  await assert.rejects(
    fixture.run({ trustedChecks: ["service-check"] }),
    (error) => error === stop,
  );
  assert.deepEqual(
    fixture.currentRun.pipelineState.bootstrapCorrections[0].diagnostics.map(
      ({ field, constraint }) => ({ field, constraint }),
    ),
    [
      {
        field: "requiredChecks[0].command",
        constraint: "staging-independent-validation-command",
      },
      {
        field: "validationInfrastructure[0]",
        constraint: "existing-canonical-repository-file",
      },
      {
        field: "requiredChecks",
        constraint: "includes-runner-trusted-commands",
      },
    ],
  );
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
  assert.equal(
    fixture.currentRun.pipelineState.pendingBootstrapCorrection,
    null,
  );
});

for (const mode of ["independent", "combined", "lazy"]) {
  test(`${mode} reload reuses accepted units and preserves independent discovery before any effect`, async (t) => {
    let interrupted = false;
    const fixture = await createFixture(t, {
      plan,
      mode,
      onTransition(run) {
        if (
          !interrupted &&
          run.pipelineState.bootstrapProgress.worker.work?.accepted.length === 1
        ) {
          interrupted = true;
          throw stop;
        }
        pauseBeforeWrites(run);
      },
    });
    await assert.rejects(fixture.run(), (error) => error === stop);
    const saved = JSON.parse(JSON.stringify(fixture.currentRun.pipelineState));
    const first = saved.bootstrapProgress.worker.work.accepted[0].unitId;
    assert.equal(saved.workerValidation, null);
    assert.equal(saved.validationSchedule, null);
    for (const change of [
      (state) => {
        state.bootstrapProgress.worker.work.accepted[0].unitId = "0".repeat(64);
      },
      (state) => {
        state.bootstrapProgress.worker.work.binding.role = "reviewer";
      },
      (state) => {
        state.bootstrapProgress.worker.subdivisions = 17;
      },
    ]) {
      const invalid = structuredClone(saved);
      change(invalid);
      assert.throws(() => normalizeExecutionState(invalid), {
        code: "ERR_INVALID_PLAN_EXECUTION_STATE",
      });
    }
    fixture.persistPipelineState(saved);
    await assert.rejects(fixture.run(), (error) => error === stop);
    assert.equal(
      fixture.applicabilityCalls.filter(
        (request) => supplied(request).unitId === first,
      ).length,
      1,
    );
    assert.equal(
      fixture.calls.worker.filter(
        ({ schema }) => schema === REPOSITORY_DISCOVERY_SCHEMA,
      ).length,
      1,
    );
    assert.equal(
      fixture.calls.reviewer.filter(
        ({ schema }) => schema === REPOSITORY_DISCOVERY_SCHEMA,
      ).length,
      mode === "lazy" ? 0 : 1,
    );
    assert.ok(
      fixture.applicabilityCalls.every(({ access }) => access === "read-only"),
    );
    assert.deepEqual(
      fixture.currentRun.pipelineState.validationSchedule.steps.map(
        ({ step }) => step,
      ),
      [1, 2, 3, 4, 5, 6],
    );
    const focused = fixture.applicabilityCalls.at(-1);
    assert.doesNotMatch(focused.prompt, /Validated plan \(/u);
    assert.match(focused.recoveryPrompt, /Frozen input hashes/u);
  });
}

test("output exhaustion subdivides only unfinished coverage and survives restart without correction charges", async (t) => {
  let interrupted = false;
  let exhausted = false;
  const fixture = await createFixture(t, {
    plan,
    onRoleRun(role, request) {
      if (role === "worker" && request.schema === APPLICABILITY_BATCH_SCHEMA) {
        const unit = supplied(request);
        if (!exhausted && unit.steps[0].number === 5) {
          exhausted = true;
          throw outputExhaustion();
        }
      }
    },
    onTransition(run) {
      if (
        !interrupted &&
        run.pipelineState.bootstrapProgress.worker.subdivisions === 1
      ) {
        interrupted = true;
        throw stop;
      }
      pauseBeforeWrites(run);
    },
  });
  attachOutputExhaustion(fixture);
  await assert.rejects(fixture.run(), (error) => error === stop);
  fixture.persistPipelineState(
    JSON.parse(JSON.stringify(fixture.currentRun.pipelineState)),
  );
  await assert.rejects(fixture.run(), (error) => error === stop);
  const ranges = fixture.applicabilityCalls
    .filter(({ role }) => role === "worker")
    .map((request) => supplied(request).steps.map(({ number }) => number));
  assert.deepEqual(ranges, [[1, 2, 3, 4], [5, 6], [5], [6]]);
  assert.equal(
    fixture.currentRun.pipelineState.bootstrapProgress.worker.subdivisions,
    1,
  );
  assert.deepEqual(fixture.currentRun.pipelineState.bootstrapCorrections, []);
  assert.equal(fixture.currentRun.counters.fixRounds, 0);
});

test("catalog correction invalidates coverage and preserves consumed output and semantic allowances", async (t) => {
  const original = bootstrapReady("Worker", [1, 2, 3, 4, 5, 6]);
  const corrected = {
    ...original,
    requiredChecks: [
      ...original.requiredChecks,
      { id: "C2", command: "node validation.js", steps: [1, 2, 3, 4, 5, 6] },
    ],
  };
  let exhausted = false;
  let reported = false;
  const fixture = await createFixture(t, {
    plan,
    worker: [
      clarificationReady(),
      original,
      corrected,
      reconciliationResolved(),
    ],
    onRoleRun(role, request) {
      if (role !== "worker" || request.schema !== APPLICABILITY_BATCH_SCHEMA)
        return;
      const unit = supplied(request);
      if (!exhausted) {
        exhausted = true;
        throw outputExhaustion();
      }
      if (!reported && unit.steps[0].number === 3) {
        reported = true;
        return {
          result: {
            ...ready(unit).result,
            status: "CATALOG_CORRECTION_REQUIRED",
            assignments: [],
            missingCommands: ["node validation.js"],
          },
        };
      }
    },
    onTransition: pauseBeforeWrites,
  });
  attachOutputExhaustion(fixture);
  await assert.rejects(fixture.run(), (error) => error === stop);
  const state = fixture.currentRun.pipelineState;
  assert.equal(state.bootstrapProgress.worker.subdivisions, 1);
  assert.equal(state.bootstrapCorrections.length, 1);
  assert.equal(state.pendingBootstrapCorrection, null);
  assert.equal(state.workerValidation.requiredChecks.length, 2);
  const requests = fixture.applicabilityCalls
    .filter(({ role }) => role === "worker")
    .map(supplied);
  assert.equal(requests.filter(({ steps }) => steps[0].number === 1).length, 3);
  assert.notEqual(
    requests[1].catalogFingerprint,
    requests.at(-1).catalogFingerprint,
  );
});

test("discovery, applicability and validation migration deliver check ownership to both roles", async (t) => {
  const prompts = [];
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      bootstrapReady("Migrating Reviewer"),
    ],
    onRoleRun(role, { schema, prompt }) {
      if (
        schema === REPOSITORY_DISCOVERY_SCHEMA ||
        schema === APPLICABILITY_BATCH_SCHEMA
      )
        prompts.push({
          key: `${role}:${fixture.currentRun.activeTurn.phase}:${schema === REPOSITORY_DISCOVERY_SCHEMA ? "discovery" : "applicability"}`,
          prompt,
        });
    },
    onTransition(run) {
      if (
        run.pipelineState.workflowState === "IMPLEMENT" &&
        !run.pipelineState.validationMigrationPending
      )
        throw stop;
    },
  });
  await assert.rejects(fixture.run(), (error) => error === stop);
  fixture.persistPipelineState({
    ...fixture.currentRun.pipelineState,
    validationMigrationPending: true,
    validationScopeLegacy: true,
    validationSchedule: null,
    workerValidation: null,
    reviewerValidation: null,
  });
  await assert.rejects(fixture.run(), (error) => error === stop);

  assert.deepEqual(
    [...new Set(prompts.map(({ key }) => key))].sort(),
    ["reviewer", "worker"]
      .flatMap((role) =>
        ["bootstrap", "validation-migration"].flatMap((phase) => [
          `${role}:${phase}:applicability`,
          `${role}:${phase}:discovery`,
        ]),
      )
      .sort(),
  );
  for (const { key, prompt } of prompts) {
    if (key.endsWith(":applicability")) {
      assert.match(prompt, /Catalog correction never adds post-completion/u);
      continue;
    }
    assert.match(prompt, /determine the owner and checkpoint/u);
    assert.match(prompt, /selected Runner-trusted commands, which remain/u);
    assert.match(prompt, /mandatory external acceptance, not a pipeline/u);
    assert.match(prompt, /expected to fail never becomes a PASS-required/u);
    assert.match(prompt, /never drops other genuine in-scope requirements/u);
  }
});

for (const target of ["discovery", "indivisible", "mutation", "input-drift"]) {
  test(`${target} cannot accept partial bootstrap or acquire writable authority`, async (t) => {
    let affected = false;
    const fixture = await createFixture(t, {
      onRoleRun(role, request) {
        if (role !== "worker" || affected) return;
        if (
          target === "discovery" &&
          request.schema === REPOSITORY_DISCOVERY_SCHEMA
        ) {
          affected = true;
          throw outputExhaustion();
        }
        if (
          target !== "discovery" &&
          request.schema === APPLICABILITY_BATCH_SCHEMA
        ) {
          affected = true;
          if (target === "indivisible") throw outputExhaustion();
          return writeFile(
            target === "mutation"
              ? join(fixture.projectPath, "source.js")
              : fixture.clarificationPath,
            "Unexpected drift.\n",
          );
        }
      },
    });
    attachOutputExhaustion(fixture);
    const result = await fixture.run();
    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(
      result.pause.reason,
      target === "mutation"
        ? "read_only_agent_mutated_repository"
        : target === "input-drift"
          ? "clarifications_changed"
          : "output_exhausted",
    );
    assert.equal(result.pipelineState.workerValidation, null);
    assert.equal(result.pipelineState.requiredChecks, null);
    assert.equal(result.pipelineState.bootstrapProgress.worker.subdivisions, 0);
    assert.ok(
      Object.values(fixture.calls)
        .flat()
        .every(({ access }) => access === "read-only"),
    );
  });
}

test("version-27 migration retains complete evidence, amendments, counters and consumed effects without batch proof", async (t) => {
  let legacy;
  const fixture = await createFixture(t, {
    onCommitVerify() {
      if (!legacy) {
        legacy = structuredClone(fixture.currentRun.pipelineState);
        delete legacy.bootstrapProgress;
        throw stop;
      }
    },
  });
  await assert.rejects(fixture.run(), (error) => error === stop);
  const migrated = migratePlanExecutionStateV27({ pipelineState: legacy });
  const { bootstrapProgress, ...retained } = migrated;
  assert.deepEqual(retained, legacy);
  assert.deepEqual(bootstrapProgress, {
    worker: { work: null, subdivisions: 0 },
    reviewer: { work: null, subdivisions: 0 },
  });
  fixture.persistPipelineState(migrated);
  const before = fixture.calls.worker.length;
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(fixture.calls.worker.length, before);
  assert.equal(completed.pipelineState.completedCommits.length, 1);
});

for (const kind of ["availability", "inactivity"]) {
  test(`version-27 migration resumes saved ${kind} retries without renewing allowances`, async (t) => {
    let migrating = false;
    let attempts = 0;
    let inactivity;
    const fixture = await createFixture(t, {
      mode: "combined",
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        bootstrapReady("Migrating Worker"),
        reconciliationResolved(),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        bootstrapReady("Migrating Reviewer"),
      ],
      onTransition(run) {
        if (
          run.pipelineState.workflowState === "IMPLEMENT" &&
          (!migrating || !run.pipelineState.validationMigrationPending)
        )
          throw stop;
      },
      onRoleRun(role, request) {
        if (!migrating) return;
        assert.equal(request.access, "read-only");
        assert.deepEqual(fixture.currentRun.activeTurn, {
          role,
          phase: "validation-migration",
        });
        if (role !== "worker" || request.schema !== REPOSITORY_DISCOVERY_SCHEMA)
          return;
        if (++attempts !== 1) return;
        if (kind === "availability") throw availabilityFailure();
        return inactivity.expire(request);
      },
    });
    await assert.rejects(fixture.run(), (error) => error === stop);
    migrating = true;
    const legacy = structuredClone(fixture.currentRun.pipelineState);
    delete legacy.bootstrapProgress;
    Object.assign(legacy, {
      validationMigrationPending: true,
      validationScopeLegacy: true,
      validationSchedule: null,
      workerValidation: null,
      reviewerValidation: null,
    });
    fixture.persistPipelineState(
      migratePlanExecutionStateV27({ pipelineState: legacy }),
    );
    const checkpoint = "implement:read-only:validation-migration";
    const field =
      kind === "availability" ? "availabilityRetry" : "inactivityRecovery";
    const counters = structuredClone(fixture.currentRun.counters);
    if (kind === "availability") {
      attachAvailability(fixture, {
        onSchedule(run) {
          if (run.availabilityRetry.attempt === 2) throw stop;
        },
      });
      await fixture.runtime.availability.schedule({
        cause: availabilityFailure(),
        role: "worker",
        checkpoint,
        repository: legacy.repositoryBaseline,
      });
    } else {
      inactivity = await attachInactivity(fixture);
      await fixture.runtime.transition({
        inactivityRecovery: {
          role: "worker",
          checkpoint,
          attempt: 1,
          status: "expired",
          expiryRevision: fixture.currentRun.revision + 1,
          reconstructionRevision: null,
          configurationFingerprint:
            fixture.currentRun.providerInactivityFingerprint,
          contentFingerprint: legacy.repositoryBaseline.contentFingerprint,
        },
      });
      inactivity.restart();
    }
    const saved = structuredClone(fixture.currentRun[field]);
    fixture.persistPipelineState(
      migratePlanExecutionStateV27({
        ...fixture.currentRun,
        pipelineStateVersion: 27,
        pipelineState: JSON.parse(JSON.stringify(legacy)),
      }),
    );
    assert.deepEqual(fixture.currentRun[field], saved);
    for (const invalid of [
      "implement:workspace-write:validation-migration",
      "finalize:read-only:validation-migration",
    ]) {
      await fixture.runtime.transition({
        [field]: { ...saved, checkpoint: invalid },
      });
      await assert.rejects(fixture.run(), {
        code:
          kind === "availability"
            ? "ERR_AVAILABILITY_RECOVERY"
            : "ERR_INACTIVITY_RECOVERY",
      });
      assert.equal(attempts, 0);
    }
    await fixture.runtime.transition({ [field]: saved });
    if (kind === "availability") {
      await assert.rejects(fixture.run(), {
        code: "ERR_AVAILABILITY_RECOVERY",
      });
      assert.equal(fixture.currentRun.availabilityRetry.id, saved.id);
    } else {
      const paused = await fixture.run();
      assert.equal(paused.pause.reason, "backend_unavailable");
      assert.equal(paused.pause.code, "ERR_PROVIDER_INACTIVE");
      assert.ok(
        paused.inactivityRecovery.reconstructionRevision > saved.expiryRevision,
      );
    }
    assert.equal(attempts, 1);
    assert.equal(fixture.currentRun[field].checkpoint, checkpoint);
    assert.equal(fixture.currentRun[field].attempt, 2);
    assert.deepEqual(fixture.currentRun.counters, counters);
    fixture.persistPipelineState(
      JSON.parse(JSON.stringify(fixture.currentRun.pipelineState)),
    );
    inactivity?.restart();
    await assert.rejects(fixture.run(), (error) => error === stop);
    assert.equal(attempts, 2);
    assert.equal(fixture.currentRun[field], null);
    assert.equal(
      fixture.currentRun.pipelineState.validationMigrationPending,
      false,
    );
    assert.deepEqual(fixture.currentRun.counters, counters);
    assert.deepEqual(fixture.currentRun.pipelineState.bootstrapCorrections, []);
  });
}

for (const target of ["discovery", "indivisible"]) {
  test(`${target} validation-migration exhaustion pauses and resumes at its read-only checkpoint`, async (t) => {
    let migrating = false;
    let exhausted = false;
    const fixture = await createFixture(t, {
      mode: "combined",
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        bootstrapReady("Migrating Worker"),
        reconciliationResolved(),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        bootstrapReady("Migrating Reviewer"),
      ],
      workWorker: [
        implementationCompleted(),
        checkAndFix(),
        finalizationPassed(),
      ],
      onTransition(run) {
        if (!migrating && run.pipelineState.workflowState === "IMPLEMENT")
          throw stop;
      },
      onRoleRun(role, request) {
        if (
          migrating &&
          !exhausted &&
          role === "worker" &&
          request.schema ===
            (target === "discovery"
              ? REPOSITORY_DISCOVERY_SCHEMA
              : APPLICABILITY_BATCH_SCHEMA)
        ) {
          exhausted = true;
          throw outputExhaustion();
        }
      },
    });
    attachOutputExhaustion(fixture);
    await assert.rejects(fixture.run(), (error) => error === stop);
    const initial = structuredClone(fixture.currentRun.pipelineState);
    const initialCounters = structuredClone(fixture.currentRun.counters);
    fixture.persistPipelineState({
      ...initial,
      validationMigrationPending: true,
      validationScopeLegacy: true,
      validationSchedule: null,
      workerValidation: null,
      reviewerValidation: null,
    });
    migrating = true;
    const paused = await fixture.run();
    assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.deepEqual(paused.pause, {
      reason: "output_exhausted",
      code: "ERR_OUTPUT_EXHAUSTED",
      resumeState: "IMPLEMENT",
      role: "worker",
      checkpoint: "validation-migration:read-only:validation-migration",
    });
    assert.equal(paused.activeTurn, null);
    assert.equal(paused.pipelineState.workerValidation, null);
    assert.equal(paused.pipelineState.bootstrapProgress.worker.subdivisions, 0);
    assert.deepEqual(paused.pipelineState.bootstrapCorrections, []);
    assert.deepEqual(paused.counters, initialCounters);
    assert.throws(
      () =>
        assertExecutionRun({
          ...paused,
          pipelineState: { ...initial, workflowState: "WAITING_FOR_USER" },
        }),
      { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
    );
    fixture.persistPipelineState(
      JSON.parse(JSON.stringify(paused.pipelineState)),
    );
    const completed = await fixture.run();
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.pipelineState.completedCommits.length, 1);
    assert.deepEqual(completed.pipelineState.bootstrapCorrections, []);
    assert.equal(
      fixture.calls.worker.filter(
        ({ schema }) => schema === REPOSITORY_DISCOVERY_SCHEMA,
      ).length,
      target === "discovery" ? 3 : 2,
    );
  });
}

test("interrupted migration batches reject repository drift and retire stale proof without renewing allowances", async (t) => {
  let migrating = false;
  let attempts = 0;
  const fixture = await createFixture(t, {
    plan,
    mode: "combined",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker", [1, 2, 3, 4, 5, 6]),
      reconciliationResolved(),
      bootstrapReady("Migrating Worker", [1, 2, 3, 4, 5, 6]),
    ],
    onTransition(run) {
      if (!migrating && run.pipelineState.workflowState === "IMPLEMENT")
        throw stop;
    },
    onRoleRun(role, request) {
      if (
        !migrating ||
        role !== "worker" ||
        request.schema !== APPLICABILITY_BATCH_SCHEMA
      )
        return;
      attempts++;
      if (attempts === 1)
        return {
          result: { ...ready(supplied(request)).result, assignments: [] },
        };
      if (attempts === 2) throw outputExhaustion();
      if (attempts === 4) throw stop;
    },
  });
  attachOutputExhaustion(fixture);
  await assert.rejects(fixture.run(), (error) => error === stop);
  fixture.persistPipelineState({
    ...fixture.currentRun.pipelineState,
    validationMigrationPending: true,
    validationScopeLegacy: true,
    validationSchedule: null,
    workerValidation: null,
    reviewerValidation: null,
  });
  migrating = true;
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  fixture.runtime.finishAgentTurn = (...args) => {
    if (attempts === 4) throw stop;
    return finishAgentTurn(...args);
  };
  await assert.rejects(fixture.run(), (error) => error === stop);
  fixture.runtime.finishAgentTurn = finishAgentTurn;
  const interrupted = fixture.currentRun.activeTurn;
  const saved = JSON.parse(JSON.stringify(fixture.currentRun.pipelineState));
  assert.equal(saved.bootstrapProgress.worker.work.accepted.length, 1);
  assert.equal(saved.bootstrapProgress.worker.subdivisions, 1);
  assert.equal(saved.bootstrapCorrections.length, 1);
  fixture.persistPipelineState(saved);
  await writeFile(
    join(fixture.projectPath, "source.js"),
    "Unexpected drift.\n",
  );
  const paused = await fixture.run();
  assert.deepEqual(interrupted, {
    role: "worker",
    phase: "validation-migration",
  });
  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "read_only_agent_mutated_repository");
  assert.deepEqual(
    paused.pipelineState.repositoryBaseline,
    saved.repositoryBaseline,
  );
  assert.equal(paused.pipelineState.bootstrapProgress.worker.work, null);
  assert.equal(paused.pipelineState.bootstrapProgress.worker.subdivisions, 1);
  assert.deepEqual(
    paused.pipelineState.bootstrapCorrections,
    saved.bootstrapCorrections,
  );
  assert.equal(paused.pipelineState.workerValidation, null);
  assert.equal(paused.pipelineState.requiredChecks, null);
  assert.equal(attempts, 4);
});

test("invalid-unit correction survives output subdivision and reload without a second semantic attempt", async (t) => {
  let attempts = 0;
  let interrupted = false;
  const fixture = await createFixture(t, {
    plan,
    onRoleRun(role, request) {
      if (role !== "worker" || request.schema !== APPLICABILITY_BATCH_SCHEMA)
        return;
      attempts++;
      if (attempts === 1)
        return {
          result: { ...ready(supplied(request)).result, assignments: [] },
        };
      if (attempts === 2) throw outputExhaustion();
    },
    onTransition(run) {
      if (
        !interrupted &&
        run.pipelineState.bootstrapProgress.worker.subdivisions === 1
      ) {
        interrupted = true;
        throw stop;
      }
      pauseBeforeWrites(run);
    },
  });
  attachOutputExhaustion(fixture);
  await assert.rejects(fixture.run(), (error) => error === stop);
  const saved = JSON.parse(JSON.stringify(fixture.currentRun.pipelineState));
  assert.equal(saved.bootstrapProgress.worker.work.pendingCorrection, "unit");
  assert.equal(saved.bootstrapProgress.worker.work.correctionAttempt, 1);
  fixture.persistPipelineState(saved);
  await assert.rejects(fixture.run(), (error) => error === stop);
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
  assert.equal(
    fixture.currentRun.pipelineState.pendingBootstrapCorrection,
    null,
  );
  assert.equal(fixture.currentRun.counters.fixRounds, 0);
});

test("an exhausted persisted subdivision allowance pauses the unfinished unit without replenishment", async (t) => {
  let interrupted = false;
  let exhaust = false;
  const fixture = await createFixture(t, {
    plan,
    onRoleRun(role, request) {
      if (
        exhaust &&
        role === "worker" &&
        request.schema === APPLICABILITY_BATCH_SCHEMA
      )
        throw outputExhaustion();
    },
    onTransition(run) {
      if (
        !interrupted &&
        run.pipelineState.bootstrapProgress.worker.work?.accepted.length === 1
      ) {
        interrupted = true;
        throw stop;
      }
    },
  });
  attachOutputExhaustion(fixture);
  await assert.rejects(fixture.run(), (error) => error === stop);
  const saved = structuredClone(fixture.currentRun.pipelineState);
  // Earlier invalidated catalogs may have consumed this allowance without
  // leaving their retired units in the current catalog's partition.
  saved.bootstrapProgress.worker.subdivisions = 16;
  fixture.persistPipelineState(saved);
  exhaust = true;
  for (let attempt = 0; attempt < 2; attempt++) {
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "output_exhausted");
    assert.equal(
      paused.pipelineState.bootstrapProgress.worker.subdivisions,
      16,
    );
    assert.equal(
      paused.pipelineState.bootstrapProgress.worker.work.accepted.length,
      1,
    );
    assert.equal(paused.pipelineState.workerValidation, null);
    assert.deepEqual(paused.pipelineState.bootstrapCorrections, []);
  }
});

test("version-27 unfinished roles rediscover independently while compatible complete inventories remain accepted", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    plan,
    onRoleRun(role, request) {
      if (
        !interrupted &&
        role === "reviewer" &&
        request.schema === REPOSITORY_DISCOVERY_SCHEMA
      ) {
        interrupted = true;
        throw stop;
      }
    },
    onTransition: pauseBeforeWrites,
  });
  await assert.rejects(fixture.run(), (error) => error === stop);
  const legacy = JSON.parse(JSON.stringify(fixture.currentRun.pipelineState));
  const accepted = legacy.workerValidation;
  delete legacy.bootstrapProgress;
  const migrated = migratePlanExecutionStateV27({ pipelineState: legacy });
  assert.equal(migrated.bootstrapProgress.reviewer.work, null);
  assert.deepEqual(migrated.workerValidation, accepted);
  fixture.persistPipelineState(migrated);
  await assert.rejects(fixture.run(), (error) => error === stop);
  assert.deepEqual(fixture.currentRun.pipelineState.workerValidation, accepted);
  assert.equal(
    fixture.calls.worker.filter(
      ({ schema }) => schema === REPOSITORY_DISCOVERY_SCHEMA,
    ).length,
    1,
  );
  assert.equal(
    fixture.calls.reviewer.filter(
      ({ schema }) => schema === REPOSITORY_DISCOVERY_SCHEMA,
    ).length,
    2,
  );
  assert.equal(
    fixture.applicabilityCalls.filter(({ role }) => role === "reviewer").length,
    2,
  );
});

test("confirmation recovery retains journal proof across bounded validation migration", async (t) => {
  const failure = Object.assign(new Error("Confirmation turn failed."), {
    code: "ERR_CODEX_TURN_FAILED",
    diagnosticClass: "turn_other",
  });
  const fixture = await createFixture(t, {
    mode: "combined",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      bootstrapReady("Migrating Reviewer"),
    ],
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      finalizationPassed(),
    ],
    onRoleRun(_role, request) {
      if (request.schema === REVIEW_SCHEMA) throw failure;
    },
  });
  const events = [];
  const record = (activity = null) => {
    const state = structuredClone(fixture.currentRun);
    events.push({
      runId: state.runId,
      revision: state.revision,
      state,
      activity,
    });
  };
  record();
  let interrupted = false;
  for (const name of [
    "transition",
    "startAgentTurn",
    "finishAgentTurn",
    "recordChildSession",
  ]) {
    const original = fixture.runtime[name].bind(fixture.runtime);
    fixture.runtime[name] = async (...args) => {
      const run = await original(...args);
      record(
        name === "startAgentTurn"
          ? { actor: args[0].role, phase: args[0].phase, kind: "turn-started" }
          : name === "transition"
            ? (args[1]?.activity ?? null)
            : null,
      );
      if (!interrupted && run.pipelineState.workflowState === "IMPLEMENT") {
        interrupted = true;
        throw stop;
      }
      return run;
    };
  }
  await assert.rejects(fixture.run(), (error) => error === stop);
  fixture.persistPipelineState({
    ...fixture.currentRun.pipelineState,
    validationMigrationPending: true,
    validationScopeLegacy: true,
    validationSchedule: null,
    workerValidation: null,
    reviewerValidation: null,
  });
  record();
  await assert.rejects(fixture.run(), (error) => error === failure);
  const failed = fixture.currentRun;
  const migrationTurns = events.filter(
    ({ activity }) =>
      activity?.kind === "turn-started" &&
      activity.phase === "validation-migration",
  );
  assert.deepEqual(
    migrationTurns.map(({ activity }) => activity.actor),
    ["worker", "worker", "reviewer", "reviewer", "worker"],
  );
  assert.ok(
    migrationTurns.every(
      ({ state }) =>
        state.pipelineState.workflowState === "IMPLEMENT" &&
        state.pipelineState.validationMigrationPending,
    ),
  );
  const prepare = (history) =>
    prepareLegacyConfirmationRecovery(
      failed,
      { run: failed, events: history },
      (run) => run,
    );
  await prepare(events);
  assert.equal(canRecoverLegacyConfirmation(failed), true);

  const invalid = structuredClone(events);
  for (const event of invalid) {
    if (event.state.activeTurn?.phase !== "implement") continue;
    event.state.activeTurn.phase = "validation-migration";
    if (event.activity?.kind === "turn-started")
      event.activity.phase = "validation-migration";
  }
  await prepare(invalid);
  assert.equal(canRecoverLegacyConfirmation(failed), false);

  const unreviewed = structuredClone(events);
  unreviewed.find(
    ({ activity }) =>
      activity?.actor === "reviewer" && activity.kind === "approved",
  ).activity = null;
  await prepare(unreviewed);
  assert.equal(canRecoverLegacyConfirmation(failed), false);
});
