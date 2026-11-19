import assert from "node:assert/strict";
import test from "node:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { serializeCommitPlan } from "@agent-runner/commit-plan";

import { createOwnershipDiagnostic } from "../../../src/platform/index.js";
import { createTrustedValidationService } from "../../../src/trusted-validation/index.js";
import {
  migratePlanExecutionStateV17,
  migratePlanExecutionStateV24,
  planExecutionPipeline,
} from "../src/index.js";
import {
  APPLICABILITY_BATCH_SCHEMA,
  REPOSITORY_DISCOVERY_SCHEMA,
} from "../src/bootstrap-unit-schemas.js";
import {
  bootstrapScopeFor,
  normalizeExecutionState,
} from "../src/bootstrap-progress.js";
import {
  acceptBootstrapBatch,
  consumeBootstrapCorrection,
  correctBootstrapCatalog,
  createBootstrapScope,
  createBootstrapWork,
  normalizeBootstrapWork,
  normalizeRepositoryDiscovery,
} from "../src/bootstrap-units.js";
import { inspectionRequirements } from "../src/capability-requirements.js";
import { FINALIZATION_SCHEMA } from "../src/schemas.js";
import { validationEvidenceFingerprint } from "../src/validation-schedule.js";
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
  capabilities: {
    scratch: true,
    cache: false,
    sourceProjection: false,
    artifacts: [],
  },
  unsupported: [],
  basis: "assigned-executor",
});
const emptyRequirement = (target = command) => ({
  command: target,
  commandIdentity: null,
  capabilities: {
    scratch: false,
    cache: false,
    sourceProjection: false,
    artifacts: [],
  },
  unsupported: [],
  basis: "assigned-executor",
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
const ordinaryChecks = [
  { id: "C1", command },
  { id: "C2", command: "npm run lint" },
  { id: "C3", command: "npm run docs:check" },
];
const ordinaryFinalization = () => ({
  ...finalizationPassed(),
  requiredChecks: ordinaryChecks,
  checks: ordinaryChecks.map(({ id, command: target }) => ({
    checkId: id,
    command: target,
    status: "PASS",
    evidence: ["Passed"],
  })),
});
const cacheReport = (basis, target = ordinaryChecks[2].command) => ({
  command: target,
  commandIdentity: null,
  capabilities: {
    scratch: false,
    cache: true,
    sourceProjection: false,
    artifacts: [],
  },
  unsupported: [],
  basis,
});
const withoutBasis = (report) => {
  const copy = structuredClone(report);
  delete copy.basis;
  return copy;
};
const constraint = (expected) => (cause) =>
  cause.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT" &&
  cause.diagnostic?.constraint === expected;
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

test("trusted ownership diagnostics survive capability pause publication", async (t) => {
  const diagnostic = createOwnershipDiagnostic("launcher-setup");
  const evidence = [
    "The runner could not prepare the frozen command capabilities.",
    `Ownership diagnostic: ${JSON.stringify(diagnostic)}`,
  ];
  const fixture = await createFixture(t, {
    onRequirementInspection: () => ({
      status: "BLOCKED",
      blockers: [{ command, reason: "unavailable", evidence }],
    }),
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");
  assert.deepEqual(paused.pause.evidence, [
    `${command}: unavailable`,
    ...evidence,
  ]);
  assert.equal(writes(fixture).length, 0);
});

test("trusted ownership diagnostics survive caught inspection, preflight and cleanup refusals", async (t) => {
  for (const boundary of ["inspection", "preflight", "cleanup"]) {
    const diagnostic = createOwnershipDiagnostic("trusted-resource-custody");
    const failure = Object.assign(new Error("PRIVATE_NATIVE_OUTPUT"), {
      code:
        boundary === "cleanup"
          ? "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE"
          : "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
      ownershipDiagnostic: diagnostic,
      evidence: ["PRIVATE_NATIVE_OUTPUT"],
    });
    const snapshot = trustedValidationSnapshot();
    const finalization = finalizationWithTrustedCheck(snapshot);
    const fixture = await createFixture(t, {
      mode: "lazy",
      trustedValidation: snapshot,
      modeSettings: { trustedChecks: ["service-check"] },
      worker: bootstrapTurns("lazy", {
        ...bootstrapReady("Worker"),
        requiredChecks: finalization.requiredChecks,
      }),
      workWorker: [implementationCompleted(), checkAndFix(), finalization],
      onRequirementInspection() {
        if (boundary === "inspection") throw failure;
        return ready;
      },
      onTrustedValidation() {
        assert.equal(boundary, "cleanup");
        throw failure;
      },
    });
    if (boundary === "preflight")
      fixture.runtime.trustedValidation.preflight = () => {
        throw failure;
      };
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "environment_blocked");
    assert.ok(
      paused.pause.evidence.includes(
        `Ownership diagnostic: ${JSON.stringify(diagnostic)}`,
      ),
    );
    assert.doesNotMatch(JSON.stringify(paused), /PRIVATE_NATIVE_OUTPUT/u);
    assert.equal(paused.pipelineState.finalizationResult, null);
    if (boundary === "cleanup") {
      assert.equal(paused.pause.resumeState, "FINALIZE");
      assert.equal(paused.pause.code, failure.code);
      assert.equal(paused.pipelineState.pendingCommit, null);
    } else {
      assert.equal(writes(fixture).length, 0);
    }
  }
});

test("capability reports reject empty needs, mismatched identities, and malformed parameters", () => {
  const result = bootstrapReady("Worker");
  for (const report of [
    emptyRequirement(),
    { ...requirement(), command: "node undeclared" },
    { ...requirement(), commandIdentity: "private value" },
    {
      ...requirement(),
      capabilities: { ...requirement().capabilities, scratch: "/tmp" },
    },
    {
      ...requirement(),
      capabilities: {
        scratch: true,
        cache: false,
        artifacts: [],
      },
    },
    {
      ...emptyRequirement(),
      capabilities: {
        ...emptyRequirement().capabilities,
        sourceProjection: true,
        sourcePath: "/tmp/projected-source",
      },
    },
    { ...requirement(), unsupported: ["secret\ntext"] },
    {
      ...requirement(),
      capabilities: {
        scratch: true,
        cache: false,
        sourceProjection: false,
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
          {
            command,
            source: "host",
            evidence: ["Unavailable"],
            basis: "assigned-executor",
          },
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
  assert.equal(
    normalizeBootstrapResult(
      {
        ...result,
        capabilityRequirements: [
          {
            ...emptyRequirement(),
            capabilities: {
              ...emptyRequirement().capabilities,
              sourceProjection: true,
            },
          },
        ],
      },
      "worker",
    ).capabilityRequirements[0].capabilities.sourceProjection,
    true,
  );

  const snapshot = trustedValidationSnapshot();
  const selected = snapshot.commands[0];
  const selectedResult = {
    ...result,
    requiredChecks: [
      ...result.requiredChecks,
      { id: "C2", command: selected.command, steps: [1] },
    ],
  };
  assert.throws(
    () =>
      normalizeBootstrapResult(
        {
          ...selectedResult,
          capabilityRequirements: [
            {
              ...requirement(selected.command),
              commandIdentity: "a".repeat(64),
            },
          ],
        },
        "worker",
        1,
        { trustedCommands: snapshot.commands },
      ),
    { code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT" },
  );
  assert.equal(
    normalizeBootstrapResult(
      {
        ...selectedResult,
        capabilityRequirements: [
          {
            ...requirement(selected.command),
            commandIdentity: selected.identity,
          },
        ],
      },
      "worker",
      1,
      { trustedCommands: snapshot.commands },
    ).capabilityRequirements[0].commandIdentity,
    selected.identity,
  );
});

test("version-24 migration denies source projection without disturbing workflow proof", () => {
  const capabilityRequirements = [
    {
      command,
      commandIdentity: null,
      capabilities: { scratch: true, cache: false, artifacts: [] },
      unsupported: [],
    },
  ];
  const validation = {
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: ["package.json"],
    capabilityRequirements,
    environmentBlockers: [],
  };
  const trustedValidation = trustedValidationSnapshot();
  const bootstrapCorrections = [{ attempt: 1, diagnostics: [] }];
  const reviewResult = { status: "APPROVED", fingerprint: "a".repeat(64) };
  const pendingCommit = {
    status: "consumed",
    authorization: { token: "opaque" },
  };
  const legacy = {
    workerValidation: validation,
    reviewerValidation: validation,
    trustedValidation,
    workflowState: "COMMIT",
    currentStep: 2,
    bootstrapCorrections,
    reviewResult,
    pendingCommit,
  };

  const migrated = migratePlanExecutionStateV24({ pipelineState: legacy });

  for (const role of ["worker", "reviewer"]) {
    assert.deepEqual(
      migrated[`${role}Validation`].capabilityRequirements[0].capabilities,
      {
        scratch: true,
        cache: false,
        artifacts: [],
        sourceProjection: false,
      },
    );
    assert.ok(
      Object.isFrozen(
        migrated[`${role}Validation`].capabilityRequirements[0].capabilities,
      ),
    );
  }
  assert.equal(migrated.trustedValidation, trustedValidation);
  assert.equal(migrated.bootstrapCorrections, bootstrapCorrections);
  assert.equal(migrated.reviewResult, reviewResult);
  assert.equal(migrated.pendingCommit, pendingCommit);
  assert.equal(migrated.workflowState, "COMMIT");
  assert.equal(migrated.currentStep, 2);
});

test("empty capability output is corrected without delegating an ordinary check", async (t) => {
  const inspections = [];
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        capabilityRequirements: [emptyRequirement()],
      },
      bootstrapReady("Worker"),
    ],
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      finalizationPassed(),
    ],
    onRequirementInspection(input) {
      inspections.push(structuredClone(input));
      return ready;
    },
  });

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.bootstrapCorrections.length, 1);
  assert.ok(inspections.length > 0);
  assert.ok(inspections.every(({ requirements }) => requirements.length === 0));
  assert.ok(
    completed.pipelineState.finalizationResult.checks.every(
      ({ executor }) => executor === "agent",
    ),
  );
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
          basis: "assigned-executor",
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
    basis: "assigned-executor",
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
    [
      {
        capabilityRequirements: [
          {
            ...needs,
            commandIdentity: snapshot.commands[0].identity,
          },
        ],
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
              sourceProjection: false,
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
            basis: "assigned-executor",
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

test("plan-execution reports require a closed basis that keeps every structural rule", () => {
  const base = bootstrapReady("Worker");
  const observed = { ...requirement(), basis: "read-only-turn" };
  const blocker = {
    command,
    source: "agent-sandbox",
    evidence: ["Unavailable"],
    basis: "read-only-turn",
  };
  for (const reports of [
    { capabilityRequirements: [withoutBasis(requirement())] },
    { capabilityRequirements: [{ ...requirement(), basis: "reviewer-turn" }] },
    { environmentBlockers: [withoutBasis(blocker)] },
    { environmentBlockers: [{ ...blocker, basis: null }] },
    {
      capabilityRequirements: [
        { ...emptyRequirement(), basis: "read-only-turn" },
      ],
    },
    {
      capabilityRequirements: [
        { ...observed, command: "node outside-inventory" },
      ],
    },
    {
      capabilityRequirements: [
        { ...observed, commandIdentity: "a".repeat(64) },
      ],
    },
    { environmentBlockers: [{ ...blocker, evidence: [] }] },
  ])
    assert.throws(
      () => normalizeBootstrapResult({ ...base, ...reports }, "worker"),
      constraint("exact-command-capability-reports"),
    );
  const accepted = normalizeBootstrapResult(
    {
      ...base,
      capabilityRequirements: [observed],
      environmentBlockers: [blocker],
    },
    "worker",
  );
  assert.deepEqual(accepted.capabilityRequirements, [observed]);
  assert.deepEqual(accepted.environmentBlockers, [blocker]);
  const savedRows = {
    ...base,
    capabilityRequirements: [withoutBasis(requirement())],
    environmentBlockers: [withoutBasis(blocker)],
  };
  assert.doesNotThrow(() =>
    normalizeBootstrapResult(savedRows, "worker", 1, { legacy: true }),
  );
  for (const schema of [
    REPOSITORY_DISCOVERY_SCHEMA.properties.result.anyOf[0],
    APPLICABILITY_BATCH_SCHEMA.properties.result.anyOf[1],
  ])
    for (const field of ["capabilityRequirements", "environmentBlockers"]) {
      const items = schema.properties[field].items;
      assert.ok(items.required.includes("basis"));
      assert.deepEqual(items.properties.basis.enum, [
        "assigned-executor",
        "read-only-turn",
      ]);
    }

  // Admission forwards assigned-executor and legacy rows, never the basis.
  assert.deepEqual(
    inspectionRequirements([
      {
        capabilityRequirements: [
          cacheReport("read-only-turn"),
          cacheReport("assigned-executor", command),
          withoutBasis(cacheReport("assigned-executor")),
        ],
        environmentBlockers: [
          blocker,
          { ...blocker, command: "npm run lint", basis: "assigned-executor" },
          withoutBasis({ ...blocker, command: "npm run docs:check" }),
        ],
      },
    ]),
    [
      {
        command,
        commandIdentity: null,
        unsupported: [],
        capabilities: { cache: true },
      },
      {
        command: "npm run docs:check",
        commandIdentity: null,
        unsupported: [],
        capabilities: { cache: true },
      },
      { command: "npm run lint" },
      { command: "npm run docs:check" },
    ],
  );
});

test("provider discovery without a basis receives the existing bounded correction", async (t) => {
  const inspections = [];
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        capabilityRequirements: [withoutBasis(requirement())],
      },
      bootstrapReady("Worker"),
    ],
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      finalizationPassed(),
    ],
    onRequirementInspection(input) {
      inspections.push(structuredClone(input));
      return ready;
    },
  });
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    completed.pipelineState.bootstrapCorrections.map(
      ({ diagnostics }) => diagnostics[0].constraint,
    ),
    ["exact-command-capability-reports"],
  );
  assert.ok(inspections.every(({ requirements }) => requirements.length === 0));
});

async function reviewerCacheFixture(t, basis, requests) {
  const root = createTrustedValidationService();
  return createFixture(t, {
    mode: "combined",
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), requiredChecks: ordinaryChecks },
      reconciliationResolved(),
    ],
    reviewer: [
      {
        ...bootstrapReady("Reviewer"),
        requiredChecks: ordinaryChecks,
        capabilityRequirements: [cacheReport(basis)],
      },
    ],
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      ordinaryFinalization(),
    ],
    onRequirementInspection(input) {
      requests.push(structuredClone(input));
      return root.inspectRequirements(input);
    },
  });
}

test("combined execution keeps a read-only-turn observation without requiring it in Worker FINALIZE", async (t) => {
  const requests = [];
  const fixture = await reviewerCacheFixture(t, "read-only-turn", requests);
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    done.pipelineState.workerValidation.capabilityRequirements,
    [],
  );
  assert.deepEqual(
    done.pipelineState.reviewerValidation.capabilityRequirements,
    [cacheReport("read-only-turn")],
  );
  assert.ok(requests.length > 0);
  assert.ok(requests.every(({ requirements }) => requirements.length === 0));
  assert.deepEqual(
    done.pipelineState.finalizationResult.checks.map(
      ({ checkId, executor }) => [checkId, executor],
    ),
    ordinaryChecks.map(({ id }) => [id, "agent"]),
  );
  const finalization = Object.values(fixture.calls)
    .flat()
    .filter(({ schema }) => schema === FINALIZATION_SCHEMA);
  assert.equal(finalization.length, 1);
  assert.equal(finalization[0].access, "workspace-write");
});

test("combined execution blocks a genuine assigned-executor need before writable work", async (t) => {
  const requests = [];
  const fixture = await reviewerCacheFixture(t, "assigned-executor", requests);
  const before = await fixture.runtime.git.snapshot();
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.match(paused.pause.evidence[0], /not-selected/u);
  assert.deepEqual(requests[0].requirements, [
    {
      command: ordinaryChecks[2].command,
      commandIdentity: null,
      unsupported: [],
      capabilities: { cache: true },
    },
  ]);
  assert.equal(writes(fixture).length, 0);
  assert.deepEqual(paused.pipelineState.completedCommits, []);
  const after = await fixture.runtime.git.snapshot();
  assert.equal(after.contentFingerprint, before.contentFingerprint);
  assert.equal(after.indexFingerprint, before.indexFingerprint);
});

test("legacy validation migration does not admit a read-only-turn observation", async (t) => {
  const root = createTrustedValidationService();
  let migrating = false;
  const requests = [];
  const fixture = await createFixture(t, {
    worker: bootstrapTurns("independent"),
    workWorker: [
      implementationBlocked(),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      implementationCompleted(),
      finalizationPassed(),
    ],
    workReviewer: [
      {
        ...bootstrapReady("Migrating Reviewer"),
        capabilityRequirements: [cacheReport("read-only-turn", command)],
      },
    ],
    onRequirementInspection(input) {
      if (migrating) requests.push(structuredClone(input));
      return root.inspectRequirements(input);
    },
  });
  const paused = await fixture.run();
  fixture.persistPipelineState(legacy(paused));
  migrating = true;
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    done.pipelineState.reviewerValidation.capabilityRequirements,
    [cacheReport("read-only-turn", command)],
  );
  assert.ok(requests.length > 0);
  assert.ok(requests.every(({ requirements }) => requirements.length === 0));
});

test("version-39 migration keeps saved reports and their admission unchanged", async (t) => {
  const completed = await (await createFixture(t)).run();
  const validation = {
    ...completed.pipelineState.workerValidation,
    capabilityRequirements: [withoutBasis(requirement())],
    environmentBlockers: [
      { command, source: "agent-sandbox", evidence: ["Not delegated."] },
    ],
  };
  const saved = { ...completed.pipelineState, workerValidation: validation };
  const provisional = legacy(completed);
  for (const state of [saved, provisional]) {
    const bytes = JSON.stringify(state);
    const migrated = planExecutionPipeline.migrations[39]({
      pipelineState: state,
    });
    assert.equal(JSON.stringify(migrated), bytes);
    assert.ok(Object.isFrozen(migrated));
    assert.doesNotThrow(() => normalizePipelineState(migrated));
  }
  for (const role of ["worker", "reviewer"])
    assert.equal(provisional[`${role}Validation`].capabilityRequirements, null);
  const migrated = planExecutionPipeline.migrations[39]({
    pipelineState: saved,
  });
  const request = inspectionRequirements([
    saved.workerValidation,
    saved.reviewerValidation,
  ]);
  assert.deepEqual(
    inspectionRequirements([
      migrated.workerValidation,
      migrated.reviewerValidation,
    ]),
    request,
  );
  assert.deepEqual(request, [
    {
      command,
      commandIdentity: null,
      unsupported: [],
      capabilities: { scratch: true },
    },
    { command },
  ]);
});

test("applicability requests carry the basis guidance, including their reconstruction", async (t) => {
  const fixture = await createFixture(t);
  await fixture.run();
  assert.ok(fixture.applicabilityCalls.length > 0);
  for (const request of fixture.applicabilityCalls)
    for (const prompt of [request.prompt, request.recoveryPrompt]) {
      assert.match(prompt, /basis "read-only-turn"/u);
      assert.match(prompt, /Never upgrade such an observation/u);
      assert.match(prompt, /never changes the basis of an accepted entry/u);
    }
});

const stop = Object.assign(new Error("Interrupted durable checkpoint."), {
  code: "ERR_RUN_REVISION_CHANGED",
});
const supplied = (request) =>
  JSON.parse(
    /Applicability request \(data\):\n([^\n]+)/u.exec(request.prompt)[1],
  );
const correctionBatch = (request, capabilityRequirements) => ({
  result: {
    status: "CATALOG_CORRECTION_REQUIRED",
    unitId: supplied(request).unitId,
    assignments: [],
    missingCommands: [],
    missingInfrastructure: [],
    capabilityRequirements,
    environmentBlockers: [],
  },
});
// Simulate the saved bytes of a version-39 run: stored reports lack a basis and
// the unfinished catalog is self-consistent with those exact bytes.
function legacyBootstrap(state, pending) {
  const legacyState = structuredClone(state);
  const progress = legacyState.bootstrapProgress.worker;
  if (pending) {
    progress.work.catalogCorrection.capabilityRequirements =
      progress.work.catalogCorrection.capabilityRequirements.map(withoutBasis);
    return legacyState;
  }
  const { binding, discovery, limits, correctionAttempt } = progress.work;
  progress.work = JSON.parse(
    JSON.stringify(
      createBootstrapWork(
        bootstrapScopeFor(
          legacyState,
          "worker",
          binding.inputFingerprint,
          binding.infrastructureFingerprint,
        ),
        {
          ...discovery,
          capabilityRequirements:
            discovery.capabilityRequirements.map(withoutBasis),
        },
        limits,
        correctionAttempt,
      ),
    ),
  );
  return legacyState;
}

for (const pending of [false, true]) {
  test(`version-39 ${pending ? "pending correction" : "catalog"} rows survive canonical catalog replacement`, async (t) => {
    const observed = cacheReport("read-only-turn", command);
    const legacyRow = withoutBasis(requirement());
    const requests = [];
    let captured;
    let published;
    let reloaded = false;
    let reported = false;
    const fixture = await createFixture(t, {
      mode: "lazy",
      worker: [
        clarificationReady(),
        {
          ...bootstrapReady("Worker"),
          capabilityRequirements: pending ? [] : [requirement()],
        },
        {
          ...bootstrapReady("Corrected Worker"),
          capabilityRequirements: pending
            ? [requirement()]
            : [requirement(), observed],
        },
      ],
      workWorker: [
        implementationCompleted(),
        checkAndFix(),
        finalizationPassed(),
      ],
      onRoleRun(role, request) {
        if (request.schema !== APPLICABILITY_BATCH_SCHEMA || reported) return;
        if (!pending && !reloaded) return;
        reported = true;
        if (!pending) {
          const work =
            fixture.currentRun.pipelineState.bootstrapProgress.worker.work;
          assert.equal(
            supplied(request).catalogFingerprint,
            work.catalogFingerprint,
          );
          assert.equal(supplied(request).unitId, work.units[0].id);
        }
        return correctionBatch(request, [pending ? requirement() : observed]);
      },
      onTransition(run) {
        const work = run.pipelineState.bootstrapProgress.worker.work;
        if (!captured && work !== null) {
          if (
            pending
              ? work.pendingCorrection === "catalog"
              : work.accepted.length === 0 && work.catalogCorrection === null
          ) {
            captured = structuredClone(run.pipelineState);
            throw stop;
          }
        }
        if (
          reloaded &&
          !published &&
          work?.catalogCorrection === null &&
          work.correctionAttempt === 1
        )
          published = structuredClone(run.pipelineState);
      },
      onRequirementInspection(input) {
        requests.push(structuredClone(input));
        return ready;
      },
    });
    await assert.rejects(fixture.run(), (cause) => cause === stop);
    const saved = legacyBootstrap(captured, pending);
    const bytes = JSON.stringify(saved);
    const migrated = planExecutionPipeline.migrations[39]({
      pipelineState: saved,
    });
    assert.equal(JSON.stringify(migrated), bytes);
    assert.doesNotThrow(() => normalizeExecutionState(migrated));
    const legacyWork = saved.bootstrapProgress.worker.work;
    fixture.persistPipelineState(migrated, { pause: null });
    reloaded = true;

    const done = await fixture.run();
    assert.equal(done.pipelineState.workflowState, "DONE");
    assert.equal(done.pipelineState.bootstrapCorrections.length, 1);
    const work = published.bootstrapProgress.worker.work;
    assert.deepEqual(
      work.discovery.capabilityRequirements,
      pending ? [legacyRow] : [legacyRow, observed],
    );
    assert.equal(work.correctionAttempt, 1);
    assert.equal(work.pendingCorrection, null);
    assert.deepEqual(work.accepted, []);
    assert.notEqual(work.catalogFingerprint, legacyWork.catalogFingerprint);
    assert.notEqual(work.units[0].id, legacyWork.units[0].id);
    assert.doesNotThrow(() => normalizeExecutionState(published));
    assert.deepEqual(
      done.pipelineState.workerValidation.capabilityRequirements,
      work.discovery.capabilityRequirements,
    );
    // The legacy need stays admitted; the read-only observation never is.
    assert.ok(requests.length > 0);
    for (const { requirements } of requests)
      assert.deepEqual(requirements, [
        {
          command,
          commandIdentity: null,
          unsupported: [],
          capabilities: { scratch: true },
        },
      ]);
  });
}

test("inherited basis-less rows are canonicalized only as exact assigned-executor copies", () => {
  const hash = (character) => character.repeat(64);
  const subject = "feat(sample): add part 1";
  const limits = { maxSteps: 2, maxBytes: 100_000 };
  const scope = (overrides = {}) =>
    createBootstrapScope({
      canonicalPlan: serializeCommitPlan({
        steps: [{ number: 1, subject, body: "Implement part 1." }],
      }),
      role: "worker",
      inputFingerprint: hash("a"),
      repositoryFingerprint: hash("b"),
      infrastructureFingerprint: hash("c"),
      position: { step: 1, subject },
      ...overrides,
    });
  const discovery = (capabilityRequirements, environmentBlockers = []) => ({
    stepAssessment: {
      step: 1,
      subject,
      disposition: "CURRENT",
      evidence: ["The selected step is pending."],
    },
    summary: "The validation script owns the check.",
    requiredChecks: [{ id: "C1", command }],
    validationInfrastructure: ["package.json"],
    capabilityRequirements,
    environmentBlockers,
  });
  const legacyRow = withoutBasis(requirement());
  const observed = { ...requirement(), basis: "read-only-turn" };
  const fresh = cacheReport("assigned-executor", command);
  const blocker = {
    command,
    source: "runner",
    evidence: ["The executable is unavailable."],
    basis: "assigned-executor",
  };

  // Revision discovery repeats a prior basis-less row as an exact copy.
  const previousValidation = {
    requiredChecks: [{ id: "C1", command, steps: [1] }],
    validationInfrastructure: ["package.json"],
    capabilityRequirements: [legacyRow],
    environmentBlockers: [withoutBasis(blocker)],
  };
  const revision = scope({ previousValidation });
  const accepted = normalizeRepositoryDiscovery(
    discovery([requirement(), fresh], [blocker]),
    revision,
    { inherited: [] },
  );
  assert.deepEqual(accepted.capabilityRequirements, [legacyRow, fresh]);
  assert.deepEqual(accepted.environmentBlockers, [withoutBasis(blocker)]);
  const revisionWork = createBootstrapWork(revision, accepted, limits, 0);
  assert.deepEqual(revisionWork.discovery.capabilityRequirements[0], legacyRow);
  assert.equal(
    revisionWork.binding.validationFingerprint,
    validationEvidenceFingerprint(previousValidation),
  );
  assert.throws(
    () =>
      normalizeRepositoryDiscovery(discovery([observed], [blocker]), revision, {
        inherited: [],
      }),
    constraint("preserve-prior-revision-requirements"),
  );
  assert.throws(
    () =>
      normalizeRepositoryDiscovery(
        discovery([legacyRow], [blocker]),
        revision,
        { inherited: [] },
      ),
    constraint("exact-command-capability-reports"),
  );

  // Catalog continuation keeps the saved discovery bytes.
  const base = scope();
  let work = createBootstrapWork(base, discovery([legacyRow]), limits, 0);
  const correction = (reports) => ({
    status: "CATALOG_CORRECTION_REQUIRED",
    unitId: work.units[0].id,
    assignments: [],
    missingCommands: [],
    missingInfrastructure: [],
    capabilityRequirements: reports,
    environmentBlockers: [],
  });
  assert.throws(
    () => acceptBootstrapBatch(base, work, correction([requirement()])),
    constraint("new-capability-evidence"),
  );
  work = consumeBootstrapCorrection(
    base,
    acceptBootstrapBatch(base, work, correction([observed])),
  );
  const replace = (pendingWork, reports) =>
    correctBootstrapCatalog(
      base,
      pendingWork,
      normalizeRepositoryDiscovery(discovery(reports), base, {
        inherited: [pendingWork.discovery, pendingWork.catalogCorrection],
      }),
    );
  assert.deepEqual(
    replace(work, [requirement(), observed]).discovery.capabilityRequirements,
    [legacyRow, observed],
  );
  assert.throws(
    () =>
      replace(work, [{ ...requirement(), basis: "read-only-turn" }, observed]),
    constraint("preserve-and-complete-catalog"),
  );

  // A charged saved correction may hold a basis-less row not yet in discovery.
  let charged = createBootstrapWork(base, discovery([]), limits, 0);
  charged = JSON.parse(
    JSON.stringify(
      acceptBootstrapBatch(base, charged, {
        ...correction([requirement()]),
        unitId: charged.units[0].id,
      }),
    ),
  );
  charged.catalogCorrection.capabilityRequirements = [legacyRow];
  charged = consumeBootstrapCorrection(
    base,
    normalizeBootstrapWork(charged, base, 0),
  );
  const replacement = replace(charged, [requirement()]);
  assert.deepEqual(replacement.discovery.capabilityRequirements, [legacyRow]);
  assert.equal(replacement.correctionAttempt, 1);
  assert.throws(
    () => consumeBootstrapCorrection(base, replacement),
    constraint("role-correction-exhausted"),
  );
});
