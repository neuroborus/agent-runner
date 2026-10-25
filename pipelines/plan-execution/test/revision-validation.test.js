import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  createPlanExecutionState,
  planExecutionPipeline,
} from "../src/index.js";
import { normalizeExecutionState } from "../src/bootstrap-progress.js";
import {
  acceptBootstrapBatch,
  applicabilityRequest,
  createBootstrapWork,
  consumeBootstrapCorrection,
  normalizeBootstrapWork,
} from "../src/bootstrap-units.js";
import { runBoundedBootstrap } from "../src/bounded-bootstrap.js";
import {
  createCommitSizeBinding,
  reserveCommitSizeAssessment,
  recordCommitSizeDecision,
} from "../src/commit-size-assessment.js";
import {
  acceptEffectivePlanRevision,
  effectivePlanRevisionCheckpoint,
  proposeEffectivePlanRevision,
  recordEffectivePlanReview,
} from "../src/effective-plan.js";
import {
  implementationEvidence,
  validImplementationEvidence,
} from "../src/implementation-evidence.js";
import {
  effectiveStepCorrespondence,
  selectedPlanPosition,
} from "../src/plan-position.js";
import {
  acceptRevisionValidation,
  assertRevisionValidation,
  effectiveValidationInventory,
  revisionBootstrapScope,
} from "../src/revision-validation.js";
import {
  deriveValidationSchedule,
  scheduledChecks,
  validationEvidenceFingerprint as fingerprint,
} from "../src/validation-schedule.js";
import { SETTINGS, trustedValidationSnapshot } from "./support/index.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const fast = "npm run test:service";
const trusted = trustedValidationSnapshot("fixture-check", fast, {
  scratch: true,
  cache: true,
});
const future = "node validation/future.js";
const independent = "node validation/reviewer.js";
const extra = "node validation/replacement.js";
const canonicalPlan =
  "## Commit 1: feat(core): add the baseline\n\nCreate the baseline.\n\n## Commit 2: feat(reader): add the complete reader\n\nImplement the reader and caller.\n\n## Commit 3: feat(output): add reporting\n\nReport results.\n";
const replacementPlan =
  "## Commit 1: feat(reader): add the reader\n\nImplement the reader.\n\n## Commit 2: feat(runtime): use the reader\n\nSwitch the caller.\n";
const inspection = Object.fromEntries(
  [
    "inputFingerprint",
    "scopeFingerprint",
    "dependenciesFingerprint",
    "contentFingerprint",
  ].map((field) => [field, hash(field)]),
);
const boundary = { reconciled: true, inspection };
const check = (id, command, steps) => ({
  id,
  command,
  ...(steps === undefined ? {} : { steps }),
});
const reload = (value) => JSON.parse(JSON.stringify(value));
const roleInventory = (reviewer = false) => ({
  requiredChecks: [
    check("C1", fast, [1, 2, 3]),
    check("C2", reviewer ? independent : future, reviewer ? [2, 3] : [3]),
  ],
  validationInfrastructure: [
    reviewer ? "validation/reviewer.js" : "package.json",
  ],
  capabilityRequirements: [
    {
      command: fast,
      commandIdentity: trusted.commands[0].identity,
      capabilities: {
        scratch: true,
        cache: false,
        sourceProjection: false,
        artifacts: [],
      },
      unsupported: [],
    },
  ],
  environmentBlockers: [],
});

function revise(state) {
  const binding = createCommitSizeBinding(
    {
      originalStep: 2,
      planFingerprint: hash(state.canonicalPlan),
      ...inspection,
      measurement: {
        baseHead: state.repositoryBaseline.head,
        contentFingerprint: inspection.contentFingerprint,
        changedLines:
          3000 + state.effectivePlanRevisions.revisions.length * 1000,
        binaryPaths: [],
        gitlinkPaths: [],
      },
    },
    state.settings,
  );
  const reserved = reserveCommitSizeAssessment(
    { ...state.commitSizeAssessment, eligible: true },
    binding,
    state.settings,
    { reconciled: true, commitPending: false },
  );
  state = {
    ...state,
    commitSizeAssessment: recordCommitSizeDecision(
      reserved.ledger,
      binding,
      {
        bindingFingerprint: reserved.bindingFingerprint,
        decision: "SPLIT",
        reason: "Introduce the reader before its caller.",
        replacementPlan,
      },
      state.settings,
    ),
  };
  state = proposeEffectivePlanRevision(
    state,
    { replacementPlan, findingOwners: [] },
    boundary,
  );
  for (let request; (request = effectivePlanRevisionCheckpoint(state));)
    state = recordEffectivePlanReview(
      state,
      request.checkpoint,
      {
        fingerprint: request.fingerprint,
        status: "CLEAN",
        reason: "Scope and checks are preserved.",
        preserves: {
          requirements: true,
          dependencies: true,
          laterSteps: true,
          checks: true,
          findings: true,
        },
      },
      boundary,
    );
  return acceptEffectivePlanRevision(state, boundary);
}

function revised(mode = "combined", patch = {}) {
  return revise({
    ...createPlanExecutionState({
      settings: { ...SETTINGS, mode, trustedChecks: ["fixture-check"] },
      trustedValidation: trusted,
    }),
    canonicalPlan,
    currentStep: 2,
    workflowState: "IMPLEMENT",
    repositoryBaseline: {
      head: "a".repeat(40),
      contentFingerprint: hash("baseline"),
    },
    completedCommits: ["a".repeat(40)],
    workerValidation: roleInventory(),
    reviewerValidation: mode === "lazy" ? null : roleInventory(true),
    ...patch,
  });
}

function workFor(
  state,
  role,
  mutate = () => {},
  inputFingerprint = fingerprint({}),
) {
  const scope = revisionBootstrapScope(state, role, {
    inputFingerprint,
    infrastructureFingerprint: hash(role),
  });
  const prior = scope.previousValidation;
  const discovery = {
    ...reload(prior),
    requiredChecks: [
      ...prior.requiredChecks.map(({ id, command }) => ({ id, command })),
      ...(prior.requiredChecks.some(({ command }) => command === extra)
        ? []
        : [{ id: "C3", command: extra }]),
    ],
    summary:
      "The replacement-specific check verifies the new intermediate result.",
    stepAssessment: {
      step: scope.binding.step,
      subject: scope.binding.subject,
      disposition: "CURRENT",
      evidence: [],
    },
  };
  mutate(discovery);
  let work = createBootstrapWork(
    scope,
    discovery,
    { maxSteps: 2, maxBytes: 256 * 1024 },
    0,
  );
  return { scope, work };
}

function batch(work) {
  const unit = work.units[work.accepted.length];
  const last = work.units.at(-1).end;
  return {
    status: "READY",
    unitId: unit.id,
    assignments: work.discovery.requiredChecks
      .map(({ id, command }) => ({
        checkId: id,
        steps: (command === future
          ? [last]
          : command === independent
            ? [3, last]
            : command === extra
              ? [2]
              : Array.from({ length: last }, (_, index) => index + 1)
        ).filter((step) => step >= unit.start && step <= unit.end),
      }))
      .filter(({ steps }) => steps.length > 0),
    missingCommands: [],
    missingInfrastructure: [],
    capabilityRequirements: [],
    environmentBlockers: [],
  };
}
function finish(scope, work) {
  while (work.accepted.length < work.units.length)
    work = acceptBootstrapBatch(scope, work, batch(work));
  return work;
}

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} requires complete revision inventories from every active role and retains additive future coverage`, () => {
    let state = revised(mode);
    const original = reload(state);
    const { scope, work } = workFor(state, "worker");
    assert.deepEqual(
      applicabilityRequest(scope, work.discovery, 2, 3).correspondence,
      [
        { step: 2, originalStep: 2, replacement: 1 },
        { step: 3, originalStep: 2, replacement: 2 },
      ],
    );
    assert.throws(() => acceptRevisionValidation(state, "worker", scope, work));
    const complete = finish(scope, work);
    state = reload(acceptRevisionValidation(state, "worker", scope, complete));
    assert.deepEqual(
      acceptRevisionValidation(state, "worker", scope, complete),
      state,
    );
    assert.equal(effectiveValidationInventory(state) === null, mode !== "lazy");
    if (mode !== "lazy") {
      const reviewer = workFor(state, "reviewer");
      state = reload(
        acceptRevisionValidation(
          state,
          "reviewer",
          reviewer.scope,
          finish(reviewer.scope, reviewer.work),
        ),
      );
    } else
      assert.throws(() =>
        acceptRevisionValidation(state, "reviewer", scope, complete),
      );
    assertRevisionValidation(state);
    const inventory = effectiveValidationInventory(state);
    assert.deepEqual(inventory.validationSchedule.commands, [
      fast,
      future,
      extra,
      ...(mode === "lazy" ? [] : [independent]),
    ]);
    assert.ok(
      inventory.requiredChecks.some(({ command }) => command === extra),
    );
    assert.ok(
      !inventory.requiredChecks.some(({ command }) => command === future),
    );
    assert.deepEqual(
      inventory.workerValidation.capabilityRequirements,
      original.workerValidation.capabilityRequirements,
    );
    for (const field of [
      "workerValidation",
      "reviewerValidation",
      "trustedValidation",
      "commitSizeAssessment",
      "bootstrapCorrections",
      "bootstrapProgress",
      "lazyCorrections",
      "additionalFixRounds",
    ])
      assert.deepEqual(state[field], original[field], field);
  });
}

test("rediscovery cannot drop commands, capability reports, infrastructure or unchanged future assignments", () => {
  const state = revised();
  for (const field of [
    "requiredChecks",
    "validationInfrastructure",
    "capabilityRequirements",
  ])
    assert.throws(() =>
      workFor(state, "worker", (discovery) => discovery[field].shift()),
    );
  const { scope, work } = workFor(state, "worker");
  const complete = finish(scope, work);
  const missingFuture = reload(complete);
  for (const accepted of missingFuture.accepted)
    accepted.assignments = accepted.assignments.filter(
      ({ checkId }) => checkId !== "C2",
    );
  // Keep the command assigned somewhere, but remove its unchanged later work.
  missingFuture.accepted[0].assignments.splice(1, 0, {
    checkId: "C2",
    steps: [2],
  });
  assert.throws(() =>
    acceptRevisionValidation(state, "worker", scope, missingFuture),
  );
  for (const patch of [
    { pendingCommit: { status: "consumed" } },
    { workflowState: "COMMIT" },
    {
      repositoryBaseline: {
        ...state.repositoryBaseline,
        contentFingerprint: hash("changed"),
      },
    },
    {
      trustedValidation: {
        commands: [{ command: fast, identity: hash("trusted") }],
      },
    },
  ])
    assert.throws(() =>
      acceptRevisionValidation(
        { ...state, ...patch },
        "worker",
        scope,
        complete,
      ),
    );
});

test("revision acceptance preserves confirmed amendment commands, applicability and infrastructure", () => {
  const amended = "node validation/amended.js";
  const state = revised("lazy", {
    validationAmendment: {
      step: 2,
      requiredChecks: [check("C1", amended)],
      confirmationFingerprint: hash("confirmed amendment"),
    },
    validationInfrastructure: ["package.json", "validation/amended.js"],
  });
  const prepare = (includeInfrastructure, includeCommand = true) => {
    const { scope, work } = workFor(state, "worker", (discovery) => {
      if (includeCommand) discovery.requiredChecks.push(check("C4", amended));
      if (includeInfrastructure)
        discovery.validationInfrastructure.push("validation/amended.js");
    });
    return { scope, work: finish(scope, work) };
  };
  assert.throws(() => prepare(false), {
    code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  });
  assert.throws(() => prepare(true, false), {
    code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  });
  const complete = prepare(true);
  const changedAmendment = {
    ...state,
    validationAmendment: {
      ...state.validationAmendment,
      confirmationFingerprint: hash("different amendment"),
    },
  };
  assert.throws(() =>
    normalizeBootstrapWork(
      complete.work,
      revisionBootstrapScope(changedAmendment, "worker", {
        inputFingerprint: fingerprint({}),
        infrastructureFingerprint: hash("worker"),
      }),
      0,
    ),
  );
  const wrongStep = reload(complete.work);
  for (const accepted of wrongStep.accepted)
    accepted.assignments = accepted.assignments
      .map((assignment) =>
        assignment.checkId === "C4"
          ? {
              ...assignment,
              steps: assignment.steps.filter((step) => step === 4),
            }
          : assignment,
      )
      .filter(({ steps }) => steps.length > 0);
  assert.throws(
    () => acceptRevisionValidation(state, "worker", complete.scope, wrongStep),
    { code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT" },
  );
  const accepted = reload(
    acceptRevisionValidation(state, "worker", complete.scope, complete.work),
  );
  assertRevisionValidation(accepted);
  const answer = hash("compatible parent amendment answer");
  const rebound = {
    ...accepted,
    effectiveValidation: [],
    replacementExecution: {
      ...accepted.replacementExecution,
      inputChanges: [
        {
          before: complete.scope.binding.inputFingerprint,
          after: answer,
          checkpoint: "IMPLEMENT",
          revision: accepted.effectiveValidation[0].revision,
          validation: accepted.effectiveValidation[0],
          reports: [],
        },
      ],
    },
  };
  const rediscovered = revisionBootstrapScope(rebound, "worker", {
    inputFingerprint: answer,
    infrastructureFingerprint: hash("worker"),
  });
  assert.deepEqual(rediscovered.inheritedAssignments.at(-1), {
    command: amended,
    steps: [2, 3],
  });
  assertRevisionValidation({
    ...accepted,
    validationAmendment: null,
    validationInfrastructure: [],
  });
  for (const omission of ["command", "applicability", "infrastructure"]) {
    const corrupt = reload(accepted);
    const record = corrupt.effectiveValidation[0];
    const inventory = record.worker.inventory;
    if (omission === "infrastructure") inventory.validationInfrastructure.pop();
    else if (omission === "applicability")
      inventory.requiredChecks.find(
        ({ command }) => command === amended,
      ).steps = [4];
    else inventory.requiredChecks.pop();
    record.schedule = deriveValidationSchedule(
      [inventory],
      4,
      record.schedule.effectivePlan,
    );
    assert.throws(() => assertRevisionValidation(corrupt), omission);
  }
});

test("clarification rediscovery keeps a later replacement amendment on its exact target", () => {
  let state = revised("lazy");
  const first = workFor(state, "worker");
  state = acceptRevisionValidation(
    state,
    "worker",
    first.scope,
    finish(first.scope, first.work),
  );
  const archived = state.effectiveValidation[0];
  const inputFingerprint = hash("compatible answer");
  const amended = "node validation/amended.js";
  state = {
    ...state,
    currentStep: 3,
    completedCommits: [...state.completedCommits, "b".repeat(40)],
    effectiveValidation: [],
    validationAmendment: {
      step: 3,
      requiredChecks: [check("C1", amended)],
      confirmationFingerprint: hash("later replacement amendment"),
    },
    validationInfrastructure: ["package.json", "validation/amended.js"],
    replacementExecution: {
      ...state.replacementExecution,
      inputChanges: [
        {
          before: first.scope.binding.inputFingerprint,
          after: inputFingerprint,
          checkpoint: "REVIEW",
          revision: archived.revision,
          validation: archived,
          reports: [],
        },
      ],
    },
  };
  const { scope, work } = workFor(
    state,
    "worker",
    (discovery) => {
      discovery.requiredChecks.push(check("C4", amended));
      discovery.validationInfrastructure.push("validation/amended.js");
    },
    inputFingerprint,
  );
  assert.deepEqual(
    scope.inheritedAssignments.find(({ command }) => command === amended).steps,
    [3],
  );
  let complete = work;
  while (complete.accepted.length < complete.units.length) {
    const result = batch(complete);
    result.assignments = result.assignments
      .map((entry) =>
        entry.checkId === "C4"
          ? { ...entry, steps: entry.steps.filter((step) => step === 3) }
          : entry,
      )
      .filter(({ steps }) => steps.length);
    complete = acceptBootstrapBatch(scope, complete, result);
  }
  const accepted = reload(
    acceptRevisionValidation(state, "worker", scope, complete),
  );
  assertRevisionValidation(accepted);
  assert.deepEqual(
    accepted.effectiveValidation[0].worker.inventory.requiredChecks.find(
      ({ command }) => command === amended,
    ).steps,
    [3],
  );
  const corrupt = reload(accepted);
  corrupt.effectiveValidation[0].worker.inventory.requiredChecks.find(
    ({ command }) => command === amended,
  ).steps = [2];
  assert.throws(() => assertRevisionValidation(corrupt));
});

test("an inherited assignment is rejected in its own unit while correction can still repair it", () => {
  const state = revised("lazy");
  const { scope, work } = workFor(state, "worker");
  const missing = batch(work);
  missing.assignments.find(({ checkId }) => checkId === "C1").steps = [2];
  missing.assignments.find(({ checkId }) => checkId === "C3").steps = [1, 2];
  assert.throws(() => acceptBootstrapBatch(scope, work, missing), {
    code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  });
  const correction = consumeBootstrapCorrection(scope, work);
  const accepted = acceptBootstrapBatch(scope, correction, batch(correction));
  assert.equal(accepted.correctionAttempt, 1);
  assert.equal(accepted.accepted.length, 1);
});

test("interrupted applicability retains exact revision, role, unit and consumed subdivision evidence", async () => {
  let state = revised("lazy");
  const { work } = workFor(state, "worker");
  const requestIds = [];
  const stop = new Error("interrupt after accepted unit");
  const fingerprintInfrastructure = async () => hash("worker");
  // The workflow uses its fixed limits; begin discovery there, then interrupt
  // after the first accepted unit instead of manufacturing a resumed partition.
  state = {
    ...state,
    bootstrapProgress: {
      ...state.bootstrapProgress,
      worker: { work: null, subdivisions: 1 },
    },
  };
  const run = () => ({ hashes: {} });
  const options = {
    role: "worker",
    checkpoint: "validation-migration",
    state: () => state,
    run,
    transition: async (next) => {
      state = reload(next);
    },
    correctionAttempt: () => 0,
    chargeCorrection: async () => assert.fail("no correction needed"),
    fingerprintInfrastructure,
    guidance: () => "Inspect read-only.",
    runContract: async (request) => {
      const prompt = request.buildPrompt("");
      if (prompt.includes("Applicability request (data):")) {
        const supplied = JSON.parse(
          /Applicability request \(data\):\n([^\n]+)/u.exec(prompt)[1],
        );
        requestIds.push(supplied.unitId);
        if (requestIds.length === 1) {
          // Force the same controlled output subdivision path as the workflow.
          state = { ...state, ...request.outputExhaustionPatch() };
          return null;
        }
        if (requestIds.length === 3) throw stop;
        return request.normalize({
          result: batch(state.bootstrapProgress.worker.work),
        });
      }
      return request.normalize({ result: work.discovery }).result;
    },
  };
  await assert.rejects(runBoundedBootstrap(options), (error) => error === stop);
  const saved = reload(state);
  assert.equal(saved.bootstrapProgress.worker.subdivisions, 2);
  assert.equal(saved.bootstrapProgress.worker.work.accepted.length, 1);
  const resumedIds = [];
  options.runContract = async (request) => {
    const supplied = JSON.parse(
      /Applicability request \(data\):\n([^\n]+)/u.exec(
        request.buildPrompt(""),
      )[1],
    );
    resumedIds.push(supplied.unitId);
    return request.normalize({
      result: batch(state.bootstrapProgress.worker.work),
    });
  };
  await runBoundedBootstrap(options);
  assert.equal(resumedIds[0], requestIds.at(-1));
  assert.deepEqual(
    state.bootstrapProgress.worker.work.accepted[0],
    saved.bootstrapProgress.worker.work.accepted[0],
  );
  assert.equal(state.bootstrapProgress.worker.subdivisions, 2);
  assert.ok(effectiveValidationInventory(state));
});

test("later splits reject stale schedules, completed work evidence and replacement ordinals", () => {
  let state = revised("lazy");
  const first = workFor(state, "worker");
  state = acceptRevisionValidation(
    state,
    "worker",
    first.scope,
    finish(first.scope, first.work),
  );
  const evidence = implementationEvidence(state);
  assert.equal(validImplementationEvidence(evidence, state), true);
  assert.equal(
    selectedPlanPosition(state).subject,
    "feat(reader): add the reader",
  );
  assert.equal(
    selectedPlanPosition(state).completed[0].head,
    state.completedCommits[0],
  );
  const shifted = reload(state);
  shifted.effectiveValidation[0].worker.binding = revisionBootstrapScope(
    state,
    "worker",
    { ...first.scope.binding, revision: 1, step: 3 },
  ).binding;
  assert.throws(() => assertRevisionValidation(shifted));
  const next = revise({
    ...state,
    currentStep: 3,
    completedCommits: [...state.completedCommits, "b".repeat(40)],
    repositoryBaseline: { ...state.repositoryBaseline, head: "b".repeat(40) },
  });
  assert.equal(effectiveValidationInventory(next), null);
  assert.equal(
    scheduledChecks(
      {
        ...next,
        validationSchedule: {
          commands: [fast],
          steps: [{ step: 3, commandIndexes: [0] }],
        },
      },
      3,
    ),
    null,
  );
  assert.equal(
    scheduledChecks(
      { ...next, validationSchedule: state.effectiveValidation[0].schedule },
      3,
    ),
    null,
  );
  assert.equal(
    validImplementationEvidence(
      { ...evidence, step: 3, head: "b".repeat(40) },
      next,
    ),
    false,
  );
  assert.deepEqual(effectiveStepCorrespondence(next, 1, 2), [
    { step: 1, steps: [1], affected: false },
    { step: 2, steps: [2], affected: false },
    { step: 3, steps: [3, 4], affected: true },
    { step: 4, steps: [5], affected: false },
  ]);
  assert.throws(() =>
    normalizeBootstrapWork(
      first.work,
      revisionBootstrapScope(next, "worker", {
        inputFingerprint: fingerprint({}),
        infrastructureFingerprint: hash("worker"),
      }),
      0,
    ),
  );
  assert.throws(() =>
    workFor(next, "worker", (discovery) => {
      discovery.requiredChecks = discovery.requiredChecks.filter(
        ({ command }) => command !== extra,
      );
    }),
  );
  const second = workFor(next, "worker");
  const accepted = acceptRevisionValidation(
    next,
    "worker",
    second.scope,
    finish(second.scope, second.work),
  );
  assert.equal(accepted.effectiveValidation.length, 2);
  assertRevisionValidation(reload(accepted));
  assert.ok(effectiveValidationInventory(accepted));
});

test("version-30 migration preserves base proof, consumed effects and allowances without fabricating revision validation", () => {
  const fresh = createPlanExecutionState({ settings: SETTINGS });
  const legacy = reload(fresh);
  delete legacy.effectiveValidation;
  const migrate = (pipelineState) =>
    planExecutionPipeline.migrations[30]({ pipelineState });
  assert.deepEqual(migrate(legacy), fresh);
  assert.doesNotThrow(() => normalizeExecutionState(migrate(legacy)));
  const run = {
    runId: "run-1",
    pipelineId: planExecutionPipeline.id,
    pipelineStateVersion: planExecutionPipeline.stateVersion,
    pipelineState: migrate(legacy),
    projectPath: "/project",
    taskPath: "/task",
    roles: Object.fromEntries(
      ["worker", "reviewer", "arbiter"].map((role) => [
        role,
        { backend: "codex" },
      ]),
    ),
    hashes: {},
    counters: {},
    sessionLineage: { source: null, children: [] },
    activeTurn: null,
    pause: null,
  };
  assert.doesNotThrow(() => planExecutionPipeline.workflow.validateRun(run));
  assert.throws(() =>
    planExecutionPipeline.workflow.validateRun({
      ...run,
      pipelineStateVersion: 30,
    }),
  );
  const state = revised();
  const old = {
    ...state,
    pendingCommit: { status: "consumed" },
    bootstrapProgress: {
      worker: { work: { legacy: true }, subdivisions: 2 },
      reviewer: { work: null, subdivisions: 3 },
    },
    stepImplementation: { accepted: true },
  };
  delete old.effectiveValidation;
  const migrated = migrate(old);
  assert.deepEqual(migrated.effectiveValidation, []);
  assert.equal(migrated.stepImplementation, null);
  assert.equal(migrated.bootstrapProgress.worker.work, null);
  for (const field of [
    "pendingCommit",
    "completedCommits",
    "commitSizeAssessment",
    "bootstrapCorrections",
    "lazyCorrections",
    "additionalFixRounds",
  ])
    assert.deepEqual(migrated[field], old[field]);
  assert.equal(migrated.bootstrapProgress.worker.subdivisions, 2);
  assert.equal(migrated.bootstrapProgress.reviewer.subdivisions, 3);
  const forged = {
    ...fresh,
    effectiveValidation: [
      { revision: 1, worker: null, reviewer: null, schedule: null },
    ],
  };
  assert.throws(() => normalizeExecutionState(forged));
});
