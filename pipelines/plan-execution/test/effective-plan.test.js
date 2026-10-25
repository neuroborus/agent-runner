import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";

import {
  createPlanExecutionState,
  planExecutionPipeline,
} from "../src/index.js";
import { normalizePipelineState } from "../src/workflow-contract.js";
import {
  createCommitSizeBinding,
  reserveCommitSizeAssessment,
  recordCommitSizeDecision,
} from "../src/commit-size-assessment.js";
import {
  acceptEffectivePlanRevision,
  assertEffectivePlanRevisions,
  createEffectivePlanRevisions,
  effectivePlanRevisionCheckpoint,
  mapEffectivePlanStopTarget,
  proposeEffectivePlanRevision,
  recordEffectivePlanReview,
  EFFECTIVE_PLAN_REVIEW_SCHEMA,
} from "../src/effective-plan.js";
import {
  SETTINGS,
  bootstrapReady,
  clarificationReady,
  createFixture,
  matchesSchemaSubset,
  reconciliationResolved,
} from "./support/index.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const canonicalPlan =
  "## Commit 1: feat(core): add the baseline\n\nCreate the baseline.\n\n## Commit 2: feat(reader): add the complete reader\n\nImplement the reader and its caller.\n\n## Commit 3: feat(output): add reporting\n\nReport the reader results.\n";
const replacementPlan =
  "## Commit 1: feat(reader): add the reader\n\nImplement and test the reader.\n\n## Commit 2: feat(runtime): use the reader\n\nSwitch and validate the caller.\n";
const inspection = Object.fromEntries(
  [
    "inputFingerprint",
    "scopeFingerprint",
    "dependenciesFingerprint",
    "contentFingerprint",
  ].map((field) => [field, hash(field)]),
);
const boundary = { reconciled: true, inspection };
const reload = (state) => JSON.parse(JSON.stringify(state));

function assessed(
  mode = "combined",
  state = {},
  originalStep = state.currentStep ?? 2,
  changedLines = 3000,
) {
  let current = {
    ...createPlanExecutionState({ settings: { ...SETTINGS, mode } }),
    canonicalPlan,
    currentStep: 2,
    workflowState: "IMPLEMENT",
    repositoryBaseline: { head: "a".repeat(40) },
    completedCommits: ["a".repeat(40)],
    ...state,
  };
  const binding = createCommitSizeBinding(
    {
      originalStep,
      planFingerprint: hash(current.canonicalPlan),
      ...inspection,
      measurement: {
        baseHead: current.repositoryBaseline.head,
        contentFingerprint: inspection.contentFingerprint,
        changedLines,
        binaryPaths: [],
        gitlinkPaths: [],
      },
    },
    current.settings,
  );
  const request = reserveCommitSizeAssessment(
    { ...current.commitSizeAssessment, eligible: true },
    binding,
    current.settings,
    { reconciled: true, commitPending: false },
  );
  current.commitSizeAssessment = recordCommitSizeDecision(
    request.ledger,
    binding,
    {
      bindingFingerprint: request.bindingFingerprint,
      decision: "SPLIT",
      reason: "Introduce the reader before switching its caller.",
      replacementPlan,
    },
    current.settings,
  );
  return current;
}

function propose(state, owners = [], plan = replacementPlan) {
  return proposeEffectivePlanRevision(
    state,
    { replacementPlan: plan, findingOwners: owners },
    boundary,
  );
}

function report(state, overrides = {}) {
  return {
    fingerprint: state.effectivePlanRevisions.revisions.at(-1).fingerprint,
    status: "CLEAN",
    preserves: {
      requirements: true,
      dependencies: true,
      laterSteps: true,
      checks: true,
      findings: true,
    },
    reason: "The replacement preserves the agreed scope and every gate.",
    ...overrides,
  };
}

function review(state, overrides = {}) {
  const request = effectivePlanRevisionCheckpoint(state);
  const result = report(state, overrides);
  assert.equal(matchesSchemaSubset(EFFECTIVE_PLAN_REVIEW_SCHEMA, result), true);
  return recordEffectivePlanReview(state, request.checkpoint, result, boundary);
}

function approve(state) {
  while (effectivePlanRevisionCheckpoint(state)) state = review(state);
  return acceptEffectivePlanRevision(state, boundary);
}

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} accepts only its distinct plan gates, never an assessment or candidate approval`, () => {
    let state = propose(assessed(mode));
    assert.throws(
      () => acceptEffectivePlanRevision(state, boundary),
      /approval gate/u,
    );
    const expected =
      mode === "lazy"
        ? ["CHECK_AND_FIX", "CLEAN_CONFIRM"]
        : mode === "independent"
          ? ["REVIEW"]
          : ["CHECK_AND_FIX", "CLEAN_CONFIRM", "REVIEW"];
    for (const phase of expected) {
      const request = effectivePlanRevisionCheckpoint(state);
      assert.equal(request.phase, phase);
      assert.equal(request.role, phase === "REVIEW" ? "reviewer" : "worker");
      assert.equal(request.access, "read-only");
      assert.throws(
        () =>
          recordEffectivePlanReview(
            state,
            `effective-plan:1:COMMIT`,
            report(state),
            boundary,
          ),
        /checkpoint/u,
      );
      state = reload(review(state));
      assertEffectivePlanRevisions(state);
      if (phase !== expected.at(-1))
        assert.throws(
          () => acceptEffectivePlanRevision(state, boundary),
          /approval gate/u,
        );
    }
    const accepted = acceptEffectivePlanRevision(state, boundary);
    assert.equal(accepted.effectivePlanRevisions.revisions[0].accepted, true);
    assert.equal(effectivePlanRevisionCheckpoint(accepted), null);
    assert.equal(accepted.canonicalPlan, canonicalPlan);
    assert.equal(accepted.currentStep, 2);
    assert.deepEqual(accepted.completedCommits, state.completedCommits);
  });
}

test("flat revisions retain exact later meaning, contiguous mapping, completed provenance and logical stop targets", () => {
  const state = approve(propose(assessed()));
  const revision = state.effectivePlanRevisions.revisions[0];
  const steps = parseCommitPlan(revision.plan).steps;
  assert.deepEqual(
    steps.map(({ number }) => number),
    [1, 2, 3, 4],
  );
  assert.deepEqual(steps[0], parseCommitPlan(canonicalPlan).steps[0]);
  assert.deepEqual(steps[3], {
    ...parseCommitPlan(canonicalPlan).steps[2],
    number: 4,
  });
  assert.deepEqual(
    steps.slice(1, 3).map(({ subject }) => subject),
    parseCommitPlan(replacementPlan).steps.map(({ subject }) => subject),
  );
  assert.deepEqual(revision.mapping, [
    { step: 1, originalStep: 1, replacement: 1 },
    { step: 2, originalStep: 2, replacement: 1 },
    { step: 3, originalStep: 2, replacement: 2 },
    { step: 4, originalStep: 3, replacement: 1 },
  ]);
  assert.deepEqual(revision.completed, [
    {
      step: 1,
      originalStep: 1,
      replacement: 1,
      subject: steps[0].subject,
      head: "a".repeat(40),
    },
  ]);
  assert.deepEqual(mapEffectivePlanStopTarget(state, { step: 2 }), {
    originalStep: 2,
    steps: [2, 3],
  });
  assert.deepEqual(mapEffectivePlanStopTarget(state, { step: 3 }), {
    originalStep: 3,
    steps: [4],
  });
  assert.deepEqual(
    mapEffectivePlanStopTarget(state, { revision: 1, step: 3 }),
    { originalStep: 2, steps: [2, 3] },
  );
  assert.throws(
    () => mapEffectivePlanStopTarget(state, { revision: 7, step: 1 }),
    /target/u,
  );
  for (const mutate of [
    (record) => {
      record.plan += "extra scope";
    },
    (record) => {
      record.mapping[3].originalStep = 2;
    },
    (record) => {
      record.completed[0].head = "b".repeat(40);
    },
    (record) => {
      record.completed[0].subject = "feat(core): rewrite history";
    },
    (record) => {
      record.parent = 1;
    },
    (record) => {
      record.reports = [];
    },
  ]) {
    const changed = reload(state);
    mutate(changed.effectivePlanRevisions.revisions[0]);
    assert.throws(
      () => assertEffectivePlanRevisions(changed),
      /effective plan/u,
    );
  }
});

test("further refinement stays flat and retains committed replacement provenance and lineage allowances", () => {
  const accepted = approve(propose(assessed()));
  const next = assessed(
    "combined",
    {
      ...accepted,
      currentStep: 3,
      completedCommits: [...accepted.completedCommits, "b".repeat(40)],
      repositoryBaseline: { head: "b".repeat(40) },
    },
    2,
    4000,
  );
  const refined = approve(propose(next));
  const [first, second] = refined.effectivePlanRevisions.revisions;
  assert.deepEqual(first, accepted.effectivePlanRevisions.revisions[0]);
  assert.equal(second.parent, first.number);
  assert.equal(second.assessmentAttempt, 2);
  assert.equal(second.completed[1].subject, "feat(reader): add the reader");
  assert.equal(second.completed[1].head, "b".repeat(40));
  assert.deepEqual(
    second.mapping.map(({ originalStep }) => originalStep),
    [1, 2, 2, 2, 3],
  );
  assert.equal(
    parseCommitPlan(second.plan).steps[4].subject,
    "feat(output): add reporting",
  );
  assert.deepEqual(
    mapEffectivePlanStopTarget(refined, { revision: 1, step: 3 }),
    { originalStep: 2, steps: [2, 3, 4] },
  );
  assert.equal(refined.commitSizeAssessment.lineages[0].attempts.length, 2);
  assert.throws(
    () =>
      assertEffectivePlanRevisions({
        ...refined,
        completedCommits: ["c".repeat(40), "b".repeat(40)],
      }),
    /provenance/u,
  );
});

test("further splits preserve finding ownership outside the replaced step", () => {
  const finding = { id: "R1", description: "Retain the caller." };
  const owner = {
    id: finding.id,
    fingerprint: hash(JSON.stringify(finding)),
    steps: [3],
  };
  const accepted = approve(
    propose(assessed("combined", { findings: [finding] }), [owner]),
  );
  const next = assessed("combined", accepted, 2, 4000);
  assert.throws(() => propose(next, [{ ...owner, steps: [2] }]), /ownership/u);
  const refined = approve(propose(next, [{ ...owner, steps: [4] }]));
  assert.deepEqual(
    refined.effectivePlanRevisions.revisions.at(-1).findingOwners,
    [{ ...owner, steps: [4] }],
  );
});

test("persisted revisions cannot split an ancestor's completed prefix even with matching review fingerprints", () => {
  const accepted = approve(propose(assessed()));
  const rewound = approve(
    propose(assessed("combined", { currentStep: 1, completedCommits: [] })),
  );
  const altered = reload(accepted);
  altered.commitSizeAssessment.lineages.push(
    rewound.commitSizeAssessment.lineages[0],
  );
  const revision = rewound.effectivePlanRevisions.revisions[0];
  revision.number = 2;
  revision.parent = 1;
  revision.plan = serializeCommitPlan({
    steps: [
      ...parseCommitPlan(replacementPlan).steps,
      ...parseCommitPlan(
        accepted.effectivePlanRevisions.revisions[0].plan,
      ).steps.slice(1),
    ].map((step, index) => ({ ...step, number: index + 1 })),
  });
  revision.mapping = [1, 1, 2, 2, 3].map((originalStep, index, origins) => ({
    step: index + 1,
    originalStep,
    replacement: origins
      .slice(0, index + 1)
      .filter((step) => step === originalStep).length,
  }));
  const {
    fingerprint: _fingerprint,
    reports: _reports,
    accepted: _accepted,
    ...proposal
  } = revision;
  revision.fingerprint = hash(JSON.stringify(proposal));
  for (const result of revision.reports)
    result.fingerprint = revision.fingerprint;
  altered.effectivePlanRevisions.revisions.push(revision);
  assert.throws(() => assertEffectivePlanRevisions(altered), /provenance/u);
});

test("accepted revisions retain separately owned finding versions through reload and further refinement", () => {
  const previous = {
    id: "R1",
    file: "reader.js",
    problem: "The reader loses its result.",
    reason: "Later reporting requires that result.",
    suggestedAction: "Retain the reader result.",
  };
  const current = { ...previous, file: "caller.js" };
  const owners = [current, previous].map((finding, index) => ({
    id: finding.id,
    fingerprint: hash(JSON.stringify(finding)),
    steps: [index + 2],
  }));
  const accepted = reload(
    approve(
      propose(
        assessed("combined", {
          findings: [current],
          previousFindings: [previous],
        }),
        owners,
      ),
    ),
  );
  assert.deepEqual(accepted.effectivePlanRevisions.revisions[0].findings, [
    current,
    previous,
  ]);
  const next = assessed("combined", accepted, 2, 4000);
  assert.throws(() => propose(next, [owners[0]]), /ownership|findings/u);
  const retained = [owners[0], { ...owners[1], steps: [4] }];
  const refined = reload(approve(propose(next, retained)));
  assertEffectivePlanRevisions(refined);
  assert.deepEqual(refined.effectivePlanRevisions.revisions[1].findings, [
    current,
    previous,
  ]);
  // Persisted validation must reject omission even when the proposal and review
  // fingerprints have been recomputed to match the altered ownership set.
  const altered = reload(refined);
  const revision = altered.effectivePlanRevisions.revisions[1];
  revision.findings.pop();
  revision.findingOwners.pop();
  const {
    fingerprint: _fingerprint,
    reports: _reports,
    accepted: _accepted,
    ...proposal
  } = revision;
  revision.fingerprint = hash(JSON.stringify(proposal));
  for (const result of revision.reports)
    result.fingerprint = revision.fingerprint;
  assert.throws(() => assertEffectivePlanRevisions(altered), /ownership/u);
});

test("scope, dependency, later-step, check and finding rejections cannot approve a proposal", () => {
  for (const field of [
    "requirements",
    "dependencies",
    "laterSteps",
    "checks",
    "findings",
  ]) {
    const combined = field === "requirements";
    let pending = propose(assessed(combined ? "combined" : "independent"));
    if (combined) pending = review(review(pending));
    const preserves = { ...report(pending).preserves, [field]: false };
    assert.throws(() => review(pending, { preserves }), /semantic/u);
    const rejected = review(pending, {
      status: "FINDINGS",
      preserves,
      reason: `The proposed plan drops ${field}.`,
    });
    assert.equal(effectivePlanRevisionCheckpoint(rejected), null);
    assert.throws(
      () => acceptEffectivePlanRevision(rejected, boundary),
      /approval gate/u,
    );
    assert.deepEqual(propose(rejected), rejected);
    const corrected = propose(
      rejected,
      [],
      replacementPlan + "\nRetain all original acceptance conditions.\n",
    );
    assert.equal(corrected.effectivePlanRevisions.revisions.length, 2);
    assert.equal(
      corrected.effectivePlanRevisions.revisions[0].reports.at(-1).status,
      "FINDINGS",
    );
    assert.equal(
      corrected.effectivePlanRevisions.revisions[1].reports.length,
      0,
    );
    assert.equal(
      effectivePlanRevisionCheckpoint(corrected).phase,
      combined ? "CHECK_AND_FIX" : "REVIEW",
    );
    assert.deepEqual(
      corrected.commitSizeAssessment,
      pending.commitSizeAssessment,
    );
    assert.equal(
      approve(corrected).effectivePlanRevisions.revisions[1].accepted,
      true,
    );
  }
});

test("restored proposals reject live input, validation, finding and commit-effect drift", () => {
  const original = assessed();
  const pending = propose(original);
  for (const field of Object.keys(inspection))
    assert.throws(
      () =>
        acceptEffectivePlanRevision(pending, {
          ...boundary,
          inspection: { ...inspection, [field]: hash("changed") },
        }),
      /stale/u,
    );
  for (const patch of [
    { pendingCommit: { status: "consumed" } },
    { pendingCommit: { status: "authorized" } },
    { workflowState: "COMMIT" },
    { repositoryBaseline: { head: "b".repeat(40) } },
    { requiredChecks: [{ id: "C1", command: "node --version" }] },
    { trustedValidation: { commands: [] } },
    { validationInfrastructureFingerprint: hash("changed") },
    { findings: [{ id: "R1", description: "Retain the caller." }] },
  ])
    assert.throws(
      () => acceptEffectivePlanRevision({ ...pending, ...patch }, boundary),
      /effective plan/u,
    );
  assert.throws(
    () =>
      proposeEffectivePlanRevision(
        original,
        { replacementPlan, findingOwners: [] },
        {},
      ),
    /boundary/u,
  );
  assert.throws(() =>
    proposeEffectivePlanRevision(
      original,
      { replacementPlan: "## Commit 1: invalid subject", findingOwners: [] },
      boundary,
    ),
  );
  const finding = { id: "R1", description: "Retain the caller." };
  const withFinding = {
    ...original,
    findings: [finding],
    previousFindings: [finding],
  };
  assert.throws(() => propose(withFinding), /finding payloads/u);
  const owners = [
    { id: "R1", fingerprint: hash(JSON.stringify(finding)), steps: [3] },
  ];
  const owned = propose(withFinding, owners);
  assert.deepEqual(approve(owned).previousFindings, withFinding.findings);
  assert.throws(
    () => propose(withFinding, [{ ...owners[0], steps: [4] }]),
    /ownership/u,
  );
});

test("validation infrastructure path drift invalidates proposal review and acceptance", () => {
  const proposed = propose(
    assessed("combined", {
      validationInfrastructure: ["package.json"],
      validationInfrastructureFingerprint: hash("infrastructure"),
    }),
  );
  const converged = review(review(proposed));
  const approved = review(converged);
  assert.equal(
    acceptEffectivePlanRevision(approved, boundary).effectivePlanRevisions
      .revisions[0].accepted,
    true,
  );
  const drifted = (state) => ({
    ...reload(state),
    validationInfrastructure: ["other-checks.json"],
  });
  assert.throws(() => review(drifted(converged)), /stale/u);
  assert.throws(
    () => acceptEffectivePlanRevision(drifted(approved), boundary),
    /stale/u,
  );
});

test("unchanged plan text requires fresh reports when its complete proposal binding changes", () => {
  const pending = review(propose(assessed()));
  const original = reload(pending);
  for (const patch of [
    { requiredChecks: [{ id: "C1", command: "node --version" }] },
    { validationInfrastructure: ["checks.json"] },
    { additionalFixRounds: 1 },
    { reviewCorrection: { attempt: 1 } },
  ]) {
    const changed = { ...reload(pending), ...patch };
    const proposed = propose(changed);
    const [previous, current] = proposed.effectivePlanRevisions.revisions;
    assert.deepEqual(previous, original.effectivePlanRevisions.revisions[0]);
    assert.equal(current.replacementPlan, previous.replacementPlan);
    assert.notEqual(current.fingerprint, previous.fingerprint);
    assert.deepEqual(current.reports, []);
    assert.equal(
      effectivePlanRevisionCheckpoint(proposed).phase,
      "CHECK_AND_FIX",
    );
    assert.deepEqual(
      proposed.commitSizeAssessment,
      changed.commitSizeAssessment,
    );
    assert.equal(proposed.additionalFixRounds, changed.additionalFixRounds);
    assert.deepEqual(proposed.reviewCorrection, changed.reviewCorrection);
    assert.equal(propose(proposed), proposed);
  }
  assert.deepEqual(pending, original);
});

test("persisted proposal consumption cannot exceed its saved lineage allowance", () => {
  let exhausted = assessed("combined", {
    settings: { ...SETTINGS, mode: "combined", maxFixRoundsPerStep: 1 },
  });
  for (let index = 0; index < 4; index++)
    exhausted = propose(
      exhausted,
      [],
      replacementPlan + `\nCondition ${index}.\n`,
    );
  assert.doesNotThrow(() => assertEffectivePlanRevisions(reload(exhausted)));

  const altered = reload(exhausted);
  const extra = reload(altered.effectivePlanRevisions.revisions.at(-1));
  extra.number++;
  extra.replacementPlan += "\nAnother condition.\n";
  extra.plan = extra.plan.replace(
    "Condition 3.",
    "Condition 3.\n\nAnother condition.",
  );
  const {
    fingerprint: _fingerprint,
    reports: _reports,
    accepted: _accepted,
    ...proposal
  } = extra;
  extra.fingerprint = hash(JSON.stringify(proposal));
  altered.effectivePlanRevisions.revisions.push(extra);
  assert.throws(() => assertEffectivePlanRevisions(altered), /allowance/u);
});

test("historical proposal grants survive step advancement without renewing lineage consumption", () => {
  let state = assessed("combined", {
    settings: { ...SETTINGS, mode: "combined", maxFixRoundsPerStep: 1 },
    additionalFixRounds: 2,
  });
  for (let index = 0; index < 5; index++)
    state = propose(state, [], replacementPlan + `\nCondition ${index}.\n`);
  const accepted = approve(state);
  const next = assessed(
    "combined",
    {
      ...accepted,
      currentStep: 3,
      completedCommits: [...accepted.completedCommits, "b".repeat(40)],
      repositoryBaseline: { head: "b".repeat(40) },
      additionalFixRounds: 0,
    },
    2,
    4000,
  );
  assert.doesNotThrow(() => assertEffectivePlanRevisions(reload(next)));
  const last = propose(next);
  assert.equal(last.effectivePlanRevisions.revisions.length, 6);
  assert.equal(
    last.effectivePlanRevisions.revisions.at(-1).binding.additionalFixRounds,
    2,
  );
  assert.doesNotThrow(() => assertEffectivePlanRevisions(reload(last)));
  assert.throws(
    () => propose(last, [], replacementPlan + "\nAnother condition.\n"),
    /allowance/u,
  );
});

test("interrupted review and acceptance reuse durable receipts without renewing allowances or approvals", () => {
  const original = assessed();
  original.correctionHistory = [{ attempt: 2 }];
  original.lazyCorrections = [{ attempt: 1 }];
  original.additionalFixRounds = 2;
  original.finalizationRecovery = {
    ...original.finalizationRecovery,
    attempts: 2,
  };
  original.reviewCorrection = { attempt: 1 };
  original.confirmationCorrection = { attempt: 1 };
  original.candidateReviewResult = { status: "APPROVED" };
  original.candidateReviewedFingerprint = hash("old candidate");
  original.candidateConfirmationFingerprint = hash("old candidate");
  original.finalizationResult = { status: "PASS" };
  original.reviewResult = { status: "APPROVED" };
  original.stepImplementation = { contentFingerprint: hash("old candidate") };
  let pending = propose(original);
  const request = effectivePlanRevisionCheckpoint(pending);
  const result = report(pending);
  const reviewed = reload(
    recordEffectivePlanReview(pending, request.checkpoint, result, boundary),
  );
  assert.deepEqual(
    recordEffectivePlanReview(reviewed, request.checkpoint, result, boundary),
    reviewed,
  );
  assert.deepEqual(propose(reviewed), reviewed);
  assert.throws(
    () =>
      recordEffectivePlanReview(
        reviewed,
        request.checkpoint,
        { ...result, reason: "Different receipt." },
        boundary,
      ),
    /receipt/u,
  );
  pending = review(review(reviewed));
  const beforePublish = reload(pending);
  const accepted = reload(acceptEffectivePlanRevision(pending, boundary));
  assert.equal(
    beforePublish.effectivePlanRevisions.revisions[0].accepted,
    false,
  );
  assert.deepEqual(
    acceptEffectivePlanRevision(beforePublish, boundary),
    accepted,
  );
  assert.deepEqual(acceptEffectivePlanRevision(accepted, boundary), accepted);
  for (const field of [
    "commitSizeAssessment",
    "correctionHistory",
    "lazyCorrections",
    "additionalFixRounds",
    "finalizationRecovery",
  ])
    assert.deepEqual(accepted[field], original[field]);
  for (const field of [
    "candidateReviewResult",
    "candidateReviewedFingerprint",
    "candidateConfirmationFingerprint",
    "finalizationResult",
    "reviewResult",
    "stepImplementation",
    "reviewCorrection",
    "confirmationCorrection",
  ])
    assert.equal(accepted[field], null);
  assert.deepEqual(
    accepted.effectivePlanRevisions.revisions[0].binding.consumedCorrections,
    {
      review: true,
      confirmation: true,
    },
  );
  const reassessed = assessed("combined", accepted, 2, 4000);
  assert.deepEqual(
    propose(reassessed).effectivePlanRevisions.revisions.at(-1).binding
      .consumedCorrections,
    {
      review: true,
      confirmation: true,
    },
  );
  assert.throws(() => propose(accepted), /allowance/u);
  let exhausted = propose({
    ...original,
    settings: { ...original.settings, maxFixRoundsPerStep: 1 },
    additionalFixRounds: 0,
  });
  for (let index = 1; index < 4; index++)
    exhausted = propose(
      exhausted,
      [],
      replacementPlan + `\nRetain condition ${index}.\n`,
    );
  assert.throws(
    () =>
      propose(
        reload(exhausted),
        [],
        replacementPlan + "\nAnother correction.\n",
      ),
    /allowance/u,
  );
});

test("version-29 migration adds no revision authority and preserves consumed effects and saved accounting", () => {
  const current = createPlanExecutionState({ settings: SETTINGS });
  const legacy = reload(current);
  legacy.commitSizeAssessment.eligible = false;
  delete legacy.effectivePlanRevisions;
  const migrated = planExecutionPipeline.migrations[29]({
    pipelineState: legacy,
  });
  assert.deepEqual(migrated, {
    ...legacy,
    effectivePlanRevisions: createEffectivePlanRevisions(),
  });
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  const pending = {
    ...legacy,
    pendingCommit: { status: "consumed" },
    completedCommits: ["a".repeat(40)],
    additionalFixRounds: 4,
  };
  assert.deepEqual(
    planExecutionPipeline.migrations[29]({ pipelineState: pending }),
    { ...pending, effectivePlanRevisions: createEffectivePlanRevisions() },
  );
  assert.equal(migrated.commitSizeAssessment.eligible, false);
});

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} revision acceptance preserves valid persisted finding progress before materialization`, async (t) => {
    const stop = Object.assign(new Error("stop before writable work"), {
      code: "ERR_RUN_REVISION_CHANGED",
    });
    const fixture = await createFixture(t, {
      plan: canonicalPlan,
      mode,
      worker: [
        clarificationReady(),
        bootstrapReady("Worker", [1, 2, 3]),
        reconciliationResolved(),
      ],
      reviewer: [bootstrapReady("Reviewer", [1, 2, 3])],
      onTransition(run) {
        if (run.pipelineState.workflowState === "IMPLEMENT") throw stop;
      },
    });
    await assert.rejects(fixture.run(), (error) => error === stop);
    const baseline = fixture.currentRun.pipelineState;
    assert.deepEqual(
      baseline.effectivePlanRevisions,
      createEffectivePlanRevisions(),
    );
    const active = assessed(mode, {
      ...baseline,
      currentStep: 1,
      completedCommits: [],
    });
    const accepted = approve(propose(active));
    assert.doesNotThrow(() => normalizePipelineState(reload(accepted)));

    if (mode === "combined") {
      let exhausted = {
        ...active,
        settings: { ...active.settings, maxFixRoundsPerStep: 1 },
      };
      for (let index = 0; index < 4; index++)
        exhausted = propose(
          exhausted,
          [],
          replacementPlan + `\nCondition ${index}.\n`,
        );
      assert.doesNotThrow(() => normalizePipelineState(reload(exhausted)));
      const altered = propose(
        {
          ...exhausted,
          settings: { ...exhausted.settings, maxFixRoundsPerStep: 2 },
        },
        [],
        replacementPlan + "\nAnother condition.\n",
      );
      altered.settings = exhausted.settings;
      assert.throws(
        () => normalizePipelineState(reload(altered)),
        /Invalid persisted effective-plan revisions/u,
      );
    }

    const finding = {
      id: "R1",
      file: "source.js",
      problem: "The caller loses its result.",
      reason: "Later reporting requires that result.",
      suggestedAction: "Retain the result.",
    };
    const correcting = {
      ...active,
      workflowState:
        mode === "independent" ? "RESOLVE_FINDINGS" : "CHECK_AND_FIX",
      findings: [finding],
      pendingCorrection: true,
      availabilityCorrectionCharged: true,
    };
    assert.doesNotThrow(() => normalizePipelineState(correcting));
    const owned = approve(
      propose(correcting, [
        {
          id: finding.id,
          fingerprint: hash(JSON.stringify(finding)),
          steps: [1],
        },
      ]),
    );
    assert.doesNotThrow(() => normalizePipelineState(reload(owned)));
    assert.equal(owned.pendingCorrection, true);
    assert.deepEqual(owned.previousFindings, [finding]);

    const previousFindings = Array.from({ length: 32 }, (_, index) => ({
      ...finding,
      id: `R${index + 1}`,
    }));
    for (const count of [1, 32]) {
      const full = {
        ...correcting,
        previousFindings,
        findings: Array.from({ length: count }, (_, index) => ({
          ...finding,
          id: `R${index + 33}`,
        })),
        reviewReconsideration: mode === "combined" ? ["R1"] : [],
      };
      assert.doesNotThrow(() => normalizePipelineState(reload(full)));
      const allFindings = [...full.findings, ...previousFindings];
      const acceptedBatch = reload(
        approve(
          propose(
            full,
            allFindings.map((entry) => ({
              id: entry.id,
              fingerprint: hash(JSON.stringify(entry)),
              steps: [1],
            })),
          ),
        ),
      );
      assert.doesNotThrow(() => normalizePipelineState(acceptedBatch));
      assert.deepEqual(
        acceptedBatch.effectivePlanRevisions.revisions[0].findings,
        allFindings,
      );
      assert.deepEqual(acceptedBatch.previousFindings, full.findings);
    }

    const revisedFinding = { ...finding, file: "caller.js" };
    const versioned = { ...correcting, previousFindings: [revisedFinding] };
    assert.doesNotThrow(() => normalizePipelineState(reload(versioned)));
    const acceptedVersions = reload(
      approve(
        propose(
          versioned,
          [finding, revisedFinding].map((entry) => ({
            id: entry.id,
            fingerprint: hash(JSON.stringify(entry)),
            steps: [1],
          })),
        ),
      ),
    );
    assert.doesNotThrow(() => normalizePipelineState(acceptedVersions));
    assert.deepEqual(
      acceptedVersions.effectivePlanRevisions.revisions[0].findings,
      [finding, revisedFinding],
    );
  });
}
