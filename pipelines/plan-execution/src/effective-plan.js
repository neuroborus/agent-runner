import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import {
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";

import { MAX_SIZE_ASSESSMENTS } from "./commit-size-assessment.js";
import { clearedCandidateAndTerminalGate } from "./gate-evidence.js";
import { candidateCheckpoint, executionPolicy } from "./mode-policy.js";

const HASH = /^[a-f0-9]{64}$/u;
const HEAD = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const SEMANTICS = [
  "requirements",
  "dependencies",
  "laterSteps",
  "checks",
  "findings",
];
const INSPECTION = [
  "inputFingerprint",
  "scopeFingerprint",
  "dependenciesFingerprint",
  "contentFingerprint",
];
const exact = (value, fields) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === fields.length &&
  fields.every((field) => Object.hasOwn(value, field));
const hash = (value) =>
  createHash("sha256")
    .update(typeof value === "string" ? value : JSON.stringify(value))
    .digest("hex");
const fail = (message) => {
  throw new Error(`Invalid effective plan: ${message}.`);
};
const positive = (value) => Number.isSafeInteger(value) && value > 0;

export function createEffectivePlanRevisions() {
  return { revisions: [] };
}

export const EFFECTIVE_PLAN_REVIEW_SCHEMA = {
  type: "object",
  properties: {
    fingerprint: { type: "string", pattern: "^[a-f0-9]{64}$" },
    status: { type: "string", enum: ["CLEAN", "FINDINGS"] },
    preserves: {
      type: "object",
      properties: Object.fromEntries(
        SEMANTICS.map((field) => [field, { type: "boolean" }]),
      ),
      required: SEMANTICS,
      additionalProperties: false,
    },
    reason: { type: "string", minLength: 1, maxLength: 4000 },
  },
  required: ["fingerprint", "status", "preserves", "reason"],
  additionalProperties: false,
};

function initialAuthority(canonicalPlan) {
  return {
    number: 0,
    plan: canonicalPlan,
    mapping: parseCommitPlan(canonicalPlan).steps.map(({ number }) => ({
      step: number,
      originalStep: number,
      replacement: 1,
    })),
  };
}

function authority(state) {
  return (
    state.effectivePlanRevisions.revisions.findLast(
      (revision) => revision.accepted,
    ) ?? initialAuthority(state.canonicalPlan)
  );
}

function phases(mode) {
  const policy = executionPolicy({ mode });
  return [
    ...(policy.primaryConvergence ? ["CHECK_AND_FIX", "CLEAN_CONFIRM"] : []),
    ...(policy.independentReview ? ["REVIEW"] : []),
  ];
}

function clean(report) {
  return (
    report.status === "CLEAN" &&
    SEMANTICS.every((field) => report.preserves[field])
  );
}

function assertReport(report, fingerprint) {
  if (
    !exact(report, ["fingerprint", "status", "preserves", "reason"]) ||
    report.fingerprint !== fingerprint ||
    !["CLEAN", "FINDINGS"].includes(report.status) ||
    !exact(report.preserves, SEMANTICS) ||
    !SEMANTICS.every((field) => typeof report.preserves[field] === "boolean") ||
    typeof report.reason !== "string" ||
    !report.reason.trim() ||
    report.reason.length > 4000 ||
    /[\0\u2028\u2029]/u.test(report.reason) ||
    (report.status === "CLEAN" && !clean(report))
  )
    fail("semantic report");
}

function validationFingerprint(state) {
  return hash([
    state.requiredChecks,
    state.validationSchedule,
    state.validationAmendment,
    state.workerValidation,
    state.reviewerValidation,
    state.trustedValidation,
    state.validationInfrastructure,
    state.validationInfrastructureFingerprint,
    state.effectiveValidation,
  ]);
}

function findingReferences(findings) {
  return findings.map((finding) => ({
    id: finding.id,
    fingerprint: hash(finding),
  }));
}

function outstandingFindings(state) {
  const findings = new Map();
  for (const finding of [
    ...(authority(state).findings ?? []),
    ...state.findings,
    ...state.previousFindings,
    ...state.primaryFindings,
  ]) {
    const fingerprint = hash(finding);
    findings.set(`${finding.id}:${fingerprint}`, finding);
  }
  return [...findings.values()];
}

function consumedCorrections(state, originalStep) {
  // Scoped gate proof is retired on acceptance; the lineage still owns every
  // consumed allowance when replacement execution is eventually activated.
  const previous = state.effectivePlanRevisions.revisions.filter(
    (revision) => revision.originalStep === originalStep,
  );
  return Object.fromEntries(
    ["review", "confirmation"].map((phase) => [
      phase,
      state[`${phase}Correction`] !== null ||
        previous.some(
          (revision) => revision.binding.consumedCorrections[phase],
        ),
    ]),
  );
}

function lineageAdditionalFixRounds(state, originalStep) {
  return state.effectivePlanRevisions.revisions.reduce(
    (rounds, revision) =>
      revision.originalStep === originalStep
        ? Math.max(rounds, revision.binding.additionalFixRounds)
        : rounds,
    state.additionalFixRounds,
  );
}

// Splice only the active unfinished step. Later bodies and exact subjects are
// copied, never regenerated by a model; numbering is the sole later-step edit.
function deriveRevision(parent, step, replacementPlan) {
  const before = parseCommitPlan(parent.plan).steps;
  const replacements = parseCommitPlan(replacementPlan).steps;
  if (
    !positive(step) ||
    step > before.length ||
    replacements.length < 2 ||
    replacements.length > 16 ||
    replacements.some(({ body }) => !body.trim())
  )
    fail("replacement scope");
  const originalStep = parent.mapping[step - 1].originalStep;
  const plan = serializeCommitPlan({
    steps: [
      ...before.slice(0, step - 1),
      ...replacements,
      ...before.slice(step),
    ].map((entry, index) => ({ ...entry, number: index + 1 })),
  });
  if (plan.length > 100000) fail("plan size");
  const origins = [
    ...parent.mapping.slice(0, step - 1).map((entry) => entry.originalStep),
    ...replacements.map(() => originalStep),
    ...parent.mapping.slice(step).map((entry) => entry.originalStep),
  ];
  const counts = new Map();
  const mapping = origins.map((origin, index) => {
    const replacement = (counts.get(origin) ?? 0) + 1;
    counts.set(origin, replacement);
    return { step: index + 1, originalStep: origin, replacement };
  });
  return { originalStep, plan, mapping };
}

function provenance(parent, completedCommits) {
  const steps = parseCommitPlan(parent.plan).steps;
  return completedCommits.map((head, index) => ({
    ...parent.mapping[index],
    subject: steps[index]?.subject,
    head,
  }));
}

function revisionFingerprint(revision) {
  const {
    fingerprint: _fingerprint,
    reports: _reports,
    accepted: _accepted,
    ...proposal
  } = revision;
  return hash(proposal);
}

function assertOwners(owners, parent, step, count) {
  if (
    !Array.isArray(owners) ||
    owners.length > 512 ||
    new Set(owners.map((owner) => `${owner?.id}:${owner?.fingerprint}`))
      .size !== owners.length ||
    owners.some(
      (owner) =>
        !exact(owner, ["id", "fingerprint", "steps"]) ||
        typeof owner.id !== "string" ||
        !owner.id.trim() ||
        owner.id.length > 256 ||
        !HASH.test(owner.fingerprint) ||
        !Array.isArray(owner.steps) ||
        owner.steps.length === 0 ||
        new Set(owner.steps).size !== owner.steps.length ||
        owner.steps.some((target) => !positive(target)),
    )
  )
    fail("finding ownership");
  if (
    parent.findingOwners?.some(
      ({ id, fingerprint }) =>
        !owners.some(
          (owner) => owner.id === id && owner.fingerprint === fingerprint,
        ),
    )
  )
    fail("missing inherited finding ownership");
  for (const owner of owners) {
    const inherited = parent.findingOwners?.find(
      ({ id, fingerprint }) =>
        id === owner.id && fingerprint === owner.fingerprint,
    );
    const retained = (inherited?.steps ?? [])
      .filter((target) => target !== step)
      .map((target) => (target > step ? target + count - 1 : target));
    const replacements = owner.steps.filter(
      (target) => target >= step && target < step + count,
    );
    const replacesOwner =
      inherited === undefined || inherited.steps.includes(step);
    if (
      retained.some((target) => !owner.steps.includes(target)) ||
      owner.steps.some(
        (target) =>
          !retained.includes(target) && !replacements.includes(target),
      ) ||
      (replacesOwner ? replacements.length === 0 : replacements.length !== 0)
    )
      fail("finding ownership correspondence");
  }
}

// This is persisted pipeline authority, separate from the frozen canonical plan.
// Production routing remains inactive until validation and materialization land.
export function assertEffectivePlanRevisions(state) {
  const ledger = state.effectivePlanRevisions;
  if (!exact(ledger, ["revisions"]) || !Array.isArray(ledger.revisions))
    fail("ledger");
  if (ledger.revisions.length === 0) return;
  if (state.canonicalPlan === null || state.settings === null)
    fail("missing frozen plan");
  let parent = initialAuthority(state.canonicalPlan);
  const used = new Set();
  const proposalConsumption = new Map();
  for (const [index, revision] of ledger.revisions.entries()) {
    if (
      !exact(revision, [
        "number",
        "parent",
        "step",
        "originalStep",
        "assessmentAttempt",
        "binding",
        "completed",
        "findings",
        "findingOwners",
        "replacementPlan",
        "plan",
        "mapping",
        "fingerprint",
        "reports",
        "accepted",
      ]) ||
      revision.number !== index + 1 ||
      revision.parent !== parent.number ||
      typeof revision.accepted !== "boolean" ||
      !positive(revision.assessmentAttempt) ||
      typeof revision.replacementPlan !== "string" ||
      revision.replacementPlan.length > 100000
    )
      fail("revision chain");
    const derived = deriveRevision(
      parent,
      revision.step,
      revision.replacementPlan,
    );
    if (
      !["originalStep", "plan", "mapping"].every((field) =>
        isDeepStrictEqual(revision[field], derived[field]),
      )
    )
      fail("correspondence");
    const binding = revision.binding;
    const assessment = state.commitSizeAssessment.lineages.find(
      (lineage) => lineage.originalStep === revision.originalStep,
    )?.attempts[revision.assessmentAttempt - 1];
    if (
      !exact(binding, [
        "assessment",
        "validationFingerprint",
        "mode",
        "consumedCorrections",
        "additionalFixRounds",
      ]) ||
      !exact(binding.consumedCorrections, ["review", "confirmation"]) ||
      !Object.values(binding.consumedCorrections).every(
        (value) => typeof value === "boolean",
      ) ||
      ledger.revisions
        .slice(0, index)
        .some(
          (earlier) =>
            earlier.originalStep === revision.originalStep &&
            ["review", "confirmation"].some(
              (phase) =>
                earlier.binding.consumedCorrections[phase] &&
                !binding.consumedCorrections[phase],
            ),
        ) ||
      !HASH.test(binding.validationFingerprint) ||
      binding.mode !== state.settings.mode ||
      !assessment ||
      assessment.result?.decision !== "SPLIT" ||
      !isDeepStrictEqual(binding.assessment, assessment.binding) ||
      binding.assessment.planFingerprint !== hash(state.canonicalPlan) ||
      used.has(`${revision.originalStep}:${revision.assessmentAttempt}`)
    )
      fail("assessment authority");
    const consumed = proposalConsumption.get(revision.originalStep) ?? {
      count: 0,
      additionalFixRounds: 0,
    };
    const allowance =
      state.settings.maxFixRoundsPerStep +
      binding.additionalFixRounds +
      MAX_SIZE_ASSESSMENTS;
    if (
      !Number.isSafeInteger(binding.additionalFixRounds) ||
      binding.additionalFixRounds < consumed.additionalFixRounds ||
      !Number.isSafeInteger(allowance) ||
      consumed.count >= allowance ||
      (revision.step === state.currentStep &&
        binding.additionalFixRounds >
          Math.max(consumed.additionalFixRounds, state.additionalFixRounds))
    )
      fail("exhausted or invalid refinement allowance");
    proposalConsumption.set(revision.originalStep, {
      count: consumed.count + 1,
      additionalFixRounds: binding.additionalFixRounds,
    });
    if (
      !Array.isArray(revision.completed) ||
      revision.step < (parent.step ?? 1) ||
      revision.completed.length !== revision.step - 1 ||
      revision.completed.some((entry) => !HEAD.test(entry?.head)) ||
      !isDeepStrictEqual(
        revision.completed,
        provenance(
          parent,
          revision.completed.map((entry) => entry.head),
        ),
      ) ||
      !isDeepStrictEqual(
        revision.completed.map((entry) => entry.head),
        state.completedCommits.slice(0, revision.step - 1),
      )
    )
      fail("completed provenance");
    assertOwners(
      revision.findingOwners,
      parent,
      revision.step,
      parseCommitPlan(revision.replacementPlan).steps.length,
    );
    if (
      !Array.isArray(revision.findings) ||
      !isDeepStrictEqual(
        findingReferences(revision.findings),
        revision.findingOwners.map(({ id, fingerprint }) => ({
          id,
          fingerprint,
        })),
      )
    )
      fail("finding payloads");
    if (
      revision.fingerprint !== revisionFingerprint(revision) ||
      !Array.isArray(revision.reports)
    )
      fail("fingerprint");
    const expected = phases(binding.mode);
    if (revision.reports.length > expected.length) fail("review sequence");
    for (const [position, report] of revision.reports.entries()) {
      assertReport(report, revision.fingerprint);
      if (position > 0 && !clean(revision.reports[position - 1]))
        fail("review after findings");
    }
    if (revision.accepted) {
      if (
        revision.reports.length !== expected.length ||
        !revision.reports.every(clean)
      )
        fail("approval gate");
      used.add(`${revision.originalStep}:${revision.assessmentAttempt}`);
      parent = revision;
    }
  }
}

function assertBoundary(state, { reconciled = false, inspection } = {}) {
  assertEffectivePlanRevisions(state);
  if (
    reconciled !== true ||
    state.pendingCommit !== null ||
    state.workflowState === "COMMIT" ||
    !state.commitSizeAssessment.eligible ||
    state.currentStep === null ||
    !exact(inspection, INSPECTION) ||
    !INSPECTION.every((field) => HASH.test(inspection[field]))
  )
    fail("unreconciled or pending commit boundary");
  return inspection;
}

function assertCurrentProposal(state, boundary) {
  const inspection = assertBoundary(state, boundary);
  const revision = state.effectivePlanRevisions.revisions.at(-1);
  if (
    !revision ||
    revision.accepted ||
    revision.parent !== authority(state).number ||
    revision.step !== state.currentStep ||
    revision.binding.assessment.baseHead !== state.repositoryBaseline.head ||
    !isDeepStrictEqual(
      revision.completed.map((entry) => entry.head),
      state.completedCommits,
    ) ||
    !INSPECTION.every(
      (field) => revision.binding.assessment[field] === inspection[field],
    ) ||
    revision.binding.validationFingerprint !== validationFingerprint(state) ||
    revision.binding.additionalFixRounds !==
      lineageAdditionalFixRounds(state, revision.originalStep) ||
    !isDeepStrictEqual(
      revision.binding.consumedCorrections,
      consumedCorrections(state, revision.originalStep),
    ) ||
    !isDeepStrictEqual(
      revision.findingOwners.map(({ id, fingerprint }) => ({
        id,
        fingerprint,
      })),
      findingReferences(outstandingFindings(state)),
    )
  )
    fail("stale proposal scope, checks or findings");
  return revision;
}

function replaceLast(state, revision) {
  return {
    ...state,
    effectivePlanRevisions: {
      revisions: [
        ...state.effectivePlanRevisions.revisions.slice(0, -1),
        revision,
      ],
    },
  };
}

export function proposeEffectivePlanRevision(
  state,
  { replacementPlan, findingOwners },
  boundary,
) {
  const inspection = assertBoundary(state, boundary);
  const parent = authority(state);
  const step = state.currentStep;
  const derived = deriveRevision(parent, step, replacementPlan);
  const lineage = state.commitSizeAssessment.lineages.find(
    (entry) => entry.originalStep === derived.originalStep,
  );
  const assessment = lineage?.attempts.at(-1);
  if (
    !assessment ||
    assessment.result?.decision !== "SPLIT" ||
    assessment.binding.baseHead !== state.repositoryBaseline.head ||
    !INSPECTION.every(
      (field) => assessment.binding[field] === inspection[field],
    ) ||
    state.completedCommits.length !== step - 1
  )
    fail("missing current split assessment");
  // Draft corrections share the original lineage's finite correction allowance.
  const previous = state.effectivePlanRevisions.revisions.filter(
    (entry) => entry.originalStep === derived.originalStep,
  );
  const revision = {
    number: state.effectivePlanRevisions.revisions.length + 1,
    parent: parent.number,
    step,
    originalStep: derived.originalStep,
    assessmentAttempt: lineage.attempts.length,
    binding: {
      assessment: structuredClone(assessment.binding),
      validationFingerprint: validationFingerprint(state),
      mode: state.settings.mode,
      consumedCorrections: consumedCorrections(state, derived.originalStep),
      additionalFixRounds: lineageAdditionalFixRounds(
        state,
        derived.originalStep,
      ),
    },
    completed: provenance(parent, state.completedCommits),
    findings: structuredClone(outstandingFindings(state)),
    findingOwners: structuredClone(findingOwners),
    replacementPlan,
    ...derived,
    reports: [],
    accepted: false,
  };
  revision.fingerprint = revisionFingerprint(revision);
  const last = state.effectivePlanRevisions.revisions.at(-1);
  if (
    last &&
    !last.accepted &&
    revisionFingerprint({ ...revision, number: last.number }) ===
      last.fingerprint
  ) {
    assertCurrentProposal(state, boundary);
    return state;
  }
  if (
    previous.length >=
      state.settings.maxFixRoundsPerStep +
        revision.binding.additionalFixRounds +
        MAX_SIZE_ASSESSMENTS ||
    previous.some(
      (entry) =>
        entry.accepted && entry.assessmentAttempt === lineage.attempts.length,
    )
  )
    fail("exhausted refinement allowance");
  const next = {
    ...state,
    effectivePlanRevisions: {
      revisions: [...state.effectivePlanRevisions.revisions, revision],
    },
  };
  assertCurrentProposal(next, boundary);
  return next;
}

export function effectivePlanRevisionCheckpoint(state) {
  assertEffectivePlanRevisions(state);
  const revision = state.effectivePlanRevisions.revisions.at(-1);
  if (
    !revision ||
    revision.accepted ||
    revision.reports.some((report) => !clean(report))
  )
    return null;
  const phase = phases(revision.binding.mode)[revision.reports.length];
  if (!phase) return null;
  return {
    role: phase === "REVIEW" ? "reviewer" : "worker",
    access: "read-only",
    phase,
    checkpoint: `effective-plan:${revision.number}:${phase}`,
    fingerprint: revision.fingerprint,
  };
}

export function recordEffectivePlanReview(state, checkpoint, report, boundary) {
  const revision = assertCurrentProposal(state, boundary);
  assertReport(report, revision.fingerprint);
  // A lost publication receipt reuses the exact result, never advances a gate.
  const expected = phases(revision.binding.mode);
  const existing = expected.findIndex(
    (phase) => checkpoint === `effective-plan:${revision.number}:${phase}`,
  );
  if (existing >= 0 && existing < revision.reports.length) {
    if (!isDeepStrictEqual(revision.reports[existing], report))
      fail("changed review receipt");
    return state;
  }
  if (effectivePlanRevisionCheckpoint(state)?.checkpoint !== checkpoint)
    fail("review checkpoint");
  return replaceLast(state, {
    ...revision,
    reports: [...revision.reports, structuredClone(report)],
  });
}

// Publish this state through the existing leased write-ahead transition BEFORE
// any caller selects different boundaries. No file, index or effect is changed.
export function acceptEffectivePlanRevision(state, boundary) {
  const latest = state.effectivePlanRevisions.revisions.at(-1);
  if (latest?.accepted) {
    assertBoundary(state, boundary);
    return state;
  }
  const revision = assertCurrentProposal(state, boundary);
  if (
    revision.reports.length !== phases(revision.binding.mode).length ||
    !revision.reports.every(clean)
  )
    fail("approval gate");
  // Preserve blockers for replacement-specific rebinding. No content gate can
  // use this authority until validation and materialization are implemented.
  return {
    ...replaceLast(state, { ...revision, accepted: true }),
    ...clearedCandidateAndTerminalGate(),
    workflowState:
      state.findings.length > 0 ||
      state.primaryFindings.length > 0 ||
      state.pendingCorrection ||
      state.pendingDisputes.length > 0 ||
      state.reviewReconsideration.length > 0 ||
      state.finalizationRecovery.pending
        ? candidateCheckpoint(state.settings)
        : "IMPLEMENT",
    reviewerStep: null,
    implementationDirection: null,
    primaryFindings: state.primaryFindings,
    findings: [],
    // This legacy batch is bounded and ID-unique. Complete versioned payloads
    // live in revision authority, including blockers owned by future steps.
    previousFindings:
      state.findings.length > 0 ? state.findings : state.previousFindings,
    lazyCorrections: state.lazyCorrections,
    pendingFinalizationCorrection: null,
    finalizationRecovery: { ...state.finalizationRecovery, pending: false },
    stepImplementation: null,
    bootstrapProgress: Object.fromEntries(
      Object.entries(state.bootstrapProgress).map(([role, progress]) => [
        role,
        { ...progress, work: null },
      ]),
    ),
  };
}

// A deferred stop names logical original work, not an ordinal shifted by splits.
// The caller retains its original target receipt; this derived mapping grants
// no stop settlement until every returned replacement has a verified commit.
export function mapEffectivePlanStopTarget(state, { revision = 0, step }) {
  assertEffectivePlanRevisions(state);
  const source =
    revision === 0
      ? initialAuthority(state.canonicalPlan)
      : state.effectivePlanRevisions.revisions.find(
          (entry) => entry.number === revision && entry.accepted,
        );
  const originalStep = source?.mapping.find(
    (entry) => entry.step === step,
  )?.originalStep;
  if (!originalStep) fail("unknown deferred stop target");
  return {
    originalStep,
    steps: authority(state)
      .mapping.filter((entry) => entry.originalStep === originalStep)
      .map((entry) => entry.step),
  };
}

export const EFFECTIVE_PLAN_REVIEW_INSTRUCTIONS = `Review only this proposed flat effective commit plan against its frozen original scope, requirements, dependencies, checks, unresolved findings, completed provenance and later steps. Preserve exact valid subjects and independently valid intermediate states. Report CLEAN only if every preservation field is true; otherwise report FINDINGS with a concrete reason. Echo the supplied fingerprint. CHECK_AND_FIX returns plan findings, never edits project files. CLEAN_CONFIRM is a distinct read-only Worker turn; REVIEW is an independent Reviewer checkpoint. Size assessment is not approval. This review grants no implementation, materialization, finalization or commit authority.`;
