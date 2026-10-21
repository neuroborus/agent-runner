import assert from "node:assert/strict";
import test from "node:test";
import { serializeCommitPlan } from "@agent-runner/commit-plan";
import {
  acceptBootstrapBatch,
  applicabilityRequest,
  assembleBootstrapInventory,
  consumeBootstrapCorrection,
  correctBootstrapCatalog,
  createBootstrapScope,
  createBootstrapWork,
  normalizeBootstrapWork,
  normalizeRepositoryDiscovery,
  subdivideBootstrapWork,
} from "../src/bootstrap-units.js";
import {
  APPLICABILITY_BATCH_SCHEMA,
  REPOSITORY_DISCOVERY_SCHEMA,
} from "../src/bootstrap-unit-schemas.js";
import { deriveValidationSchedule } from "../src/validation-schedule.js";
import { inspectionRequirements } from "../src/capability-requirements.js";
import { assertStrictSchema, matchesSchemaSubset } from "./support/index.js";

const hash = (character) => character.repeat(64);
const limits = { maxSteps: 2, maxBytes: 100_000 };
function scope(count = 4, overrides = {}) {
  return createBootstrapScope({
    canonicalPlan: serializeCommitPlan({
      steps: Array.from({ length: count }, (_, index) => ({
        number: index + 1,
        subject: `feat(sample): add part ${index + 1}`,
        body: "Inspect the relevant café module.",
      })),
    }),
    role: "worker",
    inputFingerprint: hash("a"),
    repositoryFingerprint: hash("b"),
    infrastructureFingerprint: hash("c"),
    position: { step: 1, subject: "feat(sample): add part 1" },
    ...overrides,
  });
}
function discovery() {
  return {
    stepAssessment: {
      step: 1,
      subject: "feat(sample): add part 1",
      disposition: "CURRENT",
      evidence: ["The selected step is pending."],
    },
    summary: "The validation scripts own the checks for these modules.",
    requiredChecks: [
      { id: "C1", command: "node validation/fast.js" },
      { id: "C2", command: "node validation/extended.js" },
    ],
    validationInfrastructure: ["package.json"],
    capabilityRequirements: [
      {
        command: "node validation/extended.js",
        commandIdentity: null,
        capabilities: {
          scratch: true,
          cache: false,
          sourceProjection: false,
          artifacts: [],
        },
        unsupported: [],
      },
    ],
    environmentBlockers: [
      {
        command: "node validation/extended.js",
        source: "agent-sandbox",
        evidence: ["Private scratch is required."],
      },
    ],
  };
}
function batch(work, ids = ["C1", "C2"], index = work.accepted.length) {
  const unit = work.units[index];
  return {
    status: "READY",
    unitId: unit.id,
    assignments: ids.map((checkId) => ({
      checkId,
      steps: Array.from(
        { length: unit.end - unit.start + 1 },
        (_, offset) => unit.start + offset,
      ),
    })),
    missingCommands: [],
    missingInfrastructure: [],
    capabilityRequirements: [],
    environmentBlockers: [],
  };
}
const reload = (work, context, attempt = work.correctionAttempt) =>
  normalizeBootstrapWork(JSON.parse(JSON.stringify(work)), context, attempt);

function rejectsChanges(value, changes, normalize) {
  for (const [path, replacement] of changes) {
    const invalid = structuredClone(value);
    const keys = path.split(".");
    const field = keys.pop();
    const parent = keys.reduce((current, key) => current[key], invalid);
    parent[field] = replacement;
    assert.throws(() => normalize(invalid), path);
  }
}

test("discovery is a strict catalog using the existing phase-safe inventory contracts", () => {
  const context = scope();
  const valid = discovery();
  assertStrictSchema(REPOSITORY_DISCOVERY_SCHEMA);
  assertStrictSchema(APPLICABILITY_BATCH_SCHEMA);
  assert.ok(
    matchesSchemaSubset(REPOSITORY_DISCOVERY_SCHEMA, { result: valid }),
  );
  assert.deepEqual(normalizeRepositoryDiscovery(valid, context), valid);
  assert.throws(() =>
    normalizeRepositoryDiscovery(
      valid,
      scope(4, {
        trustedCommands: [
          { command: "node validation/selected.js", identity: hash("d") },
        ],
      }),
    ),
  );
  rejectsChanges(
    valid,
    [
      ["requiredChecks.0.steps", [1]],
      ["requiredChecks.0.command", "git diff --cached --check"],
      ["requiredChecks.0.command", " node validation/fast.js"],
      ["validationInfrastructure", ["validation/../package.json"]],
      ["requiredChecks.1", valid.requiredChecks[0]],
      ["stepAssessment.disposition", "LATER_STEP"],
      ["stepAssessment.subject", "feat(sample): add another part"],
      ["capabilityRequirements.0.command", "node foreign.js"],
      ["environmentBlockers.0.source", "provider"],
      ["transcript", "Unaccepted output."],
    ],
    (value) => normalizeRepositoryDiscovery(value, context),
  );
});

test("only complete accepted coverage assembles the original inventory and applicability union", () => {
  const context = scope();
  let work = createBootstrapWork(context, discovery(), limits, 0);
  assert.throws(() => assembleBootstrapInventory(context, work));
  const first = batch(work, ["C1"]);
  assert.ok(matchesSchemaSubset(APPLICABILITY_BATCH_SCHEMA, { result: first }));
  work = acceptBootstrapBatch(context, work, first);
  assert.throws(() => assembleBootstrapInventory(context, work));
  work = acceptBootstrapBatch(context, reload(work, context), batch(work));
  const inventory = assembleBootstrapInventory(context, reload(work, context));
  assert.deepEqual(inventory.requiredChecks, [
    { ...discovery().requiredChecks[0], steps: [1, 2, 3, 4] },
    { ...discovery().requiredChecks[1], steps: [3, 4] },
  ]);
  assert.deepEqual(inspectionRequirements([inventory]), [
    {
      command: "node validation/extended.js",
      commandIdentity: null,
      unsupported: [],
      capabilities: { scratch: true },
    },
    { command: "node validation/extended.js" },
  ]);
  assert.deepEqual(
    deriveValidationSchedule(
      [
        inventory,
        {
          requiredChecks: [{ ...discovery().requiredChecks[1], steps: [1] }],
        },
      ],
      4,
    ).steps.map(({ commandIndexes }) => commandIndexes),
    [[0, 1], [0], [0, 1], [0, 1]],
  );
  assert.throws(() => acceptBootstrapBatch(context, work, first));
});

test("incomplete final applicability remains repairable within the shared role allowance", () => {
  for (const count of [1, 4]) {
    const context = scope(count);
    let work = createBootstrapWork(context, discovery(), limits, 0);
    while (work.accepted.length < work.units.length - 1)
      work = acceptBootstrapBatch(context, work, batch(work, ["C1"]));
    const prior = work.accepted;
    const incomplete = batch(work, ["C1"]);
    const rejectIncomplete = () =>
      assert.throws(() => acceptBootstrapBatch(context, work, incomplete), {
        code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      });
    rejectIncomplete();
    assert.equal(work.correctionAttempt, 0);
    work = reload(consumeBootstrapCorrection(context, work), context, 1);
    assert.deepEqual(work.accepted, prior);
    assert.equal(work.pendingCorrection, "unit");
    rejectIncomplete();
    assert.throws(() => consumeBootstrapCorrection(context, work));
    work = acceptBootstrapBatch(context, work, batch(work));
    assert.equal(work.correctionAttempt, 1);
    assert.equal(work.pendingCorrection, null);
    const inventory = assembleBootstrapInventory(
      context,
      reload(work, context),
    );
    assert.deepEqual(inventory.requiredChecks, [
      {
        ...discovery().requiredChecks[0],
        steps: Array.from({ length: count }, (_, index) => index + 1),
      },
      {
        ...discovery().requiredChecks[1],
        steps: incomplete.assignments[0].steps,
      },
    ]);
    assert.throws(() => consumeBootstrapCorrection(context, work));
  }
});

test("batch acceptance rejects missing, duplicate, reordered, foreign and cross-range assignments", () => {
  const context = scope();
  const work = createBootstrapWork(context, discovery(), limits, 0);
  const valid = batch(work);
  rejectsChanges(
    valid,
    [
      ["assignments", []],
      ["assignments", [...valid.assignments, valid.assignments[0]]],
      ["assignments", [...valid.assignments].reverse()],
      ["assignments.0.checkId", "C3"],
      ["assignments.0.steps", [2, 1]],
      ["assignments.0.steps", [1, 1]],
      ["assignments.0.steps", [3]],
      [
        "assignments",
        valid.assignments.map((entry) => ({ ...entry, steps: [2] })),
      ],
      ["unitId", work.units[1].id],
      ["status", "CATALOG_CORRECTION_REQUIRED"],
      ["missingCommands", ["node new.js"]],
      ["missingInfrastructure", undefined],
    ],
    (value) => acceptBootstrapBatch(context, work, value),
  );
  const partial = acceptBootstrapBatch(context, work, batch(work));
  assert.throws(() => acceptBootstrapBatch(context, partial, batch(work)));
  const unused = acceptBootstrapBatch(context, partial, batch(partial, ["C1"]));
  // A discovered requirement may not disappear merely because all units returned.
  const missing = {
    ...unused,
    accepted: unused.accepted.map((entry) => ({
      ...entry,
      assignments: entry.assignments.filter(({ checkId }) => checkId === "C1"),
    })),
  };
  assert.throws(() => assembleBootstrapInventory(context, missing));
});

test("reload rejects stale bindings, evidence order, gaps, overlaps and foreign role evidence", () => {
  const context = scope();
  let work = createBootstrapWork(context, discovery(), limits, 0);
  for (let index = 0; index < work.units.length; index++)
    work = acceptBootstrapBatch(context, work, batch(work));
  for (const overrides of [
    { role: "reviewer" },
    { inputFingerprint: hash("d") },
    { repositoryFingerprint: hash("d") },
    { infrastructureFingerprint: hash("d") },
    {
      trustedCommands: [
        { command: discovery().requiredChecks[0].command, identity: hash("d") },
      ],
    },
    {
      canonicalPlan: context.steps
        .map(
          (step) => `## Commit ${step.number}: ${step.subject}\nOther module.`,
        )
        .join("\n"),
    },
  ])
    assert.throws(() => reload(work, scope(4, overrides)));
  rejectsChanges(
    work,
    [
      ["binding.version", 2],
      ["discovery.summary", "Different repository evidence."],
      ["discovery.summary", ` ${work.discovery.summary} `],
      ["accepted", [...work.accepted].reverse()],
      ["accepted.1", work.accepted[0]],
      ["units", work.units.slice(1)],
      ["units.1.start", 2],
      ["units.0.end", 1],
      ["units.0.suppliedBytes", 1],
    ],
    (value) => reload(value, context),
  );
  const reviewer = createBootstrapWork(
    scope(4, { role: "reviewer" }),
    discovery(),
    limits,
    0,
  );
  const worker = createBootstrapWork(context, discovery(), limits, 0);
  assert.throws(() => acceptBootstrapBatch(context, worker, batch(reviewer)));
});

test("supplied UTF-8 bytes and deterministic subdivision stay bounded through single-step exhaustion", () => {
  const context = scope(5);
  const catalog = discovery();
  const request = applicabilityRequest(context, catalog, 1, 1);
  const bytes = Buffer.byteLength(JSON.stringify(request));
  assert.ok(bytes > JSON.stringify(request).length);
  let work = createBootstrapWork(
    context,
    catalog,
    { maxSteps: 5, maxBytes: 100_000 },
    1,
  );
  assert.equal(
    work.units[0].suppliedBytes,
    Buffer.byteLength(
      JSON.stringify(applicabilityRequest(context, catalog, 1, 5)),
    ),
  );
  const foreignPartition = createBootstrapWork(context, catalog, limits, 1);
  assert.throws(() =>
    reload({ ...work, units: foreignPartition.units }, context),
  );
  work = subdivideBootstrapWork(context, reload(work, context));
  assert.deepEqual(
    work.units.map(({ start, end }) => [start, end]),
    [
      [1, 3],
      [4, 5],
    ],
  );
  work = subdivideBootstrapWork(context, work);
  work = subdivideBootstrapWork(context, work);
  assert.equal(work.units[0].start, work.units[0].end);
  assert.equal(work.correctionAttempt, 1);
  assert.throws(() => subdivideBootstrapWork(context, work), {
    code: "ERR_BOOTSTRAP_UNIT_CAPACITY_EXHAUSTED",
  });
  assert.throws(() => consumeBootstrapCorrection(context, work));
  assert.throws(() => reload({ ...work, correctionAttempt: 0 }, context, 1));
  const exact = createBootstrapWork(
    scope(1),
    catalog,
    {
      maxSteps: 1,
      maxBytes: Buffer.byteLength(
        JSON.stringify(applicabilityRequest(scope(1), catalog, 1, 1)),
      ),
    },
    0,
  );
  assert.equal(exact.units.length, 1);
  assert.throws(
    () =>
      createBootstrapWork(
        scope(1),
        catalog,
        { ...exact.limits, maxBytes: exact.units[0].suppliedBytes - 1 },
        0,
      ),
    { code: "ERR_BOOTSTRAP_UNIT_CAPACITY_EXHAUSTED" },
  );
  const bounded = createBootstrapWork(
    context,
    catalog,
    { maxSteps: 5, maxBytes: bytes + 20 },
    0,
  );
  assert.ok(
    bounded.units.every(
      (unit) => unit.suppliedBytes <= bounded.limits.maxBytes,
    ),
  );
  assert.equal(bounded.units.length, 5);
  assert.deepEqual(
    bounded,
    createBootstrapWork(context, catalog, bounded.limits, 0),
  );
});

test("catalog correction consumes the shared role allowance before rediscovery and invalidates coverage", () => {
  const context = scope();
  let work = createBootstrapWork(context, discovery(), limits, 0);
  work = acceptBootstrapBatch(context, work, batch(work));
  const correction = {
    ...batch(work),
    status: "CATALOG_CORRECTION_REQUIRED",
    assignments: [],
    missingCommands: ["node validation/special.js"],
    missingInfrastructure: ["validation/config.json"],
    capabilityRequirements: [
      {
        ...discovery().capabilityRequirements[0],
        command: "node validation/special.js",
      },
    ],
    environmentBlockers: [
      {
        ...discovery().environmentBlockers[0],
        command: "node validation/special.js",
      },
    ],
  };
  assert.ok(
    matchesSchemaSubset(APPLICABILITY_BATCH_SCHEMA, { result: correction }),
  );
  work = acceptBootstrapBatch(context, work, correction);
  const replacement = discovery();
  replacement.requiredChecks.push({
    id: "C3",
    command: correction.missingCommands[0],
  });
  replacement.validationInfrastructure.push(
    correction.missingInfrastructure[0],
  );
  replacement.capabilityRequirements.push(...correction.capabilityRequirements);
  replacement.environmentBlockers.push(...correction.environmentBlockers);
  assert.throws(() => correctBootstrapCatalog(context, work, replacement));
  work = reload(consumeBootstrapCorrection(context, work), context, 1);
  assert.throws(() => correctBootstrapCatalog(context, work, discovery()));
  const stripped = structuredClone(replacement);
  stripped.capabilityRequirements = [];
  assert.throws(() => correctBootstrapCatalog(context, work, stripped));
  const originalUnit = work.units[0].id;
  work = correctBootstrapCatalog(context, work, replacement);
  assert.equal(work.accepted.length, 0);
  assert.notEqual(work.units[0].id, originalUnit);
  assert.equal(work.correctionAttempt, 1);
  assert.equal(work.pendingCorrection, null);
  assert.throws(() => acceptBootstrapBatch(context, work, correction));
  work = subdivideBootstrapWork(context, reload(work, context, 1));
  assert.throws(() => consumeBootstrapCorrection(context, work));
  while (work.accepted.length < work.units.length)
    work = acceptBootstrapBatch(context, work, batch(work, ["C1", "C2", "C3"]));
  const inventory = assembleBootstrapInventory(context, work);
  assert.equal(inventory.requiredChecks.length, 3);
  assert.deepEqual(
    inventory.capabilityRequirements,
    replacement.capabilityRequirements,
  );
  assert.deepEqual(
    inventory.environmentBlockers,
    replacement.environmentBlockers,
  );
});

test("invalid-unit correction and aggregate capacity cannot be renewed or truncated by batching", () => {
  const context = scope(1);
  let work = createBootstrapWork(context, discovery(), limits, 0);
  work = consumeBootstrapCorrection(context, work);
  work = acceptBootstrapBatch(context, reload(work, context, 1), batch(work));
  assert.equal(work.pendingCorrection, null);
  assert.equal(work.correctionAttempt, 1);
  let reports = createBootstrapWork(context, discovery(), limits, 0);
  const blocker = {
    command: discovery().requiredChecks[0].command,
    source: "runner",
    evidence: ["The required executable is unavailable."],
  };
  reports = acceptBootstrapBatch(context, reports, {
    ...batch(reports),
    status: "CATALOG_CORRECTION_REQUIRED",
    assignments: [],
    environmentBlockers: [blocker],
  });
  const replacement = discovery();
  replacement.environmentBlockers.push(blocker);
  reports = correctBootstrapCatalog(
    context,
    consumeBootstrapCorrection(context, reports),
    replacement,
  );
  assert.deepEqual(
    reports.discovery.environmentBlockers,
    replacement.environmentBlockers,
  );
  for (const field of ["requiredChecks", "validationInfrastructure"]) {
    const payload = discovery();
    payload[field] = Array.from({ length: 256 }, (_, index) =>
      field === "requiredChecks"
        ? { id: `C${index + 1}`, command: `node validation/check-${index}.js` }
        : `validation/config-${index}.json`,
    );
    if (field === "requiredChecks") {
      payload.capabilityRequirements = [];
      payload.environmentBlockers = [];
    }
    let full = createBootstrapWork(context, payload, limits, 0);
    const ready = acceptBootstrapBatch(
      context,
      full,
      batch(
        full,
        payload.requiredChecks.map(({ id }) => id),
      ),
    );
    assert.equal(assembleBootstrapInventory(context, ready)[field].length, 256);
    full = acceptBootstrapBatch(context, full, {
      ...batch(full),
      status: "CATALOG_CORRECTION_REQUIRED",
      assignments: [],
      missingCommands:
        field === "requiredChecks" ? ["node validation/extra.js"] : [],
      missingInfrastructure:
        field === "validationInfrastructure" ? ["validation/extra.json"] : [],
    });
    full = consumeBootstrapCorrection(context, full);
    payload[field].push(
      field === "requiredChecks"
        ? { id: "C257", command: "node validation/extra.js" }
        : "validation/extra.json",
    );
    assert.throws(() => correctBootstrapCatalog(context, full, payload));
    assert.throws(() => createBootstrapWork(context, payload, limits, 0));
  }
});
