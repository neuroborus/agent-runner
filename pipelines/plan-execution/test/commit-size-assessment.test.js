import assert from "node:assert/strict";
import test from "node:test";

import {
  createPlanExecutionState,
  planExecutionPipeline,
} from "../src/index.js";
import { normalizePipelineState } from "../src/workflow-contract.js";
import { selectRoleSession } from "../src/mode-policy.js";
import {
  COMMIT_SIZE_DEFAULTS,
  assertCommitSizeAssessment,
  createCommitSizeAssessment,
  createCommitSizeBinding,
  normalizeCommitSizeDecision,
  recordCommitSizeDecision,
  reserveCommitSizeAssessment,
} from "../src/commit-size-assessment.js";

const settings = { ...COMMIT_SIZE_DEFAULTS, mode: "independent" };
const boundary = { reconciled: true, commitPending: false };
const eligible = () => ({ ...createCommitSizeAssessment(), eligible: true });
function binding(changedLines = 2701, overrides = {}) {
  return {
    ...createCommitSizeBinding(
      {
        originalStep: 1,
        planFingerprint: "a".repeat(64),
        inputFingerprint: "b".repeat(64),
        scopeFingerprint: "c".repeat(64),
        dependenciesFingerprint: "d".repeat(64),
        measurement: {
          baseHead: "a".repeat(40),
          contentFingerprint: "e".repeat(64),
          changedLines,
          binaryPaths: ["image.bin"],
          gitlinkPaths: [],
        },
      },
      settings,
    ),
    ...overrides,
  };
}
const reserve = (
  ledger,
  scope = binding(),
  selectedSettings = settings,
  options = boundary,
) => reserveCommitSizeAssessment(ledger, scope, selectedSettings, options);
function settle(request, scope, overrides = {}) {
  return recordCommitSizeDecision(
    request.ledger,
    scope,
    {
      bindingFingerprint: request.bindingFingerprint,
      decision: "ATOMIC",
      reason: "The format reader and writer must change together.",
      replacementPlan: "",
      ...overrides,
    },
    settings,
  );
}

test("only reconciled, eligible, unconsumed commit work strictly above the threshold reserves assessment", () => {
  assert.equal(reserve(eligible(), binding(2700)), null);
  const request = reserve(eligible());
  assert.equal(request.ledger.lineages[0].attempts.length, 1);
  assert.equal(request.ledger.lineages[0].attempts[0].binding.binaryFiles, 1);
  for (const options of [
    {},
    { ...boundary, reconciled: false },
    { ...boundary, commitPending: true },
    { ...boundary, reconciled: "true", commitPending: 0 },
    { ...boundary, planKind: "custom" },
  ]) {
    assert.equal(reserve(eligible(), binding(), settings, options), null);
  }
  assert.equal(reserve(createCommitSizeAssessment()), null);
});

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} size checkpoint preserves the continuing primary or isolates the configured Reviewer`, () => {
    const selected = { ...settings, mode };
    const request = reserve(eligible(), binding(), selected);
    assert.equal(request.access, "read-only");
    assert.equal(request.role, mode === "lazy" ? "worker" : "reviewer");
    const sessionOptions = {
      settings: selected,
      role: request.role,
      latestSession: { sessionId: "existing-role", contextKey: "candidate" },
      contextKey: request.checkpoint,
      sourceSession: "source",
      sourceForkConsumed: true,
      recovering: false,
      freshSession: false,
    };
    const session = selectRoleSession(sessionOptions);
    assert.deepEqual(
      session.session,
      mode === "lazy"
        ? { id: "existing-role", mode: "continue" }
        : { id: sessionOptions.sourceSession, mode: "fork" },
    );
    assert.equal(
      selectRoleSession({ ...sessionOptions, recovering: true }).session,
      undefined,
    );
    assert.equal(
      selectRoleSession({ ...sessionOptions, sourceSession: null }).session
        ?.mode,
      mode === "lazy" ? "continue" : undefined,
    );
  });
}

test("atomic exceptions survive content repairs and reassess only expanded scope or more than one further target", () => {
  const scope = binding();
  const accepted = settle(reserve(eligible(), scope), scope);
  for (const changedLines of [2701, 3000, 3601]) {
    assert.equal(
      reserve(
        accepted,
        binding(changedLines, { contentFingerprint: "f".repeat(64) }),
      ),
      null,
    );
  }
  assert.ok(reserve(accepted, binding(3602)));
  assert.ok(
    reserve(accepted, binding(2701, { scopeFingerprint: "f".repeat(64) })),
  );
  assert.ok(
    reserve(
      accepted,
      binding(2701, { dependenciesFingerprint: "f".repeat(64) }),
    ),
  );
  assert.throws(
    () =>
      reserve(accepted, binding(2701, { inputFingerprint: "f".repeat(64) })),
    /Frozen/u,
  );
});

test("restart reuses pending reservations and bounds all proposals across the original-step lineage", () => {
  let ledger = eligible();
  for (let index = 0; index < 3; index++) {
    const scope = binding(2701 + index * 901);
    const request = reserve(ledger, scope);
    const restored = JSON.parse(JSON.stringify(request.ledger));
    assert.deepEqual(reserve(restored, scope), request);
    assert.throws(
      () => reserve(restored, binding(scope.changedLines + 1)),
      /pending/u,
    );
    assert.throws(() => reserve(restored, binding(2700)), /pending/u);
    assert.throws(
      () =>
        reserve(restored, binding(2700, { inputFingerprint: "f".repeat(64) })),
      /Frozen/u,
    );
    ledger = settle(request, scope, {
      decision: "SPLIT",
      reason: "Introduce the reader before switching its caller.",
      replacementPlan:
        "## Commit 1: feat(reader): add the new reader\n\nImplement and test the reader.\n\n## Commit 2: feat(runtime): use the new reader\n\nSwitch and validate the caller.\n",
    });
    assert.deepEqual(
      settle(
        { ...request, ledger },
        scope,
        ledger.lineages[0].attempts.at(-1).result,
      ),
      ledger,
    );
  }
  assert.equal(ledger.lineages[0].attempts.length, 3);
  assert.equal(
    reserve(ledger, binding(9000, { baseHead: "b".repeat(40) })),
    null,
  );
  assert.equal(
    reserve(ledger, binding(5000, { scopeFingerprint: "f".repeat(64) })),
    null,
  );
});

test("authorized clarification bindings preserve historical assessments and the shared attempt limit", () => {
  const original = binding();
  let ledger = settle(reserve(eligible(), original), original);
  const inputChanges = [];
  for (const after of ["f".repeat(64), "a".repeat(64)]) {
    const before = ledger.lineages[0].attempts.at(-1).binding.inputFingerprint;
    inputChanges.push({ before, after });
    const scope = binding(2701, { inputFingerprint: after });
    const request = reserve(ledger, scope, settings, {
      ...boundary,
      inputChanges,
    });
    assert.ok(request);
    ledger = recordCommitSizeDecision(
      request.ledger,
      scope,
      {
        ...ledger.lineages[0].attempts[0].result,
        bindingFingerprint: request.bindingFingerprint,
      },
      settings,
      inputChanges,
    );
  }
  assert.equal(ledger.lineages[0].attempts.length, 3);
  assert.deepEqual(ledger.lineages[0].attempts[0].binding, original);
  assert.doesNotThrow(() =>
    assertCommitSizeAssessment(ledger, settings, inputChanges),
  );
  assert.throws(() => assertCommitSizeAssessment(ledger, settings));
  assert.equal(
    reserve(
      ledger,
      binding(5000, { inputFingerprint: "a".repeat(64) }),
      settings,
      { ...boundary, inputChanges },
    ),
    null,
  );
});

test("decision evidence is exact, fingerprint-bound and cannot authorize malformed replacements", () => {
  const scope = binding();
  const request = reserve(eligible(), scope);
  const result = settle(request, scope).lineages[0].attempts[0].result;
  for (const patch of [
    { bindingFingerprint: "f".repeat(64) },
    { decision: "APPROVED" },
    { reason: " " },
    { replacementPlan: "unexpected" },
    { commitAuthorized: true },
    {
      decision: "SPLIT",
      replacementPlan: "## Commit 1: invalid subject\n\nChange the reader.",
    },
    {
      decision: "SPLIT",
      replacementPlan:
        "## Commit 1: feat(reader): add a reader\n\nChange the reader.",
    },
  ])
    assert.throws(() =>
      normalizeCommitSizeDecision({ ...result, ...patch }, scope),
    );
  assert.throws(
    () => recordCommitSizeDecision(eligible(), scope, result, settings),
    /reservation/u,
  );
  assert.throws(
    () =>
      normalizeCommitSizeDecision(result, {
        ...scope,
        contentFingerprint: "f".repeat(64),
      }),
    /decision/u,
  );
});

test("new runs are eligible, intermediate migration stays disabled and resume retains resolved settings", () => {
  const resolved = Object.fromEntries(
    Object.entries(planExecutionPipeline.settings).map(([name, definition]) => [
      name,
      definition.defaultValue,
    ]),
  );
  const current = createPlanExecutionState({
    settings: {
      ...resolved,
      preferredCommitLineLimit: 700,
      commitSizeAssessmentMultiplier: 4,
    },
  });
  const restored = normalizePipelineState(JSON.parse(JSON.stringify(current)));
  assert.deepEqual(restored.settings, current.settings);
  assert.equal(restored.commitSizeAssessment.eligible, true);
  const legacy = { ...current };
  delete legacy.commitSizeAssessment;
  const {
    preferredCommitLineLimit: _target,
    commitSizeAssessmentMultiplier: _multiplier,
    ...oldSettings
  } = legacy.settings;
  legacy.settings = oldSettings;
  const migrated = planExecutionPipeline.migrations[28]({
    pipelineState: legacy,
  });
  assert.deepEqual(migrated.commitSizeAssessment, createCommitSizeAssessment());
  assert.equal(migrated.settings.preferredCommitLineLimit, 900);
  assert.equal(migrated.settings.commitSizeAssessmentMultiplier, 3);
  assert.doesNotThrow(() =>
    normalizePipelineState(
      planExecutionPipeline.migrations[38]({ pipelineState: migrated }),
    ),
  );
  assert.deepEqual(migrated, {
    ...legacy,
    settings: { ...COMMIT_SIZE_DEFAULTS, ...oldSettings },
    commitSizeAssessment: createCommitSizeAssessment(),
  });
  assert.equal(
    planExecutionPipeline.migrations[28]({
      pipelineState: {
        ...legacy,
        settings: null,
      },
    }).settings,
    null,
  );
  const active = {
    ...current,
    commitSizeAssessment: reserve(eligible()).ledger,
  };
  // A ledger bound to different frozen settings cannot be reused on resume.
  assert.throws(() => normalizePipelineState(active), /commit-size/u);
});

test("automatic splitting freezes creation eligibility and migrates saved eligibility unchanged", () => {
  const resolved = Object.fromEntries(
    Object.entries(planExecutionPipeline.settings).map(([name, definition]) => [
      name,
      definition.defaultValue,
    ]),
  );
  assert.equal(resolved.automaticCommitSplitting, true);
  const create = (overrides) =>
    createPlanExecutionState({ settings: { ...resolved, ...overrides } });
  const enabled = create({});
  const disabled = create({
    automaticCommitSplitting: false,
    commitSizeAssessmentMultiplier: 4,
  });
  assert.equal(enabled.commitSizeAssessment.eligible, true);
  assert.equal(disabled.commitSizeAssessment.eligible, false);
  for (const automaticCommitSplitting of [true, false])
    assert.equal(
      create({ planKind: "custom", automaticCommitSplitting })
        .commitSizeAssessment.eligible,
      false,
    );
  const restored = normalizePipelineState(JSON.parse(JSON.stringify(disabled)));
  assert.deepEqual(restored.settings, disabled.settings);
  assert.equal(restored.commitSizeAssessment.eligible, false);
  // Size settings stay validated while the switch is disabled.
  for (const overrides of [
    { commitSizeAssessmentMultiplier: 0 },
    { preferredCommitLineLimit: 1.5 },
    { preferredCommitLineLimit: Number.MAX_SAFE_INTEGER },
  ])
    assert.throws(
      () => create({ automaticCommitSplitting: false, ...overrides }),
      /commit-size threshold|preferredCommitLineLimit|commitSizeAssessmentMultiplier/u,
    );
  for (const automaticCommitSplitting of ["false", 0, 1, null, undefined])
    assert.throws(
      () => create({ automaticCommitSplitting }),
      /automaticCommitSplitting|settings are invalid/u,
    );
  const forged = [
    { ...disabled, commitSizeAssessment: eligible() },
    { ...enabled, commitSizeAssessment: createCommitSizeAssessment() },
    {
      ...create({ automaticCommitSplitting: false }),
      commitSizeAssessment: reserve(eligible()).ledger,
    },
  ];
  for (const state of forged)
    assert.throws(
      () => normalizePipelineState(state),
      /commit-size|splitting/iu,
    );

  const migrate = (pipelineState) =>
    planExecutionPipeline.migrations[38]({ pipelineState });
  const saved = (state, changes = {}) => {
    const { automaticCommitSplitting: _flag, ...settings } = state.settings;
    return { ...state, settings, ...changes };
  };
  // Saved eligibility, not the new default, decides the frozen switch.
  for (const [current, changes] of [
    [enabled, {}],
    [disabled, {}],
    [
      enabled,
      {
        pendingCommit: { status: "consumed" },
        completedCommits: ["a".repeat(40)],
        additionalFixRounds: 4,
      },
    ],
  ]) {
    const legacy = saved(current, changes);
    const migrated = migrate(legacy);
    assert.deepEqual(migrated, {
      ...legacy,
      settings: current.settings,
    });
  }
  assert.doesNotThrow(() => normalizePipelineState(migrate(saved(enabled))));
  assert.doesNotThrow(() => normalizePipelineState(migrate(saved(disabled))));
  const legacyNull = { ...disabled, settings: null };
  assert.deepEqual(migrate(legacyNull), legacyNull);
});
