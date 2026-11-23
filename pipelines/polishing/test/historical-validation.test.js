import assert from "node:assert/strict";
import test from "node:test";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { polishingPipeline } from "../src/index.js";
import {
  normalizePipelineState,
  retainWorkReport,
  normalizePolishResult,
  normalizeCheckAndFixResult,
  normalizeResolutionResult,
  normalizeFinalizationResult,
} from "../src/workflow-contract.js";
import {
  CANDIDATE_REVIEW_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  REVIEW_SCHEMA,
  FINALIZATION_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  FINDING_RECOVERY_SCHEMA,
  DISPUTE_RECONSIDERATION_SCHEMA,
  FINDING_ARBITRATION_SCHEMA,
} from "../src/schemas.js";
import { HISTORICAL_VALIDATION_INSTRUCTIONS } from "../src/prompts.js";
import {
  createFixture,
  polishingCompleted,
  checkAndFix,
  candidateClean,
  cleanConfirmation,
  candidateApproved,
  finalizationPassed,
  finalizationFailed,
  finalizationBlocked,
  resolution,
  candidateFindings,
  reviewApproved,
  reviewFindings,
  bootstrapReady,
  clarificationReady,
  reconciliationResolved,
  reconciliationDisagreement,
  arbitrationResolved,
  migrateVersionOneState,
  versionOneState,
  trustedValidationSnapshot,
  reconsideration,
  findingArbitration,
  stagnationDirection,
  SETTINGS,
} from "./support/index.js";

for (const phase of ["ARBITRATE_BOOTSTRAP", "ARBITRATE_VALIDATION_MIGRATION"]) {
  test(`${phase} retains rationale-only history through publication loss and reconstruction`, async (t) => {
    const migration = phase === "ARBITRATE_VALIDATION_MIGRATION";
    const arbitrated = arbitrationResolved();
    arbitrated.rationale =
      "Arbitration-only disclosure: a reserved synthetic check ran early; no credit is granted and all FINALIZE checks remain pending.";
    const report = {
      phase,
      arbitration: {
        direction: arbitrated.direction,
        rationale: arbitrated.rationale,
      },
    };
    let laterRequests = 0;
    const fixture = await createFixture(t, {
      arbiter: [arbitrated],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        reviewApproved(),
        ...(migration
          ? [bootstrapReady("Reviewer"), candidateApproved(), reviewApproved()]
          : []),
      ],
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        migration ? reconciliationResolved() : reconciliationDisagreement(),
        polishingCompleted(),
        finalizationPassed(),
        ...(migration
          ? [
              bootstrapReady("Worker"),
              reconciliationDisagreement(),
              finalizationPassed(),
            ]
          : []),
      ],
      onRoleRun(_role, request) {
        if (
          !fixture.currentRun.pipelineState.workReports.some(
            (entry) => entry.phase === phase,
          )
        )
          return;
        for (const prompt of [request.prompt, request.recoveryPrompt])
          assert.ok(prompt.includes(arbitrated.rationale));
        laterRequests++;
      },
    });
    if (migration) {
      const done = await fixture.run();
      assert.equal(done.pipelineState.workflowState, "DONE");
      await fixture.persistPipelineState(
        migrateVersionOneState(
          versionOneState({ ...done.pipelineState, workflowState: "REVIEW" }),
        ),
      );
    }
    const transition = fixture.runtime.transition;
    const loss = new Error(
      "Synthetic arbitration publication acknowledgement loss",
    );
    let published = null;
    fixture.runtime.transition = async (...args) => {
      const next = await transition(...args);
      if (
        published === null &&
        next.pipelineState.workReports.some((entry) => entry.phase === phase)
      ) {
        published = structuredClone(next);
        throw loss;
      }
      return next;
    };
    await assert.rejects(fixture.run(), (cause) => cause === loss);
    assert.notEqual(published, null);
    assert.deepEqual(fixture.currentRun, published);
    assert.deepEqual(
      published.pipelineState.workReports.find(
        (entry) => entry.phase === phase,
      ),
      report,
    );
    assert.equal(published.pipelineState.finalizationResult, null);
    assert.equal(published.pipelineState.candidateReviewResult, null);
    await fixture.recover();
    await fixture.persistPipelineState(
      JSON.parse(JSON.stringify(published.pipelineState)),
    );
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.ok(laterRequests > 0);
    assert.equal(fixture.calls.arbiter.length, 1);
    assert.equal(
      fixture.calls.worker.filter(
        ({ schema }) => schema === FINALIZATION_SCHEMA,
      ).length,
      migration ? 2 : 1,
    );
    assert.deepEqual(
      done.pipelineState.requiredChecks,
      bootstrapReady("Worker").requiredChecks,
    );
    assert.deepEqual(
      normalizePipelineState(
        JSON.parse(JSON.stringify(done.pipelineState)),
      ).workReports.find((entry) => entry.phase === phase),
      report,
    );
  });
}

for (const mode of ["independent", "combined"]) {
  for (const kind of mode === "independent"
    ? ["finding", "stagnation", "bootstrap"]
    : ["finding", "stagnation"]) {
    test(`${mode} ${kind} product decision retains rationale-only history after answer and reconstruction`, async (t) => {
      const arbitrated =
        kind === "bootstrap"
          ? {
              ...arbitrationResolved(),
              direction: "PRODUCT_DECISION_REQUIRED",
              summary: "",
            }
          : kind === "finding"
            ? findingArbitration("REQUIREMENT_AMBIGUOUS")
            : stagnationDirection("PRODUCT_DECISION_REQUIRED");
      Object.assign(arbitrated, {
        rationale:
          "Rationale-only disclosure: a reserved synthetic check ran early, without credit; all FINALIZE checks remain pending.",
        question: "Should behavior use variant A or variant B?",
        options: ["Variant A", "Variant B"],
        whyBlocked: "Both product variants satisfy the current requirements.",
        evidence: ["The repository does not select a variant."],
      });
      const phase =
        kind === "bootstrap"
          ? "ARBITRATE_BOOTSTRAP"
          : kind === "finding"
            ? "ARBITRATE_FINDING"
            : "ARBITRATE_STAGNATION";
      const report = {
        phase,
        arbitration: {
          ...(kind === "finding" ? { findingId: "R1" } : {}),
          direction: arbitrated.direction,
          rationale: arbitrated.rationale,
        },
      };
      const converge =
        mode === "combined" ? [checkAndFix(), candidateClean()] : [];
      let laterRequests = 0;
      const fixture = await createFixture(t, {
        mode,
        modeSettings: { maxDisputesPerFinding: 1, stagnationWindowRounds: 1 },
        arbiter: [arbitrated],
        reviewer: [
          bootstrapReady("Reviewer"),
          ...(kind === "bootstrap"
            ? []
            : [
                candidateFindings("R1"),
                kind === "finding"
                  ? reconsideration("UPHOLD", "R1")
                  : candidateFindings("R2"),
              ]),
          bootstrapReady("Reviewer"),
          candidateApproved(),
          reviewApproved(),
        ],
        worker: [
          clarificationReady(),
          bootstrapReady("Worker"),
          ...(kind === "bootstrap"
            ? [reconciliationDisagreement()]
            : [
                reconciliationResolved(),
                polishingCompleted(),
                ...converge,
                resolution(kind === "finding" ? "DISPUTE" : "FIX", "R1"),
                ...(kind === "stagnation" ? converge : []),
              ]),
          bootstrapReady("Worker"),
          reconciliationResolved(),
          polishingCompleted(),
          ...converge,
          finalizationPassed(),
        ],
        onRoleRun(_role, request) {
          if (
            !fixture.currentRun.pipelineState.workReports.some(
              (entry) => entry.phase === phase,
            )
          )
            return;
          for (const prompt of [request.prompt, request.recoveryPrompt])
            assert.ok(prompt.includes(arbitrated.rationale));
          laterRequests++;
        },
      });
      const transition = fixture.runtime.transition;
      const loss = new Error(
        "Synthetic product-decision publication acknowledgement loss",
      );
      let published = null;
      fixture.runtime.transition = async (...args) => {
        const next = await transition(...args);
        if (
          published === null &&
          next.pause?.reason === "product_decision_required"
        ) {
          published = structuredClone(next);
          throw loss;
        }
        return next;
      };
      await assert.rejects(fixture.run(), (cause) => cause === loss);
      assert.notEqual(published, null);
      assert.deepEqual(fixture.currentRun, published);
      assert.deepEqual(
        published.pipelineState.workReports.find(
          (entry) => entry.phase === phase,
        ),
        report,
      );
      assert.equal(published.pipelineState.finalizationResult, null);
      assert.equal(published.pipelineState.candidateReviewResult, null);
      assert.deepEqual(published.pipelineState.pendingDisputes, []);
      assert.deepEqual(published.pipelineState.findingArbitrations, []);
      const consumed = published.counters;
      fixture.runtime.transition = transition;
      await fixture.persistPipelineState(
        JSON.parse(JSON.stringify(published.pipelineState)),
      );
      await fixture.recover();
      const path = published.pipelineState.clarificationPath;
      await writeFile(path, `${await readFile(path, "utf8")}Behavior A.\n`);
      const done = await fixture.run();
      assert.equal(
        done.pipelineState.workflowState,
        "DONE",
        JSON.stringify(done.pause),
      );
      assert.ok(laterRequests > 0);
      assert.equal(fixture.calls.arbiter.length, 1);
      assert.equal(done.counters.productDecisions, 1);
      assert.ok(done.counters.fixRounds >= consumed.fixRounds);
      assert.deepEqual(done.pipelineState.findings, []);
      assert.equal(
        fixture.calls.worker.filter(
          ({ schema }) => schema === FINALIZATION_SCHEMA,
        ).length,
        1,
      );
      assert.deepEqual(
        done.pipelineState.requiredChecks,
        bootstrapReady("Worker").requiredChecks,
      );
      const restored = normalizePipelineState(
        JSON.parse(JSON.stringify(done.pipelineState)),
      );
      assert.deepEqual(
        restored.workReports.find((entry) => entry.phase === phase),
        report,
      );
      assert.throws(
        () =>
          normalizePipelineState({
            ...restored,
            ...(kind === "finding"
              ? { findingArbitrations: [report.arbitration] }
              : { stagnationDirection: report.arbitration }),
          }),
        { code: "ERR_INVALID_POLISHING_STATE" },
      );
    });
  }
}

for (const mode of ["independent", "combined"]) {
  for (const direction of ["WITHDRAW", "WORKER_CORRECT", "REVIEWER_CORRECT"]) {
    test(`${mode} retains ${direction} disclosures through containment and reconstruction`, async (t) => {
      const reconsidered = reconsideration(
        direction === "WITHDRAW" ? "WITHDRAW" : "UPHOLD",
        "R1",
      );
      reconsidered.decisions[0].reason =
        "Reconsideration-only disclosure: a reserved synthetic check ran early.";
      reconsidered.decisions[0].evidence = [
        "That historical execution grants no credit; FINALIZE retains the complete pending inventory.",
      ];
      const arbitrated = findingArbitration(
        direction === "WITHDRAW" ? "WORKER_CORRECT" : direction,
      );
      arbitrated.rationale =
        "Arbitration-only disclosure: a separate reserved synthetic check ran early, without acceptance credit.";
      const converge =
        mode === "combined" ? [checkAndFix(), candidateClean()] : [];
      let accepted = false;
      let laterRequests = 0;
      const fixture = await createFixture(t, {
        mode,
        modeSettings: { maxDisputesPerFinding: 1 },
        worker: [
          clarificationReady(),
          bootstrapReady("Worker"),
          reconciliationResolved(),
          polishingCompleted(),
          ...converge,
          resolution("DISPUTE", "R1"),
          ...(direction === "REVIEWER_CORRECT"
            ? [resolution("FIX", "R1")]
            : []),
          ...converge,
          finalizationPassed(),
        ],
        reviewer: [
          bootstrapReady("Reviewer"),
          candidateFindings("R1"),
          reconsidered,
          candidateApproved(),
          reviewApproved(),
        ],
        arbiter: direction === "WITHDRAW" ? [] : [arbitrated],
        onRoleRun(_role, request) {
          if (
            request.schema ===
            (direction === "WITHDRAW"
              ? DISPUTE_RECONSIDERATION_SCHEMA
              : FINDING_ARBITRATION_SCHEMA)
          ) {
            accepted = true;
            return;
          }
          if (!accepted) return;
          for (const prompt of [request.prompt, request.recoveryPrompt]) {
            assert.ok(prompt.includes(reconsidered.decisions[0].reason));
            assert.ok(prompt.includes(reconsidered.decisions[0].evidence[0]));
            if (direction !== "WITHDRAW")
              assert.ok(prompt.includes(arbitrated.rationale));
          }
          laterRequests++;
        },
      });
      if (mode === "combined" && direction === "WORKER_CORRECT") {
        for (const phase of ["RECONSIDER_DISPUTES", "ARBITRATE_FINDING"]) {
          const transition = fixture.runtime.transition;
          const loss = new Error(
            "Synthetic adjudication publication acknowledgement loss",
          );
          let lost = false;
          fixture.runtime.transition = async (...args) => {
            const next = await transition(...args);
            if (
              !lost &&
              next.pipelineState.workReports.some(
                (report) => report.phase === phase,
              )
            ) {
              lost = true;
              throw loss;
            }
            return next;
          };
          await assert.rejects(fixture.run(), (cause) => cause === loss);
          fixture.runtime.transition = transition;
          await fixture.persistPipelineState(
            JSON.parse(JSON.stringify(fixture.currentRun.pipelineState)),
          );
          await fixture.recover();
        }
      }
      const done = await fixture.run();
      assert.equal(
        done.pipelineState.workflowState,
        "DONE",
        JSON.stringify(done.pause),
      );
      assert.ok(laterRequests > 0);
      assert.deepEqual(done.pipelineState.findings, []);
      assert.equal(
        fixture.calls.reviewer.filter(
          ({ schema }) => schema === DISPUTE_RECONSIDERATION_SCHEMA,
        ).length,
        1,
      );
      assert.equal(
        fixture.calls.arbiter.length,
        direction === "WITHDRAW" ? 0 : 1,
      );
      assert.equal(
        fixture.calls.worker.filter(
          ({ schema }) => schema === FINALIZATION_SCHEMA,
        ).length,
        1,
      );
      assert.deepEqual(
        done.pipelineState.requiredChecks,
        bootstrapReady("Worker").requiredChecks,
      );
      const history = JSON.parse(JSON.stringify(done.pipelineState));
      assert.deepEqual(
        normalizePipelineState(history).workReports,
        done.pipelineState.workReports,
      );
    });
  }
}

test("stagnation-only rationale remains historical context after content repairs", async (t) => {
  const arbitrated = stagnationDirection();
  arbitrated.rationale =
    "Stagnation-only disclosure: a reserved synthetic check ran early; it grants no credit and FINALIZE retains all checks.";
  let accepted = false;
  let laterRequests = 0;
  let repairs = 0;
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, stagnationWindowRounds: 1 },
    arbiter: [arbitrated],
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateFindings("R1"),
      candidateFindings("R2"),
      candidateApproved(),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      resolution("FIX", "R1"),
      resolution("FIX", "R2"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (role === "arbiter") {
        accepted = true;
        return;
      }
      if (request.schema === FINDING_RESOLUTION_SCHEMA)
        await writeFile(
          join(request.cwd, "safe-repair.txt"),
          `Safe repair ${++repairs}\n`,
        );
      if (!accepted) return;
      for (const prompt of [request.prompt, request.recoveryPrompt])
        assert.ok(prompt.includes(arbitrated.rationale));
      laterRequests++;
    },
  });
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.ok(laterRequests > 0);
  assert.deepEqual(done.pipelineState.findings, []);
  assert.deepEqual(
    done.pipelineState.requiredChecks,
    bootstrapReady("Worker").requiredChecks,
  );
});

test("adjudication history is strict normalized context without gate authority", () => {
  const decision = {
    findingId: "R1",
    direction: "WITHDRAW",
    reason: "Containment preserves the disclosure.",
    evidence: [],
  };
  const report = { phase: "RECONSIDER_DISPUTES", decisions: [decision] };
  assert.deepEqual(retainWorkReport([], report), [report]);
  for (const decisions of [
    [],
    [decision, decision],
    [{ ...decision, findingId: "F1" }],
    [{ ...decision, findingId: ["R1"] }],
    [{ ...decision, direction: "CLEAN" }],
    [{ ...decision, reason: "" }],
    [{ ...decision, reason: " Noncanonical reason. " }],
    [{ ...decision, evidence: ["x".repeat(4001)] }],
    [{ ...decision, evidence: [" Noncanonical evidence. "] }],
    [{ ...decision, fingerprint: "untrusted" }],
  ])
    assert.throws(() => retainWorkReport([], { ...report, decisions }), {
      code: "ERR_INVALID_POLISHING_STATE",
    });
  for (const [phase, arbitration] of [
    ...["ARBITRATE_BOOTSTRAP", "ARBITRATE_VALIDATION_MIGRATION"].flatMap(
      (phase) =>
        [
          "USE_WORKER",
          "USE_REVIEWER",
          "SYNTHESIZE",
          ...(phase === "ARBITRATE_BOOTSTRAP"
            ? ["PRODUCT_DECISION_REQUIRED"]
            : []),
        ].map((direction) => [
          phase,
          { direction, rationale: "Historical disclosure remains preserved." },
        ]),
    ),
    [
      "ARBITRATE_FINDING",
      {
        findingId: "R1",
        direction: "WORKER_CORRECT",
        rationale: "Historical disclosure remains preserved.",
      },
    ],
    [
      "ARBITRATE_FINDING",
      {
        findingId: "R1",
        direction: "REQUIREMENT_AMBIGUOUS",
        rationale: "Historical disclosure remains preserved.",
      },
    ],
    [
      "ARBITRATE_STAGNATION",
      {
        direction: "PRODUCT_DECISION_REQUIRED",
        rationale: "Historical disclosure remains preserved.",
      },
    ],
    [
      "ARBITRATE_STAGNATION",
      {
        direction: "CONTINUE_FIXES",
        rationale: "Historical disclosure remains preserved.",
      },
    ],
  ]) {
    const entry = { phase, arbitration };
    assert.deepEqual(retainWorkReport([], entry), [entry]);
    for (const invalid of [
      null,
      { ...arbitration, direction: "APPROVED" },
      ...(phase === "ARBITRATE_VALIDATION_MIGRATION"
        ? [{ ...arbitration, direction: "PRODUCT_DECISION_REQUIRED" }]
        : []),
      { ...arbitration, rationale: "" },
      { ...arbitration, rationale: " Noncanonical rationale. " },
      { ...arbitration, rationale: "x".repeat(4001) },
      {
        ...arbitration,
        direction:
          phase === "ARBITRATE_FINDING"
            ? "PRODUCT_DECISION_REQUIRED"
            : "REQUIREMENT_AMBIGUOUS",
      },
      { ...arbitration, decision: { question: "Unbound active decision" } },
      { ...arbitration, findingId: "F1" },
      { ...arbitration, findingId: ["R1"] },
      { ...arbitration, validationChange: "ACCEPTED" },
    ])
      assert.throws(
        () => retainWorkReport([], { ...entry, arbitration: invalid }),
        { code: "ERR_INVALID_POLISHING_STATE" },
      );
  }
});

const stop = (base = polishingCompleted()) => ({
  ...Object.fromEntries(
    Object.entries(base).map(([key, value]) => [
      key,
      Array.isArray(value) ? [] : "",
    ]),
  ),
  status: "VALIDATION_POLICY_BLOCKED",
  reason: "The frozen task makes the proven execution irrecoverable.",
  evidence: [
    "The Worker disclosed executing the reserved synthetic check before FINALIZE.",
    "Task policy: execution before FINALIZE makes this run ineligible for acceptance.",
    "Disclosure and later checks cannot satisfy that explicit ineligibility rule.",
  ],
});

for (const [mode, phase] of [
  ["independent", "POLISH"],
  ["lazy", "CHECK_AND_FIX"],
  ["combined", "CHECK_AND_FIX"],
  ["independent", "RESOLVE_FINDINGS"],
  ["lazy", "RESOLVE_FINDINGS"],
  ["combined", "RESOLVE_FINDINGS"],
]) {
  test(`${mode} ${phase} retains blocked-only disclosures through retry and reconstruction`, async (t) => {
    const base =
      phase === "RESOLVE_FINDINGS" ? resolution("FIX") : polishingCompleted();
    const blocked = {
      ...base,
      status: "BLOCKED",
      reason: "A synthetic prerequisite is temporarily unavailable.",
      evidence: [
        "Historical disclosure solely in blocked evidence: the reserved synthetic check ran early without acceptance credit.",
      ],
    };
    if (phase === "RESOLVE_FINDINGS") blocked.decisions = [];
    else blocked.summary = "";
    const convergence =
      mode === "independent" ? [] : [checkAndFix(), candidateClean()];
    const restated = mode === "combined" && phase === "RESOLVE_FINDINGS";
    const invalid = resolution("FIX");
    invalid.decisions[0].reason = "";
    const fixture = await createFixture(t, {
      mode,
      stateStore: restated ? "disk" : "memory",
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
        ...(phase === "POLISH"
          ? [blocked, polishingCompleted()]
          : [polishingCompleted()]),
        ...(phase === "CHECK_AND_FIX" ? [blocked] : []),
        ...convergence,
        ...(phase === "RESOLVE_FINDINGS"
          ? [
              finalizationFailed(),
              ...(restated ? [invalid] : []),
              blocked,
              resolution("FIX"),
              ...convergence,
            ]
          : []),
        finalizationPassed(),
        ...(mode === "lazy" ? [cleanConfirmation()] : []),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        candidateApproved(),
      ],
      async onRoleRun(_role, request) {
        if (
          restated &&
          request.schema === FINDING_RESOLUTION_SCHEMA &&
          request.access === "workspace-write"
        )
          await writeFile(
            join(request.cwd, "safe-repair.txt"),
            "safe repair\n",
          );
      },
    });
    const paused = await fixture.run();
    assert.equal(
      paused.pause?.reason,
      "environment_blocked",
      JSON.stringify(paused.pause),
    );
    const report = {
      phase,
      status: "BLOCKED",
      reason: blocked.reason,
      evidence: blocked.evidence,
    };
    assert.deepEqual(
      paused.pipelineState.workReports.find(
        (entry) => entry.status === "BLOCKED",
      ),
      report,
    );
    assert.equal(
      paused.pipelineState.finalizationResult?.status === "PASS",
      false,
    );
    assert.deepEqual(await fixture.recover(), paused);
    const before = Object.fromEntries(
      Object.entries(fixture.calls).map(([role, calls]) => [
        role,
        calls.length,
      ]),
    );
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    for (const role of ["worker", "reviewer"])
      for (const request of fixture.calls[role].slice(before[role]))
        for (const prompt of [request.prompt, request.recoveryPrompt])
          for (const fact of [blocked.reason, blocked.evidence[0]])
            assert.ok(prompt.includes(fact));
    assert.deepEqual(
      done.pipelineState.requiredChecks,
      bootstrapReady("Worker").requiredChecks,
    );
    if (restated)
      assert.deepEqual(
        fixture.calls.worker
          .filter(({ schema }) =>
            [FINDING_RESOLUTION_SCHEMA, FINDING_RECOVERY_SCHEMA].includes(
              schema,
            ),
          )
          .map(({ access }) => access),
        ["workspace-write", "read-only", "read-only"],
      );
    assert.deepEqual(
      (await fixture.recover()).pipelineState.workReports,
      done.pipelineState.workReports,
    );
  });
}

test("blocked work reports retain strict normalized context without approval fields", () => {
  const report = {
    phase: "POLISH",
    status: "BLOCKED",
    reason: "A prerequisite is unavailable.",
    evidence: ["Retained disclosure."],
  };
  assert.deepEqual(retainWorkReport([], report), [report]);
  assert.deepEqual(retainWorkReport([report], report), [report]);
  for (const invalid of [
    { ...report, phase: "CONFIRM" },
    { ...report, status: "PASS" },
    { ...report, reason: "" },
    { ...report, reason: "  Noncanonical reason. " },
    { ...report, evidence: [] },
    { ...report, evidence: ["x".repeat(4001)] },
    { ...report, evidence: ["  Noncanonical evidence. "] },
    { ...report, checks: [] },
    { ...report, decisions: [] },
  ])
    assert.throws(() => retainWorkReport([], invalid), {
      code: "ERR_INVALID_POLISHING_STATE",
    });
});

test("polishing rejects malformed policy stops and inactive approval evidence", () => {
  for (const [base, normalize] of [
    [polishingCompleted, normalizePolishResult],
    [checkAndFix, normalizeCheckAndFixResult],
    [
      () => resolution("FIX", "R1"),
      (value) => normalizeResolutionResult(value, [], new Set()),
    ],
    [finalizationPassed, normalizeFinalizationResult],
  ]) {
    assert.equal(normalize(stop(base())).status, "VALIDATION_POLICY_BLOCKED");
    for (const invalid of [
      { ...stop(base()), evidence: ["unknown"] },
      { ...stop(base()), reason: "" },
      { ...stop(base()), question: "Choose a policy?" },
      { ...stop(base()), extra: "untrusted" },
      {
        ...stop(base()),
        ...(Object.hasOwn(base(), "checks")
          ? { checks: base().checks }
          : { evidence: ["proof", "requirement", ""] }),
      },
    ])
      assert.throws(() => normalize(invalid), {
        code: "ERR_INVALID_POLISHING_OUTPUT",
      });
  }
});

for (const mode of ["independent", "lazy", "combined"]) {
  for (const phase of [
    "POLISH",
    "CHECK_AND_FIX",
    "RESOLVE_FINDINGS",
    "FINALIZE",
  ]) {
    if (
      (mode === "independent" && phase === "CHECK_AND_FIX") ||
      (mode === "lazy" && phase === "RESOLVE_FINDINGS")
    )
      continue;
    test(`${mode} ${phase} preserves a policy stop without accepting evidence or invoking trusted checks`, async (t) => {
      const trustedValidation = trustedValidationSnapshot();
      const bootstrap = (role) => ({
        ...bootstrapReady(role),
        requiredChecks: [
          ...bootstrapReady(role).requiredChecks,
          { id: "C2", command: trustedValidation.commands[0].command },
        ],
      });
      const converge =
        mode === "independent" ? [] : [checkAndFix(), candidateClean()];
      const base =
        phase === "FINALIZE"
          ? finalizationPassed()
          : phase === "CHECK_AND_FIX"
            ? checkAndFix()
            : phase === "RESOLVE_FINDINGS"
              ? resolution("FIX", "R1")
              : polishingCompleted();
      const fixture = await createFixture(t, {
        mode,
        modeSettings: { trustedChecks: [trustedValidation.commands[0].alias] },
        trustedValidation,
        worker: [
          clarificationReady(),
          bootstrap("Worker"),
          ...(mode === "lazy" ? [] : [reconciliationResolved()]),
          ...(phase === "POLISH"
            ? []
            : [
                polishingCompleted(),
                ...(phase === "CHECK_AND_FIX" ? [] : converge),
              ]),
          stop(base),
        ],
        reviewer: [
          bootstrap("Reviewer"),
          phase === "RESOLVE_FINDINGS"
            ? candidateFindings("R1")
            : candidateApproved(),
        ],
        async onRoleRun(_role, request) {
          if (
            mode === "combined" &&
            phase === "CHECK_AND_FIX" &&
            request.schema === CHECK_AND_FIX_SCHEMA
          )
            await writeFile(
              join(request.cwd, "safe-repair.txt"),
              "safe repair\n",
            );
        },
        onTrustedValidation() {
          assert.fail("No trusted validation may follow a policy stop");
        },
      });
      const paused = await fixture.run();
      assert.equal(
        paused.pause?.reason,
        "validation_policy_blocked",
        JSON.stringify(paused.pause),
      );
      assert.equal(paused.pause.checkpoint, phase);
      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(paused.pipelineState.finalizationResult, null);
      if (mode === "combined" && phase === "CHECK_AND_FIX")
        assert.equal(paused.counters.fixRounds, 1);
      const projection = polishingPipeline.projections.pause(paused);
      assert.deepEqual(projection.nextActions, []);
      assert.deepEqual(projection.evidence, stop().evidence);
      assert.match(projection.explanation, /cannot waive/u);
      assert.throws(
        () => polishingPipeline.validateResumeAction(paused, null),
        /no retry or override/u,
      );
      assert.ok(
        fixture.calls.worker
          .at(-1)
          .schema.properties.status.enum.includes("VALIDATION_POLICY_BLOCKED"),
      );
      assert.ok(
        fixture.calls.worker
          .at(-1)
          .prompt.includes(HISTORICAL_VALIDATION_INSTRUCTIONS),
      );
      assert.ok(
        fixture.calls.worker
          .at(-1)
          .recoveryPrompt.includes(HISTORICAL_VALIDATION_INSTRUCTIONS),
      );
      assert.deepEqual(
        polishingPipeline.migrations[21](paused),
        paused.pipelineState,
      );
    });
  }
}

test("content-changing resolution can restate a policy stop without replay or a second charge", async (t) => {
  const report = stop(resolution("FIX", "R1"));
  const fixture = await createFixture(t, {
    mode: "combined",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      checkAndFix(),
      candidateClean(),
      { ...report, evidence: ["insufficient"] },
      report,
    ],
    reviewer: [bootstrapReady("Reviewer"), candidateFindings("R1")],
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (
        request.schema === FINDING_RESOLUTION_SCHEMA &&
        request.access === "workspace-write"
      )
        await writeFile(join(projectPath, "repair.txt"), "safe repair\n");
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "validation_policy_blocked");
  assert.equal(
    await readFile(join(fixture.projectPath, "repair.txt"), "utf8"),
    "safe repair\n",
  );
  const requests = fixture.calls.worker.filter(({ schema }) =>
    [FINDING_RESOLUTION_SCHEMA, FINDING_RECOVERY_SCHEMA].includes(schema),
  );
  assert.deepEqual(
    requests.map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
  assert.ok(requests[1].prompt.includes(HISTORICAL_VALIDATION_INSTRUCTIONS));
  assert.match(requests[1].prompt, /exactly-three-policy-evidence-items/u);
  assert.equal(paused.pipelineState.resolutionCorrection.stage, "correcting");
  assert.equal(paused.pipelineState.resolutionCorrection.attempts, 1);
  assert.equal(paused.counters.fixRounds, 2); // One primary pass and one actual repair.
  assert.deepEqual(
    paused.pipelineState.findings.map(({ id }) => id),
    ["R1"],
  );
  const saved = structuredClone(paused);
  await assert.rejects(fixture.run(), /no retry or override/u);
  assert.deepEqual(fixture.currentRun, saved);
});

test("a lazy finalization repair preserves its originating policy-stop checkpoint", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      checkAndFix(),
      candidateClean(),
      finalizationFailed(),
      stop(resolution("FIX")),
    ],
    async onRoleRun(_role, request) {
      if (request.schema === FINDING_RESOLUTION_SCHEMA)
        await writeFile(join(request.cwd, "safe-repair.txt"), "safe repair\n");
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "validation_policy_blocked");
  assert.equal(paused.pause.checkpoint, "RESOLVE_FINDINGS");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(
    await readFile(join(fixture.projectPath, "safe-repair.txt"), "utf8"),
    "safe repair\n",
  );
  assert.equal(paused.counters.fixRounds, 2);
});

test("contained historical reports survive candidate approval into terminal reconstruction", async (t) => {
  const historical = candidateFindings("R1");
  historical.findings[0].problem =
    "The Worker disclosed a synthetic validation command executed before FINALIZE.";
  const disposition = resolution("FIX", "R1");
  disposition.decisions[0].reason =
    "Retain the historical disclosure, give no early coverage credit and keep the full checks with FINALIZE.";
  const fixture = await createFixture(t, {
    mode: "combined",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      checkAndFix(),
      candidateClean(),
      disposition,
      checkAndFix(),
      candidateClean(),
      resolution("FIX", "R2"),
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      historical,
      candidateFindings("R2"),
      candidateApproved(),
    ],
  });
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  const terminal = fixture.calls.reviewer.at(-1);
  assert.ok(terminal.recoveryPrompt.includes(historical.findings[0].problem));
  assert.ok(terminal.recoveryPrompt.includes(disposition.decisions[0].reason));
  assert.ok(terminal.prompt.includes(HISTORICAL_VALIDATION_INSTRUCTIONS));
  assert.deepEqual(
    done.pipelineState.requiredChecks,
    bootstrapReady("Worker").requiredChecks,
  );
});

test("loss after policy-pause publication preserves the stop without a replacement failure", async (t) => {
  const fixture = await createFixture(t, {
    stateStore: "disk",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      stop(),
    ],
    reviewer: [bootstrapReady("Reviewer")],
  });
  const transition = fixture.runtime.transition;
  const loss = new Error("Synthetic acknowledgement loss");
  let lost = false;
  fixture.runtime.transition = async (...args) => {
    const next = await transition(...args);
    if (!lost && next.pause?.reason === "validation_policy_blocked") {
      lost = true;
      throw loss;
    }
    return next;
  };
  await assert.rejects(fixture.run(), (cause) => cause === loss);
  const published = structuredClone(fixture.currentRun);
  assert.equal(published.pause.reason, "validation_policy_blocked");
  assert.deepEqual(await fixture.recover(), published);
  const calls = fixture.calls.worker.length;
  await assert.rejects(fixture.run(), /no retry or override/u);
  assert.equal(fixture.calls.worker.length, calls);
  assert.deepEqual(fixture.currentRun, published);
});

test("combined polishing retains primary history and summary-only disclosures after containment", async (t) => {
  const historical = candidateFindings("R1");
  historical.findings[0].problem =
    "A synthetic reserved check was disclosed as executed before FINALIZE.";
  const polish = polishingCompleted();
  polish.summary =
    "Historical disclosure: an early reserved execution grants no credit; FINALIZE still owns all pending checks.";
  const containment = checkAndFix();
  containment.summary =
    "Preserve the historical disclosure with no check credit and the full pending FINALIZE inventory.";
  const changed = checkAndFix("CHANGED");
  changed.summary =
    "A check/fix-only historical disclosure grants no credit and leaves the checks pending.";
  let repaired = false;
  const fixture = await createFixture(t, {
    mode: "combined",
    stateStore: "disk",
    async onRoleRun(_role, request) {
      if (request.schema === CHECK_AND_FIX_SCHEMA && !repaired) {
        repaired = true;
        await writeFile(join(request.cwd, "safe-repair.txt"), "safe repair\n");
      }
    },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polish,
      changed,
      checkAndFix(),
      historical,
      containment,
      candidateClean(),
      finalizationPassed(),
    ],
    reviewer: [bootstrapReady("Reviewer"), candidateApproved()],
  });
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.deepEqual(done.pipelineState.primaryFindings, []);
  assert.deepEqual(
    done.pipelineState.workReports.find(
      ({ phase }) => phase === "CLEAN_CONFIRM",
    ).findings,
    historical.findings,
  );
  for (const request of fixture.calls.reviewer.filter(({ schema }) =>
    [CANDIDATE_REVIEW_SCHEMA, REVIEW_SCHEMA].includes(schema),
  )) {
    for (const prompt of [request.prompt, request.recoveryPrompt]) {
      assert.ok(prompt.includes(historical.findings[0].problem));
      assert.ok(prompt.includes(polish.summary));
      assert.ok(prompt.includes(changed.summary));
      assert.ok(prompt.includes(containment.summary));
    }
  }
  assert.deepEqual(
    (await fixture.recover()).pipelineState.workReports,
    done.pipelineState.workReports,
  );
  const legacy = structuredClone(done);
  delete legacy.pipelineState.workReports;
  const migrated = polishingPipeline.migrations[21](legacy);
  assert.deepEqual(migrated, { ...legacy.pipelineState, workReports: [] });
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} retains a FINALIZE-only disclosure after content repair without retaining check credit`, async (t) => {
    const failed = finalizationFailed();
    failed.summary =
      "Historical disclosure: the synthetic reserved check ran early; no acceptance credit is granted and all later checks remain required.";
    failed.issues[0].evidence = [
      "A separate historical disclosure appears only in the accepted finalization issue evidence.",
    ];
    failed.checks[0].evidence = [
      "A check-only disclosure: the synthetic reserved command ran early, without acceptance credit.",
    ];
    const convergence =
      mode === "independent" ? [] : [checkAndFix(), candidateClean()];
    let repaired = false;
    let reconstructed = false;
    const fixture = await createFixture(t, {
      mode,
      stateStore: mode === "combined" ? "disk" : "memory",
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
        polishingCompleted(),
        ...convergence,
        failed,
        resolution("FIX"),
        ...convergence,
        finalizationPassed(),
        ...(mode === "lazy" ? [cleanConfirmation()] : []),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        candidateApproved(),
      ],
      async onRoleRun(_role, request) {
        if (request.schema === FINDING_RESOLUTION_SCHEMA) {
          await writeFile(
            join(request.cwd, "safe-repair.txt"),
            "safe repair\n",
          );
          repaired = true;
        } else if (
          repaired &&
          [CHECK_AND_FIX_SCHEMA, CANDIDATE_REVIEW_SCHEMA].includes(
            request.schema,
          )
        ) {
          const current = fixture.currentRun.pipelineState;
          assert.equal(current.finalizationResult, null);
          assert.equal(current.finalizedFingerprint, null);
          assert.deepEqual(current.requiredChecks, failed.requiredChecks);
          for (const prompt of [request.prompt, request.recoveryPrompt]) {
            assert.ok(prompt.includes(failed.summary));
            assert.ok(prompt.includes(failed.issues[0].evidence[0]));
            assert.ok(prompt.includes(failed.checks[0].evidence[0]));
          }
          reconstructed = true;
        }
      },
    });
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.ok(reconstructed);
    const report = {
      phase: "FINALIZE",
      summary: failed.summary,
      issues: failed.issues,
      checks: failed.checks,
    };
    assert.deepEqual(
      done.pipelineState.workReports.find(({ phase }) => phase === "FINALIZE"),
      report,
    );
    if (mode === "combined")
      assert.deepEqual(
        (await fixture.recover()).pipelineState.workReports,
        done.pipelineState.workReports,
      );
  });
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} retains disclosures solely in an accepted FIX reason and evidence`, async (t) => {
    const disposition = resolution("FIX");
    disposition.decisions[0].reason =
      "Historical disclosure: the reserved synthetic check ran before FINALIZE.";
    disposition.decisions[0].evidence = [
      "The early execution grants no credit; the complete inventory remains pending with its assigned FINALIZE owners.",
    ];
    const convergence =
      mode === "independent" ? [] : [checkAndFix(), candidateClean()];
    let resolved = false;
    let inspected = false;
    const fixture = await createFixture(t, {
      mode,
      stateStore: mode === "combined" ? "disk" : "memory",
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
        polishingCompleted(),
        ...convergence,
        finalizationFailed(),
        disposition,
        ...convergence,
        finalizationPassed(),
        ...(mode === "lazy" ? [cleanConfirmation()] : []),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        candidateApproved(),
      ],
      async onRoleRun(_role, request) {
        if (request.schema === FINDING_RESOLUTION_SCHEMA) {
          await writeFile(
            join(request.cwd, "safe-repair.txt"),
            "safe repair\n",
          );
          resolved = true;
        } else if (
          resolved &&
          [
            CHECK_AND_FIX_SCHEMA,
            CANDIDATE_REVIEW_SCHEMA,
            REVIEW_SCHEMA,
          ].includes(request.schema)
        ) {
          assert.deepEqual(fixture.currentRun.pipelineState.findings, []);
          for (const prompt of [request.prompt, request.recoveryPrompt]) {
            assert.ok(prompt.includes(disposition.decisions[0].reason));
            assert.ok(prompt.includes(disposition.decisions[0].evidence[0]));
          }
          inspected = true;
        }
      },
    });
    if (mode === "combined") {
      // Lose the acknowledgement after acceptance, then discard the hot store.
      // The next requests must rebuild their context from the published record.
      const loss = new Error("Synthetic acceptance acknowledgement loss");
      const transition = fixture.runtime.transition;
      let lost = false;
      fixture.runtime.transition = async (...args) => {
        const next = await transition(...args);
        if (
          !lost &&
          next.pipelineState.workReports.some(
            ({ phase }) => phase === "RESOLVE_FINDINGS",
          )
        ) {
          lost = true;
          throw loss;
        }
        return next;
      };
      await assert.rejects(fixture.run(), (cause) => cause === loss);
      const accepted = structuredClone(fixture.currentRun);
      assert.deepEqual(await fixture.recover(), accepted);
    }
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.ok(inspected);
    assert.equal(
      fixture.calls.worker.filter(({ schema }) =>
        [FINDING_RESOLUTION_SCHEMA, FINDING_RECOVERY_SCHEMA].includes(schema),
      ).length,
      1,
    );
    assert.deepEqual(
      done.pipelineState.workReports.find(
        ({ phase }) => phase === "RESOLVE_FINDINGS",
      ),
      { phase: "RESOLVE_FINDINGS", decisions: disposition.decisions },
    );
    assert.deepEqual(
      done.pipelineState.requiredChecks,
      finalizationPassed().requiredChecks,
    );
    assert.deepEqual(
      (await fixture.recover()).pipelineState.workReports,
      done.pipelineState.workReports,
    );
  });
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} retains terminal validation evidence through rejection, repair and reconstruction`, async (t) => {
    const disclosures = [
      "Evidence-only disclosure: the reserved synthetic check ran before FINALIZE.",
      "Evidence-only disclosure: that early run grants no acceptance credit.",
      "Evidence-only disclosure: FINALIZE still owns every established check.",
    ];
    const rejection = {
      ...reviewFindings("R1"),
      validationChange: "REJECTED",
      validationEvidence: [disclosures[0]],
      finalizationFindingIds: ["R1"],
    };
    const content = {
      ...reviewFindings("R2"),
      validationEvidence: [disclosures[1]],
    };
    const clean = {
      ...(mode === "lazy" ? cleanConfirmation() : reviewApproved()),
      validationEvidence: [disclosures[2]],
    };
    const terminalSchema =
      mode === "lazy" ? CLEAN_CONFIRM_SCHEMA : REVIEW_SCHEMA;
    const converge =
      mode === "independent" ? [] : [checkAndFix(), candidateClean()];
    const confirmationsBefore = new Map();
    let confirmations = 0;
    const fixture = await createFixture(t, {
      mode,
      stateStore: mode === "combined" ? "disk" : "memory",
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        ...(mode === "lazy" ? [] : [reconciliationResolved()]),
        polishingCompleted(),
        ...converge,
        ...(mode === "lazy"
          ? [
              finalizationPassed(),
              rejection,
              finalizationPassed(),
              content,
              checkAndFix("CHANGED"),
              candidateClean(),
              finalizationPassed(),
              clean,
            ]
          : [
              finalizationPassed(),
              finalizationPassed(),
              resolution("FIX", "R2"),
              ...converge,
              finalizationPassed(),
            ]),
      ],
      reviewer:
        mode === "lazy"
          ? []
          : [
              bootstrapReady("Reviewer"),
              candidateApproved(),
              rejection,
              content,
              candidateApproved(),
              clean,
            ],
      async onRoleRun(_role, request) {
        confirmationsBefore.set(request, confirmations);
        if (request.schema === terminalSchema) confirmations++;
        // Repair the content finding so no gate evidence survives into later requests.
        if (
          request.access === "workspace-write" &&
          fixture.currentRun.pipelineState.findings.some(
            ({ id }) => id === "R2",
          )
        )
          await writeFile(
            join(request.cwd, "safe-repair.txt"),
            "safe repair\n",
          );
      },
    });
    for (const reportCount of [1, 2]) {
      const loss = new Error(
        "Synthetic terminal acceptance acknowledgement loss",
      );
      const transition = fixture.runtime.transition;
      let published = null;
      fixture.runtime.transition = async (...args) => {
        // Fail only the acknowledgement; subsequent publications remain available.
        const next = await transition(...args);
        if (
          published === null &&
          next.pipelineState.workReports.filter(
            ({ phase }) => phase === "CONFIRM",
          ).length === reportCount
        ) {
          published = structuredClone(next);
          throw loss;
        }
        return next;
      };
      await assert.rejects(fixture.run(), (cause) => cause === loss);
      assert.notEqual(published, null);
      assert.deepEqual(fixture.currentRun, published);
      assert.deepEqual(await fixture.recover(), published);
      assert.equal(
        published.pipelineState.workflowState,
        reportCount === 1
          ? "FINALIZE"
          : mode === "lazy"
            ? "CHECK_AND_FIX"
            : "RESOLVE_FINDINGS",
      );
      assert.equal(published.pipelineState.reviewResult, null);
      assert.equal(
        published.pipelineState.workReports.filter(
          ({ phase }) => phase === "CONFIRM",
        ).length,
        reportCount,
      );
    }
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.equal(confirmations, 3);
    assert.deepEqual(
      done.pipelineState.workReports.filter(({ phase }) => phase === "CONFIRM"),
      [
        {
          phase: "CONFIRM",
          findings: rejection.findings,
          validationEvidence: rejection.validationEvidence,
        },
        {
          phase: "CONFIRM",
          findings: content.findings,
          validationEvidence: content.validationEvidence,
        },
        { phase: "CONFIRM", validationEvidence: clean.validationEvidence },
      ],
    );
    // Retained evidence is no gate credit: rejection and repair each rerun FINALIZE.
    assert.equal(
      fixture.calls.worker.filter(
        ({ schema }) => schema === FINALIZATION_SCHEMA,
      ).length,
      3,
    );
    assert.deepEqual(
      done.pipelineState.requiredChecks,
      bootstrapReady("Worker").requiredChecks,
    );
    for (const request of Object.values(fixture.calls).flat())
      for (const prompt of [request.prompt, request.recoveryPrompt])
        for (const disclosure of disclosures.slice(
          0,
          confirmationsBefore.get(request),
        ))
          assert.ok(prompt.includes(disclosure));
    assert.deepEqual(
      normalizePipelineState(JSON.parse(JSON.stringify(done.pipelineState)))
        .workReports,
      done.pipelineState.workReports,
    );
  });
}

test("terminal validation evidence reports are strict history without gate fields", () => {
  const findings = reviewFindings("R1").findings;
  const validationEvidence = ["Evidence-only disclosure retained as history."];
  for (const report of [
    { phase: "CONFIRM", validationEvidence },
    { phase: "CONFIRM", findings, validationEvidence },
  ])
    assert.deepEqual(retainWorkReport([], report), [report]);
  for (const invalid of [
    { phase: "CONFIRM" },
    { phase: "CONFIRM", validationEvidence: [] },
    { phase: "CONFIRM", validationEvidence: ["  Noncanonical evidence.  "] },
    { phase: "CONFIRM", validationEvidence: ["x".repeat(4001)] },
    { phase: "CONFIRM", validationEvidence, validationChange: "ACCEPTED" },
    { phase: "REVIEW", findings, validationEvidence },
    { phase: "FINALIZE", summary: "Accepted report.", validationEvidence },
  ])
    assert.throws(() => retainWorkReport([], invalid), {
      code: "ERR_INVALID_POLISHING_STATE",
    });
});

test("resolution report context keeps normalized mixed decisions and rejects malformed facts", () => {
  const decisions = [
    {
      id: "R1",
      decision: "FIX",
      reason: "Retained historical disclosure.",
      evidence: [],
    },
    {
      id: "R2",
      decision: "DISPUTE",
      reason: "No prohibited execution established.",
      evidence: ["Source observation alone supplies no execution proof."],
    },
  ];
  const report = { phase: "RESOLVE_FINDINGS", decisions };
  const reports = retainWorkReport([], report);
  assert.deepEqual(reports, [report]);
  assert.deepEqual(retainWorkReport(reports, report), reports);
  for (const invalid of [
    [],
    [decisions[0], decisions[0]],
    [{ ...decisions[0], id: "unknown" }],
    [{ ...decisions[0], id: ["R1"] }],
    [{ ...decisions[0], decision: "CLEAN" }],
    [{ ...decisions[0], reason: "" }],
    [{ ...decisions[0], reason: "  Noncanonical text.  " }],
    [{ ...decisions[0], evidence: ["x".repeat(4001)] }],
    [{ ...decisions[0], checks: [] }],
    [{ ...decisions[1], evidence: [] }],
  ])
    assert.throws(
      () => retainWorkReport([], { ...report, decisions: invalid }),
      { code: "ERR_INVALID_POLISHING_STATE" },
    );
});

test("polishing Worker report history rejects malformed or excessive context without dropping facts", () => {
  const report = { phase: "POLISH", summary: "Retained disclosure." };
  const reports = retainWorkReport([], report);
  assert.deepEqual(retainWorkReport(reports, report), reports);
  const issueReport = {
    ...report,
    phase: "FINALIZE",
    issues: finalizationFailed().issues,
  };
  assert.deepEqual(retainWorkReport([], issueReport), [issueReport]);
  for (const malformed of [
    { ...report, checks: [] },
    { ...report, phase: "HANDOFF" },
    { ...report, summary: "" },
    { phase: "CLEAN_CONFIRM", findings: [] },
    { ...issueReport, phase: "POLISH" },
    { ...issueReport, issues: [] },
    { ...issueReport, issues: [{ ...issueReport.issues[0], evidence: [] }] },
    {
      ...issueReport,
      issues: [
        { ...issueReport.issues[0], problem: "  Noncanonical issue.  " },
      ],
    },
    { ...issueReport, checks: [] },
  ])
    assert.throws(() => retainWorkReport([], malformed), {
      code: "ERR_INVALID_POLISHING_STATE",
    });
  assert.throws(
    () =>
      retainWorkReport(
        Array.from({ length: 256 }, (_, i) => ({
          ...report,
          summary: `Report ${i}`,
        })),
        report,
      ),
    /bounded context capacity/u,
  );
  const oversized = Array.from({ length: 106 }, (_, i) => ({
    ...report,
    summary: `${i}:` + "x".repeat(19_990),
  }));
  assert.throws(
    () => retainWorkReport(oversized, report),
    /bounded context capacity/u,
  );
  assert.deepEqual(reports, [report]);
});

test("historical finalization check reports are strict context without executor authority", () => {
  const checks = finalizationPassed().checks;
  const report = { phase: "FINALIZE", summary: "Accepted report.", checks };
  assert.deepEqual(retainWorkReport([], report), [report]);
  for (const invalid of [
    [],
    [checks[0], checks[0]],
    [{ ...checks[0], checkId: "unknown" }],
    [{ ...checks[0], command: " invalid command " }],
    [{ ...checks[0], status: "APPROVED" }],
    [{ ...checks[0], evidence: [] }],
    [{ ...checks[0], evidence: ["  Noncanonical evidence.  "] }],
    [{ ...checks[0], evidence: ["x".repeat(4001)] }],
    [{ ...checks[0], executor: "runner" }],
  ])
    assert.throws(() => retainWorkReport([], { ...report, checks: invalid }), {
      code: "ERR_INVALID_POLISHING_STATE",
    });
  assert.throws(() => retainWorkReport([], { ...report, evidence: [] }), {
    code: "ERR_INVALID_POLISHING_STATE",
  });
});

test("trusted placeholder disclosures survive blocked execution, retry and receipt replacement", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const withTrusted = () => ({
    ...finalizationPassed(),
    requiredChecks: [
      ...finalizationPassed().requiredChecks,
      { id: "C2", command: trustedValidation.commands[0].command },
    ],
    checks: [
      ...finalizationPassed().checks,
      {
        checkId: "C2",
        command: trustedValidation.commands[0].command,
        status: "NOT_RUN",
        evidence: ["Reserved for Runner."],
      },
    ],
  });
  const first = withTrusted();
  const later = withTrusted();
  const disclosure =
    "Historical disclosure only in a reserved check: a synthetic command ran early and grants no credit.";
  first.checks.at(-1).evidence = [disclosure];
  const bootstrap = (role) => ({
    ...bootstrapReady(role),
    requiredChecks: first.requiredChecks,
  });
  let executions = 0;
  const fixture = await createFixture(t, {
    mode: "combined",
    modeSettings: { trustedChecks: ["service-check"] },
    trustedValidation,
    stateStore: "disk",
    worker: [
      clarificationReady(),
      bootstrap("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      checkAndFix(),
      candidateClean(),
      first,
      later,
    ],
    reviewer: [bootstrap("Reviewer"), candidateApproved()],
    onTrustedValidation(options) {
      executions++;
      assert.deepEqual(
        fixture.currentRun.pipelineState.workReports.find(
          ({ phase }) => phase === "FINALIZE",
        ).checks,
        first.checks,
      );
      return {
        ...options.bindings,
        commandIdentity: options.commandIdentity,
        status: executions === 1 ? "BLOCKED" : "PASS",
        exitCode: executions === 1 ? null : 0,
        signal: null,
        timedOut: false,
        evidence: ["Synthetic executor receipt."],
      };
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.deepEqual(paused.pipelineState.requiredChecks, first.requiredChecks);
  assert.deepEqual(await fixture.recover(), paused);
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.equal(executions, 2);
  assert.deepEqual(
    done.pipelineState.finalizationResult.checks.at(-1).evidence,
    ["Synthetic executor receipt."],
  );
  assert.equal(
    done.pipelineState.finalizationResult.checks.at(-1).executor,
    "runner",
  );
  for (const request of fixture.calls.reviewer.filter(
    ({ schema }) => schema === REVIEW_SCHEMA,
  )) {
    assert.ok(request.prompt.includes(disclosure));
    assert.ok(request.recoveryPrompt.includes(disclosure));
  }
  assert.ok(
    fixture.calls.reviewer.some(({ schema }) => schema === REVIEW_SCHEMA),
  );
  const finalizing = fixture.calls.worker.filter(
    ({ schema }) => schema === FINALIZATION_SCHEMA,
  );
  assert.equal(finalizing.length, 2);
  assert.ok(finalizing[1].prompt.includes(disclosure));
  assert.ok(finalizing[1].recoveryPrompt.includes(disclosure));
  assert.deepEqual(
    (await fixture.recover()).pipelineState.workReports,
    done.pipelineState.workReports,
  );
});

test("accepted blocked check disclosures survive retry without check credit", async (t) => {
  const blocked = finalizationBlocked(
    "A synthetic prerequisite is unavailable.",
    "Blocker evidence.",
  );
  blocked.checks[0].evidence = [
    "A disclosure solely in blocked check evidence survives recovery without credit.",
  ];
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      blocked,
      finalizationPassed(),
    ],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.deepEqual(
    paused.pipelineState.workReports.find(({ phase }) => phase === "FINALIZE"),
    {
      phase: "FINALIZE",
      summary: blocked.reason,
      evidence: blocked.evidence,
      checks: blocked.checks,
    },
  );
  assert.deepEqual(await fixture.recover(), paused);
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  const terminal = fixture.calls.reviewer.at(-1);
  for (const prompt of [terminal.prompt, terminal.recoveryPrompt])
    assert.ok(prompt.includes(blocked.checks[0].evidence[0]));
  assert.deepEqual(done.pipelineState.requiredChecks, blocked.requiredChecks);
});
