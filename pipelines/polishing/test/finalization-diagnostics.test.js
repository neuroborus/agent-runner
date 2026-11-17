import assert from "node:assert/strict";
import test from "node:test";

import { main } from "../../../src/index.js";
import { createMcpControlPlane } from "../../../src/mcp/index.js";
import { polishingPipeline } from "../src/index.js";
import { FINALIZATION_SCHEMA } from "../src/schemas.js";
import {
  assertRun,
  finalizationDiagnostic,
  normalizeFinalizationResult,
} from "../src/workflow-contract.js";
import {
  bootstrapReady,
  candidateClean,
  checkAndFix,
  clarificationReady,
  createFixture,
  finalizationBlocked,
  finalizationFailed,
  finalizationPassed,
  finalizationUnavailable,
  polishingCompleted,
  reconciliationResolved,
} from "./support/index.js";

const PRIVATE = "PRIVATE_REJECTED_VALUE";
const contextual = (field, constraint) => ({
  role: "worker",
  phase: "finalization",
  contract: "finalization",
  field,
  constraint,
});
const malformedEvidence = () => {
  const result = structuredClone(finalizationPassed());
  result.checks[0].evidence = [];
  return result;
};
const turns = (fixture) =>
  fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA);
const bootstrap = () => [
  clarificationReady(),
  bootstrapReady("Worker"),
  reconciliationResolved(),
  polishingCompleted(),
];

test("valid finalization controls retain statuses, inventories and trusted reservations", () => {
  for (const report of [
    finalizationPassed(),
    finalizationFailed(),
    finalizationBlocked("Check unavailable.", "Execution unavailable."),
    finalizationUnavailable("SKILL_MISSING"),
    finalizationUnavailable("SKILL_INVALID"),
  ]) {
    const normalized = normalizeFinalizationResult(report);
    assert.equal(normalized.status, report.status);
    assert.deepEqual(normalized.requiredChecks, report.requiredChecks);
    assert.deepEqual(normalized.checks, report.checks);
  }
  const reserved = structuredClone(finalizationPassed());
  reserved.checks[0].status = "NOT_RUN";
  const trustedCommands = [reserved.requiredChecks[0].command];
  assert.equal(
    normalizeFinalizationResult(reserved, { trustedCommands }).checks[0].status,
    "NOT_RUN",
  );
});

test("recognized finalization rejections identify bounded fields without rejected values", () => {
  const passed = finalizationPassed();
  const check = (patch) => ({
    ...passed,
    checks: [{ ...passed.checks[0], ...patch }],
  });
  const issue = (patch) => ({
    ...finalizationFailed(),
    issues: [{ ...finalizationFailed().issues[0], ...patch }],
  });
  const unavailable = finalizationUnavailable("SKILL_INVALID");
  const cases = [
    [null, "result", "exact-field-set"],
    [{ ...passed, [PRIVATE]: true }, "result", "exact-field-set"],
    [{ ...passed, status: PRIVATE }, "status", "finalization-status"],
    [check({ status: "FAIL" }), "checks", "pass-status-check-consistency"],
    [
      malformedEvidence(),
      "checks[0].evidence",
      "nonempty-array-up-to-32-items",
    ],
    [
      { ...unavailable, checks: passed.checks },
      "checks",
      "empty-for-unavailable-finalization",
    ],
    [
      { ...unavailable, requiredChecks: passed.requiredChecks },
      "requiredChecks",
      "empty-for-unavailable-finalization",
    ],
    [
      {
        ...unavailable,
        validationInfrastructure: passed.validationInfrastructure,
      },
      "validationInfrastructure",
      "empty-for-unavailable-finalization",
    ],
    [{ ...passed, checks: [] }, "checks", "complete-ordered-check-results"],
    [{ ...passed, checks: [null] }, "checks[0]", "object"],
    [
      check({ checkId: PRIVATE }),
      "checks[0].checkId",
      "required-check-id-in-order",
    ],
    [
      check({ command: PRIVATE }),
      "checks[0].command",
      "required-check-command",
    ],
    [
      check({ command: " node --version" }),
      "checks[0].command",
      "exact-single-line-command-up-to-4000-characters",
    ],
    [check({ status: PRIVATE }), "checks[0].status", "check-result-status"],
    [
      check({ status: "NOT_RUN" }),
      "checks[0].status",
      "agent-executed-check-status",
    ],
    [
      check({ evidence: [PRIVATE + "\n"] }),
      "checks[0].evidence[0]",
      "nonempty-plain-text-up-to-4000-characters",
    ],
    [
      { ...passed, summary: "" },
      "summary",
      "concise-markdown-up-to-20000-characters",
    ],
    [
      { ...passed, skillPath: "../private.md" },
      "skillPath",
      "repository-relative-path-up-to-4000-characters",
    ],
    [{ ...passed, reason: PRIVATE }, "reason", "empty-string"],
    [{ ...passed, evidence: [PRIVATE] }, "evidence", "empty-array"],
    [{ ...passed, question: PRIVATE }, "question", "empty-string"],
    [{ ...passed, options: [PRIVATE] }, "options", "empty-array"],
    [{ ...passed, whyBlocked: PRIVATE }, "whyBlocked", "empty-string"],
    [
      { ...passed, issues: finalizationFailed().issues },
      "issues",
      "empty-when-pass",
    ],
    [{ ...finalizationFailed(), issues: [] }, "issues", "nonempty-when-fail"],
    [
      { ...finalizationFailed(), checks: passed.checks },
      "checks",
      "fail-status-check-consistency",
    ],
    [
      { ...finalizationFailed(), checks: check({ status: "BLOCKED" }).checks },
      "checks",
      "fail-status-check-consistency",
    ],
    [
      {
        ...finalizationBlocked("Unavailable.", "No execution."),
        checks: passed.checks,
      },
      "checks",
      "blocked-status-check-consistency",
    ],
    [{ ...unavailable, summary: PRIVATE }, "summary", "empty-string"],
    [
      { ...unavailable, skillPath: "" },
      "skillPath",
      "selected-finalization-guidance",
    ],
    [
      { ...unavailable, reason: "" },
      "reason",
      "nonempty-plain-text-up-to-4000-characters",
    ],
    [
      { ...unavailable, evidence: [PRIVATE + "\n"] },
      "evidence[0]",
      "nonempty-plain-text-up-to-4000-characters",
    ],
    [
      { ...passed, issues: Array(33).fill({}) },
      "issues",
      "array-up-to-32-items",
    ],
    [{ ...passed, issues: [null] }, "issues[0]", "object"],
    [issue({ id: PRIVATE }), "issues[0].id", "finalization-issue-id"],
    [issue({ [PRIVATE]: true }), "issues[0]", "exact-field-set"],
    [
      issue({ command: "" }),
      "issues[0].command",
      "nonempty-plain-text-up-to-4000-characters",
    ],
    [
      issue({ problem: "" }),
      "issues[0].problem",
      "nonempty-plain-text-up-to-4000-characters",
    ],
    [
      issue({ evidence: [] }),
      "issues[0].evidence",
      "nonempty-array-up-to-32-items",
    ],
    [
      issue({ evidence: [PRIVATE + "\n"] }),
      "issues[0].evidence[0]",
      "nonempty-plain-text-up-to-4000-characters",
    ],
    [
      {
        ...finalizationFailed(),
        issues: [
          ...finalizationFailed().issues,
          ...finalizationFailed().issues,
        ],
      },
      "issues",
      "unique-ids",
    ],
    [
      { ...passed, requiredChecks: [] },
      "requiredChecks",
      "nonempty-array-up-to-512-items",
    ],
    [
      { ...passed, requiredChecks: [null] },
      "requiredChecks[0]",
      "exact-field-set",
    ],
    [
      {
        ...passed,
        requiredChecks: [{ id: PRIVATE, command: "node --version" }],
      },
      "requiredChecks[0].id",
      "required-check-id",
    ],
    [
      {
        ...passed,
        requiredChecks: [...passed.requiredChecks, ...passed.requiredChecks],
      },
      "requiredChecks",
      "unique-ids-and-commands",
    ],
    [
      { ...passed, requiredChecks: [{ id: "C1", command: "git add ." }] },
      "requiredChecks[0].command",
      "staging-independent-validation-command",
    ],
    [
      { ...passed, validationInfrastructure: null },
      "validationInfrastructure",
      "array-up-to-512-items",
    ],
    [
      { ...passed, validationInfrastructure: ["../private"] },
      "validationInfrastructure[0]",
      "exact-repository-relative-path-up-to-4000-characters",
    ],
    [
      { ...passed, validationInfrastructure: ["package.json", "package.json"] },
      "validationInfrastructure",
      "unique-paths",
    ],
    [
      { ...passed, summary: "x".repeat(2 * 1024 * 1024) },
      "result",
      "maximum-2-mebibytes",
    ],
  ];
  const cyclic = structuredClone(passed);
  cyclic.issues = [cyclic];
  cases.push([cyclic, "result", "serializable-json"]);
  for (const [report, field, constraint] of cases) {
    assert.throws(
      () => normalizeFinalizationResult(report),
      (error) => {
        assert.equal(error.code, "ERR_INVALID_POLISHING_OUTPUT");
        assert.deepEqual(error.diagnostic, { field, constraint });
        assert.deepEqual(
          finalizationDiagnostic(error.diagnostic),
          error.diagnostic,
        );
        assert.doesNotMatch(
          String(error) + JSON.stringify(error),
          /PRIVATE_REJECTED_VALUE/u,
        );
        return true;
      },
      `${field}: ${constraint}`,
    );
  }
  assert.throws(
    () =>
      normalizeFinalizationResult(passed, {
        trustedCommands: [passed.requiredChecks[0].command],
      }),
    {
      diagnostic: {
        field: "checks[0].status",
        constraint: "runner-trusted-check-not-run",
      },
    },
  );
  const ordered = structuredClone(passed);
  ordered.requiredChecks.push({ id: "C2", command: "node --version" });
  ordered.checks.push({
    ...ordered.checks[0],
    checkId: "C2",
    command: "node --version",
  });
  ordered.checks.reverse();
  assert.throws(() => normalizeFinalizationResult(ordered), {
    diagnostic: {
      field: "checks[0].checkId",
      constraint: "required-check-id-in-order",
    },
  });
});

test("combined correction reconstructs actionable evidence without renewing its allowance", async (t) => {
  const stopped = new Error("Simulated interruption.");
  const fixture = await createFixture(t, {
    mode: "combined",
    worker: [
      ...bootstrap(),
      checkAndFix(),
      candidateClean(),
      malformedEvidence(),
      { ...finalizationPassed(), checks: [] },
    ],
  });
  const transition = fixture.runtime.transition;
  const start = fixture.runtime.startAgentTurn;
  let interrupted = false;
  fixture.runtime.transition = async (patch, options) => {
    if (interrupted) throw stopped;
    const result = await transition(patch, options);
    if (options.activity?.kind === "finalization-correction")
      interrupted = true;
    return result;
  };
  fixture.runtime.startAgentTurn = async (turn) => {
    if (interrupted) throw stopped;
    return start(turn);
  };
  await assert.rejects(fixture.run(), (error) => error === stopped);
  const saved = structuredClone(fixture.currentRun);
  assertRun(saved);
  const correction = saved.pipelineState.pendingFinalizationCorrection;
  assert.deepEqual(correction, {
    attempt: 1,
    guidance: "resolved",
    contentFingerprint:
      saved.pipelineState.repositoryBaseline.contentFingerprint,
    ...contextual("checks[0].evidence", "nonempty-array-up-to-32-items"),
  });
  fixture.runtime.transition = transition;
  fixture.runtime.startAgentTurn = start;
  await assert.rejects(fixture.run(), {
    code: "ERR_INVALID_POLISHING_OUTPUT",
    diagnostic: contextual("checks", "complete-ordered-check-results"),
  });
  const failed = fixture.currentRun;
  assertRun(failed);
  assert.equal(failed.pipelineState.workflowState, "FAILED");
  assert.deepEqual(failed.counters, saved.counters);
  assert.deepEqual(failed.pipelineState.finalizationCorrection, correction);
  assert.deepEqual(
    failed.pipelineState.finalizationRecovery,
    saved.pipelineState.finalizationRecovery,
  );
  assert.ok(
    fixture.transitions.every(
      ({ patch }) => patch.pipelineState.workflowState !== "HANDOFF",
    ),
  );
  assert.equal(turns(fixture).length, 2);
  const request = turns(fixture)[1];
  assert.equal(request.access, "read-only");
  assert.equal(request.session, undefined);
  for (const prompt of [request.prompt, request.recoveryPrompt]) {
    assert.match(prompt, /checks\[0\]\.evidence/u);
    assert.match(prompt, /nonempty-array-up-to-32-items/u);
    assert.match(prompt, /Resolved bootstrap context/u);
    assert.match(prompt, /\.agents\/skills\/finalization\/SKILL.md/u);
    assert.match(prompt, /Established validation tuple/u);
    for (const { command } of saved.pipelineState.requiredChecks)
      assert.ok(prompt.includes(command));
  }
  const projection = polishingPipeline.projections.pause(failed);
  assert.deepEqual(projection.evidence, [
    "finalization: checks (complete-ordered-check-results).",
  ]);
  assert.deepEqual(projection.nextActions, []);
  assert.equal(projection.resumeState, null);
  const status = { run: failed, directoryPath: "/state/run" };
  const control = createMcpControlPlane({
    runner: { status: async () => status },
    runStore: { inspectRunLeaseOwner: async () => ({ status: "none" }) },
  });
  assert.deepEqual(
    (await control.runStatus({ runId: failed.runId })).pause,
    projection,
  );
  let output = "";
  assert.equal(
    await main(["status", "--run", failed.runId], {
      runner: { status: async () => status },
      stdout: {
        write: (value) => {
          output += value;
        },
      },
      stderr: { write: (value) => assert.fail(value) },
    }),
    0,
  );
  assert.match(
    output,
    /finalization: checks \(complete-ordered-check-results\)\./u,
  );
  assert.doesNotMatch(output, /agent-run resume/u);
});

test("a corrected semantic report rejoins the gate without changing budgets or inventories", async (t) => {
  for (const invalid of [
    { ...finalizationPassed(), checks: finalizationFailed().checks },
    malformedEvidence(),
    {
      ...finalizationUnavailable("SKILL_INVALID"),
      checks: finalizationPassed().checks,
    },
  ]) {
    const fixture = await createFixture(t, {
      worker: [...bootstrap(), invalid, finalizationPassed()],
    });
    const result = await fixture.run();
    assert.equal(result.pipelineState.workflowState, "DONE");
    assert.equal(turns(fixture).length, 2);
    assert.equal(turns(fixture)[1].access, "read-only");
    assert.deepEqual(
      result.pipelineState.requiredChecks,
      finalizationPassed().requiredChecks,
    );
    assert.deepEqual(result.counters, {
      clarificationRounds: 0,
      productDecisions: 0,
      fixRounds: 0,
      correctionRounds: 0,
    });
    assert.equal(result.pipelineState.finalizationRecovery.attempts, 0);
  }
});

test("legacy unknown correction identities reconstruct generically without a new allowance", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    worker: [...bootstrap(), malformedEvidence(), finalizationPassed()],
    onRoleRun(_role, request) {
      if (
        request.schema === FINALIZATION_SCHEMA &&
        request.access === "read-only" &&
        !interrupted
      ) {
        interrupted = true;
        throw Object.assign(new Error("Provider temporarily unavailable."), {
          code: "ERR_POLISHING_BACKEND_UNAVAILABLE",
          recoverable: true,
        });
      }
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  const correction = {
    ...paused.pipelineState.finalizationCorrection,
    field: "legacyField",
    constraint: "legacyConstraint",
  };
  await fixture.persistPipelineState({
    ...paused.pipelineState,
    finalizationCorrection: correction,
    pendingFinalizationCorrection: correction,
  });
  assertRun(fixture.currentRun);
  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.counters, paused.counters);
  assert.equal(
    fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "finalization-correction",
    ).length,
    1,
  );
  const reconstructed = turns(fixture).at(-1);
  assert.equal(reconstructed.access, "read-only");
  assert.equal(reconstructed.session, undefined);
  for (const prompt of [reconstructed.prompt, reconstructed.recoveryPrompt]) {
    assert.match(prompt, /semantic-contract/u);
    assert.doesNotMatch(prompt, /legacyField|legacyConstraint/u);
  }
});

test("unknown diagnostic-like identities are reduced on errors, durable feedback and public output", async (t) => {
  for (const value of [
    null,
    { field: PRIVATE, constraint: "object" },
    { field: "checks[512].evidence", constraint: "object" },
    { field: "issues[32].id", constraint: "finalization-issue-id" },
    { field: "validationInfrastructure[0].status", constraint: "object" },
    { field: "requiredChecks[0].checkId", constraint: "required-check-id" },
    { field: "checks[0].evidence[32]", constraint: "object" },
    { field: "result", constraint: PRIVATE },
    { field: "result", constraint: "object\n" },
  ]) {
    assert.deepEqual(finalizationDiagnostic(value), {
      field: "result",
      constraint: "semantic-contract",
    });
  }
  let injections = 0;
  const fixture = await createFixture(t, {
    onRoleRun(_role, request) {
      if (request.schema !== FINALIZATION_SCHEMA) return;
      injections += 1;
      throw Object.assign(new Error(PRIVATE), {
        code: "ERR_INVALID_POLISHING_OUTPUT",
        diagnostic: contextual(PRIVATE, PRIVATE),
        stderr: PRIVATE,
      });
    },
  });
  await assert.rejects(fixture.run(), (error) => {
    assert.deepEqual(
      error.diagnostic,
      contextual("result", "semantic-contract"),
    );
    assert.doesNotMatch(
      String(error) + JSON.stringify(error),
      /PRIVATE_REJECTED_VALUE/u,
    );
    return true;
  });
  assert.equal(injections, 2);
  const failed = fixture.currentRun;
  const hostile = structuredClone(failed);
  hostile.pause.diagnostic = contextual(PRIVATE, PRIVATE);
  assert.deepEqual(polishingPipeline.projections.pause(hostile).evidence, [
    "finalization: result (semantic-contract).",
  ]);
  assert.doesNotMatch(
    JSON.stringify(failed) +
      JSON.stringify(fixture.transitions) +
      JSON.stringify(turns(fixture)),
    /PRIVATE_REJECTED_VALUE/u,
  );
});
