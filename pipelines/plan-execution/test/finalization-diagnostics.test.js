import assert from "node:assert/strict";
import test from "node:test";

import { planExecutionPipeline } from "../src/index.js";
import { FINALIZATION_SCHEMA } from "../src/schemas.js";
import {
  assertRun,
  normalizeFinalizationResult,
  normalizePipelineState,
} from "../src/workflow-contract.js";
import {
  bootstrapReady,
  clarificationReady,
  createFixture,
  finalizationBlocked,
  finalizationFailed,
  finalizationPassed,
  finalizationUnavailable,
  finalizationWithTrustedCheck,
  implementationCompleted,
  reconciliationResolved,
  trustedValidationSnapshot,
} from "./support/index.js";

const PRIVATE = "PRIVATE_REJECTED_VALUE";
const diagnostic = (field, constraint) => ({ field, constraint });
const contextual = (entry) => ({
  role: "worker",
  phase: "finalization",
  contract: "finalization",
  ...entry,
});
const idViolation = diagnostic(
  "checks[0].checkId",
  "required-check-id-in-order",
);
const evidenceViolation = diagnostic(
  "checks[0].evidence",
  "nonempty-array-up-to-32-items",
);

function malformed({ id = false, evidence = false, command = false } = {}) {
  const result = structuredClone(finalizationPassed());
  if (id) result.checks[0].checkId = PRIVATE;
  if (evidence) result.checks[0].evidence = [];
  if (command) result.checks[0].command = PRIVATE;
  return result;
}

function rejectsWith(payload, expected, options) {
  assert.throws(
    () => normalizeFinalizationResult(payload, options),
    (cause) => {
      assert.equal(cause.code, "ERR_INVALID_PLAN_EXECUTION_OUTPUT");
      assert.deepEqual(cause.diagnostics ?? [cause.diagnostic], expected);
      assert.doesNotMatch(
        String(cause) + JSON.stringify(cause),
        /PRIVATE_REJECTED_VALUE/u,
      );
      return true;
    },
  );
}

test("finalization violations identify trusted fields without rejected values", () => {
  const passed = finalizationPassed();
  const check = passed.checks[0];
  const checkPatch = (patch) => ({
    ...passed,
    checks: [{ ...check, ...patch }],
  });
  const cases = [
    [null, "result", "object"],
    [{ ...passed, status: PRIVATE }, "status", "finalization-status"],
    [{ ...passed, [PRIVATE]: true }, "result", "exact-field-set"],
    [checkPatch({ [PRIVATE]: true }), "checks[0]", "exact-field-set"],
    [malformed({ id: true }), idViolation.field, idViolation.constraint],
    [
      malformed({ command: true }),
      "checks[0].command",
      "required-check-command",
    ],
    [
      checkPatch({ command: " node --version" }),
      "checks[0].command",
      "exact-single-line-command-up-to-4000-characters",
    ],
    [
      checkPatch({ status: PRIVATE }),
      "checks[0].status",
      "check-result-status",
    ],
    [
      checkPatch({ status: "NOT_RUN" }),
      "checks[0].status",
      "agent-executed-check-status",
    ],
    [
      malformed({ evidence: true }),
      evidenceViolation.field,
      evidenceViolation.constraint,
    ],
    [
      checkPatch({ evidence: [PRIVATE.repeat(200)] }),
      "checks[0].evidence[0]",
      "nonempty-plain-text-up-to-4000-characters",
    ],
    [{ ...passed, checks: [] }, "checks", "complete-ordered-check-results"],
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
    [
      { ...finalizationUnavailable("SKILL_INVALID"), skillPath: "" },
      "skillPath",
      "selected-finalization-guidance",
    ],
    [
      { ...finalizationUnavailable("SKILL_MISSING"), reason: "" },
      "reason",
      "nonempty-plain-text-up-to-4000-characters",
    ],
    [
      {
        ...finalizationBlocked("Unavailable.", "No service."),
        checks: passed.checks,
      },
      "checks",
      "finalization-status-checks",
    ],
    [
      { ...finalizationFailed("F1"), issues: [] },
      "issues",
      "finalization-status-issues",
    ],
    [
      { ...finalizationFailed("F1"), checks: passed.checks },
      "checks",
      "finalization-status-checks",
    ],
    [
      { ...passed, issues: finalizationFailed("F1").issues },
      "issues",
      "finalization-status-issues",
    ],
  ];
  for (const [payload, field, constraint] of cases)
    rejectsWith(payload, [diagnostic(field, constraint)]);

  const failed = finalizationFailed("F1");
  for (const [patch, field, constraint] of [
    [{ id: PRIVATE }, "id", "finalization-issue-id"],
    [{ command: "" }, "command", "nonempty-plain-text-up-to-4000-characters"],
    [{ problem: "" }, "problem", "nonempty-plain-text-up-to-4000-characters"],
    [{ evidence: [] }, "evidence", "nonempty-array-up-to-32-items"],
  ])
    rejectsWith({ ...failed, issues: [{ ...failed.issues[0], ...patch }] }, [
      diagnostic(`issues[0].${field}`, constraint),
    ]);
});

test("finalization batches independent violations without inventing dependent ones", () => {
  rejectsWith(malformed({ id: true, command: true, evidence: true }), [
    idViolation,
    diagnostic("checks[0].command", "required-check-command"),
    evidenceViolation,
  ]);
  rejectsWith(
    { ...malformed({ id: true }), reason: PRIVATE, question: PRIVATE },
    [
      diagnostic("reason", "empty-string"),
      diagnostic("question", "empty-string"),
      idViolation,
    ],
  );
  rejectsWith({ ...malformed({ id: true }), requiredChecks: [], summary: "" }, [
    diagnostic("requiredChecks", "nonempty-array-up-to-512-items"),
    diagnostic("summary", "concise-markdown-up-to-20000-characters"),
  ]);
  const requiredChecks = Array.from({ length: 512 }, (_, index) => ({
    id: `C${index + 1}`,
    command: `node check-${index + 1}.js`,
  }));
  rejectsWith(
    {
      ...finalizationPassed(),
      requiredChecks,
      checks: requiredChecks.map(({ command }) => ({
        checkId: PRIVATE,
        command,
        status: "PASS",
        evidence: [],
      })),
    },
    requiredChecks
      .slice(0, 256)
      .flatMap((_, index) => [
        diagnostic(`checks[${index}].checkId`, "required-check-id-in-order"),
        diagnostic(
          `checks[${index}].evidence`,
          "nonempty-array-up-to-32-items",
        ),
      ]),
  );
  const unsafe = requiredChecks.map((check) => ({
    ...check,
    command: `git diff --check && ${check.command}`,
  }));
  rejectsWith(
    {
      ...finalizationPassed(),
      reason: PRIVATE,
      requiredChecks: unsafe,
      checks: [],
    },
    unsafe.map((_, index) =>
      diagnostic(
        `requiredChecks[${index}].command`,
        "staging-independent-validation-command",
      ),
    ),
  );
});

test("reserved placeholders require NOT_RUN and preserve ordered identity", () => {
  const trusted = trustedValidationSnapshot();
  const payload = finalizationWithTrustedCheck(trusted);
  const options = {
    trustedCommands: trusted.commands.map(({ command }) => command),
  };
  assert.equal(normalizeFinalizationResult(payload, options).status, "PASS");
  rejectsWith(
    {
      ...payload,
      checks: payload.checks.map((check) => ({ ...check, status: "PASS" })),
    },
    [diagnostic("checks[1].status", "runner-trusted-not-run")],
    options,
  );
  const unreserved = {
    ...payload,
    checks: payload.checks.map((check) => ({ ...check, status: "PASS" })),
  };
  rejectsWith({ ...unreserved, checks: [...unreserved.checks].reverse() }, [
    idViolation,
    diagnostic("checks[0].command", "required-check-command"),
    diagnostic("checks[1].checkId", "required-check-id-in-order"),
    diagnostic("checks[1].command", "required-check-command"),
  ]);
});

test("distinct finalization diagnostics survive interruption and Runner replacement", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const passed = finalizationWithTrustedCheck(trustedValidation);
  const invalid = (patch) => ({
    ...passed,
    checks: [patch.checks[0], passed.checks[1]],
  });
  const bootstrap = (role) => ({
    ...bootstrapReady(role),
    requiredChecks: passed.requiredChecks,
  });
  let executed = 0;
  const fixture = await createFixture(t, {
    trustedValidation,
    worker: [
      clarificationReady(),
      bootstrap("Worker"),
      reconciliationResolved(),
    ],
    reviewer: [bootstrap("Reviewer")],
    workWorker: [
      implementationCompleted(),
      invalid(malformed({ id: true })),
      invalid(malformed({ evidence: true })),
      passed,
    ],
    onTrustedValidation(options) {
      executed += 1;
      return {
        status: "PASS",
        commandIdentity: options.commandIdentity,
        exitCode: 0,
        signal: null,
        timedOut: false,
        evidence: ["Runner-trusted command exited with code 0."],
        ...options.bindings,
      };
    },
  });
  const stop = new Error("Interrupted before second correction.");
  const transition = fixture.runtime.transition;
  let stopped = false;
  fixture.runtime.transition = async (patch, options) => {
    if (stopped) throw stop;
    const result = await transition(patch, options);
    if (patch.pipelineState.pendingFinalizationCorrection?.attempt === 2)
      stopped = true;
    return result;
  };
  const start = fixture.runtime.startAgentTurn;
  fixture.runtime.startAgentTurn = (turn) => {
    if (stopped) throw stop;
    return start(turn);
  };
  await assert.rejects(
    fixture.run({ trustedChecks: ["service-check"] }),
    (cause) => cause === stop,
  );
  assert.equal(executed, 0);
  assertRun(fixture.currentRun);
  const saved = normalizePipelineState(
    JSON.parse(JSON.stringify(fixture.currentRun.pipelineState)),
  );
  assert.deepEqual(
    saved.finalizationCorrections.map(({ diagnostics }) => diagnostics),
    [[contextual(idViolation)], [contextual(evidenceViolation)]],
  );
  fixture.persistPipelineState(saved);
  stopped = false;
  fixture.runtime.transition = transition;
  fixture.runtime.startAgentTurn = start;
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(executed, 1);
  assert.equal(
    completed.pipelineState.finalizationResult.checks[1].executor,
    "runner",
  );
  assert.deepEqual(
    fixture.transitions
      .filter(
        ({ options }) => options.activity?.kind === "finalization-correction",
      )
      .at(-1).patch.pipelineState.finalizationCorrections,
    saved.finalizationCorrections,
  );
  const requests = fixture.calls.worker.filter(
    ({ schema }) => schema === FINALIZATION_SCHEMA,
  );
  assert.equal(requests.length, 3);
  const correction = requests.at(-1);
  assert.equal(correction.access, "read-only");
  assert.match(correction.prompt, /checks\[0\]\.evidence/u);
  assert.doesNotMatch(
    correction.prompt + correction.recoveryPrompt,
    /PRIVATE_REJECTED_VALUE/u,
  );
});

for (const [name, invalid, attempts, field, constraint] of [
  [
    "repeated",
    [malformed({ id: true }), malformed({ id: true })],
    1,
    idViolation.field,
    idViolation.constraint,
  ],
  [
    "mixed",
    [malformed({ id: true }), malformed({ id: true, evidence: true })],
    1,
    idViolation.field,
    idViolation.constraint,
  ],
  [
    "exhausted",
    [
      malformed({ id: true }),
      malformed({ evidence: true }),
      malformed({ command: true }),
    ],
    2,
    "checks[0].command",
    "required-check-command",
  ],
]) {
  test(`finalization ${name} violations fail closed with redacted public details`, async (t) => {
    const fixture = await createFixture(t, {
      workWorker: [implementationCompleted(), ...invalid],
      workReviewer: [],
    });
    await assert.rejects(
      fixture.run(),
      (cause) => cause.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
    );
    const failed = fixture.currentRun;
    assert.equal(failed.pipelineState.workflowState, "FAILED");
    assertRun(failed);
    assert.equal(failed.pipelineState.finalizationCorrections.length, attempts);
    assert.deepEqual(
      failed.pause.diagnostic,
      contextual(diagnostic(field, constraint)),
    );
    const projection = planExecutionPipeline.projections.pause(failed);
    assert.deepEqual(projection.evidence, [
      `finalization: ${field} (${constraint}).`,
    ]);
    assert.deepEqual(projection.nextActions, []);
    if (name === "repeated") {
      const unknown = structuredClone(failed);
      unknown.pause.diagnostic = contextual(
        diagnostic("result", "semantic-contract"),
      );
      assert.deepEqual(
        planExecutionPipeline.projections.pause(unknown).evidence,
        ["finalization: result (semantic-contract)."],
      );
    }
    assert.doesNotMatch(
      JSON.stringify(failed) +
        JSON.stringify(fixture.transitions) +
        JSON.stringify(projection),
      /PRIVATE_REJECTED_VALUE/u,
    );
  });
}
