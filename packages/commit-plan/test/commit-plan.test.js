import assert from "node:assert/strict";
import test from "node:test";

import * as commitPlanApi from "../src/index.js";

const {
  assertCommitPlan,
  CommitPlanValidationError,
  parseCommitPlan,
  serializeCommitPlan,
  validateCommitPlan,
} = commitPlanApi;

const VALID_PLAN = [
  "## Commit 1: feat(market): add repository",
  "",
  "### Goal",
  "",
  "Add the repository boundary.",
  "",
  "## Commit 2: test(market): cover repository",
  "",
  "Keep `## Commitments` and `### Commit 7: example` as body text.",
  "",
].join("\n");

test("parses sequential commit steps and preserves opaque bodies", () => {
  const plan = parseCommitPlan(VALID_PLAN);

  assert.deepEqual(plan, {
    steps: [
      {
        number: 1,
        subject: "feat(market): add repository",
        body: "\n### Goal\n\nAdd the repository boundary.\n",
      },
      {
        number: 2,
        subject: "test(market): cover repository",
        body: "\nKeep `## Commitments` and `### Commit 7: example` as body text.\n",
      },
    ],
  });
  assert.ok(Object.isFrozen(plan));
  assert.ok(Object.isFrozen(plan.steps));
  assert.ok(plan.steps.every((step) => Object.isFrozen(step)));
});

test("serializes plans deterministically with stable round trips", () => {
  const parsed = parseCommitPlan(VALID_PLAN.replaceAll("\n", "\r\n"));
  const serialized = serializeCommitPlan(parsed);

  assert.equal(serialized, VALID_PLAN);
  assert.deepEqual(parseCommitPlan(serialized), parsed);

  const manualPlan = {
    steps: [
      {
        number: 1,
        subject: "docs(core): explain behavior",
        body: "\r\n### Goal\r\n",
      },
    ],
  };
  assert.equal(
    serializeCommitPlan(manualPlan),
    "## Commit 1: docs(core): explain behavior\n\n### Goal\n",
  );
  assert.equal(manualPlan.steps[0].body, "\r\n### Goal\r\n");

  assert.equal(
    serializeCommitPlan({
      steps: [
        {
          number: 1,
          subject: "docs(core): preserve opaque body",
          body: "##\nCommit remains body text.",
        },
      ],
    }),
    [
      "## Commit 1: docs(core): preserve opaque body",
      "##",
      "Commit remains body text.",
    ].join("\n"),
  );
});

test("rejects empty, malformed, non-sequential, and invalid plans", () => {
  const invalidPlans = [
    ["", /at least one commit step/u],
    ["   \n", /at least one commit step/u],
    [
      "# Plan\n## Commit 1: feat(core): add behavior",
      /must start with a delimiter on line 1/u,
    ],
    [
      "## Commit one: feat(core): add behavior",
      /Line 1 resembles a commit delimiter/u,
    ],
    [
      "## Commit 1 feat(core): add behavior",
      /Line 1 resembles a commit delimiter/u,
    ],
    [
      "## Commit: feat(core): add behavior",
      /Line 1 resembles a commit delimiter/u,
    ],
    [
      "##  Commit 1: feat(core): add behavior",
      /Line 1 resembles a commit delimiter/u,
    ],
    [
      "## Commit 01: feat(core): add behavior",
      /Line 1 resembles a commit delimiter/u,
    ],
    ["## Commit 1: ", /Commit step 1: Commit subject/u],
    ["## Commit 1: feat: add behavior", /Commit step 1: Commit subject/u],
    [
      "## Commit 2: feat(core): add behavior",
      /Commit step 1 number must be 1/u,
    ],
    [
      [
        "## Commit 1: feat(core): add behavior",
        "## Commit 3: test(core): cover behavior",
      ].join("\n"),
      /Commit step 2 number must be 2/u,
    ],
    [
      [
        "## Commit 1: feat(core): add behavior",
        "## Commit 1: test(core): cover behavior",
      ].join("\n"),
      /Commit step 2 number must be 2/u,
    ],
    [
      [
        "## Commit 1: feat(core): add behavior",
        "## Commit next: this is reserved",
      ].join("\n"),
      /Line 2 resembles a commit delimiter/u,
    ],
  ];

  for (const [source, expectedIssue] of invalidPlans) {
    assert.throws(
      () => parseCommitPlan(source),
      (error) =>
        error instanceof CommitPlanValidationError &&
        error.code === "ERR_INVALID_COMMIT_PLAN" &&
        error.issues.some((issue) => expectedIssue.test(issue)),
      source,
    );
  }
  assert.throws(
    () => parseCommitPlan({}),
    (error) =>
      error instanceof CommitPlanValidationError &&
      error.issues.includes("Commit plan source must be a string."),
  );
});

test("validates the complete serializable plan shape", () => {
  const validPlan = {
    steps: [
      {
        number: 1,
        subject: "feat(core): add behavior",
        body: "\nBody.\n",
      },
    ],
  };

  assert.equal(assertCommitPlan(validPlan), validPlan);
  assert.deepEqual(validateCommitPlan(validPlan), []);
  assert.ok(Object.isFrozen(validateCommitPlan(validPlan)));

  for (const plan of [
    null,
    {},
    { steps: [] },
    { steps: [], extra: true },
    { steps: [null] },
    { steps: [{}] },
    {
      steps: [
        {
          number: 1,
          subject: "feat(core): add behavior",
          body: "",
          extra: true,
        },
      ],
    },
    {
      steps: [{ number: 2, subject: "feat(core): add behavior", body: "" }],
    },
    { steps: [{ number: 1, subject: "invalid", body: "" }] },
    {
      steps: [{ number: 1, subject: "feat(core): add behavior", body: null }],
    },
    {
      steps: [
        {
          number: 1,
          subject: "feat(core): add behavior",
          body: "Body.\n## Commit next: reserved",
        },
      ],
    },
  ]) {
    assert.throws(
      () => serializeCommitPlan(plan),
      (error) =>
        error instanceof CommitPlanValidationError &&
        error.code === "ERR_INVALID_COMMIT_PLAN" &&
        error.issues.length > 0,
    );
  }
});

test("exports only the public commit-plan contract", () => {
  assert.deepEqual(Object.keys(commitPlanApi).sort(), [
    "COMMIT_TYPES",
    "CommitPlanValidationError",
    "MAX_COMMIT_SUBJECT_LENGTH",
    "assertCommitPlan",
    "assertCommitSubject",
    "parseCommitPlan",
    "serializeCommitPlan",
    "validateCommitPlan",
    "validateCommitSubject",
  ]);
});
