import assert from "node:assert/strict";
import test from "node:test";

import * as commitPlanApi from "../src/index.js";

const {
  assertCommitSubject,
  COMMIT_TYPES,
  CommitPlanValidationError,
  MAX_COMMIT_SUBJECT_LENGTH,
  validateCommitSubject,
} = commitPlanApi;
const SUBJECT_PREFIX = "feat(core): ";

test("accepts the shared Conventional Commit subject format", () => {
  const maximumLengthSubject = `${SUBJECT_PREFIX}${"x".repeat(
    MAX_COMMIT_SUBJECT_LENGTH - SUBJECT_PREFIX.length,
  )}`;

  assert.equal(
    assertCommitSubject("feat(market): add repository"),
    "feat(market): add repository",
  );
  assert.equal(
    assertCommitSubject("fix(agent-runner)!: reject unsafe commit"),
    "fix(agent-runner)!: reject unsafe commit",
  );
  assert.equal(
    assertCommitSubject("fix(git): reject Co-authored-by trailers"),
    "fix(git): reject Co-authored-by trailers",
  );
  assert.equal(assertCommitSubject(maximumLengthSubject), maximumLengthSubject);
});

test("rejects invalid commit subjects", () => {
  for (const subject of [
    "Add repository",
    "feat: add repository",
    "Feat(core): add API",
    "feat(core): add repository.",
    "feat(core): add repository\n\nCo-authored-by: Agent <agent@example.test>",
    `${SUBJECT_PREFIX}${"x".repeat(
      MAX_COMMIT_SUBJECT_LENGTH - SUBJECT_PREFIX.length + 1,
    )}`,
  ]) {
    assert.notEqual(validateCommitSubject(subject).length, 0, subject);
  }

  assert.throws(
    () => assertCommitSubject("invalid"),
    (error) =>
      error instanceof CommitPlanValidationError &&
      error.code === "ERR_INVALID_COMMIT_SUBJECT" &&
      Object.isFrozen(error.issues),
  );
});

test("exports the allowed type set as immutable data", () => {
  assert.deepEqual(COMMIT_TYPES, [
    "feat",
    "fix",
    "refactor",
    "perf",
    "test",
    "docs",
    "build",
    "ci",
    "chore",
    "revert",
  ]);
  assert.ok(Object.isFrozen(COMMIT_TYPES));
});

test("keeps the validation pattern internal", () => {
  assert.equal(typeof assertCommitSubject, "function");
  assert.equal("COMMIT_SUBJECT_PATTERN" in commitPlanApi, false);
});
