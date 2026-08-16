export const COMMIT_TYPES = Object.freeze([
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

export const MAX_COMMIT_SUBJECT_LENGTH = 72;

const COMMIT_SUBJECT_PATTERN = new RegExp(
  `^(?:${COMMIT_TYPES.join("|")})\\([a-z0-9]+(?:-[a-z0-9]+)*\\)!?: \\S(?:.*\\S)?$`,
  "u",
);

export class CommitPlanValidationError extends Error {
  constructor(message, issues) {
    super(message);
    this.name = "CommitPlanValidationError";
    this.code = "ERR_INVALID_COMMIT_SUBJECT";
    this.issues = Object.freeze([...issues]);
  }
}

export function validateCommitSubject(subject) {
  if (typeof subject !== "string") {
    return Object.freeze(["Commit subject must be a string."]);
  }

  const issues = [];

  if (/\r|\n/u.test(subject)) {
    issues.push("Commit subject must contain exactly one line.");
  }

  if ([...subject].length > MAX_COMMIT_SUBJECT_LENGTH) {
    issues.push(
      `Commit subject must not exceed ${MAX_COMMIT_SUBJECT_LENGTH} Unicode code points.`,
    );
  }

  if (!COMMIT_SUBJECT_PATTERN.test(subject)) {
    issues.push(
      "Commit subject must match type(scope)[!]: imperative summary with an allowed type and kebab-case scope.",
    );
  }

  if (subject.endsWith(".")) {
    issues.push("Commit subject must not end with a period.");
  }

  return Object.freeze(issues);
}

export function assertCommitSubject(subject) {
  const issues = validateCommitSubject(subject);
  if (issues.length > 0) {
    throw new CommitPlanValidationError("Invalid commit subject.", issues);
  }

  return subject;
}
