import {
  CommitPlanValidationError,
  validateCommitSubject,
} from "./commit-subject.js";

const DELIMITER_PATTERN = /^## Commit ([1-9][0-9]*): (.*)$/u;
const DELIMITER_CANDIDATE_PATTERN = /^##[ \t]+Commit(?:[ \t]|[0-9]|:|$)/mu;
const PLAN_FIELDS = new Set(["steps"]);
const STEP_FIELDS = new Set(["number", "subject", "body"]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function normalizeLineEndings(value) {
  return value.replace(/\r\n?/gu, "\n");
}

function rejectUnknownFields(value, allowedFields, path, issues) {
  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      issues.push(`${path}.${field} is not supported.`);
    }
  }
}

function invalidPlan(issues) {
  return new CommitPlanValidationError("Invalid commit plan.", issues);
}

function freezeCommitPlan(plan) {
  return Object.freeze({
    steps: Object.freeze(plan.steps.map((step) => Object.freeze({ ...step }))),
  });
}

export function validateCommitPlan(plan) {
  if (!isRecord(plan)) {
    return Object.freeze(["Commit plan must be an object."]);
  }

  const issues = [];
  rejectUnknownFields(plan, PLAN_FIELDS, "Commit plan", issues);

  if (!Array.isArray(plan.steps)) {
    issues.push("Commit plan steps must be an array.");
    return Object.freeze(issues);
  }
  if (plan.steps.length === 0) {
    issues.push("Commit plan must contain at least one commit step.");
  }

  for (const [index, step] of plan.steps.entries()) {
    const position = index + 1;
    const path = `Commit step ${position}`;
    if (!isRecord(step)) {
      issues.push(`${path} must be an object.`);
      continue;
    }

    rejectUnknownFields(step, STEP_FIELDS, path, issues);

    if (!Number.isSafeInteger(step.number) || step.number < 1) {
      issues.push(`${path} number must be a positive safe integer.`);
    } else if (step.number !== position) {
      issues.push(
        `${path} number must be ${position}; received ${step.number}.`,
      );
    }

    for (const issue of validateCommitSubject(step.subject)) {
      issues.push(`${path}: ${issue}`);
    }

    if (typeof step.body !== "string") {
      issues.push(`${path} body must be a string.`);
    } else if (
      DELIMITER_CANDIDATE_PATTERN.test(normalizeLineEndings(step.body))
    ) {
      issues.push(`${path} body must not contain commit delimiter lines.`);
    }
  }

  return Object.freeze(issues);
}

export function assertCommitPlan(plan) {
  const issues = validateCommitPlan(plan);
  if (issues.length > 0) {
    throw invalidPlan(issues);
  }

  return plan;
}

export function parseCommitPlan(source) {
  if (typeof source !== "string") {
    throw invalidPlan(["Commit plan source must be a string."]);
  }

  const normalizedSource = normalizeLineEndings(source);
  if (normalizedSource.trim().length === 0) {
    throw invalidPlan(["Commit plan must contain at least one commit step."]);
  }

  const lines = normalizedSource.split("\n");
  const delimiters = [];
  const issues = [];

  for (const [lineIndex, line] of lines.entries()) {
    const match = DELIMITER_PATTERN.exec(line);
    if (match !== null) {
      delimiters.push({
        lineIndex,
        number: Number(match[1]),
        subject: match[2],
      });
    } else if (DELIMITER_CANDIDATE_PATTERN.test(line)) {
      issues.push(
        `Line ${lineIndex + 1} resembles a commit delimiter but must match "## Commit N: <subject>" with a positive integer N.`,
      );
    }
  }

  if (delimiters.length === 0) {
    issues.push("Commit plan must contain at least one commit step.");
  } else if (delimiters[0].lineIndex !== 0) {
    issues.push(
      `Commit plan must start with a delimiter on line 1; the first delimiter is on line ${delimiters[0].lineIndex + 1}.`,
    );
  }

  if (issues.length > 0) {
    throw invalidPlan(issues);
  }

  const plan = {
    steps: delimiters.map((delimiter, index) => {
      const nextLineIndex = delimiters[index + 1]?.lineIndex ?? lines.length;
      return {
        number: delimiter.number,
        subject: delimiter.subject,
        body: lines.slice(delimiter.lineIndex + 1, nextLineIndex).join("\n"),
      };
    }),
  };
  const validationIssues = validateCommitPlan(plan);
  if (validationIssues.length > 0) {
    throw invalidPlan(validationIssues);
  }

  return freezeCommitPlan(plan);
}

export function serializeCommitPlan(plan) {
  assertCommitPlan(plan);

  return plan.steps
    .map((step) => {
      const delimiter = `## Commit ${step.number}: ${step.subject}`;
      const body = normalizeLineEndings(step.body);
      return body.length === 0 ? delimiter : `${delimiter}\n${body}`;
    })
    .join("\n");
}
