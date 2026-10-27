const HEADER_FIELDS = new Set(["kind", "criteria", "inputs", "outputs"]);
const PLAN_FIELDS = new Set([...HEADER_FIELDS, "steps"]);
const CRITERION_FIELDS = new Set(["id", "condition"]);
const STEP_FIELDS = new Set([
  "number",
  "title",
  "work",
  "expectedResults",
  "criterionRefs",
]);
const STEP_PATTERN = /^## Step ([1-9][0-9]*): (.*)$/u;
const CRITERION_ID_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
const SECTION_HEADINGS = ["### Work", "### Expected results", "### Criteria"];
const RESERVED_BODY_HEADING = /^#{2,3}(?:[ \t]|$)/mu;

export class CustomPlanValidationError extends Error {
  constructor(issues) {
    super("Invalid custom plan.");
    this.name = "CustomPlanValidationError";
    this.code = "ERR_INVALID_CUSTOM_PLAN";
    this.issues = Object.freeze([...issues]);
  }
}

function isRecord(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

function normalizeText(value) {
  const lines = value.replace(/\r\n?/gu, "\n").split("\n");
  let start = 0;
  let end = lines.length;
  while (start < end && lines[start].trim() === "") start += 1;
  while (end > start && lines[end - 1].trim() === "") end -= 1;
  return lines.slice(start, end).join("\n");
}

function rejectUnknownFields(value, fields, path, issues) {
  for (const field of Object.keys(value)) {
    if (!fields.has(field)) issues.push(`${path}.${field} is not supported.`);
  }
}

function isText(value) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    !value.includes("\0")
  );
}

function isSingleLine(value) {
  return (
    isText(value) &&
    value === value.trim() &&
    !/[\u0000-\u001f\u007f\u2028\u2029]/u.test(value)
  );
}

function validateList(value, path, issues, { required = false } = {}) {
  if (!Array.isArray(value)) {
    issues.push(`${path} must be an array.`);
    return [];
  }
  if (required && value.length === 0) {
    issues.push(`${path} must contain at least one reference.`);
  }
  const seen = new Set();
  for (const item of value) {
    if (!isSingleLine(item)) {
      issues.push(
        `${path} entries must be nonempty, trimmed single-line strings.`,
      );
    } else if (seen.has(item)) {
      issues.push(`${path} must not contain duplicate references.`);
    } else {
      seen.add(item);
    }
  }
  return [...seen];
}

function inspectCriteria(criteria) {
  const issues = [];
  const criterionIds = new Set();
  if (!Array.isArray(criteria) || criteria.length === 0) {
    issues.push("Custom plan criteria must be a nonempty array.");
  } else {
    for (const [index, criterion] of criteria.entries()) {
      const path = `Criterion ${index + 1}`;
      if (!isRecord(criterion)) {
        issues.push(`${path} must be an object.`);
        continue;
      }
      rejectUnknownFields(criterion, CRITERION_FIELDS, path, issues);
      if (
        !isSingleLine(criterion.id) ||
        !CRITERION_ID_PATTERN.test(criterion.id)
      ) {
        issues.push(
          `${path} id must be a lowercase kebab-case reference starting with a letter.`,
        );
      } else if (criterionIds.has(criterion.id)) {
        issues.push(`${path} id must be unique.`);
      } else {
        criterionIds.add(criterion.id);
      }
      if (!isText(criterion.condition)) {
        issues.push(
          `${path} condition must be nonempty text without NUL characters.`,
        );
      }
    }
  }

  return { issues, criterionIds };
}

export function normalizeCustomCriteria(criteria) {
  const { issues } = inspectCriteria(criteria);
  if (issues.length > 0) throw new CustomPlanValidationError(issues);
  return Object.freeze(
    criteria.map(({ id, condition }) =>
      Object.freeze({ id, condition: normalizeText(condition) }),
    ),
  );
}

export function validateCustomPlan(plan) {
  if (!isRecord(plan)) return Object.freeze(["Custom plan must be an object."]);

  const issues = [];
  rejectUnknownFields(plan, PLAN_FIELDS, "Custom plan", issues);
  if (plan.kind !== "custom") {
    issues.push('Custom plan kind must be explicitly "custom".');
  }
  validateList(plan.inputs, "Custom plan inputs", issues);
  validateList(plan.outputs, "Custom plan outputs", issues);

  const { issues: criterionIssues, criterionIds } = inspectCriteria(
    plan.criteria,
  );
  issues.push(...criterionIssues);

  const usedCriteria = new Set();
  if (!Array.isArray(plan.steps) || plan.steps.length === 0) {
    issues.push("Custom plan must contain at least one step.");
  } else {
    for (const [index, step] of plan.steps.entries()) {
      const position = index + 1;
      const path = `Step ${position}`;
      if (!isRecord(step)) {
        issues.push(`${path} must be an object.`);
        continue;
      }
      rejectUnknownFields(step, STEP_FIELDS, path, issues);
      if (!Number.isSafeInteger(step.number) || step.number !== position) {
        issues.push(
          `${path} number must be ${position}, a positive safe integer.`,
        );
      }
      if (!isSingleLine(step.title)) {
        issues.push(
          `${path} title must be nonempty, trimmed single-line text.`,
        );
      }
      for (const field of ["work", "expectedResults"]) {
        if (!isText(step[field])) {
          issues.push(
            `${path}.${field} must be nonempty text without NUL characters.`,
          );
        } else if (
          RESERVED_BODY_HEADING.test(step[field].replace(/\r\n?/gu, "\n"))
        ) {
          issues.push(
            `${path}.${field} must not contain level-two or level-three headings.`,
          );
        }
      }
      for (const reference of validateList(
        step.criterionRefs,
        `${path} criterionRefs`,
        issues,
        { required: true },
      )) {
        if (!criterionIds.has(reference)) {
          issues.push(`${path} references an unknown criterion: ${reference}.`);
        } else {
          usedCriteria.add(reference);
        }
      }
    }
  }
  for (const id of criterionIds) {
    if (!usedCriteria.has(id))
      issues.push(`Criterion ${id} must be referenced by at least one step.`);
  }
  return Object.freeze(issues);
}

export function assertCustomPlan(plan) {
  const issues = validateCustomPlan(plan);
  if (issues.length > 0) throw new CustomPlanValidationError(issues);
  return plan;
}

function normalizedHeader(plan) {
  return {
    kind: plan.kind,
    criteria: normalizeCustomCriteria(plan.criteria),
    inputs: [...plan.inputs],
    outputs: [...plan.outputs],
  };
}

function freezePlan(plan) {
  const header = normalizedHeader(plan);
  return Object.freeze({
    ...header,
    criteria: Object.freeze(
      header.criteria.map((criterion) => Object.freeze(criterion)),
    ),
    inputs: Object.freeze(header.inputs),
    outputs: Object.freeze(header.outputs),
    steps: Object.freeze(
      plan.steps.map((step) =>
        Object.freeze({
          ...step,
          work: normalizeText(step.work),
          expectedResults: normalizeText(step.expectedResults),
          criterionRefs: Object.freeze([...step.criterionRefs]),
        }),
      ),
    ),
  });
}

function parseStep(delimiter, body) {
  const sections = [[], [], []];
  let section = -1;
  for (const line of body) {
    if (/^###(?:[ \t]|$)/u.test(line)) {
      if (line !== SECTION_HEADINGS[section + 1]) {
        throw new CustomPlanValidationError([
          `Step ${delimiter.number} sections must be Work, Expected results, and Criteria in that order.`,
        ]);
      }
      section += 1;
    } else if (section < 0) {
      if (line.trim())
        throw new CustomPlanValidationError([
          `Step ${delimiter.number} must start with a Work section.`,
        ]);
    } else {
      sections[section].push(line);
    }
  }
  if (section !== 2)
    throw new CustomPlanValidationError([
      `Step ${delimiter.number} requires Work, Expected results, and Criteria sections.`,
    ]);

  const criterionRefs = sections[2]
    .filter((line) => line.trim())
    .map((line) => {
      if (!line.startsWith("- ") || !CRITERION_ID_PATTERN.test(line.slice(2))) {
        throw new CustomPlanValidationError([
          `Step ${delimiter.number} Criteria must contain only "- <criterion-id>" lines.`,
        ]);
      }
      return line.slice(2);
    });
  return {
    number: delimiter.number,
    title: delimiter.title,
    work: normalizeText(sections[0].join("\n")),
    expectedResults: normalizeText(sections[1].join("\n")),
    criterionRefs,
  };
}

export function parseCustomPlan(source) {
  if (typeof source !== "string")
    throw new CustomPlanValidationError([
      "Custom plan source must be a string.",
    ]);
  const lines = source.replace(/\r\n?/gu, "\n").split("\n");
  const headerEnd = lines.indexOf("```", 1);
  if (lines[0] !== "```json" || headerEnd < 0) {
    throw new CustomPlanValidationError([
      "Custom plan must start with a fenced JSON declaration on line 1.",
    ]);
  }
  let header;
  try {
    header = JSON.parse(lines.slice(1, headerEnd).join("\n"));
  } catch {
    throw new CustomPlanValidationError([
      "Custom plan declaration must be valid JSON.",
    ]);
  }
  if (!isRecord(header))
    throw new CustomPlanValidationError([
      "Custom plan declaration must be an object.",
    ]);
  const issues = [];
  rejectUnknownFields(header, HEADER_FIELDS, "Custom plan declaration", issues);

  const delimiters = [];
  for (let index = headerEnd + 1; index < lines.length; index += 1) {
    const line = lines[index];
    const match = STEP_PATTERN.exec(line);
    if (match) {
      delimiters.push({
        lineIndex: index,
        number: Number(match[1]),
        title: match[2],
      });
    } else if (/^##(?:[ \t]|$)/u.test(line)) {
      issues.push(
        `Line ${index + 1} must match "## Step N: <title>" with a positive integer N.`,
      );
    } else if (delimiters.length === 0 && line.trim()) {
      issues.push(
        `Line ${index + 1} must be a step delimiter or blank after the declaration.`,
      );
    }
  }
  if (issues.length > 0) throw new CustomPlanValidationError(issues);
  const plan = {
    ...header,
    steps: delimiters.map((delimiter, index) =>
      parseStep(
        delimiter,
        lines.slice(
          delimiter.lineIndex + 1,
          delimiters[index + 1]?.lineIndex ?? lines.length,
        ),
      ),
    ),
  };
  assertCustomPlan(plan);
  return freezePlan(plan);
}

export function serializeCustomPlan(plan) {
  assertCustomPlan(plan);
  const header = `\`\`\`json\n${JSON.stringify(normalizedHeader(plan), null, 2)}\n\`\`\``;
  const steps = plan.steps.map((step) =>
    [
      `## Step ${step.number}: ${step.title}`,
      SECTION_HEADINGS[0],
      normalizeText(step.work),
      SECTION_HEADINGS[1],
      normalizeText(step.expectedResults),
      SECTION_HEADINGS[2],
      step.criterionRefs.map((reference) => `- ${reference}`).join("\n"),
    ].join("\n\n"),
  );
  return `${[header, ...steps].join("\n\n")}\n`;
}
