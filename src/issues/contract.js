import { createHash } from "node:crypto";
import { basename, isAbsolute, resolve } from "node:path";

const ISSUE_SCHEMA_VERSION = 1;
const ISSUE_STATUSES = Object.freeze([
  "open",
  "queued",
  "in_progress",
  "resolved",
  "dismissed",
]);
export const MAX_ISSUE_BYTES = 256 * 1_024;
const MAX_PATH_LENGTH = 4_096;
const MAX_REQUEST_PATH_LENGTH = 16_384;
const MAX_MARKDOWN_LENGTH = 64 * 1_024;
const MAX_REFERENCES = 32;
const MAX_REFERENCE_LENGTH = 1_024;
const MAX_NOTE_LENGTH = 4_000;
const REPORT_FIELDS = Object.freeze({
  summary: 1_000,
  expectedBehavior: 4_000,
  actualBehavior: 4_000,
  occurrence: 4_000,
  unexpectedReason: 4_000,
  details: 16_000,
});
const REQUEST_FIELDS = new Set([
  ...Object.keys(REPORT_FIELDS),
  "idempotencyKey",
  "projectPath",
  "projectConfigurationPath",
  "runId",
  "errorCode",
]);

const ISSUE_ID =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const RUN_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu;
const ERROR_CODE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const HASH = /^[a-f0-9]{64}$/u;
// Markdown keeps tabs and line breaks; single-line values reject all controls.
const UNSAFE_MARKDOWN =
  /[\0\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F\p{Zl}\p{Zp}]/u;
const UNSAFE_LINE = /[\p{Cc}\p{Zl}\p{Zp}]/u;

const matches = (pattern, value) =>
  typeof value === "string" && pattern.test(value);

export class IssueError extends Error {
  constructor(message, { cause, code = "ERR_UNEXPECTED_ISSUE_REPORT" } = {}) {
    super(message, { cause });
    this.name = "IssueError";
    this.code = code;
  }
}

export const sha256 = (value) =>
  createHash("sha256").update(value).digest("hex");

export const isIssueId = (value) =>
  typeof value === "string" && ISSUE_ID.test(value);

export const isDocumentHash = (value) =>
  typeof value === "string" && HASH.test(value);

export const issueFilename = (issueId) => `${issueId}.json`;

export function safeAbsolutePath(value, paths = { isAbsolute, resolve }) {
  if (
    typeof value !== "string" ||
    value.length > MAX_PATH_LENGTH ||
    UNSAFE_LINE.test(value) ||
    !paths.isAbsolute(value)
  ) {
    return null;
  }
  return paths.resolve(value);
}

export function isTimestamp(value) {
  return (
    typeof value === "string" &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isRecord(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function hasFields(value, fields) {
  return (
    isRecord(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function isBoundedText(value, maximumLength, unsafe = UNSAFE_LINE) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maximumLength &&
    !unsafe.test(value)
  );
}

function isReferenceList(value) {
  return (
    Array.isArray(value) &&
    value.length <= MAX_REFERENCES &&
    value.every((entry) => isBoundedText(entry, MAX_REFERENCE_LENGTH)) &&
    new Set(value).size === value.length
  );
}

function invalidInput() {
  return new IssueError("Issue report input is invalid.", {
    code: "ERR_INVALID_ISSUE_REPORT",
  });
}

// The shared capability validates capture independently of its projections.
export function assertReportInput(input) {
  if (
    !isRecord(input) ||
    Object.keys(input).some((field) => !REQUEST_FIELDS.has(field)) ||
    typeof input.idempotencyKey !== "string" ||
    !isBoundedText(input.projectPath, MAX_REQUEST_PATH_LENGTH) ||
    (input.projectConfigurationPath !== undefined &&
      !isBoundedText(
        input.projectConfigurationPath,
        MAX_REQUEST_PATH_LENGTH,
      )) ||
    Object.entries(REPORT_FIELDS).some(([field, maximumLength]) =>
      field === "details" && input.details === undefined
        ? false
        : !isBoundedText(input[field], maximumLength, UNSAFE_MARKDOWN),
    ) ||
    (input.runId !== undefined && !matches(RUN_ID, input.runId)) ||
    (input.errorCode !== undefined && !matches(ERROR_CODE, input.errorCode))
  ) {
    throw invalidInput();
  }
}

function renderReport(input) {
  const sections = [
    "# Unexpected Agent Runner Issue",
    "",
    "## Summary",
    "",
    input.summary,
    "",
    "## Expected Behavior",
    "",
    input.expectedBehavior,
    "",
    "## Actual Behavior",
    "",
    input.actualBehavior,
    "",
    "## Occurrence",
    "",
    input.occurrence,
    "",
    "## Why This Was Unexpected",
    "",
    input.unexpectedReason,
  ];
  if (input.details !== undefined) {
    sections.push("", "## Details", "", input.details);
  }
  if (input.runId !== undefined || input.errorCode !== undefined) {
    sections.push("", "## Metadata", "");
    if (input.runId !== undefined) {
      sections.push(`- Run ID: \`${input.runId}\``);
    }
    if (input.errorCode !== undefined) {
      sections.push(`- Error code: \`${input.errorCode}\``);
    }
  }
  return `${sections.join("\n")}\n`;
}

function serialize(document) {
  return Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
}

function invalidDocument(cause) {
  return new IssueError("Issue document is invalid.", {
    cause,
    code: "ERR_INVALID_ISSUE",
  });
}

// One canonical document holds the immutable report and its tracking record.
function parseIssueDocument(bytes, issueId) {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength > MAX_ISSUE_BYTES) {
    throw invalidDocument();
  }
  let document;
  try {
    document = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    throw invalidDocument(cause);
  }
  const { report, tracking } = document ?? {};
  const origin = tracking?.origin;
  if (
    !hasFields(document, ["schemaVersion", "id", "report", "tracking"]) ||
    document.schemaVersion !== ISSUE_SCHEMA_VERSION ||
    document.id !== issueId ||
    !isIssueId(issueId) ||
    !hasFields(report, ["sha256", "markdown"]) ||
    !isBoundedText(report.markdown, MAX_MARKDOWN_LENGTH, UNSAFE_MARKDOWN) ||
    report.sha256 !== sha256(report.markdown) ||
    !hasFields(tracking, [
      "revision",
      "status",
      "origin",
      "createdAt",
      "updatedAt",
      "runId",
      "errorCode",
      "planReferences",
      "commitReferences",
      "note",
    ]) ||
    !Number.isSafeInteger(tracking.revision) ||
    tracking.revision < 1 ||
    !ISSUE_STATUSES.includes(tracking.status) ||
    !hasFields(origin, ["name", "path"]) ||
    safeAbsolutePath(origin.path) !== origin.path ||
    origin.name !== basename(origin.path) ||
    !isTimestamp(tracking.createdAt) ||
    !isTimestamp(tracking.updatedAt) ||
    tracking.updatedAt < tracking.createdAt ||
    (tracking.runId !== null && !matches(RUN_ID, tracking.runId)) ||
    (tracking.errorCode !== null && !matches(ERROR_CODE, tracking.errorCode)) ||
    !isReferenceList(tracking.planReferences) ||
    !isReferenceList(tracking.commitReferences) ||
    (tracking.note !== null &&
      !isBoundedText(tracking.note, MAX_NOTE_LENGTH, UNSAFE_MARKDOWN)) ||
    // Canonical bytes reject duplicate fields and alternate encodings.
    !serialize(document).equals(bytes)
  ) {
    throw invalidDocument();
  }
  return document;
}

export function createIssueDocument({
  issueId,
  createdAt,
  projectPath,
  report,
}) {
  const markdown = renderReport(report);
  const bytes = serialize({
    schemaVersion: ISSUE_SCHEMA_VERSION,
    id: issueId,
    report: { sha256: sha256(markdown), markdown },
    tracking: {
      revision: 1,
      status: "open",
      origin: { name: basename(projectPath), path: projectPath },
      createdAt,
      updatedAt: createdAt,
      runId: report.runId ?? null,
      errorCode: report.errorCode ?? null,
      planReferences: [],
      commitReferences: [],
      note: null,
    },
  });
  parseIssueDocument(bytes, issueId);
  return bytes;
}
