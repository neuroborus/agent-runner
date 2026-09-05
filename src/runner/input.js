import { PROVIDER_REGISTRY } from "../agents/index.js";
import { DETACHED_RUNTIME_COMPATIBILITY_TOKEN } from "../pipeline-registry.js";

const RUN_FIELDS = new Set([
  "pipelineId",
  "projectPath",
  "taskPath",
  "proactiveClarification",
  "roleOverrides",
  "executionOverrides",
  "settingOverrides",
  "projectConfigurationPath",
  "sourceSession",
]);
const RESUME_FIELDS = new Set([
  "runId",
  "action",
  "expectedRuntimeCompatibility",
]);
const CREATE_OPTIONS_FIELDS = new Set(["runId"]);
const INPUT_FIELDS = new Set([
  "runId",
  "requestId",
  "expectedRevision",
  "answers",
  "responseHash",
]);
const ANSWER_FIELDS = new Set(["questionId", "answer"]);
const SOURCE_SESSION_FIELDS = new Set(["backend", "id", "profile"]);

export class RunnerError extends Error {
  constructor(message, { cause, code = "ERR_RUNNER" } = {}) {
    super(message, { cause });
    this.name = "RunnerError";
    this.code = code;
  }
}

export function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function rejectUnknownFields(value, fields, name) {
  if (!isRecord(value)) {
    throw new RunnerError(`${name} must be an object.`, {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
  const unknown = Object.keys(value).find((field) => !fields.has(field));
  if (unknown !== undefined) {
    throw new RunnerError(`${name}.${unknown} is not supported.`, {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
}

export function assertNonEmptyString(value, name) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new RunnerError(`${name} must be a non-empty string.`, {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
  return value;
}

export function parseSourceSession(value, providers = PROVIDER_REGISTRY) {
  const backends = new Set(providers.sourceSessionIds);
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new RunnerError(
      `Source session must use <${providers.sourceSessionIds.join("|")}>:<session-id>.`,
      { code: "ERR_INVALID_SOURCE_SESSION" },
    );
  }
  const separator = value.indexOf(":");
  const backend = value.slice(0, separator);
  const id = value.slice(separator + 1);
  if (
    separator < 1 ||
    !backends.has(backend) ||
    id.trim().length === 0 ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(id)
  ) {
    throw new RunnerError(
      `Source session must use <${providers.sourceSessionIds.join("|")}>:<session-id>.`,
      { code: "ERR_INVALID_SOURCE_SESSION" },
    );
  }
  return Object.freeze({ backend, id });
}

function normalizeSourceSession(value, providers) {
  if (value === undefined || value === null) {
    return null;
  }
  rejectUnknownFields(value, SOURCE_SESSION_FIELDS, "sourceSession");
  if (
    !providers.supportsSourceSessionFork(value.backend) ||
    typeof value.id !== "string" ||
    value.id.trim().length === 0 ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value.id)
  ) {
    throw new RunnerError("sourceSession is invalid.", {
      code: "ERR_INVALID_SOURCE_SESSION",
    });
  }
  if (
    value.profile !== undefined &&
    (typeof value.profile !== "string" || value.profile.trim().length === 0)
  ) {
    throw new RunnerError("sourceSession is invalid.", {
      code: "ERR_INVALID_SOURCE_SESSION",
    });
  }
  return Object.freeze({
    backend: value.backend,
    id: value.id,
    ...(value.profile === undefined ? {} : { profile: value.profile }),
  });
}

export function normalizeRunInput(input, providers = PROVIDER_REGISTRY) {
  rejectUnknownFields(input, RUN_FIELDS, "run");
  return Object.freeze({
    pipelineId: assertNonEmptyString(input.pipelineId, "run.pipelineId"),
    projectPath: assertNonEmptyString(input.projectPath, "run.projectPath"),
    taskPath: assertNonEmptyString(input.taskPath, "run.taskPath"),
    proactiveClarification:
      input.proactiveClarification === undefined
        ? false
        : input.proactiveClarification,
    roleOverrides: input.roleOverrides ?? {},
    executionOverrides: input.executionOverrides ?? {},
    settingOverrides: input.settingOverrides ?? {},
    projectConfigurationPath:
      input.projectConfigurationPath === undefined
        ? undefined
        : assertNonEmptyString(
            input.projectConfigurationPath,
            "run.projectConfigurationPath",
          ),
    sourceSession: normalizeSourceSession(input.sourceSession, providers),
  });
}

export function normalizeResumeInput(input) {
  rejectUnknownFields(input, RESUME_FIELDS, "resume");
  if (
    input.expectedRuntimeCompatibility !== undefined &&
    input.expectedRuntimeCompatibility !== DETACHED_RUNTIME_COMPATIBILITY_TOKEN
  ) {
    throw new RunnerError(
      "Detached continuation runtime is incompatible with the process that " +
        "dispatched it; restart the Agent Runner MCP server and retry with " +
        "the same idempotency key.",
      { code: "ERR_RUNTIME_VERSION_SKEW" },
    );
  }
  return Object.freeze({
    runId: assertNonEmptyString(input.runId, "resume.runId"),
    action: input.action ?? null,
    ...(input.expectedRuntimeCompatibility === undefined
      ? {}
      : {
          expectedRuntimeCompatibility: input.expectedRuntimeCompatibility,
        }),
  });
}

export function normalizeCreateOptions(options) {
  rejectUnknownFields(options, CREATE_OPTIONS_FIELDS, "createOptions");
  return Object.freeze({
    runId:
      options.runId === undefined
        ? undefined
        : assertNonEmptyString(options.runId, "createOptions.runId"),
  });
}

export function normalizeInputSubmission(
  input,
  { requireResponseHash = false } = {},
) {
  rejectUnknownFields(input, INPUT_FIELDS, "input");
  if (
    !Number.isSafeInteger(input.expectedRevision) ||
    input.expectedRevision < 1 ||
    !Array.isArray(input.answers)
  ) {
    throw new RunnerError("Input response is invalid.", {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
  const answers = input.answers.map((answer, index) => {
    rejectUnknownFields(answer, ANSWER_FIELDS, `input.answers[${index}]`);
    return Object.freeze({
      questionId: assertNonEmptyString(
        answer.questionId,
        `input.answers[${index}].questionId`,
      ),
      answer: assertNonEmptyString(
        answer.answer,
        `input.answers[${index}].answer`,
      ),
    });
  });
  if (
    requireResponseHash &&
    (typeof input.responseHash !== "string" ||
      !/^[a-f0-9]{64}$/u.test(input.responseHash))
  ) {
    throw new RunnerError("Input response hash is invalid.", {
      code: "ERR_INVALID_RUNNER_INPUT",
    });
  }
  return Object.freeze({
    runId: assertNonEmptyString(input.runId, "input.runId"),
    requestId: assertNonEmptyString(input.requestId, "input.requestId"),
    expectedRevision: input.expectedRevision,
    answers: Object.freeze(answers),
    responseHash: input.responseHash,
  });
}

export function orderedInputAnswers(run, input) {
  const request = run.pause?.inputRequest;
  if (
    run.pipelineState.workflowState !== "WAITING_FOR_USER" ||
    run.pipelineState.pendingEdit === null ||
    request === null ||
    typeof request !== "object" ||
    request.id !== input.requestId ||
    !Array.isArray(request.questions)
  ) {
    throw new RunnerError("Pending input request does not match.", {
      code: "ERR_STALE_INPUT_REQUEST",
    });
  }
  if (run.revision !== input.expectedRevision) {
    throw new RunnerError("Pending input request revision is stale.", {
      code: "ERR_STALE_INPUT_REQUEST",
    });
  }
  if (run.pause.inputResponse !== undefined) {
    throw new RunnerError("Pending input request was already answered.", {
      code: "ERR_INPUT_ALREADY_SUBMITTED",
    });
  }
  const expectedIds = request.questions.map((question) => question.id);
  const byId = new Map(
    input.answers.map(({ questionId, answer }) => [questionId, answer]),
  );
  if (
    byId.size !== input.answers.length ||
    byId.size !== expectedIds.length ||
    expectedIds.some((id) => !byId.has(id))
  ) {
    throw new RunnerError("One answer is required for every question.", {
      code: "ERR_INCOMPLETE_INPUT_RESPONSE",
    });
  }
  return Object.freeze(expectedIds.map((id) => byId.get(id)));
}
