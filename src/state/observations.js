import { isDeepStrictEqual } from "node:util";

import { normalizeProviderObservation } from "../agents/index.js";

const MAX_ATTEMPTS = 32;
const MAX_OBSERVATIONS = 9;
const STATUSES = ["active", "completed", "failed", "interrupted"];
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const key = ({ attempt, turn }) => `${attempt}:${turn}`;
const MEASUREMENT_FIELDS = [
  "promptBytes",
  "recoveryPromptBytes",
  "schemaBytes",
  "resultBytes",
  "structuredResultBytes",
  "referencedFileCount",
  "referencedFileBytes",
];

function exact(value, fields) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function invalid() {
  throw new TypeError("Run observations are invalid.");
}

function normalizeMeasurements(value) {
  if (
    !exact(value, MEASUREMENT_FIELDS) ||
    MEASUREMENT_FIELDS.some(
      (field) => value[field] !== null && !count(value[field]),
    ) ||
    // References in a prompt are not evidence that their contents were read.
    value.referencedFileCount !== null ||
    value.referencedFileBytes !== null
  )
    invalid();
  return { ...value };
}

function accounting(attempt) {
  return attempt.status === "completed" &&
    !attempt.incomplete &&
    attempt.observations.length > 0 &&
    attempt.observations.every(
      (value) => value.accounting === "reported" && !value.factsIncomplete,
    )
    ? "reported"
    : "incomplete";
}

export function normalizeObservationState(state) {
  const value = state.observations;
  if (state.schemaVersion < 18) {
    if (value !== undefined && value !== null) invalid();
    return null;
  }
  if (value === null) return null;
  if (
    !exact(value, ["schemaVersion", "omittedAttempts", "attempts"]) ||
    value.schemaVersion !== 1 ||
    !count(value.omittedAttempts) ||
    !Array.isArray(value.attempts) ||
    value.attempts.length < 1 ||
    value.attempts.length > MAX_ATTEMPTS
  )
    invalid();
  let previousId = 0;
  const attempts = value.attempts.map((attempt, index) => {
    if (
      !exact(attempt, [
        "id",
        "role",
        "checkpoint",
        "status",
        "accounting",
        "incomplete",
        "observations",
        ...(state.schemaVersion >= 19 &&
        attempt != null &&
        Object.hasOwn(attempt, "measurements")
          ? ["measurements"]
          : []),
      ]) ||
      !count(attempt.id) ||
      attempt.id <= previousId ||
      attempt.id > state.revision ||
      typeof attempt.role !== "string" ||
      !Object.hasOwn(state.roles, attempt.role) ||
      typeof attempt.checkpoint !== "string" ||
      !/^[A-Za-z][A-Za-z0-9:._-]{0,127}$/u.test(attempt.checkpoint) ||
      !STATUSES.includes(attempt.status) ||
      (attempt.status === "active" && index !== value.attempts.length - 1) ||
      typeof attempt.incomplete !== "boolean" ||
      !Array.isArray(attempt.observations) ||
      attempt.observations.length > MAX_OBSERVATIONS
    )
      invalid();
    previousId = attempt.id;
    const observations = attempt.observations.map(normalizeProviderObservation);
    const measurements = Object.hasOwn(attempt, "measurements")
      ? normalizeMeasurements(attempt.measurements)
      : undefined;
    if (
      new Set(observations.map(key)).size !== observations.length ||
      attempt.accounting !== accounting({ ...attempt, observations }) ||
      (attempt.status !== "completed" &&
        (measurements?.resultBytes != null ||
          measurements?.structuredResultBytes != null))
    )
      invalid();
    return {
      ...attempt,
      observations,
      ...(Object.hasOwn(attempt, "measurements") ? { measurements } : {}),
    };
  });
  return { ...value, attempts };
}

// Recovery and replacement retain accepted facts, but never infer terminal usage.
export function interruptObservations(value) {
  if (value?.attempts.at(-1).status !== "active") return value;
  const attempts = [...value.attempts];
  attempts[attempts.length - 1] = {
    ...attempts.at(-1),
    status: "interrupted",
    accounting: "incomplete",
  };
  return { ...value, attempts };
}

export function beginObservationAttempt(state, identity, measurements) {
  if (
    !exact(identity, ["role", "checkpoint"]) ||
    state.schemaVersion < 18 ||
    (state.schemaVersion < 19 && measurements !== undefined) ||
    state.activeTurn?.role !== identity.role ||
    measurements?.resultBytes != null ||
    measurements?.structuredResultBytes != null
  )
    invalid();
  const value = interruptObservations(state.observations) ?? {
    schemaVersion: 1,
    omittedAttempts: 0,
    attempts: [],
  };
  const attempts = [
    ...value.attempts,
    {
      id: state.revision + 1,
      ...identity,
      status: "active",
      accounting: "incomplete",
      incomplete: false,
      observations: [],
      ...(measurements === undefined
        ? {}
        : { measurements: normalizeMeasurements(measurements) }),
    },
  ];
  const omitted = Math.max(0, attempts.length - MAX_ATTEMPTS);
  return {
    ...value,
    omittedAttempts: Math.min(
      Number.MAX_SAFE_INTEGER,
      value.omittedAttempts + omitted,
    ),
    attempts: attempts.slice(-MAX_ATTEMPTS),
  };
}

export function recordObservations(
  state,
  identity,
  records,
  status,
  incomplete,
  { resultBytes, structuredResultBytes } = {},
) {
  if (
    !exact(identity, ["id", "role", "checkpoint"]) ||
    !count(identity.id) ||
    !Array.isArray(records) ||
    records.length > MAX_OBSERVATIONS ||
    !STATUSES.includes(status) ||
    typeof incomplete !== "boolean" ||
    (resultBytes !== undefined &&
      resultBytes !== null &&
      !count(resultBytes)) ||
    (structuredResultBytes !== undefined &&
      structuredResultBytes !== null &&
      !count(structuredResultBytes)) ||
    (status !== "completed" &&
      (resultBytes != null || structuredResultBytes != null))
  )
    invalid();
  const value = state.observations;
  const current = value?.attempts.at(-1);
  // A callback belongs only to the currently open runner attempt, even when a
  // replacement uses the same role and checkpoint or resets native ordinals.
  if (
    current?.status !== "active" ||
    ["id", "role", "checkpoint"].some(
      (field) => current[field] !== identity[field],
    )
  )
    return value;
  const observations = [...current.observations];
  for (const record of records.map(normalizeProviderObservation)) {
    if (observations.some((prior) => key(prior) === key(record))) continue;
    if (observations.length === MAX_OBSERVATIONS) {
      incomplete = true;
      continue;
    }
    observations.push(record);
  }
  const next = {
    ...current,
    status,
    observations,
    incomplete: current.incomplete || incomplete,
  };
  if (current.measurements !== undefined)
    next.measurements = {
      ...current.measurements,
      resultBytes: resultBytes ?? null,
      structuredResultBytes: structuredResultBytes ?? null,
    };
  next.accounting = accounting(next);
  return { ...value, attempts: [...value.attempts.slice(0, -1), next] };
}

export function assertObservationContinuity(previous, current) {
  const before = previous.observations;
  const after = current.observations;
  if (isDeepStrictEqual(before, after)) return;
  if (after === null) invalid();
  const started = after.attempts.at(-1).id === current.revision;
  if (started) {
    const latest = after.attempts.at(-1);
    const expected = beginObservationAttempt(
      previous,
      {
        role: latest.role,
        checkpoint: latest.checkpoint,
      },
      latest.measurements,
    );
    if (!isDeepStrictEqual(expected, after)) invalid();
    return;
  }
  const prior = before?.attempts.at(-1);
  const next = after.attempts.at(-1);
  if (
    prior?.status !== "active" ||
    before.omittedAttempts !== after.omittedAttempts ||
    !isDeepStrictEqual(
      before.attempts.slice(0, -1),
      after.attempts.slice(0, -1),
    ) ||
    ["id", "role", "checkpoint"].some(
      (field) => prior[field] !== next[field],
    ) ||
    (prior.incomplete && !next.incomplete) ||
    !isDeepStrictEqual(
      prior.measurements,
      next.measurements === undefined
        ? undefined
        : {
            ...next.measurements,
            resultBytes: null,
            structuredResultBytes: null,
          },
    ) ||
    !isDeepStrictEqual(
      prior.observations,
      next.observations.slice(0, prior.observations.length),
    )
  )
    invalid();
}

// Public evidence is copied from validated state, never from provider errors or
// native session state. Legacy absence stays distinguishable from missing usage.
export function projectObservations(run) {
  const value = run.observations;
  if (value == null) return null;
  return {
    omittedAttempts: value.omittedAttempts,
    attempts: value.attempts.map((attempt) => ({
      id: attempt.id,
      role: attempt.role,
      checkpoint: attempt.checkpoint,
      status: attempt.status,
      accounting: attempt.accounting,
      incomplete: attempt.incomplete,
      measurements:
        attempt.measurements === undefined
          ? null
          : normalizeMeasurements(attempt.measurements),
      observations: attempt.observations.map(normalizeProviderObservation),
    })),
  };
}

export function observationActivity(attempt) {
  const measured = attempt.measurements;
  const known = (value) => value ?? "unknown";
  return {
    actor: attempt.role,
    phase: "observations",
    kind: attempt.status,
    message: `Attempt ${attempt.id} ${attempt.checkpoint}: ${attempt.status}; accounting ${attempt.accounting}; native turns ${attempt.observations.length}; prompt/schema/output/structured bytes ${known(measured?.promptBytes)}/${known(measured?.schemaBytes)}/${known(measured?.resultBytes)}/${known(measured?.structuredResultBytes)}.`,
  };
}
