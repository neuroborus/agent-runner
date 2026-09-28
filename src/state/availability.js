import { AVAILABILITY_REASONS } from "../agents/index.js";

export const DEFAULT_AVAILABILITY_POLICY = Object.freeze({
  initialDelayMs: 5_000,
  maxDelayMs: 1_800_000,
});
// Node timers must not overflow into an immediate retry.
export const MAX_AVAILABILITY_DELAY_MS = 2_147_483_647;
const EPISODE_FIELDS = [
  "id",
  "role",
  "checkpoint",
  "reason",
  "attempt",
  "delayMs",
  "scheduledAt",
  "nextRetryAt",
  "contentFingerprint",
  "reconciledRevision",
];
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CHECKPOINT = /^[A-Za-z][A-Za-z0-9:._-]{0,127}$/u;
const HASH = /^[a-f0-9]{64}$/u;

function exactFields(value, fields) {
  return (
    value !== null &&
    typeof value === "object" &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function timestamp(value) {
  return (
    typeof value === "string" &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

export function normalizeAvailabilityPolicy(value) {
  if (
    !exactFields(value, ["initialDelayMs", "maxDelayMs"]) ||
    value.initialDelayMs !== DEFAULT_AVAILABILITY_POLICY.initialDelayMs ||
    !Number.isSafeInteger(value.maxDelayMs) ||
    value.maxDelayMs < value.initialDelayMs ||
    value.maxDelayMs > MAX_AVAILABILITY_DELAY_MS
  ) {
    throw new TypeError("Availability policy is invalid.");
  }
  return Object.freeze({
    initialDelayMs: value.initialDelayMs,
    maxDelayMs: value.maxDelayMs,
  });
}

export function availabilityDelayMs(policy, attempt) {
  const normalized = normalizeAvailabilityPolicy(policy);
  if (!Number.isSafeInteger(attempt) || attempt < 1) {
    throw new TypeError("Availability attempt is invalid.");
  }
  return Math.min(
    normalized.maxDelayMs,
    normalized.initialDelayMs * 2 ** Math.min(attempt - 1, 31),
  );
}

export function normalizeAvailabilityState(state) {
  const legacy = state.schemaVersion < 15;
  const policy = normalizeAvailabilityPolicy(
    legacy && state.availabilityPolicy === undefined
      ? DEFAULT_AVAILABILITY_POLICY
      : state.availabilityPolicy,
  );
  const episode =
    legacy && state.availabilityRetry === undefined
      ? null
      : state.availabilityRetry;
  if (
    legacy &&
    (policy.maxDelayMs !== DEFAULT_AVAILABILITY_POLICY.maxDelayMs ||
      episode !== null)
  ) {
    throw new TypeError("Legacy runs cannot declare availability recovery.");
  }
  if (
    episode !== null &&
    (!exactFields(episode, EPISODE_FIELDS) ||
      typeof episode.id !== "string" ||
      !UUID.test(episode.id) ||
      typeof episode.role !== "string" ||
      !/^[a-z][a-z0-9-]{0,63}$/u.test(episode.role) ||
      !Object.hasOwn(state.roles, episode.role) ||
      typeof episode.checkpoint !== "string" ||
      !CHECKPOINT.test(episode.checkpoint) ||
      !AVAILABILITY_REASONS.includes(episode.reason) ||
      episode.delayMs !== availabilityDelayMs(policy, episode.attempt) ||
      !timestamp(episode.scheduledAt) ||
      !timestamp(episode.nextRetryAt) ||
      Date.parse(episode.nextRetryAt) - Date.parse(episode.scheduledAt) !==
        episode.delayMs ||
      Date.parse(episode.scheduledAt) < Date.parse(state.createdAt) ||
      Date.parse(episode.scheduledAt) > Date.parse(state.updatedAt) ||
      typeof episode.contentFingerprint !== "string" ||
      !HASH.test(episode.contentFingerprint) ||
      !Number.isSafeInteger(episode.reconciledRevision) ||
      episode.reconciledRevision < 1 ||
      episode.reconciledRevision >= state.revision)
  ) {
    throw new TypeError("Availability retry episode is invalid.");
  }
  return {
    availabilityPolicy: policy,
    availabilityRetry: episode === null ? null : { ...episode },
  };
}

// Identity and progression survive unrelated transitions, migration and restart.
// Clearing an episode is reserved for the coordinator's successful-turn path.
export function assertAvailabilityContinuity(previous, current) {
  const before = previous.availabilityRetry;
  const after = current.availabilityRetry;
  if (after === null) return;
  const unchanged =
    before !== null &&
    EPISODE_FIELDS.every((field) => before[field] === after[field]);
  if (unchanged) return;
  if (
    previous.activeTurn !== null ||
    previous.executionProcess !== null ||
    previous.executionResource !== null ||
    current.activeTurn !== null ||
    current.executionProcess !== null ||
    current.executionResource !== null ||
    after.reconciledRevision !== previous.revision ||
    after.scheduledAt !== current.updatedAt ||
    after.attempt !==
      (before === null
        ? 1
        : Math.min(Number.MAX_SAFE_INTEGER, before.attempt + 1)) ||
    (before !== null &&
      (after.id !== before.id ||
        after.role !== before.role ||
        after.checkpoint !== before.checkpoint ||
        after.scheduledAt < before.nextRetryAt))
  ) {
    throw new TypeError("Availability retry history is inconsistent.");
  }
}
