export const DEFAULT_MAX_EVENT_LOG_BYTES = 536_870_912;
export const MAX_EVENT_LOG_BYTES = 2_147_483_647;

export function normalizeMaxEventLogBytes(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > MAX_EVENT_LOG_BYTES
  ) {
    throw new TypeError(
      "maxEventLogBytes must be an integer from 1 through 2147483647.",
    );
  }
  return value;
}
