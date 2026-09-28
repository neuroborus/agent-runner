import { isRecord } from "../adapter-contract.js";

export const MAX_HTTP_ERROR_BYTES = 16_384;

// Parse only the bounded native wrapper. Callers own status/type policy;
// neither response prose nor additional details establish an HTTP status.
export function parseHttpError(message) {
  if (
    typeof message !== "string" ||
    message.length > MAX_HTTP_ERROR_BYTES ||
    Buffer.byteLength(message) > MAX_HTTP_ERROR_BYTES
  ) {
    return false;
  }
  const match =
    /^unexpected status ([0-9]{3})(?: ([A-Za-z ]+))?: [\t\r\n ]*(\{[\s\S]*\})[\t\r\n ]*((?:, (?:url|cf-ray|request id): [^,\s{}]+)*)$/u.exec(
      message,
    );
  if (match === null) return false;
  const [, statusText, reason, body, metadata] = match;
  const metadataKeys = [...metadata.matchAll(/, ([^:]+):/gu)].map(
    (entry) => entry[1],
  );
  if (new Set(metadataKeys).size !== metadataKeys.length) return false;
  let envelope;
  try {
    envelope = JSON.parse(body);
  } catch {
    return false;
  }
  if (
    !isRecord(envelope) ||
    Object.keys(envelope).length !== 1 ||
    !isRecord(envelope.error)
  ) {
    return false;
  }
  const error = envelope.error;
  const keys = Object.keys(error);
  if (
    keys.some((key) => !["message", "type", "param", "code"].includes(key)) ||
    typeof error.message !== "string" ||
    typeof error.type !== "string" ||
    (error.param !== undefined &&
      error.param !== null &&
      typeof error.param !== "string") ||
    (error.code !== undefined &&
      error.code !== null &&
      typeof error.code !== "string")
  ) {
    return false;
  }
  // Scalar values let us count keys without treating strings as structure.
  // Reject duplicate fields, including escaped names, before using the body.
  const keyCount = [...body.matchAll(/"(?:[^"\\]|\\.)*"\s*(:)?/gsu)].filter(
    (entry) => entry[1] !== undefined,
  ).length;
  return keyCount === keys.length + 1
    ? { status: Number(statusText), reason, error }
    : false;
}
