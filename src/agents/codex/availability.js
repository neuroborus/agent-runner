import { STATUS_CODES } from "node:http";

import { isRecord } from "../adapter-contract.js";
import { MAX_HTTP_ERROR_BYTES, parseHttpError } from "./http-error.js";

const TRANSPORT_VARIANTS = new Set([
  "httpConnectionFailed",
  "responseStreamConnectionFailed",
  "responseStreamDisconnected",
]);
const TRANSIENT_STATUSES = new Set([408, 425, 500, 502, 503, 504, 529]);
const CREDENTIAL_REJECTION =
  /\b(?:token|credentials?|api[_ -]?key)[^\n]{0,40}(?:expired|revoked|invalid)|\b(?:expired|revoked|invalid)[^\n]{0,40}(?:token|credentials?|api[_ -]?key)|\b(?:log|sign) ?in required|\bnot authenticated\b|\bplease (?:log|sign) ?in\b/iu;
const TRANSPORT_ERROR =
  /\b(?:ENETDOWN|ENETUNREACH|EHOSTUNREACH|EAI_AGAIN|ENOTFOUND|ECONNREFUSED|ECONNRESET|ETIMEDOUT|ESOCKETTIMEDOUT)\b|\b(?:network (?:is )?(?:offline|unreachable)|dns (?:lookup|resolution) failed|failed to lookup address information|connection (?:refused|reset|timed out)|(?:request|operation) timed out)\b/iu;
const TERMINAL_ERROR =
  /\b(?:(?:authentication|authorization)(?:[_ -](?:error|failed|required))?|unauthenticated|unauthorized|forbidden|permission[_ -](?:denied|error)|EACCES|EPERM|401|403|429|(?:invalid|bad)[_ -]request(?:_error)?|invalid[_ -](?:api[_ -]key|json[_ -]schema)|protocol[_ -](?:error|invalid|incompatible|incompatibility)|(?:usage|rate)[_ -]limit(?:[_ -](?:error|exceeded|exhausted))?|(?:quota|credits?|budget)(?:[_ -](?:exceeded|exhausted))?|insufficient[_ -](?:quota|credits?))\b/iu;

// Only native turn and turn-start errors are inspected; item output and additional
// details cannot turn an unrelated failure into provider availability.
export function codexAvailabilityEvidence(error) {
  const info = error?.codexErrorInfo;
  const variant =
    typeof info === "string"
      ? info
      : isRecord(info) && Object.keys(info).length === 1
        ? Object.keys(info)[0]
        : undefined;
  if (
    !TRANSPORT_VARIANTS.has(variant) &&
    ![
      "other",
      "serverOverloaded",
      "internalServerError",
      "responseTooManyFailedAttempts",
    ].includes(variant)
  )
    return {};
  let status;
  if (isRecord(info)) {
    const payload = info[variant];
    if (
      !isRecord(payload) ||
      Object.keys(payload).some((key) => key !== "httpStatusCode")
    )
      return {};
    status = payload.httpStatusCode ?? undefined;
    if (
      status !== undefined &&
      (!Number.isInteger(status) || status < 100 || status > 599)
    )
      return {};
  }
  if (status !== undefined && !TRANSIENT_STATUSES.has(status))
    return { status };
  let message = error?.message;
  if (
    typeof message !== "string" ||
    Buffer.byteLength(message) > MAX_HTTP_ERROR_BYTES
  )
    return { status };
  if (message.startsWith("unexpected status ")) {
    const parsed = parseHttpError(message);
    // The wrapper may corroborate a native transient status, never supply it.
    // Closed server-error fields exclude conflicting or opaque response bodies.
    if (
      status === undefined ||
      !parsed ||
      parsed.status !== status ||
      (parsed.reason !== undefined && parsed.reason !== STATUS_CODES[status]) ||
      !["server_error", "overloaded_error"].includes(parsed.error.type) ||
      parsed.error.param != null ||
      (parsed.error.code != null && parsed.error.code !== parsed.error.type)
    )
      return { status };
    message = parsed.error.message;
  }
  if (TERMINAL_ERROR.test(message) || CREDENTIAL_REJECTION.test(message))
    return { status };
  let availabilityReason;
  if (status !== undefined) {
    availabilityReason =
      status === 529
        ? "temporarily_overloaded"
        : status === 408 || status === 504
          ? "transport_unavailable"
          : "server_unavailable";
  } else if (
    variant === "serverOverloaded" ||
    /\b(?:overloaded_error|(?:provider|server|service|api) (?:is )?overloaded)\b/iu.test(
      message,
    )
  ) {
    availabilityReason = "temporarily_overloaded";
  } else if (/\bmodel(?:[_ -]is)?[_ -]busy\b/iu.test(message)) {
    availabilityReason = "model_busy";
  } else if (TRANSPORT_ERROR.test(message) || TRANSPORT_VARIANTS.has(variant)) {
    availabilityReason = "transport_unavailable";
  } else if (variant === "internalServerError") {
    availabilityReason = "server_unavailable";
  }
  return { status, availabilityReason };
}
