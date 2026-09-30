const TRANSIENT_STATUSES = new Set([408, 425, 500, 502, 503, 504, 529]);
const TRANSPORT_ERROR =
  /\b(?:ENETDOWN|ENETUNREACH|EHOSTUNREACH|EAI_AGAIN|ENOTFOUND|ECONNREFUSED|ECONNRESET|ETIMEDOUT|ESOCKETTIMEDOUT|UND_ERR_CONNECT_TIMEOUT|UND_ERR_SOCKET)\b|\b(?:network (?:is )?(?:offline|unreachable)|dns (?:lookup|resolution) failed|connection (?:refused|reset|timed out)|(?:request|operation) timed out)\b/iu;
const TERMINAL_ERROR =
  /\b(?:(?:authentication|authorization)(?:[_ -](?:error|failed|required))?|unauthenticated|unauthorized|forbidden|permission[_ -](?:denied|error)|EACCES|EPERM|401|403|429|(?:invalid|bad)[_ -]request(?:_error)?|invalid[_ -](?:api[_ -]key|json[_ -]schema)|protocol[_ -](?:error|invalid|incompatible|incompatibility)|(?:usage|rate)[_ -]limit(?:[_ -](?:error|exceeded|exhausted))?|(?:quota|credits?|budget)(?:[_ -](?:exceeded|exhausted))?|insufficient[_ -](?:quota|credits?))\b/iu;
const CREDENTIAL_REJECTION =
  /\b(?:token|credentials?|api[_ -]?key)[^\n]{0,40}(?:expired|revoked|invalid)|\b(?:expired|revoked|invalid)[^\n]{0,40}(?:token|credentials?|api[_ -]?key)|\b(?:log|sign) ?in required|\bnot authenticated\b|\bplease (?:log|sign) ?in\b/iu;

export function claudeAvailabilityReason(message, status) {
  // A truncated diagnostic cannot exclude contradictory terminal evidence.
  if (
    typeof message !== "string" ||
    Buffer.byteLength(message) >= 4_096 ||
    TERMINAL_ERROR.test(message) ||
    CREDENTIAL_REJECTION.test(message)
  )
    return undefined;
  if (status !== undefined) {
    if (!TRANSIENT_STATUSES.has(status)) return undefined;
    if (status === 529) return "temporarily_overloaded";
    return status === 408 || status === 504
      ? "transport_unavailable"
      : "server_unavailable";
  }
  if (
    /\b(?:overloaded_error|(?:provider|server|service|api) (?:is )?overloaded)\b/iu.test(
      message,
    )
  )
    return "temporarily_overloaded";
  if (/\bmodel(?:[_ -]is)?[_ -]busy\b/iu.test(message)) return "model_busy";
  return TRANSPORT_ERROR.test(message) ? "transport_unavailable" : undefined;
}
