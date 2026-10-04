import {
  closed,
  hash,
  requireWindows,
  normalizeWindowsLaunch,
  normalizeWindowsArguments,
  sameWindowsIdentity,
  systemIdentity,
  windowsLaunchDigest,
} from "./protocol.js";

/** Actual UCRT fixture output joined by the independent native observer to the
 * admitted private process/image/cwd. Encoding tests alone cannot prove argv. */
export function assertWindowsLiteralObservation(
  input,
  argumentsList,
  record,
  observation,
) {
  const request = normalizeWindowsLaunch(input),
    args = normalizeWindowsArguments(argumentsList);
  closed(observation, [
    "independent",
    "verifier",
    "requestSha256",
    "payload",
    "cwdIdentity",
    "imageSha256",
    "output",
    "exitCode",
    "timedOut",
    "complete",
    "nativeEventSha256",
  ]);
  const verifier = systemIdentity(observation.verifier);
  requireWindows(
    record.status === "ADMITTED" &&
      record.requestSha256 === windowsLaunchDigest(request, args) &&
      observation.independent === true &&
      observation.requestSha256 === record.requestSha256 &&
      sameWindowsIdentity(observation.payload, record.payload) &&
      record.payload.userSid === record.accountSid &&
      observation.cwdIdentity === record.authority.cwdIdentity &&
      observation.imageSha256 === request.executable.sha256 &&
      observation.exitCode === 0 &&
      observation.timedOut === false &&
      observation.complete === true &&
      hash(observation.nativeEventSha256) &&
      record.helpers.some(
        (entry) =>
          entry.role === "verifier" &&
          sameWindowsIdentity(entry.identity, verifier),
      ),
  );
  const argvUtf16 = args.map((arg) => {
    let hex = "";
    for (let index = 0; index < arg.length; index++)
      hex += arg.charCodeAt(index).toString(16).padStart(4, "0");
    return hex;
  });
  // A single exact frame rejects missing, duplicated, extra or truncated data.
  requireWindows(observation.output === JSON.stringify({ argvUtf16 }) + "\n");
  return {
    status: "OBSERVED",
    requestSha256: record.requestSha256,
    nativeEventSha256: observation.nativeEventSha256,
  };
}
