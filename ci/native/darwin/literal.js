import { observationObject } from "../index.js";
import {
  darwinLaunchDigest,
  normalizeDarwinArguments,
  normalizeDarwinIdentity,
  normalizeDarwinLaunch,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";

/** Exact fixture bytes are joined to independently observed admitted image,
 * process and cwd identities. Output alone cannot establish native launch. */
export function assertDarwinLiteralObservation(
  input,
  argumentsList,
  record,
  observation,
) {
  const request = normalizeDarwinLaunch(input),
    args = normalizeDarwinArguments(argumentsList);
  observationObject(observation, [
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
  observationObject(observation.cwdIdentity, ["dev", "ino"]);
  const verifier = normalizeDarwinIdentity(observation.verifier);
  requireDarwin(
    record.status === "ADMITTED" &&
      record.requestSha256 === darwinLaunchDigest(request, args) &&
      observation.independent === true &&
      observation.requestSha256 === record.requestSha256 &&
      sameDarwinIdentity(observation.payload, record.payload) &&
      record.payload.uid === request.uid &&
      record.payload.gid === request.gid &&
      observation.cwdIdentity.dev === record.authority.cwd.dev &&
      observation.cwdIdentity.ino === record.authority.cwd.ino &&
      observation.imageSha256 === request.executable.sha256 &&
      observation.exitCode === 0 &&
      observation.timedOut === false &&
      observation.complete === true &&
      /^[a-f0-9]{64}$/u.test(observation.nativeEventSha256) &&
      record.helpers.some(
        (entry) =>
          entry.role === "verifier" &&
          sameDarwinIdentity(entry.identity, verifier),
      ),
  );
  requireDarwin(observation.output === JSON.stringify(args) + "\n");
  return {
    status: "OBSERVED",
    requestSha256: record.requestSha256,
    nativeEventSha256: observation.nativeEventSha256,
  };
}
