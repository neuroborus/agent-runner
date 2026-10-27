import {
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import { normalizeDarwinIdentity, sameDarwinIdentity } from "./protocol.js";

export function darwinImageFrame(value, phase, helper) {
  observationObject(value, [
    "version",
    "phase",
    "helper",
    "payload",
    "controls",
  ]);
  requireObservation(
    value.version === 2 &&
      value.phase === phase &&
      value.controls === true &&
      sameDarwinIdentity(value.helper, helper),
  );
  return normalizeDarwinIdentity(value.payload);
}

export function assertDarwinImageTransition(creator, target) {
  requireObservation(
    target.pidVersion !== creator.pidVersion &&
      sameDarwinIdentity(target, { ...creator, pidVersion: target.pidVersion }),
  );
}

export function assertDarwinImageRecord(value) {
  observationObject(value, [
    "version",
    "creator",
    "target",
    "execution",
    "continuation",
    ...(value.continuation === "possible" ? ["observationsSha256"] : []),
  ]);
  requireObservation(
    value.version === 2 &&
      value.execution === "possible" &&
      ["not-started", "possible"].includes(value.continuation),
  );
  const creator = normalizeDarwinIdentity(value.creator);
  if (value.target !== null)
    assertDarwinImageTransition(creator, normalizeDarwinIdentity(value.target));
  if (value.continuation === "possible")
    requireObservation(
      value.target !== null && /^[a-f0-9]{64}$/u.test(value.observationsSha256),
    );
  return value;
}

// Both ordinary owners use the same bounded durable ordering. Publication owns
// the full protected record, including original domain custody; no local Mach
// names escape the independent reader or become reconstruction authority.
export async function admitDarwinImage({
  reader,
  creator,
  helper,
  next,
  publish,
  observe,
  executable,
  policySha256,
  guard,
  now = () => performance.now(),
}) {
  const deadline = now() + 30000;
  const bounded = () => {
    guard();
    requireObservation(now() <= deadline);
  };
  const image = {
    version: 2,
    creator,
    target: null,
    execution: "possible",
    continuation: "not-started",
  };
  const persist = async () => {
    bounded();
    assertDarwinImageRecord(image);
    const { pin, bytes } = await publish(structuredClone(image));
    requireObservation(
      (await reader.ownershipReceipt(pin.index, pin.sha256)).equals(bytes),
    );
    bounded();
    return pin;
  };
  bounded();
  const bound = await reader.imageCreator();
  observationObject(bound, ["version", "creator", "closed"]);
  requireObservation(
    bound.version === 2 &&
      bound.closed === true &&
      sameDarwinIdentity(bound.creator, creator),
  );
  await persist(); // original identity and possible exec precede the one-shot X
  await reader.imageExec();
  bounded();
  const target = darwinImageFrame(await next(), "image", helper);
  assertDarwinImageTransition(creator, target);
  image.target = target;
  await persist(); // unpublished epochs are still recoverable from the creator domain
  const read = async () => {
    bounded();
    const actual = await reader.imageRead();
    observationObject(actual, [
      "version",
      "creator",
      "target",
      "closed",
      "stopped",
      "imageSha256",
      "cdhash",
      "policySha256",
    ]);
    requireObservation(
      actual.version === 2 &&
        actual.closed === true &&
        actual.stopped === true &&
        sameDarwinIdentity(actual.creator, creator) &&
        sameDarwinIdentity(actual.target, target) &&
        actual.imageSha256 === executable.sha256 &&
        actual.cdhash === executable.cdhash &&
        actual.policySha256 === policySha256,
    );
    const policy = await observe(target);
    bounded();
    return { actual, policy };
  };
  const first = await read();
  image.observationsSha256 = observationDigest(first);
  image.continuation = "possible";
  const pin = await persist();
  const repeated = await read();
  requireObservation(observationDigest(repeated) === image.observationsSha256);
  bounded();
  await reader.imageContinue(pin);
  bounded();
  return { target, policy: first.policy, image };
}
