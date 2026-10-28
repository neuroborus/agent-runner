import {
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import {
  digest,
  DARWIN_LITERAL_ARGUMENTS,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";

export function darwinImageFrame(value, phase, helper) {
  observationObject(value, [
    "version",
    "phase",
    "helper",
    "payload",
    "controls",
  ]);
  requireObservation(
    value.version === 3 &&
      value.phase === phase &&
      value.controls === !phase.startsWith("control-") &&
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
    ...(value.version === 3
      ? ["control", "execControl", "probe", "witness"]
      : []),
    ...(value.continuation === "possible" ? ["observationsSha256"] : []),
  ]);
  requireObservation(
    [2, 3].includes(value.version) &&
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
  if (value.version === 3) {
    requireObservation(typeof value.control === "boolean");
    if (value.witness !== null) {
      observationObject(value.witness, [
        "version",
        "control",
        "creator",
        "target",
        "closed",
        "stopped",
        "imageSha256",
        "cdhash",
        "policySha256",
      ]);
      requireObservation(
        value.witness.version === 3 &&
          value.witness.control === value.control &&
          value.witness.closed === true &&
          value.witness.stopped === true &&
          sameDarwinIdentity(value.witness.creator, creator) &&
          sameDarwinIdentity(value.witness.target, value.target) &&
          /^[a-f0-9]{64}$/u.test(value.witness.imageSha256) &&
          /^[a-f0-9]{64}$/u.test(value.witness.policySha256) &&
          /^[a-f0-9]{40}$/u.test(value.witness.cdhash),
      );
    }
    if (value.continuation === "possible")
      requireObservation(value.witness !== null);
    if (value.control)
      requireObservation(value.execControl === null && value.probe === null);
    else {
      observationObject(value.execControl, [
        "retired",
        "image",
        "outputSha256",
      ]);
      requireObservation(
        value.execControl?.retired === true &&
          value.execControl.image?.version === 3 &&
          value.execControl.image.control === true,
      );
      assertDarwinImageRecord(value.execControl.image);
      requireObservation(
        value.execControl.image.creator.asid !== creator.asid &&
          ["auid", "uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
            (key) => value.execControl.image.creator[key] === creator[key],
          ),
      );
      requireObservation(
        value.execControl.image.target !== null &&
          value.execControl.image.continuation === "possible" &&
          value.execControl.outputSha256 ===
            digest(JSON.stringify(DARWIN_LITERAL_ARGUMENTS) + "\n"),
      );
      if (value.probe !== null) {
        if (value.probe.state === "possible")
          observationObject(value.probe, ["state"]);
        else assertDarwinExecProbe(value.probe, creator);
      }
      if (value.target !== null)
        assertDarwinExecProbe(
          value.probe,
          creator,
          value.execControl.image.witness.policySha256,
          value.execControl.image.witness.imageSha256,
        );
      if (value.witness !== null)
        requireObservation(
          value.witness.policySha256 === value.probe.policySha256,
        );
    }
  }
  return value;
}

export function assertDarwinExecProbe(
  value,
  creator,
  policySha256,
  assetSha256,
) {
  observationObject(value, [
    "version",
    "subject",
    "policySha256",
    "assetSha256",
    "status",
    "prepared",
    "filesCleanup",
    "attributesCleanup",
    "read",
    "map",
    "unchanged",
  ]);
  requireObservation(
    value.version === 1 &&
      sameDarwinIdentity(value.subject, creator) &&
      [1, 13].includes(value.status) &&
      value.prepared === true &&
      value.filesCleanup === 0 &&
      value.attributesCleanup === 0 &&
      value.read === 0 &&
      value.map === 0 &&
      value.unchanged === true &&
      /^[a-f0-9]{64}$/u.test(value.policySha256) &&
      /^[a-f0-9]{64}$/u.test(value.assetSha256) &&
      (policySha256 === undefined || value.policySha256 === policySha256) &&
      (assetSha256 === undefined || value.assetSha256 === assetSha256),
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
  control = false,
  execControl = null,
  asset,
  guard,
  now = () => performance.now(),
}) {
  const deadline = now() + 30000;
  const bounded = () => {
    guard();
    requireObservation(now() <= deadline);
  };
  const image = {
    version: 3,
    control,
    execControl,
    probe: null,
    witness: null,
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
  observationObject(bound, ["version", "control", "creator", "closed"]);
  requireObservation(
    bound.version === 3 &&
      bound.control === control &&
      bound.closed === true &&
      sameDarwinIdentity(bound.creator, creator),
  );
  await persist(); // original identity and possible exec precede the one-shot X
  if (!control) {
    requireObservation(
      execControl?.retired === true &&
        execControl.image.witness.policySha256 === policySha256 &&
        execControl.image.witness.imageSha256 === asset.sha256 &&
        execControl.image.witness.cdhash === asset.cdhash,
    );
    image.probe = { state: "possible" };
    await persist(); // consume uncertainty before the distinct T operation
    image.probe = assertDarwinExecProbe(
      await reader.imageProbe(),
      creator,
      policySha256,
      asset.sha256,
    );
    await persist();
  }
  await reader.imageExec();
  bounded();
  const target = darwinImageFrame(
    await next(),
    control ? "control-image" : "image",
    helper,
  );
  assertDarwinImageTransition(creator, target);
  image.target = target;
  await persist(); // unpublished epochs are still recoverable from the creator domain
  const read = async () => {
    bounded();
    const actual = await reader.imageRead();
    observationObject(actual, [
      "version",
      "control",
      "creator",
      "target",
      "closed",
      "stopped",
      "imageSha256",
      "cdhash",
      "policySha256",
    ]);
    requireObservation(
      actual.version === 3 &&
        actual.control === control &&
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
  image.witness = first.actual;
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
