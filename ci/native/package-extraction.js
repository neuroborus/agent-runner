import { createHash } from "node:crypto";
import { win32 as path } from "node:path";
import { observationDigest, requireObservation } from "./observation.js";
import {
  materializeNativePolicy,
  verifyNativePolicy,
} from "./policy-template.js";
import { packageMemberPath, nativePackageInput } from "./package-inputs.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);

/** Reviewed native data-only 7z extraction. No SFX, shell, package script or
 * discovered executable can reach this boundary. Uncertain work stays private. */
export async function materializeReviewedGit(
  archive,
  directory,
  review,
  effects,
  { signal, persist } = {},
) {
  requireObservation(
    review.schemaVersion === 2 &&
      review.packageId === "git-for-windows" &&
      typeof persist === "function",
  );
  for (const name of [
    "readProtected",
    "readProvisioning",
    "readPolicy",
    "extract",
    "settle",
    "verifyStaged",
    "seal",
  ])
    requireObservation(typeof effects?.[name] === "function");
  requireObservation(
    [archive, directory].every(
      (value) => path.isAbsolute(value) && path.normalize(value) === value,
    ),
  );
  const { extractor, policyBinding: binding } = review.extraction;
  const work = new AbortController(),
    deadline = AbortSignal.timeout(120000),
    workSignal = AbortSignal.any([
      work.signal,
      deadline,
      ...(signal ? [signal] : []),
    ]);
  const guard = () => requireObservation(!workSignal.aborted);
  const read = async (file, expected) => {
    guard();
    const observed = await effects.readProtected(
      {
        file,
        maximum: expected.bytes,
        sha256: expected.sha256,
        bindings: structuredClone(expected.bindings),
      },
      { signal: workSignal },
    );
    requireObservation(
      Buffer.isBuffer(observed?.bytes) &&
        observed.bytes.length === expected.bytes &&
        digest(observed.bytes) === expected.sha256 &&
        observed.independent === true &&
        observed.held === true &&
        observed.birthProtected === true &&
        observed.protectedParents === true &&
        observed.unchanged === true &&
        observed.file === file &&
        hash(observed.identitySha256) &&
        hash(observed.nativeEventSha256),
    );
    requireObservation(
      observed.bindingsSha256 === observationDigest(expected.bindings) &&
        observed.loadedDependenciesVerified === true,
    );
    guard();
  };
  await read(extractor.path, extractor);
  const provisioning = structuredClone(
    await effects.readProvisioning(structuredClone(binding), {
      signal: workSignal,
    }),
  );
  const policy = materializeNativePolicy(
    binding.template,
    binding.approval,
    provisioning,
    binding.context,
  );
  const request = {
    schemaVersion: 1,
    candidateSha: review.candidateSha,
    platform: "win32",
    mode: "7z-data-only",
    extractor,
    archive,
    directory,
    archiveBytes: review.archiveBytes,
    archiveIntegrity: nativePackageInput(review.packageId).integrity,
    arguments: ["x", "-y", "-bd", "-bb0", `-o${directory}`, archive],
    reviewSha256: observationDigest(review),
    inventory: review.files,
    policySha256: policy.expectedPolicySha256,
    deadlineMs: 120000,
  };
  const requestSha256 = observationDigest(request);
  const verifyPolicy = async () => {
    const observed = await effects.readPolicy(
      structuredClone(request),
      structuredClone(binding),
      {
        signal: workSignal,
      },
    );
    verifyNativePolicy(
      binding.template,
      binding.approval,
      provisioning,
      binding.context,
      requestSha256,
      observed,
    );
    guard();
  };
  let failed = false,
    failure,
    extracted;
  try {
    await verifyPolicy();
    await persist({
      request: structuredClone(request),
      requestSha256,
      status: "POSSIBLE",
    });
    guard();
    await verifyPolicy();
    extracted = structuredClone(
      await effects.extract(structuredClone(request), { signal: workSignal }),
    );
    guard();
    requireObservation(
      extracted?.requestSha256 === requestSha256 &&
        extracted.independent === true &&
        extracted.inventoryVerifiedBeforeWrite === true &&
        extracted.archiveVerified === true &&
        extracted.archiveBytes === request.archiveBytes &&
        extracted.archiveIntegrity === request.archiveIntegrity &&
        extracted.dataOnly === true &&
        extracted.archiveExecuted === false &&
        extracted.extractorSha256 === extractor.sha256 &&
        extracted.exitCode === 0 &&
        extracted.signal === null &&
        extracted.timedOut === false &&
        hash(extracted.nativeEventSha256),
    );
  } catch (error) {
    failed = true;
    failure = error;
  } finally {
    work.abort();
  }
  // Cancellation of extraction cannot cancel the independent retirement gate.
  const cleanup = AbortSignal.timeout(30000);
  let settlement;
  try {
    settlement = structuredClone(
      await effects.settle(structuredClone(request), { signal: cleanup }),
    );
    requireObservation(
      !cleanup.aborted &&
        settlement?.requestSha256 === requestSha256 &&
        settlement.status === "RETIRED" &&
        settlement.independent === true &&
        settlement.noLiveMembers === true &&
        settlement.emergencyCleanup === false &&
        hash(settlement.nativeEventSha256),
    );
  } catch (error) {
    throw failed ? failure : error;
  }
  try {
    await persist({
      request: structuredClone(request),
      requestSha256,
      status: "RETIRED",
      receiptSha256: observationDigest(settlement),
    });
  } catch (error) {
    throw failed ? failure : error;
  }
  if (failed) throw failure;
  const verificationSignal = signal
    ? AbortSignal.any([signal, deadline])
    : deadline;
  requireObservation(!verificationSignal.aborted);
  const staged = structuredClone(
    await effects.verifyStaged(structuredClone(request), {
      signal: verificationSignal,
    }),
  );
  requireObservation(
    staged?.requestSha256 === requestSha256 &&
      staged.independent === true &&
      staged.complete === true &&
      staged.noReparsePoints === true &&
      staged.noAlternateStreams === true &&
      staged.protectedParents === true &&
      hash(staged.nativeEventSha256) &&
      Array.isArray(staged.files) &&
      staged.files.length === review.files.length,
  );
  const names = new Set();
  for (const file of staged.files) {
    const member = packageMemberPath(file.path),
      expected = review.files.find((entry) => entry.path === member);
    requireObservation(
      expected &&
        !names.has(member.toLowerCase()) &&
        file.kind === "file" &&
        file.links === 1 &&
        file.bytes === expected.bytes &&
        file.sha256 === expected.sha256 &&
        file.executable === expected.executable &&
        hash(file.identitySha256),
    );
    names.add(member.toLowerCase());
    requireObservation(!verificationSignal.aborted);
    const observed = await effects.readProtected(
      {
        file: path.join(directory, ...member.split("/")),
        maximum: Math.max(1, expected.bytes),
        sha256: expected.sha256,
      },
      { signal: verificationSignal },
    );
    requireObservation(
      Buffer.isBuffer(observed?.bytes) &&
        observed.bytes.length === expected.bytes &&
        digest(observed.bytes) === expected.sha256 &&
        observed.file === path.join(directory, ...member.split("/")) &&
        observed.held === true &&
        observed.independent === true &&
        observed.birthProtected === true &&
        observed.protectedParents === true &&
        observed.unchanged === true &&
        hash(observed.identitySha256) &&
        observed.identitySha256 === file.identitySha256 &&
        hash(observed.nativeEventSha256),
    );
    requireObservation(!verificationSignal.aborted);
  }
  const sealed = await effects.seal(structuredClone(request), {
    signal: verificationSignal,
  });
  requireObservation(
    !verificationSignal.aborted &&
      sealed?.requestSha256 === requestSha256 &&
      sealed.independent === true &&
      sealed.unchanged === true &&
      sealed.readExecuteOnly === true &&
      sealed.complete === true &&
      hash(sealed.nativeEventSha256),
  );
  return {
    settlement,
    nativeEventSha256: observationDigest({ extracted, staged, sealed }),
  };
}
