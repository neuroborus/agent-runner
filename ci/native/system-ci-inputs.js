import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  observationDigest,
  observationObject,
  requireObservation,
} from "./observation.js";
import { normalizeNativeJob } from "./dispatch.js";
import { normalizeReviewAuthority } from "./closure.js";
import { nativePreparationError } from "./first-failure.js";
import { readSystemCIFile } from "./system-ci.js";
import {
  captureReviewData,
  nativeCandidateReader,
  verifyNativeReviewInputs,
} from "./review-inputs.js";
import { prerequisiteSourceSnapshot } from "./prerequisite-source.js";
import { normalizePrerequisiteAdmission } from "./prerequisite-worker.mjs";
import { normalizePrerequisiteCustodyApproval } from "./prerequisite-transport.js";

const MAXIMUM = 8 * 1024 * 1024;
const RECEIPT_MAXIMUM = 32 * 1024 * 1024;
const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const pins = [
  "RUNNER_TEMP",
  "NATIVE_SYSTEM_INPUT_REPOSITORY",
  "NATIVE_SYSTEM_INPUT_REVISION",
  "NATIVE_SYSTEM_REVIEW_SHA256",
  "NATIVE_LINUX_REVIEW_SHA256",
  "NATIVE_PROVIDER_REVIEW_SHA256",
  "NATIVE_SOURCE_REVIEW_SHA256",
  "NATIVE_REVIEWED_INPUT_DIRECTORY",
  "NATIVE_LINUX_REVIEW_FILE",
];
const binding = (job) => ({
  candidateSha: job.candidateSha,
  platform: job.platform,
  runId: job.provenance.runId,
  runAttempt: job.provenance.runAttempt,
});
const refuse = (id, missing = false) =>
  nativePreparationError("review", [
    { id, diagnosis: missing ? "missing" : "malformed" },
  ]);
const admitted = new WeakMap();

/** Progress and observed job IDs may change; original custody intents may not.
 * Bare historical test contexts retain exact equality, never a weaker scope. */
export function nativeCIJobBinding(original, current) {
  if (!original?.provenance || !current?.provenance)
    return (
      observationDigest(original ?? null) === observationDigest(current ?? null)
    );
  return (
    ["candidateSha", "platform", "schemaVersion", "tier"].every(
      (key) => original[key] === current[key],
    ) &&
    ["repository", "runId", "runAttempt"].every(
      (key) => original.provenance[key] === current.provenance[key],
    )
  );
}

function delivery(bytes, approved, job, now) {
  if (typeof approved !== "string" || !/^[a-f0-9]{64}$/u.test(approved))
    throw refuse("NATIVE_SYSTEM_CI_INPUTS_SHA256", !approved);
  if (
    !Buffer.isBuffer(bytes) ||
    !bytes.length ||
    bytes.length > MAXIMUM ||
    digest(bytes) !== approved
  )
    throw refuse("NATIVE_SYSTEM_CI_INPUTS_SHA256");
  try {
    const value = captureReviewData(
      JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
      MAXIMUM,
    );
    observationObject(value, [
      "schemaVersion",
      "candidateSha",
      "platform",
      "runId",
      "runAttempt",
      "expires",
      "templateReviews",
      "prerequisiteCustody",
    ]);
    requireObservation(
      value.schemaVersion === 1 &&
        Object.entries(binding(job)).every(
          ([key, expected]) => value[key] === expected,
        ),
    );
    requireObservation(
      Number.isSafeInteger(now) &&
        now >= 0 &&
        Number.isSafeInteger(value.expires) &&
        value.expires > now &&
        value.expires - now <= 86400000,
    );
    requireObservation(
      Array.isArray(value.templateReviews) &&
        value.templateReviews.length <= 256,
    );
    for (const review of value.templateReviews)
      normalizeReviewAuthority(review, job.candidateSha, job.platform);
    observationObject(value.prerequisiteCustody, [
      "output",
      "admission",
      "runtime",
      "privilege",
      "approvals",
    ]);
    requireObservation(
      normalizePrerequisiteAdmission(value.prerequisiteCustody.admission, now)
        .platform === job.platform,
    );
    return value;
  } catch {
    throw refuse("native-ci-inputs.json");
  }
}

/** Trusted provisioning supplies this file and its approval independently.
 * The captured bytes are data, never a module, factory or self approval. */
export async function readNativeSystemCIDelivery(
  job,
  env,
  { read = readSystemCIFile, now = Date.now } = {},
) {
  let bytes;
  try {
    job = normalizeNativeJob(job);
    requireObservation(
      job.schemaVersion === 6 &&
        typeof env.RUNNER_TEMP === "string" &&
        path.isAbsolute(env.RUNNER_TEMP) &&
        path.resolve(env.RUNNER_TEMP) === env.RUNNER_TEMP,
    );
    const file = path.resolve(
      env.RUNNER_TEMP,
      `native-${job.platform}-ci-inputs.json`,
    );
    bytes = await read(file, MAXIMUM);
  } catch (error) {
    throw refuse("native-ci-inputs.json", error?.code === "ENOENT");
  }
  const approvedAt = now();
  const value = delivery(
    bytes,
    env.NATIVE_SYSTEM_CI_INPUTS_SHA256,
    job,
    approvedAt,
  );
  return {
    value,
    bytes: Buffer.from(bytes),
    approvedAt,
    sha256: env.NATIVE_SYSTEM_CI_INPUTS_SHA256,
  };
}

/** Shared source, manifest, runtime, privilege, scope and output validators.
 * This completes data admission before any acquisition write or native effect. */
export async function admitNativeSystemCIDelivery(
  job,
  captured,
  system,
  env,
  {
    readCandidate = nativeCandidateReader(job.candidateSha, ROOT),
    verify = verifyNativeReviewInputs,
    now = Date.now,
  } = {},
) {
  try {
    requireObservation(captured.sha256 === env.NATIVE_SYSTEM_CI_INPUTS_SHA256);
    observationObject(system, ["manifest", "capabilityBytes", "linuxManifest"]);
    requireObservation(
      Buffer.isBuffer(system.capabilityBytes) &&
        system.capabilityBytes.length > 0 &&
        system.capabilityBytes.length <= 2097152,
    );
    system = {
      manifest: captureReviewData(system.manifest, MAXIMUM),
      capabilityBytes: Buffer.from(system.capabilityBytes),
      linuxManifest: captureReviewData(system.linuxManifest ?? null, MAXIMUM),
    };
    const value = delivery(
      captured.bytes,
      captured.sha256,
      job,
      captured.approvedAt,
    );
    requireObservation(system.manifest.schemaVersion === 2);
    const metadata = await verify(
      {
        ...binding(job),
        manifest: system.manifest,
        capabilityBytes: system.capabilityBytes,
        systemReviewSha256: env.NATIVE_SYSTEM_REVIEW_SHA256,
        linuxManifest: system.linuxManifest ?? null,
        linuxReviewSha256:
          job.platform === "linux" ? env.NATIVE_LINUX_REVIEW_SHA256 : null,
        templateReviews: value.templateReviews,
      },
      { readCandidate },
    );
    const source = async (name) => readCandidate("ci/native/" + name, 1048576);
    const snapshot = await prerequisiteSourceSnapshot(system.manifest, source);
    const sources = [...snapshot.sources];
    for (const name of [
      "first-failure.js",
      "prerequisite-source.js",
      "prerequisite-transport.js",
    ]) {
      const bytes = await source(name);
      const citations = system.manifest.source.citations.filter(
        (citation) =>
          citation.kind === "reached-code" &&
          citation.member === "candidate/ci/native/" + name,
      );
      requireObservation(
        citations.length === 1 && citations[0].sha256 === digest(bytes),
      );
      sources.push({ name, bytes: bytes.length, sha256: digest(bytes) });
    }
    normalizePrerequisiteCustodyApproval(
      value.prerequisiteCustody,
      system.manifest,
      sources,
      captured.approvedAt,
    );
    requireObservation(
      metadata.candidateEntryBound === true && now() < value.expires,
    );
    admitted.set(captured, {
      ...binding(job),
      job: normalizeNativeJob(captureReviewData(job, MAXIMUM)),
      approvedAt: captured.approvedAt,
      bytes: Buffer.from(captured.bytes),
      sha256: captured.sha256,
      system,
      environment: Object.fromEntries(
        pins.map((key) => [key, env[key] ?? null]),
      ),
    });
    return metadata;
  } catch {
    throw refuse("native-ci-inputs.json");
  }
}

function contextFile(directory) {
  return path.join(directory, "system-ci-input-context.json");
}

/** One immutable, controller-private receipt retains the original approval and
 * review context before effects. It is never renewed by a later delivery. */
export async function retainNativeSystemCIContext(
  job,
  directory,
  captured,
  system,
  env,
  { fs = { open, realpath }, read = readSystemCIFile } = {},
) {
  try {
    const original = admitted.get(captured);
    requireObservation(
      original &&
        Object.entries(binding(job)).every(
          ([key, value]) => original[key] === value,
        ) &&
        original.sha256 === env.NATIVE_SYSTEM_CI_INPUTS_SHA256 &&
        pins.every((key) => (env[key] ?? null) === original.environment[key]),
    );
    system = original.system;
    const custody = delivery(
      original.bytes,
      original.sha256,
      job,
      original.approvedAt,
    ).prerequisiteCustody;
    const paths = job.platform === "win32" ? path.win32 : path.posix;
    const lower = (file) =>
      job.platform === "win32" ? file.toLowerCase() : file;
    // The controller receipt and acquisition directory cannot be payload write roots.
    for (const root of custody.admission.writeRoots)
      for (const protectedRoot of [
        directory,
        path.resolve(env.RUNNER_TEMP, `native-${job.platform}-reviewed`),
        path.resolve(env.RUNNER_TEMP, `native-${job.platform}-ci-inputs.json`),
      ])
        requireObservation(
          !lower(protectedRoot).startsWith(lower(root) + paths.sep) &&
            lower(protectedRoot) !== lower(root) &&
            !lower(root).startsWith(lower(protectedRoot) + paths.sep),
        );
    requireObservation((await fs.realpath(directory)) === directory);
    const environment = original.environment;
    const record = {
      schemaVersion: 1,
      ...binding(job),
      job: original.job,
      approvedAt: original.approvedAt,
      deliverySha256: original.sha256,
      delivery: original.bytes.toString("base64"),
      environment,
      system: {
        manifest: system.manifest,
        capability: system.capabilityBytes.toString("base64"),
        linuxManifest: system.linuxManifest ?? null,
      },
    };
    const bytes = Buffer.from(JSON.stringify(record) + "\n");
    requireObservation(bytes.length <= RECEIPT_MAXIMUM);
    const file = contextFile(directory);
    const handle = await fs.open(
      file,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o400,
    );
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    requireObservation(
      (await read(file, RECEIPT_MAXIMUM, { privateReceipt: true })).equals(
        bytes,
      ),
    );
  } catch {
    throw refuse("native-ci-inputs.json");
  }
}

/** Recovery uses only the protected original receipt, including after expiry
 * or delivery removal. Expiry still fences every new work operation. */
export async function loadNativeSystemCIContext(
  job,
  directory,
  env,
  { recovery = false, read = readSystemCIFile, now = Date.now } = {},
) {
  try {
    const file = contextFile(directory);
    const record = captureReviewData(
      JSON.parse(await read(file, RECEIPT_MAXIMUM, { privateReceipt: true })),
      RECEIPT_MAXIMUM,
    );
    observationObject(record, [
      "schemaVersion",
      "candidateSha",
      "platform",
      "runId",
      "runAttempt",
      "job",
      "approvedAt",
      "deliverySha256",
      "delivery",
      "environment",
      "system",
    ]);
    requireObservation(
      record.schemaVersion === 1 &&
        Object.entries(binding(job)).every(
          ([key, expected]) => record[key] === expected,
        ) &&
        Number.isSafeInteger(record.approvedAt) &&
        record.approvedAt >= 0,
    );
    record.job = normalizeNativeJob(record.job);
    requireObservation(nativeCIJobBinding(record.job, job));
    const bytes = Buffer.from(record.delivery, "base64");
    requireObservation(bytes.toString("base64") === record.delivery);
    const value = delivery(
      bytes,
      record.deliverySha256,
      job,
      record.approvedAt,
    );
    observationObject(record.environment, pins);
    observationObject(record.system, [
      "manifest",
      "capability",
      "linuxManifest",
    ]);
    const capabilityBytes = Buffer.from(record.system.capability, "base64");
    requireObservation(
      capabilityBytes.toString("base64") === record.system.capability &&
        capabilityBytes.length <= 2097152 &&
        digest(capabilityBytes) === record.system.manifest.capabilitySha256,
    );
    // Current environment cannot change the original review scope for recovery.
    requireObservation(record.environment.RUNNER_TEMP === env.RUNNER_TEMP);
    if (!recovery) {
      requireObservation(
        env.NATIVE_SYSTEM_CI_INPUTS_SHA256 === record.deliverySha256 &&
          pins.every((key) => (env[key] ?? null) === record.environment[key]),
      );
    }
    const assertLive = () => {
      if (recovery || now() >= value.expires)
        throw refuse("native-ci-inputs.json");
    };
    if (!recovery) assertLive();
    return {
      templateReviews: value.templateReviews,
      prerequisiteCustody: {
        ...value.prerequisiteCustody,
        job: record.job,
        manifest: record.system.manifest,
      },
      reviewInputs: { ...record.system, capabilityBytes },
      env: {
        ...env,
        ...Object.fromEntries(
          pins.map((key) => [key, record.environment[key] ?? undefined]),
        ),
        NATIVE_SYSTEM_CI_INPUTS_SHA256: record.deliverySha256,
      },
      assertLive,
    };
  } catch {
    throw refuse("native-ci-inputs.json");
  }
}

/** Fence admission only. Settlement and recovery always reach original owners. */
export function guardNativeCIAdmissions(
  effects,
  assertLive,
  names = [
    "prepare",
    "provision",
    "build",
    "literal",
    "prepareBuild",
    "admit",
    "admitTransport",
    "launchParked",
  ],
) {
  for (const name of names) {
    const operation = effects[name]?.bind(effects);
    if (operation)
      effects[name] = (...args) => {
        assertLive();
        const result = operation(...args);
        if (name !== "prepare") return result;
        return Promise.resolve(result).then((value) => {
          if (value) {
            if (value.effects)
              guardNativeCIAdmissions(value.effects, assertLive);
            if (typeof value.admit === "function")
              guardNativeCIAdmissions(value, assertLive, ["admit"]);
            if (value.options)
              guardNativeCIAdmissions(value.options, assertLive, [
                "ownership",
                "access",
                "files",
                "build",
              ]);
          }
          return value;
        });
      };
  }
  return effects;
}
