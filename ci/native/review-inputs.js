import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { initializeNativeJob } from "./dispatch.js";
import {
  observationDigest,
  observationList,
  requireObservation,
} from "./observation.js";
import { sourceReviewDigest } from "./evidence.js";
import { releaseClosureDigest } from "./closure.js";
import { NATIVE_PREREQUISITE_LIMITS } from "./prerequisites.js";
import { readSystemCIFile } from "./system-ci.js";
import { packageMemberPath } from "./package-inputs.js";

const ENTRY = "ci/native/native-effects.mjs";
const ENTRY_BYTES = 2097152,
  SOURCE_BYTES = 1048576;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const owners = Object.freeze({
  linux: async () => (await import("./linux/index.js")).admitLinuxSystemReview,
  darwin: async () =>
    (await import("./darwin/index.js")).admitDarwinSystemReview,
  win32: async () =>
    (await import("./win32/index.js")).admitWindowsSystemReview,
});

// Capture JSON data through descriptors before serialization or asynchronous
// reads. Record schemas remain owned by the existing manifest validators.
export function captureReviewData(input, maximum) {
  let remaining = maximum;
  const consume = (bytes) => requireObservation((remaining -= bytes) >= 0);
  const copy = (value, depth = 0) => {
    requireObservation(depth <= 64);
    if (
      value === null ||
      ["string", "boolean", "number"].includes(typeof value)
    ) {
      requireObservation(typeof value !== "number" || Number.isFinite(value));
      consume(Buffer.byteLength(JSON.stringify(value)));
      return value;
    }
    requireObservation(typeof value === "object");
    if (Array.isArray(value)) {
      const values = observationList(value, maximum);
      consume(2 + Math.max(0, values.length - 1));
      return values.map((item) => copy(item, depth + 1));
    }
    const prototype = Object.getPrototypeOf(value);
    requireObservation(prototype === Object.prototype || prototype === null);
    const keys = Reflect.ownKeys(value);
    consume(2 + Math.max(0, keys.length - 1));
    const entries = keys.map((key) => {
      const field = Object.getOwnPropertyDescriptor(value, key);
      requireObservation(
        typeof key === "string" &&
          field?.enumerable &&
          Object.hasOwn(field, "value"),
      );
      consume(Buffer.byteLength(JSON.stringify(key)) + 1);
      return [key, copy(field.value, depth + 1)];
    });
    return Object.setPrototypeOf(Object.fromEntries(entries), prototype);
  };
  return copy(input);
}

/** Immutable regular-file Git blobs only; missing objects cannot trigger fetch. */
export function nativeCandidateReader(
  candidateSha,
  repository,
  { execute = promisify(execFile), env = process.env } = {},
) {
  requireObservation(/^[a-f0-9]{40}$/u.test(candidateSha));
  const inspect = async (args, maximum) =>
    (
      await execute(
        "git",
        ["--no-replace-objects", "-C", path.resolve(repository), ...args],
        {
          encoding: "buffer",
          maxBuffer: maximum,
          timeout: 10000,
          env: { ...env, GIT_OPTIONAL_LOCKS: "0", GIT_NO_LAZY_FETCH: "1" },
        },
      )
    ).stdout;
  let commit;
  return async (member, maximum) => {
    packageMemberPath(member);
    requireObservation(
      Number.isSafeInteger(maximum) && maximum > 0 && maximum <= ENTRY_BYTES,
    );
    commit ??= inspect(["cat-file", "-t", candidateSha], 64);
    requireObservation((await commit).toString() === "commit\n");
    const entry = (
      await inspect(["ls-tree", candidateSha, "--", member], 4096)
    ).toString();
    requireObservation(
      /^(?:100644|100755) blob [a-f0-9]{40,64}\t/u.test(entry) &&
        entry.split("\t")[1] === member + "\n",
    );
    return inspect(["cat-file", "blob", `${candidateSha}:${member}`], maximum);
  };
}

/** Metadata and supplied candidate bytes only. Approvals are external inputs;
 * no acquired entry is evaluated and no native factory is constructed. */
export async function verifyNativeReviewInputs(
  {
    candidateSha,
    platform,
    manifest,
    capabilityBytes,
    systemReviewSha256,
    linuxManifest = null,
    linuxReviewSha256 = null,
    templateReviews = [],
  },
  { readCandidate } = {},
) {
  requireObservation(
    typeof candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(candidateSha) &&
      typeof platform === "string" &&
      Object.hasOwn(owners, platform) &&
      typeof readCandidate === "function" &&
      Buffer.isBuffer(capabilityBytes) &&
      capabilityBytes.length > 0 &&
      capabilityBytes.length <= ENTRY_BYTES &&
      Array.isArray(templateReviews) &&
      (platform === "linux" ||
        (linuxManifest === null && linuxReviewSha256 === null)),
  );
  // Capture caller-owned data before any asynchronous read can mutate it.
  manifest = captureReviewData(
    manifest,
    NATIVE_PREREQUISITE_LIMITS.metadataBytes,
  );
  linuxManifest = captureReviewData(linuxManifest, SOURCE_BYTES);
  templateReviews = captureReviewData(
    templateReviews,
    NATIVE_PREREQUISITE_LIMITS.metadataBytes,
  );
  requireObservation(
    manifest.execution?.schemaVersion === 2 || templateReviews.length === 0,
  );
  capabilityBytes = Buffer.from(capabilityBytes);
  const job = initializeNativeJob(
    {
      candidateSha,
      platform,
      repository: "review/inputs",
      runId: "1",
      runAttempt: 1,
    },
    { schemaVersion: 6, tier: "system" },
  );
  const admit = await owners[platform]();
  const admission = admit(job, manifest, {
    systemReviewSha256,
    linuxManifest,
    linuxReviewSha256,
    templateReviews,
  });
  requireObservation(
    digest(capabilityBytes) === manifest.capabilitySha256 &&
      (manifest.schemaVersion !== 2 ||
        Buffer.from(capabilityBytes.toString("utf8")).equals(capabilityBytes)),
  );
  const captured = new Map();
  const read = async (member, maximum = SOURCE_BYTES) => {
    packageMemberPath(member);
    if (!captured.has(member)) {
      const bytes = await readCandidate(member, maximum);
      requireObservation(
        Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= maximum,
      );
      captured.set(member, Buffer.from(bytes));
    }
    requireObservation(captured.get(member).length <= maximum);
    return captured.get(member);
  };
  if (manifest.schemaVersion === 2) {
    requireObservation(
      (await read(ENTRY, ENTRY_BYTES)).equals(capabilityBytes) &&
        manifest.source.citations.filter(
          (citation) =>
            citation.kind === "reached-code" &&
            citation.member === "candidate/" + ENTRY &&
            citation.sha256 === manifest.capabilitySha256,
        ).length === 1,
    );
  }
  for (const helper of manifest.helpers)
    requireObservation(
      digest(await read(`ci/native/${platform}/${helper.name}.c`)) ===
        helper.sourceSha256,
    );
  for (const asset of manifest.prerequisites?.assets ?? []) {
    if (asset.kind !== "source") continue;
    const bytes = await read(`ci/native/${platform}/${asset.name}`);
    requireObservation(
      bytes.length === asset.bytes && digest(bytes) === asset.sha256,
    );
  }
  for (const citation of manifest.source.citations) {
    if (!citation.member.startsWith("candidate/")) continue;
    const member = citation.member.slice(10);
    const fact = manifest.source.inspected.find(
      ({ id }) => id === citation.sourceId,
    );
    const bytes = await read(
      member,
      member === ENTRY ? ENTRY_BYTES : SOURCE_BYTES,
    );
    requireObservation(
      fact.revision === candidateSha &&
        digest(bytes) === citation.sha256 &&
        citation.lastLine <= bytes.toString("utf8").split("\n").length,
    );
  }
  return {
    status: "METADATA_VERIFIED",
    candidateSha,
    platform,
    references: {
      system: observationDigest(manifest),
      source: sourceReviewDigest(manifest.source),
      release: releaseClosureDigest(manifest.release),
      execution: observationDigest(manifest.execution),
      capability: digest(capabilityBytes),
      linux: admission.linuxReviewSha256 ?? null,
    },
    approvals: {
      system: systemReviewSha256,
      linux: linuxReviewSha256,
      templates:
        manifest.execution.schemaVersion === 2
          ? manifest.execution.policyTemplates.map(
              ({ approval }) => approval.manifestSha256,
            )
          : [],
    },
    candidateEntryBound: manifest.schemaVersion === 2,
    prerequisiteCustodyRequired: manifest.schemaVersion === 2,
    templateReviewsRequired: manifest.execution.schemaVersion === 2,
    nativeCustody: "NOT_OBSERVED",
    nativeAdmission: "NOT_OBSERVED",
  };
}

/** Read-only CLI: local metadata and immutable Git blobs, never native tools or
 * installed inputs. Git effects are restricted to object inspection. */
export async function verifyNativeReviewInputsCommand(
  args,
  { readFile = readSystemCIFile, execute = promisify(execFile) } = {},
) {
  const names = [
    "--candidate",
    "--platform",
    "--candidate-repository",
    "--inputs",
    "--system-review",
    "--linux-review",
    "--template-reviews",
  ];
  const options = new Map();
  requireObservation(args.length % 2 === 0);
  for (let index = 0; index < args.length; index += 2) {
    requireObservation(
      names.includes(args[index]) &&
        !options.has(args[index]) &&
        typeof args[index + 1] === "string" &&
        args[index + 1].length > 0,
    );
    options.set(args[index], args[index + 1]);
  }
  requireObservation(names.slice(0, 5).every((name) => options.has(name)));
  const candidateSha = options.get("--candidate"),
    platform = options.get("--platform");
  requireObservation(
    /^[a-f0-9]{40}$/u.test(candidateSha) && Object.hasOwn(owners, platform),
  );
  const root = path.resolve(options.get("--inputs"));
  const json = async (
    file,
    maximum = NATIVE_PREREQUISITE_LIMITS.metadataBytes,
  ) => JSON.parse(await readFile(file, maximum));
  const readCandidate = nativeCandidateReader(
    candidateSha,
    options.get("--candidate-repository"),
    { execute },
  );
  return verifyNativeReviewInputs(
    {
      candidateSha,
      platform,
      manifest: await json(path.join(root, "system-inputs.json")),
      capabilityBytes: await readFile(path.join(root, "native-effects.mjs")),
      systemReviewSha256: options.get("--system-review"),
      linuxManifest:
        platform === "linux"
          ? await json(path.join(root, "linux-review.json"), SOURCE_BYTES)
          : null,
      linuxReviewSha256: options.get("--linux-review") ?? null,
      templateReviews: options.has("--template-reviews")
        ? await json(path.resolve(options.get("--template-reviews")))
        : [],
    },
    { readCandidate },
  );
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  verifyNativeReviewInputsCommand(process.argv.slice(2)).then(
    (result) => process.stdout.write(JSON.stringify(result) + "\n"),
    () => {
      process.exitCode = 1;
      process.stderr.write(
        "Review inputs unverified; evidence, independent approvals and native admission remain required.\n",
      );
    },
  );
}
