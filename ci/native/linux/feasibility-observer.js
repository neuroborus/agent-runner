import { constants } from "node:fs";
import { lstat, open, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { feasibilityCapabilities } from "../feasibility/index.js";
import { digest, protectedReceipt } from "./inspect.js";
import { freshVerifier } from "./proof.js";

export function requireLinuxFeasibilityCI(candidateSha) {
  if (
    process.platform !== "linux" ||
    process.arch !== "x64" ||
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    process.env.RUNNER_OS !== "Linux" ||
    process.env.ImageOS !== "ubuntu24" ||
    !/^[a-f0-9]{40}$/u.test(candidateSha ?? "")
  ) {
    const error = new Error(
      "Linux feasibility requires matching Ubuntu 24.04 hosted CI",
    );
    error.code = "ERR_NATIVE_FEASIBILITY_WORKER_UNAVAILABLE";
    throw error;
  }
}

export function linuxFeasibilityCause(stage, error) {
  const prerequisite = error?.prerequisites?.checks?.find(
    (entry) => entry.status === "BLOCKED",
  );
  const unavailable =
    [
      "ERR_NATIVE_FEASIBILITY_PREREQUISITE_UNAVAILABLE",
      "ERR_NATIVE_FEASIBILITY_WORKER_UNAVAILABLE",
    ].includes(error?.code) ||
    ["absent", "protection-unavailable"].includes(prerequisite?.diagnosis) ||
    (prerequisite?.diagnosis === "probe-failed" &&
      prerequisite.observation?.exitCode === 1 &&
      prerequisite.observation.signal === null &&
      prerequisite.observation.timedOut === false);
  const code = /^[A-Z0-9_]{1,64}$/u.test(String(error?.code ?? ""))
    ? String(error.code)
    : "UNVERIFIED";
  const observation = prerequisite?.observation;
  const timedOut =
    observation?.timedOut === true || error?.code === "ETIMEDOUT";
  const signal = observation?.signal ?? error?.signal;
  const outcome =
    observation?.errno ??
    observation?.signal ??
    (Number.isInteger(observation?.exitCode)
      ? `EXIT_${observation.exitCode}`
      : code);
  return {
    code: unavailable
      ? "prerequisite-unavailable"
      : timedOut
        ? "deadline"
        : signal
          ? "crash"
          : "setup-failed",
    detail: `Linux ${stage} failed (${prerequisite ? `${prerequisite.id}, ${prerequisite.diagnosis}, ${outcome}` : code}).`,
  };
}

/** Held owned sentinels bind contents and identity, not just a path read. */
export async function observeLinuxFeasibilitySentinel(file) {
  if ((await realpath(file)) !== file)
    throw new Error("Substituted sentinel path");
  const before = await lstat(file, { bigint: true });
  const handle = await open(
    file,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const held = await handle.stat({ bigint: true });
    const fields = [
      "dev",
      "ino",
      "mode",
      "uid",
      "gid",
      "nlink",
      "size",
      "mtimeNs",
      "ctimeNs",
    ];
    if (
      !held.isFile() ||
      held.uid !== BigInt(process.getuid()) ||
      held.nlink !== 1n ||
      ![0o400n, 0o600n].includes(held.mode & 0o7777n) ||
      held.size < 1n ||
      held.size > 4096n ||
      fields.some((key) => held[key] !== before[key])
    )
      throw new Error("Unprotected feasibility sentinel");
    const bytes = Buffer.alloc(4097);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const [after, named] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(file, { bigint: true }),
    ]);
    if (
      bytesRead !== Number(held.size) ||
      fields.some((key) => held[key] !== after[key] || held[key] !== named[key])
    )
      throw new Error("Feasibility sentinel identity changed");
    return {
      ...Object.fromEntries(fields.map((key) => [key, String(held[key])])),
      sha256: digest(bytes.subarray(0, bytesRead)),
    };
  } finally {
    await handle.close();
  }
}

/** The existing verifier starts a fresh process, reopens the protected receipt,
 * and checks persisted boot/start identities and namespace retirement. */
export async function observeLinuxFeasibilityRetirement(
  binding,
  candidateSha,
  caseId,
  { readReceipt = protectedReceipt, verify = freshVerifier } = {},
) {
  if (readReceipt === protectedReceipt || verify === freshVerifier)
    requireLinuxFeasibilityCI(candidateSha);
  if (
    !binding ||
    typeof binding.file !== "string" ||
    !path.isAbsolute(binding.file) ||
    !/^[a-f0-9]{64}$/u.test(binding.sha256 ?? "")
  )
    throw new Error("Missing feasibility retirement binding");
  const receipt = await readReceipt(binding.file, binding.sha256);
  if (
    receipt.candidateSha !== candidateSha ||
    receipt.caseId !== caseId ||
    receipt.hostSession !== false ||
    receipt.isolatedNamespace !== true
  )
    throw new Error("Feasibility retirement receipt mismatch");
  const settlement = await verify(binding.file, binding.sha256);
  const repeated = await readReceipt(binding.file, binding.sha256);
  if (JSON.stringify(receipt) !== JSON.stringify(repeated))
    throw new Error("Feasibility retirement receipt changed");
  return {
    candidateSha,
    caseId,
    receiptSha256: binding.sha256,
    receipt,
    settlement,
  };
}

export async function persistLinuxFeasibilityObservation(fixture, name, value) {
  const bytes = JSON.stringify(value) + "\n";
  await writeFile(
    path.join(fixture.directory, "evidence", `${name}-feasibility.json`),
    bytes,
    { flag: "wx", mode: 0o400 },
  );
  return digest(bytes);
}

/** Refuse another admission until the preceding evidence and cleanup settle. */
export function canContinueLinuxFeasibility(entry) {
  const isDigest = (value) =>
    typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
  return (
    entry.status === "PASS" &&
    entry.ready === true &&
    entry.positiveControl === true &&
    entry.attemptAcknowledged === true &&
    isDigest(entry.observationSha256) &&
    isDigest(entry.sentinelsBeforeSha256) &&
    entry.sentinelsBeforeSha256 === entry.sentinelsAfterSha256 &&
    Number.isSafeInteger(entry.elapsedMs) &&
    entry.elapsedMs >= 0 &&
    entry.elapsedMs <= 120000 &&
    entry.cleanup.status === "PASS" &&
    entry.cleanup.independent === true &&
    entry.cleanup.emergency === false &&
    isDigest(entry.cleanup.witnessSha256) &&
    Number.isSafeInteger(entry.cleanup.elapsedMs) &&
    entry.cleanup.elapsedMs >= 0 &&
    entry.cleanup.elapsedMs <= 30000
  );
}

/** Joins independently collected entries; the pure report contract still
 * rejects missing controls, observations, deadlines and uncertain cleanup. */
export function linuxFeasibilityResult(capability, entries, components) {
  const definition = feasibilityCapabilities("linux").find(
    ({ id }) => id === capability,
  );
  if (!definition || entries.length === 0)
    throw new Error("Missing feasibility case");
  const failed = entries.find((entry) => entry.status !== "PASS");
  const unsettled = entries.find((entry) => entry.cleanup.status !== "PASS");
  const bothBundles =
    !["git.denial", "network.tcp-denial", "ipc.local-denial"].includes(
      capability,
    ) ||
    (entries.length === 2 &&
      ["read-only", "workspace-write"].every(
        (caseId) =>
          entries.filter((entry) => entry.caseId === caseId).length === 1,
      ));
  const isDigest = (value) =>
    typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
  const joinDigests = (values) =>
    values.every(isDigest) ? digest(JSON.stringify(values)) : null;
  return {
    capability,
    status: failed || !bothBundles ? "FAIL" : "PASS",
    cause:
      failed?.cause ??
      (bothBundles
        ? null
        : {
            code: "missing-observation",
            detail:
              "Linux shared denial requires both distinct fixed access bundles.",
          }),
    elapsedMs: entries.reduce((sum, entry) => sum + entry.elapsedMs, 0),
    components,
    evidence: {
      ready: entries.every((entry) => entry.ready === true),
      positiveControl: entries.every((entry) => entry.positiveControl === true),
      attemptAcknowledged: entries.every(
        (entry) => entry.attemptAcknowledged === true,
      ),
      independent: entries.every((entry) => isDigest(entry.observationSha256)),
      outcome: definition.outcome,
      observationSha256: joinDigests(
        entries.map((entry) => entry.observationSha256),
      ),
      sentinelsBeforeSha256: joinDigests(
        entries.map((entry) => entry.sentinelsBeforeSha256),
      ),
      sentinelsAfterSha256: joinDigests(
        entries.map((entry) => entry.sentinelsAfterSha256),
      ),
    },
    cleanup: {
      status: unsettled?.cleanup.status ?? "PASS",
      independent: entries.every((entry) => entry.cleanup.independent),
      emergency: entries.some((entry) => entry.cleanup.emergency),
      elapsedMs: entries.every((entry) => entry.cleanup.elapsedMs !== null)
        ? entries.reduce((sum, entry) => sum + entry.cleanup.elapsedMs, 0)
        : null,
      witnessSha256: joinDigests(
        entries.map((entry) => entry.cleanup.witnessSha256),
      ),
      cause: unsettled?.cleanup.cause ?? null,
    },
  };
}
