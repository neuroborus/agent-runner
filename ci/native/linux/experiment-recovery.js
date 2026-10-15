import { lstat, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { readProcessIdentity } from "../../../src/agents/index.js";
import { nativeException } from "../diagnostics.js";
import {
  normalizeExperimentJob,
  normalizeNativeJob,
  recordExperimentRecovery,
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import {
  readProtectedEvidence,
  protectedReceipt,
  digest,
  assertLinuxProcVisibility,
} from "./inspect.js";
import { freshVerifier } from "./proof.js";
import { LINUX_OWNERSHIP_CASES } from "./protocol.js";
import { ACCESS_PROFILES } from "./profiles.js";

const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;

/** Rejoin the purpose-bound reference and original native receipts only after
 * its writer has disappeared. No probe, build or failed observation is retried. */
export async function recoverLinuxExperimentProofs(
  input,
  directory,
  persist,
  {
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
    read = readProtectedEvidence,
    receipt = protectedReceipt,
    verify = freshVerifier,
    identity = readProcessIdentity,
    visible = assertLinuxProcVisibility,
    fs = { readdir, lstat },
    signal,
    fence = async (value) => {
      const file = path.join(directory, "experiment-proof-recovery.json");
      try {
        requireObservation(
          observationDigest(JSON.parse(await read(file))) ===
            observationDigest(value),
        );
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        await writeFile(file, JSON.stringify(value) + "\n", {
          flag: "wx",
          mode: 0o400,
        });
      }
    },
  } = {},
) {
  const job = normalizeExperimentJob(input);
  requireObservation(
    job.platform === "linux" &&
      platform === "linux" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24" &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      env.RUNNER_OS === "Linux" &&
      env.GITHUB_REPOSITORY === job.repository &&
      env.GITHUB_RUN_ID === job.runId &&
      env.GITHUB_RUN_ATTEMPT === String(job.runAttempt),
  );
  if (!job.cases.length) return job;
  try {
    await fence({
      purpose: "experiment",
      candidateSha: job.candidateSha,
      repository: job.repository,
      runId: job.runId,
      runAttempt: job.runAttempt,
      preparationSha256: observationDigest(job.preparation),
    });
    signal?.throwIfAborted();
    const envelope = JSON.parse(
      await read(path.join(directory, "experiment-reference.json")),
    );
    observationObject(envelope, [
      "purpose",
      "preparationSha256",
      "owner",
      "job",
    ]);
    observationObject(envelope.owner, ["pid", "identity"]);
    observationObject(envelope.owner.identity, ["bootId", "startTicks"]);
    requireObservation(
      envelope.purpose === "experiment" &&
        envelope.preparationSha256 === observationDigest(job.preparation) &&
        Number.isSafeInteger(envelope.owner.pid) &&
        envelope.owner.pid > 0 &&
        envelope.owner.pid <= 2147483647 &&
        /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(
          envelope.owner.identity.bootId,
        ) &&
        /^[0-9]{1,32}$/u.test(envelope.owner.identity.startTicks),
    );
    await visible();
    requireObservation((await identity(envelope.owner.pid)) === null);
    try {
      await fs.lstat(`/proc/${envelope.owner.pid}`);
      throw new Error("Original proof owner remains present");
    } catch (error) {
      requireObservation(["ENOENT", "ESRCH"].includes(error.code));
    }
    await visible();
    const reference = normalizeNativeJob(envelope.job),
      binding = job.preparation.expected.binding;
    requireObservation(
      reference.schemaVersion === 5 &&
        reference.platform === "linux" &&
        reference.candidateSha === job.candidateSha &&
        reference.checkoutSha === job.candidateSha &&
        reference.provenance.repository === job.repository &&
        reference.provenance.runId === job.runId &&
        reference.provenance.runAttempt === job.runAttempt &&
        reference.provenance.jobId === binding.jobId,
    );
    // Every original admission needs exhaustive native receipts, even if the
    // reference writer disappeared before publishing group retirement.
    requireObservation(
      Object.values(reference.admissions).every(
        ({ settlement }) => !settlement.emergencyCleanup,
      ),
    );
    const evidence = path.join(directory, "linux", "evidence"),
      names = await fs.readdir(evidence),
      reads = [];
    requireObservation(names.length <= 4096);
    const inspect = async (
      file,
      expectedCase,
      expectedSha256,
      expectedNonce,
    ) => {
      signal?.throwIfAborted();
      const sha256 = digest(await read(file)),
        native = await receipt(file, sha256);
      requireObservation(
        native.candidateSha === job.candidateSha &&
          native.caseId === expectedCase &&
          (!expectedSha256 || sha256 === expectedSha256) &&
          (!expectedNonce || native.nonce === expectedNonce) &&
          retired(await verify(file, sha256)),
      );
      reads.push({ file, sha256 });
      return { native, sha256 };
    };
    for (const [admission, ids] of [
      ["ownership", LINUX_OWNERSHIP_CASES],
      ["access", ACCESS_PROFILES],
    ])
      if (reference.admissions[admission].admission === "possible")
        for (const id of ids) {
          const nonce = (
            await read(
              path.join(directory, "linux", "control", `${id}.sentinel`),
            )
          ).toString();
          await inspect(path.join(evidence, `${id}.json`), id, null, nonce);
        }
    if (reference.admissions["file-build"].admission === "possible") {
      const record = JSON.parse(
        await read(path.join(directory, "preparation", "build-record.json")),
      );
      requireObservation(
        record.purpose === "experiment" &&
          record.candidateSha === job.candidateSha &&
          observationDigest({
            commands: record.commands,
            receipts: record.built.receipts,
          }) === job.preparationEffects.receiptSha256 &&
          record.built.receipts.length === 2,
      );
      // The experiment reuses preparation's two digest-bound original births.
      for (const index of [0, 1]) {
        const file = path.join(directory, "build", `command-${index}.json`);
        requireObservation(record.built.receipts[index].file === file);
        await inspect(file, "argv", record.built.receipts[index].sha256);
      }
    }
    const helpers = names.filter((name) =>
      /^file-helper-[a-f0-9-]{36}\.json$/u.test(name),
    );
    if (reference.admissions["file-helper"].admission === "possible")
      requireObservation(helpers.length > 0);
    const helperReceipts = new Map();
    for (const name of helpers) {
      const nonce = name.slice("file-helper-".length, -5);
      helperReceipts.set(
        nonce,
        await inspect(path.join(evidence, name), "file-helper", null, nonce),
      );
    }
    // Each file-session intent must have its original returned session and
    // terminal record. Fresh verifiers above still own descendant retirement.
    const admissions = new Map(),
      sessions = new Map(),
      sequences = new Map();
    for (const name of names.filter((name) =>
      /^file-cases-[a-f0-9-]{36}-[0-9]+\.json$/u.test(name),
    )) {
      const entry = JSON.parse(await read(path.join(evidence, name)));
      requireObservation(entry.candidateSha === job.candidateSha);
      const prefix = name.slice(0, name.lastIndexOf("-")),
        sequence = Number(name.slice(name.lastIndexOf("-") + 1, -5));
      const indices = sequences.get(prefix) ?? [];
      indices.push(sequence);
      sequences.set(prefix, indices);
      const key = `${prefix}:${entry.checkId}:${entry.sequence}`;
      if (entry.type === "admission") {
        requireObservation(!admissions.has(key));
        admissions.set(key, entry);
      }
      if (entry.type === "session") {
        requireObservation(!sessions.has(key));
        sessions.set(key, entry.result);
      }
    }
    for (const indices of sequences.values())
      requireObservation(
        indices
          .sort((a, b) => a - b)
          .every((index, position) => index === position),
      );
    const markers = names.filter((name) =>
      /^file-helper-[a-f0-9-]{36}-result\.json$/u.test(name),
    );
    requireObservation(
      markers.length === helpers.length &&
        helpers.every((name) =>
          markers.includes(name.replace(".json", "-result.json")),
        ),
    );
    requireObservation(
      admissions.size === sessions.size &&
        (helpers.length === 0 || sessions.size > 0),
    );
    for (const [key, session] of sessions) {
      requireObservation(
        admissions.has(key) &&
          retired(session.settlement) &&
          helperReceipts.get(session.nonce)?.sha256 === session.receiptDigest &&
          helpers.includes(`file-helper-${session.nonce}.json`),
      );
      const terminal = JSON.parse(
        await read(
          path.join(evidence, `file-helper-${session.nonce}-terminal.json`),
        ),
      );
      requireObservation(
        observationDigest(terminal) === observationDigest(session) &&
          /^file-[a-f0-9-]{36}$/u.test(session.anchorName),
      );
      const closed =
        session.storage === "REMOVED" && session.exclusion === "RELEASED"
          ? session
          : [...sessions.values()].find(
              (value) =>
                value.recoveredFrom === session.nonce &&
                value.anchorName === session.anchorName &&
                value.nativeAnchor === session.nativeAnchor &&
                value.storage === "REMOVED" &&
                value.exclusion === "RELEASED",
            );
      requireObservation(closed && retired(closed.settlement));
      try {
        await fs.lstat(path.join(directory, "linux", session.anchorName));
        throw new Error("Original file storage remains present");
      } catch (error) {
        requireObservation(error.code === "ENOENT");
      }
    }
    requireObservation(
      helpers.every((name) =>
        [...sessions.values()].some(
          (session) => name === `file-helper-${session.nonce}.json`,
        ),
      ),
    );
    requireObservation(reads.length > 0);
    const updated = recordExperimentRecovery(job, {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
      nativeEventSha256: observationDigest({ envelope, reads }),
    });
    await persist(updated);
    return updated;
  } catch (error) {
    nativeException("linux-experiment-proof-recovery", error);
    const retained = normalizeExperimentJob({
      ...job,
      failure: job.failure ?? "cleanup-failed",
    });
    await persist(retained);
    return retained;
  }
}
