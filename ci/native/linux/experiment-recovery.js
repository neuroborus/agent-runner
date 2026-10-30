import { lstat, readdir, rename, writeFile } from "node:fs/promises";
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
import { linuxExperimentProofState } from "./experiment.js";
import {
  recoverLinuxExperimentPreparation,
  rejoinLinuxExperimentInterpreter,
} from "./experiment-preparation.js";
import { readLinuxNamespaceEvidence } from "./namespace-preparation.js";

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
    verify: verifyInput,
    identity = readProcessIdentity,
    visible = assertLinuxProcVisibility,
    fs = { readdir, lstat },
    signal,
    proofJournal,
    readJournal = readLinuxNamespaceEvidence,
    persistProof,
    reconcilePreparation = recoverLinuxExperimentPreparation,
    rejoinInterpreter = rejoinLinuxExperimentInterpreter,
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
  try {
    const journal =
        proofJournal ??
        (await readJournal(path.join(directory, "experiment-stages.json"))),
      proof = linuxExperimentProofState(job, journal);
    if (!proof) {
      requireObservation(!journal.stages.probe && job.cases.length === 0);
      return job;
    }
    const saveProof = async (next) => {
      if (persistProof) await persistProof(next);
      else {
        const file = path.join(directory, "experiment-stages.json"),
          temporary = `${file}.${process.pid}.tmp`;
        await writeFile(
          temporary,
          JSON.stringify({ ...journal, proof: next }) + "\n",
          { flag: "wx", mode: 0o600 },
        );
        await rename(temporary, file);
      }
    };
    const close = (reads) =>
      saveProof({
        ...proof,
        retirementSha256: observationDigest({
          proof: { ...proof, retirementSha256: null },
          reads,
        }),
      });
    await saveProof({ ...proof, retirementSha256: null });
    await fence({
      purpose: "experiment",
      candidateSha: job.candidateSha,
      repository: job.repository,
      runId: job.runId,
      runAttempt: job.runAttempt,
      preparationSha256: observationDigest(job.preparation),
    });
    signal?.throwIfAborted();
    requireObservation(proof.owner !== null);
    await visible();
    requireObservation((await identity(proof.owner.pid)) === null);
    try {
      await fs.lstat(`/proc/${proof.owner.pid}`);
      throw new Error("Original proof owner remains present");
    } catch (error) {
      requireObservation(["ENOENT", "ESRCH"].includes(error.code));
    }
    await visible();
    const interpreter = await rejoinInterpreter(job, directory);
    const verify =
      verifyInput ??
      ((file, sha256) => freshVerifier(file, sha256, { interpreter }));
    await reconcilePreparation(job, directory, async () => {}, {
      env,
      platform,
      architecture,
      fs,
      read,
      receipt,
      verify,
      identity,
      visible,
      reconcile: true,
    });
    let envelope;
    try {
      envelope = JSON.parse(
        await read(path.join(directory, "experiment-reference.json")),
      );
    } catch (error) {
      requireObservation(
        error.code === "ENOENT" &&
          !proof.releasePossible &&
          job.cases.length === 0,
      );
      await close({
        release: "not-started",
        preparation: job.preparationEffects,
      });
      return job;
    }
    observationObject(envelope, [
      "purpose",
      "preparationSha256",
      "owner",
      "job",
    ]);
    requireObservation(
      envelope.purpose === "experiment" &&
        envelope.preparationSha256 === proof.preparationSha256 &&
        observationDigest(envelope.owner) === observationDigest(proof.owner),
    );
    const reference = normalizeNativeJob(envelope.job, {
        purpose: "experiment",
      }),
      binding = job.preparation.expected.binding;
    requireObservation(
      reference.schemaVersion === 5 &&
        reference.platform === "linux" &&
        reference.candidateSha === job.candidateSha &&
        reference.buildObservationSha256 ===
          job.preparationEffects.receiptSha256 &&
        reference.checkoutSha === job.candidateSha &&
        reference.provenance.repository === job.repository &&
        reference.provenance.runId === job.runId &&
        reference.provenance.runAttempt === job.runAttempt &&
        reference.provenance.jobId === binding.jobId,
    );
    if (
      Object.values(reference.admissions).every(
        ({ admission }) => admission === "not-started",
      )
    ) {
      requireObservation(
        reference.results.length === 0 &&
          (proof.releasePossible || job.cases.length === 0) &&
          job.cases.length <= 1 &&
          job.cases.every(
            ({ status, observations }) =>
              status !== "PASS" && observations.length === 0,
          ),
      );
      const updated = recordExperimentRecovery(job, {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest(envelope),
      });
      await persist(updated);
      await close({ envelope, preparation: job.preparationEffects });
      return updated;
    }
    requireObservation(proof.releasePossible);
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
    await close({ envelope, reads });
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
