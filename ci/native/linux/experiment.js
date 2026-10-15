import { lstat, realpath, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { readProcessIdentity } from "../../../src/agents/index.js";
import {
  initializeNativeJob,
  recordNativeStage,
  normalizeExperimentJob,
  recordExperimentCase,
  observationDigest,
  requireObservation,
  NATIVE_EFFECT_CLASSES,
  NATIVE_GROUPS,
  LINUX_NATIVE_GROUPS,
} from "../index.js";
import { linuxSystemRecipes } from "./composition.js";
import { loadLinuxExperiment } from "./experiment-preparation.js";
import { runLinuxSystemProofs } from "./system.js";
import { observeLinuxRelease } from "./release.js";
import { readLinuxObservedFile } from "./inspect.js";
import {
  readLinuxNamespaceEvidence,
  verifyLinuxNamespaces,
} from "./namespace-preparation.js";
import { persistLinuxExperimentFailure } from "./diagnostics.js";

const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;
const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
const contracts = (recipe) =>
  recipe.checkIds.map((checkId) => ({
    checkId,
    policyId: Object.values(LINUX_NATIVE_GROUPS).find(({ checkIds }) =>
      checkIds.includes(checkId),
    ).policyId,
  }));
const flags = ["matched", "positiveControl", "attempted", "sentinelsUnchanged"];
const controls = (status, observedFlags, settled) =>
  JSON.stringify({ status, ...observedFlags, retired: settled });
const expectedControls = controls(
  "PASS",
  Object.fromEntries(flags.map((key) => [key, true])),
  true,
);

/** Both fixed recipes reuse the real reference engine and fresh receipt owner.
 * The private v5 progress record is enclosed with experiment purpose; it is
 * never emitted as reviewed composition or protected approval. */
export async function runLinuxExperimentProofs(
  input,
  directory,
  {
    persist,
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
    load = loadLinuxExperiment,
    run = runLinuxSystemProofs,
    read = readLinuxObservedFile,
    namespaces = readLinuxNamespaceEvidence,
    verifyNamespaces = verifyLinuxNamespaces,
    now = () => performance.now(),
    signal,
    onFailure = (job, error) =>
      persistLinuxExperimentFailure(job, directory, "probe", error),
    persistReference: writeReference,
  } = {},
) {
  let job = normalizeExperimentJob(input),
    reference,
    bundle,
    policyWitness;
  requireObservation(
    platform === "linux" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24" &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      env.RUNNER_OS === "Linux" &&
      env.GITHUB_REPOSITORY === job.repository &&
      env.GITHUB_RUN_ID === job.runId &&
      env.GITHUB_RUN_ATTEMPT === String(job.runAttempt) &&
      job.platform === "linux" &&
      job.preparation &&
      retired(job.preparationEffects.settlement) &&
      job.failure === null &&
      job.cases.length === 0 &&
      typeof persist === "function",
  );
  const referenceOwner = {
    pid: process.pid,
    identity: await readProcessIdentity(process.pid),
  };
  const persistReference =
    writeReference ??
    ((value) =>
      persistLinuxExperimentReference(directory, value, job, referenceOwner));
  const recipes = linuxSystemRecipes();
  let started;
  const save = async (next) => {
    signal?.throwIfAborted();
    job = normalizeExperimentJob(next);
    await persist(job);
    signal?.throwIfAborted();
  };
  const admit = async (recipe) => {
    started = now();
    const effects = Object.fromEntries(
      NATIVE_EFFECT_CLASSES.map((key) => [
        key,
        {
          admission: "not-started",
          settlement: retained(),
          receiptSha256: null,
        },
      ]),
    );
    await save(
      recordExperimentCase(job, {
        purpose: "experiment",
        id: recipe.id,
        preparationSha256: observationDigest(job.preparation),
        status: "NOT_RUN",
        elapsedMs: null,
        cleanupMs: null,
        policy: {
          expectedSha256: observationDigest(contracts(recipe)),
          observedSha256: null,
          independent: false,
          effective: false,
        },
        components: null,
        observations: [],
        effects,
      }),
    );
    for (const key of NATIVE_GROUPS.linux[recipe.group].effects)
      effects[key] = {
        admission: "possible",
        settlement: retained(),
        receiptSha256: null,
      };
    await save(recordExperimentCase(job, { ...job.cases.at(-1), effects }));
  };
  const record = async (recipe, success) => {
    const byId = new Map(
      (reference?.results ?? []).map((result) => [result.checkId, result]),
    );
    const results = [];
    for (const id of recipe.checkIds) {
      const result = byId.get(id);
      if (!result) break;
      results.push(result);
    }
    const settled =
      reference &&
      Object.values(reference.admissions)
        .filter(({ admission }) => admission === "possible")
        .every(({ settlement }) => retired(settlement)) &&
      results.length === recipe.checkIds.length &&
      results.every(({ settlement }) => retired(settlement));
    const observations = results.map((result) => {
      const observedFlags = Object.fromEntries(
        flags.map((key) => [
          key,
          result.observations.length > 0 &&
            result.observations.every((value) => value[key] === true),
        ]),
      );
      return {
        checkId: result.checkId,
        observation: {
          expected: expectedControls,
          observed: controls(
            result.status,
            observedFlags,
            retired(result.settlement),
          ),
          ...observedFlags,
        },
      };
    });
    const actualContracts = results.map(({ checkId, policy }) => ({
      checkId,
      policyId: policy?.id ?? null,
    }));
    const cleanupStarted = now();
    const components = bundle ? [await bundle.observeRuntime()] : null;
    const cleanupMs = Math.ceil(now() - cleanupStarted);
    const elapsedMs = Math.ceil(now() - started),
      valid =
        success &&
        settled &&
        policyWitness &&
        elapsedMs <= recipe.deadlineMs &&
        cleanupMs <= 30000 &&
        observationDigest(actualContracts) ===
          job.cases.at(-1).policy.expectedSha256 &&
        observations.every(
          ({ observation }) =>
            observation.expected === observation.observed &&
            flags.every((key) => observation[key]),
        );
    const effects = structuredClone(job.cases.at(-1).effects);
    if (settled)
      for (const value of Object.values(effects).filter(
        ({ admission }) => admission === "possible",
      )) {
        value.settlement = {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
        };
        value.receiptSha256 = observationDigest({
          reference,
          policyWitness: policyWitness ?? null,
          components,
        });
      }
    await save(
      recordExperimentCase(job, {
        ...job.cases.at(-1),
        status: valid ? "PASS" : "FAIL",
        elapsedMs,
        cleanupMs,
        policy: {
          ...job.cases.at(-1).policy,
          observedSha256: observationDigest(actualContracts),
          independent: Boolean(policyWitness),
          effective:
            Boolean(policyWitness) &&
            results.every(({ status }) => status === "PASS"),
        },
        components,
        observations,
        effects,
      }),
    );
    if (!valid) await save({ ...job, failure: "probe-failed" });
  };
  await admit(recipes[0]);
  try {
    bundle = await load(job, directory, { env, platform, architecture });
    const binding = job.preparation.expected.binding;
    const node = await read(await realpath(process.execPath), 268435456);
    const namespace = await namespaces(
      path.join(directory, "linux-namespace-preparation.json"),
    );
    requireObservation(
      observationDigest(namespace) ===
        job.preparation.expected.sources.find(
          ({ id }) => id === "namespace-binding",
        )?.sha256,
    );
    await verifyNamespaces(
      namespace,
      {
        candidateSha: job.candidateSha,
        runId: job.runId,
        runAttempt: String(job.runAttempt),
      },
      directory,
    );
    const bwrap = namespace.after ?? namespace.before;
    requireObservation(
      namespace.status === "PASS" &&
        namespace.candidateSha === job.candidateSha &&
        namespace.runId === job.runId &&
        namespace.runAttempt === String(job.runAttempt) &&
        bwrap.executable.sha256 === (await read("/usr/bin/bwrap")).sha256 &&
        binding.nodeVersion === process.version,
    );
    reference = recordNativeStage(
      initializeNativeJob(
        {
          candidateSha: job.candidateSha,
          platform: "linux",
          repository: job.repository,
          runId: job.runId,
          runAttempt: job.runAttempt,
        },
        { schemaVersion: 5 },
      ),
      "setup",
      {
        status: "PASS",
        elapsedMs: Math.ceil(now() - started),
        deadlineMs: recipes[0].deadlineMs,
        reason: null,
      },
      {
        checkoutSha: binding.checkoutSha,
        observed: {
          os: "linux",
          image: binding.image,
          build: binding.osBuild,
          architecture: binding.architecture,
        },
        provenance: {
          repository: job.repository,
          runId: job.runId,
          runAttempt: job.runAttempt,
          workflow: "native-poc.yml",
          jobId: binding.jobId,
        },
        versions: [
          { name: "node", version: process.version, sha256: node.sha256 },
          {
            name: "bubblewrap",
            version: bwrap.executable.version,
            sha256: bwrap.executable.sha256,
          },
        ],
      },
    );
    signal?.throwIfAborted();
    await persistReference(reference);
    reference = await run(reference, directory, {
      env,
      platform,
      signal,
      purpose: "experiment",
      build: bundle.build,
      loadInputs: async () => ({ build: bundle.record.pins }),
      observeRelease: (...args) =>
        observeLinuxRelease(...args, { readObserved: read }),
      persist: async (value) => {
        signal?.throwIfAborted();
        reference = value;
        await persistReference(value);
        signal?.throwIfAborted();
      },
      onPolicy: async (proof) => {
        requireObservation(/^[a-f0-9]{64}$/u.test(proof.nativeEventSha256));
        policyWitness = observationDigest(proof);
      },
      beforeRelease: async (value) => {
        reference = value;
        await record(
          recipes[0],
          value.results.length === 22 &&
            value.results.every(({ status }) => status === "PASS"),
        );
        requireObservation(job.failure === null);
        await admit(recipes[1]);
      },
    });
    await record(
      recipes[job.cases.length - 1],
      reference.results.length === 23 &&
        reference.results.every(({ status }) => status === "PASS"),
    );
  } catch (error) {
    const current = job.cases.at(-1);
    if (current.status === "NOT_RUN")
      await save(
        recordExperimentCase(job, {
          ...current,
          status: "FAIL",
          elapsedMs: Math.ceil(now() - started),
          cleanupMs: null,
        }),
      );
    try {
      await onFailure(job, error);
    } finally {
      await save({ ...job, failure: job.failure ?? "probe-failed" });
    }
  }
  return job;
}

async function persistLinuxExperimentReference(
  directory,
  reference,
  job,
  owner,
) {
  try {
    await lstat(path.join(directory, "experiment-proof-recovery.json"));
    throw new Error("Linux experiment proof admission is fenced by recovery");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const file = path.join(directory, "experiment-reference.json"),
    temporary = `${file}.${process.pid}.tmp`;
  await writeFile(
    temporary,
    JSON.stringify({
      purpose: "experiment",
      preparationSha256: observationDigest(job.preparation),
      owner,
      job: reference,
    }) + "\n",
    { flag: "wx", mode: 0o400 },
  );
  await rename(temporary, file);
}
