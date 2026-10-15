import path from "node:path";
import { PLATFORMS } from "./catalog.js";
import { normalizeExperimentJob } from "./experiment.js";
import { compositionEffectRetired } from "./composition.js";
import { nativeException } from "./diagnostics.js";
import {
  systemJobBounds,
  experimentSystemInventory,
} from "./system-inventory.js";
import { boundSystemEffect } from "./system-ci.js";
import { normalizeNativeJob, renderNativeJob } from "./dispatch.js";
import {
  assertNativePreparationInputs,
  nativeFailureDetails,
  captureNativeFirstFailure,
  normalizeNativeFirstFailure,
  persistNativeFirstFailure,
  loadNativeFirstFailure,
} from "./first-failure.js";
import {
  observationDigest,
  observationObject,
  requireObservation,
} from "./observation.js";
import {
  prepareLinuxExperiment,
  loadLinuxExperiment,
  recoverLinuxExperimentPreparation,
  runLinuxExperimentProofs,
  recoverLinuxExperimentProofs,
  initialLinuxPreparation,
  prepareLinuxBubblewrap,
  initialLinuxNamespacePreparation,
  prepareLinuxNamespaces,
  verifyLinuxNamespaces,
  readLinuxNamespaceEvidence,
} from "./linux/index.js";
import {
  prepareDarwinExperiment,
  loadDarwinExperiment,
  recoverDarwinExperimentPreparation,
  runDarwinExperimentProofs,
} from "./darwin/index.js";
import {
  prepareWindowsExperiment,
  loadWindowsExperiment,
  recoverWindowsExperimentPreparation,
  recoverWindowsExperimentProofs,
  runWindowsExperimentProofs,
} from "./win32/index.js";

const owners = {
  linux: {
    prepare: (job, directory, persist, options) =>
      prepareLinuxExperiment(job, options.binding, directory, persist, options),
    load: loadLinuxExperiment,
    probe: runLinuxExperimentProofs,
    recoverPreparation: recoverLinuxExperimentPreparation,
    recover: recoverLinuxExperimentProofs,
  },
  darwin: {
    prepare: prepareDarwinExperiment,
    load: loadDarwinExperiment,
    probe: runDarwinExperimentProofs,
    recoverPreparation: recoverDarwinExperimentPreparation,
    recover: recoverDarwinExperimentPreparation,
  },
  win32: {
    prepare: prepareWindowsExperiment,
    load: loadWindowsExperiment,
    probe: runWindowsExperimentProofs,
    recoverPreparation: recoverWindowsExperimentPreparation,
    recover: recoverWindowsExperimentProofs,
  },
};
const namespaceContext = (job) => ({
  candidateSha: job.candidateSha,
  runId: job.runId,
  runAttempt: String(job.runAttempt),
});

export function runExperimentProofs(job, directory, options) {
  job = normalizeExperimentJob(job);
  return owners[job.platform].probe(job, directory, options);
}

/** Read-only hosted admission precedes every native stage. No external review
 * or delivery input participates in the ordinary experiment path. */
export async function observeExperimentBinding(
  job,
  env,
  controller,
  host = process,
) {
  assertNativePreparationInputs(job, env);
  const image = await controller.inspectImage(env),
    checkoutSha = (
      await controller.command("git", ["rev-parse", "HEAD"])
    ).stdout.trim(),
    jobs = await controller.listMetadata(env, "jobs"),
    selected = jobs.filter(
      (entry) =>
        entry.name === `native-system-${job.platform}` &&
        String(entry.run_id) === job.runId &&
        entry.run_attempt === job.runAttempt,
    );
  requireObservation(
    host.platform === job.platform &&
      host.arch === "x64" &&
      host.version === "v24.21.0" &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      env.RUNNER_OS ===
        { linux: "Linux", darwin: "macOS", win32: "Windows" }[job.platform] &&
      env.GITHUB_REPOSITORY === job.repository &&
      env.GITHUB_RUN_ID === job.runId &&
      env.GITHUB_RUN_ATTEMPT === String(job.runAttempt) &&
      (env.NATIVE_RUNTIME_OUTCOME ?? "success") === "success" &&
      checkoutSha === job.candidateSha &&
      image.os === job.platform &&
      image.architecture === "x64" &&
      image.image === PLATFORMS.find(({ os }) => os === job.platform).image &&
      selected.length === 1 &&
      Number.isSafeInteger(selected[0].id) &&
      selected[0].id > 0,
  );
  const binding = {
    candidateSha: job.candidateSha,
    platform: job.platform,
    repository: job.repository,
    runId: job.runId,
    runAttempt: job.runAttempt,
    checkoutSha,
    image: image.image,
    osBuild:
      job.platform === "win32"
        ? /^10\.0\.26100(?:\.|\s|$)/u.test(image.build)
          ? "10.0.26100"
          : null
        : env.ImageVersion,
    architecture: "x64",
    nodeVersion: host.version,
    workflow: "native-poc",
    jobId: String(selected[0].id),
  };
  requireObservation(
    typeof binding.osBuild === "string" &&
      /^[A-Za-z0-9.]{1,128}$/u.test(binding.osBuild),
  );
  if (job.preparation)
    requireObservation(
      observationDigest(binding) ===
        observationDigest(job.preparation.expected.binding),
    );
  return binding;
}

/** A private write-ahead stage journal fences reentry without adding stages or
 * reviewed provenance to the closed v7 payload. Cleanup is always a fresh lifetime. */
export async function runExperimentStage(
  stage,
  env,
  directory,
  controller,
  options = {},
) {
  const file = path.join(directory, "native-job.json"),
    receipt = path.join(directory, "native-first-failure.json"),
    journalFile = path.join(directory, "experiment-stages.json");
  let job = normalizeExperimentJob(await controller.readJSON(file)),
    writes = Promise.resolve();
  const save = async (value) => {
    const next = normalizeExperimentJob(value);
    writes = writes.then(async () => {
      await controller.persistJSON(file, next);
      job = next;
    });
    await writes;
  };
  const optional = async (name) => {
    try {
      return await controller.readJSON(name);
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw error;
    }
  };
  await save(
    await loadNativeFirstFailure(job, () => controller.readJSON(receipt)),
  );
  if (stage === "report") {
    const rendered = renderNativeJob(job);
    for (const [key, name] of [
      ["firstFailures", receipt],
      ["cleanupFailures", path.join(directory, "native-cleanup-failure.json")],
    ]) {
      const failure = await optional(name);
      if (failure) {
        const value = normalizeNativeFirstFailure(failure, job);
        rendered.report[key] = [value];
        rendered.summary += `\n\n${key === "firstFailures" ? "First failure" : "Cleanup failure"}: ${value.stage}/${value.diagnosis}.`;
      }
    }
    await controller.publish(env, directory, rendered);
    return experimentSystemInventory(job).status === "PASS";
  }
  requireObservation(
    ["prepare-linux", "prepare", "setup", "probe", "cleanup"].includes(stage),
  );
  const context = Object.fromEntries(
    ["candidateSha", "platform", "repository", "runId", "runAttempt"].map(
      (key) => [key, job[key]],
    ),
  );
  const journal = (await optional(journalFile)) ?? {
    purpose: "experiment",
    context,
    stages: {},
  };
  observationObject(journal, ["purpose", "context", "stages"]);
  observationObject(journal.context, Object.keys(context));
  requireObservation(
    journal.stages &&
      Object.getPrototypeOf(journal.stages) === Object.prototype &&
      Object.entries(journal.stages).every(
        ([key, value]) =>
          ["prepare-linux", "prepare", "setup", "probe", "cleanup"].includes(
            key,
          ) && ["POSSIBLE", "PASS", "FAIL"].includes(value),
      ),
  );
  requireObservation(
    journal.purpose === "experiment" &&
      observationDigest(journal.context) === observationDigest(context),
  );
  requireObservation(
    stage === "cleanup" || (!journal.stages.cleanup && !journal.stages[stage]),
  );
  journal.stages[stage] = "POSSIBLE";
  await controller.persistJSON(journalFile, journal);
  const owner = options.owner ?? owners[job.platform],
    bounds = systemJobBounds(job.platform, 7),
    deadline =
      stage === "prepare"
        ? bounds.preparationMs
        : stage === "probe"
          ? bounds.probeMs
          : stage === "cleanup"
            ? bounds.cleanupMs
            : stage === "setup"
              ? bounds.setupMs
              : bounds.preparationMs;
  let primary,
    active = true;
  try {
    await (options.bound ?? boundSystemEffect)(async (signal) => {
      const binding = await observeExperimentBinding(
          job,
          env,
          controller,
          options.host,
        ),
        persistStage = async (value) => {
          requireObservation(active && !signal.aborted);
          await save(value);
          requireObservation(active && !signal.aborted);
        },
        settings = { env, binding, signal, ...options.platformOptions };
      const assertActive = () => requireObservation(active && !signal.aborted);
      const persistAuxiliary = async (file, value, settings) => {
        assertActive();
        await controller.persistJSON(file, value, settings);
        assertActive();
      };
      assertActive();
      if (stage !== "cleanup") requireObservation(job.failure === null);
      if (stage === "prepare-linux") {
        requireObservation(
          job.platform === "linux" &&
            job.preparationEffects.admission === "not-started",
        );
        const packageFile = path.join(directory, "linux-preparation.json"),
          namespaceFile = path.join(
            directory,
            "linux-namespace-preparation.json",
          );
        requireObservation(
          (await controller.readJSON(packageFile)).status === "NOT_RUN",
        );
        const prepared = await (options.prepareLinux ?? prepareLinuxBubblewrap)(
          job.candidateSha,
          directory,
          (value) => persistAuxiliary(packageFile, value),
          settings,
        );
        requireObservation(prepared.status === "PASS");
        assertActive();
        const policy = await (
          options.prepareNamespaces ?? prepareLinuxNamespaces
        )(
          namespaceContext(job),
          directory,
          (value) => persistAuxiliary(namespaceFile, value, { mode: 0o600 }),
          settings,
        );
        requireObservation(policy.status === "PASS");
      } else if (stage === "prepare") {
        if (job.platform === "linux")
          requireObservation(journal.stages["prepare-linux"] === "PASS");
        await owner.prepare(job, directory, persistStage, settings);
        requireObservation(
          job.preparation &&
            compositionEffectRetired(job.preparationEffects) &&
            !job.failure,
        );
      } else if (stage === "setup") {
        requireObservation(
          journal.stages.prepare === "PASS" &&
            (env.NATIVE_PREPARATION_OUTCOME ?? "success") === "success",
        );
        await owner.load(job, directory, settings);
        if (job.platform === "linux")
          await verifyLinuxNamespaces(
            await readLinuxNamespaceEvidence(
              path.join(directory, "linux-namespace-preparation.json"),
            ),
            namespaceContext(job),
            directory,
            settings,
          );
      } else if (stage === "probe") {
        requireObservation(journal.stages.setup === "PASS");
        await persistStage(
          await owner.probe(job, directory, {
            ...settings,
            persist: persistStage,
          }),
        );
        requireObservation(experimentSystemInventory(job).status === "PASS");
      } else {
        // Preparation retirement cannot stand in for admitted case recovery.
        if (
          !compositionEffectRetired(job.preparationEffects) &&
          job.preparationEffects.admission === "possible"
        )
          await persistStage(
            await owner.recoverPreparation(
              job,
              directory,
              persistStage,
              settings,
            ),
          );
        if (
          job.platform !== "linux"
            ? job.preparation !== null
            : job.cases.some((entry) =>
                Object.values(entry.effects).some(
                  (effect) => !compositionEffectRetired(effect),
                ),
              )
        )
          await persistStage(
            await owner.recover(job, directory, persistStage, settings),
          );
        requireObservation(
          [
            job.preparationEffects,
            ...job.cases.flatMap((entry) => Object.values(entry.effects)),
          ].every(compositionEffectRetired),
        );
      }
      requireObservation(!signal.aborted);
    }, deadline);
  } catch (error) {
    active = false;
    primary = error;
    nativeException(`experiment-ci:${stage}`, error);
    // A write already released to the filesystem must finish before the first
    // cause snapshots its admissions. Otherwise a late rename could erase it.
    await boundSystemEffect(() => writes, 30000);
    const details = nativeFailureDetails(error);
    if (stage === "cleanup") {
      const cleanupFile = path.join(directory, "native-cleanup-failure.json");
      if (!(await optional(cleanupFile)))
        await controller.persistJSON(
          cleanupFile,
          captureNativeFirstFailure(job, stage, details),
        );
    }
    await persistNativeFirstFailure(job, stage, details, {
      read: () => optional(receipt),
      persist: (value) => controller.persistJSON(receipt, value),
      persistJob: save,
    });
  }
  active = false;
  journal.stages[stage] = primary ? "FAIL" : "PASS";
  await controller.persistJSON(journalFile, journal);
  return !primary;
}

export async function initializeExperimentCI(job, directory, controller) {
  job = normalizeNativeJob(job);
  requireObservation(job.purpose === "experiment");
  if (job.platform === "linux") {
    await controller.persistJSON(
      path.join(directory, "linux-preparation.json"),
      initialLinuxPreparation(job.candidateSha),
    );
    await controller.persistJSON(
      path.join(directory, "linux-namespace-preparation.json"),
      initialLinuxNamespacePreparation(namespaceContext(job)),
      { mode: 0o600 },
    );
  }
}
