import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFile,
  lstat,
  mkdir,
  readFile,
  rename,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  initializeNativeJob,
  isWindows2025Image,
  joinNativeArtifacts,
  normalizeNativeArtifactSelection,
  normalizeNativeJob,
  nativeCleanupFailure,
  recordNativeStage,
  renderNativeJob,
  resolveNativeDispatch,
  selectNativeArtifacts,
} from "./dispatch.js";
import {
  initialLinuxPreparation,
  initialLinuxReviewedPreparation,
  linuxPreparationVersion,
  prepareLinuxBubblewrap,
  prepareLinuxReviewedInputs,
  runLinuxSystemProofs,
  runLinuxComposedSystemProofs,
  prepareLinuxSystemCI,
  acquireLinuxSystemCI,
  loadLinuxSystemCI,
} from "./linux/index.js";

import {
  runDarwinSystemProofs,
  acquireDarwinSystemCI,
  prepareDarwinSystemCI,
  loadDarwinSystemCI,
} from "./darwin/index.js";
import {
  runWindowsSystemProofs,
  acquireWindowsSystemCI,
  prepareWindowsSystemCI,
  loadWindowsSystemCI,
} from "./win32/index.js";
import {
  runProtectedProviderProofs,
  providerJobBounds,
  acquireProviderCI,
  loadProviderCI,
  prepareProviderCI,
  recoverProviderCI,
  takeRelayCredentials,
} from "./providers/index.js";
import { assertAcceptanceRevision } from "./acceptance.js";
import {
  acceptanceRequest,
  collectAcceptance,
  verifySelectedSystem,
  aggregateAcceptance,
} from "./acceptance-ci.js";
import {
  initialSystemPreparation,
  normalizeSystemPreparation,
  boundSystemEffect,
  recoverSystemCI,
} from "./system-ci.js";
import {
  assertSystemPreparationEnvelope,
  systemJobBounds,
  selectedSystemInventory,
} from "./system-inventory.js";

const systemOwners = {
  linux: {
    acquire: acquireLinuxSystemCI,
    prepare: prepareLinuxSystemCI,
    load: loadLinuxSystemCI,
  },
  darwin: {
    acquire: acquireDarwinSystemCI,
    prepare: prepareDarwinSystemCI,
    load: loadDarwinSystemCI,
  },
  win32: {
    acquire: acquireWindowsSystemCI,
    prepare: prepareWindowsSystemCI,
    load: loadWindowsSystemCI,
  },
};

/** External CI preparation supplies indexed native capabilities and separately
 * admitted review authority. This entry never loads arbitrary adapter modules. */
export async function runNativeJobProofs(job, directory, options = {}) {
  if (job.schemaVersion !== 6) {
    if (job.platform !== "linux" || job.tier === "provider")
      throw new Error("Unsupported historical native job");
    return runLinuxSystemProofs(job, directory, options);
  }
  if (job.tier === "provider") return runProtectedProviderProofs(job, options);
  if (job.platform === "linux")
    return runLinuxComposedSystemProofs(job, directory, options);
  return (
    job.platform === "darwin" ? runDarwinSystemProofs : runWindowsSystemProofs
  )(job, options);
}

const execute = promisify(execFile);
const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const LIMIT = 2097152;
const DEADLINE = 120000;

function context(env) {
  return {
    candidateSha: env.NATIVE_CANDIDATE_SHA,
    repository: env.GITHUB_REPOSITORY,
    runId: env.GITHUB_RUN_ID,
    runAttempt: Number(env.GITHUB_RUN_ATTEMPT),
  };
}

async function readJSON(file) {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.size > LIMIT) throw new Error("Invalid CI input");
  const bytes = await readFile(file);
  if (bytes.length > LIMIT) throw new Error("Invalid CI input");
  return JSON.parse(bytes);
}

async function persistJSON(file, value) {
  const bytes = JSON.stringify(value, null, 2) + "\n";
  if (Buffer.byteLength(bytes) > LIMIT) throw new Error("Oversized CI report");
  const temporary = `${file}.${process.pid}.tmp`;
  await writeFile(temporary, bytes, { flag: "wx" });
  await rename(temporary, file);
}

async function command(executable, args, timeout = 30000) {
  const {
    GH_TOKEN,
    NATIVE_CODEX_MODEL_CREDENTIAL,
    NATIVE_CLAUDE_MODEL_CREDENTIAL,
    ...env
  } = process.env;
  return execute(executable, args, {
    cwd: ROOT,
    env,
    timeout,
    maxBuffer: 65536,
    windowsHide: true,
    killSignal: "SIGKILL",
  });
}

// CI-only read authority. Never send this token to payloads, providers, or logs.
async function github(env, route, { repositoryRoute = false } = {}) {
  if (
    !/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/u.test(env.GITHUB_REPOSITORY) ||
    !/^[1-9][0-9]*$/u.test(env.GITHUB_RUN_ID) ||
    !/^[1-9][0-9]*$/u.test(env.GITHUB_RUN_ATTEMPT) ||
    !env.GH_TOKEN
  )
    throw new Error("Missing CI metadata authority");
  const response = await fetch(
    `https://api.github.com/repos/${env.GITHUB_REPOSITORY}${repositoryRoute ? "" : "/actions"}${route ? "/" + route : ""}`,
    {
      headers: {
        authorization: `Bearer ${env.GH_TOKEN}`,
        accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      signal: AbortSignal.timeout(10000),
      redirect: "error",
    },
  );
  if (!response.ok) throw new Error("CI metadata unavailable");
  let size = 0;
  const chunks = [];
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > LIMIT) throw new Error("Oversized CI metadata");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function listMetadata(env, kind) {
  const entries = [];
  for (let page = 1; page <= 4; page++) {
    const route =
      kind === "jobs"
        ? `runs/${env.GITHUB_RUN_ID}/attempts/${env.GITHUB_RUN_ATTEMPT}/jobs`
        : `runs/${env.GITHUB_RUN_ID}/artifacts`;
    const data = await github(env, `${route}?per_page=100&page=${page}`);
    if (!Array.isArray(data[kind]) || data[kind].length > 100)
      throw new Error("Invalid CI metadata");
    entries.push(...data[kind]);
    if (data[kind].length < 100) return entries;
  }
  throw new Error("CI metadata exceeds the collection bound");
}

async function inspectImage(env) {
  let image = null;
  let build = os.release();
  if (process.platform === "linux") {
    const release = await readFile("/etc/os-release", "utf8");
    if (
      /^ID=ubuntu$/mu.test(release) &&
      /^VERSION_ID="24\.04"$/mu.test(release) &&
      env.ImageOS === "ubuntu24"
    )
      image = "ubuntu-24.04";
  } else if (process.platform === "darwin") {
    const version = (
      await command("/usr/bin/sw_vers", ["-productVersion"])
    ).stdout.trim();
    build += ` ${version} ${(await command("/usr/bin/sw_vers", ["-buildVersion"])).stdout.trim()}`;
    if (/^15\.[0-9]+(?:\.[0-9]+)?$/u.test(version) && env.ImageOS === "macos15")
      image = "macos-15-intel";
  } else if (process.platform === "win32") {
    if (
      isWindows2025Image({
        build,
        imageOS: env.ImageOS,
        imageVersion: env.ImageVersion,
      })
    )
      image = "windows-2025";
  }
  if (!/^[a-zA-Z0-9._-]{1,128}$/u.test(env.ImageVersion ?? "")) image = null;
  else build += ` image-${env.ImageVersion}`;
  return { os: process.platform, image, build, architecture: process.arch };
}

async function setup(env, job, directory) {
  const checkoutSha = (
    await command("git", ["rev-parse", "HEAD"])
  ).stdout.trim();
  const observed = await inspectImage(env);
  const versions = [
    {
      name: "node",
      version: process.version,
      sha256: createHash("sha256")
        .update(await readFile(process.execPath))
        .digest("hex"),
    },
  ];
  const update = {
    checkoutSha,
    observed,
    versions,
    provenance: job.provenance,
  };
  try {
    const jobs = await listMetadata(env, "jobs");
    const matched = jobs.filter(
      (entry) =>
        entry.name === `native-${job.tier ?? "system"}-${job.platform}` &&
        String(entry.run_id) === job.provenance.runId &&
        entry.run_attempt === job.provenance.runAttempt,
    );
    if (matched.length !== 1 || !Number.isSafeInteger(matched[0].id))
      throw new Error("CI job identity unavailable");
    update.provenance = { ...job.provenance, jobId: String(matched[0].id) };
  } catch {
    return { update, status: "FAIL", reason: "setup-failed" };
  }
  if (checkoutSha !== job.candidateSha)
    return { update, status: "FAIL", reason: "setup-failed" };
  const isCompatible =
    observed.os === job.platform &&
    observed.image === job.declaredImage &&
    observed.architecture === "x64";
  if (
    (env.NATIVE_RUNTIME_OUTCOME && env.NATIVE_RUNTIME_OUTCOME !== "success") ||
    process.version !== "v24.21.0"
  )
    return { update, status: "FAIL", reason: "setup-failed" };
  if (job.platform === "linux") {
    try {
      versions.push(
        linuxPreparationVersion(
          await readJSON(path.join(directory, "linux-preparation.json")),
          job.candidateSha,
          env.NATIVE_LINUX_PREPARATION_OUTCOME ?? "success",
        ),
      );
    } catch {
      return { update, status: "FAIL", reason: "setup-failed" };
    }
  }
  if (job.schemaVersion === 6) {
    try {
      const prepared = normalizeSystemPreparation(
        await readJSON(path.join(directory, "platform-preparation.json")),
        job,
      );
      if (
        (env.NATIVE_PREPARATION_OUTCOME ?? "success") !== "success" ||
        prepared.status !== "PASS" ||
        prepared.candidateSha !== job.candidateSha ||
        prepared.platform !== job.platform
      )
        throw new Error("Platform preparation failed");
      if (job.tier === "provider") {
        await readSystemAdmission(env, job, directory);
        const provider = await readJSON(
          path.join(directory, "provider-preparation.json"),
        );
        if (
          provider.status !== "PASS" ||
          provider.request?.candidateSha !== job.candidateSha ||
          provider.request?.platform !== job.platform ||
          provider.request.reviewSha256 !== env.NATIVE_PROVIDER_REVIEW_SHA256
        )
          throw new Error("Provider preparation failed");
      }
      versions.push(
        ...prepared.versions.map((version) => ({
          ...version,
          name: `build.${version.name}`,
        })),
      );
    } catch {
      return { update, status: "FAIL", reason: "setup-failed" };
    }
  }
  return {
    update,
    status: isCompatible ? "PASS" : "FAIL",
    reason: isCompatible ? null : "incompatible-image",
  };
}

async function runStage(env, file, name, credentialCustody) {
  let job = normalizeNativeJob(await readJSON(file));
  if (
    job.stages[name].status !== "NOT_RUN" ||
    job.stages[name].elapsedMs !== null
  )
    throw new Error("CI stage already settled");
  // Initialization persisted NOT_RUN before releasing any work. A lost runner
  // retains that evidence or is independently noticed as an absent artifact.
  const start = performance.now();
  const deadlineMs =
    name === "setup"
      ? DEADLINE
      : job.tier === "provider"
        ? name === "probe"
          ? providerJobBounds(job.platform).probeMs
          : providerJobBounds(job.platform).cleanupMs
        : name === "probe"
          ? systemJobBounds(job.platform, job.schemaVersion).probeMs
          : systemJobBounds(job.platform, job.schemaVersion).cleanupMs;
  let status = "PASS";
  let reason = null;
  let update = {};
  try {
    if (name === "setup") {
      const result = await setup(env, job, path.dirname(file));
      update = result.update;
      status = result.status;
      reason = status === "PASS" ? null : result.reason;
    } else if (name === "probe") {
      if (job.stages.setup.status !== "PASS") {
        status = "NOT_RUN";
        reason = "setup-failed";
      } else {
        // Keep this effect-free file in the awaited child instead of spawning
        // a file worker that could outlive the child's deadline termination.
        await command(
          process.execPath,
          [
            "--test",
            "--test-reporter=dot",
            "--test-isolation=none",
            "ci/native/harness.test.js",
          ],
          30000,
        );
        let prepared = {};
        if (job.schemaVersion === 6 && job.tier === "system") {
          prepared = await loadPreparedSystemCI(env, job, path.dirname(file));
          job = normalizeNativeJob({
            ...job,
            reviews: { ...job.reviews, ...prepared.reviews },
          });
          await persistJSON(file, job);
        }
        if (job.tier === "provider") {
          const loaded = await loadPreparedProviderCI(
            env,
            job,
            path.dirname(file),
            { credentialCustody },
          );
          job = loaded.job;
          prepared = loaded;
          await persistJSON(file, job);
        }
        if (job.platform === "linux" || job.schemaVersion === 6) {
          job = await runNativeJobProofs(job, path.dirname(file), {
            ...prepared,
            manifest: prepared.manifest?.execution,
            sourceManifest: prepared.manifest?.source,
            releaseManifest: prepared.manifest?.release,
            persist: async (value) => {
              await persistJSON(file, value);
              job = value;
            },
            diagnostic: (group, phase) => {
              const event =
                typeof group === "object" ? group : { group, phase };
              process.stdout.write(
                `native-${job.platform} ${event.executionId ?? "reference"} ${event.group} ${event.phase}\n`,
              );
            },
          });
          if (
            job.results.some((result) => result.status === "FAIL") ||
            job.executions?.some((entry) => entry.status === "FAIL")
          ) {
            status = "FAIL";
            reason = "probe-failed";
          } else if (
            job.schemaVersion === 6 &&
            (job.results.length === 0 ||
              job.results.some(({ status }) => status !== "PASS"))
          ) {
            status = "BLOCKED";
            reason = "missing-input";
          }
        }
      }
    }
    // Linux cases attempt independent retirement inside their own deadlines.
    // A lost probe never gains cleanup evidence from this later reporting step.
    if (name === "cleanup") {
      if (job.schemaVersion === 6 && job.tier === "system") {
        const prepared = await loadPreparedSystemCI(
          env,
          job,
          path.dirname(file),
          { recovery: true },
        );
        await recoverSystemCI(
          job,
          prepared,
          await readJSON(
            path.join(path.dirname(file), "platform-preparation.json"),
          ),
          Math.max(1, deadlineMs - Math.ceil(performance.now() - start)),
          (value) =>
            persistJSON(
              path.join(path.dirname(file), "platform-cleanup.json"),
              value,
            ),
        );
      }
      if (job.schemaVersion === 6 && job.tier === "provider") {
        // Recovery is credential-free and freshly bound to both preparation
        // and actual provider effect ledgers. Failed proof remains failed.
        const prepared = await loadPreparedSystemCI(
          env,
          preparationJob(job),
          path.dirname(file),
          { recovery: true },
        );
        try {
          const provider = await loadPreparedProviderCI(
            env,
            job,
            path.dirname(file),
            { recovery: true, preparedSystem: prepared },
          );
          let receipt = null;
          try {
            receipt = await readJSON(
              path.join(path.dirname(file), "provider-preparation.json"),
            );
          } catch {
            /* No build was admitted. */
          }
          await recoverProviderCI(job, provider, receipt, (value) =>
            persistJSON(
              path.join(path.dirname(file), "provider-cleanup.json"),
              value,
            ),
          );
        } finally {
          await recoverSystemCI(
            job,
            prepared,
            await readJSON(
              path.join(path.dirname(file), "platform-preparation.json"),
            ),
            120000,
            (value) =>
              persistJSON(
                path.join(path.dirname(file), "platform-cleanup.json"),
                value,
              ),
          );
        }
      }
      const failure = nativeCleanupFailure(job);
      if (failure) {
        status = "FAIL";
        reason = failure;
      }
    }
  } catch (error) {
    status = "FAIL";
    reason = error?.killed ? "deadline" : `${name}-failed`;
  }
  const elapsedMs = Math.ceil(performance.now() - start);
  if (elapsedMs > deadlineMs) {
    status = "FAIL";
    reason = "deadline";
  }
  try {
    job = recordNativeStage(
      job,
      name,
      { status, reason, elapsedMs, deadlineMs },
      update,
    );
  } catch {
    // Invalid observations cannot erase the phase failure or become evidence.
    status = "FAIL";
    job = recordNativeStage(job, name, {
      status,
      reason: `${name}-failed`,
      elapsedMs,
      deadlineMs,
    });
  }
  await persistJSON(file, job);
  if (status !== "PASS") process.exitCode = 1;
}

async function publish(env, directory, rendered, emit = true) {
  await persistJSON(path.join(directory, "report.json"), rendered.report);
  await writeFile(path.join(directory, "summary.md"), rendered.summary + "\n");
  if (!emit) return;
  if (env.GITHUB_STEP_SUMMARY)
    await appendFile(env.GITHUB_STEP_SUMMARY, rendered.summary + "\n");
  for (const annotation of rendered.annotations)
    process.stdout.write(annotation + "\n");
}

async function collect(env, directory) {
  const selectedContext = { ...context(env), workflowSha: env.GITHUB_SHA };
  let selection;
  try {
    if (
      (await command("git", ["rev-parse", "HEAD"])).stdout.trim() !==
      selectedContext.candidateSha
    )
      throw new Error("Controller checkout mismatch");
    const run = await github(env, `runs/${env.GITHUB_RUN_ID}`);
    const jobs = await listMetadata(env, "jobs");
    const artifacts = await listMetadata(env, "artifacts");
    selection = normalizeNativeArtifactSelection(
      selectedContext,
      selectNativeArtifacts(selectedContext, run, jobs, artifacts),
    );
  } catch {
    selection = {
      entries: [],
      issues: [{ code: "metadata", platform: null }],
      jobs: [],
    };
  }
  await persistJSON(path.join(directory, "selection.json"), {
    context: selectedContext,
    selection,
  });
  if (env.GITHUB_OUTPUT)
    await appendFile(
      env.GITHUB_OUTPUT,
      `artifact_ids=${selection.entries.map(({ binding }) => binding.artifactId).join(",")}\n`,
    );
}

async function aggregate(env, directory) {
  const expectedContext = { ...context(env), workflowSha: env.GITHUB_SHA };
  let selected;
  try {
    selected = await readJSON(path.join(directory, "selection.json"));
    if (
      JSON.stringify(selected.context) !== JSON.stringify(expectedContext) ||
      (await command("git", ["rev-parse", "HEAD"])).stdout.trim() !==
        expectedContext.candidateSha
    )
      throw new Error("Controller revision mismatch");
    selected.selection = normalizeNativeArtifactSelection(
      expectedContext,
      selected.selection,
    );
  } catch {
    selected = {
      context: expectedContext,
      selection: {
        entries: [],
        issues: [{ code: "metadata", platform: null }],
        jobs: [],
      },
    };
  }
  if (
    selected.selection.entries.length &&
    env.NATIVE_DOWNLOAD_OUTCOME !== "success"
  )
    selected.selection.issues.push({ code: "download", platform: null });
  const payloads = {};
  for (const { name } of selected.selection.entries) {
    try {
      const artifactDirectory = path.join(env.RUNNER_TEMP, "native-artifacts");
      for (const directory of [
        artifactDirectory,
        path.join(artifactDirectory, name),
      ])
        if (!(await lstat(directory)).isDirectory())
          throw new Error("Invalid artifact directory");
      payloads[name] = await readJSON(
        path.join(artifactDirectory, name, "native-job.json"),
      );
    } catch {
      /* Missing, oversized, or non-file payload remains a failed join. */
    }
  }
  const rendered = joinNativeArtifacts(
    selected.context,
    selected.selection,
    payloads,
  );
  const inventory = selectedSystemInventory(
    selected.context,
    selected.selection,
    payloads,
  );
  const { jobs: _inventoryJobs, ...inventorySummary } = inventory;
  rendered.report.systemInventory = inventorySummary;
  rendered.summary += `\n\n## System inventory only: ${inventory.status}\n\n${inventory.records}/69 system records. Full acceptance remains ${rendered.report.decision}; provider and source requirements are unchanged.`;
  await publish(env, directory, rendered);
  if (rendered.report.decision !== "GO" || rendered.report.ciStatus !== "PASS")
    process.exitCode = 1;
}

async function main() {
  const env = process.env;
  const { stage, tier } = resolveNativeDispatch(process.argv.slice(2));
  const credentialCustody = takeRelayCredentials(env);
  if (tier === "provider") await verifyAcceptanceCheckout(env);
  if (stage === "verify-revision") return;
  if (stage === "deadlines") {
    if (env.GITHUB_ACTIONS !== "true" || !env.GITHUB_OUTPUT)
      throw new Error("CI-only inventory output");
    const bounds = Object.fromEntries(
      ["linux", "darwin", "win32"].map((platform) => [
        platform,
        tier === "system"
          ? systemJobBounds(platform)
          : {
              ...providerJobBounds(platform),
              preparationMinutes:
                systemJobBounds(platform).preparationMinutes +
                providerJobBounds(platform).preparationMinutes,
              jobMinutes:
                systemJobBounds(platform).preparationMinutes +
                systemJobBounds(platform).bootstrapMinutes +
                providerJobBounds(platform).probeMinutes +
                providerJobBounds(platform).preparationMinutes +
                providerJobBounds(platform).cleanupMinutes +
                20,
            },
      ]),
    );
    await appendFile(env.GITHUB_OUTPUT, `bounds=${JSON.stringify(bounds)}\n`);
    return;
  }
  if (
    env.GITHUB_ACTIONS !== "true" ||
    !env.RUNNER_TEMP ||
    !(
      tier === "system"
        ? ["native-system", "native-aggregate"]
        : ["native-provider", "native-acceptance"]
    ).includes(env.NATIVE_REPORT_NAME)
  )
    throw new Error("CI-only entry point");
  const directory = path.resolve(env.RUNNER_TEMP, env.NATIVE_REPORT_NAME);
  const relative = path.relative(path.resolve(env.RUNNER_TEMP), directory);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative))
    throw new Error("CI output must be runner-private");
  await mkdir(directory, { recursive: true });
  const file = path.join(directory, "native-job.json");
  const controller = {
    github,
    listMetadata,
    command,
    readJSON,
    persistJSON,
    publish,
  };
  if (stage === "collect")
    return tier === "system"
      ? collect(env, directory)
      : collectAcceptance(env, directory, controller);
  if (stage === "aggregate")
    return tier === "system"
      ? aggregate(env, directory)
      : aggregateAcceptance(env, directory, controller);
  if (stage === "verify-system")
    return verifySelectedSystem(env, directory, controller);
  if (stage === "initialize" || stage === "all") {
    const job = initializeNativeJob(
      {
        ...context(env),
        platform: env.NATIVE_PLATFORM,
      },
      { schemaVersion: 6, tier },
    );
    await persistJSON(file, job);
    if (job.schemaVersion === 6)
      await persistJSON(
        path.join(directory, "platform-preparation.json"),
        initialSystemPreparation(job),
      );
    if (job.platform === "linux") {
      await persistJSON(
        path.join(directory, "linux-preparation.json"),
        initialLinuxPreparation(job.candidateSha),
      );
      await persistJSON(
        path.join(directory, "linux-reviewed-inputs.json"),
        initialLinuxReviewedPreparation(job.candidateSha),
      );
    }
    await publish(env, directory, renderNativeJob(job), false);
  }
  let preparationReady = true;
  if (stage === "prepare-inputs" || (stage === "all" && tier === "system")) {
    try {
      const job = normalizeNativeJob(await readJSON(file));
      if (tier === "provider") {
        if (job.stages.setup.elapsedMs !== null)
          throw new Error("Preparation must precede setup");
        await readSystemAdmission(env, job, directory);
      }
      const bootstrap = preparationJob(job);
      await verifyPreparationEnvelope(env, bootstrap);
      await boundSystemEffect(
        (signal) =>
          systemOwners[job.platform].acquire(
            bootstrap,
            path.resolve(env.RUNNER_TEMP, `native-${job.platform}-reviewed`),
            { env, signal },
          ),
        60000,
      );
      if (tier === "provider") await acquireProviderCI(job, env);
    } catch {
      preparationReady = false;
      process.exitCode = 1;
      if (stage !== "all")
        throw new Error("Reviewed platform inputs unavailable");
    }
  }
  if (
    stage === "prepare-linux" ||
    (stage === "all" &&
      preparationReady &&
      tier === "system" &&
      env.NATIVE_PLATFORM === "linux")
  ) {
    try {
      const job = normalizeNativeJob(await readJSON(file));
      if (job.platform !== "linux" || job.stages.setup.elapsedMs !== null)
        throw new Error("Linux preparation must precede setup");
      if (tier === "provider") {
        if (job.stages.setup.elapsedMs !== null)
          throw new Error("Preparation must precede setup");
        await readSystemAdmission(env, job, directory);
      }
      await verifyPreparationEnvelope(env, preparationJob(job));
      const preparationFile = path.join(directory, "linux-preparation.json");
      const previous = await readJSON(preparationFile);
      if (
        previous.candidateSha !== job.candidateSha ||
        previous.status !== "NOT_RUN"
      )
        throw new Error("Linux preparation already attempted");
      const reviewedFile = path.join(directory, "linux-reviewed-inputs.json");
      const reviewed = await prepareLinuxReviewedInputs(
        job.candidateSha,
        env.NATIVE_REVIEWED_INPUT_DIRECTORY,
        (record) => persistJSON(reviewedFile, record),
        { env, previous: await readJSON(reviewedFile) },
      );
      process.stdout.write(`Linux reviewed inputs: ${reviewed.status}.\n`);
      if (reviewed.status !== "PASS") {
        throw new Error("Reviewed Linux input preparation failed");
      }
      const prepared = await prepareLinuxBubblewrap(
        job.candidateSha,
        directory,
        (record) => persistJSON(preparationFile, record),
      );
      process.stdout.write(
        `Linux preparation: ${prepared.status} (${prepared.phase}).\n`,
      );
      if (prepared.status !== "PASS") {
        preparationReady = false;
        process.exitCode = 1;
      }
    } catch (error) {
      preparationReady = false;
      if (stage !== "all") throw error;
      process.exitCode = 1;
    }
  }
  if (
    stage === "prepare" ||
    (stage === "all" && preparationReady && tier === "system")
  ) {
    try {
      const job = normalizeNativeJob(await readJSON(file));
      const current = await readJSON(
        path.join(directory, "platform-preparation.json"),
      );
      if (current.status !== "NOT_RUN")
        throw new Error("Platform preparation already attempted");
      if (tier === "provider") {
        if (job.stages.setup.elapsedMs !== null)
          throw new Error("Preparation must precede setup");
        await readSystemAdmission(env, job, directory);
      }
      const bootstrap = preparationJob(job);
      await verifyPreparationEnvelope(env, bootstrap);
      const root = path.resolve(
        env.RUNNER_TEMP,
        `native-${job.platform}-reviewed`,
      );
      const prepared = await systemOwners[job.platform].prepare(
        bootstrap,
        root,
        path.join(directory, "platform-build"),
        (value) =>
          persistJSON(path.join(directory, "platform-preparation.json"), value),
        { env },
      );
      if (prepared.status !== "PASS") process.exitCode = 1;
      else if (tier === "provider") {
        const loaded = await loadPreparedProviderCI(env, job, directory);
        await prepareProviderCI(
          loaded.job,
          loaded,
          loaded.buildManifest,
          directory,
          (value) =>
            persistJSON(
              path.join(directory, "provider-preparation.json"),
              value,
            ),
        );
        await persistJSON(file, loaded.job);
      }
    } catch {
      process.exitCode = 1;
      if (stage !== "all") throw new Error("Platform preparation unavailable");
    }
  }
  for (const name of ["setup", "probe", "cleanup"]) {
    if (stage === name) await runStage(env, file, name, credentialCustody);
    else if (stage === "all")
      await runStage(env, file, name, credentialCustody).catch(() => {
        process.exitCode = 1;
      });
  }
  if (stage === "report" || stage === "all")
    await publish(env, directory, renderNativeJob(await readJSON(file)));
  credentialCustody.close();
}

async function verifyPreparationEnvelope(env, job) {
  assertSystemPreparationEnvelope(job, {
    checkoutSha: (await command("git", ["rev-parse", "HEAD"])).stdout.trim(),
    nodeVersion: process.version,
    image: await inspectImage(env),
  });
}

async function loadPreparedSystemCI(env, job, directory, options) {
  if (
    (await command("git", ["rev-parse", "HEAD"])).stdout.trim() !==
    job.candidateSha
  )
    throw new Error("Native dispatch checkout mismatch");
  const receipt = await readJSON(
    path.join(directory, "platform-preparation.json"),
  );
  return boundSystemEffect(
    () =>
      systemOwners[job.platform].load(
        job,
        path.resolve(env.RUNNER_TEMP, `native-${job.platform}-reviewed`),
        directory,
        receipt,
        env,
        options,
      ),
    30000,
  );
}

// Importing this entry point never launches CI, probes, providers, or report I/O.
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch(async () => {
    process.exitCode = 1;
    process.stderr.write(
      "Native CI reporting failed; retain BLOCKED and inspect setup/probe/cleanup or absent artifacts.\n",
    );
    if (process.env.GITHUB_STEP_SUMMARY)
      await appendFile(
        process.env.GITHUB_STEP_SUMMARY,
        "\nNative CI reporting failed. Missing evidence remains BLOCKED.\n",
      ).catch(() => {});
  });
}

function preparationJob(job) {
  if (job.tier !== "provider") return job;
  return initializeNativeJob(
    {
      ...context({
        NATIVE_CANDIDATE_SHA: job.candidateSha,
        GITHUB_REPOSITORY: job.provenance.repository,
        GITHUB_RUN_ID: job.provenance.runId,
        GITHUB_RUN_ATTEMPT: String(job.provenance.runAttempt),
      }),
      platform: job.platform,
    },
    { schemaVersion: 6, tier: "system" },
  );
}

async function verifyAcceptanceCheckout(env) {
  return assertAcceptanceRevision(acceptanceRequest(env), {
    event: env.GITHUB_EVENT_NAME,
    workflowSha: env.GITHUB_WORKFLOW_SHA,
    dispatchSha: env.GITHUB_SHA,
    checkoutSha: (await command("git", ["rev-parse", "HEAD"])).stdout.trim(),
  });
}

async function readSystemAdmission(env, job, directory) {
  const receipt = await readJSON(path.join(directory, "system-admission.json"));
  if (
    JSON.stringify(receipt.request) !==
      JSON.stringify(acceptanceRequest(env)) ||
    receipt.system.platform !== job.platform ||
    receipt.system.candidateSha !== job.candidateSha
  )
    throw new Error("Protected system admission mismatch");
  return receipt;
}

async function loadPreparedProviderCI(env, job, directory, options) {
  const admission = await readSystemAdmission(env, job, directory);
  const prepared =
    options?.preparedSystem ??
    (await loadPreparedSystemCI(env, preparationJob(job), directory, options));
  return boundSystemEffect(
    () =>
      loadProviderCI(
        job,
        admission.system,
        admission.binding,
        prepared,
        directory,
        env,
        options,
      ),
    30000,
  );
}
