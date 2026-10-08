import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { assertOwnedProcessLauncherProtected } from "../../../src/agents/index.js";
import {
  feasibilityCapabilities,
  unavailableFeasibilityResults,
} from "../feasibility/index.js";
import { prepareLinuxFixture } from "./confinement.js";
import { prepareLinuxFeasibilityAccess } from "./access.js";
import { digest } from "./inspect.js";
import {
  runLinuxFeasibilityCase,
  runLinuxBuildCommand,
  linuxFeasibilityBuildArguments,
} from "./proof.js";
import {
  LINUX_FILE_BUILD_ARGUMENTS,
  verifyLinuxFileElf,
} from "./file-build.js";
import {
  runLinuxFileSession,
  observeLinuxFileControl,
  restoreLinuxFileControl,
} from "./files.js";
import {
  assertLinuxFileObservation,
  assertLinuxFileDenial,
} from "./files-cases.js";
import {
  requireLinuxFeasibilityCI,
  linuxFeasibilityCause,
  linuxFeasibilityResult,
  canContinueLinuxFeasibility,
  observeLinuxFeasibilitySentinel,
  observeLinuxFeasibilityRetirement,
  persistLinuxFeasibilityObservation,
} from "./feasibility-observer.js";

const execute = promisify(execFile);
const SOURCE = fileURLToPath(new URL("./", import.meta.url));
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const COMPILER = "/usr/bin/x86_64-linux-gnu-gcc-13";
const ENV = Object.freeze({ PATH: "/usr/bin:/bin", LANG: "C" });
const CONTENTS = "006f6c64ff";
const ACCESS_IDS = [
  "access.read-only",
  "access.workspace-write",
  "git.denial",
  "network.tcp-denial",
  "ipc.local-denial",
];
const STORAGE_IDS = ["storage.private", "storage.substitution"];

function failedEntries(ids, stage, error, possible = false) {
  const cause = linuxFeasibilityCause(stage, error);
  return unavailableFeasibilityResults("linux", cause)
    .filter(({ capability }) => ids.includes(capability))
    .map((entry) =>
      possible
        ? {
            ...entry,
            status: "FAIL",
            cause:
              cause.code === "prerequisite-unavailable"
                ? { ...cause, code: "setup-failed" }
                : cause,
            cleanup: {
              status: "UNCERTAIN",
              independent: false,
              emergency: false,
              elapsedMs: null,
              witnessSha256: null,
              cause: {
                code: "cleanup-unobserved",
                detail: `Linux ${stage} partial setup was not independently settled.`,
              },
            },
          }
        : entry,
    );
}

async function buildHelper(candidateSha, fixture) {
  const directory = path.join(fixture.directory, "build");
  await mkdir(directory, { mode: 0o700 });
  let compiler;
  try {
    compiler = await realpath(COMPILER);
  } catch (error) {
    if (error.code === "ENOENT")
      error.code = "ERR_NATIVE_FEASIBILITY_PREREQUISITE_UNAVAILABLE";
    throw error;
  }
  if (compiler !== COMPILER) throw new Error("Noncanonical compiler");
  assertOwnedProcessLauncherProtected(COMPILER);
  const toolSha256 = digest(await readFile(COMPILER));
  const source = path.join(fixture.directory, "inputs", "file-helper.c");
  await copyFile(path.join(SOURCE, "file-helper.c"), source);
  await chmod(source, 0o400);
  const sourceSha256 = digest(await readFile(source));
  const request = {
    candidateSha,
    platform: "linux",
    file: COMPILER,
    cwd: directory,
    env: ENV,
    args: ["--version"],
    deadlineMs: 20000,
    toolSha256,
  };
  const version = await runLinuxBuildCommand(request);
  if (version.exitCode !== 0 || !version.stdout.trim())
    throw new Error("Compiler version observation failed");
  const actualArguments = linuxFeasibilityBuildArguments(source, directory);
  const compiled = await runLinuxBuildCommand(
    { ...request, args: actualArguments },
    { feasibilitySource: { path: source, sha256: sourceSha256 } },
  );
  if (compiled.exitCode !== 0)
    throw new Error("Static helper compilation failed");
  const executable = path.join(directory, "file-helper");
  const metadata = await lstat(executable);
  if (
    !metadata.isFile() ||
    metadata.nlink !== 1 ||
    metadata.uid !== process.getuid() ||
    (metadata.mode & 0o7777) !== 0o500 ||
    (await realpath(executable)) !== executable
  )
    throw new Error("Unprotected compiled helper");
  const bytes = await readFile(executable);
  verifyLinuxFileElf(bytes);
  const build = {
    candidateSha,
    executable,
    sha256: digest(bytes),
    sourceSha256,
    arguments: [...LINUX_FILE_BUILD_ARGUMENTS],
    actualArguments,
    compiler: {
      role: "tool",
      name: "gcc-13",
      version: version.stdout.split("\n")[0].trim(),
      sha256: toolSha256,
    },
    observations: [version, compiled],
  };
  await persistLinuxFeasibilityObservation(fixture, "helper-build", build);
  return build;
}

async function storageEntry(
  candidateSha,
  fixture,
  build,
  outside,
  substitution,
) {
  const started = performance.now();
  const name = substitution ? "storage-substitution" : "storage-private";
  const entry = {
    status: "FAIL",
    cause: null,
    elapsedMs: 0,
    ready: false,
    positiveControl: false,
    attemptAcknowledged: false,
    observationSha256: null,
    sentinelsBeforeSha256: null,
    sentinelsAfterSha256: null,
    cleanup: {
      status: "UNCERTAIN",
      independent: false,
      emergency: false,
      elapsedMs: null,
      witnessSha256: null,
      cause: {
        code: "cleanup-unobserved",
        detail: `Linux ${name} retirement or storage cleanup was not observed.`,
      },
    },
  };
  const sessions = [],
    observations = [];
  const job = {
    platform: "linux",
    candidateSha,
    stages: { setup: { status: "PASS" } },
  };
  let cleanupStarted = null;
  const witness = async (session) => {
    const observed = await observeLinuxFeasibilityRetirement(
      {
        file: path.join(
          fixture.directory,
          "evidence",
          `file-helper-${session.nonce}.json`,
        ),
        sha256: session.receiptDigest,
      },
      candidateSha,
      "file-helper",
    );
    if (
      observed.settlement.status !== "RETIRED" ||
      !observed.settlement.independent ||
      session.settlement.emergencyCleanup
    )
      throw new Error("Storage domain did not retire independently");
    observations.push(observed);
  };
  const observe = async (controls, message, expected) => {
    const snapshot = await controls.observe();
    assertLinuxFileObservation(message, snapshot, expected);
    observations.push({ message, snapshot, expected });
  };
  const session = async (body, options) => {
    const value = await runLinuxFileSession(job, fixture, build, body, options);
    sessions.push(value);
    await witness(value);
    return value;
  };
  const positive = async (operation, controls) => {
    const allocated = await operation("allocate");
    await observe(controls, allocated, { leaf: null, temporary: null });
    const published = await operation("publish", CONTENTS);
    await observe(controls, published, { leaf: CONTENTS, temporary: null });
    entry.ready = entry.positiveControl = true;
    return published;
  };
  try {
    entry.sentinelsBeforeSha256 = digest(
      JSON.stringify(await observeLinuxFeasibilitySentinel(outside)),
    );
    if (!substitution) {
      const value = await session(async (operation, controls) => {
        await positive(operation, controls);
        cleanupStarted = performance.now();
        const removed = await operation("cleanup");
        await observe(controls, removed, { leaf: null, temporary: null });
        entry.attemptAcknowledged = true;
      });
      if (
        value.status !== "PASS" ||
        value.storage !== "REMOVED" ||
        value.exclusion !== "RELEASED"
      )
        throw new Error("Matching private-storage cleanup failed");
    } else {
      let barrier, applied;
      const denied = await session(
        async (operation, controls) => {
          await positive(operation, controls);
          await operation("cleanup", "", async (message) => {
            barrier = message;
            await observe(controls, message, {
              leaf: CONTENTS,
              temporary: null,
            });
            applied = await controls.fault("cleanup-leaf");
          });
        },
        { control: "cleanup-leaf" },
      );
      if (
        !barrier ||
        !applied ||
        denied.status !== "FAIL" ||
        denied.interrupted ||
        denied.storage !== "RETAINED" ||
        denied.exclusion !== "RETAINED" ||
        denied.control !== "cleanup-leaf" ||
        denied.denial?.phase !== "denied"
      )
        throw new Error("Substitution did not produce an acknowledged refusal");
      const observed = await observeLinuxFileControl(fixture, denied);
      assertLinuxFileDenial(
        "cleanup-leaf",
        barrier,
        denied.denial,
        applied.before,
        applied.applied,
        observed,
      );
      observations.push({ barrier, applied, denial: denied.denial, observed });
      entry.attemptAcknowledged = true;
      // The substitute has survived the refused native cleanup. Only the sole
      // parent now restores its own identity-bound control and retires originals.
      cleanupStarted = performance.now();
      const restored = await restoreLinuxFileControl(fixture, denied);
      if (JSON.stringify(restored) !== JSON.stringify(applied.before))
        throw new Error("Substitution control restoration failed");
      const recovered = await session(
        async (operation, controls) => {
          const inspected = await operation("inspect");
          const stable = (value) =>
            value
              ?.split(":")
              .filter((_, index) => index !== 3)
              .join(":") ?? null;
          if (
            ["anchor", "allocation", "leaf", "temporary"].some(
              (key) => stable(inspected[key]) !== stable(barrier[key]),
            )
          )
            throw new Error("Recovered storage identity changed");
          await observe(controls, inspected, {
            leaf: CONTENTS,
            temporary: null,
          });
          await operation("cleanup");
        },
        { recovery: denied },
      );
      if (
        recovered.status !== "PASS" ||
        recovered.storage !== "REMOVED" ||
        recovered.exclusion !== "RELEASED"
      )
        throw new Error("Recovered storage cleanup failed");
    }
    entry.sentinelsAfterSha256 = digest(
      JSON.stringify(await observeLinuxFeasibilitySentinel(outside)),
    );
    entry.observationSha256 = await persistLinuxFeasibilityObservation(
      fixture,
      name,
      { observations, sessions },
    );
    entry.cleanup = {
      status: "PASS",
      independent: true,
      emergency: false,
      elapsedMs: Math.ceil(performance.now() - cleanupStarted),
      witnessSha256: await persistLinuxFeasibilityObservation(
        fixture,
        `${name}-cleanup`,
        { sessions, outside: entry.sentinelsAfterSha256 },
      ),
      cause: null,
    };
    entry.status = "PASS";
  } catch (error) {
    entry.cause = linuxFeasibilityCause(name, error);
    entry.cleanup.emergency = sessions.some(
      (value) => value.settlement.emergencyCleanup,
    );
    await persistLinuxFeasibilityObservation(fixture, `${name}-failure`, {
      sessions,
      observations,
      cause: entry.cause,
    });
  }
  entry.elapsedMs = Math.ceil(performance.now() - started);
  return entry;
}

/** CI-private bounded experiment; no compilation/probe occurs on import. Owned
 * evidence and the outside sentinel remain retained for the artifact owner. */
export async function runLinuxFeasibility({ expectedSha, checkoutSha }) {
  requireLinuxFeasibilityCI(expectedSha);
  const { stdout } = await execute("git", ["rev-parse", "HEAD"], {
    cwd: ROOT,
    env: ENV,
    timeout: 3000,
    maxBuffer: 128,
  });
  if (checkoutSha !== expectedSha || stdout.trim() !== expectedSha)
    throw new Error("Linux feasibility checkout changed before admission");
  const nativeIds = feasibilityCapabilities("linux")
    .filter(({ tier }) => tier === "native")
    .map(({ id }) => id);
  const pending = unavailableFeasibilityResults("linux", {
    code: "prerequisite-unavailable",
    detail: "Dependent Linux admission requires a settled preceding probe.",
  }).filter(({ capability }) => nativeIds.includes(capability));
  const records = new Map(pending.map((entry) => [entry.capability, entry]));
  const put = (entries) =>
    entries.forEach((entry) => records.set(entry.capability, entry));
  const results = () => [...records.values()];
  let fixture, outside;
  try {
    if (!process.env.RUNNER_TEMP || !path.isAbsolute(process.env.RUNNER_TEMP))
      throw new Error("Missing CI artifact storage");
    const parent = await realpath(process.env.RUNNER_TEMP);
    const root = path.join(parent, "native-feasibility");
    await mkdir(root, { mode: 0o700 });
    await writeFile(
      path.join(root, "intent.json"),
      JSON.stringify({ candidateSha: expectedSha, nonce: randomUUID() }) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    await mkdir(path.join(root, "outside"), { mode: 0o700 });
    outside = path.join(root, "outside", "sentinel");
    await writeFile(outside, randomUUID(), { flag: "wx", mode: 0o400 });
    fixture = await prepareLinuxFixture(path.join(root, "fixture"));
    await persistLinuxFeasibilityObservation(fixture, "policy", fixture.policy);
  } catch (error) {
    return failedEntries(nativeIds, "fixture preparation", error);
  }
  const components = [
    { ...fixture.version, role: "tool" },
    {
      role: "tool",
      name: "node",
      version: process.version,
      sha256: fixture.executableDigest,
    },
    {
      role: "helper",
      name: "payload",
      version: "1",
      sha256: fixture.policy.payloadDigest,
    },
  ];
  for (const [caseId, capability] of [
    ["argv", "launch.argv"],
    ["cancel", "ownership.cancel"],
    ["owner-loss", "ownership.owner-loss"],
  ]) {
    let entry;
    try {
      entry = await runLinuxFeasibilityCase(expectedSha, fixture, caseId);
    } catch (error) {
      put(failedEntries([capability], `${caseId} preparation`, error, true));
      return results();
    }
    put([linuxFeasibilityResult(capability, [entry], components)]);
    if (!canContinueLinuxFeasibility(entry)) return results();
  }
  try {
    const access = await prepareLinuxFeasibilityAccess(fixture, expectedSha);
    const entries = [];
    let tools;
    for (const profile of ["read-only", "workspace-write"]) {
      const prepared = await access.prepare(profile);
      let entry;
      try {
        entry = await runLinuxFeasibilityCase(
          expectedSha,
          prepared.fixture,
          profile,
          { access: prepared.effects },
        );
      } finally {
        await prepared.close();
      }
      entries.push(entry);
      tools = [
        ...components.filter(({ role }) => role !== "helper"),
        { ...access.version, role: "tool" },
        {
          role: "helper",
          name: "access-payload",
          version: "1",
          sha256: prepared.fixture.policy.payloadDigest,
        },
      ];
      put([linuxFeasibilityResult(`access.${profile}`, [entry], tools)]);
      if (!canContinueLinuxFeasibility(entry)) {
        for (const id of ACCESS_IDS.slice(2))
          put([linuxFeasibilityResult(id, entries, tools)]);
        return results();
      }
    }
    for (const id of ACCESS_IDS.slice(2))
      put([linuxFeasibilityResult(id, entries, tools)]);
  } catch (error) {
    put(
      failedEntries(
        ACCESS_IDS.filter((id) => records.get(id).status === "BLOCKED"),
        "access preparation",
        error,
      ),
    );
    return results();
  }
  let build;
  try {
    build = await buildHelper(expectedSha, fixture);
  } catch (error) {
    put(
      failedEntries(
        STORAGE_IDS,
        "helper build",
        error,
        error.code !== "ERR_NATIVE_FEASIBILITY_PREREQUISITE_UNAVAILABLE",
      ),
    );
    return results();
  }
  const tools = [
    ...components.filter(({ role }) => role !== "helper"),
    build.compiler,
    { role: "helper", name: "file-helper", version: "1", sha256: build.sha256 },
  ];
  for (const [capability, substitution] of [
    ["storage.private", false],
    ["storage.substitution", true],
  ]) {
    const entry = await storageEntry(
      expectedSha,
      fixture,
      build,
      outside,
      substitution,
    );
    put([linuxFeasibilityResult(capability, [entry], tools)]);
    if (!canContinueLinuxFeasibility(entry)) break;
  }
  return results();
}
