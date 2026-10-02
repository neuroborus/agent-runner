import { execFile, spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { promisify } from "node:util";
import {
  access,
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  realpath,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertOwnedProcessLauncherProtected,
  resolveOwnedProcessLauncher,
} from "../../../src/agents/index.js";
import {
  LINUX_PREREQUISITE_IDS,
  linuxPrerequisiteObservation,
  normalizeLinuxPrerequisites,
} from "../index.js";
import { digest, assertLinuxProcVisibility } from "./inspect.js";
import { LINUX_POLICY_ID } from "./protocol.js";

export const LITERAL_ARGV = Object.freeze([
  "",
  "two words",
  "Unicode λ",
  "; exit 99",
  "$(exit 99)",
  "*",
  "a'\"b",
]);
const execute = promisify(execFile);
const SOURCE = fileURLToPath(new URL("./", import.meta.url));

class LinuxPrerequisiteCommandError extends Error {
  constructor(observation) {
    super("Linux prerequisite command unavailable");
    this.observation = observation;
    this.code = observation.errno ?? observation.exitCode ?? "UNVERIFIED";
  }
}

async function executePrerequisite(file, args, options, run = execute) {
  try {
    return await run(file, args, options);
  } catch (error) {
    // execFile reports process exits/signals here. Arbitrary later fixture
    // exceptions do not establish that a command started or terminated.
    throw new LinuxPrerequisiteCommandError(
      linuxPrerequisiteObservation(null, {
        status: error?.code,
        signal: error?.signal,
        error,
      }),
    );
  }
}

export async function protectedLibraries(executable) {
  const ldd = await realpath("/usr/bin/ldd");
  assertOwnedProcessLauncherProtected(ldd);
  const { stdout } = await executePrerequisite(ldd, [executable], {
    timeout: 10000,
    maxBuffer: 65536,
    env: { PATH: "/usr/bin:/bin", LANG: "C" },
  });
  const libraries = new Map();
  for (const line of stdout.trim().split("\n")) {
    if (/not found/u.test(line))
      throw new Error("Missing executable ABI dependency");
    const member = line.match(/(?:=>\s+)?(\/[^\s]+)\s+\(/u)?.[1];
    if (!member) {
      if (!/^\s*linux-vdso\.so\.[0-9]+\s+\(/u.test(line))
        throw new Error("Unknown executable ABI dependency");
      continue;
    }
    const source = await realpath(member);
    assertOwnedProcessLauncherProtected(source);
    libraries.set(member, source);
  }
  if (!libraries.size || libraries.size > 32)
    throw new Error("Incomplete executable ABI closure");
  return Promise.all(
    [...libraries].sort().map(async ([target, source]) => ({
      target,
      source,
      sha256: digest(await readFile(source)),
    })),
  );
}

const BUBBLEWRAP_CANDIDATES = Object.freeze([
  "/usr/bin/bwrap",
  "/bin/bwrap",
  "/usr/local/bin/bwrap",
  "/usr/local/sbin/bwrap",
]);
class LinuxPrerequisiteError extends Error {
  constructor(prerequisites) {
    super("Linux fixture prerequisite unavailable");
    this.code = "ERR_NATIVE_PREREQUISITE_UNAVAILABLE";
    this.prerequisites = normalizeLinuxPrerequisites(prerequisites);
  }
}

export async function prepareLinuxFixture(
  directory,
  {
    fs = { access, chmod, copyFile, lstat, mkdir, readFile, realpath },
    protect = assertOwnedProcessLauncherProtected,
    resolveLauncher = resolveOwnedProcessLauncher,
    probe = spawnSync,
    procVisibility = assertLinuxProcVisibility,
    librariesFor = protectedLibraries,
    executeFile = execute,
    expectedExecutableDigest = null,
    expectedLauncherDigest = null,
    expectedLauncherVersion = null,
  } = {},
) {
  const checks = LINUX_PREREQUISITE_IDS.map((id) => ({
    id,
    status: "NOT_RUN",
    diagnosis: null,
    observation: linuxPrerequisiteObservation(),
  }));
  let prerequisite = checks[0].id;
  const pass = (observation = linuxPrerequisiteObservation()) => {
    const index = LINUX_PREREQUISITE_IDS.indexOf(prerequisite);
    checks[index] = {
      id: prerequisite,
      status: "PASS",
      diagnosis: null,
      observation,
    };
  };
  const fail = (
    diagnosis = "unverifiable",
    observation = linuxPrerequisiteObservation(),
  ) => {
    const index = LINUX_PREREQUISITE_IDS.indexOf(prerequisite);
    if (
      ![
        "ordinary-namespace",
        "nested-namespaces",
        "protected-executable-abi",
        "bubblewrap-version",
      ].includes(prerequisite)
    )
      observation = {
        ...observation,
        exitCode: null,
        signal: null,
        timedOut: null,
      };
    checks[index] = {
      id: prerequisite,
      status: "BLOCKED",
      diagnosis,
      observation,
    };
    throw new LinuxPrerequisiteError({
      schemaVersion: 1,
      status: "BLOCKED",
      failedPrerequisite: prerequisite,
      checks,
    });
  };
  try {
    // Mirror only the public launcher's fixed discovery set, never PATH. The
    // public protection check and namespace probes retain their own policy.
    const failures = [];
    let bubblewrap;
    for (const candidate of BUBBLEWRAP_CANDIDATES) {
      let stage = 0;
      let diagnosis = "unverifiable";
      try {
        const canonical = await fs.realpath(candidate);
        stage = 1;
        const metadata = await fs.lstat(canonical);
        if (
          !path.isAbsolute(canonical) ||
          !metadata.isFile() ||
          metadata.nlink !== 1 ||
          (expectedLauncherDigest !== null &&
            digest(await fs.readFile(canonical)) !== expectedLauncherDigest)
        ) {
          failures.push({
            stage,
            diagnosis: "invalid-identity",
            observation: linuxPrerequisiteObservation(),
          });
          continue;
        }
        try {
          await fs.access(canonical, constants.X_OK);
        } catch (error) {
          failures.push({
            stage,
            diagnosis: ["EACCES", "EPERM"].includes(error?.code)
              ? "not-executable"
              : "unverifiable",
            observation: linuxPrerequisiteObservation(error),
          });
          continue;
        }
        stage = 2;
        protect(canonical);
        bubblewrap = canonical;
        break;
      } catch (error) {
        if (stage === 0 && ["ENOENT", "ENOTDIR"].includes(error?.code))
          diagnosis = "absent";
        if (stage === 2 && error?.code === "ERR_EXECUTION_PROCESS_UNVERIFIABLE")
          diagnosis = "protection-unavailable";
        failures.push({
          stage,
          diagnosis,
          observation: linuxPrerequisiteObservation(error),
        });
      }
    }
    if (!bubblewrap) {
      // A later reached stage means at least one fixed candidate satisfied the
      // earlier stages. Alternative missing candidates do not hide that fact.
      const furthest = Math.max(...failures.map((entry) => entry.stage));
      const failure =
        failures.find(
          (entry) => entry.stage === furthest && entry.diagnosis !== "absent",
        ) ?? failures[0];
      for (let index = 0; index < failure.stage; index++) {
        prerequisite = checks[index].id;
        pass();
      }
      prerequisite = checks[failure.stage].id;
      fail(failure.diagnosis, failure.observation);
    }
    for (const id of LINUX_PREREQUISITE_IDS.slice(0, 3)) {
      prerequisite = id;
      pass();
    }
    const namespace = (ownershipMode) => {
      let observation = linuxPrerequisiteObservation();
      let isSupported = false;
      let isUnsupported = false;
      const capture = (file, args, options) => {
        let result;
        try {
          result = probe(file, args, options);
        } catch (error) {
          observation = linuxPrerequisiteObservation(error);
          throw error;
        }
        observation = linuxPrerequisiteObservation(null, result);
        isSupported =
          result.status === 0 && result.error === undefined && !result.signal;
        isUnsupported =
          result.status === 1 && result.error === undefined && !result.signal;
        return result;
      };
      let launcher;
      try {
        launcher = resolveLauncher(directory, {
          bubblewrap,
          cache: new Map(),
          probe: capture,
          ownershipMode,
        });
      } catch {
        fail(isUnsupported ? "probe-failed" : "unverifiable", observation);
      }
      if (launcher.isolatedNamespace !== true || launcher.hostSession !== false)
        fail("non-isolated-fallback", observation);
      if (!isSupported || launcher.file !== bubblewrap)
        fail("unverifiable", observation);
      pass(observation);
      return launcher;
    };
    prerequisite = "ordinary-namespace";
    const launcher = namespace("ordinary");
    prerequisite = "procfs-retirement";
    await procVisibility();
    pass();
    prerequisite = "nested-namespaces";
    namespace("native-sandbox-provider");
    prerequisite = "private-fixture-storage";
    await fs.mkdir(directory, { mode: 0o700 });
    if ((await fs.realpath(directory)) !== directory) fail("invalid-identity");
    for (const name of [
      "executables",
      "inputs",
      "control",
      "evidence",
      "output",
    ])
      await fs.mkdir(path.join(directory, name), { mode: 0o700 });
    const executable = path.join(directory, "executables", "node");
    const payload = path.join(directory, "inputs", "payload.cjs");
    const fault = path.join(directory, "control", "fault.cjs");
    await fs.copyFile(process.execPath, executable);
    await fs.chmod(executable, 0o500);
    for (const [source, target] of [
      ["payload.cjs", payload],
      ["fault.cjs", fault],
    ]) {
      await fs.copyFile(path.join(SOURCE, source), target);
      await fs.chmod(target, 0o400);
    }
    pass();
    prerequisite = "protected-executable-abi";
    const libraries = await librariesFor(executable);
    const executableDigest = digest(await fs.readFile(executable));
    if (
      expectedExecutableDigest !== null &&
      executableDigest !== expectedExecutableDigest
    )
      fail("runtime-mismatch");
    const policy = {
      id: LINUX_POLICY_ID,
      executableDigest,
      payloadDigest: digest(await fs.readFile(payload)),
      faultDigest: digest(await fs.readFile(fault)),
      libraries,
      namespaces: ["user", "pid", "net", "ipc", "uts"],
      output: "/output",
      hostCheckout: false,
    };
    pass();
    prerequisite = "bubblewrap-version";
    const { stdout: version } = await executePrerequisite(
      launcher.file,
      ["--version"],
      {
        timeout: 10000,
        maxBuffer: 1024,
        env: { PATH: "/usr/bin:/bin", LANG: "C" },
      },
      executeFile,
    );
    if (
      !/^bubblewrap [0-9]+\.[0-9]+\.[0-9]+\s*$/u.test(version) ||
      (expectedLauncherVersion !== null &&
        version.trim() !== expectedLauncherVersion)
    )
      fail("invalid-version");
    const versionDigest = digest(await fs.readFile(launcher.file));
    if (
      expectedLauncherDigest !== null &&
      versionDigest !== expectedLauncherDigest
    )
      fail("unverifiable");
    pass();
    return {
      directory,
      executable,
      payload,
      fault,
      launcher: launcher.file,
      policy,
      policyDigest: digest(JSON.stringify(policy)),
      executableDigest,
      version: {
        name: "bubblewrap",
        version: version.trim(),
        sha256: versionDigest,
      },
    };
  } catch (error) {
    if (error instanceof LinuxPrerequisiteError) throw error;
    fail(
      "unverifiable",
      error instanceof LinuxPrerequisiteCommandError
        ? error.observation
        : linuxPrerequisiteObservation(error),
    );
  }
}

export function fixtureArguments(fixture, output, nonce) {
  const grants = fixture.policy.grants ?? [];
  const directories = new Set([
    "/proof",
    "/proof/bin",
    "/output",
    "/dev",
    "/proc",
  ]);
  for (const { target } of fixture.policy.libraries) {
    let directory = path.posix.dirname(target);
    while (directory !== "/") {
      directories.add(directory);
      directory = path.posix.dirname(directory);
    }
  }
  for (const { target } of grants) {
    let directory = path.posix.dirname(target);
    while (directory !== "/") {
      directories.add(directory);
      directory = path.posix.dirname(directory);
    }
  }
  return [
    "--new-session",
    "--die-with-parent",
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--as-pid-1",
    "--cap-drop",
    "ALL",
    "--clearenv",
    "--tmpfs",
    "/",
    ...[...directories]
      .sort(
        (a, b) =>
          a.split("/").length - b.split("/").length || a.localeCompare(b),
      )
      .flatMap((directory) => ["--dir", directory]),
    "--ro-bind",
    fixture.executable,
    "/proof/bin/node",
    "--ro-bind",
    fixture.payload,
    "/proof/payload.cjs",
    ...fixture.policy.libraries.flatMap(({ source, target }) => [
      "--ro-bind",
      source,
      target,
    ]),
    ...grants.flatMap(({ source, target, writable }) => [
      writable ? "--bind" : "--ro-bind",
      source,
      target,
    ]),
    "--bind",
    output,
    "/output",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--chdir",
    fixture.profile ? "/workspace" : "/output",
    "--setenv",
    "PATH",
    "/proof/bin",
    "--setenv",
    "HOME",
    "/output",
    "--setenv",
    "LANG",
    "C",
    "--",
    "/proof/bin/node",
    "/proof/payload.cjs",
    ...(fixture.profile ? fixture.arguments : ["root", nonce, ...LITERAL_ARGV]),
  ];
}
