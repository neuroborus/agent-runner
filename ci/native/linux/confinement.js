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
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  nativeException,
  nativeDiagnostic,
  diagnosticCommand,
} from "../diagnostics.js";
import {
  assertOwnedProcessLauncherProtected,
  resolveOwnedProcessLauncher,
} from "../../../src/agents/index.js";
import {
  LINUX_PREREQUISITE_IDS,
  linuxPrerequisiteObservation,
  normalizeLinuxPrerequisites,
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import {
  digest,
  assertLinuxProcVisibility,
  readLinuxObservedFile,
  readLinuxInterpreterSource,
} from "./inspect.js";
import { LINUX_POLICY_ID } from "./protocol.js";
import { linuxDiagnosticError, linuxNamespaceProbe } from "./diagnostics.js";
import { feasibilityFailureCause } from "../feasibility/index.js";
import {
  normalizeLinuxFileControl,
  assertLinuxFileControlPolicy,
} from "./files-protocol.js";

export const LITERAL_ARGV = Object.freeze([
  "",
  "two words",
  "Unicode λ",
  "; exit 99",
  "$(exit 99)",
  "*",
  "a'\"b",
]);
const execute = diagnosticCommand("linux/confinement.js", promisify(execFile));
const SOURCE = fileURLToPath(new URL("./", import.meta.url));

/** Preparation alone acquires writable setup input into the private executable
 * inventory. Later owners verify this record and never revisit that source. */
export async function acquireLinuxExperimentInterpreter(
  job,
  owner,
  directory,
  {
    source = readLinuxInterpreterSource,
    read = readLinuxObservedFile,
    fs = { mkdir, writeFile, realpath },
    sharedObjects = () => process.report.getReport().sharedObjects,
    version = process.version,
  } = {},
) {
  requireObservation(version === "v24.21.0");
  const actual = await source(),
    libraries = [],
    objects = sharedObjects();
  requireObservation(
    Array.isArray(objects) && objects.length > 0 && objects.length <= 33,
  );
  let total = 0;
  for (const target of [...new Set(objects)].sort()) {
    if (/^linux-vdso\.so\.[0-9]+$/u.test(target)) continue;
    requireObservation(path.isAbsolute(target) && libraries.length < 32);
    const canonical = await fs.realpath(target),
      observed = await read(canonical);
    total += observed.bytes.length;
    requireObservation(total <= 67108864);
    libraries.push({
      target,
      source: canonical,
      sha256: observed.sha256,
      identitySha256: observed.identitySha256,
    });
  }
  requireObservation(libraries.length > 0);
  const executable = path.join(directory, "preparation", "executables", "node"),
    intent = {
      purpose: "experiment",
      candidateSha: job.candidateSha,
      ownerSha256: observationDigest(owner),
      version,
      source: {
        file: actual.file,
        sha256: actual.sha256,
        identitySha256: actual.identitySha256,
      },
      executable,
      libraries,
    };
  await fs.writeFile(
    path.join(directory, "preparation", "interpreter-intent.json"),
    JSON.stringify(intent) + "\n",
    { flag: "wx", mode: 0o400 },
  );
  await fs.mkdir(path.dirname(executable), { mode: 0o700 });
  await fs.writeFile(executable, actual.bytes, { flag: "wx", mode: 0o500 });
  const sealed = await read(executable, 268435456, { protectedInput: false });
  requireObservation(sealed.sha256 === actual.sha256);
  const interpreter = { ...intent, identitySha256: sealed.identitySha256 };
  await verifyLinuxExperimentInterpreter(interpreter, { read });
  await fs.writeFile(
    path.join(directory, "preparation", "interpreter.json"),
    JSON.stringify(interpreter) + "\n",
    { flag: "wx", mode: 0o400 },
  );
  return interpreter;
}

/** Rejoin the same sealed inode and protected loader closure for every launch. */
export async function verifyLinuxExperimentInterpreter(
  interpreter,
  { read = readLinuxObservedFile } = {},
) {
  observationObject(interpreter, [
    "purpose",
    "candidateSha",
    "ownerSha256",
    "version",
    "source",
    "executable",
    "libraries",
    "identitySha256",
  ]);
  observationObject(interpreter.source, ["file", "sha256", "identitySha256"]);
  requireObservation(
    interpreter.purpose === "experiment" &&
      interpreter.version === "v24.21.0" &&
      /^[a-f0-9]{40}$/u.test(interpreter.candidateSha) &&
      [
        interpreter.ownerSha256,
        interpreter.identitySha256,
        interpreter.source.sha256,
        interpreter.source.identitySha256,
      ].every(
        (value) => typeof value === "string" && /^[a-f0-9]{64}$/u.test(value),
      ) &&
      path.isAbsolute(interpreter.executable) &&
      path.normalize(interpreter.executable) === interpreter.executable &&
      interpreter.executable.endsWith("/preparation/executables/node") &&
      path.isAbsolute(interpreter.source.file) &&
      path.normalize(interpreter.source.file) === interpreter.source.file &&
      Array.isArray(interpreter.libraries) &&
      interpreter.libraries.length > 0 &&
      interpreter.libraries.length <= 32 &&
      new Set(interpreter.libraries.map(({ target }) => target)).size ===
        interpreter.libraries.length,
  );
  const image = await read(interpreter.executable, 268435456, {
    protectedInput: false,
  });
  requireObservation(
    image.sha256 === interpreter.source.sha256 &&
      image.identitySha256 === interpreter.identitySha256 &&
      image.metadata.mode === 0o500,
  );
  const elf = (bytes) =>
    Buffer.isBuffer(bytes) &&
    bytes.length >= 64 &&
    bytes.subarray(0, 6).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1])) &&
    bytes.readUInt16LE(18) === 62;
  requireObservation(elf(image.bytes));
  let total = 0;
  for (const member of interpreter.libraries) {
    observationObject(member, ["target", "source", "sha256", "identitySha256"]);
    requireObservation(
      path.isAbsolute(member.target) &&
        path.normalize(member.target) === member.target &&
        path.isAbsolute(member.source),
    );
    const observed = await read(member.source);
    total += observed.bytes.length;
    requireObservation(
      total <= 67108864 &&
        elf(observed.bytes) &&
        observed.sha256 === member.sha256 &&
        observed.identitySha256 === member.identitySha256,
    );
  }
  return interpreter;
}

class LinuxPrerequisiteCommandError extends Error {
  constructor(observation, cause) {
    super("Linux prerequisite command unavailable");
    this.observation = observation;
    this.code = observation.errno ?? observation.exitCode ?? "UNVERIFIED";
    this.feasibilityCause = cause;
  }
}

async function executePrerequisite(
  file,
  args,
  options,
  run = execute,
  operation = "protected-executable-abi",
) {
  try {
    return await run(file, args, options);
  } catch (error) {
    nativeException("linux/confinement.js:exception", error);
    // execFile reports process exits/signals here. Arbitrary later fixture
    // exceptions do not establish that a command started or terminated.
    throw new LinuxPrerequisiteCommandError(
      linuxPrerequisiteObservation(null, {
        status: error?.code,
        signal: error?.signal,
        error,
      }),
      feasibilityFailureCause("prepare", operation, error),
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
  constructor(prerequisites, diagnostic, components) {
    super("Linux fixture prerequisite unavailable");
    this.code = "ERR_NATIVE_PREREQUISITE_UNAVAILABLE";
    this.prerequisites = normalizeLinuxPrerequisites(prerequisites);
    this.feasibilityCause = diagnostic;
    this.feasibilityComponents = components;
  }
}

export async function prepareLinuxFixture(
  directory,
  {
    fs = { access, chmod, copyFile, lstat, mkdir, readFile, realpath },
    protect = assertOwnedProcessLauncherProtected,
    resolveLauncher = resolveOwnedProcessLauncher,
    probe = diagnosticCommand("linux-prerequisite", spawnSync),
    procVisibility = assertLinuxProcVisibility,
    librariesFor = protectedLibraries,
    executeFile = execute,
    expectedExecutableDigest = null,
    expectedLauncherDigest = null,
    expectedLauncherVersion = null,
    captureDiagnostics = false,
    interpreter,
  } = {},
) {
  const checks = LINUX_PREREQUISITE_IDS.map((id) => ({
    id,
    status: "NOT_RUN",
    diagnosis: null,
    observation: linuxPrerequisiteObservation(),
  }));
  let prerequisite = checks[0].id;
  let diagnostic = null,
    components = [];
  const pass = (observation = linuxPrerequisiteObservation()) => {
    diagnostic = null;
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
    throw new LinuxPrerequisiteError(
      {
        schemaVersion: 1,
        status: "BLOCKED",
        failedPrerequisite: prerequisite,
        checks,
      },
      diagnostic ??
        feasibilityFailureCause(
          "prepare",
          prerequisite,
          {
            ...observation,
            code: observation.errno,
            signal:
              observation.exitCode === null && observation.signal === null
                ? undefined
                : observation.signal,
          },
          ["absent", "protection-unavailable", "probe-failed"].includes(
            diagnosis,
          )
            ? "prerequisite-unavailable"
            : "setup-failed",
        ),
      components,
    );
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
          nativeException("linux/confinement.js:exception", error);
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
        nativeException("linux/confinement.js:exception", error);
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
    if (captureDiagnostics) {
      // Observe installed bytes before a failed namespace probe can stop setup;
      // this side channel neither passes nor reorders full-acceptance prerequisites.
      try {
        const { stdout } = await executeFile(bubblewrap, ["--version"], {
          timeout: 10000,
          maxBuffer: 1024,
          env: { PATH: "/usr/bin:/bin", LANG: "C" },
        });
        if (
          typeof stdout === "string" &&
          /^bubblewrap [0-9]+\.[0-9]+\.[0-9]+\s*$/u.test(stdout) &&
          Buffer.byteLength(stdout) <= 1024 &&
          Buffer.byteLength(stdout.trim()) <= 128
        )
          components = [
            {
              role: "tool",
              name: "bubblewrap",
              version: stdout.trim(),
              sha256: digest(await fs.readFile(bubblewrap)),
            },
          ];
      } catch (diagnosticError) {
        nativeException("linux/confinement.js:exception", diagnosticError);
        /* Missing version/identity stays unobserved; namespace evidence remains independent. */
      }
    }
    const namespace = (ownershipMode) => {
      let observation = linuxPrerequisiteObservation();
      let isSupported = false;
      let isUnsupported = false;
      let hasProbed = false;
      const boundedProbe = linuxNamespaceProbe(
        probe,
        "prepare",
        prerequisite,
        (cause) => {
          diagnostic = cause;
        },
      );
      const capture = (file, args, options) => {
        hasProbed = true;
        let result;
        try {
          result = boundedProbe(file, args, options);
        } catch (error) {
          nativeException("linux/confinement.js:exception", error);
          observation = linuxPrerequisiteObservation(error);
          throw error;
        }
        nativeDiagnostic("linux-prerequisite-probe", {
          ...result,
          exitCode: result.status,
        });
        observation = linuxPrerequisiteObservation(null, result);
        isSupported =
          result.status === 0 && result.error === undefined && !result.signal;
        isUnsupported =
          result.status === 1 &&
          result.error === undefined &&
          !result.signal &&
          diagnostic?.code === "prerequisite-unavailable";
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
      } catch (error) {
        nativeException("linux/confinement.js:exception", error);
        if (!hasProbed) {
          observation = linuxPrerequisiteObservation(error);
          diagnostic = linuxDiagnosticError(
            "prepare",
            ownershipMode === "ordinary"
              ? "ordinary-launcher-construction"
              : "nested-launcher-construction",
            {
              code: error?.code,
              feasibilityCause: error?.feasibilityCause,
            },
          ).feasibilityCause;
        }
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
    const executable = interpreter
      ? (await verifyLinuxExperimentInterpreter(interpreter)).executable
      : path.join(directory, "executables", "node");
    const payload = path.join(directory, "inputs", "payload.cjs");
    const fault = path.join(directory, "control", "fault.cjs");
    if (!interpreter) {
      await fs.copyFile(process.execPath, executable);
      await fs.chmod(executable, 0o500);
    }
    for (const [source, target] of [
      ["payload.cjs", payload],
      ["fault.cjs", fault],
    ]) {
      await fs.copyFile(path.join(SOURCE, source), target);
      await fs.chmod(target, 0o400);
    }
    pass();
    prerequisite = "protected-executable-abi";
    const libraries = interpreter
      ? interpreter.libraries.map(({ identitySha256, ...entry }) => entry)
      : await librariesFor(executable);
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
      "bubblewrap-version",
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
      ...(interpreter ? { interpreter } : {}),
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
    nativeException("linux/confinement.js:exception", error);
    if (error instanceof LinuxPrerequisiteError) throw error;
    diagnostic ??= error?.feasibilityCause;
    fail(
      "unverifiable",
      error instanceof LinuxPrerequisiteCommandError
        ? error.observation
        : linuxPrerequisiteObservation(error),
    );
  }
}

export function fixtureArguments(fixture, output, nonce) {
  if (fixture.fileHelper === true) {
    const control = normalizeLinuxFileControl(fixture.fileControl ?? null);
    if (control !== null) assertLinuxFileControlPolicy(fixture.policy, control);
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
      "--dir",
      "/proof",
      "--dir",
      "/proof/bin",
      "--dir",
      "/anchor",
      "--ro-bind",
      fixture.executable,
      "/proof/bin/file-helper",
      "--bind",
      output,
      "/anchor",
      ...(control === "magic-link"
        ? ["--dir", "/proc", "--proc", "/proc"]
        : []),
      ...(control === "mount"
        ? [
            "--ro-bind",
            path.join(output, ".crossing-source"),
            "/anchor/crossing",
          ]
        : []),
      "--chdir",
      "/",
      "--",
      "/proof/bin/file-helper",
      "--session",
      nonce,
      fixture.fileAnchorIdentity ?? "-",
      ...(control === null ? [] : [control]),
    ];
  }
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
