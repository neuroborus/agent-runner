import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, copyFile, mkdir, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertOwnedProcessLauncherProtected,
  resolveOwnedProcessLauncher,
} from "../../../src/agents/index.js";
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

export async function protectedLibraries(executable) {
  const ldd = await realpath("/usr/bin/ldd");
  assertOwnedProcessLauncherProtected(ldd);
  const { stdout } = await execute(ldd, [executable], {
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

export async function prepareLinuxFixture(directory) {
  let prerequisite = "protected-bubblewrap";
  try {
    const launcher = resolveOwnedProcessLauncher(directory);
    if (launcher.isolatedNamespace !== true || launcher.hostSession !== false)
      throw new Error(
        "Missing isolated PID namespace; host-session fallback excluded",
      );
    assertOwnedProcessLauncherProtected(launcher.file);
    prerequisite = "procfs-retirement";
    await assertLinuxProcVisibility();
    prerequisite = "nested-namespaces";
    // Probe only this public launcher capability. No provider-private policy or
    // provider execution is admitted by the prerequisite probe.
    const nested = resolveOwnedProcessLauncher(directory, {
      ownershipMode: "native-sandbox-provider",
    });
    if (
      !nested.isolatedNamespace ||
      nested.hostSession ||
      nested.file !== launcher.file
    )
      throw new Error("Missing nested user/PID/network namespace support");
    prerequisite = "private-fixture-storage";
    await mkdir(directory, { mode: 0o700 });
    if ((await realpath(directory)) !== directory)
      throw new Error("Substituted fixture path");
    for (const name of [
      "executables",
      "inputs",
      "control",
      "evidence",
      "output",
    ])
      await mkdir(path.join(directory, name), { mode: 0o700 });
    const executable = path.join(directory, "executables", "node");
    const payload = path.join(directory, "inputs", "payload.cjs");
    const fault = path.join(directory, "control", "fault.cjs");
    await copyFile(process.execPath, executable);
    await chmod(executable, 0o500);
    for (const [source, target] of [
      ["payload.cjs", payload],
      ["fault.cjs", fault],
    ]) {
      await copyFile(path.join(SOURCE, source), target);
      await chmod(target, 0o400);
    }
    prerequisite = "protected-executable-abi";
    const libraries = await protectedLibraries(executable);
    const executableDigest = digest(await readFile(executable));
    const policy = {
      id: LINUX_POLICY_ID,
      executableDigest,
      payloadDigest: digest(await readFile(payload)),
      faultDigest: digest(await readFile(fault)),
      libraries,
      namespaces: ["user", "pid", "net", "ipc", "uts"],
      output: "/output",
      hostCheckout: false,
    };
    prerequisite = "bubblewrap-version";
    const { stdout: version } = await execute(launcher.file, ["--version"], {
      timeout: 10000,
      maxBuffer: 1024,
      env: { PATH: "/usr/bin:/bin", LANG: "C" },
    });
    if (!/^bubblewrap [0-9]+\.[0-9]+\.[0-9]+\s*$/u.test(version))
      throw new Error("Unknown protected bubblewrap version");
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
        sha256: digest(await readFile(launcher.file)),
      },
    };
  } catch (cause) {
    throw Object.assign(new Error("Linux fixture prerequisite unavailable"), {
      prerequisite,
      code: /^[A-Z][A-Z0-9_]{0,79}$/u.test(cause.code ?? "")
        ? cause.code
        : "UNVERIFIED",
    });
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
