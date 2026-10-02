import { execFile } from "node:child_process";
import {
  chmod,
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
import { digest } from "./inspect.js";

const execute = promisify(execFile);
const SOURCE = fileURLToPath(new URL("./file-helper.c", import.meta.url));
const COMPILER = "/usr/bin/x86_64-linux-gnu-gcc-13";
const SHA = /^[a-f0-9]{64}$/u;
export const LINUX_FILE_BUILD_ARGUMENTS = Object.freeze([
  "-B/usr/lib/gcc/x86_64-linux-gnu/13/",
  "-B/usr/bin/",
  "--sysroot=/",
  "-std=c11",
  "-O2",
  "-Wall",
  "-Wextra",
  "-Werror",
  "-fno-ident",
  "-frandom-seed=native-files-v1",
  "-ffile-prefix-map=/build=.",
  "-fno-pie",
  "-no-pie",
  "-static",
  "-Wl,--build-id=none",
  "-o",
  "/output/file-helper",
  "/build/file-helper.c",
]);

function requireValue(condition) {
  if (!condition)
    throw new Error("Missing or mismatched Linux helper build inputs");
}

function closed(value, keys) {
  requireValue(
    value !== null &&
      typeof value === "object" &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
}

/** Pins come from separately reviewed system build evidence, never observed
 * hashes promoted to authority. Unlisted toolchain/headers/libraries are absent
 * from the build domain, so an incomplete pin set fails rather than falling back. */
export function normalizeLinuxFileBuildPins(value, candidateSha) {
  closed(value, [
    "schemaVersion",
    "candidateSha",
    "sourceSha256",
    "compilerVersion",
    "inputs",
  ]);
  requireValue(
    value.schemaVersion === 1 &&
      typeof candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(candidateSha) &&
      value.candidateSha === candidateSha &&
      typeof value.sourceSha256 === "string" &&
      SHA.test(value.sourceSha256) &&
      typeof value.compilerVersion === "string" &&
      /^13\.[0-9]+\.[0-9]+$/u.test(value.compilerVersion) &&
      Array.isArray(value.inputs) &&
      Object.getPrototypeOf(value.inputs) === Array.prototype &&
      value.inputs.length > 0 &&
      value.inputs.length <= 512 &&
      Reflect.ownKeys(value.inputs).length === value.inputs.length + 1,
  );
  const targets = new Set();
  for (let index = 0; index < value.inputs.length; index++) {
    const field = Object.getOwnPropertyDescriptor(value.inputs, index);
    requireValue(field?.enumerable && Object.hasOwn(field, "value"));
  }
  const inputs = Array.from(value.inputs, (input) => {
    closed(input, ["source", "target", "sha256"]);
    for (const key of ["source", "target"]) {
      const name = input[key];
      // The compiler's interpreter uses this ABI path; its source stays canonical.
      requireValue(
        typeof name === "string" &&
          (/^\/(?:usr\/(?:bin|include|lib)|lib\/x86_64-linux-gnu)\/[a-zA-Z0-9_./+\-]+$/u.test(
            name,
          ) ||
            (key === "target" && name === "/lib64/ld-linux-x86-64.so.2")) &&
          path.posix.normalize(name) === name &&
          !name.endsWith("/"),
      );
    }
    requireValue(
      typeof input.sha256 === "string" &&
        SHA.test(input.sha256) &&
        !targets.has(input.target),
    );
    targets.add(input.target);
    return { ...input };
  });
  requireValue(targets.has(COMPILER));
  return { ...value, inputs };
}

/** Static ELF has no dynamic loader/library search path in the helper domain. */
export function verifyLinuxFileElf(bytes) {
  requireValue(
    Buffer.isBuffer(bytes) &&
      bytes.length >= 64 &&
      bytes.length <= 4194304 &&
      bytes
        .subarray(0, 7)
        .equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1])) &&
      bytes.readUInt16LE(16) === 2 &&
      bytes.readUInt16LE(18) === 62 &&
      bytes.readUInt32LE(20) === 1 &&
      bytes.readUInt16LE(52) === 64 &&
      bytes.readUInt16LE(54) === 56,
  );
  const offset = Number(bytes.readBigUInt64LE(32));
  const count = bytes.readUInt16LE(56);
  requireValue(
    Number.isSafeInteger(offset) &&
      offset >= 64 &&
      count > 0 &&
      count <= 64 &&
      offset + count * 56 <= bytes.length,
  );
  let stack = false;
  let executableEntry = false;
  const entry = bytes.readBigUInt64LE(24);
  for (let index = 0; index < count; index++) {
    const start = offset + index * 56;
    const type = bytes.readUInt32LE(start);
    requireValue(type !== 2 && type !== 3); // PT_DYNAMIC and PT_INTERP forbidden.
    const fileOffset = bytes.readBigUInt64LE(start + 8);
    const size = bytes.readBigUInt64LE(start + 32);
    requireValue(fileOffset + size <= BigInt(bytes.length));
    if (type === 1) {
      const flags = bytes.readUInt32LE(start + 4);
      const address = bytes.readBigUInt64LE(start + 16);
      const memorySize = bytes.readBigUInt64LE(start + 40);
      requireValue(
        memorySize >= size &&
          address + memorySize <= 18446744073709551615n &&
          (flags & 3) !== 3,
      );
      if ((flags & 1) !== 0 && entry >= address && entry < address + size)
        executableEntry = true;
    }
    if (type === 0x6474e551) {
      requireValue((bytes.readUInt32LE(start + 4) & 1) === 0);
      stack = true;
    }
  }
  requireValue(stack && executableEntry);
  return {
    architecture: "x86-64",
    linkage: "static",
    dynamicDependencies: [],
    requiredSyscalls: ["openat2", "statx", "renameat2", "close_range", "fsync"],
  };
}

/** Deliberately not called by local checks or ordinary suite discovery. */
export async function buildLinuxFileHelper(
  candidateSha,
  directory,
  launcher,
  suppliedPins,
  {
    fs = { chmod, lstat, mkdir, readFile, realpath, writeFile },
    run = execute,
    protect = assertOwnedProcessLauncherProtected,
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
  } = {},
) {
  requireValue(
    platform === "linux" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24",
  );
  const pins = normalizeLinuxFileBuildPins(suppliedPins, candidateSha);
  const release = await fs.readFile("/etc/os-release", "utf8");
  requireValue(
    /^ID=ubuntu$/mu.test(release) && /^VERSION_ID="24\.04"$/mu.test(release),
  );
  requireValue(
    launcher === "/usr/bin/bwrap" && (await fs.realpath(launcher)) === launcher,
  );
  protect(launcher);
  await fs.mkdir(directory, { mode: 0o700 });
  requireValue((await fs.realpath(directory)) === directory);
  await fs.mkdir(path.join(directory, "output"), { mode: 0o700 });
  await fs.mkdir(path.join(directory, "inputs"), { mode: 0o700 });
  const source = await fs.readFile(SOURCE);
  requireValue(
    source.length > 0 &&
      source.length <= 65536 &&
      digest(source) === pins.sourceSha256,
  );
  const sourceFile = path.join(directory, "file-helper.c");
  await fs.writeFile(sourceFile, source, { flag: "wx", mode: 0o400 });
  const directories = new Set(["/build", "/output", "/tmp", "/dev"]);
  let total = 0;
  const exposures = [];
  for (const input of pins.inputs) {
    requireValue((await fs.realpath(input.source)) === input.source);
    protect(input.source);
    const metadata = await fs.lstat(input.source);
    total += metadata.size;
    requireValue(
      metadata.isFile() && metadata.nlink === 1 && total <= 67108864,
    );
    const snapshot = await fs.readFile(input.source);
    requireValue(
      snapshot.length === metadata.size && digest(snapshot) === input.sha256,
    );
    const copy = path.join(directory, "inputs", String(exposures.length));
    await fs.writeFile(copy, snapshot, {
      flag: "wx",
      mode: (metadata.mode & 0o111) !== 0 ? 0o500 : 0o400,
    });
    exposures.push({ source: copy, target: input.target });
    let parent = path.posix.dirname(input.target);
    while (parent !== "/") {
      directories.add(parent);
      parent = path.posix.dirname(parent);
    }
  }
  const argumentsFor = (args) => [
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
      .flatMap((name) => ["--dir", name]),
    ...exposures.flatMap(({ source, target }) => ["--ro-bind", source, target]),
    "--ro-bind",
    sourceFile,
    "/build/file-helper.c",
    "--bind",
    path.join(directory, "output"),
    "/output",
    "--dev",
    "/dev",
    "--chdir",
    "/build",
    "--setenv",
    "PATH",
    "/usr/bin",
    "--setenv",
    "LANG",
    "C",
    "--",
    COMPILER,
    ...args,
  ];
  const options = {
    cwd: directory,
    env: { PATH: "/usr/bin:/bin", LANG: "C" },
    timeout: 20000,
    maxBuffer: 65536,
    killSignal: "SIGKILL",
  };
  const version = await run(
    launcher,
    argumentsFor(["-dumpfullversion", "-dumpversion"]),
    options,
  );
  requireValue(version.stdout.trim() === pins.compilerVersion);
  await run(launcher, argumentsFor(LINUX_FILE_BUILD_ARGUMENTS), options);
  const executable = path.join(directory, "output", "file-helper");
  const metadata = await fs.lstat(executable);
  requireValue(
    metadata.isFile() &&
      metadata.nlink === 1 &&
      metadata.size <= 4194304 &&
      (await fs.realpath(executable)) === executable,
  );
  const bytes = await fs.readFile(executable);
  requireValue(bytes.length === metadata.size);
  const abi = verifyLinuxFileElf(bytes);
  await fs.chmod(executable, 0o500);
  const record = {
    schemaVersion: 1,
    candidateSha,
    sourceSha256: pins.sourceSha256,
    compiler: {
      file: COMPILER,
      version: pins.compilerVersion,
      sha256: pins.inputs.find(({ target }) => target === COMPILER).sha256,
    },
    arguments: [...LINUX_FILE_BUILD_ARGUMENTS],
    inputs: pins.inputs,
    sha256: digest(bytes),
    abi,
  };
  await fs.writeFile(
    path.join(directory, "build.json"),
    JSON.stringify(record) + "\n",
    { flag: "wx", mode: 0o400 },
  );
  return { ...record, executable };
}
