import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { promisify } from "node:util";

import { assertOwnedProcessLauncherProtected } from "../../../src/agents/index.js";

const execute = promisify(execFile);
const KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg";
const SOURCE = `deb [arch=amd64 signed-by=${KEYRING}] https://archive.ubuntu.com/ubuntu noble main universe\n`;
const VERSION = /^[0-9][a-zA-Z0-9.+~\-]{0,95}$/u;
const SHA = /^[a-f0-9]{64}$/u;
const ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  DEBIAN_FRONTEND: "noninteractive",
});

export function initialLinuxPreparation(candidateSha) {
  return {
    schemaVersion: 1,
    candidateSha,
    status: "NOT_RUN",
    phase: null,
    package: null,
    version: null,
  };
}

function closed(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Reflect.ownKeys(value).length === keys.length &&
    keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor?.enumerable && Object.hasOwn(descriptor, "value");
    })
  );
}

function validPackage(value) {
  return (
    closed(value, ["filename", "sha256", "size", "version"]) &&
    typeof value.version === "string" &&
    VERSION.test(value.version) &&
    typeof value.sha256 === "string" &&
    SHA.test(value.sha256) &&
    Number.isSafeInteger(value.size) &&
    value.size > 0 &&
    value.size <= 33554432 &&
    ["main", "universe"].some(
      (component) =>
        value.filename ===
        `pool/${component}/b/bubblewrap/bubblewrap_${value.version}_amd64.deb`,
    )
  );
}

/** This receipt is setup evidence only, never native acceptance or retirement. */
export function linuxPreparationVersion(
  value,
  candidateSha,
  outcome = "success",
) {
  const keys = [
    "schemaVersion",
    "candidateSha",
    "status",
    "phase",
    "package",
    "version",
  ];
  if (
    typeof candidateSha !== "string" ||
    !/^[a-f0-9]{40}$/u.test(candidateSha) ||
    !closed(value, keys) ||
    value.schemaVersion !== 1 ||
    value.candidateSha !== candidateSha ||
    outcome !== "success" ||
    value.status !== "PASS" ||
    value.phase !== "verification" ||
    !validPackage(value.package) ||
    !closed(value.version, ["name", "sha256", "version"]) ||
    value.version.name !== "bubblewrap" ||
    typeof value.version.version !== "string" ||
    !/^bubblewrap [0-9]+\.[0-9]+\.[0-9]+$/u.test(value.version.version) ||
    typeof value.version.sha256 !== "string" ||
    !SHA.test(value.version.sha256)
  )
    throw new Error("Linux preparation is incomplete or mismatched");
  return { ...value.version };
}

function packageMetadata(output) {
  if (output.trim().split(/\n\s*\n/u).length !== 1)
    throw new Error("Ambiguous package metadata");
  const fields = new Map();
  for (const line of output.trim().split("\n")) {
    if (/^\s/u.test(line)) continue;
    const match = line.match(/^([a-zA-Z0-9-]+): (.*)$/u);
    if (!match || fields.has(match[1]))
      throw new Error("Invalid package metadata");
    fields.set(match[1], match[2]);
  }
  const selected = {
    version: fields.get("Version"),
    filename: fields.get("Filename"),
    size: Number(fields.get("Size")),
    sha256: fields.get("SHA256"),
  };
  if (
    !validPackage(selected) ||
    fields.get("Package") !== "bubblewrap" ||
    fields.get("Architecture") !== "amd64"
  )
    throw new Error("Unexpected package identity");
  return selected;
}

/** Only dedicated system CI supplies real effects; tests inject every effect. */
export async function prepareLinuxBubblewrap(
  candidateSha,
  directory,
  persist,
  {
    run = execute,
    fs = { lstat, mkdir, readFile, realpath, writeFile },
    protect = assertOwnedProcessLauncherProtected,
    now = () => performance.now(),
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
  } = {},
) {
  if (
    platform !== "linux" ||
    architecture !== "x64" ||
    env.CI !== "true" ||
    env.GITHUB_ACTIONS !== "true" ||
    env.ImageOS !== "ubuntu24" ||
    !/^[a-f0-9]{40}$/u.test(candidateSha)
  )
    throw new Error("Linux preparation requires declared system CI");
  const record = initialLinuxPreparation(candidateSha);
  const deadline = now() + 150000;
  let configuration;
  const command = async (
    file,
    args,
    seconds,
    privileged = false,
    cwd = directory,
  ) => {
    const remaining = Math.min(
      seconds,
      Math.floor((deadline - now()) / 1000) - 7,
    );
    if (remaining < 1) throw new Error("Preparation deadline");
    const bounded = [
      "--signal=TERM",
      "--kill-after=5s",
      `${remaining}s`,
      file,
      ...args,
    ];
    // The privileged timer must retain authority to signal its root children.
    const result = await run(
      privileged ? "/usr/bin/sudo" : "/usr/bin/timeout",
      privileged
        ? [
            "--non-interactive",
            "--preserve-env=APT_CONFIG,DEBIAN_FRONTEND",
            "--",
            "/usr/bin/timeout",
            ...bounded,
          ]
        : bounded,
      {
        cwd,
        env: {
          ...ENVIRONMENT,
          ...(configuration ? { APT_CONFIG: configuration } : {}),
        },
        timeout: (remaining + 7) * 1000,
        maxBuffer: 65536,
        killSignal: "SIGKILL",
      },
    );
    if (now() >= deadline) throw new Error("Preparation deadline");
    return result.stdout;
  };
  const phase = async (name) => {
    record.status = "RUNNING";
    record.phase = name;
    await persist({ ...record }); // Write ahead of each new class of effects.
  };
  try {
    await phase("metadata");
    const release = await fs.readFile("/etc/os-release", "utf8");
    if (
      !/^ID=ubuntu$/mu.test(release) ||
      !/^VERSION_ID="24\.04"$/mu.test(release)
    )
      throw new Error("Incompatible preparation image");
    for (const file of [
      KEYRING,
      "/usr/bin/timeout",
      "/usr/bin/sudo",
      "/usr/bin/apt-get",
      "/usr/bin/apt-cache",
      "/usr/bin/dpkg-query",
    ])
      protect(await fs.realpath(file));
    const storage = path.join(directory, "linux-packages");
    if (!path.isAbsolute(storage) || /["\\\x00-\x1f\x7f]/u.test(storage))
      throw new Error("Invalid preparation storage");
    await fs.mkdir(storage, { mode: 0o700 });
    for (const name of [
      "configuration",
      "lists",
      "lists/partial",
      "archives",
      "archives/partial",
    ])
      await fs.mkdir(path.join(storage, name), { mode: 0o700 });
    const sources = path.join(storage, "sources.list");
    await fs.writeFile(sources, SOURCE, { flag: "wx", mode: 0o400 });
    // APT_CONFIG is read before image-wide configuration. Command-line -o
    // overrides alone cannot prevent already-loaded hooks from executing.
    configuration = path.join(storage, "apt.conf");
    await fs.writeFile(
      configuration,
      `Dir::Etc::parts "${storage}/configuration";\nDir::Etc::main "/dev/null";\n`,
      { flag: "wx", mode: 0o400 },
    );
    const options = [
      "-o",
      `Dir::Etc::sourcelist=${sources}`,
      "-o",
      "Dir::Etc::sourceparts=-",
      "-o",
      "Dir::Etc::preferences=-",
      "-o",
      "Dir::Etc::preferencesparts=-",
      "-o",
      "Dir::Cache::pkgcache=",
      "-o",
      "Dir::Cache::srcpkgcache=",
      "-o",
      `Dir::State::lists=${storage}/lists`,
      "-o",
      `Dir::Cache::archives=${storage}/archives`,
      "-o",
      "APT::Architecture=amd64",
      "-o",
      "Acquire::Languages=none",
      "-o",
      "Acquire::Retries=0",
      "-o",
      "Acquire::http::Timeout=15",
      "-o",
      "Acquire::https::Timeout=15",
      "-o",
      "Acquire::AllowInsecureRepositories=false",
      "-o",
      "Acquire::AllowDowngradeToInsecureRepositories=false",
      "-o",
      "APT::Get::AllowUnauthenticated=false",
      "-o",
      "APT::Update::Error-Mode=any",
      "-o",
      "DPkg::Lock::Timeout=5",
      "-o",
      "Dpkg::Options::=--force-confdef",
      "-o",
      "Dpkg::Options::=--force-confold",
    ];
    await command("/usr/bin/apt-get", [...options, "update"], 35);
    record.package = packageMetadata(
      await command(
        "/usr/bin/apt-cache",
        [...options, "--no-all-versions", "show", "bubblewrap"],
        5,
      ),
    );
    const install = [
      "--yes",
      "--reinstall",
      "--no-install-recommends",
      "--no-remove",
      "install",
      `bubblewrap=${record.package.version}`,
    ];
    const simulation = await command(
      "/usr/bin/apt-get",
      [...options, "--simulate", ...install],
      5,
    );
    const changes = simulation
      .split("\n")
      .filter((line) => /^(?:Inst|Remv|Conf) /u.test(line));
    const installations = changes.filter((line) => line.startsWith("Inst "));
    if (
      installations.length !== 1 ||
      installations[0].match(
        /^Inst bubblewrap (?:\[[^\]]+\] )?\(([^ ]+) /u,
      )?.[1] !== record.package.version ||
      changes.some((line) => !/^(?:Inst|Conf) bubblewrap /u.test(line))
    )
      throw new Error("Unreviewed dependency changes");
    await phase("acquisition");
    await command(
      "/usr/bin/apt-get",
      [...options, "download", `bubblewrap=${record.package.version}`],
      35,
      false,
      path.join(storage, "archives"),
    );
    const archive = path.join(
      storage,
      "archives",
      path.posix.basename(record.package.filename),
    );
    const metadata = await fs.lstat(archive);
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1 ||
      metadata.size !== record.package.size
    )
      throw new Error("Invalid acquired package identity");
    const bytes = await fs.readFile(archive);
    if (
      bytes.length !== record.package.size ||
      createHash("sha256").update(bytes).digest("hex") !== record.package.sha256
    )
      throw new Error("Package integrity mismatch");
    await phase("installation");
    // APT rechecks its authenticated package digest. Missing dependency bytes
    // fail instead of acquiring another installation vector.
    await command(
      "/usr/bin/apt-get",
      [...options, "--no-download", ...install],
      35,
      true,
    );
    await phase("verification");
    const installed = await command(
      "/usr/bin/dpkg-query",
      ["--show", "--showformat=${Version}", "bubblewrap"],
      5,
    );
    if (installed !== record.package.version)
      throw new Error("Installed package version mismatch");
    const executable = await fs.realpath("/usr/bin/bwrap");
    const identity = await fs.lstat(executable);
    if (
      executable !== "/usr/bin/bwrap" ||
      !identity.isFile() ||
      identity.nlink !== 1
    )
      throw new Error("Installed executable identity mismatch");
    protect(executable);
    record.version = {
      name: "bubblewrap",
      version: (await command(executable, ["--version"], 5)).trim(),
      sha256: createHash("sha256")
        .update(await fs.readFile(executable))
        .digest("hex"),
    };
    if (now() >= deadline) throw new Error("Preparation deadline");
    record.status = "PASS";
    linuxPreparationVersion(record, candidateSha);
  } catch {
    record.status = "FAIL";
    record.version = null;
  }
  await persist({ ...record });
  return record;
}
