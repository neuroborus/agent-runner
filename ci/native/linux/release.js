import { constants } from "node:fs";
import { open, lstat, readFile, realpath } from "node:fs/promises";
import { posix as path } from "node:path";
import { assertOwnedProcessLauncherProtected } from "../../../src/agents/index.js";
import {
  CHECK_IDS,
  SOURCE_FINDING_IDS,
  LINUX_RELEASE_POLICY_ID,
} from "../index.js";
import { digest } from "./inspect.js";
import {
  LINUX_FILE_BUILD_ARGUMENTS,
  normalizeLinuxFileBuildPins,
  verifyLinuxFileElf,
} from "./file-build.js";

const LIMIT = 1048576;
const HASH = /^[a-f0-9]{64}$/u;
const LABEL = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u;
const VERSION = /^[a-zA-Z0-9][a-zA-Z0-9 ._+-]{0,127}$/u;
const EXECUTABLES = Object.freeze([
  "node",
  "bubblewrap",
  "git",
  "compiler",
  "file-helper",
]);
const matches = (value, pattern) =>
  typeof value === "string" && pattern.test(value);

function requireValue(value) {
  if (!value)
    throw new Error("Missing or mismatched reviewed Linux release inputs");
}

function closed(value, keys) {
  requireValue(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
}

function list(value, maximum) {
  requireValue(
    Array.isArray(value) &&
      Object.getPrototypeOf(value) === Array.prototype &&
      value.length <= maximum &&
      Reflect.ownKeys(value).length === value.length + 1,
  );
  for (let i = 0; i < value.length; i++)
    requireValue(
      Object.getOwnPropertyDescriptor(value, i)?.enumerable &&
        Object.hasOwn(Object.getOwnPropertyDescriptor(value, i), "value"),
    );
  return value;
}

/** Reviewed bindings are supplied authority, never generated from observations. */
export function normalizeLinuxReleaseInputs(value, candidateSha) {
  closed(value, [
    "schemaVersion",
    "candidateSha",
    "buildPinsSha256",
    "components",
    "unresolvedAssumptions",
  ]);
  requireValue(
    value.schemaVersion === 1 &&
      matches(candidateSha, /^[a-f0-9]{40}$/u) &&
      value.candidateSha === candidateSha &&
      matches(value.buildPinsSha256, HASH),
  );
  const components = list(value.components, 600).map((component) => {
    closed(component, [
      "name",
      "version",
      "sha256",
      "publication",
      "source",
      "build",
      "license",
    ]);
    requireValue(
      matches(component.name, LABEL) &&
        (EXECUTABLES.includes(component.name) ||
          /^(?:build-input|abi)-[a-f0-9]{32}$/u.test(component.name)) &&
        matches(component.version, VERSION) &&
        matches(component.sha256, HASH),
    );
    const bindings = Object.fromEntries(
      ["publication", "source", "build", "license"].map((kind) => {
        closed(component[kind], ["id", "sha256"]);
        requireValue(
          matches(component[kind].id, LABEL) &&
            matches(component[kind].sha256, HASH),
        );
        return [kind, { ...component[kind] }];
      }),
    );
    return {
      name: component.name,
      version: component.version,
      sha256: component.sha256,
      ...bindings,
    };
  });
  requireValue(
    components.length >= 5 &&
      new Set(components.map(({ name }) => name)).size === components.length,
  );
  requireValue(
    JSON.stringify(list(value.unresolvedAssumptions, 4)) ===
      JSON.stringify(SOURCE_FINDING_IDS),
  );
  return {
    ...value,
    components,
    unresolvedAssumptions: [...SOURCE_FINDING_IDS],
  };
}

/** Only a canonical, private, immutable CI side-input directory is admitted. */
export async function readLinuxReviewedFile(
  file,
  { fs = { open, lstat, realpath }, ownerUid = process.getuid } = {},
) {
  requireValue(typeof file === "string" && file === path.resolve(file));
  const directory = path.dirname(file);
  requireValue((await fs.realpath(directory)) === directory);
  const metadata = await fs.lstat(directory);
  requireValue(
    metadata.isDirectory() &&
      (metadata.mode & 0o7777) === 0o700 &&
      metadata.uid === ownerUid(),
  );
  let handle;
  try {
    requireValue((await fs.realpath(file)) === file);
    handle = await fs.open(
      file,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await handle.stat();
    requireValue(
      before.isFile() &&
        before.nlink === 1 &&
        before.uid === ownerUid() &&
        (before.mode & 0o7777) === 0o400 &&
        before.size > 0 &&
        before.size <= LIMIT,
    );
    // Bound allocation even if the input grows after the held-file stat.
    const buffer = Buffer.alloc(before.size + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        size,
        buffer.length - size,
        size,
      );
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    const bytes = buffer.subarray(0, size);
    const after = await handle.stat(),
      named = await fs.lstat(file),
      parent = await fs.lstat(directory);
    requireValue(
      bytes.length === before.size &&
        after.size === before.size &&
        after.mtimeMs === before.mtimeMs &&
        after.ctimeMs === before.ctimeMs &&
        named.dev === before.dev &&
        named.ino === before.ino &&
        named.uid === before.uid &&
        named.nlink === 1 &&
        (named.mode & 0o7777) === 0o400 &&
        parent.dev === metadata.dev &&
        parent.ino === metadata.ino &&
        parent.uid === metadata.uid &&
        (parent.mode & 0o7777) === 0o700 &&
        (await fs.realpath(file)) === file,
    );
    return bytes;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  } finally {
    await handle?.close();
  }
}

export async function readLinuxReviewedInputs(
  directory,
  candidateSha,
  options,
) {
  if (!directory) return { build: null, release: null };
  requireValue(
    typeof directory === "string" && directory === path.resolve(directory),
  );
  const read = async (name) => {
    const bytes = await readLinuxReviewedFile(
      path.join(directory, name),
      options,
    );
    return bytes === null ? null : JSON.parse(bytes);
  };
  const build = await read("linux-file-build.json"),
    release = await read("linux-release.json");
  return {
    build:
      build === null ? null : normalizeLinuxFileBuildPins(build, candidateSha),
    release:
      release === null
        ? null
        : normalizeLinuxReleaseInputs(release, candidateSha),
  };
}

export const linuxReleaseComponentId = (prefix, target) =>
  `${prefix}-${digest(target).slice(0, 32)}`;

/** Compare every actually used component with separately reviewed bindings. */
export function verifyLinuxReleaseInputs(reviewed, observed) {
  closed(observed, [
    "candidateSha",
    "buildPinsSha256",
    "components",
    "helperAbi",
    "privileges",
    "effectivePolicies",
    "unresolvedAssumptions",
    "policyId",
  ]);
  const components = list(observed.components, 600);
  for (const component of components) {
    closed(component, ["name", "version", "sha256"]);
    requireValue(
      matches(component.name, LABEL) &&
        matches(component.version, VERSION) &&
        matches(component.sha256, HASH),
    );
  }
  requireValue(
    new Set(components.map(({ name }) => name)).size === components.length &&
      EXECUTABLES.every((name) =>
        components.some((entry) => entry.name === name),
      ),
  );
  closed(observed.helperAbi, [
    "architecture",
    "linkage",
    "dynamicDependencies",
    "requiredSyscalls",
  ]);
  requireValue(
    observed.helperAbi.architecture === "x86-64" &&
      observed.helperAbi.linkage === "static" &&
      list(observed.helperAbi.dynamicDependencies, 0).length === 0 &&
      JSON.stringify(list(observed.helperAbi.requiredSyscalls, 5)) ===
        JSON.stringify([
          "openat2",
          "statx",
          "renameat2",
          "close_range",
          "fsync",
        ]),
  );
  closed(observed.privileges, [
    "uid",
    "capabilities",
    "noNewPrivileges",
    "executables",
  ]);
  requireValue(
    Number.isSafeInteger(observed.privileges.uid) &&
      observed.privileges.uid >= 0 &&
      matches(observed.privileges.capabilities, /^[a-f0-9]{16}$/u) &&
      [0, 1].includes(observed.privileges.noNewPrivileges),
  );
  const executablePrivileges = list(observed.privileges.executables, 5);
  requireValue(
    executablePrivileges.length === 5 &&
      new Set(executablePrivileges.map(({ name }) => name)).size === 5,
  );
  for (const entry of executablePrivileges) {
    closed(entry, ["name", "uid", "gid", "mode"]);
    requireValue(
      EXECUTABLES.includes(entry.name) &&
        [entry.uid, entry.gid, entry.mode].every(
          (value) => Number.isSafeInteger(value) && value >= 0,
        ) &&
        entry.mode <= 0o7777,
    );
  }
  for (const policy of list(observed.effectivePolicies, 23)) {
    closed(policy, ["checkId", "id", "sha256"]);
    requireValue(
      CHECK_IDS.includes(policy.checkId) &&
        matches(policy.id, LABEL) &&
        matches(policy.sha256, HASH),
    );
  }
  requireValue(
    observed.policyId === LINUX_RELEASE_POLICY_ID &&
      JSON.stringify(list(observed.unresolvedAssumptions, 4)) ===
        JSON.stringify(SOURCE_FINDING_IDS),
  );
  reviewed = normalizeLinuxReleaseInputs(reviewed, observed.candidateSha);
  requireValue(
    reviewed.buildPinsSha256 === observed.buildPinsSha256 &&
      reviewed.components.length === observed.components.length,
  );
  for (const component of observed.components) {
    const binding = reviewed.components.find(
      ({ name }) => name === component.name,
    );
    requireValue(
      binding &&
        binding.version === component.version &&
        binding.sha256 === component.sha256,
    );
  }
  return {
    schemaVersion: 1,
    candidateSha: observed.candidateSha,
    reviewed,
    observed,
  };
}

/** Read-only release observation. Version commands already ran under the
 * ownership/access/build owners; this audit cannot create pins or close source
 * findings. The composition owner freshly verifies their protected receipts. */
export async function observeLinuxRelease(
  job,
  fixture,
  build,
  pins,
  {
    fs = { lstat, readFile, realpath },
    protect = assertOwnedProcessLauncherProtected,
    ownerUid = () => process.getuid(),
  } = {},
) {
  pins = normalizeLinuxFileBuildPins(pins, job.candidateSha);
  const uid = ownerUid();
  requireValue(Number.isSafeInteger(uid) && uid >= 0);
  requireValue(
    build.candidateSha === job.candidateSha &&
      build.sourceSha256 === pins.sourceSha256 &&
      JSON.stringify(build.inputs) === JSON.stringify(pins.inputs) &&
      build.compiler.version === pins.compilerVersion &&
      build.compiler.sha256 ===
        pins.inputs.find(({ target }) => target === build.compiler.file)
          ?.sha256 &&
      JSON.stringify(build.arguments) ===
        JSON.stringify(LINUX_FILE_BUILD_ARGUMENTS),
  );
  const executablePrivileges = [];
  const read = async (
    file,
    expected,
    maximum = 67108864,
    name = null,
    privateCopy = false,
  ) => {
    requireValue((await fs.realpath(file)) === file);
    if (!privateCopy) protect(file);
    const stat = await fs.lstat(file);
    requireValue(
      stat.isFile() &&
        stat.nlink === 1 &&
        stat.size > 0 &&
        stat.size <= maximum,
    );
    if (privateCopy)
      requireValue(
        stat.uid === uid && [0o400, 0o500].includes(stat.mode & 0o7777),
      );
    const bytes = await fs.readFile(file);
    requireValue(bytes.length === stat.size && digest(bytes) === expected);
    if (name !== null)
      executablePrivileges.push({
        name,
        uid: stat.uid,
        gid: stat.gid,
        mode: stat.mode & 0o7777,
      });
    return bytes;
  };
  const git = job.results
    .flatMap(({ versions }) => versions)
    .find(({ name }) => name === "git");
  const versions = [
    job.versions.find(({ name }) => name === "node"),
    fixture.version,
    git,
    {
      name: "compiler",
      version: build.compiler.version,
      sha256: build.compiler.sha256,
    },
    { name: "file-helper", version: "1", sha256: build.sha256 },
  ];
  requireValue(versions.every(Boolean));
  // The pinned Node runtime exceeds the separate 64-MiB compiler-input budget.
  await read(fixture.executable, versions[0].sha256, 268435456, "node", true);
  await read(fixture.launcher, versions[1].sha256, 67108864, "bubblewrap");
  await read(
    path.join(fixture.directory, "executables", "git"),
    git.sha256,
    67108864,
    "git",
    true,
  );
  const abi = verifyLinuxFileElf(
    await read(build.executable, build.sha256, 4194304, "file-helper", true),
  );
  requireValue(JSON.stringify(abi) === JSON.stringify(build.abi));
  const components = [...versions];
  await read(
    path.join(path.dirname(path.dirname(build.executable)), "file-helper.c"),
    pins.sourceSha256,
    65536,
    null,
    true,
  );
  for (let i = 0; i < pins.inputs.length; i++) {
    const input = pins.inputs[i];
    await read(
      path.join(
        path.dirname(path.dirname(build.executable)),
        "inputs",
        String(i),
      ),
      input.sha256,
      67108864,
      input.target === build.compiler.file ? "compiler" : null,
      true,
    );
    components.push({
      name: linuxReleaseComponentId("build-input", input.target),
      version: "unversioned",
      sha256: input.sha256,
    });
  }
  const libraries = new Map(
    fixture.policy.libraries.map((entry) => [entry.target, entry]),
  );
  for (const result of job.results.filter(
    ({ policy }) => policy?.id === "linux-access-fixture-v1",
  )) {
    const file = path.join(
      fixture.directory,
      "evidence",
      `${result.checkId}-policy.json`,
    );
    const stat = await fs.lstat(file);
    requireValue(
      stat.isFile() && stat.size <= LIMIT && (stat.mode & 0o777) === 0o400,
    );
    const policy = JSON.parse(await fs.readFile(file));
    requireValue(digest(JSON.stringify(policy)) === result.policy.sha256);
    for (const entry of policy.libraries) {
      requireValue(
        !libraries.has(entry.target) ||
          libraries.get(entry.target).sha256 === entry.sha256,
      );
      libraries.set(entry.target, entry);
    }
  }
  for (const library of libraries.values()) {
    await read(library.source, library.sha256);
    components.push({
      name: linuxReleaseComponentId("abi", library.target),
      version: "unversioned",
      sha256: library.sha256,
    });
  }
  const status = await fs.readFile("/proc/self/status", "utf8");
  const capabilities = status.match(/^CapEff:\s+([a-f0-9]{16})$/mu)?.[1];
  const noNewPrivileges = status.match(/^NoNewPrivs:\s+([01])$/mu)?.[1];
  requireValue(capabilities && noNewPrivileges !== undefined);
  return {
    candidateSha: job.candidateSha,
    buildPinsSha256: digest(JSON.stringify(pins)),
    components,
    helperAbi: abi,
    privileges: {
      uid,
      capabilities,
      noNewPrivileges: Number(noNewPrivileges),
      executables: executablePrivileges,
    },
    effectivePolicies: job.results
      .filter(({ policy }) => policy !== null)
      .map(({ checkId, policy }) => ({ checkId, ...policy })),
    unresolvedAssumptions: [...SOURCE_FINDING_IDS],
    policyId: LINUX_RELEASE_POLICY_ID,
  };
}
