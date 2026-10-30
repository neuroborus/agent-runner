import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { selectTestFiles } from "../../scripts/index.js";

const HASH = /^[a-f0-9]{64}$/u;
const LAUNCHER_PATHS = [
  "scripts/format.js",
  "scripts/index.js",
  "scripts/test.js",
  "scripts/test-selection.js",
  "scripts/test-storage.js",
];
// Freeze the installed launcher's contract when this Runner process loads it.
// A self-hosted execution must settle and restart before using changed code.
const LAUNCHER_SOURCES = LAUNCHER_PATHS.map((path) =>
  readFileSync(new URL(`../../${path}`, import.meta.url), "utf8"),
);
const digest = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const LAUNCHER_FINGERPRINT = digest(LAUNCHER_SOURCES);
const INVENTORY_FIELDS = [
  "schemaVersion",
  "commandIdentity",
  "contentFingerprint",
  "launcherFingerprint",
  "files",
  "fingerprint",
];

export function isRepositoryCheck(command) {
  return (
    command?.alias === "agent-runner-check" &&
    command.command === "npm run check" &&
    command.executable === "npm" &&
    Array.isArray(command.arguments) &&
    command.arguments.length === 2 &&
    command.arguments[0] === "run" &&
    command.arguments[1] === "check"
  );
}

export function isCanonicalTestFile(path) {
  return (
    typeof path === "string" &&
    Buffer.byteLength(path) <= 256 &&
    /^(?:test\/|pipelines\/[A-Za-z0-9._-]+\/test\/|packages\/[A-Za-z0-9._-]+\/test\/)[A-Za-z0-9._/-]+\.test\.js$/u.test(
      path,
    ) &&
    !path
      .split("/")
      .some((part) => part === "" || part === "." || part === "..")
  );
}

// Validate saved membership against its original bindings, never a later tree.
export function normalizeTestInventory(
  value,
  { commandIdentity, contentFingerprint },
) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== INVENTORY_FIELDS.length ||
    INVENTORY_FIELDS.some((field) => !Object.hasOwn(value, field)) ||
    value.schemaVersion !== 1 ||
    value.commandIdentity !== commandIdentity ||
    value.contentFingerprint !== contentFingerprint ||
    ![
      value.commandIdentity,
      value.contentFingerprint,
      value.launcherFingerprint,
      value.fingerprint,
    ].every((entry) => HASH.test(entry)) ||
    !Array.isArray(value.files) ||
    value.files.length === 0 ||
    value.files.length > 1024 ||
    [...value.files].some(
      (path, index) =>
        !isCanonicalTestFile(path) ||
        path.endsWith(".slow.test.js") ||
        (index > 0 && value.files[index - 1] >= path),
    )
  ) {
    throw new TypeError("Invalid bound trusted test inventory.");
  }
  const { fingerprint } = value;
  const bound = {
    schemaVersion: value.schemaVersion,
    commandIdentity: value.commandIdentity,
    contentFingerprint: value.contentFingerprint,
    launcherFingerprint: value.launcherFingerprint,
    files: value.files,
  };
  if (fingerprint !== digest(bound))
    throw new TypeError("Invalid trusted test inventory binding.");
  return Object.freeze({
    ...bound,
    files: Object.freeze([...value.files]),
    fingerprint,
  });
}

export async function inspectTestInventory({
  command,
  contentFingerprint,
  projectPath,
  git,
}) {
  if (!isRepositoryCheck(command) || typeof git.inspectPath !== "function")
    return null;
  try {
    const sources = await Promise.all(
      LAUNCHER_PATHS.map((path) => readFile(join(projectPath, path), "utf8")),
    );
    if (sources.some((source, index) => source !== LAUNCHER_SOURCES[index]))
      return null;
    const metadata = JSON.parse(
      await readFile(join(projectPath, "package.json"), "utf8"),
    );
    if (
      metadata.scripts?.check !==
        "npm run format:check && npm test && node bin/agent-run.js --help" ||
      metadata.scripts?.test !== "node scripts/test.js" ||
      metadata.scripts?.["format:check"] !== "node scripts/format.js --check"
    )
      return null;
    const { files } = selectTestFiles([], { cwd: projectPath });
    if (files.length > 1024 || files.some((path) => !isCanonicalTestFile(path)))
      return null;
    for (const path of ["package.json", ...LAUNCHER_PATHS, ...files]) {
      const inspected = await git.inspectPath({ projectPath, path });
      if (
        !inspected.exists ||
        inspected.kind !== "file" ||
        (inspected.ignored === true && !inspected.tracked) ||
        inspected.relativePath !== path
      )
        return null;
    }
    const bound = {
      schemaVersion: 1,
      commandIdentity: command.identity,
      contentFingerprint,
      launcherFingerprint: LAUNCHER_FINGERPRINT,
      files,
    };
    return normalizeTestInventory(
      { ...bound, fingerprint: digest(bound) },
      bound,
    );
  } catch {
    // Unsupported launchers/inventories retain finite-label diagnostics only.
    return null;
  }
}
