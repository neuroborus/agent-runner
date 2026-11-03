import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve, sep, win32 } from "node:path";

export class RuntimePayloadError extends Error {
  constructor(
    message = "Application payload verification failed.",
    options = {},
  ) {
    super(message, options);
    this.name = "RuntimePayloadError";
    this.code = "ERR_RUNTIME_PAYLOAD";
  }
}

export const digest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
export const isWithin = (parent, path) => {
  const child = relative(parent, path);
  return (
    child === "" ||
    (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`))
  );
};

export function absolutePath(path) {
  if (
    typeof path !== "string" ||
    !isAbsolute(path) ||
    resolve(path) !== path ||
    /[\p{Cc}\p{Zl}\p{Zp}]/u.test(path)
  )
    throw new RuntimePayloadError(
      "Runtime locations must be canonical absolute paths.",
    );
  return path;
}

export function resolveRuntimeRoot({
  env = process.env,
  platform = process.platform,
  homeDirectory = env.HOME ?? homedir(),
} = {}) {
  if (platform === "win32") {
    if (
      typeof env.LOCALAPPDATA !== "string" ||
      !win32.isAbsolute(env.LOCALAPPDATA) ||
      win32.parse(env.LOCALAPPDATA).root.length < 2 ||
      /[\p{Cc}]/u.test(env.LOCALAPPDATA)
    )
      throw new RuntimePayloadError(
        "A safe absolute local application directory is required.",
      );
    return win32.join(env.LOCALAPPDATA, "agent-runner", "runtime");
  }
  if (platform === "darwin")
    return join(
      absolutePath(homeDirectory),
      "Library",
      "Application Support",
      "agent-runner",
      "runtime",
    );
  if (platform !== "linux")
    throw new RuntimePayloadError(
      "Runtime storage is unsupported on this platform.",
    );
  const root =
    env.XDG_DATA_HOME && isAbsolute(env.XDG_DATA_HOME)
      ? absolutePath(env.XDG_DATA_HOME)
      : join(absolutePath(homeDirectory), ".local", "share");
  return join(root, "agent-runner", "runtime");
}

const HASH = /^[a-f0-9]{64}$/u;
export const payloadDirectoryId = (name) =>
  /^\.payload-([a-f0-9]{64})-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.exec(
    name,
  )?.[1] ?? null;

export function parseManifest(bytes) {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new RuntimePayloadError("Invalid application manifest.");
  }
  if (
    !manifest ||
    Object.keys(manifest).sort().join() !==
      "dependencies,files,lockSha256,name,schemaVersion,version" ||
    manifest.schemaVersion !== 1 ||
    typeof manifest.name !== "string" ||
    typeof manifest.version !== "string" ||
    !HASH.test(manifest.lockSha256) ||
    !Array.isArray(manifest.files) ||
    manifest.files.length > 10_000 ||
    !Array.isArray(manifest.dependencies)
  )
    throw new RuntimePayloadError("Invalid application manifest.");
  const files = new Map();
  let total = 0;
  for (const entry of manifest.files) {
    if (
      !entry ||
      Object.keys(entry).sort().join() !== "mode,path,sha256,size" ||
      typeof entry.path !== "string" ||
      entry.path.includes("\\") ||
      /\p{Cc}/u.test(entry.path) ||
      entry.path.split("/").some((part) => !part || part.startsWith(".")) ||
      files.has(entry.path) ||
      ![0o644, 0o755].includes(entry.mode) ||
      !Number.isSafeInteger(entry.size) ||
      entry.size < 0 ||
      !HASH.test(entry.sha256)
    )
      throw new RuntimePayloadError("Invalid application file manifest.");
    total += entry.size;
    if (total > 64 * 1024 * 1024)
      throw new RuntimePayloadError("Application payload is too large.");
    files.set(entry.path, entry);
  }
  for (const required of [
    "package.json",
    "bin/agent-run.js",
    "src/index.js",
    "src/runtime/index.js",
    "src/runtime/bootstrap.js",
    "src/runtime/admission.js",
    "src/runtime/contract.js",
    "src/runtime/files.js",
    "src/runtime/payload.js",
    "docs/OPERATOR_GUIDE.md",
  ])
    if (!files.has(required))
      throw new RuntimePayloadError("Application manifest is incomplete.");
  if (files.has("release-manifest.json"))
    throw new RuntimePayloadError(
      "Application manifest cannot include itself.",
    );
  const dependencies = new Set();
  for (const entry of manifest.dependencies) {
    if (
      !entry ||
      Object.keys(entry).sort().join() !== "integrity,name,path,version" ||
      typeof entry.path !== "string" ||
      !entry.path.startsWith("node_modules/") ||
      !files.has(`${entry.path}/package.json`) ||
      dependencies.has(entry.path) ||
      typeof entry.name !== "string" ||
      typeof entry.version !== "string" ||
      !(
        entry.integrity === null ||
        (typeof entry.integrity === "string" && entry.integrity.length > 0)
      )
    )
      throw new RuntimePayloadError("Invalid application dependency manifest.");
    dependencies.add(entry.path);
  }
  return { manifest, files, id: digest(bytes) };
}
