import { constants } from "node:fs";
import { access, lstat, realpath, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import {
  absolutePath,
  isWithin,
  payloadDirectoryId,
  resolveRuntimeRoot,
  RuntimePayloadError,
} from "./contract.js";
import { readRegular } from "./files.js";
import { inspectPayload, materializePayload } from "./payload.js";

const ROOT = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const CONTEXT = Symbol.for("agent-runner.runtime-context");
export const RUNTIME_PAYLOAD_ENV = "AGENT_RUNNER_PARENT_PAYLOAD";
export const getRuntimeContext = () => globalThis[CONTEXT] ?? null;

async function nodeIdentity() {
  if (process.versions.node.split(".")[0] !== "24")
    throw new RuntimePayloadError("Agent Runner requires Node.js >=24 <25.");
  const nodePath = await realpath(process.execPath);
  const metadata = await stat(nodePath, { bigint: true });
  if (process.platform === "linux") {
    const running = await stat("/proc/self/exe", { bigint: true });
    if (running.dev !== metadata.dev || running.ino !== metadata.ino)
      throw new RuntimePayloadError(
        "The running Node executable was replaced.",
      );
  }
  const identity = Object.freeze(
    Object.fromEntries(
      ["dev", "ino", "size", "mtimeNs", "ctimeNs"].map((key) => [
        key,
        String(metadata[key]),
      ]),
    ),
  );
  return { nodePath, nodeVersion: process.version, nodeIdentity: identity };
}

async function isCheckout(rootPath) {
  try {
    // A release manifest always selects installed verification, even beside Git.
    await lstat(join(rootPath, "release-manifest.json"));
    return false;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  try {
    const metadata = JSON.parse(
      (
        await readRegular(join(rootPath, "package.json"), 1024 * 1024)
      ).bytes.toString(),
    );
    const git = await lstat(join(rootPath, ".git"));
    return (
      Array.isArray(metadata.workspaces) && (git.isFile() || git.isDirectory())
    );
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

// Read-only update inspection never prepares storage or activates a payload.
export async function inspectRuntimeInstallation({
  context = getRuntimeContext(),
  rootPath = context?.rootPath ?? ROOT,
} = {}) {
  absolutePath(rootPath);
  if ((await realpath(rootPath)) !== rootPath)
    throw new RuntimePayloadError("Application root is aliased.");
  if (context?.mode !== "pinned") {
    if (!(await isCheckout(rootPath)))
      throw new RuntimePayloadError(
        "Installed inspection requires a pinned runtime.",
      );
    const metadata = JSON.parse(
      (
        await readRegular(join(rootPath, "package.json"), 1024 * 1024)
      ).bytes.toString(),
    );
    return {
      developmentManaged: true,
      rootPath,
      installationPath: rootPath,
      runningMetadata: metadata,
      installedMetadata: metadata,
      nodeVersion: process.version,
      canWriteInstallation: false,
      restartRequired: false,
    };
  }
  if (context.rootPath !== rootPath)
    throw new RuntimePayloadError("Inspection is outside the running payload.");
  const running = await inspectPayload(rootPath, {
    immutable: true,
    published: true,
  });
  const node = await nodeIdentity();
  if (
    running.id !== context.payloadId ||
    node.nodePath !== context.nodePath ||
    node.nodeVersion !== context.nodeVersion ||
    !isDeepStrictEqual(node.nodeIdentity, context.nodeIdentity)
  )
    throw new RuntimePayloadError("Running payload or Node identity changed.");
  const installed =
    context.installationPath === rootPath
      ? running
      : await inspectPayload(context.installationPath);
  let canWriteInstallation = true;
  try {
    await access(context.installationPath, constants.W_OK);
  } catch (error) {
    if (!["EACCES", "EPERM", "EROFS"].includes(error.code)) throw error;
    canWriteInstallation = false;
  }
  return {
    developmentManaged: false,
    rootPath,
    installationPath: context.installationPath,
    runningMetadata: JSON.parse(
      running.captured.get("package.json").bytes.toString(),
    ),
    installedMetadata: JSON.parse(
      installed.captured.get("package.json").bytes.toString(),
    ),
    nodeVersion: node.nodeVersion,
    canWriteInstallation,
    restartRequired: installed.id !== running.id,
  };
}

function expectedContext(environment) {
  const text = environment[RUNTIME_PAYLOAD_ENV];
  if (text === undefined) return null;
  if (typeof text !== "string" || Buffer.byteLength(text) > 4096)
    throw new RuntimePayloadError("Invalid detached payload identity.");
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new RuntimePayloadError("Invalid detached payload identity.");
  }
  if (
    !value ||
    Object.keys(value).sort().join() !==
      "executablePath,installationPath,mode,nodeIdentity,nodePath,nodeVersion,payloadId,rootPath" ||
    value.mode !== "pinned" ||
    !/^[a-f0-9]{64}$/u.test(value.payloadId)
  )
    throw new RuntimePayloadError("Invalid detached payload identity.");
  for (const key of [
    "rootPath",
    "installationPath",
    "executablePath",
    "nodePath",
  ])
    absolutePath(value[key]);
  return value;
}

// This is the only pre-application preparation path. It never resolves settings
// or run state, installs packages, selects an update, or activates a controller.
export async function prepareRuntime({
  rootPath = ROOT,
  storageRoot,
  environment = process.env,
  beforeSeal,
  beforePublish,
} = {}) {
  absolutePath(rootPath);
  if ((await realpath(rootPath)) !== rootPath)
    throw new RuntimePayloadError("Application root is aliased.");
  const expected = expectedContext(environment);
  const node = await nodeIdentity();
  if (!expected && (await isCheckout(rootPath)))
    return Object.freeze({
      mode: "development",
      rootPath,
      installationPath: rootPath,
      executablePath: join(rootPath, "bin/agent-run.js"),
      payloadId: null,
      ...node,
    });
  const locationId =
    basename(dirname(rootPath)) === "payloads"
      ? payloadDirectoryId(basename(rootPath))
      : null;
  const source = await inspectPayload(rootPath, {
    immutable: expected !== null || locationId !== null,
    published: locationId !== null,
  });
  const stored = locationId === source.id;
  if (locationId !== null && !stored)
    throw new RuntimePayloadError(
      "Stored payload location disagrees with its identity.",
    );
  if (
    expected &&
    (!stored ||
      expected.rootPath !== rootPath ||
      expected.executablePath !== join(rootPath, "bin/agent-run.js") ||
      expected.payloadId !== source.id ||
      expected.nodePath !== node.nodePath ||
      expected.nodeVersion !== node.nodeVersion ||
      !isDeepStrictEqual(expected.nodeIdentity, node.nodeIdentity))
  )
    throw new RuntimePayloadError(
      "Detached continuation payload or Node identity changed.",
    );
  if (stored)
    return Object.freeze({
      mode: "pinned",
      rootPath,
      installationPath: expected?.installationPath ?? rootPath,
      executablePath: join(rootPath, "bin/agent-run.js"),
      payloadId: source.id,
      ...node,
    });
  const storage = absolutePath(
    storageRoot ?? resolveRuntimeRoot({ env: environment }),
  );
  if (
    isWithin(rootPath, storage) ||
    isWithin(storage, rootPath) ||
    storage
      .split(/[\\/]/u)
      .some((part) => [".git", ".agents", ".codex", ".claude"].includes(part))
  )
    throw new RuntimePayloadError(
      "Runtime storage overlaps application or control storage.",
    );
  const pinned = await materializePayload(source, storage, {
    beforeSeal,
    beforePublish,
  });
  return Object.freeze({
    mode: "pinned",
    rootPath: pinned,
    installationPath: rootPath,
    executablePath: join(pinned, "bin/agent-run.js"),
    payloadId: source.id,
    ...node,
  });
}

export async function prepareRuntimeLaunch(
  executablePath = join(ROOT, "bin/agent-run.js"),
) {
  const context = getRuntimeContext();
  if (context?.mode === "pinned") {
    if (executablePath !== context.executablePath)
      throw new RuntimePayloadError(
        "Detached executable is outside the pinned payload.",
      );
    const payload = await inspectPayload(context.rootPath, {
      immutable: true,
      published: true,
    });
    const node = await nodeIdentity();
    if (
      payload.id !== context.payloadId ||
      node.nodePath !== context.nodePath ||
      node.nodeVersion !== context.nodeVersion ||
      !isDeepStrictEqual(node.nodeIdentity, context.nodeIdentity)
    )
      throw new RuntimePayloadError("Pinned continuation identity changed.");
    return {
      executablePath: context.executablePath,
      nodePath: context.nodePath,
      environment: { [RUNTIME_PAYLOAD_ENV]: JSON.stringify(context) },
    };
  }
  if (
    executablePath === join(ROOT, "bin/agent-run.js") &&
    !(await isCheckout(ROOT))
  )
    throw new RuntimePayloadError(
      "Installed applications must start through the payload bootstrap.",
    );
  return { executablePath, nodePath: process.execPath, environment: {} };
}

export async function startApplication() {
  let context;
  try {
    if (getRuntimeContext() !== null)
      throw new RuntimePayloadError("Runtime selection is already frozen.");
    context = await prepareRuntime();
  } catch {
    process.stderr.write(
      "Application payload could not be verified; no command was started.\n",
    );
    return 1;
  }
  delete process.env[RUNTIME_PAYLOAD_ENV];
  Object.defineProperty(globalThis, CONTEXT, { value: context });
  const { main } = await import(
    pathToFileURL(join(context.rootPath, "src/index.js")).href
  );
  return await main();
}
