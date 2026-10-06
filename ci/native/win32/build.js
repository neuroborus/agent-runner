import { win32 as path } from "node:path";
import { observationDigest, observationObject } from "../index.js";
import {
  hash,
  requireWindows,
  sameWindowsIdentity,
  systemIdentity,
} from "./protocol.js";

export const WINDOWS_HELPER_NAMES = Object.freeze([
  "launcher",
  "argv-fixture",
  "ownership-fixture",
  "access-fixture",
  "file-helper",
  "git-fixture",
  "git-policy",
  "policy-helper",
  "retirement",
  "observer-helper",
  "custody-reader",
  "custody-bridge",
  "build-helper",
]);
export const WINDOWS_BUILD_LIBRARIES = Object.freeze([
  "advapi32.lib",
  "bcrypt.lib",
  "crypt32.lib",
  "wintrust.lib",
  "psapi.lib",
  "ole32.lib",
  "oleaut32.lib",
  "taskschd.lib",
  "uuid.lib",
  "fwpuclnt.lib",
  "xmllite.lib",
  "wevtapi.lib",
]);
export const WINDOWS_BUILD_COMMAND_MS = 60000;
export const WINDOWS_BUILD_TOOLS = Object.freeze([
  {
    name: "compiler",
    path: /^[A-Z]:\\Program Files\\Microsoft Visual Studio\\[0-9]{4}\\(?:Enterprise|Professional|BuildTools)\\VC\\Tools\\MSVC\\[0-9.]+\\bin\\Hostx64\\x64\\cl\.exe$/u,
    args: ["/Bv"],
    versionExitCodes: [2],
  },
  {
    name: "sdk",
    path: /^[A-Z]:\\Program Files \(x86\)\\Windows Kits\\10\\bin\\[0-9.]+\\x64\\rc\.exe$/u,
    args: ["/?"],
    versionExitCodes: [],
  },
]);
export const windowsCompilerArguments = (source, target) => [
  "/nologo",
  "/std:c17",
  "/O2",
  "/W4",
  "/Brepro",
  source,
  `/Fo${target}.obj`,
  `/Fe${target}`,
  "/link",
  "/Brepro",
  "/INCREMENTAL:NO",
  "/DYNAMICBASE",
  "/NXCOMPAT",
  ...WINDOWS_BUILD_LIBRARIES,
];

/** Only reviewed fixed MSVC/SDK vectors can reach the native entry. */
export function windowsBuildOperation(request, manifest, output) {
  observationObject(request, [
    "candidateSha",
    "platform",
    "toolSha256",
    "file",
    "args",
    "cwd",
    "env",
    "deadlineMs",
  ]);
  const tool = manifest.tools.find((entry) => entry.path === request.file);
  requireWindows(
    WINDOWS_BUILD_TOOLS.some(
      (entry) => entry.name === tool?.name && entry.path.test(request.file),
    ),
  );
  requireWindows(
    request.platform === "win32" &&
      request.candidateSha === manifest.candidateSha &&
      tool?.sha256 === request.toolSha256 &&
      request.cwd === output &&
      observationDigest(request.env) ===
        observationDigest({
          CI: "true",
          GITHUB_ACTIONS: "true",
          LANG: "C",
          ...manifest.environment,
        }) &&
      Number.isSafeInteger(request.deadlineMs) &&
      request.deadlineMs > 0 &&
      request.deadlineMs <= WINDOWS_BUILD_COMMAND_MS,
  );
  const equal = (args) =>
    observationDigest(args) === observationDigest(request.args);
  if (tool.name === "compiler" && equal(["/Bv"])) {
    requireWindows(request.deadlineMs <= 30000);
    return { mode: "compiler-version", tool };
  }
  if (tool.name === "sdk" && equal(["/?"])) {
    requireWindows(request.deadlineMs <= 30000);
    return { mode: "sdk-version", tool };
  }
  requireWindows(tool.name === "compiler");
  for (const helper of manifest.helpers) {
    requireWindows(WINDOWS_HELPER_NAMES.includes(helper.name));
    const source = manifest.windowsPreparation.sources.find(
        (entry) =>
          entry.name === helper.name + ".c" &&
          entry.sha256 === helper.sourceSha256,
      ),
      target = path.join(output, helper.name + ".exe");
    if (
      source &&
      equal(
        windowsCompilerArguments(
          path.join(manifest.windowsPreparation.sourceDirectory, source.name),
          target,
        ),
      )
    )
      return {
        mode: "compile",
        tool,
        helper,
        target,
        source: {
          path: path.join(
            manifest.windowsPreparation.sourceDirectory,
            source.name,
          ),
          sha256: source.sha256,
        },
      };
  }
  throw new Error("Unapproved Windows build vector");
}

/** The System reader parks the sealed compiler entry and independently joins
 * the created worker's image and creation identity before either release. */
export async function runWindowsBuildCommand(
  request,
  operation,
  entry,
  reader,
  persist,
  { signal } = {},
) {
  requireWindows(!signal?.aborted);
  const id = observationDigest(request),
    channel = await reader.openBuild(request, operation, entry);
  let worker;
  try {
    const frame = await channel.receive();
    observationObject(frame, ["worker"]);
    worker = systemIdentity(frame.worker);
    requireWindows(worker.pid !== channel.identity.pid);
    const held = await reader.retainProcess(worker),
      actual = await reader.processImage(held.slot, entry.tool);
    requireWindows(
      sameWindowsIdentity(held.observation.identity, worker) &&
        actual.sha256 === request.toolSha256 &&
        actual.signatureSha256 === entry.toolSignatureSha256 &&
        sameWindowsIdentity(actual.identity, worker),
    );
    await persist({
      phase: "worker-admitted",
      requestSha256: id,
      helper: channel.identity,
      worker,
    });
    requireWindows(!signal?.aborted);
    await channel.send("R");
    const chunks = { stdout: [], stderr: [] };
    let total = 0,
      result;
    for (let frames = 0; frames < 1024; frames++) {
      const value = await channel.receive();
      if (Object.hasOwn(value, "exitCode")) {
        result = value;
        break;
      }
      observationObject(value, ["stream", "hex"]);
      requireWindows(
        ["stdout", "stderr"].includes(value.stream) &&
          typeof value.hex === "string" &&
          /^(?:[a-f0-9]{2}){1,1024}$/u.test(value.hex),
      );
      const bytes = Buffer.from(value.hex, "hex");
      total += bytes.length;
      requireWindows(total <= 65536);
      chunks[value.stream].push(bytes);
    }
    observationObject(result, ["exitCode", "signal", "members"]);
    requireWindows(
      Number.isSafeInteger(result.exitCode) &&
        result.exitCode >= 0 &&
        result.exitCode <= 255 &&
        result.signal === null &&
        result.members === 0,
    );
    const retiredWorker = await reader.process(held.slot);
    requireWindows(
      retiredWorker.retired === true &&
        sameWindowsIdentity(retiredWorker.identity, worker),
    );
    await persist({
      phase: "publication-possible",
      requestSha256: id,
      helper: channel.identity,
      worker,
      exitCode: result.exitCode,
    });
    requireWindows(!signal?.aborted);
    await channel.send("S");
    const settlement = await channel.close();
    requireWindows(
      settlement.status === "RETIRED" &&
        settlement.independent === true &&
        settlement.emergencyCleanup === false &&
        hash(settlement.nativeEventSha256),
    );
    const decode = (name) =>
      new TextDecoder("utf-8", { fatal: true }).decode(
        Buffer.concat(chunks[name]),
      );
    const stdout = decode("stdout"),
      stderr = decode("stderr");
    requireWindows(!signal?.aborted);
    return {
      exitCode: result.exitCode,
      signal: null,
      stdout,
      stderr,
      timedOut: false,
      independent: true,
      identity: worker,
      helperIdentity: channel.identity,
      requestSha256: id,
      toolSha256: request.toolSha256,
      nativeEventSha256: observationDigest({
        actual,
        retiredWorker,
        result,
        settlement,
      }),
      settlement,
    };
  } catch (error) {
    try {
      await persist({
        phase: "uncertain",
        requestSha256: id,
        helper: channel.identity,
        worker: worker ?? null,
      });
    } catch {
      /* The existing possible intent survives; preserve the first failure. */
    }
    throw error;
  }
}
