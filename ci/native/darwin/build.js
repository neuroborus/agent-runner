import { spawn } from "node:child_process";
import path from "node:path";
import { observationObject, observationDigest } from "../index.js";
import { darwinCustodyChannel } from "./channel.js";
import {
  normalizeDarwinIdentity,
  sameDarwinIdentity,
  requireDarwin,
} from "./protocol.js";

export const DARWIN_HELPER_NAMES = Object.freeze([
  "launcher",
  "argv-fixture",
  "ownership-fixture",
  "access-fixture",
  "file-helper",
  "git-executor",
  "git-fixture",
  "observer-helper",
  "custody-reader",
  "build-helper",
]);
// Two version queries and compile/sign for each fixed helper, plus cleanup.
export const DARWIN_BUILD_CUSTODY_MS =
  120000 + (2 + DARWIN_HELPER_NAMES.length * 2) * 60000;
export const darwinCompilerArguments = (source, target, env) => [
  "-std=c17",
  "-O2",
  "-Wall",
  "-Wextra",
  "-arch",
  "x86_64",
  "-isysroot",
  env.SDKROOT,
  source,
  "-o",
  target,
  "-Wl,-no_uuid",
  "-fblocks",
  "-framework",
  "Security",
  "-framework",
  "CoreFoundation",
  "-lbsm",
  "-lsandbox",
];

/** Only these vectors can cross the compiler entry. Source/output approval is
 * read before exec; a hash of a generated command is not that approval. */
export function darwinBuildOperation(request, manifest, output) {
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
  requireDarwin(
    request.platform === "darwin" &&
      request.candidateSha === manifest.candidateSha &&
      tool?.sha256 === request.toolSha256 &&
      request.file ===
        {
          compiler: "/usr/bin/clang",
          sdk: "/usr/bin/xcrun",
          signer: "/usr/bin/codesign",
        }[tool.name] &&
      request.cwd === output &&
      observationDigest(request.env) ===
        observationDigest({
          CI: "true",
          GITHUB_ACTIONS: "true",
          LANG: "C",
          SDKROOT: manifest.environment.SDKROOT,
        }) &&
      Number.isSafeInteger(request.deadlineMs) &&
      request.deadlineMs > 0 &&
      request.deadlineMs <= 30000,
  );
  const equal = (args) =>
    observationDigest(args) === observationDigest(request.args);
  if (tool.name === "compiler" && equal(["--version"]))
    return { mode: "compiler-version", tool };
  if (tool.name === "sdk" && equal(["--show-sdk-build-version"]))
    return { mode: "sdk-version", tool };
  for (const helper of manifest.helpers) {
    requireDarwin(DARWIN_HELPER_NAMES.includes(helper.name));
    const target = path.join(output, helper.name),
      source = manifest.darwinPreparation.sources.find(
        (entry) =>
          entry.name === helper.name + ".c" &&
          entry.sha256 === helper.sourceSha256,
      );
    const sourceInput = source && {
      path: path.join(manifest.darwinPreparation.sourceDirectory, source.name),
      sha256: source.sha256,
    };
    if (
      tool.name === "compiler" &&
      sourceInput &&
      equal(
        darwinCompilerArguments(sourceInput.path, target, manifest.environment),
      )
    )
      return { mode: "compile", tool, source: sourceInput, target, helper };
    if (
      tool.name === "signer" &&
      equal(["--force", "--sign", "-", "--timestamp=none", target])
    )
      return { mode: "sign", tool, target, helper };
  }
  throw new Error("Unapproved Darwin build vector");
}

function transport(entry, args, deadlineMs) {
  requireDarwin(
    process.platform === "darwin" &&
      process.arch === "x64" &&
      process.env.CI === "true" &&
      process.env.GITHUB_ACTIONS === "true" &&
      process.env.ImageOS === "macos15",
  );
  const child = spawn(
    entry.tools.elevation.path,
    [
      "-n",
      "--",
      entry.tools.environment.path,
      "-i",
      "CI=true",
      "GITHUB_ACTIONS=true",
      entry.helper.path,
      ...args,
    ],
    {
      cwd: path.dirname(entry.helper.path),
      env: { PATH: "/nonexistent" },
      stdio: ["pipe", "pipe", "ignore"],
    },
  );
  return {
    channel: darwinCustodyChannel(child, { deadlineMs }),
  };
}
function commandResult(value) {
  observationObject(value, ["exitCode", "signal", "stdoutHex", "stderrHex"]);
  requireDarwin(
    Number.isInteger(value.exitCode) &&
      value.exitCode >= 0 &&
      value.exitCode <= 255 &&
      value.signal === null &&
      [value.stdoutHex, value.stderrHex].every(
        (bytes) =>
          typeof bytes === "string" && /^(?:[a-f0-9]{2})*$/u.test(bytes),
      ) &&
      value.stdoutHex.length + value.stderrHex.length <= 131072,
  );
  const decode = (bytes) =>
    new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(bytes, "hex"));
  return {
    exitCode: value.exitCode,
    signal: value.signal,
    stdout: decode(value.stdoutHex),
    stderr: decode(value.stderrHex),
  };
}

/** Private native helper parks an already-execed tool, including version
 * queries. The separately admitted custody reader verifies its actual image. */
export async function runDarwinBuildCommand(
  request,
  operation,
  entry,
  reader,
  persist,
  { signal, open = transport } = {},
) {
  requireDarwin(!signal?.aborted);
  const targetSha256 =
    operation.mode === "sign"
      ? entry.targetSha256
      : (operation.source?.sha256 ?? "-");
  const args = [
    operation.mode,
    request.file,
    request.toolSha256,
    entry.toolCdhash,
    request.cwd,
    request.env.SDKROOT,
    operation.source?.path ?? "-",
    targetSha256,
    operation.target ?? "-",
    String(Math.max(1, Math.floor(request.deadlineMs / 1000))),
  ];
  const { channel } = await open(entry, args, request.deadlineMs),
    id = observationDigest(request);
  let helper,
    worker,
    firstFailure,
    complete = false;
  const abort = () => channel.close();
  signal?.addEventListener("abort", abort, { once: true });
  try {
    const announced = await channel.receive();
    observationObject(announced, ["helper"]);
    helper = normalizeDarwinIdentity(announced.helper);
    const actualHelper = await reader.helper(helper);
    requireDarwin(
      helper.asid > 0 &&
        actualHelper.sha256 === entry.helper.sha256 &&
        actualHelper.signature.cdhash === entry.helper.cdhash &&
        !signal?.aborted,
    );
    if (entry.directoryIdentity) {
      const [dev, , , ino] = entry.directoryIdentity.split(":");
      requireDarwin(
        actualHelper.directories.filter(
          (directory) =>
            directory.fd === 3 &&
            directory.dev === dev &&
            directory.ino === ino &&
            directory.uid === 0 &&
            directory.gid === 0 &&
            directory.mode === 0o700,
        ).length === 1,
      );
    }
    await persist({ phase: "helper", requestSha256: id, helper });
    const custody = await reader.rootDomain(helper);
    requireDarwin(
      custody.complete === true &&
        custody.independent === true &&
        custody.members.length === 1 &&
        sameDarwinIdentity(custody.members[0], helper),
    );
    await channel.send("P");
    const parked = await channel.receive();
    observationObject(parked, ["worker"]);
    worker = normalizeDarwinIdentity(parked.worker);
    const actualWorker = await reader.helper(worker);
    requireDarwin(
      helper.pid !== worker.pid &&
        worker.asid === helper.asid &&
        sameDarwinIdentity(actualWorker.identity, worker) &&
        actualWorker.sha256 === request.toolSha256 &&
        actualWorker.signature.cdhash === entry.toolCdhash &&
        !signal?.aborted,
    );
    await persist({ phase: "worker", requestSha256: id, helper, worker });
    requireDarwin(!signal?.aborted);
    await channel.send("R");
    const result = commandResult(await channel.receive());
    const workerSettlement = await reader.retired(worker);
    requireDarwin(
      workerSettlement.status === "RETIRED" &&
        workerSettlement.independent === true &&
        workerSettlement.emergencyCleanup === false,
    );
    const domain = await reader.rootDomain(helper);
    requireDarwin(
      domain.complete === true &&
        domain.independent === true &&
        domain.members.length === 1 &&
        sameDarwinIdentity(domain.members[0], helper),
    );
    if (result.exitCode === 0)
      await persist({
        phase: "publication-possible",
        requestSha256: id,
        output: request.cwd,
        target: operation.target ?? null,
        helper,
        worker,
      });
    requireDarwin(!signal?.aborted);
    await channel.send("S");
    const exit = await channel.completion,
      helperSettlement = await reader.retired(helper);
    requireDarwin(
      exit.code === 0 &&
        exit.signal === null &&
        !signal?.aborted &&
        helperSettlement.status === "RETIRED" &&
        helperSettlement.independent === true &&
        helperSettlement.emergencyCleanup === false,
    );
    const finalDomain = await reader.rootDomain(helper);
    requireDarwin(
      finalDomain.complete === true &&
        finalDomain.independent === true &&
        finalDomain.members.length === 0,
    );
    complete = true;
    return {
      ...result,
      timedOut: false,
      independent: true,
      identity: worker,
      helperIdentity: helper,
      requestSha256: id,
      toolSha256: request.toolSha256,
      nativeEventSha256: observationDigest({
        actualHelper,
        actualWorker,
        result,
        workerSettlement,
        helperSettlement,
        domain,
        finalDomain,
      }),
      settlement: {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
      },
    };
  } catch (cause) {
    firstFailure = cause;
    throw cause;
  } finally {
    signal?.removeEventListener("abort", abort);
    channel.close();
    if (!complete) {
      try {
        await persist({
          phase: "uncertain",
          requestSha256: id,
          helper: helper ?? null,
          worker: worker ?? null,
        });
      } catch (cause) {
        if (!firstFailure) throw cause;
      }
    }
  }
}
