import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { PassThrough } from "node:stream";
import { createInterface } from "node:readline";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rmdir,
  unlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { observationDigest } from "../index.js";
import { feasibilityFailureCause } from "../feasibility/index.js";
import {
  digest,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
} from "./protocol.js";
import { createWindowsAuditDecoder } from "./audit-decoder.js";
import { windowsCompilerArguments } from "./build.js";
import {
  windowsFeasibilityImports,
  windowsFeasibilityCause,
} from "./feasibility.js";

const execute = promisify(execFile),
  SOURCE = fileURLToPath(new URL("./", import.meta.url));
const need = (v) => {
  if (!v) throw new Error("Incomplete Windows command custody");
};
const regular = async (file) => {
  const st = await lstat(file);
  need(
    st.isFile() &&
      !st.isSymbolicLink() &&
      st.size > 0 &&
      st.size <= 134217728 &&
      (await realpath(file)) === file,
  );
  return readFile(file);
};
/** The finite file experiment consumes typed Security fields. Localized access
 * lists are not evidence and can contain line breaks. Full reader rules stay
 * unchanged; the native XmlLite parser still bounds/validates the entire XML. */
export function windowsCommandAuditRead(native) {
  need(
    ["event", "bookmark"].includes(native?.kind) &&
      Array.isArray(native.fields) &&
      native.fields.length <= 96,
  );
  if (native.kind === "bookmark") return { native, logonId: null };
  const selected = new Set([
    "Provider",
    "Channel",
    "EventID",
    "Version",
    "Keywords",
    "TimeCreated",
    "EventRecordID",
    "ObjectType",
    "ProcessId",
    "ObjectName",
    "SubjectUserSid",
    "AccessMask",
  ]);
  const fields = [],
    names = new Set();
  let logonId;
  for (const field of native.fields) {
    need(
      /^(?:[a-f0-9]{4}){1,127}$/u.test(field.nameHex) &&
        /^(?:[a-f0-9]{4}){0,4095}$/u.test(field.hex),
    );
    const name = Buffer.from(field.nameHex, "hex").toString("utf16le");
    need(!names.has(name));
    names.add(name);
    if (selected.has(name)) fields.push(field);
    if (name === "SubjectLogonId") {
      const value = Buffer.from(field.hex, "hex").toString("utf16le");
      need(/^0x[a-fA-F0-9]{1,16}$/u.test(value));
      logonId = BigInt(value).toString(16).padStart(16, "0");
    }
  }
  // Loss events intentionally reach the strict decoder even without a subject.
  return { native: { kind: "event", fields }, logonId };
}
/** Interface/configuration claims cannot admit a broker. Join independent held
 * token/object reads to the actual decoder's fresh native success delivery. */
export function windowsCommandBrokerCoverage(value, observation) {
  const { before, after, start, end, events } = observation,
    broker = normalizeWindowsIdentity(value.observer),
    original = value.original.files[3];
  need(
    sameWindowsIdentity(broker, before.identity) &&
      sameWindowsIdentity(broker, after.identity) &&
      /^[a-f0-9]{8}:[a-f0-9]{8}$/u.test(before.token.tokenId) &&
      /^[a-f0-9]{8}:[a-f0-9]{8}$/u.test(before.token.modifiedId) &&
      JSON.stringify(before.token) === JSON.stringify(after.token) &&
      before.token.details.appContainer === false &&
      before.token.details.restricted === false &&
      before.token.details.restrictingSids === 0 &&
      before.token.details.integrity >= 12288 &&
      /^[a-f0-9]{8}:[a-f0-9]{8}$/u.test(
        before.token.details.authenticationId,
      ) &&
      /^[a-f0-9]{16}:[a-f0-9]{32}$/u.test(original.identity) &&
      /^[a-f0-9]{64}$/u.test(original.daclSha256) &&
      original.sha256 === digest(value.nonce) &&
      [before.gate, after.gate].every(
        (gate) => JSON.stringify(gate) === JSON.stringify(original),
      ),
  );
  const unavailable = () => {
    throw Object.assign(
      new Error("Effective broker audit coverage unavailable"),
      {
        code: 78,
      },
    );
  };
  if (
    ![before, after].every(
      (v) => v.effective.available === true && v.effective.success === true,
    )
  )
    unavailable();
  need(
    observation.captureComplete === true &&
      end.sequence === start.sequence + 1 &&
      BigInt(end.time) > BigInt(start.time) &&
      BigInt(broker.creationTime) < BigInt(start.time) &&
      end.records - start.records === events.length,
  );
  if (
    !events.some(
      ({ raw, time, logonId }) =>
        raw.pid === broker.pid &&
        raw.subjectSid === broker.userSid &&
        logonId === before.token.details.authenticationId.replace(":", "") &&
        raw.opcode === "4663" &&
        raw.auditFailure === false &&
        (raw.accessMask & 1) !== 0 &&
        raw.target.toLowerCase() === value.gateFile.toLowerCase() &&
        BigInt(time) > BigInt(start.time) &&
        BigInt(time) < BigInt(end.time),
    )
  )
    unavailable();
  return digest(JSON.stringify(observation));
}
export function windowsCommandEnvironment(home, directory, systemRoot) {
  for (const value of [home, directory, systemRoot])
    need(
      typeof value === "string" &&
        /^[A-Za-z]:\\/u.test(value) &&
        path.win32.normalize(value) === value &&
        !/[\0\r\n"%<>&']/u.test(value),
    );
  return {
    PATH: `${path.win32.join(directory, "codex-path")};${path.win32.join(systemRoot, "System32")}`,
    SystemRoot: systemRoot,
    WINDIR: systemRoot,
    USERPROFILE: home,
    HOME: home,
    CODEX_HOME: home,
    TEMP: home,
    TMP: home,
    CI: "true",
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Windows",
  };
}
// FileVersionInfo reads the selected file's version resource. LINK's help text
// has no supported success-status contract here; never admit its exit 1100.
// https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo.getversioninfo
async function readInstalledLinkerVersion(linker, command, options) {
  const systemRoot = options.env.SystemRoot;
  if (
    typeof systemRoot !== "string" ||
    !path.win32.isAbsolute(systemRoot) ||
    path.win32.normalize(systemRoot) !== systemRoot ||
    /[\0\r\n]/u.test(systemRoot)
  )
    throw Object.assign(new Error("Windows version query unavailable"), {
      code: 78,
    });
  // Encode the filename as data, including spaces and PowerShell metacharacters.
  const filename = Buffer.from(linker, "utf8").toString("base64"),
    script = [
      "$ErrorActionPreference = 'Stop'; try {",
      `$file = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${filename}'));`,
      "$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($file);",
      "if ([string]::IsNullOrEmpty($version.FileVersion) -or -not [StringComparer]::OrdinalIgnoreCase.Equals($file, $version.FileName)) { exit 1 };",
      "$parts = @($version.FileMajorPart, $version.FileMinorPart, $version.FileBuildPart, $version.FilePrivatePart);",
      "[Console]::Out.WriteLine('native-linker-version=' + ($parts -join '.')); exit 0",
      "} catch { exit 1 }",
    ].join(" ");
  options.signal?.throwIfAborted();
  const result = await command(
    path.win32.join(
      systemRoot,
      "System32",
      "WindowsPowerShell",
      "v1.0",
      "powershell.exe",
    ),
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(script, "utf16le").toString("base64"),
    ],
    { ...options, maxBuffer: 4096 },
  );
  options.signal?.throwIfAborted();
  need(
    result &&
      (result.code === undefined || result.code === 0) &&
      (result.exitCode === undefined || result.exitCode === 0) &&
      !result.signal &&
      !result.killed &&
      !result.timedOut &&
      !result.truncated &&
      typeof result.stdout === "string" &&
      Buffer.byteLength(result.stdout, "utf8") <= 128 &&
      result.stderr === "",
  );
  const match =
    /^native-linker-version=([0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5})\r?\n$/u.exec(
      result.stdout,
    );
  need(
    match &&
      match[0] === result.stdout &&
      match[1]
        .split(".")
        .every(
          (part) => /^(?:0|[1-9][0-9]*)$/u.test(part) && Number(part) <= 65535,
        ) &&
      Number(match[1].split(".")[0]) > 0,
  );
  return match[1];
}
/** Reuse the working installed MSVC/SDK selection; this builds only the finite
 * variant of the existing helper and records its actual source/SDK bytes. */
export async function buildWindowsCommandHelper(
  root,
  components,
  signal,
  options = {},
) {
  return buildWindowsAuditHelper("command", root, components, signal, options);
}
/** Compile/link the default reader recipe only; this creates no custody or review. */
export async function buildWindowsCustodyReader(
  root,
  components,
  signal,
  options = {},
) {
  return buildWindowsAuditHelper("custody", root, components, signal, options);
}
async function buildWindowsAuditHelper(
  variant,
  root,
  components,
  signal,
  {
    command = execute,
    read = regular,
    environment = process.env,
    inspect = windowsFeasibilityImports,
  } = {},
) {
  need(
    command !== execute ||
      (process.platform === "win32" &&
        process.arch === "x64" &&
        process.env.GITHUB_ACTIONS === "true"),
  );
  let operation = "compiler-discovery";
  try {
    const options = {
      signal,
      timeout: 10000,
      maxBuffer: 1048576,
      windowsHide: true,
      env: environment,
    };
    const compiler = (await command("where.exe", ["cl.exe"], options)).stdout
      .trim()
      .split(/\r?\n/u)[0];
    need(path.win32.isAbsolute(compiler));
    operation = "sdk-discovery";
    const version = environment.WindowsSDKVersion?.replace(/\\$/u, "");
    if (!version || !/^[0-9.]+$/u.test(version) || !environment.WindowsSdkDir)
      throw Object.assign(new Error("SDK unavailable"), { code: 78 });
    operation = "compiler-discovery";
    let banner;
    try {
      banner = await command(compiler, ["/Bv"], options);
    } catch (error) {
      if (error.code !== 2 || error.signal || error.killed || error.timedOut)
        throw error;
      banner = error;
    }
    const compilerVersion = /Compiler Version ([0-9.]+) for x64/u.exec(
      `${banner.stdout}\n${banner.stderr}`,
    )?.[1];
    need(compilerVersion);
    components.push({
      role: "tool",
      name: "msvc",
      version: compilerVersion,
      sha256: digest(await read(compiler)),
    });
    const linker = path.win32.join(path.win32.dirname(compiler), "link.exe");
    operation = "linker-discovery";
    const linkerComponent = {
      role: "tool",
      name: "msvc-linker",
      version: "unqueried",
      sha256: digest(await read(linker)),
    };
    components.push(linkerComponent);
    const linkerVersion = await readInstalledLinkerVersion(
      linker,
      command,
      options,
    );
    need(digest(await read(linker)) === linkerComponent.sha256);
    linkerComponent.version = linkerVersion;
    operation = "sdk-discovery";
    const sdk = await read(
      path.win32.join(
        environment.WindowsSdkDir,
        "Include",
        version,
        "um",
        "Windows.h",
      ),
    );
    components.push({
      role: "tool",
      name: "windows-sdk-header",
      version,
      sha256: digest(sdk),
    });
    operation = "source-read";
    const sources = [],
      sourceFiles =
        variant === "command"
          ? [
              ["feasibility-helper.c", "windows-command-source"],
              ["feasibility-command.h", "windows-command-header"],
              ["effective-reader.h", "windows-command-xml"],
              ["audit-policy-remove.h", "windows-audit-removal-source"],
            ]
          : [
              ["custody-reader.c", "windows-custody-source"],
              ["custody.h", "windows-custody-header"],
              ["account.h", "windows-custody-account"],
              ["effective-reader.h", "windows-custody-policy"],
              ["audit-policy-remove.h", "windows-audit-removal-source"],
            ];
    for (const [file, name] of sourceFiles) {
      const bytes = await read(path.join(SOURCE, file));
      sources.push(bytes);
      components.push({
        role: "tool",
        name,
        version: "1",
        sha256: digest(bytes),
      });
    }
    const basename =
      variant === "command" ? "command-helper" : "custody-reader";
    const helper = path.win32.join(root, "build", basename + ".exe");
    const object =
      variant === "command"
        ? path.win32.join(root, "build", basename + ".obj")
        : helper + ".obj";
    const recipe = windowsCompilerArguments(
      path.join(SOURCE, "custody-reader.c"),
      helper,
    );
    const boundary = recipe.indexOf("/link");
    const compileArguments =
      variant === "custody"
        ? [
            ...recipe
              .slice(0, boundary)
              .filter((arg) => !arg.startsWith("/Fe")),
            "/c",
          ]
        : null;
    const linkArguments =
      variant === "custody"
        ? ["/NOLOGO", `/OUT:${helper}`, object, ...recipe.slice(boundary + 1)]
        : null;
    operation = "helper-compile";
    signal?.throwIfAborted();
    await command(
      compiler,
      compileArguments ?? [
        "/nologo",
        "/std:c17",
        "/O2",
        "/W4",
        "/MT",
        "/Brepro",
        "/DNATIVE_COMMAND_EXPERIMENT",
        "/c",
        path.join(SOURCE, "feasibility-helper.c"),
        `/Fo${object}`,
      ],
      { ...options, cwd: path.win32.join(root, "build") },
    );
    operation = "helper-link";
    signal?.throwIfAborted();
    await command(
      linker,
      linkArguments ?? [
        "/NOLOGO",
        "/Brepro",
        "/INCREMENTAL:NO",
        "/MANIFEST:EMBED",
        `/OUT:${helper}`,
        object,
        "advapi32.lib",
        "userenv.lib",
        "bcrypt.lib",
        "ws2_32.lib",
        "wevtapi.lib",
        "xmllite.lib",
        "ole32.lib",
        "uuid.lib",
      ],
      { ...options, cwd: path.win32.join(root, "build") },
    );
    operation = "helper-image-inspection";
    for (const [index, [file]] of sourceFiles.entries())
      need(
        digest(await read(path.join(SOURCE, file))) === digest(sources[index]),
      );
    const bytes = await read(helper);
    inspect(bytes);
    const helperSha256 = digest(bytes);
    components.push({
      role: "helper",
      name:
        variant === "command"
          ? "windows-command-helper"
          : "windows-custody-reader",
      version: "1",
      sha256: helperSha256,
    });
    return {
      helper,
      helperSha256,
      sdkSha256: digest(sdk),
      abiSha256: digest(Buffer.concat(sources)),
    };
  } catch (error) {
    throw Object.assign(
      new Error("Windows command helper build failed.", { cause: error }),
      {
        feasibilityCause:
          error.code === "ERR_FEASIBILITY_WINDOWS_PE"
            ? windowsFeasibilityCause(operation, error)
            : feasibilityFailureCause(
                "command",
                operation,
                error,
                [
                  "compiler-discovery",
                  "linker-discovery",
                  "sdk-discovery",
                ].includes(operation) && [78, "ENOENT"].includes(error.code)
                  ? "prerequisite-unavailable"
                  : "setup-failed",
              ),
      },
    );
  }
}

/** Exclusive preparation tree and directly owned build processes. No recursive
 * removal primitive, path substitution, PID signalling or broker-stage inference. */
export function createWindowsCommandPreparation({
  temporary = mkdtemp,
  canonical = realpath,
  stat = lstat,
  createDirectory = mkdir,
  list = readdir,
  removeFile = unlink,
  removeDirectory = rmdir,
  command = execute,
} = {}) {
  let allocation,
    root,
    closing = false;
  const directories = new Map(),
    work = new Set(),
    processes = [];
  const identity = (st) => {
    need(
      typeof st.dev === "bigint" && typeof st.ino === "bigint" && st.ino > 0n,
    );
    return { dev: st.dev, ino: st.ino };
  };
  const matches = (st, id) => id && st.dev === id.dev && st.ino === id.ino;
  const run = (operation) => {
    need(!closing);
    const pending = Promise.resolve().then(operation);
    work.add(pending);
    pending.finally(() => work.delete(pending)).catch(() => {});
    return pending;
  };
  return {
    acquired: () => Boolean(allocation) || work.size > 0,
    run,
    async allocate(parent) {
      const created = await temporary(
        path.win32.join(parent, "native-command-win32-"),
      );
      allocation = { path: created, identity: null }; // Before canonicalization.
      const st = await stat(created, { bigint: true });
      need(st.isDirectory() && !st.isSymbolicLink());
      allocation.identity = identity(st);
      const canonicalRoot = await canonical(created);
      need(
        matches(
          await stat(canonicalRoot, { bigint: true }),
          allocation.identity,
        ),
      );
      root = canonicalRoot;
      for (const name of [
        "build",
        "home",
        "schema-home",
        "schema",
        "workspace",
      ]) {
        const directory = path.win32.join(root, name);
        await createDirectory(directory);
        directories.set(directory, null); // A failed identity read remains owned but uncertain.
        const child = await stat(directory, { bigint: true });
        need(child.isDirectory() && !child.isSymbolicLink());
        directories.set(directory, identity(child));
      }
      return root;
    },
    command(image, args, options) {
      need(!closing);
      need(
        command !== execute ||
          (process.platform === "win32" &&
            process.arch === "x64" &&
            process.env.GITHUB_ACTIONS === "true"),
      );
      const pending = command(image, args, options);
      let record;
      if (pending.child) {
        const child = pending.child;
        record = { closed: false, emergency: false };
        processes.push(record);
        record.completion = new Promise((resolve) =>
          child.once("close", (code, signal) => {
            record.closed = true;
            record.emergency ||= signal !== null;
            resolve();
          }),
        );
      }
      return run(() => pending).catch((error) => {
        if (record)
          record.emergency ||=
            error.killed === true ||
            error.timedOut === true ||
            error.code === "ABORT_ERR";
        throw error;
      });
    },
    async settle(signal) {
      closing = true;
      // A deadline race can leave the preparation promise or execFile callback
      // active. Observe completion before inspecting/removing any owned bytes.
      await Promise.allSettled([...work]);
      await Promise.all(processes.map((record) => record.completion));
      let failure,
        entries = 0;
      const retain = (error) => {
        failure ??= error;
      };
      const sameDirectory = async (file, id) => {
        signal?.throwIfAborted();
        const st = await stat(file, { bigint: true });
        need(st.isDirectory() && !st.isSymbolicLink() && matches(st, id));
      };
      const remove = async (directory, id, depth) => {
        await sameDirectory(directory, id);
        need(depth <= 8);
        const names = await list(directory);
        need((entries += names.length) <= 2048);
        for (const name of names) {
          try {
            need(
              name && name !== "." && name !== ".." && !/[\\/:\0]/u.test(name),
            );
            const file = path.win32.join(directory, name),
              before = await stat(file, { bigint: true });
            need(!before.isSymbolicLink() && (await canonical(file)) === file);
            if (before.isDirectory()) {
              // Top-level directories must be original acquisitions. Descendants
              // stay inside those scopes after complete process/custody retirement.
              const pinned =
                depth === 0 ? directories.get(file) : identity(before);
              need(pinned);
              await remove(file, pinned, depth + 1);
            } else {
              need(before.isFile());
              await sameDirectory(directory, id);
              need(
                matches(await stat(file, { bigint: true }), identity(before)),
              );
              await removeFile(file);
            }
          } catch (error) {
            retain(error);
          }
        }
        await sameDirectory(directory, id);
        await removeDirectory(directory);
      };
      if (processes.some((record) => !record.closed || record.emergency))
        throw Object.assign(
          new Error("Build process retirement was uncertain"),
          { emergency: true },
        );
      if (allocation) {
        try {
          await sameDirectory(allocation.path, allocation.identity);
          await remove(root ?? allocation.path, allocation.identity, 0);
        } catch (error) {
          retain(error);
        }
        try {
          await stat(allocation.path, { bigint: true });
          retain(new Error("Owned preparation root remains"));
        } catch (error) {
          if (error.code !== "ENOENT") retain(error);
        }
      }
      if (failure) throw failure;
      return {
        independent: true,
        processesRetired: true,
        fixturesRemoved: true,
        emergency: false,
        witnessSha256: digest(
          JSON.stringify({
            allocated: Boolean(allocation),
            processes: processes.length,
            entries,
          }),
        ),
      };
    },
  };
}

/** Only independently closed, empty custody authorizes restoration. Capture
 * failure still fails settlement, but cannot strand verified owned audit changes. */
export async function settleWindowsCommandCustody(effects) {
  let domain,
    stopped,
    observed,
    failure,
    restorationReady = false,
    emergency = false;
  const retain = (error) => {
    failure ??= error;
    emergency ||= error.emergency === true;
  };
  try {
    domain = await effects.retireDomain();
    need(domain.empty === true && domain.admissionsClosed === true);
    await effects.prepareFinish(domain);
    restorationReady = true;
  } catch (error) {
    retain(error);
  }
  try {
    stopped = await effects.closeObserver();
    need(stopped.captureRetired === true);
  } catch (error) {
    retain(error);
  }
  try {
    observed = await effects.verifyObserver();
    need(observed.completeDomain === true);
    if (observed.failure) retain(observed.failure);
  } catch (error) {
    retain(error);
  }
  let final;
  if (restorationReady && observed?.completeDomain === true) {
    try {
      final = await effects.finish();
    } catch (error) {
      retain(error);
    }
  } else {
    try {
      await effects.abandonFinish();
    } catch (error) {
      retain(error);
    }
  }
  if (failure) {
    failure.emergency = emergency;
    throw failure;
  }
  return { domain, stopped, observed, final };
}
/** Original handles remain authoritative. Check final sentinel bytes/DACLs
 * before releasing the finish owner to restore and remove the owned fixtures. */
export function windowsCommandCleanupSnapshot(original, final) {
  need(
    original?.length === 4 &&
      final?.length === 4 &&
      final.every((file, i) => file.identity === original[i].identity) &&
      [2, 3].every(
        (i) => JSON.stringify(final[i]) === JSON.stringify(original[i]),
      ),
  );
  return digest(JSON.stringify(final[2]));
}

/** Hold the subject while alive; a new PID lookup after exit is not custody.
 * Transport errors retain their first cause and cannot satisfy retirement. */
export async function openWindowsCommandWatcher(
  helper,
  args,
  environment,
  signal,
  launch = spawn,
) {
  need(!signal.aborted);
  const child = launch(helper, args, {
    env: environment,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  let failure,
    count = 0;
  const retain = (error) => {
    failure ??= error;
  };
  child.stdin.on("error", retain);
  const done = new Promise((resolve, reject) => {
    child.once("error", (error) => {
      retain(error);
      reject(failure);
    });
    child.once("close", (code, killed) => {
      if (failure) reject(failure);
      else if (code === 0 && !killed) resolve();
      else
        reject(
          Object.assign(new Error("Native watcher failed"), {
            code,
            signal: killed,
          }),
        );
    });
  });
  done.catch(() => {});
  const frames = [],
    lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const iterator = lines[Symbol.asyncIterator]();
  child.stderr.on("data", (v) => {
    count += v.length;
    if (count > 65536) {
      retain(new Error("Native watcher exceeded bound"));
      lines.close();
    }
  });
  const abort = () => child.kill();
  signal.addEventListener("abort", abort, { once: true });
  if (signal.aborted) abort();
  let ready;
  try {
    const first = await iterator.next();
    if (first.done) await done;
    need(!signal.aborted && !first.done && first.value.length < 1048576);
    ready = JSON.parse(first.value);
    need(ready.ready === true);
    normalizeWindowsIdentity(ready.identity);
  } catch (error) {
    child.stdin.end();
    child.kill();
    await done.catch(() => {});
    throw failure ?? error;
  } finally {
    signal.removeEventListener("abort", abort);
  }
  return {
    identity: ready.identity,
    child,
    async abandon() {
      child.stdin.end();
      await done;
    },
    async initialize(value) {
      child.stdin.write(value);
      const next = await iterator.next();
      if (next.done) await done;
      need(
        !next.done &&
          next.value.length < 1048576 &&
          JSON.parse(next.value).custodyReady === true,
      );
    },
    async inspect() {
      child.stdin.write("D");
      const next = await iterator.next();
      if (next.done) await done;
      need(!next.done && next.value.length < 1048576);
      return JSON.parse(next.value);
    },
    async finish(active = signal) {
      need(!active.aborted);
      child.stdin.end("R");
      for await (const line of { [Symbol.asyncIterator]: () => iterator }) {
        need(line.length < 1048576 && frames.length < 4);
        frames.push(JSON.parse(line));
      }
      await done;
      need(
        frames.at(-1)?.retired === true &&
          frames.at(-1).completeDomain === true,
      );
      return frames.at(-1);
    },
  };
}

export function createWindowsCommandEffects(dispatch, inputs) {
  const started = performance.now();
  const preparation = createWindowsCommandPreparation();
  let broker,
    closed,
    reading,
    failed,
    prepared,
    decoder,
    observationSignal,
    closing = false,
    start,
    watcher,
    cleanupReader,
    cleanupReady = false,
    readerVerifier,
    observerVerifier,
    coverageAdmitted = false,
    cleanupDeadline = Infinity;
  const pending = new Map(),
    xml = new Map(),
    logons = new Map(),
    rpc = new PassThrough(),
    errorOutput = new PassThrough(),
    input = new PassThrough();
  let probeOutput = "",
    bytes = 0;
  const nativeEnvironment = () => ({
    ...prepared.environment,
    NATIVE_COMMAND_LIFETIME_MS: String(
      Math.max(
        1,
        Math.ceil(
          Math.min(started + 150000, cleanupDeadline) - performance.now(),
        ),
      ),
    ),
  });
  const fail = (error) => {
    failed ??= error;
    for (const [key, entry] of pending)
      if (!["D", "S"].includes(key)) {
        entry.reject(failed);
        pending.delete(key);
      }
  };
  const call = (operation) => {
    const key = operation.split(" ")[0],
      settlement = ["D", "S"].includes(key);
    need(broker?.stdin.writable && !pending.has(key));
    if (!settlement) need(!failed && !closing && !observationSignal.aborted);
    if (["V", "G", "A", "R", "J", "C"].includes(key)) need(coverageAdmitted);
    if (key === "D") closing = true;
    return new Promise((resolve, reject) => {
      pending.set(key, { resolve, reject });
      broker.stdin.write(operation + "\n");
    });
  };
  const native = async (args, signal) =>
    JSON.parse(
      (
        await (!broker ? preparation.command : execute)(prepared.helper, args, {
          env: nativeEnvironment(),
          signal,
          timeout: 10000,
          maxBuffer: 1048576,
          windowsHide: true,
        })
      ).stdout,
    );
  const verifier = async (value, signal) => {
    const id = normalizeWindowsIdentity(value.identity),
      owner = prepared.observer;
    const observed = await native(
      [
        "command-check",
        String(owner.pid),
        owner.creationTime,
        prepared.jobHandle,
        String(id.pid),
        id.creationTime,
        value.imageSha256,
      ],
      signal,
    );
    need(
      sameWindowsIdentity(observed.identity, id) &&
        JSON.stringify(observed.token) === JSON.stringify(value.token) &&
        observed.creationJob === true,
    );
    return observed;
  };
  const watch = (args, signal) =>
    openWindowsCommandWatcher(
      prepared.helper,
      args,
      nativeEnvironment(),
      signal,
    );
  const observation = async (spec, signal) => {
    const before = await call("N"),
      independentBefore = await verifier(
        { ...before, imageSha256: prepared.helperSha256 },
        signal,
      );
    await call("T");
    const after = await call("F"),
      independentAfter = await verifier(
        { ...after, imageSha256: prepared.helperSha256 },
        signal,
      );
    const settled = await call("U");
    const end = await call("B"),
      state = decoder.state();
    return {
      controlExitCode: settled.exitCode,
      before: independentBefore.identity,
      after: independentAfter.identity,
      beforeToken: independentBefore.token,
      afterToken: independentAfter.token,
      imageSha256: prepared.helperSha256,
      creationJob: true,
      captureComplete: state.ready && !failed,
      start,
      end,
      events: state.events
        .slice(start.records, end.records)
        .map((event) => ({ ...event, logonId: logons.get(event.raw.id) })),
      object: { before: before.object, after: after.object },
      gate: { before: before.gate, after: after.gate },
    };
  };
  return {
    noCustody: () => !broker && !preparation.acquired(),
    prepare(nonce, components, signal) {
      return preparation.run(async () => {
        need(
          dispatch.platform === "win32" &&
            process.platform === "win32" &&
            process.arch === "x64",
        );
        need(
          process.env.RUNNER_TEMP &&
            path.win32.isAbsolute(process.env.RUNNER_TEMP),
        );
        const root = await preparation.allocate(process.env.RUNNER_TEMP);
        prepared = {
          root,
          nonce,
          home: path.join(root, "home"),
          workspace: path.join(root, "workspace"),
          files: {
            inspect: path.join(root, "workspace", "inspection"),
            edit: path.join(root, "workspace", "edit"),
            outside: path.join(root, "outside"),
          },
          gateFile: path.join(root, "workspace", "gate"),
          gate: `\\\\.\\pipe\\native.command.${nonce}`,
        };
        Object.assign(
          prepared,
          await buildWindowsCommandHelper(root, components, signal, {
            command: preparation.command,
          }),
        );
        prepared.environment = windowsCommandEnvironment(
          prepared.home,
          inputs.packages.codex.directory,
          process.env.SystemRoot,
        );
        for (const file of [
          ...Object.values(prepared.files),
          prepared.gateFile,
        ])
          await writeFile(file, nonce, { flag: "wx" });
        let preflight;
        try {
          preflight = await native(["command-preflight"], signal);
        } catch (error) {
          throw Object.assign(
            new Error("Native command prerequisites failed.", { cause: error }),
            {
              feasibilityCause: feasibilityFailureCause(
                "command",
                "native-prerequisites",
                error,
                error.code === 78 ? "prerequisite-unavailable" : "setup-failed",
              ),
            },
          );
        }
        Object.assign(prepared, preflight);
        decoder = createWindowsAuditDecoder(
          {
            xml: (bytes) => {
              const key = digest(bytes),
                value = xml.get(key);
              need(value);
              xml.delete(key);
              return value;
            },
          },
          {
            sdkSha256: prepared.sdkSha256,
            abiSha256: prepared.abiSha256,
            versions: preflight.versions,
            mappingSha256: observationDigest(preflight.versions),
          },
        );
        return prepared;
      });
    },
    async coverage(value, signal) {
      observationSignal = signal;
      broker = spawn(
        value.helper,
        [
          "command-broker",
          value.root,
          value.nonce,
          inputs.packages.codex.file,
          inputs.packages.codex.component.sha256,
          value.helper,
          value.helperSha256,
        ],
        {
          env: nativeEnvironment(),
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
        },
      );
      const ready = new Promise((resolve, reject) =>
        pending.set("ready", { resolve, reject }),
      );
      closed = new Promise((resolve) => {
        broker.once("error", fail);
        broker.once("close", (code, killed) => {
          resolve({ code, signal: killed });
          rpc.end();
          errorOutput.end();
          const error = Object.assign(new Error("Native broker closed"), {
            code,
            signal: killed,
          });
          for (const entry of pending.values()) entry.reject(error);
          pending.clear();
        });
      });
      broker.stdin.on("error", (error) => {
        fail(error);
        for (const key of ["D", "S"]) {
          pending.get(key)?.reject(error);
          pending.delete(key);
        }
      });
      broker.stderr.on("data", (v) => {
        bytes += v.length;
        if (bytes > 33554432) fail(new Error("Native capture exceeded bound"));
      });
      reading = (async () => {
        for await (const line of createInterface({
          input: broker.stdout,
          crlfDelay: Infinity,
        })) {
          try {
            need(line.length <= 600000);
            bytes += Buffer.byteLength(line);
            need(bytes <= 33554432);
            const frame = JSON.parse(line);
            if (failed && !["D", "S"].includes(frame.event)) continue;
            if (frame.event === "audit") {
              need(/^(?:[a-f0-9]{2}){4,65536}$/u.test(frame.hex));
              const raw = Buffer.from(frame.hex, "hex"),
                header = Buffer.alloc(4);
              const decoded = windowsCommandAuditRead(frame.decoded);
              xml.set(digest(raw), decoded.native);
              logons.set(digest(raw), decoded.logonId);
              header.writeUInt32LE(raw.length);
              await decoder.push(Buffer.concat([header, raw]));
            } else if (
              frame.event === "rpc" ||
              frame.event === "stderr" ||
              frame.event === "probe-output" ||
              frame.event === "probe-stderr"
            ) {
              need(/^(?:[a-f0-9]{2}){1,4096}$/u.test(frame.hex));
              const raw = Buffer.from(frame.hex, "hex");
              if (frame.event === "probe-output") {
                probeOutput += raw.toString("utf8");
                need(probeOutput.length <= 4096);
              } else if (frame.event !== "probe-stderr")
                (frame.event === "rpc" ? rpc : errorOutput).write(raw);
            } else if (["rpc-end", "stderr-end"].includes(frame.event))
              (frame.event === "rpc-end" ? rpc : errorOutput).end();
            else if (frame.event === "capture-end") {
              need(/^(?:[a-f0-9]{2}){4,65536}$/u.test(frame.hex));
              const raw = Buffer.from(frame.hex, "hex"),
                header = Buffer.alloc(16);
              xml.set(digest(raw), frame.decoded);
              header.writeUInt32LE(0xffffffff);
              header.writeUInt32LE(frame.bytes, 4);
              header.writeUInt32LE(frame.records, 8);
              header.writeUInt32LE(raw.length, 12);
              await decoder.push(Buffer.concat([header, raw]));
            } else {
              if (frame.event === "ready") await decoder.push(Buffer.alloc(4));
              if (frame.event === "B") {
                const raw = Buffer.alloc(20);
                raw.writeUInt32LE(0xfffffffe);
                raw.writeUInt32LE(frame.sequence, 4);
                raw.writeBigUInt64LE(BigInt(frame.time), 8);
                raw.writeUInt32LE(frame.records, 16);
                await decoder.push(raw);
              }
              const entry = pending.get(frame.event);
              need(entry);
              pending.delete(frame.event);
              entry.resolve(frame);
            }
          } catch (error) {
            fail(error);
          }
        }
      })();
      reading.catch(fail);
      const admitted = await ready;
      value.observer = normalizeWindowsIdentity(admitted.identity);
      value.jobHandle = admitted.jobHandle;
      need(
        /^[1-9][0-9]{0,19}$/u.test(value.jobHandle) &&
          admitted.files.length === 4,
      );
      value.sentinelSha256 = digest(JSON.stringify(admitted.files[2]));
      value.original = admitted;
      watcher = await watch(
        [
          "command-watch",
          String(value.observer.pid),
          value.observer.creationTime,
          value.helperSha256,
          value.nonce,
          value.jobHandle,
        ],
        signal,
      );
      cleanupReader = await watch(
        [
          "command-finish",
          String(value.observer.pid),
          value.observer.creationTime,
          value.helperSha256,
          value.nonce,
          value.jobHandle,
        ],
        signal,
      );
      const original = value.original.cleanup;
      need(
        [original.intentHandle, original.closedHandle].every((v) =>
          /^[1-9][0-9]{0,19}$/u.test(v),
        ),
      );
      need(original.files.length === 6);
      need(
        /^[a-f0-9]{64}$/u.test(original.systemSha256) &&
          /^[a-f0-9]{64}$/u.test(original.nullSha256) &&
          /^[1-9][0-9]{0,19}$/u.test(original.nullHandle),
      );
      await cleanupReader.initialize(
        `${original.systemSha256} ${original.nullSha256} ${original.nullHandle} ${original.intentHandle} ${original.closedHandle}\n` +
          original.files
            .map((file) => {
              need(
                /^[1-9][0-9]{0,19}$/u.test(file.handle) &&
                  /^[a-f0-9]{16}:[a-f0-9]{32}$/u.test(file.identity) &&
                  /^(?:[a-f0-9]{2})+$/u.test(file.baselineHex) &&
                  /^(?:[a-f0-9]{2})*$/u.test(file.saclHex),
              );
              return `${file.handle} ${file.identity} ${file.baselineHex} ${file.saclHex || "-"}\n`;
            })
            .join(""),
      );
      cleanupReady = true;
      readerVerifier = await watch(
        [
          "command-watch",
          String(cleanupReader.identity.pid),
          cleanupReader.identity.creationTime,
          value.helperSha256,
          value.nonce,
        ],
        signal,
      );
      observerVerifier = await watch(
        [
          "command-watch",
          String(watcher.identity.pid),
          watcher.identity.creationTime,
          value.helperSha256,
          value.nonce,
        ],
        signal,
      );
      await call("I");
      const inspect = () =>
        native(
          [
            "command-broker-check",
            String(value.observer.pid),
            value.observer.creationTime,
            value.helperSha256,
            admitted.tokenHandle,
            admitted.gateHandle,
            value.jobHandle,
          ],
          signal,
        );
      const before = await inspect();
      if (!before.effective.available || !before.effective.success)
        throw Object.assign(
          new Error("Effective broker auditing unavailable"),
          { code: 78 },
        );
      const start = await call("B");
      await call("P");
      const end = await call("B"),
        after = await inspect(),
        state = decoder.state();
      const observation = {
        before,
        after,
        start,
        end,
        captureComplete: state.ready && !failed,
        events: state.events
          .slice(start.records, end.records)
          .map((event) => ({ ...event, logonId: logons.get(event.raw.id) })),
      };
      windowsCommandBrokerCoverage(value, observation);
      await call("M");
      coverageAdmitted = true;
      return observation;
    },
    async schema(value) {
      need(coverageAdmitted);
      probeOutput = "";
      need(
        (await call("V")).exitCode === 0 &&
          ["codex-cli 0.160.0\r\n", "codex-cli 0.160.0\n"].includes(
            probeOutput,
          ),
      );
      probeOutput = "";
      need((await call("G")).exitCode === 0);
      return {
        params: JSON.parse(
          await regular(
            path.join(value.root, "schema", "v2", "CommandExecParams.json"),
          ),
        ),
        response: JSON.parse(
          await regular(
            path.join(value.root, "schema", "v2", "CommandExecResponse.json"),
          ),
        ),
      };
    },
    async arm(value, signal) {
      need((await readdir(value.home)).length === 0);
      const admitted = await call("A");
      const independent = await verifier(admitted, signal);
      input.on("data", (chunk) => {
        if (
          failed ||
          closing ||
          observationSignal.aborted ||
          chunk.length > 65536
        ) {
          fail(new Error("Command admission closed"));
          return;
        }
        broker.stdin.write("J " + chunk.toString("hex") + "\n");
      });
      input.on("end", () => {
        if (!closing && !failed) call("E").catch(fail);
      });
      return {
        ...independent,
        imageSha256: admitted.imageSha256,
        captureReady: decoder.state().ready,
        independent: true,
        transport: { input, output: rpc, errorOutput },
      };
    },
    release: () => call("R"),
    async control(value, signal) {
      start = await call("B");
      probeOutput = "";
      await call("C");
      const observed = await observation({ action: "outside" }, signal),
        reply = {
          exitCode: observed.controlExitCode,
          stdout: probeOutput,
          stderr: "",
        };
      await call("X");
      return { observation: observed, reply };
    },
    async begin(value, spec) {
      start = await call("B");
      await call(`K ${["inspect", "edit", "outside"].indexOf(spec.action)}`);
    },
    observe: (value, spec, signal) => observation(spec, signal),
    async retire(value, signal) {
      cleanupDeadline = performance.now() + 30000;
      value ??= prepared;
      if (!broker)
        return { ...(await preparation.settle(signal)), preparationOnly: true };
      need(broker && value);
      if (!watcher || !cleanupReady) {
        // Installation cannot start before these owners acknowledge custody.
        // Still retire every acquired owner; incomplete custody cannot pass.
        try {
          await call("D");
        } catch (error) {
          fail(error);
        }
        try {
          await call("S");
        } catch (error) {
          fail(error);
        }
        await closed;
        await reading;
        for (const owner of [
          watcher,
          observerVerifier,
          cleanupReader,
          readerVerifier,
        ]) {
          try {
            if (owner === cleanupReader) await owner?.abandon();
            else await owner?.finish(signal);
          } catch (error) {
            fail(error);
          }
        }
        throw failed ?? new Error("Early native custody was incomplete");
      }
      let capture,
        sentinelSha256,
        emergency = false,
        fixturesRetired = false;
      const outcome = await settleWindowsCommandCustody({
        async retireDomain() {
          // Even a broken broker pipe cannot replace the early native custody.
          try {
            await call("D");
          } catch (error) {
            fail(error);
          }
          const domain = await cleanupReader.inspect();
          need(domain.empty === true && domain.admissionsClosed === true);
          emergency ||= domain.emergency === true;
          if (domain.emergency)
            fail(
              Object.assign(new Error("Emergency native retirement"), {
                emergency: true,
              }),
            );
          return domain;
        },
        async prepareFinish(domain) {
          sentinelSha256 = windowsCommandCleanupSnapshot(
            value.original.files,
            domain.files,
          );
        },
        async closeObserver() {
          let stopped;
          try {
            stopped = await call("S");
          } catch (error) {
            fail(error);
          }
          const completion = await closed;
          await reading;
          need(completion.code === 0 && !completion.signal);
          capture = coverageAdmitted ? decoder.finish() : { admitted: false };
          need(stopped?.captureRetired === true);
          return stopped;
        },
        async verifyObserver() {
          let held,
            failure,
            watcherRetired = false;
          try {
            held = await watcher.finish(signal);
            emergency ||= [124, 126].includes(held.exitCode);
          } catch (error) {
            failure = error;
          }
          try {
            need(
              observerVerifier &&
                (await observerVerifier.finish(signal)).retired === true,
            );
            watcherRetired = true;
          } catch (error) {
            failure ??= error;
          }
          if (failure) {
            const completion = await closed;
            failure.emergency ||=
              [124, 126].includes(completion.code) ||
              [124, 126].includes(failure.code);
            if (watcherRetired) {
              try {
                const domain = await cleanupReader.inspect();
                need(
                  domain.ownerRetired === true &&
                    domain.empty === true &&
                    domain.admissionsClosed === true,
                );
                sentinelSha256 = windowsCommandCleanupSnapshot(
                  value.original.files,
                  domain.files,
                );
                return { completeDomain: true, failure };
              } catch {
                // Failed delivery alone never supplies native retirement proof.
              }
            }
            throw failure;
          }
          return held;
        },
        async abandonFinish() {
          let failure;
          try {
            await cleanupReader.abandon();
          } catch (error) {
            failure = error;
          }
          try {
            if (readerVerifier) await readerVerifier.finish(signal);
          } catch (error) {
            failure ??= error;
          }
          if (failure) throw failure;
        },
        async finish() {
          let restored, reader, failure;
          try {
            restored = await cleanupReader.finish(signal);
          } catch (error) {
            failure = error;
          }
          try {
            reader = await readerVerifier.finish(signal);
          } catch (error) {
            failure ??= error;
          }
          fixturesRetired =
            restored?.restored === true &&
            restored?.fixturesRemoved === true &&
            reader?.retired === true;
          if (failure || failed) throw failure ?? failed;
          need(fixturesRetired);
          return { restored, reader };
        },
      }).catch(async (error) => {
        if (fixturesRetired) {
          try {
            await preparation.settle(signal);
          } catch (cleanup) {
            error.preparationCleanup = cleanup;
          }
        }
        error.emergency ||= emergency;
        throw error;
      });
      await preparation.settle(signal);
      return {
        independent: true,
        completeDomain: true,
        admissionsClosed: true,
        serverRetired: true,
        helpersRetired: true,
        observerRetired: true,
        readerRetired: true,
        jobClosed: true,
        emergency: false,
        auditRestored: true,
        fixturesRemoved: true,
        sentinelSha256,
        witnessSha256: digest(JSON.stringify([outcome, capture])),
      };
    },
  };
}
