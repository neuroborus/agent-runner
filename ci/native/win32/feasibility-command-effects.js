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
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { observationDigest } from "../index.js";
import {
  digest,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
} from "./protocol.js";
import { createWindowsAuditDecoder } from "./audit-decoder.js";
import { windowsFeasibilityImports } from "./feasibility.js";

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
/** Reuse the working installed MSVC/SDK selection; this builds only the finite
 * variant of the existing helper and records its actual source/SDK bytes. */
export async function buildWindowsCommandHelper(
  root,
  components,
  signal,
  { command = execute, read = regular, environment = process.env } = {},
) {
  const options = {
    signal,
    timeout: 10000,
    maxBuffer: 1048576,
    windowsHide: true,
  };
  const compiler = (await command("where.exe", ["cl.exe"], options)).stdout
    .trim()
    .split(/\r?\n/u)[0];
  need(path.win32.isAbsolute(compiler));
  const version = environment.WindowsSDKVersion?.replace(/\\$/u, "");
  if (!version || !/^[0-9.]+$/u.test(version) || !environment.WindowsSdkDir)
    throw Object.assign(new Error("SDK unavailable"), { code: 78 });
  let banner;
  try {
    banner = await command(compiler, ["/Bv"], options);
  } catch (error) {
    if (error.code !== 2 || error.signal || error.killed) throw error;
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
  const sources = await Promise.all(
    ["feasibility-helper.c", "feasibility-command.h", "effective-reader.h"].map(
      (file) => read(path.join(SOURCE, file)),
    ),
  );
  const helper = path.win32.join(root, "build", "command-helper.exe");
  await command(
    compiler,
    [
      "/nologo",
      "/std:c17",
      "/O2",
      "/W4",
      "/MT",
      "/Brepro",
      "/DNATIVE_COMMAND_EXPERIMENT",
      path.join(SOURCE, "feasibility-helper.c"),
      `/Fo${path.win32.join(root, "build", "command-helper.obj")}`,
      `/Fe${helper}`,
      "/link",
      "/INCREMENTAL:NO",
    ],
    { ...options, cwd: path.win32.join(root, "build") },
  );
  const bytes = await read(helper);
  windowsFeasibilityImports(bytes);
  const helperSha256 = digest(bytes);
  components.push({
    role: "helper",
    name: "windows-command-helper",
    version: "1",
    sha256: helperSha256,
  });
  return {
    helper,
    helperSha256,
    sdkSha256: digest(sdk),
    abiSha256: digest(Buffer.concat(sources)),
  };
}

/** Failures never authorize restoration, but still attempt observer retirement.
 * Keep the first failure and abandon the parked finish owner without releasing it. */
export async function settleWindowsCommandCustody(effects) {
  let domain,
    stopped,
    observed,
    failure,
    emergency = false;
  const retain = (error) => {
    failure ??= error;
    emergency ||= error.emergency === true;
  };
  try {
    domain = await effects.retireDomain();
    need(domain.empty === true && domain.admissionsClosed === true);
    await effects.prepareFinish(domain);
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
  } catch (error) {
    retain(error);
  }
  if (failure) {
    try {
      await effects.abandonFinish();
    } catch (error) {
      retain(error);
    }
    failure.emergency = emergency;
    throw failure;
  }
  return { domain, stopped, observed, final: await effects.finish() };
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
  const first = await iterator.next();
  if (first.done) await done;
  need(!first.done && first.value.length < 1048576);
  const ready = JSON.parse(first.value);
  need(ready.ready === true);
  normalizeWindowsIdentity(ready.identity);
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
    async finish() {
      need(!signal.aborted);
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
    if (key === "D") closing = true;
    return new Promise((resolve, reject) => {
      pending.set(key, { resolve, reject });
      broker.stdin.write(operation + "\n");
    });
  };
  const native = async (args, signal) =>
    JSON.parse(
      (
        await execute(prepared.helper, args, {
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
    noCustody: () => !broker,
    async prepare(nonce, components, signal) {
      need(
        dispatch.platform === "win32" &&
          process.platform === "win32" &&
          process.arch === "x64",
      );
      need(
        process.env.RUNNER_TEMP &&
          path.win32.isAbsolute(process.env.RUNNER_TEMP),
      );
      const root = await realpath(
        await mkdtemp(
          path.join(process.env.RUNNER_TEMP, "native-command-win32-"),
        ),
      );
      for (const directory of [
        "build",
        "home",
        "schema-home",
        "schema",
        "workspace",
      ])
        await mkdir(path.join(root, directory));
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
        ...(await buildWindowsCommandHelper(root, components, signal)),
      };
      prepared.environment = windowsCommandEnvironment(
        prepared.home,
        inputs.packages.codex.directory,
        process.env.SystemRoot,
      );
      for (const file of [...Object.values(prepared.files), prepared.gateFile])
        await writeFile(file, nonce, { flag: "wx" });
      const preflight = await native(["command-preflight"], signal);
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
    },
    async schema(value, signal) {
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
      broker.stdin.on("error", fail);
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
      need(broker && value && watcher);
      let readerVerifier, observerVerifier, capture, sentinelSha256;
      const outcome = await settleWindowsCommandCustody({
        retireDomain: () => call("D"),
        async prepareFinish(domain) {
          sentinelSha256 = windowsCommandCleanupSnapshot(
            value.original.files,
            domain.files,
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
          need(original.files.length === 6);
          need(
            /^[a-f0-9]{64}$/u.test(original.systemSha256) &&
              /^[a-f0-9]{64}$/u.test(original.nullSha256) &&
              /^[1-9][0-9]{0,19}$/u.test(original.nullHandle),
          );
          await cleanupReader.initialize(
            `${original.systemSha256} ${original.nullSha256} ${original.nullHandle}\n` +
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
        },
        async closeObserver() {
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
          const stopped = await call("S"),
            completion = await closed;
          await reading;
          need(completion.code === 0 && !completion.signal);
          capture = decoder.finish();
          return stopped;
        },
        async verifyObserver() {
          let held, failure;
          try {
            held = await watcher.finish();
          } catch (error) {
            failure = error;
          }
          try {
            need(
              observerVerifier &&
                (await observerVerifier.finish()).retired === true,
            );
          } catch (error) {
            failure ??= error;
          }
          if (failure) {
            const completion = await closed;
            failure.emergency = [124, 126].includes(completion.code);
            throw failure;
          }
          return held;
        },
        async abandonFinish() {
          try {
            if (cleanupReader) await cleanupReader.abandon();
          } finally {
            if (readerVerifier) await readerVerifier.finish();
          }
        },
        async finish() {
          const restored = await cleanupReader.finish(),
            reader = await readerVerifier.finish();
          need(
            restored.restored === true &&
              restored.fixturesRemoved === true &&
              reader.retired === true &&
              !failed,
          );
          return { restored, reader };
        },
      });
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
