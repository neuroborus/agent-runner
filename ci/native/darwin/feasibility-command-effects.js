import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { PassThrough } from "node:stream";
import { createInterface } from "node:readline";
import {
  chmod,
  chown,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import {
  nativeException,
  nativeDiagnostic,
  diagnosticCommand,
  observeNativeProcess,
} from "../diagnostics.js";
import {
  buildDarwinFeasibility,
  darwinFeasibilityIdentityArguments,
  startupObserver,
} from "./feasibility.js";
import {
  DARWIN_COLD_STARTUP_TRACE_INTENT,
  assertDarwinColdStartupTrace,
  openDarwinStartupTrace,
} from "./startup-trace.js";
import { feasibilityFailureCause } from "../feasibility/index.js";
import { createDarwinAuditDecoder } from "./audit.js";
import {
  digest,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";

const execute = diagnosticCommand(
  "darwin/feasibility-command-effects.js",
  promisify(execFile),
);
const env = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  CI: "true",
  GITHUB_ACTIONS: "true",
  RUNNER_ENVIRONMENT: "github-hosted",
  RUNNER_OS: "macOS",
});
const need = (value) => {
  if (!value) throw new Error("Incomplete native command observation");
};
export function darwinCommandEnvironment(home, directory) {
  return {
    PATH: `${path.join(directory, "codex-path")}:/usr/bin:/bin`,
    HOME: home,
    CODEX_HOME: home,
    LANG: "C",
    CI: "true",
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "macOS",
  };
}
/** Match the BSM reader's permission representation while retaining the complete
 * experiment file/volume identity, including native type bits. */
export function darwinCommandFileObservation(file) {
  need(
    typeof file.identity === "string" &&
      file.identity.length <= 256 &&
      /^[a-f0-9]{64}$/u.test(file.sha256),
  );
  const fields = file.identity.split(":");
  need(
    fields.length === 10 &&
      fields
        .slice(0, 8)
        .every((value) => /^(?:0|[1-9][0-9]{0,19})$/u.test(value)) &&
      fields.slice(0, 3).every((value) => BigInt(value) <= 0xffffffffn) &&
      BigInt(fields[3]) <= 0xffffffffffffffffn &&
      BigInt(fields[3]) > 0 &&
      BigInt(fields[4]) > 0 &&
      BigInt(fields[4]) <= 0x7fffffffffffffffn &&
      BigInt(fields[5]) < 1000000000n &&
      fields.slice(6, 8).every((value) => BigInt(value) <= 0xffffffffn) &&
      /^[0-7]{1,6}$/u.test(fields[8]) &&
      /^[a-f0-9]{32}$/u.test(fields[9]) &&
      fields[9] !== "0".repeat(32),
  );
  need((Number.parseInt(fields[8], 8) & 0o170000) === 0o100000);
  return {
    object: {
      identity: file.identity,
      uid: Number(fields[6]),
      gid: Number(fields[7]),
      mode: Number.parseInt(fields[8], 8) & 0o7777,
    },
    sha256: file.sha256,
  };
}
/** A failed independent inventory must still settle the native observer. Keep
 * the first failure; successful retirement cannot repair missing evidence. */
export async function settleDarwinCommandCustody(sessions, effects) {
  let domain, verifier, failure;
  const retired = [];
  try {
    domain = await effects.retireDomain();
    need(
      domain.empty === true &&
        typeof domain.emergency === "boolean" &&
        Array.isArray(domain.sessions) &&
        domain.sessions.length === sessions.size &&
        new Set(domain.sessions).size === domain.sessions.length &&
        domain.sessions.every((asid) => sessions.has(asid)),
    );
    for (const asid of domain.sessions) {
      try {
        const fresh = await effects.verifySession(asid);
        need(fresh.empty === true);
        retired.push(fresh);
      } catch (error) {
        nativeException(
          "darwin/feasibility-command-effects.js:exception",
          error,
        );
        failure ??= error;
      }
    }
    need(domain.serverClean === true);
  } catch (error) {
    nativeException("darwin/feasibility-command-effects.js:exception", error);
    failure ??= error;
  }
  try {
    await effects.closeObserver();
  } catch (error) {
    nativeException("darwin/feasibility-command-effects.js:exception", error);
    failure ??= error;
  }
  try {
    verifier = await effects.verifyObserver();
    need(verifier.status === "RETIRED");
  } catch (error) {
    nativeException("darwin/feasibility-command-effects.js:exception", error);
    failure ??= error;
  }
  if (failure) {
    failure.emergency = domain?.emergency === true;
    throw failure;
  }
  return { domain, retired, verifier };
}
/** Removal uses original native ownership receipts, never a replacement's
 * freshly observed identity. Validate the whole set before deleting any leaf. */
export function darwinCommandCleanupArguments(value, final, parents) {
  const files = Object.values(value.files);
  need(
    files.length === 3 &&
      final.length === 3 &&
      parents.length === 2 &&
      value.fileIdentities.length === 3 &&
      value.parentIdentities.length === 2,
  );
  need(
    parents.every(
      (entry, index) =>
        entry.sha256 === null &&
        entry.identity === value.parentIdentities[index],
    ),
  );
  need(
    final.every(
      (entry, index) =>
        darwinCommandFileObservation(entry) &&
        entry.identity === value.fileIdentities[index],
    ) && digest(JSON.stringify(final[2])) === value.sentinelSha256,
  );
  return files.map((file, index) => [
    "remove",
    path.dirname(file),
    path.basename(file),
    value.fileIdentities[index],
    value.parentIdentities[index === 2 ? 0 : 1],
  ]);
}
function commandDeadline() {
  return Object.assign(new Error("Command deadline"), {
    code: "ERR_FEASIBILITY_DEADLINE",
  });
}

function commandWait(promise, signal) {
  if (signal.aborted) return Promise.reject(commandDeadline());
  return new Promise((resolve, reject) => {
    const abort = () => reject(commandDeadline());
    signal.addEventListener("abort", abort, { once: true });
    promise
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
  });
}

// Exec changes pidversion, not the admitted birth, credentials or audit domain.
function commandExecIdentity(parked, frame, imageSha256) {
  const target = normalizeDarwinIdentity(frame.identity);
  need(
    frame.imageSha256 === imageSha256 &&
      target.pidVersion !== parked.pidVersion &&
      sameDarwinIdentity(parked, { ...target, pidVersion: parked.pidVersion }),
  );
  return target;
}

/** Keep the original stream and native custody through cancellation. A rejected
 * request, closed stream or reaped broker supplies no independent retirement. */
export function observeDarwinCommandBroker(
  broker,
  value,
  { signal, decoder, tokens, admittedSessions, coldStart, coldExec },
) {
  const pending = new Map(),
    cold = new Map(),
    rpc = new PassThrough(),
    errorOutput = new PassThrough(),
    input = new PassThrough();
  let failed,
    captureFailure,
    captureFinished = false,
    stopping = false,
    admissionsClosed = false,
    interrupted = false,
    exit,
    total = 0;
  const interrupt = () => {
    if (interrupted || exit) return;
    interrupted = true;
    try {
      // sudo forwards this to the held helper. Its existing non-restarting
      // signal handler enters bounded native failure settlement.
      broker.kill("SIGTERM");
    } catch (error) {
      try {
        nativeException("darwin-command-cancellation", error);
      } catch {
        /* Diagnostics cannot replace the original cancellation. */
      }
    }
  };
  const fail = (error, capture = true) => {
    const pendingWork = [...pending.values()].some(
      (entry) => !entry.settlement,
    );
    failed ??= error;
    if (capture) captureFailure ??= error;
    admissionsClosed = true;
    for (const entry of [...pending.values()])
      if (!entry.settlement) entry.reject(failed);
    if (capture || pendingWork) interrupt();
    try {
      nativeException("darwin-command-broker", error);
    } catch {
      /* Keep settling original custody if the diagnostic sink fails. */
    }
  };
  const abortWork = () => fail(commandDeadline(), false),
    fence = () => {
      admissionsClosed = true;
      signal.removeEventListener("abort", abortWork);
    },
    send = (frame) => {
      need(broker.stdin.writable && !broker.stdin.destroyed && !exit);
      try {
        broker.stdin.write(frame, (error) => {
          if (error) fail(error);
        });
      } catch (error) {
        fail(error);
        throw error;
      }
    },
    request = (operation, active, settlement = false) => {
      if (active.aborted) return Promise.reject(commandDeadline());
      need(!pending.has(operation));
      return new Promise((resolve, reject) => {
        const settle = (fn, result) => {
            if (pending.get(operation) !== entry) return;
            pending.delete(operation);
            active.removeEventListener("abort", abort);
            fn(result);
          },
          abort = () => {
            if (settlement) {
              entry.reject(commandDeadline());
              interrupt();
            } else abortWork();
          },
          entry = {
            settlement,
            resolve: (result) => settle(resolve, result),
            reject: (error) => settle(reject, error),
          };
        pending.set(operation, entry);
        active.addEventListener("abort", abort, { once: true });
      });
    },
    call = async (operation, active = signal) => {
      const settlement = ["D", "S"].includes(operation);
      if (operation === "D") fence();
      if (!settlement) {
        if (failed) throw failed;
        need(!admissionsClosed && active === signal);
      }
      if (active.aborted) throw commandDeadline();
      need(broker.stdin.writable && !broker.stdin.destroyed && !exit);
      const response = request(operation, active, settlement);
      try {
        send(operation + "\n");
      } catch (error) {
        pending.get(operation)?.reject(error);
      }
      return response;
    };
  input.on("data", (chunk) => {
    if (signal.aborted || admissionsClosed || failed || chunk.length > 65536) {
      fail(new Error("Command transport closed"));
      return;
    }
    try {
      send("J " + chunk.toString("hex") + "\n");
    } catch (error) {
      fail(error);
    }
  });
  input.on("end", () => {
    if (!failed && !admissionsClosed) {
      try {
        send("E\n");
      } catch (error) {
        fail(error);
      }
    }
  });
  broker.on("error", fail);
  broker.stdin.on("error", fail);
  broker.stdout.on("error", fail);
  broker.stderr.on("error", fail);
  input.on("error", fail);
  rpc.on("error", fail);
  errorOutput.on("error", fail);
  const closed = new Promise((resolve) =>
    broker.once("close", (code, signal) => {
      exit = { code, signal };
      fence();
      resolve(exit);
    }),
  );
  observeNativeProcess("darwin/feasibility-command-effects.js", broker);
  broker.stderr.on("data", (bytes) => {
    total += bytes.length;
    if (total > 8388608) fail(new Error("Native capture exceeded bound"));
  });
  const ready = request("ready", signal);
  ready.catch(() => {});
  signal.addEventListener("abort", abortWork, { once: true });
  if (signal.aborted) abortWork();
  const observation = (async () => {
    try {
      for await (const line of createInterface({
        input: broker.stdout,
        crlfDelay: Infinity,
      })) {
        try {
          need(line.length <= 524288);
          total += Buffer.byteLength(line);
          const frame = JSON.parse(line);
          if (
            captureFailure &&
            !["ready", "D", "S", "custody"].includes(frame.event)
          )
            continue;
          need(captureFailure || total <= 33554432);
          if (frame.event === "audit") {
            need(/^(?:[a-f0-9]{2}){18,65536}$/u.test(frame.hex));
            const bytes = Buffer.from(frame.hex, "hex"),
              header = Buffer.alloc(4);
            header.writeUInt32BE(bytes.length);
            tokens.set(digest(bytes), frame.tokens);
            await decoder.push(Buffer.concat([header, bytes]));
          } else if (frame.event === "barrier") {
            const bytes = Buffer.alloc(16);
            [
              0xfffffffe,
              frame.sequence,
              frame.seconds,
              frame.milliseconds,
            ].forEach((v, i) => bytes.writeUInt32BE(v, i * 4));
            await decoder.push(bytes);
            const entry = pending.get("B");
            need(entry || failed);
            entry?.resolve(decoder.acknowledgement(frame.sequence));
          } else if (["rpc-end", "stderr-end"].includes(frame.event)) {
            (frame.event === "rpc-end" ? rpc : errorOutput).end();
          } else if (["rpc", "stderr"].includes(frame.event)) {
            need(/^(?:[a-f0-9]{2}){1,65536}$/u.test(frame.hex));
            const bytes = Buffer.from(frame.hex, "hex");
            nativeDiagnostic(`darwin-command:${frame.event}`, {
              [frame.event === "stderr" ? "stderr" : "stdout"]: bytes,
            });
            const output = frame.event === "rpc" ? rpc : errorOutput;
            need(!output.writableEnded);
            output.write(bytes);
          } else if (frame.event === "capture-end") {
            const bytes = Buffer.alloc(12);
            [0xffffffff, frame.bytes, frame.records].forEach((v, i) =>
              bytes.writeUInt32BE(v, i * 4),
            );
            await decoder.push(bytes);
            captureFinished = true;
          } else if (frame.event === "cold-start") {
            const identity = normalizeDarwinIdentity(frame.identity);
            need(
              ["V", "G"].includes(frame.operation) &&
                frame.phase === "pre-exec" &&
                !cold.has(frame.operation) &&
                pending.has(frame.operation) &&
                admittedSessions.has(identity.asid) &&
                ["uid", "ruid", "svuid", "auid"].every(
                  (key) => identity[key] === value.uid,
                ) &&
                ["gid", "rgid", "svgid"].every(
                  (key) => identity[key] === value.gid,
                ) &&
                frame.imageSha256 === value.commandImageSha256 &&
                typeof coldStart === "function",
            );
            const entry = { identity, armed: false, target: null };
            cold.set(frame.operation, entry);
            await coldStart({ ...frame, identity }, (error) => {
              if (pending.has(frame.operation)) fail(error);
            });
            need(!failed && !admissionsClosed && !signal.aborted);
            entry.armed = true;
            send("T\n");
          } else if (frame.event === "exec") {
            const entry = cold.get(frame.operation);
            need(entry?.armed && !entry.target && pending.has(frame.operation));
            entry.target = commandExecIdentity(
              entry.identity,
              frame,
              value.commandImageSha256,
            );
            need(typeof coldExec === "function");
            await coldExec({ ...frame, identity: entry.target });
            need(!failed && !admissionsClosed && !signal.aborted);
            send("E\n");
          } else if (frame.event === "custody") {
            need(
              frame.sessionHeld === true &&
                Number.isInteger(frame.identity.asid) &&
                frame.identity.asid > 0 &&
                admittedSessions.size < 16 &&
                !admittedSessions.has(frame.identity.asid),
            );
            admittedSessions.add(frame.identity.asid);
          } else {
            if (frame.event === "ready") {
              need(!value.observer);
              value.observer = normalizeDarwinIdentity(frame.identity);
              need(
                ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
                  (key) => value.observer[key] === 0,
                ) && frame.imageSha256 === value.helperSha256,
              );
              await decoder.push(Buffer.alloc(4));
            }
            if (["V", "G"].includes(frame.event))
              need(cold.get(frame.event)?.target);
            const entry = pending.get(frame.event);
            need(
              entry ||
                (failed &&
                  ["ready", "V", "G", "A", "R", "C", "N", "F"].includes(
                    frame.event,
                  )),
            );
            if (frame.event === "S") stopping = true;
            entry?.resolve(frame);
          }
        } catch (error) {
          fail(error);
        }
      }
      if (!stopping)
        throw new Error("Native observation stream closed before settlement");
    } catch (error) {
      fail(error);
      throw error;
    }
  })();
  observation.catch(() => {});
  // A close event can precede asynchronous decoding of its last custody frame.
  // Drain that same reader before rejecting requests lacking a final response.
  closed.then(async () => {
    try {
      await observation;
    } catch {
      /* Capture failure remains latched. */
    }
    rpc.end();
    errorOutput.end();
    for (const entry of [...pending.values()])
      entry.reject(Object.assign(new Error("Native custody closed"), exit));
  });
  return {
    ready,
    closed,
    observation,
    call,
    cancel: (error) => fail(error, false),
    send(frame) {
      if (failed) throw failed;
      need(!admissionsClosed && !signal.aborted);
      send(frame);
    },
    transport: { input, output: rpc, errorOutput },
    get captureFailure() {
      return captureFailure;
    },
    get captureFinished() {
      return captureFinished;
    },
    async close(active) {
      let failure, result;
      try {
        await call("S", active);
      } catch (error) {
        failure = error;
      }
      try {
        result = await commandWait(closed, active);
        await commandWait(observation, active);
      } catch (error) {
        failure ??= error;
      }
      if (failure) throw failure;
      return result;
    },
  };
}

export function createDarwinCommandEffects(dispatch, inputs) {
  let root,
    helper,
    broker,
    command,
    decoder,
    sequence = 0,
    prepared,
    serverParked,
    active = false;
  const tokens = new Map(),
    admittedSessions = new Set(),
    coldTraces = new Map();
  const nativeArgs = (args, environment = env) => [
    "-n",
    "/usr/bin/env",
    "-i",
    ...Object.entries(environment).map(([k, v]) => `${k}=${v}`),
    helper,
    ...args,
  ];
  const native = async (args, signal) =>
    execute("/usr/bin/sudo", nativeArgs(args), {
      env,
      signal,
      timeout: 10000,
      maxBuffer: 1048576,
    });
  const call = (operation, signal) => command.call(operation, signal);
  const finishColdTrace = async (operation, requireComplete = false) => {
    const entry = coldTraces.get(operation);
    if (!entry) {
      need(!requireComplete);
      return;
    }
    const trace = (entry.result ??= await entry.trace.finish());
    if (!entry.reported) {
      const report = JSON.stringify({ ...entry.binding, trace });
      nativeDiagnostic("darwin-command:cold-startup", { stderr: report });
      await writeFile(
        path.join(root, "evidence", `command-${operation}-startup.json`),
        report,
        { flag: "wx", mode: 0o600 },
      );
      entry.reported = true;
    }
    need(["RETIRED", "NOT_RUN"].includes(trace.cleanup));
    if (requireComplete) assertDarwinColdStartupTrace(trace);
  };
  const snapshots = async (signal) =>
    JSON.parse(
      (
        await execute(helper, ["files", ...Object.values(prepared.files)], {
          env,
          signal,
          timeout: 10000,
          maxBuffer: 65536,
        })
      ).stdout,
    );
  return {
    noCustody: () => !active,
    async prepare(nonce, components, signal) {
      if (!(
        process.platform === "darwin" &&
        process.arch === "x64" &&
        process.env.CI === "true" &&
        process.env.RUNNER_OS === "macOS" &&
        process.env.GITHUB_ACTIONS === "true" &&
        process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
        /^[a-f0-9]{40}$/u.test(dispatch.expectedSha) &&
        process.getuid() > 500
      ))
        throw Object.assign(new Error("Matching native worker unavailable"), {
          code: "ERR_FEASIBILITY_UNAVAILABLE",
        });
      try {
        need(
          (
            await execute("/usr/bin/sudo", ["-n", "/usr/bin/id", "-u"], {
              env,
              signal,
              timeout: 10000,
              maxBuffer: 4096,
            })
          ).stdout === "0\n",
        );
      } catch (error) {
        nativeException(
          "darwin/feasibility-command-effects.js:exception",
          error,
        );
        error.feasibilityCause = feasibilityFailureCause(
          "command",
          "root-prerequisite",
          error,
          [1, "EPERM", "EACCES", "ENOENT"].includes(error.code)
            ? "prerequisite-unavailable"
            : "setup-failed",
        );
        throw error;
      }
      root = await realpath(
        await mkdtemp(
          path.join(
            await realpath(process.env.RUNNER_TEMP),
            "native-darwin-command-",
          ),
        ),
      );
      await chmod(root, 0o700);
      // Darwin creations inherit the temporary parent's group. Keep the shared
      // native group check strict by normalizing only this owned private root.
      const owner = await lstat(root);
      need(
        owner.isDirectory() &&
          !owner.isSymbolicLink() &&
          owner.uid === process.getuid() &&
          (owner.mode & 0o7777) === 0o700,
      );
      await chown(root, -1, process.getgid());
      for (const name of [
        "build",
        "evidence",
        "workspace",
        "home",
        "schema-home",
        "schema",
      ])
        await mkdir(path.join(root, name), { mode: 0o700 });
      await buildDarwinFeasibility(root, components, {
        commandObservation: true,
        executeFile: (file, args, options) =>
          execute(file, args, { ...options, signal }),
      });
      helper = path.join(root, "build/helper");
      const build = JSON.parse(
          await readFile(path.join(root, "evidence/build.json")),
        ),
        args = build.builds[0].args,
        sdk = args[args.indexOf("-isysroot") + 1];
      need(
        build.builds[0].handoffSourceSha256 ===
          digest(await readFile(new URL("./exec-handoff.h", import.meta.url))),
      );
      need(
        build.builds[0].imageClosureSourceSha256 ===
          digest(await readFile(new URL("./image-closure.h", import.meta.url))),
      );
      const abi = await readFile(
        path.join(sdk, "usr/include/bsm/audit_record.h"),
      );
      const home = path.join(root, "home"),
        workspace = path.join(root, "workspace"),
        files = {
          inspect: path.join(workspace, "inspection.txt"),
          edit: path.join(workspace, "edit.txt"),
          outside: path.join(root, "outside.txt"),
        };
      need((await readdir(home)).length === 0);
      for (const file of Object.values(files))
        await writeFile(file, nonce, { flag: "wx", mode: 0o600 });
      // This outer policy permits all fixture writes. Its denial cannot satisfy
      // a stock command-sandbox case; the native outside control proves that.
      await writeFile(
        path.join(root, "admission.sb"),
        [
          "(version 1)",
          "(deny default)",
          "(allow process-fork)",
          "(allow process-exec)",
          "(allow file-read*)",
          "(allow file-map-executable)",
          '(allow sysctl-read (sysctl-name "hw.pagesize"))',
          '(allow sysctl-read (sysctl-name "hw.pagesize_compat"))',
          "(allow process-info* (target same-sandbox))",
          `(allow file-write* (subpath ${JSON.stringify(root)}) (literal \"/dev/null\"))`,
          "",
        ].join("\n"),
        { flag: "wx", mode: 0o600 },
      );
      const prerequisites = JSON.parse(
        (
          await native(
            [
              "command-prerequisites",
              root,
              String(process.getuid()),
              String(process.getgid()),
            ],
            signal,
          )
        ).stdout,
      );
      need(
        prerequisites.audit === true &&
          prerequisites.admission === true &&
          prerequisites.completeRetirement === true,
      );
      const mapping = {
        headerVersion: prerequisites.headerVersion,
        events: prerequisites.events,
      };
      prerequisites.mapping = {
        ...mapping,
        mappingSha256: digest(JSON.stringify(mapping)),
        sdkSha256: components.find(({ name }) => name === "macos-sdk").sha256,
        abiSha256: digest(abi),
      };
      prepared = {
        root,
        helper,
        home,
        workspace,
        files,
        nonce,
        uid: process.getuid(),
        gid: process.getgid(),
        environment: darwinCommandEnvironment(
          home,
          path.dirname(inputs.packages.codex.file),
        ),
        gate: path.join(workspace, ".command-gate"),
        helperSha256: digest(await readFile(helper)),
        commandImageSha256: inputs.packages.codex.component.sha256,
        ...prerequisites,
      };
      const before = await snapshots(signal),
        parents = JSON.parse(
          (
            await execute(helper, ["files", root, workspace], {
              env,
              signal,
              timeout: 10000,
              maxBuffer: 65536,
            })
          ).stdout,
        );
      prepared.fileIdentities = before.map(({ identity }) => identity);
      prepared.parentIdentities = parents.map(({ identity }) => identity);
      prepared.sentinelSha256 = digest(JSON.stringify(before[2]));
      decoder = createDarwinAuditDecoder(
        {
          bsm: async (bytes) => {
            const key = digest(bytes),
              value = tokens.get(key);
            need(value);
            tokens.delete(key);
            return value;
          },
        },
        prerequisites.mapping,
      );
      return prepared;
    },
    cancel: (error) => command?.cancel(error),
    async schema(value, signal) {
      signal.throwIfAborted();
      const codex = inputs.packages.codex;
      broker = spawn(
        "/usr/bin/sudo",
        nativeArgs(
          [
            "command-broker",
            root,
            codex.file,
            codex.component.sha256,
            String(value.uid),
            String(value.gid),
            value.nonce,
            value.helperSha256,
          ],
          value.environment,
        ),
        { env, stdio: ["pipe", "pipe", "pipe"] },
      );
      active = true;
      command = observeDarwinCommandBroker(broker, value, {
        signal,
        decoder,
        tokens,
        admittedSessions,
        coldExec: async ({ operation, identity }) => {
          const entry = coldTraces.get(operation);
          need(entry && !entry.binding.targetIdentity);
          need(
            (await entry.trace.bindExec(identity, signal)).status === "bound",
          );
          entry.binding.targetIdentity = identity;
        },
        coldStart: async (
          { operation, identity, imageSha256, policyFileSha256 },
          onFailure,
        ) => {
          need(!coldTraces.has(operation) && coldTraces.size < 2);
          const binding = {
              identity,
              imageSha256,
              operation,
              traceIntent: DARWIN_COLD_STARTUP_TRACE_INTENT,
              policyFileSha256: digest(
                await readFile(path.join(root, "admission.sb")),
              ),
            },
            observe = (selector, value) =>
              startupObserver(root, selector, value, prepared.helperSha256),
            trace = openDarwinStartupTrace(binding, {
              coldCommand: true,
              onFailure,
              readObserver: (pid) => observe("startup-observer", pid),
              observeObserver: (value) =>
                observe("startup-observer-observe", value),
              retireObserver: (value) =>
                observe("startup-observer-retire", value),
            });
          need(policyFileSha256 === binding.policyFileSha256);
          coldTraces.set(operation, { trace, binding });
          need((await trace.arm()).status === "armed");
        },
      });
      value.transport = command.transport;
      await command.ready;
      const version = await call("V", signal);
      need(version.stdout === "codex-cli 0.160.0\n" && version.exitCode === 0);
      await finishColdTrace("V", true);
      const schema = await call("G", signal);
      need(schema.exitCode === 0);
      await finishColdTrace("G", true);
      const readSchema = async (name) => {
        const file = path.join(root, "schema/v2", name),
          st = await lstat(file);
        need(
          (await realpath(file)) === file &&
            st.isFile() &&
            !st.isSymbolicLink() &&
            st.nlink === 1 &&
            st.size > 0 &&
            st.size <= 1048576,
        );
        return JSON.parse(await readFile(file));
      };
      return {
        params: await readSchema("CommandExecParams.json"),
        response: await readSchema("CommandExecResponse.json"),
      };
    },
    async arm(value) {
      need((await readdir(value.home)).length === 0);
      const response = await call("A");
      need(
        !serverParked &&
          response.phase === "pre-exec" &&
          response.imageSha256 === inputs.packages.codex.component.sha256 &&
          response.policyFileSha256 ===
            digest(await readFile(path.join(root, "admission.sb"))),
      );
      serverParked = normalizeDarwinIdentity(response.identity);
      value.asid = serverParked.asid;
      return {
        ...response,
        captureReady: true,
        sessionHeld: response.sessionHeld,
        transport: value.transport,
      };
    },
    async release() {
      need(serverParked);
      const response = await call("R");
      commandExecIdentity(
        serverParked,
        response,
        inputs.packages.codex.component.sha256,
      );
      serverParked = null;
      return response;
    },
    async control() {
      const start = await call("B"),
        response = await call("C"),
        end = await call("B");
      need(end.sequence === start.sequence + 1);
      return {
        permitted: response.permitted,
        reply: { exitCode: response.exitCode, stdout: response.stdout },
        observation: {
          ...response,
          object: {
            before: darwinCommandFileObservation(response.object.before),
            after: darwinCommandFileObservation(response.object.after),
          },
          events: decoder.window(start.sequence, end.sequence),
          barrierSha256: start.barrierSha256,
        },
      };
    },
    async begin(value, spec) {
      sequence = (await call("B")).sequence;
      command.send(`K ${spec.action}\n`);
    },
    async observe(value, spec) {
      const admitted = await call("N"),
        after = await call("F"),
        end = await call("B");
      need(end.sequence === sequence + 1);
      return {
        before: admitted.identity,
        after: after.identity,
        imageSha256: after.imageSha256,
        sandboxed: admitted.sandboxed && after.sandboxed,
        events: decoder.window(sequence, end.sequence),
        barrierSha256: decoder.acknowledgement(sequence).barrierSha256,
        object: {
          before: darwinCommandFileObservation(admitted.object),
          after: darwinCommandFileObservation(after.object),
        },
        gate: { before: admitted.gate, after: after.gate },
      };
    },
    async retire(value, signal) {
      if (!broker) throw new Error("No native custody was admitted");
      // Stop admissions first; retain the audit-session right through the fresh
      // external all-UID kernel inventory, then retire the observer itself.
      let exit, settled, failure;
      try {
        settled = await settleDarwinCommandCustody(admittedSessions, {
          retireDomain: () => call("D", signal),
          verifySession: async (asid) =>
            JSON.parse(
              (await native(["command-verify", String(asid)], signal)).stdout,
            ),
          closeObserver: async () => {
            exit = await command.close(signal);
          },
          verifyObserver: async () => {
            const verifier = JSON.parse(
              (
                await native(
                  [
                    "command-observe",
                    ...darwinFeasibilityIdentityArguments(value.observer),
                  ],
                  signal,
                )
              ).stdout,
            );
            need(verifier.status === "RETIRED");
            return verifier;
          },
        });
      } catch (error) {
        failure = error;
      }
      // On a failed cold request the domain retires first. Every trace still
      // settles through its original outside observer, including attach failure.
      for (const operation of coldTraces.keys()) {
        try {
          await finishColdTrace(operation);
        } catch (error) {
          failure ??= error;
        }
      }
      if (failure) {
        failure.emergency =
          failure.emergency === true || settled?.domain.emergency === true;
        throw failure;
      }
      active = false;
      try {
        need(
          !command.captureFailure &&
            command.captureFinished &&
            tokens.size === 0,
        );
        decoder.finish(exit);
      } catch (error) {
        nativeException(
          "darwin/feasibility-command-effects.js:exception",
          error,
        );
        error.emergency = settled.domain.emergency;
        throw error;
      }
      return {
        independent: true,
        completeDomain: true,
        sessionHeldUntilEmpty: true,
        admissionsClosed: true,
        serverRetired: true,
        helpersRetired: true,
        observerRetired: true,
        emergency: settled.domain.emergency,
        witnessSha256: digest(JSON.stringify(settled)),
      };
    },
    async finish(value, signal) {
      const final = await snapshots(signal),
        parents = JSON.parse(
          (
            await execute(helper, ["files", root, value.workspace], {
              env,
              signal,
              timeout: 10000,
              maxBuffer: 65536,
            })
          ).stdout,
        );
      for (const args of darwinCommandCleanupArguments(value, final, parents))
        await execute(helper, args, {
          env,
          signal,
          timeout: 10000,
          maxBuffer: 65536,
        });
      return {
        sentinelSha256: digest(JSON.stringify(final[2])),
        witnessSha256: digest(JSON.stringify({ final, parents })),
      };
    },
  };
}
