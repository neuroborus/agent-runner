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
  buildDarwinFeasibility,
  darwinFeasibilityIdentityArguments,
} from "./feasibility.js";
import { feasibilityFailureCause } from "../feasibility/index.js";
import { createDarwinAuditDecoder } from "./audit.js";
import { digest, normalizeDarwinIdentity } from "./protocol.js";

const execute = promisify(execFile);
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
        failure ??= error;
      }
    }
    need(domain.serverClean === true);
  } catch (error) {
    failure ??= error;
  }
  try {
    await effects.closeObserver();
  } catch (error) {
    failure ??= error;
  }
  try {
    verifier = await effects.verifyObserver();
    need(verifier.status === "RETIRED");
  } catch (error) {
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
export function createDarwinCommandEffects(dispatch, inputs) {
  let root,
    helper,
    broker,
    closed,
    decoder,
    sequence = 0,
    prepared,
    failed,
    active = false,
    captureFinished,
    observation,
    observationSignal,
    admissionsClosed = false;
  const pending = new Map(),
    tokens = new Map(),
    admittedSessions = new Set();
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
  const call = (operation) => {
    const settlement = ["D", "S"].includes(operation);
    need(
      (!failed || settlement) &&
        broker?.stdin.writable &&
        !broker.stdin.destroyed &&
        !pending.has(operation),
    );
    if (!settlement) need(!admissionsClosed && !observationSignal.aborted);
    if (operation === "D") admissionsClosed = true;
    return new Promise((resolve, reject) => {
      pending.set(operation, { resolve, reject, settlement });
      broker.stdin.write(operation + "\n");
    });
  };
  const fail = (error) => {
    failed ??= error;
    for (const [key, entry] of pending) {
      if (!entry.settlement) {
        entry.reject(failed);
        pending.delete(key);
      }
    }
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
    async schema(value, signal) {
      signal.throwIfAborted();
      observationSignal = signal;
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
      const rpc = new PassThrough(),
        errorOutput = new PassThrough(),
        input = new PassThrough();
      input.on("data", (chunk) => {
        if (
          signal.aborted ||
          admissionsClosed ||
          failed ||
          chunk.length > 65536
        ) {
          fail(new Error("Command transport closed"));
          return;
        }
        broker.stdin.write("J " + chunk.toString("hex") + "\n");
      });
      input.on("end", () => {
        if (!failed && !admissionsClosed) broker.stdin.write("E\n");
      });
      value.transport = { input, output: rpc, errorOutput };
      broker.on("error", fail);
      broker.stdin.on("error", fail);
      closed = new Promise((resolve) =>
        broker.once("close", (code, signal) => {
          resolve({ code, signal });
          rpc.end();
          errorOutput.end();
          for (const entry of pending.values())
            entry.reject(
              Object.assign(new Error("Native custody closed"), {
                code,
                signal,
              }),
            );
          pending.clear();
        }),
      );
      let total = 0;
      broker.stderr.on("data", (bytes) => {
        total += bytes.length;
        if (total > 8388608) fail(new Error("Native capture exceeded bound"));
      });
      const ready = new Promise((resolve, reject) =>
        pending.set("ready", { resolve, reject }),
      );
      observation = (async () => {
        for await (const line of createInterface({
          input: broker.stdout,
          crlfDelay: Infinity,
        })) {
          try {
            need(line.length <= 524288);
            total += Buffer.byteLength(line);
            const frame = JSON.parse(line);
            if (failed && !["D", "S", "custody"].includes(frame.event))
              continue;
            need(failed || total <= 33554432);
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
              need(entry);
              pending.delete("B");
              entry.resolve(decoder.acknowledgement(frame.sequence));
            } else if (
              frame.event === "rpc-end" ||
              frame.event === "stderr-end"
            ) {
              (frame.event === "rpc-end" ? rpc : errorOutput).end();
            } else if (frame.event === "rpc" || frame.event === "stderr") {
              need(/^(?:[a-f0-9]{2}){1,65536}$/u.test(frame.hex));
              (frame.event === "rpc" ? rpc : errorOutput).write(
                Buffer.from(frame.hex, "hex"),
              );
            } else if (frame.event === "capture-end") {
              const bytes = Buffer.alloc(12);
              [0xffffffff, frame.bytes, frame.records].forEach((v, i) =>
                bytes.writeUInt32BE(v, i * 4),
              );
              await decoder.push(bytes);
              captureFinished = true;
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
                value.observer = normalizeDarwinIdentity(frame.identity);
                need(
                  ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
                    (key) => value.observer[key] === 0,
                  ) && frame.imageSha256 === value.helperSha256,
                );
                await decoder.push(Buffer.alloc(4));
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
      observation.catch(fail);
      await ready;
      const version = await call("V");
      need(version.stdout === "codex-cli 0.160.0\n" && version.exitCode === 0);
      need((await call("G")).exitCode === 0);
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
      value.asid = response.identity.asid;
      return {
        ...response,
        captureReady: true,
        sessionHeld: response.sessionHeld,
        transport: value.transport,
      };
    },
    release: () => call("R"),
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
      need(!failed);
      sequence = (await call("B")).sequence;
      need(!observationSignal.aborted && !admissionsClosed);
      broker.stdin.write(`K ${spec.action}\n`);
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
      let exit;
      const settled = await settleDarwinCommandCustody(admittedSessions, {
        retireDomain: () => call("D"),
        verifySession: async (asid) =>
          JSON.parse(
            (await native(["command-verify", String(asid)], signal)).stdout,
          ),
        closeObserver: async () => {
          let failure;
          try {
            await call("S");
          } catch (error) {
            failure = error;
          }
          try {
            exit = await closed;
            await observation;
          } catch (error) {
            failure ??= error;
          }
          if (failure) throw failure;
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
          active = false;
          return verifier;
        },
      });
      try {
        need(!failed && captureFinished && tokens.size === 0);
        decoder.finish(exit);
      } catch (error) {
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
