import { spawn, execFile } from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { promisify } from "node:util";
import {
  normalizeDarwinIdentity,
  sameDarwinIdentity,
  darwinIdentityArguments,
} from "./protocol.js";

const PRIVILEGED_ENV = [
  "CI=true",
  "GITHUB_ACTIONS=true",
  "RUNNER_ENVIRONMENT=github-hosted",
  "RUNNER_OS=macOS",
  "PATH=/usr/bin:/bin",
  "LANG=C",
  "GIT_CONFIG_NOSYSTEM=1",
  "GIT_CONFIG_GLOBAL=/dev/null",
];

const need = (value) => {
  if (!value) throw new Error("Incomplete Darwin fault-domain custody");
};
export const feasibilityDomainPath = (nonce) => {
  need(/^[a-f0-9]{32}$/u.test(nonce));
  return `/private/var/run/native-feasibility-${nonce}`;
};

/** Fixed privileged channel and the original unprivileged helper's stdio stay
 * distinct. Numeric PIDs locate observations; complete identities own effects. */
export async function openDarwinFaultDomain(
  root,
  candidate,
  caseId,
  nonce,
  helperHash,
  policyHash,
  env,
  openSession,
  {
    launch = spawn,
    execute = promisify(execFile),
    uid = process.getuid(),
    gid = process.getgid(),
  } = {},
) {
  const directory = feasibilityDomainPath(nonce),
    helper = directory + "/helper";
  const owner = launch(
    "/usr/bin/sudo",
    [
      "-n",
      "--",
      "/usr/bin/env",
      "-i",
      ...PRIVILEGED_ENV,
      root + "/build/helper",
      "fault-domain",
      root,
      candidate,
      caseId,
      nonce,
      helperHash,
      policyHash,
      String(uid),
      String(gid),
    ],
    { cwd: root, env, stdio: ["pipe", "pipe", "pipe"] },
  );
  let sequence = 0,
    pending,
    ready,
    failed,
    bytes = Buffer.alloc(0),
    stderr = Buffer.alloc(0),
    total = 0;
  const virtual = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  const fail = (error) => {
    failed ??= error;
    failed.stderr ??= stderr;
    pending?.reject(failed);
    pending = null;
    ready?.reject(failed);
    // The payload protocol annotates its errors; retain the custody cause intact.
    virtual.emit("error", Object.assign(new Error(failed.message), failed));
  };
  // The original protocol attaches its own error listener after ready.
  virtual.on("error", () => {});
  const rpc = async (operation, ...args) => {
    need(!failed && !pending);
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        fail(new Error("Fault custody reply deadline"));
      }, 12000);
      pending = {
        id,
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
      owner.stdin.write(
        `${id} ${operation}${args.length ? " " + args.join(" ") : ""}\n`,
        (error) => {
          if (error) fail(error);
        },
      );
    });
  };
  virtual.stdin = new Writable({
    write(chunk, encoding, done) {
      rpc("payload", chunk.toString()).then(() => done(), done);
    },
  });
  let close;
  const closed = new Promise((resolve) => {
    close = resolve;
  });
  const settle = async () => {
    let timer;
    try {
      const exit = await Promise.race([
        closed,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            fail(
              Object.assign(new Error("Fault custody closure deadline"), {
                code: "ERR_FEASIBILITY_DEADLINE",
              }),
            );
            reject(failed);
          }, 12000);
        }),
      ]);
      if (failed) throw failed;
      need(exit.code === 0 && exit.signal === null);
    } finally {
      clearTimeout(timer);
    }
  };
  owner.on("error", fail);
  owner.stdin.on("error", fail);
  owner.stderr.on("data", (chunk) => {
    total += chunk.length;
    const length = stderr.length + chunk.length;
    stderr = Buffer.concat([stderr, chunk.subarray(0, 65536 - stderr.length)]);
    if (length > 65536 || total > 262144)
      fail(new Error("Fault custody output bound"));
  });
  owner.stdout.on("error", fail);
  owner.stderr.on("error", fail);
  owner.stdout.on("data", (chunk) => {
    try {
      total += chunk.length;
      need(total <= 262144);
      bytes = Buffer.concat([bytes, chunk]);
      for (let end; (end = bytes.indexOf(10)) >= 0;) {
        const value = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            bytes.subarray(0, end),
          ),
        );
        bytes = bytes.subarray(end + 1);
        if (value.ready) {
          need(ready);
          ready.resolve(value.ready);
          ready = null;
        } else if (value.stream) {
          need(
            ["stdout", "stderr"].includes(value.stream) &&
              /^(?:[a-f0-9]{2})*$/u.test(value.hex),
          );
          virtual[value.stream].write(Buffer.from(value.hex, "hex"));
        } else {
          need(pending && value.sequence === pending.id);
          const request = pending;
          pending = null;
          request.resolve(value.value);
        }
      }
    } catch (error) {
      fail(error);
    }
  });
  owner.once("close", (code, signal) => {
    if (bytes.length || pending || ready || code !== 0 || signal)
      fail(
        Object.assign(
          new Error("Fault custody closed without complete evidence"),
          {
            code,
            exitCode: code,
            signal,
          },
        ),
      );
    close({ code, signal });
  });
  const initial = await new Promise((resolve, reject) => {
    ready = { resolve, reject };
    const timer = setTimeout(() => {
      if (ready) fail(new Error("Fault custody admission deadline"));
    }, 12000);
    closed.finally(() => clearTimeout(timer));
  });
  const custodian = normalizeDarwinIdentity(initial.custodian);
  need(
    initial.candidateSha === candidate &&
      initial.caseId === caseId &&
      initial.stage === 1 &&
      initial.helperSha256 === helperHash &&
      initial.policySha256 === policyHash &&
      initial.asid > 0 &&
      custodian.asid !== initial.asid,
  );
  virtual.pid = initial.owner.pid;
  const running = openSession(
    root,
    "exec",
    [root + `/evidence/${caseId}.sb`, root + "/build/helper", "fault"],
    { launch: () => virtual },
  );
  let faulted = false,
    finalized = false,
    admission;
  const witness = async (record, finished = false) => {
    const { stdout } = await execute(
      "/usr/bin/sudo",
      [
        "-n",
        "--",
        "/usr/bin/env",
        "-i",
        ...PRIVILEGED_ENV,
        helper,
        finished ? "fault-closed" : "fault-verify",
        nonce,
        record.receiptSha256,
      ],
      { cwd: root, env, timeout: 12000, maxBuffer: 65536 },
    );
    const value = JSON.parse(stdout);
    need(
      value.independent === true &&
        value.complete === true &&
        value.held === !finished &&
        JSON.stringify(value.record) === JSON.stringify(record),
    );
    const verifier = normalizeDarwinIdentity(value.verifier);
    need(verifier.pid !== custodian.pid && verifier.asid !== initial.asid);
    return value;
  };
  return {
    running: {
      ...running,
      failure: () => failed ?? running.failure(),
      finish: async () => {
        need(faulted);
      },
      waitClosed: async () => {
        need(faulted);
      },
    },
    parentPid: custodian.pid,
    helper,
    policyHash,
    initial,
    inspect: async (_root, operation, ...args) => {
      if (operation === "files") return rpc("files");
      if (operation === "cancel" || operation === "retire") {
        need(
          admission &&
            JSON.stringify(args) ===
              JSON.stringify(darwinIdentityArguments(admission.owner)),
        );
        const result = await rpc("fault");
        faulted = true;
        // Drain final original payload output before closing its virtual stdio.
        virtual.stdout.end();
        virtual.stderr.end();
        virtual.emit(
          "close",
          null,
          caseId === "cancel" ? "SIGTERM" : "SIGKILL",
        );
        return result;
      }
      return rpc(
        operation,
        ...args.slice(0, operation === "identity" ? 2 : 12),
      );
    },
    intent: async (pin) => {
      const record = await rpc("intent", pin);
      admission = record;
      need(
        record.stage === 2 &&
          record.intentSha256 === pin &&
          record.asid === initial.asid &&
          record.owner.pidVersion > initial.owner.pidVersion &&
          [
            "pid",
            "auid",
            "uid",
            "gid",
            "ruid",
            "rgid",
            "svuid",
            "svgid",
            "asid",
            "startSeconds",
            "startMicroseconds",
          ].every((field) => record.owner[field] === initial.owner[field]) &&
          sameDarwinIdentity(record.custodian, custodian),
      );
      return record;
    },
    retire: async () => {
      const record = await rpc("retire");
      need(
        record.stage === 5 &&
          record.candidateSha === candidate &&
          record.caseId === caseId &&
          sameDarwinIdentity(record.custodian, custodian),
      );
      const fresh = await witness(record);
      await running.finish(caseId === "cancel" ? "SIGTERM" : "SIGKILL");
      running.closeInput();
      const final = await rpc("close");
      need(final.stage === 6);
      await settle();
      finalized = true;
      const settled = await witness(final, true);
      return {
        complete: true,
        independent: true,
        nonEmergency: true,
        record,
        fresh,
        settled,
      };
    },
    abort: async () => {
      if (finalized) return;
      await rpc("emergency");
      await rpc("close");
      await settle();
    },
  };
}
