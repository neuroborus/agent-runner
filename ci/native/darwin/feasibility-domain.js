import { AsyncLocalStorage } from "node:async_hooks";
import { spawn, execFile } from "node:child_process";
import { EventEmitter } from "node:events";
import { constants } from "node:os";
import { PassThrough, Writable } from "node:stream";
import { promisify } from "node:util";
import {
  openDarwinStartupTrace,
  DARWIN_CONSTRUCTOR_TRACE_INTENT,
} from "./startup-trace.js";
import { nativeDiagnostic } from "../diagnostics.js";
import {
  digest,
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
    retain = () => {},
    openTrace = openDarwinStartupTrace,
    observe,
  } = {},
) {
  need(typeof retain === "function" && typeof observe === "function");
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
    childStderr = Buffer.alloc(0),
    custodyExit,
    total = 0,
    running,
    payloadExit,
    trace,
    parent,
    creator,
    creatorReceiptHash,
    sealed = false,
    releasePossible = false,
    observerPending,
    acquiring = Promise.resolve();
  // Keep the original acquisition reachable even when admission never completes.
  const acquired = { owner, directory };
  const retainFailure = (error) => {
    error.custodyError ??= {};
    Object.assign(error.custodyError, custodyExit, { stderr });
    error.stderr = !running && childStderr.length ? childStderr : stderr;
    if (!running && payloadExit) {
      error.exitCode = payloadExit.code;
      error.signal = payloadExit.signal;
    }
  };
  const rejectAdmission = (error) => {
    error.faultDomain = acquired;
    retainFailure(error);
    try {
      owner.stdin.end();
    } catch (cleanupError) {
      error.cleanupError ??= cleanupError;
    }
    return error;
  };
  const virtual = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  const closePayload = (code, signal) => {
    need(!payloadExit);
    payloadExit = { code, signal };
    if (!running && ready)
      fail(new Error("Fault child exited before admission"));
    if (running) {
      virtual.stdout.end();
      virtual.stderr.end();
      virtual.emit("close", code, signal);
    }
  };
  const fail = (error) => {
    failed ??= error;
    if (error.exitCode !== undefined) failed.exitCode ??= error.exitCode;
    if (error.signal !== undefined) failed.signal ??= error.signal;
    retainFailure(failed);
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
  const settle = async (admissionFailure = false) => {
    let timer;
    try {
      const exit = await Promise.race([
        closed,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            const error = Object.assign(
              new Error("Fault custody closure deadline"),
              {
                code: "ERR_FEASIBILITY_DEADLINE",
              },
            );
            fail(error);
            reject(error);
          }, 12000);
        }),
      ]);
      if (admissionFailure) return;
      if (failed) throw failed;
      need(exit.code === 0 && exit.signal === null);
    } finally {
      clearTimeout(timer);
    }
  };
  owner.on("error", fail);
  owner.stdin.on("error", fail);
  owner.stderr.on(
    "data",
    AsyncLocalStorage.bind((chunk) => {
      total += chunk.length;
      const length = stderr.length + chunk.length;
      stderr = Buffer.concat([
        stderr,
        chunk.subarray(0, 65536 - stderr.length),
      ]);
      if (failed) retainFailure(failed);
      if (length > 65536 || total > 262144)
        fail(new Error("Fault custody output bound"));
      // Custodian diagnostics stay separate from relayed payload stdio and cannot
      // interrupt the original bounded capture, refusal or independent cleanup.
      try {
        nativeDiagnostic("darwin-fault-custody", { stderr: chunk });
      } catch {
        // The output sink supplies no custody or retirement evidence.
      }
    }),
  );
  owner.stdout.on("error", fail);
  owner.stderr.on("error", fail);
  const creatorFrame = (value, phase) => {
    need(
      value &&
        Object.keys(value).sort().join(",") === "phase,record,version" &&
        value.version === 1 &&
        value.phase === phase,
    );
    const record = value.record;
    need(
      record &&
        Object.keys(record).sort().join(",") ===
          "asid,candidateSha,caseId,constructorCaptureSha256,constructorProgramSha256,creatorReceiptSha256,custodian,descendant,emergency,helperSha256,intentSha256,members,owner,policySha256,receiptSha256,stage" &&
        record.stage === 1 &&
        record.emergency === false &&
        record.intentSha256 === "" &&
        record.constructorProgramSha256 === "" &&
        record.constructorCaptureSha256 === "" &&
        Array.isArray(record.members) &&
        record.members.length === 0 &&
        /^[a-f0-9]{64}$/u.test(record.receiptSha256),
    );
    return record;
  };
  const verifyParent = async () => {
    const { stdout } = await execute(
      "/usr/bin/sudo",
      [
        "-n",
        "--",
        "/usr/bin/env",
        "-i",
        ...PRIVILEGED_ENV,
        helper,
        "fault-parent",
        nonce,
        "-",
      ],
      { cwd: root, env, timeout: 12000, maxBuffer: 65536 },
    );
    need(!failed && sameDarwinIdentity(JSON.parse(stdout).parent, parent));
  };
  const acquire = (operation) => {
    acquiring = acquiring
      .then(() => {
        need(!failed);
        return operation();
      })
      .catch(fail);
  };
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
        if (value.observerStored === true) {
          need(observerPending);
          const done = observerPending;
          observerPending = null;
          done();
        } else if (value.hello) {
          need(!parent && !trace);
          parent = normalizeDarwinIdentity(value.hello.custodian);
          need(
            value.hello.candidateSha === candidate &&
              value.hello.caseId === caseId &&
              value.hello.stage === 0 &&
              value.hello.helperSha256 === helperHash &&
              value.hello.policySha256 === policyHash,
          );
          acquired.parent = parent;
          acquire(async () => {
            trace = openTrace(
              { identity: parent },
              {
                constructorMode: true,
                readObserver: (pid) => observe("constructor-observer", pid),
                observeObserver: (identity) =>
                  observe("constructor-observer-observe", identity),
                retireObserver: (identity) =>
                  observe("constructor-observer-retire", identity),
                onFailure: fail,
                onObserver: async ({ identity, toolSha256 }) => {
                  need(
                    !failed &&
                      !observerPending &&
                      /^[a-f0-9]{64}$/u.test(toolSha256),
                  );
                  await new Promise((resolve, reject) => {
                    observerPending = resolve;
                    owner.stdin.write(
                      "O " +
                        darwinIdentityArguments(identity).join(" ") +
                        " " +
                        toolSha256 +
                        "\n",
                      (error) => {
                        if (error) reject(error);
                      },
                    );
                  });
                },
              },
            );
            acquired.trace = trace;
            need((await trace.arm()).status === "armed");
            await verifyParent();
            owner.stdin.write("P\n");
          });
        } else if (value.creator) {
          need(Object.keys(value).length === 1 && parent && trace && !creator);
          creator = creatorFrame(value.creator, 1);
          need(
            creator.stage === 1 &&
              creator.candidateSha === candidate &&
              creator.caseId === caseId &&
              creator.helperSha256 === helperHash &&
              creator.policySha256 === policyHash &&
              sameDarwinIdentity(creator.custodian, parent),
          );
          acquire(async () => {
            const receipt = await trace.receipt(creator.owner);
            creatorReceiptHash = digest(receipt);
            need(!failed);
            owner.stdin.write("creator " + receipt.toString("hex") + "\n");
          });
        } else if (value.sealed) {
          const record = creatorFrame(value.sealed, 2);
          need(
            Object.keys(value).length === 1 &&
              !sealed &&
              creator &&
              trace &&
              sameDarwinIdentity(record.owner, creator.owner) &&
              sameDarwinIdentity(record.custodian, parent) &&
              record.creatorReceiptSha256 === creatorReceiptHash &&
              [
                "candidateSha",
                "caseId",
                "helperSha256",
                "policySha256",
                "asid",
              ].every((field) => record[field] === creator[field]) &&
              JSON.stringify(record.descendant) ===
                JSON.stringify(creator.descendant),
          );
          sealed = true;
          acquire(async () => {
            const observed = await trace.finish();
            acquired.traceResult = observed;
            need(
              observed.status === "observed" &&
                observed.captureComplete &&
                observed.cleanup === "RETIRED" &&
                observed.programSha256 ===
                  DARWIN_CONSTRUCTOR_TRACE_INTENT.programSha256 &&
                /^[a-f0-9]{64}$/u.test(observed.sha256) &&
                sameDarwinIdentity(observed.creator.identity, creator.owner) &&
                observed.creator.receiptSha256 === creatorReceiptHash,
            );
            await verifyParent();
            releasePossible = true;
            owner.stdin.write(
              `seal1 ${observed.programSha256} ${observed.sha256}\n`,
            );
          });
        } else if (value.ready) {
          need(ready && sealed && releasePossible);
          ready.resolve(value.ready);
          ready = null;
        } else if (value.stream) {
          need(
            ["stdout", "stderr"].includes(value.stream) &&
              /^(?:[a-f0-9]{2})*$/u.test(value.hex),
          );
          const chunk = Buffer.from(value.hex, "hex");
          if (!running && value.stream === "stderr") {
            const length = childStderr.length + chunk.length;
            childStderr = Buffer.concat([
              childStderr,
              chunk.subarray(0, 65536 - childStderr.length),
            ]);
            if (failed) retainFailure(failed);
            need(length <= 65536);
          }
          virtual[value.stream].write(chunk);
        } else if (value.exit) {
          const { code, signal } = value.exit;
          const signalName = Object.entries(constants.signals).find(
            ([, number]) => number === signal,
          )?.[0];
          need(
            !payloadExit &&
              Number.isInteger(code) &&
              code >= -1 &&
              code <= 255 &&
              Number.isInteger(signal) &&
              signal >= 0 &&
              signal <= 31 &&
              ((code >= 0 && signal === 0) ||
                (code === -1 && signalName !== undefined)),
          );
          closePayload(code >= 0 ? code : null, signal ? signalName : null);
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
    custodyExit = { exitCode: code, signal };
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
  try {
    retain(acquired);
  } catch (error) {
    throw rejectAdmission(error);
  }
  const settleAdmission = async (error) => {
    // Closing custody first lets its original child settle independently of
    // missing trace records or uncertain observer retirement.
    rejectAdmission(error);
    const settling = settle(true).catch((cleanupError) => {
      error.custodyError.cleanupError = cleanupError;
    });
    if (trace) {
      try {
        acquired.traceResult = await trace.finish();
      } catch (cleanupError) {
        error.observerError = cleanupError;
        error.cleanupError ??= cleanupError;
      }
    }
    await settling;
    retainFailure(error);
    return error;
  };
  const initial = await new Promise((resolve, reject) => {
    ready = { resolve, reject };
    const timer = setTimeout(() => {
      if (ready) fail(new Error("Fault custody admission deadline"));
    }, 12000);
    closed.finally(() => clearTimeout(timer));
  }).catch(async (error) => {
    throw await settleAdmission(error);
  });
  let custodian;
  try {
    if (failed) throw failed;
    custodian = normalizeDarwinIdentity(initial.custodian);
    need(
      initial.candidateSha === candidate &&
        initial.caseId === caseId &&
        initial.stage === 1 &&
        initial.helperSha256 === helperHash &&
        initial.policySha256 === policyHash &&
        initial.asid > 0 &&
        initial.asid === creator.asid &&
        initial.creatorReceiptSha256 === creatorReceiptHash &&
        initial.constructorProgramSha256 ===
          acquired.traceResult.programSha256 &&
        initial.constructorCaptureSha256 === acquired.traceResult.sha256 &&
        sameDarwinIdentity(initial.owner, creator.owner) &&
        sameDarwinIdentity(custodian, parent) &&
        custodian.asid !== initial.asid,
    );
    virtual.pid = initial.owner.pid;
    running = openSession(
      root,
      "exec",
      [root + `/evidence/${caseId}.sb`, root + "/build/helper", "fault"],
      { launch: () => virtual },
    );
  } catch (error) {
    throw await settleAdmission(error);
  }
  if (payloadExit) {
    virtual.stdout.end();
    virtual.stderr.end();
    virtual.emit("close", payloadExit.code, payloadExit.signal);
  }
  let faulted = false,
    finalized = false,
    emergency = false,
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
  const retire = async (recovering = false) => {
    need(!emergency);
    const record = await rpc(recovering ? "recover" : "retire");
    const fields = [
      "candidateSha",
      "caseId",
      "asid",
      "helperSha256",
      "policySha256",
    ];
    need(
      record.stage === 5 &&
        record.emergency === false &&
        fields.every((field) => record[field] === initial[field]) &&
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
    const fresh = await witness(record);
    // Failure stays terminal. Recovery drains the original pipes and proves the
    // original domain; it never repeats payload work or a consumed finish.
    if (!recovering)
      await running.finish(caseId === "cancel" ? "SIGTERM" : "SIGKILL");
    running.closeInput();
    const final = await rpc("close");
    need(
      final.stage === 6 &&
        [
          ...fields,
          "intentSha256",
          "custodian",
          "owner",
          "descendant",
          "members",
          "emergency",
        ].every(
          (field) =>
            JSON.stringify(final[field]) === JSON.stringify(record[field]),
        ),
    );
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
    initial: structuredClone(initial),
    constructorEvidence: acquired.traceResult,
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
        closePayload(null, caseId === "cancel" ? "SIGTERM" : "SIGKILL");
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
    retire: () => retire(),
    recover: () => retire(true),
    abort: async () => {
      if (finalized) return;
      emergency = true;
      await rpc("emergency");
      await rpc("close");
      await settle();
    },
  };
}
