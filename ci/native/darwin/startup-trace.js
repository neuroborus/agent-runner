import { spawn } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { constants as osConstants } from "node:os";
import {
  digest,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import { nativeException, observeNativeProcess } from "../diagnostics.js";

// Installed providers must accept this entire fixed program. No fallback probe,
// pathname argument capture, destructive action or unrelated-process predicate.
const PROGRAM = `#pragma D option quiet
dtrace:::BEGIN { printf("armed %d %llu\\n", pid, timestamp); }
syscall:::entry /pid == $1/ { printf("entry %d %llu %s\\n", pid, timestamp, probefunc); }
syscall:::return /pid == $1/ { printf("return %d %llu %s %d %lld\\n", pid, timestamp, probefunc, errno, (int64_t)arg0); }
proc:::exec-success /pid == $1/ { printf("exec %d %llu\\n", pid, timestamp); }
proc:::exit /pid == $1/ { printf("exit %d %llu\\n", pid, timestamp); exit(0); }
`;
export const DARWIN_STARTUP_TRACE_INTENT = Object.freeze({
  tool: "/usr/sbin/dtrace",
  programSha256: digest(PROGRAM),
});
const matchingCI = () =>
  process.platform === "darwin" &&
  process.arch === "x64" &&
  process.env.CI === "true" &&
  process.env.GITHUB_ACTIONS === "true" &&
  process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
  process.env.RUNNER_OS === "macOS";
const need = (value) => {
  if (!value) throw new Error("Unproved startup trace");
};
async function installed() {
  for (const file of ["/usr/bin/sudo", "/usr/sbin/dtrace"]) {
    const info = await lstat(file);
    need(
      info.isFile() &&
        info.uid === 0 &&
        !(info.mode & 0o022) &&
        (await realpath(file)) === file,
    );
  }
}
async function bounded(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("Startup trace deadline")),
          milliseconds,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

const TRACE_FIELDS = Object.freeze({
  armed: 3,
  entry: 4,
  return: 6,
  exec: 3,
  exit: 3,
});
function traceRow(line) {
  const fields = line.split(" "),
    [kind, pid, time, name, error, value] = fields;
  need(
    Object.hasOwn(TRACE_FIELDS, kind) && fields.length === TRACE_FIELDS[kind],
  );
  need(
    /^[1-9][0-9]{0,9}$/u.test(pid) &&
      Number(pid) <= 0x7fffffff &&
      /^[1-9][0-9]{0,19}$/u.test(time),
  );
  const timestamp = BigInt(time);
  need(timestamp <= 0xffffffffffffffffn);
  if (name !== undefined) need(/^[a-zA-Z0-9_]{1,64}$/u.test(name));
  if (kind === "return")
    need(
      /^(0|[1-9][0-9]{0,4})$/u.test(error) &&
        Number(error) <= 65535 &&
        /^(?:0|-?[1-9][0-9]{0,18})$/u.test(value) &&
        BigInt(value) >= -0x8000000000000000n &&
        BigInt(value) <= 0x7fffffffffffffffn,
    );
  return { kind, pid: Number(pid), timestamp };
}

function traceFailure(error, reason) {
  return {
    reason,
    code:
      Number.isInteger(error?.code) && error.code >= 0 && error.code <= 255
        ? error.code
        : ["ENOENT", "EACCES", "EPERM", "ESRCH", "ETIMEDOUT"].includes(
              error?.code,
            )
          ? error.code
          : null,
    signal:
      typeof error?.signal === "string" &&
      Object.hasOwn(osConstants.signals, error.signal)
        ? error.signal
        : null,
  };
}
function requireRetired(results) {
  need(Array.isArray(results));
  const rejected = results.find((result) => result.status === "rejected");
  if (rejected) throw rejected.reason;
  need(
    results.every(
      (result) =>
        result.status === "fulfilled" && result.value?.status === "RETIRED",
    ),
  );
}

/** Private diagnostic owner. Tests replace all effects; default launch is CI-only. */
export function openDarwinStartupTrace(
  binding,
  {
    isMatchingCI = matchingCI(),
    verifyInstalled = installed,
    launch = spawn,
    readObserver,
    observeObserver,
    retireObserver,
    parentPid = process.pid,
  } = {},
) {
  let boundPid,
    child,
    closed,
    armedPid,
    armTime,
    previousTime,
    pending = "",
    count = 0,
    stdoutBytes = 0,
    stderrBytes = 0,
    invalid = false,
    failure,
    cleanupFailure,
    exit,
    status = "unavailable",
    arming = false,
    domainBound = false,
    captureTimer,
    finished;
  const owners = [],
    rows = [];
  let acknowledge, refuse;
  const ready = new Promise((resolve, reject) => {
    acknowledge = resolve;
    refuse = reject;
  });
  ready.catch(() => {});
  const fail = (error, reason) => {
    nativeException("darwin/startup-trace.js", error);
    const facts = traceFailure(error, reason);
    failure ??= facts;
    if (reason === "retirement") cleanupFailure ??= facts;
    status = reason === "capture" ? "partial" : "refused";
    refuse(error);
  };
  const observer = (observed) => {
    need(
      observed &&
        !Array.isArray(observed) &&
        Object.keys(observed).sort().join(",") === "identity,kind,parentPid" &&
        ["sudo", "dtrace"].includes(observed.kind) &&
        Number.isSafeInteger(observed.parentPid) &&
        observed.parentPid > 0 &&
        observed.parentPid <= 0x7fffffff,
    );
    const identity = normalizeDarwinIdentity(observed.identity);
    return { ...observed, identity };
  };
  const retain = (observed) => {
    const { identity } = observed;
    if (!owners.some((value) => sameDarwinIdentity(value.identity, identity)))
      owners.push({ ...observed, identity });
    return observed;
  };
  const retireOwned = async (owner) => {
    const state = await observeObserver(owner.identity);
    if (state.status === "RETIRED") return state;
    need(state.status === "LIVE");
    const again = observer(await readObserver(owner.identity.pid));
    need(
      sameDarwinIdentity(owner.identity, again.identity) &&
        owner.kind === again.kind &&
        owner.parentPid === again.parentPid,
    );
    return retireObserver(owner.identity);
  };
  const consume = (chunk) => {
    stdoutBytes += chunk.length;
    if (invalid) return;
    if (
      stdoutBytes > 65536 ||
      [...chunk].some((byte) => byte !== 10 && (byte < 32 || byte > 126))
    ) {
      invalid = true;
      rows.length = 0;
      fail(new Error("Startup trace capture rejected"), "capture");
      return;
    }
    pending += chunk.toString("ascii");
    let newline;
    while ((newline = pending.indexOf("\n")) !== -1) {
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      let row;
      try {
        row = traceRow(line);
        need(
          row.kind === "armed"
            ? armTime === undefined
            : armTime !== undefined &&
                row.pid === boundPid &&
                row.timestamp >= previousTime &&
                row.timestamp - armTime <= 30000000000n,
        );
      } catch (error) {
        invalid = true;
        rows.length = 0;
        fail(error, "capture");
        return;
      }
      const { kind, pid, timestamp } = row;
      previousTime = timestamp;
      if (kind === "armed") {
        armedPid = pid;
        armTime = timestamp;
        acknowledge();
      } else {
        count++;
        rows.push(line);
      }
    }
  };
  return {
    async arm() {
      if (!isMatchingCI) return { status };
      try {
        await verifyInstalled();
      } catch (error) {
        nativeException("darwin/startup-trace.js", error);
        return { status };
      }
      try {
        const identity = normalizeDarwinIdentity(binding.identity);
        need(
          !child &&
            !finished &&
            typeof readObserver === "function" &&
            typeof observeObserver === "function" &&
            typeof retireObserver === "function",
        );
        boundPid = identity.pid;
        arming = true;
        child = launch(
          "/usr/bin/sudo",
          [
            "--non-interactive",
            "--",
            "/usr/sbin/dtrace",
            "-q",
            "-n",
            PROGRAM,
            String(boundPid),
          ],
          {
            env: { PATH: "/usr/bin:/bin", LANG: "C" },
            stdio: ["ignore", "pipe", "pipe"],
          },
        );
        closed = new Promise((resolve) =>
          child.once("close", (code, signal) => {
            clearTimeout(captureTimer);
            exit = { code, signal };
            resolve();
            if (arming)
              fail(new Error("Startup trace closed before binding"), "attach");
          }),
        );
        child.on("error", (error) => fail(error, "attach"));
        observeNativeProcess("darwin/startup-trace.js", child);
        child.stdout.on("data", consume);
        child.stdout.on("error", (error) => {
          invalid = true;
          fail(error, "capture");
        });
        child.stderr.on("data", (chunk) => {
          stderrBytes += chunk.length;
          if (stderrBytes > 4096) {
            invalid = true;
            fail(new Error("Startup trace stderr exceeded bound"), "capture");
          } else
            fail(
              new Error(
                "Startup trace diagnostics prevent complete observation",
              ),
              "attach",
            );
        });
        child.stderr.on("error", (error) => {
          invalid = true;
          fail(error, "capture");
        });
        captureTimer = setTimeout(() => {
          invalid = true;
          fail(new Error("Startup trace capture deadline"), "capture");
        }, 30000);
        await bounded(
          (async () => {
            const wrapper = observer(await readObserver(child.pid));
            need(
              wrapper.identity.pid === child.pid &&
                wrapper.parentPid === parentPid &&
                arming &&
                !failure &&
                !exit,
            );
            retain(wrapper);
            await ready;
            let pid = armedPid;
            const chain = [];
            for (let index = 0; index < 4; index++) {
              const owner = observer(await readObserver(pid));
              need(
                owner.identity.pid === pid &&
                  (index === 0
                    ? owner.kind === "dtrace"
                    : owner.kind === "sudo"),
              );
              chain.push(owner);
              if (pid === child.pid) {
                need(owner.parentPid === parentPid);
                break;
              }
              pid = owner.parentPid;
            }
            need(chain.at(-1).identity.pid === child.pid);
            for (const owner of chain) {
              const again = await readObserver(owner.identity.pid);
              need(
                sameDarwinIdentity(owner.identity, again.identity) &&
                  owner.kind === again.kind &&
                  owner.parentPid === again.parentPid,
              );
            }
            need(arming && !failure);
            chain.forEach(retain);
            domainBound = true;
          })(),
          5000,
        );
        need(!failure && !exit);
        status = "armed";
      } catch (error) {
        fail(error, invalid ? "capture" : "identity");
      } finally {
        arming = false;
      }
      return { status };
    },
    finish() {
      return (finished ??= (async () => {
        if (!child) return { status, cleanup: "NOT_RUN" };
        let cleanup = "UNCERTAIN";
        let retirementFailed = false;
        try {
          // The target is already independently retired. exit(0) ends tracing;
          // a timeout still requires identity-safe retirement, never child.kill.
          try {
            await bounded(closed, 10000);
          } catch (error) {
            fail(error, "retirement");
            const attempts = await bounded(
              Promise.allSettled(owners.map(retireOwned)),
              10000,
            ).catch((error) => {
              fail(error, "retirement");
              return null;
            });
            try {
              requireRetired(attempts);
            } catch (error) {
              fail(error, "retirement");
              retirementFailed = true;
            }
            await bounded(closed, 10000).catch((error) => {
              fail(error, "retirement");
              retirementFailed = true;
            });
          }
          const observations = await bounded(
            Promise.allSettled(
              owners.map(async (owner) => {
                let observed = await observeObserver(owner.identity);
                if (observed.status === "LIVE") {
                  need((await retireOwned(owner)).status === "RETIRED");
                  observed = await observeObserver(owner.identity);
                }
                return observed;
              }),
            ),
            10000,
          );
          requireRetired(observations);
          need(
            !retirementFailed &&
              domainBound &&
              owners.some((owner) => owner.identity.pid === child.pid),
          );
          cleanup = "RETIRED";
        } catch (error) {
          fail(error, "retirement");
        }
        clearTimeout(captureTimer);
        if (!child.stdout.readableEnded || !child.stderr.readableEnded) {
          invalid = true;
          cleanup = "UNCERTAIN";
          fail(new Error("Startup trace streams did not drain"), "retirement");
          await bounded(
            Promise.all(
              [child.stdout, child.stderr].map(
                (stream) =>
                  new Promise((resolve) => {
                    if (stream.closed) return resolve();
                    stream.once("close", resolve);
                    stream.destroy();
                  }),
              ),
            ),
            1000,
          ).catch((error) => fail(error, "retirement"));
        }
        const intact =
          !invalid &&
          !pending &&
          child.stdout.readableEnded &&
          child.stderr.readableEnded;
        const complete = intact && !stderrBytes;
        if (!complete) {
          rows.length = 0;
          status = intact ? "refused" : "partial";
        } else if (
          !failure &&
          exit?.code === 0 &&
          !exit.signal &&
          status === "armed"
        )
          status = "observed";
        else if (!failure) status = "refused";
        return {
          status,
          cleanup,
          exit: exit ?? null,
          failure: failure ?? null,
          cleanupFailure: cleanupFailure ?? null,
          captureComplete: complete,
          observers: owners,
          events: complete && status === "observed" ? count : null,
          sha256:
            complete && status === "observed" ? digest(rows.join("\n")) : null,
        };
      })());
    },
  };
}
