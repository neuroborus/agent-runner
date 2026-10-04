import { spawn } from "node:child_process";
import { protectedBytes } from "./private-files.js";
import {
  digest,
  inspectDarwinMachO,
  normalizeDarwinIdentity,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";
import {
  buildDarwinPolicy,
  darwinPfctlArguments,
  isDarwinDigest,
} from "./policy.js";

/** A protected settlement receipt belongs to the admitted native identities,
 * not just a repeatable tool vector or a reported zero exit. */
export function assertDarwinPfSettlement(
  value,
  helper,
  worker,
  operationSha256,
) {
  const verifier = normalizeDarwinIdentity(value.verifier);
  requireDarwin(
    value.independent === true &&
      value.settled === true &&
      value.operationSha256 === operationSha256 &&
      isDarwinDigest(value.receiptSha256) &&
      sameDarwinIdentity(value.helper, helper) &&
      sameDarwinIdentity(value.worker, worker) &&
      verifier.pid !== helper.pid &&
      verifier.pid !== worker.pid &&
      ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
        (key) => verifier[key] === 0,
      ),
  );
  return verifier;
}

/** A fixed root helper parks itself and its approved private pfctl worker.
 * Separate native readers admit both before effects and settle both afterward. */
export async function runDarwinPfctl(
  input,
  operation,
  tool,
  restoreSha256,
  effects,
) {
  const plan = buildDarwinPolicy(input),
    { request } = plan.value;
  const vector = darwinPfctlArguments(input, operation),
    file = vector.at(-1);
  const fileSha256 = operation.includes("restore")
    ? restoreSha256
    : plan.pfSha256;
  requireDarwin(
    tool &&
      Object.getPrototypeOf(tool) === Object.prototype &&
      Reflect.ownKeys(tool).length === 3 &&
      ["path", "sha256", "cdhash"].every((key) => {
        const field = Object.getOwnPropertyDescriptor(tool, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
  tool = { ...tool };
  requireDarwin(
    process.platform === "darwin" &&
      process.arch === "x64" &&
      process.geteuid() === 0 &&
      process.env.CI === "true" &&
      process.env.GITHUB_ACTIONS === "true" &&
      process.env.ImageOS === "macos15" &&
      tool.path === request.custody + "/pfctl" &&
      isDarwinDigest(tool.sha256) &&
      typeof tool.cdhash === "string" &&
      /^[a-f0-9]{40}$/u.test(tool.cdhash) &&
      isDarwinDigest(fileSha256) &&
      ["intent", "admit", "settle"].every(
        (key) => typeof effects?.[key] === "function",
      ),
  );
  inspectDarwinMachO(
    await protectedBytes(request.launcher, 0, 0o550, 134217728),
  );
  inspectDarwinMachO(await protectedBytes(tool, 0, 0o550, 134217728));
  await protectedBytes({ path: file, sha256: fileSha256 }, 0, 0o400, 1048576);
  const args = [
    "--pfctl",
    tool.path,
    tool.sha256,
    tool.cdhash,
    file,
    fileSha256,
    plan.anchor,
    operation,
  ];
  const operationSha256 = digest(
    JSON.stringify({ compositionSha256: plan.compositionSha256, args }),
  );
  requireDarwin(
    (
      await effects.intent(
        structuredClone(plan.value),
        [...args],
        operationSha256,
      )
    ).operationSha256 === operationSha256,
  );
  const child = spawn(request.launcher.path, args, {
    cwd: request.custody,
    env: { CI: "true", GITHUB_ACTIONS: "true", PATH: "/nonexistent" },
    stdio: ["pipe", "pipe", "ignore"],
  });
  let helper,
    worker,
    phase = "helper",
    failed = false,
    rejectFault;
  const fault = new Promise((_, reject) => {
    rejectFault = reject;
  });
  fault.catch(() => {});
  const fail = () => {
    if (failed) return;
    failed = true;
    child.stdin.destroy();
    rejectFault(new Error("Unverified Darwin PF helper"));
  };
  const timer = setTimeout(fail, 30000);
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  completion.catch(() => {});
  child.once("error", fail);
  child.stdin.on("error", fail);
  child.stdout.on("error", fail);
  const body = new Promise((resolve) => {
    let bytes = Buffer.alloc(0);
    child.stdout.on("data", (chunk) => {
      try {
        requireDarwin(
          !failed &&
            ["helper", "worker", "result"].includes(phase) &&
            bytes.length + chunk.length <= 16384,
        );
        bytes = Buffer.concat([bytes, chunk]);
        const end = bytes.indexOf(10);
        if (end < 0) return;
        requireDarwin(end === bytes.length - 1);
        const value = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(bytes),
        );
        bytes = Buffer.alloc(0);
        if (phase === "result") {
          requireDarwin(
            value &&
              Object.keys(value).length === 2 &&
              value.exitCode === 0 &&
              value.signal === null,
          );
          phase = "done";
          resolve();
          return;
        }
        const initial = phase === "helper",
          identity = normalizeDarwinIdentity(
            initial ? value.verifier : value.worker,
          );
        requireDarwin(
          Object.keys(value).join(",") === (initial ? "verifier" : "worker") &&
            ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
              (key) => identity[key] === 0,
            ) &&
            (initial
              ? identity.pid === child.pid
              : identity.pid !== helper.pid),
        );
        if (initial) helper = identity;
        else worker = identity;
        phase = "verify";
        child.stdout.pause();
        Promise.resolve()
          .then(() =>
            effects.admit(structuredClone(plan.value), {
              helper: structuredClone(helper),
              worker: worker ? structuredClone(worker) : null,
              operationSha256,
              toolSha256: tool.sha256,
            }),
          )
          .then((verified) => {
            const verifier = normalizeDarwinIdentity(verified.verifier);
            requireDarwin(
              !failed &&
                verified.independent === true &&
                verifier.pid !== helper.pid &&
                (!worker || verifier.pid !== worker.pid) &&
                ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
                  (key) => verifier[key] === 0,
                ) &&
                sameDarwinIdentity(verified.helper, helper) &&
                (worker
                  ? sameDarwinIdentity(verified.worker, worker)
                  : verified.worker === null) &&
                verified.operationSha256 === operationSha256 &&
                verified.toolSha256 === tool.sha256 &&
                verified.closureSha256 === request.bindings.closure &&
                isDarwinDigest(verified.receiptSha256),
            );
            phase = initial ? "worker" : "result";
            child.stdin.write(initial ? "P" : "R");
            child.stdout.resume();
          })
          .catch(fail);
      } catch {
        fail();
      }
    });
    child.once("close", () => {
      if (phase !== "done") fail();
    });
  });
  try {
    await Promise.race([body, fault]);
    const completionValue = await Promise.race([completion, fault]);
    requireDarwin(
      completionValue.code === 0 && completionValue.signal === null && !failed,
    );
    const settled = await Promise.race([
      effects.settle(structuredClone(plan.value), {
        helper: structuredClone(helper),
        worker: structuredClone(worker),
        operationSha256,
      }),
      fault,
    ]);
    const verifier = assertDarwinPfSettlement(
      settled,
      helper,
      worker,
      operationSha256,
    );
    return {
      helper,
      worker,
      verifier,
      receiptSha256: settled.receiptSha256,
      toolSha256: tool.sha256,
      exitCode: 0,
      signal: null,
      timedOut: false,
      settled: true,
    };
  } catch (error) {
    fail();
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
