import { spawn } from "node:child_process";
import { protectedBytes } from "./private-files.js";
import {
  digest,
  inspectDarwinMachO,
  normalizeDarwinIdentity,
  normalizeDarwinLaunch,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";

export function darwinRetirementArguments(operation, input, target) {
  const request = normalizeDarwinLaunch(input);
  if (operation === "members") {
    requireDarwin(target === undefined);
    return ["--members", String(request.uid)];
  }
  if (operation === "custody") {
    requireDarwin(
      Number.isSafeInteger(target) && target > 0 && target < 0xffffffff,
    );
    return ["--custody", String(target)];
  }
  requireDarwin(operation === "signal");
  const identity = normalizeDarwinIdentity(target);
  requireDarwin(
    identity.pid > 1 &&
      (["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
        (key) => identity[key] === 0,
      ) ||
        (identity.auid === request.uid &&
          ["uid", "ruid", "svuid"].every(
            (key) => identity[key] === request.uid,
          ) &&
          ["gid", "rgid", "svgid"].every(
            (key) => identity[key] === request.gid,
          ))),
  );
  return [
    "--signal",
    ...[
      "auid",
      "uid",
      "gid",
      "ruid",
      "rgid",
      "pid",
      "asid",
      "pidVersion",
      "startSeconds",
      "startMicroseconds",
      "svuid",
      "svgid",
    ].map((key) => String(identity[key])),
  ];
}

/** Root helpers are admitted and settled through separate protected native
 * readers. Closing a pipe or receiving helper text is never settlement. */
export async function runDarwinRetirementOperation(
  input,
  operation,
  target,
  effects,
) {
  const request = normalizeDarwinLaunch(input),
    args = darwinRetirementArguments(operation, request, target);
  requireDarwin(
    process.platform === "darwin" &&
      process.arch === "x64" &&
      process.geteuid() === 0 &&
      process.env.CI === "true" &&
      process.env.GITHUB_ACTIONS === "true" &&
      process.env.ImageOS === "macos15" &&
      ["intent", "admitHelper", "settleHelper"].every(
        (key) => typeof effects?.[key] === "function",
      ),
  );
  inspectDarwinMachO(
    await protectedBytes(request.launcher, 0, 0o550, 134217728),
  );
  const operationSha256 = digest(JSON.stringify({ request, args }));
  requireDarwin(
    (await effects.intent(structuredClone(request), [...args], operationSha256))
      .operationSha256 === operationSha256,
  );
  const child = spawn(request.launcher.path, args, {
    cwd: request.custody,
    env: { CI: "true", GITHUB_ACTIONS: "true", PATH: "/nonexistent" },
    stdio: ["pipe", "pipe", "ignore"],
  });
  let identity,
    phase = "helper",
    failed = false,
    rejectBody,
    rejectFault,
    timer;
  const fault = new Promise((_, reject) => {
    rejectFault = reject;
  });
  fault.catch(() => {});
  const close = () => {
    if (failed) return;
    failed = true;
    clearTimeout(timer);
    child.stdin.destroy();
    const error = new Error("Darwin native operation unavailable");
    rejectBody(error);
    rejectFault(error);
  };
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  completion.catch(() => {});
  const body = new Promise((resolve, reject) => {
    rejectBody = reject;
    let bytes = Buffer.alloc(0);
    timer = setTimeout(close, 30000);
    child.once("error", close);
    child.once("close", () => {
      if (phase !== "result") close();
    });
    child.stdin.on("error", close);
    child.stdout.on("error", close);
    child.stdout.on("data", (chunk) => {
      try {
        requireDarwin(
          !failed &&
            ["helper", "body"].includes(phase) &&
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
        if (phase === "helper") {
          requireDarwin(value && Object.keys(value).join(",") === "verifier");
          identity = normalizeDarwinIdentity(value.verifier);
          requireDarwin(
            identity.pid === child.pid &&
              ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
                (key) => identity[key] === 0,
              ),
          );
          phase = "admit";
          child.stdout.pause();
          Promise.resolve()
            .then(() =>
              effects.admitHelper(
                structuredClone(identity),
                structuredClone(request),
                [...args],
                operationSha256,
              ),
            )
            .then((verified) => {
              requireDarwin(
                !failed &&
                  sameDarwinIdentity(verified.identity, identity) &&
                  verified.operationSha256 === operationSha256 &&
                  verified.helperSha256 === request.launcher.sha256 &&
                  typeof verified.receiptSha256 === "string" &&
                  /^[a-f0-9]{64}$/u.test(verified.receiptSha256),
              );
              phase = "body";
              child.stdin.write("P");
              child.stdout.resume();
            })
            .catch(close);
        } else {
          phase = "result";
          resolve(value);
        }
      } catch {
        close();
      }
    });
  });
  const settle = async () => {
    const result = await Promise.race([completion, fault]);
    requireDarwin(!failed && result.code === 0 && result.signal === null);
    const verified = await Promise.race([
      effects.settleHelper(structuredClone(identity), structuredClone(request)),
      fault,
    ]);
    requireDarwin(
      sameDarwinIdentity(verified.identity, identity) &&
        verified.settled === true &&
        verified.independent === true,
    );
    clearTimeout(timer);
  };
  try {
    const value = await Promise.race([body, fault]);
    if (operation !== "custody") {
      await settle();
      return { verifier: structuredClone(identity), value };
    }
    requireDarwin(value.asid === target && value.held === true);
    clearTimeout(timer);
    timer = setTimeout(close, 60000);
    let settling = false;
    return {
      verifier: structuredClone(identity),
      value,
      async settle() {
        requireDarwin(!settling && !failed && !child.stdin.destroyed);
        settling = true;
        child.stdin.end("S");
        await settle();
      },
    };
  } catch (error) {
    close();
    throw error;
  }
}
