import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { protectedBytes } from "./private-files.js";
import {
  digest,
  inspectDarwinMachO,
  normalizeDarwinIdentity,
  normalizeDarwinLaunch,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";
import {
  normalizeDarwinFileIdentity,
  normalizeDarwinFileMessage,
  normalizeDarwinFileState,
  runDarwinFileTransaction,
} from "./files-protocol.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const keys = ["base", "root", "allocation", "leaf", "temporary", "alias"];
const stateOf = (value) =>
  Object.fromEntries(keys.map((key) => [key, value[key]]));
export function normalizeDarwinFileInput(value) {
  requireDarwin(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === 4 &&
      ["request", "base", "root", "reviewSha256"].every((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }) &&
      hash(value.reviewSha256),
  );
  const input = {
    request: normalizeDarwinLaunch(value.request),
    base: normalizeDarwinFileIdentity(value.base),
    root: normalizeDarwinFileIdentity(value.root),
    reviewSha256: value.reviewSha256,
  };
  normalizeDarwinFileState({
    ...stateOf({
      ...input,
      allocation: null,
      leaf: null,
      temporary: null,
      alias: false,
    }),
  });
  return input;
}
function rootIdentity(value) {
  const identity = normalizeDarwinIdentity(value);
  requireDarwin(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
}
function admission(value, input) {
  const helper = rootIdentity(value.helper),
    verifier = rootIdentity(value.verifier);
  requireDarwin(
    verifier.pid !== helper.pid &&
      value.independent === true &&
      value.soleParentAuthority === true &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      value.helperSha256 === input.request.executable.sha256 &&
      value.cdhash === input.request.executable.cdhash &&
      value.closureSha256 === input.request.bindings.closure &&
      value.reviewSha256 === input.reviewSha256 &&
      value.base === input.base &&
      value.root === input.root &&
      hash(value.receiptSha256),
  );
  return helper;
}

/** The only concrete transport. Descriptor acquisition, signed image/loader
 * admission and stable process settlement remain protected external owners. */
export async function openDarwinFileHelper(value, effects) {
  const input = normalizeDarwinFileInput(value),
    requestSha256 = digest(JSON.stringify(input));
  requireDarwin(
    process.platform === "darwin" &&
      process.arch === "x64" &&
      process.geteuid() === 0 &&
      process.env.CI === "true" &&
      process.env.GITHUB_ACTIONS === "true" &&
      process.env.ImageOS === "macos15" &&
      ["descriptors", "created", "admit"].every(
        (key) => typeof effects?.[key] === "function",
      ),
  );
  inspectDarwinMachO(
    await protectedBytes(input.request.executable, 0, 0o550, 134217728),
  );
  const descriptors = await effects.descriptors(structuredClone(input));
  requireDarwin(
    [descriptors.root, descriptors.base].every(
      (fd) => Number.isSafeInteger(fd) && fd >= 3,
    ) && descriptors.root !== descriptors.base,
  );
  const child = spawn(
    input.request.executable.path,
    [input.request.nonce, input.root, input.base],
    {
      cwd: input.request.custody,
      env: { CI: "true", GITHUB_ACTIONS: "true", PATH: "/nonexistent" },
      stdio: ["pipe", "pipe", "ignore", descriptors.root, descriptors.base],
    },
  );
  let pending,
    failure,
    rejectFault,
    buffer = Buffer.alloc(0),
    total = 0;
  const fault = new Promise((_, reject) => {
    rejectFault = reject;
  });
  fault.catch(() => {});
  const wait = (value) => Promise.race([value, fault]);
  const queue = [];
  const close = () => {
    child.stdin.destroy();
  };
  const fail = () => {
    if (failure) return;
    failure = new Error("Unverified Darwin file helper");
    close();
    pending?.reject(failure);
    pending = null;
    rejectFault(failure);
  };
  const timer = setTimeout(fail, 30000);
  const completion = new Promise((resolve) =>
    child.once("close", (code, signal) =>
      resolve({
        code,
        signal,
        failed: Boolean(failure),
        remainingMessages: queue.length,
        partialBytes: buffer.length,
      }),
    ),
  );
  child.once("error", fail);
  child.stdin.on("error", fail);
  child.stdout.on("error", fail);
  child.once("close", () => {
    if (pending || buffer.length) fail();
  });
  child.stdout.on("data", (chunk) => {
    try {
      total += chunk.length;
      buffer = Buffer.concat([buffer, chunk]);
      requireDarwin(total <= 262144 && buffer.length <= 8192);
      let end;
      while ((end = buffer.indexOf(10)) >= 0) {
        requireDarwin(end < 4096 && !failure);
        const message = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            buffer.subarray(0, end),
          ),
        );
        buffer = buffer.subarray(end + 1);
        if (pending) {
          pending.resolve(message);
          pending = null;
        } else {
          requireDarwin(queue.length < 2);
          queue.push(message);
        }
      }
    } catch {
      fail();
    }
  });
  const receive = () => {
    if (failure) return Promise.reject(failure);
    if (queue.length) return Promise.resolve(queue.shift());
    requireDarwin(!pending);
    return new Promise((resolve, reject) => {
      pending = { resolve, reject };
    });
  };
  const send = (bytes) => {
    requireDarwin(
      !failure &&
        !child.stdin.destroyed &&
        typeof bytes === "string" &&
        Buffer.byteLength(bytes) <= 9000,
    );
    return new Promise((resolve, reject) =>
      child.stdin.write(bytes, (error) => (error ? reject(error) : resolve())),
    );
  };
  try {
    // A possible-child receipt precedes admission, even when bootstrap fails.
    await wait(effects.created(child, structuredClone(input), requestSha256));
    const message = normalizeDarwinFileMessage(
      await receive(),
      input.request.nonce,
    );
    requireDarwin(
      message.phase === "ready" &&
        message.base === input.base &&
        message.root === input.root &&
        message.allocation === null &&
        message.leaf === null &&
        message.temporary === null,
    );
    const admitted = structuredClone(
      await wait(
        effects.admit(child, structuredClone(input), structuredClone(message)),
      ),
    );
    requireDarwin(admission(admitted, input).pid === child.pid);
    await wait(send("start - - - -\n"));
    return {
      admission: admitted,
      receive,
      send,
      close,
      completion,
      dispose: () => clearTimeout(timer),
    };
  } catch (error) {
    fail();
    clearTimeout(timer);
    throw error;
  }
}

/** A protected recovery reader supplies the actual immutable receipt. Caller
 * identities are never a replacement for its previously recorded authority. */
export function normalizeDarwinFileRecovery(value, input) {
  requireDarwin(
    value &&
      value.independent === true &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      value.candidateSha === input.request.candidateSha &&
      value.nonce === input.request.nonce &&
      hash(value.receiptSha256) &&
      ["publish", "replace", "cleanup", "inspect", "finish"].includes(
        value.operation,
      ) &&
      ["FAIL", "INTERRUPTED", "OBSERVED"].includes(value.status),
  );
  const state = normalizeDarwinFileState(value.state);
  requireDarwin(
    state.root === input.root &&
      state.base === input.base &&
      state.allocation !== null,
  );
  requireDarwin(value.stateSha256 === digest(JSON.stringify(state)));
  admission(value.admission, input);
  return structuredClone({ ...value, state });
}

/** One serial owner, at most 32 operations, immutable intent/barrier receipts.
 * The old session and payload domain retire before a new cleanup helper starts. */
export async function runDarwinFileSession(
  value,
  operations,
  effects,
  { recovery = null, now = () => performance.now() } = {},
) {
  const input = normalizeDarwinFileInput(value),
    requestSha256 = digest(JSON.stringify(input));
  requireDarwin(
    Array.isArray(operations) &&
      Object.getPrototypeOf(operations) === Array.prototype &&
      operations.length > 0 &&
      operations.length <= 30 &&
      Reflect.ownKeys(operations).length === operations.length + 1 &&
      typeof effects?.persist === "function",
  );
  operations = Array.from({ length: operations.length }, (_, index) => {
    const item = Object.getOwnPropertyDescriptor(operations, index);
    requireDarwin(item?.enumerable && Object.hasOwn(item, "value"));
    const operation = item.value;
    requireDarwin(
      operation &&
        Object.getPrototypeOf(operation) === Object.prototype &&
        Reflect.ownKeys(operation).length === 2 &&
        ["type", "bytes"].every((key) => {
          const field = Object.getOwnPropertyDescriptor(operation, key);
          return field?.enumerable && Object.hasOwn(field, "value");
        }) &&
        [
          "allocate",
          "publish",
          "replace",
          "inspect",
          "cleanup",
          "finish",
        ].includes(operation.type) &&
        typeof operation.bytes === "string" &&
        /^(?:[a-f0-9]{2}){0,4096}$/u.test(operation.bytes) &&
        (["publish", "replace"].includes(operation.type) ||
          operation.bytes === ""),
    );
    return { type: operation.type, bytes: operation.bytes };
  });
  requireDarwin(
    operations.at(-1).type === "finish" &&
      operations.slice(0, -1).every((operation) => operation.type !== "finish"),
  );
  const record = {
    schemaVersion: 1,
    candidateSha: input.request.candidateSha,
    nonce: input.request.nonce,
    requestSha256,
    status: "BLOCKED",
    phase: "review",
    reservation: "RETAINED",
    missingInputs: [],
    events: [],
    state: {
      base: input.base,
      root: input.root,
      allocation: null,
      leaf: null,
      temporary: null,
      alias: false,
    },
  };
  for (const key of ["review", "open", "verify", "barrier", "retire"])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("darwin-files-" + key);
  if (recovery !== null)
    for (const key of ["readRecovery", "verifyRetirement"])
      if (typeof effects[key] !== "function")
        record.missingInputs.push("darwin-files-" + key);
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  let channel,
    prior,
    interrupted = false;
  const start = now(),
    bounded = () => {
      const elapsed = now() - start;
      requireDarwin(
        Number.isFinite(elapsed) && elapsed >= 0 && elapsed <= 30000,
      );
    };
  const verifyRetirement = async (state) => {
    const retired = structuredClone(
      await effects.verifyRetirement(
        structuredClone(input),
        structuredClone(prior),
      ),
    );
    const verifier = rootIdentity(retired.verifier);
    requireDarwin(
      retired.independent === true &&
        retired.noLiveUid === true &&
        retired.uid === input.request.uid &&
        retired.helpersSettled === true &&
        retired.requestSha256 === requestSha256 &&
        retired.recoverySha256 === prior.receiptSha256 &&
        sameDarwinIdentity(retired.helper, prior.admission.helper) &&
        verifier.pid !== prior.admission.helper.pid &&
        (!record.admission || verifier.pid !== record.admission.helper.pid) &&
        hash(retired.receiptSha256),
    );
    record.priorRetirementSha256 = retired.receiptSha256;
    return {
      independent: true,
      retired: true,
      stateSha256: digest(JSON.stringify(state)),
      receiptSha256: retired.receiptSha256,
    };
  };
  try {
    const review = structuredClone(
      await effects.review(structuredClone(input), requestSha256),
    );
    if (review.missingInputs?.length) {
      requireDarwin(
        Array.isArray(review.missingInputs) &&
          review.missingInputs.length <= 256 &&
          review.missingInputs.every(
            (value) =>
              typeof value === "string" &&
              value.length > 0 &&
              value.length <= 512 &&
              !/[\u0000-\u001f\u007f]/u.test(value),
          ),
      );
      record.missingInputs = review.missingInputs;
      await save();
      return record;
    }
    requireDarwin(
      review.approvedSha256 === requestSha256 &&
        review.reviewSha256 === input.reviewSha256,
    );
    if (recovery !== null) {
      prior = normalizeDarwinFileRecovery(
        structuredClone(
          await effects.readRecovery(recovery, structuredClone(input)),
        ),
        input,
      );
      await verifyRetirement(prior.state);
      requireDarwin(
        operations.every((operation) =>
          ["cleanup", "finish"].includes(operation.type),
        ),
      );
      operations.unshift({
        type: "recover",
        allocation: prior.state.allocation,
        leaf: prior.state.leaf,
        temporary: prior.state.temporary,
        bytes: "",
      });
    } else
      requireDarwin(
        operations.every(
          (operation) => !["cleanup", "recover"].includes(operation.type),
        ),
      );
    record.status = "RUNNING";
    record.phase = "possible-admission";
    await save();
    bounded();
    channel = await effects.open(structuredClone(input));
    admission(channel.admission, input);
    record.admission = structuredClone(channel.admission);
    record.phase = "transactions";
    await save();
    for (const operation of operations) {
      bounded();
      const transaction = await runDarwinFileTransaction(
        {
          ...operation,
          ...(operation.type === "recover"
            ? {}
            : {
                allocation: record.state.allocation,
                leaf: record.state.leaf,
                temporary: record.state.temporary,
              }),
        },
        {
          nonce: input.request.nonce,
          state: structuredClone(record.state),
          send: channel.send,
          receive: channel.receive,
          verify: effects.verify,
          barrier: effects.barrier,
          authorizeCleanup: prior ? verifyRetirement : undefined,
          async persist(kind, value) {
            bounded();
            record.events.push({ kind, ...value });
            record.state = value.state;
            await save();
          },
        },
      );
      if (transaction.state) record.state = structuredClone(transaction.state);
      if (transaction.status === "INTERRUPTED") {
        interrupted = true;
        break;
      }
      requireDarwin(transaction.status === "OBSERVED");
      if (operation.type === "finish") break;
    }
    bounded();
    record.status = interrupted ? "INTERRUPTED" : "OBSERVED";
  } catch {
    record.status = "FAIL";
  }
  if (channel) {
    record.phase = "retirement";
    await save();
    channel.close();
    try {
      const settled = structuredClone(
        await effects.retire(structuredClone(input), structuredClone(record)),
      );
      const verifier = rootIdentity(settled.verifier);
      const completion = await channel.completion;
      requireDarwin(
        settled.independent === true &&
          settled.helpersSettled === true &&
          settled.requestSha256 === requestSha256 &&
          sameDarwinIdentity(settled.helper, record.admission.helper) &&
          verifier.pid !== record.admission.helper.pid &&
          hash(settled.receiptSha256) &&
          completion &&
          completion.failed === false &&
          completion.remainingMessages === 0 &&
          completion.partialBytes === 0 &&
          (interrupted
            ? (completion.code === 126 && completion.signal === null) ||
              (completion.code === null && completion.signal === "SIGKILL")
            : record.status !== "OBSERVED" ||
              (completion.code === 0 && completion.signal === null)),
      );
      record.helperSettlementSha256 = settled.receiptSha256;
    } catch {
      record.status = "FAIL";
    }
    channel.dispose();
  }
  record.phase = "retained";
  await save();
  return structuredClone(record);
}
