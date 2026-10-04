import { performance } from "node:perf_hooks";

import {
  closed,
  dense,
  digest,
  hash,
  requireWindows,
  normalizeWindowsLaunch,
  sameWindowsIdentity,
  systemIdentity,
} from "./protocol.js";
import {
  normalizeWindowsFileIdentity,
  normalizeWindowsFileState,
  normalizeWindowsFileMessage,
  runWindowsFileTransaction,
} from "./files-protocol.js";

const STATE = ["base", "root", "allocation", "leaf", "temporary", "alias"];
const stateOf = (value) =>
  Object.fromEntries(STATE.map((key) => [key, value[key]]));
export function normalizeWindowsFileInput(value) {
  closed(value, ["request", "base", "root", "reviewSha256"]);
  requireWindows(hash(value.reviewSha256));
  const input = {
    request: normalizeWindowsLaunch(value.request),
    base: normalizeWindowsFileIdentity(value.base),
    root: normalizeWindowsFileIdentity(value.root),
    reviewSha256: value.reviewSha256,
  };
  normalizeWindowsFileState({
    base: input.base,
    root: input.root,
    allocation: null,
    leaf: null,
    temporary: null,
    alias: false,
  });
  return input;
}
/** The external native bridge uses this exact vector, held verified images and
 * a four-handle list: root, base, private stdin and private stdout/stderr. Node
 * stdio, a pathname reopen or a restricted payload launcher is no substitute. */
export function windowsFileHelperArguments(value, handles) {
  const input = normalizeWindowsFileInput(value);
  closed(handles, ["root", "base"]);
  for (const handle of Object.values(handles))
    requireWindows(
      typeof handle === "string" &&
        /^[1-9][0-9]{0,19}$/u.test(handle) &&
        BigInt(handle) < 0xffffffffffffffffn,
    );
  requireWindows(handles.root !== handles.base);
  return [
    input.request.nonce,
    handles.root,
    handles.base,
    input.root,
    input.base,
  ];
}
function admission(value, input, helper, sourceSha256) {
  closed(value, [
    "independent",
    "helper",
    "verifier",
    "requestSha256",
    "reviewSha256",
    "sourceSha256",
    "helperSha256",
    "signatureSha256",
    "closureSha256",
    "base",
    "root",
    "soleParentAuthority",
    "privateParents",
    "explicitHandleList",
    "inheritedHandleCount",
    "windows2025X64",
    "receiptSha256",
  ]);
  const verifier = systemIdentity(value.verifier);
  requireWindows(
    value.independent === true &&
      verifier.pid !== helper.pid &&
      sameWindowsIdentity(value.helper, helper) &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      value.reviewSha256 === input.reviewSha256 &&
      value.sourceSha256 === sourceSha256 &&
      value.helperSha256 === input.request.executable.sha256 &&
      value.signatureSha256 === input.request.executable.signatureSha256 &&
      value.closureSha256 === input.request.bindings.closure &&
      value.base === input.base &&
      value.root === input.root &&
      value.soleParentAuthority === true &&
      value.privateParents === true &&
      value.explicitHandleList === true &&
      value.inheritedHandleCount === 4 &&
      value.windows2025X64 === true &&
      hash(value.receiptSha256),
  );
  return structuredClone(value);
}
export function normalizeWindowsFileRecovery(value, input) {
  closed(value, [
    "independent",
    "immutable",
    "protectedDacl",
    "heldIdentitiesRetained",
    "requestSha256",
    "candidateSha",
    "nonce",
    "receiptSha256",
    "sourceSha256",
    "status",
    "operation",
    "state",
    "stateSha256",
    "helper",
    "admission",
    "observation",
  ]);
  requireWindows(
    value?.independent === true &&
      value.immutable === true &&
      value.protectedDacl === true &&
      value.heldIdentitiesRetained === true &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      value.candidateSha === input.request.candidateSha &&
      value.nonce === input.request.nonce &&
      hash(value.receiptSha256) &&
      hash(value.sourceSha256) &&
      ["publish", "replace", "cleanup", "inspect", "finish"].includes(
        value.operation,
      ) &&
      ["FAIL", "INTERRUPTED", "OBSERVED"].includes(value.status),
  );
  const state = normalizeWindowsFileState(value.state),
    helper = systemIdentity(value.helper);
  requireWindows(
    state.base === input.base &&
      state.root === input.root &&
      (state.allocation !== null || value.operation === "cleanup") &&
      value.stateSha256 === digest(JSON.stringify(state)),
  );
  closed(value.observation, [
    "stateSha256",
    "receiptSha256",
    "leafSha256",
    "temporarySha256",
  ]);
  requireWindows(
    value.observation.stateSha256 === value.stateSha256 &&
      hash(value.observation.receiptSha256),
  );
  for (const key of ["leaf", "temporary"])
    requireWindows(
      state[key] === null
        ? value.observation[key + "Sha256"] === null
        : hash(value.observation[key + "Sha256"]),
    );
  admission(value.admission, input, helper, value.sourceSha256);
  return structuredClone({ ...value, state, helper });
}

/** Imports are effect-free. Protected external review/open/admission/readers
 * provide actual native custody and observations, never producer text. A
 * successful protocol remains OBSERVED with every reservation retained. */
export async function runWindowsFileSession(
  value,
  commands,
  effects,
  {
    recovery = null,
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  const input = normalizeWindowsFileInput(value),
    requestSha256 = digest(JSON.stringify(input));
  const operations = dense(commands, 30).map((value) => {
    closed(value, ["type", "bytes"]);
    requireWindows(
      [
        "allocate",
        "publish",
        "replace",
        "inspect",
        "cleanup",
        "finish",
      ].includes(value.type) &&
        typeof value.bytes === "string" &&
        /^(?:[a-f0-9]{2}){0,4096}$/u.test(value.bytes) &&
        (["publish", "replace"].includes(value.type) || value.bytes === ""),
    );
    return { type: value.type, bytes: value.bytes };
  });
  requireWindows(
    operations.length &&
      typeof effects?.persist === "function" &&
      operations.slice(0, -1).every((operation) => operation.type !== "finish"),
  );
  if (operations.at(-1).type !== "finish")
    operations.push({ type: "finish", bytes: "" });
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
    helper: null,
    admission: null,
    state: {
      base: input.base,
      root: input.root,
      allocation: null,
      leaf: null,
      temporary: null,
      alias: false,
    },
  };
  for (const key of ["review", "open", "admit", "verify", "barrier", "retire"])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("windows-files-" + key);
  if (recovery !== null)
    for (const key of ["readRecovery", "verifyRetirement"])
      if (typeof effects[key] !== "function")
        record.missingInputs.push("windows-files-" + key);
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  let channel,
    prior,
    interrupted = false,
    expired = false,
    rejectDeadline;
  const closeChannel = () => {
    try {
      channel?.close();
    } catch {
      record.status = "FAIL";
    }
  };
  const started = now(),
    deadline = new Promise((_, reject) => {
      rejectDeadline = reject;
    });
  deadline.catch(() => {});
  const timer = schedule(() => {
    expired = true;
    closeChannel();
    rejectDeadline(new Error("Windows file session deadline"));
  }, 30000);
  const active = () => {
    const elapsed = now() - started;
    requireWindows(
      !expired && Number.isFinite(elapsed) && elapsed >= 0 && elapsed < 30000,
    );
  };
  const wait = async (action) => {
    active();
    const result = await Promise.race([action(), deadline]);
    active();
    return result;
  };
  const retired = async (state) => {
    const evidence = structuredClone(
      await wait(() =>
        effects.verifyRetirement(
          structuredClone(input),
          structuredClone(prior),
          structuredClone(state),
        ),
      ),
    );
    const verifier = systemIdentity(evidence.verifier);
    requireWindows(
      evidence.independent === true &&
        evidence.noLiveMembers === true &&
        evidence.admissionsClosed === true &&
        evidence.helpersSettled === true &&
        evidence.sameHeldObjects === true &&
        evidence.stateSha256 === digest(JSON.stringify(state)) &&
        evidence.requestSha256 === requestSha256 &&
        evidence.recoverySha256 === prior.receiptSha256 &&
        evidence.restrictingSid === input.request.restrictingSid &&
        sameWindowsIdentity(evidence.helper, prior.helper) &&
        !sameWindowsIdentity(verifier, prior.helper) &&
        verifier.pid !== record.helper?.pid &&
        hash(evidence.receiptSha256),
    );
    record.priorRetirementSha256 = evidence.receiptSha256;
    return {
      independent: true,
      retired: true,
      stateSha256: evidence.stateSha256,
      receiptSha256: evidence.receiptSha256,
    };
  };
  try {
    const review = structuredClone(
      await wait(() => effects.review(structuredClone(input), requestSha256)),
    );
    if (review.missingInputs?.length) {
      record.missingInputs = dense(review.missingInputs, 256);
      requireWindows(
        record.missingInputs.every(
          (item) =>
            typeof item === "string" && /^[a-z][a-z0-9-]{0,127}$/u.test(item),
        ),
      );
      await wait(save);
      return structuredClone(record);
    }
    requireWindows(
      review.independent === true &&
        review.approvedSha256 === requestSha256 &&
        review.reviewSha256 === input.reviewSha256 &&
        hash(review.sourceSha256) &&
        review.windows2025X64 === true &&
        review.sdkAndLoaderVerified === true &&
        review.ntfsSemanticsVerified === true &&
        review.soleParentAuthorityVerified === true,
    );
    record.sourceSha256 = review.sourceSha256;
    if (recovery !== null) {
      prior = normalizeWindowsFileRecovery(
        structuredClone(
          await wait(() =>
            effects.readRecovery(recovery, structuredClone(input)),
          ),
        ),
        input,
      );
      requireWindows(
        prior.sourceSha256 === review.sourceSha256 &&
          operations.every((operation) =>
            ["cleanup", "finish"].includes(operation.type),
          ),
      );
      await retired(prior.state);
      if (prior.state.allocation !== null)
        operations.unshift({
          type: "recover",
          ...stateOf(prior.state),
          bytes: "",
        });
    } else
      requireWindows(
        operations.every((operation) => operation.type !== "cleanup"),
      );
    record.status = "RUNNING";
    record.phase = "possible-admission";
    await wait(save);
    const opening = () =>
      Promise.resolve(effects.open(structuredClone(input))).then((value) => {
        channel = value;
        if (expired) value.close();
        return value;
      });
    channel = await wait(opening);
    requireWindows(
      ["send", "receive", "close", "dispose"].every(
        (key) => typeof channel?.[key] === "function",
      ),
    );
    record.helper = systemIdentity(channel.helper);
    await wait(save);
    const ready = normalizeWindowsFileMessage(
      await wait(() => channel.receive()),
      input.request.nonce,
    );
    requireWindows(
      ready.phase === "ready" &&
        JSON.stringify(stateOf(ready)) === JSON.stringify(record.state),
    );
    record.admission = admission(
      structuredClone(
        await wait(() =>
          effects.admit(
            structuredClone(input),
            structuredClone(record.helper),
            structuredClone(ready),
          ),
        ),
      ),
      input,
      record.helper,
      record.sourceSha256,
    );
    if (prior)
      requireWindows(!sameWindowsIdentity(record.helper, prior.helper));
    record.phase = "transactions";
    await wait(save);
    await wait(() => channel.send("start - - - -\n"));
    for (const operation of operations) {
      const transaction = await runWindowsFileTransaction(
        {
          type: operation.type,
          bytes: operation.bytes,
          allocation:
            operation.type === "recover"
              ? operation.allocation
              : record.state.allocation,
          leaf:
            operation.type === "recover" ? operation.leaf : record.state.leaf,
          temporary:
            operation.type === "recover"
              ? operation.temporary
              : record.state.temporary,
        },
        {
          nonce: input.request.nonce,
          state: structuredClone(record.state),
          recoveryOperation: prior?.operation,
          send: (message) => wait(() => channel.send(message)),
          receive: () => wait(() => channel.receive()),
          async verify(message, request) {
            const evidence = await wait(() => effects.verify(message, request));
            for (const retained of [prior, record]) {
              if (!retained?.observation) continue;
              for (const key of ["leaf", "temporary"])
                for (const known of ["leaf", "temporary"])
                  if (
                    message[key] !== null &&
                    message[key] === retained.state[known]
                  )
                    requireWindows(
                      evidence[key + "Sha256"] ===
                        retained.observation[known + "Sha256"],
                    );
            }
            return evidence;
          },
          barrier: (message) => wait(() => effects.barrier(message)),
          authorizeCleanup: prior ? retired : undefined,
          async persist(kind, value) {
            requireWindows(record.events.length < 192);
            record.events.push({ kind, ...value });
            record.state = structuredClone(value.state);
            if (value.observation)
              record.observation = structuredClone(value.observation);
            await wait(save);
          },
        },
      );
      if (transaction.state) record.state = structuredClone(transaction.state);
      if (transaction.status === "INTERRUPTED") {
        interrupted = true;
        break;
      }
      requireWindows(transaction.status === "OBSERVED");
    }
    record.status = interrupted ? "INTERRUPTED" : "OBSERVED";
  } catch {
    record.status = "FAIL";
  } finally {
    cancel(timer);
  }
  if (record.phase !== "review") {
    record.phase = "retirement";
    let rejectSettlement;
    const settlementDeadline = new Promise((_, reject) => {
      rejectSettlement = reject;
    });
    settlementDeadline.catch(() => {});
    const settlementTimer = schedule(
      () => rejectSettlement(new Error("Windows file retirement deadline")),
      30000,
    );
    try {
      try {
        await Promise.race([save(), settlementDeadline]);
      } catch {
        record.status = "FAIL";
      }
      closeChannel();
      const settlement = structuredClone(
        await Promise.race([
          effects.retire(structuredClone(input), structuredClone(record)),
          settlementDeadline,
        ]),
      );
      const verifier = systemIdentity(settlement.verifier);
      const completion = await Promise.race([
        channel?.completion,
        settlementDeadline,
      ]);
      requireWindows(
        record.helper &&
          settlement.independent === true &&
          settlement.helpersSettled === true &&
          settlement.requestSha256 === requestSha256 &&
          sameWindowsIdentity(settlement.helper, record.helper) &&
          verifier.pid !== record.helper.pid &&
          hash(settlement.receiptSha256) &&
          completion?.failed === false &&
          completion.partialBytes === 0 &&
          completion.remainingMessages === 0 &&
          Number.isSafeInteger(completion.code) &&
          completion.code >= 0 &&
          completion.code <= 0xffffffff &&
          completion.signal === null &&
          (record.status === "FAIL" ||
            completion.code === (interrupted ? 126 : 0)),
      );
      record.helperSettlementSha256 = settlement.receiptSha256;
    } catch {
      record.status = "FAIL";
    } finally {
      cancel(settlementTimer);
      try {
        channel?.dispose();
      } catch {
        record.status = "FAIL";
      }
    }
  }
  record.phase = "retained";
  await save();
  return structuredClone(record);
}
