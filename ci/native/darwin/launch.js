import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { darwinAdmissionChannel } from "./channel.js";
import {
  assertDarwinAuthority,
  darwinLaunchDigest,
  digest,
  inspectDarwinMachO,
  normalizeDarwinArguments,
  normalizeDarwinIdentity,
  normalizeDarwinLaunch,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";

async function protectedBytes(entry, gid, mode, maximum) {
  requireDarwin((await realpath(entry.path)) === entry.path);
  const handle = await open(
    entry.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat({ bigint: true });
    requireDarwin(
      before.isFile() &&
        before.uid === 0n &&
        before.gid === BigInt(gid) &&
        before.nlink === 1n &&
        (before.mode & 0o7777n) === BigInt(mode) &&
        before.size > 0n &&
        before.size <= BigInt(maximum),
    );
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        size,
        buffer.length - size,
        size,
      );
      if (!bytesRead) break;
      size += bytesRead;
    }
    const after = await handle.stat({ bigint: true }),
      named = await lstat(entry.path, { bigint: true });
    requireDarwin(
      BigInt(size) === before.size &&
        after.size === before.size &&
        after.mtimeNs === before.mtimeNs &&
        after.ctimeNs === before.ctimeNs &&
        named.dev === before.dev &&
        named.ino === before.ino &&
        named.mode === before.mode &&
        named.uid === 0n &&
        named.gid === BigInt(gid) &&
        named.nlink === 1n &&
        (await realpath(entry.path)) === entry.path,
    );
    const bytes = buffer.subarray(0, size);
    requireDarwin(digest(bytes) === entry.sha256);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function nativeTransport(request, args, verified, onHelper) {
  inspectDarwinMachO(
    await protectedBytes(request.launcher, 0, 0o550, 134217728),
  );
  const image = inspectDarwinMachO(
    await protectedBytes(request.executable, request.gid, 0o550, 134217728),
  );
  requireDarwin(
    JSON.stringify(image.libraries) === JSON.stringify(verified.libraries),
  );
  await protectedBytes(request.policy, 0, 0o400, 1048576);
  const child = spawn(
    request.launcher.path,
    [
      String(request.uid),
      String(request.gid),
      request.custody,
      request.storage,
      request.workspace,
      request.executable.path,
      request.executable.sha256,
      request.executable.cdhash,
      request.policy.path,
      request.policy.sha256,
      request.nonce,
      "--",
      ...args,
    ],
    {
      cwd: request.custody,
      env: { CI: "true", GITHUB_ACTIONS: "true", PATH: "/nonexistent" },
      stdio: ["pipe", "pipe", "ignore", "pipe"],
    },
  );
  return darwinAdmissionChannel(child, onHelper);
}

/** Dedicated external admission; callbacks belong to reviewed native input,
 * policy, receipt and retirement owners, not provider self-reporting. */
export async function admitDarwinLaunch(
  input,
  argumentsList,
  approvedSha256,
  effects,
  {
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
    uid = process.geteuid?.(),
    now = () => performance.now(),
  } = {},
) {
  const request = normalizeDarwinLaunch(input),
    args = normalizeDarwinArguments(argumentsList);
  requireDarwin(
    platform === "darwin" &&
      architecture === "x64" &&
      uid === 0 &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "macos15" &&
      typeof effects?.persist === "function",
  );
  const record = {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    requestSha256: darwinLaunchDigest(request, args),
    status: "BLOCKED",
    phase: "inputs",
    admission: "not-started",
    helpers: [],
    payload: null,
    missingInputs: [],
    reservation: "RETAINED",
  };
  for (const [key, inputName] of Object.entries({
    verifyInputs: "darwin-reviewed-system-source-loader-inputs",
    inspect: "darwin-native-identity-verifier",
    verifyAuthority: "darwin-complete-policy-and-custody-verifier",
    verifyReceipt: "darwin-protected-receipt-verifier",
    retire: "darwin-independent-retirement",
  }))
    if (typeof effects[key] !== "function")
      record.missingInputs.push(inputName);
  if (!approvedSha256)
    record.missingInputs.push("independent-darwin-launch-approval");
  let persistence = Promise.resolve();
  const save = () => {
    const snapshot = structuredClone(record),
      write = () => effects.persist(snapshot);
    // A late helper write must never overwrite the subsequent failure receipt.
    persistence = persistence.then(write, write);
    return persistence;
  };
  if (record.missingInputs.length) {
    await save();
    return { record, transport: null };
  }
  const start = now();
  let transport,
    admissionFailed = false;
  const bounded = () => {
    const elapsed = now() - start;
    requireDarwin(
      !admissionFailed &&
        Number.isFinite(elapsed) &&
        elapsed >= 0 &&
        elapsed <= 30000,
    );
  };
  const verifiers = (values, payload) => {
    requireDarwin(
      Array.isArray(values) && values.length > 0 && values.length <= 4,
    );
    const pids = new Set();
    for (const value of values) {
      const identity = normalizeDarwinIdentity(value);
      requireDarwin(
        [
          identity.uid,
          identity.ruid,
          identity.svuid,
          identity.gid,
          identity.rgid,
          identity.svgid,
        ].every((id) => id === 0) &&
          identity.pid !== record.helpers[0].identity.pid &&
          identity.pid !== payload?.pid &&
          identity.asid !== payload?.asid &&
          !pids.has(identity.pid),
      );
      pids.add(identity.pid);
      const existing = record.helpers.find(
        (entry) => entry.identity.pid === identity.pid,
      );
      if (existing)
        requireDarwin(
          existing.role === "verifier" &&
            sameDarwinIdentity(existing.identity, identity),
        );
      else record.helpers.push({ role: "verifier", identity });
    }
  };
  try {
    requireDarwin(approvedSha256 === record.requestSha256);
    const verified = await effects.verifyInputs(
      structuredClone(request),
      approvedSha256,
      [...args],
    );
    if (verified.missingInputs !== undefined) {
      const missing = verified.missingInputs;
      requireDarwin(
        Array.isArray(missing) &&
          Object.getPrototypeOf(missing) === Array.prototype &&
          missing.length <= 256 &&
          Reflect.ownKeys(missing).length === missing.length + 1,
      );
      record.missingInputs = Array.from(
        { length: missing.length },
        (_, index) => {
          const field = Object.getOwnPropertyDescriptor(missing, index);
          requireDarwin(
            field?.enumerable &&
              Object.hasOwn(field, "value") &&
              typeof field.value === "string" &&
              field.value.length > 0 &&
              Buffer.byteLength(field.value) <= 512 &&
              !/[\u0000-\u001f\u007f\uD800-\uDFFF]/u.test(field.value),
          );
          return field.value;
        },
      );
      if (record.missingInputs.length) {
        await save();
        return { record, transport: null };
      }
    }
    requireDarwin(
      verified.approvedSha256 === approvedSha256 &&
        verified.bindings &&
        Object.keys(verified.bindings).length ===
          Object.keys(request.bindings).length &&
        Object.keys(request.bindings).every(
          (key) =>
            Object.hasOwn(verified.bindings, key) &&
            verified.bindings[key] === request.bindings[key],
        ),
    );
    bounded();
    record.admission = "possible";
    record.status = "RUNNING";
    record.phase = "park";
    await save();
    transport = await (effects.launchParked ?? nativeTransport)(
      structuredClone(request),
      [...args],
      verified,
      async (value) => {
        bounded();
        requireDarwin(record.helpers.length === 0);
        const helper = normalizeDarwinIdentity(value);
        requireDarwin(
          [
            helper.uid,
            helper.ruid,
            helper.svuid,
            helper.gid,
            helper.rgid,
            helper.svgid,
          ].every((id) => id === 0),
        );
        record.helpers.push({ role: "launcher", identity: helper });
        record.phase = "helper";
        await save();
        bounded();
        const observed = await effects.inspect(structuredClone(request), {
          helper: structuredClone(helper),
          payload: null,
        });
        requireDarwin(
          sameDarwinIdentity(observed.helper, helper) &&
            observed.payload === null,
        );
        verifiers(observed.verifiers, null);
        await save();
        bounded();
        const receipt = await effects.verifyReceipt(
          structuredClone(request),
          structuredClone(record),
        );
        requireDarwin(receipt.sha256 === digest(JSON.stringify(record) + "\n"));
        bounded();
      },
    );
    const ready = await transport.ready;
    const helper = normalizeDarwinIdentity(ready.helper),
      payload = normalizeDarwinIdentity(ready.payload);
    requireDarwin(
      record.helpers.length > 0 &&
        sameDarwinIdentity(record.helpers[0].identity, helper),
    );
    record.payload = payload;
    record.phase = "park";
    await save();
    const observed = await effects.inspect(structuredClone(request), {
      helper: structuredClone(helper),
      payload: structuredClone(payload),
    });
    requireDarwin(
      sameDarwinIdentity(observed.helper, helper) &&
        sameDarwinIdentity(observed.payload, payload) &&
        helper.pid !== payload.pid &&
        helper.uid === 0 &&
        helper.ruid === 0 &&
        helper.svuid === 0 &&
        payload.asid > 0 &&
        helper.asid !== payload.asid &&
        payload.auid === request.uid &&
        [payload.uid, payload.ruid, payload.svuid].every(
          (id) => id === request.uid,
        ) &&
        [payload.gid, payload.rgid, payload.svgid].every(
          (id) => id === request.gid,
        ) &&
        Array.isArray(observed.verifiers) &&
        observed.verifiers.length > 0 &&
        observed.verifiers.length <= 4,
    );
    verifiers(observed.verifiers, payload);
    record.phase = "verify";
    await save();
    const authority = structuredClone(
      assertDarwinAuthority(
        await effects.verifyAuthority(
          structuredClone(request),
          structuredClone(record),
        ),
        request,
        record,
      ),
    );
    record.authority = structuredClone(authority);
    bounded();
    record.phase = "release";
    await save();
    // Fresh root-custody read and native policy/identity reinspection follow
    // persistence. No effects are released on an unverified or stale receipt.
    const receipt = await effects.verifyReceipt(
      structuredClone(request),
      structuredClone(record),
    );
    requireDarwin(receipt.sha256 === digest(JSON.stringify(record) + "\n"));
    const fresh = assertDarwinAuthority(
      await effects.verifyAuthority(
        structuredClone(request),
        structuredClone(record),
      ),
      request,
      record,
    );
    requireDarwin(JSON.stringify(fresh) === JSON.stringify(authority));
    bounded();
    await transport.release();
    record.status = "ADMITTED";
    await save();
    const native = transport,
      admitted = structuredClone(record);
    let settling = false;
    return {
      record: structuredClone(admitted),
      transport: {
        ...native,
        async settle() {
          requireDarwin(!settling);
          settling = true;
          // The protected retirement owner must independently settle the domain
          // before releasing the root helper's audit-session reference.
          await effects.retire(
            structuredClone(request),
            structuredClone(admitted),
          );
          await native.settle();
        },
      },
    };
  } catch {
    admissionFailed = true;
    transport?.close();
    record.status = "FAIL";
    await save();
    // A closed parked channel is not proof that the UID/audit domain or root
    // helpers retired. The separate retirement owner must settle these effects.
    return { record, transport: null };
  }
}
