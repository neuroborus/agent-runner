import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { protectedBytes } from "./private-files.js";
import {
  DARWIN_PROCESS_LIMIT,
  digest,
  normalizeDarwinIdentity,
  normalizeDarwinLaunch,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";

const HASH = /^[a-f0-9]{64}$/u;
const DEAD_FIELDS = [
  "pid",
  "uid",
  "gid",
  "ruid",
  "rgid",
  "svuid",
  "svgid",
  "startSeconds",
  "startMicroseconds",
];
const sameProcess = (a, b) => DEAD_FIELDS.every((key) => a[key] === b[key]);
const root = (value) => {
  const identity = normalizeDarwinIdentity(value);
  requireDarwin(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
};
const member = (value, request, asid) => {
  const identity = normalizeDarwinIdentity(value);
  requireDarwin(
    identity.auid === request.uid &&
      identity.asid === asid &&
      ["uid", "ruid", "svuid"].every((key) => identity[key] === request.uid) &&
      ["gid", "rgid", "svgid"].every((key) => identity[key] === request.gid),
  );
  return identity;
};

/** Reads only the fixed protected admission receipt. Its expected digest comes
 * from trusted custody, never from hashing an arbitrary observed file. */
export async function readDarwinRecoveryReceipt(
  input,
  expectedSha256,
  retirementSha256,
) {
  const request = normalizeDarwinLaunch(input);
  requireDarwin(
    typeof expectedSha256 === "string" &&
      HASH.test(expectedSha256) &&
      (await realpath(request.custody)) === request.custody,
  );
  const handle = await open(
    request.custody,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat({ bigint: true });
    requireDarwin(
      before.isDirectory() &&
        before.uid === 0n &&
        before.gid === 0n &&
        (before.mode & 0o7777n) === 0o700n,
    );
    const bytes = await protectedBytes(
      {
        path: request.custody + "/darwin-admission.json",
        sha256: expectedSha256,
      },
      0,
      0o400,
      1048576,
    );
    const receipt = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    requireDarwin(Buffer.from(JSON.stringify(receipt) + "\n").equals(bytes));
    let previousRetirement = null;
    if (retirementSha256 !== undefined) {
      requireDarwin(
        typeof retirementSha256 === "string" && HASH.test(retirementSha256),
      );
      const previousBytes = await protectedBytes(
          {
            path: request.custody + "/darwin-retirement.json",
            sha256: retirementSha256,
          },
          0,
          0o400,
          1048576,
        ),
        previous = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(previousBytes),
        );
      requireDarwin(
        Buffer.from(JSON.stringify(previous) + "\n").equals(previousBytes) &&
          previous.candidateSha === request.candidateSha &&
          previous.nonce === request.nonce &&
          previous.requestSha256 === receipt.requestSha256 &&
          previous.reservation === "RETAINED",
      );
      previousRetirement = previous;
    }
    const after = await lstat(request.custody, { bigint: true });
    requireDarwin(
      after.dev === before.dev &&
        after.ino === before.ino &&
        after.mode === before.mode &&
        after.uid === before.uid &&
        after.gid === before.gid &&
        (await realpath(request.custody)) === request.custody,
    );
    return {
      receipt,
      receiptSha256: expectedSha256,
      previousRetirement,
    };
  } finally {
    await handle.close();
  }
}

function recovery(value, request, approvedSha256) {
  const receipt = value.receipt;
  requireDarwin(
    receipt &&
      receipt.schemaVersion === 1 &&
      receipt.candidateSha === request.candidateSha &&
      receipt.nonce === request.nonce &&
      receipt.requestSha256 === approvedSha256 &&
      HASH.test(approvedSha256) &&
      value.receiptSha256 === digest(JSON.stringify(receipt) + "\n") &&
      receipt.reservation === "RETAINED" &&
      receipt.processLimit === DARWIN_PROCESS_LIMIT &&
      receipt.admission === "possible" &&
      ["RUNNING", "ADMITTED", "FAIL"].includes(receipt.status) &&
      Array.isArray(receipt.helpers) &&
      receipt.helpers.length > 0 &&
      receipt.helpers.length <= 16,
  );
  if (!receipt.payload)
    return { missingInputs: ["darwin-protected-payload-audit-identity"] };
  const payload = normalizeDarwinIdentity(receipt.payload);
  requireDarwin(payload.asid > 0);
  member(payload, request, payload.asid);
  const helpers = receipt.helpers.map((entry) => {
    requireDarwin(["launcher", "verifier"].includes(entry.role));
    const identity = root(entry.identity);
    requireDarwin(identity.asid !== payload.asid);
    return identity;
  });
  const previous = value.previousRetirement;
  if (previous !== undefined && previous !== null)
    requireDarwin(
      previous.schemaVersion === 1 &&
        previous.candidateSha === request.candidateSha &&
        previous.nonce === request.nonce &&
        previous.requestSha256 === approvedSha256 &&
        previous.reservation === "RETAINED",
    );
  const previousHelpers =
    previous?.helpers === undefined ? [] : previous.helpers;
  requireDarwin(
    Array.isArray(previousHelpers) &&
      previousHelpers.length <= 16 &&
      (previous?.helpers !== undefined ||
        (previous?.custodian === undefined && previous?.domain === undefined)),
  );
  // An interrupted recovery can retain both its new custodian and older ones
  // already carried in helpers. Preserve the whole chain before any signals.
  for (const identity of [
    ...previousHelpers,
    ...(previous?.custodian === undefined ? [] : [previous.custodian]),
  ].map(root)) {
    requireDarwin(identity.asid !== payload.asid);
    if (!helpers.some((value) => sameDarwinIdentity(value, identity)))
      helpers.push(identity);
  }
  requireDarwin(helpers.length <= 16);
  requireDarwin(
    new Set(helpers.map((value) => value.pid)).size === helpers.length,
  );
  const previousMembers = previous ? previous.members : [];
  requireDarwin(
    Array.isArray(previousMembers) && previousMembers.length <= 1024,
  );
  const members = [payload];
  for (const identity of previousMembers.map((value) =>
    member(value, request, payload.asid),
  ))
    if (!members.some((value) => sameDarwinIdentity(value, identity)))
      members.push(identity);
  requireDarwin(members.length <= 1024);
  return {
    payload,
    helpers,
    members,
  };
}

/** A full UID enumeration is not ancestry evidence. Unknown zombies, stale
 * identities, errors and full buffers cannot establish an empty domain. */
export function assessDarwinEnumeration(value, input, asid, known = []) {
  const request = normalizeDarwinLaunch(input);
  requireDarwin(Array.isArray(known) && known.length <= 1024);
  known = known.map((value) => member(value, request, asid));
  requireDarwin(
    value &&
      Object.keys(value).sort().join(",") ===
        "capacity,complete,live,uid,zombies" &&
      value.complete === true &&
      value.capacity === DARWIN_PROCESS_LIMIT + 1 &&
      value.uid === request.uid &&
      Array.isArray(value.live) &&
      Array.isArray(value.zombies) &&
      value.live.length + value.zombies.length <= DARWIN_PROCESS_LIMIT,
  );
  const live = value.live.map((value) => member(value, request, asid));
  const pids = new Set(live.map((value) => value.pid));
  requireDarwin(pids.size === live.length);
  for (const dead of value.zombies) {
    requireDarwin(
      dead &&
        Object.keys(dead).sort().join(",") ===
          [...DEAD_FIELDS].sort().join(",") &&
        known.some((identity) => sameProcess(identity, dead)) &&
        !pids.has(dead.pid),
    );
    pids.add(dead.pid);
  }
  return { live, zombies: structuredClone(value.zombies) };
}

/** Dedicated external retirement. All callbacks are protected native owners;
 * missing source/ABI/custody capabilities leave exclusions in force. */
export async function retireDarwinDomain(
  input,
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
  const request = normalizeDarwinLaunch(input);
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
    requestSha256: approvedSha256,
    status: "BLOCKED",
    phase: "recovery",
    reservation: "RETAINED",
    missingInputs: [],
    members: [],
    helpersSettled: false,
    freshVerifier: null,
    work: 0,
  };
  for (const key of [
    "recover",
    "verifyRecovery",
    "stopAdmissions",
    "enumerate",
    "signal",
    "verifyRetirement",
    "settleCustody",
  ])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("darwin-retirement-" + key);
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  const start = now(),
    verifiers = [];
  const bounded = () => {
    const elapsed = now() - start;
    requireDarwin(
      Number.isFinite(elapsed) &&
        elapsed >= 0 &&
        elapsed <= 30000 &&
        record.work <= 1024,
    );
  };
  const bindings = (value) =>
    requireDarwin(
      value &&
        Object.keys(value).length === Object.keys(request.bindings).length &&
        Object.keys(request.bindings).every(
          (key) => value[key] === request.bindings[key],
        ),
    );
  const verifier = (value) => {
    const identity = root(value);
    requireDarwin(
      identity.asid !== record.domain.asid &&
        !record.helpers.some((helper) => helper.pid === identity.pid) &&
        identity.pid !== record.custodian.pid,
    );
    verifiers.push(identity);
    return identity;
  };
  try {
    const recovered = await effects.recover(
        structuredClone(request),
        approvedSha256,
      ),
      domain = recovery(recovered, request, approvedSha256);
    if (domain.missingInputs) {
      record.missingInputs = domain.missingInputs;
      await save();
      return record;
    }
    record.domain = {
      uid: request.uid,
      gid: request.gid,
      asid: domain.payload.asid,
      auid: request.uid,
    };
    record.helpers = domain.helpers;
    record.members = domain.members;
    record.receiptSha256 = recovered.receiptSha256;
    record.status = "RUNNING";
    record.phase = "audit-custody";
    record.custodyAdmission = "possible";
    await save();
    // Recovery also admits separately receipted root custody of the audit
    // session. It must exist before stopping any old launcher/session holder.
    bounded();
    const verified = await effects.verifyRecovery(
      structuredClone(request),
      structuredClone(record),
    );
    if (verified.missingInputs?.length) {
      requireDarwin(
        Array.isArray(verified.missingInputs) &&
          verified.missingInputs.length <= 256 &&
          verified.missingInputs.every(
            (value) =>
              typeof value === "string" &&
              value.length > 0 &&
              value.length <= 512 &&
              !/[\u0000-\u001f\u007f]/u.test(value),
          ),
      );
      record.status = "BLOCKED";
      record.missingInputs = [...verified.missingInputs];
      await save();
      return record;
    }
    bindings(verified.bindings);
    requireDarwin(
      verified.requestSha256 === approvedSha256 &&
        verified.auditSessionHeld === true &&
        verified.asid === record.domain.asid,
    );
    record.custodian = root(verified.custodian);
    requireDarwin(
      record.custodian.asid !== record.domain.asid &&
        !record.helpers.some((helper) => helper.pid === record.custodian.pid),
    );
    bounded();
    record.status = "RUNNING";
    record.phase = "stop-admissions";
    await save();
    bounded();
    const stopped = await effects.stopAdmissions(
      structuredClone(request),
      structuredClone(record),
    );
    requireDarwin(
      stopped.closed === true &&
        stopped.requestSha256 === approvedSha256 &&
        HASH.test(stopped.receiptSha256),
    );
    record.stopSha256 = stopped.receiptSha256;
    const signal = async (identity, role) => {
      bounded();
      record.work++;
      bounded();
      record.phase = "signal";
      record.pending = { role, identity };
      await save();
      bounded();
      const result = await effects.signal(
        structuredClone(request),
        structuredClone(identity),
        role,
      );
      verifier(result.verifier);
      requireDarwin(
        sameDarwinIdentity(result.identity, identity) &&
          ["sent", "not-found", "zombie"].includes(result.outcome),
      );
      delete record.pending;
      bounded();
      await save();
    };
    for (const helper of record.helpers) await signal(helper, "helper");
    for (let pass = 0; pass < 32; pass++) {
      bounded();
      record.work++;
      bounded();
      record.phase = "enumerate";
      await save();
      bounded();
      const observed = await effects.enumerate(
        structuredClone(request),
        structuredClone(record.domain),
      );
      verifier(observed.verifier);
      const enumeration = assessDarwinEnumeration(
        observed.enumeration,
        request,
        record.domain.asid,
        record.members,
      );
      for (const identity of enumeration.live)
        if (
          !record.members.some((value) => sameDarwinIdentity(value, identity))
        )
          record.members.push(identity);
      requireDarwin(record.members.length <= 1024);
      bounded();
      await save();
      if (enumeration.live.length) {
        for (const identity of enumeration.live)
          await signal(identity, "member");
        continue;
      }
      record.phase = "fresh-verification";
      await save();
      bounded();
      const fresh = await effects.verifyRetirement(
        structuredClone(request),
        structuredClone(record),
      );
      const freshIdentity = root(fresh.verifier);
      requireDarwin(
        fresh.custodyStillHeld === true &&
          sameDarwinIdentity(fresh.custodian, record.custodian),
      );
      requireDarwin(
        !verifiers.some((value) => value.pid === freshIdentity.pid),
      );
      verifier(freshIdentity);
      bindings(fresh.bindings);
      requireDarwin(
        fresh.stopSha256 === record.stopSha256 &&
          Array.isArray(fresh.helpersSettled) &&
          fresh.helpersSettled.length === record.helpers.length &&
          record.helpers.every(
            (helper) =>
              fresh.helpersSettled.filter((value) =>
                sameDarwinIdentity(value, helper),
              ).length === 1,
          ),
      );
      requireDarwin(
        assessDarwinEnumeration(
          fresh.enumeration,
          request,
          record.domain.asid,
          record.members,
        ).live.length === 0,
      );
      bounded();
      record.freshVerifier = freshIdentity;
      record.phase = "custody-settlement";
      await save();
      bounded();
      const settled = await effects.settleCustody(
        structuredClone(request),
        structuredClone(record),
      );
      requireDarwin(
        sameDarwinIdentity(settled.custodian, record.custodian) &&
          settled.settled === true &&
          settled.independent === true,
      );
      requireDarwin(
        !verifiers.some((value) => value.pid === settled.verifier?.pid),
      );
      verifier(settled.verifier);
      bounded();
      record.helpersSettled = true;
      record.status = "RETIRED";
      record.phase = "retired";
      await save();
      return structuredClone(record);
    }
    throw new Error("Darwin retirement work exhausted");
  } catch {
    record.status = "FAIL";
    await save();
    return structuredClone(record);
  }
}
