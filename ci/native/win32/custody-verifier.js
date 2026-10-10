import { observationDigest } from "../index.js";
import {
  closed,
  dense,
  digest,
  hash,
  requireWindows,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  systemIdentity,
} from "./protocol.js";
import { normalizeWindowsFileIdentity } from "./files-protocol.js";
import { buildWindowsPolicy } from "./policy.js";
import {
  expectedAces,
  normalizeWindowsSecurityRead,
} from "./effective-protocol.js";
import {
  assertWindowsWfpFilterRead,
  assertWindowsWfpOwnersRead,
} from "./wfp-reader.js";
import {
  encode,
  integer,
  normalizeWindowsCustodyInput,
  processObservation,
  fileObservation,
  jobObservation,
  windowsVerificationArguments,
  WINDOWS_CUSTODY_DEADLINE_MS,
} from "./custody-protocol.js";

const same = (left, right) =>
  observationDigest(left) === observationDigest(right);
const retired = (observations) => ({
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
  nativeEventSha256: observationDigest(observations),
});

/** The caller owns a separately approved/admitted repository custody reader.
 * Its native lane supplies observations; its protected ledger precedes every
 * operation. This factory launches nothing and never retires that live reader.
 * Only raw framed IPC is replaceable for neutral protocol regressions. */
export function createWindowsCustodyVerifier(
  reader,
  {
    exchange,
    clock = Date.now,
    maximumSubjects = 32,
    deadline = clock() + WINDOWS_CUSTODY_DEADLINE_MS,
  } = {},
) {
  const native = reader?.verification;
  requireWindows(
    [32, 128].includes(maximumSubjects) &&
      native &&
      (typeof native.command === "function" || typeof exchange === "function"),
  );
  const observerInput = normalizeWindowsCustodyInput(native.input);
  requireWindows(
    Number.isSafeInteger(deadline) &&
      deadline > clock() &&
      deadline - clock() <= WINDOWS_CUSTODY_DEADLINE_MS,
  );
  let input,
    target,
    bridge,
    taskSha256,
    sequence = 0,
    failure,
    failed = false,
    tail = Promise.resolve(),
    pending = Promise.resolve();
  const subjects = new Map(),
    transfers = new Map(),
    files = new Map(),
    recoveredJobNonces = new Set();
  const verifier = () => systemIdentity(native.identity);
  const call = (name, values = []) => {
    const args = windowsVerificationArguments(name, values);
    const work = tail.then(async () => {
      if (failed) throw failure;
      try {
        requireWindows(clock() < deadline);
        verifier();
        if (!exchange) {
          const value = await native.command(name, args);
          requireWindows(clock() < deadline);
          return value;
        }
        const id = ++sequence;
        requireWindows(id <= 32768);
        const reply = await exchange(
          Buffer.from(["verify-" + name, id, ...args].join(" ") + "\n"),
        );
        requireWindows(
          Buffer.isBuffer(reply) &&
            reply.length <= 262144 &&
            reply.at(-1) === 10,
        );
        const frame = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(reply),
        );
        closed(frame, ["sequence", "value"]);
        requireWindows(frame.sequence === id && clock() < deadline);
        return frame.value;
      } catch (error) {
        failed = true;
        failure = error;
        throw error;
      }
    });
    tail = work.catch(() => {});
    return work;
  };
  const bind = (value) => {
    const declaration = normalizeWindowsCustodyInput(value);
    requireWindows(
      same(declaration.context, observerInput.context) &&
        declaration.nonce !== observerInput.nonce &&
        (!input || same(input, declaration)),
    );
    input ??= declaration;
    return declaration;
  };
  const retain = async (value) => {
    const identity = normalizeWindowsIdentity(value),
      key = observationDigest(identity);
    requireWindows(identity.pid !== verifier().pid);
    let held = subjects.get(key);
    if (!held) {
      const actual = await call("retain", [
        identity.pid,
        identity.creationTime,
      ]);
      closed(actual, ["slot", "process"]);
      const process = processObservation(actual.process);
      requireWindows(
        integer(actual.slot, maximumSubjects - 1) &&
          sameWindowsIdentity(process.identity, identity) &&
          ![...subjects.values()].some((entry) => entry.slot === actual.slot),
      );
      held = { identity, slot: actual.slot };
      subjects.set(key, held);
    }
    return held;
  };
  const observe = async (identity) => {
    const held = await retain(identity),
      actual = processObservation(await call("process", [held.slot]));
    requireWindows(sameWindowsIdentity(actual.identity, held.identity));
    return actual;
  };
  const empty = async (identity) => {
    const actual = await observe(identity),
      held = await retain(identity);
    requireWindows(actual.retired);
    const observed = await call("job", [held.slot]);
    let job;
    if (observed.absent === true) {
      closed(observed, ["absent"]);
      requireWindows(!transfers.has(held.slot));
      job = null;
    } else job = jobObservation(observed);
    requireWindows(!job || job.members.length === 0);
    if (job && transfers.has(held.slot)) {
      const { members: _members, ...before } = transfers.get(held.slot).job,
        { members: _current, ...after } = job;
      requireWindows(same(before, after));
    }
    return { actual, job };
  };
  const inventory = async (identities, jobSlots = []) => {
    dense(identities, maximumSubjects);
    const retained = await call("subjects");
    closed(retained, ["identities", "jobs"]);
    const expected = new Set(
        identities.map((identity) =>
          observationDigest(normalizeWindowsIdentity(identity)),
        ),
      ),
      actual = dense(retained.identities, maximumSubjects).map((identity) =>
        observationDigest(normalizeWindowsIdentity(identity)),
      );
    requireWindows(
      expected.size === identities.length &&
        actual.length === identities.length &&
        new Set(actual).size === actual.length &&
        actual.every((key) => expected.has(key)),
    );
    requireWindows(
      dense(retained.jobs, 32).every((slot) => integer(slot, 31)) &&
        same(retained.jobs, jobSlots),
    );
  };
  const recoveryJobs = async (owners) => {
    const observations = [];
    const settled = (value, compiler = false) => {
      if (value.absent === true) {
        closed(value, ["absent"]);
        return;
      }
      const job = jobObservation(value);
      requireWindows(
        job.members.length === 0 &&
          job.limitFlags === 0x2008 &&
          (compiler
            ? job.processLimit === 31 && job.uiRestrictions === 255
            : [1, 32].includes(job.processLimit) &&
              [0, 255].includes(job.uiRestrictions)),
      );
    };
    const unique = new Map(
      dense(owners, maximumSubjects).map((owner) => [
        observationDigest(owner),
        owner,
      ]),
    );
    for (const { identity, nonce } of unique.values()) {
      requireWindows(
        /^[a-f0-9]{32}$/u.test(nonce) && nonce !== observerInput.nonce,
      );
      const held = await retain(identity);
      for (let pass = 0; pass < 2; pass++) {
        const actual = await call("recovery-jobs", [held.slot, nonce]);
        closed(actual, ["nonce", "identity", "jobs", "compilerJob"]);
        requireWindows(
          actual.nonce === nonce &&
            sameWindowsIdentity(actual.identity, held.identity) &&
            dense(actual.jobs, 128).length === 128,
        );
        actual.jobs.forEach((job) => settled(job));
        settled(actual.compilerJob, true);
        observations.push(actual);
      }
      recoveredJobNonces.add(nonce);
    }
    return observations;
  };
  const file = async (pin) => {
    requireWindows(
      hash(pin.sha256) &&
        (pin.signatureSha256 == null || hash(pin.signatureSha256)),
    );
    const key = observationDigest(pin);
    if (!files.has(key)) {
      const actual = await call("file", [
        encode(pin.path),
        pin.sha256,
        pin.signatureSha256 ?? "-",
        pin.bytes ?? 134217728,
      ]);
      closed(actual, [
        "identity",
        "sha256",
        "signatureSha256",
        "daclSha256",
        "slot",
        "bytes",
      ]);
      normalizeWindowsFileIdentity(actual.identity);
      requireWindows(
        integer(actual.slot) &&
          integer(actual.bytes, pin.bytes ?? 134217728) &&
          actual.bytes > 0 &&
          actual.sha256 === pin.sha256 &&
          actual.signatureSha256 === (pin.signatureSha256 ?? null) &&
          hash(actual.daclSha256),
      );
      files.set(key, actual);
    }
    return files.get(key);
  };
  const read = async (pin) => {
    requireWindows(integer(pin.bytes, 8388608) && pin.bytes > 0);
    const held = await file(pin);
    requireWindows(
      integer(pin.bytes, 8388608) && pin.bytes > 0 && pin.bytes === held.bytes,
    );
    const bytes = Buffer.alloc(pin.bytes);
    for (let offset = 0; offset < bytes.length; offset += 32768) {
      const count = Math.min(32768, bytes.length - offset),
        frame = await call("read", [held.slot, offset, count]);
      closed(frame, ["hex"]);
      requireWindows(
        typeof frame.hex === "string" &&
          frame.hex.length === count * 2 &&
          /^[a-f0-9]+$/u.test(frame.hex),
      );
      Buffer.from(frame.hex, "hex").copy(bytes, offset);
    }
    requireWindows(digest(bytes) === pin.sha256);
    return bytes;
  };
  const image = async (identity, pin) => {
    const held = await retain(identity),
      actual = await call("image", [
        held.slot,
        pin.sha256,
        pin.signatureSha256,
      ]);
    closed(actual, ["sha256", "signatureSha256", "pathHex"]);
    requireWindows(
      actual.sha256 === pin.sha256 &&
        actual.signatureSha256 === pin.signatureSha256 &&
        actual.pathHex === encode(pin.path),
    );
    return actual;
  };
  const task = async (kind, nonce) => {
    const actual = await call("task", [kind, encode(nonce)]);
    if (actual.absent === true) closed(actual, ["absent"]);
    else {
      closed(actual, ["absent", "sha256", "instances"]);
      requireWindows(
        actual.absent === false &&
          hash(actual.sha256) &&
          integer(actual.instances, 32),
      );
    }
    return actual;
  };
  const recoverTask = async (nonce, sha256, identity) => {
    requireWindows(
      /^[a-f0-9]{32}$/u.test(nonce) &&
        nonce !== observerInput.nonce &&
        recoveredJobNonces.has(nonce),
    );
    const observations = [],
      installed = await task("custody", nonce);
    if (!installed.absent) {
      requireWindows(
        hash(sha256) &&
          installed.sha256 === sha256 &&
          installed.instances === 0,
      );
      observations.push(await empty(identity), await empty(identity));
      const subject = await retain(identity),
        removal = await call("task-remove", [
          "custody",
          encode(nonce),
          sha256,
          subject.slot,
        ]);
      closed(removal, ["removed", "sha256"]);
      requireWindows(removal.removed === true && removal.sha256 === sha256);
      observations.push(removal);
    }
    const before = await task("custody", nonce),
      after = await task("custody", nonce);
    requireWindows(before.absent && after.absent);
    return retired([installed, ...observations, before, after]);
  };
  const api = {
    read,
    async verifyRestoration(value) {
      requireWindows(
        input &&
          same(value.input, input) &&
          input.context.executionId.startsWith("access.") &&
          value.kind === "policy" &&
          value.request.operation === "remove",
      );
      const observed = await api.verifyAccessCoverage(value),
        raw = observed.actual,
        plan = buildWindowsPolicy(value.request.value),
        objects = plan.manifest.objects.filter(
          ({ name }) => name !== "registry",
        );
      requireWindows(
        raw.creationSealed &&
          raw.members.every(({ signaled }) => signaled) &&
          raw.flows.length === 0 &&
          (!raw.job || raw.job.members.length === 0) &&
          raw.objects.length === objects.length &&
          raw.ownedWfp.provider &&
          raw.ownedWfp.sublayer &&
          dense(raw.ownedWfp.filters, 52).length === 52 &&
          raw.ownedWfp.filters.every(Boolean) &&
          dense(raw.ownedWfp.observations.filters, 52).length === 52,
      );
      raw.objects.forEach((object, i) => {
        const security = normalizeWindowsSecurityRead(object.security);
        requireWindows(
          security.ownerSid === "S-1-5-18" &&
            security.protectedDacl &&
            same(security.aces, expectedAces(objects[i])) &&
            object.index === value.objects[i].slot &&
            object.identity === value.objects[i].identity,
        );
      });
      raw.ownedWfp.observations.filters.forEach((actual, i) =>
        assertWindowsWfpFilterRead(actual, plan.manifest.filters[i], plan),
      );
      assertWindowsWfpOwnersRead(
        raw.ownedWfp.observations.provider,
        raw.ownedWfp.observations.sublayer,
        plan,
      );
      const {
        custody: _custody,
        contextSha256: _context,
        hex: _hex,
        ...observations
      } = value;
      return {
        independent: true,
        noLiveMembers: true,
        unchangedInstalled: true,
        observationsSha256: observationDigest(observations),
        verifier: verifier(),
        nativeEventSha256: observed.nativeEventSha256,
      };
    },
    async verifyAccessControl(value) {
      requireWindows(input && same(value.input, input));
      const owner = await retain(systemIdentity(value.helper));
      const actual = await call("access-control", [
        owner.slot,
        value.custody,
        value.id,
        value.hex,
      ]);
      closed(actual, [
        "id",
        "nonce",
        "controller",
        "kind",
        "denialCode",
        "targetHex",
        "targetIdentitySha256",
        "endpoint",
      ]);
      requireWindows(
        actual.id === value.id &&
          actual.nonce === input.nonce &&
          sameWindowsIdentity(actual.controller, value.helper),
      );
      if (actual.endpoint) {
        const process = await observe(actual.endpoint.identity);
        requireWindows(
          !process.retired &&
            actual.endpoint.identity.sessionId === 0 &&
            hash(actual.endpoint.socketIdentitySha256),
        );
      } else
        requireWindows(hash(actual.targetIdentitySha256) || actual.kind === 2);
      return {
        independent: true,
        actual,
        verifier: verifier(),
        nativeEventSha256: observationDigest(actual),
      };
    },
    async verifyAccessSocket(value) {
      requireWindows(
        input &&
          same(value.input, input) &&
          value.contextSha256 === observationDigest(input.context),
      );
      const subject = await retain(value.identity),
        before = await observe(value.identity);
      requireWindows(!before.retired);
      const actual = await call("socket", [
        subject.slot,
        value.contextSha256,
        value.handle,
        value.hex,
      ]);
      closed(actual, [
        "identity",
        "socketIdentitySha256",
        "protocol",
        "family",
        "localAddress",
        "localPort",
        "remote",
      ]);
      requireWindows(
        sameWindowsIdentity(actual.identity, before.identity) &&
          hash(actual.socketIdentitySha256) &&
          !(await observe(value.identity)).retired,
      );
      return {
        independent: true,
        actual,
        verifier: verifier(),
        nativeEventSha256: observationDigest(actual),
      };
    },
    async verifyAccessPeerRetirement(value) {
      requireWindows(input && same(value.input, input));
      const peer = await retain(value.identity);
      requireWindows((await observe(value.identity)).retired);
      const actual = await call("access-peer-retired", [
        peer.slot,
        value.custody,
      ]);
      closed(actual, [
        "retired",
        "accountAbsent",
        "rightsAbsent",
        "contextSha256",
      ]);
      requireWindows(
        actual.retired &&
          actual.accountAbsent &&
          actual.rightsAbsent &&
          actual.contextSha256 === observationDigest(input.context),
      );
      return { ...retired(actual), verifier: verifier() };
    },
    async verifyAccessPeerPolicy(value) {
      requireWindows(input && same(value.input, input));
      const owner = await retain(systemIdentity(value.helper)),
        subject = await retain(value.identity);
      requireWindows(!(await observe(value.identity)).retired);
      const actual = await call("access-peer-policy", [
        owner.slot,
        value.custody,
        subject.slot,
        value.hex,
      ]);
      closed(actual, ["parked", "imageSha256", "signatureSha256"]);
      requireWindows(
        actual.parked &&
          actual.imageSha256 === value.image.sha256 &&
          actual.signatureSha256 === value.image.signatureSha256,
      );
      return {
        independent: true,
        actual,
        verifier: verifier(),
        nativeEventSha256: observationDigest(actual),
      };
    },
    async verifyAccessFault(value) {
      requireWindows(input && same(value.input, input));
      const actual = await observe(systemIdentity(value.identity));
      requireWindows(actual.retired === value.signaled);
      return {
        independent: true,
        actual,
        verifier: verifier(),
        nativeEventSha256: observationDigest(actual),
      };
    },
    async readAccessReceipt(value) {
      requireWindows(
        input &&
          same(value.input, input) &&
          input.context.executionId.startsWith("access."),
      );
      const actual = await call("receipt", [
        value.custody,
        value.index,
        value.sha256,
      ]);
      closed(actual, ["hex"]);
      requireWindows(
        typeof actual.hex === "string" &&
          /^(?:[a-f0-9]{2}){1,16384}$/u.test(actual.hex) &&
          digest(Buffer.from(actual.hex, "hex")) === value.sha256,
      );
      return {
        independent: true,
        actual,
        verifier: verifier(),
        nativeEventSha256: observationDigest(actual),
      };
    },
    async verifyAuditRetirement(value) {
      requireWindows(
        input &&
          same(value.input, input) &&
          input.context.executionId.startsWith("access."),
      );
      const observed = await api.verifyAccessCoverage(value),
        raw = observed.actual;
      requireWindows(
        raw.creationSealed &&
          raw.members.every(({ signaled }) => signaled) &&
          raw.flows.length === 0 &&
          (!raw.job || raw.job.members.length === 0),
      );
      for (const identity of value.processes)
        requireWindows((await observe(identity)).retired);
      return {
        ...retired(observed),
        candidateSha: input.context.candidateSha,
        nonce: input.nonce,
        verifier: verifier(),
        noLiveMembers: true,
        noForeignCreators: true,
        noPrincipalFlows: true,
        exclusiveWriter: true,
        admissionsClosed: true,
      };
    },
    async verifyAccessCoverage(value) {
      requireWindows(
        input &&
          same(value.input, input) &&
          value.contextSha256 === observationDigest(input.context),
      );
      const owner = await retain(systemIdentity(value.helper));
      const actual = await call("access", [
        owner.slot,
        value.custody,
        value.contextSha256,
        value.hex,
      ]);
      requireWindows(actual.contextSha256 === value.contextSha256);
      for (const member of dense(actual.members, 32)) {
        const observed = await observe(member.identity);
        requireWindows(
          observed.retired === member.signaled &&
            observed.identity.userSid === actual.accountSid &&
            observed.tokenId === member.token.tokenId &&
            observed.authenticationId === member.token.authenticationId &&
            observed.integritySid === member.token.integritySid &&
            same(observed.restricting, member.token.restrictedSids) &&
            observed.privileges.length === 0,
        );
      }
      return {
        independent: true,
        actual,
        verifier: verifier(),
        nativeEventSha256: observationDigest(actual),
      };
    },
    async verifyCaseProvisioning(value) {
      requireWindows(
        input && same(value.input, input) && hash(value.contextSha256),
      );
      const owner = await retain(systemIdentity(value.helper));
      const actual = await call("case", [
        owner.slot,
        value.custody,
        value.contextSha256,
        value.tokenHandle,
      ]);
      return {
        independent: true,
        actual,
        nativeEventSha256: observationDigest(actual),
        verifier: verifier(),
      };
    },
    async verifyCaseRetirement(value) {
      requireWindows(input && same(value.input, input));
      const actual = await call("case-retired", [
        value.custody,
        value.contextSha256,
      ]);
      closed(actual, [
        "accountAbsent",
        "rightsAbsent",
        "jobAbsent",
        "contextSha256",
      ]);
      requireWindows(
        actual.accountAbsent === true &&
          actual.rightsAbsent === true &&
          actual.jobAbsent === true &&
          actual.contextSha256 === value.contextSha256,
      );
      return retired(actual);
    },
    async recoverCase(
      declaration,
      records,
      observers = [],
      objects = [],
      ledger = [],
    ) {
      const original = bind(declaration),
        contextSha256 = observationDigest(original.context),
        observations = [],
        identities = [];
      const registered = records.find(
          (record) => record.phase === "task-register-possible",
        ),
        run = records.find((record) => record.phase === "task-run-possible"),
        admitted = records.find((record) => record.phase === "admitted");
      // A possible run without an independently acknowledged birth remains
      // excluded; no PID/name guess or missing final output can settle it.
      requireWindows(!run || admitted);
      if (registered)
        identities.push(normalizeWindowsIdentity(registered.bridge));
      if (admitted) identities.push(systemIdentity(admitted.helper));
      const starts = records.filter(
          (record) => record.phase === "helper-start",
        ),
        births = records.filter((record) => record.phase === "helper-admitted");
      requireWindows(starts.length === births.length);
      identities.push(...births.map((record) => systemIdentity(record.child)));
      const receipts = new Map();
      const receipt = async (pin) => {
        closed(pin, ["index", "sha256"]);
        requireWindows(integer(pin.index, 4095) && hash(pin.sha256));
        if (receipts.has(pin.index)) {
          requireWindows(digest(receipts.get(pin.index)) === pin.sha256);
          return receipts.get(pin.index);
        }
        const actual = await call("receipt", [2, pin.index, pin.sha256]);
        closed(actual, ["hex"]);
        requireWindows(
          typeof actual.hex === "string" &&
            /^(?:[a-f0-9]{2}){1,16384}$/u.test(actual.hex),
        );
        const bytes = Buffer.from(actual.hex, "hex");
        requireWindows(digest(bytes) === pin.sha256);
        receipts.set(pin.index, bytes);
        return bytes;
      };
      for (const command of records.filter(
        (record) =>
          record.phase === "ownership-receipt" &&
          record.arguments?.length === 3,
      )) {
        const [index, sha256, hex] = command.arguments;
        requireWindows(
          typeof hex === "string" && /^(?:[a-f0-9]{2}){1,16384}$/u.test(hex),
        );
        requireWindows(
          (await receipt({ index: Number(index), sha256 })).equals(
            Buffer.from(hex, "hex"),
          ),
        );
      }
      for (const entry of ledger.filter((record) =>
        ["ownership-receipt-possible", "operation-receipt-possible"].includes(
          record.phase,
        ),
      ))
        await receipt(entry.pin);
      const nativeRecords = [];
      for (const entry of ledger) {
        if (
          ![
            "ownership-receipt",
            "access-receipt",
            "operation-receipt",
          ].includes(entry.phase)
        )
          continue;
        let bytes = await receipt(entry.pin);
        if (entry.phase !== "ownership-receipt") {
          requireWindows(hash(entry.contentSha256));
          dense(entry.parts, 16);
          requireWindows(
            entry.parts.length > 0 &&
              same(JSON.parse(bytes), {
                contentSha256: entry.contentSha256,
                parts: entry.parts,
              }),
          );
          const parts = [];
          for (const pin of entry.parts) parts.push(await receipt(pin));
          bytes = Buffer.concat(parts);
          requireWindows(
            bytes.length <= 262144 && digest(bytes) === entry.contentSha256,
          );
        }
        const record = JSON.parse(bytes);
        requireWindows(
          bytes.equals(Buffer.from(JSON.stringify(record) + "\n")) &&
            (record.candidateSha === undefined ||
              record.candidateSha === original.context.candidateSha) &&
            (record.nonce === undefined || record.nonce === original.nonce),
        );
        nativeRecords.push(record);
        if (record.helpers) {
          for (const helper of dense(record.helpers, 32))
            identities.push(systemIdentity(helper.identity));
        }
        if (
          ["operation-birth-possible", "operation-birth-held"].includes(
            record.kind,
          )
        )
          identities.push(normalizeWindowsIdentity(record.identity));
        if (record.phase === "access-peers-parked") {
          identities.push(
            normalizeWindowsIdentity(record.privatePeer),
            normalizeWindowsIdentity(record.otherPeer),
          );
        }
      }
      // A stopped task or restored policy cannot stand in for an audit drain.
      // Interrupted installation has an independently read absent observer lane.
      if (records.some((record) => record.phase === "ownership-launch"))
        requireWindows(
          nativeRecords.some(
            (record) =>
              record.helpers?.some((helper) => helper.role === "launcher") &&
              record.helpers.some((helper) => helper.role === "custodian"),
          ),
        );
      if (records.some((record) => record.phase === "access-peers-park"))
        requireWindows(
          nativeRecords.some(
            (record) => record.phase === "access-peers-parked",
          ),
        );
      if (
        nativeRecords.some(
          (record) => record.phase === "audit-install-possible",
        )
      ) {
        requireWindows(
          nativeRecords.some((record) => record.phase === "audit-restored") &&
            nativeRecords.some(
              (record) =>
                ["access-observer-retired", "access-observer-absent"].includes(
                  record.phase,
                ) &&
                record.scoped?.drained === true &&
                record.scoped?.independent === true,
            ),
        );
      }
      if (nativeRecords.some((record) => record.kind === "git-audit-possible"))
        requireWindows(
          nativeRecords.some((record) => record.kind === "operation-restored"),
        );
      const observerOwners = new Map();
      for (const { intent, birth } of observers) {
        requireWindows(
          intent.schemaVersion === 1 &&
            intent.status === "POSSIBLE" &&
            birth?.schemaVersion === 1 &&
            birth.status === "POSSIBLE" &&
            hash(birth.taskSha256) &&
            intent.argumentsHex?.[6] === encode(birth.nonce),
        );
        identities.push(
          systemIdentity(birth.helper),
          normalizeWindowsIdentity(birth.bridge),
        );
        for (const identity of [birth.helper, birth.bridge])
          observerOwners.set(
            observationDigest(normalizeWindowsIdentity(identity)),
            birth.nonce,
          );
      }
      const unique = [
        ...new Map(
          identities.map((identity) => [observationDigest(identity), identity]),
        ).values(),
      ];
      requireWindows(unique.length <= maximumSubjects);
      for (const identity of unique) await retain(identity);
      observations.push(
        ...(await recoveryJobs(
          unique.map((identity) => ({
            identity,
            nonce:
              observerOwners.get(observationDigest(identity)) ?? original.nonce,
          })),
        )),
      );
      for (const identity of unique) {
        observations.push(await empty(identity), await empty(identity));
      }
      // Creator retirement precedes payload Job settlement. Native recovery
      // rejoins the owned account record and complete SID census, and touches
      // only an unchanged private baseline. Readers/observers are already gone.
      for (const { index, object, security } of dense(objects, 128)) {
        const actual = await call("recovery-object", [index]);
        closed(actual, ["object", "security"]);
        requireWindows(
          same(fileObservation(actual.object), fileObservation(object)) &&
            same(
              normalizeWindowsSecurityRead(actual.security),
              normalizeWindowsSecurityRead(security),
            ),
        );
        observations.push(actual);
      }
      const accountPossible = records.some(
        (record) => record.phase === "case-account",
      )
        ? 1
        : 0;
      const first = await call("case-recover", [
          2,
          contextSha256,
          original.nonce,
          accountPossible,
        ]),
        last = await call("case-recover", [
          2,
          contextSha256,
          original.nonce,
          accountPossible,
        ]);
      for (const actual of [first, last]) {
        closed(actual, [
          "accountAbsent",
          "rightsAbsent",
          "jobAbsent",
          "contextSha256",
          "policyRestored",
          "auditDrained",
          "readersClosed",
        ]);
        requireWindows(
          actual.accountAbsent === true &&
            actual.rightsAbsent === true &&
            actual.jobAbsent === true &&
            actual.contextSha256 === contextSha256 &&
            actual.policyRestored === true &&
            actual.auditDrained === true &&
            actual.readersClosed === true,
        );
      }
      observations.push(first, last);
      requireWindows(
        !run ||
          (registered && sameWindowsIdentity(run.bridge, registered.bridge)),
      );
      observations.push(
        await recoverTask(original.nonce, run?.taskSha256, registered?.bridge),
      );
      for (const { birth } of observers)
        observations.push(
          await recoverTask(birth.nonce, birth.taskSha256, birth.bridge),
        );
      return {
        ...retired(observations),
        noLiveMembers: true,
        taskRemoved: true,
      };
    },
    async verifyBuildWorker(record, tool, signatureSha256) {
      requireWindows(input && hash(record.requestSha256));
      const worker = systemIdentity(record.worker),
        creator = systemIdentity(record.helper);
      const actual = await observe(worker),
        parent = await retain(creator),
        job = jobObservation(await call("job", [parent.slot]));
      requireWindows(
        !actual.retired &&
          !(await observe(creator)).retired &&
          transfers.has(parent.slot) &&
          job.members.some((member) => sameWindowsIdentity(member, worker)),
      );
      await image(worker, {
        path: tool.path,
        sha256: tool.sha256,
        signatureSha256,
      });
      const held = await retain(worker),
        authority = await call("compiler-policy", [held.slot, parent.slot]);
      closed(authority, ["defaultDacl", "inheritedHandles", "compilerJob"]);
      requireWindows(Array.isArray(authority.defaultDacl));
      requireWindows(
        same(authority.defaultDacl, [
          { type: 0, flags: 0, mask: 0x10000000, sid: "S-1-5-18" },
        ]) && same(authority.inheritedHandles, ["pipe", "pipe", "pipe"]),
      );
      return {
        independent: true,
        worker,
        compilerPolicy: { process: actual, outerJob: job, ...authority },
        nativeEventSha256: observationDigest({ actual, job, authority }),
      };
    },
    async verifyPublication(value) {
      requireWindows(input && same(value.input, input));
      const output = {
        path: value.operation.target,
        sha256: value.operation.helper.sha256,
        signatureSha256: value.actual.signatureSha256,
      };
      const actual = await file(output);
      requireWindows(
        actual.identity === value.actual.identity &&
          actual.daclSha256 === value.actual.daclSha256 &&
          value.actual.writerClosed === true,
      );
      const observations = [];
      for (const held of subjects.values())
        if (
          (!target || !sameWindowsIdentity(held.identity, target)) &&
          (!bridge || !sameWindowsIdentity(held.identity, bridge))
        )
          observations.push(
            await empty(held.identity),
            await empty(held.identity),
          );
      return {
        independent: true,
        observationsSha256: observationDigest(value),
        protectedDacl: true,
        writerClosed: true,
        verifier: verifier(),
        nativeEventSha256: observationDigest({ actual, observations }),
        settlement: retired(observations),
      };
    },
    async verifyBootstrap(declaration) {
      bind(declaration);
      const entries = [];
      for (const pin of [
        input.bridge,
        input.reader,
        input.plan,
        ...input.sources,
      ]) {
        const { slot: _slot, bytes: _bytes, ...observed } = await file(pin);
        entries.push({ path: pin.path, ...observed });
      }
      return {
        independent: true,
        held: true,
        protectedDacl: true,
        protectedParents: true,
        reviewSha256: input.reviewSha256,
        sdkSha256: input.sdkSha256,
        buildSha256: input.buildSha256,
        entries,
        nativeEventSha256: observationDigest({ verifier: verifier(), entries }),
      };
    },
    async verifyAdmission(value) {
      requireWindows(input && same(value.input, input));
      const actual = await observe(systemIdentity(value.helper)),
        installed = await task("custody", input.nonce),
        executable = await image(value.helper, input.reader);
      bridge = normalizeWindowsIdentity(value.bridge);
      requireWindows(
        bridge.userSid === input.runnerSid &&
          bridge.pid !== value.helper.pid &&
          !(await observe(bridge)).retired,
      );
      await image(bridge, input.bridge);
      requireWindows(
        !actual.retired &&
          actual.processDaclSha256 === value.processDaclSha256 &&
          installed.absent === false &&
          installed.instances === 1 &&
          installed.sha256 === value.taskSha256,
      );
      taskSha256 = installed.sha256;
      target = structuredClone(actual.identity);
      return {
        independent: true,
        helper: actual.identity,
        verifier: verifier(),
        planSha256: input.plan.sha256,
        taskSha256,
        imageSha256: executable.sha256,
        signatureSha256: executable.signatureSha256,
        processDaclSha256: actual.processDaclSha256,
        nativeEventSha256: observationDigest({ actual, installed, executable }),
      };
    },
    async verifyTransfer(value) {
      requireWindows(
        input &&
          same(value.input, input) &&
          value.transferSha256 === observationDigest(value.transfer),
      );
      const actual = await observe(systemIdentity(value.child)),
        child = await retain(value.child),
        creator = await retain(systemIdentity(value.creator));
      requireWindows(
        !actual.retired && !(await observe(value.creator)).retired,
      );
      const transfer = await call("transfer", [child.slot, creator.slot]);
      closed(transfer, [
        "threadDaclSha256",
        "job",
        "objects",
        "inheritedHandleCount",
        "pipeDaclSha256",
        "creatorDefaultDaclSha256",
      ]);
      const job = jobObservation(transfer.job),
        objects = dense(transfer.objects, 130),
        expected = value.transfer.objects.map((entry) =>
          normalizeWindowsFileIdentity(entry.identity),
        ),
        received = objects.filter((entry) => entry !== null);
      requireWindows(
        objects.filter((entry) => entry === null).length === 2 &&
          dense(transfer.pipeDaclSha256, 2).length === 2 &&
          transfer.pipeDaclSha256.every(hash) &&
          received.length === expected.length &&
          new Set(received).size === received.length &&
          expected.every((entry) => received.includes(entry)) &&
          transfer.inheritedHandleCount === expected.length + 2 &&
          actual.processDaclSha256 === value.actual.processDaclSha256 &&
          hash(transfer.threadDaclSha256) &&
          transfer.threadDaclSha256 === value.actual.threadDaclSha256 &&
          hash(transfer.creatorDefaultDaclSha256) &&
          same(job, value.actual.job) &&
          job.members.some((member) =>
            sameWindowsIdentity(member, value.child),
          ),
      );
      transfers.set(child.slot, transfer);
      const executable = await image(value.child, value.transfer.image);
      const sharing =
        value.transfer.kind === "file"
          ? await call("sharing", [value.transfer.objects[0].pathHex])
          : null;
      if (sharing) {
        closed(sharing, ["identity"]);
        requireWindows(sharing.identity === expected[0]);
      }
      requireWindows(
        !value.actual.creatorDefaultDaclSha256 ||
          value.actual.creatorDefaultDaclSha256 ===
            transfer.creatorDefaultDaclSha256,
      );
      return {
        independent: true,
        helper: actual.identity,
        verifier: verifier(),
        explicitHandleList: true,
        inheritedHandleCount: transfer.inheritedHandleCount,
        transferSha256: value.transferSha256,
        imageSha256: executable.sha256,
        signatureSha256: executable.signatureSha256,
        processDaclSha256: actual.processDaclSha256,
        threadDaclSha256: transfer.threadDaclSha256,
        ...(sharing ? { fileRootDeleteSharing: true } : {}),
        ...(value.actual.creatorDefaultDaclSha256
          ? { creatorDefaultDaclSha256: transfer.creatorDefaultDaclSha256 }
          : {}),
        jobSha256: observationDigest(job),
        nativeEventSha256: observationDigest({
          actual,
          transfer,
          executable,
          sharing,
        }),
      };
    },
    async verifyHelperRetirement(identity) {
      requireWindows(transfers.has((await retain(identity)).slot));
      const observations = [await empty(identity), await empty(identity)];
      return {
        ...retired(observations),
        helper: identity,
        verifier: verifier(),
      };
    },
    async verifyRetirement(value) {
      requireWindows(
        input &&
          same(value.input, input) &&
          target &&
          sameWindowsIdentity(value.helper, target),
      );
      const observations = [];
      for (const held of subjects.values())
        if (
          !sameWindowsIdentity(held.identity, value.helper) &&
          (!bridge || !sameWindowsIdentity(held.identity, bridge))
        )
          observations.push(await empty(held.identity));
      for (const identity of dense(value.processes ?? [], 32))
        observations.push(await empty(identity));
      await inventory([...subjects.values()].map((held) => held.identity));
      requireWindows(dense(value.jobs ?? [], 32).length === 0);
      requireWindows(!(await observe(value.helper)).retired);
      return {
        ...retired(observations),
        helper: value.helper,
        verifier: verifier(),
        noLiveMembers: true,
      };
    },
    async verifyTaskRemoval(value) {
      requireWindows(
        input &&
          same(value.input, input) &&
          target &&
          sameWindowsIdentity(value.helper, target) &&
          value.taskSha256 === taskSha256,
      );
      requireWindows(bridge);
      await inventory([...subjects.values()].map((held) => held.identity));
      const observations = [];
      for (const held of subjects.values())
        observations.push(
          await empty(held.identity),
          await empty(held.identity),
        );
      const before = await task("custody", input.nonce),
        after = await task("custody", input.nonce);
      requireWindows(before.absent && after.absent);
      observations.push(before, after);
      // The independently admitted reader remains owned by preparation. EOF or
      // its own finish never supplies proof of this observer's retirement.
      return {
        ...retired(observations),
        helper: value.helper,
        verifier: verifier(),
        taskRemoved: true,
        noLiveMembers: true,
      };
    },
    async verifyCompleted(declaration, identities, nonces = [], jobs = []) {
      bind(declaration);
      requireWindows(dense(identities, maximumSubjects).length > 0);
      const observations = [];
      await inventory(identities);
      for (const identity of identities)
        observations.push(await empty(identity), await empty(identity));
      requireWindows(dense(jobs, 32).length === 0); // Missing whole-Job custody cannot be reconstructed from exit.
      for (const nonce of dense(nonces, 32)) {
        requireWindows(nonce === input.nonce);
        const before = await task("custody", nonce),
          after = await task("custody", nonce);
        requireWindows(before.absent && after.absent);
        observations.push(before, after);
      }
      return {
        ...retired(observations),
        noLiveMembers: true,
        tasksRemoved: nonces.length > 0,
      };
    },
    async verifyPreparation(declaration, owners) {
      bind(declaration);
      dense(owners, 128);
      requireWindows(
        owners.length > 0 &&
          new Set(owners.map(({ nonce }) => nonce)).size === owners.length,
      );
      const identities = new Map(),
        observations = [];
      for (const owner of owners) {
        closed(owner, ["nonce", "identities"]);
        requireWindows(
          /^[a-f0-9]{32}$/u.test(owner.nonce) &&
            owner.nonce !== observerInput.nonce &&
            dense(owner.identities, 32).length > 0,
        );
        for (const identity of owner.identities)
          identities.set(
            observationDigest(normalizeWindowsIdentity(identity)),
            identity,
          );
      }
      requireWindows(identities.size <= maximumSubjects);
      for (const identity of identities.values()) await retain(identity);
      observations.push(
        ...(await recoveryJobs(
          owners.flatMap(({ nonce, identities }) =>
            identities.map((identity) => ({ nonce, identity })),
          ),
        )),
      );
      await inventory([...identities.values()]);
      for (const identity of identities.values())
        observations.push(await empty(identity), await empty(identity));
      for (const { nonce } of owners) {
        const before = await task("custody", nonce),
          after = await task("custody", nonce);
        requireWindows(before.absent && after.absent);
        observations.push(before, after);
      }
      return {
        ...retired(observations),
        noLiveMembers: true,
        tasksRemoved: true,
      };
    },
    async recoverCompleted(
      declaration,
      identities,
      nonces = [],
      observerOwners = [],
    ) {
      bind(declaration);
      requireWindows(dense(identities, maximumSubjects).length > 0);
      for (const identity of identities) await retain(identity);
      const owners = new Map(
        dense(observerOwners, maximumSubjects).map((owner) => {
          closed(owner, ["identity", "nonce"]);
          requireWindows(
            identities.some((identity) =>
              sameWindowsIdentity(identity, owner.identity),
            ),
          );
          return [
            observationDigest(normalizeWindowsIdentity(owner.identity)),
            owner.nonce,
          ];
        }),
      );
      const jobs = await recoveryJobs(
          identities.map((identity) => ({
            identity,
            nonce:
              owners.get(
                observationDigest(normalizeWindowsIdentity(identity)),
              ) ?? input.nonce,
          })),
        ),
        proof = await api.verifyCompleted(declaration, identities, nonces);
      return {
        ...proof,
        nativeEventSha256: observationDigest({ jobs, proof }),
      };
    },
    async recoverOwnedTask(nonce, sha256, identity) {
      return recoverTask(nonce, sha256, identity);
    },
    async retainPrerequisiteJob(request) {
      requireWindows(
        typeof native.record === "function" &&
          request.platform === "win32" &&
          same(request.job, observerInput.context) &&
          request.admission.nonce !== observerInput.nonce,
      );
      const name = "Local\\NativeProof-" + request.admission.nonce,
        held = await call("job-open", [encode(name)]);
      closed(held, ["slot", "observation"]);
      const job = jobObservation(held.observation);
      requireWindows(
        integer(held.slot, 31) &&
          job.limitFlags === 0x2008 &&
          job.processLimit > 0 &&
          job.uiRestrictions === 255,
      );
      const { members: _members, ...jobIdentity } = job;
      const binding = {
        observer: verifier(),
        jobSlot: held.slot,
        jobName: name,
        job: jobIdentity,
        requestSha256: observationDigest(request),
        nativeEventSha256: observationDigest(held),
      };
      requireWindows(clock() < deadline);
      await native.record("prerequisite-bound", { request, binding });
      return binding;
    },
    async recoverPrerequisite(expected, intent, birthPin) {
      requireWindows(
        typeof native.record === "function" &&
          clock() < deadline &&
          expected.platform === "win32" &&
          expected.admission.platform === "win32" &&
          same(expected.job, observerInput.context) &&
          expected.admission.nonce !== observerInput.nonce,
      );
      const request = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(
          await read({
            path: intent.file,
            bytes: intent.bytes,
            sha256: intent.sha256,
          }),
        ),
      );
      requireWindows(same(request, expected));
      const birth = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(
          await read({
            path: birthPin.file,
            bytes: birthPin.bytes,
            sha256: birthPin.sha256,
          }),
        ),
      );
      closed(birth, [
        "schemaVersion",
        "requestSha256",
        "worker",
        "children",
        "verifiers",
        "observer",
        "jobSlot",
        "jobName",
        "job",
        "taskSha256",
      ]);
      requireWindows(
        birth.schemaVersion === 1 &&
          birth.requestSha256 === observationDigest(request) &&
          hash(birth.taskSha256) &&
          birth.jobName === "Local\\NativeProof-" + request.admission.nonce &&
          integer(birth.jobSlot, 31) &&
          sameWindowsIdentity(systemIdentity(birth.observer), verifier()),
      );
      const identities = [
        birth.worker,
        ...dense(birth.children, 30),
        ...dense(birth.verifiers, 30),
      ].map(systemIdentity);
      requireWindows(
        new Set(identities.map(observationDigest)).size === identities.length &&
          identities.length <= 32,
      );
      await inventory(identities, [birth.jobSlot]);
      const observations = [];
      for (const identity of identities)
        observations.push(await empty(identity), await empty(identity));
      const job = jobObservation(
        await call("job-read", [birth.jobSlot, encode(birth.jobName)]),
      );
      const { members: _members, ...jobIdentity } = job;
      requireWindows(
        job.members.length === 0 &&
          job.limitFlags === 0x2008 &&
          job.processLimit > 0 &&
          job.uiRestrictions === 255 &&
          same(jobIdentity, birth.job),
      );
      const after = jobObservation(
        await call("job-read", [birth.jobSlot, encode(birth.jobName)]),
      );
      requireWindows(same(job, after));
      observations.push(job, after);
      const installed = await task("prerequisite", request.admission.nonce);
      if (!installed.absent) {
        requireWindows(
          installed.sha256 === birth.taskSha256 && installed.instances === 0,
        );
        const subject = await retain(birth.worker),
          removed = await call("task-remove", [
            "prerequisite",
            encode(request.admission.nonce),
            birth.taskSha256,
            subject.slot,
          ]);
        closed(removed, ["removed", "sha256"]);
        requireWindows(
          removed.removed === true && removed.sha256 === birth.taskSha256,
        );
      }
      const first = await task("prerequisite", request.admission.nonce),
        last = await task("prerequisite", request.admission.nonce);
      requireWindows(first.absent && last.absent);
      observations.push(installed, first, last);
      const proof = {
        ...retired(observations),
        requestSha256: birth.requestSha256,
        noLiveMembers: true,
        taskRemoved: true,
        verifier: verifier(),
      };
      requireWindows(clock() < deadline);
      await native.record("prerequisite-settled", {
        intent,
        birthPin,
        settlement: proof,
      });
      return proof;
    },
  };
  return Object.fromEntries(
    Object.entries(api).map(([name, operation]) => [
      name,
      (...args) => {
        const snapshot = args.map((arg, index) =>
          index === 0 ||
          [
            "verifyCompleted",
            "verifyPreparation",
            "recoverCase",
            "recoverCompleted",
            "recoverOwnedTask",
            "recoverPrerequisite",
          ].includes(name)
            ? structuredClone(arg)
            : arg,
        );
        const running = pending.then(async () => {
          if (failed) throw failure;
          try {
            requireWindows(clock() < deadline);
            const result = await operation(...snapshot);
            requireWindows(clock() < deadline);
            return result;
          } catch (error) {
            if (!failed) {
              failed = true;
              failure = error;
            }
            throw failure;
          }
        });
        pending = running.catch(() => {});
        return running;
      },
    ]),
  );
}
