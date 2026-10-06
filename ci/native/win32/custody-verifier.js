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
import {
  encode,
  integer,
  normalizeWindowsCustodyInput,
  processObservation,
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
    deadline = clock() + WINDOWS_CUSTODY_DEADLINE_MS,
  } = {},
) {
  const native = reader?.verification;
  requireWindows(
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
    files = new Map();
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
        integer(actual.slot, 31) &&
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
    dense(identities, 32);
    const retained = await call("subjects");
    closed(retained, ["identities", "jobs"]);
    const expected = new Set(
        identities.map((identity) =>
          observationDigest(normalizeWindowsIdentity(identity)),
        ),
      ),
      actual = dense(retained.identities, 32).map((identity) =>
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
  const api = {
    read,
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
      requireWindows(dense(identities, 32).length > 0);
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
          ["verifyCompleted", "recoverPrerequisite"].includes(name)
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
