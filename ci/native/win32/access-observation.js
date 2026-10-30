import { observationDigest, requireObservation } from "../index.js";
import { buildWindowsPolicy, assertWindowsPolicyToken } from "./policy.js";
import { digest, sameWindowsIdentity } from "./protocol.js";
import { WINDOWS_ACCESS_DENIALS } from "./access.js";
import {
  observeWindowsAccessDenial,
  observeWindowsAccessLoopback,
} from "./access-transport.js";

const fileTargets = {
  "metadata-write": ["metadata", "write"],
  "pointer-write": ["pointer", "write"],
  "pointer-delete": ["pointer", "delete"],
  "pointer-replace": ["pointer", "replace"],
  "parent-delete": ["workspace", "delete"],
  "parent-replace": ["workspace", "rename"],
  custody: ["custody", "write"],
  checkout: ["checkout", "write"],
  configuration: ["configuration", "write"],
  credentials: ["credentials", "write"],
  registry: ["registry", "registry"],
  "outside-write": ["outside", "write"],
};
const accessMasks = {
  write: 2,
  delete: 0x10000,
  replace: 0x10002,
  rename: 0x10000,
};
const identity = (object) =>
  object.descriptor.name === "registry"
    ? object.registryIdentitySha256
    : digest(object.volumeSerial + ":" + object.fileId);

/** Join fixture acknowledgements to held subjects, independent controls and
 * native Security/BFE windows. A pending connect, UDP send, error or timeout
 * cannot become a DROP observation. */
export async function collectWindowsAccess(current, session) {
  const { reader, accessReaders, input } = current,
    plan = buildWindowsPolicy(input),
    { request } = plan.value,
    { admission, installation, payloadSlot, jobSlot, capture } = session,
    objects = installation.effective.objects,
    proof = await accessReaders.read(),
    raw = proof.actual,
    held = raw.members.find(({ identity }) =>
      sameWindowsIdentity(identity, admission.payload),
    );
  requireObservation(
    held && held.inJob && !held.signaled && raw.fileRoots.length === 2,
  );
  assertWindowsPolicyToken(held.token, plan.value);
  const native = (value) => ({
    independent: true,
    verifier: proof.verifier,
    nonce: request.nonce,
    timedOut: false,
    lossCount: 0,
    identityVerified: true,
    nativeEventSha256: observationDigest(value),
  });
  const state = async (name) => {
    const object = objects.find(({ descriptor }) => descriptor.name === name);
    requireObservation(object);
    const slot =
        current.provisioned.accessSlots[
          plan.manifest.objects
            .filter(({ name }) => name !== "registry")
            .findIndex(({ name: value }) => value === name)
        ],
      directory =
        name !== "registry" &&
        current.provisioned.entries[slot].kind === "directory";
    const observation =
      name === "registry"
        ? await reader.registry(payloadSlot)
        : directory
          ? await reader.tree(slot)
          : await reader.file(slot);
    return {
      identitySha256: identity(object),
      bytesSha256:
        name === "registry" || directory
          ? observationDigest(observation)
          : observation.sha256,
      nativeEventSha256: observationDigest(observation),
    };
  };
  const frame = async (phase, operation) => {
    const value = JSON.parse(await reader.ownershipOutput());
    requireObservation(
      value.nonce === request.nonce &&
        value.phase === phase &&
        value.operation === operation,
    );
    return value;
  };
  const attempt = async (id, operation, target, network = false) => {
    await session.persist({
      phase: "access-attempt-possible",
      id,
      operation,
      target,
    });
    await reader.sendAccessCommand(operation, [target]);
    const ready = await frame("ready", operation);
    const before = (await capture.barrier()).barriers.at(-1);
    await reader.sendOwnership("A");
    const result = await frame(network ? "initiated" : "attempted", operation);
    const after = await capture.barrier();
    const window = after.events.filter(
      (event) =>
        event.index >= before.events &&
        event.index < after.barriers.at(-1).events &&
        BigInt(event.time) >= BigInt(before.time) &&
        BigInt(event.time) <= BigInt(after.barriers.at(-1).time),
    );
    requireObservation(before.sequence + 1 === after.barriers.at(-1).sequence);
    const actual = await accessReaders.read();
    requireObservation(
      actual.actual.members.some(
        (member) =>
          sameWindowsIdentity(member.identity, admission.payload) &&
          !member.signaled &&
          member.inJob,
      ),
    );
    return { ready, result, window, actual };
  };
  const owned = objects.find(({ descriptor }) => descriptor.name === "owned");
  let result = await attempt("read", "read", owned.descriptor.path);
  requireObservation(
    result.result.allowed &&
      result.result.nativeCode === 0 &&
      result.window.some(
        ({ raw }) =>
          raw.pid === admission.payload.pid &&
          raw.opcode === "4663" &&
          raw.target.toLowerCase() === owned.descriptor.path.toLowerCase() &&
          raw.subjectSid === plan.value.accountSid &&
          raw.accessMask & 1,
      ),
  );
  const read = {
    ...native(result),
    identity: admission.payload,
    allowed: true,
    nativeCode: 0,
    bytes: request.nonce,
    fileIdentitySha256: identity(owned),
  };
  const editBefore = await state("owned");
  result = await attempt("edit", "write", owned.descriptor.path);
  const editAfter = await state("owned"),
    writable = plan.value.profile !== "read-only";
  requireObservation(
    result.result.allowed === writable &&
      result.result.nativeCode === (writable ? 0 : 5) &&
      result.window.some(
        ({ raw }) =>
          raw.pid === admission.payload.pid &&
          raw.opcode === (writable ? "4663" : "4656") &&
          raw.target.toLowerCase() === owned.descriptor.path.toLowerCase() &&
          raw.subjectSid === plan.value.accountSid &&
          raw.accessMask & 2,
      ),
  );
  const edit = {
    ...native(result),
    identity: admission.payload,
    allowed: writable,
    nativeCode: result.result.nativeCode,
    bytes: writable ? request.nonce + "-owned-edit" : request.nonce,
    before: editBefore,
    after: editAfter,
  };
  const denials = [];
  const loopback = [];
  for (const endpoint of plan.value.endpoints)
    loopback.push(
      await observeWindowsAccessLoopback(reader, endpoint, {
        ...session,
        input: plan.value,
      }),
    );
  for (const id of WINDOWS_ACCESS_DENIALS) {
    const control = await reader.accessControl(id, payloadSlot);
    requireObservation(
      control.independent &&
        control.ready &&
        control.reachable &&
        control.nonce === request.nonce,
    );
    if (!fileTargets[id]) {
      // Network/IPC observations retain their actual control/socket objects;
      // the native transport supplies operations, never an owner callback.
      denials.push(
        await observeWindowsAccessDenial(reader, id, {
          ...session,
          input: plan.value,
          control,
          payload: admission.payload,
        }),
      );
      continue;
    }
    const [name, operation] = fileTargets[id],
      target = objects.find(({ descriptor }) => descriptor.name === name),
      before = await state(name);
    requireObservation(control.targetIdentitySha256 === before.identitySha256);
    const value = await attempt(id, operation, target.descriptor.path);
    requireObservation(
      value.result.allowed === false && value.result.nativeCode === 5,
    );
    if (name !== "registry")
      requireObservation(
        value.window.some(
          ({ raw }) =>
            raw.pid === admission.payload.pid &&
            raw.opcode === "4656" &&
            raw.subjectSid === plan.value.accountSid &&
            raw.target.toLowerCase() === target.descriptor.path.toLowerCase() &&
            (raw.accessMask & accessMasks[operation]) ===
              accessMasks[operation],
        ),
      );
    denials.push({
      ...native(value),
      caseId: id,
      identity: admission.payload,
      attempted: true,
      allowed: false,
      nativeCode: value.result.nativeCode,
      target: target.descriptor.path,
      before,
      after: await state(name),
      control: { ...control, readyBeforeAttempt: true },
    });
  }
  const final = await accessReaders.read();
  return {
    ...native({ proof, final, denials, loopback }),
    candidateSha: request.candidateSha,
    compositionSha256: plan.compositionSha256,
    identity: admission.payload,
    token: held.token,
    jobObjectSha256: admission.setup.job.heldObjectSha256,
    privateChannelsOnly: true,
    providersExcluded: true,
    members: final.actual.members.map((member) => ({
      ...native(member),
      identity: member.identity,
      token: member.token,
      jobObjectSha256: admission.setup.job.heldObjectSha256,
      creationTimeJobVerified: member.inJob,
      heldIdentityVerified: true,
    })),
    read,
    edit,
    denials,
    loopback,
  };
}
