import { observationDigest } from "../index.js";
import {
  closed,
  dense,
  digest,
  hash,
  requireWindows,
  sameWindowsIdentity,
  systemIdentity,
} from "./protocol.js";
import { integer, decode, fileObservation } from "./custody-protocol.js";
import {
  normalizeWindowsBarrierRead,
  normalizeWindowsSecurityRead,
} from "./effective-protocol.js";
import {
  windowsObserverConfiguration,
  assertWindowsObserverEvent,
} from "./observer.js";
import { buildWindowsPolicy } from "./policy.js";
import { assertWindowsWfpFilterRead } from "./wfp-reader.js";

const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const categories = [
  "0cce921d-69ae-11d9-bed3-505054503030",
  "0cce9225-69ae-11d9-bed3-505054503030",
  "0cce9226-69ae-11d9-bed3-505054503030",
];
export { createWindowsAuditDecoder } from "./audit-decoder.js";

/** Joins only freshly read held process/token/Job/object identities and an
 * acknowledged native interval. Route hashes identify actual kernel objects. */
export async function bindWindowsAuditEvent(
  reader,
  event,
  value,
  binding,
  transfer,
  barriers,
) {
  windowsObserverConfiguration(value);
  closed(transfer, ["subject", "job", "object"]);
  value = structuredClone(value);
  event = structuredClone(event);
  binding = structuredClone(binding);
  transfer = structuredClone(transfer);
  barriers = structuredClone(barriers);
  requireWindows(
    dense(barriers, 2).length === 2 &&
      barriers[1].sequence === barriers[0].sequence + 1 &&
      BigInt(event.time) >= BigInt(barriers[0].time) &&
      BigInt(event.time) <= BigInt(barriers[1].time) &&
      integer(event.index, 4095) &&
      barriers[0].events <= event.index &&
      event.index < barriers[1].events,
  );
  const before = await reader.process(transfer.subject),
    token = await reader.effectiveToken(transfer.subject),
    job = await reader.inspectJob(transfer.job);
  requireWindows(
    before.independent === true &&
      !before.retired &&
      before.identity.pid === event.raw.pid &&
      BigInt(event.time) >= BigInt(before.identity.creationTime) &&
      token.userSid === value.domain.accountSid &&
      equal(token.restrictedSids, [value.domain.restrictingSid]) &&
      token.tokenId === before.tokenId &&
      job.independent === true &&
      job.members.some((identity) =>
        sameWindowsIdentity(identity, before.identity),
      ) &&
      observationDigest(
        Object.fromEntries(
          Object.entries(job).filter(([key]) => key !== "independent"),
        ),
      ) === value.domain.jobSha256,
  );
  let objectSha256, nativeFilter;
  if (event.raw.filterId === null) {
    closed(transfer.object, ["before", "after", "index"]);
    const first = normalizeWindowsBarrierRead(transfer.object.before),
      last = normalizeWindowsBarrierRead(transfer.object.after),
      held = await reader.inspect(transfer.object.index);
    requireWindows(
      first.identity === last.identity &&
        last.identity === held.identity &&
        decode(held.pathHex) === event.raw.target,
    );
    objectSha256 = digest(held.identity);
  } else {
    closed(transfer.object, ["key", "descriptor", "policy"]);
    const plan = buildWindowsPolicy(transfer.object.policy),
      actual = await reader.wfp("filter", transfer.object.key);
    requireWindows(
      plan.value.request.candidateSha === value.plan.candidateSha &&
        plan.value.request.nonce === value.plan.nonce &&
        plan.policySha256 === value.plan.policySha256 &&
        plan.value.request.policy.sha256 === plan.policySha256 &&
        plan.value.request.bindings.policy === plan.compositionSha256 &&
        plan.value.accountSid === value.domain.accountSid &&
        plan.value.request.restrictingSid === value.domain.restrictingSid &&
        plan.manifest.filters.some((item) =>
          equal(item, transfer.object.descriptor),
        ) &&
        actual.id === event.raw.filterId,
    );
    assertWindowsWfpFilterRead(actual, transfer.object.descriptor, plan);
    nativeFilter = { key: transfer.object.key, actual };
    objectSha256 = observationDigest({
      filterId: event.raw.filterId,
      target: event.raw.target,
    });
  }
  const after = await reader.process(transfer.subject),
    again = await reader.inspectJob(transfer.job);
  requireWindows(
    equal(before, after) &&
      equal(job, again) &&
      equal(token, await reader.effectiveToken(transfer.subject)),
  );
  if (nativeFilter)
    requireWindows(
      equal(await reader.wfp("filter", nativeFilter.key), nativeFilter.actual),
    );
  const bound = {
    independent: true,
    held: true,
    timeBound: true,
    nativeId: event.raw.id,
    selector: event.raw.target,
    objectSha256,
    before: before.identity,
    after: after.identity,
    jobSha256: value.domain.jobSha256,
    restrictingSid: token.restrictedSids[0],
  };
  assertWindowsObserverEvent(event.raw, bound, value, binding);
  return bound;
}

function auditRead(value, sid) {
  closed(value, ["sid", "systemSha256", "system", "principal"]);
  requireWindows(value.sid === sid && hash(value.systemSha256));
  const normalize = (entries) => {
    const keys = new Set();
    for (const entry of dense(entries, 128)) {
      closed(entry, ["key", "flags"]);
      requireWindows(
        /^[a-f0-9-]{36}$/u.test(entry.key) &&
          integer(entry.flags, 15) &&
          !keys.has(entry.key),
      );
      keys.add(entry.key);
    }
    requireWindows(categories.every((key) => keys.has(key)));
    return structuredClone(entries);
  };
  return {
    sid,
    systemSha256: value.systemSha256,
    system: normalize(value.system),
    principal: value.principal === null ? null : normalize(value.principal),
  };
}
export function createWindowsAuditCustody(
  reader,
  value,
  transfer,
  options = {},
) {
  const configuration = windowsObserverConfiguration(value),
    input = structuredClone(value);
  const verifier = systemIdentity(options.verifier);
  closed(transfer, ["subject", "objects", "helper"]);
  const held = structuredClone(transfer);
  requireWindows(
    integer(held.subject, 31) &&
      integer(held.helper) &&
      dense(held.objects, 44).length > 0 &&
      held.objects.every((index) => integer(index)) &&
      new Set(held.objects).size === held.objects.length,
  );
  let before,
    installed,
    channel,
    possible = false,
    finished = false,
    failed = false,
    busy = false;
  const snapshot = async () => {
    requireWindows(
      sameWindowsIdentity(await reader.verifier(verifier), verifier),
    );
    const audit = auditRead(
        await reader.auditSnapshot(held.subject),
        input.domain.accountSid,
      ),
      objects = [];
    for (const index of held.objects) {
      const read = await reader.acl(held.subject, index);
      closed(read, ["object", "security", "access"]);
      objects.push({
        index,
        object: fileObservation(read.object),
        security: normalizeWindowsSecurityRead(read.security),
      });
    }
    requireWindows(
      sameWindowsIdentity(await reader.verifier(verifier), verifier),
    );
    return { audit, objects, sha256: observationDigest({ audit, objects }) };
  };
  const persist = async (phase, data) => {
    requireWindows(typeof options.persist === "function");
    await options.persist(
      structuredClone({
        candidateSha: input.plan.candidateSha,
        nonce: input.plan.nonce,
        domainSha256: input.plan.domainSha256,
        configurationSha256: observationDigest(configuration),
        phase,
        reservation: "RETAINED",
        ...data,
      }),
    );
  };
  return {
    snapshot,
    async install() {
      requireWindows(!possible && !finished && !failed && !busy);
      busy = true;
      try {
        before = await snapshot();
        requireWindows(
          before.audit.principal === null &&
            before.objects.every(
              (item) =>
                item.security.ownerSid === "S-1-5-18" &&
                item.security.protectedDacl &&
                item.security.sacl.every((ace) => ace.type === 17),
            ) &&
            typeof options.review === "function",
        );
        const proof = await options.review(
          structuredClone({ input, configuration, before }),
        );
        requireWindows(
          proof.independent === true &&
            proof.candidateSha === input.plan.candidateSha &&
            proof.nonce === input.plan.nonce &&
            proof.configurationSha256 === observationDigest(configuration) &&
            proof.beforeSha256 === before.sha256 &&
            proof.ownedObjectsVerified === true &&
            proof.exclusiveWriter === true &&
            proof.admissionsClosed === true &&
            proof.imageSha256 === input.pins.imageSha256 &&
            proof.sourceSha256 === input.pins.sourceSha256 &&
            proof.abiSha256 === input.pins.abiSha256 &&
            sameWindowsIdentity(systemIdentity(proof.verifier), verifier) &&
            hash(proof.nativeEventSha256),
        );
        possible = true;
        await persist("audit-install-possible", {
          beforeSha256: before.sha256,
        });
        await reader.installAudit(
          held.subject,
          before.objects.map((item) => ({
            index: item.index,
            descriptorSha256: item.security.descriptorSha256,
          })),
          before.audit.systemSha256,
        );
        installed = await snapshot();
        requireWindows(
          equal(installed.audit.system, before.audit.system) &&
            installed.audit.systemSha256 === before.audit.systemSha256 &&
            installed.audit.principal !== null &&
            installed.audit.principal.every(
              (entry) =>
                entry.flags === (categories.includes(entry.key) ? 5 : 0),
            ),
        );
        installed.objects.forEach((item, index) => {
          const old = before.objects[index];
          requireWindows(
            item.object.identity === old.object.identity &&
              item.security.daclSha256 === old.security.daclSha256 &&
              equal(item.security.aces, old.security.aces) &&
              item.security.ownerSid === old.security.ownerSid &&
              equal(item.security.sacl, [
                ...old.security.sacl,
                {
                  type: 2,
                  flags: 192,
                  mask: 0x1f01ff,
                  sid: input.domain.accountSid,
                },
              ]),
          );
        });
        await persist("audit-installed", { installedSha256: installed.sha256 });
        channel = await reader.openObserver(input, held.helper);
        return {
          before: structuredClone(before),
          installed: structuredClone(installed),
          channel,
        };
      } catch (error) {
        failed = true;
        throw error;
      } finally {
        busy = false;
      }
    },
    async restore(payloads, observer) {
      requireWindows(possible && !failed && !busy && installed && channel);
      busy = true;
      try {
        for (const proof of [payloads, observer])
          requireWindows(
            proof?.status === "RETIRED" &&
              proof.independent === true &&
              proof.noLiveMembers === true &&
              proof.emergencyCleanup === false &&
              proof.candidateSha === input.plan.candidateSha &&
              proof.nonce === input.plan.nonce &&
              proof.domainSha256 === input.plan.domainSha256 &&
              hash(proof.nativeEventSha256),
          );
        requireWindows(
          sameWindowsIdentity(observer.helper, channel.identity) &&
            typeof options.verifyRetirement === "function",
        );
        const proof = await options.verifyRetirement(
          structuredClone({ input, payloads, observer, before, installed }),
        );
        requireWindows(
          proof.independent === true &&
            proof.status === "RETIRED" &&
            proof.emergencyCleanup === false &&
            proof.candidateSha === input.plan.candidateSha &&
            proof.nonce === input.plan.nonce &&
            proof.domainSha256 === input.plan.domainSha256 &&
            proof.noLiveMembers === true &&
            proof.noForeignCreators === true &&
            proof.noPrincipalFlows === true &&
            proof.exclusiveWriter === true &&
            proof.admissionsClosed === true &&
            proof.installedSha256 === installed.sha256 &&
            sameWindowsIdentity(systemIdentity(proof.verifier), verifier) &&
            verifier.pid !== channel.identity.pid &&
            hash(proof.nativeEventSha256),
        );
        requireWindows((await snapshot()).sha256 === installed.sha256);
        await persist("audit-restore-possible", {
          beforeSha256: before.sha256,
          installedSha256: installed.sha256,
        });
        await reader.restoreAudit();
        const restored = await snapshot();
        requireWindows(
          restored.sha256 === before.sha256 &&
            typeof options.verifySettlement === "function",
        );
        const settlement = await options.verifySettlement(
          structuredClone({ input, before, installed, restored }),
        );
        requireWindows(
          settlement.independent === true &&
            settlement.beforeSha256 === before.sha256 &&
            settlement.installedSha256 === installed.sha256 &&
            settlement.restoredSha256 === restored.sha256 &&
            sameWindowsIdentity(
              systemIdentity(settlement.verifier),
              verifier,
            ) &&
            hash(settlement.nativeEventSha256),
        );
        await persist("audit-restored", { beforeSha256: before.sha256 });
        possible = false;
        finished = true;
        return settlement;
      } catch (error) {
        failed = true;
        throw error;
      } finally {
        busy = false;
      }
    },
  };
}

/** The caller retires payload domains before stop(), then independently
 * retires/closes the helper channel before owned audit restoration. */
export function createWindowsSecurityCapture(channel, decoder, value) {
  windowsObserverConfiguration(value);
  requireWindows(decoder.binding().abiSha256 === value.pins.abiSha256);
  const plan = structuredClone(value.plan);
  let ready = false,
    ended = false,
    failed = false,
    pending = false;
  const exact = async (size) => {
    const chunks = [];
    let total = 0;
    while (total < size) {
      const chunk = await channel.receive(Math.min(16384, size - total));
      requireWindows(
        Buffer.isBuffer(chunk) &&
          chunk.length > 0 &&
          chunk.length <= size - total,
      );
      total += chunk.length;
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  };
  const frame = async () => {
    const header = await exact(4),
      size = header.readUInt32LE();
    let bytes = header;
    if (size === 0xfffffffe) bytes = Buffer.concat([header, await exact(16)]);
    else if (size === 0xffffffff) {
      const rest = await exact(12),
        count = rest.readUInt32LE(8);
      requireWindows(count >= 4 && count <= 65536);
      bytes = Buffer.concat([header, rest, await exact(count)]);
    } else if (size !== 0) {
      requireWindows(size >= 4 && size <= 65536);
      bytes = Buffer.concat([header, await exact(size)]);
    }
    await decoder.push(bytes);
    bytes.fill(0);
    return size;
  };
  const guarded = async (body) => {
    requireWindows(!pending && !failed && !ended);
    pending = true;
    try {
      return await body();
    } catch (error) {
      failed = true;
      throw error;
    } finally {
      pending = false;
    }
  };
  return {
    start: () =>
      guarded(async () => {
        requireWindows(!ready);
        await channel.send("A");
        requireWindows((await frame()) === 0);
        ready = true;
        return decoder.state();
      }),
    barrier: () =>
      guarded(async () => {
        requireWindows(ready);
        const previous = decoder.state().barriers.length;
        await channel.send("B");
        while ((await frame()) !== 0xfffffffe)
          requireWindows(!decoder.state().ended);
        const state = decoder.state();
        requireWindows(state.barriers.length === previous + 1);
        return state;
      }),
    stop: (proof) =>
      guarded(async () => {
        requireWindows(
          ready &&
            proof?.status === "RETIRED" &&
            proof.independent === true &&
            proof.noLiveMembers === true &&
            proof.emergencyCleanup === false &&
            proof.candidateSha === plan.candidateSha &&
            proof.nonce === plan.nonce &&
            proof.domainSha256 === plan.domainSha256 &&
            hash(proof.nativeEventSha256),
        );
        systemIdentity(proof.verifier);
        await channel.send("S");
        while ((await frame()) !== 0xffffffff) {}
        ended = true;
        return decoder.finish();
      }),
  };
}
