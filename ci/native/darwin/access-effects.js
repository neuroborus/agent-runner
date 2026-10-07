import { isIP } from "node:net";
import {
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import {
  digest,
  darwinLaunchDigest,
  DARWIN_LITERAL_ARGUMENTS,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import { buildDarwinPolicy, darwinPfctlArguments } from "./policy.js";
import {
  DARWIN_ACCESS_DENIALS,
  assertDarwinAccessObservation,
} from "./access.js";
import {
  configureDarwinPolicy,
  assertDarwinPolicyInstallation,
} from "./policy-effects.js";
import { createDarwinPfPreparation } from "./pf-preparation.js";
import { createDarwinAuditDecoder, bindDarwinAuditEvent } from "./audit.js";
import { createDarwinEffectiveReaders } from "./effective.js";
import { createDarwinCaseEffects } from "./case-effects.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const root = (value) => {
  const identity = normalizeDarwinIdentity(value);
  requireObservation(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
};
const ids = (plan) => [
  "inspection",
  "edit",
  ...DARWIN_ACCESS_DENIALS,
  ...plan.value.endpoints.map(
    ({ family, protocol }) => `loopback-${family}-${protocol}`,
  ),
];

/** The independently approved access record contains only bounded data. It is
 * distinct from the generated composition and from the PF bootstrap approval. */
export async function darwinAccessPreparation(state, setup, binding, base) {
  observationObject(setup.access, ["approval"]);
  observationObject(setup.access.approval, ["path", "sha256"]);
  const plan = buildDarwinPolicy(setup.input),
    bytes = await state.read(
      setup.access.approval.path,
      setup.access.approval.sha256,
    ),
    value = JSON.parse(bytes);
  requireObservation(
    bytes.equals(Buffer.from(JSON.stringify(value) + "\n")) &&
      digest(bytes) === plan.value.reviewSha256,
  );
  observationObject(value, [
    "schemaVersion",
    "contextSha256",
    "pf",
    "audit",
    "assets",
    "objects",
    "attempts",
  ]);
  requireObservation(
    value.schemaVersion === 1 &&
      value.contextSha256 === observationDigest(binding.context),
  );
  observationObject(value.pf, [
    "approval",
    "tool",
    "install",
    "restore",
    "configuration",
    "before",
    "anchorRulesSha256",
  ]);
  observationObject(value.audit, ["mapping", "classes", "helper"]);
  requireObservation(
    Number.isSafeInteger(value.audit.classes) &&
      value.audit.classes > 0 &&
      value.audit.classes <= 0x7fffffff,
  );
  const entries = [...base];
  requireObservation(
    Array.isArray(value.assets) &&
      value.assets.length > 0 &&
      value.assets.length <= 64,
  );
  for (const asset of value.assets) {
    observationObject(asset, ["kind", "path", "sha256", "source"]);
    requireObservation(
      ["authority", "data", "image", "helper", "cache"].includes(asset.kind) &&
        (asset.kind === "authority"
          ? asset.sha256 === null
          : hash(asset.sha256)) &&
        typeof asset.path === "string" &&
        asset.path.startsWith("/") &&
        (asset.source === null ||
          (Number.isSafeInteger(asset.source) &&
            asset.source >= 0 &&
            asset.source < entries.length)),
    );
    if (asset.source !== null)
      requireObservation(
        ["image", "helper", "data"].includes(asset.kind) &&
          entries[asset.source].sha256 === asset.sha256 &&
          asset.path.startsWith(plan.value.request.custody + "/"),
      );
    const { source, ...entry } = asset;
    entries.push(entry);
  }
  requireObservation(
    entries.length <= 128 &&
      new Set(entries.map(({ path }) => path)).size === entries.length,
  );
  const at = (index) => {
    requireObservation(
      Number.isSafeInteger(index) && index >= 0 && index < entries.length,
    );
    return entries[index];
  };
  observationObject(value.pf.tool, ["index", "cdhash"]);
  observationObject(value.audit.helper, ["index", "cdhash"]);
  requireObservation(
    [value.pf.tool.cdhash, value.audit.helper.cdhash].every(
      (value) => typeof value === "string" && /^[a-f0-9]{40}$/u.test(value),
    ),
  );
  requireObservation(
    at(value.pf.tool.index).path === plan.value.request.custody + "/pfctl" &&
      at(value.pf.configuration).path ===
        plan.value.request.custody + "/darwin-pf.conf" &&
      at(value.pf.configuration).sha256 === plan.pfSha256 &&
      at(value.pf.before).path ===
        plan.value.request.custody + "/darwin-pf-before.conf" &&
      at(value.pf.before).sha256 === digest("\n") &&
      at(value.audit.helper.index).path ===
        plan.value.request.custody + "/observer" &&
      at(value.audit.helper.index).sha256 ===
        state.manifest.helpers.find(({ name }) => name === "observer-helper")
          ?.sha256 &&
      hash(value.pf.anchorRulesSha256),
  );
  requireObservation(
    Array.isArray(value.objects) &&
      value.objects.length <= 128 &&
      new Set(value.objects.map(({ index }) => index)).size ===
        value.objects.length,
  );
  for (const object of value.objects) {
    observationObject(object, ["index", "decisions", "aclSha256"]);
    at(object.index);
    requireObservation(
      Array.isArray(object.decisions) &&
        object.decisions.length === 5 &&
        object.decisions.every((decision) => [0, 1].includes(decision)) &&
        hash(object.aclSha256),
    );
  }
  requireObservation(
    Array.isArray(value.attempts) &&
      same(
        value.attempts.map(({ id }) => id),
        ids(plan),
      ),
  );
  const { request } = plan.value,
    caseRoot = request.custody.slice(0, -8);
  const operations = [
    "read",
    "write",
    "write",
    "write",
    "unlink",
    "replace",
    "parent",
    "read",
    "write",
    "read",
    "read",
    "read",
    "write",
    "mach",
    "unix",
    "shm",
    "sem",
    "sysv-shm",
    "sysv-sem",
  ];
  const targets = [
    request.workspace + "/inspection",
    request.workspace + "/edit",
    plan.value.metadata + "/sentinel",
    plan.value.pointer,
    plan.value.pointer,
    plan.value.pointer,
    request.workspace,
    request.custody + "/sentinel",
    request.custody + "/sentinel",
    plan.value.checkout + "/sentinel",
    plan.value.configuration + "/sentinel",
    plan.value.credentials + "/sentinel",
    caseRoot + "/outside/sentinel",
    "org.native-poc." + request.nonce,
    caseRoot + "/ipc",
    "/native-poc-" + request.nonce,
    "/native-poc-" + request.nonce,
    "sysv-shm",
    "sysv-sem",
  ];
  for (const [i, attempt] of value.attempts.entries()) {
    const endpoint = i >= 35 ? plan.value.endpoints[i - 35] : null,
      operation =
        operations[i] ??
        (endpoint
          ? `${endpoint.protocol}${endpoint.family === "inet" ? 4 : 6}-pair`
          : `${(i - 19) % 2 ? "udp" : "tcp"}${(i - 19) % 4 >= 2 ? 6 : 4}`);
    requireObservation(
      attempt.operation === operation &&
        (i >= 19 || attempt.target === targets[i]),
    );
    if (endpoint)
      requireObservation(
        attempt.target === endpoint.address &&
          attempt.remote === endpoint.serverPort &&
          attempt.local === endpoint.clientPort,
      );
    else if (i >= 19) {
      const family = (i - 19) % 4 >= 2 ? 6 : 4,
        category = Math.floor((i - 19) / 4),
        loopback = family === 6 ? "::1" : "127.0.0.1",
        wildcard = family === 6 ? "::" : "0.0.0.0";
      requireObservation(
        isIP(attempt.target) === family &&
          attempt.remote >= 1024 &&
          attempt.local >= 1024 &&
          (category === 1
            ? attempt.target === wildcard
            : category === 2
              ? ![loopback, wildcard].includes(attempt.target)
              : attempt.target === loopback) &&
          !plan.value.endpoints.some(
            (entry) =>
              [entry.clientPort, entry.serverPort].includes(attempt.remote) ||
              [entry.clientPort, entry.serverPort].includes(attempt.local),
          ),
      );
    }
    observationObject(attempt, [
      "id",
      "event",
      "controlEvent",
      "target",
      "operation",
      "remote",
      "local",
    ]);
    requireObservation(
      typeof attempt.target === "string" &&
        attempt.target.length > 0 &&
        attempt.target.length <= 4096 &&
        !/[\u0000-\u0020\u007f]/u.test(attempt.target) &&
        [
          "read",
          "write",
          "unlink",
          "replace",
          "parent",
          "mach",
          "unix",
          "shm",
          "sem",
          "sysv-shm",
          "sysv-sem",
          "tcp4",
          "tcp6",
          "udp4",
          "udp6",
          "tcp4-pair",
          "tcp6-pair",
          "udp4-pair",
          "udp6-pair",
        ].includes(attempt.operation) &&
        [attempt.remote, attempt.local].every(
          (port) => Number.isSafeInteger(port) && port >= 0 && port <= 65535,
        ) &&
        [attempt.event, attempt.controlEvent].every((event) =>
          value.audit.mapping.events.some((entry) => entry.event === event),
        ),
    );
  }
  return { ...value, entries };
}

/** Private fixed-entry composition. The sealed reader supplies syscall results,
 * BSM frames, held objects and kernel identities, never an access verdict. */
export function createDarwinAccessEffects(state, current, save) {
  const { reader, binding, provisioned, recipe } = current,
    specification = provisioned.access,
    plan = buildDarwinPolicy(current.input),
    { request } = plan.value,
    requestSha256 = darwinLaunchDigest(request, DARWIN_LITERAL_ARGUMENTS),
    caseOwner = createDarwinCaseEffects(state, current, save),
    decoder = createDarwinAuditDecoder(reader, specification.audit.mapping);
  let failure,
    policy,
    proof,
    observer,
    health,
    retirement,
    restored,
    sequence = 0;
  const latched =
    (operation) =>
    async (...args) => {
      try {
        return await operation(...args);
      } catch (cause) {
        throw (failure ??= cause);
      }
    };
  const persist = latched((kind, value) =>
    caseOwner.custody.persist(kind, value),
  );
  const guard = () => {
    if (failure) throw failure;
    state.guard(current.cleanupSignal ?? current.signal);
  };
  const checked = (operation) =>
    latched(async (...args) => {
      guard();
      const result = await operation(...args);
      guard();
      return result;
    });
  const witnesses = async () => {
    await caseOwner.custody.witness();
    return createDarwinEffectiveReaders(
      reader,
      binding.context,
      current.admission.helper,
    );
  };
  const pfSnapshot = async () => {
    const actual = await reader.pf(),
      rules =
        actual.graph.find(({ anchor }) => anchor === plan.anchor)?.rules ?? [],
      empty = rules.length === 0,
      expected = {
        compositionSha256: plan.compositionSha256,
        rootSha256: specification.pf.approval.installedRootSha256,
        anchorRulesSha256: empty
          ? digest(JSON.stringify([]))
          : specification.pf.anchorRulesSha256,
        routesSha256: specification.pf.approval.routesSha256,
        anchorSha256: empty ? digest("\n") : plan.pfSha256,
      };
    const sockets = await reader.access("sockets");
    const snapshot = await (
      await witnesses()
    ).pfSnapshot(plan.value, expected, 10, sockets);
    return { ...snapshot, savedAnchorSha256: digest("\n") };
  };
  const verifyRetirement = async () => {
    requireObservation(retirement);
    const actual = await reader.verifyOwnership(retirement.domain.asid);
    requireObservation(
      actual.enumeration.live.length === 0 &&
        actual.enumeration.zombies.length === 0,
    );
    const verifier = root(actual.verifier);
    requireObservation(verifier.pid !== retirement.freshVerifier.pid);
    return {
      independent: true,
      noLiveUid: true,
      uid: request.uid,
      gid: request.gid,
      asid: retirement.domain.asid,
      helpersSettled: true,
      requestSha256,
      authoritySha256: plan.compositionSha256,
      verifier,
      receiptSha256: observationDigest(actual),
    };
  };
  const pf = createDarwinPfPreparation(
    {
      context: binding.context,
      approval: specification.pf.approval,
      tool: specification.pf.tool,
      install: specification.pf.install,
      restore: specification.pf.restore,
      reservation: 10,
      nonce: request.nonce,
    },
    {
      review: async (approval) => {
        requireObservation(same(approval, specification.pf.approval));
        return {
          status: "MATCHED",
          contextSha256: specification.contextSha256,
          manifestSha256: approval.manifestSha256,
        };
      },
      read: () => reader.pf(),
      reserve: async (index, nonce) => {
        requireObservation(index === 10 && nonce === request.nonce);
        await reader.reservation();
      },
      write: (...args) => reader.writePf(...args),
      reservation: () => reader.reservation(),
      persist: (record) => persist("pf-prerequisite", record),
      verifyRetirement: async () => {
        await verifyRetirement();
        return true;
      },
    },
  );
  const policyEffects = {
    persist: (record) => persist("access-policy", record),
    review: async () => ({
      status: "MATCHED",
      approvedSha256: binding.approval.manifestSha256,
      reviewSha256: plan.value.reviewSha256,
      toolSha256: specification.entries[specification.pf.tool.index].sha256,
    }),
    snapshot: pfSnapshot,
    stage: async () => {
      const seatbelt = await reader.read(6),
        configuration = await reader.read(specification.pf.configuration),
        before = await reader.read(specification.pf.before);
      requireObservation(
        digest(seatbelt) === plan.seatbeltSha256 &&
          digest(configuration) === plan.pfSha256 &&
          digest(before) === digest("\n"),
      );
      return {
        seatbeltSha256: digest(seatbelt),
        pfSha256: digest(configuration),
        restoreSha256: digest(before),
        immutable: true,
        receiptSha256: observationDigest({
          seatbelt: digest(seatbelt),
          pf: digest(configuration),
          before: digest(before),
        }),
      };
    },
    pfctl: async (input, vector, toolSha256) => {
      const operation = [
        "validate",
        "validate-restore",
        "install",
        "restore",
      ].find((op) => same(vector, darwinPfctlArguments(input, op)));
      requireObservation(
        operation &&
          toolSha256 ===
            specification.entries[specification.pf.tool.index].sha256,
      );
      const started = await reader.access(
          "pf-start",
          specification.pf.tool.index,
          operation.includes("restore")
            ? specification.pf.before
            : specification.pf.configuration,
          specification.pf.tool.cdhash,
          operation,
        ),
        helper = root(started.helper);
      await persist("pf-helper", { operation, helper, worker: null });
      requireObservation(
        (await reader.helper(helper)).sha256 === request.launcher.sha256,
      );
      const worker = root((await reader.access("pf-worker")).worker);
      await persist("pf-helper", { operation, helper, worker });
      requireObservation(
        (await reader.helper(worker)).sha256 === request.launcher.sha256 &&
          (await reader.signature(specification.pf.tool.index)).cdhash ===
            specification.pf.tool.cdhash,
      );
      await caseOwner.custody.witness();
      const completed = await reader.access("pf-run");
      requireObservation(completed.exitCode === 0 && completed.signal === null);
      await reader.retired(helper);
      await reader.retired(worker);
      const verifier = await caseOwner.custody.witness();
      return {
        helper,
        worker,
        verifier,
        receiptSha256: observationDigest({
          started,
          worker,
          completed,
          verifier,
        }),
        toolSha256,
        exitCode: 0,
        signal: null,
        timedOut: false,
        settled: true,
      };
    },
    verifySettlement: async (input, record) => {
      const helpers = record.helperReceipts.flatMap(({ helper, worker }) => [
        helper,
        worker,
      ]);
      for (const helper of helpers) await reader.retired(helper);
      return {
        independent: true,
        helpersSettled: true,
        compositionSha256: plan.compositionSha256,
        helpers,
        verifier: await caseOwner.custody.witness(),
      };
    },
    verifyRetirement,
    readPolicy: async () => {
      current.accessPolicy = {
        seatbelt: specification.objects,
        pf: await pfSnapshot(),
      };
      proof = await caseOwner.prepare();
      return proof.observed;
    },
  };
  // Preserve the native first cause when the policy orchestrator records FAIL.
  for (const [key, operation] of Object.entries(policyEffects))
    policyEffects[key] = latched(operation);
  const capture = async (command) => {
    const frame = await reader.access("audit", command);
    observationObject(frame, ["hex"]);
    requireObservation(
      typeof frame.hex === "string" && /^(?:[a-f0-9]{2})+$/u.test(frame.hex),
    );
    await decoder.push(Buffer.from(frame.hex, "hex"));
    return frame;
  };
  const window = async (operation) => {
    await capture("B");
    const before = ++sequence;
    await operation();
    await capture("B");
    const after = ++sequence;
    return decoder.window(before, after);
  };
  let installedRules;
  const attempts = [];
  const target = async (index, control) => {
    const value = await reader.access("target", index, control ? 1 : 0);
    observationObject(value, ["kind", "path", "value"]);
    requireObservation(["path", "socket", "ipc"].includes(value.kind));
    return {
      ...value,
      sha256:
        value.kind === "path"
          ? value.value.sha256
          : observationDigest(
              value.kind === "socket" ? value.value.target : value.value,
            ),
      bindingSha256: observationDigest(value.value),
    };
  };
  const attempt = async (spec, index, control) => {
    const begin = await reader.access("attempt", control ? 1 : 0, index),
      before = await target(index, control),
      subject = normalizeDarwinIdentity(begin.identity);
    requireObservation(
      control ? subject.uid !== request.uid : subject.uid === request.uid,
    );
    await persist("access-attempt", { index, control, subject, before });
    const checkedBefore = await reader.process(subject.pid);
    requireObservation(sameDarwinIdentity(subject, checkedBefore));
    let result;
    const countersBefore =
      !control && index >= 19 ? await reader.access("counters") : null;
    const events = await window(async () => {
      result = await reader.access("run", control ? 1 : 0);
    });
    const countersAfter = countersBefore
      ? await reader.access("counters")
      : null;
    const checkedAfter = await reader.process(subject.pid),
      after = await target(index, control);
    requireObservation(sameDarwinIdentity(subject, checkedAfter));
    const native = events.filter(
      (event) =>
        event.pid === subject.pid &&
        event.opcode ===
          specification.audit.mapping.events.find(
            (entry) =>
              entry.event === (control ? spec.controlEvent : spec.event),
          ).opcode,
    );
    requireObservation(
      native.length === 1 &&
        result.nativeCode === native[0].error &&
        result.nonce === request.nonce,
    );
    const event = native[0],
      expected =
        (index === 1 && !control && plan.value.profile !== "read-only") ||
        (control && spec.operation === "write")
          ? digest(request.nonce + "-edit")
          : before.kind === "path"
            ? before.sha256
            : before.bindingSha256;
    const beforeObject = before.value,
      afterObject = after.value;
    requireObservation(
      before.kind === after.kind &&
        event.kind === before.kind &&
        before.sha256 ===
          (before.kind === "path"
            ? before.value.sha256
            : observationDigest(
                before.kind === "socket" ? before.value.target : before.value,
              )) &&
        after.sha256 ===
          (after.kind === "path"
            ? after.value.sha256
            : observationDigest(
                after.kind === "socket" ? after.value.target : after.value,
              )),
    );
    bindDarwinAuditEvent(
      event,
      checkedBefore,
      checkedAfter,
      { before: beforeObject, after: afterObject },
      expected,
      event.window.barrierSha256,
    );
    requireObservation(
      control
        ? event.error === 0
        : index !== 0 && index !== 1 && index < 35
          ? event.error !== 0
          : true,
    );
    if (event.kind === "path") requireObservation(event.target === before.path);
    let peer;
    if (index >= 35 && !control) {
      requireObservation(
        result.nativeCode === 0 &&
          countersBefore.length === countersAfter.length,
      );
      const members = await reader.ownershipMembers(subject.asid);
      requireObservation(
        members.complete &&
          members.zombies.length === 0 &&
          members.live.some((value) => sameDarwinIdentity(value, subject)),
      );
      peer = await reader.access("peer");
      const peerIdentity = normalizeDarwinIdentity(peer.identity);
      requireObservation(
        sameDarwinIdentity(
          await reader.process(peerIdentity.pid),
          peerIdentity,
        ) &&
          peerIdentity.asid === subject.asid &&
          peerIdentity.auid === request.uid &&
          ["uid", "ruid", "svuid"].every(
            (key) => peerIdentity[key] === request.uid,
          ) &&
          ["gid", "rgid", "svgid"].every(
            (key) => peerIdentity[key] === request.gid,
          ) &&
          peer.socket.kernelId === before.value.target.kernelId &&
          peer.socket.port === spec.remote &&
          peer.socket.exclusive === true &&
          sameDarwinIdentity(peer.socket.subject, peerIdentity),
      );
      const endpoint = plan.value.endpoints[index - 35],
        networkEvents = [];
      for (const [legIndex, leg] of ["request", "return"].entries())
        for (const [directionIndex, direction] of ["out", "in"].entries()) {
          const ruleIndex = (index - 35) * 8 + legIndex * 2 + directionIndex;
          const a = countersBefore[ruleIndex],
            b = countersAfter[ruleIndex];
          requireObservation(
            a &&
              b &&
              a.index === ruleIndex &&
              b.index === ruleIndex &&
              a.action === "permit" &&
              b.action === "permit" &&
              hash(a.ruleSha256) &&
              a.ruleSha256 === b.ruleSha256 &&
              a.ruleSha256 ===
                digest(Buffer.from(installedRules[ruleIndex].raw, "hex")) &&
              BigInt(b.packets) > BigInt(a.packets),
          );
          networkEvents.push({
            leg,
            direction,
            decision: "permit",
            ownerUid: request.uid,
            identity:
              (leg === "request") === (direction === "out")
                ? subject
                : peerIdentity,
            sourcePort:
              leg === "request" ? endpoint.clientPort : endpoint.serverPort,
            destinationPort:
              leg === "request" ? endpoint.serverPort : endpoint.clientPort,
            sourceAddress: endpoint.family === "inet" ? "127.0.0.1" : "::1",
            destinationAddress:
              endpoint.family === "inet" ? "127.0.0.1" : "::1",
            nativeEventSha256: observationDigest({
              before: a,
              after: b,
              subject,
              event: event.id,
            }),
          });
        }
      result = {
        ...result,
        requestSha256: digest(request.nonce),
        responseSha256: digest(request.nonce),
        events: networkEvents,
      };
    }
    if (peer) requireObservation(same(peer, await reader.access("peer")));
    await reader.access("complete", control ? 1 : 0);
    if (peer) await reader.retired(peer.identity, { reserved: true });
    if (control) {
      await reader.retired(subject);
      return {
        ready: true,
        reachable: true,
        independent: true,
        discretionaryAllowed: true,
        identity: subject,
        nonce: request.nonce,
        targetSha256: before.sha256,
        acknowledgementSha256: observationDigest({
          begin,
          result,
          before,
          after,
        }),
        nativeEventSha256: event.id,
      };
    }
    requireObservation(
      subject.asid === caseOwner.custody.admitted().payload.asid,
    );
    requireObservation(
      [0, 1, 13, 61].includes(event.error) ||
        (spec.operation === "mach" && event.error === 1100),
    );
    const observation = {
      id: spec.id,
      identity: subject,
      attempted: true,
      timedOut: false,
      code:
        event.error === 0
          ? "OK"
          : event.error === 1
            ? "EPERM"
            : event.error === 13
              ? "EACCES"
              : event.error === 61
                ? "ECONNREFUSED"
                : "MACH_DENIED",
      nativeDecision: event.error === 0 ? "permit" : "deny",
      nativeEventSha256: event.id,
      beforeSha256: before.sha256,
      afterSha256: after.sha256,
      result,
    };
    if (index >= 2 && index < 35)
      Object.assign(observation, {
        denied: true,
        control: attempts[index].control,
      });
    if (observation.code === "ECONNREFUSED") {
      const drops = countersAfter?.filter(
        (b, i) =>
          b.action === "deny" &&
          b.ruleSha256 === countersBefore[i]?.ruleSha256 &&
          BigInt(b.packets) > BigInt(countersBefore[i].packets),
      );
      requireObservation(drops?.length > 0);
      Object.assign(observation, {
        layer: "pf",
        pfDropSha256: observationDigest({
          countersBefore,
          drops,
          event: event.id,
        }),
      });
    }
    return observation;
  };
  const restore = latched(async () => {
    if (restored) return structuredClone(restored);
    requireObservation(policy?.status === "INSTALLED" && retirement);
    await verifyRetirement();
    if (observer) {
      await capture("S");
      const completion = await reader.access("audit-close");
      health = decoder.finish(completion);
      await reader.retired(observer);
      await persist("audit-retired", { observer, health });
      observer = null;
    }
    await reader.access("controls-close");
    const result = await configureDarwinPolicy(
      plan.value,
      binding,
      policyEffects,
      {
        operation: "restore",
        previous: policy,
        retirement,
        provisioning: provisioned.provisioning,
        argumentsList: DARWIN_LITERAL_ARGUMENTS,
        platform: "darwin",
        architecture: "x64",
        uid: current.admission.helper.uid,
        env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "macos15" },
      },
    );
    requireObservation(result.status === "RESTORED");
    await pf.restore(retirement);
    restored = {
      status: "RESTORED",
      helpersSettled: true,
      candidateSha: request.candidateSha,
      nonce: request.nonce,
      compositionSha256: plan.compositionSha256,
      reservation: "RETAINED",
    };
    await persist("access-restored", restored);
    return structuredClone(restored);
  });
  const retire = latched(async () => {
    if (!retirement)
      retirement = {
        ...(await caseOwner.custody.retire()),
        authoritySha256: plan.compositionSha256,
        caseHelpersSettled: true,
      };
    return structuredClone(retirement);
  });
  return {
    async prepare() {
      return checked(async () => {
        const build = await reader.build();
        requireObservation(/^24[A-Z][0-9]+$/u.test(build.osBuild));
        current.caseEffectsPossible = true;
        await pf.prepare();
        const started = await reader.access(
          "audit-start",
          specification.audit.helper.index,
          specification.audit.helper.cdhash,
          specification.audit.classes,
        );
        observer = root(started.identity);
        await persist("audit-possible", { observer });
        requireObservation(
          (await reader.helper(observer)).sha256 ===
            specification.entries[specification.audit.helper.index].sha256,
        );
        await caseOwner.custody.witness();
        await capture("A");
        const bank = specification.entries.findIndex(
          ({ path }) => path === request.custody + "/access-cases",
        );
        requireObservation(bank >= 12);
        const expected = Buffer.from(
          specification.attempts
            .map(
              ({ operation, target, remote, local }) =>
                `${operation} ${Buffer.from(target).toString("hex")} ${remote} ${local}\n`,
            )
            .join(""),
        );
        requireObservation((await reader.read(bank)).equals(expected));
        await reader.access("provision", bank);
        const pointer = specification.entries.findIndex(
          ({ path }) => path === plan.value.pointer,
        );
        requireObservation(pointer >= 12);
        await reader.rejoinCaseObject(pointer);
        for (const [index, spec] of specification.attempts.entries()) {
          attempts.push({});
          if (index >= 2 && index < 35)
            attempts[index].control = await attempt(spec, index, true);
        }
        policy = await configureDarwinPolicy(
          plan.value,
          binding,
          policyEffects,
          {
            provisioning: provisioned.provisioning,
            argumentsList: DARWIN_LITERAL_ARGUMENTS,
            platform: "darwin",
            architecture: "x64",
            uid: current.admission.helper.uid,
            env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "macos15" },
          },
        );
        assertDarwinPolicyInstallation(policy, plan.value);
        installedRules = (await reader.pf()).graph.find(
          ({ anchor }) => anchor === plan.anchor,
        ).rules;
        requireObservation(
          digest(JSON.stringify(installedRules)) ===
            specification.pf.anchorRulesSha256,
        );
        return proof;
      })();
    },
    effects: {
      persist: (record) => persist("access-owner", record),
      prepare: checked(async () => ({ policy, launchSha256: requestSha256 })),
      verifyPolicy: checked(async () => {
        assertDarwinPolicyInstallation(policy, plan.value);
        return structuredClone(policy);
      }),
      admit: checked(async () => ({
        ...caseOwner.custody.admitted(),
        authority: { policy: { compositionSha256: plan.compositionSha256 } },
      })),
      observe: checked(async () => {
        const values = [];
        for (const [index, spec] of specification.attempts.entries())
          values.push(await attempt(spec, index, false));
        const admitted = caseOwner.custody.admitted(),
          verifier = await caseOwner.custody.witness();
        await caseOwner.custody.unchanged();
        const currentPolicy = await pfSnapshot();
        requireObservation(
          currentPolicy.anchorSha256 === plan.pfSha256 &&
            currentPolicy.rootSha256 === policy.effective.rootSha256,
        );
        const result = {
          independent: true,
          candidateSha: request.candidateSha,
          nonce: request.nonce,
          compositionSha256: plan.compositionSha256,
          requestSha256,
          verifier,
          inspectionObservation: {
            ...values[0],
            bytesSha256: values[0].afterSha256,
          },
          editObservation: values[1],
          inspectionSha256: values[0].afterSha256,
          edit: plan.value.profile === "read-only" ? "denied" : "permitted",
          editEventSha256: values[1].nativeEventSha256,
          protectedUnchanged: true,
          policyPreserved: true,
          denials: values.slice(2, 35),
          loopback: values.slice(35).map((value, i) => ({
            ...plan.value.endpoints[i],
            requestSha256: value.result.requestSha256,
            responseSha256: value.result.responseSha256,
            timedOut: false,
            events: value.result.events,
          })),
        };
        assertDarwinAccessObservation(result, plan.value, admitted);
        await persist("access-observation", result);
        return result;
      }),
      retire,
      restore,
    },
    async finish({ signal }) {
      current.cleanupSignal = signal;
      try {
        await reader.beginCleanup({ signal });
        await retire();
        await restore();
        const objects = await reader.retireCase();
        await reader.releaseReservation({
          context: binding.context,
          nonce: request.nonce,
          status: "RETIRED",
          independent: true,
          noLiveUid: true,
          helpersSettled: true,
          domain: retirement.domain,
          verifier: retirement.freshVerifier,
          receiptSha256: retirement.nativeEventSha256,
          pfBaselineSha256: specification.pf.approval.baselineSha256,
        });
        const custody = await reader.close();
        requireObservation(
          custody.status === "RETIRED" && custody.independent && custody.closed,
        );
        current.retired = true;
        const result = {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
          nativeEventSha256: observationDigest({
            objects,
            custody,
            retirement,
            restored,
            health,
          }),
        };
        await save(recipe.id, { phase: "access-retired", settlement: result });
        return result;
      } catch (cause) {
        throw (failure ??= cause);
      }
    },
  };
}
