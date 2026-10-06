import { performance } from "node:perf_hooks";
import {
  NATIVE_OBSERVER_LIMITS,
  observationDigest,
  requireObservation,
  observationObject,
  observationList,
  normalizeToolObservationPlan,
  assertNativeObserverHealth,
  isWindows2025Image,
  joinNativeToolObservations,
  assertNativeToolAttempt,
  assertNativeObserverSettlement,
} from "../index.js";
import {
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  sid,
} from "./protocol.js";

function normalizeInput(value) {
  observationObject(value, ["plan", "domain", "bindings", "pins"]);
  const plan = normalizeToolObservationPlan(value.plan),
    domain = value.domain;
  observationObject(domain, ["accountSid", "restrictingSid", "jobSha256"]);
  sid(domain.accountSid);
  sid(domain.restrictingSid);
  requireObservation(
    domain.accountSid !== domain.restrictingSid &&
      /^S-1-5-21-/u.test(domain.accountSid) &&
      /^[a-f0-9]{64}$/u.test(domain.jobSha256),
  );
  requireObservation(observationDigest(domain) === plan.domainSha256);
  observationObject(value.pins, [
    "manifestSha256",
    "imageSha256",
    "sourceSha256",
    "abiSha256",
  ]);
  for (const pin of Object.values(value.pins))
    requireObservation(typeof pin === "string" && /^[a-f0-9]{64}$/u.test(pin));
  requireObservation(value.pins.manifestSha256 === plan.reviewSha256);
  const bindings = observationList(
    value.bindings,
    NATIVE_OBSERVER_LIMITS.routes * 3,
  ).map((binding) => {
    observationObject(binding, [
      "routeId",
      "phase",
      "selector",
      "opcode",
      "accessMask",
      "filterId",
    ]);
    requireObservation(
      plan.routes.some((route) => route.id === binding.routeId) &&
        ["control-permit", "control-deny", "tool"].includes(binding.phase) &&
        typeof binding.selector === "string" &&
        binding.selector.length > 0 &&
        binding.selector.length <= 4096 &&
        !/[\u0000-\u001f\u007f]/u.test(binding.selector) &&
        typeof binding.opcode === "string" &&
        /^[a-zA-Z0-9_]{1,64}$/u.test(binding.opcode) &&
        (binding.accessMask === null ||
          (Number.isInteger(binding.accessMask) &&
            binding.accessMask > 0 &&
            binding.accessMask <= 0xffffffff)) &&
        (binding.filterId === null ||
          (typeof binding.filterId === "string" &&
            /^[1-9][0-9]{0,19}$/u.test(binding.filterId))),
    );
    return { ...binding };
  });
  requireObservation(
    bindings.length === plan.routes.length * 3 &&
      new Set(bindings.map((binding) => binding.routeId + ":" + binding.phase))
        .size === bindings.length,
  );
  return {
    plan,
    domain: structuredClone(domain),
    bindings,
    pins: { ...value.pins },
  };
}

export function windowsObserverConfiguration(value) {
  const input = normalizeInput(value);
  const filters = [
    ...new Set(
      input.bindings
        .map((binding) => binding.filterId)
        .filter((id) => id !== null),
    ),
  ];
  // Separate bounded Select expressions avoid the native XPath complexity
  // limit. SID and filter IDs have already been parsed as literal native IDs.
  const selectors = [
    "*[System[((EventID=4656) and band(Keywords,4503599627370496)) or ((EventID=4663) and band(Keywords,9007199254740992))] and EventData[Data[@Name='SubjectUserSid']='" +
      input.domain.accountSid +
      "']]",
    ...filters.map(
      (id) =>
        "*[System[(EventID=5152 or EventID=5156 or EventID=5157)] and EventData[Data[@Name='FilterRTID']='" +
        id +
        "']]",
    ),
    "*[System[(EventID=1101 or EventID=1102)]]",
  ];
  const query =
    "<QueryList><Query Id='0' Path='Security'>" +
    selectors
      .map((selector) => "<Select Path='Security'>" + selector + "</Select>")
      .join("") +
    "</Query></QueryList>";
  requireObservation(query.length <= 16384);
  return {
    mechanism: "object-access-wfp",
    channel: "Security",
    eventIds: [4656, 4663, 5152, 5156, 5157],
    lossEventIds: [1101, 1102],
    subjectSid: input.domain.accountSid,
    success: true,
    failure: true,
    policyScope: "private-sid",
    systemPolicy: "snapshot-only",
    subcategories: [
      "File System",
      "Filtering Platform Packet Drop",
      "Filtering Platform Connection",
    ],
    perUserFlags: [
      "PER_USER_AUDIT_SUCCESS_INCLUDE",
      "PER_USER_AUDIT_FAILURE_INCLUDE",
    ],
    bookmarkRequired: true,
    strictSubscription: true,
    protectOwnedSacl: true,
    ownedChangesOnly: true,
    query,
    bindings: input.bindings,
  };
}

/** Called only with records decoded by the protected native reader and a
 * separate identity/object reader. Unresolved objects and PID reuse fail. */
export function assertWindowsObserverEvent(raw, bound, value, binding) {
  const input = normalizeInput(value);
  observationObject(raw, [
    "id",
    "pid",
    "opcode",
    "target",
    "subjectSid",
    "auditFailure",
    "accessMask",
    "filterId",
  ]);
  observationObject(binding, [
    "routeId",
    "phase",
    "selector",
    "opcode",
    "accessMask",
    "filterId",
  ]);
  requireObservation(
    input.bindings.some(
      (entry) => observationDigest(entry) === observationDigest(binding),
    ) &&
      bound?.independent === true &&
      bound.held === true &&
      bound.timeBound === true &&
      bound.nativeId === raw.id &&
      bound.selector === binding.selector &&
      bound.objectSha256 ===
        (binding.phase === "control-permit"
          ? input.plan.routes.find((route) => route.id === binding.routeId)
              .permitTargetSha256
          : binding.phase === "control-deny"
            ? input.plan.routes.find((route) => route.id === binding.routeId)
                .denyTargetSha256
            : input.plan.routes.find((route) => route.id === binding.routeId)
                .targetSha256) &&
      raw.target === binding.selector &&
      raw.opcode === binding.opcode,
  );
  const before = normalizeWindowsIdentity(bound.before),
    after = normalizeWindowsIdentity(bound.after);
  requireObservation(
    before.pid === raw.pid &&
      sameWindowsIdentity(before, after) &&
      before.userSid === input.domain.accountSid &&
      bound.jobSha256 === input.domain.jobSha256 &&
      bound.restrictingSid === input.domain.restrictingSid,
  );
  if (["4656", "4663"].includes(raw.opcode)) {
    requireObservation(
      raw.subjectSid === input.domain.accountSid &&
        Number.isInteger(raw.accessMask) &&
        raw.accessMask > 0 &&
        raw.accessMask <= 0xffffffff &&
        raw.filterId === null &&
        binding.filterId === null &&
        binding.accessMask > 0 &&
        (raw.accessMask & binding.accessMask) >>> 0 === binding.accessMask &&
        ((raw.opcode === "4656" && raw.auditFailure === true) ||
          (raw.opcode === "4663" && raw.auditFailure === false)),
    );
    return raw.auditFailure ? "deny" : "permit";
  }
  requireObservation(
    ["5152", "5156", "5157"].includes(raw.opcode) &&
      raw.subjectSid === null &&
      raw.accessMask === null &&
      binding.accessMask === null &&
      raw.auditFailure === (raw.opcode !== "5156") &&
      raw.filterId === binding.filterId &&
      typeof raw.filterId === "string" &&
      /^[1-9][0-9]*$/u.test(raw.filterId),
  );
  return raw.opcode === "5156" ? "permit" : "deny";
}

/** All native readers/setup are dedicated external CI effects. The existing
 * protected custody owner supplies these capabilities, never the provider.
 * No arbitrary exception message, native trace or selector is persisted. */
export async function runWindowsToolObserver(
  value,
  effects,
  execute,
  {
    platform = process.platform,
    architecture = process.arch,
    env = process.env,
    build = "",
    now = () => performance.now(),
  } = {},
) {
  const input = normalizeInput(value),
    { plan } = input;
  requireObservation(
    platform === "win32" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      isWindows2025Image({
        build,
        imageOS: env.ImageOS,
        imageVersion: env.ImageVersion,
      }) &&
      typeof effects?.persist === "function" &&
      typeof execute === "function",
  );
  const configuration = windowsObserverConfiguration(input);
  const configurationSha256 = observationDigest(configuration);
  const record = {
    schemaVersion: 1,
    candidateSha: plan.candidateSha,
    nonce: plan.nonce,
    domainSha256: plan.domainSha256,
    configurationSha256,
    status: "BLOCKED",
    phase: "review",
    reservation: "RETAINED",
    missingInputs: [],
  };
  for (const key of [
    "review",
    "snapshot",
    "admit",
    "verifyAdmission",
    "arm",
    "control",
    "collect",
    "bind",
    "read",
    "retirePayloads",
    "drain",
    "retireObserver",
    "restore",
    "verifySettlement",
  ])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("win32-observer-" + key);
  const save = (options) => effects.persist(structuredClone(record), options);
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  let custody = null,
    before = null,
    installed = null,
    observerSha256 = null;
  let failure = false,
    settlement = null,
    health = null;
  const events = [],
    reads = [];
  let active = true,
    pending = false,
    controlsReady = false,
    settled = false;
  let session = null,
    mainComplete = false,
    cleanupStarted = null;
  // Every callback is fenced before invocation and after completion. Abort is
  // not retirement: unreturned native work retains exclusion and cannot restore
  // audit state, even if it later resolves after its deadline.
  const bounded = async (body, deadline, started = now()) => {
    const controller = new AbortController();
    let open = true;
    const guard = () => {
      const elapsed = now() - started;
      requireObservation(
        open &&
          !controller.signal.aborted &&
          Number.isFinite(elapsed) &&
          elapsed >= 0 &&
          elapsed < deadline,
      );
    };
    const context = {
      signal: controller.signal,
      guard,
      call: async (callback, ...args) => {
        guard();
        const result = await callback(...args, { signal: controller.signal });
        guard();
        return result;
      },
    };
    let timer;
    try {
      return await Promise.race([
        Promise.resolve().then(() => body(context)),
        new Promise((_, reject) => {
          timer = setTimeout(
            () => {
              controller.abort();
              reject(new Error("Native observer deadline"));
            },
            Math.max(0, deadline - (now() - started)),
          );
        }),
      ]);
    } catch (error) {
      controller.abort();
      throw error;
    } finally {
      open = false;
      clearTimeout(timer);
    }
  };
  const phase = async (context, name) =>
    context.call(() => {
      record.phase = name;
      return save({ signal: context.signal });
    });
  const attempt = async (routeId, kind, action) => {
    let ownsWindow = false;
    try {
      requireObservation(
        active &&
          !pending &&
          !failure &&
          typeof action === "function" &&
          (kind !== "tool" || controlsReady),
      );
      session.guard();
      const binding = input.bindings.find(
        (item) => item.routeId === routeId && item.phase === kind,
      );
      requireObservation(
        binding &&
          !events.some(
            (event) => event.routeId === routeId && event.phase === kind,
          ),
      );
      pending = true;
      ownsWindow = true;
      const call = async (callback, ...args) => {
        requireObservation(active && !failure);
        const result = await session.call(callback, ...args);
        requireObservation(active && !failure);
        return result;
      };
      await call(() => phase(session, "attempt-possible"));
      const arm = await call(
        effects.arm.bind(effects),
        custody,
        structuredClone(binding),
        configurationSha256,
      );
      requireObservation(
        arm?.candidateSha === plan.candidateSha &&
          arm.nonce === plan.nonce &&
          arm.configurationSha256 === configurationSha256 &&
          arm.acknowledged === true &&
          arm.routeId === routeId &&
          arm.phase === kind &&
          typeof arm.barrierSha256 === "string" &&
          /^[a-f0-9]{64}$/u.test(arm.barrierSha256) &&
          !events.some((event) => event.barrierSha256 === arm.barrierSha256),
      );
      await call(action);
      const capture = await call(
        effects.collect.bind(effects),
        custody,
        structuredClone(binding),
        arm,
      );
      assertNativeObserverHealth(capture.health);
      const native = observationList(
        capture.records,
        NATIVE_OBSERVER_LIMITS.events,
      );
      requireObservation(native.length === 1);
      const raw = native[0];
      const bound = await call(
        effects.bind.bind(effects),
        custody,
        structuredClone(raw),
        structuredClone(binding),
        arm,
      );
      const outcome = assertWindowsObserverEvent(raw, bound, input, binding);
      const route = plan.routes.find((item) => item.id === routeId);
      const event = {
        sequence: events.length + 1,
        routeId,
        phase: kind,
        operation: route.operation,
        outcome,
        nativeId: raw.id,
        subjectSha256: plan.domainSha256,
        targetSha256: bound.objectSha256,
        barrierSha256: arm.barrierSha256,
      };
      const read = await call(
        effects.read.bind(effects),
        custody,
        structuredClone(event),
        arm,
      );
      requireObservation(
        !events.some((previous) => previous.nativeId === event.nativeId),
      );
      assertNativeToolAttempt(plan, event, read, observerSha256);
      events.push(event);
      reads.push(structuredClone(read));
    } catch (error) {
      // A caller catching an error cannot retry away missing or lost evidence.
      failure = true;
      throw error;
    } finally {
      if (ownsWindow) pending = false;
    }
  };
  try {
    await bounded(async (context) => {
      session = context;
      const { signal, call } = context;
      try {
        record.status = "RUNNING";
        await call(save);
        const review = await call(
          effects.review.bind(effects),
          structuredClone(input),
          configurationSha256,
        );
        requireObservation(
          review?.status === "MATCHED" &&
            review.candidateSha === plan.candidateSha &&
            review.configurationSha256 === configurationSha256 &&
            Object.keys(input.pins).every(
              (key) => review[key] === input.pins[key],
            ),
        );
        before = structuredClone(
          await call(effects.snapshot.bind(effects), structuredClone(input)),
        );
        requireObservation(
          before?.candidateSha === plan.candidateSha &&
            before.nonce === plan.nonce &&
            before.configurationSha256 === configurationSha256 &&
            before.independent === true &&
            before.ownedChangesOnly === true &&
            typeof before.sha256 === "string" &&
            /^[a-f0-9]{64}$/u.test(before.sha256),
        );
        await phase(context, "admission-possible");
        // Recovery uses the write-ahead intent even if admission never returns.
        custody = await call(
          effects.admit.bind(effects),
          structuredClone(input),
          structuredClone(configuration),
          structuredClone(before),
        );
        const admission = await call(
          effects.verifyAdmission.bind(effects),
          custody,
          structuredClone(input),
        );
        requireObservation(
          admission?.candidateSha === plan.candidateSha &&
            admission.nonce === plan.nonce &&
            admission.configurationSha256 === configurationSha256 &&
            admission.domainSha256 === plan.domainSha256 &&
            admission.policySha256 === plan.policySha256 &&
            admission.imageSha256 === input.pins.imageSha256 &&
            admission.sourceSha256 === input.pins.sourceSha256 &&
            admission.abiSha256 === input.pins.abiSha256 &&
            admission.independent === true &&
            admission.protected === true &&
            admission.beforeProviderRelease === true &&
            typeof admission.observerSha256 === "string" &&
            /^[a-f0-9]{64}$/u.test(admission.observerSha256) &&
            admission.observerSha256 !== plan.domainSha256,
        );
        observerSha256 = admission.observerSha256;
        installed = structuredClone(
          await call(effects.snapshot.bind(effects), structuredClone(input)),
        );
        requireObservation(
          installed?.candidateSha === plan.candidateSha &&
            installed.nonce === plan.nonce &&
            installed.configurationSha256 === configurationSha256 &&
            installed.independent === true &&
            installed.ownedChangesOnly === true &&
            installed.exclusiveWriter === true &&
            typeof installed.sha256 === "string" &&
            /^[a-f0-9]{64}$/u.test(installed.sha256),
        );
        await phase(context, "positive-controls");
        for (const route of plan.routes)
          for (const kind of ["control-permit", "control-deny"])
            await attempt(route.id, kind, () =>
              effects.control(custody, route.id, kind, { signal }),
            );
        controlsReady = true;
        record.providerStartSequence = events.length + 1;
        await phase(context, "controls-ready");
        await call(execute, {
          attempt: (id, action) => attempt(id, "tool", action),
          signal,
        });
        requireObservation(!pending && !failure);
      } finally {
        mainComplete = true;
      }
    }, NATIVE_OBSERVER_LIMITS.sessionMs);
  } catch {
    failure = true;
    record.status = "FAIL";
  } finally {
    active = false;
    cleanupStarted = now();
    try {
      await bounded(
        async (context) => {
          const { call } = context;
          await phase(context, "retirement-possible");
          let payloads = null;
          try {
            const receipt = await call(
              effects.retirePayloads.bind(effects),
              custody,
              structuredClone(input),
            );
            requireObservation(
              receipt?.independent === true &&
                receipt.candidateSha === plan.candidateSha &&
                receipt.nonce === plan.nonce &&
                receipt.domainSha256 === plan.domainSha256 &&
                receipt.noLiveMembers === true,
            );
            payloads = receipt;
          } catch {
            failure = true;
            record.status = "FAIL";
          }
          if (payloads)
            try {
              health = await call(
                effects.drain.bind(effects),
                custody,
                structuredClone(input),
                payloads,
              );
              assertNativeObserverHealth(health);
            } catch {
              failure = true;
              record.status = "FAIL";
            }
          // Reader retirement is still attempted after a failed payload receipt
          // or lost capture. Neither permits restoration or a successful join.
          const retirement = await call(
            effects.retireObserver.bind(effects),
            custody,
            structuredClone(input),
          );
          requireObservation(
            retirement?.independent === true &&
              retirement.noLiveMembers === true &&
              retirement.candidateSha === plan.candidateSha &&
              retirement.nonce === plan.nonce &&
              retirement.domainSha256 === plan.domainSha256 &&
              retirement.observerSha256 === observerSha256,
          );
          requireObservation(
            payloads && mainComplete && !pending && before && installed,
          );
          await phase(context, "restoration-possible");
          await call(
            effects.restore.bind(effects),
            custody,
            structuredClone(input),
            before,
            installed,
            payloads,
            retirement,
          );
          settlement = await call(
            effects.verifySettlement.bind(effects),
            structuredClone(input),
            before,
            installed,
          );
          assertNativeObserverSettlement(plan, settlement, observerSha256);
          requireObservation(
            settlement.beforeAuditSha256 === before.sha256 &&
              settlement.installedAuditSha256 === installed.sha256,
          );
          settled = true;
          record.settlementSha256 = observationDigest(settlement);
        },
        NATIVE_OBSERVER_LIMITS.cleanupMs,
        cleanupStarted,
      );
    } catch {
      failure = true;
      record.status = "FAIL";
    }
  }
  if (!failure) {
    try {
      record.observation = joinNativeToolObservations(plan, {
        candidateSha: plan.candidateSha,
        nonce: plan.nonce,
        domainSha256: plan.domainSha256,
        policySha256: plan.policySha256,
        observerSha256,
        providerStartSequence: record.providerStartSequence,
        events,
        reads,
        health,
        settlement,
      });
      record.status = "OBSERVED";
    } catch {
      record.status = "FAIL";
    }
  }
  record.phase = settled ? "settled" : "retained";
  try {
    await bounded(
      ({ call }) => call(save),
      NATIVE_OBSERVER_LIMITS.cleanupMs,
      cleanupStarted,
    );
  } catch {
    record.status = "FAIL";
  }
  return record;
}
