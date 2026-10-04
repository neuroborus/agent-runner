import { performance } from "node:perf_hooks";
import {
  observationDigest,
  requireObservation,
  observationObject,
} from "../index.js";
import {
  normalizeProviderSpec,
  providerInvocation,
  PROVIDER_LIMITS,
} from "./contract.js";
import { normalizeRelayPolicy } from "./relay.js";

function freeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
const CONTROLS = Object.freeze([
  "transport",
  "credential-file",
  "credential-environment",
  "credential-process",
  "debug",
  "signal",
  "alternate-network",
  "alternate-ipc",
  "relay-loss",
  "bridge-loss",
]);

/** Native capability callbacks are trusted external CI effects, never provider
 * assertions. The platform owner alone constructs and launches OS authority. */
export async function runProviderTransport(
  input,
  relayPolicy,
  platformOwner,
  effects,
  execute,
  {
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  const spec = freeze(normalizeProviderSpec(input)),
    invocation = freeze(providerInvocation(spec)),
    policy = freeze(normalizeRelayPolicy(relayPolicy));
  requireObservation(
    policy.provider === spec.provider &&
      policy.nonce === spec.nonce &&
      policy.model === spec.model &&
      typeof effects?.persist === "function" &&
      typeof platformOwner?.launch === "function" &&
      typeof execute === "function",
  );
  const configurationSha256 = observationDigest({
    specificationSha256: invocation.specificationSha256,
    policy,
  });
  const record = {
    schemaVersion: 1,
    candidateSha: spec.candidateSha,
    nonce: spec.nonce,
    configurationSha256,
    status: "BLOCKED",
    phase: "inputs",
    reservation: "RETAINED",
    missingInputs: [],
    roles: [],
  };
  for (const key of [
    "review",
    "admitTransport",
    "verifyTransport",
    "controls",
    "closeTransport",
    "retire",
    "verifySettlement",
  ])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("provider-transport-" + key);
  if (typeof platformOwner.assertTransport !== "function")
    record.missingInputs.push("provider-platform-transport");
  let persistence = Promise.resolve();
  const save = () => {
    const snapshot = structuredClone(record),
      write = () => effects.persist(snapshot);
    // Preserve receipt order even when an older write outlives its deadline.
    persistence = persistence.then(write, write);
    return persistence;
  };
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  const controller = new AbortController(),
    started = now();
  let active = true,
    custody,
    provider,
    failed = false,
    preparation = "open",
    rejectDeadline;
  const pending = new Set();
  const deadline = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  deadline.catch(() => {});
  const timer = schedule(() => {
    active = false;
    controller.abort();
    rejectDeadline(new Error("Provider transport deadline"));
  }, PROVIDER_LIMITS.sessionMs);
  const guard = () =>
    requireObservation(
      active &&
        !controller.signal.aborted &&
        now() - started >= 0 &&
        now() - started < PROVIDER_LIMITS.sessionMs,
    );
  const call = async (fn, ...args) => {
    guard();
    const work = Promise.resolve().then(() => {
      guard();
      return fn(...args, { signal: controller.signal });
    });
    pending.add(work);
    work.then(
      () => pending.delete(work),
      () => pending.delete(work),
    );
    const result = await Promise.race([work, deadline]);
    guard();
    return result;
  };
  const matches = (receipt) =>
    requireObservation(
      receipt?.independent === true &&
        receipt.candidateSha === spec.candidateSha &&
        receipt.nonce === spec.nonce &&
        receipt.configurationSha256 === configurationSha256,
    );
  const prepare = async (domain) => {
    try {
      guard();
      requireObservation(preparation === "open");
      preparation = "pending";
      record.phase = "bridge-admission-possible";
      await call(save);
      const bridge = await call(
        effects.admitTransport.bind(effects),
        "bridge",
        { spec, invocation, policy, configurationSha256, domain },
        custody,
      );
      matches(bridge);
      requireObservation(
        bridge.role === "bridge" &&
          bridge.admitted === true &&
          bridge.receiptVerified === true,
      );
      const verified = structuredClone(
        await call(
          effects.verifyTransport.bind(effects),
          { spec, domain, configurationSha256 },
          custody,
          bridge,
        ),
      );
      matches(verified);
      requireObservation(
        verified.packageSha256 === spec.closureSha256 &&
          verified.profile === spec.profile &&
          verified.endpoint === spec.endpoint,
      );
      for (const key of [
        "relayAdmitted",
        "bridgeAdmitted",
        "receiptsVerified",
        "privatePipes",
        "credentialCustodyProtected",
        "providerHasNoCredential",
        "environmentAllowlist",
        "handleAllowlist",
        "endpointExclusive",
        "receivingPrincipalVerified",
        "noInspection",
        "noDebug",
        "noSignalling",
        "noFilesystemAccess",
        "ownedChangesOnly",
      ])
        requireObservation(verified[key] === true);
      requireObservation(
        typeof verified.nativeSha256 === "string" &&
          /^[a-f0-9]{64}$/u.test(verified.nativeSha256),
      );
      platformOwner.assertTransport(verified);
      record.roles.push({ role: "bridge", sha256: verified.nativeSha256 });
      record.phase = "positive-controls";
      await call(save);
      const controls = structuredClone(
        await call(
          effects.controls.bind(effects),
          { spec, domain, configurationSha256 },
          custody,
          bridge,
        ),
      );
      matches(controls);
      observationObject(controls.cases, CONTROLS);
      for (const id of CONTROLS) {
        const item = controls.cases[id];
        requireObservation(
          item?.attempted === true &&
            item.acknowledged === true &&
            item.independent === true &&
            item.expectedEffect === true &&
            item.sentinelsUnchanged === true &&
            /^[a-f0-9]{64}$/u.test(item.nativeSha256),
        );
      }
      // Loss controls use separately admitted sacrificial domains; this exact
      // transport must be freshly reverified before provider release.
      const fresh = structuredClone(
        await call(
          effects.verifyTransport.bind(effects),
          { spec, domain, configurationSha256 },
          custody,
          bridge,
        ),
      );
      requireObservation(
        observationDigest(fresh) === observationDigest(verified),
      );
      record.controlsSha256 = observationDigest(controls);
      record.transportSha256 = observationDigest(fresh);
      record.phase = "transport-ready";
      await call(save);
      preparation = "complete";
    } catch (error) {
      failed = true;
      preparation = "failed";
      throw error;
    }
  };
  try {
    const reviewed = structuredClone(
      await call(effects.review.bind(effects), {
        spec,
        invocation,
        policy,
        configurationSha256,
      }),
    );
    matches(reviewed);
    requireObservation(
      reviewed.status === "MATCHED" &&
        reviewed.packageSha256 === spec.closureSha256,
    );
    record.status = "RUNNING";
    record.phase = "relay-admission-possible";
    await call(save);
    custody = await call(effects.admitTransport.bind(effects), "relay", {
      spec,
      invocation,
      policy,
      configurationSha256,
    });
    matches(custody);
    requireObservation(
      custody.role === "relay" &&
        custody.admitted === true &&
        custody.receiptVerified === true &&
        /^[a-f0-9]{64}$/u.test(custody.nativeSha256),
    );
    record.roles.push({ role: "relay", sha256: custody.nativeSha256 });
    record.phase = "provider-admission-possible";
    await call(save);
    provider = await call(
      platformOwner.launch.bind(platformOwner),
      spec,
      invocation,
      prepare,
      controller.signal,
    );
    requireObservation(
      preparation === "complete" &&
        !failed &&
        record.phase === "transport-ready" &&
        provider?.record?.status === "ADMITTED",
    );
    record.phase = "provider-running";
    await call(save);
    const observed = structuredClone(await call(execute, provider.transport));
    matches(observed);
    requireObservation(
      observed.attempted === true &&
        observed.transportObserved === true &&
        /^[a-f0-9]{64}$/u.test(observed.nativeSha256),
    );
    record.observationSha256 = observationDigest(observed);
    record.status = "TRANSPORT_OBSERVED";
  } catch {
    failed = true;
    record.status = "FAIL";
  } finally {
    active = false;
    controller.abort();
    cancel(timer);
    record.phase = "retirement-possible";
    const cleanup = new AbortController();
    let rejectCleanup;
    const cleanupDeadline = new Promise((_, reject) => {
      rejectCleanup = reject;
    });
    cleanupDeadline.catch(() => {});
    const cleanupTimer = schedule(() => {
      cleanup.abort();
      rejectCleanup(new Error("Transport retirement deadline"));
    }, 30000);
    const settle = (fn, ...args) =>
      Promise.race([
        Promise.resolve().then(() => {
          requireObservation(!cleanup.signal.aborted);
          return fn(...args, { signal: cleanup.signal });
        }),
        cleanupDeadline,
      ]);
    try {
      try {
        await settle(save);
      } catch {
        failed = true;
      }
      // Closing a failed capability must not suppress the separate retirement
      // attempt. No timed-out controller may later release an admitted payload.
      try {
        await settle(effects.closeTransport.bind(effects), custody);
      } catch {
        failed = true;
      }
      try {
        provider?.transport?.close?.();
      } catch {
        failed = true;
      }
      const retirement = structuredClone(
        await settle(
          effects.retire.bind(effects),
          { spec, configurationSha256 },
          custody,
          provider?.record ?? null,
        ),
      );
      matches(retirement);
      requireObservation(
        retirement.payloadsRetired === true &&
          retirement.relayRetired === true &&
          retirement.bridgeRetired === true &&
          pending.size === 0,
      );
      const settled = structuredClone(
        await settle(
          effects.verifySettlement.bind(effects),
          { spec, configurationSha256 },
          retirement,
        ),
      );
      matches(settled);
      requireObservation(
        settled.ownedChangesOnly === true &&
          settled.restored === true &&
          settled.reservation === "RETAINED" &&
          /^[a-f0-9]{64}$/u.test(settled.nativeSha256),
      );
      record.phase = "settled";
      record.settlementSha256 = observationDigest(settled);
    } catch {
      failed = true;
      record.phase = "retained";
    }
    if (cleanup.signal.aborted) {
      failed = true;
      record.phase = "retained";
    }
    if (failed) record.status = "FAIL";
    // Enqueue the terminal receipt even after expiry. This is metadata only:
    // no late write can grant authority or release the retained reservation.
    try {
      await Promise.race([save(), cleanupDeadline]);
    } catch {
      record.status = "FAIL";
      record.phase = "retained";
      save().catch(() => {});
    } finally {
      cleanup.abort();
      cancel(cleanupTimer);
    }
  }
  return record;
}
