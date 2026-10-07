import {
  observationDigest,
  observationObject,
  assertNativePolicyParameters,
  requireObservation,
  verifyNativePolicy,
} from "../index.js";
import {
  digest,
  normalizeWindowsLaunch,
  sameWindowsIdentity,
  systemIdentity,
  windowsLaunchDigest,
  WINDOWS_LITERAL_ARGUMENTS,
} from "./protocol.js";
import { WINDOWS_OWNERSHIP_CASES } from "./ownership.js";
import { assessWindowsDomain } from "./recovery.js";
import { retireWindowsOwnership } from "./retirement.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const literal = (id) => ["ownership.literal", "ownership.storage"].includes(id);
const early = new Set([
  "admission-interruption",
  "receipt-before",
  "receipt-after",
]);
const denials = new Set([
  "breakaway",
  "spoofed-parent",
  "wmi",
  "com",
  "service",
]);

export function windowsOwnershipArguments(id, request) {
  if (literal(id)) return [...WINDOWS_LITERAL_ARGUMENTS];
  requireObservation(
    id.startsWith("ownership.") &&
      WINDOWS_OWNERSHIP_CASES.includes(id.slice(10)),
  );
  return [id.slice(10), request.nonce];
}

// Only case-private objects change. Neither this policy nor its hash approves
// stock-host changes, a provider, a network endpoint or an additional principal.
export function windowsOwnershipParameters(actual) {
  return {
    kind: "windows-ownership",
    accountSid: actual.accountSid,
    restrictingSid: actual.restrictingSid,
    objects: actual.objects.map(({ object }, i) => ({
      identitySha256: observationDigest(object.identity),
      mask: [0, 0, 0x120020, 0x12019f, 0, 0x1200a9][i],
    })),
    processLimit: 32,
    network: "deny-all",
  };
}

/** Private fixed ownership composition. Replaceable inputs stop at framed
 * filesystem/IPC reads; admission, approval and settlement remain owned here. */
export function createWindowsCaseEffects(state, current, save) {
  const { reader, recipe, binding, provisioned } = current,
    bootstrap = normalizeWindowsLaunch(current.input.request ?? current.input),
    args = windowsOwnershipArguments(recipe.id, bootstrap),
    mode = recipe.id.slice(10),
    parameters = windowsOwnershipParameters(provisioned.actual),
    expected = assertNativePolicyParameters(
      binding,
      provisioned.provisioning,
      { request: bootstrap, ...parameters },
      args,
    ),
    bytes = Buffer.from(JSON.stringify(expected.policy) + "\n"),
    request = {
      ...bootstrap,
      policy: { ...bootstrap.policy, sha256: digest(bytes) },
      bindings: {
        ...bootstrap.bindings,
        policy: expected.expectedPolicySha256,
      },
    },
    requestSha256 = windowsLaunchDigest(request, args);
  let admitted,
    pin,
    receiptIndex = 0,
    outside,
    retirement,
    fault,
    failure;
  const known = [],
    witnesses = new Set();
  const persist = async (kind, record) => {
    const data = Buffer.from(JSON.stringify(record) + "\n"),
      value = { index: receiptIndex++, sha256: digest(data) };
    await save(recipe.id, {
      phase: "ownership-receipt-possible",
      kind,
      pin: value,
    });
    requireObservation(
      (await reader.ownershipReceipt(value.index, value.sha256, data)).equals(
        data,
      ),
    );
    await save(recipe.id, { phase: "ownership-receipt", kind, pin: value });
    if (kind === "admission") pin = value;
    return value;
  };
  const checked =
    (operation) =>
    async (...values) => {
      if (failure) throw failure;
      try {
        state.guard(current.signal);
        const result = await operation(...values);
        state.guard(current.signal);
        return result;
      } catch (cause) {
        throw (failure ??= cause);
      }
    };
  const witness = async () => {
    const result = await reader.ownershipWitness(),
      verifier = systemIdentity(result.verifier);
    requireObservation(
      result.imageSha256 === current.declared.custody.reader.sha256 &&
        result.settled === true &&
        verifier.pid !== current.admission.helper.pid &&
        verifier.pid !== current.admission.verifier.pid &&
        !admitted?.helpers.some(
          ({ identity }) => identity.pid === verifier.pid,
        ) &&
        !known.some(({ pid }) => pid === verifier.pid) &&
        !witnesses.has(verifier.pid),
    );
    witnesses.add(verifier.pid);
    requireObservation(
      result.accountSid === parameters.accountSid &&
        result.restrictingSid === parameters.restrictingSid &&
        result.contextSha256 === observationDigest(binding.context),
    );
    requireObservation(same(result.accountToken, provisioned.native.token));
    if (admitted)
      requireObservation(
        result.jobObjectSha256 === admitted.setup.job.heldObjectSha256 &&
          ["launcher", "custodian"].every((role) =>
            sameWindowsIdentity(
              result.helpers.find((helper) => helper.role === role)?.identity,
              admitted.helpers.find((helper) => helper.role === role).identity,
            ),
          ),
      );
    const members = assessWindowsDomain(
      {
        ...result.enumeration,
        nativeEventSha256: observationDigest(result.enumeration),
      },
      parameters.accountSid,
      result.jobObjectSha256,
      !result.jobAbsent,
    );
    for (const { identity } of members)
      if (!known.some((held) => sameWindowsIdentity(held, identity)))
        known.push(identity);
    requireObservation(
      known.length <= 32 &&
        known.every((held) =>
          members.some(({ identity }) => sameWindowsIdentity(held, identity)),
        ),
    );
    if (!result.jobAbsent)
      requireObservation(
        result.job.limitFlags === 0x2008 &&
          result.job.processLimit === 32 &&
          result.job.uiRestrictions === 255,
      );
    requireObservation(result.tokens.length === members.length);
    for (const token of result.tokens)
      requireObservation(
        token.userSid === parameters.accountSid &&
          token.primary === true &&
          token.sessionId === 0 &&
          token.integritySid === "S-1-16-4096" &&
          token.virtualized === false &&
          token.writeRestricted === false &&
          same(token.restrictedSids, [parameters.restrictingSid]) &&
          token.enabledGroups.length === 0 &&
          token.privileges.length === 0,
      );
    return result;
  };
  const unchanged = async () => {
    const actual = await reader.ownershipOutside();
    requireObservation(outside && same(actual, outside));
    return actual;
  };
  const policyProof = (native) => {
    requireObservation(
      native.policyVerified === true &&
        same(native.objects, parameters.objects),
    );
    const observed = {
      schemaVersion: 1,
      context: binding.context,
      templateSha256: expected.templateSha256,
      provisioningSha256: expected.provisioningSha256,
      requestSha256,
      policySha256: expected.expectedPolicySha256,
      policy: expected.policy,
      held: true,
      complete: true,
      independent: true,
      verifierSha256: observationDigest(native.verifier),
      nativeEventSha256: observationDigest(native),
    };
    verifyNativePolicy(
      binding.template,
      binding.approval,
      provisioned.provisioning,
      binding.context,
      requestSha256,
      observed,
    );
    const proof = {
      provisioning: provisioned.provisioning,
      requestSha256,
      observed,
    };
    current.policyProof = proof;
    return proof;
  };
  const control = async (phase) => {
    const value = await reader.ownershipControl();
    observationObject(value, [
      "nonce",
      "phase",
      "helper",
      "payload",
      "accountSid",
    ]);
    requireObservation(
      value.nonce === request.nonce &&
        value.phase === phase &&
        sameWindowsIdentity(value.helper, admitted.helpers[0].identity) &&
        (phase !== "ready" || value.accountSid === parameters.accountSid),
    );
    return value;
  };
  const recoverReceipt = async () => {
    requireObservation(pin);
    const data = await reader.ownershipReceipt(pin.index, pin.sha256),
      value = JSON.parse(data);
    requireObservation(
      data.equals(Buffer.from(JSON.stringify(value) + "\n")) &&
        value.candidateSha === request.candidateSha &&
        value.nonce === request.nonce &&
        value.requestSha256 === requestSha256 &&
        value.admission === "possible",
    );
    return value;
  };
  const retire = async () => {
    if (retirement) return structuredClone(retirement);
    const record = await recoverReceipt();
    const held = await reader.reconstructOwnership();
    requireObservation(
      sameWindowsIdentity(held.helper, record.helpers[0].identity),
    );
    if (record.setup.job.heldObjectSha256 !== null)
      requireObservation(
        record.setup.job.heldObjectSha256 === held.jobObjectSha256,
      );
    record.setup.job.heldObjectSha256 = held.jobObjectSha256;
    if (record.payload)
      requireObservation(
        held.members.some((member) =>
          sameWindowsIdentity(member, record.payload),
        ),
      );
    record.payload ??= held.members[0] ?? null;
    await persist("admission", record);
    retirement = await retireWindowsOwnership(request, requestSha256, record, {
      persist: (record) => persist("retirement", record),
      fence: () => reader.ownershipStop(),
      snapshot: witness,
      outside: unchanged,
    });
    return structuredClone(retirement);
  };
  const admit = checked(async () => {
    requireObservation(!admitted);
    const before = await witness(),
      { helper, owner } = await reader.startOwnership(args);
    admitted = {
      schemaVersion: 1,
      candidateSha: request.candidateSha,
      nonce: request.nonce,
      requestSha256,
      request,
      arguments: args,
      admission: "possible",
      status: "RUNNING",
      reservation: "RETAINED",
      accountSid: parameters.accountSid,
      setup: {
        account: { sid: parameters.accountSid },
        job: { heldObjectSha256: before.jobObjectSha256 },
      },
      helpers: [
        { role: "launcher", identity: helper },
        { role: "custodian", identity: owner },
      ],
      payload: null,
    };
    await persist("admission", admitted);
    await control("helper");
    await reader.sendOwnership("P");
    await control("setup");
    await reader.installOwnershipPolicy(bytes);
    const installed = await witness();
    await persist("policy", policyProof(installed));
    admitted.setup.job.heldObjectSha256 = installed.jobObjectSha256;
    await reader.sendOwnership("C" + request.policy.sha256 + "\n");
    const ready = await control("ready");
    admitted.payload = ready.payload;
    await reader.retainOwnershipChildren([admitted.payload]);
    const parked = await witness();
    await persist("policy", policyProof(parked));
    requireObservation(
      parked.enumeration.processes.some((entry) =>
        sameWindowsIdentity(entry.identity, admitted.payload),
      ) &&
        parked.payloadSuspended === true &&
        parked.explicitHandles === true &&
        parked.creationTimeJob === true &&
        parked.payloadImageSha256 === request.executable.sha256,
    );
    admitted.authority = { cwdIdentity: parked.cwdIdentity };
    if (mode !== "receipt-before") await persist("admission", admitted);
    // Early cases stop at the native R barrier; fixture bytes cannot substitute
    // for proof that the payload was never resumed.
    if (!early.has(mode)) {
      await reader.sendOwnership("R");
      if (!literal(recipe.id)) await reader.sendOwnership("G");
      admitted.status = "ADMITTED";
    }
    const verifier = systemIdentity(parked.verifier);
    admitted.helpers.push({ role: "verifier", identity: verifier });
    if (mode !== "receipt-before") await persist("admission", admitted);
    return structuredClone(admitted);
  });
  return {
    async prepare() {
      requireObservation(
        recipe.group === "ownership" &&
          request.schemaVersion === 3 &&
          request.bindings.source === binding.template.sourceReviewSha256 &&
          state.manifest.helpers.find(({ name }) => name === "launcher")
            ?.sha256 === request.launcher.sha256 &&
          state.manifest.helpers.find(
            ({ name }) =>
              name ===
              (literal(recipe.id) ? "argv-fixture" : "ownership-fixture"),
          )?.sha256 === request.executable.sha256,
      );
      outside = await reader.ownershipOutside();
      await save(recipe.id, { phase: "ownership-outside", snapshot: outside });
      // Preparation records an approved, complete plan; an installed policy
      // receipt is recorded only after the native setup barrier below.
      current.input = request;
      current.ownership = this;
      return expected;
    },
    persist: (record) => persist("owner", record),
    admit,
    async admitLiteral(recordPolicy) {
      const record = await admit(),
        native = await witness();
      record.helpers.push({ role: "verifier", identity: native.verifier });
      await recordPolicy(policyProof(native));
      return { record };
    },
    verifyComposition: checked(async () => {
      const native = await witness();
      requireObservation(
        native.sourceVerified === true &&
          native.sdkExportsVerified === true &&
          native.creatorAccessDenied === true &&
          native.noForeignHandles === true,
      );
      return {
        independent: true,
        verifier: native.verifier,
        sourceSha256: request.bindings.source,
        policySha256: request.bindings.policy,
        nativeEventSha256: observationDigest(native),
        sdkExportsVerified: true,
        immutableRestrictedToken: true,
        creationTimeJob: true,
        noBreakaway: true,
        nestedJobsContained: true,
        parentObjectAccessDenied: true,
        hostServicesDenied: true,
        noDelegation: true,
        jobDaclProtected: true,
        receiptDaclProtected: true,
        noForeignHandles: true,
        processLimit: 32,
      };
    }),
    observe: checked(async () => {
      let output = Buffer.alloc(0),
        event;
      if (!early.has(mode)) {
        output = await reader.ownershipOutput();
        event = JSON.parse(output);
        requireObservation(
          event.caseId === mode &&
            event.nonce === request.nonce &&
            event.acknowledged === true,
        );
        // Retain every acknowledged child before allowing a reparenting leader
        // to exit, then inspect its token and outer Job independently.
        await reader.retainOwnershipChildren(event.children ?? []);
        if (mode === "process-limit") {
          const denied = JSON.parse(await reader.ownershipOutput());
          requireObservation(
            denied.caseId === mode &&
              denied.nonce === request.nonce &&
              denied.acknowledged === true,
          );
          event.nativeError = denied.nativeError;
        }
        if (mode === "reparent") await reader.sendOwnership("E");
      }
      const native = await witness();
      policyProof(native);
      await unchanged();
      requireObservation(
        native.explicitHandles === true && native.creationTimeJob === true,
      );
      const result = {
        independent: true,
        verifier: native.verifier,
        caseId: mode,
        nonce: request.nonce,
        requestSha256,
        attempted: true,
        complete: true,
        timedOut: false,
        outsideUnchanged: true,
        nativeEventSha256: observationDigest(native),
        bytesSha256: digest(output),
        members: native.enumeration.processes.map(({ identity }) => identity),
      };
      if (["detached", "reparent"].includes(mode))
        Object.assign(result, {
          childAcknowledged: event.children.length > 0,
          creationTimeJobVerified: true,
          inheritedTokenVerified: true,
          creatorSignaled:
            native.enumeration.processes.find(({ identity }) =>
              sameWindowsIdentity(identity, admitted.payload),
            )?.signaled === true,
        });
      if (mode === "nested-job")
        Object.assign(result, {
          outerMembershipVerified: true,
          nestedOutcome: event.nestedOutcome,
        });
      if (denials.has(mode)) {
        const control = await reader.ownershipOutsideControl(mode);
        requireObservation(
          control.ready === true && control.reachable === true,
        );
        await unchanged();
        Object.assign(result, {
          denied: true,
          nativeError: event.nativeError,
          control: {
            ...control,
            operation: mode,
            nativeEventSha256: observationDigest(control),
            protectedBeforeSha256: observationDigest(outside),
            protectedAfterSha256: observationDigest(outside),
          },
        });
      }
      if (mode === "process-limit")
        Object.assign(result, {
          activeProcessLimit: 32,
          creationRejected: true,
          nativeError: event.nativeError,
        });
      if (early.has(mode))
        Object.assign(result, {
          payloadReleased: false,
          receiptBoundary: mode === "receipt-after" ? "after" : "before",
          barrierAcknowledged: native.payloadSuspended === true,
        });
      if (mode === "stale-identity") {
        const stale = {
          ...admitted.payload,
          creationTime: String(BigInt(admitted.payload.creationTime) - 1n),
        };
        const check = await reader.ownershipStale(stale);
        requireObservation(
          check.rejected === true &&
            sameWindowsIdentity(check.current, admitted.payload),
        );
        Object.assign(result, {
          stale,
          current: check.current,
          staleRejected: true,
          forcedPidReuse: false,
        });
      }
      return result;
    }),
    armFault: checked(async () => {
      const native = await reader.armOwnership(mode);
      requireObservation(
        native.armed === true &&
          (early.has(mode) || native.fixtureAcknowledged === true),
      );
      const value = {
        armed: true,
        independent: true,
        caseId: mode,
        point: mode,
        nonce: request.nonce,
        requestSha256,
        ...(mode === "last-handle-close"
          ? {
              jobHandleHeld: false,
              processHandlesVerified: true,
              processHandles: known,
              holderInventoryComplete: native.holderInventoryComplete === true,
            }
          : {}),
      };
      const receipt = await persist("fault", value);
      fault = { ...value, receiptSha256: receipt.sha256 };
      return structuredClone(fault);
    }),
    fireFault: checked(async () => {
      requireObservation(fault);
      const native = await reader.fireOwnership(mode);
      requireObservation(native.acknowledged === true);
      return {
        acknowledged: true,
        caseId: mode,
        nonce: request.nonce,
        faultSha256: fault.receiptSha256,
        nativeEventSha256: observationDigest(native),
      };
    }),
    recoverAndRetire: retire,
    verify: async () => {
      const native = await witness();
      await unchanged();
      requireObservation(
        native.jobAbsent === true &&
          native.jobHolders === 0 &&
          native.launcherSignaled === true &&
          native.ownerSignaled === true &&
          native.ownerJobEmpty === true &&
          native.enumeration.processes.every(({ signaled }) => signaled),
      );
      return {
        independent: true,
        verifier: native.verifier,
        requestSha256,
        nonce: request.nonce,
        helpersSettled: true,
        knownProcessHandlesSignaled: true,
        jobHolders: 0,
        outsideUnchanged: true,
        reservation: "RETAINED",
        nativeEventSha256: observationDigest(native),
        enumeration: {
          ...native.enumeration,
          nativeEventSha256: observationDigest(native.enumeration),
        },
        ...(mode === "last-handle-close"
          ? {
              lastHandleCloseObserved: true,
              jobAbsent: true,
              jobHandleHeld: false,
            }
          : {}),
      };
    },
    async literal(admission) {
      const output = await reader.ownershipOutput(),
        native = await witness();
      requireObservation(
        native.payloadSignaled === true &&
          native.exitCode === 0 &&
          native.payloadImageSha256 === request.executable.sha256,
      );
      await unchanged();
      requireObservation(
        sameWindowsIdentity(
          native.verifier,
          admission.record.helpers.at(-1).identity,
        ) === false,
      );
      admission.record.helpers.push({
        role: "verifier",
        identity: native.verifier,
      });
      return {
        independent: true,
        verifier: native.verifier,
        requestSha256,
        payload: admitted.payload,
        cwdIdentity: admitted.authority.cwdIdentity,
        imageSha256: native.payloadImageSha256,
        output: output.toString("utf8"),
        exitCode: native.exitCode,
        timedOut: false,
        complete: true,
        nativeEventSha256: observationDigest(native),
      };
    },
    async finish({ signal }) {
      await reader.beginCleanup({ signal });
      const payload = await retire();
      await unchanged();
      policyProof(await witness());
      await reader.restoreOwnershipPolicy();
      const restored = await witness();
      requireObservation(
        restored.policyRestored === true && restored.policyVerified === false,
      );
      await unchanged();
      const account = await reader.retireOwnershipAccount(),
        custody = await reader.close();
      requireObservation(
        [account, custody].every(
          (result) =>
            result.status === "RETIRED" &&
            result.independent === true &&
            !result.emergencyCleanup,
        ),
      );
      const result = {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({
          payload,
          restored,
          account,
          custody,
        }),
      };
      await save(recipe.id, { phase: "ownership-retired", settlement: result });
      current.retired = true;
      return result;
    },
    request,
    get policyProof() {
      return current.policyProof;
    },
  };
}
