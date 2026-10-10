import {
  assertNativePolicyParameters,
  observationDigest,
  observationObject,
  requireObservation,
  verifyNativePolicy,
} from "../index.js";
import {
  digest,
  sameWindowsIdentity,
  systemIdentity,
  windowsLaunchDigest,
} from "./protocol.js";
import { buildWindowsPolicy } from "./policy.js";
import {
  assertWindowsPolicyInstallation,
  assertWindowsPolicySnapshot,
} from "./policy-effects.js";
import { windowsAccessArguments } from "./case-effects.js";
import {
  createWindowsAuditCustody,
  createWindowsAuditDecoder,
  createWindowsSecurityCapture,
} from "./audit.js";
import { windowsObserverConfiguration } from "./observer.js";
import { collectWindowsAccess } from "./access-observation.js";
import { expectedAces } from "./effective-protocol.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);

/** Default fixed access composition. Replaceable inputs end at filesystem and
 * native pipe transport. Reviews are pinned data; all admission and cleanup
 * operations remain repository owned. */
export function createWindowsAccessEffects(state, current, save, recordPolicy) {
  const { reader, recipe, binding, provisioned, accessReaders } = current,
    plan = buildWindowsPolicy(current.input),
    request = plan.value.request,
    args = windowsAccessArguments(request),
    requestSha256 = windowsLaunchDigest(request, args),
    expected = assertNativePolicyParameters(
      binding,
      provisioned.provisioning,
      plan.value,
      args,
    ),
    approval = provisioned.access,
    source = (name) =>
      state.plan.sources.find((entry) => entry.name === name + ".c"),
    image = (name) =>
      state.manifest.helpers.find((entry) => entry.name === name),
    receipts = new Map();
  let receiptIndex = 0,
    installation,
    admission,
    payloadSlot,
    jobSlot,
    capture,
    channel,
    audit,
    policyHelper,
    policySettlement,
    retirement,
    firstCause,
    fault,
    controls,
    peers,
    auditInput,
    policyPossible = false;
  const persist = async (record) => {
    const bytes = Buffer.from(JSON.stringify(record) + "\n"),
      parts = [];
    requireObservation(bytes.length > 0 && bytes.length <= 262144);
    // ownershipReceipt persists each exact part/manifest command before its
    // native write. Repeating a digest-only intent adds no recovery authority.
    for (let offset = 0; offset < bytes.length; offset += 16384) {
      const part = bytes.subarray(offset, offset + 16384),
        pin = { index: receiptIndex++, sha256: digest(part) };
      requireObservation(
        (await reader.ownershipReceipt(pin.index, pin.sha256, part)).equals(
          part,
        ),
      );
      parts.push(pin);
    }
    const manifest = Buffer.from(
        JSON.stringify({ contentSha256: digest(bytes), parts }) + "\n",
      ),
      pin = { index: receiptIndex++, sha256: digest(manifest) };
    requireObservation(
      (await reader.ownershipReceipt(pin.index, pin.sha256, manifest)).equals(
        manifest,
      ),
    );
    receipts.set(digest(bytes), { pin, parts, bytes });
    await save(recipe.id, {
      phase: "access-receipt",
      contentSha256: digest(bytes),
      pin,
      parts,
    });
    return pin;
  };
  const verifyReceipt = async (record) => {
    const bytes = Buffer.from(JSON.stringify(record) + "\n"),
      held = receipts.get(digest(bytes));
    requireObservation(held);
    const manifest = await reader.readAccessReceipt(
        held.pin.index,
        held.pin.sha256,
      ),
      parts = [];
    requireObservation(
      same(JSON.parse(manifest), {
        contentSha256: digest(bytes),
        parts: held.parts,
      }),
    );
    for (const pin of held.parts)
      parts.push(await reader.readAccessReceipt(pin.index, pin.sha256));
    requireObservation(Buffer.concat(parts).equals(bytes));
    return {
      independent: true,
      immutable: true,
      verifier: current.admission.verifier,
      sha256: held.pin.sha256,
      contentSha256: digest(bytes),
    };
  };
  const guarded =
    (body) =>
    async (...values) => {
      if (firstCause) throw firstCause;
      try {
        requireObservation(!current.admissionsClosed);
        state.guard(current.signal);
        const result = await body(...values);
        requireObservation(!current.admissionsClosed);
        state.guard(current.signal);
        return result;
      } catch (error) {
        throw (firstCause ??= error);
      }
    };
  const tracked =
    (body) =>
    async (...values) => {
      try {
        return await body(...values);
      } catch (error) {
        firstCause ??= error;
        throw error;
      }
    };
  const witness = async () => {
    const observed = await reader.ownershipWitness();
    requireObservation(
      observed.settled &&
        observed.sourceVerified &&
        observed.sdkExportsVerified &&
        observed.creatorAccessDenied &&
        observed.noForeignHandles &&
        observed.accountSid === plan.value.accountSid &&
        observed.restrictingSid === request.restrictingSid &&
        observed.contextSha256 === observationDigest(binding.context),
    );
    return observed;
  };
  const snapshot = async () => {
    requireObservation(payloadSlot !== undefined);
    const transfer = { subject: payloadSlot, objects: provisioned.accessSlots };
    return retirement
      ? current.readers.retiredPolicySnapshot(plan.value, transfer, [jobSlot])
      : current.readers.policySnapshot(plan.value, transfer);
  };
  const nativePolicy = async (_request, record) => {
    // The policy owner has just validated this independent parked snapshot.
    // Admission performs the next fresh complete read immediately before R.
    const effective = record.effective;
    assertWindowsPolicySnapshot(effective, plan.value);
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
      verifierSha256: observationDigest(effective.verifier),
      nativeEventSha256: effective.nativeEventSha256,
    };
    verifyNativePolicy(
      binding.template,
      binding.approval,
      provisioned.provisioning,
      binding.context,
      requestSha256,
      observed,
    );
    current.policyProof = {
      provisioning: provisioned.provisioning,
      requestSha256,
      observed,
    };
    return observed;
  };
  const controlFrame = async (phase) => {
    const frame = await reader.ownershipControl();
    observationObject(frame, [
      "nonce",
      "phase",
      "helper",
      "payload",
      "accountSid",
    ]);
    requireObservation(
      frame.phase === phase &&
        frame.nonce === request.nonce &&
        sameWindowsIdentity(frame.helper, admission.helpers[0].identity),
    );
    return frame;
  };
  const auditProof = async (value) => {
    const proof = await accessReaders.read();
    requireObservation(
      value.input.domain.accountSid === plan.value.accountSid &&
        same(value.input.pins, approval.audit.pins) &&
        value.input.pins.imageSha256 === image("observer-helper").sha256 &&
        value.input.pins.sourceSha256 === source("observer-helper").sha256,
    );
    return {
      independent: true,
      candidateSha: request.candidateSha,
      nonce: request.nonce,
      configurationSha256: observationDigest(value.configuration),
      beforeSha256: value.before.sha256,
      ownedObjectsVerified: true,
      exclusiveWriter: true,
      admissionsClosed: true,
      ...value.input.pins,
      verifier: proof.verifier,
      nativeEventSha256: proof.nativeEventSha256,
    };
  };
  const auditRetirement = async (value) => {
    const proof = await current.readers.retirement([payloadSlot], [jobSlot]);
    return {
      ...proof,
      domainSha256: auditInput.plan.domainSha256,
      exclusiveWriter: true,
      admissionsClosed: true,
      installedSha256: value.installed.sha256,
      currentSha256: value.current.sha256,
    };
  };
  const policyMutation = async (_plan, operation, admitHelper) => {
    policyHelper = await current.owners.policyTransport(plan.value, operation);
    await admitHelper({
      identity: policyHelper.identity,
      imageSha256: image("policy-helper").sha256,
      sourceSha256: source("policy-helper").sha256,
    });
    const before = await policyHelper.receive();
    requireObservation(
      before.nonce === request.nonce &&
        before.phase === "before-write" &&
        before.pid === policyHelper.identity.pid &&
        before.filters === 0,
    );
    await policyHelper.send(operation === "install" ? "I" : "D");
    const installed = await policyHelper.receive();
    requireObservation(
      installed.nonce === request.nonce &&
        installed.pid === policyHelper.identity.pid &&
        installed.phase ===
          (operation === "install" ? "installed" : "removed") &&
        installed.filters === plan.manifest.filters.length,
    );
    if (operation === "install") await reader.verifyAccessFilters(plan.value);
    await policyHelper.send("V");
    const settled = await policyHelper.receive();
    requireObservation(
      settled.nonce === request.nonce &&
        settled.phase === "settled" &&
        settled.pid === policyHelper.identity.pid,
    );
    await policyHelper.closeInput();
    policySettlement = await policyHelper.close();
    requireObservation(
      policySettlement.drained &&
        policySettlement.closed &&
        policySettlement.exitCode === 0,
    );
    if (operation === "install") {
      // Both effective barriers precede release: every BFE descriptor is read
      // before C, and complete token/object/BFE custody is reread at parked R.
      const actual = (await accessReaders.read()).actual;
      requireObservation(
        actual.registryPresent && actual.ownedWfp.filters.every(Boolean),
      );
      actual.objects.forEach((object, i) =>
        requireObservation(
          same(
            object.security.aces,
            expectedAces(
              plan.manifest.objects.filter(({ name }) => name !== "registry")[
                i
              ],
            ),
          ),
        ),
      );
      accessReaders.rememberInstalled(actual);
      await reader.acknowledgeAccessPolicy(Buffer.from(plan.bytes));
      await reader.sendOwnership("C" + plan.policySha256 + "\n");
      const ready = await controlFrame("ready");
      admission.payload = ready.payload;
      await reader.retainOwnershipChildren([ready.payload]);
      payloadSlot = (await reader.retainProcess(ready.payload)).slot;
      const job = await reader.job();
      jobSlot = job.slot;
      admission.setup.job.heldObjectSha256 = (await witness()).jobObjectSha256;
      const parked = await witness();
      requireObservation(
        parked.payloadSuspended &&
          parked.explicitHandles &&
          parked.creationTimeJob &&
          parked.payloadImageSha256 === request.executable.sha256,
      );
      await persist(admission);
    }
  };
  const retire = async () => {
    if (retirement) return structuredClone(retirement);
    await persist({ phase: "access-retirement-possible", admission });
    await reader.retireAccessControls();
    const stopped = await reader.ownershipStop(),
      native = await witness();
    requireObservation(
      stopped.creationSealed &&
        stopped.helpersSettled &&
        native.launcherSignaled &&
        native.ownerSignaled &&
        native.ownerJobEmpty &&
        native.enumeration.processes.every(({ signaled }) => signaled),
    );
    if (peers)
      requireObservation(
        (await reader.verifyAccessPeerRetirement(peers.otherPeer)).status ===
          "RETIRED",
      );
    await reader.drainAccessControls();
    const proof =
      payloadSlot === undefined
        ? await accessReaders.retirement({ context: binding.context })
        : await current.readers.retirement([payloadSlot], [jobSlot]);
    retirement = {
      schemaVersion: 1,
      ...proof,
      requestSha256,
      accountSid: plan.value.accountSid,
      jobObjectSha256: admission.setup.job.heldObjectSha256,
      reservation: "RETAINED",
      members: native.enumeration.processes.map(({ identity }) => identity),
      helpers: admission.helpers,
      helpersSettled: true,
      freshVerifier: proof.verifier,
      ...(auditInput ? { domainSha256: auditInput.plan.domainSha256 } : {}),
    };
    await persist(retirement);
    current.payloadRetirement = retirement;
    return structuredClone(retirement);
  };
  const owner = {
    get cause() {
      return firstCause;
    },
    persist,
    snapshot: guarded(snapshot),
    prepare: guarded(async () => {
      requireObservation(
        !admission &&
          request.executable.sha256 === image("access-fixture").sha256 &&
          request.launcher.sha256 === image("launcher").sha256,
      );
      const native = await witness(),
        started = await reader.startOwnership(args);
      admission = {
        schemaVersion: 1,
        status: "RUNNING",
        admission: "possible",
        reservation: "RETAINED",
        candidateSha: request.candidateSha,
        nonce: request.nonce,
        requestSha256,
        request,
        arguments: args,
        accountSid: plan.value.accountSid,
        payload: null,
        setup: {
          account: { sid: plan.value.accountSid },
          job: { heldObjectSha256: native.jobObjectSha256 },
        },
        helpers: [
          { role: "launcher", identity: started.helper, settled: false },
          { role: "custodian", identity: started.owner, settled: false },
        ],
      };
      await persist(admission);
      await controlFrame("helper");
      await reader.sendOwnership("P");
      await controlFrame("setup");
      policyPossible = true;
      await reader.beginAccessPolicy(plan.value.profile);
      installation = await current.owners.policy({
        persist,
        review: async (_value, approvedSha256) => {
          const actual = await witness();
          return {
            approvedSha256,
            localSystemSession0: true,
            helperImageSha256: image("policy-helper").sha256,
            helperSourceSha256: source("policy-helper").sha256,
            sdkExportsVerified: actual.sdkExportsVerified,
            loaderClosureVerified:
              approval.sourceFacts.noUnreviewedLoaderExceptions,
            completeCompositionReviewed: true,
          };
        },
        snapshot: tracked((_value, operation) =>
          operation === "install" ? accessReaders.baseline() : snapshot(),
        ),
        mutate: tracked(policyMutation),
        verifySettlement: async (helpers) => ({
          ...policySettlement,
          signaled: true,
          timedOut: false,
          helper: helpers[0].identity,
        }),
        verifyReceipt: tracked(verifyReceipt),
        readPolicy: tracked(nativePolicy),
      });
      if (firstCause) throw firstCause;
      assertWindowsPolicyInstallation(installation, plan.value);
      admission.policyReceiptSha256 = installation.receiptSha256;
      admission.helpers.push(
        ...installation.helpers.map((helper) => ({ ...helper, role: "wfp" })),
      );
      await recordPolicy(current.policyProof);
      const job = await reader.inspectJob(jobSlot),
        domain = {
          accountSid: plan.value.accountSid,
          restrictingSid: request.restrictingSid,
          jobSha256: observationDigest(job),
        };
      // Capture selectors cover the complete installed filter inventory. The
      // source-reviewed mapping/ABI remains independent of observed filter IDs.
      const routes = [],
        bindings = [],
        filters = installation.effective.wfp.filters;
      for (let i = 0; i < Math.ceil(filters.length / 3); i++) {
        const id = "access-" + i,
          hashes = [0, 1, 2].map((n) =>
            observationDigest(filters[(i * 3 + n) % filters.length].descriptor),
          );
        routes.push({
          id,
          operation: "command",
          targetSha256: hashes[2],
          permitTargetSha256: hashes[0],
          denyTargetSha256: hashes[1],
          nonceSha256: digest(request.nonce),
          beforeSha256: digest(request.nonce),
          afterSha256: digest(request.nonce),
          outcome: "deny",
        });
        for (const [n, phase] of [
          "control-permit",
          "control-deny",
          "tool",
        ].entries())
          bindings.push({
            routeId: id,
            phase,
            selector: filters[(i * 3 + n) % filters.length].descriptor.key,
            opcode: "5157",
            accessMask: null,
            filterId: filters[(i * 3 + n) % filters.length].id,
          });
      }
      auditInput = {
        plan: {
          schemaVersion: 1,
          candidateSha: request.candidateSha,
          nonce: request.nonce,
          domainSha256: observationDigest(domain),
          policySha256: plan.policySha256,
          reviewSha256: approval.audit.pins.manifestSha256,
          routes,
        },
        domain,
        bindings,
        pins: approval.audit.pins,
      };
      windowsObserverConfiguration(auditInput);
      audit = createWindowsAuditCustody(
        reader,
        auditInput,
        {
          subject: payloadSlot,
          objects: provisioned.accessSlots,
          helper: current.resources.observer,
        },
        {
          verifier: current.admission.verifier,
          persist,
          review: auditProof,
          verifyRetirement: auditRetirement,
          verifySettlement: async (value) => {
            const proof = await accessReaders.read();
            return {
              independent: true,
              verifier: proof.verifier,
              beforeSha256: value.before.sha256,
              installedSha256: value.installed.sha256,
              restoredSha256: value.restored.sha256,
              nativeEventSha256: proof.nativeEventSha256,
            };
          },
        },
      );
      current.audit = audit;
      const installed = await audit.install();
      channel = installed.channel;
      current.auditChannel = channel;
      capture = createWindowsSecurityCapture(
        channel,
        createWindowsAuditDecoder(reader, approval.audit.mapping),
        auditInput,
      );
      current.capture = capture;
      await capture.start();
      controls = await reader.prepareAccessControls();
      const parked = await witness();
      requireObservation(
        parked.payloadSuspended &&
          parked.explicitHandles &&
          parked.creationTimeJob,
      );
      await persist(admission);
      return {
        independent: true,
        completeCompositionReviewed: true,
        profile: plan.value.profile,
        reviewSha256: plan.value.reviewSha256,
        disposable: plan.value.disposable,
        controlsReady: true,
        barriersAcknowledged: true,
        nativeEventSha256: observationDigest({ parked, controls }),
        installation,
        ownerIdentityVerified: true,
        owner: started.owner,
      };
    }),
    admit: guarded(async () => {
      requireObservation(
        installation && capture && admission.status === "RUNNING",
      );
      await snapshot();
      await persist(admission);
      await reader.sendOwnership("R");
      admission.status = "ADMITTED";
      await persist(admission);
      const roots = await reader.transferAccessFileRoots(),
        rootProof = await accessReaders.read();
      requireObservation(rootProof.actual.fileRoots.length === 2);
      await persist({
        phase: "access-file-roots-held",
        roots,
        proof: rootProof,
      });
      await reader.transferAccessSockets();
      peers = await reader.startAccessPeers(async (parked) => {
        const peerSlot = (await reader.retainProcess(parked.privatePeer)).slot;
        await accessReaders.read();
        await current.readers.policySnapshot(plan.value, {
          subject: peerSlot,
          objects: provisioned.accessSlots,
        });
        await persist({ phase: "access-peers-parked", ...parked });
      });
      return structuredClone(admission);
    }),
    observe: guarded(async () =>
      collectWindowsAccess(current, {
        admission,
        installation,
        payloadSlot,
        jobSlot,
        capture,
        controls,
        peers,
        auditInput,
        persist,
      }),
    ),
    armFault: guarded(async (kind) => {
      requireObservation(["owner-loss", "helper-loss"].includes(kind));
      const actual = await reader.armAccessFault(kind),
        identity = systemIdentity(actual.identity);
      fault = {
        independent: true,
        nonce: request.nonce,
        timedOut: false,
        lossCount: 0,
        identityVerified: true,
        nativeEventSha256: observationDigest(actual),
        identity,
        verifier: current.admission.verifier,
        fault: kind,
        requestSha256,
        acknowledged: true,
        heldIdentityVerified: true,
        signaled: false,
      };
      await persist(fault);
      return structuredClone(fault);
    }),
    fireFault: guarded(async (kind) => {
      requireObservation(fault?.fault === kind);
      const actual = await reader.fireAccessFault(kind);
      requireObservation(
        actual.signaled && sameWindowsIdentity(actual.identity, fault.identity),
      );
      return {
        ...fault,
        faultSha256: fault.nativeEventSha256,
        nativeEventSha256: observationDigest(actual),
        signaled: true,
      };
    }),
    retire: tracked(retire),
    finish: tracked(async ({ signal }) => {
      current.cleanupSignal = signal;
      await reader.beginCleanup({ signal });
      if (!admission) {
        // Provisioning can fail before a launcher exists. Its owning ledger
        // remains available to the shared recovery step; never invent settlement.
        requireObservation(!policyPossible && !current.caseEffectsPossible);
      }
      const payload = await retire();
      await reader.retireAccessHelper(0);
      let stopFailure;
      if (audit?.possible) {
        let scoped;
        if (capture && channel) {
          let observation, observer;
          try {
            observation = await capture.stop(payload);
            observer = await channel.close();
          } catch (error) {
            stopFailure = firstCause ??= error;
            observer = await reader.retireAccessHelper(1);
            requireObservation(
              observer &&
                sameWindowsIdentity(observer.helper, channel.identity),
            );
          }
          requireObservation(observer.drained && observer.closed);
          scoped = {
            ...observer,
            candidateSha: request.candidateSha,
            nonce: request.nonce,
            domainSha256: auditInput.plan.domainSha256,
            noLiveMembers: true,
          };
          await persist({
            phase: "access-observer-retired",
            observationSha256: observation
              ? observationDigest(observation)
              : null,
            excluded: Boolean(stopFailure),
            scoped,
          });
        } else {
          // A partial per-user/SACL setter can fail before observer admission.
          // Only a fresh independent absent-lane read permits its restoration.
          const proof = await accessReaders.read();
          requireObservation(
            audit.cause &&
              !audit.channel &&
              proof.actual.observerAbsent &&
              proof.actual.creationSealed,
          );
          scoped = {
            ...payload,
            domainSha256: auditInput.plan.domainSha256,
            drained: true,
            nativeEventSha256: proof.nativeEventSha256,
            verifier: proof.verifier,
          };
          await persist({ phase: "access-observer-absent", scoped });
        }
        await (audit.cause || stopFailure
          ? audit.recover(payload, scoped)
          : audit.restore(payload, scoped));
      }
      if (installation?.status === "INSTALLED")
        await accessReaders.unchangedInstalled();
      await reader.authorizeRestoration(payload);
      if (policyPossible) {
        const keys = await reader.wfpInventory(),
          installed = plan.manifest.filters.filter(({ key }) =>
            keys.includes(key),
          );
        requireObservation(
          installed.length === 0 ||
            installed.length === plan.manifest.filters.length,
        );
        if (installed.length)
          await policyMutation(plan, "remove", async (helper) =>
            persist({ phase: "access-removal-helper", helper }),
          );
        await reader.restoreAccessPolicy();
        await accessReaders.restored();
      }
      await reader.closeDomainJobs();
      const account = await reader.retireOwnershipAccount(),
        custody = await reader.close();
      requireObservation(
        account.status === "RETIRED" &&
          custody.status === "RETIRED" &&
          custody.taskRemoved,
      );
      const result = {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({ payload, account, custody }),
      };
      await save(recipe.id, { phase: "access-retired", settlement: result });
      current.retired = true;
      if (stopFailure) throw stopFailure;
      return result;
    }),
  };
  current.access = owner;
  return owner;
}
