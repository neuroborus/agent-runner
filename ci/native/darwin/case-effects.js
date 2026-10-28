import {
  observationDigest,
  observationObject,
  nativePolicyLaunchData,
  requireObservation,
} from "../index.js";
import {
  digest,
  darwinLaunchDigest,
  DARWIN_LITERAL_ARGUMENTS,
  normalizeDarwinLaunch,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import {
  policyPin,
  normalizePolicyTemplate,
  verifyPolicyBinding,
  assertPolicyParameters,
} from "./experiment-policy.js";
import {
  admitDarwinImage,
  darwinImageFrame,
  assertDarwinImageRecord,
} from "./image-admission.js";
import { DARWIN_OWNERSHIP_CASES } from "./ownership.js";
import {
  assessDarwinEnumeration,
  assertDarwinSessionCustody,
} from "./retirement.js";
import {
  createDarwinRefusalBinding,
  DARWIN_CONSTRUCTOR_TRACE_INTENT,
} from "./startup-trace.js";
import { buildDarwinPolicy } from "./policy.js";
import { createDarwinEffectiveReaders } from "./effective.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const literal = (id) => ["ownership.literal", "ownership.storage"].includes(id);
const root = (value) => {
  const identity = normalizeDarwinIdentity(value);
  requireObservation(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
};
export function darwinOwnershipArguments(id, request) {
  if (literal(id)) return [...DARWIN_LITERAL_ARGUMENTS];
  const mode = id.slice(10);
  requireObservation(
    id.startsWith("ownership.") && DARWIN_OWNERSHIP_CASES.includes(mode),
  );
  return [request.nonce, mode];
}

// This fixture policy has no network, IPC, credential or foreign-process grants.
// Its complete bytes, rather than selected successful queries, bound authority.
export function darwinOwnershipPolicy(
  request,
  { execWitnessVersion = 1 } = {},
) {
  requireObservation([0, 1].includes(execWitnessVersion));
  const quote = JSON.stringify;
  return [
    "(version 1)",
    "(deny default)",
    "(allow process-fork)",
    "(allow process-info* (target same-sandbox))",
    `(allow file-read* file-write* (subpath ${quote(request.workspace)}))`,
    `(allow file-read-metadata (literal ${quote(request.storage)}))`,
    ...[
      request.executable.path,
      ...(request.purpose === "experiment" && execWitnessVersion === 1
        ? [request.storage + "/exec-control"]
        : []),
      "/usr/lib/dyld",
      "/usr/lib/libSystem.B.dylib",
    ].map(
      (name) =>
        `(allow file-read-data file-read-metadata file-map-executable (literal ${quote(name)}))`,
    ),
    `(allow process-exec (literal ${quote(request.executable.path)}))`,
    "",
  ].join("\n");
}

// Historical constructor records grant recovery evidence only. Invalid or
// incomplete capture never suppresses independent observer retirement.
export async function retireDarwinConstructorHistory(reader, recovered) {
  const admitted = recovered?.admitted;
  let uncertain;
  try {
    const history = recovered?.history ?? [],
      refusals = history.filter(({ kind }) => kind === "constructor-refusal"),
      children = history.filter(({ kind }) => kind === "constructor-child"),
      sealed = history.filter(({ kind }) => kind === "constructor-sealed");
    // CR1 may already have permitted a diagnostic fork before the first
    // registration survived. Only a successful seal rules that out.
    if (children.length || refusals.length || sealed.length) {
      requireObservation(children.length === 1);
      const child = children[0].record;
      observationObject(child, [
        "identity",
        "parent",
        "receiptSha256",
        "receipt",
      ]);
      requireObservation(
        sameDarwinIdentity(child.identity, admitted.creatorChild) &&
          sameDarwinIdentity(
            child.parent,
            admitted.helpers.find(({ role }) => role === "launcher")?.identity,
          ) &&
          /^[a-f0-9]{1024}$/u.test(child.receipt) &&
          digest(Buffer.from(child.receipt, "hex")) === child.receiptSha256,
      );
      if (!refusals.length) {
        requireObservation(sealed.length === 1);
        const result = sealed[0].record;
        requireObservation(
          result.status === "observed" &&
            result.captureComplete === true &&
            result.cleanup === "RETIRED" &&
            result.programSha256 ===
              DARWIN_CONSTRUCTOR_TRACE_INTENT.programSha256 &&
            result.refusal === null &&
            sameDarwinIdentity(result.creator?.identity, child.identity) &&
            result.creator.receiptSha256 === child.receiptSha256,
        );
      } else {
        requireObservation(sealed.length === 0);
        const binding = createDarwinRefusalBinding(
          child.parent,
          child.identity,
          admitted.candidateSha,
          child.receiptSha256,
        );
        for (const { record } of refusals) {
          const { bindingSha256, ...registration } = record;
          requireObservation(
            binding.consume(
              record.phase === "register" ? registration : record,
            ) === bindingSha256,
          );
        }
        requireObservation(binding.evidence().cleanup === "RETIRED");
      }
    }
  } catch (cause) {
    uncertain = cause;
  }
  for (const { record: observer } of recovered?.history?.filter(
    ({ kind }) => kind === "constructor-observer",
  ) ?? []) {
    try {
      requireObservation(
        (await reader.constructorObserver("retire", observer.identity))
          .status === "RETIRED",
      );
    } catch (cause) {
      uncertain ??= cause;
    }
  }
  return uncertain;
}

/** Private ownership composition. Every effect crosses the sealed root reader;
 * purpose-bound expectations remain data, including the complete policy. */
export function createDarwinCaseEffects(state, current, save, recovered) {
  const { reader, binding, declared, provisioned, recipe } = current,
    execWitnessVersion = declared.bindings.execControl ? 1 : 0,
    request = normalizeDarwinLaunch(
      current.input.request ?? current.input,
      binding.purpose ?? "reviewed",
    ),
    access =
      recipe.group === "access"
        ? buildDarwinPolicy(current.input, { execWitnessVersion })
        : null,
    args = access
      ? [...DARWIN_LITERAL_ARGUMENTS]
      : darwinOwnershipArguments(recipe.id, request),
    mode = access ? "access" : recipe.id.slice(10),
    requestSha256 = darwinLaunchDigest(request, args),
    expectedBytes = Buffer.from(
      access?.seatbelt ??
        darwinOwnershipPolicy(request, { execWitnessVersion }),
    );
  let failure,
    admitted = recovered?.admitted,
    admissionPin = recovered?.pin,
    retirement,
    receiptIndex = recovered?.receiptIndex ?? 0,
    outside = recovered?.outside,
    fault,
    admissionsClosed = false;
  const known = [...(recovered?.members ?? [])],
    now = state.now ?? (() => performance.now());
  const guard = () => {
    if (failure) throw failure;
    state.guard(current.signal);
  };
  const checked =
    (operation) =>
    async (...values) => {
      try {
        guard();
        await state.admit(current.signal);
        const result = await operation(...values);
        guard();
        return result;
      } catch (cause) {
        throw (failure ??= cause);
      }
    };
  const persist = async (kind, record) => {
    const bytes = Buffer.from(JSON.stringify(record) + "\n"),
      pin = { index: receiptIndex++, sha256: digest(bytes) };
    const version =
      kind === "admission" && record.schemaVersion === 2
        ? { admissionVersion: 2 }
        : {};
    await save(recipe.id, {
      phase: "ownership-receipt-possible",
      kind,
      pin,
      ...version,
    });
    requireObservation(
      (await reader.ownershipReceipt(pin.index, pin.sha256, bytes)).equals(
        bytes,
      ),
    );
    await save(recipe.id, {
      phase: "ownership-receipt",
      kind,
      pin,
      ...version,
    });
    if (kind === "admission") admissionPin = pin;
    return pin;
  };
  const recoverReceipt = async () => {
    requireObservation(admissionPin);
    const bytes = await reader.ownershipReceipt(
        admissionPin.index,
        admissionPin.sha256,
      ),
      record = JSON.parse(bytes);
    requireObservation(
      bytes.equals(Buffer.from(JSON.stringify(record) + "\n")) &&
        record.candidateSha === request.candidateSha &&
        record.nonce === request.nonce &&
        record.requestSha256 === requestSha256 &&
        record.admission === "possible" &&
        (!record.payload ||
          (record.controls === true &&
            (assertDarwinSessionCustody(record.sessionCustody, record.payload)
              .held ||
              (record.sessionCustody.closed &&
                record.execControl?.retired === true &&
                record.image?.control === true)))),
    );
    if (record.schemaVersion === 2 && record.image) {
      assertDarwinImageRecord(record.image);
      requireObservation(
        sameDarwinIdentity(record.image.creator, record.creatorChild) &&
          (!record.image.target ||
            sameDarwinIdentity(record.image.target, record.payload)),
      );
    }
    return record;
  };
  const witness = async () => {
    const value = await reader.witness(current.admission.helper);
    requireObservation(value.subject.sha256 === declared.custody.reader.sha256);
    return root(value.verifier);
  };
  const inDomain = (subject, asid) => {
    const value = normalizeDarwinIdentity(subject);
    requireObservation(
      value.auid === request.uid &&
        value.asid === asid &&
        ["uid", "ruid", "svuid"].every((key) => value[key] === request.uid) &&
        ["gid", "rgid", "svgid"].every((key) => value[key] === request.gid),
    );
    return value;
  };
  const members = async (asid) => {
    const result = await reader.ownershipMembers(asid);
    assessDarwinEnumeration(result, request, asid, known);
    for (const value of result.live)
      if (!known.some((identity) => sameDarwinIdentity(identity, value)))
        known.push(value);
    requireObservation(known.length <= 1024);
    return result;
  };
  const snapshot = async () => {
    const setup = await reader.readCase();
    requireObservation(
      (access
        ? setup.objects.length >= 7 + execWitnessVersion
        : setup.objects.length === 7 + execWitnessVersion) &&
        setup.endpoints.length ===
          (access && !recovered?.accessRetired ? 8 : 0),
    );
    const immutable = [];
    for (const index of [4, 5, 6, 7, 8, 9, 10])
      immutable.push({
        index,
        object: await reader.inspect(index),
        sha256: digest(await reader.read(index)),
      });
    const files = await reader.tree(0),
      outsideFiles = [];
    for (const file of files) {
      if (file.name.startsWith("storage/work/")) continue;
      if (
        file.name === "custody/audit-custody" ||
        /^custody\/receipt-[0-9]+\.json$/u.test(file.name)
      ) {
        requireObservation(
          file.file.object.uid === 0 &&
            file.file.object.gid === 0 &&
            file.file.object.mode === 0o400,
        );
        continue;
      }
      if (
        [`custody/uid-${request.uid}`, `custody/gid-${request.gid}`].includes(
          file.name,
        )
      ) {
        requireObservation(
          file.file.sha256 === digest(request.nonce) &&
            file.file.object.uid === 0 &&
            file.file.object.mode === 0o400,
        );
        continue;
      }
      outsideFiles.push(file);
    }
    return { setup, immutable, files: outsideFiles };
  };
  const unchanged = async () => {
    const actual = await snapshot();
    const comparable = (value) =>
      recovered?.accessRetired
        ? { ...value, setup: { ...value.setup, endpoints: [] } }
        : value;
    // Fresh recovery has no endpoint descriptors. The old custodian's root
    // audit domain and reserved UID domain must both be independently empty;
    // immutable objects still rejoin the original outside snapshot exactly.
    requireObservation(same(comparable(actual), comparable(outside)));
    return actual;
  };
  const event = async () => {
    const bytes = await reader.ownershipOutput(),
      value = JSON.parse(bytes);
    observationObject(value, ["nonce", "phase", "pid", "count"]);
    requireObservation(
      value.nonce === request.nonce &&
        Number.isSafeInteger(value.pid) &&
        value.pid > 1 &&
        Number.isSafeInteger(value.count) &&
        value.count >= 0 &&
        value.count <= 31,
    );
    return { value, bytes };
  };
  const subject = async (pid, parked) => {
    const actual = await reader.ownershipSubject(pid, { access: !!access }),
      identity = inDomain(actual.identity, parked.asid);
    requireObservation(
      identity.pid === parked.pid &&
        identity.startSeconds === parked.startSeconds &&
        identity.startMicroseconds === parked.startMicroseconds &&
        actual.imageSha256 === request.executable.sha256,
    );
    const work = await reader.inspect(3),
      parts = work.identity.split(":");
    requireObservation(
      actual.cwd.dev === parts[0] && actual.cwd.ino === parts[3],
    );
    return actual;
  };
  const retire = async () => {
    let observerRetirement;
    const retireObservers = () =>
      (observerRetirement ??= retireDarwinConstructorHistory(
        reader,
        recovered,
      ));
    // Original process settlement cannot depend on a complete observer capture.
    // The finally branch still retires observers if original cleanup refuses.
    try {
      // Always reread the exclusive root receipt, even when admission was cached.
      const record = await recoverReceipt();
      requireObservation(record.helpers.length > 0);
      const pendingPayload = record.payload ?? record.creatorChild;
      const payload = pendingPayload
          ? inDomain(pendingPayload, pendingPayload.asid)
          : null,
        launcher = root(
          record.helpers.find(({ role }) => role === "launcher")?.identity,
        );
      if (
        payload &&
        !known.some((identity) => sameDarwinIdentity(identity, payload))
      )
        known.push(payload);
      const deadline = now() + 30000;
      admissionsClosed = true;
      await reader.fenceOwnership();
      const custodians = [
        ...(recovered?.custodians ?? []),
        ...((record.sessionCustody ??
        record.creatorSessionCustody ??
        recovered?.imageSession ??
        admitted?.creatorSessionCustody)
          ? [
              (
                record.sessionCustody ??
                record.creatorSessionCustody ??
                recovered?.imageSession ??
                admitted?.creatorSessionCustody
              ).owner,
            ]
          : []),
      ]
        .map(root)
        .filter(
          (identity, i, all) =>
            all.findIndex((entry) => sameDarwinIdentity(entry, identity)) === i,
        );
      let sessionCustody = payload
        ? assertDarwinSessionCustody(
            record.sessionCustody ??
              record.creatorSessionCustody ??
              recovered?.imageSession ??
              admitted?.creatorSessionCustody,
            payload,
          )
        : null;
      if (
        payload &&
        !sameDarwinIdentity(sessionCustody.owner, current.admission.helper)
      ) {
        sessionCustody = assertDarwinSessionCustody(
          await reader.recoverOwnershipSession(payload, sessionCustody),
          payload,
        );
        if (sessionCustody.closed)
          requireObservation(
            (record.image?.version === 3 && record.image.control) ||
              recovered.history.some(
                ({ kind, record }) =>
                  kind === "retirement" &&
                  record.status === "RETIRED" &&
                  record.requestSha256 === requestSha256,
              ),
          );
      }
      await persist("retirement", {
        phase: "stop-admissions",
        requestSha256,
        payload,
        launcher,
        members: known,
        sessionCustody,
        custodians,
      });
      // New root custody is receipted before retiring any original holder.
      for (const identity of [...custodians, ...(recovered?.subjects ?? [])]) {
        if (
          identity.pid === current.admission.helper.pid ||
          identity.pid === launcher.pid
        )
          continue;
        const stopped = await reader.signalOwnership(identity);
        requireObservation(
          ["sent", "not-found", "zombie"].includes(stopped.outcome),
        );
        await reader.retired(identity);
      }
      const stopped = await reader.signalOwnership(launcher);
      requireObservation(
        ["sent", "not-found", "zombie"].includes(stopped.outcome),
      );
      let result,
        work = 0;
      for (
        let pass = 0;
        payload && !sessionCustody.closed && pass < 32;
        pass++
      ) {
        requireObservation(now() <= deadline);
        result = await members(payload.asid);
        if (!result.live.length) break;
        for (const identity of result.live) {
          requireObservation(++work <= 1024);
          await persist("retirement", {
            phase: "signal",
            requestSha256,
            identity,
            members: known,
          });
          const signalled = await reader.signalOwnership(identity);
          requireObservation(
            ["sent", "not-found", "zombie"].includes(signalled.outcome),
          );
        }
      }
      if (!payload || sessionCustody.closed)
        result = await reader.emptyOwnership();
      requireObservation(
        result &&
          (!payload || sessionCustody.closed || result.live.length === 0) &&
          now() <= deadline,
      );
      if (payload && !sessionCustody.closed) {
        const zombies = new Set(result.zombies.map(({ pid }) => pid)),
          checked = new Set();
        for (const identity of known)
          if (!zombies.has(identity.pid) && !checked.has(identity.pid)) {
            checked.add(identity.pid);
            requireObservation(now() <= deadline);
            await reader.retired(identity, { reserved: true });
          }
      }
      await reader.retired(launcher);
      for (const helper of record.helpers.filter(
        ({ role }) => role === "verifier",
      ))
        await reader.retired(helper.identity);
      for (const identity of recovered?.subjects ?? [])
        if (identity.asid > 0) await reader.retiredRootDomain(identity);
      const actual = await unchanged(),
        verification = await reader.verifyOwnership(
          sessionCustody?.closed ? 0 : (payload?.asid ?? 0),
        ),
        freshVerifier = root(verification.verifier);
      assessDarwinEnumeration(
        verification.enumeration,
        request,
        sessionCustody?.closed ? 0 : (payload?.asid ?? 0),
        sessionCustody?.closed ? [] : known,
      );
      requireObservation(
        verification.enumeration.live.length === 0 && now() <= deadline,
      );
      const observerUncertain = await retireObservers();
      if (observerUncertain) throw observerUncertain;
      requireObservation(now() <= deadline);
      retirement = {
        status: "RETIRED",
        candidateSha: request.candidateSha,
        nonce: request.nonce,
        requestSha256,
        domain: {
          uid: request.uid,
          gid: request.gid,
          asid: payload?.asid ?? null,
        },
        helpersSettled: true,
        reservation: "RETAINED",
        freshVerifier,
        sessionCustody,
        custodians,
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({
          result,
          actual,
          verification,
          stopped,
        }),
      };
      await persist("retirement", retirement);
      requireObservation(now() <= deadline);
      return structuredClone(retirement);
    } finally {
      await retireObservers();
    }
  };
  const prepare = checked(async () => {
    requireObservation(!admissionsClosed);
    const payloadName = access
      ? "access-fixture"
      : literal(recipe.id)
        ? "argv-fixture"
        : "ownership-fixture";
    requireObservation(
      request.schemaVersion === 1 &&
        expectedBytes.length <= 65536 &&
        digest(expectedBytes) === request.policy.sha256 &&
        state.manifest.helpers.find(({ name }) => name === "launcher")
          ?.sha256 === request.launcher.sha256 &&
        state.manifest.helpers.find(({ name }) => name === payloadName)
          ?.sha256 === request.executable.sha256,
    );
    assertPolicyParameters(
      binding,
      provisioned.provisioning,
      access?.value ?? {
        request,
        kind: "darwin-ownership",
        seatbeltSha256: request.policy.sha256,
        processLimit: 32,
      },
      args,
    );
    requireObservation((await reader.read(6)).equals(expectedBytes));
    outside = await snapshot();
    await save(recipe.id, { phase: "ownership-outside", snapshot: outside });
    current.caseEffectsPossible = true;
    const born = await reader.startOwnership(mode, request.executable.cdhash),
      hello = await reader.ownershipControl();
    observationObject(hello, ["helper", "payload"]);
    const helper = root(hello.helper);
    requireObservation(helper.pid === born.pid && hello.payload === null);
    admitted = {
      schemaVersion: binding.purpose === "experiment" ? 2 : 1,
      candidateSha: request.candidateSha,
      nonce: request.nonce,
      requestSha256,
      admission: "possible",
      status: "RUNNING",
      reservation: "RETAINED",
      processLimit: 32,
      helpers: [{ role: "launcher", identity: helper }],
      payload: null,
    };
    await persist("admission", admitted);
    requireObservation(
      (await reader.helper(helper)).sha256 === request.launcher.sha256,
    );
    await reader.sendOwnership(false, "P");
    let parked = await reader.ownershipControl();
    const authorities = [];
    const policy = async (target) => {
      const values = [];
      if (!access) {
        for (let i = 0; i < 7; i++) {
          const value = await reader.authority(target, i);
          const expected =
            i === 3
              ? [0, 0, 0, 0, 1]
              : i === 5
                ? [0, 1, 1, 1, 0]
                : [1, 1, 1, 1, 1];
          requireObservation(
            binding.purpose === "experiment"
              ? same(value.decisions, expected.slice(0, 4))
              : value.decisions[1] === expected[1] &&
                  value.decisions[4] === expected[4],
          );
          values.push(value);
        }
      } else {
        requireObservation(current.accessPolicy);
        const objects = [];
        for (const item of current.accessPolicy.seatbelt) {
          const object = await reader.inspect(item.index);
          objects.push({
            ...item,
            path: await reader.location(item.index),
            identity: object.identity,
            ...(binding.purpose === "experiment" && item.aclSha256 === null
              ? {
                  aclSha256: (await reader.authority(target, item.index))
                    .aclSha256,
                }
              : {}),
          });
        }
        if (binding.purpose === "experiment") {
          const freshPf = await current.accessPolicy.inspectPf();
          // Independent witness identities and passive observation digests may
          // differ; validated effective policy and exclusion must not.
          const policyBinding = ({ verifier, evidenceSha256, ...value }) =>
            value;
          requireObservation(
            same(
              policyBinding(freshPf),
              policyBinding(current.accessPolicy.pf),
            ),
          );
        }
        values.push(
          await createDarwinEffectiveReaders(
            reader,
            binding.context,
            current.admission.helper,
          ).seatbelt(
            access.value,
            { ...admitted, payload: target, phase: "verify" },
            6,
            objects,
            args,
          ),
          current.accessPolicy.pf,
        );
      }
      return values;
    };
    if (binding.purpose === "experiment") {
      let execControl = null;
      for (const control of [true, false]) {
        const creator = darwinImageFrame(
          parked,
          control ? "control-creator" : "creator",
          helper,
        );
        admitted.creatorChild = creator;
        admitted.payload = null;
        admitted.controls = false;
        delete admitted.image;
        delete admitted.creatorSessionCustody;
        delete admitted.sessionCustody;
        known.push(creator);
        await persist("admission", admitted); // birth precedes fallible custody acquisition
        admitted.creatorSessionCustody = assertDarwinSessionCustody(
          await reader.holdOwnershipSession(creator, helper),
          creator,
        );
        const result = await admitDarwinImage({
          reader,
          creator,
          helper,
          next: () => reader.ownershipControl(),
          control,
          execControl,
          asset: declared.bindings.execControl,
          executable: control
            ? declared.bindings.execControl
            : request.executable,
          policySha256: request.policy.sha256,
          guard,
          now,
          observe: control ? async () => [] : policy,
          publish: async (image) => {
            admitted.image = image;
            admitted.controls = true;
            admitted.sessionCustody = admitted.creatorSessionCustody;
            if (image.target) {
              admitted.payload = image.target;
              if (
                !known.some((value) => sameDarwinIdentity(value, image.target))
              )
                known.push(image.target);
            }
            const pin = await persist("admission", admitted);
            return { pin, bytes: Buffer.from(JSON.stringify(admitted) + "\n") };
          },
        });
        if (control) {
          requireObservation(
            JSON.parse(await reader.ownershipOutput()).phase === "armed",
          );
          await reader.sendOwnership(true, "A");
          const output = await reader.ownershipOutput();
          requireObservation(
            output === JSON.stringify(DARWIN_LITERAL_ARGUMENTS) + "\n",
          );
          requireObservation(
            same(await reader.ownershipControl(), {
              exitCode: 0,
              signal: null,
            }),
          );
          admitted.sessionCustody = admitted.creatorSessionCustody =
            await reader.finishOwnershipSession(creator.asid);
          execControl = {
            image: result.image,
            retired: true,
            outputSha256: digest(output),
          };
          admitted.execControl = execControl;
          known.splice(
            0,
            known.length,
            ...known.filter((identity) => identity.asid !== creator.asid),
          );
          await persist("admission", admitted);
          await reader.imageControlNext();
          parked = await reader.ownershipControl();
        } else authorities.push(...result.policy);
      }
    } else {
      observationObject(parked, ["helper", "payload", "controls"]);
      requireObservation(
        parked.controls === true && sameDarwinIdentity(parked.helper, helper),
      );
      admitted.payload = inDomain(parked.payload, parked.payload.asid);
      known.push(admitted.payload);
      admitted.controls = true;
      admitted.sessionCustody = assertDarwinSessionCustody(
        await reader.holdOwnershipSession(admitted.payload, helper),
        admitted.payload,
      );
      await persist("admission", admitted);
      await recoverReceipt();
      if (!access) authorities.push(...(await policy(admitted.payload)));
      await reader.sendOwnership(false, "R");
    }
    let ready;
    if (literal(recipe.id) || access) {
      ready = JSON.parse(await reader.ownershipOutput());
      observationObject(ready, ["phase"]);
      requireObservation(ready.phase === "armed");
    } else {
      ready = (await event()).value;
      requireObservation(
        ready.phase === "armed" &&
          ready.pid === admitted.payload.pid &&
          ready.count === 0,
      );
    }
    if (access)
      requireObservation((await reader.access("payload-sockets")).held === 8);
    const actual = await subject(admitted.payload.pid, admitted.payload);
    if (binding.purpose === "experiment")
      requireObservation(
        sameDarwinIdentity(actual.identity, admitted.image.target),
      );
    admitted.parkedPayload = admitted.payload;
    admitted.payload = actual.identity;
    known.push(actual.identity);
    admitted.authority = { cwd: actual.cwd };
    admitted.helpers.push({ role: "verifier", identity: await witness() });
    if (access && binding.purpose !== "experiment")
      authorities.push(...(await policy(admitted.payload)));
    const observed = {
      schemaVersion: 1,
      context: structuredClone(binding.context),
      templateSha256: policyPin(binding),
      provisioningSha256: observationDigest(provisioned.provisioning),
      requestSha256,
      policy: {
        launch: nativePolicyLaunchData(request, args),
        policy: access
          ? Object.fromEntries(
              Object.entries(access.value).filter(([key]) => key !== "request"),
            )
          : {
              kind: "darwin-ownership",
              seatbeltSha256: digest(await reader.read(6)),
              processLimit: 32,
            },
      },
      held: true,
      complete: true,
      independent: true,
      verifierSha256: declared.custody.reader.sha256,
      nativeEventSha256: observationDigest({
        actual,
        authorities,
        ready,
        outside,
        admitted,
      }),
    };
    observed.policy = normalizePolicyTemplate({
      ...binding.template,
      bindings: [],
      policy: observed.policy,
    }).policy;
    observed.policySha256 = observationDigest(observed.policy);
    verifyPolicyBinding(
      binding,
      provisioned.provisioning,
      requestSha256,
      observed,
    );
    admitted.status = "ADMITTED";
    await persist("admission", admitted);
    return { provisioning: provisioned.provisioning, requestSha256, observed };
  });
  const effects = {
    async persist(record) {
      try {
        return failure
          ? await save(recipe.id, { phase: "ownership-failure", record })
          : await persist("owner", record);
      } catch (cause) {
        throw (failure ??= cause);
      }
    },
    admit: checked(async () => ({ ...structuredClone(admitted) })),
    observe: checked(async (id) => {
      requireObservation(id === mode && admitted?.status === "ADMITTED");
      await recoverReceipt();
      await reader.sendOwnership(true, "A");
      const events = [];
      for (
        let i = 0;
        i < (mode === "process-limit" ? 32 : mode === "stale-identity" ? 1 : 2);
        i++
      )
        events.push(await event());
      const count = mode === "process-limit" ? 31 : 1,
        leaves = events.filter(({ value }) => value.phase === "leaf");
      requireObservation(
        leaves.length === count &&
          new Set(leaves.map(({ value }) => value.pid)).size === count,
      );
      for (const { value } of leaves) {
        const file = await reader.barrier(3, `nonce-${value.pid}`);
        requireObservation(
          file.sha256 === digest(request.nonce) &&
            file.object.uid === request.uid &&
            file.object.gid === request.gid &&
            file.object.mode === 0o600,
        );
      }
      const actual = await members(admitted.payload.asid);
      await persist("members", { requestSha256, members: known });
      requireObservation(
        actual.live.length ===
          (mode === "process-limit" ? 32 : mode === "stale-identity" ? 1 : 2) &&
          leaves.every(({ value }) =>
            actual.live.some(({ pid }) => pid === value.pid),
          ),
      );
      const observation = {
        caseId: mode,
        nonce: request.nonce,
        attempted: true,
        independent: true,
        outsideUnchanged: true,
        members: actual.live,
        bytesSha256: digest(events.map(({ bytes }) => bytes).join("")),
        nativeEventSha256: observationDigest({
          events,
          actual,
          outside: await unchanged(),
        }),
      };
      if (mode === "stale-identity") {
        const after = (await subject(admitted.payload.pid, admitted.payload))
            .identity,
          rejection = await reader.signalOwnership(admitted.payload);
        requireObservation(
          rejection.outcome === "stale" &&
            sameDarwinIdentity(
              (await subject(after.pid, after)).identity,
              after,
            ),
        );
        Object.assign(observation, {
          before: admitted.payload,
          after,
          staleRejected: true,
          forcedPidReuse: false,
        });
      } else
        requireObservation(
          events.some(
            ({ value }) =>
              value.phase === (mode === "process-limit" ? "limit" : "parent") &&
              value.pid === admitted.payload.pid &&
              value.count === count,
          ),
        );
      if (mode === "process-limit")
        Object.assign(observation, {
          forkError: "EAGAIN",
          softLimit: 32,
          hardLimit: 32,
        });
      return observation;
    }),
    armFault: checked(async (id) => {
      requireObservation(id === mode);
      let acknowledgement;
      if (mode === "stale-identity")
        acknowledgement = await members(admitted.payload.asid);
      else {
        await reader.sendOwnership(true, "B");
        acknowledgement = (await event()).value;
        requireObservation(
          acknowledgement.phase === "fault-armed" &&
            acknowledgement.pid === admitted.payload.pid &&
            acknowledgement.count === 0,
        );
      }
      fault = {
        caseId: mode,
        nonce: request.nonce,
        armed: true,
        receiptSha256: observationDigest(acknowledgement),
      };
      await persist("fault", { ...fault, acknowledgement });
      return structuredClone(fault);
    }),
    fireFault: checked(async (id, value, acknowledgement) => {
      requireObservation(id === mode && same(acknowledgement, fault));
      if (mode !== "stale-identity") await reader.sendOwnership(true, "C");
      if (mode === "reparent") {
        const exit = await reader.ownershipControl();
        observationObject(exit, ["exitCode", "signal"]);
        requireObservation(
          exit.exitCode === 0 &&
            exit.signal === null &&
            !(await members(admitted.payload.asid)).live.some(
              ({ pid }) => pid === admitted.payload.pid,
            ),
        );
      }
      if (mode === "cancel")
        requireObservation(
          (await reader.signalOwnership(admitted.payload)).outcome === "sent",
        );
      if (mode === "owner-loss" || mode === "helper-loss") {
        const identity =
          mode === "owner-loss"
            ? admitted.helpers[0].identity
            : (await members(admitted.payload.asid)).live.find(
                ({ pid }) => pid !== admitted.payload.pid,
              );
        requireObservation(
          identity &&
            (await reader.signalOwnership(identity)).outcome === "sent",
        );
      }
      if (mode === "receipt-recovery") admitted = await recoverReceipt();
    }),
    recoverAndRetire: retire,
    verify: checked(async () => {
      requireObservation(
        retirement && !(await members(retirement.domain.asid)).live.length,
      );
      const verification = await reader.verifyOwnership(retirement.domain.asid),
        verifier = root(verification.verifier);
      assessDarwinEnumeration(
        verification.enumeration,
        request,
        retirement.domain.asid,
        known,
      );
      requireObservation(verification.enumeration.live.length === 0);
      requireObservation(verifier.pid !== retirement.freshVerifier.pid);
      await unchanged();
      return {
        independent: true,
        noLiveMembers: true,
        helpersSettled: true,
        outsideUnchanged: true,
        nonce: request.nonce,
        requestSha256,
        verifier,
      };
    }),
  };
  return {
    effects,
    prepare,
    custody: {
      persist,
      witness,
      retire,
      unchanged,
      admitted: () => structuredClone(admitted),
    },
    async admitLiteral() {
      guard();
      return { record: structuredClone(admitted) };
    },
    literal: checked(async (result) => {
      requireObservation(result.record.requestSha256 === requestSha256);
      await recoverReceipt();
      const actual = await subject(admitted.payload.pid, admitted.payload);
      await reader.sendOwnership(true, "A");
      const output = await reader.ownershipOutput(),
        exit = await reader.ownershipControl();
      observationObject(exit, ["exitCode", "signal"]);
      requireObservation(exit.exitCode === 0 && exit.signal === null);
      await reader.ownershipEof();
      await unchanged();
      const verifier = await witness();
      result.record.helpers.push({ role: "verifier", identity: verifier });
      admitted = structuredClone(result.record);
      await persist("admission", admitted);
      return {
        independent: true,
        verifier,
        requestSha256,
        payload: actual.identity,
        cwdIdentity: actual.cwd,
        imageSha256: actual.imageSha256,
        output,
        exitCode: exit.exitCode,
        timedOut: false,
        complete: true,
        nativeEventSha256: observationDigest({
          actual,
          output,
          exit,
          verifier,
        }),
      };
    }),
    async finish({ signal }) {
      requireObservation(!current.signal || current.signal.aborted);
      await reader.beginCleanup({ signal });
      await retire();
      const objects = await reader.retireCase(),
        custody = await reader.close();
      requireObservation(
        custody.status === "RETIRED" && custody.independent && custody.closed,
      );
      current.retired = true;
      const result = {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({ objects, custody, retirement }),
      };
      await save(recipe.id, { phase: "ownership-retired", settlement: result });
      return result;
    },
    async recover() {
      await retire();
      const objects = await reader.retireCase(),
        custody = await reader.close();
      requireObservation(
        custody.status === "RETIRED" && custody.independent && custody.closed,
      );
      const result = {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({ objects, custody, retirement }),
      };
      await save(recipe.id, { phase: "ownership-retired", settlement: result });
      return result;
    },
  };
}
