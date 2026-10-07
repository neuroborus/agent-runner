import {
  observationDigest,
  observationObject,
  nativePolicyLaunchData,
  normalizeNativePolicyTemplate,
  requireObservation,
  verifyNativePolicy,
  assertNativePolicyParameters,
} from "../index.js";
import {
  digest,
  darwinLaunchDigest,
  DARWIN_LITERAL_ARGUMENTS,
  normalizeDarwinLaunch,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import { DARWIN_OWNERSHIP_CASES } from "./ownership.js";
import { assessDarwinEnumeration } from "./retirement.js";
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
function darwinOwnershipPolicy(request) {
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

/** Private ownership composition. Every effect crosses the sealed root reader;
 * independently approved inputs remain data, including the complete policy. */
export function createDarwinCaseEffects(state, current, save, recovered) {
  const { reader, binding, declared, provisioned, recipe } = current,
    request = normalizeDarwinLaunch(current.input.request ?? current.input),
    access =
      recipe.group === "access" ? buildDarwinPolicy(current.input) : null,
    args = access
      ? [...DARWIN_LITERAL_ARGUMENTS]
      : darwinOwnershipArguments(recipe.id, request),
    mode = access ? "access" : recipe.id.slice(10),
    requestSha256 = darwinLaunchDigest(request, args),
    expectedBytes = Buffer.from(
      access?.seatbelt ?? darwinOwnershipPolicy(request),
    );
  let failure,
    admitted = recovered?.admitted,
    admissionPin = recovered?.pin,
    retirement,
    receiptIndex = recovered?.receiptIndex ?? 0,
    outside = recovered?.outside,
    fault;
  const known = [...(recovered?.members ?? [])];
  const guard = () => {
    if (failure) throw failure;
    state.guard(current.signal);
  };
  const checked =
    (operation) =>
    async (...values) => {
      try {
        guard();
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
    await save(recipe.id, { phase: "ownership-receipt-possible", kind, pin });
    requireObservation(
      (await reader.ownershipReceipt(pin.index, pin.sha256, bytes)).equals(
        bytes,
      ),
    );
    await save(recipe.id, { phase: "ownership-receipt", kind, pin });
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
        record.admission === "possible",
    );
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
      (access ? setup.objects.length >= 7 : setup.objects.length === 7) &&
        setup.endpoints.length === (access ? 8 : 0),
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
      if (/^custody\/receipt-[0-9]+\.json$/u.test(file.name)) {
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
    requireObservation(same(actual, outside));
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
    // Always reread the exclusive root receipt, even when admission was cached.
    const record = await recoverReceipt();
    requireObservation(record.helpers.length > 0);
    const payload = record.payload
        ? inDomain(record.payload, record.payload.asid)
        : null,
      launcher = root(
        record.helpers.find(({ role }) => role === "launcher")?.identity,
      );
    if (
      payload &&
      !known.some((identity) => sameDarwinIdentity(identity, payload))
    )
      known.push(payload);
    const deadline = performance.now() + 30000;
    // Separate reader custody retains the audit session before any old holder is
    // stopped. Recovery can acquire it by ASID even after its leader has exited.
    const initial = payload ? await members(payload.asid) : null,
      helper = await reader.ownershipHelper(launcher);
    if (payload && (initial.live.length || helper.subject.status === "live"))
      await reader.holdOwnershipSession(payload.asid);
    await persist("retirement", {
      phase: "stop-admissions",
      requestSha256,
      payload,
      launcher,
      members: known,
    });
    const stopped = await reader.signalOwnership(launcher);
    requireObservation(
      ["sent", "not-found", "zombie"].includes(stopped.outcome),
    );
    let result,
      work = 0;
    for (let pass = 0; payload && pass < 32; pass++) {
      requireObservation(performance.now() <= deadline);
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
    if (!payload) result = await reader.emptyOwnership();
    requireObservation(
      result &&
        (!payload || result.live.length === 0) &&
        performance.now() <= deadline,
    );
    await reader.retired(launcher);
    for (const helper of record.helpers.filter(
      ({ role }) => role === "verifier",
    ))
      await reader.retired(helper.identity);
    const actual = await unchanged(),
      verification = await reader.verifyOwnership(payload?.asid ?? 0),
      freshVerifier = root(verification.verifier);
    assessDarwinEnumeration(
      verification.enumeration,
      request,
      payload?.asid ?? 0,
      known,
    );
    requireObservation(
      verification.enumeration.live.length === 0 &&
        performance.now() <= deadline,
    );
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
    requireObservation(performance.now() <= deadline);
    return structuredClone(retirement);
  };
  const prepare = checked(async () => {
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
    assertNativePolicyParameters(
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
      schemaVersion: 1,
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
    const parked = await reader.ownershipControl();
    observationObject(parked, ["helper", "payload"]);
    requireObservation(sameDarwinIdentity(parked.helper, helper));
    admitted.payload = inDomain(parked.payload, parked.payload.asid);
    known.push(admitted.payload);
    requireObservation(
      sameDarwinIdentity(
        await reader.process(admitted.payload.pid, { retainSession: true }),
        admitted.payload,
      ),
    );
    await persist("admission", admitted);
    await recoverReceipt();
    // Query the installed sandbox while the child is still behind R. The
    // executing root owner has already enforced credentials, Mach rights and
    // RLIMIT_NPROC; fixture output is not evidence of those operations.
    const authorities = [];
    for (let i = 0; !access && i < 7; i++) {
      const authority = await reader.authority(admitted.payload, i);
      requireObservation(
        authority.decisions[1] === (i === 3 ? 0 : 1) &&
          authority.decisions[4] === (i === 5 ? 0 : 1),
      );
      authorities.push(authority);
    }
    await reader.sendOwnership(false, "R");
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
    admitted.parkedPayload = admitted.payload;
    admitted.payload = actual.identity;
    known.push(actual.identity);
    admitted.authority = { cwd: actual.cwd };
    admitted.helpers.push({ role: "verifier", identity: await witness() });
    if (access) {
      requireObservation(current.accessPolicy);
      const objects = [];
      for (const item of current.accessPolicy.seatbelt) {
        const object = await reader.inspect(item.index);
        objects.push({
          ...item,
          path: await reader.location(item.index),
          identity: object.identity,
        });
      }
      const actualPolicy = await createDarwinEffectiveReaders(
        reader,
        binding.context,
        current.admission.helper,
      ).seatbelt(
        access.value,
        { ...admitted, phase: "verify" },
        6,
        objects,
        args,
      );
      authorities.push(actualPolicy, current.accessPolicy.pf);
    }
    const observed = {
      schemaVersion: 1,
      context: structuredClone(binding.context),
      templateSha256: binding.approval.manifestSha256,
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
    observed.policy = normalizeNativePolicyTemplate({
      ...binding.template,
      bindings: [],
      policy: observed.policy,
    }).policy;
    observed.policySha256 = observationDigest(observed.policy);
    verifyNativePolicy(
      binding.template,
      binding.approval,
      provisioned.provisioning,
      binding.context,
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
