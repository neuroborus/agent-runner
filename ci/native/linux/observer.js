import { performance } from "node:perf_hooks";
import {
  NATIVE_OBSERVER_LIMITS,
  observationDigest,
  requireObservation,
  observationObject,
  observationList,
  normalizeToolObservationPlan,
  assertNativeObserverHealth,
  joinNativeToolObservations,
  assertNativeToolAttempt,
  assertNativeObserverSettlement,
} from "../index.js";
import { sameLinuxIdentity } from "./protocol.js";

export function linuxObserverArguments() {
  return Object.freeze([
    "-f",
    "--kill-on-exit",
    "-qq",
    "-ttt",
    "-s",
    "4096",
    "-yy",
    "-e",
    "trace=%file,%network,%ipc,%process,read,write,ptrace,process_vm_readv,process_vm_writev,kill,tgkill,tkill,pidfd_open,pidfd_getfd,pidfd_send_signal",
    "-e",
    "raw=read,write,ptrace,process_vm_readv,process_vm_writev,pidfd_getfd,pidfd_send_signal",
  ]);
}
/** Private-pipe decoder. Buffer contents and exec arguments are discarded;
 * only a fixed native selector can survive. FD resolution is independently
 * joined through the held-process/object reader, never a pathname guess. */
export function createLinuxObserverDecoder(
  selectors,
  { initialPid = null } = {},
) {
  const allowed = new Set(
    observationList(selectors, NATIVE_OBSERVER_LIMITS.routes * 3),
  );
  requireObservation(
    allowed.size > 0 &&
      [...allowed].every(
        (item) =>
          typeof item === "string" && item.length > 0 && item.length <= 4096,
      ) &&
      (initialPid === null ||
        (Number.isSafeInteger(initialPid) &&
          initialPid > 0 &&
          initialPid <= 2147483647)),
  );
  let bytes = 0,
    sequence = 0,
    failed = false,
    finished = false;
  const pending = new Map();
  // Split only native argument boundaries. A quoted send buffer or argv entry
  // cannot impersonate socket metadata or the selected pathname argument.
  const fields = (text) => {
    const result = [],
      stack = [];
    let start = 0,
      quoted = false,
      escaped = false;
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === '"') quoted = false;
      } else if (char === '"') quoted = true;
      else if ("([{<".includes(char)) stack.push(char);
      else if (char === ">" && text[i - 1] === "-") continue;
      else if (")]}>".includes(char))
        requireObservation(stack.pop() === "([{<"[")]}>".indexOf(char)]);
      else if (char === "," && stack.length === 0) {
        result.push(text.slice(start, i).trim());
        start = i + 1;
      }
    }
    requireObservation(!quoted && stack.length === 0);
    result.push(text.slice(start).trim());
    return result;
  };
  const quoted = (text) => {
    const value = text.match(/"((?:[^"\\]|\\.)*)"/u)?.[1];
    if (value === undefined) return null;
    return value.replace(
      /\\(?:([0-7]{1,3})|x([a-f0-9]{2})|([\\"nrt]))/giu,
      (_, octal, hex, char) =>
        octal
          ? String.fromCharCode(parseInt(octal, 8))
          : hex
            ? String.fromCharCode(parseInt(hex, 16))
            : ({ n: "\n", r: "\r", t: "\t" }[char] ?? char),
    );
  };
  return Object.freeze({
    select(selector) {
      try {
        requireObservation(
          !failed &&
            !finished &&
            typeof selector === "string" &&
            selector.length > 0 &&
            selector.length <= 4096 &&
            (allowed.has(selector) ||
              allowed.size < NATIVE_OBSERVER_LIMITS.routes * 3),
        );
        allowed.add(selector);
      } catch (error) {
        failed = true;
        throw error;
      }
    },
    line(text) {
      try {
        requireObservation(!failed && !finished);
        requireObservation(
          typeof text === "string" &&
            Buffer.byteLength(text) <= NATIVE_OBSERVER_LIMITS.recordBytes,
        );
        bytes += Buffer.byteLength(text);
        requireObservation(
          bytes <= NATIVE_OBSERVER_LIMITS.captureBytes &&
            ++sequence <= NATIVE_OBSERVER_LIMITS.events,
        );
        const prefix = text.match(
          /^(?:(?:\[pid\s+([1-9][0-9]*)\]|([1-9][0-9]*))\s+)?([0-9]+\.[0-9]+)\s+(.*)$/u,
        );
        requireObservation(prefix);
        // strace omits the prefix for its initial tracee before a fork. That PID
        // must come from independently verified creation-time admission.
        const pid = Number(prefix[1] ?? prefix[2] ?? initialPid);
        requireObservation(
          Number.isSafeInteger(pid) && pid > 0 && pid <= 2147483647,
        );
        let body = prefix[4];
        if (/^(?:--- |\+\+\+ )/u.test(body)) return null;
        const unfinished = body.match(
          /^([a-z0-9_]+)\((.*)<unfinished \.\.\.>$/u,
        );
        if (unfinished) {
          requireObservation(!pending.has(pid) && pending.size < 32);
          pending.set(pid, { opcode: unfinished[1], args: unfinished[2] });
          return null;
        }
        const resumed = body.match(/^<\.\.\. ([a-z0-9_]+) resumed>(.*)$/u);
        if (resumed) {
          const previous = pending.get(pid);
          requireObservation(previous && previous.opcode === resumed[1]);
          pending.delete(pid);
          body = previous.opcode + "(" + previous.args + resumed[2];
        } else requireObservation(!pending.has(pid));
        if (/^(?:exit|exit_group)\([0-9]+\)\s+=\s+\?$/u.test(body)) return null;
        const call = body.match(
          /^([a-z0-9_]+)\((.*)\)\s+=\s+(-?(?:0x[a-f0-9]+|[0-9]+))(?:<(?:[^>]|(?<=-)>)*>)?(?:\s+([A-Z][A-Z0-9_]+)(?:\s+.*)?|\s+<[^>]+>)?$/u,
        );
        requireObservation(call);
        const opcode = call[1],
          args = call[2];
        let target = null;
        if (
          ["read", "write", "pidfd_getfd", "pidfd_send_signal"].includes(opcode)
        ) {
          const fd = args.match(
            /^(0x[a-f0-9]+|[0-9]+)(?:<(?:[^>]|(?<=-)>)*>)?,/u,
          )?.[1];
          requireObservation(fd);
          target = "fd:" + Number(fd);
        } else if (
          [
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "kill",
            "tkill",
            "tgkill",
            "pidfd_open",
          ].includes(opcode)
        ) {
          const values = fields(args);
          const pid = (opcode === "ptrace" ? values[1] : values[0])?.trim();
          requireObservation(pid && /^(?:0x[a-f0-9]+|[1-9][0-9]*)$/u.test(pid));
          target = "process:" + Number(pid);
        } else if (
          [
            "shmget",
            "semget",
            "msgget",
            "shmat",
            "semop",
            "semctl",
            "msgsnd",
            "msgrcv",
          ].includes(opcode)
        ) {
          const key = args.match(/^((?:0x[a-f0-9]+|[0-9]+))[,)]/u)?.[1];
          requireObservation(key);
          target = "ipc:" + opcode + ":" + Number(key);
        } else if (["connect", "sendto", "sendmsg"].includes(opcode)) {
          const values = fields(args);
          let socket = values[opcode === "sendto" ? 4 : 1];
          if (opcode === "sendmsg") {
            requireObservation(socket?.startsWith("{") && socket.endsWith("}"));
            socket = fields(socket.slice(1, -1))
              .find((field) => field.startsWith("msg_name="))
              ?.slice(9);
          }
          requireObservation(typeof socket === "string");
          const port = socket.match(/sin(?:6)?_port=htons\(([0-9]+)\)/u)?.[1];
          const address = socket.match(
            /(?:inet_addr\(|inet_pton\(AF_INET6,\s*)"([a-fA-F0-9:.]+)"/u,
          )?.[1];
          target =
            port && address
              ? address + ":" + port
              : quoted(
                  socket.match(/sun_path=("(?:[^"\\]|\\.)*")/u)?.[1] ?? "",
                );
        } else if (["rename", "renameat", "renameat2"].includes(opcode)) {
          const values = fields(args);
          target = quoted(values[opcode === "rename" ? 1 : 3] ?? "");
        } else if (
          [
            "open",
            "openat",
            "openat2",
            "execve",
            "execveat",
            "unlink",
            "unlinkat",
            "mkdir",
            "mkdirat",
          ].includes(opcode)
        ) {
          target = quoted(
            fields(args)[
              ["openat", "openat2", "execveat", "unlinkat", "mkdirat"].includes(
                opcode,
              )
                ? 1
                : 0
            ] ?? "",
          );
        }
        if (!allowed.has(target)) return null;
        const result = Number(call[3]);
        requireObservation(Number.isSafeInteger(result));
        return {
          id: "linux:" + pid + ":" + prefix[3] + ":" + sequence,
          pid,
          opcode,
          target,
          result,
          errno: call[4] ?? null,
        };
      } catch (error) {
        failed = true;
        throw error;
      }
    },
    finish() {
      try {
        requireObservation(!failed && !finished && pending.size === 0);
        finished = true;
        return { bytes, complete: true };
      } catch (error) {
        failed = true;
        throw error;
      }
    },
  });
}
// strace runs with the admitted fixture from creation, never a late PID attach.
// Output is an inherited pipe, not -o/-ff files. The protected decoder resolves
// raw read/write FDs without dumping buffers; unfinished/resumed pairs must be
// joined by the reviewed decoder before they reach this boundary.

function normalizeInput(value) {
  observationObject(value, ["plan", "domain", "bindings", "pins"]);
  const plan = normalizeToolObservationPlan(value.plan),
    domain = value.domain;
  observationObject(domain, [
    "bootId",
    "namespaceId",
    "initPid",
    "initStartTicks",
  ]);
  requireObservation(
    typeof domain.bootId === "string" &&
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(domain.bootId) &&
      typeof domain.namespaceId === "string" &&
      domain.namespaceId.length <= 64 &&
      /^pid:\[[1-9][0-9]*\]$/u.test(domain.namespaceId) &&
      Number.isSafeInteger(domain.initPid) &&
      domain.initPid > 0 &&
      domain.initPid <= 2147483647 &&
      typeof domain.initStartTicks === "string" &&
      /^[1-9][0-9]{0,31}$/u.test(domain.initStartTicks),
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

export function linuxObserverConfiguration(value) {
  const input = normalizeInput(value);
  return {
    mechanism: "ptrace",
    fromCreation: true,
    followForkCloneExec: true,
    output: "protected-inherited-pipe",
    arguments: linuxObserverArguments(),
    bindings: input.bindings,
  };
}

/** Called only with records decoded by the protected native reader and a
 * separate identity/object reader. Unresolved objects and PID reuse fail. */
export function assertLinuxObserverEvent(raw, bound, value, binding) {
  const input = normalizeInput(value);
  observationObject(raw, ["id", "pid", "opcode", "target", "result", "errno"]);
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
  requireObservation(
    Number.isSafeInteger(raw.result) &&
      (raw.result >= 0
        ? raw.errno === null
        : ["EACCES", "EPERM", "EROFS"].includes(raw.errno) ||
          (["ENOENT", "ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH"].includes(
            raw.errno,
          ) &&
            bound.boundary?.independent === true &&
            bound.boundary.outsideControlReady === true &&
            bound.boundary.completeInventory === true &&
            bound.boundary.objectSha256 === bound.objectSha256 &&
            bound.boundary.domainSha256 === input.plan.domainSha256 &&
            bound.boundary.selector === binding.selector &&
            bound.boundary.nativeId === raw.id &&
            /^[a-f0-9]{64}$/u.test(bound.boundary.nativeEventSha256) &&
            /^[a-f0-9]{64}$/u.test(bound.boundary.controlSha256))),
  );
  for (const process of [bound.before, bound.after]) {
    observationObject(process, ["pid", "identity", "namespaceId"]);
    observationObject(process.identity, ["bootId", "startTicks"]);
    requireObservation(
      Number.isSafeInteger(process.pid) &&
        process.pid > 0 &&
        process.pid <= 2147483647 &&
        typeof process.identity.startTicks === "string" &&
        /^(?:0|[1-9][0-9]{0,31})$/u.test(process.identity.startTicks),
    );
  }
  requireObservation(
    bound.before.pid === raw.pid &&
      bound.after.pid === raw.pid &&
      sameLinuxIdentity(bound.before.identity, bound.after.identity) &&
      bound.before.identity.bootId === input.domain.bootId &&
      bound.before.namespaceId === input.domain.namespaceId &&
      bound.after.namespaceId === input.domain.namespaceId,
  );
  return raw.result >= 0 ? "permit" : "deny";
}

/** All native readers/setup are dedicated external CI effects. The existing
 * protected custody owner supplies these capabilities, never the provider.
 * No arbitrary exception message, native trace or selector is persisted. */
export async function runLinuxToolObserver(
  value,
  effects,
  execute,
  {
    platform = process.platform,
    architecture = process.arch,
    env = process.env,
    now = () => performance.now(),
  } = {},
) {
  const input = normalizeInput(value),
    { plan } = input;
  requireObservation(
    platform === "linux" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24" &&
      typeof effects?.persist === "function" &&
      typeof execute === "function",
  );
  const configuration = linuxObserverConfiguration(input);
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
      record.missingInputs.push("linux-observer-" + key);
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
      const outcome = assertLinuxObserverEvent(raw, bound, input, binding);
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
