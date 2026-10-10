import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import { posix, win32 } from "node:path";
import { fileURLToPath } from "node:url";

import {
  observationDigest,
  observationObject,
  requireObservation,
} from "./observation.js";
import { nativePreparationError } from "./first-failure.js";
import {
  createPosixPrerequisiteFiles,
  prerequisiteCreationRequest,
  PREREQUISITE_FILE_LIMITS,
} from "./prerequisite-files.js";
import {
  prerequisiteSourceSnapshot,
  prerequisiteWorkerEntry,
} from "./prerequisite-source.js";
import {
  normalizePrerequisiteAdmission,
  prerequisiteFrames,
  prerequisitePath,
  PREREQUISITE_WORKER_LIMITS,
} from "./prerequisite-worker.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const same = (left, right) =>
  observationDigest(left) === observationDigest(right);
const inside = (file, root) => file === root || file.startsWith(root + "/");
const limits = Object.freeze({
  recordBytes: 8388608,
  records: 65536,
  ledgerBytes: 1073741824,
  processes: 65536,
  cleanupMs: 30000,
  entryBytes: 120000,
});
const operations = new Set([
  "hold",
  "read-held",
  "release-read",
  "create",
  "create-begin",
  "create-chunk",
  "create-finish",
  "recover",
  "directory-create",
  "directory-read",
]);

function pin(value, platform) {
  observationObject(value, ["path", "bytes", "sha256"]);
  requireObservation(
    prerequisitePath(platform, value.path) &&
      Number.isSafeInteger(value.bytes) &&
      value.bytes > 0 &&
      value.bytes <= 536870912 &&
      typeof value.sha256 === "string" &&
      /^[a-f0-9]{64}$/u.test(value.sha256),
  );
}

/** Pure supplied-context admission; host identity and held bytes remain native
 * transport checks. Recovery validates the original time, never renews it. */
export function normalizePrerequisiteCustodyApproval(
  value,
  manifest,
  sources,
  now,
) {
  observationObject(value, [
    "output",
    "admission",
    "runtime",
    "privilege",
    "approvals",
  ]);
  const admission = normalizePrerequisiteAdmission(value.admission, now);
  const paths = admission.platform === "win32" ? win32 : posix;
  const lower = (file) =>
    admission.platform === "win32" ? file.toLowerCase() : file;
  const within = (file, root) =>
    lower(file) === lower(root) ||
    lower(file).startsWith(lower(root) + paths.sep);
  const { nonce: _nonce, expires: _expires, ...scope } = admission;
  observationObject(value.runtime, ["node", "dependencies"]);
  pin(value.runtime.node, admission.platform);
  requireObservation(
    Array.isArray(value.runtime.dependencies) &&
      value.runtime.dependencies.length <= 256,
  );
  for (const dependency of value.runtime.dependencies)
    pin(dependency, admission.platform);
  requireObservation(
    new Set(
      [value.runtime.node, ...value.runtime.dependencies].map(
        ({ path }) => path,
      ),
    ).size ===
      value.runtime.dependencies.length + 1,
  );
  observationObject(value.privilege, ["uid", "session", "worker"]);
  observationObject(value.approvals, [
    "sourceSha256",
    "runtimeSha256",
    "privilegeSha256",
    "scopeSha256",
    "manifestSha256",
  ]);
  requireObservation(
    admission.platform === manifest.platform &&
      prerequisitePath(admission.platform, value.output) &&
      within(value.output, admission.root) &&
      lower(value.output) !== lower(admission.root) &&
      admission.readRoots.some((root) => within(value.output, root)) &&
      !admission.writeRoots.some(
        (root) => within(value.output, root) || within(root, value.output),
      ) &&
      same(value.privilege, {
        uid: admission.controllerUid,
        session: "private",
        worker: "files-only",
      }) &&
      value.approvals.sourceSha256 === observationDigest(sources) &&
      value.approvals.runtimeSha256 === observationDigest(value.runtime) &&
      value.approvals.privilegeSha256 === observationDigest(value.privilege) &&
      value.approvals.scopeSha256 ===
        observationDigest({ ...scope, output: value.output }) &&
      value.approvals.manifestSha256 === observationDigest(manifest),
  );
  return structuredClone(value);
}

/** Fixed stock-host vectors only. Darwin files still require a native ACL owner;
 * Windows gateway/task release additionally requires the approved native verifier. */
export function prerequisiteTransportCommand(
  snapshot,
  admission,
  runtime,
  now = Date.now(),
) {
  observationObject(runtime, ["node", "dependencies"]);
  pin(runtime.node, admission.platform);
  requireObservation(
    Array.isArray(runtime.dependencies) && runtime.dependencies.length <= 256,
  );
  for (const dependency of runtime.dependencies)
    pin(dependency, admission.platform);
  requireObservation(
    new Set([runtime.node, ...runtime.dependencies].map(({ path }) => path))
      .size ===
      runtime.dependencies.length + 1,
  );
  requireObservation(admission.platform !== "win32");
  const entry = prerequisiteWorkerEntry(snapshot, admission, { now });
  requireObservation(Buffer.byteLength(entry) <= limits.entryBytes);
  const args = ["--input-type=module", "--eval", entry];
  if (admission.platform === "darwin") {
    for (const path of ["/usr/bin/sudo", "/usr/bin/env"])
      requireObservation(
        runtime.dependencies.some((member) => member.path === path),
      );
    return {
      file: "/usr/bin/sudo",
      args: ["-n", "/usr/bin/env", "-i", runtime.node.path, ...args],
    };
  }
  return { file: runtime.node.path, args };
}

// Procfs is the independent observer, never worker output or child exit status.
// No signalling occurs here: a PID check followed by kill would permit PID reuse.
function linuxObserver(fs, observerPid, check) {
  const read = async (file, maximum = 65536) => {
    check();
    const handle = await fs.open(file, constants.O_RDONLY);
    try {
      const bytes = Buffer.alloc(maximum + 1);
      let offset = 0;
      while (offset < bytes.length) {
        check();
        const { bytesRead } = await handle.read(
          bytes,
          offset,
          bytes.length - offset,
          offset,
        );
        requireObservation(
          Number.isSafeInteger(bytesRead) &&
            bytesRead >= 0 &&
            bytesRead <= bytes.length - offset,
        );
        if (!bytesRead) break;
        offset += bytesRead;
      }
      requireObservation(offset <= maximum);
      return bytes.subarray(0, offset);
    } finally {
      await handle.close();
    }
  };
  const stat = (bytes) => {
    const text = bytes.toString("utf8"),
      end = text.lastIndexOf(")");
    requireObservation(end > 1);
    const fields = text
        .slice(end + 2)
        .trim()
        .split(/\s+/u),
      pid = Number(text.slice(0, text.indexOf(" ")));
    requireObservation(
      Number.isSafeInteger(pid) &&
        pid > 0 &&
        fields.length >= 20 &&
        /^[1-9][0-9]*$/u.test(fields[19]),
    );
    const [parent, group, session] = fields.slice(1, 4).map(Number);
    requireObservation(
      [parent, group, session].every(
        (value) => Number.isSafeInteger(value) && value >= 0,
      ),
    );
    return { pid, parent, group, session, startTicks: fields[19] };
  };
  const control = async () => {
    const bootId = (await read("/proc/sys/kernel/random/boot_id"))
        .toString()
        .trim(),
      namespace = await fs.readlink("/proc/self/ns/pid"),
      initNamespace = await fs.readlink("/proc/1/ns/pid"),
      self = stat(await read("/proc/self/stat")),
      init = stat(await read("/proc/1/stat")),
      mounts = (await read("/proc/self/mountinfo", 1048576))
        .toString()
        .trim()
        .split("\n")
        .map((line) => line.split(" ")),
      proc = mounts.filter((fields) => fields[4] === "/proc"),
      mount = proc[0],
      separator = mount?.indexOf("-");
    requireObservation(
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(bootId) &&
        /^pid:\[[0-9]+\]$/u.test(namespace) &&
        namespace === initNamespace &&
        self.pid === observerPid &&
        init.pid === 1 &&
        proc.length === 1 &&
        mount[3] === "/" &&
        separator >= 6 &&
        mount[separator + 1] === "proc" &&
        ![mount[5], mount[separator + 3]].some((options) =>
          options
            .split(",")
            .some(
              (option) =>
                option.startsWith("hidepid=") &&
                !["hidepid=0", "hidepid=off"].includes(option),
            ),
        ) &&
        !mounts.some((fields) => /^\/proc\/[0-9]+(?:\/|$)/u.test(fields[4])),
    );
    return { bootId, namespace, controller: self };
  };
  const process = async (pid, controls) => {
    const base = `/proc/${pid}`;
    const before = stat(await read(base + "/stat")),
      status = (await read(base + "/status")).toString(),
      uid = status.match(
        /^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$/mu,
      ),
      after = stat(await read(base + "/stat"));
    requireObservation(
      before.pid === pid &&
        same(before, after) &&
        uid &&
        uid.slice(1).every((value) => Number.isSafeInteger(Number(value))),
    );
    return {
      ...before,
      uid: Number(uid[1]),
      uids: uid.slice(1).map(Number),
      bootId: controls.bootId,
      namespace: controls.namespace,
    };
  };
  const census = async (request, birth = null) => {
    const before = await control(),
      names = await fs.readdir("/proc");
    requireObservation(names.length <= limits.processes);
    const ids = names.filter((name) => /^[1-9][0-9]*$/u.test(name)).sort(),
      members = [],
      entries = [];
    for (const name of ids) {
      const observed = await process(Number(name), before);
      entries.push(observed);
      if (observed.uid === request.admission.controllerUid) {
        const argv = await read(
          `/proc/${name}/cmdline`,
          limits.entryBytes + 4096,
        );
        if (
          argv.equals(
            Buffer.from(
              [request.command.file, ...request.command.args, ""].join("\0"),
            ),
          )
        )
          members.push(observed);
      }
    }
    if (birth) {
      const parents = new Set([birth.pid]);
      for (let changed = true; changed;) {
        changed = false;
        for (const entry of entries)
          if (parents.has(entry.parent) && !parents.has(entry.pid)) {
            parents.add(entry.pid);
            changed = true;
          }
      }
      for (const entry of entries)
        if (
          (entry.session === birth.session || parents.has(entry.pid)) &&
          !members.some((member) => member.pid === entry.pid)
        )
          members.push(entry);
    }
    const afterNames = (await fs.readdir("/proc"))
        .filter((name) => /^[1-9][0-9]*$/u.test(name))
        .sort(),
      after = await control();
    requireObservation(
      same(ids, afterNames) &&
        before.bootId === after.bootId &&
        before.namespace === after.namespace &&
        request.control.bootId === after.bootId &&
        request.control.namespace === after.namespace,
    );
    const current = birth && entries.find((entry) => entry.pid === birth.pid);
    return {
      control: after,
      members,
      birthState: current
        ? same(current, birth)
          ? "live"
          : "reused"
        : "absent",
    };
  };
  return {
    control,
    census,
    async birth(pid, request, nodeIdentity) {
      const controls = await control(),
        observed = await process(pid, controls),
        namespace = await fs.readlink(`/proc/${pid}/ns/pid`),
        image = await fs.stat(`/proc/${pid}/exe`, { bigint: true }),
        argv = await read(`/proc/${pid}/cmdline`, limits.entryBytes + 4096);
      requireObservation(
        controls.bootId === request.control.bootId &&
          controls.namespace === request.control.namespace &&
          observed.uids.every(
            (uid) => uid === request.admission.controllerUid,
          ) &&
          observed.parent === request.control.controller.pid &&
          observed.group === pid &&
          observed.session === pid &&
          namespace === controls.namespace &&
          String(image.dev) === nodeIdentity.dev &&
          String(image.ino) === nodeIdentity.ino &&
          argv.equals(
            Buffer.from(
              [request.command.file, ...request.command.args, ""].join("\0"),
            ),
          ),
      );
      return observed;
    },
  };
}

/** Reconstruct the separately approved owner from held intent and creation
 * identities. Closing cannot replace uncertain retirement or the first cause. */
export async function recoverPrerequisiteTransport(input, intent, options) {
  const owner = createPrerequisiteTransport(input, options);
  let proof, primary;
  try {
    proof = await owner.recover(intent);
  } catch (error) {
    primary = error;
  }
  try {
    await owner.close();
  } catch (error) {
    primary ??= error;
  }
  if (primary) throw primary;
  return proof;
}

/** Effect-free construction. Approved inputs are data; only raw filesystem and
 * process edges are replaceable. No acquired helper, PATH lookup, compiler,
 * extraction, credential or provider operation is enabled by this owner. */
export function createPrerequisiteTransport(
  input,
  {
    fs = filesystem,
    spawnProcess = spawn,
    platform = process.platform,
    uid = process.getuid?.(),
    pid = process.pid,
    execPath = process.execPath,
    clock = Date.now,
    signal,
    windowsReader,
  } = {},
) {
  const value = structuredClone(input),
    admission = normalizePrerequisiteAdmission(
      value.admission,
      Math.min(clock(), value.admission.expires - 1),
    );
  const { nonce: _nonce, expires: _expires, ...scope } = admission;
  requireObservation(
    value.job?.platform === admission.platform &&
      value.manifest?.platform === admission.platform &&
      value.manifest.candidateSha === value.job.candidateSha &&
      /^[a-f0-9]{40}$/u.test(value.job.candidateSha) &&
      prerequisitePath(admission.platform, value.output),
  );
  let files,
    snapshot,
    sources,
    command,
    request,
    requestSha256,
    birth,
    child,
    frames,
    completion,
    starting,
    launching,
    closing,
    recovering,
    windowsSettlement,
    windowsVerifier,
    windowsIntent,
    primary,
    failed = false,
    fenced = false,
    retired,
    recoveryReady = true,
    recoveryRecords = false,
    unidentifiedRelease = false,
    sequence = 0,
    ledgerBytes = 0,
    observationDeadline = admission.expires,
    tail = Promise.resolve();
  const handles = new Set(),
    parents = new Map();
  const pathFor = (suffix) =>
    posix.join(
      value.output,
      `prerequisite-custody-${admission.nonce}-${suffix}.json`,
    );
  const guard = () =>
    requireObservation(
      !fenced && !signal?.aborted && clock() < admission.expires,
    );
  const fail = (error) => {
    if (!failed) {
      failed = true;
      primary = error;
    }
    fenced = true;
  };
  const disconnect = () => {
    for (const stream of [child?.stdin, child?.stdout, child?.stderr])
      stream?.destroy();
  };
  const bounded = async (work, cleanup = false) => {
    // A deadline may already be exhausted while an owned promise rejects.
    // Observe it even when admission below refuses to wait for it.
    Promise.resolve(work).catch(() => {});
    const left = (cleanup ? observationDeadline : admission.expires) - clock();
    requireObservation(left > 0 && (cleanup || !signal?.aborted));
    let timer, aborted;
    try {
      return await Promise.race([
        work,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(nativePreparationError("deadline")),
            left,
          );
          if (!cleanup && signal) {
            aborted = () => reject(signal.reason);
            signal.addEventListener("abort", aborted, { once: true });
            if (signal.aborted) aborted();
          }
        }),
      ]);
    } finally {
      clearTimeout(timer);
      if (aborted) signal.removeEventListener("abort", aborted);
    }
  };
  const observer = linuxObserver(fs, pid, () =>
    requireObservation(clock() < observationDeadline),
  );
  const checkParents = async () => {
    const chain = [];
    for (let current = value.output; ; current = posix.dirname(current)) {
      chain.unshift(current);
      requireObservation(chain.length <= 64);
      if (current === "/") break;
    }
    for (const directory of chain) {
      let entry = parents.get(directory);
      if (!entry) {
        requireObservation((await fs.realpath(directory)) === directory);
        const handle = await fs.open(
          directory,
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
        );
        handles.add(handle);
        entry = { handle, stat: await handle.stat({ bigint: true }) };
        parents.set(directory, entry);
      }
      const held = await entry.handle.stat({ bigint: true }),
        named = await fs.lstat(directory, { bigint: true });
      requireObservation(
        held.isDirectory() &&
          named.isDirectory() &&
          held.dev === named.dev &&
          held.ino === named.ino &&
          held.dev === entry.stat.dev &&
          held.ino === entry.stat.ino &&
          held.uid === named.uid &&
          held.mode === named.mode &&
          [0n, BigInt(uid)].includes(held.uid) &&
          !(held.mode & 0o22n) &&
          (!inside(directory, admission.root) ||
            (held.uid === BigInt(uid) && !(held.mode & 0o77n))),
      );
    }
  };
  const publish = async (file, record) => {
    const bytes = Buffer.from(JSON.stringify(record) + "\n");
    requireObservation(
      bytes.length <= limits.recordBytes &&
        ++sequence <= limits.records &&
        ledgerBytes + bytes.length <= limits.ledgerBytes,
    );
    ledgerBytes += bytes.length;
    await checkParents();
    const writer = await fs.open(
      file,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_RDWR |
        constants.O_NOFOLLOW,
      0o600,
    );
    handles.add(writer);
    const born = await writer.stat({ bigint: true }),
      named = await fs.lstat(file, { bigint: true });
    requireObservation(
      born.isFile() &&
        named.isFile() &&
        born.nlink === 1n &&
        born.uid === BigInt(uid) &&
        !(born.mode & 0o77n) &&
        ["dev", "ino", "uid", "mode", "nlink"].every(
          (key) => born[key] === named[key],
        ),
    );
    await writer.writeFile(bytes);
    await writer.sync();
    await writer.chmod(0o400);
    const observed = await files.hold(file, {
      maximum: bytes.length,
      sealed: true,
    });
    requireObservation(
      observed.bytes.equals(bytes) &&
        observed.identity.dev === String(born.dev) &&
        observed.identity.ino === String(born.ino),
    );
    await writer.close();
    handles.delete(writer);
    await parents.get(value.output).handle.sync();
    await checkParents();
    return { file, bytes: bytes.length, sha256: hash(bytes) };
  };
  const prepare = async () => {
    // Fail before filesystem, elevation, gateway or task effects on unsupported
    // owners. Windows release still requires its protected preparation owner.
    requireObservation(platform === admission.platform && platform === "linux");
    requireObservation(
      uid === admission.controllerUid &&
        Number.isSafeInteger(pid) &&
        pid > 0 &&
        inside(value.output, admission.root) &&
        value.output !== admission.root &&
        admission.readRoots.some((root) => inside(value.output, root)) &&
        !admission.writeRoots.some(
          (root) => inside(value.output, root) || inside(root, value.output),
        ),
    );
    files ??= createPosixPrerequisiteFiles({
      root: admission.root,
      ownerUid: uid,
      controllerUid: uid,
      fs,
      platform,
    });
    const readSource = async (name) => {
      const file = fileURLToPath(new URL(name, import.meta.url), {
          windows: platform === "win32",
        }),
        citations = value.manifest.source.citations.filter(
          (entry) =>
            entry.kind === "reached-code" &&
            entry.member === "candidate/ci/native/" + name,
        ),
        stat = await fs.lstat(file, { bigint: true });
      requireObservation(citations.length === 1);
      requireObservation(stat.size > 0n && stat.size <= 1048576n);
      const held = await files.hold(file, { maximum: Number(stat.size) });
      requireObservation(hash(held.bytes) === citations[0].sha256);
      return held.bytes;
    };
    const captured = await prerequisiteSourceSnapshot(
      value.manifest,
      readSource,
    );
    requireObservation(
      !snapshot ||
        (snapshot.sha256 === captured.sha256 &&
          same(snapshot.sources, captured.sources)),
    );
    snapshot ??= captured;
    sources = [...snapshot.sources];
    for (const name of [
      "first-failure.js",
      "prerequisite-source.js",
      "prerequisite-transport.js",
    ]) {
      const bytes = await readSource(name);
      sources.push({ name, bytes: bytes.length, sha256: hash(bytes) });
    }
    command ??= prerequisiteTransportCommand(
      snapshot,
      admission,
      value.runtime,
      Math.min(clock(), admission.expires - 1),
    );
    normalizePrerequisiteCustodyApproval(
      Object.fromEntries(
        ["output", "admission", "runtime", "privilege", "approvals"].map(
          (key) => [key, value[key]],
        ),
      ),
      value.manifest,
      sources,
      Math.min(clock(), admission.expires - 1),
    );
    requireObservation(
      value.runtime.node.path === execPath &&
        same(value.privilege, {
          uid,
          session: "private",
          worker: "files-only",
        }),
    );
    let node;
    for (const pin of [value.runtime.node, ...value.runtime.dependencies]) {
      const held = await files.hold(pin.path, { maximum: pin.bytes });
      requireObservation(
        held.bytes.length === pin.bytes && hash(held.bytes) === pin.sha256,
      );
      if (pin.path === value.runtime.node.path) node = held;
    }
    await checkParents();
    return node;
  };
  const expected = (control) => ({
    schemaVersion: 1,
    phase: "prerequisite-custody",
    job: value.job,
    manifestSha256: observationDigest(value.manifest),
    admission,
    output: value.output,
    source: sources,
    runtime: value.runtime,
    privilege: value.privilege,
    approvals: value.approvals,
    command,
    options: {
      cwd: value.output,
      env: {},
      detached: true,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
    },
    control,
  });
  const rpc = async (operation, args = [], cleanup = false) => {
    if (!cleanup) guard();
    const id = ++nextId,
      frame = {
        id,
        nonce: admission.nonce,
        operation,
        args: structuredClone(args),
      };
    requireObservation(
      Buffer.byteLength(JSON.stringify(frame)) <=
        PREREQUISITE_WORKER_LIMITS.frameBytes,
    );
    await publish(pathFor(`${id}-operation`), {
      schemaVersion: 1,
      requestSha256,
      frame,
    });
    if (!cleanup) guard();
    const work = async () => {
      await new Promise((resolve, reject) =>
        child.stdin.write(JSON.stringify(frame) + "\n", (error) =>
          error ? reject(error) : resolve(),
        ),
      );
      const next = await frames.next();
      requireObservation(!next.done);
      observationObject(next.value, ["id", "nonce", "result"]);
      requireObservation(
        next.value.id === id && next.value.nonce === admission.nonce,
      );
      return next.value.result;
    };
    const result = await bounded(work(), cleanup);
    if (!cleanup) guard();
    return result;
  };
  let nextId = 0;
  const start = async () => {
    guard();
    const node = await prepare();
    guard();
    const control = await observer.control();
    request = expected(control);
    requestSha256 = observationDigest(request);
    await publish(pathFor("intent"), request);
    guard();
    // Recheck retained source/tool bytes after intent durability and immediately
    // before release. No image found in a downloaded asset can become a host.
    await prepare();
    guard();
    child = spawnProcess(
      command.file,
      command.args,
      structuredClone(request.options),
    );
    const spawned = new Promise((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", reject);
    });
    completion = new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    completion.catch(() => {});
    const streamFailure = (error) => {
      fail(error);
      disconnect();
    };
    for (const stream of [child, child.stdin, child.stdout, child.stderr])
      stream.on("error", streamFailure);
    child.stderr.resume();
    frames = prerequisiteFrames(child.stdout)[Symbol.asyncIterator]();
    await bounded(spawned);
    requireObservation(Number.isSafeInteger(child.pid) && child.pid > 0);
    birth = await observer.birth(child.pid, request, node.identity);
    await publish(pathFor("birth"), { schemaVersion: 1, requestSha256, birth });
    guard();
    const initialized = await rpc("init", [admission]);
    requireObservation(
      initialized.pid === birth.pid && initialized.platform === platform,
    );
    return {
      requestSha256,
      birth: structuredClone(birth),
      intent: pathFor("intent"),
    };
  };
  const ensure = async () => {
    guard();
    return (starting ??= bounded((launching = start())).catch((error) => {
      fail(error);
      disconnect();
      throw error;
    }));
  };
  const enqueue = (work) => {
    const running = tail.then(() => {
      guard();
      return work();
    });
    const result = bounded(running).catch((error) => {
      fail(error);
      disconnect();
      throw error;
    });
    // A timed-out filesystem call may still finish. Retain its raw promise so
    // cleanup cannot close descriptors while an owned operation is unresolved.
    tail = running.catch(() => {});
    return result;
  };
  const invoke = (operation, args = []) => {
    requireObservation(operations.has(operation));
    args = structuredClone(args);
    return enqueue(async () => {
      await ensure();
      guard();
      return rpc(operation, args);
    });
  };
  const settle = async () => {
    requireObservation(recoveryReady && !unidentifiedRelease);
    const possible =
      birth ?? (child ? { pid: child.pid, session: child.pid } : null);
    const before = await observer.census(request, possible),
      after = await observer.census(request, possible);
    requireObservation(
      before.birthState === "absent" &&
        after.birthState === "absent" &&
        before.members.length === 0 &&
        after.members.length === 0,
    );
    const proof = {
      status: "RETIRED",
      requestSha256,
      independent: true,
      noLiveMembers: true,
      emergencyCleanup: false,
      nativeEventSha256: observationDigest({ before, after }),
    };
    await publish(pathFor("completion"), {
      schemaVersion: 1,
      requestSha256,
      birth: birth ?? null,
      settlement: proof,
    });
    requireObservation(clock() < observationDeadline);
    retired = proof;
    return proof;
  };
  const release = async () => {
    await files?.close();
    for (const handle of handles) {
      await handle.close();
      handles.delete(handle);
    }
  };
  return {
    start: () => ensure(),
    invoke,
    createDirectory(file) {
      requireObservation(
        platform === "linux" &&
          prerequisitePath(platform, file) &&
          admission.writeRoots.some((root) => inside(file, root)),
      );
      return enqueue(async () => {
        await ensure();
        const request = {
          schemaVersion: 1,
          operation: "directory-create",
          root: admission.root,
          file,
        };
        const intent = await publish(
          pathFor(`${nextId + 1}-directory`),
          request,
        );
        return rpc("directory-create", [file, intent]);
      });
    },
    directory: (file) => invoke("directory-read", [file]),
    persist(record) {
      record = structuredClone(record);
      return enqueue(async () => {
        await prepare();
        guard();
        const pin = await publish(
          pathFor(`record-${sequence + 1}-${observationDigest(record)}`),
          record,
        );
        const observed = await files.hold(pin.file, {
          maximum: pin.bytes,
          sealed: true,
        });
        requireObservation(hash(observed.bytes) === pin.sha256);
        return {
          ...pin,
          recordSha256: observationDigest(record),
          independent: true,
          held: true,
          immutable: true,
          protectedParents: true,
          birthProtected: true,
          identitySha256: observationDigest(observed.identity),
          nativeEventSha256: observationDigest(observed.event),
        };
      });
    },
    readRecord(expected) {
      expected = structuredClone(expected);
      pin(expected, platform);
      requireObservation(
        !starting &&
          !request &&
          !recovering &&
          !closing &&
          !failed &&
          posix.dirname(expected.path) === value.output &&
          expected.bytes <= limits.recordBytes,
      );
      // Reconstruction reads must survive an expired worker admission. Fence
      // release before the first read and share one budget with kernel recovery.
      if (!recoveryRecords) observationDeadline = clock() + limits.cleanupMs;
      recoveryRecords = true;
      fenced = true;
      const running = tail.then(async () => {
        requireObservation(clock() < observationDeadline);
        await prepare();
        const observed = await files.hold(expected.path, {
          maximum: expected.bytes,
          sealed: true,
        });
        requireObservation(
          observed.bytes.length === expected.bytes &&
            hash(observed.bytes) === expected.sha256 &&
            clock() < observationDeadline,
        );
        return JSON.parse(observed.bytes.toString("utf8"));
      });
      tail = running.catch(() => {});
      return bounded(running, true).catch((error) => {
        fail(error);
        throw primary;
      });
    },
    create(file, input, { executable = false } = {}) {
      requireObservation(
        input instanceof Uint8Array &&
          input.length <= PREREQUISITE_FILE_LIMITS.bytes,
      );
      const bytes = Buffer.from(input);
      return enqueue(async () => {
        await ensure();
        guard();
        const creation = prerequisiteCreationRequest(
            admission.root,
            file,
            bytes,
            executable,
          ),
          intent = await publish(pathFor(`${nextId + 1}-creation`), creation);
        if (bytes.length <= PREREQUISITE_WORKER_LIMITS.chunkBytes)
          return rpc("create", [
            file,
            { nativeBytes: bytes.toString("base64") },
            { executable, intent },
          ]);
        await rpc("create-begin", [creation, { executable, intent }]);
        for (
          let offset = 0;
          offset < bytes.length;
          offset += PREREQUISITE_WORKER_LIMITS.chunkBytes
        )
          await rpc("create-chunk", [
            offset,
            {
              nativeBytes: bytes
                .subarray(
                  offset,
                  offset + PREREQUISITE_WORKER_LIMITS.chunkBytes,
                )
                .toString("base64"),
            },
          ]);
        return rpc("create-finish");
      });
    },
    hold(file, { maximum, sealed = true } = {}) {
      requireObservation(
        Number.isSafeInteger(maximum) &&
          maximum > 0 &&
          maximum <= PREREQUISITE_FILE_LIMITS.bytes &&
          typeof sealed === "boolean",
      );
      return enqueue(async () => {
        await ensure();
        guard();
        const proof = await rpc("hold", [file, { maximum, sealed }]);
        requireObservation(
          Number.isSafeInteger(proof.bytesLength) &&
            proof.bytesLength >= 0 &&
            proof.bytesLength <= maximum,
        );
        const bytes = Buffer.alloc(proof.bytesLength);
        for (
          let offset = 0;
          offset < bytes.length;
          offset += PREREQUISITE_WORKER_LIMITS.chunkBytes
        ) {
          const count = Math.min(
              PREREQUISITE_WORKER_LIMITS.chunkBytes,
              bytes.length - offset,
            ),
            result = await rpc("read-held", [proof.readId, offset, count]);
          observationObject(result, ["nativeBytes"]);
          requireObservation(
            typeof result.nativeBytes === "string" &&
              result.nativeBytes.length <= 43692,
          );
          const chunk = Buffer.from(result.nativeBytes, "base64");
          requireObservation(
            chunk.length === count &&
              chunk.toString("base64") === result.nativeBytes,
          );
          chunk.copy(bytes, offset);
        }
        await rpc("release-read", [proof.readId]);
        requireObservation(hash(bytes) === proof.event?.sha256);
        return { ...proof, bytes };
      });
    },
    async close() {
      fenced = true;
      if (platform === "win32") {
        try {
          if (recovering)
            await bounded(
              recovering.catch(() => {}),
              true,
            );
          if (failed) throw primary;
          requireObservation(windowsSettlement);
          windowsSettlement = await bounded(
            windowsVerifier.recoverPrerequisite(
              value.windowsRequest,
              windowsIntent,
              value.windowsBirth,
            ),
            true,
          );
          // Preparation still owns the independent reader and its held objects.
          // This proof retires the exact worker/task, never the live verifier.
          return {
            ...windowsSettlement,
            closed: true,
            custodianRetired: true,
            verifierRetired: false,
          };
        } catch (error) {
          fail(error);
          throw primary;
        }
      }
      if (!closing) {
        if (!recovering) observationDeadline = clock() + limits.cleanupMs;
        closing = (async () => {
          try {
            if (recovering)
              await bounded(
                recovering.catch(() => {}),
                true,
              );
            if (starting)
              await bounded(
                starting.catch(() => {}),
                true,
              );
            if (launching)
              await bounded(
                launching.catch(() => {}),
                true,
              );
            await bounded(tail, true);
            if (retired) {
              await release();
              if (failed) throw primary;
              return retired;
            }
            if (!request) {
              await release();
              if (failed) throw primary;
              return { status: "CLOSED", custodianRetired: false };
            }
            if (child && !failed) {
              const acknowledged = await rpc("close", [], true);
              requireObservation(
                acknowledged.status === "CLOSED" &&
                  acknowledged.custodianRetired === false,
              );
              child.stdin.end();
              const exit = await bounded(completion, true);
              requireObservation(exit.code === 0 && exit.signal === null);
            } else if (child) {
              // Drain a disconnected owner before the independent observation. Its
              // exit result grants nothing and never replaces the first failure.
              await bounded(
                completion.catch(() => null),
                true,
              );
            }
            await settle();
            await release();
          } catch (error) {
            fail(error);
            disconnect();
          }
          if (failed) throw primary;
          return retired;
        })();
        const pending = closing;
        pending
          .finally(() => {
            if (closing === pending) closing = undefined;
          })
          .catch(() => {});
      }
      try {
        return await bounded(closing, true);
      } catch (error) {
        fail(error);
        disconnect();
        throw primary;
      }
    },
    async recover(intent) {
      requireObservation(!starting && !request && !recovering && !closing);
      fenced = true;
      recoveryReady = false;
      if (!recoveryRecords) observationDeadline = clock() + limits.cleanupMs;
      recovering = (async () => {
        try {
          intent = structuredClone(intent);
          observationObject(intent, ["file", "bytes", "sha256"]);
          pin(
            { path: intent.file, bytes: intent.bytes, sha256: intent.sha256 },
            platform,
          );
          await bounded(tail, true);
          if (platform === "win32") {
            const within = (file, root) =>
              file.toLowerCase() === root.toLowerCase() ||
              file.toLowerCase().startsWith(root.toLowerCase() + "\\");
            requireObservation(
              intent.bytes <= limits.recordBytes &&
                within(value.output, admission.root) &&
                value.output.toLowerCase() !== admission.root.toLowerCase() &&
                admission.readRoots.some((root) =>
                  within(value.output, root),
                ) &&
                !admission.writeRoots.some(
                  (root) =>
                    within(value.output, root) || within(root, value.output),
                ) &&
                intent.file ===
                  win32.join(
                    value.output,
                    `prerequisite-custody-${admission.nonce}-intent.json`,
                  ) &&
                admission.platform === "win32" &&
                value.windowsRequest &&
                value.windowsBirth &&
                value.windowsBirth.file ===
                  win32.join(
                    value.output,
                    `prerequisite-custody-${admission.nonce}-birth.json`,
                  ) &&
                same(value.windowsRequest.job, value.job) &&
                same(value.windowsRequest.admission, admission) &&
                value.windowsRequest.output === value.output &&
                same(value.windowsRequest.approvals, value.approvals) &&
                value.approvals.manifestSha256 ===
                  observationDigest(value.manifest) &&
                value.windowsRequest.manifestSha256 ===
                  value.approvals.manifestSha256 &&
                value.approvals.sourceSha256 ===
                  observationDigest(value.windowsRequest.source) &&
                value.approvals.runtimeSha256 ===
                  observationDigest(value.runtime) &&
                value.approvals.privilegeSha256 ===
                  observationDigest(value.privilege) &&
                same(value.windowsRequest.privilege, value.privilege) &&
                value.approvals.scopeSha256 ===
                  observationDigest({ ...scope, output: value.output }),
            );
            const { createWindowsCustodyVerifier } =
              await import("./win32/index.js");
            windowsVerifier = createWindowsCustodyVerifier(windowsReader, {
              clock,
              deadline: observationDeadline,
            });
            windowsIntent = intent;
            windowsSettlement = await windowsVerifier.recoverPrerequisite(
              value.windowsRequest,
              intent,
              value.windowsBirth,
            );
            requireObservation(clock() < observationDeadline);
            return windowsSettlement;
          }
          requireObservation(
            intent.file === pathFor("intent") &&
              intent.bytes <= limits.recordBytes,
          );
          await prepare();
          const held = await files.hold(intent.file, {
            maximum: intent.bytes,
            sealed: true,
          });
          requireObservation(
            held.bytes.length === intent.bytes &&
              hash(held.bytes) === intent.sha256,
          );
          request = JSON.parse(held.bytes.toString("utf8"));
          requestSha256 = observationDigest(request);
          requireObservation(same(request, expected(request.control)));
          try {
            const heldBirth = await files.hold(pathFor("birth"), {
                maximum: limits.recordBytes,
                sealed: true,
              }),
              record = JSON.parse(heldBirth.bytes.toString("utf8"));
            observationObject(record, [
              "schemaVersion",
              "requestSha256",
              "birth",
            ]);
            requireObservation(
              record.schemaVersion === 1 &&
                record.requestSha256 === requestSha256,
            );
            birth = record.birth;
            observationObject(birth, [
              "pid",
              "parent",
              "group",
              "session",
              "startTicks",
              "uid",
              "uids",
              "bootId",
              "namespace",
            ]);
            requireObservation(
              Number.isSafeInteger(birth.pid) &&
                birth.pid > 0 &&
                birth.session === birth.pid &&
                birth.group === birth.pid &&
                birth.parent === request.control.controller.pid &&
                typeof birth.startTicks === "string" &&
                /^[1-9][0-9]*$/u.test(birth.startTicks) &&
                birth.uid === uid &&
                Array.isArray(birth.uids) &&
                birth.uids.length === 4 &&
                birth.uids.every((item) => item === uid) &&
                birth.bootId === request.control.bootId &&
                birth.namespace === request.control.namespace,
            );
          } catch (error) {
            if (error?.code !== "ENOENT") throw error;
          }
          // A lost birth record after possible init release cannot identify all
          // possible members. A matching completion or empty scan cannot repair it.
          if (!birth) {
            try {
              await fs.lstat(pathFor("1-operation"));
              unidentifiedRelease = true;
            } catch (error) {
              if (error?.code !== "ENOENT") throw error;
            }
          }
          recoveryReady = true;
          const before = await observer.census(request, birth),
            after = await observer.census(request, birth);
          const absent =
            !unidentifiedRelease &&
            before.birthState === "absent" &&
            after.birthState === "absent" &&
            before.members.length === 0 &&
            after.members.length === 0;
          const proof = {
            status: absent ? "RETIRED" : "RETAINED",
            requestSha256,
            independent: true,
            noLiveMembers: absent,
            emergencyCleanup: false,
            nativeEventSha256: observationDigest({ before, after }),
          };
          if (absent) {
            await publish(
              pathFor(`recovery-${randomBytes(16).toString("hex")}`),
              {
                schemaVersion: 1,
                requestSha256,
                birth: birth ?? null,
                settlement: proof,
              },
            );
            requireObservation(clock() < observationDeadline);
            retired = proof;
            await release();
          }
          return proof;
        } catch (error) {
          fail(error);
          throw primary;
        }
      })();
      const pending = recovering;
      pending
        .finally(() => {
          if (recovering === pending) recovering = undefined;
        })
        .catch(() => {});
      try {
        return await bounded(pending, true);
      } catch (error) {
        fail(error);
        throw primary;
      }
    },
  };
}
