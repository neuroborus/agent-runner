import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import {
  lstat,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import {
  assertOwnedProcessLauncherProtected,
  resolveOwnedProcessLauncher,
} from "../../../src/agents/index.js";
import { requireObservation } from "../index.js";
import { assertLinuxProcVisibility } from "./inspect.js";
import {
  assertLinuxNamespacePreparation,
  initialLinuxNamespacePreparation,
  linuxNamespaceDenials,
  linuxNamespaceLabel,
  linuxNamespacePolicyDecision,
  linuxNamespaceProfile,
  linuxNamespaceProfileName,
  linuxNamespaceProfileMembership,
  linuxNamespaceTracePids,
  linuxNamespaceProbeOutcome,
  linuxNamespaceObservationFailure,
  linuxNamespacePreparationCause,
  LINUX_NAMESPACE_CLEANUP_BLOCKER,
  LINUX_NAMESPACE_CAPTURE_CLEANUP_BLOCKER,
  namespaceDigest,
  normalizeLinuxNamespaceObservation,
  normalizeLinuxNamespacePreparation,
} from "./namespace-policy.js";

const ENV = Object.freeze({ PATH: "/usr/bin:/bin", LANG: "C" });
const ABI = "/etc/apparmor.d/abi/4.0";
const PROFILE_LIST = "/sys/kernel/security/apparmor/profiles";
const OPTIONS = Object.freeze({
  timeout: 10000,
  maxBuffer: 65536,
  encoding: "utf8",
  env: ENV,
});

function namespaceCommand(
  file,
  args,
  privileged,
  input,
  {
    execute = spawnSync,
    protect = assertOwnedProcessLauncherProtected,
    now = () => performance.now(),
    deadline = Infinity,
    encoding = "utf8",
  } = {},
) {
  requireObservation(now() < deadline);
  for (const image of privileged
    ? [file, "/usr/bin/sudo", "/usr/bin/timeout"]
    : [file])
    protect(image);
  return execute(
    privileged ? "/usr/bin/sudo" : file,
    privileged
      ? [
          "--non-interactive",
          "--",
          "/usr/bin/timeout",
          "--signal=TERM",
          "--kill-after=2s",
          "8s",
          file,
          ...args,
        ]
      : args,
    { ...OPTIONS, timeout: 12000, encoding, ...(input ? { input } : {}) },
  );
}

const JOURNAL_CURSOR = /^[\x21-\x7e]{1,512}$/u;
function journalDiagnosis(stderr) {
  if (
    /^(?:journalctl|\/usr\/bin\/journalctl): (?:unrecognized option|invalid option)/mu.test(
      stderr,
    )
  )
    return "journal-command-rejected";
  if (
    /^sudo: (?:a password is required|.*not allowed to execute|.*not in the sudoers file)/mu.test(
      stderr,
    ) ||
    /^(?:No journal files were opened due to insufficient permissions\.|Failed to (?:open|read) (?:journal|journal files): Permission denied)/mu.test(
      stderr,
    )
  )
    return "journal-authority-unavailable";
  if (/^No journal files were found\.$/mu.test(stderr))
    return "journal-unavailable";
  if (/^Failed to (?:get|seek to|test) cursor\b/mu.test(stderr))
    return "journal-cursor-unavailable";
  return null;
}

/** Keep the cursor private and opaque. Only complete journalctl output can
 * bracket a probe; injected commands exercise the same sudo/timeout boundary. */
export function readLinuxNamespaceJournal(
  cursor = null,
  {
    execute = spawnSync,
    protect = assertOwnedProcessLauncherProtected,
    now = () => performance.now(),
    deadline = Infinity,
  } = {},
) {
  if (execute === spawnSync)
    requireWorker(process.env, process.platform, process.arch);
  requireObservation(
    cursor === null ||
      (typeof cursor === "string" && JOURNAL_CURSOR.test(cursor)),
  );
  const stage = cursor === null ? "journal-cursor" : "journal-read";
  let result;
  const refuse = (code) => {
    throw Object.assign(new Error("Linux namespace journal refused."), {
      namespaceStage: stage,
      namespaceNativeCode: code,
      namespaceOutcome: result,
    });
  };
  try {
    result = namespaceCommand(
      "/usr/bin/journalctl",
      [
        "--kernel",
        ...(cursor === null
          ? ["--lines=1", "--output=json", "--show-cursor"]
          : [`--after-cursor=${cursor}`, "--output=json"]),
        "--no-pager",
      ],
      true,
      undefined,
      { execute, protect, now, deadline, encoding: null },
    );
  } catch (error) {
    error.namespaceStage ??= stage;
    throw error;
  }
  if (!result || typeof result !== "object") refuse("journal-command-failed");
  if (result.error?.code === "ETIMEDOUT" || result.status === 124)
    refuse("ETIMEDOUT"); // GNU timeout, without --preserve-status.
  if (result.status === 137) refuse("journal-command-killed");
  const decode = (value) => {
    if (value === undefined || value === null) return "";
    if (typeof value === "string" && value.isWellFormed()) return value;
    if (Buffer.isBuffer(value)) {
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(value);
      } catch {
        /* Invalid bytes supply no trusted cursor or public prose. */
      }
    }
    refuse("journal-output-malformed");
  };
  if (
    result.error?.code === "ENOBUFS" ||
    [result.stdout, result.stderr].reduce(
      (size, value) =>
        size +
        (typeof value === "string" || Buffer.isBuffer(value)
          ? Buffer.byteLength(value)
          : 0),
      0,
    ) > 65536
  )
    refuse("journal-output-bound");
  const stdout = decode(result.stdout),
    stderr = decode(result.stderr),
    diagnosis = journalDiagnosis(stderr);
  if (diagnosis) refuse(diagnosis);
  if (result.status !== 0 || result.error || result.signal)
    refuse(result.error?.code ?? "journal-command-failed");
  if (stderr !== "") refuse("journal-output-malformed");
  const lines = stdout.split("\n").filter((line) => line !== "");
  if (stdout !== "" && !stdout.endsWith("\n"))
    refuse(
      cursor === null ? "journal-cursor-malformed" : "journal-output-malformed",
    );
  const entry = (line, code) => {
    let value;
    try {
      value = JSON.parse(line);
    } catch {
      refuse(code);
    }
    if (value === null || typeof value !== "object" || Array.isArray(value))
      refuse(code);
    return value;
  };
  if (cursor === null) {
    const markers = lines.filter((line) => line.startsWith("-- cursor:"));
    if (markers.length === 0) refuse("journal-cursor-absent");
    const value = markers[0].slice("-- cursor: ".length);
    if (
      lines.length !== 2 ||
      markers.length !== 1 ||
      lines[1] !== `-- cursor: ${value}` ||
      !JOURNAL_CURSOR.test(value)
    )
      refuse("journal-cursor-malformed");
    if (entry(lines[0], "journal-cursor-malformed").__CURSOR !== value)
      refuse("journal-cursor-malformed");
    return value;
  }
  for (const line of lines) entry(line, "journal-output-malformed");
  return stdout;
}

function requireWorker(env, platform, architecture) {
  requireObservation(
    platform === "linux" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24" &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      env.RUNNER_OS === "Linux",
  );
}
async function stableBytes(file, limit = 65536, owned = false, held = null) {
  requireObservation((await realpath(file)) === file);
  const handle =
    held?.descriptor ??
    (await open(file, constants.O_RDONLY | constants.O_NOFOLLOW));
  try {
    const before = await handle.stat();
    if (held) {
      need(same(held.identity, before, ["nlink"]) && (await named(held)));
      need(before.size > 0, "trace-incomplete");
      need(before.size <= limit, "capture-bound");
    }
    requireObservation(
      before.isFile() &&
        before.nlink === 1 &&
        before.size > 0 &&
        before.size <= limit,
    );
    if (owned)
      requireObservation(
        before.uid === process.getuid() &&
          !(before.mode & 0o7022) &&
          (owned !== "private" || (before.mode & 0o7777) === 0o600),
      );
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      requireObservation(bytesRead > 0);
      offset += bytesRead;
    }
    requireObservation(
      (await handle.read(Buffer.alloc(1), 0, 1, offset)).bytesRead === 0,
    );
    const after = await handle.stat(),
      namedStat = await lstat(file);
    for (const key of [
      "dev",
      "ino",
      "mode",
      "uid",
      "gid",
      "nlink",
      "size",
      "mtimeMs",
      "ctimeMs",
    ])
      requireObservation(
        before[key] === after[key] && before[key] === namedStat[key],
      );
    requireObservation(bytes.length === before.size);
    return bytes;
  } finally {
    if (!held) await handle.close();
  }
}
export async function readLinuxNamespaceEvidence(
  file,
  { privateFile = true } = {},
) {
  return JSON.parse(
    await stableBytes(file, 1048576, privateFile ? "private" : "owned"),
  );
}

const LIMIT = 65536;
const IDENTITY = ["dev", "ino", "mode", "uid", "gid"];
const DIRECTORY =
  constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const CAPTURE =
  constants.O_RDWR |
  constants.O_CREAT |
  constants.O_EXCL |
  constants.O_NOFOLLOW;
const failure = (code, outcome) =>
  Object.assign(new Error("Linux namespace capture refused."), {
    namespaceNativeCode: code,
    namespaceOutcome: outcome,
  });
const need = (condition, code = "capture-substitution") => {
  if (!condition) throw failure(code);
};
const same = (before, after, extra = []) =>
  [...IDENTITY, ...extra].every(
    (key) => Number.isSafeInteger(before[key]) && before[key] === after[key],
  );
const named = async (entry) =>
  same(
    entry.identity,
    await lstat(entry.path),
    entry.identity.isFile() ? ["nlink"] : [],
  );
const privateMode = (info, mode) =>
  info.uid === process.getuid() && (info.mode & 0o7777) === mode;

/** strace 6.8 prefixes host PIDs with -f -o. A kernel file-size limit bounds
 * writes, not just later reads. Only this diagnostic replay inherits that limit;
 * the unchanged original probe remains the admission observation. */
export async function linuxNamespaceDiagnosticReplay(
  binary,
  args,
  options,
  execute = spawnSync,
  { directory, settle, now = () => performance.now() } = {},
) {
  let parent, folder, file, root, result, trace, first;
  let pids = [],
    complete = false,
    cleanupFailed = false;
  const handles = [];
  const hold = async (file, flags, mode) => {
    const descriptor = await open(file, flags, mode);
    handles.push(descriptor);
    return { path: file, descriptor, identity: await descriptor.stat() };
  };
  try {
    need(
      path.isAbsolute(directory) && (await realpath(directory)) === directory,
    );
    parent = await hold(directory, DIRECTORY);
    need(
      parent.identity.isDirectory() &&
        parent.identity.uid === process.getuid() &&
        !(parent.identity.mode & 0o22),
    );
    root = await mkdtemp(path.join(directory, ".namespace-trace-"));
    folder = await hold(root, DIRECTORY);
    need(folder.identity.isDirectory() && privateMode(folder.identity, 0o700));
    file = await hold(path.join(root, "trace"), CAPTURE, 0o600);
    need(
      file.identity.isFile() &&
        file.identity.nlink === 1 &&
        privateMode(file.identity, 0o600),
    );
    need((await named(parent)) && (await named(folder)) && (await named(file)));
    const timeout = Math.min(options?.timeout ?? 10000, 10000),
      deadline = now() + timeout;
    need(Number.isFinite(timeout) && timeout > 0, "ETIMEDOUT");
    result = execute(
      "/usr/bin/prlimit",
      [
        `--fsize=${LIMIT}:${LIMIT}`,
        "--",
        "/usr/bin/strace",
        "-f",
        "-o",
        file.path,
        "-q",
        "-e",
        "trace=execve,clone,clone3,unshare,capset",
        "--",
        binary,
        ...args,
      ],
      {
        ...OPTIONS,
        ...options,
        timeout,
        maxBuffer: LIMIT,
        killSignal: "SIGKILL",
        stdio: ["ignore", "pipe", "pipe"],
        env: ENV,
      },
    );
    if (result.error)
      first = failure(
        result.error.code === "ENOBUFS" ? "capture-bound" : result.error.code,
        result,
      );
    else if (result.signal) first = failure("capture-unsettled", result);
    if (now() >= deadline) first ??= failure("ETIMEDOUT", result);
    let bytes;
    try {
      bytes = await stableBytes(file.path, LIMIT - 1, "private", file);
    } catch (error) {
      if (!error.namespaceNativeCode && !error.code)
        error.namespaceNativeCode = "capture-substitution";
      throw error;
    }
    try {
      trace = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      pids = linuxNamespaceTracePids(trace);
      complete =
        !result.error &&
        !result.signal &&
        !/^strace:/mu.test(result.stderr ?? "");
    } catch {
      throw failure("trace-incomplete", result);
    }
    if (now() >= deadline) first ??= failure("ETIMEDOUT", result);
    if (first) throw first;
    need(complete, "trace-incomplete");
  } catch (error) {
    error.namespaceOutcome ??= result;
    first ??= error;
  }
  // Process settlement, named-file removal and descriptor closure are distinct.
  // A substituted entry or unproved trace domain stays private and quarantined.
  let retired = false;
  try {
    retired =
      typeof settle === "function" &&
      (await settle(
        result ? [result.pid, ...pids] : [],
        result === undefined || complete,
      )) === true &&
      (result === undefined || complete);
  } catch (error) {
    if (!first)
      first = Object.assign(error, { namespaceStage: "process-retirement" });
  }
  if (!retired) {
    cleanupFailed = true;
    first ??= Object.assign(failure("capture-unsettled", result), {
      namespaceStage: "process-retirement",
    });
  }
  if (root && !folder) cleanupFailed = true;
  for (const entry of [file, folder]) {
    try {
      if (!entry) continue;
      need(
        retired &&
          (await named(parent)) &&
          (await named(folder)) &&
          (await named(entry)),
      );
      await (entry === file ? unlink : rmdir)(entry.path);
    } catch {
      cleanupFailed = true;
    }
  }
  for (const owned of handles.reverse()) {
    try {
      await owned.close();
    } catch {
      cleanupFailed = true;
    }
  }
  if (cleanupFailed) {
    first ??= failure("capture-cleanup", result);
    first.namespaceCleanupFailed = true;
  }
  if (first) throw first;
  return { result, trace, pids };
}

/** Construct effects only after the declared external-worker guard. No import
 * probes a namespace, reads host policy, loads a profile or changes sysctls. */
function nativeEffects(context, directory) {
  const name = linuxNamespaceProfileName(context),
    profile = linuxNamespaceProfile(context);
  const deadline = performance.now() + 90000;
  const command = (file, args, privileged = false, input) => {
    const result = namespaceCommand(file, args, privileged, input, {
      deadline,
    });
    if (result.status !== 0 || result.error || result.signal)
      throw Object.assign(new Error("Linux namespace command refused."), {
        namespaceOutcome: result,
        code: result.error?.code,
      });
    return result.stdout;
  };
  const read = async (file, limit = 65536) => {
    const bytes = await readFile(file);
    requireObservation(bytes.length <= limit);
    return bytes.toString("utf8");
  };
  const number = async (file) => {
    try {
      const source = (await read(file, 64)).trim();
      requireObservation(/^(?:0|[1-9][0-9]{0,15})$/u.test(source));
      const value = Number(source);
      requireObservation(Number.isSafeInteger(value));
      return value;
    } catch {
      return null;
    }
  };
  const ownedProfiles = () =>
    command("/usr/bin/cat", [PROFILE_LIST], true)
      .split("\n")
      .filter((line) => linuxNamespaceProfileMembership(line, context));
  const loaded = (profiles = ownedProfiles()) =>
    profiles.length === 1 && profiles[0] === `${name} (unconfined)`;
  const vacant = () => ownedProfiles().length === 0;
  const policy = (operation) => {
    assertOwnedProcessLauncherProtected(ABI);
    return command(
      "/usr/sbin/apparmor_parser",
      ["--skip-cache", operation],
      true,
      profile,
    );
  };
  const absent = async (pid) => {
    try {
      await lstat(`/proc/${pid}`);
      return false;
    } catch (error) {
      if (error.code === "ENOENT") return true;
      throw error;
    }
  };
  const observe = async (state) => {
    requireObservation(
      /^ID=ubuntu$/mu.test(await read("/etc/os-release")) &&
        /^VERSION_ID="24\.04"$/mu.test(await read("/etc/os-release")),
    );
    state.stage = "executable";
    assertOwnedProcessLauncherProtected("/usr/bin/bwrap");
    requireObservation((await realpath("/usr/bin/bwrap")) === "/usr/bin/bwrap");
    const bytes = await stableBytes("/usr/bin/bwrap", 4194304),
      metadata = await lstat("/usr/bin/bwrap");
    requireObservation(!(metadata.mode & 0o6000)); // No setuid/setgid preparation or payload.
    requireObservation(
      command("/usr/sbin/getcap", ["/usr/bin/bwrap"]).trim() === "",
    );
    requireObservation(
      command("/usr/bin/dpkg-query", ["--search", "/usr/bin/bwrap"]).trim() ===
        "bubblewrap: /usr/bin/bwrap",
    );
    const executable = {
      sha256: namespaceDigest(bytes),
      packageVersion: command("/usr/bin/dpkg-query", [
        "--show",
        "--showformat=${Version}",
        "bubblewrap",
      ]).trim(),
      version: command("/usr/bin/bwrap", ["--version"]).trim(),
    };
    state.stage = "policy";
    const sysctls = {
      restrictedUserns: await number(
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
      ),
      unprivilegedUserns: await number(
        "/proc/sys/kernel/unprivileged_userns_clone",
      ),
      maxUserNamespaces: await number("/proc/sys/user/max_user_namespaces"),
    };
    const apparmor = {
      enabled:
        (await read("/sys/module/apparmor/parameters/enabled", 64)).trim() ===
        "Y",
      parserVersion: null,
      abiSha256: null,
      usernsFeature: false,
    };
    try {
      apparmor.parserVersion =
        /^AppArmor parser version ([0-9]+\.[0-9]+\.[0-9]+)/u.exec(
          command("/usr/sbin/apparmor_parser", ["--version"]),
        )?.[1] ?? null;
      assertOwnedProcessLauncherProtected(ABI);
      const abi = await stableBytes(ABI);
      apparmor.abiSha256 = namespaceDigest(abi);
      apparmor.usernsFeature =
        /\buserns(?:_create)?\b/u.test(abi.toString("utf8")) &&
        /\buserns(?:_create)?\b/u.test(
          await read(
            "/sys/kernel/security/apparmor/features/namespaces/mask",
            4096,
          ),
        );
    } catch {
      /* Unsupported preparation remains unselected, never guessed. */
    }
    const callerLabel = linuxNamespaceLabel(
      await read("/proc/self/attr/current", 4096),
      name,
    );
    state.stage = "trace-options";
    assertOwnedProcessLauncherProtected("/usr/bin/prlimit");
    const help = command("/usr/bin/strace", ["--help"]);
    if (!/(?:^|\n)\s*-f(?:,|\s)/u.test(help) || !/(?:^|\n)\s*-o\s/u.test(help))
      throw Object.assign(new Error("Linux namespace trace options refused."), {
        namespaceNativeCode: "unsupported-options",
        namespaceOutcome: { status: 0, signal: null },
      });
    const probes = [],
      vectors = [];
    for (const [mode, ownershipMode] of [
      ["ordinary", "ordinary"],
      ["nested", "native-sandbox-provider"],
    ]) {
      state.mode = mode;
      state.stage = "journal-cursor";
      const cursor = readLinuxNamespaceJournal(null, { deadline });
      let result, launcher, vector, resolverError;
      state.stage = "probe";
      try {
        launcher = resolveOwnedProcessLauncher(directory, {
          bubblewrap: "/usr/bin/bwrap",
          cache: new Map(),
          ownershipMode,
          probe: (binary, args, options) => {
            vectors.push(args);
            vector = { binary, args, options };
            // Admission observes the original public probe. Tracing is a
            // separate diagnostic replay with identical executable/argv/env.
            result = spawnSync(binary, args, {
              ...OPTIONS,
              ...options,
              stdio: ["ignore", "pipe", "pipe"],
              env: ENV,
            });
            state.probes.push({
              mode,
              ...linuxNamespaceProbeOutcome(result),
            });
            return result;
          },
        });
      } catch (error) {
        resolverError = error;
        /* The public resolver's refusal/fallback is recorded, not used. */
      }
      if (!result && resolverError) throw resolverError;
      requireObservation(result && vectors.length === probes.length + 1);
      if (result.error || result.signal) {
        // An abnormal original probe has no complete descendant census.
        try {
          await assertLinuxProcVisibility();
          if (Number.isInteger(result.pid) && result.pid > 1)
            await absent(result.pid);
        } catch {
          /* Cleanup uncertainty must not replace the original cause. */
        }
        throw Object.assign(new Error("Linux namespace probe refused."), {
          code: result.error?.code,
          namespaceOutcome: result,
          namespaceCleanupFailed: true,
        });
      }
      state.stage = "trace-capture";
      const replay = await linuxNamespaceDiagnosticReplay(
        vector.binary,
        vector.args,
        vector.options,
        spawnSync,
        {
          directory,
          settle: async (pids, complete) => {
            await assertLinuxProcVisibility();
            return (
              Number.isInteger(result.pid) &&
              result.pid > 1 &&
              pids.every(
                (pid) => /^[1-9][0-9]*$/u.test(String(pid)) && Number(pid) > 1,
              ) &&
              (await Promise.all([...pids, result.pid].map(absent))).every(
                Boolean,
              ) &&
              complete
            );
          },
        },
      );
      const traceBytes = replay.trace,
        traced = replay.result;
      // Replay returns only after complete tracing and independent retirement.
      const settled = true;
      state.stage = "journal-read";
      const journal = readLinuxNamespaceJournal(cursor, { deadline });
      const stderr = result.stderr ?? "";
      const operation =
        /^(?:<[0-7]>)?bwrap: (?:setting up (?:uid|gid) map|error writing to setgroups):/mu.test(
          stderr,
        )
          ? "mapping"
          : /^(?:<[0-7]>)?bwrap: (?:Creating new namespace failed|No permissions to create a new namespace|unshare (?:pid|user) ns)/mu.test(
                stderr,
              )
            ? "namespace"
            : /^(?:<[0-7]>)?bwrap: capset failed:/mu.test(stderr)
              ? "capability"
              : "unknown";
      const errno =
        operation === "unknown"
          ? null
          : /: Permission denied\s*$/mu.test(stderr)
            ? "EACCES"
            : /: Operation not permitted\s*$/mu.test(stderr) ||
                /^bwrap: No permissions to create a new namespace/mu.test(
                  stderr,
                )
              ? "EPERM"
              : null;
      const sameOutcome =
        traced?.status === result.status &&
        traced.signal === result.signal &&
        !traced.error;
      state.stage = "trace-attribution";
      const denials = sameOutcome
        ? linuxNamespaceDenials(traceBytes, journal, name)
        : [];
      probes.push({
        mode,
        passed:
          result.status === 0 &&
          !result.error &&
          !result.signal &&
          sameOutcome &&
          settled &&
          !denials.length &&
          launcher?.file === "/usr/bin/bwrap" &&
          launcher.isolatedNamespace === true &&
          launcher.hostSession === false,
        settled,
        replayMatched: sameOutcome,
        exitCode: Number.isInteger(result.status) ? result.status : null,
        signal: result.signal ?? null,
        timedOut: result.error?.code === "ETIMEDOUT",
        operation,
        errno,
        denials,
      });
      state.probes[state.probes.length - 1] = probes.at(-1);
    }
    state.mode = null;
    state.stage = "proc-visibility";
    let effectiveLabel = null,
      procVisible = false;
    try {
      await assertLinuxProcVisibility();
      procVisible = true;
    } catch {
      /* Directory absence under hidden procfs proves no settlement. */
    }
    if (!procVisible)
      for (const probe of probes) {
        probe.settled = false;
        probe.passed = false;
      }
    if (probes.every(({ passed }) => passed)) {
      state.stage = "effective-label";
      // Separate policy observation, never a changed admission vector or fallback.
      const args = [...vectors[0]];
      args.splice(
        args.lastIndexOf("--") + 1,
        1,
        "/usr/bin/cat",
        "/proc/self/attr/current",
      );
      effectiveLabel = linuxNamespaceLabel(
        command("/usr/bin/bwrap", args),
        name,
      );
    }
    state.stage = "image-recheck";
    requireObservation(
      namespaceDigest(await stableBytes("/usr/bin/bwrap", 4194304)) ===
        executable.sha256,
    );
    return normalizeLinuxNamespaceObservation({
      executable,
      sysctls,
      apparmor,
      callerLabel,
      effectiveLabel,
      procVisible,
      probes,
    });
  };
  return {
    observe: async () => {
      const state = { stage: "host", mode: null, probes: [] };
      try {
        return await observe(state);
      } catch (error) {
        error.namespaceObservationFailure ??= linuxNamespaceObservationFailure(
          error.namespaceStage ?? state.stage,
          state.mode,
          error,
          state.probes,
        );
        throw error;
      }
    },
    vacant,
    install: () => {
      policy("--skip-kernel-load");
      policy("--add");
      requireObservation(loaded());
    },
    remove: async () => {
      // Global label inspection is independent of the reporting step conclusion.
      // Unknown/inaccessible membership retains the owned policy, without PID kills.
      await assertLinuxProcVisibility();
      const pids = (await readdir("/proc")).filter((pid) =>
        /^[1-9][0-9]*$/u.test(pid),
      );
      requireObservation(pids.length <= 4096);
      for (const pid of pids) {
        try {
          const label = command(
            "/usr/bin/cat",
            [`/proc/${pid}/attr/current`],
            true,
          ).trim();
          requireObservation(
            label.length > 0 &&
              !linuxNamespaceProfileMembership(label, context),
          );
        } catch (error) {
          if (!(await absent(pid))) throw error;
        }
      }
      const profiles = ownedProfiles();
      requireObservation(profiles.length === 0 || loaded(profiles));
      if (profiles.length) policy("--remove");
      requireObservation(vacant());
    },
  };
}

/** Only an attributed, supported Ubuntu restriction permits a scoped opt-in.
 * Every policy load has a reconstructible write-ahead intent. */
export async function prepareLinuxNamespaces(
  context,
  directory,
  persist,
  {
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
    effects,
    now = () => performance.now(),
  } = {},
) {
  requireWorker(env, platform, architecture);
  const record = initialLinuxNamespacePreparation(context),
    deadline = now() + 120000;
  const native = effects ?? nativeEffects(context, directory);
  const save = async (phase) => {
    requireObservation(now() < deadline);
    record.phase = phase;
    await persist(normalizeLinuxNamespacePreparation(record, context));
  };
  try {
    record.status = "RUNNING";
    await save("diagnosis");
    record.before = normalizeLinuxNamespaceObservation(await native.observe());
    const decision = linuxNamespacePolicyDecision(record.before);
    if (decision === "blocked") throw new Error("Unestablished policy");
    if (decision === "prepare") {
      requireObservation((await native.vacant()) === true);
      record.owned = {
        name: linuxNamespaceProfileName(context),
        sha256: namespaceDigest(linuxNamespaceProfile(context)),
        status: "POSSIBLE",
      };
      await save("installation");
      await native.install();
      record.owned.status = "LOADED";
      await save("verification");
      record.after = normalizeLinuxNamespaceObservation(await native.observe());
      requireObservation(
        record.after.effectiveLabel === "owned" &&
          JSON.stringify(record.before.executable) ===
            JSON.stringify(record.after.executable) &&
          JSON.stringify(record.before.sysctls) ===
            JSON.stringify(record.after.sysctls) &&
          JSON.stringify(record.before.apparmor) ===
            JSON.stringify(record.after.apparmor),
      );
    }
    record.status = "PASS";
    record.phase = "verification";
    assertLinuxNamespacePreparation(record, context);
    await save("verification");
  } catch (error) {
    record.status = "BLOCKED";
    record.observationFailure = error.namespaceObservationFailure ?? null;
    record.cause = linuxNamespacePreparationCause(
      record.before,
      record.observationFailure,
    );
    if (error.namespaceCleanupFailed)
      record.cleanupCause = {
        code: "cleanup-unobserved",
        detail: LINUX_NAMESPACE_CAPTURE_CLEANUP_BLOCKER,
      };
    // Failed preparation admitted only bounded probes. Independent membership
    // inspection must establish that removal is safe; failures stay quarantined.
    if (record.owned !== null) {
      try {
        await native.remove();
        record.owned.status = "REMOVED";
      } catch {
        record.cleanupCause ??= {
          code: "cleanup-unobserved",
          detail: LINUX_NAMESPACE_CLEANUP_BLOCKER,
        };
      }
    }
    await persist(normalizeLinuxNamespacePreparation(record, context));
  }
  return record;
}

/** Expired/failed new-work gates never replace the original cleanup context. */
export async function cleanupLinuxNamespaces(
  value,
  context,
  settled,
  persist,
  {
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
    effects,
    directory,
  } = {},
) {
  requireWorker(env, platform, architecture);
  const record = normalizeLinuxNamespacePreparation(value, context);
  if (record.owned === null || record.owned.status === "REMOVED") return record;
  record.phase = "cleanup";
  await persist(record);
  try {
    requireObservation(settled === true);
    await (effects ?? nativeEffects(context, directory)).remove();
    record.owned.status = "REMOVED";
    if (record.cleanupCause?.detail !== LINUX_NAMESPACE_CAPTURE_CLEANUP_BLOCKER)
      record.cleanupCause = null;
  } catch {
    record.cleanupCause ??= {
      code: "cleanup-unobserved",
      detail: LINUX_NAMESPACE_CLEANUP_BLOCKER,
    };
  }
  await persist(normalizeLinuxNamespacePreparation(record, context));
  return record;
}

export async function verifyLinuxNamespaces(
  value,
  context,
  directory,
  options = {},
) {
  requireWorker(
    options.env ?? process.env,
    options.platform ?? process.platform,
    options.architecture ?? process.arch,
  );
  const record = assertLinuxNamespacePreparation(value, context);
  const fresh = normalizeLinuxNamespaceObservation(
    await (options.effects ?? nativeEffects(context, directory)).observe(),
  );
  requireObservation(
    linuxNamespacePolicyDecision(fresh) === "verified" &&
      JSON.stringify(fresh.executable) ===
        JSON.stringify((record.after ?? record.before).executable) &&
      JSON.stringify(fresh.sysctls) ===
        JSON.stringify((record.after ?? record.before).sysctls) &&
      JSON.stringify(fresh.apparmor) ===
        JSON.stringify((record.after ?? record.before).apparmor) &&
      fresh.callerLabel === (record.after ?? record.before).callerLabel &&
      fresh.effectiveLabel === (record.after ?? record.before).effectiveLabel,
  );
  return record;
}
