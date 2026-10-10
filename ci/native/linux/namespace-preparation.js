import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { lstat, open, readFile, readdir, realpath } from "node:fs/promises";
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
  linuxNamespacePreparationCause,
  LINUX_NAMESPACE_CLEANUP_BLOCKER,
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
async function stableBytes(file, limit = 65536, owned = false) {
  requireObservation((await realpath(file)) === file);
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
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
      named = await lstat(file);
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
        before[key] === after[key] && before[key] === named[key],
      );
    requireObservation(bytes.length === before.size);
    return bytes;
  } finally {
    await handle.close();
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

/** Capture strace's default stderr directly. Node's inherited pipe descriptors
 * are sockets on Linux and cannot be reopened through /proc/self/fd. The fixed
 * tracee may share this transient stream; only prefixed trace records attribute
 * host PIDs, and admission still uses the original probe's separate stderr. */
export function linuxNamespaceDiagnosticReplay(binary, args, options, execute) {
  const result = execute(
    "/usr/bin/strace",
    [
      "-f",
      "--always-show-pid",
      "-qq",
      "-e",
      "trace=execve,clone,clone3,unshare,capset",
      "--",
      binary,
      ...args,
    ],
    { ...OPTIONS, ...options, stdio: ["ignore", "pipe", "pipe"], env: ENV },
  );
  const trace = result.stderr ?? "";
  requireObservation(
    typeof trace === "string" && Buffer.byteLength(trace) <= 65536,
  );
  return { result, trace };
}

/** Construct effects only after the declared external-worker guard. No import
 * probes a namespace, reads host policy, loads a profile or changes sysctls. */
function nativeEffects(context, directory) {
  const name = linuxNamespaceProfileName(context),
    profile = linuxNamespaceProfile(context);
  const deadline = performance.now() + 90000;
  const command = (file, args, privileged = false, input) => {
    requireObservation(performance.now() < deadline);
    assertOwnedProcessLauncherProtected(file);
    if (privileged) {
      assertOwnedProcessLauncherProtected("/usr/bin/sudo");
      assertOwnedProcessLauncherProtected("/usr/bin/timeout");
    }
    const result = spawnSync(
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
      { ...OPTIONS, timeout: 12000, ...(input ? { input } : {}) },
    );
    requireObservation(result.status === 0 && !result.error && !result.signal);
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
  const observe = async () => {
    requireObservation(
      /^ID=ubuntu$/mu.test(await read("/etc/os-release")) &&
        /^VERSION_ID="24\.04"$/mu.test(await read("/etc/os-release")),
    );
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
    requireObservation(
      command("/usr/bin/strace", ["--help"]).includes("--always-show-pid"),
    );
    const probes = [],
      vectors = [];
    for (const [mode, ownershipMode] of [
      ["ordinary", "ordinary"],
      ["nested", "native-sandbox-provider"],
    ]) {
      const cursor = command(
        "/usr/bin/journalctl",
        [
          "--kernel",
          "--lines=1",
          "--output=json",
          "--show-cursor",
          "--no-pager",
        ],
        true,
      ).match(/^-- cursor: ([a-zA-Z0-9=;_-]{1,512})$/mu)?.[1];
      requireObservation(cursor);
      let result, replay, launcher;
      try {
        launcher = resolveOwnedProcessLauncher(directory, {
          bubblewrap: "/usr/bin/bwrap",
          cache: new Map(),
          ownershipMode,
          probe: (binary, args, options) => {
            vectors.push(args);
            // Admission observes the original public probe. Tracing is a
            // separate diagnostic replay with identical executable/argv/env.
            result = spawnSync(binary, args, {
              ...OPTIONS,
              ...options,
              stdio: ["ignore", "pipe", "pipe"],
              env: ENV,
            });
            assertOwnedProcessLauncherProtected("/usr/bin/strace");
            replay = linuxNamespaceDiagnosticReplay(
              binary,
              args,
              options,
              spawnSync,
            );
            return result;
          },
        });
      } catch {
        /* The public resolver's refusal/fallback is recorded, not used. */
      }
      requireObservation(result && vectors.length === probes.length + 1);
      const traceBytes = replay?.trace ?? "",
        traced = replay?.result;
      const pids = linuxNamespaceTracePids(traceBytes);
      const settled =
        pids.length > 0 &&
        Number.isInteger(result.pid) &&
        result.pid > 1 &&
        (await Promise.all([...pids, result.pid].map(absent))).every(Boolean);
      const journal = command(
        "/usr/bin/journalctl",
        ["--kernel", `--after-cursor=${cursor}`, "--output=json", "--no-pager"],
        true,
      );
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
    }
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
    observe,
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
  } catch {
    record.status = "BLOCKED";
    record.cause = linuxNamespacePreparationCause(record.before);
    // Failed preparation admitted only bounded probes. Independent membership
    // inspection must establish that removal is safe; failures stay quarantined.
    if (record.owned !== null) {
      try {
        await native.remove();
        record.owned.status = "REMOVED";
      } catch {
        record.cleanupCause = {
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
    record.cleanupCause = null;
  } catch {
    record.cleanupCause = {
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
