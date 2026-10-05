import { posix as path } from "node:path";
import {
  spawnOwnedProcess,
  resolveOwnedProcessLauncher,
  assertOwnedProcessLauncherProtected,
} from "../../../src/agents/index.js";
import {
  observationObject,
  observationList,
  observationDigest,
  requireObservation,
} from "../index.js";
import {
  normalizeProviderSpec,
  providerInvocation,
  PROVIDER_LIMITS,
} from "../providers/index.js";
import { accessGrants } from "./profiles.js";
import { processDetails } from "./inspect.js";
import { sameLinuxIdentity } from "./protocol.js";

const location = (v) => {
  requireObservation(
    typeof v === "string" &&
      v.isWellFormed() &&
      Buffer.byteLength(v) <= 4096 &&
      v.startsWith("/") &&
      v !== "/" &&
      !v.endsWith("/") &&
      path.normalize(v) === v &&
      !/[\u0000-\u001f\u007f]/u.test(v),
  );
  return v;
};

/** Different from the Node fixture interface: selected native package, complete
 * immutable ABI grants and a reviewed parked exec are the actual payload. */
export function linuxProviderArguments(specification, fixture) {
  const spec = normalizeProviderSpec(specification),
    invocation = providerInvocation(specification);
  observationObject(fixture, [
    "directory",
    "launcher",
    "gate",
    "entrypoint",
    "storage",
    "mappings",
    "reviewSha256",
  ]);
  requireObservation(
    spec.platform === "linux" &&
      spec.home === "/home/provider" &&
      spec.cache === "/cache" &&
      /^[a-f0-9]{64}$/u.test(fixture.reviewSha256),
  );
  for (const key of ["directory", "launcher", "gate", "entrypoint"])
    location(fixture[key]);
  observationObject(fixture.storage, [
    "workspace",
    "metadata",
    "pointer",
    "git",
    "operation",
    "hooks",
    "home",
    "cache",
  ]);
  Object.values(fixture.storage).forEach(location);
  const mappings = observationList(fixture.mappings, 128).map((entry) => {
    observationObject(entry, ["source", "target", "sha256", "bytes"]);
    location(entry.source);
    location(entry.target);
    requireObservation(
      /^\/(?:runtime|bin|lib|lib64|usr\/(?:bin|lib))\//u.test(entry.target) &&
        /^[a-f0-9]{64}$/u.test(entry.sha256) &&
        Number.isSafeInteger(entry.bytes) &&
        entry.bytes > 0 &&
        entry.bytes <= PROVIDER_LIMITS.imageBytes,
    );
    return { ...entry };
  });
  requireObservation(
    mappings.reduce((total, entry) => total + entry.bytes, 0) <= 2147483648,
  );
  requireObservation(
    new Set(mappings.map((v) => v.target)).size === mappings.length &&
      mappings.some(
        (v) =>
          v.target === fixture.entrypoint &&
          v.sha256 === spec.entry.sha256 &&
          v.bytes === spec.entry.bytes,
      ) &&
      spec.path
        .split(":")
        .every(
          (v) =>
            (v.startsWith("/runtime/") ||
              ["/bin", "/usr/bin", "/proof/bin"].includes(v)) &&
            location(v),
        ),
  );
  const writableSources = [
    fixture.storage.workspace,
    fixture.storage.home,
    fixture.storage.cache,
  ];
  const protectedSources = [
    fixture.storage.metadata,
    fixture.storage.git,
    fixture.storage.operation,
    fixture.storage.hooks,
  ];
  requireObservation(
    protectedSources.every((root) =>
      writableSources.every(
        (write) =>
          root !== write &&
          !root.startsWith(write + "/") &&
          !write.startsWith(root + "/"),
      ),
    ) &&
      (fixture.storage.pointer === fixture.storage.workspace + "/.git" ||
        writableSources.every(
          (write) =>
            fixture.storage.pointer !== write &&
            !fixture.storage.pointer.startsWith(write + "/"),
        )),
  );
  requireObservation(
    writableSources.every((root, index) =>
      writableSources.every(
        (other, j) =>
          index === j || (root !== other && !root.startsWith(other + "/")),
      ),
    ) &&
      mappings.every(
        (entry) =>
          !writableSources.some(
            (root) =>
              entry.source === root || entry.source.startsWith(root + "/"),
          ),
      ) &&
      mappings.every((entry, index) =>
        mappings.every(
          (other, j) =>
            index === j || !entry.target.startsWith(other.target + "/"),
        ),
      ),
  );
  const grants = [
    ...accessGrants(spec.profile, fixture.storage),
    { source: fixture.storage.home, target: spec.home, writable: true },
    { source: fixture.storage.cache, target: spec.cache, writable: true },
  ];
  const directories = new Set([
    "/proof",
    "/proof/bin",
    "/workspace",
    "/metadata",
    "/home",
    spec.home,
    spec.cache,
    "/dev",
    "/proc",
  ]);
  for (const entry of [...mappings, ...grants])
    for (
      let parent = path.dirname(entry.target);
      parent !== "/";
      parent = path.dirname(parent)
    )
      directories.add(parent);
  return [
    "--new-session",
    "--die-with-parent",
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--as-pid-1",
    "--cap-drop",
    "ALL",
    "--clearenv",
    "--tmpfs",
    "/",
    ...[...directories]
      .sort(
        (a, b) =>
          a.split("/").length - b.split("/").length || a.localeCompare(b),
      )
      .flatMap((v) => ["--dir", v]),
    "--ro-bind",
    fixture.gate,
    "/proof/bin/provider-gate",
    ...mappings.flatMap((v) => ["--ro-bind", v.source, v.target]),
    ...grants.flatMap((v) => [
      v.writable ? "--bind" : "--ro-bind",
      v.source,
      v.target,
    ]),
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--remount-ro",
    "/",
    "--chdir",
    "/workspace",
    "--preserve-fds",
    "2",
    ...Object.entries(invocation.execution.environment).flatMap(([k, v]) => [
      "--setenv",
      k,
      v,
    ]),
    "--",
    "/proof/bin/provider-gate",
    spec.nonce,
    fixture.entrypoint,
    "--",
    ...invocation.arguments,
  ];
}

async function readProviderGate(pipe, nonce, signal) {
  const fail = () => pipe.destroy(new Error("Unverified provider gate"));
  const timer = setTimeout(fail, 30000),
    chunks = [];
  let size = 0;
  signal.addEventListener("abort", fail, { once: true });
  try {
    requireObservation(!signal.aborted);
    for await (const chunk of pipe) {
      size += chunk.length;
      requireObservation(size <= 512);
      chunks.push(chunk);
    }
    const bytes = Buffer.concat(chunks);
    requireObservation(
      bytes.length > 0 && bytes.indexOf(10) === bytes.length - 1,
    );
    const value = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    observationObject(value, ["nonce", "pid"]);
    requireObservation(
      value.nonce === nonce && Number.isSafeInteger(value.pid) && value.pid > 0,
    );
    return value;
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", fail);
    pipe.destroy();
  }
}

export function linuxProviderOwner(
  fixture,
  approvedSha256,
  effects,
  {
    env = process.env,
    platform = process.platform,
    spawn = spawnOwnedProcess,
  } = {},
) {
  fixture = structuredClone(fixture);
  return {
    assertTransport: assertLinuxProviderTransport,
    async interrupt(mode, domain, signal) {
      requireObservation(
        ["cancel", "helper-loss"].includes(mode) &&
          !signal.aborted &&
          typeof effects.interruptProvider === "function",
      );
      return effects.interruptProvider(mode, structuredClone(domain), {
        signal,
      });
    },
    async launch(spec, invocation, prepare, signal) {
      requireObservation(
        platform === "linux" &&
          process.arch === "x64" &&
          env.CI === "true" &&
          env.GITHUB_ACTIONS === "true" &&
          env.ImageOS === "ubuntu24",
      );
      const args = linuxProviderArguments(spec, fixture),
        requestSha256 = observationDigest({
          spec: normalizeProviderSpec(spec),
          fixture,
          args,
        });
      requireObservation(approvedSha256 === requestSha256);
      requireObservation(!signal.aborted);
      const verified = await effects.verifyInputs(
        structuredClone(fixture),
        structuredClone(spec),
        requestSha256,
      );
      requireObservation(
        verified?.independent === true &&
          verified.status === "MATCHED" &&
          verified.requestSha256 === requestSha256 &&
          verified.packageSha256 === invocation.execution.closureSha256 &&
          verified.immutableMappings === true &&
          verified.privateHomeCache === true &&
          verified.noWritableAliases === true,
      );
      requireObservation(!signal.aborted);
      const record = {
        candidateSha: spec.candidateSha,
        nonce: spec.nonce,
        requestSha256,
        status: "RUNNING",
        phase: "admission-possible",
        reservation: "RETAINED",
      };
      await effects.persist(structuredClone(record));
      let child;
      try {
        requireObservation(!signal.aborted);
        child = spawn(fixture.launcher, args, {
          signal,
          ownershipMode: "native-sandbox-provider",
          cwd: fixture.directory,
          env: { PATH: "/usr/bin:/bin", LANG: "C" },
          stdio: ["pipe", "pipe", "pipe", "pipe", "pipe"],
          resolveLauncher(cwd, { ownershipMode }) {
            const launcher = resolveOwnedProcessLauncher(cwd, {
              ownershipMode,
            });
            assertOwnedProcessLauncherProtected(launcher.file);
            requireObservation(
              launcher.isolatedNamespace === true &&
                launcher.hostSession === false &&
                launcher.file === fixture.launcher,
            );
            return launcher;
          },
          async onProcess(pid, admission) {
            if (pid === null) return;
            requireObservation(!signal.aborted);
            const init = await processDetails(pid);
            requireObservation(
              sameLinuxIdentity(init.identity, admission.processIdentity),
            );
            record.init = init;
            record.admission = structuredClone(admission);
            await effects.persist(structuredClone(record));
            const receipt = await effects.verifyReceipt(
              structuredClone(record),
            );
            requireObservation(
              receipt.independent === true &&
                receipt.sha256 === observationDigest(record),
            );
          },
        });
        // The owned supervisor inserts its IPC channel at parent descriptor 3;
        // payload descriptors 3/4 are the parent's control/report pipes 4/5.
        const gate = await Promise.race([
          (effects.readGate ?? readProviderGate)(
            child.stdio[5],
            spec.nonce,
            signal,
          ),
          child.ownedCompletion.then(() => {
            throw new Error("Provider gate retired");
          }),
        ]);
        observationObject(gate, ["nonce", "pid"]);
        requireObservation(
          gate.nonce === spec.nonce &&
            Number.isSafeInteger(gate.pid) &&
            gate.pid > 0,
        );
        const domain = await effects.inspectGate(
          child,
          gate,
          structuredClone(record),
        );
        requireObservation(
          domain.independent === true &&
            domain.held === true &&
            domain.candidateSha === spec.candidateSha &&
            domain.nonce === spec.nonce &&
            domain.networkPrivate === true &&
            domain.ipcPrivate === true &&
            domain.gatePid === gate.pid &&
            domain.rootReadOnly === true &&
            domain.immutableMappingsVerified === true &&
            domain.profile === spec.profile,
        );
        await prepare(domain);
        requireObservation(!signal.aborted);
        const fresh = await effects.inspectGate(
          child,
          gate,
          structuredClone(record),
        );
        requireObservation(
          observationDigest(fresh) === observationDigest(domain),
        );
        requireObservation(!signal.aborted);
        record.phase = "release";
        await effects.persist(structuredClone(record));
        requireObservation(!signal.aborted);
        await new Promise((resolve, reject) =>
          child.stdio[4].end("R", (error) =>
            error ? reject(error) : resolve(),
          ),
        );
        record.status = "ADMITTED";
        await effects.persist(structuredClone(record));
        return {
          record,
          transport: {
            input: child.stdin,
            output: child.stdout,
            errorOutput: child.stderr,
            completion: child.ownedCompletion,
            close() {
              child.stdin.destroy();
              child.stdio[4].destroy();
            },
            async settle() {
              await effects.retire(structuredClone(record));
            },
          },
        };
      } catch {
        child?.stdin?.destroy();
        child?.stdio[4]?.destroy();
        record.status = "FAIL";
        await effects.persist(structuredClone(record));
        return { record, transport: null };
      }
    },
  };
}

/** nsenter joins only a held network namespace, never the payload PID/user
 * namespace. Exact nsenter/Node/entry images and inherited descriptors are
 * independently admitted by the protected transport owner before this exec. */
export function linuxProviderBridgeArguments(node, entry, gate, nonce) {
  requireObservation(/^[a-f0-9]{32}$/u.test(nonce));
  return [
    "--net=/proc/self/fd/5",
    "--",
    location(gate),
    "--bridge-loopback",
    nonce,
    location(node),
    location(entry),
  ];
}

export function assertLinuxProviderTransport(value) {
  for (const key of [
    "samePrivateNetworkNamespace",
    "bridgeOutsidePayloadPidNamespace",
    "credentialFreeBridge",
    "fixedInheritedPipe",
  ])
    requireObservation(value[key] === true);
}
