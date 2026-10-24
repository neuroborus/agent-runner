import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  observationObject,
  observationDigest,
  requireObservation,
  assertNativeObserverHealth,
  normalizeNativePolicyBinding,
  normalizeNativePolicyTemplate,
  materializeNativePolicy,
  nativePolicyLaunchData,
  normalizeNativePackageReview,
  nativePackageReviewDigest,
  CODEX_RELEASE_REFERENCE,
  CLAUDE_WRAPPER_REFERENCE,
} from "../index.js";
import {
  normalizeProviderSpec,
  providerInvocation,
  normalizeCodexCases,
  normalizeClaudeCases,
  CLAUDE_TOOLS,
} from "../providers/index.js";
import {
  linuxProviderArguments,
  linuxProviderBridgeArguments,
} from "./provider-launch.js";
import { createLinuxReleaseReaders } from "./release-readers.js";
import {
  createLinuxProviderKernel,
  linuxProviderRootArguments,
  sameLinuxData as same,
} from "./provider-kernel.js";
import {
  linuxProviderFrames,
  writeLinuxProviderPipe,
} from "./provider-channel.js";
import { linuxObserverArguments } from "./observer.js";
import { createLinuxProviderObservation } from "./provider-observation.js";
import { accessGrants } from "./profiles.js";
import { createLinuxProviderTransport } from "./provider-transport.js";
import { retireLinuxProviderIdentity } from "./provider-retirement.js";

const retired = (nativeEventSha256) => ({
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
  noLiveMembers: true,
  nativeEventSha256,
});
const RELAY = fileURLToPath(
  new URL("../providers/relay-process.js", import.meta.url),
);
const BRIDGE = fileURLToPath(
  new URL("../providers/bridge-process.js", import.meta.url),
);

/** CI-private composition. Construction neither reads credentials nor starts
 * work. Approved data supplies bytes and literal cases, never owner callbacks. */
export function createLinuxProviderEffects(input, options = {}) {
  const job = structuredClone(input.job),
    manifest = structuredClone(input.manifest),
    kernel = createLinuxProviderKernel(options),
    sessions = new Map(),
    pins = new Map(manifest.inputs.map((item) => [item.path, item])),
    environment = Object.fromEntries(
      ["CI", "GITHUB_ACTIONS", "ImageOS", "RUNNER_TEMP"].map((key) => [
        key,
        (options.env ?? process.env)[key],
      ]),
    );
  let fenced = false;
  requireObservation(
    job.platform === "linux" &&
      job.selectedSystem?.binding?.conclusion === "success" &&
      job.selectedSystem.binding.candidateSha === job.candidateSha,
  );
  const guard = (signal) =>
    requireObservation(
      !fenced &&
        !signal?.aborted &&
        environment.CI === "true" &&
        environment.GITHUB_ACTIONS === "true" &&
        environment.ImageOS === "ubuntu24",
    );
  const pinned = async (file, expected = null, maximum = 536870912) => {
    const pin = pins.get(file);
    requireObservation(
      pin && pin.bytes <= maximum && (!expected || pin.sha256 === expected),
    );
    const held = await kernel.hold(file);
    try {
      const bytes = await kernel.read(held, maximum);
      requireObservation(
        bytes.length === pin.bytes && digestBytes(bytes) === pin.sha256,
      );
      return { held, bytes, sha256: pin.sha256 };
    } catch (error) {
      await kernel.close(held);
      throw error;
    }
  };
  const json = async (file) => {
    const value = await pinned(file, null, 1048576);
    try {
      return JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(value.bytes),
      );
    } finally {
      await kernel.close(value.held);
    }
  };
  const tool = async (session, file) => {
    const existing = session.images.get(file);
    if (existing) {
      await kernel.inspect(existing.held);
      return existing;
    }
    let value;
    if (file === session.launch.gate) {
      const helper = manifest.helpers.find(
        (item) => item.name === "provider-gate",
      );
      requireObservation(
        helper &&
          (file === path.join(input.providerHelpers, "provider-gate") ||
            pins.get(file)?.sha256 === helper.sha256),
      );
      const held = await kernel.hold(file);
      session.images.set(file, { held });
      const bytes = await kernel.read(held);
      requireObservation(digestBytes(bytes) === helper.sha256);
      const source = await kernel.hold(
        path.join(
          manifest.providerPreparation.sourceDirectory,
          "provider-gate.c",
        ),
      );
      session.images.set(source.file, { held: source });
      requireObservation(
        digestBytes(await kernel.read(source, 1048576)) === helper.sourceSha256,
      );
      session.images.set(source.file, {
        held: source,
        sha256: helper.sourceSha256,
      });
      value = { held, bytes, sha256: helper.sha256 };
    } else value = await pinned(file);
    value = {
      held: value.held,
      bytes: value.bytes.length,
      sha256: value.sha256,
    };
    session.images.set(file, value);
    return value;
  };
  const get = (current) => {
    const session = sessions.get(current.recipe.id);
    requireObservation(session && same(session.binding, current.binding));
    session.current = current;
    return session;
  };
  const policyData = (session, value) =>
    normalizeNativePolicyTemplate({
      ...session.binding.template,
      bindings: [],
      policy: value,
    }).policy;
  const snapshot = async (session) => {
    const values = [];
    for (const value of session.objects.values()) {
      const identity = await kernel.inspect(value.held),
        bytes = await kernel.read(value.held);
      values.push({
        file: value.held.file,
        identity,
        sha256: digestBytes(bytes),
      });
    }
    return values;
  };
  const probe = async (session, action, signal) => {
    guard(signal);
    observationObject(action, ["operation", "target", "data"]);
    requireObservation(
      [
        "read",
        "write",
        "signal",
        "debug",
        "network",
        "ipc",
        "barrier",
      ].includes(action.operation) &&
        typeof action.target === "string" &&
        action.target.length > 0 &&
        action.target.length <= 4096 &&
        !action.target.includes("\0") &&
        typeof action.data === "string" &&
        action.data.length <= 8192 &&
        !action.data.includes("\0"),
    );
    requireObservation(
      session.probes &&
        !session.retiring &&
        !session.payloadRetired &&
        !signal?.aborted,
    );
    const sequence = ++session.probeSequence;
    await session.persist({
      phase: "probe-possible",
      sequence,
      actionSha256: observationDigest(action),
      identity: session.probeIdentity,
    });
    guard(signal);
    requireObservation(!session.retiring && !session.payloadRetired);
    await writeLinuxProviderPipe(
      session.worker.child.stdio[6],
      `${sequence} ${action.operation} ${Buffer.from(action.target).toString("hex")} ${action.data ? Buffer.from(action.data).toString("hex") : "-"}\n`,
    );
    const result = await session.probes.take(signal);
    observationObject(result, ["sequence", "pid", "result", "error"]);
    requireObservation(
      result.sequence === sequence &&
        result.pid === session.probeIdentity.nspid.at(-1) &&
        Number.isSafeInteger(result.result) &&
        Number.isSafeInteger(result.error) &&
        result.error >= 0 &&
        result.error <= 4095,
    );
    requireObservation(
      same(
        (await kernel.process(session.probeIdentity.pid)).identity,
        session.probeIdentity.identity,
      ),
    );
    return result;
  };
  const members = async (session) => {
    requireObservation(session.domain);
    const all = await kernel.processes(),
      own = all.filter(
        (item) => item.namespaceId === session.domain.namespaceId,
      );
    requireObservation(
      own.some(
        (item) =>
          item.pid === session.gateIdentity.pid &&
          same(item.identity, session.gateIdentity.identity),
      ),
    );
    requireObservation(
      own.every(
        (item) =>
          item.networkId === session.gateIdentity.networkId &&
          item.ipcId === session.gateIdentity.ipcId &&
          item.mountId === session.gateIdentity.mountId &&
          item.userId === session.gateIdentity.userId &&
          Object.values(item.authority.capabilitySets).every(
            (mask) => mask === "0000000000000000",
          ) &&
          item.authority.noNewPrivileges === 1,
      ),
    );
    return own;
  };
  const retirePayload = async (session, signal) => {
    requireObservation(!signal?.aborted);
    if (session.payloadRetired) return session.payloadRetired;
    session.retiring = true;
    await session.persist({
      phase: "payload-retirement-possible",
      domain: session.domain,
      identity: session.gateIdentity ?? null,
    });
    session.worker?.child.stdio[4]?.destroy();
    session.worker?.child.stdio[6]?.destroy();
    if (session.worker) await kernel.retire(session.worker);
    let native = observationDigest({ noWorker: true });
    if (session.gateIdentity)
      native = await kernel.absent(session.gateIdentity, session.namespaces);
    session.payloadRetired = {
      ...retired(native),
      candidateSha: job.candidateSha,
      nonce: session.spec.nonce,
      ...(session.domain
        ? { domainSha256: observationDigest(session.domain) }
        : {}),
    };
    await session.persist({
      phase: "payload-retired",
      settlement: session.payloadRetired,
    });
    return session.payloadRetired;
  };
  const retireParticipants = async (session, signal) => {
    const payload = await retirePayload(session, signal);
    if (session.transport) {
      await session.transport.closeTransport();
      await session.transport.retire();
    }
    return payload;
  };
  const restore = async (session) => {
    requireObservation(session.payloadRetired && session.auditRetired);
    // No host-global policy was changed. Owned namespaces have already died;
    // all immutable inputs must still match before closing their readers.
    for (const value of session.images.values())
      await kernel.inspect(value.held);
    await session.observer?.closeControls();
    const closed = [];
    for (const item of session.namespaces
      ? Object.values(session.namespaces)
      : []) {
      await kernel.closeNamespace(item);
      closed.push(item.identity);
    }
    session.namespaces = null;
    for (const value of [
      ...session.images.values(),
      ...session.objects.values(),
    ])
      await kernel.close(value.held);
    if (session.release) await session.release.verifyClosed();
    return {
      status: "RESTORED",
      independent: true,
      unchangedInstalled: true,
      nativeEventSha256: observationDigest({
        closed,
        payload: session.payloadRetired,
        audit: session.auditRetired,
      }),
    };
  };
  const dependencies = {
    guard,
    kernel,
    pinned,
    json,
    tool,
    probe,
    members,
    snapshot,
    retirePayload,
    retireParticipants,
    restore,
    environment,
    RELAY,
    BRIDGE,
    options,
  };
  return {
    async openLinuxCustody(declaration, { signal, persist }) {
      let identity,
        closed = false;
      return {
        async start() {
          guard(signal);
          requireObservation(!identity && !closed);
          await persist({
            phase: "linux-reader-possible",
            context: declaration.context,
          });
          identity = await kernel.process(options.pid ?? process.pid);
          return {
            independent: true,
            context: declaration.context,
            nativeEventSha256: observationDigest(identity),
          };
        },
        async close() {
          requireObservation(identity && !closed);
          const actual = await kernel.process(identity.pid);
          requireObservation(same(actual.identity, identity.identity));
          closed = true;
          return { ...retired(observationDigest(actual)), closed: true };
        },
      };
    },
    async provision(declared, binding, { signal, persist }) {
      guard(signal);
      binding = normalizeNativePolicyBinding(binding);
      requireObservation(
        !sessions.has(declared.id) &&
          same(declared.custody.context, binding.context),
      );
      const spec = normalizeProviderSpec(declared.specification),
        launch = structuredClone(declared.launch),
        bindings = structuredClone(declared.bindings);
      observationObject(bindings, [
        "relayPolicy",
        "release",
        "compilerVersion",
        "casesFile",
        "observationFile",
        "transportControlsFile",
        "configurationFile",
        "files",
      ]);
      requireObservation(
        launch.probeChannels === true &&
          launch.directory.startsWith(input.directory + "/") &&
          spec.candidateSha === job.candidateSha,
      );
      linuxProviderArguments(spec, launch);
      const session = {
        spec,
        launch,
        binding,
        bindings,
        persist,
        images: new Map(),
        objects: new Map(),
        probeSequence: 0,
        worker: null,
        domain: null,
        auditRetired: null,
        payloadRetired: null,
      };
      sessions.set(declared.id, session);
      await persist({
        phase: "linux-provider-provisioning-possible",
        id: declared.id,
        declarationSha256: observationDigest(declared),
        context: binding.context,
      });
      let absent = false;
      try {
        await kernel.fs.lstat(launch.directory);
      } catch (error) {
        if (error.code === "ENOENT") absent = true;
        else throw error;
      }
      requireObservation(absent);
      const ensureDirectory = async (file) => {
        requireObservation(
          file === input.directory ||
            (file.startsWith(input.directory + "/") &&
              path.normalize(file) === file),
        );
        const root =
          session.images.get(input.directory)?.held ??
          (await kernel.hold(input.directory, {
            directory: true,
            sealed: false,
          }));
        requireObservation(
          root.identity.uid === String(options.ownerUid ?? process.getuid()),
        );
        session.images.set(input.directory, { held: root });
        let parent = input.directory;
        for (const name of path
          .relative(input.directory, file)
          .split(path.sep)
          .filter(Boolean)) {
          await kernel.inspect(session.images.get(parent).held);
          parent = path.join(parent, name);
          guard(signal);
          try {
            await kernel.fs.mkdir(parent, { mode: 0o700 });
          } catch (error) {
            if (error.code !== "EEXIST") throw error;
          }
          const held = await kernel.hold(parent, {
            directory: true,
            sealed: false,
          });
          requireObservation(
            held.identity.uid === root.identity.uid &&
              (BigInt(held.identity.mode) & 0o7777n) === 0o700n,
          );
          const previous = session.images.get(parent);
          if (previous) await kernel.close(previous.held);
          session.images.set(parent, { held });
        }
      };
      await ensureDirectory(launch.directory);
      for (const directory of [
        "workspace",
        "metadata",
        "hooks",
        "home",
        "cache",
      ].map((key) => launch.storage[key])) {
        requireObservation(directory.startsWith(launch.directory + "/"));
        await ensureDirectory(directory);
      }
      requireObservation(
        Array.isArray(bindings.files) &&
          bindings.files.length > 0 &&
          bindings.files.length <= 256 &&
          new Set(bindings.files.map((item) => item.path)).size ===
            bindings.files.length,
      );
      for (const entry of bindings.files) {
        observationObject(entry, ["path", "input", "writable"]);
        requireObservation(
          typeof entry.writable === "boolean" &&
            entry.path.startsWith(launch.directory + "/") &&
            path.normalize(entry.path) === entry.path,
        );
        const source = await pinned(entry.input);
        try {
          // Intent precedes even directory/file creation. A failed return still
          // leaves enough declaration-bound records for reconstruction.
          await persist({
            phase: "linux-provider-file-possible",
            path: entry.path,
            sourceSha256: source.sha256,
          });
          await ensureDirectory(path.dirname(entry.path));
          guard(signal);
          await kernel.fs.writeFile(entry.path, source.bytes, {
            flag: "wx",
            mode: entry.writable ? 0o600 : 0o400,
          });
          const held = await kernel.hold(entry.path, {
            sealed: !entry.writable,
          });
          requireObservation(
            digestBytes(await kernel.read(held)) === source.sha256,
          );
          session.objects.set(entry.path, {
            held,
            sourceSha256: source.sha256,
          });
        } finally {
          await kernel.close(source.held);
        }
        guard(signal);
      }
      for (const file of [
        launch.launcher,
        launch.gate,
        "/usr/bin/strace",
        "/usr/bin/nsenter",
        "/usr/bin/sudo",
        "/usr/bin/env",
        process.execPath,
        RELAY,
        BRIDGE,
      ])
        await tool(session, file);
      for (const mapping of launch.mappings) {
        const value = await tool(session, mapping.source);
        requireObservation(
          value.sha256 === mapping.sha256 && value.bytes === mapping.bytes,
        );
      }
      session.casesData = await json(bindings.casesFile);
      session.observationData = await json(bindings.observationFile);
      session.transportControls = await json(bindings.transportControlsFile);
      session.configuration = await json(bindings.configurationFile);
      observationObject(session.configuration, [
        "invocation",
        "environment",
        "enabledTools",
      ]);
      requireObservation(
        same(session.configuration.invocation, providerInvocation(spec)) &&
          same(
            session.configuration.environment,
            Object.entries(providerInvocation(spec).execution.environment)
              .map(([key, value]) => `${key}=${value}`)
              .sort(),
          ) &&
          same(
            session.configuration.enabledTools,
            spec.provider === "codex"
              ? ["exec_command", "write_stdin", "apply_patch"]
              : [...CLAUDE_TOOLS],
          ),
      );
      session.before = await snapshot(session);
      await persist({
        phase: "linux-provider-provisioned",
        id: declared.id,
        beforeSha256: observationDigest(session.before),
      });
      guard(signal);
      return { specification: spec, launch };
    },
    async bindReaders(current, { signal }) {
      guard(signal);
      const session = get(current);
      const packageBinding =
        session.bindings.release.providers[session.spec.provider];
      observationObject(packageBinding, ["reviewFile", "directory"]);
      const actualReview = normalizeNativePackageReview(
        await json(packageBinding.reviewFile),
        job.candidateSha,
      );
      requireObservation(
        nativePackageReviewDigest(actualReview) === session.spec.closureSha256,
      );
      for (const member of actualReview.files) {
        requireObservation(
          session.launch.mappings.some(
            (mapping) =>
              mapping.source ===
                path.join(packageBinding.directory, member.path) &&
              mapping.sha256 === member.sha256 &&
              mapping.bytes === member.bytes,
          ),
        );
      }
      for (const mapping of session.launch.mappings) {
        requireObservation(
          session.bindings.release.components.some(
            (entry) =>
              entry.path === mapping.source &&
              manifest.release.components.some(
                (component) =>
                  component.id === entry.id &&
                  component.sha256 === mapping.sha256,
              ),
          ),
        );
      }
      session.release = createLinuxReleaseReaders(
        {
          job,
          manifest,
          bindings: session.bindings.release,
          compilerVersion: session.bindings.compilerVersion,
          runnerTemp: environment.RUNNER_TEMP,
        },
        {
          fs: kernel.fs,
          inspectProcess: kernel.process,
          ownerUid: () => options.ownerUid ?? process.getuid(),
          protect: options.protect,
        },
      );
      const observer = createLinuxProviderObservation(session, dependencies);
      session.observer = observer;
      return {
        release: session.release,
        observe: observer.observe,
        async inspect(specification, cases, domain, { signal }) {
          guard(signal);
          requireObservation(
            same(normalizeProviderSpec(specification), session.spec) &&
              same(domain, session.launchDomain),
          );
          const own = await members(session),
            images = [];
          for (const member of own.filter(
            (member) => member.pid !== session.probeIdentity.pid,
          )) {
            const executable = await kernel.fs.readlink(
              `/proc/${member.pid}/exe`,
            );
            requireObservation(!executable.endsWith(" (deleted)"));
            const actual = await kernel.fs.stat(`/proc/${member.pid}/exe`, {
                bigint: true,
              }),
              mapped = [];
            for (const candidate of session.launch.mappings) {
              const held = await (
                await tool(session, candidate.source)
              ).held.handle.stat({ bigint: true });
              if (actual.dev === held.dev && actual.ino === held.ino)
                mapped.push(candidate);
            }
            const mapping = mapped[0];
            const gate = await session.images
              .get(session.launch.gate)
              .held.handle.stat({ bigint: true });
            requireObservation(
              mapped.length === 1 ||
                (mapped.length === 0 &&
                  actual.dev === gate.dev &&
                  actual.ino === gate.ino),
            );
            if (mapping) {
              const env = (
                await kernel.fs.readFile(`/proc/${member.pid}/environ`)
              )
                .toString("utf8")
                .split("\0")
                .filter(Boolean)
                .sort();
              const expected = session.configuration.environment;
              requireObservation(
                new Set(env.map((entry) => entry.split("=", 1)[0])).size ===
                  env.length &&
                  expected.every((entry) => env.includes(entry)) &&
                  env.every(
                    (entry) =>
                      expected.includes(entry) ||
                      /^(?:PWD=\/workspace(?:\/[^\u0000-\u001f]*)?|SHLVL=[0-9]{1,3}|_=(?:\/runtime\/|\/bin\/|\/usr\/bin\/)[^\u0000-\u001f]+)$/u.test(
                        entry,
                      ),
                  ),
              );
              const maps = await kernel.text(
                `/proc/${member.pid}/maps`,
                1048576,
              );
              const files = maps
                .trim()
                .split("\n")
                .map((line) =>
                  line.match(
                    /^[a-f0-9]+-[a-f0-9]+\s+[-rwxps]{4}\s+[a-f0-9]+\s+([a-f0-9]+):([a-f0-9]+)\s+([0-9]+)(?:\s+(.*))?$/u,
                  ),
                );
              requireObservation(files.every(Boolean));
              const backing = files.filter((line) => line[3] !== "0");
              for (const line of backing) {
                requireObservation(
                  line[4]?.startsWith("/") && !line[4].endsWith(" (deleted)"),
                );
                const named = await kernel.fs.stat(
                    `/proc/${member.pid}/root${line[4]}`,
                    { bigint: true },
                  ),
                  major =
                    ((named.dev >> 8n) & 0xfffn) |
                    ((named.dev >> 32n) & 0xfffff000n),
                  minor =
                    (named.dev & 0xffn) | ((named.dev >> 12n) & 0xffffff00n);
                requireObservation(
                  major === BigInt("0x" + line[1]) &&
                    minor === BigInt("0x" + line[2]) &&
                    String(named.ino) === line[3] &&
                    session.launch.mappings.some((entry) => {
                      const identity = session.images.get(entry.source).held
                        .identity;
                      return (
                        identity.dev === String(named.dev) &&
                        identity.ino === String(named.ino)
                      );
                    }),
                );
              }
              images.push({
                member,
                executable,
                envSha256: observationDigest(env),
                mapsSha256: observationDigest(
                  backing.map((line) => line.slice(1)),
                ),
              });
            }
            const fresh = await kernel.fs.stat(`/proc/${member.pid}/exe`, {
              bigint: true,
            });
            requireObservation(
              fresh.dev === actual.dev &&
                fresh.ino === actual.ino &&
                (await kernel.fs.readlink(`/proc/${member.pid}/exe`)) ===
                  executable,
            );
          }
          requireObservation(
            same(await members(session), own) &&
              images.length > 0 &&
              session.transportVerified &&
              session.policyObserved &&
              observer.ready,
          );
          requireObservation(
            same(
              session.configuration.invocation,
              providerInvocation(session.spec),
            ) &&
              same(
                session.configuration.enabledTools,
                session.spec.provider === "codex"
                  ? ["exec_command", "write_stdin", "apply_patch"]
                  : [...CLAUDE_TOOLS],
              ),
          );
          const spec = session.spec,
            provenance = Object.fromEntries(
              Object.entries(spec.review.bindings)
                .filter(([, value]) => value)
                .map(([key, value]) => [key + "Sha256", value.sha256]),
            );
          const result = {
            status: "MATCHED",
            independent: true,
            candidateSha: spec.candidateSha,
            nonce: spec.nonce,
            packageSha256: spec.closureSha256,
            imageSha256: spec.entry.sha256,
            ...provenance,
            invocationSha256: observationDigest(providerInvocation(spec)),
            casesSha256: observationDigest(cases),
            cwd: cases.cwd,
            domainSha256: cases.plan.domainSha256,
            policySha256: cases.plan.policySha256,
            model: spec.model,
            profile: spec.profile,
            registrySha256: cases.registrySha256,
            nativeSha256: observationDigest({
              images,
              policy: session.policyObserved,
              transport: session.transportVerified,
            }),
            heldImages: true,
            loaderClosure: true,
            effectivePolicy: true,
            noHooks: true,
            noPlugins: true,
            noMcp: true,
            backgroundChildrenBound: true,
            relayReceiptPipePrivate: true,
            enabledTools: session.configuration.enabledTools,
          };
          return spec.provider === "codex"
            ? {
                ...result,
                sourceRevision: CODEX_RELEASE_REFERENCE.revision,
                reviewSha256: cases.plan.reviewSha256,
                toolMode: "direct",
                privateHomeCache: true,
                noAmbientAuth: true,
                noDynamicTools: true,
                noCodeMode: true,
                noHostControl: true,
                commandRuntimesBound: true,
                fileHandlersBound: true,
                executionServersBound: true,
                workersBound: true,
                internalEscalationBound: true,
              }
            : {
                ...result,
                version: CLAUDE_WRAPPER_REFERENCE.version,
                dispatcherSource: "UNAVAILABLE",
                platform: "linux",
                outerCompositionSha256: cases.plan.reviewSha256,
                privateHomeConfig: true,
                noRealCredential: true,
                noUpdater: true,
                noAlternateInstall: true,
                nativeRuntimeBound: true,
                fileToolsBound: true,
              };
        },
      };
    },
    async launchEffects(current, { signal }) {
      guard(signal);
      const session = get(current);
      const inventory = async () => {
        const identity = await kernel.process(session.gateIdentity.pid);
        requireObservation(
          same(identity.identity, session.gateIdentity.identity),
        );
        const base = `/proc/${identity.pid}`,
          mounts = (await kernel.text(base + "/mountinfo", 1048576))
            .trim()
            .split("\n")
            .map((line) => {
              const [left, right] = line.split(" - ");
              requireObservation(right);
              const fields = left.split(" "),
                details = right.split(" ");
              return {
                target: fields[4],
                options: fields[5].split(",").sort(),
                type: details[0],
                source: details[1],
              };
            })
            .sort((a, b) => a.target.localeCompare(b.target));
        requireObservation(
          mounts.find((item) => item.target === "/")?.options.includes("ro"),
        );
        for (const mapping of [
          ...session.launch.mappings,
          ...accessGrants(session.spec.profile, session.launch.storage).map(
            (grant) => ({ ...grant, writable: grant.writable }),
          ),
          {
            source: session.launch.storage.home,
            target: "/home/provider",
            writable: true,
          },
          {
            source: session.launch.storage.cache,
            target: "/cache",
            writable: true,
          },
          {
            source: session.launch.gate,
            target: "/proof/bin/provider-gate",
            writable: false,
          },
        ]) {
          const actual = await kernel.fs.stat(base + "/root" + mapping.target, {
              bigint: true,
            }),
            value = await tool(session, mapping.source),
            held = await value.held.handle.stat({ bigint: true });
          requireObservation(
            actual.dev === held.dev &&
              actual.ino === held.ino &&
              mounts
                .find((item) => item.target === mapping.target)
                ?.options.includes(mapping.writable ? "rw" : "ro"),
          );
        }
        const descriptors = (await kernel.fs.readdir(base + "/fd")).sort();
        requireObservation(descriptors.length <= 64);
        if (!session.payloadReleased)
          requireObservation(
            descriptors.every((fd) => ["0", "1", "2", "3", "4"].includes(fd)),
          );
        else
          for (const fd of descriptors) {
            const target = await kernel.fs.readlink(base + "/fd/" + fd);
            requireObservation(
              /^(?:pipe|socket):\[[1-9][0-9]*\]$/u.test(target) ||
                /^anon_inode:\[/u.test(target) ||
                ["/dev/null", "/dev/urandom"].includes(target) ||
                target.startsWith("/home/provider/") ||
                target.startsWith("/cache/") ||
                session.launch.mappings.some((item) => item.target === target),
            );
          }
        const idMap = async (name, key) =>
          (await kernel.text(base + "/" + name))
            .trim()
            .split("\n")
            .map((line) => {
              requireObservation(
                /^\s*[0-9]+\s+[0-9]+\s+[1-9][0-9]*\s*$/u.test(line),
              );
              const [inside, outside, count] = line
                .trim()
                .split(/\s+/u)
                .map(Number);
              requireObservation(
                [inside, outside, count].every(
                  (value) => Number.isSafeInteger(value) && value <= 4294967295,
                ),
              );
              return { inside, [key]: outside, count };
            });
        return {
          authority: identity.authority,
          namespaces: Object.fromEntries(
            Object.entries({
              pid: identity.namespaceId,
              net: identity.networkId,
              ipc: identity.ipcId,
              mnt: identity.mountId,
              user: identity.userId,
            }).map(([key, namespace]) => [
              key,
              { custodySha256: observationDigest(namespace) },
            ]),
          ),
          uidMap: await idMap("uid_map", "uid"),
          gidMap: await idMap("gid_map", "gid"),
          mounts,
          descriptors,
        };
      };
      session.inventory = inventory;
      return {
        async persist(record) {
          if (record.phase !== "release" || record.status === "FAIL")
            return session.persist(record);
          guard(signal);
          await session.persist(record);
          guard(signal);
          requireObservation(!session.retiring && !session.payloadRetired);
          session.payloadReleased = true;
        },
        processDetails: kernel.process,
        spawnProvider(file, args, settings) {
          guard(signal);
          requireObservation(
            !session.worker &&
              !session.retiring &&
              !session.payloadRetired &&
              file === session.launch.launcher &&
              same(args, linuxProviderArguments(session.spec, session.launch)),
          );
          const worker = kernel.start(
            "/usr/bin/strace",
            [
              ...linuxObserverArguments(),
              "-o",
              "/proc/self/fd/7",
              "--",
              file,
              ...args,
            ],
            {
              ...settings,
              persist: session.persist,
              stdio: [...settings.stdio, "pipe"],
            },
          );
          session.worker = worker;
          session.payloadReleased = false;
          session.observer.capture(worker.child.stdio[8]);
          session.tracePipeIdentity = kernel.fs.readlink(
            `/proc/self/fd/${worker.child.stdio[8]._handle.fd}`,
          );
          session.probes = linuxProviderFrames(worker.child.stdio[7]);
          return worker.child;
        },
        async verifyInputs(fixture, spec, templateSha256, requestSha256) {
          requireObservation(
            same(fixture, session.launch) &&
              same(spec, session.spec) &&
              templateSha256 === session.binding.approval.manifestSha256,
          );
          for (const value of session.images.values())
            await kernel.inspect(value.held);
          const sources = [];
          for (const [key, directory] of Object.entries(fixture.storage)) {
            const isDirectory = [
                "workspace",
                "metadata",
                "hooks",
                "home",
                "cache",
              ].includes(key),
              held =
                session.objects.get(directory)?.held ??
                session.images.get(directory)?.held ??
                (await kernel.hold(directory, {
                  directory: isDirectory,
                  sealed: !isDirectory,
                }));
            const stat = await kernel.inspect(held);
            requireObservation(
              stat.uid === String(options.ownerUid ?? process.getuid()),
            );
            sources.push(stat.dev + ":" + stat.ino);
            session.images.set(directory, { held });
          }
          requireObservation(new Set(sources).size === sources.length);
          await session.observer.initializeControls(signal);
          await session.persist({
            phase: "linux-provider-audit-possible",
            observationSha256: pins.get(session.bindings.observationFile)
              .sha256,
          });
          return {
            status: "MATCHED",
            independent: true,
            requestSha256,
            templateSha256,
            packageSha256: spec.closureSha256,
            immutableMappings: true,
            privateHomeCache: true,
            noWritableAliases: true,
          };
        },
        async verifyReceipt(record) {
          requireObservation(
            same(
              (await kernel.process(record.init.pid)).identity,
              record.init.identity,
            ) && same(record.admission.processIdentity, record.init.identity),
          );
          return { independent: true, sha256: observationDigest(record) };
        },
        async inspectGate(child, gate, record) {
          requireObservation(
            child === session.worker.child &&
              record.nonce === session.spec.nonce,
          );
          if (!session.gateIdentity) {
            const all = await kernel.processes(),
              descendants = new Set([record.init.pid]);
            for (let previous = -1; previous !== descendants.size;) {
              previous = descendants.size;
              for (const item of all)
                if (descendants.has(item.parent)) descendants.add(item.pid);
            }
            const selected = all.filter(
              (item) =>
                descendants.has(item.pid) &&
                item.nspid.at(-1) === gate.pid &&
                item.namespaceId !== record.init.namespaceId,
            );
            requireObservation(
              selected.length === 1 && selected[0].nspid.at(-1) === 1,
            );
            session.gateIdentity = selected[0];
            session.namespaces = await kernel.namespace(selected[0]);
            session.domain = {
              bootId: selected[0].identity.bootId,
              namespaceId: selected[0].namespaceId,
              initPid: selected[0].pid,
              initStartTicks: selected[0].identity.startTicks,
            };
            const hello = await session.probes.take(signal);
            observationObject(hello, ["phase", "nonce", "pid"]);
            requireObservation(
              hello.phase === "probes" && hello.nonce === session.spec.nonce,
            );
            const probes = all.filter(
              (item) =>
                item.namespaceId === selected[0].namespaceId &&
                item.nspid.at(-1) === hello.pid,
            );
            requireObservation(
              probes.length === 1 && probes[0].parent === selected[0].pid,
            );
            session.probeIdentity = probes[0];
            await session.persist({
              phase: "linux-provider-domain-held",
              id: current.recipe.id,
              identity: selected[0],
              probe: probes[0],
              domain: session.domain,
              namespaces: Object.fromEntries(
                Object.entries(session.namespaces).map(([key, item]) => [
                  key,
                  { identity: item.identity, label: item.label },
                ]),
              ),
            });
          }
          session.tracePipeIdentity = await session.tracePipeIdentity;
          requireObservation(
            /^(?:pipe|socket):\[[1-9][0-9]*\]$/u.test(
              session.tracePipeIdentity,
            ),
          );
          const policy = await inventory(),
            own = await members(session);
          const parent = await kernel.process(record.init.pid);
          requireObservation(
            session.gateIdentity.networkId !== parent.networkId &&
              session.gateIdentity.ipcId !== parent.ipcId &&
              session.gateIdentity.mountId !== parent.mountId &&
              session.gateIdentity.userId !== parent.userId,
          );
          session.kernelPolicy = policy;
          session.launchDomain ??= {
            independent: true,
            held: true,
            candidateSha: job.candidateSha,
            nonce: session.spec.nonce,
            networkPrivate: true,
            ipcPrivate: true,
            gatePid: gate.pid,
            rootReadOnly: true,
            immutableMappingsVerified: true,
            profile: session.spec.profile,
            policySha256: observationDigest(
              policyData(session, {
                launch: nativePolicyLaunchData(
                  {
                    candidateSha: session.spec.candidateSha,
                    nonce: session.spec.nonce,
                    fixture: session.launch,
                    executable: session.spec.entry,
                    packageReviewSha256: session.spec.closureSha256,
                    policy: {},
                    bindings: {},
                    execution: providerInvocation(session.spec).execution,
                  },
                  providerInvocation(session.spec).arguments,
                ),
                policy,
              }),
            ),
          };
          requireObservation(own.length >= 2);
          return structuredClone(session.launchDomain);
        },
        async readProvisioning() {
          requireObservation(session.domain);
          const bindings = session.binding.template.bindings.map((rule) => {
            const values = {
              "pid-namespace": observationDigest(
                session.gateIdentity.namespaceId,
              ),
              "network-namespace": observationDigest(
                session.gateIdentity.networkId,
              ),
              "ipc-namespace": observationDigest(session.gateIdentity.ipcId),
              "mount-namespace": observationDigest(
                session.gateIdentity.mountId,
              ),
              "user-namespace": observationDigest(session.gateIdentity.userId),
              "process-identity": session.gateIdentity.authority.identitySha256,
              "owner-uid": options.ownerUid ?? process.getuid(),
              "owner-gid": options.ownerGid ?? process.getgid(),
              nonce: session.spec.nonce,
              "endpoint-port": Number(new URL(session.spec.endpoint).port),
              session: session.gateIdentity.session,
            };
            requireObservation(Object.hasOwn(values, rule.id));
            return { id: rule.id, kind: rule.kind, value: values[rule.id] };
          });
          const value = {
            schemaVersion: 1,
            context: session.binding.context,
            authoritySha256: session.binding.template.provisioningReviewSha256,
            bindings,
            held: true,
            independent: true,
            verifierSha256: observationDigest(session.namespaces.pid.identity),
            nativeEventSha256: observationDigest({
              bindings,
              kernel: await inventory(),
            }),
          };
          session.provisioning = value;
          return value;
        },
        async readPolicy() {
          const expected = materializeNativePolicy(
              session.binding.template,
              session.binding.approval,
              session.provisioning,
              session.binding.context,
            ),
            actual = await inventory();
          const policy = policyData(session, {
            launch: nativePolicyLaunchData(
              {
                candidateSha: session.spec.candidateSha,
                nonce: session.spec.nonce,
                fixture: session.launch,
                executable: session.spec.entry,
                packageReviewSha256: session.spec.closureSha256,
                policy: {},
                bindings: {},
                execution: providerInvocation(session.spec).execution,
              },
              providerInvocation(session.spec).arguments,
            ),
            policy: actual,
          });
          requireObservation(same(policy, expected.policy));
          session.policyObserved = actual;
          return {
            schemaVersion: 1,
            context: session.binding.context,
            templateSha256: expected.templateSha256,
            provisioningSha256: expected.provisioningSha256,
            requestSha256: observationDigest({
              spec: session.spec,
              fixture: session.launch,
              args: linuxProviderArguments(session.spec, session.launch),
            }),
            policySha256: expected.expectedPolicySha256,
            policy,
            held: true,
            complete: true,
            independent: true,
            verifierSha256: observationDigest({
              namespaces: actual.namespaces,
            }),
            nativeEventSha256: observationDigest(actual),
          };
        },
        retire: () => retirePayload(session),
        async interruptProvider(mode, domain, { signal, taskIds }) {
          requireObservation(same(domain, session.launchDomain));
          const own = await members(session),
            background = own.filter(
              (item) =>
                ![session.gateIdentity.pid, session.probeIdentity.pid].includes(
                  item.pid,
                ),
            );
          requireObservation(
            background.length > 1 &&
              Array.isArray(taskIds) &&
              taskIds.length > 0 &&
              taskIds.length <= 32 &&
              new Set(taskIds).size === taskIds.length &&
              taskIds.every(
                (id) =>
                  typeof id === "string" && /^[A-Za-z0-9_-]{1,128}$/u.test(id),
              ),
          );
          const before = observationDigest(background),
            settlement = await retirePayload(session, signal);
          return {
            independent: true,
            candidateSha: job.candidateSha,
            nonce: session.spec.nonce,
            mode,
            domainSha256: observationDigest(session.domain),
            acknowledged: true,
            faultApplied: true,
            backgroundStarted: true,
            backgroundHeld: true,
            backgroundRetired: true,
            helpersSettled: true,
            nativeSha256: observationDigest({ before, settlement }),
            barrierSha256: before,
            taskIds: [...taskIds],
          };
        },
      };
    },
    async transportEffects(current) {
      const session = get(current);
      return (session.transport ??= createLinuxProviderTransport(
        session,
        dependencies,
      ));
    },
    async prepareCases(current, domain, { signal }) {
      guard(signal);
      const session = get(current);
      requireObservation(same(domain, session.launchDomain));
      const data = structuredClone(session.casesData);
      observationObject(data, ["cwd", "registrySha256", "cases", "routes"]);
      const routes = [];
      for (const route of data.routes) {
        const targets = session.observationData.targets.filter(
          (item) => item.routeId === route.id,
        );
        requireObservation(targets.length === 3);
        const hashes = {};
        for (const target of targets) {
          const object = session.objects.get(target.file);
          requireObservation(object);
          hashes[target.phase] = await session.observer.targetDigest(target);
        }
        routes.push({
          ...route,
          targetSha256: hashes.tool,
          permitTargetSha256: hashes["control-permit"],
          denyTargetSha256: hashes["control-deny"],
        });
      }
      const cases = {
        cwd: data.cwd,
        registrySha256: data.registrySha256,
        cases: data.cases,
        plan: {
          schemaVersion: 1,
          candidateSha: job.candidateSha,
          nonce: session.spec.nonce,
          domainSha256: observationDigest(session.domain),
          policySha256: current.policySha256,
          reviewSha256: current.recipe.reviewSha256,
          routes,
        },
      };
      session.cases = (
        session.spec.provider === "codex"
          ? normalizeCodexCases
          : normalizeClaudeCases
      )(session.spec, cases);
      return session.cases;
    },
    async retire(current, { signal }) {
      const session = sessions.get(current.recipe.id);
      requireObservation(session);
      return retireParticipants(session, signal);
    },
    async releaseAudit(current, payload) {
      const session = get(current);
      requireObservation(
        (payload === session.payloadRetired ||
          same(payload, session.payloadRetired)) &&
          (!session.transport || session.transportRetired),
      );
      const health = session.worker
        ? await session.observer.drain()
        : { notStarted: true };
      session.auditRetired = {
        ...retired(observationDigest(health)),
        drained: true,
      };
      await session.persist({
        phase: "linux-provider-audit-retired",
        health,
        settlement: session.auditRetired,
      });
      return session.auditRetired;
    },
    async restore(current) {
      return restore(get(current));
    },
    async recoverCases(records, { signal, persist }) {
      fenced = true;
      kernel.fence();
      const evidence = [];
      requireObservation(Array.isArray(records) && records.length <= 65536);
      for (const { name, record } of records) {
        const declared = manifest.providerPreparation.cases.find((item) =>
          same(item.custody.context, record.context),
        );
        requireObservation(
          declared &&
            name.startsWith(`provider-case-${declared.id}-`) &&
            /^(?:0|[1-9][0-9]{0,9})\.json$/u.test(
              name.slice(`provider-case-${declared.id}-`.length),
            ),
        );
      }
      for (const declared of manifest.providerPreparation.cases) {
        const relevant = records.filter(
            ({ record }) => record.context?.executionId === declared.id,
          ),
          births = relevant.filter(
            ({ record }) =>
              record.record?.phase === "linux-provider-domain-held",
          ),
          workers = relevant
            .filter(({ record }) => record.record?.phase === "worker-created")
            .map(({ record }) => record.record);
        if (!relevant.length) continue;
        requireObservation(
          relevant.some(
            ({ record }) => record.phase === "provisioning-possible",
          ) && births.length <= 1,
        );
        if (!workers.length) {
          requireObservation(
            !relevant.some(({ record }) =>
              [
                "admission-possible",
                "linux-provider-transport-possible",
              ].includes(record.record?.phase),
            ) && births.length === 0,
          );
          evidence.push({ id: declared.id, noWorker: true });
        }
        const authorities = [];
        for (const worker of workers) {
          const relay = linuxProviderRootArguments(process.execPath, RELAY),
            bridge = linuxProviderRootArguments(
              "/usr/bin/nsenter",
              ...linuxProviderBridgeArguments(
                process.execPath,
                BRIDGE,
                declared.launch.gate,
                declared.specification.nonce,
              ),
            ),
            parked = linuxProviderRootArguments(process.execPath, BRIDGE);
          requireObservation(
            (worker.file === "/usr/bin/strace" &&
              same(worker.args, [
                ...linuxObserverArguments(),
                "-o",
                "/proc/self/fd/7",
                "--",
                declared.launch.launcher,
                ...linuxProviderArguments(
                  declared.specification,
                  declared.launch,
                ),
              ])) ||
              (worker.file === "/usr/bin/sudo" &&
                [relay, bridge, parked].some((args) =>
                  same(args, worker.args),
                )),
          );
          requireObservation(
            worker.identity?.nspid?.at(-1) === 1 &&
              same(
                worker.identity.identity,
                worker.admission.processIdentity,
              ) &&
              worker.admission.namespaceId === worker.identity.namespaceId &&
              worker.identity.namespaceId !==
                (await kernel.process(options.pid ?? process.pid)).namespaceId,
          );
          authorities.push(worker.identity);
        }
        // Stop the provider domain before relay/bridge helpers. Every recorded
        // supervisor is a held private PID-namespace init, not a process name.
        if (births.length) {
          const birth = births[0].record.record;
          requireObservation(
            birth.id === declared.id &&
              same(birth.domain, {
                bootId: birth.identity.identity.bootId,
                namespaceId: birth.identity.namespaceId,
                initPid: birth.identity.pid,
                initStartTicks: birth.identity.identity.startTicks,
              }),
          );
          authorities.unshift(birth.identity);
        }
        const bootstrap = manifest.inputs.find(
            (item) =>
              item.sha256 ===
              manifest.helpers.find((helper) => helper.name === "provider-gate")
                ?.sha256,
          ),
          session = {
            launch: {
              ...declared.launch,
              gate: bootstrap?.path ?? declared.launch.gate,
            },
            images: new Map(),
          };
        for (const identity of authorities) {
          const all = await kernel.processes(),
            live = all.find((item) => item.pid === identity.pid);
          if (live) {
            requireObservation(
              same(live.identity, identity.identity) &&
                live.namespaceId === identity.namespaceId &&
                !signal?.aborted,
            );
            const worker = [...kernel.workers].find(
              (item) => item.identity && same(item.identity, identity),
            );
            const heldSession = sessions.get(declared.id);
            if (
              heldSession?.gateIdentity &&
              same(heldSession.gateIdentity, identity)
            )
              await retirePayload(heldSession, signal);
            else if (worker) await kernel.retire(worker);
            else
              await retireLinuxProviderIdentity(
                identity,
                session,
                dependencies,
                { signal, persist },
              );
          }
          const after = await kernel.processes();
          requireObservation(
            !after.some(
              (item) =>
                item.namespaceId === identity.namespaceId ||
                item.pid === identity.pid,
            ),
          );
          evidence.push({
            id: declared.id,
            identity,
            retirementSha256: observationDigest(after),
          });
        }
        // A birth for another helper cannot settle an unreturned admission.
        const possible = relevant.filter(
            ({ record }) =>
              record.record?.phase === "linux-provider-transport-possible",
          ),
          counts = new Map();
        for (const {
          record: { record: intent },
        } of possible) {
          const key = observationDigest(intent.args);
          counts.set(key, (counts.get(key) ?? 0) + 1);
        }
        for (const [key, count] of counts)
          requireObservation(
            workers.filter(
              (worker) =>
                worker.file === "/usr/bin/sudo" &&
                observationDigest(worker.args) === key,
            ).length === count,
          );
        requireObservation(
          !relevant.some(
            ({ record }) => record.record?.phase === "admission-possible",
          ) || workers.some((worker) => worker.file === "/usr/bin/strace"),
        );
        for (const value of session.images.values())
          await kernel.inspect(value.held);
        const existing = sessions.get(declared.id);
        if (existing) {
          existing.payloadRetired ??= retired(observationDigest(evidence));
          await retireParticipants(existing, signal);
          if (existing.worker) {
            const health = await existing.observer.drain();
            existing.auditRetired = {
              ...retired(observationDigest(health)),
              drained: true,
            };
            await existing.persist({
              phase: "linux-provider-audit-retired",
              health,
              settlement: existing.auditRetired,
            });
          }
          await existing.observer?.closeControls();
        }
        if (workers.length && !existing?.auditRetired) {
          const audits = relevant.filter(
            ({ record }) =>
              record.record?.phase === "linux-provider-audit-retired",
          );
          requireObservation(audits.length > 0);
          for (const {
            record: { record: audit },
          } of audits) {
            assertNativeObserverHealth(audit.health);
            requireObservation(
              same(audit.settlement, {
                ...retired(observationDigest(audit.health)),
                drained: true,
              }),
            );
          }
        }
        const controls = relevant.filter(
            ({ record }) =>
              record.record?.phase === "linux-provider-outside-control-held",
          ),
          possibleControls = relevant.filter(
            ({ record }) =>
              record.record?.phase ===
              "linux-provider-outside-control-possible",
          );
        requireObservation(
          possibleControls.every(({ record }) =>
            controls.some((item) =>
              same(item.record.record.declaration, record.record.declaration),
            ),
          ),
        );
        for (const { record } of relevant.filter(
          ({ record }) =>
            record.record?.phase === "linux-provider-outside-control-held",
        )) {
          const control = record.record,
            alive = (await kernel.processes()).find(
              (item) => item.pid === control.owner.pid,
            );
          if (alive) {
            requireObservation(same(alive.identity, control.owner.identity));
            const descriptors = await kernel.fs.readdir(
              `/proc/${alive.pid}/fd`,
            );
            for (const fd of descriptors)
              requireObservation(
                (await kernel.fs.readlink(`/proc/${alive.pid}/fd/${fd}`)) !==
                  control.inode,
              );
          }
        }
      }
      for (const value of kernel.namespaces) await kernel.closeNamespace(value);
      for (const value of kernel.handles) await kernel.close(value);
      return {
        ...retired(observationDigest(evidence)),
        recordsSha256: observationDigest(records),
      };
    },
  };
}

// Kept private to the platform owner; bytes, rather than parsed JSON, are pins.
const digestBytes = (bytes) => createHash("sha256").update(bytes).digest("hex");
