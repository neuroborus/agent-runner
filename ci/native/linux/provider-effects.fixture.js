import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { PassThrough, Readable } from "node:stream";
import { EventEmitter } from "node:events";
import { getSystemErrorName } from "node:util";
import { providerPreparationFixture } from "../providers/preparation.fixture.js";
import { prerequisiteFixture } from "../prerequisite-fixture.js";
import {
  normalizeProviderSpec,
  providerInvocation,
  CLAUDE_TOOLS,
  CODEX_TOOL_CASES,
  CLAUDE_TOOL_CASES,
} from "../providers/index.js";
import {
  observationDigest,
  nativePolicyLaunchData,
  nativePolicyTemplateDigest,
  normalizeNativePolicyBinding,
} from "../index.js";
import { accessGrants } from "./profiles.js";
import { linuxKernelAuthority } from "./inspect.js";

export const providerFixtureDigest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

function literalCases(spec, root, nonceSha256) {
  const inventory =
      spec.provider === "codex" ? CODEX_TOOL_CASES : CLAUDE_TOOL_CASES,
    routes = [],
    cases = [],
    targets = [];
  for (const [id, declaration] of Object.entries(inventory)) {
    const operation = Array.isArray(declaration) ? declaration[0] : declaration,
      permit =
        [
          "command",
          "read",
          "glob",
          "grep",
          "end-conversation",
          "command-background",
          "background-cancel",
          "background-helper-loss",
        ].includes(id) ||
        (["edit", "write"].includes(id) && spec.profile !== "read-only"),
      command = "cat /workspace/value",
      changed = providerFixtureDigest(Buffer.from("changed value"));
    routes.push({
      id,
      operation,
      nonceSha256,
      beforeSha256: nonceSha256,
      afterSha256:
        permit && ["edit", "write"].includes(id) ? changed : nonceSha256,
      outcome: permit ? "permit" : "deny",
    });
    for (const [index, phase] of [
      "tool",
      "control-permit",
      "control-deny",
    ].entries())
      targets.push({
        routeId: id,
        phase,
        file: root + "/workspace/value",
        selector: `/workspace/${id}-${index}`,
        opcode: "openat",
        action: {
          operation: "read",
          target: `/workspace/${id}-${index}`,
          data: "",
        },
      });
    if (spec.provider === "codex")
      cases.push({
        id,
        command: id === "edit" ? null : command,
        commandSha256:
          id === "edit" ? null : providerFixtureDigest(Buffer.from(command)),
        patch:
          id === "edit"
            ? "*** Begin Patch\n*** Update File: value\n@@\n-owned nonce\n+changed value\n*** End Patch"
            : null,
        changesSha256: id === "edit" ? changed : null,
        outputSha256: ["command", "read"].includes(id) ? nonceSha256 : null,
      });
    else {
      const name = declaration[1],
        inputs = {
          Bash: { command, run_in_background: id.startsWith("background-") },
          Read: { file_path: "/workspace/value" },
          Glob: { pattern: "value", path: "/workspace" },
          Grep: { pattern: "owned nonce", path: "/workspace/value" },
          Edit: {
            file_path: "/workspace/value",
            old_string: "owned nonce",
            new_string: "changed value",
          },
          Write: { file_path: "/workspace/value", content: "changed value" },
        };
      cases.push({
        id,
        tools: [
          ...(id === "edit"
            ? [{ name: "Read", input: inputs.Read, outputSha256: nonceSha256 }]
            : []),
          {
            name,
            input: inputs[name],
            outputSha256: [
              "command",
              "read",
              "glob",
              "grep",
              "end-conversation",
            ].includes(id)
              ? nonceSha256
              : null,
          },
          {
            name: "EndConversation",
            input: { reason: "complete" },
            outputSha256: null,
          },
        ],
      });
    }
  }
  return {
    cases: {
      cwd: "/workspace",
      registrySha256: observationDigest(inventory),
      cases,
      routes,
    },
    targets,
  };
}

/** Held files and procfs bytes only. Proofs are produced by the repository
 * owners; the fixture supplies no accepted native callback results. */
export async function linuxProviderFixture() {
  const prepared = providerPreparationFixture(),
    raw = await prerequisiteFixture(),
    input = prepared.input,
    records = [],
    fs = { ...raw.edges.fs };
  delete input.api;
  raw.add(input.directory);
  raw.add(input.providerHelpers);
  const asset = (file, bytes, mode = 0o444) => {
    raw.add(file, bytes, mode);
    input.manifest.inputs = input.manifest.inputs.filter(
      (item) => item.path !== file,
    );
    const value = {
      path: file,
      bytes: bytes.length,
      sha256: providerFixtureDigest(bytes),
    };
    input.manifest.inputs.push(value);
    return value;
  };
  for (const tool of [
    "/usr/bin/strace",
    "/usr/bin/nsenter",
    "/usr/bin/sudo",
    "/usr/bin/env",
    "/usr/bin/bwrap",
    process.execPath,
  ])
    asset(tool, Buffer.from("sealed " + tool), 0o555);
  for (const name of ["relay-process.js", "bridge-process.js"]) {
    const file = fileURLToPath(
      new URL("../providers/" + name, import.meta.url),
    );
    asset(file, await readFile(file));
  }
  const source = fileURLToPath(new URL("./provider-gate.c", import.meta.url)),
    sourceBytes = await readFile(source),
    gate = Buffer.from("approved gate binary");
  raw.add(input.providerHelpers + "/provider-gate", gate, 0o555);
  raw.add(
    input.manifest.providerPreparation.sourceDirectory + "/provider-gate.c",
    sourceBytes,
  );
  input.manifest.helpers[0] = {
    name: "provider-gate",
    sha256: providerFixtureDigest(gate),
    sourceSha256: providerFixtureDigest(sourceBytes),
  };
  const data = asset("/fixture/sealed/nonce", Buffer.from("owned nonce")),
    operation = asset(
      "/fixture/sealed/operation",
      Buffer.from("fixed operation"),
    );
  const components = [];
  for (const declared of input.manifest.providerPreparation.cases) {
    const spec = declared.specification;
    spec.home = "/home/provider";
    spec.cache = "/cache";
    spec.path = "/runtime/bin";
    const packageDirectory = `/fixture/sealed/${declared.id}-package`,
      image = asset(
        packageDirectory + "/" + spec.review.files[0].path,
        Buffer.alloc(100, 97),
        0o555,
      );
    spec.review.files[0].sha256 = image.sha256;
    const normalized = normalizeProviderSpec(spec),
      root = input.directory + "/cases/" + declared.id;
    declared.launch = {
      directory: root,
      launcher: "/usr/bin/bwrap",
      gate: input.providerHelpers + "/provider-gate",
      entrypoint: "/runtime/" + normalized.entry.path,
      storage: {
        workspace: root + "/workspace",
        metadata: root + "/metadata",
        pointer: root + "/pointer",
        git: root + "/git",
        operation: root + "/operation",
        hooks: root + "/hooks",
        home: root + "/home",
        cache: root + "/cache",
      },
      mappings: [
        {
          source: image.path,
          target: "/runtime/" + normalized.entry.path,
          sha256: image.sha256,
          bytes: image.bytes,
        },
      ],
      reviewSha256: prepared.templates.find(
        ({ template }) => template.policy.launch.profile === spec.profile,
      ).approval.manifestSha256,
      probeChannels: true,
    };
    const literal = (name, value) =>
      asset(
        `/fixture/sealed/${declared.id}-${name}.json`,
        Buffer.from(JSON.stringify(value)),
      );
    const bindings = declared.bindings;
    const review = asset(
      `/fixture/sealed/${declared.id}-review.json`,
      Buffer.from(JSON.stringify(spec.review)),
    );
    bindings.release = {
      schemaVersion: 1,
      candidateSha: input.job.candidateSha,
      components,
      providers: {
        codex: {},
        claude: {},
        [spec.provider]: {
          reviewFile: review.path,
          directory: packageDirectory,
        },
      },
    };
    components.push({
      id: declared.id,
      path: image.path,
      bindings: Object.fromEntries(
        ["publication", "source", "build", "license"].map((key) => [
          key,
          review.path,
        ]),
      ),
    });
    bindings.compilerVersion = "13.3.0";
    const complete = literalCases(normalized, root, data.sha256),
      reviewSha256 = input.manifest.execution.cases.find(
        (item) => item.id === declared.id,
      ).reviewSha256;
    bindings.casesFile = literal("cases", complete.cases).path;
    bindings.observationFile = literal("observation", {
      targets: complete.targets,
      pins: {
        manifestSha256: reviewSha256,
        imageSha256: input.manifest.inputs.find(
          (item) => item.path === "/usr/bin/strace",
        ).sha256,
        sourceSha256: reviewSha256,
        abiSha256: reviewSha256,
      },
      outsideControls: [],
    }).path;
    bindings.transportControlsFile = literal("controls", {}).path;
    bindings.configurationFile = literal("configuration", {
      invocation: providerInvocation(normalized),
      environment: Object.entries(
        providerInvocation(normalized).execution.environment,
      )
        .map(([key, value]) => `${key}=${value}`)
        .sort(),
      enabledTools:
        spec.provider === "codex"
          ? ["exec_command", "write_stdin", "apply_patch"]
          : [...CLAUDE_TOOLS],
    }).path;
    bindings.files = [
      { path: root + "/pointer", input: operation.path, writable: false },
      { path: root + "/git", input: image.path, writable: false },
      { path: root + "/operation", input: operation.path, writable: false },
      { path: root + "/workspace/value", input: data.path, writable: true },
    ];
  }
  input.manifest.release.components = components.map((entry) => ({
    id: entry.id,
    sha256: input.manifest.inputs.find((pin) => pin.path === entry.path).sha256,
  }));
  fs.open = async (...args) => {
    const handle = await raw.edges.fs.open(...args);
    let closed = false;
    return {
      ...handle,
      async stat(...settings) {
        if (closed)
          throw Object.assign(new Error("Closed descriptor"), {
            code: "EBADF",
          });
        return handle.stat(...settings);
      },
      async close() {
        await handle.close();
        closed = true;
      },
    };
  };
  fs.mkdir = async (file, settings) => {
    if (!raw.nodes.has(file)) {
      raw.add(file, null, settings.mode);
      raw.events.push("mkdir:" + file);
    }
  };
  fs.writeFile = async (file, bytes, settings) => {
    if (raw.nodes.has(file))
      throw Object.assign(new Error("Exclusive creation"), { code: "EEXIST" });
    raw.add(file, bytes, settings.mode);
    raw.events.push("write:" + file);
  };
  fs.readFile = async (file) => {
    if (raw.nodes.has(file)) return Buffer.from(raw.nodes.get(file).content);
    const handle = await fs.open(file, 0);
    try {
      const bytes = Buffer.alloc(65536),
        { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
      return bytes.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  };
  fs.lstat = async (file) => ({
    ...(await raw.edges.fs.lstat(file)),
    isSymbolicLink: () => false,
  });
  return {
    ...prepared,
    raw,
    records,
    input,
    options: {
      fs,
      ownerUid: 0,
      pid: 42,
      env: {
        CI: "true",
        GITHUB_ACTIONS: "true",
        ImageOS: "ubuntu24",
        RUNNER_TEMP: "/fixture",
      },
    },
    persist: async (record) => {
      records.push(structuredClone(record));
      raw.events.push("intent:" + record.phase);
    },
  };
}

/** Native process edges: raw procfs, inherited pipes and supervisor births.
 * No policy, admission, observation or retirement verdict is injected. */
export async function linuxProviderProcessFixture(
  provider = "codex",
  profile = "read-only",
  withControls = false,
  caseId = null,
) {
  const f = await linuxProviderFixture(),
    fs = f.options.fs,
    declared = f.input.manifest.providerPreparation.cases.find(
      (item) =>
        item.specification.provider === provider &&
        item.specification.profile === profile &&
        (caseId === null || item.id === caseId),
    ),
    spec = normalizeProviderSpec(declared.specification),
    launch = declared.launch,
    processes = new Map(),
    pipes = new Map(),
    children = [],
    bootId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  let nextPid = 100,
    nextFd = 500,
    tick = 0;
  const status = (item) =>
    `Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nNSpid:\t${item.nspid.join("\t")}\n${["Inh", "Prm", "Eff", "Bnd", "Amb"].map((key) => `Cap${key}:\t0000000000000000`).join("\n")}\nNoNewPrivs:\t1\nSeccomp:\t0\n`;
  const member = (
    pid,
    parent,
    namespace = pid,
    local = [pid, 1],
    entry = null,
    network = namespace,
  ) => {
    const value = {
      pid,
      parent,
      session: pid,
      startTicks: String(pid + 1000),
      nspid: local,
      namespaces: Object.fromEntries(
        ["pid", "net", "ipc", "mnt", "user"].map((key) => [
          key,
          `${key}:[${1000 + (key === "net" ? network : namespace)}]`,
        ]),
      ),
      entry,
      argv: entry ? [process.execPath, entry] : [],
      descriptors: Object.fromEntries(
        [0, 1, 2, 3, 4].map((fd) => [String(fd), `pipe:[${pid * 10 + fd}]`]),
      ),
    };
    processes.set(pid, value);
    return value;
  };
  member(1, 0, 1, [1]);
  member(42, 1, 1, [42]);
  const gate = member(72, 70, 72, [72, 3, 1]);
  const prober = member(74, 72, 72, [74, 4, 2]);
  processes.delete(72);
  processes.delete(74);
  delete gate.descriptors["4"];
  const grants = [
    ...launch.mappings.map((item) => ({ ...item, writable: false })),
    ...accessGrants(profile, launch.storage),
    { source: launch.storage.home, target: "/home/provider", writable: true },
    { source: launch.storage.cache, target: "/cache", writable: true },
    {
      source: launch.gate,
      target: "/proof/bin/provider-gate",
      writable: false,
    },
  ];
  const mounts = [
    { target: "/", options: ["ro"], type: "tmpfs", source: "tmpfs" },
    ...grants.map((item) => ({
      target: item.target,
      options: [item.writable ? "rw" : "ro"],
      type: "ext4",
      source: "/dev/owned",
    })),
  ].sort((a, b) => a.target.localeCompare(b.target));
  const stat = (node) => ({
    ...node,
    size: BigInt(node.content?.length ?? 0),
    isFile: () => node.content !== null,
    isDirectory: () => node.content === null,
  });
  const errno = () =>
    Object.assign(new Error("Missing native object"), { code: "ENOENT" });
  const native = (file) => {
    if (file === "/proc/sys/kernel/random/boot_id")
      return Buffer.from(bootId + "\n");
    if (file === "/proc/self/mountinfo")
      return Buffer.from("1 0 0:1 / /proc rw - proc proc rw\n");
    if (file === "/proc/sys/kernel/yama/ptrace_scope")
      return Buffer.from("1\n");
    const match = file.match(
        /^\/proc\/([0-9]+)\/(stat|status|cmdline|environ|mountinfo|uid_map|gid_map|maps|net\/tcp)$/u,
      ),
      item = match && processes.get(Number(match[1]));
    if (!item) throw errno();
    if (match[2] === "stat")
      return Buffer.from(
        `${item.pid} (owned) S ${item.parent} ${item.pid} ${item.session} ${Array(15).fill("0").join(" ")} ${item.startTicks}\n`,
      );
    if (match[2] === "status") return Buffer.from(status(item));
    if (match[2] === "cmdline") return Buffer.from(item.argv.join("\0") + "\0");
    if (match[2] === "environ")
      return Buffer.from(
        "PATH=/usr/bin:/bin\0LANG=C\0CI=true\0GITHUB_ACTIONS=true\0",
      );
    if (["uid_map", "gid_map"].includes(match[2]))
      return Buffer.from("0 1000 1\n");
    if (match[2] === "mountinfo")
      return Buffer.from(
        mounts
          .map(
            (mount, index) =>
              `${index + 1} 0 1:1 / ${mount.target} ${mount.options.join(",")} - ${mount.type} ${mount.source} rw`,
          )
          .join("\n") + "\n",
      );
    if (match[2] === "net/tcp")
      return Buffer.from(
        "header\n 0: 0100007F:A029 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 9999 1\n",
      );
    throw errno();
  };
  const edges = {
    ...fs,
    async readFile(file) {
      return file.startsWith("/proc/") ? native(file) : fs.readFile(file);
    },
    async readlink(file) {
      if (file.startsWith("/proc/self/fd/")) {
        const value = pipes.get(Number(file.split("/").at(-1)));
        if (!value) throw errno();
        return value;
      }
      const match = file.match(
          /^\/proc\/([0-9]+)\/(?:ns\/(pid|net|ipc|mnt|user)|fd\/([0-9]+)|exe)$/u,
        ),
        item = match && processes.get(Number(match[1]));
      if (!item) throw errno();
      if (match[2]) return item.namespaces[match[2]];
      if (match[3]) {
        if (!item.descriptors[match[3]]) throw errno();
        return item.descriptors[match[3]];
      }
      return process.execPath;
    },
    async readdir(file, ...rest) {
      if (file === "/proc") return [...processes.keys()].map(String);
      const match = file.match(/^\/proc\/([0-9]+)\/fd$/u);
      if (match) {
        const item = processes.get(Number(match[1]));
        if (!item) throw errno();
        return Object.keys(item.descriptors);
      }
      return fs.readdir(file, ...rest);
    },
    async stat(file, ...rest) {
      if (file.endsWith("/exe")) return fs.lstat(process.execPath);
      const match = file.match(/^\/proc\/(72|74)\/root(\/.*)$/u);
      if (match) {
        const grant = grants.find((item) => item.target === match[2]),
          target = targets.find((item) => item.selector === match[2]);
        if (!grant && !target) throw errno();
        return fs.lstat(grant?.source ?? target.file);
      }
      return fs.stat(file, ...rest);
    },
    async open(file, flags, ...rest) {
      const match = file.match(
          /^\/proc\/([0-9]+)\/ns\/(pid|net|ipc|mnt|user)$/u,
        ),
        item = match && processes.get(Number(match[1]));
      if (!match) return fs.open(file, flags, ...rest);
      if (!item) throw errno();
      const inode = BigInt(item.namespaces[match[2]].match(/\[([0-9]+)\]/u)[1]),
        handle = { fd: ++nextFd },
        node = { dev: 4n, ino: inode, content: null };
      let closed = false;
      f.raw.handles.add(handle);
      handle.stat = async () => {
        if (closed)
          throw Object.assign(new Error("Closed namespace"), { code: "EBADF" });
        return stat(node);
      };
      handle.close = async () => {
        closed = true;
        f.raw.handles.delete(handle);
      };
      return handle;
    },
  };
  const input = f.raw.nodes.get(declared.bindings.observationFile),
    hash = observationDigest("review");
  const targets = literalCases(
    spec,
    launch.directory,
    providerFixtureDigest(Buffer.from("owned nonce")),
  ).targets;
  const outsideControls = [];
  if (withControls) {
    const file = launch.directory + "/workspace/value",
      tcp = "127.0.0.1:42002",
      unix = launch.directory + "/outside.sock";
    for (const [index, selector] of [tcp, unix].entries()) {
      const target = targets.find(
        (item) =>
          item.routeId === "outside" &&
          item.phase === (index ? "control-deny" : "tool"),
      );
      target.selector = selector;
      target.opcode = "connect";
      target.action = {
        operation: index ? "ipc" : "network",
        target: selector,
        data: "",
      };
      outsideControls.push({ kind: index ? "unix" : "tcp", selector, file });
    }
    const action = (operation, target, expectedError) => ({
        action: { operation, target, data: "" },
        expectedError,
      }),
      controls = {
        transport: action("network", new URL(spec.endpoint).host, 0),
        "credential-file": action("read", file, 2),
        "credential-environment": action("read", "relay-environment", 2),
        "credential-process": action("read", "relay-memory", 2),
        debug: action("debug", "relay", 3),
        signal: action("signal", "relay", 3),
        "alternate-network": action("network", tcp, 111),
        "alternate-ipc": action("ipc", unix, 2),
        "relay-loss": {},
        "bridge-loss": {},
      };
    const bytes = Buffer.from(JSON.stringify(controls)),
      controlPin = f.input.manifest.inputs.find(
        (item) => item.path === declared.bindings.transportControlsFile,
      );
    f.raw.nodes.get(controlPin.path).content = bytes;
    controlPin.bytes = bytes.length;
    controlPin.sha256 = providerFixtureDigest(bytes);
  }
  input.content = Buffer.from(
    JSON.stringify({
      targets,
      pins: {
        manifestSha256: hash,
        imageSha256: f.input.manifest.inputs.find(
          (pin) => pin.path === "/usr/bin/strace",
        ).sha256,
        sourceSha256: hash,
        abiSha256: hash,
      },
      outsideControls,
    }),
  );
  const pin = f.input.manifest.inputs.find(
    (pin) => pin.path === declared.bindings.observationFile,
  );
  pin.bytes = input.content.length;
  pin.sha256 = providerFixtureDigest(input.content);
  const expected = {
    launch: nativePolicyLaunchData(
      {
        candidateSha: spec.candidateSha,
        nonce: spec.nonce,
        fixture: launch,
        executable: spec.entry,
        packageReviewSha256: spec.closureSha256,
        policy: {},
        bindings: {},
        execution: providerInvocation(spec).execution,
      },
      providerInvocation(spec).arguments,
    ),
    policy: {
      authority: linuxKernelAuthority(status(gate), {
        ...gate,
        identity: { bootId, startTicks: gate.startTicks },
      }),
      namespaces: Object.fromEntries(
        Object.entries(gate.namespaces).map(([key, value]) => [
          key,
          { custodySha256: observationDigest(value) },
        ]),
      ),
      uidMap: [{ inside: 0, uid: 1000, count: 1 }],
      gidMap: [{ inside: 0, gid: 1000, count: 1 }],
      mounts,
      descriptors: Object.keys(gate.descriptors).sort(),
    },
  };
  const template = { ...f.templates[0].template, policy: expected };
  const binding = normalizeNativePolicyBinding({
    template,
    approval: {
      ...f.templates[0].approval,
      manifestSha256: nativePolicyTemplateDigest(template),
    },
    context: declared.custody.context,
  });
  const trace = (child, pid, body) =>
    child.stdio[8].write(
      `${pid} 1000.${String(++tick).padStart(6, "0")} ${body}\n`,
    );
  const spawn = (file, args, settings) => {
    const child = new EventEmitter(),
      pid = file === "/usr/bin/strace" ? 70 : ++nextPid,
      supervisor = member(pid, 42),
      role =
        args.includes("--bridge-loopback") ||
        args.at(-1).endsWith("bridge-process.js")
          ? "bridge"
          : "relay",
      entry = args.at(-1),
      nativeProcess =
        file === "/usr/bin/strace"
          ? null
          : member(
              ++nextPid,
              pid,
              pid,
              [nextPid, 2],
              entry,
              role === "bridge" && args.includes("--bridge-loopback")
                ? 72
                : pid,
            );
    let done;
    const descriptors = [...settings.stdio];
    descriptors.splice(3, 0, "ipc");
    child.stdio = descriptors.map((_, index) => {
      const stream = new PassThrough(),
        fd = ++nextFd;
      stream._handle = { fd };
      pipes.set(fd, `pipe:[${pid * 10 + index}]`);
      return stream;
    });
    if (nativeProcess)
      nativeProcess.descriptors = Object.fromEntries(
        [0, 1, 2, 3, 4].map((fd) => [
          String(fd),
          `pipe:[${pid * 10 + (fd >= 3 ? fd + 1 : fd)}]`,
        ]),
      );
    child.stdin = child.stdio[0];
    child.stdout = child.stdio[1];
    child.stderr = child.stdio[2];
    child.stderr.on("error", () => {});
    child.ownedCompletion = new Promise((resolve) => {
      done = resolve;
    });
    children.push(child);
    const identity = { bootId, startTicks: supervisor.startTicks },
      admission = {
        processIdentity: identity,
        namespaceId: supervisor.namespaces.pid,
      };
    settings.signal.addEventListener(
      "abort",
      () => {
        for (const item of [...processes.values()])
          if (
            item.namespaces.pid === supervisor.namespaces.pid ||
            (file === "/usr/bin/strace" &&
              item.namespaces.pid === gate.namespaces.pid)
          )
            processes.delete(item.pid);
        for (const stream of child.stdio) stream.end();
        done({ type: "close", exitCode: 0, signal: null });
      },
      { once: true },
    );
    Promise.resolve()
      .then(async () => {
        await settings.onProcess(pid, admission);
        if (file === "/usr/bin/strace") {
          processes.set(72, gate);
          processes.set(74, prober);
          child.stdio[5].end(
            JSON.stringify({ nonce: spec.nonce, pid: 1 }) + "\n",
          );
          child.stdio[7].write(
            JSON.stringify({ phase: "probes", nonce: spec.nonce, pid: 2 }) +
              "\n",
          );
          trace(child, 4, "write(0x6, 0x123, 0x40) = 0x40");
          child.stdio[6].on("data", (bytes) => {
            const [sequence, operation, targetHex] = bytes
                .toString()
                .trim()
                .split(" "),
              target = Buffer.from(targetHex, "hex").toString();
            const error =
              withControls && operation !== "barrier"
                ? operation === "network"
                  ? target === new URL(spec.endpoint).host
                    ? 0
                    : 111
                  : operation === "ipc" ||
                      target.startsWith("/proc/") ||
                      target.startsWith(launch.directory)
                    ? 2
                    : ["signal", "debug"].includes(operation)
                      ? 3
                      : target.endsWith("2")
                        ? 13
                        : 0
                : target.endsWith("2")
                  ? 13
                  : 0;
            const result = error
              ? -1
              : ["read", "write"].includes(operation)
                ? 9
                : 0;
            if (operation !== "barrier") {
              const [host, port] = target.split(":"),
                syscall =
                  operation === "network"
                    ? `connect(8, {sa_family=AF_INET, sin_port=htons(${port}), sin_addr=inet_addr("${host}")}, 16)`
                    : operation === "ipc"
                      ? `connect(8, {sa_family=AF_UNIX, sun_path="${target}"}, 110)`
                      : operation === "signal"
                        ? `kill(${target}, 0)`
                        : operation === "debug"
                          ? `ptrace(0x10, ${target}, 0, 0)`
                          : `openat(AT_FDCWD, "${target}", O_RDONLY)`;
              trace(
                child,
                4,
                `${syscall} = ${error ? "-1 " + getSystemErrorName(-error) : result}`,
              );
            }
            child.stdio[7].write(
              JSON.stringify({
                sequence: Number(sequence),
                pid: 2,
                result,
                error,
              }) + "\n",
            );
            trace(child, 4, "write(0x6, 0x123, 0x40) = 0x40");
          });
        } else {
          const ready = () =>
            child.stdio[5].write(
              JSON.stringify({ phase: role + "-ready", pid: 2 }) + "\n",
            );
          if (args.includes("--bridge-loopback")) {
            child.stdio[5].write(
              JSON.stringify({
                phase: "bridge-loopback",
                nonce: spec.nonce,
                netInode: "1072",
              }) + "\n",
            );
            child.stdio[4].once("data", ready);
            child.stdio[4].once("finish", () => {
              delete nativeProcess.descriptors["3"];
              delete nativeProcess.descriptors["4"];
              nativeProcess.descriptors["9"] = "socket:[9999]";
              child.stdio[5].end(
                JSON.stringify({
                  nonce: spec.nonce,
                  endpoint: spec.endpoint,
                  configurationSha256: observationDigest({
                    specificationSha256:
                      providerInvocation(spec).specificationSha256,
                    policy: declared.bindings.relayPolicy,
                  }),
                }) + "\n",
              );
            });
          } else ready();
        }
      })
      .catch((error) => {
        child.stderr.destroy(error);
        done({ type: "close", exitCode: 126, signal: null });
      });
    return child;
  };
  const sockets = new Map();
  const server = (handler) => {
    const value = new EventEmitter(),
      fd = ++nextFd;
    value._handle = { fd };
    value.listening = false;
    value.listen = (address) => {
      const selector =
        typeof address === "string"
          ? address
          : `${address.host}:${address.port}`;
      sockets.set(selector, { handler, value });
      pipes.set(fd, `socket:[${fd}]`);
      processes.get(42).descriptors[String(fd)] = `socket:[${fd}]`;
      value.listening = true;
      queueMicrotask(() => value.emit("listening"));
    };
    value.close = (callback) => {
      value.listening = false;
      delete processes.get(42).descriptors[String(fd)];
      pipes.delete(fd);
      callback();
    };
    return value;
  };
  const controlsOptions = withControls
    ? {
        httpServer: server,
        unixServer: server,
        httpRequest(url, settings, callback) {
          const client = new EventEmitter();
          client.setTimeout = () => {};
          client.destroy = (error) => client.emit("error", error);
          client.end = () =>
            queueMicrotask(() =>
              sockets.get(new URL(url).host).handler(
                { resume() {} },
                {
                  end(bytes) {
                    const response = Readable.from([bytes]);
                    response.statusCode = 200;
                    callback(response);
                  },
                },
              ),
            );
          return client;
        },
        createConnection(selector) {
          const client = new PassThrough();
          client.setTimeout = () => client;
          queueMicrotask(() =>
            sockets.get(selector).handler({
              end(bytes) {
                client.end(bytes);
              },
            }),
          );
          return client;
        },
      }
    : {};
  return {
    ...f,
    declared,
    spec,
    binding,
    processes,
    children,
    targets,
    trace,
    member,
    reviewSha256: hash,
    options: { ...f.options, fs: edges, spawn, ...controlsOptions },
  };
}
