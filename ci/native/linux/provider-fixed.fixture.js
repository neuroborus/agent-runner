import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { posix } from "node:path";
import { createProviderEffects } from "../provider-effects.mjs";
import {
  observationDigest,
  releaseClosureDigest,
  nativePackageReviewDigest,
  nativePolicyContext,
  nativePolicyTemplateDigest,
  nativePolicyLaunchData,
  CLAUDE_WRAPPER_REFERENCE,
} from "../index.js";
import {
  createProtectedRelay,
  takeRelayCredentials,
  providerInvocation,
  normalizeProviderSpec,
  CLAUDE_TOOLS,
} from "../providers/index.js";
import { linuxProviderCIContract } from "./index.js";
import {
  linuxProviderProcessFixture,
  providerFixtureDigest as digest,
} from "./provider-effects.fixture.js";

function image() {
  const bytes = Buffer.alloc(512);
  bytes.set([127, 69, 76, 70, 2, 1, 1]);
  bytes.writeUInt16LE(2, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(1, 56);
  bytes.writeUInt32LE(1, 64);
  bytes.writeBigUInt64LE(512n, 96);
  return bytes;
}

/** Full fixed-entry composition over byte/OS/pipe/HTTP edges. All admission,
 * mediation, policy, observation and settlement owners remain repository code. */
export async function linuxProviderFixedFixture(provider, profile, caseId) {
  const f = await linuxProviderProcessFixture(provider, profile, true, caseId),
    { input, raw, declared } = f,
    { manifest, job } = input,
    fs = f.options.fs,
    bytes = image(),
    provenance = Buffer.from("independently approved fixture publication"),
    changes = [
      {
        path: "/workspace/edit-0",
        kind: { type: "update", movePath: null },
        diff: "+changed value",
      },
    ],
    registry =
      provider === "codex"
        ? ["exec_command", "write_stdin", "apply_patch"].map((name) => ({
            type: "function",
            name,
          }))
        : CLAUDE_TOOLS.map((name) => ({
            name,
            input_schema: { type: "object" },
          }));
  const asset = (file, content, mode = 0o444) => {
    if (raw.nodes.has(file)) raw.nodes.get(file).content = Buffer.from(content);
    else raw.add(file, content, mode);
    const pin = { path: file, bytes: content.length, sha256: digest(content) };
    manifest.inputs = manifest.inputs.filter((item) => item.path !== file);
    manifest.inputs.push(pin);
    return pin;
  };
  for (const [file, content] of f.files)
    if (!raw.nodes.has(file)) raw.add(file, content);
  const literal = (file, value) =>
    asset(file, Buffer.from(JSON.stringify(value)));
  const components = [],
    bindings = [],
    providers = {},
    packages = {};
  for (const name of ["codex", "claude"]) {
    const definition =
        name === provider
          ? declared
          : manifest.providerPreparation.cases.find(
              (item) => item.specification.provider === name,
            ),
      mapping = definition.launch.mappings[0],
      directory = definition.bindings.release.providers[name].directory;
    const pin = asset(mapping.source, bytes, 0o555);
    mapping.sha256 = pin.sha256;
    mapping.bytes = pin.bytes;
    definition.specification.review.files[0].sha256 = pin.sha256;
    definition.specification.review.files[0].bytes = pin.bytes;
    literal(
      definition.bindings.release.providers[name].reviewFile,
      definition.specification.review,
    );
    raw.nodes.get(directory).mode = 0o500n;
    raw.nodes.get(posix.dirname(mapping.source)).mode = 0o500n;
    packages[name] = definition.bindings.release.providers[name];
    providers[name] = {
      reviewSha256: nativePackageReviewDigest(definition.specification.review),
      closureSha256: nativePackageReviewDigest(definition.specification.review),
      members: [name + "-image"],
    };
    components.push({
      id: name + "-image",
      role: "executable",
      sha256: pin.sha256,
      format: "elf-x64",
      loader: [],
      bindings: {
        publication: digest(provenance),
        source: digest(provenance),
        build: digest(provenance),
        license: digest(provenance),
        abi: observationDigest({ interpreter: null, needed: [], search: [] }),
      },
    });
    bindings.push({
      id: name + "-image",
      path: pin.path,
      bindings: Object.fromEntries(
        ["publication", "source", "build", "license"].map((key) => [
          key,
          "/fixture/sealed/publication",
        ]),
      ),
    });
  }
  asset("/fixture/sealed/publication", provenance);
  const helper = asset("/fixture/sealed/release-helper", bytes, 0o555);
  components.push({
    ...components[0],
    id: "release-helper",
    role: "helper",
    sha256: helper.sha256,
  });
  bindings.push({ ...bindings[0], id: "release-helper", path: helper.path });
  declared.bindings.release = {
    schemaVersion: 1,
    candidateSha: job.candidateSha,
    components: bindings,
    providers: packages,
  };
  Object.assign(f.spec, normalizeProviderSpec(declared.specification));
  f.binding.template.policy.launch = nativePolicyLaunchData(
    {
      candidateSha: f.spec.candidateSha,
      nonce: f.spec.nonce,
      fixture: declared.launch,
      executable: f.spec.entry,
      packageReviewSha256: f.spec.closureSha256,
      policy: {},
      bindings: {},
      execution: providerInvocation(f.spec).execution,
    },
    providerInvocation(f.spec).arguments,
  );
  const template = {
    template: f.binding.template,
    approval: {
      ...f.binding.approval,
      manifestSha256: nativePolicyTemplateDigest(f.binding.template),
    },
  };
  const index = f.templates.findIndex(
    (item) => item.template.policy.launch.profile === profile,
  );
  f.templates[index] = template;
  manifest.execution.policyTemplates = f.templates;
  input.templateReviews = f.templates.map((item) => item.approval);
  for (const recipe of manifest.execution.cases)
    recipe.templateSha256 = (
      recipe.profile === profile
        ? template
        : f.templates.find(
            (item) => item.template.policy.launch.profile === recipe.profile,
          )
    ).approval.manifestSha256;
  const compiler = input.buildManifest.tools[0];
  asset(compiler.path, Buffer.from("sealed fixture bytes"), 0o555);
  manifest.tools = [compiler];
  asset("/etc/os-release", Buffer.from('ID=ubuntu\nVERSION_ID="24.04"\n'));
  manifest.release = {
    schemaVersion: 2,
    candidateSha: job.candidateSha,
    platform: "linux",
    image: "ubuntu-24.04",
    osBuild: "24.04",
    sdkBuild: "13.3.0",
    policyTemplates: f.templates
      .map((item) => item.approval.manifestSha256)
      .sort(),
    privileges: [
      "uid-0",
      "gid-0",
      "capabilities-0000000000000000",
      "no-new-privileges-1",
    ].sort(),
    components,
    providers,
  };
  job.reviews.release = {
    candidateSha: job.candidateSha,
    platform: "linux",
    authority: "operator-protected",
    manifestSha256: releaseClosureDigest(manifest.release),
  };
  job.closure.manifestSha256 = job.reviews.release.manifestSha256;
  job.closure.policyTemplates = manifest.release.policyTemplates;
  job.selectedSystem.closure = structuredClone(job.closure);
  for (const definition of manifest.providerPreparation.cases)
    definition.custody.context = nativePolicyContext(job, definition.id);
  manifest.providerPreparation.bootstrap.context = nativePolicyContext(
    job,
    "provider-build",
  );
  f.binding = { ...template, context: declared.custody.context };
  job.reviews.provider.manifestSha256 = observationDigest(manifest.execution);
  const recipe = manifest.execution.cases.find(
      (item) => item.id === declared.id,
    ),
    cases = JSON.parse(raw.nodes.get(declared.bindings.casesFile).content);
  cases.registrySha256 = observationDigest(registry);
  for (const item of cases.cases) {
    const target = `/workspace/${item.id}-0`,
      command = "cat " + target;
    if (provider === "codex" && item.command !== null) {
      item.command = command;
      item.commandSha256 = digest(Buffer.from(command));
    }
    if (provider === "codex" && item.id === "edit") {
      item.changesSha256 = observationDigest(changes);
      item.patch = item.patch.replace(
        "Update File: value",
        "Update File: edit-0",
      );
    }
    if (provider === "claude")
      for (const tool of item.tools) {
        if (tool.name === "Bash") tool.input.command = command;
        if (["Read", "Edit", "Write"].includes(tool.name))
          tool.input.file_path = target;
        if (tool.name === "Grep") tool.input.path = target;
        if (tool.name === "Glob") tool.input.pattern = item.id + "-0";
        if (tool.outputSha256 !== null)
          tool.outputSha256 = observationDigest("owned nonce");
      }
  }
  literal(declared.bindings.casesFile, cases);
  const observation = JSON.parse(
    raw.nodes.get(declared.bindings.observationFile).content,
  );
  for (const route of cases.routes) {
    for (const phase of ["tool", "control-permit", "control-deny"]) {
      const index = ["tool", "control-permit", "control-deny"].indexOf(phase),
        file =
          declared.launch.directory + "/workspace/" + route.id + "-" + index;
      declared.bindings.files.push({
        path: file,
        input: "/fixture/sealed/nonce",
        writable: true,
      });
      for (const target of [...f.targets, ...observation.targets])
        if (target.routeId === route.id && target.phase === phase)
          target.file = file;
    }
    for (const control of observation.outsideControls)
      if (route.id === "outside")
        control.file = observation.targets.find(
          (target) => target.selector === control.selector,
        ).file;
  }
  observation.pins.manifestSha256 = recipe.reviewSha256;
  literal(declared.bindings.observationFile, observation);
  literal(declared.bindings.configurationFile, {
    invocation: providerInvocation(f.spec),
    environment: Object.entries(
      providerInvocation(f.spec).execution.environment,
    )
      .map(([key, value]) => `${key}=${value}`)
      .sort(),
    enabledTools:
      provider === "codex"
        ? ["exec_command", "write_stdin", "apply_patch"]
        : [...CLAUDE_TOOLS],
  });
  declared.bindings.relayPolicy.budgetMicros = 1000000;
  declared.bindings.relayPolicy.requests = 32;
  // Read the same raw procfs identity through the public stock process edge.
  f.member(process.pid, 1, 1, [process.pid]);
  const read = fs.readFile.bind(fs),
    stat = fs.stat.bind(fs),
    link = fs.readlink.bind(fs),
    readdir = fs.readdir.bind(fs),
    lstat = fs.lstat.bind(fs);
  fs.lstat = async (file, settings) => {
    const value = await lstat(file);
    return settings?.bigint
      ? value
      : Object.fromEntries(
          Object.entries(value).map(([key, entry]) => [
            key,
            typeof entry === "bigint" ? Number(entry) : entry,
          ]),
        );
  };
  fs.readFile = async (file, encoding) => {
    let data;
    if (file === "/proc/self/status")
      data = await read(`/proc/${process.pid}/status`);
    else if (/^\/proc\/(?:72|76|77)\/environ$/u.test(file))
      data = Buffer.from(
        Object.entries(providerInvocation(f.spec).execution.environment)
          .map(([key, value]) => `${key}=${value}`)
          .join("\0") + "\0",
      );
    else if (/^\/proc\/(?:72|76|77)\/maps$/u.test(file)) {
      const node = raw.nodes.get(declared.launch.mappings[0].source);
      data = Buffer.from(
        `1000-2000 r-xp 00000000 00:01 ${node.ino} ${declared.launch.entrypoint}\n`,
      );
    } else data = await read(file);
    return encoding === "utf8" ? data.toString() : data;
  };
  fs.readlink = async (file) =>
    /^\/proc\/(?:72|76|77)\/exe$/u.test(file)
      ? declared.launch.entrypoint
      : link(file);
  fs.stat = async (file, ...args) =>
    /^\/proc\/(?:72|76|77)\/exe$/u.test(file)
      ? fs.lstat(declared.launch.mappings[0].source, ...args)
      : /^\/proc\/(?:72|76|77)\/root\/runtime\//u.test(file)
        ? fs.lstat(declared.launch.mappings[0].source, ...args)
        : stat(file, ...args);
  fs.readdir = async (file, settings) => {
    const names = await readdir(file);
    if (!settings?.withFileTypes) return names;
    return names.map((name) => ({
      name,
      isSymbolicLink: () => false,
      isFile: () => raw.nodes.get(posix.join(file, name)).content !== null,
      isDirectory: () => raw.nodes.get(posix.join(file, name)).content === null,
    }));
  };
  // Native compiler/stock verifier transport. Repository preparation owns the
  // protected intents, receipts, fresh verification and closure of readers.
  const bootId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  const verify = async (_file, args) => {
    assert.equal(args[1], "--verify");
    assert.equal(digest(raw.nodes.get(args[2]).content), args[3]);
    return {
      stdout: JSON.stringify({
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
      }),
    };
  };
  const start = (_file, args) => {
    const worker = new EventEmitter();
    worker.pid = 700;
    const invocation = JSON.parse(raw.nodes.get(args[1]).content),
      command = invocation.command,
      identity = { bootId, startTicks: "110" },
      receipt = {
        schemaVersion: 1,
        candidateSha: job.candidateSha,
        caseId: "argv",
        nonce: bootId,
        policyDigest: observationDigest(command),
        executableDigest: compiler.sha256,
        isolatedNamespace: true,
        hostSession: false,
        parentNamespaceId: "pid:[1]",
        init: { pid: 701, identity, namespaceId: "pid:[2]", nspid: [701, 1] },
        launcher: { pid: 702, identity: { bootId, startTicks: "100" } },
        controller: { pid: 700, identity: { bootId, startTicks: "90" } },
        admission: {
          processIdentity: identity,
          namespaceId: "pid:[2]",
          launchCutoff: identity,
          ancestryBaseline: [{ bootId, pid: 1, startTicks: "1" }],
          controlGroup: compiler.sha256,
        },
      },
      file = invocation.directory + "/command-0.json",
      output = Buffer.from(JSON.stringify(receipt));
    raw.add(file, output, 0o400);
    raw.add(
      input.providerHelpers + "/provider-gate",
      Buffer.from("approved gate binary"),
      0o555,
    );
    queueMicrotask(() => {
      worker.emit("message", {
        status: "PASS",
        receipts: [{ file, sha256: digest(output) }],
        observation: { exitCode: 0, signal: null, timedOut: false },
      });
      worker.emit("close", 0);
    });
    return worker;
  };
  const options = {
    ...f.options,
    protect() {},
    processTransport: async (pid) => ({
      pid,
      identity: { bootId, startTicks: "90" },
    }),
    commandTransport: {
      fs: { mkdir: fs.mkdir, writeFile: fs.writeFile },
      start,
      receiptOptions: { fs, ownerUid: () => 0 },
      verifierOptions: { executeFile: verify },
    },
    verifierTransport: verify,
  };
  const request = {
    candidateSha: job.candidateSha,
    platform: "linux",
    reviewSha256: observationDigest(manifest),
    helpers: manifest.helpers,
    tools: input.buildManifest.tools,
    output: input.providerHelpers,
    deadlineMs: 120000,
    commands: linuxProviderCIContract({
      tools: input.buildManifest.tools,
      output: input.providerHelpers,
      sourceDirectory: manifest.providerPreparation.sourceDirectory,
    }).commands,
  };
  raw.nodes.delete(input.providerHelpers + "/provider-gate");
  const builder = createProviderEffects(input, options),
    receipt = await builder.prepareBuild(request, {}),
    filesSettlement = await builder.settleBuild();
  input.preparation = {
    status: "PASS",
    request,
    requestSha256: observationDigest(request),
    receiptSha256: observationDigest(receipt),
    filesSettlement,
  };
  const controller = new AbortController();
  let relay,
    transportFailure = null,
    interrupted = false,
    turns = 0;
  const credentials = takeRelayCredentials({
    [provider === "codex"
      ? "NATIVE_CODEX_MODEL_CREDENTIAL"
      : "NATIVE_CLAUDE_MODEL_CREDENTIAL"]: "synthetic-private-credential",
  });
  const spawn = options.spawn;
  options.spawn = (file, args, settings) => {
    const child = spawn(file, args, settings);
    if (
      file !== "/usr/bin/strace" &&
      args.at(-1).endsWith("relay-process.js")
    ) {
      let privateRelay;
      child.stdio[4].on("data", (packet) => {
        const admitted = JSON.parse(packet);
        assert.equal(admitted.credential, "synthetic-private-credential");
        privateRelay = relay = createProtectedRelay(
          admitted.policy,
          admitted.credential,
          {
            request(_url, _settings, callback) {
              const outgoing = new EventEmitter();
              outgoing.end = (body) => {
                outgoing.write(body);
                queueMicrotask(() => {
                  const response = Readable.from([
                    Buffer.from(JSON.stringify(outgoing.response)),
                  ]);
                  response.statusCode = 200;
                  response.complete = true;
                  response.headers = { "content-type": "application/json" };
                  callback(response);
                });
              };
              outgoing.write = (body) => {
                const request = JSON.parse(body);
                outgoing.response =
                  provider === "codex"
                    ? { object: "response", status: "completed", output: [] }
                    : {
                        type: "message",
                        id: "message_1",
                        role: "assistant",
                        model: f.spec.model,
                        content: cases.cases
                          .find((item) => item.id === caseId.split(".").at(-1))
                          .tools.map((tool, index) => ({
                            type: "tool_use",
                            id: "tool_" + index,
                            name: tool.name,
                            input: tool.input,
                          })),
                        stop_reason: "tool_use",
                      };
                assert.deepEqual(request.tools, registry);
              };
              outgoing.destroy = () => {};
              return outgoing;
            },
            onReceipt: (value) =>
              child.stdio[5].write(JSON.stringify(value) + "\n"),
          },
        );
      });
      settings.signal.addEventListener("abort", () => privateRelay?.close(), {
        once: true,
      });
    }
    if (file === "/usr/bin/strace") {
      child.stdio[4].once("data", () => {
        if (provider === "claude")
          child.stdout.write(
            JSON.stringify({
              type: "system",
              subtype: "init",
              session_id: bootId,
              model: f.spec.model,
              claude_code_version: CLAUDE_WRAPPER_REFERENCE.version,
              permissionMode: "bypassPermissions",
              tools: CLAUDE_TOOLS,
              mcp_servers: [],
            }) + "\n",
          );
      });
      let work = Promise.resolve();
      child.stdin.on("data", (chunk) => {
        work = work
          .then(async () => {
            const value = JSON.parse(chunk);
            const send = (record) =>
              child.stdout.write(JSON.stringify(record) + "\n");
            if (provider === "codex" && value.method !== "turn/start") {
              if (value.method === "initialize")
                send({ id: value.id, result: { codexHome: f.spec.home } });
              if (value.method === "thread/start")
                send({
                  id: value.id,
                  result: {
                    thread: { id: "thread_1" },
                    model: f.spec.model,
                    modelProvider: "native_poc",
                    approvalPolicy: "never",
                    cwd: cases.cwd,
                  },
                });
              return;
            }
            const item =
                provider === "codex"
                  ? cases.cases[turns++]
                  : cases.cases.find(
                      (item) => item.id === caseId.split(".").at(-1),
                    ),
              route = cases.routes.find((route) => route.id === item.id),
              target = f.targets.find(
                (target) =>
                  target.routeId === item.id && target.phase === "tool",
              ),
              turnId = "turn_" + turns;
            if (interrupted) {
              controller.abort();
              child.stdout.destroy(new Error("Injected provider interruption"));
              return;
            }
            assert.ok(relay, "Payload work preceded private relay admission");
            await relay.forward(
              {
                method: "POST",
                path: provider === "codex" ? "/v1/responses" : "/v1/messages",
                headers: { authorization: "Bearer native-poc-" + f.spec.nonce },
                body: Buffer.from(
                  JSON.stringify({
                    model: f.spec.model,
                    tools: registry,
                    input: "neutral literal turn",
                    client_metadata: { thread_id: "thread_1", turn_id: turnId },
                  }),
                ),
              },
              async () => {},
              settings.signal,
            );
            f.trace(
              child,
              3,
              target.opcode === "connect"
                ? `connect(8, {sa_family=AF_INET, sin_port=htons(42002), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED`
                : `openat(AT_FDCWD, "${target.selector}", O_RDONLY) = ${route.outcome === "permit" ? "9" : "-1 EACCES"}`,
            );
            if (
              route.outcome === "permit" &&
              ["edit", "write"].includes(item.id)
            )
              raw.nodes.get(target.file).content = Buffer.from("changed value");
            if (provider === "codex") {
              send({ id: value.id, result: { turn: { id: turnId } } });
              send({
                method: "thread/settings/updated",
                params: {
                  threadId: "thread_1",
                  threadSettings: {
                    cwd: cases.cwd,
                    model: f.spec.model,
                    modelProvider: "native_poc",
                    approvalPolicy: "never",
                    sandboxPolicy: {
                      type: "externalSandbox",
                      networkAccess: "enabled",
                    },
                  },
                },
              });
              send({
                method: "turn/started",
                params: {
                  threadId: "thread_1",
                  turn: { id: turnId, status: "inProgress" },
                },
              });
              const tool =
                item.id === "edit"
                  ? { id: "item_" + turns, type: "fileChange", changes }
                  : {
                      id: "item_" + turns,
                      type: "commandExecution",
                      command: item.command,
                      cwd: cases.cwd,
                      source: "agent",
                      exitCode: route.outcome === "permit" ? 0 : 1,
                      aggregatedOutput: "owned nonce",
                    };
              send({
                method: "item/started",
                params: {
                  threadId: "thread_1",
                  turnId,
                  item: { ...tool, status: "inProgress" },
                },
              });
              send({
                method: "item/completed",
                params: {
                  threadId: "thread_1",
                  turnId,
                  item: {
                    ...tool,
                    status: route.outcome === "permit" ? "completed" : "failed",
                  },
                },
              });
              send({
                method: "turn/completed",
                params: {
                  threadId: "thread_1",
                  turn: { id: turnId, status: "completed" },
                },
              });
            } else {
              send({
                type: "assistant",
                session_id: bootId,
                message: {
                  id: "message_1",
                  role: "assistant",
                  model: f.spec.model,
                  content: item.tools.map((tool, index) => ({
                    type: "tool_use",
                    id: "tool_" + index,
                    name: tool.name,
                    input: tool.input,
                  })),
                },
              });
              if (item.id.startsWith("background-")) {
                f.member(76, 72, 72, [76, 5, 3]);
                f.member(77, 76, 72, [77, 6, 4]);
                send({
                  type: "system",
                  subtype: "task_started",
                  session_id: bootId,
                  task_id: "task_1",
                  task_type: "local_bash",
                  tool_use_id: "tool_0",
                });
              }
              send({
                type: "user",
                session_id: bootId,
                message: {
                  role: "user",
                  content: item.tools.map((tool, index) => ({
                    type: "tool_result",
                    tool_use_id: "tool_" + index,
                    content: "owned nonce",
                    is_error:
                      tool.name !== "EndConversation" &&
                      index >= item.tools.length - 2 &&
                      route.outcome !== "permit",
                  })),
                },
              });
              send({
                type: "result",
                subtype: "success",
                is_error: false,
                permission_denials: [],
                session_id: bootId,
              });
            }
          })
          .catch((error) => child.stderr.destroy(error));
      });
    }
    return child;
  };
  // Construct after installing raw spawn edges: owners snapshot their inputs.
  const effects = createProviderEffects(input, options);
  return {
    ...f,
    input,
    options,
    recipe,
    cases,
    owner: effects,
    controller,
    async prepare() {
      const prepared = await effects.prepare(recipe, {
        signal: controller.signal,
        policyBinding: f.binding,
      });
      const admit = prepared.effects.admitTransport.bind(prepared.effects);
      prepared.effects.admitTransport = async (role, context, ...args) => {
        const receiver = await admit(role, context, ...args);
        if (role === "relay") {
          const verified = await prepared.effects.verifyRelayCustody(
            receiver,
            context,
            args.at(-1),
          );
          await credentials.deliver(
            "linux",
            context,
            receiver,
            verified,
            args.at(-1),
          );
          if (transportFailure)
            raw.nodes.get(transportFailure).content = Buffer.from(
              "substituted bridge source",
            );
        }
        return receiver;
      };
      return prepared;
    },
    blockTransport() {
      transportFailure = manifest.inputs.find((pin) =>
        pin.path.endsWith("bridge-process.js"),
      ).path;
    },
    interrupt() {
      interrupted = true;
    },
    async close() {
      credentials.close();
      relay?.close();
      await effects.settleBuild();
      await raw.teardown();
    },
  };
}
