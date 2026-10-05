import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import { Readable, PassThrough, Duplex } from "node:stream";
import {
  nativePackageInput,
  CODEX_RELEASE_REFERENCE,
  observationDigest,
  normalizeNativePackageReview,
  nativePackageReviewDigest,
} from "../index.js";
import {
  providerInvocation,
  normalizeProviderSpec,
  normalizeProviderExecution,
  createProtectedRelay,
  runProviderTransport,
  createPipeExchange,
  serveRelayPipe,
  runProtectedRelay,
  runCredentialFreeBridge,
} from "./index.js";
import {
  linuxProviderArguments,
  linuxProviderBridgeArguments,
  linuxProviderOwner,
  assertLinuxProviderTransport,
} from "../linux/index.js";
import {
  darwinProviderLaunch,
  buildDarwinPolicy,
  normalizeDarwinLaunch,
} from "../darwin/index.js";
import {
  windowsProviderLaunch,
  buildWindowsPolicy,
  windowsPolicyHelperArguments,
  normalizeWindowsLaunch,
  WINDOWS_ARGUMENT_PARSER,
} from "../win32/index.js";

const HASH = "a".repeat(64),
  CANDIDATE = "b".repeat(40),
  NONCE = "c".repeat(32);
const gitReview = normalizeNativePackageReview(
  {
    schemaVersion: 1,
    candidateSha: CANDIDATE,
    packageId: "git-for-windows",
    archiveBytes: nativePackageInput("git-for-windows").bytes,
    files: [
      { path: "usr/bin/bash.exe", bytes: 100, sha256: HASH, executable: true },
    ],
    bindings: Object.fromEntries(
      [
        "publication",
        "source",
        "build",
        "dependencies",
        "license",
        "abi",
        "transport",
        "extraction",
      ].map((key) => [
        key,
        { url: "https://example.org/git-review", revision: null, sha256: HASH },
      ]),
    ),
  },
  CANDIDATE,
);
function specification(provider = "codex", platform = "linux") {
  const input = nativePackageInput(provider + "-" + platform);
  const reference = {
    url: "https://example.org/native-review",
    revision: null,
    sha256: HASH,
  };
  const windows = platform === "win32";
  return {
    candidateSha: CANDIDATE,
    nonce: NONCE,
    provider,
    platform,
    profile: "read-only",
    review: {
      schemaVersion: 1,
      candidateSha: CANDIDATE,
      packageId: input.id,
      archiveBytes: input.bytes ?? 100,
      bindings: Object.fromEntries(
        [
          "publication",
          "source",
          "build",
          "dependencies",
          "license",
          "abi",
          "transport",
          "extraction",
        ].map((key) => [
          key,
          key === "source"
            ? provider === "claude"
              ? null
              : {
                  url: CODEX_RELEASE_REFERENCE.sourceUrl,
                  revision: CODEX_RELEASE_REFERENCE.revision,
                  sha256: HASH,
                }
            : provider === "claude" && windows && key === "dependencies"
              ? { ...reference, sha256: nativePackageReviewDigest(gitReview) }
              : reference,
        ]),
      ),
      files: [
        {
          path: input.entrypoint,
          bytes: 300000000,
          sha256: HASH,
          executable: true,
        },
      ],
    },
    home: windows
      ? "C:\\Fixture\\Storage\\provider-home"
      : platform === "linux"
        ? "/home/provider"
        : "/fixture/storage/home",
    cache: windows
      ? "C:\\Fixture\\Storage\\provider-cache"
      : platform === "linux"
        ? "/cache"
        : "/fixture/storage/cache",
    path: windows ? "C:\\Fixture\\Storage\\runtime" : "/runtime/bin",
    endpoint: "http://127.0.0.1:41001",
    model: "reviewed-model",
  };
}
function launchRequest(platform, spec) {
  const bindings = {
    system: HASH,
    source: HASH,
    policy: HASH,
    closure: normalizeProviderSpec(spec).closureSha256,
  };
  return platform === "darwin"
    ? {
        schemaVersion: 1,
        candidateSha: CANDIDATE,
        nonce: NONCE,
        uid: 90001,
        gid: 90002,
        custody: "/fixture/custody",
        storage: "/fixture/storage",
        workspace: "/fixture/storage/work",
        launcher: { path: "/fixture/custody/launcher", sha256: HASH },
        executable: {
          path: "/fixture/storage/payload",
          sha256: HASH,
          cdhash: "d".repeat(40),
        },
        policy: { path: "/fixture/custody/policy", sha256: HASH },
        bindings,
      }
    : {
        schemaVersion: 1,
        candidateSha: CANDIDATE,
        nonce: NONCE,
        restrictingSid: "S-1-5-21-4-5-6-1002",
        custody: "C:\\Fixture\\Custody",
        storage: "C:\\Fixture\\Storage",
        workspace: "C:\\Fixture\\Storage\\Work",
        launcher: {
          path: "C:\\Fixture\\Custody\\launcher.exe",
          sha256: HASH,
          signatureSha256: HASH,
        },
        executable: {
          path: "C:\\Fixture\\Storage\\payload.exe",
          sha256: HASH,
          signatureSha256: HASH,
          parser: WINDOWS_ARGUMENT_PARSER,
        },
        policy: { path: "C:\\Fixture\\Custody\\policy.json", sha256: HASH },
        bindings,
        ...(spec.provider === "claude"
          ? { bash: { root: "C:\\Fixture\\Storage\\git", review: gitReview } }
          : {}),
      };
}

test("provider package and public environment remain bound across all native launch routes", () => {
  for (const provider of ["codex", "claude"])
    for (const platform of ["linux", "darwin", "win32"]) {
      const spec = specification(provider, platform),
        normalized = normalizeProviderSpec(spec);
      assert.deepEqual(normalizeProviderSpec(normalized), normalized);
      const invocation = providerInvocation(normalized);
      assert.equal(invocation.execution.imageBytes, spec.review.files[0].bytes);
      assert.equal(invocation.execution.environment.HOME, spec.home);
      assert.equal(
        Object.values(invocation.execution.environment).includes(
          "native-poc-" + NONCE,
        ),
        true,
      );
      assert.throws(() =>
        normalizeProviderExecution(
          {
            ...invocation.execution,
            environment: {
              ...invocation.execution.environment,
              OPENAI_API_KEY: "synthetic-key",
            },
          },
          NONCE,
        ),
      );
      const altered = structuredClone(spec);
      altered.review.bindings.abi = null;
      assert.throws(() => providerInvocation(altered));
      assert.throws(() => providerInvocation({ ...spec, profile: "commit" }));
      if (platform !== "linux") {
        const base = launchRequest(platform, spec);
        const owner =
          platform === "darwin" ? darwinProviderLaunch : windowsProviderLaunch;
        const normalize =
          platform === "darwin"
            ? normalizeDarwinLaunch
            : normalizeWindowsLaunch;
        const { bash, ...nativeBase } = base;
        assert.equal(normalize(nativeBase).schemaVersion, 1);
        const launch = owner(spec, base);
        assert.equal(launch.request.schemaVersion, 2);
        assert.deepEqual(normalize(launch.request), launch.request);
        assert.equal(
          launch.arguments.includes(
            provider === "codex" ? "app-server" : "--print",
          ),
          true,
        );
        assert.throws(() =>
          normalize({
            ...launch.request,
            bindings: { ...base.bindings, closure: HASH },
          }),
        );
      }
    }
});

test("native provider policy permits private cache writes and the exclusive distinct-principal broker only", () => {
  const macSpec = specification("codex", "darwin"),
    mac = darwinProviderLaunch(
      macSpec,
      launchRequest("darwin", macSpec),
    ).request;
  const policy = {
    request: mac,
    profile: "read-only",
    disposable: true,
    metadata: "/fixture/storage/metadata",
    pointer: mac.workspace + "/.git",
    checkout: "/protected/checkout",
    configuration: "/protected/config",
    credentials: "/protected/credentials",
    runtime: [
      {
        path: mac.executable.path,
        sha256: HASH,
        executable: true,
        mapped: true,
      },
    ],
    endpoints: [{ family: "inet", protocol: "tcp", serverPort: 41001 }],
    reviewSha256: HASH,
  };
  assert.throws(() =>
    buildDarwinPolicy({ ...policy, profile: "workspace-write" }),
  );
  const plan = buildDarwinPolicy(policy);
  assert.match(
    plan.seatbelt,
    /file-read\* file-write\* \(subpath "\/fixture\/storage\/home"\)/u,
  );
  assert.doesNotMatch(
    plan.seatbelt,
    /allow network-bind|allow network-inbound|allow file-write\* \(require-all/u,
  );
  assert.match(plan.pf, /pass in quick.*port 41001 user = 0/u);
  assert.match(plan.pf, /block return out quick.*user = 90001/u);
  assert.throws(() =>
    buildDarwinPolicy({
      ...policy,
      endpoints: [{ family: "inet6", protocol: "tcp", serverPort: 41001 }],
    }),
  );
  const wrongHome = structuredClone(policy);
  wrongHome.request.execution.environment.HOME = policy.credentials;
  assert.throws(() => buildDarwinPolicy(wrongHome));
  const winSpec = specification("claude", "win32"),
    win = windowsProviderLaunch(
      winSpec,
      launchRequest("win32", winSpec),
    ).request;
  const input = {
    request: win,
    profile: "read-only",
    disposable: true,
    accountSid: "S-1-5-21-1-2-3-1001",
    runtime: [{ path: win.executable.path, sha256: HASH, reviewSha256: HASH }],
    endpoints: [{ family: "v4", protocol: "tcp", serverPort: 41001 }],
    reviewSha256: HASH,
  };
  assert.throws(() =>
    buildWindowsPolicy({ ...input, profile: "workspace-write" }),
  );
  const windows = buildWindowsPolicy(input);
  assert.equal(
    windows.manifest.objects.find((v) => v.name === "workspace").grant,
    "read-tree",
  );
  assert.equal(
    windows.manifest.objects.find((v) => v.name === "provider-home").grant,
    "private-tree",
  );
  assert.equal(windows.manifest.filters.length, 12);
  assert.equal(
    windows.manifest.filters.filter(
      (v) => v.principal === "S-1-5-18" && v.action === "PERMIT",
    ).length,
    2,
  );
  assert.equal(
    windows.manifest.filters.filter(
      (v) => v.layer.endsWith("V6") && v.action === "PERMIT",
    ).length,
    0,
  );
  const handles = windows.manifest.objects
    .filter((v) => v.name !== "registry")
    .map((v, i) => ({ path: v.path, handle: String(i + 1) }));
  assert.deepEqual(
    windowsPolicyHelperArguments(input, "install", handles).slice(3, 6),
    ["read-only", "install-provider", "41001"],
  );
});

function linuxFixture() {
  return {
    directory: "/fixture",
    launcher: "/reviewed/launcher",
    gate: "/fixture/gate",
    entrypoint: "/runtime/bin/codex",
    reviewSha256: HASH,
    storage: Object.fromEntries(
      [
        "workspace",
        "metadata",
        "pointer",
        "git",
        "operation",
        "hooks",
        "home",
        "cache",
      ].map((v) => [v, "/fixture/" + v]),
    ),
    mappings: [
      {
        source: "/fixture/package/codex",
        target: "/runtime/bin/codex",
        sha256: HASH,
        bytes: 300000000,
      },
    ],
  };
}

test("Linux launches the package through a parked native gate with immutable ABI and separate home grants", () => {
  const spec = { ...specification(), path: "/runtime/bin:/proof/bin" },
    fixture = linuxFixture();
  const args = linuxProviderArguments(spec, fixture);
  assert.equal(args.includes("--unshare-net"), true);
  assert.equal(args.includes("--remount-ro"), true);
  assert.equal(args.includes("--preserve-fds"), true);
  assert.equal(args.includes("/proof/bin/provider-gate"), true);
  assert.equal(args.includes("app-server"), true);
  assert.equal(
    args.join(" ").includes("--ro-bind /fixture/metadata /metadata"),
    true,
  );
  assert.equal(
    args.join(" ").includes("--bind /fixture/home /home/provider"),
    true,
  );
  assert.deepEqual(
    linuxProviderBridgeArguments(
      "/reviewed/node",
      "/reviewed/bridge.js",
      "/reviewed/gate",
      NONCE,
    ),
    [
      "--net=/proc/self/fd/5",
      "--",
      "/reviewed/gate",
      "--bridge-loopback",
      NONCE,
      "/reviewed/node",
      "/reviewed/bridge.js",
    ],
  );
  const wrong = structuredClone(fixture);
  wrong.mappings[0].source = "/fixture/home/codex";
  assert.throws(() => linuxProviderArguments(spec, wrong));
  const alias = structuredClone(fixture);
  alias.storage.metadata = fixture.storage.home + "/metadata";
  assert.throws(() => linuxProviderArguments(spec, alias));
});

test("Linux provider gate pipes account for the owned supervisor's reserved IPC descriptor", async () => {
  const spec = specification(),
    fixture = linuxFixture(),
    invocation = providerInvocation(spec);
  const requestSha256 = observationDigest({
    spec: normalizeProviderSpec(spec),
    fixture,
    args: linuxProviderArguments(spec, fixture),
  });
  const control = new PassThrough(),
    report = new PassThrough(),
    input = new PassThrough();
  const child = {
    stdin: input,
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    stdio: [input, null, null, null, control, report],
    ownedCompletion: new Promise(() => {}),
  };
  const domain = {
    independent: true,
    held: true,
    candidateSha: CANDIDATE,
    nonce: NONCE,
    networkPrivate: true,
    ipcPrivate: true,
    gatePid: 1,
    rootReadOnly: true,
    immutableMappingsVerified: true,
    profile: spec.profile,
  };
  let command = "",
    prepared = false;
  control.on("data", (bytes) => {
    command += bytes.toString();
  });
  const effects = {
    persist: async () => {},
    verifyInputs: async () => ({
      independent: true,
      status: "MATCHED",
      requestSha256,
      packageSha256: invocation.execution.closureSha256,
      immutableMappings: true,
      privateHomeCache: true,
      noWritableAliases: true,
    }),
    readGate: async (pipe) => {
      assert.equal(pipe, report);
      return { nonce: NONCE, pid: 1 };
    },
    inspectGate: async () => ({ ...domain }),
  };
  const owner = linuxProviderOwner(fixture, requestSha256, effects, {
    platform: "linux",
    env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "ubuntu24" },
    spawn(file, args, options) {
      assert.equal(options.ownershipMode, "native-sandbox-provider");
      return child;
    },
  });
  try {
    const result = await owner.launch(
      spec,
      invocation,
      async () => {
        prepared = true;
      },
      new AbortController().signal,
    );
    assert.equal(result.record.status, "ADMITTED");
    assert.equal(prepared, true);
    assert.equal(command, "R");
    result.transport.close();
    assert.equal(control.destroyed, true);
    assert.equal(input.destroyed, true);
  } finally {
    for (const pipe of [control, report, input, child.stdout, child.stderr])
      pipe.destroy();
  }
});

const relayPolicy = (provider = "codex") => ({
  provider,
  nonce: NONCE,
  model: "reviewed-model",
  requests: 2,
  outputTokens: 32,
  budgetMicros: 100000,
  inputMicros: 1,
  outputMicros: 1,
  beta: ["reviewed-feature"],
});
const requestValue = (provider = "codex") => ({
  method: "POST",
  path: provider === "codex" ? "/v1/responses" : "/v1/messages",
  headers: {
    authorization: "Bearer native-poc-" + NONCE,
    cookie: "synthetic-cookie",
    "x-api-key": "foreign-key",
    "anthropic-beta": "reviewed-feature",
  },
  body: Buffer.from(JSON.stringify({ model: "reviewed-model", stream: true })),
});
function upstream({
  status = 200,
  headers = {},
  body = '{"type":"response.completed"}',
} = {}) {
  const calls = [];
  return {
    calls,
    request(url, options, receive) {
      const request = new EventEmitter();
      request.destroy = () => {
        request.destroyed = true;
      };
      request.end = (bytes) => {
        calls.push({ url: url.href, options, body: JSON.parse(bytes) });
        queueMicrotask(() => {
          const response = Readable.from([Buffer.from(body)]);
          response.statusCode = status;
          response.headers = { "content-type": "application/json", ...headers };
          response.complete = true;
          receive(response);
        });
      };
      return request;
    },
  };
}

test("trusted relay fixes destination/authentication, reserves cost, and strips client and upstream headers", async () => {
  for (const provider of ["codex", "claude"]) {
    const fake = upstream({
      headers: {
        "set-cookie": "synthetic-upstream-cookie",
        authorization: "synthetic-key",
      },
    });
    const relay = createProtectedRelay(
      relayPolicy(provider),
      "synthetic-upstream-key",
      { request: fake.request },
    );
    const sent = [];
    await relay.forward(requestValue(provider), async (v) => sent.push(v));
    assert.equal(
      fake.calls[0].url,
      provider === "codex"
        ? "https://api.openai.com/v1/responses"
        : "https://api.anthropic.com/v1/messages",
    );
    assert.equal(fake.calls[0].options.headers.cookie, undefined);
    assert.equal(
      fake.calls[0].options.headers.authorization,
      provider === "codex" ? "Bearer synthetic-upstream-key" : undefined,
    );
    assert.equal(
      fake.calls[0].options.headers["x-api-key"],
      provider === "claude" ? "synthetic-upstream-key" : undefined,
    );
    assert.equal(
      fake.calls[0].body[
        provider === "codex" ? "max_output_tokens" : "max_tokens"
      ],
      32,
    );
    if (provider === "codex") assert.equal(fake.calls[0].body.store, false);
    assert.deepEqual(
      sent.filter((v) => v.type === "headers"),
      [{ type: "headers", contentType: "application/json" }],
    );
    await relay.forward(requestValue(provider), async () => {});
    await assert.rejects(
      relay.forward(requestValue(provider), async () => {}),
      /Provider transport closed/u,
    );
    assert.equal(fake.calls.length, 2);
  }
});

test("invalid routes/models/budgets close before effects; redirects and HTTP-200 upstream errors never forward", async () => {
  for (const change of [
    (value) => {
      value.path = "https://example.org/v1/responses";
    },
    (value) => {
      value.method = "CONNECT";
    },
    (value) => {
      value.body = Buffer.from(
        JSON.stringify({
          model: "reviewed-model",
          input: [
            { type: "input_image", image_url: "https://example.org/image" },
          ],
        }),
      );
    },
    ...["previous_response_id", "conversation", "prompt"].map(
      (key) => (value) => {
        value.body = Buffer.from(
          JSON.stringify({
            model: "reviewed-model",
            [key]: "unbounded-context",
          }),
        );
      },
    ),
    (value) => {
      value.body = Buffer.from(
        JSON.stringify({
          model: "reviewed-model",
          input: [{ type: "item_reference", id: "unbounded-context" }],
        }),
      );
    },
    (value) => {
      value.body = Buffer.from(
        JSON.stringify({ model: "reviewed-model", store: true }),
      );
    },
    (value) => {
      value.body = Buffer.from('{"model":"foreign-model"}');
    },
    (value) => {
      value.headers.authorization = "Bearer foreign-key";
    },
  ]) {
    const fake = upstream(),
      relay = createProtectedRelay(relayPolicy(), "synthetic-key", {
        request: fake.request,
      });
    const value = requestValue();
    change(value);
    await assert.rejects(relay.forward(value, async () => {}));
    await assert.rejects(relay.forward(requestValue(), async () => {}));
    assert.equal(fake.calls.length, 0);
  }
  const budget = upstream();
  await assert.rejects(
    createProtectedRelay(
      { ...relayPolicy(), budgetMicros: 1 },
      "synthetic-key",
      { request: budget.request },
    ).forward(requestValue(), async () => {}),
  );
  assert.equal(budget.calls.length, 0);
  for (const response of [
    {
      status: 302,
      headers: { location: "https://example.org" },
      body: "raw-upstream-error",
    },
    { body: '{"error":{"message":"raw-upstream-error"}}' },
    {
      headers: { "content-type": "text/event-stream" },
      body: 'event: error\ndata: {"type":"error","error":{"message":"raw-upstream-error"}}\n\n',
    },
  ]) {
    const fake = upstream(response),
      sent = [],
      relay = createProtectedRelay(relayPolicy(), "synthetic-key", {
        request: fake.request,
      });
    await assert.rejects(
      relay.forward(requestValue(), async (v) => sent.push(v)),
      /Provider transport closed/u,
    );
    assert.equal(
      sent.some((v) => v.type === "data"),
      false,
    );
    assert.equal(fake.calls.length, 1);
  }
});

function transportFixture() {
  const spec = specification(),
    policy = relayPolicy(),
    configurationSha256 = observationDigest({
      specificationSha256: providerInvocation(spec).specificationSha256,
      policy,
    });
  const binding = {
      independent: true,
      candidateSha: CANDIDATE,
      nonce: NONCE,
      configurationSha256,
    },
    phases = [];
  const verify = {
    ...binding,
    nativeSha256: HASH,
    packageSha256: normalizeProviderSpec(spec).closureSha256,
    profile: spec.profile,
    endpoint: spec.endpoint,
  };
  for (const key of [
    "relayAdmitted",
    "bridgeAdmitted",
    "receiptsVerified",
    "privatePipes",
    "credentialCustodyProtected",
    "providerHasNoCredential",
    "environmentAllowlist",
    "handleAllowlist",
    "endpointExclusive",
    "receivingPrincipalVerified",
    "noInspection",
    "noDebug",
    "noSignalling",
    "noFilesystemAccess",
    "ownedChangesOnly",
    "samePrivateNetworkNamespace",
    "bridgeOutsidePayloadPidNamespace",
    "credentialFreeBridge",
    "fixedInheritedPipe",
  ])
    verify[key] = true;
  const cases = Object.fromEntries(
    [
      "transport",
      "credential-file",
      "credential-environment",
      "credential-process",
      "debug",
      "signal",
      "alternate-network",
      "alternate-ipc",
      "relay-loss",
      "bridge-loss",
    ].map((id) => [
      id,
      {
        attempted: true,
        acknowledged: true,
        independent: true,
        expectedEffect: true,
        sentinelsUnchanged: true,
        nativeSha256: HASH,
      },
    ]),
  );
  let attempts = 0;
  const effects = {
    persist: async (v) => {
      phases.push(v.phase);
    },
    review: async () => ({
      ...binding,
      status: "MATCHED",
      packageSha256: normalizeProviderSpec(spec).closureSha256,
    }),
    admitTransport: async (role) => {
      attempts++;
      assert.equal(phases.at(-1), role + "-admission-possible");
      return {
        ...binding,
        role,
        admitted: true,
        receiptVerified: true,
        nativeSha256: HASH,
      };
    },
    verifyTransport: async () => structuredClone(verify),
    controls: async () => ({ ...binding, cases }),
    closeTransport: async () => {
      phases.push("closed");
    },
    retire: async () => {
      phases.push("retired");
      return {
        ...binding,
        payloadsRetired: true,
        relayRetired: true,
        bridgeRetired: true,
      };
    },
    verifySettlement: async () => ({
      ...binding,
      restored: true,
      ownedChangesOnly: true,
      reservation: "RETAINED",
      nativeSha256: HASH,
    }),
  };
  const owner = {
    assertTransport: assertLinuxProviderTransport,
    async launch(input, invocation, prepare) {
      await prepare({});
      return {
        record: { status: "ADMITTED" },
        transport: {
          close() {
            phases.push("provider-closed");
          },
        },
      };
    },
  };
  return {
    spec,
    policy,
    effects,
    owner,
    phases,
    verify,
    cases,
    observed: {
      ...binding,
      attempted: true,
      transportObserved: true,
      nativeSha256: HASH,
    },
    attempts: () => attempts,
  };
}

test("admission intents and native controls precede provider execution and independent settlement", async () => {
  const fixture = transportFixture();
  let executed = false;
  const result = await runProviderTransport(
    fixture.spec,
    fixture.policy,
    fixture.owner,
    fixture.effects,
    async () => {
      assert.equal(fixture.phases.at(-1), "provider-running");
      executed = true;
      return fixture.observed;
    },
  );
  assert.equal(executed, true);
  assert.equal(result.status, "TRANSPORT_OBSERVED");
  assert.equal(result.phase, "settled");
  assert.equal(result.reservation, "RETAINED");
  assert.equal(fixture.attempts(), 2);
  assert.equal(
    fixture.phases.indexOf("closed") < fixture.phases.indexOf("retired"),
    true,
  );
  for (const failure of [
    "missing-control",
    "ambiguous-principal",
    "unretired",
  ]) {
    const broken = transportFixture();
    let ran = false;
    if (failure === "missing-control")
      broken.cases["credential-file"].attempted = false;
    if (failure === "ambiguous-principal")
      broken.verify.receivingPrincipalVerified = false;
    if (failure === "unretired")
      broken.effects.retire = async () => ({ independent: true });
    const result = await runProviderTransport(
      broken.spec,
      broken.policy,
      broken.owner,
      broken.effects,
      async () => {
        ran = true;
        return broken.observed;
      },
    );
    assert.equal(result.status, "FAIL");
    assert.equal(ran, failure === "unretired");
    assert.equal(result.reservation, "RETAINED");
    if (failure === "unretired") assert.equal(result.phase, "retained");
  }
});

test("missing capability is BLOCKED; an unsettled timed-out admission cannot authorize restoration", async () => {
  const missing = transportFixture();
  delete missing.effects.controls;
  const blocked = await runProviderTransport(
    missing.spec,
    missing.policy,
    missing.owner,
    missing.effects,
    async () => assert.fail(),
  );
  assert.equal(blocked.status, "BLOCKED");
  assert.equal(missing.attempts(), 0);
  const fixture = transportFixture();
  let deadline, entered, finish;
  const admission = new Promise((resolve) => {
    finish = resolve;
  });
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  fixture.effects.admitTransport = () => {
    entered();
    return admission;
  };
  fixture.effects.verifySettlement = async () =>
    assert.fail("Unsettled admission cannot restore custody");
  const result = runProviderTransport(
    fixture.spec,
    fixture.policy,
    fixture.owner,
    fixture.effects,
    async () => assert.fail(),
    {
      schedule(callback, ms) {
        if (ms === 120000) deadline = callback;
        return callback;
      },
      cancel() {},
    },
  );
  await started;
  deadline();
  const record = await result;
  assert.equal(record.status, "FAIL");
  assert.equal(record.phase, "retained");
  finish({});
  await admission;
});

test("a late admission write cannot replace the terminal retained failure receipt", async () => {
  const fixture = transportFixture(),
    writes = [];
  let entered,
    finish,
    stored,
    terminal,
    cleanupStarted,
    deadline,
    cleanupDeadline;
  const admissionStarted = new Promise((resolve) => {
    entered = resolve;
  });
  const holding = new Promise((resolve) => {
    finish = resolve;
  });
  const admissionStored = new Promise((resolve) => {
    stored = resolve;
  });
  const terminalStored = new Promise((resolve) => {
    terminal = resolve;
  });
  const cleanup = new Promise((resolve) => {
    cleanupStarted = resolve;
  });
  fixture.effects.persist = async (snapshot) => {
    if (snapshot.phase === "relay-admission-possible") {
      entered();
      await holding;
    }
    writes.push(snapshot);
    if (snapshot.phase === "relay-admission-possible") stored();
    if (snapshot.phase === "retained" && snapshot.status === "FAIL") terminal();
  };
  const running = runProviderTransport(
    fixture.spec,
    fixture.policy,
    fixture.owner,
    fixture.effects,
    async () => assert.fail(),
    {
      schedule(callback, ms) {
        if (ms === 120000) deadline = callback;
        else {
          cleanupDeadline = callback;
          cleanupStarted();
        }
        return callback;
      },
      cancel() {},
    },
  );
  await admissionStarted;
  deadline();
  await cleanup;
  cleanupDeadline();
  const result = await running;
  assert.equal(result.status, "FAIL");
  assert.equal(result.phase, "retained");
  finish();
  await admissionStored;
  await terminalStored;
  assert.equal(writes.at(-1).status, "FAIL");
  assert.equal(writes.at(-1).phase, "retained");
});

test("relay preserves successful streamed model events across UTF-8 and CRLF chunk boundaries", async () => {
  const bytes = Buffer.from(
    'event: response.output_text.delta\r\ndata: {"type":"response.output_text.delta","delta":"λ"}\r\n\r\nevent: response.completed\ndata: {"type":"response.completed"}\n\n',
  );
  const split = bytes.indexOf(Buffer.from("λ")) + 1;
  const request = (url, options, receive) => {
    const value = new EventEmitter();
    value.destroy = () => {};
    value.end = () =>
      queueMicrotask(() => {
        const response = Readable.from([
          bytes.subarray(0, split),
          bytes.subarray(split, bytes.length - 1),
          bytes.subarray(bytes.length - 1),
        ]);
        response.statusCode = 200;
        response.headers = { "content-type": "text/event-stream" };
        response.complete = true;
        receive(response);
      });
    return value;
  };
  const relay = createProtectedRelay(relayPolicy(), "synthetic-key", {
      request,
    }),
    output = [];
  try {
    await relay.forward(requestValue(), async (v) => {
      if (v.type === "data") output.push(v.bytes);
    });
    assert.equal(
      Buffer.concat(output).toString(),
      bytes.toString().replaceAll("\r\n", "\n"),
    );
  } finally {
    relay.close();
  }
});

test("complete upstream connection closure does not interrupt response delivery", async () => {
  const request = (url, options, receive) => {
    const value = new EventEmitter();
    value.destroy = () => {};
    value.end = () =>
      queueMicrotask(() => {
        const response = Readable.from([
          Buffer.from('{"type":"response.completed"}'),
        ]);
        response.statusCode = 200;
        response.headers = { "content-type": "application/json" };
        response.complete = false;
        response.once("end", () => {
          response.complete = true;
          value.emit("close");
        });
        receive(response);
      });
    return value;
  };
  const relay = createProtectedRelay(relayPolicy(), "synthetic-key", {
      request,
    }),
    output = [];
  try {
    await relay.forward(requestValue(), async (value) => output.push(value));
    assert.equal(output.at(-1).type, "end");
    assert.equal(
      output.some((value) => value.type === "data"),
      true,
    );
  } finally {
    relay.close();
  }
});

test("provider assertion alone cannot establish transport observation and close failure still attempts native retirement", async () => {
  for (const fault of [
    "provider-text",
    "close-failure",
    "caught-control",
    "changed-receipt",
  ]) {
    const fixture = transportFixture();
    if (fault === "close-failure")
      fixture.effects.closeTransport = async () => {
        throw new Error("Synthetic failure");
      };
    if (fault === "caught-control") {
      fixture.verify.noInspection = false;
      fixture.owner.launch = async (spec, invocation, prepare) => {
        try {
          await prepare({});
        } catch {}
        return { record: { status: "ADMITTED" }, transport: {} };
      };
    }
    if (fault === "changed-receipt") {
      fixture.effects.verifyTransport = async () => fixture.verify;
      const controls = fixture.effects.controls;
      fixture.effects.controls = async () => {
        fixture.verify.privatePipes = false;
        return controls();
      };
    }
    const result = await runProviderTransport(
      fixture.spec,
      fixture.policy,
      fixture.owner,
      fixture.effects,
      async () =>
        fault === "provider-text"
          ? { text: "Transport successful" }
          : fixture.observed,
    );
    assert.equal(result.status, "FAIL");
    assert.equal(result.reservation, "RETAINED");
    assert.equal(fixture.phases.includes("retired"), true);
  }
});

test("fixed private pipe exchanges preserve framing and reject partial or noncanonical payloads", async () => {
  const incoming = new PassThrough(),
    outgoing = new PassThrough();
  const client = Duplex.from({ writable: incoming, readable: outgoing }),
    server = Duplex.from({ writable: outgoing, readable: incoming });
  const fake = upstream(),
    relay = createProtectedRelay(relayPolicy(), "synthetic-key", {
      request: fake.request,
    });
  const serving = serveRelayPipe(server, relay);
  serving.catch(() => {});
  try {
    const sent = [];
    await createPipeExchange(client)(requestValue(), async (v) => sent.push(v));
    assert.equal(sent.at(-1).type, "end");
    assert.equal(fake.calls.length, 1);
    client.end();
    await serving;
  } finally {
    relay.close();
    client.destroy();
    server.destroy();
    incoming.destroy();
    outgoing.destroy();
  }
  for (const frame of [
    Buffer.from([0, 0, 0]),
    (() => {
      const body = Buffer.from(
          JSON.stringify({ type: "data", bytes: "not-base64" }),
        ),
        header = Buffer.alloc(4);
      header.writeUInt32BE(body.length);
      const first = Buffer.from(
          JSON.stringify({ type: "headers", contentType: "application/json" }),
        ),
        prefix = Buffer.alloc(4);
      prefix.writeUInt32BE(first.length);
      return Buffer.concat([prefix, first, header, body]);
    })(),
  ]) {
    const read = Readable.from([frame]),
      write = new PassThrough();
    write.resume();
    const pipe = Duplex.from({ readable: read, writable: write });
    try {
      await assert.rejects(
        createPipeExchange(pipe)(requestValue(), async () => {}),
        /Provider transport closed/u,
      );
    } finally {
      pipe.destroy();
      read.destroy();
      write.destroy();
    }
  }
});

test("closing a full private pipe rejects its pending exchange without waiting for drain", async () => {
  let entered;
  const writing = new Promise((resolve) => {
    entered = resolve;
  });
  const pipe = new Duplex({
    writableHighWaterMark: 1,
    read() {},
    write(bytes, encoding, callback) {
      entered();
    },
  });
  const exchange = createPipeExchange(pipe, { schedule() {}, cancel() {} });
  const pending = exchange(requestValue(), async () => assert.fail());
  pending.catch(() => {});
  await writing;
  pipe.destroy();
  await assert.rejects(pending, /Provider transport closed/u);
});

test("an expired pipe exchange cannot report successful delivery afterward", async () => {
  const messages = [
    { type: "headers", contentType: "application/json" },
    { type: "data", bytes: Buffer.from("{}").toString("base64") },
    { type: "end" },
  ];
  const frames = messages.map((value) => {
    const bytes = Buffer.from(JSON.stringify(value)),
      header = Buffer.alloc(4);
    header.writeUInt32BE(bytes.length);
    return Buffer.concat([header, bytes]);
  });
  const incoming = Readable.from(frames),
    outgoing = new PassThrough();
  outgoing.resume();
  const pipe = Duplex.from({ readable: incoming, writable: outgoing });
  pipe.on("error", () => {});
  let expire;
  const exchange = createPipeExchange(pipe, {
    schedule(callback) {
      expire = callback;
    },
    cancel() {},
  });
  try {
    await assert.rejects(
      exchange(requestValue(), async (item) => {
        if (item.type === "end") expire();
      }),
      /Provider transport closed/u,
    );
  } finally {
    pipe.destroy();
    incoming.destroy();
    outgoing.destroy();
  }
});

test("transport entry points close inherited resources when control admission fails", async () => {
  for (const entry of [runProtectedRelay, runCredentialFreeBridge]) {
    const exchange = new PassThrough();
    let closed = false;
    const server = {
      close() {
        closed = true;
      },
    };
    try {
      await assert.rejects(
        entry({
          exchange,
          server,
          control: async () => {
            throw new Error("Synthetic admission failure");
          },
        }),
      );
      assert.equal(exchange.destroyed, true);
      if (entry === runCredentialFreeBridge) assert.equal(closed, true);
    } finally {
      exchange.destroy();
    }
  }
});
