import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import {
  AgentBoundaryError,
  AUTHENTICATION_REQUIRED_DISPOSITION,
  AVAILABILITY_REASONS,
  createCapabilityProof,
  createProviderRegistry,
  DEFAULT_CLIENT_ATTRIBUTION,
  deriveEffectStarted,
  FAILURE_DISPOSITIONS,
  LAUNCH_CHECKPOINTS,
  normalizeAdapterFailure,
  normalizeClientAttribution,
  normalizeFailureRecord,
  PROVIDER_REGISTRY,
  ProviderRegistryError,
} from "../../src/agents/index.js";
import {
  parseRunnerConfiguration,
  resolvePipelineConfiguration,
} from "../../src/config/index.js";
import { createMcpServer } from "../../src/mcp/index.js";
import { listPipelines } from "../../src/pipeline-registry.js";
import { createRunner, parseSourceSession } from "../../src/runner/index.js";
import { createRunStore } from "../../src/state/index.js";

const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";

function fakeProvider() {
  const adapterOptions = [];
  const adapter = {
    probes: [],
    async probe(options) {
      this.probes.push(options);
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        autonomousWrite: true,
        gitMetadataWriteBlocked: true,
        workspaceWrite: true,
        localCommit: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: true,
      };
    },
    async run() {
      throw new Error("The registry test does not execute agent turns.");
    },
  };
  const validations = [];
  const registry = createProviderRegistry([
    {
      id: "fake",
      createAdapter(options) {
        adapterOptions.push(options);
        return adapter;
      },
      clientAttribution: { supportsCustom: true },
      validateExecutionOptions(value) {
        assert.deepEqual(Object.keys(value).sort(), [
          "contextSize",
          "effort",
          "model",
          "profile",
        ]);
        validations.push(value);
      },
      trustedProfile: {
        fields: ["backend", "workspace"],
        normalize(value, path) {
          if (value.workspace !== "work") {
            throw new Error(`${path}.workspace must be work.`);
          }
          return { backend: "fake", workspace: value.workspace };
        },
        resolve: (profile) => `native-${profile.workspace}`,
      },
      sourceSession: { fork: true },
      failures: {
        classes: new Set(["fake_native"]),
        classify(cause) {
          if (cause?.diagnosticClass !== "fake_native") return undefined;
          return {
            failureClass: cause.diagnosticClass,
            checkpoint: "turn",
            outcome: "rejected",
            effect: "possible",
            retry: "terminal",
          };
        },
      },
    },
  ]);
  return { adapter, adapterOptions, registry, validations };
}

function fakeConfiguration() {
  return {
    schemaVersion: 1,
    clientAttribution: {
      name: "example/agent-runner",
      title: "Example Agent Runner",
    },
    defaultBackend: "fake",
    defaultProfile: "fake-work",
    profiles: {
      "fake-work": { backend: "fake", workspace: "work" },
    },
  };
}

test("built-in provider registration is static and frozen", () => {
  assert.deepEqual(PROVIDER_REGISTRY.ids, ["codex", "claude"]);
  assert.deepEqual(PROVIDER_REGISTRY.sourceSessionIds, ["codex", "claude"]);
  assert.ok(Object.isFrozen(PROVIDER_REGISTRY));
  assert.ok(Object.isFrozen(PROVIDER_REGISTRY.ids));
  assert.ok(Object.isFrozen(PROVIDER_REGISTRY.list()));
  assert.equal(
    PROVIDER_REGISTRY.isDiagnosticClass("launch_process_exited"),
    true,
  );
  assert.ok(
    PROVIDER_REGISTRY.list().every(({ failures }) =>
      failures.classes.has("effort_unsupported"),
    ),
  );
  assert.deepEqual(
    PROVIDER_REGISTRY.list().map(({ id, clientAttribution }) => [
      id,
      clientAttribution.supportsCustom,
    ]),
    [
      ["codex", true],
      ["claude", false],
    ],
  );
  for (const descriptor of PROVIDER_REGISTRY.list()) {
    assert.ok(Object.isFrozen(descriptor));
    assert.ok(Object.isFrozen(descriptor.trustedProfile));
    assert.ok(Object.isFrozen(descriptor.sourceSession));
    assert.ok(Object.isFrozen(descriptor.clientAttribution));
    assert.ok(Object.isFrozen(descriptor.failures));
    assert.ok(Object.isFrozen(descriptor.failures.classes));
    assert.throws(() => descriptor.failures.classes.add("new_class"), {
      code: "ERR_INVALID_PROVIDER_REGISTRY",
    });
    assert.throws(
      () => Set.prototype.add.call(descriptor.failures.classes, "new_class"),
      TypeError,
    );
    descriptor.failures.classes.forEach((value, duplicate, classes) => {
      assert.equal(value, duplicate);
      assert.equal(classes, descriptor.failures.classes);
    });
    assert.equal(descriptor.failures.classes.has("new_class"), false);
  }
});

test("client attribution is strict, frozen, and descriptor-driven", () => {
  const custom = normalizeClientAttribution({
    name: "example/agent-runner",
    title: "Example Agent Runner",
  });
  assert.deepEqual(DEFAULT_CLIENT_ATTRIBUTION, {
    name: "agent_runner",
    title: "Agent Runner",
  });
  assert.ok(Object.isFrozen(DEFAULT_CLIENT_ATTRIBUTION));
  assert.ok(Object.isFrozen(custom));
  assert.equal(
    PROVIDER_REGISTRY.supportsClientAttribution("codex", custom),
    true,
  );
  assert.equal(
    PROVIDER_REGISTRY.supportsClientAttribution("claude", custom),
    false,
  );
  for (const invalid of [
    null,
    {},
    { name: "agent" },
    { name: "agent", title: "Runner", extra: true },
    { name: " agent", title: "Runner" },
    { name: "agent", title: "Runner\tSecret" },
    { name: "agent", title: "Runner\u202eSecret" },
    { name: "a".repeat(257), title: "Runner" },
  ]) {
    assert.throws(() => normalizeClientAttribution(invalid), TypeError);
  }

  const options = [];
  const registry = createProviderRegistry([
    {
      ...PROVIDER_REGISTRY.list()[0],
      id: "injected",
      clientAttribution: { supportsCustom: false },
      createAdapter(value) {
        options.push(value);
        return {};
      },
    },
  ]);
  registry.createAdapters();
  registry.createAdapters(custom);
  assert.equal(
    registry.supportsClientAttribution("injected", DEFAULT_CLIENT_ATTRIBUTION),
    true,
  );
  assert.equal(registry.supportsClientAttribution("injected", custom), false);
  assert.deepEqual(options, [
    { clientAttribution: DEFAULT_CLIENT_ATTRIBUTION },
    { clientAttribution: custom },
  ]);
  for (const option of options) {
    assert.ok(Object.isFrozen(option));
    assert.ok(Object.isFrozen(option.clientAttribution));
  }
  for (const clientAttribution of [
    { supportsCustom: "yes" },
    { supportsCustom: true, nativeField: true },
    Object.assign(Object.create({ supportsCustom: true }), {
      nativeField: true,
    }),
  ]) {
    assert.throws(
      () =>
        createProviderRegistry([
          {
            ...PROVIDER_REGISTRY.list()[0],
            clientAttribution,
          },
        ]),
      { code: "ERR_INVALID_PROVIDER_REGISTRY" },
    );
  }
});

test("shared failure records strictly bound commit-executor proof", () => {
  const none = normalizeFailureRecord({
    failureClass: "adapter_failure",
    checkpoint: "commit",
    outcome: "rejected",
    effect: "none",
    retry: "terminal",
    commitExecutor: "not_started",
  });
  const possible = normalizeFailureRecord({
    failureClass: "adapter_failure",
    checkpoint: "commit",
    outcome: "ambiguous",
    effect: "possible",
    retry: "terminal",
    commitExecutor: "not_started",
  });

  assert.ok(Object.isFrozen(none));
  assert.ok(Object.isFrozen(possible));
  assert.equal(deriveEffectStarted(none), false);
  assert.equal(deriveEffectStarted(possible), false);
  assert.equal(
    deriveEffectStarted(
      normalizeFailureRecord({
        failureClass: "adapter_failure",
        checkpoint: "turn",
        outcome: "rejected",
        effect: "possible",
        retry: "terminal",
      }),
    ),
    undefined,
  );
  assert.equal(
    deriveEffectStarted(
      normalizeFailureRecord({
        failureClass: "adapter_failure",
        checkpoint: "turn",
        outcome: "completed",
        effect: "started",
        retry: "terminal",
      }),
    ),
    true,
  );

  for (const value of [
    { ...none, effect: "started" },
    ...LAUNCH_CHECKPOINTS.filter((checkpoint) => checkpoint !== "commit").map(
      (checkpoint) => ({ ...none, checkpoint }),
    ),
    { ...none, commitExecutor: "started" },
    { ...none, nativeCause: "must not cross the boundary" },
  ]) {
    assert.throws(() => normalizeFailureRecord(value), TypeError);
  }
});

test("reconstruction evidence stays terminal, closed and provider-owned", () => {
  const failure = {
    failureClass: "protocol_history_unavailable",
    checkpoint: "turn",
    outcome: "rejected",
    effect: "possible",
    retry: "terminal",
    reconstruction: { schemaVersion: 1, kind: "completed_turn_acquisition" },
  };
  const classified = PROVIDER_REGISTRY.classifyFailure("codex", { failure });
  assert.deepEqual(classified, failure);
  assert.ok(Object.isFrozen(classified.reconstruction));
  assert.deepEqual(
    normalizeAdapterFailure(
      "codex",
      new AgentBoundaryError({ code: "ERR_CODEX_PROTOCOL" }, classified),
    ).failure,
    failure,
  );
  for (const changed of [
    { effect: "started" },
    { effect: "none" },
    { outcome: "ambiguous" },
    { retry: "transient" },
    { checkpoint: "commit" },
    { availabilityReason: "transport_unavailable" },
    { reconstruction: { ...failure.reconstruction, schemaVersion: 2 } },
    {
      reconstruction: {
        ...failure.reconstruction,
        raw: "PRIVATE_NATIVE_PAYLOAD",
      },
    },
    ...[
      "adapter_failure",
      "operation_remote_write",
      "protocol_item_unfinished",
      "protocol_cursor",
      "protocol_framing",
    ].map((failureClass) => ({ failureClass })),
  ]) {
    assert.throws(
      () =>
        PROVIDER_REGISTRY.classifyFailure("codex", {
          failure: { ...failure, ...changed },
        }),
      { code: "ERR_INVALID_PROVIDER_REGISTRY" },
    );
    assert.throws(
      () =>
        normalizeAdapterFailure(
          "codex",
          new AgentBoundaryError(
            { code: "ERR_CODEX_PROTOCOL" },
            { ...failure, ...changed },
          ),
        ),
      { code: "ERR_INVALID_PROVIDER_REGISTRY" },
    );
  }
});

test("readiness classes come from the finite validated provider record", () => {
  for (const failureClass of [
    "commit_readiness_workspace_change",
    "commit_readiness_git_operation",
    "commit_readiness_invalid_result",
  ]) {
    assert.equal(PROVIDER_REGISTRY.isDiagnosticClass(failureClass), true);
    const failure = {
      failureClass,
      checkpoint: "commit",
      outcome: "rejected",
      effect: "none",
      retry: "terminal",
      commitExecutor: "not_started",
    };
    const normalized = normalizeAdapterFailure("codex", {
      code: "ERR_CODEX_LOCAL_COMMIT_POLICY",
      failure,
      diagnosticClass: "DO_NOT_RETAIN_RAW_CLASS",
      command: "DO_NOT_RETAIN_COMMAND",
      prompt: "DO_NOT_RETAIN_PROMPT",
      output: "DO_NOT_RETAIN_OUTPUT",
      identity: "DO_NOT_RETAIN_IDENTITY",
      path: "DO_NOT_RETAIN_PATH",
      cause: new Error("DO_NOT_RETAIN_CAUSE"),
    });
    assert.deepEqual(normalized.failure, failure);
    assert.equal(normalized.diagnosticClass, failureClass);
    assert.equal(normalized.effectStarted, false);
    assert.doesNotMatch(JSON.stringify(normalized), /DO_NOT_RETAIN/u);
    assert.throws(
      () =>
        normalizeAdapterFailure("codex", {
          failure: { ...failure, failureClass: "commit_readiness_forged" },
        }),
      ProviderRegistryError,
    );
    assert.throws(
      () =>
        normalizeAdapterFailure("codex", {
          failure: { ...failure, effect: "started" },
        }),
      ProviderRegistryError,
    );
  }
});

test("availability evidence is finite, redacted, and excludes uncertain commit effects", () => {
  const base = {
    failureClass: "adapter_failure",
    checkpoint: "turn",
    outcome: "rejected",
    effect: "possible",
    retry: "transient",
  };
  for (const availabilityReason of AVAILABILITY_REASONS) {
    const failure = { ...base, availabilityReason };
    const providers = createProviderRegistry([
      {
        ...PROVIDER_REGISTRY.list()[0],
        id: "availability-test",
        failures: { classes: new Set(), classify: () => failure },
      },
    ]);
    const normalized = normalizeAdapterFailure(
      "availability-test",
      { availabilityReason: "DO_NOT_RETAIN", cause: "DO_NOT_RETAIN" },
      providers,
    );
    assert.deepEqual(normalized.failure, failure);
    assert.ok(Object.isFrozen(normalized.failure));
    assert.doesNotMatch(JSON.stringify(normalized), /DO_NOT_RETAIN/u);
    const commit = {
      ...failure,
      checkpoint: "commit",
      commitExecutor: "not_started",
    };
    assert.equal(deriveEffectStarted(normalizeFailureRecord(commit)), false);
  }
  const available = { ...base, availabilityReason: "transport_unavailable" };
  for (const invalid of [
    ...[null, undefined, "unknown", {}, "native-provider-reason"].map(
      (availabilityReason) => ({ ...base, availabilityReason }),
    ),
    { ...available, retry: "terminal" },
    { ...available, outcome: "ambiguous" },
    { ...available, outcome: "completed" },
    { ...available, effect: "started" },
    { ...available, checkpoint: "commit" },
    {
      ...available,
      checkpoint: "commit",
      outcome: "ambiguous",
      commitExecutor: "not_started",
    },
  ]) {
    assert.throws(() => normalizeFailureRecord(invalid), TypeError);
  }
  for (const backend of ["codex", "claude"]) {
    assert.equal(
      normalizeAdapterFailure(backend, new Error("ECONNRESET")).failure
        .availabilityReason,
      undefined,
    );
  }
});

test("authentication-required disposition is finite, terminal, and redacted", () => {
  assert.deepEqual(FAILURE_DISPOSITIONS, [AUTHENTICATION_REQUIRED_DISPOSITION]);
  assert.ok(Object.isFrozen(FAILURE_DISPOSITIONS));
  const base = {
    failureClass: "adapter_failure",
    checkpoint: "turn",
    outcome: "rejected",
    effect: "possible",
    retry: "terminal",
    disposition: AUTHENTICATION_REQUIRED_DISPOSITION,
  };
  assert.deepEqual(normalizeFailureRecord(base), base);

  const sensitiveMarker = "DO_NOT_RETAIN_AUTHENTICATION_PAYLOAD";
  const providers = createProviderRegistry([
    {
      ...PROVIDER_REGISTRY.list()[0],
      id: "authentication-test",
      failures: { classes: new Set(), classify: () => base },
    },
  ]);
  const normalized = normalizeAdapterFailure(
    "authentication-test",
    {
      credential: sensitiveMarker,
      message: sensitiveMarker,
      requestId: sensitiveMarker,
      url: sensitiveMarker,
    },
    providers,
  );
  assert.deepEqual(normalized.failure, base);
  assert.ok(Object.isFrozen(normalized.failure));
  assert.doesNotMatch(JSON.stringify(normalized), /DO_NOT_RETAIN/u);

  for (const invalid of [
    ...[null, undefined, "native_authentication_error", {}, true].map(
      (disposition) => ({ ...base, disposition }),
    ),
    { ...base, outcome: "ambiguous" },
    { ...base, outcome: "not_started", effect: "none" },
    { ...base, effect: "started" },
    { ...base, retry: "transient" },
    { ...base, availabilityReason: "transport_unavailable" },
    { ...base, processOutcome: { exitCode: 1 } },
  ]) {
    assert.throws(() => normalizeFailureRecord(invalid), TypeError);
  }
});

test("one fake descriptor drives configuration and every pipeline", () => {
  const { registry, validations } = fakeProvider();
  const configuration = parseRunnerConfiguration(
    JSON.stringify(fakeConfiguration()),
    registry,
  );

  assert.deepEqual(parseSourceSession(`fake:${SOURCE_SESSION}`, registry), {
    backend: "fake",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(configuration.profiles["fake-work"], {
    backend: "fake",
    workspace: "work",
  });
  for (const pipeline of listPipelines()) {
    const resolved = resolvePipelineConfiguration(
      pipeline.id,
      configuration,
      {},
      {},
      {
        backend: "fake",
        id: SOURCE_SESSION,
        profile: "fake-work",
      },
      null,
      {},
      registry,
    );
    assert.deepEqual(
      new Set(Object.values(resolved.roles).map(({ backend }) => backend)),
      new Set(["fake"]),
    );
    assert.deepEqual(
      new Set(Object.values(resolved.roles).map(({ profile }) => profile)),
      new Set(["native-work"]),
    );
    assert.equal(resolved.sourceProfile, "fake-work");
  }
  assert.ok(validations.length > 0);
});

test("runner construction, attribution, probing, and source sessions use the registry", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-registry-"));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  t.after(() => rm(root, { recursive: true, force: true }));

  const { adapter, adapterOptions, registry } = fakeProvider();
  const configuration = parseRunnerConfiguration(
    JSON.stringify(fakeConfiguration()),
    registry,
  );
  const runner = createRunner({
    git: {
      async inspectPath({ path }) {
        return { exists: false, path: resolve(path) };
      },
      async preflight({ projectPath: requestedProjectPath }) {
        return { snapshot: { projectPath: resolve(requestedProjectPath) } };
      },
    },
    loadConfiguration: async () => configuration,
    providers: registry,
    runStore: createRunStore({ stateRoot }),
  });

  for (const pipeline of listPipelines()) {
    const { run } = await runner.create({
      pipelineId: pipeline.id,
      projectPath,
      taskPath,
      sourceSession: {
        backend: "fake",
        id: SOURCE_SESSION,
        profile: "fake-work",
      },
    });
    assert.equal(run.sessionLineage.source, SOURCE_SESSION);
    assert.equal(run.sessionLineage.sourceProfile, "fake-work");
    assert.deepEqual(
      new Set(Object.values(run.roles).map(({ backend }) => backend)),
      new Set(["fake"]),
    );
    for (const [role, receipt] of Object.entries(run.providerPolicies)) {
      if (role === "arbiter") {
        assert.equal(receipt, null);
      } else {
        assert.equal(receipt.schemaVersion, 1);
        assert.match(receipt.fingerprint, /^[a-f0-9]{64}$/u);
      }
    }
  }
  assert.ok(adapter.probes.length > 0);
  assert.ok(adapter.probes.every(({ profile }) => profile === "native-work"));
  assert.deepEqual(adapterOptions, [
    {
      clientAttribution: {
        name: "example/agent-runner",
        title: "Example Agent Runner",
      },
    },
  ]);

  const normalized = normalizeAdapterFailure(
    "fake",
    { code: "ERR_FAKE", diagnosticClass: "fake_native" },
    registry,
  );
  assert.equal(normalized.code, "ERR_FAKE");
  assert.equal(normalized.diagnosticClass, "fake_native");
  assert.deepEqual(normalized.failure, {
    failureClass: "fake_native",
    checkpoint: "turn",
    outcome: "rejected",
    effect: "possible",
    retry: "terminal",
  });

  const unclassified = normalizeAdapterFailure(
    "fake",
    new Error("native details"),
    registry,
  );
  assert.deepEqual(unclassified.failure, {
    failureClass: "adapter_failure",
    checkpoint: "turn",
    outcome: "rejected",
    effect: "possible",
    retry: "terminal",
  });
  assert.equal(unclassified.ambiguous, false);
  assert.equal(unclassified.recoverable, false);
  assert.equal(unclassified.cause, undefined);
  assert.doesNotMatch(
    JSON.stringify({ ...unclassified, message: unclassified.message }),
    /native details/u,
  );
});

test("provider failure hooks are finite and return strict records", () => {
  const descriptor = PROVIDER_REGISTRY.list()[0];
  for (const failures of [
    undefined,
    { classes: ["not-a-set"], classify() {} },
    { classes: new Set(["invalid-class"]), classify() {} },
    { classes: new Set(["valid_class"]), classify: "invalid" },
  ]) {
    assert.throws(() => createProviderRegistry([{ ...descriptor, failures }]), {
      code: "ERR_INVALID_PROVIDER_REGISTRY",
    });
  }

  for (const failure of [
    {
      failureClass: "unknown_class",
      checkpoint: "turn",
      outcome: "rejected",
      effect: "possible",
      retry: "terminal",
    },
    {
      failureClass: "valid_class",
      checkpoint: "turn",
      outcome: "ambiguous",
      effect: "none",
      retry: "terminal",
    },
    {
      failureClass: "valid_class",
      checkpoint: "turn",
      outcome: "rejected",
      effect: "possible",
      retry: "terminal",
      nativeMessage: "must not cross the boundary",
    },
    {
      failureClass: "launch_process_exited",
      checkpoint: "spawn",
      outcome: "exited",
      effect: "none",
      retry: "transient",
      processOutcome: { exitCode: 1, stderr: "must not cross the boundary" },
    },
    {
      failureClass: "launch_process_exited",
      checkpoint: "spawn",
      outcome: "exited",
      effect: "none",
      retry: "transient",
      processOutcome: {
        exitCode: 1,
        [Symbol("stderr")]: "must not cross the boundary",
      },
    },
    {
      failureClass: "launch_version_unsupported",
      checkpoint: "probe",
      outcome: "rejected",
      effect: "none",
      retry: "transient",
    },
    {
      failureClass: "launch_process_exited",
      checkpoint: "spawn",
      outcome: "not_started",
      effect: "none",
      retry: "terminal",
    },
    {
      failureClass: "launch_process_exited",
      checkpoint: "turn",
      outcome: "exited",
      effect: "started",
      retry: "terminal",
    },
    {
      failureClass: "launch_protocol_incompatible",
      checkpoint: "initialize",
      outcome: "completed",
      effect: "started",
      retry: "terminal",
    },
  ]) {
    const registry = createProviderRegistry([
      {
        ...descriptor,
        failures: {
          classes: new Set(["valid_class"]),
          classify: () => failure,
        },
      },
    ]);
    assert.throws(
      () => registry.classifyFailure(descriptor.id, new Error("native")),
      { code: "ERR_INVALID_PROVIDER_REGISTRY" },
    );
  }

  const registry = createProviderRegistry([
    {
      ...descriptor,
      failures: {
        classes: new Set(["valid_class"]),
        classify: (cause) =>
          cause?.ambiguous === true
            ? {
                failureClass: "launch_process_exited",
                checkpoint: "turn",
                outcome: "ambiguous",
                effect: "possible",
                retry: "terminal",
                processOutcome: { signal: "SIGTERM" },
              }
            : {
                failureClass: "launch_process_exited",
                checkpoint: "spawn",
                outcome: "exited",
                effect: "none",
                retry: "transient",
                processOutcome: { signal: "SIGTERM" },
              },
      },
    },
  ]);
  assert.deepEqual(registry.classifyFailure(descriptor.id, new Error()), {
    failureClass: "launch_process_exited",
    checkpoint: "spawn",
    outcome: "exited",
    effect: "none",
    retry: "transient",
    processOutcome: { signal: "SIGTERM" },
  });
  assert.deepEqual(
    registry.classifyFailure(descriptor.id, { ambiguous: true }),
    {
      failureClass: "launch_process_exited",
      checkpoint: "turn",
      outcome: "ambiguous",
      effect: "possible",
      retry: "terminal",
      processOutcome: { signal: "SIGTERM" },
    },
  );
});

test("capability proofs enforce exact fields and policy receipts", () => {
  const capabilities = {
    version: "fixture-1",
    readOnly: true,
  };
  const receipt = {
    schemaVersion: 1,
    fingerprint: "a".repeat(64),
    supportedAccess: ["read-only"],
  };
  const proof = createCapabilityProof(capabilities, ["readOnly"], receipt);
  assert.ok(Object.isFrozen(proof));
  assert.ok(Object.isFrozen(proof.requiredCapabilities));
  assert.ok(Object.isFrozen(proof.policyReceipt));
  assert.ok(Object.isFrozen(proof.policyReceipt.supportedAccess));
  assert.deepEqual(proof, {
    version: "fixture-1",
    readOnly: true,
    requiredCapabilities: ["readOnly"],
    policyReceipt: receipt,
  });
  assert.throws(
    () =>
      createCapabilityProof(
        { ...capabilities, nativeCapability: true },
        ["readOnly"],
        receipt,
      ),
    TypeError,
  );
  assert.throws(
    () => createCapabilityProof(capabilities, Array(1), receipt),
    TypeError,
  );
  assert.throws(
    () =>
      createCapabilityProof(capabilities, ["readOnly"], {
        ...receipt,
        supportedAccess: Array(1),
      }),
    TypeError,
  );
  assert.throws(
    () =>
      createCapabilityProof(capabilities, ["readOnly"], {
        ...receipt,
        nativeReceipt: true,
      }),
    TypeError,
  );
});

test("raw cause fields cannot override validated failure evidence", () => {
  const descriptor = PROVIDER_REGISTRY.list()[0];
  let classified = {
    failureClass: "synthetic_failure",
    checkpoint: "commit",
    outcome: "ambiguous",
    effect: "possible",
    retry: "terminal",
  };
  const registry = createProviderRegistry([
    {
      ...descriptor,
      id: "synthetic",
      failures: {
        classes: new Set(["synthetic_failure"]),
        classify: () => classified,
      },
    },
  ]);

  const possible = normalizeAdapterFailure(
    "synthetic",
    {
      code: "ERR_SYNTHETIC",
      effectStarted: false,
      ambiguous: false,
      recoverable: true,
    },
    registry,
  );
  assert.equal(possible.effectStarted, undefined);
  assert.equal(Object.hasOwn(possible, "effectStarted"), false);
  assert.equal(possible.ambiguous, true);
  assert.equal(possible.recoverable, false);
  assert.equal(possible.diagnosticClass, "synthetic_failure");

  classified = { ...classified, commitExecutor: "not_started" };
  const notStarted = normalizeAdapterFailure(
    "synthetic",
    { code: "ERR_SYNTHETIC", effectStarted: true },
    registry,
  );
  assert.equal(notStarted.effectStarted, false);
  assert.equal(notStarted.ambiguous, true);
  assert.equal(notStarted.recoverable, false);
});

test("MCP backend schemas derive from an injected registry", async (t) => {
  const { registry } = fakeProvider();
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const control = new Proxy(
    {},
    {
      get: () => async () => ({}),
    },
  );
  const server = createMcpServer({
    control,
    issueReportingEnabled: false,
    providers: registry,
  });
  const client = new Client({ name: "registry-test", version: "1.0.0" });
  t.after(() => client.close().catch(() => {}));
  t.after(() => server.close().catch(() => {}));
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const { tools } = await client.listTools();
  const startSchema = tools.find(
    ({ name }) => name === "run_start",
  ).inputSchema;
  const serialized = JSON.stringify(startSchema);
  assert.match(serialized, /"enum":\["fake"\]/u);
  assert.doesNotMatch(serialized, /"codex"|"claude"/u);
});
