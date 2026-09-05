import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import {
  createProviderRegistry,
  normalizeAdapterFailure,
  PROVIDER_REGISTRY,
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
      createAdapter: () => adapter,
      validateExecutionOptions(value) {
        assert.deepEqual(Object.keys(value).sort(), [
          "contextSize",
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
      normalizeDiagnosticClass: (value) =>
        value === "fake-native" ? value : undefined,
    },
  ]);
  return { adapter, registry, validations };
}

function fakeConfiguration() {
  return {
    schemaVersion: 1,
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
  for (const descriptor of PROVIDER_REGISTRY.list()) {
    assert.ok(Object.isFrozen(descriptor));
    assert.ok(Object.isFrozen(descriptor.trustedProfile));
    assert.ok(Object.isFrozen(descriptor.sourceSession));
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

test("runner construction, probing, and source sessions use the registry", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-registry-"));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  t.after(() => rm(root, { recursive: true, force: true }));

  const { adapter, registry } = fakeProvider();
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
  }
  assert.ok(adapter.probes.length > 0);
  assert.ok(adapter.probes.every(({ profile }) => profile === "native-work"));

  const normalized = normalizeAdapterFailure(
    "fake",
    { code: "ERR_FAKE", diagnosticClass: "fake-native" },
    registry,
  );
  assert.equal(normalized.code, "ERR_FAKE");
  assert.equal(normalized.diagnosticClass, "fake-native");
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
