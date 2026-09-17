import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
} from "../src/trusted-validation/index.js";
import { sandboxTrustedCommand } from "../src/trusted-validation/execution.js";
import { inspectTrustedRequirements } from "../src/runner/trusted-requirements.js";
import { reconcileOperatorStop } from "../src/runner/stops.js";

const command = "node required-check";
const artifact = {
  url: "https://downloads.example.com/tool",
  sha256: "a".repeat(64),
};
const passed = {
  status: "PASS",
  exitCode: 0,
  signal: null,
  timedOut: false,
  reason: "exit",
};
const snapshot = (capabilities = {}) =>
  createTrustedValidationSnapshot(
    {
      check: {
        command,
        executable: process.execPath,
        arguments: ["required-check"],
        capabilities,
      },
    },
    ["check"],
  );

async function fixture(t, capabilities = {}) {
  const root = await mkdtemp(join(tmpdir(), "trusted-requirements-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const storageRoot = join(root, "storage");
  await mkdir(projectPath);
  const calls = [],
    records = [];
  let result = passed;
  const options = {
    storageRoot,
    environment: { HOME: root, PATH: "/usr/bin:/bin" },
    git: {
      async snapshot() {
        calls.push("snapshot");
        return { projectPath, contentFingerprint: "b".repeat(64) };
      },
      async assertUnchanged() {
        calls.push("unchanged");
      },
    },
    sandboxCommand(value, settings) {
      calls.push("sandbox");
      assert.equal(settings.preparationOnly, true);
      return sandboxTrustedCommand(value, {
        ...settings,
        bubblewrapPath: "/usr/bin/bwrap",
      });
    },
    async runCommand(value, settings) {
      calls.push("probe");
      assert.deepEqual(value.arguments.slice(-3), [
        process.execPath,
        "--eval",
        "",
      ]);
      assert.ok(!value.arguments.includes("required-check"));
      assert.ok(value.arguments.includes("--unshare-net"));
      assert.equal(settings.timeoutMs, 10_000);
      await settings.onProcess(42, {});
      await settings.onProcess(null);
      return result;
    },
  };
  const input = {
    projectPath,
    inventory: [command],
    snapshot: snapshot(capabilities),
    onResource: async (value) => records.push(value),
    onProcess: async () => {},
  };
  return {
    root,
    projectPath,
    storageRoot,
    calls,
    records,
    options,
    input,
    service: createTrustedValidationService(options),
    setResult(value) {
      result = value;
    },
  };
}

test("malformed reports receive contract diagnostics before any availability effects", async (t) => {
  const f = await fixture(t);
  const bad = [
    null,
    [],
    { command: "node another-check" },
    { command, extra: true },
    { command, commandIdentity: "bad" },
    { command, capabilities: null },
    { command, capabilities: { scratch: false } },
    { command, capabilities: { cache: "/tmp" } },
    { command, capabilities: { network: true } },
    { command, capabilities: { artifacts: [] } },
    {
      command,
      capabilities: { artifacts: [{ ...artifact, destination: "/tmp" }] },
    },
    { command, unsupported: null },
    { command, unsupported: ["secret\ntext"] },
    { command, unsupported: Array(17).fill("network") },
  ];
  for (const value of bad) {
    await assert.rejects(
      f.service.inspectRequirements({ ...f.input, requirements: [value] }),
      { code: "ERR_INVALID_TRUSTED_REQUIREMENTS" },
    );
  }
  for (const inventory of [
    null,
    [command, command],
    [command + " "],
    Array.from({ length: 513 }, (_, index) => `node check-${index}`),
    [],
  ]) {
    await assert.rejects(
      f.service.inspectRequirements({ ...f.input, inventory }),
      { code: "ERR_INVALID_TRUSTED_REQUIREMENTS" },
    );
  }
  await assert.rejects(
    f.service.inspectRequirements({
      ...f.input,
      requirements: Array(1025).fill({ command }),
    }),
    { code: "ERR_INVALID_TRUSTED_REQUIREMENTS" },
  );
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.records, []);
});

test("valid unsatisfied needs are bounded blockers and never grants", async (t) => {
  const f = await fixture(t);
  for (const [requirements, expected] of [
    [
      [{ command, capabilities: { scratch: true } }, { command }],
      "insufficient-authority",
    ],
    [[{ command, capabilities: { cache: true } }], "insufficient-authority"],
    [[{ command, commandIdentity: "c".repeat(64) }], "insufficient-authority"],
    [
      [{ command, capabilities: { artifacts: [artifact] } }],
      "insufficient-authority",
    ],
    [[{ command, unsupported: ["network"] }], "unsupported"],
  ]) {
    const result = await f.service.inspectRequirements({
      ...f.input,
      requirements,
    });
    assert.equal(result.status, "BLOCKED");
    assert.equal(result.blockers[0].reason, expected);
    assert.ok(!JSON.stringify(result).includes(artifact.url));
  }
  const missing = await f.service.inspectRequirements({
    ...f.input,
    snapshot: undefined,
    requirements: [{ command }],
  });
  assert.equal(missing.blockers[0].reason, "not-selected");
  const ordinary = await f.service.inspectRequirements({
    ...f.input,
    snapshot: undefined,
  });
  assert.deepEqual(ordinary, { status: "READY", blockers: [] });
  assert.deepEqual(f.calls, []);
});

test("artifact requests match both the canonical URL and digest before preparation", async (t) => {
  const f = await fixture(t, { artifacts: [artifact] });
  for (const value of [
    { ...artifact, sha256: "b".repeat(64) },
    { ...artifact, url: "https://downloads.example.com/other" },
  ]) {
    const result = await f.service.inspectRequirements({
      ...f.input,
      requirements: [{ command, capabilities: { artifacts: [value] } }],
    });
    assert.equal(result.blockers[0].reason, "insufficient-authority");
  }
  assert.deepEqual(f.calls, []);
});

test("frozen declarations remain requirements without reports; preparation is not check evidence", async (t) => {
  const f = await fixture(t, { scratch: true, cache: true });
  const original = JSON.stringify(f.input.snapshot);
  for (const requirements of [
    [],
    [
      {
        command,
        commandIdentity: f.input.snapshot.commands[0].identity,
        capabilities: { scratch: true },
      },
      { command, capabilities: { cache: true } },
    ],
  ]) {
    assert.deepEqual(
      await f.service.inspectRequirements({ ...f.input, requirements }),
      { status: "READY", blockers: [] },
    );
    assert.deepEqual(await readdir(f.storageRoot), []);
  }
  assert.equal(JSON.stringify(f.input.snapshot), original);
  assert.deepEqual(
    f.records.map((value) => value?.phase ?? null),
    ["allocating", "allocated", null, "allocating", "allocated", null],
  );
  assert.deepEqual(f.calls, [
    "snapshot",
    "sandbox",
    "probe",
    "unchanged",
    "snapshot",
    "sandbox",
    "probe",
    "unchanged",
  ]);
});

test("availability is rechecked after storage and isolation repair", async (t) => {
  const f = await fixture(t, { scratch: true });
  await writeFile(f.storageRoot, "unavailable");
  assert.equal(
    (await f.service.inspectRequirements(f.input)).status,
    "BLOCKED",
  );
  assert.ok(!f.calls.includes("probe"));
  await rm(f.storageRoot);
  f.setResult({
    status: "BLOCKED",
    exitCode: null,
    signal: null,
    timedOut: false,
    reason: "isolation",
  });
  const result = await f.service.inspectRequirements(f.input);
  assert.equal(result.blockers[0].reason, "unavailable");
  assert.deepEqual(await readdir(f.storageRoot), []);
  f.setResult(passed);
  assert.equal((await f.service.inspectRequirements(f.input)).status, "READY");
});

test("missing executable and isolation setup errors cannot be attested by a successful probe", async (t) => {
  const f = await fixture(t);
  const missing = createTrustedValidationSnapshot(
    {
      check: {
        command,
        executable: join(f.root, "missing"),
        arguments: [],
      },
    },
    ["check"],
  );
  assert.equal(
    (await f.service.inspectRequirements({ ...f.input, snapshot: missing }))
      .status,
    "BLOCKED",
  );
  const unavailable = createTrustedValidationService({
    ...f.options,
    sandboxCommand() {
      throw new Error("private host diagnostics");
    },
  });
  const result = await unavailable.inspectRequirements(f.input);
  assert.equal(result.status, "BLOCKED");
  assert.ok(!JSON.stringify(result).includes("private host"));
  assert.ok(!f.calls.includes("probe"));
});

test("cancellation, journal ownership, and repository mutation remain safety outcomes", async (t) => {
  const f = await fixture(t, { scratch: true });
  await assert.rejects(
    f.service.inspectRequirements({ ...f.input, signal: AbortSignal.abort() }),
    { name: "AbortError" },
  );
  assert.deepEqual(f.calls, []);
  await assert.rejects(
    f.service.inspectRequirements({ ...f.input, onResource: undefined }),
    { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
  );
  const service = createTrustedValidationService({
    ...f.options,
    git: {
      ...f.options.git,
      async assertUnchanged() {
        throw new Error("mutated");
      },
    },
  });
  await assert.rejects(service.inspectRequirements(f.input), {
    code: "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY",
  });
  assert.deepEqual(await readdir(f.storageRoot), []);
});

test("uncertain probe registration stops inspection before preparing another command", async (t) => {
  const f = await fixture(t, { scratch: true });
  const selected = createTrustedValidationSnapshot(
    Object.fromEntries(
      ["first", "second"].map((alias) => [
        alias,
        {
          command: `node ${alias}`,
          executable: process.execPath,
          arguments: [alias],
          capabilities: { scratch: true },
        },
      ]),
    ),
    ["first", "second"],
  );
  let probes = 0;
  const service = createTrustedValidationService({
    ...f.options,
    async runCommand(_command, { onProcess }) {
      probes++;
      await onProcess(42, {});
      await onProcess(null);
      return passed;
    },
  });
  await assert.rejects(
    service.inspectRequirements({
      ...f.input,
      snapshot: selected,
      inventory: selected.commands.map(({ command }) => command),
      async onProcess(pid) {
        if (pid === null) throw new Error("Retirement journal failed.");
      },
    }),
    { code: "ERR_EXECUTION_PROCESS_ACTIVE" },
  );
  assert.equal(probes, 1);
  assert.deepEqual(
    f.records.map((value) => value?.phase),
    ["allocating", "allocated"],
  );
  assert.equal((await readdir(f.storageRoot)).length, 1);
  assert.ok(!f.calls.includes("unchanged"));
});

test("runner inspection pins durable authority and uses monitored lease callbacks", async () => {
  const saved = snapshot();
  const lease = {},
    run = { runId: "saved-run" };
  const current = {
    projectPath: "/project",
    pipelineState: { trustedValidation: saved },
  };
  const calls = [];
  const controller = new AbortController();
  const context = {
    lease,
    run,
    checkConfiguration: async () => calls.push("configuration"),
    validatePersistedBoundary: async () => calls.push("boundary"),
    storageForbiddenPaths: () => ["/state", "/task"],
    runStore: {
      async loadRun(id) {
        assert.equal(id, run.runId);
        return current;
      },
      async recordExecutionResource(owner, value) {
        assert.equal(owner, lease);
        calls.push(value);
      },
    },
    monitor: {
      async check() {
        calls.push("stop-check");
      },
      async invoke(operation, request) {
        return operation({
          ...request,
          signal: controller.signal,
          onProcess() {},
        });
      },
    },
    trustedValidation: {
      async inspectRequirements(request) {
        assert.equal(request.snapshot, saved);
        assert.equal(request.projectPath, "/project");
        assert.deepEqual(request.storageForbiddenPaths, ["/state", "/task"]);
        assert.equal(request.signal, controller.signal);
        assert.equal(typeof request.onProcess, "function");
        await request.onResource("journal");
        return { status: "READY", blockers: [] };
      },
    },
  };
  const input = {
    inventory: [command],
    snapshot: snapshot({ scratch: true }),
    projectPath: "/wrong",
    onResource: assert.fail,
  };
  assert.equal(
    (await inspectTrustedRequirements(context, input)).status,
    "READY",
  );
  assert.deepEqual(calls, [
    "configuration",
    "stop-check",
    "journal",
    "configuration",
    "boundary",
  ]);
  calls.length = 0;
  await assert.rejects(
    inspectTrustedRequirements(
      {
        ...context,
        checkConfiguration() {
          throw new Error("configuration changed");
        },
      },
      input,
    ),
    /configuration changed/u,
  );
  assert.deepEqual(calls, []);
  await assert.rejects(
    inspectTrustedRequirements(
      {
        ...context,
        monitor: {
          ...context.monitor,
          async check() {
            throw new Error("stop requested");
          },
        },
      },
      input,
    ),
    /stop requested/u,
  );
  assert.deepEqual(calls, ["configuration"]);
  calls.length = 0;
  await assert.rejects(
    inspectTrustedRequirements(
      {
        ...context,
        checkConfiguration: async () => {
          calls.push("configuration");
          if (calls.includes("journal"))
            throw new Error("configuration changed during inspection");
        },
      },
      input,
    ),
    /configuration changed during inspection/u,
  );
  assert.deepEqual(calls, [
    "configuration",
    "stop-check",
    "journal",
    "configuration",
  ]);
  calls.length = 0;
  current.executionResource = {};
  await assert.rejects(inspectTrustedRequirements(context, input), {
    code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE",
  });
  assert.ok(!calls.includes("journal"));
});

test("stop reconciliation rejects inspection before any new preparation", async () => {
  const run = {
    runId: "stopped",
    executionProcess: null,
    stopRequest: { reconciledRevision: null },
    pipelineState: { settings: {} },
  };
  await assert.rejects(
    reconcileOperatorStop({
      run,
      runStore: {
        loadRun: async () => run,
        recordStopActivity: async () => run,
      },
      publish: async () => {},
      runtime: {
        adapters: {},
        trustedValidation: { inspectRequirements: assert.fail },
      },
      pipeline: {
        workflow: {
          run: async ({ runtime }) =>
            runtime.trustedValidation.inspectRequirements({ inventory: [] }),
        },
      },
    }),
    { code: "ERR_STOP_RECONCILIATION_EFFECT" },
  );
});

test("inspection accepts the complete two-role requirement and blocker union", async () => {
  const inventory = Array.from(
    { length: 512 },
    (_, index) => `node check-${index}`,
  );
  const requirements = inventory.flatMap((command) => [
    { command },
    { command },
  ]);
  const result = await createTrustedValidationService().inspectRequirements({
    inventory,
    requirements,
  });
  assert.equal(result.status, "BLOCKED");
  assert.equal(result.blockers.length, 512);
  assert.ok(result.blockers.every(({ reason }) => reason === "not-selected"));
});
