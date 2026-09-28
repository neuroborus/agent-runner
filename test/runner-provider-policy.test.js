import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { planExecutionPipeline } from "@agent-runner/plan-execution";

import {
  createProviderRegistry,
  PROVIDER_REGISTRY,
} from "../src/agents/index.js";
import { main } from "../src/cli.js";
import { parseRunnerConfiguration } from "../src/config/index.js";
import { createMcpControlPlane } from "../src/mcp/index.js";
import { createRunner } from "../src/runner/index.js";
import { RunnerError } from "../src/runner/input.js";
import { probeRequiredRoles, roleAdapters } from "../src/runner/roles.js";
import { createRunStore } from "../src/state/index.js";

const CONFIGURATION = Object.freeze({
  backend: "codex",
  contextSize: "current",
  effort: "current",
  model: "current",
  profile: "current",
});

function capabilities(overrides = {}) {
  return {
    version: "fixture-1",
    structuredOutput: true,
    readOnly: true,
    autonomousWrite: true,
    gitMetadataWriteBlocked: true,
    workspaceWrite: true,
    localCommit: true,
    remoteWriteBlocked: true,
    nativeSessionContinuation: true,
    nativeSessionFork: true,
    ...overrides,
  };
}

function failureProviders(classify) {
  const descriptor = PROVIDER_REGISTRY.list()[0];
  return createProviderRegistry([
    {
      ...descriptor,
      id: "fixture",
      failures: {
        classes: new Set(["fixture_failure"]),
        classify,
      },
    },
  ]);
}

const FAILURE_CONFIGURATION = Object.freeze({
  ...CONFIGURATION,
  backend: "fixture",
});

function failureAdapter(classify, run) {
  return roleAdapters(
    {
      pipelineId: planExecutionPipeline.id,
      roles: { worker: FAILURE_CONFIGURATION },
      sessionLineage: { source: null },
    },
    planExecutionPipeline,
    {
      fixture: {
        async probe() {
          return capabilities();
        },
        run,
      },
    },
    failureProviders(classify),
    async () => {},
  ).worker;
}

test("pipeline access requirements produce one bounded policy receipt", async () => {
  const receipt = await probeRequiredRoles(
    planExecutionPipeline,
    { worker: CONFIGURATION },
    {
      codex: {
        async probe() {
          return capabilities();
        },
        async run() {},
      },
    },
    null,
    PROVIDER_REGISTRY,
  );

  assert.equal(receipt.worker.schemaVersion, 1);
  assert.match(receipt.worker.fingerprint, /^[a-f0-9]{64}$/u);
  assert.deepEqual(receipt.worker.supportedAccess, [
    "read-only",
    "workspace-write",
    "local-commit",
  ]);
});

test("requested access fails through one provider-neutral diagnosis", async () => {
  await assert.rejects(
    probeRequiredRoles(
      planExecutionPipeline,
      { worker: CONFIGURATION },
      {
        codex: {
          async probe() {
            return capabilities({
              autonomousWrite: false,
              gitMetadataWriteBlocked: false,
              localCommit: false,
              workspaceWrite: false,
            });
          },
          async run() {},
        },
      },
      null,
      PROVIDER_REGISTRY,
    ),
    (error) => {
      assert.equal(error.code, "ERR_UNSUPPORTED_BACKEND");
      assert.equal(
        error.message,
        "Backend cannot safely run plan-execution.worker: codex " +
          "(unsupported: workspace-write, local-commit).",
      );
      assert.doesNotMatch(error.message, /payload|stderr|prompt|credential/u);
      return true;
    },
  );
});

test("adapter probing verifies the immutable receipt before provider work", async () => {
  const order = [];
  const run = {
    pipelineId: planExecutionPipeline.id,
    roles: { worker: CONFIGURATION },
    sessionLineage: { source: null },
  };
  const selected = roleAdapters(
    run,
    planExecutionPipeline,
    {
      codex: {
        async probe() {
          order.push("probe");
          return capabilities();
        },
        async run() {
          order.push("run");
          return { output: "done", sessionId: "session" };
        },
      },
    },
    PROVIDER_REGISTRY,
    async (_role, receipt) => {
      assert.deepEqual(receipt.supportedAccess, [
        "read-only",
        "workspace-write",
        "local-commit",
      ]);
      order.push("receipt");
    },
  );

  const proof = await selected.worker.probe();
  assert.deepEqual(
    new Set(proof.requiredCapabilities),
    new Set([
      "structuredOutput",
      "remoteWriteBlocked",
      "readOnly",
      "autonomousWrite",
      "gitMetadataWriteBlocked",
      "workspaceWrite",
      "localCommit",
    ]),
  );
  assert.equal(proof.policyReceipt.schemaVersion, 1);
  assert.ok(Object.isFrozen(proof));
  assert.ok(Object.isFrozen(proof.requiredCapabilities));
  await selected.worker.run({});
  assert.deepEqual(order, ["probe", "receipt", "run"]);

  let providerRuns = 0;
  const drifted = roleAdapters(
    run,
    planExecutionPipeline,
    {
      codex: {
        async probe() {
          return capabilities();
        },
        async run() {
          providerRuns += 1;
        },
      },
    },
    PROVIDER_REGISTRY,
    async () => {
      throw Object.assign(new Error("Provider policy changed."), {
        code: "ERR_PROVIDER_POLICY_CHANGED",
      });
    },
  );
  await assert.rejects(drifted.worker.probe(), {
    code: "ERR_PROVIDER_POLICY_CHANGED",
  });
  assert.equal(providerRuns, 0);
});

test("an abort race does not derive stop proof from raw cause fields", async () => {
  const controller = new AbortController();
  const stopReason = Object.assign(new Error("Operator stop requested."), {
    code: "ERR_OPERATOR_STOP_BEFORE_COMMIT",
  });
  controller.abort(stopReason);
  const adapter = failureAdapter(
    () => ({
      failureClass: "fixture_failure",
      checkpoint: "commit",
      outcome: "ambiguous",
      effect: "possible",
      retry: "transient",
    }),
    async () => {
      throw Object.assign(new Error("Unrelated rejection."), {
        cause: stopReason,
        code: "ERR_UNRELATED_REJECTION",
        effectStarted: false,
      });
    },
  );

  await assert.rejects(adapter.run({ signal: controller.signal }), (error) => {
    assert.equal(error.code, "ERR_UNRELATED_REJECTION");
    assert.equal(error.effectStarted, undefined);
    assert.equal(Object.hasOwn(error, "effectStarted"), false);
    assert.equal(error.ambiguous, true);
    assert.equal(error.recoverable, true);
    assert.equal(error.diagnosticClass, "fixture_failure");
    return true;
  });
});

test("runner stop proof follows normalized commit-executor evidence", async () => {
  const controller = new AbortController();
  const stopReason = Object.assign(new Error("Operator stop requested."), {
    code: "ERR_OPERATOR_STOP_BEFORE_COMMIT",
  });
  controller.abort(stopReason);
  const adapter = failureAdapter(
    () => ({
      failureClass: "fixture_failure",
      checkpoint: "commit",
      outcome: "ambiguous",
      effect: "possible",
      retry: "transient",
      commitExecutor: "not_started",
    }),
    async () => {
      throw Object.assign(new Error("Interrupted provider turn."), {
        cause: stopReason,
        code: "ERR_PROVIDER_INTERRUPTED",
        effectStarted: true,
      });
    },
  );

  await assert.rejects(adapter.run({ signal: controller.signal }), (error) => {
    assert.equal(error.code, "ERR_OPERATOR_STOP_BEFORE_COMMIT");
    assert.equal(error.effectStarted, false);
    assert.equal(error.ambiguous, false);
    assert.equal(error.recoverable, false);
    assert.equal(error.diagnosticClass, undefined);
    assert.deepEqual(error.failure, {
      failureClass: "adapter_failure",
      checkpoint: "commit",
      outcome: "rejected",
      effect: "none",
      retry: "terminal",
      commitExecutor: "not_started",
    });
    return true;
  });
});

test("matching stop codes without cause identity do not prove a stop", async () => {
  const controller = new AbortController();
  controller.abort(
    Object.assign(new Error("Operator stop requested."), {
      code: "ERR_OPERATOR_STOP_BEFORE_COMMIT",
    }),
  );
  const adapter = failureAdapter(
    () => ({
      failureClass: "fixture_failure",
      checkpoint: "commit",
      outcome: "ambiguous",
      effect: "possible",
      retry: "transient",
      commitExecutor: "not_started",
    }),
    async () => {
      throw Object.assign(new Error("Independent provider rejection."), {
        code: "ERR_OPERATOR_STOP_BEFORE_COMMIT",
      });
    },
  );

  await assert.rejects(adapter.run({ signal: controller.signal }), (error) => {
    assert.equal(error.code, "ERR_OPERATOR_STOP_BEFORE_COMMIT");
    assert.equal(error.effectStarted, false);
    assert.equal(error.ambiguous, true);
    assert.equal(error.recoverable, true);
    assert.equal(error.diagnosticClass, "fixture_failure");
    assert.equal(error.failure.effect, "possible");
    return true;
  });
});

test("Runner recreation rejects policy drift before provider execution", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-policy-resume-"));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  await writeFile(join(taskPath, "task.md"), "Inspect policy drift.\n");
  t.after(() => rm(root, { force: true, recursive: true }));

  const configuration = parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
  );
  const git = {
    async assertUnchanged() {},
    async inspectPath({ path }) {
      return { exists: false, path: resolve(path) };
    },
    async preflight({ allowedPaths, projectPath: requestedProjectPath }) {
      return {
        snapshot: {
          schemaVersion: 1,
          projectPath: resolve(requestedProjectPath),
          allowedPaths: [...allowedPaths],
        },
      };
    },
    async snapshot({ allowedPaths, projectPath: requestedProjectPath }) {
      return {
        schemaVersion: 1,
        projectPath: resolve(requestedProjectPath),
        allowedPaths: [...allowedPaths],
      };
    },
  };
  const services = {
    git,
    loadConfiguration: async () => configuration,
    trustedValidation: {
      async execute() {},
      async preflight() {},
    },
  };
  const original = createRunner({
    ...services,
    adapters: {
      codex: {
        async probe() {
          return capabilities();
        },
        async run() {
          assert.fail("Creation must not execute provider work.");
        },
      },
    },
    runStore: createRunStore({ stateRoot }),
  });
  const created = await original.create({
    pipelineId: "plan-authoring",
    projectPath,
    taskPath,
    settingOverrides: { mode: "lazy" },
  });
  const receipt = created.run.providerPolicies.planner;
  assert.match(receipt.fingerprint, /^[a-f0-9]{64}$/u);

  let providerRuns = 0;
  const recreated = createRunner({
    ...services,
    adapters: {
      codex: {
        async probe() {
          return capabilities({ version: "fixture-2" });
        },
        async run() {
          providerRuns += 1;
        },
      },
    },
    runStore: createRunStore({ stateRoot }),
  });
  await assert.rejects(
    recreated.resume({ runId: created.run.runId }),
    (error) => {
      assert.equal(error.code, "ERR_PROVIDER_POLICY_CHANGED");
      assert.doesNotMatch(error.message, /fixture-1|fixture-2/u);
      return true;
    },
  );
  assert.equal(providerRuns, 0);
  const persisted = await recreated.status(created.run.runId);
  assert.deepEqual(persisted.run.providerPolicies.planner, receipt);
});

test("CLI and MCP preserve the same bounded capability diagnosis", async () => {
  const failure = () =>
    new RunnerError(
      "Backend cannot safely run plan-authoring.planner: claude " +
        "(unsupported: remote-write-blocked, read-only).",
      { code: "ERR_UNSUPPORTED_BACKEND" },
    );
  let standardError = "";
  const exitCode = await main(
    ["run", "plan-authoring", "--project", "/project", "--task", "/task"],
    {
      runner: {
        async run() {
          throw failure();
        },
      },
      stdout: { write() {} },
      stderr: {
        write(value) {
          standardError += value;
        },
      },
    },
  );
  assert.equal(exitCode, 1);
  assert.equal(
    standardError,
    "Backend cannot safely run plan-authoring.planner: claude " +
      "(unsupported: remote-write-blocked, read-only).\n",
  );

  const action = {
    record: { status: "pending", context: { runId: "fixture-run" } },
    async complete() {},
    async release() {},
  };
  const control = createMcpControlPlane({
    issueReporter: {},
    runIdFactory: () => "fixture-run",
    runStore: {
      async beginAction() {
        return action;
      },
      async readAction() {
        return null;
      },
    },
    runner: {
      async create() {
        throw failure();
      },
      async status() {
        throw Object.assign(new Error("missing"), {
          code: "ERR_RUN_NOT_FOUND",
        });
      },
      async validateBoundary() {
        return { projectPath: "/project", taskPath: "/task" };
      },
    },
  });
  await assert.rejects(
    control.runStart({
      idempotencyKey: "capability-diagnosis",
      pipelineId: "plan-authoring",
      projectPath: "/project",
      proactiveClarification: false,
      taskPath: "/task",
    }),
    (error) => {
      assert.equal(error.code, "ERR_UNSUPPORTED_BACKEND");
      assert.equal(error.message, standardError.trim());
      return true;
    },
  );
});
