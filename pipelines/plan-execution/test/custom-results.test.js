import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { serializeCustomPlan } from "@agent-runner/custom-plan";
import { createRunStore } from "../../../src/state/index.js";
import { createWorkspaceService } from "../../../src/workspace/index.js";
import {
  createCustomResultCheckpoint,
  assertCustomOutputPreparation,
  customResultFingerprint,
  normalizeCustomResults,
} from "../src/custom-results.js";
import {
  migratePlanExecutionStateV33,
  createPlanExecutionState,
} from "../src/index.js";
import { normalizePipelineState } from "../src/workflow-contract.js";
import { validationEvidenceFingerprint } from "../src/validation-schedule.js";

const digest = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const result = (outputPaths = []) => ({
  analysis:
    "The supplied catalog identifies two sources and no unresolved gaps.",
  evidence: [
    {
      criterionId: "coverage",
      observations: ["Both catalog entries were compared."],
    },
  ],
  outputPaths,
});
const plan = (outputs) =>
  serializeCustomPlan({
    kind: "custom",
    criteria: [
      {
        id: "coverage",
        condition: "Identify all supplied sources and evidence gaps.",
      },
    ],
    inputs: ["catalog.md"],
    outputs,
    steps: [1, 2].map((number) => ({
      number,
      title: `Analyze sources ${number}`,
      work: "Compare the supplied catalog.",
      expectedResults: "A supported analysis.",
      criterionRefs: ["coverage"],
    })),
  });

function fixture({ mode = "independent", outputs = [] } = {}) {
  const projectPath = "/project";
  let run = {
    projectPath,
    revision: 1,
    activeTurn: null,
    executionProcess: null,
    executionResource: null,
    preparation: null,
    stopRequest: null,
    hashes: { task: "frozen" },
    workspace: {
      kind: "directory",
      bindingFingerprint: "a".repeat(64),
      protectedFingerprint: "b".repeat(64),
      policy: { workspacePath: projectPath, outputPaths: outputs },
    },
    pipelineState: {
      planKind: "custom",
      canonicalPlan: plan(outputs),
      customResults: null,
      currentStep: 1,
      settings: { mode },
      workflowState: "CONFIRM",
    },
  };
  let snapshot = { contentFingerprint: "c".repeat(64), entries: [] };
  let onTransition = () => {};
  const history = [];
  const runtime = {
    workspace: {
      async snapshot() {
        return structuredClone(snapshot);
      },
    },
    async transition(patch, { expectedRevision }) {
      assert.equal(expectedRevision, run.revision);
      if (run.stopRequest)
        throw Object.assign(new Error("Stopped"), {
          code: "ERR_STOP_RECONCILIATION_REQUIRED",
        });
      run = structuredClone({ ...run, ...patch, revision: run.revision + 1 });
      history.push(structuredClone(run));
      onTransition(run);
      return run;
    },
  };
  return {
    runtime,
    history,
    get run() {
      return run;
    },
    get snapshot() {
      return snapshot;
    },
    set snapshot(value) {
      snapshot = value;
    },
    set onTransition(value) {
      onTransition = value;
    },
    checkpoint: () => createCustomResultCheckpoint({ run, runtime }),
    async approve(value = result()) {
      await this.checkpoint().prepareOutputRoots([]);
      approve(
        run,
        customResultFingerprint(
          run.pipelineState.customResults.binding,
          snapshot,
          value,
          run.pipelineState.customResults.clarificationFingerprint,
        ),
      );
      return value;
    },
  };
}

function approve(run, fingerprint) {
  const finalizationResult = {
    status: "PASS",
    step: run.pipelineState.currentStep,
    fingerprint,
    checks: [],
  };
  Object.assign(run.pipelineState, {
    candidateReviewedFingerprint: fingerprint,
    candidateReviewResult: { status: "APPROVED", fingerprint },
    candidateConfirmationFingerprint: fingerprint,
    finalizationResult,
    finalizedFingerprint: fingerprint,
    reviewedFingerprint: fingerprint,
    cleanConfirmationFingerprint: fingerprint,
    reviewResult: {
      status: "APPROVED",
      fingerprint,
      validationChange: "UNCHANGED",
      validationTupleFingerprint:
        validationEvidenceFingerprint(finalizationResult),
    },
    findings: [],
    previousFindings: [],
    pendingDisputes: [],
    reviewReconsideration: [],
    findingOverrides: [],
  });
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} accepts analysis only after all gates and reconstructs without provider sessions or Git`, async () => {
    const f = fixture({ mode });
    await assert.rejects(f.checkpoint().accept(result()), {
      code: "ERR_CUSTOM_RESULT_GATE",
    });
    assert.equal(f.history.length, 0);
    const value = await f.approve();
    const record = await f.checkpoint().accept(value);
    assert.deepEqual(record.outputs, []);
    assert.equal(record.result.analysis, value.analysis);
    assert.equal(record.step, 1);
    assert.equal(record.previous, null);
    assert.equal(
      f.history.at(-2).pipelineState.customResults.pending.receipt,
      record.receipt,
    );
    assert.equal(
      (await f.checkpoint().reconcile()).accepted[0].receipt,
      record.receipt,
    );
    // The checkpoint alone never advances workflow progress or grants effects.
    assert.equal(f.run.pipelineState.currentStep, 1);
    assert.equal(f.run.pipelineState.workflowState, "CONFIRM");
    await assert.rejects(f.checkpoint().accept(value), {
      code: "ERR_CUSTOM_RESULT_GATE",
    });
    f.run.pipelineState.currentStep = 2;
    await f.approve();
    const second = await f.checkpoint().accept(value);
    assert.equal(second.previous, record.receipt);
    assert.equal(second.step, 2);
  });
}

test("changed criteria, frozen inputs, permissions and accepted output bytes cannot be adopted", async () => {
  const path = "/project/report.md";
  const f = fixture({ outputs: [path] });
  f.snapshot.entries = [{ path, kind: "file", hash: "report", mode: 0o600 }];
  await f.approve(result([path]));
  await f.checkpoint().accept(result([path]));
  for (const mutate of [
    (run) => {
      run.hashes.task = "changed";
    },
    (run) => {
      run.workspace.policy.outputPaths = [];
    },
    (run) => {
      run.pipelineState.canonicalPlan = run.pipelineState.canonicalPlan.replace(
        "Identify all",
        "List some",
      );
    },
  ]) {
    const changed = structuredClone(f.run);
    mutate(changed);
    assert.throws(() =>
      createCustomResultCheckpoint({ run: changed, runtime: f.runtime }),
    );
  }
  f.snapshot.entries[0].hash = "changed";
  await assert.rejects(f.checkpoint().verify(), {
    code: "ERR_CUSTOM_RESULT_DRIFT",
  });
  assert.equal(f.run.pipelineState.customResults.accepted.length, 1);
});

test("a clarification version cannot reuse active gates or replace earlier receipts", async () => {
  const f = fixture({ mode: "combined" });
  await f.approve();
  const first = await f.checkpoint().accept(result());
  f.run.pipelineState.currentStep = 2;
  await f.approve();
  f.run.hashes.executionClarifications = "authorized-answer";
  await assert.rejects(f.checkpoint().accept(result()), {
    code: "ERR_CUSTOM_RESULT_GATE",
  });
  assert.deepEqual(f.run.pipelineState.customResults.accepted, [first]);
  f.run.pipelineState.customResults = {
    ...f.run.pipelineState.customResults,
    clarificationFingerprint: digest(f.run.hashes.executionClarifications),
  };
  await assert.rejects(f.checkpoint().accept(result()), {
    code: "ERR_CUSTOM_RESULT_GATE",
  });
  await f.approve();
  const second = await f.checkpoint().accept(result());
  assert.notEqual(second.resultFingerprint, first.resultFingerprint);
  assert.equal(second.previous, first.receipt);
  assert.deepEqual(f.run.pipelineState.customResults.accepted[0], first);
});

test("accepted subtrees bind external link targets, intermediate links and linked directory contents", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "custom-result-links-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  for (const scenario of ["target", "intermediate", "directory"]) {
    const projectPath = join(root, scenario);
    const output = join(projectPath, "reports");
    const selected = join(output, "first");
    await fs.mkdir(selected, { recursive: true });
    await fs.writeFile(join(projectPath, "catalog.md"), "two entries\n");
    await fs.writeFile(join(output, "shared.md"), "accepted content\n");
    await fs.writeFile(join(output, "other.md"), "other content\n");
    await fs.mkdir(join(output, "shared"));
    await fs.symlink("../shared.md", join(output, "shared", "nested"));
    await fs.symlink("shared.md", join(output, "bridge"));
    await fs.symlink(
      scenario === "target"
        ? "../shared.md"
        : scenario === "intermediate"
          ? "../bridge"
          : "../shared",
      join(selected, "result"),
    );
    const workspace = createWorkspaceService();
    const inspection = await workspace.inspect({
      workspacePath: projectPath,
      stateRoot: join(root, "state"),
      inputPaths: ["catalog.md"],
      outputPaths: [output],
    });
    const f = fixture({ outputs: [output] });
    f.run.projectPath = projectPath;
    f.run.workspace.policy.workspacePath = projectPath;
    f.runtime.workspace.snapshot = () => workspace.snapshot({ inspection });
    f.snapshot = await f.runtime.workspace.snapshot();
    await f.approve(result([selected]));
    await f.checkpoint().accept(result([selected]));
    // Independent siblings remain available to later steps.
    await fs.writeFile(join(output, "other.md"), "later step content\n");
    await f.checkpoint().verify();
    if (scenario === "intermediate") {
      await fs.unlink(join(output, "bridge"));
      await fs.symlink("other.md", join(output, "bridge"));
    } else await fs.writeFile(join(output, "shared.md"), "changed content\n");
    await assert.rejects(f.checkpoint().verify(), {
      code: "ERR_CUSTOM_RESULT_DRIFT",
    });
    assert.equal(f.run.pipelineState.customResults.accepted.length, 1);
  }
});

test("closed bounded evidence rejects unknown criteria, output authority and malformed receipts", async () => {
  const f = fixture();
  await f.approve();
  for (const invalid of [
    { ...result(), status: "COMPLETED" },
    { ...result(), analysis: "x".repeat(32769) },
    { ...result(), evidence: [] },
    {
      ...result(),
      evidence: [{ criterionId: "invented", observations: ["claim"] }],
    },
    result(["/elsewhere/report.md"]),
  ])
    await assert.rejects(f.checkpoint().accept(invalid), {
      code: "ERR_INVALID_CUSTOM_RESULT",
    });
  await f.checkpoint().accept(result());
  const invalid = structuredClone(f.run.pipelineState.customResults);
  invalid.accepted[0].result.analysis = "unsupported replacement";
  assert.throws(
    () => normalizeCustomResults(invalid, f.run.pipelineState.canonicalPlan),
    { code: "ERR_INVALID_CUSTOM_RESULT" },
  );
});

test("interrupted acceptance reconciles its exact record and retains drift or stop evidence", async () => {
  const f = fixture();
  await f.approve();
  f.onTransition = (run) => {
    if (run.pipelineState.customResults.pending)
      throw new Error("Lost owner after durable intent");
  };
  await assert.rejects(f.checkpoint().accept(result()), /Lost owner/);
  const pending = structuredClone(f.run.pipelineState.customResults.pending);
  f.onTransition = () => {};
  f.run.stopRequest = { reconciledRevision: null };
  await assert.rejects(f.checkpoint().reconcile(), {
    code: "ERR_CUSTOM_RESULT_SUSPENDED",
  });
  f.run.stopRequest = null;
  f.snapshot.contentFingerprint = "d".repeat(64);
  await assert.rejects(f.checkpoint().reconcile(), {
    code: "ERR_CUSTOM_RESULT_DRIFT",
  });
  assert.deepEqual(f.run.pipelineState.customResults.pending, pending);
  f.snapshot.contentFingerprint = pending.contentFingerprint;
  f.run.hashes.executionClarifications = "changed";
  await assert.rejects(f.checkpoint().reconcile(), {
    code: "ERR_CUSTOM_RESULT_GATE",
  });
  assert.deepEqual(f.run.pipelineState.customResults.pending, pending);
  delete f.run.hashes.executionClarifications;
  const accepted = await f.checkpoint().reconcile();
  assert.deepEqual(accepted.accepted, [pending]);
  assert.equal(accepted.pending, null);
});

test("a raced stop cannot settle pending acceptance or permit another result", async () => {
  const f = fixture();
  await f.approve();
  f.onTransition = (run) => {
    if (run.pipelineState.customResults.pending)
      run.stopRequest = { reconciledRevision: null };
  };
  await assert.rejects(f.checkpoint().accept(result()), {
    code: "ERR_CUSTOM_RESULT_SUSPENDED",
  });
  assert.equal(f.run.pipelineState.customResults.accepted.length, 0);
  assert.ok(f.run.pipelineState.customResults.pending);
});

test("lost output creation proof preserves the journaled intent without another creation", async () => {
  const path = "/project/reports";
  const f = fixture({ outputs: [path] });
  const parent = {
    path: "/project",
    exists: true,
    kind: "directory",
    ancestors: [],
    identity: { device: "1", inode: "2", mode: "16832" },
  };
  const intent = {
    path,
    before: {
      path,
      exists: false,
      kind: "missing",
      ancestors: [],
      identity: null,
    },
    parent,
    storage: {
      ...parent,
      path: "/state",
    },
    staging: {
      path: "/state/output-00000000-0000-4000-8000-000000000000",
      exists: false,
      kind: "missing",
      ancestors: [],
      identity: null,
    },
  };
  let creations = 0;
  f.runtime.workspace.inspectOutputDirectory = async () => intent;
  f.runtime.workspace.prepareOutputDirectory = async () => {
    if (creations !== 0)
      throw Object.assign(new Error("Unproved directory"), {
        code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
      });
    creations += 1;
    throw new Error("Lost owner after creation, before identity publication");
  };
  await assert.rejects(f.checkpoint().prepareOutputRoots([path]), /Lost owner/);
  assert.deepEqual(f.run.pipelineState.customResults.preparation, {
    intent,
    prepared: null,
  });
  assert.doesNotThrow(() => assertCustomOutputPreparation(f.run, intent));
  for (const patch of [
    { stopRequest: { reconciledRevision: null } },
    { activeTurn: { role: "worker", phase: "implement" } },
    { executionProcess: {} },
    { executionResource: {} },
    { preparation: {} },
    {
      pipelineState: {
        ...f.run.pipelineState,
        workflowState: "WAITING_FOR_USER",
      },
    },
  ])
    assert.throws(
      () => assertCustomOutputPreparation({ ...f.run, ...patch }, intent),
      { code: "ERR_CUSTOM_RESULT_SUSPENDED" },
    );
  const malformed = structuredClone(f.run.pipelineState.customResults);
  malformed.preparation.intent.before = null;
  assert.throws(
    () => normalizeCustomResults(malformed, f.run.pipelineState.canonicalPlan),
    { code: "ERR_INVALID_CUSTOM_RESULT" },
  );
  await assert.rejects(f.checkpoint().reconcile(), {
    code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
  });
  assert.equal(creations, 1);
  assert.deepEqual(f.run.pipelineState.customResults.preparation, {
    intent,
    prepared: null,
  });
});

test("changing analysis or removing mode-required confirmation invalidates result acceptance", async () => {
  for (const mode of ["independent", "lazy", "combined"]) {
    const f = fixture({ mode });
    await f.approve();
    await assert.rejects(
      f
        .checkpoint()
        .accept({ ...result(), analysis: "An unreviewed assertion." }),
      { code: "ERR_CUSTOM_RESULT_GATE" },
    );
    f.run.pipelineState.reviewResult.validationTupleFingerprint = "d".repeat(
      64,
    );
    await assert.rejects(f.checkpoint().accept(result()), {
      code: "ERR_CUSTOM_RESULT_GATE",
    });
    await f.approve();
    if (mode === "independent") f.run.pipelineState.reviewedFingerprint = null;
    else f.run.pipelineState.candidateConfirmationFingerprint = null;
    await assert.rejects(f.checkpoint().accept(result()), {
      code: "ERR_CUSTOM_RESULT_GATE",
    });
    assert.equal(f.run.pipelineState.customResults.accepted.length, 0);
    assert.equal(f.run.pipelineState.customResults.pending, null);
  }
});

test("version 33 migration creates no custom acceptance or output authority", () => {
  const { customResults: _results, ...legacy } = createPlanExecutionState();
  const migrated = migratePlanExecutionStateV33({ pipelineState: legacy });
  assert.deepEqual(migrated, { ...legacy, customResults: null });
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.throws(
    () => normalizePipelineState({ ...migrated, customResults: {} }),
    { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
  );
});

for (const interruption of ["allocation", "creation", "identity"]) {
  test(`leased journal recovery preserves output preparation after ${interruption} interruption without Git`, async (t) => {
    const root = await fs.mkdtemp(join(tmpdir(), "custom-checkpoint-"));
    let lease;
    t.after(async () => {
      await lease?.release();
      await fs.rm(root, { recursive: true, force: true });
    });
    const projectPath = join(root, "project");
    const taskPath = join(root, "task");
    const stateRoot = join(root, "state");
    await fs.mkdir(projectPath);
    await fs.mkdir(taskPath);
    await fs.writeFile(join(projectPath, "catalog.md"), "two entries\n");
    await fs.writeFile(join(projectPath, "unrelated.md"), "preserve\n");
    const path = join(projectPath, "reports");
    let interrupt = true;
    const fileSystem = {
      ...fs,
      async mkdir(destination, options) {
        const created = await fs.mkdir(destination, options);
        if (
          interrupt &&
          interruption === "allocation" &&
          /\/output-[a-f0-9-]+$/u.test(destination)
        ) {
          interrupt = false;
          throw new Error("Interrupted before prepared identity publication");
        }
        return created;
      },
      async rename(source, destination) {
        await fs.rename(source, destination);
        if (
          interrupt &&
          interruption === "creation" &&
          destination.endsWith("/reports")
        ) {
          interrupt = false;
          throw new Error("Interrupted before prepared identity publication");
        }
      },
    };
    const workspace = createWorkspaceService({ fileSystem });
    const inspection = await workspace.inspect({
      workspacePath: projectPath,
      taskPath,
      stateRoot,
      inputPaths: ["catalog.md"],
      outputPaths: [path],
    });
    const store = createRunStore({ stateRoot });
    const f = fixture({ outputs: [path] });
    const created = await store.createRun({
      pipelineId: "plan-execution",
      pipelineStateVersion: 35,
      projectPath,
      taskPath,
      roles: { worker: { backend: "codex", model: null } },
      pipelineState: f.run.pipelineState,
    });
    lease = created.lease;
    let run = {
      ...created.state,
      workspace: {
        kind: "directory",
        policy: { workspacePath: projectPath, outputPaths: [path] },
        bindingFingerprint: "a".repeat(64),
        protectedFingerprint: "b".repeat(64),
      },
    };
    const before = await workspace.snapshot({ inspection });
    const runtime = {
      workspace: {
        snapshot: () => workspace.snapshot({ inspection }),
        inspectPath: (request) => workspace.inspectPath(request),
        inspectOutputDirectory: (path) =>
          workspace.inspectOutputDirectory({ inspection, path }),
        prepareOutputDirectory: async (intent) => {
          assertCustomOutputPreparation(run, intent);
          assert.throws(
            () =>
              assertCustomOutputPreparation(run, {
                ...intent,
                path: projectPath,
              }),
            { code: "ERR_INVALID_CUSTOM_RESULT" },
          );
          const prepared = await workspace.prepareOutputDirectory({
            inspection,
            intent,
            publishDirectory: async ({
              sourceParent,
              sourceName,
              destinationParent,
              destinationName,
            }) => {
              await fileSystem.rename(
                `/proc/self/fd/${sourceParent}/${sourceName}`,
                `/proc/self/fd/${destinationParent}/${destinationName}`,
              );
            },
          });
          return { prepared, run };
        },
      },
      async transition(patch, options) {
        run = {
          ...(await store.transitionRun(lease, patch, options)),
          workspace: run.workspace,
        };
        if (
          interrupt &&
          interruption === "identity" &&
          run.pipelineState.customResults.preparation?.prepared
        ) {
          interrupt = false;
          throw new Error("Interrupted after prepared identity publication");
        }
        return run;
      },
    };
    const checkpoint = () => createCustomResultCheckpoint({ run, runtime });
    await assert.rejects(checkpoint().prepareOutputRoots([path]), (error) =>
      /Interrupted/u.test(error.cause?.message ?? error.message),
    );
    const pending = run.pipelineState.customResults.preparation;
    const prepared = run.pipelineState.customResults.preparation.prepared;
    await lease.release();
    lease = await store.acquireRunLease(created.state.runId);
    run = {
      ...(await store.loadRun(created.state.runId)),
      workspace: run.workspace,
    };
    if (interruption === "allocation") {
      assert.equal(pending.prepared, null);
      assert.equal(
        (await fs.stat(pending.intent.staging.path)).isDirectory(),
        true,
      );
      await assert.rejects(fs.stat(path), { code: "ENOENT" });
      await assert.rejects(checkpoint().reconcile(), {
        code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
      });
      assert.deepEqual(run.pipelineState.customResults.preparation, pending);
      assert.deepEqual(run.pipelineState.customResults.accepted, []);
      workspace.assertUnchanged({
        before,
        after: await workspace.snapshot({ inspection }),
      });
      return;
    }
    if (interruption === "creation") {
      assert.equal(pending.prepared, null);
      assert.equal(pending.intent.before.exists, false);
      assert.deepEqual((await fs.readdir(projectPath)).sort(), [
        "catalog.md",
        "reports",
        "unrelated.md",
      ]);
      const identity = (await fs.stat(path, { bigint: true })).ino;
      workspace.assertUnchanged({
        before,
        after: await workspace.snapshot({ inspection }),
        allowOutputs: true,
      });
      await assert.rejects(checkpoint().reconcile(), {
        code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
      });
      assert.equal((await fs.stat(path, { bigint: true })).ino, identity);
      assert.deepEqual(run.pipelineState.customResults.preparation, pending);
      assert.deepEqual(run.pipelineState.customResults.accepted, []);
      return;
    }
    await checkpoint().reconcile();
    assert.deepEqual(run.pipelineState.customResults.preparedRoots, [prepared]);
    const output = join(path, "summary.md");
    await fs.writeFile(output, "two supported entries\n");
    const value = result([output]);
    run = structuredClone(run);
    approve(
      run,
      customResultFingerprint(
        run.pipelineState.customResults.binding,
        await runtime.workspace.snapshot(),
        value,
      ),
    );
    // Gate evidence is also persisted by the normal pipeline before acceptance.
    run = await runtime.transition(
      { pipelineState: run.pipelineState },
      { expectedRevision: run.revision },
    );
    const accepted = await checkpoint().accept(value);
    assert.equal(accepted.outputs[0].path, output);
    assert.equal(accepted.outputs[0].fingerprint.length, 64);
    assert.equal(
      await fs.readFile(join(projectPath, "unrelated.md"), "utf8"),
      "preserve\n",
    );
    assert.equal(
      await fs.stat(join(projectPath, ".git")).catch((error) => error.code),
      "ENOENT",
    );
    assert.equal(
      digest(
        (await store.loadRun(created.state.runId)).pipelineState.customResults,
      ),
      digest(run.pipelineState.customResults),
    );
  });
}
