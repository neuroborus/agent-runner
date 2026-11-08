import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { auditPipeline } from "@agent-runner/audit";

import {
  READY,
  complete,
  decision,
  finding,
  recheck,
} from "../pipelines/audit/test/support/index.js";
import { CodexAdapterError } from "../src/agents/index.js";
import { parseRunnerConfiguration } from "../src/config/index.js";
import { main } from "../src/index.js";
import { createMcpControlPlane } from "../src/mcp/index.js";
import { createRunner } from "../src/runner/index.js";
import { createRunStore } from "../src/state/index.js";
import { availabilityFailure } from "./support/availability.js";
import { executeFile } from "./support/index.js";
import { outputExhaustion } from "./support/output-exhaustion.js";

const evidence = (request) => JSON.parse(request.prompt.split("\n").at(-1));
const interrupted = () =>
  Object.assign(new Error("Controlled owner interruption"), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
const batch = (candidates) => (request) =>
  complete({
    snapshotFingerprint: evidence(request).snapshotFingerprint,
    candidates,
  });
const clean = batch([]);
const confirmed = (run) =>
  auditPipeline.projections.status(run).auditReport.confirmedFindings;

// Real journals, leases, workspace snapshots and artifact writes; only provider
// responses and scheduling are injected. Every reopen discards store caches.
async function fixture(t, mode, sourceScope = "directory") {
  const root = await mkdtemp(join(tmpdir(), "audit-recovery-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  await writeFile(join(projectPath, "source.txt"), "Original source\n");
  await writeFile(join(taskPath, "task.md"), "Audit the complete workspace.\n");
  if (sourceScope === "git")
    await executeFile("git", ["init", "--quiet", projectPath]);
  const calls = [];
  const outputs = [];
  const probes = [];
  let child = 0;
  const adapter = {
    async probe(request) {
      probes.push(request);
      return {
        version: "fixture",
        readOnly: true,
        structuredOutput: true,
        declaredWorkspace: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: true,
        policyReceipt: {
          schemaVersion: 1,
          fingerprint: createHash("sha256")
            .update(JSON.stringify(request))
            .digest("hex"),
          supportedAccess: ["read-only"],
        },
      };
    },
    async run(request) {
      calls.push(request);
      assert.equal(request.access, "read-only");
      assert.ok(outputs.length, "Unexpected provider invocation");
      const next = outputs.shift();
      const structured =
        typeof next === "function" ? await next(request) : next;
      if (structured instanceof Error) throw structured;
      return {
        structured,
        sessionId:
          request.session?.mode === "continue"
            ? request.session.id
            : `child-${++child}`,
      };
    },
  };
  const configuration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      pipelines: { audit: { mode, sourceScope } },
    }),
  );
  function open(options = {}) {
    const store = options.runStore ?? createRunStore({ stateRoot });
    const runner = createRunner({
      adapters: { codex: adapter },
      runStore: store,
      loadConfiguration: async () => configuration,
      ...options,
    });
    return { store, runner };
  }
  return {
    root,
    stateRoot,
    taskPath,
    projectPath,
    calls,
    outputs,
    probes,
    open,
    input: {
      pipelineId: "audit",
      projectPath,
      taskPath,
      sourceSession: { backend: "codex", id: "synthetic-source" },
    },
    report: () => readFile(join(taskPath, "audit.md"), "utf8"),
  };
}

function frozen(run) {
  const state = run.pipelineState;
  return {
    hashes: run.hashes,
    roles: run.roles,
    workspace: run.workspace,
    configuration: run.projectConfigurationProtection,
    counters: run.counters,
    inputs: state.inputs,
    inputsFingerprint: state.inputsFingerprint,
    settings: state.settings,
    baseline: state.repositoryBaseline,
  };
}

test("combined pending revisions survive exhaustion, legacy cold migration and interruption before replacement launch", async (t) => {
  const f = await fixture(t, "combined");
  const dismissed = finding({ id: "dismissed", causeId: "guarded-caller" });
  const uncertain = finding({ id: "uncertain", causeId: "unknown-caller" });
  const dispositions = [
    decision(finding().id),
    decision(dismissed.id, {
      kind: "reject",
      rationale: "The caller checks the input",
    }),
    decision(uncertain.id, {
      kind: "hypothesis",
      hypothesis: {
        id: uncertain.id,
        title: uncertain.title,
        evidence: [],
        uncertainty: "Caller input is unknown",
      },
    }),
  ];
  const additional = finding({
    id: "unchecked-size",
    causeId: "size-boundary",
  });
  f.outputs.push(
    READY,
    batch([finding(), dismissed, uncertain]),
    (request) => recheck(request, { decisions: dispositions }),
    recheck,
    recheck,
    batch([
      finding({ impact: "Another caller aborts before allocation" }),
      additional,
    ]),
    (request) => recheck(request, { decisions: [] }),
  );
  const initial = f.open();
  const invalid = (await initial.runner.run(f.input)).run;
  assert.equal(invalid.pause.reason, "invalid_recheck");
  assert.equal(
    confirmed(invalid),
    0,
    "Old acceptance cannot approve a revision",
  );
  assert.equal(invalid.pipelineState.acceptedBatches.length, 1);
  f.outputs.push(outputExhaustion());
  const waiting = (
    await f.open().runner.resume({ runId: invalid.runId, action: null })
  ).run;
  assert.equal(waiting.pause.reason, "output_exhausted");
  assert.equal(confirmed(waiting), 0);
  assert.deepEqual(
    waiting.pipelineState.correctionFeedback,
    invalid.pipelineState.correctionFeedback,
  );
  const report = await f.report();
  assert.match(report, /## Confirmed findings\n\nNone\.\n/u);

  // Import an exercised legacy snapshot through the store's creation boundary,
  // preserving its evidence rather than rewriting canonical journal bytes.
  const legacyStore = f.open().store;
  const { outputRecovery, ...legacyState } = waiting.pipelineState;
  const legacy = await legacyStore.createRun({
    ...Object.fromEntries(
      [
        "pipelineId",
        "projectPath",
        "taskPath",
        "roles",
        "workspace",
        "projectConfigurationProtection",
        "hashes",
        "pause",
        "counters",
        "providerPolicies",
        "availabilityPolicy",
        "providerInactivityTimeoutMs",
      ].map((key) => [key, waiting[key]]),
    ),
    pipelineStateVersion: 7,
    pipelineState: legacyState,
    sourceSession: waiting.sessionLineage.source,
    sourceProfile: waiting.sessionLineage.sourceProfile,
    childSessions: waiting.sessionLineage.children,
  });
  await legacy.lease.release();
  const legacyRunId = legacy.state.runId;
  const coldStore = f.open().store;
  let stopped = false;
  const pausedClear = f.open({
    runStore: {
      ...coldStore,
      async transitionRun(...args) {
        const next = await coldStore.transitionRun(...args);
        if (
          !stopped &&
          next.pause === null &&
          next.pipelineState.outputRecovery !== null
        ) {
          stopped = true;
          throw interrupted();
        }
        return next;
      },
    },
  });
  const turns = f.calls.length;
  await assert.rejects(
    pausedClear.runner.resume({ runId: legacyRunId, action: null }),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );
  assert.equal(stopped, true);
  assert.equal(f.calls.length, turns);
  const replacement = f.open();
  const saved = await replacement.store.loadRun(legacyRunId);
  assert.equal(saved.pipelineStateVersion, 8);
  assert.equal(saved.pause, null);
  assert.deepEqual(saved.pipelineState.outputRecovery, outputRecovery);
  assert.deepEqual(frozen(saved), frozen(waiting));
  for (const field of [
    "history",
    "recheckHistory",
    "pendingBatch",
    "ledger",
    "acceptedBatches",
    "publication",
    "correctionFeedback",
    "sourceForkContexts",
  ])
    assert.deepEqual(saved.pipelineState[field], waiting.pipelineState[field]);
  assert.equal(await f.report(), report);
  const reservation = saved.pipelineState.recheckHistory.at(-1);
  f.outputs.push(
    async (request) => {
      assert.equal(request.session, undefined);
      const current = await replacement.store.loadRun(saved.runId);
      assert.equal(confirmed(current), 0);
      assert.equal(current.activeTurn.role, waiting.pause.role);
      assert.deepEqual(
        current.pipelineState.sourceForkContexts,
        saved.pipelineState.sourceForkContexts,
      );
      assert.deepEqual(
        current.pipelineState.recheckHistory.at(-1),
        reservation,
      );
      const context = evidence(request);
      assert.deepEqual(context.batch, saved.pipelineState.pendingBatch);
      assert.deepEqual(context.accumulatedFindings, saved.pipelineState.ledger);
      assert.deepEqual(
        context.correctionFeedback,
        saved.pipelineState.correctionFeedback,
      );
      assert.deepEqual(
        context.outputRecovery.acceptedBatches[0].dispositions,
        dispositions,
      );
      return recheck(request);
    },
    (request) => recheck(request, { decisions: [decision(finding().id)] }),
  );
  const missing = (
    await replacement.runner.resume({ runId: saved.runId, action: null })
  ).run;
  assert.equal(missing.pause.reason, "invalid_recheck");
  assert.equal(confirmed(missing), 0);
  assert.match(await f.report(), /## Confirmed findings\n\nNone\.\n/u);
  assert.deepEqual(
    missing.pipelineState.acceptedBatches,
    saved.pipelineState.acceptedBatches,
  );
  const finish = f.open();
  f.outputs.push((request) => recheck(request, { status: "INCOMPLETE" }));
  const incomplete = (
    await finish.runner.resume({ runId: saved.runId, action: null })
  ).run;
  assert.equal(incomplete.pause.reason, "recheck_incomplete");
  assert.equal(confirmed(incomplete), 0);
  assert.match(await f.report(), /## Confirmed findings\n\nNone\.\n/u);
  f.outputs.push(
    recheck,
    async (request) => {
      assert.equal(confirmed(await finish.store.loadRun(saved.runId)), 0);
      return recheck(request);
    },
    clean,
    clean,
  );
  const done = (
    await finish.runner.resume({ runId: saved.runId, action: null })
  ).run;
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(confirmed(done), 2);
  assert.deepEqual(frozen(done), frozen(saved));
  assert.equal(done.pipelineState.pendingBatch, null);
  assert.equal(done.pipelineState.acceptedBatches.length, 2);
  assert.deepEqual(
    done.pipelineState.acceptedBatches[0],
    saved.pipelineState.acceptedBatches[0],
  );
  assert.deepEqual(
    done.pipelineState.acceptedBatches[1].batch.entries,
    saved.pipelineState.pendingBatch.entries,
  );
  const finalReport = await f.report();
  assert.match(finalReport, /2 confirmed findings\./u);
  const confirmedSection = finalReport
    .split("## Confirmed findings\n")[1]
    .split("## Pending candidates")[0];
  assert.match(confirmedSection, /negative-count/u);
  assert.match(confirmedSection, /unchecked-size/u);
  assert.doesNotMatch(confirmedSection, /dismissed|uncertain/u);
  assert.match(finalReport, /Caller input is unknown/u);
  assert.equal(done.pipelineState.history.length, 4);
  assert.deepEqual(
    done.pipelineState.history.slice(0, 3).map(({ contextKey }) => contextKey),
    Array(3).fill(saved.pipelineState.history[0].contextKey),
  );
  assert.notEqual(
    done.pipelineState.history[3].contextKey,
    saved.pipelineState.history[0].contextKey,
  );
  assert.deepEqual(
    done.pipelineState.recheckHistory.map(({ outcome }) => outcome),
    [
      "corrected",
      "clean",
      "clean",
      "invalid",
      "clean",
      "invalid",
      "incomplete",
      "clean",
      "clean",
    ],
  );
  const history = await finish.store.loadRunHistory(saved.runId);
  assert.ok(
    history.events.some(({ state }) => state.pipelineStateVersion === 7),
  );
  assert.ok(
    history.events.some(
      ({ state, activity }) =>
        state.pipelineStateVersion === 8 && activity?.kind === "migrated",
    ),
  );
});

test("lazy acknowledged replacement survives cold response loss, availability, inactivity and repeated exhaustion", async (t) => {
  const f = await fixture(t, "lazy", "git");
  const gitBefore = await executeFile("git", [
    "-C",
    f.projectPath,
    "status",
    "--porcelain",
  ]);
  f.outputs.push(READY, outputExhaustion());
  const waiting = (await f.open().runner.run(f.input)).run;
  const reservation = waiting.pipelineState.history[0];
  const report = await f.report();
  const firstReplacement = f.open();
  f.outputs.push(async (request) => {
    assert.equal(request.session, undefined);
    await request.onSessionCreated("acknowledged-replacement");
    throw interrupted();
  });
  await assert.rejects(
    firstReplacement.runner.resume({ runId: waiting.runId, action: null }),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );
  const cold = f.open();
  const acknowledged = await cold.store.loadRun(waiting.runId);
  assert.equal(
    acknowledged.sessionLineage.children.at(-1).sessionId,
    "acknowledged-replacement",
  );
  assert.deepEqual(
    acknowledged.pipelineState.outputRecovery,
    waiting.pipelineState.outputRecovery,
  );
  assert.deepEqual(
    acknowledged.pipelineState.history,
    waiting.pipelineState.history,
  );
  assert.deepEqual(
    acknowledged.pipelineState.publication,
    waiting.pipelineState.publication,
  );
  assert.equal(await f.report(), report);
  let fire;
  let now = Date.now();
  const schedules = [];
  const resumed = f.open({
    inactivityTimers: {
      setTimeout(callback) {
        fire = callback;
        return callback;
      },
      clearTimeout(handle) {
        if (fire === handle) fire = undefined;
      },
    },
    availabilityClock: () => now,
    availabilityWait: async (delay) => {
      const current = await cold.store.loadRun(waiting.runId);
      now = Math.max(
        now + delay,
        Date.parse(current.availabilityRetry.nextRetryAt),
      );
      schedules.push(current.availabilityRetry);
      assert.deepEqual(current.pipelineState.history[0], reservation);
      assert.deepEqual(
        current.pipelineState.outputRecovery,
        waiting.pipelineState.outputRecovery,
      );
    },
  });
  f.outputs.push(
    (request) => {
      assert.deepEqual(request.session, {
        mode: "continue",
        id: "acknowledged-replacement",
      });
      throw availabilityFailure();
    },
    (request) =>
      new Promise((resolve, reject) => {
        request.signal.addEventListener(
          "abort",
          () => reject(request.signal.reason),
          { once: true },
        );
        assert.equal(typeof fire, "function");
        fire();
      }),
    async (request) => {
      assert.equal(request.session, undefined);
      await request.onSessionCreated("exhausted-reconstruction");
      throw outputExhaustion();
    },
  );
  const repeated = (
    await resumed.runner.resume({ runId: waiting.runId, action: null })
  ).run;
  assert.equal(repeated.pause.reason, "output_exhausted");
  assert.equal(schedules.length, 1);
  assert.equal(schedules[0].attempt, 1);
  assert.equal(repeated.inactivityRecovery.attempt, 2);
  assert.equal(
    repeated.pipelineState.outputRecovery.retiredChildren,
    repeated.sessionLineage.children.length,
  );
  assert.deepEqual(
    repeated.pipelineState.history,
    waiting.pipelineState.history,
  );
  assert.deepEqual(frozen(repeated), frozen(waiting));
  const final = f.open();
  f.outputs.push((request) => {
    assert.equal(request.session, undefined);
    return clean(request);
  });
  const done = (
    await final.runner.resume({ runId: waiting.runId, action: null })
  ).run;
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(done.pipelineState.outputRecovery, null);
  assert.equal(done.inactivityRecovery, null);
  assert.equal(done.availabilityRetry, null);
  assert.equal(done.pipelineState.history.length, 1);
  assert.equal(done.pipelineState.sourceForkConsumed, true);
  assert.equal(
    f.calls.filter(({ session }) => session?.mode === "fork").length,
    1,
  );
  assert.deepEqual(Object.keys(done.roles), ["auditor"]);
  assert.ok(
    done.sessionLineage.children.every(({ role }) => role === "auditor"),
  );
  assert.equal(
    (await executeFile("git", ["-C", f.projectPath, "status", "--porcelain"]))
      .stdout,
    gitBefore.stdout,
  );
  assert.deepEqual(frozen(done), frozen(waiting));
});

test("independent verification recovery projects identical redacted CLI and MCP status/wait and keeps terminal completion inert", async (t) => {
  const f = await fixture(t, "independent");
  f.outputs.push(READY, batch([finding()]), async (request) => {
    await request.onSessionCreated("retired-reviewer");
    throw outputExhaustion();
  });
  const waiting = (await f.open().runner.run(f.input)).run;
  const cold = f.open();
  const control = createMcpControlPlane({
    runner: cold.runner,
    runStore: cold.store,
  });
  const status = await control.runStatus({ runId: waiting.runId });
  const waited = await control.runWait({
    runId: waiting.runId,
    cursor: 0,
    timeoutMs: 0,
  });
  assert.deepEqual(waited.pause, status.pause);
  assert.deepEqual(status.pause, auditPipeline.projections.pause(waiting));
  assert.deepEqual(status.pause.nextActions, [
    { type: "resume", action: null },
  ]);
  assert.match(status.pause.explanation, /fresh native context/u);
  assert.equal(status.auditReport.confirmedFindings, 0);
  let output = "";
  assert.equal(
    await main(["status", "--run", waiting.runId], {
      runner: cold.runner,
      stdout: {
        write(value) {
          output += value;
        },
      },
      stderr: { write: (value) => assert.fail(value) },
    }),
    0,
  );
  assert.ok(output.includes(status.pause.explanation));
  assert.doesNotMatch(
    JSON.stringify({ status, waited, output }),
    /synthetic-source|retired-reviewer|contextKey|retiredChildren/u,
  );
  const turns = f.calls.length;
  await assert.rejects(
    cold.runner.resume({ runId: waiting.runId, action: "retry" }),
  );
  assert.equal(f.calls.length, turns);
  f.outputs.push(async (request) => {
    assert.equal(request.session, undefined);
    const current = await cold.store.loadRun(waiting.runId);
    assert.equal(current.activeTurn.role, "reviewer");
    assert.deepEqual(
      current.pipelineState.history,
      waiting.pipelineState.history,
    );
    assert.deepEqual(
      current.pipelineState.recheckHistory,
      waiting.pipelineState.recheckHistory,
    );
    assert.equal(confirmed(current), 0);
    assert.deepEqual(
      evidence(request).batch,
      waiting.pipelineState.pendingBatch,
    );
    return recheck(request);
  }, clean);
  const done = (
    await cold.runner.resume({ runId: waiting.runId, action: null })
  ).run;
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(confirmed(done), 1);
  assert.deepEqual(
    done.sessionLineage.children.map(({ role }) => role),
    ["auditor", "auditor", "reviewer", "reviewer", "auditor"],
  );
  assert.equal(f.calls[3].session, undefined);
  assert.equal(f.calls[4].session.mode, "fork");
  assert.equal(done.pipelineState.recheckHistory.length, 1);
  const terminalReport = await f.report();
  const terminalTurns = f.calls.length;
  const resumed = (
    await f.open().runner.resume({ runId: waiting.runId, action: null })
  ).run;
  assert.deepEqual(resumed, done);
  assert.equal(f.calls.length, terminalTurns);
  assert.equal(await f.report(), terminalReport);
});

test("failure and cancellation after exhaustion stay inert across cold resume", async (t) => {
  for (const terminal of ["FAILED", "CANCELED"]) {
    await t.test(terminal, async () => {
      const f = await fixture(t, "independent");
      f.outputs.push(READY, outputExhaustion());
      const waiting = (await f.open().runner.run(f.input)).run;
      const cold = f.open();
      if (terminal === "FAILED") {
        f.outputs.push(
          new CodexAdapterError("PRIVATE_PROVIDER_MESSAGE", {
            code: "ERR_CODEX_ISOLATION",
            diagnosticClass: "isolation_workspace_policy",
          }),
        );
        await assert.rejects(
          cold.runner.resume({ runId: waiting.runId, action: null }),
          { code: "ERR_CODEX_ISOLATION" },
        );
      } else {
        await cold.runner.requestOperatorStop({
          runId: waiting.runId,
          kind: "cancel_requested",
          expectedRevision: waiting.revision,
          idempotencyKey: "cancel-exhausted-audit",
        });
        await cold.runner.resume({ runId: waiting.runId, action: null });
      }
      const saved = await cold.store.loadRun(waiting.runId);
      assert.equal(saved.pipelineState.workflowState, terminal);
      assert.equal(confirmed(saved), 0);
      assert.equal(saved.pipelineState.history.length, 1);
      const report = await f.report();
      const turns = f.calls.length;
      const probes = f.probes.length;
      const replacement = f.open();
      const control = createMcpControlPlane({
        runner: replacement.runner,
        runStore: replacement.store,
      });
      const status = await control.runStatus({ runId: waiting.runId });
      assert.deepEqual(status.pause.nextActions, []);
      if (terminal === "CANCELED")
        await assert.rejects(
          replacement.runner.resume({ runId: waiting.runId, action: null }),
          { code: "ERR_RUN_CANCELED" },
        );
      else
        await replacement.runner.resume({ runId: waiting.runId, action: null });
      const resumed = await replacement.store.loadRun(waiting.runId);
      assert.deepEqual(resumed, saved);
      assert.deepEqual(frozen(resumed), frozen(waiting));
      assert.equal(f.calls.length, turns);
      assert.equal(f.probes.length, probes);
      assert.equal(await f.report(), report);
      assert.doesNotMatch(
        JSON.stringify({ saved, status }),
        /PRIVATE_PROVIDER_MESSAGE/u,
      );
    });
  }
});
