import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  auditPipeline,
  createAuditState,
  runAuditDiscovery,
} from "../pipelines/audit/src/index.js";
import {
  AgentBoundaryError,
  ClaudeAdapterError,
  CodexAdapterError,
  normalizeAdapterFailure,
  PROVIDER_REGISTRY,
  STRUCTURED_OUTPUT_FAILURE_CLASS,
} from "../src/agents/index.js";
import { createClarificationService } from "../src/clarifications/index.js";
import { createAuthenticationPolicy } from "../src/runner/authentication.js";
import { createDispositionPolicy } from "../src/runner/dispositions.js";
import { bindWorkspace, directorySafety } from "../src/runner/workspace.js";
import {
  normalizeChildSession,
  normalizeTransitionPatch,
} from "../src/state/validation.js";
import { createWorkspaceService } from "../src/workspace/index.js";
import { authenticationFailure } from "./support/authentication.js";
import {
  attachAvailability,
  availabilityFailure,
} from "./support/availability.js";
import { attachInactivity } from "./support/inactivity.js";
import { outputExhaustion } from "./support/output-exhaustion.js";

const HASH = "a".repeat(64);
const INPUTS = {
  scope: ["Complete workspace"],
  references: [],
  exclusions: [],
  criteria: ["Established project rules"],
};
const READY = { status: "READY", inputs: INPUTS, questions: [], reason: "" };
const COMPLETE = {
  status: "COMPLETE",
  snapshotFingerprint: HASH,
  candidates: [],
  limitations: [],
  hypotheses: [],
  reportCorrections: [],
};

// Real runner policies and transition normalization, with effect-free storage.
function policyFixture(outputs, { mode = "independent", source = null } = {}) {
  let current = {
    runId: "audit-fixture",
    revision: 1,
    pipelineId: "audit",
    projectPath: "/workspace/project",
    taskPath: "/workspace/task",
    roles: { auditor: { backend: "codex" } },
    hashes: {},
    pause: null,
    activeTurn: null,
    sessionLineage: { source, children: [] },
    pipelineState: createAuditState({ settings: { mode } }),
  };
  const calls = [];
  const runtime = {
    transition: async (patch) => {
      const pipelinePatch = Object.fromEntries(
        Object.entries(patch).filter(([key]) =>
          ["pipelineState", "pause", "activeTurn", "hashes"].includes(key),
        ),
      );
      current = {
        ...current,
        ...structuredClone(patch),
        ...normalizeTransitionPatch(pipelinePatch),
        revision: current.revision + 1,
      };
      return current;
    },
    workspace: {
      snapshot: async () => ({ contentFingerprint: HASH }),
      assertUnchanged: async (snapshot) =>
        assert.equal(snapshot.contentFingerprint, HASH),
    },
    readInputs: async () => ({
      task: { content: "Audit the workspace", hash: "b".repeat(64) },
      context: null,
    }),
    clarifications: {
      ensureTranscript: async () => ({ content: "", hash: HASH }),
      inspectTranscript: async () => ({ content: "", hash: HASH }),
      freezeTranscript: async () => ({ hash: HASH }),
    },
    authentication: createAuthenticationPolicy({
      providers: PROVIDER_REGISTRY,
    }),
    outputExhaustion: createDispositionPolicy({
      providers: PROVIDER_REGISTRY,
      disposition: "output_exhausted",
    }),
    startAgentTurn: (activeTurn, patch) =>
      runtime.transition({ ...patch, activeTurn }),
    finishAgentTurn: () => runtime.transition({ activeTurn: null }),
    recordChildSession: async (child) => {
      current = {
        ...current,
        sessionLineage: {
          ...current.sessionLineage,
          children: [
            ...current.sessionLineage.children,
            normalizeChildSession(child),
          ],
        },
      };
      return current;
    },
    adapters: {
      auditor: {
        run: async (request) => {
          calls.push(request);
          assert.ok(outputs.length > 0, "Unexpected Auditor invocation");
          const selected = outputs.shift();
          const output =
            typeof selected === "function" ? await selected(request) : selected;
          if (output instanceof Error) throw output;
          return {
            structured: output,
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : `child-${calls.length}`,
          };
        },
      },
    },
  };
  runtime.git = runtime.workspace;
  return {
    runtime,
    calls,
    get currentRun() {
      return current;
    },
    execute: () => runAuditDiscovery({ run: current, runtime }),
  };
}

test("audit initializes actual inactivity checkpoints and preserves reconstruction accounting", async () => {
  const f = policyFixture(
    [READY, (request) => watchdog.expire(request), COMPLETE],
    { mode: "lazy", source: "source-session" },
  );
  const watchdog = await attachInactivity(f);
  const result = await f.execute();
  assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
  assert.equal(result.inactivityRecovery, null);
  assert.deepEqual(
    f.calls.map(({ session }) => session),
    [
      { mode: "fork", id: "source-session" },
      { mode: "continue", id: "child-1" },
      undefined,
    ],
  );
  assert.deepEqual(
    watchdog.events
      .filter(({ phase }) => phase === "inactivity")
      .map(({ kind }) => kind),
    ["expired", "reconstructing", "recovered"],
  );
  assert.deepEqual(
    result.observations.attempts.map(({ checkpoint }) => checkpoint),
    [
      "audit:clarify:read-only:0",
      "audit:discovery:read-only:1",
      "audit:discovery:read-only:1",
    ],
  );
  assert.equal(result.pipelineState.history.length, 1);
});

test("repeated inactivity resumes the original checkpoint without renewing its allowance", async () => {
  const f = policyFixture([
    READY,
    (request) => watchdog.expire(request),
    (request) => watchdog.expire(request),
    COMPLETE,
  ]);
  const watchdog = await attachInactivity(f);
  const paused = await f.execute();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_PROVIDER_INACTIVE");
  assert.equal(paused.inactivityRecovery.attempt, 2);
  assert.equal(paused.pipelineState.history.length, 1);
  watchdog.restart();
  const result = await f.execute();
  assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
  assert.equal(result.inactivityRecovery, null);
  assert.equal(result.pipelineState.history.length, 1);
  assert.equal(f.calls.length, 4);
});

test("input drift during reconstruction preserves recovery evidence and blocks further turns", async () => {
  const f = policyFixture([
    READY,
    (request) => watchdog.expire(request),
    () => {
      f.runtime.readInputs = async () => ({
        task: { content: "Changed input", hash: "c".repeat(64) },
        context: null,
      });
      return COMPLETE;
    },
  ]);
  const watchdog = await attachInactivity(f);
  const result = await f.execute();
  assert.equal(result.pause.reason, "input_changed");
  assert.equal(result.inactivityRecovery.attempt, 2);
  assert.equal(result.activeTurn, null);
  assert.notEqual(result.pipelineState.history[0].outcome, "clean");
  await f.execute();
  assert.equal(f.calls.length, 3);
});

test("terminal provider isolation failures cannot be resumed as clean audit discovery", async () => {
  const cause = new AgentBoundaryError(
    { code: "ERR_CODEX_MULTI_AGENT" },
    {
      failureClass: "operation_multi_agent",
      checkpoint: "turn",
      outcome: "rejected",
      effect: "possible",
      retry: "terminal",
    },
  );
  const f = policyFixture([READY, cause]);
  await assert.rejects(f.execute(), (error) => error === cause);
  assert.equal(f.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(f.currentRun.activeTurn, null);
  assert.equal(f.currentRun.pause.code, "ERR_CODEX_MULTI_AGENT");
  assert.equal(f.currentRun.pipelineState.history[0].outcome, "interrupted");
  assert.equal((await f.execute()).pipelineState.workflowState, "FAILED");
  assert.equal(f.calls.length, 2);
});

test("normalized structured-output failures pause as invalid audit passes and resume", async (t) => {
  for (const [backend, AdapterError, code] of [
    ["codex", CodexAdapterError, "ERR_CODEX_STRUCTURED_OUTPUT"],
    ["claude", ClaudeAdapterError, "ERR_CLAUDE_STRUCTURED_OUTPUT"],
  ]) {
    for (const phase of ["clarify", "discovery"])
      await t.test(`${backend}: ${phase}`, async () => {
        const cause = normalizeAdapterFailure(
          backend,
          new AdapterError("Private malformed provider output", {
            code,
            failureClass: STRUCTURED_OUTPUT_FAILURE_CLASS,
          }),
        );
        const f = policyFixture(
          phase === "clarify"
            ? [cause, READY, COMPLETE]
            : [READY, cause, COMPLETE],
        );
        const waiting = await f.execute();
        assert.equal(waiting.pipelineState.workflowState, "WAITING_FOR_USER");
        assert.equal(waiting.pause.reason, "invalid_discovery");
        assert.equal(
          waiting.pause.resumeState,
          phase === "clarify" ? "CLARIFY" : "DISCOVER",
        );
        assert.equal(waiting.activeTurn, null);
        assert.deepEqual(
          waiting.pipelineState.history.map(({ outcome }) => outcome),
          phase === "clarify" ? [] : ["invalid"],
        );
        assert.doesNotMatch(
          JSON.stringify(waiting),
          /Private malformed provider output/u,
        );
        const resumed = await f.execute();
        assert.equal(resumed.pipelineState.workflowState, "DISCOVERY_CLEAN");
        assert.deepEqual(
          resumed.pipelineState.history.map(({ outcome }) => outcome),
          phase === "clarify" ? ["clean"] : ["invalid", "clean"],
        );
        assert.equal(f.calls.length, 3);
      });
  }
});

test("audit availability failures retain runner backoff and the same discovery checkpoint", async () => {
  const f = policyFixture(
    [READY, availabilityFailure(), availabilityFailure(), COMPLETE],
    { source: "source-session" },
  );
  const recovery = attachAvailability(f);
  const result = await f.execute();
  assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
  assert.equal(result.availabilityRetry, null);
  assert.deepEqual(recovery.delays, [5000, 7000]);
  assert.deepEqual(
    recovery.scheduled.map(
      ({ availabilityRetry }) => availabilityRetry.checkpoint,
    ),
    Array(2).fill("audit:discovery:read-only:1"),
  );
  assert.equal(result.pipelineState.history.length, 1);
  assert.deepEqual(
    f.calls.map(({ session }) => session),
    [
      { mode: "fork", id: "source-session" },
      { mode: "fork", id: "source-session" },
      undefined,
      undefined,
    ],
  );
});

test("authentication and output exhaustion persist distinct pauses without repeating possible source forks", async () => {
  for (const [reason, failure] of [
    ["authentication_required", authenticationFailure()],
    ["output_exhausted", outputExhaustion()],
  ]) {
    const f = policyFixture([failure, READY, COMPLETE], {
      source: "source-session",
    });
    const waiting = await f.execute();
    assert.equal(waiting.pause.reason, reason);
    assert.equal(waiting.activeTurn, null);
    assert.ok(waiting.pipelineState.sourceForkRecovery);
    const result = await f.execute();
    assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
    assert.deepEqual(
      f.calls.map(({ session }) => session),
      [
        { mode: "fork", id: "source-session" },
        undefined,
        { mode: "fork", id: "source-session" },
      ],
    );
    assert.equal(result.pipelineState.sourceForkRecovery, null);
  }
});

test("a lazy Auditor restores only a proven unused source fork", async () => {
  for (const effect of ["none", "possible"]) {
    const f = policyFixture(
      [authenticationFailure({ effect }), READY, COMPLETE],
      { mode: "lazy", source: "source-session" },
    );
    const waiting = await f.execute();
    assert.equal(
      waiting.pipelineState.sourceForkConsumed,
      effect === "possible",
    );
    const result = await f.execute();
    assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
    assert.deepEqual(
      f.calls[1].session,
      effect === "none" ? { mode: "fork", id: "source-session" } : undefined,
    );
    assert.deepEqual(f.calls[2].session, { mode: "continue", id: "child-2" });
  }
});

test("audit rejects persistence field overflow before freezing inputs or accepting a pass", async () => {
  const value = "x".repeat(100_001);
  assert.throws(() => normalizeTransitionPatch({ pipelineState: { value } }), {
    code: "ERR_INVALID_RUN_STATE",
  });
  for (const outputs of [
    [{ ...READY, inputs: { ...INPUTS, scope: [value] } }],
    [READY, { ...COMPLETE, limitations: [value] }],
    [{ ...READY, inputs: null }],
    [
      {
        status: "QUESTIONS",
        inputs: null,
        questions: [{ question: "Which scope?", whyItMatters: value }],
        reason: "",
      },
    ],
  ]) {
    const f = policyFixture(outputs);
    const result = await f.execute();
    assert.equal(result.pause.reason, "invalid_discovery");
    assert.equal(result.activeTurn, null);
    assert.notEqual(result.pipelineState.history.at(-1)?.outcome, "running");
    assert.doesNotThrow(() =>
      normalizeTransitionPatch({ pipelineState: result.pipelineState }),
    );
  }
  const references = Array.from(
    { length: 10_001 },
    (_, index) => `reference-${index}`,
  );
  assert.throws(
    () => normalizeTransitionPatch({ pipelineState: { references } }),
    { code: "ERR_INVALID_RUN_STATE" },
  );
  const f = policyFixture([{ ...READY, inputs: { ...INPUTS, references } }]);
  const result = await f.execute();
  assert.equal(result.pause.reason, "invalid_discovery");
  assert.equal(result.pipelineState.inputs, null);
});

test("persistent text limits retain the aggregate two-MiB audit-result allowance", async () => {
  const report = {
    ...COMPLETE,
    limitations: Array.from({ length: 20 }, (_, index) =>
      String(index).padEnd(100_000, "x"),
    ),
  };
  const f = policyFixture([READY, report, report]);
  const result = await f.execute();
  assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
  assert.deepEqual(result.pipelineState.report.limitations, report.limitations);
});

test("audit discovery composes confined clarification edits and persisted session contexts", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "runner-audit-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  await mkdir(projectPath);
  await mkdir(taskPath);
  await writeFile(join(projectPath, "source.txt"), "Original source\n");
  await writeFile(join(taskPath, "task.md"), "Audit the complete workspace.\n");
  const workspace = createWorkspaceService();
  const selection =
    auditPipeline.resolveWorkspace?.({ projectPath, taskPath }) ??
    auditPipeline.workspace;
  const binding = await bindWorkspace({
    selection,
    projectPath,
    taskPath,
    taskInputs: auditPipeline.taskInputs,
    configurationPath: null,
    stateRoot: join(root, "state"),
    workspace,
  });
  let current = {
    pipelineId: "audit",
    projectPath,
    taskPath,
    roles: { auditor: {} },
    hashes: {},
    pause: null,
    activeTurn: null,
    sessionLineage: { source: null, children: [] },
    pipelineState: createAuditState(),
  };
  let turns = 0;
  const runtime = {
    workspace: directorySafety(binding, workspace),
    clarifications: createClarificationService({ interactive: false }),
    readInputs: async () => {
      const content = await readFile(join(taskPath, "task.md"), "utf8");
      return {
        task: {
          content,
          hash: createHash("sha256").update(content).digest("hex"),
        },
        context: null,
      };
    },
    transition: async (patch) =>
      (current = { ...current, ...normalizeTransitionPatch(patch) }),
    startAgentTurn: async (activeTurn, { pipelineState }) =>
      (current = { ...current, activeTurn, pipelineState }),
    finishAgentTurn: async () => (current = { ...current, activeTurn: null }),
    recordChildSession: async (child) =>
      (current = {
        ...current,
        sessionLineage: {
          ...current.sessionLineage,
          children: [
            ...current.sessionLineage.children,
            normalizeChildSession(child),
          ],
        },
      }),
    adapters: {
      auditor: {
        run: async (request) => {
          turns += 1;
          const structured =
            turns === 1
              ? {
                  status: "QUESTIONS",
                  inputs: null,
                  questions: [
                    {
                      question: "Which source scope is agreed?",
                      whyItMatters:
                        "The inspected material depends on the scope",
                    },
                  ],
                  reason: "",
                }
              : turns === 2
                ? {
                    status: "READY",
                    inputs: {
                      scope: ["Complete workspace"],
                      references: [],
                      exclusions: [],
                      criteria: ["Established project rules"],
                    },
                    questions: [],
                    reason: "",
                  }
                : {
                    status: "COMPLETE",
                    snapshotFingerprint:
                      current.pipelineState.repositoryBaseline
                        .contentFingerprint,
                    candidates: [],
                    limitations: [],
                    hypotheses: [],
                    reportCorrections: [],
                  };
          return {
            structured,
            sessionId: request.session?.id ?? `audit-child-${turns}`,
          };
        },
      },
    },
  };

  const waiting = await runAuditDiscovery({ run: current, runtime });
  assert.equal(waiting.pause.reason, "clarification_answers_required");
  assert.ok(waiting.pipelineState.pendingEdit);
  await writeFile(
    join(taskPath, "clarifications.md"),
    `${await readFile(join(taskPath, "clarifications.md"), "utf8")}\nInspect the complete workspace.\n`,
  );
  const result = await runAuditDiscovery({ run: waiting, runtime });
  assert.equal(result.pipelineState.workflowState, "DISCOVERY_CLEAN");
  assert.equal(result.pipelineState.clarificationRounds, 1);
  assert.equal(result.pipelineState.pendingEdit, null);
  assert.equal(result.sessionLineage.children.length, 2);
  assert.equal(turns, 3);
  assert.equal(
    await readFile(join(projectPath, "source.txt"), "utf8"),
    "Original source\n",
  );

  await writeFile(join(projectPath, "source.txt"), "Intervening source edit\n");
  const drifted = await runAuditDiscovery({ run: result, runtime });
  assert.equal(drifted.pause.reason, "workspace_changed");
  assert.equal(turns, 3);
});
