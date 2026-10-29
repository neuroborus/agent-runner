import assert from "node:assert/strict";

import { createAuditState, runAuditDiscovery } from "../../src/index.js";

export const HASH = "a".repeat(64);
export const INPUTS = {
  scope: ["Inspect the complete workspace"],
  references: ["docs/limits.md"],
  exclusions: ["Generated artifacts"],
  criteria: ["Counts must be nonnegative"],
};
export const READY = {
  status: "READY",
  inputs: INPUTS,
  questions: [],
  reason: "",
};
export const complete = (patch = {}) => ({
  status: "COMPLETE",
  snapshotFingerprint: HASH,
  candidates: [],
  limitations: [],
  hypotheses: [],
  reportCorrections: [],
  ...patch,
});
export const finding = (patch = {}) => ({
  id: "negative-count",
  causeId: "unchecked-count",
  title: "Negative counts reach allocation",
  severity: "Medium",
  category: "Correctness",
  locations: ["src/count.js:8"],
  evidence: ["parseCount returns negative integers without a range check"],
  impact: "The requested operation aborts during allocation",
  severityRationale: "Only invalid explicit counts trigger this failure",
  examples: [
    {
      kind: "behavioral",
      basis: "code-derived",
      conditions: "Count is -1",
      action: "Parse the count and allocate",
      expected: "Reject before allocation",
      actual: "Allocation receives -1",
    },
  ],
  ...patch,
});

// Lightweight root capabilities: no providers, Git, filesystem or clock effects.
export function fixture(
  outputs = [],
  {
    mode = "independent",
    source = null,
    saved,
    context = null,
    clarificationContent = "",
  } = {},
) {
  let current = saved
    ? structuredClone(saved)
    : {
        pipelineId: "audit",
        runId: "synthetic-run",
        projectPath: "/workspace/project",
        taskPath: "/state/task",
        roles:
          mode === "lazy" ? { auditor: {} } : { auditor: {}, reviewer: {} },
        hashes: {},
        pause: null,
        activeTurn: null,
        sessionLineage: { source, children: [] },
        pipelineState: createAuditState({ settings: { mode } }),
      };
  let sequence = current.sessionLineage.children.length;
  let transcriptHash = current.hashes.clarifications ?? "c".repeat(64);
  let taskHash = current.hashes.task ?? "b".repeat(64);
  let changed = false;
  let stopAfterReservation = false;
  let stopAfterAcceptance = false;
  let stopStage = null;
  const calls = [];
  const events = [];
  const runtime = {
    transition: async (patch) => {
      const previousStage = current.pipelineState.workflowState;
      current = { ...current, ...structuredClone(patch) };
      events.push({
        type: "persist",
        stage: current.pipelineState.workflowState,
        passes: current.pipelineState.history.length,
      });
      if (
        stopAfterReservation &&
        (current.pipelineState.history.at(-1)?.outcome === "running" ||
          current.pipelineState.recheckHistory.at(-1)?.outcome === "running")
      ) {
        stopAfterReservation = false;
        throw new Error("Simulated persistence response loss");
      }
      if (
        stopAfterAcceptance &&
        current.pipelineState.workflowState === "DISCOVERY_CLEAN"
      ) {
        stopAfterAcceptance = false;
        throw new Error("Simulated acceptance response loss");
      }
      if (
        stopStage === current.pipelineState.workflowState &&
        stopStage !== previousStage
      ) {
        stopStage = null;
        throw new Error("Simulated gate response loss");
      }
      return current;
    },
    workspace: {
      snapshot: async () => ({ contentFingerprint: HASH }),
      assertUnchanged: async () => {
        if (changed) throw new Error("Workspace changed");
      },
    },
    readInputs: async () => ({
      task: { content: "Audit the project", hash: taskHash },
      context,
    }),
    clarifications: {
      ensureTranscript: async () => ({
        content: clarificationContent,
        hash: transcriptHash,
      }),
      inspectTranscript: async () => ({
        content: clarificationContent,
        hash: transcriptHash,
      }),
      freezeTranscript: async ({ expectedHash }) => {
        assert.equal(expectedHash, transcriptHash);
        events.push({ type: "freeze" });
        return { hash: transcriptHash };
      },
      appendQuestionRound: async () => {
        transcriptHash = "d".repeat(64);
        return { hash: transcriptHash };
      },
      prepareEdit: async (request) => {
        const authorization = {
          id: "edit-one",
          action: request.action,
          suspendedState: request.suspendedState,
          preEditorHash: transcriptHash,
        };
        await request.persistPendingEdit(authorization);
        events.push({ type: "editor-authorized" });
        return authorization;
      },
      acceptEdit: async (authorization, { consumePendingEdit }) =>
        consumePendingEdit({
          authorizationId: authorization.id,
          hash: transcriptHash,
          changed: false,
        }),
    },
    startAgentTurn: async (activeTurn, { pipelineState }) => {
      current = { ...current, activeTurn, pipelineState };
      events.push({ type: "turn-start", passes: pipelineState.history.length });
      return current;
    },
    finishAgentTurn: async () => (current = { ...current, activeTurn: null }),
    recordChildSession: async (child) => {
      current = {
        ...current,
        sessionLineage: {
          ...current.sessionLineage,
          children: [...current.sessionLineage.children, child],
        },
      };
      return current;
    },
    adapters: {
      auditor: {
        run: async (request) => {
          calls.push(request);
          assert.equal(request.access, "read-only");
          assert.equal(request.cwd, "/workspace/project");
          assert.ok(outputs.length > 0, "Unexpected Auditor invocation");
          let output = outputs.shift();
          if (typeof output === "function") output = await output(request);
          if (output instanceof Error) throw output;
          return {
            structured: output,
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : `child-${++sequence}`,
          };
        },
      },
    },
  };
  runtime.adapters.reviewer = runtime.adapters.auditor;
  return {
    calls,
    events,
    runtime,
    run: () => current,
    execute: () => runAuditDiscovery({ run: current, runtime }),
    drift: () => {
      changed = true;
    },
    inputDrift: () => {
      taskHash = "e".repeat(64);
    },
    stopAt: (stage) => {
      stopStage = stage;
    },
    stopAfterReservation: () => {
      stopAfterReservation = true;
    },
    stopAfterAcceptance: () => {
      stopAfterAcceptance = true;
    },
  };
}

export function recheck(request, patch = {}) {
  const evidence = JSON.parse(request.prompt.split("\n").at(-1));
  return {
    status: "COMPLETE",
    snapshotFingerprint: evidence.batch.snapshotFingerprint,
    reportFingerprint: evidence.batch.reportFingerprint,
    batchFingerprint: evidence.batchFingerprint,
    decisions: evidence.batch.entries.map(
      ({ finding }) =>
        evidence.batch.dispositions.find(({ id }) => id === finding.id) ??
        decision(finding.id),
    ),
    additions: [],
    ...patch,
  };
}

export function decision(id, patch = {}) {
  return {
    id,
    kind: "confirm",
    rationale: "The evidence supports this finding",
    finding: null,
    targetId: null,
    hypothesis: null,
    ...patch,
  };
}

export async function pendingRun(candidates = [finding()], options = {}) {
  const f = fixture([READY, complete({ candidates })], options);
  f.stopAt("VERIFY_FINDINGS");
  await assert.rejects(f.execute(), /gate response loss/u);
  return f.run();
}
