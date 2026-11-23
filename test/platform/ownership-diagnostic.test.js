import assert from "node:assert/strict";
import test from "node:test";

import {
  createOwnershipDiagnostic,
  inspectOwnedSessionProcesses,
  normalizeOwnershipDiagnostic,
  ownershipDiagnosticFrom,
} from "../../src/platform/index.js";
import {
  AgentBoundaryError,
  ClaudeAdapterError,
  CodexAdapterError,
  normalizeAdapterFailure,
} from "../../src/agents/index.js";
import { RunStoreError } from "../../src/state/index.js";
import { RunnerError } from "../../src/runner/index.js";
import { TrustedValidationError } from "../../src/trusted-validation/index.js";

const sample = {
  work: 65_537,
  elapsedMs: 273,
  maxWork: 65_536,
  maxElapsedMs: 250,
  maxAttempts: 3,
};
const diagnostic = createOwnershipDiagnostic("parent-containment-relay", {
  branch: "finish-inspection-deadline",
  inspection: sample,
  startRequested: true,
  terminationRequested: false,
  ownershipHandedOff: false,
});

test("ownership diagnostics admit only bounded closed evidence and valid site/branch combinations", () => {
  assert.deepEqual(normalizeOwnershipDiagnostic(diagnostic), diagnostic);
  assert.equal(normalizeOwnershipDiagnostic(null), null);
  for (const patch of [
    { schemaVersion: 2 },
    { site: "unknown" },
    { branch: null },
    { branch: "arbitrary" },
    { phase: null },
    { startRequested: "true" },
    { raw: "discarded" },
    { inspection: { ...sample, work: Infinity } },
    { inspection: { ...sample, elapsedMs: -1 } },
    { inspection: { ...sample, maxWork: 65_537 } },
    { inspection: { ...sample, maxElapsedMs: 251 } },
    { inspection: { ...sample, maxAttempts: 4 } },
    { inspection: { ...sample, extra: 1 } },
  ]) {
    assert.throws(() =>
      normalizeOwnershipDiagnostic({ ...diagnostic, ...patch }),
    );
    assert.equal(
      ownershipDiagnosticFrom({
        ownershipDiagnostic: { ...diagnostic, ...patch },
      }),
      null,
    );
  }
  assert.throws(() =>
    createOwnershipDiagnostic("registration", { branch: "terminate-check" }),
  );
  assert.throws(() =>
    createOwnershipDiagnostic("state-custody", { startRequested: true }),
  );
  assert.throws(() =>
    createOwnershipDiagnostic("registration", { inspection: sample }),
  );
  for (const branch of [
    "finish-inspection-deadline",
    "finish-retirement-deadline",
    "terminate-signal",
    "terminate-check",
  ])
    assert.equal(
      createOwnershipDiagnostic("parent-containment-relay", { branch }).branch,
      branch,
    );
  assert.equal(
    ownershipDiagnosticFrom({
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      message: "registration",
    }),
    null,
  );
});

test("inspection samples retain actual overruns at existing checks without adding reads or clock calls", () => {
  let reads = 0,
    clocks = 0,
    lists = 0,
    measured;
  assert.equal(
    inspectOwnedSessionProcesses(44, "a".repeat(64), {
      now: () => {
        clocks++;
        return 0;
      },
      maxWork: 2,
      list: () => {
        lists++;
        return ["1", "2"];
      },
      read: () => {
        reads++;
        assert.fail("budget must refuse before reading");
      },
      onInspection: (value) => {
        measured = value;
      },
    }),
    null,
  );
  assert.deepEqual(measured, { ...sample, work: 3, elapsedMs: 0, maxWork: 2 });
  assert.equal(lists, 1);
  assert.equal(reads, 0);
  assert.equal(clocks, 5);

  let elapsed = 0;
  assert.equal(
    inspectOwnedSessionProcesses(44, "a".repeat(64), {
      now: () => elapsed,
      list: () => {
        elapsed = 371;
        return [];
      },
      onInspection: (value) => {
        measured = value;
      },
    }),
    null,
  );
  assert.deepEqual(measured, { ...sample, work: 1, elapsedMs: 371 });
  assert.equal(
    inspectOwnedSessionProcesses(44, "a".repeat(64), {
      now: () => NaN,
      list: () => assert.fail("invalid clock stops discovery"),
      onInspection: (value) => {
        measured = value;
      },
    }),
    null,
  );
  assert.equal(measured.elapsedMs, null);
  assert.deepEqual(
    inspectOwnedSessionProcesses(44, "a".repeat(64), {
      now: () => 0,
      list: () => [],
      onInspection: () => {
        throw new Error("observer");
      },
    }),
    [],
  );
});

test("both adapters and the shared boundary preserve only validated diagnostics without changing failure policy", () => {
  const cause = Object.assign(new Error("discarded"), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    ownershipDiagnostic: diagnostic,
  });
  for (const [backend, AdapterError] of [
    ["codex", CodexAdapterError],
    ["claude", ClaudeAdapterError],
  ]) {
    const wrapped = new AdapterError("adapter failed", { cause });
    assert.deepEqual(wrapped.ownershipDiagnostic, diagnostic);
    const failure = normalizeAdapterFailure(backend, wrapped);
    assert.ok(failure instanceof AgentBoundaryError);
    assert.deepEqual(failure.ownershipDiagnostic, diagnostic);
    const without = normalizeAdapterFailure(
      backend,
      new AdapterError("adapter failed"),
    );
    assert.deepEqual(failure.failure, without.failure);
    assert.equal(failure.effectStarted, without.effectStarted);
    assert.equal(failure.recoverable, without.recoverable);
    assert.equal(
      normalizeAdapterFailure(backend, {
        ...cause,
        ownershipDiagnostic: { ...diagnostic, private: "discarded" },
      }).ownershipDiagnostic,
      null,
    );
  }
  for (const ErrorType of [
    TrustedValidationError,
    RunStoreError,
    RunnerError,
  ]) {
    assert.deepEqual(
      new ErrorType("failed", { cause }).ownershipDiagnostic,
      diagnostic,
    );
    const invalid = new ErrorType("original refusal", {
      code: cause.code,
      ownershipDiagnostic: { ...diagnostic, raw: "discarded" },
    });
    assert.equal(invalid.code, cause.code);
    assert.equal(invalid.message, "original refusal");
    assert.equal(invalid.ownershipDiagnostic, null);
  }
});
