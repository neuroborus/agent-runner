import assert from "node:assert/strict";
import test from "node:test";

import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
} from "../src/trusted-validation/index.js";

const passed = {
  status: "PASS",
  exitCode: 0,
  signal: null,
  timedOut: false,
  reason: "exit",
};
const blocked = {
  status: "BLOCKED",
  exitCode: null,
  signal: null,
  timedOut: false,
  reason: "isolation",
};

function fixture({
  result = passed,
  preparationFailure,
  executionFailure,
  safetyFailure,
  onExecution,
} = {}) {
  const projectPath = process.cwd();
  const contentFingerprint = "a".repeat(64);
  const snapshot = createTrustedValidationSnapshot(
    {
      check: {
        command: "node check.js",
        executable: "node",
        arguments: ["check.js"],
      },
    },
    ["check"],
  );
  let now = 0n;
  const events = [];
  const service = createTrustedValidationService({
    git: {
      async snapshot() {
        events.push("snapshot");
        now += 100_000_000n; // Admission is outside the measured interval.
        return { projectPath, contentFingerprint };
      },
      async assertUnchanged() {
        events.push("safety");
        now += 7_000_000n;
        if (safetyFailure) throw safetyFailure;
      },
    },
    monotonicNow() {
      events.push("clock");
      return now;
    },
    sandboxCommand(command, { environment }) {
      events.push("preparation");
      now += 2_000_000n;
      if (preparationFailure) throw preparationFailure;
      return { command, environment };
    },
    async runCommand(_command, options) {
      events.push(options.preparationOnly ? "availability" : "invocation");
      now += 3_125_000n;
      if (options.preparationOnly) await options.onNoLaunch();
      onExecution?.();
      if (executionFailure) throw executionFailure;
      return result;
    },
  });
  const request = {
    bindings: {
      contentFingerprint,
      validationInfrastructureFingerprint: "b".repeat(64),
      commandFingerprint: snapshot.commandFingerprint,
      configurationFingerprint: snapshot.configurationFingerprint,
    },
    commandIdentity: snapshot.commands[0].identity,
    projectPath,
    snapshot,
  };
  return { service, request, events };
}

for (const [name, result, outcome] of [
  ["success", passed, "exited with code 0"],
  [
    "nonzero exit",
    { ...passed, status: "FAIL", exitCode: 7 },
    "exited with code 7",
  ],
  [
    "signal",
    { ...passed, status: "FAIL", exitCode: null, signal: "SIGTERM" },
    "terminated by a signal",
  ],
  [
    "timeout",
    { ...blocked, timedOut: true, reason: "timeout" },
    "timed out without retaining process output",
  ],
  [
    "isolation denial",
    blocked,
    "could not start in the required isolated executor",
  ],
  [
    "spawn failure",
    { ...blocked, reason: "spawn" },
    "could not be started safely",
  ],
]) {
  test(`Runner timing preserves ${name} without trusting executor telemetry`, async () => {
    const f = fixture({
      result: { ...result, durationMs: 999, stdout: "private output" },
    });
    const receipt = await f.service.execute(f.request);
    assert.equal(receipt.status, result.status);
    assert.equal(receipt.exitCode, result.exitCode);
    assert.equal(receipt.signal, result.signal);
    assert.equal(receipt.timedOut, result.timedOut);
    assert.deepEqual(receipt.evidence, [
      `Runner-trusted command check ${outcome}.`,
      "Runner-measured attempt elapsed time: 12.125 ms (executor invoked).",
    ]);
    assert.deepEqual(f.events, [
      "snapshot",
      "clock",
      "preparation",
      "invocation",
      "safety",
      "clock",
    ]);
    assert.doesNotMatch(
      JSON.stringify(receipt),
      /private output|durationMs|stdout/u,
    );
  });
}

test("pre-invocation blockage measures only the safely retired attempt", async () => {
  const f = fixture({
    preparationFailure: Object.assign(new Error("private cause"), {
      code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE",
    }),
  });
  const receipt = await f.service.execute(f.request);
  assert.equal(receipt.status, "BLOCKED");
  assert.deepEqual(receipt.evidence, [
    "Runner-trusted command check could not start in the required isolated executor.",
    "Runner-measured attempt elapsed time: 9.000 ms (blocked before executor invocation).",
  ]);
  assert.deepEqual(f.events, [
    "snapshot",
    "clock",
    "preparation",
    "safety",
    "clock",
  ]);
  assert.doesNotMatch(JSON.stringify(receipt), /private cause/u);
});

test("capability preparation and rejected admission never measure a check", async () => {
  const f = fixture();
  await f.service.preflight(f.request);
  const report = await f.service.inspectRequirements({
    ...f.request,
    inventory: [f.request.snapshot.commands[0].command],
    onResource: async () => {},
    onProcess: async () => {},
    onPreparation: async () =>
      Object.assign(async () => {}, { noLaunch: async () => {} }),
  });
  assert.deepEqual(report, { status: "READY", blockers: [] });
  assert.deepEqual(f.events, [
    "snapshot",
    "preparation",
    "availability",
    "safety",
  ]);
  f.events.length = 0;
  await assert.rejects(
    f.service.execute({
      ...f.request,
      bindings: { ...f.request.bindings, contentFingerprint: "c".repeat(64) },
    }),
    { code: "ERR_TRUSTED_VALIDATION_BINDING_CHANGED" },
  );
  assert.deepEqual(f.events, ["snapshot"]);
});

test("cancellation, uncertain retirement and safety failures cannot publish elapsed receipts", async () => {
  for (const code of [
    "ERR_EXECUTION_PROCESS_ACTIVE",
    "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE",
    "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE",
    "ABORT_ERR",
    "mutation",
  ]) {
    const controller = new AbortController();
    const failure = Object.assign(new Error("private failure"), { code });
    const f = fixture(
      code === "mutation"
        ? { safetyFailure: failure }
        : {
            executionFailure: failure,
            onExecution:
              code === "ABORT_ERR"
                ? () => controller.abort(failure)
                : undefined,
          },
    );
    await assert.rejects(
      f.service.execute({ ...f.request, signal: controller.signal }),
      code === "mutation"
        ? { code: "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY" }
        : (cause) => cause === failure,
    );
    assert.equal(f.events.filter((event) => event === "clock").length, 1);
  }
});

test("executor results remain strictly validated before timing is published", async () => {
  const f = fixture({ result: { ...passed, exitCode: 7 } });
  await assert.rejects(f.service.execute(f.request), {
    code: "ERR_INVALID_TRUSTED_VALIDATION_RESULT",
  });
  assert.equal(f.events.filter((event) => event === "clock").length, 1);
  assert.throws(() => createTrustedValidationService({ monotonicNow: 1 }), {
    code: "ERR_INVALID_TRUSTED_VALIDATION_OPTIONS",
  });
});
