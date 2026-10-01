import assert from "node:assert/strict";
import { EventEmitter, getEventListeners } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";

import { createDiagnosticCollector } from "../src/trusted-validation/diagnostics.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
  projectTrustedFailureDiagnostics,
  runExactCommand,
} from "../src/trusted-validation/index.js";

const ASSERTION = "Trusted check error class: ERR_ASSERTION.";
const TYPE = "Trusted check error class: TypeError.";
const OMITTED =
  "Trusted check diagnostics omitted unsupported, unsafe, malformed or oversized output.";

test("collects only finite labels across split UTF-8, colors and incomplete lines", () => {
  const collector = createDiagnosticCollector();
  const output = Buffer.from(
    "\x1b[31mAssertionError [ERR_ASSERTION]: private value é\x1b[0m\r\n",
  );
  for (const byte of output) collector.write("stdout", Buffer.from([byte]));
  collector.write(
    "stdout",
    Buffer.from("TypeError [ERR_INVALID_ARG_TYPE]: private value\n"),
  );
  for (const line of [
    "TypeError: private\rrewritten",
    "RangeError: private\u202erewritten",
    "\x1b]8;;https://example.com\x07TypeError: hidden",
    "unverified test title",
    "    actual: 'private value'",
    "    code: 'PRIVATE_CODE'",
    '{"provider":"private transcript"}',
    "Authorization: Bearer synthetic-token",
  ])
    collector.write("stderr", Buffer.from(`${line}\n`));
  collector.write("stderr", Buffer.from([0xff, 0x0a]));
  collector.write(
    "stderr",
    Buffer.from(
      "[warn] Code style issues found in 1 file. Run Prettier with --write to fix.\n",
    ),
  );
  collector.write("stderr", Buffer.from("    code: 'ENOENT'"));
  const result = collector.finish();
  assert.deepEqual(result, [
    ASSERTION,
    TYPE,
    "Trusted check failed stage: formatting.",
    "Trusted check error class: ENOENT.",
    OMITTED,
  ]);
  assert.doesNotMatch(
    JSON.stringify(result),
    /private|transcript|token|rewritten|example/u,
  );
  assert.deepEqual(collector.finish(), result);
});

test("bounds retained lines and candidates while accepting useful later failures", () => {
  const collector = createDiagnosticCollector();
  collector.write("stdout", Buffer.alloc(2 ** 20, 120));
  collector.write("stdout", Buffer.from("\n"));
  for (const value of [
    "AssertionError",
    "SyntaxError",
    "TypeError",
    "ReferenceError",
    "RangeError",
    "ERR_ASSERTION",
    "ERR_TEST_FAILURE",
    "ERR_MODULE_NOT_FOUND",
    "ENOENT",
    "EACCES",
    "EPERM",
    "EADDRINUSE",
    "ECONNREFUSED",
  ]) {
    collector.write("stderr", Buffer.from(`    code: '${value}'\n`));
  }
  collector.write(
    "stdout",
    Buffer.from("Failure diagnostics: test/private-title.test.js\n"),
  );
  collector.write("stdout", Buffer.from("TypeError: useful later failure\n"));
  const result = collector.finish();
  assert.ok(result.length <= 9);
  assert.ok(Buffer.byteLength(result.join("\n")) <= 1024);
  assert.ok(result.includes(TYPE));
  assert.ok(result.includes("Trusted check failed stage: tests."));
  assert.ok(result.includes(OMITTED));
  assert.doesNotMatch(JSON.stringify(result), /private-title|useful later/u);
});

async function simulatedExecution({
  success = false,
  abort = false,
  terminated = false,
  outputError = false,
} = {}) {
  const controller = new AbortController();
  let retired = false;
  const promise = runExactCommand(
    { executable: "node", arguments: [] },
    {
      cwd: process.cwd(),
      environment: {},
      timeoutMs: 1000,
      readinessRequired: true,
      signal: controller.signal,
      onProcess() {},
      spawnProcess(_file, _args, options) {
        assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe", "pipe"]);
        const child = new EventEmitter();
        const completion = Promise.withResolvers();
        child.pid = 123;
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        child.stdio = [
          null,
          child.stdout,
          child.stderr,
          null,
          new EventEmitter(),
        ];
        child.ownedCompletion = completion.promise;
        const close = (exitCode, signal) => {
          child.stdout.end();
          child.stderr.end();
          child.emit("close", exitCode, signal);
          retired = true;
          completion.resolve({ outcome: { type: "close", exitCode, signal } });
        };
        child.kill = () => close(null, "SIGKILL");
        queueMicrotask(() => {
          child.stdio[4].emit("data", Buffer.from([1]));
          child.stdout.write(Buffer.alloc(2 ** 20, 120));
          child.stdout.write(Buffer.from("\n"));
          child.stderr.write(
            Buffer.from("AssertionError [ERR_ASSERTION]: private\n"),
          );
          if (outputError)
            child.stderr.emit(
              "error",
              new Error("synthetic-private-stream-error"),
            );
          if (abort) controller.abort();
          else
            close(
              terminated ? null : success ? 0 : 7,
              terminated ? "SIGTERM" : null,
            );
        });
        return child;
      },
    },
  );
  if (abort) await assert.rejects(promise, { name: "AbortError" });
  else {
    const result = await promise;
    assert.equal(result.status, success ? "PASS" : "FAIL");
    assert.equal(result.exitCode, terminated ? null : success ? 0 : 7);
    assert.equal(result.signal, terminated ? "SIGTERM" : null);
    assert.equal(result.reason, "exit");
    assert.deepEqual(
      result.diagnostics,
      success ? undefined : [ASSERTION, OMITTED],
    );
  }
  assert.equal(retired, true);
}

test("drains both streams, discards successful diagnostics and preserves cancellation retirement", async () => {
  await simulatedExecution();
  await simulatedExecution({ success: true });
  await simulatedExecution({ terminated: true });
  await simulatedExecution({ outputError: true });
  await simulatedExecution({ abort: true });
});

test("observes failed ownership proof without waiting for inherited output pipes", async (t) => {
  const controller = new AbortController();
  const child = new EventEmitter();
  const completion = Promise.withResolvers();
  const failure = Object.assign(
    new Error("Synthetic ownership proof failed."),
    {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    },
  );
  child.pid = 123;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdio = [null, child.stdout, child.stderr, null, new EventEmitter()];
  child.ownedCompletion = completion.promise;
  child.kill = () =>
    assert.fail("Ownership failure must preserve the retained owner.");
  t.after(async () => {
    await Promise.all(
      [child.stdout, child.stderr].map((stream) => {
        const closed = new Promise((resolve) => stream.once("close", resolve));
        stream.destroy();
        return closed;
      }),
    );
  });
  await assert.rejects(
    runExactCommand(
      { executable: "node", arguments: [] },
      {
        cwd: process.cwd(),
        environment: {},
        timeoutMs: 1000,
        readinessRequired: true,
        signal: controller.signal,
        onProcess() {},
        spawnProcess() {
          queueMicrotask(() => {
            child.stdio[4].emit("data", Buffer.from([1]));
            child.stderr.write(
              Buffer.from("AssertionError [ERR_ASSERTION]: private\n"),
            );
            completion.reject(failure);
          });
          return child;
        },
      },
    ),
    (cause) => cause === failure,
  );
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("service revalidates transient fragments and leaves legacy evidence unchanged", async () => {
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
  const bindings = {
    contentFingerprint: "a".repeat(64),
    validationInfrastructureFingerprint: "b".repeat(64),
    commandFingerprint: snapshot.commandFingerprint,
    configurationFingerprint: snapshot.configurationFingerprint,
  };
  let diagnostics;
  let status = "FAIL";
  let reason = "exit";
  let signal = null;
  const service = createTrustedValidationService({
    git: {
      async snapshot() {
        return {
          projectPath: process.cwd(),
          contentFingerprint: bindings.contentFingerprint,
        };
      },
      async assertUnchanged() {},
    },
    sandboxCommand(command) {
      return { command, environment: {} };
    },
    async runCommand() {
      return {
        status,
        exitCode:
          status === "PASS"
            ? 0
            : status === "FAIL" && signal === null
              ? 7
              : null,
        signal,
        timedOut: reason === "timeout",
        reason,
        ...(diagnostics === undefined ? {} : { diagnostics }),
      };
    },
  });
  const execute = () =>
    service.execute({
      projectPath: process.cwd(),
      snapshot,
      bindings,
      commandIdentity: snapshot.commands[0].identity,
    });
  const legacy = await execute();
  assert.deepEqual(legacy.evidence, [
    "Runner-trusted command check exited with code 7.",
  ]);
  diagnostics = [ASSERTION];
  assert.deepEqual((await execute()).evidence, [...legacy.evidence, ASSERTION]);
  for (diagnostics of [
    ["TypeError: private"],
    Array(1),
    [ASSERTION, ASSERTION],
    [
      "AssertionError",
      "SyntaxError",
      "TypeError",
      "ReferenceError",
      "RangeError",
      "ERR_ASSERTION",
      "ERR_TEST_FAILURE",
      "ERR_MODULE_NOT_FOUND",
      "ENOENT",
    ].map((value) => `Trusted check error class: ${value}.`),
    Array(10).fill(ASSERTION),
    { raw: "private" },
  ]) {
    await assert.rejects(execute(), {
      code: "ERR_INVALID_TRUSTED_VALIDATION_RESULT",
    });
  }
  diagnostics = [ASSERTION];
  status = "PASS";
  assert.deepEqual((await execute()).evidence, [
    "Runner-trusted command check exited with code 0.",
  ]);
  status = "FAIL";
  signal = "SIGTERM";
  assert.deepEqual((await execute()).evidence, [
    "Runner-trusted command check terminated by a signal.",
    ASSERTION,
  ]);
  status = "BLOCKED";
  signal = null;
  for (reason of ["timeout", "process-tree", "isolation"]) {
    const result = await execute();
    assert.equal(result.status, "BLOCKED");
    assert.equal(result.evidence.includes(ASSERTION), reason !== "isolation");
  }
});

test("public diagnostics require frozen check identity and matching generated issue without changing actions", () => {
  const trustedValidation = createTrustedValidationSnapshot(
    {
      check: {
        command: "node check.js",
        executable: "node",
        arguments: ["check.js"],
      },
    },
    ["check"],
  );
  const evidence = [
    "Runner-trusted command check exited with code 7.",
    ASSERTION,
  ];
  const run = {
    pipelineState: {
      trustedValidation,
      currentStep: 1,
      repositoryBaseline: { contentFingerprint: "a".repeat(64) },
      requiredChecks: [{ id: "C1", command: "node check.js" }],
      validationInfrastructure: [],
      validationInfrastructureFingerprint: "b".repeat(64),
      finalizationResult: {
        status: "FAIL",
        step: 1,
        fingerprint: "a".repeat(64),
        validationChanged: false,
        validationInfrastructure: [],
        validationInfrastructureFingerprint: "b".repeat(64),
        trustedCommandFingerprint: trustedValidation.commandFingerprint,
        trustedConfigurationFingerprint:
          trustedValidation.configurationFingerprint,
        requiredChecks: [{ id: "C1", command: "node check.js" }],
        checks: [
          {
            checkId: "C1",
            command: "node check.js",
            status: "FAIL",
            executor: "runner",
            commandIdentity: trustedValidation.commands[0].identity,
            exitCode: 7,
            signal: null,
            timedOut: false,
            evidence,
          },
        ],
        issues: [
          {
            id: "F1",
            command: "node check.js",
            problem: "A runner-trusted validation command failed.",
            evidence,
          },
        ],
      },
    },
  };
  const pause = {
    reason: "environment_blocked",
    evidence: ["Unavailable."],
    nextActions: [{ type: "resume", action: null }],
  };
  const projected = projectTrustedFailureDiagnostics(run, pause);
  assert.deepEqual(projected.evidence, [
    `Runner check C1, issue F1: ${ASSERTION}`,
    "Unavailable.",
  ]);
  assert.equal(projected.nextActions, pause.nextActions);
  assert.doesNotMatch(
    JSON.stringify(projected),
    /node check|validation command failed/u,
  );
  for (const mutate of [
    (value) => {
      value.pipelineState.finalizationResult.step = 2;
    },
    (value) => {
      value.pipelineState.finalizationResult.validationInfrastructureFingerprint =
        "c".repeat(64);
    },
    (value) => {
      value.pipelineState.finalizationResult.requiredChecks[0].id = "C2";
    },
    (value) => {
      value.pipelineState.finalizationResult.requiredChecks.push({
        id: "C2",
        command: "node second.js",
      });
    },
    (value) => {
      value.pipelineState.finalizationResult.checks[0].exitCode = 0;
    },
    (value) => {
      value.pipelineState.finalizationResult.trustedConfigurationFingerprint =
        "f".repeat(64);
    },
    (value) => {
      value.pipelineState.finalizationResult.checks[0].executor = "agent";
    },
    (value) => {
      value.pipelineState.finalizationResult.checks[0].commandIdentity =
        "f".repeat(64);
    },
    (value) => {
      value.pipelineState.finalizationResult.trustedCommandFingerprint =
        "f".repeat(64);
    },
    (value) => {
      value.pipelineState.finalizationResult.issues[0].problem =
        "Unverified agent prose.";
    },
    (value) => {
      value.pipelineState.finalizationResult.issues[0].evidence = ["private"];
    },
    (value) => {
      value.pipelineState.repositoryBaseline.contentFingerprint = "f".repeat(
        64,
      );
    },
    (value) => {
      value.pipelineState.finalizationResult.checks[0].evidence = [
        "Opaque historical failure.",
      ];
    },
  ]) {
    const altered = structuredClone(run);
    mutate(altered);
    assert.equal(projectTrustedFailureDiagnostics(altered, pause), pause);
  }
  const amended = structuredClone(run);
  amended.pipelineState.finalizationResult.validationChanged = true;
  amended.pipelineState.finalizationResult.validationInfrastructureFingerprint =
    "c".repeat(64);
  amended.pipelineState.finalizationResult.validationInfrastructure = [
    "scripts/check.js",
  ];
  assert.deepEqual(projectTrustedFailureDiagnostics(amended, pause), projected);
  const wrapped = {
    ...run,
    pause: { operatorResume: { pause: { reason: pause.reason } } },
  };
  assert.deepEqual(
    projectTrustedFailureDiagnostics(wrapped, {
      ...pause,
      reason: "operator_paused",
    }).evidence,
    projected.evidence,
  );
});
