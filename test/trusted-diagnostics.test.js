import assert from "node:assert/strict";
import { EventEmitter, getEventListeners } from "node:events";
import { PassThrough } from "node:stream";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createDiagnosticCollector } from "../src/trusted-validation/diagnostics.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
  projectTrustedFailureDiagnostics,
  runExactCommand,
  validateTrustedFinalizationEvidence,
} from "../src/trusted-validation/index.js";

const ASSERTION = "Trusted check error class: ERR_ASSERTION.";
const TYPE = "Trusted check error class: TypeError.";
const TESTS = "Trusted check failed stage: tests.";
const ABORTED = "Trusted check test failure type: testAborted.";
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
  output = [
    ["stdout", Buffer.alloc(2 ** 20, 120)],
    ["stdout", Buffer.from("\n")],
    ["stderr", Buffer.from("AssertionError [ERR_ASSERTION]: private\n")],
  ],
  fragmented = false,
  diagnostics = [ASSERTION, OMITTED],
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
          for (const [stream, chunk] of output) {
            if (fragmented) {
              for (const byte of chunk)
                child[stream].write(Buffer.from([byte]));
            } else child[stream].write(chunk);
          }
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
    assert.deepEqual(result.diagnostics, success ? undefined : diagnostics);
  }
  assert.equal(retired, true);
}

test("retains dot reporter failures through fragmented output and unusable surrounding lines", async () => {
  const output = [
    ["stdout", Buffer.alloc(4096, 120)],
    ["stdout", Buffer.from("\n")],
    ["stdout", Buffer.from([0xff, 0x0a])],
    [
      "stdout",
      Buffer.from(
        [
          "Tests: 1 files; concurrency: up to 1; temporary storage: synthetic",
          "X",
          "\x1b[31mFailed tests:\x1b[0m",
          "✖ synthetic check (1ms)",
          "  \x1b[31mAssertionError [ERR_ASSERTION]: synthetic value é\x1b[0m",
          "    at test/synthetic.test.js:1:1",
          "    code: 'ERR_ASSERTION',",
          "    actual: 'synthetic actual',",
          "",
        ].join("\n"),
      ),
    ],
    ["stderr", Buffer.from("Tests elapsed: 0.1s\n")],
  ];
  for (const fragmented of [false, true])
    await simulatedExecution({
      output,
      fragmented,
      diagnostics: [TESTS, ASSERTION, OMITTED],
    });
  await simulatedExecution({ output, fragmented: true, success: true });
});

test("retains failure markers without classes and bounded reporter error fields", async () => {
  for (const [line, diagnostic] of [
    ["Failed tests:", TESTS],
    ["✖ failing tests:", TESTS],
    ["ℹ fail 1", TESTS],
    ["# fail 2", TESTS],
    ["  AssertionError [ERR_ASSERTION]: synthetic value", ASSERTION],
    ["            TypeError: synthetic value", TYPE],
    ["    code: 'ERR_ASSERTION',", ASSERTION],
    ['    name: "TypeError",', TYPE],
  ])
    await simulatedExecution({
      output: [["stderr", Buffer.from(`${line}\n`)]],
      fragmented: true,
      diagnostics: [diagnostic],
    });
});

test("preserves supported Node 24 failure types from TAP and spec fields", async () => {
  for (const type of [
    "testCodeFailure",
    "subtestsFailed",
    "hookFailed",
    "testAborted",
    "testTimeoutFailure",
    "cancelledByParent",
    "parentAlreadyFinished",
    "callbackAndPromisePresent",
    "multipleCallbackInvocations",
    "expectedFailure",
    "uncaughtException",
    "unhandledRejection",
  ]) {
    for (const field of [
      `  failureType: '${type}'`,
      `    failureType: "${type}",`,
    ]) {
      await simulatedExecution({
        output: [["stderr", Buffer.from(`${field}\n`)]],
        fragmented: true,
        diagnostics: [`Trusted check test failure type: ${type}.`],
      });
    }
  }
});

test("retains aborted spec diagnostics while redacting names, locations and causes", async () => {
  const output = [
    [
      "stdout",
      Buffer.from(
        [
          "✖ synthetic unfinished test (0.1ms)",
          "test at test/synthetic.test.js:1:1",
          "  Error [ERR_TEST_FAILURE]: synthetic private cause",
          "    code: 'ERR_TEST_FAILURE',",
          "    failureType: 'testAborted',",
          "    cause: 'synthetic private cause',",
          "    at TestContext.<anonymous> (test/synthetic.test.js:1:1)",
          "ℹ cancelled 1",
          "",
        ].join("\n"),
      ),
    ],
  ];
  const diagnostics = [
    TESTS,
    "Trusted check error class: ERR_TEST_FAILURE.",
    ABORTED,
    OMITTED,
  ];
  for (const fragmented of [false, true]) {
    await simulatedExecution({ output, fragmented, diagnostics });
  }
  await simulatedExecution({ output, fragmented: true, success: true });
});

test("omits unknown, malformed and unsafe failure types", async () => {
  await simulatedExecution({
    output: [
      [
        "stderr",
        Buffer.from(
          [
            "    failureType: 'syntheticPrivateType',",
            "failureType: 'testAborted'",
            "             failureType: 'testAborted'",
            "    failureType: 'testAborted', private suffix",
            "    failureType: 'testAborted\",",
            "    failureType: 'testAborted\u202e'",
            "",
          ].join("\n"),
        ),
      ],
    ],
    fragmented: true,
    diagnostics: [OMITTED],
  });
});

test("does not infer failures from started stages, zero counts or malformed markers", async () => {
  await simulatedExecution({
    output: [
      [
        "stdout",
        Buffer.from(
          [
            "> npm run format:check && npm test",
            "Checking formatting...",
            "All matched files use Prettier code style!",
            "Tests: 1 files; concurrency: up to 1; temporary storage: synthetic",
            "Test batch: 1 files; concurrency: 1",
            "ℹ fail 0",
            "# fail 0",
            "prefix Failed tests:",
            "Failed tests: suffix",
            "ℹ fail 1 suffix",
            "             AssertionError [ERR_ASSERTION]: synthetic value",
            "    code: 'ERR_ASSERTION', suffix",
            "    name: 'TypeError\",",
            "",
          ].join("\n"),
        ),
      ],
    ],
    diagnostics: [OMITTED],
  });
});

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
    clock: () => 0,
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
    "Runner-trusted check elapsed: 0 ms.",
  ]);
  diagnostics = [ASSERTION, ABORTED];
  assert.deepEqual((await execute()).evidence, [
    legacy.evidence[0],
    ASSERTION,
    ABORTED,
    legacy.evidence[1],
  ]);
  for (diagnostics of [
    ["TypeError: private"],
    ["Trusted check test failure type: syntheticPrivateType."],
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
    "Runner-trusted check elapsed: 0 ms.",
  ]);
  status = "FAIL";
  signal = "SIGTERM";
  assert.deepEqual((await execute()).evidence, [
    "Runner-trusted command check terminated by a signal.",
    ASSERTION,
    "Runner-trusted check elapsed: 0 ms.",
  ]);
  status = "BLOCKED";
  signal = null;
  for (reason of ["timeout", "process-tree", "isolation"]) {
    const result = await execute();
    assert.equal(result.status, "BLOCKED");
    assert.equal(result.evidence.includes(ASSERTION), reason !== "isolation");
  }
});

test("bound file locations and runner timing survive normalization without rediscovering a changed tree", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "trusted-files-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "scripts"));
  await mkdir(join(root, "test"));
  for (const path of [
    "scripts/format.js",
    "scripts/index.js",
    "scripts/test.js",
    "scripts/test-selection.js",
    "scripts/test-storage.js",
    "package.json",
  ]) {
    await writeFile(
      join(root, path),
      await readFile(new URL(`../${path}`, import.meta.url)),
    );
  }
  const files = Array.from(
    { length: 12 },
    (_, index) => `test/case-${String(index).padStart(2, "0")}.test.js`,
  );
  for (const path of [...files, "test/ignored.slow.test.js"])
    await writeFile(join(root, path), "");
  const snapshot = createTrustedValidationSnapshot(
    {
      "agent-runner-check": {
        command: "npm run check",
        executable: "npm",
        arguments: ["run", "check"],
      },
    },
    ["agent-runner-check"],
  );
  const bindings = {
    contentFingerprint: "a".repeat(64),
    validationInfrastructureFingerprint: "b".repeat(64),
    commandFingerprint: snapshot.commandFingerprint,
    configurationFingerprint: snapshot.configurationFingerprint,
  };
  let now = 1000.25;
  let output;
  let status = "FAIL";
  let reason = "exit";
  let rejectedPath = null;
  let rejectedInspection = {};
  let expectInventory = true;
  const inspected = [];
  const service = createTrustedValidationService({
    clock: () => now,
    git: {
      async snapshot() {
        return {
          projectPath: root,
          contentFingerprint: bindings.contentFingerprint,
        };
      },
      async assertUnchanged() {},
      async inspectPath({ path }) {
        inspected.push(path);
        return {
          exists: true,
          kind: "file",
          relativePath: path,
          ...(path === rejectedPath ? rejectedInspection : {}),
        };
      },
    },
    sandboxCommand(command) {
      return { command, environment: {} };
    },
    async runCommand(_command, options) {
      assert.deepEqual(
        options.diagnosticInventory?.files ?? [],
        expectInventory ? files : [],
      );
      const collector = createDiagnosticCollector({
        inventory: options.diagnosticInventory,
        projectPath: options.cwd,
      });
      for (const byte of Buffer.from(output))
        collector.write("stdout", Buffer.from([byte]));
      now += 20.5;
      return {
        status,
        reason,
        exitCode: status === "PASS" ? 0 : status === "FAIL" ? 7 : null,
        signal: null,
        timedOut: reason === "timeout",
        diagnostics: collector.finish(),
        elapsedMs: 99999,
      };
    },
  });
  const execute = (selected = snapshot) =>
    service.execute({
      projectPath: root,
      snapshot: selected,
      bindings: {
        ...bindings,
        commandFingerprint: selected.commandFingerprint,
        configurationFingerprint: selected.configurationFingerprint,
      },
      commandIdentity: selected.commands[0].identity,
    });
  const location = (path) =>
    `not ok 1 - opaque title\n  ---\n  location: '${path}:2:3'\n  failureType: 'testCodeFailure'\n  ...\n`;
  output = location(join(root, files[0]));
  const result = await execute();
  const identity = `Trusted check failed test file: ${files[0]}.`;
  const timing = "Runner-trusted check elapsed: 21 ms.";
  assert.ok(result.evidence.includes(identity));
  assert.ok(result.evidence.includes(timing));
  assert.ok(!JSON.stringify(result).includes(root));
  assert.ok(files.every((path) => inspected.includes(path)));
  assert.ok(!inspected.includes("test/ignored.slow.test.js"));
  const state = {
    trustedValidation: snapshot,
    repositoryBaseline: { contentFingerprint: bindings.contentFingerprint },
    requiredChecks: [{ id: "C1", command: "npm run check" }],
    validationInfrastructure: [],
    validationInfrastructureFingerprint:
      bindings.validationInfrastructureFingerprint,
    finalizationResult: {
      status: "FAIL",
      fingerprint: bindings.contentFingerprint,
      validationChanged: false,
      validationInfrastructure: [],
      validationInfrastructureFingerprint:
        bindings.validationInfrastructureFingerprint,
      trustedCommandFingerprint: snapshot.commandFingerprint,
      trustedConfigurationFingerprint: snapshot.configurationFingerprint,
      requiredChecks: [{ id: "C1", command: "npm run check" }],
      checks: [
        {
          ...result,
          checkId: "C1",
          command: "npm run check",
          executor: "runner",
        },
      ],
      issues: [
        {
          id: "F1",
          command: "npm run check",
          problem: "A runner-trusted validation command failed.",
          evidence: result.evidence,
        },
      ],
    },
  };
  const pause = {
    reason: "environment_blocked",
    evidence: [],
    nextActions: [{ type: "resume", action: null }],
  };
  const project = (value) =>
    projectTrustedFailureDiagnostics({ pipelineState: value }, pause);
  validateTrustedFinalizationEvidence(state);
  assert.ok(
    project(state).evidence.includes(`Runner check C1, issue F1: ${identity}`),
  );
  assert.ok(
    project(state).evidence.includes(`Runner check C1, issue F1: ${timing}`),
  );
  await rm(join(root, files[0]));
  await writeFile(join(root, "test/later.test.js"), "");
  validateTrustedFinalizationEvidence(JSON.parse(JSON.stringify(state)));
  assert.deepEqual(project(state).nextActions, pause.nextActions);
  await writeFile(join(root, files[0]), "");
  await rm(join(root, "test/later.test.js"));
  for (const mutate of [
    (check) => {
      check.diagnosticInventory.files[0] = "test/foreign.test.js";
    },
    (check) => {
      check.diagnosticInventory.contentFingerprint = "c".repeat(64);
    },
    (check) => {
      check.diagnosticInventory.commandIdentity = "c".repeat(64);
    },
    (check) => {
      delete check.diagnosticInventory;
    },
    (check) => {
      check.executor = "agent";
    },
    (check) => {
      check.commandIdentity = "c".repeat(64);
    },
    (check) => {
      check.evidence.push(timing);
    },
    (check) => {
      check.evidence.push("Runner-trusted check elapsed: -1 ms.");
    },
    (check) => {
      check.evidence.push("Runner-trusted check elapsed: 01 ms.");
    },
    (check) => {
      check.evidence.push("Runner-trusted check elapsed: 2147483648 ms.");
    },
  ]) {
    const altered = structuredClone(state);
    mutate(altered.finalizationResult.checks[0]);
    assert.throws(() => validateTrustedFinalizationEvidence(altered));
    assert.equal(project(altered), pause);
  }
  output = location(files[0]);
  status = "PASS";
  const success = await execute();
  assert.deepEqual(success.evidence, [
    "Runner-trusted command agent-runner-check exited with code 0.",
    timing,
  ]);
  assert.ok(!Object.hasOwn(success, "diagnosticInventory"));
  status = "BLOCKED";
  reason = "isolation";
  assert.ok(!(await execute()).evidence.includes(timing));
  reason = "timeout";
  const blocked = await execute();
  assert.ok(blocked.evidence.includes(timing));
  assert.ok(!blocked.evidence.includes(identity));
  assert.ok(!Object.hasOwn(blocked, "diagnosticInventory"));
  const blockedPause = {
    ...pause,
    code: "ERR_TRUSTED_VALIDATION_BLOCKED",
    resumeState: "FINALIZE",
    evidence: blocked.evidence,
  };
  validateTrustedFinalizationEvidence(state, blockedPause);
  assert.equal(
    projectTrustedFailureDiagnostics(
      { pipelineState: { trustedValidation: snapshot }, pause: blockedPause },
      blockedPause,
    ),
    blockedPause,
  );
  for (const mutate of [
    (value) => {
      value.code = "ERR_AGENT_BLOCKED";
    },
    (value) => {
      value.evidence.push("Runner-trusted check elapsed:NaN ms.");
    },
    (value) => {
      value.evidence.push(identity);
    },
  ]) {
    const altered = structuredClone(blockedPause);
    mutate(altered);
    assert.throws(() => validateTrustedFinalizationEvidence(state, altered));
    const projected = projectTrustedFailureDiagnostics(
      { pipelineState: { trustedValidation: snapshot }, pause: altered },
      altered,
    );
    assert.ok(!projected.evidence.includes(timing));
    assert.ok(!projected.evidence.includes(identity));
  }
  status = "FAIL";
  reason = "exit";
  output = files.map(location).join("");
  const bounded = await execute();
  assert.ok(
    bounded.evidence.filter((entry) =>
      entry.startsWith("Trusted check failed test file:"),
    ).length <= 8,
  );
  assert.ok(bounded.evidence.includes(OMITTED));
  output = [
    location("test/foreign.test.js"),
    location("test/../test/case-00.test.js"),
    location("./test/case-00.test.js"),
    location("test//case-00.test.js"),
    location("file://" + join(root, files[0])),
    location("test/%63ase-00.test.js"),
    location("test/\x1b[31mcase-00.test.js"),
    location("test/case-00.test.js\u202e"),
    location(`test/${"x".repeat(260)}.test.js`),
    location("x".repeat(3000)),
    `  location: '${files[0]}:1:1'\n`,
    `ok 1 - title\n  ---\n  location: '${files[0]}:1:1'\n  ...\n`,
    `not ok 1 - title\n  ---\n1..1\n  location: '${files[0]}:1:1'\n`,
  ].join("");
  assert.ok(
    !(await execute()).evidence.some((entry) =>
      entry.startsWith("Trusted check failed test file:"),
    ),
  );
  for (const control of ["\x1b[31m", "\t"]) {
    const projectPath = `${root}/${control}synthetic`;
    const collector = createDiagnosticCollector({
      projectPath,
      inventory: result.diagnosticInventory,
    });
    collector.write(
      "stdout",
      Buffer.from(location(`${projectPath}/${files[0]}`)),
    );
    assert.ok(!collector.finish().includes(identity));
  }
  const malformed = createDiagnosticCollector({
    projectPath: root,
    inventory: result.diagnosticInventory,
  });
  malformed.write(
    "stdout",
    Buffer.concat([
      Buffer.from("not ok 1 - title\n  ---\n  location: '"),
      Buffer.from([0xff]),
      Buffer.from(`${files[0]}:1:1'\n  ...\n`),
    ]),
  );
  assert.ok(!malformed.finish().includes(identity));
  rejectedPath = files[0];
  expectInventory = false;
  output = location(files[0]);
  for (rejectedInspection of [
    { exists: false },
    { kind: "symlink" },
    { ignored: true, tracked: false },
    { relativePath: "test/alias.test.js" },
  ]) {
    assert.ok(!(await execute()).evidence.includes(identity));
  }
  rejectedPath = null;
  for (const [alias, vector] of [
    ["another-check", {}],
    ["agent-runner-check", { executable: "another-npm" }],
    ["agent-runner-check", { arguments: ["run", "another-check"] }],
  ]) {
    const unsupported = createTrustedValidationSnapshot(
      {
        [alias]: {
          command: "npm run check",
          executable: "npm",
          arguments: ["run", "check"],
          ...vector,
        },
      },
      [alias],
    );
    assert.ok(!(await execute(unsupported)).evidence.includes(identity));
  }
  // Exact vector alone is insufficient when the launcher's implementation drifts.
  for (const path of [
    "scripts/format.js",
    "scripts/index.js",
    "scripts/test.js",
    "scripts/test-selection.js",
    "scripts/test-storage.js",
  ]) {
    assert.ok(inspected.includes(path));
    const original = await readFile(join(root, path));
    await writeFile(join(root, path), "// Unsupported launcher contract.\n");
    assert.ok(!(await execute()).evidence.includes(identity));
    await writeFile(join(root, path), original);
  }
  expectInventory = true;
  assert.ok((await execute()).evidence.includes(identity));
});

test("runner clock observations reject malformed clocks and omit unstarted checks", async () => {
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
  for (const pair of [
    [0, 0],
    [1, 4.2],
    [2, 1],
    [0, NaN],
    [0, Infinity],
    [0, 2147483648],
  ]) {
    const values = [...pair];
    const service = createTrustedValidationService({
      clock: () => values.shift(),
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
          status: "PASS",
          exitCode: 0,
          signal: null,
          timedOut: false,
          reason: "exit",
        };
      },
    });
    const execution = service.execute({
      projectPath: process.cwd(),
      snapshot,
      bindings,
      commandIdentity: snapshot.commands[0].identity,
    });
    if (
      Number.isFinite(pair[1]) &&
      pair[1] >= pair[0] &&
      pair[1] <= 2147483647
    ) {
      assert.ok(
        (await execution).evidence.includes(
          `Runner-trusted check elapsed: ${Math.round(pair[1] - pair[0])} ms.`,
        ),
      );
    } else
      await assert.rejects(execution, {
        code: "ERR_INVALID_TRUSTED_VALIDATION_RESULT",
      });
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
    ABORTED,
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
    `Runner check C1, issue F1: ${ABORTED}`,
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
