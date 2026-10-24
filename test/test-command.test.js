import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { availableParallelism, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { temporaryRoots } from "../scripts/test-storage.js";
import { createDiagnosticCollector } from "../src/trusted-validation/diagnostics.js";
import {
  createTrustedValidationSnapshot,
  projectTrustedFailureDiagnostics,
} from "../src/trusted-validation/index.js";
import { STORAGE_PATHS } from "../src/trusted-validation/resources.js";

const execute = promisify(execFile);
const script = fileURLToPath(new URL("../scripts/test.js", import.meta.url));

test("temporary roots honor overrides without filtering or fallback", () => {
  for (const override of ["test-storage", "/run/agent-runner/scratch"]) {
    assert.deepEqual(
      temporaryRoots({
        override,
        runtimeRoot: "/run/user/1000",
        systemRoot: "/tmp",
      }),
      [resolve(override)],
    );
  }
});

test("temporary roots preserve ordinary host ordering", () => {
  assert.deepEqual(
    temporaryRoots({ runtimeRoot: "/run/user/1000", systemRoot: "/tmp" }),
    ["/run/user/1000", "/tmp"],
  );
  assert.deepEqual(temporaryRoots({ override: "", systemRoot: "/var/tmp" }), [
    "/var/tmp",
  ]);
  assert.deepEqual(
    temporaryRoots({
      runtimeRoot: "/run/agent-runner-other",
      systemRoot: "/run/agent-runner-other/tmp",
    }),
    ["/run/agent-runner-other", "/run/agent-runner-other/tmp"],
  );
});

test("temporary roots replace reserved system storage and drop reserved runtime storage", () => {
  assert.deepEqual(temporaryRoots({ systemRoot: "/run/agent-runner" }), [
    "/tmp",
  ]);
  assert.deepEqual(
    temporaryRoots({
      runtimeRoot: "/run/user/1000",
      systemRoot: "/run/agent-runner/scratch",
    }),
    ["/run/user/1000", "/tmp"],
  );
  assert.deepEqual(
    temporaryRoots({
      runtimeRoot: "/run/agent-runner/scratch/nested",
      systemRoot: "/var/tmp",
    }),
    ["/var/tmp"],
  );
});

test("temporary roots reject every fixed trusted storage mount", () => {
  for (const root of Object.values(STORAGE_PATHS)) {
    assert.deepEqual(temporaryRoots({ runtimeRoot: root, systemRoot: root }), [
      "/tmp",
    ]);
  }
});

test("test command partitions coverage, propagates failures, and cleans private storage", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "test-command-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const storage = join(root, "scratch");
  await Promise.all(
    [
      "test/nested",
      "test/agents",
      "pipelines/sample/test/nested",
      "packages/sample/test/nested",
      "scratch",
    ].map((path) => mkdir(join(root, path), { recursive: true })),
  );
  const ordinaryNames = ["fast", "nested", "workspace", "package"];
  const fixture = (name, fails, predecessors = []) => `
import test from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, existsSync, writeFileSync } from "node:fs";
test("${name} boundary", (t) => {
  for (const name of ${JSON.stringify(predecessors)}) {
    assert.ok(existsSync(name + ".finished"), "ordinary fixture cleanup precedes containment");
  }
  t.after(() => writeFileSync("${name}.finished", ""));
  appendFileSync("${name}.ran", process.env.TMPDIR + "\\n");
  assert.equal(${fails}, false, "deliberate command failure");
});
`;
  for (const [file, name, fails, predecessors] of [
    ["test/fast.test.js", "fast", false],
    ["test/nested/fast.test.js", "nested", false],
    ["pipelines/sample/test/nested/fast.test.js", "workspace", false],
    ["packages/sample/test/nested/fast.test.js", "package", false],
    ["test/agents/owned-process.test.js", "contained", false, ordinaryNames],
    ["test/trusted-validation.test.js", "validation", false, ordinaryNames],
    ["pipelines/sample/test/timing.slow.test.js", "timed-slow", false],
    ["packages/sample/test/recovery.slow.test.js", "package-slow", false],
    ["test/recovery.slow.test.js", "slow", true],
  ]) {
    await writeFile(join(root, file), fixture(name, fails, predecessors));
  }
  const env = { ...process.env, AGENT_RUNNER_TEST_TMPDIR: storage };
  delete env.NODE_TEST_CONTEXT;
  const run = (...args) =>
    execute(process.execPath, [script, ...args], { cwd: root, env });
  const invocations = async (name) =>
    (await readFile(join(root, `${name}.ran`), "utf8")).trimEnd().split("\n");
  const assertFailure = (error, name, path, tap = true) => {
    assert.equal(error.code, 1);
    assert.ok(error.stdout.includes(`${name} boundary`));
    assert.match(error.stdout, /deliberate command failure/u);
    assert.match(error.stdout, /AssertionError/u);
    assert.match(error.stdout, /at TestContext/u);
    if (tap) {
      assert.match(error.stdout, /^TAP version 13$/mu);
      assert.ok(error.stdout.includes(`location: '${join(root, path)}:`));
    } else {
      assert.ok(error.stdout.includes(`test at ${path}:`));
    }
    return true;
  };

  const fast = await run();
  assert.ok(
    fast.stderr.includes(
      `Tests: 6 files; concurrency: up to ${Math.min(8, availableParallelism())};`,
    ),
  );
  assert.ok(
    fast.stderr.includes(
      `Test batch: 4 files; concurrency: ${Math.min(8, availableParallelism())}`,
    ),
  );
  assert.ok(
    fast.stderr.includes(
      `Test batch: 2 files; concurrency: ${Math.min(4, availableParallelism())}`,
    ),
  );
  assert.equal(fast.stdout, "....\n..\n");
  for (const name of [...ordinaryNames, "contained", "validation"]) {
    const recorded = await invocations(name);
    assert.equal(recorded.length, 1);
    assert.ok(recorded[0].startsWith(`${storage}/`));
  }
  for (const name of ["slow", "timed-slow", "package-slow"])
    await assert.rejects(readFile(join(root, `${name}.ran`)), {
      code: "ENOENT",
    });
  assert.deepEqual(await readdir(storage), []);

  await assert.rejects(run("--slow"), (error) => {
    assertFailure(error, "slow", "test/recovery.slow.test.js", false);
    assert.ok(
      error.stderr.includes(
        `Tests: 3 files; concurrency: up to ${Math.min(4, availableParallelism())};`,
      ),
    );
    assert.doesNotMatch(error.stderr, /Test batch:/u);
    assert.match(
      error.stdout,
      /^✔ (?:timed-slow boundary|pipelines\/sample\/test\/timing\.slow\.test\.js) \(\d+(?:\.\d+)?(?:ms|s)\)$/mu,
    );
    return true;
  });
  assert.equal((await invocations("slow")).length, 1);
  assert.equal((await invocations("timed-slow")).length, 1);
  assert.equal((await invocations("package-slow")).length, 1);
  for (const name of [...ordinaryNames, "contained", "validation"])
    assert.equal((await invocations(name)).length, 1);
  assert.deepEqual(await readdir(storage), []);

  // The title resembles a filename but is deliberately unrelated to the file.
  const failedName = "misleading-title.test.js";
  await writeFile(
    join(root, "test/failure.test.js"),
    fixture(failedName, true),
  );
  await assert.rejects(run("test/failure.test.js"), (error) =>
    assertFailure(error, failedName, "test/failure.test.js"),
  );
  const failedInvocations = await invocations(failedName);
  assert.equal(failedInvocations.length, 1);
  assert.ok(failedInvocations[0].startsWith(`${storage}/`));
  assert.deepEqual(await readdir(storage), []);

  const selected = await run("test/fast.test.js");
  assert.match(selected.stdout, /^\.+\n$/u);
  assert.match(selected.stderr, /Tests: 1 files/u);
  assert.doesNotMatch(selected.stderr, /Test batch:/u);
  assert.equal((await invocations("fast")).length, 2);
  assert.deepEqual(await readdir(storage), []);

  const selectedSlow = await run(
    "--slow",
    "pipelines/sample/test/timing.slow.test.js",
  );
  assert.match(selectedSlow.stderr, /Tests: 1 files/u);
  assert.match(
    selectedSlow.stdout,
    /^✔ (?:timed-slow boundary|pipelines\/sample\/test\/timing\.slow\.test\.js) \(\d+(?:\.\d+)?(?:ms|s)\)$/mu,
  );
  assert.equal((await invocations("timed-slow")).length, 2);
  assert.equal((await invocations("slow")).length, 1);
  assert.equal((await invocations("package-slow")).length, 1);
  assert.deepEqual(await readdir(storage), []);

  await assert.rejects(
    execute(process.execPath, [script], {
      cwd: root,
      env: { ...env, AGENT_RUNNER_TEST_TMPDIR: join(root, "missing") },
    }),
    { code: 1 },
  );
  assert.deepEqual(await readdir(storage), []);
});

test("opaque subtest failures retain native TAP classifications without exposing private diagnostics", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "test-command-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const storage = join(root, "scratch");
  await Promise.all([mkdir(join(root, "test")), mkdir(storage)]);
  await writeFile(
    join(root, "test/opaque.test.js"),
    `
import test from "node:test";
import { appendFileSync } from "node:fs";
test("opaque parent", async (t) => {
  await t.test("opaque child", () => {
    appendFileSync("opaque.ran", process.env.TMPDIR + "\\n");
    throw {
      detail: "opaque child detail",
      actual: "synthetic actual value",
      expected: "synthetic expected value",
      stack: "synthetic stack at opaque-helper.js:1:1",
      environment: process.env.SYNTHETIC_PRIVATE_VALUE,
    };
  });
});
`,
  );
  const privateValue = "synthetic private environment";
  const env = {
    ...process.env,
    AGENT_RUNNER_TEST_TMPDIR: storage,
    SYNTHETIC_PRIVATE_VALUE: privateValue,
  };
  delete env.NODE_TEST_CONTEXT;
  let failure;
  await assert.rejects(
    execute(process.execPath, [script, "test/opaque.test.js"], {
      cwd: root,
      env,
    }),
    (error) => {
      failure = error;
      assert.equal(error.code, 1);
      return true;
    },
  );
  const report = failure.stdout;
  assert.match(report, /^TAP version 13$/mu);
  const tap = report.slice(report.indexOf("TAP version 13\n"));
  assert.match(tap, /^    not ok 1 - opaque child$/mu);
  assert.match(tap, /^not ok 1 - opaque parent$/mu);
  assert.match(tap, /^      failureType: 'testCodeFailure'$/mu);
  assert.match(tap, /^  failureType: 'subtestsFailed'$/mu);
  assert.equal((tap.match(/code: 'ERR_TEST_FAILURE'/gu) ?? []).length, 2);
  const recorded = (await readFile(join(root, "opaque.ran"), "utf8"))
    .trimEnd()
    .split("\n");
  assert.equal(recorded.length, 1);
  assert.ok(recorded[0].startsWith(`${storage}/`));
  assert.deepEqual(await readdir(storage), []);

  const collector = createDiagnosticCollector();
  collector.write("stdout", Buffer.from(report));
  const diagnostics = collector.finish();
  assert.deepEqual([...diagnostics].sort(), [
    "Trusted check diagnostics omitted unsupported, unsafe, malformed or oversized output.",
    "Trusted check error class: ERR_TEST_FAILURE.",
    "Trusted check failed stage: tests.",
    "Trusted check test failure type: subtestsFailed.",
    "Trusted check test failure type: testCodeFailure.",
  ]);
  const located = createDiagnosticCollector({
    projectPath: root,
    inventory: { files: ["test/opaque.test.js"] },
  });
  located.write("stdout", Buffer.from(report));
  assert.ok(
    located
      .finish()
      .includes("Trusted check failed test file: test/opaque.test.js."),
  );
  const command = "node scripts/test.js test/opaque.test.js";
  const trustedValidation = createTrustedValidationSnapshot(
    {
      opaque: {
        command,
        executable: process.execPath,
        arguments: [script, "test/opaque.test.js"],
      },
    },
    ["opaque"],
  );
  const requiredChecks = [{ id: "C1", command }];
  const fingerprint = "a".repeat(64);
  const validationInfrastructureFingerprint = "b".repeat(64);
  const evidence = [
    "Runner-trusted command opaque exited with code 1.",
    ...diagnostics,
  ];
  const run = {
    pipelineState: {
      trustedValidation,
      currentStep: 1,
      repositoryBaseline: { contentFingerprint: fingerprint },
      requiredChecks,
      validationInfrastructure: [],
      validationInfrastructureFingerprint,
      finalizationResult: {
        status: "FAIL",
        step: 1,
        fingerprint,
        validationChanged: false,
        validationInfrastructure: [],
        validationInfrastructureFingerprint,
        trustedCommandFingerprint: trustedValidation.commandFingerprint,
        trustedConfigurationFingerprint:
          trustedValidation.configurationFingerprint,
        requiredChecks,
        checks: [
          {
            checkId: "C1",
            command,
            status: "FAIL",
            executor: "runner",
            commandIdentity: trustedValidation.commands[0].identity,
            exitCode: failure.code,
            signal: null,
            timedOut: false,
            evidence,
          },
        ],
        issues: [
          {
            id: "F1",
            command,
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
    ...diagnostics.map((value) => `Runner check C1, issue F1: ${value}`),
    ...pause.evidence,
  ]);
  assert.equal(projected.nextActions, pause.nextActions);
  for (const value of [
    "opaque parent",
    "opaque child",
    "opaque child detail",
    "synthetic actual value",
    "synthetic expected value",
    "synthetic stack at opaque-helper.js:1:1",
    privateValue,
    root,
    "opaque.test.js",
  ]) {
    assert.ok(report.includes(value), `Original report retains ${value}`);
    assert.ok(!JSON.stringify(projected).includes(value));
  }
});
