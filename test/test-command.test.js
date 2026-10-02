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
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { temporaryRoots } from "../scripts/test-storage.js";
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
  await Promise.all([mkdir(join(root, "test")), mkdir(storage)]);
  const fixture = (name, fails) => `
import test from "node:test";
import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
test("${name} boundary", () => {
  appendFileSync("${name}.ran", process.env.TMPDIR + "\\n");
  assert.equal(${fails}, false, "deliberate command failure");
});
`;
  for (const [file, name, fails] of [
    ["fast.test.js", "fast", false],
    ["timing.slow.test.js", "timed-slow", false],
    ["recovery.slow.test.js", "slow", true],
  ]) {
    await writeFile(join(root, "test", file), fixture(name, fails));
  }
  const env = { ...process.env, AGENT_RUNNER_TEST_TMPDIR: storage };
  delete env.NODE_TEST_CONTEXT;
  const run = (...args) =>
    execute(process.execPath, [script, ...args], { cwd: root, env });
  const invocations = async (name) =>
    (await readFile(join(root, `${name}.ran`), "utf8")).trimEnd().split("\n");
  const assertFailure = (error, name, path) => {
    assert.equal(error.code, 1);
    assert.ok(error.stdout.includes(`${name} boundary`));
    assert.match(error.stdout, /deliberate command failure/u);
    assert.match(error.stdout, /AssertionError/u);
    assert.match(error.stdout, /at TestContext/u);
    assert.ok(error.stdout.includes(`test at ${path}:`));
    return true;
  };

  const fast = await run();
  assert.match(fast.stderr, /Tests: 1 files/u);
  assert.match(fast.stdout, /^\.+\n$/u);
  assert.ok(
    (await readFile(join(root, "fast.ran"), "utf8")).startsWith(storage + "/"),
  );
  await assert.rejects(readFile(join(root, "slow.ran")), { code: "ENOENT" });
  assert.deepEqual(await readdir(storage), []);

  await assert.rejects(run("--slow"), (error) => {
    assertFailure(error, "slow", "test/recovery.slow.test.js");
    assert.match(
      error.stdout,
      /^✔ (?:timed-slow boundary|test\/timing\.slow\.test\.js) \(\d+(?:\.\d+)?(?:ms|s)\)$/mu,
    );
    return true;
  });
  assert.equal((await invocations("slow")).length, 1);
  assert.equal((await invocations("timed-slow")).length, 1);
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

  await run("test/fast.test.js");
  assert.equal((await invocations("fast")).length, 2);
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
