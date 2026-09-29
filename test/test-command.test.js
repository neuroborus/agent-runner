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
  for (const [file, name, fails] of [
    ["fast.test.js", "fast", false],
    ["timing.slow.test.js", "timed-slow", false],
    ["recovery.slow.test.js", "slow", true],
  ]) {
    await writeFile(
      join(root, "test", file),
      `
import test from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
test("${name} boundary", () => {
  writeFileSync("${name}.ran", process.env.TMPDIR);
  assert.equal(${fails}, false, "deliberate command failure");
});
`,
    );
  }
  const env = { ...process.env, AGENT_RUNNER_TEST_TMPDIR: storage };
  delete env.NODE_TEST_CONTEXT;
  const run = (...args) =>
    execute(process.execPath, [script, ...args], { cwd: root, env });

  const fast = await run();
  assert.match(fast.stderr, /Tests: 1 files/u);
  assert.match(fast.stdout, /^\.+\n$/u);
  assert.ok(
    (await readFile(join(root, "fast.ran"), "utf8")).startsWith(storage + "/"),
  );
  await assert.rejects(readFile(join(root, "slow.ran")), { code: "ENOENT" });
  assert.deepEqual(await readdir(storage), []);

  await assert.rejects(run("--slow"), (error) => {
    assert.equal(error.code, 1);
    assert.match(
      error.stdout,
      /^✔ (?:timed-slow boundary|test\/timing\.slow\.test\.js) \(\d+(?:\.\d+)?(?:ms|s)\)$/mu,
    );
    assert.match(error.stdout, /slow boundary/u);
    assert.match(error.stdout, /deliberate command failure/u);
    assert.match(error.stdout, /AssertionError/u);
    assert.match(error.stdout, /at TestContext/u);
    assert.match(
      error.stderr,
      /Failure diagnostics: test\/recovery\.slow\.test\.js/u,
    );
    return true;
  });
  await Promise.all([
    readFile(join(root, "slow.ran")),
    readFile(join(root, "timed-slow.ran")),
  ]);
  assert.deepEqual(await readdir(storage), []);
  await run("test/fast.test.js");
  assert.deepEqual(await readdir(storage), []);

  await assert.rejects(
    execute(process.execPath, [script], {
      cwd: root,
      env: { ...env, AGENT_RUNNER_TEST_TMPDIR: join(root, "missing") },
    }),
    { code: 1 },
  );
});
