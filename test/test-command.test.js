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
  delete env.AGENT_RUNNER_SCRATCH;
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

test("requested reports collect original failures from both fast batches and selected slow files without nested overwrite", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "test-command-report-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const storage = join(root, "storage");
  const scratch = join(root, "scratch");
  const attribution = join(scratch, ".agent-runner-test-attribution");
  await Promise.all([
    mkdir(join(root, "test")),
    mkdir(storage),
    mkdir(attribution, { recursive: true, mode: 0o700 }),
  ]);
  const request = { nonce: "a".repeat(64), commandIdentity: "b".repeat(64) };
  const reset = async () => {
    await rm(join(attribution, "claim"), { force: true });
    for (const [name, value] of [
      ["request", request],
      ["report", { ...request, locations: [] }],
    ]) {
      await writeFile(join(attribution, name), JSON.stringify(value), {
        mode: 0o600,
      });
    }
  };
  await reset();
  for (const file of [
    "first.test.js",
    "trusted-validation.test.js",
    "selected.slow.test.js",
    "nested.test.js",
  ]) {
    await writeFile(
      join(root, "test", file),
      `
import test from "node:test";
import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(join(root, "invocations"))}, ${JSON.stringify(file + "\n")});
test("private failure title", () => {
  if (${file !== "selected.slow.test.js"} || process.env.NODE_TEST_CONTEXT) assert.fail("private assertion value");
  appendFileSync(${JSON.stringify(join(root, "diagnostic-passed"))}, "passed\\n");
});
`,
    );
  }
  await writeFile(
    join(root, "test/first.test.js"),
    `
import { spawnSync } from "node:child_process";
import { strictEqual } from "node:assert";
const env = { ...process.env };
delete env.NODE_TEST_CONTEXT;
const nested = spawnSync(process.execPath, [${JSON.stringify(script)}, "test/nested.test.js"], { env, stdio: "ignore" });
strictEqual(nested.status, 1);
` + (await readFile(join(root, "test/first.test.js"), "utf8")),
  );
  const env = {
    ...process.env,
    AGENT_RUNNER_TEST_TMPDIR: storage,
    AGENT_RUNNER_SCRATCH: scratch,
  };
  delete env.NODE_TEST_CONTEXT;
  const run = (...args) =>
    execute(process.execPath, [script, ...args], { cwd: root, env });
  await assert.rejects(
    run("test/first.test.js", "test/trusted-validation.test.js"),
    (error) => {
      assert.equal(error.code, 1);
      assert.equal(error.stdout, "");
      assert.equal((error.stderr.match(/Test batch:/gu) ?? []).length, 2);
      assert.doesNotMatch(error.stderr, /private|Failure diagnostics/u);
      return true;
    },
  );
  const fast = JSON.parse(await readFile(join(attribution, "report"), "utf8"));
  assert.deepEqual(
    new Set(fast.locations.map(({ path }) => path)),
    new Set(["test/first.test.js", "test/trusted-validation.test.js"]),
  );
  const invocations = (await readFile(join(root, "invocations"), "utf8"))
    .trim()
    .split("\n")
    .sort();
  assert.deepEqual(invocations, [
    "first.test.js",
    "nested.test.js",
    "trusted-validation.test.js",
  ]);
  assert.deepEqual(await readdir(storage), []);

  await reset();
  await assert.rejects(run("--slow", "test/selected.slow.test.js"), (error) => {
    assert.equal(error.code, 1);
    assert.equal(error.stdout, "");
    assert.match(error.stderr, /Tests: 1 files/u);
    return true;
  });
  const text = await readFile(join(attribution, "report"), "utf8");
  const slow = JSON.parse(text);
  assert.equal(slow.nonce, request.nonce);
  assert.equal(slow.commandIdentity, request.commandIdentity);
  assert.deepEqual(
    slow.locations.map(({ path, class: kind }) => [path, kind]),
    [["test/selected.slow.test.js", "test-failure"]],
  );
  assert.doesNotMatch(text, /private|AssertionError|stack|stdout|stderr/u);
  const ordinaryEnv = { ...env };
  delete ordinaryEnv.AGENT_RUNNER_SCRATCH;
  await assert.rejects(
    execute(
      process.execPath,
      [script, "--slow", "test/selected.slow.test.js"],
      {
        cwd: root,
        env: ordinaryEnv,
      },
    ),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(
        error.stderr,
        /Failure diagnostics: test\/selected\.slow\.test\.js/u,
      );
      return true;
    },
  );
  assert.equal(
    await readFile(join(root, "diagnostic-passed"), "utf8"),
    "passed\n",
  );
  assert.equal(await readFile(join(attribution, "report"), "utf8"), text);
  assert.deepEqual(await readdir(storage), []);
});
