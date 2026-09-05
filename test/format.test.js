import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import packageMetadata from "../package.json" with { type: "json" };

const executeFile = promisify(execFile);
const FORMAT_SCRIPT = fileURLToPath(
  new URL("../scripts/format.js", import.meta.url),
);
const PRETTIER_VERSION = "3.9.6";

test("root metadata pins the repository formatting and test gates", async () => {
  const lockfile = JSON.parse(
    await readFile(new URL("../package-lock.json", import.meta.url), "utf8"),
  );

  assert.equal(packageMetadata.devDependencies.prettier, PRETTIER_VERSION);
  assert.equal(
    lockfile.packages[""].devDependencies.prettier,
    PRETTIER_VERSION,
  );
  assert.equal(
    lockfile.packages["node_modules/prettier"].version,
    PRETTIER_VERSION,
  );
  assert.deepEqual(packageMetadata.scripts, {
    check: "npm run format:check && npm test && node bin/agent-run.js --help",
    format: "node scripts/format.js --write",
    "format:check": "node scripts/format.js --check",
    test: "node --test --test-concurrency=8 --test-reporter=dot",
  });
});

test("compact test output preserves diagnostics from one failed run", async (t) => {
  const fixtureDirectory = await mkdtemp(
    join(tmpdir(), "agent-runner-test-reporter-"),
  );
  t.after(() => rm(fixtureDirectory, { force: true, recursive: true }));
  const fixturePath = join(fixtureDirectory, "compact-failure.test.mjs");
  const reportPath = join(fixtureDirectory, "compact-report.txt");
  await writeFile(
    fixturePath,
    `import assert from "node:assert/strict";
import test from "node:test";

test("reports the deliberate compact failure", () => {
  assert.equal("actual-value", "expected-value", "compact assertion diagnostic");
});
`,
  );

  const environment = { ...process.env };
  // Keep the nested fixture independent from the outer Node test process.
  delete environment.NODE_TEST_CONTEXT;
  await assert.rejects(
    executeFile(
      process.execPath,
      [
        "--test-reporter=dot",
        `--test-reporter-destination=${reportPath}`,
        fixturePath,
      ],
      { env: environment },
    ),
    (error) => error.code === 1,
  );
  const diagnostics = await readFile(reportPath, "utf8");
  assert.match(diagnostics, /reports the deliberate compact failure/u);
  assert.match(diagnostics, /AssertionError \[ERR_ASSERTION\]/u);
  assert.match(diagnostics, /compact assertion diagnostic/u);
  assert.match(diagnostics, /actual-value/u);
  assert.match(diagnostics, /expected-value/u);
  assert.match(diagnostics, /at TestContext\.<anonymous>/u);
});

test("formatter writes idempotently and rejects a non-ignored probe", async (t) => {
  const repositoryPath = await mkdtemp(join(tmpdir(), "agent-runner-format-"));
  t.after(() => rm(repositoryPath, { force: true, recursive: true }));
  await executeFile("git", ["init", "--quiet"], { cwd: repositoryPath });
  await Promise.all([
    writeFile(join(repositoryPath, ".gitignore"), "ignored.js\n"),
    writeFile(
      join(repositoryPath, "source.js"),
      "export  const value={answer:42}\n",
    ),
    writeFile(
      join(repositoryPath, "ignored.js"),
      "export  const ignored={answer:42}\n",
    ),
    mkdir(join(repositoryPath, "nested")),
  ]);
  await writeFile(
    join(repositoryPath, ".git", "info", "exclude"),
    "nested/local.js\n",
  );
  await writeFile(
    join(repositoryPath, "nested", "local.js"),
    "export  const local={answer:42}\n",
  );

  await executeFile(process.execPath, [FORMAT_SCRIPT, "--write"], {
    cwd: repositoryPath,
  });
  const formattedOnce = await readFile(
    join(repositoryPath, "source.js"),
    "utf8",
  );
  assert.equal(formattedOnce, "export const value = { answer: 42 };\n");
  assert.equal(
    await readFile(join(repositoryPath, "ignored.js"), "utf8"),
    "export  const ignored={answer:42}\n",
  );
  assert.equal(
    await readFile(join(repositoryPath, "nested", "local.js"), "utf8"),
    "export  const local={answer:42}\n",
  );

  await executeFile(process.execPath, [FORMAT_SCRIPT, "--write"], {
    cwd: repositoryPath,
  });
  assert.equal(
    await readFile(join(repositoryPath, "source.js"), "utf8"),
    formattedOnce,
  );
  await executeFile(process.execPath, [FORMAT_SCRIPT, "--check"], {
    cwd: repositoryPath,
  });

  await writeFile(
    join(repositoryPath, "probe.js"),
    "export  const probe={answer:42}\n",
  );
  await assert.rejects(
    executeFile(process.execPath, [FORMAT_SCRIPT, "--check"], {
      cwd: repositoryPath,
    }),
    (error) => error.code === 1,
  );
  assert.equal(
    await readFile(join(repositoryPath, "probe.js"), "utf8"),
    "export  const probe={answer:42}\n",
  );
});
