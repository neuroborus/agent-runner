import { spawnSync } from "node:child_process";
import {
  closeSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statfsSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { availableParallelism, tmpdir } from "node:os";
import { join } from "node:path";

import { temporaryRoots } from "./test-storage.js";
import { selectTestFiles } from "./test-selection.js";

const CONTAINMENT_TESTS = new Set([
  "test/agents/owned-process.test.js",
  "test/trusted-validation.test.js",
]);

function report(message) {
  writeSync(process.stderr.fd, `${message}\n`);
}

function forward(fd, output) {
  if (output.length > 0) writeSync(fd, output);
}

function runCaptured(argumentsList, outputPath, env) {
  const output = openSync(outputPath, "w");
  let result;
  try {
    result = spawnSync(process.execPath, argumentsList, {
      env,
      stdio: ["ignore", output, output],
    });
  } finally {
    closeSync(output);
  }
  const content = readFileSync(outputPath, "utf8");
  rmSync(outputPath);
  return { content, result };
}

// Keep the real filesystem and fsync calls without charging every fixture for
// physical-disk latency. Never change the runner's own storage policy.
function temporaryDirectory() {
  // /dev/shm is hidden by the owned-process namespace's private /dev mount.
  const runtimeDirectory =
    process.env.XDG_RUNTIME_DIR ??
    (process.platform === "linux"
      ? `/run/user/${process.getuid()}`
      : undefined);
  let memoryRoot;
  try {
    if (runtimeDirectory && statfsSync(runtimeDirectory).type === 0x01021994)
      memoryRoot = runtimeDirectory;
  } catch {
    // A runtime tmpfs is optional; the system temporary directory remains valid.
  }
  const roots = temporaryRoots({
    override: process.env.AGENT_RUNNER_TEST_TMPDIR,
    runtimeRoot: memoryRoot,
    systemRoot: tmpdir(),
  });
  for (const root of roots) {
    let directory;
    try {
      directory = mkdtempSync(join(root, "agent-runner-tests-"));
      const probe = join(directory, "executable-probe");
      writeFileSync(probe, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
      if (spawnSync(probe).status !== 0) {
        throw new Error("Test storage must permit executable fixtures.");
      }
      rmSync(probe);
      return directory;
    } catch (error) {
      if (directory) rmSync(directory, { recursive: true, force: true });
      if (process.env.AGENT_RUNNER_TEST_TMPDIR) throw error;
    }
  }
  throw new Error("No writable, executable temporary test directory.");
}

const { slow, files } = selectTestFiles(process.argv.slice(2));

const directory = temporaryDirectory();
const concurrency = Math.min(slow ? 4 : 8, availableParallelism());
const batches = slow
  ? [{ concurrency, files }]
  : [
      {
        concurrency,
        files: files.filter((path) => !CONTAINMENT_TESTS.has(path)),
      },
      {
        concurrency: Math.min(4, availableParallelism()),
        files: files.filter((path) => CONTAINMENT_TESTS.has(path)),
      },
    ].filter((batch) => batch.files.length > 0);
const started = performance.now();
try {
  report(
    `Tests: ${files.length} files; concurrency: up to ${concurrency}; temporary storage: ${directory}`,
  );
  const env = {
    ...process.env,
    TMPDIR: directory,
    TMP: directory,
    TEMP: directory,
  };
  let exitCode = 0;
  for (const [index, batch] of batches.entries()) {
    if (batches.length > 1) {
      report(
        `Test batch: ${batch.files.length} files; concurrency: ${batch.concurrency}`,
      );
    }
    const diagnosticPath = join(directory, `test-diagnostics-${index}.log`);
    const reporters = slow
      ? ["--test-reporter=spec"]
      : [
          "--test-reporter=dot",
          "--test-reporter-destination=stdout",
          "--test-reporter=tap",
          `--test-reporter-destination=${diagnosticPath}`,
        ];
    const captured = runCaptured(
      [
        "--test",
        `--test-concurrency=${batch.concurrency}`,
        ...reporters,
        ...batch.files,
      ],
      join(directory, `test-output-${index}.log`),
      env,
    );
    if (captured.result.error) throw captured.result.error;
    forward(process.stdout.fd, captured.content);
    if (!slow && captured.result.status !== 0) {
      try {
        forward(process.stdout.fd, readFileSync(diagnosticPath, "utf8"));
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
        // Setup failure or a signal can precede reporter-file creation.
        // Preserve the original captured output and exit/signal outcome.
        report(
          "TAP diagnostics were unavailable for the failed test invocation.",
        );
      }
    }
    if (captured.result.status !== 0 && exitCode === 0) {
      exitCode = captured.result.status ?? 1;
    }
    if (captured.result.signal) {
      report(`Tests terminated by ${captured.result.signal}.`);
    }
  }
  process.exitCode = exitCode;
} finally {
  rmSync(directory, { recursive: true, force: true });
  report(
    `Tests elapsed: ${((performance.now() - started) / 1000).toFixed(1)}s`,
  );
}
