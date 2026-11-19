// Operator-owned acceptance after commit and whole-result review. No model use.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const args = process.argv.slice(2);
assert.ok(
  args.length === 3 &&
    args[0] === "--enable" &&
    args[1].startsWith("--candidate=") &&
    args[2].startsWith("--commit="),
  "Explicit opt-in required: --enable --candidate=/absolute/package --commit=<source-commit>",
);
const candidate = args[1].slice("--candidate=".length);
const commit = args[2].slice("--commit=".length);
assert.ok(
  isAbsolute(candidate) && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(commit),
);
const source = await realpath(fileURLToPath(new URL("../", import.meta.url)));
assert.notEqual(
  await realpath(candidate),
  source,
  "Use a separately installed candidate.",
);
const execute = promisify(execFile);
const git = async (...values) =>
  (await execute("git", values, { cwd: source })).stdout.trim();
assert.equal(
  await git("rev-parse", "HEAD"),
  commit,
  "Source must be the selected committed revision.",
);
assert.equal(await git("status", "--porcelain"), "", "Source must be clean.");
for (const name of [
  "index.js",
  "linux-process.js",
  "linux-owned-process.js",
  "linux-isolation.js",
  "ownership-diagnostic.js",
]) {
  assert.deepEqual(
    await readFile(join(source, "src/platform", name)),
    await readFile(join(candidate, "src/platform", name)),
    "Installed platform bytes must match exact committed Source.",
  );
}

const root = await mkdtemp(join(tmpdir(), "ownership-diagnostic-acceptance-"));
let resourceRetained = false;
const reports = [];
try {
  const preload = join(root, "inspection-refusal.cjs");
  // This controlled procfs failure is injected. Launch, registration, IPC and
  // verified retirement use the actual supervisor and parent in each package.
  await writeFile(
    preload,
    `
if (["session", "namespace"].includes(process.argv[1])) {
  const fs = require("node:fs");
  const list = fs.readdirSync;
  fs.readdirSync = function(path, ...args) {
    if (path === "/proc") throw Object.assign(new Error("controlled inspection refusal"), { code: "EACCES" });
    return Reflect.apply(list, this, [path, ...args]);
  };
}
`,
  );
  const expiryPreload = join(root, "preparation-expiry.cjs");
  // The parent clock permits its request. The supervisor clock observes the
  // absolute deadline when handling it, through the existing preparation check.
  await writeFile(
    expiryPreload,
    `
if (["session", "namespace"].includes(process.argv[1])) {
  process.hrtime.bigint = () => BigInt(process.argv[7]);
}
`,
  );
  for (const [label, packagePath] of [
    ["Source", source],
    ["Installed", candidate],
  ]) {
    const platform = await import(
      pathToFileURL(join(packagePath, "src/platform/index.js")).href
    );
    for (const condition of [
      "controlled-refusal",
      "delayed-start-expiry",
      "clean-retirement",
    ]) {
      let registered = null;
      const registrations = [];
      const effectPath = join(root, `${label}-${condition}.txt`);
      const expiry = condition === "delayed-start-expiry";
      const injection =
        condition === "controlled-refusal"
          ? preload
          : expiry
            ? expiryPreload
            : null;
      const child = platform.spawnOwnedProcess(
        process.execPath,
        [
          "-e",
          'require("node:fs").writeFileSync(process.argv[1], "started")',
          effectPath,
        ],
        {
          cwd: root,
          env: {
            PATH: process.env.PATH,
            ...(injection === null
              ? {}
              : { NODE_OPTIONS: `--require=${injection}` }),
          },
          ...(expiry ? { deadlineNs: "10", monotonicNow: () => 0n } : {}),
          onProcess: async (pid) => {
            registered = pid;
            registrations.push(pid);
          },
          stdio: "ignore",
        },
      );
      let result, failure;
      try {
        result = await child.ownedCompletion;
      } catch (cause) {
        failure = cause;
      }
      resourceRetained ||= registered !== null;
      assert.equal(
        registered,
        null,
        "Actual retirement and deregistration must complete.",
      );
      assert.equal(registrations.length, 2);
      assert.ok(Number.isSafeInteger(registrations[0]) && registrations[0] > 0);
      assert.equal(registrations[1], null);
      assert.equal(
        child.ownedPayloadRequested,
        true,
        "Parent must actually request start.",
      );
      if (expiry) {
        assert.equal(failure, undefined);
        assert.equal(child.ownedPreparationExpired, true);
        assert.deepEqual(result.outcome, {
          type: "close",
          exitCode: null,
          signal: null,
        });
        assert.equal(result.inspectionComplete, true);
        assert.equal(result.descendantsActive, false);
        await assert.rejects(readFile(effectPath), { code: "ENOENT" });
        reports.push({
          label,
          condition,
          execution: "real-supervisor-ipc",
          preparationClockCondition: "injected",
          inspectionCondition: "native",
          startRequested: true,
          preparationExpired: true,
          targetEffect: false,
          retirementVerified: true,
          ownershipDiagnostic: null,
        });
        continue;
      }
      assert.equal(await readFile(effectPath, "utf8"), "started");
      if (condition === "controlled-refusal") {
        assert.equal(failure?.code, "ERR_EXECUTION_PROCESS_UNVERIFIABLE");
        const diagnostic = platform.ownershipDiagnosticFrom(failure);
        assert.equal(diagnostic?.site, "parent-containment-relay");
        assert.equal(diagnostic.branch, "finish-inspection-deadline");
        assert.equal(diagnostic.startRequested, true);
        assert.equal(diagnostic.terminationRequested, false);
        assert.equal(diagnostic.ownershipHandedOff, false);
        reports.push({
          label,
          condition,
          execution: "real-supervisor-ipc",
          inspectionCondition: "injected",
          ownershipDiagnostic: diagnostic,
        });
      } else {
        assert.equal(failure, undefined);
        assert.equal(result.outcome.type, "close");
        assert.equal(result.outcome.exitCode, 0);
        reports.push({
          label,
          condition,
          execution: "real-supervisor-ipc",
          inspectionCondition: "native",
          ownershipDiagnostic: null,
        });
      }
    }
  }
  process.stdout.write(
    `${JSON.stringify({ sourceCommit: commit, platformBytes: "identical", reports })}\n`,
  );
} finally {
  // Uncertain retirement retains its owned fixture storage for supported recovery.
  if (!resourceRetained) await rm(root, { recursive: true, force: true });
}
