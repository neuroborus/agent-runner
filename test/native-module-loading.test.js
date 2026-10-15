import { execFile } from "node:child_process";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);

test("the native index loads first in a fresh process without output", async () => {
  const { stdout, stderr } = await execute(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      "await import(process.argv[1]);",
      new URL("../ci/native/index.js", import.meta.url).href,
    ],
    { timeout: 10000, maxBuffer: 16384 },
  );
  assert.equal(stdout, "");
  assert.equal(stderr, "");
});

test("the Linux proof entry initializes directly with unchanged bounds", async () => {
  const proofUrl = new URL("../ci/native/linux/proof.js", import.meta.url);
  const options = { timeout: 10000, maxBuffer: 16384, env: {} };
  const direct = await execute(
    process.execPath,
    [fileURLToPath(proofUrl)],
    options,
  );
  assert.equal(direct.stdout, "");
  assert.equal(direct.stderr, "");

  const { stdout, stderr } = await execute(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const proof = await import(process.argv[1]);
       const system = await import(process.argv[2]);
       const ci = await import(process.argv[3]);
       const { systemJobBounds } = await import(process.argv[4]);
       process.stdout.write(JSON.stringify({
         buildMs: proof.LINUX_FILE_PROOF_BUILD_MS,
         systemBounds: system.LINUX_SYSTEM_BOUNDS,
         systemProbeMs: system.LINUX_SYSTEM_PROBE_MS,
         systemStepMinutes: system.LINUX_SYSTEM_STEP_MINUTES,
         systemJobMinutes: system.LINUX_SYSTEM_JOB_MINUTES,
         preparationMs: ci.LINUX_SYSTEM_PREPARATION_MS,
         workflowBounds: systemJobBounds("linux"),
       }));`,
      proofUrl.href,
      new URL("../ci/native/linux/system.js", import.meta.url).href,
      new URL("../ci/native/linux/ci.js", import.meta.url).href,
      new URL("../ci/native/system-inventory.js", import.meta.url).href,
    ],
    options,
  );
  assert.equal(stderr, "");
  assert.deepEqual(JSON.parse(stdout), {
    buildMs: 70000,
    systemBounds: {
      harness: 30000,
      ownership: 345000,
      access: 300000,
      build: 70000,
      files: 1060000,
      release: 220000,
    },
    systemProbeMs: 2025000,
    systemStepMinutes: 35,
    systemJobMinutes: 53,
    preparationMs: 520000,
    workflowBounds: {
      preparationMs: 520000,
      probeMs: 2415000,
      cleanupMs: 120000,
      preparationMinutes: 10,
      probeMinutes: 42,
      cleanupMinutes: 3,
      bootstrapMinutes: 4,
      jobMinutes: 75,
    },
  });
});

test("the Darwin experiment index exposes complete effect-free preparation owners", async () => {
  const api = await import("../ci/native/darwin/index.js");
  for (const name of [
    "prepareDarwinExperiment",
    "loadDarwinExperiment",
    "recoverDarwinExperimentPreparation",
    "createDarwinExperimentSystemEffects",
  ])
    assert.equal(typeof api[name], "function");
});
