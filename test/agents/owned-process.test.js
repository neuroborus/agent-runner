import assert from "node:assert/strict";
import { realpathSync } from "node:fs";
import { dirname } from "node:path";
import test from "node:test";

import {
  assertOwnedProcessLauncherProtected,
  spawnOwnedProcess,
  terminateOwnedProcess,
} from "../../src/agents/index.js";

test("read-only launcher mounts still protect namespace-root paths", () => {
  const launcher = realpathSync(process.execPath);
  const protectedAncestor = dirname(dirname(launcher));
  const readOnlyLauncher = [
    { id: 1, mountPoint: "/", readOnly: false },
    { id: 2, mountPoint: protectedAncestor, readOnly: true },
  ];
  assert.doesNotThrow(() =>
    assertOwnedProcessLauncherProtected(launcher, {
      canWrite: () => true,
      mounts: readOnlyLauncher,
    }),
  );

  assert.throws(
    () =>
      assertOwnedProcessLauncherProtected(launcher, {
        canWrite: (path) => path !== launcher,
        mounts: [{ id: 1, mountPoint: "/", readOnly: false }],
      }),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );
});

test("retires an inert supervisor before reporting failed registration", async () => {
  const failure = Object.assign(new Error("registration failed"), {
    code: "ERR_TEST_REGISTRATION",
  });
  const child = spawnOwnedProcess(process.execPath, ["-e", "process.exit(0)"], {
    descendantGraceMs: 100,
    onProcess: async (pid) => {
      if (pid !== null) throw failure;
    },
  });

  await assert.rejects(child.ownedCompletion, failure);
  assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
});

test("does not signal through a completed owned-process handle", async () => {
  const child = spawnOwnedProcess(process.execPath, ["-e", "process.exit(0)"], {
    onProcess: async () => {},
  });

  await child.ownedCompletion;
  assert.equal(child.kill("SIGKILL"), false);
});

test("recovery clears proven-dead owners without signaling reused PIDs", async () => {
  for (const owner of [
    null,
    { status: "dead", previousBoot: false },
    { status: "replaced", previousBoot: false },
    { status: "unverifiable", previousBoot: true },
  ]) {
    let inspections = 0;
    await terminateOwnedProcess(987_654, async () => {
      inspections += 1;
      return owner;
    });
    assert.equal(inspections, 1);
  }
});

test("recovery retains exclusion for live or unverifiable owners", async () => {
  for (const [status, code] of [
    ["live", "ERR_EXECUTION_PROCESS_ACTIVE"],
    ["unverifiable", "ERR_EXECUTION_PROCESS_UNVERIFIABLE"],
  ]) {
    await assert.rejects(
      terminateOwnedProcess(987_654, async () => ({
        status,
        previousBoot: false,
      })),
      { code },
    );
  }
});
