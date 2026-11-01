import assert from "node:assert/strict";
import { rename, readFile, lstat } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import { main } from "../src/index.js";
import { createRunner } from "../src/runner/index.js";
import { serveMcp } from "../src/mcp/index.js";
import { createRunStore } from "../src/state/index.js";
import {
  createRuntimeAdmission,
  prepareRuntime,
} from "../src/runtime/index.js";
import { runtimeFixture } from "./support/index.js";

test("a pinned MCP process defers activation; continuation uses its original tree until retirement", async (t) => {
  const a = await runtimeFixture(t);
  const b = await runtimeFixture(t, {
    extraFiles: { "src/version.js": 'export const version = "next";\n' },
  });
  const context = await prepareRuntime(a);
  const next = await prepareRuntime(b);
  const stateRoot = join(a.directory, "state");
  let ownerAvailable = false;
  const store = createRunStore({
    stateRoot,
    hostName: "fixture-host",
    processId: 101,
    processIsAlive: async (pid) => pid === 101,
    processIdentity: async (pid) =>
      pid === 101 && ownerAvailable
        ? { bootId: "11111111-1111-4111-8111-111111111111", startTicks: "101" }
        : null,
    runtimeProcessNamespace: async () => "pid:[42]",
  });
  const admission = createRuntimeAdmission({ runStore: store, context });
  const updater = createRuntimeAdmission({ runStore: store, context: next });
  let unverifiedStarted = false;
  await assert.rejects(
    admission.withAdmission("mcp", () => {
      unverifiedStarted = true;
    }),
    { code: "ERR_RUNTIME_OWNER_UNVERIFIABLE" },
  );
  assert.equal(unverifiedStarted, false);
  await assert.rejects(lstat(stateRoot), { code: "ENOENT" });
  ownerAvailable = true;
  const started = Promise.withResolvers();
  let closeServer;
  let errors = "";
  const running = main(["mcp"], {
    runtimeAdmission: admission,
    stderr: {
      write(value) {
        errors += value;
      },
    },
    startMcp: async () => {
      const server = await serveMcp({
        runnerConfiguration: { issueReporting: false },
        createServer() {
          throw new Error("No protocol request expected");
        },
        transport: {
          async start() {
            started.resolve();
          },
          async send() {},
          async close() {
            this.onclose?.();
          },
        },
      });
      closeServer = server.close;
      return server;
    },
  });
  let exitCode;
  try {
    await Promise.race([
      started.promise,
      running.then((code) => {
        throw new Error(
          `MCP fixture stopped before startup (${code}): ${errors}`,
        );
      }),
    ]);
    assert.equal((await updater.activate(next)).status, "deferred");
    let invoked = false;
    await assert.rejects(
      updater.withAdmission("cli", () => {
        invoked = true;
      }),
      { code: "ERR_RUNTIME_RESTART_REQUIRED" },
    );
    assert.equal(invoked, false);
    await rename(a.rootPath, join(a.directory, "old-outer-installation"));
    const guide = await admission.withAdmission("resume", () =>
      readFile(join(context.rootPath, "docs/OPERATOR_GUIDE.md"), "utf8"),
    );
    assert.equal(guide, "# Original complete guide\n");
    assert.equal((await updater.activate(next)).status, "deferred");
  } finally {
    await closeServer?.();
    exitCode = await running;
  }
  assert.equal(exitCode, 0);
  assert.equal(errors, "");
  assert.equal((await updater.activate(next)).status, "active");
  await assert.rejects(
    admission.withAdmission("run", () => {}),
    { code: "ERR_RUNTIME_RESTART_REQUIRED" },
  );
  assert.equal(
    await updater.withAdmission("cli", () => "accepted"),
    "accepted",
  );
  const failure = new Error("fixture command failure");
  await assert.rejects(
    updater.withAdmission("run", () => {
      throw failure;
    }),
    (error) => error === failure,
  );
  const state = JSON.parse(
    await readFile(join(stateRoot, "runtime-admission/runtime.json"), "utf8"),
  );
  assert.deepEqual(state.users, []);
  assert.equal(
    await readFile(join(context.rootPath, "docs/OPERATOR_GUIDE.md"), "utf8"),
    "# Original complete guide\n",
  );
});

test("CLI and Runner admission precede new-run and resume effects", async () => {
  const calls = [];
  const runtimeAdmission = {
    async withAdmission(kind) {
      calls.push(kind);
      throw Object.assign(new Error("deferred"), {
        code: "ERR_RUNTIME_RESTART_REQUIRED",
      });
    },
  };
  const runner = createRunner({ runtimeAdmission });
  for (const method of ["create", "run", "resume"])
    await assert.rejects(runner[method]({}), {
      code: "ERR_RUNTIME_RESTART_REQUIRED",
    });
  let output = "";
  let error = "";
  assert.equal(
    await main(["--help"], {
      runtimeAdmission,
      stdout: {
        write(value) {
          output += value;
        },
      },
      stderr: {
        write(value) {
          error += value;
        },
      },
    }),
    1,
  );
  assert.equal(output, "");
  assert.match(error, /Runtime admission/u);
  assert.deepEqual(calls, ["run", "run", "resume", "cli"]);
});

test("development-managed calls stay outside global admission", async () => {
  const development = createRuntimeAdmission({ runStore: null, context: null });
  assert.equal(await development.withAdmission("run", () => 7), 7);
});

test(
  "MCP startup failure and immediate close settle the admitted lifetime",
  { timeout: 2000 },
  async () => {
    for (const mode of ["close", "failure"]) {
      const server = await serveMcp({
        runnerConfiguration: { issueReporting: false },
        stderr: { write() {} },
        createServer() {
          throw new Error("No request expected");
        },
        transport: {
          async start() {
            if (mode === "failure") throw new Error("fixture startup failure");
            this.onclose?.();
          },
          async close() {
            this.onclose?.();
          },
          async send() {},
        },
      });
      if (mode === "failure")
        await assert.rejects(server.closed, /fixture startup failure/u);
      else await server.closed;
      await server.close();
    }
  },
);

test(
  "STDIO EOF closes the MCP lifetime and retires CLI admission",
  { timeout: 2000 },
  async (t) => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    let retired = false;
    let server;
    const running = main(["mcp"], {
      runtimeAdmission: {
        async withAdmission(_kind, operation) {
          try {
            return await operation();
          } finally {
            retired = true;
          }
        },
      },
      startMcp: async () => {
        server = await serveMcp({
          stdin,
          stdout,
          runnerConfiguration: { issueReporting: false },
          createServer() {
            throw new Error("No protocol request expected");
          },
        });
        return server;
      },
    });
    t.after(async () => {
      await server?.close();
      await running;
      stdin.destroy();
      stdout.destroy();
    });
    stdin.end();
    assert.equal(await running, 0);
    assert.equal(retired, true);
    assert.equal(stdin.listenerCount("end"), 0);
    assert.equal(stdin.listenerCount("close"), 0);
  },
);

test("runtime admission checks project and task storage boundaries before writing state", async (t) => {
  const f = await runtimeFixture(t);
  const context = await prepareRuntime(f);
  const stateRoot = join(f.directory, "project", "state");
  const admission = createRuntimeAdmission({
    runStore: createRunStore({ stateRoot }),
    context,
  });
  let entered = false;
  await assert.rejects(
    admission.withAdmission(
      "run",
      () => {
        entered = true;
      },
      async () => [join(f.directory, "project")],
    ),
    { code: "ERR_RUNTIME_ADMISSION" },
  );
  assert.equal(entered, false);
  await assert.rejects(lstat(stateRoot), { code: "ENOENT" });
});

test("activation retains the verified Node identity when caller-owned input changes", async (t) => {
  const f = await runtimeFixture(t);
  const verified = await prepareRuntime(f);
  const candidate = structuredClone(verified);
  const admission = createRuntimeAdmission({
    runStore: {
      async assertRuntimeBoundary() {
        candidate.nodeIdentity.ino = "0";
      },
      async activateRuntime({ runtime }) {
        assert.deepEqual(runtime.nodeIdentity, verified.nodeIdentity);
        return { status: "active" };
      },
    },
  });
  assert.equal((await admission.activate(candidate)).status, "active");
});
