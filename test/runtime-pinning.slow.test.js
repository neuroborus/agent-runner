import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { runtimeFixture } from "./support/index.js";

const APPLICATION = `
import { readFile, writeFile } from "node:fs/promises";
import { getRuntimeContext, RUNTIME_PAYLOAD_ENV } from "./runtime/index.js";
async function report() {
  return { marker: (await import("./late.js")).marker,
    dependency: await (await import("sample-dependency")).value(),
    guide: await readFile(new URL("../docs/OPERATOR_GUIDE.md", import.meta.url), "utf8"),
    context: getRuntimeContext(), consumed: process.env[RUNTIME_PAYLOAD_ENV] === undefined };
}
export async function main() {
  if (process.argv[2] === "resume") {
    await writeFile(process.env.FIXTURE_RECEIPT, JSON.stringify(await report()));
    return 0;
  }
  process.on("message", () => {});
  const command = new Promise(resolve => process.once("message", resolve));
  process.send({ type: "ready", context: getRuntimeContext() });
  const action = await command;
  try {
    const before = await report();
    if (action === "detach") {
      const { createDetachedLauncher } = await import("./mcp/index.js");
      const exited = Promise.withResolvers();
      await createDetachedLauncher()("00000000-0000-4000-8000-000000000001", null,
        { onExit(code, signal) { exited.resolve({ code, signal }); } });
      const exit = await exited.promise;
      process.send({ type: "complete", before, child: JSON.parse(await readFile(process.env.FIXTURE_RECEIPT, "utf8")), exit });
    } else {
      const { createDetachedLauncher } = await import("./mcp/index.js");
      await createDetachedLauncher({ spawnProcess() {
        process.send({ type: "unexpected-spawn" });
        throw new Error("A damaged payload must not spawn a child");
      } })("00000000-0000-4000-8000-000000000001");
      process.send({ type: "unexpected-launch" });
    }
  } catch (error) { process.send({ type: "rejected", code: error.code }); }
  process.disconnect();
  return 0;
}
`;

test("running and detached processes stay pinned after outer replacement; drift rejects another launch", async (t) => {
  for (const scenario of ["replace", "drift"]) {
    await t.test(scenario, async (t) => {
      const f = await runtimeFixture(t, {
        application: APPLICATION,
        extraFiles: {
          "src/mcp/index.js":
            'export { createDetachedLauncher } from "./detached.js";\n',
          "src/mcp/detached.js": await readFile(
            new URL("../src/mcp/detached.js", import.meta.url),
          ),
          "src/agents/index.js":
            'export async function readProcessIdentity() { throw new Error("No dispatch expected"); }\n',
          "src/state/index.js":
            "export const normalizeRecoveryDispatch = value => value; export class RunStoreError extends Error { constructor(message, options) { super(message); this.code = options.code; } }\n",
          "src/pipeline-registry.js":
            'export const DETACHED_RUNTIME_COMPATIBILITY_TOKEN = "fixture-runtime";\n',
        },
      });
      const logPath = join(f.directory, "child.stderr");
      const log = await open(logPath, "wx", 0o600);
      const child = spawn(
        process.execPath,
        [join(f.rootPath, "bin/agent-run.js")],
        {
          env: {
            ...process.env,
            HOME: join(f.directory, "home"),
            XDG_DATA_HOME: join(f.directory, "data"),
            FIXTURE_RECEIPT: join(f.directory, "receipt.json"),
          },
          stdio: ["ignore", "ignore", log.fd, "ipc"],
        },
      );
      const exit = new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", (code, signal) => resolve({ code, signal }));
      });
      const message = () =>
        new Promise((resolve, reject) => {
          const clear = () => {
            child.removeListener("message", receive);
            child.removeListener("exit", stopped);
            child.removeListener("error", failed);
          };
          const receive = (value) => {
            clear();
            resolve(value);
          };
          const failed = (error) => {
            clear();
            reject(error);
          };
          const stopped = async () => {
            clear();
            try {
              reject(
                new Error(
                  (await readFile(logPath, "utf8")) ||
                    "Fixture exited before its message",
                ),
              );
            } catch (error) {
              reject(error);
            }
          };
          child.once("message", receive);
          child.once("exit", stopped);
          child.once("error", failed);
        });
      try {
        const ready = await message();
        assert.equal(ready.type, "ready");
        assert.equal(ready.context.mode, "pinned");
        if (scenario === "replace") {
          await rename(f.rootPath, join(f.directory, "old-installation"));
          await mkdir(f.rootPath);
          await writeFile(
            join(f.rootPath, "package.json"),
            "unusable outer replacement\n",
          );
        } else {
          const path = join(ready.context.rootPath, "src/late.js");
          await chmod(path, 0o600);
          await writeFile(path, 'export const marker = "changed";\n');
          await chmod(path, 0o400);
        }
        const complete = message();
        child.send(scenario === "replace" ? "detach" : "verify");
        const result = await complete;
        if (scenario === "replace") {
          assert.equal(result.type, "complete");
          assert.deepEqual(result.exit, { code: 0, signal: null });
          for (const report of [result.before, result.child]) {
            assert.equal(report.marker, "original");
            assert.equal(report.dependency, "original dependency");
            assert.equal(report.guide, "# Original complete guide\n");
            assert.equal(report.context.rootPath, ready.context.rootPath);
            assert.equal(report.context.payloadId, ready.context.payloadId);
            assert.equal(report.context.installationPath, f.rootPath);
            assert.equal(report.consumed, true);
          }
        } else
          assert.deepEqual(result, {
            type: "rejected",
            code: "ERR_RUNTIME_PAYLOAD",
          });
        assert.deepEqual(await exit, { code: 0, signal: null });
      } finally {
        try {
          if (child.exitCode === null && child.signalCode === null)
            child.kill();
          await exit;
        } finally {
          await log.close();
        }
      }
    });
  }
});
