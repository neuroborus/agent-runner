import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { gzipSync } from "node:zlib";

import {
  inspectOwnedSessionProcesses,
  readProcessNamespace,
} from "../src/agents/index.js";
import { createRunStore } from "../src/state/index.js";
import { prepareRuntime } from "../src/runtime/index.js";
import { createUpdateService } from "../src/update/index.js";
import { runtimeFixture } from "./support/index.js";

const policy = {
  schemaVersion: 1,
  enabled: true,
  repository: "sample/runner",
  packageName: "@sample/runner",
  license: "MIT",
};
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const integrity = (bytes) =>
  "sha512-" + createHash("sha512").update(bytes).digest("base64");

function pack(entries) {
  const chunks = [];
  for (const [path, file] of entries) {
    const header = Buffer.alloc(512);
    header.write("package/" + path);
    header.write(file.mode.toString(8).padStart(7, "0") + "\0", 100);
    header.write(file.bytes.length.toString(8).padStart(11, "0") + "\0", 124);
    header.fill(32, 148, 156);
    header.write("0", 156);
    header.write(
      header
        .reduce((sum, byte) => sum + byte, 0)
        .toString(8)
        .padStart(6, "0") + "\0 ",
      148,
    );
    chunks.push(
      header,
      file.bytes,
      Buffer.alloc((512 - (file.bytes.length % 512)) % 512),
    );
  }
  return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]));
}

function memoryActions(contextFault) {
  const records = new Map();
  return {
    assertRuntimeBoundary: async () => {},
    readAction: async ({ key }) => structuredClone(records.get(key)),
    beginAction: async ({ key, arguments: args, context }) => {
      if (!records.has(key))
        records.set(key, { args, context, status: "intent", result: null });
      const record = records.get(key);
      assert.deepEqual(record.args, args);
      return {
        get record() {
          return structuredClone(record);
        },
        updateContext: async (value) => {
          await contextFault?.(value);
          record.context = structuredClone(value);
        },
        complete: async (result) => {
          record.status = "completed";
          record.result = structuredClone(result);
        },
        release: async () => {},
      };
    },
  };
}

async function fixture(
  t,
  {
    fault,
    mutateArchive,
    current = false,
    durable = false,
    retainPrevious = false,
    native = false,
    spawn,
    nativeRetirement = false,
    restartRequired = false,
    contextFault,
  } = {},
) {
  const f = await runtimeFixture(t);
  const metadata = JSON.parse(
    await readFile(join(f.rootPath, "package.json"), "utf8"),
  );
  Object.assign(metadata, {
    name: policy.packageName,
    private: false,
    license: "MIT",
    repository: { type: "git", url: "https://github.com/sample/runner.git" },
    publishConfig: {
      access: "public",
      registry: "https://registry.npmjs.org/",
    },
    agentRunnerCompatibility: {
      schemaVersion: 1,
      configurationVersion: 1,
      runnerVersion: 1,
      runStateVersion: 24,
      pipelines: { sample: 2 },
    },
  });
  const bytes = Buffer.from(JSON.stringify(metadata));
  await writeFile(join(f.rootPath, "package.json"), bytes);
  f.manifest.name = metadata.name;
  Object.assign(
    f.manifest.files.find((entry) => entry.path === "package.json"),
    { size: bytes.length, sha256: sha256(bytes) },
  );
  await writeFile(
    join(f.rootPath, "release-manifest.json"),
    JSON.stringify(f.manifest, null, 2) + "\n",
  );
  const previous = retainPrevious
    ? await prepareRuntime(f)
    : { rootPath: f.rootPath };
  const available = structuredClone(metadata);
  available.version = current ? metadata.version : "1.1.0";
  const manifest = structuredClone(f.manifest);
  manifest.version = available.version;
  const entries = new Map();
  for (const entry of manifest.files) {
    const bytes =
      entry.path === "package.json"
        ? Buffer.from(JSON.stringify(available))
        : await readFile(join(f.rootPath, entry.path));
    Object.assign(entry, { size: bytes.length, sha256: sha256(bytes) });
    entries.set(entry.path, { bytes, mode: entry.mode });
  }
  entries.set("release-manifest.json", {
    bytes: Buffer.from(JSON.stringify(manifest, null, 2) + "\n"),
    mode: 0o644,
  });
  if (mutateArchive) mutateArchive(entries);
  let archive = pack(entries);
  available.dist = {
    integrity: integrity(archive),
    tarball: `https://registry.npmjs.org/@sample/runner/-/runner-${available.version}.tgz`,
  };
  const store = durable
    ? createRunStore({ stateRoot: join(f.directory, "state") })
    : memoryActions(contextFault);
  const calls = [];
  const registeredPid = process.pid === 42 ? 43 : 42;
  let queries = 0;
  let canRetire = false;
  const operationId = randomUUID();
  const storageRoot = join(f.directory, "candidates");
  const action = () =>
    store.readAction({
      key: `update:${operationId}`,
      tool: "update_prepare",
      arguments: {
        version: available.version,
        storageRoot,
        official: {
          approved: true,
          packageName: policy.packageName,
          repository: policy.repository,
          license: policy.license,
          registry: "https://registry.npmjs.org/",
        },
      },
    });
  const effects = {
    retired: async () => canRetire,
    run: async (command, args, options) => {
      const kind =
        command === "npm" ? args[0] : args.includes("--help") ? "help" : "mcp";
      calls.push({ kind, command, args, options });
      await options.onProcess(registeredPid, {
        processIdentity: {
          bootId: "00000000-0000-4000-8000-000000000000",
          startTicks: "1",
        },
        namespaceId: await readProcessNamespace(process.pid),
      });
      assert.equal(
        (await action()).context.process.pid,
        registeredPid,
        "process intent precedes effects",
      );
      let interrupted = false;
      try {
        if (fault) interrupted = await fault(kind, options, calls);
        if (kind === "pack")
          await writeFile(
            join(options.directory.anchor, "candidate.tgz"),
            archive,
            { flag: "wx" },
          );
        if (kind === "install") {
          const prefix = args[args.indexOf("--prefix") + 1];
          const root = join(prefix, "lib/node_modules", policy.packageName);
          for (const [path, file] of entries) {
            await mkdir(dirname(join(root, path)), {
              recursive: true,
              mode: 0o700,
            });
            await writeFile(join(root, path), file.bytes, {
              flag: "wx",
              mode: file.mode,
            });
          }
        }
        if (interrupted)
          throw new Error("controlled owner loss after installation");
        return {
          stdout:
            kind === "help"
              ? "Agent Runner\n"
              : kind === "mcp"
                ? "MCP smoke passed\n"
                : "[]",
          stderr: "",
        };
      } finally {
        if (!interrupted) await options.onProcess(null);
      }
    },
  };
  const processInspection = {};
  if (nativeRetirement) {
    delete effects.retired;
    effects.processInspection = processInspection;
  }
  if (native) {
    const execute = effects.run;
    delete effects.run;
    effects.spawn =
      spawn ??
      ((file, vector, options) => {
        assert.equal(file, "/usr/bin/bwrap");
        assert.deepEqual(
          vector.slice(
            vector.indexOf("--ro-bind"),
            vector.indexOf("--ro-bind") + 3,
          ),
          ["--ro-bind", "/", "/"],
        );
        const bind = vector.indexOf("--bind");
        assert.equal(vector[bind + 1], "/proc/self/fd/3");
        assert.equal(typeof options.stdio[3], "number");
        const separator = vector.lastIndexOf("--");
        const [command, ...args] = vector.slice(separator + 1);
        assert.equal(
          vector.includes("--unshare-net"),
          command !== "npm" || args[0] !== "pack",
        );
        assert.ok(vector.includes("--unshare-pid"));
        assert.ok(vector.includes("--unshare-user"));
        assert.deepEqual(
          vector.slice(
            vector.indexOf("--cap-drop"),
            vector.indexOf("--cap-drop") + 2,
          ),
          ["--cap-drop", "ALL"],
        );
        assert.equal(typeof options.deadlineNs, "string");
        assert.equal(options.env.NPM_TOKEN, undefined);
        const child = {
          stdin: new PassThrough(),
          stdout: new PassThrough(),
          stderr: new PassThrough(),
          kill: () => {},
        };
        child.ownedCompletion = Promise.resolve().then(async () => {
          const path = vector[bind + 2];
          const result = await execute(command, args, {
            directory: { path, anchor: path },
            env: options.env,
            onProcess: options.onProcess,
          });
          child.stdout.end(result.stdout);
          child.stderr.end(result.stderr);
          return {
            outcome: { type: "close", exitCode: 0, signal: null },
            descendantsStopped: true,
          };
        });
        return child;
      });
  }
  const updater = createUpdateService({
    policy,
    runStore: store,
    storageRoot,
    readInstallation: async () => ({
      rootPath: previous.rootPath,
      installationPath: f.rootPath,
      installedMetadata: metadata,
      runningMetadata: metadata,
      developmentManaged: false,
      canWriteInstallation: true,
      nodeVersion: process.version,
      restartRequired,
    }),
    fetch: async () => {
      assert.equal(
        (await action()).status,
        "intent",
        "selection intent precedes registry effects",
      );
      queries++;
      return Response.json(available);
    },
    effects,
  });
  return {
    ...f,
    previous,
    updater,
    operationId,
    version: available.version,
    calls,
    action,
    available,
    storageRoot,
    processInspection,
    registeredPid,
    prepare: () => updater.prepare({ operationId, version: available.version }),
    queries: () => queries,
    retire: () => {
      canRetire = true;
    },
    corrupt: () => {
      archive = Buffer.concat([archive, Buffer.from("changed")]);
    },
  };
}

test("preparation binds exact selection, owned effects, complete payload and isolated smoke before its receipt", async (t) => {
  const f = await fixture(t, { durable: true, retainPrevious: true });
  const result = await f.prepare();
  assert.equal(result.status, "validated");
  assert.equal(result.operationId, f.operationId);
  assert.equal(result.restartRequired, true);
  assert.deepEqual(
    f.calls.map((call) => call.kind),
    ["pack", "install", "help", "mcp"],
  );
  assert.deepEqual(f.calls[0].args.slice(0, 5), [
    "pack",
    "@sample/runner@1.1.0",
    "--registry",
    "https://registry.npmjs.org/",
    "--json",
  ]);
  for (const option of [
    "--offline",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
  ])
    assert.ok(f.calls[1].args.includes(option));
  assert.equal(f.calls[1].options.readOnly.length, 1);
  assert.equal(
    await readFile(join(f.calls[0].options.directory.path, ".npmrc"), "utf8"),
    "",
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(
        join(f.calls[0].options.directory.path, "package.json"),
        "utf8",
      ),
    ),
    { private: true },
  );
  assert.equal(f.calls[2].options.env.NODE_OPTIONS, undefined);
  assert.equal(f.calls[2].options.env.NODE_PATH, undefined);
  assert.ok(f.calls[2].options.env.XDG_STATE_HOME.startsWith(f.storageRoot));
  const record = await f.action();
  assert.equal(record.status, "completed");
  assert.equal(record.context.process, null);
  assert.equal(record.context.attempts[0].phase, "validated");
  assert.equal(record.context.candidate.mode, "pinned");
  assert.equal(
    (
      await readdir(join(f.storageRoot, record.context.attempts[0].id))
    ).includes("smoke"),
    false,
  );
  assert.equal(JSON.stringify(result).includes(f.directory), false);
  const before = f.queries();
  assert.deepEqual(await f.prepare(), result);
  assert.equal(f.queries(), before);
  assert.equal(f.calls.length, 4);
  assert.equal(
    (await prepareRuntime({ rootPath: f.previous.rootPath, environment: {} }))
      .payloadId,
    f.previous.payloadId,
  );
});

test("interrupted installation reconciles completed bytes only after owned-process retirement", async (t) => {
  let once = true;
  const f = await fixture(t, {
    durable: true,
    fault: async (kind) => kind === "install" && once && ((once = false), true),
  });
  assert.equal((await f.prepare()).status, "blocked");
  assert.equal((await f.action()).context.process.pid, f.registeredPid);
  assert.deepEqual((await f.prepare()).blockers, ["process_unverifiable"]);
  assert.equal(f.calls.length, 2);
  f.retire();
  assert.equal((await f.prepare()).status, "validated");
  assert.deepEqual(
    f.calls.map((call) => call.kind),
    ["pack", "install", "help", "mcp"],
  );
});

test("failed installation retries in fresh owned storage without changing the previous payload", async (t) => {
  let once = true;
  const f = await fixture(t, {
    retainPrevious: true,
    fault: async (kind, options) => {
      if (kind === "install" && once) {
        once = false;
        await writeFile(
          join(options.directory.anchor, "prefix", "partial.txt"),
          "owned partial installation",
        );
        throw new Error("private registry diagnostic");
      }
    },
  });
  const failed = await f.prepare();
  assert.equal(failed.status, "blocked");
  assert.equal(
    JSON.stringify(failed).includes("private registry diagnostic"),
    false,
  );
  assert.equal((await f.prepare()).status, "validated");
  const attempts = (await f.action()).context.attempts;
  assert.equal(attempts.length, 2);
  assert.notEqual(attempts[0].identity.ino, attempts[1].identity.ino);
  assert.equal(
    await readFile(
      join(f.storageRoot, attempts[0].id, "prefix", "partial.txt"),
      "utf8",
    ),
    "owned partial installation",
  );
  assert.equal(
    (await prepareRuntime({ rootPath: f.previous.rootPath, environment: {} }))
      .payloadId,
    f.previous.payloadId,
  );
});

test("integrity and incomplete resource manifests fail before installation", async (t) => {
  const changed = await fixture(t);
  changed.corrupt();
  assert.equal((await changed.prepare()).status, "blocked");
  assert.deepEqual(
    changed.calls.map((call) => call.kind),
    ["pack"],
  );
  const missing = await fixture(t, {
    mutateArchive: (entries) => entries.delete("docs/OPERATOR_GUIDE.md"),
  });
  assert.equal((await missing.prepare()).status, "blocked");
  assert.deepEqual(
    missing.calls.map((call) => call.kind),
    ["pack"],
  );
});

test("substituted attempt storage is preserved and cannot become a candidate", async (t) => {
  let replacement;
  const f = await fixture(t, {
    fault: async (kind, options) => {
      if (kind === "pack") {
        const path = options.directory.path;
        await rename(path, path + "-saved");
        await mkdir(path, { mode: 0o700 });
        replacement = join(path, "unrelated.txt");
        await writeFile(replacement, "preserve");
      }
    },
  });
  assert.equal((await f.prepare()).status, "blocked");
  assert.equal(await readFile(replacement, "utf8"), "preserve");
  assert.deepEqual(
    f.calls.map((call) => call.kind),
    ["pack"],
  );
});

test("unapproved and arbitrary preparation requests perform no effects, and current receipts are reusable", async (t) => {
  const updater = createUpdateService({
    readInstallation: () => {
      throw new Error("Unexpected inspection");
    },
  });
  assert.deepEqual(
    (await updater.prepare({ operationId: randomUUID(), version: "1.1.0" }))
      .blockers,
    ["identity_unapproved"],
  );
  assert.deepEqual(
    (
      await updater.prepare({
        operationId: randomUUID(),
        version: "latest",
        source: "https://example.invalid/",
      })
    ).blockers,
    ["invalid_request"],
  );
  const f = await fixture(t, { current: true, restartRequired: true });
  const current = await f.prepare();
  assert.equal(current.status, "current");
  assert.equal(current.restartRequired, true);
  const queries = f.queries();
  assert.deepEqual(await f.prepare(), current);
  assert.equal(f.queries(), queries);
  assert.deepEqual(f.calls, []);
});

test("native vectors retain PID and filesystem containment with only the owned candidate writable", async (t) => {
  const f = await fixture(t, { native: true });
  assert.equal((await f.prepare()).status, "validated");
  assert.deepEqual(
    f.calls.map(({ kind }) => kind),
    ["pack", "install", "help", "mcp"],
  );
});

test("the native deadline retires a command that remains active after launch", async (t) => {
  const started = Promise.withResolvers();
  const completed = Promise.withResolvers();
  let kills = 0;
  const f = await fixture(t, {
    native: true,
    spawn: (_file, _vector, options) => {
      const child = {
        stdin: new PassThrough(),
        stdout: new PassThrough(),
        stderr: new PassThrough(),
        kill: (signal) => {
          assert.equal(signal, "SIGKILL");
          kills++;
          completed.resolve();
        },
      };
      child.ownedCompletion = (async () => {
        await options.onProcess(42, {
          processIdentity: {
            bootId: "00000000-0000-4000-8000-000000000000",
            startTicks: "1",
          },
          namespaceId: await readProcessNamespace(process.pid),
        });
        started.resolve();
        await completed.promise;
        await options.onProcess(null);
        // A racing successful exit cannot turn deadline expiry into a pass.
        return {
          outcome: { type: "close", exitCode: 0 },
          descendantsStopped: true,
        };
      })();
      return child;
    },
  });
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const preparing = f.prepare();
  try {
    await Promise.race([
      started.promise,
      preparing.then(() =>
        assert.fail("The controlled command did not start."),
      ),
    ]);
    t.mock.timers.tick(120_000);
    assert.equal(kills, 1);
  } finally {
    completed.resolve();
    await preparing;
  }
  assert.equal((await preparing).status, "blocked");
  assert.equal((await f.action()).context.process, null);
});

test("smoke setup failures close and remove the positively owned allocation", async (t) => {
  let once = true;
  const f = await fixture(t, {
    contextFault: async (context) => {
      if (context.attempts.at(-1)?.phase === "smoking" && once) {
        once = false;
        throw new Error("controlled smoke intent failure");
      }
    },
  });
  assert.equal((await f.prepare()).status, "blocked");
  const attempt = (await f.action()).context.attempts.at(-1);
  assert.equal(
    (await readdir(join(f.storageRoot, attempt.id))).includes("smoke"),
    false,
  );
  assert.equal((await f.prepare()).status, "validated");
});

test("persistent intent-write failures remain bounded and redacted", async (t) => {
  const f = await fixture(t, {
    contextFault: async (context) => {
      if (["packing", "failed"].includes(context.attempts.at(-1)?.phase))
        throw new Error("private state diagnostic");
    },
  });
  const result = await f.prepare();
  assert.equal(result.status, "blocked");
  assert.equal(
    JSON.stringify(result).includes("private state diagnostic"),
    false,
  );
  assert.deepEqual(f.calls, []);
});

test("permission and smoke failures retain an intent rather than accepting a candidate", async (t) => {
  for (const kind of ["install", "help"]) {
    const f = await fixture(t, {
      fault: async (current) => {
        if (kind === current)
          throw Object.assign(new Error("private diagnostic"), {
            code: kind === "install" ? "EACCES" : "EIO",
          });
      },
    });
    const result = await f.prepare();
    assert.equal(result.status, "blocked");
    assert.equal(JSON.stringify(result).includes("private diagnostic"), false);
    if (kind === "install")
      assert.deepEqual(result.blockers, ["installation_permission"]);
    const context = (await f.action()).context;
    assert.equal(context.attempts.at(-1).phase, "failed");
    assert.equal((await f.action()).status, "intent");
    assert.equal(context.process, null);
    assert.equal(
      (await readdir(join(f.storageRoot, context.attempts.at(-1).id))).includes(
        "smoke",
      ),
      false,
    );
  }
});

test("unapproved registry sources and incompatible state stop before native effects", async (t) => {
  for (const kind of ["source", "state"]) {
    const f = await fixture(t);
    if (kind === "source")
      f.available.dist.tarball = "https://example.invalid/runner.tgz";
    else f.available.agentRunnerCompatibility.runStateVersion++;
    assert.equal((await f.prepare()).status, "blocked");
    assert.deepEqual(f.calls, []);
  }
});

test("retirement ignores a reused unrelated PID but retains positively associated members", async (t) => {
  let once = true;
  const f = await fixture(t, {
    nativeRetirement: true,
    fault: async (kind) => kind === "install" && once && ((once = false), true),
  });
  assert.equal((await f.prepare()).status, "blocked");
  const recorded = (await f.action()).context.process;
  let members = [77];
  Object.assign(f.processInspection, {
    identity: async (pid) =>
      pid === process.pid
        ? recorded.processIdentity
        : { ...recorded.processIdentity, startTicks: "2" },
    namespace: async () => recorded.observerNamespace,
    session: (pid, token, options) => {
      assert.equal(pid, recorded.pid);
      assert.match(token, /^[a-f0-9]{64}$/u);
      assert.equal(options.includeSession, false);
      return members;
    },
  });
  assert.deepEqual((await f.prepare()).blockers, ["process_unverifiable"]);
  members = [];
  assert.equal((await f.prepare()).status, "validated");
  assert.deepEqual(
    f.calls.map(({ kind }) => kind),
    ["pack", "install", "help", "mcp"],
  );
});

test("retirement rejects token-owned uncertainty but ignores a reused session with an absent leader", async (t) => {
  let once = true;
  const f = await fixture(t, {
    nativeRetirement: true,
    fault: async (kind) => kind === "install" && once && ((once = false), true),
  });
  assert.equal((await f.prepare()).status, "blocked");
  const recorded = (await f.action()).context.process;
  let mode = "owned";
  const observations = [];
  Object.assign(f.processInspection, {
    identity: async (pid) =>
      pid === process.pid ? recorded.processIdentity : null,
    namespace: async () => recorded.observerNamespace,
    stat: async (path) => {
      assert.equal(path, `/proc/${recorded.pid}`);
      throw Object.assign(new Error("absent fixture owner"), {
        code: "ENOENT",
      });
    },
    session: (pid, token, options) => {
      assert.equal(pid, recorded.pid);
      assert.equal(
        token,
        sha256(
          `${recorded.pid}\0${recorded.processIdentity.bootId}\0${recorded.processIdentity.startTicks}`,
        ),
      );
      let statReads = 0;
      const members = inspectOwnedSessionProcesses(pid, token, {
        ...options,
        list: () => ["77"],
        read: (path) => {
          if (path === "/proc/77/stat") {
            if (++statReads > 1 && mode === "unverifiable")
              throw Object.assign(new Error("unreadable owned fixture"), {
                code: "EACCES",
              });
            const fields = Array(20).fill("0");
            fields[0] = "S";
            fields[3] = String(recorded.pid);
            fields[19] = "100";
            return `77 (sample) ${fields.join(" ")}`;
          }
          if (path === "/proc/77/status")
            return `Uid: ${Array(4).fill(process.getuid()).join(" ")}`;
          if (path === "/proc/77/environ")
            return mode === "unrelated"
              ? ""
              : `AGENT_RUNNER_OWNED_PROCESS=${token}\0`;
          throw new Error("Unexpected fixture path");
        },
        now: () => 0,
      });
      observations.push(members);
      return members;
    },
  });
  assert.deepEqual((await f.prepare()).blockers, ["process_unverifiable"]);
  mode = "unverifiable";
  assert.deepEqual((await f.prepare()).blockers, ["process_unverifiable"]);
  assert.deepEqual((await f.action()).context.process, recorded);
  mode = "unrelated";
  assert.equal((await f.prepare()).status, "validated");
  assert.deepEqual(observations, [[77], null, []]);
  assert.deepEqual(
    f.calls.map(({ kind }) => kind),
    ["pack", "install", "help", "mcp"],
  );
});
