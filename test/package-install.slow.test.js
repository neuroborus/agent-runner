import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import { delimiter, dirname, isAbsolute, join, relative, sep } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { assembleRelease, packRelease } from "../scripts/assemble-release.js";
import { runtimeFixtureDirectory } from "./support/index.js";

const CHECKOUT = fileURLToPath(new URL("../", import.meta.url));
const MAX_OUTPUT = 2 * 1024 * 1024;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const within = (root, path) => {
  const child = relative(root, path);
  return (
    child === "" ||
    (child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child))
  );
};

// Only these deliberately spawned children may be signaled. Every path, even
// an assertion or protocol failure, awaits their closure before fixture cleanup.
function startProcess(command, args, options) {
  const child = spawn(command, args, {
    ...options,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  let bytes = 0;
  let failure = null;
  const stop = (error) => {
    failure ??= error;
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGKILL");
  };
  const capture = (chunks) => (chunk) => {
    bytes += chunk.length;
    if (bytes > MAX_OUTPUT)
      stop(new Error("Package smoke output exceeded its bound."));
    else chunks.push(chunk);
  };
  child.stdout.on("data", capture(stdout));
  child.stderr.on("data", capture(stderr));
  child.stdin.on("error", stop);
  child.once("error", (error) => {
    failure ??= error;
  });
  const timer = setTimeout(
    () => stop(new Error("Package smoke process timed out.")),
    120_000,
  );
  const closed = new Promise((resolve) =>
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        code,
        signal,
        failure,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    }),
  );
  return {
    child,
    closed,
    stop,
    async dispose() {
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGKILL");
      await closed;
    },
  };
}

function assertSuccess(result) {
  assert.equal(result.failure, null, result.failure?.stack);
  assert.deepEqual(
    { code: result.code, signal: result.signal },
    { code: 0, signal: null },
    result.stderr,
  );
}

async function runCommand(executable, args, options) {
  const running = startProcess(executable, args, options);
  try {
    running.child.stdin.end();
    const result = await running.closed;
    assertSuccess(result);
    return result;
  } finally {
    await running.dispose();
  }
}

function mcpProcess(executable, args, options) {
  const running = startProcess(executable, args, options);
  const lines = createInterface({
    input: running.child.stdout,
    crlfDelay: Infinity,
  });
  const pending = new Map();
  let nextId = 0;
  let failure = null;
  function fail(error) {
    failure ??= error;
    for (const request of pending.values()) request.reject(failure);
    pending.clear();
    running.stop(error);
  }
  lines.on("line", (line) => {
    try {
      const message = JSON.parse(line);
      assert.equal(
        message.jsonrpc,
        "2.0",
        "STDIO must contain only MCP JSON-RPC messages.",
      );
      if (!Object.hasOwn(message, "id")) {
        assert.equal(typeof message.method, "string");
        return;
      }
      const request = pending.get(message.id);
      assert.ok(request, "Unexpected or duplicate MCP response.");
      pending.delete(message.id);
      if (message.error)
        request.reject(new Error(JSON.stringify(message.error)));
      else request.resolve(message.result);
    } catch (error) {
      fail(error);
    }
  });
  lines.on("error", fail);
  running.closed.then((result) => {
    lines.close();
    if (pending.size)
      fail(
        result.failure ??
          new Error(`MCP closed before responding: ${result.stderr}`),
      );
  });
  function send(message) {
    running.child.stdin.write(`${JSON.stringify(message)}\n`, (error) => {
      if (error) fail(error);
    });
  }
  return {
    request(method, params) {
      if (failure) return Promise.reject(failure);
      const id = ++nextId;
      const reply = Promise.withResolvers();
      pending.set(id, reply);
      send({ jsonrpc: "2.0", id, method, params });
      return reply.promise;
    },
    notify(method) {
      send({ jsonrpc: "2.0", method });
    },
    async shutdown() {
      // MCP STDIO shutdown is transport EOF, not an invented shutdown RPC.
      running.child.stdin.end();
      const result = await running.closed;
      assertSuccess(result);
      assert.equal(failure, null, failure?.stack);
      assert.equal(result.stderr, "");
    },
    async dispose() {
      await running.dispose();
      lines.close();
    },
  };
}

async function environment(directory, prefix) {
  const names = [
    "home",
    "config",
    "state",
    "data",
    "cache",
    "temporary",
    "work",
  ];
  const paths = Object.fromEntries(
    names.map((name) => [name, join(directory, name)]),
  );
  for (const path of [...Object.values(paths), prefix])
    await mkdir(path, { mode: 0o700 });
  const userConfig = join(directory, "user.npmrc");
  const globalConfig = join(directory, "global.npmrc");
  for (const path of [userConfig, globalConfig])
    await writeFile(path, "", { flag: "wx", mode: 0o600 });
  const node = await realpath(process.execPath);
  return {
    paths,
    node,
    env: {
      PATH: [join(prefix, "bin"), dirname(node)].join(delimiter),
      HOME: paths.home,
      XDG_CONFIG_HOME: paths.config,
      XDG_STATE_HOME: paths.state,
      XDG_DATA_HOME: paths.data,
      XDG_RUNTIME_DIR: paths.temporary,
      TMPDIR: paths.temporary,
      TMP: paths.temporary,
      TEMP: paths.temporary,
      NODE_COMPILE_CACHE: join(paths.cache, "node"),
      npm_config_cache: join(paths.cache, "npm"),
      npm_config_userconfig: userConfig,
      npm_config_globalconfig: globalConfig,
      npm_config_update_notifier: "false",
    },
  };
}

// Consume the documented vectors without running a shell or registering with
// real clients. Only their server command after `--` is launched in this fixture.
function installExamples(readme, prefix, candidate) {
  const section = readme
    .split("### Isolated candidate installation\n")[1]
    ?.split("\n### ")[0];
  assert.ok(section, "Missing isolated-install examples.");
  const block = /```bash\n([\s\S]*?)\n```/u.exec(section)?.[1];
  assert.ok(block);
  const replacements = new Map([
    ['"$prefix"', prefix],
    ['"$candidate"', candidate],
    ['"$prefix/bin/agent-run"', join(prefix, "bin/agent-run")],
  ]);
  const vectors = block
    .split("\n")
    .filter((line) =>
      /^(?:npm |codex |claude |"\$prefix\/bin\/agent-run")/u.test(line),
    )
    .map((line) =>
      line.split(/\s+/u).map((word) => {
        const value = replacements.get(word);
        assert.ok(
          value !== undefined || !/["'$`;|&<>]/u.test(word),
          "Unsupported example syntax.",
        );
        return value ?? word;
      }),
    );
  assert.equal(vectors.length, 4);
  const install = vectors.find(([name]) => name === "npm");
  assert.deepEqual(install, [
    "npm",
    "install",
    "--global",
    "--prefix",
    prefix,
    "--offline",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    candidate,
  ]);
  const help = vectors.find(([name]) => name === join(prefix, "bin/agent-run"));
  assert.deepEqual(help, [join(prefix, "bin/agent-run"), "--help"]);
  const registrations = vectors.filter(([name]) =>
    ["codex", "claude"].includes(name),
  );
  assert.deepEqual(
    registrations.map(([name]) => name),
    ["codex", "claude"],
  );
  const launches = registrations.map((vector) =>
    vector.slice(vector.indexOf("--") + 1),
  );
  for (const launch of launches)
    assert.deepEqual(launch, [join(prefix, "bin/agent-run"), "mcp"]);
  return { install, help, launch: launches[0] };
}

async function inspectInstallation(root, manifest, manifestBytes) {
  const files = [];
  async function walk(path) {
    const metadata = await lstat(path);
    assert.equal(await realpath(path), path);
    assert.equal(
      metadata.isSymbolicLink(),
      false,
      "Installed workspace links are forbidden.",
    );
    if (metadata.isDirectory()) {
      for (const name of await readdir(path)) await walk(join(path, name));
    } else {
      assert.ok(metadata.isFile());
      assert.equal(metadata.nlink, 1);
      files.push(relative(root, path));
    }
  }
  await walk(root);
  assert.deepEqual(
    files.sort(),
    [...manifest.files.map(({ path }) => path), "release-manifest.json"].sort(),
  );
  for (const entry of manifest.files) {
    const path = join(root, entry.path);
    const bytes = await readFile(path);
    assert.equal(bytes.length, entry.size, entry.path);
    assert.equal(digest(bytes), entry.sha256, entry.path);
    assert.equal(
      ((await lstat(path)).mode & 0o111) !== 0,
      entry.mode === 0o755,
      entry.path,
    );
  }
  assert.deepEqual(
    await readFile(join(root, "release-manifest.json")),
    manifestBytes,
  );
}

const IMPORT_PROBE = `
import assert from "node:assert/strict";
import { readFile, realpath } from "node:fs/promises";
import { createRequire } from "node:module";
import { join, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";
const root = process.argv[1];
assert.equal(process.env.NODE_PATH, undefined);
assert.equal(process.env.NODE_OPTIONS, undefined);
const metadata = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
assert.equal(metadata.type, "module");
assert.equal(metadata.engines.node, ">=24 <25");
assert.equal(metadata.private, true);
assert.equal(metadata.license, "UNLICENSED");
assert.equal(metadata.workspaces, undefined);
assert.equal(metadata.devDependencies, undefined);
assert.equal(metadata.scripts, undefined);
const application = await import(pathToFileURL(join(root, "src/index.js")));
const configuration = await application.loadRunnerConfiguration();
assert.equal(configuration.issueReporting, true);
const manifest = JSON.parse(await readFile(join(root, "release-manifest.json"), "utf8"));
const privateImports = [];
for (const dependency of manifest.dependencies) {
  if (!dependency.name.startsWith("@agent-runner/")) continue;
  const path = join(root, dependency.path, "package.json");
  const workspace = JSON.parse(await readFile(path, "utf8"));
  assert.equal(workspace.private, true);
  assert.equal(workspace.type, "module");
  const resolved = createRequire(path).resolve(dependency.name);
  const child = relative(root, resolved);
  assert.ok(child && child !== ".." && !child.startsWith(".." + sep));
  assert.equal(await realpath(resolved), resolved);
  await import(pathToFileURL(resolved));
  privateImports.push(dependency.name);
}
process.stdout.write(JSON.stringify({ metadata, privateImports: privateImports.sort(), pipelines: application.listPipelines().map(({ id }) => id).sort() }));
`;

test("an inspected candidate installs offline and serves standalone pinned CLI and MCP clients", async (t) => {
  const directory = await runtimeFixtureDirectory(t);
  assert.equal(within(await realpath(CHECKOUT), directory), false);
  const prefix = join(directory, "private prefix");
  const { env, paths, node } = await environment(directory, prefix);
  const readme = await readFile(
    new URL("../README.md", import.meta.url),
    "utf8",
  );
  const guide = await readFile(
    new URL("../docs/OPERATOR_GUIDE.md", import.meta.url),
    "utf8",
  );
  const release = await assembleRelease({
    outputPath: join(directory, "candidate"),
  });
  const manifestBytes = await readFile(
    join(release.packagePath, "release-manifest.json"),
  );
  const packed = await packRelease(release);
  assert.equal(packed.files, release.manifest.files.length + 1);
  const archiveDigest = digest(await readFile(packed.tarballPath));
  const examples = installExamples(readme, prefix, packed.tarballPath);
  await runCommand(examples.install[0], examples.install.slice(1), {
    cwd: paths.work,
    env: { ...env, PATH: process.env.PATH },
  });
  assert.equal(digest(await readFile(packed.tarballPath)), archiveDigest);
  const installed = join(prefix, "lib/node_modules", release.manifest.name);
  await inspectInstallation(installed, release.manifest, manifestBytes);
  const executable = join(prefix, "bin/agent-run");
  assert.equal(await realpath(executable), join(installed, "bin/agent-run.js"));
  assert.equal(
    (await lstat(join(installed, "bin/agent-run.js"))).mode & 0o100,
    0o100,
  );
  const probe = await runCommand(
    node,
    ["--input-type=module", "--eval", IMPORT_PROBE, installed],
    { cwd: paths.work, env },
  );
  assert.equal(probe.stderr, "");
  const imported = JSON.parse(probe.stdout);
  const privateNames = release.manifest.dependencies
    .filter(({ name }) => name.startsWith("@agent-runner/"))
    .map(({ name }) => name)
    .sort();
  assert.deepEqual(imported.privateImports, privateNames);
  assert.ok(privateNames.includes("@agent-runner/commit-plan"));
  assert.ok(privateNames.includes("@agent-runner/custom-plan"));
  const pipelines = [
    "audit",
    "init",
    "plan-authoring",
    "plan-execution",
    "polishing",
  ];
  assert.deepEqual(imported.pipelines, pipelines);
  const help = await runCommand(examples.help[0], examples.help.slice(1), {
    cwd: paths.work,
    env,
  });
  assert.match(help.stdout, /^Agent Runner\n/u);
  assert.match(help.stdout, /agent-run mcp/u);
  assert.equal(help.stderr, "");
  const version = await runCommand("agent-run", ["--version"], {
    cwd: paths.work,
    env,
  });
  assert.equal(version.stdout, `${release.manifest.version}\n`);
  assert.equal(version.stderr, "");
  const statePath = join(
    paths.state,
    "agent-runner/runtime-admission/runtime.json",
  );
  const retired = JSON.parse(await readFile(statePath, "utf8"));
  assert.deepEqual(retired.users, []);
  const runtime = retired.active;
  assert.equal(runtime.payloadId, digest(manifestBytes));
  assert.ok(
    within(join(paths.data, "agent-runner/runtime/payloads"), runtime.rootPath),
  );
  assert.notEqual(runtime.rootPath, installed);
  assert.equal(runtime.nodePath, node);
  assert.equal(runtime.nodeVersion, process.version);
  assert.equal((await lstat(runtime.executablePath)).mode & 0o777, 0o500);
  assert.equal(
    await readFile(join(runtime.rootPath, "docs/OPERATOR_GUIDE.md"), "utf8"),
    guide,
  );

  const mcp = mcpProcess(examples.launch[0], examples.launch.slice(1), {
    cwd: paths.work,
    env,
  });
  try {
    const initialized = await mcp.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "package-smoke", version: "1.0.0" },
    });
    assert.equal(initialized.protocolVersion, "2025-11-25");
    assert.equal(initialized.serverInfo.version, release.manifest.version);
    assert.ok(initialized.capabilities.tools);
    mcp.notify("notifications/initialized");
    const discovery = await mcp.request("tools/list", {});
    const names = discovery.tools.map(({ name }) => name);
    assert.equal(new Set(names).size, names.length);
    for (const name of [
      "pipelines_list",
      "guidance_read",
      "guidance_update",
      "run_start",
      "run_respond",
      "run_resume",
      "run_status",
      "run_wait",
      "run_activity",
      "run_pause",
      "run_cancel",
      "unexpected_issue_report",
    ])
      assert.ok(names.includes(name), name);
    const listing = await mcp.request("tools/call", {
      name: "pipelines_list",
      arguments: {},
    });
    assert.notEqual(listing.isError, true);
    assert.deepEqual(
      listing.structuredContent.pipelines.map(({ id }) => id).sort(),
      pipelines,
    );
    const admitted = JSON.parse(await readFile(statePath, "utf8"));
    assert.equal(admitted.users.length, 1);
    assert.deepEqual(admitted.active, runtime);
    await rename(installed, join(directory, "retired outer package"));
    const guidance = await mcp.request("tools/call", {
      name: "guidance_read",
      arguments: { projectPath: paths.work },
    });
    assert.notEqual(guidance.isError, true);
    assert.equal(guidance.structuredContent.commonContent, guide);
    assert.equal(guidance.structuredContent.localContent, "");
    assert.equal(guidance.structuredContent.localHash, null);
    await mcp.shutdown();
  } finally {
    await mcp.dispose();
  }
  assert.deepEqual(JSON.parse(await readFile(statePath, "utf8")).users, []);
  assert.equal(
    await readFile(join(runtime.rootPath, "docs/OPERATOR_GUIDE.md"), "utf8"),
    guide,
  );
  await assert.rejects(lstat(join(paths.config, "agent-runner/config.json")), {
    code: "ENOENT",
  });
  assert.deepEqual(await readdir(paths.work), []);
  assert.deepEqual(await readdir(join(paths.state, "agent-runner/runs")), []);
});
