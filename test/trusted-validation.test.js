import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { runInNewContext } from "node:vm";

import {
  readProcessIdentity,
  resolveOwnedProcessLauncher,
  spawnOwnedProcess,
} from "../src/platform/index.js";
import { createGitService } from "../src/git/index.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
  runExactCommand,
  validateTrustedValidationSnapshot,
} from "../src/trusted-validation/index.js";

const executeFile = promisify(execFile);

function passthroughSandbox(command, { environment }) {
  return { command, environment };
}

function trustedService(git, options = {}) {
  return createTrustedValidationService({
    git,
    sandboxCommand: passthroughSandbox,
    ...options,
  });
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function repository(t) {
  const projectPath = await mkdtemp(join(tmpdir(), "agent-runner-trusted-"));
  t.after(() => rm(projectPath, { recursive: true, force: true }));
  await executeFile("git", ["init", "-q", projectPath]);
  await executeFile("git", ["-C", projectPath, "config", "user.name", "Test"]);
  await executeFile("git", [
    "-C",
    projectPath,
    "config",
    "user.email",
    "test@example.com",
  ]);
  await writeFile(join(projectPath, "tracked.txt"), "initial\n");
  await executeFile("git", ["-C", projectPath, "add", "."]);
  await executeFile("git", [
    "-C",
    projectPath,
    "commit",
    "-qm",
    "test: fixture",
  ]);
  return projectPath;
}

function siblingStorage(t, projectPath, name) {
  const storageRoot = `${projectPath}-${name}`;
  t.after(() => rm(storageRoot, { recursive: true, force: true }));
  return storageRoot;
}

function snapshot(alias, command, executable, argumentsList, timeoutMs) {
  return createTrustedValidationSnapshot(
    {
      [alias]: {
        command,
        executable,
        arguments: argumentsList,
      },
    },
    [alias],
    timeoutMs,
  );
}

function legacySnapshot(schemaVersion) {
  const vector = {
    alias: "check",
    command: "node check.js",
    executable: "node",
    arguments: ["check.js"],
    ...(schemaVersion >= 2 ? { capabilities: {} } : {}),
  };
  const identity = hash(JSON.stringify(vector));
  return {
    schemaVersion,
    ...(schemaVersion >= 3 ? { timeoutMs: 3_600_000 } : {}),
    commands: [{ ...vector, identity }],
    commandFingerprint: hash(JSON.stringify([identity])),
    configurationFingerprint: hash(
      JSON.stringify({
        schemaVersion,
        commands: [vector],
        ...(schemaVersion >= 3 ? { timeoutMs: 3_600_000 } : {}),
      }),
    ),
  };
}

test("defaults trusted validation commands to a one-hour timeout", async () => {
  const projectPath = process.cwd();
  const before = { projectPath, contentFingerprint: hash("content") };
  const trusted = snapshot("check", "node check.js", "node", ["check.js"]);
  let execution;
  const service = trustedService(
    {
      async snapshot() {
        return before;
      },
      async assertUnchanged(value) {
        assert.equal(value, before);
      },
    },
    {
      runCommand(command, options) {
        execution = { command, options };
        return {
          status: "PASS",
          exitCode: 0,
          signal: null,
          timedOut: false,
          reason: "exit",
        };
      },
    },
  );

  const result = await service.execute({
    bindings: {
      contentFingerprint: before.contentFingerprint,
      validationInfrastructureFingerprint: hash("infrastructure"),
      commandFingerprint: trusted.commandFingerprint,
      configurationFingerprint: trusted.configurationFingerprint,
    },
    commandIdentity: trusted.commands[0].identity,
    projectPath,
    snapshot: trusted,
  });

  assert.equal(result.status, "PASS");
  assert.deepEqual(execution.command, trusted.commands[0]);
  assert.equal(execution.options.timeoutMs, 3_600_000);
});

test("freezes bounded timeouts into configuration fingerprints without changing command identities", () => {
  const first = snapshot("check", "node check.js", "node", ["check.js"], 1);
  const second = snapshot(
    "check",
    "node check.js",
    "node",
    ["check.js"],
    2_147_483_647,
  );

  assert.equal(first.schemaVersion, 4);
  assert.equal(first.timeoutMs, 1);
  assert.equal(second.timeoutMs, 2_147_483_647);
  assert.equal(first.commands[0].identity, second.commands[0].identity);
  assert.equal(
    first.commands[0].identity,
    legacySnapshot(2).commands[0].identity,
  );
  assert.equal(first.commandFingerprint, second.commandFingerprint);
  assert.notEqual(
    first.configurationFingerprint,
    second.configurationFingerprint,
  );
  for (const timeoutMs of [0, -1, 2_147_483_648, 1.5, "1000", null]) {
    assert.throws(
      () => snapshot("check", "node check.js", "node", ["check.js"], timeoutMs),
      { code: "ERR_INVALID_TRUSTED_VALIDATION" },
    );
  }
});

test("uses each concurrent run snapshot's timeout independently", async () => {
  const executions = new Map();
  const service = trustedService(
    {
      async snapshot({ projectPath }) {
        return {
          projectPath,
          contentFingerprint: hash(`content:${projectPath}`),
        };
      },
      async assertUnchanged(value) {
        assert.equal(
          value.contentFingerprint,
          hash(`content:${value.projectPath}`),
        );
      },
    },
    {
      async runCommand(command, options) {
        await Promise.resolve();
        executions.set(options.cwd, {
          alias: command.alias,
          timeoutMs: options.timeoutMs,
        });
        return {
          status: "PASS",
          exitCode: 0,
          signal: null,
          timedOut: false,
          reason: "exit",
        };
      },
    },
  );
  const runs = [
    {
      projectPath: "/projects/first",
      trusted: snapshot("first", "node first.js", "node", ["first.js"], 12_345),
    },
    {
      projectPath: "/projects/second",
      trusted: snapshot(
        "second",
        "node second.js",
        "node",
        ["second.js"],
        67_890,
      ),
    },
  ];

  await Promise.all(
    runs.map(({ projectPath, trusted }) =>
      service.execute({
        bindings: {
          contentFingerprint: hash(`content:${projectPath}`),
          validationInfrastructureFingerprint: hash("infrastructure"),
          commandFingerprint: trusted.commandFingerprint,
          configurationFingerprint: trusted.configurationFingerprint,
        },
        commandIdentity: trusted.commands[0].identity,
        projectPath,
        snapshot: trusted,
      }),
    ),
  );

  assert.deepEqual(Object.fromEntries(executions), {
    "/projects/first": { alias: "first", timeoutMs: 12_345 },
    "/projects/second": { alias: "second", timeoutMs: 67_890 },
  });
});

test("keeps legacy snapshot versions compatible without granting new authority", async () => {
  const projectPath = process.cwd();
  const before = { projectPath, contentFingerprint: hash("content") };
  const observed = [];
  const service = trustedService(
    {
      async snapshot() {
        return before;
      },
      async assertUnchanged(value) {
        assert.equal(value, before);
      },
    },
    {
      runCommand(_command, options) {
        observed.push(options.timeoutMs);
        return {
          status: "PASS",
          exitCode: 0,
          signal: null,
          timedOut: false,
          reason: "exit",
        };
      },
    },
  );

  for (const schemaVersion of [1, 2, 3]) {
    const trusted = legacySnapshot(schemaVersion);
    await service.execute({
      bindings: {
        contentFingerprint: before.contentFingerprint,
        validationInfrastructureFingerprint: hash("infrastructure"),
        commandFingerprint: trusted.commandFingerprint,
        configurationFingerprint: trusted.configurationFingerprint,
      },
      commandIdentity: trusted.commands[0].identity,
      projectPath,
      snapshot: trusted,
    });
  }

  assert.deepEqual(observed, [3_600_000, 3_600_000, 3_600_000]);
  const legacy = legacySnapshot(3);
  assert.throws(() =>
    validateTrustedValidationSnapshot({
      ...legacy,
      commands: [
        {
          ...legacy.commands[0],
          capabilities: { sourceProjection: true },
        },
      ],
    }),
  );
});

test("caps preparation at ten seconds while honoring shorter snapshot timeouts", async () => {
  const projectPath = process.cwd();
  const before = { projectPath, contentFingerprint: hash("content") };
  const observed = [];
  const service = trustedService(
    {
      async snapshot() {
        return before;
      },
      async assertUnchanged(value) {
        assert.equal(value, before);
      },
    },
    {
      async runCommand(_command, options) {
        observed.push(options.timeoutMs);
        await options.onNoLaunch();
        return {
          status: "PASS",
          exitCode: 0,
          signal: null,
          timedOut: false,
          reason: "exit",
        };
      },
    },
  );

  for (const timeoutMs of [4_000, 40_000]) {
    const trusted = snapshot(
      `check-${timeoutMs}`,
      `node check-${timeoutMs}.js`,
      "node",
      [`check-${timeoutMs}.js`],
      timeoutMs,
    );
    await service.inspectRequirements({
      inventory: [trusted.commands[0].command],
      requirements: [],
      projectPath,
      snapshot: trusted,
      async onProcess() {},
      onPreparation: async () =>
        Object.assign(async () => {}, { noLaunch: async () => {} }),
      async onResource() {},
    });
  }

  assert.deepEqual(observed, [4_000, 10_000]);
});

test("rejects the retired service-construction timeout override", () => {
  assert.throws(() => createTrustedValidationService({ timeoutMs: 1_000 }), {
    code: "ERR_INVALID_TRUSTED_VALIDATION_OPTIONS",
  });
});

test("forwards sandbox ownership through trusted execution without changing containment", async () => {
  for (const ownershipMode of [
    "native-sandbox-provider",
    undefined,
    "ordinary",
  ]) {
    for (const descendantsStopped of [false, true]) {
      const projectPath = process.cwd();
      const before = { projectPath, contentFingerprint: hash("content") };
      const trusted = snapshot(
        "check",
        "node check.js",
        "node",
        ["check.js"],
        456,
      );
      const environment = { PATH: "/usr/bin" };
      const signal = new AbortController().signal;
      const onProcess = async () => {};
      let execution;
      let launch;
      let inspected = false;
      const service = createTrustedValidationService({
        environment,
        git: {
          async snapshot() {
            return before;
          },
          async assertUnchanged(value) {
            assert.equal(value, before);
            inspected = true;
          },
        },
        sandboxCommand(command) {
          return {
            command,
            environment,
            ownershipMode,
            readinessRequired: true,
          };
        },
        runCommand(command, options) {
          execution = { command, options };
          return runExactCommand(command, {
            ...options,
            spawnProcess(file, argumentsList, spawnOptions) {
              launch = { file, argumentsList, options: spawnOptions };
              const child = new EventEmitter();
              child.pid = 123;
              child.stdio = [null, null, null, null, new EventEmitter()];
              child.ownedCompletion = Promise.resolve({
                outcome: { type: "close", exitCode: 7, signal: null },
                descendantsStopped,
              });
              queueMicrotask(() => {
                child.stdio[4].emit("data", Buffer.from([1]));
                child.emit("close", 0, null);
              });
              return child;
            },
          });
        },
        terminationGraceMs: 123,
      });

      const result = await service.execute({
        bindings: {
          contentFingerprint: before.contentFingerprint,
          validationInfrastructureFingerprint: hash("infrastructure"),
          commandFingerprint: trusted.commandFingerprint,
          configurationFingerprint: trusted.configurationFingerprint,
        },
        commandIdentity: trusted.commands[0].identity,
        projectPath,
        snapshot: trusted,
        signal,
        onProcess,
      });

      assert.deepEqual(execution.command, trusted.commands[0]);
      assert.equal(execution.options.timeoutMs, 456);
      assert.equal(execution.options.readinessRequired, true);
      assert.deepEqual(launch, {
        file: "node",
        argumentsList: ["check.js"],
        options: {
          cwd: projectPath,
          detached: true,
          env: environment,
          shell: false,
          stdio: ["ignore", "ignore", "ignore", "pipe"],
          signal,
          onProcess,
          descendantGraceMs: 123,
          ownershipMode: ownershipMode ?? "ordinary",
        },
      });
      assert.equal(inspected, true);
      assert.equal(result.status, descendantsStopped ? "BLOCKED" : "FAIL");
      assert.equal(result.exitCode, descendantsStopped ? null : 7);
    }
  }
});

test("bounds each snapshot independently from the command catalog", () => {
  const definitions = Object.fromEntries(
    Array.from({ length: 256 }, (_, index) => [
      `check-${index + 1}`,
      {
        command: `node validation-${index + 1}.js`,
        executable: "node",
        arguments: [`validation-${index + 1}.js`],
      },
    ]),
  );
  const aliases = Object.keys(definitions);

  assert.equal(
    createTrustedValidationSnapshot(definitions, aliases.slice(0, 32)).commands
      .length,
    32,
  );
  assert.throws(
    () => createTrustedValidationSnapshot(definitions, aliases.slice(0, 33)),
    /Trusted validation selection is invalid/u,
  );
});

test("preserves line feeds in direct command arguments", () => {
  const script = "first line\nsecond line";
  const trusted = snapshot(
    "multiline-check",
    "python3 -c multiline-check",
    "python3",
    ["-c", script],
  );

  assert.equal(trusted.commands[0].arguments[1], script);
  assert.deepEqual(validateTrustedValidationSnapshot(trusted), trusted);
  assert.throws(
    () =>
      snapshot(
        "multiline-command",
        "python3\n-c multiline-command",
        "python3",
        ["-c", script],
      ),
    /command is invalid/u,
  );
  assert.throws(
    () =>
      snapshot(
        "multiline-executable",
        "python3 -c multiline-executable",
        "python3\n-c",
        ["-c", script],
      ),
    /executable is invalid/u,
  );
});

test("rejects other control characters and line separators in direct arguments", () => {
  const forbiddenCodePoints = [
    ...Array.from({ length: 0x20 }, (_, codePoint) => codePoint),
    ...Array.from({ length: 0x21 }, (_, index) => 0x7f + index),
    0x2028,
    0x2029,
  ].filter((codePoint) => codePoint !== 0x0a);

  for (const codePoint of forbiddenCodePoints) {
    const character = String.fromCodePoint(codePoint);
    const label = `U+${codePoint.toString(16).padStart(4, "0")}`;

    assert.throws(
      () =>
        snapshot(
          "invalid-control-check",
          "python3 -c invalid-control-check",
          "python3",
          ["-c", `first line${character}second line`],
        ),
      /argument 2 is invalid/u,
      label,
    );
  }
});

async function bindings(git, projectPath, trusted) {
  return {
    contentFingerprint: await git.contentFingerprint({
      allowedPaths: [],
      projectPath,
    }),
    validationInfrastructureFingerprint: hash("test infrastructure"),
    commandFingerprint: trusted.commandFingerprint,
    configurationFingerprint: trusted.configurationFingerprint,
  };
}

async function projectedBindings(git, projectPath, trusted) {
  const source = await git.snapshot({ allowedPaths: [], projectPath });
  return {
    bindings: {
      contentFingerprint: source.contentFingerprint,
      validationInfrastructureFingerprint: hash("test infrastructure"),
      commandFingerprint: trusted.commandFingerprint,
      configurationFingerprint: trusted.configurationFingerprint,
    },
    sourceHead: source.head,
  };
}

test("executes an exact persisted vector with bounded redacted evidence", async (t) => {
  const projectPath = await repository(t);
  const git = createGitService();
  const source = `const {spawn}=await import("node:child_process");spawn(process.execPath,["--eval","process.exit(0)"],{stdio:"ignore"}).on("close",(code)=>{process.exitCode=code;});`;
  const trusted = snapshot(
    "service-check",
    "node service validation",
    process.execPath,
    ["--input-type=module", "--eval", source],
  );
  const service = trustedService(git, { monotonicNow: () => 0n });

  const result = await service.execute({
    bindings: await bindings(git, projectPath, trusted),
    commandIdentity: trusted.commands[0].identity,
    projectPath,
    snapshot: trusted,
  });

  assert.equal(result.status, "PASS");
  assert.equal(result.exitCode, 0);
  assert.equal(result.commandIdentity, trusted.commands[0].identity);
  assert.deepEqual(result.evidence, [
    "Runner-trusted command service-check exited with code 0.",
    "Runner-measured attempt elapsed time: 0.000 ms (executor invoked).",
  ]);
  assert.deepEqual(validateTrustedValidationSnapshot(trusted), trusted);
});

test("binds projected execution to exact source while leaving the checkout untouched", async (t) => {
  const projectPath = await repository(t);
  await writeFile(join(projectPath, "untracked.txt"), "workspace\n");
  const git = createGitService();
  const trusted = createTrustedValidationSnapshot(
    {
      build: {
        command: "node build",
        executable: process.execPath,
        arguments: ["build.js"],
        capabilities: { sourceProjection: true },
      },
    },
    ["build"],
  );
  const records = [];
  const service = trustedService(git, {
    storageRoot: siblingStorage(t, projectPath, "projected-storage"),
    async runCommand(command, options) {
      assert.deepEqual(command, trusted.commands[0]);
      assert.notEqual(options.cwd, projectPath);
      assert.equal(
        await readFile(join(options.cwd, "tracked.txt"), "utf8"),
        "initial\n",
      );
      assert.equal(
        await readFile(join(options.cwd, "untracked.txt"), "utf8"),
        "workspace\n",
      );
      await writeFile(join(options.cwd, "tracked.txt"), "generated\n");
      await writeFile(join(options.cwd, "build-output.txt"), "output\n");
      return {
        status: "PASS",
        exitCode: 0,
        signal: null,
        timedOut: false,
        reason: "exit",
      };
    },
  });

  const result = await service.execute({
    ...(await projectedBindings(git, projectPath, trusted)),
    commandIdentity: trusted.commands[0].identity,
    onProcess: async () => {},
    onResource: async (record) => records.push(record),
    projectPath,
    snapshot: trusted,
  });

  assert.equal(result.status, "PASS", JSON.stringify({ result, records }));
  assert.match(result.sourceHead, /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u);
  assert.equal(
    await readFile(join(projectPath, "tracked.txt"), "utf8"),
    "initial\n",
  );
  await assert.rejects(readFile(join(projectPath, "build-output.txt")), {
    code: "ENOENT",
  });
  assert.deepEqual(
    records.map((record) => record?.phase ?? null),
    ["allocating", "allocated", null],
  );
});

test("rejects source drift after projection without launching the check", async (t) => {
  const projectPath = await repository(t);
  const git = createGitService();
  const trusted = createTrustedValidationSnapshot(
    {
      build: {
        command: "node build",
        executable: process.execPath,
        arguments: ["build.js"],
        capabilities: { sourceProjection: true },
      },
    },
    ["build"],
  );
  const service = trustedService(
    {
      ...git,
      async materializeSource(options) {
        const materialized = await git.materializeSource(options);
        await writeFile(join(projectPath, "tracked.txt"), "raced\n");
        return materialized;
      },
    },
    {
      storageRoot: siblingStorage(t, projectPath, "raced-storage"),
      runCommand: () => assert.fail("A stale projection must not execute"),
    },
  );

  await assert.rejects(
    service.execute({
      ...(await projectedBindings(git, projectPath, trusted)),
      commandIdentity: trusted.commands[0].identity,
      onProcess: async () => {},
      onResource: async () => {},
      projectPath,
      snapshot: trusted,
    }),
    (error) =>
      error.code === "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY" &&
      error.changes.includes("tracked-content"),
  );
});

test("normalizes a materialization race as a stale trusted-validation binding", async (t) => {
  const projectPath = await repository(t);
  const git = createGitService();
  const trusted = createTrustedValidationSnapshot(
    {
      build: {
        command: "node build",
        executable: process.execPath,
        arguments: ["build.js"],
        capabilities: { sourceProjection: true },
      },
    },
    ["build"],
  );
  const service = trustedService(
    {
      ...git,
      async materializeSource() {
        throw Object.assign(new Error("Source raced"), {
          code: "ERR_GIT_SOURCE_CHANGED",
        });
      },
    },
    {
      storageRoot: siblingStorage(t, projectPath, "stale-storage"),
      runCommand: () => assert.fail("A stale projection must not execute"),
    },
  );

  await assert.rejects(
    service.execute({
      ...(await projectedBindings(git, projectPath, trusted)),
      commandIdentity: trusted.commands[0].identity,
      onProcess: async () => {},
      onResource: async () => {},
      projectPath,
      snapshot: trusted,
    }),
    { code: "ERR_TRUSTED_VALIDATION_BINDING_CHANGED" },
  );
});

test("rejects a changed source HEAD with the same workspace fingerprint", async (t) => {
  const projectPath = await repository(t);
  const git = createGitService();
  const trusted = createTrustedValidationSnapshot(
    {
      build: {
        command: "node build",
        executable: process.execPath,
        arguments: ["build.js"],
        capabilities: { sourceProjection: true },
      },
    },
    ["build"],
  );
  const accepted = await projectedBindings(git, projectPath, trusted);
  await executeFile("git", [
    "-C",
    projectPath,
    "commit",
    "--allow-empty",
    "-qm",
    "test: move head",
  ]);
  const service = trustedService(git, {
    storageRoot: siblingStorage(t, projectPath, "moved-head-storage"),
    runCommand: () => assert.fail("A different source HEAD must not execute"),
  });

  await assert.rejects(
    service.execute({
      ...accepted,
      commandIdentity: trusted.commands[0].identity,
      onProcess: async () => {},
      onResource: async () => {},
      projectPath,
      snapshot: trusted,
    }),
    { code: "ERR_TRUSTED_VALIDATION_BINDING_CHANGED" },
  );
});

test("does not retain trusted command process output", async (t) => {
  const projectPath = await repository(t);
  const git = createGitService();
  const trusted = snapshot(
    "failing-check",
    "node failing validation",
    process.execPath,
    [
      "--eval",
      'process.stdout.write("DO_NOT_RETAIN_STDOUT");process.stderr.write("DO_NOT_RETAIN_STDERR");process.exit(7)',
    ],
  );

  const result = await trustedService(git).execute({
    bindings: await bindings(git, projectPath, trusted),
    commandIdentity: trusted.commands[0].identity,
    projectPath,
    snapshot: trusted,
  });

  assert.equal(result.status, "FAIL");
  assert.equal(result.exitCode, 7);
  assert.doesNotMatch(JSON.stringify(result), /DO_NOT_RETAIN/u);
});

test("isolates host-control and remote-write probes", async (t) => {
  const projectPath = await repository(t);
  const git = createGitService();
  const fakeLauncher = join(projectPath, "node_modules", ".bin", "bwrap");
  await mkdir(join(projectPath, "node_modules", ".bin"), {
    recursive: true,
  });
  await writeFile(fakeLauncher, "#!/bin/sh\nexit 0\n");
  await chmod(fakeLauncher, 0o755);
  const trusted = snapshot(
    "remote-write-probe",
    "node remote-write probes",
    process.execPath,
    ["--eval", "process.exit(0)"],
  );
  let execution;
  const launcherPath = "/runner-owned/bwrap";
  const launcherChecks = [];
  const service = createTrustedValidationService({
    environment: {
      ...process.env,
      DOCKER_CONFIG: "/tmp/do-not-expose-docker-credentials",
      DOCKER_HOST: "unix:///run/docker.sock",
      GH_TOKEN: "DO_NOT_EXPOSE_HOSTING_TOKEN",
      KUBECONFIG: "/tmp/do-not-expose-kubernetes-credentials",
      PATH: `node_modules/.bin:${process.env.PATH}`,
      SSH_AUTH_SOCK: "/tmp/do-not-expose-agent.sock",
    },
    git,
    // This test inspects construction only; installed launchers are host state.
    resolveLauncher(executable) {
      assert.equal(executable, null);
      return launcherPath;
    },
    verifyLauncher(path, cwd) {
      assert.equal(path, launcherPath);
      assert.equal(cwd, projectPath);
      launcherChecks.push(path);
      return path;
    },
    async runCommand(command, options) {
      execution = { command, options };
      return {
        status: "PASS",
        exitCode: 0,
        signal: null,
        timedOut: false,
        reason: "exit",
      };
    },
  });

  await service.preflight({ projectPath });

  const result = await service.execute({
    bindings: await bindings(git, projectPath, trusted),
    commandIdentity: trusted.commands[0].identity,
    projectPath,
    snapshot: trusted,
  });

  assert.equal(result.status, "PASS");
  assert.deepEqual(launcherChecks, [launcherPath, launcherPath]);
  assert.equal(execution.command.executable, launcherPath);
  assert.equal(isAbsolute(execution.command.executable), true);
  assert.notEqual(execution.command.executable, fakeLauncher);
  assert.notEqual(execution.command.executable, "bwrap");
  assert.ok(execution.command.arguments.includes("--unshare-net"));
  assert.ok(execution.command.arguments.includes("--unshare-user"));
  assert.ok(execution.command.arguments.includes("--unshare-pid"));
  assert.ok(execution.command.arguments.includes("--cap-drop"));
  assert.ok(
    execution.command.arguments.some(
      (value, index, values) =>
        value === "--tmpfs" && values[index + 1] === "/run",
    ),
  );
  assert.equal(
    execution.command.arguments.some(
      (value, index, values) =>
        ["--bind", "--ro-bind"].includes(value) && values[index + 1] === "/run",
    ),
    false,
  );
  assert.deepEqual(execution.command.arguments.slice(-3), [
    process.execPath,
    "--eval",
    "process.exit(0)",
  ]);
  assert.ok(execution.command.arguments.includes("--ro-bind"));
  assert.equal(execution.command.arguments.includes("--bind"), false);
  assert.ok(execution.command.arguments.includes("--tmpfs"));
  assert.equal(
    execution.command.arguments.some(
      (value, index, values) =>
        value === "--ro-bind" &&
        values[index + 1] === process.env.HOME &&
        values[index + 2] === process.env.HOME,
    ),
    false,
  );
  assert.equal(
    execution.command.arguments.some(
      (value, index, values) =>
        value === "--ro-bind" &&
        values[index + 1] === "/" &&
        values[index + 2] === "/",
    ),
    false,
  );
  assert.ok(
    execution.command.arguments.some(
      (value, index, values) =>
        value === "--ro-bind" &&
        values[index + 1] === projectPath &&
        values[index + 2] === projectPath,
    ),
  );
  assert.equal(execution.options.readinessRequired, true);
  assert.equal(execution.options.ownershipMode, "native-sandbox-provider");
  assert.equal(execution.options.environment.DOCKER_CONFIG, undefined);
  assert.equal(execution.options.environment.DOCKER_HOST, undefined);
  assert.equal(execution.options.environment.GH_TOKEN, undefined);
  assert.equal(execution.options.environment.KUBECONFIG, undefined);
  assert.equal(execution.options.environment.SSH_AUTH_SOCK, undefined);
  assert.equal(execution.options.environment.HOME, "/nonexistent");
  assert.equal(execution.options.environment.GIT_SSH_COMMAND, "/bin/false");
  assert.equal(execution.options.environment.GIT_CONFIG_GLOBAL, "/dev/null");
  const shadowed = createTrustedValidationService({
    bubblewrapExecutable: fakeLauncher,
    git,
  });
  await assert.rejects(
    shadowed.preflight({ projectPath }),
    (cause) => cause.code === "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE",
  );
});

test("rejects a changed trusted launcher before executing its command", async (t) => {
  const projectPath = await repository(t);
  const git = createGitService();
  const trusted = snapshot(
    "launcher-check",
    "node launcher validation",
    process.execPath,
    ["--eval", "process.exit(0)"],
  );
  let verified = false;
  const service = createTrustedValidationService({
    git,
    resolveLauncher: () => "/runner-owned/bwrap",
    monotonicNow: () => 0n,
    verifyLauncher(path) {
      if (verified) {
        throw Object.assign(new Error("Launcher changed."), {
          code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE",
        });
      }
      verified = true;
      return path;
    },
    runCommand() {
      assert.fail("A changed launcher must not execute a command.");
    },
  });
  await service.preflight({ projectPath });

  const result = await service.execute({
    bindings: await bindings(git, projectPath, trusted),
    commandIdentity: trusted.commands[0].identity,
    projectPath,
    snapshot: trusted,
  });

  assert.equal(result.status, "BLOCKED");
  assert.deepEqual(result.evidence, [
    "Runner-trusted command launcher-check could not start in the required isolated executor.",
    "Runner-measured attempt elapsed time: 0.000 ms (blocked before executor invocation).",
  ]);
});

test("distinguishes isolation setup denial from command failure", async (t) => {
  const projectPath = await repository(t);
  const git = createGitService();
  const options = {
    cwd: projectPath,
    environment: process.env,
    readinessRequired: true,
    terminationGraceMs: 100,
    timeoutMs: 1_000,
  };

  const setupDenied = await runExactCommand(
    { executable: process.execPath, arguments: ["--eval", "process.exit(1)"] },
    options,
  );
  const commandFailed = await runExactCommand(
    {
      executable: process.execPath,
      arguments: [
        "--eval",
        'require("node:fs").writeSync(3,Buffer.from([1]));process.exit(7)',
      ],
    },
    options,
  );

  assert.deepEqual(setupDenied, {
    status: "BLOCKED",
    exitCode: null,
    signal: null,
    timedOut: false,
    reason: "isolation",
  });
  assert.equal(commandFailed.status, "FAIL");
  assert.equal(commandFailed.exitCode, 7);
  assert.equal(commandFailed.reason, "exit");

  const trusted = snapshot(
    "isolation-probe",
    "node isolation readiness probe",
    process.execPath,
    ["--eval", "process.exit(0)"],
    1_000,
  );
  const service = createTrustedValidationService({
    git,
    monotonicNow: () => 0n,
    sandboxCommand() {
      return {
        command: {
          executable: process.execPath,
          arguments: ["--eval", "process.exit(1)"],
        },
        environment: process.env,
        readinessRequired: true,
      };
    },
    terminationGraceMs: 100,
  });
  const blocked = await service.execute({
    bindings: await bindings(git, projectPath, trusted),
    commandIdentity: trusted.commands[0].identity,
    projectPath,
    snapshot: trusted,
  });
  assert.equal(blocked.status, "BLOCKED");
  assert.deepEqual(blocked.evidence, [
    "Runner-trusted command isolation-probe could not start in the required isolated executor.",
    "Runner-measured attempt elapsed time: 0.000 ms (executor invoked).",
  ]);
});

test("accepts successful trusted commands without descendants", async (t) => {
  const projectPath = await repository(t);

  const result = await runExactCommand(
    {
      executable: process.execPath,
      arguments: ["--eval", "process.exit(0)"],
    },
    {
      cwd: projectPath,
      environment: process.env,
      terminationGraceMs: 100,
      timeoutMs: 1_000,
    },
  );

  assert.deepEqual(result, {
    status: "PASS",
    exitCode: 0,
    signal: null,
    timedOut: false,
    reason: "exit",
  });
});

test("allows a successful trusted command's descendants to retire", async (t) => {
  const projectPath = await repository(t);
  const processPath = await mkdtemp(
    join(tmpdir(), "agent-runner-retiring-tree-"),
  );
  t.after(() => rm(processPath, { recursive: true, force: true }));
  const pidPath = join(processPath, "child.pid");
  const childSource = `
    const { writeFileSync } = require("node:fs");
    writeFileSync(${JSON.stringify(pidPath)}, String(process.pid));
    process.send("ready");
    setTimeout(() => process.exit(0), 100);
  `;
  const parentSource = `
    const { spawn } = require("node:child_process");
    const child = spawn(process.execPath, ["--eval", ${JSON.stringify(childSource)}], {
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    child.once("message", () => process.exit(0));
    child.once("error", () => process.exit(1));
  `;

  const result = await runExactCommand(
    {
      executable: process.execPath,
      arguments: ["--eval", parentSource],
    },
    {
      cwd: projectPath,
      environment: process.env,
      terminationGraceMs: 500,
      timeoutMs: 1_000,
    },
  );

  assert.equal(result.status, "PASS");
  assert.equal(result.exitCode, 0);
  const childPid = Number.parseInt(await readFile(pidPath, "utf8"), 10);
  assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
});

test("terminates persistent descendants after successful trusted commands", async (t) => {
  const projectPath = await repository(t);
  const processPath = await mkdtemp(
    join(tmpdir(), "agent-runner-leaked-tree-"),
  );
  const pidPath = join(processPath, "child.pid");
  t.after(async () => {
    try {
      const childPid = Number.parseInt(await readFile(pidPath, "utf8"), 10);
      try {
        process.kill(childPid, "SIGKILL");
      } catch (cause) {
        if (cause?.code !== "ESRCH") {
          throw cause;
        }
      }
    } catch (cause) {
      if (cause?.code !== "ENOENT") {
        throw cause;
      }
    } finally {
      await rm(processPath, { recursive: true, force: true });
    }
  });
  const childSource = `
    const { writeFileSync } = require("node:fs");
    writeFileSync(${JSON.stringify(pidPath)}, String(process.pid));
    process.on("SIGTERM", () => {});
    process.send("ready");
    setInterval(() => {}, 1_000);
  `;
  const parentSource = `
    const { spawn } = require("node:child_process");
    const child = spawn(process.execPath, ["--eval", ${JSON.stringify(childSource)}], {
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    child.once("message", () => process.exit(0));
    child.once("error", () => process.exit(1));
  `;

  const result = await runExactCommand(
    {
      executable: process.execPath,
      arguments: ["--eval", parentSource],
    },
    {
      cwd: projectPath,
      environment: process.env,
      terminationGraceMs: 100,
      timeoutMs: 1_000,
    },
  );

  assert.deepEqual(result, {
    status: "BLOCKED",
    exitCode: null,
    signal: null,
    timedOut: false,
    reason: "process-tree",
  });
  const childPid = Number.parseInt(await readFile(pidPath, "utf8"), 10);
  assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
});

test("supervised trusted commands preserve readiness, exit status, and descendant rejection", async (t) => {
  const projectPath = await repository(t);
  const recorded = [];
  const recordedIdentities = new Map();
  let registrationSideEffect;
  const options = {
    cwd: projectPath,
    environment: process.env,
    timeoutMs: 4000,
    terminationGraceMs: 100,
    onProcess: async (pid, proof) => {
      recorded.push(pid);
      if (pid !== null) recordedIdentities.set(pid, proof.processIdentity);
      if (pid !== null) registrationSideEffect?.();
    },
  };
  const failed = await runExactCommand(
    {
      executable: process.execPath,
      arguments: [
        "-e",
        "require('node:fs').writeSync(3, Buffer.from([1])); process.exit(7)",
      ],
    },
    { ...options, readinessRequired: true },
  );
  assert.equal(failed.status, "FAIL");
  assert.equal(failed.exitCode, 7);
  assert.equal(recorded.length, 2);
  assert.equal(recorded[1], null);

  let neighbor;
  let neighborClosed;
  registrationSideEffect = () => {
    neighbor = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
      stdio: "ignore",
    });
    neighborClosed = new Promise((resolve) => neighbor.once("close", resolve));
  };
  const concurrent = await runExactCommand(
    { executable: process.execPath, arguments: ["-e", "process.exit(0)"] },
    options,
  );
  registrationSideEffect = undefined;
  t.after(async () => {
    if (neighbor.exitCode === null && neighbor.signalCode === null)
      neighbor.kill("SIGKILL");
    await neighborClosed;
  });
  assert.equal(concurrent.status, "PASS");
  assert.doesNotThrow(() => process.kill(neighbor.pid, 0));
  neighbor.kill("SIGKILL");
  await neighborClosed;

  const detachedIdentityPath = join(projectPath, "detached-identity.json");
  let detachedIdentity;
  t.after(async () => {
    if (detachedIdentity === undefined) return;
    const currentIdentity = await readProcessIdentity(detachedIdentity.pid);
    if (
      currentIdentity?.bootId === detachedIdentity.bootId &&
      currentIdentity.startTicks === detachedIdentity.startTicks
    ) {
      try {
        process.kill(detachedIdentity.pid, "SIGKILL");
      } catch {}
    }
  });
  for (const command of [
    {
      executable: "/bin/bash",
      arguments: ["-c", "(trap '' HUP TERM; while :; do :; done) &"],
    },
    {
      executable: "/bin/bash",
      arguments: [
        "-c",
        "set -m; (child=$BASHPID; kill -0 -- -$child || exit 1; trap '' HUP TERM; while :; do :; done) &",
      ],
    },
    {
      detached: true,
      executable: process.execPath,
      arguments: [
        "-e",
        "const { spawn } = require('node:child_process'); " +
          "const { readFileSync, writeFileSync } = require('node:fs'); " +
          "function launch(attempt = 0) { " +
          "const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], " +
          "{ detached: true, stdio: 'ignore' }); " +
          "child.once('error', (cause) => { " +
          "if (cause.code === 'EAGAIN' && attempt < 20) " +
          "setTimeout(() => launch(attempt + 1), 25); " +
          "else process.exitCode = 1; }); " +
          "child.once('spawn', () => { " +
          "const stat = readFileSync('/proc/' + child.pid + '/stat', 'utf8'); " +
          "const fields = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\\s+/); " +
          `writeFileSync(${JSON.stringify(detachedIdentityPath)}, JSON.stringify({ ` +
          "pid: child.pid, bootId: readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(), " +
          "startTicks: fields[19] })); child.unref(); }); } launch();",
      ],
    },
  ]) {
    const { detached, ...request } = command;
    const recordedBefore = recorded.length;
    const leaked = await runExactCommand(request, options);
    assert.deepEqual(leaked, {
      status: "BLOCKED",
      exitCode: null,
      signal: null,
      timedOut: false,
      reason: "process-tree",
    });
    assert.equal(recorded.length, recordedBefore + 2);
    assert.equal(recorded.at(-1), null);
    const supervisorPid = recorded.at(-2);
    assert.notDeepEqual(
      await readProcessIdentity(supervisorPid),
      recordedIdentities.get(supervisorPid),
    );
    if (detached) {
      detachedIdentity = JSON.parse(
        await readFile(detachedIdentityPath, "utf8"),
      );
      const { pid, ...processIdentity } = detachedIdentity;
      assert.notDeepEqual(await readProcessIdentity(pid), processIdentity);
      detachedIdentity = undefined;
    }
  }
  const signaled = await runExactCommand(
    {
      executable: process.execPath,
      arguments: ["-e", "process.kill(process.pid, 'SIGTERM')"],
    },
    options,
  );
  assert.deepEqual(signaled, {
    status: "FAIL",
    exitCode: null,
    signal: "SIGTERM",
    timedOut: false,
    reason: "exit",
  });
  const missing = await runExactCommand(
    { executable: join(projectPath, "missing-command"), arguments: [] },
    options,
  );
  assert.deepEqual(missing, {
    status: "BLOCKED",
    exitCode: null,
    signal: null,
    timedOut: false,
    reason: "spawn",
  });
});

test("preserves a failed trusted command after descendants retire", async (t) => {
  const projectPath = await repository(t);
  const processPath = await mkdtemp(
    join(tmpdir(), "agent-runner-failed-retiring-tree-"),
  );
  t.after(() => rm(processPath, { recursive: true, force: true }));
  const pidPath = join(processPath, "child.pid");
  const childSource = `
    const { writeFileSync } = require("node:fs");
    writeFileSync(${JSON.stringify(pidPath)}, String(process.pid));
    process.send("ready");
    setTimeout(() => process.exit(0), 100);
  `;
  const parentSource = `
    const { spawn } = require("node:child_process");
    const { writeSync } = require("node:fs");
    const child = spawn(process.execPath, ["--eval", ${JSON.stringify(childSource)}], {
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    child.once("message", () => {
      writeSync(3, Buffer.from([1]));
      process.exit(7);
    });
    child.once("error", () => process.exit(1));
  `;

  const result = await runExactCommand(
    {
      executable: process.execPath,
      arguments: ["--eval", parentSource],
    },
    {
      cwd: projectPath,
      environment: process.env,
      readinessRequired: true,
      terminationGraceMs: 500,
      timeoutMs: 1_000,
    },
  );

  assert.deepEqual(result, {
    status: "FAIL",
    exitCode: 7,
    signal: null,
    timedOut: false,
    reason: "exit",
  });
  const childPid = Number.parseInt(await readFile(pidPath, "utf8"), 10);
  assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
});

test("terminates persistent descendants after failed trusted commands", async (t) => {
  const projectPath = await repository(t);
  const processPath = await mkdtemp(
    join(tmpdir(), "agent-runner-failed-leaked-tree-"),
  );
  const pidPath = join(processPath, "child.pid");
  t.after(async () => {
    try {
      const childPid = Number.parseInt(await readFile(pidPath, "utf8"), 10);
      try {
        process.kill(childPid, "SIGKILL");
      } catch (cause) {
        if (cause?.code !== "ESRCH") {
          throw cause;
        }
      }
    } catch (cause) {
      if (cause?.code !== "ENOENT") {
        throw cause;
      }
    } finally {
      await rm(processPath, { recursive: true, force: true });
    }
  });
  const childSource = `
    const { writeFileSync } = require("node:fs");
    writeFileSync(${JSON.stringify(pidPath)}, String(process.pid));
    process.on("SIGTERM", () => {});
    process.send("ready");
    setInterval(() => {}, 1_000);
  `;
  const parentSource = `
    const { spawn } = require("node:child_process");
    const { writeSync } = require("node:fs");
    const child = spawn(process.execPath, ["--eval", ${JSON.stringify(childSource)}], {
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    child.once("message", () => {
      writeSync(3, Buffer.from([1]));
      process.exit(7);
    });
    child.once("error", () => process.exit(1));
  `;

  const result = await runExactCommand(
    {
      executable: process.execPath,
      arguments: ["--eval", parentSource],
    },
    {
      cwd: projectPath,
      environment: process.env,
      readinessRequired: true,
      terminationGraceMs: 100,
      timeoutMs: 1_000,
    },
  );

  assert.deepEqual(result, {
    status: "BLOCKED",
    exitCode: null,
    signal: null,
    timedOut: false,
    reason: "process-tree",
  });
  const childPid = Number.parseInt(await readFile(pidPath, "utf8"), 10);
  assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
});

test("terminates a timed-out trusted command's complete process tree", async (t) => {
  const projectPath = await repository(t);
  const processPath = await mkdtemp(join(tmpdir(), "agent-runner-tree-"));
  t.after(() => rm(processPath, { recursive: true, force: true }));
  const socketPath = `\0agent-runner-${process.pid}-${Date.now()}`;
  const pidPath = join(processPath, "child.pid");
  const childSource = `
    const { writeFileSync } = require("node:fs");
    const { createServer } = require("node:net");
    writeFileSync(${JSON.stringify(pidPath)}, String(process.pid));
    process.on("SIGTERM", () => {});
    const server = createServer();
    server.on("error", () => {});
    server.listen(${JSON.stringify(socketPath)});
    setInterval(() => {}, 1_000);
  `;
  const parentSource = `
    const { spawn } = require("node:child_process");
    spawn(process.execPath, ["--eval", ${JSON.stringify(childSource)}], { stdio: "ignore" });
    setInterval(() => {}, 1_000);
  `;

  const result = await runExactCommand(
    {
      executable: process.execPath,
      arguments: ["--eval", parentSource],
    },
    {
      cwd: projectPath,
      environment: process.env,
      terminationGraceMs: 100,
      timeoutMs: 500,
    },
  );

  assert.equal(result.status, "BLOCKED");
  assert.equal(result.timedOut, true);
  assert.equal(result.reason, "timeout");
  const childPid = Number.parseInt(await readFile(pidPath, "utf8"), 10);
  // Process retirement and the closed socket prove cleanup immediately;
  // waiting for a hypothetical later write adds no independent guarantee.
  assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
  await assert.rejects(
    new Promise((resolvePromise, rejectPromise) => {
      const socket = createConnection(socketPath);
      socket.once("connect", () => {
        socket.destroy();
        resolvePromise();
      });
      socket.once("error", rejectPromise);
    }),
    (cause) => ["ECONNREFUSED", "ENOENT", "EPERM"].includes(cause.code),
  );
});

test("rejects commands outside or changed from the durable allowlist", async (t) => {
  const projectPath = await repository(t);
  const git = createGitService();
  const trusted = snapshot(
    "safe-check",
    "node safe validation",
    process.execPath,
    ["--eval", "process.exit(0)"],
  );
  const service = trustedService(git);
  const commandBindings = await bindings(git, projectPath, trusted);

  await assert.rejects(
    service.execute({
      bindings: commandBindings,
      commandIdentity: hash("not allowlisted"),
      projectPath,
      snapshot: trusted,
    }),
    (error) => error.code === "ERR_TRUSTED_COMMAND_NOT_ALLOWLISTED",
  );
  await assert.rejects(
    service.execute({
      bindings: {
        ...commandBindings,
        configurationFingerprint: hash("changed configuration"),
      },
      commandIdentity: trusted.commands[0].identity,
      projectPath,
      snapshot: trusted,
    }),
    (error) => error.code === "ERR_INVALID_TRUSTED_VALIDATION",
  );
  await assert.rejects(
    service.execute({
      bindings: {
        ...commandBindings,
        contentFingerprint: hash("changed content"),
      },
      commandIdentity: trusted.commands[0].identity,
      projectPath,
      snapshot: trusted,
    }),
    (error) => error.code === "ERR_TRUSTED_VALIDATION_BINDING_CHANGED",
  );
  await assert.rejects(
    service.execute({
      bindings: commandBindings,
      commandIdentity: trusted.commands[0].identity,
      projectPath,
      snapshot: {
        ...trusted,
        commands: [
          {
            ...trusted.commands[0],
            arguments: ["--eval", "process.exit(1)"],
          },
        ],
      },
    }),
    (error) => error.code === "ERR_INVALID_TRUSTED_VALIDATION",
  );
});

for (const testCase of [
  {
    name: "workspace content",
    command: "node mutates content",
    executable: process.execPath,
    arguments: [
      "--input-type=module",
      "--eval",
      'const fs=await import("node:fs");fs.writeFileSync("tracked.txt","changed\\n")',
    ],
    expectedChange: "tracked-content",
  },
  {
    name: "Git index",
    command: "git changes index flags",
    executable: "git",
    arguments: ["update-index", "--assume-unchanged", "tracked.txt"],
    expectedChange: "index",
  },
  {
    name: "Git refs",
    command: "git creates ref",
    executable: "git",
    arguments: ["branch", "unexpected-validation-ref"],
    expectedChange: "refs",
  },
  {
    name: "Git identity",
    command: "git changes identity",
    executable: "git",
    arguments: ["config", "user.name", "Changed"],
    expectedChange: "identity",
  },
  {
    name: "remote configuration",
    command: "git adds remote",
    executable: "git",
    arguments: ["remote", "add", "origin", "https://example.invalid/repo.git"],
    expectedChange: "remote-configuration",
  },
]) {
  test(`rejects trusted validation ${testCase.name} mutation`, async (t) => {
    const projectPath = await repository(t);
    const git = createGitService();
    const trusted = snapshot(
      "mutation-check",
      testCase.command,
      testCase.executable,
      testCase.arguments,
    );

    await assert.rejects(
      trustedService(git).execute({
        bindings: await bindings(git, projectPath, trusted),
        commandIdentity: trusted.commands[0].identity,
        projectPath,
        snapshot: trusted,
      }),
      (error) =>
        error.code === "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY" &&
        error.changes.includes(testCase.expectedChange),
    );
  });
}

function sessionLauncher(cwd, { ownershipMode }) {
  return resolveOwnedProcessLauncher(cwd, {
    bubblewrap: process.execPath,
    cache: new Map(),
    namespaceId: "pid:[4026531836]",
    ownershipMode,
    probe: () => ({ status: 1 }),
  });
}

// Keep real service -> executor -> supervisor routing. Only publication and
// clock delivery are controlled; the process proof and retirement are real.
function preparation(
  t,
  {
    failRegistration = false,
    failRetirement = false,
    probeExitCode = 0,
    supervisorExpired = false,
    holdClose = false,
  } = {},
) {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const snapshot = createTrustedValidationSnapshot(
    {
      check: {
        command: "node check.js",
        executable: process.execPath,
        arguments: ["--eval", "throw new Error('check body must not run')"],
      },
    },
    ["check"],
    40_000,
  );
  const registered = Promise.withResolvers();
  const registration = Promise.withResolvers();
  const retiring = Promise.withResolvers();
  const retirement = Promise.withResolvers();
  const physicalClose = Promise.withResolvers();
  let releaseClose;
  const publicationFailure = Object.assign(
    new Error("publication interrupted"),
    {
      code: "ERR_TEST_PUBLICATION",
    },
  );
  const base = process.hrtime.bigint();
  let elapsedMs = 0;
  let child;
  let executionResult;
  const work = {
    registrations: 0,
    retirements: 0,
    inspections: 0,
    repositoryChecks: 0,
  };
  const service = createTrustedValidationService({
    git: {
      async snapshot() {
        return {
          projectPath: process.cwd(),
          contentFingerprint: createHash("sha256")
            .update("content")
            .digest("hex"),
        };
      },
      async assertUnchanged() {
        work.repositoryChecks += 1;
      },
    },
    sandboxCommand(command, options) {
      assert.equal(command.identity, snapshot.commands[0].identity);
      assert.equal(options.preparationOnly, true);
      return {
        command: {
          executable: process.execPath,
          arguments: [
            "--eval",
            `require("node:fs").writeSync(3,Buffer.from([1]));process.exit(${probeExitCode})`,
          ],
        },
        environment: process.env,
        ownershipMode: "native-sandbox-provider",
        readinessRequired: true,
      };
    },
    async runCommand(command, options) {
      assert.equal(options.timeoutMs, 10_000);
      assert.equal(options.preparationOnly, true);
      executionResult = await runExactCommand(command, {
        ...options,
        monotonicNow: () => base + BigInt(elapsedMs) * 1_000_000n,
        spawnProcess(file, argumentsList, spawnOptions) {
          assert.equal(spawnOptions.deadlineNs, String(base + 10_000_000_000n));
          child = spawnOwnedProcess(file, argumentsList, {
            ...spawnOptions,
            resolveLauncher(cwd, launcherOptions) {
              const launcher = sessionLauncher(cwd, launcherOptions);
              if (!supervisorExpired) return launcher;
              return {
                ...launcher,
                arguments: launcher.arguments.map((value, index) =>
                  index === 1
                    ? `process.hrtime.bigint = () => ${spawnOptions.deadlineNs}n;\n${value}`
                    : value,
                ),
              };
            },
            inspectSessionProcesses() {
              work.inspections += 1;
              return null;
            },
          });
          if (holdClose) {
            const emit = child.emit.bind(child);
            child.emit = (event, ...values) => {
              if (event !== "close") return emit(event, ...values);
              releaseClose = () => emit(event, ...values);
              physicalClose.resolve();
              return true;
            };
          }
          return child;
        },
      });
      return executionResult;
    },
  });
  const controller = new AbortController();
  const input = {
    inventory: [snapshot.commands[0].command],
    snapshot,
    projectPath: process.cwd(),
    signal: controller.signal,
    async onResource() {
      assert.fail("this probe allocates no resource");
    },
    async onProcess(pid, proof) {
      if (pid !== null) {
        work.registrations += 1;
        assert.deepEqual(proof.launchCutoff, proof.processIdentity);
        assert.equal(proof.ancestryBaseline, null);
        assert.equal(proof.controlGroup, null);
        registered.resolve();
        await registration.promise;
        if (failRegistration) throw publicationFailure;
      } else {
        work.retirements += 1;
        retiring.resolve();
        await retirement.promise;
        if (failRetirement) throw publicationFailure;
      }
    },
  };
  input.onPreparation = async () => input.onProcess;
  const completion = service.inspectRequirements(input);
  // Observe rejection immediately while the test controls pending operations.
  void completion.catch(() => {});
  t.after(async () => {
    registration.resolve();
    retirement.resolve();
    child?.kill("SIGKILL");
    releaseClose?.();
    await completion.catch(() => {});
  });
  return {
    registered: registered.promise,
    registration,
    retiring: retiring.promise,
    retirement,
    completion,
    controller,
    work,
    publicationFailure,
    physicalClose: physicalClose.promise,
    releaseClose: () => releaseClose(),
    advance(value) {
      elapsedMs = value;
    },
    get child() {
      return child;
    },
    get result() {
      return executionResult;
    },
  };
}

for (const elapsed of [9_999, 10_000, 10_001]) {
  test(
    `preparation registration at ${elapsed}ms uses the original deadline`,
    { timeout: 5_000 },
    async (t) => {
      const run = preparation(t);
      await run.registered;
      run.advance(elapsed); // Deliberately do not deliver the timeout callback.
      run.registration.resolve();
      await run.retiring;
      let completed = false;
      void run.completion.finally(() => {
        completed = true;
      });
      await new Promise(setImmediate);
      assert.equal(
        completed,
        false,
        "durable retirement precedes availability",
      );
      run.retirement.resolve();
      const report = await run.completion;
      assert.equal(report.status, elapsed < 10_000 ? "READY" : "BLOCKED");
      assert.equal(run.child.ownedPayloadRequested, elapsed < 10_000);
      assert.equal(run.result.timedOut, elapsed >= 10_000);
      assert.equal(run.result.exitCode, elapsed < 10_000 ? 0 : null);
      assert.equal(run.result.signal, null);
      assert.equal(run.work.registrations, 1);
      assert.equal(run.work.retirements, 1);
      assert.equal(run.work.repositoryChecks, 1);
      assert.equal(
        run.work.inspections,
        0,
        "an inert supervisor needs no session scan",
      );
      if (elapsed >= 10_000) {
        assert.equal(run.result.reason, "registration-timeout");
        assert.match(report.blockers[0].evidence[0], /deadline expired/u);
      }
      const settled = { ...run.work };
      t.mock.timers.tick(100_000);
      await new Promise(setImmediate);
      assert.deepEqual(
        run.work,
        settled,
        "no callback publishes after completion",
      );
    },
  );
}

test(
  "observed close after expiry cannot pass when timer delivery is delayed",
  { timeout: 5_000 },
  async (t) => {
    const run = preparation(t, { probeExitCode: 7 });
    await run.registered;
    run.child.stdio[4].once("data", () => run.advance(10_000));
    run.registration.resolve();
    await run.retiring;
    run.retirement.resolve();
    assert.equal((await run.completion).status, "BLOCKED");
    assert.equal(run.child.ownedPayloadRequested, true);
    assert.deepEqual(run.result, {
      status: "BLOCKED",
      exitCode: 7,
      signal: null,
      timedOut: true,
      reason: "timeout",
    });
  },
);

test(
  "drains supervisor admission expiry without inventing a payload outcome",
  { timeout: 5_000 },
  async (t) => {
    const run = preparation(t, { supervisorExpired: true });
    await run.registered;
    run.registration.resolve();
    await run.retiring;
    run.retirement.resolve();
    assert.equal((await run.completion).status, "BLOCKED");
    assert.equal(run.child.ownedPayloadRequested, true);
    assert.deepEqual(run.result, {
      status: "BLOCKED",
      exitCode: null,
      signal: null,
      timedOut: true,
      reason: "registration-timeout",
    });
    assert.equal(run.work.inspections, 0);
  },
);

for (const stop of ["expiry", "cancellation", "close", "error"]) {
  test(
    `drains pending registration after ${stop} without releasing payload`,
    { timeout: 5_000 },
    async (t) => {
      const run = preparation(t);
      await run.registered;
      const closed = new Promise((resolve) => run.child.once("close", resolve));
      if (stop === "expiry") {
        run.advance(10_000);
        t.mock.timers.tick(10_000);
      } else if (stop === "cancellation") {
        run.controller.abort();
      } else if (stop === "error") {
        run.child.emit("error", run.publicationFailure);
      } else {
        run.child.kill("SIGKILL");
      }
      await closed;
      let completed = false;
      void run.completion.then(
        () => {
          completed = true;
        },
        () => {
          completed = true;
        },
      );
      t.mock.timers.tick(100_000);
      await new Promise(setImmediate);
      assert.equal(completed, false);
      assert.equal(run.work.retirements, 0);
      run.registration.resolve();
      await run.retiring;
      assert.equal(run.child.ownedPayloadRequested, false);
      run.retirement.resolve();
      if (stop === "cancellation")
        await assert.rejects(run.completion, { name: "AbortError" });
      else assert.equal((await run.completion).status, "BLOCKED");
      assert.equal(run.work.retirements, 1);
      assert.equal(run.work.inspections, 0);
    },
  );
}

test(
  "termination watchdog drains registration and reserves an unverified close",
  { timeout: 5_000 },
  async (t) => {
    const run = preparation(t, { holdClose: true });
    await run.registered;
    run.advance(10_000);
    t.mock.timers.tick(10_000);
    await run.physicalClose;
    t.mock.timers.tick(2_001);
    let completed = false;
    void run.completion.catch(() => {
      completed = true;
    });
    await new Promise(setImmediate);
    assert.equal(
      completed,
      false,
      "watchdog cannot bypass pending registration",
    );
    run.registration.resolve();
    await assert.rejects(run.completion, {
      code: "ERR_EXECUTION_PROCESS_ACTIVE",
    });
    assert.equal(run.work.retirements, 0);
    assert.equal(run.work.repositoryChecks, 0);
    const settled = { ...run.work };
    run.releaseClose();
    t.mock.timers.tick(100_000);
    await new Promise(setImmediate);
    assert.deepEqual(
      run.work,
      settled,
      "late close cannot publish retirement after return",
    );
  },
);

for (const phase of ["Registration", "Retirement"]) {
  test(
    `interrupted ${phase.toLowerCase()} publication retains uncertain ownership`,
    { timeout: 5_000 },
    async (t) => {
      const run = preparation(t, { [`fail${phase}`]: true });
      await run.registered;
      const closed = once(run.child, "close");
      run.advance(10_000);
      run.registration.resolve();
      await closed;
      if (phase === "Retirement") await run.retiring;
      run.retirement.resolve();
      await assert.rejects(run.completion, {
        code: "ERR_EXECUTION_PROCESS_ACTIVE",
      });
      assert.equal(run.work.retirements, phase === "Registration" ? 0 : 1);
      assert.equal(run.work.repositoryChecks, 0);
      assert.equal(run.child.ownedPayloadRequested, false);
      const settled = { ...run.work };
      t.mock.timers.tick(100_000);
      await new Promise(setImmediate);
      assert.deepEqual(run.work, settled);
    },
  );
}

test("supervisor rejects queued start IPC at the same absolute deadline", () => {
  const source = sessionLauncher(process.cwd(), {
    ownershipMode: "native-sandbox-provider",
  }).arguments[1];
  for (const clocks of [[999n, 999n], [1000n], [1001n], [999n, 1000n]]) {
    let spawned = 0;
    const messages = [];
    const handlers = new Map();
    const expired = new Error("supervisor exited");
    let now = 0;
    const context = {
      process: {
        argv: [
          "node",
          "namespace",
          "1000",
          "unused",
          "[]",
          "0",
          "token",
          "1000",
        ],
        connected: true,
        hrtime: { bigint: () => clocks[Math.min(now++, clocks.length - 1)] },
        on: (event, handler) => handlers.set(event, handler),
        send(message, callback) {
          messages.push(message);
          callback?.();
        },
        exit(code) {
          assert.equal(code, 124);
          throw expired;
        },
      },
      require(name) {
        if (name === "node:fs") return {};
        if (name === "node:crypto") return { createHash };
        assert.equal(name, "node:child_process");
        return {
          spawn() {
            spawned += 1;
            return { once() {} };
          },
        };
      },
    };
    runInNewContext(source, context);
    const start = () =>
      handlers.get("message")({ type: "start", ownerToken: "a".repeat(64) });
    if (clocks.at(-1) < 1000n) start();
    else assert.throws(start, (cause) => cause === expired);
    assert.equal(spawned, clocks.at(-1) < 1000n ? 1 : 0);
    assert.equal(
      messages.at(-1).type,
      spawned ? "ready" : "preparation-expired",
    );
  }
});
