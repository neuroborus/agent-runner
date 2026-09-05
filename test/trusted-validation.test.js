import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
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

function snapshot(alias, command, executable, argumentsList) {
  return createTrustedValidationSnapshot(
    {
      [alias]: {
        command,
        executable,
        arguments: argumentsList,
      },
    },
    [alias],
  );
}

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
  const service = trustedService(git);

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
  ]);
  assert.deepEqual(validateTrustedValidationSnapshot(trusted), trusted);
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
  assert.equal(isAbsolute(execution.command.executable), true);
  assert.notEqual(execution.command.executable, fakeLauncher);
  assert.notEqual(execution.command.executable, "bwrap");
  assert.ok(execution.command.arguments.includes("--unshare-net"));
  assert.ok(execution.command.arguments.includes("--unshare-pid"));
  assert.ok(execution.command.arguments.includes("--cap-drop"));
  const runMount = execution.command.arguments.lastIndexOf("/run");
  assert.equal(execution.command.arguments[runMount - 1], "--tmpfs");
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
  );
  const service = createTrustedValidationService({
    git,
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
    timeoutMs: 1_000,
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
  const delayedMutationPath = join(projectPath, "delayed.txt");
  const childSource = `
    const { writeFileSync } = require("node:fs");
    const { createServer } = require("node:net");
    writeFileSync(${JSON.stringify(pidPath)}, String(process.pid));
    process.on("SIGTERM", () => {});
    const server = createServer();
    server.on("error", () => {});
    server.listen(${JSON.stringify(socketPath)});
    setTimeout(() => writeFileSync(${JSON.stringify(delayedMutationPath)}, "late\\n"), 1_200);
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
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 1_300));
  await assert.rejects(access(delayedMutationPath), { code: "ENOENT" });
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
