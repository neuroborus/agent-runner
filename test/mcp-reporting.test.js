import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  access,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import {
  createMcpControlPlane,
  createMcpServer,
  createRunStore,
  parseRunnerConfiguration,
  serveMcp,
} from "../src/index.js";

const executeFile = promisify(execFile);
const FIXED_TIME = new Date("2026-08-24T16:45:12.123Z");
const TOKEN = "11111111-1111-4111-8111-111111111111";

function reportInput(projectPath, overrides = {}) {
  return {
    idempotencyKey: "issue-report-1",
    projectPath,
    summary: "The durable result contradicted the MCP contract.",
    expectedBehavior: "The exact retry should return the first receipt.",
    actualBehavior: "The first receipt was not available to the caller.",
    occurrence: "It occurred once after the local artifact was published.",
    unexpectedReason:
      "The documented idempotency contract requires recovery without duplication.",
    details: "Caller-supplied **Markdown** only.",
    runId: "22222222-2222-4222-8222-222222222222",
    errorCode: "ERR_EXAMPLE",
    ...overrides,
  };
}

async function repository(t, prefix = "agent-runner-issue-report-") {
  const root = await mkdtemp(join(tmpdir(), prefix));
  const projectPath = join(root, "project");
  const stateRoot = join(root, "state");
  await mkdir(projectPath);
  await executeFile("git", ["init", "-q", projectPath]);
  t.after(() => rm(root, { recursive: true, force: true }));
  return { projectPath, root, stateRoot };
}

function runnerConfiguration(input = {}) {
  return parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: 1, issueReporting: true, ...input }),
  );
}

function reportingControl(paths, options = {}) {
  return createMcpControlPlane({
    reportingOptions: {
      clock: () => FIXED_TIME,
      loadConfiguration: async () => runnerConfiguration(),
      tokenFactory: () => TOKEN,
      ...options,
    },
    runStore: createRunStore({ stateRoot: paths.stateRoot }),
  });
}

async function discoveredServer(issueReportingEnabled, control = {}) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const server = createMcpServer({
    control: new Proxy(control, {
      get(target, property) {
        return target[property] ?? (async () => ({}));
      },
    }),
    issueReportingEnabled,
  });
  const client = new Client({ name: "reporting-test", version: "1.0.0" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, server };
}

test("conditionally discovers strict deliberate reporting guidance", async (t) => {
  let called = false;
  const enabled = await discoveredServer(true, {
    async unexpectedIssueReport() {
      called = true;
      return { reportPath: "/unused" };
    },
  });
  t.after(() => enabled.client.close().catch(() => {}));
  t.after(() => enabled.server.close().catch(() => {}));

  const enabledTools = await enabled.client.listTools();
  const tool = enabledTools.tools.find(
    ({ name }) => name === "unexpected_issue_report",
  );
  assert.ok(tool);
  assert.match(enabled.client.getInstructions(), /genuinely unexpected/u);
  assert.match(tool.description, /exhausted configured budgets/u);
  assert.match(tool.description, /documented environment blockers/u);
  assert.match(tool.description, /invalid user or configuration input/u);
  assert.match(tool.description, /no logs, transcripts, prompts/u);
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.deepEqual(tool.inputSchema.required.sort(), [
    "actualBehavior",
    "expectedBehavior",
    "idempotencyKey",
    "occurrence",
    "projectPath",
    "summary",
    "unexpectedReason",
  ]);

  for (const argumentsValue of [
    { ...reportInput("/unused"), unexpectedReason: undefined },
    { ...reportInput("/unused"), extra: "unsupported" },
    { ...reportInput("/unused"), summary: "x".repeat(1_001) },
  ]) {
    const response = await enabled.client.callTool({
      name: "unexpected_issue_report",
      arguments: argumentsValue,
    });
    assert.equal(response.isError, true);
  }
  assert.equal(called, false);

  const disabled = await discoveredServer(false);
  t.after(() => disabled.client.close().catch(() => {}));
  t.after(() => disabled.server.close().catch(() => {}));
  assert.equal(
    (await disabled.client.listTools()).tools.some(
      ({ name }) => name === "unexpected_issue_report",
    ),
    false,
  );
  assert.doesNotMatch(
    disabled.client.getInstructions(),
    /unexpected_issue_report|reportable issues|diagnostics automatically/u,
  );
});

test("loads the disabled switch once when the MCP server starts", async (t) => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  let loads = 0;
  const handle = await serveMcp({
    async loadConfiguration() {
      loads += 1;
      return runnerConfiguration({ issueReporting: false });
    },
    stderr: { write() {} },
    transport: serverTransport,
  });
  const client = new Client({ name: "startup-test", version: "1.0.0" });
  t.after(() => client.close().catch(() => {}));
  t.after(() => handle.close().catch(() => {}));
  await client.connect(clientTransport);

  assert.equal(loads, 1);
  assert.equal(
    (await client.listTools()).tools.some(
      ({ name }) => name === "unexpected_issue_report",
    ),
    false,
  );
  assert.doesNotMatch(client.getInstructions(), /unexpected issue|reportable/iu);
});

test("rejects an in-project state root before persisting an action", async (t) => {
  const paths = await repository(t, "agent-runner-issue-state-boundary-");
  const stateRoot = join(paths.projectPath, ".agent-runner-state");
  const control = createMcpControlPlane({
    reportingOptions: {
      clock: () => FIXED_TIME,
      loadConfiguration: async () => runnerConfiguration(),
      tokenFactory: () => TOKEN,
    },
    runStore: createRunStore({ stateRoot }),
  });

  await assert.rejects(
    control.unexpectedIssueReport(reportInput(paths.projectPath)),
    (error) => error.code === "ERR_UNSAFE_STATE_ROOT",
  );
  await assert.rejects(
    access(join(stateRoot, "actions")),
    (error) => error.code === "ENOENT",
  );
});

test("reloads runner configuration for each fresh report", async (t) => {
  const paths = await repository(t, "agent-runner-issue-config-reload-");
  await writeFile(
    join(paths.projectPath, ".gitignore"),
    "/FIRST_REPORTS/\n/SECOND_REPORTS/\n",
  );
  let configuration = runnerConfiguration({ artifactRoot: "FIRST_REPORTS" });
  let loads = 0;
  const control = reportingControl(paths, {
    async loadConfiguration() {
      loads += 1;
      return configuration;
    },
  });
  const firstInput = reportInput(paths.projectPath);

  const first = await control.unexpectedIssueReport(firstInput);
  configuration = runnerConfiguration({ artifactRoot: "SECOND_REPORTS" });
  const second = await control.unexpectedIssueReport(
    reportInput(paths.projectPath, { idempotencyKey: "issue-report-2" }),
  );

  assert.match(first.reportPath, /\/FIRST_REPORTS\/agent-runner\/issues\//u);
  assert.match(second.reportPath, /\/SECOND_REPORTS\/agent-runner\/issues\//u);
  assert.deepEqual(await control.unexpectedIssueReport(firstInput), first);
  assert.equal(loads, 2);
});

test("writes only caller-supplied Markdown to the configured ignored root", async (t) => {
  const paths = await repository(t);
  await mkdir(join(paths.projectPath, "LOCAL_ARTIFACTS"));
  await Promise.all([
    writeFile(
      join(paths.projectPath, ".gitignore"),
      "/LOCAL_ARTIFACTS/\n/PROJECT_REPORTS/\n",
    ),
    writeFile(
      join(paths.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
      '{"schemaVersion":1,"artifactRoot":"PROJECT_REPORTS"}\n',
    ),
    writeFile(
      join(paths.projectPath, "runner.log"),
      "AUTOMATIC_SECRET_SHOULD_NOT_APPEAR\n",
    ),
    writeFile(
      join(paths.projectPath, "prompt.txt"),
      "private prompt and transcript\n",
    ),
  ]);
  const control = reportingControl(paths);
  const input = reportInput(paths.projectPath);

  const first = await control.unexpectedIssueReport(input);
  assert.match(
    first.reportPath,
    /\/PROJECT_REPORTS\/agent-runner\/issues\/issue_2026-08-24_164512\.123Z\.md$/u,
  );
  const content = await readFile(first.reportPath, "utf8");
  assert.match(content, /^# Unexpected Agent Runner Issue$/mu);
  assert.match(content, /^## Expected Behavior$/mu);
  assert.match(content, /^## Actual Behavior$/mu);
  assert.match(content, /^## Occurrence$/mu);
  assert.match(content, /^## Why This Was Unexpected$/mu);
  assert.match(content, /^## Details$/mu);
  assert.match(content, /- Run ID: `22222222-2222-4222-8222-222222222222`/u);
  assert.match(content, /- Error code: `ERR_EXAMPLE`/u);
  assert.doesNotMatch(content, /LOCAL_ARTIFACTS|PROJECT_REPORTS|agent-runner\.json/u);
  assert.doesNotMatch(content, /AUTOMATIC_SECRET_SHOULD_NOT_APPEAR/u);

  assert.deepEqual(await control.unexpectedIssueReport(input), first);
  assert.deepEqual(await readdir(join(first.reportPath, "..")), [
    "issue_2026-08-24_164512.123Z.md",
  ]);
  await assert.rejects(
    control.unexpectedIssueReport({ ...input, summary: "Different summary." }),
    (error) => error.code === "ERR_MCP_IDEMPOTENCY_CONFLICT",
  );

  const collision = await control.unexpectedIssueReport(
    reportInput(paths.projectPath, {
      idempotencyKey: "issue-report-2",
      summary: "A second unexpected issue.",
    }),
  );
  assert.match(collision.reportPath, /_001\.md$/u);
});

test("bounds reads of oversized collision files", async (t) => {
  const paths = await repository(t, "agent-runner-issue-oversized-");
  const issuesPath = join(
    paths.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner",
    "issues",
  );
  const collisionPath = join(
    issuesPath,
    "issue_2026-08-24_164512.123Z.md",
  );
  await mkdir(issuesPath, { recursive: true });
  await Promise.all([
    writeFile(join(paths.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(collisionPath, "collision\n"),
  ]);
  await truncate(collisionPath, 2 ** 32);

  const result = await reportingControl(paths).unexpectedIssueReport(
    reportInput(paths.projectPath),
  );

  assert.match(result.reportPath, /_001\.md$/u);
  assert.deepEqual(await readdir(issuesPath), [
    "issue_2026-08-24_164512.123Z.md",
    "issue_2026-08-24_164512.123Z_001.md",
  ]);
});

test("recovers publication interrupted before its idempotency receipt", async (t) => {
  const paths = await repository(t, "agent-runner-issue-recovery-");
  await writeFile(
    join(paths.projectPath, ".gitignore"),
    "/LOCAL_ARTIFACTS/\n",
  );
  const store = createRunStore({ stateRoot: paths.stateRoot });
  let interrupt = true;
  const configuration = runnerConfiguration();
  const firstControl = createMcpControlPlane({
    reportingOptions: {
      clock: () => FIXED_TIME,
      loadConfiguration: async () => configuration,
      async onPublished() {
        if (interrupt) {
          interrupt = false;
          throw new Error("simulated disconnect");
        }
      },
      tokenFactory: () => TOKEN,
    },
    runStore: store,
  });
  const input = reportInput(paths.projectPath);

  await assert.rejects(
    firstControl.unexpectedIssueReport(input),
    /simulated disconnect/u,
  );
  const { idempotencyKey, ...argumentsWithoutKey } = input;
  const intent = await store.readAction({
    key: idempotencyKey,
    tool: "unexpected_issue_report",
    arguments: argumentsWithoutKey,
  });
  assert.equal(intent.status, "intent");
  assert.match(intent.context.reportPath, /issue_2026-08-24_164512\.123Z\.md$/u);
  assert.equal(intent.context.publicationPhase, "published");
  assert.match(intent.context.temporaryPath, /^.+\.tmp$/u);

  const recoveredControl = createMcpControlPlane({
    reportingOptions: {
      clock: () => FIXED_TIME,
      loadConfiguration: async () =>
        runnerConfiguration({ artifactRoot: "CHANGED" }),
      tokenFactory: () => TOKEN,
    },
    runStore: store,
  });
  assert.deepEqual(await recoveredControl.unexpectedIssueReport(input), {
    reportPath: intent.context.reportPath,
  });
  assert.equal(
    (
      await store.readAction({
        key: idempotencyKey,
        tool: "unexpected_issue_report",
        arguments: argumentsWithoutKey,
      })
    ).status,
    "completed",
  );
  assert.deepEqual(
    await readdir(join(paths.projectPath, "LOCAL_ARTIFACTS", "agent-runner", "issues")),
    ["issue_2026-08-24_164512.123Z.md"],
  );
});

test("does not adopt an identical report reserved by another action", async (t) => {
  const paths = await repository(t, "agent-runner-issue-interleaving-");
  await writeFile(
    join(paths.projectPath, ".gitignore"),
    "/LOCAL_ARTIFACTS/\n",
  );
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const issuesPath = join(
    paths.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner",
    "issues",
  );
  const reportPath = join(
    issuesPath,
    "issue_2026-08-24_164512.123Z.md",
  );
  const inputs = [
    reportInput(paths.projectPath),
    reportInput(paths.projectPath, { idempotencyKey: "issue-report-2" }),
  ];

  for (const [index, input] of inputs.entries()) {
    const { idempotencyKey, ...argumentsWithoutKey } = input;
    const action = await store.beginAction({
      key: idempotencyKey,
      tool: "unexpected_issue_report",
      arguments: argumentsWithoutKey,
      context: {
        issuesPath,
        projectPath: paths.projectPath,
        publicationPhase: "reserved",
        reportPath,
        temporaryPath: join(
          issuesPath,
          `.${basename(reportPath)}.${process.pid}.action-${index}.tmp`,
        ),
      },
    });
    await action.release();
  }

  const control = createMcpControlPlane({
    reportingOptions: {
      clock: () => FIXED_TIME,
      loadConfiguration: async () => runnerConfiguration(),
      tokenFactory: () => TOKEN,
    },
    runStore: store,
  });
  const first = await control.unexpectedIssueReport(inputs[0]);
  const second = await control.unexpectedIssueReport(inputs[1]);

  assert.equal(first.reportPath, reportPath);
  assert.match(second.reportPath, /_001\.md$/u);
  assert.notEqual(second.reportPath, first.reportPath);
  assert.deepEqual(await readdir(issuesPath), [
    "issue_2026-08-24_164512.123Z.md",
    "issue_2026-08-24_164512.123Z_001.md",
  ]);
  assert.equal(
    await readFile(first.reportPath, "utf8"),
    await readFile(second.reportPath, "utf8"),
  );
});

test("advances after a collision races interrupted recovery", async (t) => {
  const paths = await repository(t, "agent-runner-issue-recovery-race-");
  await writeFile(
    join(paths.projectPath, ".gitignore"),
    "/LOCAL_ARTIFACTS/\n",
  );
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const baseOptions = {
    clock: () => FIXED_TIME,
    loadConfiguration: async () => runnerConfiguration(),
    tokenFactory: () => TOKEN,
  };
  const seedInput = reportInput(paths.projectPath, {
    idempotencyKey: "issue-report-seed",
  });
  const seedControl = createMcpControlPlane({
    reportingOptions: baseOptions,
    runStore: store,
  });
  const { reportPath } = await seedControl.unexpectedIssueReport(seedInput);
  const issuesPath = dirname(reportPath);
  const temporaryPath = join(
    issuesPath,
    `.${basename(reportPath)}.${process.pid}.recovery-race.tmp`,
  );
  await rename(reportPath, temporaryPath);

  const input = reportInput(paths.projectPath);
  const { idempotencyKey, ...argumentsWithoutKey } = input;
  const action = await store.beginAction({
    key: idempotencyKey,
    tool: "unexpected_issue_report",
    arguments: argumentsWithoutKey,
    context: {
      issuesPath,
      projectPath: paths.projectPath,
      publicationPhase: "reserved",
      reportPath,
      temporaryPath,
    },
  });
  await action.release();

  let raced = false;
  const control = createMcpControlPlane({
    reportingOptions: {
      ...baseOptions,
      async linkFile(sourcePath, destinationPath) {
        if (
          !raced &&
          sourcePath === temporaryPath &&
          destinationPath === reportPath
        ) {
          raced = true;
          await writeFile(reportPath, "concurrent collision\n");
        }
        return link(sourcePath, destinationPath);
      },
    },
    runStore: store,
  });
  const result = await control.unexpectedIssueReport(input);

  assert.equal(raced, true);
  assert.match(result.reportPath, /_001\.md$/u);
  assert.equal(await readFile(reportPath, "utf8"), "concurrent collision\n");
  await assert.rejects(
    access(temporaryPath),
    (error) => error.code === "ENOENT",
  );
});

test("rejects unignored, tracked, symbolic, and hard-linked destinations", async (t) => {
  await t.test("unignored", async (t) => {
    const paths = await repository(t, "agent-runner-issue-unignored-");
    const control = reportingControl(paths);
    await assert.rejects(
      control.unexpectedIssueReport(reportInput(paths.projectPath)),
      (error) => error.code === "ERR_ISSUE_REPORT_NOT_IGNORED",
    );
  });

  await t.test("tracked", async (t) => {
    const paths = await repository(t, "agent-runner-issue-tracked-");
    const issuesPath = join(
      paths.projectPath,
      "LOCAL_ARTIFACTS",
      "agent-runner",
      "issues",
    );
    await mkdir(issuesPath, { recursive: true });
    await Promise.all([
      writeFile(join(paths.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
      writeFile(join(issuesPath, "tracked.md"), "tracked\n"),
    ]);
    await executeFile("git", [
      "-C",
      paths.projectPath,
      "add",
      "-f",
      "LOCAL_ARTIFACTS/agent-runner/issues/tracked.md",
    ]);
    await assert.rejects(
      reportingControl(paths).unexpectedIssueReport(
        reportInput(paths.projectPath),
      ),
      (error) => error.code === "ERR_ISSUE_REPORT_NOT_IGNORED",
    );
  });

  await t.test("symbolic link", async (t) => {
    const paths = await repository(t, "agent-runner-issue-symbolic-");
    const outsidePath = join(paths.root, "outside");
    await mkdir(outsidePath);
    await writeFile(join(paths.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n");
    await symlink(outsidePath, join(paths.projectPath, "LOCAL_ARTIFACTS"));
    await assert.rejects(
      reportingControl(paths).unexpectedIssueReport(
        reportInput(paths.projectPath),
      ),
      (error) => error.code === "ERR_UNSAFE_REPOSITORY_PATH",
    );
  });

  await t.test("hard link", async (t) => {
    const paths = await repository(t, "agent-runner-issue-hardlink-");
    const issuesPath = join(
      paths.projectPath,
      "LOCAL_ARTIFACTS",
      "agent-runner",
      "issues",
    );
    const outsidePath = join(paths.root, "outside.md");
    await mkdir(issuesPath, { recursive: true });
    await Promise.all([
      writeFile(join(paths.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
      writeFile(outsidePath, "outside\n"),
    ]);
    await link(
      outsidePath,
      join(issuesPath, "issue_2026-08-24_164512.123Z.md"),
    );
    await assert.rejects(
      reportingControl(paths).unexpectedIssueReport(
        reportInput(paths.projectPath),
      ),
      (error) => error.code === "ERR_UNSAFE_ISSUE_REPORT_PATH",
    );
  });
});
