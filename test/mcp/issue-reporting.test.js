import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  chmod,
  link,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import {
  createRunStore,
  main,
  parseRunnerConfiguration,
} from "../../src/index.js";
import {
  createIssueService,
  ISSUE_STATUSES,
  resolveIssueStorePath,
} from "../../src/issues/index.js";
import { openIssueStore } from "../../src/issues/store.js";
import {
  createMcpControlPlane,
  createMcpServer,
  serveMcp,
} from "../../src/mcp/index.js";

const executeFile = promisify(execFile);
const FIXED_TIME = new Date("2026-08-24T16:45:12.123Z");
const ISSUE_ID = "11111111-1111-4111-8111-111111111111";
const SECOND_ID = "22222222-2222-4222-8222-222222222222";
const THIRD_ID = "33333333-3333-4333-8333-333333333333";

function reportInput(projectPath, overrides = {}) {
  return {
    idempotencyKey: "issue-report-1",
    projectPath,
    summary: "The durable result contradicted the MCP contract.",
    expectedBehavior: "The exact retry should return the first receipt.",
    actualBehavior: "The first receipt was not available to the caller.",
    occurrence: "It occurred once after the issue was published.",
    unexpectedReason:
      "The documented idempotency contract requires recovery without duplication.",
    details: "Caller-supplied **Markdown** only.",
    runId: "22222222-2222-4222-8222-222222222222",
    errorCode: "ERR_EXAMPLE",
    ...overrides,
  };
}

// Every fixture isolates home, XDG locations, state, and the origin project.
async function directory(t, prefix = "agent-runner-issue-report-") {
  const root = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  t.after(() => rm(root, { recursive: true, force: true }));
  const paths = {
    configHome: join(root, "config"),
    dataHome: join(root, "data"),
    home: join(root, "home"),
    issuesPath: join(root, "data", "agent-runner", "issues"),
    projectPath: join(root, "project"),
    root,
    stateRoot: join(root, "state"),
  };
  await Promise.all([mkdir(paths.projectPath), mkdir(paths.home)]);
  return paths;
}

async function repository(t, prefix) {
  const paths = await directory(t, prefix);
  await executeFile("git", ["init", "-q", paths.projectPath]);
  return paths;
}

// Store entries apart from the shared per-issue coordination directory.
async function issueEntries(paths) {
  return (await readdir(paths.issuesPath))
    .filter((name) => name !== ".coordination")
    .sort();
}

function issueOptions(paths, overrides = {}) {
  return {
    clock: () => FIXED_TIME,
    env: {
      HOME: paths.home,
      XDG_CONFIG_HOME: paths.configHome,
      XDG_DATA_HOME: paths.dataHome,
      XDG_STATE_HOME: paths.stateRoot,
    },
    homeDirectory: paths.home,
    idFactory: () => ISSUE_ID,
    platform: "linux",
    ...overrides,
  };
}

function reportingControl(
  paths,
  options = {},
  runStore = createRunStore({ stateRoot: paths.stateRoot }),
) {
  return createMcpControlPlane({
    reportingOptions: issueOptions(paths, options),
    runStore,
  });
}

function actionIdentity({ idempotencyKey, ...argumentsWithoutKey }) {
  return {
    key: idempotencyKey,
    tool: "unexpected_issue_report",
    arguments: argumentsWithoutKey,
  };
}

function runnerConfiguration(input = {}) {
  return parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: 1, issueReporting: true, ...input }),
  );
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

const failure = (code) => (error) => error.code === code;

test("conditionally discovers strict deliberate reporting guidance", async (t) => {
  let called = false;
  const enabled = await discoveredServer(true, {
    async unexpectedIssueReport() {
      called = true;
      return { issueId: ISSUE_ID, issuePath: "/unused" };
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
  assert.match(tool.description, /private per-user global issue store/u);
  assert.match(tool.description, /exhausted configured budgets/u);
  assert.match(tool.description, /documented environment blockers/u);
  assert.match(tool.description, /invalid user or configuration input/u);
  assert.match(tool.description, /no logs, transcripts, prompts/u);
  assert.match(
    tool.inputSchema.properties.projectPath.description,
    /ordinary directory/u,
  );
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
  assert.doesNotMatch(
    client.getInstructions(),
    /unexpected issue|reportable/iu,
  );
});

test("maps private per-user issue storage without new platform support", () => {
  assert.equal(
    resolveIssueStorePath({
      env: { XDG_DATA_HOME: "/data/user" },
      homeDirectory: "/home/user",
      platform: "linux",
    }),
    "/data/user/agent-runner/issues",
  );
  assert.equal(
    resolveIssueStorePath({
      env: { XDG_DATA_HOME: "relative/data" },
      homeDirectory: "/home/user",
      platform: "linux",
    }),
    "/home/user/.local/share/agent-runner/issues",
  );
  assert.equal(
    resolveIssueStorePath({
      env: {},
      homeDirectory: "/Users/user",
      platform: "darwin",
    }),
    "/Users/user/Library/Application Support/agent-runner/issues",
  );
  assert.equal(
    resolveIssueStorePath({
      env: { LOCALAPPDATA: "C:\\Users\\user\\AppData\\Local" },
      platform: "win32",
    }),
    "C:\\Users\\user\\AppData\\Local\\agent-runner\\issues",
  );
  for (const options of [
    { env: {}, homeDirectory: "/home/user", platform: "freebsd" },
    { env: { XDG_DATA_HOME: "/data/\nuser" }, platform: "linux" },
    { env: { XDG_DATA_HOME: `/${"x".repeat(4_096)}` }, platform: "linux" },
    { env: { LOCALAPPDATA: "\\relative" }, platform: "win32" },
  ]) {
    assert.throws(
      () => resolveIssueStorePath(options),
      failure("ERR_UNSAFE_ISSUE_STORE"),
    );
  }
});

test("validates capture input and the state boundary before persisting an action", async (t) => {
  const paths = await repository(t, "agent-runner-issue-state-boundary-");
  const stateRoot = join(paths.projectPath, ".agent-runner-state");
  const issues = createIssueService({
    ...issueOptions(paths),
    runStore: createRunStore({ stateRoot }),
  });

  for (const input of [
    reportInput(paths.projectPath, { summary: "x".repeat(1_001) }),
    reportInput(paths.projectPath, { extra: "unsupported" }),
    reportInput(paths.projectPath, { runId: "not-a-run-id" }),
    reportInput(paths.projectPath, { errorCode: 123 }),
    reportInput(paths.projectPath, {
      runId: ["22222222-2222-4222-8222-222222222222"],
    }),
  ]) {
    await assert.rejects(
      issues.report(input),
      failure("ERR_INVALID_ISSUE_REPORT"),
    );
  }
  await assert.rejects(
    issues.report(reportInput(paths.projectPath)),
    failure("ERR_UNSAFE_STATE_ROOT"),
  );
  await assert.rejects(access(join(stateRoot, "actions")), failure("ENOENT"));
  await assert.rejects(access(paths.dataHome), failure("ENOENT"));
});

test("publishes one private global document without project ignore rules", async (t) => {
  const paths = await repository(t, "agent-runner-issue-publish-");
  await Promise.all([
    writeFile(
      join(paths.projectPath, "runner.log"),
      "AUTOMATIC_SECRET_SHOULD_NOT_APPEAR\n",
    ),
    writeFile(
      join(paths.projectPath, "prompt.txt"),
      "private prompt and transcript\n",
    ),
  ]);
  const projectStatus = async () =>
    (
      await executeFile("git", [
        "-C",
        paths.projectPath,
        "status",
        "--porcelain",
        "--ignored",
      ])
    ).stdout;
  const statusBefore = await projectStatus();
  const control = reportingControl(paths);
  const input = reportInput(paths.projectPath);

  const receipt = await control.unexpectedIssueReport(input);

  assert.deepEqual(receipt, {
    issueId: ISSUE_ID,
    issuePath: join(paths.issuesPath, `${ISSUE_ID}.json`),
  });
  const source = await readFile(receipt.issuePath, "utf8");
  const document = JSON.parse(source);
  assert.deepEqual(Object.keys(document), [
    "schemaVersion",
    "id",
    "report",
    "tracking",
  ]);
  assert.equal(document.schemaVersion, 1);
  assert.equal(document.id, ISSUE_ID);
  const { markdown } = document.report;
  assert.equal(
    document.report.sha256,
    createHash("sha256").update(markdown).digest("hex"),
  );
  for (const line of [
    "# Unexpected Agent Runner Issue",
    "## Expected Behavior",
    "## Actual Behavior",
    "## Occurrence",
    "## Why This Was Unexpected",
    "## Details",
    "- Error code: `ERR_EXAMPLE`",
  ]) {
    assert.ok(markdown.split("\n").includes(line), line);
  }
  assert.deepEqual(document.tracking, {
    revision: 1,
    status: "open",
    origin: { name: "project", path: paths.projectPath },
    createdAt: FIXED_TIME.toISOString(),
    updatedAt: FIXED_TIME.toISOString(),
    runId: input.runId,
    errorCode: "ERR_EXAMPLE",
    planReferences: [],
    commitReferences: [],
    note: null,
  });
  assert.doesNotMatch(source, /AUTOMATIC_SECRET|private prompt/u);
  assert.equal((await stat(paths.issuesPath)).mode & 0o777, 0o700);
  assert.equal((await stat(receipt.issuePath)).mode & 0o777, 0o600);
  assert.deepEqual(await issueEntries(paths), [`${ISSUE_ID}.json`]);
  assert.equal(await projectStatus(), statusBefore);

  assert.deepEqual(await control.unexpectedIssueReport(input), receipt);
  await assert.rejects(
    control.unexpectedIssueReport({ ...input, summary: "Different summary." }),
    failure("ERR_MCP_IDEMPOTENCY_CONFLICT"),
  );
});

test("shares an ordinary platform parent with user settings", async (t) => {
  const paths = await repository(t, "agent-runner-issue-shared-parent-");
  const receipt = await reportingControl(paths, {
    env: { ...issueOptions(paths).env, XDG_CONFIG_HOME: paths.dataHome },
  }).unexpectedIssueReport(reportInput(paths.projectPath));

  assert.equal(receipt.issuePath, join(paths.issuesPath, `${ISSUE_ID}.json`));
});

test("publishes an ordinary directory origin without Git or project configuration", async (t) => {
  const paths = await directory(t, "agent-runner-issue-directory-");
  const origin = join(paths.projectPath, "nested");
  await mkdir(origin);
  await writeFile(join(origin, "source.txt"), "source content\n");
  const configurationPath = join(origin, "configuration.json");
  await writeFile(configurationPath, "not runner configuration\n");
  const before = await stat(origin);
  const control = reportingControl(paths, {
    git: { resolveProject: () => assert.fail("must not invoke Git") },
  });
  const input = reportInput(origin, {
    projectConfigurationPath: configurationPath,
  });

  const receipt = await control.unexpectedIssueReport(input);

  const document = JSON.parse(await readFile(receipt.issuePath, "utf8"));
  assert.deepEqual(document.tracking.origin, { name: "nested", path: origin });
  assert.doesNotMatch(
    JSON.stringify(document),
    /source content|not runner configuration/u,
  );
  assert.deepEqual((await readdir(origin)).sort(), [
    "configuration.json",
    "source.txt",
  ]);
  assert.equal(
    await readFile(join(origin, "source.txt"), "utf8"),
    "source content\n",
  );
  assert.equal(
    await readFile(configurationPath, "utf8"),
    "not runner configuration\n",
  );
  const after = await stat(origin);
  for (const field of ["dev", "ino", "mode", "mtimeMs", "ctimeMs"])
    assert.equal(after[field], before[field]);
  assert.deepEqual(await issueEntries(paths), [`${ISSUE_ID}.json`]);
});

test("recovers a bound directory publication and receipt without its deleted origin", async (t) => {
  const paths = await directory(t, "agent-runner-issue-directory-recovery-");
  const runStore = createRunStore({ stateRoot: paths.stateRoot });
  const selector = join(paths.root, "origin");
  await symlink(paths.projectPath, selector);
  const input = reportInput(selector);
  await assert.rejects(
    reportingControl(
      paths,
      {
        async linkFile() {
          throw new Error("simulated interruption");
        },
      },
      runStore,
    ).unexpectedIssueReport(input),
  );
  const { context } = await runStore.readAction(
    actionIdentity({ ...input, projectPath: paths.projectPath }),
  );
  assert.equal(context.projectPath, paths.projectPath);
  assert.equal(context.phase, "reserved");
  const reserved = await readFile(
    join(paths.issuesPath, context.temporaryName),
  );
  await rm(paths.projectPath, { recursive: true, force: true });
  const noInspection = () =>
    assert.fail("must not inspect the origin on retry");
  const options = {
    git: { resolveProject: noInspection },
    workspace: {
      exclusionPath: noInspection,
      inspectControls: noInspection,
      inspectPath: noInspection,
    },
  };
  const receipt = await reportingControl(paths, options, {
    ...runStore,
    validateStateBoundary: noInspection,
  }).unexpectedIssueReport(input);

  assert.equal(receipt.issueId, ISSUE_ID);
  assert.deepEqual(await readFile(receipt.issuePath), reserved);
  assert.deepEqual(await issueEntries(paths), [`${ISSUE_ID}.json`]);
  assert.deepEqual(
    await reportingControl(
      paths,
      {
        ...options,
        env: { XDG_DATA_HOME: "/unresolved\nlocation" },
      },
      runStore,
    ).unexpectedIssueReport(input),
    receipt,
  );
  await assert.rejects(access(paths.projectPath), failure("ENOENT"));
});

test("rejects unsafe directory origins and never falls back after Git failure", async (t) => {
  for (const [name, prepare, code] of [
    [
      "missing directory",
      async (paths) => join(paths.projectPath, "missing"),
      "ERR_INVALID_RUN_PATH",
    ],
    [
      "regular file",
      async (paths) => {
        const path = join(paths.projectPath, "source.txt");
        await writeFile(path, "source content\n");
        return path;
      },
      "ERR_INVALID_RUN_PATH",
    ],
    [
      "control tree",
      async (paths) => {
        const path = join(paths.projectPath, ".agents");
        await mkdir(path);
        return path;
      },
      "ERR_WORKSPACE_PATH",
    ],
    [
      "bare metadata",
      async (paths) => {
        await executeFile("git", ["init", "--bare", "-q", paths.projectPath]);
        return paths.projectPath;
      },
      "ERR_WORKSPACE_PATH",
    ],
    [
      "control alias",
      async (paths) => {
        await symlink(paths.home, join(paths.projectPath, ".claude"));
        return paths.projectPath;
      },
      "ERR_WORKSPACE_PATH",
    ],
    [
      "ancestor control alias targeting the origin",
      async (paths) => {
        await symlink(paths.projectPath, join(paths.root, ".claude"));
        return paths.projectPath;
      },
      "ERR_WORKSPACE_PATH",
    ],
    [
      "malformed enclosing Git",
      async (paths) => {
        await mkdir(join(paths.projectPath, ".git"));
        const path = join(paths.projectPath, "nested");
        await mkdir(path);
        return path;
      },
      "ERR_NOT_GIT_REPOSITORY",
    ],
    [
      "unavailable Git",
      async (paths, options) => {
        await executeFile("git", ["init", "-q", paths.projectPath]);
        options.git = {
          resolveProject() {
            throw Object.assign(new Error("Git unavailable"), {
              code: "ERR_GIT_UNAVAILABLE",
            });
          },
        };
        return paths.projectPath;
      },
      "ERR_GIT_UNAVAILABLE",
    ],
  ]) {
    await t.test(name, async (t) => {
      const paths = await directory(t, "agent-runner-issue-origin-boundary-");
      const options = {};
      const projectPath = await prepare(paths, options);
      await assert.rejects(
        reportingControl(paths, options).unexpectedIssueReport(
          reportInput(projectPath),
        ),
        failure(code),
      );
      await assert.rejects(access(paths.dataHome), failure("ENOENT"));
      await assert.rejects(
        access(join(paths.stateRoot, "actions")),
        failure("ENOENT"),
      );
    });
  }
});

test("retains reports and replays receipts after the origin is deleted", async (t) => {
  const paths = await repository(t, "agent-runner-issue-retention-");
  const runStore = createRunStore({ stateRoot: paths.stateRoot });
  // A subdirectory selector is bound to the canonical Git root.
  const selector = join(paths.projectPath, "nested");
  await mkdir(selector);
  const input = reportInput(selector);
  const receipt = await createIssueService({
    ...issueOptions(paths),
    runStore,
  }).report(input);
  const published = await readFile(receipt.issuePath);

  await rm(paths.projectPath, { recursive: true, force: true });
  const control = reportingControl(
    paths,
    { env: { XDG_DATA_HOME: "/unresolved\nlocation" } },
    runStore,
  );

  assert.deepEqual(await control.unexpectedIssueReport(input), receipt);
  assert.deepEqual(await readFile(receipt.issuePath), published);
  assert.equal(JSON.parse(published).tracking.origin.path, paths.projectPath);
});

test("creates concurrent reports once per idempotency key", async (t) => {
  const paths = await repository(t, "agent-runner-issue-concurrency-");
  const control = reportingControl(paths, { idFactory: undefined });
  const first = reportInput(paths.projectPath);
  const second = reportInput(paths.projectPath, {
    idempotencyKey: "issue-report-2",
    summary: "A second unexpected issue.",
  });

  const results = await Promise.allSettled([
    control.unexpectedIssueReport(first),
    control.unexpectedIssueReport(first),
    control.unexpectedIssueReport(second),
    control.unexpectedIssueReport(second),
  ]);
  for (const result of results) {
    if (result.status === "rejected") {
      assert.equal(result.reason.code, "ERR_MCP_ACTION_IN_PROGRESS");
    }
  }
  const receipts = [
    await control.unexpectedIssueReport(first),
    await control.unexpectedIssueReport(second),
  ];
  for (const [index, result] of results.entries()) {
    if (result.status === "fulfilled") {
      assert.deepEqual(result.value, receipts[Math.floor(index / 2)]);
    }
  }
  assert.notEqual(receipts[0].issueId, receipts[1].issueId);
  assert.deepEqual(
    await issueEntries(paths),
    receipts.map(({ issueId }) => `${issueId}.json`).sort(),
  );
});

// Records directory syncs and published-phase persistence in their order.
function observedPublication(runStore, events) {
  return {
    openStore: async (path) => {
      const store = await openIssueStore(path);
      return {
        ...store,
        async sync() {
          events.push("sync");
          await store.sync();
        },
      };
    },
    runStore: {
      ...runStore,
      async beginAction(input) {
        const action = await runStore.beginAction(input);
        return {
          get record() {
            return action.record;
          },
          complete: (result) => action.complete(result),
          release: () => action.release(),
          async updateContext(context) {
            if (context.phase === "published") events.push("published");
            return action.updateContext(context);
          },
        };
      },
    },
  };
}

test("recovers lost acknowledgements and interrupted publication once", async (t) => {
  for (const [name, options] of [
    [
      "lost acknowledgement",
      {
        async onPublished() {
          throw new Error("simulated disconnect");
        },
      },
    ],
    [
      "before the link",
      {
        async linkFile() {
          throw new Error("simulated interruption");
        },
      },
    ],
    [
      "after the link",
      {
        async linkFile(source, destination) {
          await link(source, destination);
          throw new Error("simulated interruption");
        },
      },
    ],
  ]) {
    await t.test(name, async (t) => {
      const paths = await repository(t, "agent-runner-issue-recovery-");
      const runStore = createRunStore({ stateRoot: paths.stateRoot });
      const input = reportInput(paths.projectPath);

      await assert.rejects(
        reportingControl(paths, options, runStore).unexpectedIssueReport(input),
      );
      const intent = await runStore.readAction(actionIdentity(input));
      assert.equal(intent.status, "intent");
      assert.equal(intent.context.issueId, ISSUE_ID);
      assert.equal(intent.context.storePath, paths.issuesPath);

      const events = [];
      const recovered = await createIssueService({
        ...issueOptions(paths, {
          idFactory: () => "33333333-3333-4333-8333-333333333333",
        }),
        ...observedPublication(runStore, events),
      }).report(input);
      assert.equal(recovered.issueId, ISSUE_ID);
      if (intent.context.phase === "reserved") {
        const published = events.indexOf("published");
        assert.notEqual(published, -1);
        assert.equal(events[published - 1], "sync");
      }
      assert.equal(
        (await runStore.readAction(actionIdentity(input))).status,
        "completed",
      );
      assert.deepEqual(await issueEntries(paths), [`${ISSUE_ID}.json`]);
    });
  }
});

test("never replays a reserved publication against a changed store", async (t) => {
  for (const [name, change, assertUntouched] of [
    [
      "relocated",
      async (paths) => ({
        env: {
          ...issueOptions(paths).env,
          XDG_DATA_HOME: join(paths.root, "relocated"),
        },
      }),
      (paths) =>
        assert.rejects(
          access(join(paths.root, "relocated")),
          failure("ENOENT"),
        ),
    ],
    [
      "replaced",
      async (paths) => {
        await rename(paths.issuesPath, `${paths.issuesPath}.moved`);
        await mkdir(paths.issuesPath, { mode: 0o700 });
        return {};
      },
      async (paths) => assert.deepEqual(await readdir(paths.issuesPath), []),
    ],
  ]) {
    await t.test(name, async (t) => {
      const paths = await repository(t, "agent-runner-issue-store-change-");
      const runStore = createRunStore({ stateRoot: paths.stateRoot });
      const input = reportInput(paths.projectPath);
      await assert.rejects(
        reportingControl(
          paths,
          {
            async linkFile() {
              throw new Error("simulated interruption");
            },
          },
          runStore,
        ).unexpectedIssueReport(input),
      );

      const options = await change(paths);
      await assert.rejects(
        reportingControl(paths, options, runStore).unexpectedIssueReport(input),
        failure("ERR_ISSUE_STORE_CHANGED"),
      );
      await assertUntouched(paths);
      assert.equal(
        (await runStore.readAction(actionIdentity(input))).status,
        "intent",
      );
    });
  }
});

test("keeps historical receipts and rejects incomplete local publications", async (t) => {
  const paths = await repository(t, "agent-runner-issue-historical-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const legacyPath = join(
    paths.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner",
    "issues",
  );
  const reportPath = join(legacyPath, "issue_2026-08-24_164512.123Z.md");
  const temporaryPath = join(
    legacyPath,
    ".issue_2026-08-24_164512.123Z.md.1.legacy.tmp",
  );
  await mkdir(legacyPath, { recursive: true });
  await writeFile(reportPath, "historical report\n");
  await link(reportPath, temporaryPath);
  const legacyContext = (values = {}) => ({
    issuesPath: null,
    projectPath: null,
    publicationPhase: null,
    reportPath: null,
    temporaryPath: null,
    ...values,
  });
  const [incomplete, completed, unstarted] = ["a", "b", "c"].map((key) =>
    reportInput(paths.projectPath, { idempotencyKey: `historical-${key}` }),
  );
  for (const [input, context, receipt] of [
    [
      incomplete,
      legacyContext({
        issuesPath: legacyPath,
        projectPath: paths.projectPath,
        publicationPhase: "reserved",
        reportPath,
        temporaryPath,
      }),
    ],
    [completed, legacyContext(), { reportPath }],
    [unstarted, legacyContext()],
  ]) {
    const action = await store.beginAction({
      ...actionIdentity(input),
      context,
    });
    if (receipt !== undefined) await action.complete(receipt);
    await action.release();
  }
  const control = reportingControl(paths, {}, store);

  await assert.rejects(
    control.unexpectedIssueReport(incomplete),
    failure("ERR_ISSUE_REPORT_LEGACY_PUBLICATION"),
  );
  await assert.rejects(access(paths.dataHome), failure("ENOENT"));
  assert.deepEqual(await control.unexpectedIssueReport(completed), {
    reportPath,
  });
  assert.equal(
    (await control.unexpectedIssueReport(unstarted)).issueId,
    ISSUE_ID,
  );
  assert.deepEqual((await readdir(legacyPath)).sort(), [
    ".issue_2026-08-24_164512.123Z.md.1.legacy.tmp",
    "issue_2026-08-24_164512.123Z.md",
  ]);
  assert.equal(await readFile(reportPath, "utf8"), "historical report\n");
  assert.equal((await stat(reportPath)).nlink, 2);

  await rm(paths.projectPath, { recursive: true, force: true });
  assert.deepEqual(await control.unexpectedIssueReport(completed), {
    reportPath,
  });
});

test("does not adopt a colliding issue identity", async (t) => {
  const paths = await repository(t, "agent-runner-issue-collision-");
  const control = reportingControl(paths);
  const first = await control.unexpectedIssueReport(
    reportInput(paths.projectPath),
  );
  const published = await readFile(first.issuePath);

  await assert.rejects(
    control.unexpectedIssueReport(
      reportInput(paths.projectPath, { idempotencyKey: "issue-report-2" }),
    ),
    failure("ERR_ISSUE_REPORT_OWNERSHIP"),
  );
  assert.deepEqual(await issueEntries(paths), [`${ISSUE_ID}.json`]);
  assert.deepEqual(await readFile(first.issuePath), published);
});

test("rejects linked, shared, and overlapping storage", async (t) => {
  await t.test("symbolic data home", async (t) => {
    const paths = await repository(t, "agent-runner-issue-symbolic-");
    const outsidePath = join(paths.root, "outside");
    await mkdir(outsidePath);
    await symlink(outsidePath, paths.dataHome);
    await assert.rejects(
      reportingControl(paths).unexpectedIssueReport(
        reportInput(paths.projectPath),
      ),
      failure("ERR_UNSAFE_ISSUE_STORE"),
    );
    assert.deepEqual(await readdir(outsidePath), []);
  });

  await t.test("shared permissions", async (t) => {
    const paths = await repository(t, "agent-runner-issue-shared-");
    await mkdir(paths.issuesPath, { recursive: true });
    await chmod(paths.issuesPath, 0o755);
    await assert.rejects(
      reportingControl(paths).unexpectedIssueReport(
        reportInput(paths.projectPath),
      ),
      failure("ERR_UNSAFE_ISSUE_STORE"),
    );
    assert.deepEqual(await readdir(paths.issuesPath), []);
  });

  for (const [name, dataHome, code] of [
    [
      "origin project",
      (paths) => join(paths.projectPath, "data"),
      "ERR_UNSAFE_ISSUE_STORE",
    ],
    [
      "run state",
      (paths) => join(paths.stateRoot, "data"),
      "ERR_UNSAFE_STATE_ROOT",
    ],
  ]) {
    await t.test(name, async (t) => {
      const paths = await directory(t, "agent-runner-issue-overlap-");
      const path = dataHome(paths);
      await assert.rejects(
        reportingControl(paths, {
          env: { ...issueOptions(paths).env, XDG_DATA_HOME: path },
        }).unexpectedIssueReport(reportInput(paths.projectPath)),
        failure(code),
      );
      await assert.rejects(
        access(join(path, "agent-runner")),
        failure("ENOENT"),
      );
    });
  }

  // Neither case relies on the filesystem allocating a different inode.
  for (const [name, substitute] of [
    [
      "recreated temporary generation",
      async ({ input, store }) => {
        const action = await store.beginAction({
          ...actionIdentity(input),
          context: {},
        });
        await action.updateContext({
          ...action.record.context,
          temporaryBirthtimeNs: "1",
        });
        await action.release();
      },
    ],
    [
      "replaced temporary file",
      async ({ paths, temporaryPath }) => {
        const replacement = join(paths.issuesPath, "replacement");
        await writeFile(replacement, "unrelated\n", { mode: 0o600 });
        await rename(replacement, temporaryPath);
      },
    ],
  ]) {
    await t.test(name, async (t) => {
      const paths = await repository(t, "agent-runner-issue-substituted-");
      const store = createRunStore({ stateRoot: paths.stateRoot });
      const input = reportInput(paths.projectPath);
      await assert.rejects(
        reportingControl(
          paths,
          {
            async linkFile() {
              throw new Error("simulated interruption");
            },
          },
          store,
        ).unexpectedIssueReport(input),
      );
      const { context } = await store.readAction(actionIdentity(input));
      const temporaryPath = join(paths.issuesPath, context.temporaryName);
      await substitute({ input, paths, store, temporaryPath });
      const substituted = await readFile(temporaryPath);

      await assert.rejects(
        reportingControl(paths, {}, store).unexpectedIssueReport(input),
        failure("ERR_ISSUE_REPORT_OWNERSHIP"),
      );
      assert.deepEqual(await readFile(temporaryPath), substituted);
      assert.deepEqual(await issueEntries(paths), [context.temporaryName]);
    });
  }

  await t.test("permissions widened during publication", async (t) => {
    const paths = await repository(t, "agent-runner-issue-widened-");
    const store = createRunStore({ stateRoot: paths.stateRoot });
    const input = reportInput(paths.projectPath);
    await assert.rejects(
      reportingControl(
        paths,
        {
          async linkFile(source, destination) {
            await chmod(paths.issuesPath, 0o755);
            await link(source, destination);
          },
        },
        store,
      ).unexpectedIssueReport(input),
      failure("ERR_UNSAFE_ISSUE_STORE"),
    );
    assert.equal(
      (await store.readAction(actionIdentity(input))).context.phase,
      "reserved",
    );

    await chmod(paths.issuesPath, 0o700);
    assert.equal(
      (await reportingControl(paths, {}, store).unexpectedIssueReport(input))
        .issueId,
      ISSUE_ID,
    );
  });

  await t.test("hard-linked document", async (t) => {
    const paths = await repository(t, "agent-runner-issue-hardlink-");
    const store = createRunStore({ stateRoot: paths.stateRoot });
    const input = reportInput(paths.projectPath);
    const issuePath = join(paths.issuesPath, `${ISSUE_ID}.json`);
    await assert.rejects(
      reportingControl(
        paths,
        {
          async linkFile(source, destination) {
            await link(source, destination);
            throw new Error("simulated interruption");
          },
        },
        store,
      ).unexpectedIssueReport(input),
    );
    const outsidePath = join(paths.root, "outside.json");
    await link(issuePath, outsidePath);
    const outside = await readFile(outsidePath);

    await assert.rejects(
      reportingControl(paths, {}, store).unexpectedIssueReport(input),
      failure("ERR_ISSUE_REPORT_OWNERSHIP"),
    );
    assert.deepEqual(await readFile(outsidePath), outside);
  });
});

function updateInput(issue, overrides = {}) {
  return {
    idempotencyKey: "issue-update-1",
    issueId: issue.issueId,
    expectedRevision: issue.tracking.revision,
    expectedHash: issue.documentHash,
    status: "resolved",
    ...overrides,
  };
}

async function reportedIssue(t, prefix, options = {}) {
  const paths = await repository(t, prefix);
  const runStore = createRunStore({ stateRoot: paths.stateRoot });
  const issues = createIssueService({ ...issueOptions(paths), runStore });
  const { issueId } = await issues.report(reportInput(paths.projectPath));
  const service = (overrides = {}) =>
    createIssueService({
      ...issueOptions(paths, { ...options, ...overrides }),
      runStore,
    });
  return {
    paths,
    runStore,
    issues,
    issue: await issues.read({ issueId }),
    service,
  };
}

test("manages the global backlog over MCP when capture is disabled", async (t) => {
  const paths = await repository(t, "agent-runner-issue-mcp-management-");
  const control = reportingControl(paths);
  const { issueId } = await control.unexpectedIssueReport(
    reportInput(paths.projectPath),
  );
  await rm(paths.projectPath, { recursive: true, force: true });
  const { client, server } = await discoveredServer(false, control);
  t.after(() => client.close().catch(() => {}));
  t.after(() => server.close().catch(() => {}));

  const { tools } = await client.listTools();
  const tool = (name) => tools.find((candidate) => candidate.name === name);
  assert.equal(tool("unexpected_issue_report"), undefined);
  for (const name of ["issues_list", "issues_read", "issues_update"]) {
    assert.equal(tool(name).inputSchema.additionalProperties, false);
    assert.equal(tool(name).annotations.readOnlyHint, name !== "issues_update");
  }
  const updateSchema = tool("issues_update").inputSchema;
  assert.deepEqual(updateSchema.required.sort(), [
    "expectedHash",
    "expectedRevision",
    "idempotencyKey",
    "issueId",
  ]);
  assert.deepEqual(updateSchema.properties.status.enum, ISSUE_STATUSES);
  const call = async (name, argumentsValue) => {
    const response = await client.callTool({
      name,
      arguments: argumentsValue,
    });
    assert.notEqual(response.isError, true, JSON.stringify(response.content));
    return response.structuredContent;
  };

  const read = await call("issues_read", { issueId });
  assert.deepEqual(read, await control.issuesRead({ issueId }));
  assert.match(read.markdown, /^# Unexpected Agent Runner Issue\n/u);
  assert.deepEqual(await call("issues_list", {}), {
    issues: [
      { issueId, documentHash: read.documentHash, tracking: read.tracking },
    ],
    nextCursor: null,
  });
  const update = updateInput(read, {
    status: "dismissed",
    note: "Expected behavior after review.",
  });
  for (const invalid of [
    { ...update, status: "closed" },
    { ...update, markdown: "replacement" },
  ]) {
    const response = await client.callTool({
      name: "issues_update",
      arguments: invalid,
    });
    assert.equal(response.isError, true);
  }
  const receipt = await call("issues_update", update);
  assert.deepEqual(receipt, await control.issuesUpdate(update));
  assert.equal(
    (await control.issuesRead({ issueId })).tracking.status,
    "dismissed",
  );
});

test("projects the same backlog through the CLI when capture is disabled", async (t) => {
  const paths = await repository(t, "agent-runner-issue-cli-");
  const runStore = createRunStore({ stateRoot: paths.stateRoot });
  const control = reportingControl(paths, {}, runStore);
  const { issueId } = await control.unexpectedIssueReport(
    reportInput(paths.projectPath),
  );
  await rm(paths.projectPath, { recursive: true, force: true });
  const { client, server } = await discoveredServer(false, control);
  t.after(() => client.close().catch(() => {}));
  t.after(() => server.close().catch(() => {}));
  const environment = issueOptions(paths).env;
  const mcp = (name, argumentsValue) =>
    client.callTool({ name, arguments: argumentsValue });
  const cli = async (args) => {
    let stdout = "";
    let stderr = "";
    const exitCode = await main(["issues", ...args], {
      environment,
      stdout: { write: (chunk) => (stdout += chunk) },
      stderr: { write: (chunk) => (stderr += chunk) },
      idempotencyKeyFactory: () => "cli-generated-key",
      createCommandRunner: () => assert.fail("must not construct a runner"),
      createCommandIssues(options) {
        assert.deepEqual(options, { env: environment });
        return createIssueService({
          ...issueOptions(paths),
          ...options,
          runStore,
        });
      },
    });
    return { exitCode, stdout, stderr };
  };
  const output = async (args) => {
    const { exitCode, stdout, stderr } = await cli(args);
    assert.equal(exitCode, 0, stderr);
    return { value: JSON.parse(stdout), stderr };
  };

  const read = (await mcp("issues_read", { issueId })).structuredContent;
  assert.deepEqual((await output(["read", "--issue", issueId])).value, read);
  assert.deepEqual(
    (
      await output([
        "list",
        "--origin",
        paths.projectPath,
        "--status",
        "queued",
        "--status",
        "open",
        "--limit",
        "1",
      ])
    ).value,
    (
      await mcp("issues_list", {
        projectPath: paths.projectPath,
        statuses: ["open", "queued"],
        limit: 1,
      })
    ).structuredContent,
  );

  // Both projections reject the same invalid request without mutation.
  const base = [
    "update",
    "--issue",
    issueId,
    "--expected-revision",
    "1",
    "--expected-hash",
    read.documentHash,
  ];
  const invalid = await cli([...base, "--status", "closed"]);
  assert.equal(invalid.exitCode, 1);
  assert.equal(invalid.stdout, "");
  assert.equal(
    (await mcp("issues_update", { ...updateInput(read), status: "closed" }))
      .isError,
    true,
  );

  // A CLI mutation shares the MCP action identity, so an exact MCP retry
  // returns the same receipt instead of applying another revision.
  const updated = await output([
    ...base,
    "--status",
    "resolved",
    "--commit-reference",
    "0123456789abcdef",
    "--note",
    "Repaired.",
  ]);
  assert.equal(updated.stderr, "Issue update retry key: cli-generated-key\n");
  const { idempotencyKey, ...receipt } = updated.value;
  assert.equal(idempotencyKey, "cli-generated-key");
  assert.deepEqual(
    (
      await mcp(
        "issues_update",
        updateInput(read, {
          idempotencyKey,
          commitReferences: ["0123456789abcdef"],
          note: "Repaired.",
        }),
      )
    ).structuredContent,
    receipt,
  );

  // A stale request fails in both projections and leaves the record intact.
  const stale = await cli([
    ...base,
    "--status",
    "dismissed",
    "--idempotency-key",
    "cli-stale",
  ]);
  assert.equal(stale.exitCode, 1);
  assert.equal(stale.stdout, "");
  assert.match(stale.stderr, /stale/u);
  assert.equal(
    (
      await mcp(
        "issues_update",
        updateInput(read, { idempotencyKey: "mcp-stale", status: "dismissed" }),
      )
    ).isError,
    true,
  );
  const current = (await mcp("issues_read", { issueId })).structuredContent;
  assert.equal(current.documentHash, receipt.documentHash);

  // Explicit clear flags map to the MCP empty array and null.
  const cleared = await output([
    "update",
    "--issue",
    issueId,
    "--expected-revision",
    String(receipt.revision),
    "--expected-hash",
    receipt.documentHash,
    "--clear-commit-references",
    "--clear-note",
    "--idempotency-key",
    "cli-clear",
  ]);
  assert.equal(cleared.stderr, "");
  const { tracking } = (await output(["read", "--issue", issueId])).value;
  assert.deepEqual(
    [tracking.status, tracking.commitReferences, tracking.note],
    ["resolved", [], null],
  );
});

test("lists the cross-project backlog with exact filters and bound pages", async (t) => {
  const paths = await repository(t, "agent-runner-issue-list-");
  const otherProject = join(paths.root, "other");
  await mkdir(otherProject);
  await executeFile("git", ["init", "-q", otherProject]);
  const times = [
    "2026-08-24T16:45:12.123Z",
    "2026-08-24T16:46:00.000Z",
    "2026-08-24T16:46:00.000Z",
    "2026-08-24T16:47:00.000Z",
  ];
  const ids = [THIRD_ID, SECOND_ID, ISSUE_ID];
  const issues = createIssueService({
    ...issueOptions(paths, {
      clock: () => new Date(times.shift()),
      idFactory: () => ids.shift(),
    }),
    runStore: createRunStore({ stateRoot: paths.stateRoot }),
  });

  // Listing is read-only and never creates the store.
  assert.deepEqual(await issues.list({}), { issues: [], nextCursor: null });
  await assert.rejects(access(paths.dataHome), failure("ENOENT"));
  for (const [index, projectPath] of [
    paths.projectPath,
    otherProject,
    paths.projectPath,
  ].entries()) {
    await issues.report(
      reportInput(projectPath, { idempotencyKey: `issue-list-${index}` }),
    );
  }
  await issues.update(
    updateInput(await issues.read({ issueId: ISSUE_ID }), {
      idempotencyKey: "issue-list-update",
    }),
  );
  const listed = async (input) =>
    (await issues.list(input)).issues.map(({ issueId }) => issueId);

  // Equal creation times order by ID.
  assert.deepEqual(await listed({}), [THIRD_ID, ISSUE_ID, SECOND_ID]);
  const first = await issues.list({ limit: 2 });
  assert.deepEqual(
    first.issues.map(({ issueId }) => issueId),
    [THIRD_ID, ISSUE_ID],
  );
  assert.deepEqual(await issues.list({ limit: 2, cursor: first.nextCursor }), {
    issues: [(await issues.list({})).issues[2]],
    nextCursor: null,
  });
  assert.deepEqual(await listed({ projectPath: paths.projectPath }), [
    THIRD_ID,
    ISSUE_ID,
  ]);
  assert.deepEqual(
    await listed({ projectPath: otherProject, statuses: ["open"] }),
    [SECOND_ID],
  );
  assert.deepEqual(await listed({ statuses: ["resolved", "dismissed"] }), [
    ISSUE_ID,
  ]);
  assert.deepEqual(
    await listed({ projectPath: join(otherProject, "nested") }),
    [],
  );
  for (const cursor of [`${first.nextCursor}x`, "invalid"]) {
    await assert.rejects(
      issues.list({ limit: 2, cursor }),
      failure("ERR_INVALID_ISSUE_CURSOR"),
    );
  }
  await assert.rejects(
    issues.list({ limit: 2, cursor: first.nextCursor, statuses: ["open"] }),
    failure("ERR_INVALID_ISSUE_CURSOR"),
  );
  for (const input of [
    { limit: 0 },
    { limit: 101 },
    { statuses: [] },
    { statuses: ["open", "open"] },
    { statuses: ["closed"] },
    { projectPath: "relative/project" },
    { extra: true },
  ]) {
    await assert.rejects(
      issues.list(input),
      failure("ERR_INVALID_ISSUE_REQUEST"),
    );
  }
});

test("updates only tracking metadata across finite statuses", async (t) => {
  const { paths, issues, issue } = await reportedIssue(
    t,
    "agent-runner-issue-update-",
  );
  await rm(paths.projectPath, { recursive: true, force: true });
  const immutable = ({ markdown, tracking }) => [
    markdown,
    tracking.origin,
    tracking.createdAt,
    tracking.runId,
    tracking.errorCode,
  ];
  const first = updateInput(issue, {
    status: "queued",
    planReferences: ["plan.md#commit-1"],
    commitReferences: ["0123456789abcdef"],
    note: "Scheduled for repair.",
  });
  const firstReceipt = await issues.update(first);
  assert.deepEqual(firstReceipt, {
    issueId: ISSUE_ID,
    revision: 2,
    documentHash: (await issues.read({ issueId: ISSUE_ID })).documentHash,
  });

  // Omitted fields stay; reopening and clearing are ordinary updates.
  let current = await issues.read({ issueId: ISSUE_ID });
  for (const [index, status] of [
    "in_progress",
    "resolved",
    "dismissed",
  ].entries()) {
    await issues.update(
      updateInput(current, { idempotencyKey: `status-${index}`, status }),
    );
    current = await issues.read({ issueId: ISSUE_ID });
    assert.equal(current.tracking.status, status);
    assert.deepEqual(current.tracking.planReferences, ["plan.md#commit-1"]);
    assert.equal(current.tracking.note, "Scheduled for repair.");
  }
  await issues.update(
    updateInput(current, {
      idempotencyKey: "reopen",
      status: "open",
      planReferences: [],
      commitReferences: [],
      note: null,
    }),
  );
  const reopened = await issues.read({ issueId: ISSUE_ID });
  assert.deepEqual(
    { ...reopened.tracking, updatedAt: issue.tracking.updatedAt },
    { ...issue.tracking, revision: 6 },
  );
  assert.deepEqual(immutable(reopened), immutable(issue));

  const stored = await readFile(reopened.issuePath);
  assert.deepEqual(await issues.update(first), firstReceipt);
  await assert.rejects(
    issues.update({ ...first, idempotencyKey: "stale-update" }),
    failure("ERR_ISSUE_REVISION_CONFLICT"),
  );
  await assert.rejects(
    issues.update({ ...first, status: "dismissed" }),
    failure("ERR_MCP_IDEMPOTENCY_CONFLICT"),
  );
  for (const input of [
    {
      ...first,
      status: undefined,
      planReferences: undefined,
      commitReferences: undefined,
      note: undefined,
    },
    { ...first, status: "closed" },
    { ...first, status: null },
    { ...first, planReferences: ["same", "same"] },
    { ...first, note: "" },
    { ...first, markdown: "replacement" },
    { ...first, expectedRevision: 0 },
  ]) {
    await assert.rejects(
      issues.update(input),
      failure("ERR_INVALID_ISSUE_REQUEST"),
    );
  }
  await assert.rejects(
    issues.update(
      updateInput(
        { ...reopened, issueId: SECOND_ID },
        { idempotencyKey: "missing-issue" },
      ),
    ),
    failure("ERR_ISSUE_NOT_FOUND"),
  );
  assert.deepEqual(await readFile(reopened.issuePath), stored);
});

test("serializes competing updates and recovers interrupted updates once", async (t) => {
  const interrupted = (name) => ({
    async [name]() {
      throw new Error("simulated interruption");
    },
  });
  await t.test("competing clients with separate state roots", async (t) => {
    const { paths, issue, service } = await reportedIssue(
      t,
      "agent-runner-issue-cas-",
    );
    // Both clients share the store, not a state root.
    const other = createIssueService({
      ...issueOptions(paths),
      runStore: createRunStore({ stateRoot: join(paths.root, "other-state") }),
    });
    const competing = updateInput(issue, {
      idempotencyKey: "competing",
      status: "dismissed",
    });
    const winner = await service({
      async renameFile(source, destination) {
        await assert.rejects(
          other.update(competing),
          failure("ERR_ISSUE_IN_PROGRESS"),
        );
        await rename(source, destination);
      },
    }).update(updateInput(issue));

    await assert.rejects(
      other.update(competing),
      failure("ERR_ISSUE_REVISION_CONFLICT"),
    );
    const current = await other.read({ issueId: ISSUE_ID });
    assert.equal(current.documentHash, winner.documentHash);
    assert.equal(current.tracking.status, "resolved");
  });

  await t.test("substituted replacement source", async (t) => {
    const { paths, issues, issue, service } = await reportedIssue(
      t,
      "agent-runner-issue-update-source-",
    );
    const stored = await readFile(issue.issuePath);
    let substituted = null;
    // Replaces the written temporary file before its pre-rename check.
    const substituting = {
      async openStore(path, options) {
        const store = await openIssueStore(path, options);
        return {
          ...store,
          async verify() {
            const name = (await readdir(path)).find(
              (entry) =>
                entry.startsWith(`.${ISSUE_ID}.`) && entry.endsWith(".tmp"),
            );
            if (substituted === null && name !== undefined) {
              substituted = join(path, name);
              await writeFile(`${substituted}.new`, "{}\n", { mode: 0o600 });
              await rename(`${substituted}.new`, substituted);
            }
            await store.verify();
          },
        };
      },
    };

    await assert.rejects(
      service(substituting).update(updateInput(issue)),
      failure("ERR_ISSUE_REPORT_OWNERSHIP"),
    );
    assert.deepEqual(await readFile(issue.issuePath), stored);
    assert.equal(await readFile(substituted, "utf8"), "{}\n");
    assert.deepEqual(await issueEntries(paths), [
      `.${ISSUE_ID}.${substituted.split(".").at(-2)}.tmp`,
      `${ISSUE_ID}.json`,
    ]);
    assert.equal(
      (await issues.update(updateInput(issue, { idempotencyKey: "retry" })))
        .revision,
      2,
    );
  });

  await t.test(
    "lost acknowledgement superseded by a newer update",
    async (t) => {
      const { issues, issue, service } = await reportedIssue(
        t,
        "agent-runner-issue-update-ack-",
      );
      const lost = updateInput(issue);
      await assert.rejects(service(interrupted("onUpdated")).update(lost));
      const applied = await issues.read({ issueId: ISSUE_ID });
      await issues.update(
        updateInput(applied, { idempotencyKey: "newer", status: "open" }),
      );
      const newer = await readFile(applied.issuePath);

      assert.deepEqual(await issues.update(lost), {
        issueId: ISSUE_ID,
        revision: 2,
        documentHash: applied.documentHash,
      });
      assert.deepEqual(await readFile(applied.issuePath), newer);
    },
  );

  await t.test("interrupted before replacement", async (t) => {
    const { paths, issues, issue, service } = await reportedIssue(
      t,
      "agent-runner-issue-update-replace-",
    );
    const input = updateInput(issue);
    await assert.rejects(service(interrupted("renameFile")).update(input));
    assert.equal(
      (await issues.read({ issueId: ISSUE_ID })).documentHash,
      issue.documentHash,
    );
    assert.deepEqual(await issueEntries(paths), [`${ISSUE_ID}.json`]);

    assert.equal((await issues.update(input)).revision, 2);
    assert.equal(
      (await issues.read({ issueId: ISSUE_ID })).tracking.status,
      "resolved",
    );
  });

  await t.test("directory sync lost after replacement", async (t) => {
    const { paths, runStore, issue, service } = await reportedIssue(
      t,
      "agent-runner-issue-update-sync-",
    );
    const input = updateInput(issue);
    let renamed = false;
    await assert.rejects(
      service({
        async openStore(path, options) {
          const store = await openIssueStore(path, options);
          return {
            ...store,
            async sync() {
              if (renamed) throw new Error("simulated sync interruption");
              await store.sync();
            },
          };
        },
        async renameFile(source, destination) {
          await rename(source, destination);
          renamed = true;
        },
      }).update(input),
      /simulated sync interruption/u,
    );

    const events = [];
    const recovered = await createIssueService({
      ...issueOptions(paths),
      async openStore(path, options) {
        const store = await openIssueStore(path, options);
        return {
          ...store,
          async sync() {
            events.push("sync");
            await store.sync();
          },
        };
      },
      runStore: {
        ...runStore,
        withIssueLease: (directory, operation) =>
          runStore.withIssueLease(directory, (ledger) => {
            events.push("lease");
            return operation(ledger);
          }),
        async beginAction(value) {
          const action = await runStore.beginAction(value);
          return {
            get record() {
              return action.record;
            },
            release: () => action.release(),
            updateContext: (context) => action.updateContext(context),
            async complete(result) {
              events.push("complete");
              return action.complete(result);
            },
          };
        },
      },
    }).update(input);
    assert.equal(recovered.revision, 2);
    // The recovered replacement is synced under the lease before completion.
    assert.deepEqual(events.slice(events.indexOf("lease") + 1), [
      "sync",
      "complete",
    ]);
  });

  await t.test("interrupted and superseded before replacement", async (t) => {
    const { issues, issue, service } = await reportedIssue(
      t,
      "agent-runner-issue-update-superseded-",
    );
    const input = updateInput(issue);
    await assert.rejects(service(interrupted("renameFile")).update(input));
    const winner = await issues.update(
      updateInput(issue, { idempotencyKey: "winner", status: "dismissed" }),
    );

    await assert.rejects(
      issues.update(input),
      failure("ERR_ISSUE_REVISION_CONFLICT"),
    );
    assert.equal(
      (await issues.read({ issueId: ISSUE_ID })).documentHash,
      winner.documentHash,
    );
  });
});

test("confines issue coordination to its bound directories", async (t) => {
  const { paths, issue, service } = await reportedIssue(
    t,
    "agent-runner-issue-coordination-link-",
  );
  const stored = await readFile(issue.issuePath);
  const coordination = join(paths.issuesPath, ".coordination", ISSUE_ID);
  const outside = join(paths.root, "outside");
  await mkdir(outside);
  let substituted = false;
  // Links the coordination name elsewhere while the update holds its lease.
  const substituting = {
    async openStore(path, options) {
      const store = await openIssueStore(path, options);
      return {
        ...store,
        async verify() {
          const pending = (await readdir(path)).some((entry) =>
            entry.endsWith(".tmp"),
          );
          if (!substituted && pending) {
            substituted = true;
            await rename(coordination, `${coordination}.moved`);
            await symlink(outside, coordination);
          }
          await store.verify();
        },
      };
    },
  };

  await assert.rejects(
    service(substituting).update(updateInput(issue)),
    failure("ERR_UNSAFE_ISSUE_STORE"),
  );
  assert.deepEqual(await readFile(issue.issuePath), stored);
  // Another writer cannot follow the link into a second lease namespace.
  await assert.rejects(
    service().update(updateInput(issue, { idempotencyKey: "other" })),
    failure("ERR_UNSAFE_ISSUE_STORE"),
  );
  assert.deepEqual(await readdir(outside), []);
  assert.deepEqual(await readFile(issue.issuePath), stored);
});

test("syncs coordination directory entries before admitting mutations", async (t) => {
  const { paths, runStore, issue } = await reportedIssue(
    t,
    "agent-runner-issue-coordination-sync-",
  );
  const coordination = join(paths.issuesPath, ".coordination");
  await rm(coordination, { recursive: true });
  const probe = await open(paths.issuesPath);
  const prototype = Object.getPrototypeOf(probe);
  await probe.close();
  const sync = prototype.sync;
  const synced = new Set();
  t.mock.method(prototype, "sync", async function () {
    synced.add((await this.stat()).ino);
    return sync.call(this);
  });
  let admitted = null;
  await createIssueService({
    ...issueOptions(paths),
    runStore: {
      ...runStore,
      withIssueLease: (directory, operation) =>
        runStore.withIssueLease(directory, (ledger) => {
          admitted = new Set(synced);
          return operation(ledger);
        }),
    },
  }).update(updateInput(issue));

  // Both parents of the recreated directories were synced first.
  for (const path of [paths.issuesPath, coordination]) {
    assert.ok(admitted.has((await stat(path)).ino), path);
  }
});

test("never replays an update against a changed store", async (t) => {
  const { paths, issue, service } = await reportedIssue(
    t,
    "agent-runner-issue-update-store-",
  );
  const input = updateInput(issue);
  await assert.rejects(
    service({
      async renameFile() {
        throw new Error("simulated interruption");
      },
    }).update(input),
  );
  const relocated = {
    env: {
      ...issueOptions(paths).env,
      XDG_DATA_HOME: join(paths.root, "moved"),
    },
  };

  await assert.rejects(
    service(relocated).update(input),
    failure("ERR_ISSUE_STORE_CHANGED"),
  );
  await assert.rejects(access(join(paths.root, "moved")), failure("ENOENT"));
  const receipt = await service().update(input);
  // A completed receipt replays before any store resolution.
  assert.deepEqual(
    await service({ env: { XDG_DATA_HOME: "/unresolved\nlocation" } }).update(
      input,
    ),
    receipt,
  );
  assert.deepEqual(await service(relocated).update(input), receipt);
  await assert.rejects(access(join(paths.root, "moved")), failure("ENOENT"));
});

test("coordinates creation and updates without worktree leases", async (t) => {
  const { paths, runStore, issues, issue } = await reportedIssue(
    t,
    "agent-runner-issue-coordination-",
  );
  // An unrelated execution owns the origin worktree; management is unaffected.
  await runStore.withGuidanceLease(paths.projectPath, async () => {
    assert.equal((await issues.list({})).issues.length, 1);
    await issues.update(updateInput(issue, { status: "in_progress" }));
  });

  const pending = reportInput(paths.projectPath, {
    idempotencyKey: "pending-report",
  });
  await assert.rejects(
    createIssueService({
      ...issueOptions(paths, {
        idFactory: () => SECOND_ID,
        async linkFile(source, destination) {
          await link(source, destination);
          throw new Error("simulated interruption");
        },
      }),
      runStore,
    }).report(pending),
  );
  // A document still linked to its reservation is not yet published.
  assert.deepEqual(
    (await issues.list({})).issues.map(({ issueId }) => issueId),
    [ISSUE_ID],
  );
  await assert.rejects(
    issues.read({ issueId: SECOND_ID }),
    failure("ERR_ISSUE_NOT_FOUND"),
  );

  const unacknowledged = reportInput(paths.projectPath, {
    idempotencyKey: "unacknowledged-report",
  });
  await assert.rejects(
    createIssueService({
      ...issueOptions(paths, {
        idFactory: () => THIRD_ID,
        async onPublished() {
          throw new Error("simulated disconnect");
        },
      }),
      runStore,
    }).report(unacknowledged),
  );
  const published = await issues.read({ issueId: THIRD_ID });
  await issues.update(
    updateInput(published, { idempotencyKey: "after-publication" }),
  );

  // Creation recovery tolerates later tracking updates and never reverts them.
  for (const [input, issueId] of [
    [pending, SECOND_ID],
    [unacknowledged, THIRD_ID],
  ]) {
    assert.equal((await issues.report(input)).issueId, issueId);
  }
  assert.equal(
    (await issues.read({ issueId: THIRD_ID })).tracking.status,
    "resolved",
  );
  assert.deepEqual(
    (await issues.list({})).issues.map(({ issueId }) => issueId).sort(),
    [ISSUE_ID, SECOND_ID, THIRD_ID],
  );
});
