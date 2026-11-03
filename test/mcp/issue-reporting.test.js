import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  chmod,
  link,
  mkdir,
  mkdtemp,
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

import { createRunStore, parseRunnerConfiguration } from "../../src/index.js";
import {
  createIssueService,
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
async function repository(t, prefix = "agent-runner-issue-report-") {
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
  await executeFile("git", ["init", "-q", paths.projectPath]);
  return paths;
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
  assert.deepEqual(await readdir(paths.issuesPath), [`${ISSUE_ID}.json`]);
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
    (await readdir(paths.issuesPath)).sort(),
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
      assert.deepEqual(await readdir(paths.issuesPath), [`${ISSUE_ID}.json`]);
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
  assert.deepEqual(await readdir(paths.issuesPath), [`${ISSUE_ID}.json`]);
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
      const paths = await repository(t, "agent-runner-issue-overlap-");
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
      assert.deepEqual(await readdir(paths.issuesPath), [
        context.temporaryName,
      ]);
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
