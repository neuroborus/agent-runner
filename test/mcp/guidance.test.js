import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import {
  main,
  MAX_GUIDANCE_BYTES,
  parseRunnerConfiguration,
} from "../../src/index.js";
import { createMcpControlPlane, createMcpServer } from "../../src/mcp/index.js";
import { fixture } from "../guidance/support/index.js";

const hash = (content) => createHash("sha256").update(content).digest("hex");

async function connect(t, control, issueReportingEnabled = true) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const server = createMcpServer({ control, issueReportingEnabled });
  const client = new Client({ name: "guidance-test", version: "1.0.0" });
  t.after(() => client.close());
  t.after(() => server.close());
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
}

function control(f, guidance = f.service) {
  return createMcpControlPlane({ runner: {}, runStore: f.store, guidance });
}

async function call(client, name, input) {
  const response = await client.callTool({ name, arguments: input });
  assert.notEqual(response.isError, true, JSON.stringify(response));
  assert.deepEqual(
    JSON.parse(response.content[0].text),
    response.structuredContent,
  );
  return response.structuredContent;
}

async function cliEdit(f, launchEditor) {
  let errors = "";
  const exitCode = await main(
    ["guidance", "edit", "--project", f.projectPath],
    {
      guidance: f.createService({
        env: { EDITOR: "test-editor" },
        temporaryRoot: f.root,
        launchEditor,
      }),
      stdout: { write() {} },
      stderr: {
        write(chunk) {
          errors += chunk;
        },
      },
      createCommandRunner: () =>
        assert.fail("guidance must not construct a run"),
    },
  );
  return { exitCode, errors };
}

test("discovers strict local guidance tools and one startup reminder with either reporting setting", async (t) => {
  for (const enabled of [true, false]) {
    const client = await connect(t, {}, enabled);
    const { tools } = await client.listTools();
    const read = tools.find(({ name }) => name === "guidance_read");
    const update = tools.find(({ name }) => name === "guidance_update");
    assert.equal(client.getInstructions().match(/guidance_read/gu).length, 1);
    assert.match(
      client.getInstructions(),
      /before first managing a run for each project/u,
    );
    assert.match(client.getInstructions(), /one run_wait call/u);
    assert.equal(
      tools.some(({ name }) => name === "unexpected_issue_report"),
      enabled,
    );
    for (const tool of [read, update]) {
      assert.equal(tool.inputSchema.additionalProperties, false);
      assert.ok(tool.inputSchema.properties.projectConfigurationPath);
    }
    assert.deepEqual(read.inputSchema.required, ["projectPath"]);
    assert.deepEqual(update.inputSchema.required.sort(), [
      "expectedHash",
      "idempotencyKey",
      "localContent",
      "projectPath",
    ]);
    assert.deepEqual(read.annotations, {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    });
    assert.deepEqual(update.annotations, {
      ...read.annotations,
      readOnlyHint: false,
      destructiveHint: true,
    });
    assert.match(update.description, /same idempotency key and arguments/u);
  }
});

test("rejects invalid guidance arguments before dispatch and accepts nullable hashes and empty content", async (t) => {
  let reads = 0;
  let updates = 0;
  const client = await connect(t, {
    async guidanceRead() {
      reads += 1;
      return {};
    },
    async guidanceUpdate() {
      updates += 1;
      return {};
    },
  });
  const input = {
    projectPath: "/project",
    localContent: "",
    expectedHash: null,
    idempotencyKey: "edit-1",
  };
  for (const argumentsValue of [
    { ...input, expectedHash: undefined },
    { ...input, expectedHash: "invalid" },
    { ...input, idempotencyKey: undefined },
    { ...input, idempotencyKey: "\n" },
    { ...input, projectPath: " " },
    { ...input, projectConfigurationPath: "bad\npath" },
    { ...input, localContent: 1 },
    { ...input, localContent: "x".repeat(MAX_GUIDANCE_BYTES + 1) },
    { ...input, commonContent: "Cannot replace this." },
    { ...input, ruleId: "no-rule-crud" },
  ]) {
    assert.equal(
      (
        await client.callTool({
          name: "guidance_update",
          arguments: argumentsValue,
        })
      ).isError,
      true,
    );
  }
  assert.equal(
    (
      await client.callTool({
        name: "guidance_read",
        arguments: { projectPath: "/project", localContent: "unsupported" },
      })
    ).isError,
    true,
  );
  assert.equal(reads, 0);
  assert.equal(updates, 0);
  await call(client, "guidance_update", input);
  await call(client, "guidance_update", { ...input, expectedHash: hash("") });
  assert.equal(updates, 2);
});

test("default MCP wiring reads complete configured guidance without creating missing files or state", async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(
    join(f.projectPath, "LOCAL_ARTIFACTS/custom.json"),
    '{"schemaVersion":1,"artifactRoot":"CUSTOM_ARTIFACTS"}',
  );
  const client = await connect(
    t,
    createMcpControlPlane({
      runner: {},
      runStore: f.store,
      loadConfiguration: async () =>
        parseRunnerConfiguration('{"schemaVersion":1}'),
    }),
  );
  const selectors = {
    projectPath: f.projectPath,
    projectConfigurationPath: "LOCAL_ARTIFACTS/custom.json",
  };
  const before = await call(client, "guidance_read", selectors);
  assert.equal(
    before.localPath,
    join(f.projectPath, "CUSTOM_ARTIFACTS/agent-runner/rules.md"),
  );
  assert.equal(before.localHash, null);
  assert.equal(before.localContent, "");
  await assert.rejects(lstat(join(f.projectPath, "CUSTOM_ARTIFACTS")), {
    code: "ENOENT",
  });
  await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
  const common = await readFile(
    new URL("../../docs/OPERATOR_GUIDE.md", import.meta.url),
    "utf8",
  );
  assert.equal(before.commonContent, common);
  assert.ok(before.combinedContent.includes(common));

  const localContent =
    "# Local additions\n\n" + "Résumé of a project lesson.\n".repeat(400);
  const receipt = await call(
    client,
    "guidance_update",
    f.request(localContent, selectors),
  );
  assert.deepEqual(Object.keys(receipt).sort(), [
    "localHash",
    "localPath",
    "projectPath",
    "updated",
  ]);
  const after = await call(client, "guidance_read", selectors);
  assert.equal(after.localHash, hash(localContent));
  assert.equal(after.localContent, localContent);
  assert.equal(after.commonContent, common);
  let cliOutput = "";
  assert.equal(
    await main(
      [
        "guidance",
        "--project",
        f.projectPath,
        "--project-config",
        selectors.projectConfigurationPath,
      ],
      {
        guidance: f.service,
        stdout: {
          write(chunk) {
            cliOutput += chunk;
          },
        },
        stderr: { write: () => assert.fail("read should succeed") },
      },
    ),
    0,
  );
  assert.equal(cliOutput, after.combinedContent);
  const empty = await call(
    client,
    "guidance_update",
    f.request("", { ...selectors, expectedHash: after.localHash }),
  );
  assert.equal(empty.localHash, hash(""));
  assert.equal(await readFile(empty.localPath, "utf8"), "");
  assert.equal(
    (await call(client, "guidance_read", selectors)).commonContent,
    common,
  );
});

test("MCP delegates content and destination safety without disclosing rejected bodies", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const client = await connect(t, control(f));
  for (const localContent of [
    "PRIVATE_BODY\u0000",
    "PRIVATE_BODY\ud800",
    "PRIVATE_BODY" + "é".repeat(MAX_GUIDANCE_BYTES / 2),
    "password=PRIVATE_BODY",
  ]) {
    const response = await client.callTool({
      name: "guidance_update",
      arguments: f.request(localContent, { expectedHash: hash("Before.") }),
    });
    assert.equal(response.isError, true);
    assert.doesNotMatch(JSON.stringify(response), /PRIVATE_BODY/u);
  }
  assert.equal(await readFile(f.localPath, "utf8"), "Before.");
  await writeFile(join(f.projectPath, ".gitignore"), "");
  assert.equal(
    (
      await client.callTool({
        name: "guidance_read",
        arguments: { projectPath: f.projectPath },
      })
    ).isError,
    true,
  );
  assert.equal(
    (
      await client.callTool({
        name: "guidance_update",
        arguments: f.request("After.", { expectedHash: hash("Before.") }),
      })
    ).isError,
    true,
  );
  assert.equal(await readFile(f.localPath, "utf8"), "Before.");
});

test("completed MCP retries replay receipts after CLI edits while stale hashes and conflicting keys fail", async (t) => {
  const f = await fixture(t);
  const client = await connect(t, control(f));
  const input = f.request("First project lesson.");
  const receipt = await call(client, "guidance_update", input);
  assert.deepEqual(
    await cliEdit(f, async (_, path) => {
      await writeFile(path, "Later project lesson.");
      return { exitCode: 0, signal: null };
    }),
    { exitCode: 0, errors: "" },
  );
  const inode = (await lstat(f.localPath)).ino;
  const restarted = await connect(
    t,
    control(
      f,
      f.createService({
        loadConfiguration: async () =>
          assert.fail("completed retries must not reload configuration"),
      }),
    ),
  );
  assert.deepEqual(await call(restarted, "guidance_update", input), receipt);
  for (const rejected of [
    { ...input, localContent: "PRIVATE_REJECTED_CONTENT" },
    f.request("PRIVATE_REJECTED_CONTENT", { expectedHash: receipt.localHash }),
  ]) {
    const response = await client.callTool({
      name: "guidance_update",
      arguments: rejected,
    });
    assert.equal(response.isError, true);
    assert.doesNotMatch(JSON.stringify(response), /PRIVATE_REJECTED_CONTENT/u);
  }
  assert.equal(await readFile(f.localPath, "utf8"), "Later project lesson.");
  assert.equal((await lstat(f.localPath)).ino, inode);
  for (const name of await readdir(join(f.stateRoot, "actions"))) {
    const record = await readFile(
      join(f.stateRoot, "actions", name, "action.json"),
      "utf8",
    );
    assert.doesNotMatch(
      record,
      /First project lesson|Later project lesson|PRIVATE_REJECTED_CONTENT/u,
    );
  }
  assert.deepEqual(await readdir(join(f.stateRoot, "runs")), []);
});

test("MCP retries reconcile every interrupted publication boundary without republishing completed content", async (t) => {
  for (const stopAt of [
    "reserved",
    "writing",
    "prepared",
    "renamed",
    "published",
    "receipted",
  ]) {
    await t.test(stopAt, async (t) => {
      const f = await fixture(t, { initialContent: "Before." });
      const input = f.request("After.", { expectedHash: hash("Before.") });
      const interrupted = await connect(
        t,
        control(
          f,
          f.createService({
            async onPublicationBoundary(phase) {
              if (phase === stopAt)
                throw new Error("PRIVATE_INTERRUPTION_DETAIL");
            },
          }),
        ),
      );
      const failure = await interrupted.callTool({
        name: "guidance_update",
        arguments: input,
      });
      assert.equal(failure.isError, true);
      assert.doesNotMatch(
        JSON.stringify(failure),
        /PRIVATE_INTERRUPTION_DETAIL/u,
      );
      const inode = (await lstat(f.localPath)).ino;
      const restarted = await connect(t, control(f, f.createService()));
      const receipt = await call(restarted, "guidance_update", input);
      assert.equal(receipt.localHash, hash("After."));
      assert.equal(await readFile(f.localPath, "utf8"), "After.");
      if (["renamed", "published", "receipted"].includes(stopAt))
        assert.equal((await lstat(f.localPath)).ino, inode);
    });
  }
});

test("a disconnected MCP client cannot cancel publication or lose its retry receipt", async (t) => {
  const f = await fixture(t);
  const prepared = Promise.withResolvers();
  const release = Promise.withResolvers();
  const receipted = Promise.withResolvers();
  t.after(() => release.resolve());
  const client = await connect(
    t,
    control(
      f,
      f.createService({
        async onPublicationBoundary(phase) {
          if (phase === "prepared") {
            prepared.resolve();
            await release.promise;
          }
          if (phase === "receipted") receipted.resolve();
        },
      }),
    ),
  );
  const input = f.request("Durable project lesson.");
  const waiting = client
    .callTool({ name: "guidance_update", arguments: input })
    .then(
      () => assert.fail("the disconnected call must not return success"),
      () => {},
    );
  await prepared.promise;
  await client.close();
  await waiting;
  release.resolve();
  await receipted.promise;
  const restarted = await connect(t, control(f));
  const receipt = await call(restarted, "guidance_update", input);
  assert.equal(receipt.localHash, hash(input.localContent));
  assert.equal(await readFile(f.localPath, "utf8"), input.localContent);
});

test("an incomplete MCP publication cannot overwrite a later CLI edit", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const input = f.request("Interrupted lesson.", {
    expectedHash: hash("Before."),
  });
  const client = await connect(
    t,
    control(
      f,
      f.createService({
        async onPublicationBoundary(phase) {
          if (phase === "prepared") throw new Error("Interrupted.");
        },
      }),
    ),
  );
  assert.equal(
    (await client.callTool({ name: "guidance_update", arguments: input }))
      .isError,
    true,
  );
  assert.equal(
    (
      await cliEdit(f, async (_, path) => {
        await writeFile(path, "Later CLI lesson.");
        return { exitCode: 0, signal: null };
      })
    ).exitCode,
    0,
  );
  const restarted = await connect(t, control(f));
  assert.equal(
    (await restarted.callTool({ name: "guidance_update", arguments: input }))
      .isError,
    true,
  );
  assert.equal(await readFile(f.localPath, "utf8"), "Later CLI lesson.");
});

test("MCP publication excludes concurrent CLI writers", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const client = await connect(
    t,
    control(
      f,
      f.createService({
        async onPublicationBoundary(phase) {
          if (phase !== "prepared") return;
          const rejected = await cliEdit(f, async (_, path) => {
            await writeFile(path, "Concurrent CLI lesson.");
            return { exitCode: 0, signal: null };
          });
          assert.equal(rejected.exitCode, 1);
          assert.doesNotMatch(rejected.errors, /Concurrent CLI lesson/u);
        },
      }),
    ),
  );
  await call(
    client,
    "guidance_update",
    f.request("MCP lesson.", { expectedHash: hash("Before.") }),
  );
  assert.equal(await readFile(f.localPath, "utf8"), "MCP lesson.");
});

test("an unchanged CLI editor close rejects an MCP update made during the edit", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const client = await connect(t, control(f));
  const rejected = await cliEdit(f, async () => {
    await call(
      client,
      "guidance_update",
      f.request("MCP lesson.", { expectedHash: hash("Before.") }),
    );
    return { exitCode: 0, signal: null };
  });
  assert.equal(rejected.exitCode, 1);
  assert.match(rejected.errors, /Local guidance changed/u);
  assert.equal(await readFile(f.localPath, "utf8"), "MCP lesson.");
});

test("MCP guidance respects execution ownership and never changes persisted run context", async (t) => {
  const f = await fixture(t);
  const created = await f.store.createRun({
    runId: randomUUID(),
    pipelineId: "plan-authoring",
    pipelineStateVersion: 1,
    projectPath: f.projectPath,
    taskPath: f.projectPath,
    roles: {},
    counters: {},
    hashes: {},
    pipelineState: { workflowState: "CLARIFY" },
  });
  await created.lease.release();
  const before = await f.store.loadRun(created.state.runId);
  const client = await connect(t, control(f));
  const lease = await f.store.acquireWorktreeLease(
    f.projectPath,
    created.state.runId,
  );
  const input = f.request("SUPERVISOR_ONLY_LESSON");
  try {
    assert.equal(
      (await client.callTool({ name: "guidance_update", arguments: input }))
        .isError,
      true,
    );
    assert.equal(
      (await call(client, "guidance_read", { projectPath: f.projectPath }))
        .localHash,
      null,
    );
    await assert.rejects(lstat(f.localPath), { code: "ENOENT" });
  } finally {
    await lease.release();
  }
  await call(client, "guidance_update", input);
  assert.deepEqual(await f.store.loadRun(created.state.runId), before);
  assert.doesNotMatch(JSON.stringify(before), /SUPERVISOR_ONLY_LESSON/u);
});
