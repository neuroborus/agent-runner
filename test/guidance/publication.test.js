import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { lstat, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";

import { executeFile, fixture, ROOT_MODULE } from "./support/index.js";

const hash = (content) => createHash("sha256").update(content).digest("hex");

test("atomic complete replacement distinguishes absence, empty content, and unchanged content", async (t) => {
  const f = await fixture(t);
  const commonPath = new URL("../../docs/OPERATOR_GUIDE.md", import.meta.url);
  const commonBefore = await readFile(commonPath);
  const first = await f.service.update(
    f.request("# First\n\nWhole document.\n"),
  );
  assert.equal(first.updated, true);
  assert.equal(first.localHash, hash("# First\n\nWhole document.\n"));
  const second = await f.service.update(
    f.request("# Second\n\nRewritten.\n", { expectedHash: first.localHash }),
  );
  assert.equal(second.updated, true);
  assert.equal(await readFile(f.localPath, "utf8"), "# Second\n\nRewritten.\n");
  assert.equal((await lstat(f.localPath)).mode & 0o777, 0o600);
  const before = await lstat(f.localPath);
  const unchanged = await f.service.update(
    f.request("# Second\n\nRewritten.\n", { expectedHash: second.localHash }),
  );
  assert.equal(unchanged.updated, false);
  assert.equal((await lstat(f.localPath)).ino, before.ino);
  const empty = await f.service.update(
    f.request("", { expectedHash: second.localHash }),
  );
  assert.equal(empty.localHash, hash(""));
  assert.equal(await readFile(f.localPath, "utf8"), "");
  assert.deepEqual(await readdir(dirname(f.localPath)), ["rules.md"]);
  assert.deepEqual(await readFile(commonPath), commonBefore);
  assert.deepEqual(await readdir(join(f.stateRoot, "runs")), []);
});

test("null expected hash requires absence, including when replacing an empty existing document", async (t) => {
  const f = await fixture(t);
  const receipt = await f.service.update(f.request(""));
  assert.equal(receipt.localHash, hash(""));
  await assert.rejects(f.service.update(f.request("Replacement.")), {
    code: "ERR_GUIDANCE_STALE",
  });
  assert.equal(await readFile(f.localPath, "utf8"), "");
});

test("completed receipt replay preserves later edits, skips configuration reload, and rejects key reuse", async (t) => {
  const f = await fixture(t);
  const firstRequest = f.request("Original local lesson.");
  const receipt = await f.service.update(firstRequest);
  await f.service.update(
    f.request("Later local lesson.", { expectedHash: receipt.localHash }),
  );
  const replay = f.createService({
    loadConfiguration: async () => {
      throw new Error("Configuration must not reload.");
    },
  });
  assert.deepEqual(await replay.update(firstRequest), receipt);
  assert.equal(await readFile(f.localPath, "utf8"), "Later local lesson.");
  await assert.rejects(
    f.service.update({ ...firstRequest, localContent: "Different." }),
    { code: "ERR_MCP_IDEMPOTENCY_CONFLICT" },
  );
  const actionFiles = await readdir(join(f.stateRoot, "actions"));
  for (const name of actionFiles) {
    const source = await readFile(
      join(f.stateRoot, "actions", name, "action.json"),
      "utf8",
    );
    assert.doesNotMatch(source, /Original local lesson|Later local lesson/u);
    const record = JSON.parse(source);
    assert.equal(record.status, "completed");
    assert.deepEqual(Object.keys(record.result).sort(), [
      "localHash",
      "localPath",
      "projectPath",
      "updated",
    ]);
    assert.ok(!Object.hasOwn(record.context, "localContent"));
  }
});

test("updates respect execution ownership and keep their exact intent retryable", async (t) => {
  const f = await fixture(t);
  const lease = await f.store.acquireWorktreeLease(f.projectPath, randomUUID());
  const input = f.request("After execution.");
  try {
    await assert.rejects(f.service.update(input), {
      code: "ERR_WORKTREE_LEASED",
    });
    await assert.rejects(lstat(f.localPath), { code: "ENOENT" });
    assert.equal(
      (await f.service.read({ projectPath: f.projectPath })).localHash,
      null,
    );
  } finally {
    await lease.release();
  }
  assert.equal((await f.service.update(input)).updated, true);
});

test("two processes cannot publish against the same inspected content", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const childRequest = f.request("Competing process.", {
    expectedHash: hash("Before."),
  });
  const childPath = join(f.root, "publisher.mjs");
  const resultPath = join(f.root, "publisher-result.json");
  await writeFile(
    childPath,
    `import {writeFile} from "node:fs/promises";
import {createGuidanceService,createRunStore,parseRunnerConfiguration} from ${JSON.stringify(ROOT_MODULE)};
const [stateRoot, input, resultPath] = JSON.parse(process.argv[2]);
const service = createGuidanceService({runStore:createRunStore({stateRoot}),loadConfiguration:async()=>parseRunnerConfiguration('{"schemaVersion":1}')});
let result;
try { await service.update(input); result = {published:true}; }
catch (error) { result = {code:error.code}; }
await writeFile(resultPath, JSON.stringify({pid:process.pid,result}));`,
  );
  const service = f.createService({
    async onPublicationBoundary(phase) {
      if (phase !== "prepared") return;
      const environment = { ...process.env };
      // This is an independent publisher, not another Node test-worker process.
      delete environment.NODE_TEST_CONTEXT;
      await executeFile(
        process.execPath,
        [childPath, JSON.stringify([f.stateRoot, childRequest, resultPath])],
        { env: environment },
      );
      // A fixture receipt proves the child ran even when an outer test process
      // consumes nested Node standard output.
      const childResult = JSON.parse(await readFile(resultPath, "utf8"));
      assert.notEqual(childResult.pid, process.pid);
      assert.deepEqual(childResult.result, { code: "ERR_WORKTREE_LEASED" });
    },
  });
  await service.update(
    f.request("Owning process.", { expectedHash: hash("Before.") }),
  );
  await assert.rejects(f.service.update(childRequest), {
    code: "ERR_GUIDANCE_STALE",
  });
  assert.equal(await readFile(f.localPath, "utf8"), "Owning process.");
});

test("every durable publication phase reconciles an interrupted update without a second replacement", async (t) => {
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
      const interrupted = f.createService({
        async onPublicationBoundary(phase) {
          if (phase === stopAt)
            throw new Error("Simulated process interruption.");
        },
      });
      await assert.rejects(interrupted.update(input), {
        code: "ERR_GUIDANCE_STORAGE",
      });
      const inodeBeforeRetry = (await lstat(f.localPath)).ino;
      const receipt = await f.createService().update(input);
      assert.equal(receipt.localHash, hash("After."));
      assert.equal(await readFile(f.localPath, "utf8"), "After.");
      if (["renamed", "published", "receipted"].includes(stopAt))
        assert.equal((await lstat(f.localPath)).ino, inodeBeforeRetry);
      assert.deepEqual(await readdir(dirname(f.localPath)), ["rules.md"]);
    });
  }
});

test("prepared intents reject later edits and never adopt another writer's identical content", async (t) => {
  for (const laterContent of ["Later.", "Reserved content."]) {
    const f = await fixture(t, { initialContent: "Before." });
    const input = f.request("Reserved content.", {
      expectedHash: hash("Before."),
    });
    const interrupted = f.createService({
      async onPublicationBoundary(phase) {
        if (phase === "prepared") throw new Error("Interrupted.");
      },
    });
    await assert.rejects(interrupted.update(input));
    await f.service.update(
      f.request(laterContent, { expectedHash: hash("Before.") }),
    );
    const inode = (await lstat(f.localPath)).ino;
    await assert.rejects(f.service.update(input), {
      code: "ERR_GUIDANCE_STALE",
    });
    assert.equal(await readFile(f.localPath, "utf8"), laterContent);
    assert.equal((await lstat(f.localPath)).ino, inode);
  }
});

test("a post-rename interruption cannot claim a later same-content replacement", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const input = f.request("Reserved content.", {
    expectedHash: hash("Before."),
  });
  await assert.rejects(
    f
      .createService({
        async onPublicationBoundary(phase) {
          if (phase === "renamed") throw new Error("Interrupted.");
        },
      })
      .update(input),
  );
  const other = join(dirname(f.localPath), "other.tmp");
  await writeFile(other, input.localContent, { mode: 0o600 });
  await rename(other, f.localPath);
  const inode = (await lstat(f.localPath)).ino;
  await assert.rejects(f.service.update(input), {
    code: "ERR_GUIDANCE_RECOVERY",
  });
  assert.equal((await lstat(f.localPath)).ino, inode);
});

test("published intent recovery returns its receipt after a later edit and configuration drift", async (t) => {
  const f = await fixture(t);
  const input = f.request("Published.");
  await assert.rejects(
    f
      .createService({
        async onPublicationBoundary(phase) {
          if (phase === "published") throw new Error("Interrupted.");
        },
      })
      .update(input),
  );
  await f.service.update(
    f.request("Later.", { expectedHash: hash("Published.") }),
  );
  f.setConfiguration({ artifactRoot: "CUSTOM_ARTIFACTS" });
  const receipt = await f.service.update(input);
  assert.equal(receipt.localPath, f.localPath);
  assert.equal(receipt.localHash, hash("Published."));
  assert.equal(await readFile(f.localPath, "utf8"), "Later.");
  await assert.rejects(lstat(join(f.projectPath, "CUSTOM_ARTIFACTS")), {
    code: "ENOENT",
  });
});

test("configuration changes and manual edits at publication reject both writes and unchanged no-ops", async (t) => {
  for (const drift of ["configuration", "content"]) {
    for (const unchanged of [false, true]) {
      const f = await fixture(t, { initialContent: "Before." });
      const input = f.request(unchanged ? "Before." : "After.", {
        expectedHash: hash("Before."),
      });
      const service = f.createService({
        async onPublicationBoundary(phase) {
          if (phase !== "before-publish") return;
          if (drift === "configuration")
            f.setConfiguration({ artifactRoot: "CUSTOM_ARTIFACTS" });
          else await writeFile(f.localPath, "Manual edit.");
        },
      });
      await assert.rejects(service.update(input), {
        code:
          drift === "configuration"
            ? "ERR_GUIDANCE_CONFIGURATION_CHANGED"
            : "ERR_GUIDANCE_STALE",
      });
      assert.equal(
        await readFile(f.localPath, "utf8"),
        drift === "configuration" ? "Before." : "Manual edit.",
      );
      await assert.rejects(lstat(join(f.projectPath, "CUSTOM_ARTIFACTS")), {
        code: "ENOENT",
      });
    }
  }
});

test("an interrupted reservation cannot be redirected through new configuration", async (t) => {
  const f = await fixture(t);
  const input = f.request("Pinned.");
  await assert.rejects(
    f
      .createService({
        async onPublicationBoundary(phase) {
          if (phase === "prepared") throw new Error("Interrupted.");
        },
      })
      .update(input),
  );
  f.setConfiguration({ artifactRoot: "CUSTOM_ARTIFACTS" });
  await assert.rejects(f.service.update(input), {
    code: "ERR_GUIDANCE_CONFIGURATION_CHANGED",
  });
  await assert.rejects(lstat(join(f.projectPath, "CUSTOM_ARTIFACTS")), {
    code: "ENOENT",
  });
  await assert.rejects(lstat(f.localPath), { code: "ENOENT" });
});

test("recovery rejects metadata that changes the caller's expected-hash precondition", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const input = f.request("Reserved.", { expectedHash: hash("Before.") });
  await assert.rejects(
    f
      .createService({
        async onPublicationBoundary(phase) {
          if (phase === "prepared") throw new Error("Interrupted.");
        },
      })
      .update(input),
  );
  await f.service.update(
    f.request("Later.", { expectedHash: hash("Before.") }),
  );
  const recordPath = join(
    f.stateRoot,
    "actions",
    hash(input.idempotencyKey),
    "action.json",
  );
  const action = JSON.parse(await readFile(recordPath, "utf8"));
  const stat = await lstat(f.localPath, { bigint: true });
  action.context.before = {
    hash: hash("Later."),
    identity: Object.fromEntries(
      Object.keys(action.context.before.identity).map((key) => [
        key,
        stat[key].toString(),
      ]),
    ),
  };
  await writeFile(recordPath, JSON.stringify(action));
  await assert.rejects(f.service.update(input), {
    code: "ERR_GUIDANCE_RECOVERY",
  });
  assert.equal(await readFile(f.localPath, "utf8"), "Later.");
});

test("competing service instances serialize publication and reject the stale contender", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const competing = f.request("Contender.", { expectedHash: hash("Before.") });
  await f
    .createService({
      async onPublicationBoundary(phase) {
        if (phase === "prepared")
          await assert.rejects(f.createService().update(competing), {
            code: "ERR_WORKTREE_LEASED",
          });
      },
    })
    .update(f.request("Owner.", { expectedHash: hash("Before.") }));
  await assert.rejects(f.service.update(competing), {
    code: "ERR_GUIDANCE_STALE",
  });
  assert.equal(await readFile(f.localPath, "utf8"), "Owner.");
});
