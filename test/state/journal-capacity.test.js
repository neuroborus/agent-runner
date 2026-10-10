import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createRunStore,
  DEFAULT_MAX_EVENT_LOG_BYTES,
} from "../../src/state/index.js";

test("journal capacity charges exact UTF-8 bytes before tail repair and keeps lower-policy recovery readable", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "journal-capacity-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  let capacity = DEFAULT_MAX_EVENT_LOG_BYTES;
  const options = {
    stateRoot: join(root, "state"),
    clock: () => new Date("2026-01-01T00:00:00.000Z"),
  };
  const store = createRunStore({
    ...options,
    maxEventLogBytes: (state) => {
      assert.throws(() => {
        state.pipelineState.payload = "changed by policy";
      }, TypeError);
      return capacity;
    },
  });
  const created = await store.createRun({
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: { worker: { backend: "codex" } },
    pipelineState: { workflowState: "CLARIFY", payload: "" },
  });
  const paths = ["events.jsonl", "state.json", "progress.md"].map((name) =>
    join(created.directoryPath, name),
  );
  const initial = await readFile(paths[0]);
  const next = {
    ...created.state,
    revision: 2,
    pipelineState: { workflowState: "CLARIFY", payload: "€😀" },
  };
  const encode = () =>
    Buffer.from(
      JSON.stringify({
        schemaVersion: next.schemaVersion,
        revision: next.revision,
        runId: next.runId,
        recordedAt: next.updatedAt,
        state: next,
        activity: null,
      }) + "\n",
    );
  // Put the first multibyte character across the reader's 64 KiB boundary.
  const padding =
    65_535 - initial.length - encode().indexOf(Buffer.from("€😀"));
  assert.ok(padding > 0);
  next.pipelineState.payload = "a".repeat(padding) + "€😀";
  const encoded = encode();
  capacity = initial.length + encoded.length - 1;
  await appendFile(paths[0], Buffer.from([0xe2, 0x82]));
  const before = await Promise.all(paths.map((path) => readFile(path)));
  await assert.rejects(
    store.transitionRun(created.lease, { pipelineState: next.pipelineState }),
    { code: "ERR_EVENT_LOG_LIMIT" },
  );
  assert.deepEqual(
    await Promise.all(paths.map((path) => readFile(path))),
    before,
  );
  capacity++;
  const accepted = await store.transitionRun(created.lease, {
    pipelineState: next.pipelineState,
  });
  assert.deepEqual(await readFile(paths[0]), Buffer.concat([initial, encoded]));
  assert.equal((await readFile(paths[0])).length, capacity);
  assert.deepEqual(
    await createRunStore(options).loadRun(accepted.runId),
    accepted,
  );
  await created.lease.release();

  const lower = createRunStore({ ...options, maxEventLogBytes: 1 });
  await appendFile(paths[0], Buffer.from([0xf0, 0x9f]));
  const history = await lower.loadRunHistory(accepted.runId);
  assert.deepEqual(history.run, accepted);
  assert.equal(history.events.length, 2);
  const lease = await lower.acquireRunLease(accepted.runId);
  try {
    assert.deepEqual(await lower.recoverRun(lease), accepted);
    assert.deepEqual(
      await readFile(paths[0]),
      Buffer.concat([initial, encoded]),
    );
    const recovered = await Promise.all(paths.map((path) => readFile(path)));
    await assert.rejects(
      lower.transitionRun(lease, { counters: { repairs: 1 } }),
      { code: "ERR_EVENT_LOG_LIMIT" },
    );
    assert.deepEqual(
      await Promise.all(paths.map((path) => readFile(path))),
      recovered,
    );
  } finally {
    await lease.release();
  }
});
