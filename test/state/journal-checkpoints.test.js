import assert from "node:assert/strict";
import { utimesSync, writeFileSync } from "node:fs";
import {
  appendFile,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createRunStore } from "../../src/state/index.js";

async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-checkpoint-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = {
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath: join(root, "project"),
    taskPath: join(root, "task"),
    roles: { worker: { backend: "codex", model: "base" } },
    pipelineState: { workflowState: "IMPLEMENT" },
  };
  await Promise.all([mkdir(input.projectPath), mkdir(input.taskPath)]);
  const stateRoot = join(root, "state");
  const store = createRunStore({ stateRoot, ...options });
  const created = await store.createRun(input);
  t.after(() => created.lease.release().catch(() => {}));
  return { store, created, input, stateRoot };
}

// Count decoded durable records at the public store boundary, without elapsed
// time assertions or a production cache-inspection API.
function eventDecodes(t, onEvent = () => {}) {
  const parse = JSON.parse;
  const revisions = [];
  t.mock.method(JSON, "parse", (...args) => {
    const value = parse(...args);
    if (value?.state?.runId && value?.recordedAt) {
      revisions.push(value.revision);
      onEvent(value);
    }
    return value;
  });
  return revisions;
}

test("repeated validated reads decode only appended records across transitions and segments", async (t) => {
  const { store, created, stateRoot } = await fixture(t);
  const { runId } = created.state;
  await store.loadRun(runId);
  const decoded = eventDecodes(t);
  for (let rounds = 1; rounds <= 4; rounds += 1) {
    const next = await store.transitionRun(created.lease, {
      counters: { rounds },
    });
    decoded.length = 0;
    assert.deepEqual(await store.loadRun(runId), next);
    assert.deepEqual(decoded, [next.revision]);
    decoded.length = 0;
    assert.deepEqual(await store.loadRun(runId), next);
    assert.deepEqual(decoded, []);
  }
  // Small legal segments exercise suffix continuity without a large fixture.
  const previous = await store.loadRun(runId);
  const state = {
    ...previous,
    revision: previous.revision + 1,
    counters: { rounds: 5 },
  };
  await writeFile(
    join(created.directoryPath, "events-000001.jsonl"),
    `${JSON.stringify({
      schemaVersion: state.schemaVersion,
      revision: state.revision,
      runId,
      recordedAt: state.updatedAt,
      state,
      activity: null,
    })}\n`,
  );
  decoded.length = 0;
  assert.deepEqual(await store.loadRun(runId), state);
  assert.deepEqual(decoded, [state.revision]);
  assert.deepEqual(
    await createRunStore({ stateRoot }).loadRunHistory(runId),
    await store.loadRunHistory(runId),
  );
  await store.recoverRun(created.lease);
  const progress = await readFile(join(created.directoryPath, "progress.md"));
  await created.lease.release();
  const coldStore = createRunStore({ stateRoot });
  const coldLease = await coldStore.acquireRunLease(runId);
  try {
    await coldStore.recoverRun(coldLease);
  } finally {
    await coldLease.release();
  }
  assert.deepEqual(
    await readFile(join(created.directoryPath, "progress.md")),
    progress,
  );
});

test("changed prefix bytes, restored mtimes, and replacements never bypass validation", async (t) => {
  const { store, created } = await fixture(t);
  const { runId } = created.state;
  await store.transitionRun(created.lease, { counters: { rounds: 1 } });
  const path = join(created.directoryPath, "events.jsonl");
  const original = await readFile(path, "utf8");
  const metadata = await stat(path);
  for (const replacement of [false, true]) {
    await store.loadRun(runId);
    const changed = original.replace('"model":"base"', '"model":"fake"');
    assert.equal(Buffer.byteLength(changed), Buffer.byteLength(original));
    const destination = replacement ? `${path}.replacement` : path;
    await writeFile(destination, changed);
    if (replacement) await rename(destination, path);
    await utimes(path, metadata.atime, metadata.mtime);
    await assert.rejects(store.loadRun(runId), {
      code: "ERR_INVALID_EVENT_LOG",
    });
    await writeFile(path, original);
  }
  await store.loadRun(runId);
  const decoded = eventDecodes(t);
  await copyFile(path, `${path}.replacement`);
  await rename(`${path}.replacement`, path);
  await store.loadRun(runId);
  assert.deepEqual(
    decoded,
    [1, 2],
    "even identical replacement bytes require cold validation",
  );
  decoded.length = 0;
  const priorDirectory = `${created.directoryPath}.prior`;
  await rename(created.directoryPath, priorDirectory);
  await mkdir(created.directoryPath);
  for (const filename of ["events.jsonl", "state.json"])
    await rename(
      join(priorDirectory, filename),
      join(created.directoryPath, filename),
    );
  await store.loadRun(runId);
  assert.deepEqual(
    decoded,
    [1, 2],
    "directory replacement invalidates the checkpoint",
  );
});

test("a prefix changed during suffix validation is revalidated even with restored mtime", async (t) => {
  const { store, created } = await fixture(t);
  const { runId } = created.state;
  const previous = await store.transitionRun(created.lease, {
    counters: { rounds: 1 },
  });
  await store.loadRun(runId);
  const path = join(created.directoryPath, "events.jsonl");
  const original = await readFile(path, "utf8");
  const metadata = await stat(path);
  const state = { ...previous, revision: 3, counters: { rounds: 2 } };
  await writeFile(
    join(created.directoryPath, "events-000001.jsonl"),
    `${JSON.stringify({
      schemaVersion: state.schemaVersion,
      revision: 3,
      runId,
      recordedAt: state.updatedAt,
      state,
      activity: null,
    })}\n`,
  );
  let changed = false;
  const decoded = eventDecodes(t, (event) => {
    if (event.revision !== 3 || changed) return;
    changed = true;
    writeFileSync(path, original.replace("Run created.", "Run updated."));
    utimesSync(path, metadata.atime, metadata.mtime);
  });
  assert.deepEqual(await store.loadRun(runId), state);
  assert.deepEqual(decoded, [3, 1, 2, 3]);
});

test("snapshot mismatch, old lagging snapshots, and partial tails require canonical proof", async (t) => {
  const { store, created } = await fixture(t);
  const { runId } = created.state;
  for (let rounds = 1; rounds <= 3; rounds += 1)
    await store.transitionRun(created.lease, { counters: { rounds } });
  const latest = await store.loadRun(runId);
  const statePath = join(created.directoryPath, "state.json");
  await writeFile(
    statePath,
    JSON.stringify({ ...latest, counters: { rounds: 99 } }),
  );
  await assert.rejects(store.loadRun(runId), { code: "ERR_INVALID_RUN_STATE" });
  await writeFile(statePath, JSON.stringify(latest));
  await store.loadRun(runId);
  await writeFile(statePath, JSON.stringify(created.state));
  const decoded = eventDecodes(t);
  assert.deepEqual(await store.loadRun(runId), latest);
  assert.deepEqual(decoded, [1, 2, 3, 4]);
  await appendFile(join(created.directoryPath, "events.jsonl"), '{"partial":');
  assert.deepEqual(await store.recoverRun(created.lease), latest);
  assert.ok(
    (
      await readFile(join(created.directoryPath, "events.jsonl"), "utf8")
    ).endsWith("\n"),
  );
});

test("bounded checkpoint retention evicts older runs without losing canonical history", async (t) => {
  const { store, created, input } = await fixture(t);
  await store.loadRun(created.state.runId);
  const runs = [created.state];
  for (let index = 0; index < 8; index += 1) {
    const next = await store.createRun(input);
    await next.lease.release();
    runs.push(await store.loadRun(next.state.runId));
  }
  const decoded = eventDecodes(t);
  assert.deepEqual(await store.loadRun(runs.at(-1).runId), runs.at(-1));
  assert.deepEqual(decoded, []);
  assert.deepEqual(await store.loadRun(runs[0].runId), runs[0]);
  assert.deepEqual(decoded, [1]);
});

test("checkpoint byte overflow falls back to complete validation", async (t) => {
  const { store, created } = await fixture(t);
  const latest = await store.transitionRun(created.lease, {
    pipelineState: {
      workflowState: "IMPLEMENT",
      records: Array(90).fill("x".repeat(100_000)),
    },
  });
  await store.loadRun(latest.runId);
  const decoded = eventDecodes(t);
  assert.deepEqual(await store.loadRun(latest.runId), latest);
  assert.deepEqual(decoded, [1, 2]);
});

test("publication interruption clears evidence populated by a callback read", async (t) => {
  let interrupt = false;
  let readDuringPublication;
  const { store, created } = await fixture(t, {
    async onTransitionBoundary(boundary) {
      if (interrupt && boundary === "event-appended") {
        await readDuringPublication();
        throw new Error("Interrupted publication.");
      }
    },
  });
  readDuringPublication = () => store.loadRun(created.state.runId);
  await readDuringPublication();
  interrupt = true;
  await assert.rejects(
    store.transitionRun(created.lease, { counters: { rounds: 1 } }),
    /Interrupted publication/u,
  );
  const decoded = eventDecodes(t);
  assert.equal((await readDuringPublication()).revision, 2);
  assert.deepEqual(decoded, [1, 2]);
  interrupt = false;
  assert.equal((await store.recoverRun(created.lease)).revision, 2);
});
