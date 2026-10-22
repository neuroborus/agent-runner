import assert from "node:assert/strict";
import {
  copyFileSync,
  mkdirSync,
  readdirSync,
  renameSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import {
  appendFile,
  copyFile,
  link,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
import filesystem from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
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

// Count decoding separately from full state validation's project-path access.
// No elapsed-time assertions or production cache-inspection API are needed.
function eventDecodes(t, onEvent = () => {}) {
  const parse = JSON.parse;
  const revisions = [];
  const normalized = [];
  Object.defineProperty(revisions, "normalized", { value: normalized });
  t.mock.method(JSON, "parse", (...args) => {
    const value = parse(...args);
    if (value?.state?.runId && value?.recordedAt) {
      revisions.push(value.revision);
      onEvent(value);
      const projectPath = value.state.projectPath;
      let inspected = false;
      Object.defineProperty(value.state, "projectPath", {
        enumerable: true,
        get() {
          if (!inspected) normalized.push(value.revision);
          inspected = true;
          return projectPath;
        },
      });
    }
    return value;
  });
  return revisions;
}

async function seedActivities(f, count, message, base = f.created.state) {
  const expected = [];
  const segments = [""];
  let latest;
  for (let index = 0; index <= count; index += 1) {
    const revision = base.revision + index + 1;
    latest = { ...base, revision, counters: { rounds: index + 1 } };
    const activity =
      index === count
        ? null
        : {
            actor: "runner",
            phase: "run",
            kind: "recorded",
            message,
          };
    if (activity)
      expected.push({ revision, recordedAt: latest.updatedAt, ...activity });
    const segment = Math.floor(index / 100);
    segments[segment] =
      (segments[segment] ?? "") +
      `${JSON.stringify({
        schemaVersion: latest.schemaVersion,
        revision,
        runId: latest.runId,
        recordedAt: latest.updatedAt,
        state: latest,
        activity,
      })}\n`;
  }
  for (const [index, source] of segments.entries())
    await appendFile(
      join(
        f.created.directoryPath,
        index === 0
          ? "events.jsonl"
          : `events-${String(index).padStart(6, "0")}.jsonl`,
      ),
      source,
    );
  await writeFile(
    join(f.created.directoryPath, "state.json"),
    JSON.stringify(latest),
  );
  return { expected, latest };
}

test("repeated control claims preserve unchanged journal certification during warm and cold reads", async (t) => {
  let publications = 0;
  const { store, created, stateRoot } = await fixture(t, {
    onLeasePublicationBoundary: async ({ filePath, phase }) => {
      if (filePath.includes("/.mutation-") && phase === "published")
        publications += 1;
    },
  });
  const { runId } = created.state;
  const latest = await store.transitionRun(created.lease, {
    counters: { rounds: 1 },
  });
  const journalPath = join(created.directoryPath, "events.jsonl");
  const original = await readFile(journalPath);
  await store.loadRun(runId);
  const decoded = eventDecodes(t);
  const nativeLstat = filesystem.lstat;
  let publishing = false;
  const mockedLstat = t.mock.method(
    filesystem,
    "lstat",
    async (path, options) => {
      const metadata = await nativeLstat(path, options);
      if (path === created.directoryPath && options?.bigint && !publishing) {
        publishing = true;
        try {
          // The public artifact operation runs the real choosing/ready protocol
          // without appending a journal event. Await every publication at the
          // observation boundary, independently of filesystem scheduling.
          for (let index = 0; index < 4; index += 1)
            await store.writeRunArtifact(
              created.lease,
              "control-note.md",
              "Note.\n",
            );
        } finally {
          publishing = false;
        }
      }
      return metadata;
    },
  );
  syncBuiltinESMExports();
  try {
    publications = 0;
    assert.deepEqual(await store.loadRun(runId), latest);
    assert.ok(publications >= 4);
    assert.deepEqual(
      decoded,
      [],
      "control publications do not revalidate history",
    );
    assert.equal(
      (await store.readPublicActivity(runId)).cursor,
      latest.revision,
    );
    assert.deepEqual(decoded, [], "covered projections need no event decoding");
    assert.deepEqual(
      await createRunStore({ stateRoot }).loadRun(runId),
      latest,
    );
    assert.deepEqual(
      decoded,
      [1, 2],
      "cold reads still validate every event once",
    );
    assert.deepEqual(await readFile(journalPath), original);
  } finally {
    mockedLstat.mock.restore();
    syncBuiltinESMExports();
  }
});

test("repeated validated reads decode only appended records across transitions and segments", async (t) => {
  const { store, created, stateRoot } = await fixture(t);
  const { runId } = created.state;
  await store.loadRun(runId);
  const decoded = eventDecodes(t);
  for (let rounds = 1; rounds <= 4; rounds += 1) {
    decoded.length = 0;
    const next = await store.transitionRun(created.lease, {
      counters: { rounds },
    });
    assert.deepEqual(decoded, [next.revision]);
    decoded.length = 0;
    assert.deepEqual(await store.loadRun(runId), next);
    assert.deepEqual(await store.readPublicActivity(runId), {
      cursor: next.revision,
      activities: [
        {
          revision: 1,
          recordedAt: created.state.createdAt,
          actor: "runner",
          phase: "run",
          kind: "created",
          message: "Run created.",
        },
      ],
    });
    assert.deepEqual(await store.recoverRun(created.lease), next);
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

test("namespace changes during suffix validation require canonical proof", async (t) => {
  for (const contiguous of [true, false]) {
    await t.test(contiguous ? "appended segment" : "segment gap", async (t) => {
      const { store, created } = await fixture(t);
      const { runId } = created.state;
      const previous = await store.transitionRun(created.lease, {
        counters: { rounds: 1 },
      });
      function record(revision) {
        const state = {
          ...previous,
          revision,
          counters: { rounds: revision - 1 },
        };
        return {
          state,
          source: `${JSON.stringify({
            schemaVersion: state.schemaVersion,
            revision,
            runId,
            recordedAt: state.updatedAt,
            state,
            activity: null,
          })}\n`,
        };
      }
      await writeFile(
        join(created.directoryPath, "events-000001.jsonl"),
        record(3).source,
      );
      const next = record(4);
      let changed = false;
      const decoded = eventDecodes(t, (event) => {
        if (event.revision !== 3 || changed) return;
        changed = true;
        writeFileSync(
          join(
            created.directoryPath,
            contiguous ? "events-000002.jsonl" : "events-000003.jsonl",
          ),
          next.source,
        );
      });
      if (contiguous) {
        assert.deepEqual(await store.loadRun(runId), next.state);
        assert.deepEqual(
          decoded.filter((revision) => revision <= 2),
          [1, 2],
        );
        // Complete state publication so this read tests the new certificate,
        // rather than the separate canonical proof for an older lagging state.
        await writeFile(
          join(created.directoryPath, "state.json"),
          JSON.stringify(next.state),
        );
        decoded.length = 0;
        assert.deepEqual(await store.loadRun(runId), next.state);
        assert.deepEqual(
          decoded,
          [],
          "the new complete prefix can be certified",
        );
      } else {
        await assert.rejects(store.loadRun(runId), {
          code: "ERR_INVALID_EVENT_LOG",
        });
      }
      assert.equal(changed, true);
    });
  }
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
  assert.equal((await store.readPublicActivity(runs.at(-1).runId)).cursor, 1);
  assert.deepEqual(await store.loadRun(runs.at(-1).runId), runs.at(-1));
  assert.deepEqual(decoded, []);
  assert.equal((await store.readPublicActivity(runs[0].runId)).cursor, 1);
  assert.deepEqual(decoded, [1]);
  assert.deepEqual(await store.loadRun(runs[0].runId), runs[0]);
});

test("checkpoint byte overflow falls back to complete validation", async (t) => {
  const { store, created } = await fixture(t);
  await seedActivities({ created }, 1030, "Checkpoint recorded.");
  const latest = await store.transitionRun(created.lease, {
    pipelineState: {
      workflowState: "IMPLEMENT",
      records: Array(90).fill("x".repeat(100_000)),
    },
  });
  await store.loadRun(latest.runId);
  const decoded = eventDecodes(t);
  assert.deepEqual(await store.loadRun(latest.runId), latest);
  assert.equal(decoded.normalized.length, latest.revision);
  decoded.normalized.length = 0;
  assert.equal(
    (await store.readPublicActivity(latest.runId, { limit: 1 })).activities[0]
      .revision,
    1,
  );
  assert.equal(
    decoded.normalized.length,
    latest.revision,
    "unretained checkpoints still validate complete history",
  );
  await store.recoverRun(created.lease);
  const progress = await readFile(
    join(created.directoryPath, "progress.md"),
    "utf8",
  );
  assert.equal(
    progress.split("\n").filter((line) => line.startsWith("- ")).length,
    1031,
  );
  decoded.normalized.length = 0;
  const next = await store.transitionRun(created.lease, {
    counters: { rounds: 2000 },
  });
  assert.equal(
    decoded.normalized.length,
    next.revision,
    "unretained operation-local certificates prevent a second historical normalization",
  );
});

test("combined checkpoint bytes evict runs before the entry cap", async (t) => {
  const { store, input } = await fixture(t);
  const runs = [];
  for (let index = 0; index < 4; index += 1) {
    const run = await store.createRun({
      ...input,
      pipelineState: {
        workflowState: "IMPLEMENT",
        records: Array(22).fill("x".repeat(100_000)),
      },
    });
    await run.lease.release();
    runs.push(run.state);
  }
  const decoded = eventDecodes(t);
  await store.loadRun(runs.at(-1).runId);
  assert.deepEqual(decoded.normalized, []);
  assert.deepEqual(await store.loadRun(runs[0].runId), runs[0]);
  assert.deepEqual(decoded.normalized, [1]);
});

test("publication interruption clears projections populated by callback reads at every boundary", async (t) => {
  const decoded = eventDecodes(t);
  for (const boundary of [
    "event-appended",
    "state-replaced",
    "progress-replaced",
  ]) {
    let interrupt = false;
    let readDuringPublication;
    const { store, created } = await fixture(t, {
      async onTransitionBoundary(point) {
        if (interrupt && point === boundary) {
          await readDuringPublication();
          throw new Error("Interrupted publication.");
        }
      },
    });
    const { runId } = created.state;
    await seedActivities({ created }, 1030, "Checkpoint recorded.");
    readDuringPublication = () => store.readPublicActivity(runId);
    await readDuringPublication();
    interrupt = true;
    await assert.rejects(
      store.transitionRun(
        created.lease,
        { counters: { rounds: 1 } },
        {
          activity: {
            actor: "runner",
            phase: "run",
            kind: "recorded",
            message: "Checkpoint recorded.",
          },
        },
      ),
      /Interrupted publication/u,
    );
    decoded.length = 0;
    decoded.normalized.length = 0;
    const page = await readDuringPublication();
    assert.equal(page.cursor, 50);
    assert.equal(decoded.normalized.length, 1033);
    interrupt = false;
    await rm(join(created.directoryPath, "progress.md"));
    assert.equal((await store.recoverRun(created.lease)).revision, 1033);
    assert.match(
      await readFile(join(created.directoryPath, "progress.md"), "utf8"),
      /Checkpoint recorded\./u,
    );
    assert.deepEqual(await readDuringPublication(), page);
  }
});

test("progress and activity revalidate prefix bytes after publication callbacks", async (t) => {
  let changePrefix;
  const { store, created } = await fixture(t, {
    async onTransitionBoundary(boundary) {
      if (boundary === "state-replaced" && changePrefix) await changePrefix();
    },
  });
  const { runId } = created.state;
  const path = join(created.directoryPath, "events.jsonl");
  changePrefix = async () => {
    const metadata = await stat(path);
    const source = await readFile(path, "utf8");
    await writeFile(path, source.replace("Run created.", "Run updated."));
    await utimes(path, metadata.atime, metadata.mtime);
  };
  await assert.rejects(
    store.transitionRun(created.lease, { counters: { rounds: 1 } }),
    { code: "ERR_INVALID_EVENT_LOG" },
  );
  assert.equal(
    (await store.readPublicActivity(runId)).activities[0].message,
    "Run updated.",
  );
  changePrefix = null;
  await store.recoverRun(created.lease);
  const progressPath = join(created.directoryPath, "progress.md");
  assert.match(await readFile(progressPath, "utf8"), /Run updated\./u);
  changePrefix = async () => {
    const source = await readFile(path, "utf8");
    await writeFile(path, source.replace('"model":"base"', '"model":"fake"'));
  };
  await assert.rejects(
    store.transitionRun(created.lease, { counters: { rounds: 2 } }),
    { code: "ERR_INVALID_EVENT_LOG" },
  );
  await assert.rejects(store.readPublicActivity(runId), {
    code: "ERR_INVALID_EVENT_LOG",
  });
});

test("lock-free activity readers see one complete prefix during interrupted state publication", async (t) => {
  let reached;
  let release;
  const arrived = new Promise((resolve) => {
    reached = resolve;
  });
  const proceed = new Promise((resolve) => {
    release = resolve;
  });
  let pause = false;
  const { store, created, stateRoot } = await fixture(t, {
    async onTransitionBoundary(boundary) {
      if (pause && boundary === "event-appended") {
        reached();
        await proceed;
      }
    },
  });
  const { runId } = created.state;
  pause = true;
  const transition = store.transitionRun(
    created.lease,
    { counters: { rounds: 1 } },
    {
      activity: {
        actor: "worker",
        phase: "implement",
        kind: "summary",
        message: "Candidate updated.",
      },
    },
  );
  try {
    await arrived;
    const peer = createRunStore({ stateRoot });
    const pages = await Promise.all([
      store.readPublicActivity(runId),
      store.readPublicActivity(runId),
      peer.readPublicActivity(runId),
    ]);
    assert.equal(pages[0].cursor, 2);
    assert.equal(pages[0].activities.at(-1).message, "Candidate updated.");
    assert.deepEqual(pages[1], pages[0]);
    assert.deepEqual(pages[2], pages[0]);
  } finally {
    release();
    await transition;
  }
});

test("bounded public projections preserve overflowed history, gaps, segments, and exact progress", async (t) => {
  const decoded = eventDecodes(t);
  for (const [count, message] of [
    [1030, "Checkpoint recorded."],
    [600, "\u{1f642}".repeat(500)],
    [1030, "\u{1f642}".repeat(500)],
  ]) {
    const { store, created, stateRoot, input } = await fixture(t);
    const { runId } = created.state;
    await store.loadRun(runId);
    const expected = [
      {
        revision: 1,
        recordedAt: created.state.updatedAt,
        actor: "runner",
        phase: "run",
        kind: "created",
        message: "Run created.",
      },
    ];
    const seeded = await seedActivities({ store, created }, count, message);
    expected.push(...seeded.expected);
    assert.equal((await store.loadRun(runId)).revision, count + 2);
    decoded.length = 0;
    decoded.normalized.length = 0;
    assert.deepEqual(
      await store.readPublicActivity(runId, {
        afterRevision: count - 1,
        limit: 1,
      }),
      { activities: [expected[count - 1]], cursor: count },
    );
    assert.deepEqual(
      await store.readPublicActivity(runId, {
        afterRevision: count,
        limit: 1,
      }),
      { activities: [expected[count]], cursor: count + 1 },
    );
    assert.deepEqual(
      await store.readPublicActivity(runId, { afterRevision: count }),
      { activities: [expected[count]], cursor: count + 2 },
    );
    assert.deepEqual(
      await store.readPublicActivity(runId, { afterRevision: count + 1 }),
      { activities: [], cursor: count + 2 },
    );
    assert.deepEqual(decoded, [], "recent pages reuse bounded projections");
    assert.deepEqual(await store.readPublicActivity(runId, { limit: 2 }), {
      activities: expected.slice(0, 2),
      cursor: 2,
    });
    assert.equal(
      decoded.length,
      count + 2,
      "even early pages prove the complete prefix",
    );
    assert.deepEqual(
      decoded.normalized,
      [],
      "certified history is decoded without full normalization",
    );
    const progressPath = join(created.directoryPath, "progress.md");
    await writeFile(progressPath, "Stale progress.\n");
    await store.recoverRun(created.lease);
    assert.equal(
      await readFile(progressPath, "utf8"),
      [
        "# Agent Runner Progress",
        "",
        `Run: \`${runId}\``,
        `Pipeline: \`${created.state.pipelineId}\``,
        `Revision: ${count + 2}`,
        "",
        "## Activity",
        "",
        "",
      ].join("\n") +
        expected
          .map(
            (activity) =>
              `- ${activity.recordedAt} — ${activity.actor}/${activity.phase}/${activity.kind}: ${activity.message}\n`,
          )
          .join(""),
    );
    assert.deepEqual(decoded.normalized, []);
    if (message === "Checkpoint recorded.") {
      await writeFile(
        join(created.directoryPath, "state.json"),
        JSON.stringify(created.state),
      );
      await store.recoverRun(created.lease);
      assert.equal(decoded.normalized.length, count + 2);
      decoded.normalized.length = 0;
      assert.deepEqual(await store.readPublicActivity(runId, { limit: 2 }), {
        activities: expected.slice(0, 2),
        cursor: 2,
      });
      assert.deepEqual(decoded.normalized, []);
    }
    const cold = createRunStore({ stateRoot });
    assert.deepEqual(await cold.readPublicActivity(runId, { limit: 2 }), {
      activities: expected.slice(0, 2),
      cursor: 2,
    });
    assert.equal(decoded.normalized.length, count + 2);
    for (let index = 0; index < 8; index += 1) {
      const other = await store.createRun(input);
      await other.lease.release();
    }
    decoded.normalized.length = 0;
    assert.deepEqual(await store.readPublicActivity(runId, { limit: 2 }), {
      activities: expected.slice(0, 2),
      cursor: 2,
    });
    assert.equal(
      decoded.normalized.length,
      count + 2,
      "evicted coverage is revalidated",
    );
    for (let round = 1; round <= 2; round += 1) {
      decoded.normalized.length = 0;
      const next = await store.transitionRun(created.lease, {
        counters: { rounds: count + round + 1 },
      });
      assert.deepEqual(
        decoded.normalized,
        [next.revision],
        "only appended states require semantic validation",
      );
    }
    if (message === "Checkpoint recorded.") {
      await appendFile(
        join(created.directoryPath, "events-000010.jsonl"),
        '{"partial":',
      );
      decoded.normalized.length = 0;
      assert.deepEqual(await store.readPublicActivity(runId, { limit: 2 }), {
        activities: expected.slice(0, 2),
        cursor: 2,
      });
      assert.equal(
        decoded.normalized.length,
        0,
        "complete consumed bytes retain operation-local proof",
      );
      decoded.normalized.length = 0;
      await store.readPublicActivity(runId, { limit: 2 });
      assert.equal(
        decoded.normalized.length,
        count + 4,
        "partial tails are never cached",
      );
      await store.recoverRun(created.lease);
    }
    const history = await store.loadRunHistory(runId);
    assert.deepEqual(
      history.events.map((event) => event.revision),
      Array.from({ length: count + 4 }, (_, index) => index + 1),
    );
  }
});

test("overflow operations establish missing proof and reject unavailable evidence before publishing", async (t) => {
  for (const phase of [
    "transient",
    "persistent",
    "stream",
    "callback",
    "snapshot",
    "control",
  ]) {
    await t.test(phase, async (t) => {
      let unavailable = 0;
      let callback = false;
      let afterPublication = false;
      let publishing = false;
      let publications = 0;
      const f = await fixture(t, {
        onLeasePublicationBoundary: async ({ filePath, phase }) => {
          if (filePath.includes("/.mutation-") && phase === "published")
            publications += 1;
        },
        async onTransitionBoundary(boundary) {
          if (callback && boundary === "progress-replaced") {
            afterPublication = true;
            if (phase === "callback") unavailable = Infinity;
          }
        },
      });
      await seedActivities(f, 1030, "Checkpoint recorded.");
      await f.store.recoverRun(f.created.lease);
      const { runId } = f.created.state;
      const progressPath = join(f.created.directoryPath, "progress.md");
      const progress = await readFile(progressPath, "utf8");
      const nativeLstat = filesystem.lstat;
      const observation = t.mock.method(
        filesystem,
        "lstat",
        async (path, options) => {
          const metadata = await nativeLstat(path, options);
          if (
            phase === "snapshot" &&
            afterPublication &&
            path.endsWith("/state.json")
          )
            unavailable = Infinity;
          if (
            phase === "control" &&
            path === f.created.directoryPath &&
            options?.bigint &&
            !publishing
          ) {
            publishing = true;
            try {
              for (let index = 0; index < 4; index += 1)
                await f.store.writeRunArtifact(
                  f.created.lease,
                  "control-note.md",
                  "Note.\n",
                );
            } finally {
              publishing = false;
            }
          }
          if (
            unavailable &&
            options?.bigint &&
            path.endsWith("/events.jsonl")
          ) {
            unavailable -= 1;
            // Controlled missing binding evidence; no historical bytes change.
            metadata.ctimeNs += 1n;
          }
          return metadata;
        },
      );
      syncBuiltinESMExports();
      try {
        let streaming = phase === "stream";
        const decoded = eventDecodes(t, (event) => {
          if (streaming && event.revision === 1) {
            streaming = false;
            unavailable = Infinity;
          }
        });
        if (["transient", "control"].includes(phase)) {
          unavailable = phase === "transient" ? 2 : 0;
          assert.equal(
            (await f.store.readPublicActivity(runId, { limit: 1 })).cursor,
            1,
          );
          if (phase === "transient")
            assert.ok(
              decoded.normalized.includes(1032),
              "missing evidence requires canonical validation",
            );
          else {
            assert.ok(publications >= 4);
            assert.deepEqual(
              decoded.normalized,
              [],
              "control claims preserve certified history",
            );
          }
        } else {
          unavailable = phase === "persistent" ? Infinity : 0;
          callback = ["callback", "snapshot"].includes(phase);
          await assert.rejects(
            callback
              ? f.store.transitionRun(f.created.lease, {
                  counters: { rounds: 2000 },
                })
              : f.store.readPublicActivity(runId, { limit: 1 }),
            { code: "ERR_INVALID_EVENT_LOG" },
          );
          if (!callback) {
            await assert.rejects(f.store.recoverRun(f.created.lease), {
              code: "ERR_INVALID_EVENT_LOG",
            });
            assert.equal(await readFile(progressPath, "utf8"), progress);
          }
        }
        unavailable = 0;
        afterPublication = false;
        decoded.normalized.length = 0;
        await f.store.loadRun(runId);
        if (!["transient", "control"].includes(phase))
          assert.equal(decoded.normalized.length, callback ? 1033 : 1032);
      } finally {
        observation.mock.restore();
        syncBuiltinESMExports();
      }
    });
  }
});

test("overflow pages prove unread ranges and identities before returning an early limit", async (t) => {
  let change;
  const decoded = eventDecodes(t, (event) => {
    if (event.revision !== 1 || !change) return;
    const apply = change;
    change = null;
    apply();
  });
  for (const race of [
    "bytes",
    "consumed",
    "sealed-growth",
    "file",
    "directory",
  ]) {
    const { store, created } = await fixture(t);
    const { runId } = created.state;
    await seedActivities({ created }, 1030, "\u{1f642}".repeat(500));
    await store.loadRun(runId);
    const path = join(
      created.directoryPath,
      race === "sealed-growth" ? "events-000009.jsonl" : "events-000010.jsonl",
    );
    const source = await readFile(path, "utf8");
    const metadata = await stat(path);
    const firstPath = join(created.directoryPath, "events.jsonl");
    const firstSource = await readFile(firstPath, "utf8");
    const firstMetadata = await stat(firstPath);
    change = () => {
      if (race === "bytes") {
        writeFileSync(path, source.replace("\u{1f642}", "\u{1f643}"));
        utimesSync(path, metadata.atime, metadata.mtime);
      } else if (race === "consumed") {
        writeFileSync(
          firstPath,
          firstSource.replace("Run created.", "Run updated."),
        );
        utimesSync(firstPath, firstMetadata.atime, firstMetadata.mtime);
      } else if (race === "sealed-growth") {
        writeFileSync(path, source + " ");
      } else if (race === "file") {
        copyFileSync(path, `${path}.replacement`);
        renameSync(`${path}.replacement`, path);
      } else {
        const prior = `${created.directoryPath}.prior`;
        renameSync(created.directoryPath, prior);
        mkdirSync(created.directoryPath);
        for (const name of readdirSync(prior))
          renameSync(join(prior, name), join(created.directoryPath, name));
      }
    };
    await assert.rejects(store.readPublicActivity(runId, { limit: 1 }), {
      code: "ERR_INVALID_EVENT_LOG",
    });
    if (race === "sealed-growth") await writeFile(path, source);
    decoded.normalized.length = 0;
    const page = await store.readPublicActivity(runId, {
      afterRevision: 1001,
      limit: 1,
    });
    assert.equal(
      decoded.normalized.length,
      1032,
      "uncertain evidence receives complete validation",
    );
    assert.equal(
      page.activities[0].message,
      race === "bytes"
        ? "\u{1f643}" + "\u{1f642}".repeat(499)
        : "\u{1f642}".repeat(500),
    );
  }
});

test("overflow streaming rejects a hard link added after its safe-open inspection", async (t) => {
  const { store, created, stateRoot } = await fixture(t);
  await seedActivities({ created }, 1030, "Checkpoint recorded.");
  await store.loadRun(created.state.runId);
  const path = join(created.directoryPath, "events.jsonl");
  const metadata = await stat(path);
  const handle = await open(path, "r");
  const prototype = Object.getPrototypeOf(handle);
  await handle.close();
  const originalStat = prototype.stat;
  let opens = 0;
  t.mock.method(prototype, "stat", async function (...args) {
    const observation = await originalStat.apply(this, args);
    if (
      args.length === 0 &&
      observation.ino === metadata.ino &&
      ++opens === 2
    ) {
      // The first open verifies the checkpoint; the second streams it. Add the
      // link after the safe-open observation, before the stream's observation.
      await link(path, join(stateRoot, "linked-events"));
    }
    return observation;
  });
  await assert.rejects(
    store.readPublicActivity(created.state.runId, { limit: 1 }),
    { code: "ERR_INVALID_EVENT_LOG" },
  );
});

test("overflow progress is atomic on projection races and rejects successful callback tampering", async (t) => {
  let callback;
  const { store, created } = await fixture(t, {
    async onTransitionBoundary(boundary) {
      if (boundary === "progress-replaced" && callback) await callback();
    },
  });
  const { runId } = created.state;
  await seedActivities({ created }, 1030, "Checkpoint recorded.");
  await store.recoverRun(created.lease);
  const progressPath = join(created.directoryPath, "progress.md");
  const progress = await readFile(progressPath, "utf8");
  const path = join(created.directoryPath, "events-000010.jsonl");
  const original = await readFile(path, "utf8");
  const metadata = await stat(path);
  let change = true;
  const decoded = eventDecodes(t, (event) => {
    if (event.revision !== 1 || !change) return;
    change = false;
    writeFileSync(path, original.replace('"model":"base"', '"model":"fake"'));
    utimesSync(path, metadata.atime, metadata.mtime);
  });
  await assert.rejects(store.recoverRun(created.lease), {
    code: "ERR_INVALID_EVENT_LOG",
  });
  assert.equal(await readFile(progressPath, "utf8"), progress);
  await assert.rejects(store.readPublicActivity(runId), {
    code: "ERR_INVALID_EVENT_LOG",
  });
  await writeFile(path, original);
  await store.loadRun(runId);
  let callbackFailure = false;
  callback = async () => {
    const source = await readFile(path, "utf8");
    await writeFile(
      path,
      source.replace("Checkpoint recorded.", "Checkpoint adjusted."),
    );
    // The callback can populate a different valid checkpoint; it cannot certify
    // the progress that was just published from the original bytes.
    await store.readPublicActivity(runId);
    if (callbackFailure) throw new Error("Interrupted callback.");
  };
  for (const rounds of [2000, 2001]) {
    callbackFailure = rounds === 2001;
    await assert.rejects(
      store.transitionRun(created.lease, { counters: { rounds } }),
      { code: "ERR_INVALID_EVENT_LOG" },
    );
    decoded.normalized.length = 0;
    await store.readPublicActivity(runId);
    assert.equal(decoded.normalized.length, rounds - 2000 + 1033);
  }
});

test("publication cannot replace its original prefix during lagging-state validation", async (t) => {
  const { store, created } = await fixture(t);
  for (let rounds = 1; rounds <= 2; rounds += 1)
    await store.transitionRun(created.lease, { counters: { rounds } });
  const statePath = join(created.directoryPath, "state.json");
  await writeFile(statePath, JSON.stringify(created.state));
  assert.equal(
    (await store.transitionRun(created.lease, { counters: { rounds: 3 } }))
      .revision,
    4,
    "unchanged lagging history remains publishable",
  );
  await writeFile(statePath, JSON.stringify(created.state));
  const progressPath = join(created.directoryPath, "progress.md");
  const progress = await readFile(progressPath, "utf8");
  const path = join(created.directoryPath, "events.jsonl");
  const nativeLstat = filesystem.lstat;
  let reads = 0;
  const observation = t.mock.method(filesystem, "lstat", async (...args) => {
    const metadata = await nativeLstat(...args);
    if (args[0] === statePath && ++reads === 2) {
      // The original prefix has been proved after append. The older snapshot
      // now forces a canonical scan, which must not adopt different history.
      const source = await readFile(path, "utf8");
      const original = await stat(path);
      await writeFile(path, source.replace("Run created.", "Run updated."));
      await utimes(path, original.atime, original.mtime);
    }
    return metadata;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(
      store.transitionRun(created.lease, { counters: { rounds: 4 } }),
      { code: "ERR_INVALID_EVENT_LOG" },
    );
    assert.equal(await readFile(progressPath, "utf8"), progress);
  } finally {
    observation.mock.restore();
    syncBuiltinESMExports();
  }
});

test("publication verification retains its certificates when state rolls back beyond the adjacent pair", async (t) => {
  let callback;
  const { store, created } = await fixture(t, {
    async onTransitionBoundary(boundary) {
      if (boundary === "progress-replaced" && callback) await callback();
    },
  });
  const { runId } = created.state;
  for (let rounds = 1; rounds <= 2; rounds += 1)
    await store.transitionRun(created.lease, { counters: { rounds } });
  const path = join(created.directoryPath, "events.jsonl");
  callback = async () => {
    const source = await readFile(path, "utf8");
    const metadata = await stat(path);
    await writeFile(path, source.replace("Run created.", "Run updated."));
    await utimes(path, metadata.atime, metadata.mtime);
    await writeFile(
      join(created.directoryPath, "state.json"),
      JSON.stringify(created.state),
    );
    // Cold replay accepts this valid history and can populate a new checkpoint,
    // but neither can prove the bytes used for the already published progress.
    assert.equal(
      (await store.readPublicActivity(runId)).activities[0].message,
      "Run updated.",
    );
  };
  await assert.rejects(
    store.transitionRun(created.lease, { counters: { rounds: 3 } }),
    { code: "ERR_INVALID_EVENT_LOG" },
  );
  assert.match(
    await readFile(join(created.directoryPath, "progress.md"), "utf8"),
    /Run created\./u,
  );
  // Failure must discard the callback's checkpoint too. Restore the latest
  // snapshot so the next read's full replay proves eviction, not snapshot lag.
  const latest = JSON.parse(
    (await readFile(path, "utf8")).trim().split("\n").at(-1),
  ).state;
  await writeFile(
    join(created.directoryPath, "state.json"),
    JSON.stringify(latest),
  );
  const decoded = eventDecodes(t);
  await store.readPublicActivity(runId);
  assert.deepEqual(decoded.normalized, [1, 2, 3, 4]);
});

test("reused and streamed records keep dispatch redaction and each event's stop summary", async (t) => {
  const { store, created, stateRoot } = await fixture(t);
  const { runId } = created.state;
  const dispatch = {
    id: "11111111-1111-4111-8111-111111111111",
    expectedRevision: 1,
  };
  await store.recordRecoveryDispatch(created.lease, dispatch);
  await store.recordRecoveryDispatch(created.lease, dispatch, true);
  const stop = await store.requestOperatorStop({
    runId,
    kind: "pause_requested",
    expectedRevision: 3,
    idempotencyKey: "pause-request",
  });
  await store.completeOperatorStop(created.lease, {
    requestId: stop.requestId,
    patch: {
      pipelineState: { workflowState: "WAITING_FOR_USER" },
      pause: {
        reason: "operator_paused",
        resumeAction: null,
        operatorResume: {
          workflowState: "IMPLEMENT",
          pause: null,
          activeTurn: null,
        },
      },
    },
    outcomeMessage: "Operator pause settled.",
  });
  const decoded = eventDecodes(t);
  const page = await store.readPublicActivity(runId);
  assert.deepEqual(decoded, []);
  assert.deepEqual(
    page.activities.slice(1, 3).map((activity) => activity.message),
    [
      "Detached recovery acquired execution ownership.",
      "Detached recovery reached checkpoint continuation.",
    ],
  );
  assert.deepEqual(
    page.activities.slice(3).map((activity) => activity.stop),
    [
      {
        kind: "pause_requested",
        revision: 4,
        timing: "immediate",
        effectiveTiming: "immediate",
        targetStep: null,
        state: "applicable",
        settlement: null,
      },
      {
        kind: "pause_requested",
        revision: 4,
        timing: "immediate",
        effectiveTiming: "immediate",
        targetStep: null,
        state: "settled",
        settlement: { kind: "quiescent", commit: null },
      },
    ],
  );
  const progress = await readFile(
    join(created.directoryPath, "progress.md"),
    "utf8",
  );
  assert.doesNotMatch(
    JSON.stringify(page) + progress,
    new RegExp(`${dispatch.id}|${stop.requestId}|requestId|"checkpoint":`, "u"),
  );
  assert.match(progress, /Operator pause settled\./u);
  const base = await store.loadRun(runId);
  await seedActivities({ created }, 1030, "Checkpoint recorded.", base);
  await store.loadRun(runId);
  decoded.normalized.length = 0;
  assert.deepEqual(
    (await store.readPublicActivity(runId, { limit: 5 })).activities,
    page.activities,
  );
  assert.deepEqual(decoded.normalized, []);

  // Historical immediate stops omitted timing and settlement fields. Read-time
  // migration must agree with canonical validation, without rewriting records.
  for (const name of (await readdir(created.directoryPath)).filter((name) =>
    /^events.*\.jsonl$/u.test(name),
  )) {
    const path = join(created.directoryPath, name);
    const events = (await readFile(path, "utf8"))
      .trim()
      .split("\n")
      .map(JSON.parse);
    for (const event of events) {
      if (event.activity)
        event.activity.message = ` ${event.activity.message} `;
      const stopRequest = event.state.stopRequest;
      if (stopRequest === null) continue;
      for (const field of [
        "timing",
        "effectiveTiming",
        "targetBoundary",
        "settlement",
        "identityVersion",
      ])
        delete stopRequest[field];
    }
    await writeFile(
      path,
      events.map((event) => JSON.stringify(event)).join("\n") + "\n",
    );
  }
  const statePath = join(created.directoryPath, "state.json");
  const legacy = JSON.parse(await readFile(statePath, "utf8"));
  for (const field of [
    "timing",
    "effectiveTiming",
    "targetBoundary",
    "settlement",
    "identityVersion",
  ])
    delete legacy.stopRequest[field];
  await writeFile(statePath, JSON.stringify(legacy));
  const peer = createRunStore({ stateRoot });
  const canonical = (await peer.loadRunHistory(runId)).events.slice(0, 5);
  const legacyPage = await store.readPublicActivity(runId, { limit: 5 });
  assert.deepEqual(
    legacyPage.activities,
    page.activities.map((activity) => ({
      ...activity,
      ...(activity.stop
        ? { stop: { ...activity.stop, settlement: null } }
        : {}),
    })),
  );
  assert.deepEqual(
    legacyPage.activities.map((activity) => activity.stop?.settlement ?? null),
    canonical.map((event) => event.state.stopRequest?.settlement ?? null),
  );
  decoded.normalized.length = 0;
  assert.deepEqual(
    await store.readPublicActivity(runId, { limit: 5 }),
    legacyPage,
  );
  assert.deepEqual(decoded.normalized, []);
  assert.doesNotMatch(
    JSON.stringify(legacyPage),
    new RegExp(`${dispatch.id}|${stop.requestId}`, "u"),
  );
});
