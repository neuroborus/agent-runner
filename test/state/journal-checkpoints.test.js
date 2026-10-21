import assert from "node:assert/strict";
import { utimesSync, writeFileSync } from "node:fs";
import filesystem from "node:fs/promises";
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
    const page = await readDuringPublication();
    assert.equal(page.cursor, 2);
    assert.deepEqual(decoded, [1, 2]);
    interrupt = false;
    await rm(join(created.directoryPath, "progress.md"));
    assert.equal((await store.recoverRun(created.lease)).revision, 2);
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
  await store.transitionRun(created.lease, { counters: { rounds: 1 } });
  assert.equal(
    (await store.readPublicActivity(runId)).activities[0].message,
    "Run updated.",
  );
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
  ]) {
    const { store, created } = await fixture(t);
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
    const segments = [""];
    let latest;
    for (let index = 0; index <= count; index += 1) {
      const revision = index + 2;
      const state = {
        ...created.state,
        revision,
        counters: { rounds: index + 1 },
      };
      latest = state;
      // The last revision has no activity: cursors must still advance to it.
      const activity =
        index === count
          ? null
          : { actor: "runner", phase: "run", kind: "recorded", message };
      if (activity)
        expected.push({ revision, recordedAt: state.updatedAt, ...activity });
      const segment = Math.floor(index / 100);
      segments[segment] =
        (segments[segment] ?? "") +
        `${JSON.stringify({
          schemaVersion: state.schemaVersion,
          revision,
          runId,
          recordedAt: state.updatedAt,
          state,
          activity,
        })}\n`;
    }
    for (const [index, source] of segments.entries())
      await appendFile(
        join(
          created.directoryPath,
          index === 0
            ? "events.jsonl"
            : `events-${String(index).padStart(6, "0")}.jsonl`,
        ),
        source,
      );
    await writeFile(
      join(created.directoryPath, "state.json"),
      JSON.stringify(latest),
    );
    assert.equal((await store.loadRun(runId)).revision, count + 2);
    decoded.length = 0;
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
    assert.deepEqual(
      decoded,
      [1, 2],
      "historical pages replay instead of omitting evicted activity",
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
    const history = await store.loadRunHistory(runId);
    assert.deepEqual(
      history.events.map((event) => event.revision),
      Array.from({ length: count + 2 }, (_, index) => index + 1),
    );
  }
});

test("reused public records keep dispatch redaction and each event's stop summary", async (t) => {
  const { store, created } = await fixture(t);
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
});
