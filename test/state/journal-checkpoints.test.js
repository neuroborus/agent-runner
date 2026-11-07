import assert from "node:assert/strict";
import { ChildProcess } from "node:child_process";
import crypto from "node:crypto";
import nativeFilesystem, {
  constants,
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

import {
  createPlanAuthoringState,
  planAuthoringPipeline,
} from "@agent-runner/plan-authoring";

import {
  readProcessIdentity,
  resolveOwnedProcessLauncher,
  spawnOwnedProcess,
  terminateOwnedProcess,
} from "../../src/agents/index.js";
import { createStopMonitor } from "../../src/runner/stops.js";
import { inspectTrustedRequirements } from "../../src/runner/trusted-requirements.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
  runExactCommand,
} from "../../src/trusted-validation/index.js";
import { sandboxTrustedCommand } from "../../src/trusted-validation/execution.js";

import {
  createRunStore,
  RunObservationBusyError,
} from "../../src/state/index.js";
import { createStateJournal } from "../../src/state/journal.js";
import { createRunner } from "../../src/runner/index.js";
import { createMcpControlPlane } from "../../src/mcp/index.js";
import { main } from "../../src/index.js";

async function fixture(
  t,
  { pipelineId = "plan-execution", runInput = {}, ...options } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-checkpoint-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = {
    pipelineId,
    pipelineStateVersion: 1,
    projectPath: join(root, "project"),
    taskPath: join(root, "task"),
    roles: { worker: { backend: "codex", model: "base" } },
    pipelineState: { workflowState: "IMPLEMENT" },
    ...runInput,
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

test("journal recovery returns its verified immutable value while preserving the original capture", async (t) => {
  const { store, created } = await fixture(t);
  const directory = created.directoryPath;
  const { runId } = created.state;
  const latest = await store.transitionRun(created.lease, {
    counters: { rounds: 1 },
  });
  const journal = createStateJournal({ onTransitionBoundary: async () => {} });
  const eventsPath = join(directory, "events.jsonl");
  const statePath = join(directory, "state.json");
  const prefix = await readFile(eventsPath, "utf8");
  const handle = await open(eventsPath, "r");
  const prototype = Object.getPrototypeOf(handle);
  await handle.close();
  const nativeStat = prototype.stat;
  const nativeTruncate = prototype.truncate;
  const inode = (await stat(eventsPath)).ino;
  let truncations = 0;
  const truncateMock = t.mock.method(
    prototype,
    "truncate",
    async function (...args) {
      if ((await nativeStat.call(this)).ino === inode) truncations += 1;
      return nativeTruncate.apply(this, args);
    },
  );
  try {
    for (const lagged of [false, true]) {
      if (lagged) await writeFile(statePath, JSON.stringify(created.state));
      const capture = await journal.loadSnapshot(directory, runId);
      assert.equal(capture.stateLagged, lagged);
      const recovered = await journal.recover(directory, capture);
      assert.equal(recovered, capture, "no tail requires no replacement proof");
      assert.equal(recovered.hasPartialTail, false);
      assert.equal(Object.isFrozen(recovered), true);
      assert.deepEqual(JSON.parse(await readFile(statePath, "utf8")), latest);
      assert.equal(await readFile(eventsPath, "utf8"), prefix);
      assert.equal(truncations, 0);
    }
    await appendFile(eventsPath, '{"partial":');
    const capture = await journal.loadSnapshot(directory, runId);
    const original = structuredClone(capture);
    assert.equal(capture.hasPartialTail, true);
    const recovered = await journal.recover(directory, capture);
    assert.notEqual(recovered, capture);
    assert.equal(recovered.hasPartialTail, false);
    assert.equal(recovered.certificate, capture.certificate);
    assert.equal(recovered.state, capture.state);
    assert.equal(recovered.lastEvent, capture.lastEvent);
    assert.equal(recovered.validByteLength, capture.validByteLength);
    assert.deepEqual(capture, original);
    assert.equal(Object.isFrozen(recovered), true);
    assert.equal(Object.isFrozen(recovered.fileObservations), true);
    assert.equal(Object.isFrozen(recovered.fileObservations[0]), true);
    assert.equal(recovered.fileObservations[0].size, Buffer.byteLength(prefix));
    assert.equal(
      capture.fileObservations[0].size,
      Buffer.byteLength(prefix + '{"partial":'),
    );
    assert.equal(truncations, 1);
    assert.equal(await journal.recover(directory, recovered), recovered);
    assert.equal(truncations, 1);
    assert.equal(await readFile(eventsPath, "utf8"), prefix);

    // Independently invoked appends also repair using their own returned value.
    await appendFile(eventsPath, '{"partial":');
    const appendCapture = await journal.loadSnapshot(directory, runId);
    const next = {
      ...latest,
      revision: latest.revision + 1,
      counters: { rounds: 2 },
    };
    await journal.appendTransition(directory, next, appendCapture, null);
    assert.equal(truncations, 2);
    assert.equal(appendCapture.hasPartialTail, true);
    const source = await readFile(eventsPath, "utf8");
    assert.equal(source.slice(0, prefix.length), prefix);
    assert.deepEqual(JSON.parse(source.slice(prefix.length)).state, next);
    assert.deepEqual(JSON.parse(await readFile(statePath, "utf8")), next);
    assert.match(
      await readFile(join(directory, "progress.md"), "utf8"),
      new RegExp(`Revision: ${next.revision}\\n`, "u"),
    );
  } finally {
    truncateMock.mock.restore();
  }
});

test("tail repair rejects changed original proof and unverified post-truncation evidence", async (t) => {
  for (const change of [
    "before-prefix",
    "before-namespace",
    "after-prefix",
    "after-namespace",
    "after-size",
  ]) {
    await t.test(change, async (t) => {
      const { created } = await fixture(t);
      const directory = created.directoryPath;
      const eventsPath = join(directory, "events.jsonl");
      const statePath = join(directory, "state.json");
      const progressPath = join(directory, "progress.md");
      const prefix = await readFile(eventsPath, "utf8");
      const state = await readFile(statePath, "utf8");
      const progress = await readFile(progressPath, "utf8");
      await appendFile(eventsPath, '{"partial":');
      const journal = createStateJournal({
        onTransitionBoundary: async () => {},
      });
      const capture = await journal.loadSnapshot(
        directory,
        created.state.runId,
      );
      const original = structuredClone(capture);
      const mutate = async () => {
        if (change.endsWith("prefix")) {
          const source = await readFile(eventsPath, "utf8");
          await writeFile(eventsPath, source.replace("IMPLEMENT", "CORRUPTED"));
        } else if (change.endsWith("namespace")) {
          await writeFile(join(directory, "events-000001.jsonl"), "");
        }
      };
      const handle = await open(eventsPath, "r");
      const prototype = Object.getPrototypeOf(handle);
      await handle.close();
      const nativeStat = prototype.stat;
      const nativeTruncate = prototype.truncate;
      const inode = (await stat(eventsPath)).ino;
      let truncations = 0;
      const truncateMock = t.mock.method(
        prototype,
        "truncate",
        async function (...args) {
          if ((await nativeStat.call(this)).ino !== inode)
            return nativeTruncate.apply(this, args);
          truncations += 1;
          if (change === "after-size") return;
          await nativeTruncate.apply(this, args);
          await mutate();
        },
      );
      try {
        if (change.startsWith("before")) await mutate();
        await assert.rejects(journal.recover(directory, capture), {
          code: "ERR_INVALID_EVENT_LOG",
        });
        assert.equal(truncations, change.startsWith("before") ? 0 : 1);
        assert.deepEqual(capture, original);
        assert.equal(capture.hasPartialTail, true);
        assert.equal(await readFile(statePath, "utf8"), state);
        assert.equal(await readFile(progressPath, "utf8"), progress);
        if (change.endsWith("size"))
          assert.equal(
            await readFile(eventsPath, "utf8"),
            prefix + '{"partial":',
          );
      } finally {
        truncateMock.mock.restore();
      }
    });
  }
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
  let published;
  await publishDuringStreams(
    t,
    join(created.directoryPath, "events-000010.jsonl"),
    [1],
    async () => {
      // Keep the capture oversized without another large event.
      published = await store.transitionRun(
        created.lease,
        {
          counters: { rounds: 2001 },
          pipelineState: { workflowState: "IMPLEMENT" },
        },
        { activity: concurrentActivity },
      );
    },
    { afterRead: true },
  );
  assert.equal(
    (await store.readPublicActivity(latest.runId, { limit: 1 })).cursor,
    1,
  );
  const tail = await store.readPublicActivity(latest.runId, {
    afterRevision: next.revision,
  });
  assert.deepEqual(pageEntries(tail), [
    { revision: published.revision, message: concurrentActivity.message },
  ]);
  assert.equal(tail.cursor, published.revision);
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

const concurrentActivity = {
  actor: "worker",
  phase: "implement",
  kind: "summary",
  message: "Candidate updated.",
};

function pageEntries(page) {
  return page.activities.map(({ revision, message }) => ({
    revision,
    message,
  }));
}

// Publish through the lease owner once each selected stream has taken its
// opening observation of the active segment, before it reads (or immediately
// after the selected read captures its bytes when afterRead is set). Loading a
// snapshot or an extension proof observes that segment twice, and each stream
// observes it when opening and closing, so the three bounded drains open at
// observations three, seven and eleven. Writer observations are excluded.
async function publishDuringStreams(
  t,
  path,
  openings,
  publish,
  { afterRead = false } = {},
) {
  const metadata = await stat(path, { bigint: true });
  const handle = await open(path, "r");
  const prototype = Object.getPrototypeOf(handle);
  await handle.close();
  const nativeStat = prototype.stat;
  const nativeRead = prototype.read;
  let observations = 0;
  let publishing = false;
  let stream = null;
  t.mock.method(prototype, "stat", async function (...args) {
    const observation = await nativeStat.apply(this, args);
    if (
      !publishing &&
      args[0]?.bigint &&
      observation.ino === metadata.ino &&
      openings.includes(++observations)
    )
      stream = this;
    return observation;
  });
  t.mock.method(prototype, "read", async function (...args) {
    if (this !== stream) return nativeRead.apply(this, args);
    // Claim the selected read before awaiting I/O.
    stream = null;
    const captured = afterRead ? await nativeRead.apply(this, args) : null;
    publishing = true;
    try {
      await publish();
    } finally {
      publishing = false;
    }
    return captured ?? nativeRead.apply(this, args);
  });
  return prototype;
}

function publishActivity(store, created, rounds) {
  return store.transitionRun(
    created.lease,
    { counters: { rounds } },
    { activity: concurrentActivity },
  );
}

async function readCanonicalFiles(directory) {
  const names = (await readdir(directory))
    .filter(
      (name) =>
        ["state.json", "progress.md"].includes(name) ||
        /^events(?:-[0-9]+)?\.jsonl$/u.test(name),
    )
    .sort();
  return Promise.all(
    names.map(async (name) => [
      name,
      await readFile(join(directory, name), "utf8"),
    ]),
  );
}

test("an unstable full scan retains its consumed prefix without granting mutation authority", async (t) => {
  const { store, created } = await fixture(t);
  const directory = created.directoryPath;
  const { runId } = created.state;
  const journal = createStateJournal({ onTransitionBoundary: async () => {} });
  let published;
  await publishDuringStreams(
    t,
    join(directory, "events.jsonl"),
    [1],
    async () => {
      published = await publishActivity(store, created, 1);
    },
    { afterRead: true },
  );
  const capture = await journal.loadSnapshot(directory, runId);
  assert.equal(capture.certificate, null);
  assert.equal(capture.capturedPrefix.lastRevision, 1);
  assert.deepEqual(capture.state, created.state);
  const original = structuredClone(capture);
  const decoded = eventDecodes(t);
  const extended = await journal.extendSnapshot(directory, capture);
  assert.deepEqual(decoded.normalized, [1, 2]);
  assert.deepEqual(extended.state, published);
  assert.ok(extended.certificate);
  const canonical = await Promise.all(
    ["events.jsonl", "state.json", "progress.md"].map((name) =>
      readFile(join(directory, name), "utf8"),
    ),
  );
  await assert.rejects(journal.recover(directory, capture), {
    code: "ERR_INVALID_EVENT_LOG",
  });
  await assert.rejects(
    journal.appendTransition(directory, published, capture, concurrentActivity),
    { code: "ERR_INVALID_EVENT_LOG" },
  );
  assert.deepEqual(capture, original);
  assert.deepEqual(
    await Promise.all(
      ["events.jsonl", "state.json", "progress.md"].map((name) =>
        readFile(join(directory, name), "utf8"),
      ),
    ),
    canonical,
  );
});

for (const mode of ["cold", "evicted"]) {
  test(`full-scan activity certification proves concurrent append with ${mode} checkpoints`, async (t) => {
    const { store, created, input, stateRoot } = await fixture(t);
    const { runId } = created.state;
    const observer = createRunStore({ stateRoot });
    if (mode === "evicted") {
      await observer.loadRun(runId);
      for (let index = 0; index < 8; index += 1) {
        const extra = await observer.createRun(input);
        await extra.lease.release();
      }
    }
    await publishDuringStreams(
      t,
      join(created.directoryPath, "events.jsonl"),
      [1],
      () => publishActivity(store, created, 1),
      { afterRead: true },
    );
    const page = await observer.readPublicActivity(runId);
    assert.deepEqual(pageEntries(page), [
      { revision: 1, message: "Run created." },
      { revision: 2, message: concurrentActivity.message },
    ]);
    assert.equal(page.cursor, 2);
  });
}

for (const mode of ["warm", "cold", "evicted", "overflow"]) {
  test(`activity certifies its consumed prefix through capture, recertification and extension publication: ${mode}`, async (t) => {
    const { store, created, input, stateRoot } = await fixture(t);
    const { runId } = created.state;
    const overflow = mode === "overflow";
    const base = overflow
      ? (await seedActivities({ created }, 1030, "Checkpoint recorded.")).latest
      : created.state;
    const observer = createRunStore({ stateRoot });
    if (["warm", "evicted"].includes(mode)) await observer.loadRun(runId);
    if (mode === "evicted") {
      for (let index = 0; index < 8; index += 1) {
        const extra = await observer.createRun(input);
        await extra.lease.release();
      }
    }
    const readCanonical = () => readCanonicalFiles(created.directoryPath);
    let publications = 0;
    let canonical;
    await publishDuringStreams(
      t,
      join(
        created.directoryPath,
        overflow ? "events-000010.jsonl" : "events.jsonl",
      ),
      mode === "warm" ? [3, 5] : [1, 3, 5],
      async () => {
        await publishActivity(
          store,
          created,
          (base.counters.rounds ?? 0) + ++publications,
        );
        canonical = await readCanonical();
      },
      { afterRead: true },
    );
    const page = await observer.readPublicActivity(runId, {
      limit: overflow ? 2 : 100,
    });
    assert.equal(publications, mode === "warm" ? 2 : 3);
    assert.deepEqual(
      pageEntries(page),
      overflow
        ? [
            { revision: 1, message: "Run created." },
            { revision: 2, message: "Checkpoint recorded." },
          ]
        : [
            { revision: 1, message: "Run created." },
            { revision: 2, message: concurrentActivity.message },
            { revision: 3, message: concurrentActivity.message },
          ].slice(0, mode === "warm" ? 2 : 3),
    );
    // The certified endpoint precedes the last publication. Its cursor must
    // match that prefix, rather than the newer canonical state or a lost page.
    assert.equal(page.cursor, overflow || mode === "warm" ? 2 : 3);
    assert.equal(
      (
        await observer.readPublicActivity(runId, {
          afterRevision: base.revision,
        })
      ).cursor,
      base.revision + publications,
    );
    assert.deepEqual(
      await readCanonical(),
      canonical,
      "observation writes nothing",
    );
  });
}

test("publication during recertification and extension consumes the existing observation bound", async (t) => {
  const { store, created, stateRoot } = await fixture(t);
  let publications = 0;
  let canonical;
  await publishDuringStreams(
    t,
    join(created.directoryPath, "events.jsonl"),
    [1, 3, 5, 9, 11, 15, 17],
    async () => {
      await publishActivity(store, created, ++publications);
      canonical = await readCanonicalFiles(created.directoryPath);
    },
    { afterRead: true },
  );
  const observer = createRunStore({ stateRoot });
  await assert.rejects(
    observer.readPublicActivity(created.state.runId),
    (error) => {
      assert.ok(error instanceof RunObservationBusyError);
      assert.equal(error.retryable, true);
      return true;
    },
  );
  assert.equal(publications, 7);
  assert.deepEqual(await readCanonicalFiles(created.directoryPath), canonical);
  assert.equal(
    (await observer.readPublicActivity(created.state.runId)).cursor,
    8,
  );
});

for (const change of [
  "original-bytes",
  "extension-bytes",
  "control",
  "link",
  "namespace",
  "sealed-tail",
]) {
  test(`raced recertification cannot certify changed ${change}`, async (t) => {
    const { store, created, stateRoot } = await fixture(t);
    const path = join(created.directoryPath, "events.jsonl");
    let publications = 0;
    let editCapturedExtension = false;
    eventDecodes(t, () => {
      if (!editCapturedExtension) return;
      editCapturedExtension = false;
      // The extension has already consumed and hashed these bytes, including
      // records beyond the original capture. Its final prefix proof must catch
      // this change even though the initial capture's bytes remain unchanged.
      const metadata = nativeFilesystem.statSync(path);
      const source = nativeFilesystem.readFileSync(path, "utf8");
      writeFileSync(
        path,
        source.replace(concurrentActivity.message, "Candidate changed."),
      );
      utimesSync(path, metadata.atime, metadata.mtime);
    });
    await publishDuringStreams(
      t,
      path,
      [1, 3, 5],
      async () => {
        const published = await publishActivity(store, created, ++publications);
        if (publications !== 3) return;
        if (change === "extension-bytes") {
          editCapturedExtension = true;
        } else if (change === "original-bytes") {
          const metadata = await stat(path);
          const source = await readFile(path, "utf8");
          await writeFile(path, source.replace("Run created.", "Run updated."));
          await utimes(path, metadata.atime, metadata.mtime);
        } else if (change === "control") {
          await filesystem.chmod(path, 0o400);
        } else if (change === "link") {
          await link(path, join(stateRoot, "linked-events"));
        } else if (change === "sealed-tail") {
          await appendFile(path, '{"partial":');
          const next = { ...published, revision: published.revision + 1 };
          await writeFile(
            join(created.directoryPath, "events-000001.jsonl"),
            `${JSON.stringify({
              schemaVersion: next.schemaVersion,
              revision: next.revision,
              runId: next.runId,
              recordedAt: next.updatedAt,
              state: next,
              activity: concurrentActivity,
            })}\n`,
          );
        } else {
          await copyFile(
            path,
            join(created.directoryPath, "events-000002.jsonl"),
          );
        }
      },
      { afterRead: true },
    );
    await assert.rejects(
      createRunStore({ stateRoot }).readPublicActivity(created.state.runId),
      {
        code: "ERR_INVALID_EVENT_LOG",
      },
    );
    assert.equal(publications, 3);
  });
}

for (const rotation of [false, true]) {
  test(`full-scan semantic validation retains proof through ${rotation ? "rotation" : "append"}`, async (t) => {
    const { created, stateRoot } = await fixture(t);
    const { runId } = created.state;
    const path = join(created.directoryPath, "events.jsonl");
    const original = await readFile(path, "utf8");
    const next = { ...created.state, revision: 2, counters: { rounds: 1 } };
    let published = false;
    eventDecodes(t, (event) => {
      if (event.revision !== 1 || published) return;
      published = true;
      const source = `${JSON.stringify({
        schemaVersion: next.schemaVersion,
        revision: 2,
        runId,
        recordedAt: next.updatedAt,
        state: next,
        activity: concurrentActivity,
      })}\n`;
      // Small legal segments expose namespace rollover without a 64 MiB file.
      writeFileSync(
        rotation ? join(created.directoryPath, "events-000001.jsonl") : path,
        rotation ? source : original + source,
      );
      writeFileSync(
        join(created.directoryPath, "state.json"),
        JSON.stringify(next),
      );
    });
    const observer = createRunStore({ stateRoot });
    const page = await observer.readPublicActivity(runId, { limit: 1 });
    assert.equal(published, true);
    assert.deepEqual(pageEntries(page), [
      { revision: 1, message: "Run created." },
    ]);
    assert.equal(page.cursor, 1);
    const tail = await observer.readPublicActivity(runId, { afterRevision: 1 });
    assert.deepEqual(pageEntries(tail), [
      { revision: 2, message: concurrentActivity.message },
    ]);
    assert.equal(tail.cursor, 2);
  });
}

for (const change of [
  "bytes",
  "advanced-bytes",
  "file",
  "directory",
  "namespace",
  "control",
]) {
  test(`canonical certification cannot replace a full scan's ${change} proof`, async (t) => {
    const { created, stateRoot } = await fixture(t);
    const directory = created.directoryPath;
    const path = join(directory, "events.jsonl");
    const original = await readFile(path, "utf8");
    const metadata = await stat(path);
    let changed = false;
    eventDecodes(t, () => {
      if (changed) return;
      changed = true;
      if (["bytes", "advanced-bytes"].includes(change)) {
        let source = original.replace("Run created.", "Run updated.");
        if (change === "advanced-bytes") {
          const next = { ...created.state, revision: 2 };
          source += `${JSON.stringify({
            schemaVersion: next.schemaVersion,
            revision: 2,
            runId: next.runId,
            recordedAt: next.updatedAt,
            state: next,
            activity: concurrentActivity,
          })}\n`;
          writeFileSync(join(directory, "state.json"), JSON.stringify(next));
        }
        writeFileSync(path, source);
        utimesSync(path, metadata.atime, metadata.mtime);
      } else if (change === "file") {
        copyFileSync(path, `${path}.replacement`);
        renameSync(`${path}.replacement`, path);
      } else if (change === "directory") {
        const prior = `${directory}.prior`;
        renameSync(directory, prior);
        mkdirSync(directory);
        for (const name of readdirSync(prior))
          renameSync(join(prior, name), join(directory, name));
      } else if (change === "namespace") {
        writeFileSync(join(directory, "events-000002.jsonl"), original);
      } else {
        nativeFilesystem.chmodSync(path, 0o400);
      }
    });
    await assert.rejects(
      createRunStore({ stateRoot }).readPublicActivity(created.state.runId),
      { code: "ERR_INVALID_EVENT_LOG" },
    );
    assert.equal(changed, true);
  });
}

for (const mode of [
  "new-warm",
  "held-cold",
  "new-evicted",
  "full-scan",
  "recertification",
]) {
  test(`MCP waits retain their activity proof through a second concurrent publication: ${mode}`, async (t) => {
    const { store, created, input, stateRoot } = await fixture(t, {
      pipelineId: "plan-authoring",
      runInput: {
        pipelineStateVersion: planAuthoringPipeline.stateVersion,
        roles: Object.fromEntries(
          planAuthoringPipeline.roles.map((role) => [
            role,
            { backend: "codex" },
          ]),
        ),
        pipelineState: createPlanAuthoringState(),
      },
    });
    const { runId } = created.state;
    const held = mode === "held-cold";
    const observer = createRunStore({ stateRoot });
    const wakeCompleted = Promise.withResolvers();
    let pageStore = observer;
    let publications = 0;
    let canonical;
    const readCanonical = () =>
      Promise.all(
        ["events.jsonl", "state.json", "progress.md"].map((name) =>
          readFile(join(created.directoryPath, name), "utf8"),
        ),
      );
    const reader = {
      ...observer,
      async readPublicActivity(...args) {
        if (held) await wakeCompleted.promise;
        if (["held-cold", "full-scan", "recertification"].includes(mode))
          pageStore = createRunStore({ stateRoot });
        if (mode === "new-evicted") {
          for (let index = 0; index < 8; index += 1) {
            const extra = await observer.createRun(input);
            await extra.lease.release();
          }
        }
        const recertification = mode === "recertification";
        const firstPage = publications === 0;
        if (firstPage)
          await publishDuringStreams(
            t,
            join(created.directoryPath, "events.jsonl"),
            recertification
              ? [1, 3, 5]
              : mode === "full-scan"
                ? [1, 7]
                : [3, 7],
            async () => {
              publications += 1;
              await store.transitionRun(
                created.lease,
                {
                  counters: { revisionRounds: publications + Number(held) },
                  ...(publications === (recertification ? 3 : 2)
                    ? {
                        pause: {
                          reason: "workspace_changed",
                          code: "ERR_WORKSPACE_DRIFT",
                        },
                        pipelineState: {
                          ...created.state.pipelineState,
                          workflowState: "WAITING_FOR_USER",
                        },
                      }
                    : {}),
                },
                { activity: concurrentActivity },
              );
              canonical = await readCanonical();
            },
            { afterRead: mode === "full-scan" || recertification },
          );
        const decoded = firstPage ? eventDecodes(t) : null;
        const page = await pageStore.readPublicActivity(...args);
        if (decoded)
          assert.equal(decoded.normalized.includes(1), mode !== "new-warm");
        return page;
      },
    };
    const control = createMcpControlPlane({
      runner: createRunner({ runStore: reader }),
      runStore: reader,
    });
    const watching = Promise.withResolvers();
    if (held) {
      const watch = nativeFilesystem.watch;
      t.mock.method(nativeFilesystem, "watch", (...args) => {
        const watcher = watch(...args);
        watching.resolve();
        return watcher;
      });
      syncBuiltinESMExports();
      t.after(() => {
        t.mock.restoreAll();
        syncBuiltinESMExports();
      });
    }
    const abort = new AbortController();
    const progress = [];
    const waiting = control.runWait(
      {
        runId,
        cursor: held ? 1 : 0,
        timeoutMs: held ? 10_000 : 0,
        progress: true,
      },
      {
        signal: abort.signal,
        progressToken: "wait-progress",
        notify: async ({ params }) => progress.push(params.progress),
      },
    );
    t.after(async () => {
      wakeCompleted.resolve();
      abort.abort();
      await waiting.catch(() => {});
    });
    if (held) {
      await Promise.race([watching.promise, waiting]);
      try {
        await store.transitionRun(
          created.lease,
          { counters: { revisionRounds: 1 } },
          { activity: concurrentActivity },
        );
      } finally {
        wakeCompleted.resolve();
      }
    }
    const waited = await waiting;
    const recertification = mode === "recertification";
    assert.equal(publications, recertification ? 3 : 2);
    assert.equal(waited.status, "WAITING_FOR_USER");
    assert.equal(waited.timedOut, false);
    assert.equal(waited.revision, held || recertification ? 4 : 3);
    assert.deepEqual(
      progress,
      held ? [2, 3, 4] : recertification ? [1, 2, 3, 4] : [1, 2, 3],
    );
    if (recertification) {
      const activity = await control.runActivity({
        runId,
        cursor: 0,
        limit: 100,
      });
      assert.deepEqual(
        activity.activities.map(({ revision }) => revision),
        [1, 2, 3, 4],
      );
      assert.equal(activity.cursor, waited.revision);
      let output = "";
      assert.equal(
        await main(["status", "--run", runId], {
          runner: createRunner({ runStore: createRunStore({ stateRoot }) }),
          stdout: {
            write: (chunk) => {
              output += chunk;
            },
          },
          stderr: { write: (chunk) => assert.fail(chunk) },
        }),
        0,
      );
      assert.match(output, /State: WAITING_FOR_USER/u);
    }
    assert.deepEqual(
      await readCanonical(),
      canonical,
      "observation writes nothing",
    );
  });
}

test("a retained activity page rereads once after a proven concurrent publication", async (t) => {
  const { store, created } = await fixture(t);
  const { runId } = created.state;
  await store.loadRun(runId);
  let published;
  await publishDuringStreams(
    t,
    join(created.directoryPath, "events.jsonl"),
    [3],
    async () => {
      published = await publishActivity(store, created, 1);
    },
  );
  const page = await store.readPublicActivity(runId);
  assert.equal(published.revision, 2);
  assert.deepEqual(pageEntries(page), [
    { revision: 1, message: "Run created." },
    { revision: 2, message: concurrentActivity.message },
  ]);
  assert.equal(page.cursor, 2);
});

test("an overflow activity stream rereads once after a proven concurrent publication", async (t) => {
  const { store, created, stateRoot } = await fixture(t);
  const { runId } = created.state;
  const { latest } = await seedActivities(
    { created },
    1030,
    "Checkpoint recorded.",
  );
  await store.loadRun(runId);
  const peer = createRunStore({ stateRoot });
  let published;
  await publishDuringStreams(
    t,
    join(created.directoryPath, "events-000010.jsonl"),
    [3],
    async () => {
      published = await publishActivity(
        store,
        created,
        latest.counters.rounds + 1,
      );
    },
  );
  const page = await peer.readPublicActivity(runId, { limit: 2 });
  assert.equal(published.revision, latest.revision + 1);
  assert.deepEqual(pageEntries(page), [
    { revision: 1, message: "Run created." },
    { revision: 2, message: "Checkpoint recorded." },
  ]);
  assert.equal(page.cursor, 2);
  const next = await peer.readPublicActivity(runId, {
    afterRevision: latest.revision,
  });
  assert.deepEqual(pageEntries(next), [
    { revision: published.revision, message: concurrentActivity.message },
  ]);
  assert.equal(next.cursor, published.revision);
});

for (const cold of [false, true]) {
  test(`proved publication exhaustion returns a retryable observation outcome after ${cold ? "full-scan" : "retained"} capture`, async (t) => {
    const { store, created, stateRoot } = await fixture(t);
    const { runId } = created.state;
    await store.loadRun(runId);
    let rounds = 0;
    await publishDuringStreams(
      t,
      join(created.directoryPath, "events.jsonl"),
      cold ? [1, 7, 11] : [3, 7, 11],
      async () => {
        rounds += 1;
        await publishActivity(store, created, rounds);
      },
      { afterRead: cold },
    );
    const observer = cold ? createRunStore({ stateRoot }) : store;
    await assert.rejects(observer.readPublicActivity(runId), (error) => {
      assert.ok(error instanceof RunObservationBusyError);
      assert.equal(error.code, "ERR_RUN_OBSERVATION_BUSY");
      assert.equal(error.retryable, true);
      return true;
    });
    assert.equal(rounds, 3, "each bounded drain observed a publication");
    assert.equal((await observer.readPublicActivity(runId)).cursor, 4);
  });
}

for (const interference of ["edited-prefix", "unavailable-proof"]) {
  test(`publication exhaustion cannot classify ${interference} as retryable`, async (t) => {
    const { store, created, stateRoot } = await fixture(t);
    const { runId } = created.state;
    const path = join(created.directoryPath, "events.jsonl");
    let publications = 0;
    await publishDuringStreams(t, path, [3, 7, 11], async () => {
      await publishActivity(store, created, ++publications);
      if (publications !== 3) return;
      if (interference === "unavailable-proof") {
        await link(path, join(stateRoot, "linked-events"));
      } else {
        const source = await readFile(path, "utf8");
        const metadata = await stat(path);
        await writeFile(path, source.replace("Run created.", "Run updated."));
        await utimes(path, metadata.atime, metadata.mtime);
        // A nested reader may cache different, semantically valid history.
        // It cannot replace this operation's original byte certificate.
        await store.loadRun(runId);
      }
    });
    await assert.rejects(store.readPublicActivity(runId), {
      code: "ERR_INVALID_EVENT_LOG",
    });
    assert.equal(publications, 3);
  });
}

test("a concurrent publication cannot certify a prefix edited in place", async (t) => {
  const { store, created } = await fixture(t);
  const { runId } = created.state;
  await store.loadRun(runId);
  const path = join(created.directoryPath, "events.jsonl");
  await publishDuringStreams(t, path, [3], async () => {
    await publishActivity(store, created, 1);
    const source = await readFile(path, "utf8");
    const metadata = await stat(path);
    await writeFile(path, source.replace("Run created.", "Run updated."));
    await utimes(path, metadata.atime, metadata.mtime);
  });
  await assert.rejects(store.readPublicActivity(runId), {
    code: "ERR_INVALID_EVENT_LOG",
    message: "Run changed during projection streaming.",
  });
});

// Only unavailable proof falls back to the original read error. Compatibility,
// validation, filesystem and programming failures found by the extension
// propagate unchanged.
for (const [name, interfere, expected] of [
  [
    "runtime version skew",
    ({ path, published }) =>
      writeFile(
        path,
        JSON.stringify({
          ...published,
          runtimeCompatibility: {
            ...published.runtimeCompatibility,
            runnerVersion: published.runtimeCompatibility.runnerVersion + 1,
          },
        }),
      ),
    { code: "ERR_RUNTIME_VERSION_SKEW" },
  ],
  [
    "malformed state",
    ({ path }) => writeFile(path, "{"),
    { code: "ERR_INVALID_RUN_STATE" },
  ],
  [
    "a hard-linked state file",
    ({ path, stateRoot }) => link(path, join(stateRoot, "linked-state")),
    { code: "ERR_UNSAFE_STATE_FILE" },
  ],
]) {
  test(`an extension failure from ${name} is not hidden by the original read error`, async (t) => {
    const { store, created, stateRoot } = await fixture(t);
    const { runId } = created.state;
    await store.loadRun(runId);
    await publishDuringStreams(
      t,
      join(created.directoryPath, "events.jsonl"),
      [3],
      async () =>
        interfere({
          path: join(created.directoryPath, "state.json"),
          published: await publishActivity(store, created, 1),
          stateRoot,
        }),
    );
    await assert.rejects(store.readPublicActivity(runId), expected);
  });
}

for (const failure of [
  Object.assign(new Error("Injected read failure."), { code: "EIO" }),
  new TypeError("Injected programming failure."),
]) {
  test(`an extension ${failure.code ?? failure.name} failure is not hidden by the original read error`, async (t) => {
    const { store, created } = await fixture(t);
    const { runId } = created.state;
    await store.loadRun(runId);
    let armed = false;
    const prototype = await publishDuringStreams(
      t,
      join(created.directoryPath, "events.jsonl"),
      [3],
      async () => {
        await publishActivity(store, created, 1);
        armed = true;
      },
    );
    const nativeReadFile = prototype.readFile;
    t.mock.method(prototype, "readFile", async function (...args) {
      if (!armed) return nativeReadFile.apply(this, args);
      armed = false;
      throw failure;
    });
    await assert.rejects(
      store.readPublicActivity(runId),
      (error) => error === failure,
    );
    assert.equal(armed, false, "the extension consumed the injected failure");
  });
}

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

const preparationSnapshot = createTrustedValidationSnapshot(
  {
    check: {
      command: "node required-check",
      executable: process.execPath,
      arguments: [
        "--eval",
        "throw new Error('configured check body must not run')",
      ],
    },
  },
  ["check"],
);
const preparationBindings = {
  commandIdentity: preparationSnapshot.commands[0].identity,
  commandFingerprint: preparationSnapshot.commandFingerprint,
  configurationFingerprint: preparationSnapshot.configurationFingerprint,
  contentFingerprint: "a".repeat(64),
};
const boundary = {
  capability: "verified-commit-v1",
  step: 1,
  completedCommits: 0,
  baselineHead: "a".repeat(40),
};

async function preparationFixture(t, options = {}) {
  const f = await fixture(t, options);
  f.current = await f.store.transitionRun(f.created.lease, {
    pipelineState: {
      ...f.created.state.pipelineState,
      trustedValidation: preparationSnapshot,
    },
  });
  f.reserve = () =>
    f.store.reservePreparation(f.created.lease, preparationBindings);
  f.proof = async () => {
    const identity = await readProcessIdentity(process.pid);
    return {
      processIdentity: identity,
      launchCutoff: identity,
      namespaceId: "pid:[1]",
      ancestryBaseline: null,
      controlGroup: null,
    };
  };
  f.attach = async (authority, canRelease = () => true) =>
    f.store.recordPreparationProcess(
      f.created.lease,
      authority,
      process.pid,
      await f.proof(),
      { canRelease },
    );
  f.retire = (authority) =>
    f.store.recordPreparationProcess(f.created.lease, authority, null);
  f.settle = () => f.store.settlePreparation(f.created.lease);
  f.recover = (retire) => f.store.recoverPreparation(f.created.lease, retire);
  f.saved = () => f.store.loadRun(f.current.runId);
  f.history = () => f.store.loadRunHistory(f.current.runId);
  f.stop = async (
    kind = "cancel_requested",
    timing = "immediate",
    expectedRevision,
  ) =>
    f.store.requestOperatorStop({
      runId: f.current.runId,
      kind,
      timing,
      expectedRevision: expectedRevision ?? (await f.saved()).revision,
      idempotencyKey: `${kind}-${timing}`,
    });
  return f;
}

test("preparation custody requires owner identity and namespace with optional historical proofs", async (t) => {
  const f = await preparationFixture(t);
  const proof = await f.proof();
  const authority = await f.reserve();
  for (const [change, code] of [
    [
      { processIdentity: null, launchCutoff: null },
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    ],
    [{ namespaceId: null }, "ERR_EXECUTION_PROCESS_UNVERIFIABLE"],
    [{ ancestryBaseline: [] }, "ERR_INVALID_RUN_STATE"],
    [{ controlGroup: "invalid" }, "ERR_INVALID_RUN_STATE"],
  ]) {
    f.proof = () => ({ ...proof, ...change });
    await assert.rejects(f.attach(authority), { code });
  }
  for (const historical of [false, true]) {
    f.proof = () => ({
      ...proof,
      ancestryBaseline: historical
        ? [{ ...proof.processIdentity, pid: process.pid }]
        : null,
      controlGroup: historical ? "a".repeat(64) : null,
    });
    const currentAuthority = historical ? await f.reserve() : authority;
    await f.attach(currentAuthority);
    await f.retire(currentAuthority);
    await f.settle();
    const cold = createRunStore({ stateRoot: f.stateRoot });
    const loaded = await cold.loadRun(f.current.runId);
    assert.equal(loaded.preparation, null);
  }
});

// Reuse the journal growth/rotation fixture and normalization counter above.
// Count actual bytes and hashing as well as expensive canonical publications.
for (const mode of [
  "cold",
  "warm",
  "evicted",
  "oversized",
  "polishing",
  "stopped",
  "interrupted-execution",
  "interrupted-polishing",
  "expired",
  "canceled",
  "canceled-before-attachment",
  "not-launched",
  "not-launched-async",
  "not-launched-canceled",
  "replaced-proof",
  "lost-admission",
  "queued-publication",
]) {
  test(`preparation custody: monitored ${mode} registration is independent of history publication`, async (t) => {
    const work = { bytes: 0, compact: 0, hashed: 0, publications: 0 };
    const registering = Promise.withResolvers(),
      release = Promise.withResolvers(),
      closed = Promise.withResolvers();
    let elapsed = 0;
    let launchClosed = false;
    let originalCustody;
    let base;
    let holdPublication = false;
    let attachmentPending = false;
    const controller = new AbortController();
    const interrupted = mode.startsWith("interrupted-");
    const notLaunched = mode.startsWith("not-launched");
    const blocked = notLaunched || ["stopped", "expired"].includes(mode);
    const tampering = ["replaced-proof", "lost-admission"].includes(mode);
    if (notLaunched) {
      const kill = ChildProcess.prototype.kill;
      t.mock.method(ChildProcess.prototype, "kill", function (...args) {
        // A regression must fail before a failed native handle can signal PID 0.
        assert.ok(Number.isSafeInteger(this.pid), "no process was created");
        return kill.apply(this, args);
      });
    }
    const f = await preparationFixture(t, {
      pipelineId: mode.includes("polishing") ? "polishing" : "plan-execution",
      resolveStopBoundary:
        mode === "queued-publication" ? () => boundary : null,
      async processIdentity(pid) {
        if (
          mode === "canceled-before-attachment" &&
          pid !== process.pid &&
          !attachmentPending
        ) {
          attachmentPending = true;
          registering.resolve();
          await release.promise;
        }
        return readProcessIdentity(pid);
      },
      async onTransitionBoundary(point) {
        work.publications++;
        if (holdPublication && point === "event-appended") {
          holdPublication = false;
          registering.resolve();
          await release.promise;
        }
      },
      async onPreparationBoundary({ phase, directory }) {
        if (mode === "canceled-before-attachment" && phase === "admitted")
          throw new Error("denied attachment interrupted");
        if (
          (mode === "replaced-proof" && phase === "attached") ||
          (mode === "lost-admission" && phase === "admitted")
        ) {
          const path = join(directory, ".preparation-custody.jsonl");
          originalCustody = await readFile(path, "utf8");
          const records = originalCustody.trimEnd().split("\n").map(JSON.parse);
          if (mode === "replaced-proof") records.at(-1).value.pid++;
          else records.pop();
          await writeFile(
            path,
            records.map((record) => JSON.stringify(record)).join("\n") + "\n",
          );
        }
        if (phase === "no-launch") {
          if (mode !== "not-launched") {
            assert.equal(launchClosed, true);
            assert.equal(child.pid, undefined);
          }
          samples.push({ ...work, normalizations: decodes.normalized.length });
        }
        if (phase !== "attached") return;
        if (interrupted) throw new Error("attachment interrupted");
        if (["expired", "canceled"].includes(mode)) {
          registering.resolve();
          await release.promise;
        }
      },
    });
    const seeded = await seedActivities(
      f,
      mode === "warm" ? 1030 : 105,
      "Preparation history.",
      f.current,
    );
    if (mode === "oversized")
      await f.store.transitionRun(f.created.lease, {
        pipelineState: {
          ...seeded.latest.pipelineState,
          records: Array(90).fill("x".repeat(100_000)),
        },
      });
    if (mode === "cold") {
      // A new store may not use the old store's live execution capability.
      await f.created.lease.release();
      f.store = createRunStore({
        stateRoot: f.stateRoot,
        onTransitionBoundary() {
          work.publications++;
        },
      });
      f.created = {
        ...f.created,
        lease: await f.store.acquireRunLease(f.current.runId),
      };
      t.after(() => f.created.lease.release().catch(() => {}));
    }
    if (mode === "evicted")
      for (let index = 0; index < 8; index++) {
        const extra = await f.store.createRun(f.input);
        await extra.lease.release();
      }
    const decodes = eventDecodes(t);
    const nativeOpen = filesystem.open;
    t.mock.method(filesystem, "open", async (path, ...args) => {
      const handle = await nativeOpen(path, ...args);
      const nativeRead = handle.read.bind(handle);
      t.mock.method(handle, "read", async (...values) => {
        const result = await nativeRead(...values);
        if (/events(?:-[0-9]+)?\.jsonl$/u.test(String(path)))
          work.bytes += result.bytesRead;
        else work.compact += result.bytesRead;
        return result;
      });
      return handle;
    });
    const nativeHash = crypto.createHash;
    t.mock.method(crypto, "createHash", (...args) => {
      const hash = nativeHash(...args),
        update = hash.update.bind(hash);
      hash.update = (value, ...rest) => {
        work.hashed += Buffer.byteLength(value);
        return update(value, ...rest);
      };
      return hash;
    });
    syncBuiltinESMExports();
    t.after(() => {
      t.mock.restoreAll();
      syncBuiltinESMExports();
    });
    const waiting = Promise.withResolvers();
    const monitor = createStopMonitor({
      runId: f.current.runId,
      lease: f.created.lease,
      publish: async () => {},
      runStore: {
        ...f.store,
        async waitForRunChange(_id, { signal }) {
          waiting.resolve();
          await new Promise((resolve) =>
            signal.aborted
              ? resolve()
              : signal.addEventListener("abort", resolve, { once: true }),
          );
          return f.current;
        },
      },
    });
    await waiting.promise;
    t.after(() => monitor.close());
    const samples = [];
    let proofBytes = 0,
      capturedProof,
      child;
    const service = createTrustedValidationService({
      git: {
        snapshot: async () => ({
          projectPath: f.input.projectPath,
          contentFingerprint: preparationBindings.contentFingerprint,
        }),
        assertUnchanged: async () => {},
      },
      sandboxCommand(command, settings) {
        const sandbox = sandboxTrustedCommand(command, {
          ...settings,
          bubblewrapPath: "/usr/bin/bwrap",
        });
        assert.deepEqual(sandbox.command.arguments.slice(-3), [
          process.execPath,
          "--eval",
          "",
        ]);
        assert.ok(
          !sandbox.command.arguments.includes(command.arguments.at(-1)),
        );
        // Controlled sandbox transport; retain the real inert supervisor and IPC.
        return {
          command: { executable: process.execPath, arguments: ["--eval", ""] },
          environment: process.env,
          ownershipMode: "native-sandbox-provider",
        };
      },
      async runCommand(command, settings) {
        if (mode === "stopped") await f.stop(); // Watcher remains deliberately delayed.
        let publication;
        if (mode === "queued-publication") {
          await f.stop("pause_requested", "after-current-commit");
          holdPublication = true;
          publication = monitor.persist(() =>
            f.store.recordStopActivity(f.created.lease, {
              actor: "runner",
              phase: "stop",
              kind: "stopping",
              message: "Publishing stop activity.",
            }),
          );
          void publication.catch(() => {});
          await registering.promise;
        }
        const before = { ...work, normalizations: decodes.normalized.length };
        base = process.hrtime.bigint();
        const result = await runExactCommand(command, {
          ...settings,
          monotonicNow: () => base + BigInt(elapsed) * 1_000_000n,
          spawnProcess(file, args, options) {
            if (mode === "not-launched") throw new Error("launch unavailable");
            child = spawnOwnedProcess(file, args, {
              ...options,
              resolveLauncher: (cwd, settings) =>
                notLaunched
                  ? {
                      file: join(f.input.projectPath, "missing-supervisor"),
                      arguments: [],
                      isolatedNamespace: false,
                    }
                  : resolveOwnedProcessLauncher(cwd, {
                      ...settings,
                      bubblewrap: process.execPath,
                      cache: new Map(),
                      namespaceId: "pid:[4026531836]",
                      probe: () => ({ status: 1 }),
                    }),
              onProcess: async (pid, proof, admission) => {
                if (pid === null) {
                  samples.push({
                    ...work,
                    normalizations: decodes.normalized.length,
                  });
                  if (mode === "queued-publication") release.resolve();
                } else {
                  proofBytes = Buffer.byteLength(JSON.stringify(proof));
                  capturedProof = structuredClone(proof);
                }
                return options.onProcess(pid, proof, admission);
              },
            });
            child.once("close", () => {
              launchClosed = true;
              closed.resolve();
            });
            if (mode === "not-launched-canceled")
              controller.abort(new Error("preparation canceled during spawn"));
            return child;
          },
        });
        await publication;
        assert.equal(result.status, blocked ? "BLOCKED" : "PASS");
        assert.equal(child?.ownedPayloadRequested ?? false, !blocked);
        assert.equal(samples[0].normalizations, before.normalizations);
        assert.equal(samples[0].publications, before.publications);
        assert.equal(
          samples[0].bytes,
          before.bytes,
          "registration reads no historical journal bytes",
        );
        assert.ok(samples[0].compact > before.compact);
        assert.ok(
          samples[0].hashed - before.hashed < proofBytes * 16 + 20_000,
          "compact hashing is bounded by the process proof",
        );
        assert.ok(
          work.publications > before.publications,
          "settlement publishes complete canonical evidence",
        );
        return result;
      },
    });
    const inspecting = inspectTrustedRequirements(
      {
        trustedValidation: service,
        runStore: f.store,
        lease: f.created.lease,
        run: f.current,
        monitor,
        checkConfiguration: async () => {},
        validatePersistedBoundary: async () => {},
        storageForbiddenPaths: () => [],
      },
      {
        inventory: [preparationSnapshot.commands[0].command],
        signal: controller.signal,
      },
    );
    void inspecting.catch(() => {});
    t.after(async () => {
      release.resolve();
      child?.kill("SIGKILL");
      await inspecting.catch(() => {});
    });
    if (["expired", "canceled", "canceled-before-attachment"].includes(mode)) {
      await registering.promise;
      if (mode === "expired") elapsed = 10_000;
      else controller.abort(new Error("preparation canceled"));
      if (mode === "canceled-before-attachment") {
        await closed.promise;
        assert.equal(await readProcessIdentity(child.ownedPid), null);
      }
      release.resolve();
    }
    if (
      interrupted ||
      mode === "canceled" ||
      mode === "canceled-before-attachment" ||
      tampering ||
      mode === "not-launched-canceled"
    ) {
      await assert.rejects(inspecting);
      if (mode === "canceled-before-attachment") {
        const records = (
          await readFile(
            join(f.created.directoryPath, ".preparation-custody.jsonl"),
            "utf8",
          )
        )
          .trimEnd()
          .split("\n")
          .map(JSON.parse);
        const attachment = records.find(({ kind }) => kind === "attached");
        assert.ok(
          attachment,
          "the exited supervisor's complete proof is retained",
        );
        const attached = attachment.value;
        assert.equal(attached.pid, child.ownedPid);
        for (const [name, value] of Object.entries(capturedProof))
          assert.deepEqual(attached[name], value);
        assert.equal(records.at(-1).kind, "admitted");
        assert.equal(records.at(-1).value, false);
        await assert.rejects(
          f.recover(async () => {
            throw new Error("retirement uncertain");
          }),
          /retirement uncertain/u,
        );
        assert.ok((await f.saved()).preparation);
        await assert.rejects(f.created.lease.release(), {
          code: "ERR_EXECUTION_PROCESS_ACTIVE",
        });
      }
      if (originalCustody !== undefined) {
        await assert.rejects(f.recover(assert.fail));
        assert.ok((await f.saved()).preparation);
        await writeFile(
          join(f.created.directoryPath, ".preparation-custody.jsonl"),
          originalCustody,
        );
      }
      if (mode === "not-launched-canceled")
        assert.equal((await f.saved()).preparation, null);
      else
        await f.recover((owner, inspect) =>
          terminateOwnedProcess(owner.pid, inspect),
        );
      assert.equal(child.ownedPayloadRequested, false);
    } else
      assert.equal((await inspecting).status, blocked ? "BLOCKED" : "READY");
    const saved = await f.saved();
    assert.equal(saved.preparation, null);
    assert.equal(saved.executionProcess, null);
    assert.deepEqual(saved.counters, seeded.latest.counters);
    const history = await f.store.loadRunHistory(saved.runId);
    const settled = history.events.filter(
      (event) => event.activity?.kind === "settled",
    );
    assert.equal(settled.length, 1);
    assert.deepEqual(
      settled[0].state.preparation.targetBoundary,
      mode === "queued-publication" ? boundary : null,
    );
    assert.equal(
      settled[0].state.preparation.settlement.records.at(-1).kind,
      notLaunched ? "no-launch" : "retired",
    );
    assert.ok(decodes.normalized.length > 0);
  });
}

for (const order of ["stop-first", "attach-first", "interrupted-acceptance"]) {
  test(
    `preparation custody: ${order} uses the same compact admission gate`,
    { timeout: 5000 },
    async (t) => {
      const entered = Promise.withResolvers(),
        release = Promise.withResolvers();
      let claims = 0;
      const operations = [];
      t.after(async () => {
        release.resolve();
        await Promise.allSettled(operations);
      });
      let interrupt = order === "interrupted-acceptance";
      const f = await preparationFixture(t, {
        onLeasePublicationBoundary({ filePath, phase }) {
          if (
            phase === "published" &&
            filePath.includes("/.custody-") &&
            ++claims === 3
          )
            release.resolve();
        },
        async onPreparationBoundary({ phase }) {
          if (
            order !== "interrupted-acceptance" &&
            phase === (order === "stop-first" ? "stop" : "attached")
          ) {
            entered.resolve();
            await release.promise;
          }
          if (phase === "stop" && interrupt) {
            interrupt = false;
            throw new Error("acceptance interrupted");
          }
        },
      });
      const authority = await f.reserve();
      if (interrupt) {
        await assert.rejects(f.stop(), /acceptance interrupted/u);
        assert.equal(await f.attach(authority), false);
      } else {
        const first = order === "attach-first" ? f.attach(authority) : f.stop();
        operations.push(first);
        await entered.promise;
        const second =
          order === "attach-first" ? f.stop() : f.attach(authority);
        operations.push(second);
        const results = await Promise.all(operations);
        assert.equal(
          claims,
          3,
          "the second caller contended at the held custody gate",
        );
        assert.equal(
          results[order === "attach-first" ? 0 : 1],
          order === "attach-first",
        );
      }
      const log = await readFile(
        join(f.created.directoryPath, ".preparation-custody.jsonl"),
        "utf8",
      );
      assert.ok(log.includes('"kind":"stop"'));
      await assert.rejects(f.created.lease.release(), {
        code:
          order === "interrupted-acceptance"
            ? "ERR_EXECUTION_PROCESS_ACTIVE"
            : "ERR_STOP_RECONCILIATION_REQUIRED",
      });
      await f.retire(authority);
      await f.settle();
      assert.equal((await f.saved()).preparation, null);
    },
  );
}

for (const target of [null, boundary, { ...boundary, step: 2 }]) {
  test(`preparation custody: explicit ${target === null ? "null" : target.step} target preserves deferred-stop rules`, async (t) => {
    let selected = target;
    const f = await preparationFixture(t, {
      resolveStopBoundary: () => selected,
    });
    const authority = await f.reserve();
    if (target === null) {
      await assert.rejects(f.stop("pause_requested", "after-current-commit"), {
        code: "ERR_STOP_BOUNDARY_UNSUPPORTED",
      });
      assert.equal(await f.attach(authority), true);
    } else {
      selected = boundary;
      await f.stop("pause_requested", "after-current-commit");
      assert.equal(await f.attach(authority), target.step === 1);
    }
    await f.retire(authority);
    await f.settle();
  });
}

test("preparation custody: cancellation cannot defer an immediate pause", async (t) => {
  const f = await preparationFixture(t, {
    resolveStopBoundary: () => boundary,
  });
  const authority = await f.reserve();
  await f.stop("pause_requested");
  const receipt = await f.stop("cancel_requested", "after-current-commit");
  assert.equal(receipt.effectiveTiming, "immediate");
  assert.equal(await f.attach(authority), false);
  await f.retire(authority);
  await f.settle();
});

test("preparation custody: admission rejects a hard link added after safe open", async (t) => {
  let armed = false;
  const f = await preparationFixture(t, {
    onPreparationBoundary({ phase }) {
      if (phase === "admitted") armed = true;
    },
  });
  const authority = await f.reserve();
  const path = join(f.created.directoryPath, ".preparation-custody.jsonl");
  const linked = join(f.stateRoot, "linked-custody");
  const inode = (await stat(path)).ino;
  const handle = await open(path, "r");
  const prototype = Object.getPrototypeOf(handle);
  await handle.close();
  const nativeStat = prototype.stat;
  t.mock.method(prototype, "stat", async function (...args) {
    const metadata = await nativeStat.apply(this, args);
    if (armed && args.length === 0 && metadata.ino === inode) {
      armed = false;
      await link(path, linked);
    }
    return metadata;
  });
  await assert.rejects(f.attach(authority), { code: "ERR_UNSAFE_STATE_FILE" });
  await rm(linked);
  await f.retire(authority);
  await f.settle();
});

test("preparation custody: competing interrupted stop acceptance preserves the recoverable log", async (t) => {
  let interrupt = true;
  const f = await preparationFixture(t, {
    onPreparationBoundary({ phase }) {
      if (phase === "stop" && interrupt) {
        interrupt = false;
        throw new Error("acceptance interrupted");
      }
    },
  });
  const authority = await f.reserve();
  await assert.rejects(f.stop("pause_requested"), /acceptance interrupted/u);
  const path = join(f.created.directoryPath, ".preparation-custody.jsonl");
  const source = await readFile(path, "utf8");
  await assert.rejects(f.stop(), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
  assert.equal(await readFile(path, "utf8"), source);
  assert.equal((await f.saved()).stopRequest, null);
  assert.equal(await f.attach(authority), false);
  await f.retire(authority);
  await f.settle();
});

test("preparation custody: other live reservations cannot evict a stop disposition's prefix proof", async (t) => {
  const f = await preparationFixture(t);
  const authority = await f.reserve();
  const path = join(f.created.directoryPath, ".preparation-custody.jsonl");
  const header = await readFile(path, "utf8");
  await f.stop();
  const stopped = await readFile(path, "utf8");
  const pending = [];
  for (let index = 0; index < 8; index++) {
    const created = await f.store.createRun({
      ...f.input,
      pipelineState: {
        ...f.input.pipelineState,
        trustedValidation: preparationSnapshot,
      },
    });
    t.after(() => created.lease.release().catch(() => {}));
    pending.push({
      lease: created.lease,
      authority: await f.store.reservePreparation(
        created.lease,
        preparationBindings,
      ),
    });
  }
  await writeFile(path, header);
  await assert.rejects(f.attach(authority), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
  await writeFile(path, stopped);
  const line = stopped.trimEnd().split("\n").at(-1);
  const duplicate = {
    ...JSON.parse(line),
    previous: crypto.createHash("sha256").update(line).digest("hex"),
  };
  await appendFile(path, JSON.stringify(duplicate) + "\n");
  await assert.rejects(f.attach(authority), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
  await writeFile(path, stopped);
  pending.push({ lease: f.created.lease, authority });
  for (const entry of pending) {
    await f.store.recordPreparationProcess(
      entry.lease,
      entry.authority,
      undefined,
    );
    await f.store.settlePreparation(entry.lease);
  }
});

for (const phase of [
  "attached",
  "admitted",
  "retired",
  "before-removal",
  "removed",
  "settlement-publication",
]) {
  test(`preparation custody: ${phase} interruption reconciles one exact endpoint`, async (t) => {
    let fail = true,
      settling = false;
    let originalLive = true;
    const identity = await readProcessIdentity(process.pid);
    const owners = {
      processIdentity: async () => identity,
      processIsAlive: (pid) => pid !== 41001 || originalLive,
    };
    const f = await preparationFixture(t, {
      ...owners,
      processId: 41001,
      onPreparationBoundary({ phase: point }) {
        if (point === phase && fail) {
          fail = false;
          throw new Error("custody interrupted");
        }
      },
      onTransitionBoundary(point) {
        if (
          phase === "settlement-publication" &&
          settling &&
          point === "event-appended" &&
          fail
        ) {
          fail = false;
          throw new Error("custody interrupted");
        }
      },
    });
    const authority = await f.reserve();
    if (["attached", "admitted"].includes(phase))
      await assert.rejects(f.attach(authority), /custody interrupted/u);
    else {
      assert.equal(await f.attach(authority), true);
      if (phase === "retired")
        await assert.rejects(f.retire(authority), /custody interrupted/u);
      else {
        await f.retire(authority);
        settling = true;
        await assert.rejects(f.settle(), /custody interrupted/u);
      }
    }
    originalLive = false;
    const replacement = createRunStore({
      stateRoot: f.stateRoot,
      ...owners,
      processId: 41002,
    });
    const lease = await replacement.acquireRunLease(f.current.runId);
    t.after(() => lease.release().catch(() => {}));
    const recover = (retire) => replacement.recoverPreparation(lease, retire);
    if (phase === "attached") {
      for (let attempt = 0; attempt < 18; attempt++)
        await assert.rejects(
          recover(async () => {
            throw new Error("retirement uncertain");
          }),
          /retirement uncertain/u,
        );
      const records = (
        await readFile(
          join(f.created.directoryPath, ".preparation-custody.jsonl"),
          "utf8",
        )
      )
        .trimEnd()
        .split("\n")
        .map(JSON.parse);
      assert.equal(records.filter(({ kind }) => kind === "revoked").length, 1);
    }
    let retirements = 0;
    const recovered = await recover(async (owner, inspect) => {
      retirements++;
      assert.equal(owner.pid, process.pid);
      assert.equal((await inspect()).status, "live");
      // State policy fixture: production supplies the existing tree retire proof.
    });
    assert.equal(recovered.preparation, null);
    assert.equal(retirements, ["attached", "admitted"].includes(phase) ? 1 : 0);
    assert.equal(
      (await f.history()).events.filter(
        (event) => event.activity?.kind === "settled",
      ).length,
      1,
    );
    assert.deepEqual(await recover(assert.fail), recovered);
  });
}

test("preparation custody: partial final records require the issued prefix and verified retirement", async (t) => {
  const f = await preparationFixture(t);
  const authority = await f.reserve();
  await f.attach(authority);
  const path = join(f.created.directoryPath, ".preparation-custody.jsonl");
  await appendFile(path, '{"kind":"ret');
  await assert.rejects(
    f.recover(async () => {
      throw new Error("retirement uncertain");
    }),
    /retirement uncertain/u,
  );
  assert.ok((await f.saved()).preparation);
  await f.recover(async () => {});
  assert.equal((await f.saved()).preparation, null);
});

for (const change of ["replacement", "tail-completion"]) {
  test(`preparation custody: tail repair rejects ${change} after inspection`, async (t) => {
    const f = await preparationFixture(t);
    const authority = await f.reserve();
    await f.attach(authority);
    const path = join(f.created.directoryPath, ".preparation-custody.jsonl");
    const prefix = await readFile(path, "utf8");
    const previous = crypto
      .createHash("sha256")
      .update(prefix.trimEnd().split("\n").at(-1))
      .digest("hex");
    const line = JSON.stringify({ kind: "revoked", value: null, previous });
    await appendFile(path, line.slice(0, -1));
    let changed;
    const nativeOpen = filesystem.open;
    const opened = t.mock.method(
      filesystem,
      "open",
      async (filePath, flags, ...args) => {
        if (
          changed === undefined &&
          ((filePath === path &&
            flags === (constants.O_RDWR | (constants.O_NOFOLLOW ?? 0))) ||
            (String(filePath).includes("..preparation-custody.jsonl.") &&
              flags === "wx"))
        ) {
          if (change === "replacement") {
            changed = await readFile(path, "utf8");
            await writeFile(path + ".replacement", changed);
            await rename(path + ".replacement", path);
          } else {
            await appendFile(path, "}\n");
            changed = await readFile(path, "utf8");
          }
        }
        return nativeOpen(filePath, flags, ...args);
      },
    );
    syncBuiltinESMExports();
    t.after(() => {
      opened.mock.restore();
      syncBuiltinESMExports();
    });
    let retirements = 0;
    const retire = async () => {
      retirements++;
    };
    await assert.rejects(f.recover(retire), { code: "ERR_INVALID_EVENT_LOG" });
    assert.equal(retirements, 1);
    assert.equal(await readFile(path, "utf8"), changed);
    assert.equal((await f.saved()).preparation.settlement, null);
    await assert.rejects(f.created.lease.release(), {
      code: "ERR_EXECUTION_PROCESS_ACTIVE",
    });
    await f.recover(retire);
    const settled = (await f.history()).events.filter(
      (event) => event.activity?.kind === "settled",
    );
    assert.equal(settled.length, 1);
    const records = settled[0].state.preparation.settlement.records;
    assert.equal(records.at(-1).kind, "retired");
    assert.equal(
      records.some((record) => record.kind === "revoked"),
      change === "tail-completion",
    );
    assert.equal((await f.saved()).preparation, null);
  });
}

test("preparation custody: settlement rechecks the exact log endpoint before removal", async (t) => {
  let original;
  const f = await preparationFixture(t, {
    async onPreparationBoundary({ phase, directory }) {
      if (phase !== "before-removal") return;
      const path = join(directory, ".preparation-custody.jsonl");
      original = await readFile(path, "utf8");
      await appendFile(path, "{");
    },
  });
  const authority = await f.reserve();
  await f.attach(authority);
  await f.retire(authority);
  await assert.rejects(f.settle(), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
  const path = join(f.created.directoryPath, ".preparation-custody.jsonl");
  assert.equal(await readFile(path, "utf8"), original + "{");
  assert.ok((await f.saved()).preparation.settlement);
  await assert.rejects(f.created.lease.release(), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
});

test("preparation custody: missing registration and changed original history retain ownership", async (t) => {
  const f = await preparationFixture(t);
  await f.reserve();
  await assert.rejects(f.recover(assert.fail), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
  const path = join(f.created.directoryPath, "events.jsonl");
  const source = await readFile(path, "utf8");
  await writeFile(path, source.replace('"model":"base"', '"model":"next"'));
  await assert.rejects(f.recover(assert.fail));
  await assert.rejects(f.created.lease.release());
});

test("preparation custody: cold rollback cannot hide an unmerged custody log", async (t) => {
  const f = await preparationFixture(t);
  const eventsPath = join(f.created.directoryPath, "events.jsonl");
  const statePath = join(f.created.directoryPath, "state.json");
  const beforeEvents = await readFile(eventsPath, "utf8");
  const beforeState = await readFile(statePath, "utf8");
  const authority = await f.reserve();
  await f.attach(authority);
  const reservedEvents = await readFile(eventsPath, "utf8");
  const reservedState = await readFile(statePath, "utf8");
  const custodyPath = join(
    f.created.directoryPath,
    ".preparation-custody.jsonl",
  );
  const custody = await readFile(custodyPath, "utf8");
  await writeFile(eventsPath, beforeEvents);
  await writeFile(statePath, beforeState);
  const replacement = createRunStore({ stateRoot: f.stateRoot });
  for (const inspect of [
    () => replacement.loadRun(f.current.runId),
    () => replacement.runIsLeased(f.current.runId),
    () => replacement.acquireRunLease(f.current.runId),
  ])
    await assert.rejects(inspect(), {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
  assert.equal(await readFile(custodyPath, "utf8"), custody);
  assert.equal(await readFile(eventsPath, "utf8"), beforeEvents);
  assert.equal(await readFile(statePath, "utf8"), beforeState);
  await writeFile(eventsPath, reservedEvents);
  await writeFile(statePath, reservedState);
  await f.retire(authority);
  await f.settle();
});

for (const settled of [false, true]) {
  test(`preparation custody: lock-free reads reconcile concurrent ${settled ? "settlement" : "reservation"}`, async (t) => {
    const f = await preparationFixture(t);
    const nativeStat = filesystem.lstat;
    const path = join(f.created.directoryPath, ".preparation-custody.jsonl");
    let authority;
    let armed = true;
    t.mock.method(filesystem, "lstat", async (filePath, ...args) => {
      if (!armed || filePath !== path) return nativeStat(filePath, ...args);
      armed = false;
      authority = await f.reserve();
      const metadata = await nativeStat(filePath, ...args);
      if (settled) {
        await f.store.recordPreparationProcess(
          f.created.lease,
          authority,
          undefined,
        );
        await f.settle();
      }
      return metadata;
    });
    syncBuiltinESMExports();
    t.after(() => {
      t.mock.restoreAll();
      syncBuiltinESMExports();
    });
    const read = await f.saved();
    assert.equal(read.preparation?.id ?? null, settled ? null : authority.id);
    if (!settled) {
      await f.store.recordPreparationProcess(
        f.created.lease,
        authority,
        undefined,
      );
      await f.settle();
    }
  });
}

test("preparation custody: cold canonical replay rejects clearing without settlement", async (t) => {
  const f = await preparationFixture(t);
  const authority = await f.reserve();
  await f.attach(authority);
  await f.retire(authority);
  await f.settle();
  const path = join(f.created.directoryPath, "events.jsonl");
  const events = (await readFile(path, "utf8"))
    .trimEnd()
    .split("\n")
    .map(JSON.parse);
  events.find(
    ({ activity }) => activity?.kind === "settled",
  ).state.preparation = null;
  await writeFile(path, events.map(JSON.stringify).join("\n") + "\n");
  const replacement = createRunStore({ stateRoot: f.stateRoot });
  await assert.rejects(replacement.loadRun(f.current.runId), {
    code: "ERR_INVALID_EVENT_LOG",
  });
});

test("preparation custody: replacement owner cannot reuse a live issuer's release capability", async (t) => {
  let originalLive = true;
  const identity = await readProcessIdentity(process.pid);
  const options = {
    processId: 41001,
    processIdentity: async () => identity,
    processIsAlive: (pid) => pid !== 41001 || originalLive,
  };
  const f = await preparationFixture(t, options);
  const authority = await f.reserve();
  await f.attach(authority);
  originalLive = false;
  const replacement = createRunStore({
    stateRoot: f.stateRoot,
    ...options,
    processId: 41002,
  });
  const lease = await replacement.acquireRunLease(f.current.runId);
  t.after(() => lease.release().catch(() => {}));
  await assert.rejects(f.attach(authority), { code: "ERR_INVALID_RUN_LEASE" });
  await assert.rejects(
    replacement.recordPreparationProcess(
      lease,
      authority,
      process.pid,
      await f.proof(),
      { canRelease: () => true },
    ),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );
  await replacement.recoverPreparation(lease, async (owner) =>
    assert.equal(owner.pid, process.pid),
  );
  assert.equal((await replacement.loadRun(f.current.runId)).preparation, null);
});

for (const publication of [
  "event-appended",
  "state-replaced",
  "progress-replaced",
]) {
  test(`preparation custody: interrupted reservation ${publication} never issues launch authority`, async (t) => {
    let fail = false;
    const f = await preparationFixture(t, {
      onTransitionBoundary(point) {
        if (fail && point === publication) {
          fail = false;
          throw new Error("reservation interrupted");
        }
      },
    });
    fail = true;
    await assert.rejects(f.reserve(), /reservation interrupted/u);
    assert.ok((await f.saved()).preparation);
    await assert.rejects(f.recover(assert.fail));
    await assert.rejects(f.created.lease.release(), {
      code: "ERR_EXECUTION_PROCESS_ACTIVE",
    });
  });
}
