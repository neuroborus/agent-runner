import assert from "node:assert/strict";
import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createPlanProgressPublisher,
  publishPlanProgress,
} from "../src/runner/plan-progress.js";

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "plan-progress-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const taskPath = join(root, "task");
  await mkdir(taskPath);
  const run = {
    runId: "11111111-1111-4111-8111-111111111111",
    revision: 1,
    pipelineState: {},
    taskPath,
    projectPath: root,
  };
  const marker = `<!-- agent-runner plan-progress ${run.runId} -->\n`;
  const artifact = {
    path: join(taskPath, "plan.progress.md"),
    content: `${marker}Accepted revision 1; pending.\n`,
  };
  const git = {
    async inspectPath() {
      return { tracked: false, ignored: true };
    },
  };
  return { root, run, marker, artifact, git };
}

test("overlapping publications serialize per run and older snapshots cannot replace newer progress", async (t) => {
  const f = await fixture(t);
  const paused = Promise.withResolvers();
  const release = Promise.withResolvers();
  t.after(() => release.resolve());
  let inspections = 0;
  const publish = createPlanProgressPublisher({
    git: {
      async inspectPath() {
        if (++inspections === 3) {
          paused.resolve();
          await release.promise;
        }
        return { tracked: false, ignored: true };
      },
    },
  });
  const older = publish(f.run, f.artifact);
  await paused.promise;
  const next = { ...f.artifact, content: `${f.marker}Verified completion.\n` };
  const newer = publish({ ...f.run, revision: 2 }, next);
  release.resolve();
  await Promise.all([older, newer]);
  assert.equal(await readFile(f.artifact.path, "utf8"), next.content);
  const before = inspections;
  await publish(f.run, f.artifact);
  assert.equal(inspections, before);
  assert.equal(await readFile(f.artifact.path, "utf8"), next.content);
  assert.deepEqual(await readdir(f.run.taskPath), ["plan.progress.md"]);
});

test("publication failure permits same-revision regeneration and consumed commits defer writes", async (t) => {
  const f = await fixture(t);
  let interrupted = false;
  const publish = createPlanProgressPublisher({
    git: {
      async inspectPath() {
        if (!interrupted) {
          interrupted = true;
          throw new Error("Interrupted publication");
        }
        return { tracked: false, ignored: true };
      },
    },
  });
  await assert.rejects(publish(f.run, f.artifact), {
    code: "ERR_PLAN_PROGRESS_PUBLICATION",
  });
  await publish(f.run, f.artifact);
  const consumed = {
    ...f.run,
    revision: 2,
    pipelineState: { pendingCommit: { status: "consumed" } },
  };
  const next = { ...f.artifact, content: `${f.marker}Verified completion.\n` };
  await publish(consumed, next);
  assert.equal(await readFile(f.artifact.path, "utf8"), f.artifact.content);
  await publish({ ...f.run, revision: 3 }, next);
  assert.equal(await readFile(f.artifact.path, "utf8"), next.content);
});

test("derived publication repairs stale/missing files after interruption without reading Markdown as authority", async (t) => {
  const f = await fixture(t);
  await publishPlanProgress(f.run, f.artifact, f.git);
  const authoritative = structuredClone(f.run);
  await writeFile(
    f.artifact.path,
    `${f.marker}Manual claims: accepted revision 99; completed; replay COMMIT.\n`,
  );
  let inspections = 0;
  const interrupted = {
    async inspectPath() {
      if (++inspections === 3)
        throw new Error("Interrupted before replacement");
      return { tracked: false, ignored: true };
    },
  };
  await assert.rejects(publishPlanProgress(f.run, f.artifact, interrupted), {
    code: "ERR_PLAN_PROGRESS_PUBLICATION",
  });
  assert.match(await readFile(f.artifact.path, "utf8"), /Manual claims/u);
  assert.deepEqual(await readdir(f.run.taskPath), ["plan.progress.md"]);
  await publishPlanProgress(f.run, f.artifact, f.git);
  assert.equal(await readFile(f.artifact.path, "utf8"), f.artifact.content);
  await rm(f.artifact.path);
  await publishPlanProgress(f.run, f.artifact, f.git);
  assert.equal(await readFile(f.artifact.path, "utf8"), f.artifact.content);
  assert.deepEqual(f.run, authoritative);
});

test("progress refuses unowned files, links, escaping parents and nonignored or tracked destinations", async (t) => {
  const f = await fixture(t);
  const refuse = () =>
    assert.rejects(publishPlanProgress(f.run, f.artifact, f.git), {
      code: "ERR_PLAN_PROGRESS_PUBLICATION",
    });
  await writeFile(f.artifact.path, "User notes\n");
  await refuse();
  assert.equal(await readFile(f.artifact.path, "utf8"), "User notes\n");
  await rm(f.artifact.path);
  const other = join(f.root, "other.md");
  await writeFile(other, f.artifact.content);
  await symlink(other, f.artifact.path);
  await refuse();
  await rm(f.artifact.path);
  await link(other, f.artifact.path);
  await refuse();
  await rm(f.artifact.path);
  await mkdir(f.artifact.path);
  await refuse();
  await rm(f.artifact.path, { recursive: true });
  for (const inspected of [
    { tracked: true, ignored: true },
    { tracked: false, ignored: false },
  ])
    await assert.rejects(
      publishPlanProgress(f.run, f.artifact, {
        async inspectPath() {
          return inspected;
        },
      }),
      { code: "ERR_PLAN_PROGRESS_PUBLICATION" },
    );
  await assert.rejects(readFile(f.artifact.path), { code: "ENOENT" });
  await publishPlanProgress(f.run, f.artifact, f.git);
  for (const inspected of [
    { tracked: true, ignored: true },
    { tracked: false, ignored: false },
  ])
    await assert.rejects(
      publishPlanProgress(f.run, f.artifact, {
        async inspectPath() {
          return inspected;
        },
      }),
      { code: "ERR_PLAN_PROGRESS_PUBLICATION" },
    );
  await assert.rejects(
    publishPlanProgress(
      { ...f.run, runId: "22222222-2222-4222-8222-222222222222" },
      {
        ...f.artifact,
        content: f.artifact.content.replace(
          f.run.runId,
          "22222222-2222-4222-8222-222222222222",
        ),
      },
      f.git,
    ),
    { code: "ERR_PLAN_PROGRESS_PUBLICATION" },
  );
  const alias = join(f.root, "alias");
  await symlink(f.run.taskPath, alias);
  await assert.rejects(
    publishPlanProgress(
      { ...f.run, taskPath: alias },
      { ...f.artifact, path: join(alias, "plan.progress.md") },
      f.git,
    ),
    { code: "ERR_PLAN_PROGRESS_PUBLICATION" },
  );
  assert.equal(await readFile(other, "utf8"), f.artifact.content);
});

test("publication rechecks the destination and requires ignored temporary paths", async (t) => {
  const f = await fixture(t);
  await publishPlanProgress(f.run, f.artifact, f.git);
  const next = { ...f.artifact, content: `${f.marker}Accepted revision 2.\n` };
  const concurrent = `${f.marker}Concurrent edit.\n`;
  let inspections = 0;
  await assert.rejects(
    publishPlanProgress(f.run, next, {
      async inspectPath() {
        if (++inspections === 3) await writeFile(f.artifact.path, concurrent);
        return { tracked: false, ignored: true };
      },
    }),
    { code: "ERR_PLAN_PROGRESS_PUBLICATION" },
  );
  assert.equal(await readFile(f.artifact.path, "utf8"), concurrent);
  await assert.rejects(
    publishPlanProgress(f.run, next, {
      async inspectPath({ path }) {
        return { tracked: false, ignored: path === f.artifact.path };
      },
    }),
    { code: "ERR_PLAN_PROGRESS_PUBLICATION" },
  );
  assert.deepEqual(await readdir(f.run.taskPath), ["plan.progress.md"]);
});

test("ancestor substitution during ignore checks cannot redirect publication or temporary cleanup", async (t) => {
  for (const substituteAt of [2, 3]) {
    const f = await fixture(t);
    const parent = join(f.root, "parent");
    const moved = join(f.root, "moved");
    const outside = join(f.root, "outside");
    await mkdir(parent);
    await rename(f.run.taskPath, join(parent, "task"));
    f.run.taskPath = join(parent, "task");
    f.artifact.path = join(f.run.taskPath, "plan.progress.md");
    await mkdir(join(outside, "task"), { recursive: true });
    let inspections = 0;
    await assert.rejects(
      publishPlanProgress(f.run, f.artifact, {
        async inspectPath() {
          if (++inspections === substituteAt) {
            await rename(parent, moved);
            await symlink(outside, parent);
          }
          return { tracked: false, ignored: true };
        },
      }),
      { code: "ERR_PLAN_PROGRESS_PUBLICATION" },
    );
    assert.deepEqual(await readdir(join(outside, "task")), []);
    assert.deepEqual(await readdir(join(moved, "task")), []);
  }
});
