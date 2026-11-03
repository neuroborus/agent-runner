import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createWorkspaceService } from "../../src/workspace/index.js";

async function fixture(t, fileSystem = fs, beforePublish = async () => {}) {
  const root = await fs.mkdtemp(join(tmpdir(), "workspace-output-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const workspacePath = join(root, "project");
  await fs.mkdir(workspacePath);
  await fs.mkdir(join(root, "state"), { mode: 0o700 });
  const path = join(workspacePath, "reports");
  const workspace = createWorkspaceService({ fileSystem });
  const service = {
    ...workspace,
    prepareOutputDirectory: (request) =>
      workspace.prepareOutputDirectory({
        publishDirectory: async ({
          sourceParent,
          sourceName,
          destinationParent,
          destinationName,
        }) => {
          await beforePublish();
          const source = `/proc/self/fd/${sourceParent}/${sourceName}`;
          const destination = `/proc/self/fd/${destinationParent}/${destinationName}`;
          if (
            await fs.lstat(destination).catch((cause) => {
              if (cause.code !== "ENOENT") throw cause;
              return null;
            })
          )
            return;
          await fileSystem.rename(source, destination);
        },
        ...request,
      }),
  };
  const inspection = await service.inspect({
    workspacePath,
    stateRoot: join(root, "state"),
    outputPaths: [path],
  });
  return { root, workspacePath, path, service, inspection };
}

test("output preparation creates only a declared directory and preserves existing content", async (t) => {
  const f = await fixture(t);
  const before = await f.service.snapshot({ inspection: f.inspection });
  const intent = await f.service.inspectOutputDirectory({
    inspection: f.inspection,
    path: f.path,
  });
  assert.equal(intent.before.exists, false);
  await assert.rejects(fs.stat(f.path), { code: "ENOENT" });
  const prepared = await f.service.prepareOutputDirectory({
    inspection: f.inspection,
    intent,
  });
  assert.equal(prepared.kind, "directory");
  f.service.assertUnchanged({
    before,
    after: await f.service.snapshot({ inspection: f.inspection }),
    allowOutputs: true,
  });
  await fs.writeFile(join(f.path, "existing.md"), "preserve\n");
  const existing = await f.service.inspectOutputDirectory({
    inspection: f.inspection,
    path: f.path,
  });
  assert.deepEqual(
    await f.service.prepareOutputDirectory({
      inspection: f.inspection,
      intent: existing,
    }),
    prepared,
  );
  assert.equal(
    await fs.readFile(join(f.path, "existing.md"), "utf8"),
    "preserve\n",
  );
  await assert.rejects(
    f.service.inspectOutputDirectory({
      inspection: f.inspection,
      path: f.workspacePath,
    }),
    { code: "ERR_WORKSPACE_PATH" },
  );
});

test("possibly completed directory creation cannot be adopted or retried from its absent intent", async (t) => {
  const f = await fixture(t);
  const intent = await f.service.inspectOutputDirectory({
    inspection: f.inspection,
    path: f.path,
  });
  await fs.mkdir(f.path);
  await fs.writeFile(join(f.path, "other.md"), "retain ambiguity\n");
  await assert.rejects(
    f.service.prepareOutputDirectory({ inspection: f.inspection, intent }),
    { code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS" },
  );
  assert.equal(
    await fs.readFile(join(f.path, "other.md"), "utf8"),
    "retain ambiguity\n",
  );
});

for (const content of [false, true]) {
  test(`a newly published root replaced before inspection preserves its ${content ? "nonempty" : "empty"} replacement`, async (t) => {
    let replace;
    const f = await fixture(t, {
      ...fs,
      async mkdir(path, options) {
        const result = await fs.mkdir(path, options);
        if (replace && path.endsWith("/reports")) await replace();
        return result;
      },
      async rename(source, destination) {
        await fs.rename(source, destination);
        if (replace && destination.endsWith("/reports")) await replace();
      },
    });
    const intent = await f.service.inspectOutputDirectory({
      inspection: f.inspection,
      path: f.path,
    });
    replace = async () => {
      replace = null;
      await fs.rename(f.path, `${f.path}-created`);
      await fs.mkdir(f.path, { mode: 0o700 });
      if (content)
        await fs.writeFile(
          join(f.path, "unrelated.md"),
          "preserve replacement\n",
        );
    };
    await assert.rejects(
      f.service.prepareOutputDirectory({ inspection: f.inspection, intent }),
      { code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS" },
    );
    if (content)
      assert.equal(
        await fs.readFile(join(f.path, "unrelated.md"), "utf8"),
        "preserve replacement\n",
      );
    else assert.deepEqual(await fs.readdir(f.path), []);
  });
}

test("an empty root appearing immediately before publication retains its identity", async (t) => {
  let appear;
  const f = await fixture(t, fs, async () => appear?.());
  const intent = await f.service.inspectOutputDirectory({
    inspection: f.inspection,
    path: f.path,
  });
  let identity;
  appear = async () => {
    appear = null;
    await fs.mkdir(f.path);
    identity = (await fs.stat(f.path, { bigint: true })).ino;
  };
  await assert.rejects(
    f.service.prepareOutputDirectory({ inspection: f.inspection, intent }),
    { code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS" },
  );
  assert.equal((await fs.stat(f.path, { bigint: true })).ino, identity);
  assert.deepEqual(await fs.readdir(f.path), []);
  assert.deepEqual(await fs.readdir(f.workspacePath), ["reports"]);
});

test("owner loss during publication leaves only the declared root and cannot replay preparation", async (t) => {
  let interrupt = false;
  const f = await fixture(t, {
    ...fs,
    async rename(source, destination) {
      await fs.rename(source, destination);
      if (interrupt && destination.endsWith("/reports"))
        throw new Error("Lost owner before identity publication");
    },
  });
  const before = await f.service.snapshot({ inspection: f.inspection });
  const intent = await f.service.inspectOutputDirectory({
    inspection: f.inspection,
    path: f.path,
  });
  interrupt = true;
  await assert.rejects(
    f.service.prepareOutputDirectory({ inspection: f.inspection, intent }),
  );
  assert.deepEqual(await fs.readdir(f.workspacePath), ["reports"]);
  const identity = (await fs.stat(f.path, { bigint: true })).ino;
  f.service.assertUnchanged({
    before,
    after: await f.service.snapshot({ inspection: f.inspection }),
    allowOutputs: true,
  });
  interrupt = false;
  await assert.rejects(
    f.service.prepareOutputDirectory({ inspection: f.inspection, intent }),
    { code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS" },
  );
  assert.equal((await fs.stat(f.path, { bigint: true })).ino, identity);
});

test("missing parents and aliased or substituted roots never expand mount authority", async (t) => {
  const f = await fixture(t);
  const path = join(f.workspacePath, "absent", "reports");
  const inspection = await f.service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: join(f.root, "state"),
    outputPaths: [path],
  });
  await assert.rejects(f.service.inspectOutputDirectory({ inspection, path }));
  await assert.rejects(fs.stat(join(f.workspacePath, "absent")), {
    code: "ENOENT",
  });
  await fs.mkdir(f.path);
  const intent = await f.service.inspectOutputDirectory({
    inspection: f.inspection,
    path: f.path,
  });
  await fs.rename(f.path, `${f.path}-original`);
  await fs.mkdir(f.path);
  await assert.rejects(
    f.service.prepareOutputDirectory({ inspection: f.inspection, intent }),
    { code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS" },
  );
  await fs.rm(f.path, { recursive: true });
  await fs.symlink(`${f.path}-original`, f.path);
  await assert.rejects(
    f.service.inspectOutputDirectory({
      inspection: f.inspection,
      path: f.path,
    }),
  );
});

test("parent replacement during creation cannot redirect a prepared output into another tree", async (t) => {
  let redirect;
  const f = await fixture(t, {
    ...fs,
    async rename(source, destination) {
      if (redirect && destination.endsWith("/reports")) await redirect();
      return fs.rename(source, destination);
    },
  });
  const intent = await f.service.inspectOutputDirectory({
    inspection: f.inspection,
    path: f.path,
  });
  const outside = join(f.root, "unrelated");
  await fs.mkdir(outside);
  redirect = async () => {
    redirect = null;
    await fs.rename(f.workspacePath, `${f.workspacePath}-retired`);
    await fs.symlink(outside, f.workspacePath);
  };
  await assert.rejects(
    f.service.prepareOutputDirectory({ inspection: f.inspection, intent }),
  );
  await assert.rejects(fs.stat(join(outside, "reports")), { code: "ENOENT" });
  // Creation stays anchored to the old parent. Its unrecorded identity remains
  // preserved there rather than being deleted after the parent's replacement.
  assert.deepEqual(await fs.readdir(`${f.workspacePath}-retired`), ["reports"]);
});
