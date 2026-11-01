import assert from "node:assert/strict";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import {
  prepareRuntime,
  resolveRuntimeRoot,
  RUNTIME_PAYLOAD_ENV,
} from "../src/runtime/index.js";
import { runtimeFixture } from "./support/index.js";

test("runtime storage uses separate deterministic user locations", () => {
  assert.equal(
    resolveRuntimeRoot({
      env: { HOME: "/home/example", XDG_DATA_HOME: "/data" },
      platform: "linux",
    }),
    "/data/agent-runner/runtime",
  );
  assert.equal(
    resolveRuntimeRoot({
      env: { HOME: "/home/example", XDG_DATA_HOME: "relative" },
      platform: "linux",
    }),
    "/home/example/.local/share/agent-runner/runtime",
  );
  assert.equal(
    resolveRuntimeRoot({ env: { HOME: "/home/example" }, platform: "darwin" }),
    "/home/example/Library/Application Support/agent-runner/runtime",
  );
  assert.equal(
    resolveRuntimeRoot({
      env: { LOCALAPPDATA: "C:\\Users\\example\\Local" },
      platform: "win32",
    }),
    "C:\\Users\\example\\Local\\agent-runner\\runtime",
  );
  assert.throws(() =>
    resolveRuntimeRoot({
      env: { LOCALAPPDATA: "\\relative" },
      platform: "win32",
    }),
  );
});

test("complete immutable payloads survive outer replacement and retain delayed resources", async (t) => {
  const f = await runtimeFixture(t);
  await writeFile(
    join(f.rootPath, ".agent-runner.json"),
    "legacy settings stay outside\n",
  );
  const runtime = await prepareRuntime(f);
  assert.equal(runtime.mode, "pinned");
  assert.equal(runtime.installationPath, f.rootPath);
  assert.equal((await lstat(runtime.rootPath)).mode & 0o777, 0o500);
  assert.equal((await lstat(runtime.executablePath)).mode & 0o777, 0o500);
  await assert.rejects(readFile(join(runtime.rootPath, ".agent-runner.json")), {
    code: "ENOENT",
  });
  await rename(f.rootPath, join(f.directory, "previous-installation"));
  await mkdir(f.rootPath);
  await writeFile(join(f.rootPath, "package.json"), "invalid replacement\n");
  const application = await import(
    pathToFileURL(join(runtime.rootPath, "src/index.js"))
  );
  assert.equal(await application.delayed(), "original");
  assert.equal(await application.dependencyValue(), "original dependency");
  assert.equal(
    await readFile(join(runtime.rootPath, "docs/OPERATOR_GUIDE.md"), "utf8"),
    "# Original complete guide\n",
  );
  const selected = await prepareRuntime({ rootPath: runtime.rootPath });
  assert.equal(selected.rootPath, runtime.rootPath);
  assert.equal(selected.payloadId, runtime.payloadId);
});

test("detached startup rejects changed payload, executable and Node identities", async (t) => {
  const f = await runtimeFixture(t);
  const runtime = await prepareRuntime(f);
  for (const changed of [
    { ...runtime, payloadId: "b".repeat(64) },
    { ...runtime, executablePath: join(f.rootPath, "bin/agent-run.js") },
    { ...runtime, nodeVersion: "v0.0.0" },
    { ...runtime, nodeIdentity: { ...runtime.nodeIdentity, ino: "0" } },
  ]) {
    await assert.rejects(
      prepareRuntime({
        rootPath: runtime.rootPath,
        environment: { [RUNTIME_PAYLOAD_ENV]: JSON.stringify(changed) },
      }),
    );
  }
  const resumed = await prepareRuntime({
    rootPath: runtime.rootPath,
    environment: { [RUNTIME_PAYLOAD_ENV]: JSON.stringify(runtime) },
  });
  assert.equal(resumed.installationPath, f.rootPath);
  assert.equal(resumed.payloadId, runtime.payloadId);
});

test("interrupted preparation is never adopted and a fresh attempt publishes complete bytes", async (t) => {
  const f = await runtimeFixture(t);
  let partial;
  await assert.rejects(
    prepareRuntime({
      ...f,
      beforePublish({ preparationPath }) {
        partial = preparationPath;
        throw new Error("interrupted");
      },
    }),
    /interrupted/u,
  );
  const published = async () =>
    (await readdir(join(f.storageRoot, "payloads"))).filter((name) =>
      /^[a-f0-9]{64}$/u.test(name),
    );
  assert.equal((await published()).length, 0);
  await assert.rejects(prepareRuntime({ rootPath: partial }));
  const selected = await prepareRuntime(f);
  assert.equal((await lstat(partial)).isDirectory(), true);
  assert.notEqual(selected.rootPath, partial);
  assert.equal((await published()).length, 1);
  assert.equal((await prepareRuntime(f)).rootPath, selected.rootPath);
});

test("concurrent complete preparations converge without adopting partial or substituted targets", async (t) => {
  const f = await runtimeFixture(t);
  const ready = Promise.withResolvers();
  let arrivals = 0;
  const beforePublish = async () => {
    if (++arrivals === 2) ready.resolve();
    await ready.promise;
  };
  const settled = await Promise.allSettled([
    prepareRuntime({ ...f, beforePublish }),
    prepareRuntime({ ...f, beforePublish }),
  ]);
  for (const result of settled)
    assert.equal(result.status, "fulfilled", result.reason?.stack);
  const results = settled.map((result) => result.value);
  assert.equal(results[0].rootPath, results[1].rootPath);
  assert.equal(results[0].payloadId, results[1].payloadId);
});

test("publication preserves an empty destination appearing after the final absence check", async (t) => {
  const f = await runtimeFixture(t);
  let target;
  let identity;
  await assert.rejects(
    prepareRuntime({
      ...f,
      async beforePublish({ payloadId }) {
        target = join(f.storageRoot, "payloads", payloadId);
        await mkdir(target, { mode: 0o700 });
        identity = await lstat(target, { bigint: true });
      },
    }),
  );
  const actual = await lstat(target, { bigint: true });
  for (const key of ["dev", "ino", "mode", "uid", "mtimeNs", "ctimeNs"])
    assert.equal(actual[key], identity[key]);
  assert.deepEqual(await readdir(target), []);
});

test("sealing rejects replaced preparation directories and leaves linked targets unchanged", async (t) => {
  for (const replaced of ["root", "nested"]) {
    await t.test(replaced, async (t) => {
      const f = await runtimeFixture(t);
      const outside = join(f.directory, "unrelated");
      await mkdir(outside, { mode: 0o750 });
      const file = join(outside, "index.js");
      await writeFile(file, "unchanged unrelated bytes\n", { mode: 0o640 });
      const before = [(await lstat(outside)).mode, (await lstat(file)).mode];
      await assert.rejects(
        prepareRuntime({
          ...f,
          async beforeSeal({ preparationPath }) {
            const original =
              replaced === "root"
                ? preparationPath
                : join(preparationPath, "src");
            await rename(original, join(f.directory, "saved-preparation"));
            await symlink(outside, original);
          },
        }),
      );
      assert.deepEqual(
        [(await lstat(outside)).mode, (await lstat(file)).mode],
        before,
      );
      assert.equal(await readFile(file, "utf8"), "unchanged unrelated bytes\n");
    });
  }
});

test("runtime rejects missing, extra, aliased and drifting content without repairing payloads", async (t) => {
  for (const scenario of [
    "missing",
    "extra",
    "link",
    "stored-drift",
    "stored-missing",
    "storage-link",
    "unsafe-permissions",
    "source-overlap",
    "manifest-omission",
    "dependency-omission",
    "bootstrap-omission",
    "payload-parent-permissions",
    "payload-storage-permissions",
    "publication-outside",
  ]) {
    await t.test(scenario, async (t) => {
      const f = await runtimeFixture(t);
      let damagedFile;
      if (scenario === "missing") await rm(join(f.rootPath, "src/late.js"));
      if (scenario === "extra")
        await writeFile(join(f.rootPath, ".env"), "local-only\n");
      if (scenario === "link") {
        await rm(join(f.rootPath, "src/late.js"));
        await symlink(
          join(f.rootPath, "src/index.js"),
          join(f.rootPath, "src/late.js"),
        );
      }
      if (scenario === "stored-drift") {
        const runtime = await prepareRuntime(f);
        const file = join(runtime.rootPath, "src/late.js");
        damagedFile = file;
        await chmod(file, 0o600);
        await writeFile(file, 'export const marker = "drifted";\n');
        await chmod(file, 0o400);
      }
      if (scenario === "stored-missing") {
        const runtime = await prepareRuntime(f);
        const directory = join(runtime.rootPath, "src");
        await chmod(directory, 0o700);
        await rm(join(directory, "late.js"));
        await chmod(directory, 0o500);
      }
      if (scenario === "storage-link") {
        await mkdir(join(f.directory, "elsewhere"));
        await symlink(join(f.directory, "elsewhere"), f.storageRoot);
      }
      if (scenario === "unsafe-permissions")
        await mkdir(f.storageRoot, { mode: 0o755 });
      if (scenario === "publication-outside") {
        const runtime = await prepareRuntime(f);
        const reference = join(f.storageRoot, "payloads", runtime.payloadId);
        await rm(reference);
        await symlink(f.rootPath, reference);
      }
      if (scenario === "source-overlap")
        f.storageRoot = join(f.rootPath, "runtime");
      if (scenario === "manifest-omission") {
        f.manifest.files = f.manifest.files.filter(
          (file) => file.path !== "docs/OPERATOR_GUIDE.md",
        );
        await writeFile(
          join(f.rootPath, "release-manifest.json"),
          JSON.stringify(f.manifest),
        );
      }
      if (scenario === "dependency-omission") {
        f.manifest.dependencies = [];
        await writeFile(
          join(f.rootPath, "release-manifest.json"),
          JSON.stringify(f.manifest),
        );
      }
      if (scenario === "bootstrap-omission") {
        f.manifest.files = f.manifest.files.filter(
          (file) => file.path !== "src/runtime/bootstrap.js",
        );
        await rm(join(f.rootPath, "src/runtime/bootstrap.js"));
        await writeFile(
          join(f.rootPath, "release-manifest.json"),
          JSON.stringify(f.manifest),
        );
      }
      let inspected = f;
      if (
        scenario === "payload-parent-permissions" ||
        scenario === "payload-storage-permissions"
      ) {
        const runtime = await prepareRuntime(f);
        await chmod(
          scenario === "payload-parent-permissions"
            ? join(f.storageRoot, "payloads")
            : f.storageRoot,
          0o755,
        );
        inspected = { rootPath: runtime.rootPath };
      }
      await assert.rejects(prepareRuntime(inspected));
      if (scenario === "stored-drift") {
        assert.match(await readFile(damagedFile, "utf8"), /drifted/u);
      }
    });
  }
});

test("linked checkouts remain development managed without creating runtime storage", async (t) => {
  const f = await runtimeFixture(t);
  await rm(join(f.rootPath, "release-manifest.json"));
  await mkdir(join(f.rootPath, ".git"));
  await writeFile(
    join(f.rootPath, "package.json"),
    JSON.stringify({ workspaces: ["packages/*"] }),
  );
  const link = join(f.directory, "linked-checkout");
  await symlink(f.rootPath, link);
  const selected = await prepareRuntime({
    ...f,
    rootPath: await realpath(link),
    selectActive: true,
    stateRoot: join(f.directory, "absent-state"),
  });
  assert.equal(selected.mode, "development");
  assert.equal(selected.rootPath, f.rootPath);
  await assert.rejects(lstat(f.storageRoot), { code: "ENOENT" });
});

test("unknown forward runtime selections preserve progress and block pre-import startup", async (t) => {
  const f = await runtimeFixture(t);
  const stateRoot = join(f.directory, "state");
  const admissionPath = join(stateRoot, "runtime-admission");
  await mkdir(admissionPath, { recursive: true, mode: 0o700 });
  const path = join(admissionPath, "runtime.json");
  const bytes = JSON.stringify({ schemaVersion: 3, progress: "retained" });
  await writeFile(path, bytes, { mode: 0o600 });
  await assert.rejects(
    prepareRuntime({ ...f, selectActive: true, stateRoot }),
    { code: "ERR_RUNTIME_SELECTION_VERSION" },
  );
  assert.equal(await readFile(path, "utf8"), bytes);
  await assert.rejects(lstat(f.storageRoot), { code: "ENOENT" });
});

test("release manifests cannot bypass verification through checkout metadata", async (t) => {
  const f = await runtimeFixture(t);
  await mkdir(join(f.rootPath, ".git"));
  await writeFile(
    join(f.rootPath, "package.json"),
    JSON.stringify({ workspaces: ["packages/*"] }),
  );
  await assert.rejects(prepareRuntime(f));
  await assert.rejects(lstat(f.storageRoot), { code: "ENOENT" });
});
