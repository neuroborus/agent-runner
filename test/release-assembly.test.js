import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { assembleRelease } from "../scripts/assemble-release.js";
import { inspectReleaseArchive } from "../scripts/release-archive.js";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
async function put(root, path, content, mode = 0o644) {
  await mkdir(dirname(join(root, path)), { recursive: true });
  await writeFile(
    join(root, path),
    typeof content === "object"
      ? JSON.stringify(content, null, 2) + "\n"
      : content,
    { mode },
  );
}

async function fixture(t) {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "agent-runner-assembly-")),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = join(directory, "source");
  const outputPath = join(directory, "output");
  const metadata = {
    name: "@your-scope/agent-runner",
    version: "0.0.0",
    private: true,
    license: "UNLICENSED",
    type: "module",
    workspaces: ["packages/*", "pipelines/*"],
    engines: { node: ">=24 <25" },
    exports: "./src/index.js",
    bin: { "agent-run": "bin/agent-run.js" },
    dependencies: { "@sample/pipeline": "0.0.0", "sample-lib": "1.0.0" },
    devDependencies: { "dev-only": "9.0.0" },
    scripts: { test: "node --test" },
    bundleDependencies: ["@sample/pipeline", "sample-lib"],
    files: [
      "bin/agent-run.js",
      "src/**/*.js",
      "README.md",
      "docs/OPERATOR_GUIDE.md",
      "release-manifest.json",
    ],
  };
  const pipeline = {
    name: "@sample/pipeline",
    version: "0.0.0",
    type: "module",
    private: true,
    files: ["src/**/*.js"],
    exports: "./src/index.js",
    dependencies: { "@sample/contract": "0.0.0", "sample-lib": "2.0.0" },
  };
  const contract = {
    name: "@sample/contract",
    version: "0.0.0",
    type: "module",
    private: true,
    files: ["src/**/*.js"],
    exports: "./src/index.js",
  };
  const packages = {
    "": { ...metadata },
    "node_modules/@sample/pipeline": {
      link: true,
      resolved: "pipelines/sample",
    },
    "node_modules/@sample/contract": {
      link: true,
      resolved: "packages/contract",
    },
    "pipelines/sample": {
      version: "0.0.0",
      dependencies: pipeline.dependencies,
    },
    "packages/contract": { version: "0.0.0" },
  };
  for (const [slot, name, version] of [
    ["node_modules/sample-lib", "sample-lib", "1.0.0"],
    ["pipelines/sample/node_modules/sample-lib", "sample-lib", "2.0.0"],
    ["node_modules/dev-only", "dev-only", "9.0.0"],
  ]) {
    const library = {
      name,
      version,
      type: "module",
      exports: "./index.js",
      files: ["index.js"],
    };
    packages[slot] = {
      version,
      integrity: "sha512-" + Buffer.alloc(64).toString("base64"),
      ...(name === "dev-only" ? { dev: true } : {}),
    };
    await put(root, slot + "/package.json", library);
    await put(
      root,
      slot + "/index.js",
      `export const version = ${JSON.stringify(version)};\n`,
    );
    await put(
      root,
      slot + "/LICENSE",
      "Synthetic dependency license fixture.\n",
    );
    await put(root, slot + "/local-settings.json", "unpublished local data");
  }
  await put(root, "package.json", metadata);
  await put(root, "package-lock.json", {
    name: metadata.name,
    version: metadata.version,
    lockfileVersion: 3,
    packages,
  });
  await put(
    root,
    "src/index.js",
    'export { marker, nestedVersion } from "@sample/pipeline"; export { version } from "sample-lib";\n',
  );
  await put(
    root,
    "bin/agent-run.js",
    '#!/usr/bin/env node\nimport "../src/index.js";\n',
    0o755,
  );
  await put(root, "README.md", "# Synthetic application\n");
  await put(root, "docs/OPERATOR_GUIDE.md", "# Complete synthetic guide\n");
  await put(root, "pipelines/sample/package.json", pipeline);
  await put(
    root,
    "pipelines/sample/src/index.js",
    'export { marker } from "@sample/contract"; export { version as nestedVersion } from "sample-lib";\n',
  );
  await put(root, "packages/contract/package.json", contract);
  await put(
    root,
    "packages/contract/src/index.js",
    'export const marker = "contract";\n',
  );
  await mkdir(join(root, "node_modules/@sample"), { recursive: true });
  await symlink(
    join(root, "pipelines/sample"),
    join(root, "node_modules/@sample/pipeline"),
  );
  await symlink(
    join(root, "packages/contract"),
    join(root, "node_modules/@sample/contract"),
  );
  for (const path of [
    ".agent-runner.json",
    ".env",
    ".git/config",
    ".codex/session.json",
    "LOCAL_ARTIFACTS/task.md",
    "task.md",
    "src/settings.json",
    "docs/task.md",
    "test/example.test.js",
  ])
    await put(root, path, "local-only fixture\n");
  return { root, outputPath, metadata, packages };
}

test("assembly materializes the locked production graph with no checkout links or local data", async (t) => {
  const f = await fixture(t);
  const release = await assembleRelease({
    projectPath: f.root,
    outputPath: f.outputPath,
  });
  const metadata = JSON.parse(
    await readFile(join(release.packagePath, "package.json"), "utf8"),
  );
  assert.equal(metadata.private, true);
  assert.equal(metadata.license, "UNLICENSED");
  assert.equal(metadata.workspaces, undefined);
  assert.equal(metadata.devDependencies, undefined);
  assert.equal(metadata.scripts, undefined);
  assert.equal(metadata.exports, "./src/index.js");
  const application = await import(
    pathToFileURL(join(release.packagePath, "src/index.js"))
  );
  assert.equal(application.marker, "contract");
  assert.equal(application.version, "1.0.0");
  assert.equal(application.nestedVersion, "2.0.0");
  assert.equal(
    (await lstat(join(release.packagePath, "bin/agent-run.js"))).mode & 0o777,
    0o755,
  );
  assert.equal(
    (
      await lstat(join(f.root, "node_modules/@sample/pipeline"))
    ).isSymbolicLink(),
    true,
  );
  for (const path of [
    "node_modules/@sample/pipeline",
    "node_modules/@sample/contract",
  ])
    assert.equal(
      (await lstat(join(release.packagePath, path))).isDirectory(),
      true,
    );
  assert.equal(release.manifest.dependencies.length, 4);
  assert.ok(
    release.manifest.files.some(
      ({ path }) => path === "node_modules/sample-lib/LICENSE",
    ),
  );
  for (const { path } of release.manifest.files)
    assert.doesNotMatch(
      path,
      /(?:dev-only|local-settings|settings\.json|task\.md|\.env|\.git\/|\.codex\/|LOCAL_ARTIFACTS|test\/)/u,
    );
  assert.equal(
    await readFile(join(release.packagePath, "docs/OPERATOR_GUIDE.md"), "utf8"),
    "# Complete synthetic guide\n",
  );
});

test("assembly rejects drift, missing resources, links, unsafe output and publication metadata", async (t) => {
  for (const kind of [
    "version",
    "lock",
    "resource",
    "link",
    "hardlink",
    "existing-output",
    "source-output",
    "publication",
  ]) {
    await t.test(kind, async (t) => {
      const f = await fixture(t);
      let outputPath = f.outputPath;
      if (kind === "version")
        await put(f.root, "node_modules/sample-lib/package.json", {
          name: "sample-lib",
          version: "2.0.0",
          files: ["index.js"],
        });
      if (kind === "lock")
        await put(f.root, "package-lock.json", {
          name: "wrong-name",
          version: "0.0.0",
          lockfileVersion: 3,
          packages: f.packages,
        });
      if (kind === "resource") await rm(join(f.root, "docs/OPERATOR_GUIDE.md"));
      if (kind === "link")
        await symlink(join(f.root, "README.md"), join(f.root, "src/linked.js"));
      if (kind === "hardlink")
        await link(join(f.root, "README.md"), join(f.root, "src/linked.js"));
      if (kind === "existing-output") {
        await mkdir(outputPath);
        await put(outputPath, "keep.txt", "preserve");
      }
      if (kind === "source-output") outputPath = join(f.root, "src/output");
      if (kind === "publication")
        await put(f.root, "package.json", { ...f.metadata, private: false });
      await assert.rejects(
        assembleRelease({ projectPath: f.root, outputPath }),
      );
      if (kind === "existing-output")
        assert.equal(
          await readFile(join(outputPath, "keep.txt"), "utf8"),
          "preserve",
        );
      assert.equal(
        await readFile(join(f.root, "README.md"), "utf8"),
        "# Synthetic application\n",
      );
    });
  }
});

function archive(entries) {
  const chunks = [];
  for (const { path, bytes, type = "0", mode = 0o644 } of entries) {
    const header = Buffer.alloc(512);
    header.write("package/" + path, 0);
    header.write(mode.toString(8).padStart(7, "0") + "\0", 100);
    header.write(bytes.length.toString(8).padStart(11, "0") + "\0", 124);
    header.fill(32, 148, 156);
    header.write(type, 156);
    header.write(
      header
        .reduce((sum, byte) => sum + byte, 0)
        .toString(8)
        .padStart(6, "0") + "\0 ",
      148,
    );
    chunks.push(
      header,
      bytes,
      Buffer.alloc((512 - (bytes.length % 512)) % 512),
    );
  }
  return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]));
}

function extendedHeader(fields) {
  const records = Object.entries(fields).map(([key, value]) => {
    const body = ` ${key}=${value}\n`;
    let length = Buffer.byteLength(body) + 1;
    while (length !== Buffer.byteLength(body) + String(length).length)
      length = Buffer.byteLength(body) + String(length).length;
    return `${length}${body}`;
  });
  return { path: "PaxHeader", type: "x", bytes: Buffer.from(records.join("")) };
}

test("archive inspection rejects changed bytes, modes, extra files, traversal and links", async (t) => {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "agent-runner-archive-")),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const bytes = Buffer.from("source\n");
  const manifest = {
    schemaVersion: 1,
    files: [
      {
        path: "src/index.js",
        sha256: hash(bytes),
        size: bytes.length,
        mode: 0o644,
      },
    ],
  };
  const entries = [
    { path: "src/index.js", bytes },
    {
      path: "release-manifest.json",
      bytes: Buffer.from(JSON.stringify(manifest, null, 2) + "\n"),
    },
  ];
  const path = join(directory, "candidate.tgz");
  await writeFile(path, archive(entries));
  assert.equal((await inspectReleaseArchive(path, manifest)).files, 2);
  await writeFile(
    path,
    archive([
      extendedHeader({ path: "package/src/index.js", size: bytes.length }),
      { ...entries[0], path: "placeholder" },
      entries[1],
    ]),
  );
  assert.equal((await inspectReleaseArchive(path, manifest)).files, 2);
  for (const changed of [
    [extendedHeader({ size: 0 }), ...entries],
    [entries[0], { ...entries[1], mode: 0o755 }],
    [extendedHeader({ "GNU.sparse.size": bytes.length }), ...entries],
    [extendedHeader({ mtime: "0\n18 path=package/x\n" }), ...entries],
    [...entries, { path: "extra/", type: "5", bytes: Buffer.alloc(0) }],
    [{ ...entries[0], bytes: Buffer.from("edited\n") }, entries[1]],
    [{ ...entries[0], mode: 0o755 }, entries[1]],
    [{ ...entries[0], mode: 0o4644 }, entries[1]],
    [...entries, { path: "extra.txt", bytes }],
    [{ path: "../escape", bytes }, entries[1]],
    [{ ...entries[0], type: "2" }, entries[1]],
    [...entries, entries[0]],
  ]) {
    await writeFile(path, archive(changed));
    await assert.rejects(inspectReleaseArchive(path, manifest));
  }
});
