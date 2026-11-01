import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

function sameDirectory(actual, expected) {
  return (
    actual.isDirectory() &&
    actual.dev === expected.dev &&
    actual.ino === expected.ino &&
    actual.uid === expected.uid
  );
}

async function writableDirectories(path, expected) {
  const metadata = await lstat(path);
  if (!sameDirectory(metadata, expected) || metadata.uid !== process.getuid())
    throw new Error("Runtime fixture directory ownership changed.");
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    if (!sameDirectory(await handle.stat(), expected))
      throw new Error("Runtime fixture directory was substituted.");
    await handle.chmod(0o700);
    const anchor = `/proc/self/fd/${handle.fd}`;
    for (const name of await readdir(anchor)) {
      const child = join(anchor, name);
      const identity = await lstat(child);
      if (identity.isDirectory()) await writableDirectories(child, identity);
    }
  } finally {
    await handle.close();
  }
}

export async function runtimeFixtureDirectory(t) {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "agent-runner-runtime-")),
  );
  const identity = await lstat(directory);
  t.after(async () => {
    await writableDirectories(directory, identity);
    if (!sameDirectory(await lstat(directory), identity))
      throw new Error("Runtime fixture root was substituted before removal.");
    await rm(directory, { recursive: true, force: true });
  });
  return directory;
}

export async function runtimeFixture(t, { application, extraFiles = {} } = {}) {
  const directory = await runtimeFixtureDirectory(t);
  const rootPath = join(directory, "installation");
  const storageRoot = join(directory, "runtime");
  const contents = new Map([
    [
      "package.json",
      JSON.stringify({
        name: "@sample/runtime",
        version: "1.0.0",
        type: "module",
        engines: { node: ">=24 <25" },
        exports: "./src/index.js",
        bin: { "agent-run": "./bin/agent-run.js" },
        dependencies: { "sample-dependency": "1.0.0" },
      }) + "\n",
    ],
    [
      "src/index.js",
      application ??
        'export async function main() { return 0; }\nexport async function delayed() { return (await import("./late.js")).marker; }\nexport async function dependencyValue() { return (await import("sample-dependency")).value(); }\n',
    ],
    ["src/late.js", 'export const marker = "original";\n'],
    ["docs/OPERATOR_GUIDE.md", "# Original complete guide\n"],
    [
      "node_modules/sample-dependency/package.json",
      JSON.stringify({
        name: "sample-dependency",
        version: "1.0.0",
        type: "module",
        exports: "./index.js",
      }),
    ],
    [
      "node_modules/sample-dependency/index.js",
      'export async function value() { return (await import("./late.js")).marker; }\n',
    ],
    [
      "node_modules/sample-dependency/late.js",
      'export const marker = "original dependency";\n',
    ],
    ...Object.entries(extraFiles),
  ]);
  for (const name of await readdir(
    new URL("../../src/runtime/", import.meta.url),
  ))
    contents.set(
      `src/runtime/${name}`,
      await readFile(new URL(`../../src/runtime/${name}`, import.meta.url)),
    );
  contents.set(
    "bin/agent-run.js",
    await readFile(new URL("../../bin/agent-run.js", import.meta.url)),
  );
  const files = [];
  for (const [path, content] of contents) {
    const bytes = Buffer.from(content);
    const mode = path === "bin/agent-run.js" ? 0o755 : 0o644;
    await mkdir(dirname(join(rootPath, path)), { recursive: true });
    await writeFile(join(rootPath, path), bytes, { mode });
    files.push({
      path,
      size: bytes.length,
      mode,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  }
  const manifest = {
    schemaVersion: 1,
    name: "@sample/runtime",
    version: "1.0.0",
    lockSha256: "a".repeat(64),
    dependencies: [
      {
        path: "node_modules/sample-dependency",
        name: "sample-dependency",
        version: "1.0.0",
        integrity: "sha512-fixture",
      },
    ],
    files: files.sort((a, b) => a.path.localeCompare(b.path)),
  };
  await writeFile(
    join(rootPath, "release-manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n",
  );
  return { directory, rootPath, storageRoot, manifest };
}
