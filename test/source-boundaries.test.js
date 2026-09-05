import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import {
  basename,
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const IMPORT_PATTERN =
  /(?:\bimport\s*(?:[^'"]*?\sfrom\s*)?|\bexport\s+[^'"]*?\sfrom\s*|\bimport\s*\()\s*["']([^"']+)["']/gu;

async function walk(directory, predicate) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      paths.push(...(await walk(path, predicate)));
    } else if (predicate(path)) {
      paths.push(path);
    }
  }
  return paths;
}

async function workspaceDirectories() {
  const directories = [];
  for (const group of ["packages", "pipelines"]) {
    const entries = await readdir(join(ROOT, group), { withFileTypes: true });
    directories.push(
      ...entries
        .filter((entry) => entry.isDirectory())
        .map((entry) => join(group, entry.name)),
    );
  }
  return directories;
}

function isWithin(directory, path) {
  const pathFromDirectory = relative(directory, path);
  return (
    pathFromDirectory === "" ||
    (!pathFromDirectory.startsWith("..") && !isAbsolute(pathFromDirectory))
  );
}

function sourceOwner(path, manifests) {
  return manifests
    .filter(({ directory }) => isWithin(directory, path))
    .sort((left, right) => right.directory.length - left.directory.length)[0];
}

async function sourceImports() {
  const sourceRoots = [
    "bin",
    "src",
    ...(await workspaceDirectories()).map((directory) =>
      join(directory, "src"),
    ),
  ];
  const files = (
    await Promise.all(
      sourceRoots.map((directory) =>
        walk(join(ROOT, directory), (path) => extname(path) === ".js"),
      ),
    )
  ).flat();
  const imports = [];
  for (const importer of files) {
    const source = await readFile(importer, "utf8");
    for (const match of source.matchAll(IMPORT_PATTERN)) {
      imports.push({ importer, specifier: match[1] });
    }
  }
  return { files, imports };
}

test("source imports respect indexed capability boundaries", async () => {
  const { files, imports } = await sourceImports();
  const sourceFiles = new Set(files);
  const indexDirectories = new Set(
    files
      .filter((path) => basename(path) === "index.js")
      .map((path) => dirname(path)),
  );
  const failures = [];
  let directPrivateImports = 0;

  for (const { importer, specifier } of imports) {
    if (!specifier.startsWith(".")) {
      continue;
    }
    const target = resolve(dirname(importer), specifier);
    if (!sourceFiles.has(target)) {
      continue;
    }
    if (dirname(importer) === dirname(target)) {
      if (basename(target) === "index.js") {
        failures.push(
          `${relative(ROOT, importer)} imports its own public index`,
        );
      } else {
        directPrivateImports += 1;
      }
      continue;
    }
    const targetBoundary = [...indexDirectories]
      .filter((directory) => isWithin(directory, target))
      .sort((left, right) => right.length - left.length)[0];
    if (
      targetBoundary !== undefined &&
      !isWithin(targetBoundary, importer) &&
      target !== join(targetBoundary, "index.js")
    ) {
      failures.push(
        `${relative(ROOT, importer)} bypasses ${relative(ROOT, targetBoundary)}/index.js for ${relative(ROOT, target)}`,
      );
    }
  }

  assert.ok(directPrivateImports > 0);
  assert.deepEqual(failures, []);
});

test("source directories need an index only when consumed outwardly", async () => {
  const { files, imports } = await sourceImports();
  const sourceFiles = new Set(files);
  const outwardImports = new Map();
  for (const { importer, specifier } of imports) {
    if (!specifier.startsWith(".")) {
      continue;
    }
    const target = resolve(dirname(importer), specifier);
    if (!sourceFiles.has(target) || isWithin(dirname(target), importer)) {
      continue;
    }
    outwardImports.set(dirname(target), importer);
  }
  const missingIndexes = [...new Set(files.map(dirname))].filter(
    (directory) =>
      outwardImports.has(directory) &&
      !sourceFiles.has(join(directory, "index.js")),
  );

  assert.deepEqual(
    missingIndexes.map((path) => relative(ROOT, path)),
    [],
  );
  assert.ok(
    [...new Set(files.map(dirname))].some(
      (directory) =>
        !outwardImports.has(directory) &&
        !sourceFiles.has(join(directory, "index.js")),
    ),
  );
});

test("workspace imports follow root to pipeline to shared-package direction", async () => {
  const { imports } = await sourceImports();
  const manifestPaths = [
    "package.json",
    ...(await workspaceDirectories()).map((directory) =>
      join(directory, "package.json"),
    ),
  ];
  const manifests = await Promise.all(
    manifestPaths.map(async (path) => {
      const manifest = JSON.parse(await readFile(join(ROOT, path), "utf8"));
      return {
        dependencies: manifest.dependencies ?? {},
        directory: dirname(join(ROOT, path)),
        name: manifest.name,
        tier:
          path === "package.json" ? 0 : path.startsWith("pipelines/") ? 1 : 2,
      };
    }),
  );
  const internal = new Map(
    manifests.map((manifest) => [manifest.name, manifest]),
  );
  const failures = [];

  for (const { importer, specifier } of imports) {
    const owner = sourceOwner(importer, manifests);
    let target;
    let requiresDeclaration = false;
    if (
      specifier === "agent-runner" ||
      specifier.startsWith("@agent-runner/")
    ) {
      target = internal.get(specifier);
      requiresDeclaration = true;
      if (target === undefined) {
        failures.push(
          `${relative(ROOT, importer)} imports unknown ${specifier}`,
        );
        continue;
      }
    } else if (specifier.startsWith(".")) {
      target = sourceOwner(resolve(dirname(importer), specifier), manifests);
    } else {
      continue;
    }
    if (owner?.directory === target?.directory) {
      continue;
    }
    if (
      owner === undefined ||
      target === undefined ||
      (requiresDeclaration && !Object.hasOwn(owner.dependencies, specifier)) ||
      target.tier <= owner.tier
    ) {
      failures.push(`${relative(ROOT, importer)} imports ${specifier}`);
    }
  }

  assert.deepEqual(failures, []);
});

test("pipeline source does not branch on registered provider IDs", async () => {
  const pipelineSources = await walk(
    join(ROOT, "pipelines"),
    (path) => extname(path) === ".js" && path.includes("/src/"),
  );
  for (const path of pipelineSources) {
    const source = await readFile(path, "utf8");
    assert.doesNotMatch(
      source,
      /backend\s*(?:===|!==|==|!=)\s*["'](?:codex|claude)["']/u,
      relative(ROOT, path),
    );
  }
});
