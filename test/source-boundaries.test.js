import assert from "node:assert/strict";
import {
  glob,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
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

import { BACKEND_IDS } from "../src/agents/index.js";

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

// Workspaces are the root manifest's declarations. As in npm, `*` skips hidden
// entries; symbolic links are not workspace directories.
async function workspaceDirectories(root = ROOT) {
  const { workspaces } = JSON.parse(
    await readFile(join(root, "package.json"), "utf8"),
  );
  const directories = new Set();
  for await (const entry of glob(workspaces, {
    cwd: root,
    withFileTypes: true,
  })) {
    if (entry.isDirectory()) {
      directories.add(relative(root, join(entry.parentPath, entry.name)));
    }
  }
  return [...directories].sort();
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

async function sourceImports(root = ROOT) {
  const sourceRoots = [
    "bin",
    "src",
    ...(await workspaceDirectories(root)).map((directory) =>
      join(directory, "src"),
    ),
  ];
  const files = (
    await Promise.all(
      sourceRoots.map((directory) =>
        walk(join(root, directory), (path) => extname(path) === ".js"),
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

test("source walks follow root workspace declarations", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-workspaces-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const declare = (workspaces) =>
    writeFile(join(root, "package.json"), JSON.stringify({ workspaces }));
  const sourceFiles = async () =>
    (await sourceImports(root)).files
      .map((path) => relative(root, path))
      .sort();
  for (const directory of [
    "bin",
    "src",
    "packages/shared/src",
    "pipelines/regular/src",
    "pipelines/.operational",
  ]) {
    await mkdir(join(root, directory), { recursive: true });
  }
  for (const path of [
    "bin/cli.js",
    "src/index.js",
    "packages/shared/src/index.js",
    "pipelines/regular/src/index.js",
  ]) {
    await writeFile(join(root, path), "export {};\n");
  }
  await writeFile(join(root, "pipelines/.operational/state.json"), "{}\n");

  await declare(["packages/*", "pipelines/*"]);
  assert.deepEqual(await workspaceDirectories(root), [
    "packages/shared",
    "pipelines/regular",
  ]);
  assert.deepEqual(await sourceFiles(), [
    "bin/cli.js",
    "packages/shared/src/index.js",
    "pipelines/regular/src/index.js",
    "src/index.js",
  ]);

  await declare(["packages/*", "pipelines/*", "pipelines/.operational"]);
  assert.deepEqual(await workspaceDirectories(root), [
    "packages/shared",
    "pipelines/.operational",
    "pipelines/regular",
  ]);
  await assert.rejects(sourceImports(root), { code: "ENOENT" });
  await mkdir(join(root, "pipelines/.operational/src"));
  await writeFile(
    join(root, "pipelines/.operational/src/index.js"),
    "export {};\n",
  );
  assert.ok(
    (await sourceFiles()).includes("pipelines/.operational/src/index.js"),
  );
});

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
      specifier === manifests[0].name ||
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

test("runtime policy does not branch on registered provider IDs", async () => {
  const providerIdentity = new RegExp(
    `["'\\x60](?:${BACKEND_IDS.join("|")})["'\\x60]`,
    "u",
  );
  const policySources = [
    join(ROOT, "src/cli.js"),
    ...(await walk(
      join(ROOT, "src/runner"),
      (path) => extname(path) === ".js",
    )),
    ...(await walk(
      join(ROOT, "src/issues"),
      (path) => extname(path) === ".js",
    )),
    ...(await walk(join(ROOT, "src/mcp"), (path) => extname(path) === ".js")),
    ...(await walk(
      join(ROOT, "pipelines"),
      (path) => extname(path) === ".js" && path.includes("/src/"),
    )),
  ];
  for (const path of policySources) {
    const source = await readFile(path, "utf8");
    assert.doesNotMatch(source, providerIdentity, relative(ROOT, path));
  }
});

test("provider-private source stays inside the agent capability", async () => {
  const { imports } = await sourceImports();
  const providers = (
    await readdir(join(ROOT, "src/agents"), { withFileTypes: true })
  )
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(ROOT, "src/agents", entry.name));
  const failures = imports
    .filter(({ importer, specifier }) => {
      if (!specifier.startsWith(".")) return false;
      const target = resolve(dirname(importer), specifier);
      return (
        !isWithin(join(ROOT, "src/agents"), importer) &&
        providers.some((provider) => isWithin(provider, target))
      );
    })
    .map(
      ({ importer, specifier }) =>
        `${relative(ROOT, importer)} imports ${specifier}`,
    );
  assert.deepEqual(failures, []);
});

test("platform source imports only Node built-ins and its own siblings", async () => {
  const platform = join(ROOT, "src/platform");
  const { imports } = await sourceImports();
  const failures = imports
    .filter(
      ({ importer, specifier }) =>
        isWithin(platform, importer) &&
        !specifier.startsWith("node:") &&
        !(
          specifier.startsWith("./") &&
          isWithin(platform, resolve(dirname(importer), specifier))
        ),
    )
    .map(
      ({ importer, specifier }) =>
        `${relative(ROOT, importer)} imports ${specifier}`,
    );
  assert.deepEqual(failures, []);
});

test("the agent index does not re-export platform capabilities", async () => {
  const agents = await import("../src/agents/index.js");
  const platform = await import("../src/platform/index.js");
  assert.deepEqual(
    Object.keys(platform).filter((name) => Object.hasOwn(agents, name)),
    [],
  );
});

test("operator guidance stays outside pipeline roles and run reconstruction", async () => {
  const { files, imports } = await sourceImports();
  for (const { importer, specifier } of imports) {
    if (!specifier.includes("guidance/")) continue;
    const path = relative(ROOT, importer);
    assert.ok(
      path === "src/index.js" ||
        path === "src/cli.js" ||
        path === "src/runner/setup.js" ||
        path.startsWith("src/mcp/") ||
        path.startsWith("src/guidance/"),
      path,
    );
  }
  for (const path of files.filter(
    (path) =>
      isWithin(join(ROOT, "pipelines"), path) ||
      isWithin(join(ROOT, "src/runner"), path),
  )) {
    const source = await readFile(path, "utf8");
    const sourcePath = relative(ROOT, path);
    // Init's Runner-owned publisher uses the capability as setup data. Other
    // runner modules and every pipeline role retain the instruction boundary.
    assert.doesNotMatch(
      source,
      sourcePath === "src/runner/setup.js"
        ? /OPERATOR_GUIDE\.md|guidance_read/u
        : /OPERATOR_GUIDE\.md|agent-runner\/rules\.md|guidance_(?:read|update)|createGuidanceService/u,
      sourcePath,
    );
  }
  const root = await import("../src/index.js");
  const guidance = await import("../src/guidance/index.js");
  assert.equal(root.createGuidanceService, guidance.createGuidanceService);
  assert.deepEqual(
    Object.keys(guidance).sort(),
    [
      "GuidanceError",
      "MAX_GUIDANCE_BYTES",
      "createGuidanceService",
      "guidanceContentRejection",
      "validateGuidanceContent",
    ].sort(),
  );
});

test("project configuration protection stays behind the config index and runner", async () => {
  const { imports } = await sourceImports();
  const configFiles = join(ROOT, "src/config/files.js");
  const consumers = imports
    .filter(
      ({ importer, specifier }) =>
        specifier.startsWith(".") &&
        resolve(dirname(importer), specifier) === configFiles,
    )
    .map(({ importer }) => relative(ROOT, importer));
  assert.deepEqual(consumers.sort(), [
    "src/config/index.js",
    "src/config/user-settings.js",
  ]);

  const runnerSource = await readFile(
    join(ROOT, "src/runner/service.js"),
    "utf8",
  );
  assert.match(
    runnerSource,
    /assertProjectConfigurationProtected[\s\S]*from "\.\.\/config\/index\.js"/u,
  );
  for (const pipeline of ["plan-authoring", "plan-execution", "polishing"]) {
    const sources = await walk(
      join(ROOT, "pipelines", pipeline, "src"),
      (path) => extname(path) === ".js",
    );
    for (const path of sources) {
      assert.doesNotMatch(
        await readFile(path, "utf8"),
        /projectConfigurationProtection|assertProjectConfigurationProtected/u,
        relative(ROOT, path),
      );
    }
  }
});

test("shared editor mechanics stay in root capabilities and outside MCP and pipelines", async () => {
  const { imports } = await sourceImports();
  const editorPath = join(ROOT, "src/editor.js");
  const consumers = [];
  for (const { importer, specifier } of imports) {
    if (
      specifier.startsWith(".") &&
      resolve(dirname(importer), specifier) === editorPath
    )
      consumers.push(relative(ROOT, importer));
  }
  assert.deepEqual(consumers.sort(), [
    "src/clarifications/service.js",
    "src/guidance/service.js",
    "src/index.js",
  ]);
  const root = await import("../src/index.js");
  const editor = await import("../src/editor.js");
  assert.equal(root.openConfiguredEditor, editor.openConfiguredEditor);
  assert.equal(root.EditorError, editor.EditorError);
});
