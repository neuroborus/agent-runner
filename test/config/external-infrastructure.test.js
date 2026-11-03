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
import { join, relative } from "node:path";
import test from "node:test";

import {
  assertProjectConfigurationProtected,
  DEFAULT_ARTIFACT_ROOT,
  loadProjectConfiguration,
  parseProjectConfiguration,
  parseRunnerConfiguration,
} from "../../src/config/index.js";
import { createWorkspaceService } from "../../src/workspace/index.js";

const runnerConfiguration = parseRunnerConfiguration(
  '{"schemaVersion":1,"artifactRoot":"artifacts","defaultModel":"root"}',
);

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "runner-external-config-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const rootPath = join(root, "infrastructure");
  await Promise.all([mkdir(projectPath), mkdir(rootPath)]);
  const path = join(rootPath, "agent-runner.json");
  const infrastructure = {
    schemaVersion: 1,
    placement: "external",
    projectPath,
    rootPath,
  };
  const configuration = { schemaVersion: 1, infrastructure };
  const input = {
    projectPath,
    configurationPath: path,
    runnerConfiguration,
    inspectPath() {
      assert.fail("External configuration must not inspect target Git paths.");
    },
  };
  await writeFile(path, JSON.stringify(configuration));
  return {
    root,
    projectPath,
    rootPath,
    path,
    infrastructure,
    configuration,
    input,
  };
}

test("artifact paths apply runner defaults for sparse configuration in both placements", async (t) => {
  const f = await fixture(t);
  const integratedPath = join(f.projectPath, "project.json");
  await writeFile(integratedPath, '{"schemaVersion":1}\n');
  for (const [configurationPath, rootPath] of [
    [f.path, f.rootPath],
    [integratedPath, f.projectPath],
  ]) {
    const loaded = await loadProjectConfiguration({
      ...f.input,
      configurationPath,
      workspaceKind: "directory",
      inspectPath: createWorkspaceService().inspectPath,
      runnerConfiguration: { schemaVersion: 1 },
    });
    assert.equal(loaded.artifactPath, join(rootPath, DEFAULT_ARTIFACT_ROOT));
  }
});

test("explicit external configuration resolves resources without target writes or Git prerequisites", async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.projectPath, ".git"));
  const controlPath = join(f.projectPath, ".git", "config");
  await writeFile(controlPath, "Target control sentinel.\n");
  for (const workspaceKind of ["git", "directory"]) {
    const loaded = await loadProjectConfiguration({
      ...f.input,
      workspaceKind,
      configurationPath: relative(f.projectPath, f.path),
    });
    assert.deepEqual(loaded.infrastructure, f.infrastructure);
    assert.equal(loaded.artifactPath, join(f.rootPath, "artifacts"));
    assert.equal(loaded.protection.schemaVersion, 2);
    assert.equal(loaded.protection.infrastructureRoot, f.rootPath);
    assert.equal(loaded.protection.relativePath, "agent-runner.json");
    assert.equal(loaded.protection.projectAncestors.at(-1).path, f.projectPath);
    await assertProjectConfigurationProtected({
      ...f.input,
      workspaceKind,
      protection: loaded.protection,
    });
  }
  assert.deepEqual(await readdir(f.projectPath), [".git"]);
  assert.deepEqual(await readdir(join(f.projectPath, ".git")), ["config"]);
  assert.equal(
    await readFile(controlPath, "utf8"),
    "Target control sentinel.\n",
  );
  assert.equal(await readFile(f.path, "utf8"), JSON.stringify(f.configuration));
  const nestedPath = join(f.rootPath, "config", "selected.json");
  await mkdir(join(f.rootPath, "config"));
  await rename(f.path, nestedPath);
  const nested = await loadProjectConfiguration({
    ...f.input,
    configurationPath: nestedPath,
  });
  assert.equal(nested.artifactPath, join(f.rootPath, "artifacts"));
  assert.equal(nested.protection.relativePath, "config/selected.json");
});

test("external selectors and target, root and placement declarations must agree", async (t) => {
  const f = await fixture(t);
  const bindings = [
    undefined,
    { ...f.infrastructure, projectPath: join(f.root, "other") },
    { ...f.infrastructure, placement: "integrated" },
    { ...f.infrastructure, rootPath: f.projectPath },
    { ...f.infrastructure, rootPath: f.root },
    { ...f.infrastructure, rootPath: join(f.root, "other") },
  ];
  for (const infrastructure of bindings) {
    await writeFile(
      f.path,
      JSON.stringify({ schemaVersion: 1, infrastructure }),
    );
    await assert.rejects(loadProjectConfiguration(f.input), {
      code: "ERR_PROJECT_CONFIGURATION_BINDING",
    });
  }
  const integratedPath = join(f.projectPath, "project.json");
  await writeFile(integratedPath, JSON.stringify(f.configuration));
  await assert.rejects(
    loadProjectConfiguration({
      ...f.input,
      workspaceKind: "directory",
      inspectPath: createWorkspaceService().inspectPath,
      configurationPath: integratedPath,
    }),
    { code: "ERR_PROJECT_CONFIGURATION_BINDING" },
  );
});

test("placement bindings are strict project-only data with no additional authority", () => {
  const infrastructure = {
    schemaVersion: 1,
    placement: "external",
    projectPath: "/workspace/project",
    rootPath: "/workspace/infrastructure",
  };
  for (const binding of [
    null,
    { ...infrastructure, schemaVersion: 2 },
    { ...infrastructure, placement: "automatic" },
    { ...infrastructure, rootPath: "relative" },
    { ...infrastructure, projectPath: "/workspace/project/../other" },
    { ...infrastructure, environment: {} },
  ]) {
    assert.throws(
      () =>
        parseProjectConfiguration(
          JSON.stringify({ schemaVersion: 1, infrastructure: binding }),
          runnerConfiguration,
        ),
      { code: "ERR_INVALID_CONFIGURATION" },
    );
  }
  assert.throws(
    () =>
      parseRunnerConfiguration(
        JSON.stringify({ schemaVersion: 1, infrastructure }),
      ),
    { code: "ERR_INVALID_CONFIGURATION" },
  );
  for (const field of [
    "profiles",
    "credentials",
    "environment",
    "providerBinary",
    "update",
  ]) {
    assert.throws(
      () =>
        parseProjectConfiguration(
          JSON.stringify({ schemaVersion: 1, infrastructure, [field]: {} }),
          runnerConfiguration,
        ),
      { code: "ERR_INVALID_CONFIGURATION" },
    );
  }
});

test("integrated discovery remains local and explicit selections never merge competing placements", async (t) => {
  const f = await fixture(t);
  const input = {
    ...f.input,
    workspaceKind: "directory",
    inspectPath: createWorkspaceService().inspectPath,
    configurationPath: undefined,
  };
  assert.equal(await loadProjectConfiguration(input), null);
  const artifactPath = join(f.projectPath, "LOCAL_ARTIFACTS");
  await mkdir(artifactPath);
  await writeFile(
    join(artifactPath, "agent-runner.json"),
    JSON.stringify({
      schemaVersion: 1,
      defaultModel: "integrated",
      artifactRoot: "local",
      infrastructure: {
        ...f.infrastructure,
        placement: "integrated",
        rootPath: f.projectPath,
      },
    }),
  );
  const integrated = await loadProjectConfiguration(input);
  assert.equal(integrated.configuration.defaultModel, "integrated");
  assert.equal(integrated.artifactPath, join(f.projectPath, "local"));
  assert.equal(integrated.protection.schemaVersion, 1);
  const external = await loadProjectConfiguration({
    ...input,
    configurationPath: f.path,
  });
  assert.equal(external.configuration.defaultModel, undefined);
  assert.equal(external.artifactPath, join(f.rootPath, "artifacts"));
});

test("external configuration guards reject content, identity and target or infrastructure substitution", async (t) => {
  const mutations = {
    content: async (f) =>
      writeFile(
        f.path,
        JSON.stringify({ ...f.configuration, defaultModel: "changed" }),
      ),
    replacement: async (f) => {
      const replacement = join(f.rootPath, "replacement.json");
      await writeFile(replacement, JSON.stringify(f.configuration));
      await rename(replacement, f.path);
    },
    removal: async (f) => rm(f.path),
    hardlink: async (f) => link(f.path, join(f.rootPath, "alias.json")),
    infrastructure: async (f) => {
      await rename(f.rootPath, `${f.rootPath}-original`);
      await mkdir(f.rootPath);
      await writeFile(f.path, JSON.stringify(f.configuration));
    },
    ancestorLink: async (f) => {
      await rename(f.rootPath, `${f.rootPath}-original`);
      await symlink(`${f.rootPath}-original`, f.rootPath);
    },
    target: async (f) => {
      await rename(f.projectPath, `${f.projectPath}-original`);
      await mkdir(f.projectPath);
    },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    await t.test(name, async (t) => {
      const f = await fixture(t);
      const loaded = await loadProjectConfiguration(f.input);
      await mutate(f);
      await assert.rejects(
        assertProjectConfigurationProtected({
          ...f.input,
          protection: loaded.protection,
        }),
        (error) =>
          error.code === "ERR_PROJECT_CONFIGURATION_CHANGED" &&
          !error.message.includes(f.path),
      );
    });
  }
});

test("external loading rejects linked files and real-directory aliases before accepting a binding", async (t) => {
  const f = await fixture(t);
  await link(f.path, join(f.rootPath, "alias.json"));
  await assert.rejects(loadProjectConfiguration(f.input), {
    code: "ERR_PROJECT_CONFIGURATION_READ",
  });
  await rm(join(f.rootPath, "alias.json"));
  await rename(f.rootPath, `${f.rootPath}-original`);
  await symlink(`${f.rootPath}-original`, f.rootPath);
  await assert.rejects(loadProjectConfiguration(f.input), {
    code: "ERR_PROJECT_CONFIGURATION_READ",
  });
});
