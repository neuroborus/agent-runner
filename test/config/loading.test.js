import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  appendFile,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  CONFIG_FILENAME,
  CONFIG_SCHEMA_VERSION,
  DEFAULT_ARTIFACT_ROOT,
  assertProjectConfigurationProtected,
  loadProjectConfiguration,
  loadRunnerConfiguration,
  parseRunnerConfiguration,
  PROJECT_CONFIG_FILENAME,
} from "../../src/config/index.js";
import { createGitService } from "../../src/git/index.js";

const executeFile = promisify(execFile);
const RUNNER_ROOT_URL = new URL("../../", import.meta.url);
const CONFIG_URL = new URL(CONFIG_FILENAME, RUNNER_ROOT_URL);

async function readIfPresent(path) {
  try {
    return await readFile(path, "utf8");
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return null;
    }
    throw cause;
  }
}

test("configuration loads from the runner root without reading the target", async (t) => {
  const projectPath = await mkdtemp(join(tmpdir(), "agent-runner-config-"));
  t.after(() => rm(projectPath, { recursive: true, force: true }));
  await writeFile(join(projectPath, CONFIG_FILENAME), '{"schemaVersion":2}\n');
  const source = await readIfPresent(CONFIG_URL);

  const configuration = await loadRunnerConfiguration();

  assert.deepEqual(
    configuration,
    source === null
      ? parseRunnerConfiguration(
          JSON.stringify({ schemaVersion: CONFIG_SCHEMA_VERSION }),
        )
      : parseRunnerConfiguration(source),
  );
  assert.equal(await readIfPresent(CONFIG_URL), source);
});

test("loads only ignored confined project configuration files", async (t) => {
  const projectPath = await mkdtemp(
    join(tmpdir(), "agent-runner-project-config-"),
  );
  const outsidePath = await mkdtemp(
    join(tmpdir(), "agent-runner-project-config-outside-"),
  );
  t.after(() => rm(projectPath, { recursive: true, force: true }));
  t.after(() => rm(outsidePath, { recursive: true, force: true }));
  await executeFile("git", ["init", "-q", projectPath]);
  await Promise.all([
    mkdir(join(projectPath, DEFAULT_ARTIFACT_ROOT)),
    mkdir(join(projectPath, "custom")),
  ]);
  await writeFile(
    join(projectPath, ".gitignore"),
    "/LOCAL_ARTIFACTS/\n/custom/\n",
  );
  const defaultPath = join(
    projectPath,
    DEFAULT_ARTIFACT_ROOT,
    PROJECT_CONFIG_FILENAME,
  );
  await writeFile(defaultPath, '{"schemaVersion":1,"artifactRoot":"custom"}\n');
  const runnerConfiguration = parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
  );
  const git = createGitService();

  const discovered = await loadProjectConfiguration({
    inspectPath: git.inspectPath,
    projectPath,
    runnerConfiguration,
  });
  assert.equal(discovered.path, defaultPath);
  assert.equal(discovered.configuration.artifactRoot, "custom");
  assert.equal(discovered.protection.schemaVersion, 1);
  assert.equal(discovered.protection.path, defaultPath);
  assert.equal(discovered.protection.projectPath, projectPath);
  assert.equal(
    discovered.protection.relativePath,
    `${DEFAULT_ARTIFACT_ROOT}/${PROJECT_CONFIG_FILENAME}`,
  );
  assert.match(discovered.protection.contentHash, /^[a-f0-9]{64}$/u);
  assert.equal(discovered.protection.ancestors[0].path, projectPath);
  await assertProjectConfigurationProtected({
    inspectPath: git.inspectPath,
    projectPath,
    protection: discovered.protection,
  });

  const explicitPath = join(projectPath, "custom", "runner.json");
  await writeFile(explicitPath, '{"schemaVersion":1}\n');
  assert.equal(
    (
      await loadProjectConfiguration({
        configurationPath: "custom/runner.json",
        inspectPath: git.inspectPath,
        projectPath,
        runnerConfiguration,
      })
    ).path,
    explicitPath,
  );

  const unignoredPath = join(projectPath, "project.json");
  await writeFile(unignoredPath, '{"schemaVersion":1}\n');
  await assert.rejects(
    loadProjectConfiguration({
      configurationPath: unignoredPath,
      inspectPath: git.inspectPath,
      projectPath,
      runnerConfiguration,
    }),
    (error) => error.code === "ERR_PROJECT_CONFIGURATION_NOT_IGNORED",
  );

  const outsideFile = join(outsidePath, "outside.json");
  await writeFile(outsideFile, '{"schemaVersion":1}\n');
  const linkedPath = join(projectPath, DEFAULT_ARTIFACT_ROOT, "linked.json");
  await symlink(outsideFile, linkedPath);
  await assert.rejects(
    loadProjectConfiguration({
      configurationPath: linkedPath,
      inspectPath: git.inspectPath,
      projectPath,
      runnerConfiguration,
    }),
    (error) => error.code === "ERR_UNSAFE_REPOSITORY_PATH",
  );
});

test("guards project configuration content, identity, links, and ancestors", async (t) => {
  async function fixture(name) {
    const projectPath = await mkdtemp(
      join(tmpdir(), `agent-runner-project-guard-${name}-`),
    );
    t.after(() => rm(projectPath, { recursive: true, force: true }));
    await executeFile("git", ["init", "-q", projectPath]);
    const directory = join(projectPath, "ignored");
    const path = join(directory, "runner.json");
    await mkdir(directory);
    await Promise.all([
      writeFile(join(projectPath, ".gitignore"), "/ignored/\n"),
      writeFile(path, '{"schemaVersion":1}\n'),
    ]);
    const git = createGitService();
    const loaded = await loadProjectConfiguration({
      configurationPath: path,
      inspectPath: git.inspectPath,
      projectPath,
      runnerConfiguration: parseRunnerConfiguration('{"schemaVersion":1}'),
    });
    return { directory, git, loaded, path, projectPath };
  }

  async function rejected(f) {
    await assert.rejects(
      assertProjectConfigurationProtected({
        inspectPath: f.git.inspectPath,
        projectPath: f.projectPath,
        protection: f.loaded.protection,
      }),
      (error) =>
        error.code === "ERR_PROJECT_CONFIGURATION_CHANGED" &&
        !error.message.includes(f.path),
    );
  }

  const content = await fixture("content");
  await writeFile(content.path, '{"schemaVersion":1,"artifactRoot":"new"}\n');
  await rejected(content);

  const replacement = await fixture("replacement");
  const replacementPath = join(replacement.directory, "replacement.json");
  await writeFile(replacementPath, '{"schemaVersion":1}\n');
  await rename(replacementPath, replacement.path);
  await rejected(replacement);

  const removed = await fixture("removed");
  await rm(removed.path);
  await rejected(removed);

  const ancestor = await fixture("ancestor");
  const movedDirectory = `${ancestor.directory}-moved`;
  await rename(ancestor.directory, movedDirectory);
  await symlink(movedDirectory, ancestor.directory);
  await rejected(ancestor);

  const hardLinked = await fixture("hard-link");
  await link(hardLinked.path, join(hardLinked.directory, "alias.json"));
  await rejected(hardLinked);
});

test("rejects link substitution between path inspection and confined reading", async (t) => {
  const projectPath = await mkdtemp(
    join(tmpdir(), "agent-runner-project-config-race-"),
  );
  t.after(() => rm(projectPath, { recursive: true, force: true }));
  await executeFile("git", ["init", "-q", projectPath]);
  const directory = join(projectPath, "ignored");
  const movedDirectory = `${directory}-moved`;
  const path = join(directory, "runner.json");
  await mkdir(directory);
  await Promise.all([
    writeFile(join(projectPath, ".gitignore"), "/ignored/\n"),
    writeFile(path, '{"schemaVersion":1}\n'),
  ]);
  const git = createGitService();

  await assert.rejects(
    loadProjectConfiguration({
      configurationPath: path,
      inspectPath: async (input) => {
        const inspection = await git.inspectPath(input);
        await rename(directory, movedDirectory);
        await symlink(movedDirectory, directory);
        return inspection;
      },
      projectPath,
      runnerConfiguration: parseRunnerConfiguration('{"schemaVersion":1}'),
    }),
    { code: "ERR_PROJECT_CONFIGURATION_READ" },
  );
});

test(
  "rejects an ignored project configuration FIFO without blocking",
  { skip: process.platform === "win32", timeout: 5_000 },
  async (t) => {
    const projectPath = await mkdtemp(
      join(tmpdir(), "agent-runner-project-config-fifo-"),
    );
    t.after(() => rm(projectPath, { recursive: true, force: true }));
    await executeFile("git", ["init", "-q", projectPath]);
    const artifactPath = join(projectPath, DEFAULT_ARTIFACT_ROOT);
    await mkdir(artifactPath);
    await writeFile(join(projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n");
    const configurationPath = join(artifactPath, "fifo.json");
    await executeFile("mkfifo", [configurationPath]);

    await assert.rejects(
      loadProjectConfiguration({
        configurationPath,
        inspectPath: createGitService().inspectPath,
        projectPath,
        runnerConfiguration: parseRunnerConfiguration(
          JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
        ),
      }),
      (error) => error.code === "ERR_PROJECT_CONFIGURATION_READ",
    );
  },
);

test(
  "rejects project configuration growth while loading",
  { timeout: 5_000 },
  async (t) => {
    const projectPath = await mkdtemp(
      join(tmpdir(), "agent-runner-project-config-growth-"),
    );
    t.after(() => rm(projectPath, { recursive: true, force: true }));
    await executeFile("git", ["init", "-q", projectPath]);
    const artifactPath = join(projectPath, DEFAULT_ARTIFACT_ROOT);
    await mkdir(artifactPath);
    await writeFile(join(projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n");
    const configurationPath = join(artifactPath, "growing.json");
    await writeFile(
      configurationPath,
      '{"schemaVersion":1}\n'.padEnd(900 * 1024, " "),
    );
    const git = createGitService();
    let growth;

    try {
      await assert.rejects(
        loadProjectConfiguration({
          configurationPath,
          inspectPath: async (options) => {
            const inspection = await git.inspectPath(options);
            growth = (async () => {
              for (let index = 0; index < 4; index += 1) {
                await appendFile(
                  configurationPath,
                  Buffer.alloc(64 * 1024, " "),
                );
                await new Promise((resolveGrowth) =>
                  setImmediate(resolveGrowth),
                );
              }
            })();
            return inspection;
          },
          projectPath,
          runnerConfiguration: parseRunnerConfiguration(
            JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
          ),
        }),
        (error) => error.code === "ERR_PROJECT_CONFIGURATION_READ",
      );
    } finally {
      await growth;
    }
  },
);
