import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  appendFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
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
