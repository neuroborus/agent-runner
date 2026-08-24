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
  ConfigurationError,
  createGitService,
  DEFAULT_ARTIFACT_ROOT,
  loadProjectConfiguration,
  loadRunnerConfiguration,
  parseProjectConfiguration,
  parseRunnerConfiguration,
  PROJECT_CONFIG_FILENAME,
  resolvePipelineConfiguration,
} from "../src/index.js";

const executeFile = promisify(execFile);

const RUNNER_ROOT_URL = new URL("../", import.meta.url);
const EXAMPLE_URL = new URL(".agent-runner.example.json", RUNNER_ROOT_URL);
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

test("tracked example is valid and local configuration is ignored", async () => {
  const [source, gitignore] = await Promise.all([
    readFile(EXAMPLE_URL, "utf8"),
    readFile(new URL(".gitignore", RUNNER_ROOT_URL), "utf8"),
  ]);
  const configuration = parseRunnerConfiguration(source);

  assert.equal(CONFIG_FILENAME, ".agent-runner.json");
  assert.equal(CONFIG_SCHEMA_VERSION, 1);
  assert.equal(configuration.artifactRoot, "LOCAL_ARTIFACTS");
  assert.equal(configuration.defaultBackend, "codex");
  assert.equal(configuration.defaultProfile, "current");
  assert.equal(configuration.defaultModel, "current");
  assert.equal(configuration.defaultContextSize, "current");
  assert.deepEqual(configuration.pipelines["plan-authoring"].roles.reviewer, {
    backend: "claude",
    profile: "claude-primary",
    model: "sonnet",
  });
  assert.deepEqual(
    configuration.pipelines["plan-authoring"].roles.arbiter,
    {},
  );
  assert.deepEqual(configuration.pipelines.polishing.roles.reviewer, {
    backend: "claude",
    profile: "claude-primary",
    model: "current",
    contextSize: "current",
  });
  assert.equal(configuration.pipelines["plan-execution"].finalization, "auto");
  assert.equal(configuration.pipelines.polishing.finalization, "auto");
  assert.match(gitignore, /^\/\.agent-runner\.json$/mu);
  assert.ok(Object.isFrozen(configuration));
  assert.ok(Object.isFrozen(configuration.pipelines));
  assert.ok(Object.isFrozen(configuration.pipelines["plan-authoring"]));
  assert.ok(
    Object.isFrozen(configuration.pipelines["plan-authoring"].roles.reviewer),
  );
});

test("minimal configuration uses pipeline-owned setting defaults", () => {
  const configuration = parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: CONFIG_SCHEMA_VERSION }),
  );

  assert.equal(configuration.defaultBackend, undefined);
  assert.equal(configuration.artifactRoot, DEFAULT_ARTIFACT_ROOT);
  assert.deepEqual(configuration.profiles, {});
  assert.deepEqual(configuration.pipelines["plan-authoring"], {
    maxRevisionRounds: 15,
    stagnationWindowRounds: 3,
    roles: {},
  });
  assert.deepEqual(configuration.pipelines["plan-execution"], {
    finalization: "auto",
    maxFixRoundsPerStep: 5,
    maxDisputesPerFinding: 2,
    maxSameFindingRounds: 3,
    stagnationWindowRounds: 3,
    roles: {},
  });
  assert.deepEqual(configuration.pipelines.polishing, {
    finalization: "auto",
    maxFixRounds: 5,
    maxDisputesPerFinding: 2,
    maxSameFindingRounds: 3,
    stagnationWindowRounds: 3,
    roles: {},
  });
});

test("configuration rejects unsupported shapes and values", () => {
  const invalidConfigurations = [
    ["not json", /valid JSON/u],
    ["[]", /configuration must be an object/u],
    ["{}", /schemaVersion is required/u],
    ['{"schemaVersion":2}', /Unsupported configuration\.schemaVersion/u],
    ['{"schemaVersion":1,"extra":true}', /configuration\.extra/u],
    ['{"schemaVersion":1,"defaultBackend":null}', /defaultBackend/u],
    ['{"schemaVersion":1,"defaultBackend":"other"}', /codex, claude/u],
    ['{"schemaVersion":1,"artifactRoot":"."}', /artifactRoot/u],
    ['{"schemaVersion":1,"artifactRoot":"../outside"}', /artifactRoot/u],
    ['{"schemaVersion":1,"artifactRoot":".git/config"}', /artifactRoot/u],
    ['{"schemaVersion":1,"defaultProfile":null}', /defaultProfile/u],
    [
      '{"schemaVersion":1,"defaultProfile":"missing"}',
      /defaultProfile selects unknown profile/u,
    ],
    ['{"schemaVersion":1,"profiles":[]}', /profiles must be an object/u],
    [
      '{"schemaVersion":1,"profiles":{"current":{"backend":"codex","profile":"work"}}}',
      /profile names/u,
    ],
    [
      '{"schemaVersion":1,"profiles":{"codex-work":{"backend":"codex","configDirectory":"/profiles/work"}}}',
      /configDirectory/u,
    ],
    [
      '{"schemaVersion":1,"profiles":{"claude-work":{"backend":"claude","configDirectory":"relative"}}}',
      /absolute normalized path/u,
    ],
    ['{"schemaVersion":1,"pipelines":null}', /pipelines must be an object/u],
    ['{"schemaVersion":1,"pipelines":[]}', /pipelines must be an object/u],
    [
      '{"schemaVersion":1,"pipelines":{"unknown":{}}}',
      /pipelines\.unknown/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"extra":1}}}',
      /plan-authoring\.extra/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":null}}',
      /plan-authoring must be an object/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"maxRevisionRounds":0}}}',
      /maxRevisionRounds must be a positive integer/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"maxRevisionRounds":null}}}',
      /maxRevisionRounds must be a positive integer/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"stagnationWindowRounds":0}}}',
      /stagnationWindowRounds must be a positive integer/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-execution":{"maxFixRoundsPerStep":1.5}}}',
      /maxFixRoundsPerStep must be a positive integer/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-execution":{"finalization":1}}}',
      /finalization must be auto, none/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-execution":{"finalization":"../SKILL.md"}}}',
      /finalization must be auto, none/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"polishing":{"finalization":"checks/finalize.md"}}}',
      /finalization must be auto, none/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-execution":{"maxDisputesPerFinding":0}}}',
      /maxDisputesPerFinding must be a positive integer/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-execution":{"maxSameFindingRounds":0}}}',
      /maxSameFindingRounds must be a positive integer/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-execution":{"stagnationWindowRounds":0}}}',
      /stagnationWindowRounds must be a positive integer/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"polishing":{"maxFixRounds":0}}}',
      /maxFixRounds must be a positive integer/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"polishing":{"maxDisputesPerFinding":0}}}',
      /maxDisputesPerFinding must be a positive integer/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"roles":[]}}}',
      /roles must be an object/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"roles":null}}}',
      /roles must be an object/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"roles":{"worker":{}}}}}',
      /roles\.worker/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"roles":{"planner":"codex"}}}}',
      /roles\.planner must be an object/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"roles":{"planner":{"extra":true}}}}}',
      /roles\.planner\.extra/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"roles":{"planner":{"backend":"other"}}}}}',
      /planner\.backend/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"roles":{"planner":{"model":"  "}}}}}',
      /planner\.model/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"roles":{"planner":{"model":null}}}}}',
      /planner\.model/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"roles":{"planner":{"contextSize":null}}}}}',
      /planner\.contextSize/u,
    ],
  ];

  for (const [source, expectedMessage] of invalidConfigurations) {
    assert.throws(
      () => parseRunnerConfiguration(source),
      (error) =>
        error instanceof ConfigurationError &&
        expectedMessage.test(error.message),
      source,
    );
  }
  assert.throws(
    () => parseRunnerConfiguration({ schemaVersion: 1 }),
    /source must be a string/u,
  );
});

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

test("invalid configuration is rejected", () => {
  assert.throws(
    () => parseRunnerConfiguration('{"schemaVersion":2}\n'),
    (error) =>
      error instanceof ConfigurationError &&
      error.code === "ERR_UNSUPPORTED_CONFIGURATION_VERSION",
  );
});

test("role resolution applies CLI, role, runner, and native defaults", () => {
  const configuration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      pipelines: {
        "plan-execution": {
          maxFixRoundsPerStep: 8,
          roles: {
            worker: { backend: "claude", model: "runner-worker" },
            reviewer: { backend: "claude", model: "runner-reviewer" },
          },
        },
      },
    }),
  );

  const resolved = resolvePipelineConfiguration(
    "plan-execution",
    configuration,
    {
      worker: { backend: "codex", model: "cli-worker" },
    },
  );

  assert.deepEqual(resolved.roles, {
    worker: {
      backend: "codex",
      profile: "current",
      model: "cli-worker",
      contextSize: "current",
    },
    reviewer: {
      backend: "claude",
      profile: "current",
      model: "runner-reviewer",
      contextSize: "current",
    },
    arbiter: {
      backend: "codex",
      profile: "current",
      model: "current",
      contextSize: "current",
    },
  });
  assert.deepEqual(resolved.settings, {
    finalization: "auto",
    maxFixRoundsPerStep: 8,
    maxDisputesPerFinding: 2,
    maxSameFindingRounds: 3,
    stagnationWindowRounds: 3,
  });
  assert.ok(Object.isFrozen(resolved));
  assert.ok(Object.isFrozen(resolved.roles));
  assert.ok(Object.isFrozen(resolved.settings));
});

test("role resolution normalizes configuration objects", () => {
  const resolved = resolvePipelineConfiguration("plan-authoring", {
    schemaVersion: 1,
    defaultBackend: "codex",
    pipelines: {
      "plan-authoring": {
        maxRevisionRounds: 4,
      },
    },
  });

  assert.deepEqual(resolved, {
    artifactRoot: "LOCAL_ARTIFACTS",
    pipelineId: "plan-authoring",
    roles: {
      planner: {
        backend: "codex",
        profile: "current",
        model: "current",
        contextSize: "current",
      },
      reviewer: {
        backend: "codex",
        profile: "current",
        model: "current",
        contextSize: "current",
      },
      arbiter: {
        backend: "codex",
        profile: "current",
        model: "current",
        contextSize: "current",
      },
    },
    settings: {
      maxRevisionRounds: 4,
      stagnationWindowRounds: 3,
    },
    sourceProfile: null,
  });
  assert.throws(
    () =>
      resolvePipelineConfiguration("plan-authoring", {
        schemaVersion: 1,
        defaultBackend: "other",
      }),
    /defaultBackend/u,
  );
});

test("project configuration is a strict partial overlay", () => {
  const runnerConfiguration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      artifactRoot: "runner-artifacts",
      defaultBackend: "codex",
      defaultModel: "runner-model",
      profiles: {
        "claude-primary": {
          backend: "claude",
          configDirectory: "/profiles/claude-primary",
        },
      },
      pipelines: {
        polishing: {
          finalization: ".agents/skills/release/SKILL.md",
          maxFixRounds: 8,
          roles: { reviewer: { model: "runner-reviewer" } },
        },
      },
    }),
  );
  const projectConfiguration = parseProjectConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      artifactRoot: "project-artifacts",
      defaultProfile: "claude-primary",
      defaultModel: "project-model",
      pipelines: {
        polishing: {
          finalization: "none",
          maxFixRounds: 3,
          roles: {
            worker: { model: "project-worker" },
            reviewer: { contextSize: "200000" },
          },
        },
      },
    }),
    runnerConfiguration,
  );

  const resolved = resolvePipelineConfiguration(
    "polishing",
    runnerConfiguration,
    { worker: { model: "cli-worker" } },
    { contextSize: "300000" },
    null,
    projectConfiguration,
  );

  assert.equal(resolved.artifactRoot, "project-artifacts");
  assert.equal(resolved.settings.finalization, "none");
  assert.equal(resolved.settings.maxFixRounds, 3);
  assert.deepEqual(resolved.roles.worker, {
    backend: "claude",
    profile: "/profiles/claude-primary",
    model: "cli-worker",
    contextSize: "300000",
  });
  assert.deepEqual(resolved.roles.reviewer, {
    backend: "claude",
    profile: "/profiles/claude-primary",
    model: "project-model",
    contextSize: "300000",
  });
});

test("project configuration rejects untrusted and unsafe fields", () => {
  const runnerConfiguration = parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
  );
  const invalidConfigurations = [
    [{ profiles: {} }, /profiles/u],
    [{ credentials: {} }, /credentials/u],
    [{ binary: "/usr/bin/codex" }, /binary/u],
    [{ environment: {} }, /environment/u],
    [{ pipelines: null }, /pipelines must be an object/u],
    [{ artifactRoot: "/outside" }, /artifactRoot/u],
    [{ artifactRoot: "C:/outside" }, /artifactRoot/u],
    [{ artifactRoot: "nested/../outside" }, /artifactRoot/u],
    [{ defaultProfile: "untrusted" }, /unknown trusted profile/u],
    [
      { pipelines: { polishing: { roles: { worker: { env: {} } } } } },
      /worker\.env/u,
    ],
  ];

  for (const [input, message] of invalidConfigurations) {
    assert.throws(
      () =>
        parseProjectConfiguration(
          JSON.stringify({ schemaVersion: 1, ...input }),
          runnerConfiguration,
        ),
      message,
    );
  }
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
  await writeFile(
    defaultPath,
    '{"schemaVersion":1,"artifactRoot":"custom"}\n',
  );
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
    await writeFile(
      join(projectPath, ".gitignore"),
      "/LOCAL_ARTIFACTS/\n",
    );
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

test("trusted profiles pin backends and resolve execution precedence", () => {
  const configuration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      profiles: {
        "codex-work": { backend: "codex", profile: "native-work" },
        "claude-primary": {
          backend: "claude",
          configDirectory: "/profiles/claude-primary",
        },
      },
      defaultProfile: "codex-work",
      defaultModel: "runner-model",
      defaultContextSize: "200000",
      pipelines: {
        polishing: {
          roles: {
            reviewer: {
              profile: "claude-primary",
              model: "review-model",
              contextSize: "300000",
            },
          },
        },
      },
    }),
  );

  const resolved = resolvePipelineConfiguration(
    "polishing",
    configuration,
    {
      worker: { model: "role-model", contextSize: "400000" },
    },
    { model: "run-model", contextSize: "350000" },
  );

  assert.deepEqual(resolved.roles, {
    worker: {
      backend: "codex",
      profile: "native-work",
      model: "role-model",
      contextSize: "400000",
    },
    reviewer: {
      backend: "claude",
      profile: "/profiles/claude-primary",
      model: "run-model",
      contextSize: "350000",
    },
    arbiter: {
      backend: "codex",
      profile: "native-work",
      model: "run-model",
      contextSize: "350000",
    },
  });
});

test("source profiles inherit safely while unknown source profiles stay current", () => {
  const configuration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      profiles: {
        "claude-primary": {
          backend: "claude",
          configDirectory: "/profiles/claude-primary",
        },
        "codex-arbiter": { backend: "codex", profile: "arbiter" },
      },
      pipelines: {
        "plan-authoring": {
          roles: { arbiter: { profile: "codex-arbiter" } },
        },
      },
    }),
  );
  const source = {
    backend: "claude",
    id: "opaque:source:id",
    profile: "claude-primary",
  };

  const resolved = resolvePipelineConfiguration(
    "plan-authoring",
    configuration,
    {},
    {},
    source,
  );
  assert.equal(resolved.sourceProfile, "claude-primary");
  assert.equal(resolved.roles.planner.profile, "/profiles/claude-primary");
  assert.equal(resolved.roles.reviewer.profile, "/profiles/claude-primary");
  assert.deepEqual(resolved.roles.arbiter, {
    backend: "codex",
    profile: "arbiter",
    model: "current",
    contextSize: "current",
  });

  const unknownProfile = resolvePipelineConfiguration(
    "plan-authoring",
    { schemaVersion: 1 },
    {
      planner: { backend: "claude" },
      reviewer: { backend: "claude" },
      arbiter: { backend: "codex" },
    },
    {},
    { backend: "claude", id: "opaque" },
  );
  assert.equal(unknownProfile.sourceProfile, null);
  assert.equal(unknownProfile.roles.planner.profile, "current");
  assert.equal(unknownProfile.roles.reviewer.profile, "current");
  assert.equal(unknownProfile.roles.planner.backend, "claude");
});

test("profile and source conflicts fail closed", () => {
  const configuration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      profiles: {
        "claude-primary": {
          backend: "claude",
          configDirectory: "/profiles/claude-primary",
        },
        "codex-work": { backend: "codex", profile: "work" },
      },
    }),
  );

  assert.throws(
    () =>
      resolvePipelineConfiguration("polishing", configuration, {
        worker: { backend: "codex", profile: "claude-primary" },
      }),
    (error) => error.code === "ERR_PROFILE_BACKEND_MISMATCH",
  );
  assert.throws(
    () =>
      resolvePipelineConfiguration(
        "polishing",
        configuration,
        { worker: { profile: "codex-work" } },
        {},
        { backend: "claude", id: "opaque" },
      ),
    (error) => error.code === "ERR_SOURCE_PROFILE_MISMATCH",
  );
  assert.throws(
    () =>
      resolvePipelineConfiguration(
        "polishing",
        configuration,
        {},
        {},
        {
          backend: "codex",
          id: "opaque",
          profile: "claude-primary",
        },
      ),
    (error) => error.code === "ERR_SOURCE_PROFILE_BACKEND_MISMATCH",
  );
});

test("role resolution rejects missing backends and invalid overrides", () => {
  const configuration = parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: 1 }),
  );

  assert.throws(
    () => resolvePipelineConfiguration("plan-authoring", configuration),
    (error) =>
      error instanceof ConfigurationError &&
      error.code === "ERR_MISSING_ROLE_BACKEND",
  );
  assert.throws(
    () =>
      resolvePipelineConfiguration("plan-authoring", configuration, {
        worker: { backend: "codex" },
      }),
    /roleOverrides\.worker/u,
  );
  assert.throws(
    () =>
      resolvePipelineConfiguration("plan-authoring", configuration, {
        planner: { backend: "other" },
      }),
    /roleOverrides\.planner\.backend/u,
  );
  assert.throws(
    () =>
      resolvePipelineConfiguration("plan-authoring", configuration, {
        planner: null,
      }),
    /roleOverrides\.planner must be an object/u,
  );
  assert.throws(
    () => resolvePipelineConfiguration("unknown", configuration),
    (error) =>
      error instanceof ConfigurationError &&
      error.code === "ERR_UNKNOWN_PIPELINE",
  );
});

test("configuration ownership and defaults are documented", async () => {
  const [
    readme,
    architecture,
    authoringSpecification,
    executionSpecification,
    polishingSpecification,
    agents,
  ] = await Promise.all([
    readFile(new URL("../README.md", import.meta.url), "utf8"),
    readFile(new URL("../docs/ARCHITECTURE.md", import.meta.url), "utf8"),
    readFile(
      new URL("../pipelines/plan-authoring/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../pipelines/plan-execution/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../pipelines/polishing/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../AGENTS.md", import.meta.url), "utf8"),
  ]);

  assert.match(readme, /roles, configuration settings and defaults/u);
  assert.match(architecture, /\.agent-runner\.json/u);
  assert.match(architecture, /CLI override/u);
  assert.match(architecture, /native default/u);
  assert.match(authoringSpecification, /maxRevisionRounds = 15/u);
  assert.match(authoringSpecification, /stagnationWindowRounds = 3/u);
  assert.match(executionSpecification, /maxFixRoundsPerStep = 5/u);
  assert.match(executionSpecification, /maxDisputesPerFinding = 2/u);
  assert.match(executionSpecification, /maxSameFindingRounds = 3/u);
  assert.match(executionSpecification, /stagnationWindowRounds = 3/u);
  assert.match(polishingSpecification, /maxFixRounds = 5/u);
  assert.match(polishingSpecification, /maxDisputesPerFinding = 2/u);
  assert.match(polishingSpecification, /maxSameFindingRounds = 3/u);
  assert.match(polishingSpecification, /stagnationWindowRounds = 3/u);
  assert.match(agents, /`src\/config\.js`/u);
});
