import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  CONFIG_FILENAME,
  CONFIG_SCHEMA_VERSION,
  ConfigurationError,
  loadRepositoryConfiguration,
  parseRepositoryConfiguration,
  resolvePipelineConfiguration,
} from "../src/index.js";

const EXAMPLE_URL = new URL("../.agent-runner.example.json", import.meta.url);

test("tracked example is valid and local configuration is ignored", async () => {
  const [source, gitignore] = await Promise.all([
    readFile(EXAMPLE_URL, "utf8"),
    readFile(new URL("../.gitignore", import.meta.url), "utf8"),
  ]);
  const configuration = parseRepositoryConfiguration(source);

  assert.equal(CONFIG_FILENAME, ".agent-runner.json");
  assert.equal(CONFIG_SCHEMA_VERSION, 1);
  assert.equal(configuration.defaultBackend, "codex");
  assert.deepEqual(configuration.pipelines["plan-authoring"].roles.reviewer, {
    backend: "claude",
    model: "sonnet",
  });
  assert.deepEqual(
    configuration.pipelines["plan-authoring"].roles.arbiter,
    {},
  );
  assert.match(gitignore, /^\/\.agent-runner\.json$/mu);
  assert.ok(Object.isFrozen(configuration));
  assert.ok(Object.isFrozen(configuration.pipelines));
  assert.ok(Object.isFrozen(configuration.pipelines["plan-authoring"]));
  assert.ok(
    Object.isFrozen(configuration.pipelines["plan-authoring"].roles.reviewer),
  );
});

test("absent configuration uses pipeline-owned setting defaults", async (t) => {
  const projectPath = await mkdtemp(join(tmpdir(), "agent-runner-config-"));
  t.after(() => rm(projectPath, { recursive: true, force: true }));

  const configuration = await loadRepositoryConfiguration(projectPath);

  assert.equal(configuration.defaultBackend, undefined);
  assert.deepEqual(configuration.pipelines["plan-authoring"], {
    maxRevisionRounds: 15,
    stagnationWindowRounds: 3,
    roles: {},
  });
  assert.deepEqual(configuration.pipelines["plan-execution"], {
    maxFixRoundsPerStep: 5,
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
  ];

  for (const [source, expectedMessage] of invalidConfigurations) {
    assert.throws(
      () => parseRepositoryConfiguration(source),
      (error) =>
        error instanceof ConfigurationError &&
        expectedMessage.test(error.message),
      source,
    );
  }
  assert.throws(
    () => parseRepositoryConfiguration({ schemaVersion: 1 }),
    /source must be a string/u,
  );
});

test("invalid files are rejected without being rewritten", async (t) => {
  const projectPath = await mkdtemp(join(tmpdir(), "agent-runner-config-"));
  const configurationPath = join(projectPath, CONFIG_FILENAME);
  const source = '{"schemaVersion":2}\n';
  t.after(() => rm(projectPath, { recursive: true, force: true }));
  await writeFile(configurationPath, source);

  await assert.rejects(
    loadRepositoryConfiguration(projectPath),
    (error) =>
      error instanceof ConfigurationError &&
      error.code === "ERR_UNSUPPORTED_CONFIGURATION_VERSION",
  );
  assert.equal(await readFile(configurationPath, "utf8"), source);
});

test("role resolution applies CLI, role, repository, and native defaults", () => {
  const configuration = parseRepositoryConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      pipelines: {
        "plan-execution": {
          maxFixRoundsPerStep: 8,
          roles: {
            worker: { backend: "claude", model: "repo-worker" },
            reviewer: { backend: "claude", model: "repo-reviewer" },
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
    worker: { backend: "codex", model: "cli-worker" },
    reviewer: { backend: "claude", model: "repo-reviewer" },
    arbiter: { backend: "codex", model: null },
  });
  assert.deepEqual(resolved.settings, {
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
    pipelineId: "plan-authoring",
    roles: {
      planner: { backend: "codex", model: null },
      reviewer: { backend: "codex", model: null },
      arbiter: { backend: "codex", model: null },
    },
    settings: {
      maxRevisionRounds: 4,
      stagnationWindowRounds: 3,
    },
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

test("role resolution rejects missing backends and invalid overrides", () => {
  const configuration = parseRepositoryConfiguration(
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
  assert.match(agents, /`src\/config\.js`/u);
});
