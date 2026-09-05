import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CONFIG_FILENAME,
  CONFIG_SCHEMA_VERSION,
  ConfigurationError,
  DEFAULT_ARTIFACT_ROOT,
  parseProjectConfiguration,
  parseRunnerConfiguration,
} from "../../src/config/index.js";

const RUNNER_ROOT_URL = new URL("../../", import.meta.url);
const EXAMPLE_URL = new URL(".agent-runner.example.json", RUNNER_ROOT_URL);

test("tracked example is valid and local configuration is ignored", async () => {
  const [source, gitignore] = await Promise.all([
    readFile(EXAMPLE_URL, "utf8"),
    readFile(new URL(".gitignore", RUNNER_ROOT_URL), "utf8"),
  ]);
  const configuration = parseRunnerConfiguration(source);

  assert.equal(CONFIG_FILENAME, ".agent-runner.json");
  assert.equal(CONFIG_SCHEMA_VERSION, 1);
  assert.equal(configuration.artifactRoot, "LOCAL_ARTIFACTS");
  assert.equal(configuration.issueReporting, true);
  assert.equal(configuration.defaultBackend, "codex");
  assert.equal(configuration.defaultProfile, "current");
  assert.equal(configuration.defaultModel, "current");
  assert.equal(configuration.defaultContextSize, "current");
  assert.deepEqual(configuration.trustedCommands, {});
  assert.equal(configuration.pipelines["plan-authoring"].mode, "independent");
  assert.equal(configuration.pipelines["plan-execution"].mode, "independent");
  assert.equal(configuration.pipelines.polishing.mode, "independent");
  assert.deepEqual(configuration.pipelines["plan-authoring"].roles.reviewer, {
    backend: "claude",
    profile: "claude-primary",
    model: "sonnet",
  });
  assert.deepEqual(configuration.pipelines["plan-authoring"].roles.arbiter, {});
  assert.deepEqual(configuration.pipelines.polishing.roles.reviewer, {
    backend: "claude",
    profile: "claude-primary",
    model: "current",
    contextSize: "current",
  });
  assert.equal(configuration.pipelines["plan-execution"].finalization, "auto");
  assert.equal(configuration.pipelines.polishing.finalization, "auto");
  assert.deepEqual(configuration.pipelines.polishing.trustedChecks, []);
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
  assert.equal(configuration.issueReporting, true);
  assert.deepEqual(configuration.profiles, {});
  assert.deepEqual(configuration.trustedCommands, {});
  assert.deepEqual(configuration.pipelines["plan-authoring"], {
    maxRevisionRounds: 15,
    mode: "independent",
    stagnationWindowRounds: 3,
    roles: {},
  });
  assert.deepEqual(configuration.pipelines["plan-execution"], {
    finalization: "auto",
    maxFixRoundsPerStep: 5,
    maxDisputesPerFinding: 2,
    maxSameFindingRounds: 3,
    mode: "independent",
    stagnationWindowRounds: 3,
    trustedChecks: [],
    roles: {},
  });
  assert.deepEqual(configuration.pipelines.polishing, {
    finalization: "auto",
    maxFixRounds: 5,
    maxDisputesPerFinding: 2,
    maxSameFindingRounds: 3,
    mode: "independent",
    stagnationWindowRounds: 3,
    trustedChecks: [],
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
    ['{"schemaVersion":1,"issueReporting":"yes"}', /issueReporting/u],
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
      '{"schemaVersion":1,"trustedCommands":[]}',
      /trustedCommands must be an object/u,
    ],
    [
      '{"schemaVersion":1,"trustedCommands":{"service":{"command":"npm test","executable":"npm","arguments":["test"],"environment":{}}}}',
      /Trusted command service is invalid/u,
    ],
    [
      '{"schemaVersion":1,"trustedCommands":{"service":{"command":"npm\\ttest","executable":"npm","arguments":["test"]}}}',
      /Trusted command service command is invalid/u,
    ],
    [
      '{"schemaVersion":1,"trustedCommands":{"service":{"command":"npm test","executable":"npm","arguments":["--flag\\tvalue"]}}}',
      /Trusted command service argument 1 is invalid/u,
    ],
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
    ['{"schemaVersion":1,"pipelines":{"unknown":{}}}', /pipelines\.unknown/u],
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
      '{"schemaVersion":1,"pipelines":{"plan-authoring":{"mode":"automatic"}}}',
      /mode must be independent or lazy/u,
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
      '{"schemaVersion":1,"pipelines":{"plan-execution":{"mode":"automatic"}}}',
      /mode must be independent or lazy/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"polishing":{"finalization":"checks/finalize.md"}}}',
      /finalization must be auto, none/u,
    ],
    [
      '{"schemaVersion":1,"pipelines":{"polishing":{"mode":"automatic"}}}',
      /mode must be independent or lazy/u,
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

test("configuration accepts 256 trusted command definitions", () => {
  const trustedCommands = Object.fromEntries(
    Array.from({ length: 256 }, (_, index) => [
      `check-${index + 1}`,
      {
        command: `node validation-${index + 1}.js`,
        executable: "node",
        arguments: [`validation-${index + 1}.js`],
      },
    ]),
  );

  const configuration = parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: 1, trustedCommands }),
  );

  assert.equal(Object.keys(configuration.trustedCommands).length, 256);
  assert.ok(Object.isFrozen(configuration.trustedCommands));
  assert.ok(Object.isFrozen(configuration.trustedCommands["check-1"]));
  assert.ok(
    Object.isFrozen(configuration.trustedCommands["check-1"].arguments),
  );
});

test("configuration rejects more than 256 trusted command definitions", () => {
  const trustedCommands = Object.fromEntries(
    Array.from({ length: 257 }, (_, index) => [
      `check-${index + 1}`,
      {
        command: `node validation-${index + 1}.js`,
        executable: "node",
        arguments: [`validation-${index + 1}.js`],
      },
    ]),
  );

  assert.throws(
    () =>
      parseRunnerConfiguration(
        JSON.stringify({ schemaVersion: 1, trustedCommands }),
      ),
    /may define at most 256 commands/u,
  );
});

test("configuration preserves line feeds in trusted command arguments", () => {
  const script = "first line\nsecond line";
  const configuration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      trustedCommands: {
        "multiline-check": {
          command: "node --eval multiline-check",
          executable: "node",
          arguments: ["--eval", script],
        },
      },
    }),
  );

  assert.equal(
    configuration.trustedCommands["multiline-check"].arguments[1],
    script,
  );
});

test("invalid configuration is rejected", () => {
  assert.throws(
    () => parseRunnerConfiguration('{"schemaVersion":2}\n'),
    (error) =>
      error instanceof ConfigurationError &&
      error.code === "ERR_UNSUPPORTED_CONFIGURATION_VERSION",
  );
});

test("runner issue reporting is default-enabled and explicitly disableable", () => {
  assert.equal(
    parseRunnerConfiguration('{"schemaVersion":1}').issueReporting,
    true,
  );
  assert.equal(
    parseRunnerConfiguration('{"schemaVersion":1,"issueReporting":false}')
      .issueReporting,
    false,
  );
});

test("project configuration rejects untrusted and unsafe fields", () => {
  const runnerConfiguration = parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
  );
  const invalidConfigurations = [
    [{ profiles: {} }, /profiles/u],
    [{ issueReporting: false }, /issueReporting/u],
    [{ credentials: {} }, /credentials/u],
    [{ binary: "/usr/bin/codex" }, /binary/u],
    [{ environment: {} }, /environment/u],
    [{ trustedCommands: {} }, /trustedCommands/u],
    [
      {
        pipelines: {
          "plan-execution": {
            trustedChecks: [
              { alias: "service", executable: "npm", arguments: ["test"] },
            ],
          },
        },
      },
      /trustedChecks must be an array of unique trusted command aliases/u,
    ],
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
