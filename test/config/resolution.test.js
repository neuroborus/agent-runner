import assert from "node:assert/strict";
import test from "node:test";

import {
  ConfigurationError,
  parseProjectConfiguration,
  parseRunnerConfiguration,
  resolvePipelineConfiguration,
} from "../../src/config/index.js";
import { getPipeline } from "../../src/pipeline-registry.js";

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
    mode: "independent",
    stagnationWindowRounds: 3,
    trustedChecks: [],
  });
  assert.deepEqual(resolved.trustedValidation.commands, []);
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
      mode: "independent",
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

test("lazy plan authoring resolves only the Planner role", () => {
  const resolved = resolvePipelineConfiguration("plan-authoring", {
    schemaVersion: 1,
    defaultBackend: "codex",
    pipelines: {
      "plan-authoring": {
        mode: "lazy",
        roles: {
          reviewer: { model: "preserved-reviewer-model" },
          arbiter: { model: "preserved-arbiter-model" },
        },
      },
    },
  });

  assert.deepEqual(Object.keys(resolved.roles), ["planner"]);
  assert.equal(resolved.settings.mode, "lazy");
});

test("lazy plan execution resolves only the Worker role", () => {
  const resolved = resolvePipelineConfiguration("plan-execution", {
    schemaVersion: 1,
    defaultBackend: "codex",
    pipelines: {
      "plan-execution": {
        mode: "lazy",
        roles: {
          reviewer: { model: "preserved-reviewer-model" },
          arbiter: { model: "preserved-arbiter-model" },
        },
      },
    },
  });

  assert.deepEqual(Object.keys(resolved.roles), ["worker"]);
  assert.equal(resolved.settings.mode, "lazy");
});

test("lazy polishing resolves only the Worker role", () => {
  const resolved = resolvePipelineConfiguration("polishing", {
    schemaVersion: 1,
    defaultBackend: "codex",
    pipelines: {
      polishing: {
        mode: "lazy",
        roles: {
          reviewer: { model: "preserved-reviewer-model" },
          arbiter: { model: "preserved-arbiter-model" },
        },
      },
    },
  });

  assert.deepEqual(Object.keys(resolved.roles), ["worker"]);
  assert.equal(resolved.settings.mode, "lazy");
});

test("setting overrides take precedence over project and runner settings", () => {
  const runnerConfiguration = {
    schemaVersion: 1,
    defaultBackend: "codex",
    pipelines: { "plan-authoring": { mode: "independent" } },
  };
  const projectConfiguration = {
    schemaVersion: 1,
    pipelines: { "plan-authoring": { mode: "lazy" } },
  };

  const projectResolved = resolvePipelineConfiguration(
    "plan-authoring",
    runnerConfiguration,
    {},
    {},
    null,
    projectConfiguration,
  );
  assert.equal(projectResolved.settings.mode, "lazy");
  assert.deepEqual(Object.keys(projectResolved.roles), ["planner"]);

  const overridden = resolvePipelineConfiguration(
    "plan-authoring",
    runnerConfiguration,
    {},
    {},
    null,
    projectConfiguration,
    { mode: "independent" },
  );
  assert.equal(overridden.settings.mode, "independent");
  assert.deepEqual(Object.keys(overridden.roles), [
    "planner",
    "reviewer",
    "arbiter",
  ]);

  for (const settingOverrides of [
    { mode: "automatic" },
    { unsupported: "value" },
  ]) {
    assert.throws(
      () =>
        resolvePipelineConfiguration(
          "plan-authoring",
          runnerConfiguration,
          {},
          {},
          null,
          projectConfiguration,
          settingOverrides,
        ),
      /settingOverrides/u,
    );
  }
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

test("only runner configuration defines exact trusted command vectors", () => {
  const runnerConfiguration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      trustedCommands: {
        "service-check": {
          command: "npm run test:service",
          executable: "/opt/validation  tools/npm",
          arguments: ["run", "  test:service  "],
        },
      },
    }),
  );
  const projectConfiguration = parseProjectConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      pipelines: {
        "plan-execution": {
          trustedChecks: ["service-check"],
        },
        polishing: {
          trustedChecks: ["service-check"],
        },
      },
    }),
    runnerConfiguration,
  );

  const resolved = resolvePipelineConfiguration(
    "plan-execution",
    runnerConfiguration,
    {},
    {},
    null,
    projectConfiguration,
  );

  assert.deepEqual(resolved.settings.trustedChecks, ["service-check"]);
  assert.deepEqual(resolved.trustedValidation.commands[0], {
    alias: "service-check",
    command: "npm run test:service",
    executable: "/opt/validation  tools/npm",
    arguments: ["run", "  test:service  "],
    identity: resolved.trustedValidation.commands[0].identity,
  });
  assert.match(
    resolved.trustedValidation.commands[0].identity,
    /^[a-f0-9]{64}$/u,
  );
  assert.match(
    resolved.trustedValidation.commandFingerprint,
    /^[a-f0-9]{64}$/u,
  );
  assert.match(
    resolved.trustedValidation.configurationFingerprint,
    /^[a-f0-9]{64}$/u,
  );
  assert.ok(Object.isFrozen(resolved.trustedValidation.commands));
  const state = getPipeline("plan-execution").workflow.createState({
    settings: resolved.settings,
    trustedValidation: resolved.trustedValidation,
  });
  assert.equal(
    state.trustedValidation.commands[0].executable,
    "/opt/validation  tools/npm",
  );
  assert.equal(
    state.trustedValidation.commands[0].arguments[1],
    "  test:service  ",
  );
  const polishingResolved = resolvePipelineConfiguration(
    "polishing",
    runnerConfiguration,
    {},
    {},
    null,
    projectConfiguration,
  );
  assert.deepEqual(polishingResolved.settings.trustedChecks, ["service-check"]);
  const polishingState = getPipeline("polishing").workflow.createState({
    settings: polishingResolved.settings,
    trustedValidation: polishingResolved.trustedValidation,
  });
  assert.deepEqual(
    polishingState.trustedValidation,
    resolved.trustedValidation,
  );

  assert.throws(
    () =>
      parseProjectConfiguration(
        JSON.stringify({
          schemaVersion: 1,
          pipelines: {
            "plan-execution": { trustedChecks: ["missing"] },
          },
        }),
        runnerConfiguration,
      ),
    (error) => error.code === "ERR_UNKNOWN_TRUSTED_COMMAND",
  );
});

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

test("configuration resolves only descriptor-selected roles after settings", () => {
  const configuration = parseRunnerConfiguration(
    JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
  );

  for (const pipelineId of ["plan-authoring", "plan-execution", "polishing"]) {
    const pipeline = getPipeline(pipelineId);
    const resolved = resolvePipelineConfiguration(
      pipelineId,
      configuration,
      Object.fromEntries(
        pipeline.roles.map((role) => [role, { model: `${role}-model` }]),
      ),
    );

    assert.deepEqual(
      Object.keys(resolved.roles),
      pipeline.resolveActiveRoles(resolved.settings),
    );
    for (const role of Object.keys(resolved.roles)) {
      assert.equal(resolved.roles[role].model, `${role}-model`);
    }
  }
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
