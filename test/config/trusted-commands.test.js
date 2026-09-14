import assert from "node:assert/strict";
import test from "node:test";

import {
  parseProjectConfiguration,
  parseRunnerConfiguration,
  resolvePipelineConfiguration,
} from "../../src/config/index.js";
import { getPipeline } from "../../src/pipeline-registry.js";
import { createTrustedValidationSnapshot } from "../../src/trusted-validation/index.js";

function command(name) {
  return {
    command: `npm run ${name}`,
    executable: "npm",
    arguments: ["run", name],
  };
}

function configuration(trustedCommands = {}, pipelines = {}) {
  return {
    schemaVersion: 1,
    defaultBackend: "codex",
    trustedCommands,
    pipelines,
  };
}

function project(root, trustedCommands = {}, pipelines = {}) {
  return parseProjectConfiguration(
    JSON.stringify(configuration(trustedCommands, pipelines)),
    root,
  );
}

function resolve(root, overlay, pipelineId = "plan-execution") {
  return resolvePipelineConfiguration(pipelineId, root, {}, {}, null, overlay);
}

test("project-only selections produce immutable exact snapshots for both writable pipelines", () => {
  const rootCommand = command("root-check");
  const projectCommand = {
    command: "node --eval project-check",
    executable: "/opt/validation tools/node",
    arguments: ["--eval", "const value = 1; process.exit(value - 1);"],
  };
  const root = configuration(
    { "root-check": rootCommand },
    { "plan-execution": { trustedChecks: ["root-check"] } },
  );
  const pipelines = Object.fromEntries(
    ["plan-execution", "polishing"].map((id) => [
      id,
      { trustedChecks: ["project-check", "root-check"] },
    ]),
  );
  const overlay = project(root, { "project-check": projectCommand }, pipelines);
  const expected = createTrustedValidationSnapshot(
    { "root-check": rootCommand, "project-check": projectCommand },
    ["project-check", "root-check"],
  );
  assert.deepEqual(Object.keys(overlay.trustedCommands), ["project-check"]);
  assert.ok(Object.isFrozen(overlay.trustedCommands));
  assert.ok(
    Object.isFrozen(overlay.trustedCommands["project-check"].arguments),
  );
  for (const pipelineId of ["plan-execution", "polishing"]) {
    const resolved = resolve(root, overlay, pipelineId);
    assert.deepEqual(resolved.trustedValidation, expected);
    assert.ok(Object.isFrozen(resolved.trustedValidation));
    assert.ok(Object.isFrozen(resolved.trustedValidation.commands));
    assert.ok(
      Object.isFrozen(resolved.trustedValidation.commands[0].arguments),
    );
    assert.deepEqual(
      getPipeline(pipelineId).workflow.createState({
        settings: resolved.settings,
        trustedValidation: resolved.trustedValidation,
      }).trustedValidation,
      expected,
    );
  }
  assert.deepEqual(
    resolve(root, project(root, { "project-check": projectCommand })).settings
      .trustedChecks,
    ["root-check"],
  );
});

test("identical same-name definitions deduplicate without changing identities or selection order", () => {
  const shared = command("shared");
  const root = configuration({ first: command("first"), shared });
  const overlay = project(
    root,
    {
      last: command("last"),
      shared: {
        arguments: shared.arguments,
        executable: shared.executable,
        command: shared.command,
      },
    },
    { "plan-execution": { trustedChecks: ["last", "shared", "first"] } },
  );
  const expected = createTrustedValidationSnapshot(
    { ...root.trustedCommands, last: command("last") },
    ["last", "shared", "first"],
  );
  const resolved = resolve(root, overlay);
  assert.deepEqual(resolved.trustedValidation, expected);
  shared.arguments[1] = "changed-after-resolution";
  assert.deepEqual(resolved.trustedValidation, expected);
});

test("conflicting same-name definitions reject even when unselected and do not expose vectors", () => {
  const shared = command("shared");
  const root = configuration({ shared });
  for (const change of [
    { command: "PRIVATE_CHANGED_COMMAND" },
    { executable: "PRIVATE_CHANGED_EXECUTABLE" },
    { arguments: ["PRIVATE_CHANGED_ARGUMENT"] },
  ]) {
    assert.throws(
      () => project(root, { shared: { ...shared, ...change } }),
      (error) => {
        assert.equal(error.code, "ERR_TRUSTED_COMMAND_CONFLICT");
        assert.match(error.message, /shared/u);
        assert.doesNotMatch(error.message, /PRIVATE_/u);
        return true;
      },
    );
  }
  const multiple = configuration({ first: shared, second: shared });
  assert.throws(
    () =>
      project(multiple, {
        second: command("different"),
        first: command("different"),
      }),
    /Project trusted command second conflicts/u,
  );
});

test("merged catalogs enforce 256 definitions after deduplication and 32 selections", () => {
  const definitions = Object.fromEntries(
    Array.from({ length: 256 }, (_, index) => [
      `check-${index}`,
      command(`check-${index}`),
    ]),
  );
  const entries = Object.entries(definitions);
  const root = configuration(Object.fromEntries(entries.slice(0, 128)));
  const projectCommands = Object.fromEntries(entries.slice(128));
  const selected = Object.keys(projectCommands).slice(0, 32);
  const overlay = project(root, projectCommands, {
    "plan-execution": { trustedChecks: selected },
    polishing: { trustedChecks: selected },
  });
  for (const pipelineId of ["plan-execution", "polishing"]) {
    assert.equal(
      resolve(root, overlay, pipelineId).trustedValidation.commands.length,
      32,
    );
    assert.throws(
      () =>
        project(root, projectCommands, {
          [pipelineId]: { trustedChecks: [...selected, "check-160"] },
        }),
      /trustedChecks/u,
    );
  }
  assert.throws(
    () => project(root, { ...projectCommands, extra: command("extra") }),
    /at most 256 commands/u,
  );
  const fullRoot = configuration(definitions);
  assert.doesNotThrow(() => project(fullRoot, definitions));
  assert.throws(
    () => project(fullRoot, { extra: command("extra") }),
    /at most 256 commands/u,
  );
  assert.doesNotThrow(() => project(configuration(), definitions));
  assert.throws(
    () => project(configuration(), { ...definitions, extra: command("extra") }),
    /at most 256 commands/u,
  );
});

test("unknown selections cannot resolve inherited object properties", () => {
  for (const alias of ["missing", "constructor"]) {
    assert.throws(
      () =>
        project(
          configuration(),
          {},
          {
            "plan-execution": { trustedChecks: [alias] },
          },
        ),
      { code: "ERR_UNKNOWN_TRUSTED_COMMAND" },
    );
    assert.throws(
      () =>
        parseRunnerConfiguration(
          JSON.stringify(
            configuration(
              {},
              {
                polishing: { trustedChecks: [alias] },
              },
            ),
          ),
        ),
      { code: "ERR_UNKNOWN_TRUSTED_COMMAND" },
    );
  }
  const root = configuration();
  const overlay = project(
    root,
    { constructor: command("constructor") },
    { "plan-execution": { trustedChecks: ["constructor"] } },
  );
  assert.equal(
    resolve(root, overlay).trustedValidation.commands[0].alias,
    "constructor",
  );
});

test("project catalogs retain exact-vector validation without additional authority fields", () => {
  const valid = command("project-check");
  for (const definition of [
    "npm run project-check",
    { command: valid.command },
    { ...valid, arguments: "run project-check" },
    { ...valid, command: " npm run project-check" },
    { ...valid, executable: "npm\n" },
    { ...valid, arguments: ["bad\targument"] },
    ...[
      "environment",
      "credentials",
      "cwd",
      "shell",
      "network",
      "allowHostAccess",
    ].map((field) => ({ ...valid, [field]: {} })),
  ]) {
    assert.throws(() => project(configuration(), { check: definition }));
  }
  assert.throws(() => project(configuration(), { "Bad-Alias": valid }));
  assert.throws(
    () =>
      parseProjectConfiguration(
        JSON.stringify({
          ...configuration({ check: valid }),
          profiles: { injected: { backend: "codex", profile: "work" } },
        }),
        configuration(),
      ),
    /profiles/u,
  );
});
