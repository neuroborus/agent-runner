import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  parseProjectConfiguration,
  parseRunnerConfiguration,
  resolvePipelineConfiguration,
} from "../src/config/index.js";
import { getPipeline } from "../src/pipeline-registry.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
  validateTrustedValidationSnapshot,
} from "../src/trusted-validation/index.js";

const command = {
  command: "npm run build",
  executable: "npm",
  arguments: ["run", "build"],
};
const artifact = {
  url: "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
  sha256: "a".repeat(64),
};
const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const snapshot = (capabilities) =>
  createTrustedValidationSnapshot({ build: { ...command, capabilities } }, [
    "build",
  ]);

test("capability parameters are strict, immutable, and fingerprinted in both configuration layers", () => {
  const capabilities = { cache: true, artifacts: [artifact], scratch: true };
  const definition = { ...command, capabilities };
  const root = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      trustedCommands: { build: definition },
      pipelines: {
        "plan-execution": { trustedChecks: ["build"] },
        polishing: { trustedChecks: ["build"] },
      },
    }),
  );
  const overlay = parseProjectConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      trustedCommands: { build: definition },
    }),
    root,
  );
  assert.deepEqual(root.trustedCommands, overlay.trustedCommands);
  for (const pipelineId of ["plan-execution", "polishing"]) {
    const selected = resolvePipelineConfiguration(
      pipelineId,
      root,
      {},
      {},
      null,
      overlay,
    );
    const frozen = selected.trustedValidation;
    assert.equal(frozen.schemaVersion, 2);
    assert.deepEqual(
      getPipeline(pipelineId).workflow.createState({
        settings: selected.settings,
        trustedValidation: frozen,
      }).trustedValidation,
      frozen,
    );
    assert.ok(Object.isFrozen(frozen.commands[0].capabilities.artifacts[0]));
    assert.deepEqual(
      validateTrustedValidationSnapshot(JSON.parse(JSON.stringify(frozen))),
      frozen,
    );
  }
  const variants = [
    {},
    { scratch: true },
    { cache: true },
    { artifacts: [artifact] },
    { artifacts: [{ ...artifact, sha256: "b".repeat(64) }] },
    {
      artifacts: [{ ...artifact, url: "https://registry.npmjs.org/other.tgz" }],
    },
  ].map(snapshot);
  for (const key of ["commandFingerprint", "configurationFingerprint"])
    assert.equal(
      new Set(variants.map((value) => value[key])).size,
      variants.length,
    );
  assert.equal(
    new Set(variants.map((value) => value.commands[0].identity)).size,
    variants.length,
  );
  assert.throws(
    () =>
      parseProjectConfiguration(
        JSON.stringify({
          schemaVersion: 1,
          defaultBackend: "codex",
          trustedCommands: {
            build: { ...command, capabilities: { scratch: true } },
          },
        }),
        root,
      ),
    { code: "ERR_TRUSTED_COMMAND_CONFLICT" },
  );
});

test("capabilities cannot grant arbitrary mounts, environment, credentials, or network authority", () => {
  const invalid = [
    null,
    [],
    { scratch: false },
    { scratch: "/tmp" },
    { cache: { path: "/project" } },
    { network: true },
    { mounts: [] },
    { environment: { HOME: "/home" } },
    { proxy: "https://proxy.example.com" },
    { artifacts: [] },
    { artifacts: [{ ...artifact, destination: "/project" }] },
    { artifacts: [artifact, artifact] },
    { artifacts: [{ ...artifact, sha256: "bad" }] },
  ];
  for (const url of [
    "http://example.com/a",
    "https://user:password@example.com/a",
    "https://localhost/a",
    "https://127.0.0.1/a",
    "https://[::1]/a",
    "https://example.com:8443/a",
    "https://example.com/a#fragment",
    "https://EXAMPLE.com/a",
  ])
    invalid.push({ artifacts: [{ ...artifact, url }] });
  for (const capabilities of invalid) {
    const input = JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      trustedCommands: { build: { ...command, capabilities } },
    });
    assert.throws(() => parseRunnerConfiguration(input));
    assert.throws(() => parseProjectConfiguration(input, { schemaVersion: 1 }));
  }
});

test("legacy restricted snapshots retain exact identities and evidence bindings", () => {
  const vector = { alias: "build", ...command };
  const legacy = {
    schemaVersion: 1,
    commands: [{ ...vector, identity: hash(vector) }],
    commandFingerprint: hash([hash(vector)]),
    configurationFingerprint: hash({ schemaVersion: 1, commands: [vector] }),
  };
  assert.deepEqual(validateTrustedValidationSnapshot(legacy), legacy);
  for (const pipelineId of ["plan-execution", "polishing"]) {
    const pipeline = getPipeline(pipelineId);
    const state = pipeline.workflow.createState({
      settings: resolvePipelineConfiguration(pipelineId, {
        schemaVersion: 1,
        defaultBackend: "codex",
        trustedCommands: { build: command },
        pipelines: { [pipelineId]: { trustedChecks: ["build"] } },
      }).settings,
      trustedValidation: legacy,
    });
    assert.deepEqual(state.trustedValidation, legacy);
  }
  assert.throws(() =>
    validateTrustedValidationSnapshot({
      ...legacy,
      commands: [{ ...legacy.commands[0], capabilities: { scratch: true } }],
    }),
  );
  const current = snapshot({ scratch: true });
  assert.throws(() =>
    validateTrustedValidationSnapshot({
      ...current,
      commands: [{ ...current.commands[0], capabilities: { cache: true } }],
    }),
  );
});

test("declared capabilities fail closed before sandbox or command activity", async () => {
  let activity = 0;
  const service = createTrustedValidationService({
    sandboxCommand() {
      activity += 1;
    },
    runCommand() {
      activity += 1;
    },
  });
  for (const capabilities of [
    { scratch: true },
    { cache: true },
    { artifacts: [artifact] },
  ]) {
    const selected = snapshot(capabilities);
    await assert.rejects(
      service.preflight({ projectPath: "/project", snapshot: selected }),
      { code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE" },
    );
    await assert.rejects(service.execute({ snapshot: selected }), {
      code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
    });
  }
  await service.preflight({ projectPath: "/project", snapshot: snapshot({}) });
  assert.equal(activity, 0);
});

test("constructing trusted validation for status does no capability work", async () => {
  let resolutions = 0;
  const service = createTrustedValidationService({
    resolveLauncher() {
      resolutions += 1;
      return "/runner/bwrap";
    },
    verifyLauncher(path) {
      return path;
    },
  });
  assert.equal(resolutions, 0);
  await assert.rejects(
    service.preflight({
      projectPath: "/project",
      snapshot: snapshot({ scratch: true }),
    }),
    { code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE" },
  );
  assert.equal(resolutions, 0);
  await service.preflight({ projectPath: "/project", snapshot: snapshot({}) });
  assert.equal(resolutions, 1);
});

test("capability snapshots preserve exact multiline arguments through both pipeline contracts", () => {
  const vector = {
    command: "node build",
    executable: "node",
    arguments: ["--eval", "const value = 1;\nprocess.exit(value - 1);"],
    capabilities: { scratch: true },
  };
  for (const pipelineId of ["plan-execution", "polishing"]) {
    const resolved = resolvePipelineConfiguration(pipelineId, {
      schemaVersion: 1,
      defaultBackend: "codex",
      trustedCommands: { build: vector },
      pipelines: { [pipelineId]: { trustedChecks: ["build"] } },
    });
    const state = getPipeline(pipelineId).workflow.createState({
      settings: resolved.settings,
      trustedValidation: resolved.trustedValidation,
    });
    assert.deepEqual(
      state.trustedValidation.commands[0].arguments,
      vector.arguments,
    );
  }
});
