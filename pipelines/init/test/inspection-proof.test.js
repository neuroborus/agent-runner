import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { join } from "node:path";
import test from "node:test";

import { preparePipelineMigration } from "../../../src/runner/index.js";
import { createWorkspaceService } from "../../../src/workspace/index.js";
import {
  acceptInitResult,
  closeInitClarification,
  createInitState,
  externalFinalizationContent,
  externalFinalizationPath,
  initPipeline,
  inspectInitSetup,
  integratedFinalizationContent,
  integratedFinalizationPath,
  prepareInitTurn,
} from "../src/index.js";

const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const HASH = "a".repeat(64);
const document = (path) => ({
  path,
  kind: "file",
  hash: HASH,
  mode: 0o644,
  size: 1,
  identity: { device: "1", inode: path, mode: "33188" },
});
const directory = (path) => ({
  path,
  kind: "directory",
  hash: null,
  mode: 0o755,
  size: 0,
});

function fixture(placement, count = 10_010) {
  const options = {
    projectPath: "/work/project",
    taskPath: "/work/task",
    stateRoot: "/work/state",
    artifactRoot: "artifacts",
    placement,
    documents: { instructions: [], checks: [], skills: [], guidance: [] },
  };
  let captured;
  let bindings;
  const sources = [
    directory(options.projectPath),
    directory(options.taskPath),
    document(join(options.taskPath, "task.md")),
    directory("/work/project/.git"),
    document("/work/project/.git/HEAD"),
    directory("/work/project/.git/objects"),
    directory("/work/project/.git/refs"),
    ...Array.from({ length: count }, (_, index) =>
      document(`/work/project/source-${String(index).padStart(5, "0")}`),
    ),
  ];
  const workspace = {
    ...createWorkspaceService(),
    inspectPath: async ({ path }) => ({ path, exists: false, ancestors: [] }),
    inspect: async (request) => {
      bindings = {
        bindings: [
          request.workspacePath,
          request.taskPath,
          ...request.infrastructurePaths,
        ].map((path) => ({
          path,
          exists: sources.some((entry) => entry.path === path),
          ancestors: [],
        })),
        controlPaths: ["/work/project/.git"],
      };
      return bindings;
    },
    snapshot: async () => {
      captured = {
        schemaVersion: 1,
        workspacePath: options.projectPath,
        outputPaths: [],
        linkResolutions: [],
        entries: [
          ...sources,
          ...bindings.bindings
            .filter(({ exists }) => !exists)
            .map(({ path }) => ({
              path,
              kind: "missing",
              hash: null,
              mode: null,
              size: 0,
            })),
        ].toSorted((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
      };
      return structuredClone(captured);
    },
    assertUnchanged: ({ before, after }) => assert.deepEqual(before, after),
  };
  return {
    options,
    sources,
    inspect: (extra = {}) =>
      inspectInitSetup({ ...options, ...extra }, { workspace }),
    legacyHash: () =>
      hash({
        inspection: bindings,
        entries: captured.entries,
        linkResolutions: captured.linkResolutions,
      }),
    legacyProjectHash: () =>
      hash({
        binding: bindings.bindings[0],
        entries: captured.entries.filter(
          ({ path }) =>
            path === options.projectPath ||
            path.startsWith(`${options.projectPath}/`),
        ),
        linkResolutions: [],
        controls: bindings.controlPaths,
      }),
  };
}

function turn(state, inspection, result) {
  const prepared = prepareInitTurn(state, inspection, HASH);
  return acceptInitResult(prepared.state, {
    turnId: prepared.request.id,
    inspection,
    transcriptHash: HASH,
    result,
  });
}
function clarified(inspection, placement) {
  const state = turn(createInitState({ settings: { placement } }), inspection, {
    status: "READY",
    questions: [],
    reason: "",
  });
  return closeInitClarification(state, { inspection, clarificationHash: HASH });
}
function proposal(state) {
  const external = state.selection.placement === "external";
  const procedure = external
    ? externalFinalizationPath(state)
    : integratedFinalizationPath(state);
  return {
    status: "PROPOSAL",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
    summary: "Prepare exact inspected infrastructure.",
    checks: ["node --test"],
    resources: [
      [state.selection.configurationPath, "configuration", "{}"],
      [state.selection.artifactPath, "artifacts", ""],
      [
        procedure,
        "finalization",
        (external
          ? externalFinalizationContent
          : integratedFinalizationContent)(state, ["node --test"]),
      ],
      [
        join(state.selection.artifactPath, "agent-runner", "rules.md"),
        "guidance",
        "Use the reviewed checks.",
      ],
    ].map(([path, kind, content]) => ({
      path,
      kind,
      content,
      action: "create",
      beforeHash: null,
    })),
  };
}

test("large complete inspections project bounded setup evidence in either placement without losing drift proof", async () => {
  for (const placement of ["integrated", "external"]) {
    const f = fixture(placement);
    const inspection = await f.inspect();
    assert.equal(inspection.schemaVersion, 2);
    assert.ok(inspection.entries.length < 40);
    assert.ok(JSON.stringify(inspection).length < 12_000);
    const state = clarified(inspection, placement);
    const prepared = prepareInitTurn(state, inspection, HASH);
    assert.ok(prepared.request.prompt.length < 24_000);
    assert.ok(!prepared.request.prompt.includes("source-10009"));
    assert.equal(
      turn(state, inspection, proposal(state)).workflowState,
      "REVIEW",
    );
    assert.deepEqual(
      await f.inspect({ previousInspection: inspection }),
      inspection,
    );
    for (const path of [
      "/work/project/source-10009",
      "/work/project/.git/HEAD",
      "/work/task/task.md",
    ]) {
      const entry = f.sources.find((entry) => entry.path === path);
      const original = structuredClone(entry);
      entry.identity.inode = "replacement";
      const changed = await f.inspect();
      assert.notEqual(changed.snapshotHash, inspection.snapshotHash);
      assert.throws(() => prepareInitTurn(state, changed, HASH), /changed/u);
      await assert.rejects(
        f.inspect({ previousInspection: inspection }),
        /changed/u,
      );
      Object.assign(entry, original);
    }
    const omitted = structuredClone(inspection);
    omitted.entries = omitted.entries.filter(
      ({ path }) => path !== state.selection.configurationPath,
    );
    const missing = { ...state, inspection: omitted };
    assert.throws(
      () => turn(missing, omitted, proposal(missing)),
      /explicit inspected destination evidence/u,
    );
  }
});

test("legacy inspection bindings and accepted approvals migrate without new evidence or renewed accounting", async () => {
  const f = fixture("external", 0);
  const inspection = await f.inspect({ schemaVersion: 1 });
  assert.equal(inspection.snapshotHash, f.legacyHash());
  assert.equal(
    inspection.scopeBindings.find(({ path }) => path === f.options.projectPath)
      .hash,
    f.legacyProjectHash(),
  );
  let state = clarified(inspection, "external");
  state = turn(state, inspection, proposal(state));
  state = turn(state, inspection, {
    status: "CLEAN",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
    proposalHash: state.proposalHash,
    findings: [],
  });
  state = { ...state, revisionRounds: 3, sourceForks: [HASH] };
  delete state.correctiveFeedback;
  const run = {
    pipelineId: "init",
    pipelineStateVersion: 1,
    pipelineState: state,
    pause: null,
  };
  const original = structuredClone(run);
  const migrated = preparePipelineMigration(run, initPipeline);
  assert.equal(migrated.pipelineStateVersion, initPipeline.stateVersion);
  assert.deepEqual(migrated.pipelineState, {
    ...original.pipelineState,
    correctiveFeedback: null,
  });
  assert.deepEqual(run, original);
  assert.deepEqual(
    await f.inspect({
      schemaVersion: migrated.pipelineState.inspection.schemaVersion,
    }),
    inspection,
  );
  await assert.rejects(fixture("external").inspect({ schemaVersion: 1 }), {
    code: "ERR_INIT_INSPECTION",
    constraint: "evidence_capacity",
  });
});
