import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createClarificationService } from "../../../src/clarifications/index.js";
import {
  inspectFinalizationFile,
  loadProjectConfiguration,
  parseProjectConfiguration,
} from "../../../src/config/index.js";
import { createWorkspaceService } from "../../../src/workspace/index.js";
import {
  acceptInitResult,
  closeInitClarification,
  createInitState,
  externalFinalizationContent,
  externalFinalizationPath,
  inspectInitSetup,
  prepareInitTurn,
  publishExternalInit,
} from "../src/index.js";

const exec = promisify(execFile);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const externalRoot = (projectPath) =>
  join(
    dirname(projectPath),
    `.agent-runner-${basename(projectPath)
      .replace(/[^a-zA-Z0-9-]/gu, "-")
      .slice(0, 48)}-${hash(projectPath).slice(0, 12)}`,
  );

function roleResult(result) {
  return ["READY", "QUESTIONS", "BLOCKED"].includes(result.status) ||
    result.status === "PRODUCT_DECISION_REQUIRED"
    ? result
    : {
        question: "",
        options: [],
        whyBlocked: "",
        evidence: [],
        status: "PROPOSAL",
        ...result,
      };
}
async function fixture(
  t,
  {
    parent = null,
    name = "project",
    git = false,
    skill = false,
    artifactRoot = "LOCAL_ARTIFACTS",
    selected = false,
    selectedRoot = null,
    prepared = false,
    occupied = false,
    wrongTarget = false,
    changeProposal = () => {},
  } = {},
) {
  const root = parent ?? (await fs.mkdtemp(join(tmpdir(), "init-external-")));
  if (parent === null)
    t.after(() => fs.rm(root, { recursive: true, force: true }));
  const projectPath = join(root, name);
  const taskPath = join(root, `${name}-task`);
  const stateRoot = join(root, `${name}-state`);
  for (const path of [projectPath, taskPath, stateRoot])
    await fs.mkdir(path, { mode: 0o700 });
  if (git) await exec("git", ["init", "--quiet", projectPath]);
  const instructions = join(projectPath, "AGENTS.md");
  await fs.writeFile(instructions, "Run node --test from the project root.\n");
  await fs.writeFile(
    join(taskPath, "task.md"),
    "Prepare external infrastructure.\n",
  );
  const skillPath = join(
    projectPath,
    ".agents",
    "skills",
    "finalization",
    "SKILL.md",
  );
  if (skill) {
    await fs.mkdir(dirname(skillPath), { recursive: true });
    await fs.writeFile(
      skillPath,
      "# Project finalization\nRun node --test.\nPreserve manual handoff checks.\n",
    );
  }
  const rootPath = selected
    ? (selectedRoot ?? join(root, "chosen-infrastructure"))
    : externalRoot(projectPath);
  const configurationPath = selected
    ? join(rootPath, "settings", "project.json")
    : join(rootPath, "agent-runner.json");
  const original = {
    schemaVersion: 1,
    artifactRoot,
    infrastructure: {
      schemaVersion: 1,
      placement: "external",
      projectPath: wrongTarget ? root : projectPath,
      rootPath,
    },
    defaultEffort: "high",
    pipelines: { polishing: { mode: "combined" } },
  };
  if (selected) {
    await fs.mkdir(dirname(configurationPath), { recursive: true });
    if (prepared) {
      await fs.mkdir(join(rootPath, artifactRoot, "agent-runner"), {
        recursive: true,
      });
      await fs.writeFile(
        join(rootPath, artifactRoot, "retained.txt"),
        "Keep existing artifacts.\n",
      );
      const path = join(rootPath, "finalization", "SKILL.md");
      await fs.mkdir(dirname(path));
      await fs.writeFile(
        path,
        externalFinalizationContent(
          {
            inspection: {
              projectPath,
              documents: {
                instructions: [{ path: instructions }],
                skills: skill ? [{ path: skillPath }] : [],
              },
            },
          },
          ["node --test"],
        ),
      );
      for (const id of ["plan-execution", "polishing"]) {
        original.pipelines[id] = {
          ...original.pipelines[id],
          finalization: "finalization/SKILL.md",
        };
      }
    }
    await fs.writeFile(configurationPath, JSON.stringify(original));
  } else if (occupied) await fs.mkdir(rootPath);
  const workspace = createWorkspaceService();
  const clarifications = createClarificationService({ interactive: false });
  const transcript = {
    artifactRoot: taskPath,
    transcriptPath: join(taskPath, "clarifications.md"),
  };
  const { hash: transcriptHash } =
    await clarifications.ensureTranscript(transcript);
  const load = ({ configurationPath }) =>
    loadProjectConfiguration({
      projectPath,
      configurationPath,
      runnerConfiguration: { schemaVersion: 1 },
      workspaceKind: git ? "git" : "directory",
      // External loading must not inspect or edit target ignore rules.
      inspectPath: async () =>
        assert.fail("Unexpected target configuration inspection"),
    });
  const inspectSetup = () =>
    inspectInitSetup(
      {
        projectPath,
        taskPath,
        stateRoot,
        artifactRoot,
        placement: "external",
        configurationPath: selected ? configurationPath : null,
        candidatePaths: selected ? [configurationPath] : [],
        documents: {
          instructions: [instructions],
          checks: [],
          skills: skill ? [skillPath] : [],
          guidance: [],
        },
      },
      { workspace, loadProjectConfiguration: load },
    );
  const inspection = await inspectSetup();
  function turn(state, result) {
    const prepared = prepareInitTurn(state, inspection, transcriptHash);
    return acceptInitResult(prepared.state, {
      turnId: prepared.request.id,
      inspection,
      transcriptHash,
      result: roleResult(result),
    });
  }
  let state = turn(
    createInitState({
      settings: { mode: "combined", placement: "external" },
      configurationPath: selected ? configurationPath : null,
    }),
    { status: "READY", questions: [], reason: "" },
  );
  await clarifications.freezeTranscript({
    ...transcript,
    expectedHash: transcriptHash,
  });
  state = closeInitClarification(state, {
    inspection,
    clarificationHash: transcriptHash,
  });
  const resource = (path, kind, content) => {
    const observed = inspection.entries.find((entry) => entry.path === path);
    const beforeHash =
      observed?.kind === "file"
        ? observed.hash
        : observed?.kind === "directory"
          ? hash(JSON.stringify({ kind: "directory" }))
          : null;
    return {
      path,
      kind,
      content,
      beforeHash,
      action:
        beforeHash === null
          ? "create"
          : kind === "artifacts" || hash(content) === beforeHash
            ? "reuse"
            : "replace",
    };
  };
  const configuration = selected
    ? structuredClone(original)
    : {
        schemaVersion: 1,
        artifactRoot,
        infrastructure: original.infrastructure,
      };
  const finalizationPath = externalFinalizationPath(state);
  for (const id of ["plan-execution", "polishing"]) {
    configuration.pipelines ??= {};
    configuration.pipelines[id] = {
      ...configuration.pipelines[id],
      finalization: relative(rootPath, finalizationPath),
    };
  }
  const checks = ["node --test"];
  const proposal = {
    summary: "Prepare bound external prerequisites without target writes.",
    checks,
    resources: [
      resource(
        configurationPath,
        "configuration",
        JSON.stringify(configuration),
      ),
      resource(state.selection.artifactPath, "artifacts", ""),
      resource(
        finalizationPath,
        "finalization",
        externalFinalizationContent(state, checks),
      ),
      resource(
        join(state.selection.artifactPath, "agent-runner", "rules.md"),
        "guidance",
        "Validate from the project root.\n",
      ),
    ],
  };
  changeProposal(proposal);
  state = turn(state, proposal);
  state = turn(state, proposal);
  const clean = {
    status: "CLEAN",
    proposalHash: state.proposalHash,
    findings: [],
  };
  state = turn(state, clean);
  state = turn(state, clean);
  let saved = null;
  const runtime = {
    workspace,
    clarifications,
    stateRoot,
    inspectSetup,
    inspectIgnored: async () =>
      assert.fail("External setup must never change or require ignores"),
    assertLease: async () => {},
    validateConfiguration: (source) =>
      parseProjectConfiguration(source, { schemaVersion: 1 }),
    persist: async (value) => {
      saved = structuredClone(value);
    },
    publishDirectory: async ({
      sourceParent,
      sourceName,
      destinationParent,
      destinationName,
    }) => {
      await fs.rename(
        `/proc/self/fd/${sourceParent}/${sourceName}`,
        `/proc/self/fd/${destinationParent}/${destinationName}`,
      );
    },
  };
  const targetInspection = await workspace.inspect({
    workspacePath: projectPath,
    stateRoot,
  });
  const before = await workspace.snapshot({ inspection: targetInspection });
  return {
    root,
    projectPath,
    rootPath,
    configurationPath,
    finalizationPath,
    skillPath,
    state,
    runtime,
    load,
    get saved() {
      return saved;
    },
    assertTargetUnchanged: async () =>
      workspace.assertUnchanged({
        before,
        after: await workspace.snapshot({ inspection: targetInspection }),
      }),
  };
}

test("external prerequisites preserve Git and directory targets with or without existing skills", async (t) => {
  for (const existing of [false, true]) {
    const f = await fixture(t, {
      git: existing,
      skill: existing,
      artifactRoot: "build/artifacts",
    });
    const originalSkill = existing
      ? await fs.readFile(f.skillPath, "utf8")
      : null;
    const prepared = await publishExternalInit(f.state, f.runtime);
    assert.equal(prepared.configurationPath, f.configurationPath);
    assert.equal(prepared.publication.prepared, true);
    assert.equal(f.state.workflowState, "PROPOSAL_ACCEPTED");
    const loaded = await f.load({
      configurationPath: prepared.configurationPath,
    });
    assert.equal(loaded.artifactPath, join(f.rootPath, "build/artifacts"));
    assert.equal(loaded.protection.schemaVersion, 2);
    for (const id of ["plan-execution", "polishing"]) {
      const selected = await inspectFinalizationFile({
        projectPath: f.projectPath,
        infrastructureRoot: loaded.infrastructure.rootPath,
        path: loaded.configuration.pipelines[id].finalization,
      });
      assert.equal(selected.path, f.finalizationPath);
      assert.equal(selected.exists, true);
    }
    const procedure = await fs.readFile(f.finalizationPath, "utf8");
    assert.match(procedure, /node --test/u);
    assert.match(procedure, /defer all staging/u);
    if (existing) {
      assert.match(procedure, /\.agents\/skills\/finalization\/SKILL.md/u);
      assert.equal(await fs.readFile(f.skillPath, "utf8"), originalSkill);
    }
    await assert.rejects(
      fs.stat(join(loaded.artifactPath, "agent-runner", "rules.md")),
      { code: "ENOENT" },
    );
    await f.assertTargetUnchanged();
    assert.deepEqual(
      await publishExternalInit(f.state, f.runtime, prepared.publication),
      prepared,
    );
  }
});

test("canonical path hashes distinguish projects whose safe sibling names coincide", async (t) => {
  const parent = await fs.mkdtemp(join(tmpdir(), "init-neighbors-"));
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const a = await fixture(t, { parent, name: "sample one" });
  const b = await fixture(t, { parent, name: "sample_one" });
  assert.notEqual(a.rootPath, b.rootPath);
  for (const f of [a, b]) {
    assert.equal(f.state.selection.rootPath, externalRoot(f.projectPath));
    await publishExternalInit(f.state, f.runtime);
    await f.assertTargetUnchanged();
  }
});

test("explicit bound infrastructure retains its exact selector, artifact root and unrelated settings", async (t) => {
  const f = await fixture(t, {
    selected: true,
    prepared: true,
    artifactRoot: "custom/output",
  });
  const before = await f.runtime.workspace.snapshotInputs({
    paths: [f.rootPath],
    stateRoot: f.runtime.stateRoot,
  });
  const prepared = await publishExternalInit(f.state, f.runtime);
  assert.deepEqual(
    await f.runtime.workspace.snapshotInputs({
      paths: [f.rootPath],
      stateRoot: f.runtime.stateRoot,
    }),
    before,
  );
  assert.equal(
    prepared.configurationPath,
    join(f.rootPath, "settings", "project.json"),
  );
  const loaded = await f.load({
    configurationPath: prepared.configurationPath,
  });
  assert.equal(loaded.configuration.defaultEffort, "high");
  assert.equal(loaded.configuration.pipelines.polishing.mode, "combined");
  assert.equal(loaded.artifactPath, join(f.rootPath, "custom/output"));
  await assert.rejects(fs.stat(externalRoot(f.projectPath)), {
    code: "ENOENT",
  });
  await f.assertTargetUnchanged();
});

test("occupied defaults, wrong-target bindings and root races are rejected without adoption", async (t) => {
  await assert.rejects(
    fixture(t, { occupied: true }),
    /occupied by unbound infrastructure/u,
  );
  await assert.rejects(
    fixture(t, { selected: true, wrongTarget: true }),
    /binding disagree/u,
  );
  const f = await fixture(t);
  await fs.mkdir(f.rootPath);
  await assert.rejects(
    publishExternalInit(f.state, f.runtime),
    /bindings changed/u,
  );
  assert.equal(f.saved, null);
  assert.deepEqual(await fs.readdir(f.rootPath), []);
  await f.assertTargetUnchanged();
});

test("external publication rejects ancestor provider controls before intents or writes", async (t) => {
  for (const alias of [false, true]) {
    const parent = await fs.mkdtemp(join(tmpdir(), "init-provider-controls-"));
    t.after(() => fs.rm(parent, { recursive: true, force: true }));
    const providerRoot = join(parent, alias ? "provider-storage" : ".codex");
    await fs.mkdir(providerRoot);
    if (alias) await fs.symlink(providerRoot, join(parent, ".codex"));
    const f = await fixture(t, {
      parent,
      selected: true,
      selectedRoot: join(providerRoot, "infrastructure"),
    });
    const snapshot = () =>
      f.runtime.workspace.snapshotInputs({
        paths: [providerRoot],
        stateRoot: f.runtime.stateRoot,
      });
    const before = await snapshot();

    await assert.rejects(
      publishExternalInit(f.state, f.runtime),
      /External setup cannot publish inside Git or provider controls/u,
    );
    assert.equal(f.saved, null);
    assert.deepEqual(await snapshot(), before);
    await f.assertTargetUnchanged();
  }
});

test("external publication rechecks ancestor provider alias targets on recovery", async (t) => {
  const f = await fixture(t, { selected: true });
  const persist = f.runtime.persist;
  f.runtime.persist = async (value) => {
    await persist(value);
    throw new Error("Interrupted before publication");
  };
  await assert.rejects(
    publishExternalInit(f.state, f.runtime),
    /Interrupted before publication/u,
  );
  const publication = structuredClone(f.saved);
  assert.equal(publication.pending, null);
  assert.deepEqual(publication.receipts, []);
  await fs.symlink(f.rootPath, join(f.root, ".codex"));
  f.runtime.persist = persist;
  const snapshot = () =>
    f.runtime.workspace.snapshotInputs({
      paths: [f.rootPath],
      stateRoot: f.runtime.stateRoot,
    });
  const before = await snapshot();

  await assert.rejects(
    publishExternalInit(f.state, f.runtime, publication),
    /External setup cannot publish inside Git or provider controls/u,
  );
  assert.deepEqual(f.saved, publication);
  assert.deepEqual(await snapshot(), before);
  await f.assertTargetUnchanged();
});

test("lost sibling-root receipts reconcile only the recorded allocation identity", async (t) => {
  const f = await fixture(t);
  const persist = f.runtime.persist;
  f.runtime.persist = async (value) => {
    if (value.receipts.some(({ path }) => path === f.rootPath))
      throw new Error("Interrupted root receipt");
    await persist(value);
  };
  await assert.rejects(
    publishExternalInit(f.state, f.runtime),
    /Interrupted root receipt/u,
  );
  assert.equal(f.saved.pending.path, f.rootPath);
  const before = await fs.stat(f.rootPath);
  f.runtime.persist = persist;
  const prepared = await publishExternalInit(f.state, f.runtime, f.saved);
  assert.equal((await fs.stat(f.rootPath)).ino, before.ino);
  const replacement = join(f.root, "replacement");
  await fs.rename(f.rootPath, replacement);
  await fs.mkdir(f.rootPath);
  await assert.rejects(
    publishExternalInit(f.state, f.runtime, prepared.publication),
    /resource changed/u,
  );
  await f.assertTargetUnchanged();
});

test("external publication rejects changed settings and unreviewed finalization", async (t) => {
  // The fast proposal suite owns duplicate-resource rejection before approval.
  for (const changeProposal of [
    (proposal) => {
      const resource = proposal.resources[0];
      const value = JSON.parse(resource.content);
      value.defaultEffort = "low";
      resource.content = JSON.stringify(value);
    },
    (proposal) => {
      proposal.resources.find(({ kind }) => kind === "finalization").content +=
        "Omit required checks.\n";
    },
  ]) {
    const f = await fixture(t, { changeProposal });
    await assert.rejects(
      publishExternalInit(f.state, f.runtime),
      /preserve unrelated settings|derive its procedure/u,
    );
    assert.equal(f.saved, null);
    await assert.rejects(fs.stat(f.rootPath), { code: "ENOENT" });
    await f.assertTargetUnchanged();
  }
});
