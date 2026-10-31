import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createClarificationService } from "../../../src/clarifications/index.js";
import { parseProjectConfiguration } from "../../../src/config/index.js";
import { createWorkspaceService } from "../../../src/workspace/index.js";
import {
  acceptInitResult,
  closeInitClarification,
  createInitState,
  inspectInitSetup,
  prepareInitTurn,
  publishIntegratedInit,
  integratedFinalizationContent,
  integratedFinalizationPath,
  integratedIgnoreContent,
  integratedIgnorePaths,
} from "../src/index.js";

const exec = promisify(execFile);

async function fixture(
  t,
  {
    existing = false,
    artifactRoot = "LOCAL_ARTIFACTS",
    ignore = `# Local project rules\n/${artifactRoot}/\n!/${artifactRoot}/\n`,
    changeConfiguration = () => {},
    wrapper = null,
    preparedArtifacts = false,
    fileSystem = fs,
    beforeInspection = async () => {},
  } = {},
) {
  const root = await fs.mkdtemp(join(tmpdir(), "init-integrated-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  for (const path of [projectPath, taskPath, stateRoot])
    await fs.mkdir(path, { mode: 0o700 });
  await exec("git", ["init", "--quiet", projectPath]);
  await fs.writeFile(
    join(taskPath, "task.md"),
    "Prepare this project's infrastructure.\n",
  );
  const clarifications = createClarificationService({ interactive: false });
  const transcript = {
    artifactRoot: taskPath,
    transcriptPath: join(taskPath, "clarifications.md"),
  };
  const { hash } = await clarifications.ensureTranscript(transcript);
  const instructions = join(projectPath, "AGENTS.md");
  await fs.writeFile(
    instructions,
    "Validate with node --test from the project root.\n",
  );
  const skill = join(
    projectPath,
    ".agents",
    "skills",
    "finalization",
    "SKILL.md",
  );
  const configurationPath = join(
    projectPath,
    artifactRoot,
    "agent-runner.json",
  );
  const originalConfiguration = {
    schemaVersion: 1,
    defaultEffort: "high",
    pipelines: { polishing: { mode: "combined" } },
  };
  const originalIgnore = ignore;
  if (preparedArtifacts)
    await fs.mkdir(dirname(configurationPath), { recursive: true });
  if (existing) {
    await fs.mkdir(dirname(skill), { recursive: true });
    await fs.writeFile(
      skill,
      "# Existing finalization\nRun node --test.\nThen stage and inspect the staged diff for manual handoff.\n",
    );
    if (wrapper !== null)
      await fs.writeFile(join(dirname(skill), "RUNNER.md"), wrapper);
    await fs.mkdir(dirname(configurationPath), { recursive: true });
    await fs.writeFile(
      configurationPath,
      JSON.stringify(originalConfiguration),
    );
    await fs.writeFile(join(projectPath, ".gitignore"), originalIgnore);
  }
  const workspace = createWorkspaceService({ fileSystem });
  await beforeInspection({ projectPath, stateRoot, workspace });
  const inspectSetup = () =>
    inspectInitSetup(
      {
        projectPath,
        taskPath,
        stateRoot,
        artifactRoot,
        documents: {
          instructions: [instructions],
          checks: [],
          skills: existing ? [skill] : [],
          guidance: [],
        },
      },
      { workspace },
    );
  const inspection = await inspectSetup();
  function turn(state, result) {
    const prepared = prepareInitTurn(state, inspection, hash);
    return acceptInitResult(prepared.state, {
      turnId: prepared.request.id,
      inspection,
      transcriptHash: hash,
      result,
    });
  }
  let state = turn(createInitState({ settings: { mode: "combined" } }), {
    status: "READY",
    questions: [],
    reason: "",
  });
  await clarifications.freezeTranscript({ ...transcript, expectedHash: hash });
  state = closeInitClarification(state, {
    inspection,
    clarificationHash: hash,
  });
  const resource = (path, kind, content) => {
    const observed = inspection.entries.find((entry) => entry.path === path);
    return {
      path,
      kind,
      content,
      beforeHash:
        observed?.kind === "file"
          ? observed.hash
          : observed?.kind === "directory"
            ? // The proposal contract uses the structural directory digest.
              createHash("sha256")
                .update(JSON.stringify({ kind: "directory" }))
                .digest("hex")
            : null,
      action: observed && observed.kind !== "missing" ? "replace" : "create",
    };
  };
  const checks = ["node --test"];
  const finalizationPath = integratedFinalizationPath(state);
  const configuration = {
    ...(existing ? originalConfiguration : { schemaVersion: 1 }),
    artifactRoot,
    infrastructure: {
      schemaVersion: 1,
      placement: "integrated",
      projectPath,
      rootPath: projectPath,
    },
  };
  for (const id of ["plan-execution", "polishing"]) {
    configuration.pipelines ??= {};
    configuration.pipelines[id] = {
      ...configuration.pipelines[id],
      finalization: relative(projectPath, finalizationPath),
    };
  }
  changeConfiguration(configuration);
  const artifacts = resource(state.selection.artifactPath, "artifacts", "");
  if (artifacts.action === "replace") artifacts.action = "reuse";
  const proposal = {
    summary: "Prepare reviewed integrated resources.",
    checks,
    resources: [
      resource(
        configurationPath,
        "configuration",
        JSON.stringify(configuration),
      ),
      artifacts,
      resource(
        finalizationPath,
        "finalization",
        integratedFinalizationContent(state, checks),
      ),
      resource(
        join(state.selection.artifactPath, "agent-runner", "rules.md"),
        "guidance",
        "Validate from the project root.\n",
      ),
      resource(join(projectPath, ".gitignore"), "ignore", ""),
    ],
  };
  const inspectIgnored = async (path) => {
    try {
      await exec("git", [
        "-C",
        projectPath,
        "check-ignore",
        "--no-index",
        "-q",
        "--",
        relative(projectPath, path),
      ]);
      return { ignored: true, tracked: false };
    } catch (cause) {
      if (cause.code !== 1) throw cause;
      return { ignored: false, tracked: false };
    }
  };
  const needed = [];
  for (const path of integratedIgnorePaths({ ...state, proposal })) {
    if (
      !(await inspectIgnored(path)).ignored &&
      !needed.some((parent) => path.startsWith(`${parent}/`))
    )
      needed.push(path);
  }
  proposal.resources.at(-1).content = integratedIgnoreContent(
    existing ? originalIgnore : "",
    projectPath,
    needed,
  );
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
    inspectIgnored,
    assertLease: async () => {},
    validateConfiguration: (source) =>
      parseProjectConfiguration(source, { schemaVersion: 1 }),
    persist: async (value) => {
      saved = structuredClone(value);
    },
    // Controlled fixture effect; production supplies the existing supervised
    // no-replace directory publication capability, never an agent command.
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
  return {
    state,
    runtime,
    projectPath,
    skill,
    configurationPath,
    originalIgnore,
    get saved() {
      return saved;
    },
  };
}

test("a bare repository at the conventional provider root prevents all prerequisite publication", async (t) => {
  let inspection;
  let before;
  let workspace;
  await assert.rejects(async () => {
    const f = await fixture(t, {
      async beforeInspection(context) {
        workspace = context.workspace;
        await exec("git", [
          "init",
          "--bare",
          "--quiet",
          join(context.projectPath, ".agents"),
        ]);
        inspection = await workspace.inspect({
          workspacePath: context.projectPath,
          stateRoot: context.stateRoot,
        });
        before = await workspace.snapshot({ inspection });
      },
    });
    await publishIntegratedInit(f.state, f.runtime);
  }, /bare Git metadata/u);
  workspace.assertUnchanged({
    before,
    after: await workspace.snapshot({ inspection }),
  });
});

test("integrated publication creates ignored prerequisites, defers guidance and verifies reruns", async (t) => {
  const f = await fixture(t);
  const published = await publishIntegratedInit(f.state, f.runtime);
  assert.equal(published.prepared, true);
  assert.equal(f.state.workflowState, "PROPOSAL_ACCEPTED");
  assert.match(await fs.readFile(f.skill, "utf8"), /node --test/u);
  await assert.rejects(
    fs.stat(join(f.state.selection.artifactPath, "agent-runner", "rules.md")),
    { code: "ENOENT" },
  );
  const again = await publishIntegratedInit(f.state, f.runtime, published);
  assert.deepEqual(again, published);
  const replacement = `${f.skill}.replacement`;
  await fs.writeFile(replacement, await fs.readFile(f.skill));
  await fs.rename(replacement, f.skill);
  await assert.rejects(
    publishIntegratedInit(f.state, f.runtime, again),
    /resource changed/u,
  );
});

test("existing skills, negations and unrelated settings survive custom-root setup", async (t) => {
  const f = await fixture(t, {
    existing: true,
    artifactRoot: "build/artifacts",
  });
  const originalSkill = await fs.readFile(f.skill, "utf8");
  await publishIntegratedInit(f.state, f.runtime);
  assert.equal(await fs.readFile(f.skill, "utf8"), originalSkill);
  const wrapper = await fs.readFile(
    join(dirname(f.skill), "RUNNER.md"),
    "utf8",
  );
  assert.match(wrapper, /adjacent SKILL.md/u);
  assert.match(wrapper, /defer all staging/u);
  const configuration = JSON.parse(
    await fs.readFile(f.configurationPath, "utf8"),
  );
  assert.equal(configuration.defaultEffort, "high");
  assert.equal(configuration.pipelines.polishing.mode, "combined");
  assert.match(configuration.pipelines.polishing.finalization, /RUNNER.md$/u);
  const ignore = await fs.readFile(join(f.projectPath, ".gitignore"), "utf8");
  assert.ok(ignore.startsWith(f.originalIgnore));
  const lines = ignore.trimEnd().split("\n");
  assert.equal(new Set(lines).size, lines.length);
});

test("negated exclusions are reasserted with whitespace-clean literal rules", async (t) => {
  for (const [artifactRoot, ignore] of [
    ["artifacts", "/artifacts\n!/artifacts\n"],
    ["資料", "/資料\n!/資料\n"],
    ["artifacts", "/artifacts\n/[a]rtifacts\n/artifacts \n!/artifacts\n"],
  ]) {
    const f = await fixture(t, { existing: true, artifactRoot, ignore });
    await publishIntegratedInit(f.state, f.runtime);
    const content = await fs.readFile(
      join(f.projectPath, ".gitignore"),
      "utf8",
    );
    assert.ok(content.startsWith(ignore));
    const additions = content.slice(ignore.length);
    assert.doesNotMatch(additions, /[ \t]+$/mu);
    const lines = additions.trimEnd().split("\n");
    assert.equal(new Set(lines).size, lines.length);
    assert.deepEqual(
      await f.runtime.inspectIgnored(f.state.selection.artifactPath),
      { ignored: true, tracked: false },
    );
    assert.deepEqual(
      await f.runtime.inspectIgnored(join(f.projectPath, "unrelated.txt")),
      { ignored: false, tracked: false },
    );
  }
});

test("journaled file identity recovers a lost publication receipt without rewriting", async (t) => {
  const f = await fixture(t);
  const persist = f.runtime.persist;
  let interrupted = false;
  f.runtime.persist = async (value) => {
    if (
      !interrupted &&
      value.receipts.some(({ path }) => path.endsWith(".gitignore"))
    ) {
      interrupted = true;
      throw new Error("Interrupted receipt");
    }
    await persist(value);
  };
  await assert.rejects(
    publishIntegratedInit(f.state, f.runtime),
    /Interrupted receipt/u,
  );
  assert.equal(f.saved.pending.temporary.phase, "prepared");
  const redirected = structuredClone(f.saved);
  redirected.pending.intent.path = join(f.projectPath, "unapproved.md");
  await assert.rejects(
    publishIntegratedInit(f.state, f.runtime, redirected),
    /intent no longer matches/u,
  );
  const before = await fs.stat(join(f.projectPath, ".gitignore"));
  f.runtime.persist = persist;
  await publishIntegratedInit(f.state, f.runtime, f.saved);
  assert.equal(
    (await fs.stat(join(f.projectPath, ".gitignore"))).ino,
    before.ino,
  );
});

test("resumed pending publication rechecks effective ignoring before its effect", async (t) => {
  const f = await fixture(t);
  const artifactPath = f.state.selection.artifactPath;
  const persist = f.runtime.persist;
  f.runtime.persist = async (value) => {
    await persist(value);
    if (value.pending?.path === artifactPath && value.pending.directory)
      throw new Error("Interrupted directory intent");
  };
  await assert.rejects(
    publishIntegratedInit(f.state, f.runtime),
    /Interrupted directory intent/u,
  );
  const pending = structuredClone(f.saved.pending);
  assert.equal(pending.identity, null);
  f.runtime.persist = persist;
  const inspectIgnored = f.runtime.inspectIgnored;
  f.runtime.inspectIgnored = async (path) =>
    path === artifactPath
      ? { ignored: false, tracked: false }
      : inspectIgnored(path);
  await assert.rejects(
    publishIntegratedInit(f.state, f.runtime, f.saved),
    /exclusions are not effective/u,
  );
  await assert.rejects(fs.stat(artifactPath), { code: "ENOENT" });
  assert.deepEqual(f.saved.pending, pending);
});

test("same-content substitution after file publication cannot receive an owned receipt", async (t) => {
  let substituted = false;
  const f = await fixture(t, {
    fileSystem: {
      ...fs,
      async rename(source, destination) {
        await fs.rename(source, destination);
        if (destination.endsWith("/.gitignore")) {
          const replacement = `${destination}.replacement`;
          await fs.writeFile(replacement, await fs.readFile(destination), {
            mode: 0o600,
          });
          await fs.rename(replacement, destination);
          substituted = true;
        }
      },
    },
  });
  await assert.rejects(publishIntegratedInit(f.state, f.runtime), {
    code: "ERR_WORKSPACE_REPORT_CHANGED",
  });
  assert.equal(substituted, true);
  assert.equal(f.saved.pending.temporary.phase, "prepared");
  assert.deepEqual(f.saved.receipts, []);
  assert.notEqual(
    String(
      (await fs.stat(join(f.projectPath, ".gitignore"), { bigint: true })).ino,
    ),
    f.saved.pending.temporary.identity.inode,
  );
});

test("artifact-directory substitution before its intent is not adopted", async (t) => {
  const f = await fixture(t, { preparedArtifacts: true });
  const workspace = f.runtime.workspace;
  const path = f.state.selection.artifactPath;
  let substituted = false;
  f.runtime.workspace = {
    ...workspace,
    async inspectInfrastructure(request) {
      if (request.path === path && !substituted) {
        substituted = true;
        await fs.rename(path, join(f.runtime.stateRoot, "original-artifacts"));
        await fs.mkdir(path);
      }
      return workspace.inspectInfrastructure(request);
    },
  };
  await assert.rejects(
    publishIntegratedInit(f.state, f.runtime),
    /Reviewed resource changed before publication/u,
  );
  assert.equal(substituted, true);
  assert.equal(f.saved.pending, null);
  assert.ok(!f.saved.receipts.some((receipt) => receipt.path === path));
  assert.deepEqual(await fs.readdir(path), []);
});

test("lease loss after directory allocation prevents publication", async (t) => {
  const f = await fixture(t);
  const persist = f.runtime.persist;
  let leaseHeld = true;
  f.runtime.assertLease = async () => {
    assert.ok(leaseHeld, "Execution lease lost");
  };
  f.runtime.persist = async (value) => {
    await persist(value);
    if (value.pending?.directory && value.pending.identity !== null)
      leaseHeld = false;
  };
  let publications = 0;
  f.runtime.publishDirectory = async () => {
    publications += 1;
  };
  await assert.rejects(publishIntegratedInit(f.state, f.runtime));
  assert.equal(leaseHeld, false);
  assert.equal(publications, 0);
  await assert.rejects(fs.stat(f.state.selection.artifactPath), {
    code: "ENOENT",
  });
  const { intent, identity } = f.saved.pending;
  const allocation = await fs.stat(intent.staging.path, { bigint: true });
  assert.equal(String(allocation.ino), identity.inode);
});

test("input drift and conflicting destination settings prevent any publication", async (t) => {
  const f = await fixture(t);
  await fs.writeFile(
    join(f.projectPath, "AGENTS.md"),
    "Changed instructions.\n",
  );
  await assert.rejects(
    publishIntegratedInit(f.state, f.runtime),
    /bindings changed/u,
  );
  assert.equal(f.saved, null);
  const g = await fixture(t, {
    existing: true,
    changeConfiguration(configuration) {
      configuration.defaultEffort = "low";
    },
  });
  await assert.rejects(
    publishIntegratedInit(g.state, g.runtime),
    /preserve unrelated settings/u,
  );
  assert.equal(g.saved, null);
  const h = await fixture(t, {
    existing: true,
    wrapper: "Preserve this existing wrapper.\n",
  });
  await assert.rejects(
    publishIntegratedInit(h.state, h.runtime),
    /preserve existing skills/u,
  );
  assert.equal(h.saved, null);
});

test("changed or missing frozen clarifications prevent publication without target writes", async (t) => {
  for (const missing of [false, true]) {
    const f = await fixture(t);
    const path = join(f.state.inspection.taskPath, "clarifications.md");
    const { workspace, stateRoot } = f.runtime;
    const inspection = await workspace.inspect({
      workspacePath: f.projectPath,
      stateRoot,
    });
    const before = await workspace.snapshot({ inspection });
    if (missing) await fs.unlink(path);
    else await fs.writeFile(path, "Changed after approval.\n");

    await assert.rejects(publishIntegratedInit(f.state, f.runtime), {
      code: missing
        ? "ERR_CLARIFICATION_NOT_FOUND"
        : "ERR_CLARIFICATIONS_CHANGED",
    });
    assert.equal(f.saved, null);
    workspace.assertUnchanged({
      before,
      after: await workspace.snapshot({ inspection }),
    });
  }
});

test("clarification drift during baseline preparation cannot be adopted", async (t) => {
  const f = await fixture(t);
  const workspace = f.runtime.workspace;
  f.runtime.workspace = {
    ...workspace,
    async snapshot(request) {
      await fs.writeFile(
        join(f.state.inspection.taskPath, "clarifications.md"),
        "Changed during preparation.\n",
      );
      return workspace.snapshot(request);
    },
  };
  await assert.rejects(publishIntegratedInit(f.state, f.runtime), {
    code: "ERR_CLARIFICATIONS_CHANGED",
  });
  assert.equal(f.saved, null);
  assert.deepEqual((await fs.readdir(f.projectPath)).sort(), [
    ".git",
    "AGENTS.md",
  ]);
});
