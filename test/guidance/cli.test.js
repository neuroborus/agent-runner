import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  createGuidanceService,
  createRunStore,
  main,
} from "../../src/index.js";
import { readProcessIdentity } from "../../src/platform/index.js";
import {
  recordCompletedModelTurn,
  recordReadOnlyCatalogMiss,
} from "../support/model-catalog.js";
import { fixture } from "./support/index.js";

test("CLI reads and edits complete guidance through explicit project configuration", async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(
    join(f.projectPath, "LOCAL_ARTIFACTS", "custom.json"),
    '{"schemaVersion":1,"artifactRoot":"CUSTOM_ARTIFACTS"}',
  );
  const localContent = "# Local additions\n\nThe whole project lesson.\n";
  const guidance = f.createService({
    env: { EDITOR: "test-editor" },
    temporaryRoot: f.root,
    async launchEditor(_, path) {
      await writeFile(path, localContent);
      return { exitCode: 0, signal: null };
    },
  });
  let output = "";
  let errors = "";
  const options = {
    guidance,
    stdout: {
      write: (chunk) => {
        output += chunk;
      },
    },
    stderr: {
      write: (chunk) => {
        errors += chunk;
      },
    },
    createCommandRunner: () =>
      assert.fail("guidance must not construct a runner"),
  };
  const selectors = [
    "--project",
    f.projectPath,
    "--project-config",
    "LOCAL_ARTIFACTS/custom.json",
  ];
  assert.equal(await main(["guidance", "edit", ...selectors], options), 0);
  assert.equal(output, "Local guidance updated.\n");
  assert.equal(
    await readFile(
      join(f.projectPath, "CUSTOM_ARTIFACTS", "agent-runner", "rules.md"),
      "utf8",
    ),
    localContent,
  );
  output = "";
  assert.equal(await main(["guidance", ...selectors], options), 0);
  const common = await readFile(
    new URL("../../docs/OPERATOR_GUIDE.md", import.meta.url),
    "utf8",
  );
  assert.ok(output.includes(common));
  assert.ok(output.endsWith(localContent));
  assert.equal(errors, "");
});

test("CLI guidance editor failures produce concise errors and preserve local content", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const guidance = f.createService({
    env: { EDITOR: "test-editor" },
    temporaryRoot: f.root,
    async launchEditor(_, path) {
      await writeFile(path, "PRIVATE_EDIT_MARKER");
      return { exitCode: 9, signal: null };
    },
  });
  let errors = "";
  assert.equal(
    await main(["guidance", "edit", "--project", f.projectPath], {
      guidance,
      stdout: { write: () => assert.fail("must not print success") },
      stderr: {
        write: (chunk) => {
          errors += chunk;
        },
      },
    }),
    1,
  );
  assert.match(errors, /editor did not exit successfully/u);
  assert.doesNotMatch(errors, /PRIVATE_EDIT_MARKER|Error:|\n\s+at /u);
  assert.equal(await readFile(f.localPath, "utf8"), "Before.");
});

async function checkGuidanceLeaseReclamation(t, edit) {
  const f = await fixture(t, {
    initialContent: "Before.",
    stateRoot: (root) => join(root, "agent-runner"),
  });
  t.mock.property(process, "env", {
    ...process.env,
    XDG_CONFIG_HOME: f.root,
    XDG_STATE_HOME: f.root,
  });
  const identity = await readProcessIdentity(process.pid);
  // Model PID reuse without starting or terminating an unrelated process.
  const owner = createRunStore({
    stateRoot: f.stateRoot,
    processIdentity: async () => ({
      ...identity,
      startTicks: String(BigInt(identity.startTicks) + 1n),
    }),
  });
  const taskPath = join(f.root, "task");
  await mkdir(taskPath);
  const pipelineState = {
    workflowState: "REVIEW",
    reviewCorrection: null,
    pendingReviewCorrection: null,
  };
  const role = "reviewer";
  const model = "test-model";
  const { state, lease } = await owner.createRun({
    pipelineId: "polishing",
    pipelineStateVersion: 25,
    projectPath: f.projectPath,
    taskPath,
    roles: { [role]: { backend: "codex", model } },
    pipelineState,
  });
  const workspace = await owner.acquireWorktreeLease(
    f.projectPath,
    state.runId,
  );
  let reclaimed = false;
  try {
    const turn = { role, phase: "review" };
    const activity = {
      actor: role,
      phase: turn.phase,
      kind: "turn-started",
      message: "Candidate review started.",
    };
    const checkpoint = "review:read-only:review";
    await owner.startAgentTurn(lease, turn, { activity });
    await recordCompletedModelTurn(owner, lease, turn, { model });
    await recordReadOnlyCatalogMiss(owner, lease, turn, {
      activity,
      checkpoint,
    });
    await owner.transitionRun(lease, {
      pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
      activeTurn: null,
      pause: {
        reason: "backend_unavailable",
        code: "ERR_MODEL_CATALOG_RETRY",
        resumeState: "REVIEW",
        role,
        checkpoint,
      },
    });
    await owner.transitionRun(lease, { pipelineState, pause: null });
    await owner.startAgentTurn(lease, turn, {
      activity,
      catalogCheckpoint: checkpoint,
    });

    await owner.recordExecutionProcess(lease, process.pid);
    try {
      await edit(f, { allowed: false });
      assert.equal(await readFile(f.localPath, "utf8"), "Before.");
    } finally {
      await owner.recordExecutionProcess(lease, null);
      await owner.finishAgentTurn(lease, turn);
    }

    await edit(f, { allowed: true });
    reclaimed = true;
    assert.equal(await readFile(f.localPath, "utf8"), "New guidance.");
  } finally {
    if (!reclaimed) await workspace.release();
    await lease.release();
  }
}

test("CLI guidance reclaims a retired catalog retry lease after outstanding effects settle", async (t) => {
  await checkGuidanceLeaseReclamation(t, async (f, { allowed }) => {
    let output = "";
    let errors = "";
    const status = await main(
      ["guidance", "edit", "--project", f.projectPath],
      {
        createCommandGuidance: (options) =>
          f.createService({
            ...options,
            env: { EDITOR: "test-editor" },
            temporaryRoot: f.root,
            async launchEditor(_, path) {
              await writeFile(path, "New guidance.");
              return { exitCode: 0, signal: null };
            },
          }),
        stdout: {
          write: (chunk) => {
            output += chunk;
          },
        },
        stderr: {
          write: (chunk) => {
            errors += chunk;
          },
        },
      },
    );
    assert.equal(status, allowed ? 0 : 1, errors);
    assert.equal(output, allowed ? "Local guidance updated.\n" : "");
    assert.equal(
      errors,
      allowed ? "" : "Guidance operation could not complete safely.\n",
    );
  });
});

test("the public guidance factory reclaims a retired catalog retry lease after outstanding effects settle", async (t) => {
  await checkGuidanceLeaseReclamation(t, async (f, { allowed }) => {
    const guidance = createGuidanceService();
    const { localHash } = await guidance.read({ projectPath: f.projectPath });
    const update = guidance.update(
      f.request("New guidance.", { expectedHash: localHash }),
    );
    if (allowed) await update;
    else await assert.rejects(update, { code: "ERR_WORKTREE_LEASED" });
  });
});
