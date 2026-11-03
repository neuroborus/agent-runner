import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { inspectFinalizationFile } from "../src/config/index.js";
import * as execution from "../pipelines/plan-execution/test/support/index.js";
import * as polishing from "../pipelines/polishing/test/support/index.js";
import { planExecutionPipeline } from "../pipelines/plan-execution/src/index.js";
import { createFinalizationGuidanceDecision as executionDecision } from "../pipelines/plan-execution/src/workflow-contract.js";
import { polishingPipeline } from "../pipelines/polishing/src/index.js";
import { createFinalizationGuidanceDecision as polishingDecision } from "../pipelines/polishing/src/workflow-contract.js";

async function selectedFixture(
  t,
  pipeline,
  placement,
  repositoryProcedure = false,
) {
  const support = pipeline === "execution" ? execution : polishing;
  const skillPath =
    placement === "external"
      ? "finalization/SKILL.md"
      : ".agents/skills/finalization/RUNNER.md";
  const guidancePath =
    placement === "external" ? `finalization://${skillPath}` : skillPath;
  const result = {
    ...support.finalizationPassed(guidancePath),
    validationInfrastructure: [
      ...support.VALIDATION_INFRASTRUCTURE,
      ...(repositoryProcedure ? [skillPath] : []),
      guidancePath,
    ],
  };
  const bootstrap = {
    ...support.bootstrapReady("Worker"),
    validationInfrastructure: result.validationInfrastructure,
  };
  const prepareProject =
    repositoryProcedure || placement === "integrated"
      ? async (projectPath) => {
          const file = join(projectPath, skillPath);
          await mkdir(dirname(file), { recursive: true });
          await writeFile(
            file,
            repositoryProcedure
              ? "Repository validation procedure.\n"
              : "Run project checks without staging.\n",
          );
        }
      : undefined;
  const f = await support.createFixture(
    t,
    pipeline === "execution"
      ? {
          prepareProject,
          worker: [
            execution.clarificationReady(),
            bootstrap,
            execution.reconciliationResolved(),
          ],
          workWorker: [execution.implementationCompleted(), result],
        }
      : {
          prepareProject,
          settings: { ...polishing.SETTINGS, finalization: skillPath },
          worker: [
            polishing.clarificationReady(),
            bootstrap,
            polishing.reconciliationResolved(),
            polishing.polishingCompleted(),
            result,
          ],
        },
  );
  const root =
    placement === "external"
      ? await mkdtemp(join(tmpdir(), "runner-selected-procedure-"))
      : f.projectPath;
  if (placement === "external")
    t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, skillPath);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, "Run project checks without staging.\n");
  f.runtime.finalization.inspectFile = ({ path, policy }) =>
    inspectFinalizationFile({
      path,
      projectPath: f.projectPath,
      infrastructureRoot: policy === "auto" ? f.projectPath : root,
    });
  return {
    ...f,
    path,
    skillPath,
    guidancePath,
    start: () =>
      pipeline === "execution" ? f.run({ finalization: skillPath }) : f.run(),
  };
}

async function pauseBeforeAgentTurn(f, start) {
  const stopped = Object.assign(new Error("Fixture provider unavailable."), {
    recoverable: true,
  });
  const run = f.runtime.adapters.worker.run;
  f.runtime.adapters.worker.run = async () => {
    throw stopped;
  };
  const paused = await start();
  f.runtime.adapters.worker.run = run;
  assert.equal(paused.pause.reason, "backend_unavailable");
  return paused;
}

for (const pipeline of ["execution", "polishing"]) {
  test(`${pipeline} fingerprints repository validation beside external guidance with the same relative path`, async (t) => {
    const f = await selectedFixture(t, pipeline, "external", true);
    const fingerprint = f.runtime.git.validationInfrastructureFingerprint;
    const inspected = [];
    f.runtime.git.validationInfrastructureFingerprint = async (options) => {
      inspected.push(options.paths);
      return fingerprint(options);
    };
    const completed = await f.start();
    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    assert.ok(
      completed.pipelineState.validationInfrastructure.includes(f.skillPath),
    );
    assert.ok(
      completed.pipelineState.validationInfrastructure.includes(f.guidancePath),
    );
    assert.ok(
      inspected.some((paths) => paths.includes(f.skillPath)),
      "Repository validation must remain in the fingerprint alongside external guidance.",
    );
  });

  for (const placement of ["integrated", "external"]) {
    test(`${pipeline} carries the exact ${placement} Markdown procedure through bootstrap and terminal evidence`, async (t) => {
      const f = await selectedFixture(t, pipeline, placement);
      const originalSkill = join(
        f.projectPath,
        ".agents/skills/finalization/SKILL.md",
      );
      const original = await readFile(originalSkill);
      const completed = await f.start();
      assert.equal(
        completed.pipelineState.workflowState,
        "DONE",
        JSON.stringify(completed.pause),
      );
      assert.equal(
        completed.pipelineState.finalizationGuidance.selection,
        "file",
      );
      assert.equal(
        completed.pipelineState.finalizationResult.skillPath,
        f.guidancePath,
      );
      assert.ok(
        completed.pipelineState.validationInfrastructure.includes(
          f.guidancePath,
        ),
      );
      assert.equal(
        completed.pipelineState.finalizationResult
          .validationInfrastructureFingerprint,
        completed.pipelineState.validationInfrastructureFingerprint,
      );
      const reads = [...f.calls.worker, ...f.calls.reviewer].filter(
        ({ readPaths }) => readPaths,
      );
      assert.ok(reads.length > 3);
      assert.ok(
        reads.every(
          ({ readPaths, prompt, recoveryPrompt, session }) =>
            readPaths.length === 1 &&
            readPaths[0] === f.path &&
            (session?.mode === "continue"
              ? !prompt.includes("Frozen finalization file:")
              : prompt.includes(f.path)) &&
            recoveryPrompt.includes(f.path) &&
            recoveryPrompt.includes(f.guidancePath),
        ),
      );
      assert.deepEqual(await readFile(originalSkill), original);
    });
  }

  test(`${pipeline} rejects identical-byte replacement on resumed validation without another provider turn`, async (t) => {
    const f = await selectedFixture(t, pipeline, "external");
    await pauseBeforeAgentTurn(f, f.start);
    const before = f.calls.worker.length + f.calls.reviewer.length;
    const bytes = await readFile(f.path);
    await rename(f.path, `${f.path}.original`);
    await writeFile(f.path, bytes);
    const resumed = await f.start();
    assert.equal(resumed.pause.reason, "finalization_skill_invalid");
    assert.equal(resumed.pause.code, "ERR_FINALIZATION_GUIDANCE_CHANGED");
    assert.equal(f.calls.worker.length + f.calls.reviewer.length, before);
  });
}

for (const [pipeline, support, decision, version] of [
  [planExecutionPipeline, execution, executionDecision, 35],
  [polishingPipeline, polishing, polishingDecision, 18],
]) {
  test(`${pipeline.id} resumes a legacy selection without rediscovering or manufacturing file identity proof`, async (t) => {
    const f = await support.createFixture(t);
    const paused = await pauseBeforeAgentTurn(f, f.run);
    const skillPath = ".agents/skills/finalization/SKILL.md";
    const legacy = decision({
      configuredPolicy: "auto",
      skillPath,
      selectedFileFingerprint:
        await f.runtime.git.validationInfrastructureFingerprint({
          paths: [skillPath],
          projectPath: f.projectPath,
        }),
    });
    const state = { ...paused.pipelineState, finalizationGuidance: legacy };
    const migrated = pipeline.migrations[version]({ pipelineState: state });
    assert.deepEqual(migrated, state);
    await f.persistPipelineState(migrated);
    f.runtime.finalization.inspectFile = () =>
      assert.fail("Legacy selection was rebound.");
    const completed = await f.run();
    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    assert.deepEqual(completed.pipelineState.finalizationGuidance, legacy);
  });
}
