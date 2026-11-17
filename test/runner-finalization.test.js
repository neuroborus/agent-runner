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
import { REPOSITORY_DISCOVERY_SCHEMA } from "../pipelines/plan-execution/src/bootstrap-unit-schemas.js";
import * as executionSchemas from "../pipelines/plan-execution/src/schemas.js";
import * as polishingSchemas from "../pipelines/polishing/src/schemas.js";
import * as execution from "../pipelines/plan-execution/test/support/index.js";
import * as polishing from "../pipelines/polishing/test/support/index.js";
import { planExecutionPipeline } from "../pipelines/plan-execution/src/index.js";
import {
  createFinalizationGuidanceDecision as executionDecision,
  normalizeFinalizationResult as normalizeExecutionFinalization,
} from "../pipelines/plan-execution/src/workflow-contract.js";
import { polishingPipeline } from "../pipelines/polishing/src/index.js";
import {
  createFinalizationGuidanceDecision as polishingDecision,
  normalizeFinalizationResult as normalizePolishingFinalization,
} from "../pipelines/polishing/src/workflow-contract.js";

function assertEvidenceContract(prompt) {
  for (const fact of [
    /Runner owns persisted finalization properties/u,
    /per-check executor, commandIdentity, exitCode, signal and timedOut/u,
    /only the supplied closed schema/u,
    /SHA256\(JSON\.stringify\(\{infrastructure, finalizationFile\}\)\)/u,
    /selected label excluded/u,
    /raw digest over all inventory paths is a different domain/u,
    /Legacy "skill" and fallback/u,
    /Reject actual mismatches and insufficient evidence/u,
    /Never rerun reserved checks or manage Runner CLI or admission/u,
    /"finalizationGuidance":/u,
  ])
    assert.match(prompt, fact);
  assert.match(prompt, /project-defined first, final and relative-order/u);
  assert.match(prompt, /Additions are not automatically appended/u);
  assert.match(prompt, /declared inventory and ordered evidence/u);
  assert.match(
    prompt,
    /never rewrites original discovery or future assignments/u,
  );
  assert.match(prompt, /array order proves no execution sequence/u);
  assert.match(
    prompt,
    /Runner executes their frozen vectors after Worker returns/u,
  );
  assert.match(prompt, /Do not invent a later Worker phase/u);
  assert.match(
    prompt,
    /separately explicit physical sequencing requirement remains binding/u,
  );
  assert.match(prompt, /Runner's serial executor is the only exception/u);
  assert.match(
    prompt,
    /within one persisted finalization record, entries whose Runner-owned executor is "runner" therefore establish their relative physical order, after that FINALIZE turn's agent-owned work/iu,
  );
  assert.match(
    prompt,
    /such as an agent-owned check required after a Runner-trusted one, use the existing blocking outcome/u,
  );
}

async function selectedFixture(
  t,
  pipeline,
  placement,
  repositoryProcedure = false,
  mode = "independent",
) {
  const support = pipeline === "execution" ? execution : polishing;
  const skillPath =
    placement === "external"
      ? "finalization/SKILL.md"
      : ".agents/skills/finalization/RUNNER.md";
  const guidancePath =
    placement === "external" ? `finalization://${skillPath}` : skillPath;
  const referencePath = "docs/validation.md";
  const procedure =
    "Read mandatory repository reference docs/validation.md under existing read authority.\n";
  const result = {
    ...support.finalizationPassed(guidancePath),
    validationInfrastructure: [
      ...support.VALIDATION_INFRASTRUCTURE,
      ...(repositoryProcedure ? [skillPath] : []),
      guidancePath,
      referencePath,
    ],
  };
  const bootstrap = {
    ...support.bootstrapReady("Worker"),
    validationInfrastructure: result.validationInfrastructure,
  };
  const prepareProject = async (projectPath) => {
    await mkdir(join(projectPath, "docs"), { recursive: true });
    await writeFile(
      join(projectPath, referencePath),
      "Run the required project checks.\n",
    );
    if (repositoryProcedure || placement === "integrated") {
      const file = join(projectPath, skillPath);
      await mkdir(dirname(file), { recursive: true });
      await writeFile(
        file,
        repositoryProcedure ? "Repository validation procedure.\n" : procedure,
      );
    }
  };
  const f = await support.createFixture(
    t,
    pipeline === "execution"
      ? {
          mode,
          modeSettings: { finalization: skillPath },
          prepareProject,
          worker: [
            execution.clarificationReady(),
            bootstrap,
            ...(mode === "lazy" ? [] : [execution.reconciliationResolved()]),
          ],
          workWorker: [
            execution.implementationCompleted(),
            ...(mode === "independent" ? [] : [execution.checkAndFix()]),
            ...(mode === "independent" ? [] : [execution.cleanConfirmation()]),
            result,
            ...(mode === "lazy"
              ? [
                  execution.terminalLazyConfirmation(
                    execution.cleanConfirmation(),
                  ),
                ]
              : []),
          ],
        }
      : {
          mode,
          prepareProject,
          settings: { ...polishing.SETTINGS, finalization: skillPath },
          worker: [
            polishing.clarificationReady(),
            bootstrap,
            ...(mode === "lazy" ? [] : [polishing.reconciliationResolved()]),
            polishing.polishingCompleted(),
            ...(mode === "independent" ? [] : [polishing.candidateClean()]),
            result,
            ...(mode === "lazy" ? [polishing.cleanConfirmation()] : []),
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
  await writeFile(path, procedure);
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
    referencePath,
    workerResult: result,
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

  for (const [placement, mode] of [
    ["integrated", "independent"],
    ["integrated", "lazy"],
    ["integrated", "combined"],
    ["external", "independent"],
  ]) {
    test(`${pipeline} carries the exact ${placement} Markdown procedure and evidence contract in ${mode} mode`, async (t) => {
      const f = await selectedFixture(t, pipeline, placement, false, mode);
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
      const schemas =
        pipeline === "execution" ? executionSchemas : polishingSchemas;
      const bootstrapSchema =
        pipeline === "execution"
          ? REPOSITORY_DISCOVERY_SCHEMA
          : schemas.BOOTSTRAP_SCHEMA;
      const bootstrapRequests = [...f.calls.worker, ...f.calls.reviewer].filter(
        ({ schema }) => schema === bootstrapSchema,
      );
      assert.equal(bootstrapRequests.length, mode === "lazy" ? 1 : 2);
      for (const request of bootstrapRequests) {
        for (const prompt of [request.prompt, request.recoveryPrompt]) {
          assert.ok(prompt.includes(f.guidancePath));
          assert.match(prompt, /mandatory repository references/u);
          assert.match(prompt, /all known applicable checks during bootstrap/u);
          assert.match(prompt, /available supplemental validators/u);
          assert.match(
            prompt,
            /project-defined first, final and relative-order/u,
          );
          assert.match(
            prompt,
            /references controlling validation commands or gate behavior in validationInfrastructure/u,
          );
        }
      }
      const evidenceRequests = [...f.calls.worker, ...f.calls.reviewer].filter(
        ({ schema }) =>
          [
            schemas.FINALIZATION_SCHEMA,
            schemas.REVIEW_SCHEMA,
            schemas.CLEAN_CONFIRM_SCHEMA,
          ].includes(schema),
      );
      assert.equal(evidenceRequests.length, 2);
      for (const request of evidenceRequests) {
        assertEvidenceContract(request.prompt);
        assertEvidenceContract(request.recoveryPrompt);
        if (request.schema !== schemas.FINALIZATION_SCHEMA) {
          for (const prompt of [request.prompt, request.recoveryPrompt]) {
            assert.match(prompt, /actual selected finalization guidance/u);
            assert.match(prompt, /including added checks and their positions/u);
            assert.match(prompt, /passing checks alone/u);
          }
        }
        const tuple = JSON.parse(
          /Established validation tuple:\n([\s\S]*?)\n\n/u.exec(
            request.prompt,
          )[1],
        );
        assert.deepEqual(
          tuple.finalizationGuidance,
          completed.pipelineState.finalizationGuidance,
        );
      }
      if (placement === "integrated" && mode === "independent") {
        const state = completed.pipelineState;
        const descriptor =
          pipeline === "execution" ? planExecutionPipeline : polishingPipeline;
        const raw = await f.runtime.git.validationInfrastructureFingerprint({
          paths: state.validationInfrastructure,
          projectPath: f.projectPath,
        });
        assert.notEqual(
          raw,
          state.finalizationResult.validationInfrastructureFingerprint,
        );
        assert.doesNotThrow(() => descriptor.workflow.validateRun(completed));
        for (const mutate of [
          (candidate) => {
            candidate.finalizationResult.fingerprint = "f".repeat(64);
          },
          (candidate) => {
            candidate.finalizationResult.validationInfrastructureFingerprint =
              raw;
          },
          (candidate) => {
            candidate.finalizationGuidance.selectedFileFingerprint = "f".repeat(
              64,
            );
          },
          (candidate) => {
            candidate.finalizationResult.checks[0].command =
              "node other-check.js";
          },
          (candidate) => {
            candidate.finalizationResult.trustedCommandFingerprint = "f".repeat(
              64,
            );
          },
          (candidate) => {
            candidate.finalizationResult.trustedConfigurationFingerprint =
              "f".repeat(64);
          },
        ]) {
          const candidate = structuredClone(completed);
          mutate(candidate.pipelineState);
          assert.throws(() => descriptor.workflow.validateRun(candidate));
        }
        const normalize =
          pipeline === "execution"
            ? normalizeExecutionFinalization
            : normalizePolishingFinalization;
        for (const field of [
          "fingerprint",
          "validationInfrastructureFingerprint",
          "validationChanged",
        ]) {
          assert.throws(() =>
            normalize({
              ...f.workerResult,
              [field]: state.finalizationResult[field],
            }),
          );
        }
        const support = pipeline === "execution" ? execution : polishing;
        assert.equal(
          support.matchesSchemaSubset(schemas.FINALIZATION_SCHEMA, {
            ...f.workerResult,
            checks: f.workerResult.checks.map((check) => ({
              ...check,
              executor: "runner",
            })),
          }),
          false,
        );
      }
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
            recoveryPrompt.includes(f.guidancePath) &&
            /mandatory repository references/u.test(recoveryPrompt) &&
            /no parent-directory or external sibling access or recursive retrieval/u.test(
              recoveryPrompt,
            ),
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

  test(`${pipeline} invalidates finalization when a controlling repository reference digest drifts`, async (t) => {
    const f = await selectedFixture(t, pipeline, "integrated");
    const schemas =
      pipeline === "execution" ? executionSchemas : polishingSchemas;
    const support = pipeline === "execution" ? execution : polishing;
    let drifted = false;
    let inspectedReference = false;
    const transition = f.runtime.transition;
    f.runtime.transition = async (patch, options) => {
      const run = await transition(patch, options);
      if (
        options.activity?.phase === "finalization" &&
        options.activity.kind === "passed"
      )
        drifted = true;
      return run;
    };
    const fingerprint = f.runtime.git.validationInfrastructureFingerprint;
    f.runtime.git.validationInfrastructureFingerprint = (options) => {
      if (options.paths.includes(f.referencePath)) {
        inspectedReference = true;
        assert.ok(!options.paths.includes(f.guidancePath));
        if (drifted) return support.hash("changed controlling reference");
      }
      return fingerprint(options);
    };
    const worker = f.runtime.adapters.worker.run;
    f.runtime.adapters.worker.run = (request) => {
      if (drifted && request.schema === schemas.FINALIZATION_SCHEMA) {
        throw Object.assign(new Error("Fixture provider unavailable."), {
          recoverable: true,
        });
      }
      return worker(request);
    };
    const paused = await f.start();
    assert.ok(inspectedReference);
    assert.equal(paused.pause.reason, "backend_unavailable");
    assert.equal(paused.pause.resumeState, "FINALIZE");
    assert.equal(paused.pipelineState.finalizationResult, null);
    assert.equal(
      f.calls.reviewer.filter(({ schema }) => schema === schemas.REVIEW_SCHEMA)
        .length,
      0,
    );
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
    const finalization = completed.pipelineState.finalizationResult;
    assert.equal(
      finalization.validationInfrastructureFingerprint,
      await f.runtime.git.validationInfrastructureFingerprint({
        paths: finalization.validationInfrastructure,
        projectPath: f.projectPath,
      }),
    );
  });
}
