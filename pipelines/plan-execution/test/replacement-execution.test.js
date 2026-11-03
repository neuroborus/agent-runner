import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  attachOutputExhaustion,
  outputExhaustion,
} from "../../../test/support/output-exhaustion.js";

import {
  planExecutionPipeline,
  createPlanExecutionState,
  runPlanExecution,
} from "../src/index.js";
import { normalizeExecutionState } from "../src/bootstrap-progress.js";
import {
  resolveStopBoundary,
  verifiedCommitCheckpoint,
} from "../src/commit-checkpoint.js";
import {
  retainReplacementCorrections,
  replacementCorrectionConsumed,
  createReplacementCoordinator,
} from "../src/replacement-execution.js";
import {
  retainReplacementFindingAccounting,
  replacementSameFindingRounds,
} from "../src/replacement-findings.js";
import { normalizeResolutionResult } from "../src/workflow-contract.js";
import { COMMIT_SIZE_ASSESSMENT_SCHEMA } from "../src/commit-size-assessment.js";
import { EFFECTIVE_PLAN_REVIEW_SCHEMA } from "../src/effective-plan.js";
import { effectivePlanAuthority } from "../src/plan-position.js";
import {
  CANDIDATE_REVIEW_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  FINALIZATION_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  IMPLEMENTATION_SCHEMA,
} from "../src/schemas.js";
import {
  bootstrapReady,
  bootstrapCapacityExhausted,
  bootstrapProductDecision,
  checkAndFix,
  compatibilityReady,
  createFixture,
  finalizationPassed,
  hash,
  implementationCompleted,
  reconsideration,
  resolution,
  reviewFindings,
  reviewProductDecision,
  SETTINGS,
} from "./support/index.js";

const replacementPlan = `## Commit 1: feat(reader): add the reader

Implement the reader.

## Commit 2: feat(runtime): use the reader

Integrate the reader and retained future work.
`;

// Workspace effects are controlled here; state/Git preservation suites own real
// storage, path confinement and interrupted atomic filesystem operations.
async function fixture(
  t,
  {
    mode = "combined",
    crash,
    boundaryLines = 2701,
    amendment = false,
    exhaustPhase,
    mutatePhase,
    unchangedPlanRepair = false,
    stopAfterPreparation = false,
    revisionDiscovery,
    decisionRole,
    rejectInputReview = false,
    lateDecisionStep,
    renamedSiblingFinding = false,
    ownedFinding,
    repairGrowth = false,
    mixedDispute = false,
    reconsiderOwnedFinding = false,
    futureContent = "retained future work\n",
  } = {},
) {
  let failed = false;
  let amended = false;
  let rejectedPlan = false;
  let planRepairs = 0;
  let boundFinding = false;
  let commits = 0;
  let decided = false;
  let grew = false;
  let requestedRepair = false;
  const turns = [];
  const captured = new Map();
  const restored = new Map();
  const worker = Array.from(
    { length: lateDecisionStep || mixedDispute ? 4 : 3 },
    () => [implementationCompleted(), checkAndFix(), finalizationPassed()],
  ).flat();
  worker.push(
    revisionDiscovery ??
      (decisionRole === "worker"
        ? bootstrapProductDecision()
        : bootstrapReady("Worker", [1, 2])),
    compatibilityReady(),
    bootstrapReady("Worker", [1, 2]),
  );
  const f = await createFixture(t, {
    mode,
    workWorker: worker,
    workReviewer: [
      decisionRole === "reviewer"
        ? bootstrapProductDecision()
        : bootstrapReady("Reviewer", [1, 2]),
      bootstrapReady("Reviewer", [1, 2]),
      ...(mixedDispute ? [reconsideration("WITHDRAW", "R2")] : []),
    ],
    async onRoleRun(role, request) {
      turns.push([role, f.currentRun.activeTurn.phase, request.access]);
      if (
        request.schema === IMPLEMENTATION_SCHEMA &&
        !f.currentRun.pipelineState.effectivePlanRevisions.revisions.length
      )
        await writeFile(join(request.cwd, "future.txt"), futureContent);
      if (
        request.schema === IMPLEMENTATION_SCHEMA &&
        f.currentRun.pipelineState.currentStep === 2
      ) {
        assert.match(request.prompt, /Preserved unfinished work/u);
        assert.equal(
          await readFile(join(request.cwd, "implementation-1.txt"), "utf8"),
          "implemented step 1\n",
        );
        await writeFile(join(request.cwd, "future.txt"), futureContent);
      }
      if (request.access === "local-commit") commits++;
    },
    onCommitVerify() {
      if (crash === "commit" && !failed) {
        failed = true;
        throw new Error("Interrupted verification");
      }
    },
    onTransition(run) {
      if (
        ownedFinding &&
        !boundFinding &&
        run.pipelineState.stepImplementation?.accepted &&
        run.pipelineState.effectivePlanRevisions.revisions.length === 0
      ) {
        boundFinding = true;
        f.persistPipelineState({
          ...run.pipelineState,
          previousFindings: [ownedFinding],
          ...(reconsiderOwnedFinding
            ? { reviewReconsideration: [ownedFinding.id] }
            : {}),
          disputeCounts: { [ownedFinding.id]: 1 },
          disputeHistory: [
            {
              findingId: ownedFinding.id,
              attempt: 1,
              direction: "UPHOLD",
              workerReason: "The original finding was disputed.",
              workerEvidence: ["Original inspected source."],
              reviewerReason: "The finding remains applicable.",
              reviewerEvidence: ["Original source still exhibits the defect."],
            },
          ],
          findingArbitrations: [
            {
              findingId: ownedFinding.id,
              direction: "REVIEWER_CORRECT",
              rationale: "The original version must be fixed.",
            },
          ],
        });
      }
      if (
        amendment &&
        !amended &&
        run.pipelineState.stepImplementation?.accepted &&
        (amendment === true
          ? run.pipelineState.effectivePlanRevisions.revisions.length === 0
          : run.pipelineState.currentStep === amendment &&
            run.pipelineState.effectivePlanRevisions.revisions.length > 0)
      ) {
        amended = true;
        f.persistPipelineState({
          ...run.pipelineState,
          validationAmendment: {
            step: run.pipelineState.currentStep,
            requiredChecks: run.pipelineState.requiredChecks,
            confirmationFingerprint: hash("accepted amendment"),
          },
        });
      }
      if (
        crash === "assessment" &&
        !failed &&
        run.pipelineState.commitSizeAssessment.lineages[0]?.attempts[0]?.result
          ?.decision === "SPLIT" &&
        run.pipelineState.effectivePlanRevisions.revisions.length === 0
      ) {
        failed = true;
        throw new Error("Interrupted assessment publication");
      }
      if (
        crash === "acceptance" &&
        !failed &&
        run.pipelineState.effectivePlanRevisions.revisions.at(-1)?.accepted
      ) {
        failed = true;
        throw new Error("Interrupted acceptance publication");
      }
      if (
        crash === "input-acceptance" &&
        !failed &&
        run.pipelineState.replacementExecution.inputChanges.at(-1)
          ?.validation &&
        run.pipelineState.replacementExecution.inputChanges.at(-1).reports
          .length
      ) {
        failed = true;
        throw new Error("Interrupted input acceptance");
      }
      if (
        crash === "input-review" &&
        !failed &&
        run.pipelineState.replacementExecution.inputChanges
          .at(-1)
          ?.reports.some(({ status }) => status === "FINDINGS")
      ) {
        failed = true;
        throw new Error("Interrupted input-review publication");
      }
      if (
        stopAfterPreparation &&
        !failed &&
        run.pipelineState.replacementExecution.separations.at(-1)?.phase ===
          "ready"
      ) {
        failed = true;
        throw new Error("Interrupted prepared replacement");
      }
    },
  });
  f.runtime.git.measureChanges = async ({
    baseHead,
    expectedContentFingerprint,
  }) => ({
    baseHead,
    contentFingerprint: expectedContentFingerprint,
    changedLines: captured.size ? 1 : boundaryLines,
    changedPaths: ["implementation-1.txt", "future.txt"],
    additions: boundaryLines,
    deletions: 0,
    binaryPaths: [],
    gitlinkPaths: [],
  });
  for (const [role, adapter] of Object.entries(f.runtime.adapters)) {
    const original = adapter.run;
    adapter.run = async (request) => {
      if ((repairGrowth || mixedDispute) && !grew) {
        if (
          (mode === "independent" || mixedDispute) &&
          request.schema === CANDIDATE_REVIEW_SCHEMA
        ) {
          requestedRepair = true;
          const {
            validationChange,
            validationEvidence,
            finalizationFindingIds,
            ...structured
          } = reviewFindings(...(mixedDispute ? ["R1", "R2"] : ["R1"]));
          turns.push([role, f.currentRun.activeTurn.phase, request.access]);
          return { sessionId: `${role}-${turns.length}`, structured };
        }
        if (
          (!mixedDispute && request.schema === CHECK_AND_FIX_SCHEMA) ||
          (requestedRepair && request.schema === FINDING_RESOLUTION_SCHEMA)
        ) {
          grew = true;
          boundaryLines = 2701;
          await writeFile(
            join(request.cwd, "future.txt"),
            "retained future work after repair\n",
          );
          if (mode === "independent" || mixedDispute) {
            turns.push([role, f.currentRun.activeTurn.phase, request.access]);
            return {
              sessionId: `${role}-${turns.length}`,
              structured: {
                result: resolution(
                  { id: "R1", decision: "FIX" },
                  ...(mixedDispute ? [{ id: "R2", decision: "DISPUTE" }] : []),
                ),
              },
            };
          }
          const result = await original(request);
          return { ...result, structured: checkAndFix("CHANGED") };
        }
      }
      if (
        !decided &&
        lateDecisionStep &&
        request.schema === CANDIDATE_REVIEW_SCHEMA &&
        f.currentRun.pipelineState.currentStep === lateDecisionStep
      ) {
        decided = true;
        turns.push([role, f.currentRun.activeTurn.phase, request.access]);
        const {
          validationChange,
          validationEvidence,
          finalizationFindingIds,
          ...structured
        } = reviewProductDecision();
        return { sessionId: `${role}-${turns.length}`, structured };
      }
      if (
        renamedSiblingFinding &&
        request.schema === CANDIDATE_REVIEW_SCHEMA &&
        f.currentRun.pipelineState.currentStep === 2
      ) {
        turns.push([role, f.currentRun.activeTurn.phase, request.access]);
        const {
          validationChange,
          validationEvidence,
          finalizationFindingIds,
          ...structured
        } = reviewFindings("R2");
        structured.findings = [{ ...ownedFinding, id: "R2" }];
        return {
          sessionId: `${role}-${turns.length}`,
          structured,
        };
      }
      if (!failed && f.currentRun.activeTurn.phase === exhaustPhase) {
        failed = true;
        throw outputExhaustion();
      }
      if (!failed && f.currentRun.activeTurn.phase === mutatePhase) {
        failed = true;
        await writeFile(join(request.cwd, "source.js"), "Unexpected edit.\n");
      }
      if (
        unchangedPlanRepair &&
        request.schema?.properties?.replacementPlan &&
        !request.schema.properties.bindingFingerprint
      ) {
        turns.push([role, f.currentRun.activeTurn.phase, request.access]);
        planRepairs++;
        return {
          sessionId: `${role}-${turns.length}`,
          structured: {
            replacementPlan:
              planRepairs === 1
                ? replacementPlan
                : replacementPlan.replace(
                    "Implement the reader.",
                    "Implement the reader while preserving dependencies.",
                  ),
          },
        };
      }
      if (
        request.schema === COMMIT_SIZE_ASSESSMENT_SCHEMA ||
        request.schema === EFFECTIVE_PLAN_REVIEW_SCHEMA
      ) {
        const phase = f.currentRun.activeTurn.phase;
        turns.push([role, phase, request.access]);
        assert.equal(request.access, "read-only");
        let structured;
        if (request.schema === COMMIT_SIZE_ASSESSMENT_SCHEMA) {
          const data = JSON.parse(
            /Assessment binding \(data\):\n([^\n]+)/u.exec(request.prompt)[1],
          );
          structured = {
            bindingFingerprint: data.bindingFingerprint,
            decision: "SPLIT",
            reason: "Separate reader introduction from integration.",
            replacementPlan,
          };
        } else {
          const data = JSON.parse(
            /Proposed authority \(data\):\n([^\n]+)/u.exec(request.prompt)[1],
          );
          structured = {
            fingerprint: data.fingerprint,
            status: "CLEAN",
            reason: "All requirements and checks survive.",
            preserves: {
              requirements: true,
              dependencies: true,
              laterSteps: true,
              checks: true,
              findings: true,
            },
          };
          if (unchangedPlanRepair && !rejectedPlan) {
            rejectedPlan = true;
            structured.status = "FINDINGS";
            structured.reason = "State the dependency-preservation obligation.";
            structured.preserves.dependencies = false;
          }
          if (
            rejectInputReview &&
            f.currentRun.pipelineState.replacementExecution.inputChanges.at(-1)
              ?.after
          ) {
            structured.status = "FINDINGS";
            structured.reason =
              "The answer invalidates the replacement boundaries.";
            structured.preserves.requirements = false;
          }
        }
        return { structured, sessionId: `${role}-${turns.length}` };
      }
      return original(request);
    };
  }
  f.runtime.adapters.worker.canReadFiles = async () => true;
  f.runtime.preservation = {
    reconcile: (request) => f.runtime.preservation.restore(request),
    async capture({
      preservationId,
      expectedRevision = f.currentRun.revision,
      expectedSnapshot,
    }) {
      assert.equal(f.currentRun.activeTurn, null);
      assert.equal(f.currentRun.revision, expectedRevision);
      assert.ok(f.currentRun.pipelineState.effectiveValidation.at(-1).schedule);
      assert.equal(
        f.currentRun.pipelineState.effectiveValidation.at(-1).reviewer !== null,
        mode !== "lazy",
      );
      if (!captured.has(preservationId)) {
        const changes = [];
        for (const path of ["future.txt", "implementation-1.txt"]) {
          const content = await readFile(join(f.projectPath, path));
          changes.push({
            before: {
              path,
              kind: "deleted",
              hash: null,
              mode: null,
              size: 0,
            },
            after: {
              path,
              kind: "file",
              hash: hash(content),
              mode: "100644",
              size: content.length,
            },
          });
        }
        captured.set(preservationId, {
          record: {
            binding: { revision: expectedRevision, snapshot: expectedSnapshot },
          },
          changes,
        });
      }
      return f.runtime.transition({}, {});
    },
    async read(id) {
      const saved = structuredClone(captured.get(id));
      return {
        ...saved,
        source: {
          manifestPath: join(f.taskPath, `${id}.json`),
          manifestHash: hash(JSON.stringify(saved.changes)),
          blobDirectory: f.taskPath,
        },
      };
    },
    async restore({ preservationId, operationId, paths, target }) {
      assert.equal(target, "before");
      assert.deepEqual(
        paths,
        captured.get(preservationId).changes.map(({ before }) => before.path),
      );
      if (!restored.has(operationId)) {
        for (const path of paths) await rm(join(f.projectPath, path));
        restored.set(operationId, {
          complete: true,
          result: await f.runtime.git.snapshot({ allowedPaths: [] }),
        });
      }
      if (crash === "restore" && !failed) {
        failed = true;
        throw new Error("Interrupted restoration publication");
      }
      return { run: f.currentRun, receipt: restored.get(operationId) };
    },
  };
  return { f, turns, captured, restored, commits: () => commits };
}

test("an earlier refinement does not consume corrections for a later unsplit step", () => {
  const later = "feat(next): add the next feature";
  const state = {
    ...createPlanExecutionState({ settings: SETTINGS }),
    canonicalPlan: `## Commit 1: feat(test): add behavior\n\nImplement the behavior.\n\n## Commit 2: ${later}\n\nImplement the next feature.\n`,
    currentStep: 3,
    reviewCorrection: { attempt: 1 },
    lazyCorrections: [{ phase: "CHECK_AND_FIX" }],
    effectivePlanRevisions: {
      revisions: [
        {
          number: 1,
          originalStep: 1,
          accepted: true,
          plan: `${replacementPlan}\n## Commit 3: ${later}\n\nImplement the next feature.\n`,
          mapping: [
            { step: 1, originalStep: 1, replacement: 1 },
            { step: 2, originalStep: 1, replacement: 2 },
            { step: 3, originalStep: 2, replacement: 1 },
          ],
          binding: { consumedCorrections: { review: true } },
        },
      ],
    },
  };
  const retained = retainReplacementCorrections(state);
  assert.deepEqual(retained.replacementExecution, state.replacementExecution);
  assert.equal(replacementCorrectionConsumed(retained, "review"), false);
  assert.equal(replacementCorrectionConsumed(retained, "check"), false);
});

test("large cumulative captures supply bounded verified references instead of file bytes", async () => {
  const content = Buffer.alloc(13 * 1024 * 1024, "x").toString("base64");
  const sources = Array.from({ length: 3 }, (_, index) => ({
    manifestPath: `/state/saved-${index}/manifest.json`,
    manifestHash: hash(`manifest-${index}`),
    blobDirectory: `/state/saved-${index}`,
  }));
  const current = {
    ...createPlanExecutionState({ settings: SETTINGS }),
    canonicalPlan: replacementPlan,
    currentStep: 1,
    effectivePlanRevisions: {
      revisions: sources.map((_, index) => ({
        number: index + 1,
        originalStep: 1,
        accepted: true,
        plan: replacementPlan,
        mapping: [
          { step: 1, originalStep: 1, replacement: 1 },
          { step: 2, originalStep: 1, replacement: 2 },
        ],
      })),
    },
    replacementExecution: {
      separations: sources.map((_, index) => ({
        revision: index + 1,
        preservationId: index,
      })),
      corrections: [],
      findingAccounting: [],
      inputChanges: [],
    },
  };
  const coordinator = createReplacementCoordinator({
    state: () => current,
    runtime: {
      preservation: {
        async read(index) {
          return {
            source: sources[index],
            changes: [{ before: { content }, after: { content } }],
          };
        },
      },
    },
  });
  const context = await coordinator.preservedContext();
  assert.ok(Buffer.byteLength(context) < 4096);
  assert.equal(context.includes(content), false);
  for (const source of sources)
    assert.ok(context.includes(source.manifestHash));
  // Each individual reference fits, but their aggregate exceeds admission.
  for (const source of sources) source.manifestPath = "x".repeat(24 * 1024);
  await assert.rejects(coordinator.preservedContext(), {
    code: "ERR_REPLACEMENT_CONTEXT_CAPACITY_EXHAUSTED",
  });
});

test("reconstruction capacity is checked before any restoration removes the candidate", async (t) => {
  const { f, captured, restored, commits } = await fixture(t);
  const read = f.runtime.preservation.read;
  f.runtime.preservation.read = async (id) => {
    const saved = await read(id);
    return {
      ...saved,
      source: { ...saved.source, manifestPath: "x".repeat(64 * 1024) },
    };
  };
  const paused = await f.run();
  assert.equal(paused.pause.code, "ERR_REPLACEMENT_CONTEXT_CAPACITY_EXHAUSTED");
  assert.equal(captured.size, 1);
  assert.equal(restored.size, 0);
  assert.equal(commits(), 0);
  assert.equal(
    await readFile(join(f.projectPath, "future.txt"), "utf8"),
    "retained future work\n",
  );
  assert.equal(
    paused.pipelineState.replacementExecution.separations[0].phase,
    "restore",
  );
  assert.equal((await f.run()).pause.code, paused.pause.code);
  assert.equal(restored.size, 0);
  f.runtime.preservation.read = read;
  assert.equal((await f.run()).pipelineState.workflowState, "DONE");
  assert.equal(captured.size, 1);
});

test("inaccessible preserved binary sources pause before restoration and are rechecked on resume", async (t) => {
  const binary = Buffer.from([0, 255, 128, 13, 10]);
  const { f, captured, restored, commits } = await fixture(t, {
    futureContent: binary,
  });
  const requests = [];
  f.runtime.adapters.worker.canReadFiles = async (request) => {
    requests.push(request);
    return false;
  };
  const paused = await f.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.code, "ERR_REPLACEMENT_SOURCE_UNAVAILABLE");
  const separation = paused.pipelineState.replacementExecution.separations[0];
  assert.equal(separation.phase, "restore");
  const saved = await f.runtime.preservation.read(separation.preservationId);
  assert.equal(saved.changes[0].after.hash, hash(binary));
  assert.deepEqual(requests, [
    {
      access: "workspace-write",
      paths: [
        saved.source.manifestPath,
        ...saved.changes.map(({ after }) =>
          join(saved.source.blobDirectory, after.hash),
        ),
      ],
    },
  ]);
  assert.deepEqual(await readFile(join(f.projectPath, "future.txt")), binary);
  assert.equal(captured.size, 1);
  assert.equal(restored.size, 0);
  assert.equal(commits(), 0);
  assert.equal((await f.run()).pause.code, paused.pause.code);
  assert.equal(requests.length, 2);
  // An adapter without exact-file admission cannot authorize separation.
  delete f.runtime.adapters.worker.canReadFiles;
  assert.equal((await f.run()).pause.code, paused.pause.code);
  assert.equal(restored.size, 0);
  f.runtime.adapters.worker.canReadFiles = async () => true;
  assert.equal((await f.run()).pipelineState.workflowState, "DONE");
  assert.equal(captured.size, 1);
});

test("sibling findings reuse IDs without inheriting unrelated versioned decisions", () => {
  const finding = reviewFindings("R1").findings[0];
  const current = {
    ...createPlanExecutionState({ settings: SETTINGS }),
    canonicalPlan: replacementPlan,
    currentStep: 1,
    findings: [finding],
    previousFindings: [finding],
    disputeCounts: { R1: 2 },
    findingArbitrations: [
      {
        findingId: "R1",
        direction: "REVIEWER_CORRECT",
        rationale: "The original finding is valid.",
      },
    ],
    sameFindingRounds: { R1: 3 },
    findingOverrides: [
      { findingId: "R1", fingerprint: hash("first candidate") },
    ],
    additionalFixRounds: 4,
    effectivePlanRevisions: {
      revisions: [
        {
          number: 1,
          accepted: true,
          originalStep: 1,
          plan: replacementPlan,
          mapping: [
            { step: 1, originalStep: 1, replacement: 1 },
            { step: 2, originalStep: 1, replacement: 2 },
          ],
          findingOwners: [
            {
              id: "R1",
              fingerprint: hash(JSON.stringify(finding)),
              steps: [1, 2],
            },
          ],
        },
      ],
    },
  };
  const child = verifiedCommitCheckpoint({
    current,
    counters: { fixRounds: 3, correctionRounds: 3 },
    hashes: {},
    pause: null,
    verified: { head: "a".repeat(40) },
    nextRepositoryBaseline: {},
    configurationChanged: false,
  }).patch;
  assert.deepEqual(child.counters, { fixRounds: 3, correctionRounds: 3 });
  assert.equal(child.pipelineState.additionalFixRounds, 4);
  assert.deepEqual(child.pipelineState.disputeCounts, {});
  assert.deepEqual(child.pipelineState.findingArbitrations, []);
  assert.deepEqual(child.pipelineState.findingOverrides, []);
  assert.equal(
    child.pipelineState.replacementExecution.findingAccounting.length,
    1,
  );
  const unrelated = { ...finding, problem: "A separate sibling defect." };
  const next = retainReplacementFindingAccounting(child.pipelineState, {
    ...child.pipelineState,
    findings: [unrelated],
    previousFindings: [unrelated],
  });
  assert.equal(replacementSameFindingRounds(next, unrelated), 0);
  assert.doesNotThrow(() =>
    normalizeResolutionResult(
      resolution({ id: "R1", decision: "DISPUTE" }),
      next.findings,
      new Set(next.findingArbitrations.map(({ findingId }) => findingId)),
    ),
  );
  const inherited = retainReplacementFindingAccounting(child.pipelineState, {
    ...child.pipelineState,
    findings: [finding],
    previousFindings: [finding],
  });
  assert.deepEqual(inherited.disputeCounts, current.disputeCounts);
  assert.deepEqual(inherited.findingArbitrations, current.findingArbitrations);
  assert.deepEqual(inherited.findingOverrides, current.findingOverrides);
  assert.equal(replacementSameFindingRounds(inherited, finding), 3);
  const unowned = structuredClone(child.pipelineState);
  unowned.effectivePlanRevisions.revisions[0].findingOwners[0].steps = [1];
  assert.deepEqual(
    retainReplacementFindingAccounting(unowned, {
      ...unowned,
      findings: [finding],
      previousFindings: [finding],
    }).findingArbitrations,
    [],
  );
});

test("switching owned versions with the same ID cannot relabel decisions or renew consumption", () => {
  const first = reviewFindings("R1").findings[0];
  const second = {
    ...first,
    file: "other.js",
    problem: "A distinct reviewed defect.",
  };
  for (const pending of [false, true]) {
    const current = {
      ...createPlanExecutionState({ settings: SETTINGS }),
      currentStep: 1,
      findings: [first],
      previousFindings: [first],
      pendingDisputes: pending
        ? [
            {
              findingId: "R1",
              reason: "The first version is disputed.",
              evidence: ["Original inspected source."],
            },
          ]
        : [],
      disputeCounts: { R1: 1 },
      findingArbitrations: pending
        ? []
        : [
            {
              findingId: "R1",
              direction: "REVIEWER_CORRECT",
              rationale: "Only the first version was upheld.",
            },
          ],
      sameFindingRounds: { R1: 3 },
      reviewReconsideration: ["R1"],
      additionalFixRounds: 4,
      effectivePlanRevisions: {
        revisions: [
          {
            number: 1,
            accepted: true,
            findingOwners: [first, second].map((finding) => ({
              id: finding.id,
              fingerprint: hash(JSON.stringify(finding)),
              steps: [1],
            })),
          },
        ],
      },
    };
    const bound = retainReplacementFindingAccounting(current, current);
    const corrections = [
      {
        round: 4,
        fingerprint: hash("next candidate"),
        findingIds: ["R1"],
        finalizationIssueIds: [],
      },
    ];
    const next = retainReplacementFindingAccounting(bound, {
      ...bound,
      findings: [second],
      previousFindings: [second],
      sameFindingRounds: { R1: 4 },
      correctionHistory: corrections,
    });
    assert.deepEqual(next.findingArbitrations, []);
    assert.deepEqual(next.pendingDisputes, []);
    assert.deepEqual(next.disputeCounts, {});
    assert.deepEqual(next.reviewReconsideration, []);
    assert.equal(replacementSameFindingRounds(next, second), 1);
    assert.equal(next.additionalFixRounds, 4);
    assert.equal(next.correctionHistory, corrections);
    const restored = retainReplacementFindingAccounting(next, {
      ...next,
      findings: [first],
      previousFindings: [first],
      sameFindingRounds: {},
    });
    assert.deepEqual(restored.findingArbitrations, current.findingArbitrations);
    assert.deepEqual(restored.pendingDisputes, current.pendingDisputes);
    assert.deepEqual(restored.disputeCounts, current.disputeCounts);
    assert.deepEqual(
      restored.reviewReconsideration,
      current.reviewReconsideration,
    );
    assert.equal(replacementSameFindingRounds(restored, first), 3);
    const closed = retainReplacementFindingAccounting(bound, {
      ...bound,
      findings: [],
      previousFindings: [],
      pendingDisputes: [],
      reviewReconsideration: [],
    });
    const returned = retainReplacementFindingAccounting(closed, {
      ...closed,
      findings: [first],
      previousFindings: [first],
    });
    assert.deepEqual(returned.pendingDisputes, []);
    assert.deepEqual(returned.reviewReconsideration, []);
    assert.deepEqual(returned.disputeCounts, current.disputeCounts);
    assert.equal(replacementSameFindingRounds(returned, first), 3);
    const later = { ...bound, currentStep: 3 };
    const ordinary = retainReplacementFindingAccounting(later, {
      ...later,
      findings: [second],
      previousFindings: [second],
      sameFindingRounds: { R1: 4 },
    });
    assert.deepEqual(ordinary.findingArbitrations, later.findingArbitrations);
    assert.equal(replacementSameFindingRounds(ordinary, second), 4);
  }
});

test("versioned finding decisions survive replacement execution and strict reload without activating in a sibling", async (t) => {
  const finding = reviewFindings("R1").findings[0];
  const { f } = await fixture(t, {
    ownedFinding: finding,
    reconsiderOwnedFinding: true,
    crash: "restore",
  });
  await assert.rejects(f.run(), /Interrupted restoration/u);
  const result = await f.run();
  assert.equal(
    result.pipelineState.workflowState,
    "DONE",
    JSON.stringify(result.pause),
  );
  const saved = result.pipelineState.replacementExecution.findingAccounting[0];
  assert.equal(saved.fingerprint, hash(JSON.stringify(finding)));
  assert.equal(saved.disputeCounts.R1, 1);
  assert.equal(saved.findingArbitrations[0].direction, "REVIEWER_CORRECT");
  const ready = f.transitions.find(
    ({ patch }) =>
      patch?.pipelineState?.replacementExecution.separations[0]?.phase ===
      "ready",
  ).patch.pipelineState;
  assert.deepEqual(ready.reviewReconsideration, []);
  assert.deepEqual(
    ready.replacementExecution.findingAccounting[0].reviewReconsideration,
    [finding.id],
  );
  const candidate = f.transitions.find(
    ({ patch }) =>
      patch?.pipelineState?.replacementExecution.separations[0]?.phase ===
        "ready" &&
      patch.pipelineState.stepImplementation?.accepted &&
      patch.pipelineState.workflowState === "CHECK_AND_FIX",
  ).patch.pipelineState;
  assert.deepEqual(candidate.reviewReconsideration, [finding.id]);
  assert.deepEqual(result.pipelineState.disputeCounts, {});
  assert.deepEqual(result.pipelineState.findingArbitrations, []);
  assert.doesNotThrow(() =>
    normalizeExecutionState(structuredClone(result.pipelineState)),
  );
  for (const change of [
    { revision: 999 },
    { fingerprint: hash("unowned version") },
    { disputeCounts: { R2: 1 } },
  ]) {
    const forged = structuredClone(result.pipelineState);
    Object.assign(forged.replacementExecution.findingAccounting[0], change);
    assert.throws(() => normalizeExecutionState(forged));
  }
});

test("a sibling cannot rename an unchanged owned finding to bypass its prior decisions", async (t) => {
  const { f, commits } = await fixture(t, {
    ownedFinding: reviewFindings("R1").findings[0],
    renamedSiblingFinding: true,
  });
  const result = await f.run();
  assert.equal(result.pause?.reason, "review_output_invalid");
  assert.equal(commits(), 1);
  const saved = result.pipelineState.replacementExecution.findingAccounting[0];
  assert.equal(saved.id, "R1");
  assert.equal(saved.disputeCounts.R1, 1);
  assert.equal(saved.findingArbitrations[0].direction, "REVIEWER_CORRECT");
  assert.equal(
    result.pipelineState.findings.some(({ id }) => id === "R2"),
    false,
  );
});

for (const mode of ["independent", "combined"]) {
  test(`${mode} retains a mixed fix/dispute through interrupted replacement reconstruction until reconsideration`, async (t) => {
    const { f, commits } = await fixture(t, {
      mode,
      boundaryLines: 2700,
      mixedDispute: true,
      crash: "restore",
    });
    await assert.rejects(f.run(), /Interrupted restoration/u);
    const dispute = structuredClone(f.currentRun.pipelineState.pendingDisputes);
    assert.equal(dispute[0].findingId, "R2");
    const result = await f.run();
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(commits(), 2);
    const ready = f.transitions.find(
      ({ patch }) =>
        patch?.pipelineState?.replacementExecution.separations[0]?.phase ===
        "ready",
    ).patch.pipelineState;
    const accounting = (state) =>
      state.replacementExecution.findingAccounting.find(
        ({ id }) => id === "R2",
      );
    assert.deepEqual(ready.pendingDisputes, []);
    assert.deepEqual(accounting(ready).pendingDisputes, dispute);
    const candidate = f.transitions.find(
      ({ patch }) =>
        patch?.pipelineState?.stepImplementation?.accepted &&
        patch.pipelineState.replacementExecution.separations[0]?.phase ===
          "ready" &&
        patch.pipelineState.currentStep === 1 &&
        patch.pipelineState.workflowState ===
          (mode === "combined" ? "CHECK_AND_FIX" : "REVIEW"),
    ).patch.pipelineState;
    assert.deepEqual(candidate.pendingDisputes, dispute);
    const saved = accounting(result.pipelineState);
    assert.deepEqual(saved.pendingDisputes, []);
    assert.equal(saved.disputeCounts.R2, 1);
    assert.equal(saved.disputeHistory.length, 1);
    assert.equal(saved.disputeHistory[0].direction, "WITHDRAW");
    assert.equal(saved.disputeHistory[0].workerReason, dispute[0].reason);
    assert.doesNotThrow(() =>
      normalizeExecutionState(structuredClone(result.pipelineState)),
    );
  });
}

for (const [mode, decisionRole] of [
  ["lazy", "worker"],
  ["independent", "reviewer"],
  ["combined", "worker"],
  ["combined", "reviewer"],
]) {
  test(`${mode} resumes a compatible revision-discovery answer after ${decisionRole} requests it`, async (t) => {
    const { f, commits } = await fixture(t, { mode, decisionRole });
    const paused = await f.run();
    assert.equal(paused.pause?.reason, "product_decision_required");
    const assessment = structuredClone(
      paused.pipelineState.commitSizeAssessment,
    );
    const revision = structuredClone(
      paused.pipelineState.effectivePlanRevisions,
    );
    const workerReceipt =
      paused.pipelineState.effectiveValidation.at(-1)?.worker;
    assert.equal(Boolean(workerReceipt), decisionRole === "reviewer");
    f.writeClarification(`${f.readClarification()}Behavior A.\n`);
    const result = await f.run();
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(commits(), 2);
    assert.deepEqual(result.pipelineState.commitSizeAssessment, assessment);
    assert.deepEqual(result.pipelineState.effectivePlanRevisions, revision);
    const change = result.pipelineState.replacementExecution.inputChanges[0];
    assert.deepEqual(change.validation?.worker, workerReceipt);
    assert.equal(
      change.reports.length,
      mode === "lazy" ? 2 : mode === "combined" ? 3 : 1,
    );
    assert.notEqual(change.before, change.after);
    assert.equal(
      result.pipelineState.effectiveValidation[0].worker.binding
        .inputFingerprint,
      change.after,
    );
    assert.doesNotThrow(() =>
      normalizeExecutionState(structuredClone(result.pipelineState)),
    );
    const stale = structuredClone(result.pipelineState);
    stale.replacementExecution.inputChanges[0].reports = [];
    assert.throws(() => normalizeExecutionState(stale));
  });
}

for (const change of ["frozen input", "read-only content"]) {
  test(`${change} drift after receipt archival persists the safety pause and historical inventories`, async (t) => {
    const { f, captured, commits } = await fixture(t, {
      decisionRole: "reviewer",
      crash: "input-acceptance",
    });
    assert.equal((await f.run()).pause?.reason, "product_decision_required");
    f.writeClarification(`${f.readClarification()}Behavior A.\n`);
    await assert.rejects(f.run(), /Interrupted input acceptance/u);
    const before = structuredClone(f.currentRun.pipelineState);
    assert.deepEqual(before.effectiveValidation, []);
    assert.ok(before.replacementExecution.inputChanges.at(-1).validation);
    if (change === "frozen input")
      await writeFile(join(f.taskPath, "task.md"), "Changed frozen task.\n");
    else {
      const original = f.runtime.adapters.worker.run;
      f.runtime.adapters.worker.run = async (request) => {
        assert.equal(request.access, "read-only");
        await writeFile(join(f.projectPath, "source.js"), "Unexpected edit.\n");
        return original(request);
      };
    }
    const result = await f.run();
    assert.equal(
      result.pause?.reason,
      change === "frozen input"
        ? "task_input_changed"
        : "read_only_agent_mutated_repository",
    );
    for (const field of [
      "workerValidation",
      "reviewerValidation",
      "replacementExecution",
    ])
      assert.deepEqual(result.pipelineState[field], before[field]);
    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pipelineState.resolvedSummary, null);
    assert.equal(result.pipelineState.currentStep, null);
    assert.equal(result.pipelineState.validationSchedule, null);
    assert.equal(result.pipelineState.stepImplementation, null);
    assert.equal(result.pipelineState.candidateReviewedFingerprint, null);
    assert.equal(result.pipelineState.finalizedFingerprint, null);
    assert.doesNotThrow(() => normalizeExecutionState(result.pipelineState));
    assert.throws(() =>
      planExecutionPipeline.validateResumeAction(result, null),
    );
    assert.equal(captured.size, 0);
    assert.equal(commits(), 0);
  });
}

test("an interrupted clarification-bound plan rejection resumes without discovery or workspace effects", async (t) => {
  const { f, turns, captured, restored, commits } = await fixture(t, {
    decisionRole: "worker",
    rejectInputReview: true,
    crash: "input-review",
  });
  assert.equal((await f.run()).pause?.reason, "product_decision_required");
  f.writeClarification(`${f.readClarification()}Behavior A.\n`);
  await assert.rejects(f.run(), /Interrupted input-review publication/u);
  const rejected = structuredClone(f.currentRun.pipelineState);
  const turnCount = turns.length;
  const result = await f.run();
  assert.equal(result.pause?.reason, "plan_revision_required");
  assert.deepEqual(result.pause.evidence, [
    "The answer invalidates the replacement boundaries.",
  ]);
  assert.deepEqual(
    result.pipelineState.replacementExecution,
    rejected.replacementExecution,
  );
  assert.deepEqual(
    result.pipelineState.commitSizeAssessment,
    rejected.commitSizeAssessment,
  );
  assert.deepEqual(
    result.pipelineState.effectivePlanRevisions,
    rejected.effectivePlanRevisions,
  );
  assert.equal(turns.length, turnCount);
  assert.equal(captured.size, 0);
  assert.equal(restored.size, 0);
  assert.equal(commits(), 0);
});

test("a compatible answer on an amended sibling refreshes selected revision evidence without restoring committed work", async (t) => {
  const { f, captured, restored, commits } = await fixture(t, {
    lateDecisionStep: 2,
    amendment: 2,
  });
  const paused = await f.run();
  assert.equal(paused.pause?.reason, "product_decision_required");
  assert.equal(commits(), 1);
  f.writeClarification(`${f.readClarification()}Behavior A.\n`);
  const result = await f.run();
  assert.equal(
    result.pipelineState.workflowState,
    "DONE",
    JSON.stringify(result.pause),
  );
  assert.equal(commits(), 2);
  assert.equal(captured.size, 1);
  assert.equal(restored.size, 1);
  assert.equal(
    result.pipelineState.effectiveValidation[0].worker.binding.step,
    2,
  );
  assert.doesNotThrow(() =>
    normalizeExecutionState(structuredClone(result.pipelineState)),
  );
});

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} reconstructs a correction-grown split after interrupted restoration without renewing accounting`, async (t) => {
    const { f, restored, commits } = await fixture(t, {
      mode,
      boundaryLines: 2700,
      repairGrowth: true,
      crash: "restore",
    });
    await assert.rejects(f.run(), /Interrupted restoration/u);
    const before = structuredClone(f.currentRun);
    assert.equal(before.pipelineState.pendingCorrection, true);
    assert.equal(before.counters.fixRounds, 1);
    const result = await f.run();
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(commits(), 2);
    assert.equal(restored.size, 1);
    const ready = f.transitions.find(
      ({ patch }) =>
        patch?.pipelineState?.replacementExecution.separations[0]?.phase ===
        "ready",
    );
    assert.equal(ready.patch.pipelineState.pendingCorrection, false);
    assert.equal(ready.patch.counters.fixRounds, before.counters.fixRounds);
    assert.deepEqual(
      ready.patch.pipelineState.effectivePlanRevisions,
      before.pipelineState.effectivePlanRevisions,
    );
    assert.doesNotThrow(() =>
      normalizeExecutionState(structuredClone(result.pipelineState)),
    );
  });

  test(`${mode} resumes revision-discovery questions after a correction-grown split`, async (t) => {
    const { f, commits } = await fixture(t, {
      mode,
      boundaryLines: 2700,
      repairGrowth: true,
      decisionRole: "worker",
    });
    const paused = await f.run();
    assert.equal(paused.pause?.reason, "product_decision_required");
    assert.equal(paused.pipelineState.pendingEdit.suspendedState, "IMPLEMENT");
    assert.equal(
      paused.pipelineState.replacementExecution.inputChanges[0].checkpoint,
      mode === "independent" ? "REVIEW" : "CHECK_AND_FIX",
    );
    assert.equal(paused.counters.fixRounds, 1);
    const revision = structuredClone(
      paused.pipelineState.effectivePlanRevisions,
    );
    f.writeClarification(`${f.readClarification()}Behavior A.\n`);
    const result = await f.run();
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(commits(), 2);
    assert.deepEqual(result.pipelineState.effectivePlanRevisions, revision);
    const compatible = f.transitions.find(
      ({ patch }) => patch?.pipelineState?.compatibilityCheckRequired,
    );
    assert.equal(compatible.patch.pipelineState.pendingCorrection, false);
    assert.equal(
      compatible.patch.counters.fixRounds,
      paused.counters.fixRounds,
    );
    assert.deepEqual(
      compatible.patch.pipelineState.correctionHistory,
      paused.pipelineState.correctionHistory,
    );
    assert.doesNotThrow(() =>
      normalizeExecutionState(structuredClone(result.pipelineState)),
    );
  });
}

for (const result of [
  bootstrapCapacityExhausted("requiredChecks"),
  bootstrapProductDecision(),
]) {
  test(`revision discovery preserves the ${result.status} outcome and suspended authority`, async (t) => {
    const { f, captured, commits } = await fixture(t, {
      revisionDiscovery: result,
    });
    const run = f.runtime.adapters.worker.run;
    let charged = false;
    const direction = {
      direction: "CONTINUE_FIXES",
      rationale: "Retain the consumed lineage decision.",
    };
    f.runtime.adapters.worker.run = async (request) => {
      if (!charged && f.currentRun.activeTurn.phase === "revision-validation") {
        charged = true;
        f.persistPipelineState({
          ...f.currentRun.pipelineState,
          additionalFixRounds: 4,
          stagnationArbitrationUsed: true,
          stagnationDirection: direction,
        });
      }
      return run(request);
    };
    const paused = await f.run();
    assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(
      paused.pipelineState.effectivePlanRevisions.revisions[0].accepted,
      true,
    );
    assert.equal(captured.size, 0);
    assert.equal(commits(), 0);
    assert.equal(paused.pipelineState.additionalFixRounds, 4);
    assert.equal(paused.pipelineState.stagnationArbitrationUsed, true);
    assert.deepEqual(paused.pipelineState.stagnationDirection, direction);
    if (result.status === "CAPACITY_EXHAUSTED") {
      assert.equal(
        paused.pause.reason,
        "bootstrap_inventory_capacity_exhausted",
      );
      assert.ok(
        paused.pause.explanation.includes(`${result.capacityLimit} items`),
      );
      assert.ok(paused.pause.explanation.includes(result.capacityField));
      assert.ok(paused.pause.evidence.some((item) => item.includes("worker")));
    } else {
      assert.equal(paused.pause.reason, "product_decision_required");
      assert.equal(
        paused.pipelineState.pendingEdit.suspendedState,
        "IMPLEMENT",
      );
      assert.deepEqual(
        paused.pause.inputRequest.questions[0].options,
        result.options,
      );
      assert.equal(
        paused.pause.inputRequest.questions[0].question,
        result.question,
      );
      assert.equal(paused.pause.inputRequest.rationale, result.whyBlocked);
    }
  });
}

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} executes preserved replacements through separate complete gates and retains frozen inputs`, async (t) => {
    const { f, turns, captured, commits } = await fixture(t, { mode });
    const originalPlan = await readFile(join(f.taskPath, "plan.md"), "utf8");
    const result = await f.run();
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(commits(), 2);
    assert.equal(captured.size, 1);
    assert.equal(
      await readFile(join(f.taskPath, "plan.md"), "utf8"),
      originalPlan,
    );
    assert.equal(result.pipelineState.completedCommits.length, 2);
    assert.equal(
      result.pipelineState.commitSizeAssessment.lineages[0].attempts.length,
      1,
    );
    assert.equal(
      result.pipelineState.replacementExecution.separations[0].phase,
      "ready",
    );
    assert.equal(
      result.pipelineState.canonicalPlan.includes("feat(test): add behavior"),
      true,
    );
    assert.deepEqual(
      effectivePlanAuthority(result.pipelineState).steps.map(
        ({ subject }) => subject,
      ),
      ["feat(reader): add the reader", "feat(runtime): use the reader"],
    );
    const assessment = turns.find(([, phase]) => phase === "commit-size");
    assert.equal(assessment[0], mode === "lazy" ? "worker" : "reviewer");
    assert.equal(
      turns.filter(([, phase]) => phase === "effective-plan").length,
      mode === "combined" ? 3 : mode === "lazy" ? 2 : 1,
    );
    assert.equal(turns.filter(([, phase]) => phase === "finalize").length, 2);
    assert.equal(turns.filter(([, phase]) => phase === "confirm").length, 2);
    assert.equal(
      turns.filter(([, phase]) => phase === "review").length,
      mode === "lazy" ? 0 : 2,
    );
    assert.equal(
      await readFile(join(f.projectPath, "future.txt"), "utf8"),
      "retained future work\n",
    );
    const checkpoints = f.transitions.filter(
      ({ patch }) =>
        patch?.pipelineState?.currentStep === 1 &&
        patch.pipelineState.effectivePlanRevisions.revisions.at(-1)?.accepted,
    );
    const target = resolveStopBoundary({
      pipelineState: checkpoints[0].patch.pipelineState,
    });
    const second = f.transitions.find(
      ({ patch }) => patch?.pipelineState?.currentStep === 2,
    ).patch.pipelineState;
    assert.deepEqual(resolveStopBoundary({ pipelineState: second }), target);
    const authorized = f.transitions.find(
      ({ patch }) =>
        patch?.pipelineState?.currentStep === 1 &&
        patch.pipelineState.pendingCommit?.status === "consumed",
    ).patch.pipelineState;
    const charged = retainReplacementCorrections({
      ...authorized,
      reviewCorrection: { attempt: 1 },
      additionalFixRounds: 4,
    });
    const settled = verifiedCommitCheckpoint({
      current: charged,
      counters: { fixRounds: 3, correctionRounds: 2 },
      hashes: result.hashes,
      pause: null,
      verified: { head: second.repositoryBaseline.head },
      nextRepositoryBaseline: second.repositoryBaseline,
      configurationChanged: false,
    });
    assert.deepEqual(settled.patch.counters, {
      fixRounds: 3,
      correctionRounds: 2,
    });
    assert.equal(settled.patch.pipelineState.additionalFixRounds, 4);
    assert.equal(settled.patch.pipelineState.stepImplementation, null);
    assert.equal(
      settled.patch.pipelineState.candidateReviewedFingerprint,
      null,
    );
    assert.equal(
      replacementCorrectionConsumed(settled.patch.pipelineState, "review"),
      true,
    );

    assert.doesNotThrow(() =>
      normalizeExecutionState(JSON.parse(JSON.stringify(result.pipelineState))),
    );
    // Every saved enabled checkpoint migrates with unchanged authority.
    for (const { patch } of f.transitions) {
      if (!patch?.pipelineState?.settings) continue;
      const { automaticCommitSplitting, ...saved } =
        patch.pipelineState.settings;
      assert.equal(automaticCommitSplitting, true);
      const migrated = planExecutionPipeline.migrations[38]({
        pipelineState: { ...patch.pipelineState, settings: saved },
      });
      assert.deepEqual(migrated, patch.pipelineState);
    }
    if (mode === "combined") {
      const unprepared = structuredClone(result.pipelineState);
      unprepared.replacementExecution.separations = [];
      assert.throws(
        () => normalizeExecutionState(unprepared),
        /prepared revision authority/u,
      );
      for (const patch of [
        { captureRevision: 0 },
        { revision: 999 },
        { phase: "unknown" },
        {
          operationId:
            result.pipelineState.replacementExecution.separations[0]
              .preservationId,
        },
      ]) {
        const forged = structuredClone(result.pipelineState);
        Object.assign(forged.replacementExecution.separations[0], patch);
        assert.throws(() => normalizeExecutionState(forged));
      }
    }
  });
}

for (const crash of ["assessment", "acceptance", "restore", "commit"]) {
  test(`reconstruction after interrupted ${crash} retains saved work and does not replay commits`, async (t) => {
    const { f, captured, restored, commits } = await fixture(t, { crash });
    if (crash === "commit") {
      const stopped = await f.run();
      assert.equal(stopped.pause.reason, "commit_failed");
      assert.equal(stopped.pipelineState.pendingCommit.status, "consumed");
      assert.equal(commits(), 1);
    } else {
      await assert.rejects(f.run(), /Interrupted/u);
    }
    const result = await f.run();
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(commits(), 2);
    assert.equal(captured.size, 1);
    assert.equal(restored.size, 1);
    assert.equal(result.pipelineState.completedCommits.length, 2);
    assert.equal(
      result.pipelineState.commitSizeAssessment.lineages[0].attempts.length,
      1,
    );
  });
}

for (const [change, checkpoint] of [
  ["frozen input", "ready"],
  ["frozen input", "restore"],
  ["frozen clarification", "restore"],
  ["read-only content", "ready"],
]) {
  test(`${change} drift at replacement ${checkpoint} persists a blocking outcome and historical inventories`, async (t) => {
    const { f, captured, commits } = await fixture(t, {
      stopAfterPreparation: checkpoint === "ready",
      crash: checkpoint === "restore" ? "restore" : undefined,
    });
    await assert.rejects(
      f.run(),
      /Interrupted (prepared replacement|restoration)/u,
    );
    const before = structuredClone(f.currentRun.pipelineState);
    const original = f.runtime.adapters.worker.run;
    if (change === "frozen input")
      await writeFile(join(f.taskPath, "task.md"), "Changed frozen task.\n");
    else if (change === "frozen clarification")
      f.writeClarification("Changed frozen clarification.\n");
    else
      f.runtime.adapters.worker.run = async (request) => {
        if (request.access === "read-only")
          await writeFile(
            join(f.projectPath, "source.js"),
            "Unexpected edit.\n",
          );
        return original(request);
      };
    const result = await f.run();
    assert.equal(
      result.pause.reason,
      change === "frozen input"
        ? "task_input_changed"
        : change === "frozen clarification"
          ? "clarifications_changed"
          : "read_only_agent_mutated_repository",
    );
    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    for (const field of [
      "workerValidation",
      "reviewerValidation",
      "effectiveValidation",
    ])
      assert.deepEqual(result.pipelineState[field], before[field]);
    assert.equal(result.pipelineState.resolvedSummary, null);
    assert.equal(result.pipelineState.currentStep, null);
    assert.equal(result.pipelineState.validationSchedule, null);
    assert.equal(result.pipelineState.stepImplementation, null);
    assert.equal(result.pipelineState.candidateReviewedFingerprint, null);
    assert.equal(result.pipelineState.finalizedFingerprint, null);
    assert.doesNotThrow(() => normalizeExecutionState(result.pipelineState));
    assert.throws(() =>
      planExecutionPipeline.validateResumeAction(result, null),
    );
    assert.equal(captured.size, 1);
    assert.equal(commits(), 0);
    if (change === "frozen clarification") {
      const stopped = await runPlanExecution({
        run: result,
        runtime: f.runtime,
        settings: SETTINGS,
        operatorStop: true,
      });
      assert.equal(
        stopped.pause.reason,
        result.pause.reason,
        JSON.stringify(stopped.pause),
      );
      assert.equal(stopped.pipelineState.resolvedSummary, null);
      assert.equal(stopped.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(
        stopped.pipelineState.replacementExecution.separations[0].phase,
        "ready",
      );
    }
  });
}

for (const phase of ["commit-size", "effective-plan", "revision-validation"]) {
  test(`read-only mutation in ${phase} pauses the contaminated run before preservation or commit`, async (t) => {
    const { f, captured, commits } = await fixture(t, { mutatePhase: phase });
    const paused = await f.run();
    assert.equal(paused.pause.reason, "read_only_agent_mutated_repository");
    assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(commits(), 0);
    assert.equal(captured.size, 0);
    assert.throws(() =>
      planExecutionPipeline.validateResumeAction(paused, null),
    );
  });

  test(`output exhaustion preserves the ${phase} checkpoint for reconstruction`, async (t) => {
    const { f, captured, commits } = await fixture(t, {
      exhaustPhase: phase,
    });
    attachOutputExhaustion(f);
    const paused = await f.run();
    assert.equal(paused.pause.reason, "output_exhausted");
    assert.ok(paused.pause.checkpoint.startsWith(`${phase}:read-only:`));
    assert.equal(paused.activeTurn, null);
    assert.equal(commits(), 0);
    assert.equal(captured.size, 0);
    for (const patch of [
      { role: "arbiter" },
      { checkpoint: `${paused.pause.checkpoint}:unknown` },
    ])
      assert.throws(
        () =>
          planExecutionPipeline.workflow.validateRun({
            ...paused,
            pause: { ...paused.pause, ...patch },
          }),
        /Invalid output-exhaustion pause/u,
      );
    const resumed = await f.run();
    assert.equal(resumed.pipelineState.workflowState, "DONE");
    assert.equal(commits(), 2);
    assert.equal(captured.size, 1);
    assert.equal(
      resumed.pipelineState.commitSizeAssessment.lineages[0].attempts.length,
      1,
    );
  });
}

test("an unchanged rejected plan repair pauses without losing findings or accepting authority", async (t) => {
  const { f, captured, commits } = await fixture(t, {
    unchangedPlanRepair: true,
  });
  const paused = await f.run();
  assert.equal(paused.pause.reason, "effective_plan_output_invalid");
  assert.doesNotThrow(() =>
    planExecutionPipeline.validateResumeAction(paused, null),
  );
  assert.deepEqual(
    planExecutionPipeline.projections.pause(paused).nextActions,
    [{ type: "resume", action: null }],
  );
  assert.equal(commits(), 0);
  assert.equal(captured.size, 0);
  assert.equal(paused.pipelineState.effectivePlanRevisions.revisions.length, 1);
  const proposal = paused.pipelineState.effectivePlanRevisions.revisions[0];
  assert.equal(proposal.accepted, false);
  assert.equal(proposal.reports[0].status, "FINDINGS");
  const resumed = await f.run();
  assert.equal(
    resumed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(resumed.pause),
  );
  assert.equal(commits(), 2);
  assert.equal(captured.size, 1);
  assert.deepEqual(
    resumed.pipelineState.effectivePlanRevisions.revisions[0],
    proposal,
  );
  assert.equal(
    resumed.pipelineState.effectivePlanRevisions.revisions[1].reports.length,
    3,
  );
  assert.equal(
    resumed.pipelineState.commitSizeAssessment.lineages[0].attempts.length,
    1,
  );
});

test("selecting complete revision validation retains amendment proof while retiring its work units", async (t) => {
  const { f } = await fixture(t, { amendment: true });
  const result = await f.run();
  assert.equal(
    result.pipelineState.workflowState,
    "DONE",
    JSON.stringify(result.pause),
  );
  assert.equal(
    result.pipelineState.effectiveValidation[0].amendment
      .confirmationFingerprint,
    hash("accepted amendment"),
  );
  assert.equal(result.pipelineState.bootstrapProgress.worker.work, null);
  assert.equal(result.pipelineState.bootstrapProgress.reviewer.work, null);
});

test("the exact threshold does not assess, separate or grant revision authority", async (t) => {
  const { f, turns, captured, commits } = await fixture(t, {
    boundaryLines: 2700,
  });
  const result = await f.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(commits(), 1);
  assert.equal(captured.size, 0);
  assert.equal(
    turns.some(([, phase]) => phase === "commit-size"),
    false,
  );
  assert.deepEqual(result.pipelineState.effectivePlanRevisions.revisions, []);
});

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} disabled splitting executes the large predefined commit through ordinary gates`, async (t) => {
    const { f, turns, captured, commits } = await fixture(t, { mode });
    f.persistPipelineState(
      createPlanExecutionState({
        settings: { ...SETTINGS, mode, automaticCommitSplitting: false },
      }),
    );
    f.runtime.git.measureChanges = async () => {
      throw new Error("Disabled splitting measured changes.");
    };
    for (const adapter of Object.values(f.runtime.adapters)) {
      const original = adapter.run;
      adapter.run = async (request) => {
        assert.notEqual(request.schema, COMMIT_SIZE_ASSESSMENT_SCHEMA);
        assert.notEqual(request.schema, EFFECTIVE_PLAN_REVIEW_SCHEMA);
        return original(request);
      };
    }
    // A changed runtime setting cannot enable the frozen disabled run.
    const result = await f.run({ automaticCommitSplitting: true });
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(result.pipelineState.settings.automaticCommitSplitting, false);
    assert.deepEqual(result.pipelineState.commitSizeAssessment, {
      eligible: false,
      lineages: [],
    });
    assert.deepEqual(result.pipelineState.effectivePlanRevisions.revisions, []);
    assert.equal(commits(), 1);
    assert.equal(captured.size, 0);
    assert.deepEqual(
      effectivePlanAuthority(result.pipelineState).steps.map(
        ({ subject }) => subject,
      ),
      ["feat(test): add behavior"],
    );
    assert.equal(turns.filter(([, phase]) => phase === "finalize").length, 1);
    assert.equal(turns.filter(([, phase]) => phase === "confirm").length, 1);
    assert.equal(
      turns.filter(([, phase]) => phase === "review").length,
      mode === "lazy" ? 0 : 1,
    );
  });
}

test("version-31 migration keeps legacy eligibility disabled without resetting effects or accounting", () => {
  const current = createPlanExecutionState({ settings: SETTINGS });
  assert.equal(current.commitSizeAssessment.eligible, true);
  const legacy = {
    ...current,
    commitSizeAssessment: { eligible: false, lineages: [] },
  };
  delete legacy.replacementExecution;
  const migrated = planExecutionPipeline.migrations[31]({
    pipelineState: legacy,
  });
  assert.equal(migrated.commitSizeAssessment.eligible, false);
  assert.deepEqual(migrated.replacementExecution, {
    separations: [],
    corrections: [],
    findingAccounting: [],
    inputChanges: [],
  });
  for (const field of Object.keys(legacy))
    assert.deepEqual(migrated[field], legacy[field]);
  const frozen = planExecutionPipeline.migrations[38]({
    pipelineState: migrated,
  });
  assert.equal(frozen.settings.automaticCommitSplitting, false);
  assert.doesNotThrow(() => normalizeExecutionState(frozen));
});
