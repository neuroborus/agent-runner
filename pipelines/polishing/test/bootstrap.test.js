import assert from "node:assert/strict";
import {
  appendFile,
  mkdir,
  readFile,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { polishingPipeline } from "../src/index.js";
import {
  MAX_BOOTSTRAP_ITEMS,
  MAX_VALIDATION_ITEMS,
} from "../src/workflow-contract.js";
import {
  SOURCE_SESSION,
  arbitrationResolved,
  bootstrapCapacityExhausted,
  bootstrapReady,
  clarificationQuestions,
  clarificationReady,
  createFixture,
  createRealGitFixture,
  createRealStoreFixture,
  finalizationPassed,
  polishingCompleted,
  productDecision,
  reconciliationDisagreement,
  reconciliationResolved,
  reviewApproved,
} from "./support/index.js";

test("derives one stable complete inventory from independent role evidence", async (t) => {
  const workerPath = "validation/worker.js";
  const reviewerPath = "validation/reviewer.js";
  const worker = {
    ...bootstrapReady("Worker"),
    requiredChecks: [
      { id: "C7", command: "npm test" },
      { id: "C2", command: "npm run lint" },
    ],
    validationInfrastructure: [
      ".agents/skills/finalization/SKILL.md",
      workerPath,
    ],
  };
  const reviewer = {
    ...bootstrapReady("Reviewer"),
    requiredChecks: [
      { id: "C1", command: "npm test" },
      { id: "C7", command: "npm run docs" },
    ],
    validationInfrastructure: [
      ".agents/skills/finalization/SKILL.md",
      reviewerPath,
    ],
  };
  const stop = new Error("polishing turn reached");
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await mkdir(join(projectPath, "validation"));
      await Promise.all([
        writeFile(join(projectPath, workerPath), "// worker validation\n"),
        writeFile(join(projectPath, reviewerPath), "// reviewer validation\n"),
      ]);
    },
    reviewer: [reviewer],
    worker: [clarificationReady(), worker, reconciliationResolved()],
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt)
      ) {
        throw stop;
      }
    },
  });

  await assert.rejects(fixture.run(), (cause) => cause === stop);
  assert.deepEqual(fixture.currentRun.pipelineState.requiredChecks, [
    { id: "C1", command: "npm test" },
    { id: "C2", command: "npm run lint" },
    { id: "C3", command: "npm run docs" },
  ]);
  assert.deepEqual(fixture.currentRun.pipelineState.validationInfrastructure, [
    ".agents/skills/finalization/SKILL.md",
    workerPath,
    reviewerPath,
  ]);
});

test("persists and finalizes a disjoint maximum role-derived inventory", async (t) => {
  const roleInventory = (role) => ({
    requiredChecks: Array.from({ length: MAX_BOOTSTRAP_ITEMS }, (_, index) => ({
      id: `C${index + 1}`,
      command: `node --test validation/${role}-${index + 1}.test.js`,
    })),
    validationInfrastructure: Array.from(
      { length: MAX_BOOTSTRAP_ITEMS },
      (_, index) => `validation/${role}-${index + 1}.test.js`,
    ),
  });
  const workerInventory = roleInventory("worker");
  const reviewerInventory = roleInventory("reviewer");
  const derivedCommands = [
    ...workerInventory.requiredChecks,
    ...reviewerInventory.requiredChecks,
  ].map(({ command }, index) => ({ id: `C${index + 1}`, command }));
  const derivedPaths = [
    ...workerInventory.validationInfrastructure,
    ...reviewerInventory.validationInfrastructure,
  ];
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await mkdir(join(projectPath, "validation"));
      await Promise.all(
        derivedPaths.map((path) =>
          writeFile(join(projectPath, path), `// ${path}\n`),
        ),
      );
    },
    reviewer: [
      { ...bootstrapReady("Reviewer"), ...reviewerInventory },
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), ...workerInventory },
      reconciliationResolved(),
      polishingCompleted(),
      {
        ...finalizationPassed(),
        requiredChecks: derivedCommands,
        validationInfrastructure: derivedPaths,
        checks: derivedCommands.map(({ id, command }) => ({
          checkId: id,
          command,
          status: "PASS",
          evidence: ["The derived inventory check passed."],
        })),
      },
    ],
  });

  const completed = await fixture.run();
  const state = completed.pipelineState;
  const expectedFingerprint =
    await fixture.runtime.git.validationInfrastructureFingerprint({
      paths: derivedPaths,
      projectPath: fixture.projectPath,
    });

  assert.equal(
    state.workerValidation.requiredChecks.length,
    MAX_BOOTSTRAP_ITEMS,
  );
  assert.equal(
    state.reviewerValidation.validationInfrastructure.length,
    MAX_BOOTSTRAP_ITEMS,
  );
  assert.equal(state.requiredChecks.length, MAX_VALIDATION_ITEMS);
  assert.equal(state.validationInfrastructure.length, MAX_VALIDATION_ITEMS);
  assert.equal(
    state.finalizationResult.requiredChecks.length,
    MAX_VALIDATION_ITEMS,
  );
  assert.equal(state.finalizationResult.checks.length, MAX_VALIDATION_ITEMS);
  assert.equal(state.validationInfrastructureFingerprint, expectedFingerprint);
  assert.equal(
    state.finalizationResult.validationInfrastructureFingerprint,
    expectedFingerprint,
  );
});

test("pauses deterministically when a bootstrap inventory exceeds capacity", async (t) => {
  for (const capacityField of ["requiredChecks", "validationInfrastructure"]) {
    await t.test(capacityField, async (t) => {
      const fixture = await createFixture(t, {
        worker: [
          clarificationReady(),
          bootstrapCapacityExhausted(capacityField),
        ],
      });

      const paused = await fixture.run();
      const projected = polishingPipeline.projections.pause(paused);

      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.deepEqual(paused.pipelineState.bootstrapCorrections, []);
      assert.equal(fixture.calls.worker.length, 2);
      assert.deepEqual(projected, {
        reason: "bootstrap_inventory_capacity_exhausted",
        code: "ERR_BOOTSTRAP_INVENTORY_CAPACITY_EXHAUSTED",
        explanation: `The worker bootstrap reported that the complete ${capacityField} inventory exceeds the supported per-role limit of ${MAX_BOOTSTRAP_ITEMS} items. Increase the bounded Runner contract or reduce the validation-controlling surface, then start a new run.`,
        evidence: [
          "Bootstrap role: worker.",
          `Inventory field: ${capacityField}.`,
          `Per-role item limit: ${MAX_BOOTSTRAP_ITEMS}.`,
        ],
        resumeState: null,
        nextActions: [],
      });
    });
  }
});

test("corrects duplicate Worker bootstrap commands once without retaining them", async (t) => {
  const rejectedCommand = "DO_NOT_PERSIST_DUPLICATE_COMMAND";
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks: [
          { id: "C1", command: rejectedCommand },
          { id: "C2", command: rejectedCommand },
        ],
      },
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "requiredChecks",
      constraint: "unique-ids-and-commands",
    },
  ]);
  assert.equal(completed.pipelineState.pendingBootstrapCorrection, null);
  assert.match(fixture.calls.worker[2].prompt, /Correction diagnostic/u);
  assert.doesNotMatch(JSON.stringify(completed), /DO_NOT_PERSIST/u);
});

test("corrects staging-dependent bootstrap checks before polishing", async (t) => {
  const unsafeCommand = "git add -A && git diff --cached --check";
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        summary: "Worker incorrectly requires a staged handoff.",
        requiredChecks: [{ id: "C1", command: unsafeCommand }],
      },
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "requiredChecks[0].command",
      constraint: "staging-independent-validation-command",
    },
  ]);
  const correctionCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Correction diagnostic"),
  );
  assert.ok(correctionCall);
  assert.doesNotMatch(correctionCall.prompt, new RegExp(unsafeCommand, "u"));
  assert.doesNotMatch(JSON.stringify(completed), /git diff --cached/u);
});

test("fails closed when corrected bootstrap checks still depend on staging", async (t) => {
  const rejected = {
    ...bootstrapReady("Worker"),
    requiredChecks: [{ id: "C1", command: "git diff --exit-code" }],
  };
  const fixture = await createFixture(t, {
    worker: [clarificationReady(), rejected, rejected],
  });

  await assert.rejects(
    fixture.run(),
    (cause) =>
      cause.code === "ERR_INVALID_POLISHING_OUTPUT" &&
      cause.diagnostic?.constraint === "staging-independent-validation-command",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
  assert.doesNotMatch(
    JSON.stringify(fixture.currentRun),
    /git diff --exit-code/u,
  );
});

test("corrects a multiline Reviewer bootstrap command once", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      {
        ...bootstrapReady("Reviewer"),
        requiredChecks: [{ id: "C1", command: "npm test\nnpm run lint" }],
      },
      bootstrapReady("Corrected Reviewer"),
      reviewApproved(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "reviewer",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "requiredChecks[0].command",
      constraint: "exact-single-line-command-up-to-4000-characters",
    },
  ]);
  assert.match(fixture.calls.reviewer[1].prompt, /one read-only correction/u);
});

test("fails closed after a repeated invalid bootstrap result", async (t) => {
  const rejected = {
    ...bootstrapReady("Worker"),
    requiredChecks: [
      { id: "C1", command: "npm test" },
      { id: "C2", command: "npm test" },
    ],
  };
  const fixture = await createFixture(t, {
    worker: [clarificationReady(), rejected, rejected],
  });

  await assert.rejects(
    fixture.run(),
    (cause) => cause.code === "ERR_INVALID_POLISHING_OUTPUT",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.deepEqual(fixture.currentRun.pause.diagnostic, {
    role: "worker",
    phase: "bootstrap",
    contract: "bootstrap",
    field: "requiredChecks",
    constraint: "unique-ids-and-commands",
  });
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
  assert.equal(fixture.calls.worker.length, 3);
});

test("corrects missing and symlinked validation-infrastructure paths", async (t) => {
  const cases = [
    { name: "missing", invalidPath: "validation/missing.js" },
    {
      name: "symlink alias",
      invalidPath: ".claude/skills/finalization/SKILL.md",
      prepareProject: (projectPath) =>
        symlink(".agents", join(projectPath, ".claude")),
    },
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async (t) => {
      const fixture = await createFixture(t, {
        prepareProject: testCase.prepareProject,
        worker: [
          clarificationReady(),
          {
            ...bootstrapReady("Worker"),
            validationInfrastructure: [testCase.invalidPath],
          },
          bootstrapReady("Corrected Worker"),
          reconciliationResolved(),
          polishingCompleted(),
          finalizationPassed(),
        ],
      });

      const completed = await fixture.run();

      assert.equal(completed.pipelineState.workflowState, "DONE");
      assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
        {
          attempt: 1,
          role: "worker",
          phase: "bootstrap",
          contract: "bootstrap",
          field: "validationInfrastructure[0]",
          constraint: "existing-canonical-repository-file",
        },
      ]);
    });
  }
});

test("corrects a classified structured-output failure without provider text", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_PROVIDER_OUTPUT";
  let rejected = false;
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("concise bootstrap summary") &&
        !rejected
      ) {
        rejected = true;
        const error = new Error(sensitiveMarker);
        error.failureClass = "structured-output";
        error.nativeResponse = { message: sensitiveMarker };
        error.stderr = sensitiveMarker;
        throw error;
      }
    },
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "result",
      constraint: "semantic-contract",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(completed), /DO_NOT_PERSIST/u);
});

test("prepares a dirty worktree through independent source-session bootstraps", async (t) => {
  const fixture = await createRealStoreFixture(t, {
    sourceSession: SOURCE_SESSION,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.clarificationFrozen, true);
  assert.equal(result.pipelineState.repositoryBaseline.clean, false);
  assert.deepEqual(result.pipelineState.backendVersions, {
    worker: "fake-1.0.0",
    reviewer: "fake-1.0.0",
    arbiter: null,
  });
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["worker", "worker", "reviewer", "worker", "reviewer"],
  );
  assert.deepEqual(fixture.calls.worker[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.reviewer[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.worker[1].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.worker[2].session, {
    mode: "continue",
    id: result.sessionLineage.children[1].sessionId,
  });
  assert.match(
    fixture.calls.worker[1].prompt,
    /\.agents.*unless the user's task explicitly requires them.*not a user question/u,
  );
  assert.doesNotMatch(fixture.calls.worker[2].prompt, /\.agents/u);
  assert.match(
    fixture.calls.worker[2].recoveryPrompt,
    /\.agents.*unless the user's task explicitly requires them.*not a user question/u,
  );
  assert.deepEqual(fixture.calls.worker[3].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.reviewer[1].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.match(
    fixture.calls.reviewer[1].prompt,
    /\.agents.*unless the user's task explicitly requires them.*not a user question/u,
  );
  for (const heading of [
    /Task \(/u,
    /Task-level clarifications:/u,
    /Context:/u,
    /Execution clarifications \(/u,
  ]) {
    assert.match(fixture.calls.worker[1].prompt, heading);
    assert.doesNotMatch(fixture.calls.worker[2].prompt, heading);
    assert.match(fixture.calls.worker[2].recoveryPrompt, heading);
  }
  assert.match(
    fixture.calls.worker[3].prompt,
    /Change-set fingerprint before this turn:/u,
  );
  assert.match(fixture.calls.worker[3].prompt, /Resolved bootstrap context:/u);
  assert.doesNotMatch(
    fixture.calls.reviewer[0].prompt,
    /Worker independently/u,
  );
  assert.doesNotMatch(
    fixture.calls.worker[1].prompt,
    /Reviewer independently/u,
  );
  assert.match(fixture.calls.worker[2].prompt, /Reviewer bootstrap summary/u);
  const finalizationCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Run the complete project finalization procedure"),
  );
  assert.ok(finalizationCall);
  assert.deepEqual(finalizationCall.session, {
    mode: "continue",
    id: result.sessionLineage.children[3].sessionId,
  });
  assert.doesNotMatch(finalizationCall.prompt, /Resolved bootstrap context:/u);
  assert.doesNotMatch(finalizationCall.prompt, /Worker polishing summary:/u);
  assert.match(finalizationCall.recoveryPrompt, /Resolved bootstrap context:/u);
  assert.match(finalizationCall.recoveryPrompt, /Worker polishing summary:/u);
  assert.match(
    fixture.calls.reviewer[1].prompt,
    /Resolved bootstrap context:/u,
  );
  assert.match(fixture.calls.reviewer[1].prompt, /Worker polishing summary:/u);
  assert.equal(
    fixture.calls.reviewer[1].prompt,
    fixture.calls.reviewer[1].recoveryPrompt,
  );
  for (const child of result.sessionLineage.children) {
    assert.match(child.contextKey, /^[a-f0-9]{64}$/u);
  }
  const workerKeys = result.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .map(({ contextKey }) => contextKey);
  const reviewerKeys = result.sessionLineage.children
    .filter(({ role }) => role === "reviewer")
    .map(({ contextKey }) => contextKey);
  assert.equal(new Set(workerKeys).size, 3);
  assert.equal(new Set(reviewerKeys).size, 2);
  for (const call of [
    ...fixture.calls.worker.slice(0, 3),
    ...fixture.calls.reviewer,
  ]) {
    assert.equal(call.access, "read-only");
    assert.equal(call.schema.additionalProperties, false);
  }
  for (const call of fixture.calls.worker.slice(3)) {
    assert.equal(call.access, "workspace-write");
    assert.equal(call.schema.additionalProperties, false);
  }
  assert.match(
    await readFile(
      join(fixture.directoryPath, "context", "resolved.md"),
      "utf8",
    ),
    /existing change set/u,
  );
});

test("uses and persists a configured runner artifact root", async (t) => {
  const fixture = await createFixture(t, {
    artifactRoot: "IGNORED_RUNS",
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.artifactRoot, "IGNORED_RUNS");
  assert.equal(
    result.pipelineState.clarificationPath,
    join(
      fixture.projectPath,
      "IGNORED_RUNS",
      "agent-runner",
      result.runId,
      "clarifications.md",
    ),
  );
});

test("pauses clean repositories before creating a clarification artifact", async (t) => {
  const fixture = await createFixture(t, {
    dirty: false,
    reviewer: [],
    worker: [],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_changes");
  assert.equal(fixture.calls.worker.length, 0);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(result.pipelineState.clarificationPath, null);
});

test("resumes preflight after the clarification path becomes ignored", async (t) => {
  const fixture = await createFixture(t, {
    ignoreArtifacts: false,
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "local_artifacts_not_ignored");
  assert.equal(paused.pipelineState.clarificationPath, null);

  await appendFile(
    join(fixture.projectPath, ".gitignore"),
    "LOCAL_ARTIFACTS/\n",
  );
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pause, null);
});

test("resumes preflight after a transient unsafe Git state", async (t) => {
  const fixture = await createFixture(t);
  const git = fixture.runtime.git;
  let preflightCalls = 0;
  fixture.runtime.git = {
    ...git,
    async preflight(options) {
      preflightCalls += 1;
      if (preflightCalls === 1) {
        const error = new Error("Git snapshot raced with another process.");
        error.code = "ERR_GIT_SNAPSHOT_RACE";
        throw error;
      }
      return git.preflight(options);
    },
  };

  const paused = await fixture.run();
  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "unsafe_git_state");
  assert.equal(paused.pipelineState.preflightComplete, false);

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pause, null);
});

for (const taskLocation of [
  "dirty-tracked",
  "untracked",
  "symlinked-untracked",
]) {
  test(`rejects ${taskLocation} repository-local task input overlap`, async (t) => {
    const fixture = await createRealGitFixture(t, {
      taskLocation,
      reviewer: [],
      worker: [],
    });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "task_input_overlaps_changes");
    assert.match(result.pause.path, /task\.md$/u);
    assert.equal(fixture.calls.worker.length, 0);
  });
}

for (const taskLocation of ["ignored", "tracked"]) {
  test(`accepts ${taskLocation} repository-local immutable task input`, async (t) => {
    const fixture = await createFixture(t, { taskLocation });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "DONE");
  });
}

test("pauses for clarification answers and resumes without consuming an extra round", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationQuestions(),
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "clarification_answers_required");
  assert.equal(paused.counters.clarificationRounds, 1);
  await appendFile(
    paused.pipelineState.clarificationPath,
    "Use the existing public behavior.\n",
  );

  await fixture.recover();
  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.counters.clarificationRounds, 1);
  assert.equal(resumed.pipelineState.pendingEdit, null);
  assert.equal(fixture.calls.worker[1].session, undefined);
  assert.match(fixture.calls.worker[1].prompt, /Task \(/u);
  assert.notEqual(
    resumed.sessionLineage.children[0].contextKey,
    resumed.sessionLineage.children[1].contextKey,
  );
});

test("accepts an unchanged proactive clarification without consuming a round", async (t) => {
  const fixture = await createFixture(t, {
    interactive: true,
    onEdit: async () => {},
    proactiveClarification: true,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.proactiveClarificationComplete, true);
  assert.equal(result.counters.clarificationRounds, 0);
});

test("stops after the bounded clarification question rounds", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
    ],
    reviewer: [],
  });

  for (let round = 1; round <= 3; round += 1) {
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "clarification_answers_required");
    assert.equal(paused.counters.clarificationRounds, round);
    await appendFile(
      paused.pipelineState.clarificationPath,
      `Answer ${round}.\n`,
    );
  }

  const exhausted = await fixture.run();
  assert.equal(exhausted.pause.reason, "clarification_limit_reached");
  assert.equal(exhausted.counters.clarificationRounds, 3);
});

test("detects immutable task-input drift during a read-only turn", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "worker" && !changed) {
        changed = true;
        await appendFile(
          join(fixture.taskPath, "task.md"),
          "Unexpected drift.\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
});

test("detects unauthorized clarification drift during a read-only turn", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "worker" && !changed) {
        changed = true;
        await appendFile(
          fixture.currentRun.pipelineState.clarificationPath,
          "Unexpected clarification drift.\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarifications_changed");
});

test("arbitrates a material bootstrap disagreement in a fresh read-only context", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [arbitrationResolved()],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.bootstrapArbitrationUsed, true);
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.calls.arbiter[0].access, "read-only");
  assert.equal(fixture.calls.arbiter[0].session, undefined);
});

test("invalidates dependent work before product-decision bootstrap re-entry", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      productDecision({
        status: "PRODUCT_DECISION_REQUIRED",
        findings: [],
        validationChange: "UNCHANGED",
        validationEvidence: [],
      }),
      bootstrapReady("Reviewer"),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const waiting = await fixture.run();

  assert.equal(waiting.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(waiting.pause.reason, "product_decision_required");
  assert.equal(waiting.pipelineState.pendingEdit.suspendedState, "BOOTSTRAP");
  assert.equal(waiting.pipelineState.polishSummary, null);
  assert.equal(waiting.pipelineState.finalizationResult, null);
  assert.equal(waiting.pipelineState.resolvedSummary, null);
  const { clarificationPath } = waiting.pipelineState;
  const previousWorkerKey = waiting.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .at(-1).contextKey;
  const previousReviewerKey = waiting.sessionLineage.children
    .filter(({ role }) => role === "reviewer")
    .at(-1).contextKey;
  await writeFile(
    clarificationPath,
    `${await readFile(clarificationPath, "utf8")}Behavior A.\n`,
  );

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const resumedWork = [
    fixture.calls.worker
      .filter(({ prompt }) => /Polish the existing local/u.test(prompt))
      .at(-1),
    fixture.calls.reviewer
      .filter(({ prompt }) => /Review the complete current/u.test(prompt))
      .at(-1),
  ];
  for (const request of resumedWork) {
    assert.equal(request.session, undefined);
    assert.equal(request.prompt, request.recoveryPrompt);
  }
  assert.notEqual(
    previousWorkerKey,
    completed.sessionLineage.children
      .filter(({ role }) => role === "worker")
      .at(-1).contextKey,
  );
  assert.notEqual(
    previousReviewerKey,
    completed.sessionLineage.children
      .filter(({ role }) => role === "reviewer")
      .at(-1).contextKey,
  );
});
