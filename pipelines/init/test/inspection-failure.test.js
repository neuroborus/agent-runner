import assert from "node:assert/strict";
import test from "node:test";

import {
  createInitState,
  initPipeline,
  inspectInitSetup,
} from "../src/index.js";
import {
  assertInspectionFailure,
  initInspectionFailure,
  inspectInitOperation,
} from "../src/inspection-failure.js";

const run = () => ({
  pipelineId: "init",
  pipelineState: createInitState(),
  pause: null,
  activeTurn: null,
  preparation: null,
  executionProcess: null,
  executionResource: null,
});
const failure = (code, cause) =>
  Object.assign(new Error("Private rejected data"), { code, cause });

test("complete over-capacity document discovery rejects before any workspace or role authority", async () => {
  let calls = 0;
  const operation = () =>
    inspectInitSetup(
      {
        projectPath: "/work/project",
        taskPath: "/work/task",
        stateRoot: "/work/state",
        artifactRoot: "artifacts",
        placement: "external",
        documents: {
          instructions: Array.from(
            { length: 257 },
            (_, index) => `/work/project/component-${index}/AGENTS.md`,
          ),
          checks: [],
          skills: [],
          guidance: [],
        },
      },
      {
        workspace: {
          inspect() {
            calls++;
            assert.fail("Partial inspection cannot be accepted.");
          },
        },
      },
    );
  let cause;
  try {
    await inspectInitOperation("inspection", operation);
  } catch (error) {
    cause = error;
  }
  assert.equal(calls, 0);
  const original = run();
  const patch = initInspectionFailure(original, cause);
  assert.deepEqual(patch.pause.inspectionFailure, {
    phase: "inspection",
    constraint: "evidence_capacity",
  });
  const paused = { ...original, ...patch };
  initPipeline.workflow.validateRun(paused);
  assert.equal(paused.pipelineState.sequence, 0);
  assert.equal(paused.pipelineState.inspection, null);
  assert.equal(paused.pipelineState.publication, null);
  const projection = initPipeline.projections.pause(paused);
  assert.deepEqual(projection.inspectionFailure, patch.pause.inspectionFailure);
  assert.deepEqual(projection.nextActions, []);
  assert.match(projection.explanation, /fresh init run/u);
});

test("diagnosis retains only finite constraints and permits only transient unchanged-input recovery", async () => {
  const original = run();
  const patch = initInspectionFailure(
    original,
    failure("ERR_WORKSPACE_INSPECTION", failure("EMFILE")),
  );
  assert.deepEqual(patch.pause.inspectionFailure, {
    phase: "recovery",
    constraint: "inspection_unavailable",
  });
  const paused = { ...original, ...patch };
  initPipeline.workflow.validateRun(paused);
  assert.deepEqual(initPipeline.projections.pause(paused).nextActions, [
    { type: "resume", action: null },
  ]);
  assert.equal(JSON.stringify(patch).includes("Private rejected data"), false);
  for (const cause of [
    null,
    undefined,
    "ERR_WORKSPACE_PROOF_CAPACITY",
    { code: "ERR_WORKSPACE_PROOF_CAPACITY" },
    {
      code: "ERR_PROJECT_CONFIGURATION_READ",
      readFailure: "inspection_unavailable",
    },
    new TypeError("Private rejected data"),
    failure("ERR_INIT_PROPOSAL"),
    failure("ERR_WORKSPACE_INSPECTION", failure("EIO")),
    failure("ERR_WORKSPACE_OUTPUT_AMBIGUOUS"),
    failure("ERR_CLARIFICATION_WRITE"),
    failure("ERR_INVALID_EDITOR_COMMAND"),
    failure("ERR_INVALID_EDIT_AUTHORIZATION"),
    failure("ERR_INIT_INSPECTION"),
    failure("ERR_GUIDANCE_STORAGE", failure("EMFILE")),
    Object.assign(failure("ERR_WORKSPACE_INSPECTION", failure("EMFILE")), {
      executionResourceRetained: true,
    }),
  ]) {
    assert.equal(initInspectionFailure(original, cause), null);
    await assert.rejects(
      inspectInitOperation("inspection", () => {
        throw cause;
      }),
      (error) => error === cause,
    );
  }
  for (const binding of [
    { executionResource: {} },
    { executionProcess: {} },
    { preparation: {} },
    {
      pipelineState: {
        ...original.pipelineState,
        publication: { pending: {} },
      },
    },
    { pipelineState: { ...original.pipelineState, guidanceIntent: {} } },
  ]) {
    assert.equal(
      initInspectionFailure(
        { ...original, ...binding },
        failure("ERR_WORKSPACE_PROOF_CAPACITY"),
      ),
      null,
    );
    assert.throws(
      () => initPipeline.workflow.validateRun({ ...paused, ...binding }),
      /settled pause/u,
    );
  }
  for (const invalid of [
    { phase: "unknown", constraint: "evidence_capacity" },
    { phase: "inspection", constraint: "unknown" },
    {
      phase: "inspection",
      constraint: "evidence_capacity",
      raw: "Private rejected data",
    },
  ])
    assert.throws(
      () =>
        assertInspectionFailure({ ...patch.pause, inspectionFailure: invalid }),
      /invalid/u,
    );
});

test("only trusted bounded-file constraints classify deterministic read rejection", async () => {
  for (const code of [
    "ERR_INVALID_CLARIFICATION",
    "ERR_PROJECT_CONFIGURATION_READ",
  ]) {
    for (const [constraint, expected] of [
      ["file_size", "evidence_capacity"],
      ["isolated_regular_file", "unsafe_path"],
    ]) {
      const cause = Object.assign(failure(code), { constraint });
      await assert.rejects(
        inspectInitOperation("reinspection", () => {
          throw cause;
        }),
        {
          code: "ERR_INIT_INSPECTION",
          phase: "reinspection",
          constraint: expected,
        },
      );
      assert.equal(
        JSON.stringify(initInspectionFailure(run(), cause)).includes(
          "Private rejected data",
        ),
        false,
      );
    }
    for (const constraint of [undefined, "unknown"]) {
      const cause = Object.assign(failure(code), { constraint });
      assert.equal(initInspectionFailure(run(), cause), null);
      await assert.rejects(
        inspectInitOperation("preparation", () => {
          throw cause;
        }),
        (error) => error === cause,
      );
    }
  }
});

test("normalized guidance read metadata requires a scoped read and grants no effect recovery", async () => {
  for (const code of [
    "ERR_UNSAFE_GUIDANCE_PATH",
    "ERR_GUIDANCE_STORAGE",
    "ERR_PROJECT_CONFIGURATION_READ",
  ]) {
    const cause = Object.assign(failure(code), {
      readFailure: "inspection_unavailable",
    });
    let tagged;
    await assert.rejects(
      inspectInitOperation("preparation", () => {
        throw cause;
      }),
      (error) => {
        tagged = error;
        assert.equal(error.code, "ERR_INIT_INSPECTION");
        assert.equal(error.constraint, "inspection_unavailable");
        return true;
      },
    );
    assert.equal(initInspectionFailure(run(), cause, null), null);
    assert.equal(
      initInspectionFailure(run(), tagged).pause.inspectionFailure.phase,
      "preparation",
    );
    for (const pipelineState of [
      { ...run().pipelineState, publication: { pending: {} } },
      { ...run().pipelineState, guidanceIntent: {} },
    ])
      assert.equal(
        initInspectionFailure({ ...run(), pipelineState }, tagged),
        null,
      );
  }
  for (const readFailure of [
    "unsafe_path",
    "workspace_changed",
    "evidence_capacity",
  ]) {
    const cause = Object.assign(failure("ERR_UNSAFE_GUIDANCE_PATH"), {
      readFailure,
    });
    let tagged;
    await assert.rejects(
      inspectInitOperation("preparation", () => {
        throw cause;
      }),
      (error) => {
        tagged = error;
        assert.equal(error.constraint, readFailure);
        return true;
      },
    );
    const paused = { ...run(), ...initInspectionFailure(run(), tagged) };
    assert.deepEqual(initPipeline.projections.pause(paused).nextActions, []);
  }
  for (const [code, readFailure] of [
    ["ERR_UNSAFE_GUIDANCE_PATH", undefined],
    ["ERR_UNSAFE_GUIDANCE_PATH", "unknown"],
    ["ERR_GUIDANCE_RECOVERY", "inspection_unavailable"],
    ["ERR_GUIDANCE_STORAGE", undefined],
    ["ERR_GUIDANCE_STORAGE", "unknown"],
  ]) {
    const cause = Object.assign(failure(code), { readFailure });
    assert.equal(initInspectionFailure(run(), cause), null);
    await assert.rejects(
      inspectInitOperation("preparation", () => {
        throw cause;
      }),
      (error) => error === cause,
    );
  }
});

test("only trusted configuration absence metadata diagnoses a vanished selection", async () => {
  const cause = Object.assign(failure("ERR_PROJECT_CONFIGURATION_READ"), {
    constraint: "missing_file",
  });
  const paused = { ...run(), ...initInspectionFailure(run(), cause) };
  assert.equal(paused.pause.inspectionFailure.constraint, "workspace_changed");
  assert.deepEqual(initPipeline.projections.pause(paused).nextActions, []);
  await assert.rejects(
    inspectInitOperation("reinspection", () => {
      throw cause;
    }),
    {
      code: "ERR_INIT_INSPECTION",
      phase: "reinspection",
      constraint: "workspace_changed",
    },
  );
  assert.equal(
    initInspectionFailure(run(), failure("ERR_PROJECT_CONFIGURATION_READ")),
    null,
  );
});

test("inspection recovery preserves blocked, exhausted and non-resumable diagnoses", () => {
  const transient = failure("ERR_WORKSPACE_INSPECTION", failure("EMFILE"));
  const original = run();
  const inspectionPause = initInspectionFailure(
    original,
    failure("ERR_WORKSPACE_PROOF_CAPACITY"),
  );
  for (const reason of [
    "setup_blocked",
    "revision_limit",
    "clarification_limit",
  ]) {
    const blocked = {
      ...original,
      pipelineState: {
        ...original.pipelineState,
        workflowState: "WAITING_FOR_USER",
        pauseReason: reason,
        revisionRounds:
          reason === "revision_limit"
            ? original.pipelineState.settings.maxRevisionRounds
            : 0,
        clarificationRounds: reason === "clarification_limit" ? 3 : 0,
      },
      pause: { reason, resumeState: "CLARIFY" },
    };
    const reloaded = JSON.parse(JSON.stringify(blocked));
    initPipeline.workflow.validateRun(reloaded);
    assert.equal(initInspectionFailure(reloaded, transient), null);
    assert.equal(initPipeline.inspectionFailure(reloaded, transient), null);
    assert.deepEqual(reloaded, blocked);
    assert.deepEqual(initPipeline.projections.pause(reloaded).nextActions, []);
    assert.throws(() => initPipeline.validateResumeAction(reloaded, null));
    const diagnosed = {
      ...reloaded,
      pause: initInspectionFailure(original, transient).pause,
    };
    assert.throws(
      () => initPipeline.workflow.validateRun(diagnosed),
      /diagnosis is invalid/u,
    );
    assert.throws(() => initPipeline.validateResumeAction(diagnosed, null));
  }
  const blocked = JSON.parse(
    JSON.stringify({ ...original, ...inspectionPause }),
  );
  initPipeline.workflow.validateRun(blocked);
  assert.equal(initPipeline.inspectionFailure(blocked, transient), null);
  assert.deepEqual(initPipeline.projections.pause(blocked).nextActions, []);
  assert.throws(() => initPipeline.validateResumeAction(blocked, null));
});
