import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createClarificationService } from "../../../src/clarifications/index.js";
import { createWorkspaceService } from "../../../src/workspace/index.js";
import {
  acceptInitEdit,
  acceptInitQuestionAppend,
  acceptInitResult,
  assertInitState,
  authorizeInitEdit,
  closeInitClarification,
  createInitState,
  externalFinalizationContent,
  initPipeline,
  integratedFinalizationContent,
  integratedFinalizationPath,
  integratedIgnoreContent,
  inspectInitSetup,
  prepareInitTurn,
  selectInitPlacement,
} from "../src/index.js";

const HASH = "a".repeat(64);
const OTHER = "b".repeat(64);

test("external finalization references only the target's finalization skills", () => {
  const finalization = ".agents/skills/finalization/SKILL.md";
  const unrelated = ".agents/skills/test-authoring/SKILL.md";
  const inspection = {
    projectPath: "/work/project",
    documents: {
      instructions: [{ path: "/work/project/AGENTS.md" }],
      skills: [
        { path: `/work/project/${finalization}` },
        { path: `/work/project/${unrelated}` },
        { path: "/work/other/finalization/SKILL.md" },
      ],
    },
  };
  const content = externalFinalizationContent({ inspection }, ["node --test"]);
  assert.ok(content.includes(`- ${finalization}\n`));
  assert.ok(!content.includes(unrelated));
  assert.ok(!content.includes("../other/"));
  assert.ok(content.includes("AGENTS.md"));
  assert.ok(content.includes("- node --test\n"));
});

test("ignore additions preserve missing newlines and literal path characters", () => {
  assert.equal(
    integratedIgnoreContent("# Preserve", "/work/project", []),
    "# Preserve",
  );
  assert.equal(
    integratedIgnoreContent("# Preserve", "/work/project", [
      "/work/project/artifacts[local] cache",
    ]),
    "# Preserve\n/artifacts\\[local\\]\\ cache\n",
  );
  assert.equal(
    integratedIgnoreContent("/artifacts\n!/artifacts\n", "/work/project", [
      "/work/project/artifacts",
      "/work/project/artifacts",
    ]),
    "/artifacts\n!/artifacts\n/artifacts\n",
  );
});
const candidate = (placement = "external", rootPath = "/work/setup") => ({
  placement,
  rootPath,
  configurationPath: `${rootPath}/agent-runner.json`,
  artifactPath: `${rootPath}/artifacts`,
  protectionHash: HASH,
});
const inspection = (candidates = []) => ({
  schemaVersion: 1,
  projectPath: "/work/project",
  taskPath: "/state/task",
  artifactRoot: "artifacts",
  configurationPaths: [],
  candidates,
  documents: { instructions: [], checks: [], skills: [], guidance: [] },
  controlPaths: [".git", ".codex", ".claude", ".agents", ".claude.json"].map(
    (name) => `/work/project/${name}`,
  ),
  roots: ["/work/project", ...candidates.map((value) => value.rootPath)],
  scopeBindings: [
    ...new Set([
      "/work/project",
      "/state/task",
      ...candidates.map((value) => value.rootPath),
      ...[".git", ".codex", ".claude", ".agents", ".claude.json"].map(
        (name) => `/work/project/${name}`,
      ),
    ]),
  ].map((path) => ({ path, hash: HASH })),
  entries: [],
  snapshotHash: HASH,
});
const ready = { status: "READY", questions: [], reason: "" };

test("bound integrated skills use an adjacent wrapper unless their procedure already matches", () => {
  const checks = ["node --test"];
  const skillPath = "/work/project/.agents/skills/finalization/SKILL.md";
  const wrapperPath = "/work/project/.agents/skills/finalization/RUNNER.md";
  const selected = {
    ...candidate("integrated", "/work/project"),
    finalizationPath: skillPath,
  };
  const setup = inspection([selected]);
  const state = { inspection: setup, selection: selected };
  const matching = integratedFinalizationContent(state, checks);
  const hash = (content) => createHash("sha256").update(content).digest("hex");
  setup.documents.skills.push({
    path: skillPath,
    hash: hash("Original checks.\n"),
  });
  setup.entries.push({
    path: skillPath,
    kind: "file",
    hash: hash("Original checks.\n"),
  });
  assert.equal(integratedFinalizationPath(state, checks), wrapperPath);
  assert.match(
    integratedFinalizationContent(state, checks),
    /adjacent SKILL.md/u,
  );

  setup.entries[0].hash = hash(matching);
  setup.documents.skills[0].hash = hash(matching);
  assert.equal(integratedFinalizationPath(state, checks), skillPath);
  assert.equal(integratedFinalizationContent(state, checks), matching);
  assert.equal(
    integratedFinalizationPath(state, ["node --test --test-reporter=spec"]),
    wrapperPath,
  );
  // Same-run repair authority remains confined to its prepared procedure.
  assert.equal(
    integratedFinalizationPath(
      { ...state, createdFinalizationPath: skillPath },
      ["node --test --test-reporter=spec"],
    ),
    skillPath,
  );
});

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
function turn(state, setup, result) {
  const reserved = prepareInitTurn(state, setup, state.transcriptHash ?? HASH);
  assert.equal(reserved.request.access, "read-only");
  assert.equal(
    reserved.request.role,
    state.workflowState === "REVIEW" ? "reviewer" : "planner",
  );
  return acceptInitResult(reserved.state, {
    turnId: reserved.request.id,
    inspection: setup,
    transcriptHash: reserved.state.transcriptHash,
    result: roleResult(
      typeof result === "function" ? result(reserved.state) : result,
    ),
  });
}
function start(mode, setup = inspection(), options = {}) {
  const state = turn(
    createInitState({ settings: { mode, ...options } }),
    setup,
    ready,
  );
  return closeInitClarification(state, {
    inspection: setup,
    clarificationHash: HASH,
  });
}
const proposal = (state) => ({
  summary: "Prepare infrastructure from inspected project requirements.",
  checks: ["node --test"],
  resources: [
    {
      path: state.selection.configurationPath,
      kind: "configuration",
      action: "create",
      beforeHash: null,
      content: '{"schemaVersion":1}\n',
    },
    {
      path: state.selection.artifactPath,
      kind: "artifacts",
      action: "create",
      beforeHash: null,
      content: "",
    },
    {
      path: `${state.selection.rootPath}/finalization/SKILL.md`,
      kind: "finalization",
      action: "create",
      beforeHash: null,
      content: "Run node --test.\n",
    },
    {
      path: `${state.selection.artifactPath}/agent-runner/rules.md`,
      kind: "guidance",
      action: "create",
      beforeHash: null,
      content: "Validate from the project root.\n",
    },
  ],
});
const clean = (state) => ({
  status: "CLEAN",
  proposalHash: state.proposalHash,
  findings: [],
});
const findings = (state) => ({
  status: "FINDINGS",
  proposalHash: state.proposalHash,
  findings: ["Preserve the existing validation command."],
});

test("a proposal cannot select multiple finalization resources for guidance and repair", () => {
  const setup = inspection();
  const content = "Preserve the existing procedure.\n";
  const path = "/work/project/existing-finalization.md";
  const hash = createHash("sha256").update(content).digest("hex");
  setup.entries.push({ path, kind: "file", hash });
  const initial = start("combined", setup);
  const valid = proposal(initial);
  const ambiguous = structuredClone(valid);
  ambiguous.resources.unshift({
    path,
    kind: "finalization",
    action: "reuse",
    beforeHash: hash,
    content,
  });
  assert.throws(
    () => turn(initial, setup, ambiguous),
    /exactly one.*finalization/u,
  );
  const accepted = turn(initial, setup, valid);
  assert.deepEqual(accepted.proposal, valid);
});

test("reviewed guidance records the selected finalization path and replaces only managed metadata on rerun", () => {
  const setup = inspection();
  const render = (inspected, previous, finalizationPath) => {
    const state = turn(start("combined", inspected), inspected, (current) => {
      const result = proposal(current);
      const guide = result.resources.find(({ kind }) => kind === "guidance");
      guide.content = previous;
      guide.beforeHash =
        inspected.entries.find(({ path }) => path === guide.path)?.hash ?? null;
      guide.action = guide.beforeHash === null ? "create" : "replace";
      result.resources.find(({ kind }) => kind === "finalization").path =
        finalizationPath;
      return result;
    });
    const { request } = prepareInitTurn(state, inspected, HASH);
    return JSON.parse(request.prompt.split("\n").at(-1)).mergedGuidance;
  };
  const skillPath = "/work/project/finalization/SKILL.md";
  const wrapperPath = "/work/project/finalization/RUNNER.md";
  const first = render(setup, "Keep local instructions.\n", skillPath);
  assert.ok(first.includes(`Finalization: ${skillPath}\n`));
  const content = `${first}\nKeep later operator instructions.\n`;
  const hash = createHash("sha256").update(content).digest("hex");
  setup.entries.push({
    path: "/work/project/artifacts/agent-runner/rules.md",
    kind: "file",
    hash,
  });
  setup.documents.guidance.push({ path: setup.entries[0].path, hash });
  const updated = render(setup, content, wrapperPath);
  assert.ok(updated.includes(`Finalization: ${wrapperPath}\n`));
  assert.ok(!updated.includes(skillPath));
  assert.equal(updated.split("## Runner setup").length, 2);
  assert.ok(updated.includes("Keep local instructions."));
  assert.ok(updated.includes("Keep later operator instructions."));
});

test("proposal gates keep placement independent of all three review modes", () => {
  for (const mode of ["lazy", "independent", "combined"]) {
    for (const placement of ["integrated", "external"]) {
      const setup = inspection([
        candidate(
          placement,
          placement === "integrated" ? "/work/project" : "/work/setup",
        ),
      ]);
      let state = start(mode, setup, { placement });
      const phases = [];
      while (state.workflowState !== "PROPOSAL_ACCEPTED") {
        phases.push(state.workflowState);
        state = turn(
          state,
          setup,
          ["PROPOSE", "CHECK_AND_FIX"].includes(state.workflowState)
            ? proposal
            : clean,
        );
        assertInitState(structuredClone(state));
      }
      assert.deepEqual(
        phases,
        mode === "independent"
          ? ["PROPOSE", "REVIEW"]
          : mode === "lazy"
            ? ["PROPOSE", "CHECK_AND_FIX", "CLEAN_CONFIRM"]
            : ["PROPOSE", "CHECK_AND_FIX", "CLEAN_CONFIRM", "REVIEW"],
      );
      assert.equal(state.selection.placement, placement);
      assert.equal(state.workflowState === "DONE", false);
      assert.throws(
        () => prepareInitTurn(state, setup, HASH),
        /not at an agent checkpoint/u,
      );
    }
  }
  assert.deepEqual(initPipeline.resolveActiveRoles({ mode: "lazy" }), [
    "planner",
  ]);
  assert.equal(initPipeline.settings.mode.defaultValue, "independent");
});

test("persisted init settings retain the resolved independent default", () => {
  const setup = inspection();
  const state = turn(createInitState(), setup, ready);
  const reloaded = JSON.parse(JSON.stringify(state));
  assertInitState(reloaded);
  assert.equal(reloaded.settings.mode, "independent");
  const closed = closeInitClarification(reloaded, {
    inspection: setup,
    clarificationHash: HASH,
  });
  assert.equal(turn(closed, setup, proposal).workflowState, "REVIEW");
  for (const key of Object.keys(reloaded.settings)) {
    const incomplete = structuredClone(reloaded);
    delete incomplete.settings[key];
    assert.throws(
      () => assertInitState(incomplete),
      /missing or unsupported fields/u,
    );
    assert.throws(
      () => prepareInitTurn(incomplete, setup, HASH),
      /missing or unsupported fields/u,
    );
  }
});

test("oversized merged guidance is rejected before replacing a retryable proposal", () => {
  const setup = inspection();
  const initial = start("combined", setup);
  const proposed = turn(initial, setup, proposal);
  const nearLimit = proposal(initial);
  const guide = nearLimit.resources.find(({ kind }) => kind === "guidance");
  // The existing document fits; the rendered setup section puts it over.
  guide.content = "x".repeat(65_536);
  guide.beforeHash = createHash("sha256").update(guide.content).digest("hex");
  guide.action = "reuse";
  const existing = inspection();
  existing.entries.push({
    path: guide.path,
    kind: "file",
    hash: guide.beforeHash,
  });
  existing.documents.guidance.push({
    path: guide.path,
    hash: guide.beforeHash,
  });
  const withExisting = start("combined", existing);
  const oversized = (state) => {
    const result = proposal(state);
    result.resources.find(({ kind }) => kind === "guidance").content =
      "é".repeat(40_000);
    return result;
  };
  for (const [state, inspected, invalid] of [
    [initial, setup, oversized],
    [proposed, setup, oversized],
    [withExisting, existing, nearLimit],
  ]) {
    const before = structuredClone(state);
    assert.throws(
      () => turn(state, inspected, invalid),
      /Merged init guidance/u,
    );
    assert.deepEqual(state, before);
    const repaired =
      typeof invalid === "function"
        ? proposal(state)
        : structuredClone(invalid);
    if (typeof invalid !== "function") {
      const resource = repaired.resources.find(
        ({ kind }) => kind === "guidance",
      );
      resource.content = "Keep the existing validation instructions.\n";
      resource.action = "replace";
    }
    const next = turn(state, inspected, repaired);
    assertInitState(next);
    assert.doesNotThrow(() => prepareInitTurn(next, inspected, HASH));
  }
});

test("revisions clear both approvals and restart combined convergence without renewing accounting", () => {
  const setup = inspection();
  let state = start("combined", setup, { maxRevisionRounds: 1 });
  for (const result of [proposal, proposal, clean])
    state = turn(state, setup, result);
  assert.ok(state.primaryApproval);
  state = turn(state, setup, findings);
  assert.equal(state.workflowState, "CHECK_AND_FIX");
  assert.equal(state.primaryApproval, null);
  assert.equal(state.reviewApproval, null);
  assert.equal(state.revisionRounds, 1);
  state = turn(state, setup, proposal);
  state = turn(state, setup, findings);
  assert.equal(state.workflowState, "WAITING_FOR_USER");
  assert.equal(state.pauseReason, "revision_limit");
  assert.equal(state.revisionRounds, 1);
});

test("selection reuses one bound setup, defaults new targets, and never merges conflicts", () => {
  assert.equal(selectInitPlacement(inspection()).placement, "integrated");
  const external = candidate();
  assert.deepEqual(selectInitPlacement(inspection([external])), external);
  assert.throws(
    () =>
      selectInitPlacement(inspection([external]), {
        placement: "integrated",
        configurationPath: external.configurationPath,
      }),
    /disagree/u,
  );
  const setup = inspection([
    external,
    candidate("integrated", "/work/project"),
  ]);
  let state = turn(createInitState(), setup, ready);
  assert.equal(state.pauseReason, "placement_conflict");
  const authorization = {
    schemaVersion: 1,
    id: "edit-1",
    artifactRoot: setup.taskPath,
    transcriptPath: `${setup.taskPath}/clarifications.md`,
    suspendedState: "CLARIFY",
    action: "proactive-clarification",
    preEditorHash: HASH,
  };
  state = authorizeInitEdit(state, authorization);
  state = acceptInitEdit(
    structuredClone(state),
    {
      ...authorization,
      authorizationId: authorization.id,
      hash: OTHER,
      changed: true,
    },
    { placement: "external", configurationPath: external.configurationPath },
  );
  assert.equal(state.pendingEdit, null);
  assert.equal(state.clarificationRounds, 0);
  state = turn(state, setup, ready);
  state = closeInitClarification(state, {
    inspection: setup,
    clarificationHash: OTHER,
  });
  assert.deepEqual(state.selection, external);
  assert.throws(
    () => authorizeInitEdit(state, authorization),
    /cannot authorize/u,
  );
});

test("read-only turns reject drift, stale results, premature closure and forged gate state", () => {
  const setup = inspection();
  assert.throws(
    () =>
      closeInitClarification(createInitState(), {
        inspection: setup,
        clarificationHash: HASH,
      }),
    /cannot close/u,
  );
  const state = start("combined", setup);
  const reserved = prepareInitTurn(state, setup, HASH);
  assert.deepEqual(
    prepareInitTurn(structuredClone(reserved.state), setup, HASH).state,
    reserved.state,
  );
  for (const change of [
    { inspection: { ...setup, snapshotHash: OTHER } },
    { transcriptHash: OTHER },
    { turnId: 99 },
  ]) {
    assert.throws(
      () =>
        acceptInitResult(reserved.state, {
          turnId: reserved.request.id,
          inspection: setup,
          transcriptHash: HASH,
          result: proposal(state),
          ...change,
        }),
      /stale|changed/u,
    );
  }
  assert.throws(
    () => assertInitState({ ...state, workflowState: "PROPOSAL_ACCEPTED" }),
    /not passed/u,
  );
  const proposed = turn(state, setup, proposal);
  assert.throws(
    () => assertInitState({ ...proposed, workflowState: "REVIEW" }),
    /primary gate/u,
  );
  assert.throws(
    () => prepareInitTurn(state, setup, OTHER),
    /outside an authorized/u,
  );
  for (const reason of ["workspace_changed", "project_configuration_changed"]) {
    const blocked = {
      pipelineId: "init",
      pipelineState: { ...reserved.state, workflowState: "WAITING_FOR_USER" },
      pause: { reason },
    };
    assert.doesNotThrow(() => initPipeline.workflow.validateRun(blocked));
    assert.throws(
      () => initPipeline.validateResumeAction(blocked, null),
      /cannot resume/u,
    );
  }
});

test("an authorized placement change requires new inspection before clarification freezes", () => {
  const setup = inspection();
  setup.entries.push({
    path: `${setup.taskPath}/task.md`,
    kind: "file",
    hash: HASH,
  });
  let state = turn(createInitState(), setup, ready);
  const authorization = {
    schemaVersion: 1,
    id: "placement-edit",
    artifactRoot: setup.taskPath,
    transcriptPath: `${setup.taskPath}/clarifications.md`,
    suspendedState: "CLARIFY",
    action: "proactive-clarification",
    preEditorHash: HASH,
  };
  state = authorizeInitEdit(state, authorization);
  state = acceptInitEdit(
    state,
    {
      ...authorization,
      authorizationId: authorization.id,
      hash: OTHER,
      changed: true,
    },
    { placement: "external", configurationPath: null },
  );
  assert.deepEqual(state.inspection, setup);
  assert.throws(
    () => prepareInitTurn(state, setup, OTHER),
    /unbound infrastructure/u,
  );
  const prefix = createHash("sha256")
    .update(setup.projectPath)
    .digest("hex")
    .slice(0, 12);
  const rootPath = `/work/.agent-runner-project-${prefix}`;
  const selected = {
    ...setup,
    roots: [...setup.roots, rootPath],
    scopeBindings: [...setup.scopeBindings, { path: rootPath, hash: OTHER }],
    snapshotHash: OTHER,
  };
  for (const change of [
    {
      ...selected,
      configurationPaths: ["/state/replacement.json"],
      scopeBindings: [
        ...selected.scopeBindings,
        { path: "/state/replacement.json", hash: OTHER },
      ],
    },
    { ...selected, entries: [{ ...setup.entries[0], hash: OTHER }] },
    {
      ...selected,
      scopeBindings: selected.scopeBindings.map((binding) =>
        binding.path === setup.taskPath ? { ...binding, hash: OTHER } : binding,
      ),
    },
    {
      ...selected,
      scopeBindings: selected.scopeBindings.map((binding) =>
        binding.path === setup.projectPath
          ? { ...binding, hash: OTHER }
          : binding,
      ),
    },
  ])
    assert.throws(
      () => prepareInitTurn(structuredClone(state), change, OTHER),
      /changed/u,
    );
  state = turn(state, selected, ready);
  state = closeInitClarification(state, {
    inspection: selected,
    clarificationHash: OTHER,
  });
  assert.equal(state.selection.rootPath, rootPath);
  assert.throws(() => prepareInitTurn(state, setup, OTHER), /changed/u);
});

test("placement edits cannot adopt configuration substitution even when the destination is unchanged", () => {
  const setup = inspection([candidate("integrated", "/work/project")]);
  let state = turn(createInitState(), setup, ready);
  const authorization = {
    schemaVersion: 1,
    id: "same-destination-edit",
    artifactRoot: setup.taskPath,
    transcriptPath: `${setup.taskPath}/clarifications.md`,
    suspendedState: "CLARIFY",
    action: "proactive-clarification",
    preEditorHash: HASH,
  };
  state = authorizeInitEdit(state, authorization);
  state = acceptInitEdit(
    structuredClone(state),
    {
      ...authorization,
      authorizationId: authorization.id,
      hash: OTHER,
      changed: true,
    },
    { placement: "integrated", configurationPath: null },
  );
  const substituted = structuredClone(setup);
  substituted.candidates[0].protectionHash = OTHER;
  substituted.snapshotHash = OTHER;
  assert.throws(() => prepareInitTurn(state, substituted, OTHER), /changed/u);
  state = turn(state, setup, ready);
  state = closeInitClarification(state, {
    inspection: setup,
    clarificationHash: OTHER,
  });
  assert.equal(state.selection.rootPath, setup.projectPath);
});

test("proposal validation protects live configuration, existing skills and inspected resource hashes", () => {
  const setup = inspection();
  setup.configurationPaths = ["/work/project/artifacts/agent-runner.json"];
  setup.scopeBindings.push({ path: setup.configurationPaths[0], hash: HASH });
  const state = start("independent", setup);
  assert.throws(() => turn(state, setup, proposal), /configuration resolved/u);
  setup.configurationPaths = [];
  const existing = inspection();
  existing.entries = [
    {
      path: "/work/project/artifacts/agent-runner.json",
      kind: "file",
      hash: HASH,
    },
  ];
  const bound = start("independent", existing);
  assert.throws(() => turn(bound, existing, proposal), /prior content/u);
  const replacement = proposal(bound);
  Object.assign(replacement.resources[0], {
    action: "replace",
    beforeHash: HASH,
  });
  Object.assign(replacement.resources[2], {
    action: "replace",
    beforeHash: HASH,
  });
  existing.entries.push({
    path: replacement.resources[2].path,
    kind: "file",
    hash: HASH,
  });
  existing.documents.skills = [
    { path: replacement.resources[2].path, hash: HASH },
  ];
  assert.throws(
    () => turn(start("independent", existing), existing, replacement),
    /preserve existing skills/u,
  );
});

test("shared clarification appends and answer windows retain unanswered rounds across reload", async (t) => {
  const taskPath = await mkdtemp(join(tmpdir(), "agent-runner-init-"));
  t.after(() => rm(taskPath, { recursive: true, force: true }));
  const setup = { ...inspection(), taskPath };
  setup.scopeBindings.push({ path: taskPath, hash: HASH });
  const service = createClarificationService({ env: {}, interactive: false });
  const location = {
    artifactRoot: taskPath,
    transcriptPath: join(taskPath, "clarifications.md"),
  };
  const initial = await service.ensureTranscript(location);
  let state = createInitState({ proactiveClarification: true });
  state.transcriptHash = initial.hash;
  state = turn(state, setup, ready);
  assert.equal(state.proactiveClarificationComplete, false);
  const optional = await service.prepareEdit({
    ...location,
    expectedHash: state.transcriptHash,
    suspendedState: "CLARIFY",
    action: "proactive-clarification",
    persistPendingEdit: (authorization) => {
      state = authorizeInitEdit(state, authorization);
      assert.equal(state.proactiveClarificationComplete, true);
      assert.equal(state.pendingEdit.id, authorization.id);
    },
  });
  await service.acceptEdit(optional, {
    consumePendingEdit: (result) => {
      state = acceptInitEdit(state, result);
    },
  });
  assert.equal(state.workflowState, "CLARIFY");
  assert.equal(state.clarificationRounds, 0);
  const materialQuestion = {
    question: "Which existing setup should be retained?",
    whyItMatters: "Competing setups cannot be merged.",
  };
  for (const field of ["question", "whyItMatters"]) {
    for (const value of ["x".repeat(4_001), "Two\nlines"])
      assert.throws(
        () =>
          turn(state, setup, {
            status: "QUESTIONS",
            questions: [{ ...materialQuestion, [field]: value }],
            reason: "",
          }),
        /plain-text rationale/u,
      );
  }
  for (let round = 1; round <= 3; round += 1) {
    state = turn(state, setup, {
      status: "QUESTIONS",
      questions: [materialQuestion],
      reason: "",
    });
    assert.equal(state.clarificationRounds, round);
    const expectedHash = state.transcriptHash;
    const transcript = await service.appendQuestionRound({
      ...location,
      expectedHash,
      round,
      questions: state.questions,
    });
    const receipt = { round, expectedHash, transcript };
    assert.throws(() => authorizeInitEdit(state, {}), /cannot authorize/u);
    for (const change of [
      { round: round + 1 },
      { expectedHash: OTHER },
      {
        transcript: {
          ...transcript,
          transcriptPath: join(taskPath, "other.md"),
        },
      },
    ])
      assert.throws(
        () => acceptInitQuestionAppend(state, { ...receipt, ...change }),
        /does not match/u,
      );
    state = acceptInitQuestionAppend(structuredClone(state), receipt);
    assert.throws(
      () => acceptInitQuestionAppend(state, receipt),
      /does not match/u,
    );
    const prepareEdit = () =>
      service.prepareEdit({
        ...location,
        expectedHash: state.transcriptHash,
        suspendedState: "CLARIFY",
        action: "clarification-answers",
        persistPendingEdit: (authorization) => {
          state = authorizeInitEdit(state, authorization);
        },
      });
    const consumePendingEdit = (result) => {
      state = acceptInitEdit(structuredClone(state), result);
    };
    for (let close = 0; close < 2; close += 1) {
      const authorization = await prepareEdit();
      assert.throws(
        () =>
          assertInitState({
            ...state,
            pendingEdit: { ...authorization, action: "clarification" },
          }),
        /authorization is invalid/u,
      );
      const result = await service.acceptEdit(authorization, {
        consumePendingEdit,
      });
      assert.throws(() => acceptInitEdit(state, result), /does not match/u);
      assert.equal(state.pendingEdit, null);
      assert.equal(state.workflowState, "WAITING_FOR_USER");
      assert.equal(state.clarificationRounds, round);
      assert.deepEqual(state.questions, [materialQuestion]);
      assert.throws(
        () => prepareInitTurn(state, setup, state.transcriptHash),
        /not at an agent checkpoint/u,
      );
    }
    const authorization = await prepareEdit();
    const answers = ["Retain the explicitly selected setup."];
    const preview = await service.previewEditAnswers(authorization, answers);
    await service.writeEditAnswers(authorization, answers, {
      expectedHash: preview.hash,
    });
    const pending = structuredClone(state);
    await service.acceptEdit(authorization, { consumePendingEdit });
    assert.throws(
      () => acceptInitEdit(pending, { authorizationId: "wrong" }),
      /does not match/u,
    );
    assert.equal(state.workflowState, "CLARIFY");
    assert.equal(state.transcriptHash, preview.hash);
    assert.equal(state.clarificationRounds, round);
  }
  const exhausted = turn(structuredClone(state), setup, {
    status: "QUESTIONS",
    questions: [
      { question: "Choose placement", whyItMatters: "Competing setups exist." },
    ],
    reason: "",
  });
  assert.equal(exhausted.pauseReason, "clarification_limit");
  assert.equal(exhausted.clarificationRounds, 3);
  state = turn(state, setup, ready);
  const frozen = await service.freezeTranscript({
    ...location,
    expectedHash: state.transcriptHash,
  });
  state = closeInitClarification(state, {
    inspection: setup,
    clarificationHash: frozen.hash,
  });
  assert.equal(state.workflowState, "PROPOSE");
});

test("reused bytes, symbolic-link ancestors and overlapping file resources cannot be substituted", () => {
  const setup = inspection();
  const content = '{"schemaVersion":1}\n';
  const hash = createHash("sha256").update(content).digest("hex");
  setup.entries = [
    { path: "/work/project/artifacts/agent-runner.json", kind: "file", hash },
  ];
  let state = start("independent", setup);
  const reused = proposal(state);
  Object.assign(reused.resources[0], { action: "reuse", beforeHash: hash });
  assert.equal(turn(state, setup, reused).workflowState, "REVIEW");
  reused.resources[0].content += "changed";
  assert.throws(() => turn(state, setup, reused), /reused content/u);
  const linked = inspection();
  linked.entries = [
    { path: "/work/project/finalization", kind: "symlink", hash: HASH },
  ];
  state = start("independent", linked);
  assert.throws(() => turn(state, linked, proposal), /symbolic link/u);
  state = start("independent");
  const overlapping = proposal(state);
  overlapping.resources.push({
    path: `${overlapping.resources[2].path}/nested.md`,
    kind: "finalization",
    action: "create",
    beforeHash: null,
    content: "",
  });
  assert.throws(
    () => turn(state, inspection(), overlapping),
    /artifact directory/u,
  );
});

test("proposals protect discovered controls and setup inputs while allowing a new finalization skill", () => {
  const setup = inspection();
  setup.controlPaths.push("/work/project/metadata");
  setup.controlPaths.push("/work/project/nested/.git");
  setup.scopeBindings.push({ path: "/work/project/metadata", hash: HASH });
  setup.documents.instructions.push({
    path: "/work/project/AGENTS.md",
    hash: HASH,
  });
  const state = start("independent", setup);
  for (const path of [
    "/work/project/.claude/settings.md",
    "/work/project/.agents/instructions.md",
    "/work/project/metadata/notes.md",
    "/work/project/AGENTS.md",
    "/work/project/nested/finalization.md",
  ]) {
    const value = proposal(state);
    value.resources[2].path = path;
    assert.throws(
      () => turn(state, setup, value),
      /controls|setup inputs|different exclusion key/u,
    );
  }
  const value = proposal(state);
  value.resources[2].path =
    "/work/project/.agents/skills/finalization/SKILL.md";
  assert.equal(turn(state, setup, value).workflowState, "REVIEW");
});

test("conventional finalization paths cannot exempt bare Git metadata", () => {
  for (const name of [".agents", ".claude"]) {
    const setup = inspection();
    const root = join(setup.projectPath, name);
    setup.entries = [
      { path: join(root, "HEAD"), kind: "file", hash: HASH },
      { path: join(root, "objects"), kind: "directory", hash: null },
      { path: join(root, "refs"), kind: "directory", hash: null },
    ];
    const state = start("independent", setup);
    const value = proposal(state);
    value.resources[2].path = join(root, "skills", "finalization", "SKILL.md");
    assert.throws(() => turn(state, setup, value), /bare Git metadata/u);
  }
});

test("a parent task directory protects exact task artifacts without excluding integrated setup", () => {
  const setup = { ...inspection(), taskPath: "/work" };
  setup.scopeBindings.push({ path: setup.taskPath, hash: HASH });
  const state = start("independent", setup);
  assert.equal(turn(state, setup, proposal).workflowState, "REVIEW");
  // An external infrastructure root can contain task artifacts too.
  const external = { ...inspection([candidate()]), taskPath: "/work/setup" };
  const selected = start("independent", external);
  for (const name of ["task.md", "context.md", "clarifications.md"]) {
    const replacement = proposal(selected);
    replacement.resources[2].path = `${external.taskPath}/${name}`;
    assert.throws(() => turn(selected, external, replacement), /setup inputs/u);
  }
});

test("artifact resources remain directories and file resources cannot replace directories or file ancestors", () => {
  for (const [path, kind] of [
    ["/work/project/artifacts", "file"],
    ["/work/project/finalization/SKILL.md", "directory"],
    ["/work/project/finalization", "file"],
  ]) {
    const setup = inspection();
    const hash = createHash("sha256")
      .update(kind === "file" ? "" : JSON.stringify({ kind }))
      .digest("hex");
    setup.entries.push({ path, kind, hash: kind === "file" ? hash : null });
    const state = start("independent", setup);
    const value = proposal(state);
    const resource = value.resources.find((resource) => resource.path === path);
    if (resource)
      Object.assign(resource, {
        action: resource.kind === "artifacts" ? "reuse" : "replace",
        beforeHash: hash,
      });
    assert.throws(() => turn(state, setup, value), /directory|ancestor/u);
  }
  const setup = inspection();
  const state = start("independent", setup);
  const value = proposal(state);
  value.resources[1].content = "Unexpected file content";
  assert.throws(() => turn(state, setup, value), /directory/u);
  setup.entries.push({
    path: state.selection.artifactPath,
    kind: "directory",
    hash: null,
  });
  const existing = start("independent", setup);
  const reused = proposal(existing);
  Object.assign(reused.resources[1], {
    action: "reuse",
    beforeHash: createHash("sha256")
      .update(JSON.stringify({ kind: "directory" }))
      .digest("hex"),
  });
  assert.equal(turn(existing, setup, reused).workflowState, "REVIEW");
});

test("a frozen placement cannot diverge from the selection recorded during clarification", () => {
  const setup = inspection([
    candidate(),
    candidate("integrated", "/work/project"),
  ]);
  let state = createInitState();
  state.clarificationSelection = {
    placement: "external",
    configurationPath: "/work/setup/agent-runner.json",
  };
  state = turn(state, setup, ready);
  state = closeInitClarification(state, {
    inspection: setup,
    clarificationHash: HASH,
  });
  state.clarificationSelection = {
    placement: "integrated",
    configurationPath: "/work/project/agent-runner.json",
  };
  assert.throws(() => assertInitState(state), /Frozen init selection/u);
});

test("resource kinds cannot redirect guidance, ignore rules or finalization to other file types", () => {
  const setup = inspection();
  const state = start("independent", setup);
  for (const [index, path] of [
    [3, "/work/project/notes.md"],
    [2, "/work/project/source.js"],
  ]) {
    const value = proposal(state);
    value.resources[index].path = path;
    assert.throws(
      () => turn(state, setup, value),
      /guidance destination|Markdown procedure/u,
    );
  }
  for (const [current, currentSetup, path] of [
    [state, setup, "/work/project/other-ignore"],
    [
      start("independent", inspection([candidate()])),
      inspection([candidate()]),
      "/work/setup/.gitignore",
    ],
  ]) {
    const value = proposal(current);
    value.resources.push({
      path,
      kind: "ignore",
      action: "create",
      beforeHash: null,
      content: "artifacts/\n",
    });
    assert.throws(
      () => turn(current, currentSetup, value),
      /Only integrated init/u,
    );
  }
});

test("inspection delegates confined reads, hashes actual inputs and detects configuration substitution", async () => {
  const calls = [];
  let reads = 0;
  const options = {
    projectPath: "/work/project",
    taskPath: "/state/task",
    stateRoot: "/state/runs",
    artifactRoot: "artifacts",
    candidatePaths: ["/work/setup/agent-runner.json"],
    configurationPaths: ["/state/live.json"],
    documents: {
      instructions: ["/work/project/AGENTS.md"],
      checks: ["/work/project/package.json"],
      skills: ["/work/project/finalization/SKILL.md"],
      guidance: ["/work/setup/notes.md"],
    },
  };
  const capabilities = {
    loadProjectConfiguration: async () => ({
      path: options.candidatePaths[0],
      infrastructure: { placement: "external", rootPath: "/work/setup" },
      artifactPath: "/work/setup/artifacts",
      protection: { projectPath: options.projectPath, identity: "original" },
    }),
    inspectConfigurationPath: () => {},
    workspace: {
      ...createWorkspaceService(),
      inspectPath: async ({ path }) => ({ path, exists: false, ancestors: [] }),
      inspect: async (request) => {
        calls.push(request);
        const files = new Set([
          ...request.inputPaths,
          ...request.configurationPaths,
        ]);
        const directories = new Set([
          request.workspacePath,
          request.taskPath,
          "/work/setup",
        ]);
        return {
          bindings: [
            ...new Set([
              request.workspacePath,
              request.taskPath,
              ...request.inputPaths,
              ...request.configurationPaths,
              ...request.infrastructurePaths,
              "/work/project/metadata",
            ]),
          ].map((path) => {
            const kind = files.has(path)
              ? "file"
              : directories.has(path)
                ? "directory"
                : "missing";
            return { path, kind, exists: kind !== "missing", ancestors: [] };
          }),
          controlPaths: ["/work/project/metadata"],
        };
      },
      snapshot: async ({ inspection }) => ({
        schemaVersion: 1,
        workspacePath: options.projectPath,
        outputPaths: [],
        entries: inspection.bindings
          .map(({ path, kind }) => ({
            path,
            kind,
            hash:
              kind === "file"
                ? createHash("sha256").update(path).digest("hex")
                : null,
          }))
          .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
        linkResolutions: [],
      }),
      assertUnchanged: ({ before, after }) => assert.deepEqual(before, after),
      readFile: async ({ path }) => {
        reads += 1;
        return path;
      },
    },
  };
  const result = await inspectInitSetup(options, capabilities);
  assert.equal(reads, 4);
  assert.equal(
    result.documents.instructions[0].hash,
    createHash("sha256")
      .update(options.documents.instructions[0])
      .digest("hex"),
  );
  assert.deepEqual(calls[0].configurationPaths, options.configurationPaths);
  assert.equal(calls[0].outputPaths, undefined);
  assert.deepEqual(result.controlPaths, ["/work/project/metadata"]);
  assert.equal(result.candidates[0].rootPath, "/work/setup");
  assert.equal(
    selectInitPlacement(result, { placement: "external" }).configurationPath,
    options.candidatePaths[0],
  );
  const selectedNew = selectInitPlacement(
    await inspectInitSetup(
      { ...options, candidatePaths: [], placement: "external" },
      capabilities,
    ),
    { placement: "external" },
  );
  const prefix = createHash("sha256")
    .update(options.projectPath)
    .digest("hex")
    .slice(0, 12);
  assert.equal(selectedNew.rootPath, `/work/.agent-runner-project-${prefix}`);
  let number = 0;
  const load = capabilities.loadProjectConfiguration;
  capabilities.loadProjectConfiguration = async () => {
    const value = await load();
    value.protection.identity = String(number++);
    return value;
  };
  await assert.rejects(
    inspectInitSetup(options, capabilities),
    /changed during inspection/u,
  );
  assert.throws(
    () =>
      initPipeline.resolveWorkspace({
        projectPath: options.projectPath,
        taskPath: options.projectPath,
      }),
    /external task/u,
  );
});

test("new external destinations retain absence and ancestor bindings through inspection", async (t) => {
  for (const change of [
    "none",
    "ancestor task",
    "occupied before inspection",
    "occupied before snapshot",
    "ancestor replacement",
  ]) {
    await t.test(change, async (t) => {
      const root = await mkdtemp(
        join(tmpdir(), "agent-runner-init-inspection-"),
      );
      t.after(() => rm(root, { recursive: true, force: true }));
      const parent = join(root, "projects");
      const projectPath = join(parent, "project");
      const taskPath = change === "ancestor task" ? parent : join(root, "task");
      await mkdir(projectPath, { recursive: true });
      await mkdir(taskPath, { recursive: true });
      const workspace = createWorkspaceService();
      let externalRoot;
      const capabilities = {
        workspace: {
          ...workspace,
          async inspectPath(request) {
            const binding = await workspace.inspectPath(request);
            assert.equal(binding.exists, false);
            externalRoot = request.path;
            return binding;
          },
          async inspect(request) {
            assert.deepEqual(request.infrastructurePaths, [externalRoot]);
            if (change === "ancestor replacement") {
              await rename(parent, join(root, "original-projects"));
              await mkdir(projectPath, { recursive: true });
            }
            async function occupy() {
              await mkdir(externalRoot);
              await writeFile(
                join(externalRoot, "unrelated.txt"),
                "Preserve this content.\n",
              );
            }
            if (change === "occupied before inspection") await occupy();
            const inspection = await workspace.inspect(request);
            if (change === "occupied before snapshot") await occupy();
            return inspection;
          },
        },
      };
      const result = inspectInitSetup(
        {
          projectPath,
          taskPath,
          stateRoot: join(root, "state"),
          artifactRoot: "artifacts",
          placement: "external",
          documents: { instructions: [], checks: [], skills: [], guidance: [] },
        },
        capabilities,
      );
      if (["none", "ancestor task"].includes(change)) {
        assert.equal(
          selectInitPlacement(await result, { placement: "external" }).rootPath,
          externalRoot,
        );
      } else {
        await assert.rejects(result, { code: "ERR_INIT_INSPECTION" });
      }
    });
  }
});

test("inspection ignores an unusable unselected default sibling", async () => {
  for (const [existing, placement] of [
    [null, null],
    [null, "integrated"],
    [candidate(), "external"],
  ]) {
    const options = {
      projectPath: "/work/project",
      taskPath: "/state/task",
      stateRoot: "/state/runs",
      artifactRoot: "artifacts",
      placement,
      configurationPath: existing?.configurationPath ?? null,
      candidatePaths: existing === null ? [] : [existing.configurationPath],
      documents: { instructions: [], checks: [], skills: [], guidance: [] },
    };
    const capabilities = {
      loadProjectConfiguration: async () => ({
        path: existing.configurationPath,
        infrastructure: existing,
        artifactPath: existing.artifactPath,
        protection: { projectPath: options.projectPath },
      }),
      inspectConfigurationPath: () => {},
      workspace: {
        ...createWorkspaceService(),
        inspectPath: async () => {
          throw Object.assign(
            new Error("Unselected sibling is a symbolic link."),
            { code: "ERR_WORKSPACE_PATH" },
          );
        },
        inspect: async (request) => {
          assert.deepEqual(
            request.infrastructurePaths,
            existing === null ? [] : [existing.rootPath],
          );
          return {
            controlPaths: [],
            bindings: [
              request.workspacePath,
              request.taskPath,
              ...request.infrastructurePaths,
            ].map((path) => ({ path })),
          };
        },
        snapshot: async () => ({
          schemaVersion: 1,
          workspacePath: options.projectPath,
          outputPaths: [],
          entries: [
            options.projectPath,
            options.taskPath,
            ...(existing ? [existing.rootPath] : []),
          ].map((path) => ({ path, kind: "directory", hash: null })),
          linkResolutions: [],
        }),
        assertUnchanged: ({ before, after }) => assert.deepEqual(before, after),
      },
    };
    const result = await inspectInitSetup(options, capabilities);
    assert.equal(
      selectInitPlacement(result, options).rootPath,
      existing?.rootPath ?? options.projectPath,
    );
    if (existing === null && placement === "integrated")
      await assert.rejects(
        inspectInitSetup({ ...options, placement: "external" }, capabilities),
        { code: "ERR_WORKSPACE_PATH" },
      );
  }
});

test("additive inspection retains prior destinations and rejects input or ancestor identity replacement", async () => {
  const options = {
    projectPath: "/work/project",
    taskPath: "/state/task",
    stateRoot: "/state/runs",
    artifactRoot: "artifacts",
    placement: "external",
    documents: {
      instructions: [],
      checks: [],
      skills: [],
      guidance: [],
    },
  };
  let inputIdentity = "original";
  let ancestorIdentity = "original";
  const capabilities = {
    workspace: {
      ...createWorkspaceService(),
      inspectPath: async ({ path }) => ({
        path,
        exists: false,
        ancestors: [{ path: "/", identity: ancestorIdentity }],
      }),
      inspect: async (request) => ({
        controlPaths: [],
        bindings: [
          request.workspacePath,
          request.taskPath,
          ...request.configurationPaths,
          ...request.infrastructurePaths,
        ].map((path) => ({
          path,
          exists: false,
          ancestors: [{ path: "/", identity: ancestorIdentity }],
        })),
      }),
      snapshot: async ({ inspection }) => ({
        schemaVersion: 1,
        workspacePath: options.projectPath,
        outputPaths: [],
        entries: [
          {
            path: "/state/task/task.md",
            kind: "file",
            hash: HASH,
            identity: inputIdentity,
          },
          ...inspection.bindings
            .filter((binding) => !binding.exists)
            .map(({ path }) => ({ path, kind: "missing", hash: null })),
        ],
        linkResolutions: [],
      }),
      assertUnchanged: ({ before, after }) => assert.deepEqual(before, after),
    },
  };
  const original = await inspectInitSetup(options, capabilities);
  const integrated = await inspectInitSetup(
    { ...options, placement: "integrated", previousInspection: original },
    capabilities,
  );
  assert.deepEqual(integrated.roots, original.roots);
  assert.deepEqual(integrated.scopeBindings, original.scopeBindings);
  assert.equal(
    selectInitPlacement(integrated, { placement: "integrated" }).rootPath,
    options.projectPath,
  );
  // Reinspect a new destination while retaining the original input scope.
  const baseline = await inspectInitSetup(
    { ...options, placement: "integrated" },
    capabilities,
  );
  const extended = await inspectInitSetup(
    { ...options, previousInspection: baseline },
    capabilities,
  );
  assert.ok(extended.scopeBindings.length > baseline.scopeBindings.length);
  inputIdentity = "replacement";
  await assert.rejects(
    inspectInitSetup(
      { ...options, previousInspection: baseline },
      capabilities,
    ),
    /changed/u,
  );
  inputIdentity = "original";
  ancestorIdentity = "replacement";
  await assert.rejects(
    inspectInitSetup(
      { ...options, previousInspection: baseline },
      capabilities,
    ),
    /changed/u,
  );
});

test("every post-clarification proposal gate supports only structured exceptional product decisions", () => {
  const setup = inspection();
  const decision = {
    status: "PRODUCT_DECISION_REQUIRED",
    question: "Which conflicting acceptance requirement should apply?",
    options: ["Keep the original check", "Use the requested replacement"],
    whyBlocked: "The supplied acceptance requirements conflict.",
    evidence: [
      "The task and agreed criteria specify incompatible acceptance commands.",
    ],
  };
  let state = start("combined", setup);
  for (const phase of ["PROPOSE", "CHECK_AND_FIX", "CLEAN_CONFIRM", "REVIEW"]) {
    assert.equal(state.workflowState, phase);
    const proposalTurn = ["PROPOSE", "CHECK_AND_FIX"].includes(phase);
    const output = {
      ...decision,
      ...(proposalTurn
        ? { summary: "", checks: [], resources: [] }
        : { proposalHash: "", findings: [] }),
    };
    const waiting = turn(state, setup, output);
    assert.equal(waiting.workflowState, "WAITING_FOR_USER");
    assert.equal(waiting.pauseReason, "product_decision_required");
    assert.deepEqual(waiting.selection, state.selection);
    assert.equal(waiting.proposal, null);
    assert.equal(waiting.primaryApproval, null);
    assert.equal(waiting.reviewApproval, null);
    assert.equal(waiting.revisionRounds, 0);
    assert.throws(
      () => turn(state, setup, { ...output, evidence: [] }),
      /material question/u,
    );
    assert.throws(
      () =>
        turn(state, setup, {
          ...output,
          ...(proposalTurn
            ? { checks: ["node --test"] }
            : { findings: ["A normal finding"] }),
        }),
      /cannot also carry/u,
    );
    state = turn(state, setup, proposalTurn ? proposal : clean);
  }
});
