import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  realpath,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { promisify } from "node:util";
import { createClarificationService } from "../../../../src/clarifications/index.js";
import { createGitService } from "../../../../src/git/index.js";
import { createRunStore } from "../../../../src/state/index.js";
import {
  createPolishingState,
  migratePolishingStateV1,
  migratePolishingStateV2,
  migratePolishingStateV3,
  migratePolishingStateV4,
  migratePolishingStateV5,
  migratePolishingStateV6,
  migratePolishingStateV7,
  migratePolishingStateV8,
  migratePolishingStateV9,
  runPolishing,
} from "../../src/index.js";
import {
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CANDIDATE_REVIEW_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  FINALIZATION_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  REVIEW_SCHEMA,
} from "../../src/schemas.js";
import { assertRun, MAX_BOOTSTRAP_ITEMS } from "../../src/workflow-contract.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "source-session";
const SETTINGS = Object.freeze({
  finalization: "auto",
  maxFixRounds: 5,
  maxDisputesPerFinding: 2,
  maxSameFindingRounds: 3,
  mode: "independent",
  stagnationWindowRounds: 3,
  trustedChecks: Object.freeze([]),
});
const REQUIRED_CHECKS = Object.freeze([
  Object.freeze({ id: "C1", command: "npm test" }),
]);
const VALIDATION_INFRASTRUCTURE = Object.freeze([
  ".agents/skills/finalization/SKILL.md",
]);

function checkResults(status, evidence = "The fixture check completed.") {
  return REQUIRED_CHECKS.map(({ id, command }) => ({
    checkId: id,
    command,
    status,
    evidence: [evidence],
  }));
}

function versionOneState(state) {
  const legacy = { ...state };
  for (const field of [
    "workerValidation",
    "reviewerValidation",
    "requiredChecks",
    "validationInfrastructure",
    "validationInfrastructureFingerprint",
    "validationMigrationPending",
    "reviewResult",
    "bootstrapCorrections",
    "pendingBootstrapCorrection",
    "finalizationCorrection",
    "pendingFinalizationCorrection",
    "lazyCorrections",
    "pendingLazyCorrection",
    "trustedValidation",
    "cleanConfirmationFingerprint",
    "lazySourceForkConsumed",
  ]) {
    delete legacy[field];
  }
  if (legacy.settings !== null) {
    const {
      mode: _mode,
      trustedChecks: _trustedChecks,
      ...settings
    } = legacy.settings;
    legacy.settings = settings;
  }
  return legacy;
}

function versionTwoState(state) {
  const legacy = { ...state };
  delete legacy.trustedValidation;
  if (legacy.settings !== null) {
    const { trustedChecks: _trustedChecks, ...settings } = legacy.settings;
    legacy.settings = settings;
  }
  if (legacy.finalizationResult !== null) {
    const {
      trustedCommandFingerprint: _trustedCommandFingerprint,
      trustedConfigurationFingerprint: _trustedConfigurationFingerprint,
      ...finalizationResult
    } = legacy.finalizationResult;
    legacy.finalizationResult = {
      ...finalizationResult,
      checks: finalizationResult.checks.map(
        ({
          executor: _executor,
          commandIdentity: _commandIdentity,
          exitCode: _exitCode,
          signal: _signal,
          timedOut: _timedOut,
          ...check
        }) => check,
      ),
    };
  }
  return legacy;
}

function versionSevenState(state) {
  const {
    cleanConfirmationFingerprint: _confirmation,
    lazySourceForkConsumed: _sourceFork,
    ...legacy
  } = state;
  if (legacy.settings !== null) {
    const { mode: _mode, ...settings } = legacy.settings;
    legacy.settings = settings;
  }
  return legacy;
}

function versionEightState(state) {
  const legacy = { ...state };
  delete legacy.lazyCorrections;
  delete legacy.pendingLazyCorrection;
  return legacy;
}

function versionNineState(state) {
  const legacy = { ...state };
  for (const field of [
    "reviewCorrection",
    "pendingReviewCorrection",
    "confirmationCorrection",
    "pendingConfirmationCorrection",
    "candidateReviewResult",
    "candidateReviewedFingerprint",
    "candidateConfirmationFingerprint",
    "candidateMigrationPending",
  ]) {
    delete legacy[field];
  }
  return legacy;
}

function versionThreeState(state) {
  const legacy = { ...state };
  delete legacy.bootstrapCorrections;
  delete legacy.pendingBootstrapCorrection;
  delete legacy.validationMigrationDisagreement;
  return legacy;
}

function versionTwoFailedFinalizationState(
  state,
  { incompleteStatus, workflowState },
) {
  const requiredChecks = Object.freeze([
    ...REQUIRED_CHECKS,
    Object.freeze({ id: "C2", command: "npm run service:test" }),
  ]);
  const finalizationResult = {
    ...state.finalizationResult,
    status: "FAIL",
    summary: "Legacy finalization retained incomplete validation evidence.",
    issues: [
      {
        id: "F1",
        command: "npm test",
        problem: "A required validation check did not pass.",
        evidence: ["The legacy validation gate remained incomplete."],
      },
    ],
    requiredChecks,
    checks: [
      {
        ...state.finalizationResult.checks[0],
        status: "FAIL",
        evidence: ["The legacy check failed."],
      },
      {
        checkId: "C2",
        command: "npm run service:test",
        status: incompleteStatus,
        evidence: ["The legacy check did not complete."],
        executor: "agent",
        commandIdentity: null,
        exitCode: null,
        signal: null,
        timedOut: false,
      },
    ],
    validationChanged: false,
  };
  return versionTwoState({
    ...state,
    workflowState,
    workerValidation: {
      ...state.workerValidation,
      requiredChecks,
    },
    reviewerValidation: {
      ...state.reviewerValidation,
      requiredChecks,
    },
    requiredChecks,
    finalizationResult,
    finalizedFingerprint: null,
    reviewResult: null,
    reviewedFingerprint: null,
    findings: [],
  });
}

function migrateVersionOneState(state) {
  const versionTwo = migratePolishingStateV1({ pipelineState: state });
  const versionThree = migratePolishingStateV2({ pipelineState: versionTwo });
  const versionFour = migratePolishingStateV3({ pipelineState: versionThree });
  const versionFive = migratePolishingStateV4({ pipelineState: versionFour });
  const versionSix = migratePolishingStateV5({ pipelineState: versionFive });
  const versionSeven = migratePolishingStateV6({ pipelineState: versionSix });
  const versionEight = migratePolishingStateV7({ pipelineState: versionSeven });
  const versionNine = migratePolishingStateV8({
    pipelineState: versionEight,
  });
  return migratePolishingStateV9({ pipelineState: versionNine });
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function trustedValidationSnapshot(
  alias = "service-check",
  command = "npm run test:service",
) {
  const vector = {
    alias,
    command,
    executable: "npm",
    arguments: ["run", "test:service"],
  };
  const identity = hash(JSON.stringify(vector));
  const commands = [{ ...vector, identity }];
  return Object.freeze({
    schemaVersion: 1,
    commands: Object.freeze(commands.map(Object.freeze)),
    commandFingerprint: hash(JSON.stringify([identity])),
    configurationFingerprint: hash(
      JSON.stringify({ schemaVersion: 1, commands: [vector] }),
    ),
  });
}

function emptyDecision() {
  return { question: "", options: [], whyBlocked: "", evidence: [] };
}

function clarificationReady() {
  return {
    status: "READY",
    questions: [],
    reason: "",
    ...emptyDecision(),
  };
}

function clarificationQuestions() {
  return {
    status: "QUESTIONS",
    questions: [
      {
        question: "Which public behavior should the existing changes preserve?",
        whyItMatters:
          "The answer changes how the dirty implementation is polished.",
      },
    ],
    reason: "",
    ...emptyDecision(),
  };
}

function bootstrapReady(role) {
  return {
    status: "READY",
    summary: `${role} independently understands the dirty change set and finalization procedure.`,
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    capacityField: "",
    capacityLimit: 0,
    reason: "",
    ...emptyDecision(),
  };
}

function bootstrapCapacityExhausted(capacityField) {
  return {
    status: "CAPACITY_EXHAUSTED",
    summary: "",
    requiredChecks: [],
    validationInfrastructure: [],
    capacityField,
    capacityLimit: MAX_BOOTSTRAP_ITEMS,
    reason: "",
    ...emptyDecision(),
  };
}

function reconciliationResolved() {
  return {
    status: "RESOLVED",
    summary:
      "Polish the existing change set within the established repository boundaries.",
    disagreement: "",
    reason: "",
    ...emptyDecision(),
  };
}

function reconciliationDisagreement() {
  return {
    status: "DISAGREEMENT",
    summary: "",
    disagreement: "The roles selected different owning modules.",
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The summaries identify different existing boundaries."],
  };
}

function arbitrationResolved() {
  return {
    direction: "SYNTHESIZE",
    summary:
      "Use the existing narrow module boundary and preserve the public behavior.",
    rationale:
      "Repository ownership and tests support the combined interpretation.",
    reason: "",
    ...emptyDecision(),
  };
}

function polishingCompleted() {
  return {
    status: "COMPLETED",
    summary:
      "Polished the existing changes and completed a concise self-review.",
    reason: "",
    ...emptyDecision(),
  };
}

function checkAndFix(status = "UNCHANGED") {
  return {
    status,
    summary:
      status === "CHANGED"
        ? "Fixed the complete change set."
        : "The complete change set is clean.",
    reason: "",
    ...emptyDecision(),
  };
}

function candidateApproved() {
  return {
    status: "APPROVED",
    findings: [],
    ...emptyDecision(),
  };
}

function candidateClean() {
  return {
    status: "CLEAN",
    findings: [],
    ...emptyDecision(),
  };
}

function candidateFindings(...ids) {
  const {
    validationChange: _change,
    validationEvidence: _evidence,
    ...result
  } = reviewFindingBatch(ids);
  return result;
}

function cleanConfirmation(validationChange = "UNCHANGED") {
  return {
    status: "CLEAN",
    findings: [],
    validationChange,
    validationEvidence:
      validationChange === "UNCHANGED"
        ? []
        : ["The task authorizes the complete validation change."],
    ...emptyDecision(),
  };
}

function cleanConfirmationFindings(...ids) {
  return {
    ...reviewFindingBatch(ids),
    status: "FINDINGS",
  };
}

function polishingBlocked() {
  return {
    status: "BLOCKED",
    summary: "",
    reason: "The required local compiler is temporarily unavailable.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [
      "The compiler executable returned a transient availability error.",
    ],
  };
}

function environmentBlocked(reason, evidence) {
  return {
    status: "BLOCKED",
    decisions: [],
    reason,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [evidence],
  };
}

function finalizationPassed(
  skillPath = ".agents/skills/finalization/SKILL.md",
) {
  return {
    status: "PASS",
    skillPath,
    summary: "The complete project validation procedure passed.",
    issues: [],
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    checks: checkResults("PASS"),
    reason: "",
    ...emptyDecision(),
  };
}

function reviewApproved(validationChange = "UNCHANGED") {
  return {
    status: "APPROVED",
    findings: [],
    validationChange,
    validationEvidence:
      validationChange === "UNCHANGED"
        ? []
        : ["The task authorizes the complete validation change."],
    ...emptyDecision(),
  };
}

function finalizationFailed(id = "F1") {
  return {
    status: "FAIL",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "The validation procedure found a scoped failure.",
    issues: [
      {
        id,
        command: "npm test",
        problem: "A scoped validation failed.",
        evidence: ["The fixture check failed."],
      },
    ],
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    checks: checkResults("FAIL", "The fixture check failed."),
    reason: "",
    ...emptyDecision(),
  };
}

function finalizationUnavailable(status) {
  return {
    status,
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "",
    issues: [],
    requiredChecks: [],
    validationInfrastructure: [],
    checks: [],
    reason: "The finalization skill cannot be used safely.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The repository instructions do not provide a valid procedure."],
  };
}

function finalizationBlocked(reason, evidence) {
  return {
    status: "BLOCKED",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "",
    issues: [],
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    checks: checkResults("BLOCKED", evidence),
    reason,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [evidence],
  };
}

function invalidProductionFinalization() {
  const requiredChecks = [
    REQUIRED_CHECKS[0],
    { id: "C2", command: "git diff --check HEAD" },
    { id: "C3", command: "git status" },
  ];
  return {
    status: "BLOCKED",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "",
    issues: [],
    requiredChecks,
    validationInfrastructure: [
      ...VALIDATION_INFRASTRUCTURE,
      "DO_NOT_PERSIST_REJECTED_PATH",
    ],
    checks: requiredChecks.map(({ id, command }, index) => ({
      checkId: id,
      command,
      status: index === 2 ? "BLOCKED" : "PASS",
      evidence: ["DO_NOT_PERSIST_REJECTED_PROVIDER_TEXT"],
    })),
    reason: "DO_NOT_PERSIST_REJECTED_BLOCKER",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["DO_NOT_PERSIST_REJECTED_EVIDENCE"],
  };
}

function reviewFindings(id = "R1") {
  return reviewFindingBatch([id]);
}

function reviewFindingBatch(ids) {
  return {
    status: "FINDINGS",
    findings: ids.map((id) => ({
      id,
      file: "tracked.txt",
      problem: `The dirty change is not minimal for ${id}.`,
      reason: "An unnecessary line remains.",
      suggestedAction: "Remove the unnecessary line.",
    })),
    validationChange: "UNCHANGED",
    validationEvidence: [],
    ...emptyDecision(),
  };
}

function resolution(decision, id = decision === "FIX" ? "F1" : "R1") {
  return resolutionBatch([{ id, decision }]);
}

function resolutionBatch(decisions) {
  return {
    status: "RESOLVED",
    decisions: decisions.map(({ id, decision }) => ({
      id,
      decision,
      reason:
        decision === "FIX"
          ? "Applied the minimal scoped correction."
          : "Repository evidence shows the finding is incorrect.",
      evidence:
        decision === "DISPUTE"
          ? ["The current test covers the reported behavior."]
          : [],
    })),
    reason: "",
    ...emptyDecision(),
  };
}

function verboseResolutionBatch(ids) {
  const detail = "worker-evidence".repeat(125);
  return {
    status: "RESOLVED",
    decisions: ids.map((id) => ({
      id,
      decision: "DISPUTE",
      reason: detail,
      evidence: [detail, detail],
    })),
    reason: "",
    ...emptyDecision(),
  };
}

function reconsiderationBatch(direction, ids) {
  return {
    status: "RESOLVED",
    decisions: ids.map((id) => ({
      id,
      direction,
      reason:
        direction === "WITHDRAW"
          ? "The Worker evidence resolves the concern."
          : "The current repository evidence still supports the finding.",
      evidence: [],
    })),
    ...emptyDecision(),
  };
}

function verboseReconsiderationBatch(ids) {
  const detail = "reviewer-evidence".repeat(110);
  return {
    status: "RESOLVED",
    decisions: ids.map((id) => ({
      id,
      direction: "UPHOLD",
      reason: detail,
      evidence: [detail, detail],
    })),
    ...emptyDecision(),
  };
}

function reconsideration(direction = "WITHDRAW", id = "R1") {
  return reconsiderationBatch(direction, [id]);
}

function findingArbitration(direction = "WORKER_CORRECT") {
  return {
    direction,
    rationale: "The recorded repository evidence determines the finding.",
    ...emptyDecision(),
  };
}

function stagnationDirection(direction = "CONTINUE_FIXES") {
  return {
    direction,
    rationale: "The loop is progressing and one more focused fix is warranted.",
    findingIds: [],
    ...emptyDecision(),
  };
}

function productDecision(statusShape) {
  return {
    ...statusShape,
    question: "Should the polished behavior use variant A or variant B?",
    options: ["Variant A", "Variant B"],
    whyBlocked: "The task and repository leave both product behaviors valid.",
    evidence: ["No existing test or convention chooses between the variants."],
  };
}

function capabilities() {
  return {
    version: "fake-1.0.0",
    structuredOutput: true,
    readOnly: true,
    autonomousWrite: true,
    gitMetadataWriteBlocked: true,
    workspaceWrite: true,
    localCommit: true,
    remoteWriteBlocked: true,
    nativeSessionContinuation: true,
    nativeSessionFork: true,
  };
}

async function runGit(repositoryPath, ...argumentsList) {
  return executeFile("git", ["-C", repositoryPath, ...argumentsList]);
}

async function optionalInput(path) {
  try {
    const content = await readFile(path, "utf8");
    return { path, content, hash: hash(content) };
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return null;
    }
    throw cause;
  }
}

async function repositoryFingerprint(root, ignoredRoots = ["LOCAL_ARTIFACTS"]) {
  const entries = [];

  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.name === ".git") {
        continue;
      }
      const path = join(directory, entry.name);
      const pathFromRoot = relative(root, path);
      if (
        ignoredRoots.some(
          (ignoredRoot) =>
            pathFromRoot === ignoredRoot ||
            pathFromRoot.startsWith(`${ignoredRoot}/`),
        )
      ) {
        continue;
      }
      if (entry.isDirectory()) {
        await visit(path);
      } else if (entry.isSymbolicLink()) {
        entries.push([pathFromRoot, hash(await readlink(path))]);
      } else {
        entries.push([pathFromRoot, hash(await readFile(path))]);
      }
    }
  }

  await visit(root);
  entries.sort(([left], [right]) => left.localeCompare(right));
  return hash(JSON.stringify(entries));
}

async function canonicalPotentialPath(path) {
  const missing = [];
  let current = resolve(path);
  while (true) {
    try {
      return resolve(await realpath(current), ...missing.reverse());
    } catch (cause) {
      if (cause?.code !== "ENOENT") {
        throw cause;
      }
      missing.push(basename(current));
      const parent = dirname(current);
      if (parent === current) {
        throw cause;
      }
      current = parent;
    }
  }
}

function memoryGitError(message, code, changes) {
  const error = new Error(message);
  error.code = code;
  if (changes !== undefined) {
    error.changes = changes;
  }
  return error;
}

async function createFixture(
  t,
  {
    artifactRoot = "LOCAL_ARTIFACTS",
    dirty = true,
    finalizationSkill = true,
    ignoreArtifacts = true,
    interactive = false,
    mode = "independent",
    modeSettings = {},
    onEdit,
    onRoleRun,
    onTrustedValidation,
    prepareProject,
    proactiveClarification = false,
    repository = "memory",
    reviewer = [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      reviewApproved(),
    ],
    roleBackends = {
      worker: "codex",
      reviewer: "codex",
      arbiter: "codex",
    },
    sessionIdForRole,
    settings = SETTINGS,
    sourceSession = null,
    stateStore = "memory",
    taskLocation = "external",
    trustedValidation,
    worker = [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
    arbiter = [],
  } = {},
) {
  settings = Object.freeze({ ...settings, ...modeSettings, mode });
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-polishing-"));
  const projectPath = join(workspace, "project");
  const externalTaskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await mkdir(projectPath, { recursive: true });
  if (repository === "git") {
    await runGit(projectPath, "init", "-q");
    await runGit(projectPath, "config", "user.name", "Polishing Test");
    await runGit(projectPath, "config", "user.email", "polishing@example.test");
  }
  await writeFile(
    join(projectPath, ".gitignore"),
    `${ignoreArtifacts ? `${artifactRoot}/\n` : ""}ignored-task/\n`,
  );
  await writeFile(join(projectPath, "tracked.txt"), "base\n");
  await writeFile(join(projectPath, "deleted.txt"), "delete me\n");
  if (finalizationSkill) {
    await mkdir(join(projectPath, ".agents", "skills", "finalization"), {
      recursive: true,
    });
    await writeFile(
      join(projectPath, ".agents", "skills", "finalization", "SKILL.md"),
      "---\nname: finalization\ndescription: Test validation.\n---\n\nRun tests.\n",
    );
  }
  await prepareProject?.(projectPath);

  const taskPath =
    taskLocation === "external" || taskLocation === "symlinked-untracked"
      ? externalTaskPath
      : taskLocation === "ignored"
        ? join(projectPath, "ignored-task")
        : join(projectPath, "task");
  if (taskLocation === "symlinked-untracked") {
    const repositoryTaskPath = join(projectPath, "task");
    await mkdir(repositoryTaskPath, { recursive: true });
    await symlink(repositoryTaskPath, taskPath, "dir");
  } else {
    await mkdir(taskPath, { recursive: true });
  }
  await writeFile(join(taskPath, "task.md"), "# Polish fixture\n");
  if (repository === "git") {
    if (taskLocation === "tracked" || taskLocation === "dirty-tracked") {
      await runGit(
        projectPath,
        "add",
        ".gitignore",
        "deleted.txt",
        "tracked.txt",
        "task/task.md",
      );
    } else {
      await runGit(
        projectPath,
        "add",
        ".gitignore",
        "deleted.txt",
        "tracked.txt",
      );
    }
    if (finalizationSkill) {
      await runGit(projectPath, "add", ".agents/skills/finalization/SKILL.md");
    }
    await runGit(projectPath, "commit", "-qm", "initialize fixture");
  }
  const committedContentFingerprint = await repositoryFingerprint(projectPath, [
    artifactRoot,
  ]);
  if (taskLocation === "dirty-tracked") {
    await appendFile(join(taskPath, "task.md"), "Changed input.\n");
  }
  if (dirty) {
    await writeFile(join(projectPath, "change.txt"), "dirty change\n");
  }
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const queues = {
    worker: [...worker],
    reviewer:
      mode === "lazy"
        ? [...reviewer]
        : [...reviewer, reviewApproved(), reviewApproved()],
    arbiter: [...arbiter],
  };
  const calls = { worker: [], reviewer: [], arbiter: [] };
  const probes = { worker: 0, reviewer: 0, arbiter: 0 };
  const transitions = [];
  const artifacts = new Map();
  const memoryRepository = {
    branch: "refs/heads/main",
    handoffComplete: false,
    head: hash("polishing-fixture-head"),
    identityFingerprint: hash("polishing-fixture-identity"),
    indexFingerprint: hash("polishing-fixture-index"),
    refsFingerprint: hash("polishing-fixture-refs"),
    remoteConfigurationFingerprint: hash("polishing-fixture-remotes"),
  };
  const initialIndexFingerprint = memoryRepository.indexFingerprint;
  let sessionIndex = 0;
  let deferredFinalization = null;
  const deferredConfirmation = { worker: null, reviewer: null };
  const isFinalizationResult = (result) =>
    ["PASS", "FAIL", "SKILL_MISSING", "SKILL_INVALID", "BLOCKED"].includes(
      result?.status,
    ) && Object.hasOwn(result, "requiredChecks");
  const isTerminalReview = (result) =>
    Object.hasOwn(result ?? {}, "validationChange");
  function candidateResult(result, acceptedStatus) {
    const {
      validationChange: _validationChange,
      validationEvidence: _validationEvidence,
      ...candidate
    } = result;
    return {
      ...candidate,
      status:
        acceptedStatus === "CLEAN" && candidate.status === "APPROVED"
          ? "CLEAN"
          : candidate.status,
    };
  }
  const adapters = Object.fromEntries(
    Object.keys(queues).map((role) => [
      role,
      {
        async probe() {
          probes[role] += 1;
          return capabilities();
        },
        async run(request) {
          calls[role].push(request);
          assert.match(request.prompt, /Do not delegate/u);
          assert.match(request.recoveryPrompt, /Do not delegate/u);
          await onRoleRun?.(role, request, calls[role].length, { projectPath });
          if (
            role === "worker" &&
            [CHECK_AND_FIX_SCHEMA, FINDING_RESOLUTION_SCHEMA].includes(
              request.schema,
            ) &&
            isFinalizationResult(queues.worker[0])
          ) {
            deferredFinalization = queues.worker.shift();
          }
          let structured;
          if (
            role === "worker" &&
            request.schema === CHECK_AND_FIX_SCHEMA &&
            !["CHANGED", "UNCHANGED", "BLOCKED", "INVALID"].includes(
              queues.worker[0]?.status,
            )
          ) {
            structured = checkAndFix();
          } else if (
            role === "worker" &&
            request.schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA &&
            isTerminalReview(queues.worker[0])
          ) {
            const terminal = queues.worker.shift();
            if (terminal.status === "CLEAN") {
              deferredConfirmation.worker = terminal;
            }
            structured = candidateResult(terminal, "CLEAN");
          } else if (
            role === "reviewer" &&
            request.schema === CANDIDATE_REVIEW_SCHEMA &&
            isTerminalReview(queues.reviewer[0])
          ) {
            const terminal = queues.reviewer.shift();
            if (terminal.status === "APPROVED") {
              deferredConfirmation.reviewer = terminal;
            }
            structured = candidateResult(terminal, "APPROVED");
          } else if (
            role === "worker" &&
            request.schema === FINALIZATION_SCHEMA &&
            deferredFinalization !== null
          ) {
            if (isFinalizationResult(queues.worker[0])) {
              deferredFinalization = queues.worker.shift();
            }
            structured = deferredFinalization;
            deferredFinalization = null;
          } else if (
            request.schema === CLEAN_CONFIRM_SCHEMA &&
            deferredConfirmation.worker !== null
          ) {
            structured = deferredConfirmation.worker;
            deferredConfirmation.worker = null;
          } else if (
            request.schema === REVIEW_SCHEMA &&
            deferredConfirmation.reviewer !== null
          ) {
            structured = deferredConfirmation.reviewer;
            deferredConfirmation.reviewer = null;
          } else {
            assert.ok(queues[role].length > 0, `Unexpected ${role} turn.`);
            structured = queues[role].shift();
          }
          sessionIndex += 1;
          return {
            output: "structured",
            structured,
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : (sessionIdForRole?.(role, sessionIndex) ??
                  `${role}-session-${sessionIndex}`),
          };
        },
      },
    ]),
  );

  const roles = Object.fromEntries(
    (mode === "lazy" ? ["worker"] : ["worker", "reviewer", "arbiter"]).map(
      (role) => [role, { backend: roleBackends[role], model: `${role}-model` }],
    ),
  );
  const pipelineState = createPolishingState({
    artifactRoot,
    proactiveClarification,
    settings,
    ...(trustedValidation === undefined ? {} : { trustedValidation }),
  });
  let store;
  let lease;
  let directoryPath;
  let currentRun;
  if (stateStore === "disk") {
    store = createRunStore({ stateRoot });
    const created = await store.createRun({
      pipelineId: "polishing",
      pipelineStateVersion: 10,
      projectPath,
      taskPath,
      roles,
      sourceSession,
      pipelineState,
      activity: {
        actor: "runner",
        phase: "run",
        kind: "created",
        message: "Polishing test run created.",
      },
    });
    lease = created.lease;
    directoryPath = created.directoryPath;
    currentRun = created.state;
    t.after(() => lease?.release().catch(() => {}));
  } else {
    directoryPath = join(stateRoot, "run-1");
    currentRun = {
      revision: 1,
      runId: "run-1",
      pipelineId: "polishing",
      pipelineStateVersion: 10,
      projectPath,
      taskPath,
      roles,
      counters: {},
      hashes: {},
      pause: null,
      activeTurn: null,
      sessionLineage: { source: sourceSession, children: [] },
      pipelineState,
    };
  }

  async function memorySnapshot({ allowedPaths = [] } = {}) {
    const normalizedAllowedPaths = allowedPaths
      .map((path) => (isAbsolute(path) ? relative(projectPath, path) : path))
      .sort();
    const contentFingerprint = await repositoryFingerprint(projectPath, [
      artifactRoot,
      ...normalizedAllowedPaths,
    ]);
    const dirtyByConstruction =
      dirty ||
      ["dirty-tracked", "untracked", "symlinked-untracked"].includes(
        taskLocation,
      );
    return Object.freeze({
      schemaVersion: 1,
      projectPath,
      allowedPaths: normalizedAllowedPaths,
      head: memoryRepository.head,
      branch: memoryRepository.branch,
      detached: false,
      clean:
        !dirtyByConstruction &&
        contentFingerprint === committedContentFingerprint &&
        memoryRepository.indexFingerprint === initialIndexFingerprint,
      refsFingerprint: memoryRepository.refsFingerprint,
      trackedContentFingerprint: contentFingerprint,
      untrackedContentFingerprint: contentFingerprint,
      contentFingerprint,
      indexFingerprint: memoryRepository.indexFingerprint,
      remoteConfigurationFingerprint:
        memoryRepository.remoteConfigurationFingerprint,
      identityAvailable: true,
      identityFingerprint: memoryRepository.identityFingerprint,
    });
  }

  const snapshotControlFields = [
    ["head", "head"],
    ["branch", "branch"],
    ["detached", "detached-head"],
    ["refsFingerprint", "refs"],
    ["trackedContentFingerprint", "tracked-content"],
    ["untrackedContentFingerprint", "untracked-content"],
    ["indexFingerprint", "index"],
    ["remoteConfigurationFingerprint", "remote-configuration"],
    ["identityFingerprint", "identity"],
  ];
  const memoryGit = {
    async assertUnchanged(previous) {
      const current = await memorySnapshot({
        allowedPaths: previous.allowedPaths,
      });
      const changes = snapshotControlFields
        .filter(([field]) => previous[field] !== current[field])
        .map(([, name]) => name);
      if (changes.length > 0) {
        throw memoryGitError(
          "Read-only repository snapshot changed.",
          "ERR_READ_ONLY_REPOSITORY_CHANGED",
          changes,
        );
      }
      return current;
    },
    async contentFingerprint({ allowedPaths = [] } = {}) {
      return (
        await memorySnapshot({
          allowedPaths,
        })
      ).contentFingerprint;
    },
    async inspectPath({ path }) {
      const requestedPath = resolve(projectPath, path);
      const canonicalPath = await canonicalPotentialPath(requestedPath);
      const relativePath = relative(projectPath, canonicalPath)
        .split(sep)
        .join("/");
      if (
        canonicalPath !== requestedPath ||
        relativePath === ".." ||
        relativePath.startsWith("../") ||
        isAbsolute(relativePath)
      ) {
        throw memoryGitError(
          "Repository path escapes through a symlink.",
          "ERR_UNSAFE_REPOSITORY_PATH",
        );
      }
      let metadata;
      try {
        metadata = await lstat(canonicalPath);
      } catch (cause) {
        if (cause?.code !== "ENOENT") {
          throw cause;
        }
        metadata = null;
      }
      const taskRelative = relative(projectPath, taskPath).split(sep).join("/");
      return Object.freeze({
        path: canonicalPath,
        relativePath,
        changed:
          ["dirty-tracked", "untracked", "symlinked-untracked"].includes(
            taskLocation,
          ) &&
          (relativePath === taskRelative ||
            relativePath.startsWith(`${taskRelative}/`)),
        exists: metadata !== null,
        kind:
          metadata === null
            ? null
            : metadata.isFile()
              ? "file"
              : metadata.isDirectory()
                ? "directory"
                : "other",
        ignored: relativePath.startsWith("ignored-task/"),
        tracked: taskLocation === "tracked",
      });
    },
    async inspectPolishingHandoff(options) {
      const current = await memorySnapshot({
        allowedPaths: options.expectedSnapshot.allowedPaths,
      });
      const controlsChanged = [
        "projectPath",
        "head",
        "branch",
        "detached",
        "refsFingerprint",
        "remoteConfigurationFingerprint",
        "identityFingerprint",
      ].some((field) => current[field] !== options.expectedSnapshot[field]);
      if (
        controlsChanged ||
        current.contentFingerprint !== options.finalizedFingerprint
      ) {
        throw memoryGitError(
          "Repository controls or content changed before polishing handoff.",
          "ERR_POLISHING_HANDOFF_CONTAMINATED",
        );
      }
      if (memoryRepository.handoffComplete) {
        return Object.freeze({ status: "complete", snapshot: current });
      }
      if (
        current.indexFingerprint !== options.expectedSnapshot.indexFingerprint
      ) {
        throw memoryGitError(
          "Polishing handoff found an incomplete or contaminated index.",
          "ERR_POLISHING_HANDOFF_CONTAMINATED",
          ["index"],
        );
      }
      return Object.freeze({ status: "untouched", snapshot: current });
    },
    async preflight({ allowedPaths = [], requiredIgnoredPaths = [] }) {
      const ignoreLines = (
        await readFile(join(projectPath, ".gitignore"), "utf8")
      )
        .split(/\r?\n/u)
        .map((line) => line.replace(/^\//u, "").replace(/\/$/u, ""));
      for (const path of requiredIgnoredPaths) {
        const relativePath = relative(projectPath, path).split(sep).join("/");
        if (
          !ignoreLines.some(
            (ignored) =>
              ignored.length > 0 &&
              (relativePath === ignored ||
                relativePath.startsWith(`${ignored}/`)),
          )
        ) {
          throw memoryGitError(
            "Repository-local artifact path must be ignored.",
            "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED",
          );
        }
      }
      return Object.freeze({
        ignoredPaths: Object.freeze([]),
        snapshot: await memorySnapshot({ allowedPaths }),
      });
    },
    async reconcileInterrupted(
      previous,
      { allowWorkspaceChanges = false, allowIndexChanges = false } = {},
    ) {
      if (!allowWorkspaceChanges) {
        return this.assertUnchanged(previous);
      }
      const current = await memorySnapshot({
        allowedPaths: previous.allowedPaths,
      });
      const changes = [
        ["projectPath", "project-path"],
        ["head", "head"],
        ["branch", "branch"],
        ["detached", "detached-head"],
        ["refsFingerprint", "refs"],
        ["remoteConfigurationFingerprint", "remote-configuration"],
        ["identityFingerprint", "identity"],
      ]
        .filter(([field]) => previous[field] !== current[field])
        .map(([, name]) => name);
      if (
        !allowIndexChanges &&
        previous.indexFingerprint !== current.indexFingerprint
      ) {
        changes.push("index");
      }
      if (changes.length > 0) {
        throw memoryGitError(
          "Repository controls changed during an interrupted writable turn.",
          "ERR_INTERRUPTED_REPOSITORY_CONTROL_CHANGED",
          changes,
        );
      }
      return current;
    },
    snapshot: memorySnapshot,
    async stagePolishingHandoff(options) {
      const inspected = await this.inspectPolishingHandoff(options);
      if (inspected.status === "complete") {
        return inspected.snapshot;
      }
      memoryRepository.indexFingerprint = hash(
        `staged:${options.finalizedFingerprint}`,
      );
      memoryRepository.handoffComplete = true;
      return memorySnapshot({
        allowedPaths: options.expectedSnapshot.allowedPaths,
      });
    },
    async validationInfrastructureFingerprint({ paths }) {
      const entries = await Promise.all(
        paths.map(async (path) => {
          try {
            return [path, await readFile(join(projectPath, path), "utf8")];
          } catch (cause) {
            if (cause?.code === "ENOENT") {
              return [path, null];
            }
            throw cause;
          }
        }),
      );
      return hash(JSON.stringify(entries));
    },
  };
  const git = repository === "git" ? createGitService() : memoryGit;
  const clarifications = createClarificationService({
    env: { EDITOR: "fixture-editor" },
    interactive,
    launchEditor: async (_command, transcriptPath) =>
      onEdit?.({ transcriptPath }),
  });
  const runtime = {
    adapters,
    clarifications,
    git,
    trustedValidation: {
      async execute(options) {
        assert.notEqual(onTrustedValidation, undefined);
        return onTrustedValidation(options);
      },
    },
    async readInputs({ taskPath: requestedTaskPath }) {
      const task = await optionalInput(join(requestedTaskPath, "task.md"));
      if (task === null) {
        const error = new Error("task.md is missing.");
        error.code = "ENOENT";
        error.path = join(requestedTaskPath, "task.md");
        throw error;
      }
      return {
        task,
        taskClarifications: await optionalInput(
          join(requestedTaskPath, "clarifications.md"),
        ),
        context: await optionalInput(join(requestedTaskPath, "context.md")),
      };
    },
  };

  function installStoreRuntime() {
    if (stateStore === "disk") {
      runtime.transition = async (patch, options) => {
        transitions.push({ patch, options });
        currentRun = await store.transitionRun(lease, patch, options);
        return currentRun;
      };
      runtime.startAgentTurn = async (activeTurn, { pipelineState } = {}) => {
        currentRun = await store.startAgentTurn(lease, activeTurn, {
          activity: {
            actor: activeTurn.role,
            phase: activeTurn.phase,
            kind: "turn-started",
            message: `${activeTurn.role} ${activeTurn.phase} turn started.`,
          },
          ...(pipelineState === undefined ? {} : { pipelineState }),
        });
        return currentRun;
      };
      runtime.finishAgentTurn = async (activeTurn) => {
        currentRun = await store.finishAgentTurn(lease, activeTurn);
        return currentRun;
      };
      runtime.recordChildSession = async (child, options) => {
        currentRun = await store.recordChildSession(lease, child, options);
        return currentRun;
      };
      runtime.writeRunArtifact = ({ path, content }) =>
        store.writeRunArtifact(lease, path, content);
      return;
    }
    runtime.transition = async (patch, options) => {
      transitions.push({ patch, options });
      currentRun = {
        ...currentRun,
        ...patch,
        revision: currentRun.revision + 1,
      };
      return currentRun;
    };
    runtime.startAgentTurn = async (activeTurn, { pipelineState } = {}) => {
      currentRun = {
        ...currentRun,
        ...(pipelineState === undefined ? {} : { pipelineState }),
        activeTurn,
        revision: currentRun.revision + 1,
      };
      return currentRun;
    };
    runtime.finishAgentTurn = async (activeTurn) => {
      assert.deepEqual(currentRun.activeTurn, activeTurn);
      currentRun = {
        ...currentRun,
        activeTurn: null,
        revision: currentRun.revision + 1,
      };
      return currentRun;
    };
    runtime.recordChildSession = async (child, options) => {
      currentRun = {
        ...currentRun,
        revision: currentRun.revision + 1,
        sessionLineage: {
          ...currentRun.sessionLineage,
          children: [...currentRun.sessionLineage.children, child],
        },
      };
      return currentRun;
    };
    runtime.writeRunArtifact = async ({ path, content }) => {
      artifacts.set(path, content);
      return join(directoryPath, path);
    };
  }
  installStoreRuntime();

  async function run(action = null) {
    currentRun = await runPolishing({
      action,
      run: currentRun,
      runtime,
      settings,
    });
    return currentRun;
  }

  async function recover() {
    if (stateStore === "memory") {
      assertRun(currentRun);
      installStoreRuntime();
      return currentRun;
    }
    await lease.release();
    const reopened = createRunStore({ stateRoot });
    lease = await reopened.acquireRunLease(currentRun.runId);
    currentRun = await reopened.recoverRun(lease);
    runtime.transition = async (patch, options) => {
      transitions.push({ patch, options });
      currentRun = await reopened.transitionRun(lease, patch, options);
      return currentRun;
    };
    runtime.startAgentTurn = async (activeTurn, { pipelineState } = {}) => {
      currentRun = await reopened.startAgentTurn(lease, activeTurn, {
        activity: {
          actor: activeTurn.role,
          phase: activeTurn.phase,
          kind: "turn-started",
          message: `${activeTurn.role} ${activeTurn.phase} turn started.`,
        },
        ...(pipelineState === undefined ? {} : { pipelineState }),
      });
      return currentRun;
    };
    runtime.finishAgentTurn = async (activeTurn) => {
      currentRun = await reopened.finishAgentTurn(lease, activeTurn);
      return currentRun;
    };
    runtime.recordChildSession = async (child, options) => {
      currentRun = await reopened.recordChildSession(lease, child, options);
      return currentRun;
    };
    runtime.writeRunArtifact = ({ path, content }) =>
      reopened.writeRunArtifact(lease, path, content);
    return currentRun;
  }

  async function persistPipelineState(
    pipelineState,
    counters = currentRun.counters,
    pause = currentRun.pause,
  ) {
    currentRun = await runtime.transition(
      {
        counters,
        hashes: currentRun.hashes,
        pause,
        pipelineState,
      },
      {
        activity: {
          actor: "runner",
          phase: "test",
          kind: "persisted",
          message: "Persisted a recovery test state.",
        },
      },
    );
    return currentRun;
  }

  return {
    calls,
    get currentRun() {
      return currentRun;
    },
    directoryPath,
    probes,
    projectPath,
    persistPipelineState,
    recover,
    run,
    runtime,
    taskPath,
    transitions,
  };
}

async function createRealGitFixture(t, options = {}) {
  return createFixture(t, { ...options, repository: "git" });
}

async function createRealStoreFixture(t, options = {}) {
  return createFixture(t, { ...options, stateStore: "disk" });
}

async function createIntegrationFixture(t, options = {}) {
  return createFixture(t, {
    ...options,
    repository: "git",
    stateStore: "disk",
  });
}

export {
  SOURCE_SESSION,
  SETTINGS,
  REQUIRED_CHECKS,
  VALIDATION_INFRASTRUCTURE,
  arbitrationResolved,
  bootstrapCapacityExhausted,
  bootstrapReady,
  candidateApproved,
  candidateClean,
  candidateFindings,
  checkAndFix,
  checkResults,
  clarificationQuestions,
  clarificationReady,
  cleanConfirmation,
  cleanConfirmationFindings,
  createFixture,
  createIntegrationFixture,
  createRealGitFixture,
  createRealStoreFixture,
  environmentBlocked,
  finalizationBlocked,
  finalizationFailed,
  finalizationPassed,
  finalizationUnavailable,
  findingArbitration,
  hash,
  invalidProductionFinalization,
  migrateVersionOneState,
  polishingBlocked,
  polishingCompleted,
  productDecision,
  reconciliationDisagreement,
  reconciliationResolved,
  reconsideration,
  reconsiderationBatch,
  resolution,
  resolutionBatch,
  reviewApproved,
  reviewFindingBatch,
  reviewFindings,
  runGit,
  stagnationDirection,
  trustedValidationSnapshot,
  verboseReconsiderationBatch,
  verboseResolutionBatch,
  versionEightState,
  versionNineState,
  versionOneState,
  versionSevenState,
  versionThreeState,
  versionTwoFailedFinalizationState,
  versionTwoState,
};
