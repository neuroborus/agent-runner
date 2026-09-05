import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
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
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { promisify } from "node:util";

import {
  createPlanExecutionState,
  migratePlanExecutionStateV1,
  migratePlanExecutionStateV2,
  migratePlanExecutionStateV3,
  migratePlanExecutionStateV4,
  migratePlanExecutionStateV5,
  migratePlanExecutionStateV6,
  migratePlanExecutionStateV7,
  migratePlanExecutionStateV8,
  migratePlanExecutionStateV9,
  migratePlanExecutionStateV10,
  migratePlanExecutionStateV11,
  migratePlanExecutionStateV12,
  migratePlanExecutionStateV13,
  planExecutionPipeline,
  runPlanExecution,
} from "../../src/index.js";
import {
  BOOTSTRAP_ARBITRATION_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_SCHEMA,
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CANDIDATE_REVIEW_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  FINALIZATION_SCHEMA,
  REVIEW_SCHEMA,
} from "../../src/schemas.js";
import {
  assertRun,
  MAX_BOOTSTRAP_ITEMS,
  MAX_VALIDATION_ITEMS,
  normalizeBootstrapArbitration,
  normalizeBootstrapResult,
  normalizeCheckAndFixResult,
  normalizeCleanConfirmationResult,
  normalizeFinalizationResult,
  normalizePipelineState,
  normalizeReconciliationResult,
} from "../../src/workflow-contract.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
const ROLE_SESSIONS = Object.freeze({
  worker: "22222222-2222-4222-8222-222222222222",
  reviewer: "33333333-3333-4333-8333-333333333333",
  arbiter: "44444444-4444-4444-8444-444444444444",
});
const RESTARTED_ROLE_SESSIONS = Object.freeze({
  worker: "55555555-5555-4555-8555-555555555555",
  reviewer: "66666666-6666-4666-8666-666666666666",
});
const REBOOTSTRAPPED_WORKER_SESSION = "88888888-8888-4888-8888-888888888888";
const MISSING_BOOTSTRAP_RESPONSE = Symbol("missing-bootstrap-response");
const TERMINAL_CONFIRMATION = Symbol("terminal-confirmation");
const TERMINAL_LAZY_CONFIRMATION = Symbol("terminal-lazy-confirmation");
const PLAN = `## Commit 1: feat(test): add behavior

Implement the requested behavior.`;
const SETTINGS = Object.freeze({
  finalization: "auto",
  maxFixRoundsPerStep: 5,
  maxDisputesPerFinding: 2,
  maxSameFindingRounds: 3,
  mode: "independent",
  stagnationWindowRounds: 3,
  trustedChecks: Object.freeze([]),
});
const REQUIRED_CHECKS = Object.freeze([
  Object.freeze({ id: "C1", command: "npm test" }),
]);
const VALIDATION_INFRASTRUCTURE = Object.freeze(["package.json"]);
const WRAPPED_BOOTSTRAP_SCHEMAS = new Set([
  BOOTSTRAP_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_ARBITRATION_SCHEMA,
]);

function bootstrapCorrection(diagnostic) {
  return {
    attempt: 1,
    diagnostics: [diagnostic],
  };
}

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
    "finalizationCorrections",
    "pendingFinalizationCorrection",
    "reviewCorrection",
    "pendingReviewCorrection",
    "confirmationCorrection",
    "pendingConfirmationCorrection",
    "trustedValidation",
    "candidateReviewResult",
    "candidateReviewedFingerprint",
    "candidateConfirmationFingerprint",
    "candidateMigrationPending",
    "cleanConfirmationFingerprint",
    "lazySourceForkConsumed",
    "lazyCorrections",
    "pendingLazyCorrection",
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
  if (legacy.pendingCommit !== null) {
    legacy.pendingCommit = {
      status: legacy.pendingCommit.status,
      authorization: legacy.pendingCommit.authorization,
    };
  }
  return legacy;
}

function versionFourState(state) {
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

function versionThirteenState(state) {
  const legacy = { ...state };
  for (const field of [
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

function migrateVersionOneState(state) {
  const versionTwo = migratePlanExecutionStateV1({ pipelineState: state });
  const versionThree = migratePlanExecutionStateV2({
    pipelineState: versionTwo,
  });
  const versionFour = migratePlanExecutionStateV3({
    pipelineState: versionThree,
  });
  const versionFive = migratePlanExecutionStateV4({
    pipelineState: versionFour,
  });
  const versionSix = migratePlanExecutionStateV5({
    pipelineState: versionFive,
  });
  const versionSeven = migratePlanExecutionStateV6({
    pipelineState: versionSix,
  });
  const versionEight = migratePlanExecutionStateV7({
    pipelineState: versionSeven,
  });
  const versionNine = migratePlanExecutionStateV8({
    pipelineState: versionEight,
  });
  const versionTen = migratePlanExecutionStateV9({
    pipelineState: versionNine,
  });
  const versionEleven = migratePlanExecutionStateV10({
    pipelineState: versionTen,
  });
  const versionTwelve = migratePlanExecutionStateV11({
    pipelineState: versionEleven,
  });
  const versionThirteen = migratePlanExecutionStateV12({
    pipelineState: versionTwelve,
  });
  return migratePlanExecutionStateV13({ pipelineState: versionThirteen });
}

async function prepareValidationMigration(t, fixtureOptions) {
  const stop = new Error("captured active legacy state");
  let legacy;
  const fixture = await createFixture(t, {
    ...fixtureOptions,
    onTransition(run) {
      if (
        legacy === undefined &&
        run.pipelineState.workflowState === "CONFIRM"
      ) {
        legacy = versionOneState({
          ...run.pipelineState,
          workflowState: "REVIEW",
        });
        throw stop;
      }
    },
  });

  await assert.rejects(fixture.run(), (cause) => cause === stop);
  assert.notEqual(legacy, undefined);
  fixture.persistPipelineState(migrateVersionOneState(legacy), { pause: null });
  return fixture;
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
        question: "Which externally visible behavior is required?",
        whyItMatters: "The answer changes implementation of the plan.",
      },
    ],
    reason: "",
    ...emptyDecision(),
  };
}

function clarificationPlanRevision() {
  return {
    status: "PLAN_REVISION_REQUIRED",
    questions: [],
    reason: "The requested behavior conflicts with the validated plan.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The plan excludes the required public behavior."],
  };
}

function bootstrapReady(role) {
  return {
    status: "READY",
    summary: `${role} understands the task, architecture, plan, risks, and finalization procedure.`,
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    capacityField: "",
    capacityLimit: 0,
    reason: "",
    ...emptyDecision(),
  };
}

function bootstrapProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    requiredChecks: [],
    validationInfrastructure: [],
    capacityField: "",
    capacityLimit: 0,
    reason: "",
    question: "Which public behavior should be implemented?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The task and plan do not choose a behavior."],
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

function compatibilityReady() {
  return { status: "READY", reason: "", evidence: [] };
}

function compatibilityPlanRevision() {
  return {
    status: "PLAN_REVISION_REQUIRED",
    reason: "The product decision changes a planned commit boundary.",
    evidence: ["The selected behavior requires another commit."],
  };
}

function reconciliationResolved() {
  return {
    status: "RESOLVED",
    summary:
      "The roles agree on the minimal implementation and finalization procedure.",
    disagreement: "",
    reason: "",
    ...emptyDecision(),
  };
}

function reconciliationDisagreement() {
  return {
    status: "DISAGREEMENT",
    summary: "",
    disagreement: "The roles disagree about the required repository boundary.",
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["Worker and Reviewer identify different owning modules."],
  };
}

function reconciliationProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    disagreement: "",
    reason: "",
    question: "Which public behavior should be implemented?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The independent summaries expose an unresolved requirement."],
  };
}

function arbitrationResolved() {
  return {
    direction: "SYNTHESIZE",
    summary: "Use the existing repository boundary and keep the change local.",
    rationale: "Repository ownership evidence supports the existing boundary.",
    reason: "",
    ...emptyDecision(),
  };
}

function arbitrationProductDecision() {
  return {
    direction: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    rationale: "The repository evidence cannot select a product behavior.",
    reason: "",
    question: "Which public behavior should be implemented?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The task and plan do not choose a behavior."],
  };
}

function implementationCompleted() {
  return {
    status: "COMPLETED",
    summary: "Implemented and self-reviewed the planned change.",
    reason: "",
    ...emptyDecision(),
  };
}

function implementationBlocked() {
  return {
    status: "BLOCKED",
    summary: "",
    reason: "A required local service is temporarily unavailable.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The local service health check failed."],
  };
}

function checkAndFix(status = "UNCHANGED") {
  return {
    status,
    summary:
      status === "CHANGED"
        ? "Fixed the problem found during the complete check."
        : status === "REFINALIZE"
          ? "The finalization evidence must be regenerated."
          : "The complete check found no problem.",
    reason: "",
    ...emptyDecision(),
  };
}

function cleanConfirmation(validationChange = "UNCHANGED") {
  return {
    status: "CLEAN",
    findings: [],
    validationChange,
    validationEvidence:
      validationChange === "UNCHANGED"
        ? []
        : ["The planned commit authorizes the complete validation change."],
    ...emptyDecision(),
  };
}

function cleanConfirmationFindings(...ids) {
  return {
    ...reviewFindings(...ids),
    status: "FINDINGS",
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
    summary: "The repository finalization procedure passed.",
    issues: [],
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    checks: checkResults("PASS"),
    reason: "",
    ...emptyDecision(),
  };
}

function finalizationWithTrustedCheck(trustedValidation) {
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  return {
    ...finalizationPassed(),
    requiredChecks,
    checks: [
      ...checkResults("PASS"),
      {
        checkId: "C2",
        command: trustedValidation.commands[0].command,
        status: "NOT_RUN",
        evidence: ["Reserved for the runner-trusted executor."],
      },
    ],
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
        : ["The planned commit authorizes the complete validation change."],
    ...emptyDecision(),
  };
}

function terminalConfirmation(result) {
  return Object.freeze({ ...result, [TERMINAL_CONFIRMATION]: true });
}

function terminalLazyConfirmation(result) {
  return Object.freeze({ ...result, [TERMINAL_LAZY_CONFIRMATION]: true });
}

function implementationProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    reason: "",
    question: "Which public behavior should the implementation expose?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The validated inputs do not choose one."],
  };
}

function finalizationFailed(...ids) {
  return {
    status: "FAIL",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "The repository finalization procedure found blocking failures.",
    issues: ids.map((id) => ({
      id,
      command: "npm test",
      problem: `Validation failed for ${id}.`,
      evidence: [`${id} failed in the test output.`],
    })),
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

function invalidProductionFinalization(...unsafeCommands) {
  const rejectedCommands =
    unsafeCommands.length === 0 ? ["git status"] : unsafeCommands;
  const requiredChecks = [
    REQUIRED_CHECKS[0],
    { id: "C2", command: "git diff --check HEAD" },
    ...rejectedCommands.map((command, index) => ({
      id: `C${index + 3}`,
      command,
    })),
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
      status: index === requiredChecks.length - 1 ? "BLOCKED" : "PASS",
      evidence: ["DO_NOT_PERSIST_REJECTED_PROVIDER_TEXT"],
    })),
    reason: "DO_NOT_PERSIST_REJECTED_BLOCKER",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["DO_NOT_PERSIST_REJECTED_EVIDENCE"],
  };
}

function persistedFinalizationCorrection(attempt, field, overrides = {}) {
  return {
    attempt,
    step: 1,
    guidance: "resolved",
    contentFingerprint: "a".repeat(64),
    diagnostics: [
      {
        role: "worker",
        phase: "finalization",
        contract: "finalization",
        field,
        constraint: "staging-independent-validation-command",
      },
    ],
    ...overrides,
  };
}

function persistedReviewCorrection(field, overrides = {}) {
  return {
    attempt: 1,
    step: 1,
    contentFingerprint: "a".repeat(64),
    validationInfrastructureFingerprint: "b".repeat(64),
    diagnostics: [
      {
        role: "reviewer",
        phase: "review",
        contract: "candidate-review",
        field,
        constraint: "review-contract",
      },
    ],
    ...overrides,
  };
}

function invalidReviewStatus() {
  return {
    ...reviewApproved(),
    status: "FINDINGS",
  };
}

function reviewFindings(...ids) {
  return {
    status: "FINDINGS",
    findings: ids.map((id) => ({
      id,
      file: "source.js",
      problem: `Problem ${id} remains.`,
      reason: `The current implementation still exhibits ${id}.`,
      suggestedAction: `Fix ${id}.`,
    })),
    validationChange: "UNCHANGED",
    validationEvidence: [],
    ...emptyDecision(),
  };
}

function reviewRejected(...ids) {
  return {
    ...reviewFindings(...ids),
    validationChange: "REJECTED",
    validationEvidence: [
      "The candidate validation infrastructure change is not authorized.",
    ],
  };
}

function reviewProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    findings: [],
    validationChange: "UNCHANGED",
    validationEvidence: [],
    question: "Which public behavior should the review require?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The validated inputs do not select either behavior."],
  };
}

function resolution(...decisions) {
  return {
    status: "RESOLVED",
    decisions: decisions.map(({ decision, id }) => ({
      id,
      decision,
      reason:
        decision === "FIX"
          ? `Applied the correction for ${id}.`
          : `The implementation already satisfies ${id}.`,
      evidence:
        decision === "FIX"
          ? []
          : [`source.js demonstrates why ${id} is invalid.`],
    })),
    reason: "",
    ...emptyDecision(),
  };
}

function reconsideration(direction, ...ids) {
  return {
    status: "RESOLVED",
    decisions: ids.map((id) => ({
      id,
      direction,
      reason: `${direction} is supported for ${id}.`,
      evidence: [`The current repository evidence supports ${direction}.`],
    })),
    ...emptyDecision(),
  };
}

function reconsiderationProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    decisions: [],
    question: "Which public behavior should resolve the disputed finding?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both interpretations remain valid and incompatible.",
    evidence: ["The plan and repository do not resolve the dispute."],
  };
}

function findingArbitration(direction) {
  return {
    direction,
    rationale: `Repository evidence supports ${direction}.`,
    ...emptyDecision(),
  };
}

function stagnation(direction, findingIds = []) {
  return {
    direction,
    rationale: `The minimal next direction is ${direction}.`,
    findingIds,
    reason: "",
    ...emptyDecision(),
  };
}

function matchesSchemaSubset(schema, value) {
  const objectValue =
    value !== null && typeof value === "object" && !Array.isArray(value);
  if (schema.type === "string" && typeof value !== "string") {
    return false;
  }
  if (schema.type === "array" && !Array.isArray(value)) {
    return false;
  }
  if (schema.type === "object" && !objectValue) {
    return false;
  }
  if (schema.enum !== undefined && !schema.enum.includes(value)) {
    return false;
  }
  if (typeof value === "string") {
    const length = [...value].length;
    if (
      (schema.minLength !== undefined && length < schema.minLength) ||
      (schema.maxLength !== undefined && length > schema.maxLength) ||
      (schema.pattern !== undefined &&
        !new RegExp(schema.pattern, "u").test(value))
    ) {
      return false;
    }
  }
  if (Array.isArray(value)) {
    if (
      (schema.minItems !== undefined && value.length < schema.minItems) ||
      (schema.maxItems !== undefined && value.length > schema.maxItems) ||
      (schema.items !== undefined &&
        value.some((item) => !matchesSchemaSubset(schema.items, item)))
    ) {
      return false;
    }
  }
  if (objectValue) {
    if (
      schema.required?.some((field) => !Object.hasOwn(value, field)) ||
      (schema.additionalProperties === false &&
        Object.keys(value).some(
          (field) => !Object.hasOwn(schema.properties, field),
        )) ||
      Object.entries(schema.properties ?? {}).some(
        ([field, propertySchema]) =>
          Object.hasOwn(value, field) &&
          !matchesSchemaSubset(propertySchema, value[field]),
      )
    ) {
      return false;
    }
  }
  if (
    schema.anyOf !== undefined &&
    !schema.anyOf.some((branch) => matchesSchemaSubset(branch, value))
  ) {
    return false;
  }
  return true;
}

function schemaPatterns(schema) {
  if (schema === null || typeof schema !== "object") {
    return [];
  }
  return [
    ...(typeof schema.pattern === "string" ? [schema.pattern] : []),
    ...Object.values(schema).flatMap(schemaPatterns),
  ];
}

function assertStrictSchema(schema) {
  if (schema === null || typeof schema !== "object") {
    return;
  }
  if (
    !Array.isArray(schema) &&
    (schema.type === "object" || schema.properties !== undefined)
  ) {
    assert.equal(schema.additionalProperties, false);
    assert.deepEqual(
      new Set(schema.required),
      new Set(Object.keys(schema.properties)),
    );
  }
  for (const child of Object.values(schema)) {
    assertStrictSchema(child);
  }
}

function assertArraySchemasDeclareItems(schema) {
  if (schema === null || typeof schema !== "object") {
    return;
  }
  if (!Array.isArray(schema) && schema.type === "array") {
    assert.notEqual(schema.items, undefined);
  }
  for (const child of Object.values(schema)) {
    assertArraySchemasDeclareItems(child);
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

function createClarificationService({
  interactive = false,
  onEdit,
  onFreeze,
} = {}) {
  let authorizationIndex = 0;
  const transcripts = new Map();

  function missingTranscript(transcriptPath) {
    const error = new Error(
      `Missing clarification transcript: ${transcriptPath}`,
    );
    error.code = "ENOENT";
    error.path = transcriptPath;
    return error;
  }

  function readTranscript(transcriptPath) {
    if (!transcripts.has(transcriptPath)) {
      throw missingTranscript(transcriptPath);
    }
    return transcripts.get(transcriptPath);
  }

  function writeTranscript(transcriptPath, content) {
    transcripts.set(transcriptPath, content);
  }

  async function inspectTranscript({ artifactRoot, transcriptPath }) {
    const content = readTranscript(transcriptPath);
    return Object.freeze({
      artifactRoot,
      transcriptPath,
      content,
      hash: hash(content),
    });
  }

  function assertExpectedHash(snapshot, expectedHash) {
    if (snapshot.hash !== expectedHash) {
      const error = new Error("Clarifications changed.");
      error.code = "ERR_CLARIFICATIONS_CHANGED";
      throw error;
    }
  }

  async function ensureTranscript(options) {
    if (!transcripts.has(options.transcriptPath)) {
      writeTranscript(options.transcriptPath, "");
    }
    return inspectTranscript(options);
  }

  async function append(options, section) {
    const snapshot = await inspectTranscript(options);
    assertExpectedHash(snapshot, options.expectedHash);
    const separator = snapshot.content.length === 0 ? "" : "\n\n";
    writeTranscript(
      options.transcriptPath,
      `${snapshot.content}${separator}${section}\n`,
    );
    return inspectTranscript(options);
  }

  async function appendQuestionRound(options) {
    return append(
      options,
      `## Round ${options.round}\n\n${options.questions[0].question}\n\n<!-- answer -->`,
    );
  }

  async function appendProductDecision(options) {
    return append(
      options,
      `## Product Decision ${options.number}\n\n${options.question}\n\n<!-- decision -->`,
    );
  }

  async function prepareEdit(options) {
    const snapshot = await inspectTranscript(options);
    assertExpectedHash(snapshot, options.expectedHash);
    const authorization = Object.freeze({
      schemaVersion: 1,
      id: `edit-${++authorizationIndex}`,
      artifactRoot: options.artifactRoot,
      transcriptPath: options.transcriptPath,
      suspendedState: options.suspendedState,
      action: options.action,
      preEditorHash: snapshot.hash,
    });
    await options.persistPendingEdit(authorization);
    return authorization;
  }

  async function acceptEdit(authorization, { consumePendingEdit }) {
    const snapshot = await inspectTranscript(authorization);
    const result = Object.freeze({
      authorizationId: authorization.id,
      suspendedState: authorization.suspendedState,
      action: authorization.action,
      transcriptPath: authorization.transcriptPath,
      preEditorHash: authorization.preEditorHash,
      hash: snapshot.hash,
      changed: snapshot.hash !== authorization.preEditorHash,
    });
    await consumePendingEdit(result);
    return result;
  }

  async function openEditor(authorization, options) {
    if (!interactive) {
      return Object.freeze({ status: "WAITING_FOR_USER", authorization });
    }
    await onEdit?.(authorization, {
      read: () => readTranscript(authorization.transcriptPath),
      write: (content) =>
        writeTranscript(authorization.transcriptPath, content),
    });
    return Object.freeze({
      status: "COMPLETED",
      result: await acceptEdit(authorization, options),
    });
  }

  return Object.freeze({
    acceptEdit,
    appendProductDecision,
    appendQuestionRound,
    ensureTranscript,
    freezeTranscript: async (options) => {
      const snapshot = await inspectTranscript(options);
      assertExpectedHash(snapshot, options.expectedHash);
      return (await onFreeze?.(snapshot)) ?? snapshot;
    },
    inspectTranscript,
    openEditor,
    prepareEdit,
    readTranscript,
    writeTranscript,
  });
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

async function createFixture(
  t,
  {
    artifactRoot = "LOCAL_ARTIFACTS",
    arbiter = [],
    capabilities = {},
    clarificationIgnored = true,
    dirty = false,
    finalizationSkill = true,
    interactive = false,
    mode = "independent",
    modeSettings = {},
    models = {},
    onEdit,
    onFreeze,
    onCommitRun,
    onCommitVerify,
    onRoleRun,
    onTrustedValidation,
    onTransition,
    plan = PLAN,
    prepareProject,
    proactiveClarification = false,
    repository = "memory",
    reviewer = [bootstrapReady("Reviewer")],
    sessionIds = ROLE_SESSIONS,
    sourceSession = null,
    trustedValidation,
    workReviewer = [reviewApproved()],
    workWorker = [implementationCompleted(), finalizationPassed()],
    worker = [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  } = {},
) {
  const projectPath = await mkdtemp(join(tmpdir(), "agent-runner-execution-"));
  const taskPath = join(projectPath, "task");
  const runId = "run-1";
  const clarificationPath = join(
    projectPath,
    artifactRoot,
    "agent-runner",
    runId,
    "clarifications.md",
  );
  if (repository === "git") {
    await executeFile("git", ["init", "-q", projectPath]);
    await executeFile("git", [
      "-C",
      projectPath,
      "config",
      "user.name",
      "Test",
    ]);
    await executeFile("git", [
      "-C",
      projectPath,
      "config",
      "user.email",
      "test@example.com",
    ]);
  }
  await mkdir(taskPath);
  await writeFile(
    join(taskPath, "task.md"),
    "Implement the requested behavior.\n",
  );
  await writeFile(join(taskPath, "plan.md"), plan);
  if (finalizationSkill) {
    await mkdir(join(projectPath, ".agents", "skills", "finalization"), {
      recursive: true,
    });
    await writeFile(
      join(projectPath, ".agents", "skills", "finalization", "SKILL.md"),
      "---\nname: finalization\ndescription: Test validation.\n---\n\nRun tests.\n",
    );
  }
  await writeFile(
    join(projectPath, ".gitignore"),
    clarificationIgnored ? `/${artifactRoot}/\n` : "",
  );
  await writeFile(join(projectPath, "source.js"), "export const value = 1;\n");
  await writeFile(
    join(projectPath, "package.json"),
    '{"scripts":{"test":"node --test"}}\n',
  );
  await prepareProject?.(projectPath);
  if (repository === "git") {
    await executeFile("git", ["-C", projectPath, "add", "."]);
    await executeFile("git", [
      "-C",
      projectPath,
      "commit",
      "-qm",
      "test: fixture",
    ]);
  }
  let committedContentFingerprint = await repositoryFingerprint(projectPath, [
    artifactRoot,
  ]);
  if (dirty) {
    await writeFile(join(projectPath, "dirty.txt"), "dirty\n");
  }
  t.after(() => rm(projectPath, { recursive: true, force: true }));

  const memoryRepository = {
    branch: "refs/heads/main",
    commit: null,
    head: hash("fixture-head"),
    identityFingerprint: hash("fixture-identity"),
    indexFingerprint: hash("fixture-index"),
    refsFingerprint: hash("fixture-refs"),
    remoteConfigurationFingerprint: hash("fixture-remotes"),
  };

  async function commitMemoryRepository(subject) {
    const parent = memoryRepository.head;
    committedContentFingerprint = await repositoryFingerprint(projectPath, [
      artifactRoot,
    ]);
    memoryRepository.head = hash(
      JSON.stringify({ parent, subject, committedContentFingerprint }),
    );
    memoryRepository.refsFingerprint = hash(memoryRepository.head);
    memoryRepository.commit = { parent, subject };
  }

  const repositoryControl = Object.freeze({
    async commit(subject) {
      await commitMemoryRepository(subject);
    },
    changeIdentity(value = "changed-identity") {
      memoryRepository.identityFingerprint = hash(value);
    },
    changeRemote(value = "changed-remote") {
      memoryRepository.remoteConfigurationFingerprint = hash(value);
    },
    changeRefs(value = "changed-refs") {
      memoryRepository.refsFingerprint = hash(value);
    },
    stage(value = "changed-index") {
      memoryRepository.indexFingerprint = hash(value);
    },
  });

  const queues = {
    worker: [...worker, ...workWorker],
    reviewer: [...reviewer, ...workReviewer],
    arbiter: [...arbiter],
  };
  const calls = { worker: [], reviewer: [], arbiter: [] };
  const probeCalls = { worker: 0, reviewer: 0, arbiter: 0 };
  const freshSessionIndexes = { worker: 0, reviewer: 0, arbiter: 0 };

  function resultMatchesSchema(result, schema) {
    if (result === MISSING_BOOTSTRAP_RESPONSE) {
      return WRAPPED_BOOTSTRAP_SCHEMAS.has(schema);
    }
    const variants = schema?.properties?.result?.anyOf ?? [schema];
    const statuses = variants.flatMap(
      (variant) => variant?.properties?.status?.enum ?? [],
    );
    if (!Array.isArray(statuses) || !statuses.includes(result?.status)) {
      return false;
    }
    if (schema === CANDIDATE_REVIEW_SCHEMA) {
      return result?.[TERMINAL_CONFIRMATION] !== true;
    }
    if (schema === REVIEW_SCHEMA) {
      return result?.[TERMINAL_CONFIRMATION] === true;
    }
    if (schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA) {
      return result?.[TERMINAL_LAZY_CONFIRMATION] !== true;
    }
    if (schema === CLEAN_CONFIRM_SCHEMA) {
      return result?.[TERMINAL_LAZY_CONFIRMATION] === true;
    }
    return true;
  }

  function takeStructured(role, schema) {
    const queue = queues[role];
    const index = queue.findIndex((result) =>
      resultMatchesSchema(result, schema),
    );
    if (index !== -1) {
      return queue.splice(index, 1)[0];
    }
    if ([CANDIDATE_REVIEW_SCHEMA, REVIEW_SCHEMA].includes(schema)) {
      return reviewApproved();
    }
    if (
      [CANDIDATE_CLEAN_CONFIRM_SCHEMA, CLEAN_CONFIRM_SCHEMA].includes(schema)
    ) {
      return cleanConfirmation();
    }
    return queue.shift();
  }

  function nextFreshSessionId(role) {
    const configured = sessionIds[role];
    if (!Array.isArray(configured)) {
      const index = freshSessionIndexes[role]++;
      return index === 0 ? configured : `${configured}-${index + 1}`;
    }
    const sessionId = configured[freshSessionIndexes[role]++];
    assert.notEqual(sessionId, undefined, `Missing fresh ${role} session ID.`);
    return sessionId;
  }

  const defaultCapabilities = {
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
  const adapters = Object.fromEntries(
    Object.keys(queues).map((role) => [
      role,
      {
        async probe() {
          probeCalls[role] += 1;
          return { ...defaultCapabilities, ...capabilities[role] };
        },
        async run(request) {
          calls[role].push(request);
          assert.match(request.prompt, /Do not delegate/u);
          assert.match(
            request.recoveryPrompt ?? request.prompt,
            /Do not delegate/u,
          );
          await onRoleRun?.(
            role,
            request,
            calls[role].length,
            repositoryControl,
          );
          if (request.access === "local-commit") {
            if (onCommitRun === undefined) {
              if (repository === "git") {
                await executeFile("git", ["-C", projectPath, "add", "-A"]);
                await executeFile("git", [
                  "-C",
                  projectPath,
                  "commit",
                  "-qm",
                  request.commit.message,
                ]);
              } else {
                await commitMemoryRepository(request.commit.message);
              }
            } else {
              await onCommitRun(request, repositoryControl);
            }
            return {
              output: "committed",
              sessionId: request.session?.id ?? nextFreshSessionId(role),
            };
          }
          const structured = takeStructured(role, request.schema);
          assert.notEqual(structured, undefined, `Unexpected ${role} turn.`);
          if (structured === MISSING_BOOTSTRAP_RESPONSE) {
            return null;
          }
          if (
            role === "worker" &&
            structured.status === "COMPLETED" &&
            request.prompt.includes("Implement the changes")
          ) {
            const step =
              /Current planned commit:\n## Commit ([1-9][0-9]*):/u.exec(
                request.prompt,
              )?.[1];
            assert.notEqual(step, undefined);
            await writeFile(
              join(projectPath, `implementation-${step}.txt`),
              `implemented step ${step}\n`,
            );
          }
          const candidateStructured = [
            CANDIDATE_REVIEW_SCHEMA,
            CANDIDATE_CLEAN_CONFIRM_SCHEMA,
          ].includes(request.schema)
            ? Object.fromEntries(
                Object.entries(structured).filter(
                  ([field]) =>
                    !["validationChange", "validationEvidence"].includes(field),
                ),
              )
            : structured;
          return {
            output: "structured",
            structured: WRAPPED_BOOTSTRAP_SCHEMAS.has(request.schema)
              ? { result: candidateStructured }
              : candidateStructured,
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : nextFreshSessionId(role),
          };
        },
      },
    ]),
  );

  async function gitSnapshot({ allowedPaths = [] } = {}) {
    const normalizedAllowedPaths = allowedPaths
      .map((path) => (isAbsolute(path) ? relative(projectPath, path) : path))
      .sort();
    if (repository === "memory") {
      const content = await repositoryFingerprint(projectPath, [artifactRoot]);
      const clean =
        content === committedContentFingerprint &&
        memoryRepository.indexFingerprint === hash("fixture-index");
      const snapshot = {
        schemaVersion: 1,
        projectPath,
        allowedPaths: normalizedAllowedPaths,
        head: memoryRepository.head,
        branch: memoryRepository.branch,
        detached: false,
        clean,
        refsFingerprint: memoryRepository.refsFingerprint,
        trackedContentFingerprint: content,
        untrackedContentFingerprint: clean ? hash("") : content,
        contentFingerprint: content,
        indexFingerprint: memoryRepository.indexFingerprint,
        remoteConfigurationFingerprint:
          memoryRepository.remoteConfigurationFingerprint,
        identityAvailable: true,
        identityFingerprint: memoryRepository.identityFingerprint,
      };
      return {
        ...snapshot,
        fingerprint: hash(JSON.stringify(snapshot)),
      };
    }
    const [head, branch, refs, status, index, remotes, identity] =
      await Promise.all([
        executeFile("git", ["-C", projectPath, "rev-parse", "HEAD"]),
        executeFile("git", [
          "-C",
          projectPath,
          "rev-parse",
          "--abbrev-ref",
          "HEAD",
        ]),
        executeFile("git", ["-C", projectPath, "for-each-ref"]),
        executeFile("git", [
          "-C",
          projectPath,
          "status",
          "--porcelain=v1",
          "--untracked-files=all",
        ]),
        executeFile("git", ["-C", projectPath, "diff", "--cached", "--binary"]),
        executeFile("git", [
          "-C",
          projectPath,
          "config",
          "--get-regexp",
          "^(remote|url)\\.",
        ]).catch(() => ({ stdout: "" })),
        executeFile("git", [
          "-C",
          projectPath,
          "config",
          "--get-regexp",
          "^user\\.(name|email)$",
        ]),
      ]);
    const content = await repositoryFingerprint(projectPath, [artifactRoot]);
    const snapshot = {
      schemaVersion: 1,
      projectPath,
      allowedPaths: normalizedAllowedPaths,
      head: head.stdout.trim(),
      branch:
        branch.stdout.trim() === "HEAD"
          ? null
          : `refs/heads/${branch.stdout.trim()}`,
      detached: branch.stdout.trim() === "HEAD",
      clean: status.stdout.trim().length === 0,
      refsFingerprint: hash(refs.stdout),
      trackedContentFingerprint: content,
      untrackedContentFingerprint: hash(status.stdout),
      contentFingerprint: content,
      indexFingerprint: hash(index.stdout),
      remoteConfigurationFingerprint: hash(remotes.stdout),
      identityAvailable: true,
      identityFingerprint: hash(identity.stdout),
    };
    return {
      ...snapshot,
      fingerprint: hash(JSON.stringify(snapshot)),
    };
  }

  let currentRun = {
    revision: 1,
    runId,
    pipelineId: "plan-execution",
    pipelineStateVersion: 14,
    projectPath,
    taskPath,
    roles: Object.fromEntries(
      (mode === "lazy" ? ["worker"] : ["worker", "reviewer", "arbiter"]).map(
        (role) => [role, { backend: "codex", model: models[role] ?? null }],
      ),
    ),
    counters: {},
    hashes: {},
    pause: null,
    activeTurn: null,
    sessionLineage: { source: sourceSession, children: [] },
    pipelineState: createPlanExecutionState({
      artifactRoot,
      proactiveClarification,
      ...(mode === "lazy"
        ? { settings: { ...SETTINGS, ...modeSettings, mode } }
        : {}),
      ...(trustedValidation === undefined ? {} : { trustedValidation }),
    }),
  };
  const preflights = [];
  const transitions = [];
  const artifacts = new Map();
  let commitAuthorizationIndex = 0;
  const clarifications = createClarificationService({
    interactive,
    onEdit,
    onFreeze,
  });
  const runtime = {
    adapters,
    clarifications,
    trustedValidation: {
      async execute(options) {
        assert.notEqual(onTrustedValidation, undefined);
        return onTrustedValidation(options);
      },
    },
    git: {
      async inspectPath({ path }) {
        const absolutePath = isAbsolute(path) ? path : join(projectPath, path);
        let canonicalPath;
        try {
          canonicalPath = await realpath(absolutePath);
        } catch (cause) {
          if (cause?.code !== "ENOENT") {
            throw cause;
          }
          return {
            exists: false,
            kind: null,
            relativePath: relative(projectPath, absolutePath),
          };
        }
        const relativePath = relative(projectPath, canonicalPath);
        if (
          relativePath === ".." ||
          relativePath.startsWith(`..${sep}`) ||
          isAbsolute(relativePath)
        ) {
          const error = new Error("Repository path escapes through a symlink.");
          error.code = "ERR_UNSAFE_REPOSITORY_PATH";
          throw error;
        }
        const metadata = await lstat(canonicalPath);
        return {
          exists: true,
          kind: metadata.isFile()
            ? "file"
            : metadata.isDirectory()
              ? "directory"
              : "other",
          relativePath,
        };
      },
      async prepareCommit({ expectedSnapshot, subject, persistPendingCommit }) {
        const authorization = Object.freeze({
          schemaVersion: 1,
          id: `commit-${++commitAuthorizationIndex}`,
          projectPath,
          expectedHead: expectedSnapshot.head,
          expectedBranch: expectedSnapshot.branch,
          expectedRefsFingerprint: expectedSnapshot.refsFingerprint,
          expectedOtherRefsFingerprint: expectedSnapshot.refsFingerprint,
          expectedContentFingerprint: expectedSnapshot.contentFingerprint,
          expectedIndexFingerprint: expectedSnapshot.indexFingerprint,
          expectedRemoteConfigurationFingerprint:
            expectedSnapshot.remoteConfigurationFingerprint,
          expectedIdentityFingerprint: expectedSnapshot.identityFingerprint,
          expectedAuthorIdentityFingerprint: hash("author"),
          expectedCommitterIdentityFingerprint: hash("committer"),
          subject,
        });
        const current = await gitSnapshot({
          allowedPaths: expectedSnapshot.allowedPaths,
        });
        if (current.fingerprint !== expectedSnapshot.fingerprint) {
          const error = new Error("Commit gate changed.");
          error.code = "ERR_COMMIT_GATE_CHANGED";
          throw error;
        }
        await persistPendingCommit(authorization);
        return authorization;
      },
      async consumeCommit(authorization, { consumePendingCommit }) {
        await consumePendingCommit();
        return Object.freeze({
          authorizationId: authorization.id,
          cwd: authorization.projectPath,
          access: "local-commit",
          commit: Object.freeze({
            expectedHead: authorization.expectedHead,
            message: authorization.subject,
          }),
        });
      },
      async verifyCommit(authorization) {
        await onCommitVerify?.(authorization);
        const snapshot = await gitSnapshot();
        if (snapshot.head === authorization.expectedHead) {
          const error = new Error("Authorized commit was not created.");
          error.code = "ERR_COMMIT_NOT_CREATED";
          throw error;
        }
        const [parent, message] =
          repository === "git"
            ? await Promise.all([
                executeFile("git", [
                  "-C",
                  projectPath,
                  "show",
                  "-s",
                  "--format=%P",
                  snapshot.head,
                ]).then(({ stdout }) => stdout.trim()),
                executeFile("git", [
                  "-C",
                  projectPath,
                  "show",
                  "-s",
                  "--format=%B",
                  snapshot.head,
                ]).then(({ stdout }) => stdout.trimEnd()),
              ])
            : [
                memoryRepository.commit?.parent ?? "",
                memoryRepository.commit?.subject ?? "",
              ];
        const changes = [];
        if (parent !== authorization.expectedHead) {
          changes.push("parent");
        }
        if (message !== authorization.subject) {
          changes.push("message");
        }
        if (/(?:^|\n)co-authored-by[ \t]*:/iu.test(message)) {
          changes.push("co-author");
        }
        if (!snapshot.clean) {
          changes.push("worktree-or-index");
        }
        if (
          (await repositoryFingerprint(projectPath, [artifactRoot])) !==
          authorization.expectedContentFingerprint
        ) {
          changes.push("content");
        }
        if (changes.length > 0) {
          const error = new Error("Authorized commit violates its contract.");
          error.code = "ERR_COMMIT_CONTRACT_VIOLATED";
          error.changes = changes;
          throw error;
        }
        return Object.freeze({
          authorizationId: authorization.id,
          head: snapshot.head,
          subject: authorization.subject,
          contentFingerprint: authorization.expectedContentFingerprint,
        });
      },
      async contentFingerprint() {
        return repositoryFingerprint(projectPath, [artifactRoot]);
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
      async preflight(options) {
        preflights.push(options);
        if (options.requireClean) {
          const isClean =
            repository === "git"
              ? await executeFile("git", [
                  "-C",
                  projectPath,
                  "status",
                  "--porcelain",
                  "--untracked-files=all",
                ]).then(({ stdout }) => stdout.trim().length === 0)
              : (await gitSnapshot()).clean;
          if (!isClean) {
            const error = new Error("Repository is not clean.");
            error.code = "ERR_REPOSITORY_NOT_CLEAN";
            throw error;
          }
        }
        for (const path of options.requiredIgnoredPaths) {
          const pathFromRoot = isAbsolute(path)
            ? relative(projectPath, path)
            : path;
          const isIgnored =
            repository === "git"
              ? await executeFile("git", [
                  "-C",
                  projectPath,
                  "check-ignore",
                  "-q",
                  "--",
                  path,
                ]).then(
                  () => true,
                  () => false,
                )
              : clarificationIgnored &&
                (pathFromRoot === artifactRoot ||
                  pathFromRoot.startsWith(`${artifactRoot}/`));
          if (!isIgnored) {
            const error = new Error("Artifact is not ignored.");
            error.code = "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED";
            throw error;
          }
        }
        return { snapshot: await gitSnapshot(options) };
      },
      snapshot: gitSnapshot,
      async assertUnchanged(snapshot) {
        const current = await gitSnapshot({
          allowedPaths: snapshot.allowedPaths,
        });
        if (snapshot.fingerprint !== current.fingerprint) {
          const error = new Error("Read-only repository changed.");
          error.code = "ERR_READ_ONLY_REPOSITORY_CHANGED";
          throw error;
        }
      },
      async reconcileInterrupted(snapshot, { allowWorkspaceChanges }) {
        const current = await gitSnapshot({
          allowedPaths: snapshot.allowedPaths,
        });
        if (!allowWorkspaceChanges) {
          await this.assertUnchanged(snapshot);
          return current;
        }
        const changes = [];
        for (const [field, name] of [
          ["head", "head"],
          ["branch", "branch"],
          ["detached", "detached-head"],
          ["refsFingerprint", "refs"],
          ["remoteConfigurationFingerprint", "remote-configuration"],
          ["identityFingerprint", "identity"],
        ]) {
          if (snapshot[field] !== current[field]) {
            changes.push(name);
          }
        }
        if (changes.length > 0) {
          const error = new Error("Interrupted repository controls changed.");
          error.code = "ERR_INTERRUPTED_REPOSITORY_CONTROL_CHANGED";
          error.changes = changes;
          throw error;
        }
        return current;
      },
    },
    async readInputs() {
      const task = await optionalInput(join(taskPath, "task.md"));
      const planInput = await optionalInput(join(taskPath, "plan.md"));
      if (task === null || planInput === null) {
        const error = new Error("Required task input is missing.");
        error.code = "ENOENT";
        error.path =
          task === null ? join(taskPath, "task.md") : join(taskPath, "plan.md");
        throw error;
      }
      return {
        task,
        plan: planInput,
        taskClarifications: await optionalInput(
          join(taskPath, "clarifications.md"),
        ),
        context: await optionalInput(join(taskPath, "context.md")),
      };
    },
    async transition(patch, options) {
      currentRun = {
        ...currentRun,
        ...patch,
        revision: currentRun.revision + 1,
      };
      transitions.push({ patch, options });
      await onTransition?.(currentRun, patch, options);
      return currentRun;
    },
    async startAgentTurn(activeTurn, { pipelineState } = {}) {
      currentRun = {
        ...currentRun,
        ...(pipelineState === undefined ? {} : { pipelineState }),
        activeTurn,
        revision: currentRun.revision + 1,
      };
      transitions.push({ activeTurn, kind: "turn-started", options: {} });
      return currentRun;
    },
    async finishAgentTurn(activeTurn) {
      assert.deepEqual(currentRun.activeTurn, activeTurn);
      currentRun = {
        ...currentRun,
        activeTurn: null,
        revision: currentRun.revision + 1,
      };
      transitions.push({ activeTurn, kind: "turn-finished", options: {} });
      return currentRun;
    },
    async recordChildSession(child, options) {
      currentRun = {
        ...currentRun,
        revision: currentRun.revision + 1,
        sessionLineage: {
          ...currentRun.sessionLineage,
          children: [...currentRun.sessionLineage.children, child],
        },
      };
      transitions.push({ child, options });
      return currentRun;
    },
    async writeRunArtifact({ path, content }) {
      artifacts.set(path, content);
      return join(
        tmpdir(),
        "agent-runner-memory-state",
        hash(projectPath),
        path,
      );
    },
  };

  async function run(settings = {}, action) {
    currentRun = await runPlanExecution({
      action,
      run: currentRun,
      runtime,
      settings: { ...SETTINGS, ...settings },
    });
    return currentRun;
  }

  function persistPipelineState(
    pipelineState,
    { pause = currentRun.pause } = {},
  ) {
    currentRun = {
      ...currentRun,
      pipelineStateVersion: 14,
      pipelineState,
      pause,
      revision: currentRun.revision + 1,
    };
    assertRun(currentRun);
    return currentRun;
  }

  return {
    artifacts,
    calls,
    clarificationPath,
    hasClarification() {
      try {
        clarifications.readTranscript(clarificationPath);
        return true;
      } catch (cause) {
        if (cause?.code === "ENOENT") {
          return false;
        }
        throw cause;
      }
    },
    readClarification() {
      return clarifications.readTranscript(clarificationPath);
    },
    get currentRun() {
      return currentRun;
    },
    preflights,
    probeCalls,
    projectPath,
    repository: repositoryControl,
    persistPipelineState,
    run,
    runtime,
    taskPath,
    transitions,
    writeClarification(content) {
      clarifications.writeTranscript(clarificationPath, content);
    },
  };
}

async function createRealGitFixture(t, options = {}) {
  return createFixture(t, { ...options, repository: "git" });
}

async function createRevision55Fixture(
  t,
  {
    refinalizationSummary,
    resumeFinalization = false,
    trustedEvidence,
    trustedOutcomes = ["PASS", "PASS"],
  } = {},
) {
  const trustedValidation = trustedValidationSnapshot();
  const finalization = finalizationWithTrustedCheck(trustedValidation);
  const refinalization =
    refinalizationSummary === undefined
      ? finalization
      : { ...finalization, summary: refinalizationSummary };
  const outcomes = [];
  const failureRecovery = trustedOutcomes.includes("FAIL")
    ? [
        resolution({ id: "F1", decision: "FIX" }),
        checkAndFix(),
        cleanConfirmation(),
        finalization,
      ]
    : [];
  const fixture = await createFixture(t, {
    mode: "lazy",
    modeSettings: { trustedChecks: ["service-check"] },
    trustedValidation,
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks: finalization.requiredChecks,
      },
    ],
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      cleanConfirmation(),
      invalidProductionFinalization(),
      finalization,
      terminalLazyConfirmation(cleanConfirmationFindings("R1")),
      checkAndFix(),
      cleanConfirmation(),
      refinalization,
      ...failureRecovery,
      ...(resumeFinalization ? [finalization] : []),
      terminalLazyConfirmation(cleanConfirmation()),
    ],
    onTrustedValidation(options) {
      const status = trustedOutcomes[outcomes.length];
      assert.notEqual(status, undefined);
      outcomes.push(status);
      return {
        status,
        commandIdentity: options.commandIdentity,
        exitCode: status === "PASS" ? 0 : 7,
        signal: null,
        timedOut: false,
        evidence: [
          trustedEvidence?.(outcomes.length, status) ??
            (status === "PASS"
              ? "The runner-trusted check passed."
              : "The runner-trusted check exited with code 7."),
        ],
        ...options.bindings,
      };
    },
  });
  return { fixture, trustedOutcomes: outcomes };
}

export {
  MISSING_BOOTSTRAP_RESPONSE,
  PLAN,
  REBOOTSTRAPPED_WORKER_SESSION,
  REQUIRED_CHECKS,
  RESTARTED_ROLE_SESSIONS,
  ROLE_SESSIONS,
  SETTINGS,
  SOURCE_SESSION,
  VALIDATION_INFRASTRUCTURE,
  arbitrationProductDecision,
  arbitrationResolved,
  assertArraySchemasDeclareItems,
  assertStrictSchema,
  bootstrapCapacityExhausted,
  bootstrapCorrection,
  bootstrapProductDecision,
  bootstrapReady,
  checkAndFix,
  checkResults,
  clarificationPlanRevision,
  clarificationQuestions,
  clarificationReady,
  cleanConfirmation,
  cleanConfirmationFindings,
  compatibilityPlanRevision,
  compatibilityReady,
  createFixture,
  createRealGitFixture,
  createRevision55Fixture,
  environmentBlocked,
  executeFile,
  finalizationBlocked,
  finalizationFailed,
  finalizationPassed,
  finalizationUnavailable,
  finalizationWithTrustedCheck,
  findingArbitration,
  hash,
  implementationBlocked,
  implementationCompleted,
  implementationProductDecision,
  invalidProductionFinalization,
  invalidReviewStatus,
  matchesSchemaSubset,
  migrateVersionOneState,
  persistedFinalizationCorrection,
  persistedReviewCorrection,
  prepareValidationMigration,
  reconciliationDisagreement,
  reconciliationProductDecision,
  reconciliationResolved,
  reconsideration,
  reconsiderationProductDecision,
  resolution,
  reviewApproved,
  reviewFindings,
  reviewProductDecision,
  reviewRejected,
  schemaPatterns,
  stagnation,
  terminalConfirmation,
  terminalLazyConfirmation,
  trustedValidationSnapshot,
  versionFourState,
  versionOneState,
  versionThirteenState,
};
