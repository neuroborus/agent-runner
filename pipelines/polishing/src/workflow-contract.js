import { createHash } from "node:crypto";
import { isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  validCapabilityReports,
  freezeReport,
} from "./capability-requirements.js";
import {
  candidateGatePassed,
  finalizationGatePassed,
  handoffGatePassed,
} from "./gate-evidence.js";
import { combinedReview, polishingPolicy } from "./mode-policy.js";

export const MAX_CLARIFICATION_ROUNDS = 3;
export const DEFAULT_FINALIZATION_POLICY = "auto";
export const CONVENTIONAL_FINALIZATION_SKILL_PATHS = Object.freeze([
  ".agents/skills/finalization/SKILL.md",
  ".claude/skills/finalization/SKILL.md",
]);
export const WORKFLOW_STATES = Object.freeze([
  "CANCELED",
  "CLARIFY",
  "BOOTSTRAP",
  "POLISH",
  "REVIEW",
  "CHECK_AND_FIX",
  "CLEAN_CONFIRM",
  "FINALIZE",
  "CONFIRM",
  "RESOLVE_FINDINGS",
  "HANDOFF",
  "WAITING_FOR_USER",
  "DONE",
  "FAILED",
]);

const ROLES = Object.freeze(["worker", "reviewer", "arbiter"]);
const SETTINGS_FIELDS = Object.freeze([
  "finalization",
  "maxFixRounds",
  "maxDisputesPerFinding",
  "maxSameFindingRounds",
  "mode",
  "stagnationWindowRounds",
  "trustedChecks",
]);
const NUMERIC_SETTINGS_FIELDS = SETTINGS_FIELDS.filter(
  (field) => !["finalization", "mode", "trustedChecks"].includes(field),
);
const COUNTER_FIELDS = Object.freeze([
  "clarificationRounds",
  "productDecisions",
  "fixRounds",
  "correctionRounds",
]);
const PIPELINE_STATE_FIELDS = new Set([
  "workflowState",
  "artifactRoot",
  "clarificationRoot",
  "preflightComplete",
  "settings",
  "finalizationGuidance",
  "repositoryBaseline",
  "backendVersions",
  "proactiveClarification",
  "proactiveClarificationComplete",
  "clarificationPath",
  "clarificationFrozen",
  "pendingEdit",
  "pendingClarificationAppend",
  "refreezeRequired",
  "workerSummary",
  "reviewerSummary",
  "workerValidation",
  "reviewerValidation",
  "resolvedSummary",
  "bootstrapDisagreement",
  "bootstrapArbitrationUsed",
  "bootstrapCorrections",
  "pendingBootstrapCorrection",
  "finalizationCorrection",
  "pendingFinalizationCorrection",
  "finalizationRecovery",
  "reviewCorrection",
  "pendingReviewCorrection",
  "confirmationCorrection",
  "pendingConfirmationCorrection",
  "lazyCorrections",
  "pendingLazyCorrection",
  "candidateReviewResult",
  "candidateReviewedFingerprint",
  "candidateConfirmationFingerprint",
  "primaryFindings",
  "workReports",
  "candidateMigrationPending",
  "cleanConfirmationFingerprint",
  "lazySourceForkConsumed",
  "authenticationSourceForkRecovery",
  "polishSummary",
  "finalizationResult",
  "finalizedFingerprint",
  "requiredChecks",
  "validationInfrastructure",
  "validationInfrastructureFingerprint",
  "trustedValidation",
  "validationMigrationPending",
  "validationMigrationDisagreement",
  "reviewResult",
  "reviewedFingerprint",
  "findings",
  "previousFindings",
  "pendingDisputes",
  "disputeCounts",
  "disputeHistory",
  "findingArbitrations",
  "correctionHistory",
  "sameFindingRounds",
  "pendingCorrection",
  "availabilityCorrectionCharged",
  "blockedSinceStagnation",
  "stagnationArbitrationUsed",
  "stagnationDirection",
  "reviewReconsideration",
  "additionalFixRounds",
  "findingOverrides",
  "resolutionCorrection",
]);
const PENDING_EDIT_FIELDS = new Set([
  "schemaVersion",
  "id",
  "artifactRoot",
  "transcriptPath",
  "suspendedState",
  "action",
  "preEditorHash",
]);
const SNAPSHOT_FIELDS = new Set([
  "schemaVersion",
  "projectPath",
  "allowedPaths",
  "head",
  "branch",
  "detached",
  "clean",
  "refsFingerprint",
  "trackedContentFingerprint",
  "untrackedContentFingerprint",
  "contentFingerprint",
  "indexFingerprint",
  "remoteConfigurationFingerprint",
  "identityAvailable",
  "identityFingerprint",
]);
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const FINALIZATION_GUIDANCE_FIELDS = Object.freeze([
  "configuredPolicy",
  "selection",
  "skillPath",
  "selectedFileFingerprint",
  "decisionFingerprint",
]);
const RUN_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/u;
const REVIEW_FINDING_ID_PATTERN = /^R[1-9][0-9]{0,8}$/u;
const FINALIZATION_ISSUE_ID_PATTERN = /^F[1-9][0-9]{0,8}$/u;
const REQUIRED_CHECK_ID_PATTERN = /^C[1-9][0-9]{0,8}$/u;
const PERSISTED_CHECK_RESULT_FIELDS = Object.freeze([
  "checkId",
  "command",
  "status",
  "evidence",
  "executor",
  "commandIdentity",
  "exitCode",
  "signal",
  "timedOut",
]);
const REQUIRED_CHECK_FIELDS = Object.freeze(["id", "command"]);
const INDEX_WRITING_GIT_COMMANDS = new Set([
  "add",
  "am",
  "checkout",
  "checkout-index",
  "cherry-pick",
  "clean",
  "commit",
  "commit-tree",
  "merge",
  "merge-index",
  "read-tree",
  "rebase",
  "reset",
  "restore",
  "revert",
  "rm",
  "stash",
  "switch",
  "update-index",
  "write-tree",
]);
const INDEX_INSPECTING_GIT_COMMANDS = new Set([
  "diff-files",
  "diff-index",
  "ls-files",
  "status",
]);
const SHELL_SEPARATOR_PATTERN = /^[;&|()<>]$/u;
const EXPLICIT_TREE_PATTERN =
  /^(?:HEAD(?:[~^][0-9]*)*|[a-f0-9]{7,64}|refs\/(?:heads|remotes|tags)\/[^\s]+)$/iu;
const TRUSTED_COMMAND_FIELDS = Object.freeze([
  "alias",
  "command",
  "executable",
  "arguments",
  "identity",
]);
const TRUSTED_VALIDATION_FIELDS = Object.freeze([
  "schemaVersion",
  "commands",
  "commandFingerprint",
  "configurationFingerprint",
]);
const MAX_TRUSTED_COMMAND_TIMEOUT_MS = 2_147_483_647;
const TRUSTED_ALIAS_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const ADAPTER_DIAGNOSTIC_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u;
const FAILURE_FIELDS = Object.freeze(["reason", "code"]);
const ADAPTER_FAILURE_FIELDS = Object.freeze([
  ...FAILURE_FIELDS,
  "diagnosticClass",
]);
// Runner-owned FINALIZE hygiene issue; the only source of a persisted FAIL
// whose checks all pass.
export const RUNNER_HYGIENE_ISSUE_COMMAND =
  "Runner staging-independent whitespace hygiene";
export const HANDOFF_WHITESPACE_CODES = Object.freeze([
  "ERR_POLISHING_HANDOFF_UNSTAGED_WHITESPACE",
  "ERR_POLISHING_HANDOFF_WHITESPACE",
]);
export const MAX_TEXT_LENGTH = 4_000;
export const MAX_SUMMARY_LENGTH = 20_000;
export const MAX_ITEMS = 32;
export const MAX_BOOTSTRAP_ITEMS = 256;
export const MAX_VALIDATION_ITEMS = MAX_BOOTSTRAP_ITEMS * 2;
export const MAX_OPTIONS = 16;
const MAX_STRUCTURED_RESULT_BYTES = 2 * 1024 * 1024;
// Twelve result-sized slots cover retained inventories, gate copies, and metadata.
export const MAX_DURABLE_RUN_BYTES = 24 * 1024 * 1024;
export const MAX_DIAGNOSTIC_ITEMS = 32;
export const MAX_DISPUTE_HISTORY_BYTES = 64 * 1024;
export const MAX_DISPUTES_PER_FINDING = 5;

export function resolveActiveRoles(settings) {
  return polishingPolicy(settings).activeRoles;
}

const INVALID_OUTPUT_CODE = "ERR_INVALID_POLISHING_OUTPUT";
export const INVALID_POLISHING_INPUT_CODE = "ERR_INVALID_POLISHING_INPUT";
const OUTPUT_DIAGNOSTIC_FIELDS = Object.freeze([
  "role",
  "phase",
  "contract",
  "field",
  "constraint",
]);
const LEGACY_OUTPUT_FAILURE_FIELDS = Object.freeze(["reason", "code"]);
const OUTPUT_FAILURE_FIELDS = Object.freeze([
  ...LEGACY_OUTPUT_FAILURE_FIELDS,
  "diagnostic",
]);
const OUTPUT_DIAGNOSTIC_VALUE_PATTERN = /^[a-zA-Z0-9_.[\]-]{1,128}$/u;
const BOOTSTRAP_CORRECTION_FIELDS = Object.freeze([
  "attempt",
  ...OUTPUT_DIAGNOSTIC_FIELDS,
]);
const FINALIZATION_CORRECTION_FIELDS = Object.freeze([
  "attempt",
  "guidance",
  "contentFingerprint",
  ...OUTPUT_DIAGNOSTIC_FIELDS,
]);
const REVIEW_CORRECTION_FIELDS = Object.freeze([
  "attempt",
  "contentFingerprint",
  "validationInfrastructureFingerprint",
  "diagnostics",
]);
const LAZY_CORRECTION_FIELDS = Object.freeze([
  "attempt",
  "fixRoundCharged",
  "phase",
  "contentFingerprint",
  "validationInfrastructureFingerprint",
  "diagnostics",
]);
export const RESOLUTION_OUTPUT_RETRY_EXPLANATION =
  "The bounded read-only finding-resolution report restatement remains invalid or was lost. Resume this checkpoint to authorize one further read-only restatement; reconciled work and blockers are preserved.";
export const LAZY_OUTPUT_RETRY_EXPLANATION =
  "The bounded automatic lazy checkpoint correction remains invalid. Retry the same correction after the backend can satisfy the unchanged contract.";
const EDIT_PAUSE_REASONS = Object.freeze({
  "clarification-answers": "clarification_answers_required",
  "product-decision": "product_decision_required",
  "proactive-clarification": "proactive_clarification",
});
const PAUSE_RESUME_STATES = Object.freeze({
  output_exhausted: Object.freeze([
    "CLARIFY",
    "BOOTSTRAP",
    "POLISH",
    "FINALIZE",
    "CHECK_AND_FIX",
    "CLEAN_CONFIRM",
    "REVIEW",
    "CONFIRM",
    "RESOLVE_FINDINGS",
  ]),
  authentication_required: Object.freeze([
    "CLARIFY",
    "BOOTSTRAP",
    "POLISH",
    "FINALIZE",
    "CHECK_AND_FIX",
    "CLEAN_CONFIRM",
    "REVIEW",
    "CONFIRM",
    "RESOLVE_FINDINGS",
  ]),
  bootstrap_disagreement: Object.freeze([
    "BOOTSTRAP",
    "POLISH",
    "REVIEW",
    "CHECK_AND_FIX",
    "FINALIZE",
    "CONFIRM",
    "RESOLVE_FINDINGS",
  ]),
  backend_unavailable: Object.freeze([
    "CLARIFY",
    "BOOTSTRAP",
    "POLISH",
    "FINALIZE",
    "CHECK_AND_FIX",
    "CLEAN_CONFIRM",
    "REVIEW",
    "CONFIRM",
    "RESOLVE_FINDINGS",
  ]),
  environment_blocked: Object.freeze([
    "CLARIFY",
    "BOOTSTRAP",
    "POLISH",
    "FINALIZE",
    "CHECK_AND_FIX",
    "CLEAN_CONFIRM",
    "REVIEW",
    "RESOLVE_FINDINGS",
    "CONFIRM",
    "HANDOFF",
  ]),
  finalization_cannot_pass: Object.freeze(["FINALIZE"]),
  finalization_evidence_rejected: Object.freeze(["FINALIZE"]),
  finalization_skill_invalid: Object.freeze(["FINALIZE"]),
  finalization_skill_missing: Object.freeze(["FINALIZE"]),
  confirmation_output_invalid: Object.freeze(["CONFIRM"]),
  review_output_invalid: Object.freeze(["REVIEW"]),
  lazy_output_invalid: Object.freeze(["CHECK_AND_FIX", "CLEAN_CONFIRM"]),
  resolution_output_invalid: Object.freeze(["RESOLVE_FINDINGS"]),
  finding_repair_required: Object.freeze(["RESOLVE_FINDINGS"]),
  fix_limit_reached: Object.freeze([
    "POLISH",
    "CHECK_AND_FIX",
    "RESOLVE_FINDINGS",
  ]),
  no_progress: Object.freeze(["CHECK_AND_FIX", "RESOLVE_FINDINGS"]),
});

export class PolishingWorkflowError extends Error {
  constructor(
    message,
    { cause, code = "ERR_POLISHING_WORKFLOW", diagnostic, diagnostics } = {},
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PolishingWorkflowError";
    this.code = code;
    if (diagnostic !== undefined) {
      this.diagnostic = Object.freeze({ ...diagnostic });
    }
    if (diagnostics !== undefined) {
      this.diagnostics = Object.freeze(
        diagnostics.map((entry) => Object.freeze({ ...entry })),
      );
    }
  }
}

export function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function workflowError(
  message,
  code = "ERR_INVALID_POLISHING_STATE",
  diagnostic,
) {
  return new PolishingWorkflowError(message, { code, diagnostic });
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function finalizationGuidanceFingerprint({
  configuredPolicy,
  selection,
  skillPath,
  selectedFileFingerprint,
}) {
  return sha256(
    JSON.stringify({
      configuredPolicy,
      selection,
      skillPath,
      selectedFileFingerprint,
    }),
  );
}

export function createFinalizationGuidanceDecision({
  configuredPolicy,
  skillPath = null,
  selectedFileFingerprint = null,
  selection = skillPath === null ? "fallback" : "skill",
}) {
  return normalizeFinalizationGuidanceDecision({
    configuredPolicy,
    selection,
    skillPath,
    selectedFileFingerprint,
    decisionFingerprint: finalizationGuidanceFingerprint({
      configuredPolicy,
      selection,
      skillPath,
      selectedFileFingerprint,
    }),
  });
}

export function normalizeFinalizationGuidanceDecision(value) {
  if (value === null) return null;
  assertExactFields(
    value,
    FINALIZATION_GUIDANCE_FIELDS,
    "Polishing finalization guidance",
  );
  const fallback = value.selection === "fallback";
  const selected = ["skill", "file"].includes(value.selection);
  const configuredPolicy = value.configuredPolicy;
  const selectedPath =
    value.selection === "file" &&
    typeof value.skillPath === "string" &&
    value.skillPath.startsWith("finalization://")
      ? value.skillPath.slice("finalization://".length)
      : value.skillPath;
  const validSelectedPath =
    selected &&
    isFinalizationPolicy(selectedPath) &&
    !["auto", "none"].includes(selectedPath) &&
    (value.selection !== "skill" ||
      value.skillPath === "SKILL.md" ||
      value.skillPath.endsWith("/SKILL.md")) &&
    HASH_PATTERN.test(value.selectedFileFingerprint ?? "") &&
    (configuredPolicy === "auto"
      ? CONVENTIONAL_FINALIZATION_SKILL_PATHS.includes(value.skillPath)
      : configuredPolicy === selectedPath);
  if (
    !isFinalizationPolicy(configuredPolicy) ||
    (!fallback && !selected) ||
    (fallback &&
      (!["auto", "none"].includes(configuredPolicy) ||
        value.skillPath !== null ||
        value.selectedFileFingerprint !== null)) ||
    (selected && !validSelectedPath) ||
    !HASH_PATTERN.test(value.decisionFingerprint) ||
    value.decisionFingerprint !== finalizationGuidanceFingerprint(value)
  ) {
    throw workflowError("Polishing finalization guidance is invalid.");
  }
  return value;
}

function capabilityError() {
  return workflowError("Trusted execution capabilities are invalid.");
}

function normalizeCapabilities(value, { sourceProjection = true } = {}) {
  const allowed = [
    "scratch",
    "cache",
    "artifacts",
    ...(sourceProjection ? ["sourceProjection"] : []),
  ];
  if (
    !isRecord(value) ||
    Object.keys(value).some((key) => !allowed.includes(key))
  ) {
    throw capabilityError();
  }
  const normalized = {};
  for (const key of ["scratch", "cache"]) {
    if (Object.hasOwn(value, key)) {
      if (value[key] !== true) throw capabilityError();
      normalized[key] = true;
    }
  }
  if (Object.hasOwn(value, "sourceProjection")) {
    if (value.sourceProjection !== true) throw capabilityError();
    normalized.sourceProjection = true;
  }
  if (Object.hasOwn(value, "artifacts")) {
    if (
      !Array.isArray(value.artifacts) ||
      value.artifacts.length === 0 ||
      value.artifacts.length > 32
    )
      throw capabilityError();
    normalized.artifacts = Object.freeze(
      value.artifacts.map((artifact) => {
        if (
          !isRecord(artifact) ||
          Object.keys(artifact).length !== 2 ||
          !Object.hasOwn(artifact, "url") ||
          !Object.hasOwn(artifact, "sha256") ||
          typeof artifact.url !== "string" ||
          artifact.url.length > 4000 ||
          typeof artifact.sha256 !== "string" ||
          !/^[a-f0-9]{64}$/u.test(artifact.sha256)
        )
          throw capabilityError();
        let url;
        try {
          url = new URL(artifact.url);
        } catch {
          throw capabilityError();
        }
        // DNS and connection enforcement belong to acquisition, never the check.
        if (
          url.protocol !== "https:" ||
          url.username ||
          url.password ||
          artifact.url.includes("#") ||
          url.port ||
          url.href !== artifact.url ||
          !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/u.test(url.hostname) ||
          /(?:^|\.)(?:localhost|local|internal|test|invalid)$/u.test(
            url.hostname,
          ) ||
          /^[0-9.]+$/u.test(url.hostname)
        )
          throw capabilityError();
        return Object.freeze({ url: url.href, sha256: artifact.sha256 });
      }),
    );
    if (
      new Set(normalized.artifacts.map(({ url }) => url)).size !==
      normalized.artifacts.length
    )
      throw capabilityError();
  }
  return Object.freeze(normalized);
}

function trustedCommandIdentity(command) {
  return sha256(
    JSON.stringify({
      alias: command.alias,
      command: command.command,
      executable: command.executable,
      arguments: command.arguments,
      ...(command.capabilities === undefined
        ? {}
        : { capabilities: command.capabilities }),
    }),
  );
}

function trustedValidationFingerprints(
  commands,
  schemaVersion = 1,
  timeoutMs = undefined,
) {
  return Object.freeze({
    commandFingerprint: sha256(
      JSON.stringify(commands.map(({ identity }) => identity)),
    ),
    configurationFingerprint: sha256(
      JSON.stringify({
        schemaVersion,
        commands: commands.map(
          ({
            alias,
            command,
            executable,
            arguments: argumentsList,
            capabilities,
          }) => ({
            alias,
            command,
            executable,
            arguments: argumentsList,
            ...(capabilities === undefined ? {} : { capabilities }),
          }),
        ),
        ...(schemaVersion >= 3 ? { timeoutMs } : {}),
      }),
    ),
  });
}

function normalizeExactVectorText(
  value,
  name,
  { allowEmpty = false, allowLineFeeds = false, requireTrimmed = false } = {},
) {
  const inspected =
    allowLineFeeds && typeof value === "string"
      ? value.replaceAll("\n", "")
      : value;
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    [...value].length > MAX_TEXT_LENGTH ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(inspected) ||
    (requireTrimmed && value.trim() !== value)
  ) {
    throw workflowError(`${name} is invalid.`);
  }
  return value;
}

function normalizeTrustedValidation(value) {
  const snapshotVersion = value?.schemaVersion;
  const snapshotFields = [
    ...TRUSTED_VALIDATION_FIELDS,
    ...(snapshotVersion >= 3 ? ["timeoutMs"] : []),
  ];
  if (
    !isRecord(value) ||
    Object.keys(value).length !== snapshotFields.length ||
    snapshotFields.some((field) => !Object.hasOwn(value, field)) ||
    ![1, 2, 3, 4].includes(snapshotVersion) ||
    !Array.isArray(value.commands) ||
    value.commands.length > MAX_ITEMS ||
    !HASH_PATTERN.test(value.commandFingerprint) ||
    !HASH_PATTERN.test(value.configurationFingerprint) ||
    (snapshotVersion >= 3 &&
      (!Number.isInteger(value.timeoutMs) ||
        value.timeoutMs < 1 ||
        value.timeoutMs > MAX_TRUSTED_COMMAND_TIMEOUT_MS))
  ) {
    throw workflowError("Polishing trusted validation is invalid.");
  }
  const commandFields = [
    ...TRUSTED_COMMAND_FIELDS,
    ...(snapshotVersion >= 2 ? ["capabilities"] : []),
  ];
  const commands = Object.freeze(
    value.commands.map((command, index) => {
      if (
        !isRecord(command) ||
        Object.keys(command).length !== commandFields.length ||
        commandFields.some((field) => !Object.hasOwn(command, field)) ||
        !TRUSTED_ALIAS_PATTERN.test(command.alias) ||
        !Array.isArray(command.arguments) ||
        command.arguments.length > 64 ||
        !HASH_PATTERN.test(command.identity)
      ) {
        throw workflowError(
          `Polishing trusted command ${index + 1} is invalid.`,
        );
      }
      const normalized = Object.freeze({
        alias: command.alias,
        command: normalizeExactVectorText(
          command.command,
          `trusted command ${command.alias} command`,
          { requireTrimmed: true },
        ),
        executable: normalizeExactVectorText(
          command.executable,
          `trusted command ${command.alias} executable`,
          { requireTrimmed: true },
        ),
        arguments: Object.freeze(
          command.arguments.map((argument) =>
            normalizeExactVectorText(
              argument,
              `trusted command ${command.alias} argument`,
              { allowEmpty: true, allowLineFeeds: true },
            ),
          ),
        ),
        ...(snapshotVersion >= 2
          ? {
              capabilities: normalizeCapabilities(command.capabilities, {
                sourceProjection: snapshotVersion >= 4,
              }),
            }
          : {}),
        identity: command.identity,
      });
      if (trustedCommandIdentity(normalized) !== command.identity) {
        throw workflowError(
          `Polishing trusted command ${command.alias} identity is invalid.`,
        );
      }
      return normalized;
    }),
  );
  if (
    new Set(commands.map(({ alias }) => alias)).size !== commands.length ||
    new Set(commands.map(({ command }) => command)).size !== commands.length ||
    new Set(commands.map(({ identity }) => identity)).size !== commands.length
  ) {
    throw workflowError("Polishing trusted commands must be unique.");
  }
  const fingerprints = trustedValidationFingerprints(
    commands,
    snapshotVersion,
    value.timeoutMs,
  );
  if (
    value.commandFingerprint !== fingerprints.commandFingerprint ||
    value.configurationFingerprint !== fingerprints.configurationFingerprint
  ) {
    throw workflowError("Polishing trusted validation fingerprint is invalid.");
  }
  return Object.freeze({
    schemaVersion: snapshotVersion,
    ...(snapshotVersion >= 3 ? { timeoutMs: value.timeoutMs } : {}),
    commands,
    ...fingerprints,
  });
}

export const EMPTY_TRUSTED_VALIDATION = Object.freeze(
  normalizeTrustedValidation({
    schemaVersion: 1,
    commands: Object.freeze([]),
    ...trustedValidationFingerprints([]),
  }),
);

function serializedBytes(value) {
  try {
    const serialized = JSON.stringify(value);
    return typeof serialized === "string"
      ? Buffer.byteLength(serialized)
      : Number.POSITIVE_INFINITY;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

export function disputeHistoryFits(value) {
  return serializedBytes(value) <= MAX_DISPUTE_HISTORY_BYTES;
}

export function assertDisputeHistoryFits(
  value,
  code = "ERR_INVALID_POLISHING_STATE",
) {
  if (!disputeHistoryFits(value)) {
    throw workflowError(
      "Polishing dispute evidence exceeds its durable history limit.",
      code,
    );
  }
}

function outputConstraint(field, constraint) {
  return Object.freeze({ field, constraint });
}

function outputError(message, diagnostic) {
  return workflowError(message, INVALID_OUTPUT_CODE, diagnostic);
}

export function isOutputDiagnostic(value) {
  return (
    isRecord(value) &&
    Object.keys(value).length === OUTPUT_DIAGNOSTIC_FIELDS.length &&
    OUTPUT_DIAGNOSTIC_FIELDS.every(
      (field) =>
        typeof value[field] === "string" &&
        OUTPUT_DIAGNOSTIC_VALUE_PATTERN.test(value[field]),
    )
  );
}

const FINALIZATION_DIAGNOSTIC_CONSTRAINTS = new Set([
  "object",
  "exact-field-set",
  "maximum-2-mebibytes",
  "serializable-json",
  "semantic-contract",
  "finalization-status",
  "empty-string",
  "empty-array",
  "empty-for-unavailable-finalization",
  "selected-finalization-guidance",
  "resolved-finalization-skill",
  "includes-frozen-finalization-guidance",
  "includes-runner-trusted-commands",
  "preserves-established-checks",
  "preserves-established-infrastructure",
  "existing-canonical-repository-file",
  "array-up-to-32-items",
  "nonempty-array-up-to-32-items",
  "array-up-to-16-items",
  "array-up-to-512-items",
  "nonempty-array-up-to-512-items",
  "exactly-three-policy-evidence-items",
  "unique-ids",
  "unique-ids-and-commands",
  "unique-paths",
  "required-check-id",
  "finalization-issue-id",
  "complete-ordered-check-results",
  "required-check-id-in-order",
  "check-result-status",
  "runner-trusted-check-not-run",
  "agent-executed-check-status",
  "required-check-command",
  "staging-independent-validation-command",
  "empty-when-pass",
  "nonempty-when-fail",
  "pass-status-check-consistency",
  "fail-status-check-consistency",
  "blocked-status-check-consistency",
  "nonempty-plain-text-up-to-4000-characters",
  "concise-markdown-up-to-20000-characters",
  "repository-relative-path-up-to-4000-characters",
  "exact-repository-relative-path-up-to-4000-characters",
  "exact-single-line-command-up-to-4000-characters",
]);
const FINALIZATION_DIAGNOSTIC_FIELD_PATTERNS = [
  /^(?:result|status|skillPath|summary|reason|question|whyBlocked|options|evidence|issues|checks|requiredChecks|validationInfrastructure)$/u,
  /^options\[(?:[0-9]|1[0-5])\]$/u,
  /^evidence\[(?:[0-9]|[12][0-9]|3[01])\]$/u,
  /^issues\[(?:[0-9]|[12][0-9]|3[01])\](?:\.(?:id|command|problem|evidence(?:\[(?:[0-9]|[12][0-9]|3[01])\])?))?$/u,
  /^requiredChecks\[(?:[0-9]|[1-9][0-9]|[1-4][0-9]{2}|50[0-9]|51[01])\](?:\.(?:id|command))?$/u,
  /^checks\[(?:[0-9]|[1-9][0-9]|[1-4][0-9]{2}|50[0-9]|51[01])\](?:\.(?:checkId|command|status|evidence(?:\[(?:[0-9]|[12][0-9]|3[01])\])?))?$/u,
  /^validationInfrastructure\[(?:[0-9]|[1-9][0-9]|[1-4][0-9]{2}|50[0-9]|51[01])\]$/u,
];

// Retain legacy diagnostic shapes, but reduce unrecognized identities before
// corrective requests, errors or public projections can expose them.
export function finalizationDiagnostic(value) {
  return isRecord(value) &&
    typeof value.field === "string" &&
    FINALIZATION_DIAGNOSTIC_FIELD_PATTERNS.some((pattern) =>
      pattern.test(value.field),
    ) &&
    FINALIZATION_DIAGNOSTIC_CONSTRAINTS.has(value.constraint)
    ? outputConstraint(value.field, value.constraint)
    : outputConstraint("result", "semantic-contract");
}

function hasExactFields(value, fields) {
  return (
    isRecord(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function assertExactFields(value, fields, name, code) {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== fields.length ||
    Object.keys(value).some((field) => !fields.includes(field))
  ) {
    throw workflowError(`${name} has invalid fields.`, code);
  }
}

function assertExactOutputFields(value, fields, field = "result") {
  if (!hasExactFields(value, fields)) {
    throw outputError(
      "Structured role result has an invalid field set.",
      outputConstraint(field, "exact-field-set"),
    );
  }
}

function assertStructuredResult(
  payload,
  diagnostic = outputConstraint("result", "maximum-2-mebibytes"),
) {
  let serialized;
  try {
    serialized = JSON.stringify(payload);
  } catch {
    throw outputError(
      "Structured role result must be serializable.",
      outputConstraint("result", "serializable-json"),
    );
  }
  if (
    typeof serialized !== "string" ||
    Buffer.byteLength(serialized) > MAX_STRUCTURED_RESULT_BYTES
  ) {
    throw outputError("Structured role result is too large.", diagnostic);
  }
}

function normalizeText(
  value,
  name,
  code = "ERR_INVALID_POLISHING_STATE",
  diagnostic,
) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > MAX_TEXT_LENGTH ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  ) {
    throw workflowError(
      `${name} must be concise plain text.`,
      code,
      diagnostic,
    );
  }
  return value.trim().replace(/\s+/gu, " ");
}

function normalizeSummary(
  value,
  name,
  code = "ERR_INVALID_POLISHING_STATE",
  diagnostic,
) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > MAX_SUMMARY_LENGTH ||
    /\0|\p{Zl}|\p{Zp}/u.test(value)
  ) {
    throw workflowError(`${name} must be concise Markdown.`, code, diagnostic);
  }
  return value.trim();
}

function normalizeTextList(
  value,
  name,
  {
    allowEmpty = false,
    maximum = MAX_ITEMS,
    code = INVALID_OUTPUT_CODE,
    diagnosticField,
    diagnostic,
  } = {},
) {
  if (
    !Array.isArray(value) ||
    (!allowEmpty && value.length === 0) ||
    value.length > maximum
  ) {
    throw workflowError(
      `${name} has an invalid number of items.`,
      code,
      diagnostic ??
        (diagnosticField === undefined
          ? undefined
          : outputConstraint(
              diagnosticField,
              `${allowEmpty ? "array" : "nonempty-array"}-up-to-${maximum}-items`,
            )),
    );
  }
  return Object.freeze(
    value.map((item, index) =>
      normalizeText(
        item,
        `${name}[${index}]`,
        code,
        diagnostic ??
          (diagnosticField === undefined
            ? undefined
            : outputConstraint(
                `${diagnosticField}[${index}]`,
                "nonempty-plain-text-up-to-4000-characters",
              )),
      ),
    ),
  );
}

function emptyArray(value) {
  return Array.isArray(value) && value.length === 0;
}

function emptyDecision(payload) {
  return (
    payload.question === "" &&
    payload.whyBlocked === "" &&
    emptyArray(payload.options) &&
    emptyArray(payload.evidence)
  );
}

function normalizeProductDecision(payload) {
  return Object.freeze({
    question: normalizeText(
      payload.question,
      "product decision question",
      INVALID_OUTPUT_CODE,
      outputConstraint("question", "nonempty-plain-text-up-to-4000-characters"),
    ),
    options: normalizeTextList(payload.options, "product decision options", {
      allowEmpty: true,
      diagnosticField: "options",
      maximum: MAX_OPTIONS,
    }),
    whyBlocked: normalizeText(
      payload.whyBlocked,
      "product decision rationale",
      INVALID_OUTPUT_CODE,
      outputConstraint(
        "whyBlocked",
        "nonempty-plain-text-up-to-4000-characters",
      ),
    ),
    evidence: normalizeTextList(payload.evidence, "product decision evidence", {
      diagnosticField: "evidence",
    }),
  });
}

function inactiveDecisionField(payload) {
  return ["question", "whyBlocked", "options", "evidence"].find((field) =>
    field === "question" || field === "whyBlocked"
      ? payload[field] !== ""
      : !emptyArray(payload[field]),
  );
}

export function normalizeClarificationResult(payload) {
  const fields = [
    "status",
    "questions",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(
    payload,
    fields,
    "Clarification result",
    INVALID_OUTPUT_CODE,
  );
  assertStructuredResult(payload);
  if (
    !["READY", "QUESTIONS", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError("Worker returned an invalid clarification status.");
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.questions) || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Clarification result contains inapplicable fields.");
  }
  if (
    !Array.isArray(payload.questions) ||
    payload.questions.length > MAX_ITEMS
  ) {
    throw outputError("Worker returned invalid clarification questions.");
  }
  const questions = Object.freeze(
    payload.questions.map((question, index) => {
      assertExactFields(
        question,
        ["question", "whyItMatters"],
        `Clarification question ${index + 1}`,
        INVALID_OUTPUT_CODE,
      );
      return Object.freeze({
        question: normalizeText(
          question.question,
          `clarification question ${index + 1}`,
          INVALID_OUTPUT_CODE,
        ),
        whyItMatters: normalizeText(
          question.whyItMatters,
          `clarification rationale ${index + 1}`,
          INVALID_OUTPUT_CODE,
        ),
      });
    }),
  );
  if (
    (payload.status === "READY" && questions.length !== 0) ||
    (payload.status === "QUESTIONS" && questions.length === 0)
  ) {
    throw outputError("Clarification status does not match its questions.");
  }
  return Object.freeze({ status: payload.status, questions });
}

export function normalizeBootstrapResult(
  payload,
  role,
  { trustedCommands = [] } = {},
) {
  const fields = [
    "status",
    "summary",
    "capabilityRequirements",
    "environmentBlockers",
    "requiredChecks",
    "validationInfrastructure",
    "capacityField",
    "capacityLimit",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  if (
    !isRecord(payload) ||
    !["READY", "CAPACITY_EXHAUSTED", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError(
      `${role} returned an invalid bootstrap status.`,
      outputConstraint("status", "supported-status"),
    );
  }
  assertStructuredResult(
    payload,
    outputConstraint("result", "maximum-2-mebibytes"),
  );
  assertExactOutputFields(payload, fields);
  if (
    payload.status !== "READY" &&
    (!emptyArray(payload.capabilityRequirements) ||
      !emptyArray(payload.environmentBlockers))
  ) {
    throw outputError(
      "Inactive capability reports must be empty.",
      outputConstraint("capabilityRequirements", "status-field-consistency"),
    );
  }
  if (payload.status === "CAPACITY_EXHAUSTED") {
    if (
      payload.summary !== "" ||
      !emptyArray(payload.requiredChecks) ||
      !emptyArray(payload.validationInfrastructure) ||
      payload.reason !== "" ||
      !emptyDecision(payload) ||
      !["requiredChecks", "validationInfrastructure"].includes(
        payload.capacityField,
      ) ||
      payload.capacityLimit !== MAX_BOOTSTRAP_ITEMS
    ) {
      throw outputError(
        "Bootstrap capacity result contains inapplicable fields.",
        outputConstraint("status", "status-field-consistency"),
      );
    }
    return Object.freeze({
      status: payload.status,
      capacityField: payload.capacityField,
      capacityLimit: payload.capacityLimit,
    });
  }
  if (payload.capacityField !== "" || payload.capacityLimit !== 0) {
    throw outputError(
      "Bootstrap result contains inapplicable capacity fields.",
      outputConstraint("status", "status-field-consistency"),
    );
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (
      payload.summary !== "" ||
      payload.reason !== "" ||
      !emptyArray(payload.requiredChecks) ||
      !emptyArray(payload.validationInfrastructure)
    ) {
      throw outputError(
        "Product decision contains inapplicable fields.",
        outputConstraint("status", "status-field-consistency"),
      );
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError(
      "Bootstrap result contains inapplicable fields.",
      outputConstraint("status", "status-field-consistency"),
    );
  }
  const requiredChecks = normalizePhaseSafeRequiredChecks(
    payload.requiredChecks,
    INVALID_OUTPUT_CODE,
    { maxItems: MAX_BOOTSTRAP_ITEMS },
  );
  if (!validCapabilityReports(payload, requiredChecks, trustedCommands)) {
    throw outputError(
      "Capability reports must contain actual needs and match the frozen command inventory.",
      outputConstraint(
        "capabilityRequirements",
        "exact-command-capability-reports",
      ),
    );
  }
  return Object.freeze({
    status: payload.status,
    summary: normalizeSummary(
      payload.summary,
      `${role} bootstrap summary`,
      INVALID_OUTPUT_CODE,
      outputConstraint("summary", "concise-markdown-up-to-20000-characters"),
    ),
    requiredChecks,
    capabilityRequirements: freezeReport(
      structuredClone(payload.capabilityRequirements),
    ),
    environmentBlockers: freezeReport(
      structuredClone(payload.environmentBlockers),
    ),
    validationInfrastructure: normalizeValidationInfrastructure(
      payload.validationInfrastructure,
      INVALID_OUTPUT_CODE,
      { maxItems: MAX_BOOTSTRAP_ITEMS },
    ),
  });
}

export function normalizeReconciliationResult(payload) {
  const fields = [
    "status",
    "summary",
    "disagreement",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  if (
    !isRecord(payload) ||
    !["RESOLVED", "DISAGREEMENT", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError(
      "Worker returned an invalid reconciliation status.",
      outputConstraint("status", "supported-status"),
    );
  }
  assertStructuredResult(
    payload,
    outputConstraint("result", "maximum-2-mebibytes"),
  );
  assertExactOutputFields(payload, fields);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (
      payload.summary !== "" ||
      payload.disagreement !== "" ||
      payload.reason !== ""
    ) {
      throw outputError(
        "Product decision contains inapplicable fields.",
        outputConstraint("status", "status-field-consistency"),
      );
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.status === "RESOLVED") {
    if (
      payload.disagreement !== "" ||
      payload.reason !== "" ||
      !emptyDecision(payload)
    ) {
      throw outputError(
        "Resolved reconciliation contains inapplicable fields.",
        outputConstraint("status", "status-field-consistency"),
      );
    }
    return Object.freeze({
      status: payload.status,
      summary: normalizeSummary(
        payload.summary,
        "resolved bootstrap summary",
        INVALID_OUTPUT_CODE,
        outputConstraint("summary", "concise-markdown-up-to-20000-characters"),
      ),
    });
  }
  if (
    payload.summary !== "" ||
    payload.reason !== "" ||
    payload.question !== "" ||
    payload.whyBlocked !== "" ||
    !emptyArray(payload.options)
  ) {
    throw outputError(
      "Bootstrap disagreement contains inapplicable fields.",
      outputConstraint("status", "status-field-consistency"),
    );
  }
  return Object.freeze({
    status: payload.status,
    disagreement: Object.freeze({
      description: normalizeText(
        payload.disagreement,
        "bootstrap disagreement",
        INVALID_OUTPUT_CODE,
        outputConstraint(
          "disagreement",
          "nonempty-plain-text-up-to-4000-characters",
        ),
      ),
      evidence: normalizeTextList(
        payload.evidence,
        "bootstrap disagreement evidence",
        { code: INVALID_OUTPUT_CODE, diagnosticField: "evidence" },
      ),
    }),
  });
}

export function normalizeBootstrapArbitration(payload) {
  const fields = [
    "direction",
    "summary",
    "rationale",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  if (
    !isRecord(payload) ||
    ![
      "USE_WORKER",
      "USE_REVIEWER",
      "SYNTHESIZE",
      "PRODUCT_DECISION_REQUIRED",
    ].includes(payload.direction)
  ) {
    throw outputError(
      "Arbiter returned an invalid bootstrap direction.",
      outputConstraint("direction", "supported-direction"),
    );
  }
  assertStructuredResult(
    payload,
    outputConstraint("result", "maximum-2-mebibytes"),
  );
  assertExactOutputFields(payload, fields);
  const rationale = normalizeText(
    payload.rationale,
    "bootstrap arbitration rationale",
    INVALID_OUTPUT_CODE,
    outputConstraint("rationale", "nonempty-plain-text-up-to-4000-characters"),
  );
  if (payload.direction === "PRODUCT_DECISION_REQUIRED") {
    if (payload.summary !== "" || payload.reason !== "") {
      throw outputError(
        "Product decision contains inapplicable fields.",
        outputConstraint("direction", "direction-field-consistency"),
      );
    }
    return Object.freeze({
      direction: payload.direction,
      rationale,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError(
      "Bootstrap arbitration contains inapplicable fields.",
      outputConstraint("direction", "direction-field-consistency"),
    );
  }
  return Object.freeze({
    direction: payload.direction,
    rationale,
    summary: normalizeSummary(
      payload.summary,
      "arbitrated bootstrap summary",
      INVALID_OUTPUT_CODE,
      outputConstraint("summary", "concise-markdown-up-to-20000-characters"),
    ),
  });
}

function normalizeOptionalEvidence(value, name, code = INVALID_OUTPUT_CODE) {
  return normalizeTextList(value, name, { allowEmpty: true, code });
}

function normalizeRelativePath(
  value,
  name,
  code = INVALID_OUTPUT_CODE,
  diagnostic,
) {
  const path = normalizeText(value, name, code, diagnostic);
  if (
    isAbsolute(path) ||
    path === "." ||
    path.split(/[\\/]/u).some((part) => part === "..")
  ) {
    throw workflowError(
      `${name} must be repository-relative.`,
      code,
      diagnostic,
    );
  }
  return path;
}

function normalizeExactCommand(value, name, code, diagnostic) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_TEXT_LENGTH ||
    value.trim() !== value ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  ) {
    throw workflowError(
      `${name} must be an exact single-line command.`,
      code,
      diagnostic,
    );
  }
  return value;
}

function shellWords(command) {
  const words = [];
  let word = "";
  let quote = null;
  let escaped = false;
  function finishWord() {
    if (word.length > 0) {
      words.push(word);
      word = "";
    }
  }
  for (const character of command) {
    if (escaped) {
      word += character;
      escaped = false;
    } else if (character === "\\" && quote !== "'") {
      escaped = true;
    } else if (quote !== null) {
      if (character === quote) {
        quote = null;
      } else {
        word += character;
      }
    } else if (character === "'" || character === '"') {
      quote = character;
    } else if (/\s/u.test(character)) {
      finishWord();
    } else if (SHELL_SEPARATOR_PATTERN.test(character)) {
      finishWord();
      words.push(character);
    } else {
      word += character;
    }
  }
  finishWord();
  return words.flatMap((candidate) =>
    /\s/u.test(candidate) ? shellWords(candidate) : candidate,
  );
}

function gitSubcommand(words, gitIndex) {
  let index = gitIndex + 1;
  while (index < words.length && !SHELL_SEPARATOR_PATTERN.test(words[index])) {
    const word = words[index];
    if (
      [
        "-C",
        "-c",
        "--config-env",
        "--git-dir",
        "--namespace",
        "--work-tree",
      ].includes(word)
    ) {
      index += 2;
    } else if (word.startsWith("-")) {
      index += 1;
    } else {
      return Object.freeze({ command: word.toLowerCase(), index });
    }
  }
  return null;
}

function diffUsesExplicitTrees(words, commandIndex) {
  for (let index = commandIndex + 1; index < words.length; index += 1) {
    const word = words[index];
    if (SHELL_SEPARATOR_PATTERN.test(word)) {
      break;
    }
    if (word === "--no-index" || EXPLICIT_TREE_PATTERN.test(word)) {
      return true;
    }
  }
  return false;
}

function gitArgumentsUseIndex(words, commandIndex) {
  const argumentsList = [];
  for (let index = commandIndex + 1; index < words.length; index += 1) {
    if (SHELL_SEPARATOR_PATTERN.test(words[index])) {
      break;
    }
    argumentsList.push(words[index]);
  }
  return (
    argumentsList.some(
      (word) =>
        /^:(?:[0-3]:)?[^/]/u.test(word) ||
        [
          "--3way",
          "--index",
          "--intent-to-add",
          "--ita-invisible-in-index",
          "--ita-visible-in-index",
        ].includes(word),
    ) ||
    argumentsList.some(
      (word, index) =>
        word === "--git-path" && argumentsList[index + 1] === "index",
    )
  );
}

function isStagingIndependentCommand(command) {
  if (
    /(?:^|[^a-zA-Z0-9_])GIT_INDEX_FILE\s*=/u.test(command) ||
    /(?:^|[\s'"(])(?:\.git|\$GIT_DIR)\/index(?:$|[\s'"),;&|])/u.test(command) ||
    /(?:^|[\s'"=])--(?:cached|staged)(?:$|[\s'",);&|])/iu.test(command) ||
    /(?:draft|prepare)[-_:]?commit(?:[-_:]?(?:msg|message))?/iu.test(command)
  ) {
    return false;
  }
  const words = shellWords(command);
  for (const [index, word] of words.entries()) {
    if (!/(?:^|\/)git$/iu.test(word)) {
      continue;
    }
    const subcommand = gitSubcommand(words, index);
    if (subcommand === null) {
      continue;
    }
    if (
      INDEX_WRITING_GIT_COMMANDS.has(subcommand.command) ||
      INDEX_INSPECTING_GIT_COMMANDS.has(subcommand.command) ||
      gitArgumentsUseIndex(words, subcommand.index) ||
      (subcommand.command === "diff" &&
        !diffUsesExplicitTrees(words, subcommand.index))
    ) {
      return false;
    }
  }
  return true;
}

function normalizePhaseSafeRequiredChecks(value, code, options) {
  const checks = normalizeRequiredChecks(value, code, options);
  for (const [index, check] of checks.entries()) {
    if (!isStagingIndependentCommand(check.command)) {
      throw workflowError(
        "Required check must be staging-independent.",
        code,
        outputConstraint(
          `requiredChecks[${index}].command`,
          "staging-independent-validation-command",
        ),
      );
    }
  }
  return checks;
}

function normalizeValidationInfrastructurePath(value, name, code, diagnostic) {
  // This non-path namespace cannot shadow a canonical repository-relative file.
  if (typeof value === "string" && value.startsWith("finalization://")) {
    const path = value.slice("finalization://".length);
    if (
      isFinalizationPolicy(path) &&
      path.endsWith(".md") &&
      path.trim() === path
    ) {
      return value;
    }
  }
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_TEXT_LENGTH ||
    value.trim() !== value ||
    value.includes("\\") ||
    value.endsWith("/") ||
    /^[a-zA-Z]:\//u.test(value) ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value) ||
    posix.isAbsolute(value) ||
    posix.normalize(value) !== value ||
    value === "." ||
    value === ".git" ||
    value.startsWith(".git/") ||
    value.split("/").some((part) => part === "..")
  ) {
    throw workflowError(
      `${name} must be an exact repository-relative path.`,
      code,
      diagnostic,
    );
  }
  return value;
}

function normalizeRequiredChecks(
  value,
  code,
  { allowEmpty = false, maxItems = MAX_VALIDATION_ITEMS } = {},
) {
  if (
    !Array.isArray(value) ||
    (!allowEmpty && value.length === 0) ||
    value.length > maxItems
  ) {
    throw workflowError(
      "Required-check inventory is invalid.",
      code,
      outputConstraint(
        "requiredChecks",
        allowEmpty
          ? `array-up-to-${maxItems}-items`
          : `nonempty-array-up-to-${maxItems}-items`,
      ),
    );
  }
  const checks = Object.freeze(
    value.map((check, index) => {
      if (!hasExactFields(check, REQUIRED_CHECK_FIELDS)) {
        throw workflowError(
          "Required check has an invalid field set.",
          code,
          outputConstraint(`requiredChecks[${index}]`, "exact-field-set"),
        );
      }
      if (!REQUIRED_CHECK_ID_PATTERN.test(check.id)) {
        throw workflowError(
          "Required check has an invalid ID.",
          code,
          outputConstraint(`requiredChecks[${index}].id`, "required-check-id"),
        );
      }
      return Object.freeze({
        id: check.id,
        command: normalizeExactCommand(
          check.command,
          `required check ${check.id} command`,
          code,
          outputConstraint(
            `requiredChecks[${index}].command`,
            "exact-single-line-command-up-to-4000-characters",
          ),
        ),
      });
    }),
  );
  if (
    new Set(checks.map(({ id }) => id)).size !== checks.length ||
    new Set(checks.map(({ command }) => command)).size !== checks.length
  ) {
    throw workflowError(
      "Required checks must have unique IDs and commands.",
      code,
      outputConstraint("requiredChecks", "unique-ids-and-commands"),
    );
  }
  return checks;
}

function normalizeValidationInfrastructure(
  value,
  code,
  { maxItems = MAX_VALIDATION_ITEMS } = {},
) {
  if (!Array.isArray(value) || value.length > maxItems) {
    throw workflowError(
      "Validation infrastructure is invalid.",
      code,
      outputConstraint(
        "validationInfrastructure",
        `array-up-to-${maxItems}-items`,
      ),
    );
  }
  const paths = Object.freeze(
    value.map((path, index) =>
      normalizeValidationInfrastructurePath(
        path,
        `validation infrastructure[${index}]`,
        code,
        outputConstraint(
          `validationInfrastructure[${index}]`,
          "exact-repository-relative-path-up-to-4000-characters",
        ),
      ),
    ),
  );
  if (new Set(paths).size !== paths.length) {
    throw workflowError(
      "Validation infrastructure paths must be unique.",
      code,
      outputConstraint("validationInfrastructure", "unique-paths"),
    );
  }
  return paths;
}

function normalizeCheckResults(
  value,
  requiredChecks,
  code,
  { trustedCommands = new Set() } = {},
) {
  if (!Array.isArray(value) || value.length !== requiredChecks.length) {
    throw workflowError(
      "Finalization check evidence is incomplete.",
      code,
      outputConstraint("checks", "complete-ordered-check-results"),
    );
  }
  return Object.freeze(
    value.map((result, index) => {
      const required = requiredChecks[index];
      const field = `checks[${index}]`;
      const reject = (name, constraint) => {
        throw workflowError(
          "Finalization check evidence was substituted.",
          code,
          outputConstraint(name, constraint),
        );
      };
      if (!isRecord(result)) reject(field, "object");
      if (result.checkId !== required.id)
        reject(`${field}.checkId`, "required-check-id-in-order");
      if (!["PASS", "FAIL", "BLOCKED", "NOT_RUN"].includes(result.status))
        reject(`${field}.status`, "check-result-status");
      if (
        trustedCommands.has(required.command)
          ? result.status !== "NOT_RUN"
          : result.status === "NOT_RUN"
      )
        reject(
          `${field}.status`,
          trustedCommands.has(required.command)
            ? "runner-trusted-check-not-run"
            : "agent-executed-check-status",
        );
      const command = normalizeExactCommand(
        result.command,
        "finalization check command",
        code,
        outputConstraint(
          `${field}.command`,
          "exact-single-line-command-up-to-4000-characters",
        ),
      );
      if (command !== required.command) {
        reject(`${field}.command`, "required-check-command");
      }
      return Object.freeze({
        checkId: result.checkId,
        command,
        status: result.status,
        evidence: normalizeTextList(
          result.evidence,
          "finalization check evidence",
          { code, diagnosticField: `${field}.evidence` },
        ),
      });
    }),
  );
}

function normalizeReviewFinding(value, code, index) {
  const field = `findings[${index}]`;
  if (!isRecord(value)) {
    throw workflowError(
      "Reviewer finding has an invalid ID.",
      code,
      outputConstraint(field, "object"),
    );
  }
  if (!REVIEW_FINDING_ID_PATTERN.test(value.id)) {
    throw workflowError(
      "Reviewer finding has an invalid ID.",
      code,
      outputConstraint(`${field}.id`, "review-finding-id"),
    );
  }
  if (
    !hasExactFields(value, [
      "id",
      "file",
      "problem",
      "reason",
      "suggestedAction",
    ])
  ) {
    throw workflowError(
      `finding ${value.id} has invalid fields.`,
      code,
      outputConstraint(field, "exact-field-set"),
    );
  }
  const text = (name, label) =>
    normalizeText(
      value[name],
      `finding ${value.id} ${label}`,
      code,
      outputConstraint(
        `${field}.${name}`,
        "nonempty-plain-text-up-to-4000-characters",
      ),
    );
  return Object.freeze({
    id: value.id,
    file: normalizeRelativePath(
      value.file,
      `finding ${value.id} file`,
      code,
      outputConstraint(
        `${field}.file`,
        "repository-relative-path-up-to-4000-characters",
      ),
    ),
    problem: text("problem", "problem"),
    reason: text("reason", "reason"),
    suggestedAction: text("suggestedAction", "suggested action"),
  });
}

function normalizeReviewFindings(value, code = INVALID_OUTPUT_CODE) {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw workflowError(
      "Reviewer findings have an invalid number of items.",
      code,
      outputConstraint("findings", "array-up-to-32-items"),
    );
  }
  const findings = Object.freeze(
    value.map((finding, index) => normalizeReviewFinding(finding, code, index)),
  );
  if (new Set(findings.map(({ id }) => id)).size !== findings.length) {
    throw workflowError(
      "Reviewer finding IDs must be unique.",
      code,
      outputConstraint("findings", "unique-ids"),
    );
  }
  return findings;
}

function normalizeFinalizationIssues(value, code = INVALID_OUTPUT_CODE) {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw workflowError(
      "Finalization issues have an invalid number of items.",
      code,
      outputConstraint("issues", "array-up-to-32-items"),
    );
  }
  const issues = Object.freeze(
    value.map((issue, index) => {
      const field = `issues[${index}]`;
      if (!isRecord(issue))
        throw workflowError(
          "Finalization issue has an invalid ID.",
          code,
          outputConstraint(field, "object"),
        );
      if (!FINALIZATION_ISSUE_ID_PATTERN.test(issue.id))
        throw workflowError(
          "Finalization issue has an invalid ID.",
          code,
          outputConstraint(`${field}.id`, "finalization-issue-id"),
        );
      if (!hasExactFields(issue, ["id", "command", "problem", "evidence"]))
        throw workflowError(
          "Finalization issue has invalid fields.",
          code,
          outputConstraint(field, "exact-field-set"),
        );
      return Object.freeze({
        id: issue.id,
        command: normalizeText(
          issue.command,
          "finalization issue command",
          code,
          outputConstraint(
            `${field}.command`,
            "nonempty-plain-text-up-to-4000-characters",
          ),
        ),
        problem: normalizeText(
          issue.problem,
          "finalization issue problem",
          code,
          outputConstraint(
            `${field}.problem`,
            "nonempty-plain-text-up-to-4000-characters",
          ),
        ),
        evidence: normalizeTextList(
          issue.evidence,
          "finalization issue evidence",
          { code, diagnosticField: `${field}.evidence` },
        ),
      });
    }),
  );
  if (new Set(issues.map(({ id }) => id)).size !== issues.length) {
    throw workflowError(
      "Finalization issue IDs must be unique.",
      code,
      outputConstraint("issues", "unique-ids"),
    );
  }
  return issues;
}

// Builds the bounded runner issue for a staging-independent hygiene failure.
export function runnerHygieneIssue(id, { tracked, paths, omitted }) {
  const evidence = tracked
    ? ["Tracked changes relative to HEAD have whitespace errors."]
    : [];
  let unlisted = omitted;
  for (const path of paths) {
    const line = `New file has whitespace errors: ${path}`;
    let normalized;
    try {
      normalized = normalizeText(line, "hygiene evidence");
    } catch {}
    if (normalized === line) evidence.push(line);
    else unlisted += 1;
  }
  if (unlisted > 0)
    evidence.push(`${unlisted} more paths have whitespace errors.`);
  return Object.freeze({
    id,
    command: RUNNER_HYGIENE_ISSUE_COMMAND,
    problem:
      "Finalized content fails Runner whitespace hygiene and cannot be staged; repair the reported whitespace.",
    evidence: Object.freeze(evidence),
  });
}

function normalizeValidationPolicyBlocked(payload) {
  for (const field of ["summary", "skillPath", "question", "whyBlocked"])
    if (Object.hasOwn(payload, field) && payload[field] !== "")
      throw outputError(
        "Policy stop contains an inactive field.",
        outputConstraint(field, "empty-string"),
      );
  for (const field of [
    "decisions",
    "issues",
    "requiredChecks",
    "validationInfrastructure",
    "checks",
    "options",
  ])
    if (Object.hasOwn(payload, field) && !emptyArray(payload[field]))
      throw outputError(
        "Policy stop contains an inactive field.",
        outputConstraint(field, "empty-array"),
      );
  const reason = normalizeText(
    payload.reason,
    "validation policy blocker",
    INVALID_OUTPUT_CODE,
    outputConstraint("reason", "nonempty-plain-text-up-to-4000-characters"),
  );
  const evidence = normalizeTextList(
    payload.evidence,
    "validation policy evidence",
    { code: INVALID_OUTPUT_CODE, diagnosticField: "evidence" },
  );
  if (evidence.length !== 3)
    throw outputError(
      "Policy stop requires execution, requirement and disposition evidence.",
      outputConstraint("evidence", "exactly-three-policy-evidence-items"),
    );
  return Object.freeze({
    status: "VALIDATION_POLICY_BLOCKED",
    reason,
    evidence,
  });
}

export function normalizePolishResult(payload) {
  const fields = [
    "status",
    "summary",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, "Polishing result", INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  if (
    ![
      "COMPLETED",
      "BLOCKED",
      "VALIDATION_POLICY_BLOCKED",
      "PRODUCT_DECISION_REQUIRED",
    ].includes(payload.status)
  ) {
    throw outputError("Worker returned an invalid polishing result.");
  }
  if (payload.status === "VALIDATION_POLICY_BLOCKED")
    return normalizeValidationPolicyBlocked(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (payload.summary !== "" || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.status === "BLOCKED") {
    if (
      payload.summary !== "" ||
      payload.question !== "" ||
      payload.whyBlocked !== "" ||
      !emptyArray(payload.options)
    ) {
      throw outputError(
        "Blocked polishing result contains inapplicable fields.",
      );
    }
    return Object.freeze({
      status: payload.status,
      reason: normalizeText(
        payload.reason,
        "polishing blocker",
        INVALID_OUTPUT_CODE,
      ),
      evidence: normalizeTextList(
        payload.evidence,
        "polishing blocker evidence",
      ),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError(
      "Completed polishing result contains inapplicable fields.",
    );
  }
  return Object.freeze({
    status: payload.status,
    summary: normalizeSummary(
      payload.summary,
      "polishing summary",
      INVALID_OUTPUT_CODE,
    ),
  });
}

export function normalizeCheckAndFixResult(payload) {
  const fields = [
    "status",
    "summary",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, "Check/fix result", INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  if (
    ![
      "CHANGED",
      "UNCHANGED",
      "BLOCKED",
      "VALIDATION_POLICY_BLOCKED",
      "PRODUCT_DECISION_REQUIRED",
    ].includes(payload.status)
  ) {
    throw outputError(
      "Worker returned an invalid check/fix result.",
      outputConstraint("status", "supported-status"),
    );
  }
  if (payload.status === "VALIDATION_POLICY_BLOCKED")
    return normalizeValidationPolicyBlocked(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (payload.summary !== "" || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.status === "BLOCKED") {
    if (
      payload.summary !== "" ||
      payload.question !== "" ||
      payload.whyBlocked !== "" ||
      !emptyArray(payload.options)
    ) {
      throw outputError(
        "Blocked check/fix result contains inapplicable fields.",
      );
    }
    return Object.freeze({
      status: payload.status,
      reason: normalizeText(
        payload.reason,
        "check/fix blocker",
        INVALID_OUTPUT_CODE,
      ),
      evidence: normalizeTextList(payload.evidence, "check/fix evidence", {
        code: INVALID_OUTPUT_CODE,
      }),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Check/fix result contains inapplicable fields.");
  }
  return Object.freeze({
    status: payload.status,
    summary: normalizeSummary(
      payload.summary,
      "check/fix summary",
      INVALID_OUTPUT_CODE,
    ),
  });
}

export function normalizeCandidateReviewResult(
  payload,
  previousFindings = [],
  { clean = false } = {},
) {
  const acceptedStatus = clean ? "CLEAN" : "APPROVED";
  const fields = [
    "status",
    "findings",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactOutputFields(payload, fields);
  assertStructuredResult(payload);
  if (
    ![acceptedStatus, "FINDINGS", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError(
      "Agent returned an invalid candidate-review result.",
      outputConstraint("status", "supported-status"),
    );
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.findings)) {
      throw outputError(
        "Product decision must not include findings.",
        outputConstraint("findings", "empty-for-product-decision"),
      );
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload)) {
    throw outputError(
      "Candidate review contains inapplicable fields.",
      outputConstraint(inactiveDecisionField(payload), "empty-for-review"),
    );
  }
  const findings = normalizeReviewFindings(payload.findings);
  if (
    (payload.status === acceptedStatus && findings.length !== 0) ||
    (payload.status === "FINDINGS" && findings.length === 0)
  ) {
    throw outputError(
      "Candidate-review status does not match its findings.",
      outputConstraint(
        "findings",
        payload.status === "FINDINGS"
          ? "nonempty-when-findings"
          : clean
            ? "empty-when-clean"
            : "empty-when-approved",
      ),
    );
  }
  for (const [index, finding] of findings.entries()) {
    const previous = previousFindings.find(
      (candidate) =>
        candidate.file === finding.file &&
        candidate.problem === finding.problem,
    );
    if (previous !== undefined && previous.id !== finding.id) {
      throw outputError(
        "Agent changed the ID of an unchanged finding.",
        outputConstraint(`findings[${index}].id`, "stable-finding-id"),
      );
    }
  }
  return Object.freeze({ status: payload.status, findings });
}

export function normalizeFinalizationResult(
  payload,
  { trustedCommands = [] } = {},
) {
  const fields = [
    "status",
    "skillPath",
    "summary",
    "issues",
    "requiredChecks",
    "validationInfrastructure",
    "checks",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactOutputFields(payload, fields);
  assertStructuredResult(payload);
  const statuses = [
    "PASS",
    "FAIL",
    "SKILL_MISSING",
    "SKILL_INVALID",
    "BLOCKED",
    "VALIDATION_POLICY_BLOCKED",
    "PRODUCT_DECISION_REQUIRED",
  ];
  if (!statuses.includes(payload.status)) {
    throw outputError(
      "Worker returned an invalid finalization result.",
      outputConstraint("status", "finalization-status"),
    );
  }
  const trustedCommandSet = new Set(trustedCommands);
  if (
    trustedCommandSet.size !== trustedCommands.length ||
    trustedCommands.some((command) => typeof command !== "string")
  ) {
    throw workflowError("Trusted finalization commands are invalid.");
  }
  if (payload.status === "VALIDATION_POLICY_BLOCKED")
    return normalizeValidationPolicyBlocked(payload);
  const inactive = (strings, arrays) => {
    for (const field of strings)
      if (payload[field] !== "")
        throw outputError(
          "Finalization result contains inapplicable fields.",
          outputConstraint(field, "empty-string"),
        );
    for (const field of arrays)
      if (!emptyArray(payload[field]))
        throw outputError(
          "Finalization result contains inapplicable fields.",
          outputConstraint(field, "empty-array"),
        );
  };
  const skillPath = () =>
    payload.skillPath === ""
      ? null
      : normalizeRelativePath(
          payload.skillPath,
          "finalization skill path",
          INVALID_OUTPUT_CODE,
          outputConstraint(
            "skillPath",
            "repository-relative-path-up-to-4000-characters",
          ),
        );
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    inactive(
      ["skillPath", "summary", "reason"],
      ["issues", "requiredChecks", "validationInfrastructure", "checks"],
    );
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (["SKILL_MISSING", "SKILL_INVALID", "BLOCKED"].includes(payload.status)) {
    inactive(["summary", "question", "whyBlocked"], ["issues", "options"]);
    if (payload.status === "SKILL_INVALID" && payload.skillPath === "") {
      throw outputError(
        "Finalization skill path is inapplicable.",
        outputConstraint("skillPath", "selected-finalization-guidance"),
      );
    }
    const requiredChecks = normalizePhaseSafeRequiredChecks(
      payload.requiredChecks,
      INVALID_OUTPUT_CODE,
      { allowEmpty: payload.status !== "BLOCKED" },
    );
    const validationInfrastructure = normalizeValidationInfrastructure(
      payload.validationInfrastructure,
      INVALID_OUTPUT_CODE,
    );
    const checks =
      payload.status === "BLOCKED"
        ? normalizeCheckResults(
            payload.checks,
            requiredChecks,
            INVALID_OUTPUT_CODE,
            { trustedCommands: trustedCommandSet },
          )
        : Object.freeze([]);
    if (
      payload.status !== "BLOCKED" &&
      (requiredChecks.length !== 0 ||
        validationInfrastructure.length !== 0 ||
        !emptyArray(payload.checks))
    ) {
      throw outputError(
        "Unavailable finalization contains validation evidence.",
        outputConstraint(
          requiredChecks.length !== 0
            ? "requiredChecks"
            : validationInfrastructure.length !== 0
              ? "validationInfrastructure"
              : "checks",
          "empty-for-unavailable-finalization",
        ),
      );
    }
    if (
      payload.status === "BLOCKED" &&
      (!checks.some(({ status }) => status === "BLOCKED") ||
        checks.some(({ status }) => status === "FAIL"))
    ) {
      throw outputError(
        "Blocked finalization has invalid check evidence.",
        outputConstraint("checks", "blocked-status-check-consistency"),
      );
    }
    const evidence =
      payload.status === "BLOCKED"
        ? normalizeTextList(payload.evidence, "finalization blocker evidence", {
            diagnosticField: "evidence",
          })
        : normalizeTextList(payload.evidence, "finalization evidence", {
            allowEmpty: true,
            diagnosticField: "evidence",
          });
    return Object.freeze({
      status: payload.status,
      skillPath: skillPath(),
      reason: normalizeText(
        payload.reason,
        "finalization blocker",
        INVALID_OUTPUT_CODE,
        outputConstraint("reason", "nonempty-plain-text-up-to-4000-characters"),
      ),
      evidence,
      requiredChecks,
      validationInfrastructure,
      checks,
    });
  }
  inactive(["reason", "question", "whyBlocked"], ["options", "evidence"]);
  const issues = normalizeFinalizationIssues(payload.issues);
  const requiredChecks = normalizePhaseSafeRequiredChecks(
    payload.requiredChecks,
    INVALID_OUTPUT_CODE,
  );
  const validationInfrastructure = normalizeValidationInfrastructure(
    payload.validationInfrastructure,
    INVALID_OUTPUT_CODE,
  );
  const checks = normalizeCheckResults(
    payload.checks,
    requiredChecks,
    INVALID_OUTPUT_CODE,
    { trustedCommands: trustedCommandSet },
  );
  if (
    (payload.status === "PASS" && issues.length !== 0) ||
    (payload.status === "FAIL" && issues.length === 0)
  ) {
    throw outputError(
      "Finalization status does not match its issues.",
      outputConstraint(
        "issues",
        payload.status === "PASS" ? "empty-when-pass" : "nonempty-when-fail",
      ),
    );
  }
  if (
    (payload.status === "PASS" &&
      checks.some(
        ({ command, status }) =>
          status !== "PASS" &&
          !(trustedCommandSet.has(command) && status === "NOT_RUN"),
      )) ||
    (payload.status === "FAIL" &&
      (!checks.some(({ status }) => status === "FAIL") ||
        checks.some(({ status }) => status === "BLOCKED")))
  ) {
    throw outputError(
      "Finalization status does not match its checks.",
      outputConstraint(
        "checks",
        payload.status === "PASS"
          ? "pass-status-check-consistency"
          : "fail-status-check-consistency",
      ),
    );
  }
  return Object.freeze({
    status: payload.status,
    skillPath: skillPath(),
    summary: normalizeSummary(
      payload.summary,
      "finalization summary",
      INVALID_OUTPUT_CODE,
      outputConstraint("summary", "concise-markdown-up-to-20000-characters"),
    ),
    issues,
    requiredChecks,
    validationInfrastructure,
    checks,
  });
}

export const MAX_SEMANTIC_FINALIZATION_RETRIES = 2;

export function createFinalizationRecovery() {
  return Object.freeze({
    attempts: 0,
    additionalAttempts: 0,
    required: false,
    pending: false,
    feedback: null,
  });
}

export function findingFingerprint(state) {
  return (
    state.finalizationRecovery?.feedback?.contentFingerprint ??
    state.reviewedFingerprint ??
    state.candidateReviewedFingerprint ??
    (state.finalizationResult?.status === "PASS"
      ? state.finalizedFingerprint
      : null)
  );
}

export function finalizationFeedbackFindings(state) {
  const feedback = state.finalizationRecovery?.feedback ?? null;
  return feedback === null
    ? []
    : feedback.findings.filter(({ id }) =>
        feedback.finalizationFindingIds.includes(id),
      );
}

function normalizeFinalizationFindingIds(
  value,
  findings,
  rejected,
  code = INVALID_OUTPUT_CODE,
) {
  if (
    !Array.isArray(value) ||
    value.length > MAX_ITEMS ||
    new Set(value).size !== value.length ||
    value.some(
      (id) =>
        !REVIEW_FINDING_ID_PATTERN.test(id) ||
        !findings.some((finding) => finding.id === id),
    ) ||
    (!rejected && value.length !== 0)
  ) {
    const message =
      "Finalization finding IDs must be a unique evidence-only subset of rejected terminal findings.";
    if (code === INVALID_OUTPUT_CODE) {
      throw outputError(
        message,
        outputConstraint(
          "finalizationFindingIds",
          "unique-rejected-finding-subset",
        ),
      );
    }
    throw workflowError(message, code);
  }
  return Object.freeze([...value]);
}

function normalizeFinalizationRecovery(value, state) {
  assertExactFields(
    value,
    ["attempts", "additionalAttempts", "required", "pending", "feedback"],
    "Finalization recovery",
  );
  if (
    !Number.isSafeInteger(value.attempts) ||
    value.attempts < 0 ||
    !Number.isSafeInteger(value.additionalAttempts) ||
    value.additionalAttempts < 0 ||
    !Number.isSafeInteger(
      value.additionalAttempts + MAX_SEMANTIC_FINALIZATION_RETRIES,
    ) ||
    value.attempts >
      value.additionalAttempts + MAX_SEMANTIC_FINALIZATION_RETRIES ||
    (value.additionalAttempts > 0 &&
      (value.attempts < MAX_SEMANTIC_FINALIZATION_RETRIES ||
        value.attempts <
          MAX_SEMANTIC_FINALIZATION_RETRIES + value.additionalAttempts - 1 ||
        (!value.required &&
          value.attempts !==
            MAX_SEMANTIC_FINALIZATION_RETRIES + value.additionalAttempts))) ||
    typeof value.required !== "boolean" ||
    typeof value.pending !== "boolean" ||
    (value.pending &&
      (!value.required ||
        value.attempts === 0 ||
        !["FINALIZE", "WAITING_FOR_USER", "FAILED"].includes(
          state.workflowState,
        ))) ||
    (!value.required && value.feedback !== null) ||
    (value.required &&
      (state.finalizationResult !== null ||
        state.reviewResult !== null ||
        state.finalizedFingerprint !== null ||
        state.reviewedFingerprint !== null))
  ) {
    throw workflowError("Polishing finalization recovery is inconsistent.");
  }
  if (value.feedback !== null) {
    const feedback = value.feedback;
    assertExactFields(
      feedback,
      [
        "contentFingerprint",
        "validationInfrastructureFingerprint",
        "findings",
        "finalizationFindingIds",
      ],
      "Finalization feedback",
    );
    if (
      !HASH_PATTERN.test(feedback.contentFingerprint) ||
      !HASH_PATTERN.test(feedback.validationInfrastructureFingerprint)
    ) {
      throw workflowError("Finalization feedback scope is invalid.");
    }
    const findings = normalizeReviewFindings(
      feedback.findings,
      "ERR_INVALID_POLISHING_STATE",
    );
    if (!isDeepStrictEqual(findings, feedback.findings)) {
      throw workflowError("Finalization feedback findings must be normalized.");
    }
    normalizeFinalizationFindingIds(
      feedback.finalizationFindingIds,
      findings,
      true,
      "ERR_INVALID_POLISHING_STATE",
    );
  }
  return value;
}

export function normalizeReviewResult(payload, previousFindings = []) {
  const fields = [
    "status",
    "findings",
    "validationChange",
    "validationEvidence",
    "finalizationFindingIds",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, "Review result", INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  if (
    !["APPROVED", "FINDINGS", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError("Reviewer returned an invalid review result.");
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (
      !emptyArray(payload.findings) ||
      !emptyArray(payload.finalizationFindingIds) ||
      payload.validationChange !== "UNCHANGED" ||
      !emptyArray(payload.validationEvidence)
    ) {
      throw outputError("Product decision must not include findings.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload)) {
    throw outputError("Review result contains inapplicable fields.");
  }
  const findings = normalizeReviewFindings(payload.findings);
  if (
    !["UNCHANGED", "ACCEPTED", "REJECTED"].includes(payload.validationChange)
  ) {
    throw outputError("Review validation-change decision is invalid.");
  }
  const validationEvidence = normalizeTextList(
    payload.validationEvidence,
    "review validation evidence",
    {
      allowEmpty: payload.validationChange === "UNCHANGED",
      code: INVALID_OUTPUT_CODE,
    },
  );
  if (
    (payload.status === "APPROVED" && findings.length !== 0) ||
    (payload.status === "FINDINGS" && findings.length === 0) ||
    (payload.status === "APPROVED" && payload.validationChange === "REJECTED")
  ) {
    throw outputError("Review status does not match its findings.");
  }
  for (const finding of findings) {
    const previous = previousFindings.find(
      (candidate) =>
        candidate.file === finding.file &&
        candidate.problem === finding.problem,
    );
    if (previous !== undefined && previous.id !== finding.id) {
      throw outputError("Reviewer changed the ID of an unchanged finding.");
    }
  }
  return Object.freeze({
    status: payload.status,
    findings,
    validationChange: payload.validationChange,
    validationEvidence,
    finalizationFindingIds: normalizeFinalizationFindingIds(
      payload.finalizationFindingIds,
      findings,
      payload.validationChange === "REJECTED",
    ),
  });
}

export function normalizeCleanConfirmationResult(
  payload,
  previousFindings = [],
) {
  if (
    !isRecord(payload) ||
    !["CLEAN", "FINDINGS", "PRODUCT_DECISION_REQUIRED"].includes(payload.status)
  ) {
    throw outputError("Worker returned an invalid clean confirmation result.");
  }
  const result = normalizeReviewResult(
    {
      ...payload,
      status: payload.status === "CLEAN" ? "APPROVED" : payload.status,
    },
    previousFindings,
  );
  return result.status === "APPROVED"
    ? Object.freeze({ ...result, status: "CLEAN" })
    : result;
}

const RESOLUTION_OUTPUT_FIELDS = Object.freeze([
  "status",
  "decisions",
  "reason",
  "question",
  "options",
  "whyBlocked",
  "evidence",
]);
const RESOLUTION_ARRAY_FIELDS = new Set(["decisions", "options", "evidence"]);

function assertInactiveResolutionFields(payload, fields, message) {
  const field = RESOLUTION_OUTPUT_FIELDS.find(
    (name) =>
      fields.includes(name) &&
      (RESOLUTION_ARRAY_FIELDS.has(name)
        ? !emptyArray(payload[name])
        : payload[name] !== ""),
  );
  if (field !== undefined) {
    throw outputError(
      message,
      outputConstraint(
        field,
        RESOLUTION_ARRAY_FIELDS.has(field) ? "empty-array" : "empty-string",
      ),
    );
  }
}

function decisionConstraint(index, suffix, constraint) {
  return index < MAX_ITEMS
    ? outputConstraint(`decisions[${index}]${suffix}`, constraint)
    : outputConstraint("decisions", "array-up-to-32-items");
}

export function normalizeResolutionResult(
  payload,
  blockers,
  nonDisputableIds,
  { recoveryOnly = false } = {},
) {
  assertExactOutputFields(payload, RESOLUTION_OUTPUT_FIELDS);
  assertStructuredResult(payload);
  if (
    !isRecord(payload) ||
    ![
      "RESOLVED",
      "BLOCKED",
      "VALIDATION_POLICY_BLOCKED",
      "PRODUCT_DECISION_REQUIRED",
      ...(recoveryOnly && blockers.length ? ["UNFINISHED"] : []),
    ].includes(payload.status)
  ) {
    throw outputError(
      "Worker returned an invalid finding resolution.",
      outputConstraint("status", "resolution-status"),
    );
  }
  if (payload.status === "VALIDATION_POLICY_BLOCKED")
    return normalizeValidationPolicyBlocked(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    assertInactiveResolutionFields(
      payload,
      ["decisions", "reason"],
      "Product decision must not include finding decisions.",
    );
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (["BLOCKED", "UNFINISHED"].includes(payload.status)) {
    assertInactiveResolutionFields(
      payload,
      ["decisions", "question", "whyBlocked", "options"],
      "Blocked finding resolution contains inapplicable fields.",
    );
    return Object.freeze({
      status: payload.status,
      reason: normalizeText(
        payload.reason,
        "finding-resolution blocker",
        INVALID_OUTPUT_CODE,
        outputConstraint("reason", "nonempty-plain-text-up-to-4000-characters"),
      ),
      evidence: normalizeTextList(
        payload.evidence,
        "finding-resolution blocker evidence",
        { diagnosticField: "evidence" },
      ),
    });
  }
  assertInactiveResolutionFields(
    payload,
    ["reason", "question", "whyBlocked", "options", "evidence"],
    "Finding resolution contains inapplicable fields.",
  );
  if (!Array.isArray(payload.decisions)) {
    throw outputError(
      "Finding resolution decisions must be an array.",
      outputConstraint("decisions", "array-up-to-32-items"),
    );
  }
  const expectedIds = blockers.map(({ id }) => id).sort();
  const decisions = Object.freeze(
    payload.decisions.map((decision, index) => {
      const field = `decisions[${index}]`;
      const invalid = (message, suffix, constraint) =>
        outputError(message, decisionConstraint(index, suffix, constraint));
      if (!isRecord(decision)) {
        throw invalid(
          "Worker returned an invalid finding decision.",
          "",
          "object",
        );
      }
      if (!["FIX", "DISPUTE"].includes(decision.decision)) {
        throw invalid(
          "Worker returned an invalid finding decision.",
          ".decision",
          "fix-or-dispute",
        );
      }
      if (!expectedIds.includes(decision.id)) {
        throw invalid(
          "Worker returned an invalid finding decision.",
          ".id",
          "current-blocker-id",
        );
      }
      if (!hasExactFields(decision, ["id", "decision", "reason", "evidence"])) {
        throw invalid(`${field} has invalid fields.`, "", "exact-field-set");
      }
      if (
        decision.decision === "DISPUTE" &&
        (decision.id.startsWith("F") || nonDisputableIds.has(decision.id))
      ) {
        throw invalid(
          "This blocker cannot be disputed.",
          ".decision",
          "disputable-blocker-only",
        );
      }
      return Object.freeze({
        id: decision.id,
        decision: decision.decision,
        reason: normalizeText(
          decision.reason,
          `${field}.reason`,
          INVALID_OUTPUT_CODE,
          decisionConstraint(
            index,
            ".reason",
            "nonempty-plain-text-up-to-4000-characters",
          ),
        ),
        evidence: normalizeTextList(decision.evidence, `${field}.evidence`, {
          allowEmpty: decision.decision === "FIX",
          diagnosticField: `${field}.evidence`,
          diagnostic:
            index < MAX_ITEMS
              ? undefined
              : outputConstraint("decisions", "array-up-to-32-items"),
        }),
      });
    }),
  );
  const actualIds = decisions.map(({ id }) => id).sort();
  if (
    decisions.length !== blockers.length ||
    new Set(actualIds).size !== actualIds.length ||
    actualIds.some((id, index) => id !== expectedIds[index])
  ) {
    throw outputError(
      "Worker must resolve every current blocker exactly once.",
      outputConstraint("decisions", "every-current-blocker-exactly-once"),
    );
  }
  return Object.freeze({ status: payload.status, decisions });
}

export const RESOLUTION_CORRECTION_CHECKPOINT =
  "resolve-findings:read-only:finding-resolution-correction";
export const INTERRUPTED_RESOLUTION_DIAGNOSTIC = Object.freeze({
  field: "result",
  constraint: "interrupted-response",
});
export const CATALOG_RESOLUTION_DIAGNOSTIC = Object.freeze({
  field: "result",
  constraint: "model-unavailable-during-recovery",
});

export function beginResolutionRestatement(checkpoint) {
  return {
    ...checkpoint,
    stage: "correcting",
    attempts: checkpoint.attempts + 1,
    diagnostics:
      checkpoint.diagnostics.length === 0
        ? [INTERRUPTED_RESOLUTION_DIAGNOSTIC]
        : checkpoint.diagnostics,
  };
}

export function originalResolutionCheckpoint(correction) {
  return `resolve-findings:${correction.access}:work`;
}

function observedResolutionRestatementCheckpoint(run, correction) {
  const original = originalResolutionCheckpoint(correction);
  return [run.availabilityRetry, run.inactivityRecovery].some(
    (recovery) =>
      recovery?.role === "worker" && recovery.checkpoint === original,
  )
    ? original
    : RESOLUTION_CORRECTION_CHECKPOINT;
}

export function matchesResolutionAvailabilityRetirement(
  previous,
  next,
  activeTurnStart,
) {
  const state = previous.pipelineState;
  const correction = state.resolutionCorrection;
  const episode = next.availabilityRetry;
  if (
    previous.activeTurn?.role !== "worker" ||
    previous.activeTurn.phase !== "resolve-findings" ||
    episode.role !== "worker" ||
    state.workflowState !== "RESOLVE_FINDINGS" ||
    correction?.stage !== "correcting" ||
    !["workspace-write", "read-only"].includes(correction.access) ||
    correction.productDecision !== null ||
    !Number.isSafeInteger(correction.attempts) ||
    correction.attempts < 1 ||
    correction.attempts !== correction.additionalAttempts + 1 ||
    activeTurnStart?.pipelineState == null ||
    correction.restatementStartedAfter !== activeTurnStart.previousRevision ||
    activeTurnStart.pipelineState.workflowState !== state.workflowState ||
    !isDeepStrictEqual(
      correction,
      activeTurnStart.pipelineState.resolutionCorrection,
    ) ||
    !isDeepStrictEqual(
      state.repositoryBaseline,
      activeTurnStart.pipelineState.repositoryBaseline,
    ) ||
    episode.contentFingerprint !==
      state.repositoryBaseline?.contentFingerprint ||
    episode.contentFingerprint !== correction.candidate?.contentFingerprint
  )
    return false;

  return (
    episode.checkpoint ===
      observedResolutionRestatementCheckpoint(previous, correction) &&
    isDeepStrictEqual(next.pipelineState, state)
  );
}

// A catalog retry of the report belongs to the read-only restatement. The
// original access stays on the reservation as historical effect evidence.
export function matchesResolutionRestatementCatalogAttempt(
  run,
  binding,
  turnStart,
  attempt,
) {
  const { pipelineState: state } = run;
  const correction = state.resolutionCorrection;
  return (
    run.activeTurn?.role === "worker" &&
    run.activeTurn.phase === "resolve-findings" &&
    binding.role === "worker" &&
    binding.checkpoint === RESOLUTION_CORRECTION_CHECKPOINT &&
    state.workflowState === binding.resumeState &&
    correction?.stage === "correcting" &&
    correction.productDecision === null &&
    correction.attempts === correction.additionalAttempts + 1 &&
    attempt?.role === binding.role &&
    attempt.checkpoint ===
      observedResolutionRestatementCheckpoint(run, correction) &&
    turnStart?.pipelineState != null &&
    (turnStart.catalogCheckpoint === undefined ||
      turnStart.catalogCheckpoint === binding.checkpoint) &&
    correction.restatementStartedAfter === turnStart.previousRevision &&
    isDeepStrictEqual(state, turnStart.pipelineState)
  );
}

export function assertRestatementCatalogPause(
  previous,
  next,
  retryCode,
  turnStart,
  attempt,
  writableAttempt,
) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  const prior = previous.pause?.operatorResume?.pause ?? previous.pause;
  if (
    pause?.code !== retryCode ||
    pause.checkpoint !== RESOLUTION_CORRECTION_CHECKPOINT ||
    previous.modelCatalogResume != null ||
    prior?.code === retryCode
  )
    return;

  const state = previous.pipelineState;
  const correction = state.resolutionCorrection;
  const originalAttempt =
    correction?.access === "read-only" ? attempt : writableAttempt;
  // Reconciliation of the original report can publish an unconsumed
  // reservation. An already started read-only restatement is different.
  if (
    turnStart?.pipelineState?.resolutionCorrection?.stage !== "correcting" &&
    previous.activeTurn?.phase === "resolve-findings" &&
    correction?.stage === "ready" &&
    originalAttempt?.role === pause.role &&
    originalAttempt.checkpoint === originalResolutionCheckpoint(correction) &&
    (turnStart?.catalogCheckpoint === undefined ||
      turnStart.catalogCheckpoint === originalAttempt.checkpoint) &&
    next.pipelineState.resolutionCorrection?.stage === "ready" &&
    matchesResolutionCatalogReservation(previous, next, pause)
  )
    return true;

  if (
    pause.reason !== "backend_unavailable" ||
    previous.pause !== null ||
    next.activeTurn !== null ||
    next.pipelineState.workflowState !== "WAITING_FOR_USER" ||
    !matchesResolutionRestatementCatalogAttempt(
      previous,
      pause,
      turnStart,
      attempt,
    ) ||
    !matchesResolutionCatalogReservation(previous, next, pause) ||
    !isDeepStrictEqual(correction, next.pipelineState.resolutionCorrection)
  )
    throw new Error(
      "Catalog pause has no verified read-only restatement retirement.",
    );
  return true;
}

export function matchesResolutionCatalogReservation(
  previous,
  next,
  { role, checkpoint, resumeState },
) {
  if (checkpoint !== RESOLUTION_CORRECTION_CHECKPOINT) return undefined;

  const before = previous.pipelineState.resolutionCorrection;
  const after = next.pipelineState.resolutionCorrection;
  if (
    role !== "worker" ||
    resumeState !== "RESOLVE_FINDINGS" ||
    !["ready", "correcting"].includes(before?.stage) ||
    before.productDecision !== null ||
    !["workspace-write", "read-only"].includes(before.access) ||
    !isDeepStrictEqual(previous.hashes, next.hashes) ||
    !isDeepStrictEqual(previous.counters, next.counters) ||
    !isDeepStrictEqual(previous.availabilityRetry, next.availabilityRetry) ||
    !isDeepStrictEqual(previous.inactivityRecovery, next.inactivityRecovery)
  )
    return false;

  if (next.activeTurn !== null) {
    return (
      before.stage === "correcting" &&
      next.pipelineState.workflowState === resumeState &&
      after?.restatementStartedAfter === previous.revision &&
      isDeepStrictEqual(next.pipelineState, {
        ...previous.pipelineState,
        resolutionCorrection: {
          ...before,
          restatementStartedAfter: after.restatementStartedAfter,
        },
      })
    );
  }

  return (
    isDeepStrictEqual(next.pipelineState, {
      ...previous.pipelineState,
      workflowState: next.pipelineState.workflowState,
      resolutionCorrection: after,
    }) &&
    (isDeepStrictEqual(before, after) ||
      (before.stage === "ready" &&
        before.attempts < before.additionalAttempts + 1 &&
        Array.isArray(before.diagnostics) &&
        isDeepStrictEqual(after, beginResolutionRestatement(before))))
  );
}

const CANDIDATE_REVIEW_CORRECTION = "candidate-review-correction";
const WRITABLE_RESOLUTION_CHECKPOINT = "resolve-findings:workspace-write:work";

export function resolutionFixBudgetExhausted(
  state,
  fixRounds,
  retryCheckpoint,
) {
  return (
    retryCheckpoint?.startsWith("resolve-findings:read-only:") === true ||
    (retryCheckpoint?.startsWith("resolve-findings:workspace-write:") !==
      true &&
      !state.availabilityCorrectionCharged &&
      fixRounds >= state.settings.maxFixRounds + state.additionalFixRounds)
  );
}

export function candidateReviewCheckpoint(state) {
  return state.pendingReviewCorrection === null
    ? "review"
    : CANDIDATE_REVIEW_CORRECTION;
}

export function candidateCleanCheckpoint(state) {
  if (state.pendingLazyCorrection !== null)
    return "lazy-correction:clean-confirm";
  return combinedReview(state.settings) ? "primary-clean" : "work";
}

export function candidateCheckCheckpoint(state) {
  if (state.pendingLazyCorrection !== null)
    return "lazy-correction:check-and-fix";
  return combinedReview(state.settings) ? "primary-check" : "work";
}

export function matchesGateCatalogReservation(previous, next, binding) {
  const before = previous.pipelineState;
  const after = next.pipelineState;
  if (binding.checkpoint === WRITABLE_RESOLUTION_CHECKPOINT) {
    const providerRetry =
      previous.availabilityRetry ??
      (previous.inactivityRecovery?.expiryRevision != null
        ? previous.inactivityRecovery
        : null);
    return (
      binding.role === "worker" &&
      binding.resumeState === "RESOLVE_FINDINGS" &&
      !polishingPolicy(before.settings).independentReview &&
      before.resolutionCorrection === null &&
      before.finalizationResult?.status === "FAIL" &&
      !resolutionFixBudgetExhausted(
        before,
        normalizedCounters(previous.counters).fixRounds,
        providerRetry?.checkpoint,
      ) &&
      (next.activeTurn === null ||
        after.workflowState === "RESOLVE_FINDINGS") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  // Writable finalization keeps its candidate, inventory, correction scope and
  // fix accounting from pause acceptance through dispatch.
  if (binding.checkpoint.startsWith("finalize:workspace-write:")) {
    return (
      binding.role === "worker" &&
      binding.resumeState === "FINALIZE" &&
      binding.checkpoint === "finalize:workspace-write:work" &&
      (next.activeTurn === null || after.workflowState === "FINALIZE") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  // POLISH keeps its candidate, pending correction and fix accounting.
  if (binding.checkpoint.startsWith("polish:")) {
    return (
      binding.role === "worker" &&
      binding.resumeState === "POLISH" &&
      binding.checkpoint === "polish:workspace-write:work" &&
      (next.activeTurn === null || after.workflowState === "POLISH") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  if (binding.checkpoint.startsWith("check-and-fix:")) {
    return (
      binding.role === "worker" &&
      binding.resumeState === "CHECK_AND_FIX" &&
      polishingPolicy(before.settings).primaryConvergence &&
      binding.checkpoint ===
        `check-and-fix:workspace-write:${candidateCheckCheckpoint(before)}` &&
      (next.activeTurn === null || after.workflowState === "CHECK_AND_FIX") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  if (binding.checkpoint.startsWith("confirm:read-only:")) {
    const confirmer = polishingPolicy(before.settings).terminalConfirmer;
    const purpose =
      before.pendingConfirmationCorrection != null
        ? "confirmation-correction"
        : confirmer === "worker"
          ? "confirmation"
          : "review";
    return (
      binding.role === confirmer &&
      binding.resumeState === "CONFIRM" &&
      binding.checkpoint === `confirm:read-only:${purpose}` &&
      (next.activeTurn === null || after.workflowState === "CONFIRM") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  if (
    /^clean-confirm:read-only:(?:primary-clean|work|lazy-correction:clean-confirm)$/u.test(
      binding.checkpoint,
    )
  ) {
    return (
      binding.role === "worker" &&
      binding.resumeState === "CLEAN_CONFIRM" &&
      polishingPolicy(before.settings).primaryConvergence &&
      binding.checkpoint ===
        `clean-confirm:read-only:${candidateCleanCheckpoint(before)}` &&
      (next.activeTurn === null || after.workflowState === "CLEAN_CONFIRM") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  if (
    binding.checkpoint !== "review:read-only:review" &&
    binding.checkpoint !== `review:read-only:${CANDIDATE_REVIEW_CORRECTION}`
  )
    return undefined;

  return (
    binding.role === "reviewer" &&
    binding.resumeState === "REVIEW" &&
    polishingPolicy(before.settings).independentReview &&
    binding.checkpoint ===
      `review:read-only:${candidateReviewCheckpoint(before)}` &&
    (next.activeTurn === null || after.workflowState === "REVIEW") &&
    isDeepStrictEqual(previous.counters, next.counters) &&
    isDeepStrictEqual(after, { ...before, workflowState: after.workflowState })
  );
}

// The first pause must keep the reservation and input hashes that acceptance
// and dispatch preserve.
export function assertWritableGateCatalogPause(previous, next, retryCode) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  const prior = previous.pause?.operatorResume?.pause ?? previous.pause;
  if (
    pause?.code !== retryCode ||
    (!/^(?:polish|check-and-fix|finalize):workspace-write:/u.test(
      pause.checkpoint,
    ) &&
      pause.checkpoint !== WRITABLE_RESOLUTION_CHECKPOINT) ||
    previous.modelCatalogResume != null ||
    prior?.code === retryCode
  )
    return;
  const { role, checkpoint, resumeState } = pause;
  if (
    !isDeepStrictEqual(previous.hashes, next.hashes) ||
    !matchesGateCatalogReservation(previous, next, {
      role,
      checkpoint,
      resumeState,
    })
  )
    throw new Error("Writable gate catalog pause changed its reservation.");
  return true;
}

// A first read-only gate pause must retire the gate turn whose own failed
// attempt recorded the no-effect catalog rejection, keeping its reservation.
export function assertReadOnlyGateCatalogPause(
  previous,
  next,
  retryCode,
  turnStart,
  attempt,
) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  const prior = previous.pause?.operatorResume?.pause ?? previous.pause;
  if (
    pause?.code !== retryCode ||
    !/^(?:review|clean-confirm|confirm):read-only:/u.test(pause.checkpoint) ||
    isValidationMigrationCheckpoint(pause.checkpoint) ||
    previous.modelCatalogResume != null ||
    prior?.code === retryCode
  )
    return;
  const { role, checkpoint, resumeState } = pause;
  const turn = previous.activeTurn;
  // Review and clean confirmation may capture the inspected infrastructure
  // once; a saved fingerprint stays unchanged through later misses.
  const field = "catalogReviewInfrastructureFingerprint";
  let pipelineState = next.pipelineState;
  if (
    !checkpoint.startsWith("confirm:") &&
    !Object.hasOwn(previous.pipelineState, field)
  ) {
    const { [field]: _, ...reserved } = pipelineState;
    pipelineState = reserved;
  }
  if (
    turn?.role !== role ||
    turn.phase !== checkpoint.split(":")[0] ||
    previous.pipelineState.workflowState !== resumeState ||
    attempt?.role !== role ||
    attempt.checkpoint !== checkpoint ||
    (turnStart?.catalogCheckpoint !== undefined &&
      turnStart.catalogCheckpoint !== checkpoint) ||
    !isDeepStrictEqual(previous.hashes, next.hashes) ||
    !matchesGateCatalogReservation(
      previous,
      { ...next, pipelineState },
      { role, checkpoint, resumeState },
    )
  )
    throw new Error("Read-only gate catalog pause changed its reservation.");
  return true;
}

// Migration turns keep the suspended workflow phase, so their checkpoints
// share gate prefixes but never gate reservations.
function isValidationMigrationCheckpoint(checkpoint) {
  return /^[a-z-]+:read-only:validation-migration$/u.test(checkpoint);
}

export function matchesValidationMigrationCatalogReservation(
  previous,
  next,
  binding,
) {
  if (!isValidationMigrationCheckpoint(binding.checkpoint)) return undefined;
  const { phase } = activeTurn(binding.role, binding.resumeState);
  if (binding.checkpoint !== `${phase}:read-only:validation-migration`)
    return false;

  const before = previous.pipelineState;
  const after = next.pipelineState;
  const policy = polishingPolicy(before.settings);
  return (
    before.validationMigrationPending === true &&
    (binding.role === "arbiter"
      ? policy.bootstrapArbitration &&
        before.validationMigrationDisagreement != null
      : before.validationMigrationDisagreement == null &&
        (binding.role === "worker" ||
          (binding.role === "reviewer" && policy.independentBootstrap))) &&
    isDeepStrictEqual(after, {
      ...before,
      workflowState: after.workflowState,
    }) &&
    isDeepStrictEqual(previous.counters, next.counters)
  );
}

// A first migration pause must retire the rediscovery turn whose own failed
// attempt recorded the no-effect catalog rejection, keeping its reservation.
export function assertValidationMigrationCatalogPause(
  previous,
  next,
  retryCode,
  turnStart,
  attempt,
) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  const prior = previous.pause?.operatorResume?.pause ?? previous.pause;
  if (
    pause?.code !== retryCode ||
    !isValidationMigrationCheckpoint(pause.checkpoint) ||
    previous.modelCatalogResume != null ||
    prior?.code === retryCode
  )
    return;
  const { role, checkpoint, resumeState } = pause;
  if (
    previous.activeTurn?.role !== role ||
    previous.activeTurn.phase !== checkpoint.split(":")[0] ||
    attempt?.role !== role ||
    attempt.checkpoint !== checkpoint ||
    (turnStart?.catalogCheckpoint !== undefined &&
      turnStart.catalogCheckpoint !== checkpoint) ||
    !isDeepStrictEqual(previous.hashes, next.hashes) ||
    !matchesValidationMigrationCatalogReservation(previous, next, {
      role,
      checkpoint,
      resumeState,
    })
  )
    throw new Error("Validation migration catalog pause has no proof.");
  return true;
}

export function assertDirectReadOnlyCatalogPause(
  previous,
  next,
  retryCode,
  turnStart,
  attempt,
) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  const prior = previous.pause?.operatorResume?.pause ?? previous.pause;
  if (
    pause?.code !== retryCode ||
    previous.modelCatalogResume != null ||
    prior?.code === retryCode
  )
    return;

  const before = previous.pipelineState;
  const policy = polishingPolicy(before.settings);
  const { role, phase } = activeTurn(pause.role, before.workflowState);
  const purpose = {
    CLARIFY: role === "worker" && "clarification",
    BOOTSTRAP:
      role === "arbiter"
        ? policy.bootstrapArbitration &&
          before.bootstrapDisagreement != null &&
          "arbitration"
        : (role === "worker" ||
            (role === "reviewer" && policy.independentBootstrap)) &&
          "bootstrap",
    FINALIZE:
      role === "worker" &&
      before.pendingFinalizationCorrection != null &&
      "finalization-correction",
    RESOLVE_FINDINGS:
      role === "arbiter"
        ? policy.arbitration && "arbitration"
        : role === "reviewer"
          ? policy.independentReview &&
            before.pendingDisputes?.length > 0 &&
            "review"
          : role === "worker" && !policy.independentReview && "work",
  }[before.workflowState];
  if (
    !purpose ||
    pause.checkpoint !== `${phase}:read-only:${purpose}` ||
    previous.activeTurn?.phase !== phase ||
    attempt?.role !== role ||
    attempt.checkpoint !== pause.checkpoint ||
    (turnStart?.catalogCheckpoint !== undefined &&
      turnStart.catalogCheckpoint !== pause.checkpoint) ||
    !isDeepStrictEqual(next.pipelineState, {
      ...before,
      workflowState: next.pipelineState.workflowState,
    }) ||
    !isDeepStrictEqual(previous.counters, next.counters)
  )
    throw new Error(
      "Catalog pause has no matching read-only polishing invocation.",
    );
  return true;
}

const RESOLUTION_CORRECTION_FIELDS = Object.freeze([
  "schemaVersion",
  "stage",
  "access",
  "blockers",
  "nonDisputableIds",
  "budgetExhausted",
  "beforeFingerprint",
  "contentChanged",
  "candidate",
  "fixRoundsBefore",
  "fixCharged",
  "attempts",
  "additionalAttempts",
  "diagnostics",
  "productDecision",
  "repair",
  "factsFingerprint",
]);
// The candidate binds the reconciled snapshot fields compared for workspace
// control drift, its content, and the established validation infrastructure.
export const RESOLUTION_CANDIDATE_REPOSITORY_FIELDS = Object.freeze([
  "projectPath",
  "head",
  "branch",
  "detached",
  "refsFingerprint",
  "remoteConfigurationFingerprint",
  "identityFingerprint",
  "indexFingerprint",
  "contentFingerprint",
]);
const RESOLUTION_CORRECTION_STAGES = Object.freeze([
  "invoking",
  "ready",
  "retry-ready",
  "correcting",
  "exhausted",
  "blocked",
  "repair-required",
  "repair-authorized",
]);
const RESOLUTION_DIAGNOSTIC_CONSTRAINTS = new Set([
  "object",
  "exact-field-set",
  "maximum-2-mebibytes",
  "serializable-json",
  "resolution-status",
  "exactly-three-policy-evidence-items",
  "empty-array",
  "empty-string",
  "nonempty-plain-text-up-to-4000-characters",
  "array-up-to-32-items",
  "nonempty-array-up-to-32-items",
  "array-up-to-16-items",
  "fix-or-dispute",
  "current-blocker-id",
  "disputable-blocker-only",
  "every-current-blocker-exactly-once",
  "semantic-contract",
]);
const RESOLUTION_DIAGNOSTIC_FIELD_PATTERN =
  /^(?:result|status|decisions|reason|question|whyBlocked|options|evidence|options\[(?:[0-9]|1[0-5])\]|evidence\[(?:[0-9]|[12][0-9]|3[01])\]|decisions\[(?:[0-9]|[12][0-9]|3[01])\](?:\.(?:id|decision|reason|evidence(?:\[(?:[0-9]|[12][0-9]|3[01])\])?))?)$/u;

// Durable correction diagnostics admit only source-defined resolution field
// identities, bounded positions and constraints; anything else is reduced.
export function resolutionCorrectionDiagnostic(value) {
  if (
    isRecord(value) &&
    value.field === INTERRUPTED_RESOLUTION_DIAGNOSTIC.field &&
    value.constraint === INTERRUPTED_RESOLUTION_DIAGNOSTIC.constraint
  ) {
    return INTERRUPTED_RESOLUTION_DIAGNOSTIC;
  }
  if (
    isRecord(value) &&
    value.field === CATALOG_RESOLUTION_DIAGNOSTIC.field &&
    value.constraint === CATALOG_RESOLUTION_DIAGNOSTIC.constraint
  ) {
    return CATALOG_RESOLUTION_DIAGNOSTIC;
  }
  return isRecord(value) &&
    typeof value.field === "string" &&
    RESOLUTION_DIAGNOSTIC_FIELD_PATTERN.test(value.field) &&
    RESOLUTION_DIAGNOSTIC_CONSTRAINTS.has(value.constraint)
    ? Object.freeze({ field: value.field, constraint: value.constraint })
    : Object.freeze({ field: "result", constraint: "semantic-contract" });
}

// A pure classifier for the strict normalizer: an empty batch means the
// report is valid; an invalid one yields only its reduced diagnostic.
export function classifyResolutionResult(payload, checkpoint, options) {
  try {
    normalizeResolutionResult(
      payload,
      checkpoint.blockers,
      new Set(checkpoint.nonDisputableIds),
      options,
    );
    return Object.freeze([]);
  } catch (cause) {
    if (cause?.code !== INVALID_OUTPUT_CODE) throw cause;
    return Object.freeze([resolutionCorrectionDiagnostic(cause.diagnostic)]);
  }
}

export function resolutionBlockers(state) {
  return state.finalizationResult?.status === "FAIL"
    ? state.finalizationResult.issues.map((issue) => ({
        ...issue,
        source: "finalization",
      }))
    : state.findings.map((finding) => ({ ...finding, source: "review" }));
}

export function resolutionNonDisputableIds(
  state,
  blockers = resolutionBlockers(state),
) {
  const blockerIds = new Set(blockers.map(({ id }) => id));
  return [
    ...new Set([
      ...state.findingArbitrations
        .filter(
          ({ findingId, direction }) =>
            blockerIds.has(findingId) && direction === "REVIEWER_CORRECT",
        )
        .map(({ findingId }) => findingId),
      ...Object.entries(state.disputeCounts)
        .filter(
          ([findingId, count]) =>
            blockerIds.has(findingId) &&
            count >= state.settings.maxDisputesPerFinding,
        )
        .map(([findingId]) => findingId),
    ]),
  ];
}

function validResolutionProductDecision(value) {
  if (
    !hasExactFields(value, ["decision", "number", "expectedHash", "resultHash"])
  )
    return false;
  try {
    return (
      hasExactFields(value.decision, [
        "question",
        "options",
        "whyBlocked",
        "evidence",
      ]) &&
      isDeepStrictEqual(
        normalizeProductDecision(value.decision),
        value.decision,
      ) &&
      Number.isSafeInteger(value.number) &&
      value.number >= 1 &&
      HASH_PATTERN.test(value.expectedHash) &&
      (value.resultHash === null ||
        (HASH_PATTERN.test(value.resultHash) &&
          value.resultHash !== value.expectedHash))
    );
  } catch {
    return false;
  }
}

export function resolutionFactsFingerprint(state) {
  return sha256(
    JSON.stringify([
      state.settings,
      state.requiredChecks,
      state.validationInfrastructure,
      state.trustedValidation,
      state.finalizationGuidance,
      state.findings,
      state.previousFindings,
      state.pendingDisputes,
      state.disputeCounts,
      state.disputeHistory,
      state.findingArbitrations,
      state.findingOverrides,
      state.correctionHistory,
      state.sameFindingRounds,
      state.blockedSinceStagnation,
      state.stagnationDirection,
      state.stagnationArbitrationUsed,
      state.additionalFixRounds,
    ]),
  );
}

export function upgradeLegacyResolutionCorrection(state) {
  const checkpoint = state.resolutionCorrection;
  if (checkpoint === null) return null;
  if (
    !isRecord(checkpoint) ||
    checkpoint.schemaVersion !== 1 ||
    Object.hasOwn(checkpoint, "repair") ||
    Object.hasOwn(checkpoint, "factsFingerprint")
  )
    return undefined;
  return Object.freeze({
    ...checkpoint,
    schemaVersion: 2,
    repair: null,
    factsFingerprint: resolutionFactsFingerprint(state),
  });
}

export function unfinishedResolutionReport(state, result) {
  const checkpoint = state.resolutionCorrection;
  return {
    phase: "RESOLVE_FINDINGS",
    ...result,
    recovery: {
      checkpointFingerprint: sha256(JSON.stringify(checkpoint)),
      candidateFingerprint: checkpoint.candidate.contentFingerprint,
      factsFingerprint: checkpoint.factsFingerprint,
      blockersFingerprint: sha256(
        JSON.stringify([checkpoint.blockers, checkpoint.nonDisputableIds]),
      ),
      attempts: checkpoint.attempts,
      additionalAttempts: checkpoint.additionalAttempts,
      fixRounds: checkpoint.fixRoundsBefore + (checkpoint.fixCharged ? 1 : 0),
      pendingCorrection: state.pendingCorrection,
      budgetExhausted: checkpoint.budgetExhausted,
      diagnostics: checkpoint.diagnostics,
      previous: checkpoint.repair,
    },
  };
}

function assertUnfinishedResolutionReport(report, reports, index) {
  const value = report.recovery;
  const count = (entry) => Number.isSafeInteger(entry) && entry >= 0;
  const hash = (entry) => typeof entry === "string" && HASH_PATTERN.test(entry);
  if (
    report.phase !== "RESOLVE_FINDINGS" ||
    !hasExactFields(value, [
      "checkpointFingerprint",
      "candidateFingerprint",
      "factsFingerprint",
      "blockersFingerprint",
      "attempts",
      "additionalAttempts",
      "fixRounds",
      "pendingCorrection",
      "budgetExhausted",
      "diagnostics",
      "previous",
    ]) ||
    ![
      value.checkpointFingerprint,
      value.candidateFingerprint,
      value.factsFingerprint,
      value.blockersFingerprint,
    ].every(hash) ||
    ![value.attempts, value.additionalAttempts, value.fixRounds].every(count) ||
    !Number.isSafeInteger(value.additionalAttempts + 1) ||
    value.attempts !== value.additionalAttempts + 1 ||
    typeof value.pendingCorrection !== "boolean" ||
    typeof value.budgetExhausted !== "boolean" ||
    !Array.isArray(value.diagnostics) ||
    value.diagnostics.length > MAX_DIAGNOSTIC_ITEMS ||
    value.diagnostics.some(
      (diagnostic) =>
        !isDeepStrictEqual(
          diagnostic,
          resolutionCorrectionDiagnostic(diagnostic),
        ),
    ) ||
    (value.previous !== null &&
      (!count(value.previous) ||
        value.previous >= index ||
        reports[value.previous]?.status !== "UNFINISHED"))
  )
    throw workflowError("Invalid unfinished repair history.");
  if (value.previous !== null) {
    const previous = reports[value.previous].recovery;
    if (
      value.attempts < previous.attempts ||
      value.additionalAttempts < previous.additionalAttempts ||
      value.fixRounds < previous.fixRounds ||
      value.blockersFingerprint !== previous.blockersFingerprint ||
      (previous.pendingCorrection && !value.pendingCorrection)
    )
      throw workflowError(
        "Unfinished repair history renewed consumed authority.",
      );
  }
}

function validResolutionCorrection(state) {
  const value = state.resolutionCorrection;
  if (value === null) return true;
  const hash = (entry) => typeof entry === "string" && HASH_PATTERN.test(entry);
  const count = (entry) => Number.isSafeInteger(entry) && entry >= 0;
  const hasStart =
    isRecord(value) && Object.hasOwn(value, "restatementStartedAfter");
  const hasConsumedRestatement = [
    "retry-ready",
    "correcting",
    "exhausted",
    "blocked",
  ].includes(value?.stage);
  if (
    !hasExactFields(
      value,
      hasStart
        ? [...RESOLUTION_CORRECTION_FIELDS, "restatementStartedAfter"]
        : RESOLUTION_CORRECTION_FIELDS,
    ) ||
    (hasStart &&
      (!count(value.restatementStartedAfter) ||
        value.restatementStartedAfter === 0 ||
        ["invoking", "ready"].includes(value.stage))) ||
    value.schemaVersion !== 2 ||
    value.factsFingerprint !== resolutionFactsFingerprint(state) ||
    !polishingPolicy(state.settings).independentReview ||
    !["RESOLVE_FINDINGS", "WAITING_FOR_USER", "FAILED", "CANCELED"].includes(
      state.workflowState,
    ) ||
    !RESOLUTION_CORRECTION_STAGES.includes(value.stage) ||
    typeof value.budgetExhausted !== "boolean" ||
    value.access !==
      (value.budgetExhausted ? "read-only" : "workspace-write") ||
    !isDeepStrictEqual(value.blockers, resolutionBlockers(state)) ||
    !isDeepStrictEqual(
      value.nonDisputableIds,
      resolutionNonDisputableIds(state),
    ) ||
    !hash(value.beforeFingerprint) ||
    !count(value.fixRoundsBefore) ||
    typeof value.fixCharged !== "boolean" ||
    !count(value.attempts) ||
    !count(value.additionalAttempts) ||
    !Number.isSafeInteger(value.additionalAttempts + 1) ||
    value.attempts < value.additionalAttempts ||
    value.attempts > value.additionalAttempts + 1 ||
    (hasConsumedRestatement &&
      value.attempts !== value.additionalAttempts + 1) ||
    (["invoking", "ready"].includes(value.stage) &&
      value.repair === null &&
      value.attempts !== value.additionalAttempts) ||
    !Array.isArray(value.diagnostics) ||
    value.diagnostics.length > MAX_DIAGNOSTIC_ITEMS ||
    value.diagnostics.some(
      (diagnostic) =>
        !hasExactFields(diagnostic, ["field", "constraint"]) ||
        !isDeepStrictEqual(diagnostic, {
          ...resolutionCorrectionDiagnostic(diagnostic),
        }),
    ) ||
    (hasConsumedRestatement && value.diagnostics.length === 0) ||
    (value.productDecision !== null &&
      (!["ready", "correcting"].includes(value.stage) ||
        !validResolutionProductDecision(value.productDecision)))
  ) {
    return false;
  }
  if (value.repair !== null) {
    const report = state.workReports[value.repair];
    const previous = report?.recovery;
    if (
      !count(value.repair) ||
      report?.status !== "UNFINISHED" ||
      previous.blockersFingerprint !==
        sha256(JSON.stringify([value.blockers, value.nonDisputableIds])) ||
      value.attempts < previous.attempts ||
      value.additionalAttempts < previous.additionalAttempts ||
      value.fixRoundsBefore + (value.fixCharged ? 1 : 0) < previous.fixRounds ||
      (previous.pendingCorrection && !state.pendingCorrection) ||
      (["repair-required", "repair-authorized"].includes(value.stage)
        ? value.candidate?.contentFingerprint !==
            previous.candidateFingerprint ||
          value.fixRoundsBefore + (value.fixCharged ? 1 : 0) !==
            previous.fixRounds ||
          value.attempts !== previous.attempts ||
          value.additionalAttempts !== previous.additionalAttempts ||
          state.pendingCorrection !== previous.pendingCorrection
        : value.fixRoundsBefore !== previous.fixRounds ||
          value.beforeFingerprint !== previous.candidateFingerprint ||
          state.pendingCorrection !==
            (previous.pendingCorrection || value.fixCharged) ||
          (value.stage !== "invoking" &&
            value.fixCharged !==
              (value.contentChanged && !previous.pendingCorrection)) ||
          (value.stage === "invoking" &&
            (value.budgetExhausted ||
              value.additionalAttempts !== previous.additionalAttempts ||
              value.attempts !== previous.attempts)))
    )
      return false;
  } else if (["repair-required", "repair-authorized"].includes(value.stage))
    return false;
  if (value.stage === "invoking") {
    return (
      value.contentChanged === null &&
      value.candidate === null &&
      !value.fixCharged &&
      (value.repair !== null || value.attempts === 0) &&
      value.diagnostics.length === 0 &&
      // A classified retry keeps the round's content after a charged partial write.
      (state.repositoryBaseline?.contentFingerprint ===
        value.beforeFingerprint ||
        (value.access === "workspace-write" && state.pendingCorrection))
    );
  }
  const candidate = value.candidate;
  return (
    typeof value.contentChanged === "boolean" &&
    hasExactFields(candidate, [
      ...RESOLUTION_CANDIDATE_REPOSITORY_FIELDS,
      "validationInfrastructureFingerprint",
    ]) &&
    hash(candidate.validationInfrastructureFingerprint) &&
    RESOLUTION_CANDIDATE_REPOSITORY_FIELDS.every(
      (field) => candidate[field] === state.repositoryBaseline?.[field],
    ) &&
    value.contentChanged ===
      (candidate.contentFingerprint !== value.beforeFingerprint) &&
    (!value.fixCharged || value.contentChanged) &&
    (!value.contentChanged ||
      (value.access === "workspace-write" && state.pendingCorrection))
  );
}

export function normalizeReconsiderationResult(payload, disputes) {
  assertExactFields(
    payload,
    ["status", "decisions", "question", "options", "whyBlocked", "evidence"],
    "Dispute reconsideration",
    INVALID_OUTPUT_CODE,
  );
  assertStructuredResult(payload);
  if (
    !isRecord(payload) ||
    !["RESOLVED", "PRODUCT_DECISION_REQUIRED"].includes(payload.status)
  ) {
    throw outputError("Reviewer returned an invalid dispute reconsideration.");
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.decisions)) {
      throw outputError("Product decision must not include dispute decisions.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload) || !Array.isArray(payload.decisions)) {
    throw outputError("Dispute reconsideration contains inapplicable fields.");
  }
  const expectedIds = disputes.map(({ findingId }) => findingId).sort();
  const decisions = Object.freeze(
    payload.decisions.map((decision) => {
      if (
        !isRecord(decision) ||
        !["WITHDRAW", "UPHOLD"].includes(decision.direction) ||
        !expectedIds.includes(decision.id)
      ) {
        throw outputError("Reviewer returned an invalid dispute decision.");
      }
      assertExactFields(
        decision,
        ["id", "direction", "reason", "evidence"],
        `dispute decision ${decision.id}`,
        INVALID_OUTPUT_CODE,
      );
      return Object.freeze({
        findingId: decision.id,
        direction: decision.direction,
        reason: normalizeText(
          decision.reason,
          `dispute ${decision.id} reconsideration`,
          INVALID_OUTPUT_CODE,
        ),
        evidence: normalizeOptionalEvidence(
          decision.evidence,
          `dispute ${decision.id} evidence`,
        ),
      });
    }),
  );
  const actualIds = decisions.map(({ findingId }) => findingId).sort();
  if (
    decisions.length !== disputes.length ||
    new Set(actualIds).size !== actualIds.length ||
    actualIds.some((id, index) => id !== expectedIds[index])
  ) {
    throw outputError("Reviewer must reconsider every dispute exactly once.");
  }
  return Object.freeze({ status: payload.status, decisions });
}

export function normalizeFindingArbitration(payload) {
  assertExactFields(
    payload,
    ["direction", "rationale", "question", "options", "whyBlocked", "evidence"],
    "Finding arbitration",
    INVALID_OUTPUT_CODE,
  );
  assertStructuredResult(payload);
  if (
    !isRecord(payload) ||
    !["WORKER_CORRECT", "REVIEWER_CORRECT", "REQUIREMENT_AMBIGUOUS"].includes(
      payload.direction,
    )
  ) {
    throw outputError("Arbiter returned an invalid finding direction.");
  }
  const rationale = normalizeText(
    payload.rationale,
    "finding arbitration rationale",
    INVALID_OUTPUT_CODE,
  );
  if (payload.direction === "REQUIREMENT_AMBIGUOUS") {
    return Object.freeze({
      direction: payload.direction,
      rationale,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload)) {
    throw outputError("Finding arbitration contains inapplicable fields.");
  }
  return Object.freeze({ direction: payload.direction, rationale });
}

export function normalizeStagnationResult(payload, pipelineState) {
  assertExactFields(
    payload,
    [
      "direction",
      "rationale",
      "findingIds",
      "question",
      "options",
      "whyBlocked",
      "evidence",
    ],
    "Stagnation arbitration",
    INVALID_OUTPUT_CODE,
  );
  assertStructuredResult(payload);
  if (
    !isRecord(payload) ||
    ![
      "CONTINUE_FIXES",
      "REWORK_IMPLEMENTATION",
      "RECONSIDER_FINDINGS",
      "PRODUCT_DECISION_REQUIRED",
    ].includes(payload.direction)
  ) {
    throw outputError("Arbiter returned an invalid stagnation direction.");
  }
  const rationale = normalizeText(
    payload.rationale,
    "stagnation rationale",
    INVALID_OUTPUT_CODE,
  );
  if (payload.direction === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.findingIds)) {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      direction: payload.direction,
      rationale,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload) || !Array.isArray(payload.findingIds)) {
    throw outputError("Stagnation result contains inapplicable fields.");
  }
  const findingIds = payload.findingIds.map((id) => {
    if (!REVIEW_FINDING_ID_PATTERN.test(id)) {
      throw outputError("Stagnation finding ID is invalid.");
    }
    return id;
  });
  const currentIds = new Set(pipelineState.findings.map(({ id }) => id));
  if (
    (payload.direction === "RECONSIDER_FINDINGS" &&
      (findingIds.length === 0 ||
        new Set(findingIds).size !== findingIds.length ||
        findingIds.some((id) => !currentIds.has(id)))) ||
    (payload.direction !== "RECONSIDER_FINDINGS" && findingIds.length !== 0)
  ) {
    throw outputError("Stagnation direction names inapplicable findings.");
  }
  return Object.freeze({
    direction: payload.direction,
    rationale,
    findingIds: Object.freeze(findingIds),
  });
}

export function normalizeResumeAction(value) {
  if (value === undefined || value === null) {
    return null;
  }
  if (
    !isRecord(value) ||
    !["extra-fix-rounds", "override-finding"].includes(value.type)
  ) {
    throw workflowError("Polishing resume action is invalid.");
  }
  if (
    value.type === "extra-fix-rounds" &&
    Object.keys(value).length === 2 &&
    Number.isSafeInteger(value.amount) &&
    value.amount > 0
  ) {
    return Object.freeze({ type: value.type, amount: value.amount });
  }
  if (
    value.type === "override-finding" &&
    Object.keys(value).length === 2 &&
    REVIEW_FINDING_ID_PATTERN.test(value.findingId)
  ) {
    return Object.freeze({ type: value.type, findingId: value.findingId });
  }
  throw workflowError("Polishing resume action is invalid.");
}

export function assertSettings(settings) {
  settings = normalizeSettings(settings);
  assertExactFields(settings, SETTINGS_FIELDS, "Polishing settings");
  if (!isFinalizationPolicy(settings.finalization)) {
    throw workflowError("Polishing setting finalization is invalid.");
  }
  if (!isTrustedCheckSelection(settings.trustedChecks)) {
    throw workflowError("Polishing setting trustedChecks is invalid.");
  }
  if (!["independent", "lazy", "combined"].includes(settings.mode)) {
    throw workflowError("Polishing setting mode is invalid.");
  }
  for (const field of NUMERIC_SETTINGS_FIELDS) {
    if (!Number.isSafeInteger(settings[field]) || settings[field] < 1) {
      throw workflowError(`Polishing setting ${field} is invalid.`);
    }
  }
  if (settings.maxDisputesPerFinding > MAX_DISPUTES_PER_FINDING) {
    throw workflowError(
      `Polishing setting maxDisputesPerFinding must not exceed ${MAX_DISPUTES_PER_FINDING}.`,
    );
  }
  disputeHistoryCapacity(settings);
}

export function isTrustedCheckSelection(value) {
  return (
    Array.isArray(value) &&
    value.length <= MAX_ITEMS &&
    new Set(value).size === value.length &&
    value.every(
      (alias) => typeof alias === "string" && TRUSTED_ALIAS_PATTERN.test(alias),
    )
  );
}

export function isFinalizationPolicy(value) {
  if (value === "auto" || value === "none") {
    return true;
  }
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 1_024 &&
    !value.includes("\\") &&
    !/^[a-zA-Z]:\//u.test(value) &&
    !posix.isAbsolute(value) &&
    posix.normalize(value) === value &&
    value !== "." &&
    value !== ".." &&
    !value.startsWith("../") &&
    value !== ".git" &&
    !value.startsWith(".git/") &&
    value.endsWith(".md") &&
    !value.split("/").includes(".git") &&
    !/[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  );
}

function normalizeSettings(settings) {
  let normalized = settings;
  if (
    isRecord(normalized) &&
    !Object.hasOwn(normalized, "finalization") &&
    ((Object.keys(normalized).length === NUMERIC_SETTINGS_FIELDS.length &&
      NUMERIC_SETTINGS_FIELDS.every((field) =>
        Object.hasOwn(normalized, field),
      )) ||
      (Object.keys(normalized).length === SETTINGS_FIELDS.length - 1 &&
        SETTINGS_FIELDS.filter((field) => field !== "finalization").every(
          (field) => Object.hasOwn(normalized, field),
        )))
  ) {
    normalized = Object.freeze({
      finalization: DEFAULT_FINALIZATION_POLICY,
      ...normalized,
    });
  }
  if (
    isRecord(normalized) &&
    !Object.hasOwn(normalized, "trustedChecks") &&
    Object.keys(normalized).length === SETTINGS_FIELDS.length - 1 &&
    SETTINGS_FIELDS.filter((field) => field !== "trustedChecks").every(
      (field) => Object.hasOwn(normalized, field),
    )
  ) {
    normalized = Object.freeze({
      ...normalized,
      trustedChecks: Object.freeze([]),
    });
  }
  return normalized;
}

export function disputeHistoryCapacity(settings) {
  const capacity = MAX_DIAGNOSTIC_ITEMS * settings?.maxDisputesPerFinding;
  if (
    !Number.isSafeInteger(capacity) ||
    capacity < 1 ||
    settings.maxDisputesPerFinding > MAX_DISPUTES_PER_FINDING
  ) {
    throw workflowError(
      "Polishing setting maxDisputesPerFinding is too large.",
    );
  }
  return capacity;
}

function normalizeOptionalSummary(value, name) {
  return value === null ? null : normalizeSummary(value, name);
}

function normalizePendingEdit(value) {
  if (value === null) {
    return null;
  }
  if (
    !isRecord(value) ||
    Object.keys(value).length !== PENDING_EDIT_FIELDS.size ||
    Object.keys(value).some((field) => !PENDING_EDIT_FIELDS.has(field)) ||
    value.schemaVersion !== 1 ||
    typeof value.id !== "string" ||
    value.id.length === 0 ||
    !isAbsolute(value.artifactRoot) ||
    !isAbsolute(value.transcriptPath) ||
    !["CLARIFY", "BOOTSTRAP"].includes(value.suspendedState) ||
    !Object.hasOwn(EDIT_PAUSE_REASONS, value.action) ||
    !HASH_PATTERN.test(value.preEditorHash)
  ) {
    throw workflowError("Polishing pending edit is invalid.");
  }
  return value;
}

function normalizeDisagreement(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["description", "evidence"],
    "Polishing bootstrap disagreement",
  );
  return Object.freeze({
    description: normalizeText(value.description, "bootstrap disagreement"),
    evidence: normalizeTextList(value.evidence, "bootstrap evidence", {
      code: "ERR_INVALID_POLISHING_STATE",
    }),
  });
}

function normalizeBootstrapCorrection(correction) {
  if (
    !hasExactFields(correction, BOOTSTRAP_CORRECTION_FIELDS) ||
    correction.attempt !== 1
  ) {
    throw workflowError("Polishing bootstrap correction is invalid.");
  }
  const diagnostic = Object.fromEntries(
    OUTPUT_DIAGNOSTIC_FIELDS.map((field) => [field, correction[field]]),
  );
  const validContext =
    (correction.contract === "bootstrap" &&
      ["worker", "reviewer"].includes(correction.role)) ||
    (correction.contract === "bootstrap-reconciliation" &&
      correction.role === "worker") ||
    (correction.contract === "bootstrap-arbitration" &&
      correction.role === "arbiter");
  if (
    !isOutputDiagnostic(diagnostic) ||
    !["bootstrap", "validation-migration"].includes(correction.phase) ||
    !validContext
  ) {
    throw workflowError("Polishing bootstrap correction is invalid.");
  }
  return correction;
}

function normalizeBootstrapCorrections(value) {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw workflowError("Polishing bootstrap corrections are invalid.");
  }
  const contexts = new Set();
  for (const correction of value) {
    normalizeBootstrapCorrection(correction);
    const context = `${correction.role}\0${correction.phase}\0${correction.contract}`;
    if (contexts.has(context)) {
      throw workflowError("Polishing bootstrap corrections must be unique.");
    }
    contexts.add(context);
  }
  return value;
}

function normalizeFinalizationCorrection(value) {
  if (value === null) {
    return null;
  }
  if (
    !hasExactFields(value, FINALIZATION_CORRECTION_FIELDS) ||
    value.attempt !== 1 ||
    !["resolved", "fallback"].includes(value.guidance) ||
    !HASH_PATTERN.test(value.contentFingerprint)
  ) {
    throw workflowError("Polishing finalization correction is invalid.");
  }
  const diagnostic = Object.fromEntries(
    OUTPUT_DIAGNOSTIC_FIELDS.map((field) => [field, value[field]]),
  );
  if (
    !isOutputDiagnostic(diagnostic) ||
    value.role !== "worker" ||
    value.phase !== "finalization" ||
    value.contract !== "finalization"
  ) {
    throw workflowError("Polishing finalization correction is invalid.");
  }
  return value;
}

function normalizeScopedCorrection(value, { name, roles, phase, contract }) {
  if (
    value === null ||
    !hasExactFields(value, REVIEW_CORRECTION_FIELDS) ||
    value.attempt !== 1 ||
    !HASH_PATTERN.test(value.contentFingerprint) ||
    !HASH_PATTERN.test(value.validationInfrastructureFingerprint) ||
    !Array.isArray(value.diagnostics) ||
    value.diagnostics.length === 0 ||
    value.diagnostics.length > MAX_DIAGNOSTIC_ITEMS
  ) {
    throw workflowError(`Polishing ${name} correction is invalid.`);
  }
  const identities = new Set();
  for (const diagnostic of value.diagnostics) {
    if (
      !isOutputDiagnostic(diagnostic) ||
      !roles.includes(diagnostic.role) ||
      diagnostic.phase !== phase ||
      diagnostic.contract !== contract
    ) {
      throw workflowError(`Polishing ${name} correction is invalid.`);
    }
    const identity = `${diagnostic.field}\0${diagnostic.constraint}`;
    if (identities.has(identity)) {
      throw workflowError(`Polishing ${name} correction is invalid.`);
    }
    identities.add(identity);
  }
  return value;
}

function normalizeReviewCorrection(value) {
  return normalizeScopedCorrection(value, {
    name: "review",
    roles: ["reviewer"],
    phase: "review",
    contract: "candidate-review",
  });
}

function normalizeConfirmationCorrection(value) {
  return normalizeScopedCorrection(value, {
    name: "confirmation",
    roles: ["worker", "reviewer"],
    phase: "confirmation",
    contract: "confirmation",
  });
}

function sameReviewCorrectionScope(left, right) {
  return (
    left.attempt === right.attempt &&
    left.contentFingerprint === right.contentFingerprint &&
    left.validationInfrastructureFingerprint ===
      right.validationInfrastructureFingerprint
  );
}

function normalizeLazyCorrection(value) {
  if (
    !isRecord(value) ||
    !hasExactFields(value, LAZY_CORRECTION_FIELDS) ||
    value.attempt !== 1 ||
    typeof value.fixRoundCharged !== "boolean" ||
    !["CHECK_AND_FIX", "CLEAN_CONFIRM"].includes(value.phase) ||
    (value.phase === "CLEAN_CONFIRM" && value.fixRoundCharged) ||
    !HASH_PATTERN.test(value.contentFingerprint) ||
    !HASH_PATTERN.test(value.validationInfrastructureFingerprint) ||
    !Array.isArray(value.diagnostics) ||
    value.diagnostics.length === 0 ||
    value.diagnostics.length > MAX_DIAGNOSTIC_ITEMS
  ) {
    throw workflowError("Polishing lazy correction is invalid.");
  }
  const expectedPhase =
    value.phase === "CHECK_AND_FIX" ? "check-and-fix" : "clean-confirm";
  const expectedContract =
    value.phase === "CHECK_AND_FIX"
      ? "lazy-check-and-fix"
      : "lazy-clean-confirm";
  const identities = new Set();
  for (const diagnostic of value.diagnostics) {
    if (
      !isOutputDiagnostic(diagnostic) ||
      diagnostic.role !== "worker" ||
      diagnostic.phase !== expectedPhase ||
      diagnostic.contract !== expectedContract
    ) {
      throw workflowError("Polishing lazy correction is invalid.");
    }
    const identity = `${diagnostic.field}\0${diagnostic.constraint}`;
    if (identities.has(identity)) {
      throw workflowError("Polishing lazy correction is invalid.");
    }
    identities.add(identity);
  }
  return value;
}

function sameLazyCorrectionScope(left, right) {
  return (
    left.attempt === right.attempt &&
    left.phase === right.phase &&
    left.contentFingerprint === right.contentFingerprint &&
    left.validationInfrastructureFingerprint ===
      right.validationInfrastructureFingerprint
  );
}

function normalizeLazyCorrections(value) {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw workflowError("Polishing lazy corrections are invalid.");
  }
  const scopes = new Set();
  for (const correction of value) {
    normalizeLazyCorrection(correction);
    const scope = [
      correction.phase,
      correction.contentFingerprint,
      correction.validationInfrastructureFingerprint,
    ].join("\0");
    if (scopes.has(scope)) {
      throw workflowError("Polishing lazy corrections must be unique.");
    }
    scopes.add(scope);
  }
  return value;
}

function assertResolutionReport(decisions) {
  try {
    if (
      !Array.isArray(decisions) ||
      decisions.length === 0 ||
      decisions.length > MAX_ITEMS ||
      decisions.some(
        (decision) =>
          typeof decision?.id !== "string" ||
          !/^(?:R|F)[1-9][0-9]{0,8}$/u.test(decision.id),
      )
    )
      throw workflowError("Invalid resolution report decisions.");
    const result = normalizeResolutionResult(
      {
        status: "RESOLVED",
        decisions,
        reason: "",
        question: "",
        options: [],
        whyBlocked: "",
        evidence: [],
      },
      decisions.map((decision) => ({ id: decision?.id })),
      new Set(),
    );
    if (!isDeepStrictEqual(result.decisions, decisions))
      throw workflowError(
        "Resolution report must contain normalized decisions.",
      );
  } catch {
    throw workflowError("Invalid resolution report decisions.");
  }
}

function assertCheckReport(checks) {
  try {
    if (!Array.isArray(checks) || checks.length === 0)
      throw workflowError("Invalid historical check report.");
    const requiredChecks = normalizeRequiredChecks(
      checks.map((check) => ({ id: check?.checkId, command: check?.command })),
      "ERR_INVALID_POLISHING_STATE",
    );
    // Historical NOT_RUN is a reported reservation, never execution authority.
    const trustedCommands = new Set(
      checks
        .filter((check) => check.status === "NOT_RUN")
        .map((check) => check.command),
    );
    const normalized = normalizeCheckResults(
      checks,
      requiredChecks,
      "ERR_INVALID_POLISHING_STATE",
      { trustedCommands },
    );
    if (!isDeepStrictEqual(normalized, checks))
      throw workflowError("Historical checks must be normalized.");
  } catch {
    throw workflowError("Invalid historical check report.");
  }
}

function assertReconsiderationReport(decisions) {
  try {
    if (
      !Array.isArray(decisions) ||
      decisions.length === 0 ||
      decisions.length > MAX_ITEMS ||
      decisions.some(
        (decision) =>
          typeof decision?.findingId !== "string" ||
          !REVIEW_FINDING_ID_PATTERN.test(decision.findingId),
      )
    )
      throw workflowError("Invalid reconsideration report decisions.");
    const result = normalizeReconsiderationResult(
      {
        status: "RESOLVED",
        decisions: decisions.map(({ findingId, ...decision }) => ({
          id: findingId,
          ...decision,
        })),
        question: "",
        options: [],
        whyBlocked: "",
        evidence: [],
      },
      decisions,
    );
    if (!isDeepStrictEqual(result.decisions, decisions))
      throw workflowError(
        "Reconsideration report must contain normalized decisions.",
      );
  } catch {
    throw workflowError("Invalid reconsideration report decisions.");
  }
}

// Accepted reports are context, never current blockers or validation evidence.
function normalizeWorkReports(reports) {
  if (
    !Array.isArray(reports) ||
    reports.length > 256 ||
    Buffer.byteLength(JSON.stringify(reports)) > 2 * 1024 * 1024
  ) {
    throw workflowError(
      "Work report history exceeds its bounded context capacity.",
    );
  }
  for (const report of reports) {
    if (!isRecord(report)) throw workflowError("Invalid work report history.");
    if (["BLOCKED", "UNFINISHED"].includes(report.status)) {
      assertExactFields(
        report,
        [
          "phase",
          "status",
          "reason",
          "evidence",
          ...(report.status === "UNFINISHED" ? ["recovery"] : []),
        ],
        "Blocked work report",
      );
      if (
        !["POLISH", "CHECK_AND_FIX", "RESOLVE_FINDINGS"].includes(report.phase)
      )
        throw workflowError("Invalid blocked work report checkpoint.");
      try {
        const normalized = normalizeCheckAndFixResult({
          status: "BLOCKED",
          summary: "",
          reason: report.reason,
          evidence: report.evidence,
          question: "",
          options: [],
          whyBlocked: "",
        });
        if (
          !isDeepStrictEqual(normalized, {
            status: "BLOCKED",
            reason: report.reason,
            evidence: report.evidence,
          })
        )
          throw workflowError("Blocked work report must be normalized.");
      } catch {
        throw workflowError("Invalid blocked work report.");
      }
      if (report.status === "UNFINISHED")
        assertUnfinishedResolutionReport(
          report,
          reports,
          reports.indexOf(report),
        );
      continue;
    }
    const findingReport = ["CLEAN_CONFIRM", "REVIEW", "CONFIRM"].includes(
      report.phase,
    );
    const inventoryArbitration = [
      "ARBITRATE_BOOTSTRAP",
      "ARBITRATE_VALIDATION_MIGRATION",
    ].includes(report.phase);
    const arbitrationReport =
      inventoryArbitration ||
      ["ARBITRATE_FINDING", "ARBITRATE_STAGNATION"].includes(report.phase);
    // Terminal confirmations may retain validation evidence without findings.
    const reportFields = ["RESOLVE_FINDINGS", "RECONSIDER_DISPUTES"].includes(
      report.phase,
    )
      ? ["decisions"]
      : arbitrationReport
        ? ["arbitration"]
        : report.phase === "CONFIRM"
          ? ["findings", "validationEvidence"].filter((field) =>
              Object.hasOwn(report, field),
            )
          : findingReport
            ? ["findings"]
            : ["summary"];
    assertExactFields(
      report,
      [
        "phase",
        ...reportFields,
        ...(report.phase === "FINALIZE"
          ? ["issues", "checks", "evidence"].filter((field) =>
              Object.hasOwn(report, field),
            )
          : []),
      ],
      "Work report",
    );
    if (
      ![
        "POLISH",
        "CHECK_AND_FIX",
        "FINALIZE",
        "CLEAN_CONFIRM",
        "REVIEW",
        "CONFIRM",
        "RESOLVE_FINDINGS",
        "RECONSIDER_DISPUTES",
        "ARBITRATE_FINDING",
        "ARBITRATE_STAGNATION",
        "ARBITRATE_BOOTSTRAP",
        "ARBITRATE_VALIDATION_MIGRATION",
      ].includes(report.phase)
    ) {
      throw workflowError("Invalid work report checkpoint.");
    }
    if (report.phase === "RESOLVE_FINDINGS") {
      assertResolutionReport(report.decisions);
    } else if (report.phase === "RECONSIDER_DISPUTES") {
      assertReconsiderationReport(report.decisions);
    } else if (arbitrationReport) {
      // History admits question outcomes without widening active arbitration authority.
      const finding = report.phase === "ARBITRATE_FINDING";
      const arbitration = report.arbitration;
      assertExactFields(
        arbitration,
        [...(finding ? ["findingId"] : []), "direction", "rationale"],
        "Historical arbitration",
      );
      const directions = inventoryArbitration
        ? [
            "USE_WORKER",
            "USE_REVIEWER",
            "SYNTHESIZE",
            ...(report.phase === "ARBITRATE_BOOTSTRAP"
              ? ["PRODUCT_DECISION_REQUIRED"]
              : []),
          ]
        : finding
          ? ["WORKER_CORRECT", "REVIEWER_CORRECT", "REQUIREMENT_AMBIGUOUS"]
          : [
              "CONTINUE_FIXES",
              "REWORK_IMPLEMENTATION",
              "RECONSIDER_FINDINGS",
              "PRODUCT_DECISION_REQUIRED",
            ];
      if (
        (finding &&
          (typeof arbitration.findingId !== "string" ||
            !REVIEW_FINDING_ID_PATTERN.test(arbitration.findingId))) ||
        !directions.includes(arbitration.direction) ||
        normalizeText(
          arbitration.rationale,
          "historical arbitration rationale",
        ) !== arbitration.rationale
      )
        throw workflowError("Invalid normalized historical arbitration.");
    } else if (findingReport) {
      if (
        reportFields.length === 0 ||
        (Object.hasOwn(report, "findings") &&
          normalizePersistedFindings(report.findings).length === 0)
      )
        throw workflowError("Finding report must be nonempty.");
      if (Object.hasOwn(report, "validationEvidence")) {
        const evidence = normalizeTextList(
          report.validationEvidence,
          "terminal validation evidence report",
          { code: "ERR_INVALID_POLISHING_STATE" },
        );
        if (!isDeepStrictEqual(evidence, report.validationEvidence))
          throw workflowError(
            "Terminal validation evidence must be normalized.",
          );
      }
    } else {
      normalizeSummary(report.summary, "Worker work summary");
      if (Object.hasOwn(report, "checks")) assertCheckReport(report.checks);
      if (Object.hasOwn(report, "evidence")) {
        const evidence = normalizeTextList(
          report.evidence,
          "finalization report evidence",
          { code: "ERR_INVALID_POLISHING_STATE" },
        );
        if (!isDeepStrictEqual(evidence, report.evidence))
          throw workflowError(
            "Finalization report evidence must be normalized.",
          );
      }
      if (Object.hasOwn(report, "issues")) {
        const issues = normalizeFinalizationIssues(
          report.issues,
          "ERR_INVALID_POLISHING_STATE",
        );
        if (issues.length === 0 || !isDeepStrictEqual(issues, report.issues))
          throw workflowError(
            "Finalization report must contain normalized nonempty issues.",
          );
      }
    }
  }
  return reports;
}

export function retainWorkReport(reports, report) {
  const next = reports.some((previous) => isDeepStrictEqual(previous, report))
    ? reports
    : [...reports, report];
  return normalizeWorkReports(next);
}

function normalizePersistedFindings(value, name = "Polishing findings") {
  try {
    return normalizeReviewFindings(value, "ERR_INVALID_POLISHING_STATE");
  } catch (cause) {
    throw new PolishingWorkflowError(`${name} are invalid.`, {
      cause,
      code: "ERR_INVALID_POLISHING_STATE",
    });
  }
}

function normalizePersistedFinalization(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    [
      "status",
      "skillPath",
      "summary",
      "issues",
      "requiredChecks",
      "validationInfrastructure",
      "validationInfrastructureFingerprint",
      "checks",
      "trustedCommandFingerprint",
      "trustedConfigurationFingerprint",
      "validationChanged",
      "fingerprint",
    ],
    "Polishing finalization result",
  );
  if (
    !["PASS", "FAIL"].includes(value.status) ||
    !HASH_PATTERN.test(value.fingerprint)
  ) {
    throw workflowError("Polishing finalization result is invalid.");
  }
  if (value.skillPath !== null) {
    normalizeRelativePath(
      value.skillPath,
      "finalization skill path",
      "ERR_INVALID_POLISHING_STATE",
    );
  }
  normalizeSummary(value.summary, "finalization summary");
  const issues = normalizeFinalizationIssues(
    value.issues,
    "ERR_INVALID_POLISHING_STATE",
  );
  const requiredChecks = normalizeRequiredChecks(
    value.requiredChecks,
    "ERR_INVALID_POLISHING_STATE",
  );
  normalizeValidationInfrastructure(
    value.validationInfrastructure,
    "ERR_INVALID_POLISHING_STATE",
  );
  if (
    !Array.isArray(value.checks) ||
    value.checks.length !== requiredChecks.length
  ) {
    throw workflowError("Polishing check evidence is incomplete.");
  }
  const checks = value.checks.map((check, index) => {
    if (
      !isRecord(check) ||
      Object.keys(check).length !== PERSISTED_CHECK_RESULT_FIELDS.length ||
      PERSISTED_CHECK_RESULT_FIELDS.some(
        (field) => !Object.hasOwn(check, field),
      )
    ) {
      throw workflowError("Polishing check evidence is invalid.");
    }
    const [normalized] = normalizeCheckResults(
      [
        {
          checkId: check.checkId,
          command: check.command,
          status: check.status,
          evidence: check.evidence,
        },
      ],
      [requiredChecks[index]],
      "ERR_INVALID_POLISHING_STATE",
    );
    const runnerResult = check.executor === "runner";
    const validRunnerResult =
      runnerResult &&
      !check.timedOut &&
      ((check.status === "PASS" &&
        check.exitCode === 0 &&
        check.signal === null) ||
        (check.status === "FAIL" &&
          (check.exitCode === null || check.exitCode !== 0) &&
          (check.exitCode !== null || check.signal !== null)));
    if (
      !["agent", "runner"].includes(check.executor) ||
      !["PASS", "FAIL"].includes(check.status) ||
      typeof check.timedOut !== "boolean" ||
      (runnerResult
        ? !HASH_PATTERN.test(check.commandIdentity) ||
          (check.exitCode !== null && !Number.isSafeInteger(check.exitCode)) ||
          (check.signal !== null &&
            (typeof check.signal !== "string" || check.signal.length > 32)) ||
          !validRunnerResult
        : check.commandIdentity !== null ||
          check.exitCode !== null ||
          check.signal !== null ||
          check.timedOut)
    ) {
      throw workflowError("Polishing check executor evidence is invalid.");
    }
    return Object.freeze({ ...normalized, ...check });
  });
  if (
    (value.status === "PASS" && issues.length !== 0) ||
    (value.status === "FAIL" && issues.length === 0) ||
    typeof value.validationChanged !== "boolean" ||
    !HASH_PATTERN.test(value.validationInfrastructureFingerprint) ||
    !HASH_PATTERN.test(value.trustedCommandFingerprint) ||
    !HASH_PATTERN.test(value.trustedConfigurationFingerprint) ||
    (value.status === "PASS" &&
      checks.some(({ status }) => status !== "PASS")) ||
    (value.status === "FAIL" &&
      !checks.some(({ status }) => status === "FAIL") &&
      !issues.some(({ command }) => command === RUNNER_HYGIENE_ISSUE_COMMAND))
  ) {
    throw workflowError("Polishing finalization result is inconsistent.");
  }
  return value;
}

function normalizePersistedValidation(value, name, trustedCommands) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    [
      "requiredChecks",
      "validationInfrastructure",
      "capabilityRequirements",
      "environmentBlockers",
    ],
    name,
  );
  normalizeRequiredChecks(value.requiredChecks, "ERR_INVALID_POLISHING_STATE", {
    maxItems: MAX_BOOTSTRAP_ITEMS,
  });
  normalizeValidationInfrastructure(
    value.validationInfrastructure,
    "ERR_INVALID_POLISHING_STATE",
    { maxItems: MAX_BOOTSTRAP_ITEMS },
  );
  if (
    !(
      value.capabilityRequirements === null &&
      value.environmentBlockers === null
    ) &&
    !validCapabilityReports(value, value.requiredChecks, trustedCommands, {
      legacy: true,
    })
  )
    throw workflowError("Persisted capability reports are invalid.");
  return value;
}

function normalizePersistedReview(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["status", "validationChange", "validationEvidence", "fingerprint"],
    "Polishing review result",
  );
  if (
    !["APPROVED", "FINDINGS"].includes(value.status) ||
    !["UNCHANGED", "ACCEPTED", "REJECTED"].includes(value.validationChange) ||
    !HASH_PATTERN.test(value.fingerprint)
  ) {
    throw workflowError("Polishing review result is invalid.");
  }
  normalizeTextList(value.validationEvidence, "review validation evidence", {
    allowEmpty: value.validationChange === "UNCHANGED",
    code: "ERR_INVALID_POLISHING_STATE",
  });
  if (value.status === "APPROVED" && value.validationChange === "REJECTED") {
    throw workflowError("Polishing review result is inconsistent.");
  }
  return value;
}

function normalizePersistedCandidateReview(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["status", "findingIds", "fingerprint"],
    "Polishing candidate-review result",
  );
  if (
    !["APPROVED", "FINDINGS"].includes(value.status) ||
    !Array.isArray(value.findingIds) ||
    value.findingIds.length > MAX_ITEMS ||
    value.findingIds.some((id) => !REVIEW_FINDING_ID_PATTERN.test(id)) ||
    new Set(value.findingIds).size !== value.findingIds.length ||
    (value.status === "APPROVED") !== (value.findingIds.length === 0) ||
    !HASH_PATTERN.test(value.fingerprint)
  ) {
    throw workflowError("Polishing candidate-review result is invalid.");
  }
  return value;
}

function normalizeCountRecord(value, name) {
  if (!isRecord(value) || Object.keys(value).length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError(`${name} is invalid.`);
  }
  for (const [id, count] of Object.entries(value)) {
    if (
      !REVIEW_FINDING_ID_PATTERN.test(id) ||
      !Number.isSafeInteger(count) ||
      count < 1
    ) {
      throw workflowError(`${name} is invalid.`);
    }
  }
  return value;
}

function normalizePendingDisputes(value) {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw workflowError("Polishing pending disputes are invalid.");
  }
  for (const dispute of value) {
    assertExactFields(
      dispute,
      ["findingId", "reason", "evidence"],
      "Polishing pending dispute",
    );
    if (!REVIEW_FINDING_ID_PATTERN.test(dispute.findingId)) {
      throw workflowError("Polishing pending dispute is invalid.");
    }
    normalizeText(dispute.reason, `dispute ${dispute.findingId} reason`);
    normalizeTextList(
      dispute.evidence,
      `dispute ${dispute.findingId} evidence`,
    );
  }
  if (new Set(value.map(({ findingId }) => findingId)).size !== value.length) {
    throw workflowError("Polishing pending disputes must be unique.");
  }
  return value;
}

function normalizeDisputeHistory(value, capacity) {
  if (!Array.isArray(value) || value.length > capacity) {
    throw workflowError("Polishing dispute history is invalid.");
  }
  assertDisputeHistoryFits(value);
  for (const entry of value) {
    assertExactFields(
      entry,
      [
        "findingId",
        "attempt",
        "direction",
        "workerReason",
        "workerEvidence",
        "reviewerReason",
        "reviewerEvidence",
      ],
      "Polishing dispute history entry",
    );
    if (
      !REVIEW_FINDING_ID_PATTERN.test(entry.findingId) ||
      !Number.isSafeInteger(entry.attempt) ||
      entry.attempt < 1 ||
      !["WITHDRAW", "UPHOLD"].includes(entry.direction)
    ) {
      throw workflowError("Polishing dispute history entry is invalid.");
    }
    normalizeText(entry.workerReason, "dispute Worker reason");
    normalizeTextList(entry.workerEvidence, "dispute Worker evidence");
    normalizeText(entry.reviewerReason, "dispute Reviewer reason");
    normalizeTextList(entry.reviewerEvidence, "dispute Reviewer evidence", {
      allowEmpty: true,
    });
  }
  return value;
}

function normalizeFindingArbitrations(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Polishing finding arbitrations are invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      ["findingId", "direction", "rationale"],
      "Polishing finding arbitration",
    );
    if (
      !REVIEW_FINDING_ID_PATTERN.test(entry.findingId) ||
      !["WORKER_CORRECT", "REVIEWER_CORRECT"].includes(entry.direction)
    ) {
      throw workflowError("Polishing finding arbitration is invalid.");
    }
    normalizeText(entry.rationale, "finding arbitration rationale");
  }
  if (new Set(value.map(({ findingId }) => findingId)).size !== value.length) {
    throw workflowError("Polishing finding arbitrations must be unique.");
  }
  return value;
}

function normalizeCorrectionHistory(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Polishing correction history is invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      ["round", "fingerprint", "finalizationIssueIds", "findingIds"],
      "Polishing correction history entry",
    );
    if (
      !Number.isSafeInteger(entry.round) ||
      entry.round < 1 ||
      !HASH_PATTERN.test(entry.fingerprint) ||
      !Array.isArray(entry.finalizationIssueIds) ||
      !Array.isArray(entry.findingIds) ||
      entry.finalizationIssueIds.some(
        (id) => !FINALIZATION_ISSUE_ID_PATTERN.test(id),
      ) ||
      entry.findingIds.some((id) => !REVIEW_FINDING_ID_PATTERN.test(id)) ||
      new Set(entry.finalizationIssueIds).size !==
        entry.finalizationIssueIds.length ||
      new Set(entry.findingIds).size !== entry.findingIds.length ||
      (entry.finalizationIssueIds.length === 0) ===
        (entry.findingIds.length === 0)
    ) {
      throw workflowError("Polishing correction history entry is invalid.");
    }
  }
  return value;
}

function normalizeStagnationDirection(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["direction", "rationale"],
    "Polishing stagnation direction",
  );
  if (
    ![
      "CONTINUE_FIXES",
      "REWORK_IMPLEMENTATION",
      "RECONSIDER_FINDINGS",
    ].includes(value.direction)
  ) {
    throw workflowError("Polishing stagnation direction is invalid.");
  }
  normalizeText(value.rationale, "stagnation direction rationale");
  return value;
}

function normalizeFindingOverrides(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Polishing finding overrides are invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      ["findingId", "fingerprint"],
      "Polishing finding override",
    );
    if (
      !REVIEW_FINDING_ID_PATTERN.test(entry.findingId) ||
      !HASH_PATTERN.test(entry.fingerprint)
    ) {
      throw workflowError("Polishing finding override is invalid.");
    }
  }
  if (
    new Set(
      value.map(({ findingId, fingerprint }) => `${findingId}:${fingerprint}`),
    ).size !== value.length
  ) {
    throw workflowError("Polishing finding overrides must be unique.");
  }
  return value;
}

function assertSnapshot(value) {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== SNAPSHOT_FIELDS.size ||
    Object.keys(value).some((field) => !SNAPSHOT_FIELDS.has(field)) ||
    value.schemaVersion !== 1 ||
    typeof value.projectPath !== "string" ||
    !isAbsolute(value.projectPath) ||
    resolve(value.projectPath) !== value.projectPath ||
    !Array.isArray(value.allowedPaths) ||
    value.allowedPaths.some(
      (path) =>
        typeof path !== "string" || path.length === 0 || isAbsolute(path),
    ) ||
    (value.head !== null && typeof value.head !== "string") ||
    (value.branch !== null && typeof value.branch !== "string") ||
    typeof value.detached !== "boolean" ||
    typeof value.clean !== "boolean" ||
    typeof value.identityAvailable !== "boolean" ||
    [
      "refsFingerprint",
      "trackedContentFingerprint",
      "untrackedContentFingerprint",
      "contentFingerprint",
      "indexFingerprint",
      "remoteConfigurationFingerprint",
      "identityFingerprint",
    ].some((field) => !HASH_PATTERN.test(value[field]))
  ) {
    throw workflowError("Polishing repository baseline is invalid.");
  }
  return value;
}

export function normalizePipelineState(value) {
  if (isRecord(value) && !Object.hasOwn(value, "artifactRoot")) {
    value = { ...value, artifactRoot: "LOCAL_ARTIFACTS" };
  }
  if (!isRecord(value)) throw workflowError("Polishing state is invalid.");
  const { catalogReviewInfrastructureFingerprint, ...fields } = value;
  if (
    Object.keys(fields).length !== PIPELINE_STATE_FIELDS.size ||
    Object.keys(fields).some((field) => !PIPELINE_STATE_FIELDS.has(field)) ||
    (Object.hasOwn(value, "catalogReviewInfrastructureFingerprint") &&
      (typeof catalogReviewInfrastructureFingerprint !== "string" ||
        !HASH_PATTERN.test(catalogReviewInfrastructureFingerprint) ||
        value.preflightComplete !== true ||
        !["REVIEW", "CLEAN_CONFIRM", "WAITING_FOR_USER"].includes(
          value.workflowState,
        ))) ||
    !WORKFLOW_STATES.includes(value.workflowState)
  ) {
    throw workflowError("Polishing state is invalid.");
  }
  if (
    value.clarificationRoot !== null &&
    (typeof value.clarificationRoot !== "string" ||
      !isAbsolute(value.clarificationRoot) ||
      resolve(value.clarificationRoot) !== value.clarificationRoot ||
      /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value.clarificationRoot))
  ) {
    throw workflowError("Clarification confinement root is invalid.");
  }
  if (value.preflightComplete && value.clarificationRoot === null)
    throw workflowError("Clarification confinement root is missing.");
  if (
    typeof value.artifactRoot !== "string" ||
    value.artifactRoot.includes("\\") ||
    /^[a-zA-Z]:\//u.test(value.artifactRoot) ||
    posix.isAbsolute(value.artifactRoot) ||
    posix.normalize(value.artifactRoot) !== value.artifactRoot ||
    value.artifactRoot === "." ||
    value.artifactRoot === ".." ||
    value.artifactRoot.startsWith("../") ||
    value.artifactRoot === ".git" ||
    value.artifactRoot.startsWith(".git/") ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value.artifactRoot)
  ) {
    throw workflowError("Polishing artifact root is invalid.");
  }
  for (const field of [
    "preflightComplete",
    "proactiveClarification",
    "proactiveClarificationComplete",
    "clarificationFrozen",
    "refreezeRequired",
    "bootstrapArbitrationUsed",
    "validationMigrationPending",
    "candidateMigrationPending",
    "pendingCorrection",
    "availabilityCorrectionCharged",
    "stagnationArbitrationUsed",
  ]) {
    if (typeof value[field] !== "boolean") {
      throw workflowError(`Polishing state field ${field} is invalid.`);
    }
  }
  if (value.settings !== null) {
    const settings = normalizeSettings(value.settings);
    assertSettings(settings);
    if (settings !== value.settings) {
      value = { ...value, settings };
    }
  }
  const finalizationGuidance = normalizeFinalizationGuidanceDecision(
    value.finalizationGuidance,
  );
  const guidanceMayBeLegacyPending =
    value.validationMigrationPending ||
    [value.workerValidation, value.reviewerValidation].some(
      (validation) => validation?.capabilityRequirements === null,
    ) ||
    (["CLARIFY", "BOOTSTRAP", "WAITING_FOR_USER"].includes(
      value.workflowState,
    ) &&
      value.resolvedSummary === null);
  const guidanceExempt = ["DONE", "FAILED", "CANCELED", "HANDOFF"].includes(
    value.workflowState,
  );
  if (
    (!value.preflightComplete &&
      finalizationGuidance !== null &&
      value.settings === null) ||
    (value.preflightComplete &&
      !guidanceExempt &&
      !guidanceMayBeLegacyPending &&
      finalizationGuidance === null) ||
    (finalizationGuidance !== null &&
      value.settings !== null &&
      finalizationGuidance.configuredPolicy !== value.settings.finalization)
  ) {
    throw workflowError("Polishing finalization guidance is inconsistent.");
  }
  const policy = polishingPolicy(value.settings);
  normalizeWorkReports(value.workReports);
  const primaryFindings = normalizePersistedFindings(value.primaryFindings);
  if (
    primaryFindings.length > 0 &&
    (!combinedReview(value.settings) ||
      value.candidateConfirmationFingerprint !== null ||
      ![
        "CHECK_AND_FIX",
        "CLEAN_CONFIRM",
        "WAITING_FOR_USER",
        "FAILED",
      ].includes(value.workflowState))
  ) {
    throw workflowError("Polishing primary findings are inapplicable.");
  }
  if (!policy.bootstrapArbitration && value.bootstrapArbitrationUsed) {
    throw workflowError("Polishing bootstrap arbitration is unavailable.");
  }
  if (
    value.cleanConfirmationFingerprint !== null &&
    (typeof value.cleanConfirmationFingerprint !== "string" ||
      !HASH_PATTERN.test(value.cleanConfirmationFingerprint))
  ) {
    throw workflowError("Polishing clean confirmation fingerprint is invalid.");
  }
  for (const [field, label] of [
    ["candidateReviewedFingerprint", "candidate-reviewed"],
    ["candidateConfirmationFingerprint", "candidate-confirmation"],
  ]) {
    if (
      value[field] !== null &&
      (typeof value[field] !== "string" || !HASH_PATTERN.test(value[field]))
    ) {
      throw workflowError(`Polishing ${label} fingerprint is invalid.`);
    }
  }
  if (typeof value.lazySourceForkConsumed !== "boolean") {
    throw workflowError("Polishing source-fork state is invalid.");
  }
  if (value.authenticationSourceForkRecovery !== null) {
    assertExactFields(
      value.authenticationSourceForkRecovery,
      ["role", "contextKey"],
      "Polishing authentication source-fork recovery",
    );
    if (
      !value.preflightComplete ||
      value.authenticationSourceForkRecovery.role === "arbiter" ||
      !resolveActiveRoles(value.settings).includes(
        value.authenticationSourceForkRecovery.role,
      ) ||
      (policy.primarySessionScope === "run" && !value.lazySourceForkConsumed) ||
      typeof value.authenticationSourceForkRecovery.contextKey !== "string" ||
      !HASH_PATTERN.test(value.authenticationSourceForkRecovery.contextKey)
    ) {
      throw workflowError(
        "Polishing authentication source-fork recovery is invalid.",
      );
    }
  }
  const trustedValidation = normalizeTrustedValidation(value.trustedValidation);
  if (trustedValidation !== value.trustedValidation) {
    value = { ...value, trustedValidation };
  }
  if (
    value.settings !== null &&
    !isDeepStrictEqual(
      value.settings.trustedChecks,
      trustedValidation.commands.map(({ alias }) => alias),
    )
  ) {
    throw workflowError(
      "Polishing trusted validation selection is inconsistent.",
    );
  }
  if (
    value.preflightComplete !== (value.repositoryBaseline !== null) ||
    value.preflightComplete !== (value.backendVersions !== null) ||
    value.preflightComplete !== (value.clarificationPath !== null) ||
    (value.preflightComplete && value.settings === null)
  ) {
    throw workflowError("Polishing preflight state is invalid.");
  }
  if (value.repositoryBaseline !== null) {
    assertSnapshot(value.repositoryBaseline);
  }
  if (value.backendVersions !== null) {
    const activeRoles = resolveActiveRoles(value.settings);
    if (
      !isRecord(value.backendVersions) ||
      Object.keys(value.backendVersions).length !== activeRoles.length ||
      !activeRoles.every((role) => Object.hasOwn(value.backendVersions, role))
    ) {
      throw workflowError("Polishing backend versions are invalid.");
    }
    for (const [role, version] of Object.entries(value.backendVersions)) {
      if (
        (role !== "arbiter" && typeof version !== "string") ||
        (version !== null &&
          (typeof version !== "string" || version.trim().length === 0))
      ) {
        throw workflowError(`Polishing ${role} version is invalid.`);
      }
    }
  }
  if (
    value.clarificationPath !== null &&
    (typeof value.clarificationPath !== "string" ||
      !isAbsolute(value.clarificationPath))
  ) {
    throw workflowError("Polishing clarification path is invalid.");
  }
  const pendingEdit = normalizePendingEdit(value.pendingEdit);
  if (
    pendingEdit !== null &&
    !["WAITING_FOR_USER", "FAILED"].includes(value.workflowState)
  ) {
    throw workflowError("Polishing pending edit is inapplicable.");
  }
  if (
    (!value.proactiveClarification && !value.proactiveClarificationComplete) ||
    (!value.proactiveClarificationComplete &&
      !["CLARIFY", "WAITING_FOR_USER", "FAILED"].includes(
        value.workflowState,
      )) ||
    (pendingEdit !== null &&
      (pendingEdit.action === "proactive-clarification") !==
        (value.proactiveClarification && !value.proactiveClarificationComplete))
  ) {
    throw workflowError("Polishing proactive clarification state is invalid.");
  }
  const workerSummary = normalizeOptionalSummary(
    value.workerSummary,
    "Worker summary",
  );
  const reviewerSummary = normalizeOptionalSummary(
    value.reviewerSummary,
    "Reviewer summary",
  );
  const workerValidation = normalizePersistedValidation(
    value.workerValidation,
    "Worker validation evidence",
    trustedValidation.commands,
  );
  const reviewerValidation = normalizePersistedValidation(
    value.reviewerValidation,
    "Reviewer validation evidence",
    trustedValidation.commands,
  );
  const resolvedSummary = normalizeOptionalSummary(
    value.resolvedSummary,
    "resolved summary",
  );
  const disagreement = normalizeDisagreement(value.bootstrapDisagreement);
  const validationMigrationDisagreement = normalizeDisagreement(
    value.validationMigrationDisagreement,
  );
  const bootstrapCorrections = normalizeBootstrapCorrections(
    value.bootstrapCorrections,
  );
  const pendingBootstrapCorrection =
    value.pendingBootstrapCorrection === null
      ? null
      : normalizeBootstrapCorrection(value.pendingBootstrapCorrection);
  if (
    pendingBootstrapCorrection !== null &&
    !bootstrapCorrections.some((correction) =>
      isDeepStrictEqual(correction, pendingBootstrapCorrection),
    )
  ) {
    throw workflowError(
      "Polishing pending bootstrap correction is inconsistent.",
    );
  }
  const finalizationRecovery = normalizeFinalizationRecovery(
    value.finalizationRecovery,
    value,
  );
  const finalizationCorrection = normalizeFinalizationCorrection(
    value.finalizationCorrection,
  );
  const pendingFinalizationCorrection = normalizeFinalizationCorrection(
    value.pendingFinalizationCorrection,
  );
  if (
    pendingFinalizationCorrection !== null &&
    !isDeepStrictEqual(pendingFinalizationCorrection, finalizationCorrection)
  ) {
    throw workflowError(
      "Polishing pending finalization correction is inconsistent.",
    );
  }
  const reviewCorrection =
    value.reviewCorrection === null
      ? null
      : normalizeReviewCorrection(value.reviewCorrection);
  const pendingReviewCorrection =
    value.pendingReviewCorrection === null
      ? null
      : normalizeReviewCorrection(value.pendingReviewCorrection);
  if (
    pendingReviewCorrection !== null &&
    (reviewCorrection === null ||
      !sameReviewCorrectionScope(pendingReviewCorrection, reviewCorrection))
  ) {
    throw workflowError("Polishing pending review correction is inconsistent.");
  }
  const confirmationCorrection =
    value.confirmationCorrection === null
      ? null
      : normalizeConfirmationCorrection(value.confirmationCorrection);
  const pendingConfirmationCorrection =
    value.pendingConfirmationCorrection === null
      ? null
      : normalizeConfirmationCorrection(value.pendingConfirmationCorrection);
  if (
    pendingConfirmationCorrection !== null &&
    (confirmationCorrection === null ||
      !sameReviewCorrectionScope(
        pendingConfirmationCorrection,
        confirmationCorrection,
      ))
  ) {
    throw workflowError(
      "Polishing pending confirmation correction is inconsistent.",
    );
  }
  const lazyCorrections = normalizeLazyCorrections(value.lazyCorrections);
  const pendingLazyCorrection =
    value.pendingLazyCorrection === null
      ? null
      : normalizeLazyCorrection(value.pendingLazyCorrection);
  if (
    pendingLazyCorrection !== null &&
    !lazyCorrections.some(
      (correction) =>
        sameLazyCorrectionScope(correction, pendingLazyCorrection) &&
        correction.fixRoundCharged === pendingLazyCorrection.fixRoundCharged,
    )
  ) {
    throw workflowError("Polishing pending lazy correction is inconsistent.");
  }
  const polishSummary = normalizeOptionalSummary(
    value.polishSummary,
    "polishing summary",
  );
  const finalizationResult = normalizePersistedFinalization(
    value.finalizationResult,
  );
  const requiredChecks =
    value.requiredChecks === null
      ? null
      : normalizeRequiredChecks(
          value.requiredChecks,
          "ERR_INVALID_POLISHING_STATE",
        );
  const validationInfrastructure =
    value.validationInfrastructure === null
      ? null
      : normalizeValidationInfrastructure(
          value.validationInfrastructure,
          "ERR_INVALID_POLISHING_STATE",
        );
  const reviewResult = normalizePersistedReview(value.reviewResult);
  const candidateReviewResult = normalizePersistedCandidateReview(
    value.candidateReviewResult,
  );
  if (
    (requiredChecks === null) !== (resolvedSummary === null) ||
    (validationInfrastructure === null) !== (resolvedSummary === null) ||
    (value.validationInfrastructureFingerprint === null) !==
      (resolvedSummary === null) ||
    (value.validationInfrastructureFingerprint !== null &&
      !HASH_PATTERN.test(value.validationInfrastructureFingerprint))
  ) {
    throw workflowError("Polishing validation inventory is inconsistent.");
  }
  if (
    requiredChecks !== null &&
    trustedValidation.commands.some(
      ({ command }) =>
        !requiredChecks.some((required) => required.command === command),
    )
  ) {
    throw workflowError(
      "Polishing validation inventory omits a trusted command.",
    );
  }
  if (
    resolvedSummary !== null &&
    !value.validationMigrationPending &&
    !guidanceMayBeLegacyPending &&
    ["skill", "file"].includes(finalizationGuidance?.selection) &&
    !validationInfrastructure.includes(finalizationGuidance.skillPath)
  ) {
    throw workflowError(
      "Polishing validation inventory omits frozen finalization guidance.",
    );
  }
  if (finalizationResult !== null) {
    const trustedCommands = new Map(
      trustedValidation.commands.map((command) => [command.command, command]),
    );
    const matchesEstablishedValidation =
      isDeepStrictEqual(finalizationResult.requiredChecks, requiredChecks) &&
      isDeepStrictEqual(
        finalizationResult.validationInfrastructure,
        validationInfrastructure,
      ) &&
      finalizationResult.validationInfrastructureFingerprint ===
        value.validationInfrastructureFingerprint;
    if (
      finalizationResult.trustedCommandFingerprint !==
        trustedValidation.commandFingerprint ||
      finalizationResult.trustedConfigurationFingerprint !==
        trustedValidation.configurationFingerprint ||
      finalizationResult.checks.some((check) => {
        const trusted = trustedCommands.get(check.command);
        return trusted === undefined
          ? check.executor !== "agent" || check.commandIdentity !== null
          : check.executor !== "runner" ||
              check.commandIdentity !== trusted.identity;
      })
    ) {
      throw workflowError(
        "Polishing trusted finalization evidence is inconsistent.",
      );
    }
    const reviewedChange = reviewResult?.validationChange;
    if (
      (!finalizationResult.validationChanged &&
        !matchesEstablishedValidation) ||
      (finalizationResult.validationChanged &&
        reviewResult !== null &&
        reviewedChange !== "ACCEPTED" &&
        matchesEstablishedValidation) ||
      (reviewedChange === "UNCHANGED" &&
        finalizationResult.validationChanged) ||
      (reviewedChange === "ACCEPTED" &&
        !finalizationResult.validationChanged) ||
      (reviewedChange === "ACCEPTED" && !matchesEstablishedValidation)
    ) {
      throw workflowError(
        "Polishing validation-change evidence is inconsistent.",
      );
    }
  }
  const findings = normalizePersistedFindings(value.findings);
  const previousFindings = normalizePersistedFindings(
    value.previousFindings,
    "Polishing previous findings",
  );
  const pendingDisputes = normalizePendingDisputes(value.pendingDisputes);
  const disputeCounts = normalizeCountRecord(
    value.disputeCounts,
    "Polishing dispute counts",
  );
  const sameFindingRounds = normalizeCountRecord(
    value.sameFindingRounds,
    "Polishing same-finding rounds",
  );
  normalizeDisputeHistory(
    value.disputeHistory,
    value.settings === null ? 0 : disputeHistoryCapacity(value.settings),
  );
  const findingArbitrations = normalizeFindingArbitrations(
    value.findingArbitrations,
  );
  normalizeCorrectionHistory(value.correctionHistory);
  const stagnationDirection = normalizeStagnationDirection(
    value.stagnationDirection,
  );
  const findingOverrides = normalizeFindingOverrides(value.findingOverrides);
  const gateState = {
    ...value,
    candidateReviewResult,
    finalizationResult,
    reviewResult,
    findingOverrides,
    findings,
    previousFindings,
    pendingDisputes,
  };
  const acceptedCandidateGate = candidateGatePassed(gateState);
  if (
    (value.finalizedFingerprint !== null &&
      !HASH_PATTERN.test(value.finalizedFingerprint)) ||
    (value.reviewedFingerprint !== null &&
      !HASH_PATTERN.test(value.reviewedFingerprint)) ||
    !Number.isSafeInteger(value.blockedSinceStagnation) ||
    value.blockedSinceStagnation < 0 ||
    !Number.isSafeInteger(value.additionalFixRounds) ||
    value.additionalFixRounds < 0 ||
    (value.settings !== null &&
      !Number.isSafeInteger(
        value.settings.maxFixRounds + value.additionalFixRounds,
      )) ||
    !Array.isArray(value.reviewReconsideration) ||
    value.reviewReconsideration.length > MAX_ITEMS ||
    value.reviewReconsideration.some(
      (id) => !REVIEW_FINDING_ID_PATTERN.test(id),
    ) ||
    new Set(value.reviewReconsideration).size !==
      value.reviewReconsideration.length
  ) {
    throw workflowError("Polishing correction state is invalid.");
  }
  if (value.stagnationArbitrationUsed !== (stagnationDirection !== null)) {
    throw workflowError("Polishing stagnation arbitration is inconsistent.");
  }
  if (
    (!policy.primaryConvergence &&
      (value.candidateConfirmationFingerprint !== null ||
        lazyCorrections.length !== 0 ||
        pendingLazyCorrection !== null ||
        ["CHECK_AND_FIX", "CLEAN_CONFIRM"].includes(value.workflowState))) ||
    (policy.terminalConfirmer !== "worker" &&
      value.cleanConfirmationFingerprint !== null) ||
    (policy.primarySessionScope !== "run" && value.lazySourceForkConsumed) ||
    (!policy.independentReview && value.workflowState === "REVIEW")
  ) {
    throw workflowError("Polishing mode state is inconsistent.");
  }
  if (
    !policy.independentReview &&
    (reviewCorrection !== null ||
      pendingReviewCorrection !== null ||
      pendingDisputes.length !== 0 ||
      Object.keys(disputeCounts).length !== 0 ||
      value.disputeHistory.length !== 0 ||
      findingArbitrations.length !== 0 ||
      value.stagnationArbitrationUsed ||
      stagnationDirection !== null ||
      value.reviewReconsideration.length !== 0 ||
      value.findingOverrides.length !== 0)
  ) {
    throw workflowError("Lazy polishing review state is inconsistent.");
  }
  if (
    value.cleanConfirmationFingerprint !== null &&
    (policy.terminalConfirmer !== "worker" ||
      value.cleanConfirmationFingerprint !== value.finalizedFingerprint ||
      value.cleanConfirmationFingerprint !== value.reviewedFingerprint ||
      reviewResult?.status !== "APPROVED")
  ) {
    throw workflowError("Polishing clean confirmation is inconsistent.");
  }
  if (
    value.candidateConfirmationFingerprint !== null &&
    (!policy.primaryConvergence ||
      (combinedReview(value.settings)
        ? value.candidateReviewedFingerprint !== null &&
          value.candidateConfirmationFingerprint !==
            value.candidateReviewedFingerprint
        : value.candidateConfirmationFingerprint !==
            value.candidateReviewedFingerprint ||
          candidateReviewResult?.status !== "APPROVED"))
  ) {
    throw workflowError("Polishing candidate confirmation is inconsistent.");
  }
  if (
    (reviewerSummary !== null && workerSummary === null) ||
    (!value.validationMigrationPending &&
      (workerValidation !== null) !== (workerSummary !== null)) ||
    (!value.validationMigrationPending &&
      (reviewerValidation !== null) !== (reviewerSummary !== null)) ||
    (value.validationMigrationPending &&
      reviewerValidation !== null &&
      workerValidation === null) ||
    ((resolvedSummary !== null || disagreement !== null) &&
      (workerSummary === null ||
        (policy.independentBootstrap && reviewerSummary === null))) ||
    (resolvedSummary !== null && disagreement !== null)
  ) {
    throw workflowError("Polishing bootstrap context is inconsistent.");
  }
  if (
    value.bootstrapArbitrationUsed &&
    (disagreement !== null ||
      resolvedSummary === null ||
      typeof value.backendVersions?.arbiter !== "string")
  ) {
    throw workflowError("Polishing bootstrap arbitration is inconsistent.");
  }
  if (
    !policy.independentBootstrap &&
    (reviewerSummary !== null ||
      reviewerValidation !== null ||
      disagreement !== null ||
      value.bootstrapArbitrationUsed)
  ) {
    throw workflowError("Lazy polishing bootstrap state is inconsistent.");
  }
  if (!policy.primaryConvergence && lazyCorrections.length !== 0) {
    throw workflowError("Polishing lazy correction state is inapplicable.");
  }
  if (
    value.validationMigrationPending &&
    (!value.preflightComplete ||
      resolvedSummary === null ||
      ["CLARIFY", "BOOTSTRAP", "DONE"].includes(value.workflowState))
  ) {
    throw workflowError("Polishing validation migration is inapplicable.");
  }
  if (
    value.candidateMigrationPending &&
    (value.workflowState !== "WAITING_FOR_USER" ||
      !value.preflightComplete ||
      resolvedSummary === null)
  ) {
    throw workflowError("Polishing candidate migration is inapplicable.");
  }
  if (
    finalizationCorrection !== null &&
    (value.repositoryBaseline === null ||
      value.repositoryBaseline.contentFingerprint !==
        finalizationCorrection.contentFingerprint ||
      ["CLARIFY", "BOOTSTRAP"].includes(value.workflowState) ||
      (pendingFinalizationCorrection !== null &&
        !["FINALIZE", "WAITING_FOR_USER", "FAILED"].includes(
          value.workflowState,
        )))
  ) {
    throw workflowError("Polishing finalization correction is inapplicable.");
  }
  if (
    reviewCorrection !== null &&
    ((value.candidateReviewedFingerprint ??
      value.repositoryBaseline?.contentFingerprint) !==
      reviewCorrection.contentFingerprint ||
      (pendingReviewCorrection !== null &&
        !["REVIEW", "WAITING_FOR_USER", "FAILED"].includes(
          value.workflowState,
        )))
  ) {
    throw workflowError("Polishing review correction is inapplicable.");
  }
  if (
    reviewCorrection !== null &&
    value.workflowState === "REVIEW" &&
    pendingReviewCorrection === null &&
    (candidateReviewResult === null ||
      value.candidateReviewedFingerprint === null)
  ) {
    throw workflowError(
      "Polishing review correction is missing its pending marker.",
    );
  }
  if (
    confirmationCorrection !== null &&
    (finalizationResult?.status !== "PASS" ||
      value.finalizedFingerprint !==
        confirmationCorrection.contentFingerprint ||
      finalizationResult.validationInfrastructureFingerprint !==
        confirmationCorrection.validationInfrastructureFingerprint ||
      (pendingConfirmationCorrection !== null &&
        !["CONFIRM", "WAITING_FOR_USER", "FAILED"].includes(
          value.workflowState,
        )))
  ) {
    throw workflowError("Polishing confirmation correction is inapplicable.");
  }
  if (
    confirmationCorrection !== null &&
    value.workflowState === "CONFIRM" &&
    pendingConfirmationCorrection === null &&
    (reviewResult === null || value.reviewedFingerprint === null)
  ) {
    throw workflowError(
      "Polishing confirmation correction is missing its pending marker.",
    );
  }
  if (
    pendingLazyCorrection !== null &&
    ![pendingLazyCorrection.phase, "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    )
  ) {
    throw workflowError("Polishing lazy correction is inapplicable.");
  }
  if (
    (validationMigrationDisagreement !== null &&
      (!value.validationMigrationPending ||
        workerValidation === null ||
        reviewerValidation === null)) ||
    (pendingBootstrapCorrection?.phase === "validation-migration" &&
      pendingBootstrapCorrection.contract === "bootstrap-arbitration" &&
      validationMigrationDisagreement === null)
  ) {
    throw workflowError(
      "Polishing validation migration checkpoint is invalid.",
    );
  }
  const currentFindingIds = new Set(findings.map(({ id }) => id));
  const previousFindingIds = new Set(previousFindings.map(({ id }) => id));
  const deferredDisputes =
    pendingDisputes.length > 0 &&
    findings.length === 0 &&
    pendingDisputes.every(({ findingId }) =>
      previousFindingIds.has(findingId),
    ) &&
    ([
      "POLISH",
      "CHECK_AND_FIX",
      "CLEAN_CONFIRM",
      "REVIEW",
      "FINALIZE",
      "CONFIRM",
      "WAITING_FOR_USER",
      "FAILED",
    ].includes(value.workflowState) ||
      (value.workflowState === "RESOLVE_FINDINGS" &&
        finalizationResult?.status === "FAIL"));
  if (
    (pendingDisputes.some(
      ({ findingId }) => !currentFindingIds.has(findingId),
    ) &&
      !deferredDisputes) ||
    (["FINALIZE", "CONFIRM", "REVIEW"].includes(value.workflowState) &&
      pendingDisputes.length > 0 &&
      !deferredDisputes) ||
    value.reviewReconsideration.some(
      (id) => !currentFindingIds.has(id) && !previousFindingIds.has(id),
    ) ||
    Object.keys(disputeCounts).some(
      (id) =>
        !currentFindingIds.has(id) &&
        !pendingDisputes.some(({ findingId }) => findingId === id) &&
        !value.disputeHistory.some((entry) => entry.findingId === id) &&
        !value.findingOverrides.some((entry) => entry.findingId === id),
    )
  ) {
    throw workflowError("Polishing finding progress is inconsistent.");
  }
  if (
    finalizationResult === null &&
    (value.finalizedFingerprint !== null ||
      value.cleanConfirmationFingerprint !== null ||
      reviewResult !== null ||
      value.reviewedFingerprint !== null)
  ) {
    throw workflowError("Polishing validation progress is inconsistent.");
  }
  if (
    finalizationResult !== null &&
    ((finalizationResult.status === "PASS") !==
      (value.finalizedFingerprint === finalizationResult.fingerprint) ||
      (value.reviewedFingerprint !== null &&
        value.reviewedFingerprint !== value.finalizedFingerprint) ||
      (finalizationResult.status === "FAIL" &&
        (reviewResult !== null ||
          value.reviewedFingerprint !== null ||
          value.cleanConfirmationFingerprint !== null)))
  ) {
    throw workflowError("Polishing finalization progress is inconsistent.");
  }
  if (
    (candidateReviewResult === null) !==
      (value.candidateReviewedFingerprint === null) ||
    (candidateReviewResult !== null &&
      candidateReviewResult.fingerprint !== value.candidateReviewedFingerprint)
  ) {
    throw workflowError("Polishing candidate-review evidence is inconsistent.");
  }
  if (
    (reviewResult === null) !== (value.reviewedFingerprint === null) ||
    (reviewResult !== null &&
      reviewResult.fingerprint !== value.reviewedFingerprint) ||
    (reviewResult?.status === "APPROVED" && findings.length !== 0)
  ) {
    throw workflowError("Polishing review evidence is inconsistent.");
  }
  if (
    value.repositoryBaseline !== null &&
    (value.candidateReviewedFingerprint !== null ||
      value.candidateConfirmationFingerprint !== null) &&
    ![
      "FINALIZE",
      "CONFIRM",
      "RESOLVE_FINDINGS",
      "HANDOFF",
      "DONE",
      "WAITING_FOR_USER",
      "FAILED",
    ].includes(value.workflowState) &&
    ((value.candidateReviewedFingerprint !== null &&
      value.candidateReviewedFingerprint !==
        value.repositoryBaseline.contentFingerprint) ||
      (value.candidateConfirmationFingerprint !== null &&
        value.candidateConfirmationFingerprint !==
          value.repositoryBaseline.contentFingerprint))
  ) {
    throw workflowError("Polishing candidate fingerprint is inconsistent.");
  }
  if (value.availabilityCorrectionCharged && !value.pendingCorrection) {
    throw workflowError(
      "Availability correction charge has no pending correction.",
    );
  }
  // A reconciled partial resolution retains blockers and its one charged fix,
  // but carries no approval for the changed content.
  const pendingResolution =
    value.pendingCorrection &&
    ["RESOLVE_FINDINGS", "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    );
  if (
    value.repositoryBaseline !== null &&
    ((finalizationResult !== null &&
      !(pendingResolution && finalizationResult.status === "FAIL") &&
      finalizationResult.fingerprint !==
        value.repositoryBaseline.contentFingerprint) ||
      (value.finalizedFingerprint !== null &&
        value.finalizedFingerprint !==
          value.repositoryBaseline.contentFingerprint) ||
      (value.reviewedFingerprint !== null &&
        value.reviewedFingerprint !==
          value.repositoryBaseline.contentFingerprint) ||
      (value.cleanConfirmationFingerprint !== null &&
        value.cleanConfirmationFingerprint !==
          value.repositoryBaseline.contentFingerprint))
  ) {
    throw workflowError("Polishing content fingerprints are inconsistent.");
  }
  if (
    (findings.length > 0 || pendingDisputes.length > 0) &&
    value.reviewedFingerprint === null &&
    value.candidateReviewedFingerprint === null &&
    (finalizationResult?.status !== "PASS" ||
      value.finalizedFingerprint === null) &&
    !(
      pendingResolution &&
      findings.length > 0 &&
      pendingDisputes.length === 0
    ) &&
    !deferredDisputes &&
    finalizationRecovery.feedback === null &&
    !(
      policy.primaryConvergence &&
      value.workflowState === "CHECK_AND_FIX" &&
      value.pendingCorrection &&
      findings.length > 0 &&
      pendingDisputes.length === 0
    )
  ) {
    throw workflowError("Polishing review progress is inconsistent.");
  }
  if (
    value.pendingCorrection &&
    ![
      "POLISH",
      "RESOLVE_FINDINGS",
      "FINALIZE",
      "CHECK_AND_FIX",
      "CLEAN_CONFIRM",
      "REVIEW",
      "CONFIRM",
      "WAITING_FOR_USER",
      "FAILED",
    ].includes(value.workflowState)
  ) {
    throw workflowError("Polishing pending correction is inapplicable.");
  }
  if (
    stagnationDirection !== null &&
    ![
      "CHECK_AND_FIX",
      "CLEAN_CONFIRM",
      "POLISH",
      "FINALIZE",
      "REVIEW",
      "CONFIRM",
      "RESOLVE_FINDINGS",
      "HANDOFF",
      "DONE",
      "WAITING_FOR_USER",
      "FAILED",
    ].includes(value.workflowState)
  ) {
    throw workflowError("Polishing stagnation direction is inapplicable.");
  }
  if (
    value.reviewReconsideration.length > 0 &&
    ![
      "CHECK_AND_FIX",
      "CLEAN_CONFIRM",
      "REVIEW",
      "CONFIRM",
      "WAITING_FOR_USER",
      "FAILED",
    ].includes(value.workflowState)
  ) {
    throw workflowError("Polishing review reconsideration is inapplicable.");
  }
  const hasCorrectionProgress =
    Object.keys(disputeCounts).length !== 0 ||
    value.disputeHistory.length !== 0 ||
    findingArbitrations.length !== 0 ||
    value.correctionHistory.length !== 0 ||
    Object.keys(sameFindingRounds).length !== 0 ||
    value.pendingCorrection ||
    value.blockedSinceStagnation !== 0 ||
    value.stagnationArbitrationUsed ||
    stagnationDirection !== null ||
    value.reviewReconsideration.length !== 0 ||
    value.additionalFixRounds !== 0 ||
    value.findingOverrides.length !== 0;
  const hasWorkProgress =
    polishSummary !== null ||
    reviewCorrection !== null ||
    pendingReviewCorrection !== null ||
    confirmationCorrection !== null ||
    pendingConfirmationCorrection !== null ||
    candidateReviewResult !== null ||
    value.candidateReviewedFingerprint !== null ||
    value.candidateConfirmationFingerprint !== null ||
    value.candidateMigrationPending ||
    finalizationResult !== null ||
    value.finalizedFingerprint !== null ||
    value.cleanConfirmationFingerprint !== null ||
    value.reviewedFingerprint !== null ||
    findings.length !== 0 ||
    primaryFindings.length !== 0 ||
    previousFindings.length !== 0 ||
    pendingDisputes.length !== 0 ||
    lazyCorrections.length !== 0 ||
    hasCorrectionProgress;
  if (
    !value.preflightComplete &&
    (value.clarificationFrozen ||
      pendingEdit !== null ||
      value.refreezeRequired ||
      workerSummary !== null ||
      reviewerSummary !== null ||
      workerValidation !== null ||
      reviewerValidation !== null ||
      resolvedSummary !== null ||
      disagreement !== null ||
      value.bootstrapArbitrationUsed ||
      bootstrapCorrections.length !== 0 ||
      pendingBootstrapCorrection !== null ||
      finalizationCorrection !== null ||
      pendingFinalizationCorrection !== null ||
      reviewCorrection !== null ||
      pendingReviewCorrection !== null ||
      confirmationCorrection !== null ||
      pendingConfirmationCorrection !== null ||
      lazyCorrections.length !== 0 ||
      pendingLazyCorrection !== null ||
      value.lazySourceForkConsumed ||
      validationMigrationDisagreement !== null ||
      hasWorkProgress)
  ) {
    throw workflowError("Polishing preflight state is inconsistent.");
  }
  if (
    ["CLARIFY", "BOOTSTRAP"].includes(value.workflowState) &&
    hasWorkProgress
  ) {
    throw workflowError("Polishing work progress is not applicable.");
  }
  if (
    value.workflowState === "CLARIFY" &&
    (value.clarificationFrozen ||
      value.refreezeRequired ||
      workerSummary !== null ||
      reviewerSummary !== null ||
      workerValidation !== null ||
      reviewerValidation !== null ||
      resolvedSummary !== null ||
      disagreement !== null)
  ) {
    throw workflowError("Polishing clarification state is inconsistent.");
  }
  if (
    value.workflowState === "BOOTSTRAP" &&
    ((!value.clarificationFrozen && !value.refreezeRequired) ||
      resolvedSummary !== null)
  ) {
    throw workflowError("Polishing bootstrap state is inconsistent.");
  }
  if (
    [
      "POLISH",
      "FINALIZE",
      "CHECK_AND_FIX",
      "CLEAN_CONFIRM",
      "REVIEW",
      "CONFIRM",
      "RESOLVE_FINDINGS",
      "HANDOFF",
      "DONE",
    ].includes(value.workflowState) &&
    (!value.clarificationFrozen ||
      value.refreezeRequired ||
      resolvedSummary === null ||
      disagreement !== null)
  ) {
    throw workflowError("Polishing prepared state is inconsistent.");
  }
  if (
    [
      "FINALIZE",
      "CHECK_AND_FIX",
      "CLEAN_CONFIRM",
      "REVIEW",
      "CONFIRM",
      "RESOLVE_FINDINGS",
      "HANDOFF",
      "DONE",
    ].includes(value.workflowState) &&
    polishSummary === null
  ) {
    throw workflowError("Polishing result state is inconsistent.");
  }
  if (
    value.workflowState === "FINALIZE" &&
    (finalizationResult !== null ||
      !acceptedCandidateGate ||
      value.cleanConfirmationFingerprint !== null ||
      findings.length !== 0 ||
      value.reviewReconsideration.length !== 0)
  ) {
    throw workflowError("Polishing finalization state is inconsistent.");
  }
  if (
    value.workflowState === "REVIEW" &&
    (!policy.independentReview ||
      (combinedReview(value.settings) &&
        value.candidateConfirmationFingerprint === null) ||
      (finalizationResult !== null && finalizationResult.status !== "PASS") ||
      reviewResult !== null ||
      value.reviewedFingerprint !== null)
  ) {
    throw workflowError("Polishing review state is inconsistent.");
  }
  if (
    value.workflowState === "CHECK_AND_FIX" &&
    (!policy.primaryConvergence ||
      (finalizationResult !== null && finalizationResult.status !== "PASS") ||
      reviewResult !== null ||
      value.reviewedFingerprint !== null ||
      value.cleanConfirmationFingerprint !== null)
  ) {
    throw workflowError("Polishing check/fix state is inconsistent.");
  }
  if (
    value.workflowState === "CLEAN_CONFIRM" &&
    (!policy.primaryConvergence ||
      (finalizationResult !== null && finalizationResult.status !== "PASS") ||
      reviewResult !== null ||
      value.reviewedFingerprint !== null ||
      findings.length !== 0 ||
      value.cleanConfirmationFingerprint !== null ||
      value.candidateConfirmationFingerprint !== null)
  ) {
    throw workflowError("Polishing clean confirmation state is inconsistent.");
  }
  if (
    value.workflowState === "CONFIRM" &&
    (!finalizationGatePassed(gateState) ||
      !acceptedCandidateGate ||
      reviewResult !== null ||
      value.reviewedFingerprint !== null ||
      findings.length !== 0 ||
      value.cleanConfirmationFingerprint !== null)
  ) {
    throw workflowError("Polishing confirmation state is inconsistent.");
  }
  const completionReady = handoffGatePassed(gateState);
  const finalizationBlocked =
    finalizationResult?.status === "FAIL" &&
    finalizationResult.issues.length > 0;
  if (
    value.workflowState === "RESOLVE_FINDINGS" &&
    !finalizationBlocked &&
    findings.length === 0 &&
    pendingDisputes.length === 0
  ) {
    throw workflowError("Polishing finding resolution has no blockers.");
  }
  if (["HANDOFF", "DONE"].includes(value.workflowState) && !completionReady) {
    throw workflowError("Completed polishing state is inconsistent.");
  }
  if (
    !["CLARIFY", "WAITING_FOR_USER", "FAILED"].includes(value.workflowState) &&
    !value.preflightComplete
  ) {
    throw workflowError("Polishing state has not completed preflight.");
  }
  if (!validResolutionCorrection(value)) {
    throw workflowError("Polishing finding-resolution correction is invalid.");
  }
  assertClarificationAppend(value);
  return value;
}

// Bind recovery to the complete producing checkpoint, independent of a native session.
export function appendCheckpointFingerprint(run, workflowState) {
  return sha256(
    JSON.stringify(
      {
        state: {
          ...run.pipelineState,
          workflowState,
          pendingClarificationAppend: null,
        },
        counters: normalizedCounters(run.counters),
        hashes: run.hashes,
        lineage: run.sessionLineage,
      },
      (_key, value) =>
        isRecord(value)
          ? Object.fromEntries(
              Object.keys(value)
                .sort()
                .map((key) => [key, value[key]]),
            )
          : value,
    ),
  );
}

function assertClarificationAppend(value) {
  const append = value.pendingClarificationAppend;
  if (append === null) return;
  const invalid = () => workflowError("Invalid pending clarification append.");
  if (
    !isRecord(append) ||
    !hasExactFields(append, [
      "kind",
      "questions",
      "decision",
      "number",
      "expectedHash",
      "resultHash",
      "checkpoint",
    ]) ||
    !isRecord(append.checkpoint) ||
    !hasExactFields(append.checkpoint, [
      "workflowState",
      "suspendedState",
      "fingerprint",
      "infrastructureFingerprint",
      "workReport",
    ])
  )
    throw invalid();
  const checkpoint = append.checkpoint;
  let canonical = false;
  try {
    canonical =
      append.kind === "questions"
        ? append.decision === null &&
          checkpoint.workflowState === "CLARIFY" &&
          checkpoint.suspendedState === "CLARIFY" &&
          checkpoint.workReport === null &&
          append.questions.length > 0 &&
          isDeepStrictEqual(
            append.questions,
            normalizeClarificationResult({
              status: "QUESTIONS",
              questions: append.questions,
              reason: "",
              question: "",
              options: [],
              whyBlocked: "",
              evidence: [],
            }).questions,
          )
        : append.kind === "product-decision" &&
          Array.isArray(append.questions) &&
          append.questions.length === 0 &&
          isRecord(append.decision) &&
          hasExactFields(append.decision, [
            "question",
            "options",
            "whyBlocked",
            "evidence",
          ]) &&
          isDeepStrictEqual(
            append.decision,
            normalizeProductDecision(append.decision),
          ) &&
          [
            "CLARIFY",
            "BOOTSTRAP",
            "POLISH",
            "CHECK_AND_FIX",
            "CLEAN_CONFIRM",
            "REVIEW",
            "FINALIZE",
            "CONFIRM",
            "RESOLVE_FINDINGS",
          ].includes(checkpoint.workflowState) &&
          checkpoint.suspendedState ===
            (checkpoint.workflowState === "CLARIFY" ? "CLARIFY" : "BOOTSTRAP");
    if (checkpoint.workReport !== null) {
      retainWorkReport(value.workReports, checkpoint.workReport);
      const report = checkpoint.workReport;
      canonical &&=
        report.phase === "ARBITRATE_BOOTSTRAP"
          ? checkpoint.workflowState === "BOOTSTRAP" &&
            polishingPolicy(value.settings).bootstrapArbitration &&
            report.arbitration.direction === "PRODUCT_DECISION_REQUIRED"
          : checkpoint.workflowState === "RESOLVE_FINDINGS" &&
            polishingPolicy(value.settings).arbitration &&
            (report.phase === "ARBITRATE_FINDING"
              ? report.arbitration.direction === "REQUIREMENT_AMBIGUOUS" &&
                value.pendingDisputes.some(
                  ({ findingId }) => findingId === report.arbitration.findingId,
                )
              : report.phase === "ARBITRATE_STAGNATION" &&
                report.arbitration.direction === "PRODUCT_DECISION_REQUIRED");
    }
  } catch {
    // Invalid saved payloads grant no replay authority.
    canonical = false;
  }
  if (
    !canonical ||
    !Number.isSafeInteger(append.number) ||
    append.number < 1 ||
    (append.kind === "questions" && append.number > MAX_CLARIFICATION_ROUNDS) ||
    ![append.expectedHash, append.resultHash, checkpoint.fingerprint].every(
      (hash) => typeof hash === "string" && HASH_PATTERN.test(hash),
    ) ||
    append.expectedHash === append.resultHash ||
    (value.validationInfrastructure === null
      ? checkpoint.infrastructureFingerprint !== null
      : typeof checkpoint.infrastructureFingerprint !== "string" ||
        !HASH_PATTERN.test(checkpoint.infrastructureFingerprint)) ||
    !value.preflightComplete ||
    !value.proactiveClarificationComplete ||
    value.pendingEdit !== null ||
    value.resolutionCorrection !== null ||
    ![checkpoint.workflowState, "WAITING_FOR_USER"].includes(
      value.workflowState,
    )
  )
    throw invalid();
}

export function createPolishingState({
  artifactRoot = "LOCAL_ARTIFACTS",
  clarificationRoot = null,
  artifactPath,
  proactiveClarification = false,
  settings = null,
  trustedValidation = EMPTY_TRUSTED_VALIDATION,
} = {}) {
  if (
    artifactPath !== undefined &&
    (clarificationRoot === null ||
      artifactPath !== join(clarificationRoot, artifactRoot))
  )
    throw workflowError("Selected clarification resources disagree.");
  if (typeof proactiveClarification !== "boolean") {
    throw workflowError("proactiveClarification must be a boolean.");
  }
  if (settings !== null) {
    assertSettings(settings);
  }
  const normalizedTrustedValidation =
    normalizeTrustedValidation(trustedValidation);
  return Object.freeze(
    normalizePipelineState({
      workflowState: "CLARIFY",
      artifactRoot,
      clarificationRoot,
      preflightComplete: false,
      settings:
        settings === null
          ? null
          : Object.freeze({
              ...settings,
              trustedChecks: Object.freeze([...settings.trustedChecks]),
            }),
      finalizationGuidance: null,
      repositoryBaseline: null,
      backendVersions: null,
      proactiveClarification,
      proactiveClarificationComplete: !proactiveClarification,
      clarificationPath: null,
      clarificationFrozen: false,
      pendingEdit: null,
      pendingClarificationAppend: null,
      refreezeRequired: false,
      workerSummary: null,
      reviewerSummary: null,
      workerValidation: null,
      reviewerValidation: null,
      resolvedSummary: null,
      bootstrapDisagreement: null,
      bootstrapArbitrationUsed: false,
      bootstrapCorrections: Object.freeze([]),
      pendingBootstrapCorrection: null,
      finalizationCorrection: null,
      pendingFinalizationCorrection: null,
      finalizationRecovery: createFinalizationRecovery(),
      reviewCorrection: null,
      pendingReviewCorrection: null,
      confirmationCorrection: null,
      pendingConfirmationCorrection: null,
      lazyCorrections: Object.freeze([]),
      pendingLazyCorrection: null,
      candidateReviewResult: null,
      candidateReviewedFingerprint: null,
      candidateConfirmationFingerprint: null,
      candidateMigrationPending: false,
      primaryFindings: Object.freeze([]),
      workReports: Object.freeze([]),
      cleanConfirmationFingerprint: null,
      lazySourceForkConsumed: false,
      authenticationSourceForkRecovery: null,
      polishSummary: null,
      finalizationResult: null,
      finalizedFingerprint: null,
      requiredChecks: null,
      validationInfrastructure: null,
      validationInfrastructureFingerprint: null,
      trustedValidation: normalizedTrustedValidation,
      validationMigrationPending: false,
      validationMigrationDisagreement: null,
      reviewResult: null,
      reviewedFingerprint: null,
      findings: [],
      previousFindings: [],
      pendingDisputes: [],
      disputeCounts: {},
      disputeHistory: [],
      findingArbitrations: [],
      correctionHistory: [],
      sameFindingRounds: {},
      pendingCorrection: false,
      availabilityCorrectionCharged: false,
      blockedSinceStagnation: 0,
      stagnationArbitrationUsed: false,
      stagnationDirection: null,
      reviewReconsideration: [],
      additionalFixRounds: 0,
      findingOverrides: [],
      resolutionCorrection: null,
    }),
  );
}

export function normalizedCounters(counters) {
  if (
    !isRecord(counters) ||
    Object.keys(counters).some((field) => !COUNTER_FIELDS.includes(field))
  ) {
    throw workflowError("Polishing counters are invalid.");
  }
  const normalized = Object.fromEntries(
    COUNTER_FIELDS.map((field) => {
      const value = Object.hasOwn(counters, field) ? counters[field] : 0;
      if (!Number.isSafeInteger(value) || value < 0) {
        throw workflowError(`Polishing counter ${field} is invalid.`);
      }
      return [field, value];
    }),
  );
  return Object.freeze(normalized);
}

function repositoryRelativePath(projectPath, path) {
  const pathFromProject = relative(projectPath, path);
  if (
    pathFromProject === "" ||
    pathFromProject === ".." ||
    pathFromProject.startsWith(`..${sep}`) ||
    isAbsolute(pathFromProject)
  ) {
    return null;
  }
  return pathFromProject.split(sep).join("/");
}

function assertInputRequest(run, state) {
  const request = run.pause?.inputRequest;
  if (state.pendingEdit === null) {
    if (request !== undefined || run.pause?.inputResponse !== undefined) {
      throw workflowError("Polishing input pause is invalid.");
    }
    return;
  }
  if (request === undefined) {
    return;
  }
  if (
    !isRecord(request) ||
    request.id !== state.pendingEdit.id ||
    request.artifactPath !== state.pendingEdit.transcriptPath ||
    !["clarification", "product-decision"].includes(request.kind) ||
    !Array.isArray(request.questions)
  ) {
    throw workflowError("Polishing input request is invalid.");
  }
}

// Structural shape only; the root-composed Git normalizer owns label meaning.
export function snapshotChangeLabels(value) {
  return Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 8 &&
    value.every((label) => typeof label === "string") &&
    new Set(value).size === value.length
    ? Object.freeze([...value])
    : null;
}

export function snapshotChangeEvidence(value) {
  const labels = snapshotChangeLabels(value);
  return `Changed snapshot domains: ${labels === null ? "unavailable" : labels.join(", ")}.`;
}

// A settled pause retains its checkpoint until a fresh cancellation of exactly
// that quiescent state is reconciled; cancellation itself must be reconciled.
function operatorStopRequestValid(request, canceled) {
  if (request == null) return false;
  if (request.reconciledRevision !== null)
    return request.kind === (canceled ? "cancel_requested" : "pause_requested");
  return (
    !canceled &&
    request.kind === "cancel_requested" &&
    request.checkpoint.revision < request.acceptedRevision &&
    request.checkpoint.workflowState === "WAITING_FOR_USER" &&
    request.checkpoint.activeTurn === null
  );
}

export function assertRun(run) {
  if (["operator_paused", "operator_canceled"].includes(run?.pause?.reason)) {
    const checkpoint = run.pause.operatorResume;
    const canceled = run.pause.reason === "operator_canceled";
    if (
      !isRecord(checkpoint) ||
      Object.keys(checkpoint).length !== 3 ||
      Object.keys(checkpoint).some(
        (field) => !["workflowState", "pause", "activeTurn"].includes(field),
      ) ||
      !WORKFLOW_STATES.includes(checkpoint.workflowState) ||
      checkpoint.workflowState === "CANCELED" ||
      ["operator_paused", "operator_canceled"].includes(
        checkpoint.pause?.reason,
      ) ||
      run.activeTurn !== null ||
      run.pause.resumeAction !== null ||
      run.pipelineState?.workflowState !==
        (canceled ? "CANCELED" : "WAITING_FOR_USER") ||
      !operatorStopRequestValid(run.stopRequest, canceled)
    ) {
      throw workflowError("Operator stop checkpoint is invalid.");
    }
    run = {
      ...run,
      pause: checkpoint.pause,
      activeTurn: checkpoint.activeTurn,
      pipelineState: {
        ...run.pipelineState,
        workflowState: checkpoint.workflowState,
      },
    };
  } else if (run?.pipelineState?.workflowState === "CANCELED") {
    throw workflowError("Cancellation requires a reconciled operator request.");
  }
  if (
    !isRecord(run) ||
    typeof run.runId !== "string" ||
    !RUN_ID_PATTERN.test(run.runId) ||
    run.pipelineId !== "polishing" ||
    run.pipelineStateVersion !== 25 ||
    typeof run.projectPath !== "string" ||
    !isAbsolute(run.projectPath) ||
    resolve(run.projectPath) !== run.projectPath ||
    typeof run.taskPath !== "string" ||
    !isAbsolute(run.taskPath) ||
    resolve(run.taskPath) !== run.taskPath ||
    !isRecord(run.roles) ||
    !isRecord(run.hashes) ||
    !isRecord(run.sessionLineage) ||
    !Array.isArray(run.sessionLineage.children)
  ) {
    throw workflowError("Polishing run envelope is invalid.");
  }
  const state = normalizePipelineState(run.pipelineState);
  const activeRoles = resolveActiveRoles(state.settings);
  assertExactFields(run.roles, activeRoles, "Polishing roles");
  for (const role of activeRoles) {
    const roleFields = Object.keys(run.roles[role]);
    if (
      roleFields.some(
        (field) =>
          !["backend", "profile", "model", "contextSize", "effort"].includes(
            field,
          ),
      ) ||
      !Object.hasOwn(run.roles[role], "backend")
    ) {
      throw workflowError(`Polishing role ${role} is invalid.`);
    }
    if (
      typeof run.roles[role].backend !== "string" ||
      run.roles[role].backend.length === 0 ||
      (run.roles[role].model !== undefined &&
        run.roles[role].model !== null &&
        (typeof run.roles[role].model !== "string" ||
          run.roles[role].model.length === 0)) ||
      (run.roles[role].effort !== undefined &&
        !["current", "low", "medium", "high", "xhigh", "max"].includes(
          run.roles[role].effort,
        )) ||
      ["profile", "contextSize"].some(
        (field) =>
          run.roles[role][field] !== undefined &&
          (typeof run.roles[role][field] !== "string" ||
            run.roles[role][field].length === 0),
      )
    ) {
      throw workflowError(`Polishing role ${role} is invalid.`);
    }
  }
  if (
    run.sessionLineage.source !== null &&
    (typeof run.sessionLineage.source !== "string" ||
      run.sessionLineage.source.length === 0)
  ) {
    throw workflowError("Polishing source session is invalid.");
  }
  if (
    run.sessionLineage.sourceProfile !== undefined &&
    run.sessionLineage.sourceProfile !== null &&
    (run.sessionLineage.source === null ||
      typeof run.sessionLineage.sourceProfile !== "string" ||
      run.sessionLineage.sourceProfile.length === 0)
  ) {
    throw workflowError("Polishing source profile is invalid.");
  }
  const sessionIds = [];
  for (const child of run.sessionLineage.children) {
    if (
      !isRecord(child) ||
      !activeRoles.includes(child.role) ||
      typeof child.sessionId !== "string" ||
      child.sessionId.length === 0 ||
      child.sessionId === run.sessionLineage.source ||
      (Object.hasOwn(child, "contextKey") &&
        (typeof child.contextKey !== "string" ||
          !/^[a-f0-9]{64}$/u.test(child.contextKey)))
    ) {
      throw workflowError("Polishing child session is invalid.");
    }
    sessionIds.push(child.sessionId);
  }
  if (new Set(sessionIds).size !== sessionIds.length) {
    throw workflowError("Polishing child sessions must be unique.");
  }
  if (
    (state.lazySourceForkConsumed && run.sessionLineage.source === null) ||
    (state.authenticationSourceForkRecovery !== null &&
      run.sessionLineage.source === null) ||
    (polishingPolicy(state.settings).primarySessionScope === "run" &&
      run.sessionLineage.source !== null &&
      (run.sessionLineage.children.length > 0 ||
        (run.activeTurn !== null && run.activeTurn !== undefined)) &&
      !state.lazySourceForkConsumed)
  ) {
    throw workflowError("Polishing source-fork lineage is invalid.");
  }
  if (state.repositoryBaseline !== null) {
    const repositoryPath = state.repositoryBaseline.projectPath;
    const expectedClarificationPath = join(
      state.clarificationRoot,
      state.artifactRoot,
      "agent-runner",
      run.runId,
      "clarifications.md",
    );
    const expectedAllowedPath = repositoryRelativePath(
      repositoryPath,
      expectedClarificationPath,
    );
    if (
      (repositoryPath !== run.projectPath &&
        repositoryRelativePath(repositoryPath, run.projectPath) === null) ||
      state.clarificationPath !== expectedClarificationPath ||
      !isDeepStrictEqual(
        state.repositoryBaseline.allowedPaths,
        expectedAllowedPath === null ? [] : [expectedAllowedPath],
      )
    ) {
      throw workflowError("Polishing repository baseline is invalid.");
    }
  }
  if (
    state.pendingEdit !== null &&
    (state.pendingEdit.artifactRoot !== state.clarificationRoot ||
      state.pendingEdit.transcriptPath !== state.clarificationPath ||
      state.pendingEdit.preEditorHash !== run.hashes.executionClarifications)
  ) {
    throw workflowError("Polishing pending edit boundary is invalid.");
  }
  const pauseExpected = ["WAITING_FOR_USER", "FAILED"].includes(
    state.workflowState,
  );
  if (
    pauseExpected !== (run.pause !== null) ||
    (run.pause !== null &&
      (!isRecord(run.pause) ||
        typeof run.pause.reason !== "string" ||
        run.pause.reason.length === 0))
  ) {
    throw workflowError("Polishing pause state is invalid.");
  }
  if (
    Object.hasOwn(run.pause ?? {}, "snapshotChanges") &&
    (run.pause.reason !== "read_only_agent_mutated_repository" ||
      run.pause.code !== "ERR_READ_ONLY_REPOSITORY_CHANGED" ||
      snapshotChangeLabels(run.pause.snapshotChanges) === null ||
      !isDeepStrictEqual(
        snapshotChangeLabels(run.pause.snapshotChanges),
        run.pause.snapshotChanges,
      ))
  ) {
    throw workflowError("Polishing snapshot change diagnostics are invalid.");
  }
  const outputFailure =
    state.workflowState === "FAILED" &&
    run.pause?.reason === "internal_failure" &&
    run.pause.code === INVALID_OUTPUT_CODE;
  const hasOutputDiagnostic = Object.hasOwn(run.pause ?? {}, "diagnostic");
  if (
    (hasOutputDiagnostic &&
      (!outputFailure ||
        !hasExactFields(run.pause, OUTPUT_FAILURE_FIELDS) ||
        !isOutputDiagnostic(run.pause.diagnostic))) ||
    (outputFailure &&
      !hasExactFields(
        run.pause,
        hasOutputDiagnostic
          ? OUTPUT_FAILURE_FIELDS
          : LEGACY_OUTPUT_FAILURE_FIELDS,
      ))
  ) {
    throw workflowError("Polishing output diagnostic is invalid.");
  }
  const adapterFailure =
    state.workflowState === "FAILED" &&
    run.pause?.reason === "internal_failure" &&
    !outputFailure;
  const hasAdapterDiagnostic = Object.hasOwn(
    run.pause ?? {},
    "diagnosticClass",
  );
  if (
    (hasAdapterDiagnostic &&
      (!adapterFailure ||
        !hasExactFields(run.pause, ADAPTER_FAILURE_FIELDS) ||
        typeof run.pause.diagnosticClass !== "string" ||
        !ADAPTER_DIAGNOSTIC_CLASS_PATTERN.test(run.pause.diagnosticClass))) ||
    (adapterFailure &&
      !hasExactFields(
        run.pause,
        hasAdapterDiagnostic ? ADAPTER_FAILURE_FIELDS : FAILURE_FIELDS,
      ))
  ) {
    throw workflowError("Polishing adapter diagnostic is invalid.");
  }
  if (
    run.pause?.reason === "handoff_whitespace_rejected" &&
    (state.workflowState !== "FAILED" ||
      !hasExactFields(run.pause, FAILURE_FIELDS) ||
      !HANDOFF_WHITESPACE_CODES.includes(run.pause.code) ||
      state.finalizedFingerprint === null ||
      state.reviewedFingerprint !== state.finalizedFingerprint)
  ) {
    throw workflowError("Polishing handoff whitespace disposition is invalid.");
  }
  if (
    run.pause?.reason === "finalization_evidence_rejected" &&
    (!state.finalizationRecovery.required ||
      state.finalizationRecovery.pending ||
      state.finalizationRecovery.attempts !==
        MAX_SEMANTIC_FINALIZATION_RETRIES +
          state.finalizationRecovery.additionalAttempts)
  ) {
    throw workflowError(
      "Semantic finalization pause has no exhausted recovery allowance.",
    );
  }
  if (state.workflowState === "WAITING_FOR_USER") {
    const configurationChanged =
      run.pause.reason === "project_configuration_changed";
    if (
      configurationChanged &&
      (!hasExactFields(run.pause, ["reason", "code"]) ||
        run.pause.code !== "ERR_PROJECT_CONFIGURATION_CHANGED")
    ) {
      throw workflowError("Polishing configuration pause is invalid.");
    }
    if (run.pause.reason === "lazy_output_invalid") {
      const expectedEvidence = state.pendingLazyCorrection?.diagnostics.map(
        ({ field, constraint }) =>
          `Worker field ${field} violated ${constraint}.`,
      );
      if (
        state.pendingLazyCorrection === null ||
        !hasExactFields(run.pause, [
          "reason",
          "code",
          "explanation",
          "evidence",
          "resumeState",
        ]) ||
        run.pause.code !== INVALID_OUTPUT_CODE ||
        run.pause.explanation !== LAZY_OUTPUT_RETRY_EXPLANATION ||
        !isDeepStrictEqual(run.pause.evidence, expectedEvidence) ||
        run.pause.resumeState !== state.pendingLazyCorrection.phase
      ) {
        throw workflowError("Polishing lazy output pause is invalid.");
      }
    }
    const correction = state.resolutionCorrection;
    if (
      run.pause.reason === "resolution_output_invalid" &&
      (correction?.stage !== "exhausted" ||
        !hasExactFields(run.pause, [
          "reason",
          "code",
          "explanation",
          "evidence",
          "resumeState",
        ]) ||
        run.pause.code !== INVALID_OUTPUT_CODE ||
        run.pause.explanation !== RESOLUTION_OUTPUT_RETRY_EXPLANATION ||
        !isDeepStrictEqual(
          run.pause.evidence,
          correction.diagnostics.map(
            ({ field, constraint }) =>
              `Worker field ${field} violated ${constraint}.`,
          ),
        ) ||
        run.pause.resumeState !== "RESOLVE_FINDINGS")
    ) {
      throw workflowError("Polishing resolution output pause is invalid.");
    }
    if (
      (run.pause.reason === "environment_blocked" &&
        correction?.stage === "blocked" &&
        run.pause.resumeState !== "RESOLVE_FINDINGS") ||
      (run.pause.reason === "output_exhausted" &&
        run.pause.checkpoint === RESOLUTION_CORRECTION_CHECKPOINT &&
        (correction?.stage !== "correcting" ||
          correction.productDecision !== null ||
          run.pause.role !== "worker"))
    ) {
      throw workflowError("Polishing resolution correction pause is invalid.");
    }
    if (run.pause?.reason === "validation_policy_blocked") {
      if (
        !hasExactFields(run.pause, [
          "reason",
          "code",
          "explanation",
          "evidence",
          "checkpoint",
        ]) ||
        run.pause.code !== "ERR_VALIDATION_POLICY_BLOCKED" ||
        !["POLISH", "CHECK_AND_FIX", "RESOLVE_FINDINGS", "FINALIZE"].includes(
          run.pause.checkpoint,
        ) ||
        state.workflowState !== "WAITING_FOR_USER" ||
        state.pendingEdit !== null ||
        !state.preflightComplete ||
        run.activeTurn !== null ||
        (state.resolutionCorrection !== null &&
          run.pause.checkpoint !== "RESOLVE_FINDINGS")
      )
        throw workflowError("Invalid validation-policy pause.");
      try {
        normalizeValidationPolicyBlocked({
          reason: run.pause.explanation,
          evidence: run.pause.evidence,
        });
      } catch {
        throw workflowError("Invalid validation-policy pause evidence.");
      }
    }
    const expectedReason = EDIT_PAUSE_REASONS[state.pendingEdit?.action];
    const hasAuthorizationId = Object.hasOwn(run.pause, "authorizationId");
    if (
      !configurationChanged &&
      ((state.pendingEdit === null &&
        (hasAuthorizationId ||
          Object.values(EDIT_PAUSE_REASONS).includes(run.pause.reason))) ||
        (state.pendingEdit !== null &&
          (run.pause.authorizationId !== state.pendingEdit.id ||
            run.pause.reason !== expectedReason)))
    ) {
      throw workflowError("Polishing pending edit pause is invalid.");
    }
    const hasResumeState = Object.hasOwn(run.pause, "resumeState");
    const hasLaunchRecovery = Object.hasOwn(run.pause, "launchRecovery");
    const allowedResumeStates = Object.hasOwn(
      PAUSE_RESUME_STATES,
      run.pause.reason,
    )
      ? PAUSE_RESUME_STATES[run.pause.reason]
      : undefined;
    const requiresResumeState =
      [
        "fix_limit_reached",
        "lazy_output_invalid",
        "no_progress",
        "resolution_output_invalid",
        "finding_repair_required",
      ].includes(run.pause.reason) ||
      (state.preflightComplete &&
        [
          "authentication_required",
          "output_exhausted",
          "backend_unavailable",
          "confirmation_output_invalid",
          "environment_blocked",
          "finalization_evidence_rejected",
          "review_output_invalid",
        ].includes(run.pause.reason)) ||
      (run.pause.reason === "finalization_cannot_pass" &&
        run.pause.code !== "ERR_FINALIZATION_MODIFIED_BEFORE_VALIDATION");
    if (
      (hasResumeState &&
        (!allowedResumeStates?.includes(run.pause.resumeState) ||
          !state.preflightComplete)) ||
      (requiresResumeState && !hasResumeState)
    ) {
      throw workflowError("Polishing pause resume state is invalid.");
    }
    if (
      run.pause.reason === "output_exhausted" &&
      (!hasExactFields(run.pause, [
        "reason",
        "code",
        "resumeState",
        "role",
        "checkpoint",
      ]) ||
        run.pause.code !== "ERR_OUTPUT_EXHAUSTED" ||
        !Object.hasOwn(run.roles, run.pause.role) ||
        typeof run.pause.checkpoint !== "string" ||
        typeof run.pause.resumeState !== "string" ||
        !/^[A-Za-z][A-Za-z0-9:._-]{0,127}$/u.test(run.pause.checkpoint) ||
        !run.pause.checkpoint.startsWith(
          `${run.pause.resumeState.toLowerCase().replaceAll("_", "-")}:`,
        ) ||
        (state.settings.mode === "lazy" && run.pause.role !== "worker"))
    ) {
      throw workflowError("Invalid output-exhaustion pause.");
    }
    if (
      run.pause.reason === "authentication_required" &&
      (!hasExactFields(run.pause, ["reason", "code", "resumeState"]) ||
        run.pause.code !== "ERR_AUTHENTICATION_REQUIRED")
    ) {
      throw workflowError("Polishing authentication pause is invalid.");
    }
    if (
      hasLaunchRecovery &&
      (run.pause.reason !== "backend_unavailable" || !hasResumeState)
    ) {
      throw workflowError("Polishing launch recovery pause is invalid.");
    }
    if (hasResumeState && !state.candidateMigrationPending) {
      normalizePipelineState({
        ...state,
        workflowState: run.pause.resumeState,
      });
    }
  }
  assertInputRequest(run, state);
  const hashFields = [
    "task",
    "taskClarifications",
    "context",
    "executionClarifications",
  ];
  const hashKeys = Object.keys(run.hashes);
  if (
    (!state.preflightComplete && hashKeys.length !== 0) ||
    (state.preflightComplete &&
      (hashKeys.length !== hashFields.length ||
        hashFields.some((field) => !Object.hasOwn(run.hashes, field)) ||
        !HASH_PATTERN.test(run.hashes.task) ||
        (run.hashes.taskClarifications !== null &&
          !HASH_PATTERN.test(run.hashes.taskClarifications)) ||
        (run.hashes.context !== null &&
          !HASH_PATTERN.test(run.hashes.context)) ||
        !HASH_PATTERN.test(run.hashes.executionClarifications)))
  ) {
    throw workflowError("Polishing input hashes are invalid.");
  }
  const append = state.pendingClarificationAppend;
  if (append !== null) {
    normalizePipelineState({
      ...state,
      pendingClarificationAppend: null,
      workflowState: append.checkpoint.workflowState,
    });
    if (
      append.expectedHash !== run.hashes.executionClarifications ||
      append.number !==
        normalizedCounters(run.counters)[
          append.kind === "questions"
            ? "clarificationRounds"
            : "productDecisions"
        ] +
          1 ||
      append.checkpoint.fingerprint !==
        appendCheckpointFingerprint(run, append.checkpoint.workflowState) ||
      run.activeTurn !== null ||
      state.authenticationSourceForkRecovery !== null ||
      !run.sessionLineage.children.some(({ role }) => role === "worker") ||
      (append.checkpoint.workReport !== null &&
        run.sessionLineage.children.at(-1)?.role !== "arbiter")
    )
      throw workflowError("Pending clarification append checkpoint changed.");
  }
  if (
    run.pause?.reason === "clarification_append_interrupted" &&
    (append === null ||
      !hasExactFields(run.pause, ["reason", "code"]) ||
      !["ERR_CLARIFICATION_READ", "ERR_CLARIFICATION_WRITE"].includes(
        run.pause.code,
      ))
  )
    throw workflowError(
      "Invalid clarification append interruption diagnostic.",
    );
  const counters = normalizedCounters(run.counters);
  const correction = state.resolutionCorrection;
  if (
    correction !== null &&
    (correction.restatementStartedAfter > run.revision ||
      (correction.stage === "retry-ready" && run.activeTurn !== null) ||
      counters.fixRounds !==
        correction.fixRoundsBefore + (correction.fixCharged ? 1 : 0) ||
      (["exhausted", "blocked"].includes(correction.stage) &&
        state.workflowState === "RESOLVE_FINDINGS"))
  ) {
    throw workflowError(
      "Polishing resolution correction accounting is invalid.",
    );
  }
  const fixBudget =
    (state.settings?.maxFixRounds ?? 0) + state.additionalFixRounds;
  const repairNeedsBudget =
    !state.pendingCorrection && counters.fixRounds >= fixBudget;
  if (
    (run.pause?.reason === "finding_repair_required" &&
      (correction?.stage !== "repair-required" ||
        repairNeedsBudget ||
        !hasExactFields(run.pause, ["reason", "resumeState"]))) ||
    (correction?.stage === "repair-required" &&
      state.workflowState === "RESOLVE_FINDINGS") ||
    (correction?.stage === "repair-authorized" &&
      state.workflowState === "RESOLVE_FINDINGS" &&
      repairNeedsBudget) ||
    (["repair-required", "repair-authorized"].includes(correction?.stage) &&
      run.activeTurn !== null) ||
    (correction?.stage === "repair-required" &&
      run.pause?.reason === "fix_limit_reached" &&
      (!repairNeedsBudget || run.pause.resumeState !== "RESOLVE_FINDINGS"))
  )
    throw workflowError("Invalid unfinished finding repair authorization.");
  const correctionHistory = state.correctionHistory;
  const lastCorrection = correctionHistory.at(-1)?.round ?? 0;
  const lastCorrectionFindingIds = new Set(
    correctionHistory.at(-1)?.findingIds ?? [],
  );
  if (
    counters.clarificationRounds > MAX_CLARIFICATION_ROUNDS ||
    counters.correctionRounds > counters.fixRounds ||
    counters.fixRounds > fixBudget ||
    (run.pause?.reason === "fix_limit_reached" &&
      (counters.fixRounds !== fixBudget ||
        run.pause.fixRounds !== counters.fixRounds)) ||
    lastCorrection !== counters.correctionRounds ||
    correctionHistory.some(
      (entry, index) =>
        index > 0 && entry.round !== correctionHistory[index - 1].round + 1,
    ) ||
    state.blockedSinceStagnation > counters.correctionRounds ||
    (state.stagnationArbitrationUsed && counters.correctionRounds === 0) ||
    Object.keys(state.sameFindingRounds).some(
      (id) => !lastCorrectionFindingIds.has(id),
    ) ||
    Object.values(state.sameFindingRounds).some(
      (count) => count > counters.correctionRounds,
    )
  ) {
    throw workflowError("Polishing persisted progress is invalid.");
  }
  if (
    state.pendingDisputes.some(
      ({ findingId }) => !Object.hasOwn(state.disputeCounts, findingId),
    ) ||
    state.disputeHistory.some(
      ({ findingId }) => !Object.hasOwn(state.disputeCounts, findingId),
    ) ||
    state.findingArbitrations.some(
      ({ findingId }) =>
        !state.disputeHistory.some((entry) => entry.findingId === findingId),
    )
  ) {
    throw workflowError("Polishing dispute progress is invalid.");
  }
  for (const [findingId, count] of Object.entries(state.disputeCounts)) {
    const recorded = state.disputeHistory.filter(
      (entry) => entry.findingId === findingId,
    );
    const pending = state.pendingDisputes.find(
      (entry) => entry.findingId === findingId,
    );
    const arbitration = state.findingArbitrations.find(
      (entry) => entry.findingId === findingId,
    );
    const latest = recorded.at(-1);
    const exhaustedUpheld =
      count === state.settings.maxDisputesPerFinding &&
      recorded.length === count &&
      latest?.direction === "UPHOLD";
    if (
      count > state.settings.maxDisputesPerFinding ||
      recorded.some((entry, index) => entry.attempt !== index + 1) ||
      (!pending && recorded.length !== count) ||
      (pending &&
        recorded.length !== count - 1 &&
        !(
          recorded.length === count &&
          count === state.settings.maxDisputesPerFinding &&
          latest.direction === "UPHOLD"
        )) ||
      (pending !== undefined &&
        recorded.length === count &&
        (pending.reason !== latest.workerReason ||
          pending.evidence.length !== latest.workerEvidence.length ||
          pending.evidence.some(
            (evidence, index) => evidence !== latest.workerEvidence[index],
          ))) ||
      (state.findings.some(({ id }) => id === findingId) &&
        exhaustedUpheld &&
        pending === undefined &&
        arbitration === undefined)
    ) {
      throw workflowError("Polishing dispute progress is invalid.");
    }
  }
  for (const arbitration of state.findingArbitrations) {
    const count = state.disputeCounts[arbitration.findingId];
    const recorded = state.disputeHistory.filter(
      (entry) => entry.findingId === arbitration.findingId,
    );
    if (
      count !== state.settings.maxDisputesPerFinding ||
      recorded.length !== count ||
      recorded.at(-1)?.direction !== "UPHOLD" ||
      state.pendingDisputes.some(
        (entry) => entry.findingId === arbitration.findingId,
      )
    ) {
      throw workflowError("Polishing arbitration history is incomplete.");
    }
  }
  if (serializedBytes(run) > MAX_DURABLE_RUN_BYTES) {
    throw workflowError("Polishing run exceeds its durable size budget.");
  }
}

export function assertRuntime(runtime, activeRoles = ROLES) {
  if (
    !isRecord(runtime) ||
    !isRecord(runtime.adapters) ||
    !isRecord(runtime.clarifications) ||
    !isRecord(runtime.git) ||
    typeof runtime.finalization?.inspectFile !== "function" ||
    !isRecord(runtime.trustedValidation) ||
    typeof runtime.trustedValidation.execute !== "function" ||
    typeof runtime.trustedValidation.preflight !== "function"
  ) {
    throw workflowError("Polishing runtime is invalid.");
  }
  for (const role of activeRoles) {
    if (
      typeof runtime.adapters[role]?.probe !== "function" ||
      typeof runtime.adapters[role]?.run !== "function"
    ) {
      throw workflowError(`Polishing ${role} adapter is invalid.`);
    }
  }
  for (const name of [
    "finishAgentTurn",
    "readInputs",
    "recordChildSession",
    "startAgentTurn",
    "transition",
    "writeRunArtifact",
  ]) {
    if (typeof runtime[name] !== "function") {
      throw workflowError(`Polishing runtime.${name} is invalid.`);
    }
  }
  for (const name of [
    "assertUnchanged",
    "contentFingerprint",
    "inspectPath",
    "preflight",
    "snapshot",
    "stagePolishingHandoff",
    "validationInfrastructureFingerprint",
  ]) {
    if (typeof runtime.git[name] !== "function") {
      throw workflowError(`Polishing Git service.${name} is invalid.`);
    }
  }
  for (const name of [
    "acceptEdit",
    "appendProductDecision",
    "appendQuestionRound",
    "ensureTranscript",
    "freezeTranscript",
    "inspectTranscript",
    "openEditor",
    "prepareEdit",
  ]) {
    if (typeof runtime.clarifications[name] !== "function") {
      throw workflowError(
        `Polishing clarification service.${name} is invalid.`,
      );
    }
  }
}

export function normalizeAdapterCapabilities(value, role, sourceSession) {
  if (
    !isRecord(value) ||
    typeof value.version !== "string" ||
    value.version.length === 0
  ) {
    throw workflowError(
      `${role} backend returned invalid capabilities.`,
      "ERR_UNSUPPORTED_POLISHING_BACKEND",
    );
  }
  const required =
    role === "worker"
      ? [
          "structuredOutput",
          "readOnly",
          "autonomousWrite",
          "gitMetadataWriteBlocked",
          "workspaceWrite",
          "remoteWriteBlocked",
        ]
      : ["structuredOutput", "readOnly", "remoteWriteBlocked"];
  if (sourceSession !== null && role !== "arbiter") {
    required.push("nativeSessionFork");
  }
  if (required.some((field) => value[field] !== true)) {
    throw workflowError(
      `${role} backend cannot enforce the required capabilities.`,
      "ERR_UNSUPPORTED_POLISHING_BACKEND",
    );
  }
  return Object.freeze({ version: value.version });
}

function assertInputFile(value, expectedPath, name, { optional = false } = {}) {
  if (value === null && optional) {
    return null;
  }
  if (
    !isRecord(value) ||
    value.path !== expectedPath ||
    typeof value.content !== "string" ||
    !HASH_PATTERN.test(value.hash) ||
    value.hash !== sha256(value.content)
  ) {
    throw workflowError(`${name} input snapshot is invalid.`);
  }
  if (!optional && value.content.trim().length === 0) {
    throw workflowError(
      `${name} must not be empty.`,
      INVALID_POLISHING_INPUT_CODE,
    );
  }
  return value;
}

export function normalizeInputSnapshot(value, taskPath) {
  assertExactFields(
    value,
    ["task", "taskClarifications", "context"],
    "Polishing input snapshot",
  );
  return Object.freeze({
    task: assertInputFile(value.task, join(taskPath, "task.md"), "task.md"),
    taskClarifications: assertInputFile(
      value.taskClarifications,
      join(taskPath, "clarifications.md"),
      "clarifications.md",
      { optional: true },
    ),
    context: assertInputFile(
      value.context,
      join(taskPath, "context.md"),
      "context.md",
      { optional: true },
    ),
  });
}

export function activity(actor, phase, kind, message) {
  return Object.freeze({ actor, phase, kind, message });
}

export function activeTurn(role, workflowState) {
  return Object.freeze({
    role,
    phase: workflowState.toLowerCase().replaceAll("_", "-"),
  });
}

export function diagnosticCode(cause, fallback) {
  return typeof cause?.code === "string" && cause.code.length > 0
    ? cause.code
    : fallback;
}
