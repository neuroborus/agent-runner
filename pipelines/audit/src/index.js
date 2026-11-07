import { join } from "node:path";

import {
  AUDIT_MODES,
  createAuditState,
  MAX_DISCOVERY_PASSES,
  MAX_FINDING_RECHECK_PASSES,
  validDiscoveryBudget,
} from "./discovery-contract.js";
import { assertAuditRun } from "./verification-contract.js";
import { reportPaths, REPORT_FILENAME } from "./publication-contract.js";
import { runAudit } from "./publication.js";
import { auditProjections, validateResumeAction } from "./projections.js";
import {
  assertSourceSettings,
  SOURCE_SCOPES,
  validExcludePaths,
} from "./source-scope.js";

export { AUDIT_CATALOG } from "./catalog.js";
export {
  AuditReportValidationError,
  normalizeAuditReport,
} from "./findings.js";
export { renderAuditReport } from "./report.js";

export {
  AuditWorkflowError,
  createAuditState,
  MAX_DISCOVERY_PASSES,
  MAX_FINDING_RECHECK_PASSES,
} from "./discovery-contract.js";
export { runAuditDiscovery } from "./workflow.js";
export { runAudit } from "./publication.js";

const ROLES = Object.freeze(["auditor", "reviewer"]);
const LAZY_ROLES = Object.freeze(["auditor"]);

export const auditPipeline = Object.freeze({
  id: "audit",
  stateVersion: 7,
  migrations: Object.freeze({
    1: ({ pipelineState }) => ({
      ...pipelineState,
      settings: {
        ...pipelineState.settings,
        maxFindingRecheckPasses: MAX_FINDING_RECHECK_PASSES,
      },
      pendingBatch:
        pipelineState.pendingBatch === null
          ? null
          : {
              ...pipelineState.pendingBatch,
              version: 1,
              dispositions: [],
            },
      recheckHistory: [],
      acceptedBatches: [],
    }),
    2: ({ pipelineState }) => ({ ...pipelineState, sourceForkContexts: [] }),
    3: ({ pipelineState }) => ({
      ...pipelineState,
      publication: { pending: null, published: null, temporary: null },
    }),
    4: ({ pipelineState }) => ({
      ...pipelineState,
      proactiveClarification: false,
      proactiveClarificationComplete: true,
    }),
    5: ({ pipelineState }) => ({ ...pipelineState, correctionFeedback: null }),
    // Absence retains whole-directory semantics and exact frozen evidence,
    // including the input fingerprint of any pending preparation.
    6: ({ pipelineState }) => ({ ...pipelineState }),
  }),
  roles: ROLES,
  resolveActiveRoles: (settings) =>
    settings?.mode === "lazy" ? LAZY_ROLES : ROLES,
  roleAccess: Object.freeze({
    auditor: Object.freeze(["read-only"]),
    reviewer: Object.freeze(["read-only"]),
  }),
  workspace: Object.freeze({
    kind: "directory",
    lease: "exclusive",
    preparation: "deferred",
  }),
  resolveWorkspace: ({ taskPath, settingOverrides = {} }) =>
    Object.freeze({
      kind: "directory",
      lease: "exclusive",
      preparation: "deferred",
      sourceScope: settingOverrides.sourceScope ?? "directory",
      excludePaths: Object.freeze([...(settingOverrides.excludePaths ?? [])]),
      artifactPaths: Object.freeze([
        join(taskPath, "clarifications.md"),
        ...reportPaths(taskPath),
      ]),
    }),
  settings: Object.freeze({
    sourceScope: Object.freeze({
      defaultValue: "directory",
      values: SOURCE_SCOPES,
      option: "source-scope",
      validate: (value) => SOURCE_SCOPES.includes(value),
      errorMessage: "must be directory or git",
    }),
    excludePaths: Object.freeze({
      defaultValue: Object.freeze([]),
      option: "exclude-path",
      multiple: true,
      validate: validExcludePaths,
      errorMessage:
        "must be distinct literal confined workspace-relative paths",
    }),
    mode: Object.freeze({
      defaultValue: "independent",
      recommendedValue: "independent",
      values: AUDIT_MODES,
      validate: (value) => AUDIT_MODES.includes(value),
      errorMessage: "must be independent, lazy, or combined",
    }),
    maxDiscoveryPasses: Object.freeze({
      defaultValue: MAX_DISCOVERY_PASSES,
      validate: validDiscoveryBudget,
      errorMessage: "must be a positive integer no greater than 20",
    }),
    maxFindingRecheckPasses: Object.freeze({
      defaultValue: MAX_FINDING_RECHECK_PASSES,
      validate: validDiscoveryBudget,
      errorMessage: "must be a positive integer no greater than 20",
    }),
  }),
  validateSettings: assertSourceSettings,
  taskInputs: Object.freeze({
    task: Object.freeze({ filename: "task.md", optional: false }),
    context: Object.freeze({ filename: "context.md", optional: true }),
  }),
  reportFilename: REPORT_FILENAME,
  runOptions: Object.freeze([
    "project",
    "task",
    "mode",
    "source-scope",
    "exclude-path",
    ...ROLES,
  ]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description:
    "Audit a Git or ordinary workspace read-only and publish a reviewed audit.md.",
  projections: auditProjections,
  validateResumeAction,
  workflow: Object.freeze({
    nonResumableStates: Object.freeze(["FAILED"]),
    createState: createAuditState,
    run: runAudit,
    validateRun: assertAuditRun,
  }),
});
