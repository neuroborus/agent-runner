import { join } from "node:path";

import {
  AUDIT_MODES,
  assertAuditRun,
  createAuditState,
  MAX_DISCOVERY_PASSES,
  validDiscoveryBudget,
} from "./discovery-contract.js";
import { runAuditDiscovery } from "./workflow.js";

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
} from "./discovery-contract.js";
export { runAuditDiscovery } from "./workflow.js";

// Intentionally absent from root dependencies/registry until all audit gates exist.
export const auditPipeline = Object.freeze({
  id: "audit",
  stateVersion: 1,
  roles: Object.freeze(["auditor"]),
  roleAccess: Object.freeze({ auditor: Object.freeze(["read-only"]) }),
  workspace: Object.freeze({ kind: "directory", lease: "exclusive" }),
  resolveWorkspace: ({ taskPath }) =>
    Object.freeze({
      kind: "directory",
      lease: "exclusive",
      artifactPaths: Object.freeze([join(taskPath, "clarifications.md")]),
    }),
  settings: Object.freeze({
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
  }),
  taskInputs: Object.freeze({
    task: Object.freeze({ filename: "task.md", optional: false }),
    context: Object.freeze({ filename: "context.md", optional: true }),
  }),
  workflow: Object.freeze({
    createState: createAuditState,
    run: runAuditDiscovery,
    validateRun: assertAuditRun,
  }),
});
