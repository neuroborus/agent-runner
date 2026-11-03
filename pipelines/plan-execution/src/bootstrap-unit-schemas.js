import { STEP_ASSESSMENT } from "./plan-position.js";
import { BOOTSTRAP_SCHEMA } from "./schemas.js";
import {
  CAPABILITY_REQUIREMENTS,
  ENVIRONMENT_BLOCKERS,
  freezeReport,
} from "./capability-requirements.js";
import {
  REQUIRED_CHECK,
  BOOTSTRAP_VALIDATION_INFRASTRUCTURE,
} from "./validation-schema-fragments.js";
import {
  MAX_BOOTSTRAP_ITEMS,
  MAX_SUMMARY_LENGTH,
} from "./workflow-contract.js";

const object = (properties) => ({
  type: "object",
  properties,
  required: Object.keys(properties),
  additionalProperties: false,
});
const list = (items, maxItems = MAX_BOOTSTRAP_ITEMS) => ({
  type: "array",
  items,
  maxItems,
});
const hash = { type: "string", pattern: "^[a-f0-9]{64}$" };
const commands = list(REQUIRED_CHECK.properties.command);
const paths = BOOTSTRAP_VALIDATION_INFRASTRUCTURE;

// Completed discovery is repository evidence and a catalog, never applicability.
export const REPOSITORY_DISCOVERY_SCHEMA = freezeReport(
  object({
    result: {
      anyOf: [
        object({
          stepAssessment: STEP_ASSESSMENT,
          summary: {
            type: "string",
            minLength: 1,
            maxLength: MAX_SUMMARY_LENGTH,
          },
          requiredChecks: { ...list(REQUIRED_CHECK), minItems: 1 },
          validationInfrastructure: paths,
          capabilityRequirements: CAPABILITY_REQUIREMENTS,
          environmentBlockers: ENVIRONMENT_BLOCKERS,
        }),
        ...BOOTSTRAP_SCHEMA.properties.result.anyOf.slice(1),
      ],
    },
  }),
);

const assignment = object({
  checkId: REQUIRED_CHECK.properties.id,
  steps: {
    type: "array",
    minItems: 1,
    items: { type: "integer", minimum: 1 },
  },
});
const batch = (status, correcting) =>
  object({
    status: { type: "string", enum: [status] },
    unitId: hash,
    assignments: {
      ...list(assignment),
      ...(correcting ? { maxItems: 0 } : {}),
    },
    missingCommands: { ...commands, ...(correcting ? {} : { maxItems: 0 }) },
    missingInfrastructure: { ...paths, ...(correcting ? {} : { maxItems: 0 }) },
    capabilityRequirements: {
      ...CAPABILITY_REQUIREMENTS,
      ...(correcting ? {} : { maxItems: 0 }),
    },
    environmentBlockers: {
      ...ENVIRONMENT_BLOCKERS,
      ...(correcting ? {} : { maxItems: 0 }),
    },
  });

export const APPLICABILITY_BATCH_SCHEMA = freezeReport(
  object({
    result: {
      anyOf: [
        batch("READY", false),
        batch("CATALOG_CORRECTION_REQUIRED", true),
      ],
    },
  }),
);
