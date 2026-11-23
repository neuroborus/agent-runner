import { createHash } from "node:crypto";

import { auditPipeline } from "@agent-runner/audit";
import { initPipeline } from "@agent-runner/init";
import { planAuthoringPipeline } from "@agent-runner/plan-authoring";
import { planExecutionPipeline } from "@agent-runner/plan-execution";
import { polishingPipeline } from "@agent-runner/polishing";

import { normalizeReadOnlySnapshotChanges } from "./git/index.js";
import {
  createRunStore as createStateRunStore,
  MODEL_CATALOG_RETRY_CODE,
  RUNTIME_COMPATIBILITY,
} from "./state/index.js";
import { projectCapabilityBlockerEvidence } from "./trusted-validation/index.js";

const PIPELINES = new Map();
// Root-owned capabilities injected into descriptor projections, so pipelines
// never import root modules to publish canonical diagnostics.
const PROJECTION_CAPABILITIES = Object.freeze({
  readOnlySnapshotChanges: normalizeReadOnlySnapshotChanges,
  capabilityBlockerEvidence: projectCapabilityBlockerEvidence,
});

function composePipeline(pipeline) {
  return Object.freeze({
    ...pipeline,
    projections: Object.freeze({
      ...pipeline.projections,
      pause: (run) => pipeline.projections.pause(run, PROJECTION_CAPABILITIES),
    }),
  });
}

for (const pipeline of [
  planAuthoringPipeline,
  planExecutionPipeline,
  polishingPipeline,
  auditPipeline,
  initPipeline,
]) {
  if (PIPELINES.has(pipeline.id)) {
    throw new Error(`Duplicate pipeline id: ${pipeline.id}`);
  }

  PIPELINES.set(pipeline.id, composePipeline(pipeline));
}

export function getPipeline(pipelineId) {
  return PIPELINES.get(pipelineId);
}

export function listPipelines() {
  return Object.freeze([...PIPELINES.values()]);
}

export function resolveStopBoundary(run) {
  return getPipeline(run.pipelineId)?.resolveStopBoundary?.(run) ?? null;
}

function matchesCatalogReservation(previous, next, binding) {
  const pipeline = getPipeline(previous.pipelineId);
  return pipeline === undefined
    ? false
    : pipeline.matchesCatalogReservation?.(previous, next, binding);
}

function assertCatalogTransition(
  previous,
  next,
  activity,
  activeTurnStart,
  commitRejection,
  readOnlyAttempt,
  writableAttempt,
) {
  const pipeline = getPipeline(previous.pipelineId);
  // Descriptors own exact pause mappings and their retained reservations.
  // Only a pipeline that validates COMMIT catalog proof can accept one.
  if (pipeline?.assertCatalogTransition === undefined) {
    if (commitRejection !== undefined)
      throw new Error("Catalog COMMIT proof has no owning checkpoint.");
    return;
  }
  return pipeline.assertCatalogTransition(
    previous,
    next,
    activity,
    MODEL_CATALOG_RETRY_CODE,
    activeTurnStart,
    commitRejection,
    readOnlyAttempt,
    writableAttempt,
  );
}

function matchesAvailabilityRetirement(previous, next, activeTurnStart) {
  return getPipeline(previous.pipelineId)?.matchesAvailabilityRetirement?.(
    previous,
    next,
    activeTurnStart,
  );
}

function readRestatementStart(run) {
  return getPipeline(run.pipelineId)?.readRestatementStart?.(run.pipelineState);
}

export function createRunStore(options) {
  return createStateRunStore({
    ...options,
    matchesCatalogReservation,
    assertCatalogTransition,
    matchesAvailabilityRetirement,
    readRestatementStart,
  });
}

export function createDetachedRuntimeCompatibilityToken({
  pipelines = listPipelines(),
  runtimeCompatibility = RUNTIME_COMPATIBILITY,
} = {}) {
  const pipelineVersions = pipelines
    .map(({ id, stateVersion }) => [id, stateVersion])
    .sort(([leftId], [rightId]) =>
      leftId < rightId ? -1 : leftId > rightId ? 1 : 0,
    );
  const canonicalCompatibility = JSON.stringify({
    detachedProtocol: 1,
    runEnvelope: [
      runtimeCompatibility.runnerVersion,
      runtimeCompatibility.runStateVersion,
    ],
    pipelines: pipelineVersions,
  });
  return createHash("sha256").update(canonicalCompatibility).digest("hex");
}

export const DETACHED_RUNTIME_COMPATIBILITY_TOKEN =
  createDetachedRuntimeCompatibilityToken();
