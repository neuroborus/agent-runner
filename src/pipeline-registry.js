import { createHash } from "node:crypto";

import { planAuthoringPipeline } from "@agent-runner/plan-authoring";
import { planExecutionPipeline } from "@agent-runner/plan-execution";
import { polishingPipeline } from "@agent-runner/polishing";

import { RUNTIME_COMPATIBILITY } from "./state-validation.js";

const PIPELINES = new Map();

for (const pipeline of [
  planAuthoringPipeline,
  planExecutionPipeline,
  polishingPipeline,
]) {
  if (PIPELINES.has(pipeline.id)) {
    throw new Error(`Duplicate pipeline id: ${pipeline.id}`);
  }

  PIPELINES.set(pipeline.id, pipeline);
}

export function getPipeline(pipelineId) {
  return PIPELINES.get(pipelineId);
}

export function listPipelines() {
  return Object.freeze([...PIPELINES.values()]);
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
