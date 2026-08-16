import { planAuthoringPipeline } from "@agent-runner/plan-authoring";
import { planExecutionPipeline } from "@agent-runner/plan-execution";

const PIPELINES = new Map();

for (const pipeline of [planAuthoringPipeline, planExecutionPipeline]) {
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
