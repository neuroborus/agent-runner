import { getPipeline } from "../pipeline-registry.js";
import { deepFreeze } from "../state/index.js";

import { isRecord, RunnerError } from "./input.js";

export function preparePipelineMigration(run, pipeline) {
  if (run.pipelineStateVersion > pipeline.stateVersion) {
    throw new RunnerError(
      `Run ${run.runId} uses newer ${pipeline.id} state version ` +
        `${run.pipelineStateVersion}; this runtime supports version ` +
        `${pipeline.stateVersion}. Use a compatible Agent Runner version.`,
      { code: "ERR_PIPELINE_VERSION_SKEW" },
    );
  }

  const originalVersion = run.pipelineStateVersion;
  let migrated = run;
  while (migrated.pipelineStateVersion < pipeline.stateVersion) {
    const migration = pipeline.migrations?.[migrated.pipelineStateVersion];
    if (typeof migration !== "function") {
      throw new RunnerError(
        `Run ${run.runId} requires an unavailable ${pipeline.id} migration ` +
          `from state version ${migrated.pipelineStateVersion}. Use an ` +
          "Agent Runner version with that migration.",
        { code: "ERR_PIPELINE_VERSION_SKEW" },
      );
    }
    let pipelineState;
    try {
      pipelineState = migration(migrated);
    } catch (cause) {
      throw new RunnerError(
        `Run ${run.runId} could not migrate ${pipeline.id} state version ` +
          `${migrated.pipelineStateVersion}.`,
        { cause, code: "ERR_PIPELINE_MIGRATION_FAILED" },
      );
    }
    if (!isRecord(pipelineState)) {
      throw new RunnerError(
        `${pipeline.id} migration from state version ` +
          `${migrated.pipelineStateVersion} returned invalid state.`,
        { code: "ERR_PIPELINE_MIGRATION_FAILED" },
      );
    }
    migrated = deepFreeze({
      ...migrated,
      pipelineStateVersion: migrated.pipelineStateVersion + 1,
      pipelineState,
    });
  }
  try {
    pipeline.workflow.validateRun(migrated);
  } catch (cause) {
    if (migrated.pipelineStateVersion === originalVersion) {
      throw cause;
    }
    throw new RunnerError(
      `Run ${run.runId} produced invalid ${pipeline.id} state after ` +
        `migration from version ${originalVersion}.`,
      { cause, code: "ERR_PIPELINE_MIGRATION_FAILED" },
    );
  }
  return migrated;
}

export function pipelineForRun(
  run,
  knownPipeline,
  { allowMigration = false } = {},
) {
  const pipeline = knownPipeline ?? getPipeline(run.pipelineId);
  if (pipeline === undefined) {
    throw new RunnerError(`Unknown pipeline: ${run.pipelineId}.`, {
      code: "ERR_UNKNOWN_PIPELINE",
    });
  }
  const compatibleRun = preparePipelineMigration(run, pipeline);
  if (
    !allowMigration &&
    compatibleRun.pipelineStateVersion !== run.pipelineStateVersion
  ) {
    throw new RunnerError(
      `Run ${run.runId} requires a persisted ${pipeline.id} state migration.`,
      { code: "ERR_PIPELINE_MIGRATION_REQUIRED" },
    );
  }
  return Object.freeze({ pipeline, run: compatibleRun });
}
