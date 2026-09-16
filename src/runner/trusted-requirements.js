import { RunnerError } from "./input.js";

// Preparation is an owned runner effect. Pipeline requests cannot replace the
// saved authority, resource journal, cancellation monitor, or repository scope.
export async function inspectTrustedRequirements(
  {
    trustedValidation,
    runStore,
    lease,
    run,
    monitor,
    checkConfiguration,
    validatePersistedBoundary,
    storageForbiddenPaths,
  },
  request,
) {
  await checkConfiguration();
  await monitor.check();
  const current = await runStore.loadRun(run.runId);
  if (current.executionResource != null || current.executionProcess != null) {
    throw new RunnerError(
      "Capability inspection requires settled resource ownership.",
      {
        code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE",
      },
    );
  }
  if (typeof trustedValidation.inspectRequirements !== "function") {
    throw new RunnerError("Runner capability inspection is unavailable.", {
      code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
    });
  }
  try {
    return await monitor.invoke(
      (value) =>
        trustedValidation.inspectRequirements({
          ...value,
          projectPath: current.projectPath,
          snapshot: current.pipelineState.trustedValidation,
          storageForbiddenPaths: storageForbiddenPaths(current),
          onResource: (resource) =>
            runStore.recordExecutionResource(lease, resource),
        }),
      request,
    );
  } finally {
    await checkConfiguration();
    await validatePersistedBoundary(run);
  }
}
