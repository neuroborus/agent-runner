import { PROVIDER_REGISTRY } from "../agents/index.js";
import {
  loadRunnerConfiguration,
  resolveRunStoragePolicy,
} from "../config/index.js";
import { createGitService } from "../git/index.js";
import { resolveStopBoundary } from "../pipeline-registry.js";
import { createRunStore } from "../state/index.js";

// One composition path also covers MCP's direct state mutations and detached
// continuations. Explicitly injected stores retain their own policy.
export function createConfiguredRunStore({
  providers = PROVIDER_REGISTRY,
  git = createGitService(),
  loadConfiguration = () => loadRunnerConfiguration(providers),
} = {}) {
  return createRunStore({
    resolveStopBoundary,
    maxEventLogBytes: async (run) =>
      resolveRunStoragePolicy({
        configuration: await loadConfiguration(),
        inspectPath: (options) => git.inspectPath(options),
        projectPath: run.projectPath,
        protection: run.projectConfigurationProtection,
      }),
  });
}
