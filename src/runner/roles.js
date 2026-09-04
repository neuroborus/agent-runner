import {
  createClaudeAdapter,
  createCodexAdapter,
  normalizeAdapterFailure,
} from "../agents/index.js";

import { isRecord, RunnerError } from "./input.js";

export function defaultAdapters() {
  return Object.freeze({
    codex: createCodexAdapter(),
    claude: createClaudeAdapter(),
  });
}

function resolveAdapter(adapters, pipelineId, role, backend) {
  const adapter = adapters[backend];
  if (
    !isRecord(adapter) ||
    typeof adapter.probe !== "function" ||
    typeof adapter.run !== "function"
  ) {
    throw new RunnerError(
      `Backend is unavailable for ${pipelineId}.${role}: ${backend}.`,
      { code: "ERR_BACKEND_UNAVAILABLE" },
    );
  }
  return adapter;
}

function validateCapabilities(
  capabilities,
  { backend, pipelineId, role, sourceSession },
) {
  if (
    !isRecord(capabilities) ||
    typeof capabilities.version !== "string" ||
    capabilities.version.trim().length === 0 ||
    capabilities.structuredOutput !== true ||
    capabilities.readOnly !== true ||
    capabilities.remoteWriteBlocked !== true
  ) {
    throw new RunnerError(
      `Backend cannot safely run ${pipelineId}.${role}: ${backend}.`,
      { code: "ERR_UNSUPPORTED_BACKEND" },
    );
  }
  if (sourceSession !== null && capabilities.nativeSessionFork !== true) {
    throw new RunnerError(
      `Backend cannot fork the supplied source: ${backend}.`,
      {
        code: "ERR_UNSUPPORTED_SOURCE_SESSION",
      },
    );
  }
  return capabilities;
}

function executionOptions(configuration) {
  return Object.freeze({
    profile: configuration.profile,
    model: configuration.model,
    contextSize: configuration.contextSize,
  });
}

async function runAdapter(adapter, backend, request) {
  try {
    return await adapter.run(request);
  } catch (cause) {
    throw normalizeAdapterFailure(backend, cause);
  }
}

function lazyArbiterAdapter(run, configuration, adapters) {
  let adapter;
  let capabilitiesPromise;
  const resolve = () => {
    adapter ??= resolveAdapter(
      adapters,
      run.pipelineId,
      "arbiter",
      configuration.backend,
    );
    return adapter;
  };
  const resolveCapabilities = async () => {
    capabilitiesPromise ??= Promise.resolve()
      .then(() => resolve().probe(executionOptions(configuration)))
      .then((capabilities) =>
        validateCapabilities(capabilities, {
          backend: configuration.backend,
          pipelineId: run.pipelineId,
          role: "arbiter",
          sourceSession: null,
        }),
      );
    try {
      return await capabilitiesPromise;
    } catch (error) {
      capabilitiesPromise = undefined;
      throw error;
    }
  };
  return Object.freeze({
    probe: resolveCapabilities,
    async run(request) {
      await resolveCapabilities();
      return runAdapter(resolve(), configuration.backend, request);
    },
  });
}

function configuredAdapter(run, role, configuration, adapters) {
  const adapter = resolveAdapter(
    adapters,
    run.pipelineId,
    role,
    configuration.backend,
  );
  return Object.freeze({
    probe: () => adapter.probe(executionOptions(configuration)),
    run: (request) => runAdapter(adapter, configuration.backend, request),
  });
}

export function roleAdapters(run, adapters) {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(run.roles).map(([role, configuration]) => [
        role,
        role === "arbiter"
          ? lazyArbiterAdapter(run, configuration, adapters)
          : configuredAdapter(run, role, configuration, adapters),
      ]),
    ),
  );
}

export function validateSourceRoles(pipeline, roles, sourceSession) {
  if (sourceSession === null) {
    return;
  }
  const incompatibleRole = Object.keys(roles)
    .filter((role) => role !== "arbiter")
    .find((role) => roles[role].backend !== sourceSession.backend);
  if (incompatibleRole !== undefined) {
    throw new RunnerError(
      `Source backend ${sourceSession.backend} does not match ${pipeline.id}.${incompatibleRole}.`,
      { code: "ERR_SOURCE_BACKEND_MISMATCH" },
    );
  }
}

export async function probeRequiredRoles(
  pipeline,
  roles,
  adapters,
  sourceSession,
) {
  const requiredRoles = Object.keys(roles).filter((role) => role !== "arbiter");
  const capabilitiesByConfiguration = new Map();
  for (const role of requiredRoles) {
    const configuration = roles[role];
    const backend = configuration.backend;
    const key = JSON.stringify(configuration);
    if (!capabilitiesByConfiguration.has(key)) {
      const adapter = resolveAdapter(adapters, pipeline.id, role, backend);
      capabilitiesByConfiguration.set(
        key,
        await adapter.probe(executionOptions(configuration)),
      );
    }
    validateCapabilities(capabilitiesByConfiguration.get(key), {
      backend,
      pipelineId: pipeline.id,
      role,
      sourceSession,
    });
  }
}
