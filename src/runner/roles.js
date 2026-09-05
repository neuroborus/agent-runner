import { normalizeAdapterFailure, PROVIDER_REGISTRY } from "../agents/index.js";

import { isRecord, RunnerError } from "./input.js";

export function defaultAdapters(providers = PROVIDER_REGISTRY) {
  return providers.createAdapters();
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

function executionOptions(configuration, providers) {
  const options = Object.freeze({
    profile: configuration.profile,
    model: configuration.model,
    contextSize: configuration.contextSize,
  });
  providers.validateExecutionOptions(configuration.backend, options);
  return options;
}

async function runAdapter(adapter, backend, request, providers) {
  try {
    return await adapter.run(request);
  } catch (cause) {
    throw normalizeAdapterFailure(backend, cause, providers);
  }
}

function lazyArbiterAdapter(run, configuration, adapters, providers) {
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
      .then(() => resolve().probe(executionOptions(configuration, providers)))
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
      return runAdapter(resolve(), configuration.backend, request, providers);
    },
  });
}

function configuredAdapter(run, role, configuration, adapters, providers) {
  const adapter = resolveAdapter(
    adapters,
    run.pipelineId,
    role,
    configuration.backend,
  );
  return Object.freeze({
    probe: () => adapter.probe(executionOptions(configuration, providers)),
    run: (request) =>
      runAdapter(adapter, configuration.backend, request, providers),
  });
}

export function roleAdapters(run, adapters, providers = PROVIDER_REGISTRY) {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(run.roles).map(([role, configuration]) => [
        role,
        role === "arbiter"
          ? lazyArbiterAdapter(run, configuration, adapters, providers)
          : configuredAdapter(run, role, configuration, adapters, providers),
      ]),
    ),
  );
}

export function validateSourceRoles(
  pipeline,
  roles,
  sourceSession,
  providers = PROVIDER_REGISTRY,
) {
  if (sourceSession === null) {
    return;
  }
  if (!providers.supportsSourceSessionFork(sourceSession.backend)) {
    throw new RunnerError(
      `Backend cannot fork the supplied source: ${sourceSession.backend}.`,
      { code: "ERR_UNSUPPORTED_SOURCE_SESSION" },
    );
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
  providers = PROVIDER_REGISTRY,
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
        await adapter.probe(executionOptions(configuration, providers)),
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
