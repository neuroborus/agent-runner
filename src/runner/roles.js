import { createHash } from "node:crypto";

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

const ACCESS_CAPABILITIES = Object.freeze({
  "read-only": Object.freeze(["readOnly"]),
  "workspace-write": Object.freeze([
    "autonomousWrite",
    "gitMetadataWriteBlocked",
    "workspaceWrite",
  ]),
  "local-commit": Object.freeze(["localCommit"]),
});
const ACCESS_ORDER = Object.freeze(Object.keys(ACCESS_CAPABILITIES));

function roleAccess(pipeline, role) {
  const access =
    pipeline.roleAccess === undefined
      ? ["read-only"]
      : isRecord(pipeline.roleAccess)
        ? pipeline.roleAccess[role]
        : undefined;
  if (
    !Array.isArray(access) ||
    access.length === 0 ||
    new Set(access).size !== access.length ||
    access.some((value) => !ACCESS_ORDER.includes(value))
  ) {
    throw new RunnerError(
      `Pipeline ${pipeline.id} has invalid access requirements for ${role}.`,
      { code: "ERR_INVALID_PIPELINE" },
    );
  }
  return access;
}

function supportedAccess(capabilities) {
  return ACCESS_ORDER.filter(
    (access) =>
      capabilities.remoteWriteBlocked === true &&
      ACCESS_CAPABILITIES[access].every(
        (capability) => capabilities[capability] === true,
      ),
  );
}

function normalizePolicyReceipt(capabilities) {
  const supported = supportedAccess(capabilities);
  const provided = capabilities.policyReceipt;
  if (provided !== undefined) {
    if (
      !isRecord(provided) ||
      Object.keys(provided).length !== 3 ||
      provided.schemaVersion !== 1 ||
      typeof provided.fingerprint !== "string" ||
      !/^[a-f0-9]{64}$/u.test(provided.fingerprint) ||
      !Array.isArray(provided.supportedAccess) ||
      provided.supportedAccess.length !== supported.length ||
      provided.supportedAccess.some(
        (access, index) => access !== supported[index],
      )
    ) {
      throw new RunnerError("Backend returned an invalid policy receipt.", {
        code: "ERR_UNSUPPORTED_BACKEND",
      });
    }
    return Object.freeze({
      schemaVersion: 1,
      fingerprint: provided.fingerprint,
      supportedAccess: Object.freeze([...provided.supportedAccess]),
    });
  }
  return Object.freeze({
    schemaVersion: 1,
    fingerprint: createHash("sha256")
      .update(
        JSON.stringify({
          contract: "adapter-capabilities-v1",
          supportedAccess: supported,
          version: capabilities.version,
        }),
      )
      .digest("hex"),
    supportedAccess: Object.freeze(supported),
  });
}

function validateCapabilities(
  capabilities,
  { access, backend, pipelineId, role, sourceSession },
) {
  const invalidBase =
    !isRecord(capabilities) ||
    typeof capabilities.version !== "string" ||
    capabilities.version.trim().length === 0;
  const unsupported = [
    ...(invalidBase ? ["adapter-contract"] : []),
    ...(capabilities?.structuredOutput === true ? [] : ["structured-output"]),
    ...(capabilities?.remoteWriteBlocked === true
      ? []
      : ["remote-write-blocked"]),
    ...access.filter((mode) =>
      ACCESS_CAPABILITIES[mode].some(
        (capability) => capabilities?.[capability] !== true,
      ),
    ),
  ];
  if (invalidBase || unsupported.length > 0) {
    throw new RunnerError(
      `Backend cannot safely run ${pipelineId}.${role}: ${backend} ` +
        `(unsupported: ${unsupported.join(", ")}).`,
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
  return Object.freeze({
    capabilities,
    policyReceipt: normalizePolicyReceipt(capabilities),
  });
}

function executionOptions(configuration, providers) {
  const options = Object.freeze({
    profile: configuration.profile,
    model: configuration.model,
    contextSize: configuration.contextSize,
    effort: configuration.effort,
  });
  providers.validateExecutionOptions(configuration.backend, options);
  return options;
}

async function runAdapter(adapter, backend, request, providers) {
  try {
    return await adapter.run(request);
  } catch (cause) {
    // Preserve the runner's pre-effect stop proof before redacting provider and
    // supervised-process error wrappers. No native cause crosses this boundary.
    if (
      cause?.effectStarted === false &&
      request.signal?.aborted &&
      [cause, cause?.cause, cause?.cause?.cause].includes(request.signal.reason)
    ) {
      throw normalizeAdapterFailure(
        backend,
        { code: request.signal.reason?.code, effectStarted: false },
        providers,
      );
    }
    throw normalizeAdapterFailure(backend, cause, providers);
  }
}

function lazyArbiterAdapter(
  run,
  pipeline,
  configuration,
  adapters,
  providers,
  onPolicyReceipt,
) {
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
          access: roleAccess(pipeline, "arbiter"),
          backend: configuration.backend,
          pipelineId: run.pipelineId,
          role: "arbiter",
          sourceSession: null,
        }),
      )
      .then(async ({ capabilities, policyReceipt }) => {
        await onPolicyReceipt("arbiter", policyReceipt);
        return capabilities;
      });
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

function configuredAdapter(
  run,
  pipeline,
  role,
  configuration,
  adapters,
  providers,
  onPolicyReceipt,
) {
  const adapter = resolveAdapter(
    adapters,
    run.pipelineId,
    role,
    configuration.backend,
  );
  let capabilitiesPromise;
  const resolveCapabilities = async () => {
    capabilitiesPromise ??= Promise.resolve()
      .then(() => adapter.probe(executionOptions(configuration, providers)))
      .then((capabilities) =>
        validateCapabilities(capabilities, {
          access: roleAccess(pipeline, role),
          backend: configuration.backend,
          pipelineId: run.pipelineId,
          role,
          sourceSession: run.sessionLineage.source,
        }),
      )
      .then(async ({ capabilities, policyReceipt }) => {
        await onPolicyReceipt(role, policyReceipt);
        return capabilities;
      });
    try {
      return await capabilitiesPromise;
    } catch (error) {
      capabilitiesPromise = undefined;
      throw error;
    }
  };
  return Object.freeze({
    probe: resolveCapabilities,
    run: (request) =>
      runAdapter(adapter, configuration.backend, request, providers),
  });
}

export function roleAdapters(
  run,
  pipeline,
  adapters,
  providers = PROVIDER_REGISTRY,
  onPolicyReceipt = async () => {},
) {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(run.roles).map(([role, configuration]) => [
        role,
        role === "arbiter"
          ? lazyArbiterAdapter(
              run,
              pipeline,
              configuration,
              adapters,
              providers,
              onPolicyReceipt,
            )
          : configuredAdapter(
              run,
              pipeline,
              role,
              configuration,
              adapters,
              providers,
              onPolicyReceipt,
            ),
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
  const receipts = Object.fromEntries(
    Object.keys(roles).map((role) => [role, null]),
  );
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
    const { policyReceipt } = validateCapabilities(
      capabilitiesByConfiguration.get(key),
      {
        access: roleAccess(pipeline, role),
        backend,
        pipelineId: pipeline.id,
        role,
        sourceSession,
      },
    );
    receipts[role] = policyReceipt;
  }
  return Object.freeze(receipts);
}
