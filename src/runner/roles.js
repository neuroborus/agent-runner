import { createHash } from "node:crypto";

import {
  ADAPTER_FAILURE_CLASS,
  AgentBoundaryError,
  createCapabilityProof,
  normalizeAdapterFailure,
  normalizeFailureRecord,
  PROVIDER_REGISTRY,
} from "../agents/index.js";

import { isRecord, RunnerError } from "./input.js";

export function defaultAdapters(
  clientAttribution,
  providers = PROVIDER_REGISTRY,
) {
  return providers.createAdapters(clientAttribution);
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

function roleAccess(pipeline, role, workspacePolicy) {
  const access =
    pipeline.resolveRoleAccess?.({ role, workspacePolicy }) ??
    (pipeline.roleAccess === undefined
      ? ["read-only"]
      : isRecord(pipeline.roleAccess)
        ? pipeline.roleAccess[role]
        : undefined);
  if (
    !Array.isArray(access) ||
    access.length === 0 ||
    new Set(access).size !== access.length ||
    access.some(
      (value) =>
        !ACCESS_ORDER.includes(value) ||
        (workspacePolicy !== undefined && value === "local-commit"),
    )
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
  { access, backend, pipelineId, role, sourceSession, workspacePolicy },
) {
  const requiredCapabilities = [
    "structuredOutput",
    "remoteWriteBlocked",
    ...(workspacePolicy === undefined ? [] : ["declaredWorkspace"]),
    ...access.flatMap((mode) => ACCESS_CAPABILITIES[mode]),
    ...(sourceSession === null ? [] : ["nativeSessionFork"]),
  ].filter((value, index, values) => values.indexOf(value) === index);
  const invalidBase =
    !isRecord(capabilities) ||
    typeof capabilities.version !== "string" ||
    capabilities.version.length === 0 ||
    capabilities.version.length > 256 ||
    capabilities.version.trim() !== capabilities.version ||
    /[\0\r\n]/u.test(capabilities.version);
  const unsupported = [
    ...(invalidBase ? ["adapter-contract"] : []),
    ...(capabilities?.structuredOutput === true ? [] : ["structured-output"]),
    ...(capabilities?.remoteWriteBlocked === true
      ? []
      : ["remote-write-blocked"]),
    ...(workspacePolicy === undefined ||
    capabilities?.declaredWorkspace === true
      ? []
      : ["declared-workspace"]),
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
  const policyReceipt = normalizePolicyReceipt(capabilities);
  let proof;
  try {
    proof = createCapabilityProof(
      capabilities,
      requiredCapabilities,
      policyReceipt,
    );
  } catch {
    throw new RunnerError("Backend returned an invalid capability proof.", {
      code: "ERR_UNSUPPORTED_BACKEND",
    });
  }
  return Object.freeze({
    capabilities: proof,
    policyReceipt,
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
    const failure = normalizeAdapterFailure(backend, cause, providers);
    if (
      request.session?.mode === "fork" &&
      failure.failure.availabilityReason === undefined &&
      failure.launchRecovery !== undefined &&
      !["spawn", "initialize"].includes(failure.launchRecovery.checkpoint)
    ) {
      // Native forking may already have created an unrecorded child. Preserve
      // the normalized failure, but do not let pipeline retry policy replay
      // this request from the source session.
      delete failure.launchRecovery;
      failure.recoverable = false;
    }
    const stopReason = request.signal?.reason;
    // Preserve the runner's pre-effect stop proof before redacting the native
    // abort reason. No provider cause crosses this boundary.
    if (
      request.signal?.aborted &&
      [cause, cause?.cause, cause?.cause?.cause].includes(stopReason) &&
      failure.effectStarted === false
    ) {
      const record = normalizeFailureRecord({
        failureClass: ADAPTER_FAILURE_CLASS,
        checkpoint: failure.failure.checkpoint,
        outcome: "rejected",
        effect: "none",
        retry: "terminal",
        ...(failure.failure.checkpoint === "commit"
          ? { commitExecutor: "not_started" }
          : {}),
      });
      throw new AgentBoundaryError({ code: stopReason?.code }, record);
    }
    if (
      request.signal?.aborted &&
      ["ERR_PROVIDER_INACTIVE", "ERR_INACTIVITY_RECOVERY"].includes(
        stopReason?.code,
      ) &&
      [cause, cause?.cause, cause?.cause?.cause].includes(stopReason)
    ) {
      throw new AgentBoundaryError({ code: stopReason.code }, failure.failure);
    }
    throw failure;
  }
}

async function probeAdapter(adapter, backend, options, providers) {
  try {
    return await adapter.probe(options);
  } catch (cause) {
    throw normalizeAdapterFailure(backend, cause, providers);
  }
}

async function probeRole(
  adapter,
  pipeline,
  role,
  configuration,
  sourceSession,
  providers,
  workspacePolicy,
  selectedAccess,
) {
  const declared = roleAccess(pipeline, role, workspacePolicy);
  const access = selectedAccess ?? declared;
  if (access.some((mode) => !declared.includes(mode)))
    throw new RunnerError("Probe exceeds role authority.");
  const options = executionOptions(configuration, providers);
  const context = {
    access,
    backend: configuration.backend,
    pipelineId: pipeline.id,
    role,
    sourceSession,
    workspacePolicy,
  };
  if (workspacePolicy === undefined)
    return validateCapabilities(
      await probeAdapter(adapter, configuration.backend, options, providers),
      context,
    );
  const proofs = [];
  for (const mode of access) {
    proofs.push(
      validateCapabilities(
        await probeAdapter(
          adapter,
          configuration.backend,
          { ...options, access: mode, workspacePolicy },
          providers,
        ),
        { ...context, access: [mode] },
      ),
    );
  }
  const policyReceipt = Object.freeze({
    schemaVersion: 1,
    fingerprint: createHash("sha256")
      .update(JSON.stringify(proofs.map(({ policyReceipt }) => policyReceipt)))
      .digest("hex"),
    supportedAccess: Object.freeze(
      ACCESS_ORDER.filter((mode) => access.includes(mode)),
    ),
  });
  const capabilities = { version: proofs[0].capabilities.version };
  const required = [
    ...new Set(
      proofs.flatMap(({ capabilities }) => capabilities.requiredCapabilities),
    ),
  ];
  for (const { capabilities: proof } of proofs) {
    if (proof.version !== capabilities.version)
      throw new RunnerError("Backend changed during access probing.", {
        code: "ERR_UNSUPPORTED_BACKEND",
      });
    for (const [name, value] of Object.entries(proof)) {
      if (typeof value === "boolean")
        capabilities[name] = proofs.every(
          ({ capabilities }) => capabilities[name] === true,
        );
    }
  }
  for (const name of required) capabilities[name] = true;
  return {
    policyReceipt,
    capabilities: createCapabilityProof(capabilities, required, policyReceipt),
  };
}

function directoryRequest(run, pipeline, role, request) {
  const policy = run.workspace?.policy;
  if (policy == null) return request;
  if (
    !roleAccess(pipeline, role, policy).includes(request.access) ||
    request.cwd !== run.projectPath
  )
    throw new RunnerError("Turn exceeds the declared workspace access.", {
      code: "ERR_UNSAFE_WORKSPACE_ACCESS",
    });
  return { ...request, workspacePolicy: policy };
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
      .then(() =>
        probeRole(
          resolve(),
          pipeline,
          "arbiter",
          configuration,
          null,
          providers,
          run.workspace?.policy ?? undefined,
        ),
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
      return runAdapter(
        resolve(),
        configuration.backend,
        directoryRequest(run, pipeline, "arbiter", request),
        providers,
      );
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
  const capabilitiesByAccess = new Map();
  const resolveCapabilities = async ({ access } = {}) => {
    const selectedAccess =
      run.workspace?.policy && pipeline.initialRoleAccess
        ? access
          ? [access]
          : pipeline.initialRoleAccess({
              role,
              workspacePolicy: run.workspace.policy,
            })
        : undefined;
    const key = JSON.stringify(selectedAccess);
    let capabilitiesPromise = capabilitiesByAccess.get(key);
    capabilitiesPromise ??= Promise.resolve()
      .then(() =>
        probeRole(
          adapter,
          pipeline,
          role,
          configuration,
          run.sessionLineage.source,
          providers,
          run.workspace?.policy ?? undefined,
          selectedAccess,
        ),
      )
      .then(async ({ capabilities, policyReceipt }) => {
        // Deferred directory writes prove their exact access immediately before
        // the turn; they do not replace the frozen read-only startup receipt.
        if (access === undefined || !pipeline.initialRoleAccess)
          await onPolicyReceipt(role, policyReceipt);
        return capabilities;
      });
    capabilitiesByAccess.set(key, capabilitiesPromise);
    try {
      return await capabilitiesPromise;
    } catch (error) {
      capabilitiesByAccess.delete(key);
      throw error;
    }
  };
  return Object.freeze({
    probe: resolveCapabilities,
    async canReadFiles(request) {
      await resolveCapabilities();
      return (
        (await adapter.canReadFiles?.({
          ...request,
          ...(run.workspace?.policy
            ? { workspacePolicy: run.workspace.policy }
            : {}),
        })) === true
      );
    },
    async run(request) {
      if (run.workspace?.policy) {
        await resolveCapabilities();
        if (pipeline.initialRoleAccess)
          await resolveCapabilities({ access: request.access });
      }
      return runAdapter(
        adapter,
        configuration.backend,
        directoryRequest(run, pipeline, role, request),
        providers,
      );
    },
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
  workspacePolicy,
  onProof,
) {
  const requiredRoles = Object.keys(roles).filter((role) => role !== "arbiter");
  const receipts = Object.fromEntries(
    Object.keys(roles).map((role) => [role, null]),
  );
  const capabilitiesByConfiguration = new Map();
  for (const role of requiredRoles) {
    const configuration = roles[role];
    if (workspacePolicy !== undefined) {
      const proof = await probeRole(
        resolveAdapter(adapters, pipeline.id, role, configuration.backend),
        pipeline,
        role,
        configuration,
        sourceSession,
        providers,
        workspacePolicy,
        pipeline.initialRoleAccess?.({ role, workspacePolicy }),
      );
      onProof?.(role, proof.capabilities);
      receipts[role] = proof.policyReceipt;
      continue;
    }
    const backend = configuration.backend;
    const key = JSON.stringify(configuration);
    if (!capabilitiesByConfiguration.has(key)) {
      const adapter = resolveAdapter(adapters, pipeline.id, role, backend);
      capabilitiesByConfiguration.set(
        key,
        await probeAdapter(
          adapter,
          backend,
          executionOptions(configuration, providers),
          providers,
        ),
      );
    }
    const { policyReceipt, capabilities } = validateCapabilities(
      capabilitiesByConfiguration.get(key),
      {
        access: roleAccess(pipeline, role),
        backend,
        pipelineId: pipeline.id,
        role,
        sourceSession,
      },
    );
    onProof?.(role, capabilities);
    receipts[role] = policyReceipt;
  }
  return Object.freeze(receipts);
}

export function capabilityAuthorityFingerprint(proof) {
  const { policyReceipt, ...authority } = proof;
  return createHash("sha256")
    .update(
      JSON.stringify({
        ...authority,
        supportedAccess: policyReceipt.supportedAccess,
      }),
    )
    .digest("hex");
}
