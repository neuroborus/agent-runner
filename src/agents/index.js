import {
  ADAPTER_FAILURE_CLASS,
  deriveEffectStarted,
  deriveLaunchRecovery,
  normalizeFailureRecord,
  STRUCTURED_OUTPUT_FAILURE_CLASS,
} from "./adapter-contract.js";
import { PROVIDER_REGISTRY } from "./registry.js";

const ERROR_CODE_PATTERN = /^[A-Z0-9_]{1,64}$/u;
const FAILURE_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u;

// Compose only fixed text, a validated code, and a validated failure class.
function boundaryMessage(code, failureClass) {
  if (code === undefined) return "Agent backend turn failed.";
  return failureClass === ADAPTER_FAILURE_CLASS ||
    typeof failureClass !== "string" ||
    !FAILURE_CLASS_PATTERN.test(failureClass)
    ? `Agent backend turn failed: ${code}.`
    : `Agent backend turn failed: ${code} (${failureClass}).`;
}

export class AgentBoundaryError extends Error {
  constructor(cause, failure) {
    const code =
      typeof cause?.code === "string" && ERROR_CODE_PATTERN.test(cause.code)
        ? cause.code
        : undefined;
    super(boundaryMessage(code, failure.failureClass));
    this.name = "AgentBoundaryError";
    this.failure = failure;
    if (code !== undefined) this.code = code;
    this.ambiguous = failure.outcome === "ambiguous";
    this.recoverable = failure.retry === "transient";
    const effectStarted = deriveEffectStarted(failure);
    if (effectStarted !== undefined) this.effectStarted = effectStarted;
    const launchRecovery = deriveLaunchRecovery(failure);
    if (launchRecovery !== undefined) this.launchRecovery = launchRecovery;
    if (cause?.failureClass === STRUCTURED_OUTPUT_FAILURE_CLASS) {
      this.failureClass = STRUCTURED_OUTPUT_FAILURE_CLASS;
    }
    if (failure.failureClass !== ADAPTER_FAILURE_CLASS) {
      this.diagnosticClass = failure.failureClass;
    }
  }
}

export function normalizeAdapterFailure(
  backend,
  cause,
  providers = PROVIDER_REGISTRY,
) {
  if (cause instanceof AgentBoundaryError) {
    return cause;
  }
  const failure =
    providers.classifyFailure(backend, cause) ??
    normalizeFailureRecord({
      failureClass: ADAPTER_FAILURE_CLASS,
      checkpoint: "turn",
      outcome: "rejected",
      effect: "possible",
      retry: "terminal",
    });
  return new AgentBoundaryError(cause, failure);
}

export function isAdapterDiagnosticClass(value, providers = PROVIDER_REGISTRY) {
  return providers.isDiagnosticClass(value);
}

// Only an actual normalized turn failure can supply a durable diagnosis.
export function terminalAdapterDiagnostic(
  cause,
  providers = PROVIDER_REGISTRY,
) {
  if (!(cause instanceof AgentBoundaryError)) return null;
  const failure = normalizeFailureRecord(cause.failure, [
    ...new Set(
      providers.list().flatMap(({ failures }) => [...failures.classes]),
    ),
  ]);
  if (failure.retry !== "terminal" || failure.disposition !== undefined)
    return null;
  return {
    code:
      typeof cause.code === "string" && ERROR_CODE_PATTERN.test(cause.code)
        ? cause.code
        : "ERR_AGENT_FAILED",
    ...(failure.failureClass === ADAPTER_FAILURE_CLASS
      ? {}
      : { diagnosticClass: failure.failureClass }),
  };
}

export {
  CLAUDE_BACKEND_ID,
  CLAUDE_FAILURE_CLASSES,
  ClaudeAdapterError,
  classifyClaudeFailure,
  createClaudeAdapter,
} from "./claude/index.js";
export {
  CODEX_BACKEND_ID,
  CODEX_FAILURE_CLASSES,
  CodexAdapterError,
  classifyCodexFailure,
  createCodexAdapter,
} from "./codex/index.js";
export {
  ADAPTER_FAILURE_CLASS,
  AUTHENTICATION_REQUIRED_DISPOSITION,
  AVAILABILITY_REASONS,
  clientAttributionFingerprint,
  createCapabilityProof,
  DEFAULT_CLIENT_ATTRIBUTION,
  deriveEffectStarted,
  deriveLaunchRecovery,
  EFFECT_EVIDENCE,
  FAILURE_DISPOSITIONS,
  LAUNCH_CHECKPOINTS,
  LAUNCH_OUTCOMES,
  LAUNCH_RECOVERY_CHECKPOINTS,
  normalizeClientAttribution,
  normalizeSessionNamingContext,
  normalizeSessionNamingDiagnostic,
  normalizeFailureRecord,
  OUTPUT_EXHAUSTED_DISPOSITION,
  PROVIDER_NEUTRAL_LAUNCH_FAILURE_CLASSES,
  RETRY_ELIGIBILITY,
  STRUCTURED_OUTPUT_FAILURE_CLASS,
} from "./adapter-contract.js";
export {
  assertOwnedProcessLauncherProtected,
  inspectOwnedSessionProcesses,
  resolveOwnedProcessLauncher,
  spawnOwnedProcess,
  terminateOwnedProcess,
} from "./owned-process.js";
export {
  readProcessIdentity,
  readProcessNamespace,
} from "./process-containment.js";
export {
  createProviderRegistry,
  PROVIDER_REGISTRY,
  ProviderRegistryError,
} from "./registry.js";

export const BACKEND_IDS = PROVIDER_REGISTRY.ids;

export { normalizeProviderObservation } from "./observations.js";
