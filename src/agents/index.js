import {
  ADAPTER_FAILURE_CLASS,
  deriveEffectStarted,
  deriveLaunchRecovery,
  normalizeFailureRecord,
  STRUCTURED_OUTPUT_FAILURE_CLASS,
} from "./adapter-contract.js";
import { PROVIDER_REGISTRY } from "./registry.js";

const ERROR_CODE_PATTERN = /^[A-Z0-9_]{1,64}$/u;

export class AgentBoundaryError extends Error {
  constructor(cause, failure) {
    super("Agent backend turn failed.");
    this.name = "AgentBoundaryError";
    this.failure = failure;
    if (
      typeof cause?.code === "string" &&
      ERROR_CODE_PATTERN.test(cause.code)
    ) {
      this.code = cause.code;
    }
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
  AVAILABILITY_REASONS,
  clientAttributionFingerprint,
  createCapabilityProof,
  DEFAULT_CLIENT_ATTRIBUTION,
  deriveEffectStarted,
  deriveLaunchRecovery,
  EFFECT_EVIDENCE,
  LAUNCH_CHECKPOINTS,
  LAUNCH_OUTCOMES,
  LAUNCH_RECOVERY_CHECKPOINTS,
  normalizeClientAttribution,
  normalizeFailureRecord,
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
export { readProcessIdentity } from "./process-containment.js";
export {
  createProviderRegistry,
  PROVIDER_REGISTRY,
  ProviderRegistryError,
} from "./registry.js";

export const BACKEND_IDS = PROVIDER_REGISTRY.ids;
