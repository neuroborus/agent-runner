import { STRUCTURED_OUTPUT_FAILURE_CLASS } from "./adapter-contract.js";
import { PROVIDER_REGISTRY } from "./registry.js";

const ERROR_CODE_PATTERN = /^[A-Z0-9_]{1,64}$/u;

export class AgentBoundaryError extends Error {
  constructor(cause, diagnosticClass) {
    super("Agent backend turn failed.");
    this.name = "AgentBoundaryError";
    if (ERROR_CODE_PATTERN.test(cause?.code)) {
      this.code = cause.code;
    }
    this.ambiguous = cause?.ambiguous === true;
    this.recoverable = cause?.recoverable === true;
    if (typeof cause?.effectStarted === "boolean") {
      this.effectStarted = cause.effectStarted;
    }
    if (cause?.failureClass === STRUCTURED_OUTPUT_FAILURE_CLASS) {
      this.failureClass = STRUCTURED_OUTPUT_FAILURE_CLASS;
    }
    if (diagnosticClass !== undefined) {
      this.diagnosticClass = diagnosticClass;
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
  const diagnosticClass = providers.normalizeDiagnosticClass(
    backend,
    cause?.diagnosticClass,
  );
  return new AgentBoundaryError(cause, diagnosticClass);
}

export function isAdapterDiagnosticClass(value, providers = PROVIDER_REGISTRY) {
  return providers.isDiagnosticClass(value);
}

export {
  CLAUDE_BACKEND_ID,
  ClaudeAdapterError,
  createClaudeAdapter,
  normalizeClaudeDiagnosticClass,
} from "./claude/index.js";
export {
  CODEX_BACKEND_ID,
  CodexAdapterError,
  createCodexAdapter,
  normalizeCodexDiagnosticClass,
} from "./codex/index.js";
export { STRUCTURED_OUTPUT_FAILURE_CLASS };
export {
  createProviderRegistry,
  PROVIDER_REGISTRY,
  ProviderRegistryError,
} from "./registry.js";

export const BACKEND_IDS = PROVIDER_REGISTRY.ids;
