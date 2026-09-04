import {
  CLAUDE_BACKEND_ID,
  ClaudeAdapterError,
  createClaudeAdapter,
  normalizeClaudeDiagnosticClass,
} from "./claude.js";
import {
  CODEX_BACKEND_ID,
  CodexAdapterError,
  createCodexAdapter,
  normalizeCodexDiagnosticClass,
} from "./codex.js";
import { STRUCTURED_OUTPUT_FAILURE_CLASS } from "./adapter-contract.js";

const ERROR_CODE_PATTERN = /^[A-Z0-9_]{1,64}$/u;
const DIAGNOSTIC_NORMALIZERS = Object.freeze({
  [CLAUDE_BACKEND_ID]: normalizeClaudeDiagnosticClass,
  [CODEX_BACKEND_ID]: normalizeCodexDiagnosticClass,
});

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

export function normalizeAdapterFailure(backend, cause) {
  if (cause instanceof AgentBoundaryError) {
    return cause;
  }
  const diagnosticClass = DIAGNOSTIC_NORMALIZERS[backend]?.(
    cause?.diagnosticClass,
  );
  return new AgentBoundaryError(cause, diagnosticClass);
}

export function isAdapterDiagnosticClass(value) {
  return Object.values(DIAGNOSTIC_NORMALIZERS).some(
    (normalize) => normalize(value) !== undefined,
  );
}

export {
  CLAUDE_BACKEND_ID,
  ClaudeAdapterError,
  CODEX_BACKEND_ID,
  CodexAdapterError,
  createClaudeAdapter,
  createCodexAdapter,
  normalizeClaudeDiagnosticClass,
  normalizeCodexDiagnosticClass,
};
export { STRUCTURED_OUTPUT_FAILURE_CLASS };

export const BACKEND_IDS = Object.freeze([CODEX_BACKEND_ID, CLAUDE_BACKEND_ID]);
