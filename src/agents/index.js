import {
  CLAUDE_BACKEND_ID,
  ClaudeAdapterError,
  createClaudeAdapter,
} from "./claude.js";
import {
  CODEX_BACKEND_ID,
  CodexAdapterError,
  createCodexAdapter,
} from "./codex.js";

export {
  CLAUDE_BACKEND_ID,
  ClaudeAdapterError,
  CODEX_BACKEND_ID,
  CodexAdapterError,
  createClaudeAdapter,
  createCodexAdapter,
};

export const BACKEND_IDS = Object.freeze([
  CODEX_BACKEND_ID,
  CLAUDE_BACKEND_ID,
]);
