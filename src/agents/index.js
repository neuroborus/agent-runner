import { CLAUDE_BACKEND_ID } from "./claude.js";
import {
  CODEX_BACKEND_ID,
  CodexAdapterError,
  createCodexAdapter,
} from "./codex.js";

export {
  CLAUDE_BACKEND_ID,
  CODEX_BACKEND_ID,
  CodexAdapterError,
  createCodexAdapter,
};

export const BACKEND_IDS = Object.freeze([
  CODEX_BACKEND_ID,
  CLAUDE_BACKEND_ID,
]);
