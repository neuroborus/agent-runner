import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

// Standard-library-only location mapping shared with pre-import startup.
// Callers own their error vocabulary and any filesystem effects.
export function resolveStateLocation({
  env = process.env,
  homeDirectory = homedir(),
} = {}) {
  const base =
    typeof env?.XDG_STATE_HOME === "string" && isAbsolute(env.XDG_STATE_HOME)
      ? env.XDG_STATE_HOME
      : typeof homeDirectory === "string" && isAbsolute(homeDirectory)
        ? join(homeDirectory, ".local", "state")
        : null;
  return base === null ? null : resolve(base, "agent-runner");
}
