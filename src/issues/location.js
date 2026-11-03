import { homedir } from "node:os";
import { isAbsolute, join, win32 } from "node:path";

import { IssueError, safeAbsolutePath } from "./contract.js";

function locationPath(value, paths) {
  const path = safeAbsolutePath(value, paths);
  if (path === null || (paths === win32 && win32.parse(path).root.length < 3)) {
    throw new IssueError("Issue storage requires a safe absolute location.", {
      code: "ERR_UNSAFE_ISSUE_STORE",
    });
  }
  return path;
}

// Maps only the private per-user data location; it grants no platform support.
export function resolveIssueStorePath({
  env = process.env,
  homeDirectory,
  platform = process.platform,
} = {}) {
  if (platform === "win32") {
    return locationPath(
      win32.join(
        locationPath(env.LOCALAPPDATA, win32),
        "agent-runner",
        "issues",
      ),
      win32,
    );
  }
  const home = () => locationPath(homeDirectory ?? env.HOME ?? homedir());
  if (platform === "darwin") {
    return locationPath(
      join(home(), "Library", "Application Support", "agent-runner", "issues"),
    );
  }
  if (platform !== "linux") {
    throw new IssueError("Issue storage is unsupported on this platform.", {
      code: "ERR_UNSAFE_ISSUE_STORE",
    });
  }
  // XDG specifies that relative values are ignored.
  const root =
    typeof env.XDG_DATA_HOME === "string" && isAbsolute(env.XDG_DATA_HOME)
      ? locationPath(env.XDG_DATA_HOME)
      : join(home(), ".local", "share");
  return locationPath(join(root, "agent-runner", "issues"));
}
