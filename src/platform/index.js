// Static native-platform selection: only Linux is implemented. Each capability
// keeps its own host guard and fails closed elsewhere.

// Process facts.
export { readProcessIdentity, readProcessNamespace } from "./linux-process.js";

// Owned processes.
export {
  assertOwnedProcessLauncherProtected,
  executeOwnedProcess,
  inspectOwnedSessionProcesses,
  resolveOwnedProcessLauncher,
  spawnOwnedProcess,
  terminateOwnedProcess,
} from "./linux-owned-process.js";

// Trusted-command isolation.
export {
  createIsolatedCommand,
  ISOLATION_SYSTEM_PATHS,
  resolveIsolationLauncher,
  verifyIsolationLauncher,
} from "./linux-isolation.js";

// Process-group signalling is unavailable on Windows hosts.
export const PROCESS_GROUPS_AVAILABLE = process.platform !== "win32";
