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
