export {
  WINDOWS_PROCESS_LIMIT,
  WINDOWS_SYSTEM_SID,
  WINDOWS_ARGUMENT_PARSER,
  WINDOWS_LITERAL_ARGUMENTS,
  WINDOWS_CREATION_PRECEDENT,
  normalizeWindowsLaunch,
  normalizeWindowsArguments,
  quoteWindowsArgument,
  windowsCommandLine,
  windowsLaunchDigest,
  windowsAccountName,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  inspectWindowsPe,
} from "./protocol.js";
export { admitWindowsLaunch } from "./launch.js";
export { assertWindowsLiteralObservation } from "./literal.js";
export {
  assessWindowsRecovery,
  assessWindowsDomain,
  assertWindowsRetirement,
} from "./recovery.js";
export { retireWindowsDomain } from "./retirement.js";
export {
  WINDOWS_OWNERSHIP_CASES,
  runWindowsOwnershipCase,
} from "./ownership.js";
export {
  WINDOWS_AUTHORITY_PROFILES,
  WINDOWS_ALE_LAYERS,
  normalizeWindowsPolicy,
  buildWindowsPolicy,
  assertWindowsPolicyToken,
} from "./policy.js";
export {
  windowsEffectiveRights,
  assertWindowsPolicySnapshot,
  assertWindowsPolicyInstallation,
  configureWindowsPolicy,
} from "./policy-effects.js";
export {
  WINDOWS_ACCESS_DENIALS,
  assertWindowsAccessObservation,
  runWindowsAccessCase,
} from "./access.js";
