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
export {
  windowsObserverConfiguration,
  assertWindowsObserverEvent,
  runWindowsToolObserver,
} from "./observer.js";
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
  windowsPolicyHelperArguments,
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
export {
  normalizeWindowsFileIdentity,
  normalizeWindowsFileState,
  encodeWindowsFileRequest,
  normalizeWindowsFileMessage,
  runWindowsFileTransaction,
} from "./files-protocol.js";
export {
  normalizeWindowsFileInput,
  windowsFileHelperArguments,
  normalizeWindowsFileRecovery,
  runWindowsFileSession,
} from "./files.js";
export {
  WINDOWS_FILE_CASE_IDS,
  WINDOWS_FILE_CONTROLS,
  WINDOWS_FILE_SESSION_LIMITS,
  assertWindowsFileObservation,
  assertWindowsFileDenial,
  assertWindowsReplacementReads,
  runWindowsFileCase,
} from "./files-cases.js";
export {
  WINDOWS_GIT_DENIALS,
  normalizeWindowsGitInput,
  windowsGitGrant,
  windowsFixedCommitArguments,
  windowsOrdinaryGitArguments,
  windowsGitPolicyArguments,
  assertWindowsCommitObservation,
  assertWindowsOrdinaryGitObservation,
  runWindowsGitCase,
} from "./git.js";

export {
  windowsClaudeBash,
  assertWindowsClaudeBash,
  windowsProviderLaunch,
  windowsProviderOwner,
} from "./provider-launch.js";

export { observeWindowsRelease } from "./release.js";

export { windowsSystemRecipes, runWindowsSystemProofs } from "./system.js";
export {
  acquireWindowsSystemCI,
  prepareWindowsSystemCI,
  loadWindowsSystemCI,
  WINDOWS_SYSTEM_PREPARATION_MS,
} from "./ci.js";

export { windowsProviderCIContract } from "./ci.js";

export {
  WINDOWS_CUSTODY_DEADLINE_MS,
  normalizeWindowsCustodyInput,
  encodeWindowsCustodyPlan,
} from "./custody-protocol.js";
export { createWindowsCustodyReader } from "./custody.js";
export { createWindowsCustodyVerifier } from "./custody-verifier.js";
export { createWindowsPreparationFiles } from "./preparation-files.js";

export {
  normalizeWindowsSecurityRead,
  normalizeWindowsBarrierRead,
  assertWindowsWfpFilterRead,
  createWindowsEffectiveReaders,
} from "./effective.js";
export {
  createWindowsAuditDecoder,
  bindWindowsAuditEvent,
  createWindowsAuditCustody,
  createWindowsSecurityCapture,
} from "./audit.js";

export {
  WINDOWS_HELPER_NAMES,
  WINDOWS_BUILD_TOOLS,
  WINDOWS_BUILD_LIBRARIES,
  WINDOWS_BUILD_COMMAND_MS,
  windowsCompilerArguments,
  windowsBuildOperation,
  windowsSignedPublication,
  runWindowsBuildCommand,
} from "./build.js";
import { createWindowsBuildEffects as buildEffects } from "./preparation.js";
import { createWindowsSystemEffects as systemEffects } from "./effects.js";

export { normalizeWindowsPreparation } from "./preparation.js";

// This composition boundary retains the original preparation observer between
// build and prepared verification. Only independently proved closure releases
// its registry entry; private factories receive the owner explicitly.
const preparationOwners = new Map();
export const createWindowsBuildEffects = (input, options) =>
  buildEffects(input, options, preparationOwners);
export const createWindowsSystemEffects = (input, options) =>
  systemEffects(input, options, preparationOwners);
export { createWindowsPackageEffects } from "./package-effects.js";
export {
  runWindowsFeasibility,
  windowsFeasibilityProfileName,
  windowsFeasibilityToolEnvironment,
  windowsFeasibilityImports,
  windowsFeasibilityCause,
  assertWindowsFeasibilityWitness,
} from "./feasibility.js";
export { prepareWindowsFeasibilityGit } from "./feasibility-git.js";
export {
  runWindowsFeasibilityCommand,
  assessWindowsCommandObservation,
} from "./feasibility-command.js";
export {
  windowsCommandEnvironment,
  buildWindowsCommandHelper,
  settleWindowsCommandCustody,
  windowsCommandAuditRead,
  windowsCommandCleanupSnapshot,
  openWindowsCommandWatcher,
} from "./feasibility-command-effects.js";
