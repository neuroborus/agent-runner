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
