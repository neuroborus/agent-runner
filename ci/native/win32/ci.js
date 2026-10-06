import path from "node:path";
import {
  acquireSystemCIInputs,
  prepareSystemCI,
  loadSystemCI,
  systemPreparationBound,
} from "../system-ci.js";
import { inspectWindowsPe, systemIdentity } from "./protocol.js";
import { windowsSystemRecipes } from "./system.js";
import {
  WINDOWS_HELPER_NAMES,
  WINDOWS_BUILD_TOOLS,
  WINDOWS_BUILD_COMMAND_MS,
  windowsCompilerArguments,
} from "./build.js";
import { normalizeWindowsPreparation } from "./preparation.js";

const profile = {
  platform: "win32",
  imageOS: /^win25(?:-vs2026)?$/u,
  extension: ".exe",
  sign: false,
  sources: WINDOWS_HELPER_NAMES,
  compileBound: WINDOWS_HELPER_NAMES.length * WINDOWS_BUILD_COMMAND_MS,
  compileCommandMs: WINDOWS_BUILD_COMMAND_MS,
  fields: ["windowsPreparation"],
  validate: (manifest) =>
    normalizeWindowsPreparation(
      manifest.windowsPreparation,
      manifest.candidateSha,
    ),
  source: (manifest, name) =>
    path.win32.join(manifest.windowsPreparation.sourceDirectory, name + ".c"),
  recoveryFromBootstrap: true,
  environment: ["INCLUDE", "LIB", "SystemRoot", "PATH"],
  tools: WINDOWS_BUILD_TOOLS,
  arguments: windowsCompilerArguments,
  inspect: inspectWindowsPe,
  inspectProcess: systemIdentity,
  api: () => import("./index.js"),
  recipes: windowsSystemRecipes,
};
export const prepareWindowsSystemCI = (job, root, output, persist, options) =>
  prepareSystemCI(job, profile, root, output, persist, options);
export const acquireWindowsSystemCI = (job, root, options) =>
  acquireSystemCIInputs(job, profile, root, options);
export const WINDOWS_SYSTEM_PREPARATION_MS = systemPreparationBound(profile);
export const loadWindowsSystemCI = (
  job,
  root,
  directory,
  receipt,
  env,
  options,
) => loadSystemCI(job, profile, root, directory, receipt, env, options);

export function windowsProviderCIContract() {
  return {
    helpers: [],
    relayPrincipal: { brokerSid: "S-1-5-18" },
    commands: [],
    validInputPath: (file) =>
      typeof file === "string" &&
      /^[A-Za-z]:\\/u.test(file) &&
      path.win32.isAbsolute(file) &&
      path.win32.normalize(file) === file &&
      !file.slice(2).includes(":"),
  };
}
