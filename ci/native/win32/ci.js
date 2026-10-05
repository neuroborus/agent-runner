import {
  acquireSystemCIInputs,
  prepareSystemCI,
  loadSystemCI,
  systemPreparationBound,
} from "../system-ci.js";
import { inspectWindowsPe, systemIdentity } from "./protocol.js";
import { windowsSystemRecipes } from "./system.js";

const profile = {
  imageOS: /^win25(?:-vs2026)?$/u,
  extension: ".exe",
  sign: false,
  sources: [
    "launcher",
    "argv-fixture",
    "ownership-fixture",
    "access-fixture",
    "file-helper",
    "git-fixture",
    "git-policy",
    "policy-helper",
    "retirement",
    "observer-helper",
  ],
  environment: ["INCLUDE", "LIB", "SystemRoot", "PATH"],
  tools: [
    {
      name: "compiler",
      path: /^[A-Z]:\\Program Files\\Microsoft Visual Studio\\[0-9]{4}\\(?:Enterprise|Professional|BuildTools)\\VC\\Tools\\MSVC\\[0-9.]+\\bin\\Hostx64\\x64\\cl\.exe$/u,
      args: ["/Bv"],
      versionExitCodes: [2],
    },
    {
      name: "sdk",
      path: /^[A-Z]:\\Program Files \(x86\)\\Windows Kits\\10\\bin\\[0-9.]+\\x64\\rc\.exe$/u,
      args: ["/?"],
      versionExitCodes: [],
    },
  ],
  arguments: (source, target) => [
    "/nologo",
    "/std:c17",
    "/O2",
    "/W4",
    "/Brepro",
    source,
    `/Fo${target}.obj`,
    `/Fe${target}`,
    "/link",
    "/Brepro",
    "/INCREMENTAL:NO",
    "/DYNAMICBASE",
    "/NXCOMPAT",
    "wevtapi.lib",
  ],
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
