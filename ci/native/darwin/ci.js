import path from "node:path";
import {
  acquireSystemCIInputs,
  prepareSystemCI,
  loadSystemCI,
  systemPreparationBound,
} from "../system-ci.js";
import {
  inspectDarwinMachO,
  normalizeDarwinIdentity,
  requireDarwin,
} from "./protocol.js";
import { darwinSystemRecipes } from "./system.js";

const profile = {
  imageOS: /^macos15$/u,
  extension: "",
  sign: true,
  sources: [
    "launcher",
    "argv-fixture",
    "ownership-fixture",
    "access-fixture",
    "file-helper",
    "git-executor",
    "git-fixture",
    "observer-helper",
  ],
  environment: ["SDKROOT"],
  tools: [
    {
      name: "compiler",
      path: /^\/usr\/bin\/clang$/u,
      args: ["--version"],
      versionExitCodes: [],
    },
    {
      name: "sdk",
      path: /^\/usr\/bin\/xcrun$/u,
      args: ["--show-sdk-build-version"],
      versionExitCodes: [],
    },
    {
      name: "signer",
      path: /^\/usr\/bin\/codesign$/u,
      // This OS-bundled tool has no standalone version-query interface.
      // Its actual executable digest and observed OS build identify it.
      versionByDigest: true,
    },
  ],
  arguments: (source, target, env) => [
    "-std=c17",
    "-O2",
    "-Wall",
    "-Wextra",
    "-arch",
    "x86_64",
    "-isysroot",
    env.SDKROOT,
    source,
    "-o",
    target,
    "-Wl,-no_uuid",
    "-framework",
    "Security",
    "-lbsm",
  ],
  inspect: inspectDarwinMachO,
  inspectProcess: (value) => {
    const identity = normalizeDarwinIdentity(value);
    requireDarwin(
      ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
        (key) => identity[key] === 0,
      ),
    );
  },
  api: () => import("./index.js"),
  recipes: darwinSystemRecipes,
};
export const prepareDarwinSystemCI = (job, root, output, persist, options) =>
  prepareSystemCI(job, profile, root, output, persist, options);
export const acquireDarwinSystemCI = (job, root, options) =>
  acquireSystemCIInputs(job, profile, root, options);
export const DARWIN_SYSTEM_PREPARATION_MS = systemPreparationBound(profile);
export const loadDarwinSystemCI = (
  job,
  root,
  directory,
  receipt,
  env,
  options,
) => loadSystemCI(job, profile, root, directory, receipt, env, options);

export function darwinProviderCIContract() {
  return {
    helpers: [],
    relayPrincipal: { brokerUid: 0 },
    commands: [],
    validInputPath: (file) =>
      typeof file === "string" &&
      path.posix.isAbsolute(file) &&
      path.posix.normalize(file) === file,
  };
}
