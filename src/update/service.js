import {
  assertPublicationMetadata,
  CONFIG_SCHEMA_VERSION,
  OFFICIAL_RELEASE_POLICY,
  resolveOfficialReleaseIdentity,
} from "../config/index.js";
import { inspectRuntimeInstallation } from "../runtime/index.js";
import { createRunStore, RUNTIME_COMPATIBILITY } from "../state/index.js";

import {
  compareVersions,
  isStableVersion,
  isVersion,
  releaseCompatibility,
} from "./compatibility.js";
import { readRegistryRelease } from "./registry.js";
import { createCandidatePreparer } from "./preparation.js";
import { createCandidateActivation } from "./activation.js";

// Only trusted root composition supplies effects. Requests select an exact
// version, never an identity, URL, project configuration or update permission.
export function createUpdateService({
  policy = OFFICIAL_RELEASE_POLICY,
  readInstallation = inspectRuntimeInstallation,
  fetch: fetchImpl = globalThis.fetch,
  runStore,
  storageRoot,
  effects,
} = {}) {
  const frozenPolicy = Object.freeze({ ...policy });
  const official = resolveOfficialReleaseIdentity(frozenPolicy);
  let store = runStore;
  const getRunStore = () => (store ??= createRunStore());
  async function select(request = {}) {
    let installation;
    let available;
    const result = {
      schemaVersion: 1,
      status: "blocked",
      official,
      installedVersion: null,
      runningVersion: null,
      stableVersion: null,
      availableVersion: null,
      channel: "stable",
      developmentManaged: false,
      restartRequired: false,
      compatibility: Object.freeze({
        scope: "runtime-contract",
        node: null,
        configuration: null,
        state: null,
      }),
      blockers: [],
      automatic: false,
    };
    const finish = () =>
      Object.freeze({
        report: Object.freeze({
          ...result,
          blockers: Object.freeze([...result.blockers]),
        }),
        installation,
        metadata: available,
      });
    if (
      !request ||
      typeof request !== "object" ||
      Array.isArray(request) ||
      Object.keys(request).some((key) => key !== "version") ||
      (request.version !== undefined && !isVersion(request.version))
    ) {
      result.blockers.push("invalid_request");
      return finish();
    }
    const selected = request.version ?? null;
    result.channel = selected === null ? "stable" : "explicit";
    try {
      installation = await readInstallation();
      if (
        !isVersion(installation.installedMetadata?.version) ||
        !isVersion(installation.runningMetadata?.version) ||
        typeof installation.developmentManaged !== "boolean" ||
        typeof installation.canWriteInstallation !== "boolean"
      )
        throw new Error("Invalid installation.");
      result.installedVersion = installation.installedMetadata.version;
      result.runningVersion = installation.runningMetadata.version;
      result.developmentManaged = installation.developmentManaged;
      result.restartRequired =
        installation.restartRequired === true ||
        result.installedVersion !== result.runningVersion;
    } catch (error) {
      result.blockers.push(
        ["EACCES", "EPERM"].includes(error?.code)
          ? "installation_permission"
          : "installation_unavailable",
      );
    }
    if (!official.approved) result.blockers.push("identity_unapproved");
    if (result.developmentManaged) result.blockers.push("development_managed");
    if (result.blockers.length) return finish();
    try {
      assertPublicationMetadata(installation.runningMetadata, frozenPolicy);
      assertPublicationMetadata(installation.installedMetadata, frozenPolicy);
    } catch {
      result.blockers.push("installation_identity");
      return finish();
    }
    try {
      const stable = await readRegistryRelease(official, "latest", fetchImpl);
      assertPublicationMetadata(stable, frozenPolicy);
      if (!isStableVersion(stable.version))
        throw new Error("Stable channel is invalid.");
      result.stableVersion = stable.version;
      available =
        selected === null || selected === stable.version
          ? stable
          : await readRegistryRelease(official, selected, fetchImpl);
      assertPublicationMetadata(available, frozenPolicy);
      if (
        !isVersion(available.version) ||
        (selected !== null && available.version !== selected)
      )
        throw new Error("Selected release differs.");
    } catch (error) {
      result.blockers.push(
        ["release_unavailable", "registry_permission"].includes(error?.code)
          ? error.code
          : "registry_unavailable",
      );
      return finish();
    }
    result.availableVersion = available.version;
    const newer =
      compareVersions(available.version, result.installedVersion) > 0;
    try {
      result.compatibility = releaseCompatibility(
        installation.runningMetadata,
        available,
        installation.nodeVersion,
        CONFIG_SCHEMA_VERSION,
        RUNTIME_COMPATIBILITY,
      );
    } catch {
      if (newer) {
        result.blockers.push("compatibility_unknown");
        return finish();
      }
    }
    if (!newer) {
      result.status = "current";
      return finish();
    }
    if (!installation.canWriteInstallation)
      result.blockers.push("installation_not_writable");
    if (!result.compatibility.node) result.blockers.push("node_incompatible");
    if (!result.compatibility.configuration)
      result.blockers.push("configuration_incompatible");
    if (!result.compatibility.state) result.blockers.push("state_incompatible");
    if (result.blockers.length === 0) result.status = "available";
    result.restartRequired = true;
    return finish();
  }
  const prepare = createCandidatePreparer({
    select,
    official,
    policy: frozenPolicy,
    readInstallation,
    getRunStore,
    storageRoot,
    effects,
  });
  const activation = createCandidateActivation({
    official,
    policy: frozenPolicy,
    readInstallation,
    getRunStore,
    storageRoot,
  });
  return Object.freeze({
    check: async (request) => (await select(request)).report,
    prepare,
    activate: activation.activate,
    status: activation.status,
  });
}
