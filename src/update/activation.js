import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  assertPublicationMetadata,
  CONFIG_SCHEMA_VERSION,
} from "../config/index.js";
import {
  createRuntimeAdmission,
  inspectRuntimeCandidate,
  prepareRuntime,
  resolveRuntimeRoot,
  RUNTIME_PAYLOAD_ENV,
} from "../runtime/index.js";
import { RUNTIME_COMPATIBILITY } from "../state/index.js";
import { isVersion, releaseCompatibility } from "./compatibility.js";
import { verifyPreparedCandidate } from "./candidate.js";
import {
  UUID,
  fields,
  fail,
  preparationRequest,
  preparationContext,
  receipt,
  assertContext,
} from "./candidate-contract.js";
import { assertStoragePath } from "./storage.js";

function blocked(operationId, version, code) {
  return Object.freeze({
    ...receipt(operationId, version, "blocked", [code]),
    downloadedVersion: null,
    installedVersion: null,
    deferredVersion: null,
    activeVersion: null,
  });
}
function failureCode(error) {
  if (error?.code === "ERR_MCP_IDEMPOTENCY_CONFLICT")
    return "operation_conflict";
  if (error?.code === "ERR_MCP_ACTION_IN_PROGRESS") return "operation_busy";
  if (["EACCES", "EPERM", "EROFS"].includes(error?.code))
    return "installation_permission";
  if (typeof error?.code === "string" && error.code.startsWith("ERR_RUNTIME_"))
    return "activation_unavailable";
  return [
    "candidate_not_validated",
    "candidate_incompatible",
    "storage_unverifiable",
    "release_identity",
  ].includes(error?.code)
    ? error.code
    : "activation_unavailable";
}

export function createCandidateActivation({
  official,
  policy,
  readInstallation,
  getRunStore,
  storageRoot,
}) {
  async function environment() {
    if (!official.approved) fail("identity_unapproved");
    const installation = await readInstallation();
    if (installation.developmentManaged) fail("development_managed");
    assertPublicationMetadata(installation.runningMetadata, policy);
    assertPublicationMetadata(installation.installedMetadata, policy);
    const path = storageRoot ?? join(resolveRuntimeRoot(), "updates");
    assertStoragePath(path, installation);
    const store = getRunStore();
    await store.assertRuntimeBoundary(
      [path, installation.rootPath, installation.installationPath].filter(
        Boolean,
      ),
    );
    return { installation, path, store };
  }
  async function runtimeVersion(runtime) {
    if (runtime === null) return null;
    await prepareRuntime({
      rootPath: runtime.rootPath,
      environment: {
        [RUNTIME_PAYLOAD_ENV]: JSON.stringify({
          ...runtime,
          mode: "pinned",
          installationPath: runtime.rootPath,
        }),
      },
    });
    const version = (await inspectRuntimeCandidate(runtime.rootPath)).metadata
      .version;
    if (!isVersion(version)) fail("release_identity");
    return version;
  }
  function validOutcome(value, operationId, version) {
    return (
      fields(value, [
        "schemaVersion",
        "operationId",
        "version",
        "status",
        "blockers",
        "restartRequired",
        "downloadedVersion",
        "installedVersion",
        "deferredVersion",
        "activeVersion",
      ]) &&
      value.schemaVersion === 1 &&
      value.operationId === operationId &&
      value.version === version &&
      ["active", "deferred"].includes(value.status) &&
      Array.isArray(value.blockers) &&
      value.blockers.length === 0 &&
      typeof value.restartRequired === "boolean" &&
      value.downloadedVersion === version &&
      value.installedVersion === version &&
      value.deferredVersion ===
        (value.status === "deferred" ? version : null) &&
      isVersion(value.activeVersion) &&
      (value.status !== "active" || value.activeVersion === version)
    );
  }
  async function prepared(record, path, version, preparationId) {
    if (
      !record ||
      record.status !== "completed" ||
      !isDeepStrictEqual(
        record.result,
        receipt(preparationId, version, "validated"),
      )
    )
      fail("candidate_not_validated");
    return verifyPreparedCandidate(record.context, path, official, version);
  }
  return Object.freeze({
    async activate(input = {}) {
      if (
        !fields(input, ["operationId", "preparationId", "version"]) ||
        !UUID.test(input.operationId) ||
        !UUID.test(input.preparationId) ||
        !isVersion(input.version)
      )
        return blocked(null, null, "invalid_request");
      const { operationId, preparationId, version } = input;
      if (!official.approved)
        return blocked(operationId, version, "identity_unapproved");
      let action, preparation;
      try {
        const { installation, path, store } = await environment();
        action = await store.beginAction({
          key: `update-activate:${operationId}`,
          tool: "update_activate",
          arguments: { preparationId, version, storageRoot: path, official },
          context: {
            schemaVersion: 1,
            candidate: null,
            runtimeOperationId: randomUUID(),
            outcome: null,
          },
        });
        const context = action.record.context;
        if (
          !fields(context, [
            "schemaVersion",
            "candidate",
            "runtimeOperationId",
            "outcome",
          ]) ||
          context.schemaVersion !== 1 ||
          !UUID.test(context.runtimeOperationId)
        )
          fail("storage_unverifiable");
        // The preparation lease protects the exact completed candidate while its
        // activation intent is verified and the serialized admission effect runs.
        preparation = await store.beginAction({
          ...preparationRequest(preparationId, version, path, official),
          context: preparationContext(path),
        });
        const candidate = await prepared(
          preparation.record,
          path,
          version,
          preparationId,
        );
        const compatibility = releaseCompatibility(
          installation.runningMetadata,
          preparation.record.context.selection.metadata,
          installation.nodeVersion,
          CONFIG_SCHEMA_VERSION,
          RUNTIME_COMPATIBILITY,
        );
        if (
          !compatibility.node ||
          !compatibility.configuration ||
          !compatibility.state
        )
          fail("candidate_incompatible");
        if (
          context.candidate !== null &&
          !isDeepStrictEqual(context.candidate, candidate)
        )
          fail("storage_unverifiable");
        if (action.record.status === "completed") {
          if (
            !isDeepStrictEqual(context.outcome, action.record.result) ||
            !validOutcome(context.outcome, operationId, version)
          )
            fail("storage_unverifiable");
          return action.record.result;
        }
        if (context.candidate === null)
          await action.updateContext({ ...context, candidate });
        const outcome = await createRuntimeAdmission({
          runStore: store,
        }).activate(candidate, { id: context.runtimeOperationId });
        const result = Object.freeze({
          ...receipt(
            operationId,
            version,
            outcome.status,
            [],
            outcome.status === "deferred" ||
              installation.rootPath !== candidate.rootPath,
          ),
          downloadedVersion: version,
          installedVersion: version,
          deferredVersion: outcome.status === "deferred" ? version : null,
          activeVersion: await runtimeVersion(outcome.runtime),
        });
        await action.updateContext({
          ...action.record.context,
          outcome: result,
        });
        await action.complete(result);
        return result;
      } catch (error) {
        return blocked(
          operationId,
          version,
          ["identity_unapproved", "development_managed"].includes(error?.code)
            ? error.code
            : failureCode(error),
        );
      } finally {
        let failed = false;
        for (const held of [preparation, action]) {
          try {
            await held?.release();
          } catch {
            failed = true;
          }
        }
        if (failed) return blocked(operationId, version, "operation_ownership");
      }
    },
    async status(input = {}) {
      if (
        !fields(input, ["preparationId", "version"]) ||
        !UUID.test(input.preparationId) ||
        !isVersion(input.version)
      )
        return blocked(null, null, "invalid_request");
      const { preparationId, version } = input;
      if (!official.approved)
        return blocked(preparationId, version, "identity_unapproved");
      try {
        const { store, path, installation } = await environment();
        const record = await store.readAction(
          preparationRequest(preparationId, version, path, official),
        );
        const runtime = await store.readRuntime();
        const validated =
          record?.status === "completed" &&
          record.result.status === "validated";
        if (record) {
          assertContext(record.context, path);
          if (
            record.context.selection !== null &&
            record.context.selection.metadata?.version !== version
          )
            fail("release_identity");
        }
        if (validated) await prepared(record, path, version, preparationId);
        const current =
          record?.status === "completed" && record.result.status === "current";
        if (
          current &&
          (typeof record.result.restartRequired !== "boolean" ||
            !isDeepStrictEqual(
              record.result,
              receipt(
                preparationId,
                version,
                "current",
                [],
                record.result.restartRequired,
              ),
            ))
        )
          fail("storage_unverifiable");
        const activeVersion = await runtimeVersion(runtime.active);
        const deferredVersion = await runtimeVersion(runtime.pending);
        return Object.freeze({
          ...receipt(
            preparationId,
            version,
            validated &&
              runtime.pending?.payloadId === record.context.candidate.payloadId
              ? "deferred"
              : validated &&
                  runtime.active?.payloadId ===
                    record.context.candidate.payloadId
                ? "active"
                : validated
                  ? "validated"
                  : current
                    ? "current"
                    : record === null
                      ? "not_prepared"
                      : record.context.attempts.at(-1)?.phase === "failed"
                        ? "failed"
                        : "preparing",
            [],
            (current && record.result.restartRequired) ||
              deferredVersion !== null ||
              (runtime.active !== null &&
                runtime.active.rootPath !== installation.rootPath),
          ),
          downloadedVersion: validated
            ? version
            : (record?.context.downloadedVersion ?? null),
          installedVersion: validated
            ? version
            : (record?.context.installedVersion ?? null),
          deferredVersion,
          activeVersion,
        });
      } catch (error) {
        return blocked(
          preparationId,
          version,
          ["identity_unapproved", "development_managed"].includes(error?.code)
            ? error.code
            : failureCode(error),
        );
      }
    },
  });
}
