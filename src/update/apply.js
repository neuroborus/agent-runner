import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { assertPublicationMetadata } from "../config/index.js";
import { resolveRuntimeRoot } from "../runtime/index.js";
import { UUID, fields, fail, receipt } from "./candidate-contract.js";
import { isVersion } from "./compatibility.js";
import { assertStoragePath } from "./storage.js";

function candidateId(official, path, version) {
  const bytes = createHash("sha256")
    .update(JSON.stringify([official, path, version]))
    .digest();
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = bytes.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const identity = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 1024 &&
  value.trim().length > 0 &&
  !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(value);

function validResult(value) {
  return (
    fields(value, [
      "schemaVersion",
      "operationId",
      "version",
      "status",
      "blockers",
      "restartRequired",
      "packageVersion",
      "runningVersion",
      "downloadedVersion",
      "installedVersion",
      "deferredVersion",
      "activeVersion",
    ]) &&
    value.schemaVersion === 1 &&
    (value.operationId === null || UUID.test(value.operationId)) &&
    ["current", "active", "deferred", "blocked"].includes(value.status) &&
    (value.status === "blocked" ||
      (UUID.test(value.operationId) && isVersion(value.version))) &&
    typeof value.restartRequired === "boolean" &&
    Array.isArray(value.blockers) &&
    value.blockers.length <= 16 &&
    value.blockers.every(
      (code) => typeof code === "string" && /^[a-z_]{1,64}$/u.test(code),
    ) &&
    (value.status === "blocked"
      ? value.blockers.length > 0
      : value.blockers.length === 0) &&
    (!["active", "deferred"].includes(value.status) ||
      (value.downloadedVersion === value.version &&
        value.installedVersion === value.version &&
        (value.status === "active"
          ? value.activeVersion === value.version &&
            value.deferredVersion === null
          : value.deferredVersion === value.version &&
            value.restartRequired))) &&
    [
      "version",
      "packageVersion",
      "runningVersion",
      "downloadedVersion",
      "installedVersion",
      "deferredVersion",
      "activeVersion",
    ].every((key) => value[key] === null || isVersion(value[key]))
  );
}

// This is an explicit operator capability. Transports supply no project, role,
// source, configuration or process authority. Actions own every effect/retry.
export function createUpdateApply({
  official,
  policy,
  select,
  readInstallation,
  getRunStore,
  storageRoot,
  prepare,
  activation,
}) {
  return async function apply(input = {}) {
    const bounded = (
      operationId,
      version,
      status,
      blockers = [],
      values = {},
    ) =>
      Object.freeze({
        ...receipt(operationId, version, status, blockers, false),
        packageVersion: null,
        runningVersion: null,
        downloadedVersion: null,
        installedVersion: null,
        deferredVersion: null,
        activeVersion: null,
        ...values,
      });
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).some(
        (key) => !["idempotencyKey", "version"].includes(key),
      ) ||
      !identity(input.idempotencyKey) ||
      (input.version !== undefined && !isVersion(input.version))
    )
      return bounded(null, null, "blocked", ["invalid_request"]);
    input = Object.freeze({ ...input });
    if (!official.approved)
      return bounded(null, input.version ?? null, "blocked", [
        "identity_unapproved",
      ]);
    let action;
    let contextValidated = false;
    try {
      const installation = await readInstallation();
      if (installation.developmentManaged)
        return bounded(null, input.version ?? null, "blocked", [
          "development_managed",
        ]);
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
      action = await store.beginAction({
        key: input.idempotencyKey,
        tool: "update_apply",
        arguments: {
          version: input.version ?? null,
          official,
          storageRoot: path,
        },
        context: {
          schemaVersion: 1,
          operationId: randomUUID(),
          activationId: randomUUID(),
          version: null,
          outcome: null,
        },
      });
      let context = action.record.context;
      if (
        !fields(context, [
          "schemaVersion",
          "operationId",
          "activationId",
          "version",
          "outcome",
        ]) ||
        context.schemaVersion !== 1 ||
        !UUID.test(context.operationId) ||
        !UUID.test(context.activationId) ||
        (context.version !== null &&
          (!isVersion(context.version) ||
            (input.version !== undefined && context.version !== input.version)))
      )
        fail("storage_unverifiable");
      contextValidated = true;
      if (
        context.outcome !== null &&
        (!validResult(context.outcome) ||
          context.outcome.operationId !== context.operationId)
      )
        fail("storage_unverifiable");
      const published =
        context.outcome !== null &&
        context.outcome.status !== "blocked" &&
        context.outcome.version === context.version;
      if (action.record.status === "completed") {
        if (
          !published ||
          !isDeepStrictEqual(context.outcome, action.record.result) ||
          action.record.result.operationId !== context.operationId ||
          action.record.result.version !== context.version
        )
          fail("storage_unverifiable");
        return action.record.result;
      }
      if (published) {
        await action.complete(context.outcome);
        return context.outcome;
      }
      const versions = {
        packageVersion: installation.installedMetadata.version,
        runningVersion: installation.runningMetadata.version,
      };
      if (!Object.values(versions).every(isVersion)) fail("release_identity");
      const publish = async (result) => {
        if (!validResult(result)) fail("storage_unverifiable");
        context = { ...context, outcome: result };
        await action.updateContext(context);
        if (result.status !== "blocked") await action.complete(result);
        return result;
      };
      if (context.version === null) {
        const { report } = await select(
          input.version === undefined ? {} : { version: input.version },
        );
        if (report.status === "blocked")
          return await publish(
            bounded(
              context.operationId,
              input.version ?? null,
              "blocked",
              report.blockers,
              versions,
            ),
          );
        context = { ...context, version: report.availableVersion };
        if (!isVersion(context.version)) fail("release_identity");
        await action.updateContext(context);
        if (report.status === "current")
          return await publish(
            bounded(context.operationId, context.version, "current", [], {
              ...versions,
              restartRequired: report.restartRequired,
            }),
          );
      }
      const prepared = await prepare({
        operationId: candidateId(official, path, context.version),
        version: context.version,
      });
      if (prepared.status !== "validated")
        return await publish(
          bounded(
            context.operationId,
            context.version,
            prepared.status,
            prepared.blockers,
            { ...versions, restartRequired: prepared.restartRequired },
          ),
        );
      const activated = await activation.activate({
        operationId: context.activationId,
        preparationId: prepared.operationId,
        version: context.version,
      });
      return await publish({
        ...activated,
        operationId: context.operationId,
        ...versions,
      });
    } catch (error) {
      const code =
        error?.code === "ERR_MCP_IDEMPOTENCY_CONFLICT"
          ? "operation_conflict"
          : error?.code === "ERR_MCP_ACTION_IN_PROGRESS"
            ? "operation_busy"
            : "update_unavailable";
      const context = action?.record.context;
      const operationId =
        typeof context?.operationId === "string" &&
        UUID.test(context.operationId)
          ? context.operationId
          : null;
      const result = bounded(
        operationId,
        contextValidated ? context.version : (input.version ?? null),
        "blocked",
        [code],
      );
      if (
        contextValidated &&
        action.record.status === "intent" &&
        !(validResult(context.outcome) && context.outcome.status !== "blocked")
      ) {
        try {
          await action.updateContext({ ...context, outcome: result });
        } catch {
          return bounded(operationId, result.version, "blocked", [
            "operation_ownership",
          ]);
        }
      }
      return result;
    } finally {
      try {
        await action?.release();
      } catch {
        return bounded(null, input.version ?? null, "blocked", [
          "operation_ownership",
        ]);
      }
    }
  };
}
