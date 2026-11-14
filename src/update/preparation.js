import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, readdir } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { readProcessNamespace } from "../platform/index.js";
import {
  assertPublicationMetadata,
  CONFIG_SCHEMA_VERSION,
} from "../config/index.js";
import {
  inspectRuntimeArchive,
  inspectRuntimeCandidate,
  openRuntimeStorage,
  prepareRuntime,
  resolveRuntimeRoot,
  RUNTIME_PAYLOAD_ENV,
} from "../runtime/index.js";
import { RUNTIME_COMPATIBILITY } from "../state/index.js";
import { isVersion, releaseCompatibility } from "./compatibility.js";
import { verifyPreparedCandidate } from "./candidate.js";
import {
  MCP_PROBE,
  preparationProcessRetired,
  runCandidateCommand,
} from "./process.js";
import {
  archiveSnapshot,
  assertStoragePath,
  commandEnvironment,
  identity,
  openAttempt,
  removeSmoke,
  sameIdentity,
} from "./storage.js";

import {
  UUID,
  SRI,
  MAX_CANDIDATE_ATTEMPTS,
  fields,
  selectedMetadata,
  fail,
  receipt,
  assertContext,
  preparationContext,
  preparationRequest,
} from "./candidate-contract.js";

export function createCandidatePreparer({
  select,
  official,
  policy,
  readInstallation,
  getRunStore,
  storageRoot,
  effects = {},
}) {
  const run =
    effects.run ??
    ((command, args, options) =>
      runCandidateCommand(command, args, { ...options, spawn: effects.spawn }));
  const retired =
    effects.retired ??
    ((record) => preparationProcessRetired(record, effects.processInspection));
  return async function prepare(input = {}) {
    if (
      !fields(input, ["operationId", "version"]) ||
      !UUID.test(input.operationId) ||
      !isVersion(input.version)
    )
      return receipt(null, null, "blocked", ["invalid_request"]);
    const { operationId, version } = input;
    if (!official.approved)
      return receipt(operationId, version, "blocked", ["identity_unapproved"]);
    let action, root, directory;
    let context;
    let contextValidated = false;
    const save = async (values) => {
      context = { ...context, ...values };
      await action.updateContext(context);
    };
    const phase = async (value, values = {}) =>
      save({
        attempts: context.attempts.map((attempt, index) =>
          index === context.attempts.length - 1
            ? { ...attempt, ...values, phase: value }
            : attempt,
        ),
      });
    try {
      const installation = await readInstallation();
      if (installation.developmentManaged)
        return receipt(operationId, version, "blocked", [
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
        ...preparationRequest(operationId, version, path, official),
        context: preparationContext(path),
      });
      context = action.record.context;
      assertContext(context, path);
      contextValidated = true;
      if (context.schemaVersion === 1 && action.record.status === "intent")
        await save({
          schemaVersion: 2,
          downloadedVersion: context.candidate ? version : null,
          installedVersion: context.candidate ? version : null,
        });
      if (
        action.record.status === "completed" &&
        action.record.result.status === "current"
      ) {
        const result = action.record.result;
        const expected = receipt(
          operationId,
          version,
          "current",
          [],
          result.restartRequired,
        );
        if (
          typeof result.restartRequired !== "boolean" ||
          !isDeepStrictEqual(result, expected)
        )
          fail("storage_unverifiable");
        return expected;
      }
      if (context.process !== null) {
        if (!(await retired(context.process))) fail("process_unverifiable");
        await save({ process: null });
      }
      if (context.selection === null) {
        const selected = await select({ version });
        if (selected.report.status === "blocked")
          return receipt(
            operationId,
            version,
            "blocked",
            selected.report.blockers,
          );
        if (selected.report.status === "current") {
          const result = receipt(
            operationId,
            version,
            "current",
            [],
            selected.report.restartRequired,
          );
          await action.complete(result);
          return result;
        }
        const metadata = selected.metadata;
        const expectedTarball = `${official.registry}${official.packageName}/-/${official.packageName.split("/")[1]}-${version}.tgz`;
        if (
          !SRI.test(metadata.dist?.integrity) ||
          metadata.dist?.tarball !== expectedTarball
        )
          fail("release_identity");
        await save({
          selection: {
            metadata: selectedMetadata(metadata),
            integrity: metadata.dist.integrity,
          },
        });
      }
      if (
        !fields(context.selection, ["metadata", "integrity"]) ||
        !SRI.test(context.selection.integrity) ||
        context.selection.metadata.version !== version ||
        Buffer.byteLength(JSON.stringify(context.selection)) > 32 * 1024
      )
        fail("release_identity");
      assertPublicationMetadata(context.selection.metadata, policy);
      const compatibility = releaseCompatibility(
        installation.runningMetadata,
        context.selection.metadata,
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
      root = {
        ...(await openRuntimeStorage(path, {
          create: context.rootIdentity === null,
        })),
        path,
      };
      const actualRoot = await root.handle.stat({ bigint: true });
      if (
        context.rootIdentity !== null &&
        !sameIdentity(actualRoot, context.rootIdentity)
      )
        fail("storage_unverifiable");
      if (context.rootIdentity === null)
        await save({ rootIdentity: identity(actualRoot) });
      if (
        action.record.status === "completed" ||
        context.attempts.at(-1)?.phase === "validated"
      ) {
        await verifyPreparedCandidate(context, path, official, version);
        const result = receipt(operationId, version, "validated");
        if (action.record.status !== "completed") await action.complete(result);
        return result;
      }
      const onProcess = async (pid, proof) => {
        const registration =
          pid === null
            ? null
            : {
                pid,
                hostname: hostname(),
                processIdentity: proof.processIdentity,
                namespaceId: proof.namespaceId,
                observerNamespace: await readProcessNamespace(process.pid),
              };
        const next = { ...context, process: registration };
        assertContext(next, path);
        await save({ process: registration });
      };
      for (;;) {
        if (
          !context.attempts.length ||
          context.attempts.at(-1).phase === "failed"
        ) {
          if (context.attempts.length === MAX_CANDIDATE_ATTEMPTS)
            fail("attempts_exhausted");
          await save({
            candidate: null,
            attempts: [
              ...context.attempts,
              {
                id: randomUUID(),
                identity: null,
                phase: "allocated",
                smokeIdentity: null,
              },
            ],
          });
        }
        const attempt = context.attempts.at(-1);
        directory = await openAttempt(root, attempt);
        if (attempt.identity === null)
          await phase(attempt.phase, { identity: directory.identity });
        const environment = await commandEnvironment(directory);
        const execute = async (command, args, options = {}) => {
          await directory.verify();
          const result = await run(command, args, {
            directory,
            env: environment.env,
            onProcess,
            ...options,
          });
          await directory.verify();
          return result;
        };
        if (attempt.phase === "allocated") {
          await phase("packing");
          await execute(
            "npm",
            [
              "pack",
              `${official.packageName}@${version}`,
              "--registry",
              official.registry,
              "--json",
              "--ignore-scripts",
              "--pack-destination",
              directory.path,
            ],
            { network: true },
          );
        }
        const archives = (await readdir(directory.anchor)).filter(
          (name) =>
            /^[a-z0-9][a-z0-9._-]*\.tgz$/u.test(name) &&
            name !== "selected.tgz",
        );
        if (archives.length !== 1) {
          await phase("failed");
          await directory.close();
          directory = null;
          continue;
        }
        const archive = await inspectRuntimeArchive(
          join(directory.anchor, archives[0]),
          undefined,
          context.selection.integrity,
        );
        const metadata = JSON.parse(
          archive.entries.get("package.json").bytes.toString(),
        );
        if (
          !isDeepStrictEqual(
            selectedMetadata(metadata),
            context.selection.metadata,
          )
        )
          fail("release_identity");
        await save({ downloadedVersion: version });
        const packagePath = join(
          environment.paths.prefix,
          "lib/node_modules",
          official.packageName,
        );
        let candidate;
        if (["installing", "installed", "smoking"].includes(attempt.phase)) {
          try {
            candidate = await inspectRuntimeCandidate(packagePath);
          } catch {
            await phase("failed");
            await directory.close();
            directory = null;
            continue;
          }
        }
        if (!candidate) {
          await phase("packed");
          const snapshot = await archiveSnapshot(
            directory,
            archive.archiveBytes,
          );
          try {
            await phase("installing");
            await execute(
              "npm",
              [
                "install",
                "--global",
                "--prefix",
                environment.paths.prefix,
                "--offline",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--registry",
                official.registry,
                snapshot.path,
              ],
              { readOnly: [snapshot] },
            );
          } finally {
            await snapshot.close();
          }
          candidate = await inspectRuntimeCandidate(packagePath);
        }
        if (
          !isDeepStrictEqual(candidate.manifest, archive.manifest) ||
          !isDeepStrictEqual(
            selectedMetadata(candidate.metadata),
            context.selection.metadata,
          )
        )
          fail("release_identity");
        await save({ installedVersion: version });
        await phase("installed");
        const pinned = await prepareRuntime({
          rootPath: packagePath,
          storageRoot: join(directory.path, "runtime"),
          environment: {},
        });
        await save({ candidate: pinned });
        if (attempt.smokeIdentity !== null)
          await removeSmoke(directory, attempt.smokeIdentity);
        await mkdir(join(directory.anchor, "smoke"), { mode: 0o700 });
        let smoke, smokeIdentity, payloadHandle;
        try {
          smoke = {
            ...(await openRuntimeStorage(join(directory.path, "smoke"))),
            path: join(directory.path, "smoke"),
          };
          smokeIdentity = identity(await smoke.handle.stat({ bigint: true }));
          await phase("smoking", { smokeIdentity });
          payloadHandle = await open(
            pinned.rootPath,
            constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
          );
          const smokeEnvironment = await commandEnvironment(smoke);
          const options = {
            directory: smoke,
            env: {
              ...smokeEnvironment.env,
              [RUNTIME_PAYLOAD_ENV]: JSON.stringify(pinned),
            },
            onProcess,
            readOnly: [{ path: pinned.rootPath, handle: payloadHandle }],
          };
          const help = await run(
            pinned.nodePath,
            [pinned.executablePath, "--help"],
            options,
          );
          if (!help.stdout.includes("Agent Runner")) fail("smoke_failed");
          const mcp = await run(
            pinned.nodePath,
            ["-e", MCP_PROBE, pinned.executablePath],
            options,
          );
          if (mcp.stdout !== "MCP smoke passed\n" || mcp.stderr)
            fail("smoke_failed");
          await prepareRuntime({
            rootPath: pinned.rootPath,
            environment: { [RUNTIME_PAYLOAD_ENV]: JSON.stringify(pinned) },
          });
        } finally {
          try {
            await payloadHandle?.close();
          } finally {
            await smoke?.close();
            if (smokeIdentity && context.process === null) {
              await removeSmoke(directory, smokeIdentity);
              await phase("installed", { smokeIdentity: null });
            }
          }
        }
        await root.verify();
        await directory.verify();
        await phase("validated");
        const result = receipt(operationId, version, "validated");
        await action.complete(result);
        return result;
      }
    } catch (error) {
      try {
        if (
          contextValidated &&
          action?.record.status === "intent" &&
          context?.attempts.length &&
          context.process === null &&
          context.attempts.at(-1).phase !== "validated"
        )
          await phase("failed");
      } catch {
        return receipt(operationId, version, "blocked", [
          "operation_ownership",
        ]);
      }
      const code =
        error?.code === "ERR_MCP_IDEMPOTENCY_CONFLICT"
          ? "operation_conflict"
          : error?.code === "ERR_MCP_ACTION_IN_PROGRESS"
            ? "operation_busy"
            : ["EACCES", "EPERM", "EROFS"].includes(error?.code)
              ? "installation_permission"
              : [
                    "release_identity",
                    "candidate_incompatible",
                    "storage_unverifiable",
                    "process_unverifiable",
                    "attempts_exhausted",
                    "smoke_failed",
                  ].includes(error?.code)
                ? error.code
                : "preparation_failed";
      return receipt(operationId, version, "blocked", [code]);
    } finally {
      let failed = false;
      for (const resource of [directory, root, action]) {
        try {
          if (resource?.close) await resource.close();
          else await resource?.release();
        } catch {
          failed = true;
        }
      }
      if (failed)
        return receipt(operationId, version, "blocked", [
          "operation_ownership",
        ]);
    }
  };
}
