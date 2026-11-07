import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ConfigurationError,
  loadRunnerConfiguration,
} from "../config/index.js";
import { createGitService, GitSafetyError } from "../git/index.js";
import {
  defaultLaunchEditor,
  EditorError,
  openConfiguredEditor,
} from "../editor.js";
import { createRunStore, RunStoreError } from "../state/index.js";
import {
  createWorkspaceService,
  WorkspaceSafetyError,
} from "../workspace/index.js";

import {
  contentHash,
  GuidanceError,
  renderGuidance,
  unsafePath,
  validateContent,
} from "./content.js";
import {
  assertContext,
  assertInput,
  assertReceipt,
  HASH,
  isWithin,
  SELECTORS,
  UPDATE_FIELDS,
} from "./contract.js";
import {
  DirectoryVerificationError,
  openLocalDirectory,
  readDocument,
  sameFile,
  withEditCopy,
} from "./files.js";
import {
  createGuidanceSelection,
  resolveConfigurationPath,
} from "./selection.js";

const COMMON_PATH = fileURLToPath(
  new URL("../../docs/OPERATOR_GUIDE.md", import.meta.url),
);
const RETRYABLE_READ_IO = ["EACCES", "EPERM", "EMFILE", "ENFILE", "ENOMEM"];

function stale() {
  return new GuidanceError(
    "Local guidance changed. Read the complete current guide before replacing it.",
    { code: "ERR_GUIDANCE_STALE" },
  );
}

function snapshot(document) {
  return { hash: document.hash, identity: document.identity };
}

function assertSnapshot(document, before) {
  if (
    document.hash !== before.hash ||
    !sameFile(document.identity, before.identity)
  )
    throw stale();
}

function normalizeFailure(cause) {
  if (cause instanceof GuidanceError) return cause;
  if (cause instanceof EditorError)
    return new GuidanceError(cause.message, { cause, code: cause.code });
  if (cause instanceof WorkspaceSafetyError) return unsafePath(cause);
  const known =
    cause instanceof ConfigurationError ||
    cause instanceof GitSafetyError ||
    cause instanceof RunStoreError;
  return new GuidanceError("Guidance operation could not complete safely.", {
    cause,
    code: known ? cause.code : "ERR_GUIDANCE_STORAGE",
  });
}

function readFailure(cause) {
  // Selection and file helpers own this control/path wrapper. Do not search
  // recovery/storage causes for a transient error that might permit retry.
  const wrappedPath =
    cause instanceof GuidanceError && cause.code === "ERR_UNSAFE_GUIDANCE_PATH";
  const origin = wrappedPath ? cause.cause : cause;
  let native = origin?.cause;
  if (origin instanceof DirectoryVerificationError) {
    native = origin.cause;
  } else if (origin instanceof WorkspaceSafetyError) {
    switch (origin.code) {
      case "ERR_WORKSPACE_PATH":
        return "unsafe_path";
      case "ERR_WORKSPACE_DRIFT":
      case "ERR_WORKSPACE_SNAPSHOT_RACE":
        return "workspace_changed";
      case "ERR_WORKSPACE_PROOF_CAPACITY":
        return "evidence_capacity";
      case "ERR_WORKSPACE_INSPECTION":
        break;
      default:
        return null;
    }
  } else if (
    origin instanceof ConfigurationError &&
    origin.code === "ERR_PROJECT_CONFIGURATION_READ"
  ) {
    if (origin.constraint === "file_size") return "evidence_capacity";
    if (origin.constraint === "isolated_regular_file") return "unsafe_path";
    if (origin.constraint === "missing_file") return "workspace_changed";
  } else if (wrappedPath && origin instanceof Error) {
    native = origin;
  } else return null;
  if (native?.code === "ENOENT") return "workspace_changed";
  return RETRYABLE_READ_IO.includes(native?.code)
    ? "inspection_unavailable"
    : null;
}

async function guarded(operation, { readOnly = false } = {}) {
  try {
    return await operation();
  } catch (cause) {
    const failure = normalizeFailure(cause);
    const classification = readOnly ? readFailure(cause) : null;
    if (classification !== null) failure.readFailure = classification;
    throw failure;
  }
}

export function createGuidanceService({
  git = createGitService(),
  workspace = createWorkspaceService(),
  loadConfiguration = loadRunnerConfiguration,
  runStore = createRunStore(),
  onPublicationBoundary = async () => {},
  env = process.env,
  launchEditor = defaultLaunchEditor,
  temporaryRoot = tmpdir(),
} = {}) {
  if (
    typeof workspace?.exclusionPath !== "function" ||
    typeof workspace?.inspectPath !== "function" ||
    typeof workspace?.inspectControls !== "function" ||
    typeof git?.inspectPath !== "function" ||
    typeof loadConfiguration !== "function" ||
    typeof runStore?.withGuidanceLease !== "function" ||
    typeof onPublicationBoundary !== "function" ||
    typeof launchEditor !== "function" ||
    typeof temporaryRoot !== "string"
  ) {
    throw new GuidanceError("Guidance service options are invalid.");
  }

  const { target, selection, assertSelection, inspectDestination } =
    createGuidanceSelection({
      git,
      workspace,
      loadConfiguration,
      commonPath: COMMON_PATH,
      stateRoot: runStore.rootPath,
    });

  async function inspect(input, { allowAbsent = false } = {}) {
    assertInput(input, SELECTORS);
    const resolved = await selection(input, input.projectPath, {
      allowAbsent,
    });
    const { projectPath } = resolved;
    const common = await readDocument(COMMON_PATH);
    if (common.hash === null)
      throw new GuidanceError(
        "The installed common operator guide is missing.",
      );
    const directory = await openLocalDirectory(
      resolved.basePath,
      resolved.localPath,
      { ancestors: resolved.binding.ancestors },
    );
    try {
      const local = await directory.read();
      // Only an absent read may skip ignore validation. If content appeared
      // during selection, require ignore validation even if it disappears again.
      await assertSelection(input, resolved, {
        allowAbsent: allowAbsent && local.hash === null,
      });
      await directory.verify();
      return {
        resolved,
        localIdentity: local.identity,
        guidance: Object.freeze({
          projectPath,
          localPath: resolved.localPath,
          projectConfigurationPath: resolved.projectConfigurationPath,
          commonContent: common.content,
          localContent: local.content,
          localHash: local.hash,
          combinedContent: renderGuidance(common.content, local.content),
        }),
      };
    } finally {
      await directory.close();
    }
  }

  async function read(input) {
    return guarded(
      async () => (await inspect(input, { allowAbsent: true })).guidance,
      { readOnly: true },
    );
  }

  async function withPublicationLease(context, operation) {
    const leasePath = context.binding?.leasePath ?? context.projectPath;
    const basePath = context.binding?.basePath ?? context.projectPath;
    return runStore.withGuidanceLease(leasePath, async (assertTarget) => {
      if (isWithin(leasePath, basePath)) return operation(assertTarget);
      // Different targets may select overlapping external infrastructure. Its
      // lease excludes those publishers as well as execution in that tree.
      return runStore.withGuidanceLease(basePath, async (assertDestination) =>
        operation(async () => {
          await assertTarget();
          await assertDestination();
        }),
      );
    });
  }

  async function edit(input) {
    return guarded(async () => {
      const { resolved, guidance } = await inspect(input);
      return withEditCopy(
        resolved.projectPath,
        guidance.localContent,
        temporaryRoot,
        async (path, readEdited) => {
          const outcome = await openConfiguredEditor(path, {
            env,
            launchEditor,
          });
          if (outcome === null)
            throw new GuidanceError(
              "Set VISUAL or EDITOR to a launchable editor.",
              { code: "ERR_EDITOR_UNAVAILABLE" },
            );
          if (outcome.exitCode !== 0 || outcome.signal !== null)
            throw new GuidanceError(
              "The guidance editor did not exit successfully. Local guidance was not changed.",
              { code: "ERR_GUIDANCE_EDITOR_FAILED" },
            );
          const localContent = await readEdited();
          return replace(
            {
              ...input,
              localContent,
              expectedHash: guidance.localHash,
              idempotencyKey: randomUUID(),
            },
            {
              selectionSnapshot: resolved,
              preserveAbsence:
                guidance.localHash === null &&
                localContent === guidance.localContent,
            },
          );
        },
      );
    });
  }

  async function replace(
    input,
    {
      selectionSnapshot,
      preserveAbsence = false,
      assertLease,
      expectedIdentity,
    } = {},
  ) {
    return guarded(async () => {
      assertInput(input, UPDATE_FIELDS);
      validateContent(input.localContent);
      if (
        input.expectedHash !== null &&
        (typeof input.expectedHash !== "string" ||
          !HASH.test(input.expectedHash))
      )
        throw new GuidanceError(
          "Expected local hash must be null or a SHA-256 hash.",
        );
      const targetSelection = await target(input.projectPath);
      let projectPath = targetSelection.projectPath;
      await runStore.validateStateBoundary({
        projectPath,
        taskPath: projectPath,
      });
      const hash = contentHash(input.localContent);
      const receiptHash = preserveAbsence ? null : hash;
      const identityFor = (
        path,
        configurationPath = resolveConfigurationPath(input, path),
      ) => ({
        key: input.idempotencyKey,
        tool: "guidance_update",
        arguments: {
          projectPath: path,
          projectConfigurationPath: configurationPath ?? null,
          localContentHash: hash,
          expectedHash: input.expectedHash,
          ...(preserveAbsence ? { preserveAbsence: true } : {}),
        },
      });
      let identity = identityFor(projectPath);
      let existing = null;
      let conflict;
      const candidates = [identity];
      if (
        input.projectConfigurationPath !== undefined &&
        resolve(input.projectPath) !== projectPath
      )
        candidates.push(identityFor(resolve(input.projectPath)));
      const legacyIdentity =
        input.projectConfigurationPath === undefined
          ? null
          : identityFor(
              projectPath,
              resolve(projectPath, input.projectConfigurationPath),
            );
      if (legacyIdentity !== null) candidates.push(legacyIdentity);
      // Locate an exact prior intent before reading mutable configuration. Both
      // worktree and explicitly directory-bound receipts preserve their target.
      // Binding-free legacy actions resolved every selector from the worktree.
      for (const candidateIdentity of candidates) {
        try {
          const record = await runStore.readAction(candidateIdentity);
          if (
            record !== null &&
            (candidateIdentity !== legacyIdentity ||
              record.context.binding === undefined)
          ) {
            existing = record;
            identity = candidateIdentity;
            projectPath = candidateIdentity.arguments.projectPath;
            break;
          }
        } catch (cause) {
          if (cause.code !== "ERR_MCP_IDEMPOTENCY_CONFLICT") throw cause;
          conflict ??= cause;
        }
      }
      if (existing === null && conflict !== undefined) throw conflict;
      if (existing?.status === "completed") {
        assertContext(
          existing.context,
          projectPath,
          receiptHash,
          input.expectedHash,
        );
        return assertReceipt(
          existing.result,
          projectPath,
          receiptHash,
          existing.context.localPath,
        );
      }
      let initial = existing?.context;
      if (initial === undefined) {
        const resolved =
          selectionSnapshot ?? (await selection(input, input.projectPath));
        projectPath = resolved.projectPath;
        identity = identityFor(projectPath);
        initial = {
          projectPath,
          localPath: resolved.localPath,
          configurationHash: resolved.configurationHash,
          binding: resolved.binding,
          phase: "reserved",
          before: null,
          temporaryName: null,
          temporaryIdentity: null,
          receipt: null,
        };
      }
      assertContext(initial, projectPath, receiptHash, input.expectedHash);
      await runStore.validateStateBoundary({
        projectPath,
        taskPath: projectPath,
      });
      if (initial.binding !== undefined && initial.phase !== "published") {
        await runStore.validateStateBoundary({
          projectPath: initial.binding.basePath,
          taskPath: initial.binding.leasePath,
        });
      }
      const action = await runStore.beginAction({
        ...identity,
        context: initial,
      });
      // Rechecks use the matched action's exact selector, including legacy paths.
      const publicationInput = {
        ...input,
        projectConfigurationPath:
          identity.arguments.projectConfigurationPath ?? undefined,
      };
      try {
        assertContext(
          action.record.context,
          projectPath,
          receiptHash,
          input.expectedHash,
        );
        if (action.record.status === "completed")
          return assertReceipt(
            action.record.result,
            projectPath,
            receiptHash,
            action.record.context.localPath,
          );
        async function patch(values) {
          await action.updateContext({ ...action.record.context, ...values });
        }
        async function complete() {
          const receipt = assertReceipt(
            action.record.context.receipt,
            projectPath,
            receiptHash,
            action.record.context.localPath,
          );
          await action.complete(receipt);
          await onPublicationBoundary("receipted");
          return receipt;
        }
        async function published(updated) {
          const receipt = {
            projectPath,
            localPath: action.record.context.localPath,
            localHash: receiptHash,
            updated,
          };
          await patch({ phase: "published", receipt });
          await onPublicationBoundary("published");
          return complete();
        }
        // A durable published record already proves the effect. Completing its
        // receipt must not depend on mutable configuration or subsequent edits.
        if (action.record.context.phase === "published")
          return await complete();
        return await (
          assertLease === undefined
            ? withPublicationLease
            : async (_context, operation) => {
                await assertLease();
                return operation(assertLease);
              }
        )(action.record.context, async (assertOwnership) => {
          let resolved = await assertSelection(
            publicationInput,
            action.record.context,
          );
          const localPath = action.record.context.localPath;
          let directory = await openLocalDirectory(
            resolved.basePath,
            localPath,
            { ancestors: resolved.binding.ancestors },
          );
          try {
            let current = await directory.read();
            let context = action.record.context;
            if (
              context.phase === "reserved" &&
              expectedIdentity !== undefined &&
              !sameFile(current.identity, expectedIdentity)
            )
              throw stale();
            if (context.phase === "prepared") {
              const temporary = await directory.read(context.temporaryName);
              if (temporary.hash === null) {
                if (
                  current.hash !== hash ||
                  !sameFile(current.identity, context.temporaryIdentity, {
                    renamed: true,
                  })
                ) {
                  throw new GuidanceError(
                    "Interrupted guidance publication cannot be attributed safely.",
                    { code: "ERR_GUIDANCE_RECOVERY" },
                  );
                }
                return published(true);
              }
              if (
                temporary.hash !== hash ||
                !sameFile(temporary.identity, context.temporaryIdentity)
              )
                throw unsafePath();
              assertSnapshot(current, context.before);
            } else {
              if (context.phase === "writing") {
                assertSnapshot(current, context.before);
                await directory.removeTemporary(
                  context.temporaryName,
                  context.temporaryIdentity,
                );
                await patch({
                  phase: "reserved",
                  before: null,
                  temporaryName: null,
                  temporaryIdentity: null,
                });
              }
              if (current.hash !== input.expectedHash) throw stale();
              if (
                current.hash === hash ||
                (preserveAbsence && current.hash === null)
              ) {
                await onPublicationBoundary("before-publish");
                await assertSelection(publicationInput, context);
                await assertOwnership();
                assertSnapshot(await directory.read(), snapshot(current));
                return published(false);
              }
              if (!directory.exists) {
                await directory.close();
                directory = await openLocalDirectory(
                  resolved.basePath,
                  localPath,
                  { create: true, ancestors: resolved.binding.ancestors },
                );
                const reread = await directory.read();
                assertSnapshot(reread, snapshot(current));
                current = reread;
              }
              const temporaryName = `.rules.${randomUUID()}.tmp`;
              await inspectDestination(
                resolved,
                join(dirname(localPath), temporaryName),
              );
              resolved = await assertSelection(publicationInput, context);
              await patch({
                ...(context.binding === undefined
                  ? {}
                  : { binding: resolved.binding }),
                phase: "reserved",
                before: snapshot(current),
                temporaryName,
                temporaryIdentity: null,
              });
              await onPublicationBoundary("reserved");
              await assertOwnership();
              const temporary = await directory.writeTemporary(
                temporaryName,
                input.localContent,
                async (temporaryIdentity) => {
                  await patch({ phase: "writing", temporaryIdentity });
                  await onPublicationBoundary("writing");
                },
              );
              await patch({
                phase: "prepared",
                temporaryIdentity: temporary.identity,
              });
              await onPublicationBoundary("prepared");
            }
            context = action.record.context;
            await onPublicationBoundary("before-publish");
            await assertSelection(publicationInput, context);
            await assertOwnership();
            await inspectDestination(
              resolved,
              join(dirname(localPath), context.temporaryName),
            );
            const temporary = await directory.read(context.temporaryName);
            if (
              temporary.hash !== hash ||
              !sameFile(temporary.identity, context.temporaryIdentity)
            )
              throw unsafePath();
            assertSnapshot(await directory.read(), context.before);
            await directory.publish(context.temporaryName);
            await onPublicationBoundary("renamed");
            const result = await directory.read();
            if (
              result.hash !== hash ||
              !sameFile(result.identity, context.temporaryIdentity, {
                renamed: true,
              })
            )
              throw unsafePath();
            await inspectDestination(resolved, localPath);
            await directory.verify();
            return published(true);
          } finally {
            await directory.close();
          }
        });
      } finally {
        await action.release();
      }
    });
  }

  return Object.freeze({
    read,
    edit,
    update: (input) => replace(input),
    readWithIdentity: (input) =>
      guarded(
        async () => {
          const { guidance, localIdentity } = await inspect(input, {
            allowAbsent: true,
          });
          return { ...guidance, localIdentity };
        },
        { readOnly: true },
      ),
    updateUnderLease: (input, assertLease, expectedIdentity) => {
      if (typeof assertLease !== "function")
        throw new GuidanceError("A held publication lease is required.");
      return replace(input, { assertLease, expectedIdentity });
    },
  });
}
