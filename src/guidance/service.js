import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ConfigurationError,
  loadProjectConfiguration,
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
  openLocalDirectory,
  readDocument,
  sameFile,
  withEditCopy,
} from "./files.js";

const COMMON_PATH = fileURLToPath(
  new URL("../../docs/OPERATOR_GUIDE.md", import.meta.url),
);
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

async function guarded(operation) {
  try {
    return await operation();
  } catch (cause) {
    if (cause instanceof GuidanceError) throw cause;
    if (cause instanceof EditorError)
      throw new GuidanceError(cause.message, { cause, code: cause.code });
    const known =
      cause instanceof ConfigurationError ||
      cause instanceof GitSafetyError ||
      cause instanceof RunStoreError;
    throw new GuidanceError("Guidance operation could not complete safely.", {
      cause,
      code: known ? cause.code : "ERR_GUIDANCE_STORAGE",
    });
  }
}

export function createGuidanceService({
  git = createGitService(),
  loadConfiguration = loadRunnerConfiguration,
  runStore = createRunStore(),
  onPublicationBoundary = async () => {},
  env = process.env,
  launchEditor = defaultLaunchEditor,
  temporaryRoot = tmpdir(),
} = {}) {
  if (
    typeof git?.resolveProject !== "function" ||
    typeof git?.inspectPath !== "function" ||
    typeof loadConfiguration !== "function" ||
    typeof runStore?.withGuidanceLease !== "function" ||
    typeof onPublicationBoundary !== "function" ||
    typeof launchEditor !== "function" ||
    typeof temporaryRoot !== "string"
  ) {
    throw new GuidanceError("Guidance service options are invalid.");
  }

  async function inspectDestination(projectPath, path) {
    const inspection = await git.inspectPath({ projectPath, path });
    if (inspection.path !== path || inspection.tracked || !inspection.ignored) {
      throw new GuidanceError(
        "Local guidance and its temporary files must be ignored, untracked, and confined.",
        { code: "ERR_GUIDANCE_NOT_IGNORED" },
      );
    }
    return inspection;
  }

  async function selection(input, projectPath) {
    const configuration = await loadConfiguration();
    const projectConfiguration = await loadProjectConfiguration({
      ...(input.projectConfigurationPath === undefined
        ? {}
        : { configurationPath: input.projectConfigurationPath }),
      inspectPath: git.inspectPath,
      projectPath,
      runnerConfiguration: configuration,
    });
    const artifactRoot =
      projectConfiguration?.configuration.artifactRoot ??
      configuration.artifactRoot;
    const localPath = join(
      projectPath,
      ...artifactRoot.split("/"),
      "agent-runner",
      "rules.md",
    );
    if (
      localPath === COMMON_PATH ||
      (projectConfiguration !== null &&
        (isWithin(localPath, projectConfiguration.path) ||
          isWithin(projectConfiguration.path, localPath)))
    )
      throw unsafePath();
    await inspectDestination(projectPath, localPath);
    const directory = await openLocalDirectory(projectPath, localPath);
    try {
      await directory.verify();
    } finally {
      await directory.close();
    }
    return {
      projectPath,
      localPath,
      projectConfigurationPath: projectConfiguration?.path ?? null,
      configurationHash: contentHash(
        JSON.stringify({ configuration, projectConfiguration }),
      ),
    };
  }

  async function assertSelection(input, context) {
    const current = await selection(input, context.projectPath);
    if (
      current.localPath !== context.localPath ||
      current.configurationHash !== context.configurationHash
    ) {
      throw new GuidanceError(
        "Guidance configuration changed. The reserved destination cannot be redirected.",
        { code: "ERR_GUIDANCE_CONFIGURATION_CHANGED" },
      );
    }
  }

  async function inspect(input) {
    assertInput(input, SELECTORS);
    const projectPath = await git.resolveProject(input.projectPath);
    const resolved = await selection(input, projectPath);
    const common = await readDocument(COMMON_PATH);
    if (common.hash === null)
      throw new GuidanceError(
        "The installed common operator guide is missing.",
      );
    const directory = await openLocalDirectory(projectPath, resolved.localPath);
    try {
      const local = await directory.read();
      await assertSelection(input, resolved);
      await directory.verify();
      return {
        resolved,
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
    return guarded(async () => (await inspect(input)).guidance);
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
    { selectionSnapshot, preserveAbsence = false } = {},
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
      const projectPath = await git.resolveProject(input.projectPath);
      await runStore.validateStateBoundary({
        projectPath,
        taskPath: projectPath,
      });
      const hash = contentHash(input.localContent);
      const receiptHash = preserveAbsence ? null : hash;
      const identity = {
        key: input.idempotencyKey,
        tool: "guidance_update",
        arguments: {
          projectPath,
          projectConfigurationPath:
            input.projectConfigurationPath === undefined
              ? null
              : resolve(projectPath, input.projectConfigurationPath),
          localContentHash: hash,
          expectedHash: input.expectedHash,
          ...(preserveAbsence ? { preserveAbsence: true } : {}),
        },
      };
      const existing = await runStore.readAction(identity);
      if (existing?.status === "completed")
        return assertReceipt(existing.result, projectPath, receiptHash);
      let initial = existing?.context;
      if (initial === undefined) {
        const resolved =
          selectionSnapshot ?? (await selection(input, projectPath));
        initial = {
          projectPath,
          localPath: resolved.localPath,
          configurationHash: resolved.configurationHash,
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
      const action = await runStore.beginAction({
        ...identity,
        context: initial,
      });
      try {
        if (action.record.status === "completed")
          return assertReceipt(action.record.result, projectPath, receiptHash);
        assertContext(
          action.record.context,
          projectPath,
          receiptHash,
          input.expectedHash,
        );
        async function patch(values) {
          await action.updateContext({ ...action.record.context, ...values });
        }
        async function complete() {
          const receipt = assertReceipt(
            action.record.context.receipt,
            projectPath,
            receiptHash,
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
        return await runStore.withGuidanceLease(
          projectPath,
          async (assertOwnership) => {
            await assertSelection(input, action.record.context);
            const localPath = action.record.context.localPath;
            let directory = await openLocalDirectory(projectPath, localPath);
            try {
              let current = await directory.read();
              let context = action.record.context;
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
                  await assertSelection(input, context);
                  await assertOwnership();
                  assertSnapshot(await directory.read(), snapshot(current));
                  return published(false);
                }
                if (!directory.exists) {
                  await directory.close();
                  directory = await openLocalDirectory(projectPath, localPath, {
                    create: true,
                  });
                  const reread = await directory.read();
                  assertSnapshot(reread, snapshot(current));
                  current = reread;
                }
                const temporaryName = `.rules.${randomUUID()}.tmp`;
                await inspectDestination(
                  projectPath,
                  join(dirname(localPath), temporaryName),
                );
                await patch({
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
              await assertSelection(input, context);
              await assertOwnership();
              await inspectDestination(
                projectPath,
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
              await inspectDestination(projectPath, localPath);
              await directory.verify();
              return published(true);
            } finally {
              await directory.close();
            }
          },
        );
      } finally {
        await action.release();
      }
    });
  }

  return Object.freeze({ read, edit, update: (input) => replace(input) });
}
