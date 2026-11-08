import { randomUUID } from "node:crypto";
import { link, realpath, rename } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";

import { resolveUserConfigurationPath } from "../config/index.js";
import { createGitService } from "../git/index.js";
import { getRuntimeContext, resolveRuntimeRoot } from "../runtime/index.js";
import { createRunStore } from "../state/index.js";
import {
  createWorkspaceService,
  WorkspaceSafetyError,
} from "../workspace/index.js";
import {
  assertReadInput,
  assertReportInput,
  createIssueDocument,
  decodeIssueCursor,
  encodeIssueCursor,
  IssueError,
  isDocumentHash,
  isIssueId,
  isSameIssue,
  issueFilename,
  isTimestamp,
  normalizeListInput,
  normalizeUpdateInput,
  parseIssueDocument,
  safeAbsolutePath,
  sha256,
  updateIssueDocument,
} from "./contract.js";
import { resolveIssueStorePath } from "./location.js";
import {
  openCoordination,
  openIssueStore,
  publishIssue,
  readIssueFile,
  readIssueFiles,
  replaceIssue,
} from "./store.js";

const REPORT_TOOL = "unexpected_issue_report";
const UPDATE_TOOL = "issues_update";
const INSTALLATION_PATH = fileURLToPath(new URL("../../", import.meta.url));
const LEGACY_CONTEXT_FIELDS = [
  "issuesPath",
  "projectPath",
  "publicationPhase",
  "reportPath",
  "temporaryPath",
];
const CONTEXT_FIELDS = [
  "createdAt",
  "documentHash",
  "issueId",
  "phase",
  "projectPath",
  "requestPath",
  "storeDevice",
  "storeInode",
  "storePath",
  "temporaryBirthtimeNs",
  "temporaryDevice",
  "temporaryInode",
  "temporaryName",
];
const UPDATE_CONTEXT_FIELDS = [
  "documentHash",
  "storeDevice",
  "storeInode",
  "storePath",
  "updatedAt",
];
const DEVICE_NUMBER = /^\d{1,20}$/u;
const TEMPORARY_NAME =
  /^\.[a-f0-9-]{36}\.[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\.tmp$/u;

const hasExactFields = (value, fields) =>
  Object.keys(value).sort().join() === fields.join();

const isLegacyContext = (context) =>
  hasExactFields(context, LEGACY_CONTEXT_FIELDS);

// An old intent that recorded no destination had not touched any filesystem.
const isUnstartedLegacyContext = (context) =>
  isLegacyContext(context) &&
  Object.values(context).every((value) => value === null);

function isWithin(parent, path) {
  const child = relative(parent, path);
  return (
    child === "" ||
    (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`))
  );
}

async function canonicalOrLexical(path) {
  try {
    return await realpath(path);
  } catch (cause) {
    if (cause?.code === "ENOENT") return resolve(path);
    throw cause;
  }
}

function legacyPublicationError() {
  return new IssueError(
    "A historical repository-local issue publication is incomplete; its files were left unchanged. Use a new idempotency key.",
    { code: "ERR_ISSUE_REPORT_LEGACY_PUBLICATION" },
  );
}

function storeChangedError() {
  return new IssueError(
    "The reserved issue store changed; the publication was not replayed elsewhere.",
    { code: "ERR_ISSUE_STORE_CHANGED" },
  );
}

function notFoundError() {
  return new IssueError("The issue was not found in the issue store.", {
    code: "ERR_ISSUE_NOT_FOUND",
  });
}

function staleError() {
  return new IssueError(
    "The issue revision or document hash is stale; read it again and use a new idempotency key.",
    { code: "ERR_ISSUE_REVISION_CONFLICT" },
  );
}

const isDeviceNumber = (value) =>
  typeof value === "string" && DEVICE_NUMBER.test(value);

const isBoundStore = (context, store) =>
  context.storePath === store.path &&
  context.storeDevice === store.device &&
  context.storeInode === store.inode;

function assertUpdateContext(context) {
  if (
    !hasExactFields(context, UPDATE_CONTEXT_FIELDS) ||
    safeAbsolutePath(context.storePath) !== context.storePath ||
    !isDeviceNumber(context.storeDevice) ||
    !isDeviceNumber(context.storeInode) ||
    !(
      (context.documentHash === null && context.updatedAt === null) ||
      (isDocumentHash(context.documentHash) && isTimestamp(context.updatedAt))
    )
  ) {
    throw new IssueError("Reserved issue update is invalid.", {
      code: "ERR_ISSUE_REPORT_OWNERSHIP",
    });
  }
}

// Ascending creation time, then ID, is immutable and therefore keyset-stable.
function compareKeys(left, right) {
  if (left.createdAt !== right.createdAt) {
    return left.createdAt < right.createdAt ? -1 : 1;
  }
  if (left.issueId === right.issueId) return 0;
  return left.issueId < right.issueId ? -1 : 1;
}

function temporaryIdentity({
  temporaryBirthtimeNs,
  temporaryDevice,
  temporaryInode,
}) {
  return temporaryDevice === null
    ? null
    : {
        device: temporaryDevice,
        inode: temporaryInode,
        birthtimeNs: temporaryBirthtimeNs,
      };
}

function assertBoundContext(context) {
  const bound =
    isDeviceNumber(context.temporaryDevice) &&
    isDeviceNumber(context.temporaryInode) &&
    isDeviceNumber(context.temporaryBirthtimeNs);
  if (
    !hasExactFields(context, CONTEXT_FIELDS) ||
    safeAbsolutePath(context.projectPath) !== context.projectPath ||
    safeAbsolutePath(context.requestPath) !== context.requestPath ||
    safeAbsolutePath(context.storePath) !== context.storePath ||
    !isDeviceNumber(context.storeDevice) ||
    !isDeviceNumber(context.storeInode) ||
    !(
      bound ||
      (context.temporaryDevice === null &&
        context.temporaryInode === null &&
        context.temporaryBirthtimeNs === null)
    ) ||
    (context.phase === "published" && !bound) ||
    !isIssueId(context.issueId) ||
    !TEMPORARY_NAME.test(context.temporaryName) ||
    !context.temporaryName.startsWith(`.${context.issueId}.`) ||
    !isTimestamp(context.createdAt) ||
    !isDocumentHash(context.documentHash) ||
    !["reserved", "published"].includes(context.phase)
  ) {
    throw new IssueError("Reserved issue publication is invalid.", {
      code: "ERR_ISSUE_REPORT_OWNERSHIP",
    });
  }
}

export function createIssueService({
  clock = () => new Date(),
  env = process.env,
  git = createGitService(),
  homeDirectory,
  idFactory = randomUUID,
  installationPath = getRuntimeContext()?.installationPath ?? INSTALLATION_PATH,
  linkFile = link,
  onPublished = async () => {},
  onUpdated = async () => {},
  openStore = openIssueStore,
  platform = process.platform,
  renameFile = rename,
  runStore = createRunStore(),
  workspace = createWorkspaceService(),
} = {}) {
  if (
    typeof clock !== "function" ||
    typeof git?.resolveProject !== "function" ||
    typeof idFactory !== "function" ||
    typeof linkFile !== "function" ||
    typeof onPublished !== "function" ||
    typeof onUpdated !== "function" ||
    typeof openStore !== "function" ||
    typeof renameFile !== "function" ||
    typeof workspace?.exclusionPath !== "function" ||
    typeof workspace?.inspectControls !== "function" ||
    typeof workspace?.inspectPath !== "function"
  ) {
    throw new IssueError("Issue service options are invalid.");
  }
  const location = { env, homeDirectory, platform };

  // Reports are user data: never inside or around settings, installed payloads,
  // run state, or the origin project; ordinary shared platform parents are fine.
  async function assertSeparateStore(storePath, projectPath = null) {
    await runStore.assertRuntimeBoundary([storePath]);
    const protectedPaths = [
      // Origins are already canonical and may be deleted or replaced after
      // reservation. Recovery retains that binding without inspecting them.
      ...(projectPath === null ? [] : [projectPath]),
      ...(await Promise.all(
        [
          installationPath,
          resolveRuntimeRoot(location),
          resolveUserConfigurationPath(location),
        ].map(canonicalOrLexical),
      )),
    ];
    if (
      protectedPaths.some(
        (path) => isWithin(path, storePath) || isWithin(storePath, path),
      )
    ) {
      throw new IssueError(
        "Issue storage must remain separate from projects, settings, run state, and installations.",
        { code: "ERR_UNSAFE_ISSUE_STORE" },
      );
    }
  }

  async function resolveOrigin(requestPath) {
    const boundary = await runStore.validateStateBoundary({
      projectPath: requestPath,
      taskPath: requestPath,
    });
    const { projectPath } = boundary;
    const leasePath = await workspace.exclusionPath({
      workspacePath: projectPath,
    });
    const marker = await workspace.inspectPath({
      projectPath: leasePath,
      path: ".git",
    });
    let hasGit = leasePath !== projectPath || marker.exists;
    if (!hasGit) {
      // Validate ordinary origins without traversing source content. This also
      // rejects control-tree origins and unsafe metadata, including bare Git.
      const controls = await workspace.inspectControls({
        workspacePath: projectPath,
        paths: [],
        stateRoot: runStore.rootPath,
      });
      if (controls.some((path) => isWithin(path, projectPath))) {
        throw new WorkspaceSafetyError(
          "Issue origin cannot be inside a control tree.",
        );
      }
      for (const path of controls) {
        // An incomplete enclosing .git directory is still a Git selection:
        // failed Git inspection must never become an ordinary-directory fallback.
        if (
          basename(path) === ".git" &&
          isWithin(dirname(path), projectPath) &&
          (await workspace.inspectPath({ projectPath: dirname(path), path }))
            .exists
        ) {
          hasGit = true;
          break;
        }
      }
    }
    if (!hasGit) return boundary;
    const root = await git.resolveProject(projectPath);
    return runStore.validateStateBoundary({
      projectPath: root,
      taskPath: root,
    });
  }

  function reservation(store, { projectPath, requestPath }, report) {
    const issueId = idFactory();
    const time = new Date(clock());
    if (!isIssueId(issueId) || Number.isNaN(time.valueOf())) {
      throw new IssueError(
        "Issue identity or clock returned an invalid value.",
      );
    }
    const createdAt = time.toISOString();
    const bytes = createIssueDocument({
      issueId,
      createdAt,
      projectPath,
      report,
    });
    return {
      createdAt,
      documentHash: sha256(bytes),
      issueId,
      phase: "reserved",
      projectPath,
      requestPath,
      storeDevice: store.device,
      storeInode: store.inode,
      storePath: store.path,
      temporaryBirthtimeNs: null,
      temporaryDevice: null,
      temporaryInode: null,
      temporaryName: `.${issueId}.${randomUUID()}.tmp`,
    };
  }

  async function report(input) {
    assertReportInput(input);
    const { idempotencyKey, ...argumentsWithoutKey } = input;
    const identityFor = (projectPath) => ({
      key: idempotencyKey,
      tool: REPORT_TOOL,
      arguments: { ...argumentsWithoutKey, projectPath },
    });
    const requestPath = resolve(input.projectPath);
    // Completed receipts and started intents need neither the mutable origin
    // nor configuration, so both survive deletion of the origin. The saved
    // selector maps an exact retry to its canonical arguments, which the action
    // store still verifies; other selectors use their lexical path.
    let existing = null;
    try {
      existing = await runStore.readAction({
        key: idempotencyKey,
        tool: REPORT_TOOL,
        arguments: (context) =>
          identityFor(
            context.requestPath === requestPath &&
              typeof context.projectPath === "string"
              ? context.projectPath
              : requestPath,
          ).arguments,
      });
    } catch (cause) {
      // A non-canonical selector is re-read after canonicalization.
      if (cause?.code !== "ERR_MCP_IDEMPOTENCY_CONFLICT") throw cause;
    }
    // A verified completed receipt never depends on its origin.
    if (existing?.status === "completed") {
      return existing.result;
    }
    let projectPath = requestPath;
    if (existing === null || isUnstartedLegacyContext(existing.context)) {
      ({ projectPath } = await resolveOrigin(requestPath));
      existing = await runStore.readAction(identityFor(projectPath));
    }
    if (existing?.status === "completed") {
      return existing.result;
    }
    const pending = existing?.context;
    if (pending !== undefined && isLegacyContext(pending)) {
      if (!isUnstartedLegacyContext(pending)) throw legacyPublicationError();
    } else if (pending !== undefined) {
      assertBoundContext(pending);
      ({ projectPath } = pending);
    }

    const storePath = resolveIssueStorePath(location);
    if (pending?.storePath !== undefined && pending.storePath !== storePath) {
      throw storeChangedError();
    }
    await assertSeparateStore(storePath, projectPath);
    const store = await openStore(storePath);
    try {
      const fresh = reservation(
        store,
        { projectPath, requestPath },
        argumentsWithoutKey,
      );
      const action = await runStore.beginAction({
        ...identityFor(projectPath),
        context: fresh,
      });
      try {
        if (action.record.status === "completed") {
          return action.record.result;
        }
        let context = action.record.context;
        if (isUnstartedLegacyContext(context)) {
          context = (await action.updateContext(fresh)).context;
        } else if (isLegacyContext(context)) {
          throw legacyPublicationError();
        }
        assertBoundContext(context);
        if (context.projectPath !== projectPath) {
          throw new IssueError("Reserved issue origin changed.", {
            code: "ERR_ISSUE_REPORT_OWNERSHIP",
          });
        }
        if (!isBoundStore(context, store)) {
          throw storeChangedError();
        }
        const bytes = createIssueDocument({
          issueId: context.issueId,
          createdAt: context.createdAt,
          projectPath,
          report: argumentsWithoutKey,
        });
        if (sha256(bytes) !== context.documentHash) {
          throw new IssueError("Reserved issue content changed.", {
            code: "ERR_ISSUE_REPORT_OWNERSHIP",
          });
        }
        const name = issueFilename(context.issueId);
        // The issue lease admits no update until publication is complete;
        // a later update changes only tracking, which recovery tolerates.
        return await withCoordination(store, context.issueId, async (store) => {
          await publishIssue(store, {
            name,
            temporaryName: context.temporaryName,
            temporaryIdentity: temporaryIdentity(context),
            bytes,
            phase: context.phase,
            linkFile,
            matches: (current) => isSameIssue(current, bytes, context.issueId),
            async bindTemporary({ device, inode, birthtimeNs }) {
              ({ context } = await action.updateContext({
                ...context,
                temporaryBirthtimeNs: birthtimeNs,
                temporaryDevice: device,
                temporaryInode: inode,
              }));
            },
            async markPublished() {
              ({ context } = await action.updateContext({
                ...context,
                phase: "published",
              }));
            },
          });
          const receipt = {
            issueId: context.issueId,
            issuePath: join(store.path, name),
          };
          await onPublished(receipt);
          await action.complete(receipt);
          return receipt;
        });
      } finally {
        await action.release();
      }
    } finally {
      await store.close();
    }
  }

  // Runs under the store-shared issue lease with a store view whose
  // verification also proves the bound coordination directories.
  async function withCoordination(store, issueId, operation) {
    const coordination = await openCoordination(store, issueId);
    try {
      return await runStore.withIssueLease(coordination.path, (ledger) =>
        operation(coordination.store, ledger),
      );
    } finally {
      await coordination.close();
    }
  }

  // Management never creates the store, inspects an origin, or takes a
  // worktree lease; a missing store is an empty backlog.
  async function openManagedStore() {
    const storePath = resolveIssueStorePath(location);
    await assertSeparateStore(storePath);
    return openStore(storePath, { create: false });
  }

  async function list(input) {
    const filters = normalizeListInput(input);
    const store = await openManagedStore();
    if (store === null) {
      if (filters.cursor !== null) decodeIssueCursor(filters.cursor, null);
      return { issues: [], nextCursor: null };
    }
    try {
      const binding = sha256(
        JSON.stringify([
          store.path,
          store.device,
          store.inode,
          filters.projectPath,
          filters.statuses,
        ]),
      );
      const after =
        filters.cursor === null
          ? null
          : decodeIssueCursor(filters.cursor, binding);
      const matches = (await readIssueFiles(store))
        .map(({ issueId, bytes }) => {
          const { tracking } = parseIssueDocument(bytes, issueId);
          return {
            issueId,
            createdAt: tracking.createdAt,
            documentHash: sha256(bytes),
            tracking,
          };
        })
        .filter(
          ({ tracking }) =>
            (filters.projectPath === null ||
              tracking.origin.path === filters.projectPath) &&
            (filters.statuses === null ||
              filters.statuses.includes(tracking.status)),
        )
        .filter((issue) => after === null || compareKeys(issue, after) > 0)
        .sort(compareKeys);
      const page = matches.slice(0, filters.limit);
      return {
        issues: page.map(({ issueId, documentHash, tracking }) => ({
          issueId,
          documentHash,
          tracking,
        })),
        nextCursor:
          matches.length > page.length
            ? encodeIssueCursor(binding, {
                createdAt: page.at(-1).createdAt,
                id: page.at(-1).issueId,
              })
            : null,
      };
    } finally {
      await store.close();
    }
  }

  async function read(input) {
    assertReadInput(input);
    const store = await openManagedStore();
    if (store === null) throw notFoundError();
    try {
      const file = await readIssueFile(store, input.issueId);
      if (file === null) throw notFoundError();
      const { report: issueReport, tracking } = parseIssueDocument(
        file.bytes,
        input.issueId,
      );
      return {
        issueId: input.issueId,
        issuePath: join(store.path, issueFilename(input.issueId)),
        documentHash: sha256(file.bytes),
        markdown: issueReport.markdown,
        tracking,
      };
    } finally {
      await store.close();
    }
  }

  // Compare-and-set on revision and document hash. The intent fixes the next
  // document before replacement; the ledger proves whether that revision was
  // published if newer metadata superseded it before the receipt was saved.
  async function update(input) {
    const { idempotencyKey, ...changes } = normalizeUpdateInput(input);
    const { issueId, expectedRevision, expectedHash } = changes;
    const identity = {
      key: idempotencyKey,
      tool: UPDATE_TOOL,
      arguments: changes,
    };
    const existing = await runStore.readAction(identity);
    if (existing?.status === "completed") return existing.result;
    const storePath = resolveIssueStorePath(location);
    if (existing !== null) {
      assertUpdateContext(existing.context);
      if (existing.context.storePath !== storePath) throw storeChangedError();
    }
    await assertSeparateStore(storePath);
    const store = await openStore(storePath, { create: false });
    if (store === null) {
      throw existing === null ? notFoundError() : storeChangedError();
    }
    try {
      const action = await runStore.beginAction({
        ...identity,
        context: {
          documentHash: null,
          storeDevice: store.device,
          storeInode: store.inode,
          storePath: store.path,
          updatedAt: null,
        },
      });
      try {
        if (action.record.status === "completed") {
          return action.record.result;
        }
        let { context } = action.record;
        assertUpdateContext(context);
        if (!isBoundStore(context, store)) throw storeChangedError();
        const revision = expectedRevision + 1;
        return await withCoordination(store, issueId, async (store, ledger) => {
          // A recovered replacement is made durable before its receipt.
          const complete = async (documentHash) => {
            await store.sync();
            await store.verify();
            const receipt = { issueId, revision, documentHash };
            await onUpdated(receipt);
            await action.complete(receipt);
            return receipt;
          };
          const file = await readIssueFile(store, issueId);
          if (file === null) throw notFoundError();
          const currentHash = sha256(file.bytes);
          const current = parseIssueDocument(file.bytes, issueId);
          if (
            context.documentHash !== null &&
            (currentHash === context.documentHash ||
              (current.tracking.revision > expectedRevision &&
                (await ledger.readRevision(revision)) === context.documentHash))
          ) {
            return complete(context.documentHash);
          }
          if (
            current.tracking.revision !== expectedRevision ||
            currentHash !== expectedHash
          ) {
            throw staleError();
          }
          let { updatedAt } = context;
          if (updatedAt === null) {
            const time = new Date(clock());
            if (Number.isNaN(time.valueOf())) {
              throw new IssueError("Issue clock returned an invalid value.");
            }
            // Tracking time never moves backwards.
            updatedAt = time.toISOString();
            if (updatedAt < current.tracking.updatedAt) {
              updatedAt = current.tracking.updatedAt;
            }
          }
          const bytes = updateIssueDocument(current, changes, updatedAt);
          const documentHash = sha256(bytes);
          if (context.documentHash === null) {
            ({ context } = await action.updateContext({
              ...context,
              documentHash,
              updatedAt,
            }));
          } else if (context.documentHash !== documentHash) {
            throw new IssueError("Reserved issue update changed.", {
              code: "ERR_ISSUE_REPORT_OWNERSHIP",
            });
          }
          await ledger.recordRevision(revision, documentHash);
          await replaceIssue(store, {
            name: issueFilename(issueId),
            temporaryName: `.${issueId}.${randomUUID()}.tmp`,
            backupName: `.${issueId}.${randomUUID()}.previous`,
            bytes,
            previous: file,
            renameFile,
          });
          return complete(documentHash);
        });
      } finally {
        await action.release();
      }
    } finally {
      await store.close();
    }
  }

  return Object.freeze({ list, read, report, update });
}
