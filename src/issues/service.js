import { randomUUID } from "node:crypto";
import { link, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveUserConfigurationPath } from "../config/index.js";
import { createGitService } from "../git/index.js";
import { getRuntimeContext, resolveRuntimeRoot } from "../runtime/index.js";
import { createRunStore } from "../state/index.js";
import {
  assertReportInput,
  createIssueDocument,
  IssueError,
  isDocumentHash,
  isIssueId,
  issueFilename,
  isTimestamp,
  safeAbsolutePath,
  sha256,
} from "./contract.js";
import { resolveIssueStorePath } from "./location.js";
import { openIssueStore, publishIssue } from "./store.js";

const REPORT_TOOL = "unexpected_issue_report";
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

const isDeviceNumber = (value) =>
  typeof value === "string" && DEVICE_NUMBER.test(value);

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
  openStore = openIssueStore,
  platform = process.platform,
  runStore = createRunStore(),
} = {}) {
  if (
    typeof clock !== "function" ||
    typeof git?.resolveProject !== "function" ||
    typeof idFactory !== "function" ||
    typeof linkFile !== "function" ||
    typeof onPublished !== "function" ||
    typeof openStore !== "function"
  ) {
    throw new IssueError("Issue service options are invalid.");
  }
  const location = { env, homeDirectory, platform };

  // Reports are user data: never inside or around settings, installed payloads,
  // run state, or the origin project; ordinary shared platform parents are fine.
  async function assertSeparateStore(storePath, projectPath) {
    await runStore.assertRuntimeBoundary([storePath]);
    const protectedPaths = await Promise.all(
      [
        projectPath,
        installationPath,
        resolveRuntimeRoot(location),
        resolveUserConfigurationPath(location),
      ].map(canonicalOrLexical),
    );
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
    // nor configuration, so both survive deletion of the checkout. The saved
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
      projectPath = await git.resolveProject(input.projectPath);
      ({ projectPath } = await runStore.validateStateBoundary({
        projectPath,
        taskPath: projectPath,
      }));
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
        if (
          context.storePath !== store.path ||
          context.storeDevice !== store.device ||
          context.storeInode !== store.inode
        ) {
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
        await publishIssue(store, {
          name,
          temporaryName: context.temporaryName,
          temporaryIdentity: temporaryIdentity(context),
          bytes,
          phase: context.phase,
          linkFile,
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
      } finally {
        await action.release();
      }
    } finally {
      await store.close();
    }
  }

  return Object.freeze({ report });
}
