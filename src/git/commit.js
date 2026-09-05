import { randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";

import { decodeUtf8, GitSafetyError, hashBuffer } from "./command.js";

const COMMIT_AUTHORIZATION_SCHEMA_VERSION = 1;
const MAX_COMMIT_SUBJECT_LENGTH = 72;
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const AUTHORIZATION_FIELDS = Object.freeze([
  "schemaVersion",
  "id",
  "projectPath",
  "expectedHead",
  "expectedBranch",
  "expectedRefsFingerprint",
  "expectedOtherRefsFingerprint",
  "expectedContentFingerprint",
  "expectedIndexFingerprint",
  "expectedRemoteConfigurationFingerprint",
  "expectedIdentityFingerprint",
  "expectedAuthorIdentityFingerprint",
  "expectedCommitterIdentityFingerprint",
  "subject",
]);

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertOptions(value, fields, name) {
  if (!isRecord(value)) {
    throw new GitSafetyError(`${name} must be an object.`, {
      code: "ERR_INVALID_COMMIT_AUTHORIZATION",
    });
  }
  const unknownField = Object.keys(value).find(
    (field) => !fields.includes(field),
  );
  if (unknownField !== undefined) {
    throw new GitSafetyError(
      `${name} field is not supported: ${unknownField}.`,
      { code: "ERR_INVALID_COMMIT_AUTHORIZATION" },
    );
  }
  return value;
}

function assertString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new GitSafetyError(`${name} must be a non-empty string.`, {
      code: "ERR_INVALID_COMMIT_AUTHORIZATION",
    });
  }
  return value;
}

function assertFingerprint(value, name) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new GitSafetyError(`${name} must be a SHA-256 fingerprint.`, {
      code: "ERR_INVALID_COMMIT_AUTHORIZATION",
    });
  }
  return value;
}

function assertSubject(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value ||
    /[\0\r\n]/u.test(value) ||
    [...value].length > MAX_COMMIT_SUBJECT_LENGTH
  ) {
    throw new GitSafetyError(
      "Commit subject must be one exact validated subject line.",
      { code: "ERR_INVALID_COMMIT_AUTHORIZATION" },
    );
  }
  return value;
}

function normalizeAuthorization(value) {
  assertOptions(value, AUTHORIZATION_FIELDS, "Commit authorization");
  if (
    value.schemaVersion !== COMMIT_AUTHORIZATION_SCHEMA_VERSION ||
    typeof value.projectPath !== "string" ||
    !isAbsolute(value.projectPath) ||
    typeof value.expectedHead !== "string" ||
    !OBJECT_ID_PATTERN.test(value.expectedHead) ||
    (value.expectedBranch !== null &&
      (typeof value.expectedBranch !== "string" ||
        value.expectedBranch.length === 0))
  ) {
    throw new GitSafetyError("Commit authorization is invalid.", {
      code: "ERR_INVALID_COMMIT_AUTHORIZATION",
    });
  }
  return Object.freeze({
    schemaVersion: COMMIT_AUTHORIZATION_SCHEMA_VERSION,
    id: assertString(value.id, "authorization.id"),
    projectPath: value.projectPath,
    expectedHead: value.expectedHead,
    expectedBranch: value.expectedBranch,
    expectedRefsFingerprint: assertFingerprint(
      value.expectedRefsFingerprint,
      "authorization.expectedRefsFingerprint",
    ),
    expectedOtherRefsFingerprint: assertFingerprint(
      value.expectedOtherRefsFingerprint,
      "authorization.expectedOtherRefsFingerprint",
    ),
    expectedContentFingerprint: assertFingerprint(
      value.expectedContentFingerprint,
      "authorization.expectedContentFingerprint",
    ),
    expectedIndexFingerprint: assertFingerprint(
      value.expectedIndexFingerprint,
      "authorization.expectedIndexFingerprint",
    ),
    expectedRemoteConfigurationFingerprint: assertFingerprint(
      value.expectedRemoteConfigurationFingerprint,
      "authorization.expectedRemoteConfigurationFingerprint",
    ),
    expectedIdentityFingerprint: assertFingerprint(
      value.expectedIdentityFingerprint,
      "authorization.expectedIdentityFingerprint",
    ),
    expectedAuthorIdentityFingerprint: assertFingerprint(
      value.expectedAuthorIdentityFingerprint,
      "authorization.expectedAuthorIdentityFingerprint",
    ),
    expectedCommitterIdentityFingerprint: assertFingerprint(
      value.expectedCommitterIdentityFingerprint,
      "authorization.expectedCommitterIdentityFingerprint",
    ),
    subject: assertSubject(value.subject),
  });
}

function sameAuthorization(left, right) {
  return AUTHORIZATION_FIELDS.every((field) => left[field] === right[field]);
}

function unique(values) {
  return [...new Set(values)];
}

function identityFingerprint(name, email) {
  return hashBuffer(Buffer.from(`${name}\0${email}`));
}

function parseIdentityHeader(line, field) {
  const match = new RegExp(
    `^${field} (.+) <([^<>]+)> -?\\d+ [+-]\\d{4}$`,
    "u",
  ).exec(line);
  if (match === null) {
    throw new GitSafetyError("Commit identity is invalid.", {
      code: "ERR_UNSUPPORTED_GIT_COMMIT",
    });
  }
  return identityFingerprint(match[1], match[2]);
}

function parseCommitObject(value) {
  const source = decodeUtf8(value, "Git commit object");
  const separator = source.indexOf("\n\n");
  if (separator === -1) {
    throw new GitSafetyError("Git commit object is invalid.", {
      code: "ERR_UNSUPPORTED_GIT_COMMIT",
    });
  }
  const headers = source.slice(0, separator).split("\n");
  const parents = headers
    .filter((line) => line.startsWith("parent "))
    .map((line) => line.slice("parent ".length));
  if (parents.some((parent) => !OBJECT_ID_PATTERN.test(parent))) {
    throw new GitSafetyError("Git commit parent is invalid.", {
      code: "ERR_UNSUPPORTED_GIT_COMMIT",
    });
  }
  const author = headers.filter((line) => line.startsWith("author "));
  const committer = headers.filter((line) => line.startsWith("committer "));
  if (author.length !== 1 || committer.length !== 1) {
    throw new GitSafetyError("Git commit identity is invalid.", {
      code: "ERR_UNSUPPORTED_GIT_COMMIT",
    });
  }
  return Object.freeze({
    parents: Object.freeze(parents),
    authorIdentityFingerprint: parseIdentityHeader(author[0], "author"),
    committerIdentityFingerprint: parseIdentityHeader(
      committer[0],
      "committer",
    ),
    message: source.slice(separator + 2),
  });
}

export function createGitCommitService({
  assertSnapshot,
  authorizationIdFactory = randomUUID,
  contentFingerprintAgainst,
  identitySnapshot,
  refsFingerprints,
  runGit,
  snapshot,
}) {
  const authorizationRecords = new Map();

  function gateChanges(authorization, current, identity, refs) {
    const changes = [];
    if (current.projectPath !== authorization.projectPath) {
      changes.push("project-path");
    }
    if (current.head !== authorization.expectedHead) {
      changes.push("head");
    }
    if (current.branch !== authorization.expectedBranch) {
      changes.push("branch");
    }
    if (
      current.refsFingerprint !== authorization.expectedRefsFingerprint ||
      refs.all !== current.refsFingerprint
    ) {
      changes.push("refs");
    }
    if (refs.excluding !== authorization.expectedOtherRefsFingerprint) {
      changes.push("refs");
    }
    if (
      current.contentFingerprint !== authorization.expectedContentFingerprint
    ) {
      changes.push("content");
    }
    if (current.indexFingerprint !== authorization.expectedIndexFingerprint) {
      changes.push("index");
    }
    if (
      current.remoteConfigurationFingerprint !==
      authorization.expectedRemoteConfigurationFingerprint
    ) {
      changes.push("remote-configuration");
    }
    if (
      current.identityFingerprint !==
        authorization.expectedIdentityFingerprint ||
      identity.identityFingerprint !==
        authorization.expectedIdentityFingerprint ||
      identity.authorIdentityFingerprint !==
        authorization.expectedAuthorIdentityFingerprint ||
      identity.committerIdentityFingerprint !==
        authorization.expectedCommitterIdentityFingerprint
    ) {
      changes.push("identity");
    }
    return Object.freeze(unique(changes));
  }

  async function inspectGate(authorization) {
    const current = await snapshot({ projectPath: authorization.projectPath });
    const [identity, refs] = await Promise.all([
      identitySnapshot(current.projectPath),
      refsFingerprints(current.projectPath, authorization.expectedBranch),
    ]);
    return Object.freeze({
      changes: gateChanges(authorization, current, identity, refs),
      current,
    });
  }

  async function prepareCommit(options) {
    assertOptions(
      options,
      ["expectedSnapshot", "subject", "persistPendingCommit"],
      "Commit preparation options",
    );
    const { expectedSnapshot, persistPendingCommit, subject } = options;
    assertSnapshot(expectedSnapshot);
    if (
      expectedSnapshot.head === null ||
      expectedSnapshot.identityAvailable !== true ||
      typeof persistPendingCommit !== "function"
    ) {
      throw new GitSafetyError("Commit preparation options are invalid.", {
        code: "ERR_INVALID_COMMIT_AUTHORIZATION",
      });
    }
    const validatedSubject = assertSubject(subject);
    const current = await snapshot({
      projectPath: expectedSnapshot.projectPath,
    });
    const [identity, refs] = await Promise.all([
      identitySnapshot(current.projectPath),
      refsFingerprints(current.projectPath, expectedSnapshot.branch),
    ]);
    const authorization = normalizeAuthorization({
      schemaVersion: COMMIT_AUTHORIZATION_SCHEMA_VERSION,
      id: authorizationIdFactory(),
      projectPath: current.projectPath,
      expectedHead: expectedSnapshot.head,
      expectedBranch: expectedSnapshot.branch,
      expectedRefsFingerprint: expectedSnapshot.refsFingerprint,
      expectedOtherRefsFingerprint: refs.excluding,
      expectedContentFingerprint: expectedSnapshot.contentFingerprint,
      expectedIndexFingerprint: expectedSnapshot.indexFingerprint,
      expectedRemoteConfigurationFingerprint:
        expectedSnapshot.remoteConfigurationFingerprint,
      expectedIdentityFingerprint: expectedSnapshot.identityFingerprint,
      expectedAuthorIdentityFingerprint: identity.authorIdentityFingerprint,
      expectedCommitterIdentityFingerprint:
        identity.committerIdentityFingerprint,
      subject: validatedSubject,
    });
    const changes = gateChanges(authorization, current, identity, refs);
    if (changes.length > 0) {
      throw new GitSafetyError(
        "Repository changed before commit authorization.",
        {
          changes,
          code: "ERR_COMMIT_GATE_CHANGED",
        },
      );
    }
    if (authorizationRecords.has(authorization.id)) {
      throw new GitSafetyError("Commit authorization ID is not unique.", {
        code: "ERR_INVALID_COMMIT_AUTHORIZATION",
      });
    }
    const record = { authorization, status: "persisting" };
    authorizationRecords.set(authorization.id, record);
    try {
      await persistPendingCommit(authorization);
      record.status = "ready";
    } catch (cause) {
      authorizationRecords.delete(authorization.id);
      throw cause;
    }
    return authorization;
  }

  async function consumeCommit(authorization, options) {
    assertOptions(
      options,
      ["consumePendingCommit"],
      "Commit consumption options",
    );
    const { consumePendingCommit } = options;
    if (typeof consumePendingCommit !== "function") {
      throw new GitSafetyError(
        "consumePendingCommit must atomically consume the authorization.",
        { code: "ERR_INVALID_COMMIT_AUTHORIZATION" },
      );
    }
    const normalized = normalizeAuthorization(authorization);
    let record = authorizationRecords.get(normalized.id);
    if (
      record !== undefined &&
      !sameAuthorization(record.authorization, normalized)
    ) {
      throw new GitSafetyError("Commit authorization does not match.", {
        code: "ERR_INVALID_COMMIT_AUTHORIZATION",
      });
    }
    if (record?.status === "consumed") {
      throw new GitSafetyError("Commit authorization was already consumed.", {
        code: "ERR_COMMIT_AUTHORIZATION_CONSUMED",
      });
    }
    if (["persisting", "consuming"].includes(record?.status)) {
      throw new GitSafetyError("Commit authorization is already in use.", {
        code: "ERR_COMMIT_AUTHORIZATION_IN_USE",
      });
    }

    const previousStatus = record?.status;
    if (record === undefined) {
      record = { authorization: normalized, status: "consuming" };
      authorizationRecords.set(normalized.id, record);
    } else {
      record.status = "consuming";
    }
    try {
      const gate = await inspectGate(normalized);
      if (gate.changes.length > 0) {
        throw new GitSafetyError(
          "Repository changed before commit authorization was consumed.",
          { changes: gate.changes, code: "ERR_COMMIT_GATE_CHANGED" },
        );
      }
      const request = Object.freeze({
        authorizationId: normalized.id,
        cwd: normalized.projectPath,
        access: "local-commit",
        commit: Object.freeze({
          expectedHead: normalized.expectedHead,
          message: normalized.subject,
        }),
      });
      await consumePendingCommit(request);
      record.status = "consumed";
      return request;
    } catch (cause) {
      if (previousStatus === undefined) {
        authorizationRecords.delete(normalized.id);
      } else {
        record.status = previousStatus;
      }
      throw cause;
    }
  }

  async function verifyCommit(authorization) {
    const normalized = normalizeAuthorization(authorization);
    const record = authorizationRecords.get(normalized.id);
    if (record !== undefined && record.status !== "consumed") {
      throw new GitSafetyError("Commit authorization was not consumed.", {
        code: "ERR_COMMIT_AUTHORIZATION_NOT_CONSUMED",
      });
    }
    const current = await snapshot({ projectPath: normalized.projectPath });
    const [identity, refs] = await Promise.all([
      identitySnapshot(current.projectPath),
      refsFingerprints(current.projectPath, normalized.expectedBranch),
    ]);
    const changes = [];
    if (current.projectPath !== normalized.projectPath) {
      changes.push("project-path");
    }
    if (current.branch !== normalized.expectedBranch) {
      changes.push("branch");
    }
    if (
      refs.all !== current.refsFingerprint ||
      refs.excluding !== normalized.expectedOtherRefsFingerprint
    ) {
      changes.push("refs");
    }
    if (
      current.remoteConfigurationFingerprint !==
      normalized.expectedRemoteConfigurationFingerprint
    ) {
      changes.push("remote-configuration");
    }
    if (
      current.identityFingerprint !== normalized.expectedIdentityFingerprint ||
      identity.identityFingerprint !== normalized.expectedIdentityFingerprint ||
      identity.authorIdentityFingerprint !==
        normalized.expectedAuthorIdentityFingerprint ||
      identity.committerIdentityFingerprint !==
        normalized.expectedCommitterIdentityFingerprint
    ) {
      changes.push("identity");
    }
    if (current.head === normalized.expectedHead) {
      if (current.refsFingerprint !== normalized.expectedRefsFingerprint) {
        changes.push("refs");
      }
      if (
        current.contentFingerprint !== normalized.expectedContentFingerprint
      ) {
        changes.push("content");
      }
      if (current.indexFingerprint !== normalized.expectedIndexFingerprint) {
        changes.push("index");
      }
      if (changes.length === 0) {
        throw new GitSafetyError("Authorized commit was not created.", {
          code: "ERR_COMMIT_NOT_CREATED",
        });
      }
    } else if (current.head !== null) {
      if (!current.clean) {
        changes.push("worktree-or-index");
      }
      const commit = parseCommitObject(
        (
          await runGit(current.projectPath, [
            "cat-file",
            "commit",
            current.head,
          ])
        ).stdout,
      );
      if (commit.parents.length > 1) {
        changes.push("merge");
      }
      if (
        commit.parents.length !== 1 ||
        commit.parents[0] !== normalized.expectedHead
      ) {
        changes.push("parent");
      }
      if (/(?:^|\n)co-authored-by[ \t]*:/iu.test(commit.message)) {
        changes.push("co-author");
      }
      if (commit.message !== `${normalized.subject}\n`) {
        changes.push("message");
      }
      if (
        commit.authorIdentityFingerprint !==
          normalized.expectedAuthorIdentityFingerprint ||
        commit.committerIdentityFingerprint !==
          normalized.expectedCommitterIdentityFingerprint
      ) {
        changes.push("commit-identity");
      }
      const committedContentFingerprint = await contentFingerprintAgainst(
        current.projectPath,
        normalized.expectedHead,
      );
      if (
        committedContentFingerprint !== normalized.expectedContentFingerprint
      ) {
        changes.push("content");
      }
    } else {
      changes.push("head");
    }

    const violations = unique(changes);
    if (violations.length > 0) {
      throw new GitSafetyError("Authorized commit violates its contract.", {
        changes: violations,
        code: "ERR_COMMIT_CONTRACT_VIOLATED",
      });
    }
    return Object.freeze({
      authorizationId: normalized.id,
      head: current.head,
      subject: normalized.subject,
      contentFingerprint: normalized.expectedContentFingerprint,
    });
  }

  return Object.freeze({ consumeCommit, prepareCommit, verifyCommit });
}
