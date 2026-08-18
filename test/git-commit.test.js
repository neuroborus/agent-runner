import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { createGitService, GitSafetyError } from "../src/index.js";

const executeFile = promisify(execFile);
const SUBJECT = "feat(git): create authorized commit";

function isGitError(code) {
  return (error) => error instanceof GitSafetyError && error.code === code;
}

async function runGit(repositoryPath, env, ...argumentsList) {
  return executeFile("git", ["-C", repositoryPath, ...argumentsList], {
    env,
    encoding: "utf8",
  });
}

async function createFixture(t) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-commit-"));
  const repositoryPath = join(workspace, "repository");
  const configHome = join(workspace, "config");
  await mkdir(repositoryPath);
  await mkdir(configHome);
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: join(configHome, "global.gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    HOME: workspace,
    LC_ALL: "C",
    XDG_CONFIG_HOME: configHome,
  };
  for (const name of [
    "EMAIL",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_NAME",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
  ]) {
    delete env[name];
  }
  await runGit(repositoryPath, env, "init", "-q", "-b", "main");
  await runGit(repositoryPath, env, "config", "user.name", "Fixture User");
  await runGit(
    repositoryPath,
    env,
    "config",
    "user.email",
    "fixture@example.com",
  );
  await writeFile(join(repositoryPath, ".gitignore"), "ignored.txt\n");
  await writeFile(join(repositoryPath, "tracked.txt"), "initial\n");
  await runGit(repositoryPath, env, "add", ".gitignore", "tracked.txt");
  await runGit(repositoryPath, env, "commit", "-qm", "chore(test): initialize");
  let nextAuthorization = 0;
  const createService = () =>
    createGitService({
      env,
      authorizationIdFactory: () =>
        `commit-authorization-${nextAuthorization += 1}`,
    });
  t.after(() => rm(workspace, { force: true, recursive: true }));
  return { createService, env, repositoryPath };
}

async function reviewedSnapshot(fixture, content = "reviewed\n") {
  await writeFile(join(fixture.repositoryPath, "tracked.txt"), content);
  await writeFile(join(fixture.repositoryPath, "untracked.txt"), "new\n");
  return fixture.createService().snapshot({
    projectPath: fixture.repositoryPath,
  });
}

async function prepareAndConsume(fixture, expectedSnapshot, subject = SUBJECT) {
  const service = fixture.createService();
  const authorization = await service.prepareCommit({
    expectedSnapshot,
    subject,
    persistPendingCommit: async () => {},
  });
  await service.consumeCommit(authorization, {
    consumePendingCommit: async () => {},
  });
  return { authorization, service };
}

async function commitAll(fixture, subject = SUBJECT, ...extraArguments) {
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "commit",
    "-qm",
    subject,
    ...extraArguments,
  );
}

test("persists, consumes, and verifies one exact local commit", async (t) => {
  const fixture = await createFixture(t);
  const service = fixture.createService();
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const events = [];
  let persisted;
  const authorization = await service.prepareCommit({
    expectedSnapshot,
    subject: SUBJECT,
    persistPendingCommit: async (value) => {
      events.push("persist");
      persisted = JSON.parse(JSON.stringify(value));
    },
  });
  assert.equal(
    (await runGit(fixture.repositoryPath, fixture.env, "rev-parse", "HEAD"))
      .stdout.trim(),
    expectedSnapshot.head,
  );
  assert.ok(Object.isFrozen(authorization));
  assert.doesNotMatch(
    JSON.stringify(authorization),
    /Fixture User|fixture@example\.com/u,
  );

  const resumedService = fixture.createService();
  const request = await resumedService.consumeCommit(persisted, {
    consumePendingCommit: async () => events.push("consume"),
  });
  assert.deepEqual(events, ["persist", "consume"]);
  assert.deepEqual(request, {
    authorizationId: authorization.id,
    cwd: fixture.repositoryPath,
    access: "local-commit",
    commit: {
      expectedHead: expectedSnapshot.head,
      message: SUBJECT,
    },
  });
  assert.ok(Object.isFrozen(request.commit));

  await commitAll(fixture);
  const result = await resumedService.verifyCommit(persisted);
  assert.equal(result.subject, SUBJECT);
  assert.match(result.head, /^[a-f0-9]{40,64}$/u);
  assert.notEqual(result.head, expectedSnapshot.head);
  assert.ok(Object.isFrozen(result));
  await assert.rejects(
    resumedService.consumeCommit(persisted, {
      consumePendingCommit: async () => {},
    }),
    isGitError("ERR_COMMIT_AUTHORIZATION_CONSUMED"),
  );
});

test("verifies an authorized commit in detached HEAD state", async (t) => {
  const fixture = await createFixture(t);
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "checkout",
    "--detach",
    "-q",
  );
  const expectedSnapshot = await reviewedSnapshot(fixture);
  assert.equal(expectedSnapshot.branch, null);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );

  await commitAll(fixture);
  await assert.doesNotReject(service.verifyCommit(authorization));
});

test("rejects repository relocation after the authorized commit", async (t) => {
  const fixture = await createFixture(t);
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await commitAll(fixture);
  const relocatedPath = `${fixture.repositoryPath}-relocated`;
  await rename(fixture.repositoryPath, relocatedPath);
  await symlink(relocatedPath, fixture.repositoryPath, "dir");

  await assert.rejects(
    service.verifyCommit(authorization),
    (error) =>
      isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
      error.changes.includes("project-path"),
  );
});

test("validates the gate before issuing and consuming authorization", async (t) => {
  const fixture = await createFixture(t);
  const service = fixture.createService();
  const expectedSnapshot = await reviewedSnapshot(fixture);
  let persisted = false;

  await assert.rejects(
    service.prepareCommit({
      expectedSnapshot,
      subject: `${SUBJECT}\n\nbody`,
      persistPendingCommit: async () => {
        persisted = true;
      },
    }),
    isGitError("ERR_INVALID_COMMIT_AUTHORIZATION"),
  );
  await assert.rejects(
    service.prepareCommit({
      expectedSnapshot: {
        ...expectedSnapshot,
        remoteConfigurationFingerprint: "0".repeat(64),
      },
      subject: SUBJECT,
      persistPendingCommit: async () => {
        persisted = true;
      },
    }),
    (error) =>
      isGitError("ERR_COMMIT_GATE_CHANGED")(error) &&
      error.changes.includes("remote-configuration"),
  );
  assert.equal(persisted, false);

  const authorization = await service.prepareCommit({
    expectedSnapshot,
    subject: SUBJECT,
    persistPendingCommit: async () => {},
  });
  await assert.rejects(
    service.verifyCommit(authorization),
    isGitError("ERR_COMMIT_AUTHORIZATION_NOT_CONSUMED"),
  );
  await writeFile(join(fixture.repositoryPath, "tracked.txt"), "changed again\n");
  let consumed = false;
  await assert.rejects(
    service.consumeCommit(authorization, {
      consumePendingCommit: async () => {
        consumed = true;
      },
    }),
    (error) =>
      isGitError("ERR_COMMIT_GATE_CHANGED")(error) &&
      error.changes.includes("content"),
  );
  assert.equal(consumed, false);

  await writeFile(join(fixture.repositoryPath, "tracked.txt"), "reviewed\n");
  await assert.rejects(
    service.consumeCommit(authorization, {
      arguments: ["commit", "--no-verify"],
      consumePendingCommit: async () => {},
    }),
    isGitError("ERR_INVALID_COMMIT_AUTHORIZATION"),
  );
  await service.consumeCommit(authorization, {
    consumePendingCommit: async () => {},
  });
  await assert.rejects(
    service.verifyCommit(authorization),
    isGitError("ERR_COMMIT_NOT_CREATED"),
  );
});

test("does not consume authorization when durable consumption fails", async (t) => {
  const fixture = await createFixture(t);
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const service = fixture.createService();
  const authorization = await service.prepareCommit({
    expectedSnapshot,
    subject: SUBJECT,
    persistPendingCommit: async () => {},
  });
  const persistenceError = new Error("state unavailable");
  await assert.rejects(
    service.consumeCommit(authorization, {
      consumePendingCommit: async () => {
        throw persistenceError;
      },
    }),
    (error) => error === persistenceError,
  );
  await assert.doesNotReject(
    service.consumeCommit(authorization, {
      consumePendingCommit: async () => {},
    }),
  );
});

test("rejects commit bodies and co-author trailers case-insensitively", async (t) => {
  const fixture = await createFixture(t);
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await commitAll(
    fixture,
    SUBJECT,
    "-m",
    "Unexpected body.",
    "-m",
    "Co-AuThOrEd-By: Agent <agent@example.test>",
  );

  await assert.rejects(
    service.verifyCommit(authorization),
    (error) =>
      isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
      error.changes.includes("message") &&
      error.changes.includes("co-author"),
  );
});

test("rejects remote, identity, commit-identity, and unrelated ref changes", async (t) => {
  const fixture = await createFixture(t);
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "remote",
    "add",
    "origin",
    "https://example.test/repository.git",
  );
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "config",
    "user.name",
    "Changed User",
  );
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "config",
    "user.email",
    "changed@example.test",
  );
  await commitAll(fixture);
  await runGit(fixture.repositoryPath, fixture.env, "tag", "unexpected-tag");

  await assert.rejects(
    service.verifyCommit(authorization),
    (error) =>
      isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
      ["refs", "remote-configuration", "identity", "commit-identity"].every(
        (change) => error.changes.includes(change),
      ),
  );
});

test("rejects commit identity overrides without a configuration change", async (t) => {
  const fixture = await createFixture(t);
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "-c",
    "user.name=Changed User",
    "-c",
    "user.email=changed@example.test",
    "commit",
    "-qm",
    SUBJECT,
  );

  await assert.rejects(
    service.verifyCommit(authorization),
    (error) =>
      isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
      error.changes.includes("commit-identity") &&
      !error.changes.includes("identity"),
  );
});

test("rejects amended history with the wrong direct parent", async (t) => {
  const fixture = await createFixture(t);
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "commit",
    "--amend",
    "-qm",
    SUBJECT,
  );

  await assert.rejects(
    service.verifyCommit(authorization),
    (error) =>
      isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
      error.changes.includes("parent"),
  );
});

test("rejects merge commits even when their tree and message match", async (t) => {
  const fixture = await createFixture(t);
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
  const tree = (
    await runGit(fixture.repositoryPath, fixture.env, "write-tree")
  ).stdout.trim();
  const side = (
    await runGit(
      fixture.repositoryPath,
      fixture.env,
      "commit-tree",
      tree,
      "-p",
      expectedSnapshot.head,
      "-m",
      "chore(test): create side parent",
    )
  ).stdout.trim();
  const merge = (
    await runGit(
      fixture.repositoryPath,
      fixture.env,
      "commit-tree",
      tree,
      "-p",
      expectedSnapshot.head,
      "-p",
      side,
      "-m",
      SUBJECT,
    )
  ).stdout.trim();
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "update-ref",
    "refs/heads/main",
    merge,
    expectedSnapshot.head,
  );

  await assert.rejects(
    service.verifyCommit(authorization),
    (error) =>
      isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
      error.changes.includes("merge") &&
      error.changes.includes("parent"),
  );
});

test("rejects content that differs from the reviewed fingerprint", async (t) => {
  const fixture = await createFixture(t);
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await writeFile(join(fixture.repositoryPath, "tracked.txt"), "different\n");
  await commitAll(fixture);

  await assert.rejects(
    service.verifyCommit(authorization),
    (error) =>
      isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
      error.changes.includes("content"),
  );
});

test("rejects branch switches and post-commit index changes", async (t) => {
  const fixture = await createFixture(t);
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await runGit(fixture.repositoryPath, fixture.env, "switch", "-qc", "other");
  await commitAll(fixture);
  await writeFile(join(fixture.repositoryPath, "leftover.txt"), "leftover\n");
  await runGit(fixture.repositoryPath, fixture.env, "add", "leftover.txt");

  await assert.rejects(
    service.verifyCommit(authorization),
    (error) =>
      isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
      ["branch", "refs", "worktree-or-index"].every((change) =>
        error.changes.includes(change),
      ),
  );
});
