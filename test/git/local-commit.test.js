import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  rename,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  createGitService,
  GitSafetyError,
  isolateGitEnvironment,
} from "../../src/git/index.js";
import { createFixtureGitBinary } from "../support/git.js";

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
  t.after(() => rm(workspace, { force: true, recursive: true }));
  const gitBinary = await createFixtureGitBinary(workspace);
  let nextAuthorization = 0;
  const createService = (serviceEnv = env) =>
    createGitService({
      env: serviceEnv,
      gitBinary,
      authorizationIdFactory: () =>
        `commit-authorization-${(nextAuthorization += 1)}`,
    });
  return { createService, env, gitBinary, repositoryPath };
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
    (
      await runGit(fixture.repositoryPath, fixture.env, "rev-parse", "HEAD")
    ).stdout.trim(),
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
  await writeFile(
    join(fixture.repositoryPath, "tracked.txt"),
    "changed again\n",
  );
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
  await assert.rejects(service.verifyCommit(authorization), (error) => {
    assert.ok(isGitError("ERR_COMMIT_NOT_CREATED")(error));
    assert.deepEqual(error.changes, []);
    return true;
  });
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

test("retains exact full staging after hygiene or hook refusal without a commit", async (t) => {
  for (const failure of ["hygiene", "hook"]) {
    await t.test(failure, async (t) => {
      const fixture = await createFixture(t);
      const expectedSnapshot = await reviewedSnapshot(
        fixture,
        failure === "hygiene" ? "reviewed  \n" : "reviewed\n",
      );
      if (failure === "hook") {
        await writeFile(
          join(fixture.repositoryPath, ".git", "hooks", "pre-commit"),
          "#!/bin/sh\nexit 1\n",
          { mode: 0o755 },
        );
      }
      const { authorization, service } = await prepareAndConsume(
        fixture,
        expectedSnapshot,
      );
      await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
      await assert.rejects(
        runGit(
          fixture.repositoryPath,
          fixture.env,
          ...(failure === "hygiene"
            ? ["diff", "--cached", "--check"]
            : ["commit", "-qm", SUBJECT]),
        ),
      );
      const staged = await service.snapshot({
        projectPath: fixture.repositoryPath,
      });
      assert.equal(staged.head, expectedSnapshot.head);
      assert.notEqual(
        staged.indexFingerprint,
        expectedSnapshot.indexFingerprint,
      );
      for (const verifier of [service, fixture.createService()]) {
        await assert.rejects(verifier.verifyCommit(authorization), (error) => {
          assert.ok(isGitError("ERR_COMMIT_NOT_CREATED")(error));
          assert.deepEqual(error.changes, ["index"]);
          return true;
        });
      }
      assert.deepEqual(
        await service.snapshot({ projectPath: fixture.repositoryPath }),
        staged,
      );
      await assert.rejects(
        service.consumeCommit(authorization, {
          consumePendingCommit: async () => assert.fail("must not replay"),
        }),
        isGitError("ERR_COMMIT_AUTHORIZATION_CONSUMED"),
      );
    });
  }
});

test("recognizes full staging of deletions, executable files and leaf links", async (t) => {
  const fixture = await createFixture(t);
  await rm(join(fixture.repositoryPath, "tracked.txt"));
  await writeFile(join(fixture.repositoryPath, "script.sh"), "exit 0\n", {
    mode: 0o755,
  });
  await symlink("script.sh", join(fixture.repositoryPath, "link"));
  const expectedSnapshot = await fixture
    .createService()
    .snapshot({ projectPath: fixture.repositoryPath });
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
  await assert.rejects(
    service.verifyCommit(authorization),
    (error) =>
      isGitError("ERR_COMMIT_NOT_CREATED")(error) &&
      error.changes.includes("index"),
  );
});

test("recognizes full staging with split-index bookkeeping", async (t) => {
  const fixture = await createFixture(t);
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "config",
    "splitIndex.maxPercentChange",
    "100",
  );
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "update-index",
    "--split-index",
  );
  const expectedSnapshot = await reviewedSnapshot(fixture);
  const { authorization, service } = await prepareAndConsume(
    fixture,
    expectedSnapshot,
  );
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
  await assert.rejects(service.verifyCommit(authorization), (error) => {
    assert.ok(isGitError("ERR_COMMIT_NOT_CREATED")(error));
    assert.deepEqual(error.changes, ["index"]);
    return true;
  });
});

test("rejects incomplete, mismatched and semantic index effects without a commit", async (t) => {
  for (const effect of [
    "incomplete",
    "blob",
    "mode",
    "ignored",
    "assume-unchanged",
    "skip-worktree",
    "intent-to-add",
    "resolve-undo",
  ]) {
    await t.test(effect, async (t) => {
      const fixture = await createFixture(t);
      const expectedSnapshot = await reviewedSnapshot(fixture);
      const { authorization, service } = await prepareAndConsume(
        fixture,
        expectedSnapshot,
      );
      await runGit(
        fixture.repositoryPath,
        fixture.env,
        "add",
        ...(effect === "incomplete" ? ["tracked.txt"] : ["-A"]),
      );
      if (effect === "blob") {
        await writeFile(
          join(fixture.repositoryPath, "tracked.txt"),
          "different\n",
        );
        await runGit(fixture.repositoryPath, fixture.env, "add", "tracked.txt");
        await writeFile(
          join(fixture.repositoryPath, "tracked.txt"),
          "reviewed\n",
        );
      } else if (effect === "mode") {
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "update-index",
          "--chmod=+x",
          "tracked.txt",
        );
      } else if (effect === "ignored") {
        await writeFile(join(fixture.repositoryPath, "ignored.txt"), "extra\n");
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "add",
          "-f",
          "ignored.txt",
        );
      } else if (["assume-unchanged", "skip-worktree"].includes(effect)) {
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "update-index",
          `--${effect}`,
          "tracked.txt",
        );
      } else if (effect === "intent-to-add") {
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "reset",
          "-q",
          "HEAD",
          "--",
          "untracked.txt",
        );
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "add",
          "-N",
          "untracked.txt",
        );
      } else if (effect === "resolve-undo") {
        const blob = (
          await runGit(
            fixture.repositoryPath,
            fixture.env,
            "rev-parse",
            "HEAD:tracked.txt",
          )
        ).stdout.trim();
        const updating = executeFile(
          "git",
          ["-C", fixture.repositoryPath, "update-index", "--index-info"],
          {
            env: fixture.env,
          },
        );
        updating.child.stdin.end(
          `0 ${blob}\ttracked.txt\n` +
            [1, 2, 3]
              .map((stage) => `100644 ${blob} ${stage}\ttracked.txt\n`)
              .join(""),
        );
        await updating;
        // Resolve a controlled conflict; Git retains its semantic undo record.
        await runGit(fixture.repositoryPath, fixture.env, "add", "tracked.txt");
      }
      await assert.rejects(
        service.verifyCommit(authorization),
        (error) =>
          isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
          error.changes.includes("index"),
      );
    });
  }
});

test("rejects content and control drift after staging without a commit", async (t) => {
  for (const effect of [
    "content",
    "branch",
    "refs",
    "remote-configuration",
    "identity",
  ]) {
    await t.test(effect, async (t) => {
      const fixture = await createFixture(t);
      const expectedSnapshot = await reviewedSnapshot(fixture);
      const { authorization, service } = await prepareAndConsume(
        fixture,
        expectedSnapshot,
      );
      await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
      if (effect === "content") {
        await writeFile(join(fixture.repositoryPath, "tracked.txt"), "drift\n");
      } else if (effect === "branch") {
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "symbolic-ref",
          "HEAD",
          "refs/heads/other",
        );
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "update-ref",
          "refs/heads/other",
          expectedSnapshot.head,
        );
      } else if (effect === "refs") {
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "update-ref",
          "refs/heads/other",
          expectedSnapshot.head,
        );
      } else if (effect === "remote-configuration") {
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "remote",
          "add",
          "origin",
          "https://example.test/repository.git",
        );
      } else {
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "config",
          "user.name",
          "Changed User",
        );
      }
      await assert.rejects(
        service.verifyCommit(authorization),
        (error) =>
          isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
          error.changes.includes(effect),
      );
    });
  }
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

test("binds commit identity to the isolated executor environment", async (t) => {
  for (const isolated of [true, false]) {
    const fixture = await createFixture(t);
    const ambientEnv = {
      ...fixture.env,
      EMAIL: "ambient@example.test",
      GIT_AUTHOR_EMAIL: "ambient-author@example.test",
      GIT_AUTHOR_NAME: "Ambient Author",
      GIT_COMMITTER_EMAIL: "ambient-committer@example.test",
      GIT_COMMITTER_NAME: "Ambient Committer",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "user.name",
      GIT_CONFIG_VALUE_0: "Counted User",
    };
    const service = fixture.createService(ambientEnv);
    await writeFile(join(fixture.repositoryPath, "tracked.txt"), "reviewed\n");
    const expectedSnapshot = await service.snapshot({
      projectPath: fixture.repositoryPath,
    });
    const authorization = await service.prepareCommit({
      expectedSnapshot,
      subject: SUBJECT,
      persistPendingCommit: async () => {},
    });
    await service.consumeCommit(authorization, {
      consumePendingCommit: async () => {},
    });
    const commitEnv = isolated ? isolateGitEnvironment(ambientEnv) : ambientEnv;
    await executeFile(
      fixture.gitBinary,
      [
        "-C",
        fixture.repositoryPath,
        "-c",
        "commit.gpgSign=false",
        "commit",
        "-qam",
        SUBJECT,
      ],
      { env: commitEnv },
    );

    if (isolated) {
      await service.verifyCommit(authorization);
      const { stdout } = await runGit(
        fixture.repositoryPath,
        fixture.env,
        "show",
        "--no-patch",
        "--format=%an <%ae>%n%cn <%ce>",
        "HEAD",
      );
      assert.equal(
        stdout,
        "Fixture User <fixture@example.com>\nFixture User <fixture@example.com>\n",
      );
    } else {
      await assert.rejects(
        service.verifyCommit(authorization),
        (error) =>
          isGitError("ERR_COMMIT_CONTRACT_VIOLATED")(error) &&
          error.changes.includes("commit-identity") &&
          !error.changes.includes("identity"),
      );
    }
  }
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

test("retains converted full staging in original and reconstructed commit verifiers", async (t) => {
  const fixture = await createFixture(t);
  const { repositoryPath, env } = fixture;
  await writeFile(
    join(repositoryPath, ".gitattributes"),
    "converted.txt text eol=crlf\n",
  );
  await writeFile(join(repositoryPath, "converted.txt"), "before\r\n");
  await runGit(repositoryPath, env, "add", "-A");
  await runGit(repositoryPath, env, "commit", "-qm", "configure text fixture");
  await writeFile(join(repositoryPath, "converted.txt"), "after\r\n");
  const baseline = await fixture
    .createService()
    .snapshot({ projectPath: repositoryPath });
  const { authorization, service } = await prepareAndConsume(fixture, baseline);
  await runGit(repositoryPath, env, "add", "-A");
  const staged = await service.snapshot({ projectPath: repositoryPath });
  assert.equal(
    (await runGit(repositoryPath, env, "show", ":converted.txt")).stdout,
    "after\n",
  );
  for (const verifier of [service, fixture.createService()]) {
    await assert.rejects(verifier.verifyCommit(authorization), (error) => {
      assert.equal(error.code, "ERR_COMMIT_NOT_CREATED");
      assert.deepEqual(error.changes, ["index"]);
      return true;
    });
  }
  assert.deepEqual(
    await service.snapshot({ projectPath: repositoryPath }),
    staged,
  );
  await assert.rejects(
    service.consumeCommit(authorization, {
      consumePendingCommit: async () => assert.fail("must not replay"),
    }),
    { code: "ERR_COMMIT_AUTHORIZATION_CONSUMED" },
  );
});

test("rejects same-size wrong blobs with clean cached stat during consumed verification", async (t) => {
  const fixture = await createFixture(t);
  const { repositoryPath, env } = fixture;
  await writeFile(
    join(repositoryPath, ".gitattributes"),
    "tracked.txt text eol=crlf\n",
  );
  await runGit(repositoryPath, env, "add", "-A");
  await runGit(repositoryPath, env, "commit", "-qm", "configure text fixture");
  await runGit(repositoryPath, env, "config", "core.trustctime", "false");
  await writeFile(join(repositoryPath, "tracked.txt"), "correct\r\n");
  await utimes(join(repositoryPath, "tracked.txt"), 946684800, 946684800);
  const baseline = await fixture
    .createService()
    .snapshot({ projectPath: repositoryPath });
  const { service, authorization } = await prepareAndConsume(fixture, baseline);
  await writeFile(join(repositoryPath, "tracked.txt"), "mistake\r\n");
  await utimes(join(repositoryPath, "tracked.txt"), 946684800, 946684800);
  await runGit(repositoryPath, env, "add", "-A");
  await writeFile(join(repositoryPath, "tracked.txt"), "correct\r\n");
  await utimes(join(repositoryPath, "tracked.txt"), 946684800, 946684800);
  assert.equal(
    (await runGit(repositoryPath, env, "diff", "--name-only")).stdout,
    "",
  );
  for (const verifier of [service, fixture.createService()])
    await assert.rejects(verifier.verifyCommit(authorization), {
      code: "ERR_COMMIT_CONTRACT_VIOLATED",
    });
});
