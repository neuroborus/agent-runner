import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { createGitService, GitSafetyError } from "../../src/git/index.js";

const executeFile = promisify(execFile);

function isGitError(code) {
  return (error) => error instanceof GitSafetyError && error.code === code;
}

async function runGit(repositoryPath, env, ...argumentsList) {
  return executeFile("git", ["-C", repositoryPath, ...argumentsList], {
    env,
    encoding: "utf8",
  });
}

async function createFixture(t, { identity = true } = {}) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-git-"));
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
  if (identity) {
    await runGit(repositoryPath, env, "config", "user.name", "Fixture User");
    await runGit(
      repositoryPath,
      env,
      "config",
      "user.email",
      "fixture@example.com",
    );
  }
  await writeFile(join(repositoryPath, ".gitignore"), "ignored.txt\n");
  await writeFile(join(repositoryPath, "tracked.txt"), "initial\n");
  await runGit(repositoryPath, env, "add", ".gitignore", "tracked.txt");
  await runGit(
    repositoryPath,
    env,
    "-c",
    "user.name=Fixture User",
    "-c",
    "user.email=fixture@example.com",
    "commit",
    "-qm",
    "initial",
  );
  t.after(() => rm(workspace, { force: true, recursive: true }));
  return {
    env,
    repositoryPath,
    service: createGitService({ env }),
    workspace,
  };
}

test("preflights clean repositories and records branch or detached state", async (t) => {
  const { env, repositoryPath, service, workspace } = await createFixture(t);
  const result = await service.preflight({
    projectPath: repositoryPath,
    requireClean: true,
    requireIdentity: true,
  });

  assert.equal(result.snapshot.clean, true);
  assert.equal(result.snapshot.branch, "refs/heads/main");
  assert.equal(result.snapshot.detached, false);
  assert.match(result.snapshot.head, /^[a-f0-9]{40,64}$/u);
  for (const fingerprint of [
    result.snapshot.contentFingerprint,
    result.snapshot.identityFingerprint,
    result.snapshot.indexFingerprint,
    result.snapshot.refsFingerprint,
    result.snapshot.remoteConfigurationFingerprint,
  ]) {
    assert.match(fingerprint, /^[a-f0-9]{64}$/u);
  }
  assert.doesNotMatch(
    JSON.stringify(result.snapshot),
    /Fixture User|fixture@example\.com/u,
  );
  assert.ok(Object.isFrozen(result.snapshot));

  await runGit(repositoryPath, env, "checkout", "--detach", "-q");
  const detached = await service.snapshot({ projectPath: repositoryPath });
  assert.equal(detached.branch, null);
  assert.equal(detached.detached, true);

  const nonWorkingTree = join(workspace, "bare.git");
  await runGit(workspace, env, "init", "--bare", "-q", nonWorkingTree);
  await assert.rejects(
    service.snapshot({ projectPath: nonWorkingTree }),
    isGitError("ERR_NOT_GIT_REPOSITORY"),
  );
  await assert.rejects(
    service.snapshot({
      allowedPaths: new Array(1),
      projectPath: repositoryPath,
    }),
    isGitError("ERR_INVALID_GIT_OPTIONS"),
  );
  await assert.rejects(
    service.assertUnchanged({
      ...result.snapshot,
      indexFingerprint: null,
    }),
    isGitError("ERR_INVALID_GIT_SNAPSHOT"),
  );
});

test("ignores ambient repository redirection", async (t) => {
  const target = await createFixture(t);
  const redirected = await createFixture(t);
  const projectPath = join(target.repositoryPath, "nested");
  await mkdir(projectPath);
  const service = createGitService({
    env: {
      ...target.env,
      GIT_CEILING_DIRECTORIES: target.repositoryPath,
      GIT_DIR: join(redirected.repositoryPath, ".git"),
      GIT_INDEX_FILE: join(redirected.repositoryPath, ".git", "index"),
      GIT_WORK_TREE: redirected.repositoryPath,
    },
  });

  const snapshot = await service.snapshot({
    projectPath,
  });
  assert.equal(snapshot.projectPath, target.repositoryPath);
  assert.equal(
    snapshot.head,
    (
      await target.service.snapshot({
        projectPath: target.repositoryPath,
      })
    ).head,
  );
});

test("enforces caller-selected cleanliness and identity requirements", async (t) => {
  const clean = await createFixture(t);
  await writeFile(join(clean.repositoryPath, "untracked.txt"), "dirty\n");
  await assert.rejects(
    clean.service.preflight({
      projectPath: clean.repositoryPath,
      requireClean: true,
    }),
    isGitError("ERR_REPOSITORY_NOT_CLEAN"),
  );
  const preserved = await clean.service.preflight({
    projectPath: clean.repositoryPath,
    requireClean: false,
  });
  assert.equal(preserved.snapshot.clean, false);

  const missingIdentity = await createFixture(t, { identity: false });
  const missingSnapshot = await missingIdentity.service.snapshot({
    projectPath: missingIdentity.repositoryPath,
  });
  assert.equal(missingSnapshot.identityAvailable, false);
  assert.match(missingSnapshot.identityFingerprint, /^[a-f0-9]{64}$/u);
  await assert.rejects(
    missingIdentity.service.preflight({
      projectPath: missingIdentity.repositoryPath,
      requireIdentity: true,
    }),
    isGitError("ERR_GIT_IDENTITY_REQUIRED"),
  );

  await runGit(
    missingIdentity.repositoryPath,
    missingIdentity.env,
    "config",
    "user.name",
    "Partial Identity",
  );
  await assert.rejects(
    missingIdentity.service.assertUnchanged(missingSnapshot),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("identity"),
  );
});

test("ignores target-repository runner configuration files", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  await writeFile(
    join(repositoryPath, ".agent-runner.json"),
    '{"schemaVersion":99}\n',
  );

  const untracked = await service.preflight({ projectPath: repositoryPath });
  assert.equal(untracked.configuration, undefined);

  await runGit(repositoryPath, env, "add", ".agent-runner.json");
  await runGit(repositoryPath, env, "commit", "-qm", "track local config");
  const tracked = await service.preflight({ projectPath: repositoryPath });
  assert.equal(tracked.snapshot.clean, true);
});

test("validates ignored repository-local artifact paths without creating them", async (t) => {
  const { env, repositoryPath, service, workspace } = await createFixture(t);
  await writeFile(join(repositoryPath, ".gitignore"), "LOCAL_ARTIFACTS/\n");
  await runGit(repositoryPath, env, "add", ".gitignore");
  await runGit(repositoryPath, env, "commit", "-qm", "ignore local artifacts");
  const clarificationPath = join(
    repositoryPath,
    "LOCAL_ARTIFACTS",
    "agent-runner",
    "run-id",
    "clarifications.md",
  );

  const accepted = await service.preflight({
    projectPath: repositoryPath,
    requiredIgnoredPaths: [clarificationPath],
  });
  assert.equal(accepted.ignoredPaths[0].exists, false);
  assert.equal(accepted.ignoredPaths[0].kind, null);
  assert.equal(accepted.ignoredPaths[0].changed, false);
  assert.equal(accepted.ignoredPaths[0].ignored, true);
  assert.equal(accepted.ignoredPaths[0].tracked, false);

  await assert.rejects(
    service.preflight({
      projectPath: repositoryPath,
      requiredIgnoredPaths: [join(repositoryPath, "visible.md")],
    }),
    isGitError("ERR_REPOSITORY_ARTIFACT_NOT_IGNORED"),
  );
  await assert.rejects(
    service.inspectPath({
      path: join(workspace, "outside.md"),
      projectPath: repositoryPath,
    }),
    isGitError("ERR_UNSAFE_REPOSITORY_PATH"),
  );

  const outsideDirectory = join(workspace, "outside");
  await mkdir(outsideDirectory);
  await symlink(outsideDirectory, join(repositoryPath, "linked"));
  await assert.rejects(
    service.inspectPath({
      path: join(repositoryPath, "linked", "artifact.md"),
      projectPath: repositoryPath,
    }),
    isGitError("ERR_UNSAFE_REPOSITORY_PATH"),
  );

  await symlink(join(workspace, "missing"), join(repositoryPath, "dangling"));
  await assert.rejects(
    service.inspectPath({
      path: join(repositoryPath, "dangling", "artifact.md"),
      projectPath: repositoryPath,
    }),
    isGitError("ERR_UNSAFE_REPOSITORY_PATH"),
  );
});

test("identifies paths that belong to a dirty worktree change set", async (t) => {
  const { repositoryPath, service } = await createFixture(t);
  const trackedPath = join(repositoryPath, "tracked.txt");
  const untrackedPath = join(repositoryPath, "untracked.txt");
  const ignoredPath = join(repositoryPath, "ignored.txt");

  await writeFile(trackedPath, "changed\n");
  await writeFile(untrackedPath, "untracked\n");
  await writeFile(ignoredPath, "ignored\n");

  const [tracked, untracked, ignored] = await Promise.all(
    [trackedPath, untrackedPath, ignoredPath].map((path) =>
      service.inspectPath({ path, projectPath: repositoryPath }),
    ),
  );

  assert.equal(tracked.tracked, true);
  assert.equal(tracked.kind, "file");
  assert.equal(tracked.changed, true);
  assert.equal(untracked.tracked, false);
  assert.equal(untracked.ignored, false);
  assert.equal(untracked.changed, true);
  assert.equal(ignored.tracked, false);
  assert.equal(ignored.ignored, true);
  assert.equal(ignored.changed, false);
});

test("content fingerprints ignore staging placement and ignored files", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const initial = await service.contentFingerprint({
    projectPath: repositoryPath,
  });

  await writeFile(join(repositoryPath, "tracked.txt"), "changed\n");
  await writeFile(join(repositoryPath, "untracked.txt"), "new\n");
  await writeFile(join(repositoryPath, "ignored.txt"), "ignored one\n");
  await symlink("tracked.txt", join(repositoryPath, "linked.txt"));
  const beforeStaging = await service.snapshot({
    projectPath: repositoryPath,
  });
  assert.notEqual(beforeStaging.contentFingerprint, initial);

  await runGit(
    repositoryPath,
    env,
    "add",
    "linked.txt",
    "tracked.txt",
    "untracked.txt",
  );
  const afterStaging = await service.snapshot({ projectPath: repositoryPath });
  assert.equal(
    afterStaging.contentFingerprint,
    beforeStaging.contentFingerprint,
  );
  assert.notEqual(
    afterStaging.indexFingerprint,
    beforeStaging.indexFingerprint,
  );

  await writeFile(join(repositoryPath, "ignored.txt"), "ignored two\n");
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    afterStaging.contentFingerprint,
  );

  await rm(join(repositoryPath, "tracked.txt"));
  const deletedBeforeStaging = await service.contentFingerprint({
    projectPath: repositoryPath,
  });
  await runGit(repositoryPath, env, "add", "-u");
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    deletedBeforeStaging,
  );
});

test("validation-infrastructure fingerprints cover only the selected files", async (t) => {
  const { repositoryPath, service } = await createFixture(t);
  const validationPath = "validation  strict.json";
  await writeFile(join(repositoryPath, validationPath), '{"strict":true}\n');
  const initial = await service.validationInfrastructureFingerprint({
    paths: [validationPath],
    projectPath: repositoryPath,
  });

  await writeFile(join(repositoryPath, "tracked.txt"), "unrelated\n");
  assert.equal(
    await service.validationInfrastructureFingerprint({
      paths: [validationPath],
      projectPath: repositoryPath,
    }),
    initial,
  );

  await writeFile(join(repositoryPath, validationPath), '{"strict":false}\n');
  assert.notEqual(
    await service.validationInfrastructureFingerprint({
      paths: [validationPath],
      projectPath: repositoryPath,
    }),
    initial,
  );
});

test("content fingerprints follow worktree content when index content diverges", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const initial = await service.contentFingerprint({
    projectPath: repositoryPath,
  });

  await writeFile(join(repositoryPath, "tracked.txt"), "staged\n");
  await runGit(repositoryPath, env, "add", "tracked.txt");
  await writeFile(join(repositoryPath, "tracked.txt"), "initial\n");
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    initial,
  );
  assert.equal(
    (await service.snapshot({ projectPath: repositoryPath })).clean,
    false,
  );
  await assert.rejects(
    service.preflight({
      projectPath: repositoryPath,
      requireClean: true,
    }),
    isGitError("ERR_REPOSITORY_NOT_CLEAN"),
  );

  await writeFile(join(repositoryPath, "new.txt"), "staged new\n");
  await runGit(repositoryPath, env, "add", "new.txt");
  await rm(join(repositoryPath, "new.txt"));
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    initial,
  );
});

test("content fingerprints ignore index-only additions without a HEAD", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  await runGit(repositoryPath, env, "checkout", "--orphan", "unborn");
  await runGit(repositoryPath, env, "rm", "-qf", "tracked.txt");
  const initial = await service.contentFingerprint({
    projectPath: repositoryPath,
  });

  const newPath = join(repositoryPath, "new.txt");
  await writeFile(newPath, "new\n");
  const beforeStaging = await service.contentFingerprint({
    projectPath: repositoryPath,
  });
  await runGit(repositoryPath, env, "add", "new.txt");
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    beforeStaging,
  );

  await rm(newPath);
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    initial,
  );
});

test("content fingerprints guard index-hidden tracked paths", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const trackedPath = join(repositoryPath, "tracked.txt");

  await runGit(
    repositoryPath,
    env,
    "update-index",
    "--assume-unchanged",
    "tracked.txt",
  );
  const assumed = await service.snapshot({ projectPath: repositoryPath });
  assert.equal(assumed.clean, true);
  await writeFile(trackedPath, "changed while assumed\n");
  assert.equal(
    (
      await service.inspectPath({
        path: trackedPath,
        projectPath: repositoryPath,
      })
    ).changed,
    true,
  );
  assert.equal(
    (await service.snapshot({ projectPath: repositoryPath })).clean,
    false,
  );
  await assert.rejects(
    service.assertUnchanged(assumed),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("tracked-content"),
  );

  await writeFile(trackedPath, "initial\n");
  await runGit(
    repositoryPath,
    env,
    "update-index",
    "--no-assume-unchanged",
    "--skip-worktree",
    "tracked.txt",
  );
  const skipped = await service.snapshot({ projectPath: repositoryPath });
  assert.equal(skipped.clean, true);
  await writeFile(trackedPath, "changed while skipped\n");
  assert.equal(
    (
      await service.inspectPath({
        path: trackedPath,
        projectPath: repositoryPath,
      })
    ).changed,
    true,
  );
  assert.equal(
    (await service.snapshot({ projectPath: repositoryPath })).clean,
    false,
  );
  await assert.rejects(
    service.assertUnchanged(skipped),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("tracked-content"),
  );
});

test("content fingerprints support tracked files replaced by directories", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const trackedPath = join(repositoryPath, "tracked.txt");
  await rm(trackedPath);
  await mkdir(trackedPath);
  await writeFile(join(trackedPath, "nested.txt"), "nested\n");
  const beforeStaging = await service.contentFingerprint({
    projectPath: repositoryPath,
  });

  await runGit(repositoryPath, env, "add", "-A");
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    beforeStaging,
  );
});

test("content fingerprints support tracked directories replaced by files", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const trackedPath = join(repositoryPath, "tracked-directory");
  await mkdir(trackedPath);
  await writeFile(join(trackedPath, "nested.txt"), "nested\n");
  await runGit(repositoryPath, env, "add", "tracked-directory");
  await runGit(repositoryPath, env, "commit", "-qm", "add directory");

  await rm(trackedPath, { recursive: true });
  await writeFile(trackedPath, "replacement\n");
  const beforeStaging = await service.contentFingerprint({
    projectPath: repositoryPath,
  });

  await runGit(repositoryPath, env, "add", "-A");
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    beforeStaging,
  );
});

test("content fingerprints do not follow replacement directory symlinks", async (t) => {
  const { env, repositoryPath, service, workspace } = await createFixture(t);
  const trackedPath = join(repositoryPath, "tracked-directory");
  await mkdir(trackedPath);
  await writeFile(join(trackedPath, "nested.txt"), "nested\n");
  await runGit(repositoryPath, env, "add", "tracked-directory");
  await runGit(repositoryPath, env, "commit", "-qm", "add directory");

  const outsidePath = join(workspace, "outside");
  await mkdir(outsidePath);
  await writeFile(join(outsidePath, "nested.txt"), "outside one\n");
  await rm(trackedPath, { recursive: true });
  await symlink(outsidePath, trackedPath);
  const beforeOutsideChange = await service.contentFingerprint({
    projectPath: repositoryPath,
  });

  await writeFile(join(outsidePath, "nested.txt"), "outside two\n");
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    beforeOutsideChange,
  );
  await runGit(repositoryPath, env, "add", "-A");
  assert.equal(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    beforeOutsideChange,
  );
});

test("content fingerprints reject a gitlink without its own worktree", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const { stdout: head } = await runGit(
    repositoryPath,
    env,
    "rev-parse",
    "HEAD",
  );
  await mkdir(join(repositoryPath, "nested"));
  await runGit(
    repositoryPath,
    env,
    "update-index",
    "--add",
    "--cacheinfo",
    "160000",
    head.trim(),
    "nested",
  );

  await assert.rejects(
    service.contentFingerprint({ projectPath: repositoryPath }),
    isGitError("ERR_UNSUPPORTED_GIT_PATH"),
  );
});

test("content fingerprints keep embedded repositories staging-independent", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const nestedPath = join(repositoryPath, "nested");
  await mkdir(nestedPath);
  await runGit(nestedPath, env, "init", "-q", "-b", "main");
  await writeFile(join(nestedPath, "nested.txt"), "nested\n");
  await runGit(nestedPath, env, "add", "nested.txt");
  await runGit(
    nestedPath,
    env,
    "-c",
    "user.name=Fixture User",
    "-c",
    "user.email=fixture@example.com",
    "commit",
    "-qm",
    "nested",
  );
  const beforeStaging = await service.contentFingerprint({
    projectPath: repositoryPath,
  });

  await runGit(repositoryPath, env, "add", "nested");
  const afterStaging = await service.contentFingerprint({
    projectPath: repositoryPath,
  });
  assert.equal(afterStaging, beforeStaging);

  await writeFile(join(nestedPath, "nested.txt"), "changed\n");
  assert.notEqual(
    await service.contentFingerprint({ projectPath: repositoryPath }),
    afterStaging,
  );

  const allowed = await service.snapshot({
    allowedPaths: [join(nestedPath, "nested.txt")],
    projectPath: repositoryPath,
  });
  await writeFile(join(nestedPath, "nested.txt"), "runner change\n");
  await assert.doesNotReject(service.assertUnchanged(allowed));
});

test("read-only guards preserve dirty baselines and constrain allowed paths", async (t) => {
  const dirty = await createFixture(t);
  await writeFile(join(dirty.repositoryPath, "tracked.txt"), "baseline\n");
  const dirtyBaseline = await dirty.service.snapshot({
    projectPath: dirty.repositoryPath,
  });
  await assert.doesNotReject(dirty.service.assertUnchanged(dirtyBaseline));
  await writeFile(join(dirty.repositoryPath, "other.txt"), "mutation\n");
  await assert.rejects(
    dirty.service.assertUnchanged(dirtyBaseline),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("untracked-content"),
  );

  const allowed = await createFixture(t);
  const allowedBaseline = await allowed.service.snapshot({
    allowedPaths: [join(allowed.repositoryPath, "tracked.txt")],
    projectPath: allowed.repositoryPath,
  });
  await writeFile(join(allowed.repositoryPath, "tracked.txt"), "runner edit\n");
  await assert.doesNotReject(allowed.service.assertUnchanged(allowedBaseline));
  await runGit(allowed.repositoryPath, allowed.env, "add", "tracked.txt");
  await assert.rejects(
    allowed.service.assertUnchanged(allowedBaseline),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("index"),
  );
});

test("reconciles interrupted writable drift without accepting Git control changes", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const baseline = await service.snapshot({ projectPath: repositoryPath });

  await writeFile(join(repositoryPath, "tracked.txt"), "interrupted work\n");
  await runGit(repositoryPath, env, "add", "tracked.txt");
  const reconciled = await service.reconcileInterrupted(baseline, {
    allowWorkspaceChanges: true,
  });
  assert.notEqual(reconciled.contentFingerprint, baseline.contentFingerprint);
  assert.notEqual(reconciled.indexFingerprint, baseline.indexFingerprint);
  await assert.rejects(
    service.reconcileInterrupted(baseline, {
      allowIndexChanges: false,
      allowWorkspaceChanges: true,
    }),
    (error) =>
      error.code === "ERR_INTERRUPTED_REPOSITORY_CONTROL_CHANGED" &&
      error.changes.includes("index"),
  );
  await assert.rejects(
    service.reconcileInterrupted(baseline, {
      allowWorkspaceChanges: false,
    }),
    (error) => error.code === "ERR_READ_ONLY_REPOSITORY_CHANGED",
  );

  await runGit(repositoryPath, env, "config", "user.name", "Changed Identity");
  await assert.rejects(
    service.reconcileInterrupted(baseline, {
      allowWorkspaceChanges: true,
    }),
    (error) => {
      assert.equal(error.code, "ERR_INTERRUPTED_REPOSITORY_CONTROL_CHANGED");
      assert.deepEqual(error.changes, ["identity"]);
      return true;
    },
  );
});

test("index fingerprints ignore stat-cache refreshes and include semantic flags", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const baseline = await service.snapshot({ projectPath: repositoryPath });
  const trackedPath = join(repositoryPath, "tracked.txt");
  const metadata = await stat(trackedPath);
  await utimes(trackedPath, metadata.atime, new Date(metadata.mtimeMs + 2_000));
  await runGit(repositoryPath, env, "status", "--short");

  await assert.doesNotReject(service.assertUnchanged(baseline));

  await runGit(
    repositoryPath,
    env,
    "update-index",
    "--skip-worktree",
    "tracked.txt",
  );
  await assert.rejects(
    service.assertUnchanged(baseline),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("index"),
  );
});

test("index fingerprints distinguish intent-to-add from staged content", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const newPath = join(repositoryPath, "new.txt");
  await writeFile(newPath, "");
  const untracked = await service.snapshot({ projectPath: repositoryPath });
  await runGit(repositoryPath, env, "add", "-N", "new.txt");
  const intended = await service.snapshot({ projectPath: repositoryPath });
  assert.equal(intended.contentFingerprint, untracked.contentFingerprint);

  await runGit(repositoryPath, env, "add", "new.txt");
  const staged = await service.snapshot({ projectPath: repositoryPath });
  assert.equal(staged.contentFingerprint, intended.contentFingerprint);
  assert.notEqual(staged.indexFingerprint, intended.indexFingerprint);
  await assert.rejects(
    service.assertUnchanged(intended),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("index"),
  );
});

test("snapshots do not modify the Git index", async (t) => {
  const { repositoryPath, service } = await createFixture(t);
  const indexPath = join(repositoryPath, ".git", "index");
  const before = await readFile(indexPath);

  await service.snapshot({ projectPath: repositoryPath });

  assert.deepEqual(await readFile(indexPath), before);
});

test("snapshots detect refs, remote configuration, and identity without exposing values", async (t) => {
  const { env, repositoryPath, service } = await createFixture(t);
  const beforeRef = await service.snapshot({ projectPath: repositoryPath });
  await runGit(repositoryPath, env, "tag", "unexpected-tag");
  await assert.rejects(
    service.assertUnchanged(beforeRef),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("refs"),
  );

  await runGit(
    repositoryPath,
    env,
    "config",
    "remote.-mirror.url",
    "https://example.com/mirror.git",
  );
  const beforeRemote = await service.snapshot({ projectPath: repositoryPath });
  const credential = "highly-secret-credential";
  await runGit(
    repositoryPath,
    env,
    "remote",
    "add",
    "origin",
    `https://user:${credential}@example.com/repository.git`,
  );
  const afterRemote = await service.snapshot({ projectPath: repositoryPath });
  assert.doesNotMatch(JSON.stringify(afterRemote), new RegExp(credential, "u"));
  await assert.rejects(
    service.assertUnchanged(beforeRemote),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("remote-configuration"),
  );

  await runGit(
    repositoryPath,
    env,
    "config",
    "extensions.worktreeConfig",
    "true",
  );
  const beforeWorktreeRemote = await service.snapshot({
    projectPath: repositoryPath,
  });
  await runGit(
    repositoryPath,
    env,
    "config",
    "--worktree",
    "remote.origin.fetch",
    "+refs/heads/main:refs/remotes/origin/main",
  );
  await assert.rejects(
    service.assertUnchanged(beforeWorktreeRemote),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("remote-configuration"),
  );

  const beforeIdentity = await service.snapshot({
    projectPath: repositoryPath,
  });
  await runGit(repositoryPath, env, "config", "user.name", "Changed Identity");
  await assert.rejects(
    service.assertUnchanged(beforeIdentity),
    (error) =>
      isGitError("ERR_READ_ONLY_REPOSITORY_CHANGED")(error) &&
      error.changes.includes("identity"),
  );
});
