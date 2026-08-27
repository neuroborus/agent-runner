import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { createGitService, GitSafetyError } from "../src/index.js";

const executeFile = promisify(execFile);

async function runGit(repositoryPath, env, ...argumentsList) {
  return executeFile("git", ["-C", repositoryPath, ...argumentsList], {
    env,
    encoding: "utf8",
  });
}

async function createFixture(t) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-handoff-"));
  const repositoryPath = join(workspace, "repository");
  const configHome = join(workspace, "config");
  await mkdir(repositoryPath);
  await mkdir(configHome);
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: join(configHome, "global.gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
    LC_ALL: "C",
    XDG_CONFIG_HOME: configHome,
  };
  for (const name of Object.keys(env)) {
    if (name === "EMAIL" || name.startsWith("GIT_")) {
      delete env[name];
    }
  }
  env.GIT_CONFIG_GLOBAL = join(configHome, "global.gitconfig");
  env.GIT_CONFIG_NOSYSTEM = "1";
  await runGit(repositoryPath, env, "init", "-q", "-b", "main");
  await runGit(repositoryPath, env, "config", "user.name", "Handoff Test");
  await runGit(
    repositoryPath,
    env,
    "config",
    "user.email",
    "handoff@example.test",
  );
  await writeFile(join(repositoryPath, ".gitignore"), "ignored.txt\n");
  await writeFile(join(repositoryPath, "deleted.txt"), "delete me\n");
  await writeFile(join(repositoryPath, "tracked.txt"), "base\n");
  await runGit(repositoryPath, env, "add", "-A");
  await runGit(repositoryPath, env, "commit", "-qm", "initialize fixture");
  t.after(() => rm(workspace, { force: true, recursive: true }));
  return {
    env,
    repositoryPath,
    service: createGitService({ env }),
  };
}

async function prepareChanges(fixture) {
  await rm(join(fixture.repositoryPath, "deleted.txt"));
  await writeFile(join(fixture.repositoryPath, "tracked.txt"), "updated\n");
  await writeFile(join(fixture.repositoryPath, "added.txt"), "added\n");
  await writeFile(join(fixture.repositoryPath, "ignored.txt"), "ignored\n");
  return fixture.service.snapshot({ projectPath: fixture.repositoryPath });
}

function handoffOptions(snapshot) {
  return {
    expectedSnapshot: snapshot,
    finalizedFingerprint: snapshot.contentFingerprint,
    reviewedFingerprint: snapshot.contentFingerprint,
  };
}

test("stages the complete finalized polishing handoff without committing", async (t) => {
  const fixture = await createFixture(t);
  const baseline = await prepareChanges(fixture);

  const staged = await fixture.service.stagePolishingHandoff(
    handoffOptions(baseline),
  );

  assert.equal(staged.head, baseline.head);
  assert.equal(staged.branch, baseline.branch);
  assert.equal(staged.refsFingerprint, baseline.refsFingerprint);
  assert.equal(
    staged.remoteConfigurationFingerprint,
    baseline.remoteConfigurationFingerprint,
  );
  assert.equal(staged.identityFingerprint, baseline.identityFingerprint);
  assert.equal(staged.contentFingerprint, baseline.contentFingerprint);
  assert.notEqual(staged.indexFingerprint, baseline.indexFingerprint);
  assert.deepEqual(
    (
      await runGit(
        fixture.repositoryPath,
        fixture.env,
        "diff",
        "--cached",
        "--name-only",
      )
    ).stdout.trim().split("\n"),
    ["added.txt", "deleted.txt", "tracked.txt"],
  );
  assert.equal(
    (
      await runGit(
        fixture.repositoryPath,
        fixture.env,
        "diff",
        "--name-only",
      )
    ).stdout,
    "",
  );
  assert.equal(
    (
      await runGit(
        fixture.repositoryPath,
        fixture.env,
        "ls-files",
        "--others",
        "--exclude-standard",
      )
    ).stdout,
    "",
  );
  assert.equal(
    (
      await runGit(fixture.repositoryPath, fixture.env, "rev-list", "--count", "HEAD")
    ).stdout.trim(),
    "1",
  );
});

test("accepts an already-complete handoff after runner interruption", async (t) => {
  const fixture = await createFixture(t);
  const baseline = await prepareChanges(fixture);
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");

  const recovered = await fixture.service.stagePolishingHandoff(
    handoffOptions(baseline),
  );

  assert.equal(recovered.contentFingerprint, baseline.contentFingerprint);
  assert.notEqual(recovered.indexFingerprint, baseline.indexFingerprint);
  assert.equal(
    (
      await runGit(fixture.repositoryPath, fixture.env, "rev-parse", "HEAD")
    ).stdout.trim(),
    baseline.head,
  );
});

test("fails closed on an incomplete index change after HANDOFF persistence", async (t) => {
  const fixture = await createFixture(t);
  const baseline = await prepareChanges(fixture);
  await runGit(fixture.repositoryPath, fixture.env, "add", "tracked.txt");

  await assert.rejects(
    fixture.service.stagePolishingHandoff(handoffOptions(baseline)),
    (error) =>
      error instanceof GitSafetyError &&
      error.code === "ERR_POLISHING_HANDOFF_CONTAMINATED" &&
      error.changes.includes("index"),
  );
  assert.equal(
    (
      await runGit(
        fixture.repositoryPath,
        fixture.env,
        "ls-files",
        "--others",
        "--exclude-standard",
      )
    ).stdout.trim(),
    "added.txt",
  );
});

test("rejects staged whitespace errors after the runner effect", async (t) => {
  const fixture = await createFixture(t);
  await writeFile(join(fixture.repositoryPath, "tracked.txt"), "trailing   \n");
  const baseline = await fixture.service.snapshot({
    projectPath: fixture.repositoryPath,
  });

  await assert.rejects(
    fixture.service.stagePolishingHandoff(handoffOptions(baseline)),
    (error) =>
      error instanceof GitSafetyError &&
      error.code === "ERR_POLISHING_HANDOFF_WHITESPACE",
  );
  assert.match(
    (
      await runGit(
        fixture.repositoryPath,
        fixture.env,
        "diff",
        "--cached",
        "--name-only",
      )
    ).stdout,
    /^tracked\.txt$/mu,
  );
});

test("does not accept index-hidden content that git add cannot stage", async (t) => {
  const fixture = await createFixture(t);
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "update-index",
    "--skip-worktree",
    "tracked.txt",
  );
  await writeFile(join(fixture.repositoryPath, "tracked.txt"), "hidden update\n");
  await writeFile(join(fixture.repositoryPath, "added.txt"), "added\n");
  const baseline = await fixture.service.snapshot({
    projectPath: fixture.repositoryPath,
  });

  await assert.rejects(
    fixture.service.stagePolishingHandoff(handoffOptions(baseline)),
    (error) =>
      error instanceof GitSafetyError &&
      error.code === "ERR_POLISHING_HANDOFF_INCOMPLETE",
  );
  assert.equal(
    (
      await runGit(fixture.repositoryPath, fixture.env, "rev-parse", "HEAD")
    ).stdout.trim(),
    baseline.head,
  );
});
