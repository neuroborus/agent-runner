import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { createGitService, GitSafetyError } from "../../src/git/index.js";

const executeFile = promisify(execFile);

async function runGit(repositoryPath, env, ...argumentsList) {
  return executeFile("git", ["-C", repositoryPath, ...argumentsList], {
    env,
    encoding: "utf8",
  });
}

async function createFixture(t, { unborn = false } = {}) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-handoff-"));
  t.after(() => rm(workspace, { force: true, recursive: true }));
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
  await runGit(repositoryPath, env, "config", "core.hooksPath", ".hooks");
  await writeFile(join(repositoryPath, ".gitignore"), "ignored.txt\n.hooks/\n");
  await writeFile(join(repositoryPath, "deleted.txt"), "delete me\n");
  await writeFile(join(repositoryPath, "tracked.txt"), "base\n");
  if (!unborn) {
    await runGit(repositoryPath, env, "add", "-A");
    await runGit(repositoryPath, env, "commit", "-qm", "initialize fixture");
  }
  return {
    env,
    repositoryPath,
    service: createGitService({ env }),
    workspace,
  };
}

async function configureHook(fixture) {
  const { env, repositoryPath, service, workspace } = fixture;
  const before = await service.snapshot({ projectPath: repositoryPath });
  const configuration = await readFile(join(repositoryPath, ".git", "config"));
  const receiptPath = join(workspace, "hook-receipt");
  env.HANDOFF_HOOK_RECEIPT = receiptPath;
  await mkdir(join(repositoryPath, ".hooks"));
  await writeFile(
    join(repositoryPath, ".hooks", "post-index-change"),
    '#!/bin/sh\nprintf "%s\\n" invoked >> "$HANDOFF_HOOK_RECEIPT"\n',
    { mode: 0o755 },
  );
  // Recreate the service with the fixture-local receipt binding.
  fixture.service = createGitService({ env });
  assert.deepEqual(
    await fixture.service.snapshot({ projectPath: repositoryPath }),
    before,
  );
  return {
    receiptPath,
    async assertUnchanged() {
      assert.deepEqual(
        await readFile(join(repositoryPath, ".git", "config")),
        configuration,
      );
      await assert.rejects(readFile(receiptPath), { code: "ENOENT" });
    },
  };
}

async function recordedService(fixture, drift) {
  const recorderPath = join(fixture.workspace, "record-git");
  const recordPath = join(fixture.workspace, "git-calls");
  await writeFile(recordPath, "");
  // An optional drift command runs before each new-file hygiene check.
  await writeFile(
    recorderPath,
    '#!/bin/sh\nprintf "%s\\n" "$@" >> "$HANDOFF_GIT_RECORD"\ncase " $* " in *" --no-index "*) [ -z "$HANDOFF_GIT_DRIFT" ] || sh -c "$HANDOFF_GIT_DRIFT" ;; esac\nexec git "$@"\n',
    { mode: 0o755 },
  );
  const calls = async () =>
    (await readFile(recordPath, "utf8")).trim().split("\n");
  return {
    calls,
    service: createGitService({
      env: {
        ...fixture.env,
        HANDOFF_GIT_RECORD: recordPath,
        ...(drift === undefined ? {} : { HANDOFF_GIT_DRIFT: drift }),
      },
      gitBinary: recorderPath,
    }),
    async assertNoIndexWrites() {
      const recorded = await calls();
      for (const command of ["add", "update-index", "reset", "hash-object"])
        assert.ok(!recorded.includes(command), command);
    },
    async assertNoHashing() {
      assert.ok(
        !(await readFile(recordPath, "utf8"))
          .split("\n")
          .includes("hash-object"),
      );
    },
    async assertNoStaging() {
      const calls = (await readFile(recordPath, "utf8")).trim().split("\n");
      assert.ok(calls.includes("diff"));
      assert.ok(!calls.includes("add"));
    },
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
  const hook = await configureHook(fixture);

  await runGit(fixture.repositoryPath, fixture.env, "add", "tracked.txt");
  assert.equal(await readFile(hook.receiptPath, "utf8"), "invoked\n");
  await runGit(fixture.repositoryPath, fixture.env, "reset", "-q");
  await rm(hook.receiptPath);
  assert.deepEqual(
    await fixture.service.snapshot({ projectPath: fixture.repositoryPath }),
    baseline,
  );

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
        "--name-status",
      )
    ).stdout
      .trim()
      .split("\n"),
    ["A\tadded.txt", "D\tdeleted.txt", "M\ttracked.txt"],
  );
  assert.equal(
    (await runGit(fixture.repositoryPath, fixture.env, "diff", "--name-only"))
      .stdout,
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
      await runGit(
        fixture.repositoryPath,
        fixture.env,
        "rev-list",
        "--count",
        "HEAD",
      )
    ).stdout.trim(),
    "1",
  );
  await hook.assertUnchanged();
});

test("inspects an untouched polishing handoff without staging it", async (t) => {
  const fixture = await createFixture(t);
  const baseline = await prepareChanges(fixture);
  const hook = await configureHook(fixture);
  const recorded = await recordedService(fixture);

  const inspected = await recorded.service.inspectPolishingHandoff(
    handoffOptions(baseline),
  );

  assert.equal(inspected.status, "untouched");
  assert.deepEqual(inspected.snapshot, baseline);
  assert.equal(
    (
      await runGit(
        fixture.repositoryPath,
        fixture.env,
        "diff",
        "--cached",
        "--name-only",
      )
    ).stdout,
    "",
  );
  await recorded.assertNoStaging();
  await hook.assertUnchanged();
});

test("accepts an already-complete handoff after runner interruption", async (t) => {
  const fixture = await createFixture(t);
  const baseline = await prepareChanges(fixture);
  const hook = await configureHook(fixture);
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
  assert.equal(await readFile(hook.receiptPath, "utf8"), "invoked\n");
  await rm(hook.receiptPath);
  const complete = await fixture.service.snapshot({
    projectPath: fixture.repositoryPath,
  });
  const recorded = await recordedService(fixture);

  const inspected = await recorded.service.inspectPolishingHandoff(
    handoffOptions(baseline),
  );
  assert.equal(inspected.status, "complete");
  const recovered = await recorded.service.stagePolishingHandoff(
    handoffOptions(baseline),
  );

  assert.equal(recovered.contentFingerprint, baseline.contentFingerprint);
  assert.notEqual(recovered.indexFingerprint, baseline.indexFingerprint);
  assert.deepEqual(recovered, complete);
  assert.equal(
    (
      await runGit(fixture.repositoryPath, fixture.env, "rev-parse", "HEAD")
    ).stdout.trim(),
    baseline.head,
  );
  await recorded.assertNoStaging();
  await hook.assertUnchanged();
});

test("keeps an unchanged handoff incomplete without invoking hooks", async (t) => {
  const fixture = await createFixture(t);
  const hook = await configureHook(fixture);
  const baseline = await fixture.service.snapshot({
    projectPath: fixture.repositoryPath,
  });

  await assert.rejects(
    fixture.service.stagePolishingHandoff(handoffOptions(baseline)),
    (error) =>
      error instanceof GitSafetyError &&
      error.code === "ERR_POLISHING_HANDOFF_INCOMPLETE",
  );

  assert.deepEqual(
    await fixture.service.snapshot({ projectPath: fixture.repositoryPath }),
    baseline,
  );
  await hook.assertUnchanged();
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

function hygieneOptions(snapshot) {
  return {
    expectedSnapshot: snapshot,
    contentFingerprint: snapshot.contentFingerprint,
  };
}

async function stagedState(fixture) {
  return (
    await runGit(
      fixture.repositoryPath,
      fixture.env,
      "ls-files",
      "--stage",
      "-z",
    )
  ).stdout;
}

test("reports new-file whitespace without staging, hashing or hooks", async (t) => {
  const fixture = await createFixture(t);
  await prepareChanges(fixture);
  await writeFile(join(fixture.repositoryPath, "new.txt"), "trailing  \n");
  // A bare "-" operand would read stdin rather than this root file.
  await writeFile(join(fixture.repositoryPath, "-"), "trailing  \n");
  const hook = await configureHook(fixture);
  const baseline = await fixture.service.snapshot({
    projectPath: fixture.repositoryPath,
  });
  const recorded = await recordedService(fixture);

  assert.deepEqual(
    await recorded.service.inspectContentHygiene(hygieneOptions(baseline)),
    {
      status: "whitespace",
      tracked: false,
      paths: ["-", "new.txt"],
      omitted: 0,
    },
  );
  assert.deepEqual(
    await fixture.service.snapshot({ projectPath: fixture.repositoryPath }),
    baseline,
  );
  await recorded.assertNoIndexWrites();
  await hook.assertUnchanged();
});

test("applies attributes and check-in conversion to new-file operands", async (t) => {
  const fixture = await createFixture(t);
  const { repositoryPath } = fixture;
  await writeFile(
    join(repositoryPath, ".gitattributes"),
    "generated/** -whitespace\nconverted.txt text eol=crlf\n",
  );
  await mkdir(join(repositoryPath, "generated"));
  await mkdir(join(repositoryPath, "other"));
  await writeFile(join(repositoryPath, "generated", "out.txt"), "spaced  \n");
  await writeFile(join(repositoryPath, "other", "out.txt"), "spaced  \n");
  await writeFile(join(repositoryPath, "converted.txt"), "line\r\n");
  await writeFile(join(repositoryPath, "raw.txt"), "line\r\n");
  const baseline = await fixture.service.snapshot({
    projectPath: repositoryPath,
  });

  assert.deepEqual(
    await fixture.service.inspectContentHygiene(hygieneOptions(baseline)),
    {
      status: "whitespace",
      tracked: false,
      paths: ["other/out.txt", "raw.txt"],
      omitted: 0,
    },
  );
});

test("excludes only exact allowed paths from tracked hygiene", async (t) => {
  const fixture = await createFixture(t);
  const { env, repositoryPath, service } = fixture;
  await mkdir(join(repositoryPath, "dir"));
  await writeFile(join(repositoryPath, "dir", "file.txt"), "base\n");
  await runGit(repositoryPath, env, "add", "-A");
  await runGit(repositoryPath, env, "commit", "-qm", "add nested fixture");
  await writeFile(join(repositoryPath, "dir", "file.txt"), "spaced  \n");
  const inspect = async (allowedPaths) =>
    service.inspectContentHygiene(
      hygieneOptions(
        await service.snapshot({ allowedPaths, projectPath: repositoryPath }),
      ),
    );

  assert.deepEqual(await inspect(["dir"]), {
    status: "whitespace",
    tracked: true,
    paths: [],
    omitted: 0,
  });
  assert.deepEqual(await inspect(["dir/file.txt"]), { status: "clean" });
});

test("keeps excluded descendants of a replaced tracked file out of hygiene", async (t) => {
  const fixture = await createFixture(t);
  const { env, repositoryPath, service } = fixture;
  await writeFile(join(repositoryPath, "dir"), "base\n");
  await runGit(repositoryPath, env, "add", "-A");
  await runGit(repositoryPath, env, "commit", "-qm", "add replaced fixture");
  await rm(join(repositoryPath, "dir"));
  await mkdir(join(repositoryPath, "dir"));
  await writeFile(join(repositoryPath, "dir", "allowed.txt"), "allowed  \n");
  await writeFile(join(repositoryPath, "dir", "control.txt"), "control\n");
  await runGit(repositoryPath, env, "add", "-A");
  const inspect = async () =>
    service.inspectContentHygiene(
      hygieneOptions(
        await service.snapshot({
          allowedPaths: ["dir/allowed.txt"],
          projectPath: repositoryPath,
        }),
      ),
    );

  assert.deepEqual(await inspect(), { status: "clean" });
  await writeFile(join(repositoryPath, "dir", "control.txt"), "control  \n");
  assert.deepEqual(await inspect(), {
    status: "whitespace",
    tracked: true,
    paths: [],
    omitted: 0,
  });
});

test("inspects unborn indexed and untracked content without HEAD or objects", async (t) => {
  const fixture = await createFixture(t, { unborn: true });
  const { env, repositoryPath } = fixture;
  const objects = async () =>
    (
      await readdir(join(repositoryPath, ".git", "objects"), {
        recursive: true,
      })
    ).sort();
  const clean = await fixture.service.snapshot({ projectPath: repositoryPath });
  assert.equal(clean.head, null);
  assert.deepEqual(
    await fixture.service.inspectContentHygiene(hygieneOptions(clean)),
    { status: "clean" },
  );

  await writeFile(join(repositoryPath, "indexed.txt"), "indexed  \n");
  await runGit(repositoryPath, env, "add", "indexed.txt");
  await writeFile(join(repositoryPath, "initial.txt"), "initial  \n");
  const baseline = await fixture.service.snapshot({
    projectPath: repositoryPath,
  });
  const before = await objects();
  const recorded = await recordedService(fixture);

  assert.deepEqual(
    await recorded.service.inspectContentHygiene(hygieneOptions(baseline)),
    {
      status: "whitespace",
      tracked: false,
      paths: ["indexed.txt", "initial.txt"],
      omitted: 0,
    },
  );
  assert.deepEqual(await objects(), before);
  assert.deepEqual(
    await fixture.service.snapshot({ projectPath: repositoryPath }),
    baseline,
  );
  await recorded.assertNoIndexWrites();

  // An indexed path whose parent became a regular file has no content.
  await mkdir(join(repositoryPath, "dir"));
  await writeFile(join(repositoryPath, "dir", "file.txt"), "nested  \n");
  await runGit(repositoryPath, env, "add", "dir/file.txt");
  await rm(join(repositoryPath, "dir"), { recursive: true });
  await writeFile(join(repositoryPath, "dir"), "replaced  \n");
  const replaced = await fixture.service.snapshot({
    projectPath: repositoryPath,
  });
  const beforeReplaced = await objects();
  const replacedRecord = await recordedService(fixture);

  assert.deepEqual(
    await replacedRecord.service.inspectContentHygiene(
      hygieneOptions(replaced),
    ),
    {
      status: "whitespace",
      tracked: false,
      paths: ["dir", "indexed.txt", "initial.txt"],
      omitted: 0,
    },
  );
  assert.deepEqual(await objects(), beforeReplaced);
  await replacedRecord.assertNoIndexWrites();
});

test("rejects untouched handoff whitespace before any index effect", async (t) => {
  for (const path of ["tracked.txt", "new.txt"]) {
    await t.test(path, async (t) => {
      const fixture = await createFixture(t);
      await writeFile(join(fixture.repositoryPath, path), "trailing   \n");
      const baseline = await fixture.service.snapshot({
        projectPath: fixture.repositoryPath,
      });
      const recorded = await recordedService(fixture);

      if (path === "tracked.txt")
        assert.equal(
          (
            await recorded.service.inspectContentHygiene(
              hygieneOptions(baseline),
            )
          ).tracked,
          true,
        );
      await assert.rejects(
        recorded.service.stagePolishingHandoff(handoffOptions(baseline)),
        { code: "ERR_POLISHING_HANDOFF_UNSTAGED_WHITESPACE" },
      );
      assert.deepEqual(
        await fixture.service.snapshot({
          projectPath: fixture.repositoryPath,
        }),
        baseline,
      );
      await recorded.assertNoIndexWrites();
    });
  }
});

test("rejects staged whitespace errors after the runner effect", async (t) => {
  const fixture = await createFixture(t);
  await writeFile(join(fixture.repositoryPath, "tracked.txt"), "trailing   \n");
  const baseline = await fixture.service.snapshot({
    projectPath: fixture.repositoryPath,
  });
  // Fixture-owned staging stands in for an interrupted Runner effect.
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
  const staged = await stagedState(fixture);
  const recorded = await recordedService(fixture);

  for (let attempt = 0; attempt < 2; attempt++) {
    await assert.rejects(
      recorded.service.inspectPolishingHandoff(handoffOptions(baseline)),
      { code: "ERR_POLISHING_HANDOFF_WHITESPACE" },
    );
    await assert.rejects(
      recorded.service.stagePolishingHandoff(handoffOptions(baseline)),
      { code: "ERR_POLISHING_HANDOFF_WHITESPACE" },
    );
  }
  await recorded.assertNoIndexWrites();
  assert.equal(await stagedState(fixture), staged);
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

test("keeps drift during hygiene inspection distinct from whitespace", async (t) => {
  for (const [name, drift, change] of [
    ["content", (path) => `printf drift >> '${path}/new.txt'`, "content"],
    [
      "control",
      (path) => `git -C '${path}' update-ref refs/heads/drift HEAD`,
      "refs",
    ],
  ]) {
    await t.test(name, async (t) => {
      const fixture = await createFixture(t);
      await writeFile(join(fixture.repositoryPath, "new.txt"), "trailing  \n");
      const baseline = await fixture.service.snapshot({
        projectPath: fixture.repositoryPath,
      });
      const staged = await stagedState(fixture);
      const recorded = await recordedService(
        fixture,
        drift(fixture.repositoryPath),
      );
      const contaminated = (error) =>
        error instanceof GitSafetyError &&
        error.code === "ERR_POLISHING_HANDOFF_CONTAMINATED" &&
        error.changes.includes(change);

      await assert.rejects(
        recorded.service.inspectContentHygiene(hygieneOptions(baseline)),
        contaminated,
      );
      if (name === "control") {
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "update-ref",
          "-d",
          "refs/heads/drift",
        );
        await assert.rejects(
          recorded.service.stagePolishingHandoff(handoffOptions(baseline)),
          contaminated,
        );
        await recorded.assertNoIndexWrites();
        assert.equal(await stagedState(fixture), staged);
      }
    });
  }
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
  await writeFile(
    join(fixture.repositoryPath, "tracked.txt"),
    "hidden update\n",
  );
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

async function convertedChanges(fixture) {
  const { repositoryPath, env } = fixture;
  await writeFile(
    join(repositoryPath, ".gitattributes"),
    "converted.txt text eol=crlf\n",
  );
  await writeFile(join(repositoryPath, "converted.txt"), "before\r\n");
  await runGit(repositoryPath, env, "add", "-A");
  await runGit(repositoryPath, env, "commit", "-qm", "configure text fixture");
  await writeFile(join(repositoryPath, "converted.txt"), "after\r\n");
  return fixture.service.snapshot({ projectPath: repositoryPath });
}

test("accepts explicit converted handoff and repeated inspection without staging replay", async (t) => {
  const fixture = await createFixture(t);
  const baseline = await convertedChanges(fixture);
  const staged = await fixture.service.stagePolishingHandoff(
    handoffOptions(baseline),
  );
  assert.equal(staged.contentFingerprint, baseline.contentFingerprint);
  for (const field of [
    "head",
    "refsFingerprint",
    "identityFingerprint",
    "remoteConfigurationFingerprint",
  ])
    assert.equal(staged[field], baseline[field]);
  assert.equal(
    (
      await runGit(
        fixture.repositoryPath,
        fixture.env,
        "show",
        ":converted.txt",
      )
    ).stdout,
    "after\n",
  );
  assert.equal(
    await readFile(join(fixture.repositoryPath, "converted.txt"), "utf8"),
    "after\r\n",
  );
  assert.equal(
    (await runGit(fixture.repositoryPath, fixture.env, "diff", "--name-only"))
      .stdout,
    "",
  );
  const recorded = await recordedService(fixture);
  for (let attempt = 0; attempt < 2; attempt++) {
    assert.equal(
      (await recorded.service.inspectPolishingHandoff(handoffOptions(baseline)))
        .status,
      "complete",
    );
    assert.deepEqual(
      await recorded.service.stagePolishingHandoff(handoffOptions(baseline)),
      staged,
    );
  }
  await recorded.assertNoStaging();
});

test("rejects exact hidden handoff entries even beside converted content", async (t) => {
  for (const mixed of [false, true]) {
    await t.test(
      mixed ? "mixed skip-worktree" : "exact assume-unchanged",
      async (t) => {
        const fixture = await createFixture(t);
        if (mixed) await convertedChanges(fixture);
        await writeFile(
          join(fixture.repositoryPath, "tracked.txt"),
          "updated\n",
        );
        const baseline = await fixture.service.snapshot({
          projectPath: fixture.repositoryPath,
        });
        await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
        await runGit(
          fixture.repositoryPath,
          fixture.env,
          "update-index",
          mixed ? "--skip-worktree" : "--assume-unchanged",
          "tracked.txt",
        );
        await assert.rejects(
          fixture.service.inspectPolishingHandoff(handoffOptions(baseline)),
          { code: "ERR_POLISHING_HANDOFF_CONTAMINATED" },
        );
      },
    );
  }
});

test("allows unchanged hidden paths outside the handoff change union", async (t) => {
  const fixture = await createFixture(t);
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "update-index",
    "--skip-worktree",
    "tracked.txt",
  );
  await writeFile(join(fixture.repositoryPath, "added.txt"), "added\n");
  const baseline = await fixture.service.snapshot({
    projectPath: fixture.repositoryPath,
  });
  const staged = await fixture.service.stagePolishingHandoff(
    handoffOptions(baseline),
  );
  assert.equal(staged.contentFingerprint, baseline.contentFingerprint);
});

async function stableTime(fixture, name = "converted.txt") {
  await runGit(
    fixture.repositoryPath,
    fixture.env,
    "config",
    "core.trustctime",
    "false",
  );
  await utimes(join(fixture.repositoryPath, name), 946684800, 946684800);
}

test("rejects same-size wrong converted blobs despite matching cached stat", async (t) => {
  const fixture = await createFixture(t);
  await convertedChanges(fixture);
  await stableTime(fixture);
  const baseline = await fixture.service.snapshot({
    projectPath: fixture.repositoryPath,
  });
  await writeFile(join(fixture.repositoryPath, "converted.txt"), "other\r\n");
  await stableTime(fixture);
  await runGit(fixture.repositoryPath, fixture.env, "add", "-A");
  await writeFile(join(fixture.repositoryPath, "converted.txt"), "after\r\n");
  await stableTime(fixture);
  assert.equal(
    (await runGit(fixture.repositoryPath, fixture.env, "diff", "--name-only"))
      .stdout,
    "",
  );
  await assert.rejects(
    fixture.service.inspectPolishingHandoff(handoffOptions(baseline)),
    { code: "ERR_POLISHING_HANDOFF_CONTAMINATED" },
  );
});

test("rejects unsupported attributes and injected conversion lookalikes", async (t) => {
  for (const attributes of [
    "text filter=fixture",
    "text filter=unspecified",
    "text filter=unset",
    "text=set",
    "text=auto",
    "text filter=fixture injected",
    "text filter=fixture drift",
  ]) {
    await t.test(attributes, async (t) => {
      const fixture = await createFixture(t);
      const { repositoryPath, env, workspace } = fixture;
      const marker = join(workspace, "filter-marker");
      env.FILTER_MARKER = marker;
      fixture.service = createGitService({ env });
      const filter = /filter=(\w+)/u.exec(attributes)?.[1];
      if (filter) {
        await runGit(
          repositoryPath,
          env,
          "config",
          `filter.${filter}.required`,
          "true",
        );
        await runGit(
          repositoryPath,
          env,
          "config",
          `filter.${filter}.clean`,
          'printf invoked >> "$FILTER_MARKER"; tr a-z A-Z',
        );
      }
      await runGit(repositoryPath, env, "config", "core.autocrlf", "false");
      await writeFile(
        join(repositoryPath, ".gitattributes"),
        `converted.txt ${attributes.endsWith("drift") ? "text" : attributes.replace(/ injected$/u, "")}\n`,
      );
      await writeFile(join(repositoryPath, "converted.txt"), "before\r\n");
      await runGit(repositoryPath, env, "add", "-A");
      await runGit(
        repositoryPath,
        env,
        "commit",
        "-qm",
        "configure attributes fixture",
      );
      await writeFile(join(repositoryPath, "converted.txt"), "after\r\n");
      await stableTime(fixture);
      const baseline = await fixture.service.snapshot({
        projectPath: repositoryPath,
      });
      const injected =
        attributes.endsWith("injected") || attributes === "text=set";
      // Fixture-owned staging deliberately bypasses the unsupported attribute,
      // retaining matching stat metadata while injecting the built-in LF blob.
      if (attributes === "text=set") {
        const info = join(repositoryPath, ".git", "info", "attributes");
        await writeFile(info, "converted.txt text\n");
        await runGit(repositoryPath, env, "add", "-A");
        await rm(info);
      } else {
        await runGit(
          repositoryPath,
          env,
          ...(injected ? ["-c", "filter.fixture.clean=cat"] : []),
          "add",
          "-A",
        );
      }
      if (attributes.endsWith("drift"))
        await writeFile(
          join(repositoryPath, ".git", "info", "attributes"),
          "converted.txt filter=fixture text\n",
        );
      // Finish fixture observation before measuring helper effects.
      await fixture.service.snapshot({ projectPath: repositoryPath });
      await rm(marker, { force: true });
      await assert.rejects(
        fixture.service.inspectPolishingHandoff(handoffOptions(baseline)),
        { code: "ERR_POLISHING_HANDOFF_CONTAMINATED" },
      );
      await assert.rejects(readFile(marker), { code: "ENOENT" });
      if (injected)
        assert.equal(
          (await runGit(repositoryPath, env, "show", ":converted.txt")).stdout,
          "after\n",
        );
    });
  }
});

test("isolates hashing beneath an enclosing repository and rejects unsafe scratch parents", async (t) => {
  for (const boundary of ["enclosing", "colon", "target", "common"]) {
    await t.test(boundary, async (t) => {
      const fixture = await createFixture(t);
      let { repositoryPath } = fixture;
      if (boundary === "common") {
        const linked = join(fixture.workspace, "linked");
        await runGit(
          repositoryPath,
          fixture.env,
          "worktree",
          "add",
          "-qb",
          "linked",
          linked,
        );
        fixture.repositoryPath = repositoryPath = linked;
      }
      const baseline = await convertedChanges(fixture);
      await runGit(repositoryPath, fixture.env, "add", "-A");
      const staged = await fixture.service.snapshot({
        projectPath: repositoryPath,
      });
      const parent =
        boundary === "target"
          ? join(repositoryPath, "scratch")
          : boundary === "common"
            ? join(fixture.workspace, "repository", ".git", "scratch")
            : join(
                fixture.workspace,
                boundary === "colon" ? "scratch:boundary" : "enclosing",
              );
      await mkdir(parent);
      const marker = join(fixture.workspace, "enclosing-marker");
      if (boundary === "enclosing") {
        await runGit(parent, fixture.env, "init", "-q");
        await writeFile(
          join(parent, ".gitattributes"),
          "* text filter=fixture\n",
        );
        await runGit(
          parent,
          fixture.env,
          "config",
          "filter.fixture.required",
          "true",
        );
        await runGit(
          parent,
          fixture.env,
          "config",
          "filter.fixture.clean",
          `touch '${marker}'; tr a-z A-Z`,
        );
      }
      const before = await readdir(parent);
      const previous = process.env.TMPDIR;
      process.env.TMPDIR = parent;
      try {
        const recorded = await recordedService(fixture);
        if (boundary === "enclosing") {
          assert.equal(
            (
              await recorded.service.inspectPolishingHandoff(
                handoffOptions(baseline),
              )
            ).status,
            "complete",
          );
          await assert.rejects(readFile(marker), { code: "ENOENT" });
        } else {
          await assert.rejects(
            recorded.service.inspectPolishingHandoff(handoffOptions(baseline)),
            { code: "ERR_GIT_UNAVAILABLE" },
          );
          await recorded.assertNoHashing();
        }
        await recorded.assertNoStaging();
      } finally {
        if (previous === undefined) delete process.env.TMPDIR;
        else process.env.TMPDIR = previous;
      }
      assert.deepEqual(await readdir(parent), before);
      if (boundary === "target") await rm(parent, { recursive: true });
      assert.deepEqual(
        await fixture.service.snapshot({ projectPath: repositoryPath }),
        staged,
      );
    });
  }
});
