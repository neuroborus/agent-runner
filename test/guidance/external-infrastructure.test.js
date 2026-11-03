import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import test from "node:test";

import { createRunStore, MAX_GUIDANCE_BYTES } from "../../src/index.js";
import { executeFile, fixture } from "./support/index.js";

const hash = (content) => createHash("sha256").update(content).digest("hex");
const noGit = {
  inspectPath() {
    assert.fail(
      "External or ordinary guidance needs no target Git inspection.",
    );
  },
};

async function externalFixture(t, options) {
  const f = await fixture(t, options);
  const rootPath = join(f.root, "infrastructure");
  await mkdir(rootPath);
  const projectConfigurationPath = join(rootPath, "agent-runner.json");
  const configuration = {
    schemaVersion: 1,
    infrastructure: {
      schemaVersion: 1,
      placement: "external",
      projectPath: f.projectPath,
      rootPath,
    },
    artifactRoot: "artifacts",
  };
  await writeFile(projectConfigurationPath, JSON.stringify(configuration));
  const selectors = { projectPath: f.projectPath, projectConfigurationPath };
  return {
    ...f,
    rootPath,
    configuration,
    selectors,
    externalPath: join(rootPath, "artifacts", "agent-runner", "rules.md"),
    updateInput: (content, values) =>
      f.request(content, { ...selectors, ...values }),
  };
}

test("selected external guidance reads complete documents and publishes without target or Git-control writes", async (t) => {
  for (const gitWorkspace of [true, false]) {
    const f = await externalFixture(t, { gitWorkspace });
    const before = await readdir(f.projectPath);
    const controls = gitWorkspace
      ? await readFile(join(f.projectPath, ".git", "config"))
      : null;
    const ignore = await readFile(join(f.projectPath, ".gitignore"));
    const service = f.createService({ git: noGit });
    const read = await service.read(f.selectors);
    assert.equal(read.localPath, f.externalPath);
    assert.equal(read.localHash, null);
    assert.equal(read.localContent, "");
    assert.equal(
      read.commonContent,
      await readFile(
        new URL("../../docs/OPERATOR_GUIDE.md", import.meta.url),
        "utf8",
      ),
    );
    assert.ok(
      Buffer.byteLength(read.commonContent) < MAX_GUIDANCE_BYTES - 1024,
    );
    await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
    assert.deepEqual(await readdir(f.rootPath), ["agent-runner.json"]);
    const localContent =
      "# Local additions\r\n\r\n" +
      "Résumé of a useful lesson.\r\n".repeat(400);
    const input = f.updateInput(localContent, {
      projectConfigurationPath: relative(
        f.projectPath,
        f.selectors.projectConfigurationPath,
      ),
    });
    const receipt = await service.update(input);
    assert.equal(receipt.localPath, f.externalPath);
    const after = await service.read(f.selectors);
    assert.equal(after.localContent, localContent);
    assert.equal(after.localHash, hash(localContent));
    assert.ok(after.combinedContent.includes(after.commonContent));
    assert.ok(after.combinedContent.endsWith(localContent));
    assert.equal((await lstat(f.externalPath)).mode & 0o777, 0o600);
    assert.deepEqual(await readdir(f.projectPath), before);
    assert.deepEqual(await readFile(join(f.projectPath, ".gitignore")), ignore);
    if (gitWorkspace)
      assert.deepEqual(
        await readFile(join(f.projectPath, ".git", "config")),
        controls,
      );
    assert.equal(
      await readFile(f.selectors.projectConfigurationPath, "utf8"),
      JSON.stringify(f.configuration),
    );
  }
});

test("ordinary-directory guidance uses integrated configuration without Git prerequisites", async (t) => {
  const f = await fixture(t, { gitWorkspace: false, ignored: false });
  const service = f.createService({ git: noGit });
  assert.equal(
    (await service.read({ projectPath: f.projectPath })).localPath,
    f.localPath,
  );
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(
    join(f.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
    '{"schemaVersion":1,"artifactRoot":"CUSTOM_ARTIFACTS"}',
  );
  const receipt = await service.update(f.request("Directory lesson."));
  assert.equal(
    receipt.localPath,
    join(f.projectPath, "CUSTOM_ARTIFACTS", "agent-runner", "rules.md"),
  );
  assert.equal(
    (await service.read({ projectPath: f.projectPath })).localContent,
    "Directory lesson.",
  );
});

test("explicit placement replaces competing integrated guidance and rejects a wrong-target binding", async (t) => {
  const f = await externalFixture(t, { initialContent: "Integrated lesson." });
  assert.equal(
    (await f.service.read({ projectPath: f.projectPath })).localContent,
    "Integrated lesson.",
  );
  await f.service.update(f.updateInput("External lesson."));
  assert.equal(
    (await f.service.read(f.selectors)).localContent,
    "External lesson.",
  );
  assert.equal(await readFile(f.localPath, "utf8"), "Integrated lesson.");
  await writeFile(
    f.selectors.projectConfigurationPath,
    JSON.stringify({
      ...f.configuration,
      infrastructure: {
        ...f.configuration.infrastructure,
        projectPath: join(f.root, "other"),
      },
    }),
  );
  await assert.rejects(f.service.read(f.selectors), {
    code: "ERR_PROJECT_CONFIGURATION_BINDING",
  });
  await assert.rejects(f.service.update(f.updateInput("Rejected.")), {
    code: "ERR_PROJECT_CONFIGURATION_BINDING",
  });
  assert.equal(await readFile(f.externalPath, "utf8"), "External lesson.");
});

test("external publication recovers partial writes, prepared files and unacknowledged renames", async (t) => {
  for (const stopAt of ["writing", "prepared", "renamed"]) {
    await t.test(stopAt, async (t) => {
      const f = await externalFixture(t, { gitWorkspace: false });
      const input = f.updateInput("Published lesson.");
      await assert.rejects(
        f
          .createService({
            async onPublicationBoundary(phase) {
              if (phase === stopAt) throw new Error("Interrupted.");
            },
          })
          .update(input),
      );
      const inode = await lstat(f.externalPath).then(
        (stat) => stat.ino,
        () => null,
      );
      const receipt = await f.createService().update(input);
      assert.equal(receipt.localPath, f.externalPath);
      assert.equal(await readFile(f.externalPath, "utf8"), "Published lesson.");
      if (stopAt === "renamed")
        assert.equal((await lstat(f.externalPath)).ino, inode);
      assert.deepEqual(await readdir(dirname(f.externalPath)), ["rules.md"]);
    });
  }
});

test("unpublished external intents reject configuration and ancestor substitution on restart", async (t) => {
  for (const drift of ["configuration", "ancestor", "target", "root"]) {
    await t.test(drift, async (t) => {
      const f = await externalFixture(t, { gitWorkspace: false });
      const input = f.updateInput("Pinned lesson.");
      await assert.rejects(
        f
          .createService({
            async onPublicationBoundary(phase) {
              if (phase === "prepared") throw new Error("Interrupted.");
            },
          })
          .update(input),
      );
      if (drift === "configuration") {
        await writeFile(
          f.selectors.projectConfigurationPath,
          JSON.stringify({ ...f.configuration, artifactRoot: "other" }),
        );
      } else {
        const path =
          drift === "ancestor"
            ? dirname(f.externalPath)
            : drift === "target"
              ? f.projectPath
              : f.rootPath;
        await rename(path, `${path}-original`);
        await mkdir(path);
        if (drift === "root")
          await writeFile(
            f.selectors.projectConfigurationPath,
            JSON.stringify(f.configuration),
          );
      }
      await assert.rejects(f.createService().update(input), {
        code: "ERR_GUIDANCE_CONFIGURATION_CHANGED",
      });
      await assert.rejects(lstat(f.externalPath), { code: "ENOENT" });
      await assert.rejects(lstat(join(f.rootPath, "other")), {
        code: "ENOENT",
      });
    });
  }
});

test("a published external intent completes its original receipt after configuration changes", async (t) => {
  const f = await externalFixture(t, { gitWorkspace: false });
  const input = f.updateInput("Published.");
  await assert.rejects(
    f
      .createService({
        async onPublicationBoundary(phase) {
          if (phase === "published") throw new Error("Interrupted.");
        },
      })
      .update(input),
  );
  await writeFile(f.externalPath, "Manual later edit.");
  await rename(f.rootPath, `${f.rootPath}-original`);
  const restarted = f.createService({
    loadConfiguration() {
      assert.fail("Published effects must only complete their receipt.");
    },
  });
  const receipt = await restarted.update(input);
  assert.equal(receipt.localPath, f.externalPath);
  assert.equal(receipt.localHash, hash("Published."));
  assert.deepEqual(await restarted.update(input), receipt);
  assert.equal(
    await readFile(
      join(`${f.rootPath}-original`, "artifacts", "agent-runner", "rules.md"),
      "utf8",
    ),
    "Manual later edit.",
  );
});

test("external updates share the target lease across placements and stale writers", async (t) => {
  const f = await externalFixture(t);
  const competing = f.updateInput("Contender.");
  await f
    .createService({
      async onPublicationBoundary(phase) {
        if (phase !== "prepared") return;
        for (const input of [competing, f.request("Integrated contender.")]) {
          await assert.rejects(f.createService().update(input), {
            code: "ERR_WORKTREE_LEASED",
          });
        }
      },
    })
    .update(f.updateInput("Owner."));
  await assert.rejects(f.service.update(competing), {
    code: "ERR_GUIDANCE_STALE",
  });
  await assert.rejects(lstat(f.localPath), { code: "ENOENT" });
});

test("different targets sharing external guidance exclude concurrent publication", async (t) => {
  const f = await externalFixture(t, { gitWorkspace: false });
  const otherProject = join(f.root, "other-project");
  const otherConfiguration = join(f.rootPath, "other-project.json");
  await mkdir(otherProject);
  await writeFile(
    otherConfiguration,
    JSON.stringify({
      ...f.configuration,
      infrastructure: {
        ...f.configuration.infrastructure,
        projectPath: otherProject,
      },
    }),
  );
  const competing = f.updateInput("Contender.", {
    projectPath: otherProject,
    projectConfigurationPath: otherConfiguration,
  });
  await f
    .createService({
      async onPublicationBoundary(phase) {
        if (phase === "prepared") {
          await assert.rejects(f.createService().update(competing), {
            code: "ERR_WORKTREE_LEASED",
          });
        }
      },
    })
    .update(f.updateInput("Owner."));
  await assert.rejects(f.service.update(competing), {
    code: "ERR_GUIDANCE_STALE",
  });
  assert.equal(await readFile(f.externalPath, "utf8"), "Owner.");
  const receipt = await f.service.update({
    ...competing,
    expectedHash: hash("Owner."),
    idempotencyKey: randomUUID(),
  });
  assert.equal(receipt.localPath, f.externalPath);
  assert.equal(await readFile(f.externalPath, "utf8"), "Contender.");
  assert.deepEqual(await readdir(f.projectPath), [".gitignore"]);
  assert.deepEqual(await readdir(otherProject), []);
});

test("Git subdirectory selectors retain integrated and external worktree-bound configurations", async (t) => {
  for (const placement of ["integrated", "external"]) {
    await t.test(placement, async (t) => {
      const f = await externalFixture(t);
      const subdirectory = join(f.projectPath, "directory");
      await mkdir(subdirectory);
      const projectConfigurationPath =
        placement === "external"
          ? f.selectors.projectConfigurationPath
          : join(f.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json");
      if (placement === "integrated") {
        await mkdir(dirname(projectConfigurationPath));
        await writeFile(projectConfigurationPath, '{"schemaVersion":1}');
      }
      const localPath = placement === "external" ? f.externalPath : f.localPath;
      const selectors = { projectPath: subdirectory, projectConfigurationPath };
      const relativePath = relative(
        placement === "external" ? subdirectory : f.projectPath,
        projectConfigurationPath,
      );
      for (const selectedPath of [projectConfigurationPath, relativePath]) {
        const guidance = await f.service.read({
          ...selectors,
          projectConfigurationPath: selectedPath,
        });
        assert.equal(guidance.projectPath, f.projectPath);
        assert.equal(guidance.localPath, localPath);
      }
      const input = f.request("Root-bound lesson.", {
        ...selectors,
        projectConfigurationPath: relativePath,
      });
      await assert.rejects(
        f
          .createService({
            async onPublicationBoundary(phase) {
              if (phase === "prepared") throw new Error("Interrupted.");
            },
          })
          .update(input),
        { code: "ERR_GUIDANCE_STORAGE" },
      );
      assert.notEqual(
        await f.store.readAction({
          key: input.idempotencyKey,
          tool: "guidance_update",
          arguments: {
            projectPath: f.projectPath,
            projectConfigurationPath,
            localContentHash: hash(input.localContent),
            expectedHash: input.expectedHash,
          },
        }),
        null,
      );
      const receipt = await f.createService().update(input);
      assert.equal(receipt.projectPath, f.projectPath);
      assert.equal(receipt.localPath, localPath);
      assert.equal(
        (await f.service.read(selectors)).localContent,
        "Root-bound lesson.",
      );
      const replay = f.createService({
        loadConfiguration() {
          assert.fail("Completed receipts must not reload configuration.");
        },
      });
      assert.deepEqual(await replay.update(input), receipt);
      assert.deepEqual(
        await replay.update({
          ...input,
          projectPath: f.projectPath,
          projectConfigurationPath,
        }),
        receipt,
      );
      if (placement === "external") {
        await assert.rejects(
          replay.update({
            ...input,
            projectConfigurationPath: relative(
              f.projectPath,
              projectConfigurationPath,
            ),
          }),
          { code: "ERR_MCP_IDEMPOTENCY_CONFLICT" },
        );
      }
    });
  }
});

test("directory targets inside a worktree retain their binding and share its execution exclusion", async (t) => {
  const f = await externalFixture(t);
  const projectPath = join(f.projectPath, "directory");
  await mkdir(projectPath);
  await writeFile(
    f.selectors.projectConfigurationPath,
    JSON.stringify({
      ...f.configuration,
      infrastructure: { ...f.configuration.infrastructure, projectPath },
    }),
  );
  const input = {
    ...f.updateInput("After execution."),
    projectPath,
    projectConfigurationPath: relative(
      projectPath,
      f.selectors.projectConfigurationPath,
    ),
  };
  const lease = await f.store.acquireWorktreeLease(f.projectPath, randomUUID());
  try {
    assert.equal(
      (await f.service.read({ ...f.selectors, projectPath })).projectPath,
      projectPath,
    );
    assert.equal(
      (
        await f.service.read({
          projectPath,
          projectConfigurationPath: input.projectConfigurationPath,
        })
      ).localPath,
      f.externalPath,
    );
    await assert.rejects(f.service.update(input), {
      code: "ERR_WORKTREE_LEASED",
    });
  } finally {
    await lease.release();
  }
  const receipt = await f.service.update(input);
  assert.equal(receipt.updated, true);
  const replay = f.createService({
    loadConfiguration() {
      assert.fail(
        "Directory-bound receipts must retain their target without configuration reload.",
      );
    },
  });
  assert.deepEqual(await replay.update(input), receipt);
  assert.deepEqual(await readdir(projectPath), []);
  assert.equal(
    (
      await executeFile("git", ["status", "--porcelain"], {
        cwd: f.projectPath,
      })
    ).stdout,
    "?? .gitignore\n",
  );
});

test("directory-bound infrastructure inside the enclosing worktree needs no second exclusion lease", async (t) => {
  const f = await fixture(t);
  const projectPath = join(f.projectPath, "directory");
  const rootPath = join(f.projectPath, "infrastructure");
  const projectConfigurationPath = join(rootPath, "agent-runner.json");
  await mkdir(projectPath);
  await mkdir(rootPath);
  await writeFile(
    projectConfigurationPath,
    JSON.stringify({
      schemaVersion: 1,
      infrastructure: {
        schemaVersion: 1,
        placement: "external",
        projectPath,
        rootPath,
      },
      artifactRoot: "artifacts",
    }),
  );
  const selectors = { projectPath, projectConfigurationPath };
  const localPath = join(rootPath, "artifacts", "agent-runner", "rules.md");
  assert.equal((await f.service.read(selectors)).localPath, localPath);
  assert.equal(
    (
      await f.service.read({
        ...selectors,
        projectConfigurationPath: relative(
          projectPath,
          projectConfigurationPath,
        ),
      })
    ).localPath,
    localPath,
  );
  const receipt = await f.service.update(
    f.request("Sibling lesson.", selectors),
  );
  assert.equal(receipt.projectPath, projectPath);
  assert.equal(receipt.localPath, localPath);
  assert.equal(await readFile(localPath, "utf8"), "Sibling lesson.");
  assert.deepEqual(await readdir(projectPath), []);
  assert.equal(
    await readFile(join(f.projectPath, ".gitignore"), "utf8"),
    "LOCAL_ARTIFACTS/\nCUSTOM_ARTIFACTS/\n",
  );
});

test("external confinement rejects linked ancestors and state overlapping infrastructure before effects", async (t) => {
  const f = await externalFixture(t, { gitWorkspace: false });
  const outside = join(f.root, "outside");
  await mkdir(outside);
  await writeFile(join(outside, "rules.md"), "Outside sentinel.");
  await symlink(outside, join(f.rootPath, "artifacts"));
  await assert.rejects(f.service.update(f.updateInput("Rejected.")), {
    code: "ERR_UNSAFE_GUIDANCE_PATH",
  });
  assert.equal(
    await readFile(join(outside, "rules.md"), "utf8"),
    "Outside sentinel.",
  );
  await rm(join(f.rootPath, "artifacts"));
  const stateRoot = join(f.rootPath, "state");
  await assert.rejects(
    f
      .createService({ runStore: createRunStore({ stateRoot }) })
      .update(f.updateInput("Rejected.")),
    { code: "ERR_UNSAFE_STATE_ROOT" },
  );
  await assert.rejects(lstat(stateRoot), { code: "ENOENT" });
  assert.deepEqual(await readdir(f.rootPath), ["agent-runner.json"]);
});

test("external guidance cannot publish inside pointer-resolved Git metadata", async (t) => {
  const f = await externalFixture(t, { gitWorkspace: false });
  await executeFile("git", [
    "init",
    "--quiet",
    "--separate-git-dir",
    f.rootPath,
    f.projectPath,
  ]);
  const marker = await readFile(join(f.projectPath, ".git"));
  const configuration = await readFile(join(f.rootPath, "config"));
  const service = f.createService({ git: noGit });
  await assert.rejects(service.read(f.selectors), {
    code: "ERR_UNSAFE_GUIDANCE_PATH",
  });
  await assert.rejects(service.update(f.updateInput("Rejected.")), {
    code: "ERR_UNSAFE_GUIDANCE_PATH",
  });
  await assert.rejects(lstat(join(f.rootPath, "artifacts")), {
    code: "ENOENT",
  });
  assert.deepEqual(await readFile(join(f.projectPath, ".git")), marker);
  assert.deepEqual(await readFile(join(f.rootPath, "config")), configuration);
});

test("external guidance rejects metadata reached through Git pointers nested in protected control trees", async (t) => {
  for (const control of [".agents", ".git"]) {
    await t.test(control, async (t) => {
      const f = await externalFixture(t, { gitWorkspace: false });
      const service = f.createService({ git: noGit });
      const unrelated = join(f.projectPath, "content");
      await mkdir(unrelated);
      await writeFile(join(unrelated, ".git"), "Not a metadata pointer.\n");
      assert.equal((await service.read(f.selectors)).localHash, null);
      const nestedControl = join(f.projectPath, control, "nested");
      const metadata = join(f.root, "metadata", "nested");
      await mkdir(nestedControl, { recursive: true });
      await mkdir(metadata, { recursive: true });
      const pointer = join(nestedControl, ".git");
      const dependency = join(metadata, ".git");
      const pointerContent = `gitdir: ${dirname(metadata)}\n`;
      const dependencyContent = `gitdir: ${f.rootPath}\n`;
      await writeFile(pointer, pointerContent);
      await writeFile(dependency, dependencyContent);
      const configuration = await readFile(
        f.selectors.projectConfigurationPath,
      );

      await assert.rejects(service.read(f.selectors), {
        code: "ERR_UNSAFE_GUIDANCE_PATH",
      });
      await assert.rejects(service.update(f.updateInput("Rejected.")), {
        code: "ERR_UNSAFE_GUIDANCE_PATH",
      });

      assert.deepEqual(await readdir(f.rootPath), ["agent-runner.json"]);
      assert.deepEqual(
        await readFile(f.selectors.projectConfigurationPath),
        configuration,
      );
      assert.equal(await readFile(pointer, "utf8"), pointerContent);
      assert.equal(await readFile(dependency, "utf8"), dependencyContent);
      await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
    });
  }
});

test("external guidance rejects metadata reached only through a state-ancestor Git pointer", async (t) => {
  const f = await externalFixture(t, {
    gitWorkspace: false,
    stateRoot: (root) => join(root, "state-owner", "state"),
  });
  await mkdir(dirname(f.stateRoot));
  const pointer = join(dirname(f.stateRoot), ".git");
  const pointerContent = `gitdir: ${f.rootPath}\n`;
  await writeFile(pointer, pointerContent);
  await mkdir(dirname(f.externalPath), { recursive: true });
  const content = "Git metadata sentinel.";
  await writeFile(f.externalPath, content);
  const entries = await readdir(f.rootPath, { recursive: true });
  const configuration = await readFile(f.selectors.projectConfigurationPath);
  const service = f.createService({ git: noGit });

  await assert.rejects(service.read(f.selectors), {
    code: "ERR_UNSAFE_GUIDANCE_PATH",
  });
  await assert.rejects(
    service.update(f.updateInput("Rejected.", { expectedHash: hash(content) })),
    { code: "ERR_UNSAFE_GUIDANCE_PATH" },
  );

  assert.equal(await readFile(f.externalPath, "utf8"), content);
  assert.deepEqual(await readdir(f.rootPath, { recursive: true }), entries);
  assert.deepEqual(
    await readFile(f.selectors.projectConfigurationPath),
    configuration,
  );
  assert.equal(await readFile(pointer, "utf8"), pointerContent);
  await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
});

test("external guidance rejects canonical ancestor provider alias targets without changing provider storage", async (t) => {
  const f = await externalFixture(t, { gitWorkspace: false });
  await mkdir(dirname(f.externalPath), { recursive: true });
  await writeFile(f.externalPath, "Provider storage sentinel.");
  await symlink(f.rootPath, join(f.root, ".codex"));
  const entries = await readdir(f.rootPath, { recursive: true });
  const configuration = await readFile(f.selectors.projectConfigurationPath);
  const service = f.createService({ git: noGit });

  await assert.rejects(service.read(f.selectors), {
    code: "ERR_UNSAFE_GUIDANCE_PATH",
  });
  await assert.rejects(
    service.update(
      f.updateInput("Rejected.", {
        expectedHash: hash("Provider storage sentinel."),
      }),
    ),
    { code: "ERR_UNSAFE_GUIDANCE_PATH" },
  );

  assert.equal(
    await readFile(f.externalPath, "utf8"),
    "Provider storage sentinel.",
  );
  assert.deepEqual(await readdir(f.rootPath, { recursive: true }), entries);
  assert.deepEqual(
    await readFile(f.selectors.projectConfigurationPath),
    configuration,
  );
  await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
});
