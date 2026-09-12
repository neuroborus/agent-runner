import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";

import { createGitService } from "../../src/git/index.js";
import { GuidanceError, MAX_GUIDANCE_BYTES } from "../../src/guidance/index.js";
import { executeFile, fixture } from "./support/index.js";

const hash = (content) => createHash("sha256").update(content).digest("hex");

test("missing guidance reads compose the installed guide without creating local or state paths", async (t) => {
  const f = await fixture(t);
  const before = await readdir(f.projectPath);
  const result = await f.service.read({ projectPath: f.projectPath });
  assert.equal(result.localContent, "");
  assert.equal(result.localHash, null);
  assert.equal(result.localPath, f.localPath);
  assert.equal(result.projectConfigurationPath, null);
  assert.equal(
    result.commonContent,
    await readFile(
      new URL("../../docs/OPERATOR_GUIDE.md", import.meta.url),
      "utf8",
    ),
  );
  assert.ok(result.combinedContent.includes(result.commonContent));
  assert.match(
    result.combinedContent,
    /cannot weaken common safety rules or product contracts/u,
  );
  assert.match(result.combinedContent, /No project-local additions/u);
  assert.deepEqual(await readdir(f.projectPath), before);
  await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
});

test("complete local Markdown and existing empty content retain exact bytes and hashes", async (t) => {
  const content =
    "# Project\r\n\r\nUse the project service fixture.\r\n\r\n## Another lesson\r\nUnicode: café 🧪\r\n";
  const f = await fixture(t, { initialContent: content });
  let result = await f.service.read({ projectPath: f.projectPath });
  assert.equal(result.localContent, content);
  assert.equal(result.localHash, hash(content));
  assert.ok(result.combinedContent.endsWith(content));
  await writeFile(f.localPath, "");
  result = await f.service.read({ projectPath: f.projectPath });
  assert.equal(result.localContent, "");
  assert.equal(result.localHash, hash(""));
});

test("current runner, discovered project, and explicit project configuration resolve artifactRoot", async (t) => {
  const f = await fixture(t);
  f.setConfiguration({ artifactRoot: "CUSTOM_ARTIFACTS" });
  assert.equal(
    (await f.service.read({ projectPath: f.projectPath })).localPath,
    join(f.projectPath, "CUSTOM_ARTIFACTS", "agent-runner", "rules.md"),
  );
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(
    join(f.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
    '{"schemaVersion":1,"artifactRoot":"LOCAL_ARTIFACTS"}',
  );
  assert.equal(
    (await f.service.read({ projectPath: f.projectPath })).localPath,
    f.localPath,
  );
  const custom = join(f.projectPath, "LOCAL_ARTIFACTS", "custom.json");
  await writeFile(
    custom,
    '{"schemaVersion":1,"artifactRoot":"CUSTOM_ARTIFACTS"}',
  );
  const request = f.request("Local lesson.", {
    projectConfigurationPath: "LOCAL_ARTIFACTS/custom.json",
  });
  const receipt = await f.service.update(request);
  assert.equal(
    receipt.localPath,
    join(f.projectPath, "CUSTOM_ARTIFACTS", "agent-runner", "rules.md"),
  );
  const result = await f.service.read({
    projectPath: f.projectPath,
    projectConfigurationPath: custom,
  });
  assert.equal(result.localContent, "Local lesson.");
  assert.equal(result.projectConfigurationPath, custom);
});

test("reading and writing reject non-ignored and tracked targets even before creation", async (t) => {
  const f = await fixture(t, { ignored: false });
  await assert.rejects(f.service.read({ projectPath: f.projectPath }), {
    code: "ERR_GUIDANCE_NOT_IGNORED",
  });
  await assert.rejects(f.service.update(f.request("Lesson.")), {
    code: "ERR_GUIDANCE_NOT_IGNORED",
  });
  await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
  await writeFile(join(f.projectPath, ".gitignore"), "LOCAL_ARTIFACTS/\n");
  await mkdir(dirname(f.localPath), { recursive: true });
  await writeFile(f.localPath, "Tracked lesson.");
  await executeFile(
    "git",
    ["add", "--force", "LOCAL_ARTIFACTS/agent-runner/rules.md"],
    { cwd: f.projectPath },
  );
  await assert.rejects(f.service.read({ projectPath: f.projectPath }), {
    code: "ERR_GUIDANCE_NOT_IGNORED",
  });
  await assert.rejects(f.service.update(f.request("Replacement.")), {
    code: "ERR_GUIDANCE_NOT_IGNORED",
  });
});

test("linked, non-regular, escaping, and protected targets fail closed", async (t) => {
  for (const kind of [
    "symlink",
    "hardlink",
    "directory",
    "fifo",
    "ancestor",
    "dangling-ancestor",
    "protected",
  ]) {
    await t.test(kind, async (t) => {
      const f = await fixture(t);
      const outside = join(f.root, "outside");
      await mkdir(outside);
      const sentinel = join(outside, "sentinel.md");
      await writeFile(sentinel, "Preserve me.");
      if (kind === "protected") {
        await writeFile(join(f.projectPath, ".gitignore"), ".agents/\n");
        f.setConfiguration({ artifactRoot: ".agents" });
      } else if (kind.endsWith("ancestor")) {
        await symlink(
          kind === "ancestor" ? outside : join(outside, "missing"),
          join(f.projectPath, "LOCAL_ARTIFACTS"),
        );
      } else {
        await mkdir(dirname(f.localPath), { recursive: true });
        if (kind === "symlink") await symlink(sentinel, f.localPath);
        if (kind === "hardlink") await link(sentinel, f.localPath);
        if (kind === "directory") await mkdir(f.localPath);
        if (kind === "fifo") await executeFile("mkfifo", [f.localPath]);
      }
      await assert.rejects(f.service.read({ projectPath: f.projectPath }));
      await assert.rejects(f.service.update(f.request("Replacement.")));
      assert.equal(await readFile(sentinel, "utf8"), "Preserve me.");
    });
  }
});

test("guidance cannot overlap the selected configuration file", async (t) => {
  const f = await fixture(t, { initialContent: '{"schemaVersion":1}' });
  await assert.rejects(
    f.service.read({
      projectPath: f.projectPath,
      projectConfigurationPath: f.localPath,
    }),
    { code: "ERR_UNSAFE_GUIDANCE_PATH" },
  );
  await assert.rejects(
    f.service.update(
      f.request("Replacement.", { projectConfigurationPath: f.localPath }),
    ),
    { code: "ERR_UNSAFE_GUIDANCE_PATH" },
  );
  assert.equal(await readFile(f.localPath, "utf8"), '{"schemaVersion":1}');
});

test("reads and replacements enforce the same byte, encoding, control, and sensitive-content limits", async (t) => {
  const f = await fixture(t, { initialContent: "" });
  for (const content of [
    "x".repeat(MAX_GUIDANCE_BYTES + 1),
    "\0",
    "bad\u001b[31m",
    "bad\u202e",
    "password=private-example-value",
    "-----BEGIN PRIVATE KEY-----",
    "<analysis>provider reasoning</analysis>",
    '{"role":"assistant"}',
  ]) {
    await writeFile(f.localPath, content);
    await assert.rejects(
      f.service.read({ projectPath: f.projectPath }),
      (error) =>
        error instanceof GuidanceError && !error.message.includes(content),
    );
    await assert.rejects(
      f.service.update(f.request(content)),
      (error) =>
        error instanceof GuidanceError && !error.message.includes(content),
    );
  }
  await writeFile(f.localPath, Buffer.from([0xc3, 0x28]));
  await assert.rejects(f.service.read({ projectPath: f.projectPath }), {
    code: "ERR_INVALID_GUIDANCE",
  });
  await assert.rejects(f.service.update(f.request("\ud800")), {
    code: "ERR_INVALID_GUIDANCE",
  });
  await writeFile(f.localPath, "é".repeat(MAX_GUIDANCE_BYTES / 2));
  assert.equal(
    (await f.service.read({ projectPath: f.projectPath })).localHash,
    hash("é".repeat(MAX_GUIDANCE_BYTES / 2)),
  );
});

test("unsafe external state is rejected before intent or lease writes", async (t) => {
  for (const alias of [false, true]) {
    const f = await fixture(t, {
      stateRoot: (root, project) =>
        alias ? join(root, "state-alias") : join(project, "unsafe-state"),
    });
    if (alias) await symlink(join(f.projectPath, "missing-state"), f.stateRoot);
    await assert.rejects(f.service.update(f.request("Lesson.")), {
      code: "ERR_UNSAFE_STATE_ROOT",
    });
    await assert.rejects(
      lstat(join(f.projectPath, alias ? "missing-state" : "unsafe-state")),
      { code: "ENOENT" },
    );
    await assert.rejects(lstat(join(f.projectPath, "LOCAL_ARTIFACTS")), {
      code: "ENOENT",
    });
  }
});

test("a project inside the state tree cannot receive guidance action or lease files", async (t) => {
  for (const name of ["actions", "worktrees", "runs"]) {
    const f = await fixture(t, { stateRoot: (root) => root });
    const projectPath = join(f.root, name);
    await rename(f.projectPath, projectPath);
    const before = await readdir(projectPath);
    await assert.rejects(
      f.service.update({ ...f.request("Lesson."), projectPath }),
      { code: "ERR_UNSAFE_STATE_ROOT" },
    );
    assert.deepEqual(await readdir(projectPath), before);
    assert.deepEqual(await readdir(f.root), [name]);
  }
});

test("concurrent ancestor replacement cannot redirect a prepared publication", async (t) => {
  const f = await fixture(t, { initialContent: "Original." });
  const outside = join(f.root, "outside");
  await mkdir(outside);
  await writeFile(join(outside, "rules.md"), "Outside.");
  const service = f.createService({
    async onPublicationBoundary(phase) {
      if (phase === "before-publish") {
        await rename(
          dirname(f.localPath),
          join(f.projectPath, "LOCAL_ARTIFACTS", "moved"),
        );
        await symlink(outside, dirname(f.localPath));
      }
    },
  });
  await assert.rejects(
    service.update(
      f.request("Replacement.", { expectedHash: hash("Original.") }),
    ),
  );
  assert.equal(await readFile(join(outside, "rules.md"), "utf8"), "Outside.");
  assert.equal(
    await readFile(
      join(f.projectPath, "LOCAL_ARTIFACTS", "moved", "rules.md"),
      "utf8",
    ),
    "Original.",
  );
});

test("a project removed during validation is never recreated by a guidance update", async (t) => {
  const f = await fixture(t);
  const movedProject = join(f.root, "moved-project");
  const before = await readdir(f.projectPath);
  const git = createGitService();
  let inspections = 0;
  const service = f.createService({
    git: {
      ...git,
      async inspectPath(input) {
        const result = await git.inspectPath(input);
        if (input.path === f.localPath && ++inspections === 2) {
          await rename(f.projectPath, movedProject);
        }
        return result;
      },
    },
  });
  const input = f.request("Local lesson.");
  await assert.rejects(service.update(input), {
    code: "ERR_UNSAFE_GUIDANCE_PATH",
  });
  await assert.rejects(lstat(f.projectPath), { code: "ENOENT" });
  assert.deepEqual(await readdir(movedProject), before);
  await rename(movedProject, f.projectPath);
  assert.equal((await f.service.update(input)).updated, true);
});

test("replacement refuses a temporary destination that is not ignored", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  await writeFile(
    join(f.projectPath, ".gitignore"),
    "LOCAL_ARTIFACTS/agent-runner/rules.md\n",
  );
  assert.equal(
    (await f.service.read({ projectPath: f.projectPath })).localContent,
    "Before.",
  );
  await assert.rejects(
    f.service.update(f.request("After.", { expectedHash: hash("Before.") })),
    { code: "ERR_GUIDANCE_NOT_IGNORED" },
  );
  assert.equal(await readFile(f.localPath, "utf8"), "Before.");
  assert.deepEqual(await readdir(dirname(f.localPath)), ["rules.md"]);
});

test("a target or temporary file linked after preparation cannot be published", async (t) => {
  for (const target of ["local", "temporary"]) {
    const f = await fixture(t, { initialContent: "Before." });
    const service = f.createService({
      async onPublicationBoundary(phase) {
        if (phase !== "before-publish") return;
        const path =
          target === "local"
            ? f.localPath
            : join(
                dirname(f.localPath),
                (await readdir(dirname(f.localPath))).find((name) =>
                  name.endsWith(".tmp"),
                ),
              );
        await link(path, join(f.root, "linked.md"));
      },
    });
    await assert.rejects(
      service.update(f.request("After.", { expectedHash: hash("Before.") })),
      { code: "ERR_UNSAFE_GUIDANCE_PATH" },
    );
    assert.equal(await readFile(f.localPath, "utf8"), "Before.");
  }
});

test("a substituted temporary inode is never adopted as the writer's publication", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const displaced = join(f.root, "displaced.tmp");
  const service = f.createService({
    async onPublicationBoundary(phase) {
      if (phase !== "writing") return;
      const name = (await readdir(dirname(f.localPath))).find((name) =>
        name.endsWith(".tmp"),
      );
      const path = join(dirname(f.localPath), name);
      await rename(path, displaced);
      await writeFile(path, "After.", { mode: 0o600 });
    },
  });
  await assert.rejects(
    service.update(f.request("After.", { expectedHash: hash("Before.") })),
    { code: "ERR_UNSAFE_GUIDANCE_PATH" },
  );
  assert.equal(await readFile(f.localPath, "utf8"), "Before.");
  assert.equal(await readFile(displaced, "utf8"), "");
});

test("strict replacement input cannot supply common content or omit concurrency and idempotency fields", async (t) => {
  const f = await fixture(t);
  const valid = f.request("Lesson.");
  for (const input of [
    { ...valid, commonContent: "Overwrite common." },
    { ...valid, expectedHash: undefined },
    { ...valid, expectedHash: "a".repeat(64) + "\n" },
    { ...valid, idempotencyKey: undefined },
    { ...valid, localContent: null },
    { ...valid, projectConfigurationPath: "bad\npath" },
  ]) {
    await assert.rejects(f.service.update(input));
  }
  await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
  await assert.rejects(lstat(f.localPath), { code: "ENOENT" });
});
