import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import test from "node:test";

import { EditorError, MAX_GUIDANCE_BYTES } from "../../src/index.js";
import { fixture } from "./support/index.js";

const success = Object.freeze({ exitCode: 0, signal: null });
const hash = (content) => createHash("sha256").update(content).digest("hex");

function editor(f, launchEditor, options = {}) {
  return f.createService({
    env: { VISUAL: "preferred", EDITOR: "fallback" },
    temporaryRoot: f.root,
    launchEditor,
    ...options,
  });
}

test("whole-document editing uses an owner-only external copy and publishes through the shared writer", async (t) => {
  const f = await fixture(t, { initialContent: "Before.\n" });
  let temporary;
  const receipt = await editor(f, async (command, path) => {
    assert.equal(command, "preferred");
    temporary = path;
    assert.ok(relative(f.projectPath, path).startsWith(".."));
    assert.equal((await lstat(dirname(path))).mode & 0o777, 0o700);
    assert.equal((await lstat(path)).mode & 0o777, 0o600);
    assert.equal(await readFile(path, "utf8"), "Before.\n");
    await writeFile(path, "# Consolidated\n\nA complete café lesson.\n");
    assert.equal(await readFile(f.localPath, "utf8"), "Before.\n");
    return success;
  }).edit({ projectPath: f.projectPath });
  assert.equal(receipt.updated, true);
  assert.equal(
    receipt.localHash,
    hash("# Consolidated\n\nA complete café lesson.\n"),
  );
  assert.equal(
    await readFile(f.localPath, "utf8"),
    "# Consolidated\n\nA complete café lesson.\n",
  );
  await assert.rejects(lstat(dirname(temporary)), { code: "ENOENT" });
});

test("unchanged editor closes are no-ops for missing, empty, and non-empty documents", async (t) => {
  for (const initialContent of [undefined, "", "Before."]) {
    const f = await fixture(t, { initialContent });
    const before =
      initialContent === undefined ? null : await lstat(f.localPath);
    const receipt = await editor(f, async () => success).edit({
      projectPath: f.projectPath,
    });
    assert.equal(receipt.updated, false);
    assert.equal(
      receipt.localHash,
      initialContent === undefined ? null : hash(initialContent),
    );
    if (before === null) {
      await assert.rejects(lstat(join(f.projectPath, "LOCAL_ARTIFACTS")), {
        code: "ENOENT",
      });
    } else {
      assert.equal((await lstat(f.localPath)).ino, before.ino);
      assert.equal(await readFile(f.localPath, "utf8"), initialContent);
    }
    assert.ok(
      (await readdir(f.root)).every(
        (name) => !name.startsWith("agent-runner-guidance-edit-"),
      ),
    );
  }
});

test("an empty edited document removes all additions", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const receipt = await editor(f, async (_, path) => {
    await writeFile(path, "");
    return success;
  }).edit({ projectPath: f.projectPath });
  assert.equal(receipt.updated, true);
  assert.equal(receipt.localHash, hash(""));
  assert.equal(await readFile(f.localPath, "utf8"), "");
});

test("failed or signalled editor closes preserve local guidance and never launch fallback", async (t) => {
  for (const outcome of [
    { exitCode: 7, signal: null },
    { exitCode: null, signal: "SIGTERM" },
  ]) {
    const f = await fixture(t, { initialContent: "Before." });
    const launched = [];
    let temporary;
    await assert.rejects(
      editor(f, async (command, path) => {
        launched.push(command);
        temporary = path;
        await writeFile(path, "Must not publish.");
        return outcome;
      }).edit({ projectPath: f.projectPath }),
      { code: "ERR_GUIDANCE_EDITOR_FAILED" },
    );
    assert.deepEqual(launched, ["preferred"]);
    assert.equal(await readFile(f.localPath, "utf8"), "Before.");
    await assert.rejects(lstat(dirname(temporary)), { code: "ENOENT" });
    await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
  }
});

test("guidance falls back only before launch and reports missing editors without creating additions", async (t) => {
  const f = await fixture(t);
  const launched = [];
  await editor(f, async (command, path) => {
    launched.push(command);
    if (command === "preferred")
      throw new EditorError("Unavailable.", { code: "ERR_EDITOR_UNAVAILABLE" });
    await writeFile(path, "Fallback lesson.");
    return success;
  }).edit({ projectPath: f.projectPath });
  assert.deepEqual(launched, ["preferred", "fallback"]);
  assert.equal(await readFile(f.localPath, "utf8"), "Fallback lesson.");
  await assert.rejects(
    editor(f, async () => assert.fail("must not launch"), { env: {} }).edit({
      projectPath: f.projectPath,
    }),
    { code: "ERR_EDITOR_UNAVAILABLE" },
  );
  assert.ok(
    (await readdir(f.root)).every(
      (name) => !name.startsWith("agent-runner-guidance-edit-"),
    ),
  );
});

test("unsafe, deleted, malformed, or oversized edited copies are never published", async (t) => {
  for (const kind of [
    "symlink",
    "hardlink",
    "directory",
    "missing",
    "encoding",
    "control",
    "oversized",
  ]) {
    await t.test(kind, async (t) => {
      const f = await fixture(t, { initialContent: "Before." });
      const sentinel = join(f.root, "sentinel.md");
      await writeFile(sentinel, "Outside.");
      let temporary;
      await assert.rejects(
        editor(f, async (_, path) => {
          temporary = path;
          if (["symlink", "hardlink", "directory", "missing"].includes(kind))
            await rm(path);
          if (kind === "symlink") await symlink(sentinel, path);
          if (kind === "hardlink") await link(sentinel, path);
          if (kind === "directory") await mkdir(path);
          if (kind === "encoding")
            await writeFile(path, Buffer.from([0xc3, 0x28]));
          if (kind === "control") await writeFile(path, "bad\u0000");
          if (kind === "oversized")
            await writeFile(path, "x".repeat(MAX_GUIDANCE_BYTES + 1));
          return success;
        }).edit({ projectPath: f.projectPath }),
      );
      assert.equal(await readFile(f.localPath, "utf8"), "Before.");
      assert.equal(await readFile(sentinel, "utf8"), "Outside.");
      await assert.rejects(lstat(dirname(temporary)), { code: "ENOENT" });
    });
  }
});

test("changed and unchanged editor closes reject another writer's newer document", async (t) => {
  for (const changed of [false, true]) {
    const f = await fixture(t, { initialContent: "Before." });
    await assert.rejects(
      editor(f, async (_, path) => {
        await f.service.update(
          f.request("Other writer.", { expectedHash: hash("Before.") }),
        );
        if (changed) await writeFile(path, "Stale editor.");
        return success;
      }).edit({ projectPath: f.projectPath }),
      { code: "ERR_GUIDANCE_STALE" },
    );
    assert.equal(await readFile(f.localPath, "utf8"), "Other writer.");
  }
});

test("configuration drift cannot redirect changed or unchanged editor results", async (t) => {
  for (const changed of [false, true]) {
    const f = await fixture(t, { initialContent: "Before." });
    await assert.rejects(
      editor(f, async (_, path) => {
        f.setConfiguration({ artifactRoot: "CUSTOM_ARTIFACTS" });
        if (changed) await writeFile(path, "Redirected.");
        return success;
      }).edit({ projectPath: f.projectPath }),
      { code: "ERR_GUIDANCE_CONFIGURATION_CHANGED" },
    );
    assert.equal(await readFile(f.localPath, "utf8"), "Before.");
    await assert.rejects(lstat(join(f.projectPath, "CUSTOM_ARTIFACTS")), {
      code: "ENOENT",
    });
  }
});

test("execution taking ownership while the editor is open blocks publication", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  let lease;
  try {
    await assert.rejects(
      editor(f, async () => {
        lease = await f.store.acquireWorktreeLease(f.projectPath, randomUUID());
        return success;
      }).edit({ projectPath: f.projectPath }),
      { code: "ERR_WORKTREE_LEASED" },
    );
    assert.equal(await readFile(f.localPath, "utf8"), "Before.");
  } finally {
    await lease?.release();
  }
});

test("a destination linked during an unchanged edit is rejected", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  await assert.rejects(
    editor(f, async () => {
      await link(f.localPath, join(f.root, "linked.md"));
      return success;
    }).edit({ projectPath: f.projectPath }),
    { code: "ERR_UNSAFE_GUIDANCE_PATH" },
  );
  assert.equal(await readFile(f.localPath, "utf8"), "Before.");
});

test("guidance refuses temporary storage inside the project before launching an editor", async (t) => {
  const f = await fixture(t);
  const before = await readdir(f.projectPath);
  await assert.rejects(
    editor(f, async () => assert.fail("must not launch"), {
      temporaryRoot: f.projectPath,
    }).edit({ projectPath: f.projectPath }),
    { code: "ERR_UNSAFE_GUIDANCE_PATH" },
  );
  assert.deepEqual(await readdir(f.projectPath), before);
});
