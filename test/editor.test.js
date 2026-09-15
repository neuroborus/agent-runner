import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { EditorError, openConfiguredEditor } from "../src/index.js";

async function fixture(t, source) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-editor-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, "editor with spaces");
  await mkdir(directory);
  const script = join(directory, "edit.mjs");
  await writeFile(script, source);
  return {
    command: `${JSON.stringify(process.execPath)} ${JSON.stringify(script)}`,
    path: join(root, "local document.md"),
  };
}

test("the preferred editor receives quoted and empty arguments without a shell", async (t) => {
  const f = await fixture(
    t,
    'import { writeFileSync } from "node:fs"; writeFileSync(process.argv.at(-1), JSON.stringify(process.argv.slice(2)));',
  );
  const outcome = await openConfiguredEditor(f.path, {
    env: {
      VISUAL: `${f.command} "two words" '' '$(not-a-command)'`,
      EDITOR: "unused",
    },
  });
  assert.deepEqual(outcome, { exitCode: 0, signal: null });
  assert.deepEqual(JSON.parse(await readFile(f.path, "utf8")), [
    "two words",
    "",
    "$(not-a-command)",
    f.path,
  ]);
});

test("fallback is used only when the preferred editor cannot launch", async (t) => {
  const f = await fixture(
    t,
    'import { writeFileSync } from "node:fs"; writeFileSync(process.argv.at(-1), "Edited.");',
  );
  for (const preferred of [
    "agent-runner-nonexistent-editor",
    "'invalid quoting",
    "invalid\ncommand",
  ]) {
    assert.deepEqual(
      await openConfiguredEditor(f.path, {
        env: { VISUAL: preferred, EDITOR: f.command },
      }),
      { exitCode: 0, signal: null },
    );
    assert.equal(await readFile(f.path, "utf8"), "Edited.");
  }
});

test("failed and signalled editor closes report their outcome without fallback", async (t) => {
  for (const [source, expected] of [
    ["process.exitCode = 7;", { exitCode: 7, signal: null }],
    [
      'process.kill(process.pid, "SIGTERM");',
      { exitCode: null, signal: "SIGTERM" },
    ],
  ]) {
    const f = await fixture(t, source);
    // A nonexistent fallback would return null if a failed close were retried.
    const outcome = await openConfiguredEditor(f.path, {
      env: { VISUAL: f.command, EDITOR: "agent-runner-nonexistent-editor" },
    });
    assert.deepEqual(outcome, expected);
  }
});

test("unavailable and duplicate candidates remain bounded while unexpected launch errors propagate", async () => {
  const launches = [];
  const outcome = await openConfiguredEditor("document.md", {
    env: { VISUAL: "missing", EDITOR: "missing" },
    launchEditor: async (command) => {
      launches.push(command);
      throw new EditorError("Unavailable.", { code: "ERR_EDITOR_UNAVAILABLE" });
    },
  });
  assert.equal(outcome, null);
  assert.deepEqual(launches, ["missing"]);
  const error = new Error("Unexpected launch failure.");
  await assert.rejects(
    openConfiguredEditor("document.md", {
      env: { VISUAL: "preferred", EDITOR: "fallback" },
      launchEditor: async () => {
        throw error;
      },
    }),
    (cause) => cause === error,
  );
});
