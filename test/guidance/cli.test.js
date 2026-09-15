import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { main } from "../../src/index.js";
import { fixture } from "./support/index.js";

test("CLI reads and edits complete guidance through explicit project configuration", async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(
    join(f.projectPath, "LOCAL_ARTIFACTS", "custom.json"),
    '{"schemaVersion":1,"artifactRoot":"CUSTOM_ARTIFACTS"}',
  );
  const localContent = "# Local additions\n\nThe whole project lesson.\n";
  const guidance = f.createService({
    env: { EDITOR: "test-editor" },
    temporaryRoot: f.root,
    async launchEditor(_, path) {
      await writeFile(path, localContent);
      return { exitCode: 0, signal: null };
    },
  });
  let output = "";
  let errors = "";
  const options = {
    guidance,
    stdout: {
      write: (chunk) => {
        output += chunk;
      },
    },
    stderr: {
      write: (chunk) => {
        errors += chunk;
      },
    },
    createCommandRunner: () =>
      assert.fail("guidance must not construct a runner"),
  };
  const selectors = [
    "--project",
    f.projectPath,
    "--project-config",
    "LOCAL_ARTIFACTS/custom.json",
  ];
  assert.equal(await main(["guidance", "edit", ...selectors], options), 0);
  assert.equal(output, "Local guidance updated.\n");
  assert.equal(
    await readFile(
      join(f.projectPath, "CUSTOM_ARTIFACTS", "agent-runner", "rules.md"),
      "utf8",
    ),
    localContent,
  );
  output = "";
  assert.equal(await main(["guidance", ...selectors], options), 0);
  const common = await readFile(
    new URL("../../docs/OPERATOR_GUIDE.md", import.meta.url),
    "utf8",
  );
  assert.ok(output.includes(common));
  assert.ok(output.endsWith(localContent));
  assert.equal(errors, "");
});

test("CLI guidance editor failures produce concise errors and preserve local content", async (t) => {
  const f = await fixture(t, { initialContent: "Before." });
  const guidance = f.createService({
    env: { EDITOR: "test-editor" },
    temporaryRoot: f.root,
    async launchEditor(_, path) {
      await writeFile(path, "PRIVATE_EDIT_MARKER");
      return { exitCode: 9, signal: null };
    },
  });
  let errors = "";
  assert.equal(
    await main(["guidance", "edit", "--project", f.projectPath], {
      guidance,
      stdout: { write: () => assert.fail("must not print success") },
      stderr: {
        write: (chunk) => {
          errors += chunk;
        },
      },
    }),
    1,
  );
  assert.match(errors, /editor did not exit successfully/u);
  assert.doesNotMatch(errors, /PRIVATE_EDIT_MARKER|Error:|\n\s+at /u);
  assert.equal(await readFile(f.localPath, "utf8"), "Before.");
});
