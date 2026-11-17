import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { createWorkspaceService } from "../../../src/workspace/index.js";
import { customWorkspace } from "../src/custom-workspace.js";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const root = "/workspace";
const reports = `${root}/reports`;
const exports = `${root}/exports`;
const artifact = `${root}/artifacts/clarifications.md`;
const identity = (inode) => ({ device: "1", inode: String(inode), mode: "1" });
const directory = (path, inode) => ({
  path,
  kind: "directory",
  mode: 0o755,
  size: 0,
  hash: null,
  identity: identity(inode),
});
const file = (path, text, inode) => ({
  path,
  kind: "file",
  mode: 0o644,
  size: text.length,
  hash: sha(text),
  identity: identity(inode),
  modifiedNs: "1",
  changedNs: "1",
});
const BASE = [
  directory(root, 1),
  directory(`${root}/artifacts`, 2),
  file(artifact, "Clarifications.\n", 3),
  file(`${root}/source.md`, "Evidence.\n", 4),
  directory(exports, 5),
];
const prepared = { identity: identity(7) };
const missingIntent = { path: reports, before: { exists: false } };
const existingIntent = { path: reports, before: { exists: true } };
const allowedPaths = [artifact];

// Injects the same complete/projection pair that runner directory safety
// returns from one inspection; the identity fingerprint covers artifacts.
function fixture(entries = BASE) {
  const workspaceService = createWorkspaceService();
  let current = entries;
  return {
    set entries(value) {
      current = value;
    },
    async outputBaseline({ allowedPaths = [] } = {}) {
      const sorted = [...current].sort((left, right) =>
        left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
      );
      const snapshot = {
        schemaVersion: 1,
        workspacePath: root,
        outputPaths: [exports, reports],
        entries: sorted.filter(
          ({ path }) =>
            !allowedPaths.some(
              (root) => path === root || path.startsWith(`${root}/`),
            ),
        ),
        linkResolutions: [],
        contentFingerprint: sha(JSON.stringify(sorted)),
        identityFingerprint: sha(JSON.stringify(sorted)),
        allowedPaths,
        projectPath: root,
      };
      return {
        snapshot,
        baseline: {
          ...workspaceService.outputBaseline(snapshot),
          allowedPaths,
          projectPath: root,
        },
      };
    },
  };
}

test("compact preparation accepts an exact empty root from a derived missing record", async () => {
  const workspace = fixture();
  const facade = customWorkspace(workspace, root);
  const before = await facade.snapshot({ allowedPaths });
  assert.equal(Object.hasOwn(before, "entries"), false);
  assert.deepEqual(before.outputs[1].entry, {
    path: reports,
    kind: "missing",
    mode: null,
    size: 0,
    hash: null,
  });
  // The prepared root arrives together with an authorized artifact edit.
  workspace.entries = [
    ...BASE.filter(({ path }) => path !== artifact),
    file(artifact, "Edited clarifications.\n", 3),
    directory(reports, 7),
  ];
  const after = await facade.preparationSnapshot(before, {
    intent: missingIntent,
    prepared,
  });
  assert.notEqual(after.identityFingerprint, before.identityFingerprint);
  assert.deepEqual(after.outputs[1], {
    path: reports,
    entry: directory(reports, 7),
    descendantCount: 0,
    descendantsHash: before.outputs[1].descendantsHash,
  });
  assert.deepEqual(
    (await facade.completeSnapshot({ allowedPaths })).entries.map(
      ({ path }) => path,
    ),
    [root, `${root}/artifacts`, exports, reports, `${root}/source.md`],
  );
});

test("compact existing-root preparation ignores only the artifact-sensitive identity", async () => {
  const workspace = fixture([...BASE, directory(reports, 7)]);
  const facade = customWorkspace(workspace, root);
  const before = await facade.snapshot({ allowedPaths });
  workspace.entries = [
    ...BASE.filter(({ path }) => path !== artifact),
    file(artifact, "Edited clarifications.\n", 3),
    directory(reports, 7),
  ];
  const after = await facade.preparationSnapshot(before, {
    intent: existingIntent,
    prepared: { identity: identity(7) },
  });
  assert.notEqual(after.identityFingerprint, before.identityFingerprint);
  assert.deepEqual(
    { ...after, identityFingerprint: before.identityFingerprint },
    before,
  );
});

test("compact preparation rejects drift outside its exact empty root", async () => {
  const cases = [
    ["remainder drift", [file(`${root}/source.md`, "Changed.\n", 4)]],
    ["other-output drift", [file(`${exports}/table.md`, "Row.\n", 8)]],
    ["non-empty root", [file(`${reports}/early.md`, "Early.\n", 8)]],
  ];
  for (const [name, extra] of cases) {
    const workspace = fixture();
    const facade = customWorkspace(workspace, root);
    const before = await facade.snapshot({ allowedPaths });
    workspace.entries = [
      ...BASE.filter(({ path }) => !extra.some((entry) => entry.path === path)),
      ...extra,
      directory(reports, 7),
    ];
    await assert.rejects(
      facade.preparationSnapshot(before, { intent: missingIntent, prepared }),
      { code: "ERR_READ_ONLY_REPOSITORY_CHANGED" },
      name,
    );
  }
  for (const [name, created] of [
    ["wrong identity", directory(reports, 9)],
    ["non-directory root", file(reports, "Report.\n", 7)],
  ]) {
    const workspace = fixture();
    const facade = customWorkspace(workspace, root);
    const before = await facade.snapshot({ allowedPaths });
    workspace.entries = [...BASE, created];
    await assert.rejects(
      facade.preparationSnapshot(before, { intent: missingIntent, prepared }),
      { code: "ERR_READ_ONLY_REPOSITORY_CHANGED" },
      name,
    );
  }
  const existing = fixture([...BASE, directory(reports, 7)]);
  const facade = customWorkspace(existing, root);
  const before = await facade.snapshot({ allowedPaths });
  await assert.rejects(
    facade.preparationSnapshot(before, { intent: missingIntent, prepared }),
    { code: "ERR_READ_ONLY_REPOSITORY_CHANGED" },
    "prior non-missing root",
  );
  existing.entries = [
    ...BASE,
    directory(reports, 7),
    file(`${reports}/early.md`, "Early.\n", 8),
  ];
  await assert.rejects(
    facade.preparationSnapshot(before, {
      intent: existingIntent,
      prepared: { identity: identity(7) },
    }),
    { code: "ERR_READ_ONLY_REPOSITORY_CHANGED" },
    "existing-root drift",
  );
  const absent = fixture();
  const unrecorded = await customWorkspace(absent, root).snapshot({
    allowedPaths,
  });
  absent.entries = [...BASE, directory(reports, 7)];
  await assert.rejects(
    customWorkspace(absent, root).preparationSnapshot(
      { ...unrecorded, outputs: unrecorded.outputs.slice(0, 1) },
      { intent: missingIntent, prepared },
    ),
    { code: "ERR_READ_ONLY_REPOSITORY_CHANGED" },
    "missing record",
  );
});

test("compact interrupted reconciliation compares complete filtered evidence", async () => {
  const workspace = fixture([...BASE, directory(reports, 7)]);
  const facade = customWorkspace(workspace, root);
  const before = await facade.snapshot({ allowedPaths });
  assert.deepEqual(
    await facade.reconcileInterrupted(before, { allowWorkspaceChanges: false }),
    before,
  );
  workspace.entries = [
    ...BASE,
    directory(reports, 7),
    file(`${reports}/summary.md`, "Summary.\n", 8),
  ];
  await assert.rejects(
    facade.reconcileInterrupted(before, { allowWorkspaceChanges: false }),
    { code: "ERR_READ_ONLY_REPOSITORY_CHANGED" },
  );
  const after = await facade.reconcileInterrupted(before, {
    allowWorkspaceChanges: true,
  });
  assert.equal(after.outputs[1].descendantCount, 1);
  assert.equal(after.remainderHash, before.remainderHash);
  await assert.rejects(
    facade.reconcileInterrupted(
      await facade.completeSnapshot({ allowedPaths }),
      { allowWorkspaceChanges: true },
    ),
    { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
  );
});

test("legacy full baselines keep entry comparison and stop explicitly above capacity", async () => {
  const workspace = fixture();
  const complete = await customWorkspace(workspace, root).completeSnapshot({
    allowedPaths,
  });
  const facade = customWorkspace(workspace, root, complete);
  const before = await facade.snapshot({ allowedPaths });
  assert.deepEqual(before, complete);
  workspace.entries = [...BASE, directory(reports, 7)];
  const after = await facade.preparationSnapshot(before, {
    intent: missingIntent,
    prepared,
  });
  assert.deepEqual(after.entries.at(-2), directory(reports, 7));
  await assert.rejects(
    facade.preparationSnapshot(before, {
      intent: missingIntent,
      prepared: { identity: identity(9) },
    }),
    { code: "ERR_READ_ONLY_REPOSITORY_CHANGED" },
  );
  await assert.rejects(
    facade.reconcileInterrupted(before, { allowWorkspaceChanges: false }),
    { code: "ERR_READ_ONLY_REPOSITORY_CHANGED" },
  );
  workspace.entries = [
    ...BASE,
    directory(reports, 7),
    ...Array.from({ length: 10_001 }, (_, index) =>
      file(`${reports}/item-${index}.md`, "", 10 + index),
    ),
  ];
  await assert.rejects(facade.snapshot({ allowedPaths }), {
    code: "ERR_CUSTOM_BASELINE_CAPACITY",
  });
  await assert.rejects(
    facade.reconcileInterrupted(before, { allowWorkspaceChanges: true }),
    { code: "ERR_CUSTOM_BASELINE_CAPACITY" },
  );
  assert.equal(
    (await facade.completeSnapshot({ allowedPaths })).entries.length,
    10_006,
  );
  const compact = await customWorkspace(workspace, root).snapshot({
    allowedPaths,
  });
  assert.equal(compact.outputs[1].descendantCount, 10_001);
});
