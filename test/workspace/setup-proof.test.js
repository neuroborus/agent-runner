import assert from "node:assert/strict";
import test from "node:test";

import { createWorkspaceService } from "../../src/workspace/index.js";

const workspace = createWorkspaceService();
const file = (path, hash = "a".repeat(64)) => ({
  path,
  kind: "file",
  mode: 0o644,
  size: 1,
  hash,
  identity: { device: "1", inode: path, mode: "33188" },
});
const directory = (path) => ({
  path,
  kind: "directory",
  mode: 0o755,
  size: 0,
  hash: null,
});
const snapshot = (entries) => ({
  schemaVersion: 1,
  workspacePath: "/work/project",
  outputPaths: [],
  entries: entries.toSorted((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  ),
  linkResolutions: [],
});

test("compact proof protects complete source, input, control and link evidence beyond the setup limit", () => {
  const before = snapshot([
    directory("/work/project"),
    directory("/work/project/.git"),
    file("/work/project/.git/HEAD"),
    { ...file("/work/project/link"), kind: "symlink" },
    file("/work/task/task.md"),
    ...Array.from({ length: 10_010 }, (_, index) =>
      file(`/work/project/source-${String(index).padStart(5, "0")}`),
    ),
  ]);
  before.linkResolutions = [
    {
      path: "/work/project/link",
      target: "/work/project/source-00000",
      paths: ["/work/project/source-00000"],
    },
  ];
  const destination = "/work/project/setup/procedure.md";
  const proof = workspace.snapshotProof({
    snapshot: before,
    paths: [destination],
  });
  assert.equal(proof.entries.length, 2);
  assert.equal(
    proof.entries.find(({ path }) => path === destination).kind,
    "missing",
  );
  assert.ok(JSON.stringify(proof).length < 2_000);
  workspace.assertSnapshotProof({
    before: proof,
    after: structuredClone(before),
  });
  for (const path of [
    "/work/project/source-10009",
    "/work/task/task.md",
    "/work/project/.git/HEAD",
  ]) {
    for (const change of ["hash", "identity"]) {
      const after = structuredClone(before);
      const entry = after.entries.find((entry) => entry.path === path);
      if (change === "hash") entry.hash = "b".repeat(64);
      else entry.identity.inode = "replacement";
      assert.throws(
        () => workspace.assertSnapshotProof({ before: proof, after }),
        { code: "ERR_WORKSPACE_DRIFT" },
      );
    }
  }
  const after = structuredClone(before);
  after.linkResolutions[0].target = "/work/project/source-10009";
  after.linkResolutions[0].paths = ["/work/project/source-10009"];
  assert.throws(() => workspace.assertSnapshotProof({ before: proof, after }), {
    code: "ERR_WORKSPACE_DRIFT",
  });
  assert.deepEqual(
    proof,
    workspace.snapshotProof({ snapshot: before, paths: [destination] }),
  );
});

test("only exact journaled paths differ; a deferred temporary must have been absent", () => {
  const guide = "/work/project/rules.md";
  const temporary = "/work/project/.rules.temporary.tmp";
  const before = snapshot([directory("/work/project"), file(guide)]);
  const proof = workspace.snapshotProof({ snapshot: before, paths: [guide] });
  const after = snapshot([
    directory("/work/project"),
    file(guide, "b".repeat(64)),
    file(temporary),
  ]);
  assert.throws(() => workspace.assertSnapshotProof({ before: proof, after }), {
    code: "ERR_WORKSPACE_DRIFT",
  });
  workspace.assertSnapshotProof({
    before: proof,
    after,
    allowedPaths: [guide, temporary],
  });
  const occupied = workspace.snapshotProof({
    snapshot: snapshot([...before.entries, file(temporary)]),
    paths: [guide],
  });
  assert.throws(
    () =>
      workspace.assertSnapshotProof({
        before: occupied,
        after,
        allowedPaths: [guide, temporary],
      }),
    { code: "ERR_WORKSPACE_DRIFT" },
  );
  const unrelated = snapshot([...after.entries, file("/work/project/extra")]);
  assert.throws(
    () =>
      workspace.assertSnapshotProof({
        before: proof,
        after: unrelated,
        allowedPaths: [guide, temporary],
      }),
    { code: "ERR_WORKSPACE_DRIFT" },
  );
  const parent = "/work/project/new-directory";
  const directoryProof = workspace.snapshotProof({
    snapshot: before,
    paths: [guide, parent],
  });
  const nested = snapshot([
    ...after.entries,
    directory(parent),
    file(`${parent}/extra`),
  ]);
  assert.throws(
    () =>
      workspace.assertSnapshotProof({
        before: directoryProof,
        after: nested,
        allowedPaths: [guide, temporary, parent],
      }),
    { code: "ERR_WORKSPACE_DRIFT" },
  );
});

test("absence requires complete coverage and cannot be inferred through a file or link", () => {
  const path = "/work/project/setup/procedure.md";
  for (const kind of ["file", "symlink"]) {
    const proof = workspace.snapshotProof({
      snapshot: snapshot([
        directory("/work/project"),
        { ...file("/work/project/setup"), kind },
      ]),
      paths: [path],
    });
    assert.equal(
      proof.entries.find((entry) => entry.path === path),
      undefined,
    );
    assert.equal(
      proof.entries.find((entry) => entry.path === "/work/project/setup").kind,
      kind,
    );
  }
  assert.throws(
    () => workspace.snapshotProof({ snapshot: snapshot([]), paths: [path] }),
    /does not cover/u,
  );
  for (const scope of [{ inspectionPaths: [] }, { excludePaths: ["setup"] }])
    assert.throws(
      () =>
        workspace.snapshotProof({
          snapshot: { ...snapshot([directory("/work/project")]), ...scope },
          paths: [path],
        }),
      /complete workspace snapshot/u,
    );
  assert.throws(
    () =>
      workspace.snapshotProof({
        snapshot: snapshot([directory("/work/project")]),
        paths: Array.from(
          { length: 10_001 },
          (_, index) => `/work/project/destination-${index}`,
        ),
      }),
    { code: "ERR_WORKSPACE_PROOF_CAPACITY" },
  );
});
