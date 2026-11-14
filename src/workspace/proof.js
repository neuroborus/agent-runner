import { createHash } from "node:crypto";
import { dirname } from "node:path";

import { hashRecords } from "./digest.js";
import { assertSafe, location, same, within } from "./paths.js";

const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const missing = (path) => ({
  path,
  kind: "missing",
  mode: null,
  size: 0,
  hash: null,
});

const isHash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const OPTIONAL_SCOPE = [
  "inspectionPaths",
  "inspectionFilesOnly",
  "excludePaths",
];

// Durable baselines retain snapshot scope and fingerprints, while one ordered
// digest replaces per-entry arrays that grow with protected control trees.
export function snapshotBaseline(snapshot) {
  assertSafe(
    snapshot?.schemaVersion === 1 &&
      Array.isArray(snapshot.entries) &&
      Array.isArray(snapshot.linkResolutions),
    "A durable baseline requires a complete workspace snapshot.",
  );
  return {
    schemaVersion: 1,
    workspacePath: snapshot.workspacePath,
    outputPaths: snapshot.outputPaths,
    ...Object.fromEntries(
      OPTIONAL_SCOPE.filter((field) => snapshot[field] !== undefined).map(
        (field) => [field, snapshot[field]],
      ),
    ),
    entryCount: snapshot.entries.length,
    entriesHash: hashRecords(snapshot.entries),
    contentFingerprint: snapshot.contentFingerprint,
    identityFingerprint: snapshot.identityFingerprint,
  };
}

export const isCompactBaseline = (baseline) =>
  baseline?.schemaVersion === 1 && !Object.hasOwn(baseline, "entries");

// Compact equality is the complete entry equality without output allowances;
// those would need the per-entry evidence the baseline deliberately omits.
export function assertBaselineUnchanged({ before, after, allowOutputs }) {
  assertSafe(
    allowOutputs === false &&
      !Object.hasOwn(before, "linkResolutions") &&
      Number.isSafeInteger(before.entryCount) &&
      before.entryCount >= 0 &&
      [
        before.entriesHash,
        before.contentFingerprint,
        before.identityFingerprint,
      ].every(isHash) &&
      Array.isArray(after.entries),
    "A valid compact workspace baseline is required.",
  );
  assertSafe(
    after.entries.length === before.entryCount &&
      hashRecords(after.entries) === before.entriesHash,
    "Workspace content or identity changed outside authorized outputs.",
    "ERR_WORKSPACE_DRIFT",
  );
}

export function snapshotProof({
  snapshot,
  paths = [],
  ignorePaths = [],
  rootPath = null,
}) {
  assertSafe(
    snapshot?.schemaVersion === 1 &&
      snapshot.inspectionPaths === undefined &&
      snapshot.excludePaths === undefined &&
      Array.isArray(snapshot.entries) &&
      Array.isArray(snapshot.linkResolutions),
    "Compact proof requires a complete workspace snapshot.",
  );
  const canonical = (values) => {
    assertSafe(Array.isArray(values), "Proof paths must be an array.");
    return [
      ...new Set(values.map((path) => location(snapshot.workspacePath, path))),
    ].sort();
  };
  paths = canonical(paths);
  ignorePaths = canonical(ignorePaths);
  if (rootPath !== null) rootPath = location(snapshot.workspacePath, rootPath);
  const inScope = (path) => rootPath === null || within(rootPath, path);
  const capacity = (condition) =>
    assertSafe(
      condition,
      "Workspace setup proof exceeds its supported evidence capacity.",
      "ERR_WORKSPACE_PROOF_CAPACITY",
    );
  capacity(paths.length <= 10_000 && ignorePaths.length <= 10_000);
  const source = new Map(snapshot.entries.map((entry) => [entry.path, entry]));
  const retained = new Map();
  for (const path of paths) {
    assertSafe(inScope(path), "Proof evidence escaped its protected scope.");
    let ancestor = path;
    while (!source.has(ancestor) && dirname(ancestor) !== ancestor)
      ancestor = dirname(ancestor);
    const observed = source.get(ancestor);
    assertSafe(
      observed !== undefined,
      "Workspace snapshot does not cover the requested setup destination.",
    );
    if (ancestor === path) retained.set(path, observed);
    else if (["directory", "missing"].includes(observed.kind))
      retained.set(path, missing(path));
    // File/link ancestors remain explicit blockers, never absence evidence.
    for (let parent = ancestor; ; parent = dirname(parent)) {
      if (inScope(parent) && source.has(parent))
        retained.set(parent, source.get(parent));
      if (dirname(parent) === parent) break;
    }
    capacity(retained.size <= 10_000);
  }
  const ignored = new Set(ignorePaths);
  const entries = [...retained.values()]
    .filter(({ path }) => !ignored.has(path))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const selected = new Set(entries.map(({ path }) => path));
  const {
    entries: _entries,
    linkResolutions,
    contentFingerprint: _content,
    identityFingerprint: _identity,
    ...scope
  } = snapshot;
  const proof = {
    schemaVersion: 2,
    workspacePath: snapshot.workspacePath,
    rootPath,
    paths,
    ignorePaths,
    scopeHash: hash(scope),
    entries,
    remainderHash: hashRecords(
      snapshot.entries.filter(
        ({ path }) =>
          inScope(path) && !selected.has(path) && !ignored.has(path),
      ),
    ),
    linkHash: hashRecords(linkResolutions.filter(({ path }) => inScope(path))),
  };
  capacity(Buffer.byteLength(JSON.stringify(proof)) <= 2 * 1024 * 1024);
  return proof;
}

export function assertSnapshotProof({ before, after, allowedPaths = [] }) {
  const fields = [
    "schemaVersion",
    "workspacePath",
    "rootPath",
    "paths",
    "ignorePaths",
    "scopeHash",
    "entries",
    "remainderHash",
    "linkHash",
  ];
  assertSafe(
    before?.schemaVersion === 2 &&
      Object.keys(before).length === fields.length &&
      fields.every((field) => Object.hasOwn(before, field)) &&
      [before.scopeHash, before.remainderHash, before.linkHash].every(
        (value) => typeof value === "string" && /^[a-f0-9]{64}$/u.test(value),
      ) &&
      [before.paths, before.ignorePaths, before.entries].every(
        (values) => Array.isArray(values) && values.length <= 10_000,
      ) &&
      Array.isArray(allowedPaths),
    "A valid compact workspace proof is required.",
  );
  const allowed = new Set(allowedPaths);
  const current = snapshotProof({
    snapshot: after,
    paths: before.paths,
    rootPath: before.rootPath,
    ignorePaths: [
      ...before.ignorePaths,
      ...allowedPaths.filter(
        (path) => !before.entries.some((entry) => entry.path === path),
      ),
    ],
  });
  const immutable = (entries) =>
    entries.filter(({ path }) => !allowed.has(path));
  assertSafe(
    current.workspacePath === before.workspacePath &&
      current.scopeHash === before.scopeHash &&
      current.remainderHash === before.remainderHash &&
      current.linkHash === before.linkHash &&
      same(immutable(current.entries), immutable(before.entries)),
    "Workspace content or identity changed outside journaled setup effects.",
    "ERR_WORKSPACE_DRIFT",
  );
}
