import { createHash } from "node:crypto";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { isDeepStrictEqual } from "node:util";
import { assertInitInspection } from "./inspection-failure.js";

export class InitProposalError extends Error {
  constructor(message) {
    super(message);
    this.name = "InitProposalError";
    this.code = "ERR_INIT_PROPOSAL";
  }
}
export function assertInit(condition, message) {
  if (!condition) throw new InitProposalError(message);
}
export function exact(value, fields) {
  assertInit(
    value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
      Object.keys(value).length === fields.length &&
      fields.every((key) => Object.hasOwn(value, key)),
    "Init record has missing or unsupported fields.",
  );
}
export const digest = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
export const hashText = (value) =>
  createHash("sha256").update(value).digest("hex");
export const isHash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
export const isPath = (value) =>
  typeof value === "string" &&
  isAbsolute(value) &&
  resolve(value) === value &&
  !/[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value);
export const within = (root, path) => {
  const name = relative(root, path);
  return (
    name === "" ||
    (!isAbsolute(name) && name !== ".." && !name.startsWith(`..${sep}`))
  );
};
export const text = (value) =>
  typeof value === "string" &&
  value.trim().length > 0 &&
  value.length <= 100_000 &&
  !/[\0\p{Zl}\p{Zp}]/u.test(value);
export function texts(value) {
  assertInit(
    Array.isArray(value) && value.length <= 256 && value.every(text),
    "Init text list is invalid.",
  );
}
export function questions(value) {
  assertInit(
    Array.isArray(value) && value.length <= 12,
    "Init questions must be bounded.",
  );
  for (const entry of value) {
    exact(entry, ["question", "whyItMatters"]);
    assertInit(
      [entry.question, entry.whyItMatters].every(
        (value) =>
          text(value) && value.length <= 4_000 && !/[\p{Cc}]/u.test(value),
      ),
      "Init material questions need concise plain-text rationale.",
    );
  }
}

export function assertResultSize(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    /* Reject non-serializable results below. */
  }
  assertInit(
    typeof serialized === "string" &&
      Buffer.byteLength(serialized) <= 2 * 1024 * 1024,
    "Init role result must be serializable and at most two MiB.",
  );
}

export function assertProductDecision(value) {
  exact(value, ["question", "options", "whyBlocked", "evidence"]);
  const plainText = (entry) =>
    text(entry) && entry.length <= 4_000 && !/[\p{Cc}]/u.test(entry);
  assertInit(
    [value.question, value.whyBlocked].every(plainText) &&
      Array.isArray(value.options) &&
      value.options.length <= 16 &&
      value.options.every(plainText) &&
      Array.isArray(value.evidence) &&
      value.evidence.length > 0 &&
      value.evidence.length <= 32 &&
      value.evidence.every(plainText),
    "Init product decision requires a bounded material question, rationale and evidence.",
  );
}

// The role envelope is separate from the durable, content-only proposal.
export function normalizeInitRoleResult(result, proposal = false) {
  exact(result, [
    "status",
    "question",
    "options",
    "whyBlocked",
    "evidence",
    ...(proposal
      ? ["summary", "checks", "resources"]
      : ["proposalHash", "findings"]),
  ]);
  const { status, question, options, whyBlocked, evidence, ...content } =
    result;
  if (status === "PRODUCT_DECISION_REQUIRED") {
    const decision = { question, options, whyBlocked, evidence };
    assertProductDecision(decision);
    assertInit(
      proposal
        ? content.summary === "" &&
            Array.isArray(content.checks) &&
            content.checks.length === 0 &&
            Array.isArray(content.resources) &&
            content.resources.length === 0
        : content.proposalHash === "" &&
            Array.isArray(content.findings) &&
            content.findings.length === 0,
      "Init product decision cannot also carry proposal or review approval.",
    );
    return { status, decision };
  }
  assertInit(
    question === "" &&
      whyBlocked === "" &&
      Array.isArray(options) &&
      options.length === 0 &&
      Array.isArray(evidence) &&
      evidence.length === 0 &&
      (proposal
        ? status === "PROPOSAL"
        : ["CLEAN", "FINDINGS"].includes(status)),
    "Init role result has invalid decision fields.",
  );
  return proposal ? content : { status, ...content };
}

export function assertInspection(value) {
  exact(value, [
    "schemaVersion",
    "projectPath",
    "taskPath",
    "artifactRoot",
    "configurationPaths",
    "candidates",
    "documents",
    "controlPaths",
    "roots",
    "entries",
    "scopeBindings",
    "snapshotHash",
  ]);
  assertInit(
    [1, 2].includes(value.schemaVersion) &&
      isHash(value.snapshotHash) &&
      isPath(value.projectPath) &&
      isPath(value.taskPath) &&
      !within(value.projectPath, value.taskPath) &&
      text(value.artifactRoot) &&
      !isAbsolute(value.artifactRoot) &&
      !value.artifactRoot
        .split(/[\\/]/u)
        .some((part) => ["", ".", ".."].includes(part)),
    "Init inspection binding is invalid.",
  );
  assertInit(
    Array.isArray(value.roots) &&
      value.roots.length <= 10_000 &&
      value.roots.every(isPath) &&
      value.roots.includes(value.projectPath) &&
      Array.isArray(value.entries) &&
      value.entries.length <= 10_000,
    "Init inspected destinations are invalid.",
  );
  const seen = new Set();
  for (const entry of value.entries) {
    exact(entry, ["path", "kind", "hash"]);
    assertInit(
      isPath(entry.path) &&
        !seen.has(entry.path) &&
        ["file", "directory", "symlink", "missing"].includes(entry.kind) &&
        (["file", "symlink"].includes(entry.kind)
          ? isHash(entry.hash)
          : entry.hash === null),
      "Init inspected resource is invalid.",
    );
    seen.add(entry.path);
  }
  assertInit(
    Array.isArray(value.configurationPaths) &&
      value.configurationPaths.length <= 10_000 &&
      value.configurationPaths.every(isPath) &&
      Array.isArray(value.controlPaths) &&
      value.controlPaths.length <= 10_000 &&
      value.controlPaths.every(isPath) &&
      Array.isArray(value.candidates) &&
      value.candidates.length <= 32,
    "Init configuration inventory is invalid.",
  );
  const paths = new Set();
  for (const candidate of value.candidates) {
    exact(candidate, [
      "configurationPath",
      "placement",
      "rootPath",
      "artifactPath",
      "protectionHash",
      ...(Object.hasOwn(candidate, "finalizationPath")
        ? ["finalizationPath"]
        : []),
    ]);
    assertInit(
      [
        candidate.configurationPath,
        candidate.rootPath,
        candidate.artifactPath,
      ].every(isPath) &&
        ["integrated", "external"].includes(candidate.placement) &&
        isHash(candidate.protectionHash) &&
        (!Object.hasOwn(candidate, "finalizationPath") ||
          (isPath(candidate.finalizationPath) &&
            within(candidate.rootPath, candidate.finalizationPath))) &&
        !paths.has(candidate.configurationPath) &&
        value.roots.includes(candidate.rootPath) &&
        within(candidate.rootPath, candidate.configurationPath) &&
        within(candidate.rootPath, candidate.artifactPath) &&
        (candidate.placement === "integrated"
          ? candidate.rootPath === value.projectPath
          : !within(value.projectPath, candidate.rootPath) &&
            !within(candidate.rootPath, value.projectPath)),
      "Init candidate binding is invalid.",
    );
    paths.add(candidate.configurationPath);
  }
  exact(value.documents, ["instructions", "checks", "skills", "guidance"]);
  for (const entries of Object.values(value.documents)) {
    assertInit(
      Array.isArray(entries) && entries.length <= 256,
      "Init evidence inventory is invalid.",
    );
    for (const entry of entries) {
      exact(entry, ["path", "hash"]);
      assertInit(
        isPath(entry.path) && isHash(entry.hash),
        "Init evidence is invalid.",
      );
    }
  }
  assertInit(
    Array.isArray(value.scopeBindings) && value.scopeBindings.length <= 10_000,
    "Init scope bindings are invalid.",
  );
  const scopes = new Set();
  for (const binding of value.scopeBindings) {
    exact(binding, ["path", "hash"]);
    assertInit(
      isPath(binding.path) && isHash(binding.hash) && !scopes.has(binding.path),
      "Init scope binding is invalid.",
    );
    scopes.add(binding.path);
  }
  assertInit(
    [
      ...value.roots,
      value.taskPath,
      ...value.configurationPaths,
      ...value.controlPaths,
    ].every((path) => [...scopes].some((scope) => within(scope, path))),
    "Init inspection omits a protected scope binding.",
  );
  if (value.schemaVersion === 2)
    assertInit(
      Buffer.byteLength(JSON.stringify(value)) <= 2 * 1024 * 1024 &&
        value.roots.every((path) => seen.has(path)),
      "Init setup evidence exceeds capacity or omits a destination root.",
    );
}

// Selection edits may add inspected scopes, never replace prior evidence.
export function assertInspectionExtension(before, after) {
  const contains = (oldValues, newValues, key) => {
    const current = new Map(newValues.map((value) => [key(value), value]));
    return oldValues.every((value) =>
      isDeepStrictEqual(value, current.get(key(value))),
    );
  };
  assertInitInspection(
    [
      "schemaVersion",
      "projectPath",
      "taskPath",
      "artifactRoot",
      "configurationPaths",
    ].every((key) => isDeepStrictEqual(before[key], after[key])) &&
      ["roots", "controlPaths"].every((key) =>
        contains(before[key], after[key], (value) => value),
      ) &&
      contains(
        before.candidates,
        after.candidates,
        (value) => value.configurationPath,
      ) &&
      ["entries", "scopeBindings"].every((key) =>
        contains(before[key], after[key], (value) => value.path),
      ) &&
      Object.keys(before.documents).every((key) =>
        contains(
          before.documents[key],
          after.documents[key],
          (value) => value.path,
        ),
      ) &&
      (before.snapshotHash === after.snapshotHash ||
        after.scopeBindings.length > before.scopeBindings.length),
    "workspace_changed",
  );
}

// Match workspace discovery before applying any provider-directory exception.
export function assertOutsideBareGitMetadata(inspection, path) {
  assertInit(
    !inspection.controlPaths.some(
      (root) =>
        within(root, path) &&
        [
          ["HEAD", ["file", "symlink"]],
          ["objects", ["directory", "symlink"]],
          ["refs", ["directory", "symlink"]],
        ].every(([name, kinds]) =>
          inspection.entries.some(
            (entry) =>
              entry.path === join(root, name) && kinds.includes(entry.kind),
          ),
        ),
    ),
    "Init cannot publish inside bare Git metadata.",
  );
}

// Only a procedure created by this setup may be repaired against its verified
// prepared baseline. A later run cannot acquire authority over an existing skill.
export function isFinalizationRepair(state, resource) {
  return (
    resource.kind === "finalization" &&
    resource.path === state.createdFinalizationPath &&
    Array.isArray(state.setupBaseline?.snapshot?.entries) &&
    state.setupBaseline.snapshot.entries.some(
      (entry) =>
        entry.path === resource.path &&
        entry.kind === "file" &&
        entry.hash === resource.beforeHash,
    )
  );
}

export function normalizeProposal(value, state) {
  assertResultSize(value);
  exact(value, ["summary", "checks", "resources"]);
  assertInit(text(value.summary), "Init proposal summary is required.");
  texts(value.checks);
  assertInit(
    Array.isArray(value.resources) &&
      value.resources.length > 0 &&
      value.resources.length <= 64,
    "Init proposal needs a bounded resource inventory.",
  );
  const paths = [];
  for (const resource of value.resources) {
    exact(resource, ["path", "kind", "action", "beforeHash", "content"]);
    assertInit(
      isPath(resource.path) &&
        resource.path !== state.selection.rootPath &&
        within(state.selection.rootPath, resource.path) &&
        !relative(state.selection.rootPath, resource.path)
          .split(sep)
          .some((part) => [".git", ".codex", ".claude.json"].includes(part)) &&
        [
          "configuration",
          "artifacts",
          "finalization",
          "guidance",
          "ignore",
        ].includes(resource.kind) &&
        ["create", "replace", "reuse"].includes(resource.action) &&
        (resource.beforeHash === null || isHash(resource.beforeHash)) &&
        typeof resource.content === "string" &&
        resource.content.length <= 100_000,
      "Init resource is invalid or escapes selected infrastructure.",
    );
    assertInit(
      (resource.action === "create") === (resource.beforeHash === null),
      "Init resource action must bind its inspected prior content.",
    );
    assertInit(
      !paths.includes(resource.path),
      "Init proposal resources overlap.",
    );
    paths.push(resource.path);
    const observed = state.inspection.entries.find(
      (entry) => entry.path === resource.path,
    );
    assertInit(
      state.inspection.schemaVersion === 1 || observed !== undefined,
      "Init resource lacks explicit inspected destination evidence.",
    );
    assertInit(
      !state.inspection.entries.some(
        (entry) =>
          entry.kind === "symlink" && within(entry.path, resource.path),
      ),
      "Init cannot publish through a symbolic link.",
    );
    assertInit(
      !state.inspection.entries.some(
        (entry) =>
          entry.kind === "file" &&
          entry.path !== resource.path &&
          within(entry.path, resource.path),
      ),
      "Init resource has a file ancestor.",
    );
    assertInit(
      resource.kind === "artifacts"
        ? resource.content === "" &&
            resource.action !== "replace" &&
            (!observed || ["missing", "directory"].includes(observed.kind))
        : !observed || ["missing", "file"].includes(observed.kind),
      "Init artifacts must remain a directory and file resources cannot replace a directory.",
    );
    const beforeHash =
      !observed || observed.kind === "missing"
        ? null
        : observed.kind === "file"
          ? observed.hash
          : digest({ kind: observed.kind });
    assertInit(
      resource.beforeHash === beforeHash,
      "Init resource prior content differs from inspection.",
    );
    if (resource.action === "reuse" && observed?.kind === "file")
      assertInit(
        hashText(resource.content) === beforeHash,
        "Init reused content must remain unchanged.",
      );
    if (resource.kind === "configuration")
      assertInit(
        resource.path === state.selection.configurationPath,
        "Init configuration destination changed.",
      );
    if (resource.kind === "artifacts")
      assertInit(
        resource.path === state.selection.artifactPath,
        "Init artifact destination changed.",
      );
    if (resource.kind === "guidance")
      assertInit(
        resource.path ===
          join(state.selection.artifactPath, "agent-runner", "rules.md"),
        "Init guidance destination changed.",
      );
    if (resource.kind === "finalization")
      assertInit(
        resource.path.endsWith(".md"),
        "Init finalization must be a Markdown procedure.",
      );
    if (resource.kind === "ignore")
      assertInit(
        state.selection.placement === "integrated" &&
          resource.path === join(state.selection.rootPath, ".gitignore"),
        "Only integrated init can propose the target ignore file.",
      );
    if (resource.action !== "reuse") {
      assertOutsideBareGitMetadata(state.inspection, resource.path);
      assertInit(
        !state.inspection.controlPaths.some(
          (path) =>
            basename(path) === ".git" &&
            within(state.selection.rootPath, path) &&
            dirname(path) !== state.selection.rootPath &&
            within(dirname(path), resource.path),
        ),
        "Init cannot publish into a nested Git worktree with a different exclusion key.",
      );
      const skillRoots = [".agents", ".claude"].map((name) =>
        join(state.selection.rootPath, name),
      );
      const finalizationSkill =
        resource.kind === "finalization" &&
        skillRoots.some((root) =>
          ["SKILL.md", "RUNNER.md"].some(
            (name) =>
              resource.path === join(root, "skills", "finalization", name),
          ),
        );
      assertInit(
        (finalizationSkill ||
          !relative(state.selection.rootPath, resource.path)
            .split(sep)
            .some((part) => [".agents", ".claude"].includes(part))) &&
          !state.inspection.controlPaths.some(
            (path) =>
              (within(path, resource.path) || within(resource.path, path)) &&
              !(finalizationSkill && skillRoots.includes(path)),
          ),
        "Init cannot write Git or provider controls outside the finalization skill.",
      );
      assertInit(
        !state.inspection.configurationPaths.some(
          (path) => within(path, resource.path) || within(resource.path, path),
        ),
        "Init cannot write configuration resolved for this run.",
      );
      assertInit(
        !state.inspection.documents.skills.some(
          ({ path }) =>
            (within(resource.path, path) || within(path, resource.path)) &&
            !(path === resource.path && isFinalizationRepair(state, resource)),
        ),
        "Init must preserve existing skills.",
      );
      assertInit(
        ![
          ...["task.md", "context.md", "clarifications.md"].map((name) =>
            join(state.inspection.taskPath, name),
          ),
          ...state.inspection.documents.instructions.map(({ path }) => path),
          ...state.inspection.documents.checks.map(({ path }) => path),
        ].some(
          (path) => within(path, resource.path) || within(resource.path, path),
        ),
        "Init cannot write its protected setup inputs.",
      );
    }
  }
  for (const resource of value.resources) {
    if (
      value.resources.some(
        (other) => other !== resource && within(resource.path, other.path),
      )
    )
      assertInit(
        resource.kind === "artifacts" &&
          resource.content === "" &&
          resource.action !== "replace",
        "Only an artifact directory may contain other proposed resources.",
      );
  }
  assertInit(
    ["configuration", "artifacts", "finalization", "guidance"].every(
      (kind) =>
        value.resources.filter((resource) => resource.kind === kind).length ===
        1,
    ),
    "Init proposal requires exactly one configuration, artifacts, finalization and guidance resource.",
  );
  return structuredClone(value);
}
