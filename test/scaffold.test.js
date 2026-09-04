import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readdir, readFile, readlink } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import packageMetadata from "../package.json" with { type: "json" };

const executeFile = promisify(execFile);
const REPOSITORY_PATH = fileURLToPath(new URL("../", import.meta.url));

const SOURCE_DIRECTORIES = [
  new URL("../src/", import.meta.url),
  new URL("../packages/commit-plan/src/", import.meta.url),
  new URL("../pipelines/plan-authoring/src/", import.meta.url),
  new URL("../pipelines/plan-execution/src/", import.meta.url),
  new URL("../pipelines/polishing/src/", import.meta.url),
];
const PACKAGE_METADATA_FILES = [
  new URL("../package.json", import.meta.url),
  new URL("../packages/commit-plan/package.json", import.meta.url),
  new URL("../pipelines/plan-authoring/package.json", import.meta.url),
  new URL("../pipelines/plan-execution/package.json", import.meta.url),
  new URL("../pipelines/polishing/package.json", import.meta.url),
];
const SKILLS_DIRECTORY = new URL("../.agents/skills/", import.meta.url);
const NODE_RANGE_DOCUMENTS = [
  new URL("../AGENTS.md", import.meta.url),
  new URL("../README.md", import.meta.url),
  new URL("../pipelines/plan-execution/docs/SPEC.md", import.meta.url),
  new URL("../pipelines/polishing/docs/SPEC.md", import.meta.url),
];

async function findJavaScriptModules(directoryUrl) {
  const entries = await readdir(directoryUrl, { withFileTypes: true });
  const modules = [];

  for (const entry of entries.sort((left, right) =>
    left.name.localeCompare(right.name),
  )) {
    if (entry.isDirectory()) {
      const nestedModules = await findJavaScriptModules(
        new URL(`${entry.name}/`, directoryUrl),
      );
      modules.push(...nestedModules);
    } else if (entry.isFile() && entry.name.endsWith(".js")) {
      modules.push(new URL(entry.name, directoryUrl));
    }
  }

  return modules;
}

function parseFrontmatter(document, skillPath) {
  const match = /^---\r?\n(?<body>[\s\S]*?)\r?\n---(?:\r?\n|$)/u.exec(document);
  assert.ok(match, `${skillPath} must start with YAML frontmatter`);

  const fields = Object.create(null);
  for (const line of match.groups.body.split(/\r?\n/u)) {
    const field = /^(?<key>[a-z][a-z0-9-]*):\s+(?<value>.+)$/u.exec(line);
    assert.ok(field, `${skillPath} has unsupported frontmatter: ${line}`);
    assert.equal(
      fields[field.groups.key],
      undefined,
      `${skillPath} repeats ${field.groups.key}`,
    );
    fields[field.groups.key] = field.groups.value;
  }

  return {
    content: document.slice(match[0].length).trim(),
    fields,
  };
}

test("every root and workspace source module can be imported", async () => {
  const sourceModules = (
    await Promise.all(SOURCE_DIRECTORIES.map(findJavaScriptModules))
  ).flat();
  assert.ok(sourceModules.length > 0, "at least one source module is required");

  await assert.doesNotReject(
    Promise.all(sourceModules.map((moduleUrl) => import(moduleUrl))),
  );
});

test("documented Node range matches package metadata", async () => {
  const supportedRange = packageMetadata.engines.node;

  assert.equal(supportedRange, ">=24 <25");
  for (const metadataUrl of PACKAGE_METADATA_FILES) {
    const metadata = JSON.parse(await readFile(metadataUrl, "utf8"));
    assert.equal(
      metadata.engines.node,
      supportedRange,
      `${metadataUrl.pathname} must use the root Node range`,
    );
  }

  for (const documentUrl of NODE_RANGE_DOCUMENTS) {
    const document = await readFile(documentUrl, "utf8");
    assert.ok(
      document.includes(supportedRange),
      `${documentUrl.pathname} must document Node ${supportedRange}`,
    );
  }
});

test("workspace topology keeps pipelines independent", async () => {
  const [commitPlan, planAuthoring, planExecution, polishing] =
    await Promise.all(
      PACKAGE_METADATA_FILES.slice(1).map(async (metadataUrl) =>
        JSON.parse(await readFile(metadataUrl, "utf8")),
      ),
    );

  assert.deepEqual(packageMetadata.workspaces, ["packages/*", "pipelines/*"]);
  assert.equal(packageMetadata.exports, "./src/index.js");
  assert.deepEqual(Object.keys(packageMetadata.dependencies).sort(), [
    "@agent-runner/plan-authoring",
    "@agent-runner/plan-execution",
    "@agent-runner/polishing",
    "@modelcontextprotocol/server",
    "zod",
  ]);
  assert.equal(commitPlan.dependencies, undefined);

  for (const workspace of [
    commitPlan,
    planAuthoring,
    planExecution,
    polishing,
  ]) {
    assert.equal(workspace.exports, "./src/index.js");
  }

  assert.deepEqual(planAuthoring.dependencies, {
    "@agent-runner/commit-plan": "0.0.0",
  });
  assert.deepEqual(planExecution.dependencies, {
    "@agent-runner/commit-plan": "0.0.0",
  });
  assert.equal(polishing.dependencies, undefined);
});

test("canonical project skills have valid instructions", async () => {
  const entries = await readdir(SKILLS_DIRECTORY, { withFileTypes: true });
  const skillDirectories = entries.filter((entry) => entry.isDirectory());

  assert.ok(
    skillDirectories.length > 0,
    "at least one project skill is required",
  );

  for (const directory of skillDirectories) {
    const skillUrl = new URL(`${directory.name}/SKILL.md`, SKILLS_DIRECTORY);
    const skillPath = `.agents/skills/${directory.name}/SKILL.md`;
    const document = await readFile(skillUrl, "utf8");
    const { content, fields } = parseFrontmatter(document, skillPath);

    assert.deepEqual(
      Object.keys(fields).sort(),
      ["description", "name"],
      `${skillPath} frontmatter must contain only name and description`,
    );
    assert.equal(fields.name, directory.name);
    assert.match(fields.name, /^[a-z0-9-]{1,63}$/u);
    assert.ok(fields.description.trim(), `${skillPath} needs a description`);
    assert.doesNotMatch(fields.description, /\bTODO\b/u);
    assert.match(content, /^#\s+\S/mu, `${skillPath} needs a Markdown title`);
    assert.doesNotMatch(
      content,
      /\bTODO\b/u,
      `${skillPath} has unfinished content`,
    );
  }
});

test("product documentation map covers every versionable document once", async () => {
  const [{ stdout }, documentMap] = await Promise.all([
    executeFile(
      "git",
      [
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        "docs/product",
      ],
      { cwd: REPOSITORY_PATH },
    ),
    readFile(new URL("../docs/README.md", import.meta.url), "utf8"),
  ]);
  const productDocuments = stdout
    .split("\n")
    .filter((path) => path.endsWith(".md"))
    .sort();
  const mappedDocuments = [
    ...documentMap.matchAll(/\]\((product\/[^)]+\.md)\)/gu),
  ]
    .map((match) => `docs/${match[1]}`)
    .sort();

  assert.ok(
    productDocuments.length > 0,
    "at least one product document is required",
  );
  assert.deepEqual(mappedDocuments, productDocuments);

  const mapLines = documentMap.split("\n");
  for (const productDocument of productDocuments) {
    const target = productDocument.slice("docs/".length);
    const row = mapLines.find((line) => line.includes(`](${target})`));
    assert.ok(row, `${productDocument} needs a document-map row`);

    const columns = row
      .split("|")
      .slice(1, -1)
      .map((column) => column.trim());
    assert.equal(columns.length, 2, `${productDocument} needs two map columns`);
    assert.match(
      columns[1],
      /\bread\b/iu,
      `${productDocument} must say when to read it`,
    );
    assert.ok(
      columns[1].length >= 20 && columns[1].length <= 240,
      `${productDocument} needs a concise ownership description`,
    );
  }
});

test("skill interface YAML is ignored without hiding canonical skills", async () => {
  const ignoredPaths = [
    ".agents/skills/finalization/agents/openai.yaml",
    ".agents/local/nested/agents/interface.yaml",
  ];
  const { stdout } = await executeFile(
    "git",
    ["check-ignore", "--no-index", "--", ...ignoredPaths],
    { cwd: REPOSITORY_PATH },
  );

  assert.deepEqual(stdout.trim().split("\n"), ignoredPaths);

  for (const visiblePath of [
    ".agents/skills/finalization/SKILL.md",
    ".agents/skills/finalization/agents/openai.yml",
    ".agents/local.yaml",
  ]) {
    await assert.rejects(
      executeFile(
        "git",
        ["check-ignore", "--no-index", "--quiet", "--", visiblePath],
        { cwd: REPOSITORY_PATH },
      ),
      (error) => error.code === 1,
      `${visiblePath} must remain visible to Git`,
    );
  }
});

test("Claude reuses the canonical agent guidance and skills", async () => {
  const claudeGuidance = await readFile(
    new URL("../CLAUDE.md", import.meta.url),
    "utf8",
  );
  const claudeSkillsTarget = await readlink(
    new URL("../.claude/skills", import.meta.url),
  );

  assert.equal(
    claudeGuidance,
    "See [AGENTS.md](AGENTS.md) for repository instructions.\n",
  );
  assert.equal(claudeSkillsTarget, "../.agents/skills");
});

test("plan-authoring limits writes to its declared artifacts", async () => {
  const documents = await Promise.all([
    readFile(new URL("../AGENTS.md", import.meta.url), "utf8"),
    readFile(new URL("../README.md", import.meta.url), "utf8"),
    readFile(
      new URL("../pipelines/plan-authoring/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
  ]);

  for (const document of documents) {
    assert.match(document, /plan[- ]authoring/iu);
    assert.match(document, /clarifications\.md/u);
    assert.match(document, /plan\.md/u);
  }

  assert.match(documents[2], /No other tracked\s+or untracked file/u);
});

test("all pipelines define the bounded clarification lifecycle", async () => {
  const documents = await Promise.all([
    readFile(new URL("../AGENTS.md", import.meta.url), "utf8"),
    readFile(new URL("../README.md", import.meta.url), "utf8"),
    readFile(new URL("../docs/ARCHITECTURE.md", import.meta.url), "utf8"),
    readFile(
      new URL("../pipelines/plan-authoring/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../pipelines/plan-execution/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../pipelines/polishing/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
  ]);

  for (const document of documents) {
    assert.match(document, /CLARIFY/u);
    assert.match(document, /clarifications\.md/u);
    assert.match(document, /PRODUCT_DECISION_REQUIRED/u);
    assert.match(document, /empty clarification artifact/u);
    assert.match(document, /without\s+changes/u);
  }

  for (const document of documents.slice(2)) {
    assert.match(document, /do not consume an agent question\s+round/u);
  }

  assert.match(documents[4], /clarification readiness and questions/u);
  assert.match(documents[4], /PLAN_REVISION_REQUIRED/u);
  assert.match(documents[4], /suspended workflow state/u);
  assert.match(documents[4], /new execution run/u);

  const gitignore = await readFile(
    new URL("../.gitignore", import.meta.url),
    "utf8",
  );
  assert.match(gitignore, /^LOCAL_ARTIFACTS\/$/mu);
});

test("run-state durability and lease ownership are documented", async () => {
  const documents = await Promise.all([
    readFile(new URL("../AGENTS.md", import.meta.url), "utf8"),
    readFile(new URL("../README.md", import.meta.url), "utf8"),
    readFile(new URL("../docs/ARCHITECTURE.md", import.meta.url), "utf8"),
    readFile(
      new URL("../pipelines/plan-authoring/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../pipelines/plan-execution/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../pipelines/polishing/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
  ]);

  for (const document of documents) {
    assert.match(document, /write-ahead/iu);
    assert.match(document, /execution lease/iu);
    assert.match(document, /lock-free/iu);
  }
  for (const document of documents.slice(2)) {
    assert.match(document, /source-session/iu);
    assert.match(document, /raw model\s+transcripts/iu);
  }
  for (const document of [
    documents[1],
    documents[2],
    documents[4],
    documents[5],
  ]) {
    assert.match(document, /canonical[- ]worktree/iu);
    assert.match(document, /same-host/iu);
  }

  assert.match(documents[2], /actor.*phase.*kind.*message/su);
  assert.match(documents[2], /symlink escapes/iu);
});

test("Worker commit ownership and shared plan safety are documented", async () => {
  const [agentsGuidance, readme, specification, commitPlanContract] =
    await Promise.all([
      readFile(new URL("../AGENTS.md", import.meta.url), "utf8"),
      readFile(new URL("../README.md", import.meta.url), "utf8"),
      readFile(
        new URL("../pipelines/plan-execution/docs/SPEC.md", import.meta.url),
        "utf8",
      ),
      readFile(
        new URL("../packages/commit-plan/README.md", import.meta.url),
        "utf8",
      ),
    ]);

  for (const document of [agentsGuidance, readme, specification]) {
    assert.match(document, /Worker/u);
    assert.match(document, /Co-authored-by/u);
    assert.match(document, /remote/u);
  }

  assert.match(specification, /runner-authorized `COMMIT` turn/u);
  assert.match(
    specification,
    /access: "read-only" \| "workspace-write" \| "local-commit"/u,
  );
  assert.match(specification, /remoteWriteBlocked: true/u);
  assert.match(specification, /@agent-runner\/commit-plan/u);
  assert.match(readme, /## Commit 1: feat\(market\): add repository/u);
  assert.match(
    commitPlanContract,
    /## Commit 1: feat\(market\): add repository/u,
  );
  assert.match(commitPlanContract, /type\(scope\)\[!\]: imperative summary/u);
  assert.match(commitPlanContract, /at most 72 Unicode\s+code points/u);
  assert.match(commitPlanContract, /no body or footer/u);
  assert.match(commitPlanContract, /numbered contiguously from `1`/u);
  assert.doesNotMatch(
    specification,
    /Only the runner creates the planned commit/u,
  );
  assert.doesNotMatch(
    specification,
    /The Worker never creates planned commits/u,
  );
});
