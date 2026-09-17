import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import { listPipelines, main, parseRunnerConfiguration } from "../src/index.js";
import { createMcpServer, MCP_INSTRUCTIONS } from "../src/mcp/index.js";

const ROOT = new URL("../", import.meta.url);
const MODE_ROWS = [
  ["Mode", "Quality", "Speed", "Token consumption", "Meaning"],
  [
    "`lazy`",
    "★★★☆☆",
    "★★★★★",
    "★★☆☆☆",
    "Lower-consumption self-review without an independent Reviewer.",
  ],
  [
    "`independent`",
    "★★★★☆",
    "★★★☆☆",
    "★★★★☆",
    "Recommended default with genuinely independent semantic review.",
  ],
  [
    "`combined`",
    "★★★★★",
    "★★☆☆☆",
    "★★★★★",
    "Primary self-convergence followed by the full independent gate.",
  ],
];

function readDocument(path) {
  return readFile(new URL(path, ROOT), "utf8");
}

function modeTable(document) {
  const lines = document.split("\n");
  const start = lines.findIndex((line) => /^\| Mode\s*\|/u.test(line));
  assert.ok(
    start > 0 && start < 30,
    "Mode guidance belongs near the beginning.",
  );
  const end = lines.findIndex(
    (line, index) => index > start && !line.startsWith("|"),
  );
  const rows = lines.slice(start, end === -1 ? undefined : end);
  assert.match(rows[1], /^\|(?:\s*:?-+:?\s*\|){5}$/u);
  return rows
    .filter((_, index) => index !== 1)
    .map((row) =>
      row
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
}

test("operator mode tables agree with the supported descriptors and recommendation", async () => {
  const documents = await Promise.all([
    readDocument("README.md"),
    readDocument("docs/OPERATOR_GUIDE.md"),
  ]);
  for (const document of documents) {
    assert.deepEqual(modeTable(document), MODE_ROWS);
    assert.equal((document.match(/\| Mode\s*\|/gu) ?? []).length, 1);
    assert.match(document, /More token stars mean greater consumption/u);
    assert.match(
      document,
      /relative guidance, not\s+measured provider guarantees/u,
    );
    assert.match(document, /`independent` is the default and recommended/u);
  }
  for (const pipeline of listPipelines()) {
    assert.deepEqual([...pipeline.settings.mode.values].sort(), [
      "combined",
      "independent",
      "lazy",
    ]);
    assert.equal(pipeline.settings.mode.defaultValue, "independent");
    assert.equal(pipeline.settings.mode.recommendedValue, "independent");
  }
});

test("operator guidance and transports retain mode and deferred-stop choices", async () => {
  let help = "";
  let errors = "";
  assert.equal(
    await main(["--help"], {
      stdout: {
        write: (value) => {
          help += value;
        },
      },
      stderr: {
        write: (value) => {
          errors += value;
        },
      },
    }),
    0,
  );
  assert.equal(errors, "");
  assert.match(help, /--mode <independent\|lazy\|combined>/u);
  assert.match(help, /independent is default and recommended/u);
  assert.match(MCP_INSTRUCTIONS, /independent is the default and recommended/u);
  for (const text of [help, MCP_INSTRUCTIONS]) {
    assert.match(text, /all three pipelines/u);
    assert.match(text, /lazy is opt-in/u);
    assert.match(text, /after-current-commit/u);
    assert.match(text, /selected (?:plan-execution|execution) step/u);
  }
  for (const command of ["pause", "cancel"]) {
    assert.match(
      help,
      new RegExp(
        `agent-run ${command}[^\\n]+--timing immediate\\|after-current-commit`,
        "u",
      ),
    );
  }
  for (const path of ["README.md", "docs/OPERATOR_GUIDE.md"]) {
    const document = await readDocument(path);
    assert.ok(document.includes("--timing after-current-commit"), path);
    assert.match(document, /run_pause/u);
    assert.match(document, /run_cancel/u);
    assert.match(document, /immediate/u);
  }
});

test("MCP discovery describes supported modes and execution-only deferred stops", async (t) => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const server = createMcpServer({ control: {}, issueReportingEnabled: false });
  const client = new Client({ name: "documentation-test", version: "1.0.0" });
  t.after(() => client.close());
  t.after(() => server.close());
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const { tools } = await client.listTools();
  const start = tools.find(({ name }) => name === "run_start");
  assert.match(start.description, /independent is default and recommended/u);
  assert.match(start.description, /lazy is opt-in/u);
  assert.match(start.description, /combined.*all three pipelines/u);
  assert.deepEqual(start.inputSchema.properties.mode.enum, [
    "independent",
    "lazy",
    "combined",
  ]);
  for (const name of ["run_pause", "run_cancel"]) {
    const stop = tools.find((tool) => tool.name === name);
    assert.match(stop.description, /Timing defaults to immediate/u);
    assert.match(
      stop.description,
      /after-current-commit is supported only for a selected execution step/u,
    );
    assert.match(stop.description, /without extra work/u);
    assert.deepEqual(stop.inputSchema.properties.timing.enum, [
      "immediate",
      "after-current-commit",
    ]);
    assert.equal(stop.inputSchema.required.includes("timing"), false);
  }
});

test("configuration examples keep trusted vectors and the preferred planning target valid", async () => {
  const text = await readDocument(".agent-runner.example.json");
  assert.doesNotThrow(() => parseRunnerConfiguration(text));
  const example = JSON.parse(text);
  for (const pipeline of listPipelines()) {
    assert.equal(
      example.pipelines[pipeline.id].mode,
      pipeline.settings.mode.defaultValue,
    );
    for (const alias of example.pipelines[pipeline.id].trustedChecks ?? []) {
      assert.ok(Object.hasOwn(example.trustedCommands, alias), alias);
    }
  }
  assert.deepEqual(example.trustedCommands["repository-check"], {
    command: "npm run check",
    executable: "npm",
    arguments: ["run", "check"],
    capabilities: { scratch: true, cache: true },
  });
  const authoring = listPipelines().find(({ id }) => id === "plan-authoring");
  assert.equal(
    example.pipelines[authoring.id].preferredCommitLineLimit,
    authoring.settings.preferredCommitLineLimit.defaultValue,
  );
  assert.equal(authoring.settings.preferredCommitLineLimit.defaultValue, 900);
  for (const path of [
    "README.md",
    "docs/OPERATOR_GUIDE.md",
    "docs/product/OPERATOR_MODEL.md",
    "pipelines/plan-authoring/docs/SPEC.md",
  ]) {
    const document = await readDocument(path);
    assert.match(document, /preferredCommitLineLimit/u, path);
    assert.match(document, /900/u, path);
    assert.match(document, /legacy/u, path);
  }
  const readme = await readDocument("README.md");
  const examples = [...readme.matchAll(/```json\n([\s\S]*?)\n```/gu)]
    .map((match) => JSON.parse(match[1]))
    .filter((value) => value.trustedCommands !== undefined);
  assert.ok(
    examples.length > 0,
    "README must demonstrate a trusted command catalog.",
  );
  for (const value of examples) {
    assert.doesNotThrow(() => parseRunnerConfiguration(JSON.stringify(value)));
    for (const settings of Object.values(value.pipelines)) {
      for (const alias of settings.trustedChecks ?? []) {
        assert.ok(Object.hasOwn(value.trustedCommands, alias), alias);
      }
    }
  }
});

test("document-map links resolve and finalization covers the operator surfaces", async () => {
  const mapUrl = new URL("docs/README.md", ROOT);
  const document = await readFile(mapUrl, "utf8");
  for (const [, target] of document.matchAll(/\]\(([^)]+)\)/gu)) {
    const url = new URL(target, mapUrl);
    assert.equal(url.protocol, "file:", target);
    assert.ok((await stat(url)).isFile(), target);
  }
  const skill = await readDocument(".agents/skills/finalization/SKILL.md");
  for (const surface of [
    "README.md",
    "docs/OPERATOR_GUIDE.md",
    ".agent-runner.example.json",
    "agent-run --help",
    "agent-run pipelines",
    "pipelines_list",
    "run_start",
    "run_pause",
    "run_cancel",
    "docs/ARCHITECTURE.md",
    "docs/product/",
    "pipelines/*/docs/SPEC.md",
    "docs/README.md",
    "RHYTHM.md",
  ]) {
    assert.ok(skill.includes(surface), surface);
  }
  assert.match(skill, /must never execute in an agent\s+turn/u);
  assert.match(skill, /NOT_RUN/u);
  assert.match(skill, /do not promise exactly-once execution/u);
  assert.match(skill, /defer staging, unstaging,/u);
  assert.match(skill, /Do not copy it into phase prompts/u);
});
