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

test("fixed operational bounds remain explicit and narrowly owned", async () => {
  const [
    architecture,
    operatorGuide,
    pipelineModel,
    providerModel,
    operatorModel,
    safetyModel,
    validationModel,
    authoringSpec,
    executionSpec,
    polishingSpec,
  ] = await Promise.all([
    readDocument("docs/ARCHITECTURE.md"),
    readDocument("docs/OPERATOR_GUIDE.md"),
    readDocument("docs/product/PIPELINE_MODEL.md"),
    readDocument("docs/product/PROVIDER_MODEL.md"),
    readDocument("docs/product/OPERATOR_MODEL.md"),
    readDocument("docs/product/SAFETY_MODEL.md"),
    readDocument("docs/product/VALIDATION_AND_REVIEW.md"),
    readDocument("pipelines/plan-authoring/docs/SPEC.md"),
    readDocument("pipelines/plan-execution/docs/SPEC.md"),
    readDocument("pipelines/polishing/docs/SPEC.md"),
  ]);

  for (const document of [
    architecture,
    operatorGuide,
    pipelineModel,
    authoringSpec,
    executionSpec,
    polishingSpec,
  ]) {
    assert.match(document, /three agent question rounds/u);
    assert.match(
      document,
      /not a configurable\s+(?:duration or\s+)?workflow\s+budget/u,
    );
  }

  for (const document of [architecture, providerModel, operatorGuide]) {
    assert.match(document, /10-second\s+deadline/u);
    assert.match(document, /one-second network-denial observation\s+deadline/u);
    assert.match(
      document,
      /both\s+providers' pre-effect\s+local-commit Git metadata\s+lookups[^.]*10-second\s+bound/iu,
    );
    assert.match(
      document,
      /preparation\s+deadlines?[^.]*do(?:es)? not cap the\s+authorized commit effect/iu,
    );
    assert.match(document, /two[^.]*30-second\s+subprocess\s+deadline/u);
  }
  assert.match(providerModel, /single fresh reconstruction/u);
  assert.match(operatorGuide, /one fresh\s+reconstruction/u);
  assert.match(architecture, /compact[^.]*retry[^.]*once/u);
  for (const document of [providerModel, operatorGuide]) {
    assert.match(document, /at most\s+one[^.]*compaction retry/u);
  }
  assert.match(
    providerModel,
    /A second failure[^.]+without another adapter retry/u,
  );
  assert.match(
    architecture,
    /32 page requests[^.]*requested limit of 100\s+entries/u,
  );
  assert.match(providerModel, /32 page requests[^.]*asking for 100\s+entries/u);
  assert.match(architecture, /256-name MCP configuration capacity/u);
  assert.match(architecture, /three fixed one-second observation/u);
  assert.match(
    providerModel,
    /one second each for natural close, TERM, and KILL/u,
  );
  assert.match(safetyModel, /one-second descendant-grace deadline/u);
  assert.match(safetyModel, /fixed safety invariant/u);

  assert.match(validationModel, /one automatic correction/u);
  assert.match(validationModel, /up to two Worker finalization corrections/u);
  assert.match(validationModel, /Two automatic semantic retries/u);
  assert.match(validationModel, /not consume the\s+separate code-fix/u);
  assert.match(authoringSpec, /permits one automatic fresh-session/u);
  assert.match(executionSpec, /Allow at most two such attempts/u);
  assert.match(executionSpec, /only one automatic read-only correction/u);
  assert.match(polishingSpec, /separate one-attempt correction records/u);
  for (const document of [executionSpec, polishingSpec]) {
    assert.match(document, /Two automatic semantic retries/u);
  }

  assert.match(architecture, /DNS has a 5-second deadline/u);
  assert.match(architecture, /one A and one AAAA lookup/u);
  assert.match(architecture, /one resolver\s+try each/u);
  assert.match(architecture, /connection establishment 10 seconds/u);
  assert.match(architecture, /body\/header inactivity 15 seconds/u);
  assert.match(architecture, /whole acquisition 5 minutes/u);
  assert.match(architecture, /retirement has a separate\s+1-second bound/u);
  for (const document of [operatorGuide, safetyModel]) {
    assert.match(document, /64 MiB per file/u);
    assert.match(document, /256 MiB total/u);
    assert.match(document, /one A and one AAAA\s+lookup/u);
    assert.match(document, /one\s+resolver\s+try each/u);
    assert.match(
      document,
      /10 seconds\s+to\s+connect|connection establishment[^.]*10\s+seconds/u,
    );
    assert.match(
      document,
      /header\/body inactivity[^.]*15 seconds|15 seconds of header\/body\s+inactivity/u,
    );
    assert.match(document, /five minutes\s+overall/u);
    assert.match(
      document,
      /separate\s+one-second (?:safety|transport-retirement) bound/u,
    );
  }

  assert.match(architecture, /lease is recoverable[^.]*five minutes/u);
  assert.match(
    operatorModel,
    /same-host execution or canonical-worktree lease becomes eligible[^.]*five minutes/u,
  );
  assert.match(
    operatorGuide,
    /same-host execution or canonical-worktree lease is eligible[^.]*five minutes/u,
  );
  for (const document of [architecture, operatorModel]) {
    assert.match(document, /500/u);
    assert.match(document, /10 milliseconds/u);
  }
  assert.match(operatorGuide, /roughly five seconds/u);
  assert.match(architecture, /Managed-state reads[^.]+five attempts/u);
  assert.match(
    architecture,
    /release of either an\s+execution or canonical-worktree lease[^.]*five stop-aware attempts/u,
  );
  assert.match(
    architecture,
    /Generated run IDs try at most\s+ten\s+candidates/u,
  );
  assert.match(architecture, /at most\s+1,010\s+collision-safe\s+names/u);
  assert.match(
    architecture,
    /fixed correctness guards rather than workflow\s+budgets/u,
  );
  assert.match(architecture, /run_wait\.timeoutMs` means 30 seconds/u);
  assert.match(architecture, /public maximum is 24\s+hours/u);
  assert.match(architecture, /bounded event-driven observation/u);
  assert.match(architecture, /at most 64 inspections within 30 seconds/u);
  assert.match(architecture, /ERR_DETACHED_OWNERSHIP_PENDING/u);
  assert.match(architecture, /at most one second at\s+a time/u);
  assert.match(
    architecture,
    /fixed correctness mechanics rather than user-work retry budgets/u,
  );
  assert.match(operatorGuide, /run_wait\.timeoutMs` waits 30 seconds/u);
});
