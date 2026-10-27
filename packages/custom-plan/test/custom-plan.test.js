import assert from "node:assert/strict";
import test from "node:test";

import {
  assertCustomPlan,
  CustomPlanValidationError,
  parseCustomPlan,
  serializeCustomPlan,
  validateCustomPlan,
} from "../src/index.js";

const SOURCE = [
  "```json",
  "{",
  '  "kind": "custom",',
  '  "criteria": [',
  "    {",
  '      "id": "source-coverage",',
  '      "condition": "Identify every supplied source and label missing evidence."',
  "    },",
  "    {",
  '      "id": "editable-result",',
  '      "condition": "Deliver an editable summary with source references."',
  "    }",
  "  ],",
  '  "inputs": [',
  '    "sources/catalog.md",',
  '    "https://example.test/reference"',
  "  ],",
  '  "outputs": [',
  '    "reports/summary.md"',
  "  ]",
  "}",
  "```",
  "",
  "## Step 1: Analyze the supplied evidence.",
  "",
  "### Work",
  "",
  "Read the supplied catalog; compare the source descriptions.",
  "",
  "#### Evidence notes",
  "",
  "- Preserve uncertainty about unavailable sources.",
  "",
  "### Expected results",
  "",
  "An analysis identifying the supplied sources and evidence gaps.",
  "",
  "### Criteria",
  "",
  "- source-coverage",
  "",
  "## Step 2: Write the summary",
  "",
  "### Work",
  "",
  "Write reports/summary.md using the preceding analysis.",
  "",
  "### Expected results",
  "",
  "An editable summary with references and explicit evidence gaps.",
  "",
  "### Criteria",
  "",
  "- source-coverage",
  "- editable-result",
  "",
].join("\n");

function analysisPlan() {
  return {
    kind: "custom",
    criteria: [
      {
        id: "comparison",
        condition:
          "Compare both alternatives against the supplied constraints.",
      },
    ],
    inputs: [],
    outputs: [],
    steps: [
      {
        number: 1,
        title: "Compare the alternatives.",
        work: "Analyze both alternatives using the supplied constraints.",
        expectedResults: "A comparison with evidence and explicit limitations.",
        criterionRefs: ["comparison"],
      },
    ],
  };
}

function invalid(operation, expectedIssue) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof CustomPlanValidationError);
    assert.equal(error.code, "ERR_INVALID_CUSTOM_PLAN");
    assert.ok(Object.isFrozen(error.issues));
    assert.ok(
      error.issues.some((issue) => expectedIssue.test(issue)),
      error.issues.join("\n"),
    );
    return true;
  });
}

test("parses criterion-driven analysis and output steps without commit subjects", () => {
  const plan = parseCustomPlan(SOURCE);
  assert.equal(plan.kind, "custom");
  assert.deepEqual(
    plan.criteria.map(({ id }) => id),
    ["source-coverage", "editable-result"],
  );
  assert.deepEqual(plan.inputs, [
    "sources/catalog.md",
    "https://example.test/reference",
  ]);
  assert.deepEqual(plan.outputs, ["reports/summary.md"]);
  assert.equal(plan.steps[0].number, 1);
  assert.equal(plan.steps[0].title, "Analyze the supplied evidence.");
  assert.match(
    plan.steps[0].work,
    /#### Evidence notes\n\n- Preserve uncertainty/u,
  );
  assert.equal(
    plan.steps[1].expectedResults,
    "An editable summary with references and explicit evidence gaps.",
  );
  assert.deepEqual(plan.steps[1].criterionRefs, [
    "source-coverage",
    "editable-result",
  ]);
  assert.equal(serializeCustomPlan(plan), SOURCE);
  assert.equal(assertCustomPlan(plan), plan);

  for (const value of [
    plan,
    plan.criteria,
    ...plan.criteria,
    plan.inputs,
    plan.outputs,
    plan.steps,
    ...plan.steps,
    ...plan.steps.map((step) => step.criterionRefs),
  ]) {
    assert.ok(Object.isFrozen(value));
  }
  assert.throws(() => {
    plan.criteria[0].condition = "Changed";
  }, TypeError);
  assert.throws(
    () => plan.steps[0].criterionRefs.push("editable-result"),
    TypeError,
  );
});

test("supports analysis-only results without file outputs or a manufactured diff", () => {
  const plan = analysisPlan();
  assert.deepEqual(validateCustomPlan(plan), []);
  assert.ok(Object.isFrozen(validateCustomPlan(plan)));
  assert.deepEqual(parseCustomPlan(serializeCustomPlan(plan)), plan);
});

test("normalizes line endings and surrounding blank lines with stable serialization", () => {
  for (const ending of ["\r\n", "\r"]) {
    assert.equal(
      serializeCustomPlan(parseCustomPlan(SOURCE.replaceAll("\n", ending))),
      SOURCE,
    );
  }
  const plan = analysisPlan();
  plan.criteria[0].condition = "First condition.\r\nSecond condition.";
  plan.steps[0].work =
    "\r\n    An indented note.\r\n\r\nAnother paragraph.\r\n";
  const before = structuredClone(plan);
  const reordered = {
    steps: plan.steps,
    outputs: plan.outputs,
    inputs: plan.inputs,
    criteria: plan.criteria,
    kind: plan.kind,
  };
  const serialized = serializeCustomPlan(plan);
  assert.equal(serializeCustomPlan(reordered), serialized);
  const parsed = parseCustomPlan(serialized);
  assert.equal(
    parsed.criteria[0].condition,
    "First condition.\nSecond condition.",
  );
  assert.equal(
    parsed.steps[0].work,
    "    An indented note.\n\nAnother paragraph.",
  );
  assert.equal(serializeCustomPlan(parsed), serialized);
  assert.deepEqual(plan, before);
});

test("rejects missing or incompatible kinds rather than inferring a plan contract", () => {
  invalid(
    () => parseCustomPlan("## Commit 1: feat(core): add behavior\nBody."),
    /fenced JSON/u,
  );
  for (const kind of [undefined, null, "commit", "unknown"]) {
    const plan = { ...analysisPlan(), kind };
    invalid(() => assertCustomPlan(plan), /explicitly "custom"/u);
    invalid(
      () =>
        parseCustomPlan(
          SOURCE.replace(
            '"kind": "custom"',
            `"kind": ${JSON.stringify(kind ?? null)}`,
          ),
        ),
      /explicitly "custom"/u,
    );
  }
  const plan = analysisPlan();
  plan.steps = [
    { number: 1, subject: "feat(core): add behavior", body: "Body." },
  ];
  invalid(() => serializeCustomPlan(plan), /subject is not supported/u);
});

test("rejects malformed declarations, delimiters and step sections", () => {
  const cases = [
    [null, /source must be a string/u],
    ["", /fenced JSON/u],
    ["# Custom plan\n" + SOURCE, /on line 1/u],
    [SOURCE.replace("```json", "```yaml"), /fenced JSON/u],
    [SOURCE.replace("}\n```", "}"), /fenced JSON/u],
    [SOURCE.replace('"custom",', '"custom",,'), /valid JSON/u],
    ["```json\nnull\n```", /must be an object/u],
    ["```json\n[]\n```", /must be an object/u],
    [
      SOURCE.replace('"kind": "custom",', '"kind": "custom", "steps": [],'),
      /steps is not supported/u,
    ],
    [
      SOURCE.replace("## Step 1:", "Unexpected preamble\n## Step 1:"),
      /delimiter or blank/u,
    ],
    [SOURCE.slice(0, SOURCE.indexOf("## Step 1:")), /at least one step/u],
    ...[
      "## Step 0:",
      "## Step 01:",
      "## Step one:",
      "##  Step 1:",
      "## Step 1",
      "## Commit 1:",
    ].map((delimiter) => [
      SOURCE.replace("## Step 1:", delimiter),
      /must match/u,
    ]),
    [SOURCE.replace("## Step 1:", "## Step 2:"), /number must be 1/u],
    [SOURCE.replace("## Step 2:", "## Step 3:"), /number must be 2/u],
    [SOURCE.replace("## Step 2:", "## Step 1:"), /number must be 2/u],
    [
      SOURCE.replace("## Step 1:", "## Step 9007199254740992:"),
      /positive safe integer/u,
    ],
    [
      SOURCE.replace("Analyze the supplied evidence.", ""),
      /title must be nonempty/u,
    ],
    [SOURCE.replace("### Work", "### Scope"), /sections must be/u],
    [
      SOURCE.replace("### Work", "Unexpected step preamble\n### Work"),
      /start with a Work/u,
    ],
    [SOURCE.replace("### Expected results", "### Work"), /sections must be/u],
    [SOURCE.slice(0, SOURCE.indexOf("### Criteria")), /requires Work/u],
    [
      SOURCE.replace(
        "### Criteria\n\n- source-coverage",
        "### Criteria\n\nsource-coverage",
      ),
      /only "- <criterion-id>"/u,
    ],
  ];
  for (const [source, issue] of cases)
    invalid(() => parseCustomPlan(source), issue);
});

test("validates closed declarations, complete criteria and scoped step results", () => {
  const cases = [
    [() => null, /must be an object/u],
    [() => new Date(0), /must be an object/u],
    [(plan) => ({ ...plan, commands: [] }), /commands is not supported/u],
    [
      (plan) => {
        delete plan.inputs;
      },
      /inputs must be an array/u,
    ],
    [
      (plan) => {
        plan.outputs = null;
      },
      /outputs must be an array/u,
    ],
    [
      (plan) => {
        plan.inputs = [{ path: "source.md" }];
      },
      /single-line strings/u,
    ],
    [
      (plan) => {
        plan.outputs = [""];
      },
      /single-line strings/u,
    ],
    [
      (plan) => {
        plan.inputs = [" source.md"];
      },
      /single-line strings/u,
    ],
    [
      (plan) => {
        plan.outputs = ["result.md\nother.md"];
      },
      /single-line strings/u,
    ],
    [
      (plan) => {
        plan.inputs = ["source.md", "source.md"];
      },
      /duplicate references/u,
    ],
    [
      (plan) => {
        plan.outputs = ["result.md", "result.md"];
      },
      /duplicate references/u,
    ],
    [
      (plan) => {
        plan.criteria = [];
      },
      /nonempty array/u,
    ],
    [
      (plan) => {
        plan.criteria = {};
      },
      /nonempty array/u,
    ],
    [
      (plan) => {
        plan.criteria = [null];
      },
      /Criterion 1 must be an object/u,
    ],
    [
      (plan) => {
        plan.criteria[0].extra = true;
      },
      /extra is not supported/u,
    ],
    [
      (plan) => {
        plan.criteria[0].id = "Not stable";
      },
      /kebab-case reference/u,
    ],
    [
      (plan) => {
        plan.criteria.push({ ...plan.criteria[0] });
      },
      /id must be unique/u,
    ],
    [
      (plan) => {
        plan.criteria[0].condition = "  ";
      },
      /condition must be nonempty/u,
    ],
    [
      (plan) => {
        delete plan.criteria[0].condition;
      },
      /condition must be nonempty/u,
    ],
    [
      (plan) => {
        plan.criteria.push({
          id: "unused",
          condition: "An omitted requirement.",
        });
      },
      /must be referenced/u,
    ],
    [
      (plan) => {
        plan.steps = [];
      },
      /at least one step/u,
    ],
    [
      (plan) => {
        plan.steps = {};
      },
      /at least one step/u,
    ],
    [
      (plan) => {
        plan.steps = [null];
      },
      /Step 1 must be an object/u,
    ],
    [
      (plan) => {
        plan.steps[0].effect = "commit";
      },
      /effect is not supported/u,
    ],
    [
      (plan) => {
        plan.steps[0].number = "1";
      },
      /positive safe integer/u,
    ],
    [
      (plan) => {
        plan.steps[0].title = "First\nSecond";
      },
      /single-line text/u,
    ],
    [
      (plan) => {
        plan.steps[0].work = "";
      },
      /work must be nonempty/u,
    ],
    [
      (plan) => {
        plan.steps[0].expectedResults = null;
      },
      /expectedResults must be nonempty/u,
    ],
    [
      (plan) => {
        plan.steps[0].work = "Scope.\r\n## Step 2: Injected";
      },
      /must not contain/u,
    ],
    [
      (plan) => {
        plan.steps[0].expectedResults = "### Criteria";
      },
      /must not contain/u,
    ],
    [
      (plan) => {
        plan.steps[0].criterionRefs = [];
      },
      /at least one reference/u,
    ],
    [
      (plan) => {
        delete plan.steps[0].criterionRefs;
      },
      /must be an array/u,
    ],
    [
      (plan) => {
        plan.steps[0].criterionRefs = ["unknown"];
      },
      /unknown criterion/u,
    ],
    [
      (plan) => {
        plan.steps[0].criterionRefs.push("comparison");
      },
      /duplicate references/u,
    ],
  ];
  for (const [change, issue] of cases) {
    const plan = analysisPlan();
    const changed = change(plan);
    const value = changed === undefined ? plan : changed;
    assert.ok(
      validateCustomPlan(value).some((message) => issue.test(message)),
      issue.toString(),
    );
    invalid(() => assertCustomPlan(value), issue);
    invalid(() => serializeCustomPlan(value), issue);
  }
});
