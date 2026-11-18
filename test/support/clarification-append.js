import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import {
  createClarificationService,
  createRunner,
  createRunStore,
} from "../../src/index.js";
import {
  configurationLoader,
  createExecutionAdapter,
  operatorFixture,
  requestedStepAssessment,
} from "./runner.js";

export const APPEND_QUESTIONS = [
  {
    question: "Which public behavior is required?",
    whyItMatters: "The alternatives produce different public results.",
  },
];

export function appendReadFailure() {
  return Object.assign(new Error("Controlled transcript read interruption."), {
    code: "ERR_CLARIFICATION_READ",
  });
}

// Real Runner, transcript service, journals and Git; only role replies and the
// explicitly selected interruption boundary are injected by each owning test.
export async function clarificationAppendFixture(
  t,
  pipelineId,
  { mode = "combined", kind = "questions" } = {},
) {
  const paths = await operatorFixture(t, pipelineId);
  const calls = [];
  const probes = [];
  const adapter = {
    ...createExecutionAdapter(),
    async probe(request) {
      probes.push(request);
      return createExecutionAdapter().probe(request);
    },
    async run(request) {
      if (request.prompt.startsWith("Validate the proposed context"))
        return {
          structured: { stepAssessment: requestedStepAssessment(request) },
          sessionId: request.session?.id ?? "append-context",
        };
      calls.push(request);
      assert.equal(request.access, "read-only");
      let structured;
      const emptyDecision = {
        reason: "",
        question: "",
        options: [],
        whyBlocked: "",
        evidence: [],
      };
      if (kind === "questions") {
        assert.equal(calls.length, 1, "Append recovery must not replay a role");
        structured = { status: "QUESTIONS", questions: APPEND_QUESTIONS };
        if (pipelineId !== "plan-authoring")
          Object.assign(structured, emptyDecision);
      } else if (calls.length === 1) {
        structured = { status: "READY", questions: [], ...emptyDecision };
      } else {
        assert.equal(
          calls.length,
          2,
          "Decision recovery must not replay a role",
        );
        structured = {
          status: "PRODUCT_DECISION_REQUIRED",
          summary: "",
          requiredChecks: [],
          validationInfrastructure: [],
          capabilityRequirements: [],
          environmentBlockers: [],
          capacityField: "",
          capacityLimit: 0,
          reason: "",
          question: APPEND_QUESTIONS[0].question,
          options: ["Behavior A", "Behavior B"],
          whyBlocked: APPEND_QUESTIONS[0].whyItMatters,
          evidence: ["The task leaves the public behavior unspecified."],
          ...(pipelineId === "plan-execution"
            ? { stepAssessment: requestedStepAssessment(request) }
            : {}),
        };
      }
      if (
        (
          request.schema?.properties?.result?.anyOf?.[0]?.properties ??
          request.schema?.properties
        )?.stepAssessment
      )
        structured.stepAssessment = requestedStepAssessment(request);
      return {
        structured:
          request.schema?.properties?.result?.anyOf === undefined
            ? structured
            : { result: structured },
        sessionId: request.session?.id ?? `append-${calls.length}`,
      };
    },
  };
  function open({
    store = createRunStore({ stateRoot: paths.stateRoot }),
    clarifications = createClarificationService({ interactive: false }),
    adapters = { codex: adapter },
  } = {}) {
    return {
      store,
      runner: createRunner({
        adapters,
        runStore: store,
        clarifications,
        loadConfiguration: configurationLoader({
          schemaVersion: 1,
          defaultBackend: "codex",
          pipelines: { [pipelineId]: { mode } },
        }),
      }),
    };
  }
  return {
    ...paths,
    calls,
    probes,
    open,
    input: {
      pipelineId,
      projectPath: paths.projectPath,
      taskPath: paths.taskPath,
    },
    async transcript(run) {
      const path =
        run.pipelineState.clarificationPath ??
        join(paths.taskPath, "clarifications.md");
      return readFile(path, "utf8");
    },
  };
}

export const transcriptHash = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
