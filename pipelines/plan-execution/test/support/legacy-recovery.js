import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  createClarificationService,
  createRunner,
  createRunStore,
  parseRunnerConfiguration,
} from "../../../../src/index.js";
import { planExecutionPipeline } from "../../src/index.js";
import * as schemas from "../../src/schemas.js";
import {
  bootstrapReady,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  executeFile,
  finalizationPassed,
  implementationCompleted,
  reconciliationResolved,
  reviewApproved,
  reviewFindings,
  cleanConfirmationFindings,
  resolution,
} from "./runtime.js";

export async function createLegacyRecoveryFixture(
  t,
  {
    mode = "lazy",
    pendingCorrection = true,
    steps = 2,
    format = false,
    source = false,
    onTransitionBoundary,
    onConfirmation,
    reuseFinalization = false,
    ignoredInfrastructure = false,
    trusted = false,
    pendingConfirmation = false,
  } = {},
) {
  const root = await mkdtemp(
    join(tmpdir(), "agent-runner-legacy-confirmation-"),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  const git = (...args) => executeFile("git", ["-C", projectPath, ...args]);
  await git("init", "-q");
  await git("config", "user.name", "Test");
  await git("config", "user.email", "test@example.com");
  await writeFile(join(projectPath, ".gitignore"), "LOCAL_ARTIFACTS/\n");
  await writeFile(
    join(projectPath, "package.json"),
    '{"scripts":{"test":"node --test"}}\n',
  );
  const infrastructure = ["package.json"];
  if (ignoredInfrastructure) {
    await mkdir(join(projectPath, "LOCAL_ARTIFACTS"));
    await writeFile(
      join(projectPath, "LOCAL_ARTIFACTS", "check-config.json"),
      "{}\n",
    );
    infrastructure.push("LOCAL_ARTIFACTS/check-config.json");
  }
  const checks = [
    { id: "C1", command: "npm test" },
    ...(trusted ? [{ id: "C2", command: "node --version" }] : []),
  ];
  await git("add", "-A");
  await git("commit", "-qm", "test: baseline");
  await writeFile(
    join(taskPath, "task.md"),
    "Implement the planned behavior.\n",
  );
  await writeFile(
    join(taskPath, "plan.md"),
    Array.from(
      { length: steps },
      (_, index) =>
        `## Commit ${index + 1}: feat(test): add behavior ${index + 1}\n\nImplement behavior ${index + 1}.`,
    ).join("\n\n"),
  );
  const calls = [];
  let legacyFailure = true;
  let providerFailures = 0;
  let changed = false;
  let terminalFindings = false;
  let trustedExecutions = 0;
  let invalidConfirmation = false;
  const adapter = {
    async probe() {
      return {
        version: "fake-1",
        structuredOutput: true,
        readOnly: true,
        autonomousWrite: true,
        gitMetadataWriteBlocked: true,
        workspaceWrite: true,
        localCommit: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: true,
      };
    },
    async run(request) {
      const position = JSON.parse(
        /Runner-selected plan position[^\n]*\n([^\n]+)/u.exec(
          request.prompt,
        )?.[1] ?? "null",
      );
      const assessment = position && {
        step: position.step,
        subject: position.subject,
        disposition: "CURRENT",
        evidence: [],
      };
      if (request.schema === schemas.PLAN_CONTEXT_SCHEMA)
        return {
          structured: { stepAssessment: assessment },
          sessionId: request.session?.id ?? randomUUID(),
        };
      calls.push(request);
      const schema = request.schema;
      const step = Number(
        /Current planned commit:\n## Commit (\d+):/u.exec(request.prompt)?.[1],
      );
      if (request.access === "local-commit") {
        await git("add", "-A");
        await git("commit", "-qm", request.commit.message);
        return {
          output: "committed",
          sessionId: request.session?.id ?? randomUUID(),
        };
      }
      let structured;
      if (schema === schemas.CLARIFICATION_SCHEMA)
        structured = clarificationReady();
      else if (schema === schemas.BOOTSTRAP_SCHEMA)
        structured = {
          result: {
            ...bootstrapReady("Role"),
            requiredChecks: checks,
            validationInfrastructure: infrastructure,
          },
        };
      else if (schema === schemas.BOOTSTRAP_RECONCILIATION_SCHEMA)
        structured = { result: reconciliationResolved() };
      else if (schema === schemas.IMPLEMENTATION_SCHEMA) {
        await writeFile(
          join(projectPath, `feature-${step}.js`),
          `export const value = ${step};\n`,
        );
        structured = implementationCompleted();
      } else if (schema === schemas.CHECK_AND_FIX_SCHEMA) {
        if (pendingCorrection && !changed && step === steps) {
          changed = true;
          await writeFile(
            join(projectPath, `feature-${steps}.js`),
            `export const fixed = ${steps};\n`,
          );
          structured = checkAndFix("CHANGED");
        } else structured = checkAndFix();
      } else if (
        schema === schemas.CANDIDATE_CLEAN_CONFIRM_SCHEMA ||
        schema === schemas.CANDIDATE_REVIEW_SCHEMA
      ) {
        const {
          validationChange,
          validationEvidence,
          finalizationFindingIds,
          ...candidate
        } =
          schema === schemas.CANDIDATE_CLEAN_CONFIRM_SCHEMA
            ? cleanConfirmation()
            : pendingCorrection && !changed && step === steps
              ? reviewFindings("R1")
              : reviewApproved();
        structured = candidate;
      } else if (schema === schemas.FINDING_RESOLUTION_SCHEMA) {
        changed = true;
        await writeFile(
          join(projectPath, `feature-${steps}.js`),
          `export const fixed = ${steps};\n`,
        );
        structured = resolution({ id: "R1", decision: "FIX" });
      } else if (schema === schemas.FINALIZATION_SCHEMA) {
        if (format)
          await writeFile(
            join(projectPath, `feature-${step}.js`),
            `export const formatted = ${step};\n`,
          );
        structured = {
          ...finalizationPassed(""),
          requiredChecks: checks,
          validationInfrastructure: infrastructure,
          checks: checks.map(({ id, command }) => ({
            checkId: id,
            command,
            status: id === "C2" ? "NOT_RUN" : "PASS",
            evidence: ["Fixture check evidence."],
          })),
        };
      } else if (
        schema === schemas.REVIEW_SCHEMA ||
        schema === schemas.CLEAN_CONFIRM_SCHEMA
      ) {
        await onConfirmation?.(request);
        if (step === steps && pendingConfirmation && !invalidConfirmation) {
          invalidConfirmation = true;
          structured = { status: "INVALID" };
        } else if (step === steps && reuseFinalization && !terminalFindings) {
          terminalFindings = true;
          structured = cleanConfirmationFindings("R1");
        } else if (step === steps && (legacyFailure || providerFailures > 0)) {
          if (!legacyFailure) providerFailures -= 1;
          throw Object.assign(new Error("PRIVATE_LEGACY_PROVIDER_PAYLOAD"), {
            code: "ERR_CODEX_TURN_FAILED",
            diagnosticClass: "turn_other",
            recoverable: !legacyFailure,
          });
        } else
          structured =
            schema === schemas.REVIEW_SCHEMA
              ? reviewApproved()
              : cleanConfirmation();
      } else throw new Error("Unexpected fixture phase.");
      if (
        (schema.properties?.result?.anyOf?.[0]?.properties ?? schema.properties)
          ?.stepAssessment
      )
        (structured.result ?? structured).stepAssessment = assessment;
      return {
        structured,
        output: "fixture result",
        sessionId:
          request.session?.mode === "continue"
            ? request.session.id
            : randomUUID(),
      };
    },
  };
  const openStore = (options = {}) => createRunStore({ stateRoot, ...options });
  const store = openStore({ onTransitionBoundary });
  const openRunner = (runStore = openStore(), services = {}) =>
    createRunner({
      adapters: { codex: adapter },
      runStore,
      clarifications: createClarificationService({ interactive: false }),
      loadConfiguration: async () =>
        parseRunnerConfiguration(
          JSON.stringify({
            schemaVersion: 1,
            defaultBackend: "codex",
            ...(trusted
              ? {
                  trustedCommands: {
                    "fixture-check": {
                      command: "node --version",
                      executable: "node",
                      arguments: ["--version"],
                    },
                  },
                  pipelines: {
                    "plan-execution": { trustedChecks: ["fixture-check"] },
                  },
                }
              : {}),
          }),
        ),
      ...(trusted
        ? {
            trustedValidation: {
              async inspectRequirements() {
                return { status: "READY", blockers: [] };
              },
              async preflight() {},
              async execute({ commandIdentity }) {
                trustedExecutions += 1;
                return {
                  status: "PASS",
                  commandIdentity,
                  exitCode: 0,
                  signal: null,
                  timedOut: false,
                  evidence: ["Runner fixture evidence."],
                };
              },
            },
          }
        : {}),
      ...services,
    });
  const runner = openRunner(store);
  const created = await runner.create({
    pipelineId: "plan-execution",
    projectPath,
    taskPath,
    roleOverrides: {},
    settingOverrides: { mode },
    ...(source
      ? { sourceSession: { backend: "codex", id: "legacy-source" } }
      : {}),
  });
  const runId = created.run.runId;
  await assert.rejects(runner.resume({ runId }), {
    code: "ERR_CODEX_TURN_FAILED",
  });
  const failed = await store.loadRun(runId);
  assert.equal(failed.pipelineState.workflowState, "FAILED");
  legacyFailure = false;
  const directoryPath = await store.getRunDirectory(runId);
  return {
    calls,
    directoryPath,
    failed,
    git,
    mode,
    openRunner,
    openStore,
    get trustedExecutions() {
      return trustedExecutions;
    },
    projectPath,
    root,
    runId,
    runner,
    stateRoot,
    store,
    taskPath,
    failAgain(count = 1) {
      providerFailures = count;
    },
    async history() {
      return store.loadRunHistory(runId);
    },
    async rewrite(edit) {
      const history = structuredClone(await store.loadRunHistory(runId));
      await edit(history);
      await writeFile(
        join(directoryPath, "events.jsonl"),
        history.events.map((event) => JSON.stringify(event)).join("\n") + "\n",
      );
      await writeFile(
        join(directoryPath, "state.json"),
        JSON.stringify(history.events.at(-1).state) + "\n",
      );
    },
    async bytes() {
      return Promise.all(
        ["state.json", "events.jsonl", "progress.md"].map((name) =>
          readFile(join(directoryPath, name), "utf8"),
        ),
      );
    },
    async recoveryAction() {
      const { run } = await openRunner().status(runId);
      return planExecutionPipeline.projections.pause(run).nextActions;
    },
  };
}

// Downgrades remove transitions that only published fields absent in the old schema.
export function removeUnchangedEvents(events) {
  for (let index = events.length - 1; index > 0; index -= 1) {
    const comparable = ({ revision, updatedAt, ...state }) => state;
    if (
      events[index].activity === null &&
      isDeepStrictEqual(
        comparable(events[index - 1].state),
        comparable(events[index].state),
      )
    )
      events.splice(index, 1);
  }
  events.forEach((event, index) => {
    event.revision = index + 1;
    event.state.revision = index + 1;
  });
}
