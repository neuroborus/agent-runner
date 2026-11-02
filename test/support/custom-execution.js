import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
  lstat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { serializeCustomPlan } from "@agent-runner/custom-plan";
import { createClarificationService } from "../../src/clarifications/index.js";
import {
  inspectFinalizationFile,
  parseRunnerConfiguration,
} from "../../src/config/index.js";
import { createRunner } from "../../src/runner/index.js";
import { createRunStore } from "../../src/state/index.js";

import { runPlanExecution } from "@agent-runner/plan-execution";
import { directorySafety } from "../../src/runner/workspace.js";
import { createTrustedValidationSnapshot } from "../../src/trusted-validation/index.js";
import { createWorkspaceService } from "../../src/workspace/index.js";
import { executeFile } from "./runner.js";

const empty = { question: "", options: [], whyBlocked: "", evidence: [] };
const criteria = [
  {
    id: "traceability",
    condition: "Trace each conclusion to the supplied evidence.",
  },
];

export async function customExecutionFixture(
  t,
  mode,
  {
    beforeTurn,
    afterTransition,
    author = false,
    trusted = false,
    durable = false,
    contained = false,
    finalization = "auto",
    missingOutputRoot = false,
    afterOutputPreparation,
    writablePolicy = () => "fixture",
  } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "custom-execution-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repositoryPath = join(root, "repository");
  const projectPath = contained
    ? join(repositoryPath, "workspace")
    : join(root, "workspace");
  const taskPath = join(root, "task");
  const output = join(projectPath, "reports", "summary.md");
  await mkdir(missingOutputRoot ? projectPath : join(projectPath, "reports"), {
    recursive: true,
  });
  if (contained) {
    await executeFile("git", [
      "-c",
      "init.templateDir=",
      "init",
      "-q",
      repositoryPath,
    ]);
    await writeFile(
      join(repositoryPath, ".gitignore"),
      "/workspace/LOCAL_ARTIFACTS/\n",
    );
  }
  await mkdir(taskPath);
  const selectedGuidance = !["auto", "none"].includes(finalization)
    ? join(projectPath, finalization)
    : null;
  if (selectedGuidance) {
    await mkdir(join(projectPath, "review"));
    await writeFile(
      selectedGuidance,
      "Inspect the result and criterion observations. No executable check is required.\n",
    );
  }
  await writeFile(join(projectPath, "source.md"), "Supplied evidence.\n");
  await writeFile(
    join(taskPath, "task.md"),
    `Analyze the evidence, then write a summary. Agreed result criterion: ${criteria[0].condition}\n`,
  );
  const plan = serializeCustomPlan({
    kind: "custom",
    criteria,
    inputs: ["source.md", "https://example.invalid/reference"],
    outputs: [missingOutputRoot ? "reports/" : "reports"],
    steps: [1, 2].map((number) => ({
      number,
      title: number === 1 ? "Analyze evidence" : "Write summary",
      work:
        number === 1
          ? "Compare the source."
          : "Write reports/summary.md from the analysis.",
      expectedResults: "A traceable result with explicit evidence gaps.",
      criterionRefs: ["traceability"],
    })),
  });
  if (!author) await writeFile(join(taskPath, "plan.md"), plan);
  const store = createRunStore({ stateRoot: join(root, "state") });
  const calls = [];
  const probes = [];
  const trustedCalls = [];
  let runId;
  let memoryRun;
  const result = (step) => ({
    analysis:
      "The supplied source supports the conclusion; the remote reference was not retrieved.",
    evidence: [
      {
        criterionId: "traceability",
        observations: [
          "The conclusion cites source.md; the unavailable reference is labeled.",
        ],
      },
    ],
    outputPaths: step === 1 ? [] : [output],
  });
  const adapter = {
    async probe(options) {
      probes.push(options);
      return {
        version: "fixture",
        structuredOutput: true,
        readOnly: options.access === "read-only",
        autonomousWrite: options.access === "workspace-write",
        workspaceWrite: options.access === "workspace-write",
        declaredWorkspace: true,
        remoteWriteBlocked: true,
        gitMetadataWriteBlocked: true,
        nativeSessionContinuation: true,
        policyReceipt: {
          schemaVersion: 1,
          fingerprint: createHash("sha256")
            .update(
              JSON.stringify({
                options,
                writablePolicy:
                  options.access === "workspace-write"
                    ? writablePolicy()
                    : null,
              }),
            )
            .digest("hex"),
          supportedAccess: [options.access],
        },
      };
    },
    async run(request) {
      const saved = memoryRun ?? (await store.loadRun(runId));
      const state = saved.pipelineState;
      const step = state.currentStep ?? 1;
      const infrastructure = ["skill", "file"].includes(
        state.finalizationGuidance?.selection,
      )
        ? [state.finalizationGuidance.skillPath]
        : [];
      const checks =
        state.trustedValidation?.commands.map(({ command }, index) => ({
          id: `C${index + 1}`,
          command,
        })) ?? [];
      const assessment = {
        step,
        subject: step === 1 ? "Analyze evidence" : "Write summary",
        disposition: "CURRENT",
        evidence: [],
      };
      calls.push({
        phase: saved.activeTurn.phase,
        role: saved.activeTurn.role,
        step,
        request,
      });
      const override = await beforeTurn?.({ saved, request, calls, output });
      let structured;
      const properties = request.schema.properties;
      if (override !== undefined) structured = override;
      else if (saved.pipelineId === "plan-authoring") {
        if (state.workflowState === "CLARIFY")
          structured = { status: "READY", questions: [], criteria };
        else if (["ANALYZE", "DRAFT"].includes(state.workflowState))
          structured = { status: "DRAFT", plan, ...empty };
        else if (state.workflowState === "CHECK_AND_FIX")
          structured = { status: "UNCHANGED", plan: "", ...empty };
        else
          structured = {
            status:
              state.workflowState === "CLEAN_CONFIRM" ? "CLEAN" : "APPROVED",
            findings: [],
            ...empty,
          };
      } else if (saved.activeTurn.phase === "plan-context")
        structured = { stepAssessment: assessment };
      else if (
        properties.result?.anyOf?.some((branch) => branch.properties?.unitId)
      ) {
        const supplied = JSON.parse(
          /Applicability request \(data\):\n([^\n]+)/u.exec(request.prompt)[1],
        );
        structured = {
          result: {
            status: "READY",
            unitId: supplied.unitId,
            assignments: checks.map(({ id }) => ({
              checkId: id,
              steps: supplied.steps.map(({ number }) => number),
            })),
            missingCommands: [],
            missingInfrastructure: [],
            capabilityRequirements: [],
            environmentBlockers: [],
          },
        };
      } else if (
        properties.result?.anyOf?.some(
          (branch) => branch.properties?.requiredChecks,
        )
      ) {
        structured = {
          result: {
            stepAssessment: assessment,
            summary:
              "Inspect the supplied evidence and agreed traceability criterion; any selected criterion checks remain required.",
            requiredChecks: checks,
            validationInfrastructure: infrastructure,
            capabilityRequirements: [],
            environmentBlockers: [],
          },
        };
      } else if (state.workflowState === "CLARIFY")
        structured = {
          status: "READY",
          questions: [],
          reason: "",
          stepAssessment: assessment,
          ...empty,
        };
      else if (state.workflowState === "BOOTSTRAP")
        structured = {
          status: "RESOLVED",
          summary:
            "The agreed criteria require traceability and explicit evidence gaps, with semantic review in the selected mode.",
          disagreement: "",
          reason: "",
          stepAssessment: assessment,
          ...empty,
        };
      else if (state.workflowState === "IMPLEMENT") {
        if (step === 2)
          await writeFile(
            output,
            "Conclusion: supplied evidence (source.md). Remote evidence unavailable.\n",
          );
        structured = {
          status: "COMPLETED",
          summary: "Produced the criterion-bound result.",
          customResult: result(step),
          reason: "",
          ...empty,
        };
      } else if (state.workflowState === "CHECK_AND_FIX")
        structured = {
          status: "UNCHANGED",
          summary: "All agreed criteria hold.",
          customResult: state.customCandidate,
          reason: "",
          ...empty,
        };
      else if (state.workflowState === "CLEAN_CONFIRM")
        structured = { status: "CLEAN", findings: [], ...empty };
      else if (state.workflowState === "REVIEW")
        structured = { status: "APPROVED", findings: [], ...empty };
      else if (state.workflowState === "FINALIZE")
        structured = {
          status: "PASS",
          summary: "Inspected the result against its criteria.",
          skillPath: state.finalizationGuidance.skillPath ?? "",
          requiredChecks: checks,
          validationInfrastructure: infrastructure,
          checks: checks.map(({ id, command }) => ({
            checkId: id,
            command,
            status: "NOT_RUN",
            evidence: ["Reserved for Runner execution."],
          })),
          issues: [],
          reason: "",
          ...empty,
        };
      else if (state.workflowState === "CONFIRM")
        structured = {
          status: mode === "lazy" ? "CLEAN" : "APPROVED",
          findings: [],
          finalizationFindingIds: [],
          validationChange: "UNCHANGED",
          validationEvidence: [],
          ...empty,
        };
      else assert.fail(`Unexpected state ${state.workflowState}`);
      if (properties.result && !Object.hasOwn(structured, "result")) {
        if (properties.customResult) {
          const { customResult, ...statusResult } = structured;
          structured = { result: statusResult, customResult };
        } else structured = { result: structured };
      }
      return {
        structured,
        sessionId:
          request.session?.mode === "continue"
            ? request.session.id
            : `child-${calls.length}`,
      };
    },
  };
  const runner = createRunner({
    adapters: { codex: adapter },
    runStore: store,
    git: new Proxy(
      {},
      {
        get() {
          assert.fail("Custom execution invoked Git");
        },
      },
    ),
    clarifications: createClarificationService({ interactive: false }),
    loadConfiguration: async () =>
      parseRunnerConfiguration(
        JSON.stringify({
          schemaVersion: 1,
          defaultBackend: "codex",
          pipelines: {
            "plan-execution": { planKind: "custom", mode, finalization },
            "plan-authoring": {
              planKind: "custom",
              mode,
              sourceReferences: [
                "source.md",
                "https://example.invalid/reference",
              ],
              outputPaths: ["reports"],
            },
          },
        }),
      ),
  });
  if (author) {
    runId = (
      await runner.create({
        pipelineId: "plan-authoring",
        projectPath,
        taskPath,
      })
    ).run.runId;
    const authored = await runner.resume({ runId });
    assert.equal(
      authored.run.pipelineState.workflowState,
      "DONE",
      JSON.stringify(authored.run.pause),
    );
    assert.equal(await readFile(join(taskPath, "plan.md"), "utf8"), plan);
    calls.length = 0;
  }
  const created = await runner.create({
    pipelineId: "plan-execution",
    projectPath,
    taskPath,
  });
  runId = created.run.runId;
  const safety = directorySafety(
    created.run.workspace,
    createWorkspaceService(),
  );
  const digest = (value) =>
    createHash("sha256").update(JSON.stringify(value)).digest("hex");
  const lightweight = {
    async snapshot({ allowedPaths = [] } = {}) {
      const entries = [];
      if (missingOutputRoot) {
        const path = join(projectPath, "reports");
        try {
          const stat = await lstat(path);
          entries.push({
            path,
            kind: "directory",
            mode: stat.mode & 0o777,
            size: 0,
            hash: null,
            identity: {
              device: String(stat.dev),
              inode: String(stat.ino),
              mode: String(stat.mode),
            },
          });
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
          entries.push({
            path,
            kind: "missing",
            mode: null,
            size: 0,
            hash: null,
          });
        }
      }
      for (const path of [
        join(projectPath, "source.md"),
        output,
        ...(selectedGuidance ? [selectedGuidance] : []),
      ]) {
        try {
          entries.push({
            path,
            kind: "file",
            mode: "33188",
            size: 0,
            hash: digest(await readFile(path, "utf8")),
          });
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
      }
      return {
        schemaVersion: 1,
        projectPath,
        workspacePath: projectPath,
        outputPaths: [join(projectPath, "reports")],
        allowedPaths,
        entries,
        contentFingerprint: digest(entries),
        identityFingerprint: digest(entries),
      };
    },
    async assertUnchanged(before) {
      if (
        JSON.stringify((await this.snapshot()).entries) !==
        JSON.stringify(before.entries)
      )
        throw Object.assign(new Error("Workspace changed"), {
          code: "ERR_WORKSPACE_DRIFT",
        });
    },
    inspectPath: safety.inspectPath,
    async inspectOutputDirectory(path) {
      if (missingOutputRoot) return safety.inspectOutputDirectory(path);
      const stat = await lstat(path);
      const parentPath = join(path, "..");
      const parentStat = await lstat(parentPath);
      const binding = (path, stat) => ({
        path,
        exists: true,
        kind: "directory",
        ancestors: [],
        identity: {
          device: String(stat.dev),
          inode: String(stat.ino),
          mode: String(stat.mode),
        },
      });
      return {
        path,
        before: binding(path, stat),
        parent: binding(parentPath, parentStat),
        storage: null,
        staging: null,
      };
    },
    async prepareOutputDirectory(intent) {
      if (missingOutputRoot) {
        if (!intent.before.exists) await mkdir(intent.path, { mode: 0o700 });
        const { before: prepared } = await safety.inspectOutputDirectory(
          intent.path,
        );
        await afterOutputPreparation?.({ output });
        return { prepared, run: memoryRun };
      }
      return { prepared: intent.before, run: memoryRun };
    },
  };
  const transition = async (patch, options = {}) => {
    if (options.expectedRevision !== undefined)
      assert.equal(options.expectedRevision, memoryRun.revision);
    memoryRun = structuredClone({
      ...memoryRun,
      ...patch,
      revision: memoryRun.revision + 1,
    });
    await afterTransition?.(memoryRun);
    return memoryRun;
  };
  const runtime = {
    finalization: {
      inspectFile: ({ path }) => inspectFinalizationFile({ path, projectPath }),
    },
    adapters: Object.fromEntries(
      Object.keys(created.run.roles).map((role) => [
        role,
        {
          probe: async (options) =>
            options?.access
              ? adapter.probe(options)
              : {
                  version: "fixture",
                  structuredOutput: true,
                  readOnly: true,
                  declaredWorkspace: true,
                  remoteWriteBlocked: true,
                },
          run: adapter.run,
        },
      ]),
    ),
    clarifications: createClarificationService({ interactive: false }),
    workspace: lightweight,
    trustedValidation: {
      async preflight() {},
      async inspectRequirements() {
        return { status: "READY", blockers: [] };
      },
      async execute(request) {
        assert.ok(trusted, "Unexpected automatic coding check");
        assert.equal(
          request.bindings.contentFingerprint,
          (await lightweight.snapshot()).contentFingerprint,
        );
        assert.equal(memoryRun.activeTurn, null);
        trustedCalls.push(request);
        return {
          status: "PASS",
          commandIdentity: request.commandIdentity,
          exitCode: 0,
          signal: null,
          timedOut: false,
          evidence: ["The selected exact fixture vector passed."],
        };
      },
    },
    async readInputs() {
      const entries = await Promise.all(
        Object.entries({
          task: "task.md",
          plan: "plan.md",
          taskClarifications: "clarifications.md",
          context: "context.md",
        }).map(async ([key, name]) => {
          const path = join(taskPath, name);
          try {
            const content = await readFile(path, "utf8");
            return [
              key,
              {
                path,
                content,
                hash: createHash("sha256").update(content).digest("hex"),
              },
            ];
          } catch (error) {
            if (error.code !== "ENOENT") throw error;
            return [key, null];
          }
        }),
      );
      return Object.fromEntries(entries);
    },
    transition,
    startAgentTurn: (activeTurn, patch = {}) =>
      transition({ ...patch, activeTurn }),
    finishAgentTurn: () => transition({ activeTurn: null }),
    recordChildSession: (child) =>
      transition({
        sessionLineage: {
          ...memoryRun.sessionLineage,
          children: [...memoryRun.sessionLineage.children, child],
        },
      }),
    writeRunArtifact: async ({ path }) => join(root, "state", path),
  };
  if (!durable) memoryRun = structuredClone(created.run);
  if (trusted) {
    assert.equal(durable, false);
    memoryRun.pipelineState.trustedValidation = createTrustedValidationSnapshot(
      {
        verify: {
          command: "node verify-result.js",
          executable: "node",
          arguments: ["verify-result.js"],
        },
      },
      ["verify"],
    );
    memoryRun.pipelineState.settings.trustedChecks = ["verify"];
  }
  return {
    runner,
    store,
    runId,
    calls,
    probes,
    trustedCalls,
    output,
    projectPath,
    repositoryPath,
    taskPath,
    plan,
    result,
    get currentRun() {
      return memoryRun;
    },
    run: async () => {
      if (durable) return runner.resume({ runId });
      memoryRun = await runPlanExecution({ run: memoryRun, runtime });
      return { run: memoryRun };
    },
  };
}
