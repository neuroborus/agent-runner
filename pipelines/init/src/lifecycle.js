import { join } from "node:path";
import { isDeepStrictEqual as same } from "node:util";

import { inspectInitSetup } from "./inspection.js";
import {
  assertInitInspection,
  InitInspectionError,
  inspectInitOperation,
} from "./inspection-failure.js";
import {
  publishIntegratedInit,
  publishExternalInit,
} from "./prerequisite-publication.js";
import {
  assertInit,
  assertResultSize,
  digest,
  hashText,
  normalizeInitRoleResult,
  texts,
} from "./proposal.js";
import { REVIEW_SCHEMA } from "./schemas.js";
import { INIT_INSTRUCTIONS } from "./prompts.js";
import { initGuidanceContent } from "./guidance.js";
import { assertIntegratedPolicy } from "./integrated-policy.js";
import { assertExternalPolicy } from "./external-policy.js";
import {
  acceptInitEdit,
  acceptInitQuestionAppend,
  acceptInitResult,
  authorizeInitEdit,
  closeInitClarification,
  prepareInitTurn,
  requestInitDecision,
} from "./workflow.js";

const publisher = (state) =>
  state.selection.placement === "external"
    ? publishExternalInit
    : publishIntegratedInit;

// Read-only recovery proof: original baseline plus exact journaled publication
// paths. Pending effects are reconciled by their publisher before another turn.
export async function inspectInitWorkspace(run, setup) {
  return inspectInitOperation("recovery", () => inspectWorkspace(run, setup));
}

async function inspectWorkspace(run, setup) {
  const state = run.pipelineState;
  if (state.publication !== null) {
    const result = await publisher(state)(
      state,
      {
        ...setup,
        verifyOnly: true,
        guidancePaths: await setup.guidancePaths(state.guidanceIntent),
        clarifications: {
          freezeTranscript: async () => {
            const content = await setup.workspace.readFile({
              projectPath: run.taskPath,
              path: join(run.taskPath, "clarifications.md"),
            });
            assertInitInspection(
              hashText(content) === state.clarificationHash,
              "workspace_changed",
              "Frozen init clarification changed.",
            );
          },
        },
      },
      state.publication,
    );
    const inspected =
      state.selection.placement === "external" ? result.publication : result;
    if (state.guidanceReceipt !== null) {
      const observed = await setup.workspace.inspectInfrastructure({
        projectPath: state.selection.rootPath,
        path: state.guidanceIntent.path,
      });
      assertInitInspection(
        same(observed, state.guidanceReceipt.observed),
        "workspace_changed",
        "Published guidance changed.",
      );
    }
    if (state.terminal !== null)
      assertInitInspection(
        digest(inspected.snapshot) === state.terminal.fingerprint,
        "workspace_changed",
        "Terminal setup snapshot changed.",
      );
    return inspected;
  }
  const { inspection, snapshot } = state.setupBaseline;
  const after = await setup.workspace.snapshot({ inspection });
  const clarificationPath = join(run.taskPath, "clarifications.md");
  // The shared service alone owns transcript edits and exact append recovery.
  // Prepared infrastructure and every other task/workspace path stay frozen.
  if (state.pendingEdit === null) {
    const content = await setup.workspace.readFile({
      projectPath: run.taskPath,
      path: clarificationPath,
    });
    assertInitInspection(
      [state.transcriptHash, state.transcriptAppendHash].includes(
        hashText(content),
      ),
      "workspace_changed",
      "Init clarification changed outside its authorized window.",
    );
  }
  const protectedSnapshot = (value) => ({
    ...value,
    entries: value.entries.filter(({ path }) => path !== clarificationPath),
  });
  if (snapshot.schemaVersion === 2)
    setup.workspace.assertSnapshotProof({ before: snapshot, after });
  else
    setup.workspace.assertUnchanged({
      before: protectedSnapshot(snapshot),
      after: protectedSnapshot(after),
    });
  return { inspection, snapshot: after };
}

export async function runInit({ run, runtime, operatorStop = false }) {
  let current = run;
  const state = () => current.pipelineState;
  const transcript = {
    artifactRoot: run.taskPath,
    transcriptPath: join(run.taskPath, "clarifications.md"),
  };
  const save = async (pipelineState, patch = {}) => {
    if (
      same(state(), pipelineState) &&
      Object.entries(patch).every(([key, value]) => same(current[key], value))
    )
      return current;
    current = await runtime.transition({ pipelineState, ...patch });
    return current;
  };
  const inspect = async (
    previousInspection = state().reinspectionRequired
      ? state().inspection
      : null,
    phase = state().reinspectionRequired ? "reinspection" : "inspection",
  ) =>
    inspectInitOperation(phase, async () =>
      inspectInitSetup(
        {
          ...(await inspectInitOperation("discovery", () =>
            runtime.setup.discover(state()),
          )),
          previousInspection,
          schemaVersion: state().inspection?.schemaVersion ?? 2,
        },
        runtime.setup,
      ),
    );
  const pause = async (reason, resumeState = state().workflowState) => {
    await save(
      { ...state(), workflowState: "WAITING_FOR_USER", pendingTurn: null },
      { pause: { reason, resumeState } },
    );
    return current;
  };
  if (operatorStop || ["CANCELED", "FAILED"].includes(state().workflowState))
    return current;

  async function consumeEdit(result) {
    if (result.action === "product-decision") {
      await runtime.clarifications.freezeTranscript({
        ...transcript,
        expectedHash: result.hash,
      });
      await save(acceptInitEdit(state(), result), {
        hashes: { ...current.hashes, clarifications: result.hash },
        pause: null,
      });
      return;
    }
    // Placement choices are explicit operator text, accepted only in an authorized window.
    const content = await runtime.setup.workspace.readFile({
      projectPath: run.taskPath,
      path: transcript.transcriptPath,
    });
    const placements = [
      ...content.matchAll(/^placement: (integrated|external)$/gmu),
    ];
    const configurations = [
      ...content.matchAll(/^configurationPath: (\/[^\r\n]+)$/gmu),
    ];
    const selection = {
      ...state().clarificationSelection,
      ...(placements.length ? { placement: placements.at(-1)[1] } : {}),
      ...(configurations.length
        ? { configurationPath: configurations.at(-1)[1] }
        : {}),
    };
    await save(acceptInitEdit(state(), result, selection), {
      hashes: { ...current.hashes, clarifications: result.hash },
      pause: null,
    });
  }
  async function edit(action) {
    const decision = action === "product-decision";
    const suspendedState = decision ? "PROPOSE" : "CLARIFY";
    const authorization = await inspectInitOperation("preparation", () =>
      runtime.clarifications.prepareEdit({
        ...transcript,
        expectedHash: state().transcriptHash,
        action,
        suspendedState,
        persistPendingEdit: async (authorization) =>
          save(authorizeInitEdit(state(), authorization), {
            pause: {
              reason: decision
                ? "product_decision_required"
                : action === "proactive-clarification"
                  ? "proactive_clarification"
                  : "clarification_required",
              resumeState: suspendedState,
              inputRequest: {
                id: authorization.id,
                kind: decision ? "product-decision" : "clarification",
                artifactPath: authorization.transcriptPath,
                rationale: decision
                  ? state().productDecision.whyBlocked
                  : "Resolve setup requirements before publication. For placement selection use an exact line: placement: integrated or placement: external; an explicit selector uses configurationPath: /absolute/path.",
                questions: decision
                  ? [
                      {
                        id: "decision",
                        question: state().productDecision.question,
                        options: state().productDecision.options,
                      },
                    ]
                  : (state().pauseReason === "placement_conflict"
                      ? [
                          {
                            question:
                              "Select the infrastructure placement and exact configuration path from the inspected candidates.",
                            whyItMatters:
                              "Competing setups cannot be merged or selected implicitly.",
                          },
                        ]
                      : state().questions
                    ).map((entry, index) => ({
                      id: `q${index + 1}`,
                      question: entry.question,
                      rationale: entry.whyItMatters,
                      options: [],
                    })),
              },
            },
          }),
      }),
    );
    const result = await inspectInitOperation("preparation", () =>
      runtime.clarifications.openEditor(authorization, {
        consumePendingEdit: consumeEdit,
      }),
    );
    return result.status !== "WAITING_FOR_USER" && state().pendingEdit === null;
  }
  if (state().pendingEdit !== null) {
    await inspectInitOperation("preparation", () =>
      runtime.clarifications.acceptEdit(state().pendingEdit, {
        consumePendingEdit: consumeEdit,
      }),
    );
    if (state().pendingEdit !== null) return current;
  } else if (state().workflowState === "WAITING_FOR_USER") {
    if (
      ![
        "clarification_required",
        "placement_conflict",
        "product_decision_required",
      ].includes(state().pauseReason)
    ) {
      if (
        ![
          "provider_interrupted",
          "invalid_result",
          "authentication_required",
          "output_exhausted",
          "init_inspection_failed",
        ].includes(current.pause?.reason)
      )
        return current;
      await save(
        { ...state(), workflowState: current.pause.resumeState },
        { pause: null },
      );
    }
  }
  const initial = await inspectInitOperation("preparation", () =>
    runtime.clarifications.ensureTranscript(transcript),
  );
  if (state().transcriptHash === null) {
    const inputs = await inspectInitOperation("preparation", () =>
      runtime.readInputs({ taskPath: run.taskPath }),
    );
    await save(
      { ...state(), transcriptHash: initial.hash },
      {
        hashes: {
          task: inputs.task.hash,
          context: inputs.context?.hash ?? null,
          clarifications: initial.hash,
        },
      },
    );
  }
  if (current.activeTurn !== null)
    current = await runtime.finishAgentTurn(current.activeTurn);

  const appendOptions = () => ({
    ...transcript,
    expectedHash: state().transcriptHash,
    ...(state().transcriptAppendHash === null
      ? {}
      : { resultHash: state().transcriptAppendHash }),
    persistAppend: async ({ expectedHash, hash }) => {
      assertInit(
        expectedHash === state().transcriptHash &&
          (state().transcriptAppendHash === null ||
            state().transcriptAppendHash === hash),
        "Init append intent changed.",
      );
      await save({ ...state(), transcriptAppendHash: hash });
    },
  });

  async function turn(request) {
    const role = request.role;
    const before = await inspectInitOperation("preparation", () =>
      runtime.workspace.snapshot(),
    );
    const inputs = await inspectInitOperation("preparation", () =>
      runtime.readInputs({ taskPath: run.taskPath }),
    );
    const clarification = await inspectInitOperation("preparation", () =>
      runtime.clarifications.inspectTranscript(transcript),
    );
    const prompt = `${request.prompt}\n\n${JSON.stringify({
      task: inputs.task.content,
      context: inputs.context?.content ?? "",
      clarifications: clarification.content,
    })}`;
    const checkpoint = `init:${role}:${request.phase}:${state().revisionRounds}`;
    if (current.availabilityRetry != null && runtime.availability)
      current = await runtime.availability.before({
        role,
        checkpoint,
        repository: before,
      });
    try {
      if (runtime.inactivity)
        current = await runtime.inactivity.before({
          role,
          checkpoint,
          repository: before,
        });
    } catch (cause) {
      if (
        cause.recoverable !== true ||
        ![
          "ERR_PROVIDER_INACTIVE",
          "ERR_PROVIDER_RECONSTRUCTION_EXHAUSTED",
        ].includes(cause.code)
      )
        throw cause;
      await inspectInitOperation("post-turn", () =>
        runtime.workspace.assertUnchanged(before),
      );
      await pause("provider_interrupted");
      return null;
    }
    const lazy = state().settings.mode === "lazy";
    const key = digest(lazy ? "init:primary" : `init:${role}:${request.phase}`);
    const previous = [...current.sessionLineage.children]
      .reverse()
      .find((child) => child.role === role && child.contextKey === key);
    const source = current.sessionLineage.source;
    const reconstructing = current.inactivityRecovery != null;
    const session =
      !reconstructing && previous
        ? { mode: "continue", id: previous.sessionId }
        : !reconstructing &&
            source !== null &&
            !state().sourceForks.includes(key)
          ? { mode: "fork", id: source }
          : undefined;
    const active = {
      role,
      phase: request.phase.toLowerCase().replaceAll("_", "-"),
    };
    current = await runtime.startAgentTurn(active, {
      pipelineState: {
        ...state(),
        sourceForks:
          session?.mode === "fork"
            ? [...state().sourceForks, key]
            : state().sourceForks,
      },
    });
    const configuration = current.roles[role];
    let response;
    const acknowledgedSessions = new Set();
    try {
      response = await runtime.adapters[role].run({
        onSessionCreated: async (sessionId) => {
          assertInit(
            sessionId !== source &&
              sessionId !== previous?.sessionId &&
              !current.sessionLineage.children.some(
                (child) => child.sessionId === sessionId,
              ),
            "Init created child session identity is invalid.",
          );
          current = await runtime.recordChildSession({
            role,
            sessionId,
            contextKey: key,
          });
          acknowledgedSessions.add(sessionId);
        },
        access: "read-only",
        cwd: run.projectPath,
        schema: request.schema,
        prompt,
        recoveryPrompt: prompt,
        ...(session ? { session } : {}),
        ...Object.fromEntries(
          ["profile", "model", "contextSize", "effort"]
            .filter(
              (key) => configuration[key] && configuration[key] !== "current",
            )
            .map((key) => [key, configuration[key]]),
        ),
      });
    } catch (cause) {
      if (
        cause instanceof InitInspectionError ||
        cause.executionResourceRetained ||
        /^ERR_EXECUTION_/u.test(cause.code ?? "")
      )
        throw cause;
      await inspectInitOperation("post-turn", () =>
        runtime.workspace.assertUnchanged(before),
      );
      current = await runtime.finishAgentTurn(active, { repository: before });
      const policy = runtime.outputExhaustion?.eligible(cause)
        ? runtime.outputExhaustion
        : runtime.authentication?.eligible(cause)
          ? runtime.authentication
          : null;
      // Restore only this attempted fork when normalized evidence proves that
      // it never started. Later launch checkpoints cannot prove an unused fork.
      if (
        acknowledgedSessions.size === 0 &&
        session?.mode === "fork" &&
        ((policy && !policy.hasPossibleEffect(cause)) ||
          (cause.recoverable === true &&
            ["spawn", "initialize"].includes(cause.launchRecovery?.checkpoint)))
      )
        await save({
          ...state(),
          sourceForks: state().sourceForks.filter((value) => value !== key),
        });
      if (policy) {
        await pause(
          policy === runtime.outputExhaustion
            ? "output_exhausted"
            : "authentication_required",
        );
        return null;
      }
      if (
        runtime.inactivity?.eligible(cause) &&
        (await runtime.inactivity.retry({ repository: before }))
      )
        return turn(request);
      if (runtime.availability?.eligible(cause)) {
        current = await runtime.availability.schedule({
          cause,
          role,
          checkpoint,
          repository: before,
        });
        return turn(request);
      }
      if (cause.recoverable !== true) throw cause;
      await pause("provider_interrupted");
      return null;
    }
    await inspectInitOperation("post-turn", () =>
      runtime.workspace.assertUnchanged(before),
    );
    assertInit(
      typeof response.sessionId === "string" &&
        response.sessionId.length > 0 &&
        response.sessionId.length <= 1024 &&
        !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(response.sessionId) &&
        response.sessionId !== source &&
        (acknowledgedSessions.has(response.sessionId) ||
          response.sessionId === previous?.sessionId ||
          !current.sessionLineage.children.some(
            (child) => child.sessionId === response.sessionId,
          )),
      "Init child session identity is invalid.",
    );
    if (
      !acknowledgedSessions.has(response.sessionId) &&
      response.sessionId !== previous?.sessionId
    )
      current = await runtime.recordChildSession({
        role,
        sessionId: response.sessionId,
        contextKey: key,
      });
    current = await runtime.finishAgentTurn(active, { repository: before });
    assertResultSize(response.structured);
    return response.structured;
  }

  for (;;) {
    if (state().workflowState === "DONE") {
      await inspectInitWorkspace(current, runtime.setup);
      return current;
    }
    if (state().workflowState === "WAITING_FOR_USER") {
      if (state().productDecision !== null) {
        if (!state().productDecisionAppended) {
          const appended = await inspectInitOperation("preparation", () =>
            runtime.clarifications.appendProductDecision({
              ...appendOptions(),
              number: state().productDecisions,
              ...state().productDecision,
            }),
          );
          await save(
            {
              ...state(),
              transcriptHash: appended.hash,
              clarificationHash: appended.hash,
              transcriptAppendHash: null,
              productDecisionAppended: true,
            },
            {
              hashes: { ...current.hashes, clarifications: appended.hash },
              pause: {
                reason: "product_decision_required",
                resumeState: "PROPOSE",
              },
            },
          );
        }
        if (!(await edit("product-decision"))) return current;
        continue;
      }
      if (state().pauseReason === "placement_conflict") {
        if (state().clarificationRounds === 3)
          return pause("clarification_limit");
        await save({
          ...state(),
          pauseReason: "clarification_required",
          clarificationReady: false,
          clarificationRounds: state().clarificationRounds + 1,
          questionAppendPending: true,
          questions: [
            {
              question:
                "Select an inspected configuration using configurationPath: /absolute/path, or choose placement: integrated or placement: external.",
              whyItMatters:
                "Competing infrastructure cannot be merged or selected implicitly.",
            },
          ],
        });
      }
      if (state().questionAppendPending) {
        const expectedHash = state().transcriptHash;
        const round = state().clarificationRounds;
        const appended = await inspectInitOperation("preparation", () =>
          runtime.clarifications.appendQuestionRound({
            ...appendOptions(),
            round,
            questions: state().questions,
          }),
        );
        await save(
          acceptInitQuestionAppend(state(), {
            round,
            expectedHash,
            transcript: appended,
          }),
          { hashes: { ...current.hashes, clarifications: appended.hash } },
        );
      }
      if (
        ["clarification_required", "placement_conflict"].includes(
          state().pauseReason,
        )
      ) {
        if (!(await edit("clarification-answers"))) return current;
        continue;
      }
      return pause(state().pauseReason);
    }
    if (state().workflowState === "PROPOSAL_ACCEPTED") break;
    let inspection = await inspect();
    if (state().reinspectionRequired) {
      current = await inspectInitOperation("reinspection", () =>
        runtime.setup.extendReadScope(inspection.roots),
      );
      // Discover documents within the newly bound reads while retaining the
      // first inspection's exact resource and ancestor evidence.
      inspection = await inspect(inspection);
    }
    if (
      state().workflowState === "CLARIFY" &&
      state().proactiveClarification &&
      !state().proactiveClarificationComplete
    ) {
      await save({
        ...state(),
        inspection,
      });
      if (!(await edit("proactive-clarification"))) return current;
      continue;
    }
    const prepared = await inspectInitOperation("preparation", () =>
      prepareInitTurn(state(), inspection, state().transcriptHash),
    );
    await save(prepared.state);
    const output = await turn(prepared.request);
    if (output === null) return current;
    const afterInspection = await inspect(undefined, "post-turn");
    const afterTranscript = await inspectInitOperation("post-turn", () =>
      runtime.clarifications.inspectTranscript(transcript),
    );
    try {
      const next = await inspectInitOperation("post-turn", () =>
        acceptInitResult(state(), {
          turnId: prepared.request.id,
          inspection: afterInspection,
          transcriptHash: afterTranscript.hash,
          result: output,
        }),
      );
      if (next.proposal !== null) {
        runtime.setup.validateGuidance(initGuidanceContent(next));
        await (
          next.selection.placement === "external"
            ? assertExternalPolicy
            : assertIntegratedPolicy
        )(next, runtime.setup, "post-turn");
      }
      await save(next, {
        pause:
          next.workflowState === "WAITING_FOR_USER"
            ? {
                reason: next.pauseReason,
                resumeState:
                  next.productDecision === null ? "CLARIFY" : "PROPOSE",
              }
            : null,
      });
    } catch (cause) {
      if (
        ![
          "ERR_INIT_PROPOSAL",
          "ERR_INVALID_GUIDANCE",
          "ERR_INVALID_CONFIGURATION",
          "ERR_UNSUPPORTED_CONFIGURATION_VERSION",
        ].includes(cause.code)
      )
        throw cause;
      return pause("invalid_result");
    }
    if (state().workflowState === "CLARIFY" && state().clarificationReady) {
      await inspectInitOperation("preparation", () =>
        runtime.clarifications.freezeTranscript({
          ...transcript,
          expectedHash: state().transcriptHash,
        }),
      );
      const closureInspection = await inspect(undefined, "preparation");
      await save(
        await inspectInitOperation("preparation", () =>
          closeInitClarification(state(), {
            inspection: closureInspection,
            clarificationHash: state().transcriptHash,
          }),
        ),
      );
    }
  }
  const finished = await runtime.setup.withInfrastructureLease(
    state(),
    async (assertLease) => {
      const localContent = initGuidanceContent(state());
      runtime.setup.validateGuidance(localContent);
      const publicationRuntime = {
        ...runtime.setup,
        assertLease,
        clarifications: runtime.clarifications,
        inspectSetup: () => inspect(undefined, "publication-preparation"),
        persist: (publication) => save({ ...state(), publication }),
        guidancePaths: await runtime.setup.guidancePaths(
          state().guidanceIntent,
        ),
      };
      const result = await publisher(state())(
        state(),
        publicationRuntime,
        state().publication,
      );
      const publication =
        state().selection.placement === "external"
          ? result.publication
          : result;
      if (!same(state().publication, publication))
        await save({ ...state(), publication });
      const selected = {
        projectPath: run.projectPath,
        projectConfigurationPath: state().selection.configurationPath,
      };
      await inspectInitOperation("preparation", async () => {
        const loaded = await runtime.setup.loadProjectConfiguration({
          configurationPath: selected.projectConfigurationPath,
        });
        assertInitInspection(
          loaded?.artifactPath === state().selection.artifactPath &&
            loaded.infrastructure.rootPath === state().selection.rootPath,
          "destination_unavailable",
          "Prepared infrastructure is unavailable.",
        );
      });
      const guide = state().proposal.resources.find(
        ({ kind }) => kind === "guidance",
      );
      if (state().guidanceIntent === null) {
        const currentGuide = await inspectInitOperation(
          "preparation",
          async () => {
            const observed = await runtime.setup.readGuidance(selected);
            assertInitInspection(
              observed.localPath === guide.path &&
                observed.localHash === guide.beforeHash,
              "workspace_changed",
              "Guidance differs from the reviewed setup.",
            );
            return observed;
          },
        );
        await inspectInitWorkspace(current, runtime.setup);
        await save({
          ...state(),
          guidanceIntent: {
            ...selected,
            path: guide.path,
            beforeIdentity: currentGuide.localIdentity,
            idempotencyKey: `init-${run.runId}-${state().revisionRounds}-${state().productDecisions}`,
            expectedHash: guide.beforeHash,
            localContentHash: hashText(localContent),
            localContent,
          },
        });
      }
      if (state().guidanceReceipt === null) {
        await assertLease();
        const receipt = await runtime.setup.publishGuidance(
          state().guidanceIntent,
          state().guidanceIntent.localContent,
          assertLease,
        );
        const observed = await runtime.setup.workspace.inspectInfrastructure({
          projectPath: state().selection.rootPath,
          path: guide.path,
        });
        assertInit(
          receipt.localHash === state().guidanceIntent.localContentHash &&
            observed.file?.contentHash === receipt.localHash,
          "Guidance publication verification failed.",
        );
        await save({ ...state(), guidanceReceipt: { receipt, observed } });
      }
      const prepared = await inspectInitWorkspace(current, runtime.setup);
      if (state().terminal === null)
        await save({
          ...state(),
          terminal: {
            fingerprint: digest(prepared.snapshot),
            status: "PENDING",
          },
        });
      let output = await turn({
        phase: "CONFIRM",
        role: state().settings.mode === "lazy" ? "planner" : "reviewer",
        schema: REVIEW_SCHEMA,
        prompt: `${INIT_INSTRUCTIONS}\nDistinct terminal confirmation: inspect the complete published infrastructure, selected configuration, finalization, merged local guidance, checks and working directory. Return CLEAN only for this exact proposal and prepared fingerprint. Findings require renewed proposal gates.\n${JSON.stringify({ proposal: state().proposal, proposalHash: state().proposalHash, fingerprint: state().terminal.fingerprint, selection: state().selection })}`,
      });
      if (output === null) return current;
      try {
        output = normalizeInitRoleResult(output);
        if (output.status !== "PRODUCT_DECISION_REQUIRED") {
          texts(output.findings);
          assertInit(
            output.proposalHash === state().proposalHash &&
              (output.status === "CLEAN"
                ? output.findings.length === 0
                : output.findings.length > 0),
            "Init terminal confirmation is invalid.",
          );
        }
      } catch (cause) {
        if (cause.code !== "ERR_INIT_PROPOSAL") throw cause;
        return pause("invalid_result", "PROPOSAL_ACCEPTED");
      }
      await inspectInitWorkspace(current, runtime.setup);
      if (["FINDINGS", "PRODUCT_DECISION_REQUIRED"].includes(output.status)) {
        if (
          output.status === "FINDINGS" &&
          state().revisionRounds === state().settings.maxRevisionRounds
        ) {
          await save({
            ...state(),
            findings: output.findings,
            pauseReason: "revision_limit",
          });
          return pause("revision_limit", "PROPOSAL_ACCEPTED");
        }
        const inspection = await inspect();
        const procedure = state().proposal.resources.find(
          ({ kind }) => kind === "finalization",
        );
        const next = {
          ...state(),
          inspection,
          publication: null,
          guidanceIntent: null,
          guidanceReceipt: null,
          terminal: null,
          setupBaseline:
            state().inspection.schemaVersion === 1
              ? prepared
              : {
                  inspection: prepared.inspection,
                  snapshot: await inspectInitOperation("preparation", () =>
                    runtime.setup.workspace.snapshotProof({
                      snapshot: prepared.snapshot,
                      paths: [procedure.path],
                      ignorePaths: [transcript.transcriptPath],
                    }),
                  ),
                },
          primaryApproval: null,
          reviewApproval: null,
          proposal: null,
          proposalHash: null,
          createdFinalizationPath:
            procedure.beforeHash === null
              ? procedure.path
              : state().createdFinalizationPath,
          findings: output.findings ?? [],
          revisionRounds:
            state().revisionRounds + (output.status === "FINDINGS" ? 1 : 0),
          workflowState: "PROPOSE",
        };
        // Refresh only protection evidence for the same frozen selected paths.
        const candidate = inspection.candidates.find(
          ({ configurationPath }) =>
            configurationPath === state().selection.configurationPath,
        );
        assertInit(
          candidate &&
            [
              "placement",
              "rootPath",
              "artifactPath",
              "configurationPath",
            ].every((key) => candidate[key] === state().selection[key]),
          "Init repair cannot redirect its selection.",
        );
        next.selection = candidate;
        await save(
          output.status === "PRODUCT_DECISION_REQUIRED"
            ? requestInitDecision(next, output.decision)
            : next,
          {
            pause:
              output.status === "PRODUCT_DECISION_REQUIRED"
                ? {
                    reason: "product_decision_required",
                    resumeState: "PROPOSE",
                  }
                : null,
          },
        );
        return current;
      }
      await save(
        {
          ...state(),
          workflowState: "DONE",
          terminal: { ...state().terminal, status: "CLEAN" },
          completion: {
            placement: state().selection.placement,
            projectPath: run.projectPath,
            configurationPath: state().selection.configurationPath,
            artifactPath: state().selection.artifactPath,
            workingDirectory: run.projectPath,
            checks: state().proposal.checks,
            resources: state().proposal.resources.map(
              ({ path, kind, action }) => ({
                path,
                kind,
                status:
                  kind === "guidance"
                    ? state().guidanceReceipt.receipt.updated
                      ? guide.beforeHash === null
                        ? "created"
                        : "changed"
                      : "reused"
                    : {
                        create: "created",
                        replace: "changed",
                        reuse: "reused",
                      }[action],
              }),
            ),
            fingerprint: state().terminal.fingerprint,
          },
        },
        { pause: null },
      );
      return current;
    },
  );
  return finished.pipelineState.workflowState === "PROPOSE" ||
    finished.pipelineState.productDecision !== null
    ? runInit({ run: finished, runtime })
    : finished;
}
