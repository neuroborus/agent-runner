import { join } from "node:path";

import { AuditWorkflowError, same } from "./discovery-contract.js";
import { publicationContent, reportPaths } from "./publication-contract.js";
import { validateResumeAction } from "./projections.js";
import { assertAuditRun } from "./verification-contract.js";
import { runAuditDiscovery } from "./workflow.js";

/** Persist intent before Runner publication; recover it before any further discovery. */
export async function runAudit({ run, runtime, operatorStop = false }) {
  assertAuditRun(run);
  if (operatorStop) return runAuditDiscovery({ run, runtime, operatorStop });
  let current = run;
  const [path, temporaryPath] = reportPaths(run.taskPath);
  const save = async (patch, options) => {
    current = await runtime.transition(patch, options);
    return current;
  };
  function requireBinding(
    condition,
    message,
    code = "ERR_AUDIT_REPORT_CHANGED",
  ) {
    if (!condition) throw new AuditWorkflowError(message, code);
  }
  async function inspectBindings() {
    const state = current.pipelineState;
    await runtime.workspace.assertUnchanged(state.repositoryBaseline);
    const inputs = await runtime.readInputs({ taskPath: run.taskPath });
    const clarification = await runtime.clarifications.inspectTranscript({
      artifactRoot: run.taskPath,
      transcriptPath: join(run.taskPath, "clarifications.md"),
    });
    requireBinding(
      inputs.task.hash === current.hashes.task &&
        (inputs.context?.hash ?? null) === current.hashes.context &&
        clarification.hash === current.hashes.clarifications,
      "Audit publication requires unchanged frozen inputs.",
      "ERR_AUDIT_INPUT_CHANGED",
    );
  }
  async function publish() {
    const state = current.pipelineState;
    if (
      state.report === null ||
      ["FAILED", "CANCELED"].includes(state.workflowState)
    )
      return;
    await inspectBindings();
    const { content, binding } = publicationContent(state);
    if (
      same(state.publication.published, binding) &&
      state.publication.pending === null
    ) {
      const inspected = await runtime.workspace.reportArtifact(
        { path, temporaryPath },
        { inspectOnly: true },
      );
      requireBinding(
        inspected.contentHash === binding.contentHash,
        "Published audit report changed.",
      );
      return;
    }
    if (state.publication.pending === null)
      await save({
        pipelineState: {
          ...state,
          publication: { ...state.publication, pending: binding },
        },
      });
    const result = await runtime.workspace.reportArtifact(
      {
        path,
        temporaryPath,
        content,
        expectedHash: state.publication.published?.contentHash ?? null,
      },
      {
        temporary: current.pipelineState.publication.temporary,
        recordTemporary: async (temporary) =>
          save({
            pipelineState: {
              ...current.pipelineState,
              publication: { ...current.pipelineState.publication, temporary },
            },
          }),
      },
    );
    requireBinding(
      result.path === path && result.contentHash === binding.contentHash,
      "Audit publication readback differs.",
    );
    await inspectBindings();
    await save({
      pipelineState: {
        ...current.pipelineState,
        publication: { pending: null, published: binding, temporary: null },
      },
    });
  }
  try {
    if (run.pipelineState.workflowState === "WAITING_FOR_USER") {
      try {
        validateResumeAction(run, null);
      } catch {
        return run;
      }
    }
    if (
      run.workspace?.policy &&
      ![path, temporaryPath].every((artifact) =>
        run.workspace.policy.artifactPaths.includes(artifact),
      )
    )
      throw new AuditWorkflowError(
        "Legacy audit lacks frozen report artifact bindings.",
        "ERR_AUDIT_REPORT_BINDING_REQUIRED",
      );
    // Settle pending publication before a subsequent pass changes its ledger.
    await publish();
    if (current.pipelineState.workflowState === "DONE") return current;
    current = await runAuditDiscovery({
      run: current,
      runtime: {
        ...runtime,
        transition: async (patch, options) => {
          await save(patch, options);
          // Editor windows retain the last accepted projection without writes.
          const state = current.pipelineState;
          if (
            state.report !== null &&
            state.workflowState !== "WAITING_FOR_USER" &&
            !same(
              publicationContent(state).binding,
              state.publication.published,
            )
          )
            await publish();
          return current;
        },
      },
    });
    if (current.pipelineState.workflowState === "DISCOVERY_CLEAN") {
      await publish();
      await save({
        pipelineState: { ...current.pipelineState, workflowState: "DONE" },
        pause: null,
      });
    }
    return current;
  } catch (cause) {
    const reason = {
      ERR_AUDIT_REPORT_CHANGED: "audit_report_changed",
      ERR_WORKSPACE_REPORT_CHANGED: "audit_report_changed",
      ERR_AUDIT_REPORT_BINDING_REQUIRED: "audit_report_binding_required",
      ERR_AUDIT_INPUT_CHANGED: "input_changed",
      ERR_WORKSPACE_DRIFT: "workspace_changed",
    }[cause?.code];
    if (!reason) throw cause;
    return save({
      pipelineState: {
        ...current.pipelineState,
        workflowState: "WAITING_FOR_USER",
      },
      pause: {
        reason,
        resumeState: current.pipelineState.workflowState,
        code: cause.code,
      },
    });
  }
}
