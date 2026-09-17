import { isDeepStrictEqual } from "node:util";

// Recovery proof belongs to the validated journal, never an agent's summary.
const recovered = new WeakMap();
const HASH = /^[a-f0-9]{64}$/u;
const HEAD = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u;

export function validImplementationEvidence(value, state) {
  return (
    value !== null &&
    typeof value === "object" &&
    Object.keys(value).length === 4 &&
    ["step", "head", "contentFingerprint", "accepted"].every((key) =>
      Object.hasOwn(value, key),
    ) &&
    Array.isArray(state.completedCommits) &&
    value.step === state.completedCommits.length + 1 &&
    value.head === state.repositoryBaseline?.head &&
    (value.head === null || HEAD.test(value.head)) &&
    typeof value.contentFingerprint === "string" &&
    HASH.test(value.contentFingerprint) &&
    typeof value.accepted === "boolean"
  );
}

export function implementationEvidence(state) {
  return {
    step: state.completedCommits.length + 1,
    head: state.repositoryBaseline.head,
    contentFingerprint: state.repositoryBaseline.contentFingerprint,
    accepted: false,
  };
}

export function prepareImplementationRecovery(run, history, migrate) {
  recovered.delete(run);
  if (!run.pipelineState.implementationEvidenceLegacy) return;
  try {
    if (
      !Array.isArray(history.events) ||
      history.events.length === 0 ||
      !isDeepStrictEqual(history.events.at(-1).state, history.run) ||
      !isDeepStrictEqual(migrate(history.run), run)
    )
      return;
    const target = run.pipelineState;
    let evidence = null;
    let previous = null;
    for (const [index, event] of history.events.entries()) {
      if (
        event.revision !== index + 1 ||
        event.state.revision !== event.revision ||
        event.runId !== run.runId
      )
        return;
      const historical = migrate(event.state);
      const state = historical.pipelineState;
      if (
        index === 0 &&
        (state.preflightComplete || historical.activeTurn !== null)
      )
        return;
      if (
        historical.projectPath !== run.projectPath ||
        historical.taskPath !== run.taskPath
      )
        return;
      if (!isDeepStrictEqual(state.completedCommits, target.completedCommits))
        continue;
      if (
        state.canonicalPlan !== null &&
        state.canonicalPlan !== target.canonicalPlan
      )
        return;
      if (
        state.repositoryBaseline !== null &&
        state.repositoryBaseline.head !== target.repositoryBaseline?.head
      )
        return;
      const writable =
        historical.activeTurn?.role === "worker" &&
        [
          "implement",
          "check-and-fix",
          "resolve-findings",
          "finalize",
          "commit",
        ].includes(historical.activeTurn.phase);
      if (writable && evidence === null) {
        if (
          historical.activeTurn.phase !== "implement" ||
          state.implementationDirection !== null ||
          state.repositoryBaseline === null
        )
          return;
        evidence = implementationEvidence(state);
      }
      if (
        evidence !== null &&
        !evidence.accepted &&
        previous?.workflowState === "IMPLEMENT" &&
        ["REVIEW", "CHECK_AND_FIX"].includes(state.workflowState)
      ) {
        if (
          state.repositoryBaseline.contentFingerprint ===
          evidence.contentFingerprint
        )
          return;
        evidence = { ...evidence, accepted: true };
      }
      previous = state;
    }
    // A journal with no writable entry proves its clean baseline is original.
    if (
      evidence === null &&
      target.repositoryBaseline?.clean === true &&
      ["CLARIFY", "BOOTSTRAP", "IMPLEMENT"].includes(
        run.pause?.resumeState ?? target.workflowState,
      )
    ) {
      evidence = implementationEvidence(target);
    }
    if (validImplementationEvidence(evidence, target)) {
      recovered.set(run, { run: structuredClone(run), evidence });
    }
  } catch {
    // Missing or inconsistent history grants no authority for new writable work.
  }
}

export function recoveredImplementationEvidence(run) {
  const proof = recovered.get(run);
  return proof && isDeepStrictEqual(proof.run, run) ? proof.evidence : null;
}
