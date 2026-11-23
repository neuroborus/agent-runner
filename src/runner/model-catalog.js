import { isDeepStrictEqual } from "node:util";

import {
  AgentBoundaryError,
  MODEL_UNAVAILABLE_DIAGNOSTIC,
  normalizeFailureRecord,
} from "../agents/index.js";
import { MODEL_CATALOG_RETRY_CODE } from "../state/index.js";

import { RunnerError } from "./input.js";

export function createModelCatalogRecovery({
  run,
  providers,
  monitor,
  verify,
}) {
  const eligible = new WeakSet();
  const possible = new WeakSet();
  let writableRejection;
  let commitRejection;
  let pause =
    run.modelCatalogResume ??
    (run.pause?.code === MODEL_CATALOG_RETRY_CODE ? run.pause : null);
  const resuming = (role, checkpoint) =>
    pause?.role === role && pause.checkpoint === checkpoint;

  return Object.freeze({
    code: MODEL_CATALOG_RETRY_CODE,
    eligible: (cause) => eligible.has(cause),
    hasWritableNoEffect: (turn) =>
      isDeepStrictEqual(monitor?.writableNoEffectTurn, turn),
    hasPossibleEffect: (cause) => possible.has(cause),
    writableRejectionFor: (candidatePause) =>
      writableRejection !== undefined &&
      candidatePause?.code === MODEL_CATALOG_RETRY_CODE &&
      writableRejection.role === candidatePause.role &&
      writableRejection.checkpoint === candidatePause.checkpoint
        ? writableRejection.proof
        : undefined,
    // The proof belongs only to the transition that records this rejection.
    commitRejectionFor(pendingCommit) {
      const value = commitRejection;
      if (
        value === undefined ||
        pendingCommit?.status !== "consumed" ||
        pendingCommit.preEffectRejection?.catalog === undefined ||
        pendingCommit.authorization?.id !== value.authorizationId
      )
        return undefined;
      commitRejection = undefined;
      return value.proof;
    },
    details: (role, checkpoint) => ({
      code: MODEL_CATALOG_RETRY_CODE,
      role,
      checkpoint,
    }),
    resuming,
    claimResume(role, checkpoint) {
      if (pause === null) return false;
      if (!resuming(role, checkpoint))
        throw new RunnerError(
          "Model catalog retry changed its frozen checkpoint.",
          {
            code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
          },
        );
      pause = null;
      return true;
    },
    async observeFailure(cause, role, request, current) {
      if (
        !(cause instanceof AgentBoundaryError) ||
        cause.failure?.failureClass !== MODEL_UNAVAILABLE_DIAGNOSTIC ||
        current.activeTurn?.role !== role ||
        current.preparation !== null ||
        current.executionProcess !== null ||
        current.executionResource !== null
      )
        return;

      const configuration = current.roles[role];
      let failure;
      try {
        failure = normalizeFailureRecord(cause.failure, [
          ...providers.get(configuration.backend).failures.classes,
        ]);
      } catch {
        return;
      }
      if (
        failure.retry !== "terminal" ||
        failure.outcome !== "rejected" ||
        failure.disposition !== undefined
      )
        return;

      if (failure.checkpoint === "turn" && failure.effect === "possible") {
        if (request.session?.mode === "fork") return;
        await verify();
        possible.add(cause);
        return;
      }
      if (
        failure.effect !== "none" ||
        (request.access === "local-commit"
          ? failure.checkpoint !== "commit" ||
            failure.commitExecutor !== "not_started"
          : failure.checkpoint !== "turn")
      )
        return;

      // Configuration and stop guards can replace the provider error before
      // retry eligibility is established. Keep effect evidence on the turn.
      if (request.access === "workspace-write")
        monitor?.recordWritableNoEffect(current.activeTurn);
      await verify();
      if (
        request.session?.mode === "fork" ||
        !Object.hasOwn(current.modelCompletionReceipts, role) ||
        request.model !== configuration.model ||
        (request.profile ?? "current") !== configuration.profile ||
        (request.effort ?? "current") !== configuration.effort
      )
        return;

      const attempt = current.observations?.attempts.at(-1);
      if (request.access === "local-commit") {
        const pending = current.pipelineState?.pendingCommit;
        // Without the attempt's own rejection, the consumed authorization
        // still needs Git verification but cannot be renewed.
        if (
          pending?.status !== "consumed" ||
          pending.authorization.id !== request.authorizationId ||
          attempt?.role !== role ||
          attempt.status !== "failed" ||
          !isDeepStrictEqual(attempt.commitRejection, failure)
        )
          return;
        commitRejection = {
          authorizationId: request.authorizationId,
          proof: { attemptId: attempt.id, failure },
        };
      } else {
        const writable = request.access === "workspace-write";
        // A retry needs this invocation's durable no-effect rejection.
        if (
          attempt?.role !== role ||
          attempt.status !== "failed" ||
          (writable && attempt.writableRetryEligible !== true) ||
          !isDeepStrictEqual(
            writable ? attempt.writableRejection : attempt.readOnlyRejection,
            failure,
          )
        )
          return;
        if (writable)
          writableRejection = {
            role,
            checkpoint: attempt.checkpoint,
            proof: { attemptId: attempt.id, failure },
          };
      }
      eligible.add(cause);
    },
  });
}
