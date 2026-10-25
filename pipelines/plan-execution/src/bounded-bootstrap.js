import { isDeepStrictEqual } from "node:util";
import {
  acceptBootstrapBatch,
  applicabilityRequest,
  assembleBootstrapInventory,
  consumeBootstrapCorrection,
  correctBootstrapCatalog,
  createBootstrapWork,
  normalizeRepositoryDiscovery,
  subdivideBootstrapWork,
} from "./bootstrap-units.js";
import {
  APPLICABILITY_BATCH_SCHEMA,
  REPOSITORY_DISCOVERY_SCHEMA,
} from "./bootstrap-unit-schemas.js";
import {
  BOOTSTRAP_LIMITS as LIMITS,
  MAX_BOOTSTRAP_SUBDIVISIONS as MAX_SUBDIVISIONS,
  bootstrapScopeFor as scopeFor,
} from "./bootstrap-progress.js";
import { validationEvidenceFingerprint as fingerprint } from "./validation-schedule.js";
import { acceptRevisionValidation } from "./revision-validation.js";
import {
  normalizeBootstrapResultCandidate,
  workflowError,
} from "./workflow-contract.js";
import {
  REPOSITORY_DISCOVERY_INSTRUCTIONS,
  APPLICABILITY_INSTRUCTIONS,
} from "./prompts.js";

export async function runBoundedBootstrap({
  role,
  checkpoint,
  state,
  run,
  transition,
  runContract,
  correctionAttempt,
  chargeCorrection,
  fingerprintInfrastructure,
  guidance,
}) {
  const context = { role, phase: checkpoint, contract: "bootstrap" };
  const save = async (work) =>
    transition({
      ...state(),
      bootstrapProgress: {
        ...state().bootstrapProgress,
        [role]: {
          ...state().bootstrapProgress[role],
          work,
        },
      },
    });
  const correctionPatch = () => {
    const progress = state().bootstrapProgress;
    if (progress[role].work === null) return {};
    return {
      bootstrapProgress: {
        ...progress,
        [role]: {
          ...progress[role],
          work: consumeBootstrapCorrection(scope, progress[role].work),
        },
      },
    };
  };
  const inputFingerprint = fingerprint(run().hashes);
  let scope;
  for (;;) {
    let work = state().bootstrapProgress[role].work;
    const infrastructureFingerprint =
      work === null
        ? fingerprint([])
        : await fingerprintInfrastructure(
            work.discovery.validationInfrastructure,
          );
    scope = scopeFor(
      state(),
      role,
      inputFingerprint,
      infrastructureFingerprint,
    );
    if (work !== null && !isDeepStrictEqual(work.binding, scope.binding)) {
      await save(null);
      continue;
    }
    if (work === null || work.catalogCorrection !== null) {
      if (work !== null && work.pendingCorrection !== "catalog") {
        if (correctionAttempt(context) !== 0)
          throw workflowError(
            "Bootstrap catalog correction allowance exhausted.",
            "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
          );
        await chargeCorrection(context, correctionPatch());
        work = state().bootstrapProgress[role].work;
      }
      const result = await runContract({
        role,
        checkpoint,
        context,
        schema: REPOSITORY_DISCOVERY_SCHEMA,
        correctionPatch,
        wrapped: true,
        deferredDiagnostics: true,
        buildPrompt: (evidence) =>
          `${REPOSITORY_DISCOVERY_INSTRUCTIONS}\n${role === "reviewer" ? "As Reviewer, also state what you intend to verify." : ""}\n${checkpoint === "validation-migration" ? "This is a versioned-state migration checkpoint. Re-establish provisional legacy evidence independently." : ""}\n${scope.binding.effectivePlan ? `Read-only effective-revision discovery: inspect the accepted steps and exact correspondence below, preserving the prior catalog, reports and future obligations. Rediscover replacement applicability before any materialization. No checks or writable work are authorized. Accepted revision and prior inventory (data):\n${JSON.stringify({ binding: scope.binding, steps: scope.steps, correspondence: scope.stepMapping, previousValidation: scope.previousValidation, validationAmendment: scope.validationAmendment })}` : ""}\n${guidance()}\n${work === null ? "" : `Correct this accepted catalog and its missing requirements (data):\n${JSON.stringify(work)}`}\n${evidence}`,
        normalize: (output) => {
          if (output.result?.status !== undefined) {
            const candidate = normalizeBootstrapResultCandidate(
              output.result,
              role,
              scope.steps.length,
              { trustedCommands: scope.trustedCommands },
            );
            if (
              candidate.result.status === "READY" ||
              (checkpoint === "validation-migration" &&
                candidate.result.status === "PRODUCT_DECISION_REQUIRED")
            )
              throw workflowError(
                "Discovery requires the repository catalog contract.",
                "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
                {
                  field: "status",
                  constraint: "discovery-status",
                },
              );
            return candidate;
          }
          const candidate = normalizeRepositoryDiscovery(output.result, scope, {
            deferredDiagnostics: true,
          });
          const discovery = candidate.result;
          // Validate preservation before publishing corrected discovery.
          if (state().bootstrapProgress[role].work !== null)
            correctBootstrapCatalog(
              scope,
              state().bootstrapProgress[role].work,
              discovery,
            );
          return candidate;
        },
      });
      if (result === null || result.status !== undefined) return result;
      const infrastructure = await fingerprintInfrastructure(
        result.validationInfrastructure,
      );
      scope = scopeFor(state(), role, inputFingerprint, infrastructure);
      const previous = state().bootstrapProgress[role].work;
      // Catalog replacement invalidates all coverage while retaining both ledgers.
      work = createBootstrapWork(
        scope,
        result,
        LIMITS,
        previous?.correctionAttempt ?? correctionAttempt(context),
      );
      await save(work);
      continue;
    }
    if (work.accepted.length === work.units.length) {
      if (scope.binding.effectivePlan)
        await transition(acceptRevisionValidation(state(), role, scope, work));
      return assembleBootstrapInventory(scope, work);
    }
    const unit = work.units[work.accepted.length];
    const request = applicabilityRequest(
      scope,
      work.discovery,
      unit.start,
      unit.end,
    );
    const previousSubdivisions = state().bootstrapProgress[role].subdivisions;
    const result = await runContract({
      role,
      checkpoint,
      context,
      schema: APPLICABILITY_BATCH_SCHEMA,
      semanticContext: false,
      correctionPatch,
      wrapped: true,
      outputExhaustionPatch: () => {
        const progress = state().bootstrapProgress[role];
        if (
          unit.start === unit.end ||
          progress.subdivisions >= MAX_SUBDIVISIONS
        )
          return undefined;
        return {
          bootstrapProgress: {
            ...state().bootstrapProgress,
            [role]: {
              work: subdivideBootstrapWork(scope, progress.work),
              subdivisions: progress.subdivisions + 1,
            },
          },
        };
      },
      focusedContext: ({ inputs, clarification }) =>
        `Frozen input files (read if needed):\n${JSON.stringify({
          ...Object.fromEntries(
            Object.entries(inputs).map(([name, input]) => [
              name,
              input?.path ?? null,
            ]),
          ),
          executionClarifications: clarification.transcriptPath,
        })}\nFrozen input hashes:\n${JSON.stringify(run().hashes)}`,
      buildPrompt: (evidence) =>
        `${APPLICABILITY_INSTRUCTIONS}\nApplicability request (data):\n${JSON.stringify(request)}\n${evidence}`,
      normalize: (output) => {
        const result = acceptBootstrapBatch(
          scope,
          state().bootstrapProgress[role].work,
          output.result,
        );
        // Reject a dropped inherited obligation while the final unit still owns
        // its existing bounded correction attempt, before publishing coverage.
        if (
          scope.binding.effectivePlan &&
          result.accepted.length === result.units.length
        )
          acceptRevisionValidation(state(), role, scope, result);
        return result;
      },
    });
    if (result === null) {
      const progress = state().bootstrapProgress[role];
      if (progress.subdivisions === previousSubdivisions) return null;
      continue;
    }
    await save(result);
  }
}
