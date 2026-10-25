import { join } from "node:path";

import { parseCommitPlan } from "@agent-runner/commit-plan";

import { commitSizeThreshold } from "./commit-size-assessment.js";
import { effectivePlanAuthority } from "./plan-position.js";

// Only persisted authority and verified settlement feed this projection. The
// Markdown is never read by selection, review, or effect reconciliation.
export function projectPlanProgress(run) {
  const state = run.pipelineState;
  // Safety pauses can publish activity before legacy settings migrate.
  if (
    !state.canonicalPlan ||
    !state.settings ||
    state.settings.preferredCommitLineLimit === undefined ||
    state.settings.commitSizeAssessmentMultiplier === undefined
  )
    return null;
  const authority = effectivePlanAuthority(state);
  const completed = state.completedCommits;
  const active = state.currentStep;
  const revisions = state.effectivePlanRevisions?.revisions ?? [];
  const originalSteps = parseCommitPlan(state.canonicalPlan).steps.map(
    ({ number: originalStep, subject }) => {
      const lineage = state.commitSizeAssessment?.lineages.find(
        (entry) => entry.originalStep === originalStep,
      );
      const attempt = lineage?.attempts.at(-1);
      const revision = revisions.findLast(
        (entry) => entry.originalStep === originalStep,
      );
      const proposalPlan =
        revision && !revision.accepted
          ? revision.replacementPlan
          : attempt?.result?.decision === "SPLIT" &&
              revision?.assessmentAttempt !== lineage.attempts.length
            ? attempt.result.replacementPlan
            : null;
      const replacements = authority.mapping.flatMap((entry, index) =>
        entry.originalStep !== originalStep
          ? []
          : [
              {
                step: entry.step,
                replacement: entry.replacement,
                label: `${originalStep}.${entry.replacement}`,
                subject: authority.steps[index].subject,
                status: completed[index]
                  ? "completed"
                  : entry.step === active
                    ? "active"
                    : "pending",
                head: completed[index] ?? null,
              },
            ],
      );
      const status = replacements.every((entry) => entry.head !== null)
        ? "completed"
        : replacements.some((entry) => entry.status === "active")
          ? "active"
          : "pending";
      const accepted = revisions.findLast(
        (entry) => entry.originalStep === originalStep && entry.accepted,
      );
      const ready = state.replacementExecution?.separations.some(
        (entry) =>
          entry.revision === accepted?.number && entry.phase === "ready",
      );
      const proposalStart =
        revision && !revision.accepted
          ? revision.mapping[revision.step - 1].replacement
          : (replacements.find((entry) => entry.status === "active")
              ?.replacement ?? 1);
      return {
        originalStep,
        subject,
        status,
        refinement:
          proposalPlan !== null
            ? "proposed"
            : accepted
              ? status === "completed"
                ? "completed"
                : ready &&
                    (status === "active" ||
                      replacements.some((entry) => entry.head !== null))
                  ? "executing"
                  : "accepted"
              : attempt?.result?.decision === "ATOMIC"
                ? "atomic"
                : null,
        measurement: attempt
          ? {
              changedLines: attempt.binding.changedLines,
              binaryFiles: attempt.binding.binaryFiles,
              gitlinks: attempt.binding.gitlinks,
            }
          : null,
        decision: attempt?.result?.decision ?? null,
        reason: attempt?.result?.reason ?? null,
        head: accepted ? null : replacements[0].head,
        replacements: accepted ? replacements : [],
        proposedReplacements:
          proposalPlan !== null
            ? parseCommitPlan(proposalPlan).steps.map((entry, index) => ({
                label: `${originalStep}.${proposalStart + index}`,
                subject: entry.subject,
                status: "pending",
                head: null,
              }))
            : [],
      };
    },
  );
  return {
    artifactPath: join(run.taskPath, "plan.progress.md"),
    effectiveRevision: authority.binding.revision,
    preferredCommitLineLimit: state.settings.preferredCommitLineLimit,
    threshold: commitSizeThreshold(state.settings),
    originalSteps,
  };
}

const inline = (value) =>
  String(value)
    .replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, " ")
    .replace(/[\\`*_[\]<>]/gu, "\\$&");

export function renderPlanProgress(run) {
  const progress = projectPlanProgress(run);
  if (progress === null) return null;
  const bodies = parseCommitPlan(run.pipelineState.canonicalPlan).steps;
  const lines = [
    `<!-- agent-runner plan-progress ${run.runId} -->`,
    "# Plan progress",
    "",
    "Derived from durable Runner state. Editing this file grants no approval, completion, or effect authority.",
    `Effective revision: ${progress.effectiveRevision}. Decimal labels are display-only; exact commit subjects remain unchanged.`,
    `Advisory planning target: ${progress.preferredCommitLineLimit} changed text lines. Execution assessment requires strictly more than ${progress.threshold}; size alone never rejects a commit.`,
  ];
  for (const entry of progress.originalSteps) {
    const note = `runner-size-${entry.originalStep}`;
    lines.push(
      "",
      `## Commit ${entry.originalStep}: ${entry.subject}`,
      bodies[entry.originalStep - 1].body,
      "",
      `Progress: ${entry.status}${entry.refinement ? `; refinement ${entry.refinement}` : ""}${entry.head ? `; verified SHA: ${entry.head}` : ""}.[^${note}]`,
      "",
      `[^${note}]: Measurement: ${entry.measurement ? `${entry.measurement.changedLines} changed text lines; ${entry.measurement.binaryFiles} binary files; ${entry.measurement.gitlinks} gitlinks` : "not assessed"}.`,
      `    Target: ${progress.preferredCommitLineLimit}; assessment threshold: >${progress.threshold}.`,
      `    Decision: ${entry.decision ?? "pending"}. Reason: ${entry.reason ? inline(entry.reason) : "No size decision recorded"}.`,
    );
    if (entry.replacements.length || entry.proposedReplacements.length)
      lines.push("");
    for (const replacement of entry.replacements) {
      lines.push(
        `    - ${replacement.label} (effective Commit ${replacement.step}): ${inline(replacement.subject)}; ${replacement.status}; verified SHA: ${replacement.head ?? "pending"}.`,
      );
    }
    for (const proposed of entry.proposedReplacements) {
      lines.push(
        `    - Proposed ${proposed.label}: ${inline(proposed.subject)}; pending; verified SHA: pending.`,
      );
    }
  }
  return { path: progress.artifactPath, content: `${lines.join("\n")}\n` };
}
