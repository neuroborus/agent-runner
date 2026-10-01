import { isDeepStrictEqual } from "node:util";

import {
  isFailureDiagnostic,
  normalizeFailureDiagnostics,
} from "./diagnostics.js";
import { validateTrustedValidationSnapshot } from "./service.js";

const FAILURE_PAUSES = new Set([
  "environment_blocked",
  "no_progress",
  "fix_limit_reached",
]);
const HASH_PATTERN = /^[a-f0-9]{64}$/u;

// Project only a validated runner check and its matching generated issue.
// Issue prose and commands are never public diagnostic data or retry authority.
export function projectTrustedFailureDiagnostics(run, pause) {
  if (pause === null) return pause;
  const reason = ["operator_paused", "operator_canceled"].includes(pause.reason)
    ? run.pause?.operatorResume?.pause?.reason
    : pause.reason;
  const state = run.pipelineState;
  const finalization = state?.finalizationResult;
  if (
    !FAILURE_PAUSES.has(reason) ||
    finalization?.status !== "FAIL" ||
    !HASH_PATTERN.test(finalization.fingerprint) ||
    finalization.fingerprint !== state.repositoryBaseline?.contentFingerprint ||
    !HASH_PATTERN.test(finalization.validationInfrastructureFingerprint) ||
    typeof finalization.validationChanged !== "boolean" ||
    (Object.hasOwn(state, "currentStep") &&
      !state.validationScopeLegacy &&
      finalization.step !== state.currentStep) ||
    !Array.isArray(finalization.checks) ||
    !Array.isArray(finalization.issues) ||
    !Array.isArray(finalization.requiredChecks) ||
    finalization.requiredChecks.some(
      (entry) =>
        !/^C[1-9][0-9]{0,8}$/u.test(entry?.id) ||
        typeof entry?.command !== "string",
    ) ||
    finalization.checks.length !== finalization.requiredChecks.length ||
    finalization.checks.some(
      (check, index) =>
        check?.checkId !== finalization.requiredChecks[index]?.id ||
        check?.command !== finalization.requiredChecks[index]?.command,
    ) ||
    new Set(finalization.requiredChecks.map((entry) => entry.id)).size !==
      finalization.requiredChecks.length ||
    new Set(finalization.requiredChecks.map((entry) => entry.command)).size !==
      finalization.requiredChecks.length ||
    (!finalization.validationChanged &&
      (finalization.validationInfrastructureFingerprint !==
        state.validationInfrastructureFingerprint ||
        !isDeepStrictEqual(finalization.requiredChecks, state.requiredChecks) ||
        !isDeepStrictEqual(
          finalization.validationInfrastructure,
          state.validationInfrastructure,
        )))
  )
    return pause;
  let snapshot;
  try {
    snapshot = validateTrustedValidationSnapshot(state.trustedValidation);
  } catch {
    return pause;
  }
  if (
    finalization.trustedCommandFingerprint !== snapshot.commandFingerprint ||
    finalization.trustedConfigurationFingerprint !==
      snapshot.configurationFingerprint
  )
    return pause;
  const evidence = [];
  for (const check of finalization.checks) {
    if (evidence.length === 32) break;
    if (
      check.status !== "FAIL" ||
      check.executor !== "runner" ||
      check.timedOut !== false ||
      (check.exitCode !== null &&
        (!Number.isSafeInteger(check.exitCode) || check.exitCode === 0)) ||
      (check.signal !== null &&
        (typeof check.signal !== "string" || check.signal.length > 32)) ||
      (check.exitCode === null && check.signal === null) ||
      !/^C[1-9][0-9]{0,8}$/u.test(check.checkId) ||
      !Array.isArray(check.evidence)
    )
      continue;
    const command = snapshot.commands.find(
      (entry) => entry.identity === check.commandIdentity,
    );
    if (command?.command !== check.command) continue;
    const issue = finalization.issues.find(
      (entry) =>
        /^F[1-9][0-9]{0,8}$/u.test(entry?.id) &&
        entry.command === check.command &&
        entry.problem === "A runner-trusted validation command failed." &&
        isDeepStrictEqual(entry.evidence, check.evidence),
    );
    if (issue === undefined) continue;
    let diagnostics;
    try {
      diagnostics = normalizeFailureDiagnostics(
        check.evidence.filter(isFailureDiagnostic),
      );
    } catch {
      continue;
    }
    for (const diagnostic of diagnostics) {
      if (evidence.length === 32) break;
      evidence.push(
        `Runner check ${check.checkId}, issue ${issue.id}: ${diagnostic}`,
      );
    }
  }
  return evidence.length === 0
    ? pause
    : Object.freeze({
        ...pause,
        evidence: Object.freeze([...evidence, ...pause.evidence].slice(0, 32)),
      });
}
