import { spawnSync } from "node:child_process";
import {
  resolveOwnedProcessLauncher,
  assertOwnedProcessLauncherProtected,
} from "../../../src/agents/index.js";
import { linuxPrerequisiteObservation } from "../index.js";
import {
  feasibilityFailureCause,
  requireFeasibility,
  unavailableFeasibilityResults,
} from "../feasibility/index.js";

export function linuxDiagnosticError(
  phase,
  operation,
  error,
  code = "setup-failed",
) {
  const cause =
    error?.feasibilityCause ??
    feasibilityFailureCause(phase, operation, error, code);
  const validated = unavailableFeasibilityResults("linux", cause)[0].cause;
  return Object.assign(new Error("Linux native operation failed."), {
    code: error?.code,
    feasibilityCause: validated,
    ...(error?.feasibilityCleanupCause
      ? { feasibilityCleanupCause: error.feasibilityCleanupCause }
      : {}),
  });
}

/** Capture presence, recognized output and native errors independently; the public launcher owns vectors and deadline. */
export function linuxNamespaceProbe(probe, phase, operation, capture) {
  return (file, args, options) => {
    let result;
    try {
      result = probe(file, args, {
        ...options,
        stdio: ["ignore", "pipe", "pipe"],
        encoding: "utf8",
        maxBuffer: 65536,
      });
    } catch (error) {
      capture(feasibilityFailureCause(phase, operation, error), null);
      throw error;
    }
    const observation = linuxPrerequisiteObservation(null, result);
    capture(
      feasibilityFailureCause(
        phase,
        operation,
        {
          ...observation,
          code: result.error?.code,
          signal: result.signal,
          stderr: result.stderr,
          stdout: result.stdout,
        },
        result.status === 1 && result.error === undefined && !result.signal
          ? "prerequisite-unavailable"
          : "setup-failed",
      ),
      result,
    );
    return result;
  };
}

export function resolveLinuxDiagnosticLauncher(
  cwd,
  {
    resolve = resolveOwnedProcessLauncher,
    protect = assertOwnedProcessLauncherProtected,
    probe = spawnSync,
    ...options
  } = {},
) {
  let operation = "launcher-discovery-protection",
    captured = null;
  try {
    const launcher = resolve(cwd, {
      ...options,
      cache: new Map(),
      probe: linuxNamespaceProbe(
        probe,
        "admission",
        options.ownershipMode === "native-sandbox-provider"
          ? "nested-namespaces"
          : "ordinary-namespace",
        (cause) => {
          captured = cause;
          operation = "namespace-admission";
        },
      ),
    });
    operation = "namespace-admission";
    if (launcher.isolatedNamespace !== true || launcher.hostSession !== false)
      throw Object.assign(new Error("CI namespace admission unavailable."), {
        code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      });
    operation = "launcher-protection";
    protect(launcher.file);
    return launcher;
  } catch (error) {
    throw linuxDiagnosticError(
      "admission",
      operation,
      captured && operation === "namespace-admission"
        ? { code: error?.code, feasibilityCause: captured }
        : error,
    );
  }
}

/** A failure carries no payload transcript and never establishes retirement. */
export function normalizeLinuxControllerFailure(value, candidateSha, nonce) {
  requireFeasibility(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === 5 &&
      Object.keys(value).sort().join() ===
        "candidateSha,cause,cleanupCause,nonce,type" &&
      ["candidateSha", "cause", "cleanupCause", "nonce", "type"].every((key) =>
        Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), "value"),
      ) &&
      value.type === "failed" &&
      typeof candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(candidateSha) &&
      typeof nonce === "string" &&
      /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(
        nonce,
      ) &&
      value.candidateSha === candidateSha &&
      value.nonce === nonce,
  );
  const cause = unavailableFeasibilityResults("linux", value.cause)[0].cause;
  const cleanupCause = unavailableFeasibilityResults(
    "linux",
    value.cleanupCause,
  )[0].cause;
  requireFeasibility(
    cause !== null &&
      (cleanupCause === null ||
        ["cleanup-failed", "cleanup-unobserved"].includes(cleanupCause.code)),
  );
  const normalized = {
    type: "failed",
    candidateSha,
    nonce,
    cause,
    cleanupCause,
  };
  requireFeasibility(Buffer.byteLength(JSON.stringify(normalized)) <= 1024);
  return normalized;
}

export function linuxControllerFailure(
  candidateSha,
  nonce,
  error,
  cleanupCause = null,
) {
  return normalizeLinuxControllerFailure(
    {
      type: "failed",
      candidateSha,
      nonce,
      cause: linuxDiagnosticError("controller", "execution", error)
        .feasibilityCause,
      cleanupCause,
    },
    candidateSha,
    nonce,
  );
}

export function linuxControllerError(value, candidateSha, nonce) {
  const failure = normalizeLinuxControllerFailure(value, candidateSha, nonce);
  return linuxDiagnosticError("controller", "execution", {
    feasibilityCause: failure.cause,
    feasibilityCleanupCause: failure.cleanupCause,
  });
}
