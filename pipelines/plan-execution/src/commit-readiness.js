// These categories describe readiness evidence, independently of its provider.
const DIAGNOSTICS = Object.freeze({
  commit_readiness_workspace_change:
    "Commit readiness reported a workspace change item; this does not prove that content changed. Preserve resumable workspace content and use supported runner reconciliation. Repair the installed adapter before retrying; unsafe reconciliation requires a new run.",
  commit_readiness_git_operation:
    "Commit readiness reported a forbidden Git operation. Repair the installed adapter's readiness instructions to match its restricted inspection policy before retrying through supported COMMIT resume.",
  commit_readiness_invalid_result:
    'Commit readiness did not return exactly {"ready":true}. Repair the installed adapter\'s readiness handling before retrying through supported COMMIT resume.',
});

const EVIDENCE = Object.freeze([
  "The commit executor did not start.",
  "Git verified that no commit was created; the consumed authorization was retired.",
  "A supported COMMIT resume requires a fresh one-shot authorization.",
]);

export function isCommitReadinessDiagnosticClass(value) {
  return typeof value === "string" && Object.hasOwn(DIAGNOSTICS, value);
}

export function publicCommitReadinessDiagnostic(pause) {
  return pause.reason === "commit_failed" &&
    pause.resumeState === "COMMIT" &&
    isCommitReadinessDiagnosticClass(pause.diagnosticClass)
    ? Object.freeze({
        explanation: DIAGNOSTICS[pause.diagnosticClass],
        evidence: EVIDENCE,
      })
    : null;
}
