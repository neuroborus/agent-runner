import { isAbsolute, join, relative, resolve, sep } from "node:path";

import { PlanExecutionWorkflowError } from "./errors.js";

const PREFLIGHT_CODES = new Set([
  "ERR_GIT_IDENTITY_REQUIRED",
  "ERR_GIT_UNAVAILABLE",
  "ERR_NOT_GIT_REPOSITORY",
  "ERR_REPOSITORY_NOT_CLEAN",
  "ERR_UNSAFE_REPOSITORY_PATH",
  "ERR_UNSUPPORTED_GIT_CONFIGURATION",
]);

export async function inspectCommitWorkspace({
  git,
  projectPath,
  artifactRoot,
  runId,
  pause,
}) {
  let discovery;
  try {
    discovery = await git.preflight({
      allowedPaths: [],
      projectPath,
      requireClean: true,
      requireIdentity: true,
      requiredIgnoredPaths: [],
    });
  } catch (cause) {
    if (!PREFLIGHT_CODES.has(cause?.code)) throw cause;
    await pause("unsafe_git_state", { code: cause.code });
    return null;
  }
  const repositoryPath = discovery?.snapshot?.projectPath;
  const prototype =
    discovery?.snapshot == null
      ? undefined
      : Object.getPrototypeOf(discovery.snapshot);
  const fromRoot =
    typeof repositoryPath === "string"
      ? relative(repositoryPath, projectPath)
      : null;
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    typeof repositoryPath !== "string" ||
    !isAbsolute(repositoryPath) ||
    resolve(repositoryPath) !== repositoryPath ||
    isAbsolute(fromRoot) ||
    fromRoot === ".." ||
    fromRoot.startsWith(`..${sep}`)
  ) {
    throw new PlanExecutionWorkflowError(
      "Git preflight returned an invalid repository root.",
      { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
    );
  }
  const clarificationPath = join(
    repositoryPath,
    artifactRoot,
    "agent-runner",
    runId,
    "clarifications.md",
  );
  let preflight;
  try {
    preflight = await git.preflight({
      allowedPaths: [clarificationPath],
      projectPath: repositoryPath,
      requireClean: true,
      requireIdentity: true,
      requiredIgnoredPaths: [clarificationPath],
    });
  } catch (cause) {
    if (cause?.code === "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED") {
      await pause("local_artifacts_not_ignored", { path: clarificationPath });
      return null;
    }
    if (!PREFLIGHT_CODES.has(cause?.code)) throw cause;
    await pause("unsafe_git_state", { code: cause.code });
    return null;
  }
  if (preflight?.snapshot?.projectPath !== repositoryPath) {
    throw new PlanExecutionWorkflowError(
      "Git preflight returned an unstable repository root.",
      { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
    );
  }
  return { snapshot: preflight.snapshot, clarificationPath };
}

// Consumed effects and stop recovery bypass this check in the workflow. A
// matching subject is never proof that the runner accepted the selected step.
export async function inspectCommitPlanPosition({
  git,
  projectPath,
  baseline,
  step,
}) {
  const observed = await git.inspectHead({ projectPath });
  if (observed.head === baseline.head && observed.subject !== step.subject)
    return null;
  const snapshot = await git.snapshot({
    projectPath,
    allowedPaths: baseline.allowedPaths,
  });
  // Independent control violations retain their existing safety diagnostics.
  if (
    [
      "branch",
      "detached",
      "remoteConfigurationFingerprint",
      "identityFingerprint",
    ].some((field) => snapshot[field] !== baseline[field]) ||
    (observed.head === baseline.head &&
      ["refsFingerprint", "indexFingerprint", "contentFingerprint"].some(
        (field) => snapshot[field] !== baseline[field],
      ))
  )
    return null;
  return [
    `Current step ${step.number}: ${step.subject}`,
    observed.subject === step.subject
      ? "HEAD already has the exact current planned subject."
      : "HEAD moved outside runner-authorized commit settlement.",
  ];
}
