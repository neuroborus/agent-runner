import {
  appendFile,
  lstat,
  mkdir,
  readFile,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertProtectedNativeEnvironment } from "../index.js";
import {
  normalizeRelayPolicy,
  protectedFeasibilityReadiness,
} from "../providers/index.js";
import {
  assessFeasibilityReport,
  feasibilityCapabilities,
  feasibilityFailureCause,
  requireFeasibility,
  unavailableFeasibilityResults,
} from "./result.js";
import {
  observeFeasibilityCheckout,
  resolveFeasibilityDispatch,
  runFeasibilityExperiment,
} from "./run.js";
import { selectInstalledWindowsToolchain } from "./windows-toolchain.js";

const LIMIT = 1048576;
const INITIAL_DETAIL = "The probe stage has not returned a complete report.";
const STAGES = [
  "initialize",
  "prepare-darwin",
  "prepare-windows",
  "probe",
  "readiness",
  "protected",
  "cleanup",
  "report",
];

/** Installed discovery and sudo availability supply no audit or custody proof. */
export async function prepareDarwinFeasibilityObserver({
  command = promisify(execFile),
  capture = async () => {},
} = {}) {
  let operation = "darwin-sdk-discovery",
    exitCode = null,
    outcome = {};
  try {
    for (const [name, file, args] of [
      [
        "darwin-sdk-discovery",
        "/usr/bin/xcrun",
        ["--sdk", "macosx", "--show-sdk-path"],
      ],
      [
        "darwin-compiler-discovery",
        "/usr/bin/xcrun",
        ["--sdk", "macosx", "--find", "clang"],
      ],
      ["darwin-observer-authority", "/usr/bin/sudo", ["-n", "/usr/bin/true"]],
    ]) {
      operation = name;
      exitCode = null;
      outcome = {};
      await capture({ operation, exitCode });
      const result = await command(file, args, {
        encoding: "utf8",
        timeout: 10000,
        maxBuffer: 65536,
      });
      outcome = { ...result, exitCode: 0, signal: null, timedOut: false };
      exitCode = 0;
      await capture({ operation, exitCode });
      if (file === "/usr/bin/xcrun") {
        const value = result.stdout.trim();
        requireFeasibility(
          value.length <= 4096 &&
            path.posix.isAbsolute(value) &&
            path.posix.normalize(value) === value &&
            !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(value),
        );
      }
    }
    return { operation, exitCode, cause: null };
  } catch (error) {
    const facts = {
      ...outcome,
      code: error.code,
      stdout: error.stdout === undefined ? outcome.stdout : error.stdout,
      stderr: error.stderr === undefined ? outcome.stderr : error.stderr,
      signal: error.signal === undefined ? outcome.signal : error.signal,
      timedOut:
        error.timedOut === undefined ? outcome.timedOut : error.timedOut,
    };
    if (Number.isInteger(error.exitCode)) facts.exitCode = error.exitCode;
    else if (Number.isInteger(error.code) && error.signal === null)
      facts.exitCode = error.code;
    exitCode =
      Number.isInteger(facts.exitCode) &&
      facts.exitCode >= 0 &&
      facts.exitCode <= 255
        ? facts.exitCode
        : null;
    const cause = feasibilityFailureCause(
      "prepare",
      operation,
      facts,
      error.code === "ENOENT" ||
        (operation === "darwin-observer-authority" &&
          [1, "EPERM", "EACCES"].includes(error.code))
        ? "prerequisite-unavailable"
        : "setup-failed",
    );
    await capture({ operation, exitCode });
    return { operation, exitCode, cause };
  }
}

/** Dispatch, workflow and observed checkout are separate revision controls. */
export function assertFeasibilityRevision(dispatch, env, observed) {
  requireFeasibility(
    observed.checkoutSha === dispatch.expectedSha &&
      env.NATIVE_CANDIDATE_SHA === dispatch.expectedSha &&
      (dispatch.protectedAcceptance
        ? env.GITHUB_EVENT_NAME === "workflow_dispatch" &&
          env.GITHUB_SHA === dispatch.expectedSha &&
          env.GITHUB_WORKFLOW_SHA === dispatch.expectedSha
        : ["pull_request", "workflow_dispatch"].includes(
            env.GITHUB_EVENT_NAME,
          ) &&
          (env.GITHUB_EVENT_NAME === "pull_request" ||
            env.GITHUB_SHA === dispatch.expectedSha)),
  );
}

/** Operator-owned public bounds; neither environment variables nor this parser
 * attest native custody or authorize delivery of upstream credentials. */
export function feasibilityModelAuthorization(dispatch, env, environment) {
  const name = `native-feasibility-provider-${dispatch.platform}`;
  assertProtectedNativeEnvironment(environment, name);
  requireFeasibility(
    dispatch.protectedAcceptance &&
      env.NATIVE_FEASIBILITY_REVIEWED_SHA === dispatch.expectedSha &&
      env.NATIVE_FEASIBILITY_MODEL_USE_AUTHORIZED === "true",
  );
  const policies = Object.fromEntries(
    ["codex", "claude"].map((provider) => {
      const input = JSON.parse(
        env[`NATIVE_FEASIBILITY_${provider.toUpperCase()}_POLICY`],
      );
      const {
        nonce,
        provider: selected,
        ...policy
      } = normalizeRelayPolicy({
        ...input,
        provider,
        nonce: "0".repeat(32),
      });
      return [selected, policy];
    }),
  );
  return {
    candidateSha: dispatch.expectedSha,
    reviewedCandidate: true,
    environmentProtected: true,
    modelUseAuthorized: true,
    ...policies,
  };
}

/** Missing custody never inherits a previous PASS or erases a probe failure. */
export function assessUnavailableProtectedFeasibility(report, detail) {
  return assessFeasibilityReport(
    {
      ...report,
      results: report.results.map((entry) =>
        feasibilityCapabilities(report.platform).find(
          ({ id }) => id === entry.capability,
        ).tier === "protected" && entry.status !== "FAIL"
          ? {
              ...entry,
              status: "BLOCKED",
              cause: { code: "prerequisite-unavailable", detail },
            }
          : entry,
      ),
    },
    { protectedAcceptance: true },
  );
}

/** Reject malformed completion envelopes before assessing the current gate.
 * Protected jobs first receive a credential-free probe assessment. */
export function assessFeasibilityCompletion(input, dispatch, observed) {
  requireFeasibility(
    Object.keys(input).sort().join() === "issues,report,status" &&
      input.report.expectedSha === dispatch.expectedSha &&
      input.report.platform === dispatch.platform,
  );
  const assessment = assessFeasibilityReport(input.report, dispatch);
  requireFeasibility(
    (input.status === assessment.status ||
      (dispatch.protectedAcceptance &&
        input.status === assessFeasibilityReport(input.report).status)) &&
      Array.isArray(input.issues) &&
      input.issues.length === assessment.issues.length &&
      input.issues.every(
        (issue, index) =>
          Object.keys(issue).sort().join() === "code,detail" &&
          issue.code === assessment.issues[index].code &&
          issue.detail === assessment.issues[index].detail,
      ) &&
      ["checkoutSha", "os", "build", "architecture"].every(
        (key) => assessment.report[key] === observed[key],
      ),
  );
  return assessment;
}

function preparationMetadata(intent, env) {
  requireFeasibility(
    /^[1-9][0-9]{0,19}$/u.test(intent.runId) &&
      /^[1-9][0-9]{0,19}$/u.test(intent.runAttempt) &&
      env.NATIVE_CANDIDATE_SHA === intent.expectedSha &&
      env.NATIVE_PLATFORM === intent.platform &&
      env.GITHUB_RUN_ID === intent.runId &&
      env.GITHUB_RUN_ATTEMPT === intent.runAttempt,
  );
  const preparation = env.NATIVE_PREPARATION_CONCLUSION ?? "";
  const probe = env.NATIVE_PROBE_CONCLUSION ?? "";
  const cleanup = env.NATIVE_CLEANUP_CONCLUSION ?? "";
  requireFeasibility(
    [preparation, probe, cleanup].every((value) =>
      ["", "success", "failure", "cancelled", "skipped"].includes(value),
    ),
  );
  const operation = env.NATIVE_PREPARATION_OPERATION ?? "";
  const operations = {
    linux: ["linux-package-update", "linux-package-install"],
    win32: [
      "windows-discovery",
      "windows-sdk-setup",
      "windows-environment-export",
    ],
    darwin: [
      "darwin-sdk-discovery",
      "darwin-compiler-discovery",
      "darwin-observer-authority",
    ],
  };
  requireFeasibility(
    operation === "" || operations[intent.platform]?.includes(operation),
  );
  const captured = env.NATIVE_PREPARATION_EXIT_CODE ?? "";
  requireFeasibility(
    typeof captured === "string" &&
      (captured === "" || /^-?(?:0|[1-9][0-9]{0,9})$/u.test(captured)),
  );
  const exitCode = captured === "" ? null : Number(captured);
  requireFeasibility(
    exitCode === null ||
      (operation !== "" &&
        Number.isInteger(exitCode) &&
        exitCode >= (intent.platform === "win32" ? -2147483648 : 0) &&
        exitCode <= (intent.platform === "win32" ? 4294967295 : 255)),
  );
  requireFeasibility(
    preparation !== "success" || exitCode === null || exitCode === 0,
  );
  const diagnostic = (name, prefix, codes, platforms = ["win32"]) => {
    const captured = env[name] ?? "";
    requireFeasibility(
      typeof captured === "string" && Buffer.byteLength(captured) <= 512,
    );
    if (captured === "") return null;
    requireFeasibility(
      platforms.includes(intent.platform) &&
        ["failure", "cancelled"].includes(preparation),
    );
    let value;
    try {
      value = JSON.parse(captured);
    } catch {
      requireFeasibility(false);
    }
    const cause = unavailableFeasibilityResults(intent.platform, value)[0]
      .cause;
    requireFeasibility(
      cause !== null &&
        codes.includes(cause.code) &&
        cause.detail.startsWith(prefix),
    );
    return cause;
  };
  const cause = diagnostic(
    "NATIVE_PREPARATION_CAUSE",
    `prepare ${operation}: exit=${exitCode ?? "unknown"},`,
    ["setup-failed", "prerequisite-unavailable", "crash", "deadline"],
    ["darwin", "win32"],
  );
  const cleanupCause = diagnostic(
    "NATIVE_PREPARATION_CLEANUP_CAUSE",
    "cleanup windows-toolchain-files:",
    ["cleanup-failed"],
  );
  return {
    preparation,
    probe,
    cleanup,
    operation,
    exitCode,
    cause,
    cleanupCause,
  };
}

/** Failed preparation explains only untouched initialization placeholders. */
export function assessFeasibilityPreparation(input, intent, env) {
  const metadata = preparationMetadata(intent, env);
  const assessment = assessFeasibilityCompletion(input, intent, input.report);
  if (
    !["failure", "cancelled"].includes(metadata.preparation) ||
    metadata.probe === "success"
  )
    return assessment;
  const firstCause =
    metadata.cause ??
    metadata.cleanupCause ??
    feasibilityFailureCause(
      "prepare",
      metadata.operation || "unobserved-operation",
      {
        exitCode: metadata.exitCode,
      },
    );
  return assessFeasibilityReport(
    {
      ...assessment.report,
      results: assessment.report.results.map((entry) =>
        entry.cause?.code === "missing-record" &&
        entry.cause.detail === INITIAL_DETAIL &&
        entry.cleanup.status === "NOT_RUN" &&
        entry.evidence === null &&
        entry.elapsedMs === null &&
        entry.components.length === 0
          ? {
              ...entry,
              status:
                firstCause.code === "prerequisite-unavailable"
                  ? "BLOCKED"
                  : "FAIL",
              cause: firstCause,
            }
          : entry,
      ),
    },
    intent,
  );
}

export function renderFeasibilitySummary(input, intent, env) {
  const metadata = preparationMetadata(intent, env);
  const assessment = assessFeasibilityCompletion(input, intent, input.report);
  const cell = (value) =>
    String(value ?? "UNOBSERVED").replace(
      /[&<>|`\\\[\]*_~]/gu,
      (character) => `&#${character.codePointAt(0)};`,
    );
  const explanation = (cause) =>
    cause === null ? "none" : `${cause.code}: ${cause.detail}`;
  const preparation =
    metadata.cause || metadata.cleanupCause
      ? `Preparation cause: ${cell(explanation(metadata.cause))}\n\nPreparation file cleanup: ${cell(explanation(metadata.cleanupCause))}\n\n`
      : "";
  const coverage = ["native", "model-free", "protected"]
    .map((tier) => {
      const ids = feasibilityCapabilities(intent.platform)
        .filter((entry) => entry.tier === tier)
        .map((entry) => entry.id);
      const passed = assessment.report.results.filter(
        (entry) => ids.includes(entry.capability) && entry.status === "PASS",
      ).length;
      return `${tier}=${passed}/${ids.length}`;
    })
    .join(", ");
  return (
    `## Native feasibility ${intent.platform}: ${assessment.status}\n\nExpected checkout: ${cell(intent.expectedSha)}\n\nObserved checkout: ${cell(assessment.report.checkoutSha)}\n\nRun: ${cell(intent.runId)}; attempt: ${cell(intent.runAttempt)}\n\nOS/build/architecture: ${cell(assessment.report.os)} / ${cell(assessment.report.build)} / ${cell(assessment.report.architecture)}\n\nStep conclusions: preparation=${metadata.preparation || "unknown"}, probe=${metadata.probe || "unknown"}, cleanup=${metadata.cleanup || "unknown"}. Cleanup's step conclusion is an assessment, not a native cleanup witness.\n\n` +
    preparation +
    `Passing records: ${coverage}. Model-free evidence replaces no native or protected requirement.\n\n` +
    "| Capability | Result | Cleanup | First cause | Cleanup cause | Cleanup witness | Observed components |\n| --- | --- | --- | --- | --- | --- | --- |\n" +
    assessment.report.results
      .map(
        (entry) =>
          `| ${entry.capability} | ${entry.status} | ${entry.cleanup.status} | ${cell(explanation(entry.cause))} | ${cell(explanation(entry.cleanup.cause))} | independent=${entry.cleanup.independent}, emergency=${entry.cleanup.emergency}, sha256=${entry.cleanup.witnessSha256 ?? "UNOBSERVED"} | ${cell(entry.components.map((component) => `${component.role}:${component.name}@${component.version} sha256=${component.sha256}`).join("; ") || "UNOBSERVED")} |`,
      )
      .join("\n") +
    "\n\nThis experiment supplies no full acceptance, source-finding closure or production support approval.\n"
  );
}

async function readJSON(file) {
  const stat = await lstat(file);
  requireFeasibility(stat.isFile() && stat.nlink === 1 && stat.size <= LIMIT);
  const bytes = await readFile(file);
  requireFeasibility(bytes.length <= LIMIT);
  return JSON.parse(bytes);
}

async function persistJSON(file, value) {
  const bytes = JSON.stringify(value, null, 2) + "\n";
  requireFeasibility(Buffer.byteLength(bytes) <= LIMIT);
  const temporary = `${file}.${randomUUID()}.tmp`;
  await writeFile(temporary, bytes, { flag: "wx", mode: 0o600 });
  await rename(temporary, file);
}

async function fetchEnvironment(env, name) {
  requireFeasibility(
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(env.GITHUB_REPOSITORY) &&
      Boolean(env.GH_TOKEN),
  );
  const response = await fetch(
    `https://api.github.com/repos/${env.GITHUB_REPOSITORY}/environments/${name}`,
    {
      headers: {
        authorization: `Bearer ${env.GH_TOKEN}`,
        accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      redirect: "error",
      signal: AbortSignal.timeout(10000),
    },
  );
  requireFeasibility(response.ok);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    requireFeasibility(size <= LIMIT);
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function main() {
  const [flag, stage, ...argumentsList] = process.argv.slice(2),
    env = process.env;
  requireFeasibility(flag === "--stage" && STAGES.includes(stage));
  const dispatch = resolveFeasibilityDispatch(argumentsList, {
    ci: env.CI === "true",
    githubActions: env.GITHUB_ACTIONS === "true",
    runnerEnvironment: env.RUNNER_ENVIRONMENT,
    runnerOs: env.RUNNER_OS,
    platform: process.platform,
    architecture: process.arch,
  });
  requireFeasibility(
    path.isAbsolute(env.RUNNER_TEMP ?? "") &&
      /^[1-9][0-9]*$/u.test(env.GITHUB_RUN_ID ?? "") &&
      /^[1-9][0-9]*$/u.test(env.GITHUB_RUN_ATTEMPT ?? ""),
  );
  const directory = path.join(
    await realpath(env.RUNNER_TEMP),
    "native-feasibility-report",
  );
  const file = path.join(directory, "report.json"),
    intentFile = path.join(directory, "intent.json");
  const intent = {
    ...dispatch,
    runId: env.GITHUB_RUN_ID,
    runAttempt: env.GITHUB_RUN_ATTEMPT,
  };
  const observed = await observeFeasibilityCheckout();
  const failed = (detail, possible = false) =>
    assessFeasibilityReport(
      {
        schemaVersion: 1,
        expectedSha: dispatch.expectedSha,
        platform: dispatch.platform,
        ...observed,
        results: unavailableFeasibilityResults(dispatch.platform, {
          code: "missing-record",
          detail,
        }).map((entry) =>
          possible
            ? {
                ...entry,
                cleanup: {
                  status: "UNCERTAIN",
                  independent: false,
                  emergency: false,
                  elapsedMs: null,
                  witnessSha256: null,
                  cause: {
                    code: "cleanup-unobserved",
                    detail:
                      "Interrupted probes have no independent cleanup witness; owned fixtures remain quarantined.",
                  },
                },
              }
            : entry,
        ),
      },
      dispatch,
    );
  if (stage === "initialize") {
    await mkdir(directory, { mode: 0o700 });
    await persistJSON(intentFile, intent);
    await persistJSON(file, failed(INITIAL_DETAIL));
    try {
      assertFeasibilityRevision(dispatch, env, observed);
    } catch {
      process.exitCode = 1;
    }
    return;
  }
  requireFeasibility(
    (await lstat(directory)).isDirectory() &&
      (await realpath(directory)) === directory &&
      JSON.stringify(await readJSON(intentFile)) === JSON.stringify(intent),
  );
  let assessment;
  try {
    assessment = assessFeasibilityCompletion(
      await readJSON(file),
      dispatch,
      observed,
    );
    assertFeasibilityRevision(dispatch, env, observed);
  } catch {
    assessment = failed(
      "The persisted probe report is missing or malformed.",
      true,
    );
  }
  if (["prepare-darwin", "prepare-windows"].includes(stage)) {
    requireFeasibility(
      dispatch.platform === (stage === "prepare-darwin" ? "darwin" : "win32") &&
        assessment.report.results.every(
          ({ cause, cleanup }) =>
            cause?.code === "missing-record" &&
            cause.detail === INITIAL_DETAIL &&
            cleanup.status === "NOT_RUN",
        ),
    );
    assertFeasibilityRevision(dispatch, env, observed);
    if (stage === "prepare-darwin") {
      const prepared = await prepareDarwinFeasibilityObserver({
        capture: ({ operation, exitCode }) =>
          appendFile(
            env.GITHUB_OUTPUT,
            `operation=${operation}\nexit_code=${exitCode ?? ""}\n`,
          ),
      });
      await appendFile(
        env.GITHUB_OUTPUT,
        `cause=${prepared.cause === null ? "" : JSON.stringify(prepared.cause)}\n`,
      );
      process.exitCode = prepared.cause ? prepared.exitCode || 1 : 0;
      return;
    }
    const prepared = await selectInstalledWindowsToolchain(
      { environment: env, temporaryRoot: directory },
      {
        capture: ({ operation, exitCode }) =>
          appendFile(
            env.GITHUB_OUTPUT,
            `operation=${operation}\nexit_code=${exitCode ?? ""}\n`,
          ),
      },
    );
    if (prepared.cause === null && prepared.cleanupCause === null) {
      try {
        await appendFile(
          env.GITHUB_ENV,
          Object.entries(prepared.environment)
            .map(([name, value]) => `${name}=${value}\n`)
            .join(""),
        );
      } catch (error) {
        prepared.cause = feasibilityFailureCause(
          "prepare",
          "windows-environment-export",
          error,
        );
      }
    }
    await appendFile(
      env.GITHUB_OUTPUT,
      `cause=${prepared.cause === null ? "" : JSON.stringify(prepared.cause)}\ncleanup_cause=${prepared.cleanupCause === null ? "" : JSON.stringify(prepared.cleanupCause)}\n`,
    );
    process.exitCode =
      prepared.cause || prepared.cleanupCause ? prepared.exitCode || 1 : 0;
    return;
  }
  if (["probe", "readiness", "protected"].includes(stage)) {
    try {
      assertFeasibilityRevision(dispatch, env, observed);
      if (stage === "probe") {
        requireFeasibility(
          assessment.report.results.every(
            ({ cause, cleanup }) =>
              cause?.code === "missing-record" && cleanup.status === "NOT_RUN",
          ),
        );
        await persistJSON(
          file,
          failed(
            "Probe execution started but complete evidence and cleanup are not yet observed.",
            true,
          ),
        );
        // This stage never receives provider credentials or authorizes model use.
        assessment = await runFeasibilityExperiment(
          argumentsList.filter((value) => value !== "--protected"),
          {
            host: {
              ci: true,
              githubActions: true,
              runnerEnvironment: env.RUNNER_ENVIRONMENT,
              runnerOs: env.RUNNER_OS,
              platform: process.platform,
              architecture: process.arch,
            },
          },
        );
      } else {
        let detail =
          "Protected environment review and explicit bounded model authorization are unavailable.";
        try {
          const authorization = feasibilityModelAuthorization(
            dispatch,
            env,
            await fetchEnvironment(
              env,
              `native-feasibility-provider-${dispatch.platform}`,
            ),
          );
          // No stock protected native owner is admitted by the experiment CLI.
          // Never infer private transport/custody from variables or complete the
          // saved provider factories merely to unlock this credential step.
          detail = protectedFeasibilityReadiness(dispatch, authorization, null);
        } catch {
          /* Retain the public prerequisite diagnosis without raw API/configuration output. */
        }
        assessment = assessUnavailableProtectedFeasibility(
          assessment.report,
          detail,
        );
        if (env.GITHUB_OUTPUT)
          await appendFile(env.GITHUB_OUTPUT, "ready=false\n");
      }
    } catch {
      // Revision/setup failures never inherit a previously passing report.
      assessment = failed(
        "The candidate binding or CI probe setup failed.",
        true,
      );
    }
  }
  if (stage === "report")
    assessment = assessFeasibilityPreparation(assessment, intent, env);
  await persistJSON(file, assessment);
  if (stage === "report") {
    const summary = renderFeasibilitySummary(assessment, intent, env);
    await writeFile(path.join(directory, "summary.md"), summary, {
      mode: 0o600,
    });
    if (env.GITHUB_STEP_SUMMARY)
      await appendFile(env.GITHUB_STEP_SUMMARY, summary);
  }
  // Cleanup itself belongs to the native owners' finally paths. This always-run
  // boundary audits their independently observed settlement; absent/uncertain
  // witnesses fail without PID guesses, broad deletion or invented retirement.
  process.exitCode = assessment.status === "PASS" ? 0 : 1;
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch(() => {
    process.stderr.write(
      "Native feasibility CI stage or evidence is unavailable.\n",
    );
    process.exitCode = 1;
  });
}
