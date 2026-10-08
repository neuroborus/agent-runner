import { execFile } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  assessFeasibilityReport,
  feasibilityCapabilities,
  requireFeasibility,
  unavailableFeasibilityResults,
} from "./result.js";

const executeFile = promisify(execFile);
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const RUNNER_OS = Object.freeze({
  linux: "Linux",
  darwin: "macOS",
  win32: "Windows",
});

/** No module/command selector, source-session fallback, or implicit host run. */
export function resolveFeasibilityDispatch(argumentsList, host) {
  requireFeasibility(Array.isArray(argumentsList) && argumentsList.length <= 5);
  const values = new Map();
  let protectedAcceptance = false;
  for (let index = 0; index < argumentsList.length; index += 1) {
    const name = argumentsList[index];
    if (name === "--protected") {
      requireFeasibility(!protectedAcceptance);
      protectedAcceptance = true;
    } else {
      requireFeasibility(
        ["--platform", "--expected-sha"].includes(name) && !values.has(name),
      );
      values.set(name, argumentsList[++index]);
    }
  }
  const platform = values.get("--platform");
  feasibilityCapabilities(platform);
  const expectedSha = values.get("--expected-sha");
  requireFeasibility(
    typeof expectedSha === "string" && /^[a-f0-9]{40}$/u.test(expectedSha),
  );
  requireFeasibility(
    host?.ci === true &&
      host.githubActions === true &&
      host.runnerEnvironment === "github-hosted" &&
      host.runnerOs === RUNNER_OS[platform] &&
      host.platform === platform &&
      host.architecture === "x64",
  );
  return Object.freeze({ platform, expectedSha, protectedAcceptance });
}

async function observeCheckout() {
  const { stdout } = await executeFile("git", ["rev-parse", "HEAD"], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 3000,
    maxBuffer: 128,
  });
  return {
    checkoutSha: stdout.trim(),
    os: process.platform,
    build: `${os.type()} ${os.release()} ${os.version()}`,
    architecture: process.arch,
  };
}

async function runNative(dispatch, observed) {
  if (dispatch.platform === "linux") {
    const { runLinuxFeasibility } = await import("../linux/index.js");
    return runLinuxFeasibility({
      ...dispatch,
      checkoutSha: observed.checkoutSha,
    });
  }
  return [];
}

/** Explicit CI operation. Injection supplies portable orchestration coverage,
 * never native success. Dispatch and observed revision precede native effects. */
export async function runFeasibilityExperiment(
  argumentsList,
  { host, observe = observeCheckout, runNative: native = runNative } = {},
) {
  const dispatch = resolveFeasibilityDispatch(argumentsList, host);
  let observed;
  let firstCause;
  try {
    observed = await observe();
  } catch (error) {
    const code =
      typeof error?.code === "string" && /^[A-Z0-9_]{1,32}$/u.test(error.code)
        ? error.code
        : Number.isInteger(error?.code) && error.code >= 0 && error.code <= 255
          ? `EXIT_${error.code}`
          : "UNOBSERVED";
    firstCause = {
      code: "setup-failed",
      detail: `Checkout observation failed: ${code}.`,
    };
    observed = { checkoutSha: null, os: null, build: null, architecture: null };
  }
  const report = {
    schemaVersion: 1,
    expectedSha: dispatch.expectedSha,
    platform: dispatch.platform,
    checkoutSha: observed.checkoutSha,
    os: observed.os,
    build: observed.build,
    architecture: observed.architecture,
    results: unavailableFeasibilityResults(dispatch.platform, firstCause),
  };
  const initial = assessFeasibilityReport(report, dispatch);
  if (initial.status === "FAIL") return initial;
  let implemented;
  try {
    implemented = await native(dispatch, observed);
  } catch (error) {
    const unavailable =
      error?.code === "ERR_NATIVE_FEASIBILITY_WORKER_UNAVAILABLE";
    implemented = unavailableFeasibilityResults(dispatch.platform, {
      code: unavailable ? "prerequisite-unavailable" : "setup-failed",
      detail: unavailable
        ? "The matching hosted CI worker is unavailable."
        : "The native feasibility owner failed before returning a complete report.",
    })
      .filter(({ capability }) =>
        feasibilityCapabilities(dispatch.platform).some(
          ({ id, tier }) => id === capability && tier === "native",
        ),
      )
      .map((entry) =>
        unavailable
          ? entry
          : {
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
                    "The native owner failed before independently reporting cleanup.",
                },
              },
            },
      );
  }
  const replacements = new Map(
    implemented.map((entry) => [entry.capability, entry]),
  );
  requireFeasibility(
    replacements.size === implemented.length &&
      implemented.every(({ capability }) =>
        feasibilityCapabilities(dispatch.platform).some(
          ({ id, tier }) => id === capability && tier === "native",
        ),
      ),
  );
  if (dispatch.platform === "linux") {
    for (const absent of unavailableFeasibilityResults("linux", {
      code: "missing-record",
      detail:
        "The Linux feasibility owner omitted a required native capability record.",
    }).filter(({ capability }) =>
      feasibilityCapabilities("linux").some(
        ({ id, tier }) => id === capability && tier === "native",
      ),
    ))
      if (!replacements.has(absent.capability))
        replacements.set(absent.capability, absent);
  }
  report.results = report.results.map(
    (entry) => replacements.get(entry.capability) ?? entry,
  );
  return assessFeasibilityReport(report, dispatch);
}

async function main() {
  const assessment = await runFeasibilityExperiment(process.argv.slice(2), {
    host: {
      ci: process.env.CI === "true",
      githubActions: process.env.GITHUB_ACTIONS === "true",
      runnerEnvironment: process.env.RUNNER_ENVIRONMENT,
      runnerOs: process.env.RUNNER_OS,
      platform: process.platform,
      architecture: process.arch,
    },
  });
  process.stdout.write(`${JSON.stringify(assessment, null, 2)}\n`);
  process.exitCode = assessment.status === "PASS" ? 0 : 1;
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch(() => {
    process.stderr.write("Native feasibility dispatch or evidence failed.\n");
    process.exitCode = 1;
  });
}
