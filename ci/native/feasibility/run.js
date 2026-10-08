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
  if (dispatch.platform === "darwin") {
    const { runDarwinFeasibility } = await import("../darwin/index.js");
    return runDarwinFeasibility({
      ...dispatch,
      checkoutSha: observed.checkoutSha,
    });
  }
  if (dispatch.platform === "win32") {
    const { runWindowsFeasibility } = await import("../win32/index.js");
    return runWindowsFeasibility(dispatch, observed);
  }
  return [];
}

async function runProviders(dispatch, observed) {
  const { runProviderFeasibility } = await import("../providers/index.js");
  return runProviderFeasibility(dispatch, observed);
}

/** Explicit CI operation. Injection supplies portable orchestration coverage,
 * never native success. Dispatch and observed revision precede native effects. */
export async function runFeasibilityExperiment(
  argumentsList,
  {
    host,
    observe = observeCheckout,
    runNative: native = runNative,
    runProviders: providers = runProviders,
  } = {},
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
  if (["linux", "darwin", "win32"].includes(dispatch.platform)) {
    for (const absent of unavailableFeasibilityResults(dispatch.platform, {
      code: "missing-record",
      detail:
        "The matching feasibility owner omitted a required native capability record.",
    }).filter(({ capability }) =>
      feasibilityCapabilities(dispatch.platform).some(
        ({ id, tier }) => id === capability && tier === "native",
      ),
    ))
      if (!replacements.has(absent.capability))
        replacements.set(absent.capability, absent);
  }
  report.results = report.results.map(
    (entry) => replacements.get(entry.capability) ?? entry,
  );
  // Normalize cleanup evidence before it can authorize any subsequent effects.
  report.results = assessFeasibilityReport(report, dispatch).report.results;
  let providerResults;
  try {
    providerResults = report.results.some(({ cleanup }) =>
      ["FAIL", "UNCERTAIN"].includes(cleanup.status),
    )
      ? unavailableFeasibilityResults(dispatch.platform, {
          code: "prerequisite-unavailable",
          detail:
            "Unsettled native cleanup prevents subsequent provider admission.",
        }).filter(({ capability }) =>
          feasibilityCapabilities(dispatch.platform).some(
            ({ id, tier }) => id === capability && tier !== "native",
          ),
        )
      : await providers(dispatch, observed);
  } catch (error) {
    const unavailable =
      error?.code === "ERR_NATIVE_FEASIBILITY_WORKER_UNAVAILABLE";
    providerResults = unavailableFeasibilityResults(dispatch.platform, {
      code: unavailable ? "prerequisite-unavailable" : "setup-failed",
      detail: unavailable
        ? "The matching provider CI worker is unavailable."
        : "The provider feasibility owner did not return complete evidence.",
    })
      .filter(({ capability }) =>
        feasibilityCapabilities(dispatch.platform).some(
          ({ id, tier }) => id === capability && tier !== "native",
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
                    "The provider owner failed before independently reporting cleanup.",
                },
              },
            },
      );
  }
  requireFeasibility(
    Array.isArray(providerResults) &&
      new Set(providerResults.map(({ capability }) => capability)).size ===
        providerResults.length &&
      providerResults.every(({ capability }) =>
        feasibilityCapabilities(dispatch.platform).some(
          ({ id, tier }) => id === capability && tier !== "native",
        ),
      ),
  );
  const providerMap = new Map(
    providerResults.map((entry) => [entry.capability, entry]),
  );
  const missingProvider = unavailableFeasibilityResults(dispatch.platform, {
    code: "missing-record",
    detail:
      "The provider owner omitted a required experiment capability record.",
  });
  report.results = report.results.map((entry) =>
    feasibilityCapabilities(dispatch.platform).find(
      ({ id }) => id === entry.capability,
    ).tier === "native"
      ? entry
      : (providerMap.get(entry.capability) ??
        missingProvider.find(
          ({ capability }) => capability === entry.capability,
        )),
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
