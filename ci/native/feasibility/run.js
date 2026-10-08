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

/** Explicit CI operation. Injection supplies portable orchestration coverage,
 * never native success. There are deliberately no implemented probe owners yet. */
export async function runFeasibilityExperiment(
  argumentsList,
  { host, observe = observeCheckout } = {},
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
  return assessFeasibilityReport(
    {
      schemaVersion: 1,
      expectedSha: dispatch.expectedSha,
      platform: dispatch.platform,
      checkoutSha: observed.checkoutSha,
      os: observed.os,
      build: observed.build,
      architecture: observed.architecture,
      results: unavailableFeasibilityResults(dispatch.platform, firstCause),
    },
    dispatch,
  );
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
