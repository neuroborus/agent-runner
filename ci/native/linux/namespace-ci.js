import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  appendFile,
  lstat,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  nativeCleanupFailure,
  nativeJobHasPossibleEffects,
  normalizeNativeJob,
  requireObservation,
} from "../index.js";
import { assessFeasibilityReport } from "../feasibility/index.js";
import {
  initialLinuxNamespacePreparation,
  linuxNamespaceContext,
  linuxNamespacePolicyRetired,
  normalizeLinuxNamespacePreparation,
} from "./namespace-policy.js";
import {
  prepareLinuxNamespaces,
  cleanupLinuxNamespaces,
  verifyLinuxNamespaces,
  readLinuxNamespaceEvidence,
} from "./namespace-preparation.js";

const execute = promisify(execFile);
export function linuxNamespaceSettlement(input, context, kind) {
  linuxNamespaceContext(context);
  if (kind === "minimal") {
    const report = assessFeasibilityReport(input.report).report;
    requireObservation(
      report.platform === "linux" &&
        report.expectedSha === context.candidateSha &&
        report.checkoutSha === context.candidateSha,
    );
    return report.results.every(
      ({ cleanup, evidence, elapsedMs }) =>
        (cleanup.status === "PASS" &&
          cleanup.independent &&
          !cleanup.emergency) ||
        (cleanup.status === "NOT_RUN" &&
          evidence === null &&
          elapsedMs === null),
    );
  }
  requireObservation(["system", "provider"].includes(kind));
  const job = normalizeNativeJob(input);
  requireObservation(
    job.platform === "linux" &&
      job.candidateSha === context.candidateSha &&
      job.provenance.runId === context.runId &&
      String(job.provenance.runAttempt) === context.runAttempt,
  );
  return (
    nativeCleanupFailure(job) === null &&
    (!nativeJobHasPossibleEffects(job) || job.stages.cleanup.status === "PASS")
  );
}

async function main() {
  const [stageFlag, stage, kindFlag, kind] = process.argv.slice(2),
    env = process.env;
  requireObservation(
    process.argv.length === 6 &&
      stageFlag === "--stage" &&
      ["prepare", "verify", "cleanup"].includes(stage) &&
      kindFlag === "--report" &&
      ["minimal", "system", "provider"].includes(kind),
  );
  requireObservation(
    process.platform === "linux" &&
      process.arch === "x64" &&
      env.NATIVE_PLATFORM === "linux" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24" &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      env.RUNNER_OS === "Linux" &&
      path.isAbsolute(env.RUNNER_TEMP ?? ""),
  );
  const context = linuxNamespaceContext({
    candidateSha: env.NATIVE_CANDIDATE_SHA,
    runId: env.GITHUB_RUN_ID,
    runAttempt: env.GITHUB_RUN_ATTEMPT,
  });
  const observed = await execute("git", ["rev-parse", "HEAD"], {
    timeout: 5000,
    maxBuffer: 1024,
  });
  requireObservation(observed.stdout.trim() === context.candidateSha);
  const temporary = await realpath(env.RUNNER_TEMP),
    directory = path.join(
      temporary,
      kind === "minimal" ? "native-feasibility-report" : `native-${kind}`,
    );
  requireObservation(
    (await lstat(directory)).isDirectory() &&
      (await realpath(directory)) === directory,
  );
  if (kind === "minimal") {
    const intent = await readLinuxNamespaceEvidence(
      path.join(directory, "intent.json"),
    );
    requireObservation(
      intent.platform === "linux" &&
        intent.expectedSha === context.candidateSha &&
        intent.runId === context.runId &&
        intent.runAttempt === context.runAttempt,
    );
  }
  const file = path.join(directory, "linux-namespace-preparation.json");
  const persist = async (value) => {
    const bytes =
      JSON.stringify(normalizeLinuxNamespacePreparation(value, context)) + "\n";
    requireObservation(Buffer.byteLength(bytes) <= 32768);
    const replacement = `${file}.${randomUUID()}.tmp`;
    await writeFile(replacement, bytes, { flag: "wx", mode: 0o600 });
    await rename(replacement, file);
  };
  let record;
  if (stage === "prepare") {
    if (env.GITHUB_OUTPUT)
      await appendFile(
        env.GITHUB_OUTPUT,
        "operation=linux-namespace-policy\nexit_code=\n",
      );
    const previous = normalizeLinuxNamespacePreparation(
      await readLinuxNamespaceEvidence(file),
      context,
    );
    requireObservation(
      previous.status === "NOT_RUN" &&
        JSON.stringify(previous) ===
          JSON.stringify(initialLinuxNamespacePreparation(context)),
    );
    record = await prepareLinuxNamespaces(context, directory, persist);
    const exitCode = record.observationFailure
      ? record.observationFailure.outcome.exitCode
      : record.before?.probes.find(({ passed }) => !passed)?.exitCode;
    if (env.GITHUB_OUTPUT)
      await appendFile(
        env.GITHUB_OUTPUT,
        `operation=linux-namespace-policy\nexit_code=${record.status === "PASS" ? "0" : (exitCode ?? "")}\ncause=${record.cause ? JSON.stringify(record.cause) : ""}\n`,
      );
    process.exitCode = record.status === "PASS" ? 0 : 1;
  } else {
    record = await readLinuxNamespaceEvidence(file);
    if (stage === "verify")
      await verifyLinuxNamespaces(record, context, directory);
    else {
      let settled = false;
      try {
        const input = await readLinuxNamespaceEvidence(
          path.join(
            directory,
            kind === "minimal" ? "report.json" : "native-job.json",
          ),
          { privateFile: kind === "minimal" },
        );
        settled = linuxNamespaceSettlement(input, context, kind);
      } catch {
        /* Missing independent recovery evidence never unloads a policy. */
      }
      record = await cleanupLinuxNamespaces(record, context, settled, persist, {
        directory,
      });
      process.exitCode = linuxNamespacePolicyRetired(record, context) ? 0 : 1;
    }
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch(() => {
    process.stderr.write(
      "Linux namespace policy preparation or settlement is unavailable; inspect redacted external CI evidence.\n",
    );
    process.exitCode = 1;
  });
}
