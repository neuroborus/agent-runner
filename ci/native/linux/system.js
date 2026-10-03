import { writeFile } from "node:fs/promises";
import path from "node:path";
import {
  LINUX_NATIVE_GROUPS,
  normalizeNativeJob,
  normalizeNativeResult,
  recordNativeAdmission,
  recordNativeSettlement,
  recordNativeResults,
  recordNativeSupportingEvidence,
  hasNativeProcessEffects,
} from "../index.js";
import { LINUX_OWNERSHIP_CASES } from "./protocol.js";
import { ACCESS_PROFILES } from "./profiles.js";
import { digest, protectedReceipt } from "./inspect.js";
import {
  freshVerifier,
  runLinuxOwnershipProofs,
  buildWithReceipts,
  LINUX_FILE_PROOF_BUILD_MS,
} from "./proof.js";
import {
  LINUX_FILE_CASE_IDS,
  linuxFileCaseBound,
  runLinuxFileProofs,
} from "./files-cases.js";
import { observeLinuxRelease, verifyLinuxReleaseInputs } from "./release.js";
import { loadPreparedLinuxReviewedInputs } from "./reviewed-inputs.js";

const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;
const FILE_SESSION_COUNTS = Object.freeze([1, 1, 4, 4, 8, 3]);
const FILE_SESSIONS = FILE_SESSION_COUNTS.reduce(
  (sum, count) => sum + count,
  0,
);
// Five ownership and four access sessions each retain their 30+5+5+5 bounds.
// Setup is charged separately. Each compiler command has a 20-second execution
// and five-second settlement/verifier allowance. No production timeout changes.
export const LINUX_SYSTEM_BOUNDS = Object.freeze({
  harness: 30000,
  ownership: 120000 + LINUX_OWNERSHIP_CASES.length * 45000,
  access: ACCESS_PROFILES.length * (30000 + 45000),
  build: LINUX_FILE_PROOF_BUILD_MS,
  files: LINUX_FILE_CASE_IDS.reduce(
    (sum, id) => sum + linuxFileCaseBound(id),
    0,
  ),
  release:
    60000 +
    (LINUX_OWNERSHIP_CASES.length +
      ACCESS_PROFILES.length +
      FILE_SESSIONS +
      2) *
      5000,
});
export const LINUX_SYSTEM_PROBE_MS = Object.values(LINUX_SYSTEM_BOUNDS).reduce(
  (sum, value) => sum + value,
  0,
);
export const LINUX_SYSTEM_STEP_MINUTES =
  Math.ceil(LINUX_SYSTEM_PROBE_MS / 60000) + 1;
// Checkout 3, initialize 1, runtime 3, preparation 3, setup 3, cleanup 1,
// always-run report 1, upload 2 and independent upload binding 1 minutes.
export const LINUX_SYSTEM_JOB_MINUTES = LINUX_SYSTEM_STEP_MINUTES + 18;

function requireValue(condition) {
  if (!condition)
    throw new Error("Incomplete or mismatched Linux system evidence");
}

function summarySettlement(results) {
  const attempted = results.filter(hasNativeProcessEffects);
  return {
    status:
      attempted.length > 0 &&
      attempted.every(({ settlement }) => retired(settlement))
        ? "RETIRED"
        : "RETAINED",
    independent:
      attempted.length > 0 &&
      attempted.every(({ settlement }) => retired(settlement)),
    emergencyCleanup: attempted.some(
      ({ settlement }) => settlement.emergencyCleanup,
    ),
  };
}

export function blockedLinuxSystemResults(job, groupId) {
  return LINUX_NATIVE_GROUPS[groupId].checkIds.map((checkId) =>
    normalizeNativeResult({
      schemaVersion: 2,
      admission: "not-started",
      candidateSha: job.candidateSha,
      checkoutSha: job.checkoutSha,
      platform: job.platform,
      declaredImage: job.declaredImage,
      observed: job.observed,
      provenance: job.provenance,
      checkId,
      profile: checkId.startsWith("profile.")
        ? checkId.slice(8)
        : checkId === "git.fixed-commit"
          ? "commit"
          : groupId,
      tier: "system",
      dispatch: "native",
      implemented: true,
      versions: job.versions,
      policy: null,
      phases: Object.fromEntries(
        ["setup", "probe", "cleanup"].map((name) => [
          name,
          {
            status: "NOT_RUN",
            elapsedMs: null,
            deadlineMs: LINUX_SYSTEM_PROBE_MS,
            reason: "missing-input",
          },
        ]),
      ),
      observations: [],
      settlement: retained(),
      status: "BLOCKED",
      reason: "missing-input",
    }),
  );
}

/** Group progress is write-ahead: neither a later exception nor reporting
 * cleanup can discard earlier records or invent retirement. Injected effects
 * exercise this composition without compilation, system cases or providers. */
export async function runLinuxSystemProofs(
  input,
  directory,
  {
    persist,
    diagnostic = () => {},
    ownership = runLinuxOwnershipProofs,
    build = buildWithReceipts,
    files = runLinuxFileProofs,
    observeRelease = observeLinuxRelease,
    verifyReceipts = verifyCompletedReceipts,
    loadInputs = () =>
      loadPreparedLinuxReviewedInputs(
        env.NATIVE_REVIEWED_INPUT_DIRECTORY,
        input.candidateSha,
        env.NATIVE_LINUX_REVIEW_SHA256,
      ),
    persistRelease = (fixture, bytes) =>
      writeFile(
        path.join(fixture.directory, "evidence", "release.json"),
        bytes,
        { flag: "wx", mode: 0o400 },
      ),
    now = () => performance.now(),
    env = process.env,
    platform = process.platform,
  } = {},
) {
  let job = normalizeNativeJob(input);
  requireValue(
    platform === "linux" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      job.schemaVersion === 5 &&
      job.platform === "linux" &&
      job.stages.setup.status === "PASS" &&
      job.results.length === 0 &&
      Object.values(job.admissions).every(
        ({ admission }) => admission === "not-started",
      ) &&
      typeof persist === "function",
  );
  const save = async (value) => {
    job = normalizeNativeJob(value);
    await persist(job);
  };
  const admit = async (id) => {
    await save(recordNativeAdmission(job, id));
    diagnostic(id, "admitted");
  };
  const record = async (
    group,
    results,
    supporting = [],
    prerequisites = null,
  ) => {
    requireValue(
      results.length === LINUX_NATIVE_GROUPS[group].checkIds.length &&
        new Set(results.map(({ checkId }) => checkId)).size ===
          results.length &&
        results.every(({ checkId }) =>
          LINUX_NATIVE_GROUPS[group].checkIds.includes(checkId),
        ),
    );
    let next = supporting.length
      ? recordNativeSupportingEvidence(job, supporting)
      : job;
    next = recordNativeResults(next, results, prerequisites);
    const effect = LINUX_NATIVE_GROUPS[group].admission;
    if (next.admissions[effect].admission === "possible")
      next = recordNativeSettlement(next, effect, summarySettlement(results));
    await save(next);
    for (const result of results)
      for (const phase of ["setup", "probe", "cleanup"])
        diagnostic(
          result.checkId,
          `${phase}-${result.phases[phase].status.toLowerCase()}`,
        );
    diagnostic(
      group,
      results.every(({ status }) => status === "PASS")
        ? "passed"
        : "blocked-or-failed",
    );
  };
  const bounded = async (group, work, maximum = LINUX_SYSTEM_BOUNDS[group]) => {
    try {
      const start = now(),
        value = await work(),
        elapsed = now() - start;
      requireValue(
        Number.isFinite(elapsed) && elapsed >= 0 && elapsed <= maximum,
      );
      return value;
    } catch (error) {
      diagnostic(group, "failed");
      throw error;
    }
  };
  await admit("ownership");
  const owned = await bounded(
    "ownership",
    () =>
      ownership(job, directory, {
        onOwnership: async (results, fixture, prerequisites) => {
          if (prerequisites) {
            await save(recordNativeResults(job, results, prerequisites));
            return;
          }
          await record("ownership", results);
        },
        beforeAccess: () => admit("access"),
        onAccess: (results) => record("access", results),
      }),
    LINUX_SYSTEM_BOUNDS.ownership + LINUX_SYSTEM_BOUNDS.access,
  );
  if (owned.linuxPrerequisites) return job;
  requireValue(job.results.length === 16);
  const fixture = owned.fixture;
  if (!fixture || job.results.some(({ status }) => status !== "PASS")) {
    await record("files", blockedLinuxSystemResults(job, "files"));
    await record("release", blockedLinuxSystemResults(job, "release"));
    return job;
  }
  const reviewedStarted = now(),
    reviewed = await loadInputs();
  const setupElapsed = now() - reviewedStarted;
  requireValue(
    Number.isFinite(setupElapsed) && setupElapsed >= 0 && setupElapsed <= 60000,
  );
  if (!reviewed.build) {
    await record("files", blockedLinuxSystemResults(job, "files"));
    await record("release", blockedLinuxSystemResults(job, "release"));
    return job;
  }
  await admit("file-build");
  const built = await bounded("build", () =>
    build(job, directory, fixture, reviewed.build),
  );
  requireValue(
    built.build.candidateSha === job.candidateSha && retired(built.settlement),
  );
  await save(recordNativeSettlement(job, "file-build", built.settlement));
  const { executable, ...buildRecord } = built.build;
  await save(
    recordNativeSupportingEvidence(
      job,
      LINUX_FILE_CASE_IDS.map((checkId) => ({
        checkId,
        kind: "build",
        id: "helper-build",
        sha256: digest(JSON.stringify(buildRecord) + "\n"),
      })),
    ),
  );
  await admit("file-helper");
  const proved = await bounded("files", () => files(job, fixture, built.build));
  const records = proved.map(({ result }) => result);
  const supporting = proved
    .filter(({ result }) => result.admission === "possible")
    .flatMap(({ result, sessions }) => {
      requireValue(
        sessions.length <= 8 &&
          sessions.every(
            (session) => session.candidateSha === job.candidateSha,
          ),
      );
      if (result.status === "PASS")
        requireValue(
          sessions.length ===
            FILE_SESSION_COUNTS[LINUX_FILE_CASE_IDS.indexOf(result.checkId)] &&
            sessions.every(
              (session) =>
                /^[a-f0-9]{64}$/u.test(session.receiptDigest) &&
                retired(session.settlement),
            ),
        );
      return sessions.length === 0
        ? []
        : [
            {
              checkId: result.checkId,
              kind: "receipt",
              id: `session-bundle-${result.checkId.slice(6)}`,
              sha256: digest(JSON.stringify(sessions)),
            },
          ];
    });
  await record("files", records, supporting);
  if (records.some(({ status }) => status !== "PASS") || !reviewed.release) {
    await record("release", blockedLinuxSystemResults(job, "release"));
    return job;
  }
  await admit("release-probe");
  const start = now();
  const audit = await bounded(
    "release",
    async () => {
      const observed = await observeRelease(
        job,
        fixture,
        built.build,
        reviewed.build,
      );
      const evidence = verifyLinuxReleaseInputs(reviewed.release, observed);
      const probeFinished = now();
      const receiptBindings = [
        ...(owned.receipts ?? []),
        ...(built.receipts ?? []),
        ...proved.flatMap(({ sessions }) =>
          sessions.map(({ nonce, receiptDigest }) => ({
            file: path.join(
              fixture.directory,
              "evidence",
              `file-helper-${nonce}.json`,
            ),
            sha256: receiptDigest,
          })),
        ),
      ];
      const settlement = await verifyReceipts(
        job,
        directory,
        fixture,
        receiptBindings,
      );
      requireValue(retired(settlement));
      const policy = {
        id: LINUX_NATIVE_GROUPS.release.policyId,
        sha256: digest(
          JSON.stringify({
            reviewed: evidence.reviewed,
            policies: observed.effectivePolicies,
            helperAbi: observed.helperAbi,
          }),
        ),
      };
      const bytes = JSON.stringify(evidence) + "\n";
      requireValue(Buffer.byteLength(bytes) <= 1048576);
      await persistRelease(fixture, bytes);
      const cleanupFinished = now();
      requireValue(probeFinished >= start && cleanupFinished >= probeFinished);
      return {
        observed,
        evidence,
        settlement,
        policy,
        sha256: digest(bytes),
        elapsed: {
          setup: Math.ceil(setupElapsed),
          probe: Math.ceil(probeFinished - start),
          cleanup: Math.ceil(cleanupFinished - probeFinished),
        },
      };
    },
    LINUX_SYSTEM_BOUNDS.release - setupElapsed,
  );
  const result = normalizeNativeResult({
    ...blockedLinuxSystemResults(job, "release")[0],
    admission: "possible",
    policy: audit.policy,
    versions: audit.observed.components.filter(({ name }) =>
      ["node", "bubblewrap", "git", "compiler", "file-helper"].includes(name),
    ),
    phases: Object.fromEntries(
      ["setup", "probe", "cleanup"].map((name) => [
        name,
        {
          status: "PASS",
          elapsedMs: audit.elapsed[name],
          deadlineMs: LINUX_SYSTEM_BOUNDS.release,
          reason: null,
        },
      ]),
    ),
    observations: [
      {
        expected:
          "Reviewed publication, source, build and license bindings for all used components",
        observed:
          "Exact component versions and digests, copied build inputs, ABI, privileges and effective policies matched; source assumptions remain open",
        matched: true,
        positiveControl: true,
        attempted: true,
        sentinelsUnchanged: true,
      },
    ],
    settlement: audit.settlement,
    status: "PASS",
    reason: null,
  });
  await record(
    "release",
    [result],
    [
      {
        checkId: "audit.release",
        kind: "release",
        id: "reviewed-release",
        sha256: audit.sha256,
      },
    ],
  );
  return job;
}

async function verifyCompletedReceipts(job, directory, fixture, bindings) {
  requireValue(
    bindings.length ===
      LINUX_OWNERSHIP_CASES.length + ACCESS_PROFILES.length + FILE_SESSIONS + 2,
  );
  requireValue(
    new Set(bindings.map(({ file }) => file)).size === bindings.length,
  );
  for (const { file, sha256 } of bindings) {
    const directoryName = path.dirname(file),
      name = path.basename(file);
    requireValue(
      file === path.resolve(file) &&
        ((directoryName === path.join(directory, "build") &&
          /^command-[01]\.json$/u.test(name)) ||
          (directoryName === path.join(fixture.directory, "evidence") &&
            ([...LINUX_OWNERSHIP_CASES, ...ACCESS_PROFILES].some(
              (id) => name === `${id}.json`,
            ) ||
              /^file-helper-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\.json$/u.test(
                name,
              )))),
    );
    const receipt = await protectedReceipt(file, sha256);
    requireValue(
      receipt.candidateSha === job.candidateSha &&
        (directoryName === path.join(directory, "build")
          ? receipt.caseId === "argv"
          : name.startsWith("file-helper-")
            ? receipt.caseId === "file-helper" &&
              name === `file-helper-${receipt.nonce}.json`
            : name === `${receipt.caseId}.json`) &&
        retired(await freshVerifier(file, sha256)),
    );
  }
  return { status: "RETIRED", independent: true, emergencyCleanup: false };
}
