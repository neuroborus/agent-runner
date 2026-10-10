import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  readFile,
  mkdir,
  mkdtemp,
  realpath,
  writeFile,
  symlink,
  link,
  rm,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  initializeNativeJob,
  observationDigest,
  readNativeSystemCIDelivery,
  admitNativeSystemCIDelivery,
  retainNativeSystemCIContext,
  loadNativeSystemCIContext,
  guardNativeCIAdmissions,
  acquireSystemCIInputs,
} from "../ci/native/index.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const job = initializeNativeJob(
  {
    candidateSha: "a".repeat(40),
    platform: "linux",
    repository: "example/native",
    runId: "42",
    runAttempt: 1,
  },
  { schemaVersion: 6, tier: "system" },
);
const time = 100;
const admission = {
  schemaVersion: 1,
  platform: "linux",
  root: "/synthetic/temp/native-custody",
  readRoots: ["/synthetic/temp/native-custody"],
  writeRoots: ["/synthetic/temp/native-custody/assets"],
  controllerUid: 0,
  controllerSid: null,
  nonce: "b".repeat(32),
  expires: 10000,
};
const envelope = () => ({
  schemaVersion: 1,
  candidateSha: job.candidateSha,
  platform: job.platform,
  runId: job.provenance.runId,
  runAttempt: job.provenance.runAttempt,
  expires: 20000,
  templateReviews: [
    {
      candidateSha: job.candidateSha,
      platform: "linux",
      manifestSha256: "c".repeat(64),
      authority: "operator-protected",
    },
  ],
  prerequisiteCustody: {
    output: admission.root + "/receipts",
    admission: structuredClone(admission),
    runtime: {
      node: { path: "/stock/node", bytes: 1, sha256: "d".repeat(64) },
      dependencies: [],
    },
    privilege: { uid: 0, session: "private", worker: "files-only" },
    approvals: {},
  },
});
const environment = (bytes) => ({
  CI: "true",
  GITHUB_ACTIONS: "true",
  RUNNER_TEMP: "/synthetic/temp",
  NATIVE_SYSTEM_INPUT_REPOSITORY: "example/reviews",
  NATIVE_SYSTEM_INPUT_REVISION: "e".repeat(40),
  NATIVE_SYSTEM_REVIEW_SHA256: "f".repeat(64),
  NATIVE_LINUX_REVIEW_SHA256: "c".repeat(64),
  NATIVE_SOURCE_REVIEW_SHA256: "d".repeat(64),
  NATIVE_REVIEWED_INPUT_DIRECTORY:
    "/synthetic/temp/native-linux-runtime-reviewed",
  NATIVE_LINUX_REVIEW_FILE:
    "/synthetic/temp/native-linux-provision/linux-review.json",
  NATIVE_SYSTEM_CI_INPUTS_SHA256: digest(bytes),
});
const capture = (bytes, env = environment(bytes), options = {}) =>
  readNativeSystemCIDelivery(job, env, {
    read: async (file, maximum) => {
      assert.equal(file, "/synthetic/temp/native-linux-ci-inputs.json");
      assert.ok(bytes.length <= maximum);
      return bytes;
    },
    now: () => time,
    ...options,
  });

test("closed delivery binds independent approval and run scope without releasing effects", async () => {
  const original = envelope();
  for (const damage of [
    (value) => {
      value.unknown = true;
    },
    (value) => {
      value.candidateSha = "9".repeat(40);
    },
    (value) => {
      value.platform = "darwin";
    },
    (value) => {
      value.runId = "43";
    },
    (value) => {
      value.runAttempt++;
    },
    (value) => {
      value.expires = time;
    },
    (value) => {
      value.prerequisiteCustody.admission.expires = time;
    },
    (value) => {
      value.templateReviews[0].authority = "self-approved";
    },
    (value) => {
      value.prerequisiteCustody.factory = "execute";
    },
  ]) {
    const value = structuredClone(original);
    damage(value);
    const bytes = Buffer.from(JSON.stringify(value));
    await assert.rejects(
      capture(bytes),
      /Native CI preparation failed: review/u,
    );
  }
  const bytes = Buffer.from(JSON.stringify(original));
  let reads = 0;
  await assert.rejects(
    readNativeSystemCIDelivery(
      { ...job, platform: "linux/../../private" },
      environment(bytes),
      {
        read: async () => {
          reads++;
        },
      },
    ),
  );
  assert.equal(reads, 0);
  for (const approval of [
    undefined,
    "",
    "private-path /synthetic/private",
    "0".repeat(64),
  ])
    await assert.rejects(
      capture(bytes, {
        ...environment(bytes),
        NATIVE_SYSTEM_CI_INPUTS_SHA256: approval,
      }),
    );
  assert.deepEqual((await capture(bytes)).value, original);
  await assert.rejects(
    capture(bytes, environment(bytes), {
      read: async () => {
        throw null;
      },
    }),
    /Native CI preparation failed: review/u,
  );
  await assert.rejects(
    capture(Buffer.from('{"private-path":"/synthetic/private"')),
    (error) => {
      assert.doesNotMatch(error.message, /synthetic|private-path/u);
      return true;
    },
  );
});

test("descriptor delivery reads reject missing, non-regular, linked and oversized files", async (t) => {
  const directory = await realpath(
    await mkdtemp(path.join(os.tmpdir(), "native-ci-inputs-")),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const bytes = Buffer.from(JSON.stringify(envelope())),
    env = { ...environment(bytes), RUNNER_TEMP: directory };
  const file = path.join(directory, "native-linux-ci-inputs.json"),
    target = path.join(directory, "target.json");
  await assert.rejects(
    readNativeSystemCIDelivery(
      job,
      { ...env, RUNNER_TEMP: path.join(directory, "absent") },
      { now: () => time },
    ),
  );
  await mkdir(file);
  await assert.rejects(
    readNativeSystemCIDelivery(job, env, { now: () => time }),
  );
  await rm(file, { recursive: true });
  await writeFile(target, bytes);
  await symlink(target, file);
  await assert.rejects(
    readNativeSystemCIDelivery(job, env, { now: () => time }),
  );
  await rm(file);
  await link(target, file);
  await assert.rejects(
    readNativeSystemCIDelivery(job, env, { now: () => time }),
  );
  await rm(file);
  await rm(target);
  await writeFile(file, Buffer.alloc(8 * 1024 * 1024 + 1));
  await assert.rejects(
    readNativeSystemCIDelivery(job, env, { now: () => time }),
  );
  await rm(file);
  await writeFile(file, bytes);
  assert.equal(
    (await readNativeSystemCIDelivery(job, env, { now: () => time })).sha256,
    digest(bytes),
  );
});

async function fixture() {
  const names = [
    "observation.js",
    "prerequisite-files.js",
    "prerequisite-windows.js",
    "prerequisite-worker.mjs",
    "first-failure.js",
    "prerequisite-source.js",
    "prerequisite-transport.js",
  ];
  const sources = new Map(
    await Promise.all(
      names.map(async (name) => [
        name,
        await readFile(new URL("../ci/native/" + name, import.meta.url)),
      ]),
    ),
  );
  const capabilityBytes = await readFile(
    new URL("../ci/native/native-effects.mjs", import.meta.url),
  );
  const manifest = {
    schemaVersion: 2,
    candidateSha: job.candidateSha,
    platform: job.platform,
    capabilitySha256: digest(capabilityBytes),
    source: {
      citations: names.map((name) => ({
        kind: "reached-code",
        member: "candidate/ci/native/" + name,
        sha256: digest(sources.get(name)),
      })),
    },
  };
  const value = envelope(),
    custody = value.prerequisiteCustody;
  const { nonce: _nonce, expires: _expires, ...scope } = custody.admission;
  custody.approvals = {
    sourceSha256: observationDigest(
      names.map((name) => ({
        name,
        bytes: sources.get(name).length,
        sha256: digest(sources.get(name)),
      })),
    ),
    runtimeSha256: observationDigest(custody.runtime),
    privilegeSha256: observationDigest(custody.privilege),
    scopeSha256: observationDigest({ ...scope, output: custody.output }),
    manifestSha256: observationDigest(manifest),
  };
  const bytes = Buffer.from(JSON.stringify(value)),
    env = {
      ...environment(bytes),
      NATIVE_SYSTEM_REVIEW_SHA256: observationDigest(manifest),
    };
  const captured = await capture(bytes, env),
    system = { manifest, capabilityBytes, linuxManifest: null };
  const options = {
    now: () => time,
    readCandidate: async (member) =>
      sources.get(member.slice("ci/native/".length)),
    // Metadata/source closure has its own full validator suite. This boundary
    // checks captured delivery wiring and the real custody/source validators.
    verify: async (input) => {
      assert.deepEqual(input.templateReviews, value.templateReviews);
      assert.equal(input.candidateSha, job.candidateSha);
      assert.equal(input.systemReviewSha256, env.NATIVE_SYSTEM_REVIEW_SHA256);
      return { candidateEntryBound: true };
    },
  };
  const files = new Map(),
    events = [],
    directory = "/synthetic/temp/native-system";
  const read = async (file) => {
    assert.ok(files.has(file));
    return files.get(file);
  };
  const fs = {
    realpath: async (file) => file,
    async open(file, flags, mode) {
      assert.ok(flags & constants.O_EXCL);
      assert.equal(mode, 0o400);
      assert.equal(files.has(file), false);
      events.push("receipt-open");
      return {
        writeFile: async (content) => files.set(file, Buffer.from(content)),
        sync: async () => events.push("receipt-sync"),
        close: async () => events.push("receipt-close"),
      };
    },
  };
  return { captured, system, env, options, files, events, directory, read, fs };
}

test("unapproved custody and candidate inputs prevent publication and native effects", async () => {
  for (const fault of [
    "metadata",
    "custody",
    "approval",
    "legacy",
    "controller-citation",
  ]) {
    const f = await fixture();
    let writes = 0;
    if (fault === "metadata")
      f.options.verify = async () => {
        throw new Error("Invalid candidate citation");
      };
    if (fault === "legacy") f.system.manifest.schemaVersion = 1;
    if (fault === "approval")
      f.env.NATIVE_SYSTEM_CI_INPUTS_SHA256 = "0".repeat(64);
    if (fault === "custody") {
      const value = JSON.parse(f.captured.bytes);
      value.prerequisiteCustody.approvals.scopeSha256 = "0".repeat(64);
      f.captured.bytes = Buffer.from(JSON.stringify(value));
      f.captured.sha256 = f.env.NATIVE_SYSTEM_CI_INPUTS_SHA256 = digest(
        f.captured.bytes,
      );
    }
    if (fault === "controller-citation") {
      const citation = f.system.manifest.source.citations.find(
        (entry) => entry.member === "candidate/ci/native/first-failure.js",
      );
      f.system.manifest.source.citations.push({ ...citation });
      const value = JSON.parse(f.captured.bytes);
      value.prerequisiteCustody.approvals.manifestSha256 =
        f.env.NATIVE_SYSTEM_REVIEW_SHA256 = observationDigest(
          f.system.manifest,
        );
      f.captured.bytes = Buffer.from(JSON.stringify(value));
      f.captured.sha256 = f.env.NATIVE_SYSTEM_CI_INPUTS_SHA256 = digest(
        f.captured.bytes,
      );
    }
    await assert.rejects(
      acquireSystemCIInputs(
        job,
        { verifyLegacy: () => {} },
        "/synthetic/temp/native-linux-reviewed",
        {
          env: f.env,
          fetchInput: async (url) => ({
            ok: true,
            body: [
              url.endsWith("system-inputs.json")
                ? Buffer.from(JSON.stringify(f.system.manifest))
                : url.endsWith("linux-review.json")
                  ? Buffer.from("{}")
                  : f.system.capabilityBytes,
            ],
          }),
          fs: { mkdir: async () => writes++, writeFile: async () => writes++ },
          beforePublish: (system) =>
            admitNativeSystemCIDelivery(
              job,
              f.captured,
              system,
              f.env,
              f.options,
            ),
        },
      ),
    );
    assert.equal(writes, 0);
    assert.equal(f.events.length, 0);
  }
});

test("protected context survives delivery loss and expiry while fencing every new admission", async () => {
  const f = await fixture();
  await assert.rejects(
    retainNativeSystemCIContext(
      job,
      f.directory,
      f.captured,
      f.system,
      f.env,
      f,
    ),
  );
  await admitNativeSystemCIDelivery(
    job,
    f.captured,
    f.system,
    f.env,
    f.options,
  );
  await retainNativeSystemCIContext(
    job,
    f.directory,
    f.captured,
    f.system,
    f.env,
    f,
  );
  assert.deepEqual(f.events, ["receipt-open", "receipt-sync", "receipt-close"]);
  let clock = time;
  const live = await loadNativeSystemCIContext(job, f.directory, f.env, {
    ...f,
    now: () => clock,
  });
  assert.deepEqual(live.templateReviews, f.captured.value.templateReviews);
  let admitted = 0,
    provisioned = 0,
    retired = 0;
  const effects = guardNativeCIAdmissions(
    {
      prepare: async () => ({ effects: { launchParked: () => admitted++ } }),
      provision: () => provisioned++,
      settle: () => retired++,
      recover: () => retired++,
    },
    live.assertLive,
  );
  effects.provision();
  assert.equal(provisioned, 1);
  const prepared = await effects.prepare();
  prepared.effects.launchParked();
  assert.equal(admitted, 1);
  clock = f.captured.value.expires;
  assert.throws(() => prepared.effects.launchParked());
  assert.throws(() => effects.provision());
  assert.equal(provisioned, 1);
  effects.settle();
  assert.equal(retired, 1);
  // Recovery cannot ask for the delivery again or use a replacement approval.
  const env = {
    ...f.env,
    NATIVE_SYSTEM_CI_INPUTS_SHA256: undefined,
    NATIVE_SYSTEM_REVIEW_SHA256: "0".repeat(64),
    NATIVE_SOURCE_REVIEW_SHA256: undefined,
    NATIVE_REVIEWED_INPUT_DIRECTORY: undefined,
  };
  await assert.rejects(
    loadNativeSystemCIContext(job, f.directory, env, {
      ...f,
      now: () => clock,
    }),
  );
  const progressed = { ...job, provenance: { ...job.provenance, jobId: "7" } };
  const recovery = await loadNativeSystemCIContext(
    progressed,
    f.directory,
    env,
    { ...f, recovery: true, now: () => clock },
  );
  assert.equal(
    recovery.env.NATIVE_SYSTEM_REVIEW_SHA256,
    f.env.NATIVE_SYSTEM_REVIEW_SHA256,
  );
  assert.equal(
    recovery.env.NATIVE_SOURCE_REVIEW_SHA256,
    f.env.NATIVE_SOURCE_REVIEW_SHA256,
  );
  assert.equal(
    recovery.env.NATIVE_REVIEWED_INPUT_DIRECTORY,
    f.env.NATIVE_REVIEWED_INPUT_DIRECTORY,
  );
  assert.deepEqual(recovery.prerequisiteCustody, live.prerequisiteCustody);
  assert.deepEqual(recovery.prerequisiteCustody.job, job);
  assert.throws(recovery.assertLive);
  guardNativeCIAdmissions(effects, recovery.assertLive).recover();
  assert.throws(() => effects.provision());
  assert.equal(provisioned, 1);
  assert.equal(retired, 2);
  assert.equal(admitted, 1);
  await assert.rejects(
    loadNativeSystemCIContext(
      { ...job, provenance: { ...job.provenance, runAttempt: 2 } },
      f.directory,
      env,
      { ...f, recovery: true },
    ),
  );
  await assert.rejects(
    loadNativeSystemCIContext(
      {
        ...job,
        provenance: { ...job.provenance, repository: "example/other" },
      },
      f.directory,
      env,
      { ...f, recovery: true },
    ),
  );
});
