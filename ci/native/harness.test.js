import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  aggregateNativeEvidence,
  CHECK_IDS,
  initializeNativeJob,
  joinNativeArtifacts,
  nativeArtifactName,
  normalizeNativeResult,
  PLATFORMS,
  PROVIDER_CHECK_IDS,
  recordNativeStage,
  recordNativeResults,
  renderNativeJob,
  renderNativeReport,
  renderPublicInputReport,
  PUBLIC_INPUT_REQUIREMENTS,
  resolveNativeDispatch,
  selectNativeArtifacts,
  SOURCE_FINDING_IDS,
  verifyPreparedPublicInputs,
} from "./index.js";
import {
  assessLinuxRetirement,
  createLinuxProtocolQueue,
  normalizeLinuxReceipt,
  runLinuxOwnershipCase,
  accessGrants,
  DENIAL_IDS,
  validateAccessObservation,
  recordAccessSetupFailure,
  validateCommitRequest,
  validateCommitEffect,
  validateCommitMetadata,
} from "./linux/index.js";

const CANDIDATE = "a".repeat(40);
const DIGEST = "b".repeat(64);
const passedPhase = () => ({
  status: "PASS",
  elapsedMs: 1,
  deadlineMs: 100,
  reason: null,
});

function publicFixture() {
  const source = Buffer.from("pub fn main() {}\n");
  const binary = Buffer.from("::warning::token=fixture-secret");
  const file = (path, kind, bytes) => ({
    path,
    kind,
    url: `https://example.org/source/${CANDIDATE}/${path}`,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    gitBlobSha1:
      kind === "source"
        ? createHash("sha1")
            .update(`blob ${bytes.length}\0`)
            .update(bytes)
            .digest("hex")
        : null,
    archiveSha256: null,
  });
  return {
    candidateSha: CANDIDATE,
    reviewed: [
      {
        id: "fixture",
        version: "1.2.3",
        revision: CANDIDATE,
        findings: ["A-RELEASE-CLOSURE"],
        urls: ["https://example.org/releases/1.2.3"],
        priorArchive: null,
        files: [
          file("src/main.rs", "source", source),
          file("helper.bin", "binary", binary),
        ],
        license: "Synthetic fixture license; no candidate installation.",
        buildInputs: ["Synthetic source and helper; build provenance absent."],
        abi: ["Synthetic ABI is unproved."],
        setupPrivileges: [],
        missing: ["Independent release/build provenance."],
      },
    ],
    bytes: new Map([
      ["fixture/src/main.rs", source],
      ["fixture/helper.bin", binary],
    ]),
  };
}

test("prepared public inputs reject altered bytes, mismatched blob identities and missing members independently", () => {
  for (const mutate of [
    (input) =>
      input.bytes.set("fixture/src/main.rs", Buffer.from("altered source")),
    (input) => {
      input.reviewed[0].files[0].bytes++;
    },
    (input) => {
      input.reviewed[0].files[0].gitBlobSha1 = "0".repeat(40);
    },
  ]) {
    const input = publicFixture();
    mutate(input);
    const result = verifyPreparedPublicInputs(input);
    const file = result.bundles[0].files.find(
      (entry) => entry.path === "src/main.rs",
    );
    assert.equal(result.status, "FAIL");
    assert.equal(file.reason, "ALTERED");
    assert.equal(
      result.source.inspected.some(
        (entry) => entry.id === "fixture/src/main.rs",
      ),
      false,
    );
    assert.equal(
      result.bundles[0].files.find((entry) => entry.path === "helper.bin")
        .status,
      "PASS",
    );
  }
  const input = publicFixture();
  input.bytes.delete("fixture/src/main.rs");
  const result = verifyPreparedPublicInputs(input);
  assert.equal(result.bundles[0].byteStatus, "BLOCKED");
  assert.equal(
    result.bundles[0].files.find((entry) => entry.path === "src/main.rs")
      .reason,
    "MISSING",
  );
});

test("public provenance rejects self-asserted bindings, moving revisions, duplicate members and unresolved digests", () => {
  for (const mutate of [
    (input) => {
      input.reviewed[0].binding = "VERIFIED";
    },
    (input) => {
      input.reviewed[0].files[0].url =
        "https://example.org/source/main/src/main.rs";
    },
    (input) => {
      input.reviewed[0].files[0].kind = "manifest";
      input.reviewed[0].files[0].url =
        "https://example.org/source/main/src/main.rs";
    },
    (input) => {
      input.reviewed[0].files[0].path = "../outside.rs";
    },
    (input) => input.reviewed[0].files.push({ ...input.reviewed[0].files[0] }),
    (input) => input.bytes.set("fixture/unreviewed", Buffer.from("extra")),
  ]) {
    const input = publicFixture();
    mutate(input);
    assert.throws(() => verifyPreparedPublicInputs(input), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
  for (const mutate of [
    (input) => {
      input.reviewed[0].files[0].sha256 = null;
    },
    (input) => {
      input.reviewed[0].revision = null;
    },
    (input) => {
      input.reviewed[0].files[0].kind = "manifest";
      input.reviewed[0].revision = null;
    },
    (input) => {
      input.reviewed[0].files[0].url = null;
    },
  ]) {
    const input = publicFixture();
    mutate(input);
    const result = verifyPreparedPublicInputs(input);
    assert.equal(
      result.bundles[0].files.find((entry) => entry.path === "src/main.rs")
        .reason,
      "PROVENANCE",
    );
    assert.equal(
      result.source.inspected.some(
        (entry) => entry.id === "fixture/src/main.rs",
      ),
      false,
    );
  }
  const reviewed = structuredClone(PUBLIC_INPUT_REQUIREMENTS);
  reviewed.find(
    (bundle) => bundle.id === "srt-release",
  ).files[0].archiveSha256 = "0".repeat(64);
  assert.throws(
    () =>
      verifyPreparedPublicInputs({
        candidateSha: CANDIDATE,
        bytes: new Map(),
        reviewed,
      }),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
});

test("matching source and helper bytes cannot close release findings, authorize installation or expose candidate contents", () => {
  const input = publicFixture();
  input.reviewed[0].missing = [];
  const rendered = renderPublicInputReport(input);
  const bundle = rendered.report.publicInputs.bundles[0];
  assert.equal(bundle.byteStatus, "PASS");
  assert.equal(bundle.binding, "UNPROVED");
  assert.equal(bundle.admission, "BLOCKED");
  assert.equal(bundle.installation, "NOT_AUTHORIZED");
  assert.equal(rendered.report.decision, "BLOCKED");
  assert.ok(
    rendered.report.source.findings.every(
      (entry) => entry.status === "BLOCKED",
    ),
  );
  assert.ok(
    rendered.report.source.inspected.every(
      (entry) => !entry.complete && entry.binding === "UNPROVED",
    ),
  );
  assert.ok(rendered.report.source.missingInputs.length > 0);
  assert.equal(JSON.stringify(rendered).includes("fixture-secret"), false);
  input.bytes = new Map([...input.bytes].reverse());
  input.reviewed[0].files.reverse();
  assert.deepEqual(renderPublicInputReport(input), rendered);

  const incomplete = { ...structuredClone(input.reviewed[0]), id: "absent" };
  input.reviewed.push(incomplete);
  const independent = verifyPreparedPublicInputs(input);
  assert.equal(
    independent.bundles.find((entry) => entry.id === "fixture").byteStatus,
    "PASS",
  );
  assert.equal(
    independent.bundles.find((entry) => entry.id === "absent").byteStatus,
    "BLOCKED",
  );

  const retained = verifyPreparedPublicInputs({
    candidateSha: CANDIDATE,
    bytes: new Map(),
  });
  const release = retained.bundles.find((entry) => entry.id === "srt-release");
  assert.deepEqual(
    release.priorArchive,
    PUBLIC_INPUT_REQUIREMENTS.find((entry) => entry.id === "srt-release")
      .priorArchive,
  );
  assert.equal(release.byteStatus, "BLOCKED");
  assert.equal(
    retained.source.inspected.find(
      (entry) => entry.id === "srt-release/prior-archive",
    ).complete,
    false,
  );
});

test("Linux fixture profiles separate ordinary edits from fixed executor metadata authority", () => {
  const storage = {
    workspace: "/owned/disposable",
    metadata: "/protected/metadata",
    pointer: "/protected/pointer",
    git: "/protected/git",
    operation: "/protected/operation",
    hooks: "/protected/hooks",
    protocol: "/protected/protocol",
  };
  for (const profile of [
    "read-only",
    "workspace-write",
    "trusted-command",
    "commit",
  ]) {
    const grants = accessGrants(profile, storage);
    assert.deepEqual(
      grants.filter((grant) => grant.writable).map((grant) => grant.target),
      profile === "read-only"
        ? []
        : profile === "commit"
          ? ["/metadata"]
          : ["/workspace"],
    );
    assert.ok(
      grants
        .filter(
          (grant) =>
            grant.target !== "/workspace" && grant.target !== "/metadata",
        )
        .every((grant) => !grant.writable),
    );
  }
  assert.throws(() => accessGrants("unknown", storage), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  const subject = "test(fixture): record owned edit";
  assert.deepEqual(validateCommitRequest({ operation: "commit", subject }), {
    operation: "commit",
    subject,
  });
  for (const request of [
    { operation: "add", subject },
    { operation: "commit", subject: `${subject}\n\nBody` },
    {
      operation: "commit",
      subject: `${subject}\nCo-authored-by: Fixture <fixture@example.invalid>`,
    },
    { operation: "commit", subject, args: [] },
  ])
    assert.throws(() => validateCommitRequest(request), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
});

test("Linux access denials require complete attempts, ready controls, isolated loopback and unchanged sentinels", () => {
  const value = {
    type: "access-result",
    profile: "workspace-write",
    inspection: true,
    edit: "permitted",
    loopback: true,
    denials: DENIAL_IDS.map((id) => ({
      id,
      code: ["git-add", "git-commit"].includes(id) ? "EXIT_128" : "EACCES",
      attempted: true,
      denied: true,
      positiveControl: true,
    })),
  };
  assert.equal(
    validateAccessObservation("workspace-write", value, true).length,
    DENIAL_IDS.length,
  );
  for (const mutate of [
    (entry) => {
      entry.denials.pop();
    },
    (entry) => {
      entry.denials[1] = { ...entry.denials[0] };
    },
    (entry) => {
      entry.denials[0].attempted = false;
    },
    (entry) => {
      entry.denials[0].denied = false;
    },
    (entry) => {
      entry.denials[0].positiveControl = false;
    },
    (entry) => {
      entry.denials[0].code = "EXIT_0";
    },
    (entry) => {
      entry.denials[0].code = "ETIMEDOUT";
    },
    (entry) => {
      entry.denials[0].code = "ENOENT";
    },
    (entry) => {
      entry.loopback = false;
    },
    (entry) => {
      entry.edit = "denied";
    },
  ]) {
    const input = structuredClone(value);
    mutate(input);
    assert.throws(
      () => validateAccessObservation("workspace-write", input, true),
      { code: "ERR_INVALID_NATIVE_EVIDENCE" },
    );
  }
  assert.throws(
    () => validateAccessObservation("workspace-write", value, false),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  const readOnly = {
    ...value,
    profile: "read-only",
    edit: "denied",
    denials: [
      ...value.denials,
      {
        id: "content-write",
        code: "EROFS",
        attempted: true,
        denied: true,
        positiveControl: true,
      },
    ],
  };
  assert.equal(
    validateAccessObservation("read-only", readOnly, true).length,
    DENIAL_IDS.length + 1,
  );
});

test("Linux fixture setup failures remain failed without probe or retirement evidence", () => {
  const result = completeEvidence().results.find(
    (entry) =>
      entry.platform === "linux" && entry.checkId === "profile.read-only",
  );
  for (const [elapsed, reason] of [
    [1, "setup-failed"],
    [30001, "deadline"],
  ]) {
    const failed = recordAccessSetupFailure(result, elapsed);
    assert.equal(failed.status, "FAIL");
    assert.equal(failed.reason, reason);
    assert.equal(failed.phases.setup.status, "FAIL");
    assert.equal(failed.phases.probe.status, "NOT_RUN");
    assert.equal(failed.phases.cleanup.status, "NOT_RUN");
    assert.deepEqual(failed.observations, []);
    assert.equal(failed.settlement.status, "RETAINED");
    assert.equal(failed.settlement.independent, false);
  }
});

test("Linux fixed commit rejects extra refs, message authority, changed configuration or identity", () => {
  const before = {
    branch: "refs/heads/proof",
    head: CANDIDATE,
    identity: "Fixture Author <fixture@example.invalid>",
    config: "synthetic unchanged configuration",
    refs: [
      ["refs/heads/proof", CANDIDATE],
      ["refs/tags/witness", CANDIDATE],
    ],
  };
  const after = {
    ...before,
    head: "c".repeat(40),
    parent: before.head,
    message: "test(fixture): record owned edit\n",
    changed: "content.txt\n",
    content: "owned edit\n",
    status: "",
    author: before.identity,
    committer: before.identity,
    refs: [
      ["refs/heads/proof", "c".repeat(40)],
      ["refs/tags/witness", CANDIDATE],
    ],
  };
  assert.equal(validateCommitEffect(before, after), true);
  for (const mutate of [
    (entry) => {
      entry.refs[1][1] = entry.head;
    },
    (entry) => {
      entry.refs.push(["refs/heads/extra", entry.head]);
    },
    (entry) => {
      entry.message += "\nBody\n";
    },
    (entry) => {
      entry.changed += "extra.txt\n";
    },
    (entry) => {
      entry.config += "changed";
    },
    (entry) => {
      entry.author = "Other <other@example.invalid>";
    },
    (entry) => {
      entry.committer = "Other <other@example.invalid>";
    },
    (entry) => {
      entry.parent = entry.head;
    },
  ]) {
    const input = structuredClone(after);
    mutate(input);
    assert.throws(() => validateCommitEffect(before, input), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
  const metadata = [
    ["config", DIGEST, 0o644],
    ["objects/aa/initial", DIGEST, 0o444],
  ];
  const commitMetadata = [
    ...metadata,
    ["index", DIGEST, 0o644],
    ["objects/cc/" + "c".repeat(38), DIGEST, 0o444],
  ];
  const objects = [after.head, CANDIDATE, "d".repeat(40)];
  assert.equal(validateCommitMetadata(metadata, commitMetadata, objects), true);
  for (const extra of [
    ["objects/info/alternates", DIGEST, 0o644],
    ["hooks/extra", DIGEST, 0o500],
  ])
    assert.throws(
      () =>
        validateCommitMetadata(metadata, [...commitMetadata, extra], objects),
      { code: "ERR_INVALID_NATIVE_EVIDENCE" },
    );
  const replaced = structuredClone(commitMetadata);
  replaced[1][1] = "changed";
  assert.throws(() => validateCommitMetadata(metadata, replaced, objects), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
});

function linuxReceipt() {
  const identity = {
    bootId: "11111111-1111-4111-8111-111111111111",
    startTicks: "44",
  };
  return {
    schemaVersion: 1,
    candidateSha: CANDIDATE,
    caseId: "cancel",
    nonce: "22222222-2222-4222-8222-222222222222",
    policyDigest: DIGEST,
    executableDigest: DIGEST,
    isolatedNamespace: true,
    hostSession: false,
    parentNamespaceId: "pid:[100]",
    init: {
      pid: 23,
      identity: { ...identity },
      namespaceId: "pid:[101]",
      nspid: [23, 1],
    },
    launcher: { pid: 22, identity: { ...identity, startTicks: "43" } },
    controller: { pid: 21, identity: { ...identity, startTicks: "42" } },
    admission: {
      processIdentity: { ...identity },
      namespaceId: "pid:[101]",
      launchCutoff: { ...identity },
      ancestryBaseline: [{ ...identity, startTicks: "42", pid: 21 }],
      controlGroup: DIGEST,
    },
  };
}

test("Linux ownership release and faults follow protected admission and acknowledged readiness", async () => {
  const receipt = linuxReceipt();
  const log = [];
  const effect = (name, result) => async () => {
    log.push(name);
    return result;
  };
  const observation = {
    expected: "synthetic owned descendant",
    observed: "synthetic matched identity",
    matched: true,
    positiveControl: true,
    attempted: true,
    sentinelsUnchanged: true,
  };
  const effects = {
    now: () => log.length,
    admit: effect("persist", receipt),
    confirmReceipt: effect("inspect"),
    acknowledgeAdmission: effect("ack"),
    ready: effect("ready"),
    release: effect("release"),
    observe: effect("observe", [observation]),
    armFault: effect("arm-ack", {
      caseId: "cancel",
      nonce: receipt.nonce,
      armed: true,
    }),
    fireFault: effect("fault"),
    settle: effect("settle"),
    verify: effect("fresh-verify", {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    }),
    cleanup: effect("cleanup"),
    emergencyStop: effect("emergency"),
  };
  const result = await runLinuxOwnershipCase("cancel", effects);
  assert.equal(result.status, "PASS");
  assert.deepEqual(log, [
    "persist",
    "inspect",
    "ack",
    "ready",
    "release",
    "observe",
    "arm-ack",
    "fault",
    "settle",
    "fresh-verify",
    "cleanup",
  ]);
  for (const boundary of ["confirmReceipt", "acknowledgeAdmission", "ready"]) {
    log.length = 0;
    const failed = await runLinuxOwnershipCase("cancel", {
      ...effects,
      [boundary]: async () => {
        throw new Error("Synthetic admission failure");
      },
    });
    assert.equal(failed.status, "FAIL");
    assert.equal(failed.phases.setup.status, "FAIL");
    assert.ok(!log.includes("release") && !log.includes("fault"));
    assert.equal(failed.settlement.emergencyCleanup, true);
  }
  for (const acknowledgement of [
    { caseId: "cancel", nonce: receipt.nonce, armed: false },
    { caseId: "owner-loss", nonce: receipt.nonce, armed: true },
    { caseId: "cancel", nonce: "substitution", armed: true },
  ]) {
    log.length = 0;
    const failed = await runLinuxOwnershipCase("cancel", {
      ...effects,
      armFault: effect("bad-ack", acknowledgement),
    });
    assert.equal(failed.status, "FAIL");
    assert.ok(!log.includes("fault"));
    assert.equal(failed.settlement.emergencyCleanup, true);
  }
  for (const status of ["RETAINED", "RETIRED"]) {
    log.length = 0;
    const retained = await runLinuxOwnershipCase("cancel", {
      ...effects,
      verify: effect("fresh-verify", {
        status,
        independent: false,
        emergencyCleanup: false,
      }),
    });
    assert.equal(retained.status, "FAIL");
    assert.equal(retained.reason, "unretired");
    assert.ok(!log.includes("cleanup"));
  }
  const cleanupFailed = await runLinuxOwnershipCase("cancel", {
    ...effects,
    fireFault: async () => {
      throw new Error("Synthetic fault failure");
    },
    cleanup: async () => {
      throw new Error("Synthetic cleanup failure");
    },
  });
  assert.equal(cleanupFailed.status, "FAIL");
  assert.equal(cleanupFailed.phases.probe.reason, "probe-failed");
  assert.equal(cleanupFailed.phases.cleanup.status, "FAIL");
  assert.equal(cleanupFailed.phases.cleanup.reason, "cleanup-failed");
  assert.equal(cleanupFailed.settlement.status, "RETIRED");
  assert.equal(cleanupFailed.settlement.emergencyCleanup, true);
  log.length = 0;
  let now = 0;
  const expired = await runLinuxOwnershipCase("cancel", {
    ...effects,
    now: () => now,
    ready: async () => {
      log.push("ready");
      now = 10000;
    },
    observe: async () => {
      log.push("observe");
      now = 31000;
      return [observation];
    },
  });
  assert.equal(expired.status, "FAIL");
  assert.equal(expired.phases.probe.reason, "deadline");
  assert.ok(!log.includes("fault"));
  assert.equal(expired.settlement.emergencyCleanup, true);
});

test("Linux protocol keeps acknowledgements selective and failures terminal", async () => {
  let now = 0;
  const timers = new Map();
  const clock = {
    now: () => now,
    setTimer: (callback) => {
      timers.set(callback, callback);
      return callback;
    },
    clearTimer: (timer) => timers.delete(timer),
  };
  const queue = createLinuxProtocolQueue(100, clock);
  const command = queue.take((message) => message.type !== "admission-ack");
  queue.push({ type: "admission-ack" });
  assert.deepEqual(
    await queue.take((message) => message.type === "admission-ack"),
    { type: "admission-ack" },
  );
  queue.push({ type: "release" });
  assert.deepEqual(await command, { type: "release" });
  assert.equal(timers.size, 0);
  queue.push({ type: "ready" });
  const failure = new Error("Synthetic lost controller");
  queue.fail(failure);
  queue.push({ type: "admission-ack" });
  await assert.rejects(
    queue.take(() => true),
    failure,
  );
  const expired = createLinuxProtocolQueue(100, clock);
  const waiting = assert.rejects(
    expired.take(() => true),
    /CI protocol deadline/u,
  );
  now = 100;
  expired.push({ type: "ready" });
  await waiting;
  await assert.rejects(
    expired.take(() => true),
    /CI protocol deadline/u,
  );
  assert.equal(timers.size, 0);
});

test("Linux recovery requires complete namespace-init evidence and explicit procfs absence", () => {
  const receipt = linuxReceipt();
  const observed = {
    bootId: receipt.init.identity.bootId,
    observerNamespaceId: receipt.parentNamespaceId,
    procVisible: true,
    before: "absent",
    after: "absent",
  };
  assert.equal(assessLinuxRetirement(receipt, observed).status, "RETIRED");
  for (const change of [
    { bootId: "33333333-3333-4333-8333-333333333333" },
    { observerNamespaceId: "pid:[102]" },
    { procVisible: false },
    ...["live", "replaced", "mismatched", "inaccessible", null].flatMap(
      (state) => [{ before: state }, { after: state }],
    ),
  ])
    assert.equal(
      assessLinuxRetirement(receipt, { ...observed, ...change }).status,
      "RETAINED",
    );
  for (const mutate of [
    (value) => {
      value.hostSession = true;
    },
    (value) => {
      value.isolatedNamespace = false;
    },
    (value) => {
      value.init.nspid = [23, 2];
    },
    (value) => {
      value.init.namespaceId = value.parentNamespaceId;
    },
    (value) => {
      value.admission.processIdentity.startTicks = "45";
    },
    (value) => {
      value.admission.ancestryBaseline = [];
    },
    (value) => {
      value.admission.ancestryBaseline.push({
        ...value.admission.ancestryBaseline[0],
      });
    },
    (value) => {
      delete value.admission.controlGroup;
    },
    (value) => {
      value.admission.ancestryBaseline[0].startTicks = "45";
    },
  ]) {
    const value = structuredClone(receipt);
    mutate(value);
    assert.throws(() => normalizeLinuxReceipt(value), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
});

// Synthetic controller inputs only. A GO here tests the evidence predicate;
// it is never a native observation or an attestation of the real candidate.
function completeEvidence() {
  const source = {
    candidateSha: CANDIDATE,
    inspected: SOURCE_FINDING_IDS.map((id) => ({
      id,
      kind: "implementation",
      url: "https://example.org/source.js",
      revision: CANDIDATE,
      sha256: DIGEST,
      binding: "VERIFIED",
      complete: true,
      summary: "Synthetic reviewed implementation binding.",
    })),
    hypotheses: [],
    missingInputs: [],
    findings: SOURCE_FINDING_IDS.map((id) => ({
      id,
      status: "CLOSED",
      sourceIds: [id],
    })),
  };
  const results = [];
  const bindings = [];
  for (const [index, platform] of PLATFORMS.entries()) {
    for (const [offset, tier] of ["system", "provider"].entries()) {
      const provenance = {
        repository: "example/native-proof",
        workflow: "native-poc.yml",
        runId: "101",
        runAttempt: 1,
        jobId: String(1 + 2 * index + offset),
      };
      bindings.push({
        artifactId: String(101 + 2 * index + offset),
        candidateSha: CANDIDATE,
        platform: platform.os,
        tier,
        provenance: { ...provenance },
        conclusion: "success",
        authority: tier === "provider" ? "operator-protected" : "ordinary",
      });
      for (const checkId of CHECK_IDS.filter(
        (id) => PROVIDER_CHECK_IDS.includes(id) === (tier === "provider"),
      )) {
        const profile = checkId.startsWith("profile.")
          ? checkId.slice(8)
          : checkId === "git.fixed-commit"
            ? "commit"
            : "fixture";
        results.push({
          schemaVersion: 1,
          candidateSha: CANDIDATE,
          checkoutSha: CANDIDATE,
          platform: platform.os,
          declaredImage: platform.image,
          observed: {
            os: platform.os,
            image: platform.image,
            build: "synthetic-build",
            architecture: platform.architecture,
          },
          provenance: { ...provenance },
          checkId,
          profile,
          tier,
          dispatch: tier === "provider" ? "protected" : "native",
          implemented: true,
          versions: [{ name: "fixture", version: "1.0.0", sha256: DIGEST }],
          policy: { id: "fixture", sha256: DIGEST },
          phases: {
            setup: passedPhase(),
            probe: passedPhase(),
            cleanup: passedPhase(),
          },
          observations: [
            {
              expected: "permitted positive control and denied attempt",
              observed: "synthetic matching observation",
              matched: true,
              positiveControl: true,
              attempted: true,
              sentinelsUnchanged: true,
            },
          ],
          settlement: {
            status: "RETIRED",
            independent: true,
            emergencyCleanup: false,
          },
          status: "PASS",
          reason: null,
        });
      }
    }
  }
  return { candidateSha: CANDIDATE, source, results, bindings };
}

test("synthetic complete same-revision evidence passes the predicate independent of input order", () => {
  const input = completeEvidence();
  const before = structuredClone(input);
  const expected = aggregateNativeEvidence(input);
  assert.equal(expected.decision, "GO");
  assert.deepEqual(input, before);
  input.results.reverse();
  input.bindings.reverse();
  input.source.inspected.reverse();
  input.source.findings.reverse();
  assert.deepEqual(aggregateNativeEvidence(input), expected);
});

test("reporting alone cannot pass missing native or source evidence", () => {
  const input = completeEvidence();
  input.results = [];
  input.bindings = [];
  input.source.inspected = [];
  input.source.findings = [];
  const { report, summary, annotations } = renderNativeReport(input);
  assert.equal(report.decision, "BLOCKED");
  assert.equal(
    report.issues.filter(({ code }) => code === "MISSING").length,
    PLATFORMS.length * CHECK_IDS.length,
  );
  assert.equal(
    report.issues.filter(({ code }) => code === "SOURCE").length,
    SOURCE_FINDING_IDS.length,
  );
  assert.ok(summary.length < 8192);
  assert.equal(annotations.length, 32);
  assert.match(summary, /additional findings remain/u);
});

test("strict result validation rejects incomplete, inconsistent, and unretired PASS records", () => {
  for (const repair of [
    (r) => {
      delete r.phases.cleanup;
    },
    (r) => {
      r.rawOutput = "token=private-value";
    },
    (r) => {
      r.checkId = "unrecognized.check";
    },
    (r) => {
      r.versions.push({ ...r.versions[0] });
    },
    (r) => {
      r.observations = [];
    },
    (r) => {
      r.observations = Array(1);
    },
    (r) => {
      r.phases.probe.elapsedMs = 101;
    },
    (r) => {
      r.phases.setup.status = "FAIL";
      r.phases.setup.reason = "setup-failed";
    },
    (r) => {
      r.settlement.status = "RETAINED";
    },
    (r) => {
      r.settlement.independent = false;
    },
    (r) => {
      r.settlement.emergencyCleanup = true;
    },
    (r) => {
      r.observations[0].positiveControl = false;
    },
    (r) => {
      r.observations[0].attempted = false;
    },
    (r) => {
      r.observations[0].sentinelsUnchanged = false;
    },
    (r) => {
      r.implemented = false;
    },
    (r) => {
      r.phases.cleanup.elapsedMs = null;
    },
    (r) => {
      r.checkoutSha = "c".repeat(40);
    },
    (r) => {
      r.provenance.jobId = null;
    },
    (r) => {
      r.observed.build = "/private/fixture";
    },
    (r) => {
      r.versions[0].version = "x".repeat(513);
    },
  ]) {
    const input = completeEvidence();
    repair(input.results[0]);
    assert.throws(() => normalizeNativeResult(input.results[0]), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
    const report = aggregateNativeEvidence(input);
    assert.equal(report.decision, "BLOCKED");
    assert.ok(report.issues.some(({ code }) => code === "INVALID"));
  }
});

test("duplicate, absent, unknown-platform, wrong-image, and mixed-revision evidence cannot yield GO", () => {
  for (const alter of [
    (i) => {
      i.results.push(structuredClone(i.results[0]));
    },
    (i) => {
      i.results.pop();
    },
    (i) => {
      i.bindings.push(structuredClone(i.bindings[0]));
    },
    (i) => {
      i.results[0].platform = "unknown";
    },
    (i) => {
      i.results[0].observed.architecture = "arm64";
    },
    (i) => {
      i.results[0].declaredImage = i.results[0].observed.image =
        "substituted-image";
    },
    (i) => {
      i.results[0].candidateSha = i.results[0].checkoutSha = "c".repeat(40);
    },
    (i) => {
      i.source.candidateSha = "c".repeat(40);
    },
    (i) => {
      i.bindings[0].candidateSha = "c".repeat(40);
    },
    (i) => {
      i.bindings[0].provenance.jobId = "901";
    },
    (i) => {
      i.bindings[0].conclusion = "cancelled";
    },
    (i) => {
      i.bindings.find(({ tier }) => tier === "provider").authority = "ordinary";
    },
    (i) => {
      i.results[0].observed.build = "different-build";
    },
    (i) => {
      i.results[0].policy.sha256 = "c".repeat(64);
    },
    (i) => {
      i.results[0].versions[0].version = "different-version";
    },
    (i) => {
      i.bindings = [];
    },
  ]) {
    const input = completeEvidence();
    alter(input);
    assert.equal(aggregateNativeEvidence(input).decision, "BLOCKED");
  }
});

test("revision text or publication bytes alone cannot close source findings", () => {
  for (const alter of [
    (i) => {
      i.source.inspected[0].complete = false;
    },
    (i) => {
      i.source.inspected[0].binding = "UNPROVED";
    },
    (i) => {
      i.source.inspected[0].kind = "publication";
    },
    (i) => {
      i.source.inspected[0].revision = null;
    },
    (i) => {
      i.source.findings[0].status = "BLOCKED";
    },
    (i) => {
      i.source.missingInputs.push({
        findingId: SOURCE_FINDING_IDS[0],
        summary: "Missing release/build binding.",
      });
    },
    (i) => {
      i.source.hypotheses.push({
        findingId: SOURCE_FINDING_IDS[0],
        summary: "Unproved ownership mechanism.",
      });
    },
  ]) {
    const input = completeEvidence();
    alter(input);
    assert.equal(aggregateNativeEvidence(input).decision, "BLOCKED");
  }
});

test("skipped and cancelled phases stay distinct from real probe or cleanup failure", () => {
  for (const status of ["SKIPPED", "CANCELLED", "FAIL"]) {
    const input = completeEvidence();
    const result = input.results[0];
    result.phases.probe = {
      status,
      elapsedMs: status === "FAIL" ? 100 : null,
      deadlineMs: 100,
      reason: status === "FAIL" ? "deadline" : status.toLowerCase(),
    };
    result.observations = [];
    result.status = status === "FAIL" ? "FAIL" : "BLOCKED";
    result.reason = result.phases.probe.reason;
    const report = aggregateNativeEvidence(input);
    assert.equal(report.decision, status === "FAIL" ? "NO_GO" : "BLOCKED");
    assert.ok(report.issues.some(({ code }) => code === "PROBE"));
    assert.equal(
      report.results.find(
        ({ checkId, platform }) =>
          checkId === result.checkId && platform === result.platform,
      ).phases.probe.status,
      status,
    );
  }
  const input = completeEvidence();
  input.results[0].status = "FAIL";
  input.results[0].reason = "unretired";
  input.results[0].settlement.emergencyCleanup = true;
  assert.equal(aggregateNativeEvidence(input).decision, "NO_GO");
  input.results[0].status = "BLOCKED";
  input.results[0].phases.cleanup = {
    status: "FAIL",
    elapsedMs: 100,
    deadlineMs: 100,
    reason: "cleanup-failed",
  };
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "NO_GO");
  assert.ok(report.issues.some(({ code }) => code === "INCONSISTENT"));
});

test("protected dispatch is required by default and cannot be replaced by a transport claim", () => {
  const input = completeEvidence();
  const result = input.results.find(({ tier }) => tier === "provider");
  result.tier = "system";
  result.dispatch = "model-free";
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "BLOCKED");
  assert.ok(report.issues.some(({ code }) => code === "DISPATCH"));
});

test("unimplemented checks retain explicit BLOCKED records and profile checks cannot borrow another profile", () => {
  const input = completeEvidence();
  const result = input.results[0];
  result.implemented = false;
  result.status = "BLOCKED";
  result.reason = "unimplemented";
  result.provenance.jobId = null;
  result.observations = [];
  for (const name of ["setup", "probe", "cleanup"])
    result.phases[name] = {
      status: "NOT_RUN",
      elapsedMs: null,
      deadlineMs: 100,
      reason: "unimplemented",
    };
  result.settlement = {
    status: "RETAINED",
    independent: false,
    emergencyCleanup: false,
  };
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "BLOCKED");
  assert.ok(
    report.results.some(
      (entry) => !entry.implemented && entry.reason === "unimplemented",
    ),
  );
  assert.ok(
    report.results.some(
      (entry) =>
        entry.provenance.jobId === null &&
        entry.phases.probe.status === "NOT_RUN",
    ),
  );
  const wrongProfile = completeEvidence().results.find(
    ({ checkId }) => checkId === "profile.read-only",
  );
  wrongProfile.profile = "workspace-write";
  assert.throws(() => normalizeNativeResult(wrongProfile), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
});

test("diagnostic prose is bounded and never becomes Markdown or annotation instructions", () => {
  const input = completeEvidence();
  const diagnostic =
    'token=private-value password="private-password" Bearer private-bearer https://example.org/?key=private-query /private/fixture C:\\private\\fixture\n::error title=injected::private-instruction\u001b[31m\u202e';
  input.results[0].observations[0].observed = diagnostic;
  input.source.inspected[0].summary = diagnostic;
  input.source.missingInputs = [
    { findingId: SOURCE_FINDING_IDS[0], summary: diagnostic },
  ];
  const { report, summary, annotations } = renderNativeReport(input);
  const serialized = JSON.stringify(report);
  for (const value of [
    "private-value",
    "private-password",
    "private-bearer",
    "private-query",
    "/private/fixture",
    "C:\\private\\fixture",
  ])
    assert.ok(!serialized.includes(value));
  assert.ok(!summary.includes("private-instruction"));
  assert.ok(!annotations.join("\n").includes("injected"));
  const result = structuredClone(input.results[0]);
  result.observations[0].observed = "x".repeat(4096);
  assert.equal(
    normalizeNativeResult(result).observations[0].observed.length,
    512,
  );
  assert.ok(
    !/[\p{Cc}\p{Cf}]/u.test(
      normalizeNativeResult(input.results[0]).observations[0].observed,
    ),
  );
});

test("redaction covers isolated credentials, paths, and control-obfuscated assignments", () => {
  for (const diagnostic of [
    'password="private-value"',
    'token="private-value\nprivate-value"',
    "access_token=private-value",
    "refresh_token=private-value",
    "client_secret=private-value",
    "to\u001b[31mken=private-value",
    "to\u202eken=private-value",
    "Bearer private-value",
    "Basic private-value",
    "sk-private-value",
    "https://example.org/private-value",
    "/private-value/fixture",
    "C:\\private-value\\fixture",
    "::error title=private-value::injected",
  ]) {
    const result = completeEvidence().results[0];
    result.observations[0].observed = diagnostic;
    const normalized = normalizeNativeResult(result);
    assert.ok(!JSON.stringify(normalized).includes("private-value"));
  }
});

const ciContext = () => ({
  candidateSha: CANDIDATE,
  repository: "example/native-proof",
  runId: "101",
  runAttempt: 1,
  workflowSha: "c".repeat(40),
});

function reportingJob(platform = PLATFORMS[0], jobId = "1") {
  const { workflowSha, ...context } = ciContext();
  let job = initializeNativeJob({ ...context, platform: platform.os });
  job = recordNativeStage(job, "setup", passedPhase(), {
    checkoutSha: CANDIDATE,
    observed: {
      os: platform.os,
      image: platform.image,
      build: "synthetic-build",
      architecture: "x64",
    },
    provenance: { ...job.provenance, jobId },
    versions: [{ name: "node", version: "v24.21.0", sha256: DIGEST }],
  });
  job = recordNativeStage(job, "probe", passedPhase());
  return recordNativeStage(job, "cleanup", passedPhase());
}

test("system dispatch is closed and cannot activate protected provider execution", () => {
  assert.deepEqual(resolveNativeDispatch(["--tier", "system"]), {
    tier: "system",
    stage: "all",
  });
  assert.equal(
    resolveNativeDispatch(["--tier", "system", "--stage", "cleanup"]).stage,
    "cleanup",
  );
  for (const args of [
    [],
    ["--tier", "provider"],
    ["--tier", "system", "--stage"],
    ["--tier", "system", "--stage", "unknown"],
    ["--tier", "system", "--retry", "all"],
  ])
    assert.throws(() => resolveNativeDispatch(args), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  const report = renderNativeJob(reportingJob()).report;
  assert.equal(report.decision, "BLOCKED");
  assert.equal(report.ciStatus, "PASS");
  assert.ok(
    report.results.every(
      ({ implemented, status, observations, settlement }) =>
        !implemented &&
        status === "BLOCKED" &&
        observations.length === 0 &&
        settlement.status === "RETAINED",
    ),
  );
});

test("CI stage failures remain distinct, cleanup is attempted, and probe cannot precede admission", () => {
  const { workflowSha, ...context } = ciContext();
  const initial = initializeNativeJob({ ...context, platform: "linux" });
  assert.throws(() => recordNativeStage(initial, "probe", passedPhase()), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  assert.equal(initial.stages.setup.status, "NOT_RUN");
  const ready = reportingJob();
  const setup = {
    checkoutSha: ready.checkoutSha,
    observed: ready.observed,
    provenance: ready.provenance,
    versions: ready.versions,
  };
  for (const stage of ["setup", "probe", "cleanup"]) {
    let job = initial;
    for (const name of ["setup", "probe", "cleanup"])
      job = recordNativeStage(
        job,
        name,
        name === stage
          ? { ...passedPhase(), status: "FAIL", reason: `${name}-failed` }
          : name === "probe" && stage === "setup"
            ? { ...passedPhase(), status: "NOT_RUN", reason: "setup-failed" }
            : passedPhase(),
        name === "setup" ? setup : {},
      );
    const { report, summary } = renderNativeJob(job);
    assert.equal(report.decision, "BLOCKED");
    assert.equal(report.ciStatus, "FAIL");
    assert.equal(report.ciStages[stage].status, "FAIL");
    assert.ok(
      report.results.every(
        (result) =>
          !result.implemented &&
          result.status === "BLOCKED" &&
          Object.values(result.phases).every(
            ({ status, reason }) =>
              status === "NOT_RUN" && reason === "unimplemented",
          ),
      ),
    );
    assert.match(summary, new RegExp(`${stage}: FAIL`, "u"));
    assert.equal(
      job.stages.cleanup.status,
      stage === "cleanup" ? "FAIL" : "PASS",
    );
    assert.throws(() => recordNativeStage(job, "setup", passedPhase()), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
});

function ciMetadata() {
  const context = ciContext();
  const run = {
    id: 101,
    run_attempt: 1,
    repository: { full_name: context.repository },
    path: ".github/workflows/native-poc.yml",
    event: "pull_request",
    head_sha: context.workflowSha,
  };
  const jobs = PLATFORMS.map(({ os }, index) => ({
    id: index + 1,
    name: `native-system-${os}`,
    run_id: 101,
    run_attempt: 1,
    status: "completed",
    conclusion: "success",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:01:00Z",
    steps: [
      { name: `Bind native artifact ${201 + index}`, conclusion: "success" },
      ...[
        "Setup",
        "Probe reporting harness",
        "Cleanup",
        "Report per-OS evidence",
      ].map((name) => ({ name, conclusion: "success" })),
    ],
  }));
  const artifacts = PLATFORMS.map(({ os }, index) => ({
    id: 201 + index,
    name: nativeArtifactName(context, os),
    expired: false,
    size_in_bytes: 1000,
    digest: `sha256:${DIGEST}`,
    workflow_run: { id: 101, head_sha: context.workflowSha },
    created_at: "2026-01-01T00:00:30Z",
  }));
  const payloads = Object.fromEntries(
    PLATFORMS.map((platform, index) => [
      nativeArtifactName(context, platform.os),
      reportingJob(platform, String(index + 1)),
    ]),
  );
  return { context, run, jobs, artifacts, payloads };
}

test("Linux check records join only their exact job and keep unrelated contracts blocked", () => {
  const input = ciMetadata();
  const name = nativeArtifactName(input.context, "linux");
  const settled = input.payloads[name];
  const pending = {
    ...settled,
    stages: {
      ...settled.stages,
      probe: {
        status: "NOT_RUN",
        elapsedMs: null,
        deadlineMs: 30000,
        reason: "missing-input",
      },
    },
  };
  const result = completeEvidence().results.find(
    (entry) => entry.platform === "linux" && entry.checkId === "launch.argv",
  );
  result.versions = settled.versions;
  result.policy = { id: "linux-ownership-fixture-v1", sha256: DIGEST };
  const recorded = recordNativeResults(pending, [result]);
  input.payloads[name] = recordNativeStage(recorded, "probe", passedPhase());
  const selection = selectNativeArtifacts(
    input.context,
    input.run,
    input.jobs,
    input.artifacts,
  );
  const report = joinNativeArtifacts(
    input.context,
    selection,
    input.payloads,
  ).report;
  assert.equal(
    report.results.find(
      (entry) => entry.platform === "linux" && entry.checkId === "launch.argv",
    ).status,
    "PASS",
  );
  assert.equal(
    report.results.find(
      (entry) =>
        entry.platform === "linux" && entry.checkId === "profile.read-only",
    ).status,
    "BLOCKED",
  );
  assert.equal(report.decision, "BLOCKED");
  for (const results of [
    [result, result],
    [{ ...result, candidateSha: "d".repeat(40), checkoutSha: "d".repeat(40) }],
    [{ ...result, provenance: { ...result.provenance, jobId: "99" } }],
    [{ ...result, checkId: "files.private" }],
  ])
    assert.throws(() => recordNativeResults(pending, results), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  const failed = {
    ...result,
    status: "FAIL",
    reason: "probe-failed",
    phases: {
      ...result.phases,
      probe: { ...passedPhase(), status: "FAIL", reason: "probe-failed" },
    },
  };
  const failedJob = recordNativeResults(pending, [failed]);
  assert.throws(() => recordNativeStage(failedJob, "probe", passedPhase()), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  for (const change of [
    { settlement: { ...failed.settlement, independent: false } },
    {
      phases: {
        ...failed.phases,
        cleanup: { ...passedPhase(), status: "FAIL", reason: "cleanup-failed" },
      },
    },
  ]) {
    const beforeCleanup = {
      ...pending,
      stages: {
        ...pending.stages,
        cleanup: {
          status: "NOT_RUN",
          elapsedMs: null,
          deadlineMs: 30000,
          reason: "missing-input",
        },
      },
    };
    const cleanupFailed = recordNativeResults(beforeCleanup, [
      { ...failed, ...change },
    ]);
    assert.throws(
      () => recordNativeStage(cleanupFailed, "cleanup", passedPhase()),
      { code: "ERR_INVALID_NATIVE_EVIDENCE" },
    );
  }
});

test("artifact joining uses actual run/job upload receipts and rejects missing or mixed-revision payloads", () => {
  const input = ciMetadata();
  const before = structuredClone(input);
  const selection = selectNativeArtifacts(
    input.context,
    input.run,
    input.jobs,
    input.artifacts,
  );
  assert.equal(selection.entries.length, 3);
  assert.deepEqual(selection.issues, []);
  const rendered = joinNativeArtifacts(
    input.context,
    selection,
    input.payloads,
  );
  assert.deepEqual(rendered.report.ciIssues, []);
  assert.equal(rendered.report.bindings.length, 3);
  assert.equal(rendered.report.decision, "BLOCKED");
  assert.equal(rendered.report.ciStatus, "PASS");
  assert.deepEqual(input, before);
  const reordered = structuredClone(selection);
  reordered.entries.reverse();
  reordered.jobs.reverse();
  for (const entry of reordered.entries)
    entry.stages = Object.fromEntries(Object.entries(entry.stages).reverse());
  assert.deepEqual(
    joinNativeArtifacts(input.context, reordered, input.payloads),
    rendered,
  );
  assert.throws(
    () =>
      joinNativeArtifacts(
        input.context,
        {
          entries: [],
          issues: [{ code: "token=private-value", platform: null }],
          jobs: [],
        },
        {},
      ),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  const unsafe = structuredClone(selection);
  unsafe.entries[0].name = "../private-control";
  assert.throws(() => joinNativeArtifacts(input.context, unsafe, {}), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  const missingSelection = { ...selection, entries: [] };
  const missingReport = joinNativeArtifacts(
    input.context,
    missingSelection,
    {},
  ).report;
  assert.equal(missingReport.ciStatus, "BLOCKED");
  assert.deepEqual(
    missingReport.ciIssues,
    PLATFORMS.map(({ os }) => ({ code: "missing", platform: os })),
  );
  for (const alter of [
    (i) => {
      i.run.run_attempt = 2;
    },
    (i) => {
      i.artifacts.pop();
    },
    (i) => {
      i.artifacts.push(structuredClone(i.artifacts[0]));
    },
    (i) => {
      i.artifacts[0].workflow_run.head_sha = "d".repeat(40);
    },
    (i) => {
      i.jobs[0].steps[0].name = "Bind native artifact 999";
    },
    (i) => {
      i.jobs[0].steps[0].conclusion = "skipped";
    },
    (i) => {
      delete i.payloads[i.artifacts[0].name];
    },
    (i) => {
      i.payloads[i.artifacts[0].name].candidateSha = "d".repeat(40);
    },
    (i) => {
      i.payloads[i.artifacts[0].name].provenance.jobId = "999";
    },
  ]) {
    const changed = ciMetadata();
    alter(changed);
    const selected = selectNativeArtifacts(
      changed.context,
      changed.run,
      changed.jobs,
      changed.artifacts,
    );
    const report = joinNativeArtifacts(
      changed.context,
      selected,
      changed.payloads,
    ).report;
    assert.equal(report.decision, "BLOCKED");
    assert.ok(report.ciIssues.length > 0);
  }
  const cancelled = ciMetadata();
  cancelled.jobs[0].conclusion = "cancelled";
  const cancelledReport = joinNativeArtifacts(
    cancelled.context,
    selectNativeArtifacts(
      cancelled.context,
      cancelled.run,
      cancelled.jobs,
      cancelled.artifacts,
    ),
    cancelled.payloads,
  ).report;
  assert.equal(
    cancelledReport.bindings.find(({ platform }) => platform === "linux")
      .conclusion,
    "cancelled",
  );
  assert.equal(cancelledReport.decision, "BLOCKED");
  assert.equal(cancelledReport.ciStatus, "BLOCKED");
  cancelled.artifacts = [];
  const absent = joinNativeArtifacts(
    cancelled.context,
    selectNativeArtifacts(
      cancelled.context,
      cancelled.run,
      cancelled.jobs,
      cancelled.artifacts,
    ),
    {},
  ).report;
  assert.equal(
    absent.ciJobs.find(({ platform }) => platform === "linux").conclusion,
    "cancelled",
  );
  assert.equal(
    absent.ciJobs.find(({ platform }) => platform === "linux").artifactId,
    null,
  );
  assert.ok(absent.ciIssues.some(({ code }) => code === "missing"));
  const partial = ciMetadata();
  partial.artifacts.pop();
  const partialSelection = selectNativeArtifacts(
    partial.context,
    partial.run,
    partial.jobs,
    partial.artifacts,
  );
  partialSelection.issues.push({ code: "download", platform: null });
  const incomplete = joinNativeArtifacts(
    partial.context,
    partialSelection,
    partial.payloads,
  ).report;
  assert.equal(incomplete.ciStatus, "BLOCKED");
  assert.ok(incomplete.ciIssues.some(({ code }) => code === "download"));
  const failed = ciMetadata();
  failed.jobs[0].conclusion = "failure";
  failed.jobs[0].steps.find(
    ({ name }) => name === "Probe reporting harness",
  ).conclusion = "failure";
  failed.payloads[failed.artifacts[0].name].stages.probe = {
    ...passedPhase(),
    status: "FAIL",
    reason: "probe-failed",
  };
  const failedReport = joinNativeArtifacts(
    failed.context,
    selectNativeArtifacts(
      failed.context,
      failed.run,
      failed.jobs,
      failed.artifacts,
    ),
    failed.payloads,
  ).report;
  assert.equal(failedReport.decision, "BLOCKED");
  assert.equal(failedReport.ciStatus, "FAIL");
  assert.equal(
    failedReport.ciJobs.find(({ platform }) => platform === "linux").stages
      .probe,
    "failure",
  );
});
