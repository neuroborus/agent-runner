import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { Writable } from "node:stream";
import {
  assertAcceptanceRevision,
  normalizeAcceptanceRequest,
  selectAcceptanceArtifacts,
  joinAcceptanceArtifacts,
  initializeNativeJob,
  selectedSystemInventory,
} from "./index.js";
import {
  providerJobBounds,
  protectedProviderRecipes,
  takeRelayCredentials,
  fetchAcceptanceInput,
} from "./providers/index.js";
import { PLATFORMS } from "./catalog.js";
import { nativeArtifactDownload } from "./dispatch.js";

const C = "a".repeat(40),
  M = "b".repeat(40),
  B = "c".repeat(40),
  H = "d".repeat(64);
const request = {
  candidateSha: C,
  repository: "example/native",
  runId: "20",
  runAttempt: 2,
  workflowSha: C,
  systemRunId: "10",
  systemRunAttempt: 3,
  sourceReviewSha256: H,
};
const now = Date.parse("2026-01-02T06:00:00Z");
function bundle(tier) {
  const provider = tier === "provider",
    runId = provider ? 20 : 10,
    attempt = provider ? 2 : 3;
  const date = provider ? "2026-01-02" : "2026-01-01";
  const stamp = (time) => `${date}T${time}:00Z`;
  const path = `.github/workflows/${provider ? "native-poc-acceptance.yml" : "native-poc.yml"}`;
  const jobs = PLATFORMS.map(({ os }, i) => ({
    id: (provider ? 300 : 100) + i,
    run_id: runId,
    run_attempt: attempt,
    name: `native-${tier}-${os}`,
    status: "completed",
    conclusion: "success",
    started_at: stamp("01:00"),
    completed_at: stamp("01:04"),
    steps: [
      "Setup",
      provider
        ? "Probe protected real providers"
        : "Probe complete system inventory",
      "Cleanup",
      "Report per-OS evidence",
      "Upload native evidence",
      `Bind native artifact ${(provider ? 400 : 200) + i}`,
    ].map((name, n) => ({
      name,
      conclusion: "success",
      started_at: stamp(n === 5 ? "01:03" : "01:01"),
      completed_at: stamp(n === 5 ? "01:04" : "01:02"),
    })),
  }));
  const artifacts = PLATFORMS.map(({ os }, i) => ({
    id: (provider ? 400 : 200) + i,
    name: `native-${tier}-${os}-${attempt}-${C}`,
    digest: `sha256:${H}`,
    expired: false,
    size_in_bytes: 1024,
    created_at: stamp("01:01"),
    expires_at: "2026-01-08T00:00:00Z",
    workflow_run: { id: runId, head_sha: provider ? C : M },
  }));
  if (!provider)
    jobs.push(
      {
        id: 501,
        run_id: runId,
        run_attempt: attempt,
        name: "candidate",
        status: "completed",
        conclusion: "success",
      },
      {
        id: 502,
        run_id: runId,
        run_attempt: attempt,
        name: "aggregate",
        status: "completed",
        conclusion: "failure",
        steps: [
          {
            name: "Collect read-only run/job/artifact metadata",
            conclusion: "success",
          },
          {
            name: "Report aggregate and enforce acceptance",
            conclusion: "failure",
          },
          {
            name: "Upload aggregate failures and summary",
            conclusion: "success",
          },
        ],
      },
    );
  return {
    repository: { id: 1, full_name: request.repository },
    workflow: { id: provider ? 6 : 5, path },
    run: {
      id: runId,
      run_attempt: attempt,
      workflow_id: provider ? 6 : 5,
      path,
      head_sha: provider ? C : M,
      event: provider ? "workflow_dispatch" : "pull_request",
      status: provider ? "in_progress" : "completed",
      conclusion: provider ? null : "failure",
      created_at: stamp("00:00"),
      run_started_at: stamp("00:30"),
      updated_at: stamp("02:00"),
      repository: { id: 1, full_name: request.repository },
      pull_requests: provider
        ? []
        : [{ head: { sha: C }, base: { sha: B, repo: { id: 1 } } }],
    },
    jobs,
    artifacts,
    merge: { sha: M, parents: [{ sha: B }, { sha: C }] },
    candidateWorkflow: { sha: B },
    runWorkflow: { sha: B },
    environments: PLATFORMS.map(({ os }) => ({
      name: `native-poc-provider-${os}`,
      protection_rules: [
        {
          type: "required_reviewers",
          prevent_self_review: true,
          reviewers: [{ id: 1 }],
        },
      ],
    })),
  };
}

test("acceptance requires dispatch, workflow and checkout to match before effects", () => {
  const observed = {
    event: "workflow_dispatch",
    workflowSha: C,
    dispatchSha: C,
    checkoutSha: C,
  };
  assert.deepEqual(assertAcceptanceRevision(request, observed), request);
  for (const key of ["event", "workflowSha", "dispatchSha", "checkoutSha"])
    assert.throws(() =>
      assertAcceptanceRevision(request, { ...observed, [key]: M }),
    );
  assert.throws(() =>
    normalizeAcceptanceRequest({ ...request, systemRunId: request.runId }),
  );
});

test("collection binds PR merge ancestry, workflow blobs, both attempts, protected jobs and upload receipts", () => {
  const original = { system: bundle("system"), provider: bundle("provider") };
  const good = selectAcceptanceArtifacts(request, original, now);
  assert.equal(good.systemContext.workflowSha, M);
  assert.equal(good.systemContext.candidateSha, C);
  assert.equal(good.system.entries.length + good.provider.entries.length, 6);
  assert.equal(
    good.provider.entries[0].binding.authority,
    "operator-protected",
  );
  assert.equal(
    selectAcceptanceArtifacts(request, original, now, { systemOnly: true })
      .provider.entries.length,
    0,
  );
  for (const mutate of [
    (v) => {
      v.system.merge.parents[1].sha = M;
    },
    (v) => {
      v.system.runWorkflow.sha = M;
    },
    (v) => {
      v.system.run.pull_requests[0].head.sha = M;
    },
    (v) => {
      v.system.run.run_attempt++;
    },
    (v) => {
      v.system.run.repository.id++;
    },
    (v) => {
      v.system.jobs.at(-1).steps[0].conclusion = "failure";
    },
    (v) => {
      v.system.jobs.at(-1).steps.push({
        name: "Download selected native artifacts",
        conclusion: "skipped",
      });
    },
    (v) => {
      v.provider.run.workflow_id++;
    },
    (v) => {
      v.provider.run.head_sha = M;
    },
    (v) => {
      v.provider.environments[0].protection_rules = [];
    },
    (v) => {
      v.provider.environments[0].protection_rules[0].prevent_self_review = false;
    },
    (v) => {
      v.system.jobs[0].steps.pop();
    },
    (v) => {
      v.system.jobs[0].steps[4].conclusion = "failure";
    },
    (v) => {
      v.provider.jobs[0].steps[1].conclusion = "skipped";
    },
    (v) => {
      v.provider.jobs[0].conclusion = "failure";
    },
    (v) => {
      v.provider.artifacts[0].digest = null;
    },
    (v) => {
      v.provider.artifacts[0].workflow_run.id = 10;
    },
    (v) => {
      v.provider.artifacts[0].expires_at = "2026-01-02T01:00:00Z";
    },
    (v) => {
      v.provider.artifacts[0].created_at = "2026-01-02T01:04:00.001Z";
    },
    (v) => {
      v.provider.artifacts.push(structuredClone(v.provider.artifacts[0]));
    },
    (v) => {
      v.provider.jobs[1].id = v.provider.jobs[0].id;
    },
    (v) => {
      v.provider.jobs.pop();
    },
  ]) {
    const value = structuredClone(original);
    mutate(value);
    assert.throws(() => selectAcceptanceArtifacts(request, value, now));
  }
  assert.throws(() =>
    selectAcceptanceArtifacts(request, original, now + 8 * 86400000),
  );
});

test("acceptance binds both tiers to the finite upload and job envelope independently of receipt completion", () => {
  for (const tier of ["system", "provider"])
    for (const [endpoint, offset, admitted] of [
      ["upload", -1, false],
      ["upload", 0, true],
      ["receipt", -1, true],
      ["receipt", 0, true],
      ["receipt", 1, true],
      ["job", -1, true],
      ["job", 0, true],
      ["job", 1, false],
    ]) {
      const bundles = {
          system: bundle("system"),
          provider: bundle("provider"),
        },
        selected = bundles[tier],
        receipt = selected.jobs[0].steps.at(-1),
        upload = selected.jobs[0].steps.find(
          ({ name }) => name === "Upload native evidence",
        );
      receipt.completed_at = new Date(
        Date.parse(receipt.started_at) + 30000,
      ).toISOString();
      const boundary = Date.parse(
        endpoint === "upload"
          ? upload.started_at
          : endpoint === "receipt"
            ? receipt.completed_at
            : selected.jobs[0].completed_at,
      );
      selected.artifacts[0].created_at = new Date(
        boundary + offset,
      ).toISOString();
      if (!admitted)
        assert.throws(() => selectAcceptanceArtifacts(request, bundles, now));
      else {
        const selection = selectAcceptanceArtifacts(request, bundles, now);
        assert.equal(selection[tier].entries.length, 3);
        assert.equal(
          selection[tier].entries[0].binding.artifactId,
          String(selected.artifacts[0].id),
        );
      }
    }
});

test("reviewed publication still requires finite ordered successful upload and receipt intervals in both tiers", () => {
  for (const tier of ["system", "provider"])
    for (const damage of [
      "upload-start",
      "upload-end",
      "receipt-start",
      "receipt-end",
      "order",
      "outside-job",
      "failed-upload",
      "duplicate-upload",
    ]) {
      const bundles = {
          system: bundle("system"),
          provider: bundle("provider"),
        },
        job = bundles[tier].jobs[0],
        upload = job.steps.find(
          ({ name }) => name === "Upload native evidence",
        ),
        receipt = job.steps.at(-1);
      if (damage === "upload-start") upload.started_at = "invalid";
      if (damage === "upload-end") upload.completed_at = "invalid";
      if (damage === "receipt-start") receipt.started_at = "invalid";
      if (damage === "receipt-end") receipt.completed_at = "invalid";
      if (damage === "order") receipt.started_at = upload.started_at;
      if (damage === "outside-job")
        receipt.completed_at = new Date(
          Date.parse(job.completed_at) + 1,
        ).toISOString();
      if (damage === "failed-upload") upload.conclusion = "failure";
      if (damage === "duplicate-upload")
        job.steps.push(structuredClone(upload));
      assert.throws(
        () => selectAcceptanceArtifacts(request, bundles, now),
        tier + ":" + damage,
      );
    }
});

test("acceptance download layouts keep simultaneous system and provider selections disjoint", () => {
  const selection = selectAcceptanceArtifacts(
      request,
      { system: bundle("system"), provider: bundle("provider") },
      now,
    ),
    root = path.resolve("synthetic", "native-artifacts");
  for (const systemCount of [0, 1, 3])
    for (const providerCount of [0, 1, 3]) {
      const destinations = [],
        ids = [];
      for (const [tier, count] of [
        ["system", systemCount],
        ["provider", providerCount],
      ]) {
        const selected = {
            ...selection[tier],
            entries: selection[tier].entries.slice(0, count),
          },
          download = nativeArtifactDownload(
            selection[tier + "Context"],
            selected,
            root,
            tier,
          );
        assert.equal(
          download.artifactIds,
          selected.entries.map(({ binding }) => binding.artifactId).join(","),
        );
        assert.equal(
          download.path,
          count === 0
            ? ""
            : count === 1
              ? path.join(root, selected.entries[0].name)
              : root,
        );
        for (const entry of selected.entries) {
          ids.push(entry.binding.artifactId);
          destinations.push(
            count === 1 ? download.path : path.join(download.path, entry.name),
          );
        }
      }
      assert.equal(new Set(ids).size, systemCount + providerCount);
      assert.equal(new Set(destinations).size, systemCount + providerCount);
      for (const destination of destinations)
        assert.equal(path.dirname(destination), root);
    }
  assert.throws(() =>
    nativeArtifactDownload(selection.systemContext, selection.provider, root),
  );
});

test("protected system selection rejects ordinary version-7 experiment payloads", () => {
  const bundles = { system: bundle("system"), provider: bundle("provider") },
    selection = selectAcceptanceArtifacts(request, bundles, now),
    payloads = Object.fromEntries(
      selection.system.entries.map((entry) => [
        entry.name,
        initializeNativeJob(
          {
            candidateSha: C,
            platform: entry.binding.platform,
            repository: request.repository,
            runId: request.systemRunId,
            runAttempt: request.systemRunAttempt,
          },
          { schemaVersion: 7, purpose: "experiment" },
        ),
      ]),
    );
  const inventory = selectedSystemInventory(
    selection.systemContext,
    selection.system,
    payloads,
  );
  assert.equal(inventory.status, "BLOCKED");
  assert.equal(inventory.records, 0);
  assert.equal(inventory.fullAcceptance, false);
});

test("failed provider artifacts retain diagnostic custody without admitting acceptance or credentials", () => {
  const bundles = { system: bundle("system"), provider: bundle("provider") };
  const failed = bundles.provider.jobs[0];
  failed.conclusion = "failure";
  failed.steps.find(({ name }) => name === "Setup").conclusion = "failure";
  failed.steps.find(
    ({ name }) => name === "Probe protected real providers",
  ).conclusion = "skipped";
  assert.throws(() => selectAcceptanceArtifacts(request, bundles, now));
  const selection = selectAcceptanceArtifacts(request, bundles, now, {
    diagnosticsOnly: true,
  });
  assert.equal(selection.diagnosticsOnly, true);
  assert.equal(selection.provider.entries[0].binding.conclusion, "failure");
  assert.throws(() => joinAcceptanceArtifacts(selection, {}, {}, []));
  assert.throws(() =>
    selectAcceptanceArtifacts(request, bundles, now, {
      diagnosticsOnly: true,
      systemOnly: true,
    }),
  );
  failed.steps.find(({ name }) =>
    name.startsWith("Bind native artifact"),
  ).conclusion = "failure";
  assert.equal(
    selectAcceptanceArtifacts(request, bundles, now, { diagnosticsOnly: true })
      .provider.entries.length,
    2,
  );
});

test("acceptance binds freshness and ordering to the selected attempts rather than original run creation", () => {
  const value = { system: bundle("system"), provider: bundle("provider") };
  for (const { run } of Object.values(value))
    run.created_at = "2025-12-01T00:00:00Z";
  assert.equal(
    selectAcceptanceArtifacts(request, value, now).provider.entries.length,
    3,
  );
  for (const mutate of [
    (v) => {
      v.provider.run.run_started_at = "2026-01-01T01:00:00Z";
    },
    (v) => {
      v.system.run.run_started_at = "2025-12-24T00:00:00Z";
    },
    (v) => {
      v.provider.run.run_started_at = "2026-01-02T03:00:00Z";
    },
    (v) => {
      v.provider.jobs[0].started_at = "2026-01-02T00:00:00Z";
    },
  ]) {
    const altered = structuredClone(value);
    mutate(altered);
    assert.throws(() => selectAcceptanceArtifacts(request, altered, now));
  }
});

test("provider deadlines cover every fixed case and separate settlement", () => {
  for (const { os } of PLATFORMS) {
    const bound = providerJobBounds(os);
    assert.ok(
      bound.probeMs >=
        protectedProviderRecipes(os).reduce(
          (sum, recipe) => sum + recipe.deadlineMs + 60000,
          0,
        ),
    );
    assert.ok(bound.probeMinutes < 360);
    assert.ok(bound.cleanupMs >= 2 * 120000 + 2 * 30000);
  }
});

test("review acquisition is bounded credential-free data from the exact public revision", async () => {
  const env = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    NATIVE_SYSTEM_INPUT_REPOSITORY: "example/reviews",
    NATIVE_SYSTEM_INPUT_REVISION: M,
  };
  const bytes = Buffer.from('throw new Error("Review data must not execute");');
  const fetchInput = async (url, options) => {
    assert.equal(
      url,
      `https://raw.githubusercontent.com/example/reviews/${M}/ci/native/reviews/${C}/linux/provider-effects.mjs`,
    );
    assert.equal(options.redirect, "error");
    assert.equal(options.credentials, "omit");
    assert.equal(options.headers, undefined);
    return { ok: true, body: [bytes] };
  };
  assert.deepEqual(
    await fetchAcceptanceInput(env, C, "linux/provider-effects.mjs", {
      fetchInput,
    }),
    bytes,
  );
  for (const member of [
    "../provider-effects.mjs",
    "linux/alternate.mjs",
    "https://example.org/input",
  ])
    await assert.rejects(fetchAcceptanceInput(env, C, member, { fetchInput }));
  await assert.rejects(
    fetchAcceptanceInput(env, C, "source-manifest.json", {
      fetchInput: async () => ({ ok: true, body: [Buffer.alloc(2097153)] }),
    }),
  );
});

test("step secrets leave the environment and reach only an admitted private relay pipe", async () => {
  const env = {
    NATIVE_CODEX_MODEL_CREDENTIAL: "synthetic-codex-key",
    NATIVE_CLAUDE_MODEL_CREDENTIAL: "synthetic-claude-key",
  };
  const custody = takeRelayCredentials(env);
  assert.deepEqual(env, {});
  const context = {
    spec: { provider: "codex", candidateSha: C, nonce: "e".repeat(32) },
    configurationSha256: H,
    invocation: { specificationSha256: H },
    policy: { provider: "codex" },
  };
  const verified = {
    independent: true,
    configurationSha256: H,
    candidateSha: C,
    nonce: context.spec.nonce,
    privateControl: true,
    receivingPrincipalVerified: true,
    providerExcluded: true,
    bridgeExcluded: true,
    nativeEventSha256: H,
    controlSha256: H,
    brokerUid: 0,
  };
  let packet;
  const control = new Writable({
    write(bytes, _encoding, callback) {
      packet = JSON.parse(bytes);
      callback();
    },
  });
  control.bindingSha256 = H;
  const receiver = {
    role: "relay",
    admitted: true,
    receiptVerified: true,
    independent: true,
    candidateSha: C,
    nonce: context.spec.nonce,
    configurationSha256: H,
    control,
  };
  for (const patch of [
    { privateControl: false },
    { providerExcluded: false },
    { bridgeExcluded: false },
    { receivingPrincipalVerified: false },
    { brokerUid: 1 },
    { controlSha256: "f".repeat(64) },
  ]) {
    await assert.rejects(
      custody.deliver("linux", context, receiver, { ...verified, ...patch }),
    );
    assert.equal(packet, undefined);
  }
  await assert.rejects(
    custody.deliver("linux", context, receiver, verified, {
      signal: AbortSignal.abort(),
    }),
  );
  await custody.deliver("linux", context, receiver, verified);
  assert.equal(packet.credential, "synthetic-codex-key");
  assert.equal(packet.configurationSha256, H);
  await assert.rejects(custody.deliver("linux", context, receiver, verified));
  custody.close();
  await assert.rejects(
    custody.deliver(
      "linux",
      { ...context, configurationSha256: "f".repeat(64) },
      receiver,
      verified,
    ),
  );
  const failedCustody = takeRelayCredentials({
    NATIVE_CODEX_MODEL_CREDENTIAL: "synthetic-key",
  });
  const failedControl = new Writable({
    write(_bytes, _encoding, callback) {
      callback(new Error("Closed control"));
    },
  });
  failedControl.bindingSha256 = H;
  await assert.rejects(
    failedCustody.deliver(
      "linux",
      context,
      { ...receiver, control: failedControl },
      verified,
    ),
  );
  failedCustody.close();
});
