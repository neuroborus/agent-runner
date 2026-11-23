import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { auditPipeline } from "../src/index.js";
import { publicationContent } from "../src/publication-contract.js";
import {
  READY,
  complete,
  decision,
  finding,
  fixture,
  recheck,
} from "./support/index.js";

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} publishes only rechecked findings and completes at its discovery gate`, async () => {
    const critical = finding({ severity: "Critical", category: "Correctness" });
    const f = fixture(
      [
        READY,
        complete({ candidates: [critical] }),
        recheck,
        ...(mode === "combined" ? [recheck] : []),
        complete(),
        ...(mode === "combined" ? [complete()] : []),
      ],
      { mode },
    );
    const result = await f.executePublic();
    assert.equal(result.pipelineState.workflowState, "DONE");
    const pending = f.publications.find((content) =>
      content.includes("### negative-count"),
    );
    assert.match(pending, /No confirmed findings\./u);
    assert.ok(
      pending.indexOf("## Pending candidates (unverified)") <
        pending.indexOf("### negative-count"),
    );
    const final = f.publications.at(-1);
    assert.match(final, /\*\*Status:\*\* Complete/u);
    assert.match(final, /1 confirmed finding\./u);
    assert.match(final, /Severity:\*\* Critical/u);
    assert.match(final, /## Pending candidates \(unverified\)\n\nNone\./u);
    assert.equal(result.pipelineState.publication.pending, null);
    assert.equal(result.pipelineState.publication.published.complete, true);
    assert.equal(f.calls.length, mode === "combined" ? 6 : 4);
    const before = f.publications.length;
    await f.executePublic();
    assert.equal(f.publications.length, before);
    assert.equal(
      auditPipeline.projections.status(result).auditReport.confirmedFindings,
      1,
    );
  });
}

test("zero findings completes without a redundant independent response and retains evidence gaps", async () => {
  const gaps = { limitations: ["The optional isolated check is unavailable"] };
  const f = fixture([READY, complete(gaps), complete(gaps)]);
  const result = await f.executePublic();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(f.calls.length, 3);
  assert.match(f.publications.at(-1), /No confirmed findings\./u);
  assert.match(
    f.publications.at(-1),
    /optional isolated check is unavailable/u,
  );
});

test("Markdown expansion rejects an oversized ledger update before publication and permits resume", async () => {
  const batch = (start, length) =>
    Array.from({ length }, (_, offset) =>
      finding({
        id: `finding-${start + offset}`,
        causeId: `cause-${start + offset}`,
        evidence: ["&".repeat(100_000)],
      }),
    );
  const outputs = [READY];
  for (const start of [0, 20, 40])
    outputs.push(complete({ candidates: batch(start, 20) }), recheck);
  // Each role result fits two MiB, and the run fits 32 MiB, but the final
  // ten findings would expand the rendered report beyond 32 MiB.
  outputs.push(
    complete({ candidates: batch(60, 10) }),
    complete({ status: "INCOMPLETE" }),
  );
  const f = fixture(outputs, { mode: "lazy" });
  const invoke = f.runtime.adapters.auditor.run;
  f.runtime.adapters.auditor.run = (request) => {
    f.calls.length = 0;
    return invoke(request);
  };
  let publishedHash = null;
  let publications = 0;
  f.runtime.workspace.reportArtifact = async (request, options) => {
    if (!options?.inspectOnly) {
      assert.ok(Buffer.byteLength(request.content) <= 32 * 1024 * 1024);
      assert.equal(request.expectedHash, publishedHash);
      publishedHash = f.run().pipelineState.publication.pending.contentHash;
      publications++;
    }
    return { path: request.path, contentHash: publishedHash };
  };
  // Exercise acceptance without repeatedly rendering every intermediate report.
  const paused = await f.execute();
  assert.equal(paused.pause.reason, "invalid_discovery");
  assert.equal(paused.pipelineState.history.at(-1).outcome, "invalid");
  assert.equal(paused.pipelineState.ledger.length, 60);
  assert.equal(paused.pipelineState.acceptedBatches.length, 3);
  assert.equal(paused.pipelineState.publication.pending, null);
  assert.equal(paused.pipelineState.publication.temporary, null);
  assert.equal(publications, 0);
  assert.deepEqual(auditPipeline.projections.pause(paused).nextActions, [
    { type: "resume", action: null },
  ]);

  outputs.splice(0, outputs.length, complete());
  const result = await f.executePublic();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.history.length, 5);
  assert.equal(result.pipelineState.ledger.length, 60);
  assert.equal(result.pipelineState.publication.pending, null);
  assert.equal(publications, 2);
});

test("interrupted publication settles its exact intent before any additional model turn", async () => {
  const f = fixture([READY, complete()]);
  const publish = f.runtime.workspace.reportArtifact;
  const prepared = {
    phase: "prepared",
    identity: { device: "1", inode: "2", mode: "33152", birthtimeNs: "3" },
  };
  f.runtime.workspace.reportArtifact = async (request, options) => {
    await options.recordTemporary(prepared);
    await publish(request, options);
    throw new Error("Publication acknowledgement lost");
  };
  await assert.rejects(f.executePublic(), /acknowledgement lost/u);
  const persisted = structuredClone(f.run().pipelineState.publication);
  assert.ok(persisted.pending);
  assert.equal(persisted.published, null);
  assert.deepEqual(persisted.temporary, prepared);
  // The real publisher reconciles only from this exact prepared custody record.
  const settled = [];
  f.runtime.workspace.reportArtifact = async (request, options) => {
    if (options?.inspectOnly) return publish(request, options);
    settled.push({
      expectedHash: request.expectedHash,
      content: request.content,
      temporary: options.temporary,
      pending: f.run().pipelineState.publication.pending,
    });
    if (settled.length > 1) return publish(request, options);
    return { path: request.path, contentHash: persisted.pending.contentHash };
  };
  assert.equal((await f.executePublic()).pipelineState.workflowState, "DONE");
  assert.deepEqual(settled, [
    {
      expectedHash: null,
      content: f.publications[0],
      temporary: prepared,
      pending: persisted.pending,
    },
    // Only the distinct completion binding follows the single settlement.
    {
      expectedHash: persisted.pending.contentHash,
      content: f.publications[1],
      temporary: null,
      pending: {
        ...persisted.pending,
        contentHash: createHash("sha256")
          .update(f.publications[1])
          .digest("hex"),
        complete: true,
      },
    },
  ]);
  assert.equal(f.calls.length, 2);
  assert.equal(f.run().pipelineState.publication.pending, null);
  assert.equal(f.run().pipelineState.publication.temporary, null);
});

test("unreproducible rendering and temporary custody refusals keep the suspended checkpoint", async () => {
  const f = fixture([READY, complete({ status: "INCOMPLETE" })]);
  const waiting = await f.executePublic();
  assert.equal(waiting.pause.reason, "discovery_incomplete");
  assert.equal(waiting.pause.resumeState, "DISCOVER");
  assert.ok(waiting.pipelineState.publication.published);
  for (const [reason, code] of [
    ["audit_report_rendering_changed", "ERR_AUDIT_REPORT_RENDERING_CHANGED"],
    [
      "audit_report_temporary_conflict",
      "ERR_WORKSPACE_REPORT_TEMPORARY_CONFLICT",
    ],
  ]) {
    const saved = structuredClone(waiting);
    const rendering = reason === "audit_report_rendering_changed";
    // The same projection with a different saved render hash, or an exact binding.
    if (rendering)
      saved.pipelineState.publication.published.contentHash = "e".repeat(64);
    const g = fixture([], { saved });
    g.runtime.workspace.reportArtifact = async (request, options) => {
      assert.ok(!rendering && options?.inspectOnly, "Unexpected artifact call");
      throw Object.assign(new Error("Temporary custody refused"), { code });
    };
    const blocked = await g.executePublic();
    assert.equal(blocked.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.deepEqual(blocked.pause, { reason, resumeState: "DISCOVER", code });
    assert.deepEqual(
      blocked.pipelineState.publication,
      saved.pipelineState.publication,
    );
    const projected = auditPipeline.projections.pause(blocked);
    assert.equal(projected.reason, reason);
    assert.equal(projected.resumeState, null);
    assert.deepEqual(projected.nextActions, []);
    assert.match(
      projected.explanation,
      /preserve audit\.md and any remaining \.audit\.md\.tmp/u,
    );
    assert.throws(
      () => auditPipeline.validateResumeAction(blocked, null),
      rendering
        ? /rendering cannot be reproduced/u
        : /custody cannot be verified/u,
    );
    g.runtime.workspace.reportArtifact = () =>
      assert.fail("Blocked publication cannot retry");
    assert.deepEqual(await g.executePublic(), blocked);
    assert.equal(g.calls.length, 0);
  }
});

test("pending revisions remove earlier confirmed versions until the revised batch is accepted", async () => {
  const original = finding();
  const revised = finding({
    impact: "The requested operation cannot produce a result",
  });
  const f = fixture([
    READY,
    complete({ candidates: [original] }),
    recheck,
    complete({ candidates: [revised] }),
  ]);
  const publish = f.runtime.workspace.reportArtifact;
  f.runtime.workspace.reportArtifact = async (...args) => {
    const result = await publish(...args);
    if (f.run().pipelineState.ledger[0]?.version === 2)
      throw new Error("Publication interrupted");
    return result;
  };
  await assert.rejects(f.executePublic(), /Publication interrupted/u);
  assert.match(f.publications.at(-1), /No confirmed findings\./u);
  assert.match(
    f.publications.at(-1),
    /requested operation cannot produce a result/u,
  );
  assert.equal(f.run().pipelineState.acceptedBatches.length, 1);
});

test("source drift and forged completion cannot turn a saved ledger into complete publication", async () => {
  const f = fixture([READY, complete()]);
  await f.executePublic();
  const saved = structuredClone(f.run());
  saved.pipelineState.publication.published.contentHash = "0".repeat(64);
  assert.throws(() => auditPipeline.workflow.validateRun(saved));
  const count = f.publications.length;
  f.drift();
  await assert.rejects(f.executePublic(), /Workspace changed/u);
  assert.equal(f.publications.length, count);
  assert.equal(f.calls.length, 2);
});

test("accepted hypotheses stay unverified and never enter confirmed sections", async () => {
  const hypothesis = {
    id: "negative-count",
    title: "Allocation behavior is uncertain",
    evidence: ["The allocation implementation is unavailable"],
    uncertainty: "Cannot verify the external implementation",
  };
  const f = fixture([
    READY,
    complete({ candidates: [finding()] }),
    (request) =>
      recheck(request, {
        decisions: [
          decision(hypothesis.id, {
            kind: "hypothesis",
            hypothesis,
          }),
        ],
      }),
    recheck,
    complete(),
  ]);
  await f.executePublic();
  const report = f.publications.at(-1);
  assert.match(report, /No confirmed findings\./u);
  assert.match(report, /Allocation behavior is uncertain \(unverified\)/u);
  assert.doesNotMatch(report, /Negative counts reach allocation/u);
});

test("report tampering remains blocking without another turn or write", async () => {
  const f = fixture([READY, complete()]);
  await f.executePublic();
  f.runtime.workspace.reportArtifact = async ({ path }) => ({
    path,
    contentHash: "f".repeat(64),
  });
  const blocked = await f.executePublic();
  assert.equal(blocked.pause.reason, "audit_report_changed");
  assert.deepEqual(auditPipeline.projections.pause(blocked).nextActions, []);
  f.runtime.workspace.reportArtifact = () =>
    assert.fail("Blocked publication cannot retry");
  await f.executePublic();
  assert.equal(f.calls.length, 2);
});

test("legacy discovery retains its ledger without acquiring report-write bindings", async () => {
  const f = fixture([READY, complete()]);
  await f.execute();
  delete f.run().pipelineState.publication;
  const historical = structuredClone(f.run().pipelineState);
  f.run().pipelineState = auditPipeline.migrations[3](f.run());
  assert.deepEqual(f.run().pipelineState, {
    ...historical,
    publication: { pending: null, published: null, temporary: null },
  });
  f.run().workspace = {
    policy: { artifactPaths: ["/state/task/clarifications.md"] },
  };
  const result = await f.executePublic();
  assert.equal(result.pause.reason, "audit_report_binding_required");
  assert.equal(result.pipelineState.history.length, 1);
  assert.equal(f.publications.length, 0);
  assert.equal(f.calls.length, 2);
});

test("legacy audit clarification defaults preserve completed discovery and reject invalid selections", async () => {
  const f = fixture([READY, complete()]);
  await f.executePublic();
  const legacy = structuredClone(f.run());
  delete legacy.pipelineState.proactiveClarification;
  delete legacy.pipelineState.proactiveClarificationComplete;
  const migrated = auditPipeline.migrations[4](legacy);
  assert.deepEqual(migrated, {
    ...legacy.pipelineState,
    proactiveClarification: false,
    proactiveClarificationComplete: true,
  });
  assert.doesNotThrow(() =>
    auditPipeline.workflow.validateRun({ ...legacy, pipelineState: migrated }),
  );
  assert.throws(() =>
    auditPipeline.workflow.createState({ proactiveClarification: "true" }),
  );
  migrated.proactiveClarificationComplete = false;
  assert.throws(() =>
    auditPipeline.workflow.validateRun({ ...legacy, pipelineState: migrated }),
  );
});

test("legacy source-scope migration preserves complete report bytes, receipts and consumed discovery/recheck budgets", async () => {
  const f = fixture([
    READY,
    complete({ candidates: [finding()] }),
    recheck,
    complete(),
  ]);
  delete f.run().pipelineState.settings.sourceScope;
  delete f.run().pipelineState.settings.excludePaths;
  const completed = await f.executePublic();
  const legacy = structuredClone(completed);
  const before = publicationContent(legacy.pipelineState);
  const migrated = auditPipeline.migrations[6](legacy);
  assert.deepEqual(migrated, legacy.pipelineState);
  assert.deepEqual(publicationContent(migrated), before);
  assert.doesNotThrow(() =>
    auditPipeline.workflow.validateRun({ ...legacy, pipelineState: migrated }),
  );
  const calls = f.calls.length;
  const publications = f.publications.length;
  f.run().pipelineState = migrated;
  const result = await f.executePublic();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(f.calls.length, calls);
  assert.equal(f.publications.length, publications);
  assert.deepEqual(
    result.pipelineState.acceptedBatches,
    legacy.pipelineState.acceptedBatches,
  );
  assert.deepEqual(result.pipelineState.history, legacy.pipelineState.history);
  assert.deepEqual(
    result.pipelineState.recheckHistory,
    legacy.pipelineState.recheckHistory,
  );
});
