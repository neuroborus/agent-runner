import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";

import { planExecutionPipeline } from "@agent-runner/plan-execution";
import { customExecutionFixture } from "./support/index.js";

test("durable custom authoring and execution settle reviewed steps across interrupted confirmation", async (t) => {
  let interrupt = true;
  const f = await customExecutionFixture(t, "combined", {
    durable: true,
    author: true,
    beforeTurn({ saved }) {
      if (
        interrupt &&
        saved.pipelineState.currentStep === 2 &&
        saved.activeTurn.phase === "confirm"
      ) {
        interrupt = false;
        throw Object.assign(new Error("Provider temporarily unavailable"), {
          recoverable: true,
        });
      }
    },
  });
  const paused = await f.run();
  assert.equal(paused.run.pause.reason, "backend_unavailable");
  assert.equal(paused.run.pipelineState.customResults.accepted.length, 1);
  const writePolicy = paused.run.pipelineState.customWritePolicy;
  assert.deepEqual(writePolicy.supportedAccess, ["workspace-write"]);
  const receipt = paused.run.pipelineState.customResults.accepted[0].receipt;
  const resumed = await f.run();
  assert.equal(
    resumed.run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(resumed.run.pause),
  );
  assert.equal(
    resumed.run.pipelineState.customResults.accepted[0].receipt,
    receipt,
  );
  assert.equal(resumed.run.pipelineState.customResults.accepted.length, 2);
  assert.deepEqual(resumed.run.pipelineState.customWritePolicy, writePolicy);
  assert.deepEqual(resumed.run.pipelineState.completedCommits, []);
  assert.equal(f.calls.filter(({ phase }) => phase === "implement").length, 2);
  assert.match(await readFile(f.output, "utf8"), /source.md/u);
  assert.ok(f.probes.some(({ access }) => access === "workspace-write"));
  assert.ok(
    f.calls.every(
      ({ request }) => request.workspacePolicy.kind === "directory",
    ),
  );
});

test("durable lazy custom execution keeps a precise candidate diagnostic through a cold null retry", async (t) => {
  const sentinel = "sentinel-value";
  let invalid = 0;
  const step1 = [];
  const f = await customExecutionFixture(t, "lazy", {
    durable: true,
    beforeTurn({ saved }) {
      if (saved.pipelineState.currentStep === 1) step1.push(saved);
      if (
        invalid === 2 ||
        saved.pipelineState.workflowState !== "CLEAN_CONFIRM" ||
        saved.pipelineState.currentStep !== 1
      )
        return;
      invalid += 1;
      return {
        status: "CLEAN",
        findings: [
          {
            id: "R1",
            file: "source.md",
            problem: sentinel,
            reason: "Reason.",
            suggestedAction: "Fix it.",
          },
        ],
        question: "",
        options: [],
        whyBlocked: "",
        evidence: [],
      };
    },
  });
  const diagnostic = {
    role: "worker",
    phase: "clean-confirm",
    contract: "lazy-clean-confirm",
    field: "findings",
    constraint: "empty-when-clean",
  };
  const batch = JSON.stringify([diagnostic], null, 2);
  const cleanCalls = () =>
    f.calls.filter(({ phase }) => phase === "clean-confirm");
  const persisted = async () => {
    const stateRoot = join(dirname(f.taskPath), "state");
    const names = await readdir(stateRoot, { recursive: true });
    const files = await Promise.all(
      names.map((name) =>
        readFile(join(stateRoot, name), "utf8").catch(() => ""),
      ),
    );
    return files.join("\n");
  };

  const { run: paused } = await f.run();
  const pending = paused.pipelineState.pendingLazyCorrection;
  const projected = planExecutionPipeline.projections.pause(paused);

  assert.equal(paused.pause.reason, "lazy_output_invalid");
  assert.equal(paused.pause.resumeState, "CLEAN_CONFIRM");
  assert.ok(cleanCalls()[1].request.prompt.includes(batch));
  assert.deepEqual(pending.diagnostics, [diagnostic]);
  assert.deepEqual(paused.pipelineState.lazyCorrections, [pending]);
  assert.equal(pending.fixRoundCharged, false);
  assert.deepEqual(projected.nextActions, [{ type: "resume", action: null }]);
  assert.deepEqual(projected.evidence, [
    "Worker field findings violated empty-when-clean.",
  ]);
  assert.equal(JSON.stringify(projected).includes(sentinel), false);
  assert.deepEqual(
    (await f.store.loadRun(f.runId)).pipelineState.pendingLazyCorrection,
    pending,
  );

  const { run: completed } = await f.run();
  const retry = cleanCalls()[2];
  const retrying = step1.filter(
    ({ activeTurn }) => activeTurn.phase === "clean-confirm",
  )[2];
  const after = step1[step1.indexOf(retrying) + 1];

  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(retry.step, 1);
  assert.deepEqual(retrying.pipelineState.pendingLazyCorrection, pending);
  assert.deepEqual(after.pipelineState.lazyCorrections, [pending]);
  assert.equal(after.pipelineState.pendingLazyCorrection, null);
  assert.equal(after.counters.fixRounds, paused.counters.fixRounds);
  assert.equal(retry.request.access, "read-only");
  assert.equal(retry.request.session, undefined);
  assert.ok(retry.request.prompt.includes(batch));
  assert.ok(
    retry.request.prompt.includes(
      `Inspected candidate fingerprint: ${pending.contentFingerprint}`,
    ),
  );
  assert.equal((await persisted()).includes(sentinel), false);
});
