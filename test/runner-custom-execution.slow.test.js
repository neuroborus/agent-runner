import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
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
