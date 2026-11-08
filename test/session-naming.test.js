import assert from "node:assert/strict";
import test from "node:test";

import {
  createClaudeAdapter,
  createCodexAdapter,
  normalizeSessionNamingContext,
  normalizeSessionNamingDiagnostic,
} from "../src/agents/index.js";
import { listPipelines } from "../src/pipeline-registry.js";
import { roleAdapters } from "../src/runner/roles.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const context = {
  runId: RUN_ID,
  project: "sample",
  pipeline: "audit",
  role: "auditor",
};
const capabilities = {
  version: "fixture-1",
  structuredOutput: true,
  readOnly: true,
  autonomousWrite: true,
  gitMetadataWriteBlocked: true,
  workspaceWrite: true,
  localCommit: true,
  remoteWriteBlocked: true,
  nativeSessionContinuation: true,
  nativeSessionFork: true,
};

test("both strict adapters reject malformed naming context and observers before native work", async () => {
  assert.deepEqual(normalizeSessionNamingContext(context), context);
  assert.ok(Object.isFrozen(normalizeSessionNamingContext(context)));
  for (const createAdapter of [createCodexAdapter, createClaudeAdapter]) {
    const adapter = createAdapter({
      execute: () => assert.fail("No native effects"),
    });
    for (const invalid of [
      { sessionNaming: { ...context, runId: RUN_ID.slice(0, 8) } },
      { sessionNaming: { ...context, project: "line\nbreak" } },
      { sessionNaming: { ...context, project: "x".repeat(129) } },
      { sessionNaming: { ...context, role: "\u202ehidden" } },
      { sessionNaming: { ...context, nativeId: "private" } },
      { onSessionCreated: true },
      { onSessionNaming: {} },
    ])
      await assert.rejects(
        adapter.run({
          access: "read-only",
          cwd: process.cwd(),
          prompt: "Inspect.",
          ...invalid,
        }),
      );
  }
  assert.throws(() =>
    normalizeSessionNamingDiagnostic({
      status: "rejected",
      message: "private",
    }),
  );
  assert.throws(() => normalizeSessionNamingDiagnostic({ status: "retry" }));
});

test("every pipeline and mode supplies the same full Runner UUID only to active roles on either backend", async () => {
  for (const pipeline of listPipelines())
    for (const mode of ["independent", "lazy", "combined"]) {
      const settings = Object.fromEntries(
        Object.entries(pipeline.settings).map(([key, value]) => [
          key,
          value.defaultValue,
        ]),
      );
      const active = pipeline.resolveActiveRoles({ ...settings, mode });
      for (const backend of ["codex", "claude"]) {
        const seen = [],
          receipts = [],
          acknowledged = [];
        const run = {
          runId: RUN_ID,
          pipelineId: pipeline.id,
          projectPath: "/workspace/sample\nproject",
          roles: Object.fromEntries(active.map((role) => [role, { backend }])),
          sessionLineage: { source: "opaque-source", children: [] },
        };
        const adapter = {
          probe: async () => capabilities,
          async run(request) {
            seen.push(request.sessionNaming);
            const id = `child-${seen.length}`;
            await request.onSessionCreated(id);
            assert.ok(
              acknowledged.includes(id),
              "Acknowledgement precedes optional metadata",
            );
            await request.onSessionNaming({ status: "rejected" });
            return { sessionId: id, structured: { status: "READY" } };
          },
        };
        const selected = roleAdapters(
          run,
          pipeline,
          { [backend]: adapter },
          undefined,
          undefined,
          async (role, id, diagnosis) => receipts.push({ role, id, diagnosis }),
        );
        assert.deepEqual(Object.keys(selected), active);
        for (const role of active) {
          await selected[role].run({
            access: "read-only",
            cwd: run.projectPath,
            prompt: "Inspect.",
            sessionNaming: { ...context, runId: "not-authoritative" },
            onSessionCreated: async (id) => acknowledged.push(id),
          });
        }
        assert.deepEqual(
          seen,
          active.map((role) => ({
            runId: RUN_ID,
            project: "sample project",
            pipeline: pipeline.id,
            role,
          })),
        );
        assert.equal(receipts.length, active.length);
        assert.ok(
          receipts.every((receipt) => receipt.diagnosis.status === "rejected"),
        );
      }
    }
});

test("continuation cannot retroactively name a session and failed creation acknowledgement stops metadata", async () => {
  const pipeline = listPipelines()[0];
  const run = {
    runId: RUN_ID,
    pipelineId: pipeline.id,
    projectPath: "/workspace/project",
    roles: { planner: { backend: "codex" } },
    sessionLineage: { source: "source", children: [] },
  };
  const selected = roleAdapters(run, pipeline, {
    codex: {
      probe: async () => capabilities,
      async run(request) {
        if (request.session?.mode === "continue") {
          await assert.rejects(request.onSessionNaming({ status: "named" }));
          await assert.rejects(request.onSessionCreated(request.session.id));
          return { sessionId: request.session.id };
        }
        await assert.rejects(request.onSessionCreated("source"));
        await request.onSessionCreated("new-child");
        assert.fail("A failed durable acknowledgement cannot proceed");
      },
    },
  });
  await selected.planner.run({ session: { mode: "continue", id: "existing" } });
  const failure = new Error("Controlled persistence failure");
  await assert.rejects(
    selected.planner.run({
      access: "read-only",
      onSessionCreated: async () => {
        throw failure;
      },
    }),
    (cause) => cause === failure,
  );
});

test("wrapped or swallowed Runner callbacks cannot become terminal provider evidence", async () => {
  const pipeline = listPipelines()[0];
  const run = {
    runId: RUN_ID,
    pipelineId: pipeline.id,
    projectPath: "/workspace/project",
    roles: { planner: { backend: "codex" } },
    sessionLineage: { source: null, children: [] },
  };
  for (const key of [
    "onProcess",
    "onResource",
    "onSessionCreated",
    "onFreshSession",
    "onSessionNaming",
  ])
    for (const wrapped of [true, false]) {
      const failure = new Error("Controlled Runner callback failure");
      const reject = async () => {
        throw failure;
      };
      const selected = roleAdapters(
        run,
        pipeline,
        {
          codex: {
            probe: async () => capabilities,
            async run(request) {
              try {
                if (key === "onSessionNaming") {
                  await request.onSessionCreated("child");
                  await request.onSessionNaming({ status: "rejected" });
                } else await request[key]("child");
              } catch {
                if (wrapped) throw new Error("Private native wrapper");
              }
              return { sessionId: "child" };
            },
          },
        },
        undefined,
        undefined,
        reject,
      );
      await assert.rejects(
        selected.planner.run({
          access: "read-only",
          [key]: reject,
          ...(key === "onSessionNaming"
            ? { onSessionCreated: async () => {} }
            : {}),
        }),
        (cause) => cause === failure,
      );
    }
});

test("concurrent metadata notifications cannot publish two diagnoses for one acknowledged child", async () => {
  const entered = Promise.withResolvers();
  const finish = Promise.withResolvers();
  let diagnoses = 0;
  const pipeline = listPipelines()[0];
  const run = {
    runId: RUN_ID,
    pipelineId: pipeline.id,
    projectPath: "/workspace/project",
    roles: { planner: { backend: "codex" } },
    sessionLineage: { source: null, children: [] },
  };
  const selected = roleAdapters(
    run,
    pipeline,
    {
      codex: {
        async run(request) {
          await request.onSessionCreated("new-child");
          const first = request.onSessionNaming({ status: "rejected" });
          await entered.promise;
          const duplicate = assert.rejects(
            request.onSessionNaming({ status: "rejected" }),
          );
          finish.resolve();
          await Promise.all([first, duplicate]);
          return { sessionId: "new-child" };
        },
        probe: async () => capabilities,
      },
    },
    undefined,
    undefined,
    async () => {
      diagnoses++;
      entered.resolve();
      await finish.promise;
    },
  );
  await selected.planner.run({ onSessionCreated: async () => {} });
  assert.equal(diagnoses, 1);
});
