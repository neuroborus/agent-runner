import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createRunStore, RunStoreError } from "../../src/state/index.js";

const BOOT_ID = "11111111-1111-4111-8111-111111111111";
const owner = {
  pid: 202,
  hostname: "test-host",
  processIdentity: { bootId: BOOT_ID, startTicks: "2020" },
};

async function fixture(t) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-recovery-"));
  let created;
  let action;
  t.after(async () => {
    try {
      await action?.release();
      await created?.lease.release();
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  const options = {
    stateRoot,
    hostName: owner.hostname,
    processIsAlive: () => true,
    processIdentity: (pid) => ({
      bootId: BOOT_ID,
      startTicks: String(pid * 10),
    }),
  };
  const store = createRunStore({ ...options, processId: 101 });
  created = await store.createRun({
    pipelineId: "plan-authoring",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: { planner: { backend: "codex", model: null } },
  });
  const runId = created.state.runId;
  const dispatch = {
    id: randomUUID(),
    expectedRevision: created.state.revision,
  };
  const actionInput = {
    key: "recovery-request",
    tool: "run_resume",
    arguments: {
      runId,
      expectedRevision: dispatch.expectedRevision,
      action: null,
    },
  };
  action = await store.beginAction({
    ...actionInput,
    context: { runId, dispatch: { ...dispatch, owner } },
  });
  const childOptions = { ...options, processId: owner.pid };
  return {
    store,
    child: createRunStore(childOptions),
    childOptions,
    created,
    runId,
    dispatch,
    action,
    actionInput,
    failurePath: (id = dispatch.id) =>
      join(created.directoryPath, `.recovery-failure-${id}.json`),
  };
}

const failure = (code = "ERR_EXECUTION_PROCESS_UNVERIFIABLE") => ({
  stage: "process-recovery",
  error: new RunStoreError("Discarded private error text.", {
    code,
    cause: new Error("Discarded private cause."),
  }),
});

test("retains a pre-acknowledgement cause despite execution-lease acquisition failure", async (t) => {
  const f = await fixture(t);
  const paths = ["state.json", "events.jsonl", ".lease"].map((name) =>
    join(f.created.directoryPath, name),
  );
  const before = await Promise.all(paths.map((path) => readFile(path, "utf8")));
  let error;
  try {
    await f.child.acquireRunLease(f.runId);
    assert.fail("The live execution lease must exclude this child.");
  } catch (cause) {
    assert.equal(cause.code, "ERR_RUN_LEASED");
    error = cause;
  }
  const diagnostic = await f.child.recordRecoveryFailure(f.runId, f.dispatch, {
    stage: "execution-lease",
    error,
  });
  const restarted = createRunStore(f.childOptions);
  const recorded = (await f.store.readAction(f.actionInput)).context.dispatch;
  assert.deepEqual(
    await restarted.readRecoveryFailure(f.runId, recorded),
    diagnostic,
  );
  assert.equal(diagnostic.code, "ERR_RUN_LEASED");
  assert.equal(diagnostic.stage, "execution-lease");
  assert.equal(
    diagnostic.explanation,
    "Execution ownership could not be acquired.",
  );
  assert.deepEqual(diagnostic.owner, owner);
  assert.deepEqual(diagnostic.dispatch, f.dispatch);
  assert.ok(Object.isFrozen(diagnostic.owner.processIdentity));
  assert.deepEqual(await f.store.inspectRecoveryDispatch(f.runId, f.dispatch), {
    started: false,
    ready: false,
    retryable: false,
  });
  assert.deepEqual(await f.store.loadRun(f.runId), f.created.state);
  assert.deepEqual(
    await Promise.all(paths.map((path) => readFile(path, "utf8"))),
    before,
  );
  assert.equal(await f.store.runLeaseOwnerIsLive(f.runId), true);
  assert.equal(f.action.record.status, "intent");
  assert.equal(f.action.record.result, null);
});

test("keeps a failure separate from admission, readiness, and workflow state", async (t) => {
  const f = await fixture(t);
  const admitted = await f.store.recordRecoveryDispatch(
    f.created.lease,
    f.dispatch,
  );
  const diagnostic = await f.child.recordRecoveryFailure(
    f.runId,
    f.dispatch,
    failure(),
  );
  assert.equal(diagnostic.code, "ERR_EXECUTION_PROCESS_UNVERIFIABLE");
  assert.equal(
    diagnostic.explanation,
    "Execution process ownership could not be verified.",
  );
  assert.deepEqual(await f.store.loadRun(f.runId), admitted);
  assert.deepEqual(await f.store.inspectRecoveryDispatch(f.runId, f.dispatch), {
    started: true,
    ready: false,
    retryable: true,
  });
  assert.equal(f.action.record.status, "intent");
  assert.deepEqual(
    await f.store.readRecoveryFailure(
      f.runId,
      f.action.record.context.dispatch,
    ),
    diagnostic,
  );
});

test("requires exact dispatch and recorded child correlation without inferring historical causes", async (t) => {
  const f = await fixture(t);
  const binding = f.action.record.context.dispatch;
  assert.equal(await f.store.readRecoveryFailure(f.runId, binding), null);
  const diagnostic = await f.child.recordRecoveryFailure(
    f.runId,
    f.dispatch,
    failure(),
  );
  for (const mismatch of [
    { ...binding, id: randomUUID() },
    { ...binding, expectedRevision: binding.expectedRevision + 1 },
    { ...binding, owner: null },
    { ...binding, owner: { ...owner, pid: 303 } },
    { ...binding, owner: { ...owner, hostname: "other-host" } },
    {
      ...binding,
      owner: {
        ...owner,
        processIdentity: { ...owner.processIdentity, startTicks: "999" },
      },
    },
    {
      ...binding,
      owner: {
        ...owner,
        processIdentity: { ...owner.processIdentity, bootId: randomUUID() },
      },
    },
  ]) {
    assert.equal(await f.store.readRecoveryFailure(f.runId, mismatch), null);
  }
  for (const substituted of [
    { ...diagnostic, runId: randomUUID() },
    { ...diagnostic, dispatch: { ...f.dispatch, id: randomUUID() } },
  ]) {
    await writeFile(f.failurePath(), JSON.stringify(substituted));
    assert.equal(await f.store.readRecoveryFailure(f.runId, binding), null);
  }
  await writeFile(f.failurePath(), JSON.stringify(diagnostic));
  const next = { ...f.dispatch, id: randomUUID() };
  const later = await f.child.recordRecoveryFailure(
    f.runId,
    next,
    failure("ERR_WORKTREE_LEASED"),
  );
  assert.deepEqual(
    await f.child.recordRecoveryFailure(f.runId, f.dispatch, failure()),
    diagnostic,
  );
  await assert.rejects(
    f.child.recordRecoveryFailure(
      f.runId,
      f.dispatch,
      failure("ERR_RUN_LEASED"),
    ),
    { code: "ERR_RECOVERY_FAILURE_CONFLICT" },
  );
  assert.deepEqual(
    await f.store.readRecoveryFailure(f.runId, { ...next, owner }),
    later,
  );
});

test("interrupted publication leaves no partial diagnostic and retries publish one immutable cause", async (t) => {
  const f = await fixture(t);
  for (const phase of ["prepared", "published"]) {
    const dispatch = { ...f.dispatch, id: randomUUID() };
    const interrupted = createRunStore({
      ...f.childOptions,
      onRecoveryFailurePublicationBoundary(boundary) {
        if (boundary.phase === phase)
          throw new Error("Interrupted publication.");
      },
    });
    await assert.rejects(
      interrupted.recordRecoveryFailure(f.runId, dispatch, failure()),
      /Interrupted publication/u,
    );
    assert.equal(
      await f.store.readRecoveryFailure(f.runId, { ...dispatch, owner }),
      null,
    );
    assert.equal(
      (await readdir(f.created.directoryPath)).some((name) =>
        name.includes(dispatch.id),
      ),
      false,
    );
    const complete = await f.child.recordRecoveryFailure(
      f.runId,
      dispatch,
      failure(),
    );
    assert.deepEqual(
      await f.store.readRecoveryFailure(f.runId, { ...dispatch, owner }),
      complete,
    );
  }
  // Reproduce process loss after the exclusive link, before temporary cleanup.
  const dispatch = { ...f.dispatch, id: randomUUID() };
  const complete = await f.child.recordRecoveryFailure(
    f.runId,
    dispatch,
    failure(),
  );
  const path = f.failurePath(dispatch.id);
  const temporary = join(
    f.created.directoryPath,
    `..recovery-failure-${dispatch.id}.json.publish.202.${randomUUID()}.tmp`,
  );
  await rename(path, temporary);
  await link(temporary, path);
  assert.equal((await lstat(path)).nlink, 2);
  assert.deepEqual(
    await f.store.readRecoveryFailure(f.runId, { ...dispatch, owner }),
    complete,
  );
  assert.equal((await lstat(path)).nlink, 1);
  await assert.rejects(lstat(temporary), { code: "ENOENT" });
  assert.equal(f.action.record.status, "intent");
  assert.deepEqual(await f.store.loadRun(f.runId), f.created.state);
});

test("stores only bounded allowlisted facts and rejects altered diagnostic shapes", async (t) => {
  const f = await fixture(t);
  const diagnostic = await f.child.recordRecoveryFailure(f.runId, f.dispatch, {
    stage: "state-recovery",
    error: {
      code: "ERR_PRIVATE_UNRECOGNIZED",
      message: "Discarded message.",
      stderr: "Discarded output.",
    },
  });
  assert.equal(diagnostic.code, null);
  assert.equal(diagnostic.explanation, "The recovery cause is unavailable.");
  const source = await readFile(f.failurePath(), "utf8");
  assert.ok(Buffer.byteLength(source) <= 4_096);
  assert.doesNotMatch(
    source,
    /Discarded|PRIVATE_UNRECOGNIZED|"(?:message|stderr|stack|cause)":/u,
  );
  for (const invalid of [
    { ...failure(), stage: "arbitrary text" },
    { ...failure(), exitCode: 1 },
    { ...failure(), signal: "SIGTERM" },
    { ...failure(), explanation: "arbitrary text" },
  ]) {
    await assert.rejects(
      f.child.recordRecoveryFailure(
        f.runId,
        { ...f.dispatch, id: randomUUID() },
        invalid,
      ),
      { code: "ERR_INVALID_RECOVERY_FAILURE" },
    );
  }
  for (const altered of [
    "{",
    "x".repeat(4_097),
    JSON.stringify({ ...diagnostic, explanation: "Discarded text." }),
    JSON.stringify({ ...diagnostic, code: "ERR_PRIVATE_UNRECOGNIZED" }),
    JSON.stringify({ ...diagnostic, stderr: "Discarded output." }),
  ]) {
    await writeFile(f.failurePath(), altered);
    await assert.rejects(
      f.store.readRecoveryFailure(f.runId, { ...f.dispatch, owner }),
      { code: "ERR_INVALID_RECOVERY_FAILURE" },
    );
  }
  // A sparse oversized sidecar must be rejected before whole-file allocation.
  await truncate(f.failurePath(), 2 ** 32);
  await assert.rejects(
    f.store.readRecoveryFailure(f.runId, { ...f.dispatch, owner }),
    { code: "ERR_INVALID_RECOVERY_FAILURE" },
  );
  await assert.rejects(
    f.child.recordRecoveryFailure(f.runId, f.dispatch, {
      stage: "state-recovery",
      error: null,
    }),
    { code: "ERR_INVALID_RECOVERY_FAILURE" },
  );
  await assert.rejects(
    f.store.writeRunArtifact(
      f.created.lease,
      `.recovery-failure-${randomUUID()}.json`,
      source,
    ),
    { code: "ERR_UNSAFE_RUN_ARTIFACT_PATH" },
  );
});
