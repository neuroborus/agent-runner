import assert from "node:assert/strict";
import test from "node:test";

import { digest } from "./protocol.js";
import {
  normalizeWindowsFileIdentity,
  normalizeWindowsFileState,
  encodeWindowsFileRequest,
  normalizeWindowsFileInput,
  windowsFileHelperArguments,
  runWindowsFileTransaction,
  runWindowsFileSession,
  normalizeWindowsFileRecovery,
} from "./index.js";

const HASH = "a".repeat(64),
  NONCE = "b".repeat(32);
const id = (number) => `0000000000000001:${String(number).padStart(32, "0")}`;
const state = (extra = {}) => ({
  base: id(1),
  root: id(2),
  allocation: id(3),
  leaf: null,
  temporary: null,
  alias: false,
  ...extra,
});
const message = (phase, held) => ({ nonce: NONCE, phase, ...held });
const operation = (type, held = state(), bytes = "") => ({
  type,
  allocation: held.allocation,
  leaf: held.leaf,
  temporary: held.temporary,
  bytes,
});
const input = () => ({
  request: {
    schemaVersion: 1,
    candidateSha: "c".repeat(40),
    nonce: NONCE,
    restrictingSid: "S-1-5-21-1-2-3-4",
    custody: "C:\\NativeProof\\custody",
    storage: "C:\\NativeProof\\storage",
    workspace: "C:\\NativeProof\\storage\\workspace",
    launcher: {
      path: "C:\\NativeProof\\custody\\launcher.exe",
      sha256: HASH,
      signatureSha256: HASH,
    },
    executable: {
      path: "C:\\NativeProof\\storage\\file-helper.exe",
      sha256: HASH,
      signatureSha256: HASH,
      parser: "msvc-ucrt-wmain-v1",
    },
    policy: { path: "C:\\NativeProof\\custody\\policy.json", sha256: HASH },
    bindings: { system: HASH, source: HASH, closure: HASH, policy: HASH },
  },
  base: id(1),
  root: id(2),
  reviewSha256: HASH,
});
const helperIdentity = {
  pid: 100,
  creationTime: "1",
  sessionId: 0,
  userSid: "S-1-5-18",
};
const admission = (value, helper = helperIdentity) => ({
  independent: true,
  helper,
  verifier: { ...helper, pid: 200 },
  requestSha256: digest(JSON.stringify(value)),
  reviewSha256: HASH,
  sourceSha256: HASH,
  helperSha256: HASH,
  signatureSha256: HASH,
  closureSha256: HASH,
  base: id(1),
  root: id(2),
  soleParentAuthority: true,
  privateParents: true,
  explicitHandleList: true,
  inheritedHandleCount: 4,
  windows2025X64: true,
  receiptSha256: HASH,
});
const review = (value) => ({
  independent: true,
  approvedSha256: digest(JSON.stringify(value)),
  reviewSha256: HASH,
  sourceSha256: HASH,
  windows2025X64: true,
  sdkAndLoaderVerified: true,
  ntfsSemanticsVerified: true,
  soleParentAuthorityVerified: true,
});
const evidence = (reply, request) => ({
  independent: true,
  stateSha256: digest(
    JSON.stringify(
      state(
        Object.fromEntries(
          ["base", "root", "allocation", "leaf", "temporary", "alias"].map(
            (key) => [key, reply[key]],
          ),
        ),
      ),
    ),
  ),
  receiptSha256: HASH,
  temporarySha256: digest(Buffer.from(request.bytes, "hex")),
  leafSha256: digest(Buffer.from(request.bytes, "hex")),
});

test("Windows file authority rejects foreign volume, identity aliases and caller paths", () => {
  assert.equal(normalizeWindowsFileIdentity(id(4)), id(4));
  for (const value of [
    "0".repeat(16) + ":" + "1".repeat(32),
    id(4) + ":extra",
    "../value",
  ])
    assert.throws(() => normalizeWindowsFileIdentity(value));
  for (const extra of [
    { leaf: id(4), temporary: id(4) },
    { leaf: id(4).replace(/^0/u, "1") },
    { allocation: id(1) },
  ])
    assert.throws(() => normalizeWindowsFileState(state(extra)));
  assert.throws(() =>
    encodeWindowsFileRequest({ ...operation("publish"), name: "value:stream" }),
  );
  assert.throws(() =>
    encodeWindowsFileRequest(operation("publish", state(), "00\ncleanup")),
  );
  for (const path of [
    "\\\\server\\share",
    "\\\\?\\C:\\NativeProof",
    "C:\\NativeProof:stream",
  ])
    assert.throws(() =>
      normalizeWindowsFileInput({
        ...input(),
        request: { ...input().request, custody: path },
      }),
    );
  assert.deepEqual(
    windowsFileHelperArguments(input(), { root: "12", base: "16" }),
    [NONCE, "12", "16", id(2), id(1)],
  );
  for (const handles of [
    { root: "12", base: "12" },
    { root: "012", base: "16" },
    { root: "18446744073709551615", base: "16" },
  ])
    assert.throws(() => windowsFileHelperArguments(input(), handles));
});

function publication({ interrupt = null, change = null } = {}) {
  const prepared = state({ temporary: id(4) }),
    linked = state({ leaf: id(4), temporary: id(4), alias: true }),
    published = state({ leaf: id(4) });
  const replies = [
    message("prepared", prepared),
    message("linked", linked),
    message("published", published),
    message("complete", published),
  ];
  if (change) change(replies);
  const events = [],
    sent = [];
  return {
    events,
    sent,
    effects: {
      nonce: NONCE,
      state: state(),
      send: async (value) => {
        sent.push(value);
        events.push("send");
      },
      receive: async () => replies.shift(),
      verify: async (reply, request) => evidence(reply, request),
      persist: async (kind) => events.push(kind),
      barrier: async (reply) =>
        reply.phase === interrupt ? "interrupt" : "continue",
    },
  };
}
test("Windows publication binds its sole temporary alias and persists barriers before continuations", async () => {
  const fixture = publication();
  const result = await runWindowsFileTransaction(
    operation("publish", state(), "00ff"),
    fixture.effects,
  );
  assert.equal(result.status, "OBSERVED");
  assert.deepEqual(result.state, state({ leaf: id(4) }));
  assert.equal(result.reservation, "RETAINED");
  assert.deepEqual(fixture.events, [
    "intent",
    "send",
    "barrier",
    "send",
    "barrier",
    "send",
    "barrier",
    "send",
    "acknowledgement",
  ]);
  for (const change of [
    (replies) => {
      replies[1].alias = false;
    },
    (replies) => {
      replies[2].leaf = id(5);
    },
  ]) {
    const rejected = publication({ change });
    assert.equal(
      (await runWindowsFileTransaction(operation("publish"), rejected.effects))
        .status,
      "FAIL",
    );
  }
});
test("Declared publication interruption retains the recorded two-link identity without acknowledgement", async () => {
  const fixture = publication({ interrupt: "linked" });
  const result = await runWindowsFileTransaction(
    operation("publish"),
    fixture.effects,
  );
  assert.equal(result.status, "INTERRUPTED");
  assert.equal(result.state.alias, true);
  assert.equal(fixture.sent.length, 2);
  assert.equal(fixture.events.at(-1), "interruption");
});
test("Cleanup rechecks retired authority after the removal fault barrier", async () => {
  for (const failure of ["retirement", "persistence"]) {
    const held = state({ leaf: id(4) }),
      sent = [],
      events = [];
    let reads = 0,
      authorizations = 0,
      received = 0;
    const result = await runWindowsFileTransaction(operation("cleanup", held), {
      nonce: NONCE,
      state: held,
      send: async (value) => sent.push(value),
      receive: async () =>
        ++received === 1
          ? message("removing", held)
          : message("removed", state({ allocation: null })),
      verify: async (reply, request) => evidence(reply, request),
      persist: async (kind, value) => {
        if (kind === "authorization") {
          assert.equal(value.authorization.receiptSha256, HASH);
          if (++authorizations === 2 && failure === "persistence")
            throw new Error("Authorization was not persisted");
        }
        events.push(kind);
      },
      barrier: async () => "continue",
      authorizeCleanup: async (current) => ({
        independent: true,
        retired: ++reads === 1 || failure !== "retirement",
        stateSha256: digest(JSON.stringify(current)),
        receiptSha256: HASH,
      }),
    });
    assert.equal(result.status, "FAIL");
    assert.equal(reads, 2);
    assert.equal(sent.length, 1);
    assert.deepEqual(events, ["authorization", "intent", "barrier"]);
  }
});
test("Recovery admits recorded publication progress but rejects lost objects and foreign identities", async () => {
  const held = state({ temporary: id(4) });
  for (const [recovered, expected] of [
    [held, "OBSERVED"],
    [state({ leaf: id(4), temporary: id(4), alias: true }), "OBSERVED"],
    [state({ leaf: id(4) }), "OBSERVED"],
    [state(), "FAIL"],
    [state({ leaf: id(5) }), "FAIL"],
    [state({ allocation: null }), "FAIL"],
  ]) {
    const result = await runWindowsFileTransaction(operation("recover", held), {
      nonce: NONCE,
      state: state({ allocation: null }),
      recoveryOperation: "publish",
      send: async () => {},
      receive: async () => message("recovered", recovered),
      verify: async (reply, request) => evidence(reply, request),
      persist: async () => {},
      barrier: async () => "continue",
    });
    assert.equal(result.status, expected);
  }
});
test("A session preserves independent admission and observations; incomplete settlement cannot succeed", async () => {
  const value = normalizeWindowsFileInput(input()),
    requestSha256 = digest(JSON.stringify(value));
  const helper = {
    pid: 100,
    creationTime: "1",
    sessionId: 0,
    userSid: "S-1-5-18",
  };
  for (const partialBytes of [0, 1]) {
    const replies = [
      message("ready", state({ allocation: null })),
      message("allocated", state()),
      message("finished", state()),
    ];
    const records = [],
      sent = [];
    const result = await runWindowsFileSession(
      value,
      [{ type: "allocate", bytes: "" }],
      {
        persist: async (record) => records.push(record),
        review: async () => review(value),
        open: async () => ({
          helper,
          receive: async () => replies.shift(),
          send: async (line) => {
            assert.equal(records.at(-1).phase, "transactions");
            sent.push(line);
          },
          close() {},
          dispose() {},
          completion: Promise.resolve({
            code: 0,
            signal: null,
            failed: false,
            partialBytes,
            remainingMessages: 0,
          }),
        }),
        admit: async () => admission(value, helper),
        verify: async (reply, request) => evidence(reply, request),
        barrier: async () => "continue",
        retire: async () => ({
          independent: true,
          helpersSettled: true,
          requestSha256,
          helper,
          verifier: { ...helper, pid: 200 },
          receiptSha256: HASH,
        }),
      },
    );
    assert.equal(result.status, partialBytes === 0 ? "OBSERVED" : "FAIL");
    assert.equal(result.reservation, "RETAINED");
    assert.equal(result.admission.receiptSha256, HASH);
    assert.equal(result.events.at(-1).observation.receiptSha256, HASH);
    assert.deepEqual(sent, [
      "start - - - -\n",
      "allocate - - - -\n",
      `finish ${id(3)} - - -\n`,
    ]);
  }
});
test("Protected recovery binds retained bytes and fresh retirement before opening", async () => {
  const value = normalizeWindowsFileInput(input()),
    requestSha256 = digest(JSON.stringify(value));
  const held = state({ leaf: id(4) }),
    stateSha256 = digest(JSON.stringify(held));
  const prior = {
    independent: true,
    immutable: true,
    protectedDacl: true,
    heldIdentitiesRetained: true,
    requestSha256,
    candidateSha: value.request.candidateSha,
    nonce: NONCE,
    receiptSha256: HASH,
    sourceSha256: HASH,
    status: "OBSERVED",
    operation: "finish",
    state: held,
    stateSha256,
    helper: helperIdentity,
    admission: admission(value),
    observation: {
      stateSha256,
      receiptSha256: HASH,
      leafSha256: digest(Buffer.from("00", "hex")),
      temporarySha256: null,
    },
  };
  assert.throws(() =>
    normalizeWindowsFileRecovery({ ...prior, observation: undefined }, value),
  );
  for (const [bytes, retirementStateSha256] of [
    ["00", stateSha256],
    ["01", stateSha256],
    ["00", HASH],
  ]) {
    const helper = { ...helperIdentity, pid: 101, creationTime: "2" },
      sent = [];
    const replies = [
      message("ready", state({ allocation: null })),
      message("recovered", held),
      message("finished", held),
    ];
    let retirementReads = 0;
    const result = await runWindowsFileSession(
      value,
      [{ type: "finish", bytes: "" }],
      {
        persist: async () => {},
        review: async () => review(value),
        readRecovery: async () => prior,
        verifyRetirement: async (_input, _prior, current) => {
          retirementReads++;
          assert.deepEqual(current, held);
          return {
            independent: true,
            noLiveMembers: true,
            admissionsClosed: true,
            helpersSettled: true,
            sameHeldObjects: true,
            stateSha256: retirementStateSha256,
            requestSha256,
            recoverySha256: HASH,
            restrictingSid: value.request.restrictingSid,
            helper: helperIdentity,
            verifier: { ...helperIdentity, pid: 200 },
            receiptSha256: HASH,
          };
        },
        open: async () => {
          assert.equal(retirementReads, 1);
          return {
            helper,
            receive: async () => replies.shift(),
            send: async (line) => sent.push(line),
            close() {},
            dispose() {},
            completion: Promise.resolve({
              code: 0,
              signal: null,
              failed: false,
              partialBytes: 0,
              remainingMessages: 0,
            }),
          };
        },
        admit: async () => admission(value, helper),
        verify: async (reply, request) => ({
          ...evidence(reply, request),
          leafSha256: digest(Buffer.from(bytes, "hex")),
        }),
        barrier: async () => "continue",
        retire: async () => ({
          independent: true,
          helpersSettled: true,
          requestSha256,
          helper,
          verifier: { ...helperIdentity, pid: 200 },
          receiptSha256: HASH,
        }),
      },
      { recovery: HASH },
    );
    const valid = bytes === "00" && retirementStateSha256 === stateSha256;
    assert.equal(result.status, valid ? "OBSERVED" : "FAIL");
    assert.equal(
      sent.some((line) => line.startsWith("finish ")),
      valid,
    );
    assert.equal(result.reservation, "RETAINED");
  }
});
test("Elapsed session deadlines fence start before callbacks even when the timer has not fired", async () => {
  const value = normalizeWindowsFileInput(input()),
    requestSha256 = digest(JSON.stringify(value));
  const sent = [],
    closed = [];
  let clock = 0,
    arm = false;
  const result = await runWindowsFileSession(
    value,
    [{ type: "finish", bytes: "" }],
    {
      persist: async (record) => {
        if (record.phase === "transactions") arm = true;
      },
      review: async () => review(value),
      open: async () => ({
        helper: helperIdentity,
        receive: async () => message("ready", state({ allocation: null })),
        send: async (line) => sent.push(line),
        close: () => closed.push(true),
        dispose() {},
        completion: Promise.resolve({
          code: 126,
          signal: null,
          failed: false,
          partialBytes: 0,
          remainingMessages: 0,
        }),
      }),
      admit: async () => admission(value),
      verify: async () => {},
      barrier: async () => "continue",
      retire: async () => ({
        independent: true,
        helpersSettled: true,
        requestSha256,
        helper: helperIdentity,
        verifier: { ...helperIdentity, pid: 200 },
        receiptSha256: HASH,
      }),
    },
    {
      now: () => {
        const current = clock;
        if (arm) {
          arm = false;
          clock = 30000;
        }
        return current;
      },
      schedule: () => 1,
      cancel() {},
    },
  );
  assert.equal(result.status, "FAIL");
  assert.equal(result.reservation, "RETAINED");
  assert.deepEqual(sent, []);
  assert.equal(closed.length, 1);
});
test("Missing native owners block before opening; failed admission never sends start and still retires", async () => {
  const value = normalizeWindowsFileInput(input()),
    requestSha256 = digest(JSON.stringify(value));
  const helper = {
    pid: 100,
    creationTime: "1",
    sessionId: 0,
    userSid: "S-1-5-18",
  };
  const records = [],
    sent = [];
  let opened = 0,
    retired = 0;
  const blocked = await runWindowsFileSession(
    value,
    [{ type: "allocate", bytes: "" }],
    {
      persist: async (record) => records.push(record),
      open: async () => {
        opened++;
      },
    },
  );
  assert.equal(blocked.status, "BLOCKED");
  assert.equal(opened, 0);
  const effects = {
    persist: async (record) => records.push(record),
    review: async () => review(value),
    open: async () => {
      opened++;
      assert.equal(records.at(-1).phase, "possible-admission");
      return {
        helper,
        receive: async () => message("ready", state({ allocation: null })),
        send: async (value) => sent.push(value),
        close() {},
        dispose() {},
        completion: Promise.resolve({
          code: 126,
          signal: null,
          failed: false,
          partialBytes: 0,
          remainingMessages: 0,
        }),
      };
    },
    admit: async () => {
      throw new Error("Independent helper binding mismatch");
    },
    verify: async () => {},
    barrier: async () => "continue",
    retire: async () => {
      retired++;
      return {
        independent: true,
        helpersSettled: true,
        requestSha256,
        helper,
        verifier: { ...helper, pid: 200 },
        receiptSha256: HASH,
      };
    },
  };
  const unsupported = await runWindowsFileSession(
    value,
    [{ type: "allocate", bytes: "" }],
    {
      ...effects,
      review: async () => ({ ...review(value), windows2025X64: false }),
    },
  );
  assert.equal(unsupported.status, "FAIL");
  assert.equal(opened, 0);
  assert.equal(retired, 0);
  const result = await runWindowsFileSession(
    value,
    [{ type: "allocate", bytes: "" }],
    effects,
  );
  assert.equal(result.status, "FAIL");
  assert.equal(retired, 1);
  assert.deepEqual(sent, []);
  assert.equal(result.reservation, "RETAINED");
});
