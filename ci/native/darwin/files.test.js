import assert from "node:assert/strict";
import test from "node:test";
import { digest } from "./protocol.js";
import {
  encodeDarwinFileRequest,
  normalizeDarwinFileIdentity,
  normalizeDarwinFileState,
  runDarwinFileTransaction,
  normalizeDarwinFileInput,
  runDarwinFileSession,
} from "./index.js";

const HASH = "a".repeat(64),
  NONCE = "b".repeat(32),
  CANDIDATE = "c".repeat(40);
const id = (inode) => `1:2:3:${inode}:100:0:${"d".repeat(32)}`;
const state = (overrides = {}) => ({
  base: id(1),
  root: id(2),
  allocation: id(3),
  leaf: null,
  temporary: null,
  alias: false,
  ...overrides,
});
const identity = (pid) => ({
  pid,
  pidVersion: 1,
  uid: 0,
  gid: 0,
  ruid: 0,
  rgid: 0,
  svuid: 0,
  svgid: 0,
  auid: 0,
  asid: 0,
  startSeconds: 100,
  startMicroseconds: pid,
});
const operation = (type, held = state(), bytes = "") => ({
  type,
  allocation: held.allocation,
  leaf: held.leaf,
  temporary: held.temporary,
  bytes,
});
const message = (phase, held) => ({ nonce: NONCE, phase, ...held });
const verify = async (value, request) => ({
  independent: true,
  receiptSha256: HASH,
  stateSha256: digest(
    JSON.stringify(
      state(
        Object.fromEntries(
          ["base", "root", "allocation", "leaf", "temporary", "alias"].map(
            (key) => [key, value[key]],
          ),
        ),
      ),
    ),
  ),
  leafSha256: digest(Buffer.from(request.bytes, "hex")),
  temporarySha256: digest(Buffer.from(request.bytes, "hex")),
});

test("Darwin file authority rejects foreign volume, hardlink aliases and path/name extensions", () => {
  assert.equal(normalizeDarwinFileIdentity(id(4)), id(4));
  for (const value of [
    id(4).replace(":100:0:", ":100:1000000000:"),
    id(4).replace(/d/gu, "0"),
    "../value",
    id(4) + ":extra",
  ])
    assert.throws(() => normalizeDarwinFileIdentity(value));
  assert.throws(() =>
    normalizeDarwinFileState(state({ leaf: id(4), temporary: id(4) })),
  );
  assert.throws(() =>
    normalizeDarwinFileState(state({ leaf: id(4).replace(/^1:/u, "5:") })),
  );
  assert.throws(() =>
    encodeDarwinFileRequest({ ...operation("publish"), name: "Value" }),
  );
  assert.throws(() =>
    encodeDarwinFileRequest({ ...operation("publish"), bytes: "00\ncleanup" }),
  );
});

function publication({ interrupt = null, substitute = null } = {}) {
  const prepared = state({ temporary: id(4) }),
    linked = state({ leaf: id(4), temporary: id(4), alias: true }),
    published = state({ leaf: id(4) });
  const replies = [
    message("prepared", prepared),
    message("linked", linked),
    message("published", published),
    message("complete", published),
  ];
  if (substitute)
    replies.find((value) => value.phase === substitute).leaf = id(5);
  const sent = [],
    records = [];
  return {
    sent,
    records,
    effects: {
      nonce: NONCE,
      state: state(),
      send: async (value) => sent.push(value),
      receive: async () => replies.shift(),
      verify,
      persist: async (kind, value) => records.push({ kind, value }),
      barrier: async (value) =>
        value.phase === interrupt ? "interrupt" : "continue",
    },
  };
}
test("Darwin link publication accounts for its sole temporary alias before single-link completion", async () => {
  const f = publication(),
    result = await runDarwinFileTransaction(
      operation("publish", state(), "00ff"),
      f.effects,
    );
  assert.equal(result.status, "OBSERVED");
  assert.equal(result.state.leaf, id(4));
  assert.equal(result.state.temporary, null);
  assert.equal(result.state.alias, false);
  assert.deepEqual(f.sent, [
    `publish ${id(3)} - - 00ff\n`,
    ...Array(3).fill("continue - - - -\n"),
  ]);
  assert.deepEqual(
    f.records.map((record) => record.kind),
    ["intent", "barrier", "barrier", "barrier", "acknowledgement"],
  );
});
test("Darwin interruption retains prepared/linked/published authority and rejects a substituted leaf", async () => {
  for (const phase of ["prepared", "linked", "published"]) {
    const f = publication({ interrupt: phase });
    f.effects.barrier = async (value) => {
      value.leaf = id(99);
      return value.phase === phase ? "interrupt" : "continue";
    };
    const result = await runDarwinFileTransaction(
      operation("publish"),
      f.effects,
    );
    assert.equal(result.status, "INTERRUPTED");
    assert.equal(result.reservation, "RETAINED");
    assert.notEqual(result.state.leaf, id(99));
    assert.equal(f.records.at(-1).kind, "interruption");
    assert.equal(result.state.alias, phase === "linked");
  }
  const f = publication({ substitute: "published" });
  assert.equal(
    (await runDarwinFileTransaction(operation("publish"), f.effects)).status,
    "FAIL",
  );
  const bytes = publication();
  bytes.effects.verify = async (...args) => ({
    ...(await verify(...args)),
    temporarySha256: HASH,
  });
  const rejected = await runDarwinFileTransaction(
    operation("publish"),
    bytes.effects,
  );
  assert.equal(rejected.status, "FAIL");
  assert.deepEqual(
    rejected.state,
    state(),
    "Unverified identities must not become recovery authority",
  );
  assert.equal(
    bytes.sent.length,
    1,
    "Unverified bytes must prevent the publication continuation",
  );
});
test("Darwin replacement binds the prepared file and exclusive losers retain the existing winner", async () => {
  for (const type of ["replace", "publish"]) {
    const held = state({ leaf: id(4) }),
      prepared = state({ leaf: id(4), temporary: id(5) }),
      published = state({ leaf: id(5) });
    const replies =
      type === "replace"
        ? [
            message("prepared", prepared),
            message("published", published),
            message("complete", published),
          ]
        : [message("prepared", prepared), message("exists", held)];
    const result = await runDarwinFileTransaction(operation(type, held, "ff"), {
      nonce: NONCE,
      state: held,
      send: async () => {},
      receive: async () => replies.shift(),
      verify,
      persist: async () => {},
      barrier: async () => "continue",
    });
    assert.equal(result.status, "OBSERVED");
    assert.deepEqual(result.state, type === "replace" ? published : held);
  }
});
test("Darwin cleanup sends no removal without fresh independent retirement authorization", async () => {
  const sent = [],
    held = state({ leaf: id(4) }),
    replies = [
      message("removing", held),
      message("removed", state({ allocation: null })),
    ];
  const effects = {
    nonce: NONCE,
    state: held,
    send: async (value) => sent.push(value),
    receive: async () => replies.shift(),
    verify,
    persist: async () => {},
    barrier: async () => "continue",
  };
  assert.equal(
    (await runDarwinFileTransaction(operation("cleanup", held), effects))
      .status,
    "FAIL",
  );
  assert.deepEqual(sent, []);
  effects.authorizeCleanup = async (value) => ({
    independent: true,
    retired: true,
    stateSha256: digest(JSON.stringify(value)),
    receiptSha256: HASH,
  });
  const result = await runDarwinFileTransaction(
    operation("cleanup", held),
    effects,
  );
  assert.equal(result.status, "OBSERVED");
  assert.equal(result.state.allocation, null);
});

function fixture() {
  const input = normalizeDarwinFileInput({
    request: {
      schemaVersion: 1,
      candidateSha: CANDIDATE,
      nonce: NONCE,
      uid: 90001,
      gid: 90002,
      custody: "/fixture/custody",
      storage: "/fixture/storage",
      workspace: "/fixture/storage/work",
      launcher: { path: "/fixture/custody/launcher", sha256: HASH },
      executable: {
        path: "/fixture/storage/helper",
        sha256: HASH,
        cdhash: "e".repeat(40),
      },
      policy: { path: "/fixture/custody/policy", sha256: HASH },
      bindings: { system: HASH, source: HASH, closure: HASH, policy: HASH },
    },
    base: id(1),
    root: id(2),
    reviewSha256: HASH,
  });
  const requestSha256 = digest(JSON.stringify(input));
  const admitted = {
    requestSha256,
    independent: true,
    soleParentAuthority: true,
    helper: identity(20),
    verifier: identity(21),
    helperSha256: HASH,
    cdhash: "e".repeat(40),
    closureSha256: HASH,
    reviewSha256: HASH,
    base: id(1),
    root: id(2),
    receiptSha256: HASH,
  };
  const prior = {
    requestSha256,
    independent: true,
    candidateSha: CANDIDATE,
    nonce: NONCE,
    receiptSha256: HASH,
    operation: "publish",
    status: "INTERRUPTED",
    state: state({ leaf: id(4), temporary: id(4), alias: true }),
    admission: admitted,
  };
  prior.stateSha256 = digest(JSON.stringify(prior.state));
  let opened = 0;
  const sent = [];
  const replies = [
    message("recovered", prior.state),
    message("removing", prior.state),
    message("removed", state({ allocation: null })),
    message("finished", state({ allocation: null })),
  ];
  const effects = {
    persist: async () => {},
    review: async () => ({ approvedSha256: requestSha256, reviewSha256: HASH }),
    readRecovery: async () => prior,
    verifyRetirement: async () => ({
      independent: true,
      noLiveUid: true,
      uid: 90001,
      helpersSettled: true,
      requestSha256,
      recoverySha256: HASH,
      helper: identity(20),
      verifier: identity(30),
      receiptSha256: HASH,
    }),
    open: async () => {
      opened++;
      return {
        admission: { ...admitted, helper: identity(40) },
        send: async (value) => sent.push(value),
        receive: async () => replies.shift(),
        close: () => {},
        dispose: () => {},
        completion: Promise.resolve({
          code: 0,
          signal: null,
          failed: false,
          remainingMessages: 0,
          partialBytes: 0,
        }),
      };
    },
    verify,
    barrier: async () => "continue",
    retire: async (_, record) => ({
      independent: true,
      helpersSettled: true,
      helper: record.admission.helper,
      verifier: identity(50),
      requestSha256,
      receiptSha256: HASH,
    }),
  };
  return { input, effects, sent, opened: () => opened };
}
test("Darwin recovery reads protected receipts and refuses live or stale helper retirement before reopening", async () => {
  for (const failure of [null, "live", "stale", "receipt", "self"]) {
    const f = fixture(),
      verifyRetirement = f.effects.verifyRetirement,
      readRecovery = f.effects.readRecovery;
    if (failure === "live")
      f.effects.verifyRetirement = async () => ({
        ...(await verifyRetirement()),
        noLiveUid: false,
      });
    if (failure === "stale")
      f.effects.verifyRetirement = async () => ({
        ...(await verifyRetirement()),
        helper: { ...identity(20), pidVersion: 2 },
      });
    if (failure === "receipt")
      f.effects.readRecovery = async () => ({
        ...(await readRecovery()),
        stateSha256: "f".repeat(64),
      });
    if (failure === "self") {
      let calls = 0;
      f.effects.verifyRetirement = async () => ({
        ...(await verifyRetirement()),
        verifier: identity(++calls === 1 ? 30 : 40),
      });
    }
    const result = await runDarwinFileSession(
      f.input,
      [
        { type: "cleanup", bytes: "" },
        { type: "finish", bytes: "" },
      ],
      f.effects,
      { recovery: HASH, now: () => 0 },
    );
    assert.equal(result.status, failure ? "FAIL" : "OBSERVED", failure);
    assert.equal(f.opened(), failure && failure !== "self" ? 0 : 1);
    if (failure === "self")
      assert.equal(
        f.sent.some((command) => command.startsWith("cleanup ")),
        false,
      );
    assert.equal(result.reservation, "RETAINED");
  }
  const f = fixture(),
    sparse = Array(2);
  sparse[1] = { type: "finish", bytes: "" };
  await assert.rejects(runDarwinFileSession(f.input, sparse, f.effects));
  assert.equal(f.opened(), 0);
  f.effects.review = async () => ({
    missingInputs: ["darwin-files-sdk-volume-contract"],
  });
  const missing = await runDarwinFileSession(
    f.input,
    [{ type: "finish", bytes: "" }],
    f.effects,
  );
  assert.equal(missing.status, "BLOCKED");
  assert.equal(f.opened(), 0);
  assert.deepEqual(missing.missingInputs, ["darwin-files-sdk-volume-contract"]);
});
test("Darwin declared interruption cannot hide a deadline or malformed helper settlement", async () => {
  for (const fault of [null, "deadline", "queued", "partial", "transport"]) {
    const f = fixture(),
      open = f.effects.open;
    f.effects.barrier = async () => "interrupt";
    f.effects.open = async () => ({
      ...(await open()),
      completion: Promise.resolve({
        code: fault === "deadline" ? 124 : 126,
        signal: null,
        failed: fault === "transport",
        remainingMessages: fault === "queued" ? 1 : 0,
        partialBytes: fault === "partial" ? 1 : 0,
      }),
    });
    const result = await runDarwinFileSession(
      f.input,
      [
        { type: "cleanup", bytes: "" },
        { type: "finish", bytes: "" },
      ],
      f.effects,
      { recovery: HASH, now: () => 0 },
    );
    assert.equal(result.status, fault ? "FAIL" : "INTERRUPTED", fault);
    assert.equal(result.reservation, "RETAINED");
  }
});
