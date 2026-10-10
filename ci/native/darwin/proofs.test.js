import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { darwinFileChannel, darwinFixedGitChannel } from "./channel.js";
import {
  FIXED_SUBJECT,
  validateCommitRequest,
  validateCommitEffect,
} from "../index.js";
import {
  validateCommitRequest as legacyRequest,
  validateCommitEffect as legacyEffect,
} from "../linux/index.js";
import { digest } from "./protocol.js";
import { normalizeDarwinFileInput } from "./files.js";
import {
  DARWIN_FILE_CASE_IDS,
  assertDarwinFileObservation,
  assertDarwinFileDenial,
  assertDarwinReplacementReads,
  runDarwinFileCase,
} from "./files-cases.js";
import {
  normalizeDarwinGitInput,
  darwinFixedCommitArguments,
  darwinOrdinaryGitArguments,
  assertDarwinCommitObservation,
  assertDarwinOrdinaryGitObservation,
  runDarwinGitCase,
} from "./git.js";

const HASH = "a".repeat(64),
  NONCE = "b".repeat(32),
  SHA = "c".repeat(40);
const OLD = "006f6c64ff",
  NEW = "006e657700ff";
const id = (inode) => `1:2:3:${inode}:100:0:${"d".repeat(32)}`;
const identity = (pid) => ({
  pid,
  pidVersion: 1,
  asid: 0,
  auid: 0,
  uid: 0,
  ruid: 0,
  svuid: 0,
  gid: 0,
  rgid: 0,
  svgid: 0,
  startSeconds: 100,
  startMicroseconds: pid,
});
const request = {
  schemaVersion: 1,
  candidateSha: SHA,
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
};
const input = normalizeDarwinFileInput({
  request,
  base: id(1),
  root: id(2),
  reviewSha256: HASH,
});
const state = (overrides = {}) => ({
  base: id(1),
  root: id(2),
  allocation: id(3),
  leaf: null,
  temporary: null,
  alias: false,
  ...overrides,
});
const message = (phase, held) => ({ nonce: NONCE, phase, ...held });
function view(value, contents) {
  return {
    independent: true,
    verifier: identity(10),
    parentAuthority: true,
    candidateSha: SHA,
    nonce: NONCE,
    requestSha256: digest(JSON.stringify(input)),
    policySha256: HASH,
    nativeEventSha256: HASH,
    receiptSha256: HASH,
    outsideBeforeSha256: HASH,
    outsideAfterSha256: HASH,
    timedOut: false,
    objects: Object.fromEntries(
      ["base", "root", "allocation", "leaf", "temporary"].map((key) => {
        const directory = !["leaf", "temporary"].includes(key),
          native = value[key];
        return [
          key,
          native === null
            ? null
            : {
                identity: native,
                namedIdentity: native,
                uid: 0,
                gid: 0,
                kind: directory ? "directory" : "file",
                mode: directory ? 0o700 : 0o600,
                links: value.alias ? 2 : 1,
                bytes: directory ? null : contents.get(native),
              },
        ];
      }),
    ),
  };
}
test("Darwin file proof requires independent native identities, exact bytes and the sole known link alias", () => {
  const value = message(
    "linked",
    state({ leaf: id(4), temporary: id(4), alias: true }),
  );
  const original = view(value, new Map([[id(4), OLD]]));
  assert.equal(
    assertDarwinFileObservation(value, original, input, {
      leaf: OLD,
      temporary: OLD,
    }).pid,
    10,
  );
  for (const mutate of [
    (entry) => {
      entry.objects.leaf.links = 1;
    },
    (entry) => {
      entry.objects.leaf.bytes = NEW;
    },
    (entry) => {
      entry.objects.root.namedIdentity = id(9);
    },
    (entry) => {
      entry.outsideAfterSha256 = "f".repeat(64);
    },
    (entry) => {
      entry.timedOut = true;
    },
  ]) {
    const broken = structuredClone(original);
    mutate(broken);
    assert.throws(() =>
      assertDarwinFileObservation(value, broken, input, {
        leaf: OLD,
        temporary: OLD,
      }),
    );
  }
});
test("Darwin controlled rejection cannot use exit status alone or hide a changed substitute", () => {
  const barrier = message("prepared", state({ leaf: id(4), temporary: id(5) }));
  const object = { identity: id(4), bytes: OLD, links: 1, kind: "file" };
  const applied = {
    object: { identity: id(6), bytes: NEW, links: 1, kind: "file" },
    saved: object,
    othersSha256: HASH,
  };
  const evidence = {
    independent: true,
    verifier: identity(10),
    control: "leaf",
    attempted: true,
    ready: true,
    reachable: true,
    continued: true,
    timedOut: false,
    exitCode: 126,
    signal: null,
    candidateSha: SHA,
    nonce: NONCE,
    requestSha256: digest(JSON.stringify(input)),
    barrierSha256: digest(JSON.stringify(barrier)),
    nativeEventSha256: HASH,
    receiptSha256: HASH,
    nativeDecision: "reject-identity",
    before: { object, othersSha256: HASH },
    applied,
    after: structuredClone(applied),
    outsideBeforeSha256: HASH,
    outsideAfterSha256: HASH,
  };
  assert.equal(assertDarwinFileDenial("leaf", barrier, evidence, input), true);
  for (const mutate of [
    (entry) => {
      entry.nativeEventSha256 = null;
    },
    (entry) => {
      entry.after.saved.bytes = NEW;
    },
    (entry) => {
      entry.ready = false;
    },
    (entry) => {
      entry.exitCode = 124;
    },
    (entry) => {
      entry.applied.othersSha256 = "f".repeat(64);
    },
  ]) {
    const broken = structuredClone(evidence);
    mutate(broken);
    assert.throws(() => assertDarwinFileDenial("leaf", barrier, broken, input));
  }
  const foreign = structuredClone(evidence);
  foreign.control = "cross-volume";
  foreign.nativeDecision = "reject-volume";
  foreign.before.object = {
    identity: barrier.allocation,
    kind: "directory",
    links: 2,
    bytes: null,
  };
  foreign.applied.saved = structuredClone(foreign.before.object);
  foreign.applied.object = {
    identity: `9:8:7:99:100:0:${"f".repeat(32)}`,
    kind: "directory",
    links: 2,
    bytes: null,
  };
  foreign.after = structuredClone(foreign.applied);
  assert.equal(
    assertDarwinFileDenial("cross-volume", barrier, foreign, input),
    true,
  );
  for (const mutate of [
    (entry) => {
      entry.applied.object.kind = "file";
    },
    (entry) => {
      entry.before.object.identity = barrier.leaf;
    },
    (entry) => {
      entry.applied.object.identity = id(9);
    },
  ]) {
    const broken = structuredClone(foreign);
    mutate(broken);
    assert.throws(() =>
      assertDarwinFileDenial("cross-volume", barrier, broken, input),
    );
  }
});
test("Darwin concurrent replacement requires complete old and new reads with no omitted or partial observations", () => {
  const value = {
    independent: true,
    verifier: identity(10),
    reader: identity(20),
    ready: true,
    overlapped: true,
    complete: true,
    dropped: false,
    timedOut: false,
    settled: true,
    candidateSha: SHA,
    nonce: NONCE,
    requestSha256: digest(JSON.stringify(input)),
    nativeEventSha256: HASH,
    receiptSha256: HASH,
    reads: [
      {
        code: "OK",
        links: 1,
        identity: id(4),
        bytes: OLD,
        nativeEventSha256: HASH,
      },
      {
        code: "OK",
        links: 1,
        identity: id(5),
        bytes: NEW,
        nativeEventSha256: HASH,
      },
    ],
  };
  assert.equal(
    assertDarwinReplacementReads(value, id(4), id(5), input).pid,
    20,
  );
  for (const mutate of [
    (entry) => {
      entry.reads[1].bytes = "00";
    },
    (entry) => {
      entry.reads[1].identity = id(6);
    },
    (entry) => {
      entry.dropped = true;
    },
    (entry) => {
      entry.overlapped = false;
    },
  ]) {
    const broken = structuredClone(value);
    mutate(broken);
    assert.throws(() =>
      assertDarwinReplacementReads(broken, id(4), id(5), input),
    );
  }
});
test("Every Darwin file case blocks before effects when its required native owners are absent", async () => {
  for (const checkId of DARWIN_FILE_CASE_IDS) {
    const result = await runDarwinFileCase(checkId, input, {
      persist: async () => {},
    });
    assert.equal(result.status, "BLOCKED");
    assert.equal(result.sessions.length, 0);
    assert.equal(result.reservation, "RETAINED");
    assert.ok(result.missingInputs.includes("darwin-file-case-observe"));
  }
});

function fileFixture({ publication = true } = {}) {
  let physical = state({ allocation: null }),
    serial = 3,
    helper = 100,
    phase,
    pendingOperation,
    readerActive = false;
  const contents = new Map(),
    receipts = new Map(),
    submitted = new Set();
  const requestSha256 = digest(JSON.stringify(input));
  const effects = {
    persist: async (record) => {
      if (record.kind === "concurrent-request") submitted.add(record.index);
    },
    observe: async (_, value) => view(value, contents),
    verifyRetirement: async (_, session) => {
      assert.equal(
        readerActive,
        false,
        "The concurrent reader settles before fresh retirement",
      );
      return {
        independent: true,
        noLiveUid: true,
        uid: request.uid,
        helpersSettled: true,
        requestSha256,
        helper: session.result.admission.helper,
        sessionReceiptSha256: session.receiptSha256,
        verifier: identity(30),
        receiptSha256: HASH,
      };
    },
    startReader: async (_, value) => {
      readerActive = true;
      return {
        independent: true,
        ready: true,
        identity: identity(50),
        verifier: identity(40),
        reviewSha256: HASH,
        requestSha256,
        receiptSha256: HASH,
        oldLeaf: value.leaf,
      };
    },
    finishReader: async (_, reader) => {
      readerActive = false;
      return {
        independent: true,
        ready: true,
        verifier: identity(40),
        reader: reader.identity,
        readerReceiptSha256: reader.receiptSha256,
        overlapped: true,
        complete: true,
        dropped: false,
        timedOut: false,
        settled: true,
        candidateSha: SHA,
        nonce: NONCE,
        requestSha256,
        nativeEventSha256: HASH,
        receiptSha256: HASH,
        reads: [reader.oldLeaf, physical.leaf].map((identity) => ({
          code: "OK",
          links: 1,
          identity,
          bytes: contents.get(identity),
          nativeEventSha256: HASH,
        })),
      };
    },
    startPublishers: async (_, value, requests) => ({
      independent: true,
      verifier: identity(40),
      ready: true,
      overlapped: true,
      requestSha256,
      reviewSha256: HASH,
      allocation: value.allocation,
      receiptSha256: HASH,
      nativeEventSha256: HASH,
      requests: requests.map((item, index) => ({
        ...item,
        identity: identity(50 + index),
        acknowledged: true,
        nativeEventSha256: HASH,
      })),
    }),
    finishPublishers: async (_, publishers, value) => ({
      independent: true,
      verifier: identity(40),
      complete: true,
      settled: true,
      timedOut: false,
      requestSha256,
      publishersReceiptSha256: publishers.receiptSha256,
      nativeEventSha256: HASH,
      receiptSha256: HASH,
      requests: publishers.requests.map((item, index) => ({
        ...item,
        leaf: value.leaf,
        outcome: index === 0 ? "complete" : "exists",
      })),
    }),
    fileEffects: async () => ({
      review: async () => ({
        approvedSha256: requestSha256,
        reviewSha256: HASH,
      }),
      persist: async (record) => {
        const recordSha256 = digest(JSON.stringify(record));
        receipts.set(recordSha256, structuredClone(record));
        return { immutable: true, recordSha256, receiptSha256: recordSha256 };
      },
      readRecovery: async (receiptSha256) => {
        const record = receipts.get(receiptSha256);
        return {
          ...record,
          independent: true,
          operation: record.events.at(-1).operation.type,
          receiptSha256,
          stateSha256: digest(JSON.stringify(record.state)),
        };
      },
      verifyRetirement: async (_, prior) => ({
        independent: true,
        noLiveUid: true,
        uid: request.uid,
        helpersSettled: true,
        requestSha256,
        recoverySha256: prior.receiptSha256,
        helper: prior.admission.helper,
        verifier: identity(30),
        receiptSha256: HASH,
      }),
      retire: async (_, record) => ({
        independent: true,
        helpersSettled: true,
        helper: record.admission.helper,
        verifier: identity(30),
        requestSha256,
        receiptSha256: HASH,
      }),
      open: async () => {
        assert.equal(
          submitted.size,
          publication ? 3 : 0,
          "Concurrent requests must all be acknowledged before native admission",
        );
        const queue = [];
        helper += 10;
        const emit = (next) => {
          phase = next;
          queue.push(message(next, structuredClone(physical)));
        };
        return {
          admission: {
            requestSha256,
            independent: true,
            soleParentAuthority: true,
            helper: identity(helper),
            verifier: identity(10),
            helperSha256: HASH,
            cdhash: request.executable.cdhash,
            closureSha256: HASH,
            reviewSha256: HASH,
            base: id(1),
            root: id(2),
            receiptSha256: HASH,
          },
          close() {},
          dispose() {},
          completion: Promise.resolve({
            code: 0,
            signal: null,
            failed: false,
            remainingMessages: 0,
            partialBytes: 0,
          }),
          receive: async () => queue.shift(),
          send: async (text) => {
            const [type, , , , bytes] = text.trim().split(" ");
            if (type === "allocate") {
              physical.allocation = id(3);
              emit("allocated");
            } else if (type === "recover") emit("recovered");
            else if (["publish", "replace"].includes(type)) {
              physical.temporary = id(++serial);
              contents.set(physical.temporary, bytes);
              pendingOperation = type;
              emit("prepared");
            } else if (type === "cleanup") {
              pendingOperation = type;
              emit("removing");
            } else if (type === "finish") emit("finished");
            else if (type === "continue") {
              if (pendingOperation === "cleanup") {
                physical = state({ allocation: null });
                emit("removed");
              } else if (
                phase === "prepared" &&
                pendingOperation === "replace"
              ) {
                physical.leaf = physical.temporary;
                physical.temporary = null;
                emit("published");
              } else if (phase === "prepared" && physical.leaf !== null) {
                physical.temporary = null;
                emit("exists");
              } else if (phase === "prepared") {
                physical.leaf = physical.temporary;
                physical.alias = true;
                emit("linked");
              } else if (phase === "linked") {
                physical.temporary = null;
                physical.alias = false;
                emit("published");
              } else if (phase === "published") emit("complete");
            } else assert.fail("Unexpected private command");
          },
        };
      },
    }),
  };
  return effects;
}
test("Darwin concurrent publication joins one winner and two losers before receipt-bound cleanup", async () => {
  const effects = fileFixture();
  const result = await runDarwinFileCase("files.publish", input, effects, {
    now: () => 0,
  });
  assert.equal(result.status, "OBSERVED");
  assert.equal(result.sessions.length, 2);
  assert.equal(result.sessions.at(-1).result.state.allocation, null);
  assert.equal(result.reservation, "RETAINED");
  const broken = fileFixture(),
    observe = broken.observe;
  broken.observe = async (...args) => {
    const snapshot = await observe(...args);
    if (args[1].phase === "linked") snapshot.objects.leaf.bytes = "00";
    return snapshot;
  };
  const failed = await runDarwinFileCase("files.publish", input, broken, {
    now: () => 0,
  });
  assert.equal(failed.status, "FAIL");
  assert.equal(
    failed.sessions.length,
    1,
    "A failed independent byte check cannot start recovery cleanup automatically",
  );
  const stale = fileFixture(),
    finish = stale.finishPublishers;
  stale.finishPublishers = async (...args) => {
    const result = await finish(...args);
    result.requests[0].identity.pidVersion++;
    return result;
  };
  assert.equal(
    (await runDarwinFileCase("files.publish", input, stale, { now: () => 0 }))
      .status,
    "FAIL",
  );
  const unavailable = fileFixture(),
    owners = unavailable.fileEffects;
  unavailable.fileEffects = async () => ({
    ...(await owners()),
    review: async () => ({ missingInputs: ["reviewed-native-reader"] }),
  });
  const blocked = await runDarwinFileCase("files.publish", input, unavailable, {
    now: () => 0,
  });
  assert.equal(blocked.status, "BLOCKED");
  assert.deepEqual(blocked.missingInputs, ["reviewed-native-reader"]);
  assert.equal(blocked.sessions[0].result.admission, undefined);
});
test("Darwin replacement settles the same concurrent reader before receipt recovery and rejects stale identity", async () => {
  const result = await runDarwinFileCase(
    "files.replace",
    input,
    fileFixture({ publication: false }),
    { now: () => 0 },
  );
  assert.equal(result.status, "OBSERVED");
  assert.equal(result.sessions.length, 2);
  assert.equal(result.sessions.at(-1).result.state.allocation, null);
  const stale = fileFixture({ publication: false }),
    finish = stale.finishReader;
  stale.finishReader = async (...args) => {
    const reads = await finish(...args);
    reads.reader = { ...reads.reader, pidVersion: 2 };
    return reads;
  };
  const failed = await runDarwinFileCase("files.replace", input, stale, {
    now: () => 0,
  });
  assert.equal(failed.status, "FAIL");
  assert.equal(failed.sessions.length, 1);
});

const gitInput = normalizeDarwinGitInput({
  request,
  git: { path: "/fixture/storage/git", sha256: HASH, cdhash: "e".repeat(40) },
  metadata: "/fixture/storage/metadata",
  hooks: "/fixture/storage/hooks",
  parent: SHA,
  reviewSha256: HASH,
});
test("Darwin fixed Git has exact literal authority and retains the Linux request/snapshot compatibility exports", async () => {
  const expected = { operation: "commit", subject: FIXED_SUBJECT };
  assert.deepEqual(legacyRequest(expected), validateCommitRequest(expected));
  assert.equal(legacyEffect, validateCommitEffect);
  assert.deepEqual(darwinFixedCommitArguments(gitInput, expected), [
    NONCE,
    gitInput.git.path,
    gitInput.metadata,
    request.workspace,
    gitInput.hooks,
    SHA,
    "commit",
    FIXED_SUBJECT,
  ]);
  for (const value of [
    { ...expected, args: [] },
    { ...expected, subject: FIXED_SUBJECT + "\nBody" },
    { operation: "add", subject: FIXED_SUBJECT },
  ])
    assert.throws(() => darwinFixedCommitArguments(gitInput, value));
  assert.throws(() => darwinOrdinaryGitArguments(gitInput, "commit"));
  assert.equal(darwinOrdinaryGitArguments(gitInput, "git-add")[1], "git-add");
  for (const value of [
    { ...gitInput, metadata: request.storage },
    {
      ...gitInput,
      metadata: "/fixture/storage",
      request: { ...request, workspace: "/fixture/storage/nested/work" },
    },
    {
      ...gitInput,
      hooks: "/fixture/storage/parent",
      request: { ...request, workspace: "/fixture/storage/parent/work" },
    },
    { ...gitInput, git: { ...gitInput.git, path: request.executable.path } },
  ])
    assert.throws(() => normalizeDarwinGitInput(value));
  for (const checkId of ["git.ordinary-denial", "git.fixed-commit"])
    assert.equal(
      (await runDarwinGitCase(checkId, gitInput, { persist: async () => {} }))
        .status,
      "BLOCKED",
    );
});
test("File transport deadline rejects pending replies and completion without a process close", async () => {
  for (const fault of [false, true]) {
    const child = new EventEmitter();
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    let expire,
      cancelled = false;
    const channel = darwinFileChannel(child, {
      schedule(callback, bound) {
        assert.equal(bound, 30000);
        expire = callback;
        return 1;
      },
      cancel() {
        cancelled = true;
      },
    });
    try {
      const reply = message("finished", state());
      const pending = channel.receive();
      if (fault) {
        const rejected = channel.completion.then(
          () => false,
          () => true,
        );
        expire();
        await assert.rejects(pending, /Unverified Darwin file helper/u);
        assert.equal(
          await Promise.race([rejected, Promise.resolve(false)]),
          true,
        );
        await assert.rejects(
          channel.completion,
          /Unverified Darwin file helper/u,
        );
        assert.equal(child.stdin.destroyed, true);
        assert.throws(() => channel.send("finish - - - -\n"));
      } else {
        child.stdout.write(JSON.stringify(reply) + "\n");
        assert.deepEqual(await pending, reply);
        await channel.send("finish - - - -\n");
        assert.equal(child.stdin.read().toString(), "finish - - - -\n");
        child.emit("close", 0, null);
        assert.deepEqual(await channel.completion, {
          code: 0,
          signal: null,
          failed: false,
          remainingMessages: 0,
          partialBytes: 0,
        });
      }
    } finally {
      channel.dispose();
      child.stdin.destroy();
      child.stdout.destroy();
    }
    assert.equal(cancelled, true);
  }
});
test("Fixed Git deadline rejects unfinished completion and preserves exact frame ordering", async () => {
  for (const fault of [null, "deadline", "duplicate-ready"]) {
    const child = new EventEmitter();
    child.pid = 900;
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    let expire,
      cancelled = false;
    const channel = darwinFixedGitChannel(child, NONCE, {
      schedule(callback, bound) {
        assert.equal(bound, 30000);
        expire = callback;
        return 1;
      },
      cancel() {
        cancelled = true;
      },
    });
    try {
      const frame = (phase) =>
        child.stdout.write(
          JSON.stringify({ nonce: NONCE, phase, pid: child.pid }) + "\n",
        );
      frame("ready");
      await channel.ready;
      if (fault === "duplicate-ready") frame("ready");
      else {
        channel.release();
        assert.equal(child.stdin.read().toString(), "P");
        if (fault === "deadline") expire();
        else {
          frame("finished");
          child.emit("close", 0, null);
        }
      }
      if (fault) {
        await assert.rejects(
          channel.completion,
          /Unverified fixed Git executor/u,
        );
        assert.equal(child.stdin.destroyed, true);
        assert.throws(() => channel.release());
      } else
        assert.deepEqual(await channel.completion, {
          code: 0,
          signal: null,
          failed: false,
        });
    } finally {
      channel.dispose();
      child.stdin.destroy();
      child.stdout.destroy();
    }
    assert.equal(cancelled, true);
  }
});
function commitFixture() {
  const before = {
    branch: "refs/heads/proof",
    head: SHA,
    identity: "Fixture <fixture@example.invalid>",
    config: "fixture config",
    workspace: [
      [".git", digest(`gitdir: ${gitInput.metadata}\n`), 0o400],
      ["content.txt", digest("owned edit\n"), 0o400],
    ],
    refs: [
      ["refs/heads/proof", SHA],
      ["refs/tags/witness", SHA],
    ],
    metadata: [["config", HASH, 0o600]],
    status: " M content.txt\n",
  };
  const commit = "f".repeat(40),
    tree = "1".repeat(40),
    blob = "2".repeat(40);
  const after = {
    ...before,
    head: commit,
    parent: SHA,
    parents: [SHA],
    message: FIXED_SUBJECT + "\n",
    changed: "content.txt\n",
    content: "owned edit\n",
    status: "",
    author: before.identity,
    committer: before.identity,
    refs: [
      ["refs/heads/proof", commit],
      ["refs/tags/witness", SHA],
    ],
    metadata: [
      ...before.metadata,
      ...[commit, tree, blob].map((object) => [
        `objects/${object.slice(0, 2)}/${object.slice(2)}`,
        HASH,
        0o400,
      ]),
    ],
  };
  const observed = {
    independent: true,
    verifier: identity(10),
    candidateSha: SHA,
    requestSha256: digest(JSON.stringify(gitInput)),
    disposable: true,
    outsideUnchanged: true,
    outsideBeforeSha256: HASH,
    outsideAfterSha256: HASH,
    directoriesUnchanged: true,
    hooksEmpty: true,
    ambientConfigurationSuppressed: true,
    providersExcluded: true,
    nativeEventSha256: HASH,
    receiptSha256: HASH,
    objects: {
      commit,
      tree,
      blob,
      blobBytes: "owned edit\n",
      treeEntry: `100644 blob ${blob}\tcontent.txt\n`,
    },
    children: ["parent", "branch", "status", "add", "commit"].map(
      (operation, index) => ({
        operation,
        identity: identity(100 + index),
        independent: true,
        settled: true,
        imageSha256: gitInput.git.sha256,
        cdhash: gitInput.git.cdhash,
        requestSha256: digest(JSON.stringify(gitInput)),
        nativeEventSha256: HASH,
      }),
    ),
  };
  return { before, after, observed, commit };
}
test("Darwin fixed commit binds object bytes, one parent, metadata closure, identity and witness refs", () => {
  const { before, after, observed, commit } = commitFixture();
  assert.equal(
    assertDarwinCommitObservation(before, after, observed, gitInput).pid,
    10,
  );
  for (const mutate of [
    (value) => {
      value.parents.push(SHA);
    },
    (value) => {
      value.refs[1][1] = commit;
    },
    (value) => {
      value.metadata.push(["objects/info/alternates", HASH, 0o600]);
    },
    (value) => {
      value.author = "Other <other@example.invalid>";
    },
  ]) {
    const broken = structuredClone(after);
    mutate(broken);
    assert.throws(() =>
      assertDarwinCommitObservation(before, broken, observed, gitInput),
    );
  }
  assert.throws(() =>
    assertDarwinCommitObservation(
      before,
      after,
      { ...observed, objects: { ...observed.objects, blobBytes: "other\n" } },
      gitInput,
    ),
  );
});
test("Darwin fixed Git releases only a valid protected fixture and joins independent child settlement", async () => {
  for (const fault of [null, "admission", "workspace", "retirement"]) {
    const { before, after, observed } = commitFixture();
    if (fault === "workspace")
      before.workspace.push(["extra.txt", HASH, 0o400]);
    const requestSha256 = digest(JSON.stringify(gitInput));
    let opened = false,
      released = false,
      disposed = false;
    const admission = {
      helper: identity(900),
      verifier: identity(10),
      independent: true,
      requestSha256,
      helperSha256: HASH,
      cdhash: request.executable.cdhash,
      gitSha256: HASH,
      gitCdhash: gitInput.git.cdhash,
      closureSha256: HASH,
      directoriesVerified: true,
      soleMetadataAuthority: true,
      noLiveUid: fault !== "admission",
      providersExcluded: true,
      receiptSha256: HASH,
    };
    const result = await runDarwinGitCase(
      "git.fixed-commit",
      gitInput,
      {
        persist: async () => {},
        snapshot: async () => before,
        review: async () => ({
          approvedSha256: requestSha256,
          reviewSha256: HASH,
          disposable: true,
          providersExcluded: true,
          nativeBindingsVerified: true,
          snapshotSha256: digest(JSON.stringify(before)),
          outsideSha256: HASH,
        }),
        open: async () => {
          opened = true;
          return {
            admission,
            completion: Promise.resolve({
              code: 0,
              signal: null,
              failed: false,
            }),
            release() {
              released = true;
            },
            close() {},
            dispose() {
              disposed = true;
            },
          };
        },
        observe: async () => ({ ...observed, after }),
        retire: async () => ({
          independent: true,
          noLiveUid: true,
          uid: request.uid,
          helpersSettled: true,
          requestSha256,
          verifier: identity(20),
          helper: admission.helper,
          receiptSha256: HASH,
          children: observed.children.map((child, index) => ({
            ...child.identity,
            pidVersion: fault === "retirement" && index === 0 ? 2 : 1,
          })),
        }),
      },
      { now: () => 0 },
    );
    assert.equal(result.status, fault === null ? "OBSERVED" : "FAIL");
    assert.equal(opened, fault !== "workspace");
    assert.equal(released, fault === null || fault === "retirement");
    assert.equal(disposed, opened);
    assert.equal(result.reservation, "RETAINED");
  }
});
test("Ordinary Darwin Git denial requires reachable real controls and preserves complete protected snapshots", () => {
  const before = {
    branch: "refs/heads/proof",
    head: SHA,
    config: "fixture config",
    identity: "Fixture <fixture@example.invalid>",
    refs: [["refs/heads/proof", SHA]],
    metadata: [["config", HASH, 0o600]],
    pointerSha256: HASH,
  };
  const value = {
    independent: true,
    verifier: identity(10),
    candidateSha: SHA,
    requestSha256: digest(JSON.stringify(gitInput)),
    receiptSha256: HASH,
    outsideBeforeSha256: HASH,
    outsideAfterSha256: HASH,
    profiles: ["read-only", "workspace-write", "trusted-command"].map(
      (profile) => ({
        profile,
        disposable: true,
        providersExcluded: true,
        outsideUnchanged: true,
        inspection: { code: 0, head: SHA, nativeEventSha256: HASH },
        before,
        after: structuredClone(before),
        denials: ["git-add", "git-commit"].map((operation, index) => ({
          id: operation,
          attempted: true,
          timedOut: false,
          signal: null,
          exitCode: 128,
          nativeCode: "EPERM",
          nativeDecision: "deny-metadata-write",
          nativeEventSha256: HASH,
          imageSha256: HASH,
          cdhash: gitInput.git.cdhash,
          identity: {
            ...identity(30 + index),
            uid: request.uid,
            ruid: request.uid,
            svuid: request.uid,
            gid: request.gid,
            rgid: request.gid,
            svgid: request.gid,
            auid: request.uid,
            asid: 7,
          },
          control: {
            ready: true,
            reachable: true,
            independent: true,
            nonce: NONCE,
            operation,
            nativeCode: "OK",
            nativeEventSha256: HASH,
            receiptSha256: HASH,
          },
        })),
      }),
    ),
  };
  assert.equal(assertDarwinOrdinaryGitObservation(value, gitInput), true);
  for (const mutate of [
    (entry) => {
      entry.profiles[0].denials[0].nativeCode = null;
    },
    (entry) => {
      entry.profiles[0].denials[0].control.nativeCode = "EPERM";
    },
    (entry) => {
      entry.profiles[0].denials[0].timedOut = true;
    },
    (entry) => {
      entry.profiles[0].after.refs[0][1] = "f".repeat(40);
    },
    (entry) => {
      delete entry.profiles[0].before.metadata;
      delete entry.profiles[0].after.metadata;
    },
  ]) {
    const broken = structuredClone(value);
    mutate(broken);
    assert.throws(() => assertDarwinOrdinaryGitObservation(broken, gitInput));
  }
  for (const field of ["metadata", "refs"]) {
    const broken = structuredClone(value),
      profile = broken.profiles[0],
      inventory = new Array(field === "refs" ? 2 : 1);
    if (field === "refs") inventory[0] = profile.before.refs[0];
    profile.before = { ...profile.before, [field]: inventory };
    profile.after[field] = structuredClone(inventory);
    assert.throws(() => assertDarwinOrdinaryGitObservation(broken, gitInput));
  }
});
