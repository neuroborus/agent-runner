import assert from "node:assert/strict";
import test from "node:test";
import { FIXED_SUBJECT } from "../index.js";
import { digest } from "./protocol.js";
import {
  WINDOWS_FILE_CASE_IDS,
  WINDOWS_GIT_DENIALS,
  normalizeWindowsFileInput,
  normalizeWindowsGitInput,
  windowsGitGrant,
  windowsFixedCommitArguments,
  windowsOrdinaryGitArguments,
  windowsGitPolicyArguments,
  assertWindowsFileDenial,
  assertWindowsReplacementReads,
  assertWindowsCommitObservation,
  assertWindowsOrdinaryGitObservation,
  runWindowsFileCase,
  runWindowsGitCase,
} from "./index.js";

const HASH = "a".repeat(64),
  SHA = "b".repeat(40),
  NONCE = "c".repeat(32),
  SID = "S-1-5-21-1-2-3-4";
const id = (number) => `0000000000000001:${String(number).padStart(32, "0")}`;
const system = (pid) => ({
  pid,
  creationTime: String(pid),
  sessionId: 0,
  userSid: "S-1-5-18",
});
const request = {
  schemaVersion: 1,
  candidateSha: SHA,
  nonce: NONCE,
  restrictingSid: "S-1-5-21-1-2-3-5",
  custody: "C:\\NativeProof\\custody",
  storage: "C:\\NativeProof\\storage",
  workspace: "C:\\NativeProof\\storage\\workspace",
  launcher: {
    path: "C:\\NativeProof\\custody\\launcher.exe",
    sha256: HASH,
    signatureSha256: HASH,
  },
  executable: {
    path: "C:\\NativeProof\\storage\\fixture.exe",
    sha256: HASH,
    signatureSha256: HASH,
    parser: "msvc-ucrt-wmain-v1",
  },
  policy: { path: "C:\\NativeProof\\custody\\policy.json", sha256: HASH },
  bindings: { system: HASH, source: HASH, closure: HASH, policy: HASH },
};
const fileInput = normalizeWindowsFileInput({
  request,
  base: id(1),
  root: id(2),
  reviewSha256: HASH,
});
const gitInput = normalizeWindowsGitInput({
  request,
  git: {
    path: request.storage + "\\git.exe",
    sha256: HASH,
    signatureSha256: HASH,
  },
  metadata: request.storage + "\\metadata",
  hooks: request.storage + "\\hooks",
  parent: SHA,
  accountSid: SID,
  reviewSha256: HASH,
});
const native = (input) => ({
  independent: true,
  verifier: system(900),
  candidateSha: SHA,
  nonce: NONCE,
  requestSha256: digest(JSON.stringify(input)),
  timedOut: false,
  lossCount: 0,
  nativeEventSha256: HASH,
  receiptSha256: HASH,
});
const before = () => ({
  branch: "refs/heads/proof",
  head: SHA,
  config: "synthetic configuration",
  identity: "Fixture <fixture@example.invalid>",
  refs: [
    ["refs/heads/proof", SHA],
    ["refs/tags/witness", SHA],
  ],
  metadata: [
    ["config", HASH, HASH],
    ["index", HASH, HASH],
  ],
  pointerIdentitySha256: HASH,
  pointerSha256: digest(`gitdir: ${gitInput.metadata.replaceAll("\\", "/")}\n`),
  parentIdentitiesSha256: HASH,
  workspaceSha256: HASH,
  contentSha256: digest("owned edit\n"),
  contentIdentitySha256: HASH,
  status: " M content.txt\n",
});
const child = (operation, pid, fixed = true, profile = "read-only") => ({
  ...native(gitInput),
  operation,
  identity: { ...system(pid), userSid: fixed ? "S-1-5-18" : SID },
  settled: true,
  imageSha256: HASH,
  signatureSha256: HASH,
  closureSha256: HASH,
  tokenVerified: true,
  bornInJob: true,
  noBreakaway: true,
  restrictingSid: fixed ? null : request.restrictingSid,
  jobIdentitySha256: HASH,
  suspendedAdmissionVerified: true,
  grantSha256: digest(
    JSON.stringify(windowsGitGrant(gitInput, fixed ? "commit" : profile)),
  ),
  admissionReceiptSha256: HASH,
});
function commitView() {
  const prior = before(),
    head = "d".repeat(40),
    tree = "e".repeat(40),
    blob = "f".repeat(40);
  const after = {
    ...structuredClone(prior),
    head,
    parent: SHA,
    parents: [SHA],
    message: FIXED_SUBJECT + "\n",
    changed: "content.txt\n",
    content: "owned edit\n",
    status: "",
    author: prior.identity,
    committer: prior.identity,
    refs: [
      ["refs/heads/proof", head],
      ["refs/tags/witness", SHA],
    ],
    metadata: [
      ["config", HASH, HASH],
      ["index", "d".repeat(64), HASH],
    ],
  };
  const evidence = {
    ...native(gitInput),
    after,
    disposable: true,
    providersExcluded: true,
    hooksEmpty: true,
    ambientConfigurationSuppressed: true,
    creatorDaclVerified: true,
    outsideBeforeSha256: HASH,
    outsideAfterSha256: HASH,
    objects: {
      commit: head,
      tree,
      blob,
      blobBytes: "owned edit\n",
      treeEntry: `100644 blob ${blob}\tcontent.txt\n`,
    },
    children: ["parent", "branch", "status", "add", "commit"].map(
      (operation, index) => child(operation, 200 + index),
    ),
  };
  return { prior, after, evidence };
}

test("Windows Git grants cannot upgrade ordinary metadata authority or accept alternate literal inputs", () => {
  const fixed = { operation: "commit", subject: FIXED_SUBJECT };
  assert.equal(
    windowsFixedCommitArguments(gitInput, fixed).at(-1),
    FIXED_SUBJECT,
  );
  assert.equal(windowsOrdinaryGitArguments(gitInput, "git-add")[1], "git-add");
  for (const profile of ["read-only", "workspace-write", "trusted-command"])
    assert.equal(
      windowsGitGrant(gitInput, profile).objects[0].grant,
      "read-tree",
    );
  assert.equal(windowsGitGrant(gitInput, "commit").principalSid, "S-1-5-18");
  for (const bad of [
    { ...fixed, subject: FIXED_SUBJECT + "\nBody" },
    { ...fixed, path: "other.txt" },
  ])
    assert.throws(() => windowsFixedCommitArguments(gitInput, bad));
  assert.throws(() => windowsOrdinaryGitArguments(gitInput, "commit"));
  assert.throws(() =>
    normalizeWindowsGitInput({ ...gitInput, hooks: gitInput.metadata }),
  );
  const held = {
    storage: { handle: "10", identity: id(1) },
    workspace: { handle: "11", identity: id(2) },
    objects: [
      {
        handle: "12",
        identity: id(3),
        kind: "directory",
        path: gitInput.metadata,
      },
      {
        handle: "13",
        identity: id(4),
        kind: "directory",
        path: gitInput.hooks,
      },
      {
        handle: "14",
        identity: id(5),
        kind: "file",
        path: request.workspace + "\\content.txt",
      },
      {
        handle: "15",
        identity: id(6),
        kind: "file",
        path: gitInput.metadata + "\\config",
      },
    ],
  };
  assert.equal(windowsGitPolicyArguments(gitInput, "install", held).length, 20);
  for (const change of [
    (value) => {
      value.objects[3].path = request.custody + "\\credential";
    },
    (value) => {
      value.objects[3].identity = id(3);
    },
    (value) => {
      value.objects.splice(0, 1);
    },
  ]) {
    const bad = structuredClone(held);
    change(bad);
    assert.throws(() => windowsGitPolicyArguments(gitInput, "install", bad));
  }
});
test("Windows fixed Git joins common commit predicates to exact native children and protected objects", () => {
  const { prior, after, evidence } = commitView();
  assert.equal(
    assertWindowsCommitObservation(prior, after, evidence, gitInput).pid,
    900,
  );
  for (const change of [
    (value) => {
      value.after.message += "Co-authored-by: Other\n";
    },
    (value) => {
      value.after.refs[1][1] = value.after.head;
    },
    (value) => {
      value.after.metadata[0][1] = "d".repeat(64);
    },
    (value) => {
      value.children[0].bornInJob = false;
    },
    (value) => {
      value.children[1].identity = value.children[0].identity;
    },
    (value) => {
      value.objects.blobBytes = "other\n";
    },
  ]) {
    const bad = structuredClone(evidence);
    change(bad);
    assert.throws(() =>
      assertWindowsCommitObservation(prior, bad.after, bad, gitInput),
    );
  }
});
test("Every ordinary Windows profile needs real Git inspection and every reachable native denial", () => {
  const value = {
    ...native(gitInput),
    outsideBeforeSha256: HASH,
    outsideAfterSha256: HASH,
    profiles: ["read-only", "workspace-write", "trusted-command"].map(
      (profile, index) => ({
        profile,
        before: before(),
        after: before(),
        disposable: true,
        providersExcluded: true,
        basePolicyVerified: true,
        grantSha256: digest(JSON.stringify(windowsGitGrant(gitInput, profile))),
        inspection: {
          ...child("inspect", 300 + index, false, profile),
          code: 0,
          head: SHA,
        },
        denials: WINDOWS_GIT_DENIALS.map((name, offset) => ({
          ...child(name, 400 + index * 20 + offset, false, profile),
          id: name,
          attempted: true,
          allowed: false,
          signal: null,
          exitCode: name.startsWith("git-") ? 128 : 0,
          nativeCode: 5,
          nativeDecision: "deny-metadata-write",
          beforeSha256: HASH,
          afterSha256: HASH,
          targetIdentitySha256: HASH,
          control: {
            ...native(gitInput),
            identity: system(500),
            settled: true,
            ready: true,
            reachable: true,
            readyBeforeAttempt: true,
            operation: name,
            nativeCode: 0,
            targetIdentitySha256: HASH,
          },
        })),
      }),
    ),
  };
  assert.equal(assertWindowsOrdinaryGitObservation(value, gitInput), true);
  for (const change of [
    (bad) => bad.profiles.pop(),
    (bad) => bad.profiles[0].denials.pop(),
    (bad) => {
      bad.profiles[0].denials[0].control.readyBeforeAttempt = false;
    },
    (bad) => {
      bad.profiles[1].denials[0].nativeCode = 2;
    },
    (bad) => {
      bad.profiles[2].after.pointerIdentitySha256 = "d".repeat(64);
    },
    (bad) => {
      bad.profiles[0].denials[2].exitCode = 126;
    },
    (bad) => {
      bad.profiles[0].denials[0].exitCode = 0xc0000005;
    },
    (bad) => {
      bad.profiles[0].denials[0].allowed = true;
    },
    (bad) => {
      bad.profiles[0].denials[0].identity = bad.profiles[0].inspection.identity;
    },
  ]) {
    const bad = structuredClone(value);
    change(bad);
    assert.throws(() => assertWindowsOrdinaryGitObservation(bad, gitInput));
  }
});
test("Windows fixed Git persists admissions and settles rejected authority or deadlines", async () => {
  for (const mode of ["complete", "child", "creator", "deadline", "persist"]) {
    const { prior, evidence } = commitView(),
      events = [];
    let serial = 0,
      retired = 0,
      deadline,
      settlement;
    const admission = {
      ...native(gitInput),
      helper: system(100),
      helperSha256: HASH,
      signatureSha256: HASH,
      gitSha256: HASH,
      gitSignatureSha256: HASH,
      closureSha256: HASH,
      grantSha256: digest(JSON.stringify(windowsGitGrant(gitInput, "commit"))),
      heldImagesVerified: true,
      argumentsSha256: digest(
        JSON.stringify(
          windowsFixedCommitArguments(gitInput, {
            operation: "commit",
            subject: FIXED_SUBJECT,
          }),
        ),
      ),
      parentsVerified: true,
      privateCreatorDaclVerified: mode !== "creator",
      hooksEmpty: true,
      soleMetadataAuthority: true,
      jobVerified: true,
      jobIdentitySha256: HASH,
    };
    const result = await runWindowsGitCase(
      "git.fixed-commit",
      gitInput,
      {
        persist: async (value) => {
          events.push(value.phase);
          if (mode === "persist" && value.phase === "retirement-intent") {
            queueMicrotask(() => settlement());
            return new Promise(() => {});
          }
        },
        snapshot: async () => {
          assert.equal(events.at(-1), "snapshot-intent");
          return prior;
        },
        review: async () => ({
          independent: true,
          approvedSha256: digest(JSON.stringify(gitInput)),
          reviewSha256: HASH,
          windows2025X64: true,
          gitClosureVerified: true,
          completeCompositionReviewed: true,
          disposable: true,
          providersExcluded: true,
          soleMetadataAuthority: true,
          outsideSha256: HASH,
          snapshotSha256: digest(JSON.stringify(prior)),
        }),
        open: async () => ({
          admission,
          release: async () => {
            events.push("release");
            if (mode === "deadline") deadline();
          },
          continue: async () => {
            assert.equal(events.at(-1), "child-release-intent");
            events.push("continue");
          },
          receive: async () =>
            serial === 5
              ? { nonce: NONCE, phase: "finished" }
              : {
                  nonce: NONCE,
                  phase: "child",
                  operation: evidence.children[serial].operation,
                  suspended: true,
                  identity: evidence.children[serial++].identity,
                },
          close() {
            if (mode === "deadline")
              throw new Error("Closed channel unavailable");
          },
          dispose() {},
          completion: Promise.resolve({
            code: 0,
            signal: null,
            failed: false,
            partialBytes: 0,
            remainingMessages: 0,
          }),
        }),
        admitChild: async (_input, _admission, frame) => ({
          ...native(gitInput),
          identity: frame.identity,
          imageSha256: HASH,
          signatureSha256: HASH,
          closureSha256: HASH,
          bornInJob: mode !== "child",
          jobIdentitySha256: HASH,
          parentsVerified: true,
          privateCreatorDaclVerified: true,
          noForeignHandles: true,
          suspended: true,
        }),
        observe: async () => evidence,
        retire: async (_input, record) => {
          retired++;
          return {
            ...native(gitInput),
            noLiveMembers: true,
            admissionsClosed: true,
            helpersSettled: true,
            accountSid: SID,
            restrictingSid: request.restrictingSid,
            helper: system(100),
            children: record.children,
          };
        },
      },
      {
        schedule(action, milliseconds) {
          if (milliseconds === 60000) deadline = action;
          if (milliseconds === 30000) settlement = action;
          return action;
        },
        cancel() {},
      },
    );
    assert.equal(result.status, mode === "complete" ? "OBSERVED" : "FAIL");
    assert.equal(retired, 1);
    assert.equal(
      events.filter((event) => event === "continue").length,
      ["complete", "persist"].includes(mode) ? 5 : 0,
    );
    assert.equal(result.reservation, "RETAINED");
  }
});

function fileFixture() {
  const receipts = new Map(),
    contents = new Map();
  let count = 20,
    current,
    control,
    oldId;
  const frame = (phase, state) => ({ nonce: NONCE, phase, ...state });
  const empty = () => ({
    base: id(1),
    root: id(2),
    allocation: null,
    leaf: null,
    temporary: null,
    alias: false,
  });
  const stateOf = (value) =>
    Object.fromEntries(
      ["base", "root", "allocation", "leaf", "temporary", "alias"].map(
        (key) => [key, value[key]],
      ),
    );
  const retirement = (prior, state) => ({
    ...native(fileInput),
    noLiveMembers: true,
    admissionsClosed: true,
    helpersSettled: true,
    sameHeldObjects: true,
    stateSha256: digest(JSON.stringify(state)),
    requestSha256: digest(JSON.stringify(fileInput)),
    recoverySha256: prior.receiptSha256,
    restrictingSid: request.restrictingSid,
    helper: prior.helper,
  });
  return {
    persist: async () => {},
    fileEffects: async () => {
      const helper = system(++count),
        replies = [];
      let state = empty(),
        stage,
        type,
        completed,
        end;
      const completion = new Promise((resolve) => {
        end = (code) => {
          if (!completed) {
            completed = true;
            resolve({
              code,
              signal: null,
              failed: false,
              partialBytes: 0,
              remainingMessages: 0,
            });
          }
        };
      });
      control = null;
      replies.push(frame("ready", state));
      return {
        review: async () => ({
          independent: true,
          approvedSha256: digest(JSON.stringify(fileInput)),
          reviewSha256: HASH,
          sourceSha256: HASH,
          windows2025X64: true,
          sdkAndLoaderVerified: true,
          ntfsSemanticsVerified: true,
          soleParentAuthorityVerified: true,
        }),
        open: async () => ({
          helper,
          completion,
          receive: async () => replies.shift(),
          close: () => end(126),
          dispose() {},
          send: async (line) => {
            const [operation, allocation, leaf, temporary, bytes] = line
              .trim()
              .split(" ");
            if (operation === "start") return;
            if (operation === "allocate") {
              state.allocation = id(++count);
              replies.push(frame("allocated", state));
            } else if (operation === "recover") {
              state = {
                ...empty(),
                allocation: allocation === "-" ? null : allocation,
                leaf: leaf === "-" ? null : leaf,
                temporary: temporary === "-" ? null : temporary,
                alias: leaf !== "-" && leaf === temporary,
              };
              replies.push(frame("recovered", state));
            } else if (["publish", "replace"].includes(operation)) {
              type = operation;
              state.temporary = id(++count);
              contents.set(state.temporary, bytes === "-" ? "" : bytes);
              stage = "prepared";
              replies.push(frame(stage, state));
            } else if (operation === "continue") {
              if (control) {
                end(126);
                throw new Error("Controlled native rejection");
              }
              if (stage === "prepared") {
                if (type === "publish" && state.leaf !== null) {
                  state.temporary = null;
                  stage = "exists";
                } else {
                  state.leaf = state.temporary;
                  state.alias = type === "publish";
                  if (!state.alias) state.temporary = null;
                  stage = state.alias ? "linked" : "published";
                }
              } else if (stage === "linked") {
                state.temporary = null;
                state.alias = false;
                stage = "published";
              } else if (stage === "published") stage = "complete";
              else if (stage === "removing") {
                state = empty();
                stage = "removed";
              }
              replies.push(frame(stage, state));
            } else if (operation === "cleanup") {
              stage = "removing";
              replies.push(frame(stage, state));
            } else if (operation === "finish") {
              replies.push(frame("finished", state));
              end(0);
            }
          },
        }),
        admit: async () => ({
          independent: true,
          helper,
          verifier: system(900),
          requestSha256: digest(JSON.stringify(fileInput)),
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
        }),
        persist: async (record) => {
          current = record;
          const receiptSha256 = (++count).toString().padStart(64, "0");
          receipts.set(receiptSha256, structuredClone(record));
          return {
            immutable: true,
            recordSha256: digest(JSON.stringify(record)),
            receiptSha256,
          };
        },
        retire: async () => ({
          independent: true,
          helpersSettled: true,
          requestSha256: digest(JSON.stringify(fileInput)),
          helper,
          verifier: system(900),
          receiptSha256: HASH,
        }),
        readRecovery: async (receiptSha256) => {
          const prior = receipts.get(receiptSha256);
          return {
            independent: true,
            immutable: true,
            protectedDacl: true,
            heldIdentitiesRetained: true,
            requestSha256: prior.requestSha256,
            candidateSha: SHA,
            nonce: NONCE,
            receiptSha256,
            sourceSha256: HASH,
            status: prior.status,
            operation: prior.events.at(-1).operation.type,
            state: prior.state,
            stateSha256: digest(JSON.stringify(prior.state)),
            helper: prior.helper,
            admission: prior.admission,
            observation: prior.observation,
          };
        },
        verifyRetirement: async (_input, prior, state) =>
          retirement(prior, state),
      };
    },
    observe: async (_input, message) => ({
      ...native(fileInput),
      soleParentAuthority: true,
      policySha256: HASH,
      outsideBeforeSha256: HASH,
      outsideAfterSha256: HASH,
      objects: Object.fromEntries(
        ["base", "root", "allocation", "leaf", "temporary"].map((key) => {
          const directory = !["leaf", "temporary"].includes(key);
          return [
            key,
            message[key] === null
              ? null
              : {
                  identity: message[key],
                  namedIdentity: message[key],
                  ownerSid: "S-1-5-18",
                  systemOnlyDacl: true,
                  protectedDacl: true,
                  noReparse: true,
                  canonicalName: true,
                  noShortAlias: true,
                  defaultStreamsOnly: true,
                  kind: directory ? "directory" : "file",
                  caseSensitive: false,
                  bytes: directory ? null : contents.get(message[key]),
                  links: message.alias ? 2 : 1,
                },
          ];
        }),
      ),
    }),
    verifyRetirement: async (_input, session) => ({
      ...native(fileInput),
      noLiveMembers: true,
      admissionsClosed: true,
      helpersSettled: true,
      restrictingSid: request.restrictingSid,
      helper: session.result.helper,
      sessionReceiptSha256: session.receiptSha256,
    }),
    privateProbe: async (_input, message) => ({
      ...native(fileInput),
      identity: { ...system(300), userSid: SID },
      ready: true,
      reachable: true,
      attempted: true,
      allowed: false,
      nativeCode: 5,
      exitCode: 0,
      signal: null,
      settled: true,
      restrictingSid: request.restrictingSid,
      tokenVerified: true,
      jobVerified: true,
      allocation: message.allocation,
    }),
    startPublishers: async (_input, message) => ({
      ...native(fileInput),
      ready: true,
      stateSha256: digest(JSON.stringify(stateOf(message))),
      reviewSha256: HASH,
      callers: [system(300), system(301), system(302)],
      overlapped: true,
      requestsAcknowledged: 3,
    }),
    finishPublishers: async (_input, prior, message) => ({
      ...native(fileInput),
      complete: true,
      settled: true,
      overlapped: true,
      participantsReceiptSha256: prior.receiptSha256,
      requests: ["006f6c64ff", "006e657700ff", "7365636f6e64"].map(
        (bytes, index) => ({
          identity: prior.callers[index],
          bytesSha256: digest(Buffer.from(bytes, "hex")),
          leaf: message.leaf,
          outcome: index === 0 ? "complete" : "exists",
          nativeEventSha256: HASH,
        }),
      ),
    }),
    startReader: async (_input, message) => {
      oldId = message.leaf;
      return {
        ...native(fileInput),
        ready: true,
        stateSha256: digest(JSON.stringify(stateOf(message))),
        reviewSha256: HASH,
        reader: system(300),
      };
    },
    finishReader: async (_input, prior, message) => ({
      ...native(fileInput),
      reader: prior.reader,
      ready: true,
      overlapped: true,
      complete: true,
      settled: true,
      dropped: false,
      participantsReceiptSha256: prior.receiptSha256,
      oldHeld: { identity: oldId, bytes: "006f6c64ff", links: 0 },
      reads: [
        [oldId, "006f6c64ff"],
        [message.leaf, "006e657700ff"],
      ].map(([identity, bytes]) => ({
        identity,
        bytes,
        code: 0,
        links: 1,
        nativeEventSha256: HASH,
      })),
    }),
    applyControl: async (name, _input, message) => {
      control = name;
      return {
        ...native(fileInput),
        ready: true,
        control: name,
        barrierSha256: digest(JSON.stringify(message)),
      };
    },
    observeDenial: async (name, _input, barrier, receipt, session) => {
      const target =
          name === "root"
            ? "root"
            : ["parent", "junction", "cross-volume"].includes(name)
              ? "allocation"
              : "leaf",
        identity = barrier[target];
      const original = {
        identity,
        bytesSha256:
          target === "leaf" ? digest(Buffer.from("006f6c64ff", "hex")) : HASH,
        links: 1,
        stateSha256: digest(JSON.stringify(stateOf(barrier))),
      };
      const applied = {
        identity: [
          "root",
          "parent",
          "cross-volume",
          "junction",
          "symlink",
        ].includes(name)
          ? id(600)
          : identity,
        bytesSha256: original.bytesSha256,
        kind: target === "leaf" ? "file" : "directory",
        reparse: name === "cross-volume" ? "volume-mount" : name,
        links: 2,
        streams: 2,
        name: "Value",
        alternateName: "VALUE~1",
      };
      const foreign = {
        identity: id(601).replace(/^0/u, "1"),
        kind: "directory",
        stateSha256: HASH,
      };
      if (name === "cross-volume") applied.targetIdentity = foreign.identity;
      return {
        ...native(fileInput),
        control: name,
        attempted: true,
        ready: true,
        reachable: true,
        continued: true,
        exitCode: 126,
        signal: null,
        barrierSha256: digest(JSON.stringify(barrier)),
        before: original,
        saved: { ...original, links: name === "hardlink" ? 2 : 1 },
        applied,
        after: applied,
        ...(name === "cross-volume"
          ? { foreignTarget: { before: foreign, after: { ...foreign } } }
          : {}),
        othersBeforeSha256: HASH,
        othersAfterSha256: HASH,
        outsideBeforeSha256: HASH,
        outsideAfterSha256: HASH,
        nativeDecision:
          "reject-" +
          (["root", "parent"].includes(name)
            ? "identity"
            : ["junction", "symlink", "cross-volume"].includes(name)
              ? "reparse"
              : name),
        helper: session.result.helper,
        sessionReceiptSha256: session.receiptSha256,
        controlReceiptSha256: receipt.receiptSha256,
        observationReceiptSha256: session.result.observation.receiptSha256,
      };
    },
    restoreControl: async (_name, _input, denial) => ({
      ...native(fileInput),
      ownedOnly: true,
      foreignPreserved: true,
      priorRetirementVerified: true,
      controlReceiptSha256: denial.controlReceiptSha256,
      restoredStateSha256: digest(JSON.stringify(current.state)),
    }),
  };
}
test("Cross-volume proof binds a local no-follow mount to an unchanged foreign target", async () => {
  const barrier = {
    nonce: NONCE,
    phase: "prepared",
    base: id(1),
    root: id(2),
    allocation: id(3),
    leaf: id(4),
    temporary: id(5),
    alias: false,
  };
  const view = await fileFixture().observeDenial(
    "cross-volume",
    fileInput,
    barrier,
    { receiptSha256: HASH },
    {
      receiptSha256: HASH,
      result: { helper: system(100), observation: { receiptSha256: HASH } },
    },
  );
  assert.equal(
    assertWindowsFileDenial("cross-volume", barrier, view, fileInput),
    true,
  );
  for (const change of [
    (bad) => {
      bad.applied.identity = bad.foreignTarget.before.identity;
    },
    (bad) => {
      bad.applied.reparse = "none";
    },
    (bad) => {
      bad.foreignTarget.before.identity = id(601);
      bad.foreignTarget.after.identity = id(601);
      bad.applied.targetIdentity = id(601);
    },
    (bad) => {
      bad.applied.targetIdentity = id(602).replace(/^0/u, "1");
    },
    (bad) => {
      bad.foreignTarget.after.stateSha256 = "d".repeat(64);
    },
    (bad) => {
      bad.nativeDecision = "reject-identity";
    },
  ]) {
    const bad = structuredClone(view);
    change(bad);
    bad.after = structuredClone(bad.applied);
    assert.throws(() =>
      assertWindowsFileDenial("cross-volume", barrier, bad, fileInput),
    );
  }
});
test("All Windows file records compose barriers, independent bytes, fault settlement and owned cleanup", async () => {
  for (const checkId of WINDOWS_FILE_CASE_IDS) {
    const result = await runWindowsFileCase(checkId, fileInput, fileFixture());
    assert.equal(result.status, "OBSERVED", checkId);
    assert.equal(result.sessions.at(-1).result.state.allocation, null);
    assert.equal(result.reservation, "RETAINED");
  }
});
test("Windows file failures retain rejected channels and attempt retirement after the case deadline", async () => {
  for (const mode of ["identity", "deadline"]) {
    const effects = fileFixture(),
      createOwners = effects.fileEffects;
    let elapsed = 0,
      closed = 0,
      disposed = 0,
      retired = 0;
    effects.fileEffects = async (...args) => {
      const owners = await createOwners(...args),
        open = owners.open;
      owners.open = async (...args) => {
        const channel = await open(...args),
          close = channel.close,
          dispose = channel.dispose;
        if (mode === "identity")
          channel.helper = { ...channel.helper, userSid: SID };
        channel.close = () => {
          closed++;
          close();
        };
        channel.dispose = () => {
          disposed++;
          dispose();
        };
        return channel;
      };
      return owners;
    };
    effects.startReader = async () => {
      elapsed = 270000;
      throw new Error("Reader admission interrupted");
    };
    effects.finishReader = async (_input, _prior, barrier) => {
      assert.equal(barrier, null);
      retired++;
    };
    const result = await runWindowsFileCase(
      "files.replace",
      fileInput,
      effects,
      {
        now: () => elapsed,
        schedule: (action) => action,
        cancel() {},
      },
    );
    assert.equal(result.status, "FAIL");
    assert.equal(closed, 1);
    assert.equal(disposed, 1);
    assert.equal(retired, mode === "deadline" ? 1 : 0);
    assert.equal(result.reservation, "RETAINED");
  }
});
test("Windows allocation privacy rejects crashed, timed-out or contradictory probes", async () => {
  for (const change of [
    { exitCode: 0xc0000005 },
    { exitCode: 124 },
    { allowed: true },
  ]) {
    const effects = fileFixture(),
      probe = effects.privateProbe;
    effects.privateProbe = async (...args) => ({
      ...(await probe(...args)),
      ...change,
    });
    const result = await runWindowsFileCase(
      "files.private",
      fileInput,
      effects,
    );
    assert.equal(result.status, "FAIL");
    assert.equal(result.reservation, "RETAINED");
  }
});
test("Replacement proof rejects absent old/new overlap, lost events and changed held bytes", () => {
  const view = {
    ...native(fileInput),
    reader: system(300),
    ready: true,
    overlapped: true,
    complete: true,
    settled: true,
    dropped: false,
    oldHeld: { identity: id(3), bytes: "006f6c64ff", links: 0 },
    reads: [
      [id(3), "006f6c64ff"],
      [id(4), "006e657700ff"],
    ].map(([identity, bytes]) => ({
      identity,
      bytes,
      links: 1,
      code: 0,
      nativeEventSha256: HASH,
    })),
  };
  assert.equal(
    assertWindowsReplacementReads(view, id(3), id(4), fileInput).pid,
    300,
  );
  for (const change of [
    (bad) => {
      bad.reads.pop();
    },
    (bad) => {
      bad.dropped = true;
    },
    (bad) => {
      bad.oldHeld.bytes = "00";
    },
  ]) {
    const bad = structuredClone(view);
    change(bad);
    assert.throws(() =>
      assertWindowsReplacementReads(bad, id(3), id(4), fileInput),
    );
  }
});
test("Missing Windows native bridges block every file/Git case before any effects", async () => {
  for (const checkId of WINDOWS_FILE_CASE_IDS)
    assert.equal(
      (
        await runWindowsFileCase(checkId, fileInput, {
          persist: async () => {},
        })
      ).status,
      "BLOCKED",
    );
  for (const checkId of ["git.ordinary-denial", "git.fixed-commit"])
    assert.equal(
      (await runWindowsGitCase(checkId, gitInput, { persist: async () => {} }))
        .status,
      "BLOCKED",
    );
});
test("Missing reviewed Git closure prevents even the protected snapshot and helper launch", async () => {
  const attempted = [];
  const result = await runWindowsGitCase("git.fixed-commit", gitInput, {
    persist: async () => {},
    review: async () => ({ missingInputs: ["windows-git-closure"] }),
    snapshot: async () => attempted.push("snapshot"),
    open: async () => attempted.push("open"),
    observe: async () => attempted.push("observe"),
    admitChild: async () => attempted.push("child"),
    retire: async () => attempted.push("retire"),
  });
  assert.equal(result.status, "BLOCKED");
  assert.deepEqual(attempted, []);
});
