import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { Script } from "node:vm";
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

// Execute the original native decisions with injected APIs. Only C data and
// pointer representations are projected; no Darwin executable is invoked.
async function nativeFileFunctions(experiment = true) {
  const [identity, effective, helper, reader] = await Promise.all(
    [
      "file-identity.h",
      "effective-reader.h",
      "file-helper.c",
      "custody-reader.c",
    ].map((name) => readFile(new URL(name, import.meta.url), "utf8")),
  );
  const declarations = [
    [identity, "file_identity_capabilities", "fd, publication"],
    [identity, "file_name_at", "parent, name, fd"],
    [effective, "file_capabilities", "fd"],
    [helper, "named", "at, name, fd, expected, directory, links"],
    [reader, "same_stat", "a, b"],
    [effective, "tree_at", "root, prefix, depth"],
    [effective, "file_tree", "root"],
  ].map(([source, name, args]) => {
    const body = new RegExp(
      `static void ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)?.[1];
    assert.ok(body, name);
    const projected = body
      .replace(
        /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#else\n([\s\S]*?)#endif/gu,
        (_, ordinary, reviewed) => (experiment ? ordinary : reviewed),
      )
      .replace(/struct attrlist attrs = \{[^;]+;/gu, "const attrs = {};")
      .replace(
        /struct \{ uint32_t length; vol_capabilities_attr_t value; \} caps = \{0\};/gu,
        "const caps = {length: 0, value: {valid: [], capabilities: []}};",
      )
      .replace(
        /struct stat ([\w, ]+);/gu,
        (_, names) =>
          `const ${names
            .split(", ")
            .map((value) => `${value} = {}`)
            .join(", ")};`,
      )
      .replace("struct statfs fs;", "const fs = {f_fsid: {val: []}};")
      .replaceAll("struct file_identity ", "let ")
      .replaceAll("struct dirent *", "let ")
      .replaceAll("DIR *", "let ")
      .replace(
        "char name[PATH_MAX], encoded[PATH_MAX * 2];",
        'const name = {value: ""}, encoded = {value: ""};',
      )
      .replaceAll("->", ".")
      .replaceAll("sizeof(caps)", "4096")
      .replaceAll("sizeof(name)", "4096")
      .replace(/\*name\b/gu, "name.length")
      .replace(/\*prefix\b/gu, "strlen(prefix)")
      .replace(/(?<!&)&(attrs|caps|before|after|named|held|st|s|fs)\b/gu, "$1")
      .replaceAll("(unsigned char *)", "")
      .replace(/\((?:void|uint32_t|size_t)\)/gu, "")
      .replace(/\b(?:unsigned|uint32_t|int) /gu, "let ");
    return `function ${name}(${args}) {${projected}}`;
  });
  return (context) =>
    new Script(
      `${declarations.join("\n")} let tree_count = 0, tree_files = 0;
      ({file_identity_capabilities, file_capabilities, file_name_at, named, tree_at, file_tree})`,
    ).runInNewContext(context);
}

test("Darwin capability admission distinguishes query, validity and supported operations without weakening reviewed reads", async () => {
  for (const experiment of [true, false]) {
    const load = await nativeFileFunctions(experiment);
    for (const publication of [false, true]) {
      for (const [valid, values, failure, queryError = 5] of [
        [15, 15, null],
        [15, 10, experiment ? null : "supported"],
        [11, 10, experiment ? null : "valid"],
        [3, 2, experiment && !publication ? null : "valid"],
        [15, 2, experiment && !publication ? null : "supported"],
        [14, 14, "valid"],
        [15, 13, "supported"],
        [15, 15, "query"],
        [15, 15, "query", 0],
        [15, 15, "length"],
      ]) {
        const diagnostics = [],
          calls = [];
        const env = {
          errno: 0,
          stderr: {},
          VOL_CAPABILITIES_FORMAT: 0,
          VOL_CAP_FMT_CASE_SENSITIVE: 1,
          VOL_CAP_FMT_CASE_PRESERVING: 2,
          VOL_CAP_FMT_PERSISTENTOBJECTIDS: 4,
          VOL_CAP_FMT_HARDLINKS: 8,
          need: (ok) => assert.ok(ok),
          fprintf: (_stream, message, ...facts) =>
            diagnostics.push({ message, facts }),
          fgetattrlist(fd, _attrs, caps) {
            calls.push(fd);
            env.errno = failure === "query" ? queryError : 0;
            caps.length = failure === "length" ? 0 : 4096;
            caps.value.valid[0] = valid;
            caps.value.capabilities[0] = values;
            return failure === "query" ? -1 : 0;
          },
        };
        const native = load(env),
          read = () =>
            publication
              ? native.file_identity_capabilities(7, true)
              : native.file_capabilities(7);
        if (failure) {
          assert.throws(read);
          assert.ok(diagnostics[0].message.includes(`predicate=${failure}`));
          if (failure === "query")
            assert.deepEqual(diagnostics[0].facts, [-1, queryError]);
        } else {
          read();
          assert.deepEqual(diagnostics, []);
        }
        assert.deepEqual(calls, [7]);
      }
    }
  }
});

test("Darwin native held-name checks exclude aliases and substitutions while retaining the controlled two-link state", async () => {
  const load = await nativeFileFunctions();
  for (const fault of [
    null,
    "two-links",
    "case",
    "unicode",
    "missing",
    "duplicate",
    "read",
    "overflow",
    "parent",
    "birth",
    "inode",
    "close",
    "hardlink",
    "symlink",
    "volume",
    "substitute",
  ]) {
    const metadata = (inode) => ({
      st_dev: fault === "volume" ? 2 : 1,
      st_ino: inode,
      st_mode: fault === "symlink" ? 0o120777 : 0o100600,
      st_uid: 0,
      st_gid: 0,
      st_nlink: ["two-links", "hardlink"].includes(fault) ? 2 : 1,
      st_birthtimespec: { tv_sec: 100, tv_nsec: 0 },
      st_mtimespec: { tv_sec: 100, tv_nsec: 0 },
      st_ctimespec: { tv_sec: 100, tv_nsec: 0 },
    });
    let position = 0,
      scanned = 0;
    const name = fault === "unicode" ? "v\u00e1lue" : "value",
      names =
        fault === "overflow"
          ? Array(4097).fill("other")
          : fault === "case"
            ? ["Value"]
            : fault === "unicode"
              ? ["va\u0301lue"]
              : fault === "missing"
                ? []
                : fault === "duplicate"
                  ? ["value", "value"]
                  : [".", "..", "value"];
    const calls = [],
      env = {
        errno: 0,
        O_RDONLY: 1,
        O_DIRECTORY: 2,
        O_NOFOLLOW: 4,
        O_CLOEXEC: 8,
        AT_SYMLINK_NOFOLLOW: 16,
        need: (ok) => assert.ok(ok),
        S_ISDIR: (mode) => mode === 0o40700,
        S_ISREG: (mode) => mode === 0o100600,
        S_ISLNK: (mode) => mode === 0o120777,
        strcmp: (a, b) => Number(a !== b),
        strchr: (value, part) => value.includes(part),
        root_id: { device: 1, fs0: 2, fs1: 3 },
        held: () => 2,
        identify: (fd) => ({
          device: fault === "volume" ? 2 : 1,
          inode: fd === 2 && fault === "substitute" ? 5 : 4,
        }),
        same: (a, b) => a.inode === b.inode,
        volume_matches: () => fault !== "volume",
        reject: (reason) => {
          throw new Error(reason);
        },
        fstatfs(_fd, fs) {
          fs.f_fsid.val = [2, 3];
          return 0;
        },
        close(fd) {
          assert.equal(fd, 2);
          calls.push("held-close");
          return 0;
        },
        openat(parent, name, flags) {
          assert.equal(parent, 1);
          assert.equal(name, ".");
          assert.equal(flags, 15);
          return 3;
        },
        fdopendir: (fd) => {
          assert.equal(fd, 3);
          return {};
        },
        readdir() {
          if (position === names.length) {
            env.errno = fault === "read" ? 5 : 0;
            return null;
          }
          return { d_name: names[position++] };
        },
        fstat(fd, out) {
          const value = metadata(fd === 3 ? 1 : 4);
          if (fd === 3) {
            value.st_mode = 0o40700;
            if (scanned++ && fault === "parent") value.st_ctimespec.tv_nsec++;
          }
          Object.assign(out, value);
          return 0;
        },
        fstatat(parent, name, out, flags) {
          assert.equal(parent, 1);
          assert.equal(name, fault === "unicode" ? "v\u00e1lue" : "value");
          assert.equal(flags, 16);
          const value = metadata(fault === "inode" ? 5 : 4);
          if (fault === "birth") value.st_birthtimespec.tv_nsec++;
          Object.assign(out, value);
          return 0;
        },
        closedir() {
          calls.push("close");
          return fault === "close" ? -1 : 0;
        },
      };
    const read = () =>
      load(env).named(
        1,
        name,
        9,
        { inode: 4 },
        false,
        fault === "two-links" ? 2 : 1,
      );
    if (fault && fault !== "two-links") assert.throws(read, undefined, fault);
    else {
      read();
      assert.deepEqual(calls, ["close", "held-close"]);
    }
  }
});

test("Darwin held tree snapshots repeat completely with independent directory offsets and checked stability", async () => {
  const load = await nativeFileFunctions();
  for (const fault of [
    null,
    "offset",
    "substitute",
    "change",
    "read",
    "close",
  ]) {
    const metadata = (inode, directory) => ({
      st_dev: 1,
      st_ino: inode,
      st_mode: directory ? 0o40700 : 0o100600,
      st_uid: 0,
      st_gid: 0,
      st_nlink: directory ? 2 : 1,
      st_size: 64,
      st_mtimespec: { tv_sec: 100, tv_nsec: 0 },
      st_ctimespec: { tv_sec: 100, tv_nsec: 0 },
    });
    const nodes = new Map([
      ["", { stat: metadata(1, true), names: ["storage", "custody"] }],
      ["storage", { stat: metadata(2, true), names: ["payload"] }],
      ["custody", { stat: metadata(3, true), names: ["launcher", "policy"] }],
      ...["storage/payload", "custody/launcher", "custody/policy"].map(
        (name, index) => [name, { stat: metadata(index + 4, false) }],
      ),
    ]);
    const retained = {
        path: "",
        node: nodes.get(""),
        cursor: fault === "offset" ? 1 : 0,
      },
      held = new Map([[1, retained]]),
      root = { fd: 1, stat: structuredClone(retained.node.stat) },
      closed = [],
      text = (value) => (typeof value === "string" ? value : value.value);
    let nextFd = 2,
      output = "",
      stable = 0,
      reads = 0;
    const opened = (description) => {
      const fd = nextFd++;
      held.set(fd, description);
      return fd;
    };
    const env = {
      errno: 0,
      O_RDONLY: 1,
      O_DIRECTORY: 2,
      O_NOFOLLOW: 4,
      O_CLOEXEC: 8,
      AT_SYMLINK_NOFOLLOW: 16,
      case_mode: false,
      need: (ok) => assert.ok(ok, "Native tree refused"),
      S_ISDIR: (mode) => mode === 0o40700,
      S_ISREG: (mode) => mode === 0o100600,
      strcmp: (a, b) => Number(text(a) !== text(b)),
      strlen: (value) => text(value).length,
      // dup aliases the original open description, including its cursor.
      dup: (fd) => opened(held.get(fd)),
      openat(fd, name, flags) {
        assert.equal(fd, 1);
        assert.equal(name, ".");
        assert.equal(flags, 15);
        const node =
          fault === "substitute"
            ? { ...retained.node, stat: metadata(99, true) }
            : retained.node;
        return opened({ path: "", node, cursor: 0 });
      },
      relative_file(fd, name) {
        assert.equal(fd, 1);
        const path = text(name);
        return opened({ path, node: nodes.get(path), cursor: 0 });
      },
      fstat(fd, out) {
        Object.assign(out, structuredClone(held.get(fd).node.stat));
        return 0;
      },
      fdopendir: (fd) => fd,
      readdir(fd) {
        reads++;
        const scan = held.get(fd);
        if (scan.cursor === scan.node.names.length) {
          env.errno = fault === "read" ? 5 : 0;
          return null;
        }
        return { d_name: scan.node.names[scan.cursor++] };
      },
      fstatat(fd, name, out, flags) {
        assert.equal(flags, 16);
        const parent = held.get(fd).path;
        Object.assign(
          out,
          structuredClone(nodes.get((parent ? parent + "/" : "") + name).stat),
        );
        return 0;
      },
      closedir(fd) {
        closed.push(fd);
        held.delete(fd);
        return fault === "close" ? -1 : 0;
      },
      snprintf(out, _size, _format, prefix, separator, name) {
        out.value = text(prefix) + separator + name;
        return out.value.length;
      },
      hex(value, size, out) {
        out.value = Buffer.from(text(value)).subarray(0, size).toString("hex");
      },
      printf(format, ...args) {
        let index = 0;
        output += format.replace(/%s/gu, () => text(args[index++]));
      },
      putchar: (value) => {
        output += value;
      },
      // Record observations at the existing file barrier boundary to isolate
      // directory-description ownership and traversal in this fixture.
      barrier_at(fd, name, contents) {
        assert.equal(fd, 1);
        assert.equal(contents, false);
        output += JSON.stringify({ sha256: digest(text(name)) });
        if (fault === "change") retained.node.stat.st_ctimespec.tv_nsec++;
      },
      stable(entry) {
        assert.deepEqual(retained.node.stat, entry.stat);
        stable++;
      },
    };
    const native = load(env);
    const snapshot = () => {
      output = "";
      native.file_tree(root);
      return JSON.parse(output);
    };
    if (fault && fault !== "offset") {
      assert.throws(snapshot, /Native tree refused/u, fault);
      if (fault === "substitute") assert.equal(reads, 0);
    } else {
      const first = snapshot(),
        second = snapshot();
      assert.deepEqual(
        first.map(({ name }) => Buffer.from(name, "hex").toString()),
        ["storage/payload", "custody/launcher", "custody/policy"],
      );
      assert.deepEqual(second, first);
      assert.equal(stable, 2);
      assert.equal(held.size, 1);
      assert.equal(closed.length, 6);
    }
    assert.equal(held.get(1), retained);
    assert.equal(retained.cursor, fault === "offset" ? 1 : 0);
  }
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
