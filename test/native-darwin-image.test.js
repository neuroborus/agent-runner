import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Script } from "node:vm";
import { admitDarwinImage } from "../ci/native/darwin/image-admission.js";
import { DARWIN_LITERAL_ARGUMENTS } from "../ci/native/darwin/protocol.js";

const creator = {
  pid: 123,
  pidVersion: 1,
  asid: 5,
  auid: 90001,
  uid: 90001,
  gid: 90002,
  ruid: 90001,
  rgid: 90002,
  svuid: 90001,
  svgid: 90002,
  startSeconds: 100,
  startMicroseconds: 2,
};
const helper = {
  ...creator,
  pid: 120,
  pidVersion: 3,
  asid: 4,
  auid: 0,
  uid: 0,
  gid: 0,
  ruid: 0,
  rgid: 0,
  svuid: 0,
  svgid: 0,
};
const target = { ...creator, pidVersion: 2 };
const executable = { sha256: "a".repeat(64), cdhash: "b".repeat(40) };
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
// Existing body fixtures model the default no-op observations. Dedicated creator
// fixtures below execute the observation implementation and call expansion.
function passiveObservations(api) {
  api.IMAGE_CALL ??= (_, result) => result;
  api.IMAGE_NOTE ??= () => {};
  api.errno ??= 0;
  return api;
}
function expandImageCalls(body, macro) {
  for (;;) {
    const match = /IMAGE_CALL\(([^,]+),\s*/u.exec(body);
    if (!match) return body;
    const start = match.index + match[0].length;
    let end = start,
      depth = 1;
    while (depth) {
      const char = body[end++];
      assert.notEqual(char, undefined);
      if (char === "(") depth++;
      if (char === ")") depth--;
    }
    const expression = body.slice(start, end - 1);
    const expanded = macro
      .replace(/\boperation\b/gu, () => match[1])
      .replace(/\bcall\b/gu, () => expression);
    body = body.slice(0, match.index) + expanded + body.slice(end);
  }
}

test("creator stderr observations preserve native results, errno and SIGPIPE state even on capture failure", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const macro = /^#define IMAGE_CALL\(operation, call\) (.+)$/mu.exec(
    source,
  )[1];
  const note = /static void image_note[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("char bytes[256];", "const bytes={};")
    .replace(
      "sigset_t blocked, previous, pending;",
      "const blocked={},previous={},pending={};",
    )
    .replaceAll(/\((?:unsigned long long|int|size_t|void)\)/gu, "")
    .replaceAll("sizeof(bytes)", "256")
    .replaceAll(/&(blocked|previous|pending)\b/gu, "$1")
    .replace("&received", "{set value(v){received=v}}")
    .replaceAll("NULL", "null")
    .replace(/\b(?:int|bool|ssize_t) /gu, "let ");
  const result = /static long image_result[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("int error", "const error");
  const script = new Script(
    `function image_note(operation,entry,result,error){${note}} function image_result(operation,result){${result}}`,
  );
  for (const fault of [
    null,
    "short",
    "pipe",
    "ignored-pipe",
    "pending-pipe",
    "blocked",
    "format",
    "mask",
    "pending",
  ]) {
    const events = [],
      records = [];
    const originallyBlocked = fault === "blocked" || fault === "pending-pipe";
    let blocked = originallyBlocked,
      pending = fault === "pending-pipe",
      waits = 0;
    const api = {
      errno: 77,
      image_diagnostic_active: true,
      image_diagnostic_failed: false,
      image_diagnostic_records: 0,
      image_diagnostic_sequence: 61,
      image_diagnostic_identity: {
        token: { val: [0, 0, 0, 0, 0, 123, 5, 2] },
        bsd: { pbi_start_tvsec: 100, pbi_start_tvusec: 2 },
      },
      SIGPIPE: 13,
      SIG_BLOCK: 1,
      SIG_SETMASK: 2,
      STDERR_FILENO: 2,
      EPIPE: 32,
      snprintf(out, size, format, ...values) {
        assert.equal(size, 256);
        assert.match(format, /^native-darwin-image-call:/u);
        assert.deepEqual(values.slice(0, 6), [61, 123, 2, 5, 100, 2]);
        out.record = values.slice(6);
        api.errno = 90;
        return fault === "format" ? 256 : 150;
      },
      sigemptyset: () => 0,
      sigaddset: () => 0,
      sigprocmask(how, mask, previous) {
        api.errno = 91;
        if (how === 1) {
          if (fault === "mask") return -1;
          previous.blocked = blocked;
          blocked = true;
        } else blocked = mask.blocked;
        return 0;
      },
      sigpending(out) {
        out.pending = pending;
        return fault === "pending" ? -1 : 0;
      },
      sigismember: (mask) => Number(mask.pending),
      sigwait(_, out) {
        waits++;
        pending = false;
        out.value = 13;
        return 0;
      },
      write(fd, bytes, length) {
        assert.equal(fd, 2);
        assert.equal(length, 150);
        assert.equal(blocked, true);
        events.push(bytes.record[1]);
        records.push(bytes.record);
        api.errno = 32;
        if (fault?.includes("pipe")) {
          if (fault !== "ignored-pipe") pending = true;
          return -1;
        }
        return fault === "short" ? 1 : length;
      },
      native() {
        events.push("native");
        api.errno = 55;
        return -9;
      },
    };
    script.runInNewContext(api);
    assert.equal(
      new Script(
        expandImageCalls('IMAGE_CALL("control/get", native())', macro),
      ).runInNewContext(api),
      -9,
    );
    assert.equal(api.errno, 55, fault);
    assert.equal(blocked, originallyBlocked, fault);
    assert.equal(pending, fault === "pending-pipe", fault);
    assert.equal(waits, fault === "pipe" ? 1 : 0, fault);
    assert.equal(events.filter((event) => event === "native").length, 1);
    if (!fault || fault === "blocked") {
      assert.deepEqual(events, ["entry", "native", "return"]);
      assert.deepEqual(records, [
        ["control/get", "entry", 0, 0],
        ["control/get", "return", -9, 55],
      ]);
      for (let i = 0; i < 200; i++) api.image_note("bounded", true, 0, 0);
      assert.equal(records.length, 128);
      api.image_diagnostic_active = false;
      api.image_diagnostic_records = 0;
      api.image_note("inactive", true, 0, 0);
      assert.equal(records.length, 128);
    } else {
      assert.equal(api.image_diagnostic_failed, true);
      const count = records.length;
      assert.equal(api.image_result("cleanup", 5), 5);
      assert.equal(
        records.length,
        count,
        "failed capture is not retried or treated as a new primary failure",
      );
    }
  }
  const dispatch =
    /\} else if \(!strcmp\(tokens\[0\], "image-creator"\)\) \{([\s\S]*?)\n    \} else if \(!strcmp\(tokens\[0\], "image-probe"/u.exec(
      source,
    )[1];
  const events = [],
    subject = { token: { val: [0, 0, 0, 0, 0, 123] } };
  const api = {
    n: 2,
    sequence: 61,
    case_audit: { subject },
    image_diagnostic_identity: null,
    image_diagnostic_sequence: 0,
    image_diagnostic_records: 99,
    image_diagnostic_failed: true,
    image_diagnostic_active: false,
    need: (ok) => assert.ok(ok),
    errno: 7,
    IMAGE_NOTE(operation, entry) {
      events.push([
        operation,
        entry,
        api.image_diagnostic_active,
        api.image_diagnostic_sequence,
        api.image_diagnostic_identity.token.val[5],
      ]);
    },
    image_begin() {
      events.push(["begin", api.image_diagnostic_active]);
    },
  };
  new Script(dispatch).runInNewContext(api);
  assert.deepEqual(events, [
    ["image-creator-dispatch", true, true, 61, 123],
    ["begin", true],
    ["image-creator-dispatch", false, true, 61, 123],
  ]);
  assert.equal(api.image_diagnostic_active, false);
  assert.equal(api.image_diagnostic_records, 0);
  assert.equal(api.image_diagnostic_failed, false);
});

test("nested creator identity observations distinguish each native call without retrying a refusal", async () => {
  const [header, reader] = await Promise.all(
    ["custody.h", "custody-reader.c"].map((name) =>
      readFile(new URL("../ci/native/darwin/" + name, import.meta.url), "utf8"),
    ),
  );
  const macro = /^#define IMAGE_CALL\(operation, call\) (.+)$/mu.exec(
    reader,
  )[1];
  const body = /static struct identity inspect[^\n]+\{([\s\S]*?)\n\}/u
    .exec(header)[1]
    .replace(
      "struct identity value = {0}; struct proc_bsdinfo after; audit_token_t again;",
      "const value={bsd:{},token:{}},after={},again={};",
    )
    .replaceAll(/sizeof\((?:value.bsd|after)\)/gu, "64")
    .replaceAll("sizeof(again)", "32")
    .replaceAll(/\((?:int|unsigned|task_info_t)\)/gu, "")
    .replaceAll(/&(?:value.bsd|value.token|after|again)\b/gu, (value) =>
      value.slice(1),
    )
    .replaceAll(
      /&(task|count)\b/gu,
      (_, name) => `{get value(){return ${name}},set value(v){${name}=v}}`,
    )
    .replace(/\b(?:mach_port_t|mach_msg_type_number_t|int) /gu, "let ");
  const operations = [
    "inspect/bsd-before",
    "inspect/task-name",
    "inspect/token-before",
    "inspect/bsd-after",
    "inspect/token-after",
    "inspect/name-release",
  ];
  for (const fault of [-1, 0, 1, 2, 3, 4, 5]) {
    const calls = [];
    let native = 0;
    const token = { val: [0, 90001, 90002, 90001, 90002, 123, 5, 2] };
    const invoke = (result) => {
      api.errno = 40 + native;
      return native++ === fault ? -1 : result;
    };
    const api = {
      pid: 123,
      errno: 7,
      MACH_PORT_NULL: 0,
      KERN_SUCCESS: 0,
      TASK_AUDIT_TOKEN_COUNT: 8,
      TASK_AUDIT_TOKEN: 1,
      PROC_PIDTBSDINFO: 2,
      signature_caller: null,
      getpid: () => 1,
      mach_task_self: () => 1,
      need: (ok) => assert.ok(ok),
      memcmp: (a, b) => Number(JSON.stringify(a) !== JSON.stringify(b)),
      proc_pidinfo(pid, kind, _, out) {
        assert.equal(pid, 123);
        assert.equal(kind, 2);
        Object.assign(out, {
          pbi_start_tvsec: 100,
          pbi_start_tvusec: 2,
          pbi_svuid: 90001,
          pbi_svgid: 90002,
          pbi_uid: 90001,
          pbi_gid: 90002,
          pbi_ruid: 90001,
          pbi_rgid: 90002,
        });
        return invoke(64);
      },
      task_name_for_pid(_, pid, out) {
        assert.equal(pid, 123);
        out.value = 9;
        return invoke(0);
      },
      task_info(task, _, out, count) {
        assert.equal(task, 9);
        Object.assign(out, token);
        count.value = 8;
        return invoke(0);
      },
      mach_port_deallocate: () => invoke(0),
      image_note: (operation, entry, result, error) =>
        calls.push({ operation, entry, result, error }),
      image_result(operation, result) {
        api.image_note(operation, false, result, api.errno);
        return result;
      },
    };
    const run = () =>
      new Script(`(()=>{${expandImageCalls(body, macro)}})()`).runInNewContext(
        api,
      );
    if (fault >= 0) assert.throws(run);
    else assert.deepEqual(run().token.val, token.val);
    const reached = operations.slice(0, fault < 0 ? 6 : fault + 1);
    assert.deepEqual(
      calls.map(({ operation, entry }) => [operation, entry]),
      reached.flatMap((operation) => [
        [operation, true],
        [operation, false],
      ]),
    );
    assert.equal(native, reached.length);
    assert.equal(calls.at(-1).result, fault < 0 ? 0 : -1);
    assert.equal(calls.at(-1).error, 40 + reached.length - 1);
  }
});
function fixture(fault) {
  const events = [],
    records = [],
    receipts = new Map();
  let clock = 0,
    reads = 0,
    continued = 0;
  const reader = {
    imageCreator: async () => {
      events.push("creator");
      return {
        version: 3,
        control: false,
        creator,
        closed: fault !== "creator-closure",
      };
    },
    imageProbe: async () => {
      events.push("probe");
      const value = {
        version: 1,
        subject: creator,
        policySha256: "e".repeat(64),
        assetSha256: executable.sha256,
        status: 1,
        prepared: true,
        filesCleanup: 0,
        attributesCleanup: 0,
        read: 0,
        map: 0,
        unchanged: true,
      };
      if (fault === "query-error") value.status = -1;
      if (fault === "wrong-policy") value.policySha256 = "0".repeat(64);
      if (fault === "cleanup") value.filesCleanup = 22;
      if (fault === "map") value.map = -1;
      return value;
    },
    imageExec: async () => {
      events.push("exec");
    },
    imageRead: async () => {
      events.push("inspect");
      reads++;
      return {
        version: 3,
        control: false,
        creator,
        target: fault === "stale" ? creator : target,
        closed: fault !== "closure",
        stopped: fault !== "running",
        cdhash: executable.cdhash,
        imageSha256: fault === "image" ? "c".repeat(64) : executable.sha256,
        policySha256: fault === "policy" ? "d".repeat(64) : "e".repeat(64),
      };
    },
    ownershipReceipt: async (index, pin) => {
      events.push("readback");
      const bytes = receipts.get(index);
      assert.equal(hash(bytes), pin);
      return fault === "readback" ? Buffer.from("changed") : bytes;
    },
    imageContinue: async () => {
      events.push("continue");
      continued++;
      if (fault === "uncertain") throw new Error("uncertain continuation");
    },
  };
  const run = () =>
    admitDarwinImage({
      reader,
      creator,
      helper,
      executable,
      asset: executable,
      execControl: {
        retired: true,
        outputSha256: hash(JSON.stringify(DARWIN_LITERAL_ARGUMENTS) + "\n"),
        image: {
          version: 3,
          control: true,
          execControl: null,
          probe: null,
          witness: {
            version: 3,
            control: true,
            creator: { ...creator, pid: 122, asid: 3 },
            target: { ...target, pid: 122, asid: 3 },
            closed: true,
            stopped: true,
            imageSha256: executable.sha256,
            cdhash: executable.cdhash,
            policySha256: "e".repeat(64),
          },
          creator: { ...creator, pid: 122, asid: 3 },
          target: { ...target, pid: 122, asid: 3 },
          execution: "possible",
          continuation: "possible",
          observationsSha256: hash("control"),
        },
      },
      policySha256: "e".repeat(64),
      now: () => clock,
      guard() {},
      next: async () => {
        events.push("replacement");
        return {
          version: 3,
          phase: "image",
          helper,
          controls: true,
          payload:
            fault === "birth"
              ? { ...target, startMicroseconds: 3 }
              : fault === "epoch"
                ? creator
                : target,
        };
      },
      publish: async (image) => {
        events.push("publish");
        records.push(structuredClone(image));
        if (fault === "persistence" && image.target)
          throw new Error("receipt failure");
        if (fault === "expired" && image.continuation === "possible")
          clock = 30001;
        const bytes = Buffer.from(JSON.stringify(image) + "\n"),
          pin = { index: records.length, sha256: hash(bytes) };
        receipts.set(pin.index, bytes);
        return { pin, bytes };
      },
      observe: async () => {
        events.push("policy");
        return { complete: fault === "drift" ? reads === 1 : true };
      },
    });
  return { run, events, records, continued: () => continued };
}
test("ordinary stopped-image admission persists original ownership, repeats policy and continues once", async () => {
  const f = fixture();
  const value = await f.run();
  assert.deepEqual(value.target, target);
  assert.equal(f.continued(), 1);
  assert.deepEqual(f.events, [
    "creator",
    "publish",
    "readback",
    "publish",
    "readback",
    "probe",
    "publish",
    "readback",
    "exec",
    "replacement",
    "publish",
    "readback",
    "inspect",
    "policy",
    "publish",
    "readback",
    "inspect",
    "policy",
    "continue",
  ]);
  assert.equal(f.records[0].target, null);
  assert.deepEqual(f.records[0].creator, creator);
  assert.equal(f.records.at(-1).continuation, "possible");
});
test("missing closure, substituted provenance, stale epochs, drift and receipt failures never continue", async () => {
  for (const fault of [
    "creator-closure",
    "epoch",
    "birth",
    "stale",
    "closure",
    "running",
    "image",
    "policy",
    "persistence",
    "readback",
    "drift",
    "expired",
    "query-error",
    "wrong-policy",
    "cleanup",
    "map",
  ]) {
    const f = fixture(fault);
    await assert.rejects(f.run(), undefined, fault);
    assert.equal(f.continued(), 0, fault);
    if (f.events.includes("exec"))
      assert.deepEqual(f.records[0].creator, creator);
  }
  const f = fixture("uncertain");
  await assert.rejects(f.run(), /uncertain continuation/u);
  assert.equal(f.continued(), 1);
  assert.equal(f.records.at(-1).continuation, "possible");
});

test("native access validation retains exact alternatives and cleanup ownership on type refusal", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/image-closure.h", import.meta.url),
    "utf8",
  );
  const reader = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const macro = /^#define IMAGE_CALL\(operation, call\) (.+)$/mu.exec(
    reader,
  )[1];
  const body = /static bool image_access[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll("->", ".")
    .replace(/([0-9])U\b/gu, "$1")
    .replace(
      /\b(?:mach_port_t|mach_port_type_t|kern_return_t|natural_t|mach_vm_address_t) /gu,
      "let ",
    )
    .replaceAll("&type", "{set value(v){type=v}}")
    .replaceAll("&kind", "{set value(v){kind=v}}")
    .replaceAll("&object", "{set value(v){object=v}}");
  const SEND = 1,
    ONCE = 2,
    DEAD = 4;
  for (const [port, type, query, kind, objectQuery, accepted, owned] of [
    [0, 0, 0, 0, 0, true, false],
    [-1, 0, 0, 0, 0, true, false],
    [8, DEAD, 0, 0, 0, true, true],
    [8, SEND, 0, 0, 0, true, true],
    [8, SEND | ONCE, 0, 0, 0, false, true],
    [8, ONCE, 0, 0, 0, false, true],
    [8, 16, 0, 0, 0, false, false],
    [8, 0, 0, 0, 0, false, false],
    [8, SEND, 9, 0, 0, false, true],
    [8, SEND, 0, 3, 0, false, true],
    [8, SEND, 0, 0, 9, false, true],
  ]) {
    const calls = [];
    const value = {
      access: port,
      count: port > 0 ? 1 : 0,
      copies: port > 0 ? [port] : [],
    };
    const api = {
      value,
      MACH_PORT_TYPE_NONE: 0,
      MACH_PORT_TYPE_SEND: SEND,
      MACH_PORT_TYPE_SEND_ONCE: ONCE,
      MACH_PORT_TYPE_DEAD_NAME: DEAD,
      MACH_PORT_NULL: 0,
      KERN_SUCCESS: 0,
      MACH_PORT_VALID: (p) => p > 0,
      mach_task_self: () => 1,
      mach_port_type: (_, __, out) => {
        out.value = type;
        return query;
      },
      mach_port_kobject: (_, __, out) => {
        out.value = kind;
        return objectQuery;
      },
      image_mach: (_, result) => result === 0,
      image_assert: (_, ok) => ok,
    };
    api.image_note = (operation, entry) => calls.push([operation, entry]);
    api.image_result = (operation, result) => {
      api.image_note(operation, false);
      return result;
    };
    assert.equal(
      new Script(`(()=>{${expandImageCalls(body, macro)}})()`).runInNewContext(
        passiveObservations(api),
      ),
      accepted,
    );
    const reached =
      port > 0
        ? [
            "access/type",
            ...(query === 0 && type === SEND ? ["access/object"] : []),
          ]
        : [];
    assert.deepEqual(
      calls,
      reached.flatMap((operation) => [
        [operation, true],
        [operation, false],
      ]),
    );
    assert.equal(
      value.copies.some((p) => p === port && p > 0),
      owned,
    );
  }
});

test("native one-shot exec consumes authority before an uncertain write and refuses replay", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = /static void image_exec\(void\) \{([\s\S]*?)\n\}/u.exec(
    source,
  )[1];
  for (const [stale, expired, writeResult] of [
    [false, false, 1],
    [true, false, 1],
    [false, true, 1],
    [false, false, -1],
  ]) {
    const writes = [],
      api = {
        image_phase: 1,
        image_control: false,
        image_probed: true,
        image_control_retired: true,
        case_fenced: false,
        image_creator: { token: { val: [0, 0, 0, 0, 0, creator.pid] } },
        operation_mode: false,
        git_in: 9,
        case_in: 8,
        stdout: {},
        need: (ok) => assert.ok(ok),
        image_deadline: () => assert.equal(expired, false),
        inspect: () => (stale ? target : creator),
        audit_identity_same: () => !stale,
        write: (fd, byte, size) => {
          writes.push([fd, byte, size]);
          return writeResult;
        },
        fputs() {},
      };
    const execute = new Script(body);
    if (stale || expired || writeResult < 0)
      assert.throws(() => execute.runInNewContext(api));
    else execute.runInNewContext(api);
    assert.equal(writes.length, stale || expired ? 0 : 1);
    if (writes.length) {
      assert.equal(api.image_phase, 2);
      assert.throws(() => execute.runInNewContext(api));
      assert.equal(writes.length, 1);
    }
  }
});

test("native image recovery reads completed Git attempts before the current domain without reconstructing authority", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = /static void image_recover[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("struct stat named;", "const named={};")
    .replace("struct stat before, after;", "const before={},after={};")
    .replace("struct case_audit_custody value;", "const value={};")
    .replace("struct identity expected", "const expected")
    .replace(/\b(?:bool|unsigned|int|off_t) /gu, "let ")
    .replaceAll("sizeof(case_audit)", "1")
    .replaceAll("sizeof(value)", "1")
    .replace(/&(named|before|after|value)\b/gu, "$1");
  const record = (subject, closed) => ({
    subject,
    closed,
    version: 1,
    context: "bound-context",
  });
  const completed = record("first", true),
    current = record("second", false);
  for (const [records, subject, expected] of [
    [[completed, current], "first", [true, false]],
    [[completed, current], "second", [true, false]],
    [[completed, current], "third", null],
    [[completed], "second", [false, true]],
    [null, "first", [false, true]],
    [[completed, completed], "first", null],
    [[record("first", false), current], "second", null],
    [[{ ...current, context: "other-context" }], "second", null],
  ]) {
    const calls = [],
      fields = [subject];
    const api = {
      fields,
      image_recovering: false,
      case_fenced: true,
      case_recovery: true,
      entries: [{}, { fd: 7 }],
      errno: 0,
      ENOENT: 2,
      AT_SYMLINK_NOFOLLOW: 1,
      case_context: "bound-context",
      need: (ok) => assert.ok(ok),
      fstatat: () => {
        api.errno = records === null ? 2 : 0;
        return records === null ? -1 : 0;
      },
      case_identity: (value) => value[0],
      case_audit_open: () => 3,
      fstat: (_, out) => {
        out.st_size = records.length;
        return 0;
      },
      read_at: (_, out, __, index) => Object.assign(out, records[index]),
      memcmp: (left, right) => (left === right ? 0 : 1),
      audit_identity_same: (left, right) => left === right,
      same_stat: (before, after) => assert.deepEqual(before, after),
      close: () => 0,
      case_session: (actual, recovering, reconstructing) => {
        assert.equal(actual, fields);
        calls.push([recovering, reconstructing]);
      },
    };
    const run = () => new Script(body).runInNewContext(api);
    if (expected) {
      run();
      assert.deepEqual(calls, [expected]);
      assert.equal(api.image_recovering, true);
    } else {
      assert.throws(run);
      assert.deepEqual(calls, []);
      assert.equal(api.image_recovering, false);
    }
  }
});

test("native image recovery retires only the pinned observer in the original reader audit domain", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = /static bool image_recovery_observer[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("char expected[PATH_MAX];", "const expected={};")
    .replaceAll("sizeof(expected)", "512")
    .replace("struct stat st;", "const st={};")
    .replaceAll("&st", "st")
    .replaceAll("0550", "0o550")
    .replace(/\bunsigned /gu, "let ");
  const path = "/owned/case/custody/observer";
  for (const fault of [
    null,
    "not-recovering",
    "not-fenced",
    "not-recovery",
    "unready",
    "closed",
    "foreign-domain",
    "other-image",
    "changed-image",
    "undeclared-image",
  ]) {
    const reads = [];
    const api = {
      path: fault === "other-image" ? path + "-other" : path,
      image_recovering: fault !== "not-recovering",
      case_fenced: fault !== "not-fenced",
      case_recovery: fault !== "not-recovery",
      case_audit: {
        ready: fault !== "unready",
        closed: fault === "closed",
        owner: { token: { val: [0, 0, 0, 0, 0, 100, 4] } },
      },
      actual: {
        token: {
          val: [0, 0, 0, 0, 0, 101, fault === "foreign-domain" ? 5 : 4],
        },
      },
      case_path: "/owned/case",
      subject_gid: 90002,
      count: 1,
      entries: [
        {
          path: fault === "undeclared-image" ? path + "-other" : path,
          kind: "helper",
          pin: "a".repeat(64),
        },
      ],
      need: (ok) => assert.ok(ok),
      snprintf: (value) => {
        value.text = path;
        return path.length;
      },
      strcmp: (left, right) =>
        (left?.text ?? left) === (right?.text ?? right) ? 0 : 1,
      free() {},
      file: (actual, gid, mode, maximum, pin) => {
        assert.deepEqual(
          [actual, gid, mode, maximum, pin],
          [path, 90002, 0o550, 134217728, "a".repeat(64)],
        );
        reads.push(actual);
        if (fault === "changed-image")
          throw new Error("Changed pinned observer");
      },
    };
    const run = () => new Script(`(()=>{${body}})()`).runInNewContext(api);
    if (["changed-image", "undeclared-image"].includes(fault))
      assert.throws(run);
    else assert.equal(run(), fault === null);
    assert.equal(
      reads.length,
      fault === null || fault === "changed-image" ? 1 : 0,
    );
  }
});

test("native inheritance compares held endpoints in one reader and rejects equally classified substitutes", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const body =
    /  memset\(&image_inspected, 0, sizeof\(image_inspected\)\);[\s\S]*?image_phase = 3;/u
      .exec(source)[0]
      .replaceAll("&image_inspected", "image_inspected")
      .replaceAll("sizeof(image_inspected)", "1")
      .replace(/\bbool /gu, "const ");
  const stopped = {
    token: { val: [0, 0, 0, 0, 0, creator.pid] },
    bsd: { pbi_status: 3 },
  };
  for (const fault of [
    null,
    "access",
    "host",
    "selector",
    "release",
    "drift",
  ]) {
    const events = [],
      inherited = { host: 8, access: 9, resource_unsupported: false },
      inspected = {};
    const api = {
      image_inherited: inherited,
      image_inspected: inspected,
      image_phase: 2,
      target: stopped,
      SSTOP: 3,
      need: (ok) => assert.ok(ok),
      memset: () => {},
      image_inputs: (value) => {
        Object.assign(value, inherited, {
          host: fault === "host" ? 10 : inherited.host,
          access: fault === "access" ? 11 : inherited.access,
          resource_unsupported: fault === "selector",
        });
      },
      image_closure_release: (value) => {
        assert.equal(value, inspected);
        events.push("release");
        return fault !== "release";
      },
      image_failure_cleanup: () => events.push("cleanup"),
      image_closure_require: (_, ok) => assert.ok(ok),
      inspect: () => stopped,
      audit_identity_same: () => fault !== "drift",
    };
    const run = () => new Script(body).runInNewContext(api);
    if (fault) {
      assert.throws(run, undefined, fault);
      assert.equal(api.image_phase, 2);
    } else {
      run();
      assert.equal(api.image_phase, 3);
    }
    assert.deepEqual(events, [
      "release",
      ...(["access", "host", "selector", "release"].includes(fault)
        ? ["cleanup"]
        : []),
    ]);
  }
});

test("native closure releases aliased acquisitions once and retains primary and independent cleanup failures", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/image-closure.h", import.meta.url),
    "utf8",
  );
  const body = /static bool image_closure_release[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll("->", ".")
    .replace(/\b(?:bool|unsigned|mach_port_t|kern_return_t) /gu, "let ")
    .replaceAll("&value.outcome", "value.outcome");
  for (const failure of [false, true]) {
    const observations = [],
      releases = [],
      value = {
        count: 4,
        copies: [8, 8, 0, 9],
        outcome: { issues: ["primary-query"] },
      };
    const api = {
      value,
      IMAGE_NOTE: (...record) => observations.push(record),
      MACH_PORT_NULL: 0,
      KERN_SUCCESS: 0,
      MACH_PORT_VALID: (p) => p > 0,
      mach_task_self: () => 1,
      mach_port_deallocate: (_, port) => {
        releases.push(port);
        return failure ? 5 : 0;
      },
      domain_bootstrap_check: (out, ok, operation, kind, result) => {
        if (!ok) out.issues.push([operation, kind, result]);
        return ok;
      },
    };
    const script = new Script(`(()=>{${body}})()`);
    assert.equal(script.runInNewContext(passiveObservations(api)), !failure);
    assert.deepEqual(releases, [8, 8, 9]);
    assert.equal(script.runInNewContext(passiveObservations(api)), true);
    assert.deepEqual(releases, [8, 8, 9]);
    assert.deepEqual(observations, [
      ["mach_port_deallocate/held-copies", true, 0, 0],
      ["mach_port_deallocate/held-copies", false, failure ? 5 : 0, 0],
      ["mach_port_deallocate/held-copies", true, 0, 0],
      ["mach_port_deallocate/held-copies", false, 0, 0],
    ]);
    assert.equal(value.outcome.issues[0], "primary-query");
    assert.equal(value.outcome.issues.length, failure ? 4 : 1);
  }
});

test("JavaScript admission refusals settle held native references before fenced retirement closes", async () => {
  const [reader, closure] = await Promise.all([
    readFile(
      new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../ci/native/darwin/image-closure.h", import.meta.url),
      "utf8",
    ),
  ]);
  const translate = (body) =>
    body
      .replaceAll("->", ".")
      .replace(/\b(?:bool|unsigned|int|mach_port_t|kern_return_t) /gu, "let ")
      .replaceAll("&value.outcome", "value.outcome")
      .replaceAll("&status", "status")
      .replaceAll(/&(image_inspected|image_inherited)\b/gu, "$1")
      .replaceAll(/^#(?:ifdef NATIVE_CI_EXPERIMENT|endif)$/gmu, "");
  const release =
    /static bool image_closure_release[^\n]+\{([\s\S]*?)\n\}/u.exec(closure)[1];
  const settle = /static bool image_settle\(void\) \{([\s\S]*?)\n\}/u.exec(
    reader,
  )[1];
  const fences = [
    /else if \(!strcmp\(tokens\[0\], "case-fence"\)\) \{([\s\S]*?)\n    \} else if/u.exec(
      reader,
    )[1],
    /static void case_retire\(void\) \{([\s\S]*?)\n\}/u.exec(reader)[1],
  ];
  for (const fault of ["drift", "persistence"])
    for (const failedRelease of [false, true])
      for (const fence of fences) {
        const admission = fixture(fault);
        await assert.rejects(admission.run);
        assert.equal(admission.continued(), 0);
        const releases = [],
          closed = [],
          held = (copies) => ({
            count: copies.length,
            copies,
            outcome: { count: 0, issues: [] },
          }),
          inspected = held([10]),
          inherited = held([8, 8, 9]);
        const api = {
          image_inspected: inspected,
          image_inherited: inherited,
          MACH_PORT_NULL: 0,
          KERN_SUCCESS: 0,
          MACH_PORT_VALID: (port) => port > 0,
          mach_task_self: () => 1,
          mach_port_deallocate: (_, port) => {
            releases.push(port);
            return failedRelease && [9, 10].includes(port) ? 5 : 0;
          },
          domain_bootstrap_check: (
            out,
            ok,
            operation,
            kind,
            value,
            cleanup,
          ) => {
            if (!ok) {
              out.count++;
              out.issues.push({ operation, kind, value, cleanup });
            }
            return ok;
          },
          need: (ok) => assert.ok(ok, "native cleanup refused"),
          case_mode: true,
          case_fenced: false,
          case_policy_possible: false,
          reservation_fd: -1,
          case_pid: 0,
          file_pid: 0,
          case_socket_count: 0,
          count: 0,
          CASE_BASE_COUNT: 13,
          operation_mode: false,
          n: 2,
          reservation_guard() {},
          case_audit_guard() {},
          no_subjects() {},
          case_account() {},
          stdout: {},
          fputs: (value) => closed.push(value),
        };
        const script = new Script(
          `function image_closure_release(value){${translate(release)}}
           function image_settle(){${translate(settle)}}
           (()=>{${translate(fence)}})()`,
        );
        if (failedRelease) {
          assert.throws(
            () => script.runInNewContext(passiveObservations(api)),
            /native cleanup refused/u,
          );
          assert.deepEqual(closed, []);
        } else script.runInNewContext(passiveObservations(api));
        assert.deepEqual(releases, [10, 8, 8, 9]);
        assert.equal(inspected.count + inherited.count, 0);
        const issues = [
          ...inspected.outcome.issues,
          ...inherited.outcome.issues,
        ];
        assert.equal(issues.length, failedRelease ? 2 : 0);
        assert.ok(issues.every(({ cleanup }) => cleanup));
        if (failedRelease)
          assert.throws(
            () => script.runInNewContext(passiveObservations(api)),
            /native cleanup refused/u,
          );
        else script.runInNewContext(passiveObservations(api));
        assert.deepEqual(releases, [10, 8, 8, 9]);
      }
});

test("native registered reads preserve the remote target and settle only successful caller-local acquisitions", async (t) => {
  const source = await readFile(
    new URL("../ci/native/darwin/image-closure.h", import.meta.url),
    "utf8",
  );
  const translate = (body) =>
    body
      .replaceAll("->", ".")
      .replace(
        /mach_port_t registered\[3\] = \{([^;]+)\};/u,
        "const registered=[$1];",
      )
      .replace(/const int slots\[\] = \{([^;]+)\};/u, "const slots=[$1];")
      .replaceAll("&value.outcome", "value.outcome")
      .replace(
        /&value\.(host|access)/gu,
        (_, key) =>
          `{get value(){return value.${key}},set value(v){value.${key}=v}}`,
      )
      .replace(
        /&(registered(?:\[[0-2]\])?|port|type|kind|object|count)(?=[,)])/gu,
        (_, key) => `{get value(){return ${key}},set value(v){${key}=v}}`,
      )
      .replaceAll("*port", "port.value")
      .replaceAll("const char *", "const ")
      .replaceAll("(mach_vm_address_t)", "")
      .replaceAll("sizeof(*registered)", "4")
      .replace(/([0-9])U\b/gu, "$1")
      .replace(
        /\b(?:bool|unsigned|natural_t|mach_port_t|mach_port_type_t|mach_msg_type_number_t|mach_vm_address_t|mach_port_array_t|kern_return_t) /gu,
        "let ",
      );
  const functions = {
    image_mach: "value,result,operation",
    image_assert: "value,ok,operation",
    image_copy: "value,port",
    image_special: "value,task,slot,port",
    image_access: "value",
    image_closure_read: "value,task,thread",
    image_closure_release: "value",
  };
  const definitions = Object.entries(functions)
    .map(([name, parameters]) => {
      const body = new RegExp(
        `static (?:bool|void) ${name}[^\\n]+\\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)[1];
      return `function ${name}(${parameters}){${translate(body)}}`;
    })
    .join("\n");
  const script = new Script(`${definitions}
    const accepted=image_closure_read(value,task,thread);
    const held=value.copies.slice(0,value.count);
    const released=image_closure_release(value);
    ({accepted,held,released});`);
  const caller = 41,
    remote = 97,
    thread = 63,
    dead = 0xffffffff;
  const valid = (port) => port !== 0 && port !== dead;
  const cases = [
    { name: "empty", ports: [0, 0, 0] },
    ...[0, 1, 2].map((slot) => ({
      name: `nonnull slot ${slot}`,
      ports: [0, 0, 0].map((port, index) => (index === slot ? 30 : port)),
    })),
    ...[0, 1, 2].map((slot) => ({
      name: `dead sentinel in slot ${slot}`,
      ports: [0, 0, 0].map((port, index) => (index === slot ? dead : port)),
    })),
    { name: "mixed sentinels and valid reference", ports: [0, dead, 31] },
    { name: "aliases across slots and other getters", ports: [8, 8, 9] },
    { name: "dirty failed getter", ports: [8, 8, 9], get: 5 },
    { name: "failed getter with sentinels", ports: [dead, 0, 31], get: 5 },
    {
      name: "every registered release fails independently",
      ports: [8, 30, 31],
      releaseErrors: [17, 19, 23],
    },
    {
      name: "aliased registered and held release failures",
      ports: [8, 8, 9],
      releaseErrors: [17, 0, 19, 23, 29],
    },
    {
      name: "earlier primary refusal and subsequent exception failure survive cleanup",
      ports: [8, 8, 9],
      special: 6,
      exceptionError: 33,
      releaseErrors: [17, 0, 19],
    },
    {
      name: "dirty getter aliases confer no ownership despite held release failures",
      ports: [8, 8, 9],
      get: 5,
      releaseErrors: [23, 29],
    },
  ];
  for (const scenario of cases)
    await t.test(scenario.name, () => {
      const events = [],
        releases = [],
        value = {
          copies: Array(16).fill(0),
          count: 0,
          host: 0,
          access: 0,
          outcome: { issues: [] },
        };
      const issue = (operation, kind, result, cleanup) => ({
        operation,
        kind,
        value: result,
        cleanup,
      });
      const check = (out, ok, operation, kind, result, cleanup) => {
        if (!ok) out.issues.push(issue(operation, kind, result, cleanup));
        return Boolean(ok);
      };
      const lookup = (target, ...outputs) => {
        assert.equal(target, remote);
        assert.equal(outputs.length, 3);
        assert.equal(new Set(outputs).size, 3);
        assert.deepEqual(
          outputs.map((out) => out.value),
          [0, 0, 0],
        );
        events.push("registered");
        outputs.forEach((out, index) => {
          out.value = scenario.ports[index];
        });
        return scenario.get ?? 0;
      };
      const noVm = () =>
        assert.fail("registered reads must not allocate or release VM");
      const api = {
        value,
        task: remote,
        thread,
        NULL: null,
        KERN_SUCCESS: 0,
        KERN_INVALID_ARGUMENT: 4,
        MACH_PORT_NULL: 0,
        MACH_PORT_TYPE_NONE: 0,
        MACH_PORT_TYPE_SEND: 1,
        MACH_PORT_TYPE_SEND_ONCE: 2,
        MACH_PORT_TYPE_DEAD_NAME: 4,
        TASK_HOST_PORT: 1,
        TASK_ACCESS_PORT: 2,
        TASK_BOOTSTRAP_PORT: 3,
        TASK_DEBUG_CONTROL_PORT: 4,
        TASK_RESOURCE_NOTIFY_PORT: 5,
        MACH_PORT_VALID: valid,
        need: (ok) => assert.ok(ok),
        mach_task_self: () => caller,
        task_get_special_port: (target, slot, out) => {
          assert.equal(target, remote);
          out.value =
            slot === 1
              ? 8
              : slot === 2
                ? 9
                : slot === 3
                  ? (scenario.special ?? 0)
                  : 0;
          return 0;
        },
        mach_port_type: (owner, port, out) => {
          assert.equal(owner, caller);
          assert.ok([8, 9].includes(port));
          out.value = 1;
          return 0;
        },
        mach_port_kobject: (owner, port, kind, object) => {
          assert.equal(owner, caller);
          kind.value = port === 8 ? 3 : 0;
          object.value = 0;
          return 0;
        },
        _kernelrpc_mach_ports_lookup3: lookup,
        // Model task.c's old target allocation: its outputs cannot be read or
        // written in the caller's address space when the inspected task differs.
        mach_ports_lookup: (target, out, count) => {
          const storage = Array(3).fill(0);
          const outputs = storage.map((_, index) => ({
            get value() {
              assert.equal(
                target,
                caller,
                "wrapper output storage belongs to the remote task",
              );
              return storage[index];
            },
            set value(port) {
              assert.equal(target, caller, "RPC output must be caller-local");
              storage[index] = port;
            },
          }));
          const result = lookup(target, ...outputs);
          if (result === 0) {
            out.value = storage;
            count.value = 3;
          }
          return result;
        },
        mach_port_deallocate: (owner, port) => {
          assert.equal(owner, caller);
          assert.ok(valid(port));
          events.push(`release:${port}`);
          releases.push(port);
          return scenario.releaseErrors?.[releases.length - 1] ?? 0;
        },
        image_exceptions: (closure, target, actualThread) => {
          assert.equal(closure, value);
          assert.deepEqual([target, actualThread], [remote, thread]);
          events.push("exceptions");
          return check(
            value.outcome,
            !scenario.exceptionError,
            "image-exceptions-get",
            "mach",
            scenario.exceptionError ?? 0,
            false,
          );
        },
        vm_allocate: noVm,
        vm_deallocate: noVm,
        mach_vm_allocate: noVm,
        mach_vm_deallocate: noVm,
        domain_bootstrap_check: check,
      };
      const result = script.runInNewContext(passiveObservations(api));
      const registered = scenario.get ? [] : scenario.ports.filter(valid);
      const held = [8, 9, ...(scenario.special ? [scenario.special] : [])];
      assert.deepEqual(Array.from(result.held), held);
      assert.deepEqual(releases, [...registered, ...held]);
      assert.deepEqual(events, [
        "registered",
        ...registered.map((port) => `release:${port}`),
        "exceptions",
        ...held.map((port) => `release:${port}`),
      ]);
      const expected = [];
      if (scenario.special)
        expected.push(issue("image-special-empty", "invariant", 0, false));
      if (scenario.get)
        expected.push(
          issue("image-registered-get", "mach", scenario.get, false),
        );
      else if (scenario.ports.some((port) => port !== 0))
        expected.push(issue("image-registered-empty", "invariant", 0, false));
      const releaseIssues = (ports, offset, operation) =>
        ports.flatMap((_, index) => {
          const error = scenario.releaseErrors?.[offset + index] ?? 0;
          return error ? [issue(operation, "mach", error, true)] : [];
        });
      expected.push(
        ...releaseIssues(registered, 0, "image-registered-release"),
      );
      if (scenario.exceptionError)
        expected.push(
          issue("image-exceptions-get", "mach", scenario.exceptionError, false),
        );
      const readIssues = expected.length;
      expected.push(
        ...releaseIssues(held, registered.length, "image-copy-release"),
      );
      assert.deepEqual(value.outcome.issues, expected);
      assert.equal(result.accepted, readIssues === 0);
      assert.equal(result.released, expected.length === readIssues);
      assert.equal(value.count, 0);
    });
});

test("native closure admits absent thread tables, bounds refusal facts and settles both getters", async () => {
  const source = await readFile(
      new URL("../ci/native/darwin/image-closure.h", import.meta.url),
      "utf8",
    ),
    header = await readFile(
      new URL("../ci/native/darwin/custody.h", import.meta.url),
      "utf8",
    );
  const project = (body) =>
    body
      .replaceAll("->", ".")
      .replace(
        /(?:exception_mask_t|mach_port_t|exception_behavior_t|thread_state_flavor_t|int) (\w+)\[EXC_TYPES_COUNT\](?: = \{0\})?/gu,
        "let $1=Array(EXC_TYPES_COUNT).fill(0)",
      )
      .replace("char bytes[256];", "const bytes={};")
      .replace(
        "sigset_t blocked, previous, pending;",
        "const blocked={},previous={},pending={};",
      )
      .replaceAll("sizeof(bytes)", "256")
      .replaceAll("&value.outcome", "value.outcome")
      .replaceAll("&count", "{get value(){return count},set value(v){count=v}}")
      .replace(/&(blocked|previous|pending)\b/gu, "$1")
      .replace("&received", "{set value(v){received=v}}")
      .replace(/\((?:int|size_t|void)\)/gu, "")
      .replace(/\bNULL\b/gu, "null")
      .replace(
        /\b(?:bool|unsigned|kern_return_t|mach_msg_type_number_t|int|ssize_t) /gu,
        "let ",
      );
  const body = project(
      /static bool image_exceptions[^\n]+\{([\s\S]*?)\n\}/u.exec(source)[1],
    ),
    settle = project(
      /static bool domain_exception_settle[^\n]+\{([\s\S]*?)\n\}/u.exec(
        header,
      )[1],
    ),
    script = new Script(
      `function domain_exception_settle(out,handlers,count,releases){${settle}} (()=>{${body}})()`,
    );
  for (const fault of [
    null,
    "thread0",
    "task0",
    "overflow",
    "zero",
    "missing",
    "overlap",
    "unknown",
    "handler",
    "dead",
    "query",
    "thread-query",
    "release",
    "capture",
    "pending-pipe",
    "blocked",
    "short",
    "format",
  ]) {
    const getters = [],
      acquired = [],
      released = [],
      issues = [],
      facts = [];
    const originallyBlocked = fault === "pending-pipe" || fault === "blocked";
    let pending = fault === "pending-pipe",
      blocked = originallyBlocked,
      waits = 0,
      captures = 0;
    const get = (owner, target, mask, masks, count, ports) => {
      getters.push(owner);
      assert.deepEqual(
        [target, mask, api.errno],
        [owner === "task" ? 1 : 2, 7, 77],
      );
      const failed =
        (fault === "query" && owner === "task") ||
        (fault === "thread-query" && owner === "thread");
      [masks[0], masks[1]] = {
        zero: [0, 7],
        missing: [1, 2],
        overlap: [1, 7],
        unknown: [1, 14],
      }[fault] ?? [1, 6];
      count.value =
        failed || fault === "overflow" ? 9 : fault === owner + "0" ? 0 : 2;
      if (
        failed ||
        [
          "handler",
          "release",
          "capture",
          "pending-pipe",
          "blocked",
          "short",
          "format",
          "query",
        ].includes(fault)
      )
        ports[0] = ports[1] = 8;
      if (fault === "dead") ports[0] = 0xffffffff;
      if (!failed)
        for (let i = 0; i < Math.min(count.value, 4); i++)
          if (ports[i] && ports[i] !== 0xffffffff) acquired.push(ports[i]);
      return failed ? 5 : 0;
    };
    const api = passiveObservations({
      value: { outcome: {} },
      task: 1,
      thread: 2,
      EXC_TYPES_COUNT: 4,
      DOMAIN_EXCEPTION_MASK: 7,
      MACH_PORT_NULL: 0,
      KERN_SUCCESS: 0,
      MACH_PORT_VALID: (port) => port !== 0 && port !== 0xffffffff,
      task_get_exception_ports: (...args) => get("task", ...args),
      thread_get_exception_ports: (...args) => get("thread", ...args),
      domain_bootstrap_check(_, ok, operation, kind, value, cleanup) {
        if (!ok) issues.push({ operation, kind, value, cleanup });
        return ok;
      },
      image_mach: (_, result, operation) =>
        api.domain_bootstrap_check(
          null,
          result === 0,
          operation,
          "mach",
          result,
          false,
        ),
      image_assert: (_, ok, operation) =>
        api.domain_bootstrap_check(null, ok, operation, "invariant", 0, false),
      mach_task_self: () => 1,
      mach_port_deallocate(self, port) {
        assert.equal(self, 1);
        assert.equal(port, acquired[released.length]);
        assert.equal(api.errno, 77);
        released.push(port);
        return ["release", "query", "capture"].includes(fault)
          ? released.length + 10
          : 0;
      },
      errno: 77,
      SIGPIPE: 13,
      SIG_BLOCK: 1,
      SIG_SETMASK: 2,
      STDERR_FILENO: 2,
      EPIPE: 32,
      snprintf(out, size, format, ...values) {
        assert.equal(size, 256);
        facts.push({ format, values });
        out.bytes = "bounded exception refusal";
        return fault === "format" ? size : out.bytes.length;
      },
      sigemptyset: () => 0,
      sigaddset: () => 0,
      sigpending: () => 0,
      sigismember: () => Number(pending),
      sigprocmask(how, mask, previous) {
        if (how === 1) {
          previous.blocked = blocked;
          blocked = true;
        } else blocked = mask.blocked;
        return 0;
      },
      write(fd) {
        captures++;
        assert.equal(fd, 2);
        assert.equal(blocked, true);
        if (fault === "capture" || fault === "pending-pipe") {
          api.errno = 32;
          pending = true;
          return -1;
        }
        return fault === "short" ? 24 : 25;
      },
      sigwait() {
        waits++;
        pending = false;
        return 0;
      },
    });
    const accepted = script.runInNewContext(api);
    assert.equal(
      accepted,
      fault === null || fault === "thread0",
      String(fault),
    );
    assert.deepEqual(getters, ["task", "thread"]);
    assert.deepEqual(released, acquired);
    assert.equal(api.errno, 77);
    assert.equal(blocked, originallyBlocked);
    assert.equal(pending, fault === "pending-pipe");
    assert.equal(waits, Number(fault === "capture"));
    assert.equal(facts.length, Number(!accepted));
    assert.equal(captures, Number(!accepted && fault !== "format"));
    if (!accepted) {
      const { format, values } = facts[0];
      assert.equal(values[0], fault === "thread-query" ? "thread" : "task");
      assert.equal(
        values[1],
        fault === "query" || fault === "thread-query" ? 5 : 0,
      );
      if (fault === "query" || fault === "thread-query") {
        assert.match(
          format,
          /count=unavailable.*observed=unavailable.*first-invalid=unavailable/u,
        );
        assert.deepEqual(values.slice(2), [7]);
      } else {
        assert.equal(
          values[2],
          fault === "task0" ? 0 : fault === "overflow" ? 9 : 2,
        );
        assert.equal(values[3], 7);
        assert.equal(
          values[4],
          { task0: 0, missing: 3, unknown: 15 }[fault] ?? 7,
        );
        assert.deepEqual(
          values.slice(5),
          {
            zero: [0, 0],
            overlap: [1, 7],
            unknown: [1, 14],
            overflow: [2, 0],
            task0: [4, 0],
            missing: [4, 0],
          }[fault] ?? [0, 1],
        );
      }
      assert.equal(issues[0].cleanup, false);
      assert.equal(
        issues[0].operation,
        values[1] ? "image-exceptions-get" : "image-exceptions-empty",
      );
      assert.equal(issues[0].value, values[1]);
    }
    if (["release", "query", "capture"].includes(fault))
      assert.deepEqual(
        issues.filter(({ cleanup }) => cleanup).map(({ value }) => value),
        released.map((_, i) => i + 11),
      );
  }
});

test("native sanitation preserves the paired resource selector rule without any access-slot setter", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/image-closure.h", import.meta.url),
    "utf8",
  );
  const body = /static void image_closure_prepare[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll("->", ".")
    .replace(
      "struct image_closure value = {0}; task_t task = mach_task_self(); thread_t thread = mach_thread_self();",
      "const value={outcome:{issues:[]}};let task=mach_task_self(),thread=mach_thread_self();",
    )
    .replace(/const int slots\[\] = \{([^;]+)\};/u, "const slots=[$1];")
    .replaceAll("&value.outcome", "value.outcome")
    .replaceAll("&value", "value")
    .replaceAll("&handoff.attributes", "handoff.attributes")
    .replaceAll("&previous", "{set value(v){previous=v}}")
    .replace(/\b(?:bool|unsigned|mach_port_t|kern_return_t) /gu, "let ");
  const spawn = /static bool image_spawn_inputs[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll("->", ".")
    .replaceAll("&handoff.attributes", "handoff.attributes");
  for (const [get, set, accepted] of [
    [0, 0, true],
    [4, 4, true],
    [4, 0, false],
    [0, 4, false],
    [5, 4, false],
    [4, 5, false],
  ]) {
    const setters = [],
      copies = [],
      handoff = { attributes: {}, files_cleanup: 0, attributes_cleanup: 0 };
    let destroyed = 0,
      read = 0;
    const check = (out, ok, operation) => {
      if (!ok) out.issues.push(operation);
      return ok;
    };
    const api = {
      handoff,
      NULL: null,
      local_bootstrap: 9,
      MACH_PORT_NULL: 0,
      KERN_SUCCESS: 0,
      KERN_INVALID_ARGUMENT: 4,
      TASK_BOOTSTRAP_PORT: 1,
      TASK_DEBUG_CONTROL_PORT: 2,
      TASK_RESOURCE_NOTIFY_PORT: 3,
      DOMAIN_EXCEPTION_MASK: 7,
      EXCEPTION_DEFAULT: 1,
      THREAD_STATE_NONE: 0,
      mach_task_self: () => 1,
      mach_thread_self: () => 2,
      image_copy: (_, port) => {
        if (port > 0) copies.push(port);
      },
      mach_ports_register: () => 0,
      task_get_special_port: (_, slot, out) => {
        out.value = 8;
        return slot === 3 ? get : 0;
      },
      task_set_special_port: (_, slot, port) => {
        setters.push(slot);
        assert.equal(port, 0);
        return slot === 3 ? set : 0;
      },
      task_set_exception_ports: (_, mask) => {
        assert.equal(mask, 7);
        return 0;
      },
      thread_set_exception_ports: (_, mask) => {
        assert.equal(mask, 7);
        return 0;
      },
      image_mach: (value, result, operation) =>
        check(value.outcome, result === 0, operation),
      image_closure_read: () => {
        read++;
        return true;
      },
      image_closure_release: () => true,
      posix_spawnattr_setspecialport_np: () => 0,
      posix_spawnattr_setexceptionports_np: () => 0,
      exec_handoff_posix: (_, result) => result === 0,
      exec_handoff_destroy: () => {
        destroyed++;
      },
      domain_bootstrap_check: check,
      image_closure_require: (_, ok) => assert.ok(ok),
    };
    api.image_spawn_inputs = new Script(
      `(handoff) => {${spawn}}`,
    ).runInNewContext(api);
    if (accepted) new Script(body).runInNewContext(api);
    else assert.throws(() => new Script(body).runInNewContext(api));
    assert.deepEqual(setters, [1, 2, 3]);
    assert.equal(read, 1);
    assert.equal(destroyed, accepted ? 0 : 1);
    assert.equal(copies.filter((port) => port === 8).length, get === 0 ? 3 : 2);
  }
});

test("native continuation reads the protected receipt, reobserves, settles handles and consumes the exact identity once", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = /static void image_continue[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("char path[PATH_MAX];", "const path={};")
    .replace("struct stat st;", "const st={};")
    .replace("struct identity target", "const target")
    .replace("bool released", "const released")
    .replaceAll("sizeof(path)", "512")
    .replaceAll("&image_inherited", "image_inherited")
    .replaceAll("&target.token", "target.token")
    .replaceAll("&st", "st");
  for (const fault of [
    null,
    "receipt",
    "observation",
    "cleanup",
    "deadline",
    "identity",
    "write",
    "signal",
  ]) {
    const events = [],
      expected = {
        token: { val: [0, 0, 0, 0, 0, 123] },
        bsd: { pbi_status: 4 },
      };
    const api = {
      index: 1,
      pin: "a".repeat(64),
      image_phase: 3,
      case_fenced: false,
      entries: [{}, { path: "/synthetic/custody" }],
      image_inherited: {},
      image_target: expected,
      operation_mode: false,
      git_in: 9,
      case_in: 8,
      stdout: {},
      SSTOP: 4,
      need: (ok) => assert.ok(ok),
      strlen: (s) => s.length,
      strspn: (s, chars) => [...s].filter((c) => chars.includes(c)).length,
      snprintf: (out, size, format, root, index) => {
        assert.equal(root, "/synthetic/custody");
        assert.equal(index, 1);
        return 40;
      },
      file: () => {
        events.push("receipt");
        assert.notEqual(fault, "receipt");
        return Buffer.from("receipt");
      },
      free() {},
      image_observe: () => {
        events.push("observe");
        assert.notEqual(fault, "observation");
      },
      image_closure_release: () => {
        events.push("settle");
        return fault !== "cleanup";
      },
      image_closure_require: (_, ok) => assert.ok(ok),
      image_deadline: () => {
        events.push("deadline");
        assert.notEqual(fault, "deadline");
      },
      inspect: (pid) => {
        assert.equal(pid, 123);
        events.push("identity");
        return expected;
      },
      audit_identity_same: () => fault !== "identity",
      write: (fd, byte, count) => {
        events.push("C");
        assert.deepEqual([fd, byte, count], [8, "C", 1]);
        return fault === "write" ? -1 : 1;
      },
      proc_signal_with_audittoken: (token, signal) => {
        events.push("signal");
        assert.equal(token, expected.token);
        assert.equal(signal, 18);
        return fault === "signal" ? -1 : 0;
      },
      SIGCONT: 18,
      fputs() {},
    };
    const execute = new Script(body);
    if (fault) assert.throws(() => execute.runInNewContext(api));
    else execute.runInNewContext(api);
    if (!fault)
      assert.deepEqual(events, [
        "receipt",
        "observe",
        "settle",
        "deadline",
        "identity",
        "C",
        "signal",
      ]);
    if (events.includes("C")) {
      assert.equal(api.image_phase, 4);
      const count = events.length;
      assert.throws(() => execute.runInNewContext(api));
      assert.equal(events.length, count);
    } else assert.ok(!events.includes("signal"));
  }
});

test("legacy Git worker continuation cannot bypass or replay image admission", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = /static void case_resume[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace(
      "audit_token_t token = {{0}};",
      "const token={val:Array(8).fill(0)};",
    )
    .replaceAll(/#(?:ifdef NATIVE_CI_EXPERIMENT|endif)/gu, "")
    .replace("struct identity actual", "const actual")
    .replaceAll("sizeof(token)", "1")
    .replaceAll("&actual.token", "actual.token")
    .replaceAll("&token", "token")
    .replace(/\b(?:unsigned|uint64_t) /gu, "let ");
  for (const pid of [target.pid, target.pid + 1]) {
    const token = {
      val: [
        target.auid,
        target.uid,
        target.gid,
        target.ruid,
        target.rgid,
        pid,
        target.asid,
        target.pidVersion,
      ],
    };
    let signals = 0;
    const api = {
      values: [...token.val, 100, 2, target.svuid, target.svgid].map(String),
      subject_uid: target.uid,
      subject_gid: target.gid,
      git_pid: helper.pid,
      image_creator: { token: { val: [0, 0, 0, 0, 0, target.pid] } },
      SIGCONT: 18,
      stdout: {},
      number: Number,
      operation_guard() {},
      need: (ok) => assert.ok(ok),
      fputs() {},
      inspect: () => ({
        token,
        bsd: {
          pbi_start_tvsec: 100,
          pbi_start_tvusec: 2,
          pbi_svuid: target.svuid,
          pbi_svgid: target.svgid,
        },
      }),
      memcmp: (a, b) => Number(JSON.stringify(a) !== JSON.stringify(b)),
      proc_signal_with_audittoken: () => {
        signals++;
        return 0;
      },
    };
    if (pid === target.pid)
      assert.throws(() => new Script(body).runInNewContext(api));
    else new Script(body).runInNewContext(api);
    assert.equal(signals, pid === target.pid ? 0 : 1);
  }
});

test("native control inspection binds the audit epoch before thread access and settles acquired handles on refusal", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const macro = /^#define IMAGE_CALL\(operation, call\) (.+)$/mu.exec(
    source,
  )[1];
  const body = /static void image_inputs[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace(
      "audit_token_t token = {{0}};",
      "const token={val:Array(8).fill(0)};",
    )
    .replaceAll("->", ".")
    .replaceAll("(task_info_t)", "")
    .replaceAll("(mach_vm_address_t)", "")
    .replaceAll("sizeof(token)", "8")
    .replaceAll("sizeof(*threads)", "4")
    .replaceAll("&token", "token")
    .replaceAll("&expected.token", "expected.token")
    .replaceAll(
      /&(task|threads|count|size)\b/gu,
      (_, key) => `{get value(){return ${key}},set value(v){${key}=v}}`,
    )
    .replaceAll("&value.outcome", "value.outcome")
    .replace(
      /\b(?:task_t|thread_act_array_t|mach_msg_type_number_t|kern_return_t|bool|unsigned) /gu,
      "let ",
    );
  for (const fault of [
    null,
    "control",
    "token-query",
    "epoch",
    "token-count",
    "threads-query",
    "threads-count",
    "closure",
    "array-release",
  ]) {
    const events = [],
      calls = [],
      releases = [],
      issues = [],
      value = { copies: [], outcome: {} },
      expected = { token: { val: [0, 0, 0, 0, 0, 123, 5, 2] } };
    const check = (_, ok, operation) => {
      if (!ok) issues.push(operation);
      return Boolean(ok);
    };
    const api = {
      value,
      expected,
      NULL: null,
      MACH_PORT_NULL: 0,
      KERN_SUCCESS: 0,
      TASK_AUDIT_TOKEN: 1,
      TASK_AUDIT_TOKEN_COUNT: 8,
      mach_task_self: () => 1,
      task_for_pid: (_, pid, out) => {
        assert.equal(pid, 123);
        events.push("control");
        out.value = 99;
        return fault === "control" ? 5 : 0;
      },
      image_copy: (_, port) => {
        events.push("own:" + port);
        value.copies.push(port);
      },
      task_info: (port, flavor, out, count) => {
        assert.deepEqual([port, flavor], [99, 1]);
        events.push("token");
        assert.deepEqual(value.copies, [99]);
        out.val = [...expected.token.val];
        if (fault === "epoch") out.val[7]--;
        count.value = fault === "token-count" ? 7 : 8;
        return fault === "token-query" ? 5 : 0;
      },
      task_threads: (_, out, count) => {
        events.push("threads");
        out.value = fault === "threads-count" ? [55, 55] : [55];
        count.value = out.value.length;
        return fault === "threads-query" ? 5 : 0;
      },
      image_closure_read: () => {
        events.push("closure");
        return fault !== "closure";
      },
      mach_port_deallocate: (_, port) => {
        releases.push(port);
        return 0;
      },
      mach_vm_deallocate: (_, array, size) => {
        events.push("array");
        assert.equal(size, array.length * 4);
        return fault === "array-release" ? 5 : 0;
      },
      image_mach: (value, result, operation) =>
        check(value, result === 0, operation),
      image_assert: check,
      domain_bootstrap_check: check,
      image_failure_cleanup: () => {
        releases.push(...value.copies);
        value.copies.length = 0;
      },
      image_closure_require: (_, ok) => assert.ok(ok),
      need: (ok) => assert.ok(ok),
      memcmp: (a, b) => Number(JSON.stringify(a) !== JSON.stringify(b)),
      inspect: () => expected,
      audit_identity_same: () => true,
    };
    api.image_note = (operation, entry, result, error) =>
      calls.push({ operation, entry, result, error });
    api.IMAGE_NOTE = api.image_note;
    api.image_result = (operation, result) => {
      api.image_note(operation, false, result, api.errno);
      return result;
    };
    const inspected = expandImageCalls(body, macro);
    if (fault)
      assert.throws(() =>
        new Script(inspected).runInNewContext(passiveObservations(api)),
      );
    else new Script(inspected).runInNewContext(passiveObservations(api));
    assert.deepEqual(
      calls.slice(0, 3).map(({ operation, entry }) => [operation, entry]),
      [
        ["image_inputs", true],
        ["control/get", true],
        ["control/get", false],
      ],
    );
    assert.equal(calls[2].result, fault === "control" ? 5 : 0);
    if (!fault)
      assert.deepEqual(
        calls
          .filter(({ operation }) => operation !== "image_inputs")
          .map(({ operation, entry }) => [operation, entry]),
        [
          "control/get",
          "control/token",
          "control/threads",
          "threads/array-release",
        ].flatMap((operation) => [
          [operation, true],
          [operation, false],
        ]),
      );
    assert.ok(
      events.indexOf("own:99") < events.indexOf("token") || fault === "control",
    );
    if (fault === "control") assert.deepEqual(releases, []);
    else if (
      ["token-query", "epoch", "token-count", "threads-query"].includes(fault)
    )
      assert.deepEqual(releases, [99]);
    else if (fault === "threads-count") {
      assert.deepEqual(releases, [55, 55, 99]);
      assert.equal(issues[0], "image-single-thread");
    } else if (fault) assert.deepEqual(releases, [99, 55]);
    else assert.deepEqual(value.copies, [99, 55]);
  }
});

test("native descriptor snapshots distinguish object substitution from unchanged descriptor numbers", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/image-closure.h", import.meta.url),
    "utf8",
  );
  const body = /static bool image_descriptors[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("struct proc_fdinfo fds[8];", "let fds = [];")
    .replaceAll(/\b(?:int|unsigned) /gu, "let ")
    .replaceAll("(unsigned)", "")
    .replaceAll("sizeof(fds)", "8")
    .replaceAll("sizeof(*fds)", "1")
    .replaceAll(
      /struct (?:pipe_fdinfo|socket_fdinfo|vnode_fdinfowithpath) value = \{0\};/gu,
      "let value = {};",
    )
    .replaceAll("sizeof(value)", "1")
    .replaceAll("&value", "value")
    .replaceAll("sizeof(uint64_t)", "1");
  const read = (fault) => {
    const state = Array.from({ length: 8 }, () => Array(4).fill(0));
    const api = {
      pid: 42,
      state,
      PROX_FDTYPE_PIPE: 1,
      PROX_FDTYPE_SOCKET: 2,
      PROX_FDTYPE_VNODE: 3,
      PROC_PIDLISTFDS: 1,
      PROC_PIDFDPIPEINFO: 2,
      PROC_PIDFDSOCKETINFO: 3,
      PROC_PIDFDVNODEPATHINFO: 4,
      memset() {},
      proc_pidinfo(_pid, _op, _arg, fds) {
        fds.push(
          { proc_fd: 0, proc_fdtype: 1 },
          { proc_fd: 1, proc_fdtype: 2 },
          {
            proc_fd: fault === "duplicate" ? 1 : 2,
            proc_fdtype: fault === "unknown" ? 4 : 3,
          },
        );
        return fault === "full" ? 8 : 3;
      },
      proc_pidfdinfo(_pid, fd, _op, value) {
        Object.assign(value, {
          pfi: { fi_openflags: fault === "flags" ? 3 : 1 },
          pipeinfo: {
            pipe_handle: fault === "pipe" ? 22 : 11,
            pipe_peerhandle: 12,
          },
          psi: { soi_so: fault === "socket" ? 22 : 11 },
          pvip: {
            vip_vi: {
              vi_stat: { vst_dev: 1, vst_ino: fault === "vnode" ? 22 : 11 },
            },
          },
        });
        return fault === "query" && fd === 1 ? 0 : 1;
      },
    };
    return {
      valid: new Script(`(() => {${body}})()`).runInNewContext(api),
      state,
    };
  };
  const original = read(null);
  assert.equal(original.valid, true);
  for (const fault of ["duplicate", "unknown", "full", "query"])
    assert.equal(read(fault).valid, false, fault);
  for (const fault of ["flags", "pipe", "socket", "vnode"]) {
    const changed = read(fault);
    assert.equal(changed.valid, true);
    assert.notDeepEqual(changed.state, original.state, fault);
  }
});

test("bound native mapping uses the same readable bytes and arguments and refuses invalid objects, results and settlement", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/exec-handoff.h", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(`static bool ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`, "u")
      .exec(source)[1]
      .replaceAll("->", ".")
      .replace(
        "struct stat before, after; unsigned char sum[32]; char hash[65];",
        "let before={},after={},sum=Buffer.alloc(32),hash=Buffer.alloc(65);",
      )
      .replace(
        "struct stat st = value.object, named;",
        "let st=value.object,named={};",
      )
      .replace("struct stat after;", "let after={};")
      .replace("struct proc_fdinfo fds[512];", "let fds=[];")
      .replace("struct vnode_fdinfowithpath info;", "let info={};")
      .replace(
        "struct vinfo_stat *st = &info.pvip.vip_vi.vi_stat;",
        "let st=info.pvip.vip_vi.vi_stat;",
      )
      .replaceAll("st->", "st.")
      .replaceAll("sizeof(fds[0])", "8")
      .replaceAll("sizeof(fds)", "4096")
      .replaceAll("sizeof(info)", "128")
      .replace("&info", "info")
      .replace("void *mapped", "let mapped")
      .replace("unsigned char *bytes", "let bytes")
      .replaceAll(/&(before|after|named|value\.object)\b/gu, "$1")
      .replaceAll(/\((?:size_t|CC_LONG|unsigned)\)/gu, "")
      .replace(
        'snprintf(hash + 2*i, 3, "%02x", sum[i]);',
        'hash.write(sum[i].toString(16).padStart(2,"0"),2*i);',
      )
      .replaceAll(/\b(?:unsigned|bool|int|size_t|ssize_t) /gu, "let ");
  const functions = ["result", "same", "close", "read", "open", "check", "held"]
    .map((name) => {
      const args = {
        result: "value,ok,operation,result,error",
        same: "a,b",
        close: "value",
        read: "value,bytes",
        open: "value,path,hash",
        check: "value,denied",
        held: "pid,object",
      }[name];
      return `function exec_mapping_${name}(${args}) {${body("exec_mapping_" + name)}}`;
    })
    .join("\n");
  for (const fault of [
    null,
    "open",
    "dup",
    "directory",
    "links",
    "empty",
    "oversize",
    "writable",
    "access",
    "substitution",
    "read",
    "digest",
    "drift",
    "malloc",
    "unmap",
    "close",
    "setup-close",
  ])
    for (const denied of [false, true]) {
      const bytes = fault
          ? Buffer.from("fixed signed image bytes")
          : Buffer.alloc(8192, 42),
        events = [],
        pin = createHash("sha256").update(bytes).digest("hex"),
        value = { fd: -1, object: {}, hash: Buffer.alloc(65) },
        st = {
          st_dev: 1,
          st_ino: 42,
          st_mode:
            fault === "directory"
              ? 0o40550
              : fault === "writable"
                ? 0o100666
                : 0o100550,
          st_uid: 0,
          st_gid: 90002,
          st_nlink: fault === "links" ? 2 : 1,
          st_size:
            fault === "empty"
              ? 0
              : fault === "oversize"
                ? 16777217
                : bytes.length,
        };
      for (const key of ["st_birthtimespec", "st_mtimespec", "st_ctimespec"])
        st[key] = { tv_sec: 1, tv_nsec: 2 };
      let attempt = false,
        statCalls = 0;
      const api = {
        Buffer,
        NULL: null,
        MAP_FAILED: -1,
        PROT_READ: 1,
        PROT_EXEC: 4,
        MAP_PRIVATE: 2,
        EPERM: 1,
        EACCES: 13,
        O_RDONLY: 0,
        O_NONBLOCK: 4,
        O_NOFOLLOW: 8,
        O_CLOEXEC: 16,
        O_ACCMODE: 3,
        F_DUPFD_CLOEXEC: 1,
        F_GETFL: 2,
        errno: 13,
        malloc: (size) => (fault === "malloc" ? null : Buffer.alloc(size)),
        free() {},
        strlen: (text) => text.length,
        memcpy: (out, text) => out.write(text),
        strcmp: (a, b) =>
          String(a).replaceAll("\0", "") === String(b).replaceAll("\0", "")
            ? 0
            : 1,
        memcmp: (a, b, size) =>
          Buffer.compare(a.subarray(0, size), b.subarray(0, size)),
        S_ISREG: (mode) => (mode & 0o170000) === 0o100000,
        open(path, flags) {
          assert.equal(path, "/bound/map-fixture");
          assert.equal(flags, 28);
          events.push("open");
          return fault === "open" ? -1 : 7;
        },
        fcntl(fd, operation, minimum) {
          if (operation === 1) {
            assert.equal(fd, 7);
            assert.equal(minimum, 64);
            events.push("dup");
            return fault === "dup" ? -1 : 64;
          }
          return fault === "access" ? 1 : 0;
        },
        close(fd) {
          events.push("close:" + fd);
          return (fault === "close" && fd === 64) ||
            (fault === "setup-close" && fd === 7)
            ? -1
            : 0;
        },
        fstat(fd, out) {
          assert.equal(fd, 64);
          Object.assign(out, st);
          if (fault === "drift" && ++statCalls > 1) out.st_ino++;
          return 0;
        },
        lstat(_path, out) {
          Object.assign(out, st);
          if (fault === "substitution") out.st_ino++;
          return 0;
        },
        pread(fd, out, size, offset) {
          assert.equal(fd, 64);
          assert.equal(offset, 0);
          assert.equal(size, bytes.length);
          events.push("read");
          bytes.copy(out);
          return fault === "read" ? -1 : bytes.length;
        },
        CC_SHA256(input, size, out) {
          createHash("sha256")
            .update(fault === "digest" ? Buffer.alloc(size) : input)
            .digest()
            .copy(out);
          return out;
        },
        mmap(address, size, protection, flags, fd, offset) {
          events.push("mmap");
          assert.deepEqual(
            [address, size, protection, flags, fd, offset],
            [null, Math.min(bytes.length, 4096), 5, 2, 64, 0],
          );
          api.errno = denied ? 1 : 13;
          return denied ? -1 : Buffer.from(bytes.subarray(0, size));
        },
        munmap(mapped, size) {
          events.push("unmap");
          assert.deepEqual(mapped, bytes.subarray(0, size));
          assert.equal(size, Math.min(bytes.length, 4096));
          return fault === "unmap" ? -1 : 0;
        },
      };
      const native = new Script(
        functions +
          ";({exec_mapping_open,exec_mapping_check,exec_mapping_close,exec_mapping_held})",
      ).runInNewContext(api);
      const opened = native.exec_mapping_open(value, "/bound/map-fixture", pin);
      const valid = !fault || ["unmap", "close"].includes(fault);
      assert.equal(!!opened, valid, fault);
      if (opened) {
        attempt = native.exec_mapping_check(value, denied);
        assert.equal(attempt, fault !== "unmap" || denied, fault);
        if (!fault && !denied) {
          const effects = { ...api },
            initialEvents = [...events];
          for (const [stage, operation, result, error] of [
            ["allocation", "allocation", 0, 0],
            ["before", "fstat-before", -1, 5],
            ["identity-before", "identity-before", 0, 0],
            ["read", "pread", -1, 5],
            ["short", "short-read", bytes.length - 1, 0],
            ["sha256", "sha256", 0, 0],
            ["after-read", "fstat-after-read", -1, 6],
            ["identity-read", "identity-after-read", 0, 0],
            ["hash", "hash", 1, 0],
            ["map", "mmap", -1, 22],
            ["positive", "mmap", -1, 13],
            ["unexpected", "unexpected-map", 0, 0],
            ["prefix", "prefix", -1, 0],
            ["after-map", "fstat-after-map", -1, 7],
            ["identity-map", "identity-after-map", 0, 0],
            ["settlement", "munmap", -1, 8],
            ["close", "close", -1, 9],
          ]) {
            const probe = {
              ...value,
              operation: null,
              result: 0,
              error: 0,
              map: 0,
              map_error: 0,
              unmap: 0,
              unmap_error: 0,
              closed: 0,
              close_error: 0,
            };
            let calls = 0;
            events.length = 0;
            Object.assign(api, {
              malloc(size) {
                events.push("allocate");
                return stage === "allocation" ? null : effects.malloc(size);
              },
              free() {
                events.push("free");
                api.errno = 97;
              },
              fstat(fd, out) {
                events.push("stat" + ++calls);
                effects.fstat(fd, out);
                api.errno = 99;
                if (
                  ["before", "after-read", "after-map"][calls - 1] === stage ||
                  (stage === "unexpected" && calls === 3)
                ) {
                  api.errno = calls === 3 ? 7 : error;
                  return -1;
                }
                if (
                  ["identity-before", "identity-read", "identity-map"][
                    calls - 1
                  ] === stage
                )
                  out.st_ino++;
                return 0;
              },
              pread(...args) {
                const used = effects.pread(...args);
                api.errno = 5;
                return stage === "read"
                  ? -1
                  : stage === "short"
                    ? used - 1
                    : used;
              },
              CC_SHA256(...args) {
                events.push("hash");
                if (stage === "sha256") return null;
                const sum = effects.CC_SHA256(...args);
                if (stage === "hash") sum.fill(0);
                return sum;
              },
              mmap(...args) {
                const mapped = effects.mmap(...args);
                if (["map", "positive"].includes(stage)) {
                  api.errno = error;
                  return -1;
                }
                return stage === "prefix" ? Buffer.alloc(args[1]) : mapped;
              },
              memcmp(...args) {
                events.push("prefix");
                return effects.memcmp(...args);
              },
              munmap(...args) {
                if (stage !== "prefix") effects.munmap(...args);
                else events.push("unmap");
                api.errno = 8;
                return ["unexpected", "settlement"].includes(stage) ? -1 : 0;
              },
              close(fd) {
                effects.close(fd);
                api.errno = 9;
                return -1;
              },
            });
            assert.equal(
              native.exec_mapping_check(
                probe,
                ["map", "unexpected"].includes(stage),
              ),
              stage === "close",
              stage,
            );
            assert.equal(native.exec_mapping_close(probe), false);
            assert.deepEqual(
              [probe.operation, probe.result, probe.error],
              [operation, result, error],
              stage,
            );
            assert.deepEqual([probe.closed, probe.close_error], [-1, 9]);
            if (probe.unmap === 1) assert.equal(probe.unmap_error, 0);
            if (stage === "unexpected") {
              assert.deepEqual(
                [probe.map, probe.map_error, probe.unmap, probe.unmap_error],
                [1, 0, -1, 8],
              );
              assert.deepEqual(events, [
                "allocate",
                "stat1",
                "read",
                "hash",
                "stat2",
                "mmap",
                "unmap",
                "stat3",
                "free",
                "close:64",
              ]);
            }
            if (
              ["allocation", "before", "read", "short", "hash"].includes(stage)
            )
              assert.equal(probe.map, 0);
            if (["map", "positive"].includes(stage))
              assert.deepEqual(
                [probe.map, probe.map_error, probe.unmap],
                [-1, error, 0],
              );
            assert.equal(native.exec_mapping_close(probe), true);
            assert.equal(
              events.filter((event) => event === "close:64").length,
              1,
            );
            assert.deepEqual(
              [probe.operation, probe.result, probe.error],
              [operation, result, error],
            );
          }
          Object.assign(api, effects);
          events.splice(0, events.length, ...initialEvents);
        }
        // A successful outside control never turns an unrelated primary error
        // or unexpected mapping success into denial. Ambient errno is stale.
        for (const error of [1, 13, 2, 12, 22]) {
          api.mmap = () => {
            api.errno = error;
            return -1;
          };
          assert.equal(
            native.exec_mapping_check(value, true),
            [1, 13].includes(error),
          );
          assert.equal(native.exec_mapping_check(value, false), false);
        }
        api.mmap = () =>
          Buffer.from(bytes.subarray(0, Math.min(bytes.length, 4096)));
        assert.equal(native.exec_mapping_check(value, true), false);
        if (!fault) {
          api.PROX_FDTYPE_VNODE = 1;
          api.PROC_PIDLISTFDS = 2;
          api.PROC_PIDFDVNODEPATHINFO = 3;
          const fields = ["dev", "ino", "mode", "uid", "gid", "nlink", "size"],
            held = {};
          for (const key of fields) held["vst_" + key] = st["st_" + key];
          api.proc_pidinfo = (pid, _selector, _arg, out) => {
            assert.equal(pid, 9000);
            out.push({ proc_fd: 64, proc_fdtype: 1 });
            return 8;
          };
          api.proc_pidfdinfo = (_pid, _fd, _selector, out) => {
            out.pvip = { vip_vi: { vi_stat: held } };
            return 128;
          };
          assert.equal(native.exec_mapping_held(9000, st), true);
          for (const key of fields) {
            held["vst_" + key]++;
            assert.equal(native.exec_mapping_held(9000, st), false);
            held["vst_" + key]--;
          }
          api.proc_pidfdinfo = () => 0;
          assert.equal(native.exec_mapping_held(9000, st), false);
          api.proc_pidinfo = () => 4096;
          assert.equal(native.exec_mapping_held(9000, st), false);
          st.st_ino++;
          assert.equal(native.exec_mapping_check(value, true), false);
          st.st_ino--;
        }
      }
      assert.equal(
        native.exec_mapping_close(value),
        !(fault === "close" && opened),
      );
      assert.equal(value.fd, -1);
      if (!valid) assert.equal(events.includes("mmap"), false);
      assert.ok(events.filter((event) => event === "close:64").length <= 1);
    }
});

test("both mapping callers settle both objects before advisory output and preserve refusal on closed capture", async () => {
  for (const [file, owner, prefix, diagnostic] of [
    ["launcher.c", "launcher", "launch", "launch_mapping_diagnostic"],
    ["feasibility-domain.h", "fault", "domain", "domain_mapping_diagnostic"],
  ]) {
    const source = await readFile(
      new URL("../ci/native/darwin/" + file, import.meta.url),
      "utf8",
    );
    const note = new RegExp(
      `static void ${diagnostic}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    )
      .exec(source)[1]
      .replace(
        /const struct exec_mapping \*work = &(\w+), \*authorized = &(\w+);/u,
        "const work=$1, authorized=$2;",
      )
      .replaceAll("->", ".")
      .replace("int saved", "let saved")
      .replaceAll("(void)", "");
    const start = source.indexOf("    bool mapped = exec_mapping_check(");
    const guard = source
      .slice(start, source.indexOf("    mach_port_t local", start))
      .replaceAll(/&(launch|domain)_(mapping|map_control)/gu, "$1_$2")
      .replaceAll("bool ", "let ");
    for (const fault of [
      null,
      "workspace",
      "authorized",
      "both",
      "settlement",
      "pipe",
      "flush",
    ]) {
      const events = [],
        records = [],
        control = fault === "workspace";
      const object = () => ({
        fd: 64,
        operation: null,
        result: 0,
        error: 0,
        map: 0,
        map_error: 0,
        unmap: 0,
        unmap_error: 0,
        closed: 0,
        close_error: 0,
      });
      const work = object(),
        authorized = object();
      let ignored = owner === "fault",
        remembered = false;
      const api = {
        [`${prefix}_mapping`]: work,
        [`${prefix}_map_control`]: authorized,
        domain_record: { control },
        control,
        errno: 77,
        stderr: 2,
        SIGPIPE: 13,
        SIG_IGN: 1,
        exec_mapping_check(value, denied) {
          events.push(value === work ? "workspace" : "authorized");
          assert.equal(denied, value === work && !control);
          const failed =
            value === work
              ? ["workspace", "both", "pipe", "flush"].includes(fault)
              : ["authorized", "both"].includes(fault);
          value.map = failed || denied ? -1 : 1;
          value.map_error = value.map < 0 ? 13 : 0;
          if (failed)
            Object.assign(value, { operation: "mmap", result: -1, error: 13 });
          return !failed;
        },
        exec_mapping_close(value) {
          events.push(value === work ? "close-workspace" : "close-authorized");
          assert.equal(value.fd, 64);
          value.fd = -1;
          api.errno = 91;
          value.closed = ["settlement", "pipe", "flush"].includes(fault)
            ? -1
            : 1;
          value.close_error = value.closed < 0 ? 9 : 0;
          return value.closed > 0;
        },
        signal(sig, disposition) {
          assert.deepEqual([sig, disposition], [13, 1]);
          ignored = true;
        },
        fprintf(fd, format, ...values) {
          assert.equal(fd, 2);
          assert.equal(ignored, true);
          assert.deepEqual(events, [
            "workspace",
            "authorized",
            "close-workspace",
            "close-authorized",
          ]);
          if (owner === "fault") assert.equal(remembered, true);
          assert.match(
            format,
            new RegExp(
              `^native-darwin-mapping: owner=${owner} round=%s workspace=`,
              "u",
            ),
          );
          assert.doesNotMatch(format, /%[px]|path|hash/u);
          let slot = 0;
          const line = format.replace(/%s|%ld|%d/gu, () =>
            String(values[slot++]),
          );
          assert.ok(Buffer.byteLength(line) < 1024);
          assert.equal(line.split("\n").length, 2);
          assert.deepEqual(values, [
            control ? "outside" : "primary",
            work.operation ?? "none",
            work.result,
            work.error,
            work.map,
            work.map_error,
            work.unmap,
            work.unmap_error,
            work.closed,
            work.close_error,
            authorized.operation ?? "none",
            authorized.result,
            authorized.error,
            authorized.map,
            authorized.map_error,
            authorized.unmap,
            authorized.unmap_error,
            authorized.closed,
            authorized.close_error,
          ]);
          records.push(values);
          api.errno = 32;
          return fault === "pipe" ? -1 : 1;
        },
        fflush() {
          api.errno = 28;
          return fault === "flush" ? -1 : 0;
        },
        remember(...args) {
          assert.deepEqual(args, ["fault-image-mapping", "invariant", 0]);
          remembered = true;
        },
        need(ok) {
          if (!ok) {
            assert.equal(api.errno, 91);
            throw new Error("launcher-refusal:126");
          }
        },
        invariant(ok, operation) {
          if (!ok) {
            assert.equal(api.errno, 91);
            throw new Error(operation + ":126");
          }
        },
      };
      const run = () =>
        new Script(
          `function ${diagnostic}(control){${note}} ${guard}; "ready";`,
        ).runInNewContext(api);
      if (fault)
        assert.throws(
          run,
          owner === "fault"
            ? /fault-image-mapping:126/u
            : /launcher-refusal:126/u,
        );
      else assert.equal(run(), "ready");
      assert.equal(records.length, fault ? 1 : 0);
      assert.deepEqual(events, [
        "workspace",
        "authorized",
        "close-workspace",
        "close-authorized",
      ]);
    }
  }
});

test("experimental descriptor sweep retains only the acquired probes until their checked closure", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/launcher.c", import.meta.url),
    "utf8",
  );
  const body = /static void descriptors\(void\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace(/^#.*$/gmu, "")
    .replace("struct proc_fdinfo fds[4096];", "let fds=[];")
    .replaceAll("sizeof(fds[0])", "8")
    .replaceAll("sizeof(fds)", "32768")
    .replaceAll(/\((?:size_t|int)\)/gu, "")
    .replaceAll(/\b(?:unsigned|int|size_t) /gu, "let ")
    .replaceAll("1U", "1");
  for (const fail of [false, true]) {
    const held = new Set([0, 1, 2, 3, 4, 5, 64, 65, 77]),
      closed = [];
    const api = {
      launch_diagnostic: 5,
      launch_mapping: { fd: 64 },
      launch_map_control: { fd: 65 },
      PROC_PIDLISTFDS: 1,
      F_SETFD: 2,
      FD_CLOEXEC: 1,
      getpid: () => 42,
      need: (ok) => assert.ok(ok),
      proc_pidinfo(_pid, _selector, _arg, out) {
        out.length = 0;
        for (const fd of held) out.push({ proc_fd: fd });
        return held.size * 8;
      },
      close(fd) {
        closed.push(fd);
        if (fail) return -1;
        held.delete(fd);
        return 0;
      },
      fcntl: (fd) => {
        assert.ok([3, 4].includes(fd));
        return 0;
      },
    };
    const sweep = new Script(`()=>{${body}}`).runInNewContext(api);
    if (fail) assert.throws(sweep);
    else {
      sweep();
      assert.deepEqual(closed, [77]);
      assert.ok(held.has(64) && held.has(65));
      for (const probe of [api.launch_mapping, api.launch_map_control]) {
        held.delete(probe.fd);
        probe.fd = -1;
      }
      sweep();
      assert.deepEqual([...held], [0, 1, 2, 3, 4, 5]);
    }
  }
});

test("the experimental mapping guard binds only its declared extension and freshly held parent", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/custody-reader.c", import.meta.url),
    "utf8",
  );
  const mapping = /static bool case_has_mapping\(void\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("char expected[PATH_MAX];", "let expected={};")
    .replaceAll("sizeof(expected)", "4096");
  const start = source.slice(source.indexOf("static void case_start("));
  const guard = start
    .slice(
      start.indexOf("  need(case_mode"),
      start.indexOf("  reservation_guard();"),
    )
    .replace(/^#.*$/gmu, "");
  const mappingGuard =
    /static void case_mapping_guard\(pid_t holder\) \{([\s\S]*?)\n\}/u
      .exec(source)[1]
      .replace(
        "struct entry *fixture = &entries[count - 1];",
        "const fixture=entries[count-1];",
      )
      .replaceAll("->", ".")
      .replaceAll(/&entries\[([^\]]+)\]/gu, "entries[$1]")
      .replace("struct stat st, work;", "let st={},work={};")
      .replaceAll(/&(st|work)\b/gu, "$1");
  const mappingCall = /case_mapping_guard\(0\);/u.exec(start)[0];
  for (const fault of [
    null,
    "missing",
    "extra",
    "path",
    "kind",
    "pin",
    "lost-parent",
  ]) {
    const root = "/bound/case",
      entries = Array.from(
        { length: fault === "missing" ? 13 : fault === "extra" ? 15 : 14 },
        (_, index) => ({
          pin: "a",
          fd: index,
          stat: { st_ino: index, st_size: index === 3 ? 0 : 17 },
        }),
      );
    Object.assign(entries.at(-1), {
      kind: fault === "kind" ? "data" : "image",
      path:
        root + "/storage/work/" + (fault === "path" ? "other" : "map-fixture"),
      pin: fault === "pin" ? "b" : "a",
    });
    const api = {
      entries,
      count: entries.length,
      case_path: root,
      case_mode: true,
      case_started: true,
      case_pid: 0,
      case_recovery: false,
      experiment_exec: true,
      CASE_BASE_COUNT: 13,
      PATH_MAX: 4096,
      mode: "literal",
      subject_gid: 90002,
      image_control_cdhash: "signed-control",
      stable: (entry) => assert.ok(entry),
      free() {},
      signature() {},
      file(_path, _gid, _mode, _limit, _pin, out) {
        Object.assign(out, entries.at(-1).stat);
      },
      same_stat: (a, b) => assert.deepEqual({ ...a }, { ...b }),
      fstat(fd, out) {
        assert.equal(fd, 3);
        Object.assign(out, entries[3].stat, { st_size: 128 });
        return 0;
      },
      exec_mapping_held(pid, object) {
        assert.equal(pid, 9000);
        // Provisioning grew the directory after its creation snapshot. Its
        // held vnode must join a fresh size, while inode/ownership stay bound.
        return (
          object.st_ino !== 3 ||
          (object.st_size === 128 && fault !== "lost-parent")
        );
      },
      need: (ok) => assert.ok(ok),
      snprintf: (out, _size, _format, root) => {
        out.value = root + "/storage/work/map-fixture";
        return out.value.length;
      },
    };
    api.strcmp = (a, b) =>
      String(a?.value ?? a) === String(b?.value ?? b) ? 0 : 1;
    const admit = new Script(
      `function case_has_mapping(){${mapping}};function case_mapping_guard(holder){${mappingGuard}};()=>{${guard}${mappingCall}case_mapping_guard(9000);}`,
    ).runInNewContext(api);
    if (fault) assert.throws(admit);
    else admit();
  }
});

test("native exec probes preserve the final handoff and settle separate spawn objects using direct POSIX status", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/exec-handoff.h", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(`static [^\\n]+ ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`, "u")
      .exec(source)[1]
      .replaceAll("->", ".")
      .replaceAll("&probe.files", "probe.files")
      .replaceAll("&probe.attributes", "probe.attributes")
      .replaceAll("&handoff.files", "handoff.files")
      .replaceAll("&handoff.attributes", "handoff.attributes")
      .replace(
        "struct exec_probe result = {.version = 1, .status = -1};",
        "let result = {version:1,status:-1};",
      )
      .replaceAll(/\b(?:int|char|ssize_t) /gu, "let ")
      .replaceAll("*gate", "gate.value")
      .replaceAll(
        "&byte",
        "{get value(){return byte},set value(value){byte=value}}",
      );
  for (const status of [1, 13, 0, -1, 2, 8, 95])
    for (const cleanup of [0, 22])
      for (const prepared of [true, false]) {
        const events = [],
          final = { operation: null },
          probe = {
            attributes_owned: prepared,
            files_owned: true,
            operation: null,
            files: "probe-files",
            attributes: "probe-attributes",
          };
        const api = {
          probe,
          final,
          image: "/sealed/control",
          argv: ["/sealed/control"],
          environment: [],
          NULL: null,
          EPERM: 1,
          EACCES: 13,
          errno: 13,
          posix_spawn(_pid, image, files, attributes) {
            events.push("attempt");
            assert.equal(files, "probe-files");
            assert.equal(attributes, "probe-attributes");
            return status;
          },
          posix_spawn_file_actions_destroy(value) {
            events.push("files");
            assert.equal(value, "probe-files");
            return cleanup;
          },
          posix_spawnattr_destroy(value) {
            events.push("attributes");
            assert.equal(value, "probe-attributes");
            return 0;
          },
          write(fd, byte) {
            assert.equal(fd, 9);
            assert.equal(byte.value, "X");
            events.push("X");
            return 1;
          },
          close(fd) {
            assert.equal(fd, 9);
            events.push("close");
            return 0;
          },
        };
        const run =
          new Script(`function exec_handoff_destroy(handoff) {${body("exec_handoff_destroy")}}
      function exec_handoff_attempt(probe, image, argv, environment) {${body("exec_handoff_attempt")}}
      function exec_handoff_refused(result) {${body("exec_handoff_refused")}}
      const result = exec_handoff_attempt(probe, image, argv, environment);
      const refused = exec_handoff_refused(result); exec_handoff_destroy(probe); ({result, refused});`);
        const value = run.runInNewContext(api);
        assert.equal(value.result.status, prepared ? status : -1);
        assert.equal(
          value.refused,
          prepared && [1, 13].includes(status) && cleanup === 0,
        );
        assert.deepEqual(
          events,
          prepared ? ["attempt", "files", "attributes"] : ["files"],
        );
        assert.equal(final.operation, null);
        assert.equal(probe.files_owned || probe.attributes_owned, false);
        if (value.refused) {
          const gate = { value: 9 };
          const release =
            new Script(`function exec_handoff_check(handoff,ok,operation,kind,value) {${body("exec_handoff_check")}}
        function exec_handoff_byte(handoff,fd,sending,expected) {${body("exec_handoff_byte")}}
        function exec_handoff_close(handoff,fd) {${body("exec_handoff_close")}}
        (handoff,gate) => {${body("exec_handoff_release")}};`).runInNewContext(
              api,
            );
          assert.equal(release(final, gate), true);
          assert.equal(gate.value, -1);
          assert.deepEqual(events.slice(-2), ["X", "close"]);
        }
      }
});
