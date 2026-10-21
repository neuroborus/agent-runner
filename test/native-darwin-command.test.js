import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { Script } from "node:vm";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import {
  runDarwinFeasibilityCommand,
  darwinCommandEnvironment,
  darwinCommandFileObservation,
  settleDarwinCommandCustody,
  observeDarwinCommandBroker,
  darwinCommandCleanupArguments,
  createDarwinAuditDecoder,
} from "../ci/native/darwin/index.js";
import { feasibilityCommandParameters } from "../ci/native/providers/index.js";
import { withNativeDiagnostics } from "../ci/native/index.js";
import { assertDarwinColdStartupTrace } from "../ci/native/darwin/startup-trace.js";

const sha = (value) => createHash("sha256").update(value).digest("hex"),
  PIN = sha("fixture");
const identity = {
  pid: 123,
  pidVersion: 2,
  asid: 17,
  auid: 501,
  uid: 501,
  ruid: 501,
  svuid: 501,
  gid: 20,
  rgid: 20,
  svgid: 20,
  startSeconds: 90,
  startMicroseconds: 1,
};

// Execute the native guards and failure owner; project only C representations
// and header-local macros. Native APIs remain injected, never macOS tools.
function commandGuards(header, helper, body, caller, options = {}) {
  const extract = (source, name) =>
      new RegExp(
        `static [^\\n]+ ${name}\\([^)]*\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)?.[1],
    project = (value) =>
      value
        .replaceAll("->", ".")
        .replace(/^#(?:ifdef|endif).*$/gmu, "")
        .replace("pid_t pids[4096];", "const pids=[];")
        .replace(
          "struct proc_bsdinfo before, after;",
          "const before={}, after={};",
        )
        .replace(
          "auditpinfo_addr_t a={.ap_pid=pids[i]}, b={.ap_pid=pids[i]};",
          "const a={ap_pid:pids[i]}, b={ap_pid:pids[i]};",
        )
        .replace(
          "struct identity member;",
          "const member={token:{val:[]},bsd:{}};",
        )
        .replace(
          /struct identity (value|actual);/gu,
          "const $1={token:{val:[]},bsd:{}};",
        )
        .replace("struct proc_bsdinfo bsd;", "const bsd={};")
        .replace("char byte;", "let byte;")
        .replace("struct timeval time;", "const time={};")
        .replace(
          "auditinfo_addr_t audit={0};",
          "const audit={ai_termid:{},ai_mask:{}};",
        )
        .replaceAll("sizeof(audit)", "1")
        .replace(/(?<!&)&time\b/gu, "time")
        .replace("au_mask_t empty={0,0};", "const empty={};")
        .replace(
          "struct auditpipe_ioctl_preselect choice={0};",
          "const choice={aip_mask:{}};",
        )
        .replace(/sizeof\(pids\)/gu, "4096")
        .replaceAll("sizeof(command_audit_bytes)", "65536")
        .replaceAll(
          "command_audit_bytes+command_pending",
          "command_audit_bytes.subarray(command_pending)",
        )
        .replaceAll(
          "command_audit_bytes+offset",
          "command_audit_bytes.subarray(offset)",
        )
        .replace("unsigned char *bytes=", "const bytes=")
        .replace("bytes+1", "bytes.subarray(1)")
        .replace(
          /sizeof\((?:pid_t|before|after|a|b|member|attempt|bsd|actual.token)\)/gu,
          "1",
        )
        .replace(
          /(?<!&)&(low|high|size|nonblocking)\b/gu,
          (_, name) => `{get value(){return ${name}},set value(v){${name}=v}}`,
        )
        .replace(/(?<!&)&foreign\b/gu, "{set value(v){foreign=v}}")
        .replace(/(?<!&)&right\b/gu, "{set value(v){right=v}}")
        .replace(/(?<!&)&byte\b/gu, "{set value(v){byte=v}}")
        .replace(
          /(?<!&)&(prerequisite_status)\b/gu,
          "{set value(v){prerequisite_status=v}}",
        )
        .replace(/(?<!&)&(\w+\.token|actual|value|bsd)\b/gu, "$1")
        .replace(
          /(?<!&)&(before|after|a|b|member|queue|mode|empty|choice|status|attempt|audit)\b/gu,
          "$1",
        )
        .replaceAll("raw+3", "raw.subarray(3)")
        .replace(/\((?:int|unsigned|void|size_t|uint64_t|pid_t)\)/gu, "")
        .replace(/\blong long /gu, "let ")
        .replace(
          /\b(?:unsigned|int|bool|pid_t|uid_t|au_asid_t|mach_port_t|ssize_t|size_t|uint32_t|uint64_t) /gu,
          "let ",
        )
        .replace(
          /command_native\(([^;]+), ((?:==|!=|>=|<=) [^;]+)\)/gu,
          (_, call, comparison) =>
            `command_native(()=>(${call}),value=>value ${comparison},${JSON.stringify(call + " " + comparison)})`,
        )
        .replace(
          /command_observed\(([^;]+), ([^,;]+), ([^,;]+)\)/gu,
          (_, ok, result, error) =>
            `command_observed(!!(${ok}),${result},${error},${JSON.stringify(ok)})`,
        )
        .replace(
          /\bneed\(([^;]+)\);/gu,
          (_, guard) => `need(!!(${guard}),${JSON.stringify(guard)});`,
        );
  const diagnostics = [],
    calls = [],
    reports = [],
    context = {
      errno: 0,
      stderr: {},
      NULL: null,
      EACCES: 13,
      ENOENT: 2,
      ENOTSUP: 45,
      WNOHANG: 1,
      EINTR: 4,
      ESRCH: 3,
      SIGCONT: 19,
      SIGKILL: 9,
      SIGALRM: 14,
      __func__: caller,
      __LINE__: 1,
      failed_operation: null,
      failed_domain: null,
      failed_value: 0,
      cleanup_operation: null,
      cleanup_domain: null,
      cleanup_value: 0,
      resource_uncertain: false,
      admitted_effects: true,
      prerequisite_mode: false,
      prerequisite_child: -1,
      command_prerequisite: true,
      command_failing: false,
      command_owner: 42,
      command_admissions_closed: false,
      command_cleanup_started: false,
      command_expired: 0,
      command_in: -1,
      command_release: -1,
      command_pending_wrapper: -1,
      command_count: 0,
      command_wrappers: [],
      command_sessions: [],
      strcmp: (a, b) => Number(a !== b),
      getpid: () => 42,
      getuid: () => 0,
      settle_prerequisite() {},
      settle_bundle() {
        context.errno = 90;
      },
      settle_fault() {},
      settle_domain() {
        if (options.cleanup)
          context.remember_cleanup("fixture-close", "errno", 16);
      },
      alarm: () => 0,
      close: () => 0,
      waitpid: () => 0,
      poll: () => 0,
      fprintf(_stream, format, ...values) {
        if (format.startsWith("native-darwin-command-guard:"))
          diagnostics.push(values);
        else reports.push(values);
        context.errno = 91;
      },
      fflush() {
        context.errno = 92;
      },
      _exit(code) {
        throw Object.assign(new Error("Native refusal"), {
          code,
          operation: context.failed_operation,
          kind: context.failed_domain,
          value: context.failed_value,
          cleanup: context.cleanup_operation && [
            context.cleanup_operation,
            context.cleanup_domain,
            context.cleanup_value,
          ],
        });
      },
    };
  Object.assign(context, options.context);
  const owners = [
    [helper, "remember", "operation,domain,value"],
    [helper, "remember_cleanup", "operation,domain,value"],
    [helper, "failure", "code"],
    [header, "command_guard_at", "ok,caller,line,guard,kind,result,error,code"],
    [header, "command_failure", ""],
    ...(options.audit ? [[header, "command_drain", ""]] : []),
    ...(options.membership ? [[header, "command_absent", "pid"]] : []),
    ...(options.lifecycle
      ? [
          [helper, "live", "expected"],
          [helper, "settle_prerequisite", ""],
          [header, "command_continue", "identity"],
        ]
      : []),
  ];
  const declarations = owners
    .map(([source, name, args]) => {
      const native = extract(source, name);
      assert.ok(native, name);
      return `function ${name}(${args}){${project(native)}}`;
    })
    .join("\n");
  const macros = header.replace(/\\\n/gu, "\n"),
    needMacro = /#define need\(ok\) ([^\n]+)/u.exec(macros)?.[1],
    observedMacro =
      /#define command_observed\(ok, result, error\)\s+([^\n]+)/u.exec(
        macros,
      )?.[1],
    nativeMacro =
      /#define command_native\(call, comparison\) do \{([\s\S]*?)\} while \(0\)/u.exec(
        macros,
      )?.[1];
  assert.ok(needMacro && observedMacro && nativeMacro);
  const macroFunctions = `
    function need(ok,guard){${needMacro.replace("#ok", "guard")};}
    function command_observed(ok,result,error,guard){${observedMacro.replace("#ok", "guard")};}
    function command_native(call,compare,guard){${project(
      nativeMacro
        .replace("(call)", "call()")
        .replace("native_result comparison", "compare(native_result)")
        .replace('#call " " #comparison', "guard"),
    )}}
  `;
  const script =
    new Script(`${declarations}\n${macroFunctions}\nObject.assign(globalThis,{remember_cleanup,command_guard_at});
    (...args)=>{${project(body)}}`);
  return {
    run: script.runInNewContext(context),
    context,
    diagnostics,
    calls,
    reports,
  };
}

function commandImageFixture(header, helper, options = {}) {
  const body =
      /static void command_image_identity\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
        header,
      )?.[1],
    metadata = {
      st_mode: 0o100500,
      st_nlink: 1,
      st_uid: 501,
      st_size: options.size ?? 8,
      st_dev: 1,
      st_ino: 2,
      st_mtimespec: { tv_sec: 100, tv_nsec: 1 },
    };
  assert.ok(body);
  const projected = body
      .replace("char actual[4096];", 'const actual={value:""};')
      .replace(
        "struct stat before,after,named;",
        "const before={},after={},named={};",
      )
      .replace(
        "unsigned char bytes[8192],sum[32];",
        "const bytes=Buffer.alloc(8192),sum=Buffer.alloc(32);",
      )
      .replace("CC_SHA256_CTX context;", "const context={};")
      .replace("char hex[65];", 'const hex={value:""};')
      .replaceAll("sizeof(actual)", "4096")
      .replaceAll("sizeof(bytes)", "bytes.length")
      .replaceAll(/&(before|after|named|context)\b/gu, "$1")
      .replaceAll("(pid_t)", "")
      .replaceAll("(CC_LONG)", "")
      .replace(/\b0([0-7]{2,})\b/gu, "0o$1")
      .replaceAll("hex+i*2", "({buffer:hex,offset:i*2})"),
    f = commandGuards(
      header,
      helper,
      `const value=nativeIdentity,path=selectedPath,expected=selectedDigest;${projected}`,
      "command_image_identity",
      { context: { command_prerequisite: false } },
    ),
    counters = { reads: 0, updates: 0, hashed: 0, closes: 0 },
    text = (value) => value?.value ?? value;
  let remaining = options.streamSize ?? metadata.st_size,
    stats = 0;
  Object.assign(f.context, {
    Buffer,
    nativeIdentity: { token: { val: [0, 0, 0, 0, 0, identity.pid] } },
    selectedPath: options.path ?? "/fixture/codex",
    selectedDigest: options.expected ?? PIN,
    command_image: "/fixture/codex",
    command_image_hash: PIN,
    command_uid: 501,
    O_RDONLY: 0,
    O_NOFOLLOW: 1,
    O_CLOEXEC: 2,
    live(value) {
      assert.equal(value.token.val[5], identity.pid);
      f.calls.push("live");
      return true;
    },
    proc_pidpath(pid, target, capacity) {
      assert.equal(pid, identity.pid);
      assert.equal(capacity, 4096);
      target.value = options.kernelPath ?? f.context.selectedPath;
      return target.value.length;
    },
    strcmp: (a, b) => Number(text(a) !== text(b)),
    open(file, flags) {
      assert.equal(text(file), f.context.selectedPath);
      assert.equal(flags, 3);
      f.calls.push("open");
      return 7;
    },
    fstat(fd, target) {
      assert.equal(fd, 7);
      Object.assign(target, structuredClone(metadata));
      if (++stats === 2 && options.substitution === "held") target.st_ino++;
      return 0;
    },
    S_ISREG: (mode) => (mode & 0o170000) === 0o100000,
    read(fd, target, capacity) {
      assert.equal(fd, 7);
      assert.equal(capacity, target.length);
      counters.reads++;
      const count = Math.min(capacity, remaining);
      remaining -= count;
      return count;
    },
    CC_SHA256_Init: () => 1,
    CC_SHA256_Update(_context, buffer, count) {
      assert.ok(count > 0 && count <= buffer.length);
      counters.updates++;
      counters.hashed += count;
      return 1;
    },
    CC_SHA256_Final(sum) {
      Buffer.from(options.actualDigest ?? f.context.selectedDigest, "hex").copy(
        sum,
      );
      return 1;
    },
    lstat(file, target) {
      assert.equal(text(file), f.context.selectedPath);
      Object.assign(target, structuredClone(metadata));
      if (options.substitution === "named") target.st_ino++;
      return 0;
    },
    close(fd) {
      assert.equal(fd, 7);
      counters.closes++;
      return 0;
    },
    snprintf(target, capacity, format, byte) {
      assert.equal(capacity, 3);
      assert.equal(format, "%02x");
      assert.equal(target.offset, target.buffer.value.length);
      target.buffer.value += byte.toString(16).padStart(2, "0");
      return 2;
    },
  });
  return { ...f, counters };
}

test("Darwin command image bounds admit only the configured pinned provider above the helper ceiling", async () => {
  const [header, helper] = await Promise.all(
      ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
        readFile(
          new URL(`../ci/native/darwin/${name}`, import.meta.url),
          "utf8",
        ),
      ),
    ),
    size = 260633072,
    provider = commandImageFixture(header, helper, { size });
  // Stream counts model the retained image; hashing and the 8-KiB buffer stay small.
  provider.run();
  assert.equal(provider.counters.hashed, size);
  assert.equal(provider.counters.updates, Math.ceil(size / 8192));
  assert.equal(provider.counters.reads, Math.ceil(size / 8192) + 1);
  assert.equal(provider.counters.closes, 1);
  assert.deepEqual(provider.calls, ["live", "open", "live"]);
  const helperImage = commandImageFixture(header, helper, {
    path: "/fixture/helper",
    expected: sha("helper"),
  });
  helperImage.run();
  assert.equal(helperImage.counters.hashed, 8);
  for (const options of [
    { size: 536870913 },
    { path: "/fixture/helper", size: 134217729 },
    { path: "/fixture/other", size },
    { expected: sha("different pin"), size },
  ]) {
    const f = commandImageFixture(header, helper, options);
    assert.throws(f.run, (error) => error.code === 126);
    assert.equal(f.counters.reads, 0);
    assert.equal(f.counters.updates, 0);
  }
});

test("Darwin command image streams retain complete hashes, kernel paths and held/named identity", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  for (const options of [
    { streamSize: 9 },
    { streamSize: 7 },
    { actualDigest: sha("different bytes") },
    { substitution: "held" },
    { substitution: "named" },
    { kernelPath: "/fixture/substitute" },
  ]) {
    const f = commandImageFixture(header, helper, options);
    assert.throws(f.run, (error) => error.code === 126);
    assert.equal(f.diagnostics[0][0], "command_image_identity");
    if (options.actualDigest) {
      assert.equal(f.counters.hashed, 8);
      assert.equal(f.counters.closes, 1);
    }
    if (options.streamSize === 9) assert.equal(f.counters.updates, 0);
  }
});

function commandSignalFixture(header, helper, body, options = {}) {
  const original = {
    token: { val: [501, 501, 20, 501, 20, 123, 17, 2] },
    bsd: {
      pbi_start_tvsec: 90,
      pbi_start_tvusec: 1,
      pbi_svuid: 501,
      pbi_svgid: 20,
      pbi_status: 1,
    },
  };
  const f = commandGuards(header, helper, body, "command_entry", {
    lifecycle: true,
    context: { command_prerequisite: options.prerequisite === true },
  });
  let reads = 0,
    signalled = false,
    memberships = 0;
  const gate = [31, 32];
  Object.assign(f.context, {
    child: 123,
    owner: structuredClone(original),
    ready: [33, 34],
    release: gate,
    prerequisite_gate: gate,
    prerequisite_mode: options.prerequisite === true,
    prerequisite_child: -1,
    prerequisite_status: 0,
    prerequisite_signalled: false,
    command_uid: 501,
    command_gid: 20,
    command_helper: "/fixture/helper",
    command_helper_hash: PIN,
    sandbox_binding: {},
    wrapper: 123,
    parent: { token: { val: [501, 501, 20, 501, 20, 42, 3, 1] } },
    PROC_PIDTBSDINFO: 1,
    SZOMB: 5,
    MACH_PORT_NULL: 0,
    KERN_SUCCESS: 0,
    byte: null,
    fd: 35,
    proc_pidinfo(pid, _flavor, _arg, output) {
      assert.equal(pid, 123);
      reads++;
      f.calls.push("live");
      Object.assign(output, original.bsd);
      if (reads === (options.driftAt ?? 1)) {
        if (options.drift === "birth") output.pbi_start_tvusec++;
        if (options.drift === "zombie") output.pbi_status = 5;
        if (options.drift === "saved") output.pbi_svuid++;
      }
      return 1;
    },
    inspect(pid, output) {
      assert.equal(pid, 123);
      Object.assign(output, structuredClone(original));
      if (reads === (options.driftAt ?? 1)) {
        if (options.drift === "version") output.token.val[7]++;
        if (options.drift === "credential") output.token.val[1]++;
        if (options.drift === "asid") output.token.val[6]++;
        if (options.drift === "inspect") return false;
      }
      return true;
    },
    memcmp: (a, b) => Number(JSON.stringify(a) !== JSON.stringify(b)),
    audit_signal(token, signal) {
      assert.deepEqual(Array.from(token.val), original.token.val);
      assert.ok(
        signal === 9 || signal === 19,
        "Only an owned positive control is signalled",
      );
      f.calls.push(["signal", signal]);
      f.context.errno = 97;
      signalled = !options.signal && signal === 9;
      return options.signal ?? 0;
    },
    command_members(asid, signalling) {
      assert.equal(asid, 17);
      assert.equal(signalling, false);
      f.calls.push("members");
      return memberships++ ? (options.survivor ? 1 : 0) : 1;
    },
    audit_session_port(asid, target) {
      assert.equal(asid, 17);
      f.calls.push("hold");
      target.value = 200;
      return 0;
    },
    command_image_identity(value) {
      assert.deepEqual(Array.from(value.token.val), original.token.val);
      f.calls.push("image");
    },
    feasibility_sandbox_active() {
      f.calls.push("sandbox");
      return 1;
    },
    read(fd, target) {
      assert.equal(fd, 33);
      target.value = "W";
      return 1;
    },
    close(fd) {
      f.calls.push(["close", fd]);
      f.context.errno = options.close === fd ? 16 : 0;
      return options.close === fd ? -1 : 0;
    },
    waitpid(pid, target, flags) {
      assert.equal(pid, 123);
      assert.equal(flags, 1);
      f.calls.push("wait");
      f.context.errno = options.wait ? 5 : 0;
      target.value = options.status ?? (signalled ? 9 : 0);
      return options.wait ? -1 : 123;
    },
    WIFEXITED: (status) => status === 0,
    WEXITSTATUS: () => 0,
    WIFSIGNALED: (status) => status > 0,
    WTERMSIG: (status) => status,
    usleep: () => 0,
    mach_task_self: () => 101,
    mach_port_deallocate(self, right) {
      assert.deepEqual([self, right], [101, 200]);
      f.calls.push("release-right");
      return 0;
    },
    write(fd, byte) {
      assert.deepEqual([fd, byte], [32, "P"]);
      f.calls.push("P");
      return 1;
    },
    emit_identity: () => f.calls.push("custody"),
    printf() {},
    puts() {},
  });
  return f;
}

test("Darwin command prerequisite proves positive signal, exact child termination and empty session", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const start = header.indexOf("    prerequisite_child=child;"),
    end = header.indexOf('    printf("{\\"audit\\":true', start);
  assert.ok(start > 0 && end > start);
  const body = header.slice(start, end);
  for (const options of [
    {},
    ...[1, 3, 22].map((signal) => ({ signal })),
    ...[
      "birth",
      "version",
      "credential",
      "asid",
      "saved",
      "zombie",
      "inspect",
    ].map((drift) => ({ drift })),
    { status: 0 },
    { status: 14 },
    { survivor: true },
    { wait: true },
    { close: 31 },
    { close: 32 },
    { signal: 1, wait: true },
    { signal: 22, close: 32, wait: true },
  ]) {
    const f = commandSignalFixture(header, helper, body, {
      ...options,
      prerequisite: true,
    });
    if (Object.keys(options).length === 0) {
      f.run();
      assert.deepEqual(f.calls, [
        ["close", 34],
        ["close", 31],
        "sandbox",
        "hold",
        "members",
        "live",
        ["signal", 9],
        ["close", 32],
        "wait",
        ["close", 33],
        "members",
        "release-right",
        ["close", 35],
      ]);
      assert.equal(f.context.prerequisite_child, -1);
      assert.equal(f.context.resource_uncertain, false);
      continue;
    }
    assert.throws(f.run, (error) => {
      assert.equal(error.code, 78);
      assert.equal(error.operation, "helper-invariant");
      // libproc's returned status, rather than the deliberately stale errno.
      assert.equal(
        error.value,
        options.signal ??
          (options.close === 31 ? 16 : options.survivor ? 1 : 0),
        JSON.stringify(options),
      );
      const cleanup = options.close
        ? ["prerequisite-close", "errno", 16]
        : options.wait
          ? ["prerequisite-wait", "errno", 5]
          : options.status === 14
            ? ["prerequisite-backstop", "invariant", 14]
            : null;
      assert.deepEqual(error.cleanup, cleanup);
      return true;
    });
    assert.equal(f.calls.includes("release-right"), false);
    assert.equal(
      f.reports[0][4],
      "unsettled",
      "Child reaping alone cannot settle possible command-domain effects",
    );
    assert.equal(
      f.calls.includes("wait"),
      true,
      "Refusal independently reaps the EOF-only original child",
    );
    assert.equal(
      f.calls.some((call) => Array.isArray(call) && call[0] === "signal"),
      !options.drift && options.close !== 31,
    );
    if (options.signal) {
      assert.equal(f.diagnostics[0][3], options.signal);
      assert.equal(f.diagnostics[0][4], 97);
    }
  }
});

test("Darwin command admission proves positive-signal permission before its private provider release", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const start = header.indexOf("  command_image_identity(owner,"),
    end = header.indexOf("pid_t child;", start);
  assert.ok(start > 0 && end > start);
  for (const options of [
    {},
    ...[1, 3, 22].map((signal) => ({ signal })),
    ...[1, 2].flatMap((driftAt) =>
      [
        "birth",
        "version",
        "credential",
        "asid",
        "saved",
        "zombie",
        "inspect",
      ].map((drift) => ({ drift, driftAt })),
    ),
  ]) {
    const f = commandSignalFixture(
      header,
      helper,
      header.slice(start, end),
      options,
    );
    if (Object.keys(options).length === 0) {
      f.run();
      assert.deepEqual(f.calls, [
        "image",
        "sandbox",
        "live",
        ["signal", 19],
        "live",
        "custody",
        "P",
        ["close", 32],
      ]);
    } else {
      assert.throws(f.run, { code: 126 });
      assert.equal(f.calls.includes("custody"), false);
      assert.equal(f.calls.includes("P"), false);
      assert.equal(
        f.calls.some((call) => Array.isArray(call) && call[0] === "signal"),
        !options.drift || options.driftAt === 2,
      );
    }
  }
  const gateStart = header.indexOf(
      '    char byte;command_native(write(birth[1],"W",1)',
    ),
    gateEnd = header.indexOf("    posix_spawnattr_t attributes;", gateStart);
  assert.ok(gateStart > 0 && gateEnd > gateStart);
  for (const [count, byte] of [
    [1, "P"],
    [1, "R"],
    [0, ""],
    [-1, ""],
  ]) {
    const f = commandGuards(
      header,
      helper,
      `${header.slice(gateStart, gateEnd)}spawn();`,
      "command_spawn",
      {
        context: { command_prerequisite: false, command_owner: 0 },
      },
    );
    Object.assign(f.context, {
      birth: [40, 41],
      release: [42, 43],
      write(fd, value) {
        assert.deepEqual([fd, value], [41, "W"]);
        f.calls.push("W");
        return 1;
      },
      read(fd, target) {
        assert.equal(fd, 42);
        f.calls.push("read-P");
        target.value = byte;
        return count;
      },
      spawn: () => f.calls.push("spawn"),
    });
    if (count === 1 && byte === "P") {
      f.run();
      assert.deepEqual(f.calls, ["W", "read-P", "spawn"]);
    } else {
      assert.throws(f.run, { code: 126 });
      assert.deepEqual(f.calls, ["W", "read-P"]);
    }
  }
});

test("Darwin command audit prerequisites retain exact native guards through cleanup", async () => {
  const [header, helper] = await Promise.all(
      ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
        readFile(
          new URL(`../ci/native/darwin/${name}`, import.meta.url),
          "utf8",
        ),
      ),
    ),
    body = /static int command_pipe\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      header,
    )?.[1];
  assert.ok(body);
  const operations = [
    "FIONBIO",
    ...[
      "GET_QLIMIT_MIN",
      "GET_QLIMIT_MAX",
      "GET_MAXAUDITDATA",
      "SET_QLIMIT",
      "SET_PRESELECT_MODE",
      "SET_PRESELECT_FLAGS",
      "SET_PRESELECT_NAFLAGS",
      "SET_PRESELECT_AUID",
      "FLUSH",
    ].map((name) => `AUDITPIPE_${name}`),
  ];
  for (const fault of [null, "open", ...operations, "queue"]) {
    const f = commandGuards(
        header,
        helper,
        `const classes=1,uid=501,select=true;${body}`,
        "command_pipe",
        { cleanup: !!fault },
      ),
      context = {
        O_RDONLY: 0,
        O_NONBLOCK: 1,
        O_CLOEXEC: 2,
        AUDITPIPE_PRESELECT_MODE_LOCAL: 1,
      };
    for (const operation of operations) context[operation] = operation;
    Object.assign(f.context, context, {
      open() {
        f.calls.push("open");
        f.context.errno = fault === "open" ? 13 : 0;
        return fault === "open" ? -1 : 7;
      },
      ioctl(fd, operation, target) {
        assert.equal(fd, 7);
        f.calls.push(operation);
        f.context.errno = operation === fault ? 5 : 0;
        if (operation === fault) return -1;
        if (operation === "FIONBIO") assert.equal(target.value, 1);
        if (operation === "AUDITPIPE_GET_QLIMIT_MIN")
          target.value = fault === "queue" ? 2048 : 1;
        if (operation === "AUDITPIPE_GET_QLIMIT_MAX") target.value = 4096;
        if (operation === "AUDITPIPE_GET_MAXAUDITDATA") target.value = 65536;
        return 0;
      },
    });
    if (!fault) {
      assert.equal(f.run(), 7);
      assert.deepEqual(f.calls, ["open", ...operations]);
      continue;
    }
    assert.throws(f.run, (error) => {
      assert.equal(error.code, 78);
      assert.equal(error.operation, "helper-invariant");
      assert.equal(
        error.value,
        fault === "open" ? 13 : fault === "queue" ? 0 : 5,
      );
      assert.deepEqual(error.cleanup, ["fixture-close", "errno", 16]);
      return true;
    });
    const [caller, line, guard, result, error] = f.diagnostics[0];
    assert.equal(caller, "command_pipe");
    assert.ok(line > 0);
    assert.ok(
      guard.includes(
        fault === "open"
          ? "open(/dev/auditpipe)"
          : fault === "queue"
            ? "queue>=low"
            : fault,
      ),
    );
    assert.equal(result, fault === "queue" ? 0 : -1);
    assert.equal(error, fault === "open" ? 13 : fault === "queue" ? 0 : 5);
    assert.deepEqual(
      f.calls,
      fault === "open"
        ? ["open"]
        : fault === "queue"
          ? ["open", ...operations.slice(0, 3)]
          : ["open", ...operations.slice(0, operations.indexOf(fault) + 1)],
    );
    assert.equal(
      f.reports[0][2],
      fault === "open" ? 13 : fault === "queue" ? 0 : 5,
    );
  }
});

function commandDrainFixture(
  header,
  helper,
  chunks = [],
  body = "command_drain();stdin();",
) {
  const f = commandGuards(header, helper, body, "command_drain", {
    audit: true,
    cleanup: true,
    context: { command_prerequisite: false, command_owner: 0 },
  });
  f.chunks = [...chunks];
  f.records = [];
  Object.assign(f.context, {
    EAGAIN: 35,
    AUT_HEADER32: 0x14,
    AUT_HEADER64: 0x74,
    AUT_HEADER32_EX: 0x15,
    AUT_HEADER64_EX: 0x79,
    command_audit: 7,
    command_audit_bytes: Buffer.alloc(65536),
    command_pending: 0,
    command_bytes: 0,
    command_records: 0,
    command_rights: [],
    KERN_SUCCESS: 0,
    stopping: false,
    command_health: () => f.calls.push("health"),
    command_u32: (bytes) => bytes.readUInt32BE(0),
    read(fd, target, capacity) {
      assert.equal(fd, 7);
      assert.equal(target.length, capacity);
      f.calls.push("read");
      const chunk = f.chunks.shift() ?? { error: 35 };
      if (!Buffer.isBuffer(chunk)) {
        f.context.errno = chunk.error;
        if (chunk.expired) f.context.command_expired = 1;
        return chunk.error ? -1 : 0;
      }
      const size = Math.min(chunk.length, capacity);
      chunk.copy(target, 0, 0, size);
      if (size < chunk.length) f.chunks.unshift(chunk.subarray(size));
      return size;
    },
    command_record(bytes, size) {
      // The unchanged libbsm token decoder is separate from this stream fixture.
      assert.equal(bytes.readUInt32BE(1), size);
      f.records.push(Buffer.from(bytes.subarray(0, size)));
      f.onRecord?.();
    },
    memmove: (target, source, size) => source.copy(target, 0, 0, size),
    memset: (target, value, size) => target.fill(value, 0, size),
    stdin: () => f.calls.push("stdin"),
    close(fd) {
      assert.equal(fd, 7);
      f.calls.push("close");
      return 0;
    },
    printf: (format) =>
      f.calls.push(format.includes('"barrier"') ? "barrier" : "capture-end"),
    puts: () => f.calls.push("S"),
  });
  return f;
}

test("Darwin command empty drains permit stdin and EINTR retries stop at expiry with their original cause", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const empty = commandDrainFixture(header, helper);
  empty.run();
  assert.deepEqual(empty.calls, ["health", "read", "health", "stdin"]);
  assert.equal(empty.context.command_records, 0);
  assert.equal(empty.context.command_bytes, 0);
  const retry = commandDrainFixture(header, helper, [{ error: 4 }]);
  retry.run();
  assert.deepEqual(retry.calls, ["health", "read", "read", "health", "stdin"]);
  for (const fault of ["expired", "interrupted", "read", "eof"]) {
    const f = commandDrainFixture(header, helper, [
      {
        error: fault === "interrupted" ? 4 : fault === "read" ? 5 : 0,
        expired: fault === "interrupted",
      },
    ]);
    if (fault === "expired") f.context.command_expired = 1;
    assert.throws(f.run, (error) => {
      assert.equal(error.code, 126);
      assert.equal(
        error.kind,
        fault === "read" ? "errno" : fault === "eof" ? "status" : "invariant",
      );
      assert.equal(error.value, fault === "read" ? 5 : 0);
      assert.deepEqual(error.cleanup, ["fixture-close", "errno", 16]);
      return true;
    });
    assert.equal(
      f.calls.filter((call) => call === "read").length,
      fault === "expired" ? 0 : 1,
    );
    assert.equal(f.calls.includes("stdin"), false);
  }
});

test("Darwin command drain retains split and coalesced BSM records, bounds and incomplete terminal tails", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const record = (type = 0x14, size = 68) => {
    const bytes = Buffer.alloc(size);
    bytes[0] = type;
    bytes.writeUInt32BE(size, 1);
    return bytes;
  };
  const records = [record(), record(0x74), record(0x15), record(0x79)],
    joined = Buffer.concat(records),
    f = commandDrainFixture(header, helper, [joined.subarray(0, 3)]);
  f.run();
  assert.equal(f.context.command_pending, 3);
  assert.equal(f.records.length, 0);
  f.chunks.push(joined.subarray(3, 2 * 68 + 7));
  f.run();
  assert.deepEqual(f.records, records.slice(0, 2));
  assert.equal(f.context.command_pending, 7);
  f.chunks.push(joined.subarray(2 * 68 + 7));
  f.run();
  assert.deepEqual(f.records, records);
  assert.equal(f.context.command_pending, 0);
  assert.equal(f.context.command_records, 4);
  assert.equal(f.context.command_bytes, joined.length);
  for (const coalesced of [false, true]) {
    const f = commandDrainFixture(
      header,
      helper,
      coalesced ? [joined] : records,
    );
    f.onRecord = () => {
      if (f.records.length === 2) f.context.command_expired = 1;
    };
    assert.throws(f.run, { code: 126 });
    assert.deepEqual(f.records, records.slice(0, 2));
    assert.equal(
      f.calls.filter((call) => call === "read").length,
      coalesced ? 1 : 2,
    );
  }
  for (const mutate of [
    (bytes) => {
      bytes[0] = 0;
    },
    (bytes) => bytes.writeUInt32BE(17, 1),
    (bytes) => bytes.writeUInt32BE(65537, 1),
  ]) {
    const bytes = record();
    mutate(bytes);
    const f = commandDrainFixture(header, helper, [bytes]);
    assert.throws(f.run, { code: 126 });
    assert.equal(f.records.length, 0);
  }
  const maximum = commandDrainFixture(header, helper, [record(0x14, 65536)]);
  maximum.run();
  assert.equal(maximum.context.command_pending, 0);
  assert.equal(maximum.records[0].length, 65536);
  for (const limit of ["records", "bytes"]) {
    const f = commandDrainFixture(header, helper, [
      Buffer.concat(records.slice(0, 2)),
    ]);
    if (limit === "records") f.context.command_records = 4095;
    else f.context.command_bytes = 8388608 - 2 * 68 + 1;
    assert.throws(f.run, { code: 126 });
    assert.equal(f.records.length, limit === "records" ? 1 : 0);
  }
  const start = header.indexOf('else if(!strcmp(line,"S")){'),
    end = header.indexOf("\n    else need(0);", start),
    terminal = header
      .slice(start + 'else if(!strcmp(line,"S")){'.length, end)
      .trim()
      .slice(0, -1);
  assert.ok(start > 0 && end > start);
  for (const incomplete of [false, true]) {
    const f = commandDrainFixture(
      header,
      helper,
      incomplete ? [joined.subarray(0, 3)] : [joined],
      terminal,
    );
    if (incomplete) {
      assert.throws(f.run, { code: 126 });
      assert.equal(f.calls.includes("close"), false);
      assert.equal(f.calls.includes("capture-end"), false);
    } else {
      f.run();
      assert.equal(f.context.stopping, true);
      assert.deepEqual(f.calls.slice(-3), ["close", "capture-end", "S"]);
    }
  }
  const barrier = /static void command_barrier\(void\) \{([\s\S]*?)\n\}/u.exec(
    header,
  )?.[1];
  assert.ok(barrier);
  for (const incomplete of [false, true]) {
    const f = commandDrainFixture(
      header,
      helper,
      incomplete ? [joined.subarray(0, 3)] : [],
      barrier,
    );
    let stamp = 100;
    Object.assign(f.context, {
      command_barriers: 0,
      command_latest_record_time: 0,
      command_previous_barrier_time: 0,
      command_clock: () => ++stamp,
      command_poll() {
        if (incomplete) f.context.command_expired = 1;
      },
    });
    if (incomplete) {
      assert.throws(f.run, { code: 126 });
      assert.equal(f.calls.includes("barrier"), false);
    } else {
      f.run();
      assert.equal(f.context.command_barriers, 1);
      assert.equal(f.calls.includes("barrier"), true);
    }
  }
});

test("Darwin command initial guards preserve prerequisite entry order and session refusals", async () => {
  const [header, helper] = await Promise.all(
      ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
        readFile(
          new URL(`../ci/native/darwin/${name}`, import.meta.url),
          "utf8",
        ),
      ),
    ),
    start = header.indexOf("  uid_t real_uid=getuid()"),
    end = header.indexOf('  if(!strcmp(argv[1],"command-observe"))', start),
    checks = [
      "getuid",
      "geteuid",
      "audit_signal",
      "feasibility_sandbox_available",
    ];
  assert.ok(
    start > header.indexOf('if(!strcmp(argv[1],"command-case"))') &&
      end > start,
  );
  assert.ok(
    header.indexOf("command_prerequisite=!strcmp", end) >
      header.indexOf('"command-verify"', end),
  );
  for (const fault of [null, ...checks]) {
    const f = commandGuards(
      header,
      helper,
      header.slice(start, end),
      "command_entry",
      { context: { command_prerequisite: false, command_owner: 0 } },
    );
    Object.assign(f.context, {
      getuid() {
        f.calls.push("getuid");
        return fault === "getuid" ? 501 : 0;
      },
      geteuid() {
        f.calls.push("geteuid");
        return fault === "geteuid" ? 501 : 0;
      },
      audit_signal: fault === "audit_signal" ? null : () => 0,
      sandbox_binding: {},
      feasibility_sandbox_available() {
        f.calls.push("feasibility_sandbox_available");
        return fault !== "feasibility_sandbox_available";
      },
    });
    if (!fault) {
      f.run();
      assert.deepEqual(f.calls, [
        "getuid",
        "geteuid",
        "feasibility_sandbox_available",
      ]);
      continue;
    }
    assert.throws(f.run, { code: 78 });
    assert.equal(f.diagnostics[0][0], "command_entry");
    assert.ok(f.diagnostics[0][2].includes(fault));
    assert.deepEqual(
      f.calls,
      fault === "getuid"
        ? ["getuid"]
        : fault === "feasibility_sandbox_available"
          ? ["getuid", "geteuid", "feasibility_sandbox_available"]
          : ["getuid", "geteuid"],
    );
  }
  const escapeStart = header.indexOf("      errno=0;int changed=setaudit_addr"),
    escapeEnd = header.indexOf("      char byte;", escapeStart);
  assert.ok(escapeStart > start && escapeEnd > escapeStart);
  for (const fault of [null, "session", "foreign-status", "foreign-slot"]) {
    const f = commandGuards(
      header,
      helper,
      header.slice(escapeStart, escapeEnd),
      "command_entry",
      { cleanup: !!fault },
    );
    Object.assign(f.context, {
      EPERM: 1,
      MACH_PORT_NULL: 0,
      attempt: {},
      parent: { token: { val: [0, 0, 0, 0, 0, 0, 3] } },
      setaudit_addr() {
        f.calls.push("setaudit_addr");
        f.context.errno = fault === "session" ? 0 : 1;
        return fault === "session" ? 0 : -1;
      },
      audit_session_port(asid, target) {
        assert.equal(asid, 3);
        f.calls.push("audit_session_port");
        target.value = fault === "foreign-slot" ? 200 : 0;
        f.context.errno = 0;
        return fault === "foreign-status" ? 0 : 5;
      },
    });
    if (!fault) {
      f.run();
      assert.deepEqual(f.calls, ["setaudit_addr", "audit_session_port"]);
      continue;
    }
    assert.throws(f.run, (error) => {
      assert.equal(error.code, 78);
      assert.deepEqual(error.cleanup, ["fixture-close", "errno", 16]);
      return true;
    });
    assert.deepEqual(
      f.calls,
      fault === "session"
        ? ["setaudit_addr"]
        : ["setaudit_addr", "audit_session_port"],
    );
    assert.equal(f.diagnostics[0][0], "command_entry");
    assert.ok(
      f.diagnostics[0][2].includes(
        fault === "session"
          ? "changed==-1"
          : fault === "foreign-status"
            ? "acquired!=0"
            : "foreign==MACH_PORT_NULL",
      ),
    );
  }
});

test("Darwin command membership errors stop at their native call and preserve the first cleanup cause", async () => {
  const [header, helper] = await Promise.all(
      ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
        readFile(
          new URL(`../ci/native/darwin/${name}`, import.meta.url),
          "utf8",
        ),
      ),
    ),
    body = /static unsigned command_members\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      header,
    )?.[1],
    operations = [
      "list",
      "bsd-before",
      "audit-before",
      "bsd-after",
      "audit-after",
      "inspect",
    ];
  assert.ok(body);
  for (const fault of [null, ...operations]) {
    const f = commandGuards(
      header,
      helper,
      `const asid=55,signal_members=true;${body}`,
      "command_members",
      { cleanup: !!fault, context: { command_prerequisite: false } },
    );
    let bsds = 0,
      audits = 0;
    const sample = (name) => {
      f.calls.push(name);
      f.context.errno = fault === name ? 5 : 0;
      return fault !== name;
    };
    Object.assign(f.context, {
      PROC_ALL_PIDS: 1,
      PROC_PIDTBSDINFO: 2,
      A_GETPINFO_ADDR: 3,
      SZOMB: 5,
      proc_listpids(_kind, _unused, pids) {
        pids.push(42);
        return sample("list") ? 1 : 0;
      },
      proc_pidinfo(pid, _kind, _unused, value) {
        assert.equal(pid, 42);
        if (!sample(bsds++ ? "bsd-after" : "bsd-before")) return 0;
        Object.assign(value, {
          pbi_start_tvsec: 90,
          pbi_start_tvusec: 1,
          pbi_uid: 501,
          pbi_status: 1,
        });
        return 1;
      },
      auditon(_kind, value) {
        if (!sample(audits++ ? "audit-after" : "audit-before")) return -1;
        Object.assign(value, { ap_asid: 55, ap_auid: 501 });
        return 0;
      },
      inspect(pid, value) {
        assert.equal(pid, 42);
        value.token.val[6] = 55;
        Object.assign(value.bsd, { pbi_start_tvsec: 90, pbi_start_tvusec: 1 });
        return sample("inspect");
      },
      signal_identity(value, signal) {
        assert.equal(value.token.val[6], 55);
        assert.equal(signal, 9);
      },
    });
    if (!fault) {
      assert.equal(f.run(), 1);
      assert.deepEqual(f.calls, operations);
      continue;
    }
    assert.throws(f.run, (error) => {
      assert.equal(error.code, 126);
      assert.deepEqual(error.cleanup, ["fixture-close", "errno", 16]);
      return true;
    });
    assert.deepEqual(
      f.calls,
      operations.slice(0, operations.indexOf(fault) + 1),
    );
    assert.equal(f.diagnostics[0][0], "command_members");
    if (fault !== "inspect") assert.equal(f.diagnostics[0][4], 5);
  }
  const f = commandGuards(
    header,
    helper,
    "command_native(ioctl(7,AUDITPIPE_FLUSH,NULL), == 0);",
    "command_pipe",
    {
      context: {
        command_prerequisite: false,
        command_count: 1,
        command_sessions: [55],
        command_wrappers: [42],
      },
    },
  );
  Object.assign(f.context, {
    AUDITPIPE_FLUSH: 1,
    ioctl() {
      f.context.errno = 5;
      return -1;
    },
    command_members() {
      f.context.command_guard_at(
        false,
        "command_members",
        2,
        "auditon",
        "errno",
        -1,
        13,
        126,
      );
    },
  });
  assert.throws(f.run, (error) => {
    assert.equal(error.code, 126);
    assert.equal(error.value, 5);
    assert.deepEqual(error.cleanup, ["helper-invariant", "errno", 13]);
    return true;
  });
  assert.equal(f.diagnostics.length, 2);
  assert.deepEqual(
    f.reports
      .filter((values) => values[0] === "helper-invariant")
      .map((values) => values[2]),
    [5, 5, 13],
  );
});
test("Darwin census disappearance needs repeated complete absence and rejects replacement births", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const body =
    /static unsigned command_members\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      header,
    )?.[1];
  assert.ok(body);
  for (const fault of [
    "nonempty",
    "gone-before",
    "gone-audit",
    "gone-after",
    "gone-audit-after",
    "present",
    "replaced",
    "incomplete",
    "inventory-error",
    "duplicate",
    "permission",
    "birth",
  ]) {
    const f = commandGuards(
      header,
      helper,
      `const asid=55,signal_members=false;${body}`,
      "command_members",
      {
        membership: true,
        context: { command_prerequisite: false, command_owner: 0 },
      },
    );
    let lists = 0,
      bsds = 0,
      audits = 0;
    const failed = (operation) =>
      fault === operation ||
      ([
        "present",
        "replaced",
        "incomplete",
        "inventory-error",
        "permission",
        "duplicate",
      ].includes(fault) &&
        operation === "gone-before");
    Object.assign(f.context, {
      PROC_ALL_PIDS: 1,
      PROC_PIDTBSDINFO: 2,
      A_GETPINFO_ADDR: 3,
      SZOMB: 5,
      proc_listpids(_kind, _uid, pids) {
        lists++;
        f.context.errno = 0;
        if (lists === 1 || ["present", "replaced"].includes(fault))
          pids.push(42);
        else {
          pids.push(43);
          if (fault === "duplicate") pids.push(43);
        }
        if (lists > 1 && fault === "inventory-error") {
          f.context.errno = 5;
          return 0;
        }
        return lists > 1 && fault === "incomplete" ? 4096 : pids.length;
      },
      proc_pidinfo(_pid, _kind, _flavor, value) {
        f.context.errno = 0;
        const operation = bsds++ ? "gone-after" : "gone-before";
        if (failed(operation)) {
          f.context.errno = fault === "permission" ? 13 : 3;
          return 0;
        }
        Object.assign(value, {
          pbi_start_tvsec: 90,
          pbi_start_tvusec: fault === "birth" && bsds > 1 ? 2 : 1,
          pbi_uid: 501,
          pbi_gid: 20,
          pbi_status: 1,
        });
        return 1;
      },
      auditon(_kind, value) {
        f.context.errno = 0;
        const operation = audits++ ? "gone-audit-after" : "gone-audit";
        if (failed(operation)) {
          f.context.errno = 3;
          return -1;
        }
        Object.assign(value, { ap_asid: 55, ap_auid: 501 });
        return 0;
      },
      inspect() {
        assert.fail("Unproved snapshots never acquire a signal identity");
      },
    });
    if (fault === "nonempty") {
      assert.equal(f.run(), 1);
      assert.equal(lists, 1);
    } else if (fault.startsWith("gone-")) {
      assert.equal(f.run(), 0, fault);
      assert.equal(lists, 3, fault);
      assert.equal(f.context.failed_operation, null);
    } else assert.throws(f.run, undefined, fault);
  }
});

test("Darwin native target and post-operation marker join exact subjects, open variants and causal delivery", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const record = /static void command_record\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    header,
  )?.[1];
  assert.ok(record);
  const paths = /      if\(command_action>=0[\s\S]*?\n      \}/u.exec(
      record,
    )?.[0],
    join = /  if\(opening &&[\s\S]*?\n  \}/u.exec(record)?.[0],
    opening = /opening=!strncmp\([^;]+;/u.exec(record)?.[0];
  assert.ok(paths && join && opening);
  for (const opcode of ["AUE_OPEN_W", "AUE_OPENAT_W", "AUE_OPEN_EXTENDED_W"]) {
    const f = commandGuards(
      header,
      helper,
      `${opening}\n${paths}\nif(extra){raw=extra;token={id:0x23,len:raw.length};${paths}}\n${join}`,
      "command_record",
    );
    Object.assign(f.context, {
      AUT_PATH: 0x23,
      command_action: 2,
      command_target: [null, null, "/fixture/target"],
      command_gate: "/fixture/gate",
      command_case_started: 100,
      command_attempt_time: 0,
      command_case_identity: {
        token: { val: [501, 501, 20, 501, 20, 42, 17] },
      },
      command_attempt_seen: false,
      command_attempt_permitted: false,
      command_marker_seen: false,
      subject: 42,
      auid: 501,
      asid: 17,
      uid: 501,
      gid: 20,
      stamp: 101,
      error: 0,
      result: 3,
      e: { ae_name: opcode },
      extra: Buffer.from([0x23, 0, 0, ...Buffer.from("/fixture/context"), 0]),
      strncmp: (a, b, n) => Number(a.slice(0, n) !== b.slice(0, n)),
      strlen: (value) => value.length,
      memcmp: (a, b, n) =>
        Number(!a.subarray(0, n).equals(Buffer.from(b).subarray(0, n))),
    });
    const event = (name, changes = {}) => {
      const raw = Buffer.from([0x23, 0, 0, ...Buffer.from(name), 0]);
      Object.assign(f.context, {
        raw,
        token: { id: 0x23, len: raw.length },
        target: false,
        marker: false,
        ...changes,
      });
      f.run();
    };
    event("/fixture/gate");
    assert.equal(f.context.command_marker_seen, false);
    event("/fixture/target", { subject: 43 });
    assert.equal(f.context.command_attempt_seen, false);
    event("/fixture/target", { subject: 42, stamp: 99 });
    assert.equal(f.context.command_attempt_seen, false);
    event("/fixture/target", { stamp: 102 });
    assert.equal(f.context.command_attempt_seen, true);
    assert.equal(f.context.command_attempt_permitted, true);
    event("/fixture/gate", { stamp: 103, asid: 18 });
    assert.equal(f.context.command_marker_seen, false);
    event("/fixture/gate", { asid: 17, error: 13, result: -1 });
    assert.equal(f.context.command_marker_seen, false);
    event("/fixture/gate", { error: 0, result: 3 });
    assert.equal(f.context.command_marker_seen, true);
  }
});

test("Darwin producer coverage is set and read back only in the owned launcher's audit session", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const start = header.indexOf(
      "    auditinfo_addr_t audit={0};",
      header.indexOf("static struct identity command_spawn("),
    ),
    end = header.indexOf("    command_native(setgroups", start);
  assert.ok(start > 0 && end > start);
  for (const fault of [
    null,
    "set",
    "get",
    "auid",
    "session",
    "success-mask",
    "failure-mask",
  ]) {
    const calls = [],
      f = commandGuards(
        header,
        helper,
        header.slice(start, end),
        "command_spawn",
      );
    Object.assign(f.context, {
      command_uid: 501,
      AU_ASSIGN_ASID: -1,
      AU_IPv4: 4,
      command_classes: () => 7,
      setaudit_addr(value) {
        calls.push("set");
        assert.equal(value.ai_auid, 501);
        assert.equal(value.ai_asid, -1);
        assert.equal(value.ai_mask.am_success, 7);
        assert.equal(value.ai_mask.am_failure, 7);
        f.context.errno = 5;
        return fault === "set" ? -1 : 0;
      },
      getaudit_addr(value) {
        calls.push("get");
        value.ai_asid = fault === "session" ? 0 : 17;
        if (fault === "auid") value.ai_auid = 502;
        if (fault === "success-mask") value.ai_mask.am_success = 0;
        if (fault === "failure-mask") value.ai_mask.am_failure = 0;
        f.context.errno = 13;
        return fault === "get" ? -1 : 0;
      },
    });
    if (fault) assert.throws(f.run);
    else f.run();
    assert.deepEqual(calls, fault === "set" ? ["set"] : ["set", "get"]);
  }
});

test("Darwin completion keeps the helper parked until target, marker, birth, policy and held reads join", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const body = /static void command_case_finish\(void\) \{([\s\S]*?)\n\}/u.exec(
    header,
  )?.[1];
  assert.ok(body);
  for (const fault of [null, "target", "marker", "birth", "policy"]) {
    const f = commandGuards(header, helper, body, "command_case_finish");
    const reads = [];
    Object.assign(f.context, {
      command_attempt_seen: false,
      command_marker_seen: false,
      command_case_identity: { token: { val: [0, 0, 0, 0, 0, 42] } },
      command_control: false,
      command_action: 0,
      command_helper: "/fixture/helper",
      command_helper_hash: PIN,
      sandbox_binding: {},
      command_gate_fd: 7,
      command_poll() {
        f.context.command_attempt_seen = fault !== "target";
        f.context.command_marker_seen = fault !== "marker";
      },
      live: () => fault !== "birth",
      command_image_identity: () => reads.push("image"),
      feasibility_sandbox_active: () => (fault === "policy" ? 0 : 1),
      command_object: () => reads.push("object"),
      command_gate_object: () => reads.push("gate"),
      emit_identity() {},
      printf() {},
      puts() {},
      write(fd, byte) {
        assert.equal(fd, 7);
        assert.equal(byte, "F");
        reads.push("release");
        return 1;
      },
    });
    if (fault) {
      assert.throws(f.run);
      assert.ok(!reads.includes("release"), fault);
    } else {
      f.run();
      assert.deepEqual(reads, ["image", "object", "gate", "release"]);
    }
    if (["target", "marker", "birth"].includes(fault))
      assert.ok(
        f.diagnostics[0][2].includes(
          fault === "birth"
            ? "live(command_case_identity)"
            : `command_${fault === "target" ? "attempt" : "marker"}_seen`,
        ),
      );
  }
});

function fixture(change = () => {}) {
  const calls = [],
    requests = [],
    durations = [],
    signals = [],
    inputs = {
      packages: {
        codex: {
          component: {
            role: "tool",
            name: "codex",
            version: "0.160.0",
            sha256: PIN,
          },
        },
      },
      tool: { role: "tool", name: "tar", version: "1", sha256: PIN },
    };
  let nonce,
    spec,
    clock = 100;
  const prepared = {
    admission: true,
    audit: true,
    completeRetirement: true,
    sessionEscapeDenied: true,
    uid: 501,
    gid: 20,
    home: "/fixture/home",
    workspace: "/fixture/workspace",
    helper: "/fixture/helper",
    gate: "/fixture/workspace/gate",
    helperSha256: PIN,
    sentinelSha256: PIN,
    files: {
      inspect: "/fixture/workspace/inspection",
      edit: "/fixture/workspace/edit",
      outside: "/fixture/outside",
    },
  };
  const client = {
    initialize: async () => ({ codexHome: prepared.home }),
    exec: async (request) => {
      requests.push(request);
      return {
        exitCode: 0,
        stdout:
          spec.action === "inspect"
            ? nonce
            : spec.permit
              ? "attempt:written"
              : "attempt:denied",
        stderr: "",
      };
    },
    close: async () => {
      calls.push("client-close");
    },
  };
  const effects = {
    noCustody: () => true,
    prepare: async (value) => {
      calls.push("prepare");
      nonce = value;
      return prepared;
    },
    schema: async () => {
      calls.push("schema");
      return {};
    },
    arm: async () => {
      calls.push("arm");
      return {
        identity,
        captureReady: true,
        sessionHeld: true,
        imageSha256: PIN,
        transport: {},
      };
    },
    release: async () => {
      calls.push("release");
    },
    control: async () => {
      const saved = spec;
      spec = {
        action: "control",
        permit: true,
        target: prepared.files.outside,
      };
      const observation = await effects.observe();
      spec = saved;
      return {
        permitted: true,
        observation,
        reply: { exitCode: 0, stdout: "attempt:written" },
      };
    },
    begin: async (_, value) => {
      calls.push("begin");
      spec = value;
    },
    observe: async () => {
      const first = darwinCommandFileObservation({
          identity: `1:2:3:4:90:1:501:20:100600:${"a".repeat(32)}`,
          sha256: sha(nonce),
        }),
        last = {
          ...first,
          sha256: sha(
            spec.permit && ["edit", "outside"].includes(spec.action)
              ? nonce + "-edited"
              : nonce,
          ),
        };
      const gate = { device: "1", inode: "5", uid: 501, gid: 20, mode: 0o600 };
      return {
        before: identity,
        after: identity,
        imageSha256: PIN,
        sandboxed: true,
        gate: { before: gate, after: { ...gate } },
        object: { before: first, after: last },
        barrierSha256: PIN,
        events: [
          {
            id: sha(JSON.stringify(spec)),
            pid: identity.pid,
            auid: 501,
            asid: 17,
            uid: 501,
            gid: 20,
            opcode: "AUE_OPEN",
            target: spec.target,
            kind: "path",
            error: spec.permit ? 0 : 13,
            result: spec.permit ? 3 : -1,
            time: 100002,
            window: { start: 100001, end: 100003, barrierSha256: PIN },
            nativeObject: {
              device: "1",
              inode: "4",
              mode: 0o600,
              uid: 501,
              gid: 20,
            },
          },
          {
            id: sha("acknowledgement" + JSON.stringify(spec)),
            pid: identity.pid,
            auid: 501,
            asid: 17,
            uid: 501,
            gid: 20,
            target: prepared.gate,
            opcode: "AUE_OPEN",
            kind: "path",
            error: 0,
            result: 3,
            time: 100002,
            window: { start: 100001, end: 100003, barrierSha256: PIN },
            nativeObject: gate,
          },
        ],
      };
    },
    retire: async () => {
      calls.push("retire");
      return {
        independent: true,
        completeDomain: true,
        sessionHeldUntilEmpty: true,
        admissionsClosed: true,
        serverRetired: true,
        helpersRetired: true,
        observerRetired: true,
        emergency: false,
        witnessSha256: PIN,
      };
    },
    finish: async () => {
      calls.push("finish");
      return { sentinelSha256: prepared.sentinelSha256, witnessSha256: PIN };
    },
  };
  const protocol = {
    open: () => client,
    parameters: feasibilityCommandParameters,
    supports: () => true,
  };
  change({ effects, prepared, client, protocol, calls });
  return {
    inputs,
    calls,
    requests,
    durations,
    signals,
    effects,
    advance: (ms) => {
      clock += ms;
    },
    run: () =>
      runDarwinFeasibilityCommand(
        { expectedSha: "a".repeat(40) },
        inputs,
        protocol,
        {
          effects,
          now: () => clock,
          timeout: (ms) => {
            durations.push(ms);
            const c = new AbortController();
            signals.push(c);
            return c.signal;
          },
        },
      ),
  };
}
test("Darwin cold exec consumes the generated admission policy with both page-size selectors", async () => {
  const [effects, header, helper] = await Promise.all(
    [
      "feasibility-command-effects.js",
      "feasibility-command.h",
      "feasibility-helper.c",
    ].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const writeStart = effects.indexOf(
      '      await writeFile(\n        path.join(root, "admission.sb"),',
    ),
    writeEnd = effects.indexOf("      const prerequisites =", writeStart),
    brokerStart = header.indexOf("  need(argc==9"),
    policyLeaf = /command_path\(command_policy,"([^"]+)"\);/u.exec(
      header.slice(brokerStart),
    )?.[1],
    launchStart = header.indexOf(
      "    char cwd[4096];",
      header.indexOf("static struct identity command_spawn("),
    ),
    launchEnd = header.indexOf("    /* The normal-UID launcher", launchStart);
  assert.ok(writeStart > 0 && writeEnd > writeStart);
  assert.ok(
    brokerStart > 0 && policyLeaf && launchStart > 0 && launchEnd > launchStart,
  );
  const root = "/fixture/command",
    files = new Map(),
    publish = new Script(
      `(async () => {${effects.slice(writeStart, writeEnd)}})()`,
    );
  await publish.runInNewContext({
    root,
    path,
    async writeFile(file, bytes, options) {
      assert.deepEqual({ ...options }, { flag: "wx", mode: 0o600 });
      assert.ok(!files.has(file));
      files.set(file, bytes);
    },
  });
  let consumed;
  const launch = commandGuards(
    header,
    helper,
    header
      .slice(launchStart, launchEnd)
      .replace("char cwd[4096];", "const cwd = {};"),
    "command_spawn",
    {
      context: {
        command_policy: path.join(root, policyLeaf),
        command_path(out, leaf) {
          out.value = path.join(root, leaf);
        },
        chdir(cwd) {
          assert.equal(cwd.value, path.join(root, "workspace"));
          return 0;
        },
        policy(file) {
          assert.ok(
            files.has(file),
            "Cold exec must consume the published policy",
          );
          consumed = files.get(file);
        },
      },
    },
  );
  launch.run();
  assert.equal(files.size, 1);
  assert.deepEqual(consumed.split("\n"), [
    "(version 1)",
    "(deny default)",
    "(allow process-fork)",
    "(allow process-exec)",
    "(allow file-read*)",
    "(allow file-map-executable)",
    '(allow sysctl-read (sysctl-name "hw.pagesize"))',
    '(allow sysctl-read (sysctl-name "hw.pagesize_compat"))',
    "(allow process-info* (target same-sandbox))",
    `(allow file-write* (subpath ${JSON.stringify(root)}) (literal "/dev/null"))`,
    "",
  ]);
});

test("Darwin cold child release follows trace acknowledgement and fresh image/policy checks", async () => {
  const [header, helper] = await Promise.all(
      ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
        readFile(
          new URL(`../ci/native/darwin/${name}`, import.meta.url),
          "utf8",
        ),
      ),
    ),
    body = /static void command_cold_start\([^)]*\) \{([\s\S]*?)\n\}/u.exec(
      header,
    )?.[1];
  assert.ok(body);
  for (const refusal of [
    null,
    "eof",
    "wrong-ack",
    "expired",
    "expired-late",
    "closed-late",
    "owner-loss",
    "capture",
    "image",
    "policy",
  ]) {
    const calls = [],
      child = { token: { val: [501, 501, 20, 20, 501, 123, 17, 2] } },
      projected = body
        .replace(
          "struct pollfd waiting[]={{0,POLLIN,0},{command_audit,POLLIN,0}};",
          "const waiting=[{revents:0},{revents:0}];",
        )
        .replace("char acknowledgement[3];", "const acknowledgement={};")
        .replaceAll("sizeof(acknowledgement)", "3")
        .replaceAll("(pid_t)", ""),
      f = commandGuards(header, helper, projected, "command_cold_start", {
        context: {
          child,
          operation: "V",
          command_image: "/fixture/codex",
          command_image_hash: PIN,
          stdin: {},
          command_audit: 6,
          POLLIN: 1,
          POLLHUP: 16,
          POLLERR: 8,
          POLLNVAL: 32,
          sandbox_binding: {},
          printf() {},
          emit_identity(value) {
            assert.equal(value, child);
            calls.push("identity");
          },
          puts() {},
          poll(waiting, size, timeout) {
            assert.equal(size, 2);
            assert.equal(timeout, 1000);
            waiting[0].revents = calls.includes("poll")
              ? refusal === "owner-loss"
                ? 16
                : 1
              : 0;
            calls.push("poll");
            return 1;
          },
          command_drain() {
            calls.push("drain");
            if (refusal === "capture") throw new Error("Capture loss");
          },
          fgets(value, size) {
            assert.equal(size, 3);
            calls.push("ack");
            value.value = refusal === "wrong-ack" ? "D\n" : "T\n";
            return refusal === "eof" ? null : value;
          },
          strcmp: (a, b) => Number((a.value ?? a) !== b),
          command_expired: refusal === "expired" ? 1 : 0,
          command_image_identity(value, file, hash) {
            assert.equal(value, child);
            assert.equal(file, "/fixture/codex");
            assert.equal(hash, PIN);
            calls.push("image");
            if (refusal === "image") throw new Error("Changed image");
          },
          feasibility_sandbox_active(_binding, pid) {
            assert.equal(pid, 123);
            calls.push("policy");
            if (refusal === "expired-late") f.context.command_expired = 1;
            if (refusal === "closed-late")
              f.context.command_admissions_closed = true;
            return refusal === "policy" ? 0 : 1;
          },
          command_continue(value) {
            assert.equal(value, child);
            calls.push("resume");
          },
        },
      });
    if (refusal) {
      assert.throws(() => f.run());
      assert.ok(!calls.includes("resume"));
    } else {
      f.run();
      assert.deepEqual(calls, [
        "identity",
        "poll",
        "drain",
        "poll",
        "drain",
        "ack",
        "image",
        "policy",
        "resume",
      ]);
    }
  }
});

test("Darwin command construction uses an empty-home credential-free allowlist and both explicit stock policies", async () => {
  const env = darwinCommandEnvironment("/fixture/home", "/fixture/codex");
  assert.deepEqual(Object.keys(env).sort(), [
    "CI",
    "CODEX_HOME",
    "GITHUB_ACTIONS",
    "HOME",
    "LANG",
    "PATH",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
  ]);
  assert.equal(env.CODEX_HOME, env.HOME);
  const f = fixture(),
    result = await f.run();
  assert.equal(result.status, "PASS");
  assert.equal(result.cleanup.status, "PASS");
  assert.equal(f.inputs.commandCleanup, result.cleanup);
  assert.deepEqual(f.durations, [120000, 30000]);
  assert.equal(f.requests.length, 6);
  assert.ok(f.calls.indexOf("arm") < f.calls.indexOf("release"));
  for (const request of f.requests) {
    assert.equal(request.sandboxPolicy.networkAccess, false);
    assert.equal(request.command[0], "/fixture/helper");
    assert.equal(request.outputBytesCap, 4096);
  }
  assert.deepEqual(
    f.requests.slice(3).map(({ sandboxPolicy }) => sandboxPolicy.writableRoots),
    Array(3).fill(["/fixture/workspace"]),
  );
  assert.ok(f.calls.indexOf("retire") < f.calls.indexOf("finish"));
});
test("Darwin command prerequisites and unsupported installed schemas stop provider release", async () => {
  for (const key of [
    "admission",
    "audit",
    "completeRetirement",
    "sessionEscapeDenied",
  ]) {
    const f = fixture(({ prepared }) => {
      prepared[key] = false;
    });
    const result = await f.run();
    assert.equal(result.status, "BLOCKED");
    assert.equal(result.cleanup.status, "NOT_RUN");
    assert.equal(f.calls.includes("schema"), false);
  }
  const f = fixture(({ protocol }) => {
    protocol.supports = () => false;
  });
  assert.equal((await f.run()).status, "BLOCKED");
  assert.equal(f.calls.includes("release"), false);
});
test("Darwin command rejects record versions that disagree with the independent prerequisite mapping", async () => {
  const events = [
      { event: 1, opcode: "AUE_FIXTURE", classes: 1, selector: "none" },
    ],
    mapping = {
      headerVersion: 11,
      events,
      sdkSha256: PIN,
      abiSha256: PIN,
      mappingSha256: sha(JSON.stringify({ headerVersion: 11, events })),
    };
  const words = (...values) => {
    const bytes = Buffer.alloc(values.length * 4);
    values.forEach((value, index) => bytes.writeUInt32BE(value, index * 4));
    return bytes;
  };
  // The injected token reader models libbsm; fixture bytes are not native proof.
  const read = async (version) => {
    const record = Buffer.alloc(18);
    record[0] = 0x14;
    record.writeUInt32BE(record.length, 1);
    record[5] = version;
    const decoder = createDarwinAuditDecoder(
      {
        bsm: async (bytes) => ({
          tokens: [
            {
              kind: "header",
              version: bytes[5],
              event: 1,
              name: Buffer.from("AUE_FIXTURE").toString("hex"),
              classes: 1,
              seconds: 100,
              milliseconds: 2,
            },
            {
              kind: "subject",
              pid: identity.pid,
              auid: identity.auid,
              asid: identity.asid,
              uid: identity.uid,
              gid: identity.gid,
            },
            { kind: "return", result: 0, error: 0 },
            { kind: "trailer" },
          ],
        }),
      },
      mapping,
    );
    await decoder.push(
      Buffer.concat([
        words(0, record.length),
        record,
        words(0xffffffff, record.length, 1),
      ]),
    );
    return decoder.finish({ code: 0, signal: null });
  };
  assert.equal((await read(11)).records, 1);
  for (const [version, independent] of [
    [2, true],
    [10, false],
  ]) {
    const f = fixture(({ effects }) => {
      effects.observe = () => read(version);
      const retire = effects.retire;
      effects.retire = async (...args) => ({
        ...(await retire(...args)),
        independent,
      });
    });
    const result = await f.run();
    assert.equal(result.status, "FAIL");
    assert.equal(result.cause.code, "setup-failed");
    assert.equal(result.cleanup.status, independent ? "PASS" : "UNCERTAIN");
    assert.equal(f.calls.includes("retire"), true);
    assert.equal(f.requests.length, 0);
    assert.equal(mapping.headerVersion, 11);
  }
});
test("Darwin failed buffered replies retain their cause while native observation is pending", async () => {
  for (const outcome of [
    "unavailable",
    "later-unavailable",
    "failure",
    "exit",
  ]) {
    const original = {
      code: "crash",
      detail: "The buffered request lost its server.",
    };
    let requests = 0,
      rejectObservation;
    const f = fixture(({ effects, client }) => {
      const observe = effects.observe,
        retire = effects.retire,
        exec = client.exec;
      effects.observe = (...args) =>
        args.length === 0 || (outcome === "later-unavailable" && requests === 1)
          ? observe(...args)
          : new Promise((_, reject) => {
              rejectObservation = reject;
            });
      client.exec = async (params) => {
        requests++;
        if (outcome === "later-unavailable" && requests === 1)
          return exec(params);
        if (outcome === "exit") return { exitCode: 17, stdout: "", stderr: "" };
        throw Object.assign(
          new Error("Buffered request failed"),
          outcome === "failure"
            ? { feasibilityCause: original }
            : { code: "ERR_FEASIBILITY_ROUTE_UNAVAILABLE" },
        );
      };
      effects.retire = async (...args) => {
        rejectObservation(new Error("Later missing helper"));
        return retire(...args);
      };
    });
    const result = await f.run();
    assert.equal(requests, outcome === "later-unavailable" ? 2 : 1);
    assert.equal(result.cleanup.status, "PASS");
    assert.equal(result.status, outcome === "unavailable" ? "BLOCKED" : "FAIL");
    if (outcome === "failure") assert.equal(result.cause, original);
    else if (outcome === "exit")
      assert.match(
        result.cause.detail,
        /buffered-reply: exit=17, signal=unknown, timeout=unknown/u,
      );
    else
      assert.equal(
        result.cause.code,
        outcome === "unavailable" ? "prerequisite-unavailable" : "setup-failed",
      );
  }
});
test("Darwin attribution, live policy, audit controls and changed held sentinels cannot pass", async () => {
  for (const mutate of [
    (o) => {
      o.after = { ...identity, pidVersion: 3 };
    },
    (o) => {
      o.imageSha256 = sha("other");
    },
    (o) => {
      o.sandboxed = false;
    },
    (o) => {
      o.events = [];
    },
    (o) => {
      o.events.pop();
    },
    (o) => {
      o.gate.after.inode = "6";
    },
    (o) => {
      o.events[0].nativeObject.inode = "5";
    },
    (o) => {
      o.object.before.sha256 = sha("changed-before");
    },
    (o) => {
      o.object.after.sha256 = sha("changed");
    },
  ]) {
    const f = fixture(({ effects }) => {
      const read = effects.observe;
      effects.observe = async (...args) => {
        const o = await read(...args);
        mutate(o);
        return o;
      };
    });
    const result = await f.run();
    assert.equal(result.status, "FAIL");
    assert.equal(f.calls.includes("retire"), true);
  }
  const f = fixture(({ effects }) => {
    effects.control = async () => ({ permitted: false });
  });
  assert.equal((await f.run()).status, "FAIL");
  assert.equal(f.requests.length, 0);
});
test("Darwin capture loss and a changed final outside sentinel retain failure through settlement", async () => {
  for (const change of [
    ({ effects }) => {
      effects.observe = async () => {
        throw new Error("capture lost");
      };
    },
    ({ effects }) => {
      effects.finish = async () => ({
        sentinelSha256: sha("changed"),
        witnessSha256: PIN,
      });
    },
  ]) {
    const f = fixture(change),
      result = await f.run();
    assert.equal(result.status, "FAIL");
  }
});
test("Darwin retirement requires the held complete domain, server, descendants and observer", async () => {
  for (const key of [
    "completeDomain",
    "sessionHeldUntilEmpty",
    "admissionsClosed",
    "serverRetired",
    "helpersRetired",
    "observerRetired",
    "independent",
  ]) {
    const f = fixture(({ effects }) => {
      const retire = effects.retire;
      effects.retire = async () => ({ ...(await retire()), [key]: false });
    });
    const result = await f.run();
    assert.equal(result.status, "FAIL");
    assert.equal(result.cleanup.status, "UNCERTAIN");
    assert.equal(f.calls.includes("finish"), false);
  }
  const f = fixture(({ effects }) => {
    const retire = effects.retire;
    effects.retire = async () => ({ ...(await retire()), emergency: true });
  });
  const result = await f.run();
  assert.equal(result.status, "FAIL");
  assert.equal(result.cleanup.status, "UNCERTAIN");
  assert.equal(result.cleanup.emergency, true);
  assert.equal(f.calls.includes("finish"), false);
  const g = fixture(({ effects }) => {
    effects.retire = async () => {
      throw Object.assign(new Error("Independent verification lost"), {
        emergency: true,
      });
    };
  });
  const uncertain = await g.run();
  assert.equal(uncertain.cleanup.status, "UNCERTAIN");
  assert.equal(uncertain.cleanup.emergency, true);
  assert.equal(g.calls.includes("finish"), false);
});
test("Darwin native custody failures still retire and independently observe the owner without replacing the first cause", async () => {
  for (const stage of ["domain", "session", "close"]) {
    const calls = [],
      first = new Error("First custody failure"),
      later = new Error("Later observer failure");
    await assert.rejects(
      settleDarwinCommandCustody(new Set([17, 18]), {
        retireDomain: async () => {
          calls.push("domain");
          if (stage === "domain") throw first;
          return {
            empty: true,
            emergency: true,
            serverClean: true,
            sessions: [17, 18],
          };
        },
        verifySession: async (asid) => {
          calls.push(asid);
          if (stage === "session" && asid === 17) throw first;
          return { empty: true };
        },
        closeObserver: async () => {
          calls.push("close");
          if (stage === "close") throw first;
        },
        verifyObserver: async () => {
          calls.push("observer");
          throw later;
        },
      }),
      (error) => error === first && error.emergency === (stage !== "domain"),
    );
    assert.deepEqual(
      calls,
      stage === "domain"
        ? ["domain", "close", "observer"]
        : ["domain", 17, 18, "close", "observer"],
    );
  }
  const invalid = { empty: true, emergency: false, sessions: [17, 17] },
    calls = [];
  await assert.rejects(
    settleDarwinCommandCustody(new Set([17, 18]), {
      retireDomain: async () => invalid,
      verifySession: async () => {
        assert.fail("Invalid custody must not be admitted");
      },
      closeObserver: async () => {
        calls.push("close");
      },
      verifyObserver: async () => {
        calls.push("observer");
        return { status: "RETIRED" };
      },
    }),
  );
  assert.deepEqual(calls, ["close", "observer"]);
  calls.length = 0;
  await assert.rejects(
    settleDarwinCommandCustody(new Set([17, 18]), {
      retireDomain: async () => ({
        empty: true,
        emergency: false,
        serverClean: false,
        sessions: [17, 18],
      }),
      verifySession: async (asid) => {
        calls.push(asid);
        return { empty: true };
      },
      closeObserver: async () => {
        calls.push("close");
      },
      verifyObserver: async () => {
        calls.push("observer");
        return { status: "RETIRED" };
      },
    }),
  );
  assert.deepEqual(calls, [17, 18, "close", "observer"]);
});
test("Darwin fixture cleanup refuses replaced files or parents before producing removal requests", () => {
  const files = [4, 5, 6].map((inode) => ({
      identity: `1:2:3:${inode}:90:1:501:20:100600:${"a".repeat(32)}`,
      sha256: PIN,
    })),
    parents = [1, 2].map((inode) => ({
      identity: `1:2:3:${inode}:90:1:501:20:40700:${"a".repeat(32)}`,
      sha256: null,
    })),
    value = {
      files: {
        inspect: "/fixture/workspace/inspection",
        edit: "/fixture/workspace/edit",
        outside: "/fixture/outside",
      },
      fileIdentities: files.map(({ identity }) => identity),
      parentIdentities: parents.map(({ identity }) => identity),
      sentinelSha256: sha(JSON.stringify(files[2])),
    };
  const args = darwinCommandCleanupArguments(value, files, parents);
  assert.equal(args.length, 3);
  assert.equal(args[0][4], parents[1].identity);
  assert.equal(args[2][4], parents[0].identity);
  for (const index of [0, 1, 2]) {
    const changed = structuredClone(files);
    changed[index].identity = changed[index].identity.replace(":90:", ":91:");
    assert.throws(() => darwinCommandCleanupArguments(value, changed, parents));
  }
  const changedParent = structuredClone(parents);
  changedParent[1].identity = changedParent[1].identity.replace(":90:", ":91:");
  assert.throws(() =>
    darwinCommandCleanupArguments(value, files, changedParent),
  );
  const changedOutside = structuredClone(files);
  changedOutside[2].sha256 = sha("changed");
  assert.throws(() =>
    darwinCommandCleanupArguments(value, changedOutside, parents),
  );
});
test("Darwin observation and partial-failure settlement have separate enforced deadlines", async () => {
  const elapsed = fixture(),
    observe = elapsed.effects.observe,
    retire = elapsed.effects.retire;
  elapsed.effects.observe = async (...args) => {
    elapsed.advance(15000);
    return observe(...args);
  };
  elapsed.effects.retire = async (...args) => {
    elapsed.advance(20000);
    return retire(...args);
  };
  const measured = await elapsed.run();
  assert.equal(measured.status, "PASS");
  assert.equal(measured.elapsedMs, 105000);
  assert.equal(measured.cleanup.elapsedMs, 20000);
  const f = fixture(({ effects }) => {
    effects.observe = () => {
      queueMicrotask(() => f.signals[0].abort());
      return new Promise(() => {});
    };
  });
  const result = await f.run();
  assert.equal(result.status, "FAIL");
  assert.equal(result.cause.code, "deadline");
  assert.equal(result.cleanup.status, "PASS");
  assert.deepEqual(f.durations, [120000, 30000]);
  const g = fixture(({ effects }) => {
    effects.retire = () => {
      queueMicrotask(() => g.signals[1].abort());
      return new Promise(() => {});
    };
  });
  assert.equal((await g.run()).cleanup.status, "UNCERTAIN");
  assert.equal(g.calls.includes("finish"), false);
});

function commandCaptureFixture(
  header,
  helper,
  { exitCode = 126, readError = 0, diagnosticFailure = false } = {},
) {
  const native =
    /static void command_capture\(const char \*event\) \{([\s\S]*?)\n\}/u.exec(
      header,
    )?.[1];
  assert.ok(native);
  const body = native
    .replace(
      "unsigned char output[65536],errors[65536];",
      "const output=Buffer.alloc(65536),errors=Buffer.alloc(65536);",
    )
    .replace(
      "int fds[]={command_out,command_err};",
      "const fds=[command_out,command_err];",
    )
    .replace(
      "struct pollfd p[]={{fds[0],POLLIN,0},{fds[1],POLLIN,0}};",
      "const p=[{fd:fds[0],revents:0},{fd:fds[1],revents:0}];",
    )
    .replace(
      "(i?errors:output)+(i?err:used)",
      "(i?errors:output).subarray(i?err:used)",
    )
    .replaceAll("errors+err", "errors.subarray(err)")
    .replace("&status", "{set value(v){status=v}}")
    .replace("output[i]=='\\n'", "output[i]===10")
    .replace("output[i]!='\"'", "output[i]!==34")
    .replace("output[i]!='\\\\'", "output[i]!==92");
  const errors = Buffer.from("fixture child refusal\n\0detail\n"),
    writes = [],
    output = [],
    streams = new Map([
      [3, [Buffer.from("codex-cli 0.160.0\n")]],
      [
        4,
        [
          errors.subarray(0, 8),
          errors.subarray(8),
          ...(readError ? [{ error: readError }] : []),
        ],
      ],
    ]);
  const f = commandGuards(
    header,
    helper,
    `const event=args[0];${body}`,
    "command_capture",
    {
      cleanup: true,
      context: {
        Buffer,
        POLLIN: 1,
        POLLHUP: 2,
        command_prerequisite: false,
        command_owner: 0,
        command_out: 3,
        command_err: 4,
        command_in: 5,
        command_count: 1,
        command_wrappers: [9],
      },
    },
  );
  Object.assign(f.context, {
    command_poll() {
      if (f.calls.length) assert.equal(f.context.errno, 17);
      f.calls.push("poll");
    },
    poll(descriptors) {
      descriptors.forEach((value) => {
        value.revents = value.fd < 0 ? 0 : 1;
      });
      return 1;
    },
    read(fd, target, capacity) {
      assert.equal(target.length, capacity);
      const chunk = streams.get(fd).shift();
      f.context.errno = chunk?.error ?? 17;
      if (chunk?.error) return -1;
      if (!chunk) return 0;
      assert.ok(chunk.length <= capacity);
      chunk.copy(target);
      return chunk.length;
    },
    fwrite(bytes, size, count, stream) {
      assert.equal(stream, f.context.stderr);
      assert.equal(size, 1);
      assert.equal(f.context.errno, 17);
      writes.push(Buffer.from(bytes.subarray(0, count)));
      f.context.errno = 28;
      return diagnosticFailure ? 0 : count;
    },
    fflush() {
      f.context.errno = 29;
      return diagnosticFailure ? -1 : 0;
    },
    waitpid(pid, status, flags) {
      assert.equal(pid, 9);
      assert.equal(flags, 0);
      f.calls.push("wait");
      status.value = exitCode;
      return pid;
    },
    WIFEXITED: () => true,
    WEXITSTATUS: (status) => status,
    printf(format, ...values) {
      let at = 0;
      output.push(format.replace(/%[sd]/gu, () => String(values[at++])));
    },
    putchar: (byte) => output.push(String.fromCharCode(byte)),
    puts: (value) => output.push(value + "\n"),
    close(fd) {
      f.calls.push("close:" + fd);
      return 0;
    },
  });
  return { ...f, errors, writes, output };
}

test("Darwin capture preserves original child bytes and V/G outcomes through schema refusal", async (t) => {
  const [header, helper, effects] = await Promise.all(
    [
      "feasibility-command.h",
      "feasibility-helper.c",
      "feasibility-command-effects.js",
    ].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const start = effects.indexOf(
      '      const version = await call("V", signal);',
    ),
    end = effects.indexOf("      const readSchema =", start),
    need = /const need = \(value\) => \{[\s\S]*?\n\};/u.exec(effects)?.[0];
  assert.ok(start >= 0 && end > start && need);
  const schema = new Script(
    `${need}\n(async()=>{${effects.slice(start, end)}})`,
  );
  for (const failed of ["V", "G"]) {
    const diagnostics = [],
      replies = [],
      traceFinishes = [],
      captures = new Map();
    for (const operation of ["V", "G"]) {
      const capture = commandCaptureFixture(header, helper, {
        exitCode: operation === failed ? 126 : 0,
      });
      capture.run(operation);
      const bytes = Buffer.concat(capture.writes),
        reply = JSON.parse(capture.output.join(""));
      assert.deepEqual(bytes, capture.errors);
      assert.equal(reply.exitCode, operation === failed ? 126 : 0);
      captures.set(operation, { bytes, reply });
    }
    await withNativeDiagnostics(
      async () => {
        const signal = new AbortController().signal;
        const f = await commandBrokerFixture(
          t,
          signal,
          (operation, { frame, finish }) => {
            if (["V", "G"].includes(operation)) {
              const { bytes, reply } = captures.get(operation);
              replies.push(reply);
              f.broker.stderr.write(bytes);
              frame(reply);
            }
            if (operation === "S") {
              frame({ event: "capture-end", bytes: 0, records: 0 });
              frame({ event: "S" });
              finish();
            }
          },
        );
        try {
          await assert.rejects(
            schema.runInNewContext({
              signal,
              call: (...args) => f.owner.call(...args),
              finishColdTrace: async (operation) => {
                traceFinishes.push(operation);
              },
            })(),
            /Incomplete native command observation/u,
          );
        } finally {
          await f.owner.close(signal);
        }
        assert.deepEqual(f.sent, failed === "V" ? ["V", "S"] : ["V", "G", "S"]);
        assert.equal(f.owner.captureFailure, undefined);
        assert.deepEqual(traceFinishes, failed === "V" ? [] : ["V"]);
      },
      (_owner, value) => {
        if (value.stderr) diagnostics.push(Buffer.from(value.stderr));
      },
    );
    assert.equal(replies.at(-1).event, failed);
    assert.equal(replies.at(-1).exitCode, 126);
    assert.deepEqual(
      Buffer.concat(diagnostics),
      Buffer.from("fixture child refusal\n\0detail\n".repeat(replies.length)),
    );
  }
  for (const options of [{ readError: 5 }, { diagnosticFailure: true }]) {
    const f = commandCaptureFixture(header, helper, options);
    if (options.readError)
      assert.throws(
        () => f.run("V"),
        (error) => {
          assert.equal(error.kind, "errno");
          assert.equal(error.value, 5);
          assert.deepEqual(error.cleanup, ["fixture-close", "errno", 16]);
          return true;
        },
      );
    else {
      f.run("V");
      assert.equal(JSON.parse(f.output.join("")).exitCode, 126);
    }
    assert.deepEqual(Buffer.concat(f.writes), f.errors);
  }
});

async function commandBrokerFixture(t, signal, respond = () => {}, coldStart) {
  const broker = new EventEmitter(),
    sent = [],
    signals = [],
    requests = new EventEmitter(),
    sessions = new Set(),
    value = { helperSha256: PIN, commandImageSha256: PIN, uid: 501, gid: 20 };
  let finished = false;
  const frame = (value) => broker.stdout.write(JSON.stringify(value) + "\n"),
    finish = () => {
      if (finished) return;
      finished = true;
      broker.stdin.end();
      broker.stdout.end();
      broker.stderr.end();
      broker.emit("close", 0, null);
    };
  broker.stdout = new PassThrough();
  broker.stderr = new PassThrough();
  broker.stdin = new Writable({
    write(bytes, encoding, callback) {
      const operation = bytes.toString().trim();
      sent.push(operation);
      requests.emit(operation);
      respond(operation, { frame, finish });
      callback();
    },
  });
  broker.kill = (signal) => {
    signals.push(signal);
    return true;
  };
  const owner = observeDarwinCommandBroker(broker, value, {
    signal,
    tokens: new Map(),
    admittedSessions: sessions,
    coldStart,
    decoder: { push: async () => {} },
  });
  t.after(async () => {
    finish();
    await Promise.allSettled([owner.closed, owner.observation]);
  });
  frame({
    event: "ready",
    imageSha256: PIN,
    identity: {
      ...identity,
      uid: 0,
      gid: 0,
      ruid: 0,
      rgid: 0,
      svuid: 0,
      svgid: 0,
    },
  });
  await owner.ready;
  return {
    broker,
    owner,
    frame,
    finish,
    sent,
    signals,
    sessions,
    when: (operation) =>
      sent.includes(operation)
        ? Promise.resolve()
        : new Promise((resolve) => requests.once(operation, resolve)),
  };
}

test("Darwin broker binds a cold trace to the held child before acknowledging resume", async (t) => {
  const armed = Promise.withResolvers(),
    entered = Promise.withResolvers(),
    f = await commandBrokerFixture(
      t,
      new AbortController().signal,
      (operation, { frame }) => {
        if (operation === "T")
          frame({ event: "V", stdout: "fixture\n", exitCode: 0 });
      },
      async (binding) => {
        entered.resolve(binding);
        await armed.promise;
      },
    ),
    response = f.owner.call("V");
  f.frame({ event: "custody", identity, sessionHeld: true });
  f.frame({ event: "cold-start", operation: "V", identity, imageSha256: PIN });
  const binding = await entered.promise;
  assert.deepEqual(binding.identity, identity);
  assert.equal(binding.operation, "V");
  assert.deepEqual(f.sent, ["V"]);
  armed.resolve();
  assert.equal((await response).exitCode, 0);
  assert.deepEqual(f.sent, ["V", "T"]);
});

test("Darwin broker refuses an unjoined cold child without releasing it", async (t) => {
  for (const mismatch of ["image", "credentials", "session", "operation"]) {
    const f = await commandBrokerFixture(
        t,
        new AbortController().signal,
        () => {},
        async () => assert.fail("Unjoined cold child"),
      ),
      refused = assert.rejects(f.owner.call("V"));
    if (mismatch !== "session")
      f.frame({ event: "custody", identity, sessionHeld: true });
    f.frame({
      event: "cold-start",
      operation: mismatch === "operation" ? "G" : "V",
      identity: {
        ...identity,
        ...(mismatch === "credentials" ? { uid: 502 } : {}),
      },
      imageSha256: mismatch === "image" ? "b".repeat(64) : PIN,
    });
    await refused;
    assert.deepEqual(f.sent, ["V"]);
    assert.deepEqual(f.signals, ["SIGTERM"]);
  }
});

test("cold admission refuses missing or partial trace reports while retirement remains independently consumable", async () => {
  const source = await readFile(
      new URL(
        "../ci/native/darwin/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    start = source.indexOf("  const finishColdTrace ="),
    end = source.indexOf("  const snapshots =", start);
  assert.ok(start > 0 && end > start);
  const coldTraces = new Map(),
    reports = [],
    finish = new Script(
      `${source.slice(start, end)}finishColdTrace`,
    ).runInNewContext({
      coldTraces,
      root: "/fixture",
      path,
      assertDarwinColdStartupTrace,
      need: (ok) => assert.ok(ok),
      nativeDiagnostic() {},
      writeFile: async (_file, report) => reports.push(JSON.parse(report)),
    });
  await assert.rejects(finish("V", true));
  await finish("V");
  coldTraces.set("G", {
    binding: { operation: "G" },
    trace: { finish: async () => ({ status: "partial", cleanup: "RETIRED" }) },
  });
  await assert.rejects(finish("G", true));
  await finish("G");
  assert.equal(reports.length, 1);
  assert.equal(reports[0].trace.status, "partial");
  assert.equal(reports[0].trace.cleanup, "RETIRED");
});

test("Darwin failed cold requests settle every trace after domain retirement without replacing its failure", async () => {
  const source = await readFile(
      new URL(
        "../ci/native/darwin/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    helperStart = source.indexOf("  const finishColdTrace ="),
    helperEnd = source.indexOf("  const snapshots =", helperStart),
    start = source.indexOf(
      "      let exit, settled, failure;",
      source.indexOf("    async retire("),
    ),
    end = source.indexOf("      active = false;", start);
  assert.ok(
    helperStart > 0 && helperEnd > helperStart && start > 0 && end > start,
  );
  const retire = new Script(
    `(async()=>{${source.slice(helperStart, helperEnd)}${source.slice(start, end)}})`,
  );
  for (const failed of ["domain", "trace"]) {
    const calls = [],
      primary = new Error("Original domain failure"),
      coldTraces = new Map(
        ["V", "G"].map((operation) => [
          operation,
          {
            binding: { operation, identity },
            trace: {
              finish: async () => {
                calls.push(operation);
                return {
                  cleanup:
                    failed === "trace" && operation === "V"
                      ? "UNCERTAIN"
                      : "RETIRED",
                };
              },
            },
          },
        ]),
      );
    await assert.rejects(
      retire.runInNewContext({
        coldTraces,
        path,
        root: "/fixture",
        admittedSessions: new Set(),
        value: {},
        signal: new AbortController().signal,
        need(ok) {
          assert.ok(ok, "Unretired trace");
        },
        nativeDiagnostic() {},
        async writeFile(file, bytes, options) {
          const report = JSON.parse(bytes);
          assert.equal(
            file,
            `/fixture/evidence/command-${report.operation}-startup.json`,
          );
          assert.deepEqual({ ...options }, { flag: "wx", mode: 0o600 });
          assert.equal(report.identity.pid, identity.pid);
        },
        async settleDarwinCommandCustody() {
          calls.push("domain");
          if (failed === "domain") throw primary;
          return { domain: { emergency: true } };
        },
      })(),
      (error) =>
        failed === "domain"
          ? error === primary
          : error.emergency === true && /Unretired trace/u.test(error.message),
    );
    assert.deepEqual(calls, ["domain", "V", "G"]);
  }
});

test("Darwin ready broker cancels an unanswered V without cancelling independent settlement", async (t) => {
  const work = new AbortController(),
    cleanup = new AbortController(),
    f = await commandBrokerFixture(
      t,
      work.signal,
      (operation, { frame, finish }) => {
        if (operation === "D") {
          // The native owner acquired this session before cancellation reached JS.
          frame({
            event: "custody",
            sessionHeld: true,
            identity: { asid: 19 },
          });
          frame({
            event: "D",
            empty: true,
            emergency: false,
            serverClean: true,
            sessions: [19],
          });
        }
        if (operation === "S") {
          frame({ event: "capture-end", bytes: 0, records: 0 });
          frame({ event: "S" });
          finish();
        }
      },
    ),
    version = assert.rejects(f.owner.call("V"), {
      code: "ERR_FEASIBILITY_DEADLINE",
    });
  await f.when("V");
  work.abort();
  await version;
  await assert.rejects(f.owner.call("G"), { code: "ERR_FEASIBILITY_DEADLINE" });
  const observed = [],
    settled = await settleDarwinCommandCustody(f.sessions, {
      retireDomain: () => f.owner.call("D", cleanup.signal),
      verifySession: async (asid) => {
        observed.push(asid);
        return { empty: true };
      },
      closeObserver: () => f.owner.close(cleanup.signal),
      verifyObserver: async () => {
        observed.push("observer");
        return { status: "RETIRED" };
      },
    });
  assert.deepEqual(f.sent, ["V", "D", "S"]);
  assert.deepEqual(f.signals, ["SIGTERM"]);
  assert.deepEqual(observed, [19, "observer"]);
  assert.deepEqual([...f.sessions], [19]);
  assert.equal(settled.retired.length, 1);
  assert.equal(f.owner.captureFinished, true);
  assert.equal(f.owner.captureFailure, undefined);
});

test("Darwin acquired launch keeps late custody after cancellation and rejects closure as retirement", async (t) => {
  const work = new AbortController(),
    cleanup = new AbortController(),
    f = await commandBrokerFixture(t, work.signal),
    held = Promise.withResolvers(),
    add = f.sessions.add.bind(f.sessions);
  f.sessions.add = (asid) => {
    const result = add(asid);
    held.resolve();
    return result;
  };
  let original;
  const launch = assert.rejects(f.owner.call("A"), (error) => {
    original = error;
    return error.code === "ERR_FEASIBILITY_DEADLINE";
  });
  f.frame({ event: "custody", sessionHeld: true, identity: { asid: 17 } });
  await held.promise;
  work.abort();
  await launch;
  f.frame({ event: "custody", sessionHeld: true, identity: { asid: 18 } });
  f.frame({ event: "A", identity, sessionHeld: true, imageSha256: PIN });
  const observed = [],
    settlement = assert.rejects(
      settleDarwinCommandCustody(f.sessions, {
        retireDomain: () => f.owner.call("D", cleanup.signal),
        verifySession: async () =>
          assert.fail("A closed broker supplies no domain proof"),
        closeObserver: () => f.owner.close(cleanup.signal),
        verifyObserver: async () => {
          observed.push("observer");
          return { status: "RETIRED" };
        },
      }),
      (error) =>
        error !== original && error.message === "Native custody closed",
    );
  await f.when("D");
  f.finish();
  await settlement;
  assert.deepEqual([...f.sessions], [17, 18]);
  assert.deepEqual(observed, ["observer"]);
  assert.equal(f.owner.captureFinished, false);
  assert.ok(f.owner.captureFailure);
  await assert.rejects(f.owner.call("R"));
});

test("Darwin broker cancellation preserves its primary deadline through separate cleanup failures", async (t) => {
  for (const failure of ["deadline", "observer"]) {
    let broker;
    const settled = Promise.withResolvers(),
      f = fixture(({ effects, calls }) => {
        effects.schema = async (value, signal) => {
          broker = await commandBrokerFixture(
            t,
            signal,
            (operation, { frame, finish }) => {
              if (operation === "V") queueMicrotask(() => f.signals[0].abort());
              if (operation === "D") {
                if (failure === "deadline")
                  queueMicrotask(() => f.signals[1].abort());
                else
                  frame({
                    event: "D",
                    empty: true,
                    emergency: false,
                    serverClean: true,
                    sessions: [],
                  });
              }
              if (operation === "S") {
                frame({ event: "capture-end", bytes: 0, records: 0 });
                frame({ event: "S" });
                finish();
              }
            },
          );
          return broker.owner.call("V", signal);
        };
        effects.cancel = (error) => broker.owner.cancel(error);
        effects.retire = async (value, signal) => {
          calls.push("retire");
          try {
            await settleDarwinCommandCustody(broker.sessions, {
              retireDomain: () => broker.owner.call("D", signal),
              verifySession: async () => assert.fail("No session was acquired"),
              closeObserver: () => broker.owner.close(signal),
              verifyObserver: async () => {
                throw new Error("Independent observer unavailable");
              },
            });
          } finally {
            settled.resolve();
          }
        };
      }),
      result = await f.run();
    await settled.promise;
    assert.equal(result.status, "FAIL");
    assert.equal(result.cause.code, "deadline");
    assert.equal(result.cleanup.status, "UNCERTAIN");
    assert.equal(result.cleanup.cause.code, "cleanup-unobserved");
    assert.deepEqual(f.durations, [120000, 30000]);
    assert.equal(f.calls.includes("finish"), false);
    if (failure === "deadline") {
      broker.frame({
        event: "custody",
        sessionHeld: true,
        identity: { asid: 21 },
      });
      broker.finish();
      await broker.owner.observation.catch(() => {});
      assert.deepEqual([...broker.sessions], [21]);
    }
  }
});

test("Darwin native cancellation closes an unreleased launch gate and reaps its original fork", async () => {
  const [header, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/darwin/${name}`, import.meta.url), "utf8"),
    ),
  );
  const calls = [],
    f = commandGuards(header, helper, "command_failure();", "command_failure", {
      context: {
        command_prerequisite: false,
        command_release: 41,
        command_pending_wrapper: 51,
      },
    });
  let reaped = false;
  Object.assign(f.context, {
    close: (fd) => {
      calls.push(["close", fd]);
      return 0;
    },
    waitpid: (pid) => {
      calls.push(["wait", pid]);
      return reaped ? pid : 0;
    },
    poll: () => {
      reaped = true;
      return 0;
    },
  });
  f.run();
  assert.deepEqual(calls, [
    ["close", 41],
    ["wait", 51],
    ["wait", 51],
  ]);
  assert.equal(f.context.command_release, -1);
  assert.equal(f.context.command_pending_wrapper, -1);
  assert.equal(f.context.command_admissions_closed, true);
});
