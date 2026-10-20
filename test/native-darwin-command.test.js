import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Script } from "node:vm";
import {
  runDarwinFeasibilityCommand,
  darwinCommandEnvironment,
  darwinCommandFileObservation,
  settleDarwinCommandCustody,
  darwinCommandCleanupArguments,
  createDarwinAuditDecoder,
} from "../ci/native/darwin/index.js";
import { feasibilityCommandParameters } from "../ci/native/providers/index.js";

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
        .replace("struct identity member;", "const member={token:{val:[]}};")
        .replace("au_mask_t empty={0,0};", "const empty={};")
        .replace(
          "struct auditpipe_ioctl_preselect choice={0};",
          "const choice={aip_mask:{}};",
        )
        .replace(/sizeof\(pids\)/gu, "4096")
        .replace(/sizeof\((?:pid_t|before|after|a|b|member|attempt)\)/gu, "1")
        .replace(
          /&(low|high|size)\b/gu,
          (_, name) => `{set value(v){${name}=v}}`,
        )
        .replace(/&foreign\b/gu, "{set value(v){foreign=v}}")
        .replace(
          /&(before|after|a|b|member|queue|mode|empty|choice|status|attempt)\b/gu,
          "$1",
        )
        .replace(/\((?:int|unsigned|void)\)/gu, "")
        .replace(/\blong long /gu, "let ")
        .replace(
          /\b(?:unsigned|int|bool|uid_t|au_asid_t|mach_port_t) /gu,
          "let ",
        )
        .replace(
          /command_native\(([^;]+), (== [^;]+)\)/gu,
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
    "GET_QLIMIT_MIN",
    "GET_QLIMIT_MAX",
    "GET_MAXAUDITDATA",
    "SET_QLIMIT",
    "SET_PRESELECT_MODE",
    "SET_PRESELECT_FLAGS",
    "SET_PRESELECT_NAFLAGS",
    "SET_PRESELECT_AUID",
    "FLUSH",
  ].map((name) => `AUDITPIPE_${name}`);
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
        if (operation === operations[0])
          target.value = fault === "queue" ? 2048 : 1;
        if (operation === operations[1]) target.value = 4096;
        if (operation === operations[2]) target.value = 65536;
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
          ? ["open", ...operations.slice(0, 2)]
          : ["open", ...operations.slice(0, operations.indexOf(fault) + 1)],
    );
    assert.equal(
      f.reports[0][2],
      fault === "open" ? 13 : fault === "queue" ? 0 : 5,
    );
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
      `const asid=55,signal_members=false;${body}`,
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
        return sample("inspect");
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
