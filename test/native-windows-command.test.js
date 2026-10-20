import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { PassThrough, Writable } from "node:stream";
import { EventEmitter, once } from "node:events";
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { Script } from "node:vm";
import { win32 as windowsPath } from "node:path";
import {
  runWindowsFeasibilityCommand,
  windowsCommandEnvironment,
  settleWindowsCommandCustody,
  windowsCommandAuditRead,
  windowsCommandBrokerSetup,
  assessWindowsCommandObservation,
  windowsCommandTerminalCapture,
  createWindowsAuditDecoder,
  windowsCommandCleanupSnapshot,
  openWindowsCommandWatcher,
  buildWindowsCommandHelper,
  buildWindowsCustodyReader,
  WINDOWS_BUILD_COMMAND_MS,
  WINDOWS_BUILD_LIBRARIES,
  windowsCompilerArguments,
  createWindowsCommandPreparation,
  windowsFeasibilityToolEnvironment,
  windowsFeasibilityCause,
  windowsFeasibilityDiagnostics,
} from "../ci/native/win32/index.js";
import {
  feasibilityCommandParameters,
  openFeasibilityCommand,
} from "../ci/native/providers/index.js";
import { observationDigest } from "../ci/native/index.js";
import {
  feasibilityFailureCause,
  unavailableFeasibilityResults,
} from "../ci/native/feasibility/index.js";

const sha = (v) => createHash("sha256").update(v).digest("hex"),
  PIN = sha("fixture");
const identity = {
  pid: 123,
  creationTime: "101",
  sessionId: 1,
  userSid: "S-1-5-21-10-20-30-1001",
};
// Bounded native-shaped bytes/fields exercise the real finite decoder. These
// portable transcripts supply no Windows compilation, query or delivery proof.
async function brokerSetup(prepared) {
  const gate = {
      identity: "1".repeat(16) + ":" + "2".repeat(32),
      sha256: sha(prepared.nonce),
      daclSha256: PIN,
    },
    inspected = {
      identity: prepared.observer,
      token: {
        tokenId: "00000000:00000002",
        modifiedId: "00000000:00000003",
        details: {
          appContainer: false,
          restricted: false,
          restrictingSids: 0,
          integrity: 12288,
          authenticationId: "00000000:00000001",
        },
      },
      effective: { available: true, success: true, failure: true, error: 0 },
      gate,
    };
  const files = Array.from({ length: 4 }, (_, i) => ({
    ...gate,
    identity:
      i === 3 ? gate.identity : `${"1".repeat(16)}:${String(i + 3).repeat(32)}`,
  }));
  prepared.original = {
    files,
    cleanup: {
      systemSha256: PIN,
      files: files.map((file) => ({
        identity: file.identity,
        baselineSaclSha256: sha("baseline"),
        saclHex: Buffer.from("owned-acl").toString("hex"),
      })),
    },
  };
  const audit = (installed) => ({
    systemSha256: PIN,
    included: installed,
    files: files.map((file) => ({
      identity: file.identity,
      saclSha256: sha(installed ? "owned-acl" : "baseline"),
    })),
  });
  inspected.audit = audit(true);
  return {
    baseline: { ...structuredClone(inspected), audit: audit(false) },
    before: inspected,
    after: structuredClone(inspected),
    captureComplete: true,
  };
}
function alter(value, key, replacement) {
  const parts = key.split("."),
    last = parts.pop();
  parts.reduce((v, part) => v[part], value)[last] = replacement;
}

const commandEpoch =
  (BigInt(Date.parse("2026-10-09T00:00:00Z")) + 11644473600000n) * 10000n;
async function decodedCommandCapture(rows, endOffset = 200n) {
  const reads = new Map(),
    logons = new Map(),
    versions = [4656, 4663, 5152, 5156, 5157].map((id) => ({
      id,
      versions: [0],
    })),
    decoder = createWindowsAuditDecoder(
      { xml: async (bytes) => reads.get(sha(bytes)) },
      {
        sdkSha256: PIN,
        abiSha256: PIN,
        versions,
        mappingSha256: observationDigest(versions),
      },
    ),
    fields = (values) =>
      Object.entries(values).map(([name, value]) => ({
        nameHex: Buffer.from(name, "utf16le").toString("hex"),
        hex: Buffer.from(value, "utf16le").toString("hex"),
      })),
    barrier = async (sequence, count, time) => {
      const bytes = Buffer.alloc(20);
      bytes.writeUInt32LE(0xfffffffe);
      bytes.writeUInt32LE(sequence, 4);
      bytes.writeBigUInt64LE(time, 8);
      bytes.writeUInt32LE(count, 16);
      await decoder.push(bytes);
      return { sequence, time: time.toString(), records: count };
    };
  let total = 0;
  await decoder.push(Buffer.alloc(4));
  const start = await barrier(1, 0, commandEpoch);
  for (const [index, row] of rows.entries()) {
    const values = {
        Provider: "Microsoft-Windows-Security-Auditing",
        Channel: "Security",
        EventID: "4663",
        Version: "0",
        Keywords: "0x8020000000000000",
        TimeCreated:
          "2026-10-09T00:00:00." +
          String(row.offset ?? 100).padStart(7, "0") +
          "Z",
        EventRecordID: String(index + 1),
        ObjectType: "File",
        ProcessId: "123",
        ObjectName: "C:\\fixture\\outside",
        SubjectUserSid: identity.userSid,
        AccessMask: "0x2",
        SubjectLogonId: "0x1",
        ...row.fields,
      },
      bytes = Buffer.from(
        `<Event><System><EventID>${values.EventID}</EventID></System><EventData>${Object.entries(
          values,
        )
          .map(([key, value]) => `<Data Name="${key}">${value}</Data>`)
          .join("")}</EventData></Event>\0`,
        "utf16le",
      ),
      parsed = windowsCommandAuditRead({
        kind: "event",
        fields: fields(values),
      }),
      header = Buffer.alloc(4);
    reads.set(sha(bytes), parsed.native);
    logons.set(sha(bytes), parsed.logonId);
    header.writeUInt32LE(bytes.length);
    total += bytes.length;
    await decoder.push(Buffer.concat([header, bytes]));
  }
  const end = await barrier(2, rows.length, commandEpoch + endOffset);
  return {
    decoder,
    logons,
    start,
    end,
    async finish() {
      const bytes = Buffer.from(
          `<BookmarkList><Bookmark Channel="Security" RecordId="${rows.length}" IsCurrent="true"/></BookmarkList>\0`,
          "utf16le",
        ),
        header = Buffer.alloc(16);
      reads.set(sha(bytes), {
        kind: "bookmark",
        fields: fields({
          Channel: "Security",
          RecordId: String(rows.length),
          IsCurrent: "true",
        }),
      });
      header.writeUInt32LE(0xffffffff);
      header.writeUInt32LE(total, 4);
      header.writeUInt32LE(rows.length, 8);
      header.writeUInt32LE(bytes.length, 12);
      await decoder.push(Buffer.concat([header, bytes]));
      return decoder.finish();
    },
  };
}
function fixture(change = () => {}) {
  const calls = [],
    requests = [],
    deadlines = [],
    signals = [];
  let nonce,
    spec,
    custody = false,
    clock = 0;
  const inputs = {
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
  const prepared = {
    admission: true,
    auditInterface: true,
    completeRetirement: true,
    home: "C:\\fixture\\home",
    workspace: "C:\\fixture\\workspace",
    helper: "C:\\fixture\\helper.exe",
    helperSha256: PIN,
    observer: { ...identity, pid: 321 },
    gate: "\\\\.\\pipe\\fixture",
    gateFile: "C:\\fixture\\workspace\\gate",
    sentinelSha256: PIN,
    files: {
      inspect: "C:\\fixture\\workspace\\inspection",
      edit: "C:\\fixture\\workspace\\edit",
      outside: "C:\\fixture\\outside",
    },
  };
  const observed = (v) => {
    const file = {
      identity: "1".repeat(16) + ":" + "2".repeat(32),
      sha256: sha(nonce),
      daclSha256: PIN,
    };
    const token = {
      appContainer: false,
      restricted: !v.control,
      restrictingSids: v.control ? 0 : 3,
      restrictedSidsSha256: PIN,
      integrity: 8192,
      authenticationId: "00000000:00000001",
    };
    return {
      before: { ...identity },
      after: { ...identity },
      beforeToken: token,
      afterToken: { ...token },
      imageSha256: PIN,
      creationJob: true,
      captureComplete: true,
      start: { sequence: 1, time: "100", records: 0 },
      end: { sequence: 2, time: "110", records: 2 },
      object: {
        before: file,
        after: {
          ...file,
          sha256: sha(
            v.permit && v.action !== "inspect" ? nonce + "-edited" : nonce,
          ),
        },
      },
      gate: { before: file, after: file },
      events: [
        {
          recordId: "1",
          time: "105",
          logonId: "0000000000000001",
          raw: {
            pid: identity.pid,
            subjectSid: identity.userSid,
            target: v.target,
            opcode: v.permit ? "4663" : "4656",
            auditFailure: !v.permit,
            accessMask: v.action === "inspect" ? 1 : 2,
          },
        },
        {
          recordId: "2",
          time: "106",
          logonId: "0000000000000001",
          raw: {
            pid: identity.pid,
            subjectSid: identity.userSid,
            target: prepared.gateFile,
            opcode: "4663",
            auditFailure: false,
            accessMask: 1,
          },
        },
      ],
    };
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
    close: async () => calls.push("client-close"),
  };
  const effects = {
    noCustody: () => !custody,
    prepare: async (n) => {
      nonce = n;
      prepared.nonce = n;
      calls.push("prepare");
      return prepared;
    },
    setup: async () => {
      calls.push("setup");
      custody = true;
      return brokerSetup(prepared);
    },
    schema: async () => {
      calls.push("schema");
      return {};
    },
    arm: async () => {
      calls.push("arm");
      return {
        identity,
        token: {
          appContainer: false,
          restrictingSids: 0,
          integrity: 8192,
          authenticationId: "00000000:00000001",
        },
        imageSha256: PIN,
        captureReady: true,
        creationJob: true,
        independent: true,
        transport: {},
      };
    },
    control: async () => {
      calls.push("control");
      const control = {
        action: "outside",
        target: prepared.files.outside,
        permit: true,
        control: true,
      };
      return {
        observation: observed(control),
        reply: { exitCode: 0, stdout: "attempt:written" },
      };
    },
    release: async () => calls.push("release"),
    begin: async (_, value) => {
      spec = value;
      calls.push("begin");
    },
    observe: async (_, value) => observed(value),
    retire: async () => {
      calls.push("retire");
      return {
        independent: true,
        completeDomain: true,
        admissionsClosed: true,
        serverRetired: true,
        helpersRetired: true,
        observerRetired: true,
        readerRetired: true,
        jobClosed: true,
        emergency: false,
        auditRestored: true,
        fixturesRemoved: true,
        sentinelSha256: PIN,
        witnessSha256: PIN,
      };
    },
  };
  change({ effects, prepared, client, observed, calls, signals });
  return {
    calls,
    requests,
    deadlines,
    inputs,
    async run() {
      return runWindowsFeasibilityCommand(
        { platform: "win32" },
        inputs,
        {
          supports: () => true,
          parameters: (command, cwd, profile) =>
            feasibilityCommandParameters(command, cwd, profile, "win32"),
          open: () => client,
        },
        {
          effects,
          now: () => clock++,
          timeout: (ms) => {
            deadlines.push(ms);
            const signal = new AbortController();
            signals.push(signal);
            return signal.signal;
          },
        },
      );
    },
  };
}

test("Windows requests keep the supported default cap, credential-free homes and explicit authority", async () => {
  const env = windowsCommandEnvironment(
    "C:\\fixture\\home",
    "C:\\fixture\\release",
    "C:\\Windows",
  );
  assert.deepEqual(
    Object.keys(env).sort(),
    [
      "CI",
      "CODEX_HOME",
      "GITHUB_ACTIONS",
      "HOME",
      "PATH",
      "RUNNER_ENVIRONMENT",
      "RUNNER_OS",
      "SystemRoot",
      "TEMP",
      "TMP",
      "USERPROFILE",
      "WINDIR",
    ].sort(),
  );
  assert.equal(env.CODEX_HOME, "C:\\fixture\\home");
  assert.equal(
    env.PATH,
    "C:\\fixture\\release\\codex-path;C:\\Windows\\System32",
  );
  assert.throws(() =>
    windowsCommandEnvironment(
      "C:\\fixture\\..\\home",
      "C:\\release",
      "C:\\Windows",
    ),
  );
  const f = fixture(),
    result = await f.run();
  assert.equal(result.status, "PASS");
  assert.equal(result.cleanup.status, "PASS");
  assert.equal(f.requests.length, 6);
  assert.deepEqual(f.deadlines, [120000, 30000]);
  assert.deepEqual(f.calls.slice(0, 6), [
    "prepare",
    "setup",
    "schema",
    "arm",
    "control",
    "release",
  ]);
  for (const [i, v] of f.requests.entries()) {
    assert.equal(Object.hasOwn(v, "outputBytesCap"), false);
    assert.equal(v.sandboxPolicy.networkAccess, false);
    assert.equal(v.sandboxPolicy.type, i < 3 ? "readOnly" : "workspaceWrite");
    assert.equal(v.command.length, 8);
  }
});

test("native attribution, controls and original sentinels cannot be replaced by successful RPCs", async () => {
  for (const change of [
    (o) => o.before.pid++,
    (o) => (o.creationJob = false),
    (o) => (o.imageSha256 = sha("other")),
    (o) => (o.beforeToken.appContainer = true),
    (o) => (o.beforeToken.restrictingSids = 0),
    (o) => (o.beforeToken.restricted = false),
    (o) => (o.afterToken.authenticationId = "00000000:00000002"),
    (o) => (o.captureComplete = false),
    (o) => (o.events[0].raw.accessMask = 4),
    (o) => (o.events[0].raw.subjectSid = "S-1-5-21-11-22-33-1001"),
    (o) => (o.events[1].recordId = "1"),
    (o) => (o.events[0].logonId = "0000000000000002"),
    (o) => (o.object.after.sha256 = sha("changed")),
    (o) => (o.object.after.identity = "3".repeat(16) + ":" + "4".repeat(32)),
  ]) {
    const f = fixture(({ effects, observed }) => {
      effects.observe = async (_, v) => {
        const o = observed(v);
        change(o);
        return o;
      };
    });
    assert.equal((await f.run()).status, "FAIL");
    assert.equal(f.calls.includes("retire"), true);
  }
  const control = fixture(({ effects }) => {
    effects.control = async () => {
      throw new Error("outside control denied");
    };
  });
  assert.equal((await control.run()).status, "FAIL");
  assert.equal(control.calls.includes("release"), false);
});

test("finite Security reads retain typed fields and logon identity without consuming localized access lists", () => {
  const field = (name, value) => ({
    nameHex: Buffer.from(name, "utf16le").toString("hex"),
    hex: Buffer.from(value, "utf16le").toString("hex"),
  });
  const native = {
    kind: "event",
    fields: [
      field("EventID", "4663"),
      field("SubjectLogonId", "0x12"),
      field("AccessList", "%%4417\r\n\t%%4418"),
    ],
  };
  const result = windowsCommandAuditRead(native);
  assert.equal(result.logonId, "0000000000000012");
  assert.deepEqual(result.native.fields, [native.fields[0]]);
  assert.throws(() =>
    windowsCommandAuditRead({
      ...native,
      fields: [...native.fields, native.fields[0]],
    }),
  );
  assert.throws(() =>
    windowsCommandAuditRead({
      ...native,
      fields: [field("SubjectLogonId", "unverified")],
    }),
  );
});

test("unavailable prerequisites block before release; capture and retirement failures keep separate causes", async () => {
  const unavailable = fixture(
    ({ prepared }) => (prepared.completeRetirement = false),
  );
  assert.equal((await unavailable.run()).status, "BLOCKED");
  assert.deepEqual(unavailable.calls, ["prepare"]);
  const f = fixture(({ effects }) => {
    effects.observe = async () => {
      throw Object.assign(new Error("capture lost"), {
        feasibilityCause: {
          code: "missing-observation",
          detail: "Native capture lost its acknowledged window.",
        },
      });
    };
    effects.retire = async () => ({ independent: true, completeDomain: false });
  });
  const result = await f.run();
  assert.equal(result.status, "FAIL");
  assert.equal(
    result.cause.detail,
    "Native capture lost its acknowledged window.",
  );
  assert.equal(result.cleanup.status, "UNCERTAIN");
  assert.equal(f.inputs.commandCleanup, result.cleanup);
  for (const field of [
    "serverRetired",
    "helpersRetired",
    "observerRetired",
    "readerRetired",
    "jobClosed",
    "auditRestored",
    "fixturesRemoved",
  ]) {
    const incomplete = fixture(({ effects }) => {
      const retire = effects.retire;
      effects.retire = async () => ({ ...(await retire()), [field]: false });
    });
    assert.equal((await incomplete.run()).status, "FAIL");
  }
});

test("system-success disabled permits verified setup and requires the real control before release", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(source, /systemFileSuccess|AuditSetSystemPolicy/u);
  const f = fixture(({ prepared }) => {
    prepared.systemSuccess = false;
  });
  const result = await f.run();
  assert.equal(result.status, "PASS");
  assert.equal(result.cleanup.status, "PASS");
  assert.equal(f.requests.length, 6);
  assert.deepEqual(f.calls.slice(0, 3), ["prepare", "setup", "schema"]);
});

test("unavailable effective policy blocks setup before Codex probes and settles custody", async () => {
  for (const [key, value] of [
    ["before.effective.available", false],
    ["after.effective.success", false],
    ["before.effective.failure", false],
    ["after.effective.error", 5],
  ]) {
    const f = fixture(({ effects }) => {
        const capture = effects.setup;
        effects.setup = async () => {
          const o = await capture();
          alter(o, key, value);

          return o;
        };
      }),
      result = await f.run();
    assert.equal(result.status, "BLOCKED");
    assert.equal(result.cause.code, "prerequisite-unavailable");
    assert.equal(result.cleanup.status, "PASS");
    assert.deepEqual(f.calls, ["prepare", "setup", "retire"]);
    assert.deepEqual(f.requests, []);
  }
});

test("setup binds the original administrative token and held gate before any command control", async () => {
  const prepared = {
      nonce: "a".repeat(32),
      observer: identity,
      gateFile: "C:\\fixture\\gate",
    },
    complete = await brokerSetup(prepared);
  assert.match(
    windowsCommandBrokerSetup(prepared, complete),
    /^[a-f0-9]{64}$/u,
  );
  assert.throws(() => windowsCommandBrokerSetup(prepared, true));
  for (const [key, value] of [
    ["after.identity.creationTime", "102"],
    ["after.token.tokenId", "00000000:00000004"],
    ["after.token.modifiedId", "00000000:00000004"],
    ["before.token.details.integrity", 8192],
    ["before.token.details.restricted", true],
    ["after.gate.daclSha256", sha("changed")],
    ["baseline.audit.included", true],
    ["baseline.audit.files.1.saclSha256", sha("foreign")],
    ["before.audit.included", false],
    ["after.audit.systemSha256", sha("foreign")],
    ["before.audit.files.0.identity", "1".repeat(16) + ":" + "8".repeat(32)],
    ["after.audit.files.2.saclSha256", sha("foreign")],
    ["baseline.token.modifiedId", "00000000:00000004"],
    ["captureComplete", false],
  ]) {
    const o = structuredClone(complete);
    alter(o, key, value);
    assert.throws(() => windowsCommandBrokerSetup(prepared, o));
  }
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
      "utf8",
    ),
    inspection = source.slice(
      source.indexOf("static void command_broker_check("),
      source.indexOf("static void command_line("),
    );
  assert.match(inspection, /DuplicateHandle\(owner,.*&token,TOKEN_QUERY/u);
  assert.match(inspection, /OpenProcessToken\(owner,TOKEN_QUERY,&actual\)/u);
  for (const member of ["TokenId", "ModifiedId", "AuthenticationId"])
    assert.ok(inspection.includes(`&held->${member},&current->${member}`));
  assert.match(
    source,
    /AuditComputeEffectivePolicyByToken\(token,&command_category,1,&policy\)/u,
  );
  assert.match(source, /ImpersonateLoggedOnUser\(command_broker_token\)/u);
  assert.match(source, /CreateFileW\(command_paths\[3\],GENERIC_READ/u);
  for (const operation of ["V", "A"])
    assert.match(
      source,
      new RegExp(
        `strcmp\\(line,"${operation}"\\).*?need\\(command_setup_verified(?:[)&])`,
        "u",
      ),
    );
});

test("real control delivery joins decoded subject, object and completion evidence before release", async () => {
  for (const fault of [
    null,
    "missing",
    "historical",
    "pid",
    "sid",
    "logon",
    "object",
    "mask",
    "opcode",
    "marker",
    "marker-order",
    "loss",
    "reply",
    "restoration",
  ]) {
    const f = fixture(({ effects, prepared }) => {
        const control = effects.control,
          retire = effects.retire;
        effects.control = async () => {
          const value = await control(),
            rows = [
              {
                offset: 100,
                fields: {
                  ProcessId: "456",
                  ObjectName: prepared.files.outside.toUpperCase(),
                },
              },
              {
                offset: 150,
                fields: {
                  ProcessId: "456",
                  ObjectName: prepared.gateFile.toUpperCase(),
                  AccessMask: "0x1",
                },
              },
            ];
          if (fault === "missing") rows.length = 0;
          if (fault === "historical")
            rows[0].fields.TimeCreated = "2026-10-08T23:59:59.9999999Z";
          if (fault === "pid") rows[0].fields.ProcessId = "999";
          if (fault === "sid")
            rows[0].fields.SubjectUserSid = "S-1-5-21-10-20-30-1002";
          if (fault === "logon") rows[0].fields.SubjectLogonId = "0x2";
          if (fault === "object")
            rows[0].fields.ObjectName = "C:\\fixture\\other";
          if (fault === "mask") rows[0].fields.AccessMask = "0x1";
          if (fault === "opcode")
            Object.assign(rows[0].fields, {
              EventID: "4656",
              Keywords: "0x8010000000000000",
            });
          if (fault === "marker") rows.pop();
          if (fault === "marker-order") rows[1].offset = 90;
          if (fault === "loss") rows[0].fields.EventID = "1101";
          const capture = await decodedCommandCapture(rows),
            observation = value.observation;
          observation.before = {
            ...identity,
            pid: 456,
            creationTime: (commandEpoch + 10n).toString(),
          };
          observation.after = { ...observation.before };
          observation.start = capture.start;
          observation.end = capture.end;
          observation.events = capture.decoder.state().events.map((event) => ({
            ...event,
            logonId: capture.logons.get(event.raw.id),
          }));
          if (fault === "reply") value.reply.exitCode = 7;
          return value;
        };
        effects.retire = async () => ({
          ...(await retire()),
          auditRestored: fault !== "restoration",
        });
      }),
      result = await f.run();
    assert.equal(result.status, fault ? "FAIL" : "PASS", fault);
    assert.equal(
      result.cleanup.status,
      fault === "restoration" ? "UNCERTAIN" : "PASS",
      fault,
    );
    assert.ok(f.calls.indexOf("schema") < f.calls.indexOf("control"));
    assert.ok(f.calls.indexOf("arm") < f.calls.indexOf("control"));
    if (fault && fault !== "restoration") {
      assert.equal(f.calls.includes("release"), false, fault);
      assert.equal(f.requests.length, 0, fault);
    } else {
      assert.ok(f.calls.indexOf("control") < f.calls.indexOf("release"));
      assert.equal(f.requests.length, 6);
    }
  }
});

test("native subscription and capture retain case-variant real control names through decoding", async () => {
  const program = await commandCaptureProgram();
  assert.match(program.source, /SubjectUserSid/u);
  assert.match(program.source, /EventID=1101 or EventID=1102/u);
  const query = /static void command_audit_query[^\n]+\n([^\n]+)/u.exec(
    program.source,
  )[1];
  assert.ok(query.includes("ObjectType") && !query.includes("ObjectName"));
  for (const substitute of [false, true]) {
    let original;
    fixture((value) => {
      original = value;
    });
    await original.effects.prepare("a".repeat(32));
    const { observation, reply } = await original.effects.control(),
      capture = commandCaptureFixture(program),
      rows = [
        {
          offset: 100,
          fields: {
            ObjectName: substitute
              ? "C:\\fixture\\other"
              : original.prepared.files.outside.toUpperCase(),
          },
        },
        {
          offset: 150,
          fields: {
            ObjectName: original.prepared.gateFile.toUpperCase(),
            AccessMask: "0x1",
          },
        },
      ];
    Object.assign(capture.api, {
      command_case_pid: identity.pid,
      command_action: 2,
      command_target_seen: false,
      command_marker_seen: false,
      command_paths: [
        original.prepared.files.inspect,
        original.prepared.files.edit,
        original.prepared.files.outside,
        original.prepared.gateFile,
      ],
      _wcsicmp: (a, b) => (a.toLowerCase() === b.toLowerCase() ? 0 : 1),
      wcscmp: (a, b) => (a === b ? 0 : 1),
      _wcstoui64: (text, end) => {
        end("");
        return Number(text);
      },
    });
    capture.api.onProject = (index) => {
      Object.assign(capture.api, {
        process: String(identity.pid),
        object: rows[index].fields.ObjectName,
        eventId: "4663",
        mask: rows[index].fields.AccessMask ?? "0x2",
      });
      const selected = program.selection.runInNewContext(capture.api);
      if (selected) program.caseProjection.runInNewContext(capture.api);
      return selected;
    };
    capture.notify(["0", "1"]);
    capture.capture();
    assert.equal(capture.api.command_target_seen, !substitute);
    assert.equal(capture.api.command_marker_seen, !substitute);
    const decoded = await decodedCommandCapture(
      capture.projected.map((index) => rows[index]),
    );
    observation.before.creationTime = observation.after.creationTime = (
      commandEpoch + 10n
    ).toString();
    observation.start = decoded.start;
    observation.end = decoded.end;
    observation.events = decoded.decoder.state().events.map((event) => ({
      ...event,
      logonId: decoded.logons.get(event.raw.id),
    }));
    const verify = () =>
      assessWindowsCommandObservation(
        {
          action: "outside",
          control: true,
          permit: true,
          target: original.prepared.files.outside,
          gateFile: original.prepared.gateFile,
          helperSha256: PIN,
          userSid: identity.userSid,
          sessionId: identity.sessionId,
          authenticationId: "00000000:00000001",
        },
        observation,
        reply,
        original.prepared.nonce,
      );
    if (substitute) assert.throws(verify);
    else assert.match(verify(), /^[a-f0-9]{64}$/u);
  }
});

test("actual effects require the assessed real control and restored target before release", async () => {
  const source = await readFile(
      new URL(
        "../ci/native/win32/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    call = source.slice(
      source.indexOf("  const call = (operation) =>"),
      source.indexOf("  const native = async"),
    ),
    control = source.slice(
      source.indexOf("    async control(value, signal) {"),
      source.indexOf("    async begin(value, spec)"),
    ),
    program = new Script(`(async () => {
      let failed, closing = false, setupVerified = true, controlVerified = false, start, probeOutput = "";
      const pending = new Map(), observationSignal = signal;
      const broker = { stdin: { writable: true, write(frame) {
        const key = frame.trim(); calls.push(key);
        if(key === "C") probeOutput = reply.stdout;
        const entry = pending.get(key); pending.delete(key);
        if(key === "X" && resetFailure) entry.reject(resetFailure);
        else entry.resolve(key === "B" ? observed.start : {});
      } } };
      ${call}
      const effects = { release: () => call("R"), ${control} };
      let refused = 0, failure;
      try { effects.release(); } catch { refused++; }
      let result;
      try { result = await effects.control(value, signal); } catch (error) { failure = error; }
      if(failure) { try { effects.release(); } catch { refused++; } }
      else await effects.release();
      return { result, failure, refused, controlVerified };
    })()`);
  for (const fault of [null, "marker", "reset"]) {
    let original;
    fixture((value) => {
      original = value;
    });
    const { effects, prepared } = original;
    await effects.prepare("a".repeat(32));
    const { observation: observed, reply } = await effects.control();
    if (fault === "marker") observed.events.pop();
    const calls = [],
      resetFailure = new Error("Owned control target reset failed"),
      result = await program.runInNewContext({
        need: assert.ok,
        calls,
        value: prepared,
        reply,
        observed,
        signal: new AbortController().signal,
        resetFailure: fault === "reset" ? resetFailure : null,
        serverAdmission: {
          identity,
          token: { authenticationId: "00000000:00000001" },
        },
        observation: async () => ({
          ...observed,
          controlExitCode: reply.exitCode,
        }),
        assessWindowsCommandObservation,
      });
    assert.equal(result.controlVerified, !fault, fault);
    assert.equal(result.refused, fault ? 2 : 1);
    assert.deepEqual(
      calls,
      fault === "marker"
        ? ["B", "C"]
        : fault === "reset"
          ? ["B", "C", "X"]
          : ["B", "C", "X", "R"],
    );
    if (fault === "reset") assert.equal(result.failure, resetFailure);
  }
});

test("terminal capture requires a separate post-domain broker event and complete decoder closure", async () => {
  const source = await readFile(
      new URL(
        "../ci/native/win32/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    close = source.slice(
      source.indexOf("        async closeObserver() {"),
      source.indexOf("        async verifyObserver() {"),
    ),
    program = new Script(`(async () => {
      let capture;
      const owner = { ${close} };
      await owner.closeObserver();
      return capture;
    })()`);
  for (const fault of [
    null,
    "absent",
    "last-marker",
    "stale",
    "sid",
    "logon",
    "object",
    "mask",
    "boundary",
    "unclosed",
  ]) {
    const value = {
        nonce: "a".repeat(32),
        observer: { ...identity, pid: 321 },
        gateFile: "C:\\fixture\\gate",
      },
      setup = await brokerSetup(value),
      rows =
        fault === "absent"
          ? []
          : [
              {
                offset: 300,
                fields: {
                  ProcessId: "321",
                  ObjectName: value.gateFile.toUpperCase(),
                  AccessMask: "0x1",
                },
              },
            ];
    value.brokerSetup = setup;
    value.lastAuditTime = (commandEpoch + 200n).toString();
    value.auditRetirement = (
      commandEpoch + (fault === "boundary" ? 100n : 250n)
    ).toString();
    if (fault === "last-marker") rows[0].fields.ProcessId = "456";
    if (fault === "stale") rows[0].offset = 100;
    if (fault === "sid")
      rows[0].fields.SubjectUserSid = "S-1-5-21-10-20-30-1002";
    if (fault === "logon") rows[0].fields.SubjectLogonId = "0x2";
    if (fault === "object") rows[0].fields.ObjectName = "C:\\fixture\\other";
    if (fault === "mask") rows[0].fields.AccessMask = "0x2";
    const capture = await decodedCommandCapture(rows, 400n);
    const finished = fault === "unclosed" ? null : await capture.finish(),
      verify = () =>
        program.runInNewContext({
          value,
          setupVerified: true,
          logons: capture.logons,
          decoder: { finish: () => finished ?? capture.decoder.finish() },
          windowsCommandTerminalCapture,
          need: assert.ok,
          call: async (key) => {
            assert.equal(key, "S");
            return { captureRetired: true };
          },
          closed: Promise.resolve({ code: 0, signal: null }),
          reading: Promise.resolve(),
          nativeException: assert.fail,
          fail: assert.fail,
        });
    if (fault) await assert.rejects(verify, fault);
    else
      assert.equal(
        (await verify()).nativeEventSha256,
        finished.nativeEventSha256,
      );
  }
});

test("native setup permits the parked control while release and forwarding require its completion", async () => {
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
      "utf8",
    ),
    line = (key) =>
      source
        .split("\n")
        .find(
          (row) =>
            row.includes(`strcmp(line,"${key}")`) ||
            row.includes(`strncmp(line,"${key} ",`),
        ),
    check = (key, api) =>
      new Script(/need\((.+?)\);/u.exec(line(key))[1]).runInNewContext(api);
  for (const setup of [false, true]) {
    const api = {
      command_setup_verified: setup,
      server: { hProcess: 1 },
      command_server_released: false,
      command_control_verified: false,
      command_control: false,
    };
    assert.equal(check("C", api), setup);
    assert.equal(check("A", { ...api, server: {} }), setup);
  }
  for (const control of [false, true])
    for (const released of [false, true])
      assert.equal(
        !!check("J", {
          command_control_verified: control,
          command_server_released: released,
          command_input: 1,
          command_closing: false,
        }),
        control && released,
      );
  for (const control of [false, true]) {
    let resumed = 0;
    assert.equal(
      check("R", {
        command_control_verified: control,
        command_server_released: false,
        command_closing: false,
        server: { hProcess: 1, hThread: 2 },
        ResumeThread: () => {
          resumed++;
          return 1;
        },
      }),
      control,
    );
    assert.equal(resumed, control ? 1 : 0);
  }
  for (const missing of [
    null,
    "command_control_completed",
    "command_target_seen",
    "command_marker_seen",
  ]) {
    const api = {
      command_control_completed: true,
      command_target_seen: true,
      command_marker_seen: true,
      command_server_released: false,
      command_control_verified: false,
    };
    if (missing) api[missing] = false;
    assert.equal(check("X", api), !missing);
  }
  assert.doesNotMatch(
    source,
    /strcmp\(line,"[PM]"\)|command_coverage_control|command_delivery_query/u,
  );
  const retirement = source.slice(
    source.indexOf("static void command_retire_domain(void) {"),
    source.indexOf("static void command_check("),
  );
  assert.ok(
    retirement.indexOf("!command_members(ownedJob)") <
      retirement.indexOf("GetSystemTimePreciseAsFileTime(&auditFrom)"),
  );
  assert.ok(
    retirement.indexOf("GetSystemTimePreciseAsFileTime(&auditFrom)") <
      retirement.indexOf("command_gate_read()"),
  );
});

test("native terminal waiting ignores queued broker records from before domain retirement", async () => {
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
      "utf8",
    ),
    body = /static BOOL command_terminal_time\([^\n]+\) \{([\s\S]*?)\n\}/u
      .exec(source)[1]
      .replace(
        "unsigned parts[6]={0},starts[6]={0,5,8,11,14,17};",
        "const parts=Array(6).fill(0),starts=[0,5,8,11,14,17];",
      )
      .replace(
        "WCHAR c=text[starts[i]+j]",
        "let c=text.charCodeAt(starts[i]+j)",
      )
      .replaceAll("text[i]", "text.charCodeAt(i)")
      .replaceAll("L'0'", "48")
      .replaceAll("L'9'", "57")
      .replace("SYSTEMTIME value={0};", "const value={};")
      .replace("FILETIME time;", "const time={};")
      .replace("ULARGE_INTEGER ticks;", "const ticks={};")
      .replaceAll("(WORD)", "")
      .replace(
        "SystemTimeToFileTime(&value,&time)",
        "SystemTimeToFileTime(value,time)",
      )
      .replace("ticks.QuadPart+fraction", "BigInt(time.ticks)+BigInt(fraction)")
      .replace(/\bL(?=['"])/gu, "")
      .replace(/\b(?:size_t|unsigned|DWORD)\b/gu, "let"),
    timestamp = new Script(`(text) => {${body}}`).runInNewContext({
      FALSE: false,
      wcslen: (text) => text.length,
      BigInt,
      command_retirement_from: commandEpoch + 100n,
      SystemTimeToFileTime: (value, result) => {
        const time = new Date(
          Date.UTC(
            value.wYear,
            value.wMonth - 1,
            value.wDay,
            value.wHour,
            value.wMinute,
            value.wSecond,
          ),
        );
        if (
          time.getUTCFullYear() !== value.wYear ||
          time.getUTCMonth() + 1 !== value.wMonth ||
          time.getUTCDate() !== value.wDay ||
          value.wHour > 23 ||
          value.wMinute > 59 ||
          value.wSecond > 59
        )
          return false;
        result.ticks = (BigInt(time.getTime()) + 11644473600000n) * 10000n;
        return true;
      },
    }),
    line = source
      .split("\n")
      .find((row) => row.trim().startsWith("if(command_closing&&process")),
    project = new Script(
      line
        .replace(/\bL(?=")/gu, "")
        .replace("WCHAR *end;", "let end;")
        .replace(/ULONGLONG (pid|rights)/gu, "let $1")
        .replaceAll("&end", "value=>end=value")
        .replaceAll("!*end", "!end"),
    );
  for (const [stamp, expected] of [
    ["2026-10-09T00:00:00Z", false],
    ["2026-10-09T00:00:00.0000099Z", false],
    ["2026-10-09T00:00:00.0000100Z", false],
    ["2026-10-09T00:00:00.0000101Z", true],
    ["2026-10-09T00:00:00.1Z", true],
    ["2026-10-09T00:00:01Z", true],
    ["2026-10-09T00:00:00.Z", false],
    ["2026-10-09T00:00:00.00001010Z", false],
    ["2026-10-09T00:00:00.0000101+00:00", false],
    ["2026-10-09 00:00:00.0000101Z", false],
    ["2026-10-09T00:00:0a.0000101Z", false],
    ["2026-13-09T00:00:00.0000101Z", false],
    ["2026-02-31T00:00:00.0000101Z", false],
  ]) {
    const api = {
      command_closing: true,
      command_retirement_seen: false,
      process: "321",
      object: "C:\\fixture\\gate",
      eventId: "4663",
      mask: "1",
      stamp,
      command_paths: [null, null, null, "C:\\fixture\\gate"],
      command_terminal_time: timestamp,
      GetCurrentProcessId: () => 321,
      TRUE: true,
      wcscmp: (a, b) => (a === b ? 0 : 1),
      _wcsicmp: (a, b) => (a.toLowerCase() === b.toLowerCase() ? 0 : 1),
      _wcstoui64: (text, end) => {
        end("");
        return Number(text);
      },
    };
    project.runInNewContext(api);
    assert.equal(api.command_retirement_seen, expected, stamp);
  }
});

test("partial setup and interrupted admission preserve the first cause and separate settlement uncertainty", async () => {
  for (const stage of ["partial-installation", "transport", "interruption"]) {
    const f = fixture(({ effects, signals }) => {
        const capture = effects.setup;
        effects.setup = async () => {
          await capture();
          if (stage === "interruption") {
            signals[0].abort();
            return new Promise(() => {});
          }
          throw Object.assign(new Error(stage), {
            feasibilityCause: { code: "setup-failed", detail: stage },
          });
        };
        if (stage === "transport")
          effects.retire = async () => ({ completeDomain: false });
      }),
      result = await f.run();
    assert.equal(result.status, "FAIL");
    if (stage !== "interruption") assert.equal(result.cause.detail, stage);
    assert.equal(
      result.cleanup.status,
      stage === "transport" ? "UNCERTAIN" : "PASS",
    );
    assert.deepEqual(f.requests, []);
    assert.deepEqual(f.calls.slice(0, 2), ["prepare", "setup"]);
  }
  const source = await readFile(
      new URL(
        "../ci/native/win32/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    coverage = source.slice(
      source.indexOf("async setup("),
      source.indexOf("async schema("),
    );
  for (const owner of [
    "watcher = await watch(",
    "cleanupReader.initialize(",
    "restorationReader.initialize(",
    "restorationVerifier = await watch(",
    "readerVerifier = await watch(",
    "observerVerifier = await watch(",
  ]) {
    const acquired = coverage.indexOf(owner);
    assert.ok(acquired >= 0 && acquired < coverage.indexOf('call("I")'), owner);
  }
  assert.ok(
    coverage.indexOf("windowsCommandBrokerSetup(") <
      coverage.indexOf("setupVerified = true"),
  );
  for (const obsolete of ['call("P")', 'call("M")'])
    assert.equal(coverage.includes(obsolete), false);
});

test("failed buffered replies and unavailable routes retain the first process cause and components", async () => {
  for (const [reply, status] of [
    [{ exitCode: 7, stdout: "", stderr: "" }, "FAIL"],
    [
      Object.assign(new Error("route missing"), {
        code: "ERR_FEASIBILITY_ROUTE_UNAVAILABLE",
      }),
      "BLOCKED",
    ],
  ]) {
    const f = fixture(({ effects, client }) => {
      client.exec = async () => {
        if (reply instanceof Error) throw reply;
        return reply;
      };
      effects.observe = () => new Promise(() => {});
    });
    const result = await f.run();
    assert.equal(result.status, status);
    assert.equal(result.cleanup.status, "PASS");
    if (status === "FAIL")
      assert.match(result.cause.detail, /buffered-reply: exit=7/u);
    assert.equal(result.components[0].sha256, PIN);
  }
});

test("observation and cleanup abort independently without sleeping or native processes", async () => {
  for (const phase of ["observe", "retire"]) {
    const f = fixture(({ effects, signals }) => {
      effects[phase] = () => {
        signals[phase === "observe" ? 0 : 1].abort();
        return new Promise(() => {});
      };
    });
    const result = await f.run();
    assert.equal(result.status, "FAIL");
    assert.deepEqual(f.deadlines, [120000, 30000]);
    assert.equal(
      result.cleanup.status,
      phase === "observe" ? "PASS" : "UNCERTAIN",
    );
  }
});

test("failed native domain settlement still retires the observer and never releases fixture restoration", async () => {
  for (const emergency of [false, true]) {
    const calls = [],
      failure = new Error("native Job inventory failed");
    await assert.rejects(
      settleWindowsCommandCustody({
        retireDomain: async () => {
          throw failure;
        },
        prepareFinish: async () => calls.push("prepare"),
        closeObserver: async () => {
          calls.push("close");
          return { captureRetired: true };
        },
        verifyObserver: async () => {
          calls.push("verify");
          if (emergency)
            throw Object.assign(new Error("observer forced retirement"), {
              emergency: true,
            });
          return { completeDomain: true };
        },
        abandonFinish: async () => calls.push("abandon"),
        finish: async () => calls.push("restore"),
      }),
      (error) => error === failure && error.emergency === emergency,
    );
    assert.deepEqual(calls, ["close", "verify", "abandon"]);
  }
});

test("capture and watcher failures restore owned changes only after independent retirement and still fail", async () => {
  for (const phase of ["capture", "watcher", "unverified-watcher"]) {
    const calls = [],
      failure = new Error(`${phase} transport lost`);
    await assert.rejects(
      settleWindowsCommandCustody({
        retireDomain: async () => {
          calls.push("domain");
          return { empty: true, admissionsClosed: true };
        },
        prepareFinish: async () => calls.push("originals"),
        closeObserver: async () => {
          calls.push("capture");
          if (phase === "capture") throw failure;
          return { captureRetired: true };
        },
        verifyObserver: async () => {
          calls.push("retired");
          if (phase === "unverified-watcher") throw failure;
          return {
            completeDomain: true,
            failure: phase === "watcher" ? failure : undefined,
          };
        },
        finish: async () => calls.push("restore"),
        abandonFinish: async () => calls.push("abandon"),
      }),
      (error) => error === failure,
    );
    assert.deepEqual(calls, [
      "domain",
      "originals",
      "capture",
      "retired",
      phase === "unverified-watcher" ? "abandon" : "restore",
    ]);
  }
});

test("failed original-handle checks forbid restoration even after empty Job and observer retirement", async () => {
  const calls = [],
    failure = new Error("original gate changed");
  await assert.rejects(
    settleWindowsCommandCustody({
      retireDomain: async () => ({ empty: true, admissionsClosed: true }),
      prepareFinish: async () => {
        throw failure;
      },
      closeObserver: async () => ({ captureRetired: true }),
      verifyObserver: async () => ({ completeDomain: true }),
      finish: async () => calls.push("restore"),
      abandonFinish: async () => calls.push("abandon"),
    }),
    (error) => error === failure,
  );
  assert.deepEqual(calls, ["abandon"]);
});

test("fixture restoration requires final original identities and unchanged outside/gate sentinels", () => {
  const original = [1, 2, 3, 4].map((v) => ({
    identity: "1".repeat(16) + ":" + String(v).repeat(32),
    sha256: PIN,
    daclSha256: PIN,
  }));
  const permitted = structuredClone(original);
  permitted[1].sha256 = sha("edited");
  assert.equal(
    windowsCommandCleanupSnapshot(original, permitted),
    sha(JSON.stringify(original[2])),
  );
  for (const [i, key] of [
    [0, "identity"],
    [2, "sha256"],
    [2, "daclSha256"],
    [3, "sha256"],
    [3, "daclSha256"],
  ]) {
    const changed = structuredClone(original);
    changed[i][key] = sha("changed");
    assert.throws(() => windowsCommandCleanupSnapshot(original, changed));
  }
});

test("native command opens respect held deletion custody without allowing replacement", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const held =
    /command_files\[i\]=CreateFileW\(command_paths\[i\],([^,]+),([^,]+),/u.exec(
      source,
    );
  assert.ok(held);
  assert.match(held[1], /\bDELETE\b/u);
  assert.doesNotMatch(held[2], /\bFILE_SHARE_DELETE\b/u);
  for (const argument of [3, 6]) {
    const opened = new RegExp(
      `CreateFileW\\(argv\\[${argument}\\],([^,]+),([^,]+),`,
      "u",
    ).exec(source);
    assert.ok(opened);
    assert.match(opened[2], /\bFILE_SHARE_DELETE\b/u);
    assert.doesNotMatch(opened[1], /\bDELETE\b/u);
  }
});

test("native custody retains live handles, original NUL and saved ACL protection through restoration", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const finish = source.slice(
    source.indexOf("static void command_finish("),
    source.indexOf("static void command_watch("),
  );
  const watch = source.slice(
    source.indexOf("static void command_watch("),
    source.indexOf("static int command_main("),
  );
  for (const body of [finish, watch])
    assert.match(
      body,
      /creation\(owner\)==number\(argv\[3\]\)&&WaitForSingleObject\(owner,0\)==WAIT_TIMEOUT/u,
    );
  assert.match(
    finish,
    /DuplicateHandle\(owner,\(HANDLE\)\(ULONG_PTR\)nullValue,GetCurrentProcess\(\),&null,READ_CONTROL/u,
  );
  assert.doesNotMatch(finish, /CreateFileW/u);
  const custody = finish.indexOf('puts("{\\"custodyReady\\":true}")');
  assert.ok(custody > 0);
  assert.equal(
    finish.slice(0, custody).match(/command_sd\(null,SE_KERNEL_OBJECT/gu)
      ?.length,
    1,
  );
  assert.equal(
    finish.slice(custody).match(/command_sd\(null,SE_KERNEL_OBJECT/gu)?.length,
    2,
  );
  assert.match(
    finish.slice(custody),
    /AuditEnumerateSubCategories\(NULL,TRUE,&command_categories,&command_category_count\)[\s\S]*AuditQuerySystemPolicy[\s\S]*command_sum[\s\S]*!strcmp\(actual,systemHash\)/u,
  );
  assert.match(
    source,
    /i==3\?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION/u,
  );
  assert.match(
    finish,
    /GetSecurityDescriptorControl\(baselines\[i\],&control,&revision\)/u,
  );
  assert.match(
    finish,
    /control&SE_SACL_PROTECTED\?PROTECTED_SACL_SECURITY_INFORMATION:UNPROTECTED_SACL_SECURITY_INFORMATION/u,
  );
  assert.doesNotMatch(
    finish,
    /SetSecurityInfo\([^;]+DACL_SECURITY_INFORMATION/u,
  );
  const owned = source.slice(
    source.indexOf("static void command_owned_sacl("),
    source.indexOf("static BOOL command_owned_policy(BOOL authorized) {"),
  );
  assert.match(
    owned,
    /GetSecurityDescriptorDacl[\s\S]*command_same_acl\(dacl,oldDacl\)/u,
  );
  assert.match(owned, /\(current\^saved\)&~SE_SACL_PRESENT/u);
  assert.ok(
    finish.indexOf("ack('V')") < finish.indexOf("FILE_DISPOSITION_INFO"),
  );
});

test("native watcher stream failures preserve their cause; recorded exit cannot replace a retirement witness", async () => {
  const launch = (failure, terminal) => () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    const close = async (code) => {
      const ended = once(child.stderr, "end");
      child.stdout.end();
      child.stderr.end();
      await ended;
      child.emit("close", code, null);
    };
    child.stdin = new Writable({
      write(value, encoding, done) {
        if (failure) done(failure);
        else {
          if (terminal) child.stdout.write(JSON.stringify(terminal) + "\n");
          done();
          queueMicrotask(() => close(0));
        }
      },
    });
    child.stdin.once("error", () => queueMicrotask(() => close(126)));
    queueMicrotask(() =>
      child.stdout.write(JSON.stringify({ ready: true, identity }) + "\n"),
    );
    return child;
  };
  const signal = new AbortController().signal;
  for (const operation of ["initialize", "inspect", "finish"]) {
    const failure = Object.assign(new Error("native pipe closed"), {
      code: "EPIPE",
    });
    const owner = await openWindowsCommandWatcher(
      "C:\\fixture\\helper.exe",
      [],
      {},
      signal,
      launch(failure),
    );
    await assert.rejects(
      owner[operation]("baseline\n"),
      (error) => error === failure,
    );
  }
  for (const terminal of [
    null,
    { retired: true, completeDomain: false },
    { retired: true, completeDomain: true },
  ]) {
    const owner = await openWindowsCommandWatcher(
      "C:\\fixture\\helper.exe",
      [],
      {},
      signal,
      launch(null, terminal),
    );
    if (terminal?.completeDomain)
      assert.deepEqual(await owner.finish(), terminal);
    else await assert.rejects(owner.finish());
  }
  const observation = new AbortController(),
    terminal = { retired: true, completeDomain: true },
    owner = await openWindowsCommandWatcher(
      "C:\\fixture\\helper.exe",
      [],
      {},
      observation.signal,
      launch(null, terminal),
    );
  observation.abort();
  assert.deepEqual(await owner.finish(signal), terminal);
});

test("Windows buffered client accepts only its platform request shape and keeps the independent reply bound", async () => {
  const input = new PassThrough(),
    output = new PassThrough(),
    errorOutput = new PassThrough();
  const methods = [];
  let buffered = "";
  input.on("data", (bytes) => {
    buffered += bytes.toString();
    let at;
    while ((at = buffered.indexOf("\n")) >= 0) {
      const value = JSON.parse(buffered.slice(0, at));
      buffered = buffered.slice(at + 1);
      methods.push(value.method);
      if (value.id)
        output.write(
          JSON.stringify({
            id: value.id,
            result:
              value.method === "initialize"
                ? {}
                : { exitCode: 0, stdout: "x".repeat(8193), stderr: "" },
          }) + "\n",
        );
    }
  });
  input.on("end", () => {
    output.end();
    errorOutput.end();
  });
  const client = openFeasibilityCommand(
    { input, output, errorOutput },
    undefined,
    "win32",
  );
  await client.initialize();
  const request = feasibilityCommandParameters(
    ["C:\\fixture\\helper.exe"],
    "C:\\fixture",
    "read-only",
    "win32",
  );
  await assert.rejects(client.exec({ ...request, outputBytesCap: 4096 }));
  await assert.rejects(client.exec({ ...request, streamStdoutStderr: true }));
  await assert.rejects(client.exec(request));
  await client.close();
  assert.deepEqual(methods, ["initialize", "initialized", "command/exec"]);
});

function commandBuildFixture(compiler = "C:\\compiler\\cl.exe") {
  const calls = [],
    reads = [],
    components = [],
    image = Buffer.from("neutral image"),
    environment = {
      WindowsSDKVersion: "10.0.26100.0\\",
      WindowsSdkDir: "C:\\sdk",
      SystemRoot: "C:\\Windows",
    };
  const effects = {
    environment,
    command: async (file, args, options) => {
      calls.push({ file, args, options });
      if (file === "where.exe") return { stdout: compiler + "\r\n" };
      if (args[0] === "/Bv")
        throw Object.assign(new Error("version query"), {
          code: 2,
          signal: null,
          stdout: "",
          stderr: "Compiler Version 19.51.36260 for x64",
        });
      if (file.endsWith("powershell.exe"))
        return {
          stdout: "native-linker-version=14.51.36260.0\r\n",
          stderr: "",
        };
      return { stdout: "", stderr: "" };
    },
    read: async (file) => {
      reads.push(file);
      return /(?:command-helper|custody-reader)\.exe$/u.test(file)
        ? image
        : Buffer.from(windowsPath.basename(file));
    },
    inspect: (bytes) => assert.equal(bytes, image),
  };
  return {
    calls,
    reads,
    components,
    effects,
    compiler,
    image,
    build: (signal, builder = buildWindowsCommandHelper) =>
      builder("C:\\owned\\fixture", components, signal, effects),
  };
}

test("both audit builds reserve the existing ceiling for compile/link and retain discovery options", async () => {
  assert.equal(WINDOWS_BUILD_COMMAND_MS, 60000);
  for (const builder of [
    buildWindowsCommandHelper,
    buildWindowsCustodyReader,
  ]) {
    const f = commandBuildFixture(),
      controller = new AbortController();
    await f.build(controller.signal, builder);
    assert.deepEqual(
      f.calls.map(({ options }) => options.timeout),
      [10000, 10000, 10000, WINDOWS_BUILD_COMMAND_MS, WINDOWS_BUILD_COMMAND_MS],
    );
    assert.deepEqual(
      f.calls.map(({ options }) => options.maxBuffer),
      [1048576, 1048576, 4096, 1048576, 1048576],
    );
    for (const { options } of f.calls) {
      assert.equal(options.signal, controller.signal);
      assert.equal(options.env, f.effects.environment);
      assert.equal(options.windowsHide, true);
    }
    for (const { options } of f.calls.slice(-2))
      assert.equal(options.cwd, "C:\\owned\\fixture\\build");
  }
});

test("both audit builds stop after cancellation before compile or between compile and link", async () => {
  for (const builder of [
    buildWindowsCommandHelper,
    buildWindowsCustodyReader,
  ]) {
    for (const boundary of ["before-compile", "after-compile"]) {
      const f = commandBuildFixture(),
        controller = new AbortController(),
        read = f.effects.read,
        command = f.effects.command;
      f.effects.read = async (file) => {
        const bytes = await read(file);
        if (
          boundary === "before-compile" &&
          file.endsWith("audit-policy-remove.h")
        )
          controller.abort();
        return bytes;
      };
      f.effects.command = async (file, args, options) => {
        const result = await command(file, args, options);
        if (boundary === "after-compile" && args.includes("/c"))
          controller.abort();
        return result;
      };
      await assert.rejects(
        f.build(controller.signal, builder),
        (error) => error.cause === controller.signal.reason,
      );
      assert.equal(
        f.calls.filter(({ args }) => args.includes("/c")).length,
        boundary === "after-compile" ? 1 : 0,
      );
      assert.equal(
        f.calls.some(({ file }) => file.endsWith("link.exe")),
        false,
      );
      assert.equal(
        f.components.some(({ role }) => role === "helper"),
        false,
      );
    }
  }
});

test("copied Windows environment retains the installed linker query across native key casing", async () => {
  const f = commandBuildFixture();
  const source = {
    ...f.effects.environment,
    SYSTEMROOT: f.effects.environment.SystemRoot,
  };
  delete source.SystemRoot;
  f.effects.environment = windowsFeasibilityToolEnvironment(source);
  await f.build();
  const query = f.calls.find((call) => call.file.endsWith("powershell.exe"));
  assert.equal(
    query.file,
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  );
  assert.equal(query.options.env.SystemRoot, "C:\\Windows");
  assert.equal(
    f.components.find((component) => component.name === "msvc-linker").version,
    "14.51.36260.0",
  );
});

test("command helper separates compilation/linking and retains source identities before image admission", async () => {
  const f = commandBuildFixture(),
    built = await f.build();
  const compile = f.calls.find((call) => call.args.includes("/c")),
    link = f.calls.find((call) => call.file.endsWith("link.exe"));
  assert.equal(compile.file, f.compiler);
  for (const flag of [
    "/std:c17",
    "/O2",
    "/W4",
    "/MT",
    "/Brepro",
    "/DNATIVE_COMMAND_EXPERIMENT",
  ])
    assert.ok(compile.args.includes(flag));
  assert.ok(!compile.args.includes("/link"));
  assert.equal(link.args.includes("/INCREMENTAL:NO"), true);
  for (const lib of [
    "advapi32.lib",
    "userenv.lib",
    "bcrypt.lib",
    "ws2_32.lib",
    "wevtapi.lib",
    "xmllite.lib",
    "ole32.lib",
    "uuid.lib",
  ])
    assert.ok(link.args.includes(lib));
  assert.equal(link.options.env, f.effects.environment);
  assert.ok(
    link.args.includes(compile.args.find((v) => v.startsWith("/Fo")).slice(3)),
  );
  assert.deepEqual(
    f.components.map((v) => v.name),
    [
      "msvc",
      "msvc-linker",
      "windows-sdk-header",
      "windows-command-source",
      "windows-command-header",
      "windows-command-xml",
      "windows-audit-removal-source",
      "windows-command-helper",
    ],
  );
  assert.equal(built.helperSha256, sha(f.image));
  assert.equal(f.components.at(-1).sha256, built.helperSha256);
  assert.deepEqual(f.components.slice(0, 2), [
    {
      role: "tool",
      name: "msvc",
      version: "19.51.36260",
      sha256: sha("cl.exe"),
    },
    {
      role: "tool",
      name: "msvc-linker",
      version: "14.51.36260.0",
      sha256: sha("link.exe"),
    },
  ]);
});

test("build-only custody reader uses the default compiler/link recipe without executing the image", async () => {
  const f = commandBuildFixture();
  const built = await buildWindowsCustodyReader(
    "C:\\owned\\fixture",
    f.components,
    undefined,
    f.effects,
  );
  const compile = f.calls.find((call) => call.args.includes("/c")),
    link = f.calls.find((call) => call.file.endsWith("link.exe"));
  assert.ok(compile.args.some((arg) => arg.endsWith("custody-reader.c")));
  assert.ok(!compile.args.includes("/DNATIVE_COMMAND_EXPERIMENT"));
  for (const flag of ["/std:c17", "/O2", "/W4", "/Brepro"])
    assert.ok(compile.args.includes(flag));
  assert.ok(compile.args.includes("/Fo" + link.args[2]));
  assert.ok(link.args.includes("rpcrt4.lib"));
  assert.deepEqual(link.args.slice(3), [
    "/Brepro",
    "/INCREMENTAL:NO",
    "/DYNAMICBASE",
    "/NXCOMPAT",
    ...WINDOWS_BUILD_LIBRARIES,
  ]);
  assert.equal(
    f.calls.some(({ file }) => file.endsWith("custody-reader.exe")),
    false,
  );
  assert.equal(built.helperSha256, sha(f.image));
  for (const name of [
    "windows-custody-source",
    "windows-custody-header",
    "windows-custody-account",
    "windows-custody-policy",
    "windows-audit-removal-source",
    "windows-custody-reader",
  ])
    assert.ok(f.components.some((component) => component.name === name));
});

test("native build entry uses the shared fixed link tail", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/build-helper.c", import.meta.url),
    "utf8",
  );
  const link = /const wchar_t \*link\[\]\s*=\s*\{([^}]+)\};/u.exec(source);
  assert.ok(link);
  const recipe = windowsCompilerArguments("source.c", "helper.exe");
  assert.deepEqual(
    link[1]
      .trim()
      .split(/\s*,\s*/u)
      .map((argument) => {
        const literal = /^L"([^"]+)"$/u.exec(argument);
        assert.ok(literal);
        return literal[1];
      }),
    recipe.slice(recipe.indexOf("/link")),
  );
});

test("shared removal bytes must remain unchanged across command and custody compilation", async () => {
  for (const build of [buildWindowsCommandHelper, buildWindowsCustodyReader]) {
    const f = commandBuildFixture(),
      original = f.effects.read;
    let reads = 0;
    f.effects.read = async (file) =>
      file.endsWith("audit-policy-remove.h") && ++reads === 2
        ? Buffer.from("substitution")
        : original(file);
    await assert.rejects(
      build("C:\\owned\\fixture", f.components, undefined, f.effects),
      (error) => error.feasibilityCause.code === "setup-failed",
    );
    assert.ok(
      f.components.some(
        (entry) => entry.name === "windows-audit-removal-source",
      ),
    );
    assert.equal(
      f.components.some((entry) => entry.role === "helper"),
      false,
    );
  }
});

test("linker version query binds the exact selected filename as data without running LINK help", async () => {
  const f = commandBuildFixture("C:\\compiler space's;$()\\cl.exe"),
    controller = new AbortController();
  await f.build(controller.signal);
  const query = f.calls.find((call) => call.file.endsWith("powershell.exe"));
  assert.equal(
    query.file,
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  );
  assert.deepEqual(query.args.slice(0, 4), [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
  ]);
  assert.equal(query.args.length, 5);
  assert.equal(query.options.signal, controller.signal);
  assert.equal(query.options.timeout, 10000);
  assert.equal(query.options.maxBuffer, 4096);
  assert.equal(query.options.env, f.effects.environment);
  const script = Buffer.from(query.args[4], "base64").toString("utf16le"),
    encoded = /FromBase64String\('([A-Za-z0-9+/=]+)'\)/u.exec(script)?.[1];
  assert.equal(
    Buffer.from(encoded, "base64").toString("utf8"),
    windowsPath.join(windowsPath.dirname(f.compiler), "link.exe"),
  );
  assert.match(
    script,
    /\[Diagnostics\.FileVersionInfo\]::GetVersionInfo\(\$file\)/u,
  );
  assert.doesNotMatch(
    script,
    /compiler space|ExecutionPolicy|Invoke-Expression/u,
  );
  assert.ok(!f.calls.some((call) => call.args.includes("/?")));
});

test("linker version discovery rejects incomplete, fatal, invalid and interrupted responses before compilation", async () => {
  const stdout = "native-linker-version=14.51.36260.0\r\n";
  for (const change of [
    { stdout: "Microsoft (R) Incremental Linker Version 14.51.36260.0" },
    { stdout: "native-linker-version=14.51.36260\n" },
    { stdout: "native-linker-version=0.0.0.0\n" },
    { stdout: "native-linker-version=14.51.65536.0\n" },
    { stdout: "native-linker-version=014.51.36260.0\n" },
    { stdout: "native-linker-version=14.51.-1.0\n" },
    { stdout: "native-linker-version=14.51.36260.0" },
    { stdout: stdout + "\n" },
    { stdout: stdout + "LINK : fatal error LNK1104: private file\n" },
    { stderr: "LINK : fatal error LNK1104: private file" },
    { stdout: "x".repeat(4097) },
    { stdout: Buffer.from(stdout) },
    { code: 1100 },
    { exitCode: 2 },
    { signal: "SIGTERM" },
    { killed: true },
    { timedOut: true },
    { truncated: true },
  ]) {
    const f = commandBuildFixture(),
      command = f.effects.command;
    f.effects.command = (file, args, options) =>
      file.endsWith("powershell.exe")
        ? Promise.resolve({ stdout, stderr: "", ...change })
        : command(file, args, options);
    await assert.rejects(f.build(), (error) => {
      assert.equal(error.feasibilityCause.code, "setup-failed");
      assert.match(error.feasibilityCause.detail, /command linker-discovery:/u);
      assert.doesNotMatch(error.feasibilityCause.detail, /private file/u);
      return true;
    });
    assert.equal(
      f.components.find((v) => v.name === "msvc-linker").version,
      "unqueried",
    );
    assert.ok(!f.calls.some((call) => call.args.includes("/c")));
    assert.ok(!f.reads.some((file) => file.endsWith("command-helper.exe")));
    assert.ok(!f.components.some((v) => v.name === "windows-command-helper"));
  }
});

test("linker version discovery refuses changed bytes, missing query environment and cancellation", async () => {
  for (const boundary of [
    "changed-linker",
    "missing-system-root",
    "aborted-before",
    "aborted-after",
  ]) {
    const f = commandBuildFixture(),
      controller = new AbortController(),
      command = f.effects.command,
      read = f.effects.read;
    let linkerReads = 0;
    if (boundary === "changed-linker")
      f.effects.read = async (file) =>
        file.endsWith("link.exe") && ++linkerReads === 2
          ? Buffer.from("substituted linker")
          : read(file);
    if (boundary === "missing-system-root")
      delete f.effects.environment.SystemRoot;
    if (boundary === "aborted-before") controller.abort();
    if (boundary === "aborted-after")
      f.effects.command = async (file, args, options) => {
        const result = await command(file, args, options);
        if (file.endsWith("powershell.exe")) controller.abort();
        return result;
      };
    await assert.rejects(f.build(controller.signal), (error) => {
      assert.match(error.feasibilityCause.detail, /command linker-discovery:/u);
      assert.equal(
        error.feasibilityCause.code,
        boundary === "missing-system-root"
          ? "prerequisite-unavailable"
          : "setup-failed",
      );
      return true;
    });
    assert.equal(
      f.components.find((v) => v.name === "msvc-linker").version,
      "unqueried",
    );
    assert.ok(!f.calls.some((call) => call.args.includes("/c")));
    assert.ok(!f.components.some((v) => v.name === "windows-command-helper"));
    if (["missing-system-root", "aborted-before"].includes(boundary))
      assert.ok(!f.calls.some((call) => call.file.endsWith("powershell.exe")));
  }
});

test("audit build failures retain the original compiler error and fence continuation when pinned inputs change", async () => {
  for (const mode of ["compile", "changed", "inspection"]) {
    const f = commandBuildFixture(),
      command = f.effects.command,
      read = f.effects.read;
    const original = Object.assign(
      new Error("build failed"),
      mode === "inspection" ? {} : { code: 2, signal: null },
    );
    let compiled = false;
    f.effects.command = async (file, args, options) => {
      if (args.includes("/c")) {
        compiled = true;
        if (mode !== "inspection") throw original;
      }
      return command(file, args, options);
    };
    f.effects.read = async (file) =>
      mode === "changed" && compiled && file.endsWith("feasibility-command.h")
        ? Buffer.from("changed header")
        : read(file);
    if (mode === "inspection")
      f.effects.inspect = () => {
        throw original;
      };
    await assert.rejects(f.build(), (error) => {
      assert.equal(error.cause, original);
      assert.equal(error.buildContinuationUnsafe, mode === "changed");
      assert.equal(error.buildOnlyInspectionFailed, mode === "inspection");
      return true;
    });
  }
});

test("build failures retain the real operation, process diagnosis and acquired components without an image", async () => {
  for (const stage of [
    "compiler-discovery",
    "linker-discovery",
    "sdk-discovery",
    "source-read",
    "helper-compile",
    "helper-link",
    "helper-image-inspection",
  ]) {
    const f = commandBuildFixture(),
      original = f.effects.command,
      read = f.effects.read;
    f.effects.command = async (file, args, options) => {
      if (
        (stage === "compiler-discovery" && file === "where.exe") ||
        (stage === "helper-compile" && args.includes("/c")) ||
        (stage === "helper-link" && file.endsWith("link.exe"))
      )
        throw Object.assign(new Error("private build path"), {
          code: stage === "compiler-discovery" ? "ENOENT" : 2,
          signal: null,
          timedOut: false,
          stderr:
            "warning C4013: 'FixtureCall' undefined; assuming extern returning int",
          stdout:
            stage === "helper-link"
              ? "fixture.obj : error LNK2019: unresolved external symbol FixtureSymbol referenced in function FixtureCall"
              : "fixture.c(12): error C2065: 'XmlNodeType_SignificantWhitespace': undeclared identifier",
        });
      return original(file, args, options);
    };
    f.effects.read = async (file) => {
      if (
        (stage === "linker-discovery" && file.endsWith("link.exe")) ||
        (stage === "sdk-discovery" && file.endsWith("Windows.h")) ||
        (stage === "source-read" && file.endsWith("feasibility-command.h"))
      )
        throw Object.assign(new Error("private read path"), {
          code: stage === "linker-discovery" ? "ENOENT" : "EIO",
        });
      return read(file);
    };
    if (stage === "helper-image-inspection")
      f.effects.inspect = () => {
        throw Object.assign(new Error("private image path"), {
          code: "ERR_FEASIBILITY_WINDOWS_PE",
        });
      };
    await assert.rejects(f.build(), (error) => {
      assert.match(error.feasibilityCause.detail, new RegExp(stage));
      assert.equal(
        error.feasibilityCause.code,
        ["compiler-discovery", "linker-discovery"].includes(stage)
          ? "prerequisite-unavailable"
          : "setup-failed",
      );
      if (["helper-compile", "helper-link"].includes(stage)) {
        assert.match(
          error.feasibilityCause.detail,
          /exit=2, signal=none, timeout=false; output=recognized/u,
        );
        assert.match(
          error.feasibilityCause.detail,
          stage === "helper-link"
            ? /LNK2019.*FixtureSymbol/u
            : /C2065.*XmlNodeType_SignificantWhitespace/u,
        );
      }
      assert.doesNotMatch(
        error.feasibilityCause.detail,
        /private|fixture\.c|fixture\.obj/u,
      );
      return true;
    });
    assert.ok(!f.components.some((v) => v.name === "windows-command-helper"));
    if (stage === "source-read")
      assert.ok(f.components.some((v) => v.name === "windows-command-source"));
    if (stage === "helper-compile")
      assert.ok(!f.calls.some((v) => v.file.endsWith("link.exe")));
  }
});

test("failed linker version discovery retains its observed digest without inventing a version", async () => {
  for (const failure of [
    { code: 1100 },
    { code: 2 },
    { code: "ENOENT" },
    { code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" },
    { code: "ABORT_ERR" },
    { code: "ETIMEDOUT", timedOut: true },
    { code: null, signal: "SIGTERM", killed: true },
  ]) {
    const f = commandBuildFixture(),
      command = f.effects.command;
    f.effects.command = async (file, args, options) => {
      if (file.endsWith("powershell.exe"))
        throw Object.assign(new Error("linker query failed"), {
          signal: null,
          stdout: "native-linker-version=14.51.36260.0\r\n",
          stderr: "",
          ...failure,
        });
      return command(file, args, options);
    };
    await assert.rejects(f.build(), (error) => {
      assert.match(error.feasibilityCause.detail, /command linker-discovery:/u);
      assert.equal(
        error.feasibilityCause.code,
        failure.timedOut
          ? "deadline"
          : failure.signal
            ? "crash"
            : failure.code === "ENOENT"
              ? "prerequisite-unavailable"
              : "setup-failed",
      );
      if (Number.isInteger(failure.code))
        assert.match(
          error.feasibilityCause.detail,
          new RegExp(`exit=${failure.code},`),
        );
      if (failure.timedOut)
        assert.match(error.feasibilityCause.detail, /timeout=true/u);
      if (failure.signal)
        assert.match(error.feasibilityCause.detail, /signal=SIGTERM/u);
      return true;
    });
    const linker = f.components.find((v) => v.name === "msvc-linker");
    assert.equal(linker.version, "unqueried");
    assert.equal(linker.sha256, sha("link.exe"));
    assert.ok(!f.calls.some((v) => v.args.includes("/c")));
    assert.ok(!f.components.some((v) => v.name === "windows-command-helper"));
  }
});

test("MSVC diagnostics prefer errors in either bounded stream and reject tainted tails", () => {
  const warning =
      "warning C4013: 'FixtureCall' undefined; assuming extern returning int",
    error =
      "C:\\private\\fixture.c(4): error C2065: 'FixtureIdentifier': undeclared identifier";
  for (const [stdout, stderr] of [
    [error, warning],
    [warning, error],
  ]) {
    const cause = feasibilityFailureCause("command", "helper-compile", {
      code: 2,
      signal: null,
      timedOut: false,
      stdout,
      stderr,
    });
    assert.match(cause.detail, /native=C2065.*FixtureIdentifier/u);
    assert.doesNotMatch(cause.detail, /private|fixture\.c/u);
  }
  const linked = feasibilityFailureCause("command", "helper-link", {
    code: 1120,
    signal: null,
    stdout:
      "fixture.obj : error LNK2019: unresolved external symbol FixtureSymbol referenced in function FixtureCall\nwarning C4133: 'FixtureCall': incompatible types",
    stderr: "fixture.exe : fatal error LNK1120: 1 unresolved externals",
  });
  assert.match(linked.detail, /native=LNK2019.*FixtureSymbol.*also C4133/u);
  assert.doesNotMatch(linked.detail, /fixture\.(?:obj|exe)|referenced in/u);
  assert.match(
    feasibilityFailureCause("command", "helper-compile", {
      code: 2,
      signal: null,
      stderr: warning,
    }).detail,
    /MSVC warning C4013/u,
  );
  const unavailable =
    "'fixture-tool' is not recognized as an internal or external command";
  for (const [stdout, stderr] of [
    [warning, unavailable],
    [unavailable, warning],
    [warning + "\n" + unavailable, ""],
    [unavailable + "\n" + error, ""],
  ]) {
    const cause = feasibilityFailureCause(
      "prepare",
      "windows-toolchain-setup",
      { code: 1, signal: null, stdout, stderr },
    );
    assert.match(
      cause.detail,
      /The command interpreter could not resolve the setup command/u,
    );
    assert.doesNotMatch(cause.detail, /MSVC warning/u);
  }
  assert.match(
    feasibilityFailureCause("prepare", "windows-toolchain-setup", {
      code: 1,
      signal: null,
      stdout: error + "\n" + unavailable,
    }).detail,
    /native=C2065/u,
  );
  for (const text of [
    error + " password=opaque",
    error + " https://example.invalid",
    error + " Bearer opaque",
    " ".repeat(65536) + error,
    "error C9999: arbitrary",
    "error C2065: 'bad/symbol': password=opaque",
  ]) {
    const cause = feasibilityFailureCause("command", "helper-compile", {
      code: 2,
      signal: null,
      stdout: text,
    });
    assert.match(cause.detail, /output=unrecognized/u);
    assert.doesNotMatch(
      cause.detail,
      /C2065|opaque|FixtureIdentifier|private/u,
    );
  }
});

function preparationFixture(change = () => {}) {
  const root = "C:\\owned\\native-command-win32-fixture",
    nodes = new Map(),
    removals = [];
  let counter = 1n;
  const add = (file, directory) =>
    nodes.set(file, { dev: 1n, ino: counter++, directory });
  const stat = async (file) => {
    const node = nodes.get(file);
    if (!node) throw Object.assign(new Error("absent"), { code: "ENOENT" });
    return {
      ...node,
      isDirectory: () => node.directory,
      isFile: () => !node.directory,
      isSymbolicLink: () => node.link === true,
    };
  };
  const effects = {
    temporary: async () => {
      add(root, true);
      return root;
    },
    canonical: async (file) => file,
    stat,
    createDirectory: async (file) => add(file, true),
    list: async (file) =>
      [...nodes.keys()]
        .filter((key) => key !== file && windowsPath.dirname(key) === file)
        .map((key) => windowsPath.basename(key)),
    removeFile: async (file) => {
      removals.push(file);
      nodes.delete(file);
    },
    removeDirectory: async (file) => {
      if ((await effects.list(file)).length)
        throw Object.assign(new Error("not empty"), { code: "ENOTEMPTY" });
      removals.push(file);
      nodes.delete(file);
    },
    command: async () => ({ stdout: "" }),
  };
  change({ effects, nodes, root, add });
  const owner = createWindowsCommandPreparation(effects);
  return { owner, nodes, root, add, removals };
}

test("partial preparation records roots/directories before later failures and settles independently", async () => {
  for (const fault of ["canonical", "directory", "identity", "zero-identity"]) {
    const f = preparationFixture(({ effects }) => {
      if (fault === "canonical")
        effects.canonical = async () => {
          throw new Error("canonical failed");
        };
      const create = effects.createDirectory;
      if (fault === "directory")
        effects.createDirectory = async (file) => {
          if (file.endsWith("schema-home")) throw new Error("directory failed");
          return create(file);
        };
      if (["identity", "zero-identity"].includes(fault)) {
        const stat = effects.stat;
        effects.stat = async (file) => {
          if (file.endsWith("schema-home")) {
            if (fault === "identity") throw new Error("identity unavailable");
            return { ...(await stat(file)), ino: 0n };
          }
          return stat(file);
        };
      }
    });
    await assert.rejects(f.owner.run(() => f.owner.allocate("C:\\owned")));
    assert.equal(f.owner.acquired(), true);
    if (["identity", "zero-identity"].includes(fault)) {
      await assert.rejects(
        f.owner.settle(),
        /identity unavailable|Incomplete Windows/u,
      );
      assert.ok(!f.nodes.has(windowsPath.join(f.root, "build")));
      assert.ok(f.nodes.has(windowsPath.join(f.root, "schema-home")));
    } else {
      assert.equal((await f.owner.settle()).fixturesRemoved, true);
      assert.equal(f.nodes.size, 0);
    }
  }
});

test("preparation cleanup refuses substituted roots and waits for owned compiler closure", async () => {
  const substituted = preparationFixture();
  await substituted.owner.run(() => substituted.owner.allocate("C:\\owned"));
  substituted.nodes.get(substituted.root).ino = 90n;
  await assert.rejects(substituted.owner.settle());
  assert.deepEqual(substituted.removals, []);
  const child = new EventEmitter(),
    failure = new Error("compile failed"),
    f = preparationFixture(({ effects }) => {
      effects.command = () => Object.assign(Promise.reject(failure), { child });
    });
  await f.owner.run(() => f.owner.allocate("C:\\owned"));
  await assert.rejects(
    f.owner.command("compiler", [], {}),
    (error) => error === failure,
  );
  const retirement = f.owner.settle();
  await new Promise(setImmediate); // Drain queued promise work; no elapsed-time assertion.
  assert.deepEqual(f.removals, []);
  child.emit("close", 2, null);
  assert.equal((await retirement).processesRetired, true);
  assert.equal(f.nodes.size, 0);
});

test("a rejected canonical identity still settles the original root without touching a foreign directory", async () => {
  const foreign = "C:\\foreign\\fixture",
    f = preparationFixture(({ effects, root, add }) => {
      add(foreign, true);
      effects.canonical = async (file) => (file === root ? foreign : file);
    });
  await assert.rejects(f.owner.run(() => f.owner.allocate("C:\\owned")));
  assert.equal((await f.owner.settle()).fixturesRemoved, true);
  assert.deepEqual(f.removals, [f.root]);
  assert.deepEqual([...f.nodes.keys()], [foreign]);
});

test("preparation cleanup attempts independent resources but never passes emergency retirement", async () => {
  const failure = new Error("owned removal failed"),
    f = preparationFixture(({ effects }) => {
      const remove = effects.removeFile;
      effects.removeFile = async (file) => {
        if (file.endsWith("blocked")) throw failure;
        return remove(file);
      };
    });
  await f.owner.run(() => f.owner.allocate("C:\\owned"));
  const blocked = windowsPath.join(f.root, "build", "blocked"),
    independent = windowsPath.join(f.root, "home", "ordinary");
  f.add(blocked, false);
  f.add(independent, false);
  await assert.rejects(f.owner.settle(), (error) => error === failure);
  assert.ok(f.nodes.has(blocked));
  assert.ok(!f.nodes.has(independent));
  assert.ok(!f.nodes.has(windowsPath.join(f.root, "schema")));
  const child = new EventEmitter(),
    emergency = preparationFixture(({ effects }) => {
      effects.command = () =>
        Object.assign(
          Promise.reject(
            Object.assign(new Error("aborted"), { code: "ABORT_ERR" }),
          ),
          { child },
        );
    });
  await emergency.owner.run(() => emergency.owner.allocate("C:\\owned"));
  await assert.rejects(emergency.owner.command("compiler", [], {}));
  child.emit("close", null, "SIGTERM");
  await assert.rejects(
    emergency.owner.settle(),
    (error) => error.emergency === true,
  );
  assert.deepEqual(emergency.removals, []);
});

test("failed preparation has zero provider effects and separate cleanup evidence", async () => {
  for (const unsettled of [false, true]) {
    const preparation = preparationFixture(),
      f = fixture(({ effects }) => {
        effects.prepare = async () => {
          await preparation.owner.run(() =>
            preparation.owner.allocate("C:\\owned"),
          );
          if (unsettled) preparation.nodes.get(preparation.root).ino = 99n;
          throw Object.assign(new Error("compiler failed"), {
            feasibilityCause: {
              code: "setup-failed",
              detail: "command helper-compile: MSVC C2065.",
            },
          });
        };
        effects.noCustody = () => !preparation.owner.acquired();
        effects.retire = async () => ({
          ...(await preparation.owner.settle()),
          preparationOnly: true,
        });
      });
    const result = await f.run();
    assert.equal(result.status, "FAIL");
    assert.equal(result.cause.detail, "command helper-compile: MSVC C2065.");
    assert.equal(result.cleanup.status, unsettled ? "UNCERTAIN" : "PASS");
    assert.deepEqual(f.requests, []);
    assert.deepEqual(f.calls, []);
  }
});

test("actual held protection preserves complete descriptors, owners and grants with checked refusal cleanup", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const body = (name) => {
    const match = new RegExp(
      `static (?:BOOL|void|PSID|PSECURITY_DESCRIPTOR) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source);
    assert.ok(match, name);
    return match[1]
      .replace(
        /static const char \*const ownerOperations\[4\]\[3\] = \{([\s\S]*?)\n  \};/u,
        (_, rows) =>
          `const ownerOperations = [${rows.replace(/\{/gu, "[").replace(/\}/gu, "]")}];`,
      )
      .replace(/WCHAR text\[512\]/u, "let text = []")
      .replace(
        /SECURITY_ATTRIBUTES attributes = \{sizeof\(attributes\), command_protection\[1\], FALSE\};/u,
        "const attributes = { nLength: attributeSize, lpSecurityDescriptor: command_protection[1], bInheritHandle: false };",
      )
      .replace(
        /\b(?:ACCESS_ALLOWED_ACE|SYSTEM_MANDATORY_LABEL_ACE) \*/gu,
        "let ",
      )
      .replace(
        /\b(?:PSECURITY_DESCRIPTOR|PSID|PACL|BOOL|SECURITY_DESCRIPTOR_CONTROL|SECURITY_INFORMATION|DWORD|unsigned)\b/gu,
        "let",
      )
      .replace(/\(void \*\*\)/gu, "")
      .replace(/->/gu, ".")
      .replace(/&((?:ace|label)\.SidStart)/gu, "$1")
      .replace(/&attributes\b/gu, "attributes")
      .replace(
        /&command_(audit_intent|closed)\b/gu,
        "(value = command_$1) => command_$1 = value",
      )
      .replace(
        /&command_preflight_owned\.(token|medium|launch|gateRead|capture\[i\])/gu,
        "(value = command_preflight_owned.$1) => command_preflight_owned.$1 = value",
      )
      .replace(/&(\w+(?:\[\d+\])?)/gu, "(value) => $1 = value")
      .replace(/\bNULL\b/gu, "null")
      .replace(/\bTRUE\b/gu, "true")
      .replace(/\bFALSE\b/gu, "false")
      .replace(/L"/gu, '"');
  };
  const dispatch = new Script(`
    function command_protection_close() {${body("command_protection_close")}}
    function command_broker_events_close() {${body("command_broker_events_close")}}
    function command_preflight_close(keepBroker) {${body("command_preflight_close").split("if (!command_preflight_owned.active) return ok;")[0]} return ok;}
    function command_protection_read(h, mask, operation) {${body("command_protection_read")}}
    function command_protection_owner(sd, operation) {${body("command_protection_owner")}}
    function command_protection_verify(sd, owner, allAccess, operation) {${body("command_protection_verify")}}
    function command_protection_descriptor() {${body("command_protection_descriptor")}}
    function command_protect(h, allAccess, operation) {${body("command_protect")}}
    function command_broker_events() {${body("command_broker_events")}}
    if (creation) command_broker_events();
    else command_protect("borrowed", allAccess, operation);
  `);
  assert.match(
    source,
    /command_protection_close\(\);\s*if \(\(!keepBroker \|\| !ok\) && !command_broker_events_close\(\)\) ok = FALSE;/u,
  );
  for (const [handle, grant, operation] of [
    ["GetCurrentProcess\\(\\)", "PROCESS", "process"],
    ["ownedJob", "JOB_OBJECT", "job"],
    ["command_audit_intent", "EVENT", "intent-event"],
    ["command_closed", "EVENT", "closed-event"],
  ])
    assert.match(
      source,
      new RegExp(
        `command_protect\\(${handle},${grant}_ALL_ACCESS,"command-protect-${operation}"\\)`,
        "u",
      ),
    );
  assert.doesNotMatch(
    body("command_protect"),
    /SetSecurityInfo|CloseHandle|release_handle/u,
  );
  assert.ok(
    source.includes(
      'L"O:%lsD:P(A;;GA;;;%ls)S:(ML;;NWNR;;;HI)",userText,userText',
    ),
  );
  const run = (
    allAccess,
    operation,
    fault,
    mapped = false,
    readError = 5,
    eventCase,
  ) => {
    const creation = eventCase !== undefined;
    if (creation) fault = eventCase.fault;
    const [ownerStage, ownerFault] =
      fault === "owner" ? ["readback", "unequal"] : (fault?.split(":") ?? []);
    const owner = "S-1-5-32-544",
      userSid = "S-1-5-21-1-2-3-1001",
      high = "S-1-16-12288";
    const freed = [],
      records = [],
      reads = [],
      calls = [];
    let lastError = fault === "descriptor" ? 8 : 1350,
      errorReads = 0,
      outcome;
    const acl = (AceType, Mask, SidStart) => ({
      AceCount: 1,
      ace: { Header: { AceType, AceFlags: 0 }, Mask, SidStart },
    });
    const output = (write, value) => {
      write(value);
      return true;
    };
    const descriptor = (id, actualOwner, grant = 0x10000000) => ({
      id,
      owner: actualOwner,
      control: 0x1000,
      dacl: acl(0, grant, userSid),
      sacl: acl(17, 3, high),
    });
    const baseline = descriptor("baseline", owner),
      input = descriptor("input", userSid);
    const readback = descriptor(
      "readback",
      owner,
      mapped ? allAccess : 0x10000000,
    );
    if (["absent", "invalid", "unequal"].includes(ownerFault)) {
      const sd = [baseline, input, readback].find(
        (value) => value.id === ownerStage,
      );
      sd.owner =
        ownerFault === "absent"
          ? null
          : ownerFault === "invalid"
            ? "invalid"
            : ownerStage === "input"
              ? owner
              : userSid;
    }
    if (fault === "grant") readback.dacl.ace.Mask = allAccess ^ 1;
    if (fault === "grantee") readback.dacl.ace.SidStart = owner;
    if (fault === "extra-ace") readback.dacl.AceCount = 2;
    if (fault === "control") readback.control = 0;
    if (fault === "label") readback.sacl.ace.Mask = 1;
    if (fault === "integrity") readback.sacl.ace.SidStart = "S-1-16-8192";
    const api = {
      creation,
      allAccess,
      operation,
      userSid,
      userText: userSid,
      command_protection: [null, null, null],
      SE_KERNEL_OBJECT: 6,
      SDDL_REVISION_1: 1,
      OWNER_SECURITY_INFORMATION: 1,
      DACL_SECURITY_INFORMATION: 4,
      PROTECTED_DACL_SECURITY_INFORMATION: 0x80000000,
      LABEL_SECURITY_INFORMATION: 16,
      SE_DACL_PROTECTED: 0x1000,
      GENERIC_ALL: 0x10000000,
      ACCESS_ALLOWED_ACE_TYPE: 0,
      SYSTEM_MANDATORY_LABEL_ACE_TYPE: 17,
      SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: 1,
      SYSTEM_MANDATORY_LABEL_NO_READ_UP: 2,
      WinHighLabelSid: high,
      ERROR_SUCCESS: 0,
      ERROR_NOT_SUPPORTED: 50,
      ERROR_CALL_NOT_IMPLEMENTED: 120,
      ERROR_PRIVILEGE_NOT_HELD: 1314,
      strcmp: (a, b) => (a === b ? 0 : 1),
      IsValidSecurityDescriptor: (sd) => Boolean(sd),
      IsValidAcl: (acl) => Boolean(acl),
      IsValidSid: (sid) => typeof sid === "string" && sid.startsWith("S-1-"),
      EqualSid: (a, b) => a === b,
      IsWellKnownSid: (sid, expected) => sid === expected,
      GetSecurityDescriptorOwner: (sd, out) =>
        sd.id === ownerStage && ownerFault === "query"
          ? false
          : output(out, sd.owner),
      GetSecurityDescriptorControl: (sd, out) => output(out, sd.control),
      GetSecurityDescriptorDacl: (sd, present, out) =>
        output(present, true) && output(out, sd.dacl),
      GetSecurityDescriptorSacl: (sd, present, out) =>
        output(present, true) && output(out, sd.sacl),
      GetAce: (acl, index, out) => {
        assert.equal(index, 0);
        return output(out, acl.ace);
      },
      swprintf_s: () => 1,
      ConvertStringSecurityDescriptorToSecurityDescriptorW: (
        _text,
        _revision,
        out,
      ) => {
        output(out, fault === "descriptor" ? { id: "unproved" } : input);
        return fault !== "descriptor";
      },
      GetSecurityInfo: (
        handle,
        kind,
        mask,
        _owner,
        _group,
        _dacl,
        _sacl,
        out,
      ) => {
        assert.equal(handle, "borrowed");
        assert.equal(kind, 6);
        reads.push(mask);
        assert.equal(mask, reads.length === 1 ? 1 : 21);
        const stage = reads.length === 1 ? "baseline" : "readback";
        if (
          (stage === "readback" && fault === "read") ||
          (stage === ownerStage && ownerFault === "read")
        )
          return readError;
        output(out, reads.length === 1 ? baseline : readback);
        return 0;
      },
      SetKernelObjectSecurity: (handle, mask, sd) => {
        assert.deepEqual(reads, [1]);
        assert.deepEqual(
          [handle, mask >>> 0, sd],
          ["borrowed", 0x80000014, input],
        );
        assert.deepEqual(sd, descriptor("input", userSid));
        calls.push("set");
        return fault !== "set" && fault !== "set-cleanup";
      },
      GetLastError: () => {
        errorReads++;
        return lastError;
      },
      LocalFree: (sd) => {
        freed.push(sd.id);
        lastError = 6;
        return ["cleanup", "set-cleanup"].includes(fault) &&
          sd.id === "baseline"
          ? sd
          : null;
      },
      remember: (...facts) => records.push(facts),
      cleanup_error: (...facts) => records.push(["cleanup", ...facts]),
      failure: (code) => {
        if (creation) api.command_preflight_close(false);
        else api.command_protection_close();
        throw code;
      },
      invariant_value: (value, label, code) => {
        if (!value) {
          api.remember(label, "invariant", code);
          api.failure(126);
        }
      },
      invariant: (value, label) => api.invariant_value(value, label, 0),
      win32_check: (value, label) => {
        if (!value) {
          api.remember(label, "win32", api.GetLastError());
          api.failure(126);
        }
      },
    };
    const acquired = [],
      opened = [],
      closed = [],
      eventReads = [];
    if (creation) {
      const convert = api.ConvertStringSecurityDescriptorToSecurityDescriptorW;
      Object.assign(api, {
        attributeSize: 24,
        EVENT_ALL_ACCESS: allAccess,
        command_preflight_owned: {
          active: false,
          capture: Array(16).fill(null),
        },
        command_event_close: (slot) => {
          slot(null);
          return true;
        },
        command_capture_close: () => true,
        command_revert: () => true,
        command_audit_intent: null,
        command_closed: null,
        ConvertStringSecurityDescriptorToSecurityDescriptorW: (...args) => {
          const ok = convert(...args);
          if (ok) acquired.push("input");
          return ok;
        },
        CreateEventW: (attributes, manual, initial, name) => {
          assert.deepEqual(
            [attributes.nLength, manual, initial, name],
            [24, true, false, null],
          );
          assert.equal(attributes.bInheritHandle, false);
          assert.deepEqual(
            attributes.lpSecurityDescriptor,
            descriptor("input", userSid),
          );
          const handle = api.command_audit_intent ? "closed" : "intent";
          if (fault?.startsWith(`create-${handle}`)) {
            lastError = 5;
            return null;
          }
          opened.push(handle);
          return handle;
        },
        GetSecurityInfo: (
          handle,
          kind,
          mask,
          _owner,
          _group,
          _dacl,
          _sacl,
          out,
        ) => {
          assert.equal(kind, 6);
          const count = eventReads.filter(([value]) => value === handle).length;
          assert.equal(mask, count === 1 ? 1 : 21);
          reads.push(mask);
          eventReads.push([handle, mask]);
          if (fault === `${handle}-read` && count === 0) return 5;
          const sd = descriptor(`${handle}:${count}`, userSid, allAccess);
          if (count === 0) {
            if (fault === `${handle}-absent`) sd.owner = null;
            if (fault === `${handle}-invalid`) sd.owner = "invalid";
            if (fault === `${handle}-mismatch`) sd.owner = owner;
            if (fault === `${handle}-grant`) sd.dacl.ace.Mask ^= 1;
            if (fault === `${handle}-label`) sd.sacl.ace.Mask = 1;
          }
          acquired.push(sd.id);
          output(out, sd);
          return 0;
        },
        SetKernelObjectSecurity: (handle, mask, sd) => {
          assert.deepEqual([mask >>> 0, sd], [0x80000014, input]);
          calls.push(handle);
          lastError = 1350;
          return !fault?.startsWith(`${handle}-set`);
        },
        LocalFree: (sd) => {
          freed.push(sd.id);
          lastError = 6;
          return sd.id === "input" &&
            ["create-closed-cleanup", "event-descriptor-cleanup"].includes(
              fault,
            )
            ? sd
            : null;
        },
        release_handle: (slot, label) => {
          const handle = slot();
          slot(null);
          if (!handle) return true;
          closed.push(handle);
          if (
            ["create-closed-cleanup", "intent-set-cleanup"].includes(fault) &&
            handle === "intent"
          ) {
            api.remember(label, "win32", 6);
            api.cleanup_error(label, "win32", 6);
            return false;
          }
          return true;
        },
      });
    }
    try {
      dispatch.runInNewContext(api);
    } catch (error) {
      outcome = error;
    }
    assert.deepEqual(api.command_protection, [null, null, null]);
    if (creation) {
      if (!fault) {
        assert.equal(outcome, undefined);
        assert.deepEqual(records, []);
        assert.deepEqual(reads, [21, 21, 1, 21, 1, 21]);
        assert.deepEqual(calls, ["intent", "closed"]);
        assert.equal(api.command_audit_intent, "intent");
        assert.equal(api.command_closed, "closed");
        assert.equal(api.command_broker_events_close(), true);
      } else {
        assert.equal(outcome, 126);
        assert.deepEqual(records[0], eventCase.expected);
        if (!fault.includes("-set")) assert.deepEqual(calls, []);
        if (fault === "create-closed-cleanup") {
          for (const label of ["command-protect-free", "command-event-close"])
            assert.ok(
              records.some(
                (record) =>
                  JSON.stringify(record) ===
                  JSON.stringify(["cleanup", label, "win32", 6]),
              ),
            );
        }
        if (fault === "intent-set-cleanup")
          assert.ok(
            records.some(
              (record) =>
                JSON.stringify(record) ===
                JSON.stringify(["cleanup", "command-event-close", "win32", 6]),
            ),
          );
      }
      assert.equal(api.command_audit_intent, null);
      assert.equal(api.command_closed, null);
      assert.deepEqual(closed, opened);
      assert.deepEqual(freed.toSorted(), acquired.toSorted());
      return;
    }
    const preSet =
      fault === "descriptor" || (ownerFault && ownerStage !== "readback");
    assert.deepEqual(calls, preSet ? [] : ["set"]);
    const setterFailed = ["set", "set-cleanup"].includes(fault);
    const readFailed = fault === "read" || ownerFault === "read";
    assert.deepEqual(
      freed,
      ["baseline", "input", "readback"].slice(
        0,
        ownerStage === "baseline" && readFailed
          ? 0
          : fault === "descriptor" || (ownerStage === "baseline" && ownerFault)
            ? 1
            : setterFailed ||
                readFailed ||
                (ownerStage === "input" && ownerFault)
              ? 2
              : 3,
      ),
    );
    if (!fault) {
      assert.equal(outcome, undefined);
      assert.equal(errorReads, 0);
      assert.deepEqual(records, []);
    } else {
      assert.equal(
        outcome,
        readFailed && [50, 120, 1314].includes(readError) ? 78 : 126,
      );
      if (setterFailed)
        assert.deepEqual(records[0], [operation, "win32", 1350]);
      else if (fault === "descriptor")
        assert.deepEqual(records[0], [
          "command-protect-descriptor",
          "win32",
          8,
        ]);
      else if (ownerFault || readFailed) {
        const stage = fault === "read" ? "readback" : ownerStage;
        const queryFailed = ownerFault === "query";
        assert.deepEqual(records[0], [
          `${operation}-${stage}-owner`,
          readFailed || queryFailed ? "win32" : "invariant",
          readFailed
            ? readError
            : queryFailed
              ? 1350
              : ["absent", "invalid", "unequal"].indexOf(ownerFault) + 1,
        ]);
        assert.equal(errorReads, queryFailed ? 1 : 0);
      }
      if (fault.includes("cleanup"))
        assert.deepEqual(records.at(-1), [
          "cleanup",
          "command-protect-free",
          "win32",
          6,
        ]);
    }
    if (setterFailed || preSet) assert.deepEqual(reads, [1]);
    if (records.length) {
      const cleanup = records.find(([kind]) => kind === "cleanup")?.slice(1);
      const line = ([name, domain, value], suffix = "") =>
        `native-windows${suffix}: operation=${name} domain=${domain} value=${value}\n`;
      const diagnosis = windowsFeasibilityDiagnostics(
        line(records[0]) + (cleanup ? line(cleanup, "-cleanup") : ""),
      );
      assert.ok(diagnosis);
      assert.doesNotMatch(JSON.stringify(diagnosis), /S-1-|borrowed/u);
    }
  };
  for (const [grant, operation] of [
    [0x1fffff, "process"],
    [0x1f003f, "job"],
    [0x1f0003, "intent-event"],
    [0x1f0003, "closed-event"],
  ]) {
    run(grant, `command-protect-${operation}`);
    run(grant, `command-protect-${operation}`, undefined, true);
    run(grant, `command-protect-${operation}`, "set");
    for (const stage of ["baseline", "input", "readback"]) {
      for (const fault of ["query", "absent", "invalid", "unequal", "read"]) {
        if (
          (stage === "baseline" && fault === "unequal") ||
          (stage === "input" && fault === "read")
        )
          continue;
        run(grant, `command-protect-${operation}`, `${stage}:${fault}`);
      }
      const label = `command-protect-${operation}-${stage}-owner`;
      for (const [domain, value] of [
        ["invariant", 0],
        ["invariant", 4],
        ["win32", 0],
        ["hresult", 0x80004005],
      ])
        assert.equal(
          windowsFeasibilityDiagnostics(
            `native-windows: operation=${label} domain=${domain} value=${value}\n`,
          ),
          null,
        );
      if (stage === "baseline")
        assert.equal(
          windowsFeasibilityDiagnostics(
            `native-windows: operation=${label} domain=invariant value=3\n`,
          ),
          null,
        );
    }
  }
  for (const error of [50, 120, 1314])
    run(0x1fffff, "command-protect-process", "baseline:read", false, error);
  for (const label of [
    "command-protect-thread-baseline-owner",
    "command-protect-process-constructed-owner",
  ])
    assert.equal(
      windowsFeasibilityDiagnostics(
        `native-windows: operation=${label} domain=invariant value=1\n`,
      ),
      null,
    );
  for (const fault of [
    "descriptor",
    "owner",
    "grant",
    "grantee",
    "extra-ace",
    "control",
    "label",
    "integrity",
    "read",
    "cleanup",
    "set-cleanup",
  ])
    run(0x1fffff, "command-protect-process", fault);
  for (const [fault, expected] of [
    [undefined, undefined],
    ["descriptor", ["command-protect-descriptor", "win32", 8]],
    ["create-intent", ["command-intent-event", "win32", 5]],
    ["create-closed", ["command-closed-event", "win32", 5]],
    ["create-closed-cleanup", ["command-closed-event", "win32", 5]],
    ["event-descriptor-cleanup", ["command-protect-free", "win32", 6]],
    [
      "intent-read",
      ["command-protect-intent-event-readback-owner", "win32", 5],
    ],
    [
      "closed-read",
      ["command-protect-closed-event-readback-owner", "win32", 5],
    ],
    [
      "intent-absent",
      ["command-protect-intent-event-readback-owner", "invariant", 1],
    ],
    [
      "intent-invalid",
      ["command-protect-intent-event-readback-owner", "invariant", 2],
    ],
    [
      "closed-mismatch",
      ["command-protect-closed-event-readback-owner", "invariant", 3],
    ],
    ["intent-grant", ["command-protect-dacl", "invariant", 0]],
    ["closed-label", ["command-protect-sacl", "invariant", 0]],
    ["intent-set", ["command-protect-intent-event", "win32", 1350]],
    ["intent-set-cleanup", ["command-protect-intent-event", "win32", 1350]],
    ["closed-set", ["command-protect-closed-event", "win32", 1350]],
  ])
    run(0x1f0003, "command-protect-intent-event", undefined, false, 5, {
      fault,
      expected,
    });
});

test("command preflight source preserves API-specific causes, independent cleanup and admission ordering", async () => {
  const [command, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((file) =>
      readFile(new URL(`../ci/native/win32/${file}`, import.meta.url), "utf8"),
    ),
  );
  const preflight = command.slice(
    command.indexOf("static void command_preflight("),
    command.indexOf("static void command_snapshot_handle("),
  );
  const cleanup = command.slice(
    command.indexOf("static BOOL command_preflight_close("),
    command.indexOf("static void command_nt("),
  );
  const mediumToken = command.slice(
    command.indexOf("static HANDLE command_medium_token("),
    command.indexOf("static void command_preflight("),
  );
  assert.match(
    mediumToken,
    /DWORD access=TOKEN_DUPLICATE\|TOKEN_QUERY\|TOKEN_ADJUST_DEFAULT;\s*if\(launch\)access\|=TOKEN_ASSIGN_PRIMARY;\s*win32_check\(OpenProcessToken\(GetCurrentProcess\(\),access,&command_preflight_owned\.token\)/u,
  );
  assert.match(
    mediumToken,
    /CreateRestrictedToken\(command_preflight_owned\.token,DISABLE_MAX_PRIVILEGE\|LUA_TOKEN,0,NULL,0,NULL,0,NULL,&command_preflight_owned\.medium\)/u,
  );
  assert.match(
    mediumToken,
    /SetTokenInformation\(command_preflight_owned\.medium,TokenIntegrityLevel,[^;]+;[\s\S]*if\(!set\)failure\(126\);\s*invariant\(command_integrity\(command_preflight_owned\.medium\)==SECURITY_MANDATORY_MEDIUM_RID,"command-medium-level"\);/u,
  );
  // Portable source contracts do not establish native token setup or admission.
  assert.match(
    command,
    /if \(value\) return;\s*DWORD error=GetLastError\(\);remember\(operation, "win32"/u,
  );
  assert.match(
    command,
    /GetSecurityInfo\([^;]+;\s*if\(error!=ERROR_SUCCESS\)\{remember\("command-security-read","win32",error\)/u,
  );
  assert.match(
    command,
    /SetLastError\(ERROR_SUCCESS\);BOOL adjusted=AdjustTokenPrivileges\([^;]+;DWORD error=GetLastError\(\);\s*if\(!adjusted\|\|error!=ERROR_SUCCESS\)\{remember\("command-privilege-adjust","win32",error\);failure\(78\)/u,
  );
  assert.match(
    helper,
    /DWORD error = queried \? ERROR_SUCCESS : GetLastError\(\)/u,
  );
  assert.match(
    helper,
    /SetLastError\(ERROR_SUCCESS\); DWORD size = GetEnvironmentVariableW\([^;]+;\s*if \(!size\) \{ DWORD error = GetLastError\(\); if \(error != ERROR_SUCCESS\)/u,
  );
  assert.match(
    helper,
    /invariant\(size && size < capacity && !wcscmp\(value, expected\), operation\)/u,
  );
  assert.match(
    command,
    /DWORD error=set\?ERROR_SUCCESS:GetLastError\(\);\s*if\(!set\)remember\("command-medium-integrity","win32",error\);LocalFree\(sid\)/u,
  );
  assert.match(
    preflight,
    /nullError=mutableNull==INVALID_HANDLE_VALUE\?GetLastError\(\):ERROR_SUCCESS/u,
  );
  assert.ok(
    preflight.indexOf('remember("command-null-control"') <
      preflight.indexOf("command_revert()"),
  );
  assert.match(
    preflight,
    /if\(!command_preflight_owned.item\)\{DWORD error=GetLastError\(\);if\(error==ERROR_NO_MORE_ITEMS\)break;remember\("command-event-next","win32",error\);failure\(126\)/u,
  );
  for (const [property, name, field] of [
    ["EventID", "id", "id"],
    ["EventVersion", "version", "version"],
  ]) {
    assert.match(
      preflight,
      new RegExp(
        `win32_check\\(EvtGetEventMetadataProperty\\([^;]+EventMetadata${property}[^;]+,"command-event-${name}"\\);invariant\\(${field}\\.Type==EvtVarTypeUInt32,"command-event-${name}-type"\\)`,
        "u",
      ),
    );
  }
  for (const guard of [
    "++total<=4096",
    "used[i]<4",
    "version.UInt32Val<=255",
    "command_category_count&&command_category_count<=128",
  ])
    assert.ok(command.includes(guard), guard);
  assert.ok(
    preflight.indexOf('"command-version-missing"') <
      preflight.indexOf('printf("{'),
  );
  assert.ok(
    preflight.indexOf("command_preflight_close(!emit)") <
      preflight.indexOf('printf("{'),
  );
  const main = command.slice(command.indexOf("static int command_main("));
  assert.ok(
    main.indexOf('"command-preflight-arguments"') <
      main.indexOf("command_preflight(emit)"),
  );
  assert.match(
    main,
    /if\(FAILED\(initialized\)\)\{remember\("command-com-initialize","hresult",\(DWORD\)initialized\);failure\(126\)/u,
  );
  const ready = main.indexOf('printf("{\\"event\\":\\"ready\\"');
  assert.ok(ready > 0);
  assert.match(
    main.slice(0, ready),
    /win32_check\(OpenProcessToken\([^;]+&command_broker_token\),"command-broker-token"\);command_broker_events\(\);/u,
  );
  assert.doesNotMatch(main.slice(0, ready), /\bneed\(/u);
  for (const name of "command_protect command_broker_events command_snapshot_handle command_fixture_label command_files_prepare command_image_read command_limits command_members command_spawn".split(
    " ",
  )) {
    const body = command.slice(command.indexOf(` ${name}(`));
    assert.doesNotMatch(
      body.slice(0, body.indexOf("\nstatic ")),
      /\bneed\(/u,
      name,
    );
  }
  assert.match(
    main,
    /command_gate==INVALID_HANDLE_VALUE\?GetLastError\(\):ERROR_SUCCESS/u,
  );
  assert.ok(
    main.indexOf('remember("command-gate-create"') <
      main.indexOf("LocalFree(gateSd)"),
  );
  assert.match(
    helper,
    /win32_check\(SetFileSecurityW\([^;]+, "file-protect"\)/u,
  );
  for (const slot of ["token", "medium", "launch", "mutableNull", "event"])
    assert.ok(
      cleanup.includes(`release_handle(&command_preflight_owned.${slot},`),
      slot,
    );
  for (const slot of ["item", "subscription", "enumerator", "metadata"])
    assert.ok(cleanup.includes(`&command_preflight_owned.${slot}`), slot);
  assert.match(
    cleanup,
    /if \(!keepBroker \|\| !ok\) \{[\s\S]*release_handle\(&command_null,[\s\S]*AuditFree\(command_system\)/u,
  );
  assert.doesNotMatch(
    cleanup,
    /(?:release_handle|command_event_close|command_hash_close)\([^;\n]*&&/u,
  );
  assert.match(
    cleanup,
    /wcscmp\(role, L"command-broker"\) && !release_handle\(&command_cleanup_timer/u,
  );
  const failure = helper.slice(
    helper.indexOf("static void failure("),
    helper.indexOf("static void invariant_value("),
  );
  assert.ok(
    failure.indexOf("struct diagnosis first = first_failure") <
      failure.indexOf("command_preflight_close(FALSE)"),
  );
  assert.ok(
    failure.indexOf("command_observe_failure()") <
      failure.indexOf("close_job(TRUE)"),
  );
  assert.ok(
    failure.indexOf("command_preflight_close(FALSE)") <
      failure.indexOf("struct diagnosis cleanup = cleanup_failure"),
  );
});

test("actual medium token separates launch rights and retains partial handles through checked cleanup", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const token = source.slice(
    source.indexOf("static HANDLE command_medium_token("),
    source.indexOf("static void command_preflight("),
  );
  const rights = token.slice(
    token.indexOf("DWORD access="),
    token.indexOf("win32_check("),
  );
  const promotion = /if\(launch\) \{([\s\S]*?)\n  \}/u.exec(token);
  assert.ok(promotion);
  assert.ok(
    token.indexOf("command_integrity(") < token.indexOf("DuplicateHandle("),
  );
  assert.match(
    source,
    /command_medium_token\(FALSE\);win32_check\(ImpersonateLoggedOnUser\(medium\)/u,
  );
  assert.match(source, /HANDLE medium=command_medium_token\(TRUE\);/u);
  assert.match(token, /\n  return command_preflight_owned\.medium;\n\}/u);
  const cleanup = source.slice(
    source.indexOf("static BOOL command_preflight_close("),
    source.indexOf("static void command_nt("),
  );
  const inactive = cleanup.indexOf(
    "if (!command_preflight_owned.active) return ok;",
  );
  assert.ok(inactive > 0);
  for (const slot of ["token", "medium", "launch"])
    assert.ok(
      cleanup.indexOf(`release_handle(&command_preflight_owned.${slot},`) <
        inactive,
    );
  const translate = (text) =>
    text
      .replace(/\b(?:DWORD|BOOL|unsigned)\b/gu, "let")
      .replace(/\bFALSE\b/gu, "false")
      .replace(
        /&command_preflight_owned\.(token|medium|launch|gateRead|capture\[i\])/gu,
        "(value = command_preflight_owned.$1) => command_preflight_owned.$1 = value",
      );
  const dispatch = new Script(`(() => {
    function rights(launch) {${translate(rights)} return access;}
    function promote() {${translate(promotion[1])}}
    function settle(keepBroker) {${translate(cleanup.slice(cleanup.indexOf("{") + 1, inactive))} return ok;}
    return { rights, promote, settle };
  })()`);
  for (const fault of [
    null,
    "duplicate",
    "duplicate-cleanup",
    "setup",
    "launch",
    "partial",
  ]) {
    const owned = {
      active: false,
      capture: Array(16).fill(null),
      token: fault === "partial" ? "source" : null,
      medium: "setup",
      launch: fault === "partial" ? "launch" : null,
    };
    const closed = [],
      records = [],
      cleanupRecords = [];
    let lastError = 5,
      outcome;
    const api = {
      command_preflight_owned: owned,
      TOKEN_DUPLICATE: 0x2,
      TOKEN_QUERY: 0x8,
      TOKEN_ADJUST_DEFAULT: 0x80,
      TOKEN_ASSIGN_PRIMARY: 0x1,
      GetCurrentProcess: () => -1,
      command_protection_close: () => true,
      command_broker_events_close: () => true,
      command_capture_close: () => true,
      command_revert: () => true,
      command_event_close: (slot) => {
        slot(null);
        return true;
      },
      DuplicateHandle: (from, setup, to, output, access, inherit, flags) => {
        assert.deepEqual(
          [from, setup, to, access, inherit, flags],
          [-1, "setup", -1, 0xb, false, 0],
        );
        if (fault?.startsWith("duplicate")) return false;
        output("launch");
        return true;
      },
      release_handle: (slot, operation) => {
        const handle = slot();
        slot(null);
        if (!handle) return true;
        closed.push(handle);
        lastError = 6;
        if (
          fault === handle ||
          fault === "partial" ||
          (fault === "duplicate-cleanup" && handle === "setup")
        ) {
          api.remember(operation, "win32", lastError);
          cleanupRecords.push([operation, "win32", lastError]);
          return false;
        }
        return true;
      },
      remember: (...record) => {
        if (!records.length) records.push(record);
      },
      win32_check: (ok, operation) => {
        if (!ok) {
          api.remember(operation, "win32", lastError);
          api.failure(126);
        }
      },
      failure: (code) => {
        api.settle(false);
        throw code;
      },
    };
    Object.assign(api, dispatch.runInNewContext(api));
    assert.equal(api.rights(false), 0x8a);
    assert.equal(api.rights(true), 0x8b);
    try {
      if (fault !== "partial") {
        assert.equal(api.promote(), "launch");
        assert.equal(owned.medium, null);
        assert.equal(owned.launch, "launch");
      }
      assert.equal(api.settle(false), !["launch", "partial"].includes(fault));
    } catch (code) {
      outcome = code;
    }
    assert.equal(
      outcome,
      ["duplicate", "duplicate-cleanup", "setup"].includes(fault)
        ? 126
        : undefined,
    );
    assert.deepEqual(
      [owned.token, owned.medium, owned.launch],
      [null, null, null],
    );
    assert.deepEqual(
      closed,
      fault === "partial"
        ? ["source", "setup", "launch"]
        : fault?.startsWith("duplicate")
          ? ["setup"]
          : ["setup", "launch"],
    );
    if (fault?.startsWith("duplicate")) {
      assert.deepEqual(records[0], ["command-medium-launch", "win32", 5]);
      assert.deepEqual(
        windowsFeasibilityDiagnostics(
          "native-windows: operation=command-medium-launch domain=win32 value=5\n" +
            (fault === "duplicate-cleanup"
              ? "native-windows-cleanup: operation=command-token-close domain=win32 value=6\n"
              : ""),
        ),
        {
          failure: {
            operation: "command-medium-launch",
            domain: "win32",
            value: 5,
          },
          cleanup:
            fault === "duplicate-cleanup"
              ? { operation: "command-token-close", domain: "win32", value: 6 }
              : null,
        },
      );
    }
    assert.equal(
      cleanupRecords.length,
      fault === "partial"
        ? 3
        : ["duplicate-cleanup", "setup", "launch"].includes(fault)
          ? 1
          : 0,
    );
  }
});

test("actual admission launch cleanup preserves creation status and independently checks every owned handle", async () => {
  const command = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const start = command.indexOf("DWORD error=created?");
  const cleanup = command
    .slice(start, command.indexOf("BOOL member;", start))
    .replace(
      /&command_preflight_owned\.launch\b/gu,
      "(value = command_preflight_owned.launch) => command_preflight_owned.launch = value",
    )
    .replace(/\b(?:DWORD|BOOL)\b/gu, "let")
    .replace(/\bTRUE\b/gu, "true")
    .replace(/\bFALSE\b/gu, "false");
  const dispatch = new Script(`function run() {${cleanup}} run();`);
  for (const [created, launchError, failedClose, expectedCode] of [
    [false, 5, "medium", 126],
    [false, 1314, "env", 126],
    [false, 1314, null, 78],
    [true, 999, "env", 126],
    [true, 999, null, undefined],
  ]) {
    const closed = [],
      records = [],
      processes = [],
      threads = [];
    let lastError = launchError,
      outcome;
    try {
      dispatch.runInNewContext({
        created,
        p: { hProcess: 41, hThread: 42 },
        command_processes: processes,
        command_threads: threads,
        command_count: 0,
        ERROR_SUCCESS: 0,
        ERROR_NOT_SUPPORTED: 50,
        ERROR_CALL_NOT_IMPLEMENTED: 120,
        ERROR_PRIVILEGE_NOT_HELD: 1314,
        environment: "env",
        attrs: "attrs",
        medium: "medium",
        command_preflight_owned: { launch: "medium" },
        readIn: "in",
        writeOut: "out",
        writeErr: "err",
        GetLastError: () => lastError,
        FreeEnvironmentStringsW: () => {
          lastError = 6;
          return failedClose !== "env";
        },
        DeleteProcThreadAttributeList: () => {},
        free: () => {},
        close_handle: (handle) => {
          closed.push(handle);
          return handle !== failedClose;
        },
        release_handle: (slot) => {
          const handle = slot();
          slot(null);
          closed.push(handle);
          return handle !== failedClose;
        },
        remember: (...facts) => records.push(facts),
        cleanup_error: (...facts) => records.push(["cleanup", ...facts]),
        failure: (code) => {
          throw code;
        },
      });
    } catch (code) {
      outcome = code;
    }
    assert.equal(outcome, expectedCode);
    assert.deepEqual(closed, ["medium", "in", "out", "err"]);
    assert.deepEqual(processes, created ? [41] : []);
    assert.deepEqual(threads, created ? [42] : []);
    if (!created)
      assert.deepEqual(records[0], [
        "command-process-create",
        "win32",
        launchError,
      ]);
    if (failedClose === "env")
      assert.deepEqual(records.at(-1), [
        "cleanup",
        "command-environment-close",
        "win32",
        6,
      ]);
    if (created && !failedClose) assert.deepEqual(records, []);
  }
});

test("actual command preflight boundary retains precise refusal and separate retirement before provider effects", async () => {
  const source = await readFile(
    new URL(
      "../ci/native/win32/feasibility-command-effects.js",
      import.meta.url,
    ),
    "utf8",
  );
  const start = source.indexOf("let preflight;"),
    admission = "Object.assign(prepared, preflight);",
    end = source.indexOf(admission, start);
  assert.ok(start >= 0 && end > start);
  const boundary = new Script(
    `(async () => {${source.slice(start, end + admission.length)} return prepared;})()`,
  );
  const accepted = {};
  await boundary.runInNewContext({
    prepared: accepted,
    signal: undefined,
    native: async () => ({ admission: true }),
  });
  assert.deepEqual(accepted, { admission: true });
  const diagnostic = (operation, domain, value, cleanup = false) =>
    `native-windows${cleanup ? "-cleanup" : ""}: operation=${operation} domain=${domain} value=${value}\n`;
  const cases = [
    [78, "command-privilege-adjust", "win32", 1300],
    [126, "command-event-id", "win32", 122],
    [126, "command-event-version-type", "invariant", 0],
    [126, "command-com-initialize", "hresult", 0x80010106],
    [126, "command-hash-update", "ntstatus", 0xc000000d],
  ];
  for (const [code, operation, domain, value] of cases) {
    const stderr =
      diagnostic(operation, domain, value) +
      diagnostic("command-token-close", "win32", 6, true);
    const primary = { operation, domain, value };
    assert.deepEqual(windowsFeasibilityDiagnostics(stderr), {
      failure: primary,
      cleanup: { operation: "command-token-close", domain: "win32", value: 6 },
    });
    const prepared = {},
      error = Object.assign(new Error("native refusal"), {
        code,
        signal: null,
        stderr,
        nativeError: 203,
        stdout: '{"admission":true}',
      });
    const refuse = () =>
      boundary.runInNewContext({
        prepared,
        signal: undefined,
        windowsFeasibilityCause,
        nativeException: () => {},
        native: async (args) => {
          assert.deepEqual(Array.from(args), ["command-preflight"]);
          throw error;
        },
      });
    const f = fixture(({ effects }) => {
      effects.prepare = refuse;
      effects.noCustody = () => false;
      effects.retire = async () => ({
        preparationOnly: true,
        independent: true,
        processesRetired: true,
        fixturesRemoved: code === 78,
        emergency: false,
        witnessSha256: PIN,
      });
    });
    const result = await f.run();
    assert.equal(result.status, code === 78 ? "BLOCKED" : "FAIL");
    assert.equal(
      result.cause.code,
      code === 78 ? "prerequisite-unavailable" : "setup-failed",
    );
    assert.ok(
      result.cause.detail.includes(`${operation} failed (${domain}=${value})`),
    );
    assert.doesNotMatch(result.cause.detail, /command-token-close|203/u);
    assert.equal(result.cleanup.status, code === 78 ? "PASS" : "UNCERTAIN");
    assert.deepEqual(prepared, {});
    assert.deepEqual(f.requests, []);
    assert.deepEqual(f.calls, []);
  }
  const primary = diagnostic("command-event-version-type", "invariant", 0);
  for (const stderr of [
    primary.trimEnd(),
    primary.replace("value=0", "value=1"),
    primary.replace("domain=invariant", "domain=win32"),
    primary.replace("command-event-version-type", "command-unrecognized"),
    primary + diagnostic("command-event-id", "win32", 5, true),
    primary + diagnostic("command-metadata-close", "invariant", 0, true),
    primary + diagnostic("command-hash-close", "ntstatus", 0, true),
  ]) {
    assert.equal(windowsFeasibilityDiagnostics(stderr), null);
    assert.doesNotMatch(
      windowsFeasibilityCause("native-prerequisites", { code: 126, stderr })
        .detail,
      /Native command-/u,
    );
  }
  assert.ok(
    windowsFeasibilityDiagnostics(
      primary + diagnostic("command-hash-close", "ntstatus", 0xc000000d, true),
    ),
  );
});

test("both native per-user audit enumerators retain SDK pointer, validation and release contracts", async () => {
  const owners = [
    {
      file: "feasibility-command.h",
      entry: "command_principal_exists(void)",
      next: "static void command_policy_equal(",
      principal: "userSid",
    },
    {
      file: "effective-reader.h",
      entry: "audit_principal_exists(PSID sid)",
      next: "static void audit_policy_read(",
      principal: "sid",
    },
  ];
  const sources = await Promise.all(
    owners.map(({ file }) =>
      readFile(new URL(`../ci/native/win32/${file}`, import.meta.url), "utf8"),
    ),
  );
  for (const [index, owner] of owners.entries()) {
    const source = sources[index];
    assert.match(source, /#include <ntsecapi\.h>/u);
    assert.doesNotMatch(source, /\bPAUDIT_SID_ARRAY\b/u);
    const begin = source.indexOf(`static BOOL ${owner.entry}`);
    const end = source.indexOf(owner.next, begin);
    assert.ok(begin >= 0 && end > begin);
    const enumeration = source.slice(begin, end);
    assert.ok(
      enumeration.includes(
        index === 0
          ? `invariant(${owner.principal} && IsValidSid(${owner.principal}),"command-audit-principal")`
          : `need(${owner.principal} && IsValidSid(${owner.principal}))`,
      ),
    );
    assert.match(enumeration, /PPOLICY_AUDIT_SID_ARRAY array = NULL;/u);
    assert.match(
      enumeration,
      /BOOL valid = AuditEnumeratePerUserPolicy\(&array\)/u,
    );
    assert.match(
      enumeration,
      /valid = array && array->UsersCount <= 4096 &&\s*\(!array->UsersCount \|\| array->UserSidArray\)/u,
    );
    assert.match(enumeration, /valid && i < array->UsersCount/u);
    assert.match(
      enumeration,
      /PSID candidate = array->UserSidArray\[i\];\s*valid = candidate && IsValidSid\(candidate\);/u,
    );
    assert.ok(
      enumeration.includes(`valid && EqualSid(${owner.principal}, candidate)`),
    );
    if (index === 0) {
      assert.ok(
        enumeration.indexOf('remember("command-audit-principals"') <
          enumeration.indexOf("AuditFree(array)"),
      );
      assert.match(
        enumeration,
        /if \(array\) AuditFree\(array\);\s*if\(!valid\)failure\(126\)/u,
      );
    } else
      assert.match(
        enumeration,
        /if \(array\) AuditFree\(array\);\s*need\(valid\);/u,
      );
    assert.doesNotMatch(enumeration, /\b(?:break|free|LocalFree)\b/u);
  }
  assert.match(
    sources[0],
    /#define WINDOWS_SECURITY_XML_ONLY\s*#include "effective-reader\.h"\s*#undef WINDOWS_SECURITY_XML_ONLY/u,
  );
  assert.match(sources[1], /^#ifndef WINDOWS_SECURITY_XML_ONLY\r?\n/u);
  assert.ok(
    sources[1].indexOf("static BOOL audit_principal_exists(") <
      sources[1].search(/\r?\n#endif\r?\n/u),
  );
  // Source contracts neither compile the selected MSVC/SDK variants nor exercise audit APIs.
});

test("actual XML reuse uses SDK C vtables and the XmlLite node enumeration", async () => {
  const source = await readFile(
      new URL("../ci/native/win32/effective-reader.h", import.meta.url),
      "utf8",
    ),
    xml = source.slice(source.indexOf("struct xml_result {"));
  assert.doesNotMatch(
    xml,
    /XmlNodeType_SignificantWhitespace|\b(?:IXmlReader|IStream)_[A-Za-z]+\(/u,
  );
  for (const call of [
    "stream->lpVtbl->SetSize(stream, size)",
    "reader->lpVtbl->SetInput(reader, (IUnknown *)stream)",
    "reader->lpVtbl->Read(reader, &type)",
  ])
    assert.ok(xml.includes(call));
  assert.match(
    xml,
    /CreateXmlReader\(&IID_IXmlReader, \(void \*\*\)&reader, NULL\)/u,
  );
  assert.match(xml, /XmlNodeType_Whitespace/u);
  // Source checks establish neither compilation with SDK 26100 nor native XML decoding.
});

test("provider hashes alone admit the pinned image and every live reader selects its bound", async () => {
  const [helper, command, effects] = await Promise.all(
    [
      "feasibility-helper.c",
      "feasibility-command.h",
      "feasibility-command-effects.js",
    ].map((file) =>
      readFile(new URL(`../ci/native/win32/${file}`, import.meta.url), "utf8"),
    ),
  );
  const small = Number(helper.match(/#define FILE_HASH_LIMIT (\d+)ULL/u)[1]),
    provider = Number(
      helper.match(/#define PROVIDER_IMAGE_HASH_LIMIT (\d+)ULL/u)[1],
    );
  assert.equal(small, 128 * 1024 * 1024);
  assert.equal(provider, 512 * 1024 * 1024);
  const guard = helper.match(
    /invariant\((length\.QuadPart >= 0 && \(ULONGLONG\)length\.QuadPart <= limit), "file-size"\)/u,
  )[1];
  const accepts = new Script(
    `(size, limit) => ${guard.replaceAll("length.QuadPart", "size").replace("(ULONGLONG)", "")}`,
  ).runInNewContext();
  for (const limit of [small, provider])
    for (const [size, expected] of [
      [-1, false],
      [0, true],
      [limit - 1, true],
      [limit, true],
      [limit + 1, false],
    ])
      assert.equal(accepts(size, limit), expected);
  assert.equal(accepts(326872368, small), false);
  assert.equal(accepts(326872368, provider), true);
  assert.match(helper, /hashfile_bounded\(h, out, FILE_HASH_LIMIT\)/u);
  assert.match(
    helper,
    /hashfile_bounded\(h, out, PROVIDER_IMAGE_HASH_LIMIT\)/u,
  );
  assert.match(
    helper,
    /BYTE bytes\[8192\][\s\S]*total == \(ULONGLONG\)length\.QuadPart[\s\S]*BCryptFinishHash\(hash, sum, 32, 0\)/u,
  );
  assert.match(
    helper,
    /nt_check\(BCryptDestroyHash\(hash\), "hash-close"\); nt_check\(BCryptCloseAlgorithmProvider\(algorithm, 0\), "hash-provider-close"\)/u,
  );
  assert.match(command, /hashfile\(command_helper_file,actualHash\)/u);
  assert.match(
    command,
    /hash_provider_image\(command_image_file,actualHash\)/u,
  );
  assert.equal(command.match(/hash_provider_image\(/gu).length, 2);
  assert.match(
    command,
    /if\(provider\)hash_provider_image\(h,hash\);else hashfile\(h,hash\)/u,
  );
  assert.match(
    command,
    /BOOL equal=!strcmp\(hash,expected\);if\(!equal\)remember\("command-image-match","invariant",0\);\s*BOOL closed=close_handle\(h,"file-close"\);if\(!equal\|\|!closed\)failure\(126\);/u,
  );
  assert.deepEqual(
    Array.from(
      command.matchAll(/command_image_read\((.*?)\);/gu),
      (match) => match[1],
    ),
    [
      "command_client,command_helper_hash,FALSE",
      'child,expected,!wcscmp(argv[8],L"provider")',
      "owner,expected,FALSE",
      "owner,expected,FALSE",
      "owner,hash,FALSE",
      "admission.hProcess,command_helper_hash,FALSE",
      "server.hProcess,command_image_hash,TRUE",
    ],
  );
  assert.match(
    command,
    /argc==9&&\(!wcscmp\(argv\[8\],L"helper"\)\|\|!wcscmp\(argv\[8\],L"provider"\)\)/u,
  );
  assert.equal(
    effects.match(/imageSha256: prepared\.helperSha256 \},\s*"helper",/gu)
      .length,
    2,
  );
  assert.match(effects, /verifier\(admitted, "provider", signal\)/u);

  const start = effects.indexOf("const verifier = async"),
    end = effects.indexOf("const watch =", start),
    calls = [],
    providerPin = sha("provider"),
    token = { integrity: 8192 };
  assert.ok(start >= 0 && end > start);
  const verify = new Script(
    `(() => {${effects.slice(start, end)} return verifier;})()`,
  ).runInNewContext({
    need: assert.ok,
    inputs: { packages: { codex: { component: { sha256: providerPin } } } },
    prepared: {
      helperSha256: PIN,
      observer: { ...identity, pid: 321 },
      jobHandle: "7",
    },
    normalizeWindowsIdentity: (value) => value,
    sameWindowsIdentity: (a, b) => JSON.stringify(a) === JSON.stringify(b),
    native: async (args) => {
      calls.push(Array.from(args));
      return { identity, token, creationJob: true };
    },
  });
  for (const [kind, pin] of [
    ["helper", PIN],
    ["provider", providerPin],
  ]) {
    await verify({ identity, token, imageSha256: pin }, kind);
    assert.equal(calls.at(-1)[0], "command-check");
    assert.equal(calls.at(-1).length, 8);
    assert.deepEqual(calls.at(-1).slice(-2), [pin, kind]);
  }
  for (const [kind, pin] of [
    ["other", providerPin],
    ["helper", providerPin],
    ["provider", PIN],
  ])
    await assert.rejects(verify({ identity, token, imageSha256: pin }, kind));
  assert.equal(calls.length, 2);
});

async function brokerCloseBoundary() {
  const source = await readFile(
    new URL(
      "../ci/native/win32/feasibility-command-effects.js",
      import.meta.url,
    ),
    "utf8",
  );
  const start = source.indexOf(
      "const ready = new Promise",
      source.indexOf("async setup("),
    ),
    end = source.indexOf("reading = (async", start),
    failureStart = source.indexOf("const fail = (error) =>"),
    failureEnd = source.indexOf("const call =", failureStart);
  assert.ok(
    start >= 0 && end > start && failureStart >= 0 && failureEnd > failureStart,
  );
  const boundary = new Script(`(() => {
    let closed, failed, brokerDiagnosticFirst, retiring = false, retirementFailure, bytes = 0, reading = Promise.resolve();
    const pending = new Map();
    ${source.slice(failureStart, failureEnd)}
    ${source.slice(start, end)}
    const effects = {${source.slice(source.indexOf("retainFailure: fail,"), source.indexOf("prepare(nonce, components, signal)"))}};
    return { closed, pending, outcome: ready.catch(error => error), failure: () => failed,
      retainFailure: effects.retainFailure, collectFailure: effects.failure };
  })()`);
  return () => {
    const broker = new EventEmitter(),
      raw = [],
      rpc = new PassThrough(),
      errorOutput = new PassThrough();
    broker.stdin = new EventEmitter();
    broker.stdout = new PassThrough();
    broker.stderr = new PassThrough();
    const result = boundary.runInNewContext({
      Buffer,
      broker,
      rpc,
      errorOutput,
      windowsFeasibilityCause,
      windowsFeasibilityDiagnostics,
      nativeException: () => {},
      observeNativeProcess: (owner, child) =>
        child.stderr.on("data", (chunk) => raw.push(chunk)),
    });
    return { ...result, broker, rpc, errorOutput, raw };
  };
}

test("actual broker pre-ready closure retains fragmented refusal and separate cleanup without custody", async () => {
  const open = await brokerCloseBoundary(),
    primary =
      "native-windows: operation=file-size domain=invariant value=0\r\n",
    cleanup =
      "native-windows-cleanup: operation=file-close domain=win32 value=6\r\n";
  for (const [first, tail] of [
    [primary, ""],
    [primary, cleanup],
    [
      "native-windows: operation=command-admission-members domain=invariant value=0\r\n",
      'native-windows-command: state={"pid":43,"thread":44,"birth":"90","status":[0,0,0,0,0,0,24,1,1,1],"held":[1,1],"members":[43],"audit":[0,-1,0,0,0,0,0,0,0]}\r\n' +
        cleanup,
    ],
    [
      "native-windows: operation=command-process-create domain=win32 value=5\r\n",
      "native-windows-cleanup: operation=command-environment-close domain=win32 value=6\r\n",
    ],
  ]) {
    const f = open(),
      bytes = Buffer.from(first + tail),
      diagnosis = first.includes("command-admission-members")
        ? "command-admission-members failed (invariant=0)"
        : first === primary
          ? "file-size failed (invariant=0)"
          : "command-process-create failed (win32=5)",
      cleanupOperation = first.includes("command-process-create")
        ? "command-environment-close"
        : "file-close";
    for (const chunk of [
      bytes.subarray(0, 3),
      bytes.subarray(3, 47),
      bytes.subarray(47),
    ])
      f.broker.stderr.write(chunk);
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end();
    await ended;
    f.broker.emit("close", 126, null);
    const error = await f.outcome;
    assert.equal(error.code, 126);
    assert.equal(error.signal, null);
    assert.equal(error.nativeDiagnosticInvalid, false);
    assert.deepEqual(error.stderr, bytes);
    assert.deepEqual(Buffer.concat(f.raw), bytes);
    assert.equal(f.failure(), error);
    assert.ok(error.feasibilityCause.detail.includes(diagnosis));
    assert.doesNotMatch(
      error.feasibilityCause.detail,
      /file-close|command-environment-close/u,
    );
    assert.equal(Boolean(error.feasibilityCleanup), Boolean(tail));
    const run = fixture(({ effects }) => {
      effects.noCustody = () => false;
      effects.setup = async () => {
        throw error;
      };
      effects.retire = async () => {
        throw error;
      };
    });
    const result = await run.run();
    assert.equal(result.status, "FAIL");
    assert.ok(result.cause.detail.includes(diagnosis));
    assert.equal(result.cleanup.status, "UNCERTAIN");
    assert.equal(result.cleanup.independent, false);
    assert.equal(result.cleanup.witnessSha256, null);
    if (tail)
      assert.ok(
        result.cleanup.cause.detail.includes(
          `${cleanupOperation} failed (win32=6)`,
        ),
      );
    else assert.match(result.cleanup.cause.detail, /remains incomplete/u);
    assert.deepEqual(run.requests, []);
    assert.deepEqual(run.calls, ["prepare"]);
  }
});

test("actual broker rejects contaminated, partial and oversized carriers while streaming every raw byte", async () => {
  const open = await brokerCloseBoundary(),
    primary = "native-windows: operation=file-size domain=invariant value=0\n";
  const carriers = [
    primary.trimEnd(),
    primary + "partial",
    primary + "{}\n",
    primary + '{"event":"ready"}\n',
    primary + primary,
    primary + "native-windows-cleanup: operation=other domain=win32 value=6\n",
    "native-windows: operation=command-process-create domain=invariant value=0\n",
    "native-windows: operation=command-broker-nonce domain=win32 value=5\n",
    primary +
      "native-windows-cleanup: operation=command-environment-close domain=invariant value=0\n",
    primary + " ".repeat(4096 - primary.length),
    primary + " ".repeat(4096),
    Buffer.concat([Buffer.from(primary), Buffer.from([0xc3])]),
  ];
  for (const carrier of carriers) {
    const f = open(),
      bytes = Buffer.from(carrier);
    for (const chunk of [
      bytes.subarray(0, 21),
      bytes.subarray(21, 60),
      bytes.subarray(60),
    ])
      f.broker.stderr.write(chunk);
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end();
    await ended;
    f.broker.emit("close", 126, null);
    const error = await f.outcome;
    assert.equal(error.nativeDiagnosticInvalid, true);
    assert.equal(error.feasibilityCleanup, undefined);
    assert.doesNotMatch(error.feasibilityCause.detail, /file-size failed/u);
    assert.match(error.feasibilityCause.detail, /diagnostic rejected/u);
    assert.deepEqual(Buffer.concat(f.raw), bytes);
    assert.ok(error.stderr.length <= 4096);
    if (bytes.length > 4096) assert.equal(error.stderr.length, 0);
  }
});

test("actual broker preserves its first transport failure, exit signal and incomplete stderr status", async () => {
  const open = await brokerCloseBoundary(),
    diagnostic =
      "native-windows: operation=file-size domain=invariant value=0\n";
  for (const stream of ["stdin", "stderr"]) {
    const f = open(),
      first = Object.assign(new Error("pipe failure"), { code: "EPIPE" });
    f.broker[stream].emit("error", first);
    const settlement = new Promise((resolve) =>
      f.pending.set("D", { reject: resolve }),
    );
    f.broker.stderr.write(diagnostic);
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end();
    await ended;
    f.broker.emit("close", null, "SIGTERM");
    assert.equal(await f.outcome, first);
    assert.equal(await settlement, first);
    assert.equal(f.failure(), first);
    assert.equal(first.code, "EPIPE");
    assert.equal(first.brokerCompletion.code, null);
    assert.equal(first.brokerCompletion.signal, "SIGTERM");
    assert.equal(
      first.brokerCompletion.nativeDiagnosticInvalid,
      stream === "stderr",
    );
    assert.deepEqual(Buffer.concat(f.raw), Buffer.from(diagnostic));
    assert.deepEqual(
      { ...(await f.closed) },
      { code: null, signal: "SIGTERM" },
    );
  }
});

test("a complete-looking broker prefix is unusable when stderr closes before EOF", async () => {
  const open = await brokerCloseBoundary(),
    f = open();
  const prefix =
    "native-windows: operation=file-size domain=invariant value=0\n" +
    "native-windows-cleanup: operation=file-close domain=win32 value=6\n";
  f.broker.stderr.write(prefix);
  const closed = once(f.broker.stderr, "close");
  f.broker.stderr.destroy();
  await closed;
  f.broker.emit("close", 126, null);
  const error = await f.outcome;
  assert.equal(f.broker.stderr.readableEnded, false);
  assert.equal(error.nativeDiagnosticInvalid, true);
  assert.deepEqual(error.stderr, Buffer.from(prefix));
  assert.doesNotMatch(error.feasibilityCause.detail, /file-size failed/u);
  assert.equal(error.feasibilityCleanup, undefined);
  assert.deepEqual(Buffer.concat(f.raw), Buffer.from(prefix));
});

test("post-ready broker refusal survives later watcher and cleanup failures through command projection", async () => {
  const open = await brokerCloseBoundary();
  for (const [independent, acknowledged] of [
    [false, false],
    [true, false],
    [false, true],
  ]) {
    const f = open(),
      watcher = Object.assign(new Error("Later watcher failed"), { code: 126 }),
      primary =
        "native-windows: operation=helper-invariant domain=invariant value=0\n",
      tail = independent
        ? ""
        : "native-windows-cleanup: operation=file-close domain=win32 value=6\n";
    f.pending.get("ready").resolve({ event: "ready" });
    f.pending.delete("ready");
    const run = fixture(({ effects }) => {
      const retire = effects.retire,
        coverage = effects.setup;
      effects.noCustody = () => false;
      effects.retainFailure = f.retainFailure;
      effects.failure = f.collectFailure;
      effects.setup = async () => {
        if (acknowledged) return coverage();
        f.broker.stderr.write(primary.slice(0, 23));
        throw watcher;
      };
      effects.retire = async () => {
        if (acknowledged) {
          f.broker.stderr.write(primary.slice(0, 23));
          f.retainFailure(watcher);
        }
        assert.equal(f.failure(), watcher); // A prefix is not yet native evidence.
        f.broker.stderr.write(primary.slice(23) + tail);
        const ended = once(f.broker.stderr, "end");
        f.broker.stderr.end();
        await ended;
        f.broker.emit("close", 126, null);
        if (independent) return retire();
        throw new Error("Independent retirement unproved");
      };
    });
    const result = await run.run(),
      first = await f.collectFailure();
    assert.notEqual(first, watcher);
    assert.equal(first.cause, watcher);
    assert.equal(first.code, 126);
    assert.deepEqual(first.stderr, Buffer.from(primary + tail));
    assert.equal(watcher.brokerCompletion.code, 126);
    assert.match(
      result.cause.detail,
      /output=recognized; Native helper-invariant failed \(invariant=0\)/u,
    );
    assert.equal(result.status, "FAIL");
    if (!acknowledged) assert.equal(result.evidence, null);
    assert.equal(result.cleanup.status, independent ? "PASS" : "UNCERTAIN");
    assert.equal(result.cleanup.independent, independent);
    if (!independent)
      assert.match(
        result.cleanup.cause.detail,
        /file-close failed \(win32=6\)/u,
      );
    assert.equal(run.requests.length, acknowledged ? 6 : 0);
  }
});

test("post-ready invalid broker carriers and earlier transport rejection cannot become primary native evidence", async () => {
  const open = await brokerCloseBoundary(),
    diagnostic =
      "native-windows: operation=command-gate-read domain=win32 value=5\n";
  for (const carrier of [
    diagnostic.trimEnd(),
    diagnostic + "contamination\n",
    diagnostic + "x".repeat(4096),
    diagnostic.replace("command-gate-read", "unknown-seam"),
    diagnostic.replace("win32", "invariant"),
    diagnostic.replace("value=5", "value=0"),
    diagnostic,
  ]) {
    const f = open(),
      first = Object.assign(new Error("Earlier transport rejection"), {
        code: "EPIPE",
      });
    f.pending.get("ready").resolve({ event: "ready" });
    f.pending.delete("ready");
    if (carrier === diagnostic) f.retainFailure(first);
    f.broker.stderr.write(carrier);
    if (carrier !== diagnostic) f.retainFailure(first);
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end();
    await ended;
    f.broker.emit("close", 126, null);
    assert.equal(await f.collectFailure(), first);
    assert.equal(first.code, "EPIPE");
    assert.equal(first.brokerCompletion.code, 126);
    assert.equal(
      first.brokerCompletion.nativeDiagnosticInvalid,
      carrier !== diagnostic,
    );
    assert.equal(first.feasibilityCause, undefined);
  }
});

test("watcher completion reuses strict diagnostics without treating exit or output as retirement", async () => {
  const open = await brokerCloseBoundary();
  const diagnostic =
    "native-windows: operation=helper-invariant domain=invariant value=0\n";
  for (const mode of [
    "complete",
    "partial",
    "contaminated",
    "oversized",
    "transport",
    "closed",
  ]) {
    const broker = mode === "transport" ? open() : null;
    const child = Object.assign(new EventEmitter(), {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      kill: () => {},
    });
    const opened = openWindowsCommandWatcher(
      "C:\\fixture\\helper.exe",
      [],
      {},
      new AbortController().signal,
      () => child,
      broker?.retainFailure,
    );
    child.stdout.write(JSON.stringify({ ready: true, identity }) + "\n");
    const owner = await opened,
      first = Object.assign(new Error("Earlier watcher transport"), {
        code: "EPIPE",
      });
    if (mode === "transport") child.stdout.emit("error", first);
    if (broker) {
      broker.broker.stderr.write(diagnostic);
      const ended = once(broker.broker.stderr, "end");
      broker.broker.stderr.end();
      await ended;
      broker.broker.emit("close", 126, null);
      assert.equal(await broker.collectFailure(), first);
    }
    const bytes =
      mode === "partial"
        ? diagnostic.trimEnd()
        : mode === "contaminated"
          ? diagnostic + "other\n"
          : mode === "oversized"
            ? diagnostic + "x".repeat(4096)
            : diagnostic;
    child.stderr.write(bytes.slice(0, 17));
    child.stderr.write(bytes.slice(17));
    const finished = owner.finish();
    child.stdout.write(
      JSON.stringify({ retired: true, completeDomain: true }) + "\n",
    );
    child.stdout.end();
    const ended = once(child.stderr, mode === "closed" ? "close" : "end");
    if (mode === "closed") child.stderr.destroy();
    else child.stderr.end();
    await ended;
    child.emit("close", 126, null);
    await assert.rejects(finished, (error) => {
      if (mode === "transport") {
        assert.equal(error, first);
        assert.equal(error.watcherCompletion.code, 126);
      } else {
        assert.equal(error.code, 126);
        assert.equal(error.nativeDiagnosticInvalid, mode !== "complete");
        assert.equal(
          /helper-invariant failed/u.test(error.feasibilityCause.detail),
          mode === "complete",
        );
      }
      return true;
    });
    for (const stream of [child.stdin, child.stdout, child.stderr])
      stream.destroy();
  }
});

test("failure collection uses the original cleanup deadline and retains the first command cause", async () => {
  const first = Object.assign(new Error("First transport failed"), {
    code: "EPIPE",
    feasibilityCause: {
      code: "setup-failed",
      detail: "Original transport rejection.",
    },
  });
  const cleanup = Object.assign(new Error("Cleanup deadline"), {
    feasibilityCleanup: {
      code: "cleanup-unobserved",
      detail: "Native file-close failed (win32=6).",
    },
  });
  const f = fixture(({ effects, signals }) => {
    effects.noCustody = () => false;
    effects.setup = async () => {
      throw first;
    };
    effects.retire = async () => {
      throw cleanup;
    };
    effects.failure = () => {
      signals[1].abort();
      return new Promise(() => {});
    };
  });
  const result = await f.run();
  assert.deepEqual(result.cause, first.feasibilityCause);
  assert.equal(result.cleanup.status, "UNCERTAIN");
  assert.equal(result.cleanup.independent, false);
  assert.equal(result.cleanup.witnessSha256, null);
  assert.deepEqual(result.cleanup.cause, cleanup.feasibilityCleanup);
  assert.deepEqual(f.deadlines, [120000, 30000]);
});

test("original gate audit queries retain installed ACEs and effective subject facts without admitting delivery", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:void|DWORD) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  // Project C storage and output pointers; execute the query and writer bodies.
  const project = (text) =>
    text
      .replace(
        "LONGLONG status[9]={-1,-1,-1,-1,-1,-1,-1,-1,-1}, total=-1;",
        "const status=Array(9).fill(-1);let total=-1;",
      )
      .replace(
        "struct command_gate_observation value={0};",
        "const value={entries:Array.from({length:8},()=>({sid:{text:''}})),sid:{text:''},status:[]};",
      )
      .replace("ACL_SIZE_INFORMATION size={0};", "const size={};")
      .replace("TOKEN_STATISTICS stats={0};", "const stats={};")
      .replace(
        "union {TOKEN_USER user;BYTE bytes[sizeof(TOKEN_USER)+SECURITY_MAX_SID_SIZE];} subject={0};char sid[184]={0};",
        "const subject={user:{User:{}}},sid={text:''};",
      )
      .replace("SYSTEM_AUDIT_ACE *audit=(void *)ace;", "const audit=ace;")
      .replace(
        "((SID *)&audit->SidStart)->SubAuthorityCount",
        "audit.SidStart.SubAuthorityCount",
      )
      .replaceAll("&audit->SidStart", "audit.SidStart")
      .replaceAll(
        "&policy->AuditSubCategoryGuid",
        "policy.AuditSubCategoryGuid",
      )
      .replace("offsetof(SYSTEM_AUDIT_ACE,SidStart)", "8")
      .replace(
        "const struct command_gate_observation *value=&command_gate_observed;",
        "const value=command_gate_observed;",
      )
      .replace("ACE_HEADER *ace=NULL", "let ace=NULL")
      .replace(
        /sizeof\((status|sid|subject|TOKEN_USER|stats|size)\)/gu,
        (_, name) =>
          ({
            status: 72,
            sid: 184,
            subject: 88,
            TOKEN_USER: 16,
            stats: 56,
            size: 16,
          })[name],
      )
      .replace(/\(void \*\*\)/gu, "")
      .replace(
        /(?<!&)&(sd|present|sacl|def|ace|token|used|policy|encoded)\b/gu,
        (_, name) => `v=>${name}=v`,
      )
      .replace(
        /(?<!&)&(subject|stats|size|command_category|diagnosticOutputLock)\b/gu,
        "$1",
      )
      .replaceAll("->", ".")
      .replaceAll(".sid[0]", ".sid.text")
      .replace(/\((?:DWORD|unsigned)\)/gu, "")
      .replace(
        /\b(?:DWORD|BOOL|PSECURITY_DESCRIPTOR|PACL|HANDLE|AUDIT_POLICY_INFORMATION|LPSTR|size_t|unsigned)\s+\*?/gu,
        "let ",
      );
  const program =
    new Script(`function command_gate_sid(sid,text){${project(body("command_gate_sid"))}}
    function query(api,originalError){${project(body("command_gate_audit"))}}
    function command_gate_audit_write(output){${project(body("command_gate_audit_write"))}}
    function fail(){${project(body("command_observe_failure"))}}
    ({query,write:command_gate_audit_write,fail})`);
  for (const fault of [
    null,
    "sacl",
    "sacl-read",
    "acl",
    "ace",
    "unsupported",
    "sid",
    "token",
    "subject",
    "subject-short",
    "stats",
    "stats-short",
    "policy",
    "policy-mismatch",
    "close",
    "truncated",
  ]) {
    let lastError = 5,
      output = "",
      queries = 0;
    const remembered = [],
      closed = [],
      freed = [],
      cleanup = [];
    const api = {
      TRUE: true,
      FALSE: false,
      NULL: null,
      ERROR_SUCCESS: 0,
      ERROR_INVALID_SID: 1337,
      ERROR_INSUFFICIENT_BUFFER: 122,
      SE_FILE_OBJECT: 1,
      SACL_SECURITY_INFORMATION: 8,
      AclSizeInformation: 2,
      SYSTEM_AUDIT_ACE_TYPE: 2,
      TOKEN_QUERY: 8,
      TokenUser: 1,
      TokenStatistics: 10,
      TokenImpersonation: 2,
      command_files: [0, 1, 2, 3],
      command_prerequisite_cleanup_failed: false,
      command_category: "file-system",
      command_gate_observed: { observed: false },
      command_observed: {
        active: true,
        pid: 43,
        thread: 44,
        birth: 90,
        status: Array(10).fill(-1),
        held: [0, 0],
        members: [],
        memberCount: 0,
        audit: [0, -1, 0, 0, 0, 0, 0, 0, 0],
      },
      diagnosticOutputLock: {},
      AcquireSRWLockExclusive: () => {},
      ReleaseSRWLockExclusive: () => {},
      stderr: {},
      GetLastError: () => lastError,
      SetLastError: (v) => {
        lastError = v;
      },
      GetCurrentThread: () => 42,
      GetSecurityInfo(file, kind, mask, owner, group, dacl, sacl, out) {
        assert.deepEqual(
          [file, kind, mask, owner, group, dacl, sacl],
          [3, 1, 8, null, null, null, null],
        );
        queries++;
        lastError = 5;
        if (fault === "sacl") return 5;
        out("descriptor");
        return 0;
      },
      GetSecurityDescriptorSacl(sd, present, sacl, def) {
        assert.equal(sd, "descriptor");
        lastError = 87;
        if (fault === "sacl-read") return false;
        present(true);
        sacl("installed");
        def(false);
        return true;
      },
      GetAclInformation(sacl, size) {
        assert.equal(sacl, "installed");
        lastError = 5;
        if (fault === "acl") return false;
        size.AceCount = fault === "truncated" ? 9 : 1;
        return true;
      },
      GetAce(sacl, index, out) {
        assert.equal(sacl, "installed");
        lastError = 6;
        if (fault === "ace") return false;
        out({
          AceType: fault === "unsupported" ? 7 : 2,
          AceFlags: 192,
          AceSize: 32,
          Mask: 3,
          SidStart: { SubAuthorityCount: 4, text: "S-1-5-21-1" },
        });
        return true;
      },
      GetSidLengthRequired: () => 24,
      IsValidSid: () => true,
      ConvertSidToStringSidA(sid, out) {
        lastError = 87;
        if (fault === "sid") return false;
        out(sid.text);
        return true;
      },
      OpenThreadToken(thread, access, self, out) {
        assert.deepEqual([thread, access, self], [42, 8, true]);
        lastError = 1008;
        if (fault === "token") return false;
        out(7);
        return true;
      },
      GetTokenInformation(token, kind, value, size, used) {
        assert.equal(token, 7);
        if (
          (kind === 1 && fault === "subject") ||
          (kind === 10 && fault === "stats")
        ) {
          lastError = 5;
          return false;
        }
        if (kind === 1) {
          assert.equal(size, 88);
          value.user.User.Sid = { text: "S-1-5-21-1" };
          used(fault === "subject-short" ? 8 : 40);
        } else {
          assert.equal(kind, 10);
          assert.equal(size, 56);
          Object.assign(value, {
            AuthenticationId: { HighPart: 0, LowPart: 1 },
            TokenType: 2,
            ImpersonationLevel: 2,
          });
          used(fault === "stats-short" ? 8 : 56);
        }
        return true;
      },
      AuditComputeEffectivePolicyByToken(token, category, count, out) {
        assert.deepEqual([token, category, count], [7, "file-system", 1]);
        lastError = 5;
        if (fault === "policy") return false;
        out({
          AuditSubCategoryGuid:
            fault === "policy-mismatch" ? "other" : "file-system",
          AuditingInformation: 3,
        });
        return true;
      },
      IsEqualGUID: (a, b) => a === b,
      CloseHandle: (token) => {
        closed.push(token);
        lastError = 6;
        return fault !== "close";
      },
      LocalFree: (value) => {
        freed.push(value);
        lastError = 91;
      },
      AuditFree: (value) => {
        freed.push(value);
        lastError = 92;
      },
      cleanup_error: (...cause) => cleanup.push(cause),
      remember: (...cause) => remembered.push(cause),
      strlen: (value) => value.length,
      memcpy: (target, value) => {
        if (Array.isArray(target)) target.push(...value);
        else target.text = typeof value === "string" ? value : value.text;
      },
      fprintf(stream, format, ...args) {
        let i = 0;
        output += format.replace(/%(?:08)?(?:ll|l)?[usdx]/gu, (match) => {
          const value = args[i++];
          return match.endsWith("x")
            ? value.toString(16).padStart(8, "0")
            : String(value?.text ?? value);
        });
        lastError = 90;
      },
      fputs: (text) => {
        output += text;
      },
      fputc: (char) => {
        output += char;
      },
      fflush: () => {},
    };
    const run = program.runInNewContext(api);
    run.write(api.stderr);
    assert.equal(output, "null");
    output = "";
    run.query("ReadFile", 5);
    assert.equal(lastError, 5);
    assert.equal(output, "");
    run.query("ReadFile", 0);
    assert.equal(queries, 1); // The original query is not replayed at retirement.
    run.write(api.stderr);
    const value = JSON.parse(output);
    assert.equal(value.api, "ReadFile");
    assert.equal(value.error, 5);
    assert.equal(value.caller, "command_gate_read");
    assert.ok(output.length < 2500);
    assert.deepEqual(closed, fault === "token" ? [] : [7]);
    assert.equal(freed.includes("descriptor"), fault !== "sacl");
    assert.deepEqual(
      cleanup,
      fault === "close" ? [["command-token-close", "win32", 6]] : [],
    );
    assert.deepEqual(remembered, cleanup);
    assert.equal(api.command_prerequisite_cleanup_failed, fault === "close");
    assert.equal(
      value.present,
      ["sacl", "sacl-read"].includes(fault) ? null : true,
    );
    assert.equal(
      value.aceCount,
      ["sacl", "sacl-read", "acl"].includes(fault)
        ? -1
        : fault === "truncated"
          ? 9
          : 1,
    );
    assert.equal(value.truncated, fault === "truncated");
    if (!["sacl", "sacl-read", "acl"].includes(fault)) {
      assert.equal(value.aces.length, fault === "truncated" ? 8 : 1);
      assert.equal(
        value.aces[0][1],
        fault === "ace"
          ? 6
          : fault === "sid"
            ? 87
            : fault === "unsupported"
              ? -1
              : 0,
      );
      if (!["ace", "sid", "unsupported"].includes(fault))
        assert.deepEqual(value.aces[0].slice(2), [2, 192, 3, "S-1-5-21-1"]);
    }
    assert.equal(
      value.subject,
      ["token", "subject", "subject-short", "sid"].includes(fault)
        ? null
        : "S-1-5-21-1",
    );
    assert.equal(
      value.logon,
      ["token", "stats", "stats-short"].includes(fault)
        ? null
        : "00000000:00000001",
    );
    assert.equal(
      value.policy,
      ["token", "policy", "policy-mismatch"].includes(fault) ? null : 3,
    );
    assert.equal(value.status[0], fault === "sacl" ? 5 : 0);
    assert.equal(value.status[3], fault === "token" ? 1008 : 0);
    const refusal =
      "native-windows: operation=command-gate-read domain=win32 value=5\n";
    output = "";
    run.fail();
    assert.ok(Buffer.byteLength(refusal + output) < 4096);
    assert.deepEqual(windowsFeasibilityDiagnostics(refusal + output).failure, {
      operation: "command-gate-read",
      domain: "win32",
      value: 5,
    });
    for (const observation of [
      "native-windows-command: gate-audit=" + JSON.stringify(value) + "\n",
      "native-windows-command: gate-audit={bad metadata}\n",
    ])
      assert.deepEqual(
        windowsFeasibilityDiagnostics(observation + refusal).failure,
        { operation: "command-gate-read", domain: "win32", value: 5 },
      );
  }
});

async function commandGateReadProgram() {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const gate = /static void command_gate_read\(void\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("char id[50],bytes[32],expected[33];", "let id,bytes,expected;")
    .replace(/\b(?:BOOL|DWORD|int)\b/gu, "let")
    .replace(
      "fileid(command_preflight_owned.gateRead,id)",
      "fileid(command_preflight_owned.gateRead,value=>id=value)",
    )
    .replace(
      "ReadFile(command_preflight_owned.gateRead,bytes,32,&count,NULL)",
      "ReadFile(command_preflight_owned.gateRead,value=>bytes=value,32,value=>count=value,NULL)",
    )
    .replace("&command_preflight_owned.gateRead", "command_preflight_owned")
    .replace("nonce,-1,expected,33", "nonce,-1,value=>expected=value,33");
  return { source, gate, program: new Script(gate) };
}

test("actual gate-read source captures the first API cause before independent handle closure and reversal", async () => {
  const { source, gate, program } = await commandGateReadProgram();
  assert.doesNotMatch(gate, /\bneed\(/u);
  for (const mode of [
    "ok",
    "identity",
    "read",
    "size",
    "close",
    "revert",
    "read-cleanup",
    "query-close",
    "encoding",
    "nonce",
  ]) {
    const events = [],
      cleanup = [],
      owned = { gateRead: null, impersonating: false };
    let first,
      lastError = 5;
    const remember = (...cause) => {
      first ??= cause;
    };
    const api = {
      TRUE: true,
      FALSE: false,
      NULL: null,
      ERROR_SUCCESS: 0,
      INVALID_HANDLE_VALUE: -1,
      CP_UTF8: 65001,
      WC_ERR_INVALID_CHARS: 128,
      GENERIC_READ: 1,
      FILE_READ_ATTRIBUTES: 2,
      FILE_SHARE_READ: 1,
      FILE_SHARE_WRITE: 2,
      FILE_SHARE_DELETE: 4,
      OPEN_EXISTING: 3,
      FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
      command_observed: { audit: Array(9).fill(0) },
      command_preflight_owned: owned,
      command_broker_token: 7,
      command_files: [0, 0, 0, 8],
      command_prerequisite_cleanup_failed: false,
      command_paths: [null, null, null, "C:\\fixture\\gate"],
      command_ids: [0, 0, 0, "original"],
      nonce: "n".repeat(32),
      GetLastError: () => lastError,
      ImpersonateLoggedOnUser: () => true,
      command_gate_audit: (operation, error) => {
        assert.equal(owned.impersonating, true);
        if (mode.startsWith("read"))
          assert.deepEqual(first, ["command-gate-read", "win32", error]);
        events.push("gate-query");
        if (mode === "query-close") {
          api.command_prerequisite_cleanup_failed = true;
          remember("command-token-close", "win32", 6);
        }
        lastError = 91;
      },
      CreateFileW: (...args) => {
        assert.deepEqual(args, [
          "C:\\fixture\\gate",
          3,
          7,
          null,
          3,
          0x200000,
          null,
        ]);
        assert.equal(owned.impersonating, true);
        return 9;
      },
      fileid: (_handle, output) =>
        output(mode === "identity" ? "substitution" : "original"),
      strcmp: (a, b) => (a === b ? 0 : 1),
      memcmp: (a, b) => (a === b ? 0 : 1),
      ReadFile: (_handle, output, _size, count) => {
        events.push("read");
        output("n".repeat(32));
        count(mode === "size" ? 31 : 32);
        return !mode.startsWith("read");
      },
      release_handle: (slot) => {
        events.push("close");
        slot.gateRead = null;
        lastError = 6;
        if (["close", "read-cleanup"].includes(mode)) {
          remember("file-close", "win32", 6);
          cleanup.push("close");
          return false;
        }
        return true;
      },
      command_revert: () => {
        events.push("revert");
        owned.impersonating = false;
        lastError = 8;
        if (["revert", "read-cleanup"].includes(mode)) {
          remember("command-revert", "win32", 8);
          cleanup.push("revert");
          return false;
        }
        return true;
      },
      WideCharToMultiByte: (_cp, _flags, _nonce, _length, output) => {
        output(mode === "nonce" ? "other" : "n".repeat(32));
        return mode === "encoding" ? 0 : 33;
      },
      remember,
      failure: (code) => {
        throw code;
      },
      win32_check: (ok, operation) => {
        if (!ok) {
          remember(operation, "win32", lastError);
          throw 126;
        }
      },
      invariant: (ok, operation) => {
        if (!ok) {
          remember(operation, "invariant", 0);
          throw 126;
        }
      },
    };
    try {
      program.runInNewContext(api);
      assert.equal(mode, "ok");
    } catch (code) {
      assert.equal(code, 126);
    }
    assert.equal(owned.gateRead, null);
    assert.equal(owned.impersonating, false);
    assert.deepEqual(events.slice(-2), ["close", "revert"]);
    if (mode.startsWith("read"))
      assert.deepEqual(first, ["command-gate-read", "win32", 5]);
    if (mode === "read-cleanup") assert.deepEqual(cleanup, ["close", "revert"]);
    if (first)
      assert.ok(
        windowsFeasibilityDiagnostics(
          `native-windows: operation=${first[0]} domain=${first[1]} value=${first[2]}\n`,
        ),
      );
  }
  const preflight = source.slice(
    source.indexOf("static BOOL command_preflight_close("),
    source.indexOf("static void command_nt("),
  );
  assert.ok(
    preflight.indexOf("&command_preflight_owned.gateRead") <
      preflight.indexOf("if (!command_preflight_owned.active)"),
  );
});

async function commandLifetimeSource() {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:void|DWORD|BOOL) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const translate = (text) =>
    text
      .replace(
        /BYTE bytes\[[^;]+; JOBOBJECT_BASIC_PROCESS_ID_LIST \*list=\(void \*\)bytes; DWORD used=0;/u,
        "const bytes={}, list={}; const used={value:0};",
      )
      .replaceAll("sizeof(bytes)", "272")
      .replaceAll(
        "command_observed.status[6]=queried?(LONGLONG)used:-1",
        "command_observed.status[6]=queried?used.value:-1",
      )
      .replace(
        "FILETIME born,exited,kernel,user;",
        "const born={},exited={},kernel={},user={};",
      )
      .replace("DWORD exitCode=0", "const exitCode={value:0}")
      .replace("DWORD code,waited=", "const code={value:0};let waited=")
      .replace("code!=STILL_ACTIVE", "code.value!=STILL_ACTIVE")
      .replace("BOOL member;", "const member={value:false};")
      .replace("invariant(member,", "invariant(member.value,")
      .replace(
        "command_observed.status[4]=exitCode",
        "command_observed.status[4]=exitCode.value",
      )
      .replace("invariant(exitCode==0", "invariant(exitCode.value==0")
      .replace(
        "((ULONGLONG)born.dwHighDateTime<<32)|born.dwLowDateTime",
        "born.dwHighDateTime*2**32+born.dwLowDateTime",
      )
      .replace(
        /&(born|exited|kernel|user|exitCode|code|used|member|diagnosticOutputLock)\b/gu,
        "$1",
      )
      .replace(/&command_(input|output|error)\b/gu, '"$1"')
      .replace(
        /(?<!&)&command_(processes|threads)\[([^\]]+)\]/gu,
        "(value=command_$1[$2])=>command_$1[$2]=value",
      )
      .replaceAll("(DWORD)", "")
      .replace(/\b(?:DWORD|BOOL|HANDLE|unsigned)\b/gu, "let")
      .replaceAll("->", ".");
  return { source, body, translate };
}

test("actual admission releases the checked child before a complete Job census without accepting survivors", async () => {
  const { source, body, translate } = await commandLifetimeSource();
  const admission = source.slice(
    source.indexOf("  command_observed.pid=admission.dwProcessId;"),
    source.indexOf("  command_files_prepare();"),
  );
  const projected = new Script(
    `function command_members(job){${translate(body("command_members"))}} function command_child_close(index){${translate(body("command_child_close"))}} function emit(){${translate(body("command_observe_failure"))}} ${translate(admission)}`,
  );
  for (const fault of [
    null,
    "survivor",
    "unexpected",
    "partial",
    "more-data",
    "query",
    "close",
    "terminate",
    "wait",
    "birth",
    "status",
    "exit",
    "thread-close",
    "process-close",
  ]) {
    let error = 17,
      diagnosis,
      output = "",
      queries = 0;
    const released = [];
    const observed = {
      active: true,
      census: false,
      pid: 0,
      thread: 0,
      birth: 0,
      status: Array(10).fill(-1),
      held: [0, 0],
      members: [],
      memberCount: 0,
      audit: [0, -1, 0, 0, 0, 0, 0, 0, 0],
    };
    const api = {
      command_observed: observed,
      command_gate_observed: { observed: false },
      command_gate_audit_write: () => {},
      admission: { hProcess: 41, hThread: 42, dwProcessId: 43, dwThreadId: 44 },
      command_processes: [41],
      command_threads: [42],
      command_count: 1,
      command_server: null,
      ownedJob: 7,
      TRUE: true,
      FALSE: false,
      NULL: null,
      ERROR_SUCCESS: 0,
      ERROR_MORE_DATA: 234,
      WAIT_OBJECT_0: 0,
      WAIT_FAILED: 0xffffffff,
      MAXDWORD: 0xffffffff,
      JobObjectBasicProcessIdList: 3,
      PROCESS_QUERY_LIMITED_INFORMATION: 0x1000,
      SYNCHRONIZE: 0x100000,
      diagnosticOutputLock: {},
      stderr: {},
      GetLastError: () => error,
      SetLastError: (value) => {
        error = value;
      },
      GetProcessTimes: (_, born) => {
        born.dwHighDateTime = 0;
        born.dwLowDateTime = 90;
        error = 5;
        return fault !== "birth";
      },
      TerminateProcess: () => {
        error = 5;
        return fault !== "terminate";
      },
      WaitForSingleObject: () => (fault === "wait" ? 258 : 0),
      GetExitCodeProcess: (_, code) => {
        code.value = fault === "exit" ? 259 : 0;
        error = 5;
        return fault !== "status";
      },
      release_handle: (slot, operation) => {
        if (typeof slot !== "function") return true;
        const handle = slot();
        slot(null);
        if (!handle) return true;
        released.push(handle);
        if (fault === operation) {
          diagnosis ??= operation;
          return false;
        }
        return true;
      },
      QueryInformationJobObject: (job, kind, list, size, used) => {
        assert.deepEqual([job, kind, size], [7, 3, 272]);
        queries++;
        assert.deepEqual(api.command_processes, [null]);
        assert.deepEqual(api.command_threads, [null]);
        assert.equal(api.command_count, 1);
        const members = ["survivor", "close", "more-data"].includes(fault)
          ? [43]
          : fault === "unexpected"
            ? [43, 99]
            : [];
        Object.assign(list, {
          NumberOfAssignedProcesses:
            members.length + (["partial", "more-data"].includes(fault) ? 1 : 0),
          NumberOfProcessIdsInList: members.length,
          ProcessIdList: members,
        });
        used.value = 16 + members.length * 8;
        error = fault === "more-data" ? 234 : 5;
        return !["query", "more-data"].includes(fault);
      },
      OpenProcess: () => 61,
      IsProcessInJob: (_, job, member) => {
        assert.equal(job, 7);
        member.value = true;
        return true;
      },
      close_handle: () => fault !== "close",
      win32_check: (ok, operation) => {
        if (!ok) {
          diagnosis = operation;
          api.emit();
          throw operation;
        }
      },
      invariant: (ok, operation) => {
        if (!ok) {
          diagnosis = operation;
          api.emit();
          throw operation;
        }
      },
      failure: () => {
        diagnosis ??= "process-close";
        api.emit();
        throw diagnosis;
      },
      AcquireSRWLockExclusive: () => {},
      ReleaseSRWLockExclusive: () => {},
      fflush: () => {},
      fprintf: (_, format, ...values) => {
        let i = 0;
        output += format.replace(/%(?:lld|llu|lu|s)/gu, () =>
          String(values[i++]),
        );
      },
      fputs: (text) => {
        output += text;
      },
    };
    try {
      projected.runInNewContext(api);
      assert.equal(fault, null);
    } catch (cause) {
      assert.equal(cause, diagnosis);
      assert.notEqual(fault, null, String(cause));
    }
    assert.deepEqual(observed.held, [1, 1]);
    assert.equal(observed.pid, 43);
    assert.equal(observed.thread, 44);
    assert.equal(observed.birth, fault === "birth" ? 0 : 90);
    const beforeRelease = [
      "birth",
      "terminate",
      "wait",
      "status",
      "exit",
    ].includes(fault);
    assert.deepEqual(released, beforeRelease ? [] : [42, 41]);
    assert.equal(
      queries,
      beforeRelease || ["thread-close", "process-close"].includes(fault)
        ? 0
        : 1,
    );
    if (fault) {
      const expected = {
        survivor: "command-admission-members",
        unexpected: "command-admission-members",
        partial: "command-members-count",
        "more-data": "command-members-query",
        query: "command-members-query",
        close: "process-close",
        terminate: "command-admission-terminate",
        wait: "command-admission-wait",
        birth: "command-admission-birth",
        status: "command-admission-status",
        exit: "command-admission-status",
        "thread-close": "thread-close",
        "process-close": "process-close",
      }[fault];
      assert.equal(diagnosis, expected);
      const nativeError = [
        "query",
        "more-data",
        "birth",
        "status",
        "terminate",
        "close",
        "thread-close",
        "process-close",
      ].includes(fault);
      const carrier = `native-windows: operation=${expected} domain=${nativeError ? "win32" : "invariant"} value=${fault === "more-data" ? 234 : nativeError ? 5 : 0}\n`;
      assert.ok(windowsFeasibilityDiagnostics(carrier + output), String(fault));
      assert.equal(
        windowsFeasibilityDiagnostics(carrier + output + output),
        null,
      );
      assert.equal(
        windowsFeasibilityDiagnostics(
          carrier + output.replace('"held":[1,1]', '"held":[17,1]'),
        ),
        null,
      );
      assert.equal(
        windowsFeasibilityDiagnostics(output),
        null,
        "observations never establish a cause",
      );
      if (["survivor", "unexpected"].includes(fault)) {
        assert.equal(observed.status[2], 0);
        assert.equal(observed.status[9], 1);
        assert.equal(observed.status[7], fault === "survivor" ? 1 : 2);
      }
      if (fault === "more-data")
        assert.deepEqual(observed.status.slice(5), [234, -1, 2, 1, 1]);
      if (fault === "query")
        assert.deepEqual(observed.status.slice(5), [5, -1, -1, -1, -1]);
    }
  }
});

test("actual retirement releases only exited children before the complete whole-Job census and never closes a slot twice", async () => {
  const { source, body, translate } = await commandLifetimeSource();
  const retirement = body("command_retire_domain");
  const final = source.slice(source.indexOf('else if(!strcmp(line,"S"))'));
  const closeChildren =
    /for\(unsigned i=0;i<command_count;i\+\+\)if\(!command_child_close\(i\)\)closed=FALSE;/u.exec(
      final,
    )[0];
  const program = new Script(`
    function command_child_close(index){${translate(body("command_child_close"))}}
    function command_release_exited(){${translate(body("command_release_exited"))}}
    function command_members(job){${translate(body("command_members"))}}
    function retire(){${translate(retirement.slice(retirement.indexOf("for(;;)"), retirement.indexOf("/* This broker")))}}
    function finish(){let closed=true;${translate(closeChildren)}return closed;}
  `);
  for (const fault of [
    null,
    "live",
    "missing-member",
    "unexpected",
    "partial",
    "query",
    "wait",
    "status",
    "active-status",
    "thread-close",
    "process-close",
    "orphan",
  ]) {
    const processes = [41, 51],
      threads = [42, 52],
      released = [],
      events = [];
    let ticks = 0,
      queries = 0,
      active = ["live", "missing-member"].includes(fault),
      first;
    if (fault === "orphan") processes[0] = null;
    const api = {
      command_processes: processes,
      command_threads: threads,
      command_count: 2,
      command_server: 51,
      command_control: false,
      command_observed: { census: false },
      ownedJob: 7,
      NULL: null,
      TRUE: true,
      FALSE: false,
      WAIT_FAILED: 0xffffffff,
      WAIT_OBJECT_0: 0,
      WAIT_TIMEOUT: 258,
      STILL_ACTIVE: 259,
      ERROR_SUCCESS: 0,
      ERROR_MORE_DATA: 234,
      MAXDWORD: 0xffffffff,
      JobObjectBasicProcessIdList: 3,
      PROCESS_QUERY_LIMITED_INFORMATION: 0x1000,
      SYNCHRONIZE: 0x100000,
      command_bound: () => {
        if (++ticks > 2) api.invariant(false, "command-deadline");
      },
      WaitForSingleObject: (handle, timeout) => {
        assert.equal(timeout, 0);
        events.push(`wait:${handle}`);
        return fault === "wait"
          ? 0xffffffff
          : active && handle === 41
            ? 258
            : 0;
      },
      GetExitCodeProcess: (handle, code) => {
        events.push(`exit:${handle}`);
        code.value = fault === "active-status" ? 259 : 0;
        return fault !== "status";
      },
      release_handle: (slot, operation) => {
        const handle = slot();
        slot(null);
        if (!handle) return true;
        events.push(`close:${handle}`);
        released.push(handle);
        if (fault === operation) {
          first ??= operation;
          return false;
        }
        return true;
      },
      QueryInformationJobObject: (job, kind, list, size, used) => {
        assert.deepEqual([job, kind, size], [7, 3, 272]);
        queries++;
        events.push("census");
        // A member unknown to the local slots, including a nested descendant,
        // must remain in the original whole-Job census.
        const members =
          active && fault !== "missing-member"
            ? [41]
            : fault === "unexpected"
              ? [99]
              : [];
        assert.deepEqual(processes, active ? [41, null] : [null, null]);
        assert.deepEqual(threads, active ? [42, null] : [null, null]);
        Object.assign(list, {
          NumberOfAssignedProcesses:
            members.length + (fault === "partial" ? 1 : 0),
          NumberOfProcessIdsInList: members.length,
          ProcessIdList: members,
        });
        used.value = 16 + members.length * 8;
        return fault !== "query";
      },
      OpenProcess: (rights, inherit, pid) => {
        assert.ok([41, 99].includes(pid));
        return 61;
      },
      IsProcessInJob: (_, job, member) => {
        assert.equal(job, 7);
        member.value = true;
        return true;
      },
      close_handle: () => true,
      GetLastError: () => 5,
      SetLastError: () => {},
      command_capture: () => {},
      command_pump: () => {},
      Sleep: (milliseconds) => {
        assert.equal(milliseconds, 1);
        active = false;
      },
      invariant: (ok, operation) => {
        if (!ok) {
          first ??= operation;
          throw operation;
        }
      },
      win32_check: (ok, operation) => api.invariant(ok, operation),
      failure: () => {
        throw first;
      },
    };
    program.runInNewContext(api);
    if ([null, "live"].includes(fault)) {
      api.retire();
      assert.equal(queries, fault === "live" ? 2 : 1);
      assert.equal(api.command_server, null);
      assert.deepEqual(
        released,
        fault === "live" ? [52, 51, 42, 41] : [42, 41, 52, 51],
      );
      assert.ok(events.indexOf("exit:51") < events.indexOf("close:52"));
      ticks = 0;
      api.retire();
      assert.equal(api.finish(), true);
      assert.equal(released.length, 4);
    } else {
      const expected = {
        unexpected: "command-deadline",
        "missing-member": "command-retirement-state",
        partial: "command-members-count",
        query: "command-members-query",
        wait: "command-retirement-wait",
        status: "command-retirement-status",
        "active-status": "command-retirement-status",
        "thread-close": "thread-close",
        "process-close": "process-close",
        orphan: "command-retirement-slot",
      }[fault];
      assert.throws(
        () => api.retire(),
        (error) => error === expected,
        fault,
      );
      assert.equal(first, expected);
      if (
        [
          "thread-close",
          "process-close",
          "unexpected",
          "partial",
          "query",
        ].includes(fault)
      )
        assert.deepEqual(released, [42, 41, 52, 51]);
      else
        assert.deepEqual(released, fault === "missing-member" ? [52, 51] : []);
      assert.equal(
        queries,
        fault === "unexpected"
          ? 2
          : ["partial", "query", "missing-member"].includes(fault)
            ? 1
            : 0,
      );
      assert.ok(
        windowsFeasibilityDiagnostics(
          `native-windows: operation=${expected} domain=${["wait", "status", "query", "thread-close", "process-close"].includes(fault) ? "win32" : "invariant"} value=${["wait", "status", "query", "thread-close", "process-close"].includes(fault) ? 5 : 0}\n`,
        ),
      );
    }
  }
  const resume = new Script(
    /else if\(!strcmp\(line,"R"\)\)\{([^\n]+)\}/u.exec(source)[1],
  );
  for (const closing of [false, true]) {
    let resumed = 0;
    const api = {
      command_closing: closing,
      server: { hProcess: 51, hThread: 52 },
      command_server_released: false,
      command_control_verified: true,
      TRUE: true,
      need: assert.ok,
      ResumeThread: (thread) => {
        assert.equal(thread, 52);
        resumed++;
        return 1;
      },
      puts: () => {},
    };
    if (closing) assert.throws(() => resume.runInNewContext(api));
    else resume.runInNewContext(api);
    assert.equal(resumed, closing ? 0 : 1);
    assert.equal(api.command_server_released, !closing);
  }
});

async function commandCaptureProgram() {
  const [source, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((file) =>
      readFile(new URL(`../ci/native/win32/${file}`, import.meta.url), "utf8"),
    ),
  );
  const body = (text, name) => {
    const match = new RegExp(
      `static (?:void|BOOL) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(text);
    assert.ok(match, name);
    return match[1];
  };
  const capture = body(source, "command_capture").replace(
    "command_audit_project(bytes,length)",
    "project(bytes,length)",
  );
  // Control only XML projection; execute the owned wait, batch, rendering,
  // bookmark and closure flow from source, without a native tool or compiler.
  const translate = (text) =>
    text
      .replace(/EVT_HANDLE \*events/gu, "let events")
      .replace(/BYTE \*bytes/gu, "let bytes")
      .replace(/\b(?:EVT_HANDLE|HANDLE|BOOL|DWORD|unsigned)\b/gu, "let")
      .replace(/\*slot\b/gu, "slot.value")
      .replace(
        /&(?:command_preflight_owned\.)?capture\[i\]/gu,
        "ref(command_preflight_owned.capture,i)",
      )
      .replace(/&events\[i\]/gu, "ref(events,i)")
      .replace(
        /&command_preflight_owned\.(\w+)/gu,
        'ref(command_preflight_owned,"$1")',
      )
      .replace(
        /&(command_subscription|command_bookmark|command_event)\b/gu,
        'ref(globals,"$1")',
      )
      .replace(/,&(count|length|counted)\b/gu, ",value=>$1=value");
  const preflight = body(source, "command_preflight_close").split(
    "if (!command_preflight_owned.active) return ok;",
  )[0];
  const dispatch = new Script(`
    function close_handle(handle,operation) {${translate(body(helper, "close_handle"))}}
    function release_handle(slot,operation) {${translate(body(helper, "release_handle"))}}
    function command_event_close(slot) {${translate(body(source, "command_event_close"))}}
    function command_capture_close() {${translate(body(source, "command_capture_close"))}}
    function command_preflight_close(keepBroker) {${translate(preflight)} return ok;}
    function command_capture(timeout) {${translate(capture)}}
  `);
  const creations = source.match(
    /command_(?:preflight_owned\.event|event)=CreateEventW\([^;]+\);/gu,
  );
  assert.equal(creations.length, 2);
  const selectionBody =
      /\n  (BOOL selected=[\s\S]*?)\n  if\(selected\)\{/u.exec(source)[1],
    caseBody = source
      .split("\n")
      .find((line) => line.trim().startsWith("if(command_case_pid&&process"));
  return {
    dispatch,
    createEvents: new Script(creations.join("\n")),
    source,
    selection: new Script(
      `(() => {${selectionBody.replace(/\bL(?=")/gu, "").replace(/\b(?:BOOL|unsigned)\b/gu, "let")} return selected;})()`,
    ),
    caseProjection: new Script(
      caseBody
        .replace(/\bL(?=")/gu, "")
        .replace("WCHAR *end;", "let end;")
        .replace(/ULONGLONG (pid|rights)/gu, "let $1")
        .replaceAll("&end", "value=>end=value")
        .replaceAll("!*end", "!end"),
    ),
  };
}

function commandCaptureFixture(program, { fault, closeFailures = [] } = {}) {
  const calls = [],
    closed = [],
    projected = [],
    cleanup = [],
    queue = [];
  let signaled = false,
    lastError = 0,
    emptyCount = 0;
  const ref = (object, key) => ({
    get value() {
      return object[key];
    },
    set value(value) {
      object[key] = value;
    },
  });
  const api = {
    TRUE: true,
    FALSE: false,
    NULL: null,
    ERROR_SUCCESS: 0,
    ERROR_NO_MORE_ITEMS: 259,
    ERROR_INSUFFICIENT_BUFFER: 122,
    WAIT_OBJECT_0: 0,
    WAIT_TIMEOUT: 258,
    WAIT_FAILED: 0xffffffff,
    INVALID_HANDLE_VALUE: -1,
    EvtRenderEventXml: 1,
    command_preflight_owned: { active: false, capture: Array(16).fill(null) },
    command_observed: { audit: Array(9).fill(0) },
    command_subscription: "subscription",
    command_bookmark: "bookmark",
    command_event: "notification",
    command_records: 0,
    command_bytes: 0,
    command_scanned: 0,
    command_scanned_bytes: 0,
    command_prerequisite_cleanup_failed: false,
    ref,
    GetLastError: () => lastError,
    SetLastError: (value) => {
      lastError = value;
    },
    remember: (...cause) => {
      api.first ??= cause;
    },
    cleanup_error: (...cause) => cleanup.push(cause),
    failure: (code) => {
      api.command_preflight_close(false);
      throw code;
    },
    invariant: (ok, operation) => {
      if (!ok) {
        api.remember(operation, "invariant", 0);
        api.failure(126);
      }
    },
    win32_check: (ok, operation) => {
      if (!ok) {
        api.remember(operation, "win32", lastError);
        api.failure(126);
      }
    },
    command_protection_close: () => true,
    command_broker_events_close: () => true,
    command_revert: () => true,
    WaitForSingleObject: (event, timeout) => {
      assert.equal(event, "notification");
      calls.push(["wait", timeout]);
      if (fault === "wait") {
        lastError = 5;
        return api.WAIT_FAILED;
      }
      if (fault === "wait-result") return 0x80;
      return signaled ? api.WAIT_OBJECT_0 : api.WAIT_TIMEOUT;
    },
    EvtNext: (subscription, size, events, timeout, flags, count) => {
      assert.deepEqual(
        [subscription, size, timeout, flags],
        ["subscription", 16, 0, 0],
      );
      calls.push(["next"]);
      const batch = queue.shift();
      count(batch?.length ?? 0);
      batch?.forEach((event, index) => {
        events[index] = event;
      });
      if (
        fault === "next" ||
        (fault === "rearm-next" && calls.some(([name]) => name === "reset"))
      ) {
        lastError = 4317;
        return false;
      }
      if (!batch) {
        lastError = api.ERROR_NO_MORE_ITEMS;
        api.onEmpty?.(++emptyCount);
        return false;
      }
      return true;
    },
    ResetEvent: (event) => {
      assert.equal(event, "notification");
      calls.push(["reset"]);
      if (fault === "reset") {
        lastError = 5;
        return false;
      }
      signaled = false;
      api.onReset?.();
      return true;
    },
    EvtRender: (_context, event, flags, size, bytes, length, count) => {
      assert.equal(flags, api.EvtRenderEventXml);
      const stage = size ? "render" : "query";
      calls.push([stage, event]);
      length(8);
      count(1);
      if (fault === stage) {
        lastError = 5;
        return false;
      }
      if (!size) {
        lastError = api.ERROR_INSUFFICIENT_BUFFER;
        return false;
      }
      bytes.event = event;
      return true;
    },
    calloc: () => ({}),
    free: () => {
      lastError = 8;
    },
    project: (bytes) => {
      calls.push(["project", bytes.event]);
      const selected = api.onProject?.(bytes.event) ?? true;
      if (selected) projected.push(bytes.event);
      return selected;
    },
    EvtUpdateBookmark: (bookmark, event) => {
      assert.equal(bookmark, "bookmark");
      calls.push(["bookmark", event]);
      if (fault === "bookmark") {
        lastError = 5;
        return false;
      }
      return true;
    },
    EvtClose: (handle) => {
      calls.push(["event-close", handle]);
      closed.push(handle);
      lastError = 6;
      return !closeFailures.includes(handle);
    },
    CloseHandle: (handle) => {
      calls.push(["handle-close", handle]);
      closed.push(handle);
      lastError = 6;
      return !closeFailures.includes(handle);
    },
  };
  api.globals = api;
  program.dispatch.runInNewContext(api);
  return {
    api,
    calls,
    closed,
    projected,
    cleanup,
    notify: (...batches) => {
      queue.push(...batches);
      signaled = true;
    },
    capture: (timeout = 0) => api.command_capture(timeout),
  };
}

test("actual capture waits, drains ordered batches, rearms once and accepts later notifications", async () => {
  const program = await commandCaptureProgram(),
    f = commandCaptureFixture(program);
  const creations = [],
    owned = {},
    creationContext = {
      TRUE: true,
      FALSE: false,
      NULL: null,
      command_preflight_owned: owned,
      CreateEventW: (...args) => {
        creations.push(args);
        return `notification-${creations.length}`;
      },
    };
  program.createEvents.runInNewContext(creationContext);
  assert.deepEqual(creations, [
    [null, true, false, null],
    [null, true, false, null],
  ]);
  assert.equal(owned.event, "notification-1");
  assert.equal(creationContext.command_event, "notification-2");
  for (const timeout of [0, 1, 10]) f.capture(timeout);
  assert.deepEqual(f.calls, [
    ["wait", 0],
    ["wait", 1],
    ["wait", 10],
  ]);
  f.notify(["a", "b"], ["c"]);
  f.capture();
  assert.deepEqual(f.projected, ["a", "b", "c"]);
  for (const event of f.projected)
    assert.deepEqual(
      f.calls.filter((call) => call[1] === event).map(([name]) => name),
      ["query", "render", "project", "bookmark", "event-close"],
    );
  assert.deepEqual(
    f.calls.filter(([name]) => ["next", "reset"].includes(name)),
    [["next"], ["next"], ["next"], ["reset"], ["next"]],
  );
  const nextCount = f.calls.filter(([name]) => name === "next").length;
  f.capture();
  f.capture(1);
  assert.equal(f.calls.filter(([name]) => name === "next").length, nextCount);
  f.notify(["later"]);
  f.capture(10);
  assert.deepEqual(f.projected, ["a", "b", "c", "later"]);
  assert.equal(f.api.command_records, 4);
  assert.deepEqual(f.api.command_observed.audit.slice(2, 7), [2, 7, 4, 2, 4]);
  assert.equal(f.api.command_bytes, 32);
  assert.equal(f.api.command_capture_close(), true);
  assert.deepEqual(f.closed, [
    "a",
    "b",
    "c",
    "later",
    "subscription",
    "bookmark",
    "notification",
  ]);
});

test("actual capture preserves arrivals during draining and across exhaustion/reset rearming", async () => {
  const program = await commandCaptureProgram();
  for (const boundary of ["drain", "exhaustion", "reset", "after-recheck"]) {
    const f = commandCaptureFixture(program);
    f.notify(["first"]);
    if (boundary === "drain")
      f.api.onProject = (event) => {
        if (event === "first") f.notify(["raced"]);
      };
    if (boundary === "exhaustion" || boundary === "after-recheck")
      f.api.onEmpty = (count) => {
        if (count === (boundary === "exhaustion" ? 1 : 2)) f.notify(["raced"]);
      };
    if (boundary === "reset")
      f.api.onReset = () => {
        f.api.onReset = null;
        f.notify(["raced"]);
      };
    f.capture();
    if (boundary === "after-recheck") assert.deepEqual(f.projected, ["first"]);
    f.capture();
    assert.deepEqual(f.projected, ["first", "raced"], boundary);
    const nextCount = f.calls.filter(([name]) => name === "next").length;
    f.capture();
    assert.equal(
      f.calls.filter(([name]) => name === "next").length,
      nextCount,
      boundary,
    );
  }
});

test("actual capture failures retain immediate causes and independently retire every acquired handle", async () => {
  const program = await commandCaptureProgram();
  for (const [fault, operation, domain, value] of [
    ["wait", "command-capture-wait", "win32", 5],
    ["wait-result", "command-capture-wait", "invariant", 0],
    ["next", "command-capture-next", "win32", 4317],
    ["rearm-next", "command-capture-next", "win32", 4317],
    ["query", "command-capture-query", "win32", 5],
    ["render", "command-capture-render", "win32", 5],
    ["bookmark", "command-capture-bookmark", "win32", 5],
    ["reset", "command-capture-reset", "win32", 5],
    ["close", "command-metadata-close", "win32", 6],
  ]) {
    const f = commandCaptureFixture(program, {
      fault,
      closeFailures: [
        "subscription",
        "bookmark",
        "notification",
        ...(fault === "close" || fault === "bookmark" ? ["a"] : []),
      ],
    });
    f.notify(["a", "b", "c"]);
    assert.throws(
      () => f.capture(),
      (code) => code === 126,
      fault,
    );
    assert.deepEqual(f.api.first, [operation, domain, value], fault);
    assert.deepEqual(
      f.closed,
      [
        ...(fault.startsWith("wait") ? [] : ["a", "b", "c"]),
        "subscription",
        "bookmark",
        "notification",
      ],
      fault,
    );
    assert.ok(
      f.api.command_preflight_owned.capture.every((handle) => handle === null),
    );
    for (const name of [
      "command_subscription",
      "command_bookmark",
      "command_event",
    ])
      assert.equal(f.api[name], null, name);
    assert.ok(f.cleanup.length >= 3, fault);
    assert.ok(
      windowsFeasibilityDiagnostics(
        `native-windows: operation=${operation} domain=${domain} value=${value}\n`,
      ),
    );
  }
});

test("actual capture retirement checks all closures and partial resources even with inactive preflight", async () => {
  const program = await commandCaptureProgram(),
    handles = ["a", "b", "subscription", "bookmark", "notification"];
  for (const failed of [null, ...handles]) {
    const f = commandCaptureFixture(program, {
      closeFailures: failed ? [failed] : [],
    });
    f.api.command_preflight_owned.capture.splice(0, 2, "a", "b");
    assert.equal(f.api.command_preflight_close(false), !failed);
    assert.deepEqual(f.closed, handles);
    assert.equal(f.api.command_preflight_close(false), true);
    assert.deepEqual(f.closed, handles);
    if (failed) {
      assert.deepEqual(f.api.first, [
        failed === "notification"
          ? "command-event-close"
          : "command-metadata-close",
        "win32",
        6,
      ]);
      assert.equal(f.cleanup.length, 1);
    }
  }
  const creationOrder = ["notification", "bookmark", "subscription"];
  for (let acquired = 0; acquired <= creationOrder.length; acquired++) {
    const f = commandCaptureFixture(program),
      held = creationOrder.slice(0, acquired);
    for (const name of ["event", "bookmark", "subscription"])
      if (!held.includes(f.api[`command_${name}`]))
        f.api[`command_${name}`] = null;
    assert.equal(f.api.command_preflight_close(false), true);
    assert.deepEqual(f.closed, [...held].reverse());
  }
});

test("setup admission and retirement preserve immediate errors and independent closure", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const retirement = source.slice(
      source.indexOf("static void command_retire_domain(void) {"),
      source.indexOf("static void command_check("),
    ),
    prefix = retirement
      .slice(
        retirement.indexOf("BOOL notified="),
        retirement.indexOf("for(;;)"),
      )
      .replace(/\b(?:BOOL|DWORD)\b/gu, "let")
      .replace(/&([a-z_]+)/gu, '"$1"');
  for (const failed of [false, true]) {
    const released = [];
    let first;
    const api = {
      TRUE: true,
      FALSE: false,
      ERROR_SUCCESS: 0,
      command_closed: 1,
      command_server: 2,
      command_server_released: false,
      command_control: true,
      SetEvent: () => !failed,
      GetLastError: () => 5,
      remember: (...cause) => {
        first ??= cause;
      },
      release_handle: (slot) => {
        released.push(slot);
        return false;
      },
      TerminateProcess: () => {
        released.push("terminate");
        return false;
      },
      failure: (code) => {
        throw code;
      },
    };
    assert.throws(
      () => new Script(prefix).runInNewContext(api),
      (code) => code === 126,
    );
    assert.deepEqual(released, [
      "command_gate",
      "command_client",
      "terminate",
      "command_input",
      "command_saved_input",
    ]);
    if (failed)
      assert.deepEqual(first, ["command-retirement-event", "win32", 5]);
  }
  assert.match(
    retirement,
    /if\(command_setup_verified\)\{command_gate_read\(\)[\s\S]*!command_retirement_seen[\s\S]*command-retirement-delivery/u,
  );
  assert.match(
    source,
    /invariant\(!ferror\(stdout\),"command-ready-output"\)/u,
  );
  const final = source.slice(
    source.indexOf('else if(!strcmp(line,"S"))'),
    source.indexOf(
      "}else need(0);",
      source.indexOf('else if(!strcmp(line,"S"))'),
    ),
  );
  assert.doesNotMatch(final, /\bneed\(/u);
  assert.ok(final.includes("command_capture_close()"));
  assert.ok(
    final.indexOf("close_job(FALSE)") <
      final.indexOf("if(!closed)failure(126)"),
  );
});

async function commandSetupOwnerProgram() {
  const source = await readFile(
      new URL(
        "../ci/native/win32/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    guards = source.slice(
      source.indexOf("function commandAuditSnapshot("),
      source.indexOf("/** Setup establishes"),
    ),
    start = source.indexOf(
      "const inspect = () =>",
      source.indexOf("async setup("),
    ),
    end =
      source.indexOf("return observation;", start) +
      "return observation;".length;
  assert.ok(start > 0 && end > start);
  return new Script(`(async () => {
    ${guards}
    let operation;
    try { ${source.slice(start, end)} }
    catch (error) { throw commandSetupFailure(operation, error); }
  })()`);
}

test("actual setup rejects stale baselines before installation and joins all held SACLs before probes", async () => {
  const program = await commandSetupOwnerProgram();
  for (const fault of [
    null,
    "baseline",
    "sacl",
    "failure-policy",
    "reader-error",
  ]) {
    const value = {
        nonce: "a".repeat(32),
        observer: identity,
        gateFile: "C:\\fixture\\gate",
        helperSha256: PIN,
        jobHandle: "7",
      },
      capture = await brokerSetup(value),
      reads = [capture.baseline, capture.before, capture.after],
      calls = [],
      originalCause = {
        code: "setup-failed",
        detail: "Native command-policy-query failed (win32=5).",
      },
      originalError = Object.assign(new Error("native reader refused"), {
        feasibilityCause: originalCause,
      });
    value.original.cleanup.files.forEach((file, i) => {
      file.handle = String(i + 10);
    });
    if (fault === "baseline")
      capture.baseline.audit.files[2].saclSha256 = sha("foreign");
    if (fault === "sacl")
      capture.before.audit.files[0].saclSha256 = sha("foreign");
    if (fault === "failure-policy") capture.before.effective.failure = false;

    let setupVerified = false;
    const context = {
      value,
      original: value.original.cleanup,
      admitted: {
        files: value.original.files,
        tokenHandle: "8",
        gateHandle: "13",
      },
      signal: new AbortController().signal,
      Buffer,
      need: assert.ok,
      digest: sha,
      sameWindowsIdentity: (a, b) => JSON.stringify(a) === JSON.stringify(b),
      windowsFeasibilityCause,
      windowsCommandBrokerSetup,
      native: async (args) => {
        calls.push("read");
        assert.deepEqual(Array.from(args), [
          "command-broker-check",
          "123",
          "101",
          PIN,
          "8",
          "13",
          "7",
          "10",
          "11",
          "12",
        ]);
        if (fault === "reader-error") throw originalError;
        return reads.shift();
      },
      call: async (key) => {
        calls.push(key);
        assert.equal(key, "I");
        return {};
      },
      decoder: { state: () => ({ ready: true }) },
      failed: null,
      set setupVerified(value) {
        setupVerified = value;
      },
      get setupVerified() {
        return setupVerified;
      },
    };
    if (!fault) {
      await program.runInNewContext(context);
      assert.deepEqual(calls, ["read", "I", "read", "read"]);
      assert.equal(setupVerified, true);
    } else {
      await assert.rejects(program.runInNewContext(context), (error) => {
        if (fault === "reader-error") {
          assert.equal(error, originalError);
          assert.equal(error.feasibilityCause, originalCause);
        } else
          assert.ok(
            error.feasibilityCause.detail.includes(
              fault === "baseline" ? "baseline-read" : "installed-audit-read",
            ),
          );
        return true;
      });
      assert.equal(setupVerified, false);
      assert.equal(calls.includes("M"), false);
      if (["baseline", "reader-error"].includes(fault))
        assert.equal(calls.includes("I"), false);
      if (["sacl", "failure-policy"].includes(fault))
        assert.equal(calls.includes("P"), false);
    }
  }
});

test("setup operation labels preserve native failure classes and bounded report causes", async () => {
  const source = await readFile(
      new URL(
        "../ci/native/win32/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    start = source.indexOf("function commandSetupFailure("),
    end = source.indexOf("\n}", start) + 2;
  assert.ok(start >= 0 && end > start);
  const annotate = new Script(`(${source.slice(start, end)})`).runInNewContext({
    windowsFeasibilityCause,
  });
  for (const properties of [
    { code: 124, signal: null },
    { code: null, signal: "SIGTERM" },
    { code: 78, signal: null },
    { code: 78, signal: null, nativeDiagnosticInvalid: true },
    { code: "ERR_FEASIBILITY_DEADLINE" },
    {
      code: 126,
      signal: null,
      operation: "git-status",
      stderr:
        "native-windows: operation=command-policy-query domain=win32 value=5\n",
    },
  ]) {
    const error = Object.assign(
        new Error("private diagnostics are not a cause"),
        properties,
      ),
      expected = windowsFeasibilityCause(
        "broker-cleanup-reader-admission",
        error,
      );
    assert.equal(annotate("cleanup-reader-admission", error), error);
    assert.deepEqual(error.feasibilityCause, expected);
    assert.ok(error.feasibilityCause.detail.length <= 256);
    assert.equal(
      unavailableFeasibilityResults("win32", error.feasibilityCause)[0].cause
        .code,
      expected.code,
    );
    const first = error.feasibilityCause;
    assert.equal(annotate("setup-join", error).feasibilityCause, first);
  }
});

async function commandAuditInstallProgram() {
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
      "utf8",
    ),
    body = source.slice(
      source.indexOf("static void command_audit_install(void) {"),
      source.indexOf("static void command_token_read("),
    ),
    script = new Script(
      "var command_install_from={}, command_install_to={}, command_install_error;" +
        body
          .replace(
            "static void command_audit_install(void)",
            "function install()",
          )
          .replace(/AUDIT_POLICY_INFORMATION policy=\{0\}/u, "let policy={}")
          .replace(/\b(?:DWORD|BOOL|unsigned)\b/gu, "let")
          .replace(/&command_install_(from|to)/gu, "command_install_$1")
          .replace("&policy", "policy") +
        "install();",
    );
  return script;
}

test("native audit installation records intent first and preserves exact setter and wait errors", async () => {
  const script = await commandAuditInstallProgram();
  for (const fault of [null, "wait", "intent", "policy", 0, 1, 2, 3]) {
    const calls = [];
    let first,
      clock = 0,
      lastError = 5;
    const remember = (...cause) => {
        first ??= cause;
      },
      api = {
        command_policy_equal: () => calls.push("baseline"),
        command_principal_exists: () => false,
        command_audit_intent: 1,
        command_category: 2,
        userSid: 3,
        command_files: [0, 1, 2, 3],
        command_sacls: [4, 5, 6, 7],
        WAIT_FAILED: -1,
        WAIT_TIMEOUT: 258,
        FALSE: false,
        ERROR_SUCCESS: 0,
        NULL: null,
        PER_USER_AUDIT_SUCCESS_INCLUDE: 1,
        PER_USER_AUDIT_FAILURE_INCLUDE: 4,
        SE_FILE_OBJECT: 1,
        SACL_SECURITY_INFORMATION: 8,
        WaitForSingleObject: () => (fault === "wait" ? -1 : 258),
        GetLastError: () => lastError,
        SetLastError: (value) => {
          lastError = value;
        },
        GetSystemTimePreciseAsFileTime: (value) => {
          value.time = ++clock;
          lastError = 99;
        },
        SetEvent: () => {
          calls.push("intent");
          return fault !== "intent";
        },
        AuditSetPerUserPolicy: () => {
          calls.push("policy");
          lastError = 5;
          return fault !== "policy";
        },
        SetSecurityInfo: (file) => {
          calls.push(file);
          return fault === file ? 1314 : 0;
        },
        invariant: (ok, operation) => {
          if (!ok) {
            remember(operation, "invariant", 0);
            throw 126;
          }
        },
        win32_check: (ok, operation) => {
          if (!ok) {
            remember(operation, "win32", lastError);
            throw 126;
          }
        },
        status_check: (status, operation) => {
          if (status) {
            remember(operation, "win32", status);
            throw 126;
          }
        },
      };
    if (fault === null) {
      script.runInNewContext(api);
      assert.deepEqual(calls, ["baseline", "intent", "policy", 0, 1, 2, 3]);
      assert.equal(api.command_install_from.time, 1);
      assert.equal(api.command_install_to.time, 2);
      assert.equal(api.command_install_error, 0);
    } else {
      assert.throws(
        () => script.runInNewContext(api),
        (code) => code === 126,
      );
      const operation =
        typeof fault === "number"
          ? "command-sacl-install"
          : `command-${fault === "policy" ? "policy-install" : fault === "wait" ? "intent-wait" : "intent-set"}`;
      assert.deepEqual(first, [
        operation,
        "win32",
        typeof fault === "number" ? 1314 : 5,
      ]);
      assert.ok(
        windowsFeasibilityDiagnostics(
          `native-windows: operation=${first[0]} domain=win32 value=${first[2]}\n`,
        ),
      );
      if (["wait", "intent"].includes(fault))
        assert.equal(calls.includes("policy"), false);
      if (typeof fault === "number") assert.equal(calls.at(-1), fault);
    }
  }
});

test("effective audit reads retain both outcomes and the immediate native query status", async () => {
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
      "utf8",
    ),
    body = source.slice(
      source.indexOf("static void command_effective(HANDLE token) {"),
      source.indexOf("static void command_system_observation("),
    ),
    script = new Script(
      body
        .replace(
          "static void command_effective(HANDLE token)",
          "function effective(token)",
        )
        .replace("AUDIT_POLICY_INFORMATION *policy", "let policy")
        .replace(/\b(?:BOOL|DWORD)\b/gu, "let")
        .replace("&policy->AuditSubCategoryGuid", "policy.AuditSubCategoryGuid")
        .replace(/policy->/gu, "policy.")
        .replace(/&command_category/gu, "command_category")
        .replace("&policy", "value=>policy=value") + "effective(7);",
    );
  for (const [available, flags] of [
    [true, 3],
    [true, 1],
    [false, 0],
  ]) {
    let output,
      closed = 0,
      lastError = 5;
    script.runInNewContext({
      NULL: null,
      TRUE: true,
      FALSE: false,
      ERROR_SUCCESS: 0,
      command_category: "file-system",
      POLICY_AUDIT_EVENT_SUCCESS: 1,
      POLICY_AUDIT_EVENT_FAILURE: 2,
      AuditComputeEffectivePolicyByToken: (token, category, count, result) => {
        assert.deepEqual([token, category, count], [7, "file-system", 1]);
        if (available)
          result({
            AuditSubCategoryGuid: category,
            AuditingInformation: flags,
          });
        return available;
      },
      GetLastError: () => lastError,
      AuditFree: () => {
        closed++;
        lastError = 6;
      },
      IsEqualGUID: (a, b) => a === b,
      invariant: assert.ok,
      printf: (_format, ...args) => {
        output = args;
      },
    });
    assert.deepEqual(output, [
      available ? "true" : "false",
      flags & 1 ? "true" : "false",
      flags & 2 ? "true" : "false",
      available ? 0 : 5,
    ]);
    assert.equal(closed, available ? 1 : 0);
  }
});

test("original policy diagnostics preserve unavailable values without querying or changing policy", async () => {
  const { source } = await commandCaptureProgram();
  const system =
    /static void command_system_observation\(void\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )[1];
  const project = new Script(
    system
      .replace(/\b(?:BOOL|DWORD|ULONG)\b/gu, "let")
      .replaceAll(
        "&command_system[i].AuditSubCategoryGuid",
        "command_system[i].AuditSubCategoryGuid",
      )
      .replaceAll("&command_category", "command_category"),
  );
  for (const policy of [
    null,
    [],
    [{ AuditSubCategoryGuid: "other", AuditingInformation: 3 }],
    [{ AuditSubCategoryGuid: "file", AuditingInformation: 0 }],
    [{ AuditSubCategoryGuid: "file", AuditingInformation: 3 }],
  ]) {
    const output = [];
    project.runInNewContext({
      FALSE: false,
      TRUE: true,
      command_system: policy,
      command_category_count: policy?.length ?? 0,
      command_category: "file",
      IsEqualGUID: (a, b) => a === b,
      printf: (_f, v) => output.push(v),
      fputs: (v) => output.push(v),
      putchar: () => {},
      stdout: {},
    });
    assert.deepEqual(
      output,
      policy?.[0]?.AuditSubCategoryGuid === "file"
        ? ["true", policy[0].AuditingInformation]
        : ["false", "null"],
    );
  }
});

test("native audit ACE sizing counts SidStart once and excludes unused baseline ACL storage", async () => {
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
      "utf8",
    ),
    start = source.indexOf(
      "PACL old; BOOL present;",
      source.indexOf("static void command_files_prepare("),
    ),
    end = source.indexOf("invariant(length<=16384", start);
  assert.ok(start > 0 && end > start);
  const program = new Script(`(() => {
    ${source
      .slice(start, end)
      .replace("ACL_SIZE_INFORMATION used={0}", "let used={}")
      .replaceAll("sizeof(DWORD)", "4")
      .replace(/\b(?:PACL|BOOL|DWORD)\b/gu, "let")
      .replace("&present", "value=>present=value")
      .replace("&old", "value=>old=value")
      .replace("&def", "null")
      .replace("&used", "used")
      .replaceAll("sizeof(ACL)", "8")
      .replaceAll("sizeof(SYSTEM_AUDIT_ACE)", "12")
      .replaceAll("sizeof(used)", "12")}
    return length;
  })()`);
  for (const old of [null, { AclSize: 64, AclBytesInUse: 28 }]) {
    for (const sidBytes of [12, 28]) {
      let queried = false;
      const length = program.runInNewContext({
        command_baseline: [1],
        i: 0,
        userSid: 2,
        AclSizeInformation: 2,
        GetSecurityDescriptorSacl: (_sd, present, acl) => {
          present(Boolean(old));
          acl(old);
          return true;
        },
        GetAclInformation: (acl, used, size, kind) => {
          assert.deepEqual([acl, size, kind], [old, 12, 2]);
          used.AclBytesInUse = old.AclBytesInUse;
          queried = true;
          return true;
        },
        GetLengthSid: () => sidBytes,
        win32_check: assert.ok,
      });
      // The new ACE is an 8-byte type/flags/size/mask header followed by the
      // complete SID. Existing occupied bytes already include their ACL header.
      assert.equal(length, (old ? 28 : 8) + 8 + sidBytes);
      assert.equal(queried, old !== null);
    }
  }
});

test("the actual finish reader admits only live original baselines before any installation intent", async () => {
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
      "utf8",
    ),
    start = source.indexOf(
      "command_privilege(SE_SECURITY_NAME);win32_check(AuditEnumerateSubCategories",
      source.indexOf("static void command_finish("),
    ),
    end = source.indexOf('puts("{\\"custodyReady\\":true}")', start);
  assert.ok(start > 0 && end > start);
  const program = new Script(
    `${source
      .slice(start, end)
      .replaceAll("command_sd(null,", "command_sd(nullHandle,")
      .replace(/\(BYTE \*\)/gu, "")
      .replace("sizeof(*command_system)", "1")
      .replace("char initialHash[65]", "let initialHash")
      .replace(/\b(?:DWORD|BOOL|PSECURITY_DESCRIPTOR|unsigned)\b/gu, "let")
      .replace(
        /,&(command_categories|command_category_count|command_system)\b/gu,
        ",value=>$1=value",
      )
      .replaceAll(",initialHash)", ",value=>initialHash=value)")} admitted();`,
  );
  for (const fault of [
    null,
    "system",
    "principal",
    "intent",
    "null",
    0,
    1,
    2,
    3,
    4,
    5,
  ]) {
    const baselines = Array.from({ length: 6 }, (_, i) => ({
      serial: `original-${i}`,
    }));
    let admitted = false;
    const api = {
      command_categories: null,
      command_category_count: 0,
      command_system: null,
      SE_SECURITY_NAME: "security",
      SE_KERNEL_OBJECT: 1,
      SE_FILE_OBJECT: 2,
      OWNER_SECURITY_INFORMATION: 1,
      DACL_SECURITY_INFORMATION: 4,
      SACL_SECURITY_INFORMATION: 8,
      NULL: null,
      TRUE: true,
      FALSE: false,
      WAIT_FAILED: -1,
      WAIT_TIMEOUT: 258,
      systemHash: "system",
      nullHash: "null",
      nullHandle: "null-handle",
      intent: "intent-handle",
      files: [0, 1, 2, 3, 4, 5],
      baselines,
      command_privilege: () => {},
      AuditEnumerateSubCategories: (_category, _all, categories, count) => {
        categories(["file-system"]);
        count(1);
        return true;
      },
      AuditQuerySystemPolicy: (_categories, _count, policy) => {
        policy(fault === "system" ? "foreign" : "system");
        return true;
      },
      command_sum: (data, _length, result) =>
        result(typeof data === "string" ? data : data.serial),
      command_principal_exists: () => fault === "principal",
      WaitForSingleObject: () => (fault === "intent" ? 0 : 258),
      command_sd: (file) =>
        file === "null-handle"
          ? { serial: fault === "null" ? "foreign" : "null" }
          : { serial: fault === file ? "foreign" : baselines[file].serial },
      GetSecurityDescriptorLength: (sd) => sd.serial.length,
      LocalFree: () => {},
      strcmp: (a, b) => (a === b ? 0 : 1),
      memcmp: (a, b) => (a.serial === b.serial ? 0 : 1),
      invariant: (ok, operation) => {
        if (!ok) throw new Error(operation);
      },
      win32_check: assert.ok,
      admitted: () => {
        admitted = true;
      },
    };
    if (fault === null) {
      program.runInNewContext(api);
      assert.equal(admitted, true);
    } else {
      assert.throws(
        () => program.runInNewContext(api),
        /command-(?:cleanup-baseline|intent-state)/u,
      );
      assert.equal(admitted, false);
    }
  }
});

test("owned command fixture deletion waits for independent restoration, and refusal closes without release", async () => {
  for (const refused of [false, true]) {
    const writes = [],
      child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    const close = async (code) => {
      const ended = once(child.stderr, "end");
      child.stdout.end();
      child.stderr.end();
      await ended;
      child.emit("close", code, null);
    };
    child.stdin = new Writable({
      write(value, _encoding, done) {
        writes.push(value.toString());
        if (value.toString() === "R")
          child.stdout.write('{"restorationReady":true}\n');
        else {
          assert.equal(value.toString(), "V");
          child.stdout.write(
            '{"retired":true,"completeDomain":true,"restored":true}\n',
          );
        }
        done();
      },
      final(done) {
        done();
        queueMicrotask(() => close(refused ? 126 : 0));
      },
    });
    const launch = () => {
      queueMicrotask(() =>
        child.stdout.write(JSON.stringify({ ready: true, identity }) + "\n"),
      );
      return child;
    };
    const signal = new AbortController().signal;
    const owner = await openWindowsCommandWatcher(
      "C:\\fixture\\helper.exe",
      [],
      {},
      signal,
      launch,
    );
    const failure = new Error("independent SACL mismatch");
    const settling = owner.finish(signal, async () => {
      assert.deepEqual(writes, ["R"]);
      if (refused) throw failure;
    });
    if (refused) await assert.rejects(settling, (error) => error === failure);
    else assert.equal((await settling).restored, true);
    assert.deepEqual(writes, refused ? ["R"] : ["R", "V"]);
  }
});

test("command settlement preserves its original failure and a separate cleanup cause", async () => {
  const original = new Error("lost payload reply");
  await assert.rejects(
    settleWindowsCommandCustody({
      retireDomain: async () => {
        throw original;
      },
      closeObserver: async () => {
        throw new Error("capture could not drain");
      },
      verifyObserver: async () => ({ completeDomain: true }),
      abandonFinish: async () => {},
    }),
    (error) =>
      error === original &&
      error.feasibilityCleanup.code === "cleanup-unobserved" &&
      error.feasibilityCleanup.detail.includes("capture retirement"),
  );
});

test("a failed restoration writer settles both early readers without replacing the first failure", async () => {
  const source = await readFile(
    new URL(
      "../ci/native/win32/feasibility-command-effects.js",
      import.meta.url,
    ),
    "utf8",
  );
  const start = source.lastIndexOf("        async finish() {"),
    end = source.indexOf("\n      }).catch", start);
  assert.ok(start > 0 && end > start);
  const finish = new Script(`({${source.slice(start, end)}}).finish()`);
  for (const phase of ["writer", "reader"]) {
    const calls = [],
      failure = new Error(`${phase} failed`);
    const context = {
      signal: new AbortController().signal,
      failed: undefined,
      retirementFailure: undefined,
      fixturesRetired: false,
      nativeException: () => {},
      need: assert.ok,
      cleanupReader: {
        async finish(_signal, verify) {
          calls.push("writer");
          if (phase === "writer") throw failure;
          await verify();
          assert.fail("failed verification cannot release fixture deletion");
        },
      },
      restorationReader: {
        async finish() {
          calls.push("read");
          throw failure;
        },
        async abandon() {
          calls.push("abandon");
          throw new Error("reader exited without verification");
        },
      },
      restorationVerifier: {
        async finish() {
          calls.push("reader-retired");
          return { retired: true, exitCode: phase === "reader" ? 126 : 0 };
        },
      },
      readerVerifier: {
        async finish() {
          calls.push("writer-retired");
          return { retired: true };
        },
      },
    };
    await assert.rejects(
      finish.runInNewContext(context),
      (error) => error === failure,
    );
    assert.deepEqual(calls, [
      "writer",
      phase === "writer" ? "abandon" : "read",
      "reader-retired",
      "writer-retired",
    ]);
    assert.equal(context.fixturesRetired, false);
  }
});

test("actual failed broker reader retains admitted terminal capture and records a separate cleanup error", async () => {
  const source = await readFile(
      new URL(
        "../ci/native/win32/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    start = source.indexOf("reading = (async"),
    end = source.indexOf("reading.catch(fail);", start),
    failureStart = source.indexOf("const fail = (error) =>"),
    failureEnd = source.indexOf("const call =", failureStart),
    program = new Script(`(async () => {
      let failed = primary, retiring = true, retirementFailure, reading, bytes = 0;
      ${source.slice(failureStart, failureEnd)}
      ${source.slice(start, end)}
      await reading;
      return { failed, retirementFailure };
    })()`);
  for (const admitted of [false, true])
    for (const malformed of [false, true]) {
      const stdout = new PassThrough(),
        pushed = [],
        settled = [],
        primary = new Error("setup or command rejected"),
        pending = new Map(
          ["D", "S"].map((event) => [
            event,
            {
              resolve: () => settled.push(event),
              reject: assert.fail,
            },
          ]),
        ),
        running = program.runInNewContext({
          primary,
          Buffer,
          createInterface,
          broker: { stdout },
          pending,
          closing: false,
          setupVerified: admitted,
          nativeException: () => {},
          need: assert.ok,
          digest: sha,
          windowsCommandAuditRead: () => ({
            native: {},
            logonId: "0000000000000001",
          }),
          xml: new Map(),
          logons: new Map(),
          decoder: { push: async (bytes) => pushed.push(bytes.readUInt32LE()) },
        });
      stdout.end(
        [
          {
            event: "audit",
            hex: malformed ? "invalid" : "00000000",
            decoded: {},
          },
          {
            event: "capture-end",
            hex: "00000000",
            decoded: {},
            bytes: 4,
            records: 1,
          },
          { event: "D" },
          { event: "S" },
        ]
          .map((frame) => JSON.stringify(frame) + "\n")
          .join(""),
      );
      const outcome = await running;
      assert.equal(outcome.failed, primary);
      assert.deepEqual(settled, ["D", "S"]);
      assert.deepEqual(
        pushed,
        admitted ? (malformed ? [0xffffffff] : [4, 0xffffffff]) : [],
      );
      assert.equal(!!outcome.retirementFailure, admitted && malformed);
    }
});

test("actual rejected-setup retirement restores originals without rethrowing the primary and still rejects cleanup failures", async () => {
  const source = await readFile(
      new URL(
        "../ci/native/win32/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    start = source.indexOf("async retire(value, signal) {"),
    end = source.lastIndexOf("\n    },\n  };"),
    failureStart = source.indexOf("const fail = (error) =>"),
    failureEnd = source.indexOf("const call =", failureStart),
    program = new Script(`(async () => {
      let failed = primary, retiring = false, retirementFailure, cleanupDeadline, closing = false;
      ${source.slice(failureStart, failureEnd)}
      const effects = {${source.slice(start, end)} }};
      return effects.retire(value, signal);
    })()`);
  for (const fault of [
    null,
    "capture",
    "watcher",
    "writer",
    "restoration",
    "restoration-barrier",
    "reader-barrier",
    "abandon",
  ]) {
    const primary = Object.assign(new Error("broker setup authority absent"), {
        feasibilityCause: {
          code: "prerequisite-unavailable",
          detail: "broker setup authority absent",
        },
      }),
      cleanup = Object.assign(new Error(`${fault} refused`), {
        feasibilityCleanup: {
          code: "cleanup-unobserved",
          detail: `${fault} refused`,
        },
      }),
      calls = [],
      file = { identity: "held", sha256: PIN, daclSha256: PIN },
      value = { original: { files: [file, file, file, file] } },
      context = {
        primary,
        value,
        signal: new AbortController().signal,
        performance: { now: () => 1 },
        broker: {},
        watcher: {
          finish: async () => {
            calls.push("watcher");
            return { completeDomain: true, exitCode: 0 };
          },
        },
        cleanupReady: true,
        pending: new Map(),
        prepared: value,
        setupVerified: false,
        need: assert.ok,
        digest: sha,
        nativeException: () => {},
        settleWindowsCommandCustody,
        windowsCommandCleanupSnapshot,
        closed: Promise.resolve({ code: 0, signal: null }),
        reading: Promise.resolve(),
        decoder: { finish: assert.fail }, // Rejected setup cannot claim admitted capture.
        preparation: { settle: async () => calls.push("preparation") },
        call: async (key) => {
          calls.push(key);
          if (fault === "capture" && key === "S") throw cleanup;
          return { captureRetired: key === "S" };
        },
        cleanupReader: {
          inspect: async () => {
            calls.push("domain");
            return {
              empty: true,
              admissionsClosed: true,
              files: value.original.files,
            };
          },
          finish: async (_signal, verify) => {
            calls.push("restore");
            if (fault === "writer") throw cleanup;
            await verify();
            calls.push("remove");
            return { restored: true, fixturesRemoved: true };
          },
          abandon: async () => {
            calls.push("abandon");
            if (fault === "abandon") throw cleanup;
          },
        },
        observerVerifier: {
          finish: async () => {
            calls.push("watcher-barrier");
            if (["watcher", "abandon"].includes(fault)) throw cleanup;
            return { retired: true };
          },
        },
        restorationReader: {
          finish: async () => {
            calls.push("restoration-read");
            if (fault === "restoration") throw cleanup;
            return { independent: true, restored: true };
          },
          abandon: async () => calls.push("restoration-abandon"),
        },
        restorationVerifier: {
          finish: async () => {
            calls.push("restoration-barrier");
            if (fault === "restoration-barrier") throw cleanup;
            return { retired: true, exitCode: 0 };
          },
        },
        readerVerifier: {
          finish: async () => {
            calls.push("writer-barrier");
            if (fault === "reader-barrier") throw cleanup;
            return { retired: true };
          },
        },
      };
    const f = fixture(({ effects }) => {
      const prepare = effects.prepare,
        coverage = effects.setup;
      effects.prepare = async (...args) => ({
        ...(await prepare(...args)),
        sentinelSha256: sha(JSON.stringify(file)),
      });
      effects.setup = async () => {
        await coverage();
        throw primary;
      };
      effects.retire = () => program.runInNewContext(context);
    });
    const result = await f.run();
    assert.equal(result.status, "BLOCKED");
    assert.deepEqual(result.cause, primary.feasibilityCause);
    assert.equal(
      result.cleanup.status,
      fault ? "UNCERTAIN" : "PASS",
      JSON.stringify(result.cleanup),
    );
    if (fault)
      assert.deepEqual(result.cleanup.cause, cleanup.feasibilityCleanup);
    else {
      assert.equal(result.cleanup.independent, true);
      assert.equal(result.cleanup.emergency, false);
    }
    assert.deepEqual(f.requests, []);
    assert.equal(
      primary.feasibilityCause.detail,
      "broker setup authority absent",
    );
    assert.deepEqual(calls.slice(0, 5), [
      "D",
      "domain",
      "S",
      "watcher",
      "watcher-barrier",
    ]);
    assert.equal(calls.includes("writer-barrier"), true);
    assert.equal(calls.includes("restoration-barrier"), true);
    if (["watcher", "abandon"].includes(fault)) {
      assert.equal(calls.includes("restore"), false);
      assert.equal(calls.includes("abandon"), true);
      assert.equal(calls.includes("restoration-abandon"), true);
    } else if (fault === "writer") {
      assert.equal(calls.includes("restoration-abandon"), true);
      assert.equal(calls.includes("remove"), false);
    } else {
      assert.ok(calls.indexOf("restore") > calls.indexOf("watcher-barrier"));
      assert.ok(
        calls.indexOf("restoration-barrier") >
          calls.indexOf("restoration-read"),
      );
      assert.equal(
        calls.includes("remove"),
        !["restoration", "restoration-barrier"].includes(fault),
      );
    }
  }
});
