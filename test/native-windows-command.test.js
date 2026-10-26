import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { PassThrough, Writable } from "node:stream";
import { EventEmitter, once } from "node:events";
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { Script } from "node:vm";
import { win32 as windowsPath } from "node:path";
import { createNativeDiagnosticWriter } from "../ci/native/diagnostics.js";
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
      auditing: Object.fromEntries(
        ["before", "after"].map((phase) => [
          phase,
          {
            operating: {
              userSid: identity.userSid,
              level: 2,
              token: { ...token },
            },
            effective: {
              available: true,
              success: true,
              failure: true,
              error: 0,
            },
            files: [file, file].map(({ identity }) => ({
              identity,
              saclSha256: PIN,
            })),
          },
        ]),
      ),
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
    "control-policy",
    "control-sacl",
    "control-operating",
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
          if (fault === "control-policy")
            observation.auditing.before.effective.success = false;
          if (fault === "control-sacl")
            observation.auditing.after.files[0].saclSha256 = sha("changed");
          if (fault === "control-operating")
            observation.auditing.before.operating.token.authenticationId =
              "00000000:00000002";
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
        stamp: String(100 + Number(index) * 50),
        subject: capture.api.userText,
        logon: "0x1",
        keywords: "0x8020000000000000",
        record: String(Number(index) + 1),
      });
      const selected = program.selection.runInNewContext(capture.api);
      if (selected) program.caseProjection.runInNewContext(capture.api);
      return selected;
    };
    capture.notify(["0", "1"]);
    capture.capture();
    assert.equal(capture.api.command_target_seen, !substitute);
    assert.equal(capture.api.command_marker_seen, !substitute);
    if (substitute) {
      assert.throws(
        () => capture.api.command_barrier(),
        (code) => code === 126,
      );
      assert.deepEqual(capture.api.first, [
        "command-marker-barrier",
        "invariant",
        0,
      ]);
      assert.match(
        capture.output(),
        /scanned=2 scanned-bytes=16 selected=1 selected-bytes=8/u,
      );
      assert.match(capture.output(), /target-seen=0 marker-seen=0/u);
    } else {
      capture.api.command_barrier();
      assert.deepEqual(JSON.parse(capture.replies()), {
        event: "B",
        sequence: 1,
        time: "90",
        records: 2,
      });
      assert.equal(capture.output(), "");
    }
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

test("completed command I/O keeps output live while target then marker delivery gates release", async () => {
  const program = await commandCaptureProgram();
  for (const fault of [
    null,
    "absent",
    "target-only",
    "wrong-marker",
    "unfinished",
    "child-exit",
    "child-zero",
    "stop",
    "owner-loss",
    "queued-input",
  ]) {
    const f = commandCaptureFixture(program),
      api = f.api,
      exited = fault === "child-exit" || fault === "child-zero";
    api.command_control_completed = false;
    api.command_case_finished = fault !== "unfinished";
    api.command_paths = ["inspect", "edit", "outside", "marker"];
    let retired = false;
    api.ownerInput =
      fault === "stop" ? "D\n" : fault === "queued-input" ? "J 00\n" : "";
    api.ownerPresent = fault !== "owner-loss";
    api.command_retire_domain = () => {
      retired = true;
    };
    api.wcscmp = (a, b) => Number(a !== b);
    api._wcsicmp = (a, b) => Number(a.toLowerCase() !== b.toLowerCase());
    api.onProject = (row) => {
      Object.assign(api, {
        process: String(api.command_case_pid),
        object:
          row === "target"
            ? "outside"
            : fault === "wrong-marker"
              ? "other"
              : "marker",
        eventId: "4663",
        mask: row === "target" ? "2" : "1",
        stamp: row === "target" ? "100" : "101",
        subject: api.userText,
        logon: "1",
        keywords: "0x8020000000000000",
        record: row === "target" ? "10" : "11",
      });
      program.caseProjection.runInNewContext(api);
      return true;
    };
    let delivered = false;
    api.onWait = () => {
      if (delivered || fault === "absent" || f.calls.at(-1)?.[1] !== 10) return;
      delivered = true;
      f.notify(fault === "target-only" ? ["target"] : ["target", "marker"]);
    };
    if (exited) {
      const wait = api.WaitForSingleObject,
        remaining = { "child-output": 2, "child-error": 3 },
        print = api.printf;
      api.WaitForSingleObject = (handle, timeout) =>
        handle === "client" ? 0 : wait(handle, timeout);
      api.GetExitCodeProcess = (_process, code) => {
        api.controlExited = true;
        code(fault === "child-zero" ? 0 : 126);
        return true;
      };
      api.command_pump = (slot, event) => {
        if (!slot.value) return;
        f.calls.push(["pump", event]);
        if (api.controlExited && --remaining[slot.value] === 0)
          slot.value = null;
      };
      api.printf = (format, ...values) => {
        if (format.includes("probe-exit"))
          assert.deepEqual(remaining, { "child-output": 0, "child-error": 0 });
        print(format, ...values);
      };
    }
    if (fault === "stop") {
      api.command_barrier();
      assert.equal(retired, true);
      assert.equal(f.replies(), "", "Cancellation cannot acknowledge capture");
    } else if (fault && fault !== "queued-input") {
      assert.throws(
        () => api.command_barrier(),
        (code) => code === 126,
        fault,
      );
      assert.equal(f.replies().includes('"event":"B"'), false, fault);
      assert.equal(
        api.first[0],
        fault === "unfinished"
          ? "command-coverage-state"
          : exited
            ? "command-case-lifetime"
            : fault === "owner-loss"
              ? "command-owner-read"
              : "command-marker-barrier",
      );
      if (exited)
        assert.deepEqual(JSON.parse(f.replies()), {
          event: "probe-exit",
          exitCode: fault === "child-zero" ? 0 : 126,
        });
      if (fault === "absent")
        assert.match(f.output(), /scanned=0.*io-completed=1/u);
    } else {
      api.command_barrier();
      assert.equal(JSON.parse(f.replies()).event, "B");
      assert.deepEqual(f.projected, ["target", "marker"]);
      assert.equal(api.command_target_seen && api.command_marker_seen, true);
      assert.equal(
        api.command_control_completed,
        false,
        "Event delivery does not invent the later process exit",
      );
      assert.ok(
        f.calls.findIndex(([name]) => name === "pump") <
          f.calls.findIndex(([name]) => name === "project"),
      );
      if (fault === "queued-input") {
        assert.equal(api.ownerInput, "J 00\n");
        assert.equal(api.ownerReads, 0);
      }
    }
    api.command_capture_close();
    for (const handle of ["subscription", "bookmark", "notification"])
      assert.equal(
        f.closed.filter((value) => value === handle).length,
        1,
        `${fault}:${handle}`,
      );
  }
});

test("native structured audit query selects only loss and exact subject/type Event nodes", async () => {
  const program = await commandCaptureProgram(),
    f = commandCaptureFixture(program);
  // XPath 'or' outside the selected Event predicate returns a Boolean, not
  // Event nodes. Inspect the produced expression, without emulating Event Log.
  const eventPredicate = (query) => {
    assert.ok(query.startsWith("*["));
    let depth = 0,
      quote;
    for (let i = 1; i < query.length; i++) {
      const c = query[i];
      if (quote) {
        if (c === quote) quote = null;
        continue;
      }
      if (c === '"' || c === "'") {
        quote = c;
        continue;
      }
      if (c === "[") depth++;
      if (c === "]" && --depth === 0) {
        assert.equal(i, query.length - 1, "the result must select Event nodes");
        return query.slice(2, -1);
      }
    }
    assert.fail("Unclosed Event predicate");
  };
  assert.throws(() =>
    eventPredicate("*[System[EventID=1101]] or *[System[EventID=4663]]"),
  );
  for (const interval of [
    "",
    " and TimeCreated[@SystemTime>='2026-10-01T00:00:00Z']",
  ]) {
    f.api.command_audit_query(f.api.command_subscription_query, interval);
    const query = f.api.command_subscription_query.text;
    assert.match(query, /^<QueryList><Query Id="0" Path="Security">/u);
    assert.ok(query.endsWith("</Query></QueryList>"));
    const selections = [
      ...query.matchAll(/<Select Path="Security">(.*?)<\/Select>/gu),
    ];
    assert.equal(selections.length, 2);
    const [loss, access] = selections.map((m) => eventPredicate(m[1]));
    assert.deepEqual(
      [...loss.matchAll(/EventID=(\d+)/gu)].map((m) => Number(m[1])),
      [1101, 1102],
    );
    assert.ok(!loss.includes("EventData")); // Loss cannot be filtered by a command principal.
    assert.deepEqual(
      [...access.matchAll(/EventID=(\d+)/gu)].map((m) => Number(m[1])),
      [4663, 4656],
    );
    assert.ok(access.includes("band(Keywords,4503599627370496)"));
    assert.ok(access.includes("band(Keywords,9007199254740992)"));
    assert.ok(
      access.includes('Provider[@Name="Microsoft-Windows-Security-Auditing"]'),
    );
    assert.ok(
      access.includes(`Data[@Name="SubjectUserSid"]="${f.api.userText}"`),
    );
    assert.ok(access.includes('Data[@Name="ObjectType"]="File"'));
    assert.equal(
      query.split(interval || "TimeCreated").length - 1,
      interval ? 2 : 0,
    );
    assert.ok(!query.includes("ObjectName")); // Held Windows names join after subscription.
  }
});

test("native target and later marker require the parked birth, operating logon and actual outcome", async () => {
  const program = await commandCaptureProgram();
  for (const [action, control, permit] of [
    [0, false, true],
    [1, false, true],
    [1, false, false],
    [2, false, false],
    [2, true, true],
  ]) {
    const faults =
      action === 2 && control
        ? [
            null,
            "pid",
            "sid",
            "logon",
            "before-release",
            "before-birth",
            "mask",
            "outcome",
            "keywords",
            "missing",
            "closing",
            "birth",
            "exited",
            "wait",
            "marker-order",
            "marker-time",
            "marker-outcome",
          ]
        : [null, "mask", "outcome"];
    for (const fault of faults) {
      const f = commandCaptureFixture(program),
        api = f.api;
      Object.assign(api, {
        command_action: action,
        command_control: control,
        command_case_permit: permit,
        command_paths: [
          "C:\\fixture\\inspect",
          "C:\\fixture\\edit",
          "C:\\fixture\\outside",
          "C:\\fixture\\gate",
        ],
        process: fault === "pid" ? "44" : "43",
        object: [
          "C:\\fixture\\inspect",
          "C:\\fixture\\edit",
          "C:\\fixture\\outside",
        ][action],
        eventId: permit ? "4663" : "4656",
        mask: action === 0 ? "0x1" : "0x2",
        stamp:
          fault === "before-release"
            ? "89"
            : fault === "before-birth"
              ? "49"
              : "100",
        subject: fault === "sid" ? "S-1-5-21-2" : api.userText,
        logon: fault === "logon" ? "0x2" : "0x1",
        keywords: permit ? "0x8020000000000000" : "0x8010000000000000",
        record: "10",
        _wcsicmp: (a, b) => (a.toLowerCase() === b.toLowerCase() ? 0 : 1),
        wcscmp: (a, b) => (a === b ? 0 : 1),
      });
      if (fault === "before-birth") api.command_case_from = 40n;
      if (fault === "mask") api.mask = "0x4";
      if (fault === "outcome")
        api.eventId = api.eventId === "4656" ? "4663" : "4656";
      if (fault === "keywords") api.keywords = "0x8030000000000000";
      if (fault === "missing") api.logon = null;
      if (fault === "closing") api.command_closing = true;
      if (fault === "birth") api.creation = () => 51n;
      if (fault === "exited") api.WaitForSingleObject = () => api.WAIT_OBJECT_0;
      if (fault === "wait")
        api.WaitForSingleObject = () => {
          api.SetLastError(5);
          return api.WAIT_FAILED;
        };
      if (fault === "birth" || fault === "exited" || fault === "wait") {
        assert.throws(
          () => program.caseProjection.runInNewContext(api),
          (code) => code === 126,
        );
        const [operation, domain, value] =
          fault === "wait"
            ? ["command-case-wait", "win32", 5]
            : ["command-case-lifetime", "invariant", 0];
        assert.deepEqual(api.first, [operation, domain, value]);
        assert.deepEqual(
          windowsFeasibilityDiagnostics(
            `native-windows: operation=${operation} domain=${domain} value=${value}\n`,
          ).failure,
          { operation, domain, value },
        );
        continue;
      }
      program.caseProjection.runInNewContext(api);
      const acceptedTarget = !fault || fault.startsWith("marker-");
      assert.equal(
        api.command_target_seen,
        acceptedTarget,
        `${action}:${control}:${fault}`,
      );
      Object.assign(api, {
        object: api.command_paths[3].toUpperCase(),
        eventId: fault === "marker-outcome" ? "4656" : "4663",
        mask: "0x1",
        stamp: fault === "marker-time" ? "99" : "101",
        record: fault === "marker-order" ? "10" : "11",
        keywords: "0x8020000000000000",
      });
      program.caseProjection.runInNewContext(api);
      assert.equal(
        api.command_marker_seen,
        !fault,
        `${action}:${control}:${fault}`,
      );
      if (!fault)
        assert.deepEqual(
          [api.command_target_record, api.command_marker_record],
          [10n, 11n],
        );
      if (!fault && control) {
        Object.assign(api, {
          object: api.command_paths[action],
          mask: "0x2",
          record: "12",
          stamp: "102",
        });
        program.caseProjection.runInNewContext(api);
        assert.equal(
          api.command_marker_seen,
          false,
          "a later target needs its own post-operation marker",
        );
        Object.assign(api, {
          object: api.command_paths[3],
          mask: "0x1",
          record: "13",
          stamp: "103",
        });
        program.caseProjection.runInNewContext(api);
        assert.equal(api.command_marker_seen, true);
        assert.equal(api.command_marker_record, 13n);
      }
    }
  }
});

test("the private command selection carries each frozen policy outcome to the native event predicate", async () => {
  const [effects, source] = await Promise.all(
    ["feasibility-command-effects.js", "feasibility-command.h"].map((file) =>
      readFile(new URL(`../ci/native/win32/${file}`, import.meta.url), "utf8"),
    ),
  );
  const begin = /async begin\(value, spec\) \{([\s\S]*?)\n    \},/u.exec(
    effects,
  )[1];
  const native = source
    .split("\n")
    .find((row) => row.includes('strncmp(line,"K ",2)'));
  const select = new Script(
    native
      .slice(native.indexOf("{") + 1, native.indexOf("puts("))
      .replace("(unsigned)", ""),
  );
  for (const profile of ["read-only", "workspace-write"]) {
    for (const [index, action] of ["inspect", "edit", "outside"].entries()) {
      const permit =
        action === "inspect" ||
        (action === "edit" && profile === "workspace-write");
      const calls = [],
        resets = [],
        state = {
          need: assert.ok,
          command_control_verified: true,
          command_server_released: true,
          command_client: null,
          command_reset: (selected) => resets.push(selected),
          strlen: (text) => text.length,
        };
      await new Script(`(async () => {${begin}})()`).runInNewContext({
        value: {},
        spec: { action, permit },
        phase: "",
        start: null,
        need: assert.ok,
        call: async (line) => {
          calls.push(line);
          if (line !== "B") {
            state.line = line;
            select.runInNewContext(state);
          }
          return {};
        },
      });
      assert.deepEqual(calls, ["B", `K ${index} ${permit ? 1 : 0}`]);
      assert.equal(state.command_action, index);
      assert.equal(state.command_case_permit, permit);
      assert.deepEqual(resets, index < 2 ? [index] : []);
      for (const line of ["K 1", "K 1 true", "K 1 2", "K 3 1"]) {
        state.line = line;
        assert.throws(() => select.runInNewContext(state));
        assert.equal(state.command_case_permit, permit);
      }
    }
  }
});

test("actual command token and held SACL reads precede control I/O and remain required after it", async () => {
  const source = await readFile(
    new URL(
      "../ci/native/win32/feasibility-command-effects.js",
      import.meta.url,
    ),
    "utf8",
  );
  const guards = source.slice(
    source.indexOf("const effectiveCommandAudit ="),
    source.indexOf("/** A reply cannot"),
  );
  const start = source.indexOf(
    "  const observation = async (spec, signal) => {",
  );
  const observe = source.slice(
    start,
    source.indexOf("\n  return {\n    noCustody:", start),
  );
  const program = new Script(
    `(async () => {${guards} ${observe} return observation({action:"outside"}, signal);})()`,
  );
  for (const fault of [
    null,
    "missing",
    "query",
    "success",
    "failure",
    "sacl",
    "identity",
    "after",
    "operating-missing",
    "operating-sid",
    "operating-level",
    "operating-token",
    "operating-after",
    "before-completed",
    "after-incomplete",
  ]) {
    const prepared = {
      nonce: "a".repeat(32),
      observer: identity,
      helperSha256: PIN,
    };
    await brokerSetup(prepared);
    const audit = {
      effective: { available: true, success: true, failure: true, error: 0 },
      operating: { userSid: identity.userSid, level: 2, token: {} },
      files: [2, 3].map((index) => ({
        identity: prepared.original.files[index].identity,
        saclSha256: sha("owned-acl"),
      })),
    };
    const before = {
        identity,
        token: {},
        ioCompleted: false,
        auditing: structuredClone(audit),
      },
      after = structuredClone(before),
      calls = [];
    after.ioCompleted = true;
    if (fault === "before-completed") before.ioCompleted = true;
    if (fault === "after-incomplete") after.ioCompleted = false;
    if (fault === "missing") delete before.auditing;
    if (fault === "query") before.auditing.effective.error = 5;
    if (fault === "success" || fault === "failure")
      before.auditing.effective[fault] = false;
    if (fault === "sacl") before.auditing.files[0].saclSha256 = sha("foreign");
    if (fault === "identity")
      before.auditing.files[1].identity = prepared.original.files[0].identity;
    if (fault === "after") after.auditing.files[1].saclSha256 = sha("foreign");
    if (fault === "operating-missing") delete before.auditing.operating;
    if (fault === "operating-sid") before.auditing.operating.userSid += "0";
    if (fault === "operating-level") before.auditing.operating.level = 1;
    if (fault === "operating-token")
      before.auditing.operating.token.restricted = true;
    if (fault === "operating-after")
      after.auditing.operating.token.restricted = true;
    const context = {
      Buffer,
      prepared,
      signal: new AbortController().signal,
      start: { records: 0 },
      logons: new Map(),
      failed: null,
      digest: sha,
      commandEvidence: (ok, reason) => assert.ok(ok, reason),
      verifier: async (row) => row,
      decoder: { state: () => ({ ready: true, events: [] }) },
      call: async (key) => {
        calls.push(key);
        return key === "N"
          ? before
          : key === "F"
            ? after
            : key === "B"
              ? { time: "110", records: 0 }
              : { exitCode: 0 };
      },
    };
    if (fault) {
      await assert.rejects(
        program.runInNewContext(context),
        /command token|SACL/u,
        fault,
      );
      assert.deepEqual(
        calls,
        ["after", "operating-after", "after-incomplete"].includes(fault)
          ? ["N", "T", "F"]
          : ["N"],
      );
    } else {
      const result = await program.runInNewContext(context);
      assert.deepEqual(calls, ["N", "T", "F", "B", "U"]);
      assert.deepEqual(result.auditing.before, audit);
      assert.equal(
        result.events.length,
        0,
        "producer prerequisites do not invent delivered events",
      );
    }
  }
});

test("native command auditing queries the dynamic operating context, reverts and reads held target/marker SACLs", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:void|struct command_token_observation) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const effective = body("command_effective")
    .replace("AUDIT_POLICY_INFORMATION *policy", "let policy")
    .replace(/\b(?:BOOL|DWORD)\b/gu, "let")
    .replaceAll("&policy->AuditSubCategoryGuid", "policy.AuditSubCategoryGuid")
    .replaceAll("policy->", "policy.")
    .replaceAll("&command_category", "command_category")
    .replace("&policy", "value=>policy=value");
  const auditing = body("command_case_auditing")
    .replace("struct command_token_observation operating=", "const operating=")
    .replace("&operating", "operating")
    .replaceAll("&command_preflight_owned.token", "tokenSlot")
    .replace("TOKEN_USER *subject", "const subject")
    .replace("TOKEN_STATISTICS *stats", "const stats")
    .replaceAll("subject->User.Sid", "subject.User.Sid")
    .replaceAll("stats->", "stats.")
    .replace(
      "((ULONGLONG)(DWORD)stats.AuthenticationId.HighPart<<32)|stats.AuthenticationId.LowPart",
      "stats.AuthenticationId.HighPart*0x100000000+stats.AuthenticationId.LowPart",
    )
    .replace(
      "unsigned indices[2]={command_action,3}",
      "const indices=[command_action,3]",
    )
    .replace("char id[50],hash[65]", "const id={},hash={}")
    .replace(/\b(?:unsigned|BOOL|ULONGLONG)\b/gu, "let")
    .replace("(let)SecurityImpersonation", "SecurityImpersonation")
    .replace("strcmp(id,", "strcmp(id.value,")
    .replace(
      "memcpy(command_delivery.sacls[i],hash,65)",
      "command_delivery.sacls[i]=hash.value",
    )
    .replace('i?",":"",id,hash', 'i?",":"",id.value,hash.value');
  const program = new Script(
    `function command_effective(token) {${effective}} ${auditing}`,
  );
  for (const fault of [
    null,
    "impersonate",
    "open",
    "subject",
    "subject-diagnostic",
    "type",
    "level",
    "logon",
    "revert",
    "query",
    "failure-policy",
    "close",
    "identity",
    "sacl",
  ]) {
    const calls = [],
      freed = [],
      tokenSlot = { value: null };
    let output = "",
      lastError = 5;
    const context = {
      tokenSlot,
      command_preflight_owned: {
        get token() {
          return tokenSlot.value;
        },
      },
      NULL: null,
      TRUE: true,
      FALSE: false,
      ERROR_SUCCESS: 0,
      TOKEN_QUERY: 8,
      TokenUser: 1,
      TokenStatistics: 10,
      TokenImpersonation: 2,
      SecurityImpersonation: 2,
      POLICY_AUDIT_EVENT_SUCCESS: 1,
      POLICY_AUDIT_EVENT_FAILURE: 2,
      command_client: 73,
      command_case_logon: fault === "logon" ? 2 : 0,
      command_gate: 74,
      userSid: identity.userSid,
      userText: identity.userSid,
      command_category: "file-system",
      command_delivery: {
        subject: [],
        operating: false,
        sacls: [{}, {}],
        rejected: Array(4).fill(0),
      },
      command_operating_sacls(indices) {
        assert.equal(context.command_preflight_owned.impersonating, false);
        assert.deepEqual(Array.from(indices), [2, 3]);
        calls.push("ace-projection");
      },
      command_action: 2,
      command_files: [11, 12, 13, 14],
      command_ids: ["inspect", "edit", "outside", "marker"],
      stdout: {},
      ImpersonateNamedPipeClient(pipe) {
        assert.equal(pipe, 74);
        calls.push("impersonate");
        return fault !== "impersonate";
      },
      GetCurrentThread: () => 99,
      OpenThreadToken(thread, access, asSelf, out) {
        assert.deepEqual([thread, access, asSelf], [99, 8, true]);
        calls.push("token");
        if (fault === "open") return false;
        out.value = 19;
        return true;
      },
      OpenProcessToken: () =>
        assert.fail("The parked primary is not the operating token"),
      info(token, kind) {
        assert.equal(token, 19);
        return kind === 1
          ? { User: { Sid: fault === "subject" ? "other" : identity.userSid } }
          : {
              TokenType: fault === "type" ? 1 : 2,
              ImpersonationLevel: fault === "level" ? 1 : 2,
              AuthenticationId: { HighPart: 0, LowPart: 1 },
            };
      },
      command_gate_sid: (sid) => {
        context.command_delivery.subject =
          fault === "subject-diagnostic" ? "" : sid;
        return fault === "subject-diagnostic" ? 5 : 0;
      },
      EqualSid: (a, b) => a === b,
      free: () => {},
      command_revert() {
        assert.equal(context.command_preflight_owned.impersonating, true);
        context.command_preflight_owned.impersonating = false;
        calls.push("revert");
        if (fault === "revert") throw new Error("command-revert");
        return true;
      },
      command_token_observe(token) {
        assert.equal(token, 19);
        assert.equal(context.command_preflight_owned.impersonating, true);
        calls.push("operating-token");
        return { authenticationId: "00000000:00000001" };
      },
      command_token_write(value) {
        assert.equal(context.command_preflight_owned.impersonating, false);
        calls.push("token-output");
        output += JSON.stringify(value);
      },
      AuditComputeEffectivePolicyByToken(token, category, count, out) {
        assert.deepEqual([token, category, count], [19, "file-system", 1]);
        assert.equal(context.command_preflight_owned.impersonating, false);
        calls.push("effective");
        if (fault === "query") return false;
        out({
          AuditSubCategoryGuid: category,
          AuditingInformation: fault === "failure-policy" ? 1 : 3,
        });
        return true;
      },
      AuditFree(policy) {
        freed.push(policy);
        lastError = 6;
      },
      release_handle(slot, operation) {
        assert.deepEqual([slot.value, operation], [19, "command-token-close"]);
        slot.value = null;
        calls.push("close");
        if (fault === "close") throw new Error(operation);
        return true;
      },
      fileid(handle, out) {
        calls.push(`id:${handle}`);
        out.value =
          fault === "identity" ? "other" : handle === 13 ? "outside" : "marker";
      },
      command_sacl_read(handle, out) {
        calls.push(`sacl:${handle}`);
        if (fault === "sacl") throw new Error("sacl-read");
        out.value = sha(String(handle));
      },
      GetLastError: () => lastError,
      IsEqualGUID: (a, b) => a === b,
      strcmp: (a, b) => (a === b ? 0 : 1),
      win32_check(ok, operation) {
        if (!ok) throw new Error(operation);
      },
      invariant(ok, operation) {
        if (!ok) throw new Error(operation);
      },
      failure: () => assert.fail("Unexpected cleanup dispatch"),
      fputs: (text) => {
        output += text;
      },
      printf: (format, ...args) => {
        let i = 0;
        output += format.replace(/%(?:l)?[us]/gu, () => String(args[i++]));
      },
      putchar: (text) => {
        output += text;
      },
    };
    if (
      [
        "impersonate",
        "open",
        "subject",
        "type",
        "level",
        "logon",
        "revert",
        "close",
        "identity",
        "sacl",
      ].includes(fault)
    )
      assert.throws(
        () => program.runInNewContext(context),
        /command-client|command-revert|command-token-close|command-file-identity|sacl-read/u,
      );
    else {
      program.runInNewContext(context);
      const row = JSON.parse(output);
      assert.equal(
        context.command_delivery.policyError,
        fault === "query" ? 5 : 0,
      );
      assert.equal(context.command_delivery.operating, false);
      assert.deepEqual(context.command_delivery.sacls, [sha("13"), sha("14")]);
      assert.deepEqual(row.effective, {
        available: fault !== "query",
        success: fault !== "query",
        failure: fault !== "query" && fault !== "failure-policy",
        error: fault === "query" ? 5 : 0,
      });
      assert.deepEqual(row.operating, {
        userSid: identity.userSid,
        level: 2,
        token: { authenticationId: "00000000:00000001" },
      });
      assert.deepEqual(row.files, [
        { identity: "outside", saclSha256: sha("13") },
        { identity: "marker", saclSha256: sha("14") },
      ]);
      assert.deepEqual(calls, [
        "impersonate",
        "token",
        "operating-token",
        "revert",
        "effective",
        "token-output",
        "close",
        "id:13",
        "sacl:13",
        "id:14",
        "sacl:14",
        "ace-projection",
      ]);
    }
    if (!["impersonate", "open"].includes(fault)) {
      assert.equal(
        context.command_delivery.subjectError,
        fault === "subject-diagnostic" ? 5 : 0,
      );
      assert.equal(
        context.command_delivery.subject,
        fault === "subject"
          ? "other"
          : fault === "subject-diagnostic"
            ? ""
            : identity.userSid,
      );
    }
    assert.equal(
      freed.length,
      [
        "impersonate",
        "open",
        "subject",
        "type",
        "level",
        "logon",
        "revert",
        "query",
      ].includes(fault)
        ? 0
        : 1,
    );
  }
  const observation = body("command_case_observe");
  const projectToken = (text) =>
    text
      .replace("DWORD *container=", "const container=")
      .replaceAll("*container", "container.value")
      .replace("TOKEN_GROUPS *restricted=", "const restricted=")
      .replace("TOKEN_STATISTICS *stats=", "const stats=")
      .replace(
        "struct command_token_observation value={0}; BYTE bytes[4096]={0};",
        "const value={hash:{}},bytes=Buffer.alloc(4096);",
      )
      .replace(
        "struct command_token_observation value=command_token_observe(token);",
        "const value=command_token_observe(token);",
      )
      .replaceAll("->", ".")
      .replace(
        "value.authentication=stats.AuthenticationId",
        "value.authentication={...stats.AuthenticationId}",
      )
      .replaceAll("bytes+used", "bytes.subarray(used)")
      .replaceAll("&attributes", "attributeBytes(attributes)")
      .replaceAll("&value", "value")
      .replaceAll("sizeof(bytes)", "4096")
      .replaceAll("(DWORD)", "")
      .replace(/\b(?:DWORD|unsigned|PSID) /gu, "let ");
  const tokenProgram = new Script(
    [
      ["command_token_observe", "token"],
      ["command_token_write", "value"],
      ["command_token_read", "token"],
    ]
      .map(
        ([name, args]) =>
          `function ${name}(${args}){${projectToken(body(name))}}`,
      )
      .join("\n") +
      "\n({observe:command_token_observe,write:command_token_write,read:command_token_read})",
  );
  for (const cached of [false, true]) {
    let output = "",
      queries = 0,
      queryAllowed = true;
    const sid = Buffer.alloc(16, 1),
      container = { value: 0 },
      restricted = { GroupCount: 1, Groups: [{ Sid: sid, Attributes: 4 }] },
      stats = { AuthenticationId: { HighPart: 1, LowPart: 2 } },
      freed = [];
    const attributeBytes = (value) => {
      const bytes = Buffer.alloc(4);
      bytes.writeUInt32LE(value);
      return bytes;
    };
    const run = tokenProgram.runInNewContext({
      Buffer,
      TokenIsAppContainer: 1,
      TokenRestrictedSids: 2,
      TokenStatistics: 3,
      need: assert.ok,
      attributeBytes,
      info(token, kind) {
        assert.equal(token, 19);
        assert.equal(queryAllowed, true);
        queries++;
        return [null, container, restricted, stats][kind];
      },
      IsValidSid: () => true,
      GetLengthSid: (value) => value.length,
      memcpy: (target, source, size) => source.copy(target, 0, 0, size),
      command_sum: (bytes, size, out) => {
        out.text = sha(bytes.subarray(0, size));
      },
      IsTokenRestricted(token) {
        assert.equal(token, 19);
        assert.equal(queryAllowed, true);
        queries++;
        return true;
      },
      command_integrity(token) {
        assert.equal(token, 19);
        assert.equal(queryAllowed, true);
        queries++;
        return 8192;
      },
      free(value) {
        freed.push(value);
        if (value === stats) stats.AuthenticationId.LowPart = 0;
      },
      printf(format, ...args) {
        let i = 0;
        output += format.replace(/%(?:08lx|lu|s)/gu, (match) => {
          const value = args[i++];
          return match === "%08lx"
            ? value.toString(16).padStart(8, "0")
            : String(value?.text ?? value);
        });
      },
    });
    if (cached) {
      const value = run.observe(19);
      assert.equal(output, "");
      queryAllowed = false;
      run.write(value);
    } else run.read(19);
    assert.equal(queries, 5);
    assert.deepEqual(freed, [container, restricted, stats]);
    assert.equal(
      output,
      JSON.stringify({
        appContainer: false,
        restricted: true,
        restrictingSids: 1,
        restrictedSidsSha256: sha(Buffer.concat([attributeBytes(4), sid])),
        integrity: 8192,
        authenticationId: "00000001:00000002",
      }),
    );
  }
  assert.ok(observation.includes("command_case_auditing()"));
  for (const [operation, domain, value] of [
    ["command-client-impersonate", "win32", 5],
    ["command-client-token", "win32", 5],
    ["command-client-context", "invariant", 0],
  ]) {
    assert.deepEqual(
      windowsFeasibilityDiagnostics(
        `native-windows: operation=${operation} domain=${domain} value=${value}\n`,
      ).failure,
      { operation, domain, value },
    );
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
      let phase, controlStderr = null, controlStderrInvalid = false, controlError, controlExitCode;
      ${source.slice(source.indexOf("const controlFailure = () =>"), source.indexOf("const fail = (error) =>"))}
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
        Buffer,
        windowsFeasibilityCause,
        windowsFeasibilityDiagnostics,
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
          settlementDiagnostic: () => {},
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
  for (const missing of [
    null,
    "command_client",
    "command_case_finished",
    "command_target_seen",
    "command_marker_seen",
  ]) {
    const api = {
      command_client: 73,
      command_case_finished: true,
      command_target_seen: true,
      command_marker_seen: true,
    };
    if (missing) api[missing] = false;
    assert.equal(!!check("U", api), !missing);
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
    body = /static ULONGLONG command_event_time\([^\n]+\) \{([\s\S]*?)\n\}/u
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
    timestamp = new Script(
      `(text) => {const ticks=(() => {${body}})();return ticks>command_retirement_from;}`,
    ).runInNewContext({
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
  const wrapper =
    /static HANDLE command_case_open\(const WCHAR \*path,DWORD access,unsigned object\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(wrapper);
  const opened = /CreateFileW\(path,access,([^,]+),/u.exec(wrapper);
  assert.ok(opened);
  assert.match(opened[1], /\bFILE_SHARE_DELETE\b/u);
  for (const [argument, object] of [
    [3, 0],
    [6, 1],
  ]) {
    const call = new RegExp(
      `command_case_open\\(argv\\[${argument}\\],([^,]+),${object}\\)`,
      "u",
    ).exec(source);
    assert.ok(call);
    assert.doesNotMatch(call[1], /\bDELETE\b/u);
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
    function command_interface(value, operation) {${body("command_interface")}}
    function command_protection_close() {${body("command_protection_close")}}
    function command_broker_events_close() {${body("command_broker_events_close")}}
    function command_preflight_close(keepBroker) {${body("command_preflight_close").split("if (!command_preflight_owned.active) return ok;")[0]} return ok;}
    function command_protection_read(h, mask, operation) {${body("command_protection_read")}}
    function command_protection_owner(sd, operation) {${body("command_protection_owner")}}
    function command_protection_verify(sd, owner, process, allAccess, operation) {${body("command_protection_verify")}}
    function command_protection_descriptor(process) {${body("command_protection_descriptor")}}
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
  const run = (
    allAccess,
    operation,
    {
      fault,
      mapped = false,
      readError = 5,
      apiError,
      mask,
      creation = false,
      expected,
    } = {},
  ) => {
    const [ownerStage, ownerFault] =
      fault === "owner" ? ["readback", "unequal"] : (fault?.split(":") ?? []);
    const owner = "S-1-5-21-4-5-6-1002",
      userSid = "S-1-5-21-1-2-3-1001",
      administrators = "S-1-5-32-544",
      process = operation === "command-protect-process",
      grantee = process ? administrators : userSid,
      high = "S-1-16-12288";
    const freed = [],
      records = [],
      reads = [],
      calls = [];
    const nativeError = apiError ?? (fault === "descriptor" ? 8 : 1350);
    let lastError = nativeError,
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
      dacl: acl(0, grant, grantee),
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
    if (fault === "grant") readback.dacl.ace.Mask = mask ?? allAccess ^ 1;
    if (fault === "grantee")
      readback.dacl.ace.SidStart = process ? userSid : administrators;
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
      WinBuiltinAdministratorsSid: administrators,
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
      GetSecurityDescriptorControl: (sd, out) =>
        !(sd === readback && fault === "control-query") &&
        output(out, sd.control),
      GetSecurityDescriptorDacl: (sd, present, out) =>
        !(sd === readback && fault === "dacl-query") &&
        output(present, true) &&
        output(out, sd.dacl),
      GetSecurityDescriptorSacl: (sd, present, out) =>
        !(sd === readback && fault === "sacl-query") &&
        output(present, true) &&
        output(out, sd.sacl),
      GetAce: (acl, index, out) => {
        assert.equal(index, 0);
        if (
          (acl === readback.dacl && fault === "dacl-ace") ||
          (acl === readback.sacl && fault === "sacl-ace")
        )
          return false;
        return output(out, acl.ace);
      },
      swprintf_s: (text, capacity, format, owner, principal) => {
        assert.equal(capacity, 512);
        assert.equal(format, "O:%lsD:P(A;;GA;;;%ls)S:(ML;;NWNR;;;HI)");
        text[0] = format.replace("%ls", owner).replace("%ls", principal);
        return text[0].length;
      },
      ConvertStringSecurityDescriptorToSecurityDescriptorW: (
        text,
        revision,
        out,
      ) => {
        assert.equal(revision, 1);
        assert.equal(
          text[0],
          `O:${userSid}D:P(A;;GA;;;${grantee})S:(ML;;NWNR;;;HI)`,
        );
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
            lastError = apiError ?? 5;
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
          if (fault === `${handle}-read` && count === 0) return readError;
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
          lastError = apiError ?? 1350;
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
        const primaryError = expected[2];
        assert.equal(
          outcome,
          [50, 120, 1314].includes(primaryError) ? 78 : 126,
        );
        assert.deepEqual(records[0], expected);
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
        [50, 120, 1314].includes(readFailed ? readError : nativeError)
          ? 78
          : 126,
      );
      if (setterFailed)
        assert.deepEqual(records[0], [operation, "win32", nativeError]);
      else if (fault === "descriptor")
        assert.deepEqual(records[0], [
          "command-protect-descriptor",
          "win32",
          nativeError,
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
              ? nativeError
              : ["absent", "invalid", "unequal"].indexOf(ownerFault) + 1,
        ]);
        assert.equal(errorReads, queryFailed ? 1 : 0);
      }
      if (/^(control|dacl|sacl)-(query|ace)$/u.test(fault)) {
        assert.deepEqual(records[0], [
          `command-protect-${fault.split("-")[0]}`,
          "win32",
          nativeError,
        ]);
        assert.equal(errorReads, 1);
      }
      if (fault === "set" || fault === "descriptor")
        assert.equal(errorReads, 1);
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
    run(grant, `command-protect-${operation}`, { mapped: true });
    run(grant, `command-protect-${operation}`, { fault: "set" });
    run(grant, `command-protect-${operation}`, { fault: "grantee" });
    if (operation !== "process")
      run(grant, `command-protect-${operation}`, {
        fault: "grant",
        mask: 0x1fffff,
      });
    for (const stage of ["baseline", "input", "readback"]) {
      for (const fault of ["query", "absent", "invalid", "unequal", "read"]) {
        if (
          (stage === "baseline" && fault === "unequal") ||
          (stage === "input" && fault === "read")
        )
          continue;
        run(grant, `command-protect-${operation}`, {
          fault: `${stage}:${fault}`,
        });
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
  for (const error of [50, 120, 1314]) {
    for (const fault of ["baseline:read", "readback:read"])
      run(0x1fffff, "command-protect-process", { fault, readError: error });
    for (const fault of [
      "descriptor",
      "set",
      "set-cleanup",
      "baseline:query",
      "input:query",
      "readback:query",
      "control-query",
      "dacl-query",
      "dacl-ace",
      "sacl-query",
      "sacl-ace",
    ])
      run(0x1fffff, "command-protect-process", { fault, apiError: error });
  }
  for (const mask of [0x1f003f, 0x1f0003, 0x10000001])
    run(0x1fffff, "command-protect-process", { fault: "grant", mask });
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
    "extra-ace",
    "control",
    "label",
    "integrity",
    "read",
    "cleanup",
    "set-cleanup",
    "control-query",
    "dacl-query",
    "dacl-ace",
    "sacl-query",
    "sacl-ace",
  ])
    run(0x1fffff, "command-protect-process", { fault });
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
    run(0x1f0003, "command-protect-intent-event", {
      creation: true,
      fault,
      expected,
    });
  for (const error of [50, 120, 1314]) {
    for (const [fault, operation] of [
      ["descriptor", "command-protect-descriptor"],
      ["create-intent", "command-intent-event"],
      ["create-closed", "command-closed-event"],
      ["intent-read", "command-protect-intent-event-readback-owner"],
      ["intent-set", "command-protect-intent-event"],
    ])
      run(0x1f0003, "command-protect-intent-event", {
        creation: true,
        fault,
        apiError: error,
        readError: error,
        expected: [operation, "win32", error],
      });
  }
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
  // Nested experiment guards do not close the outer XML-only boundary.
  let depth = 0,
    guardEnd = -1;
  for (const directive of sources[1].matchAll(
    /^#(if|ifdef|ifndef|endif)\b/gmu,
  )) {
    depth += directive[1] === "endif" ? -1 : 1;
    if (depth === 0) {
      guardEnd = directive.index;
      break;
    }
  }
  assert.ok(
    sources[1].indexOf("static BOOL audit_principal_exists(") < guardEnd,
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

test("actual command-case guards attribute native calls and control invariants without changing successful controls", async () => {
  const [source, helper] = await Promise.all(
    ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(`../ci/native/win32/${name}`, import.meta.url), "utf8"),
    ),
  );
  const body = (text, name) => {
    const match = new RegExp(
      `static [^\\n]+ ${name}\\([^\\n]*\\) \\{`,
      "u",
    ).exec(text);
    assert.ok(match, name);
    const start = match.index + match[0].length;
    let depth = 1;
    for (let i = start; i < text.length; i++) {
      if (text[i] === "{") depth++;
      if (text[i] === "}" && !--depth) return text.slice(start, i);
    }
    assert.fail(`Unclosed native function: ${name}`);
  };
  // Keep the actual control flow and API-specific checks; project C buffers,
  // output pointers and local declarations only. No native tool runs here.
  const project = (text) =>
    text
      .replace(
        "DWORD rights[2]={PROCESS_DUP_HANDLE,PROCESS_TERMINATE};",
        "const rights=[PROCESS_DUP_HANDLE,PROCESS_TERMINATE];",
      )
      .replace(
        /char (nonceBytes|bytes)\[(\d+)\](?:=\{0\})?;/gu,
        (_, name, size) => `const ${name}=Buffer.alloc(${size});`,
      )
      .replace("char ackValue;", "let ackValue;")
      .replace("const char *operation=", "const operation=")
      .replaceAll("&count", "{set value(v){count=v}}")
      .replaceAll("&ackValue", "{set value(v){ackValue=v}}")
      .replace(/\((?:DWORD|LONGLONG|ULONGLONG)\)/gu, "")
      .replace(
        "FILETIME born={0},exited,kernel,user;FILE_ID_INFO id={0};",
        "const born={dwHighDateTime:0,dwLowDateTime:0},exited={},kernel={},user={},id={FileId:{Identifier:Array(16).fill(0)}};",
      )
      .replace(
        "FILETIME sampled={0};",
        "const sampled={dwHighDateTime:0,dwLowDateTime:0};",
      )
      .replace(
        "struct command_open_context before,after;",
        "const before={},after={};",
      )
      .replace(
        "FILETIME from={0},to={0};",
        "const from={dwHighDateTime:0,dwLowDateTime:0},to={dwHighDateTime:0,dwLowDateTime:0};",
      )
      .replaceAll("sizeof(LUID)", "8")
      .replace(/(?<!&)&(before|after|from|to)\b/gu, "$1")
      .replace(
        /&command_operating_(bytes|incomplete)/gu,
        '"command_operating_$1"',
      )
      .replaceAll("sizeof(id)", "24")
      .replace(/&(born|exited|kernel|user|id|sampled)\b/gu, "$1")
      .replace(/\bL(?=")/gu, "")
      .replace(/\b(?:HANDLE|BOOL|DWORD|LONGLONG|int|unsigned) /gu, "let ");
  const program = new Script(`
    function invariant_value(ok,operation,value){${project(body(helper, "invariant_value"))}}
    function invariant(ok,operation){${body(helper, "invariant")}}
    function win32_check(ok,operation){${project(body(helper, "win32_check"))}}
    function close_handle(handle,operation){${project(body(helper, "close_handle"))}}
    function command_case_io(ok,operation,object,count,file){${project(body(source, "command_case_io"))}}
    function command_case_open(path,access,object){${project(body(source, "command_case_open"))}}
    (function(argc,argv){${project(body(source, "command_case"))}})`);
  const cases = [
    ["arguments", "edit", "invariant"],
    ["nonce", "edit", "invariant"],
    ["nonce-size", "edit", "invariant"],
    ["ready-write-size", "edit", "invariant"],
    ["ready-read-size", "edit", "invariant"],
    ["ready-ack", "edit", "invariant"],
    ["broker-duplicate", "edit", "invariant"],
    ["broker-terminate", "edit", "invariant"],
    ["broker-duplicate-error", "edit", "win32"],
    ["broker-terminate-error", "edit", "win32"],
    ["broker-duplicate-close", "edit", "invariant"],
    ["broker-terminate-close", "edit", "invariant"],
    ["target-read-size", "inspect", "invariant"],
    ["target-nonce", "inspect", "invariant"],
    ["target-write-size", "edit", "invariant"],
    ["edit-size", "edit", "invariant"],
    ["target-denial", "outside", "win32"],
    ["output", "edit", "invariant"],
    ["marker-size", "edit", "invariant"],
    ["marker-nonce", "edit", "invariant"],
    ["finish-write-size", "edit", "invariant"],
    ["finish-read-size", "edit", "invariant"],
    ["finish-ack", "edit", "invariant"],
    ...[
      "pipe-open",
      "nonce-encode",
      "ready-write",
      "ready-read",
      "target-write",
      "edit-write",
      "target-truncate",
      "target-flush",
      "target-close",
      "marker-open",
      "marker-read",
      "marker-close",
      "finish-write",
      "finish-read",
      "pipe-close",
    ].map((fault) => [fault, "edit", "win32"]),
    ["target-open", "inspect", "win32"],
    ["target-read", "inspect", "win32"],
  ];
  for (const [
    fault,
    mode,
    domain,
    markerCloseFails,
    diagnosticFault,
    permitted,
  ] of [
    [null, "inspect"],
    [null, "edit"],
    [null, "outside"],
    [null, "outside", null, false, null, true],
    [null, "outside", null, false, "birth", true],
    [null, "outside", null, false, "file-id", true],
    ...cases,
    ["marker-read", "edit", "win32", true],
    ["marker-size", "edit", "invariant", true],
    ["marker-nonce", "edit", "invariant", true],
  ]) {
    let first,
      lastError = 0,
      pipeWrites = 0,
      pipeReads = 0;
    const calls = [],
      cleanup = [],
      output = [],
      io = [],
      brokerRights = [],
      nonce = "a".repeat(32);
    const call = (operation, value = true) => {
      calls.push(operation);
      lastError = 5;
      return fault === operation ? false : value;
    };
    const api = {
      Buffer,
      NULL: null,
      TRUE: true,
      FALSE: false,
      stdout: {},
      INVALID_HANDLE_VALUE: -1,
      GENERIC_READ: 0x80000000,
      GENERIC_WRITE: 0x40000000,
      FILE_SHARE_READ: 1,
      FILE_SHARE_WRITE: 2,
      FILE_SHARE_DELETE: 4,
      OPEN_EXISTING: 3,
      FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
      SECURITY_SQOS_PRESENT: 0x100000,
      SECURITY_CONTEXT_TRACKING: 0x40000,
      SECURITY_IMPERSONATION: 0x20000,
      PROCESS_DUP_HANDLE: 64,
      PROCESS_TERMINATE: 1,
      ERROR_ACCESS_DENIED: 5,
      ERROR_SUCCESS: 0,
      FileIdInfo: 18,
      stderr: {},
      command_context_capture: (value) => {
        value.statsRead = false;
      },
      command_context_write: () => {},
      command_operating_incomplete: false,
      command_operating_bytes: 0,
      diagnostic_write: () => {},
      errno: 0,
      GetCurrentProcess: () => "self",
      GetCurrentProcessId: () => 43,
      GetSystemTimePreciseAsFileTime: (time) => {
        time.dwLowDateTime = 200 + io.length;
      },
      GetProcessTimes(process, born) {
        assert.equal(process, "self");
        lastError = 50;
        if (diagnosticFault === "birth") return false;
        born.dwLowDateTime = 100;
        return true;
      },
      GetFileInformationByHandleEx(file, kind, id, size) {
        assert.ok(["target", "marker"].includes(file));
        assert.deepEqual([kind, size], [18, 24]);
        lastError = 50;
        id.VolumeSerialNumber = 7;
        id.FileId.Identifier.fill(1);
        return diagnosticFault !== "file-id";
      },
      fprintf(_stream, format, ...args) {
        if (format.startsWith("native-windows-command: io")) io.push(args);
        lastError = 92;
      },
      fputs: () => {},
      fputc: () => {},
      CP_UTF8: 65001,
      WC_ERR_INVALID_CHARS: 128,
      wcslen: (value) => value.length,
      wcscmp: (a, b) => Number(a !== b),
      number: Number,
      GetLastError: () => lastError,
      SetLastError: (value) => {
        lastError = value;
      },
      remember: (...value) => {
        first ??= value;
      },
      cleanup_error: (...value) => cleanup.push(value),
      failure: (code) => {
        lastError = 999;
        throw Object.assign(new Error("Native control refusal"), { code });
      },
      CreateFileW(name, access, sharing, _security, creation, flags) {
        const operation = name === "pipe" ? "pipe-open" : `${name}-open`;
        assert.equal(creation, 3);
        if (name === "target") {
          assert.equal(sharing, 7);
          assert.equal(flags, 0x200000);
        }
        if (name === "marker") assert.equal(flags, 0x200000);
        if (name === "pipe") assert.equal(flags, 0x160000);
        if (!call(operation)) return -1;
        if (name === "target" && mode === "outside" && !permitted) {
          lastError = fault === "target-denial" ? 87 : 5;
          return -1;
        }
        return name;
      },
      WideCharToMultiByte(_page, _flags, value, _length, target) {
        target.write(value);
        return !call("nonce-encode") ? 0 : fault === "nonce-size" ? 32 : 33;
      },
      WriteFile(handle, value, size, count) {
        const operation =
          handle === "pipe"
            ? ++pipeWrites === 1
              ? "ready-write"
              : "finish-write"
            : typeof value === "string"
              ? "edit-write"
              : "target-write";
        count.value =
          fault ===
          (operation === "edit-write" ? "edit-size" : `${operation}-size`)
            ? size - 1
            : size;
        return call(operation);
      },
      ReadFile(handle, target, size, count) {
        const operation =
          handle === "pipe"
            ? ++pipeReads === 1
              ? "ready-read"
              : "finish-read"
            : `${handle}-read`;
        count.value =
          fault ===
          (operation === "marker-read" ? "marker-size" : `${operation}-size`)
            ? size - 1
            : size;
        if (handle === "pipe")
          target.value =
            fault === (pipeReads === 1 ? "ready-ack" : "finish-ack")
              ? "!"
              : pipeReads === 1
                ? "R"
                : "F";
        else {
          target.write(nonce);
          if (fault === "target-nonce" && handle === "target") target[0]++;
          if (fault === "marker-nonce" && handle === "marker") target[0]++;
        }
        return call(operation);
      },
      OpenProcess(right, inherit, pid) {
        assert.equal(inherit, false);
        assert.equal(pid, 99);
        brokerRights.push(right);
        const operation =
          right === 64 ? "broker-duplicate" : "broker-terminate";
        call(operation);
        lastError = fault === `${operation}-error` ? 87 : 5;
        return fault === operation || fault === `${operation}-close`
          ? "unexpected-authority"
          : null;
      },
      CloseHandle(handle) {
        if (handle === "marker" && markerCloseFails) {
          call("marker-close");
          return false;
        }
        if (handle !== "unexpected-authority") return call(`${handle}-close`);
        lastError = 6;
        return !fault?.endsWith("-close");
      },
      SetEndOfFile: () => call("target-truncate"),
      FlushFileBuffers: () => call("target-flush"),
      memcmp: (a, b, size) =>
        Buffer.compare(a.subarray(0, size), b.subarray(0, size)),
      printf: (format, value) =>
        output.push(
          format === "%s" ? value.subarray(0, 32).toString() : format,
        ),
      fflush: () => (fault === "output" ? 1 : 0),
    };
    const run = () =>
      program.runInNewContext(api)(fault === "arguments" ? 7 : 8, [
        "helper",
        "command-case",
        "pipe",
        "target",
        mode,
        fault === "nonce" ? "short" : nonce,
        "marker",
        "99",
      ]);
    if (!fault) {
      run();
      assert.deepEqual(brokerRights, [64, 1]);
      assert.equal(first, undefined);
      assert.deepEqual(output, [
        mode === "inspect"
          ? nonce
          : mode === "outside" && !permitted
            ? "attempt:denied"
            : "attempt:written",
      ]);
      assert.equal(io[0][0], 43);
      assert.equal(io[0][1], diagnosticFault === "birth" ? 0 : 100);
      assert.equal(io[0][2], diagnosticFault === "birth" ? 50 : 0);
      assert.equal(io[0][9], 200);
      assert.equal(
        io[0][8],
        mode === "outside" && !permitted
          ? -1
          : diagnosticFault === "file-id"
            ? 50
            : 0,
      );
      if (permitted)
        assert.deepEqual(
          io.map((row) => [row[3], row[4], row[5], row[6], row[7]]),
          [
            [0, "open", true, 0, 0],
            [0, "write", true, 0, 32],
            [0, "edit", true, 0, 7],
            [0, "truncate", true, 0, 0],
            [0, "flush", true, 0, 0],
            [0, "close", true, 0, 0],
            [1, "open", true, 0, 0],
            [1, "read", true, 0, 32],
            [1, "close", true, 0, 0],
          ],
        );
      continue;
    }
    assert.throws(run, { code: 126 });
    for (const row of io.filter((row) => !row[5])) {
      assert.equal(row[6], fault === "target-denial" ? 87 : 5);
      assert.equal(row[7], -1);
    }
    const broker = fault.startsWith("broker-");
    const operation = `command-case-${fault === "target-denial" ? "target-open" : fault.replace(/-(error|close)$/u, (match) => (fault.startsWith("broker-") ? "" : match))}`;
    assert.deepEqual(first, [
      operation,
      domain,
      fault === "target-denial" || fault.endsWith("-error")
        ? 87
        : domain === "win32"
          ? 5
          : 0,
    ]);
    const carrier = `native-windows: operation=${first[0]} domain=${first[1]} value=${first[2]}\n`;
    assert.ok(windowsFeasibilityDiagnostics(carrier), fault);
    assert.equal(
      windowsFeasibilityDiagnostics(
        carrier
          .replace(
            `domain=${domain}`,
            `domain=${broker ? "hresult" : domain === "win32" ? "invariant" : "win32"}`,
          )
          .replace(/value=\d+/u, broker ? "value=2147500037" : "value=5"),
      ),
      null,
      fault,
    );
    assert.deepEqual(
      cleanup,
      broker && fault.endsWith("-close")
        ? [["process-close", "win32", 6]]
        : markerCloseFails || fault === "marker-close"
          ? [["command-case-marker-close", "win32", 5]]
          : [],
    );
    if (cleanup.length) {
      const [operation, domain, value] = cleanup[0],
        diagnosis = windowsFeasibilityDiagnostics(
          carrier +
            `native-windows-cleanup: operation=${operation} domain=${domain} value=${value}\n`,
        );
      assert.deepEqual(diagnosis?.cleanup, { operation, domain, value });
      assert.equal(diagnosis.failure.operation, first[0]);
    }
    if (fault.startsWith("marker-")) {
      assert.equal(pipeWrites, 1, "Failed marker checks cannot send F");
      if (fault !== "marker-open")
        assert.equal(
          calls.filter((value) => value === "marker-close").length,
          1,
        );
    }
    if (broker) {
      assert.deepEqual(
        brokerRights,
        fault.startsWith("broker-duplicate") ? [64] : [64, 1],
      );
      assert.equal(calls.includes("target-open"), false);
    }
  }
  for (const operation of ["duplicate", "terminate"]) {
    for (const [domain, value] of [
      ["win32", 0],
      ["invariant", 1],
    ])
      assert.equal(
        windowsFeasibilityDiagnostics(
          `native-windows: operation=command-case-broker-${operation} domain=${domain} value=${value}\n`,
        ),
        null,
      );
  }
});

async function brokerCloseBoundary({ control = false, read = false } = {}) {
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
    failureStart = source.indexOf("const controlFailure = () =>"),
    failureEnd = source.indexOf("const call =", failureStart);
  assert.ok(
    start >= 0 && end > start && failureStart >= 0 && failureEnd > failureStart,
  );
  const boundary = new Script(`(() => {
    ${source.slice(source.indexOf("function commandOperatingDiagnostic"), source.indexOf("\nconst regular"))}
    let closed, failed, brokerDiagnosticFirst, brokerDiagnosticPhase, retiring = false, retirementFailure, bytes = 0, reading = Promise.resolve();
    let phase = ${JSON.stringify(control ? "permitted-control" : "broker-setup")}, failurePhase, probeOutput = "",
      controlStderr = ${control ? "Buffer.alloc(0)" : "null"}, controlStderrInvalid = false,
      controlDiagnosticFirst, controlBeforeBroker, controlExitCode, controlError;
    const pending = new Map();
    ${source.slice(failureStart, failureEnd)}
    ${source.slice(start, end)}
    ${read ? source.slice(end, source.indexOf("reading.catch(fail);", end) + "reading.catch(fail);".length) : ""}
    const effects = {${source.slice(source.indexOf("retainFailure: fail,"), source.indexOf("prepare(nonce, components, signal)"))}};
    return { closed, pending, outcome: ready.catch(error => error), failure: () => failed,
      retainFailure: effects.retainFailure, collectFailure: effects.failure,
      controlFailure, output: () => probeOutput, reading: () => reading, setPhase: value => {phase=value;} };
  })()`);
  return () => {
    const broker = new EventEmitter(),
      diagnosticEvents = new EventEmitter(),
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
      createInterface,
      need: assert.ok,
      setupVerified: true,
      nativeDiagnostic: (event) => diagnosticEvents.emit(event),
      decoder: { push: async () => {} },
      nativeException: () => {},
      observeNativeProcess: (owner, child) =>
        child.stderr.on("data", (chunk) => raw.push(chunk)),
    });
    return { ...result, broker, rpc, errorOutput, raw, diagnosticEvents };
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

test("cached SACL diagnostics preserve silent success, strict refusal errors and bounded raw publication", async () => {
  const open = await brokerCloseBoundary();
  const refusal =
    "native-windows: operation=command-marker-barrier domain=invariant value=0\n";
  const metadata =
    `native-windows-command: operating-sacl phase=N pid=43 birth=90 logon=7 policy=3 identity=${"a".repeat(16)}:${"b".repeat(32)} hash=${PIN} count=1 truncated=0 status=0,0,0 close=0\n` +
    "native-windows-command: operating-ace object=2 index=0 status=0 type=2 flags=192 mask=3 subject-match=1\n";
  for (const fault of [
    null,
    "malformed",
    "truncated",
    "overflow",
    "orphan",
    "success",
  ]) {
    const f = open(),
      bytes = Buffer.from(
        fault === "success"
          ? ""
          : fault === "orphan"
            ? metadata
            : refusal +
              (fault === "malformed"
                ? metadata.replace("subject-match=1", "subject-match=2")
                : fault === "truncated"
                  ? metadata.slice(0, -1)
                  : fault === "overflow"
                    ? metadata.repeat(20)
                    : metadata),
      );
    for (let at = 0; at < bytes.length; at += 7)
      f.broker.stderr.write(bytes.subarray(at, at + 7));
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end();
    await ended;
    f.broker.emit(
      "close",
      ["success", "orphan"].includes(fault) ? 0 : 126,
      null,
    );
    const error = await f.outcome;
    assert.deepEqual(Buffer.concat(f.raw), bytes);
    if (fault === "success") {
      assert.equal(f.failure(), undefined);
      continue;
    }
    assert.equal(
      error.nativeDiagnosticInvalid,
      ![null, "overflow"].includes(fault),
      fault,
    );
    if (!fault || fault === "overflow") {
      assert.equal(error.stderr.toString(), refusal);
      assert.match(error.feasibilityCause.detail, /command-marker-barrier/u);
      assert.equal(error.operatingObservationIncomplete, fault === "overflow");
    } else assert.equal(f.failure(), error);
  }
});

test("audit rows share the operating allowance without exhausting the original failure or cleanup carrier", async () => {
  const open = await brokerCloseBoundary();
  const refusal =
    "native-windows: operation=command-marker-barrier domain=invariant value=0\n";
  const cleanup =
    "native-windows-cleanup: operation=command-metadata-close domain=win32 value=6\n";
  const sacl = `native-windows-command: operating-sacl phase=N pid=43 birth=90 logon=7 policy=3 identity=${"a".repeat(16)}:${"b".repeat(32)} hash=${PIN} count=0 truncated=0 status=0,0,0 close=0\n`;
  const header =
    "native-windows-command: operating-audit index=0 types=8,1,21,17,1,6,10,10,1,1,20,1,4 valid=8191 pid=43 logon=7 time=100 id=4663 keywords=9232379236109516800 record=12 mask=1 target=1 marker=0 excluded=1 version=0 decoder=0 eligible=0 delivered=0 order=-1\n";
  const audit =
    header +
    Array.from(
      { length: 5 },
      (_, field) =>
        `native-windows-command: operating-audit-value index=0 field=${field} bytes=128 offset=0 encoded=64 complete=0 hex=${"61".repeat(64)}\n`,
    ).join("");
  for (const invalid of ["win32 value=6", "ntstatus value=0"])
    assert.equal(
      windowsFeasibilityDiagnostics(
        refusal +
          `native-windows-cleanup: operation=hash-provider-close domain=${invalid}\n`,
      ),
      null,
    );
  for (const fault of [
    null,
    "coalesced",
    "overflow",
    "orphan",
    "malformed",
    "partial",
    "hash-close",
  ]) {
    const f = open();
    const closure =
      fault === "hash-close"
        ? "native-windows-cleanup: operation=hash-provider-close domain=ntstatus value=3221225485\n"
        : cleanup;
    const observation =
      fault === "overflow"
        ? sacl +
          audit.repeat(4) +
          "native-windows-command: operating-incomplete\n"
        : sacl + audit;
    const text =
      fault === "orphan"
        ? observation
        : refusal +
          (fault === "malformed"
            ? observation.replace("field=4", "field=5")
            : observation) +
          closure;
    const bytes = Buffer.from(
      fault === "partial" ? refusal + observation.slice(0, -1) : text,
    );
    for (
      let at = 0;
      at < bytes.length;
      at += fault === "coalesced" ? bytes.length : 13
    )
      f.broker.stderr.write(
        bytes.subarray(at, at + (fault === "coalesced" ? bytes.length : 13)),
      );
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end();
    await ended;
    f.broker.emit("close", 126, null);
    const error = await f.outcome;
    assert.deepEqual(Buffer.concat(f.raw), bytes);
    assert.equal(
      error.nativeDiagnosticInvalid,
      ["orphan", "malformed", "partial"].includes(fault),
    );
    if ([null, "coalesced", "overflow", "hash-close"].includes(fault)) {
      assert.equal(error.stderr.toString(), refusal + closure);
      assert.match(error.feasibilityCause.detail, /command-marker-barrier/u);
      assert.ok(
        error.feasibilityCleanup.detail.includes(
          fault === "hash-close"
            ? "hash-provider-close"
            : "command-metadata-close",
        ),
      );
      assert.equal(error.operatingObservationIncomplete, fault === "overflow");
    }
  }
});

test("native optional publication bounds encoded framing before writing and preserves error state", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const body = /static void diagnostic_write\([^\n]+\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("char line[2048]; va_list args;", "const line={};let args;")
    .replace("va_start(args, format)", "args=values")
    .replace("va_end(args)", "")
    .replaceAll("sizeof(line)", "2048")
    .replaceAll("line[i]", "line.text[i]")
    .replaceAll("*used", "used.value")
    .replaceAll("*incomplete", "incomplete.value")
    .replace(/\((?:DWORD|size_t|int)\)/gu, "")
    .replace(/\b(?:DWORD|int)\b/gu, "let");
  const program = new Script(
    `(output,used,incomplete,format,...values)=>{${body}}`,
  );
  for (const fault of [null, "oversized", "write"]) {
    const used = { value: 0 },
      incomplete = { value: false },
      writes = [];
    const api = {
      TRUE: true,
      errno: 7,
      GetLastError: () => 91,
      SetLastError: (v) => assert.equal(v, 91),
      vsnprintf(line, maximum, format, args) {
        assert.equal(maximum, 2048);
        let i = 0;
        line.text = format.replace(/%s/gu, () => args[i++]);
        return Buffer.byteLength(line.text);
      },
      fwrite(line, size, count, stream) {
        assert.equal(stream, "stderr");
        assert.equal(size, 1);
        assert.equal(count, Buffer.byteLength(line.text));
        writes.push(line.text.replaceAll("\n", "\r\n"));
        api.errno = 9;
        return fault === "write" ? 0 : count;
      },
    };
    const write = program.runInNewContext(api);
    const row =
      fault === "oversized"
        ? "x".repeat(2048)
        : `native-windows-command: operating-audit-value index=0 field=0 bytes=128 offset=0 encoded=64 complete=0 hex=${"61".repeat(64)}\n`;
    for (let i = 0; i < 32; i++) write("stderr", used, incomplete, "%s", row);
    assert.equal(incomplete.value, true);
    assert.equal(api.errno, 7);
    assert.ok(
      used.value +
        Buffer.byteLength("native-windows-command: operating-incomplete\n") <=
        4096,
    );
    assert.equal(
      writes.length,
      fault === "oversized"
        ? 0
        : fault === "write"
          ? 1
          : Math.floor((4096 - 128) / (row.length + 1)),
    );
    assert.equal(Buffer.byteLength(writes.join("")), used.value);
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

test("an early control exit retains complete output and its first cause while fencing the barrier", async () => {
  const open = await brokerCloseBoundary({ control: true, read: true }),
    diagnostic =
      "native-windows: operation=command-case-marker-nonce domain=invariant value=0\n";
  for (const prior of [false, true]) {
    const f = open(),
      original = new Error("Earlier capture failure"),
      rejected = [];
    f.pending.get("ready").resolve({ event: "ready" });
    f.pending.delete("ready");
    f.pending.set("B", {
      resolve: assert.fail,
      reject: (error) => rejected.push(error),
    });
    if (prior) f.retainFailure(original);
    const frames = [
      {
        event: "probe-output",
        hex: Buffer.from("attempt:written").toString("hex"),
      },
      ...[diagnostic.slice(0, 13), diagnostic.slice(13)].map((text) => ({
        event: "probe-stderr",
        hex: Buffer.from(text).toString("hex"),
      })),
      { event: "probe-exit", exitCode: 126 },
    ];
    f.broker.stdout.end(
      frames.map((frame) => JSON.stringify(frame) + "\n").join(""),
    );
    await f.reading();
    const child = f.controlFailure();
    assert.equal(child.code, 126);
    assert.deepEqual(child.stderr, Buffer.from(diagnostic));
    assert.equal(child.nativeDiagnosticInvalid, false);
    assert.equal(f.output(), "attempt:written");
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0], prior ? original : child);
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end(
      "native-windows: operation=command-case-lifetime domain=invariant value=0\n" +
        "native-windows-cleanup: operation=pipe-close domain=win32 value=6\n",
    );
    await ended;
    f.broker.emit("close", 126, null);
    const first = await f.collectFailure();
    assert.equal(first, prior ? original : child);
    assert.ok(first.feasibilityCleanup);
  }
});

test("control release requires one completed pipe drain and the matching real exit", async () => {
  const open = await brokerCloseBoundary({ control: true, read: true });
  for (const fault of [null, "missing", "repeated", "mismatch", "invalid"]) {
    const f = open(),
      rejected = [];
    let released = false;
    f.pending.get("ready").resolve({ event: "ready" });
    f.pending.delete("ready");
    f.pending.set("U", {
      resolve: () => {
        released = true;
      },
      reject: (error) => rejected.push(error),
    });
    const exit = {
        event: "probe-exit",
        exitCode: fault === "invalid" ? -1 : 0,
      },
      frames = fault === "missing" ? [] : [exit];
    if (fault === "repeated") frames.push(exit);
    frames.push({ event: "U", exitCode: fault === "mismatch" ? 126 : 0 });
    f.broker.stdout.end(
      frames.map((frame) => JSON.stringify(frame) + "\n").join(""),
    );
    await f.reading();
    assert.equal(released, !fault);
    assert.equal(rejected.length, fault ? 1 : 0);
    assert.equal(Boolean(f.failure()), Boolean(fault));
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end();
    await ended;
    f.broker.emit("close", fault ? 126 : 0, null);
    await f.closed;
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

test("fragmented control diagnostics retain the permitted-control phase and original cause through broker cleanup", async () => {
  const open = await brokerCloseBoundary({ control: true, read: true });
  for (const independent of [false, true]) {
    const f = open(),
      original = Object.assign(new Error("Control observation failed"), {
        code: 126,
      }),
      primary =
        "native-windows: operation=command-case-ready-read domain=win32 value=5\n",
      cleanup =
        "native-windows-cleanup: operation=pipe-close domain=win32 value=7\n",
      secondary =
        "native-windows: operation=command-retirement-event domain=win32 value=8\n";
    const run = fixture(({ effects }) => {
      const retire = effects.retire;
      effects.retainFailure = f.retainFailure;
      effects.failure = f.collectFailure;
      effects.control = async () => {
        const bytes = Buffer.from(primary + cleanup);
        for (const raw of [
          bytes.subarray(0, 9),
          bytes.subarray(9, 71),
          bytes.subarray(71),
        ])
          f.broker.stdout.write(
            JSON.stringify({
              event: "probe-stderr",
              hex: raw.toString("hex"),
            }) + "\n",
          );
        f.broker.stdout.end();
        await f.reading();
        assert.equal(
          f.failure(),
          undefined,
          "A child prefix is not completion or retirement",
        );
        throw original;
      };
      effects.retire = async () => {
        f.setPhase("broker-setup"); // A later owner cannot relabel the first failure.
        f.broker.stderr.write(
          secondary +
            "native-windows-cleanup: operation=file-close domain=win32 value=6\n",
        );
        const ended = once(f.broker.stderr, "end");
        f.broker.stderr.end();
        await ended;
        f.broker.emit("close", 126, null);
        if (independent) return retire();
        throw new Error("Independent retirement remains unproved");
      };
    });
    const result = await run.run(),
      first = await f.collectFailure();
    assert.notEqual(first, original);
    assert.equal(first.cause, original);
    assert.deepEqual(first.stderr, Buffer.from(primary + cleanup));
    assert.match(result.cause.detail, /permitted-control/u);
    assert.match(
      result.cause.detail,
      /command-case-ready-read failed \(win32=5\)/u,
    );
    assert.doesNotMatch(
      result.cause.detail,
      /broker-setup|retirement-event|file-close/u,
    );
    assert.match(
      first.brokerCompletion.feasibilityCause.detail,
      /permitted-control/u,
    );
    assert.match(
      first.brokerCompletion.feasibilityCause.detail,
      /command-retirement-event failed/u,
    );
    assert.match(
      first.feasibilityCleanup.detail,
      /pipe-close failed \(win32=7\)/u,
    );
    assert.equal(result.status, "FAIL");
    assert.equal(result.cleanup.status, independent ? "PASS" : "UNCERTAIN");
    if (!independent)
      assert.deepEqual(result.cleanup.cause, first.feasibilityCleanup);
    assert.deepEqual(run.deadlines, [120000, 30000]);
    assert.deepEqual(run.requests, []);
  }
});

test("control and broker carriers keep validated arrival precedence and their originating phase", async () => {
  const open = await brokerCloseBoundary({ control: true, read: true });
  for (const [
    brokerFirst,
    brokerValid,
    childValid,
    laterTransport,
    retainedControl,
  ] of [
    [false, true, true],
    [true, true, true],
    [true, false, true],
    [false, true, false],
    [true, true, true, true],
    [false, true, true, false, true],
    [true, true, true, false, true],
    [false, true, false, false, true],
  ]) {
    const f = open(),
      child =
        "native-windows: operation=command-case-ready-read domain=win32 value=5\n",
      broker =
        "native-windows: operation=command-retirement-event domain=win32 value=6\n" +
        (brokerValid ? "" : "invalid\n");
    if (brokerFirst) f.broker.stderr.write(broker);
    if (laterTransport) {
      f.setPhase("command-observation");
      f.retainFailure(
        Object.assign(new Error("Later transport failure"), { code: "EPIPE" }),
      );
    }
    if (retainedControl) f.pending.set("U", { resolve() {}, reject() {} });
    f.broker.stdout.end(
      JSON.stringify({
        event: "probe-stderr",
        hex: Buffer.from(childValid ? child : child.trimEnd()).toString("hex"),
      }) +
        "\n" +
        (retainedControl
          ? '{"event":"probe-exit","exitCode":126}\n{"event":"U","exitCode":126}\n'
          : ""),
    );
    await f.reading();
    if (!brokerFirst) f.broker.stderr.write(broker);
    const original = retainedControl ? f.controlFailure() : null;
    if (original) f.retainFailure(original);
    f.setPhase("command-close");
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end();
    await ended;
    f.broker.emit("close", 126, null);
    const error = await f.collectFailure(),
      childWins = childValid && (!brokerFirst || !brokerValid);
    assert.match(error.feasibilityCause.detail, /permitted-control/u);
    assert.ok(
      error.feasibilityCause.detail.includes(
        childWins
          ? "command-case-ready-read failed"
          : "command-retirement-event failed",
      ),
    );
    assert.equal(
      childWins
        ? error.brokerCompletion.nativeDiagnosticInvalid
        : error.controlCompletion.nativeDiagnosticInvalid,
      childWins ? !brokerValid : !childValid,
    );
    if (retainedControl) {
      assert.equal(error === original, childWins);
      const seen = new Set();
      for (let cause = error; cause; cause = cause.cause) {
        assert.ok(
          !seen.has(cause),
          "Child and broker causes must remain acyclic",
        );
        seen.add(cause);
      }
    }
  }
});

test("control carriers reject partial, malformed, oversized and incomplete transcripts without replacing earlier failures", async () => {
  const open = await brokerCloseBoundary({ control: true, read: true }),
    diagnostic =
      "native-windows: operation=command-case-target-read domain=win32 value=5\n";
  for (const [carrier, earlier, incomplete, framing] of [
    [diagnostic.trimEnd(), false, false],
    [diagnostic + "other\n", false, false],
    [diagnostic + "x".repeat(4096), false, false],
    [
      diagnostic.replace("command-case-target-read", "unknown-seam"),
      false,
      false,
    ],
    [diagnostic.replace("win32", "invariant"), false, false],
    [diagnostic, true, false],
    [diagnostic, false, true],
    [diagnostic, false, false, "hex"],
    [diagnostic, false, false, "json"],
    [diagnostic, false, false, "exit"],
  ]) {
    const f = open(),
      first = Object.assign(new Error("Original transport refusal"), {
        code: "EPIPE",
      });
    if (earlier) f.retainFailure(first);
    const parsed = incomplete
      ? once(f.diagnosticEvents, "windows-command:probe-stderr")
      : null;
    const bytes = Buffer.from(carrier);
    for (let offset = 0; offset < bytes.length; offset += 1024)
      f.broker.stdout.write(
        JSON.stringify({
          event: "probe-stderr",
          hex: bytes.subarray(offset, offset + 1024).toString("hex"),
        }) + "\n",
      );
    if (framing)
      f.broker.stdout.write(
        framing === "hex"
          ? '{"event":"probe-stderr","hex":"zz"}\n'
          : framing === "exit"
            ? '{"event":"probe-exit","exitCode":-1}\n'
            : "{\n",
      );
    if (incomplete) {
      await parsed;
      f.retainFailure(first);
      f.broker.stdout.destroy();
    } else f.broker.stdout.end();
    await f.reading();
    const retained = f.failure() ?? first;
    if (!earlier) f.retainFailure(first);
    const ended = once(f.broker.stderr, "end");
    f.broker.stderr.end();
    await ended;
    f.broker.emit("close", 126, null);
    assert.equal(await f.collectFailure(), retained);
    assert.equal(retained.controlCompletion.nativeDiagnosticInvalid, !earlier);
    assert.ok(retained.controlCompletion.stderr.length <= 4096);
    assert.equal(retained.feasibilityCause, undefined);
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
  const effectsSource = await readFile(
    new URL(
      "../ci/native/win32/feasibility-command-effects.js",
      import.meta.url,
    ),
    "utf8",
  );
  const isObservation = new Script(
    effectsSource.slice(
      effectsSource.indexOf("function commandOperatingDiagnostic"),
      effectsSource.indexOf("\nconst regular"),
    ) + "\ncommandOperatingDiagnostic",
  ).runInNewContext();
  const capture = commandCaptureFixture(await commandCaptureProgram());
  capture.api.command_observe_failure();
  const delivery =
    capture
      .output()
      .split("\n")
      .find((line) => line.startsWith("native-windows-command: delivery ")) +
    "\n";
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:void|DWORD|struct command_gate_observation) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
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
      .replace(
        "struct command_gate_observation value=command_sacl_projection(command_files[3]);",
        "const value=command_sacl_projection(command_files[3]);",
      )
      .replace(
        "struct command_gate_observation value=command_sacl_projection(command_files[indices[i]]);",
        "const value=command_sacl_projection(command_files[indices[i]]);",
      )
      .replace("LONGLONG status[9];", "const status=[];")
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
      .replace(
        "const struct command_gate_observation *value=&command_operating_observed.values[i];",
        "const value=command_operating_observed.values[i];",
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
      .replaceAll(
        /&command_operating_(bytes|incomplete)/gu,
        '"command_operating_$1"',
      )
      .replace(/\((?:DWORD|unsigned)\)/gu, "")
      .replace(
        /\b(?:DWORD|BOOL|PSECURITY_DESCRIPTOR|PACL|HANDLE|AUDIT_POLICY_INFORMATION|LPSTR|size_t|unsigned|int)\s+\*?/gu,
        "let ",
      );
  const program =
    new Script(`function command_gate_sid(sid,text){${project(body("command_gate_sid"))}}
    function command_sacl_projection(file){${project(body("command_sacl_projection"))}}
    function command_operating_sacls(indices){${project(body("command_operating_sacls"))}}
    function command_operating_sacls_write(output){${project(body("command_operating_sacls_write"))}}
    function query(api,originalError){${project(body("command_gate_audit"))}}
    function command_gate_audit_write(output){${project(body("command_gate_audit_write"))}}
    function fail(){${project(body("command_observe_failure"))}}
    ({query,write:command_gate_audit_write,fail,sample:command_operating_sacls,writeOperating:command_operating_sacls_write})`);
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
    "descriptor-close",
  ]) {
    let lastError = 5,
      output = "",
      queries = 0,
      sampling = false,
      flushed = 0;
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
      command_case_pid: 43,
      command_case_birth: 90,
      command_case_logon: 7,
      command_ids: [
        "a",
        "b",
        "a".repeat(16) + ":" + "b".repeat(32),
        "c".repeat(16) + ":" + "d".repeat(32),
      ],
      errno: 9,
      command_prerequisite_cleanup_failed: false,
      command_category: "file-system",
      command_gate_observed: { observed: false },
      command_operating_observed: {
        observed: false,
        subject: {},
        indices: [],
        hashes: [{}, {}],
        values: [],
      },
      command_operating_incomplete: false,
      command_inspection_incomplete: false,
      diagnostic_write: (stream, _used, _incomplete, format, ...args) =>
        api.fprintf(stream, format, ...args),
      command_delivery_observe: () => {},
      command_delivery_freeze: () => {},
      command_attempt_write: () => {},
      command_delivery: {
        rejected: Array(4).fill(0),
        subject: "S-1-5-21-1",
        sacls: [PIN, PIN],
        policy: 3,
      },
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
          [sampling ? file : 3, 1, 8, null, null, null, null],
        );
        assert.ok([2, 3].includes(file));
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
        assert.equal(
          sampling,
          false,
          "held SACL sampling cannot replay the operating token query after reversal",
        );
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
        return fault === "descriptor-close" && value === "descriptor"
          ? value
          : null;
      },
      AuditFree: (value) => {
        freed.push(value);
        lastError = 92;
      },
      cleanup_error: (...cause) => cleanup.push(cause),
      remember: (...cause) => remembered.push(cause),
      strlen: (value) => value.length,
      strcmp: (a, b) => Number((a?.text ?? a) !== (b?.text ?? b)),
      memcpy: (target, value) => {
        if (Array.isArray(target)) target.splice(0, target.length, ...value);
        else {
          target.text = typeof value === "string" ? value : value.text;
          target[0] = target.text[0];
        }
      },
      fprintf(stream, format, ...args) {
        let i = 0;
        output += format.replace(/%(?:08)?(?:ll|l)?[usdx]/gu, (match) => {
          const value = args[i++];
          return match.endsWith("x")
            ? value.toString(16).padStart(8, "0")
            : String(
                typeof value === "boolean"
                  ? Number(value)
                  : (value?.text ?? value),
              );
        });
        lastError = 90;
      },
      fputs: (text) => {
        output += text;
      },
      fputc: (char) => {
        output += char;
      },
      fflush: () => {
        flushed = output.length;
      },
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
    output += delivery;
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
    output = "";
    sampling = true;
    lastError = 5;
    api.errno = 9;
    run.sample([2, 3]);
    assert.equal(queries, 3);
    assert.equal(lastError, 5);
    assert.equal(api.errno, 9);
    assert.equal(
      output,
      "",
      "successful sampling preserves silent broker stderr",
    );
    run.sample([2, 3]);
    assert.equal(queries, 3);
    api.command_delivery.subject = "S-1-5-21-2";
    api.command_delivery.policy = 0;
    api.command_case_logon = 8;
    run.writeOperating(api.stderr);
    assert.equal(output.split("operating-sacl phase=N").length - 1, 2);
    assert.ok(
      output.includes(
        `pid=43 birth=90 logon=7 policy=3 identity=${api.command_ids[2]} hash=${PIN}`,
      ),
    );
    assert.ok(Buffer.byteLength(output) < 4096);
    for (const line of output.trimEnd().split("\n"))
      assert.equal(isObservation(Buffer.from(line + "\n")), true);
    if (fault === "descriptor-close") assert.match(output, /close=91/u);
    if (!fault) assert.equal(output.split("subject-match=1").length - 1, 2);
    if (fault === "unsupported") assert.match(output, /subject-match=-1/u);
    const first = output;
    run.sample([2, 3]);
    assert.equal(output, first);
    assert.equal(queries, 3);
    const blocked = {};
    output = "";
    flushed = 0;
    api.command_observed.audit[0] = 5;
    for (const name of "subscription_flags subscription_query capture_wait capture_wait_error next_error scanned scanned_bytes records bytes action target_seen marker_seen case_finished setup_verified control control_completed control_verified closing retirement_seen".split(
      " ",
    ))
      api["command_" + name] = 0;
    api.command_delivery_observe = () => {
      assert.match(output, /operating-sacl phase=N/u);
      assert.equal(
        flushed,
        output.length,
        "cached observations flush before post-refusal queries",
      );
      throw blocked;
    };
    assert.throws(
      () => run.fail(),
      (error) => error === blocked,
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
      command_delivery_observe: () => {},
      command_delivery_freeze: () => {},
      command_attempt_write: () => {},
      command_delivery: { rejected: Array(4).fill(0) },
      command_gate_audit_write: () => {},
      command_operating_sacls_write: () => {},
      command_operating_incomplete: false,
      command_inspection_incomplete: false,
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
      `static (?:void|BOOL|DWORD) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
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
      .replace(
        /&(command_operating_bytes|command_operating_incomplete)\b/gu,
        'ref(globals,"$1")',
      )
      .replaceAll("&diagnosisLock", "diagnosisLock")
      .replace(/,&(count|length|counted)\b/gu, ",value=>$1=value");
  const progress = (text) =>
    text
      .replace(/&(command_output|command_error)\b/gu, 'ref(globals,"$1")')
      .replace(/,&code\b/gu, ",value=>code=value");
  const preflight = body(source, "command_preflight_close").split(
    "if (!command_preflight_owned.active) return ok;",
  )[0];
  const barrier = progress(
    source
      .slice(
        source.indexOf("static void command_barrier(void)"),
        source.indexOf(
          "static void command_pump(",
          source.indexOf("static void command_barrier(void)"),
        ),
      )
      .replace(
        "static void command_barrier(void)",
        "function command_barrier()",
      )
      .replace("ULONGLONG wait", "let wait")
      .replace("FILETIME ft;", "const ft={};")
      .replace(
        "ULARGE_INTEGER time;",
        "const time={get QuadPart(){return this.LowPart+this.HighPart*0x100000000;}};",
      )
      .replaceAll("&ft", "ft"),
  );
  const dispatch = new Script(`
    function close_handle(handle,operation) {${translate(body(helper, "close_handle"))}}
    function release_handle(slot,operation) {${translate(body(helper, "release_handle"))}}
    function command_event_close(slot) {${translate(body(source, "command_event_close"))}}
    function command_capture_close() {${translate(body(source, "command_capture_close"))}}
    function command_preflight_close(keepBroker) {${translate(preflight)} return ok;}
    function command_capture(timeout) {${translate(capture)}}
    function command_control_output() {${progress(translate(body(source, "command_control_output")))}}
    function command_control_exit(child) {${progress(translate(body(source, "command_control_exit")))}}
    function command_case_live() {${progress(translate(body(source, "command_case_live")))}}
    function command_stop_requested() {${translate(
      body(source, "command_stop_requested"),
    )
      .replace("char request[2];", "const request=[];")
      .replaceAll("sizeof(request)", "2")
      .replace(/,&(available|copied|count)\b/gu, ",value=>$1=value")}}
    function command_attempt_write(output) {${translate(body(source, "command_attempt_write"))}}
    function command_observe_failure() {${translate(body(source, "command_observe_failure")).replaceAll("&diagnosticOutputLock", "diagnosticOutputLock")}}
    function command_audit_query(query,interval) {${body(source, "command_audit_query").replace(/\bL(?=")/gu, "")}}
    ${barrier}
  `);
  const creations = source.match(
    /command_(?:preflight_owned\.event|event)=CreateEventW\([^;]+\);/gu,
  );
  assert.equal(creations.length, 2);
  const setup = source.match(
      /command_event=CreateEventW[^\n]+win32_check\(command_bookmark!=NULL,"command-bookmark"\);/u,
    )[0],
    subscribe = source
      .match(
        /command_subscription=EvtSubscribe[^\n]+win32_check\(command_subscription!=NULL,"command-subscription-create"\);/u,
      )[0]
      .replace(/\bDWORD\b/gu, "let"),
    ready = source.match(
      /invariant\(!ferror\(stdout\),"command-ready-output"\);command_capture\(0\);/u,
    )[0];
  const selectionBody =
      /\n  (BOOL selected=[\s\S]*?)\n  if\(selected\)\{/u.exec(source)[1],
    caseBody =
      /static void command_case_event\([\s\S]*?\) \{([\s\S]*?)\n\}/u.exec(
        source,
      )[1];
  return {
    dispatch,
    setup: new Script(setup),
    subscribe: new Script(subscribe),
    arm: new Script(setup + subscribe + ready),
    subscriptionFlags: new Script(
      `command_subscription_flags=${/static const DWORD command_subscription_flags = ([^;]+);/u.exec(source)[1]};`,
    ),
    createEvents: new Script(creations.join("\n")),
    source,
    selection: new Script(
      `(() => {${selectionBody.replace(/\bL(?=")/gu, "").replace(/\b(?:BOOL|unsigned)\b/gu, "let")} return selected;})()`,
    ),
    caseProjection: new Script(
      `(function(process,object,eventId,mask,stamp,subject,logon,keywords,record){${caseBody
        .replace(/\bL(?=")/gu, "")
        .replace(/\b(?:ULONGLONG|BOOL)\b/gu, "let")
        .replace(/\b(0x[a-fA-F0-9]+)ULL\b/gu, "$1n")
        .replaceAll(
          "rights&(command_action==0?1:2)",
          "rights&(command_action==0?1n:2n)",
        )
        .replaceAll("rights&1", "rights&1n")
        .replace(
          /,&(pid|rights|id|authentication|bits|sequence)\b/gu,
          ",value=>$1=value",
        )}
      })(process,object,eventId,mask,stamp,subject,logon,keywords,record);`,
    ),
  };
}

function commandCaptureFixture(
  program,
  { fault, closeFailures = [], start = true } = {},
) {
  const calls = [],
    lifecycle = [],
    closed = [],
    projected = [],
    cleanup = [],
    queue = [];
  let signaled = false,
    state = "unsubscribed",
    decoderReady = false,
    lastError = 0,
    emptyCount = 0,
    clockRead = 0,
    output = "",
    replies = "";
  const format = (text, args) => {
    let index = 0;
    return text.replace(/%(?:ll|l)?[uds]/gu, (specifier) => {
      const value = args[index++];
      return String(
        specifier.endsWith("s")
          ? (value?.text ?? value)
          : typeof value === "boolean"
            ? Number(value)
            : value,
      );
    });
  };
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
    command_observed: {
      active: true,
      pid: 43,
      thread: 44,
      birth: 90,
      status: Array(10).fill(-1),
      held: [0, 0],
      members: [],
      memberCount: 0,
      audit: [5, 0, 0, 0, 0, 0, 0, 0, 1],
    },
    command_gate_observed: { observed: false },
    command_delivery_observe: () => {},
    command_delivery_freeze: () => {},
    command_operating_sacls_write: () => {},
    command_operating_incomplete: false,
    command_operating_bytes: 0,
    command_inspection_incomplete: false,
    command_delivery: { rejected: Array(4).fill(0) },
    command_subscription_query: { text: "" },
    command_subscription_flags: 0,
    EvtSubscribeToFutureEvents: 1,
    EvtSubscribeStrict: 0x10000,
    userText: "S-1-5-21-1",
    command_capture_wait: -1,
    command_capture_wait_error: -1,
    command_next_error: -1,
    command_case_pid: 43,
    command_client: "client",
    command_case_birth: 50n,
    command_case_from: 90n,
    command_case_logon: 1n,
    command_target_record: 0n,
    command_marker_record: 0n,
    command_target_time: 0n,
    command_case_until: 0n,
    first_failure: { operation: null },
    diagnosisLock: {},
    AcquireSRWLockShared: () => {},
    ReleaseSRWLockShared: () => {},
    command_event_time: (stamp) => BigInt(stamp ?? 0),
    command_event_number: (text, out) => {
      if (typeof text !== "string" || !/^(?:0x[0-9a-f]+|[0-9]+)$/iu.test(text))
        return false;
      const value = BigInt(text);
      if (value > 0xffffffffffffffffn) return false;
      out(value);
      return true;
    },
    MAXDWORD: 0xffffffff,
    creation: () => 50n,
    command_action: 2,
    command_case_permit: true,
    command_case_finished: true,
    command_ids: ["inspect-id", "edit-id", "outside-id", "marker-id"],
    command_target_seen: false,
    command_marker_seen: false,
    command_setup_verified: true,
    command_control: true,
    command_control_completed: true,
    command_control_verified: false,
    command_closing: false,
    command_output: "child-output",
    command_error: "child-error",
    command_pump: (slot, event) => {
      calls.push(["pump", event]);
      if (api.controlExited) slot.value = null;
    },
    command_retire_domain: assert.fail,
    STD_INPUT_HANDLE: -10,
    GetStdHandle: () => "owner-input",
    ownerReads: 0,
    PeekNamedPipe: (handle, buffer, size, read, available) => {
      assert.equal(handle, "owner-input");
      const bytes = (api.ownerInput ?? "").slice(0, size);
      buffer.push(...bytes);
      read(bytes.length);
      available(api.ownerInput?.length ?? 0);
      lastError = 109;
      return api.ownerPresent !== false;
    },
    ReadFile: (handle, bytes, size, count) => {
      assert.equal(handle, "owner-input");
      assert.equal(size, 2);
      api.ownerReads++;
      bytes.splice(0, bytes.length, ...api.ownerInput.slice(0, size));
      api.ownerInput = api.ownerInput.slice(size);
      count(2);
      return true;
    },
    GetExitCodeProcess: (_process, code) => {
      api.controlExited = true;
      code(126);
      return true;
    },
    command_retirement_seen: false,
    command_barriers: 0,
    command_subscription: null,
    command_bookmark: null,
    command_event: null,
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
      api.first_failure.operation ??= cause[0];
    },
    cleanup_error: (...cause) => cleanup.push(cause),
    failure: (code) => {
      const saved = lastError;
      api.command_observe_failure();
      assert.equal(
        lastError,
        saved,
        "diagnostic writes preserve the original API error",
      );
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
    command_bound: () => {},
    GetTickCount64: () => [0, 9999, 10000][clockRead++] ?? 10000,
    GetSystemTimePreciseAsFileTime: (value) =>
      Object.assign(value, { dwLowDateTime: 90, dwHighDateTime: 0 }),
    swprintf_s: (buffer, size, text, ...args) => {
      assert.equal(size, 2048);
      buffer.text = format(text, args);
      return buffer.text.length;
    },
    CreateEventW: (attributes, manual, initial, name) => {
      assert.deepEqual([attributes, manual, name], [null, true, null]);
      lifecycle.push("event");
      signaled = initial;
      if (fault === "event") {
        lastError = 5;
        return null;
      }
      return "notification";
    },
    EvtCreateBookmark: (xml) => {
      assert.equal(xml, null);
      lifecycle.push("bookmark");
      if (fault === "create-bookmark") {
        lastError = 5;
        return null;
      }
      return "bookmark";
    },
    EvtSubscribe: (
      session,
      signal,
      channel,
      query,
      bookmark,
      context,
      callback,
      flags,
    ) => {
      assert.deepEqual(
        [session, signal, channel, bookmark, context, callback, flags],
        [null, "notification", null, null, null, null, 0x10001],
      );
      assert.equal(query, api.command_subscription_query);
      assert.equal(state, "unsubscribed");
      lifecycle.push("subscribe");
      if (fault === "subscribe") {
        lastError = 5;
        return null;
      }
      state = "idle";
      api.onSubscribe?.();
      return "subscription";
    },
    diagnosticOutputLock: {},
    AcquireSRWLockExclusive: () => {},
    ReleaseSRWLockExclusive: () => {},
    stderr: {},
    stdout: {},
    ferror: () => {
      decoderReady = true;
      lifecycle.push("ready");
      return fault === "ready-output";
    },
    fprintf: (_stream, text, ...args) => {
      output += format(text, args);
      lastError = 90;
    },
    diagnostic_write: (_stream, _used, _incomplete, text, ...args) => {
      output += format(text, args);
    },
    fputs: (text) => (output += text),
    fflush: () => {},
    printf: (text, ...args) => (replies += format(text, args)),
    WaitForSingleObject: (event, timeout) => {
      if (event === "client") return api.WAIT_TIMEOUT;
      assert.equal(event, "notification");
      calls.push(["wait", timeout]);
      if (fault === "wait") {
        lastError = 5;
        return api.WAIT_FAILED;
      }
      if (fault === "wait-result") return 0x80;
      const result = signaled ? api.WAIT_OBJECT_0 : api.WAIT_TIMEOUT;
      api.onWait?.(result);
      return result;
    },
    EvtNext: (subscription, size, events, timeout, flags, count) => {
      assert.deepEqual(
        [subscription, size, timeout, flags],
        ["subscription", 16, 0, 0],
      );
      calls.push(["next"]);
      assert.ok(
        state === "notified" || state === "enumerating",
        `EvtNext without service readiness: ${state}`,
      );
      state = "enumerating";
      const batch = queue.shift();
      count(batch?.length ?? 0);
      batch?.forEach((event, index) => {
        events[index] = event;
      });
      if (fault === "next" || (fault === "later-next" && emptyCount > 0)) {
        lastError = 4317;
        return false;
      }
      if (!batch) {
        lastError = api.ERROR_NO_MORE_ITEMS;
        state = "exhausted";
        api.onEmpty?.(++emptyCount);
        return false;
      }
      return true;
    },
    ResetEvent: (event) => {
      assert.equal(event, "notification");
      calls.push(["reset"]);
      if (
        fault === "reset" ||
        (fault === "later-reset" &&
          calls.filter(([name]) => name === "reset").length === 2)
      ) {
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
      assert.equal(decoderReady, true, "ready must precede every audit frame");
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
      if (handle === "subscription") state = "closed";
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
  program.subscriptionFlags.runInNewContext(api);
  api.command_audit_query(api.command_subscription_query, "");
  if (start) {
    program.setup.runInNewContext(api);
    program.subscribe.runInNewContext(api);
    decoderReady = true;
  }
  return {
    api,
    calls,
    lifecycle,
    closed,
    projected,
    cleanup,
    output: () => output,
    replies: () => replies,
    notify: (...batches) => {
      assert.ok(
        ["idle", "notified", "enumerating", "exhausted"].includes(state),
      );
      queue.push(...batches);
      signaled = true;
      state = "notified";
    },
    capture: (timeout = 0) => api.command_capture(timeout),
    arm: () => {
      assert.equal(start, false);
      program.arm.runInNewContext(api);
    },
  };
}

test("the future-only pull subscription waits for service readiness after decoder setup", async () => {
  const program = await commandCaptureProgram(),
    f = commandCaptureFixture(program, { start: false });
  const subscription = program.source.indexOf(
      "command_subscription=EvtSubscribe",
    ),
    readyEnd = program.source.indexOf('puts("]}}");', subscription),
    firstDrain = program.source.indexOf("command_capture(0);", subscription);
  assert.ok(
    readyEnd > subscription && readyEnd < firstDrain,
    "the decoder readiness frame must precede any queued audit frame",
  );
  const queued = commandCaptureFixture(program, { start: false });
  queued.api.onSubscribe = () => queued.notify(["queued"]);
  queued.arm();
  assert.deepEqual(queued.projected, ["queued"]);
  assert.deepEqual(queued.lifecycle, [
    "event",
    "bookmark",
    "subscribe",
    "ready",
  ]);
  assert.equal(queued.api.command_target_seen, false);
  assert.equal(queued.api.command_marker_seen, false);
  f.arm();
  assert.deepEqual(
    f.calls.filter(([name]) => ["wait", "next", "reset"].includes(name)),
    [["wait", 0]],
  );
  assert.equal(f.api.command_records, 0);
  assert.equal(f.api.command_target_seen, false);
  assert.equal(f.api.command_marker_seen, false);
  assert.equal(f.api.command_next_error, -1);
  f.notify();
  f.capture(1);
  assert.equal(f.api.command_next_error, 259);
  assert.equal(f.api.command_records, 0);
  assert.equal(f.api.command_target_seen, false);
  assert.equal(f.api.command_marker_seen, false);
  assert.throws(
    () => f.api.command_barrier(),
    (code) => code === 126,
  );
  assert.equal(f.replies(), "");
  assert.deepEqual(f.api.first, ["command-marker-barrier", "invariant", 0]);
  const failed = commandCaptureFixture(program, {
    start: false,
    fault: "next",
    closeFailures: ["subscription"],
  });
  failed.api.onSubscribe = () => failed.notify(["queued"]);
  assert.throws(
    () => failed.arm(),
    (code) => code === 126,
  );
  assert.deepEqual(failed.api.first, ["command-capture-next", "win32", 4317]);
  assert.deepEqual(failed.closed, [
    "queued",
    "subscription",
    "bookmark",
    "notification",
  ]);
  assert.equal(failed.cleanup.length, 1);
  assert.match(
    failed.output(),
    /delivery teardown .*closed=0 subscription=0 bookmark=0 notification=0/u,
  );
});

test("actual subscription setup retains partial ownership and refuses failed readiness output", async () => {
  const program = await commandCaptureProgram();
  for (const [fault, operation, domain, held] of [
    ["event", "command-capture-event", "win32", []],
    ["create-bookmark", "command-bookmark", "win32", ["notification"]],
    [
      "subscribe",
      "command-subscription-create",
      "win32",
      ["bookmark", "notification"],
    ],
    [
      "ready-output",
      "command-ready-output",
      "invariant",
      ["subscription", "bookmark", "notification"],
    ],
  ]) {
    const f = commandCaptureFixture(program, {
      start: false,
      fault,
      closeFailures: held,
    });
    assert.throws(
      () => f.arm(),
      (code) => code === 126,
      fault,
    );
    assert.deepEqual(
      f.api.first,
      [operation, domain, domain === "win32" ? 5 : 0],
      fault,
    );
    assert.deepEqual(f.closed, held, fault);
    assert.equal(f.cleanup.length, held.length, fault);
    assert.equal(
      f.calls.some(([name]) => name === "next"),
      false,
      fault,
    );
  }
});

test("actual capture waits, drains ordered batches and accepts later service notifications", async () => {
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
  const missing = commandCaptureFixture(program);
  assert.throws(
    () => missing.api.command_barrier(),
    (code) => code === 126,
  );
  assert.deepEqual(missing.api.first, [
    "command-marker-barrier",
    "invariant",
    0,
  ]);
  assert.deepEqual(
    missing.calls.filter(([name]) => name === "wait"),
    [
      ["wait", 0],
      ["wait", 10],
      ["wait", 0],
    ],
  );
  assert.equal(missing.replies(), "");
  const refusal =
      "native-windows: operation=command-marker-barrier domain=invariant value=0\n",
    delivery = missing.output();
  assert.match(
    delivery,
    /operating-attempt .*target-record=0 marker-record=0 .*generation=unproved/u,
  );
  assert.ok(Buffer.byteLength(refusal + delivery) < 4096);
  assert.ok(
    delivery.includes(
      `channel=Security flags=65537 query=${missing.api.command_subscription_query.text} wait=258 wait-error=0 next-error=-1`,
    ),
  );
  assert.match(
    delivery,
    /scanned=0 scanned-bytes=0 selected=0 selected-bytes=0 pid=43 action=2 target-id=outside-id marker-id=marker-id target-seen=0 marker-seen=0 io-completed=1 setup=1 control=1 control-completed=1 control-verified=0 closing=0 retirement-seen=0\n/u,
  );
  const transport = (await brokerCloseBoundary())();
  transport.broker.stderr.write(refusal + delivery);
  const ended = once(transport.broker.stderr, "end");
  transport.broker.stderr.end();
  await ended;
  transport.broker.emit("close", 126, null);
  const error = await transport.outcome;
  assert.equal(error.nativeDiagnosticInvalid, false);
  assert.equal(error.operatingObservationIncomplete, false);
  assert.equal(Buffer.concat(transport.raw).toString(), refusal + delivery);
  assert.deepEqual(windowsFeasibilityDiagnostics(error.stderr).failure, {
    operation: "command-marker-barrier",
    domain: "invariant",
    value: 0,
  });
  assert.equal(windowsFeasibilityDiagnostics(delivery), null);
  assert.equal(
    windowsFeasibilityDiagnostics(
      refusal.replace("domain=invariant", "domain=win32"),
    ),
    null,
  );
  assert.deepEqual(
    windowsFeasibilityDiagnostics(
      refusal + "native-windows-command: delivery malformed\n",
    ).failure,
    {
      operation: "command-marker-barrier",
      domain: "invariant",
      value: 0,
    },
  );
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
    [["reset"], ["next"], ["reset"], ["next"], ["reset"], ["next"]],
  );
  const nextCount = f.calls.filter(([name]) => name === "next").length;
  f.capture();
  f.capture(1);
  assert.equal(f.calls.filter(([name]) => name === "next").length, nextCount);
  f.notify(["later"]);
  f.capture(10);
  assert.deepEqual(f.projected, ["a", "b", "c", "later"]);
  assert.equal(f.api.command_records, 4);
  assert.deepEqual(f.api.command_observed.audit.slice(2, 7), [2, 5, 4, 5, 4]);
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

test("actual capture preserves arrivals before and after reset, exhaustion and readiness rechecks", async () => {
  const program = await commandCaptureProgram();
  for (const boundary of [
    "before-reset",
    "drain",
    "exhaustion",
    "reset",
    "after-recheck",
  ]) {
    const f = commandCaptureFixture(program);
    f.notify(["first"]);
    if (boundary === "before-reset")
      f.api.onWait = (result) => {
        if (result === f.api.WAIT_OBJECT_0) {
          f.api.onWait = null;
          f.notify(["raced"]);
        }
      };
    if (boundary === "drain")
      f.api.onProject = (event) => {
        if (event === "first") f.notify(["raced"]);
      };
    if (boundary === "exhaustion")
      f.api.onEmpty = (count) => {
        if (count === 1) f.notify(["raced"]);
      };
    if (boundary === "after-recheck")
      f.api.onWait = (result) => {
        if (result === f.api.WAIT_TIMEOUT) {
          f.api.onWait = null;
          f.notify(["raced"]);
        }
      };
    if (boundary === "reset")
      f.api.onReset = () => {
        f.api.onReset = null;
        f.notify(["raced"]);
      };
    f.capture(10);
    const waits = f.calls.filter(([name]) => name === "wait");
    assert.deepEqual(waits[0], ["wait", 10], boundary);
    assert.ok(
      waits.slice(1).every(([, timeout]) => timeout === 0),
      boundary,
    );
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
    ["later-next", "command-capture-next", "win32", 4317],
    ["query", "command-capture-query", "win32", 5],
    ["render", "command-capture-render", "win32", 5],
    ["bookmark", "command-capture-bookmark", "win32", 5],
    ["reset", "command-capture-reset", "win32", 5],
    ["later-reset", "command-capture-reset", "win32", 5],
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
    if (fault === "later-next")
      f.api.onEmpty = (count) => {
        if (count === 1) f.notify(["raced"]);
      };
    assert.throws(
      () => f.capture(),
      (code) => code === 126,
      fault,
    );
    assert.deepEqual(f.api.first, [operation, domain, value], fault);
    assert.equal(
      f.api.command_capture_wait,
      fault === "wait" ? 0xffffffff : fault === "wait-result" ? 0x80 : 0,
    );
    assert.equal(f.api.command_capture_wait_error, fault === "wait" ? 5 : 0);
    assert.equal(
      f.api.command_next_error,
      fault.startsWith("wait") || fault === "reset"
        ? -1
        : fault.includes("next")
          ? 4317
          : 0,
    );
    assert.deepEqual(
      f.closed,
      [
        ...(fault.startsWith("wait") || fault === "reset"
          ? []
          : ["a", "b", "c"]),
        ...(fault === "later-next" ? ["raced"] : []),
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
      source.indexOf("struct command_token_observation {"),
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

test("post-refusal projection confines text and retains both exact original interval endpoints", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const text =
    /static const WCHAR \*command_delivery_text\([^\n]+\) \{([\s\S]*?)\n\}/u
      .exec(source)[1]
      .replaceAll("(ULONG_PTR)", "")
      .replaceAll("sizeof(WCHAR)", "2")
      .replaceAll("->", ".")
      .replace(/\b(?:ULONG_PTR|size_t)\b/gu, "let");
  const textProgram = new Script(`(value,bytes,size)=>{${text}}`);
  for (const [pointer, type, length, accepted] of [
    [120, 1, 2, true],
    [99, 1, 2, false],
    [132, 1, 2, false],
    [121, 1, 2, false],
    [130, 1, 1, false],
    [120, 129, 2, false],
    [0, 1, 2, false],
  ]) {
    const read = textProgram.runInNewContext({
      NULL: null,
      EvtVarTypeString: 1,
      wcsnlen_s: (value, capacity) => {
        assert.equal(value, pointer);
        return Math.min(length, capacity);
      },
    });
    assert.equal(
      read({ Type: type, StringVal: pointer }, 100, 32),
      accepted ? pointer : null,
    );
  }
  const sid = /static PSID command_delivery_sid\([^\n]+\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace(
      "const SID *sid=(const SID *)value->SidVal;",
      "const sid=sidAt(value.SidVal);",
    )
    .replaceAll("(ULONG_PTR)", "")
    .replaceAll("sizeof(DWORD)", "4")
    .replaceAll("->", ".")
    .replace(/\b(?:ULONG_PTR|DWORD)\b/gu, "let");
  const sidProgram = new Script(`(value,bytes,size)=>{${sid}}`);
  for (const [pointer, type, count, valid, accepted] of [
    [496, 19, 2, true, true],
    [508, 19, 0, true, false],
    [498, 19, 2, true, false],
    [496, 147, 2, true, false],
    [496, 19, 255, true, false],
    [99, 19, 2, true, false],
    [416, 19, 2, false, false],
  ]) {
    const read = sidProgram.runInNewContext({
      NULL: null,
      EvtVarTypeSid: 19,
      SECURITY_MAX_SID_SIZE: 68,
      sidAt: () => ({ SubAuthorityCount: count }),
      GetSidLengthRequired: (n) => 8 + 4 * n,
      IsValidSid: () => valid,
    });
    assert.equal(
      read({ Type: type, SidVal: pointer }, 100, 412),
      accepted ? pointer : null,
    );
  }
  const interval =
    /static BOOL command_delivery_interval\([^\n]+\) \{([\s\S]*?)\n\}/u
      .exec(source)[1]
      .replace(
        "FILETIME to={(DWORD)command_case_until,(DWORD)(command_case_until>>32)},from={(DWORD)command_case_from,(DWORD)(command_case_from>>32)};SYSTEMTIME first,last;",
        "const to={dwLowDateTime:Number(command_case_until&0xffffffffn),dwHighDateTime:Number(command_case_until>>32n)},from={dwLowDateTime:Number(command_case_from&0xffffffffn),dwHighDateTime:Number(command_case_from>>32n)},first={},last={};",
      )
      .replaceAll("*until", "until.value")
      .replace(
        "((ULONGLONG)to.dwHighDateTime<<32)|to.dwLowDateTime",
        "((BigInt(to.dwHighDateTime)<<32n)|BigInt(to.dwLowDateTime))",
      )
      .replace(
        "(DWORD)(command_case_from%10000000)",
        "Number(command_case_from%10000000n)",
      )
      .replace("(DWORD)(until.value%10000000)", "Number(until.value%10000000n)")
      .replace(/&(?=(?:to|from|first|last)\b)/gu, "")
      .replaceAll(/\bL(?=")/gu, "");
  const program = new Script(`(interval,until)=>{${interval}}`);
  const freeze =
    /static void command_delivery_freeze\([^\n]+\) \{([\s\S]*?)\n\}/u
      .exec(source)[1]
      .replace("FILETIME to;", "const to={};")
      .replace(
        "((ULONGLONG)to.dwHighDateTime<<32)|to.dwLowDateTime",
        "(BigInt(to.dwHighDateTime)<<32n)|BigInt(to.dwLowDateTime)",
      )
      .replace("&to", "to");
  let samples = 0;
  const frozen = {
    TRUE: true,
    command_delivery_frozen: false,
    command_case_from: 90n,
    command_case_until: 0n,
    GetSystemTimePreciseAsFileTime(to) {
      samples++;
      Object.assign(to, { dwHighDateTime: 1, dwLowDateTime: samples });
    },
  };
  const freezeOnce = new Script(`()=>{${freeze}}`).runInNewContext(frozen);
  freezeOnce();
  freezeOnce();
  assert.equal(samples, 1);
  assert.equal(frozen.command_case_until, 4294967297n);
  for (const fault of [null, "missing", "birth", "clock", "conversion"]) {
    const from = fault === "missing" ? 0n : 133000000001234567n,
      to = fault === "clock" ? from - 1n : 133000000009876543n,
      output = {},
      until = { value: 0 };
    const api = {
      FALSE: false,
      BigInt,
      command_case_from: from,
      command_case_until: to,
      command_case_birth: fault === "birth" ? from + 1n : from - 1n,
      FileTimeToSystemTime(value, result) {
        assert.ok(
          [from, to].includes(
            (BigInt(value.dwHighDateTime) << 32n) | BigInt(value.dwLowDateTime),
          ),
        );
        Object.assign(result, {
          wYear: 2026,
          wMonth: 1,
          wDay: 2,
          wHour: 3,
          wMinute: 4,
          wSecond: 5,
        });
        return fault !== "conversion";
      },
      swprintf_s(value, size, format, ...args) {
        assert.equal(size, 256);
        let i = 0;
        value.text = format.replace(/%0([0-9]+)l?u/gu, (_, width) =>
          String(args[i++]).padStart(Number(width), "0"),
        );
        return value.text.length;
      },
    };
    assert.equal(program.runInNewContext(api)(output, until), fault === null);
    assert.equal(until.value, to);
    if (!fault)
      assert.equal(
        output.text,
        "TimeCreated[@SystemTime>='2026-01-02T03:04:05.1234567Z' and @SystemTime<='2026-01-02T03:04:05.9876543Z']",
      );
    else assert.equal(output.text, undefined);
  }
});

test("original live Security record IDs remain bounded and freeze with the failure boundary", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const body = /static void command_delivery_record\([^\n]+\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("ULONGLONG record=0;", "let record=0;")
    .replace("&record", "value=>record=value");
  const state = {
    TRUE: true,
    command_case_from: 1,
    command_delivery_frozen: false,
    command_delivery_record_count: 0,
    command_delivery_records_incomplete: false,
    command_delivery_records: Array(256).fill(0),
    command_event_number(text, out) {
      if (text === null) return false;
      out(BigInt(text));
      return true;
    },
  };
  const retain = new Script(`text=>{${body}}`).runInNewContext(state);
  retain("9007199254740993");
  assert.equal(state.command_delivery_records[0], 9007199254740993n);
  for (let i = 1; i < 256; i++) retain(String(i));
  retain("257");
  assert.equal(state.command_delivery_record_count, 256);
  assert.equal(state.command_delivery_records_incomplete, true);
  state.command_delivery_records_incomplete = false;
  state.command_delivery_frozen = true;
  retain(null);
  assert.equal(state.command_delivery_record_count, 256);
  assert.equal(state.command_delivery_records_incomplete, false);
  state.command_delivery_frozen = false;
  state.command_delivery_record_count = 0;
  retain("0");
  retain(null);
  assert.equal(state.command_delivery_record_count, 0);
  assert.equal(state.command_delivery_records_incomplete, true);
});

test("post-refusal audit inspection joins the original case without draining the subscription", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
    "utf8",
  );
  const effectsSource = await readFile(
    new URL(
      "../ci/native/win32/feasibility-command-effects.js",
      import.meta.url,
    ),
    "utf8",
  );
  const isObservation = new Script(
    effectsSource.slice(
      effectsSource.indexOf("function commandOperatingDiagnostic"),
      effectsSource.indexOf("\nconst regular"),
    ) + "\ncommandOperatingDiagnostic",
  ).runInNewContext();
  const body = (name) =>
    new RegExp(
      `static (?:void|BOOL|int) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const number = body("command_delivery_number")
    .replaceAll("->", ".")
    .replace(/\*number=([^;]+);/gu, "number($1);");
  const match = body("command_delivery_match")
    .replace(
      "union { EVT_VARIANT alignment; BYTE bytes[32768]; } buffer;",
      "const buffer={bytes:[]};",
    )
    .replace(
      "const EVT_VARIANT *values=(const EVT_VARIANT *)buffer.bytes;",
      "const values=buffer.bytes;",
    )
    .replace("ULONGLONG pid,logon,time=", "let pid,logon;let time=")
    .replaceAll("sizeof(buffer.bytes)", "32768")
    .replaceAll("sizeof(EVT_VARIANT)", "16")
    .replace(/\*(operation|error)=([^;]+);/gu, "$1($2);")
    .replace(/&(values\[(?:[012]|i)\])/gu, "$1")
    .replace(/,&(pid|logon|used|count)/gu, ",value=>$1=value")
    .replace(/\b(?:DWORD|BOOL|unsigned)\b/gu, "let");
  const fact = body("command_delivery_fact")
    .replace(
      "ULONGLONG numbers[13]={0};DWORD valid=0;const WCHAR *strings[13]={0};char types[156]={0};unsigned offset=0;",
      'const numbers=Array(13).fill(0),strings=Array(13).fill(null);let valid=0,types="";',
    )
    .replace(
      "const BYTE *data[13]={0};DWORD lengths[13]={0};",
      "const data=Array(13).fill(null),lengths=Array(13).fill(0);",
    )
    .replace("PSID sid=", "const sid=")
    .replace(
      'offset+=(unsigned)snprintf(types+offset,sizeof(types)-offset,"%s%lu",i?",":"",values[i].Type);',
      'types+=(i?",":"")+values[i].Type;',
    )
    .replace("EVT_VARIANT value=values[i];", "const value={...values[i]};")
    .replace(
      "const unsigned fields[]={4,8,9,1,11};",
      "const fields=[4,8,9,1,11];",
    )
    .replace('char hex[129]="-";', 'let hex="-";')
    .replace(
      'for(DWORD j=0;j<encoded;j++)snprintf(hex+2*j,3,"%02x",data[fields[i]][at+j]);',
      'hex=encoded?byteSlice(data[fields[i]],at,encoded):"-";',
    )
    .replaceAll("(const BYTE *)", "")
    .replaceAll("(DWORD)", "")
    .replaceAll("sizeof(WCHAR)", "2")
    .replace(/\b([0-9]+)u\b/gu, "$1")
    .replaceAll("0x0020000000000000ULL", "0x0020000000000000n")
    .replaceAll("0x0010000000000000ULL", "0x0010000000000000n")
    .replaceAll("0x0030000000000000ULL", "0x0030000000000000n")
    .replaceAll(/\bL(?=")/gu, "")
    .replaceAll(
      /&command_operating_(bytes|incomplete)/gu,
      '"command_operating_$1"',
    )
    .replace(/(?<!&)&values\[i\]/gu, "values[i]")
    .replace(/(?<!&)&value\b/gu, "value")
    .replaceAll("&numbers[i]", "v=>numbers[i]=v")
    .replace(/\*(operation|error)=([^;]+);/gu, "$1($2);")
    .replace(/\b(?:unsigned|DWORD|BOOL|LONG|ULONGLONG|int)\b/gu, "let");
  const log = body("command_delivery_log")
    .replace("EVT_VARIANT value={0};", "const value={};")
    .replace(/\*(oldest|records)=([^;]+);/gu, "$1($2);")
    .replace(/\*(oldest|records)/gu, "$1()")
    .replaceAll("sizeof(value)", "16")
    .replace(/&(value|used)\b/gu, (_, name) =>
      name === "used" ? "v=>used=v" : name,
    )
    .replaceAll(/\bL(?=")/gu, "")
    .replace(/\b(?:EVT_HANDLE|DWORD|BOOL|unsigned)\b/gu, "let");
  {
    let expired = false,
      reads = 0,
      closes = 0,
      diagnostic;
    const api = {
      NULL: null,
      TRUE: true,
      FALSE: false,
      ERROR_SUCCESS: 0,
      ERROR_TIMEOUT: 1460,
      EvtOpenChannelPath: 1,
      EvtLogOldestRecordNumber: 3,
      EvtLogNumberOfLogRecords: 2,
      stderr: {},
      command_delivery_expired: () => expired,
      EvtOpenLog: () => "log",
      EvtGetLogInfo() {
        reads++;
        expired = true;
        return false;
      },
      GetLastError: () => 0,
      EvtClose() {
        closes++;
        return true;
      },
      fprintf(_stream, _format, ...args) {
        diagnostic = args;
      },
      cleanup_error: () =>
        assert.fail("Successful closure cannot report a cleanup failure"),
    };
    const sample = new Script(`(oldest,records)=>{${log}}`).runInNewContext(
      api,
    );
    assert.equal(
      sample(
        () => 0,
        () => 0,
      ),
      false,
    );
    assert.equal(reads, 1, "Expiry prevents the second property read");
    assert.equal(closes, 1, "Expiry still closes the acquired log");
    assert.equal(
      diagnostic[0],
      0,
      "Expiry cannot replace the original read failure with a timeout",
    );
  }
  const availability = body("command_delivery_interface")
    .replace("EVT_HANDLE handles[3]={0};", "const handles=Array(3).fill(null);")
    .replace(
      "LONGLONG status[6]={-1,-1,-1,-1,-1,-1},values[3]={-1,-1,-1},closed[3]={-1,-1,-1};",
      "const status=Array(6).fill(-1),values=Array(3).fill(-1),closed=Array(3).fill(-1);",
    )
    .replace(
      "LONGLONG types[3]={-1,-1,-1},sizes[3]={-1,-1,-1};",
      "const types=Array(3).fill(-1),sizes=Array(3).fill(-1);",
    )
    .replace("EVT_VARIANT value={0};", "let value={};")
    .replaceAll("memset(&value,0,sizeof(value))", "value={}")
    .replaceAll("sizeof(value)", "16")
    .replaceAll("value.UInt64Val>>63", "value.UInt64Val/2**63>=1")
    .replace(/(?<!&)&value\b/gu, "value")
    .replace(/(?<!&)&used\b/gu, "v=>used=v")
    .replace(/\((?:DWORD|LONGLONG)\)/gu, "")
    .replaceAll(/\bL(?=")/gu, "")
    .replace(/\b(?:DWORD|BOOL|unsigned)\b/gu, "let");
  const inspection = body("command_delivery_observe")
    .replace(
      "ULONGLONG until=0;WCHAR interval[256];BOOL bounded=",
      "let until=0;const interval={};let bounded=",
    )
    .replace(
      "command_delivery_interval(interval,&until)",
      "command_delivery_interval(interval,value=>until=value)",
    )
    .replace("WCHAR query[2048];", "const query={};")
    .replace("EVT_HANDLE events[16]={0};", "const events=Array(16).fill(null);")
    .replace(/const WCHAR \*paths\[\]=\{([^}]+)\};/u, "const paths=[$1];")
    .replaceAll("const char *", "let ")
    .replaceAll(", *", ", ")
    .replaceAll(/\bL(?=")/gu, "")
    .replace(
      /\b(?:DWORD|EVT_HANDLE|BOOL|LONGLONG|ULONGLONG|int|unsigned)\b/gu,
      "let",
    )
    .replaceAll(
      /&command_operating_(bytes|incomplete)/gu,
      '"command_operating_$1"',
    )
    .replace(/,&(count|readOperation|readError)/gu, ",value=>$1=value")
    .replace(
      /(?<!&)&(oldest|records|afterOldest|afterRecords)\b/gu,
      "value=>value===undefined?$1:($1=value)",
    );
  const program =
    new Script(`function command_delivery_number(value,number){${number}}
    function command_delivery_fact(values,bytes,size,index,until,operation,error){${fact}}
    function command_delivery_match(context,event,operation,error,wide,index,until){${match}}
    function command_delivery_interface(){${availability}}
    function command_delivery_log(oldest,records){${log}}
    function command_delivery_expired(){${body("command_delivery_expired")}}
    ()=>{${inspection}}`);
  for (const fault of [
    null,
    "query",
    "empty",
    "next",
    "event-close",
    "query-close",
    "context-close",
    "saturated",
    "context",
    "render",
    "event-fields",
    "text",
    "other-pid",
    "other-logon",
    "stale",
    "object-case",
    "channel",
    "channel-enabled",
    "channel-type",
    "publisher",
    "log",
    "log-info",
    "interface-close",
    "other-provider",
    "other-id",
    "other-keywords",
    "other-subject",
    "other-object-type",
    "missing-field",
    "future",
    "deadline",
    "render-deadline",
    "render-count",
    "render-size",
    "missing-provider",
    "missing-record",
    "numeric-range",
    "array-field",
    "sid",
    "other-sid",
    "bad-sid",
    "failure-event",
    "projection-deadline",
    "unrelated-first",
    "short-batches",
    "undelivered",
    "log-rollover",
    "log-clear",
    "loss",
    "version",
    "version-unavailable",
    "output-bound",
    "partial-next",
    "long-field",
    "partial-cleanup",
    "render-zero",
    "close-zero",
    "log-first-zero",
    "both-keywords",
    "marker-first",
  ]) {
    const calls = [],
      closed = [],
      cleanup = [],
      queries = [],
      frames = [],
      optional = [],
      continuity = [],
      batches = [0, 0];
    let lastError = 91,
      selected = 0,
      logReads = 0,
      visibility;
    const api = {
      NULL: null,
      TRUE: true,
      FALSE: false,
      ERROR_SUCCESS: 0,
      ERROR_INSUFFICIENT_BUFFER: 122,
      ERROR_INVALID_DATA: 13,
      ERROR_TIMEOUT: 1460,
      ERROR_NO_MORE_ITEMS: 259,
      MAXDWORD: 0xffffffff,
      EvtQueryChannelPath: 1,
      EvtQueryForwardDirection: 0x100,
      EvtRenderContextValues: 0,
      EvtRenderEventValues: 0,
      EvtVarTypeUInt32: 8,
      EvtVarTypeByte: 4,
      EvtVarTypeUInt16: 6,
      EvtVarTypeHexInt32: 20,
      EvtVarTypeUInt64: 10,
      EvtVarTypeHexInt64: 21,
      EvtVarTypeFileTime: 17,
      EvtVarTypeString: 1,
      EvtVarTypeSid: 19,
      EvtVarTypeNull: 0,
      EvtVarTypeBoolean: 13,
      EvtChannelConfigEnabled: 0,
      EvtOpenChannelPath: 1,
      EvtLogNumberOfLogRecords: 2,
      EvtLogOldestRecordNumber: 3,
      command_subscription: "subscription",
      command_event: "notification",
      command_bookmark: "bookmark",
      command_observed: { audit: [5, 0, 1, 2, 3, 4, 5, 0, 0] },
      EvtOpenChannelConfig(session, channel, flags) {
        assert.deepEqual([session, channel, flags], [null, "Security", 0]);
        lastError = 5;
        return fault === "channel" ? null : "channel";
      },
      EvtOpenPublisherMetadata(session, publisher, file, locale, flags) {
        assert.deepEqual(
          [session, publisher, file, locale, flags],
          [null, "Microsoft-Windows-Security-Auditing", null, 0, 0],
        );
        lastError = 5;
        return fault === "publisher" ? null : "publisher";
      },
      EvtOpenLog(session, channel, flags) {
        assert.deepEqual([session, channel, flags], [null, "Security", 1]);
        lastError = 5;
        logReads++;
        return fault === "log" ? null : "log";
      },
      EvtGetChannelConfigProperty(handle, kind, flags, size, value, used) {
        assert.deepEqual([handle, kind, flags, size], ["channel", 0, 0, 16]);
        lastError = 5;
        Object.assign(value, {
          Type: fault === "channel-type" ? 8 : 13,
          BooleanVal: true,
        });
        used(16);
        return fault !== "channel-enabled";
      },
      EvtGetLogInfo(handle, kind, size, value, used) {
        assert.deepEqual([handle, size], ["log", 16]);
        assert.ok([2, 3].includes(kind));
        lastError = 5;
        if (fault === "log-first-zero" && logReads < 3) {
          lastError = kind === 3 ? 0 : 6;
          return false;
        }
        Object.assign(value, {
          Type: 10,
          UInt64Val:
            kind === 2
              ? fault === "log-clear" && logReads === 2
                ? 1
                : 2
              : fault === "log-rollover" && logReads === 2
                ? 11
                : 10,
        });
        used(16);
        return fault !== "log-info";
      },
      stderr: {},
      command_case_pid: 43,
      command_case_birth: 50,
      command_case_logon: 7,
      command_case_permit: fault !== "failure-event",
      command_client: "client",
      command_case_from: 90,
      command_action: 2,
      command_paths: ["inspect", "edit", "outside", "marker"],
      command_started: 0,
      command_cleanup_started: 0,
      command_closing: false,
      command_operating_bytes: 0,
      command_operating_incomplete: false,
      command_inspection_incomplete: false,
      command_helper_hash: PIN,
      command_ids: Array(4).fill("a".repeat(16) + ":" + "b".repeat(32)),
      command_delivery_versions: [[0], [0]],
      command_delivery_version_count:
        fault === "version-unavailable" ? [0, 0] : [1, 1],
      command_delivery_records: fault === "undelivered" ? [] : [12],
      command_delivery_record_count: fault === "undelivered" ? 0 : 1,
      command_delivery_records_incomplete: false,
      command_inspection_target_record: 0,
      command_inspection_target_time: 0,
      command_delivery_interval(interval, until) {
        interval.text = "TimeCreated[@SystemTime>='90' and @SystemTime<='110']";
        until(110);
        return true;
      },
      GetTickCount64: () =>
        fault === "deadline" ||
        (fault === "render-deadline" && calls.includes("next")) ||
        (fault === "projection-deadline" &&
          optional.some(([format]) =>
            format.includes("operating-audit index="),
          ))
          ? 120000
          : 0,
      command_delivery_text: (value) =>
        value.Type === 1 ? value.StringVal : null,
      userSid: Buffer.from("synthetic-subject"),
      command_delivery_sid: (value) =>
        value.Type === 19 ? value.SidVal : null,
      GetLengthSid: (value) => value.length,
      EqualSid: (a, b) => a.equals(b),
      diagnostic_write: (_stream, _used, _incomplete, format, ...args) => {
        optional.push([format, ...args]);
        if (fault === "output-bound" && format.includes("audit-value"))
          api.command_operating_incomplete = true;
      },
      byteSlice(value, at, length) {
        return (
          typeof value === "string" ? Buffer.from(value, "utf16le") : value
        )
          .subarray(at, at + length)
          .toString("hex");
      },
      wcscmp: (a, b) => (a === b ? 0 : 1),
      wcslen: (text) => text.length,
      userText: identity.userSid,
      command_delivery: {
        subject: identity.userSid,
        subjectError: 0,
        level: 2,
        policy: 3,
        policyError: 0,
        sacls: [sha("target"), sha("marker")],
        rejected: [1, 2, 3, 4],
      },
      command_event_time: (text) => Number(text),
      command_event_number(text, out) {
        if (!text || !/^(?:0x[0-9a-f]+|[0-9]+)$/u.test(text)) return false;
        out(Number(text));
        return true;
      },
      _wcsicmp: (a, b) => (a.toLowerCase() === b.toLowerCase() ? 0 : 1),
      wcsnlen_s: (text, maximum) => Math.min(text.length, maximum),
      GetLastError: () => lastError,
      SetLastError: (value) => {
        lastError = value;
      },
      EvtCreateRenderContext(count, paths, flags) {
        assert.equal(count, 13);
        assert.equal(paths.length, 13);
        assert.equal(flags, 0);
        assert.ok(paths[0].includes("ProcessId"));
        assert.ok(paths[2].includes("SubjectLogonId"));
        lastError = 5;
        return fault === "context" ? null : "context";
      },
      swprintf_s(query, maximum, format, ...args) {
        assert.equal(maximum, 2048);
        let i = 0;
        query.text = format.replace(/%ls/gu, () => {
          const value = args[i++];
          return value?.text ?? value;
        });
        queries.push(query.text);
        return query.text.length;
      },
      EvtQuery(session, channel, query, flags) {
        assert.deepEqual([session, channel, flags], [null, "Security", 0x101]);
        selected = queries.length - 1;
        calls.push("query");
        lastError = 5;
        assert.equal(
          query.text.includes("ObjectName"),
          false,
          "Case-insensitive held names are joined after projection",
        );
        assert.ok(
          query.text.includes(
            "TimeCreated[@SystemTime>='90' and @SystemTime<='110']",
          ),
        );
        return fault === "query" ? null : `query:${selected}`;
      },
      EvtNext(query, maximum, events, timeout, flags, count) {
        assert.deepEqual(
          [query, maximum, timeout, flags],
          [`query:${selected}`, 16, 0, 0],
        );
        calls.push("next");
        const batch = batches[selected]++;
        if (
          batch &&
          fault !== "saturated" &&
          !(fault === "short-batches" && batch === 1) &&
          !(fault === "unrelated-first" && selected && batch === 1)
        ) {
          count(0);
          lastError = 259;
          return false;
        }
        lastError = fault === "empty" ? 259 : 50;
        const size =
          fault === "saturated"
            ? 16
            : fault === "empty" || fault === "next"
              ? 0
              : ["undelivered", "marker-first"].includes(fault)
                ? 2
                : selected
                  ? 1
                  : 2;
        count(size);
        for (let i = 0; i < size; i++)
          events[i] = `event:${selected}:${batch}:${i}`;
        if (fault === "unrelated-first" && selected && batch === 0)
          events[0] = "unrelated";
        if (fault === "short-batches" && batch === 1)
          events[0] = "later-marker";
        if (["partial-next", "partial-cleanup"].includes(fault)) {
          lastError = 50;
          return false;
        }
        return !["empty", "next"].includes(fault);
      },
      EvtRender(context, event, flags, maximum, bytes, used, count) {
        assert.deepEqual([context, flags, maximum], ["context", 0, 32768]);
        calls.push("render");
        lastError = 50;
        if (fault === "render") return false;
        if (fault === "render-zero") {
          lastError = event.endsWith(":0") ? 0 : 50;
          return false;
        }
        const object =
          fault === "marker-first" && selected
            ? event.endsWith(":0")
              ? "marker"
              : "outside"
            : event === "later-marker"
              ? "marker"
              : event.endsWith(":0")
                ? "outside"
                : "marker";
        bytes.push(
          fault === "text"
            ? { Type: 1, StringVal: "0x2b" }
            : { Type: 8, UInt32Val: fault === "other-pid" ? 44 : 43 },
          {
            Type: fault === "event-fields" ? 8 : 1,
            StringVal: fault === "object-case" ? object.toUpperCase() : object,
          },
          fault === "text"
            ? { Type: 1, StringVal: "0x7" }
            : { Type: 21, UInt64Val: fault === "other-logon" ? 8 : 7 },
          fault === "text"
            ? { Type: 1, StringVal: "100" }
            : {
                Type: 17,
                FileTimeVal:
                  fault === "stale" ? 89 : fault === "future" ? 111 : 100,
              },
          {
            Type:
              fault === "missing-provider"
                ? 0
                : fault === "array-field"
                  ? 129
                  : 1,
            StringVal:
              fault === "other-provider"
                ? "Synthetic-Provider"
                : "Microsoft-Windows-Security-Auditing",
          },
          {
            Type: 6,
            UInt16Val:
              fault === "other-id"
                ? 5000
                : fault === "failure-event"
                  ? 4656
                  : 4663,
          },
          {
            Type: 10,
            UInt64Val:
              fault === "other-keywords"
                ? 0n
                : fault === "both-keywords"
                  ? 0x8030000000000000n
                  : fault === "failure-event"
                    ? 0x8010000000000000n
                    : 0x8020000000000000n,
          },
          {
            Type: 10,
            UInt64Val:
              fault === "missing-record"
                ? 0
                : object === "marker"
                  ? fault === "marker-first"
                    ? 11
                    : 13
                  : 12,
          },
          {
            Type: ["sid", "other-sid", "bad-sid"].includes(fault) ? 19 : 1,
            StringVal:
              fault === "other-subject" ? "S-1-5-21-99" : identity.userSid,
            SidVal:
              fault === "bad-sid"
                ? null
                : Buffer.from(
                    fault === "other-sid"
                      ? "other-subject"
                      : "synthetic-subject",
                  ),
          },
          {
            Type: 1,
            StringVal: fault === "other-object-type" ? "Key" : "File",
          },
          {
            Type:
              fault === "missing-field"
                ? 0
                : fault === "numeric-range"
                  ? 10
                  : 20,
            UInt32Val: object === "marker" ? 1 : 2,
            UInt64Val: 4294967296n,
          },
          {
            Type: 1,
            StringVal:
              fault === "long-field"
                ? "C:\\fixture\\" + "actor-λ".repeat(12) + ".exe"
                : "C:\\fixture\\actor.exe",
          },
          { Type: 4, ByteVal: fault === "version" ? 9 : 0 },
        );
        if (event === "unrelated") {
          for (const index of [0, 1, 2, 8, 9, 10, 11])
            bytes[index] = { Type: 0 };
          bytes[5] = { Type: 6, UInt16Val: 4688 };
        }
        if (fault === "loss") bytes[5] = { Type: 6, UInt16Val: 1102 };
        used(fault === "render-size" ? 191 : 1024);
        count(fault === "render-count" ? 12 : 13);
        return true;
      },
      EvtClose(handle) {
        closed.push(handle);
        lastError = 6;
        if (
          fault === "close-zero" &&
          (handle.startsWith("event:") || handle.startsWith("query:"))
        ) {
          lastError =
            handle.startsWith("event:") && handle.endsWith(":0") ? 0 : 6;
          return false;
        }
        if (
          fault === "partial-cleanup" &&
          (handle === "context" ||
            handle.startsWith("event:") ||
            handle.startsWith("query:"))
        )
          return false;
        return (
          !(
            fault === "event-close" &&
            handle.endsWith(":0") &&
            handle.startsWith("event:")
          ) &&
          !(fault === "query-close" && handle.startsWith("query:")) &&
          !(fault === "context-close" && handle === "context") &&
          !(
            fault === "interface-close" &&
            ["channel", "publisher", "log"].includes(handle)
          )
        );
      },
      cleanup_error: (...cause) => cleanup.push(cause),
      fprintf: (_stream, _format, ...args) => {
        if (_format.includes("delivery continuity")) continuity.push(args);
        else if (_format.includes("delivery visibility")) visibility = args;
        else frames.push(args);
        lastError = 92;
      },
      fflush: () => {},
    };
    program.runInNewContext(api)();
    assert.equal(queries.length, 2);
    assert.equal(queries[0].includes("band(Keywords"), false);
    for (const predicate of [
      "Provider[",
      "EventID=",
      "SubjectUserSid",
      "ObjectType",
      "band(Keywords",
    ])
      assert.equal(queries[1].includes(predicate), false);
    assert.equal(lastError, 91);
    if (
      [
        null,
        "empty",
        "query",
        "deadline",
        "render-deadline",
        "short-batches",
        "saturated",
      ].includes(fault)
    )
      assert.equal(
        calls.filter((call) => call === "next").length,
        {
          empty: 2,
          query: 0,
          deadline: 0,
          "render-deadline": 1,
          "short-batches": 6,
          saturated: 16,
        }[fault] ?? 4,
      );
    assert.equal(frames.length, 6);
    assert.equal(continuity.length, 2);
    assert.deepEqual(frames[4], [true, true, true, 0, 1, 2, 3, 4, 5]);
    assert.equal(frames[5][0], fault === "channel" ? 5 : 0);
    assert.equal(frames[5][1], fault === "publisher" ? 5 : 0);
    assert.equal(frames[5][2], fault === "log" ? 5 : 0);
    assert.equal(frames[0][4], identity.userSid);
    assert.equal(frames[0][5], 0);
    assert.equal(
      frames[5][12],
      ["channel", "channel-enabled"].includes(fault)
        ? -1
        : fault === "channel-type"
          ? 8
          : 13,
    );
    assert.equal(
      frames[5][15],
      ["channel", "channel-enabled"].includes(fault) ? -1 : 16,
    );
    assert.equal(
      frames[5][6],
      ["channel", "channel-enabled", "channel-type"].includes(fault)
        ? -1
        : true,
    );
    assert.equal(frames[5][7], ["log", "log-info"].includes(fault) ? -1 : 2);
    assert.equal(frames[5][8], ["log", "log-info"].includes(fault) ? -1 : 10);
    for (const handle of ["channel", "publisher", "log"])
      assert.equal(
        closed.filter((value) => value === handle).length,
        fault === handle
          ? 0
          : handle === "log"
            ? fault === "deadline"
              ? 1
              : ["render-deadline", "projection-deadline"].includes(fault)
                ? 2
                : 3
            : 1,
      );
    if (fault === "interface-close") {
      assert.deepEqual(frames[5].slice(9, 12), [6, 6, 6]);
      assert.equal(cleanup.length, 5);
    }
    assert.equal(frames[1][0], 0);
    assert.equal(frames[2][0], 1);
    assert.equal(
      frames[1][1],
      fault === "query"
        ? "EvtQuery"
        : fault === "deadline"
          ? "deadline"
          : "EvtNext",
    );
    assert.equal(
      frames[1][2],
      fault === "deadline"
        ? 1460
        : fault === "query"
          ? 5
          : ["next", "partial-next", "partial-cleanup"].includes(fault)
            ? 50
            : 0,
    );
    assert.equal(frames[1][4], fault === "saturated");
    assert.equal(
      frames[1][5],
      ["event-close", "query-close", "partial-cleanup"].includes(fault) ? 6 : 0,
    );
    assert.equal(
      frames[3][0],
      ["context-close", "partial-cleanup"].includes(fault) ? 6 : 0,
    );
    assert.equal(
      closed.filter((handle) => handle.startsWith("query:")).length,
      ["query", "deadline"].includes(fault)
        ? 0
        : fault === "render-deadline"
          ? 1
          : 2,
    );
    assert.equal(
      closed.filter((handle) => handle === "context").length,
      ["context", "deadline"].includes(fault) ? 0 : 1,
    );
    assert.equal(
      cleanup.length > 0,
      [
        "event-close",
        "query-close",
        "context-close",
        "interface-close",
        "partial-cleanup",
        "close-zero",
      ].includes(fault),
    );
    assert.equal(
      frames[1][10],
      ["render-deadline", "deadline"].includes(fault)
        ? 1460
        : fault === "context"
          ? 5
          : fault === "render"
            ? 50
            : ["event-fields", "render-count", "render-size"].includes(fault)
              ? 13
              : 0,
    );
    const matches = ![
      "query",
      "empty",
      "next",
      "render",
      "event-fields",
      "other-pid",
      "other-logon",
      "stale",
      "future",
      "deadline",
      "render-deadline",
      "render-count",
      "render-size",
      "partial-next",
      "partial-cleanup",
      "render-zero",
    ].includes(fault);
    assert.equal(
      frames[1][7],
      ["context", "deadline"].includes(fault)
        ? -1
        : matches
          ? fault === "saturated"
            ? 8
            : 1
          : 0,
    );
    assert.equal(
      frames[1][8],
      ["context", "deadline"].includes(fault)
        ? -1
        : matches
          ? fault === "saturated"
            ? 120
            : fault === "short-batches"
              ? 3
              : 1
          : 0,
    );
    assert.deepEqual(api.command_delivery.rejected, [1, 2, 3, 4]);
    const row = optional.find(([format]) =>
      format.includes("operating-audit index="),
    );
    for (const [format, ...args] of optional) {
      let at = 0;
      const line = format.replace(/%(?:ll|l)?[usdx]/gu, () => {
        const value = args[at++];
        return String(typeof value === "boolean" ? Number(value) : value);
      });
      assert.equal(isObservation(Buffer.from(line)), true, line);
    }
    if (
      [
        "other-provider",
        "other-id",
        "other-keywords",
        "other-subject",
        "other-object-type",
        "other-sid",
      ].includes(fault)
    ) {
      const expected = {
        "other-provider": 1,
        "other-id": 2,
        "other-keywords": 2,
        "other-subject": 4,
        "other-object-type": 8,
        "other-sid": 4,
      }[fault];
      assert.equal(row[13], expected);
      assert.equal(
        row[11],
        true,
        "Correlated diagnostics cannot supply native acceptance",
      );
    }
    if (
      [
        "missing-field",
        "missing-provider",
        "missing-record",
        "numeric-range",
        "array-field",
        "bad-sid",
      ].includes(fault)
    ) {
      assert.equal(frames[2][10], 13);
      assert.equal(api.command_inspection_incomplete, true);
      const field =
        fault === "missing-provider" || fault === "array-field"
          ? 4
          : fault === "missing-record"
            ? 7
            : fault === "bad-sid"
              ? 8
              : 10;
      assert.equal(row[3] & (1 << field), 0);
    }
    if (fault === "failure-event") assert.equal(row[13], 0);
    if (fault === "projection-deadline") {
      assert.equal(frames[2][10], 1460);
      assert.equal(api.command_inspection_incomplete, true);
      assert.equal(
        optional.filter(([format]) => format.includes("operating-audit index="))
          .length,
        1,
      );
    }
    if (
      fault === null ||
      fault === "empty" ||
      fault === "short-batches" ||
      fault === "unrelated-first" ||
      fault === "undelivered"
    ) {
      assert.equal(
        frames[1][11],
        true,
        "Only ERROR_NO_MORE_ITEMS proves enumeration exhaustion",
      );
      assert.deepEqual(visibility, [true, true]);
    }
    if (
      [
        "log-rollover",
        "log-clear",
        "log-first-zero",
        "loss",
        "next",
        "partial-next",
        "partial-cleanup",
        "render-zero",
        "close-zero",
        "saturated",
        "output-bound",
      ].includes(fault)
    ) {
      assert.equal(visibility[0], false);
      assert.equal(api.command_inspection_incomplete, true);
    }
    if (fault === "unrelated-first") {
      assert.equal(
        row[1],
        1,
        "The unrelated 4688 record precedes the retained candidate",
      );
      assert.equal(
        optional.filter(([format]) => format.includes("operating-audit index="))
          .length,
        1,
      );
    }
    if (fault === "undelivered") {
      const rows = optional.filter(([format]) =>
        format.includes("operating-audit index="),
      );
      assert.equal(rows.length, 2);
      assert.equal(rows[0][16], true);
      assert.equal(rows[0][17], 0);
      assert.equal(rows[1][16], 1);
      assert.equal(rows[1][18], true);
    }
    if (fault === "other-logon") {
      assert.equal(
        row[11],
        true,
        "Retain original object candidates before logon selection",
      );
      assert.equal(row[16], false);
    }
    if (fault === "version") {
      assert.equal(row[14], 9);
      assert.equal(row[15], false);
    }
    if (fault === "both-keywords") {
      assert.equal(row[13], 0);
      assert.equal(row[15], false);
      assert.equal(row[16], false);
    }
    if (fault === "marker-first") {
      assert.equal(row[12], true);
      assert.equal(row[18], 0);
    }
    if (fault === "version-unavailable") {
      assert.equal(row[15], -1);
      assert.equal(visibility[0], false);
    }
    if (fault === "long-field") {
      const chunks = optional.filter(
        ([format, , field]) => format.includes("audit-value") && field === 4,
      );
      assert.ok(chunks.length > 1);
      assert.equal(chunks[0][6], false);
      assert.equal(chunks.at(-1)[6], true);
      assert.equal(
        Buffer.from(chunks.map((chunk) => chunk[7]).join(""), "hex").toString(
          "utf16le",
        ),
        "C:\\fixture\\" + "actor-λ".repeat(12) + ".exe",
      );
    }
    if (fault === "partial-cleanup") {
      assert.equal(
        frames[1][2],
        50,
        "Enumeration failure survives independent cleanup failures",
      );
      assert.equal(cleanup.length, 6);
      assert.equal(
        closed.filter((handle) => handle.startsWith("event:")).length,
        3,
      );
    }
    if (fault === "render-zero")
      assert.equal(
        frames[1][10],
        0,
        "A later render failure cannot replace the first zero error code",
      );
    if (fault === "close-zero") {
      assert.equal(
        frames[1][5],
        0,
        "Later closures cannot replace the first zero error code",
      );
      assert.equal(frames[1][6], "event");
    }
    if (fault === "log-first-zero")
      assert.equal(
        continuity[0][0],
        0,
        "The later log-property failure cannot replace the first zero error code",
      );
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
      command_delivery: {
        operating: false,
        sacls: [{}, {}],
        rejected: Array(4).fill(0),
      },
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

test("the owned audit ACE precedes retained SACL entries without changing their restoration authority", async () => {
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-command.h", import.meta.url),
      "utf8",
    ),
    start = source.indexOf("    win32_check(AddAuditAccessAceEx("),
    end = source.indexOf("\n  }\n}", start);
  assert.ok(start > 0 && end > start);
  const program = new Script(
    source
      .slice(start, end)
      .replace("unsigned j", "let j")
      .replace("ACE_HEADER *ace", "let ace")
      .replaceAll("->", ".")
      .replace("(void **)&ace", "value=>ace=value"),
  );
  for (const fault of [null, "empty", "audit", "read", "copy"]) {
    const baseline = [
        { type: "mandatory-label", AceSize: 20, bytes: "label-bytes" },
        { type: "inherited-audit", AceSize: 24, bytes: "inherited-bytes" },
      ],
      before = structuredClone(baseline),
      acl = [],
      old = { AceCount: baseline.length },
      operations = [];
    const build = () =>
      program.runInNewContext({
        i: 0,
        command_sacls: [acl],
        present: fault !== "empty",
        old,
        ACL_REVISION: 2,
        MAXDWORD: 0xffffffff,
        FILE_READ_DATA: 1,
        FILE_WRITE_DATA: 2,
        userSid: "command-user",
        TRUE: true,
        AddAuditAccessAceEx: (
          target,
          revision,
          flags,
          mask,
          sid,
          success,
          failure,
        ) => {
          assert.deepEqual(
            [target, revision, flags, mask, sid, success, failure],
            [acl, 2, 0, 3, "command-user", true, true],
          );
          if (fault === "audit") return false;
          target.push({ type: "owned-audit", mask, sid, success, failure });
          return true;
        },
        GetAce: (value, index, result) => {
          assert.equal(value, old);
          if (fault === "read" && index === 1) return false;
          result(baseline[index]);
          return true;
        },
        AddAce: (target, revision, position, ace, size) => {
          assert.deepEqual(
            [target, revision, position, size],
            [acl, 2, 0xffffffff, ace.AceSize],
          );
          if (fault === "copy" && ace === baseline[1]) return false;
          target.push(structuredClone(ace));
          return true;
        },
        win32_check: (ok, operation) => {
          operations.push(operation);
          if (!ok) throw new Error(operation);
        },
      });
    if (fault && fault !== "empty") {
      const operation = `command-audit-${fault === "audit" ? "ace" : `ace-${fault}`}`;
      assert.throws(build, { message: operation });
      assert.equal(operations.at(-1), operation);
    } else {
      build();
      assert.deepEqual(acl, [
        {
          type: "owned-audit",
          mask: 3,
          sid: "command-user",
          success: true,
          failure: true,
        },
        ...(fault === "empty" ? [] : before),
      ]);
    }
    assert.deepEqual(
      baseline,
      before,
      "The independent restorer retains the original SACL",
    );
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
      settlementDiagnostic: () => {},
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
      let controlStderr = null, controlExitCode, phase = "command-observation", failurePhase;
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
    "diagnostic",
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
      diagnostics = [],
      logged = [],
      log = createNativeDiagnosticWriter((bytes) => {
        if (fault === "diagnostic") throw new Error("Diagnostic sink closed");
        logged.push(bytes);
      }),
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
        nativeDiagnostic: (owner, value) => {
          assert.equal(owner, "windows-command:settlement");
          diagnostics.push(JSON.parse(value.stderr));
          log(owner, value);
        },
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
      fault && fault !== "diagnostic" ? "UNCERTAIN" : "PASS",
      JSON.stringify(result.cleanup),
    );
    if (fault && fault !== "diagnostic")
      assert.deepEqual(result.cleanup.cause, cleanup.feasibilityCleanup);
    else {
      assert.equal(result.cleanup.independent, true);
      assert.equal(result.cleanup.emergency, false);
      assert.deepEqual(
        diagnostics.map((value) => value.phase),
        [
          "broker",
          "independent-domain-verification",
          "capture-close",
          "restoration",
          "restoration-settlement",
        ],
      );
      assert.equal(diagnostics[2].code, 0);
      assert.equal(diagnostics[4].fixturesRemoved, true);
      for (const value of diagnostics)
        if (fault !== "diagnostic")
          assert.ok(
            Buffer.concat(logged)
              .toString()
              .includes(`"phase":"${value.phase}"`),
          );
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
