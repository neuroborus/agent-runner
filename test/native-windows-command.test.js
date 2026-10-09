import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { PassThrough, Writable } from "node:stream";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import {
  runWindowsFeasibilityCommand,
  windowsCommandEnvironment,
  settleWindowsCommandCustody,
  windowsCommandAuditRead,
  windowsCommandBrokerCoverage,
  createWindowsAuditDecoder,
  windowsCommandCleanupSnapshot,
  openWindowsCommandWatcher,
} from "../ci/native/win32/index.js";
import {
  feasibilityCommandParameters,
  openFeasibilityCommand,
} from "../ci/native/providers/index.js";
import { observationDigest } from "../ci/native/index.js";

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
async function brokerCapture(prepared) {
  const fields = {
    Provider: "Microsoft-Windows-Security-Auditing",
    Channel: "Security",
    EventID: "4663",
    Version: "0",
    Keywords: "0x8020000000000000",
    TimeCreated: "2026-10-09T00:00:00.0000100Z",
    EventRecordID: "1",
    ObjectType: "File",
    ProcessId: String(prepared.observer.pid),
    ObjectName: prepared.gateFile,
    SubjectUserSid: identity.userSid,
    AccessMask: "0x1",
    SubjectLogonId: "0x1",
  };
  const native = {
      kind: "event",
      fields: Object.entries(fields).map(([name, text]) => ({
        nameHex: Buffer.from(name, "utf16le").toString("hex"),
        hex: Buffer.from(text, "utf16le").toString("hex"),
      })),
    },
    raw = Buffer.from(
      `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="${fields.Provider}"/><EventID>${fields.EventID}</EventID><Version>${fields.Version}</Version><Keywords>${fields.Keywords}</Keywords><TimeCreated SystemTime="${fields.TimeCreated}"/><EventRecordID>${fields.EventRecordID}</EventRecordID><Channel>${fields.Channel}</Channel></System><EventData>${Object.entries(
        fields,
      )
        .filter(
          ([name]) =>
            ![
              "Provider",
              "Channel",
              "EventID",
              "Version",
              "Keywords",
              "TimeCreated",
              "EventRecordID",
            ].includes(name),
        )
        .map(([k, v]) => `<Data Name="${k}">${v}</Data>`)
        .join("")}</EventData></Event>\0`,
      "utf16le",
    ),
    decoded = windowsCommandAuditRead(native),
    versions = [4656, 4663, 5152, 5156, 5157].map((id) => ({
      id,
      versions: [0],
    })),
    decoder = createWindowsAuditDecoder(
      { xml: async () => decoded.native },
      {
        sdkSha256: PIN,
        abiSha256: PIN,
        versions,
        mappingSha256: observationDigest(versions),
      },
    ),
    epoch =
      (BigInt(Date.parse("2026-10-09T00:00:00Z")) + 11644473600000n) * 10000n,
    barrier = (sequence, records, time) => {
      const frame = Buffer.alloc(20);
      frame.writeUInt32LE(0xfffffffe);
      frame.writeUInt32LE(sequence, 4);
      frame.writeBigUInt64LE(time, 8);
      frame.writeUInt32LE(records, 16);
      return frame;
    },
    frame = Buffer.alloc(4);
  frame.writeUInt32LE(raw.length);
  await decoder.push(Buffer.alloc(4));
  await decoder.push(barrier(1, 0, epoch));
  await decoder.push(Buffer.concat([frame, raw]));
  await decoder.push(barrier(2, 1, epoch + 200n));
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
      effective: { available: true, success: true },
      gate,
    };
  prepared.original = { files: [gate, gate, gate, gate] };
  return {
    before: inspected,
    after: structuredClone(inspected),
    captureComplete: true,
    start: { sequence: 1, time: epoch.toString(), records: 0 },
    end: { sequence: 2, time: (epoch + 200n).toString(), records: 1 },
    events: decoder
      .state()
      .events.map((event) => ({ ...event, logonId: decoded.logonId })),
  };
}
function alter(value, key, replacement) {
  const parts = key.split("."),
    last = parts.pop();
  parts.reduce((v, part) => v[part], value)[last] = replacement;
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
    coverage: async () => {
      calls.push("coverage");
      custody = true;
      return brokerCapture(prepared);
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
    "coverage",
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

test("system-success disabled admits effective per-user broker coverage only with native delivery", async () => {
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
  assert.deepEqual(f.calls.slice(0, 3), ["prepare", "coverage", "schema"]);
});

test("unavailable policy or missing/mismatched delivery blocks every Codex probe and settles custody", async () => {
  for (const [key, value] of [
    ["before.effective.available", false],
    ["after.effective.success", false],
    ["events", []],
    ["events.0.raw.pid", 999],
    ["events.0.raw.subjectSid", "S-1-5-21-10-20-30-1002"],
    ["events.0.logonId", "0000000000000002"],
    ["events.0.raw.accessMask", 2],
    ["events.0.raw.target", "C:\\fixture\\other"],
    ["events.0.time", "0"],
  ]) {
    const f = fixture(({ effects }) => {
        const capture = effects.coverage;
        effects.coverage = async () => {
          const o = await capture();
          alter(o, key, value);
          if (key === "events") o.end.records = 0;
          return o;
        };
      }),
      result = await f.run();
    assert.equal(result.status, "BLOCKED");
    assert.equal(result.cause.code, "prerequisite-unavailable");
    assert.equal(result.cleanup.status, "PASS");
    assert.deepEqual(f.calls, ["prepare", "coverage", "retire"]);
    assert.deepEqual(f.requests, []);
  }
});

test("coverage binds the original administrative token and held gate, not an inclusion or RPC claim", async () => {
  const prepared = {
      nonce: "a".repeat(32),
      observer: identity,
      gateFile: "C:\\fixture\\gate",
    },
    complete = await brokerCapture(prepared);
  assert.match(
    windowsCommandBrokerCoverage(prepared, complete),
    /^[a-f0-9]{64}$/u,
  );
  assert.throws(() => windowsCommandBrokerCoverage(prepared, true));
  for (const [key, value] of [
    ["after.identity.creationTime", "102"],
    ["after.token.tokenId", "00000000:00000004"],
    ["after.token.modifiedId", "00000000:00000004"],
    ["before.token.details.integrity", 8192],
    ["before.token.details.restricted", true],
    ["after.gate.daclSha256", sha("changed")],
    ["captureComplete", false],
    ["end.sequence", 3],
  ]) {
    const o = structuredClone(complete);
    alter(o, key, value);
    assert.throws(() => windowsCommandBrokerCoverage(prepared, o));
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
  assert.match(source, /ReOpenFile\(command_files\[3\],GENERIC_READ/u);
  for (const operation of ["V", "A"])
    assert.match(
      source,
      new RegExp(
        `strcmp\\(line,"${operation}"\\).*?need\\(command_coverage_admitted\\)`,
        "u",
      ),
    );
});

test("partial setup and interrupted coverage preserve the first cause and separate settlement uncertainty", async () => {
  for (const stage of ["partial-installation", "transport", "interruption"]) {
    const f = fixture(({ effects, signals }) => {
        const capture = effects.coverage;
        effects.coverage = async () => {
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
    assert.deepEqual(f.calls.slice(0, 2), ["prepare", "coverage"]);
  }
  const source = await readFile(
      new URL(
        "../ci/native/win32/feasibility-command-effects.js",
        import.meta.url,
      ),
      "utf8",
    ),
    coverage = source.slice(
      source.indexOf("async coverage("),
      source.indexOf("async schema("),
    );
  assert.ok(
    coverage.indexOf("cleanupReader.initialize(") <
      coverage.indexOf('call("I")'),
  );
  assert.ok(
    coverage.indexOf("readerVerifier = await watch(") <
      coverage.indexOf('call("I")'),
  );
  assert.ok(
    coverage.indexOf("windowsCommandBrokerCoverage(") <
      coverage.indexOf('call("M")'),
  );
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
  assert.equal(finish.match(/command_sd\(null,SE_KERNEL_OBJECT/gu)?.length, 2);
  assert.match(
    source,
    /i==3\?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION/u,
  );
  assert.match(
    finish,
    /GetSecurityDescriptorControl\(baselines\[i\],&control,&revision\)/u,
  );
  for (const kind of ["DACL", "SACL"]) {
    assert.match(
      finish,
      new RegExp(
        `control&SE_${kind}_PROTECTED\\?PROTECTED_${kind}_SECURITY_INFORMATION:UNPROTECTED_${kind}_SECURITY_INFORMATION`,
        "u",
      ),
    );
  }
  assert.match(
    finish,
    /\(control\^actualControl\)&\(SE_DACL_PROTECTED\|SE_SACL_PROTECTED\)/u,
  );
});

test("native watcher stream failures preserve their cause; recorded exit cannot replace a retirement witness", async () => {
  const launch = (failure, terminal) => () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    const close = (code) => {
      child.stdout.end();
      child.stderr.end();
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
