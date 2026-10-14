import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { Script } from "node:vm";
import {
  DARWIN_STARTUP_TRACE_INTENT,
  openDarwinStartupTrace,
} from "../ci/native/darwin/startup-trace.js";
import {
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../ci/native/index.js";
import {
  darwinFeasibilityCause,
  darwinFeasibilityIdentityArguments,
  darwinFeasibilityPhases,
  darwinFeasibilityPolicy,
  openDarwinFeasibilitySession,
  runDarwinFeasibilityArgv,
  runDarwinFeasibilityStartup,
  darwinStartupCrash,
  darwinStartupDenial,
  readDarwinStartupCrash,
  readDarwinStartupDenial,
} from "../ci/native/darwin/index.js";
import {
  LITERAL_ARGUMENTS,
  unavailableFeasibilityResults,
  assessFeasibilityReport,
  renderFeasibilitySummary,
} from "../ci/native/feasibility/index.js";

const SHA = "a".repeat(64),
  FIXTURE_SHA = "b".repeat(64);

test("Darwin publishes selected unusable crash and log bytes before strict attribution rejects them", async () => {
  const captured = [];
  const f = observationFixture();
  f.bytes = Buffer.from("unclassified crash contents");
  const log = '{"eventMessage":"unclassified log contents"}';
  f.options.run = async () => ({
    stdout: log,
    stderr: "unclassified log stderr",
  });
  await withNativeDiagnostics(
    async () => {
      assert.equal(
        (await readDarwinStartupCrash(f.binding, f.options)).status,
        "unusable",
      );
      const diagnosis = await readDarwinStartupDenial(f.binding, f.options);
      assert.equal(diagnosis.status, "unusable");
      assert.equal(diagnosis.reason, "timestamp-missing");
    },
    createNativeDiagnosticWriter((chunk) => captured.push(chunk)),
  );
  const output = Buffer.concat(captured);
  assert.ok(output.includes(f.bytes));
  assert.ok(output.includes(Buffer.from(log)));
  assert.match(output.toString(), /unclassified log stderr/u);
  assert.equal(f.closed, f.opened);
});
const EXEC_PHASES = [
  "policy-enter",
  "policy-applied",
  "exec-enter",
  "fixture-main",
];
const markers = (phases) =>
  phases.map((phase) => `native-darwin-phase: phase=${phase}\n`).join("");
const observationRejection = (kind, reason, status = "unusable") => ({
  status,
  kind,
  reason,
});
const imageFacts = (
  form,
  expectedFilename = false,
  expectedDirectory = false,
) => ({
  form,
  exactPath: false,
  expectedFilename,
  expectedDirectory,
});

test("Darwin kernel diagnosis binds fixture PID and time and discards private log tails", () => {
  const startedAt = Date.parse("2026-10-10T00:00:00Z"),
    binding = {
      pid: 42,
      image: "/fixture/build/argv-fixture",
      startedAt,
      endedAt: startedAt + 2000,
    },
    event = {
      timestamp: "2026-10-10T00:00:01Z",
      processID: 0,
      senderImagePath: "/System/Library/Extensions/Sandbox.kext/Sandbox",
      eventMessage:
        "Sandbox: argv-fixture(42) deny(1) file-read-data /private/fixture",
    };
  const encode = (value) => JSON.stringify(value) + "\n";
  assert.equal(darwinStartupDenial(encode(event), binding), "file-read-data");
  assert.equal(
    darwinStartupDenial(
      encode({
        ...event,
        eventMessage:
          "Sandbox: argv-fixture(42) deny(1) system-mac-syscall vnguard",
      }),
      binding,
    ),
    "syscall-vnguard",
  );
  for (const value of [
    { ...event, timestamp: "2026-10-10T00:01:00Z" },
    { ...event, processID: 99 },
    { ...event, eventMessage: event.eventMessage.replace("(42)", "(43)") },
    { ...event, eventMessage: "unrecognized private log text" },
  ])
    assert.equal(darwinStartupDenial(encode(value), binding), null);
  assert.equal(darwinStartupDenial(encode(event) + "partial", binding), null);
  assert.equal(darwinStartupDenial("x".repeat(65537), binding), null);
  const cause = darwinFeasibilityCause("argv", {
    nativeOperation: "exec",
    signal: "SIGABRT",
    nativeDenial: "file-read-data",
  });
  assert.match(cause.detail, /observed-denial=file-read-data$/u);
  assert.equal(cause.code, "crash");
  assert.doesNotMatch(cause.detail, /private\/fixture/u);
  for (const [nativeDenial, expected] of [
    [{ status: "empty" }, "log-read=empty"],
    [{ status: "command-failed", exitCode: 64 }, "log-read=command-failed:64"],
    [{ status: "unmatched" }, "log-read=unmatched"],
  ])
    assert.ok(
      darwinFeasibilityCause("argv", {
        nativeOperation: "exec",
        signal: "SIGABRT",
        nativeDenial,
      }).detail.endsWith(expected),
    );
});

test("Darwin crash diagnosis requires the exact fixture PID, image and launch window and publishes no report contents", () => {
  const startedAt = Date.parse("2026-10-10T00:00:00Z");
  const binding = {
    pid: 42,
    image: "/fixture/build/argv-fixture",
    identity: {
      ...IDENTITY,
      startSeconds: startedAt / 1000,
      startMicroseconds: 0,
    },
    imageUUID: "00112233-4455-6677-8899-aabbccddeeff",
    startedAt,
    endedAt: startedAt + 2000,
  };
  const report = {
    pid: 42,
    procPath: binding.image,
    procLaunch: "2026-10-10T00:00:00Z",
    usedImages: [{ path: binding.image, uuid: binding.imageUUID }],
    captureTime: "2026-10-10T00:00:01Z",
    exception: { signal: "SIGABRT" },
    termination: { namespace: "DYLD", code: 1 },
    faultingThread: 0,
    threads: [{ frames: [{ symbol: "__abort_with_payload" }] }],
    privateDetails: "/private/crash-details",
  };
  const text = (value) =>
    JSON.stringify({ bug_type: "309" }) + "\n" + JSON.stringify(value);
  const crash = darwinStartupCrash(text(report), binding);
  assert.deepEqual(crash, {
    namespace: "DYLD",
    code: 1,
    frame: "abort-payload",
  });
  const cause = darwinFeasibilityCause("argv-exec", {
    signal: "SIGABRT",
    nativeOperation: "exec",
    nativePhases: EXEC_PHASES.slice(0, 3),
    nativeCrash: crash,
  });
  assert.equal(cause.code, "crash");
  assert.match(cause.detail, /crash=DYLD:1:abort-payload$/u);
  assert.doesNotMatch(
    JSON.stringify(cause),
    /\/fixture|\/private|privateDetails/u,
  );
  for (const mutation of [
    { pid: 43 },
    { procPath: "/other/build/argv-fixture" },
    { procLaunch: "2026-10-09T23:59:59Z" },
    {
      usedImages: [
        { path: binding.image, uuid: "11112233-4455-6677-8899-aabbccddeeff" },
      ],
    },
    { usedImages: [{ path: "/different/image", uuid: binding.imageUUID }] },
    { captureTime: "2026-10-09T23:59:59Z" },
    { captureTime: "2026-10-10T00:00:03Z" },
    { exception: { signal: "SIGSEGV" } },
    { termination: { namespace: "UNRECOGNIZED", code: 1 } },
    { termination: { namespace: "DYLD", code: 65536 } },
  ])
    assert.equal(
      darwinStartupCrash(text({ ...report, ...mutation }), binding),
      null,
    );
  assert.equal(
    darwinStartupCrash(text(report), { ...binding, startedAt: NaN }),
    null,
  );
  for (const mutation of [
    { identity: { ...binding.identity, pid: 43 } },
    { identity: { ...binding.identity, startMicroseconds: 1000 } },
    { identity: undefined },
    { imageUUID: undefined },
  ])
    assert.equal(
      darwinStartupCrash(text(report), { ...binding, ...mutation }),
      null,
    );
  assert.equal(darwinStartupCrash(text(report) + "trailing", binding), null);
  assert.equal(
    darwinStartupCrash("x".repeat(2 * 1024 * 1024 + 1), binding),
    null,
  );
  assert.equal(
    darwinStartupCrash(text({ ...report, faultingThread: 1 }), binding).frame,
    null,
  );
  for (const status of ["image-changed", "read-failed"])
    assert.match(
      darwinFeasibilityCause("argv", {
        signal: "SIGABRT",
        nativeOperation: "exec",
        nativeCrash: { status },
      }).detail,
      new RegExp(`crash-read=${status}$`, "u"),
    );
});

function observationFixture() {
  const image = Buffer.alloc(108);
  for (const [offset, value] of [
    [0, 0xfeedfacf],
    [4, 0x01000007],
    [12, 2],
    [16, 3],
    [20, 72],
    [32, 0xe],
    [36, 32],
    [40, 12],
    [64, 0x1d],
    [68, 16],
    [72, 104],
    [76, 4],
    [80, 0x1b],
    [84, 24],
  ])
    image.writeUInt32LE(value, offset);
  image.write("/usr/lib/dyld", 44);
  Buffer.from("00112233445566778899aabbccddeeff", "hex").copy(image, 88);
  const binding = {
    pid: IDENTITY.pid,
    identity: IDENTITY,
    image: "/fixture/build/argv-fixture",
    sha256: createHash("sha256").update(image).digest("hex"),
    startedAt: 100000,
    endedAt: 102000,
  };
  const report = {
    pid: 43,
    procPath: binding.image,
    procLaunch: "1970-01-01T00:01:40.000001Z",
    captureTime: new Date(101000).toISOString(),
    usedImages: [
      { path: binding.image, uuid: "00112233-4455-6677-8899-aabbccddeeff" },
    ],
    exception: { signal: "SIGABRT" },
    termination: { namespace: "DYLD", code: 1 },
  };
  const encode = (value) => Buffer.from("{}\n" + JSON.stringify(value));
  const f = {
    binding,
    report,
    encode,
    image,
    names: ["argv-fixture_case.ips"],
    bytes: encode(report),
    watchers: [],
    opened: 0,
    closed: 0,
    canceled: 0,
    reads: 0,
  };
  const failure = (code) =>
    Object.assign(new Error("private observation details"), { code });
  const timer = {};
  f.options = {
    isMatchingCI: true,
    read: async () => {
      if (f.imageReadError || ++f.reads === f.readErrorAt) throw failure("EIO");
      const bytes = Buffer.from(image);
      if (f.reads > 1 && f.imageChanged) bytes[105] ^= 1;
      return bytes;
    },
    now: () => 101000,
    schedule: (expire, delay) => {
      assert.equal(delay, 8000);
      f.expire = expire;
      return timer;
    },
    cancel: (value) => {
      assert.equal(value, timer);
      f.canceled++;
    },
    observe: (directory, settings, publish) => {
      f.publish = publish;
      if (f.watchError) throw failure(f.watchError);
      const watcher = Object.assign(new EventEmitter(), {
        closed: 0,
        close() {
          this.closed++;
          if (f.watchCloseError) throw failure("EIO");
        },
      });
      f.watchers.push(watcher);
      return watcher;
    },
    list: async () => {
      f.expire();
      if (f.listError) throw failure(f.listError);
      return f.names;
    },
    openReport: async () => {
      if (f.openError) throw failure("EIO");
      f.opened++;
      let stats = 0;
      return {
        stat: async () => {
          if (f.statError) throw failure("EIO");
          return {
            size: f.bytes.length,
            mtimeMs: ++stats > 1 && f.changing ? 2 : 1,
            isFile: () => f.isRegular !== false,
          };
        },
        read: async (bytes) => {
          if (f.reportReadError) throw failure("EIO");
          f.bytes.copy(bytes);
          return { bytesRead: bytes.length - (f.short ? 1 : 0) };
        },
        close: async () => {
          f.closed++;
          if (f.closeError) throw failure("EIO");
        },
      };
    },
  };
  return f;
}

test("Darwin privacy crash images require verified argv bytes and one consistent exact representation", async () => {
  const privacyPath = "/Users/USER/*/argv-fixture",
    literalPath = "/fixture/build/argv-fixture",
    uuid = "00112233-4455-6677-8899-aabbccddeeff";
  const reportImage = (path, imageUUID = uuid) => ({ path, uuid: imageUUID });
  const fixture = (mutation = {}) => {
    const f = observationFixture();
    f.report = {
      ...f.report,
      pid: f.binding.pid,
      procPath: privacyPath,
      usedImages: [reportImage(privacyPath)],
      termination: { namespace: "<0x23>", code: 2 },
      faultingThread: 0,
      threads: [{ frames: [{ symbol: "__abort_with_payload" }] }],
      ...mutation,
    };
    f.bytes = f.encode(f.report);
    return f;
  };
  const inspect = async (f) => {
    const observed = await readDarwinStartupCrash(f.binding, f.options);
    assert.equal(f.closed, f.opened);
    assert.equal(f.canceled, 1);
    assert.ok(f.watchers.every((watcher) => watcher.closed === 1));
    return observed;
  };
  const expected = {
    namespace: "LIBIGNITION",
    code: 2,
    frame: "abort-payload",
  };
  for (const namespace of ["LIBIGNITION", "<0x23>"]) {
    const f = fixture({ termination: { namespace, code: 2 } });
    assert.equal(
      darwinStartupCrash(f.bytes.toString(), { ...f.binding, imageUUID: uuid }),
      null,
    );
    assert.equal(
      darwinStartupCrash(f.bytes.toString(), {
        ...f.binding,
        image: privacyPath,
        imageUUID: uuid,
      }),
      null,
    );
    const observed = await inspect(f);
    assert.deepEqual(observed, expected);
    assert.equal(f.reads, 2);
    const cause = darwinFeasibilityCause("argv-exec", {
      signal: "SIGABRT",
      nativeOperation: "exec",
      nativePhases: EXEC_PHASES.slice(0, 3),
      nativeCrash: observed,
    });
    assert.match(cause.detail, /crash=LIBIGNITION:2:abort-payload$/u);
    assert.ok(Buffer.byteLength(cause.detail) <= 256);
    assert.doesNotMatch(JSON.stringify(cause), /\/Users|\/fixture|00112233/u);
  }
  const sibling = fixture();
  sibling.binding.alternatives = [
    { image: sibling.binding.image, sha256: sibling.binding.sha256 },
  ];
  sibling.binding.image = "/fixture/build/helper";
  assert.deepEqual(await inspect(sibling), expected);
  const ordinary = fixture({
    procPath: literalPath,
    usedImages: [reportImage(literalPath)],
  });
  assert.deepEqual(await inspect(ordinary), expected);
  const loaded = fixture({
    usedImages: [
      reportImage(privacyPath),
      reportImage("/other/image", "11112233-4455-6677-8899-aabbccddeeff"),
    ],
  });
  assert.deepEqual(await inspect(loaded), expected);
  for (const procPath of [
    "/Users/USER/other/argv-fixture",
    "/Users/OTHER/*/argv-fixture",
    "/Users/USER/**/argv-fixture",
    "/Users/USER/*/helper",
    "/Users/USER/*/argv-fixture/",
    "Users/USER/*/argv-fixture",
    "/Users/USER/*/../argv-fixture",
  ]) {
    const f = fixture({ procPath, usedImages: [reportImage(procPath)] });
    assert.equal((await inspect(f)).reason, "image");
  }
  for (const [mutation, reason] of [
    [{ usedImages: [reportImage("/other/image")] }, "uuid"],
    [{ usedImages: [reportImage(literalPath)] }, "uuid"],
    [{ procPath: literalPath }, "uuid"],
    [
      { usedImages: [reportImage(privacyPath), reportImage(privacyPath)] },
      "uuid",
    ],
    [
      { usedImages: [reportImage(privacyPath), reportImage(literalPath)] },
      "uuid",
    ],
    [
      { usedImages: [reportImage(privacyPath), reportImage("/other/image")] },
      "uuid",
    ],
    [
      {
        procPath: literalPath,
        usedImages: [reportImage(literalPath), reportImage(literalPath)],
      },
      "uuid",
    ],
    [
      {
        usedImages: [
          reportImage(privacyPath, "11112233-4455-6677-8899-aabbccddeeff"),
        ],
      },
      "uuid",
    ],
    [
      {
        usedImages: [
          reportImage(privacyPath),
          reportImage(privacyPath, "11112233-4455-6677-8899-aabbccddeeff"),
        ],
      },
      "uuid",
    ],
    [{ pid: IDENTITY.pid + 1 }, "pid"],
    [{ procLaunch: "1970-01-01T00:01:40.000002Z" }, "birth"],
    [{ captureTime: "1970-01-01T00:01:39.999999Z" }, "window"],
    [{ captureTime: "1970-01-01T00:01:49.000001Z" }, "window"],
    [{ exception: { signal: "SIGSEGV" } }, "signal"],
    ...["<0X23>", "0x23", "35", "libignition"].map((namespace) => [
      { termination: { namespace, code: 2 } },
      "termination",
    ]),
  ]) {
    const f = fixture(mutation);
    const observed = await inspect(f);
    assert.equal(observed.reason, reason);
    assert.equal(observed.namespace, undefined);
  }
  const helper = fixture();
  helper.binding.image = "/fixture/build/helper";
  helper.names = ["helper_case.ips"];
  assert.equal((await inspect(helper)).reason, "image");
  const changed = fixture();
  changed.imageChanged = true;
  assert.deepEqual(await inspect(changed), { status: "image-changed" });
  const unverified = fixture();
  unverified.binding.sha256 = "a".repeat(64);
  assert.deepEqual(
    await readDarwinStartupCrash(unverified.binding, unverified.options),
    { status: "image-changed" },
  );
  assert.equal(unverified.opened, 0);
  const closure = fixture();
  closure.closeError = true;
  assert.deepEqual(await inspect(closure), {
    ...expected,
    observationFailure: "read-failed",
  });
});

test("Darwin startup observations normalize timestamp representations without birth or window tolerance", async () => {
  const f = observationFixture(),
    binding = {
      ...f.binding,
      identity: { ...IDENTITY, startMicroseconds: 123456 },
      imageUUID: "00112233-4455-6677-8899-aabbccddeeff",
    },
    report = {
      ...f.report,
      pid: binding.pid,
      captureTime: "1970-01-01 00:01:41.000000 +0000",
    };
  for (const procLaunch of [
    "1970-01-01T00:01:40.123456Z",
    "1970-01-01 00:01:40.123456 +0000",
    "1970-01-01 01:01:40.123456+0100",
    "1969-12-31T23:01:40.123456-01:00",
  ]) {
    const text =
      '{"bug_type":"309"}\r\n' +
      JSON.stringify({ ...report, procLaunch }, null, 2);
    assert.deepEqual(darwinStartupCrash(text, binding), {
      namespace: "DYLD",
      code: 1,
      frame: null,
    });
  }
  for (const [mutation, kind, reason] of [
    [{ pid: 43 }, "binding-rejection", "pid"],
    [{ procPath: "/other/build/argv-fixture" }, "binding-rejection", "image"],
    [
      { procLaunch: "1970-01-01T00:01:40.123455Z" },
      "binding-rejection",
      "birth",
    ],
    [{ procLaunch: "1970-01-01T00:01:40.123Z" }, "binding-rejection", "birth"],
    [
      {
        usedImages: [
          { path: binding.image, uuid: "11112233-4455-6677-8899-aabbccddeeff" },
        ],
      },
      "binding-rejection",
      "uuid",
    ],
    [
      { captureTime: "1970-01-01T00:01:49.000001Z" },
      "binding-rejection",
      "window",
    ],
    [{ captureTime: undefined }, "crash-record", "timestamp-missing"],
    [{ procLaunch: "invalid" }, "crash-record", "timestamp-format"],
    [
      { captureTime: "1970-02-30T00:00:00Z" },
      "crash-record",
      "timestamp-calendar",
    ],
    [
      { procLaunch: "1970-01-01T00:01:40.123456" },
      "crash-record",
      "timestamp-timezone",
    ],
    [
      { procLaunch: "1970-01-01T00:01:40.1234567Z" },
      "crash-record",
      "timestamp-precision",
    ],
    [
      { procLaunch: "1970-01-01T00:01:40.123456+00:60" },
      "crash-record",
      "timestamp-timezone",
    ],
    [{ procPath: "\ud800" }, "crash-record", "path"],
  ]) {
    const fixture = observationFixture();
    fixture.binding = binding;
    fixture.bytes = fixture.encode({
      ...report,
      procLaunch: "1970-01-01T00:01:40.123456Z",
      ...mutation,
    });
    const observed = await readDarwinStartupCrash(
      fixture.binding,
      fixture.options,
    );
    assert.deepEqual(observed, {
      ...observationRejection(
        kind,
        reason,
        kind === "crash-record" ? "unusable" : "unmatched",
      ),
      ...(reason === "image"
        ? { imageFacts: imageFacts("absolute", true) }
        : {}),
    });
    const cause = darwinFeasibilityCause("argv-exec", {
      nativeOperation: "exec",
      signal: "SIGABRT",
      nativeCrash: observed,
    });
    assert.equal(cause.code, "crash");
    assert.ok(
      cause.detail.endsWith(
        `${kind}=${reason}${reason === "image" ? "[a010]" : ""}`,
      ),
    );
    assert.doesNotMatch(
      JSON.stringify(cause),
      /\/other|\/fixture|00112233|1970-/u,
    );
    assert.equal(fixture.closed, fixture.opened);
  }
  const text = f
    .encode({
      ...report,
      procLaunch: "1970-01-01T00:01:40.123456Z",
      captureTime: "1970-01-01T00:01:42.000001Z",
    })
    .toString();
  assert.equal(darwinStartupCrash(text, binding), null);
  assert.deepEqual(
    darwinStartupCrash(
      f
        .encode({ ...report, procLaunch: "1970-01-01T00:01:40.1234Z" })
        .toString(),
      {
        ...binding,
        identity: { ...binding.identity, startMicroseconds: 123400 },
      },
    ),
    { namespace: "DYLD", code: 1, frame: null },
  );

  const sibling = observationFixture();
  sibling.binding.alternatives = [
    { image: "/fixture/build/helper", sha256: sibling.binding.sha256 },
  ];
  sibling.names = ["helper_case.ips"];
  sibling.bytes = sibling.encode({
    ...sibling.report,
    pid: IDENTITY.pid,
    procPath: sibling.binding.alternatives[0].image,
    usedImages: [
      {
        path: sibling.binding.alternatives[0].image,
        uuid: binding.imageUUID.toUpperCase(),
      },
    ],
  });
  assert.deepEqual(
    await readDarwinStartupCrash(sibling.binding, sibling.options),
    { namespace: "DYLD", code: 1, frame: null },
  );
});

test("Darwin crash mismatches retain both held-image comparisons without aliases or abort attribution", async () => {
  for (const [
    image,
    rejectionPair,
    relationshipPair,
    directory = "/fixture/build",
  ] of [
    ["/other/build/argv-fixture", "image,image", "a010,a000"],
    ["/fixture/build/argv-fixture", "uuid,image", "none,a001"],
    ["/fixture/build/helper", "image,uuid", "a001,none"],
    ["argv-fixture", "image,image", "r010,r000"],
    ["", "image,image", "e000,e000"],
    ["/fixture//build/argv-fixture", "image,image", "a010,a000"],
    ["/fixture/build/argv-fixture/", "image,image", "a000,a000"],
    ["argv-fixture", "image,image", "r010,r000", ""],
    ["", "image,image", "e000,e000", ""],
    ["/", "image,image", "a001,a001", ""],
  ]) {
    const reasons = rejectionPair.split(","),
      codes = relationshipPair.split(","),
      facts = codes.map((code) =>
        code === "none"
          ? null
          : imageFacts(
              { a: "absolute", r: "relative", e: "empty" }[code[0]],
              code[2] === "1",
              code[3] === "1",
            ),
      ),
      suffixes = codes.map((code) => (code === "none" ? "" : `[${code}]`));
    const f = observationFixture();
    f.binding.image = `${directory}/argv-fixture`;
    f.binding.alternatives = [
      { image: `${directory}/helper`, sha256: f.binding.sha256 },
    ];
    f.bytes = f.encode({
      ...f.report,
      pid: f.binding.pid,
      procPath: image,
      usedImages: [
        { path: image, uuid: "11112233-4455-6677-8899-aabbccddeeff" },
      ],
    });
    const observed = await readDarwinStartupCrash(f.binding, f.options);
    const checks = ["argv-fixture", "helper"].map((image, index) => ({
      image,
      reason: reasons[index],
      ...(facts[index] ? { imageFacts: facts[index] } : {}),
    }));
    assert.deepEqual(observed.imageChecks, checks);
    assert.equal(
      observed.reason,
      reasons.every((reason) => reason === "image") ? "image" : "uuid",
    );
    const cause = darwinFeasibilityCause("argv", {
      nativeOperation: "exec",
      signal: "SIGABRT",
      nativeCrash: observed,
    });
    assert.equal(cause.code, "crash");
    assert.ok(
      cause.detail.includes(
        `images=${checks.map(({ image, reason }, index) => `${image}:${reason}${suffixes[index]}`).join(",")}`,
      ),
    );
    assert.doesNotMatch(cause.detail, /\/other|\/fixture|11112233|crash=DYLD/u);
    assert.equal(f.closed, f.opened);
    for (const imageChecks of [
      [{ ...checks[0], privatePath: "/private/image" }, checks[1]],
      [checks[0], checks[0]],
      [{ image: "foreign", reason: "image" }, checks[1]],
      [{ image: "argv-fixture", reason: "private" }, checks[1]],
      ...[
        { form: "private" },
        { exactPath: true },
        { expectedFilename: "private" },
        { privatePath: "/private/image" },
        { expectedFilename: true, expectedDirectory: true },
        { form: "relative", expectedDirectory: true },
        { form: "empty", expectedFilename: true },
      ].map((invalid) => [
        { ...checks[0], imageFacts: { ...imageFacts("absolute"), ...invalid } },
        checks[1],
      ]),
    ])
      assert.doesNotMatch(
        darwinFeasibilityCause("argv", {
          nativeOperation: "exec",
          signal: "SIGABRT",
          nativeCrash: { ...observed, imageChecks },
        }).detail,
        /images=|binding-rejection=|private|foreign/u,
      );
  }
  const changed = observationFixture();
  changed.binding.alternatives = [
    { image: "/fixture/build/helper", sha256: changed.binding.sha256 },
  ];
  changed.imageChanged = true;
  assert.deepEqual(
    await readDarwinStartupCrash(changed.binding, changed.options),
    { status: "image-changed" },
  );
  assert.equal(changed.opened, 0);
  assert.match(
    darwinFeasibilityCause("argv", {
      nativeOperation: "exec",
      signal: "SIGABRT",
      nativeCrash: observationRejection("crash-record", "timestamp"),
    }).detail,
    /crash-record=timestamp$/u,
  );
});

test("Darwin missing timestamps retain only known field types and bounded image relationships through reports", async () => {
  let observed;
  for (const [event, types] of [
    [{}, ["missing", "missing", "missing", "missing", "missing"]],
    [
      {
        eventMessage: "raw-event",
        processID: 0,
        senderImagePath: "/private/record",
        subsystem: "raw-source",
        secretField: "raw-extra",
      },
      ["missing", "string", "number", "string", "string"],
    ],
    [
      {
        eventMessage: [],
        processID: true,
        senderImagePath: null,
        subsystem: {},
      },
      ["missing", "array", "boolean", "null", "object"],
    ],
  ]) {
    const f = observationFixture();
    f.options.run = async () => ({
      stdout: Buffer.from(JSON.stringify(event)),
    });
    observed = await readDarwinStartupDenial(f.binding, f.options);
    assert.deepEqual(observed, {
      ...observationRejection("log-record", "timestamp-missing"),
      logFields: types,
    });
    assert.equal(f.closed, f.opened);
    assert.doesNotMatch(
      JSON.stringify(observed),
      /raw-|secretField|\/private/u,
    );
  }
  const nativeCrash = {
    ...observationRejection("binding-rejection", "image", "unmatched"),
    imageChecks: [
      {
        image: "argv-fixture",
        reason: "image",
        imageFacts: imageFacts("absolute", true),
      },
      { image: "helper", reason: "image", imageFacts: imageFacts("absolute") },
    ],
  };
  const error = {
    nativeOperation: "exec",
    nativePhases: EXEC_PHASES.slice(0, 3),
    signal: "SIGABRT",
    nativeCrash,
    nativeDenial: observed,
    feasibilityObservationFailures: [
      { source: "nativeCrash", status: "read-failed" },
    ],
  };
  const cause = darwinFeasibilityCause("argv", error);
  assert.ok(Buffer.byteLength(cause.detail) <= 256);
  for (const fact of [
    "signal=SIGABRT",
    "phase=exec-enter",
    "abort-cause=unobserved",
    "argv-fixture:image[a010]",
    "helper:image[a000]",
    "log-record=timestamp-missing[m,a,b,z,o]",
    "observation=failed",
  ])
    assert.ok(cause.detail.includes(fact), fact);
  const candidateSha = "a".repeat(40),
    intent = {
      expectedSha: candidateSha,
      candidateSha,
      platform: "darwin",
      runId: "42",
      runAttempt: "1",
      protectedAcceptance: false,
    },
    results = unavailableFeasibilityResults("darwin", cause);
  results[0].cleanup = {
    ...results[0].cleanup,
    status: "UNCERTAIN",
    cause: {
      code: "cleanup-unobserved",
      detail: "Independent cleanup remains unobserved.",
    },
  };
  const report = assessFeasibilityReport(
    JSON.parse(
      JSON.stringify({
        schemaVersion: 1,
        expectedSha: candidateSha,
        checkoutSha: candidateSha,
        platform: "darwin",
        os: "darwin",
        build: "synthetic",
        architecture: "x64",
        results,
      }),
    ),
  );
  assert.deepEqual(report.report.results[0].cause, cause);
  assert.equal(report.report.results[0].status, "FAIL");
  assert.equal(report.report.results[0].cleanup.status, "UNCERTAIN");
  const summary = renderFeasibilitySummary(report, intent, {
    NATIVE_CANDIDATE_SHA: candidateSha,
    NATIVE_PLATFORM: "darwin",
    GITHUB_RUN_ID: "42",
    GITHUB_RUN_ATTEMPT: "1",
  });
  assert.ok(summary.includes("argv-fixture:image&#91;a010&#93;"));
  assert.ok(summary.includes("timestamp-missing&#91;m,a,b,z,o&#93;"));
  assert.ok(summary.includes("Independent cleanup remains unobserved."));
  assert.doesNotMatch(summary, /raw-|secretField|\/private\/record/u);
  for (const logFields of [
    [],
    Array(5),
    Object.assign([...observed.logFields], {
      [Symbol.iterator]: () => {
        throw new Error("private iterator");
      },
    }),
    ["string", ...observed.logFields.slice(1)],
    ...["private", {}].map((type) => [
      "missing",
      type,
      ...observed.logFields.slice(2),
    ]),
  ])
    assert.doesNotMatch(
      darwinFeasibilityCause("argv", {
        ...error,
        nativeDenial: { ...observed, logFields },
      }).detail,
      /log-record=|private/u,
    );
  for (const nativeDenial of [
    { ...observed, privatePath: "/private/record" },
    { ...observed, reason: "message" },
  ])
    assert.doesNotMatch(
      darwinFeasibilityCause("argv", { ...error, nativeDenial }).detail,
      /log-record=|\/private/u,
    );
  const legacy = darwinFeasibilityCause("argv", {
    ...error,
    nativeCrash: observationRejection(
      "binding-rejection",
      "image",
      "unmatched",
    ),
    nativeDenial: observationRejection("log-record", "timestamp-missing"),
  });
  assert.ok(
    legacy.detail.includes(
      "binding-rejection=image; log-read=unusable; log-record=timestamp-missing",
    ),
  );
});

test("Darwin NDJSON diagnosis preserves submillisecond windows and finite record rejection classes", async () => {
  const event = {
    timestamp: "1970-01-01 00:01:41.123456+0000",
    processID: 0,
    subsystem: "com.apple.sandbox.reporting",
    eventMessage:
      "Sandbox: argv-fixture(42) deny(1) file-read-data /private/target",
  };
  for (const [mutation, expected] of [
    [{}, "file-read-data"],
    [
      { timestamp: "1970-01-01T00:01:42.000001Z" },
      observationRejection("binding-rejection", "window", "unmatched"),
    ],
    [{ processID: undefined }, observationRejection("log-record", "process")],
    [
      { timestamp: "not-a-timestamp" },
      observationRejection("log-record", "timestamp-format"),
    ],
    [{ subsystem: 1 }, observationRejection("log-record", "source")],
    [{ eventMessage: "\ud800" }, observationRejection("log-record", "message")],
  ]) {
    const f = observationFixture();
    f.options.run = async () => ({
      stdout: Buffer.from(JSON.stringify({ ...event, ...mutation }) + "\r\n"),
    });
    const observed = await readDarwinStartupDenial(f.binding, f.options);
    assert.deepEqual(observed, expected);
  }
  for (const nativeCrash of [
    observationRejection("crash-record", "/private/tainted"),
    {
      ...observationRejection("crash-record", "json"),
      privateDetails: "/private/tainted",
    },
    observationRejection("foreign-record", "json"),
    observationRejection("crash-record", "json", "unmatched"),
    observationRejection("binding-rejection", "birth"),
  ])
    assert.doesNotMatch(
      darwinFeasibilityCause("argv", {
        nativeOperation: "exec",
        signal: "SIGABRT",
        nativeCrash,
      }).detail,
      /tainted|foreign-record|(?:crash-record|binding-rejection)=/u,
    );
});

test("Darwin crash reader distinguishes actual failed and unusable reads from empty and unmatched inspection", async () => {
  for (const [changes, status, kind, reason] of [
    [{}, "unmatched", "binding-rejection", "pid"],
    [{ names: [] }, "empty"],
    [{ listError: "ENOENT", watchError: "ENOENT" }, "unavailable"],
    [{ listError: "EACCES" }, "read-failed"],
    [{ watchError: "EACCES", names: [] }, "watch-failed"],
    [{ openError: true }, "read-failed"],
    [{ statError: true }, "read-failed"],
    [{ reportReadError: true }, "read-failed"],
    [{ isRegular: false }, "unusable"],
    [{ short: true }, "unusable"],
    [{ changing: true }, "unusable"],
    [{ bytes: Buffer.from([0xff]) }, "unusable", "crash-record", "encoding"],
    [
      { bytes: Buffer.from("incomplete private report") },
      "unusable",
      "crash-record",
      "metadata",
    ],
    [{ bytes: Buffer.from("{}\n{}") }, "unusable", "crash-record", "pid"],
    [
      { report: { procLaunch: 100 } },
      "unusable",
      "crash-record",
      "timestamp-type",
    ],
    [{ report: { usedImages: [null] } }, "unusable", "crash-record", "images"],
    [
      { report: { termination: [] } },
      "unusable",
      "crash-record",
      "termination",
    ],
    [
      { report: { faultingThread: 0, threads: [{ frames: {} }] } },
      "unusable",
      "crash-record",
      "threads",
    ],
    [
      { report: { pid: 42, termination: { namespace: "UNKNOWN", code: 1 } } },
      "unmatched",
      "binding-rejection",
      "termination",
    ],
    [{ imageChanged: true }, "image-changed"],
  ]) {
    const { report, ...effects } = changes;
    const f = Object.assign(observationFixture(), effects);
    if (report) f.bytes = f.encode({ ...f.report, ...report });
    const observed = await readDarwinStartupCrash(f.binding, f.options);
    assert.deepEqual(
      observed,
      kind ? observationRejection(kind, reason, status) : { status },
    );
    assert.equal(f.closed, f.opened);
    assert.equal(f.canceled, 1);
    assert.ok(f.watchers.every((watcher) => watcher.closed === 1));
    const cause = darwinFeasibilityCause("argv", {
      nativeOperation: "exec",
      signal: "SIGABRT",
      nativePhases: EXEC_PHASES.slice(0, 3),
      nativeCrash: observed,
    });
    assert.equal(cause.code, "crash");
    for (const text of [
      "argv-exec",
      "signal=SIGABRT",
      "phase=exec-enter",
      "abort-cause=unobserved",
      `crash-read=${status}`,
    ])
      assert.ok(cause.detail.includes(text));
    if (kind) assert.ok(cause.detail.endsWith(`${kind}=${reason}`));
    assert.doesNotMatch(JSON.stringify(cause), /private|\/fixture/u);
  }
});

test("Darwin report publication and watcher errors wake bounded collection and close every resource", async () => {
  for (const kind of ["publication", "watch-error", "expiry"]) {
    const f = observationFixture();
    f.bytes = f.encode({ ...f.report, pid: f.binding.pid });
    let listed,
      count = 0;
    const waiting = new Promise((resolve) => {
      listed = resolve;
    });
    f.options.list = async () => {
      if (++count === 2) listed();
      return count <= 2 ? [] : f.names;
    };
    const collecting = readDarwinStartupCrash(f.binding, f.options);
    await waiting;
    if (kind === "watch-error") {
      f.names = [];
      for (const watcher of f.watchers)
        watcher.emit("error", new Error("private watcher error"));
    } else if (kind === "expiry") f.expire();
    else f.publish("rename", f.names[0]);
    const observed = await collecting;
    assert.equal(
      kind === "publication" ? observed.namespace : observed.status,
      kind === "publication"
        ? "DYLD"
        : kind === "expiry"
          ? "empty"
          : "watch-failed",
    );
    assert.equal(f.canceled, 1);
    assert.ok(f.watchers.every((watcher) => watcher.closed === 1));
    assert.equal(f.closed, f.opened);
  }
  for (const [field, status] of [
    ["closeError", "read-failed"],
    ["watchCloseError", "watch-failed"],
  ]) {
    const f = observationFixture();
    f.bytes = f.encode({ ...f.report, pid: f.binding.pid });
    f[field] = true;
    const observed = await readDarwinStartupCrash(f.binding, f.options);
    assert.deepEqual(observed, {
      namespace: "DYLD",
      code: 1,
      frame: null,
      observationFailure: status,
    });
    const cause = darwinFeasibilityCause("argv", {
      nativeOperation: "exec",
      signal: "SIGABRT",
      nativeCrash: observed,
    });
    assert.ok(cause.detail.endsWith(`crash=DYLD:1; crash-read=${status}`));
    assert.equal(f.canceled, 1);
    assert.equal(f.closed, f.opened);
    assert.ok(f.watchers.every((watcher) => watcher.closed === 1));
  }
  for (const [isMatched, unavailableSystem] of [
    [false, false],
    [true, false],
    [true, true],
  ]) {
    const partial = observationFixture();
    partial.bytes = partial.encode({
      ...partial.report,
      pid: isMatched ? partial.binding.pid : 43,
    });
    partial.options.list = async (directory) => {
      partial.expire();
      if (
        (directory === "/Library/Logs/DiagnosticReports") !==
        unavailableSystem
      )
        return isMatched ? partial.names : [];
      throw Object.assign(new Error("private unavailable source"), {
        code: "ENOENT",
      });
    };
    const observed = await readDarwinStartupCrash(
      partial.binding,
      partial.options,
    );
    assert.deepEqual(
      observed,
      isMatched
        ? {
            namespace: "DYLD",
            code: 1,
            frame: null,
            observationFailure: "unavailable",
          }
        : { status: "unavailable" },
    );
    assert.equal(partial.canceled, 1);
    assert.ok(partial.watchers.every((watcher) => watcher.closed === 1));
  }
});

test("Darwin denial reader refuses malformed data and preserves separate command, image and read outcomes", async () => {
  const event = {
    timestamp: new Date(101000).toISOString(),
    processID: 0,
    subsystem: "com.apple.sandbox.reporting",
    eventMessage:
      "Sandbox: argv-fixture(42) deny(1) file-read-data /private/log-target",
  };
  for (const [stdout, expected] of [
    [" \n", { status: "empty" }],
    [
      JSON.stringify({
        ...event,
        eventMessage: event.eventMessage.replace("(42)", "(43)"),
      }),
      observationRejection("binding-rejection", "pid", "unmatched"),
    ],
    [JSON.stringify(event), "file-read-data"],
    [
      JSON.stringify(event) + "\npartial",
      observationRejection("log-record", "json"),
    ],
    ["null", observationRejection("log-record", "shape")],
    ["[]", observationRejection("log-record", "shape")],
    [
      "{}",
      {
        ...observationRejection("log-record", "timestamp-missing"),
        logFields: Array(5).fill("missing"),
      },
    ],
    ["\ud800", observationRejection("log-record", "encoding")],
    [Buffer.from([0xff]), observationRejection("log-record", "encoding")],
    [Buffer.alloc(65537), observationRejection("log-record", "size")],
  ]) {
    const f = observationFixture();
    f.options.run = async (file, args, options) => {
      assert.equal(file, "/usr/bin/sudo");
      assert.ok(args.includes("ndjson"));
      assert.equal(options.maxBuffer, 65536);
      return { stdout };
    };
    assert.deepEqual(
      await readDarwinStartupDenial(f.binding, f.options),
      expected,
    );
    const cause = darwinFeasibilityCause("argv", {
      nativeOperation: "exec",
      signal: "SIGABRT",
      nativeDenial:
        typeof expected === "string"
          ? expected
          : {
              ...expected,
              exitCode: 64,
              privateDetails: "/private/log-target",
            },
    });
    assert.doesNotMatch(cause.detail, /private|:64/u);
  }
  for (const [changes, expected] of [
    [{ imageReadError: true }, { status: "read-failed" }],
    [{ readErrorAt: 2 }, { status: "read-failed" }],
    [{ imageChanged: true }, { status: "image-changed" }],
    [{}, { status: "command-failed", exitCode: 64 }],
  ]) {
    const f = Object.assign(observationFixture(), changes);
    f.options.run = async () => {
      if (f.imageChanged || f.readErrorAt) return { stdout: "" };
      throw Object.assign(new Error("private command stderr"), { code: 64 });
    };
    assert.deepEqual(
      await readDarwinStartupDenial(f.binding, f.options),
      expected,
    );
  }
  const f = observationFixture();
  f.options.isMatchingCI = false;
  f.options.read = async () =>
    assert.fail("Wrong-worker observation must have no effects");
  for (const read of [readDarwinStartupCrash, readDarwinStartupDenial])
    assert.deepEqual(await read(f.binding, f.options), {
      status: "unavailable",
    });
});

function streams(t, operation = "exec", args = []) {
  const child = Object.assign(new EventEmitter(), {
    pid: 42,
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  t.after(() => {
    child.stdin.destroy();
    child.stdout.destroy();
    child.stderr.destroy();
  });
  const session = openDarwinFeasibilitySession("/fixture", operation, args, {
    launch: (file, launchedArgs, options) => {
      assert.equal(file, "/fixture/build/helper");
      assert.deepEqual(launchedArgs, [operation, ...args]);
      assert.equal(options.env.NATIVE_OWNERSHIP_CUSTODY, "true");
      return child;
    },
  });
  return {
    child,
    session,
    close: (code = 0, signal = null) => child.emit("close", code, signal),
  };
}

test("Darwin helper input exceptions stay visible without replacing the first failure", async (t) => {
  const chunks = [];
  const original = new Error("unknown helper failure");
  const secondary = new Error("unknown helper input failure", {
    cause: new Error("unknown input cause"),
  });
  await withNativeDiagnostics(
    async () => {
      const f = streams(t);
      const waiting = assert.rejects(
        f.session.next(),
        (error) => error === original,
      );
      f.child.emit("error", original);
      f.child.stdin.emit("error", secondary);
      f.close(19);
      await waiting;
      await assert.rejects(
        f.session.finish(),
        (error) => error === original && error.exitCode === 19,
      );
    },
    createNativeDiagnosticWriter((bytes) => chunks.push(bytes)),
  );
  const output = Buffer.concat(chunks).toString();
  for (const error of [original, secondary, secondary.cause])
    assert.ok(output.includes(error.stack));
});

test("Darwin startup markers tolerate stream fragmentation without changing stdout receipts", async (t) => {
  const f = streams(t),
    first = f.session.next();
  const phaseBytes = markers(EXEC_PHASES);
  f.child.stderr.write(phaseBytes.slice(0, 8));
  f.child.stdout.write('{"phase":"armed"}\n');
  assert.deepEqual(await first, { phase: "armed" });
  assert.deepEqual(f.session.phases(), []);
  f.child.stderr.write(phaseBytes.slice(8));
  f.child.stdout.write(`${JSON.stringify(LITERAL_ARGUMENTS)}\n`);
  assert.deepEqual(await f.session.next(), LITERAL_ARGUMENTS);
  f.close();
  assert.deepEqual(await f.session.finish(), { code: 0, signal: null });
  assert.deepEqual(f.session.phases(), EXEC_PHASES);
});

test("Darwin markers reject reordering, duplication, unknown fields and incomplete lines", () => {
  assert.deepEqual(
    darwinFeasibilityPhases(Buffer.from(markers(EXEC_PHASES)), "exec"),
    EXEC_PHASES,
  );
  for (const bytes of [
    markers(["policy-applied"]),
    markers(["policy-enter", "policy-enter"]),
    markers(["policy-enter", "unexpected"]),
    "native-darwin-phase: phase=policy-enter path=/private/fixture\n",
    " native-darwin-phase: phase=policy-enter\n",
    "native-darwin-phase: phase=policy-enter",
  ])
    assert.throws(() => darwinFeasibilityPhases(Buffer.from(bytes), "exec"));
  assert.throws(() => darwinFeasibilityPhases(Buffer.from([0xff, 10]), "exec"));
  assert.throws(() => darwinFeasibilityPhases(Buffer.alloc(65537), "exec"));
  assert.throws(() =>
    darwinFeasibilityPhases(Buffer.from(markers(["exec-enter"])), "__proto__"),
  );
});

test("Darwin self-exec ownership probes retain their receipts and signal without fixture-main", async (t) => {
  const f = streams(t, "exec", [
    "/fixture/evidence/fault.sb",
    "/fixture/build/helper",
    "fault",
  ]);
  f.child.stderr.write(markers(EXEC_PHASES.slice(0, 3)));
  for (const event of ["armed", "detached", "fault-ack"]) {
    f.child.stdout.write(`${JSON.stringify({ event })}\n`);
    assert.deepEqual(await f.session.next(), { event });
  }
  f.close(null, "SIGTERM");
  assert.deepEqual(await f.session.finish("SIGTERM"), {
    code: null,
    signal: "SIGTERM",
  });
  assert.deepEqual(f.session.phases(), EXEC_PHASES.slice(0, 3));
});

test("Darwin startup failures retain exit/signal facts and only the last validated phase", async (t) => {
  const f = streams(t),
    waiting = f.session.next();
  f.child.stderr.write(markers(EXEC_PHASES.slice(0, 3)));
  f.child.stderr.write(
    "runtime failed at /private/fixture with credential=hidden\n",
  );
  f.close(null, "SIGABRT");
  await assert.rejects(waiting, (error) => {
    const cause = darwinFeasibilityCause("argv", error);
    assert.match(cause.detail, /SIGABRT/u);
    assert.match(cause.detail, /phase=exec-enter/u);
    assert.doesNotMatch(
      cause.detail,
      /private|credential|hidden|fixture-main/u,
    );
    return true;
  });
});

test("Darwin pre-main aborts identify each fixed control and confined execution", async (t) => {
  for (const [operation, phases] of [
    ["policy-only", ["policy-enter"]],
    ["fixture-control", ["exec-enter"]],
    ["policy-invalid", ["policy-enter"]],
    ["exec-control", EXEC_PHASES.slice(0, 3)],
    ["exec", EXEC_PHASES.slice(0, 3)],
  ]) {
    const f = streams(t, operation),
      waiting = f.session.next();
    f.child.stderr.write(markers(phases));
    f.child.stderr.write("unknown abort at /private/fixture\n");
    f.close(null, "SIGABRT");
    await assert.rejects(waiting, (error) => {
      assert.equal(error.nativeOperation, operation);
      assert.deepEqual(error.nativePhases, phases);
      const cause = darwinFeasibilityCause("argv", error);
      assert.ok(cause.detail.startsWith(`darwin argv-${operation}:`));
      assert.ok(
        cause.detail.endsWith(`phase=${phases.at(-1)}; abort-cause=unobserved`),
      );
      assert.doesNotMatch(cause.detail, /private|fixture-main/u);
      assert.equal(
        unavailableFeasibilityResults("darwin", cause)[0].status,
        "FAIL",
      );
      return true;
    });
  }
});

test("Darwin abort diagnoses retain only bounded loader classes and operation-valid phase prefixes", () => {
  for (const [stderr, expected] of [
    ["dyld[42]: Library not loaded: /private/image\n", "dyld-library"],
    ["dyld: Symbol not found: _private_symbol\n", "dyld-symbol"],
    ["dyld[42]: ignition failed\n", "dyld-ignition"],
    ["dyld: no shared cache in cryptex\n", "dyld-cryptex"],
    [
      "dyld: dyld shared region dynamic config data was not set\n",
      "dyld-region",
    ],
    [
      "dyld: dyld private shared cache could not be found\n",
      "dyld-cache-missing",
    ],
    ["dyld: dyld shared cache could not be mapped\n", "dyld-cache-map"],
    ["dyld: missing lazy symbol called\n", "dyld-lazy-symbol"],
    ["dyld: ignition failed at /private/image\n", "unobserved"],
    ["other: dyld: Library not loaded: /private/image\n", "unobserved"],
    ["dyld: arbitrary abort /private/image\n", "unobserved"],
    [
      "x".repeat(65536) + "\ndyld: Library not loaded: /private/image\n",
      "unobserved",
    ],
  ]) {
    const cause = darwinFeasibilityCause("argv", {
      nativeOperation: "fixture-control",
      nativePhases: ["exec-enter"],
      signal: "SIGABRT",
      code: null,
      stderr,
    });
    assert.equal(cause.code, "crash");
    assert.ok(
      cause.detail.includes(
        `output=${expected === "unobserved" ? "unrecognized" : "recognized"}`,
      ),
    );
    assert.ok(
      cause.detail.endsWith(`; phase=exec-enter; abort-cause=${expected}`),
    );
    assert.ok(Buffer.byteLength(cause.detail) <= 256);
    assert.doesNotMatch(cause.detail, /private|_private_symbol/u);
  }
  for (const [nativeOperation, nativePhases] of [
    ["policy-only", ["exec-enter"]],
    ["exec", ["exec-enter", "fixture-main"]],
    ["exec", [, "policy-applied"]],
    ["/private/operation", ["exec-enter"]],
    ["__proto__", ["exec-enter"]],
  ]) {
    const cause = darwinFeasibilityCause("argv", {
      nativeOperation,
      nativePhases,
      signal: "SIGABRT",
    });
    assert.doesNotMatch(cause.detail, /; phase=|private|__proto__/u);
  }
});

test("Darwin synchronous session launch refusal retains operation without inventing phases", () => {
  const original = Object.assign(new Error("private launch text"), {
    code: "ENOENT",
  });
  assert.throws(
    () =>
      openDarwinFeasibilitySession("/fixture", "fixture-control", [], {
        launch: () => {
          throw original;
        },
      }),
    (error) => {
      assert.equal(error, original);
      assert.equal(error.nativeOperation, "fixture-control");
      assert.deepEqual(error.nativePhases, []);
      assert.doesNotMatch(
        darwinFeasibilityCause("argv", error).detail,
        /private|; phase=/u,
      );
      return true;
    },
  );
});

test("Darwin sessions reject combined output overflow and extra receipts after readiness", async (t) => {
  for (const variation of ["extra", "malformed", "overflow"]) {
    const f = streams(t),
      first = f.session.next();
    f.child.stderr.write(markers(EXEC_PHASES));
    f.child.stdout.write('{"phase":"armed"}\n');
    await first;
    f.child.stdout.write(`${JSON.stringify(LITERAL_ARGUMENTS)}\n`);
    await f.session.next();
    if (variation === "overflow") {
      f.child.stderr.write(Buffer.alloc(65536, 120));
    } else
      f.child.stdout.write(
        variation === "extra" ? '{"extra":true}\n' : "malformed-json\n",
      );
    f.close();
    await assert.rejects(f.session.finish());
  }
});

test("Darwin early stream refusal retains later observed exit facts without replacing first cause", async (t) => {
  const f = streams(t),
    waiting = f.session.next();
  f.child.stderr.write(markers(EXEC_PHASES.slice(0, 3)));
  f.child.stdout.write("malformed-json\n");
  let first;
  await assert.rejects(waiting, (error) => {
    first = error;
    return true;
  });
  f.close(null, "SIGABRT");
  await assert.rejects(f.session.finish(), (error) => {
    assert.equal(error, first);
    assert.match(
      darwinFeasibilityCause("argv", error).detail,
      /signal=SIGABRT/u,
    );
    return true;
  });
});

test("Darwin sandbox application retains only its documented failure status", () => {
  for (const [value, recognized] of [
    [-1, true],
    [0, false],
    [1, false],
    [2147483648, false],
  ]) {
    const cause = darwinFeasibilityCause("argv", {
      code: 126,
      signal: null,
      stderr: `native-darwin: operation=sandbox-apply domain=status value=${value} effects=none settlement=unsettled\n`,
    });
    assert.equal(
      cause.detail.includes("Native sandbox-apply failed (status=-1)"),
      recognized,
    );
    assert.match(cause.detail, /exit=126/u);
  }
});

const IDENTITY = {
  pid: 42,
  pidVersion: 7,
  asid: 2,
  auid: 501,
  uid: 501,
  gid: 20,
  ruid: 501,
  rgid: 20,
  svuid: 501,
  svgid: 20,
  startSeconds: 100,
  startMicroseconds: 1,
};
const COMPONENTS = [
  { role: "helper", name: "helper", sha256: SHA },
  { role: "helper", name: "argv-fixture", sha256: FIXTURE_SHA },
];
function startupEffects({
  failure,
  failedOperation = "policy-only",
  beforeReady = false,
  cleanupFailure,
  closeFailure,
  diagnosticValues = {},
  substituteImage = false,
} = {}) {
  const calls = [],
    policies = [],
    saved = [],
    sentinel = { untouched: true };
  let current;
  return {
    calls,
    policies,
    saved,
    sentinel,
    options: {
      openTrace: (binding, options) =>
        openDarwinStartupTrace(binding, {
          ...options,
          isMatchingCI: false,
          verifyInstalled: async () => assert.fail("Native tool discovery"),
          launch: () => assert.fail("Native trace launch"),
        }),
      write: async (file, policy, options) => {
        assert.deepEqual(options, { flag: "wx", mode: 0o600 });
        policies.push([file, policy]);
      },
      openSession: (root, operation, ...args) => {
        current = operation;
        calls.push(["open", operation, args]);
        let row = 0;
        const negative = ["policy-invalid", "exec-control"].includes(operation);
        const count =
          operation === "exec" ? 4 : operation === "exec-control" ? 3 : 2;
        return {
          child: {
            pid: 42,
            stdin: {
              write: (byte) => calls.push(["exec-release", operation, byte]),
              end: (byte) => calls.push(["release", operation, byte]),
            },
          },
          next: async () => {
            if (beforeReady && failure && operation === failedOperation)
              throw failure;
            if (row++ === 0) return { phase: "launch-armed" };
            return row === 2
              ? { phase: "armed" }
              : ["fixture-control", "exec"].includes(operation)
                ? LITERAL_ARGUMENTS
                : { policyApplied: true };
          },
          finish: async (signal = null, code = 0) => {
            if (failure && operation === failedOperation) throw failure;
            assert.equal(signal, null);
            assert.equal(code, negative ? 126 : 0);
            return { code, signal };
          },
          waitClosed: async () => {
            calls.push(["close", operation]);
            if (closeFailure) throw closeFailure;
            return { code: 126, signal: null };
          },
          phases: () =>
            operation === "fixture-control"
              ? ["exec-enter", "fixture-main"]
              : operation === "policy-invalid"
                ? ["policy-enter"]
                : EXEC_PHASES.slice(0, count),
          diagnostic: () =>
            negative
              ? {
                  operation:
                    operation === "policy-invalid"
                      ? "sandbox-apply"
                      : "exec-launch",
                  domain: operation === "policy-invalid" ? "status" : "errno",
                  value:
                    diagnosticValues[operation] ??
                    (operation === "policy-invalid" ? -1 : 13),
                }
              : null,
        };
      },
      inspect: async (root, operation, ...args) => {
        calls.push(["inspect", current, operation, args]);
        if (operation === "identity") return IDENTITY;
        if (operation === "image")
          return {
            sha256: substituteImage
              ? "c".repeat(64)
              : args.at(-1).endsWith("argv-fixture")
                ? FIXTURE_SHA
                : SHA,
          };
        if (operation === "policy" || operation === "policy-absent")
          return { sandboxed: operation === "policy" };
        if (operation === "files") {
          const bytes = policies.find(([file]) => file === args[0])[1];
          return [
            {
              identity: "fixture-policy",
              sha256: createHash("sha256").update(bytes).digest("hex"),
            },
          ];
        }
        if (operation === "retire" && cleanupFailure) throw cleanupFailure;
        return { status: "RETIRED" };
      },
      readSnapshots: async () => sentinel,
      save: async (root, name, observed) => saved.push([name, observed]),
    },
  };
}

test("Darwin fixed startup controls join images, live policy, exact failures and independent retirement", async () => {
  const f = startupEffects();
  const observed = await runDarwinFeasibilityStartup(
    "/fixture",
    COMPONENTS,
    f.sentinel,
    f.options,
  );
  assert.deepEqual(
    observed.map(({ operation }) => operation),
    ["policy-only", "fixture-control", "policy-invalid", "exec-control"],
  );
  assert.equal(f.saved.length, 8);
  for (const { operation, retired, launch } of observed) {
    assert.equal(retired.status, "RETIRED");
    assert.deepEqual(launch.trace, {
      status: "unavailable",
      cleanup: "NOT_RUN",
    });
    const calls = f.calls.filter((call) => call[1] === operation);
    const imageIndex = calls.findIndex((call) => call[2] === "image"),
      releaseIndex = calls.findIndex((call) => call[0] === "release");
    const execRelease = calls.findIndex((call) => call[0] === "exec-release");
    assert.ok(execRelease > imageIndex && execRelease < releaseIndex);
    assert.ok(imageIndex >= 0 && releaseIndex > imageIndex);
    assert.ok(
      calls.findIndex((call) => call[2] === "observe") >
        calls.findIndex((call) => call[0] === "release"),
    );
  }
  const withheld = f.policies.find(([file]) =>
    file.endsWith("startup-exec-control.sb"),
  )[1];
  const execution = withheld
    .split("\n")
    .find((line) => line.startsWith("(allow process-exec"));
  assert.doesNotMatch(execution, /argv-fixture/u);
  assert.match(withheld, /file-map-executable.*argv-fixture/u);
  assert.deepEqual(
    f.calls.find(
      (call) => call[0] === "open" && call[1] === "fixture-control",
    )[2],
    LITERAL_ARGUMENTS,
  );
});

test("Darwin pre-main failures bind every control to original custody without granting admission or replacing failures", async () => {
  for (const operation of [
    "policy-only",
    "fixture-control",
    "policy-invalid",
    "exec-control",
    "exec",
  ]) {
    const original = Object.assign(new Error("Original abort"), {
        signal: "SIGABRT",
        code: null,
      }),
      f = startupEffects({ failure: original, failedOperation: operation }),
      observations = [];
    f.options.readCrash = async (binding) => {
      observations.push(["crash", binding]);
      throw Object.assign(new Error("private observation failure"), {
        code: "EIO",
      });
    };
    f.options.readDenial = async (binding) => {
      observations.push(["denial", binding]);
      return "syscall-vnguard";
    };
    await assert.rejects(
      runDarwinFeasibilityArgv("/fixture", COMPONENTS, f.sentinel, f.options),
      (error) => {
        assert.equal(error, original);
        assert.equal(error.nativeOperation, operation);
        assert.equal(error.feasibilityObservationFailures.length, 1);
        assert.deepEqual(error.nativeCrash, { status: "read-failed" });
        assert.equal(error.feasibilityCleanup.status, "UNCERTAIN");
        assert.equal(error.nativeDenial, "syscall-vnguard");
        assert.match(
          darwinFeasibilityCause("argv", error).detail,
          /observation=failed$/u,
        );
        assert.doesNotMatch(
          JSON.stringify(error.feasibilityObservationFailures),
          /private observation failure/u,
        );
        return true;
      },
    );
    assert.deepEqual(
      observations.map(([kind]) => kind),
      ["crash", "denial"],
    );
    for (const [, binding] of observations) {
      assert.deepEqual(binding.identity, IDENTITY);
      assert.equal(binding.pid, IDENTITY.pid);
      assert.ok(binding.startedAt <= binding.endedAt);
      const fixture = ["exec", "exec-control", "fixture-control"].includes(
        operation,
      );
      assert.equal(
        binding.image,
        `/fixture/build/${fixture ? "argv-fixture" : "helper"}`,
      );
      assert.equal(binding.sha256, fixture ? FIXTURE_SHA : SHA);
    }
    assert.equal(
      f.saved.some(([name]) => name === "argv"),
      false,
    );
    assert.equal(
      f.calls.filter(([kind]) => kind === "open").at(-1)[1],
      operation,
    );
  }
});

test("Darwin startup intent precedes exec release and rejects a changed process birth", async () => {
  const unwritten = startupEffects(),
    writeFailure = new Error("Intent storage refused");
  unwritten.options.save = async () => {
    throw writeFailure;
  };
  await assert.rejects(
    runDarwinFeasibilityStartup(
      "/fixture",
      COMPONENTS,
      unwritten.sentinel,
      unwritten.options,
    ),
    (error) => error === writeFailure,
  );
  assert.equal(
    unwritten.calls.some(([kind]) => kind === "exec-release"),
    false,
  );
  assert.ok(
    unwritten.calls.some(
      ([kind, , operation]) => kind === "inspect" && operation === "retire",
    ),
  );
  const changed = startupEffects(),
    inspect = changed.options.inspect;
  let identities = 0;
  changed.options.inspect = async (...args) =>
    args[1] === "identity" && ++identities === 2
      ? { ...IDENTITY, startMicroseconds: 2 }
      : inspect(...args);
  await assert.rejects(
    runDarwinFeasibilityStartup(
      "/fixture",
      COMPONENTS,
      changed.sentinel,
      changed.options,
    ),
  );
  assert.equal(
    changed.calls.some(([kind, , byte]) => kind === "release" && byte === "A"),
    false,
  );
  assert.equal(
    changed.calls.find(
      ([kind, , operation]) => kind === "inspect" && operation === "retire",
    )[3][9],
    "1",
  );
  for (const observation of [
    null,
    [{ identity: "fixture-policy", sha256: "c".repeat(64) }],
  ]) {
    const substituted = startupEffects(),
      read = substituted.options.inspect;
    substituted.options.inspect = async (...args) =>
      args[1] === "files" ? observation : read(...args);
    await assert.rejects(
      runDarwinFeasibilityStartup(
        "/fixture",
        COMPONENTS,
        substituted.sentinel,
        substituted.options,
      ),
    );
    assert.equal(
      substituted.calls.some(([kind]) => kind === "exec-release"),
      false,
    );
  }
});

test("Darwin startup refuses substituted images before release and preserves separate cleanup failures", async () => {
  const substituted = startupEffects({ substituteImage: true });
  await assert.rejects(
    runDarwinFeasibilityStartup(
      "/fixture",
      COMPONENTS,
      substituted.sentinel,
      substituted.options,
    ),
  );
  assert.equal(
    substituted.calls.some(
      ([kind, , byte]) => kind === "release" && byte === "A",
    ),
    false,
  );
  const original = Object.assign(new Error("First native failure"), {
    signal: "SIGABRT",
    code: null,
  });
  const f = startupEffects({
    failure: original,
    cleanupFailure: Object.assign(new Error("private cleanup text"), {
      code: "EIO",
    }),
    closeFailure: Object.assign(new Error("later closure failure"), {
      code: "ETIMEDOUT",
    }),
  });
  await assert.rejects(
    runDarwinFeasibilityStartup("/fixture", COMPONENTS, f.sentinel, f.options),
    (error) => {
      assert.equal(error, original);
      assert.equal(error.feasibilityCleanup.status, "UNCERTAIN");
      assert.match(error.feasibilityCleanup.cause.detail, /EIO/u);
      assert.doesNotMatch(
        error.feasibilityCleanup.cause.detail,
        /private cleanup text/u,
      );
      return true;
    },
  );
  assert.equal(f.calls.filter(([kind]) => kind === "open").length, 1);
  assert.equal(f.saved.length, 1);
  assert.equal(f.calls.filter(([kind]) => kind === "close").length, 1);
});

test("Darwin startup failures stop admission and retain the failing operation through cleanup", async () => {
  for (const operation of [
    "policy-only",
    "fixture-control",
    "policy-invalid",
    "exec-control",
    "exec",
  ]) {
    const original = Object.assign(new Error("Original native abort"), {
      signal: "SIGABRT",
      code: null,
    });
    const f = startupEffects({ failure: original, failedOperation: operation });
    await assert.rejects(
      runDarwinFeasibilityArgv("/fixture", COMPONENTS, f.sentinel, f.options),
      (error) => {
        assert.equal(error, original);
        assert.equal(error.nativeOperation, operation);
        assert.equal(error.feasibilityCleanup.status, "UNCERTAIN");
        assert.equal(error.feasibilityCleanup.independent, false);
        assert.equal(darwinFeasibilityCause("argv", error).code, "crash");
        return true;
      },
    );
    assert.equal(
      f.calls.filter(([kind]) => kind === "open").at(-1)[1],
      operation,
    );
    assert.ok(
      f.calls.some(
        ([kind, owner, action]) =>
          kind === "inspect" && owner === operation && action === "retire",
      ),
    );
    assert.equal(
      f.saved.some(([name]) => name === "argv"),
      false,
    );
  }
});

test("Darwin failures before custody never invent identity or independent retirement", async () => {
  const original = Object.assign(new Error("Pre-main abort"), {
    signal: "SIGABRT",
    nativePhases: ["exec-enter"],
  });
  const f = startupEffects({
    failure: original,
    failedOperation: "fixture-control",
    beforeReady: true,
    closeFailure: Object.assign(new Error("Closure deadline"), {
      code: "ERR_FEASIBILITY_DEADLINE",
    }),
  });
  await assert.rejects(
    runDarwinFeasibilityArgv("/fixture", COMPONENTS, f.sentinel, f.options),
    (error) => {
      assert.equal(error, original);
      assert.equal(error.nativeOperation, "fixture-control");
      assert.equal(error.feasibilityCleanup.status, "UNCERTAIN");
      assert.equal(error.feasibilityCleanup.cause.code, "deadline");
      assert.match(
        darwinFeasibilityCause("argv", error).detail,
        /phase=exec-enter/u,
      );
      return true;
    },
  );
  assert.equal(
    f.calls.some(
      ([kind, owner]) => kind === "inspect" && owner === "fixture-control",
    ),
    false,
  );
  assert.equal(
    f.calls.some(
      ([kind, owner, byte]) =>
        kind === "release" && owner === "fixture-control" && byte === "A",
    ),
    false,
  );
  const writeFailure = new Error("private write failure");
  const noLaunch = startupEffects();
  noLaunch.options.write = async () => {
    throw writeFailure;
  };
  await assert.rejects(
    runDarwinFeasibilityArgv(
      "/fixture",
      COMPONENTS,
      noLaunch.sentinel,
      noLaunch.options,
    ),
    (error) => {
      assert.equal(error, writeFailure);
      assert.equal(error.nativeOperation, "policy-only");
      assert.equal(error.feasibilityCleanup.independent, false);
      assert.doesNotMatch(
        darwinFeasibilityCause("argv", error).detail,
        /private|; phase=/u,
      );
      return true;
    },
  );
  assert.deepEqual(noLaunch.calls, []);
});

test("Darwin expected negative controls require their exact native cause before confined admission", async () => {
  for (const [operation, value] of [
    ["policy-invalid", 0],
    ["exec-control", 2],
  ]) {
    const f = startupEffects({ diagnosticValues: { [operation]: value } });
    await assert.rejects(
      runDarwinFeasibilityArgv("/fixture", COMPONENTS, f.sentinel, f.options),
      (error) => error.nativeOperation === operation,
    );
    assert.equal(
      f.calls.some(([kind, owner]) => kind === "open" && owner === "exec"),
      false,
    );
  }
  const positive = startupEffects();
  const result = await runDarwinFeasibilityArgv(
    "/fixture",
    COMPONENTS,
    positive.sentinel,
    positive.options,
  );
  assert.equal(result.status, "PASS");
  assert.equal(result.cleanup.status, "PASS");
  assert.equal(positive.saved.at(-1)[0], "argv");
  assert.equal(positive.saved.at(-1)[1].operation, "exec");
  assert.deepEqual(positive.saved.at(-1)[1].phases, EXEC_PHASES);
  assert.match(positive.policies.at(-1)[1], /\(deny default\)/u);
});

test("Darwin runtime policy and actual source retain narrow grants and finite flushed phases", async () => {
  const policy = darwinFeasibilityPolicy("/fixture");
  const execControl = darwinFeasibilityPolicy("/fixture", false, false);
  for (const value of [policy, execControl])
    assert.match(value, /^\(allow file-read-data \(literal "\/"\)\)$/mu);
  assert.doesNotMatch(
    execControl
      .split("\n")
      .find((line) => line.startsWith("(allow process-exec ")),
    /argv-fixture/u,
  );
  assert.match(
    policy,
    /system-mac-syscall \(require-all \(mac-policy-name "Sandbox"\) \(mac-syscall-number 67\)\)/u,
  );
  assert.doesNotMatch(
    policy,
    /mach-lookup|network-|iokit-|file-test-existence|path-ancestors/u,
  );
  const [helper, fixture] = await Promise.all([
    readFile(
      new URL("../ci/native/darwin/feasibility-helper.c", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../ci/native/darwin/argv-fixture.c", import.meta.url),
      "utf8",
    ),
  ]);
  const application = helper.slice(
    helper.indexOf("static void policy("),
    helper.indexOf("static void parked("),
  );
  assert.ok(
    application.indexOf("phase=policy-enter") <
      application.indexOf("sandbox_init("),
  );
  assert.ok(
    application.indexOf("sandbox_init(") <
      application.indexOf("phase=policy-applied"),
  );
  assert.match(application, /remember\("sandbox-apply", "status", result\)/u);
  for (const phase of ["policy-enter", "policy-applied", "exec-enter"])
    assert.match(
      helper,
      new RegExp(`phase=${phase}\\\\n"\\); fflush\\(stderr\\);`, "u"),
    );
  assert.ok(
    fixture.indexOf("phase=fixture-main") < fixture.indexOf("getuid()"),
  );
  assert.match(fixture, /fflush\(stderr\)/u);
  assert.ok(
    fixture.indexOf("phase=fixture-main") <
      fixture.indexOf('puts("{\\"phase\\":\\"armed\\"}")'),
  );
  assert.match(helper, /strcmp\(name \+ 1, "helper"\)/u);
  assert.match(helper, /strcpy\(name \+ 1, "argv-fixture"\)/u);
  assert.match(
    helper,
    /execv\(image, arguments\); int error = errno;\s+remember\("exec-launch", "errno", error\); failure\(126\)/u,
  );
  const image = helper.slice(
    helper.indexOf("static void image_identity("),
    helper.indexOf("static int connection("),
  );
  assert.match(image, /O_RDONLY \| O_NOFOLLOW \| O_CLOEXEC/u);
  assert.match(
    image,
    /before\.st_uid == getuid\(\) && before\.st_gid == getgid\(\) && \(before\.st_mode & 07777\) == 0500/u,
  );
  assert.match(
    image,
    /same_file_stat\(&before, &after\) && same_file_stat\(&before, &named\)/u,
  );
  assert.match(image, /live\(value\) &&\s*proc_pidpath/u);
});

test("Darwin final statistics validate exact counts without hiding malformed events or empty observations", async () => {
  const f = observationFixture();
  const event = {
    timestamp: new Date(f.binding.startedAt).toISOString(),
    processID: 0,
    senderImagePath: "/System/Library/Extensions/Sandbox.kext/Sandbox",
    eventMessage: `Sandbox: argv-fixture(${f.binding.pid}) deny(1) file-read-data /fixture`,
  };
  const encode = (value) => JSON.stringify(value) + "\n";
  const read = async (text) =>
    readDarwinStartupDenial(f.binding, {
      ...f.options,
      run: async () => ({ stdout: Buffer.from(text) }),
    });
  assert.equal((await read(encode({ count: 0, finished: 1 }))).status, "empty");
  assert.equal(
    await read(encode(event) + encode({ count: 1, finished: 1 })),
    "file-read-data",
  );
  for (const footer of [
    { count: -1, finished: 1 },
    { count: 0, finished: 1 },
    { count: "1", finished: 1 },
    { count: 1.5, finished: 1 },
    { count: Number.MAX_SAFE_INTEGER + 1, finished: 1 },
    { count: 1, finished: true },
    { count: 1, finished: 0 },
    { count: 1 },
    { finished: 1 },
    { count: 1, finished: 1, extra: 0 },
  ])
    assert.equal((await read(encode(event) + encode(footer))).reason, "footer");
  const footer = encode({ count: 0, finished: 1 });
  for (const text of [
    footer + footer,
    footer + encode(event),
    encode(event) + footer + "partial",
  ])
    assert.equal((await read(text)).status, "unusable");
  assert.equal(
    (
      await read(
        encode({ ...event, timestamp: undefined }) +
          encode({ count: 1, finished: 1 }),
      )
    ).reason,
    "timestamp-missing",
  );
});

test("startup observer authority admits only fixed sudo/helper selectors and normalized arguments", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility.js", import.meta.url),
    "utf8",
  );
  const bytes = Buffer.from("candidate helper"),
    digest = (value) => createHash("sha256").update(value).digest("hex"),
    helperSha256 = digest(bytes),
    calls = [],
    reads = [];
  const invoke = new Script(
    source.slice(
      source.indexOf("async function command("),
      source.indexOf("async function persist("),
    ) + "; startupObserver",
  ).runInNewContext({
    path,
    digest,
    need: (value) => assert.ok(value),
    darwinFeasibilityIdentityArguments,
    setTimeout,
    clearTimeout,
    nativeException: () => {},
  });
  const options = {
    read: async (file) => {
      reads.push(file);
      return bytes;
    },
    run: async (file, args, options) => {
      calls.push([file, [...args], JSON.parse(JSON.stringify(options.env))]);
      return { stdout: '{"status":"RETIRED"}' };
    },
  };
  const vector = [501, 501, 20, 501, 20, 42, 2, 7, 100, 1, 501, 20].map(String);
  for (const [selector, value, args] of [
    ["startup-observer", 900, ["900"]],
    ["startup-observer-observe", IDENTITY, vector],
    ["startup-observer-retire", IDENTITY, vector],
  ]) {
    await invoke("/fixture", selector, value, helperSha256, options);
    assert.deepEqual(calls.at(-1), [
      "/usr/bin/sudo",
      [
        "--non-interactive",
        "CI=true",
        "GITHUB_ACTIONS=true",
        "RUNNER_ENVIRONMENT=github-hosted",
        "RUNNER_OS=macOS",
        "--",
        "/fixture/build/helper",
        selector,
        ...args,
      ],
      { PATH: "/usr/bin:/bin", LANG: "C" },
    ]);
  }
  assert.deepEqual(reads, Array(6).fill("/fixture/build/helper"));
  for (const [selector, value] of [
    ["retire", IDENTITY],
    ["startup-observer-cancel", IDENTITY],
    ...[1, 0x80000000, "900"].map((pid) => ["startup-observer", pid]),
    ["startup-observer-retire", { ...IDENTITY, pid: 1 }],
    ["startup-observer-observe", { ...IDENTITY, extra: true }],
  ])
    await assert.rejects(
      invoke("/fixture", selector, value, helperSha256, options),
    );
  assert.equal(calls.length, 3);
  for (const after of [false, true]) {
    let count = 0;
    const before = calls.length;
    await assert.rejects(
      invoke("/fixture", "startup-observer", 900, helperSha256, {
        ...options,
        read: async () =>
          after && count++ === 0 ? bytes : Buffer.from("substitute"),
      }),
    );
    assert.equal(calls.length, before + Number(after));
  }
});

test("native observer root admission keeps exact arities, Worker identity checks and pre-signal rechecks", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const condition = source
    .match(
      /static bool startup_observer_request\(int argc, char \*\*argv\) \{\s+return ([\s\S]*?);\s+\}/u,
    )[1]
    .replace(/!strcmp\(argv\[1\], "([a-z-]+)"\)/gu, 'argv[1] === "$1"');
  const admitted = new Script(
    `(argc, argv) => (${condition})`,
  ).runInNewContext();
  const arities = {
    "startup-observer": 3,
    "startup-observer-observe": 14,
    "startup-observer-retire": 14,
  };
  for (const selector of [
    ...Object.keys(arities),
    "identity",
    "command-run",
    "startup-observer-cancel",
  ])
    for (const argc of [0, 2, 3, 13, 14, 15])
      assert.equal(
        admitted(argc, ["helper", selector]),
        arities[selector] === argc,
      );
  assert.match(
    source,
    /if \(observer\) invariant\(getuid\(\) == 0 && geteuid\(\) == 0/u,
  );
  assert.match(
    source,
    /else invariant\(getuid\(\) > 500 && geteuid\(\) == getuid\(\) && argc >= 2/u,
  );
  assert.match(
    source,
    /for \(const char \*p = argv\[i\]; \*p; p\+\+\) need\(\*p >= '0' && \*p <= '9'\)/u,
  );
  assert.match(
    source,
    /startup_observer_live\(value\)\) \{\s+signal_identity\(value, SIGKILL\)/u,
  );
});

function traceFixture({
  identity = IDENTITY,
  refused = false,
  cleanupFailure = false,
  live = false,
  unrelated = false,
  retireFailure = false,
  substituted = null,
  acknowledge = true,
  beforeRead,
  observeState,
} = {}) {
  const binding = { identity: { ...identity } },
    child = new EventEmitter(),
    calls = [];
  child.pid = 900;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  const tracerPid = unrelated ? 903 : 901;
  const ids = [900, tracerPid].map((pid) => ({ ...IDENTITY, pid }));
  const retired = new Set();
  let tracerReads = 0;
  const trace = openDarwinStartupTrace(
    { identity: binding.identity },
    {
      isMatchingCI: true,
      parentPid: 999,
      verifyInstalled: async () => {},
      launch: (file, args, options) => {
        assert.equal(file, "/usr/bin/sudo");
        const program = args[5];
        assert.deepEqual(args, [
          "--non-interactive",
          "--",
          "/usr/sbin/dtrace",
          "-q",
          "-n",
          program,
          String(identity.pid),
        ]);
        assert.equal(
          createHash("sha256").update(program).digest("hex"),
          DARWIN_STARTUP_TRACE_INTENT.programSha256,
        );
        assert.match(program, /^#pragma D option strsize=129$/mu);
        assert.equal(
          program.match(/copyinstr\(self->pointer, 128\)/gu)?.length,
          1,
        );
        assert.ok(program.includes("%S\\n"));
        assert.ok(program.includes('probefunc == "abort_with_payload" ? arg4'));
        assert.doesNotMatch(program, /\barg[235]\b/u);
        for (const line of program
          .split("\n")
          .filter((line) => line.includes(":::")))
          assert.ok(
            line.startsWith("dtrace:::BEGIN") || line.includes("/pid == $1"),
          );
        assert.equal(program.match(/\/pid == \$1\//gu)?.length, 4);
        for (const probe of [
          "syscall:::entry",
          "syscall:::return",
          "proc:::exec-success",
          "proc:::exit",
        ])
          assert.ok(program.includes(`${probe} /pid == $1/ {`));
        assert.match(
          program,
          /^dtrace:::BEGIN \{ printf\("armed %d %llu\\n", pid, timestamp\); \}$/mu,
        );
        assert.match(
          program,
          /^proc:::exit \/pid == \$1\/ \{ printf\("exit %d %llu\\n", pid, timestamp\); exit\(0\); \}$/mu,
        );
        assert.equal(program.match(/\bexit\(/gu)?.length, 1);
        assert.doesNotMatch(
          program,
          /\$target|\$[02-9]|copyin\(|system\(|raise\(|stop\(|chill\(|panic\(/u,
        );
        assert.equal(options.stdio[0], "ignore");
        if (acknowledge)
          queueMicrotask(() => child.stdout.write(`armed ${tracerPid} 100\n`));
        return child;
      },
      readObserver: async (pid) => {
        child.emit("observer-read", pid);
        await beforeRead?.(pid);
        if (refused)
          throw Object.assign(new Error("Identity unavailable"), {
            code: "EPERM",
          });
        const changed = pid === tracerPid && tracerReads++ >= 2;
        return {
          kind:
            pid === tracerPid && !(changed && substituted === "image")
              ? "dtrace"
              : "sudo",
          parentPid:
            pid === tracerPid
              ? unrelated || (changed && substituted === "parent")
                ? 500
                : 900
              : 999,
          identity: {
            ...ids.find((id) => id.pid === pid),
            ...(changed && substituted === "birth"
              ? { startMicroseconds: 2 }
              : {}),
          },
        };
      },
      observeObserver: async (id) => {
        calls.push(["observe", id.pid]);
        if (cleanupFailure && id.pid === 901)
          throw Object.assign(new Error("Retirement unavailable"), {
            code: "EPERM",
          });
        const state = {
          status: live && !retired.has(id.pid) ? "LIVE" : "RETIRED",
        };
        return observeState ? observeState(id, state) : state;
      },
      retireObserver: async (id) => {
        calls.push(["retire", id.pid]);
        child.emit("retirement-attempt", id.pid);
        if (retireFailure && id.pid === 900)
          throw new Error("Retirement refused");
        retired.add(id.pid);
        return { status: "RETIRED" };
      },
    },
  );
  return {
    binding,
    trace,
    child,
    calls,
    acknowledge: () => child.stdout.write(`armed ${tracerPid} 100\n`),
    close: async (code = 0) => {
      const ended = Promise.all([
        once(child.stdout, "end"),
        once(child.stderr, "end"),
      ]);
      child.stdout.end();
      child.stderr.end();
      await ended;
      child.emit("close", code, null);
    },
  };
}

test("startup argument diagnostics join only the same thread and retain escaped bounded values without unsigned loss", async () => {
  const f = traceFixture();
  await f.trace.arm();
  const rows = [
    "entry 42 101 open",
    "argument-entry 42 101 open 7 complete 0 0 /neutral/space and\\nline\\\\tail\\0",
    "entry 42 102 open",
    "argument-entry 42 102 open 8 complete 0 0 /neutral/other\\\\0\\0",
    "return 42 103 open 1 -1",
    "argument-return 42 103 open 8 1 -1",
    "return 42 104 open 0 3",
    "argument-return 42 104 open 7 0 3",
    "argument-entry 42 105 openat 9 complete 0 0 relative name\\377\\000",
    "argument-return 42 106 openat 9 1 -1",
    "argument-entry 42 107 csrctl 10 complete 4294967295 0 ",
    "argument-return 42 108 csrctl 10 1 -1",
    "argument-entry 42 109 sysctl 11 unsupported 0 0 ",
    "argument-return 42 110 sysctl 11 1 -1",
    'argument-entry 42 111 abort_with_payload 12 complete 35 18446744073709551615 neutral\\n\\"reason\\"\\0',
    "exit 42 112",
  ];
  const stream = rows.join("\n") + "\n";
  for (const chunk of [
    stream.slice(0, 37),
    stream.slice(37, 139),
    stream.slice(139),
  ])
    f.child.stdout.write(chunk);
  await f.close();
  const result = await f.trace.finish();
  assert.equal(result.status, "observed");
  assert.equal(result.events, rows.length);
  assert.equal(
    result.sha256,
    createHash("sha256").update(rows.join("\n")).digest("hex"),
  );
  assert.equal(result.cleanup, "RETIRED");
  assert.deepEqual(
    result.arguments
      .slice(0, 2)
      .map(({ thread, text, result }) => [thread, text, result]),
    [
      ["7", "/neutral/space and\\nline\\\\tail", { errno: 0, value: "3" }],
      ["8", "/neutral/other\\\\0", { errno: 1, value: "-1" }],
    ],
  );
  assert.equal(result.arguments[2].text, "relative name\\377");
  assert.equal(result.arguments[3].selector, 4294967295);
  assert.equal(result.arguments[4].acquisition, "unsupported");
  assert.equal(result.arguments[5].code, "18446744073709551615");
  assert.equal(result.arguments[5].namespace, 35);
  assert.equal(result.arguments[5].text, 'neutral\\n\\"reason\\"');
  assert.equal(result.arguments[5].pairing, "nonreturning");
  const cause = darwinFeasibilityCause("argv", {
    signal: "SIGABRT",
    nativeOperation: "exec",
    nativeTrace: result,
  });
  assert.match(cause.detail, /trace-args=unsupported/u);
  assert.doesNotMatch(
    JSON.stringify(cause),
    /neutral|18446744073709551615|4294967295/u,
  );
  assert.ok(Buffer.byteLength(cause.detail) <= 256);
  const limited = {
    signal: "SIGABRT",
    nativeOperation: "exec",
    nativePhases: EXEC_PHASES.slice(0, 3),
    nativeCrash: {
      namespace: "LIBIGNITION",
      code: 2,
      frame: "abort-payload",
      observationFailure: "read-failed",
    },
    nativeDenial: {
      ...observationRejection("log-record", "timestamp-missing"),
      logFields: ["missing", "string", "number", "string", "string"],
    },
    feasibilityObservationFailures: [
      { source: "nativeCrash", status: "read-failed" },
    ],
    nativeTrace: { status: "partial", cleanup: "UNCERTAIN" },
  };
  const originalDetail = darwinFeasibilityCause("argv", limited).detail;
  limited.nativeTrace.argumentStatus = "unavailable";
  assert.equal(darwinFeasibilityCause("argv", limited).detail, originalDetail);
  assert.match(originalDetail, /trace-cleanup=uncertain/u);
});

test("startup argument limitations never identify a denied object from a prefix or ambiguous pairing", async () => {
  for (const [state, text, acquisition, completeness, storedText] of [
    ["complete", "\\0", "acquired", "complete", ""],
    [
      "complete",
      "x".repeat(127) + "\\0",
      "acquired",
      "complete",
      "x".repeat(127),
    ],
    [
      "complete",
      "\\377".repeat(127) + "\\000",
      "acquired",
      "complete",
      "\\377".repeat(127),
    ],
    ["missing", "\\0", "missing", "unavailable", null],
    ["missing", "\\000", "missing", "unavailable", null],
    ["copy-failed", "", "copy-failed", "unavailable", null],
    ["truncated", "/" + "x".repeat(127) + "\\0", "acquired", "truncated", null],
    ["truncated", "\\377".repeat(128) + "\\0", "acquired", "truncated", null],
  ]) {
    const f = traceFixture();
    await f.trace.arm();
    f.child.stdout.write(
      `argument-entry 42 101 open 7 ${state} 0 0 ${text}\nargument-return 42 102 open 7 1 -1\n`,
    );
    await f.close();
    const result = await f.trace.finish();
    assert.equal(result.status, "observed");
    assert.equal(result.argumentStatus, state);
    assert.equal(result.arguments[0].acquisition, acquisition);
    assert.equal(result.arguments[0].completeness, completeness);
    assert.equal(result.arguments[0].text, storedText);
    assert.equal(result.cleanup, "RETIRED");
  }
  for (const suffix of [
    "argument-return 42 102 open 8 1 -1\n",
    "argument-return 42 102 openat 7 1 -1\n",
    "argument-entry 42 102 open 7 complete 0 0 /other\\0\n",
    "argument-entry 43 102 open 8 complete 0 0 /other\\0\n",
    "argument-entry 42 102 open 8 complete 0 0 bad\\q\\0\n",
    "argument-entry 42 102 open 8 complete 0 0 bad\\000tail\\0\n",
    "argument-entry 42 102 open 8 complete 0 0 bad\\0\\0\n",
    "argument-entry 42 102 open 8 complete 0 0 bad\\0tail\n",
    "argument-entry 42 102 open 8 complete 0 0 /other\\\\0\n",
    "argument-entry 42 102 open 8 complete 0 0 bad\\00\n",
    "argument-entry 42 102 open 8 complete 0 0 /unframed\n",
    "argument-entry 42 102 open 8 missing 0 0 /neutral\\0\n",
    "argument-entry 42 102 open 8 missing 0 0 \n",
    "argument-entry 42 102 open 8 copy-failed 0 0 \\0\n",
    "argument-entry 42 102 csrctl 8 complete 0 0 \\0\n",
    "argument-entry 42 102 sysctl 8 unsupported 0 0 \\0\n",
    `argument-entry 42 102 open 8 complete 0 0 ${"x".repeat(128)}\\0\n`,
    `argument-entry 42 102 open 8 truncated 0 0 ${"x".repeat(129)}\\0\n`,
    "argument-entry 42 102 open 8 truncated 0 0 short\\0\n",
    "argument-entry 42 102 abort_with_payload 8 complete 35 18446744073709551616 reason\\0\n",
    "argument-entry 42 102 csrctl 8 complete 4294967296 0 \n",
    "argument-entry 42 102 open 8 complete 0 0 " + "x".repeat(1025),
    Array.from(
      { length: 64 },
      (_, i) =>
        `argument-entry 42 102 open ${100 + i} complete 0 0 /neutral\\0\n`,
    ).join(""),
  ]) {
    const f = traceFixture();
    await f.trace.arm();
    f.child.stdout.write(
      "argument-entry 42 101 open 7 complete 0 0 /neutral\\0\n" + suffix,
    );
    await f.close();
    const result = await f.trace.finish();
    assert.equal(result.status, "partial");
    assert.equal(result.argumentStatus, "malformed");
    assert.equal(result.arguments, null);
    assert.equal(result.sha256, null);
    assert.equal(result.cleanup, "RETIRED");
  }
  for (const [rows, pairing] of [
    [
      "argument-entry 42 101 open 7 complete 0 0 /neutral\\0\nexit 42 102\n",
      "missing-return",
    ],
    ["entry 42 101 open\nreturn 42 102 open 1 -1\n", null],
    [
      "entry 42 101 open\nreturn 42 102 open 1 -1\nargument-entry 42 103 csrctl 7 complete 0 0 \nargument-return 42 104 csrctl 7 1 -1\n",
      "returned",
    ],
  ]) {
    const missing = traceFixture();
    await missing.trace.arm();
    missing.child.stdout.write(rows);
    await missing.close();
    const result = await missing.trace.finish();
    assert.equal(result.argumentStatus, "missing");
    assert.equal(result.arguments.length, pairing ? 1 : 0);
    assert.ok(
      result.arguments.every(
        (record) => record.pairing === pairing && record.text === null,
      ),
    );
  }
});

test("startup trace allows delayed BEGIN within one 15-second arm and spawn-based 30-second capture budget", async (t) => {
  t.mock.timers.enable({ apis: ["Date", "setTimeout"] });
  for (const deadline of ["timer", "late-close"]) {
    const f = traceFixture({ acknowledge: false });
    const spawned = once(f.child, "observer-read");
    const arming = f.trace.arm();
    await spawned;
    t.mock.timers.tick(6000);
    f.acknowledge();
    assert.equal((await arming).status, "armed");
    t.mock.timers.tick(23999);
    f.child.stdout.write("entry 42 101 open\n");
    if (deadline === "timer") t.mock.timers.tick(1);
    else t.mock.timers.setTime(Date.now() + 1);
    await f.close();
    const result = await f.trace.finish();
    assert.equal(result.status, "partial");
    assert.equal(result.captureComplete, false);
    assert.equal(result.sha256, null);
    assert.equal(result.cleanup, "RETIRED");
  }
});

test("late BEGIN and incomplete identity rechecks cannot outlive the shared arm budget", async (t) => {
  t.mock.timers.enable({ apis: ["Date", "setTimeout"] });
  for (const stage of ["timer", "acknowledgement", "chain"]) {
    const blockedChain = stage === "chain",
      reads = [];
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const f = traceFixture({
      acknowledge: false,
      beforeRead: (pid) => {
        reads.push(pid);
        return blockedChain && pid === 901 ? gate : undefined;
      },
    });
    const spawned = once(f.child, "observer-read");
    const arming = f.trace.arm();
    await spawned;
    if (blockedChain) {
      t.mock.timers.tick(6000);
      const checking = once(f.child, "observer-read");
      f.acknowledge();
      await checking;
      t.mock.timers.setTime(Date.now() + 9000);
      release();
    } else if (stage === "acknowledgement") {
      t.mock.timers.setTime(Date.now() + 15000);
      f.acknowledge();
    } else t.mock.timers.tick(15000);
    assert.notEqual((await arming).status, "armed");
    if (blockedChain) assert.deepEqual(reads, [900, 901]);
    release();
    if (stage === "timer") f.acknowledge();
    await f.close();
    const result = await f.trace.finish();
    assert.notEqual(result.status, "observed");
    assert.equal(result.cleanup, "UNCERTAIN");
    assert.equal(result.sha256, null);
  }
});

test("trace framing admits only one drained terminal empty separator after valid capture", async () => {
  const rows = ["entry 42 101 open", "exit 42 102"];
  for (const suffix of [[], ["\n"]]) {
    const f = traceFixture();
    await f.trace.arm();
    for (const chunk of ["entry 42 101 o", "pen\nexit 42 ", "102\n", ...suffix])
      f.child.stdout.write(chunk);
    await f.close();
    const result = await f.trace.finish();
    assert.equal(result.status, "observed");
    assert.equal(result.events, 2);
    assert.equal(
      result.sha256,
      createHash("sha256").update(rows.join("\n")).digest("hex"),
    );
  }
  for (const chunks of [
    ["\n"],
    ["entry 42 101 open\n\n", "exit 42 102\n"],
    ["entry 42 101 open\n\n\n"],
    ["entry 42 101 open\n \n"],
    ["entry 42 101 open\n\n", "x"],
    ["entry 42 101 open\ntruncated"],
    ["entry 42 0 open\n"],
    [],
  ]) {
    const f = traceFixture();
    await f.trace.arm();
    chunks.forEach((chunk) => f.child.stdout.write(chunk));
    await f.close();
    const result = await f.trace.finish();
    assert.equal(result.captureComplete, false);
    assert.equal(result.sha256, null);
    assert.notEqual(result.status, "observed");
    assert.equal(result.cleanup, "RETIRED");
  }
});

test("observer disappearance races require fresh validated retirement of the bound birth", async () => {
  for (const race of ["read", "observe"])
    for (const outcome of ["RETIRED", "LIVE", "UNCERTAIN", "failed", "extra"]) {
      let settling = false,
        disappeared = false;
      const f = traceFixture({
        live: true,
        beforeRead: (pid) => {
          if (settling && pid === 901 && race === "read") {
            disappeared = true;
            throw Object.assign(new Error("Observer disappeared"), {
              code: "ESRCH",
            });
          }
        },
        observeState: (id, state) => {
          if (settling && id.pid === 901) {
            if (!disappeared && race === "observe") {
              disappeared = true;
              throw Object.assign(new Error("Live read raced exit"), {
                code: "ESRCH",
              });
            }
            if (disappeared) {
              if (outcome === "failed") throw new Error("Unproved retirement");
              return outcome === "extra"
                ? { status: "RETIRED", extra: true }
                : { status: outcome };
            }
          }
          return state;
        },
      });
      assert.equal((await f.trace.arm()).status, "armed");
      settling = true;
      f.child.stdout.write("exit 42 101\n\n");
      await f.close();
      const result = await f.trace.finish();
      assert.equal(
        result.cleanup,
        outcome === "RETIRED" ? "RETIRED" : "UNCERTAIN",
      );
      assert.equal(
        result.status,
        outcome === "RETIRED" ? "observed" : "refused",
      );
      assert.ok(
        f.calls.some(([kind, pid]) => kind === "retire" && pid === 900),
      );
      assert.ok(
        !f.calls.some(([kind, pid]) => kind === "retire" && pid === 901),
      );
      assert.equal(
        f.calls.filter(([kind, pid]) => kind === "observe" && pid === 901)
          .length,
        2,
      );
    }
});

test("fixed startup tracing binds owned native parents and independently retires the tracer and sudo", async () => {
  const f = traceFixture({ live: true });
  assert.equal((await f.trace.arm()).status, "armed");
  f.child.stdout.write(
    "entry 42 101 open\nreturn 42 102 open 13 -1\nexec 42 103\n",
  );
  await f.close();
  const result = await f.trace.finish();
  assert.equal(result.status, "observed");
  assert.equal(result.events, 3);
  assert.equal(result.cleanup, "RETIRED");
  assert.match(result.sha256, /^[a-f0-9]{64}$/u);
  assert.deepEqual(
    f.calls
      .filter(([kind]) => kind === "retire")
      .map(([, pid]) => pid)
      .sort(),
    [900, 901],
  );
  const unavailable = openDarwinStartupTrace(
    {},
    { isMatchingCI: false, launch: () => assert.fail("native launch") },
  );
  assert.equal((await unavailable.arm()).status, "unavailable");
  assert.equal((await unavailable.finish()).cleanup, "NOT_RUN");
});

test("startup tracing retains the normalized bound PID and refuses invalid macro operands before launch", async () => {
  const f = traceFixture({ identity: { ...IDENTITY, pid: 73 } });
  assert.equal((await f.trace.arm()).status, "armed");
  f.binding.identity.pid = 74;
  f.child.stdout.write("entry 73 101 open\nexit 73 102\n");
  await f.close();
  const result = await f.trace.finish();
  assert.equal(result.status, "observed");
  assert.equal(result.events, 2);
  assert.equal(result.cleanup, "RETIRED");

  for (const pid of [0, 0x80000000, "42"]) {
    let launched = false;
    const invalid = openDarwinStartupTrace(
      { identity: { ...IDENTITY, pid } },
      {
        isMatchingCI: true,
        verifyInstalled: async () => {},
        launch: () => {
          launched = true;
          assert.fail("invalid PID launch");
        },
        readObserver: () => assert.fail("invalid PID observer"),
        observeObserver: () => assert.fail("invalid PID observation"),
        retireObserver: () => assert.fail("invalid PID retirement"),
      },
    );
    assert.equal((await invalid.arm()).status, "refused");
    assert.equal(launched, false);
    assert.equal((await invalid.finish()).cleanup, "NOT_RUN");
  }
});

test("refused, partial and unretired startup traces retain limitations without adopting a valid prefix", async () => {
  for (const options of [
    { refused: true },
    { cleanupFailure: true },
    { cleanupFailure: true, captureFailure: true },
    { unrelated: true },
    {},
  ]) {
    const f = traceFixture(options);
    const armed = await f.trace.arm();
    if (options.refused || options.unrelated)
      assert.equal(armed.status, "refused");
    else assert.equal(armed.status, "armed");
    if (options.captureFailure) f.child.stdout.write("invalid\n");
    if (!options.refused && !options.cleanupFailure && !options.unrelated)
      f.child.stdout.write("return 42 102 open 13 -1\npartial");
    await f.close(options.refused ? 1 : 0);
    const result = await f.trace.finish();
    assert.notEqual(result.status, "observed");
    assert.equal(result.sha256, null);
    if (options.refused) assert.equal(result.failure.code, "EPERM");
    if (options.cleanupFailure)
      assert.equal(result.cleanupFailure.code, "EPERM");
    if (options.captureFailure) {
      assert.equal(result.failure.reason, "capture");
      assert.equal(result.status, "partial");
    }
    if (options.refused || options.cleanupFailure || options.unrelated)
      assert.equal(result.cleanup, "UNCERTAIN");
    if (options.cleanupFailure)
      assert.ok(f.calls.some(([, pid]) => pid === 900));
    if (options.unrelated)
      assert.equal(
        f.calls.some(([, pid]) => pid === 903),
        false,
      );
    if (!options.refused && !options.cleanupFailure && !options.unrelated)
      assert.equal(result.status, "partial");
  }
});

test("startup tracing refuses unsupported capture and missing installed tools without native fallback", async () => {
  for (const chunk of [
    "entry 43 101 open\n",
    Buffer.from([0xc3]),
    Buffer.alloc(65537, 120),
  ]) {
    const f = traceFixture();
    await f.trace.arm();
    f.child.stdout.write(chunk);
    await f.close();
    const observed = await f.trace.finish();
    assert.equal(observed.status, "partial");
    assert.equal(observed.sha256, null);
    assert.equal(observed.cleanup, "RETIRED");
  }
  const missing = openDarwinStartupTrace(
    { identity: IDENTITY },
    {
      isMatchingCI: true,
      verifyInstalled: async () => {
        throw Object.assign(new Error("missing"), { code: "ENOENT" });
      },
      launch: () => assert.fail("fallback launch"),
    },
  );
  assert.equal((await missing.arm()).status, "unavailable");
  assert.equal((await missing.finish()).cleanup, "NOT_RUN");
});

test("trace shutdown checks every observer after a retirement refusal", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = traceFixture({ retireFailure: true, live: true });
  await f.trace.arm();
  const attempted = once(f.child, "retirement-attempt");
  const finished = f.trace.finish();
  t.mock.timers.tick(10000);
  await attempted;
  await f.close();
  assert.equal((await finished).cleanup, "UNCERTAIN");
  assert.deepEqual(
    [
      ...new Set(
        f.calls.filter(([kind]) => kind === "observe").map(([, pid]) => pid),
      ),
    ].sort(),
    [900, 901],
  );
});

test("observer retirement refuses substituted birth, image or parent and still checks the other owner", async () => {
  for (const substituted of ["birth", "image", "parent"]) {
    const f = traceFixture({ live: true, substituted });
    assert.equal((await f.trace.arm()).status, "armed");
    await f.close();
    assert.equal((await f.trace.finish()).cleanup, "UNCERTAIN");
    assert.ok(f.calls.some(([kind, pid]) => kind === "retire" && pid === 900));
    assert.ok(!f.calls.some(([kind, pid]) => kind === "retire" && pid === 901));
    assert.ok(f.child.stdout.readableEnded && f.child.stderr.readableEnded);
  }
});

test("refused trace shutdown closes undrained owned streams without erasing its first failure", async () => {
  const f = traceFixture();
  await f.trace.arm();
  f.child.stderr.write("refused\n");
  f.child.emit("close", 1, null);
  const result = await f.trace.finish();
  assert.equal(result.cleanup, "UNCERTAIN");
  assert.equal(result.status, "partial");
  assert.equal(result.failure.reason, "attach");
  assert.equal(result.cleanupFailure.reason, "retirement");
  assert.ok(f.child.stdout.closed && f.child.stderr.closed);
});

test("startup trace intent and arm precede release, with changed bindings fenced and SIGABRT preserved", async (t) => {
  for (const changed of ["none", "identity", "image", "files"]) {
    const f = startupEffects(),
      inspect = f.options.inspect;
    let armed = false;
    f.options.openTrace = (binding) => ({
      arm: async () => {
        assert.ok(
          f.saved.some(
            ([name, intent]) =>
              name.endsWith("-intent") && intent.traceIntent.programSha256,
          ),
        );
        assert.deepEqual(binding.identity, IDENTITY);
        armed = true;
        f.calls.push(["trace-arm"]);
        return { status: "armed" };
      },
      finish: async () => {
        f.calls.push(["trace-retired"]);
        return { status: "observed", cleanup: "RETIRED" };
      },
    });
    f.options.inspect = async (...args) => {
      const observed = await inspect(...args);
      if (!armed || args[1] !== changed) return observed;
      if (changed === "identity") return { ...IDENTITY, startMicroseconds: 2 };
      if (changed === "image") return { sha256: "c".repeat(64) };
      return observed.map((value) => ({
        ...value,
        identity: "substituted-policy",
      }));
    };
    const run = runDarwinFeasibilityStartup(
      "/fixture",
      COMPONENTS,
      f.sentinel,
      f.options,
    );
    if (changed !== "none") {
      await assert.rejects(run);
      assert.equal(
        f.calls.some(([kind]) => kind === "exec-release"),
        false,
      );
    } else {
      await run;
      assert.ok(
        f.calls.findIndex(([kind]) => kind === "trace-arm") <
          f.calls.findIndex(([kind]) => kind === "exec-release"),
      );
    }
    assert.ok(f.calls.some(([kind]) => kind === "trace-retired"));
  }
  const original = Object.assign(new Error("Original abort"), {
    signal: "SIGABRT",
    code: null,
  });
  const f = startupEffects({ failure: original });
  let clock = 100000;
  t.mock.method(Date, "now", () => clock);
  f.options.readDenial = async (binding) => {
    assert.equal(binding.endedAt, 100000);
    return { status: "empty" };
  };
  f.options.openTrace = () => ({
    arm: async () => ({ status: "refused" }),
    finish: async () => {
      clock = 200000;
      return { status: "partial", cleanup: "UNCERTAIN" };
    },
  });
  await assert.rejects(
    runDarwinFeasibilityStartup("/fixture", COMPONENTS, f.sentinel, f.options),
    (error) => {
      assert.equal(error, original);
      assert.equal(error.signal, "SIGABRT");
      assert.equal(error.nativeOperation, "policy-only");
      assert.equal(error.nativePhases.at(-1), "policy-applied");
      assert.equal(error.nativeTrace.cleanup, "UNCERTAIN");
      assert.match(
        darwinFeasibilityCause("argv", error).detail,
        /signal=SIGABRT.*startup-trace=partial.*trace-cleanup=uncertain/u,
      );
      return true;
    },
  );
});
