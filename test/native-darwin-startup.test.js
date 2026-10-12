import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { PassThrough } from "node:stream";
import test from "node:test";
import {
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../ci/native/index.js";
import {
  darwinFeasibilityCause,
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
  for (const { operation, retired } of observed) {
    assert.equal(retired.status, "RETIRED");
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

test("Darwin runtime policy and actual source retain the narrow grant and finite flushed phases", async () => {
  const policy = darwinFeasibilityPolicy("/fixture");
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
