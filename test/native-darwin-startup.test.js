import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { PassThrough } from "node:stream";
import test from "node:test";
import {
  darwinFeasibilityCause,
  darwinFeasibilityPhases,
  darwinFeasibilityPolicy,
  openDarwinFeasibilitySession,
  runDarwinFeasibilityArgv,
  runDarwinFeasibilityStartup,
  darwinStartupCrash,
} from "../ci/native/darwin/index.js";
import {
  LITERAL_ARGUMENTS,
  unavailableFeasibilityResults,
} from "../ci/native/feasibility/index.js";

const SHA = "a".repeat(64),
  FIXTURE_SHA = "b".repeat(64);
const EXEC_PHASES = [
  "policy-enter",
  "policy-applied",
  "exec-enter",
  "fixture-main",
];
const markers = (phases) =>
  phases.map((phase) => `native-darwin-phase: phase=${phase}\n`).join("");

test("Darwin crash diagnosis requires the exact fixture PID, image and launch window and publishes no report contents", () => {
  const startedAt = Date.parse("2026-10-10T00:00:00Z");
  const binding = {
    pid: 42,
    image: "/fixture/build/argv-fixture",
    startedAt,
    endedAt: startedAt + 2000,
  };
  const report = {
    pid: 42,
    procPath: binding.image,
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
  assert.equal(darwinStartupCrash(text(report) + "trailing", binding), null);
  assert.equal(
    darwinStartupCrash("x".repeat(2 * 1024 * 1024 + 1), binding),
    null,
  );
  assert.equal(
    darwinStartupCrash(text({ ...report, faultingThread: 1 }), binding).frame,
    null,
  );
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
            stdin: { end: (byte) => calls.push(["release", operation, byte]) },
          },
          next: async () => {
            if (beforeReady && failure && operation === failedOperation)
              throw failure;
            return row++ === 0
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
  assert.equal(f.saved.length, 4);
  for (const { operation, retired } of observed) {
    assert.equal(retired.status, "RETIRED");
    const calls = f.calls.filter((call) => call[1] === operation);
    const imageIndex = calls.findIndex((call) => call[2] === "image"),
      releaseIndex = calls.findIndex((call) => call[0] === "release");
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
  assert.equal(f.saved.length, 0);
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
