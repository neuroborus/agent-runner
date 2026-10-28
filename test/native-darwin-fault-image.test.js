import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { readFile } from "node:fs/promises";
import { PassThrough } from "node:stream";
import test from "node:test";
import { Script } from "node:vm";
import { openDarwinFaultDomain } from "../ci/native/darwin/feasibility-domain.js";
import { openDarwinFeasibilitySession } from "../ci/native/darwin/feasibility.js";
import { DARWIN_LITERAL_ARGUMENTS } from "../ci/native/darwin/protocol.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const candidate = "a".repeat(40),
  pin = "b".repeat(64);
const creator = {
  pid: 42,
  pidVersion: 6,
  asid: 55,
  auid: 90001,
  uid: 90001,
  gid: 90002,
  ruid: 90001,
  rgid: 90002,
  svuid: 90001,
  svgid: 90002,
  startSeconds: 100,
  startMicroseconds: 1,
};
const target = { ...creator, pidVersion: 7 };
const controlCreator = { ...creator, pid: 41, asid: 54 };
const custodian = {
  ...creator,
  pid: 9000,
  pidVersion: 3,
  asid: 77,
  auid: 0,
  uid: 0,
  gid: 0,
  ruid: 0,
  rgid: 0,
  svuid: 0,
  svgid: 0,
};
const policyObservation =
  "native-darwin-fault-policy: caller=9000 target=42 row=0 operation=file-read-data expected=0 actual=1 observed_errno=71\n";
const cleanupRefusal =
  "native-darwin-cleanup: operation=fault-journal-write domain=errno value=5 effects=possible settlement=unsettled\n";

function fixture(caseId, fault) {
  const child = Object.assign(new EventEmitter(), {
    pid: custodian.pid,
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  const events = [];
  let clock = 0,
    inspected = 0,
    current,
    acquired,
    closing = false,
    failed = false;
  let record = {
    candidateSha: candidate,
    caseId,
    asid: controlCreator.asid,
    stage: 0,
    emergency: false,
    receiptSha256: pin,
    intentSha256: "",
    helperSha256: pin,
    policySha256: pin,
    custodian,
    owner: controlCreator,
    descendant: {},
    members: [controlCreator],
    creatorReceiptSha256: "",
    constructorProgramSha256: "",
    constructorCaptureSha256: "",
    version: 5,
    control: true,
    controlRetired: false,
    controlSha256: pin,
    probeConsumed: false,
    probeStatus: 0,
    controlCreator: null,
    controlTarget: null,
    controlCdhash: "",
    controlObservationsSha256: "",
    controlOutputSha256: "",
    creator: controlCreator,
    target: null,
    execution: 1,
    continuation: 0,
    observationsSha256: "",
    imageCdhash: "",
  };
  const refresh = () => {
    record.receiptSha256 = hash(
      JSON.stringify({ ...record, receiptSha256: undefined }),
    );
    return structuredClone(record);
  };
  const send = (value) => child.stdout.write(JSON.stringify(value) + "\n");
  const stream = (name, bytes) =>
    send({ stream: name, hex: Buffer.from(bytes).toString("hex") });
  const close = () => {
    if (closing) return;
    closing = true;
    events.push("custody-closed");
    child.stdout.end();
    child.stderr.end();
    child.emit("close", 0, null);
  };
  child.stdin.on("finish", close);
  child.stdin.on("data", (chunk) => {
    const text = chunk.toString();
    if (text === "P\n") {
      record.stage = 1;
      stream(
        "stderr",
        "native-darwin-phase: phase=policy-enter\nnative-darwin-phase: phase=policy-applied\n",
      );
      send({ creator: { version: 5, phase: 1, record: refresh() } });
      return;
    }
    const [sequence, operation, ...args] = text.trim().split(" ");
    events.push(operation);
    let value;
    if (operation === "image-probe") {
      record.probeConsumed = true;
      record.probeStatus = fault === "probe-query-error" ? -1 : 1;
      if (fault === "control-identity-substitution") {
        record.controlCreator = {
          ...record.controlCreator,
          pid: record.controlCreator.pid + 1,
        };
        record.controlTarget = {
          ...record.controlTarget,
          pid: record.controlTarget.pid + 1,
        };
      }
      if (fault === "control-signature-substitution")
        record.controlCdhash = "d".repeat(40);
      if (fault === "control-observations-substitution")
        record.controlObservationsSha256 = "d".repeat(64);
      if (fault === "control-output-substitution")
        record.controlOutputSha256 = "d".repeat(64);
      value = refresh();
    } else if (operation === "payload" && record.control) {
      stream(
        "stdout",
        JSON.stringify(
          fault === "control-output" ? [] : DARWIN_LITERAL_ARGUMENTS,
        ) + "\n",
      );
      send({ exit: { code: 0, signal: 0 } });
      value = null;
    } else if (operation === "control-settle") {
      record.controlRetired = true;
      record.controlCreator = record.creator;
      record.controlTarget = record.target;
      record.controlCdhash = record.imageCdhash;
      record.controlObservationsSha256 = record.observationsSha256;
      record.controlOutputSha256 = hash(
        '{"phase":"armed"}\n' + JSON.stringify(DARWIN_LITERAL_ARGUMENTS) + "\n",
      );
      value = refresh();
    } else if (operation === "control-next") {
      value = null;
    } else if (operation === "image-exec") {
      record.target = {
        ...record.creator,
        pidVersion: record.creator.pidVersion + 1,
      };
      if (!record.control && fault === "epoch")
        record.target.pidVersion = creator.pidVersion;
      if (!record.control && fault === "birth")
        record.target.startMicroseconds++;
      record.owner = record.target;
      record.imageCdhash = "c".repeat(40);
      record.members.push(record.target);
      value = refresh();
    } else if (operation === "image-read") {
      inspected++;
      value = structuredClone(record);
      if (!record.control && fault === "drift" && inspected === 2)
        value.imageCdhash = "d".repeat(40);
    } else if (operation === "image-seal") {
      record.continuation = 1;
      record.observationsSha256 = args[0];
      if (!record.control && fault === "seal-substitution")
        record.imageCdhash = "d".repeat(40);
      value = refresh();
      if (!record.control && fault === "expired") clock = 12001;
    } else if (operation === "image-continue") {
      assert.equal(args[0], record.receiptSha256);
      record.continuation = 2;
      if (!record.control && fault === "continue-substitution")
        record.imageCdhash = "d".repeat(40);
      value = refresh();
      if (!record.control && fault === "uncertain") {
        child.stdout.emit("error", new Error("Uncertain continuation"));
        return;
      }
    } else if (operation === "recover" || operation === "retire") {
      record.stage = 5;
      value = refresh();
    } else if (operation === "close") {
      record.stage = 6;
      value = refresh();
    } else if (operation === "identity" && fault === "native-error") {
      stream(
        "stderr",
        "native-darwin: operation=fault-image-policy domain=invariant value=0 effects=possible settlement=unsettled\n",
      );
      child.stderr.write(policyObservation);
      child.stderr.write(cleanupRefusal);
      child.stderr.write("native custody failure\n");
      child.emit("close", 78, null);
      return;
    } else value = null;
    if (
      !record.control &&
      fault === "persistence" &&
      operation === "image-seal" &&
      !failed
    ) {
      failed = true;
      child.stdout.emit("error", new Error("Receipt publication failed"));
      return;
    }
    send({ sequence: Number(sequence), value });
    if (operation === "image-continue" && record.control)
      stream("stdout", '{"phase":"armed"}\n');
    if (operation === "control-next") {
      record = {
        ...record,
        asid: creator.asid,
        control: false,
        creator,
        target: null,
        owner: creator,
        members: [creator],
        continuation: 0,
        observationsSha256: "",
        imageCdhash: "",
        probeConsumed: false,
        probeStatus: 0,
      };
      inspected = 0;
      send({ creator: { version: 5, phase: 1, record: refresh() } });
    }
    // Reply delivery and process exit are distinct events.
    if (operation === "close") setImmediate(close);
  });
  const open = () =>
    openDarwinFaultDomain(
      "/fixture",
      candidate,
      caseId,
      "e".repeat(32),
      pin,
      pin,
      {},
      (_root, operation, args, options) => {
        assert.equal(operation, "fault");
        assert.deepEqual(args, []);
        assert.equal(options.suspendedImage, true);
        current = options.launch();
        return { failure: () => null, closeInput() {}, finish: async () => {} };
      },
      {
        controlHash: pin,
        uid: 501,
        gid: 20,
        now: () => clock,
        retain: (value) => {
          acquired = value;
        },
        launch: () => {
          queueMicrotask(() => send({ hello: structuredClone(record) }));
          return child;
        },
        execute: async (_file, args) => {
          if (args.includes("fault-parent"))
            return { stdout: JSON.stringify({ parent: custodian }) };
          if (args.includes("fault-control-verify")) {
            events.push("verify-control");
            return {
              stdout: JSON.stringify({
                independent: fault !== "control-retirement",
                verifier: { ...custodian, pid: 9050 },
                record,
              }),
            };
          }
          if (args.includes("fault-admission")) {
            events.push("readback");
            const value = structuredClone(record);
            if (
              !record.control &&
              ["readback", "verifier"].includes(fault) &&
              record.target
            )
              value.policySha256 = "f".repeat(64);
            return {
              stdout: JSON.stringify({
                independent: record.control || fault !== "independent",
                record: value,
              }),
            };
          }
          const finished = args.includes("fault-closed");
          events.push(finished ? "verify-closed" : "verify-empty");
          if (finished)
            assert.equal(
              closing,
              true,
              "Final verification requires observed custodian exit",
            );
          return {
            stdout: JSON.stringify({
              independent: true,
              complete: fault !== "retirement",
              held: !finished,
              record,
              verifier: {
                ...custodian,
                pid: finished ? 9200 : 9100,
                uid: fault === "verifier" ? 90001 : 0,
              },
            }),
          };
        },
      },
    );
  return {
    open,
    events,
    acquired: () => acquired,
    current: () => current,
    child,
    dispose() {
      close();
      for (const value of [child.stdin, child.stdout, child.stderr])
        value.destroy();
    },
  };
}

test("both Darwin faults read back stopped-image evidence before exactly one continuation", async () => {
  for (const caseId of ["cancel", "owner-loss"]) {
    const f = fixture(caseId);
    try {
      const domain = await f.open();
      assert.deepEqual(domain.initial.creator, creator);
      assert.deepEqual(domain.initial.target, target);
      assert.equal(domain.imageEvidence.version, 5);
      assert.deepEqual(f.events.slice(0, 9), [
        "readback",
        "image-exec",
        "image-read",
        "readback",
        "image-seal",
        "readback",
        "image-read",
        "readback",
        "image-continue",
      ]);
      assert.ok(
        f.events.indexOf("verify-control") < f.events.indexOf("image-probe"),
      );
      await domain.recover();
      assert.equal(
        f.events.filter((value) => value === "image-exec").length,
        2,
      );
      assert.equal(
        f.events.filter((value) => value === "image-continue").length,
        2,
      );
      assert.ok(f.events.indexOf("verify-empty") < f.events.indexOf("close"));
      assert.ok(f.events.indexOf("close") < f.events.indexOf("verify-closed"));
    } finally {
      f.dispose();
    }
  }
});

test("fault admission failures retain both epochs and retire without replaying either image gate", async () => {
  for (const caseId of ["cancel", "owner-loss"])
    for (const fault of [
      "epoch",
      "birth",
      "readback",
      "independent",
      "drift",
      "persistence",
      "expired",
      "uncertain",
      "seal-substitution",
      "continue-substitution",
    ]) {
      const f = fixture(caseId, fault);
      try {
        await assert.rejects(f.open(), undefined, caseId + ":" + fault);
        assert.ok(f.acquired().creator);
        assert.equal(f.acquired().recovery.complete, true, fault);
        assert.equal(
          f.events.filter((value) => value === "image-exec").length,
          fault === "independent" ? 1 : 2,
        );
        assert.equal(
          f.events.filter((value) => value === "image-continue").length,
          ["uncertain", "continue-substitution"].includes(fault) ? 2 : 1,
        );
      } finally {
        f.dispose();
      }
    }
});

test("admission refusal validates the independent verifier before releasing original custody", async () => {
  const f = fixture("cancel", "verifier");
  try {
    await assert.rejects(f.open(), (error) => {
      assert.ok(error.cleanupError);
      assert.notEqual(f.acquired().recovery?.complete, true);
      return true;
    });
    assert.ok(f.events.includes("verify-empty"));
    assert.ok(!f.events.includes("close"));
  } finally {
    f.dispose();
  }
});

test("native fault continuation reobserves and settles before durable one-shot consumption", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-domain.h", import.meta.url),
    "utf8",
  );
  const body = /static void domain_image_continue[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll("&domain_inherited", "domain_inherited")
    .replace(/\bbool /gu, "let ")
    .replace("struct identity target =", "let target =");
  for (const fault of [
    null,
    "receipt",
    "observe",
    "release",
    "persistence",
    "identity",
    "signal",
  ]) {
    const events = [],
      api = {
        domain_record: {
          continuation: 1,
          target: { token: { val: [0, 0, 0, 0, 0, 42] } },
        },
        domain_image_phase: 3,
        domain_inherited: {},
        pin,
        SSTOP: 3,
        SIGCONT: 18,
        need: (ok) => assert.ok(ok),
        domain_image_bound() {},
        domain_image_readback() {
          events.push("readback");
          assert.notEqual(fault, "receipt");
        },
        domain_image_observe() {
          events.push("observe");
          assert.notEqual(fault, "observe");
        },
        image_closure_release() {
          events.push("release");
          return fault !== "release";
        },
        domain_port_cleanup() {},
        failure() {
          throw new Error("cleanup refused");
        },
        domain_store() {
          events.push("persist");
          assert.equal(api.domain_image_phase, 4);
          assert.notEqual(fault, "persistence");
        },
        fault_inspect: () => ({ bsd: { pbi_status: 3 } }),
        audit_identity_same: () => fault !== "identity",
        signal_identity() {
          events.push("continue");
          assert.notEqual(fault, "signal");
        },
      };
    const script = new Script(body);
    if (fault) assert.throws(() => script.runInNewContext(api));
    else script.runInNewContext(api);
    if (!fault)
      assert.deepEqual(events, [
        "readback",
        "observe",
        "release",
        "persist",
        "continue",
      ]);
    if (events.includes("persist")) {
      const previous = events.length;
      assert.throws(() => script.runInNewContext(api));
      assert.equal(events.length, previous);
    } else assert.ok(!events.includes("continue"));
  }
});

test("suspended fault sessions retain gated acknowledgements and original policy diagnostics", async () => {
  const child = Object.assign(new EventEmitter(), {
    pid: 42,
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  const session = openDarwinFeasibilitySession("/fixture", "fault", [], {
    suspendedImage: true,
    launch: () => child,
  });
  child.stderr.write(
    "native-darwin-phase: phase=policy-enter\nnative-darwin-phase: phase=policy-applied\n",
  );
  child.stdout.write(
    '{"event":"armed","ownerPid":42,"childPid":43,"controls":true}\n',
  );
  await session.next();
  await session.authorize("A");
  child.stdout.write('{"event":"detached"}\n');
  await session.next();
  await session.authorize("L");
  child.stdout.write('{"event":"fault-ack","caseId":"owner-loss"}\n');
  await session.next();
  const ended = Promise.all([
    once(child.stdout, "end"),
    once(child.stderr, "end"),
  ]);
  child.stdout.end();
  child.stderr.end();
  await ended;
  child.emit("close", null, "SIGKILL");
  await session.finish("SIGKILL");
  for (const value of [child.stdin, child.stdout, child.stderr])
    value.destroy();
});

test("native fault exec persists original ownership before consuming X and keeps uncertain epochs recoverable", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-domain.h", import.meta.url),
    "utf8",
  );
  const body = /static void domain_image_exec\(void\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace(
      "int *ready = domain_pipes[3], *release = domain_pipes[4]; struct exec_handoff handoff = {0};",
      "let ready = domain_pipes[3], release = domain_pipes[4], handoff = {};",
    )
    .replace("struct identity target;", "let target;")
    .replaceAll("&handoff", "handoff")
    .replaceAll("&release[1]", "release")
    .replaceAll("&ready[0]", "ready")
    .replaceAll("(void)", "")
    .replace(/\bbool /gu, "let ");
  for (const fault of [null, "persist", "write", "receipt", "observe"]) {
    const events = [],
      api = {
        domain_record: {
          creator: { token: { val: [0, 0, 0, 0, 0, 42] } },
          control_retired: true,
          probe: {},
        },
        exec_handoff_refused: () => true,
        domain_image_phase: 1,
        domain_pin: 200,
        MACH_PORT_NULL: 0,
        domain_released: false,
        domain_pipes: [[], [], [], [3], [4]],
        NULL: null,
        domain_image_bound() {},
        need: (ok) => assert.ok(ok),
        invariant: (ok) => assert.ok(ok),
        domain_check: (ok) => assert.ok(ok),
        fault_inspect: () => ({ token: {} }),
        audit_identity_same: () => true,
        domain_store() {
          events.push("persist");
          assert.notEqual(fault, "persist");
        },
        exec_handoff_release() {
          events.push("X");
          assert.equal(api.domain_image_phase, 2);
          assert.equal(api.domain_released, true);
          return fault !== "write";
        },
        exec_handoff_receive() {
          events.push("EOF");
          return fault !== "receipt";
        },
        exec_handoff_identity: () => true,
        domain_close() {},
        poll() {},
        domain_known() {},
        domain_image_observe(inheritance) {
          assert.equal(inheritance, true);
          events.push("observe");
          assert.notEqual(fault, "observe");
          api.domain_image_phase = 3;
        },
      };
    const script = new Script(body);
    if (fault) assert.throws(() => script.runInNewContext(api));
    else script.runInNewContext(api);
    assert.equal(events[0], "persist");
    if (fault !== "persist") {
      const before = events.length;
      assert.throws(() => script.runInNewContext(api));
      assert.equal(
        events.length,
        before,
        "An uncertain gate cannot be replayed",
      );
    }
    if (["write", "receipt"].includes(fault))
      assert.equal(api.domain_record.target, undefined);
    if (!fault)
      assert.deepEqual(events, ["persist", "X", "EOF", "observe", "persist"]);
  }
});

test("fault recovery admits an unpublished replacement only through original birth, credentials and audit custody", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-domain.h", import.meta.url),
    "utf8",
  );
  const selector = source
    .slice(
      source.indexOf("static void domain_image(struct identity"),
      source.indexOf("static void domain_policy_check"),
    )
    .split("  int fd = openat")[0]
    .split("\n")
    .slice(1)
    .join("\n")
    .replace("char image[4096];", "let image = {};")
    .replace("sizeof(image)", "4096")
    .replace("bool control", "let control")
    .replace("const char *leaf", "let leaf")
    .replace(", *expected", ", expected");
  for (const fault of [
    null,
    "unfenced",
    "legacy",
    "historical",
    "unattempted",
    "published",
    "foreign",
  ]) {
    const api = {
      value: { token: { val: [0, 0, 0, 0, 0, 42] } },
      domain_record: {
        control: false,
        probe_consumed: fault !== "unattempted",
        creator: { token: { val: [0, 0, 0, 0, 0, 42] } },
        target: {
          token: { val: [0, 0, 0, 0, 0, fault === "published" ? 42 : 0] },
        },
      },
      domain_legacy: fault === "legacy",
      domain_historical: fault === "historical",
      domain_fenced: fault !== "unfenced",
      domain_control_asset: "/sealed/exec-control",
      domain_helper: "/sealed/helper",
      proc_pidpath(_pid, out) {
        out.value =
          fault === "foreign" ? "/other/image" : "/sealed/exec-control";
        return 20;
      },
      strcmp(a, b) {
        return (a.value ?? a) === b ? 0 : 1;
      },
      need: (ok) => assert.ok(ok),
    };
    const select = () =>
      new Script(`(() => {${selector}; return leaf;})()`).runInNewContext(api);
    if (fault) assert.throws(select, undefined, fault);
    else assert.equal(select(), "exec-control");
  }
  const body = /static void domain_recheck\(void\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll(/\b(?:unsigned|int) /gu, "let ")
    .replaceAll("struct identity ", "let ")
    .replace("struct proc_bsdinfo b;", "let b = {};")
    .replaceAll("&b", "b")
    .replaceAll("sizeof(b)", "128");
  const original = {
    token: { val: [90001, 90001, 90002, 90001, 90002, 42, 55, 6] },
    birth: 100,
  };
  const target = {
    ...structuredClone(original),
    token: { val: [...original.token.val.slice(0, 7), 7] },
  };
  for (const fault of [
    null,
    "legacy",
    "execution",
    "creator",
    "birth",
    "credentials",
    "published",
    "image",
  ]) {
    const actual = structuredClone(target),
      record = {
        creator: original,
        target: { token: { val: [] } },
        members: 1,
        known: [original],
        execution: 1,
      };
    if (fault === "execution") record.execution = 0;
    if (fault === "creator") record.creator = actual;
    if (fault === "credentials") actual.token.val[1]++;
    if (fault === "published") record.target = { ...actual, birth: 101 };
    let images = 0;
    const run = () =>
      new Script(body).runInNewContext({
        domain_record: record,
        domain_legacy: fault === "legacy",
        errno: 0,
        PROC_PIDTBSDINFO: 1,
        SZOMB: 5,
        ESRCH: 3,
        ENOENT: 2,
        proc_pidinfo(_pid, _kind, _arg, b) {
          b.pbi_status = 3;
          return 128;
        },
        domain_birth_same: () => fault !== "birth",
        fault_inspect: () => actual,
        audit_identity_same: (a, b) => JSON.stringify(a) === JSON.stringify(b),
        need: (ok) => assert.ok(ok),
        domain_image() {
          images++;
          assert.notEqual(fault, "image");
        },
      });
    if (fault) assert.throws(run, undefined, fault);
    else {
      run();
      assert.equal(images, 1);
    }
  }
});

test("fault policy queries retain exact decisions and errno before the first unchanged refusal", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-domain.h", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static void ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const diagnostic = body("domain_effective_diagnostic").replaceAll(
    "int ",
    "let ",
  );
  const effective = body("domain_effective")
    .replace("char paths[4][4096];", "const paths = Array(4);")
    .replaceAll(
      /const char \*(names|objects|operations)\[\] = \{([^\n]+)\};/gu,
      "const $1 = [$2];",
    )
    .replaceAll("sizeof(paths[i])", "4096")
    .replace("snprintf(paths[i],", "snprintf(paths, i,")
    .replace(/int expected = ([^\n]+);/u, "let expected = Number($1);")
    .replaceAll(/\b(?:unsigned|bool|int) /gu, "let ")
    .replace("struct stat type;", "let type = {};")
    .replace("&type", "type")
    .replace("*sandbox_binding.no_report", "sandbox_binding.no_report");
  const objects = [
    "/sealed/helper",
    "/sealed/root/build/helper",
    "/sealed/root/build/argv-fixture",
    "/sealed/root/build/git",
    "/sealed/root/workspace",
    "/usr/lib/libSystem.B.dylib",
    "/dev/null",
    "/",
    "/sealed/policy",
  ];
  const operations = [
    "file-read-data",
    "file-write-data",
    "file-write-create",
    "file-write-unlink",
    "file-map-executable",
  ];
  const decisions = [
    [0, 1, 1, 1, 0, 0],
    [0, 1, 1, 1, 0, 0],
    [0, 1, 1, 1, 0, 0],
    [0, 1, 1, 1, 0, 0],
    [0, 1, 1, 1, 1, 1],
    [0, 1, 1, 1, 0, 1],
    [0, 0, 0, 0, 1, 1],
    [0, 1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 1],
  ];
  const queries = objects.flatMap((object, row) =>
    operations.flatMap((operation, column) =>
      column === 4 && [4, 6, 7].includes(row)
        ? []
        : [
            {
              object,
              row,
              operation,
              expected: decisions[row][column],
            },
          ],
    ),
  );
  queries.push(
    {
      row: 9,
      object: "/sealed/exec-control",
      operation: "file-read-data",
      expected: 0,
    },
    {
      row: 9,
      object: "/sealed/exec-control",
      operation: "file-map-executable",
      expected: 0,
    },
    { row: -1, operation: "process-fork", expected: 0 },
  );
  for (const fault of [
    null,
    { at: 0, actual: 1, errno: 71 },
    { at: 1, actual: 0, errno: 72 },
    { at: 4, actual: -1, errno: 13 },
    { at: 10, actual: -1, errno: 13 },
    { at: 7, actual: 2, errno: 0 },
    { at: 44, actual: 1, errno: 74 },
  ]) {
    const calls = [],
      records = [];
    let comparisons = 0,
      flushes = 0,
      advanced = false;
    const refusal = new Error("fault-image-policy");
    const query = (pid, operation, object) => {
      assert.equal(pid, 42);
      const expected = queries[calls.length];
      assert.deepEqual(
        { operation, object },
        {
          operation: expected.operation,
          object: expected.object,
        },
      );
      const failing = calls.length === fault?.at;
      calls.push(expected);
      api.errno = failing ? fault.errno : 79;
      return failing ? fault.actual : expected.expected;
    };
    const api = {
      errno: 0,
      stderr: {},
      domain_helper: objects[0],
      domain_policy: objects[8],
      domain_record: {
        root: "/sealed/root",
        control: false,
        control_retired: true,
        probe: {},
      },
      domain_control_asset: "/sealed/exec-control",
      exec_handoff_refused: () => true,
      lstat(path, type) {
        type.st_mode = path === "/dev/null" ? "character" : "directory";
        return 0;
      },
      S_ISCHR: (mode) => mode === "character",
      S_ISDIR: (mode) => mode === "directory",
      sandbox_binding: {
        no_report: 256,
        check(pid, operation, filter) {
          assert.equal(filter, 256);
          return query(pid, operation);
        },
      },
      feasibility_sandbox_path(binding, pid, operation, object) {
        assert.equal(binding, api.sandbox_binding);
        return query(pid, operation, object);
      },
      snprintf(paths, index, size, format, root, name) {
        assert.equal(size, 4096);
        assert.equal(format, "%s/%s");
        paths[index] = `${root}/${name}`;
        return paths[index].length;
      },
      need: (ok) => assert.ok(ok),
      invariant(ok, operation) {
        comparisons++;
        assert.equal(operation, "fault-image-policy");
        assert.equal(
          api.errno,
          fault?.at === calls.length - 1 ? fault.errno : 79,
        );
        if (!ok) throw refusal;
      },
      getpid() {
        api.errno = 95;
        return 9000;
      },
      fprintf(stream, format, ...values) {
        assert.equal(stream, api.stderr);
        records.push(format.replace(/%[dus]/gu, () => String(values.shift())));
        assert.equal(values.length, 0);
        api.errno = 5;
        return -1;
      },
      fflush(stream) {
        assert.equal(stream, api.stderr);
        flushes++;
        api.errno = 28;
        return -1;
      },
    };
    const evaluate = new Script(`
      function domain_effective_diagnostic(target, row, operation, expected, actual, observed_errno) {${diagnostic}}
      (target) => {${effective}}
    `).runInNewContext(api);
    const run = () => {
      evaluate({ token: { val: [0, 0, 0, 0, 0, 42] } });
      advanced = true;
    };
    if (fault) assert.throws(run, (error) => error === refusal);
    else run();
    const count = fault ? fault.at + 1 : 45;
    assert.deepEqual(calls, queries.slice(0, count));
    assert.equal(
      comparisons,
      count - (count > 42 ? Math.min(2, count - 42) : 0),
    );
    assert.equal(advanced, fault === null);
    assert.equal(flushes, fault ? 1 : 0);
    const expected = fault && queries[fault.at];
    assert.deepEqual(
      records,
      fault
        ? [
            `native-darwin-fault-policy: caller=9000 target=42 row=${expected.row} operation=${expected.operation} expected=${expected.expected} actual=${fault.actual} observed_errno=${fault.errno}\n`,
          ]
        : [],
    );
    if (fault?.at === 0) assert.equal(records[0], policyObservation);
    if (!fault) {
      // The observed directory-map return 0 is not queried as regular-file
      // mapping evidence. Native type substitution still refuses admission.
      assert.ok(
        !calls.some(
          ({ object, operation }) =>
            object === objects[4] && operation === "file-map-executable",
        ),
      );
      api.lstat = (_path, type) => {
        type.st_mode = "regular";
        return 0;
      };
      calls.length = 0;
      assert.throws(() => evaluate({ token: { val: [0, 0, 0, 0, 0, 42] } }));
    }
  }
});

test("fault custody diagnostics retain the original native refusal and separate control stderr", async () => {
  const f = fixture("cancel", "native-error");
  try {
    const domain = await f.open();
    await assert.rejects(
      domain.inspect("/fixture", "identity", 42, 9000),
      (error) => {
        assert.equal(error.exitCode, 78);
        assert.equal(error.custodyError.exitCode, 78);
        assert.equal(
          error.custodyError.stderr.toString(),
          policyObservation + cleanupRefusal + "native custody failure\n",
        );
        return true;
      },
    );
    const original = f.current().stderr.read().toString();
    assert.match(
      original,
      /native-darwin: operation=fault-image-policy domain=invariant value=0/u,
    );
    assert.doesNotMatch(
      original,
      /native-darwin-fault-policy|native-darwin-cleanup/u,
    );
  } finally {
    f.dispose();
  }
});

test("native failure settlement retains original custody and never retries a refused retirement", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-domain.h", import.meta.url),
    "utf8",
  );
  const body = /static void domain_failure_retire\(void\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("  static bool settling;", "");
  for (const fault of [null, "pin", "stage", "persist", "retire"]) {
    const events = [],
      api = {
        settling: false,
        domain_failure_cleanup: false,
        domain_pin: fault === "pin" ? 0 : 200,
        MACH_PORT_NULL: 0,
        domain_record: { stage: fault === "stage" ? 5 : 1 },
        domain_fenced: false,
        domain_store(stage) {
          assert.equal(api.domain_fenced, true);
          assert.equal(stage, 3);
          events.push("persist");
          assert.notEqual(fault, "persist");
        },
        domain_retire() {
          events.push("retire");
          assert.notEqual(fault, "retire");
        },
      };
    const run = new Script(`(() => {${body}})()`);
    if (["persist", "retire"].includes(fault))
      assert.throws(() => run.runInNewContext(api));
    else run.runInNewContext(api);
    const count = events.length;
    run.runInNewContext(api);
    assert.equal(events.length, count);
    if (!fault) assert.deepEqual(events, ["persist", "retire"]);
    if (["pin", "stage"].includes(fault)) assert.deepEqual(events, []);
  }
});

test("fault trusted setup applies policy and complete closure before the direct suspended image gate", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-domain.h", import.meta.url),
    "utf8",
  );
  const helper = await readFile(
    new URL("../ci/native/darwin/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  // Apple's Libc include/unistd.h selects directory-backed __getgroups for
  // either explicit opt-in. Model that declaration rule from the real preamble;
  // restoring the macro must fail the missing-directory-record regression.
  const extended =
    /^\s*#\s*define\s+(?:_DARWIN_C_SOURCE|_DARWIN_UNLIMITED_GETGROUPS)\b/mu.test(
      helper.split("#include")[0],
    );
  const start = source.indexOf(
    '    char *arguments[] = {domain_helper, "fault", NULL};',
  );
  const end = source.indexOf('    remember("fault-image-exec"', start);
  assert.ok(start > 0 && end > start);
  const body = source
    .slice(start, end)
    .replace(
      'char *arguments[] = {domain_helper, "fault", NULL}; extern char **environ;',
      'let arguments_ = [domain_helper, "fault", null];',
    )
    .replace(
      /char \*control_arguments\[\] = \{([^\n]+)\};/u,
      "let control_arguments = [$1];",
    )
    .replace("struct exec_handoff probe = {0};", "let probe = {};")
    .replace("struct exec_probe result =", "let result =")
    .replaceAll("&probe", "probe")
    .replaceAll("&result", "result")
    .replaceAll("sizeof(result)", "20")
    .replace("sizeof(result)", "20")
    .replace(
      "struct exec_handoff handoff = {0}; domain_handoff = &handoff; const int descriptors[] = {0, 1, 2};",
      "let handoff = {}; domain_handoff = handoff; const descriptors = [0, 1, 2];",
    )
    .replace(
      "struct rlimit limit = {.rlim_cur = 32, .rlim_max = 32}, observed;",
      "let limit = {rlim_cur:32, rlim_max:32}, observed = {};",
    )
    .replace("gid_t group;", "let group;")
    .replace("mach_port_t local =", "let local =")
    .replace("struct identity birth =", "let birth =")
    .replaceAll("&handoff", "handoff")
    .replaceAll("&limit", "limit")
    .replaceAll("&observed", "observed")
    .replaceAll("&birth", "birth")
    .replace("sizeof(birth)", "128")
    .replace("sizeof(birth)", "128")
    .replace("&group", "{set value(v){group=v}}")
    .replaceAll(/\bbool /gu, "let ")
    .replaceAll("&domain_mapping", "domain_mapping")
    .replaceAll("&domain_map_control", "domain_map_control")
    .replaceAll(/\barguments, environ/gu, "arguments_, environ");
  for (const fault of [
    null,
    "missing-directory",
    "prepare",
    "policy",
    "closure",
    "mapping",
    "map-close",
    "groups-failed",
    "groups-empty",
    "groups-wrong",
    "groups-additional",
    "nproc-failed",
    "nproc-soft",
    "nproc-hard",
  ]) {
    const events = [],
      api = {
        domain_helper: "/sealed/helper",
        domain_policy: "/sealed/policy",
        domain_record: { uid: 90001, gid: 90002, control: false },
        domain_control_asset: "/sealed/exec-control",
        image_spawn_inputs: () => true,
        setenv: () => 0,
        exec_handoff_byte: () => true,
        exec_handoff_attempt: () => ({}),
        exec_handoff_refused: () => true,
        domain_mapping: {},
        domain_map_control: {},
        exec_mapping_check(_value, denied) {
          events.push(denied ? "map-deny" : "map-allow");
          return fault !== "mapping";
        },
        exec_mapping_close() {
          events.push("map-close");
          return fault !== "map-close";
        },
        need: (ok) => assert.ok(ok),
        domain_bootstrap_local: 200,
        MACH_PORT_NULL: 0,
        NULL: null,
        RLIMIT_NPROC: 1,
        domain_handoff: null,
        sandbox_binding: {},
        environ: [],
        exec_handoff_prepare(handoff) {
          handoff.kind = "errno";
          handoff.value = 12;
          return fault !== "prepare";
        },
        remember(operation, kind, value) {
          assert.deepEqual(
            [operation, kind, value],
            ["fault-image-prepare", "errno", 12],
          );
        },
        failure() {
          throw new Error("prepare refused");
        },
        invariant: (ok, operation) => assert.ok(ok, operation),
        posix_check: (value) => assert.equal(value, 0),
        audit_fresh() {
          events.push("audit");
        },
        setrlimit: () => 0,
        setgroups: () => 0,
        setgid: () => 0,
        setuid: () => 0,
        getgroups(capacity, group) {
          assert.equal(capacity, 1);
          if (
            fault === "groups-failed" ||
            (extended && fault === "missing-directory")
          )
            return -1;
          const actual =
            fault === "groups-empty"
              ? []
              : fault === "groups-wrong"
                ? [90003]
                : fault === "groups-additional"
                  ? [90002, 90003]
                  : [90002];
          if (actual.length > capacity) return -1;
          if (actual.length) group.value = actual[0];
          return actual.length;
        },
        getrlimit(_kind, value) {
          Object.assign(value, {
            rlim_cur: fault === "nproc-soft" ? 31 : 32,
            rlim_max: fault === "nproc-hard" ? 33 : 32,
          });
          return fault === "nproc-failed" ? -1 : 0;
        },
        policy() {
          events.push("policy");
          assert.notEqual(fault, "policy");
        },
        feasibility_sandbox_active: () => 1,
        image_closure_prepare(_handoff, local) {
          events.push("closure");
          assert.equal(local, 200);
          assert.equal(api.domain_bootstrap_local, 0);
          assert.notEqual(fault, "closure");
        },
        fault_inspect: () => creator,
        getpid: () => 42,
        write: (_fd, value) => (value === creator ? 128 : 20),
        domain_io: (size, expected) => assert.equal(size, expected),
        exec_handoff_execute(_handoff, gate, receipt, image, args) {
          assert.equal(api.domain_handoff, _handoff);
          assert.deepEqual([gate, receipt, image], [4, 3, "/sealed/helper"]);
          assert.equal(args.join(","), "/sealed/helper,fault,");
          events.push("X");
        },
      };
    const run = () => new Script(body).runInNewContext(api);
    const refused = fault && fault !== "missing-directory";
    if (refused)
      assert.throws(
        run,
        fault.startsWith("groups-") || fault.startsWith("nproc-")
          ? /fault-image-credentials/u
          : undefined,
      );
    else {
      run();
      assert.deepEqual(events, [
        "audit",
        "policy",
        "map-deny",
        "map-allow",
        "map-close",
        "map-close",
        "closure",
        "X",
      ]);
    }
    if (refused) assert.ok(!events.includes("X"));
    if (["mapping", "map-close"].includes(fault))
      assert.equal(events.filter((event) => event === "map-close").length, 2);
  }
});

test("native fault retirement failures retain the primary refusal and an independent cleanup cause", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const body = /static void remember\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    source,
  )[1];
  const api = {
    domain_failure_cleanup: false,
    resource_uncertain: false,
    failed_operation: null,
    failed_domain: null,
    failed_value: 0,
    cleanup_operation: null,
    cleanup_domain: null,
    cleanup_value: 0,
  };
  const remember = new Script(
    `(operation, domain, value) => {${body}}`,
  ).runInNewContext(api);
  remember("fault-image-policy", "invariant", 0);
  api.domain_failure_cleanup = true;
  remember("fault-journal-write", "errno", 5);
  remember("audit-session-create", "errno", 1);
  assert.deepEqual(
    [api.failed_operation, api.failed_domain, api.failed_value],
    ["fault-image-policy", "invariant", 0],
  );
  assert.deepEqual(
    [api.cleanup_operation, api.cleanup_domain, api.cleanup_value],
    ["fault-journal-write", "errno", 5],
  );
  assert.equal(api.resource_uncertain, true);
});

test("fault creator admission rejects unexpected real, effective or saved credentials and inherited audit custody", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-domain.h", import.meta.url),
    "utf8",
  );
  const body = /static void domain_creator_check[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll("(unsigned)", "");
  const admitted = {
    token: { val: [90001, 90001, 90002, 90001, 90002, 42, 55, 6] },
    bsd: { pbi_svuid: 90001, pbi_svgid: 90002 },
  };
  const check = new Script(
    `(creator, parent_asid) => {${body}}`,
  ).runInNewContext({
    domain_record: { uid: 90001, gid: 90002 },
    AU_ASSIGN_ASID: 0xffffffff,
    invariant: (ok, operation) => {
      if (!ok) throw new Error(operation);
    },
  });
  check(admitted, 77);
  for (const index of [0, 1, 2, 3, 4]) {
    const changed = structuredClone(admitted);
    changed.token.val[index] = 0;
    assert.throws(() => check(changed, 77), /fault-image-credentials/u);
  }
  for (const field of ["pbi_svuid", "pbi_svgid"]) {
    const changed = structuredClone(admitted);
    changed.bsd[field] = 0;
    assert.throws(() => check(changed, 77), /fault-image-credentials/u);
  }
  for (const asid of [0, 77, 0xffffffff]) {
    const changed = structuredClone(admitted);
    changed.token.val[6] = asid;
    assert.throws(() => check(changed, 77), /fault-image-credentials/u);
  }
});

test("invalid outside controls and query-like probe statuses fence the primary without replay", async () => {
  for (const fault of [
    "control-output",
    "control-retirement",
    "probe-query-error",
    "control-identity-substitution",
    "control-signature-substitution",
    "control-observations-substitution",
    "control-output-substitution",
  ]) {
    const f = fixture("cancel", fault);
    try {
      await assert.rejects(f.open());
      assert.equal(f.acquired().recovery.complete, true);
      assert.equal(
        f.events.filter((event) => event === "image-exec").length,
        1,
      );
      assert.equal(
        f.events.filter((event) => event === "image-probe").length,
        ["control-output", "control-retirement"].includes(fault) ? 0 : 1,
      );
    } finally {
      f.dispose();
    }
  }
});
