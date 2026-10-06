import assert from "node:assert/strict";
import test from "node:test";
import { observationDigest } from "../index.js";
import {
  createWindowsAuditDecoder,
  bindWindowsAuditEvent,
  createWindowsAuditCustody,
  createWindowsSecurityCapture,
  windowsObserverConfiguration,
} from "./index.js";
import {
  effectiveFixture,
  hash,
  candidateSha,
  nonce,
  account,
  fileId,
} from "./effective.fixture.js";
import { digest } from "./protocol.js";
import { encode } from "./custody-protocol.js";

const versions = [4656, 4663, 5152, 5156, 5157].map((id) => ({
  id,
  versions: [1],
}));
const mapping = {
  sdkSha256: hash,
  abiSha256: hash,
  versions,
  mappingSha256: observationDigest(versions),
};
const word = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};
const time = 134116992000000000n;
const barrier = (sequence, records) => {
  const bytes = Buffer.alloc(20);
  bytes.writeUInt32LE(0xfffffffe);
  bytes.writeUInt32LE(sequence, 4);
  bytes.writeBigUInt64LE(time + BigInt(sequence) * 10000n, 8);
  bytes.writeUInt32LE(records, 16);
  return bytes;
};
const eventBytes = Buffer.from("event\0", "utf16le"),
  bookmarkBytes = Buffer.from("bookmark\0", "utf16le");
const framed = Buffer.concat([word(eventBytes.length), eventBytes]);
const terminal = Buffer.concat([
  word(0xffffffff),
  word(eventBytes.length),
  word(1),
  word(bookmarkBytes.length),
  bookmarkBytes,
]);
const capture = () =>
  Buffer.concat([word(0), barrier(1, 0), framed, barrier(2, 1), terminal]);
const native = (kind, object) => ({
  kind,
  fields: Object.entries(object).map(([name, value]) => ({
    nameHex: encode(name),
    hex: encode(value),
  })),
});
const event = () => ({
  Provider: "Microsoft-Windows-Security-Auditing",
  EventID: "4663",
  Version: "1",
  Keywords: "0x8020000000000000",
  Channel: "Security",
  EventRecordID: "10",
  TimeCreated: "2026-01-01T00:00:00.0015000Z",
  ProcessId: "0x385",
  SubjectUserSid: account,
  ObjectType: "File",
  ObjectName: "C:\\Fixture\\storage\\workspace\\owned.txt",
  AccessMask: "0x1",
});
function decoder(change = (value) => value) {
  return createWindowsAuditDecoder(
    {
      xml: async (bytes) =>
        bytes.equals(eventBytes)
          ? change(native("event", event()))
          : native("bookmark", {
              Channel: "Security",
              RecordId: "10",
              IsCurrent: "true",
            }),
    },
    mapping,
  );
}
function observerInput(f = effectiveFixture()) {
  const job = {
    daclSha256: hash,
    limitFlags: 0x2008,
    processLimit: 32,
    uiRestrictions: 255,
    members: [f.subject],
  };
  const domain = {
    accountSid: account,
    restrictingSid: f.input.request.restrictingSid,
    jobSha256: observationDigest(job),
  };
  const value = {
    plan: {
      schemaVersion: 1,
      candidateSha,
      nonce,
      domainSha256: observationDigest(domain),
      policySha256: f.plan.policySha256,
      reviewSha256: hash,
      routes: [
        {
          id: "inspect",
          operation: "read",
          targetSha256: digest(fileId(4)),
          permitTargetSha256: digest(fileId(5)),
          denyTargetSha256: digest(fileId(6)),
          nonceSha256: hash,
          beforeSha256: hash,
          afterSha256: hash,
          outcome: "permit",
        },
      ],
    },
    domain,
    bindings: ["control-permit", "control-deny", "tool"].map((phase) => ({
      routeId: "inspect",
      phase,
      selector: event().ObjectName,
      opcode: phase === "control-deny" ? "4656" : "4663",
      accessMask: 1,
      filterId: null,
    })),
    pins: {
      manifestSha256: hash,
      imageSha256: hash,
      sourceSha256: hash,
      abiSha256: hash,
    },
  };
  return { value, job, f };
}
const retired = (value, helper) => ({
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
  candidateSha,
  nonce,
  domainSha256: value.plan.domainSha256,
  noLiveMembers: true,
  noForeignCreators: true,
  noPrincipalFlows: true,
  nativeEventSha256: hash,
  verifier: {
    pid: 902,
    creationTime: "10902",
    sessionId: 0,
    userSid: "S-1-5-18",
  },
  helper,
});

test("Windows bounded Security frames preserve native XML records, bookmark and acknowledged intervals", async () => {
  const configuration = windowsObserverConfiguration(observerInput().value);
  assert.ok(
    configuration.query.includes(
      "EventID=4656) and band(Keywords,4503599627370496)",
    ),
  );
  assert.ok(
    configuration.query.includes(
      "EventID=4663) and band(Keywords,9007199254740992)",
    ),
  );
  const d = decoder(),
    bytes = capture();
  for (let at = 0; at < bytes.length; at += 7)
    await d.push(bytes.subarray(at, at + 7));
  const result = d.finish();
  assert.equal(result.records, 1);
  assert.equal(result.events[0].raw.pid, 901);
  assert.equal(result.events[0].raw.target, event().ObjectName);
  assert.equal(result.bookmark, "10");
  assert.equal(result.barriers.length, 2);
  const truncated = decoder();
  await truncated.push(bytes.subarray(0, -1));
  assert.throws(() => truncated.finish());
});
test("Windows malformed schema, duplicates, loss/clear, versions and terminal counters latch failure", async () => {
  for (const change of [
    (value) => {
      value.fields.push(structuredClone(value.fields[0]));
      return value;
    },
    (value) => {
      value.fields.find((item) => item.nameHex === encode("EventID")).hex =
        encode("1101");
      return value;
    },
    (value) => {
      value.fields.find((item) => item.nameHex === encode("EventID")).hex =
        encode("1102");
      return value;
    },
    (value) => {
      value.fields.find((item) => item.nameHex === encode("Version")).hex =
        encode("2");
      return value;
    },
    (value) => {
      value.fields.find((item) => item.nameHex === encode("ProcessId")).hex =
        encode("0");
      return value;
    },
  ]) {
    const d = decoder(change);
    await assert.rejects(d.push(capture()));
    await assert.rejects(d.push(word(0)));
    assert.throws(() => d.finish());
  }
  const bad = capture();
  bad.writeUInt32LE(2, bad.length - terminal.length + 8);
  await assert.rejects(decoder().push(bad));
});
test("Windows Security network schemas use matched per-event process fields and valid native addresses", async () => {
  for (const id of [5152, 5156, 5157]) {
    const values = {
      ...event(),
      EventID: String(id),
      Keywords: id === 5156 ? "0x8020000000000000" : "0x8010000000000000",
      FilterRTID: "17",
      Protocol: "6",
      SourceAddress: "127.0.0.1",
      SourcePort: "40000",
      DestAddress: "127.0.0.1",
      DestPort: "40001",
      Direction: "%%14593",
    };
    for (const key of [
      "ProcessId",
      "SubjectUserSid",
      "ObjectType",
      "ObjectName",
      "AccessMask",
    ])
      delete values[key];
    values[id === 5152 ? "ProcessId" : "ProcessID"] = "901";
    const d = decoder(() => native("event", values));
    await d.push(capture());
    assert.equal(
      d.finish().events[0].raw.target,
      "tcp:127.0.0.1:40000>127.0.0.1:40001:out",
    );
    values.SourceAddress = "::::";
    await assert.rejects(
      decoder(() => native("event", values)).push(capture()),
    );
  }
});
test("Windows audit attribution requires unchanged held creation/token/Job/file identities in the native window", async () => {
  const { value, job, f } = observerInput(),
    d = decoder();
  await d.push(capture());
  const observation = d.finish(),
    witness = observation.events[0];
  f.reader.inspectJob = async () => ({ ...job, independent: true });
  const bytes = Buffer.from("sentinel"),
    file = {
      identity: fileId(4),
      bytes: bytes.length,
      sha256: digest(bytes),
      daclSha256: hash,
      hex: bytes.toString("hex"),
    };
  const transfer = {
    subject: 0,
    job: 0,
    object: { before: file, after: file, index: 3 },
  };
  assert.equal(
    (
      await bindWindowsAuditEvent(
        f.reader,
        witness,
        value,
        value.bindings[2],
        transfer,
        observation.barriers,
      )
    ).held,
    true,
  );
  for (const change of [
    () => {
      transfer.object.after = { ...file, identity: fileId(5) };
    },
    () => {
      f.token.restrictedSids = [];
    },
    () => {
      job.members = [];
    },
    () => {
      witness.time = String(time);
    },
  ]) {
    const prior = structuredClone({ transfer, token: f.token, job, witness });
    change();
    await assert.rejects(
      bindWindowsAuditEvent(
        f.reader,
        witness,
        value,
        value.bindings[2],
        transfer,
        observation.barriers,
      ),
    );
    Object.assign(transfer, prior.transfer);
    Object.assign(f.token, prior.token);
    Object.assign(job, prior.job);
    Object.assign(witness, prior.witness);
  }
  f.subject.creationTime = String(BigInt(witness.time) + 1n);
  await assert.rejects(
    bindWindowsAuditEvent(
      f.reader,
      witness,
      value,
      value.bindings[2],
      transfer,
      observation.barriers,
    ),
  );
});

test("Windows network attribution binds the observer policy and an unchanged native filter", async () => {
  const { value, job, f } = observerInput(),
    descriptor = f.plan.manifest.filters[0],
    filter = await f.reader.wfp("filter", descriptor.key),
    target = "tcp:127.0.0.1:40000>127.0.0.1:40001:out",
    witness = {
      raw: {
        id: hash,
        pid: f.subject.pid,
        opcode: "5157",
        target,
        subjectSid: null,
        auditFailure: true,
        accessMask: null,
        filterId: filter.id,
      },
      time: String(time + 15000n),
      index: 0,
    },
    barriers = [
      { sequence: 1, time: String(time + 10000n), events: 0 },
      { sequence: 2, time: String(time + 20000n), events: 1 },
    ],
    transfer = {
      subject: 0,
      job: 0,
      object: { key: descriptor.key, descriptor, policy: f.input },
    };
  value.plan.routes[0].outcome = "deny";
  value.plan.routes[0].targetSha256 = observationDigest({
    filterId: filter.id,
    target,
  });
  value.bindings = value.bindings.map((binding) => ({
    ...binding,
    selector: target,
    opcode: binding.phase === "control-permit" ? "5156" : "5157",
    accessMask: null,
    filterId: filter.id,
  }));
  f.reader.inspectJob = async () => ({ ...job, independent: true });
  const bind = () =>
    bindWindowsAuditEvent(
      f.reader,
      witness,
      value,
      value.bindings[2],
      transfer,
      barriers,
    );
  assert.equal((await bind()).held, true);
  const prior = structuredClone(f.input);
  for (const change of [
    () => {
      f.input.request.candidateSha = "d".repeat(40);
    },
    () => {
      value.plan.policySha256 = "d".repeat(64);
    },
    () => {
      value.plan.nonce = "d".repeat(32);
    },
  ]) {
    change();
    await assert.rejects(bind());
    Object.assign(f.input, structuredClone(prior));
    value.plan.policySha256 = f.plan.policySha256;
    value.plan.nonce = nonce;
  }
  let reads = 0;
  f.reader.wfp = async () => ({
    ...structuredClone(filter),
    flags: ++reads === 1 ? filter.flags : 1,
  });
  await assert.rejects(bind());
});

function setupFixture() {
  const { value, f } = observerInput(),
    phases = [],
    helper = {
      pid: 903,
      creationTime: "10903",
      sessionId: 0,
      userSid: "S-1-5-18",
    };
  const keys = [
    "0cce921d-69ae-11d9-bed3-505054503030",
    "0cce9225-69ae-11d9-bed3-505054503030",
    "0cce9226-69ae-11d9-bed3-505054503030",
  ];
  const audit = {
    sid: account,
    systemSha256: hash,
    system: keys.map((key) => ({ key, flags: 0 })),
    principal: null,
  };
  const security = structuredClone(f.objects[3].security),
    initial = structuredClone(security);
  let observerClosed = false;
  f.reader.auditSnapshot = async () => structuredClone(audit);
  f.reader.acl = async () => ({
    object: f.objects[3].object,
    security: structuredClone(security),
    access: structuredClone(f.objects[3].access),
  });
  f.reader.installAudit = async (_, objects, systemSha256) => {
    assert.deepEqual(objects, [
      { index: 3, descriptorSha256: security.descriptorSha256 },
    ]);
    assert.equal(systemSha256, audit.systemSha256);
    phases.push("set");
    audit.principal = keys.map((key) => ({ key, flags: 5 }));
    security.sacl.push({ type: 2, flags: 192, mask: 0x1f01ff, sid: account });
    security.descriptorSha256 = observationDigest(security.sacl);
  };
  f.reader.openObserver = async () => {
    phases.push("open");
    return { identity: helper };
  };
  f.reader.restoreAudit = async () => {
    assert.ok(observerClosed);
    phases.push("restore");
    audit.principal = null;
    Object.assign(security, structuredClone(initial));
  };
  const options = {
    verifier: f.verifier,
    persist: async ({ phase }) => phases.push(phase),
    review: async ({ configuration, before }) => ({
      independent: true,
      candidateSha,
      nonce,
      configurationSha256: observationDigest(configuration),
      beforeSha256: before.sha256,
      ownedObjectsVerified: true,
      exclusiveWriter: true,
      admissionsClosed: true,
      nativeEventSha256: hash,
      verifier: f.verifier,
      imageSha256: hash,
      sourceSha256: hash,
      abiSha256: hash,
    }),
    verifyRetirement: async ({ installed }) => ({
      ...retired(value, helper),
      verifier: f.verifier,
      installedSha256: installed.sha256,
      exclusiveWriter: true,
      admissionsClosed: true,
    }),
    verifySettlement: async ({ before, installed, restored }) => ({
      independent: true,
      verifier: f.verifier,
      beforeSha256: before.sha256,
      installedSha256: installed.sha256,
      restoredSha256: restored.sha256,
      nativeEventSha256: hash,
    }),
  };
  const owner = createWindowsAuditCustody(
    f.reader,
    value,
    { subject: 0, objects: [3], helper: 0 },
    options,
  );
  return {
    owner,
    value,
    audit,
    security,
    phases,
    options,
    helper,
    closed: () => {
      observerClosed = true;
    },
  };
}
test("Windows audit setup persists before setters and restores only its unchanged subset after both retirement proofs", async () => {
  const f = setupFixture();
  assert.deepEqual(f.phases, []);
  const installed = await f.owner.install();
  assert.equal(installed.before.audit.principal, null);
  assert.ok(
    f.phases.indexOf("audit-install-possible") < f.phases.indexOf("set"),
  );
  f.closed();
  await f.owner.restore(retired(f.value), retired(f.value, f.helper));
  assert.equal(f.audit.principal, null);
  assert.ok(
    f.phases.indexOf("audit-restore-possible") < f.phases.indexOf("restore"),
  );
  await assert.rejects(f.owner.install());
});
test("Windows foreign audit policy, unreviewed code, live custody and changed installed state prohibit restoration", async () => {
  for (const change of [
    (f) => {
      f.audit.principal = [{ key: f.audit.system[0].key, flags: 5 }];
    },
    (f) => {
      const review = f.options.review;
      f.options.review = async (value) => ({
        ...(await review(value)),
        sourceSha256: "d".repeat(64),
      });
    },
    (f) => {
      const review = f.options.review;
      f.options.review = async (value) => ({
        ...(await review(value)),
        exclusiveWriter: false,
      });
    },
    (f) => {
      const review = f.options.review;
      f.options.review = async (value) => {
        const proof = await review(value);
        f.security.descriptorSha256 = "d".repeat(64);
        return proof;
      };
    },
  ]) {
    const f = setupFixture();
    change(f);
    await assert.rejects(f.owner.install());
    assert.ok(!f.phases.includes("set"));
  }
  for (const change of [
    (f, payload) => {
      payload.noLiveMembers = false;
    },
    (f, payload) => {
      payload.domainSha256 = "d".repeat(64);
    },
    (f) => {
      f.security.sacl[1].mask = 1;
    },
    (f) => {
      f.audit.system[0].flags = 1;
    },
    (f) => {
      f.audit.systemSha256 = "d".repeat(64);
    },
    ...[
      ["candidateSha", "d".repeat(40)],
      ["nonce", "d".repeat(32)],
      ["domainSha256", "d".repeat(64)],
      ["emergencyCleanup", true],
    ].map(([key, value]) => (f) => {
      const verify = f.options.verifyRetirement;
      f.options.verifyRetirement = async (input) => ({
        ...(await verify(input)),
        [key]: value,
      });
    }),
  ]) {
    const f = setupFixture();
    await f.owner.install();
    const payload = retired(f.value);
    change(f, payload);
    f.closed();
    await assert.rejects(f.owner.restore(payload, retired(f.value, f.helper)));
    assert.ok(!f.phases.includes("restore"));
  }
});
test("Windows private binary capture drains bounded records before independent helper retirement", async () => {
  const { value } = observerInput();
  const d = decoder(),
    commands = [];
  let queue = Buffer.alloc(0);
  const channel = {
    send: async (command) => {
      commands.push(command);
      queue =
        command === "A"
          ? word(0)
          : command === "B"
            ? Buffer.concat([barrier(1, 0)])
            : Buffer.concat([framed, barrier(2, 1), terminal]);
    },
    receive: async (size) => {
      const bytes = Buffer.from(queue.subarray(0, Math.min(size, 7)));
      queue = queue.subarray(bytes.length);
      return bytes;
    },
  };
  const reader = createWindowsSecurityCapture(channel, d, value);
  await reader.start();
  await reader.barrier();
  assert.equal((await reader.stop(retired(value))).records, 1);
  assert.deepEqual(commands, ["A", "B", "S"]);
  const blocked = createWindowsSecurityCapture(channel, decoder(), value);
  await blocked.start();
  await assert.rejects(
    blocked.stop({ ...retired(value), noLiveMembers: false }),
  );
  assert.equal(commands.at(-1), "A");
  await assert.rejects(blocked.barrier());
});
