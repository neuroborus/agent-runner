import assert from "node:assert/strict";
import test from "node:test";
import { createDarwinAuditDecoder, bindDarwinAuditEvent } from "./index.js";
import { digest } from "./protocol.js";

const hash = "a".repeat(64),
  path = "/fixture/control";
const events = [{ event: 1, opcode: "AUE_OPEN", classes: 1, selector: "path" }];
const mapping = {
  sdkSha256: hash,
  abiSha256: hash,
  headerVersion: 11,
  mappingSha256: digest(JSON.stringify({ headerVersion: 11, events })),
  events,
};
const subject = {
  pid: 20,
  pidVersion: 1,
  asid: 30,
  auid: 1001,
  uid: 1001,
  gid: 1002,
  ruid: 1001,
  rgid: 1002,
  svuid: 1001,
  svgid: 1002,
  startSeconds: 100,
  startMicroseconds: 0,
};
const word = (n) => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(n);
  return buffer;
};
const barrier = (sequence, time) =>
  Buffer.concat([word(0xfffffffe), word(sequence), word(100), word(time)]);
const record = Buffer.alloc(18, 1),
  framed = Buffer.concat([word(record.length), record]);
const finish = Buffer.concat([word(0xffffffff), word(record.length), word(1)]);
function decoder(change = (value) => value, attributeType = 0x3e) {
  const token = Buffer.alloc(4 + Buffer.byteLength(path));
  token[0] = 0x23;
  token.writeUInt16BE(Buffer.byteLength(path) + 1, 1);
  token.write(path, 3);
  const attribute = Buffer.alloc(
    attributeType === 0x73 ? 33 : attributeType === 0x31 ? 21 : 29,
  );
  attribute[0] = attributeType;
  attribute.writeUInt32BE(0o400, 1);
  if (attributeType === 0x31) {
    attribute.writeUInt32BE(1, 9);
    attribute.writeUInt32BE(4, 13);
  } else {
    attribute.writeUInt32BE(1, 13);
    attribute.writeBigUInt64BE(4n, 17);
  }
  return createDarwinAuditDecoder(
    {
      bsm: async () =>
        change({
          tokens: [
            {
              kind: "header",
              version: 11,
              event: 1,
              name: Buffer.from("AUE_OPEN").toString("hex"),
              classes: 1,
              seconds: 100,
              milliseconds: 2,
            },
            {
              kind: "subject",
              pid: subject.pid,
              auid: subject.auid,
              asid: subject.asid,
              uid: subject.uid,
              gid: subject.gid,
            },
            { kind: "metadata", type: 0x23, hex: token.toString("hex") },
            {
              kind: "metadata",
              type: attributeType,
              hex: attribute.toString("hex"),
            },
            { kind: "return", result: 3, error: 0 },
            { kind: "trailer" },
          ],
        }),
    },
    mapping,
  );
}
const capture = () =>
  Buffer.concat([word(0), barrier(1, 1), framed, barrier(2, 3), finish]);
test("bounded BSM frames join acknowledged windows and held native identities", async () => {
  for (const attributeType of [0x3e, 0x73, 0x31]) {
    const d = decoder(undefined, attributeType),
      bytes = capture();
    if (attributeType === 0x31) {
      await assert.rejects(d.push(bytes), /Unverified/);
      continue;
    }
    for (let i = 0; i < bytes.length; i += 7)
      await d.push(bytes.subarray(i, i + 7));
    assert.deepEqual(d.finish({ code: 0, signal: null }), {
      records: 1,
      health: {
        bytes: 18,
        dropped: 0,
        truncated: 0,
        ambiguous: 0,
        overflow: false,
        complete: true,
      },
      mappingSha256: mapping.mappingSha256,
    });
    const event = d.window(1, 2)[0];
    assert.equal(event.target, path);
    const barrierSha256 = event.window.barrierSha256;
    const file = {
        object: {
          identity: `1:2:3:4:100:0:${"d".repeat(32)}`,
          mode: 0o400,
          uid: 0,
          gid: 0,
        },
        sha256: digest("control"),
      },
      object = { before: file, after: file };
    assert.equal(
      bindDarwinAuditEvent(
        event,
        subject,
        subject,
        object,
        file.sha256,
        barrierSha256,
      ).held,
      true,
    );
    assert.throws(() =>
      bindDarwinAuditEvent(
        event,
        subject,
        { ...subject, pidVersion: 2 },
        object,
        file.sha256,
        barrierSha256,
      ),
    );
    assert.throws(() =>
      bindDarwinAuditEvent(
        { ...event, nativeObject: { ...event.nativeObject, inode: "5" } },
        subject,
        subject,
        object,
        file.sha256,
        barrierSha256,
      ),
    );
  }
});
test("audit truncation, unmatched mappings, ambiguous selectors and helper loss fail closed", async () => {
  const truncated = decoder();
  await truncated.push(capture().subarray(0, -1));
  assert.throws(() => truncated.finish({ code: 0, signal: null }));
  const lost = decoder();
  await lost.push(capture());
  assert.throws(() => lost.finish({ code: 126, signal: null }));
  for (const change of [
    (value) => {
      value.tokens[0].version = 12;
      return value;
    },
    (value) => {
      value.tokens[0].classes = 2;
      return value;
    },
    (value) => {
      value.tokens.splice(3, 0, { ...value.tokens[2] });
      return value;
    },
    (value) => {
      value.tokens[1].kind = "unknown";
      return value;
    },
  ]) {
    const d = decoder(change);
    await assert.rejects(d.push(capture()), /Unverified/);
    await assert.rejects(d.push(word(0)));
  }
});
test("missing acknowledged windows cannot become an audit witness", async () => {
  const d = decoder();
  await d.push(Buffer.concat([word(0), framed, finish]));
  assert.throws(() => d.window(1, 2));
  const ambiguous = decoder((value) => {
    value.tokens[0].milliseconds = 1;
    return value;
  });
  await ambiguous.push(capture());
  assert.throws(() => ambiguous.window(1, 2));
});
test("socket and IPC joins require native descriptor/object identities across the window", async () => {
  const d = decoder();
  await d.push(capture());
  const observed = d.window(1, 2)[0],
    barrierSha256 = observed.window.barrierSha256;
  const source = {
    subject,
    descriptor: 3,
    kernelId: "abc",
    family: "inet",
    protocol: "tcp",
    address: "127.0.0.1",
    port: 41001,
    exclusive: true,
  };
  const target = {
    ...source,
    subject: { ...subject, pid: 30, uid: 0, ruid: 0, svuid: 0 },
    port: 41002,
    kernelId: "def",
  };
  const socket = { source, target },
    event = {
      ...observed,
      kind: "socket",
      target: "inet:127.0.0.1:41002",
      descriptor: 3,
      nativeObject: null,
    };
  const objects = { before: socket, after: socket },
    expected = digest(JSON.stringify(socket));
  assert.equal(
    bindDarwinAuditEvent(
      event,
      subject,
      subject,
      objects,
      expected,
      barrierSha256,
    ).held,
    true,
  );
  for (const address of ["::1", "::", "2001:db8::1"]) {
    const target6 = { ...target, family: "inet6", address },
      source6 = { ...source, family: "inet6" },
      sockets = { source: source6, target: target6 },
      text =
        address === "::1"
          ? "0:0:0:0:0:0:0:1"
          : address === "::"
            ? "0:0:0:0:0:0:0:0"
            : "2001:db8:0:0:0:0:0:1";
    assert.equal(
      bindDarwinAuditEvent(
        { ...event, target: `inet6:${text}:41002` },
        subject,
        subject,
        { before: sockets, after: sockets },
        digest(JSON.stringify(sockets)),
        barrierSha256,
      ).held,
      true,
    );
    assert.throws(() =>
      bindDarwinAuditEvent(
        { ...event, target: "inet6:2001:db8:0:0:0:0:0:2:41002" },
        subject,
        subject,
        { before: sockets, after: sockets },
        digest(JSON.stringify(sockets)),
        barrierSha256,
      ),
    );
  }
  assert.throws(() =>
    bindDarwinAuditEvent(
      { ...event, descriptor: 4 },
      subject,
      subject,
      objects,
      expected,
      barrierSha256,
    ),
  );
  const ipc = {
      type: 2,
      id: 25,
      created: "100",
      size: 1,
      authoritySha256: hash,
    },
    ipcEvent = {
      ...observed,
      kind: "ipc",
      target: "ipc:2:25",
      nativeObject: null,
    };
  assert.equal(
    bindDarwinAuditEvent(
      ipcEvent,
      subject,
      subject,
      { before: ipc, after: ipc },
      digest(JSON.stringify(ipc)),
      barrierSha256,
    ).held,
    true,
  );
  assert.throws(() =>
    bindDarwinAuditEvent(
      ipcEvent,
      subject,
      subject,
      { before: ipc, after: { ...ipc, created: "101" } },
      digest(JSON.stringify(ipc)),
      barrierSha256,
    ),
  );
});
