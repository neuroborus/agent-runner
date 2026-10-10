import { isIP } from "node:net";
import { observationObject, observationList } from "../index.js";
import {
  digest,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
  requireDarwin,
} from "./protocol.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const integer = (value, bound = 0xffffffff) =>
  Number.isSafeInteger(value) && value >= 0 && value <= bound;
const decodeText = (bytes) =>
  new TextDecoder("utf-8", { fatal: true }).decode(bytes);
function selector(token, kind) {
  if (kind === "path" && token.type === 0x23) {
    const bytes = Buffer.from(token.hex, "hex");
    requireDarwin(
      bytes.length >= 5 &&
        bytes.readUInt16BE(1) === bytes.length - 3 &&
        bytes.at(-1) === 0 &&
        !bytes.subarray(3, -1).includes(0),
    );
    const path = decodeText(bytes.subarray(3, -1));
    requireDarwin(path.startsWith("/") && !/[\u0000-\u001f\u007f]/u.test(path));
    return path;
  }
  if (kind === "socket" && [0x80, 0x81].includes(token.type)) {
    const bytes = Buffer.from(token.hex, "hex"),
      ipv6 = token.type === 0x81;
    requireDarwin(
      bytes.length === (ipv6 ? 21 : 9) &&
        bytes.readUInt16BE(1) === (ipv6 ? 30 : 2),
    );
    const address = ipv6
      ? Array.from({ length: 8 }, (_, i) =>
          bytes.readUInt16BE(5 + i * 2).toString(16),
        ).join(":")
      : [...bytes.subarray(5)].join(".");
    return `${ipv6 ? "inet6" : "inet"}:${address}:${bytes.readUInt16BE(3)}`;
  }
  if (kind === "ipc" && token.type === 0x22) {
    const bytes = Buffer.from(token.hex, "hex");
    requireDarwin(bytes.length === 6);
    return `ipc:${bytes[1]}:${bytes.readUInt32BE(2)}`;
  }
  return null;
}
function normalizeMapping(value) {
  observationObject(value, [
    "sdkSha256",
    "abiSha256",
    "mappingSha256",
    "headerVersion",
    "events",
  ]);
  requireDarwin(
    [value.sdkSha256, value.abiSha256, value.mappingSha256].every(hash) &&
      integer(value.headerVersion, 255) &&
      value.headerVersion > 0,
  );
  const events = observationList(value.events, 256).map((event) => {
    observationObject(event, ["event", "opcode", "classes", "selector"]);
    requireDarwin(
      integer(event.event, 65535) &&
        /^[A-Za-z0-9_]{1,64}$/u.test(event.opcode) &&
        integer(event.classes) &&
        event.classes > 0 &&
        ["path", "socket", "ipc", "none"].includes(event.selector),
    );
    return { ...event };
  });
  requireDarwin(
    events.length > 0 &&
      new Set(events.map((event) => event.event)).size === events.length &&
      digest(JSON.stringify({ headerVersion: value.headerVersion, events })) ===
        value.mappingSha256,
  );
  return { ...value, events };
}

/** Constructor has no effects. Input is exclusively the admitted helper's
 * private pipe, continuously drained by its protected external CI owner. */
export function createDarwinAuditDecoder(reader, mappingValue) {
  const mapping = normalizeMapping(mappingValue);
  let buffer = Buffer.alloc(0),
    ready = false,
    ended = false,
    failed = false,
    pushing = false,
    total = 0,
    records = 0;
  const events = [],
    barriers = [];
  const guarded = (body) => {
    try {
      return body();
    } catch {
      failed = true;
      throw new Error("Unverified Darwin audit capture");
    }
  };
  return {
    async push(chunk) {
      try {
        requireDarwin(!failed && !ended && !pushing && Buffer.isBuffer(chunk));
        pushing = true;
        requireDarwin(
          chunk.length <= 8388608 &&
            buffer.length + chunk.length <= 8388608 + 65536,
        );
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 4) {
          const size = buffer.readUInt32BE(0);
          if (!ready) {
            requireDarwin(size === 0);
            ready = true;
            buffer = buffer.subarray(4);
            continue;
          }
          if (size === 0xfffffffe) {
            if (buffer.length < 16) break;
            const sequence = buffer.readUInt32BE(4),
              seconds = buffer.readUInt32BE(8),
              milliseconds = buffer.readUInt32BE(12);
            requireDarwin(
              sequence === barriers.length + 1 &&
                sequence <= 256 &&
                milliseconds < 1000,
            );
            const time = seconds * 1000 + milliseconds;
            requireDarwin(!barriers.length || time >= barriers.at(-1).time);
            barriers.push({ sequence, time, events: events.length });
            buffer = buffer.subarray(16);
            continue;
          }
          if (size === 0xffffffff) {
            if (buffer.length < 12) break;
            requireDarwin(
              buffer.readUInt32BE(4) === total &&
                buffer.readUInt32BE(8) === records &&
                buffer.length === 12,
            );
            ended = true;
            buffer = Buffer.alloc(0);
            break;
          }
          requireDarwin(
            size > 0 &&
              size <= 65536 &&
              records < 4096 &&
              total + size <= 8388608,
          );
          if (buffer.length < size + 4) break;
          const bytes = Buffer.from(buffer.subarray(4, size + 4));
          buffer = buffer.subarray(size + 4);
          total += size;
          records++;
          const native = await reader.bsm(bytes);
          requireDarwin(!failed);
          observationObject(native, ["tokens"]);
          const tokens = observationList(native.tokens, 256),
            header = tokens[0],
            trailer = tokens.at(-1);
          observationObject(header, [
            "kind",
            "version",
            "event",
            "name",
            "classes",
            "seconds",
            "milliseconds",
          ]);
          observationObject(trailer, ["kind"]);
          requireDarwin(
            header.kind === "header" &&
              header.version === mapping.headerVersion &&
              trailer.kind === "trailer" &&
              integer(header.seconds) &&
              integer(header.milliseconds, 999),
          );
          const event = mapping.events.find(
            (item) => item.event === header.event,
          );
          requireDarwin(
            event &&
              header.name === Buffer.from(event.opcode).toString("hex") &&
              header.classes === event.classes,
          );
          const subjects = [],
            returns = [],
            selectors = [],
            objects = [],
            descriptors = [];
          for (const token of tokens.slice(1, -1)) {
            if (token.kind === "subject") {
              observationObject(token, [
                "kind",
                "pid",
                "auid",
                "asid",
                "uid",
                "gid",
              ]);
              requireDarwin(
                [token.pid, token.auid, token.asid, token.uid, token.gid].every(
                  (n) => integer(n),
                ),
              );
              subjects.push(token);
            } else if (token.kind === "return") {
              observationObject(token, ["kind", "error", "result"]);
              requireDarwin(
                integer(token.error, 255) && Number.isSafeInteger(token.result),
              );
              returns.push(token);
            } else {
              observationObject(token, ["kind", "type", "hex"]);
              requireDarwin(
                token.kind === "metadata" &&
                  integer(token.type, 255) &&
                  token.type !== 0x31 &&
                  /^(?:[a-f0-9]{2}){1,65536}$/u.test(token.hex) &&
                  token.hex.startsWith(
                    token.type.toString(16).padStart(2, "0"),
                  ),
              );
              const value = selector(token, event.selector);
              if (value !== null) selectors.push(value);
              if (token.type === 0x2d) {
                const bytes = Buffer.from(token.hex, "hex");
                requireDarwin(
                  bytes.length >= 9 &&
                    bytes.readUInt16BE(6) === bytes.length - 8 &&
                    bytes.at(-1) === 0,
                );
                if (
                  bytes[1] === 1 &&
                  decodeText(bytes.subarray(8, -1)) === "fd"
                )
                  descriptors.push(bytes.readUInt32BE(2));
              }
              if ([0x3e, 0x73].includes(token.type)) {
                const bytes = Buffer.from(token.hex, "hex");
                requireDarwin(bytes.length === (token.type === 0x3e ? 29 : 33));
                objects.push({
                  mode: bytes.readUInt32BE(1) & 0o7777,
                  uid: bytes.readUInt32BE(5),
                  gid: bytes.readUInt32BE(9),
                  device: String(bytes.readUInt32BE(13)),
                  inode: bytes.readBigUInt64BE(17).toString(),
                });
              }
            }
          }
          requireDarwin(
            subjects.length === 1 &&
              returns.length === 1 &&
              (event.selector === "none"
                ? selectors.length === 0
                : selectors.length === 1) &&
              objects.length <= 1 &&
              descriptors.length <= 1,
          );
          if (event.selector !== "none") {
            const subject = subjects[0],
              result = returns[0];
            events.push({
              id: digest(bytes),
              pid: subject.pid,
              opcode: event.opcode,
              target: selectors[0],
              auid: subject.auid,
              asid: subject.asid,
              result: result.result,
              error: result.error,
              time: header.seconds * 1000 + header.milliseconds,
              uid: subject.uid,
              gid: subject.gid,
              kind: event.selector,
              descriptor: descriptors[0] ?? null,
              nativeObject: objects[0] ?? null,
            });
          }
          bytes.fill(0);
        }
      } catch {
        failed = true;
        buffer.fill(0);
        buffer = Buffer.alloc(0);
        throw new Error("Unverified Darwin audit capture");
      } finally {
        pushing = false;
      }
    },
    window(start, end) {
      return guarded(() => {
        requireDarwin(
          !failed &&
            !pushing &&
            integer(start, 256) &&
            integer(end, 256) &&
            end === start + 1 &&
            start > 0 &&
            end <= barriers.length,
        );
        const before = barriers[start - 1],
          after = barriers[end - 1],
          selected = events.slice(before.events, after.events);
        requireDarwin(
          selected.length > 0 &&
            selected.every(
              (event) => event.time > before.time && event.time < after.time,
            ) &&
            new Set(selected.map((event) => event.id)).size === selected.length,
        );
        return structuredClone(
          selected.map((event) => ({
            ...event,
            window: {
              start: before.time,
              end: after.time,
              barrierSha256: digest(
                JSON.stringify({
                  mappingSha256: mapping.mappingSha256,
                  before,
                }),
              ),
            },
          })),
        );
      });
    },
    acknowledgement(sequence) {
      return guarded(() => {
        requireDarwin(
          !failed &&
            integer(sequence, 256) &&
            sequence > 0 &&
            sequence <= barriers.length,
        );
        const before = barriers[sequence - 1];
        return {
          ...before,
          barrierSha256: digest(
            JSON.stringify({ mappingSha256: mapping.mappingSha256, before }),
          ),
        };
      });
    },
    finish(exit) {
      return guarded(() => {
        requireDarwin(
          !failed &&
            !pushing &&
            ended &&
            buffer.length === 0 &&
            total > 0 &&
            exit?.code === 0 &&
            exit.signal === null,
        );
        return {
          records,
          health: {
            bytes: total,
            dropped: 0,
            truncated: 0,
            ambiguous: 0,
            overflow: false,
            complete: true,
          },
          mappingSha256: mapping.mappingSha256,
        };
      });
    },
  };
}

/** Bind a single acknowledged window to before/after held identities and an
 * independently read object. Numeric PID, paths and provider output are not proof. */
function auditIpv6(address) {
  requireDarwin(
    isIP(address) === 6 && !address.includes(".") && !address.includes("%"),
  );
  const parts = address.split("::");
  requireDarwin(parts.length <= 2);
  const left = parts[0] ? parts[0].split(":") : [],
    right = parts[1] ? parts[1].split(":") : [];
  return [...left, ...Array(8 - left.length - right.length).fill("0"), ...right]
    .map((part) => Number.parseInt(part, 16).toString(16))
    .join(":");
}

export function bindDarwinAuditEvent(
  event,
  beforeValue,
  afterValue,
  object,
  expectedObjectSha256,
  barrierSha256,
) {
  const before = normalizeDarwinIdentity(beforeValue),
    after = normalizeDarwinIdentity(afterValue);
  const first = object?.before,
    last = object?.after,
    native = event.nativeObject;
  requireDarwin(
    sameDarwinIdentity(before, after) &&
      event.pid === before.pid &&
      event.auid === before.auid &&
      event.asid === before.asid &&
      event.uid === before.uid &&
      event.gid === before.gid &&
      hash(event.id) &&
      hash(barrierSha256) &&
      hash(expectedObjectSha256) &&
      event.window?.barrierSha256 === barrierSha256 &&
      event.time > event.window.start &&
      event.time < event.window.end &&
      event.time >=
        before.startSeconds * 1000 +
          Math.floor(before.startMicroseconds / 1000),
  );
  if (event.kind === "path") {
    requireDarwin(
      first?.object.identity === last?.object.identity &&
        last?.sha256 === expectedObjectSha256 &&
        native &&
        last.object.identity.split(":")[0] === native.device &&
        last.object.identity.split(":")[3] === native.inode &&
        ["mode", "uid", "gid"].every(
          (key) =>
            last.object[key] === native[key] &&
            first.object[key] === native[key],
        ),
    );
  } else {
    requireDarwin(
      first &&
        last &&
        JSON.stringify(first) === JSON.stringify(last) &&
        digest(JSON.stringify(last)) === expectedObjectSha256,
    );
    if (event.kind === "socket") {
      const { source, target } = last;
      requireDarwin(
        source &&
          target &&
          sameDarwinIdentity(source.subject, before) &&
          source.descriptor === event.descriptor &&
          [source, target].every(
            (socket) =>
              /^[1-9a-f][a-f0-9]{0,15}$/u.test(socket.kernelId) &&
              socket.exclusive === true,
          ) &&
          source.protocol === target.protocol &&
          source.family === target.family &&
          event.target ===
            `${target.family}:${target.family === "inet6" ? auditIpv6(target.address) : target.address}:${target.port}`,
      );
    } else
      requireDarwin(
        event.kind === "ipc" &&
          Number.isSafeInteger(last.id) &&
          last.id >= 0 &&
          event.target === `ipc:${last.type}:${last.id}` &&
          hash(last.authoritySha256) &&
          /^[1-9][0-9]*$/u.test(last.created),
      );
  }
  return {
    independent: true,
    held: true,
    timeBound: true,
    nativeId: event.id,
    selector: event.target,
    objectSha256: expectedObjectSha256,
    before,
    after,
    barrierSha256,
  };
}
export function darwinAuditRecord(event) {
  return Object.fromEntries(
    ["id", "pid", "opcode", "target", "auid", "asid", "result", "error"].map(
      (key) => [key, event[key]],
    ),
  );
}
