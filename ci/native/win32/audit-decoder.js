import { isIP } from "node:net";

import { observationDigest } from "../index.js";
import { closed, dense, digest, hash, requireWindows } from "./protocol.js";
import { integer } from "./custody-protocol.js";

const ids = [4656, 4663, 5152, 5156, 5157];
const text = (hex) => {
  requireWindows(
    typeof hex === "string" &&
      /^(?:[a-f0-9]{4})*$/u.test(hex) &&
      hex.length <= 16380,
  );
  const value = new TextDecoder("utf-16le", { fatal: true }).decode(
    Buffer.from(hex, "hex"),
  );
  requireWindows(!/[\u0000-\u001f\u007f]/u.test(value));
  return value;
};
const decimal = (value, maximum = 0xffffffffffffffffn) => {
  requireWindows(
    typeof value === "string" &&
      /^(?:0|[1-9][0-9]{0,19})$/u.test(value) &&
      BigInt(value) <= maximum,
  );
  return BigInt(value);
};
const number = (value, maximum = 0xffffffff) => {
  requireWindows(
    typeof value === "string" &&
      /^(?:0x[a-fA-F0-9]{1,16}|[0-9]{1,20})$/u.test(value),
  );
  const parsed = BigInt(value);
  requireWindows(parsed <= BigInt(maximum));
  return Number(parsed);
};
function fields(native, kind) {
  closed(native, ["kind", "fields"]);
  requireWindows(native.kind === kind);
  const result = new Map();
  for (const field of dense(native.fields, 96)) {
    closed(field, ["nameHex", "hex"]);
    const name = text(field.nameHex),
      value = text(field.hex);
    requireWindows(
      /^[A-Za-z][A-Za-z0-9]{0,127}$/u.test(name) && !result.has(name),
    );
    result.set(name, value);
  }
  return result;
}
function filetime(value) {
  const matched =
    /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.([0-9]{1,7}))?Z$/u.exec(value);
  requireWindows(matched);
  const milliseconds = Date.parse(matched[1] + "Z");
  requireWindows(Number.isSafeInteger(milliseconds) && milliseconds >= 0);
  requireWindows(
    new Date(milliseconds).toISOString().slice(0, 19) === matched[1],
  );
  return (
    (BigInt(milliseconds) + 11644473600000n) * 10000n +
    BigInt((matched[2] ?? "").padEnd(7, "0"))
  );
}
function eventRead(native, bytes, mapping) {
  const value = fields(native, "event"),
    id = number(value.get("EventID"), 65535);
  requireWindows(
    ![1101, 1102].includes(id) &&
      ids.includes(id) &&
      value.get("Provider") === "Microsoft-Windows-Security-Auditing" &&
      value.get("Channel") === "Security" &&
      mapping.versions
        .find((entry) => entry.id === id)
        ?.versions.includes(number(value.get("Version"), 255)),
  );
  requireWindows(/^0x[a-fA-F0-9]{1,16}$/u.test(value.get("Keywords")));
  const recordId = decimal(value.get("EventRecordID")),
    time = filetime(value.get("TimeCreated")),
    keywords = BigInt(value.get("Keywords"));
  requireWindows(
    recordId > 0n &&
      ((keywords & 0x0030000000000000n) === 0x0010000000000000n ||
        (keywords & 0x0030000000000000n) === 0x0020000000000000n),
  );
  const auditFailure = !!(keywords & 0x0010000000000000n),
    file = id === 4656 || id === 4663;
  let pid,
    target,
    accessMask = null,
    filterId = null,
    subjectSid = null;
  if (file) {
    requireWindows(value.get("ObjectType") === "File");
    pid = number(value.get("ProcessId"));
    target = value.get("ObjectName");
    subjectSid = value.get("SubjectUserSid");
    accessMask = number(value.get("AccessMask"));
    requireWindows(
      typeof target === "string" &&
        target.length > 0 &&
        accessMask > 0 &&
        /^S-1-5-21-[0-9-]+$/u.test(subjectSid),
    );
  } else {
    pid = number(value.get(id === 5152 ? "ProcessId" : "ProcessID"));
    filterId = decimal(value.get("FilterRTID")).toString();
    requireWindows(filterId !== "0");
    const protocol = number(value.get("Protocol")),
      sourcePort = number(value.get("SourcePort"), 65535),
      destinationPort = number(value.get("DestPort"), 65535),
      source = value.get("SourceAddress"),
      destination = value.get("DestAddress"),
      direction = value.get("Direction");
    requireWindows(
      [6, 17].includes(protocol) &&
        ["%%14592", "%%14593"].includes(direction) &&
        [source, destination].every(
          (value) =>
            typeof value === "string" && value.length <= 45 && isIP(value) > 0,
        ),
    );
    target = `${protocol === 6 ? "tcp" : "udp"}:${source}:${sourcePort}>${destination}:${destinationPort}:${direction === "%%14592" ? "in" : "out"}`;
  }
  requireWindows(pid > 0 && auditFailure === [4656, 5152, 5157].includes(id));
  return {
    raw: {
      id: digest(bytes),
      pid,
      opcode: String(id),
      target,
      subjectSid,
      auditFailure,
      accessMask,
      filterId,
    },
    recordId: recordId.toString(),
    time: time.toString(),
  };
}

/** Framed input is solely the admitted helper's pipe. Decoding errors latch;
 * terminal/bookmark counts, native barriers and event versions cannot be inferred. */
export function createWindowsAuditDecoder(reader, value) {
  closed(value, ["sdkSha256", "abiSha256", "versions", "mappingSha256"]);
  requireWindows(
    hash(value.sdkSha256) && hash(value.abiSha256) && hash(value.mappingSha256),
  );
  const mapping = structuredClone(value);
  requireWindows(
    dense(mapping.versions, 5).length === 5 &&
      new Set(mapping.versions.map((entry) => entry.id)).size === 5,
  );
  for (const entry of mapping.versions) {
    closed(entry, ["id", "versions"]);
    requireWindows(
      ids.includes(entry.id) &&
        dense(entry.versions, 4).length > 0 &&
        entry.versions.every((version) => integer(version, 255)) &&
        new Set(entry.versions).size === entry.versions.length,
    );
  }
  requireWindows(observationDigest(mapping.versions) === mapping.mappingSha256);
  let buffer = Buffer.alloc(0),
    ready = false,
    ended = false,
    failed = false,
    pushing = false,
    total = 0,
    records = 0,
    bookmark;
  const events = [],
    barriers = [];
  return {
    binding: () => ({
      sdkSha256: mapping.sdkSha256,
      abiSha256: mapping.abiSha256,
      mappingSha256: mapping.mappingSha256,
    }),
    async push(chunk) {
      try {
        requireWindows(
          !failed &&
            !ended &&
            !pushing &&
            Buffer.isBuffer(chunk) &&
            chunk.length <= 8388608 &&
            buffer.length + chunk.length <= 8454144,
        );
        pushing = true;
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 4) {
          const size = buffer.readUInt32LE(0);
          if (!ready) {
            requireWindows(size === 0);
            ready = true;
            buffer = buffer.subarray(4);
            continue;
          }
          if (size === 0xfffffffe) {
            if (buffer.length < 20) break;
            const sequence = buffer.readUInt32LE(4),
              time = buffer.readBigUInt64LE(8),
              count = buffer.readUInt32LE(16);
            requireWindows(
              sequence === barriers.length + 1 &&
                sequence <= 256 &&
                count === records &&
                time > 0n &&
                (!barriers.length || time >= BigInt(barriers.at(-1).time)),
            );
            barriers.push({
              sequence,
              time: time.toString(),
              events: events.length,
            });
            buffer = buffer.subarray(20);
            continue;
          }
          if (size === 0xffffffff) {
            if (buffer.length < 16) break;
            const bytes = buffer.readUInt32LE(12);
            requireWindows(
              bytes >= 4 &&
                bytes <= 65536 &&
                bytes % 2 === 0 &&
                buffer.readUInt32LE(4) === total &&
                buffer.readUInt32LE(8) === records,
            );
            if (buffer.length < 16 + bytes) break;
            requireWindows(buffer.length === 16 + bytes);
            const checkpoint = Buffer.from(buffer.subarray(16));
            let decoded;
            try {
              decoded = fields(await reader.xml(checkpoint), "bookmark");
            } finally {
              checkpoint.fill(0);
            }
            requireWindows(
              !failed &&
                decoded.size === 3 &&
                decoded.get("Channel") === "Security" &&
                decoded.get("IsCurrent") === "true",
            );
            bookmark = decimal(decoded.get("RecordId")).toString();
            requireWindows(
              events.length === 0 ||
                BigInt(bookmark) === BigInt(events.at(-1).recordId),
            );
            ended = true;
            buffer.fill(0);
            buffer = Buffer.alloc(0);
            break;
          }
          requireWindows(
            size >= 4 &&
              size <= 65536 &&
              size % 2 === 0 &&
              records < 4096 &&
              total + size <= 8388608,
          );
          if (buffer.length < size + 4) break;
          const bytes = Buffer.from(buffer.subarray(4, size + 4));
          buffer = buffer.subarray(size + 4);
          total += size;
          records++;
          let event;
          try {
            event = eventRead(await reader.xml(bytes), bytes, mapping);
          } finally {
            bytes.fill(0);
          }
          requireWindows(
            !failed &&
              (!events.length ||
                BigInt(event.recordId) > BigInt(events.at(-1).recordId)) &&
              !events.some((item) => item.raw.id === event.raw.id),
          );
          events.push({ ...event, index: records - 1 });
        }
      } catch {
        failed = true;
        buffer.fill(0);
        throw new Error("Unverified Windows audit capture");
      } finally {
        pushing = false;
      }
    },
    state() {
      requireWindows(!failed && !pushing);
      return {
        ready,
        ended,
        events: structuredClone(events),
        barriers: structuredClone(barriers),
      };
    },
    finish() {
      requireWindows(
        !failed && !pushing && ready && ended && buffer.length === 0,
      );
      return {
        events: structuredClone(events),
        barriers: structuredClone(barriers),
        bookmark,
        nativeEventSha256: observationDigest({ events, barriers, bookmark }),
        records,
        bytes: total,
      };
    },
  };
}
