import {
  closed,
  dense,
  digest,
  hash,
  sid,
  requireWindows,
} from "./protocol.js";
import { integer } from "./custody-protocol.js";
import { normalizeWindowsFileIdentity } from "./files-protocol.js";

const u32 = (value) => integer(value, 0xffffffff);
const readMask = 0x120089,
  writeMask = 0x120116,
  allMask = 0x1f01ff;
const ace = (sid, mask, flags = 0, type = 0) => ({ type, flags, mask, sid });
export function normalizeWindowsSecurityRead(value) {
  closed(value, [
    "ownerSid",
    "protectedDacl",
    "daclSha256",
    "descriptorSha256",
    "aces",
    "sacl",
  ]);
  sid(value.ownerSid);
  requireWindows(
    typeof value.protectedDacl === "boolean" &&
      hash(value.daclSha256) &&
      hash(value.descriptorSha256),
  );
  for (const acl of [value.aces, value.sacl])
    for (const item of dense(acl, 32)) {
      closed(item, ["type", "flags", "mask", "sid"]);
      sid(item.sid);
      requireWindows(
        [0, 1, 2, 17].includes(item.type) &&
          integer(item.flags, 255) &&
          u32(item.mask),
      );
    }
  return structuredClone(value);
}
export function normalizeWindowsBarrierRead(value, contents = true) {
  closed(value, [
    "identity",
    "sha256",
    "daclSha256",
    "bytes",
    ...(contents ? ["hex"] : []),
  ]);
  normalizeWindowsFileIdentity(value.identity);
  requireWindows(
    hash(value.sha256) &&
      hash(value.daclSha256) &&
      integer(value.bytes, contents ? 65536 : 134217728),
  );
  if (contents)
    requireWindows(
      typeof value.hex === "string" &&
        /^(?:[a-f0-9]{2})*$/u.test(value.hex) &&
        value.hex.length === value.bytes * 2 &&
        digest(Buffer.from(value.hex, "hex")) === value.sha256,
    );
  return structuredClone(value);
}
export function access(value, token) {
  closed(value, [
    "granted",
    "micDenied",
    "subjectLevel",
    "objectLevel",
    "label",
    "tokenId",
  ]);
  requireWindows(
    [
      value.granted,
      value.micDenied,
      value.subjectLevel,
      value.objectLevel,
      value.label,
    ].every(u32) &&
      value.tokenId === token.tokenId &&
      value.subjectLevel === 4096 &&
      [4096, 8192].includes(value.objectLevel) &&
      value.label === 1,
  );
  return value.granted & ~value.micDenied;
}
export function expectedAces(descriptor) {
  const { grant, accountSid, restrictingSid } = descriptor;
  const edit = readMask | writeMask | 0x10000;
  const masks = {
    system: 0,
    traverse: 0x120020,
    "read-tree": readMask | 32,
    workspace: readMask | 32 | 6,
    "private-tree": readMask | 32 | 6,
    read: readMask,
    edit,
    execute: readMask | 32,
  };
  const mask = masks[grant];
  requireWindows(mask !== undefined);
  const result = [ace("S-1-5-18", allMask)];
  if (mask) result.push(ace(accountSid, mask), ace(restrictingSid, mask));
  const child =
    grant === "workspace"
      ? edit
      : grant === "private-tree"
        ? edit | 6
        : grant === "read-tree"
          ? readMask
          : 0;
  if (child)
    result.push(
      ace("S-1-3-4", 0xc0000, 11, 1),
      ace("S-1-5-18", allMask, 11),
      ace(accountSid, child, 9),
      ace(restrictingSid, child, 9),
      ace(accountSid, child | 32, 10),
      ace(restrictingSid, child | 32, 10),
    );
  return result;
}
export function rights(mask, directory, registry = false) {
  if (registry)
    return {
      read: !!(mask & 1),
      write: !!(mask & 2),
      createFile: false,
      createDirectory: !!(mask & 4),
      traverse: false,
      execute: false,
      delete: !!(mask & 0x10000),
      deleteChild: false,
      writeDacl: !!(mask & 0x40000),
      writeOwner: !!(mask & 0x80000),
    };
  return {
    read: !!(mask & 1),
    write: !directory && !!(mask & 2),
    createFile: directory && !!(mask & 2),
    createDirectory: directory && !!(mask & 4),
    traverse: directory && !!(mask & 32),
    execute: !directory && !!(mask & 32),
    delete: !!(mask & 0x10000),
    deleteChild: !!(mask & 64),
    writeDacl: !!(mask & 0x40000),
    writeOwner: !!(mask & 0x80000),
  };
}
export const systemOnly = (value, file = false) => {
  const sd = normalizeWindowsSecurityRead(value);
  requireWindows(
    sd.ownerSid === "S-1-5-18" &&
      sd.protectedDacl &&
      sd.aces.length === 1 &&
      sd.aces[0].sid === "S-1-5-18" &&
      sd.aces[0].type === 0 &&
      sd.aces[0].flags === 0 &&
      (file
        ? sd.aces[0].mask === allMask
        : u32(sd.aces[0].mask) && sd.aces[0].mask > 0),
  );
  return sd;
};
