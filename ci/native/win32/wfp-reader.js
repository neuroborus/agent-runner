import { closed, dense, sid, requireWindows } from "./protocol.js";
import { integer } from "./custody-protocol.js";
import { observationDigest } from "../index.js";
import {
  normalizeWindowsSecurityRead,
  systemOnly,
} from "./effective-protocol.js";
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const ace = (sid, mask, flags = 0, type = 0) => ({ type, flags, mask, sid });
export const windowsGuid = (value) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/u.test(value);
const u32 = (value) => integer(value, 0xffffffff);

const uint64 = (value) =>
  typeof value === "string" &&
  /^(?:0|[1-9][0-9]{0,19})$/u.test(value) &&
  BigInt(value) <= 0xffffffffffffffffn;
const bytes = (value, maximum, exact) =>
  typeof value === "string" &&
  /^(?:[a-f0-9]{2})*$/u.test(value) &&
  value.length <= maximum * 2 &&
  (exact === undefined || value.length === exact * 2);
export function assertWindowsWfpOwnersRead(provider, sublayer, plan) {
  closed(provider, [
    "key",
    "flags",
    "providerData",
    "serviceNameHex",
    "security",
  ]);
  closed(sublayer, [
    "key",
    "providerKey",
    "weight",
    "flags",
    "providerData",
    "security",
  ]);
  requireWindows(
    provider.key === plan.manifest.providerKey &&
      provider.flags === 1 &&
      provider.providerData === "" &&
      provider.serviceNameHex === null &&
      sublayer.key === plan.manifest.sublayerKey &&
      sublayer.providerKey === provider.key &&
      sublayer.flags === 1 &&
      sublayer.providerData === "" &&
      sublayer.weight === 65535,
  );
  systemOnly(provider.security);
  systemOnly(sublayer.security);
}
function nativeValue(value, depth = 0) {
  closed(value, ["type", "value"]);
  const data = value.value;
  requireWindows(integer(value.type, 258) && depth <= 1);
  switch (value.type) {
    case 0:
      requireWindows(data === null);
      break;
    case 1:
    case 2:
    case 3:
      requireWindows(integer(data, [0, 255, 65535, 0xffffffff][value.type]));
      break;
    case 4:
      requireWindows(uint64(data));
      break;
    case 5:
    case 6:
    case 7: {
      const bits = [0, 0, 0, 0, 0, 8, 16, 32][value.type];
      requireWindows(
        Number.isInteger(data) &&
          data >= -(2 ** (bits - 1)) &&
          data < 2 ** (bits - 1),
      );
      break;
    }
    case 8:
      requireWindows(
        typeof data === "string" &&
          /^(?:0|-?[1-9][0-9]{0,18})$/u.test(data) &&
          BigInt(data) >= -0x8000000000000000n &&
          BigInt(data) <= 0x7fffffffffffffffn,
      );
      break;
    case 9:
    case 10:
    case 11:
    case 17: {
      const size = { 9: 4, 10: 8, 11: 16, 17: 6 }[value.type];
      requireWindows(bytes(data, size, size));
      break;
    }
    case 12:
    case 13:
    case 15:
      requireWindows(bytes(data, 4096));
      break;
    case 14:
      closed(data, ["sids", "restricted"]);
      for (const list of [data.sids, data.restricted])
        for (const item of dense(list, 128)) {
          closed(item, ["sid", "attributes"]);
          sid(item.sid);
          requireWindows(u32(item.attributes));
        }
      break;
    case 16:
      requireWindows(bytes(data, 4096) && data.length % 4 === 0);
      break;
    case 256:
      closed(data, ["address", "mask"]);
      requireWindows(u32(data.address) && u32(data.mask));
      break;
    case 257:
      closed(data, ["address", "prefix"]);
      requireWindows(bytes(data.address, 16, 16) && integer(data.prefix, 128));
      break;
    case 258:
      requireWindows(depth === 0);
      closed(data, ["low", "high"]);
      nativeValue(data.low, depth + 1);
      nativeValue(data.high, depth + 1);
      break;
    default:
      requireWindows(false);
  }
}
/** Preserve every observed global filter value, including foreign sublayer
 * precedence. The manifest selects owned filters; it cannot fill this graph. */
export function normalizeWindowsWfpGlobalRead(value, key) {
  closed(value, [
    "key",
    "providerKey",
    "layer",
    "sublayer",
    "sublayerWeight",
    "sublayerFlags",
    "sublayerProviderKey",
    "sublayerSecurity",
    "id",
    "flags",
    "action",
    "callout",
    "context",
    "providerData",
    "weight",
    "effectiveWeight",
    "conditions",
    "security",
  ]);
  requireWindows(
    value.key === key &&
      windowsGuid(key) &&
      (value.providerKey === null || windowsGuid(value.providerKey)) &&
      windowsGuid(value.layer) &&
      windowsGuid(value.sublayer) &&
      integer(value.sublayerWeight, 65535) &&
      u32(value.sublayerFlags) &&
      (value.sublayerProviderKey === null ||
        windowsGuid(value.sublayerProviderKey)) &&
      uint64(value.id) &&
      value.id !== "0" &&
      u32(value.flags) &&
      u32(value.action) &&
      (value.callout === null || windowsGuid(value.callout)) &&
      (uint64(value.context) || windowsGuid(value.context)) &&
      bytes(value.providerData, 4096),
  );
  normalizeWindowsSecurityRead(value.security);
  normalizeWindowsSecurityRead(value.sublayerSecurity);
  nativeValue(value.weight);
  nativeValue(value.effectiveWeight);
  for (const condition of dense(value.conditions, 64)) {
    closed(condition, ["field", "match", "value"]);
    requireWindows(windowsGuid(condition.field) && u32(condition.match));
    nativeValue(condition.value);
  }
  return structuredClone(value);
}

/** Field names and native type tags are sealed SDK mappings, not manifest
 * observations. Unsupported types/fields cannot be normalized into approval. */
export function assertWindowsWfpFilterRead(value, descriptor, plan) {
  closed(value, [
    "key",
    "providerKey",
    "sublayerKey",
    "id",
    "layer",
    "flags",
    "weight",
    "action",
    "conditions",
    "security",
  ]);
  requireWindows(
    value.key === descriptor.key &&
      value.providerKey === plan.manifest.providerKey &&
      value.sublayerKey === plan.manifest.sublayerKey &&
      /^[1-9][0-9]{0,19}$/u.test(value.id) &&
      BigInt(value.id) <= 0xffffffffffffffffn &&
      value.layer === descriptor.layer &&
      value.flags === 9 &&
      value.weight === descriptor.weight &&
      value.action === descriptor.action,
  );
  systemOnly(value.security);
  const conditions = {};
  for (const item of dense(value.conditions, 8)) {
    closed(item, ["field", "type", "value"]);
    const name = item.field;
    requireWindows(
      [
        "principal",
        "protocol",
        "localAddress",
        "remoteAddress",
        "localPort",
        "remotePort",
      ].includes(name) && !Object.hasOwn(conditions, name),
    );
    if (name === "principal") {
      requireWindows(item.type === 13 && descriptor.principal !== null);
      const expected =
        descriptor.principal === "S-1-5-18"
          ? [ace("S-1-5-18", 1)]
          : [
              ace(plan.value.accountSid, 1),
              ace(plan.value.request.restrictingSid, 1),
            ];
      requireWindows(equal(item.value, expected));
      conditions.principal = descriptor.principal;
    } else if (name === "protocol") {
      requireWindows(item.type === 1 && [6, 17].includes(item.value));
      conditions[name] = item.value === 6 ? "tcp" : "udp";
    } else if (name.endsWith("Address")) {
      requireWindows(
        (item.type === 3 && item.value === 0x7f000001) ||
          (item.type === 11 && item.value === "0".repeat(31) + "1"),
      );
      conditions[name] = item.type === 3 ? "127.0.0.1" : "::1";
    } else {
      requireWindows(
        item.type === 2 && integer(item.value, 65535) && item.value >= 1024,
      );
      conditions[name] = item.value;
    }
  }
  requireWindows((conditions.principal ?? null) === descriptor.principal);
  delete conditions.principal;
  requireWindows(
    Object.keys(conditions).length ===
      Object.keys(descriptor.conditions).length &&
      Object.entries(descriptor.conditions).every(
        ([key, value]) => conditions[key] === value,
      ),
  );
  return {
    descriptor: structuredClone(descriptor),
    id: value.id,
    providerKey: value.providerKey,
    sublayerKey: value.sublayerKey,
    userConditionIncludesRestrictingSid:
      descriptor.principal === plan.value.accountSid,
    nativeEventSha256: observationDigest(value),
  };
}
