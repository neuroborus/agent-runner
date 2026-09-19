import { isIP } from "node:net";

function addressBits(address, family) {
  if (family === 4)
    return address
      .split(".")
      .reduce((bits, part) => (bits << 8n) | BigInt(part), 0n);
  const halves = address
    .split("::")
    .map((half) => (half ? half.split(":") : []));
  const groups =
    halves.length === 1
      ? halves[0]
      : [
          ...halves[0],
          ...Array(8 - halves[0].length - halves[1].length).fill("0"),
          ...halves[1],
        ];
  return groups.reduce((bits, part) => (bits << 16n) | BigInt(`0x${part}`), 0n);
}

function within(bits, address, prefix, family) {
  const shift = BigInt((family === 4 ? 32 : 128) - prefix);
  return bits >> shift === addressBits(address, family) >> shift;
}

// Conservative public-unicast policy: special-use, transition, documentation,
// multicast and IPv6 outside global-unicast space never authorize a connection.
const IPV4_EXCLUSIONS = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 3],
];
const IPV6_EXCLUSIONS = [
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3ffe::", 16],
  ["3fff::", 20],
];

export function publicAddress(address) {
  if (typeof address !== "string" || address.includes("%")) return null;
  const family = isIP(address);
  if (!family || (family === 6 && address.includes("."))) return null;
  const bits = addressBits(address, family);
  if (family === 6 && !within(bits, "2000::", 3, 6)) return null;
  if (
    (family === 4 ? IPV4_EXCLUSIONS : IPV6_EXCLUSIONS).some(
      ([network, prefix]) => within(bits, network, prefix, family),
    )
  )
    return null;
  return { address, family, key: `${family}:${bits}` };
}
