import { windowsFeasibilityImports } from "./feasibility.js";
import { digest, requireWindows } from "./protocol.js";

export const WINDOWS_EXPERIMENT_MARKER = Buffer.from(
  "native-ci-experiment-v1\0",
);

/** Actual unsigned PE/import bytes. This supplies no Authenticode approval. */
export function inspectWindowsExperimentPe(bytes, helper = true) {
  // Helpers require the durable marker. Unsigned installed runtime images are
  // separately observed by the native PE/API-set reader; they acquire no trust.
  const imports = helper ? windowsFeasibilityImports(bytes) : null;
  requireWindows(
    Buffer.isBuffer(bytes) &&
      bytes.length >= 512 &&
      bytes.length <= 134217728 &&
      bytes.readUInt16LE(0) === 0x5a4d,
  );
  const offset = bytes.readUInt32LE(60);
  requireWindows(
    offset >= 64 &&
      offset + 24 <= bytes.length &&
      bytes.readUInt32LE(offset) === 0x4550 &&
      bytes.readUInt16LE(offset + 4) === 0x8664,
  );
  const pe = bytes.readUInt32LE(60),
    optional = pe + 24,
    size = bytes.readUInt16LE(pe + 20),
    count = bytes.readUInt16LE(pe + 6),
    sections = optional + size;
  requireWindows(
    size >= 152 &&
      sections + count * 40 <= bytes.length &&
      count > 0 &&
      count <= 96 &&
      bytes.readUInt16LE(optional) === 0x20b &&
      (!helper || !(bytes.readUInt16LE(pe + 22) & 0x2000)) &&
      bytes.readUInt32LE(optional + 144) === 0 &&
      bytes.readUInt32LE(optional + 148) === 0,
  );
  const markers = [];
  for (let i = 0; i < count; i++) {
    const at = sections + i * 40;
    if (bytes.subarray(at, at + 8).toString("ascii") !== ".nexp\0\0\0")
      continue;
    const start = bytes.readUInt32LE(at + 20),
      length = bytes.readUInt32LE(at + 16);
    requireWindows(
      start + length <= bytes.length &&
        length >= WINDOWS_EXPERIMENT_MARKER.length &&
        bytes
          .subarray(start, start + WINDOWS_EXPERIMENT_MARKER.length)
          .equals(WINDOWS_EXPERIMENT_MARKER) &&
        (bytes.readUInt32LE(at + 36) & 0xa0000000) === 0,
    );
    markers.push(at);
  }
  requireWindows(helper ? markers.length === 1 : markers.length <= 1);
  return {
    purpose: "experiment",
    architecture: "x64",
    sha256: digest(bytes),
    signature: { kind: "unsigned", authenticated: false },
    imports,
  };
}
