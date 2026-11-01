import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { gunzipSync } from "node:zlib";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const text = (bytes) => bytes.toString("utf8").replace(/\0.*$/su, "");

function octal(bytes) {
  const value = text(bytes).trim();
  if (!/^[0-7]*$/u.test(value)) throw new Error("Invalid archive number.");
  return value === "" ? 0 : Number.parseInt(value, 8);
}

function pax(bytes) {
  const fields = Object.create(null);
  for (let offset = 0; offset < bytes.length;) {
    const space = bytes.indexOf(32, offset);
    const lengthText = bytes.subarray(offset, space).toString();
    const length = Number(lengthText);
    if (
      space < offset ||
      !/^[1-9][0-9]*$/u.test(lengthText) ||
      !Number.isSafeInteger(length) ||
      length <= space - offset + 1 ||
      offset + length > bytes.length ||
      bytes[offset + length - 1] !== 10
    ) {
      throw new Error("Invalid archive extended header.");
    }
    const record = bytes
      .subarray(space + 1, offset + length - 1)
      .toString("utf8");
    const equal = record.indexOf("=");
    if (equal < 1) throw new Error("Invalid archive extended field.");
    const key = record.slice(0, equal);
    const value = record.slice(equal + 1);
    // npm's portable pack headers need only these fields. Other extraction
    // semantics (including sparse files or links) must not escape inspection.
    if (
      !["path", "size", "mtime", "linkpath"].includes(key) ||
      Object.hasOwn(fields, key) ||
      /\p{Cc}/u.test(value) ||
      (key === "linkpath" && value !== "")
    )
      throw new Error("Unsupported archive extended field.");
    fields[key] = value;
    offset += length;
  }
  return fields;
}

// Inspect actual tar bytes, never npm's advisory file list. Links and extra files fail.
export async function inspectReleaseArchive(path, manifest) {
  const tar = gunzipSync(Buffer.isBuffer(path) ? path : await readFile(path), {
    maxOutputLength: 64 * 1024 * 1024,
  });
  const files = new Map();
  let extended = {};
  let offset = 0;
  for (; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const checksum = header.reduce(
      (sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte),
      0,
    );
    if (checksum !== octal(header.subarray(148, 156)))
      throw new Error("Archive checksum mismatch.");
    const size = octal(header.subarray(124, 136));
    const body = tar.subarray(offset + 512, offset + 512 + size);
    if (body.length !== size) throw new Error("Truncated release archive.");
    offset += 512 + Math.ceil(size / 512) * 512;
    const type = String.fromCharCode(header[156]);
    if (type === "x") {
      if (Object.keys(extended).length)
        throw new Error(
          "Consecutive archive extended headers are unsupported.",
        );
      extended = pax(body);
      continue;
    }
    if (extended.size !== undefined && extended.size !== String(size))
      throw new Error("Archive extended size disagrees with its header.");
    if (type !== "0" && type !== "\0")
      throw new Error("Release archive contains an unsupported entry.");
    const prefix = text(header.subarray(345, 500));
    const name =
      extended.path ??
      [prefix, text(header.subarray(0, 100))].filter(Boolean).join("/");
    extended = {};
    if (
      !name.startsWith("package/") ||
      /[\\\p{Cc}]/u.test(name) ||
      name
        .replace(/\/$/u, "")
        .split("/")
        .some((part) => ["", ".", ".."].includes(part))
    ) {
      throw new Error("Release archive path is unsafe.");
    }
    const relativePath = name.slice("package/".length);
    if (files.has(relativePath))
      throw new Error("Duplicate release archive path.");
    files.set(relativePath, {
      bytes: body,
      mode: octal(header.subarray(100, 108)) & 0o7777,
    });
  }
  if (
    Object.keys(extended).length ||
    offset + 1024 > tar.length ||
    !tar.subarray(offset).every((byte) => byte === 0)
  )
    throw new Error("Release archive terminator is invalid.");
  const expected = new Set([
    ...manifest.files.map(({ path }) => path),
    "release-manifest.json",
  ]);
  if (
    files.size !== expected.size ||
    [...files.keys()].some((name) => !expected.has(name))
  )
    throw new Error("Packed contents differ from the assembled file manifest.");
  if (
    files.get("release-manifest.json").mode !== 0o644 ||
    !files
      .get("release-manifest.json")
      .bytes.equals(Buffer.from(JSON.stringify(manifest, null, 2) + "\n"))
  )
    throw new Error("Packed release manifest changed.");
  for (const entry of manifest.files) {
    const actual = files.get(entry.path);
    if (
      !actual ||
      actual.mode !== entry.mode ||
      actual.bytes.length !== entry.size ||
      digest(actual.bytes) !== entry.sha256
    ) {
      throw new Error(`Packed file differs from assembly: ${entry.path}.`);
    }
  }
  return Object.freeze({ files: files.size, bytes: tar.length });
}
