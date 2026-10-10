import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";

import { NativeEvidenceError } from "./evidence.js";
import {
  NATIVE_PACKAGE_LIMITS,
  packageMemberPath,
  requirePackageValue,
} from "./package-inputs.js";

function field(header, start, length) {
  const bytes = header.subarray(start, start + length);
  const end = bytes.indexOf(0);
  const value = end === -1 ? bytes : bytes.subarray(0, end);
  requirePackageValue(value.every((byte) => byte >= 32 && byte < 127));
  return value.toString("ascii");
}

function octal(header, start, length) {
  const value = field(header, start, length).trim();
  requirePackageValue(/^[0-7]+$/u.test(value));
  const number = Number.parseInt(value, 8);
  requirePackageValue(Number.isSafeInteger(number));
  return number;
}

function paxPath(bytes) {
  let offset = 0,
    path = null;
  const keys = new Set();
  while (offset < bytes.length) {
    const space = bytes.indexOf(32, offset);
    requirePackageValue(space > offset && space - offset < 8);
    const lengthText = bytes.subarray(offset, space).toString("ascii");
    requirePackageValue(/^[1-9][0-9]*$/u.test(lengthText));
    const end = offset + Number(lengthText);
    requirePackageValue(
      end > space + 1 && end <= bytes.length && bytes[end - 1] === 10,
    );
    const record = bytes.subarray(space + 1, end - 1);
    requirePackageValue(record.every((byte) => byte >= 32 && byte < 127));
    const equals = record.indexOf(61);
    requirePackageValue(equals > 0);
    const key = record.subarray(0, equals).toString("ascii");
    const value = record.subarray(equals + 1).toString("ascii");
    requirePackageValue(!keys.has(key));
    keys.add(key);
    if (key === "path") path = value;
    else
      requirePackageValue(
        ["mtime", "atime", "ctime"].includes(key) &&
          /^-?[0-9]+(?:\.[0-9]+)?$/u.test(value),
      );
    offset = end;
  }
  return path;
}

/** Data-only POSIX/PAX tar extraction into trusted quarantine. The caller owns
 * exclusive parents and rollback; no alias, script or archive mode is granted. */
export async function materializeReviewedTar(source, files, openMember) {
  requirePackageValue(Array.isArray(files) && typeof openMember === "function");
  return walkTar(source, files, openMember);
}

/** Inspect every header and byte before granting a native extractor any input.
 * This manifest describes observed archive bytes, not a release closure review. */
export async function preflightNativeTar(source) {
  return walkTar(source, null, null);
}

async function walkTar(source, files, openMember) {
  const inspecting = files === null;
  requirePackageValue(
    inspecting ||
      (typeof openMember === "function" &&
        Array.isArray(files) &&
        files.length > 0 &&
        files.length <= NATIVE_PACKAGE_LIMITS.members),
  );
  const expected = new Map((files ?? []).map((file) => [file.path, file]));
  requirePackageValue(inspecting || expected.size === files.length);
  const directories = new Set();
  for (const file of files ?? []) {
    packageMemberPath(file.path);
    const parts = file.path.split("/");
    parts.pop();
    while (parts.length) {
      directories.add(parts.join("/"));
      parts.pop();
    }
  }
  const input = Readable.from(source),
    decoder = createGunzip({ chunkSize: 65536 });
  const pumping = pipeline(input, decoder);
  pumping.catch(() => {});
  const iterator = decoder[Symbol.asyncIterator]();
  let buffered = Buffer.alloc(0),
    expanded = 0,
    headers = 0,
    nextPax = null;
  const seen = new Set(),
    seenDirectories = new Set();
  async function take(count) {
    const result = Buffer.alloc(count);
    let offset = 0;
    while (offset < count) {
      if (!buffered.length) {
        const entry = await iterator.next();
        requirePackageValue(!entry.done);
        buffered = entry.value;
        expanded += buffered.length;
        requirePackageValue(
          expanded <= NATIVE_PACKAGE_LIMITS.expandedBytes + 8 * 1024 * 1024,
        );
      }
      const size = Math.min(buffered.length, count - offset);
      buffered.copy(result, offset, 0, size);
      buffered = buffered.subarray(size);
      offset += size;
    }
    return result;
  }
  try {
    while (true) {
      const header = await take(512);
      if (header.every((byte) => byte === 0)) {
        requirePackageValue(
          nextPax === null && (await take(512)).every((byte) => byte === 0),
        );
        let padding = buffered.length;
        requirePackageValue(buffered.every((byte) => byte === 0));
        for await (const chunk of { [Symbol.asyncIterator]: () => iterator }) {
          padding += chunk.length;
          requirePackageValue(
            padding <= 65536 && chunk.every((byte) => byte === 0),
          );
        }
        requirePackageValue(
          padding <= 65536 && seen.size === expected.size && seen.size > 0,
        );
        await pumping;
        if (inspecting) {
          for (const directory of seenDirectories)
            requirePackageValue(
              !expected.has(directory) &&
                [...expected.keys()].some((name) =>
                  name.startsWith(directory + "/"),
                ),
            );
          for (const name of expected.keys()) {
            const parts = name.split("/");
            parts.pop();
            while (parts.length) {
              requirePackageValue(!expected.has(parts.join("/")));
              parts.pop();
            }
          }
          return [...expected.values()];
        }
        return {
          members: seen.size,
          bindingStatus: "MATCHED",
          admission: "BLOCKED",
        };
      }
      requirePackageValue(++headers <= NATIVE_PACKAGE_LIMITS.members * 3);
      const checksum = header.reduce(
        (sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte),
        0,
      );
      requirePackageValue(
        octal(header, 148, 8) === checksum &&
          field(header, 257, 6) === "ustar" &&
          (octal(header, 100, 8) & 0o7000) === 0 &&
          field(header, 157, 100) === "",
      );
      const size = octal(header, 124, 12),
        type = header[156];
      if (type === 120) {
        requirePackageValue(size > 0 && size <= 8192 && nextPax === null);
        nextPax = { path: paxPath(await take(size)) };
      } else {
        requirePackageValue(type === 0 || type === 48 || type === 53);
        const prefix = field(header, 345, 155),
          name = field(header, 0, 100);
        const rawMember =
          nextPax?.path ?? `${prefix ? `${prefix}/` : ""}${name}`;
        requirePackageValue(type === 53 || !rawMember.endsWith("/"));
        const member = packageMemberPath(
          type === 53 ? rawMember.replace(/\/$/u, "") : rawMember,
        );
        nextPax = null;
        if (type === 53) {
          requirePackageValue(
            size === 0 &&
              (inspecting || directories.has(member)) &&
              !seenDirectories.has(member),
          );
          seenDirectories.add(member);
        } else {
          const file = inspecting
            ? {
                path: member,
                bytes: size,
                executable: (octal(header, 100, 8) & 0o111) !== 0,
              }
            : expected.get(member);
          requirePackageValue(
            file !== undefined &&
              file.bytes === size &&
              !seen.has(member) &&
              seen.size < NATIVE_PACKAGE_LIMITS.members,
          );
          seen.add(member);
          const writer = inspecting ? null : await openMember({ ...file });
          const hash = createHash("sha256");
          for (let remaining = size; remaining > 0;) {
            const chunk = await take(Math.min(remaining, 65536));
            hash.update(chunk);
            if (!inspecting) await writer.write(chunk);
            remaining -= chunk.length;
          }
          const sha256 = hash.digest("hex");
          if (inspecting) expected.set(member, { ...file, sha256 });
          else requirePackageValue(sha256 === file.sha256);
          if (!inspecting) await writer.close();
        }
      }
      const padding = (512 - (size % 512)) % 512;
      if (padding)
        requirePackageValue((await take(padding)).every((byte) => byte === 0));
    }
  } catch {
    throw new NativeEvidenceError();
  } finally {
    input.destroy();
    decoder.destroy();
    await pumping.catch(() => {});
  }
}
