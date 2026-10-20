import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import { constants } from "node:fs";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { Script } from "node:vm";
import { PassThrough, Writable } from "node:stream";
import {
  createDarwinCustodyReader,
  encodeDarwinCustodyPlan,
  normalizeDarwinCustodyInput,
} from "./index.js";
import { darwinCustodyChannel } from "./channel.js";
import { digest } from "./protocol.js";
import { protectedBytes, isDarwinInstalledPath } from "./private-files.js";
import {
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../diagnostics.js";

test("Darwin native access sockaddr builders decode exact experiment scope and preserve unscoped addresses", async () => {
  // Execute the two small C constructors with injected sockaddr/inet operations;
  // this is portable source coverage, not Darwin compilation or native proof.
  for (const [file, prefix, end] of [
    ["access-fixture.c", "address", "static const char *network_source"],
    ["custody-reader.c", "access", "static bool owned_access_socket"],
  ]) {
    const source = await readFile(new URL(file, import.meta.url), "utf8"),
      start = source.indexOf(`static uint32_t ${prefix}_scope(`),
      body = source.slice(start, source.indexOf(end, start));
    assert.ok(body.startsWith(`static uint32_t ${prefix}_scope(`));
    for (const experiment of [false, true]) {
      const translated = body
        .replace(
          /#ifndef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#endif/gu,
          (_, guarded) => (experiment ? "" : guarded),
        )
        .replace(
          /static uint32_t (\w+)\([^\n]+\)/u,
          "function $1(text, literal, capacity)",
        )
        .replace(
          /static socklen_t \w+\(struct sockaddr_storage \*storage, (?:int|unsigned) family, const char \*(text|name), unsigned (value|port)\)/u,
          (_, target, port) =>
            `function build(storage, family, ${target}, ${port})`,
        )
        .replace(/char literal\[INET6_ADDRSTRLEN\]/u, "let literal = []")
        .replace(/\b(?:size_t|uint64_t|uint32_t) /gu, "let ")
        .replace(/\((?:uint32_t|unsigned)\)/gu, "")
        .replace(
          /struct sockaddr_in6? \*a\s*=\s*\(void \*\)storage/gu,
          "let a = storage",
        )
        .replaceAll("sizeof(literal)", "46")
        .replaceAll("sizeof(*storage)", "128")
        .replaceAll("sizeof(*a)", "(family === AF_INET ? 16 : 28)")
        .replaceAll("&a->", "a.")
        .replaceAll("->", ".");
      const build = new Script(`${translated}\nbuild;`).runInNewContext({
        AF_INET: 2,
        AF_INET6: 30,
        UINT32_MAX: 0xffffffff,
        strcspn: (text, delimiter) =>
          text.includes(delimiter) ? text.indexOf(delimiter) : text.length,
        memcpy(target, text, length) {
          for (let i = 0; i < length; i++) target[i] = text[i];
        },
        memset(target) {
          Object.assign(target, {
            sin_addr: {},
            sin6_addr: {},
            sin6_scope_id: 0,
          });
        },
        htons: (port) => port,
        inet_pton(family, literal, target) {
          const text = literal.slice(0, literal.indexOf(0)).join("");
          target.text = text;
          return Number(isIP(text) === (family === 2 ? 4 : 6));
        },
        IN6_IS_ADDR_LINKLOCAL: (address) =>
          /^fe[89ab][0-9a-f]:/iu.test(address.text),
        need: (ok) => assert.ok(ok, "Native address refused"),
      });
      for (const [target, family, scope] of [
        ["192.0.2.2", 2, 0],
        ["2001:db8::2", 30, 0],
        ["::1", 30, 0],
        ["::", 30, 0],
        ["fe80::2%7", 30, 7],
        ["FEBF::2%4294967295", 30, 0xffffffff],
        ...[
          "fe80::2",
          "fe80::2%",
          "fe80::2%0",
          "fe80::2%07",
          "fe80::2%-1",
          "fe80::2%fixture",
          "fe80::2%1.5",
          "fe80::2%4294967296",
          "fe80::2%7%8",
          "2001:db8::2%7",
          "::1%7",
          "fe80:::2%7",
        ].map((target) => [target, 30, null]),
        ["192.0.2.2%7", 2, null],
        ["192.0.2.2", 99, null],
      ]) {
        const storage = {},
          run = () => build(storage, family, target, 48001);
        if (scope === null || (!experiment && scope))
          assert.throws(run, /Native address refused/);
        else {
          assert.equal(run(), family === 2 ? 16 : 28);
          assert.equal(storage.sin6_scope_id, scope);
          assert.equal(
            storage[family === 2 ? "sin_addr" : "sin6_addr"].text,
            target.split("%")[0],
          );
          assert.equal(storage[family === 2 ? "sin_port" : "sin6_port"], 48001);
        }
      }
    }
  }
});

test("Darwin scoped access targets survive control and payload argv with confined source binding", async () => {
  const fixture = await readFile(
      new URL("access-fixture.c", import.meta.url),
      "utf8",
    ),
    custody = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    source =
      /static const char \*network_source\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
        fixture,
      )?.[1],
    controlVector =
      /char \*argv\[\] = \{entries\[5\]\.path, nonce, args\[0\], target,[^\n]+?\};/u.exec(
        custody,
      )?.[0],
    payloadVector =
      /char \*vector\[\] = \{argv\[0\], fields\[0\],[^\n]+?\};/u.exec(
        fixture,
      )?.[0];
  assert.ok(source && controlVector && payloadVector);
  for (const control of [false, true]) {
    const select = new Script(
      `(family, target) => {${source}}`,
    ).runInNewContext({
      AF_INET: 2,
      getenv: () => control,
      strchr: (text, character) => text.includes(character),
    });
    assert.equal(select(30, "fe80::2%7"), control ? "fe80::2%7" : "::1");
    assert.equal(select(30, "::1"), "::1");
    assert.equal(select(2, "192.0.2.2"), "127.0.0.1");
  }
  for (const operation of ["tcp6", "udp6"]) {
    const target = "fe80::2%7",
      nonce = "a".repeat(32),
      args = [operation, Buffer.from(target).toString("hex"), "48001", "48002"];
    for (const vector of [controlVector, payloadVector]) {
      const expression = vector.slice(
          vector.indexOf("{") + 1,
          vector.lastIndexOf("}"),
        ),
        actual = new Script(`[${expression}]`).runInNewContext({
          entries: Array.from({ length: 6 }, () => ({
            path: "/fixture/access",
          })),
          argv: ["/fixture/access"],
          fields: [nonce, ...args],
          args,
          nonce,
          target,
          index: 29,
          NULL: null,
        });
      assert.deepEqual(Array.from(actual.slice(1, 5)), [
        nonce,
        operation,
        target,
        "48001",
      ]);
      assert.equal(actual[5], vector === controlVector ? "0" : "48002");
    }
  }
});

test("Darwin protected installed hardlinks require classification, protected ancestry and stable held bytes", async () => {
  for (const fault of [
    null,
    "sdk",
    "ordinary",
    "generated",
    "path",
    "owner",
    "group",
    "mode",
    "parent",
    "symlink",
    "canonical",
    "zero-links",
    "links-changed",
    "identity-changed",
    "content-changed",
  ]) {
    const bytes = Buffer.from("protected installed fixture"),
      file =
        fault === "sdk"
          ? "/Library/Developer/CommandLineTools/SDKs/Fixture.sdk/usr/include/fixture.h"
          : fault === "generated"
            ? "/Library/native-poc-" + "a".repeat(64) + "/build-helper"
            : fault === "path"
              ? "/fixture/clang"
              : "/usr/bin/clang",
      mode = ["mode", "sdk"].includes(fault) ? 0o444 : 0o755;
    let readStarted = false;
    const stat = (name, bigint = false) => {
      const leaf = name === file,
        convert = (value) => (bigint ? BigInt(value) : value);
      return {
        isFile: () => leaf,
        isDirectory: () => !leaf,
        isSymbolicLink: () => leaf && fault === "symlink",
        dev: convert(1),
        ino: convert(
          readStarted && leaf && fault === "identity-changed" ? 2 : 1,
        ),
        uid: convert(leaf && fault === "owner" ? 501 : 0),
        gid: convert(leaf && fault === "group" ? 20 : 0),
        mode: convert(leaf ? mode : fault === "parent" ? 0o777 : 0o755),
        nlink: convert(
          leaf
            ? fault === "zero-links"
              ? 0
              : readStarted && fault === "links-changed"
                ? 79
                : 78
            : 1,
        ),
        size: convert(leaf ? bytes.length : 0),
        mtimeNs: convert(1),
        ctimeNs: convert(1),
      };
    };
    const fs = {
      realpath: async (file) =>
        fault === "canonical" ? "/fixture/alias" : file,
      lstat: async (name, options) => stat(name, options?.bigint),
      open: async (name, flags) => {
        assert.equal(name, file);
        assert.ok(flags & constants.O_NOFOLLOW);
        return {
          stat: async () => stat(file, true),
          read: async (buffer, offset, length, position) => {
            readStarted = true;
            const source =
                fault === "content-changed"
                  ? Buffer.alloc(bytes.length)
                  : bytes,
              chunk = source.subarray(position, position + length);
            chunk.copy(buffer, offset);
            return { bytesRead: chunk.length };
          },
          close: async () => {},
        };
      },
    };
    const read = () =>
      protectedBytes(
        { path: file, sha256: digest(bytes) },
        0,
        mode,
        1024,
        fs,
        fault !== "ordinary",
      );
    if (fault && fault !== "sdk") await assert.rejects(read, undefined, fault);
    else assert.deepEqual(await read(), bytes);
  }
});

test("Darwin experiment installed reads retain canonical parents, held identities and bytes under hosted trust", async () => {
  const cache =
    "/System/Volumes/Preboot/fixture/runtime/dyld_shared_cache_x86_64h";
  for (const [purpose, file, fault, accepted = false] of [
    ["experiment", cache, null, true],
    ["experiment", "/System/Library/dyld/dyld_shared_cache_x86_64", null, true],
    ["reviewed", cache],
    [undefined, cache],
    ["unknown", cache],
    ...[
      "/usr/bin/clang",
      "/sbin/pfctl",
      "/usr/bin/hdiutil",
      "/usr/bin/log",
      "/usr/lib/dyld",
      "/Applications/Fixture.app/Contents/Developer/usr/bin/git",
      "/private/etc/security/audit_event",
      "/Library/Developer/Fixture.sdk/usr/include/bsm/audit_kevents.h",
    ].map((file) => ["experiment", file, null, true]),
    ["experiment", cache, "file-owner", true],
    [
      "experiment",
      "/Library/native-poc-" + "a".repeat(64) + "/dyld_shared_cache_x86_64",
    ],
    [
      "experiment",
      "/private/var/run/native-poc/cases/fixture/dyld_shared_cache_x86_64",
    ],
    ...[
      "parent-kind",
      "parent-alias",
      "parent-identity",
      "file-alias",
      "file-identity",
      "content",
    ].map((fault) => ["experiment", cache, fault]),
  ]) {
    const bytes = Buffer.from("installed cache fixture");
    let readStarted = false,
      parentSamples = 0,
      closed = false;
    const metadata = (name) => {
      const leaf = name === file;
      return {
        dev: 1n,
        ino: leaf
          ? readStarted && fault === "file-identity"
            ? 2n
            : 1n
          : fault === "parent-identity"
            ? BigInt(++parentSamples)
            : 3n,
        mode: leaf ? 0o666n : 0o777n,
        uid: leaf && fault !== "file-owner" ? 0n : 501n,
        gid: 0n,
        nlink: 2n,
        size: leaf ? BigInt(bytes.length) : 0n,
        mtimeNs: 1n,
        ctimeNs: 1n,
        isFile: () => leaf,
        isDirectory: () => !leaf && fault !== "parent-kind",
        isSymbolicLink: () => false,
      };
    };
    const fs = {
      realpath: async (name) =>
        (name === file && fault === "file-alias") ||
        (name !== file && fault === "parent-alias")
          ? "/fixture/alias"
          : name,
      lstat: async (name) => metadata(name),
      open: async () => ({
        stat: async () => metadata(file),
        read: async (buffer, offset, length, position) => {
          readStarted = true;
          const chunk = (
            fault === "content" ? Buffer.alloc(bytes.length) : bytes
          ).subarray(position, position + length);
          chunk.copy(buffer, offset);
          return { bytesRead: chunk.length };
        },
        close: async () => {
          closed = true;
        },
      }),
    };
    const read = () =>
      protectedBytes(
        { path: file, sha256: digest(bytes) },
        0,
        0o444,
        1024,
        fs,
        true,
        purpose,
      );
    if (accepted) assert.deepEqual(await read(), bytes);
    else await assert.rejects(read, undefined, `${purpose}/${file}/${fault}`);
    if (fault !== "file-alias") assert.equal(closed, true);
  }
});

const hash = "a".repeat(64),
  candidateSha = "b".repeat(40),
  cdhash = "c".repeat(40);

function loaderImage(format) {
  const thin = Buffer.alloc(144);
  for (const [at, value] of [
    [0, 0xfeedfacf],
    [4, 0x01000007],
    [8, 3],
    [12, 7],
    [16, 3],
    [20, 96],
    [32, 0x24],
    [36, 16],
    [40, 0xe0000],
    [44, 0xf0000],
    [48, 0x1b],
    [52, 24],
    [72, 0xc],
    [76, 56],
    [80, 24],
  ])
    thin.writeUInt32LE(value, at);
  thin.fill(0xdd, 56, 72);
  thin.write("/usr/lib/libfixture.dylib\0", 96);
  thin.fill(0x5a, 128);
  if (format === "thin") return thin;
  const wide = format.startsWith("fat64"),
    little = format.endsWith("le"),
    bytes = Buffer.alloc(768),
    width = wide ? 32 : 20,
    write = (value, at, size = 4) => {
      if (size === 8)
        bytes[little ? "writeBigUInt64LE" : "writeBigUInt64BE"](
          BigInt(value),
          at,
        );
      else bytes[little ? "writeUInt32LE" : "writeUInt32BE"](value, at);
    };
  write(wide ? 0xcafebabf : 0xcafebabe, 0);
  write(2, 4);
  for (const [index, cpu, start] of [
    [0, 0x0100000c, 256],
    [1, 0x01000007, 512],
  ]) {
    const at = 8 + index * width;
    write(cpu, at);
    write(3, at + 4);
    write(start, at + 8, wide ? 8 : 4);
    write(thin.length, at + (wide ? 16 : 12), wide ? 8 : 4);
    write(8, at + (wide ? 24 : 16));
    thin.copy(bytes, start);
    bytes.writeUInt32LE(cpu, start + 4);
  }
  return bytes;
}

let imageScript;
async function nativeImageRead(
  bytes,
  {
    file = "/usr/lib/dyld",
    purpose = "experiment",
    operation = "macho",
    pin = digest(bytes),
  } = {},
) {
  if (!imageScript) {
    const source = await readFile(
        new URL("custody-reader.c", import.meta.url),
        "utf8",
      ),
      parser = source.slice(
        source.indexOf("static void macho("),
        source.indexOf("static void case_members("),
      ),
      input = /  char actual\[65\]; sha_range\(value.fd,[^\n]+/u.exec(
        source,
      )?.[0];
    assert.ok(parser && input);
    const translate = (body) =>
      body
        .replace(/#ifndef NATIVE_CI_EXPERIMENT[\s\S]*?#endif/gu, "")
        .replace(/static void macho\([^\n]+\)/u, "function macho(bytes, size)")
        .replace(
          /static bool installed_loader\([^\n]+\)/u,
          "function installed_loader(value)",
        )
        .replace(
          /static uint64_t container_number\([^\n]+\)/u,
          "function container_number(bytes, width, little)",
        )
        .replace(/static void image\([^\n]+\)/u, "function image(value)")
        .replace(
          "const struct mach_header_64 *h = (const void *)bytes",
          "const h = headerView(bytes)",
        )
        .replaceAll(
          "const struct load_command *lc = (const void *)(bytes + at)",
          "const lc = commandView(bytes, at)",
        )
        .replace(
          /const struct (?:build_version_command|version_min_command) \*v = \(const void \*\)lc/gu,
          "const v = lc",
        )
        .replace(
          /\(\(const struct (?:dylib_command|dylinker_command|rpath_command) \*\)lc\)->(?:dylib.name|name|path).offset/gu,
          "lc.name",
        )
        .replace("((const struct uuid_command *)lc)->uuid", "lc.uuid")
        .replace(
          "const unsigned char *name = bytes + at + offset",
          "const name = bytes.subarray(at + offset)",
        )
        .replace(
          /container_number\((prefix|record) \+ \(([^)]+)\),/gu,
          "container_number($1.subarray($2),",
        )
        .replace(
          /container_number\((prefix|record) \+ (\d+),/gu,
          "container_number($1.subarray($2),",
        )
        .replace(/char (sum|encoded|id|actual)\[[^;]+\]/gu, "let $1 = {}")
        .replace(
          /unsigned char (digest_bytes|uuid|prefix|record)\[(\d+)\](?: = \{0\})?/gu,
          "let $1 = Buffer.alloc($2)",
        )
        .replace(
          "struct mach_header_64 header",
          "let header = {nativeHeader: true}",
        )
        .replace(
          "unsigned char *bytes = malloc(size)",
          "let bytes = Buffer.alloc(size)",
        )
        .replace("starts[128], lengths[128]", "starts = [], lengths = []")
        .replaceAll("sizeof(struct mach_header_64)", "32")
        .replaceAll("sizeof(struct load_command)", "8")
        .replaceAll("sizeof(struct dylib_command)", "24")
        .replaceAll("sizeof(struct dylinker_command)", "12")
        .replaceAll("sizeof(struct rpath_command)", "12")
        .replaceAll("sizeof(struct build_tool_version)", "8")
        .replaceAll("sizeof(struct uuid_command)", "24")
        .replaceAll("sizeof(*h)", "32")
        .replaceAll("sizeof(*v)", "v.width")
        .replaceAll("sizeof(header)", "32")
        .replaceAll("sizeof(prefix)", "8")
        .replaceAll("sizeof(magic)", "4")
        .replaceAll("(1ULL << alignment)", "(2 ** alignment)")
        .replaceAll(/\((?:uint64_t|uint32_t|CC_LONG|const char \*)\)/gu, "")
        .replaceAll("->", ".")
        .replaceAll(/&(header|value|magic)\b/gu, "$1")
        .replaceAll(/\b(?:uint64_t|uint32_t|unsigned|size_t|bool) /gu, "let ");
    const buildInput = input
      .replace("uint32_t magic = 0", "uint32_t magic = {value: 0}")
      .replace("magic == MH_MAGIC_64", "magic.value == MH_MAGIC_64");
    imageScript = new Script(`${translate(parser)}
      function build_input(value, pin) { ${translate(buildInput)} stable(value); }
      operation === "build-input" ? build_input(value, pin) : image(value);`);
  }
  let output = "",
    stable = 0;
  const need = (ok) => {
      if (!ok) throw new Error("Native image refused");
    },
    number = (data, at) => data.readUInt32LE(at),
    headerView = (data) =>
      Object.fromEntries(
        [
          "magic",
          "cputype",
          "cpusubtype",
          "filetype",
          "ncmds",
          "sizeofcmds",
        ].map((name, i) => [name, number(data, i * 4)]),
      ),
    commandView = (data, at) => ({
      cmd: number(data, at),
      cmdsize: number(data, at + 4),
      name: number(data, at + 8),
      version: number(data, at + 8),
      sdk: number(data, at + 12),
      platform: number(data, at + 8),
      minos: number(data, at + 12),
      ntools: data.readUInt32LE(at + 20),
      width: number(data, at) === 0x32 ? 24 : 16,
      uuid: data.subarray(at + 8, at + 24),
    }),
    scalar = (value) => value?.value ?? value;
  imageScript.runInNewContext({
    Buffer,
    operation,
    pin,
    headerView,
    commandView,
    value: { fd: 7, path: file, stat: { st_size: bytes.length } },
    MH_MAGIC_64: 0xfeedfacf,
    CPU_TYPE_X86_64: 0x01000007,
    FAT_MAGIC: 0xcafebabe,
    FAT_CIGAM: 0xbebafeca,
    FAT_MAGIC_64: 0xcafebabf,
    FAT_CIGAM_64: 0xbfbafeca,
    MH_EXECUTE: 2,
    MH_DYLIB: 6,
    MH_DYLINKER: 7,
    LC_DYLD_ENVIRONMENT: 0x27,
    LC_LOAD_DYLIB: 0xc,
    LC_LOAD_WEAK_DYLIB: 0x80000018,
    LC_REEXPORT_DYLIB: 0x8000001f,
    LC_LOAD_UPWARD_DYLIB: 0x80000023,
    LC_LAZY_LOAD_DYLIB: 0x20,
    LC_LOAD_DYLINKER: 0xe,
    LC_RPATH: 0x8000001c,
    LC_BUILD_VERSION: 0x32,
    LC_VERSION_MIN_MACOSX: 0x24,
    LC_UUID: 0x1b,
    PLATFORM_MACOS: 1,
    PATH_MAX: 1024,
    experiment_installed_path: (name) =>
      purpose === "experiment" && isDarwinInstalledPath(name),
    need,
    stdout: {},
    read_at(fd, out, size, at) {
      need(fd === 7 && at >= 0 && at + size <= bytes.length);
      const data = bytes.subarray(at, at + size);
      if (Buffer.isBuffer(out)) {
        need(size <= out.length);
        data.copy(out);
      } else if (out.nativeHeader) Object.assign(out, headerView(data));
      else out.value = data.readUInt32LE(0);
    },
    sha_range(fd, at, size, out) {
      need(fd === 7 && at === 0 && size === bytes.length);
      out.value = digest(bytes);
    },
    CC_SHA256(data, size, out) {
      Buffer.from(digest(data.subarray(0, size)), "hex").copy(out);
      return true;
    },
    hex(data, size, out) {
      out.value = data.subarray(0, size).toString("hex");
    },
    strcmp: (a, b) => Number(scalar(a) !== scalar(b)),
    strnlen: (data, size) => {
      const end = data.subarray(0, size).indexOf(0);
      return end < 0 ? size : end;
    },
    memcpy: (target, source, size) => source.copy(target, 0, 0, size),
    printf(format, ...args) {
      output += format.replace(/%[su]/gu, () => scalar(args.shift()));
    },
    fputs: (text) => {
      output += scalar(text);
    },
    putchar: (text) => {
      output += text;
    },
    free() {},
    stable() {
      stable++;
    },
  });
  assert.ok(stable > 0);
  return JSON.parse(
    operation === "build-input" ? `{${output.slice(1)}}` : output,
  );
}

test("Darwin native loader reads select identical thin metadata from every universal container encoding", async () => {
  const thin = loaderImage("thin"),
    expected = await nativeImageRead(thin);
  assert.equal(expected.headerSha256, digest(thin.subarray(0, 128)));
  assert.deepEqual(expected.dependencies, [
    Buffer.from("/usr/lib/libfixture.dylib").toString("hex"),
  ]);
  assert.equal(expected.sdk, 0xf0000);
  assert.deepEqual(
    await nativeImageRead(thin, {
      file: "/fixture/helper",
      purpose: "reviewed",
    }),
    expected,
  );
  for (const format of [
    "thin",
    "fat32-be",
    "fat32-le",
    "fat64-be",
    "fat64-le",
  ]) {
    const bytes = loaderImage(format),
      acquired = await nativeImageRead(bytes, { operation: "build-input" });
    assert.deepEqual(acquired.macho, expected, format);
    assert.deepEqual(await nativeImageRead(bytes), expected, format);
    assert.equal(acquired.sha256, digest(bytes));
    await assert.rejects(
      nativeImageRead(bytes, { operation: "build-input", pin: "f".repeat(64) }),
      /Native image refused/u,
    );
    if (format === "thin") continue;
    for (const [file, purpose] of [
      ["/usr/lib/dyld", "reviewed"],
      ["/fixture/helper", "experiment"],
      ["/usr/bin/git", "experiment"],
    ])
      await assert.rejects(
        nativeImageRead(bytes, { file, purpose }),
        /Native image refused/u,
      );
    assert.equal(
      Object.hasOwn(
        await nativeImageRead(bytes, {
          file: "/usr/bin/git",
          operation: "build-input",
        }),
        "macho",
      ),
      false,
    );
  }
});

test("Darwin native loader container and selected Mach-O bounds reject malformed and ambiguous images", async () => {
  for (const format of ["fat32-be", "fat32-le", "fat64-be", "fat64-le"]) {
    const wide = format.startsWith("fat64"),
      little = format.endsWith("le"),
      width = wide ? 32 : 20,
      selected = 8 + width;
    for (const fault of [
      "table-truncated",
      "table-empty",
      "table-large",
      "missing",
      "duplicate",
      "table-overlap",
      "slice-overlap",
      "range",
      "slice-size",
      "unselected-range",
      "empty-slice",
      "alignment",
      "misaligned",
      "header-short",
      "commands-short",
      "magic",
      "cpu",
      "subtype",
      "command",
      "commands-large",
      ...(wide ? ["reserved", "wide-offset"] : []),
    ]) {
      let bytes = loaderImage(format);
      const write = (value, at, size = 4) => {
        if (size === 8)
          bytes[little ? "writeBigUInt64LE" : "writeBigUInt64BE"](
            BigInt(value),
            at,
          );
        else bytes[little ? "writeUInt32LE" : "writeUInt32BE"](value, at);
      };
      if (fault === "table-truncated")
        bytes = bytes.subarray(0, 8 + 2 * width - 1);
      if (fault === "table-empty") write(0, 4);
      if (fault === "table-large") write(129, 4);
      if (fault === "missing") write(0x0100000c, selected);
      if (fault === "duplicate") write(0x01000007, 8);
      if (
        ["table-overlap", "slice-overlap", "range", "misaligned"].includes(
          fault,
        )
      )
        write(
          {
            "table-overlap": 0,
            "slice-overlap": 256,
            range: 1024,
            misaligned: 513,
          }[fault],
          selected + 8,
          wide ? 8 : 4,
        );
      if (["empty-slice", "header-short", "commands-short"].includes(fault))
        write(
          { "empty-slice": 0, "header-short": 31, "commands-short": 127 }[
            fault
          ],
          selected + (wide ? 16 : 12),
          wide ? 8 : 4,
        );
      if (fault === "alignment") write(63, selected + (wide ? 24 : 16));
      if (fault === "slice-size")
        write(257, selected + (wide ? 16 : 12), wide ? 8 : 4);
      if (fault === "unselected-range") {
        write(0x01000007, 8);
        bytes.writeUInt32LE(0x01000007, 260);
        write(0x0100000c, selected);
        bytes.writeUInt32LE(0x0100000c, 516);
        write(1024, selected + 8, wide ? 8 : 4);
      }
      if (fault === "reserved") write(1, selected + 28);
      if (fault === "wide-offset") write(0x100000200, selected + 8, 8);
      if (fault === "magic") bytes.writeUInt32LE(0, 512);
      if (fault === "cpu") bytes.writeUInt32LE(0x0100000c, 516);
      if (fault === "subtype") bytes.writeUInt32LE(8, 520);
      if (fault === "command") bytes.writeUInt32LE(7, 512 + 36);
      if (fault === "commands-large") bytes.writeUInt32LE(1048577, 512 + 20);
      for (const operation of ["build-input", "macho"])
        await assert.rejects(
          nativeImageRead(bytes, { operation }),
          /Native image refused/u,
          `${format}: ${fault}: ${operation}`,
        );
    }
  }
  for (const bytes of [
    Buffer.alloc(7),
    Buffer.alloc(144),
    Buffer.from("unsupported installed loader"),
  ])
    await assert.rejects(
      nativeImageRead(bytes, { operation: "build-input" }),
      /Native image refused/u,
    );
});

let signatureScript;
async function checkInputSignature(
  file,
  pin,
  signing = {},
  purpose = "experiment",
) {
  if (!signatureScript) {
    const source = await readFile(
      new URL("custody.h", import.meta.url),
      "utf8",
    );
    const functions = [
      ["input_refusal", "name, predicate, st"],
      ["signature_rule", "name, predicate, ok"],
      ["signature_hash", "name, info, actual"],
      ["signature_entitlements", "name, entitlements"],
      ["signature", "name, pin"],
    ].map(([name, parameters]) => {
      const body = new RegExp(
        `static void ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)?.[1];
      assert.ok(body, name);
      return `function ${name}(${parameters}) {${body
        .replace(
          "char encoded[PATH_MAX*2+1] = {0};",
          'const encoded = {value: ""};',
        )
        .replace("char actual[41];", "const actual = {};")
        .replace(
          "const void *keys[2], *values[2];",
          "const keys = [], values = [];",
        )
        .replaceAll("st->", "st.")
        .replace(/\((?:const unsigned char \*|intmax_t|uintmax_t)\)/gu, "")
        .replace(
          /\b(?:int|size_t|CFDataRef|CFDictionaryRef|CFIndex) /gu,
          "let ",
        )}}`;
    });
    signatureScript = new Script(`${functions.join("\n")} signature;`);
  }
  const diagnostics = [],
    operations = [],
    grants = signing.entitlements ?? null,
    info = {
      hash:
        signing.hash === undefined
          ? Buffer.from(signing.cdhash ?? cdhash, "hex")
          : signing.hash,
      entitlements: grants,
    },
    context = {
      PATH_MAX: 1024,
      NULL: null,
      stderr: {},
      errno: signing.errno ?? 0,
      kSecCodeInfoUnique: "hash",
      kSecCodeInfoEntitlementsDict: "entitlements",
      kCFBooleanTrue: true,
      signature_information(name, detailed) {
        assert.equal(detailed, true);
        operations.push(["native-signature", name]);
        context.need(signing.valid !== false);
        return info;
      },
      experiment_installed_path: (name) =>
        purpose === "experiment" && isDarwinInstalledPath(name),
      CFDictionaryGetValue: (value, key) => value[key],
      CFGetTypeID: (value) =>
        Buffer.isBuffer(value)
          ? "data"
          : Array.isArray(value)
            ? "dictionary"
            : "other",
      CFDataGetTypeID: () => "data",
      CFDictionaryGetTypeID: () => "dictionary",
      CFDataGetLength: (value) => value.length,
      CFDataGetBytePtr: (value) => value,
      CFDictionaryGetCount: (value) => value.length,
      CFDictionaryGetKeysAndValues(value, keys, values) {
        operations.push(["helper-entitlements", file]);
        for (const [key, grant] of value) {
          keys.push(key);
          values.push(grant);
        }
      },
      CFEqual: (left, right) => left === right,
      CFSTR: (value) => value,
      CFRelease: () => operations.push(["release", file]),
      strlen: (value) => Buffer.byteLength(value),
      strcmp: (left, right) => Number(left.value !== right),
      hex(bytes, size, output) {
        output.value = Buffer.from(bytes).subarray(0, size).toString("hex");
      },
      fprintf(stream, format, ...values) {
        diagnostics.push({
          format,
          values: values.map((value) => value?.value ?? value),
        });
        context.errno = 97;
        return -1; // Diagnostic failure must preserve the original refusal.
      },
      fflush() {
        context.errno = 98;
        return -1;
      },
      need(ok) {
        if (!ok)
          throw Object.assign(new Error("Native signature refused"), {
            errno: context.errno,
            diagnostics,
          });
      },
    };
  signatureScript.runInNewContext(context)(file, pin);
  return { diagnostics, operations };
}

test("Darwin signature policy exempts only installed experiment originals and preserves native refusals", async () => {
  const installed = "/usr/bin/hdiutil",
    helper = "/fixture/report/platform-build/launcher",
    foreign = [["fixture.entitlement", true]],
    jit = [["com.apple.security.cs.allow-jit", true]];
  for (const [file, purpose, signing, rule] of [
    [
      installed,
      "experiment",
      { entitlements: [...foreign, ...foreign, ...foreign] },
    ],
    [helper, "experiment", { entitlements: jit }],
    [helper, "experiment", {}],
    [
      installed,
      "reviewed",
      { entitlements: foreign },
      "helper-entitlement-key",
    ],
    [helper, "experiment", { entitlements: foreign }, "helper-entitlement-key"],
    [
      "/private/var/run/native-poc/cases/fixture/storage/git",
      "experiment",
      { entitlements: foreign },
      "helper-entitlement-key",
    ],
    [
      helper,
      "experiment",
      { entitlements: [...jit, ...jit, ...jit] },
      "helper-entitlements-count",
    ],
    [
      helper,
      "experiment",
      { entitlements: [[jit[0][0], false]] },
      "helper-entitlement-value",
    ],
    [
      helper,
      "experiment",
      { entitlements: "malformed" },
      "helper-entitlements-dictionary",
    ],
    [installed, "experiment", { hash: null }, "signature-cdhash-data"],
    [
      installed,
      "experiment",
      { hash: Buffer.alloc(19) },
      "signature-cdhash-size",
    ],
    [
      installed,
      "experiment",
      { cdhash: "e".repeat(40) },
      "signature-cdhash-match",
    ],
    [installed, "experiment", { valid: false }, "native"],
  ]) {
    for (const errno of rule ? [0, 7] : [0]) {
      const run = () =>
        checkInputSignature(file, cdhash, { ...signing, errno }, purpose);
      if (rule)
        await assert.rejects(run, (error) => {
          assert.equal(error.errno, errno);
          if (rule !== "native")
            assert.deepEqual(error.diagnostics[0].values, [
              rule,
              Buffer.byteLength(file),
              Buffer.from(file).toString("hex"),
              errno,
            ]);
          return true;
        });
      else {
        const result = await run();
        assert.deepEqual(result.diagnostics, []);
        assert.deepEqual(result.operations[0], ["native-signature", file]);
        assert.equal(
          result.operations.some(
            ([operation]) => operation === "helper-entitlements",
          ),
          file === helper && signing.entitlements !== undefined,
        );
      }
    }
  }
});

test("Darwin native installed, build and helper-slot guards distinguish hosted files from private inputs", async () => {
  const reader = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    header = await readFile(new URL("custody.h", import.meta.url), "utf8");
  for (const lane of ["installed", "build", "slot"]) {
    const source = lane === "installed" ? header : reader,
      start = source.indexOf(
        lane === "slot"
          ? "      bool hosted = !authority"
          : "  bool sampled = false;",
      ),
      end = source.indexOf(
        lane === "installed"
          ? "    need(!fstat(fd, &after)"
          : lane === "build"
            ? "  printf("
            : "      if (!dir && !authority)",
        start,
      ),
      body = source
        .slice(start, end)
        .replaceAll(/\bbool\b/gu, "let")
        .replaceAll("const char *predicate", "let predicate")
        .replaceAll("->", ".")
        .replaceAll(/&(value\.stat|entry\.stat|before)/gu, "$1")
        .replaceAll("(uint64_t)", "")
        .replaceAll(/\b(\d+)ULL\b/gu, "$1")
        .replaceAll(/\b0([0-7]{2,})\b/gu, "0o$1");
    assert.ok(start > 0 && end > start);
    for (const [file, experiment, fault, accepted] of [
      ["/usr/bin/hdiutil", true, null, true],
      [
        "/Applications/Fixture.app/Contents/Developer/usr/bin/git",
        true,
        null,
        true,
      ],
      ["/usr/bin/hdiutil", false, null, false],
      ["/fixture/private/helper", true, null, false],
      ["/unrelated/git", true, null, false],
      ...["open", "stat", "kind", "links", "size"]
        .filter((fault) => lane !== "installed" || fault !== "size")
        .map((fault) => ["/usr/bin/hdiutil", true, fault, false]),
    ]) {
      const refusals = [],
        calls = [],
        stat = {
          st_uid: 501,
          st_gid: 20,
          st_mode: 0o100777,
          st_nlink: fault === "links" ? 0 : 3,
          st_size: fault === "size" ? 536870913 : 4,
        },
        entry = {
          path: file,
          kind: "helper",
          fd: fault === "open" ? -1 : 3,
          stat: {},
        },
        hosted = experiment && isDarwinInstalledPath(file),
        context = {
          value: entry,
          entry,
          name: file,
          hosted,
          authority: false,
          dir: false,
          fd: entry.fd,
          before: {},
          identity: stat,
          parent: file,
          leaf: true,
          file_stat_same: () => true,
          subject_uid: 1001,
          subject_gid: 1002,
          fstat(fd, target) {
            calls.push("stat");
            Object.assign(target, stat);
            return fault === "stat" ? -1 : 0;
          },
          S_ISREG: () => fault !== "kind",
          S_ISDIR: () => false,
          experiment_installed_path: () => hosted,
          installed_input() {
            calls.push("held");
            return 1;
          },
          no_acl() {
            calls.push("acl");
          },
          strcmp: (a, b) => Number(a !== b),
          NULL: null,
          input_refusal(name, predicate, metadata) {
            refusals.push({ name, predicate, metadata });
          },
          need(ok) {
            if (!ok) throw new Error("Original native refusal");
          },
        },
        run = () => new Script(body).runInNewContext(context);
      if (accepted) {
        run();
        assert.deepEqual(
          calls,
          lane === "installed" ? ["stat"] : ["stat", "held"],
        );
      } else {
        assert.throws(run, /Original native refusal/);
        assert.equal(refusals[0].name, file);
        assert.equal(refusals[0].predicate, fault ?? "eligibility");
        assert.equal(
          refusals[0].metadata === null,
          ["open", "stat"].includes(fault),
        );
        assert.ok(!calls.includes("held") && !calls.includes("acl"));
      }
    }
  }
});
const identity = (pid) => ({
  pid,
  pidVersion: 1,
  asid: 0,
  auid: 0,
  uid: 0,
  gid: 0,
  ruid: 0,
  rgid: 0,
  svuid: 0,
  svgid: 0,
  startSeconds: 100,
  startMicroseconds: pid,
});
const fileId = (inode) => `1:2:3:${inode}:100:0:${"d".repeat(32)}`;
const context = {
  candidateSha,
  platform: "darwin",
  tier: "system",
  runId: "1",
  runAttempt: 1,
  jobBindingSha256: hash,
  executionId: "darwin.files",
  closureSha256: hash,
  selectedSystemSha256: null,
};
const image = { path: "/fixture/sealed/reader", sha256: hash, cdhash };
const input = {
  context,
  reader: image,
  sources: [
    "custody-reader.c",
    "custody.h",
    "file-identity.h",
    "effective-reader.h",
    "feasibility-sandbox.h",
  ].map((name) => ({
    path: `/fixture/sealed/${name}`,
    sha256: hash,
  })),
  plan: { path: "/fixture/sealed/plan", sha256: hash },
  tools: {
    elevation: { path: "/usr/bin/sudo", sha256: hash },
    environment: { path: "/usr/bin/env", sha256: hash },
  },
  reportDirectory: "/fixture/report",
  reviewSha256: hash,
  sdkSha256: hash,
  buildSha256: hash,
};
export function fixture({
  failure,
  onPersist,
  purpose = "reviewed",
  build = false,
  inputBytes = 4,
  buildBytes = 4,
  hosted = false,
  signing,
  inputData,
  loaderFormat,
  entries = [],
} = {}) {
  const loaderBytes = loaderFormat
    ? loaderImage(loaderFormat === "universal" ? "fat32-be" : loaderFormat)
    : undefined;
  if (loaderBytes && entries.length === 0)
    entries = [
      { kind: "image", path: "/usr/lib/dyld", sha256: digest(loaderBytes) },
    ];
  const selectedInput = structuredClone(input);
  if (build) selectedInput.context.executionId = "build";
  if (purpose === "experiment") {
    selectedInput.purpose = purpose;
    selectedInput.bindingSha256 = selectedInput.reviewSha256;
    delete selectedInput.reviewSha256;
    for (const name of ["experiment.h", "pf-abi.h"])
      selectedInput.sources.push({
        path: "/fixture/sealed/" + name,
        sha256: hash,
      });
  }
  const events = [],
    receipts = [],
    probed = [],
    frames = [{ helper: identity(20) }];
  let helperLive = true,
    fileLive = true,
    finishing = false,
    reserved = false;
  const object = (index) => ({
    identity: fileId(index + 1),
    bytes:
      index === 0 && loaderBytes
        ? loaderBytes.length
        : [0, 4].includes(index)
          ? 4
          : index === 3
            ? 23
            : 0,
    uid: 0,
    gid: 0,
    mode:
      index === 4 ? 0o555 : index === 0 ? 0o550 : index === 3 ? 0o400 : 0o700,
    directory: ![0, 3, 4].includes(index),
    ...(hosted && index === 0 ? { uid: 501, gid: 20, mode: 0o777 } : {}),
  });
  const transport = async (_, args) => {
    events.push(args[0]);
    if (args[0] === "--probe") {
      const pid = Number(args[1]);
      probed.push(pid);
      const subject = (pid === 20 ? helperLive : fileLive)
        ? {
            status: "live",
            identity: identity(
              finishing && failure === "foreign-retirement" ? pid + 1 : pid,
            ),
            sha256: failure === "image" ? "e".repeat(64) : hash,
            signature: {
              cdhash: failure === "signature" ? "e".repeat(40) : cdhash,
              entitlementsSha256: hash,
              valid: true,
            },
            directories:
              pid === 30
                ? [3, 4].map((fd) => ({
                    fd,
                    dev: "1",
                    ino: String(fd === 3 ? 2 : 3),
                    uid: 0,
                    gid: 0,
                    mode: 0o700,
                  }))
                : [],
          }
        : { status: "absent" };
      return {
        receive: async () => ({ verifier: identity(40), subject }),
        completion: Promise.resolve({ code: 0, signal: null }),
        close() {},
      };
    }
    return {
      async send(line) {
        events.push(line.trim());
        if (line === "P\n") {
          frames.push({
            ...(purpose === "experiment" && failure !== "purpose"
              ? { purpose }
              : {}),
            candidateSha,
            entries: 4,
            uid: 1001,
            gid: 1002,
          });
          return;
        }
        const [op, sequence, a, b, c] = line.trim().split(" ");
        let value = null;
        if (["open", "inspect"].includes(op)) value = object(Number(a));
        if (
          op === "inspect" &&
          (failure === "substitution" ||
            (failure === "lease-substitution" && reserved && Number(a) === 3))
        )
          value.identity = fileId(99);
        if (op === "reserve") {
          reserved = true;
          value = object(Number(a));
        }
        if (op === "reservation") value = { held: true };
        if (op === "pf-write") value = { pid: 50, settled: true };
        if (["process", "session"].includes(op)) {
          value = identity(Number(a));
          if (failure === "process-substitution") value.pid++;
          if (failure === "process-malformed") value.pidVersion = 0;
        }
        if (op === "read")
          value = {
            hex: (Number(a) === 0 && loaderBytes
              ? loaderBytes
              : Buffer.from("data")
            )
              .subarray(Number(b), Number(b) + Number(c))
              .toString("hex"),
          };
        if (op === "signature")
          value = { cdhash, entitlementsSha256: hash, valid: true };
        if (op === "authority")
          value = {
            subject: identity(Number(a)),
            sandboxed: true,
            path: Buffer.from(entries[Number(b)].path).toString("hex"),
            object: object(Number(b)),
            aclSha256: hash,
            decisions: [0, 1, 1, 1, 0],
          };
        const metadata = {
          headerSha256: hash,
          dependencies: [
            Buffer.from("/usr/lib/libfixture.dylib").toString("hex"),
          ],
          rpaths: [],
          sdk: 0xf0000,
          minimum: 0xf0000,
          uuid: "d".repeat(32),
        };
        if (op === "macho")
          value =
            Number(a) === 0 && loaderBytes
              ? await nativeImageRead(loaderBytes, { purpose })
              : metadata;
        if (op === "build-root") value = { ...object(1), mode: 0o555 };
        if (op === "build-open")
          value = {
            index: 4,
            object: { ...object(4), bytes: buildBytes },
            root: { ...object(1), mode: 0o555 },
            sha256: digest(Buffer.from("data")),
          };
        if (op === "build-input") {
          const file = Buffer.from(a, "hex").toString(),
            data =
              (await inputData?.(file)) ??
              (file === "/usr/lib/dyld" ? loaderBytes : undefined),
            native =
              file === "/usr/lib/dyld" && data
                ? await nativeImageRead(data, {
                    file,
                    purpose,
                    operation: "build-input",
                    pin: b,
                  })
                : null,
            installed = hosted && isDarwinInstalledPath(file);
          if (c)
            await checkInputSignature(
              file,
              c,
              {
                ...signing,
                ...(failure === "build-signature"
                  ? { cdhash: "e".repeat(40) }
                  : {}),
              },
              purpose,
            );
          value = {
            object: {
              ...object(4),
              mode: installed ? 0o666 : 0o444,
              uid: installed ? 501 : 0,
              gid: 80,
              bytes: data?.length ?? inputBytes,
            },
            sha256:
              failure === "build-input"
                ? "e".repeat(64)
                : data
                  ? digest(data)
                  : b,
            ...(native
              ? { macho: native.macho }
              : data?.length >= 4 && data.readUInt32LE(0) === 0xfeedfacf
                ? { macho: metadata }
                : {}),
            ...(c
              ? { cdhash: failure === "build-signature" ? "e".repeat(40) : c }
              : {}),
            ...(Buffer.from(a, "hex")
              .toString()
              .endsWith("/SDKSettings.json") && failure !== "sdk-missing"
              ? {
                  sdk: {
                    ...object(2),
                    gid: 20,
                    uid: installed ? 501 : 0,
                    mode:
                      failure === "sdk-writable" || installed ? 0o775 : 0o755,
                    directory: failure !== "sdk-file",
                  },
                  ...(failure === "developer-missing"
                    ? {}
                    : {
                        developer: {
                          ...object(2),
                          uid: installed ? 501 : 0,
                          gid: 20,
                          mode:
                            failure === "developer-writable" || installed
                              ? 0o775
                              : 0o755,
                          directory: failure !== "developer-file",
                        },
                      }),
                  compilerPathHex:
                    failure === "compiler-path"
                      ? "xx"
                      : Buffer.from(
                          "/Library/Developer/CommandLineTools/usr/bin/clang",
                        ).toString("hex"),
                }
              : {}),
          };
        }
        if (op === "build")
          value = {
            osBuild: Buffer.from("fixture-build").toString("hex"),
            macho: metadata,
          };
        if (op === "cache")
          value = {
            ...(purpose === "experiment" && failure !== "runtime-hash"
              ? { sha256: hash }
              : {}),
            cacheUuid: (failure === "runtime-cache-uuid" ? "0" : "e").repeat(
              32,
            ),
            imageUuid:
              failure === "runtime-uuid" ? "f".repeat(32) : metadata.uuid,
            signatureSha256: hash,
            macho: metadata,
          };
        if (op === "transfer") value = { pid: 30 };
        if (op === "file-read")
          value = {
            nonce: "f".repeat(32),
            phase: "ready",
            base: fileId(3),
            root: fileId(2),
            allocation: null,
            leaf: null,
            temporary: null,
            alias: false,
          };
        if (op === "file-close") {
          fileLive = false;
          value = {
            code: 0,
            signal: null,
            decision: null,
            ...(failure === "file-trailing" ? {} : { drained: true }),
          };
        }
        if (op === "finish") {
          if (reserved) throw new Error("Unreleased PF reservation");
          finishing = true;
          helperLive = ["live-retirement", "foreign-retirement"].includes(
            failure,
          );
          value = { closed: true };
        }
        frames.push({
          sequence:
            failure === "sequence" ? Number(sequence) + 1 : Number(sequence),
          value,
        });
      },
      receive: async () => frames.shift(),
      completion: Promise.resolve({ code: 0, signal: null }),
      close() {
        events.push("fault");
      },
    };
  };
  const reader = createDarwinCustodyReader(selectedInput, {
    entries,
    runtime: {
      platform: "darwin",
      arch: "x64",
      env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "macos15" },
    },
    transport,
    kill(pid, signal) {
      assert.equal(signal, 0);
      throw Object.assign(new Error("Absent verifier"), { code: "ESRCH" });
    },
    verifyAssets: async () => {
      events.push("assets");
      if (failure === "source") throw new Error("private detail");
    },
    persist: async (record) => {
      receipts.push(structuredClone(record));
      events.push(`intent:${record.phase}`);
      await onPersist?.(record);
      if (failure === "persistence") throw new Error("private detail");
    },
  });
  return {
    reader,
    events,
    receipts,
    probed,
    input: selectedInput,
    loaderBytes,
  };
}
test("Darwin experiment build reads keep installed pins and held signatures separate from unsigned signing inputs", async () => {
  const value = fixture({ purpose: "experiment", build: true });
  await value.reader.start();
  const unsigned = await value.reader.readBuildImage(
    "/fixture/report/platform-build/launcher",
    null,
    134217728,
    false,
  );
  assert.equal(unsigned.held, true);
  assert.equal(unsigned.signature, undefined);
  assert.ok(!value.events.some((event) => event.startsWith("signature ")));
  const signed = await value.reader.readBuildImage(
    "/fixture/report/platform-build/launcher",
  );
  assert.equal(signed.signature.valid, true);
  assert.deepEqual(signed.macho.dependencies, ["/usr/lib/libfixture.dylib"]);
  assert.equal(
    (await value.reader.readBuildInput("/Library/Developer/input.h", hash))
      .sha256,
    hash,
  );
  const settings = await value.reader.readBuildInput(
    "/Library/Developer/CommandLineTools/SDKs/Fixture.sdk/SDKSettings.json",
    hash,
  );
  assert.equal(settings.sdk.directory, true);
  assert.equal(settings.sdk.identity, fileId(3));
  assert.equal(settings.developer.directory, true);
  assert.equal(
    (
      await value.reader.readBuildInput(
        "/Library/Developer/CommandLineTools/usr/bin/clang",
        hash,
        cdhash,
      )
    ).cdhash,
    cdhash,
  );
  assert.equal((await value.reader.close()).status, "RETIRED");
  const substituted = fixture({
    purpose: "experiment",
    build: true,
    failure: "build-input",
  });
  await substituted.reader.start();
  await assert.rejects(
    substituted.reader.readBuildInput("/Library/Developer/input.h", hash),
  );
  await substituted.reader.close();
  for (const failure of [
    "sdk-missing",
    "sdk-file",
    "developer-missing",
    "developer-file",
    "compiler-path",
  ]) {
    const refused = fixture({ purpose: "experiment", build: true, failure });
    await refused.reader.start();
    await assert.rejects(
      refused.reader.readBuildInput(
        "/Library/Developer/CommandLineTools/SDKs/Fixture.sdk/SDKSettings.json",
        hash,
      ),
    );
    await refused.reader.close();
  }
  const badSignature = fixture({
    purpose: "experiment",
    build: true,
    failure: "build-signature",
  });
  await badSignature.reader.start();
  await assert.rejects(
    badSignature.reader.readBuildInput(
      "/Library/Developer/CommandLineTools/usr/bin/clang",
      hash,
      cdhash,
    ),
  );
  await badSignature.reader.close();
  const reviewed = fixture({ build: true });
  await assert.rejects(
    reviewed.reader.readBuildInput("/Library/Developer/input.h", hash),
  );
  assert.deepEqual(reviewed.events, []);
});
test("Darwin custody relaxes only experiment installed slots and preserves repeated observations", async () => {
  const installed = "/Applications/Fixture.app/Contents/Developer/usr/bin/git";
  for (const [purpose, file, accepted] of [
    ["experiment", installed, true],
    ["reviewed", installed, false],
    ["experiment", "/fixture/private/helper", false],
    ["experiment", "/unrelated/git", false],
  ]) {
    const f = fixture({
      purpose,
      hosted: true,
      entries: [{ kind: "helper", path: file }],
    });
    await f.reader.start();
    if (accepted) {
      assert.equal((await f.reader.open(0)).uid, 501);
      for (let i = 0; i < 2; i++) {
        assert.equal((await f.reader.inspect(0)).mode, 0o777);
        assert.equal((await f.reader.read(0)).toString(), "data");
        assert.equal(
          (await f.reader.authority(identity(30), 0)).aclSha256,
          hash,
        );
      }
    } else await assert.rejects(f.reader.open(0));
    await f.reader.close();
  }
  const f = fixture({ purpose: "experiment", build: true, hosted: true });
  await f.reader.start();
  const settings = await f.reader.readBuildInput(
    "/Library/Developer/Fixture.sdk/SDKSettings.json",
    hash,
  );
  assert.equal(settings.object.uid, 501);
  assert.equal(settings.developer.uid, 501);
  await f.reader.close();
});
test("Darwin selected toolchain response sizes retain the installed-data bound and generated-image limit", async () => {
  for (const bytes of [134217729, 536870912, 536870913]) {
    const value = fixture({
      purpose: "experiment",
      build: true,
      inputBytes: bytes,
    });
    await value.reader.start();
    try {
      for (const tool of ["clang", "ld"])
        for (let read = 0; read < 2; read++) {
          const result = value.reader.readBuildInput(
            "/Library/Developer/CommandLineTools/usr/bin/" + tool,
            hash,
            cdhash,
          );
          if (bytes > 536870912) await assert.rejects(result);
          else {
            const actual = await result;
            assert.equal(actual.object.bytes, bytes);
            assert.equal(actual.sha256, hash);
            assert.equal(actual.cdhash, cdhash);
            assert.equal(actual.unchanged, true);
          }
        }
    } finally {
      assert.equal((await value.reader.close()).status, "RETIRED");
    }
  }
  for (const purpose of ["reviewed", "experiment"]) {
    const value = fixture({ purpose, build: true, buildBytes: 134217729 });
    await value.reader.start();
    try {
      await assert.rejects(
        value.reader.readBuildImage("/fixture/report/platform-build/launcher"),
      );
      assert.equal(
        value.events.some((event) => event.startsWith("read ")),
        false,
      );
    } finally {
      assert.equal((await value.reader.close()).status, "RETIRED");
    }
  }
});

test("Darwin cache custody rejects absent cache UUIDs, substituted images and missing experiment text hashes", async () => {
  for (const purpose of ["reviewed", "experiment"])
    for (const failure of [
      "runtime-cache-uuid",
      "runtime-uuid",
      ...(purpose === "experiment" ? ["runtime-hash"] : []),
    ]) {
      const value = fixture({ purpose, failure });
      await value.reader.start();
      await value.reader.open(0);
      await assert.rejects(value.reader.cache(0, "/usr/lib/libfixture.dylib"));
      assert.ok(value.events.includes("fault"));
      assert.equal((await value.reader.close()).status, "RETAINED");
    }
});
test("Darwin experimental custody binds purpose before admission and never supplies review references", async () => {
  for (const failure of [undefined, "signature", "purpose"]) {
    const value = fixture({ purpose: "experiment", failure });
    for (const [header, substitute] of [
      "pf-abi.h",
      "feasibility-sandbox.h",
    ].flatMap((header) =>
      [null, "substitute.h"].map((substitute) => [header, substitute]),
    )) {
      const missing = structuredClone(value.input);
      missing.sources = missing.sources.flatMap((source) =>
        !source.path.endsWith("/" + header)
          ? [source]
          : substitute
            ? [{ ...source, path: "/fixture/sealed/" + substitute }]
            : [],
      );
      assert.throws(() => normalizeDarwinCustodyInput(missing, "experiment"));
    }
    assert.throws(() => normalizeDarwinCustodyInput(value.input));
    assert.throws(() =>
      createDarwinCustodyReader({ ...value.input, reviewSha256: hash }),
    );
    assert.throws(() =>
      createDarwinCustodyReader({
        ...value.input,
        context: { ...context, tier: "provider", selectedSystemSha256: hash },
      }),
    );
    if (failure) {
      await assert.rejects(value.reader.start());
      assert.equal((await value.reader.close()).status, "RETAINED");
    } else {
      assert.equal((await value.reader.start()).purpose, "experiment");
      assert.deepEqual((await value.reader.build()).observedBindings, {
        sdkSha256: hash,
        buildSha256: hash,
      });
      assert.equal((await value.reader.close()).status, "RETIRED");
    }
    assert.ok(
      value.receipts.every(
        (record) =>
          record.purpose === "experiment" && record.bindingSha256 === hash,
      ),
    );
    assert.ok(!JSON.stringify(value.receipts).includes("review"));
  }
});
test("Darwin custody construction is effect-free; sealed source and intent precede elevation and independent admission precedes release", async () => {
  const value = fixture();
  assert.deepEqual(value.events, []);
  await value.reader.start();
  assert.ok(
    value.events.indexOf("assets") < value.events.indexOf("intent:entry"),
  );
  assert.ok(
    value.events.indexOf("intent:entry") < value.events.indexOf("--serve"),
  );
  assert.ok(value.events.indexOf("--probe") < value.events.indexOf("P"));
  assert.ok(
    value.events.indexOf("intent:admitted") < value.events.indexOf("P"),
  );
  assert.deepEqual(
    value.receipts.find((record) => record.phase === "admitted").subjects,
    {
      helper: identity(20),
      verifier: identity(40),
    },
  );
  const opened = await value.reader.open(0);
  opened.identity = fileId(99);
  assert.equal((await value.reader.inspect(0)).identity, fileId(1));
  assert.equal((await value.reader.read(0)).toString(), "data");
  assert.equal((await value.reader.signature(0)).cdhash, cdhash);
  assert.deepEqual((await value.reader.macho(0)).dependencies, [
    "/usr/lib/libfixture.dylib",
  ]);
  assert.equal((await value.reader.build()).osBuild, "fixture-build");
  assert.equal(
    (await value.reader.cache(0, "/usr/lib/libfixture.dylib")).imageUuid,
    "d".repeat(32),
  );
  assert.equal((await value.reader.close()).status, "RETIRED");
  assert.ok(
    value.receipts.every(
      (record) =>
        record.context.runId === "1" && record.context.closureSha256 === hash,
    ),
  );
  assert.ok(!JSON.stringify(value.receipts).includes("data"));
});
test("Darwin missing source approval, persistence failure and substituted helper withhold the root setup barrier", async () => {
  for (const failure of ["source", "persistence", "image"]) {
    const value = fixture({ failure });
    await assert.rejects(
      value.reader.start(),
      /custody admission unavailable/u,
    );
    assert.ok(!value.events.includes("P"), failure);
    assert.equal((await value.reader.close()).status, "RETAINED");
    assert.ok(!JSON.stringify(value.receipts).includes("private detail"));
  }
  assert.throws(() => createDarwinCustodyReader({ ...input, sources: [] }));
});
test("Darwin stale held objects and malformed response sequences retain custody instead of declaring closure", async () => {
  for (const failure of [
    "sequence",
    "substitution",
    "process-substitution",
    "process-malformed",
    "live-retirement",
    "foreign-retirement",
  ]) {
    const value = fixture({ failure });
    await value.reader.start();
    if (failure === "sequence") await assert.rejects(value.reader.open(0));
    else if (failure === "substitution") {
      await value.reader.open(0);
      await assert.rejects(value.reader.read(0));
    } else if (failure.startsWith("process-"))
      await assert.rejects(value.reader.process(60, { retainSession: true }));
    assert.equal((await value.reader.close()).status, "RETAINED", failure);
  }
});
test("Darwin materialized plans reject undeclared paths, members and duplicate inputs without manufacturing approval", () => {
  const plan = {
    candidateSha,
    uid: 1001,
    gid: 1002,
    entries: [{ kind: "data", path: "/fixture/sealed/input", sha256: hash }],
  };
  assert.ok(
    encodeDarwinCustodyPlan({ ...plan, purpose: "experiment" })
      .toString()
      .startsWith(`native-experiment-custody-v1 ${candidateSha} 1001 1002\n`),
  );
  assert.ok(
    encodeDarwinCustodyPlan(plan)
      .toString()
      .startsWith(`native-custody-v1 ${candidateSha} 1001 1002\n`),
  );
  for (const entries of [
    [{ ...plan.entries[0], path: "/fixture/../input" }],
    [plan.entries[0], plan.entries[0]],
    [{ ...plan.entries[0], extra: true }],
    [{ ...plan.entries[0], path: "/" + "p".repeat(1023) }],
  ])
    assert.throws(() => encodeDarwinCustodyPlan({ ...plan, entries }));
});
test("PF exclusion rejoins the shared lease pathname and retains custody on substitution", async () => {
  const intact = fixture();
  await intact.reader.start();
  await intact.reader.open(3);
  await intact.reader.reserve(3, "f".repeat(32));
  assert.deepEqual(await intact.reader.reservation(), { held: true });
  assert.equal((await intact.reader.close()).status, "RETAINED");
  const substituted = fixture({ failure: "lease-substitution" });
  await substituted.reader.start();
  await substituted.reader.open(3);
  await substituted.reader.reserve(3, "f".repeat(32));
  await assert.rejects(substituted.reader.reservation(), /Unverified/);
  assert.ok(
    !substituted.events.some((event) => event.startsWith("reservation ")),
  );
  assert.equal((await substituted.reader.close()).status, "RETAINED");
});
test("Darwin descriptor transfer requires fresh exclusive custody and verifies the signed helper and its creation-time handles before start", async () => {
  const value = fixture();
  await value.reader.start();
  await value.reader.open(0);
  await value.reader.open(1);
  await value.reader.open(2);
  const file = {
    request: {
      schemaVersion: 1,
      candidateSha,
      nonce: "f".repeat(32),
      uid: 1001,
      gid: 1002,
      custody: "/fixture/custody",
      storage: "/fixture/storage",
      workspace: "/fixture/storage/work",
      launcher: { path: "/fixture/custody/launcher", sha256: hash },
      executable: {
        path: "/fixture/storage/file-helper",
        sha256: hash,
        cdhash,
      },
      policy: { path: "/fixture/custody/policy", sha256: hash },
      bindings: { system: hash, source: hash, closure: hash, policy: hash },
    },
    base: fileId(3),
    root: fileId(2),
    reviewSha256: hash,
  };
  const transfer = {
    helperIndex: 0,
    rootIndex: 1,
    baseIndex: 2,
    authority: {
      context,
      base: file.base,
      root: file.root,
      held: true,
      exclusive: true,
      independent: true,
      verifier: identity(50),
      verifierSha256: hash,
      nativeEventSha256: hash,
    },
  };
  await assert.rejects(
    value.reader.openFile(
      { ...file, request: { ...file.request, purpose: "experiment" } },
      transfer,
    ),
  );
  const experimental = fixture({ purpose: "experiment" });
  await experimental.reader.start();
  for (const index of [0, 1, 2]) await experimental.reader.open(index);
  await assert.rejects(experimental.reader.openFile(file, transfer));
  assert.ok(
    !experimental.events.some((event) => event.startsWith("transfer ")),
  );
  assert.equal((await experimental.reader.close()).status, "RETIRED");
  await assert.rejects(
    value.reader.openFile(file, {
      ...transfer,
      authority: { ...transfer.authority, exclusive: false },
    }),
  );
  assert.ok(!value.events.some((event) => event.startsWith("transfer ")));
  const channel = await value.reader.openFile(file, transfer);
  assert.equal(channel.admission.helper.pid, 30);
  assert.equal(channel.admission.soleParentAuthority, true);
  channel.admission.helper.pid = 99;
  const admitted = value.events.indexOf("intent:file-admitted"),
    start = value.events.findIndex((event) => event.startsWith("file-send "));
  assert.ok(admitted < start);
  channel.close();
  await channel.completion;
  assert.equal(value.probed.at(-1), 30);
  assert.equal((await value.reader.close()).status, "RETIRED");

  const incomplete = fixture({ failure: "file-trailing" });
  await incomplete.reader.start();
  for (const index of [0, 1, 2]) await incomplete.reader.open(index);
  const unread = await incomplete.reader.openFile(file, transfer);
  unread.close();
  await assert.rejects(unread.completion, /custody retained/u);
  assert.equal((await incomplete.reader.close()).status, "RETAINED");
});
test("Darwin expiration fences further native operations", async () => {
  const value = fixture(),
    controller = new AbortController();
  await value.reader.start({ signal: controller.signal });
  controller.abort();
  await assert.rejects(value.reader.open(0));
  assert.ok(!value.events.some((event) => event.startsWith("open ")));
  assert.equal((await value.reader.close()).status, "RETAINED");
});
test("Darwin bounded cleanup preserves held observations and restoration without reopening admission", async () => {
  for (const operation of ["restore", "open", "install", "expired"]) {
    const value = fixture(),
      work = new AbortController(),
      cleanup = new AbortController();
    await value.reader.start({ signal: work.signal });
    for (const index of [0, 3]) await value.reader.open(index);
    work.abort();
    await value.reader.beginCleanup({ signal: cleanup.signal });
    assert.equal(value.receipts.at(-1).phase, "cleanup");
    if (operation === "restore") {
      assert.equal((await value.reader.read(0)).toString(), "data");
      await value.reader.writePf(0, 3, cdhash, "restore");
      assert.equal((await value.reader.close()).status, "RETIRED");
    } else {
      if (operation === "expired") cleanup.abort();
      const before = value.events.length;
      await assert.rejects(
        operation === "open"
          ? value.reader.open(1)
          : operation === "install"
            ? value.reader.writePf(0, 3, cdhash, "install")
            : value.reader.read(0),
      );
      assert.ok(
        !value.events
          .slice(before)
          .some(
            (event) =>
              event.startsWith("open ") ||
              event.startsWith("pf-write ") ||
              event.startsWith("read "),
          ),
      );
      assert.equal((await value.reader.close()).status, "RETAINED");
    }
    cleanup.abort();
  }
});
test("Darwin cancellation while persisting admission withholds the setup barrier", async () => {
  const controller = new AbortController();
  const value = fixture({
    onPersist(record) {
      if (record.phase === "admitted") controller.abort();
    },
  });
  await assert.rejects(value.reader.start({ signal: controller.signal }));
  assert.ok(!value.events.includes("P"));
  assert.equal((await value.reader.close()).status, "RETAINED");
});
test("Darwin custody deadlines reject pending completion without claiming process exit", async () => {
  const child = new EventEmitter();
  child.stdin = new Writable({ write() {} });
  child.stdout = new PassThrough();
  let expire;
  const transport = darwinCustodyChannel(child, {
    deadlineMs: 390000,
    schedule(callback, delay) {
      assert.equal(delay, 390000);
      expire = callback;
    },
    cancel() {},
  });
  try {
    const completion = assert.rejects(transport.completion),
      pending = assert.rejects(transport.receive()),
      writing = assert.rejects(transport.send("P\n"));
    expire();
    await Promise.all([pending, completion, writing]);
    assert.equal(child.stdin.destroyed, true);
  } finally {
    child.emit("close", 0, null);
    child.stdin.destroy();
    child.stdout.destroy();
  }
});
test("Darwin custody completion rejects an unconsumed trailing frame", async () => {
  const child = new EventEmitter();
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  const transport = darwinCustodyChannel(child, { schedule() {}, cancel() {} });
  try {
    child.stdout.emit("data", Buffer.from('{"closed":true}\n{"extra":true}\n'));
    assert.deepEqual(await transport.receive(), { closed: true });
    child.emit("close", 0, null);
    await assert.rejects(transport.completion);
  } finally {
    transport.close();
    child.stdin.destroy();
    child.stdout.destroy();
  }
});
test("Darwin guard locations and errno remain diagnostics through failed custody", async () => {
  const chunks = [],
    guard = Buffer.from(
      "native-darwin-sdk: realpath=1 realpath-errno=0 equal=1 lstat=0 lstat-errno=0 kind=1 owner=1 writable=1\n" +
        "native-darwin-sdk-metadata: uid=0 gid=0 mode=040775 dev=1 inode=42\n" +
        "native-darwin-sdk: malformed untrusted=value\n" +
        "native-darwin-guard: file=fixture.c line=19 errno=13\n",
    );
  await withNativeDiagnostics(
    async () => {
      const child = new EventEmitter();
      child.stdin = new PassThrough();
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      const channel = darwinCustodyChannel(child, {
        schedule() {},
        cancel() {},
      });
      try {
        const pending = assert.rejects(channel.receive()),
          completion = assert.rejects(channel.completion);
        const at = guard.indexOf("file=");
        child.stderr.write(guard.subarray(0, at));
        child.stderr.write(guard.subarray(at));
        child.emit("close", 126, null);
        await Promise.all([pending, completion]);
      } finally {
        channel.close();
        child.stdin.destroy();
        child.stdout.destroy();
        child.stderr.destroy();
      }
    },
    createNativeDiagnosticWriter((bytes) => chunks.push(bytes)),
  );
  const output = Buffer.concat(chunks).toString();
  assert.ok(output.includes("native-darwin-guard"));
  assert.ok(output.includes("file=fixture.c line=19 errno=13"));
  assert.ok(output.includes("kind=1 owner=1 writable=1"));
  assert.ok(output.includes("uid=0 gid=0 mode=040775 dev=1 inode=42"));
});
