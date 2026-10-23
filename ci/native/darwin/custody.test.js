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
    ...[
      "/Library/Developer/CommandLineTools/usr/bin/clang",
      "/Library/Developer/CommandLineTools/SDKs/Fixture.sdk/SDKSettings.json",
      "/usr/bin/codesign",
    ].map((file) => ["experiment", file, "file-owner", true]),
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

test("Darwin native receipt guards bound the aggregate separately without broadening preparation admission", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    extract = (name) => {
      const body = new RegExp(
        `static [^\\n]+ ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)?.[1];
      assert.ok(body, name);
      return body;
    },
    limit = extract("preparation_receipt_limit")
      .replace("const char *leaf", "const leaf")
      .replace("leaf + 1", "leaf.slice(1)"),
    build = extract("build_receipt"),
    observe = extract("preparation_observe"),
    buildGuard =
      /need\(fd >= 0 && !fstat\(fd, &before\)[\s\S]*?\); no_acl\(fd\);/u.exec(
        build,
      )?.[0],
    admission = /need\(approved \|\| \(!directory && receipt\)\);/u.exec(
      observe,
    )?.[0],
    classify = observe.slice(
      observe.indexOf("  bool receipt ="),
      observe.indexOf("  if (receipt)"),
    ),
    preparationGuard = observe.slice(
      observe.indexOf("  if (receipt ||"),
      observe.indexOf("  char actual[65]"),
    ),
    project = (body) =>
      body
        .replaceAll(/\bbool\b/gu, "let")
        .replaceAll("const char *suffix", "const suffix")
        .replaceAll("&before", "before")
        .replaceAll(/\b0([0-7]{2,})\b/gu, "0o$1")
        .replaceAll(
          "name + strlen(report_path) + 1",
          "name.slice(report_path.length + 1)",
        );
  assert.ok(buildGuard && admission && preparationGuard);
  const prefix = `function preparation_receipt_limit(name) {${limit}}\n`;
  for (const [name, size, accepted, onlyLane] of [
    ["darwin-experiment-preparation.json", 1048577, true],
    ["darwin-experiment-preparation.json", 4194304, true],
    ["darwin-experiment-preparation.json", 4194305, false],
    ["darwin-experiment-preparation-close.json", 1048576, true],
    ["darwin-experiment-preparation-close.json", 1048577, false],
    ["darwin-experiment-preparation-extra.json", 1048577, false],
    ["provider-preparation.json", 1048576, true],
    ["provider-preparation.json", 1048577, false],
    ["darwin-input.bin", 4194305, true, "preparation"],
  ]) {
    for (const lane of ["build", "preparation"]) {
      if (onlyLane && lane !== onlyLane) continue;
      const stat = {
          st_uid: 1001,
          st_mode: 0o100400,
          st_nlink: 1,
          st_size: size,
        },
        context = {
          name: "/fixture/report/" + name,
          report_path: "/fixture/report",
          directory: false,
          approved: true,
          fd: 3,
          before: stat,
          value: { stat },
          authority: { st_uid: 1001 },
          strlen: (value) => value.length,
          strcmp: (left, right) => Number(left !== right),
          strncmp: (left, right, length) =>
            Number(left.slice(0, length) !== right.slice(0, length)),
          strchr: (value, character) =>
            value.includes(character)
              ? value.slice(value.indexOf(character))
              : null,
          strrchr: (value, character) =>
            value.includes(character)
              ? value.slice(value.lastIndexOf(character))
              : null,
          fstat: () => 0,
          S_ISREG: (mode) => (mode & 0o170000) === 0o100000,
          no_acl() {},
          need: (ok) => assert.ok(ok, "Native receipt refused"),
        },
        run = () =>
          new Script(
            prefix +
              "{\n" +
              project(
                lane === "build"
                  ? buildGuard
                  : classify + admission + preparationGuard,
              ) +
              "\n}",
          ).runInNewContext(context);
      if (accepted) run();
      else
        assert.throws(run, /Native receipt refused/, `${lane}:${name}:${size}`);
      if (lane === "build" && accepted)
        for (const [key, value] of [
          ["st_uid", 1002],
          ["st_mode", 0o100600],
          ["st_nlink", 2],
          ["st_size", 0],
        ]) {
          const previous = stat[key];
          stat[key] = value;
          assert.throws(run, /Native receipt refused/, key);
          stat[key] = previous;
        }
      if (lane === "preparation" && accepted) {
        context.approved = false;
        if (name.startsWith("provider-")) run();
        else
          assert.throws(
            run,
            /Native receipt refused/,
            "Aggregate bound must not grant admission",
          );
      }
    }
  }
});

async function boundCustodyFixture({ experiment = true } = {}) {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    header = await readFile(new URL("custody.h", import.meta.url), "utf8"),
    effective = await readFile(
      new URL("effective-reader.h", import.meta.url),
      "utf8",
    );
  const functions = [
    ["installed_cache_path", "name"],
    ["installed_input_path", "name"],
    ["experiment_installed_path", "name"],
    ["is_bootstrap_parent", "name, st"],
    ["experiment_case_parent", "name, parent, st"],
    ["same_stat", "a, b"],
    ["lease_entry", "value"],
    ["lease_guard", "value"],
    ["ancestors", "path"],
    ["stable_identity", "value"],
    ["build_guard", ""],
    ["build_entry", "value"],
    ["entry_ancestors", "value"],
    ["stable", "value"],
    ["slot", "text"],
    ["build_directory", "encoded"],
    ["build_root_open", "name"],
    ["case_directories", ""],
    ["reservation_contents", "entry"],
    ["reservation_guard", ""],
    ["reserve", "entry, nonce"],
    ["reservation_close", ""],
  ];
  const project = (body) =>
    body
      .replace(
        /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#else\n([\s\S]*?)#endif/gu,
        (_, ordinary, reviewed) => (experiment ? ordinary : reviewed),
      )
      .replace(
        "unsigned char bytes[65536];",
        "const bytes = Buffer.alloc(65536);",
      )
      .replace(
        /const char expected\[\] = ("[^\n]+");/gu,
        'const expected = Buffer.from($1 + "\\0");',
      )
      .replace(
        "char bytes[sizeof(expected) - 1];",
        "const bytes = Buffer.alloc(expected.length - 1);",
      )
      .replace("char *end;", "const end = {};")
      .replace("struct pfioc_rule rule = {0};", "const rule = {rule: {}};")
      .replaceAll("!*end", "!end.value")
      .replaceAll("*tokens[3]", "tokens[3][0]")
      .replace(
        "struct entry value = {.fd = build_root};",
        "const value = {fd: build_root, kind: {}, path: {}};",
      )
      .replace(
        "struct entry parent = {.fd = build_parent, .stat = report_identity}, root = {.fd = build_root, .stat = build_identity};",
        "const parent = {fd: build_parent, stat: report_identity}, root = {fd: build_root, stat: build_identity};",
      )
      .replace(/struct stat (\w+) = value->stat;/gu, "const $1 = value.stat;")
      .replace(
        /struct stat ([\w, ]+);/gu,
        (_, names) =>
          `const ${names
            .split(", ")
            .map((name) => `${name} = {}`)
            .join(", ")};`,
      )
      .replace(
        /char (\w+)\[(?:PATH_MAX|\d+)\](?:, (\w+)\[PATH_MAX\])?;/gu,
        (_, a, b) => `const ${a} = {}${b ? `, ${b} = {}` : ""};`,
      )
      .replace(/struct entry \*(\w+) = /gu, "const $1 = ")
      .replace(/(?:const )?char \*(\w+)/gu, "let $1")
      .replace("name + length", "name.slice(length)")
      .replaceAll("->", ".")
      .replace(/&(entries\[index\]|value\.stat|\w+)/gu, "$1")
      .replace(/\*(leaf|slash|parent) = 0/gu, "$1.truncate()")
      .replace(/\b(leaf|slash|parent|base) \+ 1\b/gu, "$1.next")
      .replace("slash != name", "slash.index !== 0")
      .replace("slash == name", "slash.index === 0")
      .replace("leaf != name", "leaf.index !== 0")
      .replaceAll("sizeof(bytes)", "bytes.length")
      .replaceAll(
        "sizeof(expected)",
        body.includes("const char expected[]") ? "expected.length" : "4096",
      )
      .replace(/sizeof\(("(?:[^"\\]|\\.)*")\)/gu, (_, literal) =>
        String(Buffer.byteLength(JSON.parse(literal)) + 1),
      )
      .replace(/sizeof\([^)]+\)/gu, "4096")
      .replace(/\b(?:unsigned|bool|int|size_t|uint64_t) /gu, "let ")
      .replace(/\(uint64_t\)/gu, "")
      .replace(/\(void\)(\w+);/gu, "void $1;")
      .replace(/\b0([0-7]{2,})\b/gu, "0o$1");
  const declarations = functions.map(([name, args]) => {
    const body = new RegExp(
      `static [^\\n]+ \\*?${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(
      name.startsWith("installed_") ||
        name === "experiment_installed_path" ||
        name === "is_bootstrap_parent" ||
        name === "experiment_case_parent"
        ? header
        : name.startsWith("reservation_") || name === "reserve"
          ? effective
          : source,
    )?.[1];
    assert.ok(body, name);
    return `function ${name}(${args}) {${project(body)}}`;
  });
  const start = source.indexOf('    } else if (!strcmp(tokens[0], "open")) {'),
    end = source.indexOf(
      '    } else if (!strcmp(tokens[0], "case-directory"))',
      start,
    ),
    open = source.slice(source.indexOf("\n", start) + 1, end),
    plan = /static void plan\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(source)[1],
    admissionStart = plan.indexOf("  need(count); free(bytes);"),
    admission = plan.slice(
      admissionStart + "  need(count); free(bytes);".length,
    ),
    readStart = source.indexOf('    } else if (!strcmp(tokens[0], "read")) {'),
    readEnd = source.indexOf(
      '    } else if (!strcmp(tokens[0], "signature"))',
      readStart,
    ),
    read = source.slice(source.indexOf("\n", readStart) + 1, readEnd);
  assert.ok(start > 0 && end > start);
  assert.ok(admissionStart > 0 && readStart > 0 && readEnd > readStart);
  const script = new Script(
    `${declarations.join("\n")} ({build_directory, case_directories, ancestors, stable, slot, reserve, reservation_guard, reservation_close, admitPlan() {${project(admission)}}, openEntry() {${project(open)}}, readEntry() {${project(read)}}});`,
  );
  const bytes = Buffer.from("generated helper bytes"),
    output = "/fixture/report/platform-build",
    file = output + "/launcher",
    text = (value) => (typeof value === "string" ? value : value.value),
    metadata = (ino, uid, gid, mode, size = 64) => ({
      st_dev: 1,
      st_ino: ino,
      st_uid: uid,
      st_gid: gid,
      st_mode: mode,
      st_nlink: (mode & 0o170000) === 0o40000 ? 2 : 1,
      st_size: size,
      st_birthtimespec: { tv_sec: ino, tv_nsec: 0 },
      st_mtimespec: { tv_sec: 1, tv_nsec: 0 },
      st_ctimespec: { tv_sec: 1, tv_nsec: 0 },
    });
  const fixture = ({ unbuilt = false } = {}) => {
    const events = [],
      nodes = new Map(),
      held = new Map();
    nodes.set("/fixture", { stat: metadata(1, 0, 0, 0o40755) });
    const parent = {
      stat: metadata(2, 1001, 20, 0o40700),
      children: new Map(),
    };
    nodes.set("/fixture/report", parent);
    let nextFd = 1;
    const env = {
      build_root: -1,
      build_parent: -1,
      build_path: {},
      report_path: {},
      build_identity: {},
      report_identity: {},
      lease_parent: -1,
      lease_base: -1,
      lease_parent_identity: {},
      lease_base_identity: {},
      lease_identity: {},
      reservation_fd: -1,
      reservation_entry: null,
      reservation_stat: {},
      case_recovery: false,
      case_mode: false,
      preparation_mode: false,
      case_path: "/private/var/run/native-poc/cases/fixture",
      count: 1,
      entries: [{ kind: "directory", path: output, pin: "-", fd: -1 }],
      n: 3,
      tokens: ["open", "1", "0"],
      encoded: output,
      errno: 0,
      ENOENT: 2,
      Buffer,
      LOCK_EX: 1,
      LOCK_NB: 2,
      build_mode: false,
      O_RDONLY: 1,
      O_DIRECTORY: 2,
      O_NOFOLLOW: 4,
      O_CLOEXEC: 8,
      O_NONBLOCK: 16,
      AT_SYMLINK_NOFOLLOW: 32,
      NULL: null,
      stderr: {},
      stdout: {},
      INT64_MAX: Number.MAX_SAFE_INTEGER,
      need(ok) {
        if (!ok) throw new Error("Native bound custody refused");
      },
      number: Number,
      strtoull(value, end) {
        end.value = "";
        return Number(value);
      },
      S_ISDIR: (mode) => (mode & 0o170000) === 0o40000,
      S_ISREG: (mode) => (mode & 0o170000) === 0o100000,
      installed_input: () =>
        assert.fail("Generated helpers are never installed inputs"),
      decode: (value, out) => {
        out.value = text(value);
      },
      strcpy: (out, value) => {
        out.value = text(value);
      },
      strlen: (value) => text(value).length,
      strspn: (value) => /^[a-f0-9]*/u.exec(text(value))[0].length,
      strcmp: (a, b) => Number(text(a) !== text(b)),
      strncmp: (a, b, size) =>
        Number(text(a).slice(0, size) !== text(b).slice(0, size)),
      strstr: (value, part) => text(value).includes(part),
      strrchr(value) {
        const index = text(value).lastIndexOf("/");
        return index < 0
          ? null
          : {
              index,
              next: text(value).slice(index + 1),
              truncate() {
                value.value = text(value).slice(0, index);
              },
            };
      },
      snprintf(out, maximum, format, value) {
        out.value = format.replace("%s", text(value));
        return out.value.length;
      },
      realpath(value, out) {
        out.value = nodes.get(text(value))?.canonical ?? text(value);
        return nodes.has(text(value));
      },
      open(value, flags) {
        assert.ok(flags & env.O_NOFOLLOW);
        const node = nodes.get(text(value));
        if (!node || node.symlink) return -1;
        const fd = nextFd++;
        held.set(fd, node);
        return fd;
      },
      openat(fd, name, flags) {
        assert.ok(flags & env.O_NOFOLLOW);
        const node = held.get(fd)?.children?.get(text(name));
        if (!node || node.symlink) return -1;
        const opened = nextFd++;
        held.set(opened, node);
        return opened;
      },
      fstat(fd, out) {
        const node = held.get(fd);
        if (!node) return -1;
        Object.assign(out, structuredClone(node.stat));
        return 0;
      },
      lstat(value, out) {
        const node = nodes.get(text(value));
        if (!node) return -1;
        Object.assign(out, structuredClone(node.stat));
        return 0;
      },
      fstatat(fd, name, out, flags) {
        assert.equal(flags, env.AT_SYMLINK_NOFOLLOW);
        const node = held.get(fd)?.children?.get(text(name));
        if (!node) {
          env.errno = env.ENOENT;
          return -1;
        }
        Object.assign(out, structuredClone(node.stat));
        return 0;
      },
      mkdirat(fd, name, mode) {
        assert.equal(held.get(fd), parent);
        assert.equal(name, "platform-build");
        const root = {
          stat: metadata(3, 0, 20, 0o40000 | mode),
          children: new Map(),
        };
        parent.children.set(name, root);
        nodes.set(output, root);
        return 0;
      },
      no_acl(fd) {
        events.push("acl");
        env.need(!held.get(fd).acl);
      },
      fchown(fd, uid, gid) {
        events.push("chown");
        Object.assign(held.get(fd).stat, { st_uid: uid, st_gid: gid });
        return 0;
      },
      fchmod(fd, mode) {
        events.push("chmod");
        held.get(fd).stat.st_mode = 0o40000 | mode;
        return 0;
      },
      sha_range(fd, offset, size, out) {
        out.value = digest(held.get(fd).bytes.subarray(offset, offset + size));
      },
      read_at(fd, out, size, offset) {
        held.get(fd).bytes.copy(out, 0, offset, offset + size);
      },
      memcmp: (a, b, size) => a.subarray(0, size).compare(b.subarray(0, size)),
      dup(fd) {
        const duplicate = nextFd++;
        held.set(duplicate, held.get(fd));
        return duplicate;
      },
      flock() {
        events.push("lock");
        return env.lockUnavailable ? -1 : 0;
      },
      no_subjects: () => events.push("subjects-absent"),
      pf_restored_guard: () => events.push("pf-restored"),
      close(fd) {
        events.push("close");
        return held.delete(fd) ? 0 : -1;
      },
      fputs() {},
      hex(value, size, out) {
        out.value = value.subarray(0, size).toString("hex");
      },
      printf(format, value) {
        if (format === '{"hex":"%s"}') env.lastRead = text(value);
      },
      wire: "",
      identity(value) {
        const s = value.stat;
        env.wire += JSON.stringify({
          identity: fileId(s.st_ino),
          bytes: 0,
          uid: s.st_uid,
          gid: s.st_gid,
          mode: s.st_mode & 0o7777,
          directory: true,
        });
      },
      fputs(value) {
        env.wire += value;
      },
      fprintf() {},
      fflush() {},
      input_refusal() {},
    };
    const native = script.runInNewContext(env);
    if (unbuilt) return { env, native, nodes, held, events, metadata };
    native.build_directory(output);
    assert.deepEqual(
      events.filter((name) => name !== "acl"),
      ["chown", "chmod"],
    );
    const root = nodes.get(output);
    root.stat.st_mode = 0o40555;
    const image = { stat: metadata(4, 0, 0, 0o100555, bytes.length), bytes };
    root.children.set("launcher", image);
    nodes.set(file, image);
    // A new consumer joins the published root without inheriting or resealing it.
    held.clear();
    nextFd = 3;
    env.build_root = env.build_parent = -1;
    env.build_identity = {};
    env.report_identity = {};
    env.build_path = {};
    env.report_path = {};
    env.case_mode = true;
    env.entries = [
      { kind: "image", path: file, pin: digest(bytes), fd: -1, stat: {} },
      env.entries[0],
    ];
    env.count = 2;
    events.length = 0;
    return { env, native, nodes, root, parent, image, events };
  };
  return { fixture, bytes, output, file };
}

test("Darwin native case directory frames retain held roles without resealing metadata", async () => {
  const { fixture } = await boundCustodyFixture();
  const f = fixture();
  f.native.admitPlan();
  f.env.wire = "";
  f.native.case_directories();
  assert.deepEqual(
    JSON.parse(f.env.wire).map(({ role, fd, object }) => [
      role,
      fd,
      object.uid,
      object.gid,
      object.mode,
    ]),
    [
      ["workspace", 3, 1001, 20, 0o700],
      ["build", 4, 0, 0, 0o555],
    ],
  );
  for (const [target, key, value] of [
    ["parent", "st_uid", 1002],
    ["parent", "st_gid", 21],
    ["parent", "st_mode", 0o40700 | 0o10],
    ["root", "st_uid", 1],
    ["root", "st_gid", 20],
    ["root", "st_mode", 0o40700],
    ["root", "st_ino", 99],
  ]) {
    const changed = fixture();
    changed.native.admitPlan();
    changed[target].stat[key] = value;
    assert.throws(
      () => changed.native.case_directories(),
      /Native bound custody refused/,
      `${target}/${key}`,
    );
    assert.ok(
      !changed.events.some((name) => ["chown", "chmod"].includes(name)),
    );
  }
});

test("Darwin generated custody joins the real build producer and consuming guards beneath a private report parent", async () => {
  const { fixture, bytes, output, file } = await boundCustodyFixture();
  const admitted = fixture();
  // This unchanged generic route reproduces the original successful-lstat refusal.
  assert.throws(
    () => admitted.native.ancestors(file),
    /Native bound custody refused/u,
  );
  admitted.native.admitPlan();
  admitted.native.openEntry();
  assert.equal(admitted.native.slot("0").path, file);
  admitted.env.n = 5;
  admitted.env.tokens = ["read", "2", "0", "0", String(bytes.length)];
  admitted.native.readEntry();
  assert.equal(admitted.env.lastRead, bytes.toString("hex"));
  assert.deepEqual(
    admitted.events.filter((name) => name !== "acl"),
    [],
  );
  const replaced = fixture();
  replaced.native.admitPlan();
  const replacement = {
    ...replaced.root,
    stat: { ...replaced.root.stat, st_ino: 30 },
  };
  replaced.nodes.set(output, replacement);
  replaced.parent.children.set("platform-build", replacement);
  assert.throws(
    () => replaced.native.openEntry(),
    /Native bound custody refused/u,
  );
  const preparation = fixture();
  preparation.env.case_mode = false;
  preparation.env.preparation_mode = true;
  preparation.env.report_path.value = "/fixture/report";
  preparation.native.admitPlan();
  preparation.native.openEntry();
  assert.equal(preparation.native.slot("0").path, file);
  assert.deepEqual(
    preparation.events.filter((name) => name !== "acl"),
    [],
  );
  for (const fault of [
    "root",
    "file",
    "parent-birth",
    "root-birth",
    "root-acl",
    "file-acl",
  ]) {
    const f = fixture();
    f.native.openEntry();
    if (fault === "root") {
      const replacement = { ...f.root, stat: { ...f.root.stat, st_ino: 30 } };
      f.nodes.set(output, replacement);
      f.parent.children.set("platform-build", replacement);
    } else if (fault === "file") {
      const replacement = { ...f.image, stat: { ...f.image.stat, st_ino: 40 } };
      f.nodes.set(file, replacement);
      f.root.children.set("launcher", replacement);
    } else if (fault === "parent-birth")
      f.parent.stat.st_birthtimespec.tv_sec++;
    else if (fault === "root-birth") f.root.stat.st_birthtimespec.tv_sec++;
    else if (fault === "root-acl") f.root.acl = true;
    else f.image.acl = true;
    assert.throws(
      () => f.native.slot("0"),
      /Native bound custody refused/u,
      fault,
    );
  }
  for (const fault of [
    "wrong-root",
    "wrong-pin",
    "unrelated",
    "prefix",
    "alias",
    "writable",
    "links",
    "preparation-binding",
  ]) {
    const f = fixture();
    if (fault === "wrong-root") f.env.entries[1].path += "-other";
    else if (fault === "wrong-pin") f.env.entries[0].pin = "e".repeat(64);
    else if (fault === "unrelated") {
      f.env.entries[0].path = "/fixture/report/launcher";
      f.nodes.set(f.env.entries[0].path, f.image);
    } else if (fault === "prefix") {
      const other = output + "-other";
      f.env.entries[0].path = other + "/launcher";
      f.nodes.set(other, { stat: { ...f.root.stat, st_ino: 30 } });
      f.nodes.set(f.env.entries[0].path, f.image);
    } else if (fault === "alias") f.image.canonical = "/fixture/other/launcher";
    else if (fault === "writable") f.root.stat.st_mode = 0o40777;
    else if (fault === "links") f.image.stat.st_nlink = 2;
    else {
      f.env.case_mode = false;
      f.env.preparation_mode = true;
      f.env.report_path.value = "/fixture/wrong-report";
    }
    assert.throws(
      () => f.native.openEntry(),
      /Native bound custody refused/u,
      fault,
    );
  }

  const caseRoot = "/private/var/run/native-poc/cases/" + "a".repeat(64),
    launcher = caseRoot + "/custody/launcher",
    run = "/private/var/run",
    reviewed = await boundCustodyFixture({ experiment: false }),
    refused = /Native bound custody refused/u;
  const hosted = (make = fixture, target = launcher) => {
    const f = make({ unbuilt: true });
    let parent = "";
    for (const component of target.split("/").slice(1, -1)) {
      parent += "/" + component;
      const mode =
        parent === run ? 0o775 : parent.length < run.length ? 0o755 : 0o700;
      f.nodes.set(parent, {
        stat: f.metadata(
          f.nodes.size + 10,
          0,
          parent === run ? 1 : 0,
          0o40000 | mode,
        ),
      });
    }
    f.image = {
      stat: f.metadata(100, 0, 0, 0o100555, bytes.length),
      bytes,
    };
    f.nodes.set(target, f.image);
    f.env.entries = [
      { kind: "image", path: target, pin: digest(bytes), fd: -1, stat: {} },
    ];
    f.env.count = 1;
    f.env.encoded = target;
    return f;
  };
  const ordinary = hosted();
  ordinary.native.ancestors(caseRoot);
  ordinary.native.ancestors(caseRoot + "/custody");
  ordinary.native.ancestors(launcher);
  ordinary.native.admitPlan();
  ordinary.native.openEntry();
  ordinary.env.n = 5;
  ordinary.env.tokens = ["read", "2", "0", "0", String(bytes.length)];
  ordinary.native.readEntry();
  assert.equal(ordinary.env.lastRead, bytes.toString("hex"));
  assert.deepEqual(
    ordinary.events.filter((name) => name !== "acl"),
    [],
  );

  const privateRead = hosted(reviewed.fixture);
  assert.throws(() => privateRead.native.ancestors(launcher), refused);
  privateRead.nodes.get(run).stat.st_mode = 0o40755;
  privateRead.native.ancestors(launcher);
  for (const parent of [
    "/private",
    "/private/var",
    run + "/native-poc",
    run + "/native-poc/cases",
    caseRoot,
    caseRoot + "/custody",
  ]) {
    const f = hosted();
    f.nodes.get(parent).stat.st_mode = 0o40775;
    assert.throws(() => f.native.ancestors(launcher), refused, parent);
  }
  for (const [key, value] of [
    ["st_uid", 501],
    ["st_mode", 0o40777],
    ["st_mode", 0o42775],
    ["st_mode", 0o120775],
  ]) {
    const f = hosted();
    f.nodes.get(run).stat[key] = value;
    assert.throws(
      () => f.native.ancestors(launcher),
      refused,
      `${key}/${value}`,
    );
  }
  for (const target of [
    run + "/native-poc/cases-other/" + "a".repeat(64) + "/custody/launcher",
    caseRoot + "b/custody/launcher",
    caseRoot + "g/custody/launcher",
    caseRoot.slice(0, -1) + "/custody/launcher",
    caseRoot.slice(0, -64) + "A".repeat(64) + "/custody/launcher",
    run + "/unrelated/launcher",
  ]) {
    const f = hosted(fixture, target);
    assert.throws(() => f.native.ancestors(target), refused, target);
  }
  for (const fault of ["alias", "symlink", "replacement"]) {
    const f = hosted();
    if (fault === "alias") f.image.canonical = caseRoot + "/other";
    else if (fault === "symlink") f.image.symlink = true;
    else {
      f.native.openEntry();
      f.nodes.set(launcher, {
        ...f.image,
        stat: { ...f.image.stat, st_ino: 101 },
      });
    }
    assert.throws(
      () =>
        fault === "replacement" ? f.native.slot("0") : f.native.openEntry(),
      refused,
      fault,
    );
  }
});

test("Darwin fixed PF lease joins its exclusive producer through admission, open, stability and reservation", async () => {
  const source = await readFile(
      new URL("experiment-inputs.js", import.meta.url),
      "utf8",
    ),
    provisioning = await readFile(
      new URL("case-provisioning.js", import.meta.url),
      "utf8",
    ),
    start = source.indexOf(
      "  for (const directory of [",
      source.indexOf("// Create only the fixed"),
    ),
    end = source.indexOf("  const publish =", start),
    leaseStart = source.indexOf("  const leaseSource =", end),
    leaseEnd = source.indexOf("  const volumeSource =", leaseStart);
  assert.ok(
    start > 0 && end > start && leaseStart > end && leaseEnd > leaseStart,
  );
  const publish = new Script(
      `(async () => {${source.slice(start, end)}${source.slice(leaseStart, leaseEnd)}})();`,
    ),
    ordinary = await boundCustodyFixture(),
    reviewed = await boundCustodyFixture({ experiment: false }),
    leasePath = JSON.parse(/const lease = ("[^"]+");/u.exec(provisioning)[1]),
    basePath = leasePath.slice(0, leasePath.lastIndexOf("/")),
    declaration = new Script(
      `(${/entries.push\(\s*(\{\s*kind: "data",\s*path: lease,[\s\S]*?\})/u.exec(provisioning)[1]})`,
    ).runInNewContext({ lease: leasePath, digest }),
    contents = Buffer.from("native-poc-pf-lease-v1\n"),
    refused = /Native bound custody refused/u;
  const fixture = async ({ experiment = true, recovery = false } = {}) => {
    const f = (experiment ? ordinary : reviewed).fixture({ unbuilt: true }),
      { env, nodes, metadata, events } = f,
      staged = new Map(),
      parent = { stat: metadata(10, 0, 1, 0o40775), children: new Map() };
    nodes.set("/private", { stat: metadata(8, 0, 0, 0o40755) });
    nodes.set("/private/var", { stat: metadata(9, 0, 0, 0o40755) });
    nodes.set("/private/var/run", parent);
    let ino = 11;
    await publish.runInNewContext({
      staging: "/fixture/staging",
      path: { join: (directory, name) => directory + "/" + name },
      fs: {
        async writeFile(name, bytes, options) {
          assert.deepEqual({ ...options }, { flag: "wx", mode: 0o400 });
          assert.ok(!staged.has(name));
          staged.set(name, Buffer.from(bytes));
        },
      },
      async run(binary, args) {
        assert.equal(binary, "/usr/bin/sudo");
        assert.deepEqual(Array.from(args.slice(0, 2)), ["-n", "--"]);
        const name = args.at(-1),
          parent = nodes.get(name.slice(0, name.lastIndexOf("/"))),
          leaf = name.slice(name.lastIndexOf("/") + 1);
        if (args[2] === "/bin/mkdir") {
          assert.deepEqual(Array.from(args.slice(3, 5)), ["-m", "0711"]);
          assert.ok(!nodes.has(name), "Private publication must be exclusive");
          const node = {
            stat: metadata(ino++, 0, parent.stat.st_gid, 0o40711),
            children: new Map(),
          };
          nodes.set(name, node);
          parent.children.set(leaf, node);
        } else if (args[2] === "/usr/sbin/chown") {
          assert.equal(args[3], "0:0");
          Object.assign(nodes.get(name).stat, { st_uid: 0, st_gid: 0 });
        } else {
          assert.deepEqual(Array.from(args.slice(2, 9)), [
            "/usr/bin/install",
            "-o",
            "0",
            "-g",
            "0",
            "-m",
            "0400",
          ]);
          assert.ok(!parent.children.has(leaf));
          const bytes = staged.get(args[9]),
            node = {
              stat: metadata(ino++, 0, 0, 0o100400, bytes.length),
              bytes,
            };
          nodes.set(name, node);
          parent.children.set(leaf, node);
        }
        events.push(args[2]);
      },
    });
    assert.deepEqual(events, [
      "/bin/mkdir",
      "/usr/sbin/chown",
      "/bin/mkdir",
      "/usr/sbin/chown",
      "/usr/bin/install",
    ]);
    const entry = {
      kind: declaration.kind,
      path: declaration.path,
      pin: declaration.sha256,
      fd: -1,
      stat: {},
    };
    Object.assign(env, {
      case_mode: true,
      case_recovery: recovery,
      entries: [entry],
      count: 1,
    });
    events.length = 0;
    return {
      ...f,
      entry,
      parent,
      base: nodes.get(basePath),
      lease: nodes.get(leasePath),
    };
  };
  const open = (f) => {
      f.native.admitPlan();
      f.native.openEntry();
    },
    reserve = (f) => f.native.reserve(f.entry, "a".repeat(32));
  for (const recovery of [false, true]) {
    const f = await fixture({ recovery });
    // Reproduce the original successful-lstat refusal without weakening it.
    assert.throws(() => f.native.ancestors(leasePath), refused);
    open(f);
    assert.equal(f.native.slot("0"), f.entry);
    reserve(f);
    f.native.reservation_guard();
    assert.deepEqual(f.lease.bytes, contents);
    assert.equal(
      f.base.stat.st_gid,
      0,
      "Only the producer normalizes inherited GID",
    );
    assert.equal(f.events.includes("subjects-absent"), !recovery);
    assert.ok(
      f.events.every((event) =>
        ["acl", "lock", "subjects-absent"].includes(event),
      ),
    );
    f.events.length = 0;
    f.native.reservation_close();
    assert.equal(f.env.reservation_fd, -1);
    assert.ok(
      f.events.indexOf("subjects-absent") < f.events.indexOf("pf-restored"),
    );
    assert.ok(f.events.indexOf("pf-restored") < f.events.indexOf("close"));
  }
  for (const stage of ["admitted", "opened", "reserved"])
    for (const target of ["parent", "base", "lease"]) {
      const f = await fixture();
      f.native.admitPlan();
      if (stage !== "admitted") f.native.openEntry();
      if (stage === "reserved") reserve(f);
      const replacement = {
        ...f[target],
        stat: { ...f[target].stat, st_ino: 99 },
      };
      if (target === "parent") f.nodes.set("/private/var/run", replacement);
      if (target === "base") f.parent.children.set("native-poc", replacement);
      if (target === "lease") {
        f.base.children.set("pf-lease", replacement);
        f.nodes.set(leasePath, replacement);
      }
      assert.throws(
        () =>
          stage === "admitted"
            ? f.native.openEntry()
            : stage === "opened"
              ? f.native.slot("0")
              : f.native.reservation_guard(),
        refused,
        `${stage}/${target}`,
      );
    }
  for (const fault of [
    "kind",
    "pin",
    "content",
    "size",
    "owner",
    "group",
    "mode",
    "links",
    "base-owner",
    "base-group",
    "base-mode",
    "base-acl",
    "lease-acl",
    "parent-birth",
    "base-birth",
    "lease-birth",
    "canonical",
    "parent-owner",
    "parent-mode",
    "prefix",
    "near-miss",
    "lock",
  ]) {
    const f = await fixture();
    open(f);
    reserve(f);
    if (fault === "kind") f.entry.kind = "image";
    if (fault === "pin") f.entry.pin = "e".repeat(64);
    if (fault === "content") f.lease.bytes[0] ^= 1;
    if (fault === "size") f.lease.stat.st_size++;
    if (fault === "owner") f.lease.stat.st_uid = 501;
    if (fault === "group") f.lease.stat.st_gid = 1;
    if (fault === "mode") f.lease.stat.st_mode = 0o100600;
    if (fault === "links") f.lease.stat.st_nlink = 2;
    if (fault === "base-owner") f.base.stat.st_uid = 501;
    if (fault === "base-group") f.base.stat.st_gid = 1;
    if (fault === "base-mode") f.base.stat.st_mode = 0o40775;
    if (fault === "base-acl") f.base.acl = true;
    if (fault === "lease-acl") f.lease.acl = true;
    if (fault === "parent-birth") f.parent.stat.st_birthtimespec.tv_sec++;
    if (fault === "base-birth") f.base.stat.st_birthtimespec.tv_sec++;
    if (fault === "lease-birth") f.lease.stat.st_birthtimespec.tv_sec++;
    if (fault === "parent-owner") f.parent.stat.st_uid = 501;
    if (fault === "parent-mode") f.parent.stat.st_mode = 0o40777;
    if (fault === "canonical") f.lease.canonical = basePath + "/other";
    if (["prefix", "near-miss"].includes(fault)) {
      f.entry.path =
        fault === "prefix"
          ? basePath + "-other/pf-lease"
          : leasePath + "-other";
      f.nodes.set(f.entry.path, f.lease);
      f.nodes.set(basePath + "-other", f.base);
    }
    if (fault === "lock") f.env.lockUnavailable = true;
    assert.throws(() => f.native.reservation_guard(), refused, fault);
    assert.ok(f.env.reservation_fd >= 0, "Failure must retain exclusion");
  }
  const corrupt = await fixture();
  corrupt.lease.bytes[0] ^= 1;
  corrupt.native.admitPlan();
  assert.throws(() => corrupt.native.openEntry(), refused);
  for (const target of ["base", "lease"]) {
    const f = await fixture();
    f[target].symlink = true;
    f[target].stat.st_mode = 0o120777;
    assert.throws(() => open(f), refused, `${target} symlink`);
  }
  for (const experiment of [false, true]) {
    const f = await fixture({ experiment });
    if (experiment) f.env.case_mode = false;
    assert.throws(() => f.native.admitPlan(), refused);
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
  caseContextSha256,
  caseRead,
  directoryBindings,
  onProbe,
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
    planRead = false,
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
    if (["--probe", "--probe-domain"].includes(args[0])) {
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
              pid === 20 && caseContextSha256 && planRead
                ? caseDirectoryBindings().map(({ fd, object }) => ({
                    fd,
                    dev: object.identity.split(":")[0],
                    ino: object.identity.split(":")[3],
                    uid: object.uid,
                    gid: object.gid,
                    mode: object.mode,
                  }))
                : pid === 30
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
        receive: async () => {
          await onProbe?.(subject, pid);
          return {
            verifier: identity(40),
            subject,
            ...(args[0] === "--probe-domain"
              ? {
                  enumeration: {
                    uid: failure === "census-uid" ? 1002 : 1001,
                    asid: Number(args[4]),
                    scope: Number(args[4]) ? "audit-session" : "reserved-uid",
                    complete: failure !== "incomplete-census",
                    capacity: failure === "census-capacity" ? 32 : 33,
                    live: [],
                    zombies: [],
                  },
                }
              : {}),
          };
        },
        completion: Promise.resolve({ code: 0, signal: null }),
        close() {},
      };
    }
    return {
      async send(line) {
        events.push(line.trim());
        if (line === "P\n") {
          planRead = true;
          frames.push({
            ...(purpose === "experiment" && failure !== "purpose"
              ? { purpose }
              : {}),
            candidateSha,
            entries: 4,
            uid: 1001,
            gid: 1002,
            ...(caseContextSha256
              ? { directories: caseDirectoryBindings() }
              : {}),
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
        if (op === "case-read") value = structuredClone(caseRead);
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
  const caseDirectoryBindings = () => [
    {
      role: "workspace",
      fd: 3,
      object: { ...object(1), uid: 701, gid: 32 },
    },
    { role: "build", fd: 4, object: { ...object(2), mode: 0o555 } },
  ];
  const reader = createDarwinCustodyReader(selectedInput, {
    entries,
    caseContextSha256,
    directoryBindings,
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
test("Darwin case directory roles bind prepared ownership and sealed builds through independent closure", async () => {
  for (const directoryBindings of [null, false, 0, ""]) {
    assert.throws(() =>
      fixture({ caseContextSha256: hash, directoryBindings }),
    );
  }
  for (const purpose of ["reviewed", "experiment"]) {
    const f = fixture({ purpose, caseContextSha256: hash });
    await f.reader.start();
    const bindings = f.receipts.find(
      ({ phase }) => phase === "directories-bound",
    ).request.directories;
    assert.deepEqual(
      bindings.map(({ role, fd, object: { uid, gid, mode } }) => ({
        role,
        fd,
        uid,
        gid,
        mode,
      })),
      [
        { role: "workspace", fd: 3, uid: 701, gid: 32, mode: 0o700 },
        { role: "build", fd: 4, uid: 0, gid: 0, mode: 0o555 },
      ],
    );
    const observation = await f.reader.verifyOwnership(0);
    assert.equal(observation.subject.directories.length, 2);
    assert.equal((await f.reader.close()).status, "RETIRED");
    const fresh = fixture({
      purpose,
      caseContextSha256: hash,
      directoryBindings: bindings,
    });
    await fresh.reader.start();
    assert.equal((await fresh.reader.close()).status, "RETIRED");
    for (const key of ["identity", "uid", "gid", "mode"]) {
      const original = structuredClone(bindings);
      if (key === "identity") original[0].object.identity = fileId(99);
      else if (key === "mode") original[0].object.mode = 0o710;
      else original[0].object[key]++;
      const construct = () =>
        fixture({
          purpose,
          caseContextSha256: hash,
          directoryBindings: original,
        });
      if (key === "mode") assert.throws(construct);
      else
        await assert.rejects(
          construct().reader.start(),
          /admission unavailable/,
        );
    }
  }
});

test("Darwin directory probes reject incomplete, swapped, aliased and changed held roles", async () => {
  for (const fault of [
    "missing",
    "duplicate",
    "extra",
    "swapped",
    "aliased",
    "device",
    "inode",
    "workspace-owner",
    "workspace-group",
    "workspace-mode",
    "build-owner",
    "build-group",
    "build-mode",
  ]) {
    let damaged = false;
    const f = fixture({
      purpose: "experiment",
      caseContextSha256: hash,
      onProbe(subject) {
        if (
          !damaged ||
          subject.status !== "live" ||
          !subject.directories.length
        )
          return;
        const directories = subject.directories;
        if (fault === "missing") directories.pop();
        else if (fault === "duplicate") directories[1] = { ...directories[0] };
        else if (fault === "extra")
          directories.push({ ...directories[0], fd: 5 });
        else if (fault === "swapped")
          [directories[0].fd, directories[1].fd] = [4, 3];
        else if (fault === "aliased") directories[1].ino = directories[0].ino;
        else if (fault === "device") directories[0].dev = "2";
        else if (fault === "inode") directories[1].ino = "99";
        else {
          const [role, key] = fault.split("-"),
            directory = directories[role === "workspace" ? 0 : 1];
          directory[{ owner: "uid", group: "gid", mode: "mode" }[key]]++;
        }
      },
    });
    await f.reader.start();
    damaged = true;
    await assert.rejects(f.reader.verifyOwnership(0), /Unverified/, fault);
    assert.equal((await f.reader.close()).status, "RETAINED", fault);
    assert.ok(!f.events.some((event) => event.startsWith("finish ")), fault);
  }
  const live = fixture({ caseContextSha256: hash, failure: "live-retirement" });
  await live.reader.start();
  assert.equal(
    (await live.reader.verifyOwnership(0)).enumeration.live.length,
    0,
  );
  assert.equal((await live.reader.close()).status, "RETAINED");
  for (const failure of [
    "incomplete-census",
    "census-uid",
    "census-capacity",
  ]) {
    const f = fixture({ caseContextSha256: hash, failure });
    await f.reader.start();
    await assert.rejects(f.reader.verifyOwnership(0), /Unverified/);
    assert.equal((await f.reader.close()).status, "RETAINED");
  }
});

test("Darwin native case admission censuses numeric identities without borrowing reviewed accounts", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    launcher = await readFile(new URL("launcher.c", import.meta.url), "utf8"),
    start = source.indexOf("static struct case_accounts case_account(void) {"),
    body = source.slice(start, source.indexOf("static bool git_path", start)),
    wireStart = source.indexOf(
      '  printf("{"',
      source.indexOf("static void case_read(void)"),
    ),
    wire = source.slice(
      wireStart,
      source.indexOf("  unsigned emitted", wireStart),
    ),
    verifyStart = launcher.indexOf(
      "    uid_t uid = number(argv[2]);",
      launcher.indexOf('"--verify-inputs"'),
    ),
    verify = launcher.slice(
      verifyStart,
      launcher.indexOf("    struct stat image;", verifyStart),
    );
  assert.ok(
    start > 0 &&
      wireStart > 0 &&
      verifyStart > 0 &&
      body.includes("return accounts;"),
  );
  // Retain the native predicates and loops; translate only C declarations,
  // conditional compilation and output pointers for injected libc coverage.
  const project = (text, experiment) =>
    text
      .replace(
        /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#else\n([\s\S]*?)#endif/gu,
        (_, ordinary, reviewed) => (experiment ? ordinary : reviewed),
      )
      .replace(
        /#ifndef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#endif/gu,
        (_, reviewed) => (experiment ? "" : reviewed),
      )
      .replace(
        "static struct case_accounts case_account(void)",
        "function case_account()",
      )
      .replace(
        "struct case_accounts accounts = {0}",
        "const accounts = {uid_accounts: 0, primary_members: 0, gid_groups: 0}",
      )
      .replace("char home[PATH_MAX]", "const home = []")
      .replace(
        "gid_t groups[2]; int count = 2",
        "const groups = []; const count = {value: 2}",
      )
      .replaceAll("&count", "count")
      .replaceAll("count == 1", "count.value == 1")
      .replaceAll("sizeof(home)", "4096")
      .replace(/\b0700\b/gu, "0o700")
      .replace(/struct (?:passwd|group) \*/gu, "let ")
      .replace(/const unsigned /gu, "const ")
      .replace(/\b(?:unsigned|bool|int|uid_t|gid_t) /gu, "let ")
      .replaceAll("->", ".");
  const uid = 90001,
    gid = 90002,
    home = "/fixture/case/storage/work";
  const account = () => ({
    pw_uid: uid,
    pw_gid: gid,
    pw_name: "case-user",
    pw_shell: "/usr/bin/false",
    pw_passwd: "*",
    pw_dir: home,
  });
  for (const experiment of [false, true]) {
    const script = new Script(`${project(body, experiment)} case_account;`),
      emit = new Script(
        project(wire, experiment).replace(/"\s*\n\s*"/gu, '" + "'),
      ),
      verifier = new Script(`() => {${project(verify, experiment)}}`);
    for (const fault of [
      null,
      "uid",
      "uid-alias",
      "primary",
      "group",
      "group-alias",
      "passwd-error",
      "group-error",
      "passwd-bound",
      "group-bound",
      "reservation",
      "missing",
      "shell",
      "password",
      "home",
      "members",
      "supplementary",
      "account-gid",
      "group-id",
      "census-gid",
      "census-members",
    ]) {
      const pw = account(),
        gr = { gr_gid: gid, gr_mem: [null] },
        unrelated = { pw_uid: 501, pw_gid: 20 },
        users = experiment ? [unrelated] : [unrelated, account()],
        groups = experiment
          ? [{ gr_gid: 20 }]
          : [{ gr_gid: 20 }, { gr_gid: gid, gr_mem: [null] }],
        events = [],
        refusals = [];
      if (fault === "uid") users.push({ ...account(), pw_gid: 20 });
      if (fault === "uid-alias") users.push(account());
      if (fault === "primary") users.push({ pw_uid: 502, pw_gid: gid });
      if (fault === "group") groups.push({ gr_gid: gid, gr_mem: ["other"] });
      if (fault === "group-alias") groups.push({ gr_gid: gid, gr_mem: [null] });
      if (fault === "passwd-bound") users.push(...Array(4096).fill(unrelated));
      if (fault === "group-bound")
        groups.push(...Array(4096).fill({ gr_gid: 20 }));
      if (fault === "shell") pw.pw_shell = "/bin/sh";
      if (fault === "password") pw.pw_passwd = "unlocked";
      if (fault === "home") pw.pw_dir = "/fixture/other";
      if (fault === "account-gid") pw.pw_gid++;
      if (fault === "group-id") gr.gr_gid++;
      if (fault === "members") gr.gr_mem = ["other"];
      if (!experiment && fault === "census-gid") users[1].pw_gid++;
      if (!experiment && fault === "census-members")
        groups[1].gr_mem = ["other"];
      let userIndex = 0,
        groupIndex = 0;
      const env = {
        subject_uid: uid,
        subject_gid: gid,
        case_path: "/fixture/case",
        uid,
        gid,
        argv: [null, null, String(uid), String(gid), home],
        errno: 0,
        stderr: {},
        number: Number,
        reservation_guard() {
          events.push("reservation");
          assert.notEqual(fault, "reservation", "Case refused");
        },
        getpwuid() {
          events.push("lookup-user");
          return fault === "missing" ? null : pw;
        },
        getgrgid() {
          events.push("lookup-group");
          return gr;
        },
        snprintf(out, _size, _format, root) {
          out[0] = root + "/storage/work";
          return out[0].length;
        },
        strcmp: (a, b) =>
          Number(
            (Array.isArray(a) ? a[0] : a) !== (Array.isArray(b) ? b[0] : b),
          ),
        getgrouplist(_name, _gid, out, count) {
          out[0] = gid;
          count.value = fault === "supplementary" ? 2 : 1;
          return 0;
        },
        setpwent() {
          events.push("passwd-start");
        },
        getpwent() {
          if (userIndex < users.length) return users[userIndex++];
          env.errno = fault === "passwd-error" ? 5 : 0;
          return null;
        },
        endpwent() {
          events.push("passwd-end");
        },
        setgrent() {
          events.push("group-start");
        },
        getgrent() {
          if (groupIndex < groups.length) return groups[groupIndex++];
          env.errno = fault === "group-error" ? 5 : 0;
          return null;
        },
        endgrent() {
          events.push("group-end");
        },
        fprintf(_fd, _format, ...counts) {
          refusals.push(counts);
        },
        directory(file, actualUid, actualGid, mode) {
          assert.deepEqual(
            [file, actualUid, actualGid, mode],
            [home, uid, gid, 0o700],
          );
          events.push("workspace");
          return 9;
        },
        close(fd) {
          assert.equal(fd, 9);
          return 0;
        },
        need(ok) {
          assert.ok(ok, "Case refused");
        },
      };
      const read = script.runInNewContext(env),
        reviewedFault = [
          "missing",
          "shell",
          "password",
          "home",
          "members",
          "supplementary",
          "account-gid",
          "group-id",
          "census-gid",
          "census-members",
        ].includes(fault),
        rejected = fault && (!reviewedFault || !experiment);
      if (rejected)
        assert.throws(read, /Case refused/, `${experiment}/${fault}`);
      else {
        const accounts = { ...read() };
        assert.deepEqual(accounts, {
          uid_accounts: experiment ? 0 : 1,
          primary_members: experiment ? 0 : 1,
          gid_groups: experiment ? 0 : 1,
        });
        assert.ok(
          events.includes("passwd-end") && events.includes("group-end"),
        );
        let output;
        emit.runInNewContext({
          ...env,
          accounts,
          case_context: hash,
          printf(format, ...args) {
            output = format.replace(/%[su]/gu, () => String(args.shift()));
          },
        });
        const actual = JSON.parse(output + '],"endpoints":[]}');
        assert.deepEqual(actual, {
          ...(experiment ? { purpose: "experiment" } : {}),
          contextSha256: hash,
          uid,
          gid,
          accountVerified: !experiment,
          accounts: {
            uidAccounts: accounts.uid_accounts,
            primaryGroupMembers: accounts.primary_members,
            gidGroups: accounts.gid_groups,
          },
          objects: [],
          endpoints: [],
        });
      }
      if (experiment)
        assert.ok(!events.some((event) => event.startsWith("lookup-")));
      if (experiment && ["uid", "primary", "group"].includes(fault))
        assert.deepEqual(refusals[0], [
          0,
          Number(fault === "uid"),
          Number(fault === "primary"),
          Number(fault === "group"),
        ]);
      if (
        [
          null,
          "missing",
          "shell",
          "password",
          "home",
          "members",
          "account-gid",
        ].includes(fault)
      ) {
        // The launch verifier checks the actual private workspace in experiment
        // builds and retains every reviewed login predicate in reviewed builds.
        const run = verifier.runInNewContext(env);
        if (!experiment && fault) assert.throws(run, /Case refused/);
        else run();
      }
    }
  }
});

test("Darwin launcher numeric credentials retain primary-only groups and every saved identity check", async () => {
  const launcher = await readFile(
      new URL("launcher.c", import.meta.url),
      "utf8",
    ),
    start = launcher.indexOf("    need(!setgroups(0, NULL));"),
    drop = launcher.slice(start, launcher.indexOf("    char *error", start)),
    credentials = /    need\(identity\.bsd\.pbi_uid == uid[\s\S]*?;\n/u.exec(
      launcher,
    )?.[0];
  assert.ok(start > 0 && credentials);
  const script = new Script(
    `() => {${drop}
    ${credentials}}`
      .replace("gid_t only", "const only = {value: 0}")
      .replaceAll("&only", "only")
      .replaceAll("only == gid", "only.value == gid")
      .replaceAll("&observed", "observed")
      .replaceAll("NULL", "null")
      .replaceAll("(unsigned)", ""),
  );
  for (const fault of [
    null,
    "setgroups",
    "setgid",
    "setuid",
    "groups",
    "primary",
    "pbi_uid",
    "pbi_ruid",
    "pbi_svuid",
    "pbi_gid",
    "pbi_rgid",
    "pbi_svgid",
  ]) {
    const uid = 90001,
      gid = 90002,
      events = [],
      bsd = Object.fromEntries(
        [
          "pbi_uid",
          "pbi_ruid",
          "pbi_svuid",
          "pbi_gid",
          "pbi_rgid",
          "pbi_svgid",
        ].map((key) => [key, key.includes("uid") ? uid : gid]),
      );
    if (Object.hasOwn(bsd, fault)) bsd[fault] = 0;
    const run = script.runInNewContext({
      uid,
      gid,
      identity: { bsd, token: { val: [uid, 0, 0, 0, 0, 0, 17] } },
      audit: { ai_asid: 17 },
      observed: {},
      RLIMIT_NPROC: 7,
      launch_stage() {},
      setgroups(count, groups) {
        assert.equal(count, 0);
        assert.equal(groups, null);
        events.push("setgroups");
        return fault === "setgroups" ? -1 : 0;
      },
      setgid(value) {
        assert.equal(value, gid);
        events.push("setgid");
        return fault === "setgid" ? -1 : 0;
      },
      setuid(value) {
        assert.equal(value, uid);
        events.push("setuid");
        return fault === "setuid" ? -1 : 0;
      },
      getgroups(capacity, only) {
        assert.equal(capacity, 1);
        only.value = fault === "primary" ? 0 : gid;
        return fault === "groups" ? -1 : 1;
      },
      getrlimit(_kind, observed) {
        observed.rlim_cur = observed.rlim_max = 32;
        return 0;
      },
      need(ok) {
        assert.ok(ok, "Credential refusal");
      },
    });
    if (fault) assert.throws(run, /Credential refusal/, fault);
    else {
      run();
      assert.deepEqual(events, ["setgroups", "setgid", "setuid"]);
    }
  }
});

test("Darwin case reads bind numeric and reviewed censuses to the admitted purpose", async () => {
  for (const purpose of ["experiment", "reviewed"]) {
    const expected = purpose === "experiment" ? 0 : 1;
    for (const fault of [
      null,
      "purpose",
      "verification",
      "uidAccounts",
      "primaryGroupMembers",
      "gidGroups",
      "other-census",
    ]) {
      const caseRead = {
        ...(purpose === "experiment" ? { purpose } : {}),
        contextSha256: hash,
        uid: 1001,
        gid: 1002,
        accountVerified: purpose === "reviewed",
        accounts: {
          uidAccounts: expected,
          primaryGroupMembers: expected,
          gidGroups: expected,
        },
        objects: [],
        endpoints: [],
      };
      if (fault === "purpose") {
        if (purpose === "experiment") delete caseRead.purpose;
        else caseRead.purpose = "experiment";
      }
      if (fault === "verification")
        caseRead.accountVerified = !caseRead.accountVerified;
      if (Object.hasOwn(caseRead.accounts, fault)) caseRead.accounts[fault]++;
      if (fault === "other-census")
        for (const key of Object.keys(caseRead.accounts))
          caseRead.accounts[key] = 1 - expected;
      const f = fixture({ purpose, caseRead, caseContextSha256: hash });
      await f.reader.start();
      if (fault) await assert.rejects(f.reader.readCase());
      else assert.deepEqual(await f.reader.readCase(), caseRead);
    }
  }
});

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
test("Darwin ownership launch bodies preserve setup and handshake causes on the original diagnostic channel", async () => {
  const [reader, launcher] = await Promise.all(
    ["custody-reader.c", "launcher.c"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const body = (source, name) =>
    new RegExp(
      `static (?:void|char|struct identity) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const translate = (text) =>
    text
      .replace(
        "struct proc_bsdinfo identity = {0}; siginfo_t status = {0};",
        "let identity={};const status={si_pid:0,si_code:0,si_status:0};",
      )
      .replace(
        /struct pollfd (\w+) = \{\s*\.fd = ([^,]+), \.events = POLLIN\s*\};/gu,
        "const $1={fd:$2,events:POLLIN,revents:0};",
      )
      .replace("struct identity parked;", "const parked={token:{val:[]}};")
      .replace("char bytes[512];", "const bytes={};")
      .replace(
        "struct sigaction ignored = {0}, previous;",
        "const ignored={sa_mask:{}},previous={};",
      )
      .replaceAll(/&(ignored(?:\.sa_mask)?|previous)\b/gu, "$1")
      .replace(
        "char bytes[8192]; unsigned length = 0;",
        "const bytes=[]; let length=0;",
      )
      .replace("char out[16385];", "const out={};")
      .replace(/char (byte|value);/gu, "const $1={value:0};")
      .replace(
        "bytes[length++] = byte; if (byte == '\\n') break;",
        "bytes[length++]=byte.value; if(byte.value===10)break;",
      )
      .replace("if (!byte ||", "if (!byte.value ||")
      .replace(
        'case_launch_failure("case-frame", byte,',
        'case_launch_failure("case-frame", byte.value,',
      )
      .replace("return value;", "return value.value;")
      .replace(
        'operation = "mach_thread_self";',
        'mach_body: { operation = "mach_thread_self";',
      )
      .replaceAll("goto mach_cleanup;", "break mach_body;")
      .replace("mach_cleanup:", "}")
      .replace("const char *operation", "let operation")
      .replace("const char *prior", "let prior")
      .replace(
        /const char \*cleanup_operations\[\] = \{([^;]+)\};/u,
        "const cleanup_operations=[$1];",
      )
      .replace(
        /kern_return_t releases\[7\] = \{([^;]+)\};/u,
        "const releases=[$1];",
      )
      .replace(/int errors\[7\] = \{([^;]+)\};/u, "const errors=[$1];")
      .replaceAll("~0U", "0xffffffff")
      .replaceAll(
        /&(identity|status|waitReady|wait|p|parked|byte|value)\b/gu,
        "$1",
      )
      .replace(
        /&(host|access|notify|readback|type|address|access_type|reply_type|names|types|n|nt)\b/gu,
        (_, name) =>
          `{get value(){return ${name}},set value(value){${name}=value}}`,
      )
      .replaceAll(
        /\((?:unsigned long long|unsigned|int|long|id_t|size_t|void|void \*|mach_vm_address_t|mach_vm_size_t)\)/gu,
        "",
      )
      .replaceAll("sizeof(identity)", "48")
      .replaceAll("sizeof(status)", "64")
      .replaceAll("sizeof(parked)", "96")
      .replaceAll(
        "sizeof(bytes)",
        text.includes("char bytes[512];") ? "512" : "8192",
      )
      .replaceAll("sizeof(*names)", "4")
      .replaceAll("sizeof(*types)", "4")
      .replaceAll("&argv[12]", "argv.slice(12)")
      .replaceAll(
        /\b(?:int|long|unsigned|bool|ssize_t|task_t|thread_t|mach_port_t|mach_port_type_t|natural_t|mach_vm_address_t|kern_return_t|mach_port_name_array_t|mach_port_type_array_t|mach_msg_type_number_t) /gu,
        "let ",
      );
  const [ordinary, protectedBody] = body(launcher, "mach_rights").split(
      "#else\n",
    ),
    experiment = ordinary.replace("#ifdef NATIVE_CI_EXPERIMENT", ""),
    mach = protectedBody.replace("#endif", ""),
    sanitation = mach.indexOf("  need(task_set_special_port");
  assert.ok(sanitation > 0);
  const functions =
    [
      [reader, "case_launch_failure", "operation,result,error,revents,used"],
      [reader, "case_launch_check", "operation,result"],
      [reader, "case_line", "fd,encoded"],
      [launcher, "launch_stage", "stage,operation,result,error"],
      [launcher, "launch_failure", "operation,result,error,revents,used,child"],
      [launcher, "command", "fd,milliseconds"],
      [launcher, "child_stdio", "workspace,provider"],
      [launcher, "child_exec", "argv,environment,provider"],
      [launcher, "parked_identity", "fd,child"],
    ]
      .map(
        ([source, name, args]) =>
          `function ${name}(${args}) {${translate(body(source, name))}}`,
      )
      .join("\n") +
    `\nfunction initial_mach_rights(){${translate(mach.slice(0, sanitation))}mach_sanitation();}` +
    `\nfunction experiment_mach_rights(){${translate(experiment)}}`;
  const start = reader.indexOf("static void case_start("),
    setup = reader
      .slice(
        reader.indexOf("  posix_spawn_file_actions_t actions;", start),
        reader.indexOf("  char uid[24]", start),
      )
      .replace(
        "posix_spawn_file_actions_t actions; posix_spawnattr_t attributes;",
        "const actions={},attributes={};",
      )
      .replaceAll(/&(actions|attributes)/gu, "$1"),
    capture = /  launcher_identity = inspect\(getpid\(\)\);/u.exec(
      launcher,
    )?.[0];
  assert.ok(start > 0 && setup && capture);
  const SEND = 0x10000,
    RECEIVE = 0x20000,
    ONCE = 0x40000,
    DEAD = 0x100000;
  const machCases = [
    ...["reply", "destroy", "cleanup"].map((fatal) => [
      { fatal, ...(fatal === "cleanup" ? { destroy: 24 } : {}) },
      "parked-read",
      0,
      0,
    ]),
    [{ fatal: "cleanup", notify: 300, release: "notify" }, "parked-read", 0, 0],
    [{ stageWriteFailure: true }],
    [{ stageSignalFailure: true }],
    ...[0, 0xffffffff, 200, 201].map((access) => [{ access }]),
    [{ type: DEAD }],
    [{ access: 7 }], // A new getter copy can reuse the released host's local name.
    ...[1, 2, 3, 99].map((kind) => [
      { kind },
      "mach_port_kobject/access/type",
      kind,
    ]),
    ...[RECEIVE, ONCE, SEND | RECEIVE, SEND | DEAD, 0, 0x80000000].map(
      (type) => [{ type }, "TASK_ACCESS_PORT/authority", type],
    ),
    [{ typeQuery: 15 }, "mach_port_type/access", 15],
    [{ type: RECEIVE, typeQuery: 15 }, "mach_port_type/access", 15],
    [{ accessKobject: 17 }, "mach_port_kobject/access", 17],
    [{ accessGet: 19 }, "task_get_special_port/TASK_ACCESS_PORT", 19],
    [{ hostGet: -37 }, "task_get_special_port/TASK_HOST_PORT", -37],
    [{ hostKobject: 17 }, "mach_port_kobject", 17],
    ...[1, 2].map((access) => [
      { access },
      "TASK_ACCESS_PORT/identity",
      access,
    ]),
    [{ reply: 200 }, "mig_get_reply_port/identity", 200],
    [{ missing: true }, "TASK_ACCESS_PORT/census", 0],
    [{ changed: true }, "TASK_ACCESS_PORT/census", ONCE],
    [{ duplicate: true }, "TASK_ACCESS_PORT/census", SEND],
    [{ list: 25 }, "mach_port_names", 25],
    [{ mismatch: true }, "mach_port_names/count", 5],
    [{ overflow: true }, "mach_port_names/count", 4097],
    [{ partial: true, list: 25 }, "mach_port_names", 25],
    [{ partial: true }, "mach_port_names/count", 5],
    [{ sanitation: 23 }, "task_set_special_port/TASK_DEBUG_CONTROL_PORT", 23],
    [{ destroy: 24 }, "mach_port_destroy", 24],
    ...["names", "types", "access", "thread", "host"].map((release) => [
      { release },
      `${release === "names" || release === "types" ? "mach_vm" : "mach_port"}_deallocate/${release}`,
      15,
      22,
    ]),
    [{ type: DEAD, release: "access" }, "mach_port_deallocate/access", 15, 22],
    [{ kind: 1, release: "access" }, "mach_port_kobject/access/type", 1],
    [{ changed: true, release: "all" }, "TASK_ACCESS_PORT/census", ONCE],
    [{ notifyGet: 4, notifySet: 4, notify: 300 }],
    ...[0, 0xffffffff, 300, 200, 2, 7].map((notify) => [{ notify }]),
    ...[
      [4, 0],
      [4, 5],
      [5, 0],
      [5, 4],
      [5, 5],
    ].map(([notifyGet, notifySet]) => [
      { notifyGet, notifySet, notify: 300 },
      "task_get_special_port/TASK_RESOURCE_NOTIFY_PORT",
      notifyGet,
      31,
    ]),
    ...[4, 5].map((notifySet) => [
      { notifySet, notify: 300 },
      "task_set_special_port/TASK_RESOURCE_NOTIFY_PORT",
      notifySet,
      32,
    ]),
    ...[4, 5].map((readbackGet) => [
      { notify: 300, readback: 301, readbackGet },
      "task_get_special_port/TASK_RESOURCE_NOTIFY_PORT/readback",
      readbackGet,
      33,
    ]),
    ...[0xffffffff, 301, 300, 200, 2, 7].map((readback) => [
      { notify: 300, readback },
      "TASK_RESOURCE_NOTIFY_PORT/null",
      readback,
      33,
    ]),
    [{ notify: 300, release: "notify" }, "mach_port_deallocate/notify", 15, 41],
    [
      { notify: 200, readback: 200, readbackGet: 5, release: "all" },
      "task_get_special_port/TASK_RESOURCE_NOTIFY_PORT/readback",
      5,
      33,
    ],
    [
      { notify: 300, notifySet: 4, release: "all" },
      "task_set_special_port/TASK_RESOURCE_NOTIFY_PORT",
      4,
      32,
    ],
    ...["notify", "readback", ["notify", "readback"], "all"].map((release) => [
      { notify: 200, readback: 200, release },
      "TASK_RESOURCE_NOTIFY_PORT/null",
      200,
      33,
    ]),
  ];
  for (const [
    fault,
    invocation,
    operation,
    result,
    error,
    revents,
    used,
    machCase,
  ] of [
    ["setup", "setup()", "spawn-stderr", 22, 0, 0, -1],
    ["child", "child_stdio(10,false)", "fchdir", -1, 13, 0, -1],
    ["exec", "child_exec(argv,env,false)", "execve", -1, 2, 0, -1],
    ["timeout", "case_line(7,false)", "case-poll", 0, 0, 0, -1],
    ["poll-error", "case_line(7,false)", "case-poll", -1, 4, 0, -1],
    ["hup", "case_line(7,false)", "case-poll-events", 1, 0, 16, -1],
    ["eof", "case_line(7,false)", "case-read", 0, 0, 1, 0],
    ["read-error", "case_line(7,false)", "case-read", -1, 5, 1, -1],
    ["parked-eof", "parked_identity(8,42)", "parked-read", 0, 0, 16, 0],
    ["parked-timeout", "parked_identity(8,42)", "parked-poll", 0, 0, 0, -1],
    ["parked-read-error", "parked_identity(8,42)", "parked-read", -1, 5, 1, -1],
    ...["error", "mismatch", "empty"].map((status) => [
      `parked-status-${status}`,
      "parked_identity(8,42)",
      "parked-read",
      0,
      0,
      1,
      0,
    ]),
    ["parked-unrelated", "parked_identity(8,43)", "parked-read", 0, 0, 1, 0],
    [
      "parked-identity",
      "parked_identity(8,42)",
      "parked-identity",
      43,
      0,
      1,
      96,
    ],
    ["command-eof", "command(0,30000)", "command-read", 0, 0, 1, 0],
    ["command-timeout", "command(0,30000)", "command-poll", 0, 0, 0, -1],
    [
      "mach-host",
      "initial_mach_rights()",
      "task_get_special_port/TASK_HOST_PORT",
      -37,
      0,
      0,
      -1,
    ],
    [
      "mach-kobject",
      "initial_mach_rights()",
      "mach_port_kobject",
      17,
      11,
      0,
      -1,
    ],
    [
      "mach-type",
      "initial_mach_rights()",
      "mach_port_kobject/type",
      0xffffffff,
      11,
      0,
      -1,
    ],
    [
      "mach-deallocate",
      "initial_mach_rights()",
      "mach_port_deallocate/host",
      15,
      12,
      0,
      -1,
    ],
    [
      "mach-access",
      "initial_mach_rights()",
      "task_get_special_port/TASK_ACCESS_PORT",
      19,
      13,
      0,
      -1,
    ],
    [
      "mach-access-value",
      "initial_mach_rights()",
      "TASK_ACCESS_PORT/null",
      0xffffffff,
      13,
      0,
      -1,
    ],
    [
      "mach-access-service",
      "initial_mach_rights()",
      "TASK_ACCESS_PORT/null",
      200,
      13,
      0,
      -1,
    ],
    ["success"],
    ...machCases.map(([value, operation, result, error = 13]) => [
      "experiment",
      "experiment_mach_rights()",
      operation,
      result,
      error,
      0,
      -1,
      value,
    ]),
  ]) {
    const diagnostics = [],
      output = [],
      frames = [...Buffer.from('{"payload":null}\n')],
      descriptors = new Map([
        [0, "control"],
        [1, "control"],
        [2, "diagnostic"],
        [3, "data"],
        [4, "provider-input"],
        [5, "provider-error"],
      ]),
      actions = [],
      machCalls = [],
      stageAttempts = [],
      cloexec = new Set(),
      replaced = {},
      killed = {};
    const record = (format, values) => {
      let index = 0;
      const line = format.replace(/%(?:\.48s|llu|ld|d|s)/gu, (specifier) => {
        const raw = values[index++],
          value = String(specifier.endsWith("s") ? raw : Number(raw));
        return specifier === "%.48s" ? value.slice(0, 48) : value;
      });
      assert.ok(Buffer.byteLength(line) < 1024);
      return { format, values, line };
    };
    let reads = 0,
      reporter = 41,
      pipeIgnored = false;
    const api = {
      errno: 91,
      case_pid: fault === "setup" ? 0 : 41,
      case_mode: true,
      launcher_pid: 41,
      launcher_identity: {},
      launch_child: 42,
      KERN_SUCCESS: 0,
      MACH_PORT_NULL: 0,
      TASK_HOST_PORT: 1,
      TASK_ACCESS_PORT: 2,
      mach_task_self() {
        machCalls.push("task");
        return 1;
      },
      mach_thread_self() {
        machCalls.push("thread");
        return 2;
      },
      task_get_special_port(self, which, out) {
        assert.equal(self, 1);
        assert.ok(which === 1 || which === 2);
        machCalls.push(which === 1 ? "host" : "access");
        api.errno = which === 1 ? 0 : 13;
        out.value =
          which === 1
            ? 7
            : fault === "mach-access-value"
              ? 0xffffffff
              : fault === "mach-access-service"
                ? 200
                : 0;
        return fault === (which === 1 ? "mach-host" : "mach-access")
          ? which === 1
            ? -37
            : 19
          : 0;
      },
      mach_port_kobject(self, host, type, address) {
        assert.deepEqual([self, host], [1, 7]);
        machCalls.push("kobject");
        api.errno = 11;
        type.value = fault === "mach-type" ? 0xffffffff : 3;
        address.value = 4096;
        return fault === "mach-kobject" ? 17 : 0;
      },
      mach_port_deallocate(self, host) {
        assert.deepEqual([self, host], [1, 7]);
        machCalls.push("deallocate");
        api.errno = 12;
        return fault === "mach-deallocate" ? 15 : 0;
      },
      mach_sanitation() {
        machCalls.push("sanitation");
      },
      argv: Array.from({ length: 14 }, (_, i) => String(i)),
      env: ["LANG=en_US.UTF-8"],
      F_DUPFD_CLOEXEC: 64,
      POLLIN: 1,
      P_PID: 1,
      WEXITED: 1,
      WNOHANG: 2,
      WNOWAIT: 4,
      SIGPIPE: 13,
      SIG_IGN: 1,
      signal(number, disposition) {
        assert.deepEqual([number, disposition], [13, 1]);
        pipeIgnored = true;
        return 0;
      },
      sigemptyset(mask) {
        mask.value = "empty";
        api.errno = 98;
        return 0;
      },
      sigaction(number, action, previous) {
        assert.equal(number, 13);
        api.errno = 98;
        if (machCase?.stageSignalFailure) return -1;
        if (previous) {
          assert.equal(action.sa_handler, 1);
          assert.equal(action.sa_mask.value, "empty");
          Object.assign(previous, {
            sa_handler: 0,
            sa_flags: 64,
            sa_mask: "original-mask",
          });
          pipeIgnored = true;
        } else {
          assert.deepEqual(
            [action.sa_handler, action.sa_flags, action.sa_mask],
            [0, 64, "original-mask"],
          );
          pipeIgnored = false;
        }
        return 0;
      },
      PROC_PIDTBSDINFO: 3,
      POSIX_SPAWN_CLOEXEC_DEFAULT: 16,
      control: [10, 11],
      output: [12, 13],
      data: [14, 15],
      stderr: {},
      stdout: {},
      provider: false,
      proc_pidinfo(pid, kind, arg, out, size) {
        assert.equal(
          reporter,
          41,
          "Child diagnostics must use the saved launcher birth",
        );
        assert.deepEqual([pid, kind, arg, size], [41, 3, 1, 48]);
        api.errno = 70;
        out.pbi_start_tvsec = 100;
        out.pbi_start_tvusec = 200;
        return fault === "read-error" ? -1 : 48;
      },
      waitid(kind, pid, out, flags) {
        assert.equal(kind, 1);
        assert.ok([41, 42].includes(pid));
        assert.equal(flags, 7);
        Object.assign(out, {
          si_pid:
            fault === "parked-status-mismatch"
              ? 43
              : fault === "parked-status-empty"
                ? 0
                : pid,
          si_code: 1,
          si_status: 126,
        });
        api.errno = 71;
        return fault === "read-error" || fault === "parked-status-error"
          ? -1
          : 0;
      },
      getpid: () => reporter,
      stage_preserved(error) {
        assert.equal(api.errno, error);
        assert.equal(pipeIgnored, false);
      },
      inspect(pid) {
        assert.equal(pid, 41);
        return {
          token: { val: [0, 0, 0, 0, 0, 41] },
          bsd: { pbi_start_tvsec: 100, pbi_start_tvusec: 200 },
        };
      },
      memset(out, value, size) {
        assert.deepEqual([value, size], [0, 64]);
        for (const key of Object.keys(out)) out[key] = 0;
        return out;
      },
      fprintf(stream, format, ...values) {
        assert.equal(stream, api.stderr);
        if (machCase && format.startsWith("native-darwin-launch-cleanup:"))
          assert.ok(
            pipeIgnored,
            "Cleanup reporting must survive a closed diagnostic pipe",
          );
        diagnostics.push(record(format, values));
        return -1;
      },
      snprintf(bytes, maximum, format, ...values) {
        assert.equal(maximum, 512);
        bytes.record = record(format, values);
        api.errno = 97;
        return Buffer.byteLength(bytes.record.line);
      },
      write(fd, bytes, size) {
        assert.equal(fd, 2);
        assert.equal(descriptors.get(fd), "diagnostic");
        assert.ok(pipeIgnored);
        assert.equal(size, Buffer.byteLength(bytes.record.line));
        stageAttempts.push(bytes.record);
        api.errno = 99;
        if (machCase?.stageWriteFailure) return -1;
        diagnostics.push(bytes.record);
        return size;
      },
      fflush() {
        api.errno = 99;
        return -1;
      },
      dprintf(fd, format, ...values) {
        assert.equal(descriptors.get(fd), "diagnostic");
        const result = api.fprintf(api.stderr, format, ...values);
        api.errno = 99;
        return result;
      },
      fcntl(fd, operation, minimum) {
        assert.deepEqual([fd, operation, minimum], [2, 64, 3]);
        let copy = minimum;
        while (descriptors.has(copy)) copy++;
        descriptors.set(copy, descriptors.get(fd));
        cloexec.add(copy);
        return copy;
      },
      execve(path, args, environment) {
        assert.equal(path, api.argv[6]);
        assert.deepEqual(Array.from(args), api.argv.slice(12));
        assert.equal(environment, api.env);
        if (fault === "exec") {
          api.errno = 2;
          return -1;
        }
        for (const fd of cloexec) descriptors.delete(fd);
        cloexec.clear();
        throw replaced;
      },
      _exit(code) {
        assert.equal(code, 126);
        assert.equal(api.errno, error);
        throw new Error("launch refused");
      },
      need(ok) {
        if (!ok) {
          assert.equal(api.errno, error);
          throw new Error("launch refused");
        }
      },
      poll(wait, count, milliseconds) {
        assert.equal(count, 1);
        assert.equal(milliseconds, wait.fd === 8 ? 10000 : 30000);
        wait.revents =
          fault.includes("timeout") || fault === "poll-error"
            ? 0
            : fault === "hup" || fault === "parked-eof"
              ? 16
              : 1;
        api.errno = 4;
        return fault.includes("timeout") ? 0 : fault === "poll-error" ? -1 : 1;
      },
      read(fd, out, size) {
        reads++;
        api.errno = 5;
        if (
          fault.endsWith("eof") ||
          fault.startsWith("parked-status-") ||
          fault === "parked-unrelated"
        )
          return 0;
        if (fault.endsWith("read-error")) return -1;
        if (fd === 8) {
          assert.equal(size, 96);
          out.token.val[5] = fault === "parked-identity" ? 43 : 42;
          return 96;
        }
        assert.equal(size, 1);
        out.value = fd === 0 ? 80 : frames.shift();
        return 1;
      },
      close(fd) {
        assert.equal(fd, 8);
        return 0;
      },
      fputs(bytes) {
        output.push(Buffer.from(bytes.slice(0, bytes.indexOf(0))).toString());
      },
      hex(bytes, length, out) {
        out.value = Buffer.from(bytes.slice(0, length)).toString("hex");
      },
      printf(format, out) {
        output.push(format.replace("%s", out.value));
      },
      fchdir(workspace) {
        assert.equal(workspace, 10);
        api.errno = 13;
        return fault === "child" ? -1 : 0;
      },
      dup2(from, to) {
        descriptors.set(to, descriptors.get(from));
        return to;
      },
      posix_spawn_file_actions_init: () => 0,
      posix_spawnattr_init: () => 0,
      posix_spawnattr_setflags: (_attributes, flags) => {
        assert.equal(flags, 16);
        return 0;
      },
      posix_spawn_file_actions_adddup2(_actions, from, to) {
        actions.push([from, to]);
        api.errno = 88;
        return fault === "setup" && to === 2 ? 22 : 0;
      },
    };
    const acquired = [],
      released = [],
      arrays = [],
      destroyed = [];
    if (machCase) {
      const access = machCase.access ?? 200,
        accessType = machCase.type ?? SEND;
      let accessRead = false,
        replyReads = 0,
        notifyReads = 0;
      const resourceCopies = [];
      const resourcesSettled = () => {
        for (const copy of resourceCopies)
          assert.deepEqual(
            released
              .filter((entry) => entry.kind === copy.kind)
              .map(({ kind, name, status }) => ({ kind, name, status })),
            [{ ...copy, status: 0 }],
          );
      };
      const portRelease = (kind, name) => {
        const status =
          machCase.release === kind ||
          (Array.isArray(machCase.release) &&
            machCase.release.includes(kind)) ||
          (machCase.release === "all" && kind !== "host")
            ? 15
            : 0;
        api.errno = kind === "notify" ? 41 : kind === "readback" ? 42 : 22;
        released.push({ kind, name, status, error: api.errno });
        return status;
      };
      Object.assign(api, {
        NULL: null,
        KERN_INVALID_ARGUMENT: 4,
        KERN_FAILURE: 5,
        MACH_PORT_DEAD: 0xffffffff,
        MACH_PORT_TYPE_NONE: 0,
        MACH_PORT_TYPE_SEND: SEND,
        MACH_PORT_TYPE_RECEIVE: RECEIVE,
        MACH_PORT_TYPE_SEND_ONCE: ONCE,
        MACH_PORT_TYPE_DEAD_NAME: DEAD,
        MACH_PORT_VALID: (name) => name !== 0 && name !== 0xffffffff,
        TASK_BOOTSTRAP_PORT: 3,
        TASK_DEBUG_CONTROL_PORT: 4,
        TASK_RESOURCE_NOTIFY_PORT: 5,
        EXC_MASK_ALL: 63,
        EXCEPTION_DEFAULT: 1,
        THREAD_STATE_NONE: 0,
        mach_thread_self() {
          machCalls.push("thread");
          acquired.push({ kind: "thread", name: 2 });
          return 2;
        },
        task_get_special_port(self, which, out) {
          assert.equal(self, 1);
          assert.ok([1, 2, 5].includes(which));
          const kind =
            which === 1
              ? "host"
              : which === 2
                ? "access"
                : notifyReads++ === 0
                  ? "notify"
                  : "readback";
          machCalls.push(kind);
          if (which === 2) accessRead = true;
          const status = machCase[`${kind}Get`] ?? 0;
          out.value =
            which === 1 ? 7 : which === 2 ? access : (machCase[kind] ?? 0);
          if (!status && api.MACH_PORT_VALID(out.value)) {
            const copy = { kind, name: out.value };
            acquired.push(copy);
            if (which === 5) resourceCopies.push(copy);
          }
          api.errno = kind === "notify" ? 31 : kind === "readback" ? 33 : 13;
          return status;
        },
        mach_port_kobject(self, name, type, address) {
          assert.equal(self, 1);
          assert.equal(name, accessRead ? access : 7);
          machCalls.push(["kobject", name]);
          type.value = accessRead ? (machCase.kind ?? 0) : 3;
          address.value = 4096;
          api.errno = 13;
          return machCase[accessRead ? "accessKobject" : "hostKobject"] ?? 0;
        },
        mach_port_type(self, name, out) {
          assert.equal(self, 1);
          machCalls.push(["type", name]);
          api.errno = 13;
          out.value = name === access ? accessType : RECEIVE;
          return name === access ? (machCase.typeQuery ?? 0) : 0;
        },
        mach_port_deallocate(self, name) {
          assert.equal(self, 1);
          if (
            machCase.fatal === "cleanup" &&
            stageAttempts.at(-1)?.values[0] === "mach-cleanup"
          )
            throw killed;
          machCalls.push(["release", name]);
          const resource = resourceCopies.find(
            (copy) =>
              copy.name === name &&
              !released.some((entry) => entry.kind === copy.kind),
          );
          return portRelease(
            resource
              ? resource.kind
              : accessRead && name === access
                ? "access"
                : name === 2
                  ? "thread"
                  : "host",
            name,
          );
        },
        task_set_special_port(self, slot, name) {
          assert.deepEqual([self, name], [1, 0]);
          assert.ok([3, 4, 5].includes(slot));
          machCalls.push(["set", slot]);
          api.errno = slot === 5 ? 32 : 13;
          return slot === 5
            ? (machCase.notifySet ?? 0)
            : slot === 4
              ? (machCase.sanitation ?? 0)
              : 0;
        },
        mach_ports_register(self, ports, count) {
          assert.deepEqual([self, ports, count], [1, null, 0]);
          resourcesSettled();
          machCalls.push("register");
          return 0;
        },
        task_set_exception_ports: () => 0,
        thread_set_exception_ports: () => 0,
        mig_get_reply_port() {
          api.errno = 13;
          return ++replyReads === 1 ? 8 : (machCase.reply ?? 3);
        },
        mig_dealloc_reply_port(name) {
          assert.equal(name, 8);
          if (machCase.fatal === "reply") throw killed;
        },
        mach_port_names(self, names, n, types, nt) {
          assert.equal(self, 1);
          resourcesSettled();
          machCalls.push("census");
          api.errno = 13;
          const live = api.MACH_PORT_VALID(access) && accessType === SEND;
          const rows = [
            1,
            2,
            3,
            9,
            ...(live && !machCase.missing ? [access] : []),
          ];
          if (machCase.duplicate) rows.push(access);
          const kinds = rows.map((name) =>
            name === 3
              ? RECEIVE
              : name === access && machCase.changed
                ? ONCE
                : SEND,
          );
          n.value = machCase.overflow ? 4097 : rows.length;
          nt.value = rows.length + Number(Boolean(machCase.mismatch));
          names.value = rows;
          arrays.push({ kind: "names", buffer: rows, size: n.value * 4 });
          if (!machCase.partial) {
            types.value = kinds;
            arrays.push({ kind: "types", buffer: kinds, size: nt.value * 4 });
          }
          return machCase.list ?? 0;
        },
        mach_port_destroy(self, name) {
          assert.deepEqual([self, name], [1, 9]);
          if (machCase.fatal === "destroy") throw killed;
          destroyed.push(name);
          api.errno = 13;
          return machCase.destroy ?? 0;
        },
        mach_vm_deallocate(self, buffer, size) {
          assert.equal(self, 1);
          if (machCase.fatal === "cleanup") throw killed;
          const allocation = arrays.find((entry) => entry.buffer === buffer);
          assert.ok(allocation);
          assert.equal(size, allocation.size);
          return portRelease(allocation.kind, buffer);
        },
      });
    }
    const program = new Script(
        functions +
          `\nconst entered=launch_stage;
          launch_stage=(...args)=>{const saved=errno;entered(...args);stage_preserved(saved);};
          function setup(){${setup}}\nfunction capture(){${capture}}\n({case_line,command,child_stdio,child_exec,parked_identity,initial_mach_rights,experiment_mach_rights,setup,capture});`,
      ),
      native = program.runInNewContext(api);
    native.capture();
    if (machCase) {
      reporter = 42;
      if (machCase.fatal) {
        assert.throws(
          native.experiment_mach_rights,
          (cause) => cause === killed,
        );
        const last = stageAttempts.at(-1);
        assert.deepEqual(last.values.slice(0, 5), [
          {
            reply: "mach-reply-replace",
            destroy: "mach-census-destroy",
            cleanup: "mach-cleanup",
          }[machCase.fatal],
          41,
          42,
          100,
          200,
        ]);
        assert.deepEqual(
          last.values.slice(5),
          machCase.release === "notify"
            ? ["mach_port_deallocate/notify", 15, 41]
            : machCase.fatal === "cleanup"
              ? ["mach_port_destroy", 24, 13]
              : ["none", 0, 0],
        );
        assert.ok(last.line.includes("entered=1"));
        assert.ok(
          !diagnostics.some(({ line }) =>
            line.startsWith("native-darwin-launch:"),
          ),
        );
        reporter = 41;
        api.read = (fd) => {
          assert.equal(fd, 8);
          return 0;
        };
        api.waitid = (kind, pid, status, flags) => {
          assert.deepEqual([kind, pid, flags], [1, 42, 7]);
          Object.assign(status, { si_pid: 42, si_code: 2, si_status: 9 });
          api.errno = 71;
          return 0;
        };
        assert.throws(() => native.parked_identity(8, 42), /launch refused/u);
        const termination = diagnostics.at(-1);
        assert.match(
          termination.line,
          /available=1 pid=42 code=2 status=9 kernel-reason=unavailable/u,
        );
        assert.ok(
          diagnostics
            .at(-2)
            .line.includes("operation=parked-read result=0 errno=0"),
        );
        assert.equal(api.errno, 0);
        assert.deepEqual(output, []);
        continue;
      }
      if (operation)
        assert.throws(native.experiment_mach_rights, /launch refused/u);
      else native.experiment_mach_rights();
      const primary = diagnostics.filter(({ line }) =>
        line.startsWith("native-darwin-launch:"),
      );
      assert.equal(primary.length, operation ? 1 : 0);
      if (operation)
        assert.deepEqual(primary[0].values.slice(0, 5), [
          operation,
          result,
          error,
          0,
          -1,
        ]);
      const accessType = machCase.type ?? SEND;
      const unowned =
        !(machCase.typeQuery ?? 0) && !(accessType & (SEND | ONCE | DEAD));
      const owned = acquired.filter(
        (entry) => !(unowned && entry.kind === "access"),
      );
      for (const name of new Set(owned.map((entry) => entry.name)))
        assert.equal(
          released.filter((entry) => entry.name === name).length,
          owned.filter((entry) => entry.name === name).length,
        );
      assert.equal(
        released.filter((entry) => typeof entry.name === "number").length,
        owned.length,
      );
      for (const allocation of arrays)
        assert.equal(
          released.filter((entry) => entry.name === allocation.buffer).length,
          1,
        );
      const failed = released.filter((entry) => entry.status);
      const early =
        operation === "mach_port_deallocate/host" ||
        (accessType === DEAD && operation === "mach_port_deallocate/access");
      const cleanup = diagnostics.filter(({ line }) =>
        line.startsWith("native-darwin-launch-cleanup:"),
      );
      assert.deepEqual(
        cleanup.map((entry) => entry.values),
        failed
          .slice(Number(early))
          .map(({ kind, status, error }) => [
            `${kind === "names" || kind === "types" ? "mach_vm" : "mach_port"}_deallocate/${kind}`,
            status,
            error,
          ]),
      );
      if (machCalls.includes("notify")) {
        assert.equal(machCalls.filter((call) => call === "notify").length, 1);
        const shouldReadBack =
          !(machCase.notifyGet ?? 0) && !(machCase.notifySet ?? 0);
        assert.equal(
          machCalls.filter((call) => call === "readback").length,
          Number(shouldReadBack),
        );
        if (
          operation?.includes("RESOURCE_NOTIFY_PORT") ||
          [
            "mach_port_deallocate/notify",
            "mach_port_deallocate/readback",
          ].includes(operation)
        ) {
          assert.equal(machCalls.includes("register"), false);
          assert.equal(machCalls.includes("census"), false);
        }
      }
      if (!operation) {
        assert.equal(pipeIgnored, false);
        assert.deepEqual(destroyed, [9]);
        assert.equal(machCalls.filter((value) => value === "census").length, 1);
        assert.deepEqual(
          machCalls
            .filter(Array.isArray)
            .filter(([at]) => at === "set")
            .map(([, slot]) => slot),
          [3, 4, 5],
        );
      }
      assert.ok(stageAttempts.length <= 10);
      assert.ok(
        Buffer.byteLength(diagnostics.map(({ line }) => line).join("")) < 8192,
      );
      if (machCase.stageWriteFailure || machCase.stageSignalFailure)
        assert.deepEqual(diagnostics, []);
      if (
        api.MACH_PORT_VALID(machCase.access ?? 200) &&
        accessType === SEND &&
        arrays.length
      ) {
        const census = machCalls.indexOf("census"),
          release = machCalls.findLastIndex(
            (entry) =>
              Array.isArray(entry) &&
              entry[0] === "release" &&
              entry[1] === (machCase.access ?? 200),
          );
        assert.ok(release > census);
      }
      assert.equal(reads, 0);
      assert.deepEqual(output, []);
      assert.equal(descriptors.get(2), "diagnostic");
      continue;
    }
    if (fault === "child" || fault === "exec" || fault.startsWith("mach-"))
      reporter = 42;
    if (fault === "exec") {
      native.child_stdio(10, false);
      for (const fd of [3, 4, 5]) descriptors.delete(fd);
    }
    if (operation) {
      assert.throws(
        () => new Script(invocation).runInNewContext({ ...api, ...native }),
        /launch refused/u,
      );
      const termination = diagnostics.filter(({ line }) =>
        line.startsWith("native-darwin-launch-termination:"),
      );
      assert.equal(diagnostics.length, 1 + termination.length, fault);
      if (
        (fault.startsWith("parked-") && fault !== "parked-unrelated") ||
        fault.startsWith("command-")
      ) {
        assert.equal(termination.length, 1);
        assert.match(termination[0].line, /kernel-reason=unavailable/u);
        if (fault.startsWith("parked-status-")) {
          assert.match(
            termination[0].line,
            /available=0 pid=0 code=0 status=0/u,
          );
          assert.match(
            termination[0].line,
            new RegExp(
              `wait-result=${fault === "parked-status-error" ? -1 : 0}`,
            ),
          );
        }
      } else assert.deepEqual(termination, []);
      assert.deepEqual(diagnostics[0].values.slice(0, 5), [
        operation,
        result,
        error,
        revents,
        used,
      ]);
      assert.ok(
        diagnostics[0].line.includes(
          fault === "setup" ? "launcher=0" : "launcher=41",
        ),
      );
      if (fault === "child" || fault === "exec" || fault.startsWith("mach-"))
        assert.match(
          diagnostics[0].line,
          /start-seconds=100 start-micros=200/u,
        );
      if (fault === "read-error")
        assert.match(diagnostics[0].line, /wait-result=-1 .*status-pid=0/u);
      assert.deepEqual(output, []);
      if (fault.startsWith("mach-")) {
        const stopped = {
          "mach-host": 3,
          "mach-kobject": 4,
          "mach-type": 4,
          "mach-deallocate": 5,
          "mach-access": 6,
          "mach-access-value": 6,
          "mach-access-service": 6,
        }[fault];
        assert.deepEqual(
          machCalls,
          [
            "task",
            "thread",
            "host",
            "kobject",
            "deallocate",
            "access",
            "sanitation",
          ].slice(0, stopped),
        );
        assert.equal(reads, 0);
        assert.equal(descriptors.get(2), "diagnostic");
      }
      if (
        [
          "setup",
          "child",
          "exec",
          "timeout",
          "poll-error",
          "hup",
          "parked-timeout",
        ].includes(fault)
      )
        assert.equal(reads, 0);
    } else {
      native.setup();
      assert.deepEqual(actions, [
        [10, 0],
        [13, 1],
        [2, 2],
        [15, 3],
      ]);
      native.child_stdio(10, false);
      assert.equal(descriptors.get(2), "diagnostic");
      native.case_line(7, false);
      assert.deepEqual(output, ['{"payload":null}']);
      frames.push(...Buffer.from("fixture\n"));
      native.case_line(7, true);
      assert.equal(output[1], '{"hex":"666978747572650a"}');
      assert.equal(native.command(0, 30000), 80);
      assert.equal(native.parked_identity(8, 42).token.val[5], 42);
      for (const fd of [3, 4, 5]) descriptors.delete(fd);
      assert.throws(
        () => native.child_exec(api.argv, api.env, false),
        (cause) => cause === replaced,
      );
      assert.equal(cloexec.size, 0);
      assert.deepEqual([...descriptors.keys()], [0, 1, 2]);
      assert.deepEqual(
        [descriptors.get(0), descriptors.get(1), descriptors.get(2)],
        ["data", "data", "data"],
      );
      descriptors.set(3, "data");
      descriptors.set(4, "provider-input");
      descriptors.set(5, "provider-error");
      native.child_stdio(10, true);
      assert.equal(descriptors.get(2), "provider-error");
      native.initial_mach_rights();
      assert.deepEqual(machCalls, [
        "task",
        "thread",
        "host",
        "kobject",
        "deallocate",
        "access",
        "sanitation",
      ]);
      assert.deepEqual(diagnostics, []);
    }
  }
});

test("Darwin guard locations and errno remain diagnostics through failed custody", async () => {
  const chunks = [],
    guard = Buffer.from(
      "native-darwin-sdk: realpath=1 realpath-errno=0 equal=1 lstat=0 lstat-errno=0 kind=1 owner=1 writable=1\n" +
        "native-darwin-sdk-metadata: uid=0 gid=0 mode=040775 dev=1 inode=42\n" +
        "native-darwin-sdk: malformed untrusted=value\n" +
        "native-darwin-guard: file=fixture.c line=19 errno=13\n" +
        "native-darwin-launch: owner=launcher operation=task_get_special_port/TASK_ACCESS_PORT result=19 errno=13 revents=0 read=-1 launcher=41 reporter=42 child=0\n" +
        "native-darwin-launch: owner=launcher operation=parked-read result=0 errno=0 revents=16 read=0 launcher=41 child=42 status=126\n",
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
        const hello = { helper: { pid: 41 }, payload: null };
        child.stdout.write(JSON.stringify(hello) + "\n");
        assert.deepEqual(await channel.receive(), hello);
        const pending = assert.rejects(channel.receive()),
          completion = assert.rejects(channel.completion);
        const at = guard.indexOf("file=");
        child.stderr.write(guard.subarray(0, at));
        child.stdout.emit(
          "error",
          new Error("Injected custody transport failure"),
        );
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
  assert.ok(
    output.includes(
      "operation=task_get_special_port/TASK_ACCESS_PORT result=19 errno=13",
    ),
  );
  assert.ok(
    output.includes(
      "operation=parked-read result=0 errno=0 revents=16 read=0 launcher=41 child=42 status=126",
    ),
  );
});
