import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";
import { Script } from "node:vm";

import {
  createWindowsCustodyReader,
  createWindowsCustodyVerifier,
  encodeWindowsCustodyPlan,
  windowsCompilerArguments,
  WINDOWS_CUSTODY_DEADLINE_MS,
} from "./index.js";
import {
  coldProcessObservation,
  windowsClosedPreparationOwner,
} from "./custody-protocol.js";
import { windowsCustodyChannel } from "./channel.js";
import {
  digest,
  quoteWindowsArgument,
  windowsBuildHelperCommandLine,
  WINDOWS_BUILD_ENVIRONMENT_MAX_UNITS,
} from "./protocol.js";
import { observationDigest } from "../index.js";
import { createPrerequisiteTransport } from "../prerequisite-transport.js";
import { windowsPolicyFixture } from "./policy.fixture.js";
import { windowsOwnershipParameters } from "./case-effects.js";
import { compilerTrustFixture } from "./compiler-trust.fixture.js";
import {
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../diagnostics.js";

const hash = "a".repeat(64),
  candidateSha = "b".repeat(40),
  nonce = "c".repeat(32),
  runnerSid = "S-1-5-21-1-2-3-1001";
const identity = (pid, userSid = "S-1-5-18") => ({
  pid,
  userSid,
  sessionId: 0,
  creationTime: String(10000 + pid),
});
const id = (number) => `0000000000000001:${String(number).padStart(32, "0")}`;
const instance = {
  guid: "{11111111-2222-3333-4444-555555555555}",
  state: 4,
  enginePid: 20,
};
const hex = (text) => Buffer.from(text, "utf16le").toString("hex");
function executable() {
  const bytes = Buffer.alloc(512),
    optional = 88,
    cert = 448;
  bytes.writeUInt16LE(0x5a4d);
  bytes.writeUInt32LE(64, 0x3c);
  bytes.writeUInt32LE(0x4550, 64);
  bytes.writeUInt16LE(0x8664, 68);
  bytes.writeUInt16LE(1, 70);
  bytes.writeUInt16LE(240, 84);
  bytes.writeUInt16LE(0x20b, optional);
  bytes.writeUInt32LE(16, optional + 108);
  bytes.writeUInt32LE(cert, optional + 144);
  bytes.writeUInt32LE(8, optional + 148);
  bytes.writeUInt32LE(8, cert);
  bytes.writeUInt16LE(0x200, cert + 4);
  bytes.writeUInt16LE(2, cert + 6);
  return bytes;
}

function importImage(normal = 2, delay = 1) {
  const bytes = Buffer.alloc(0x3200);
  executable().subarray(0, 448).copy(bytes);
  bytes.writeUInt32LE(512, 88 + 60);
  for (const [at, value] of [
    [328 + 8, 0x3000],
    [328 + 12, 0x1000],
    [328 + 16, 0x3000],
    [328 + 20, 512],
  ])
    bytes.writeUInt32LE(value, at);
  for (const [directory, count, address, width] of [
    [1, normal, 0x1000, 20],
    [13, delay, 0x2400, 32],
  ]) {
    bytes.writeUInt32LE(address, 200 + directory * 8);
    bytes.writeUInt32LE(0x1200, 204 + directory * 8);
    for (let i = 0; i < count; i++) {
      const at = address - 0x1000 + 512 + i * width;
      if (directory === 13) bytes.writeUInt32LE(1, at);
      bytes.writeUInt32LE(
        i % 2 ? 0x3820 : directory === 13 ? 0x3840 : 0x3800,
        at + (directory === 13 ? 4 : 12),
      );
    }
  }
  bytes.write("fixture.dll\0", 0x2a00);
  bytes.write("second.dll\0", 0x2a20);
  bytes.write("fixture.dll\0", 0x2a40);
  return bytes;
}

let importProgram;
async function nativeImports(bytes, mode) {
  if (!importProgram) {
    const source = await readFile(
        new URL("custody-reader.c", import.meta.url),
        "utf8",
      ),
      rva = source.slice(
        source.indexOf("static DWORD rva("),
        source.indexOf("static void loader("),
      ),
      prepare =
        /static void release_pe_file\(struct held_file \*file\) \{[\s\S]*?\n\}/u.exec(
          source,
        )?.[0],
      start = source.indexOf(
        "  for (unsigned directory = 0; directory < 2; directory++)",
        source.indexOf("static void loader("),
      ),
      loader = source.slice(start, source.indexOf("\n  free(bytes); }", start));
    assert.ok(rva && prepare && start > 0 && loader);
    const translate = (body) =>
      body
        .replace(/#ifndef NATIVE_CI_EXPERIMENT\n[\s\S]*?#endif/gu, "")
        .replace(
          /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#else\n[\s\S]*?#endif/gu,
          "$1",
        )
        .replace(/#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#endif/gu, "$1")
        .replace(
          /static DWORD rva\([^\n]+\)/u,
          "function rva(bytes, size, pe, address, needed)",
        )
        .replace(
          /static void release_pe_file\([^\n]+\)/u,
          "function release_pe_file(file)",
        )
        .replace(
          /BYTE \*bytes\s*=\s*read_file\(file,\s*536870912,\s*&size\)/u,
          "let bytes = read_file(file, 536870912, value => (size = value))",
        )
        .replace(
          /IMAGE_DOS_HEADER \*dos\s*=\s*\(void \*\)bytes/u,
          "const dos = dosView(bytes)",
        )
        .replace(
          /IMAGE_NT_HEADERS64 \*pe\s*=\s*\(void \*\)\(bytes\s*\+\s*dos->e_lfanew\)/u,
          "const pe = peView(bytes, dos.e_lfanew)",
        )
        .replace(
          "IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(pe)",
          "const sections = pe.sections",
        )
        .replace(
          "(BYTE *)sections >= bytes && (BYTE *)(sections + pe->FileHeader.NumberOfSections) <= bytes + size",
          "pe.sectionOffset >= 0 && pe.sectionOffset + pe.FileHeader.NumberOfSections * 40 <= size",
        )
        .replace(
          /DWORD \*(item|entry)\s*=\s*\(void \*\)\(bytes\s*\+\s*at\s*\+\s*i\*width\)/gu,
          "let $1 = words(bytes, at + i*width, width)",
        )
        .replace(
          /wchar_t name\[256\]\s*=\s*\{0\}(, host\[256\]\s*=\s*\{0\})?/gu,
          (_, host) =>
            "let name = Array(256).fill(0)" +
            (host ? ", host = Array(256).fill(0)" : ""),
        )
        .replace("wchar_t actual[4096]", "const actual = {}")
        .replace("struct held_file resolved", "let resolved")
        .replace(/wcsrchr\(paths\[j\], [^)]+\)\+1/gu, "basename(paths[j])")
        .replaceAll("bytes+nameAt,", "bytes.subarray(nameAt),")
        .replaceAll("sizeof(IMAGE_IMPORT_DESCRIPTOR)", "20")
        .replaceAll("sizeof(IMAGE_NT_HEADERS64)", "264")
        .replaceAll("sizeof(IMAGE_OPTIONAL_HEADER64)", "240")
        .replaceAll("sizeof(files[j].id)", "1")
        .replaceAll(/\((?:DWORD|ULONGLONG)\)/gu, "")
        .replaceAll("->", ".")
        .replaceAll(/&(files\[j\].id|resolved.id|resolved)/gu, "$1")
        .replaceAll(
          /\b(?:DWORD|BOOL|ULONGLONG|unsigned|IMAGE_DATA_DIRECTORY) /gu,
          "let ",
        )
        .replace(/'((?:\\.|[^'])*)'/gu, (_, value) =>
          String((value === "\\\\" ? "\\" : value).charCodeAt(0)),
        );
    importProgram = new Script(`${translate(rva)}\n${translate(prepare)}
      if (mode === "prepare") release_pe_file({bytes});
      else { const size = bytes.length, pe = peView(bytes, dosView(bytes).e_lfanew), source = 0, n = paths.length; let emitted = 0;
        ${translate(loader)}
      }`);
  }
  let output = mode === "prepare" ? "" : '{"imports":[';
  const uint = (at) => bytes.readUInt32LE(at),
    peView = (_bytes, at) => {
      const optional = at + 24,
        sectionOffset = optional + bytes.readUInt16LE(at + 20);
      return {
        Signature: uint(at),
        sectionOffset,
        FileHeader: {
          Machine: bytes.readUInt16LE(at + 4),
          NumberOfSections: bytes.readUInt16LE(at + 6),
          TimeDateStamp: uint(at + 8),
          SizeOfOptionalHeader: bytes.readUInt16LE(at + 20),
          Characteristics: bytes.readUInt16LE(at + 22),
        },
        OptionalHeader: {
          Magic: bytes.readUInt16LE(optional),
          MajorLinkerVersion: bytes[optional + 2],
          MinorLinkerVersion: bytes[optional + 3],
          SizeOfHeaders: uint(optional + 60),
          NumberOfRvaAndSizes: uint(optional + 108),
          DataDirectory: Array.from({ length: 16 }, (_, i) => ({
            VirtualAddress: uint(optional + 112 + i * 8),
            Size: uint(optional + 116 + i * 8),
          })),
        },
        sections: Array.from(
          { length: bytes.readUInt16LE(at + 6) },
          (_, i) => ({
            VirtualAddress: uint(sectionOffset + i * 40 + 12),
            SizeOfRawData: uint(sectionOffset + i * 40 + 16),
            PointerToRawData: uint(sectionOffset + i * 40 + 20),
          }),
        ),
      };
    },
    wide = (value) =>
      Array.isArray(value)
        ? String.fromCharCode(...value.slice(0, value.indexOf(0)))
        : (value?.value ?? value),
    need = (ok) => {
      if (!ok) throw new Error("Native PE import refused");
    },
    paths = [
      "C:\\Fixture\\image.exe",
      "C:\\Fixture\\fixture.dll",
      "C:\\Fixture\\second.dll",
    ];
  importProgram.runInNewContext({
    bytes,
    mode,
    paths,
    peView,
    Array,
    files: paths.map((path) => ({ id: path })),
    process: {},
    TRUE: true,
    FALSE: false,
    IMAGE_DOS_SIGNATURE: 0x5a4d,
    IMAGE_NT_SIGNATURE: 0x4550,
    IMAGE_FILE_MACHINE_AMD64: 0x8664,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC: 0x20b,
    IMAGE_FILE_DLL: 0x2000,
    IMAGE_DIRECTORY_ENTRY_IMPORT: 1,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: 13,
    dosView: () => ({ e_magic: bytes.readUInt16LE(0), e_lfanew: uint(60) }),
    words: (_bytes, at, width) =>
      Array.from({ length: width / 4 }, (_, i) => uint(at + i * 4)),
    read_file: (file, maximum, size) => {
      assert.equal(file.bytes, bytes);
      assert.equal(maximum, 536870912);
      size(bytes.length);
      return bytes;
    },
    need,
    free() {},
    close_file() {},
    experiment_import: () => need(false),
    basename: (path) => path.slice(path.lastIndexOf("\\") + 1),
    _wcsicmp: (a, b) => Number(wide(a).toLowerCase() !== wide(b).toLowerCase()),
    wcscpy_s: (target, maximum, source) => {
      assert.equal(maximum, 256);
      for (let i = 0; i < source.length; i++) target[i] = source[i];
      return 0;
    },
    memcmp: (a, b) => Number(a !== b),
    strchr: (text, byte) => text.includes(String.fromCharCode(byte)),
    printf(format, ...args) {
      output += format.replace(/%(?:ls|lu|s|u)/gu, () => wide(args.shift()));
    },
    hex(data, length) {
      output += data.subarray(0, length).toString("hex");
    },
  });
  return JSON.parse(mode === "prepare" ? output : output + "]}");
}

test("Windows native import walks bound descriptors rather than the complete data extent", async () => {
  for (const mode of ["prepare", "loader"]) {
    const actual = await nativeImports(importImage(), mode);
    assert.deepEqual(
      actual.imports.map((item) => item.delay),
      [false, false, true],
    );
    if (mode === "prepare")
      assert.deepEqual(
        actual.imports.map((item) => item.name),
        ["fixture.dll", "second.dll", "fixture.dll"],
      );
    else
      assert.deepEqual(
        actual.imports.map((item) => [
          item.source,
          Buffer.from(item.importHex, "hex").toString(),
          item.resolved,
        ]),
        [
          [0, "fixture.dll", 1],
          [0, "second.dll", 2],
          [0, "fixture.dll", 1],
        ],
      );
    assert.equal(
      (await nativeImports(importImage(128, 128), mode)).imports.length,
      256,
    );
    for (const [normal, delay] of [
      [129, 1],
      [1, 129],
    ])
      await assert.rejects(
        nativeImports(importImage(normal, delay), mode),
        /Native PE import refused/u,
      );
    for (const directory of [1, 13]) {
      const width = directory === 1 ? 20 : 32,
        count = directory === 1 ? 2 : 1,
        data = importImage();
      data.writeUInt32LE(0, 200 + directory * 8);
      data.writeUInt32LE(0, 204 + directory * 8);
      assert.equal(
        (await nativeImports(data, mode)).imports.length,
        directory === 1 ? 1 : 2,
      );
      const exact = importImage();
      exact.writeUInt32LE((count + 1) * width, 204 + directory * 8);
      assert.equal((await nativeImports(exact, mode)).imports.length, 3);
      for (const fault of [
        "unterminated",
        "short-terminator",
        "range",
        "empty-range",
        "name-range",
        "name-limit",
        "name-character",
        ...(directory === 13 ? ["delay-attributes"] : []),
      ]) {
        const bytes = importImage(),
          table = directory === 1 ? 512 : 0x1600;
        if (fault === "unterminated")
          bytes.writeUInt32LE(count * width, 204 + directory * 8);
        if (fault === "short-terminator")
          bytes.writeUInt32LE((count + 1) * width - 1, 204 + directory * 8);
        if (fault === "range") bytes.writeUInt32LE(0x3fff, 200 + directory * 8);
        if (fault === "empty-range")
          bytes.writeUInt32LE(0, 204 + directory * 8);
        if (fault === "name-range")
          bytes.writeUInt32LE(0xffffffff, table + (directory === 1 ? 12 : 4));
        const name = directory === 1 ? 0x2a00 : 0x2a40;
        if (fault === "name-limit") bytes.fill(0x61, name, name + 256);
        if (fault === "name-character") bytes[name] = 0x2f;
        if (fault === "delay-attributes") bytes.writeUInt32LE(0, table);
        await assert.rejects(
          nativeImports(bytes, mode),
          /Native PE import refused/u,
          `${mode}: ${directory}: ${fault}`,
        );
      }
    }
    if (mode === "loader") {
      const missing = importImage();
      missing.write("absent.dll\0", 0x2a00);
      await assert.rejects(
        nativeImports(missing, mode),
        /Native PE import refused/u,
      );
    }
  }
});

function fixture({
  policy = false,
  git = false,
  observer = false,
  build = false,
} = {}) {
  const events = [],
    records = [],
    frames = [],
    bytes = new Map();
  const image = (name) => {
    const data = executable(),
      path = "C:\\Fixture\\Sealed\\" + name;
    bytes.set(path, data);
    return { path, sha256: digest(data), signatureSha256: hash };
  };
  const source = (name) => {
    const data = Buffer.from("reviewed fixture " + name),
      path = "C:\\Fixture\\Sealed\\" + name;
    bytes.set(path, data);
    return { path, sha256: digest(data) };
  };
  const helperImage = image("file-helper.exe"),
    bridge = identity(10, runnerSid),
    helper = identity(20),
    verifier = identity(40),
    fileHelper = identity(30);
  bytes.delete(helperImage.path);
  helperImage.path = "C:\\Fixture\\Storage\\file-helper.exe";
  bytes.set(helperImage.path, executable());
  const entries = [
    { kind: "helper", ...helperImage },
    {
      kind: "directory",
      path: "C:\\Fixture\\Storage",
      sha256: null,
      signatureSha256: null,
    },
    {
      kind: "directory",
      path: "C:\\Fixture\\Storage\\Work",
      sha256: null,
      signatureSha256: null,
    },
    {
      kind: "data",
      path: "C:\\Fixture\\Sealed\\data",
      sha256: digest("data"),
      signatureSha256: null,
    },
  ];
  const file = {
    request: {
      schemaVersion: 1,
      candidateSha,
      nonce,
      restrictingSid: "S-1-5-21-4-5-6-1002",
      custody: "C:\\Fixture\\Sealed",
      storage: entries[1].path,
      workspace: entries[2].path,
      launcher: {
        path: "C:\\Fixture\\Sealed\\launcher.exe",
        sha256: hash,
        signatureSha256: hash,
      },
      executable: { ...helperImage, parser: "msvc-ucrt-wmain-v1" },
      policy: { path: "C:\\Fixture\\Sealed\\policy.json", sha256: hash },
      bindings: { system: hash, source: hash, closure: hash, policy: hash },
    },
    root: id(2),
    base: id(3),
    reviewSha256: hash,
  };
  let policyFixture, policyHelper, policyObjects;
  if (policy) {
    policyFixture = windowsPolicyFixture(file.request, runnerSid);
    policyHelper = entries.length;
    entries.push({ kind: "helper", ...image("policy-helper.exe") });
    policyObjects = policyFixture.plan.manifest.objects
      .filter((entry) => entry.name !== "registry")
      .map((entry) => {
        let index = entries.findIndex((held) => held.path === entry.path);
        if (index < 0) {
          index = entries.length;
          const directory = [
            "custody",
            "storage",
            "workspace",
            "metadata",
            "checkout",
            "configuration",
            "credentials",
            "provider-home",
            "provider-cache",
          ].includes(entry.name);
          entries.push({
            kind: directory ? "directory" : "data",
            path: entry.path,
            sha256: directory ? null : hash,
            signatureSha256: null,
          });
        }
        return index;
      });
  }
  let gitInput, gitTransfer, gitPolicyTransfer;
  if (git) {
    const add = (entry) => {
      entries.push(entry);
      return entries.length - 1;
    };
    const gitImage = {
      ...image("git-fixture.exe"),
      path: file.request.storage + "\\git-fixture.exe",
    };
    bytes.set(gitImage.path, executable());
    const helperSlot = add({ kind: "helper", ...gitImage });
    const gitTool = {
      ...image("git.exe"),
      path: file.request.storage + "\\git.exe",
    };
    bytes.set(gitTool.path, executable());
    const gitSlot = add({ kind: "image", ...gitTool });
    const directory = (name) =>
      add({
        kind: "directory",
        path: file.request.storage + "\\" + name,
        sha256: null,
        signatureSha256: null,
      });
    const metadata = directory("metadata"),
      hooks = directory("hooks");
    const content = add({
      kind: "data",
      path: file.request.workspace + "\\content.txt",
      sha256: hash,
      signatureSha256: null,
    });
    gitInput = {
      request: {
        ...file.request,
        executable: { ...gitImage, parser: "msvc-ucrt-wmain-v1" },
      },
      git: gitTool,
      metadata: entries[metadata].path,
      hooks: entries[hooks].path,
      parent: "e".repeat(40),
      accountSid: runnerSid,
      reviewSha256: hash,
    };
    gitTransfer = {
      helper: helperSlot,
      git: gitSlot,
      metadata,
      workspace: 2,
      hooks,
    };
    gitPolicyTransfer = {
      helper: add({ kind: "helper", ...image("git-policy.exe") }),
      storage: 1,
      workspace: 2,
      objects: [metadata, hooks, content],
    };
  }
  let observerSlot;
  if (observer) {
    observerSlot = entries.length;
    entries.push({ kind: "helper", ...image("observer-helper.exe") });
  }
  let buildRequest, buildEntry;
  if (build) {
    const tool = image("cl.exe");
    buildEntry = {
      helper: entries.length,
      tool: entries.length + 1,
      toolSignatureSha256: hash,
    };
    entries.push(
      { kind: "helper", ...image("build-helper.exe") },
      { kind: "image", ...tool },
    );
    buildRequest = {
      candidateSha,
      platform: "win32",
      file: tool.path,
      toolSha256: tool.sha256,
      args: ["/Bv"],
      cwd: entries[1].path,
      env: {
        CI: "true",
        GITHUB_ACTIONS: "true",
        LANG: "C",
        INCLUDE: "include",
        LIB: "lib",
        SystemRoot: "C:\\Windows",
        PATH: "tools",
      },
      deadlineMs: 30000,
    };
  }
  const planPath = "C:\\Fixture\\Sealed\\plan",
    planBytes = encodeWindowsCustodyPlan({ candidateSha, nonce, entries });
  bytes.set(planPath, planBytes);
  const input = {
    context: {
      candidateSha,
      platform: "win32",
      tier: "system",
      runId: "1",
      runAttempt: 1,
      jobBindingSha256: hash,
      executionId: "windows.files",
      closureSha256: hash,
      selectedSystemSha256: null,
    },
    nonce,
    reader: image("custody-reader.exe"),
    bridge: image("custody-bridge.exe"),
    sources: [
      "custody-reader.c",
      "custody-bridge.c",
      "custody.h",
      "effective-reader.h",
      "account.h",
      "audit-policy-remove.h",
    ].map(source),
    plan: { path: planPath, sha256: digest(planBytes) },
    runnerSid,
    reviewSha256: hash,
    sdkSha256: hash,
    buildSha256: hash,
  };
  const object = (index) => ({
    identity: id(index + 1),
    pathHex: hex(entries[index].path),
    volumeHex: hex("\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\"),
    filesystemHex: hex("NTFS"),
    daclSha256: hash,
    links: 1,
    directory: entries[index].kind === "directory",
    held: true,
    reparse: false,
  });
  const process = {
    identity: identity(50, runnerSid),
    processDaclSha256: hash,
    tokenId: "1".padStart(16, "0"),
    authenticationId: "2".padStart(16, "0"),
    integritySid: "S-1-16-4096",
    groups: [],
    restricting: [],
    privileges: [],
    retired: false,
  };
  const job = {
    daclSha256: hash,
    limitFlags: 0x2008,
    processLimit: 1,
    uiRestrictions: 255,
    members: [fileHelper],
  };
  const retirement = (subject) => ({
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    nativeEventSha256: hash,
    noLiveMembers: true,
    helper: subject,
    verifier,
  });
  const owner = {
    pid: bridge.pid,
    async send(line) {
      events.push(line.trim());
      if (line === "T") {
        frames.push({ phase: "task-registered", taskSha256: hash });
        return;
      }
      if (line === "B") {
        frames.push(
          {
            phase: "entry",
            helper,
            bridge,
            processDaclSha256: hash,
            instance: { ...instance, enginePid: helper.pid },
          },
          { helper, peer: bridge },
        );
        return;
      }
      if (line === "P\n") {
        frames.push({ candidateSha, nonce, entries: entries.length });
        return;
      }
      if (line === "D") {
        frames.push({
          phase: "retired",
          taskSha256: hash,
          taskRemoved: true,
          helperRetired: true,
        });
        return;
      }
      const parts = line.trim().split(" "),
        [op, sequence, a, b, c] = parts;
      let value;
      if (["open", "inspect"].includes(op)) value = object(Number(a));
      if (op === "read")
        value = {
          hex: Buffer.from("data")
            .subarray(Number(b), Number(b) + Number(c))
            .toString("hex"),
        };
      if (op === "signature") value = { sha256: hash };
      if (op === "process-open") value = { slot: 0, observation: process };
      if (op === "process") value = process;
      if (op === "verifier") value = verifier;
      if (op === "job-open") value = { slot: 0, observation: job };
      if (op === "job") value = job;
      if (op === "loader")
        value = {
          complete: true,
          loaded: [
            {
              pathHex: hex(helperImage.path),
              identity: id(1),
              sha256: helperImage.sha256,
              signatureSha256: hash,
              daclSha256: hash,
              links: 1,
            },
          ],
          imports: [
            {
              source: 0,
              resolved: 0,
              delay: false,
              importHex: Buffer.from("fixture.dll").toString("hex"),
            },
          ],
          linkerMajor: 14,
          linkerMinor: 0,
          timestamp: 1,
        };
      if (op === "build")
        value = {
          major: 10,
          minor: 0,
          build: 26100,
          sdkRootHex: hex("C:\\SDK\\"),
        };
      if (op === "helper-start") {
        job.limitFlags = a === "build" ? 0x2808 : 0x2008;
        job.processLimit = ["git", "build"].includes(a) ? 32 : 1;
        const actor = a === "observer" ? identity(31) : fileHelper;
        job.members = [actor];
        value = {
          helper: actor,
          processDaclSha256: hash,
          threadDaclSha256: hash,
          inheritedHandleCount: Number(parts[5 + Number(parts[4])]) + 2,
          job,
          ...(["git", "build"].includes(a)
            ? { creatorDefaultDaclSha256: hash }
            : {}),
          ...(a === "file" ? { fileRootDeleteSharing: true } : {}),
        };
      }
      if (op === "helper-release") value = { released: true };
      if (op === "helper-send") value = { sent: true };
      if (op === "helper-close-input") value = { closed: true };
      if (op === "helper-read")
        value = {
          hex: Buffer.from(JSON.stringify({ ready: true })).toString("hex"),
        };
      if (op === "helper-bytes") value = { hex: "00" };
      if (op === "audit-install") value = { installed: true, objects: 1 };
      if (op === "audit-restore") value = { restored: true };
      if (op === "helper-finish")
        value = { retired: true, members: 0, drained: true, exitCode: 0 };
      if (op === "finish") value = { closed: true };
      const frame = {
        sequence: Number(sequence),
        value: structuredClone(value),
      };
      frames.push(options.damage ? options.damage(op, frame) : frame);
      if (op === "finish")
        frames.push({ phase: "helper-retired", helper, exitCode: 0 });
    },
    receive: async () => structuredClone(frames.shift()),
    completion: Promise.resolve({ code: 0, signal: null }),
    close() {
      events.push("fault");
    },
  };
  const options = {
    persist: async (record) => {
      records.push(structuredClone(record));
      events.push("persist-" + record.phase);
    },
    read: async (path) => {
      events.push("read-" + path);
      return bytes.get(path);
    },
    open: async () => {
      events.push("entry");
      frames.push({ phase: "task-intent", taskSha256: hash, bridge });
      return owner;
    },
    verifyBootstrap: async () => {
      events.push("verify-bootstrap");
      return {
        independent: true,
        held: true,
        protectedDacl: true,
        protectedParents: true,
        reviewSha256: hash,
        sdkSha256: hash,
        buildSha256: hash,
        nativeEventSha256: hash,
        entries: [input.bridge, input.reader, input.plan, ...input.sources].map(
          (entry, index) => ({
            path: entry.path,
            sha256: entry.sha256,
            signatureSha256: entry.signatureSha256 ?? null,
            identity: id(index + 10),
            daclSha256: hash,
          }),
        ),
      };
    },
    verifyAdmission: async () => {
      events.push("verify-admission");
      return {
        independent: true,
        helper,
        verifier,
        planSha256: input.plan.sha256,
        taskSha256: hash,
        imageSha256: input.reader.sha256,
        signatureSha256: hash,
        processDaclSha256: hash,
        nativeEventSha256: hash,
      };
    },
    verifyTransfer: async (value) => {
      events.push("verify-transfer");
      return {
        independent: true,
        helper: value.child,
        verifier,
        explicitHandleList: true,
        inheritedHandleCount: value.transfer.objects.length + 2,
        transferSha256: value.transferSha256,
        imageSha256: value.transfer.image.sha256,
        signatureSha256: value.transfer.image.signatureSha256,
        processDaclSha256: hash,
        threadDaclSha256: hash,
        jobSha256: observationDigest(job),
        nativeEventSha256: hash,
        ...(["git", "build"].includes(value.transfer.kind)
          ? { creatorDefaultDaclSha256: hash }
          : {}),
        ...(value.transfer.kind === "file"
          ? { fileRootDeleteSharing: true }
          : {}),
      };
    },
    verifyHelperRetirement: async (child) => retirement(child),
    verifyRetirement: async () => {
      events.push("verify-retirement");
      return retirement(helper);
    },
    verifyTaskRemoval: async () => {
      events.push("verify-removal");
      return { ...retirement(helper), taskRemoved: true };
    },
  };
  return {
    input,
    options,
    owner,
    events,
    records,
    frames,
    entries,
    bytes,
    file,
    process,
    helper,
    verifier,
    fileHelper,
    object,
    policyFixture,
    policyHelper,
    gitInput,
    gitTransfer,
    gitPolicyTransfer,
    policyObjects,
    observerSlot,
    buildRequest,
    buildEntry,
    reader: () => createWindowsCustodyReader(input, options),
    transfer: { helper: 0, root: 1, base: 2 },
  };
}

test("Windows custody is effect-free until write-ahead task and verified setup admission", async () => {
  const f = fixture(),
    reader = f.reader();
  assert.deepEqual(f.events, []);
  const result = await reader.start();
  assert.equal(result.independent, true);
  for (const [first, next] of [
    ["persist-task-possible", "verify-bootstrap"],
    ["verify-bootstrap", "entry"],
    ["persist-task-register-possible", "T"],
    ["persist-task-run-possible", "B"],
    ["verify-admission", "P"],
    ["persist-admitted", "P"],
  ])
    assert.ok(f.events.indexOf(first) < f.events.indexOf(next));
  await reader.open(3);
  const effects = f.events.length;
  await assert.rejects(reader.read(3, 536870912, 1));
  assert.equal(f.events.length, effects);
  assert.equal((await reader.read(3, 0, 4)).toString(), "data");
  assert.equal((await reader.close()).closed, true);
  assert.ok(
    f.events.indexOf("verify-retirement") < f.events.indexOf("finish 3"),
  );
  assert.equal(f.records.at(-1).custody, "RETIRED");
});

test("Windows native XML and path arguments stay on private transport, outside persisted command intents", async () => {
  const f = fixture();
  f.options.damage = (op, frame) =>
    op === "xml" ? { ...frame, value: { kind: "event", fields: [] } } : frame;
  const reader = f.reader();
  await reader.start();
  const bytes = Buffer.from("<Event>protected selector</Event>\0", "utf16le");
  await reader.xml(bytes);
  const record = f.records.find((item) => item.phase === "xml");
  assert.equal(
    record.argumentsSha256,
    observationDigest([bytes.toString("hex")]),
  );
  assert.ok(!JSON.stringify(f.records).includes(bytes.toString("hex")));
  await reader.close();
});
test("Windows live verifier checks use temporary custody without retaining a payload process", async () => {
  const f = fixture(),
    reader = f.reader();
  await reader.start();
  assert.deepEqual(await reader.verifier(f.verifier), f.verifier);
  const effects = f.events.length;
  await assert.rejects(
    reader.verifier({ ...f.verifier, creationTime: "10999" }),
  );
  assert.equal(f.events.length, effects);
  assert.ok(!f.events.some((event) => event.startsWith("process-open")));
  await reader.close();
});
test("Windows owned audit restoration fences new custody until fresh retirement verification settles", async () => {
  const f = fixture(),
    reader = f.reader();
  f.options.damage = (op, frame) =>
    op === "audit-install"
      ? { ...frame, value: { installed: true, objects: 1 } }
      : op === "audit-restore"
        ? { ...frame, value: { restored: true } }
        : frame;
  const retirement = Promise.withResolvers(),
    verificationStarted = Promise.withResolvers();
  f.options.verifyAuditRetirement = () => {
    verificationStarted.resolve();
    return retirement.promise;
  };
  await reader.start();
  await reader.open(3);
  await reader.retainProcess(f.process.identity);
  await reader.installAudit(0, [{ index: 3, descriptorSha256: hash }], hash);
  f.process.retired = true;
  const pending = reader.restoreAudit();
  await verificationStarted.promise;
  const effects = f.events.length;
  await assert.rejects(
    reader.retainProcess({ ...f.process.identity, pid: 51 }),
  );
  await assert.rejects(reader.job());
  assert.equal(f.events.length, effects);
  retirement.resolve({
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    candidateSha,
    nonce,
    noLiveMembers: true,
    noForeignCreators: true,
    noPrincipalFlows: true,
    exclusiveWriter: true,
    admissionsClosed: true,
    verifier: f.verifier,
    nativeEventSha256: hash,
  });
  assert.equal((await pending).restored, true);
  await reader.close();
});

test("Windows entry requires separately observed sealed code, SDK and build pins before execution", async () => {
  for (const damage of [
    (seal) => {
      seal.entries[0].sha256 = "d".repeat(64);
    },
    (seal) => {
      seal.sdkSha256 = "d".repeat(64);
    },
    (seal) => {
      seal.protectedParents = false;
    },
  ]) {
    const f = fixture(),
      verify = f.options.verifyBootstrap;
    f.options.verifyBootstrap = async (...args) => {
      const seal = await verify(...args);
      damage(seal);
      return seal;
    };
    await assert.rejects(f.reader().start());
    assert.ok(!f.events.includes("entry"));
    assert.equal(f.records.at(-1).custody, "POSSIBLE");
  }
  const f = fixture();
  f.bytes.set(f.input.sources[0].path, Buffer.from("substituted"));
  await assert.rejects(f.reader().start());
  assert.ok(!f.events.includes("entry"));
});

test("Windows sealed task paths cannot expand environment variables", () => {
  const f = fixture();
  for (const asset of [
    f.input.bridge,
    f.input.reader,
    f.input.plan,
    ...f.input.sources,
  ])
    asset.path = asset.path.replace("\\Sealed\\", "\\%TASK_ROOT%\\");
  assert.throws(() => f.reader());
  assert.deepEqual(f.events, []);
});

test("Windows an administrator, reused creation identity or self-verifier cannot acknowledge setup", async () => {
  for (const damage of [
    (value) => {
      value.helper.userSid = runnerSid;
    },
    (value) => {
      value.helper.creationTime = "90000";
    },
    (value) => {
      value.verifier = value.helper;
    },
  ]) {
    const f = fixture(),
      verify = f.options.verifyAdmission;
    f.options.verifyAdmission = async (...args) => {
      const value = structuredClone(await verify(...args));
      damage(value);
      return value;
    };
    await assert.rejects(f.reader().start());
    assert.ok(!f.events.includes("P"));
    assert.equal(f.records.at(-1).phase, "uncertain");
  }
});

test("Windows absent independent admission retains a registered possible task", async () => {
  const f = fixture();
  delete f.options.verifyAdmission;
  const reader = f.reader();
  await assert.rejects(reader.start());
  assert.ok(f.events.includes("B"));
  assert.ok(!f.events.includes("P"));
  assert.equal((await reader.close()).status, "RETAINED");
  assert.equal(f.records.at(-1).custody, "POSSIBLE");
});

test("Windows admission failure survives an unsuccessful uncertainty receipt", async () => {
  const f = fixture(),
    failure = new Error("independent admission unavailable"),
    persist = f.options.persist;
  f.options.verifyAdmission = async () => {
    throw failure;
  };
  f.options.persist = async (record) => {
    if (record.phase === "uncertain") throw new Error("receipt unavailable");
    return persist(record);
  };
  const reader = f.reader();
  await assert.rejects(reader.start(), (error) => error === failure);
  assert.equal(f.records.at(-1).phase, "task-parked");
  assert.equal(f.records.at(-1).custody, "POSSIBLE");
  assert.ok(!f.events.includes("fault"));
  assert.equal((await reader.close()).status, "RETAINED");
});

test("Windows callback and returned identity snapshots cannot rewrite admitted custody", async () => {
  const f = fixture(),
    verify = f.options.verifyAdmission;
  f.options.verifyAdmission = async (value) => {
    value.input.reader.sha256 = "d".repeat(64);
    return verify();
  };
  const reader = f.reader(),
    admitted = await reader.start();
  admitted.helper.pid = 99;
  admitted.verifier.pid = 99;
  for (const index of [0, 1, 2]) await reader.open(index);
  const file = await reader.openFile(f.file, f.transfer);
  file.identity.pid = 99;
  await file.close();
  assert.equal((await reader.close()).closed, true);
});

test("Windows held files, volumes, process creation identities and loader edges reject substitution", async () => {
  for (const [operation, damage] of [
    [
      "loader",
      (value) => {
        value.importScope = "private-runtime";
      },
    ],
    [
      "inspect",
      (value) => {
        value.identity = id(99);
      },
    ],
    [
      "inspect",
      (value) => {
        value.volumeHex = hex(
          "\\\\?\\Volume{99999999-2222-3333-4444-555555555555}\\",
        );
      },
    ],
    [
      "process",
      (value) => {
        value.identity.creationTime = "90000";
      },
    ],
    [
      "loader",
      (value) => {
        value.imports[0].resolved = 1;
      },
    ],
    [
      "loader",
      (value) => {
        value.complete = false;
      },
    ],
  ]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    await reader.open(0);
    await reader.retainProcess(f.process.identity);
    f.options.damage = (op, frame) => {
      if (op === operation) damage(frame.value);
      return frame;
    };
    await assert.rejects(
      operation === "inspect"
        ? reader.inspect(0)
        : operation === "process"
          ? reader.process(0)
          : reader.loader(0, 0),
    );
  }
});

test("Windows file transfer admits only the joined held roots and creation-time Job before release", async () => {
  const f = fixture(),
    reader = f.reader();
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  const file = await reader.openFile(f.file, f.transfer);
  assert.ok(
    f.events.indexOf("verify-transfer") <
      f.events.findIndex((event) => event.startsWith("helper-release ")),
  );
  assert.ok(
    f.events.indexOf("persist-helper-admitted") <
      f.events.findIndex((event) => event.startsWith("helper-release ")),
  );
  assert.deepEqual(await file.receive(), { ready: true });
  await file.send("P");
  assert.equal((await file.close()).closed, true);
  assert.deepEqual(await file.completion, {
    code: 0,
    signal: null,
    failed: false,
    partialBytes: 0,
    remainingMessages: 0,
  });
  file.dispose();
  await assert.rejects(file.send("P"));
  assert.equal((await reader.close()).closed, true);
});

test("Windows file completion exposes only native drained retirement and the bounded interruption exit", async () => {
  for (const exitCode of [126, 1]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    for (const index of [0, 1, 2]) await reader.open(index);
    const channel = await reader.openFile(f.file, f.transfer);
    f.options.damage = (op, frame) => {
      if (op === "helper-finish") frame.value.exitCode = exitCode;
      return frame;
    };
    if (exitCode === 126) {
      channel.close();
      assert.equal((await channel.completion).code, 126);
      assert.equal((await reader.close()).closed, true);
    } else {
      await assert.rejects(channel.close());
      await assert.rejects(channel.completion);
    }
    assert.ok(
      f.events.some((event) => event.startsWith("helper-close-input ")),
    );
  }
});

test("Windows active Security observation has separate helper pipes through file work and retirement", async () => {
  const f = fixture({ observer: true }),
    reader = f.reader();
  await reader.start();
  for (const index of [0, 1, 2, 3, f.observerSlot]) await reader.open(index);
  await reader.retainProcess(f.process.identity);
  await reader.installAudit(0, [{ index: 3, descriptorSha256: hash }], hash);
  const domain = {
    accountSid: runnerSid,
    restrictingSid: f.file.request.restrictingSid,
    jobSha256: hash,
  };
  const value = {
    plan: {
      schemaVersion: 1,
      candidateSha,
      nonce,
      domainSha256: observationDigest(domain),
      policySha256: hash,
      reviewSha256: hash,
      routes: [
        {
          id: "inspect",
          operation: "read",
          targetSha256: digest("target"),
          permitTargetSha256: digest("permit"),
          denyTargetSha256: digest("deny"),
          nonceSha256: hash,
          beforeSha256: hash,
          afterSha256: hash,
          outcome: "permit",
        },
      ],
    },
    domain,
    bindings: ["control-permit", "control-deny", "tool"].map((phase) => ({
      routeId: "inspect",
      phase,
      selector: f.entries[3].path,
      opcode: "4663",
      accessMask: 1,
      filterId: null,
    })),
    pins: {
      manifestSha256: hash,
      imageSha256: f.entries[f.observerSlot].sha256,
      sourceSha256: hash,
      abiSha256: hash,
    },
  };
  const observer = await reader.openObserver(value, f.observerSlot);
  const file = await reader.openFile(f.file, f.transfer);
  assert.notEqual(observer.identity.pid, file.helper.pid);
  await observer.send("P");
  await file.send("P");
  await observer.receive(1);
  await file.receive();
  await file.close();
  await observer.send("S");
  assert.equal((await observer.close()).drained, true);
  const lanes = f.events
    .filter((event) => event.startsWith("helper-send "))
    .map((event) => event.split(" ")[2]);
  assert.deepEqual(lanes, ["1", "0", "1"]);
  f.process.retired = true;
  f.options.verifyAuditRetirement = async () => ({
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    nativeEventSha256: hash,
    exclusiveWriter: true,
    admissionsClosed: true,
    candidateSha,
    nonce,
    noLiveMembers: true,
    noForeignCreators: true,
    noPrincipalFlows: true,
    verifier: f.verifier,
  });
  await reader.restoreAudit();
  assert.equal((await reader.close()).closed, true);
});

test("Windows pending helper creation excludes a second launch before native effects", async () => {
  const f = fixture(),
    reader = f.reader(),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers(),
    send = f.owner.send;
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  f.owner.send = async (bytes) => {
    if (bytes.startsWith("helper-start ")) {
      entered.resolve();
      await release.promise;
    }
    return send(bytes);
  };
  const first = reader.openFile(f.file, f.transfer);
  await entered.promise;
  const pending = Promise.allSettled([
    first,
    reader.openFile(f.file, f.transfer),
  ]);
  release.resolve();
  const results = await pending;
  assert.equal(results[0].status, "fulfilled");
  await results[0].value.close();
  assert.equal((await reader.close()).closed, true);
  assert.equal(results[1].status, "rejected");
  assert.equal(
    f.events.filter((event) => event.startsWith("helper-start ")).length,
    1,
  );
});

test("Windows retirement verification excludes new helper effects", async () => {
  const f = fixture(),
    reader = f.reader(),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers(),
    verify = f.options.verifyRetirement;
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  f.options.verifyRetirement = async (...args) => {
    entered.resolve();
    await release.promise;
    return verify(...args);
  };
  const closing = reader.close();
  await entered.promise;
  const [result] = await Promise.allSettled([
    reader.openFile(f.file, f.transfer),
  ]);
  if (result.status === "fulfilled") await result.value.close();
  release.resolve();
  assert.equal((await closing).closed, true);
  assert.equal(result.status, "rejected");
  assert.ok(!f.events.some((event) => event.startsWith("helper-start ")));
});

test("Windows incorrect transferred roots and unobserved creation authority withhold helper release", async () => {
  const wrong = fixture(),
    first = wrong.reader();
  await first.start();
  for (const index of [0, 1, 2]) await first.open(index);
  wrong.transfer.base = 1;
  await assert.rejects(first.openFile(wrong.file, wrong.transfer));
  assert.ok(!wrong.events.some((event) => event.startsWith("helper-start ")));
  assert.equal((await first.close()).closed, true);
  for (const damage of [
    (f) => {
      f.options.damage = (op, frame) => {
        if (op === "helper-start") frame.value.job.limitFlags |= 0x800;
        return frame;
      };
    },
    (f) => {
      f.options.verifyTransfer = async () => ({ independent: false });
    },
  ]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    for (const index of [0, 1, 2]) await reader.open(index);
    damage(f);
    await assert.rejects(reader.openFile(f.file, f.transfer));
    assert.ok(!f.events.some((event) => event.startsWith("helper-release ")));
    assert.equal((await reader.close()).status, "RETAINED");
  }
});

test("Windows file release requires native and independent delete-sharing evidence for owned root controls", async () => {
  for (const damage of ["missing", "proof"]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    for (const index of [0, 1, 2]) await reader.open(index);
    if (damage === "missing")
      f.options.damage = (op, frame) => {
        if (op === "helper-start") delete frame.value.fileRootDeleteSharing;
        return frame;
      };
    else {
      const verify = f.options.verifyTransfer;
      f.options.verifyTransfer = async (value) => ({
        ...(await verify(value)),
        fileRootDeleteSharing: false,
      });
    }
    await assert.rejects(reader.openFile(f.file, f.transfer));
    assert.ok(!f.events.some((event) => event.startsWith("helper-release ")));
    assert.equal((await reader.close()).status, "RETAINED");
  }
});

test("Windows policy handle lists cannot substitute a different observed pathname", async () => {
  const f = fixture(),
    policy = windowsPolicyFixture(f.file.request, runnerSid),
    reader = f.reader();
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  const objects = policy.plan.manifest.objects
    .filter((object) => object.name !== "registry")
    .map(() => 1);
  await assert.rejects(
    reader.openPolicy(policy.input, "install", { helper: 0, objects }),
  );
  assert.ok(!f.events.some((event) => event.startsWith("helper-start ")));
});

test("Windows policy transfer uses the complete ordered held-object list through the private helper pipe", async () => {
  const f = fixture({ policy: true }),
    reader = f.reader();
  await reader.start();
  for (const index of new Set([f.policyHelper, ...f.policyObjects]))
    await reader.open(index);
  const helper = await reader.openPolicy(f.policyFixture.input, "install", {
    helper: f.policyHelper,
    objects: f.policyObjects,
  });
  const command = f.events
      .find((event) => event.startsWith("helper-start "))
      .split(" "),
    argc = Number(command[4]),
    count = Number(command[5 + argc]);
  assert.equal(count, f.policyObjects.length);
  assert.deepEqual(command.slice(6 + argc).map(Number), f.policyObjects);
  assert.ok(
    f.events.indexOf("verify-transfer") <
      f.events.findIndex((event) => event.startsWith("helper-release ")),
  );
  await helper.send("P");
  assert.equal((await helper.close()).closed, true);
  assert.equal((await reader.close()).closed, true);
});

test("Windows cancellation while admission is pending cannot send a late setup acknowledgement", async () => {
  const f = fixture(),
    abort = new AbortController();
  let entered, finish;
  const waiting = new Promise((resolve) => {
    entered = resolve;
  });
  f.options.verifyAdmission = () => {
    entered();
    return new Promise((resolve) => {
      finish = resolve;
    });
  };
  const running = f.reader().start({ signal: abort.signal });
  await waiting;
  abort.abort();
  finish({
    independent: true,
    helper: f.helper,
    verifier: f.verifier,
    planSha256: f.input.plan.sha256,
    nativeEventSha256: hash,
  });
  await assert.rejects(running);
  assert.ok(!f.events.includes("P"));
  assert.equal(f.records.at(-1).custody, "POSSIBLE");
});

test("Windows admitted work cancellation retains custody for bounded cleanup and fences new process/Job/helper admissions", async () => {
  const f = fixture(),
    work = new AbortController(),
    reader = f.reader();
  await reader.start({ signal: work.signal });
  for (const index of [0, 1, 2]) await reader.open(index);
  await assert.rejects(
    reader.beginCleanup({ signal: new AbortController().signal }),
  );
  work.abort();
  assert.ok(!f.events.includes("fault"));
  await reader.beginCleanup({ signal: new AbortController().signal });
  const before = f.events.length;
  await assert.rejects(reader.retainProcess(f.fileHelper));
  await assert.rejects(reader.job());
  await assert.rejects(reader.openFile(f.file, f.transfer));
  assert.equal(f.events.length, before);
  assert.equal((await reader.close()).closed, true);
  assert.equal(
    f.records.find((record) => record.phase === "cleanup").admission,
    "CLOSED",
  );
});

test("Windows cleanup cancellation retains the possible task and cannot acknowledge retirement", async () => {
  const f = fixture(),
    work = new AbortController(),
    finish = new AbortController(),
    reader = f.reader();
  await reader.start({ signal: work.signal });
  work.abort();
  await reader.beginCleanup({ signal: finish.signal });
  finish.abort();
  assert.ok(f.events.includes("fault"));
  assert.equal((await reader.close()).status, "RETAINED");
  assert.ok(!f.records.some((record) => record.phase === "retired"));
});

test("Windows cleanup only admits owned removal with fresh unchanged-state and retirement evidence", async () => {
  for (const damage of [null, "installed", "retirement"]) {
    const f = fixture({ policy: true }),
      work = new AbortController(),
      reader = f.reader();
    await reader.start({ signal: work.signal });
    for (const index of new Set([f.policyHelper, ...f.policyObjects]))
      await reader.open(index);
    work.abort();
    await reader.beginCleanup({ signal: new AbortController().signal });
    const transfer = { helper: f.policyHelper, objects: f.policyObjects };
    await assert.rejects(
      reader.openPolicy(f.policyFixture.input, "remove", transfer),
    );
    const retirement = {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
      nativeEventSha256: hash,
      candidateSha,
      nonce,
      noLiveMembers: damage !== "retirement",
    };
    if (damage === "retirement") {
      await assert.rejects(reader.authorizeRestoration(retirement));
      continue;
    }
    await reader.authorizeRestoration(retirement);
    f.options.verifyRestoration = async (observations) => ({
      independent: true,
      noLiveMembers: true,
      unchangedInstalled: damage !== "installed",
      observationsSha256: observationDigest(observations),
      verifier: f.verifier,
      nativeEventSha256: hash,
    });
    await assert.rejects(
      reader.openPolicy(f.policyFixture.input, "install", transfer),
    );
    if (damage)
      await assert.rejects(
        reader.openPolicy(f.policyFixture.input, "remove", transfer),
      );
    else {
      const helper = await reader.openPolicy(
        f.policyFixture.input,
        "remove",
        transfer,
      );
      await helper.close();
      assert.equal((await reader.close()).closed, true);
      assert.ok(
        f.records.some((record) => record.phase === "restore-helper-possible"),
      );
    }
    if (damage)
      assert.ok(!f.events.some((event) => event.startsWith("helper-start ")));
  }
});

test("Windows Git helpers use fixed vectors and a complete distinct held-object list", async () => {
  const f = fixture({ git: true }),
    reader = f.reader();
  await reader.start();
  for (const index of new Set([
    ...Object.values(f.gitTransfer),
    f.gitPolicyTransfer.helper,
    f.gitPolicyTransfer.storage,
    ...f.gitPolicyTransfer.objects,
  ]))
    await reader.open(index);
  const policy = await reader.openGitPolicy(
    f.gitInput,
    "install",
    f.gitPolicyTransfer,
  );
  const command = f.events
      .find((event) => event.startsWith("helper-start "))
      .split(" "),
    argc = Number(command[4]);
  assert.equal(command[2], "git-policy");
  assert.deepEqual(command.slice(6 + argc).map(Number), [
    1,
    2,
    ...f.gitPolicyTransfer.objects,
  ]);
  await policy.close();
  await assert.rejects(
    reader.openGitPolicy(f.gitInput, "install", {
      ...f.gitPolicyTransfer,
      objects: [1, ...f.gitPolicyTransfer.objects],
    }),
  );
  const helper = await reader.openGit(f.gitInput, f.gitTransfer);
  assert.ok(
    f.events.some(
      (event) =>
        event.startsWith("helper-start ") && event.split(" ")[2] === "git",
    ),
  );
  await helper.close();
  assert.equal((await reader.close()).closed, true);
});

test("Windows fixed Git release requires independently joined creator default DACL evidence", async () => {
  for (const damage of ["missing", "mismatch"]) {
    const f = fixture({ git: true }),
      reader = f.reader();
    await reader.start();
    for (const index of Object.values(f.gitTransfer)) await reader.open(index);
    if (damage === "missing")
      f.options.damage = (op, frame) => {
        if (op === "helper-start") delete frame.value.creatorDefaultDaclSha256;
        return frame;
      };
    else {
      const verify = f.options.verifyTransfer;
      f.options.verifyTransfer = async (value) => ({
        ...(await verify(value)),
        creatorDefaultDaclSha256: "f".repeat(64),
      });
    }
    await assert.rejects(reader.openGit(f.gitInput, f.gitTransfer));
    assert.ok(!f.events.some((event) => event.startsWith("helper-release ")));
    assert.equal((await reader.close()).status, "RETAINED");
  }
});

test("Windows build controller admission rejects stale policy, extra flags and members before release", async () => {
  for (const damage of ["nested", "silent", "member", "proof"]) {
    const f = fixture({ build: true }),
      reader = f.reader();
    await reader.start();
    for (const index of [f.buildEntry.helper, f.buildEntry.tool])
      await reader.open(index);
    f.options.damage = (op, frame) => {
      if (op === "helper-start") {
        if (damage === "nested") frame.value.job.limitFlags = 0x2008;
        if (damage === "silent") frame.value.job.limitFlags |= 0x1000;
        if (damage === "member") frame.value.job.members.push(identity(41));
      }
      return frame;
    };
    if (damage === "proof") {
      const verify = f.options.verifyTransfer;
      f.options.verifyTransfer = async (...args) => ({
        ...(await verify(...args)),
        jobSha256: "f".repeat(64),
      });
    }
    await assert.rejects(
      reader.openBuild(
        f.buildRequest,
        { mode: "compiler-version" },
        f.buildEntry,
      ),
    );
    assert.ok(!f.events.some((event) => event.startsWith("helper-release ")));
    assert.equal((await reader.close()).status, "RETAINED");
  }
});

test("actual restricted-token construction deletes every other privilege and independent peer/Git guards require exact traversal authority", async () => {
  const [account, reader] = await Promise.all(
    ["account.h", "custody-reader.c"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const body = (source, name) => {
    const match = new RegExp(
      `static [^\\n]+ ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source);
    assert.ok(match, name);
    return match[1];
  };
  // Representation-only projection of the actual native construction/guards.
  const project = (value) =>
    value
      .replaceAll("->", ".")
      .replace(/\bLUID notify\b/gu, "LUID notify = {}")
      .replace("LUID_AND_ATTRIBUTES deleted[64]", "var deleted=[]")
      .replace("SID_AND_ATTRIBUTES disabled[128]", "var disabled=[]")
      .replace("{ capability, 0 }", "{ Sid: capability, Attributes: 0 }")
      .replace(
        "{ { low, SE_GROUP_INTEGRITY } }",
        "{ Label: { Sid: low, Attributes: SE_GROUP_INTEGRITY } }",
      )
      .replace(/sizeof\([^)]*\)/gu, "1")
      .replace(
        /\b(?:TOKEN_PRIVILEGES|TOKEN_GROUPS|TOKEN_MANDATORY_LABEL|SID_AND_ATTRIBUTES|DWORD|BOOL|HANDLE|LUID|PSID) \*?/gu,
        "var ",
      )
      .replaceAll("*session", "session.value")
      .replace(
        /(?<!&)&(privileges\.Privileges\[[^\]]+\]\.Luid|notify|restricting|integrity|off)\b/gu,
        "$1",
      )
      .replace(/(?<!&)&(token|low)\b/gu, "ref(()=>$1,v=>$1=v)")
      .replace(/\bL"/gu, '"');
  const peerBody = body(reader, "verify_access_peer_policy"),
    peer = peerBody.slice(
      peerBody.indexOf("  TOKEN_GROUPS *groups="),
      peerBody.indexOf("  BOOL belongs;"),
    ),
    gitBody = body(reader, "git_creator_token"),
    gitStart = gitBody.indexOf("    change_notify_privilege(token);"),
    git = gitBody.slice(gitStart, gitBody.indexOf("\n  }", gitStart));
  assert.ok(peer && gitStart > 0 && git);
  const program = new Script(`
    function change_notify_privilege(token){${project(body(account, "change_notify_privilege"))}}
    function construct(base,capability){${project(body(account, "restrict_token"))}}
    function peer(token,kind){var view={kind};${project(peer)}}
    function git(token){${project(git)}}
    ({construct,peer,git,guard:change_notify_privilege});
  `);
  const notify = { HighPart: 23, LowPart: 41 },
    entry = (Attributes = 3, Luid = notify) => ({
      Luid: { ...Luid },
      Attributes,
    });
  const fixture = (options = {}) => {
    const base = options.base ?? [
        entry(),
        entry(2, { HighPart: 9, LowPart: 7 }),
      ],
      after = options.after ?? [
        entry(base.find((p) => p.Luid.HighPart === 23)?.Attributes & 3),
      ],
      ordinary = { Sid: "ordinary", Attributes: 4 },
      integrity = { Sid: "integrity", Attributes: 0x20 },
      deny = { Sid: "deny", Attributes: 0x10 },
      calls = [];
    let error = 0,
      lookups = 0;
    const api = {
      NULL: null,
      FALSE: false,
      SE_CHANGE_NOTIFY_NAME: "SeChangeNotifyPrivilege",
      SE_PRIVILEGE_ENABLED: 2,
      SE_PRIVILEGE_ENABLED_BY_DEFAULT: 1,
      SE_PRIVILEGE_USED_FOR_ACCESS: 0x80000000,
      SE_GROUP_ENABLED: 4,
      SE_GROUP_INTEGRITY: 0x20,
      SE_GROUP_USE_FOR_DENY_ONLY: 0x10,
      TokenPrivileges: 1,
      TokenGroups: 2,
      TokenRestrictedSids: 3,
      TokenSessionId: 4,
      TokenIntegrityLevel: 5,
      TokenVirtualizationEnabled: 6,
      HANDLE_FLAG_INHERIT: 1,
      ERROR_INVALID_DATA: 13,
      ref: (get, set) => ({
        get value() {
          return get();
        },
        set value(value) {
          set(value);
        },
      }),
      token_info(token, kind) {
        calls.push([token, kind]);
        if (kind === 1) {
          const Privileges = token === "base" ? base : after;
          return structuredClone({
            PrivilegeCount:
              token === "base"
                ? (options.baseCount ?? Privileges.length)
                : Privileges.length,
            Privileges,
          });
        }
        if (kind === 2) {
          const Groups =
            token === "base"
              ? [ordinary, integrity, deny]
              : (options.groups ?? [
                  { ...ordinary, Attributes: 0x10 },
                  integrity,
                  deny,
                ]);
          return structuredClone({ GroupCount: Groups.length, Groups });
        }
        if (kind === 3) {
          const Groups = (options.restricting ?? ["private"]).map((Sid) => ({
            Sid,
          }));
          return { GroupCount: Groups.length, Groups };
        }
        assert.equal(kind, 4);
        return { value: 0 };
      },
      LookupPrivilegeValueW(_, name, out) {
        assert.equal(name, "SeChangeNotifyPrivilege");
        if (++lookups === options.lookupFailure) {
          error = 5;
          return false;
        }
        Object.assign(out, notify);
        return true;
      },
      CreateRestrictedToken(
        token,
        flags,
        disabledCount,
        disabled,
        deletedCount,
        deleted,
        restrictedCount,
        restricting,
        out,
      ) {
        assert.equal(token, "base");
        assert.equal(flags, 0);
        assert.equal(disabledCount, 1);
        assert.deepEqual(structuredClone(disabled[0]), ordinary);
        assert.deepEqual(
          structuredClone(Array.from(deleted).slice(0, deletedCount)),
          base.filter((p) => p.Luid.HighPart !== 23 || p.Luid.LowPart !== 41),
        );
        assert.equal(restrictedCount, 1);
        assert.equal(restricting.Sid, "private");
        calls.push(["create"]);
        out.value = "restricted";
        return true;
      },
      ConvertStringSidToSidW(_, out) {
        out.value = "low";
        return true;
      },
      SetTokenInformation: () => true,
      GetLengthSid: () => 1,
      IsTokenRestricted: () => true,
      EqualSid: (a, b) => a === b,
      SetHandleInformation: () => true,
      SetLastError: (value) => {
        error = value;
      },
      need: (value) => {
        if (!value) throw Object.assign(new Error("native refusal"), { error });
      },
      memcmp: (a, b) => Number(JSON.stringify(a) !== JSON.stringify(b)),
      free: () => {},
      LocalFree: () => {},
    };
    return { native: program.runInNewContext(api), calls };
  };
  for (const attributes of [2, 3, 0x80000002, 0x80000003]) {
    const f = fixture({
      base: [
        entry(2, { HighPart: 9, LowPart: 7 }),
        entry(attributes),
        entry(0, { HighPart: 4, LowPart: 5 }),
      ],
    });
    assert.equal(f.native.construct("base", "private"), "restricted");
    f.native.peer("restricted", 0);
    f.native.git("restricted");
    assert.ok(
      f.calls.filter(([token, kind]) => token === "restricted" && kind === 1)
        .length >= 3,
    );
  }
  for (const options of [
    { base: [] },
    { base: [entry(0)] },
    { base: [entry(1)] },
    { base: [entry(6)] },
    { base: [entry(10)] },
    { base: [entry(), entry()] },
    { base: [entry(2, { HighPart: 9, LowPart: 7 })] },
    { baseCount: 65 },
    { lookupFailure: 1 },
    { lookupFailure: 2 },
    { after: [] },
    { after: [entry(), entry()] },
    { after: [entry(0)] },
    { after: [entry(2)] },
    { after: [entry(3, { HighPart: 9, LowPart: 7 })] },
    { groups: [{ Sid: "ordinary", Attributes: 4 }] },
    { groups: [{ Sid: "ordinary", Attributes: 0 }] },
    { restricting: [] },
    { restricting: ["foreign"] },
    { restricting: ["private", "foreign"] },
  ]) {
    const f = fixture(options);
    assert.throws(
      () => f.native.construct("base", "private"),
      (cause) => cause.error === (options.lookupFailure ? 5 : 13),
    );
  }
  for (const after of [
    [],
    [entry(0)],
    [entry(6)],
    [entry(10)],
    [entry(), entry()],
    [entry(3, { HighPart: 9, LowPart: 7 })],
  ]) {
    const f = fixture({ after });
    assert.throws(() => f.native.peer("restricted", 0));
    assert.throws(() => f.native.git("restricted"));
  }
  fixture({ after: [] }).native.peer("restricted", 1); // Separate other-account policy is unchanged.
});

test("actual privilege emission is typed and unfiltered in both held readers and refuses malformed native names", async () => {
  const [reader, effective] = await Promise.all(
    ["custody-reader.c", "effective-reader.h"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const body = /static void emit_privilege\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    reader,
  )?.[1];
  assert.ok(body);
  const project = (value) =>
    value
      .replaceAll("->", ".")
      .replace("wchar_t name[128] = {0}", "var name=Array(128).fill(0)")
      .replaceAll("name + length - 9", "name.slice(length-9)")
      .replace(/\b(?:DWORD|BOOL|unsigned) /gu, "var ")
      .replaceAll("&value.Luid", "value.Luid")
      .replaceAll("&length", "ref(()=>length,v=>length=v)")
      .replace(/L'([^'])'/gu, (_, c) => String(c.charCodeAt(0)))
      .replace(/\bL"/gu, '"')
      .replaceAll("&privileges.Privileges[i]", "privileges.Privileges[i]");
  for (const source of [reader, effective]) {
    const loop = source
      .split("\n")
      .find(
        (line) =>
          line.includes("for (unsigned i") && line.includes("emit_privilege("),
      );
    assert.ok(loop);
    for (const fault of [
      null,
      "api",
      "empty",
      "truncated",
      "length",
      "unterminated",
      "invalid",
      "noncanonical",
    ]) {
      let output = "",
        error = 0;
      const text = (value) =>
        typeof value === "string"
          ? value
          : String.fromCharCode(
              ...value.slice(
                0,
                value.indexOf(0) < 0 ? value.length : value.indexOf(0),
              ),
            );
      const entries = [
        { Luid: { HighPart: 23, LowPart: 41 }, Attributes: 0x80000003 },
        { Luid: { HighPart: 5, LowPart: 7 }, Attributes: 0x40000000 },
      ];
      const api = {
        NULL: null,
        ERROR_INVALID_DATA: 13,
        privileges: { PrivilegeCount: 2, Privileges: entries },
        ref: (get, set) => ({
          get value() {
            return get();
          },
          set value(v) {
            set(v);
          },
        }),
        LookupPrivilegeNameW(_, luid, name, length) {
          assert.equal(length.value, 128);
          if (fault === "api") {
            error = 1313;
            return false;
          }
          const value =
            fault === "empty"
              ? ""
              : fault === "invalid"
                ? 'SeBad"Privilege'
                : fault === "noncanonical"
                  ? "OtherPrivilege"
                  : luid.HighPart === 23
                    ? "SeChangeNotifyPrivilege"
                    : "SeDebugPrivilege";
          for (let i = 0; i < value.length; i++) name[i] = value.charCodeAt(i);
          name[value.length] = fault === "unterminated" ? 88 : 0;
          length.value =
            fault === "truncated"
              ? 128
              : value.length + Number(fault === "length");
          return true;
        },
        wcslen: (value) => text(value).length,
        wcsncmp: (a, b, n) => Number(text(a).slice(0, n) !== b.slice(0, n)),
        wcscmp: (a, b) => Number(text(a) !== b),
        SetLastError: (value) => {
          error = value;
        },
        need: (value) => {
          if (!value)
            throw Object.assign(new Error("native refusal"), { error });
        },
        putchar: (value) => {
          output += value;
        },
        printf(format, ...values) {
          let i = 0;
          output += format.replace(/%08lx|%ls|%lu/gu, (kind) => {
            const value = values[i++];
            return kind === "%08lx"
              ? value.toString(16).padStart(8, "0")
              : kind === "%ls"
                ? text(value)
                : String(value);
          });
        },
      };
      const program = new Script(
        `function emit_privilege(value){${project(body)}}\n${project(loop)}`,
      );
      if (fault)
        assert.throws(
          () => program.runInNewContext(api),
          (cause) => cause.error === (fault === "api" ? 1313 : 13),
        );
      else
        assert.deepEqual(
          JSON.parse("[" + (program.runInNewContext(api), output) + "]"),
          [
            {
              luid: "0000001700000029",
              name: "SeChangeNotifyPrivilege",
              attributes: 0x80000003,
            },
            {
              luid: "0000000500000007",
              name: "SeDebugPrivilege",
              attributes: 0x40000000,
            },
          ],
        );
    }
  }
});

test("actual build-only creation separates UI-restricted Jobs without compiler breakaway authority", async () => {
  const [reader, helper] = await Promise.all(
    ["custody-reader.c", "build-helper.c"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const controller = reader.slice(
      reader.indexOf("static void start_helper("),
      reader.indexOf("static void build(void)"),
    ),
    policy = controller.slice(
      controller.indexOf("limits.BasicLimitInformation.LimitFlags ="),
      controller.indexOf("JOBOBJECT_BASIC_UI_RESTRICTIONS ui"),
    );
  for (const kind of [
    "build",
    "git",
    "file",
    "observer",
    "policy",
    "git-policy",
  ]) {
    const limits = { BasicLimitInformation: {} };
    new Script(policy.replace(/\/\*[\s\S]*?\*\//gu, "")).runInNewContext({
      limits,
      compiler: kind === "build",
      git: kind === "git",
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: 0x2000,
      JOB_OBJECT_LIMIT_ACTIVE_PROCESS: 8,
      JOB_OBJECT_LIMIT_BREAKAWAY_OK: 0x800,
    });
    assert.equal(
      limits.BasicLimitInformation.LimitFlags,
      kind === "build" ? 0x2808 : 0x2008,
    );
    assert.equal(
      limits.BasicLimitInformation.ActiveProcessLimit,
      ["build", "git"].includes(kind) ? 32 : 1,
    );
  }
  const flags =
    /CreateProcessW\(tool\.path, command, &private, &private, TRUE, ([^,]+), NULL/u.exec(
      helper,
    )[1];
  assert.equal(
    new Script(flags).runInNewContext({
      CREATE_BREAKAWAY_FROM_JOB: 0x1000000,
      CREATE_SUSPENDED: 4,
      CREATE_UNICODE_ENVIRONMENT: 0x400,
      EXTENDED_STARTUPINFO_PRESENT: 0x80000,
    }),
    0x1080404,
  );
  assert.equal(helper.match(/CREATE_BREAKAWAY_FROM_JOB/gu).length, 1);
  assert.ok(!controller.includes("CREATE_BREAKAWAY_FROM_JOB"));
  assert.match(
    helper,
    /LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE \| JOB_OBJECT_LIMIT_ACTIVE_PROCESS; limits.BasicLimitInformation.ActiveProcessLimit = 31;/u,
  );
  assert.match(
    helper,
    /HANDLE handles\[\] = \{childIn, childOut, childError\}/u,
  );
  assert.match(helper, /PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof\(job\)/u);
});

test("Windows build input bounds refuse invalid environment text before helper-start", async () => {
  const f = fixture({ build: true }),
    reader = f.reader(),
    request = f.buildRequest,
    baseline = { ...request.env },
    starts = () =>
      f.events.filter((event) => event.startsWith("helper-start "));
  await reader.start();
  for (const index of [f.buildEntry.helper, f.buildEntry.tool])
    await reader.open(index);
  for (const name of ["INCLUDE", "LIB", "SystemRoot", "PATH"]) {
    const maximum = name === "SystemRoot" ? 4095 : 16384;
    for (const value of [
      "x".repeat(maximum),
      "x".repeat(maximum + 1),
      "",
      "x\0y",
      "\n",
      "\u001f",
      "\u007f",
      "\ud800",
      "\udc00",
    ]) {
      Object.assign(request.env, baseline, { [name]: value });
      const before = starts().length,
        pending = reader.openBuild(
          request,
          { mode: "compiler-version" },
          f.buildEntry,
        );
      if (value.length === maximum) {
        const channel = await pending,
          args = starts()
            .at(-1)
            .split(" ")
            .slice(5, 19)
            .map((part) => Buffer.from(part, "hex").toString("utf16le"));
        assert.deepEqual(
          args.slice(10),
          ["INCLUDE", "LIB", "SystemRoot", "PATH"].map(
            (key) => request.env[key],
          ),
        );
        await channel.close();
      } else {
        await assert.rejects(pending);
        assert.equal(starts().length, before);
      }
    }
  }
  Object.assign(request.env, baseline, {
    INCLUDE: "i".repeat(16384),
    PATH: "p".repeat(16384),
  });
  const before = starts().length;
  await assert.rejects(
    reader.openBuild(request, { mode: "compiler-version" }, f.buildEntry),
  );
  assert.equal(
    starts().length,
    before,
    "Individually valid lists must still fit the quoted command",
  );
  assert.equal((await reader.close()).closed, true);
});

test("actual helper startup refuses invalid OS directories before launch effects", async () => {
  for (const environment of [
    { length: 0 },
    { length: 4096 },
    { terminated: false },
    { directory: "C:\\Bad|OS" },
  ]) {
    for (const kind of ["build", "file"]) {
      const source = await compilerTrustFixture({ entries: [], environment });
      assert.throws(() => source.startHelper(kind), /native guard rejected/u);
      assert.deepEqual(source.events, ["windows-directory"]);
      assert.deepEqual(source.helperStarts, []);
      assert.deepEqual(source.calls, []);
      assert.deepEqual(source.records, []);
    }
  }
});

test("Windows build quoting preserves UCRT literals and counts the final separator and NUL", () => {
  const image = "C:\\Fixture\\build-helper.exe",
    args = Array(14).fill("x");
  for (const value of ["λ雪😀", 'a"b', "tail\\", 'slash\\"quote']) {
    args[10] = value;
    assert.equal(
      windowsBuildHelperCommandLine(image, args),
      [image, ...args].map(quoteWindowsArgument).join(" ") + " ",
    );
  }
  for (const index of [2, 8, 12]) {
    args[index] = "x".repeat(4095);
    assert.doesNotThrow(() => windowsBuildHelperCommandLine(image, args));
    args[index] += "x";
    assert.throws(() => windowsBuildHelperCommandLine(image, args));
    args[index] = "x";
  }
  args[10] = "i".repeat(16384);
  assert.throws(
    () => quoteWindowsArgument(args[10]),
    "Generic quoting retains its original bound",
  );
  const remaining = 32766 - windowsBuildHelperCommandLine(image, args).length;
  args[13] += "p".repeat(remaining);
  assert.equal(windowsBuildHelperCommandLine(image, args).length, 32766);
  args[13] += "p";
  assert.throws(() => windowsBuildHelperCommandLine(image, args));
});

test("actual Windows decoder and child argument guards share only the build list capacity", async () => {
  const [header, reader, helper] = await Promise.all(
    ["custody.h", "custody-reader.c", "build-helper.c"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const definitions = [
      ...header.matchAll(/^#define (WINDOWS_BUILD_ENVIRONMENT_\w+) (.+)$/gmu),
    ]
      .map(([, name, value]) => `const ${name} = ${value};`)
      .join("\n"),
    body = header
      .slice(
        header.indexOf("static unsigned nibble("),
        header.indexOf("static void decode("),
      )
      .replace("static unsigned nibble(char value)", "function nibble(value)")
      .replace(
        /static void bounded_text\([^)]*\)/u,
        "function bounded_text(value, size, maximum)",
      )
      .replace(
        /static void decode_bounded\([^)]*\)/u,
        "function decode_bounded(bytes, out, maximum)",
      )
      .replaceAll("size_t ", "let ")
      .replace(
        "BYTE *target = (BYTE *)out;",
        "const target = new Uint8Array(out.buffer);",
      )
      .replaceAll("(BYTE)", "")
      .replace(/'([0-9a-f])'/gu, (_, value) => String(value.charCodeAt(0))),
    readerLoop =
      /  for \(unsigned i = 0; i < argc; i\+\+\) decode_bounded\([\s\S]*?(?=\n  need\(wcslen\(args\[0\]\))/u.exec(
        reader,
      )?.[0],
    helperLoop =
      /  for \(unsigned i = 3; i < 15; i\+\+\)[\s\S]*?(?=\n  wchar_t \*end;)/u.exec(
        helper,
      )?.[0];
  assert.ok(body && definitions && readerLoop && helperLoop);
  const length = (value) =>
      value.includes(0) ? value.indexOf(0) : value.length,
    native = new Script(`${definitions}\n${body}
      function decodeArguments(values, args, compiler, observer) {
        const argc = args.length; ${readerLoop.replace("unsigned i", "let i")}
      }
      function validateArguments(argv) { ${helperLoop.replace("unsigned i", "let i")} }
      ({decode_bounded, decodeArguments, validateArguments,
        maximum: WINDOWS_BUILD_ENVIRONMENT_MAX_UNITS,
        capacity: WINDOWS_BUILD_ENVIRONMENT_CAPACITY});`).runInNewContext({
      need: assert.ok,
      strlen: length,
      wcslen: length,
    }),
    wide = (value) =>
      Uint16Array.from(
        value
          .split("")
          .map((unit) => unit.charCodeAt(0))
          .concat(0),
      ),
    inspect = (args, compiler = true, observer = false) => {
      const decoded = args.map(() => new Uint16Array(native.capacity));
      native.decodeArguments(
        [...Array(5), ...args.map((value) => Buffer.from(hex(value), "ascii"))],
        decoded,
        compiler,
        observer,
      );
      return decoded;
    };
  assert.equal(native.maximum, WINDOWS_BUILD_ENVIRONMENT_MAX_UNITS);
  assert.equal(native.capacity, 16385);
  const observed = [
      [10, 663],
      [11, 376],
      [12, 10],
      [13, 4516],
    ],
    args = Array(14).fill("x");
  for (const [index, size] of observed)
    args[index] =
      index === 12 ? "C:\\Windows" : 'λ雪😀"'.padEnd(size - 1, "x") + "\\";
  const decoded = inspect(args);
  native.validateArguments([wide("helper"), ...decoded]);
  for (const [index, size] of observed)
    assert.deepEqual(
      Buffer.from(decoded[index].buffer).subarray(0, size * 2),
      Buffer.from(args[index], "utf16le"),
    );
  for (const [index, maximum] of [
    [10, 16384],
    [11, 16384],
    [13, 16384],
    [12, 4095],
    [2, 4095],
  ]) {
    for (const value of [
      "x".repeat(maximum),
      "x".repeat(maximum + 1),
      "",
      "\0",
      "\n",
      "\u001f",
      "\u007f",
      "\ud800",
      "\udc00",
      "\ud800x",
    ]) {
      const args = Array(14).fill("x");
      args[index] = value;
      if (value.length === maximum) {
        const decoded = inspect(args);
        assert.deepEqual(
          Buffer.from(decoded[index].buffer).subarray(0, value.length * 2),
          Buffer.from(value, "utf16le"),
        );
        native.validateArguments([wide("helper"), ...decoded]);
      } else {
        assert.throws(() => inspect(args));
        assert.throws(() =>
          native.validateArguments([wide("helper"), ...args.map(wide)]),
        );
      }
    }
    if (maximum === 16384) {
      const args = Array(14).fill("x");
      args[index] = "x".repeat(maximum);
      assert.throws(
        () => inspect(args, false),
        "Other helper kinds retain ordinary bounds",
      );
    }
  }
  const query = ["x", "x".repeat(16384)];
  assert.doesNotThrow(() => inspect(query, false, true));
  assert.throws(() => inspect(query, false, false));
  for (const encoded of ["", "123", "zzzz", hex("x\0y")])
    assert.throws(() =>
      native.decode_bounded(
        Buffer.from(encoded, "ascii"),
        new Uint16Array(16385),
        16385,
      ),
    );
});

test("Windows build publication joins held output and reviewed certificate image to independent closed-writer proof", async () => {
  for (const damage of [null, "image", "proof"]) {
    const f = fixture();
    f.input.context.executionId = "build";
    const request = { candidateSha, cwd: f.entries[1].path },
      operation = {
        mode: "compile",
        helper: { sha256: f.entries[0].sha256 },
        source: { path: "C:\\Fixture\\Sealed\\file-helper.c", sha256: hash },
        target: f.entries[1].path + "\\file-helper.exe",
      };
    request.args = windowsCompilerArguments(
      operation.source.path,
      operation.target,
    );
    f.options.damage = (op, frame) =>
      op === "publish-build"
        ? {
            ...frame,
            value: {
              identity: id(5),
              sha256: damage === "image" ? hash : f.entries[0].sha256,
              signatureSha256: hash,
              daclSha256: hash,
              writerClosed: true,
            },
          }
        : frame;
    f.options.verifyPublication = async (observations) => ({
      independent: true,
      verifier: f.verifier,
      observationsSha256:
        damage === "proof" ? hash : observationDigest(observations),
      protectedDacl: true,
      writerClosed: true,
      nativeEventSha256: hash,
      settlement: {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: hash,
      },
    });
    const reader = f.reader();
    await reader.start();
    await reader.open(0);
    await reader.open(1);
    const result = reader.publishBuild(request, operation, hash, {
      image: 0,
      root: 1,
    });
    if (damage) await assert.rejects(result);
    else {
      assert.equal((await result).imageSha256, f.entries[0].sha256);
      assert.ok(f.records.some((record) => record.phase === "build-published"));
    }
    await reader.close();
  }
});

test("Windows child exit never replaces independent domain retirement or owned task removal", async () => {
  for (const name of ["verifyRetirement", "verifyTaskRemoval"]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    f.options[name] = async () => ({ status: "RETAINED", independent: false });
    assert.equal((await reader.close()).status, "RETAINED");
    assert.equal(f.records.at(-1).custody, "POSSIBLE");
    if (name === "verifyRetirement")
      assert.ok(!f.events.some((event) => event.startsWith("finish ")));
  }
});

test("Windows task removal requires the original finish response, held exit and durable acknowledgement", async () => {
  for (const fault of [null, "lost", "identity", "persist", "removal"]) {
    const f = fixture(),
      reader = f.reader(),
      primary = new Error("lost original completion"),
      cleanup = new Error("removal response lost");
    await reader.start();
    const receive = f.owner.receive,
      send = f.owner.send,
      persist = f.options.persist;
    f.owner.receive = async () => {
      const frame = await receive();
      if (fault === "lost" && frame.value?.closed) throw primary;
      if (fault === "identity" && frame.phase === "helper-retired")
        frame.helper.pid++;
      return frame;
    };
    f.options.persist = async (record) => {
      if (fault === "persist" && record.phase === "finish-acknowledged")
        throw cleanup;
      return persist(record);
    };
    f.owner.send = async (line) => {
      if (line === "D") {
        assert.ok(
          f.records.some((record) => record.phase === "finish-acknowledged"),
        );
        if (fault === "removal") throw cleanup;
      }
      return send(line);
    };
    const result = await reader.close();
    assert.equal(result.status, fault ? "RETAINED" : "RETIRED");
    if (fault) {
      assert.equal(result.independent, false);
      if (fault === "lost") assert.equal(result.primaryCause, primary);
      assert.equal(f.events.includes("D"), false);
      assert.equal(f.events.includes("verify-removal"), false);
      assert.equal(f.records.at(-1).command.name, "finish");
    } else {
      assert.ok(
        f.events.indexOf("persist-finish-acknowledged") < f.events.indexOf("D"),
      );
      assert.ok(f.events.indexOf("D") < f.events.indexOf("verify-removal"));
    }
  }
});

test("Windows helper retirement cannot discard unread private output", async () => {
  const f = fixture(),
    reader = f.reader();
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  const helper = await reader.openFile(f.file, f.transfer);
  f.options.damage = (op, frame) => {
    if (op === "helper-finish") frame.value.drained = false;
    return frame;
  };
  await assert.rejects(helper.close());
  assert.equal((await reader.close()).status, "RETAINED");
});

function transport({ holdWrites = false } = {}) {
  const child = new EventEmitter();
  child.pid = 10;
  child.stdin = new Writable({
    write(_, __, done) {
      if (!holdWrites) done();
    },
  });
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  let deadline;
  const channel = windowsCustodyChannel(child, {
    schedule(callback, ms) {
      assert.equal(ms, WINDOWS_CUSTODY_DEADLINE_MS);
      deadline = callback;
      return 1;
    },
    cancel() {},
  });
  return { child, channel, expire: () => deadline() };
}
test("Windows private transport rejects truncation, malformed bytes, unread frames and expired completion", async () => {
  const pending = transport(),
    read = pending.channel.receive();
  pending.expire();
  await assert.rejects(read);
  await assert.rejects(pending.channel.completion);
  const malformed = transport(),
    bad = malformed.channel.receive();
  malformed.child.stdout.write(Buffer.from([0xff, 10]));
  await assert.rejects(bad);
  const truncated = transport(),
    frame = truncated.channel.receive();
  truncated.child.stdout.write('{"phase":');
  truncated.child.emit("close", 0, null);
  await assert.rejects(frame);
  await assert.rejects(truncated.channel.completion);
  const trailing = transport();
  trailing.child.stdout.write("{}\n");
  trailing.child.emit("close", 0, null);
  await assert.rejects(trailing.channel.completion);
  const exited = transport(),
    verification = exited.channel.wait(new Promise(() => {}));
  exited.child.emit("close", 0, null);
  exited.expire();
  await assert.rejects(verification);
  const writing = transport({ holdWrites: true }),
    written = assert.rejects(writing.channel.send("P\n"));
  writing.child.emit("close", 0, null);
  try {
    await assert.rejects(writing.channel.completion);
    assert.throws(() => writing.channel.settle());
  } finally {
    writing.channel.close();
    await written;
  }
});
test("Windows terminal reader faults settle outstanding work before bridge exit without retiring it", async () => {
  for (const diagnostic of [false, true]) {
    const f = transport({ holdWrites: true }),
      work = [
        f.channel.send("open 2 14\n"),
        f.channel.receive(),
        f.channel.wait(new Promise(() => {})),
        f.channel.completion,
      ],
      rejected = Promise.all(
        work.map((value) => value.catch((cause) => cause)),
      );
    let exited = false;
    f.channel.exited.then(() => {
      exited = true;
    });
    if (diagnostic)
      f.child.stdout.write(
        '\x1e{"phase":"reader-failure","sequence":2,"command":"open","source":"custody.h","line":1}\n',
      );
    else f.child.stdout.emit("end");
    const causes = await rejected;
    assert.ok(causes[0] instanceof Error);
    assert.ok(causes.every((cause) => cause === causes[0]));
    assert.equal(!!causes[0].custodyReaderFailure, diagnostic);
    assert.equal(exited, false);
    f.child.emit("close", 126, null);
    assert.deepEqual(await f.channel.exited, { code: 126, signal: null });
    assert.throws(() => f.channel.settle());
  }
});

test("Windows reader failure rejects queued commands while the dependent journal remains pending", async () => {
  const f = fixture(),
    reader = f.reader(),
    fault = Promise.withResolvers(),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers(),
    waiting = Promise.withResolvers(),
    exited = Promise.withResolvers(),
    primary = new Error("original reader EOF");
  fault.promise.catch(() => {});
  f.owner.wait = (value) => Promise.race([value, fault.promise]);
  await reader.start();
  const persist = f.options.persist;
  f.options.persist = async (record) => {
    await persist(record);
    if (record.phase === "open") {
      entered.resolve();
      await release.promise;
    }
  };
  const first = reader.open(3),
    queued = reader.open(2),
    rejected = Promise.all(
      [first, queued].map((value) =>
        assert.rejects(value, (cause) => cause === primary),
      ),
    );
  await entered.promise;
  fault.reject(primary);
  await rejected;
  assert.ok(!f.events.some((event) => /^open [0-9]/u.test(event)));
  release.resolve();
  assert.equal(reader.transportFailed, true);
  assert.equal(reader.failure, primary);
  Object.defineProperty(f.owner, "exited", {
    get() {
      waiting.resolve();
      return exited.promise;
    },
  });
  let closed = false;
  const closing = reader
    .close({ signal: new AbortController().signal })
    .then((result) => {
      closed = true;
      return result;
    });
  await waiting.promise;
  assert.equal(
    closed,
    false,
    "A rejected command is not actual transport closure",
  );
  exited.resolve({ code: 126, signal: null });
  const result = await closing;
  assert.equal(result.status, "RETAINED");
  assert.equal(result.primaryCause, primary);
  assert.ok(!f.events.some((event) => /^open [0-9]/u.test(event)));
});

test("actual witness completion preserves original child and parent refusals before fencing", async () => {
  const [source, header] = await Promise.all(
    ["custody-reader.c", "custody.h"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const start = source.indexOf(
      "  HANDLE *inherited = reader_witness_resources.inherited;",
      source.indexOf("static void ownership_fresh("),
    ),
    end = source.indexOf("\n}\nstatic void ownership_send", start),
    guard = /static void need_at\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(header)[1];
  assert.ok(start > 0 && end > start);
  const body = (name) =>
    new RegExp(
      `static (?:void|BOOL|HANDLE) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const translate = (body) =>
    body
      .replace(/#ifdef NATIVE_CUSTODY_FAILURE\n([\s\S]*?)#endif/gu, "$1")
      .replaceAll("NATIVE_CUSTODY_FAILURE", "reader_failure")
      .replace("char result[65536]", "const result = Buffer.alloc(65536)")
      .replace(
        "char frame[9216], encoded[2049] = {0}; DWORD written;",
        'const frame={text:""},encoded={text:""}; let written;',
      )
      .replace(
        'char bytes[1024], transfer[256] = ""; DWORD written;',
        'const bytes={text:""},transfer={text:""}; let written;',
      )
      .replace("const char *source", "let source")
      .replace("source+1", "source.slice(1)")
      .replace("const char *operation", "let operation")
      .replace(
        "HANDLE creators[] = {ownership_launcher.hProcess, ownership_owner.hProcess};",
        "const creators = [ownership_launcher.hProcess, ownership_owner.hProcess];",
      )
      .replaceAll("sizeof(creators)/sizeof(creators[0])", "creators.length")
      .replaceAll("sizeof(handles)/sizeof(handles[0])", "handles.length")
      .replace(/HANDLE \*(inherited|value)\b/gu, "let $1")
      .replace(/HANDLE \*handles\[\] = \{([^}]+)\}/u, "const handles = [$1]")
      .replace(/\*handles\[i\]/gu, "handles[i].value")
      .replace(/\*value\b/gu, "value.value")
      .replaceAll("sizeof(frame)", "9216")
      .replaceAll("sizeof(encoded)", "2049")
      .replaceAll("sizeof(transfer)", "256")
      .replaceAll("sizeof(bytes)", "1024")
      .replaceAll("encoded+i*2", "{target:encoded,offset:i*2}")
      .replaceAll("\\036", "\\x1e")
      .replace(
        "JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = {0}",
        "const accounting = {}",
      )
      .replace(
        "JOBOBJECT_ASSOCIATE_COMPLETION_PORT association = {0}",
        "const association = {}",
      )
      .replace(
        "JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0}",
        "const limits = {BasicLimitInformation:{}}",
      )
      .replace("STARTUPINFOEXW start = {0}", "const start = {StartupInfo:{}}")
      .replace(
        "FILETIME birth, exit, kernel, user",
        "const birth={},exit={},kernel={},user={}",
      )
      .replace(
        "((ULONGLONG)birth.dwHighDateTime << 32) | birth.dwLowDateTime",
        "birth.dwHighDateTime * 2 ** 32 + birth.dwLowDateTime",
      )
      .replace(/wchar_t (name|command)\[(128|8192)\]/gu, "const $1 = {text:''}")
      .replace(
        "PROCESS_INFORMATION child = {0}",
        "const child = {hProcess:null,hThread:null}",
      )
      .replace("BYTE extra", "const extra = {}")
      .replaceAll("sizeof(result)", "65536")
      .replaceAll(
        /sizeof\((?:accounting|association|limits|start|view|job|HANDLE)\)/gu,
        "1",
      )
      .replaceAll(
        "&reader_witness_resources.inherited[i]",
        "ref(reader_witness_resources.inherited,i)",
      )
      .replaceAll("&inherited[i]", "ref(inherited,i)")
      .replace(
        /&view\.(files|tokens|processes)\[([^\]]+)\]/gu,
        "ref(view.$1,$2)",
      )
      .replace(/&view\.([a-zA-Z]+)\b/gu, 'ref(view,"$1")')
      .replace(
        /&reader_witness_resources\.child\.(hThread|hProcess)/gu,
        'ref(reader_witness_resources.child,"$1")',
      )
      .replace(
        /&reader_witness_resources\.(input|output|port|job)\b/gu,
        'ref(reader_witness_resources,"$1")',
      )
      .replaceAll(
        "&reader_witness_resources.child",
        "reader_witness_resources.child",
      )
      .replaceAll(
        /&(accounting|association|limits|start\.StartupInfo|view|private|sa|birth|kernel|user|extra|child)\b/gu,
        "$1",
      )
      .replace("&exit, &kernel", "exit, kernel")
      .replace(
        /&(exit|used|belongs|returned|message|key|payload|bytes|written|job|input|output|duplicate)\b/gu,
        (_, name) =>
          `({get value(){return ${name}},set value(value){${name}=value}})`,
      )
      .replaceAll("*owned", "owned.value")
      .replace(
        /\((?:DWORD|ULONG_PTR|PVOID|ULONGLONG|unsigned long long|unsigned|int)\)/gu,
        "",
      )
      .replace(
        /\b(?:DWORD|BOOL|HANDLE|ULONGLONG|ULONG_PTR|LPOVERLAPPED|PSECURITY_DESCRIPTOR|SECURITY_ATTRIBUTES|SIZE_T|size_t|unsigned|int) /gu,
        "let ",
      )
      .replace(/\bL"/gu, '"')
      .replace(/\bprivate\b/gu, "privateAttributes");
  const program = new Script(`
    function need_at(ok,file,line){${translate(guard)}}
    function need(ok){need_at(ok,"custody-reader.c",1);}
    function recovery_job(attributes){${translate(body("recovery_job"))}}
    function ownership_witness_cleanup_error(operation,error){${translate(body("ownership_witness_cleanup_error"))}}
    function ownership_witness_handle_close(owned){${translate(body("ownership_witness_handle_close"))}}
    function ownership_witness_close(){${translate(body("ownership_witness_close"))}}
    function reader_witness_failure(source,line,error){${translate(body("reader_witness_failure"))}}
    function ownership_failure_fence(error){${translate(body("ownership_failure_fence"))}}
    function reader_failure(file,line,error){${translate(body("reader_failure"))}}
    ${translate(source.slice(start, end))}
  `);
  const pid = 41,
    zero = 4,
    born = 6,
    exited = 7,
    abnormal = 8;
  let sample, completionSample, notificationSample, sizeSample;
  for (const [fault, operation, actual, error = 0, outsideControl = false] of [
    [null],
    [null, undefined, undefined, 0, true],
    ["delayed"],
    ["lifecycle"],
    ["lost-zero"],
    ["deadline-zero"],
    ["active", "ActiveProcesses", 1],
    ["notification-only", "ActiveProcesses", 1],
    ["packet-cap", "ActiveProcesses", 1],
    ["wrong-key", "job-notification", zero],
    ["zero-payload", "job-notification", zero],
    ["wrong-pid", "job-notification", born],
    ["unknown", "job-notification", 999],
    ["unexpected", "job-notification", 3],
    ["completion-api", "GetQueuedCompletionStatus", 0, 5],
    ["failed-packet", "GetQueuedCompletionStatus", 0, 258],
    ["accounting-size", "accounting-size", 0],
    ["accounting-after-wakeup", "QueryInformationJobObject", 0, 87],
    ["wait-failed", "WaitForSingleObject", 0xffffffff, 5],
    ["wait-timeout", "WaitForSingleObject", 258],
    ["exit-query", "GetExitCodeProcess", 0, 5],
    ["child-exit", "child-exit", 126],
    ["child-exit", "child-exit", 126, 0, true],
    ["accounting-query", "QueryInformationJobObject", 0, 87],
    ["diagnostic", "child-exit", 126],
    ["format", "child-exit", 126],
    ["cleanup", "child-exit", 126],
    ["truncated", "child-exit", 126],
    ["maximum", "child-exit", 126],
    ["binary", "child-exit", 126],
    ["empty", "child-exit", 126],
    ["input-pipe", null, 0, 5],
    ["output-pipe", null, 0, 5],
    ["parent-inherit", null, 0, 5],
    ["duplicate-file", null, 0, 5],
    ["duplicate-process", null, 0, 5],
    ["duplicate-pin", null, 0, 5],
    ["job-create", null, 0, 5],
    ["job-collision", null, 0, 183],
    ["port-create", null, 0, 5],
    ["port-inherit", null, 0, 5],
    ["association", null, 0, 5],
    ["association-cleanup", null, 0, 5],
    ["limits", null, 0, 5],
    ["allocation", null, 0, 8],
    ["attributes", null, 0, 5],
    ["handle-list", null, 0, 5],
    ["job-list", null, 0, 5],
    ["command", null, 0, 5],
    ["launch", null, 0, 5],
    ["inherit-close", null, 0, 5],
    ["system-process", null, 0, 5],
    ["resume", null, 0, 5],
    ["input-write", null, 0, 5],
    ["input-close", null, 0, 5],
    ["eof", null, 0, 5],
    ["outside", null, 0, 5, true],
    ["final-close", null, 0, 5],
  ]) {
    const refuses = operation !== undefined,
      calls = [],
      diagnostics = [],
      frames = [],
      waits = [],
      f = transport(),
      pending = f.channel.receive().catch((cause) => cause),
      completion = f.channel.completion.catch((cause) => cause),
      refused = new Error("exit 126"),
      inherited = Array(208).fill(null),
      owned = new Set(),
      released = new Set(),
      resources = {
        inherited,
        input: null,
        output: null,
        job: null,
        port: null,
        child: { hProcess: null, hThread: null },
        attributes: null,
        attributesReady: false,
        cleanupFailed: false,
        cleanupError: 0,
        descriptor: null,
      },
      exitCode = [
        "child-exit",
        "diagnostic",
        "format",
        "cleanup",
        "truncated",
        "maximum",
        "binary",
        "empty",
      ].includes(fault)
        ? 126
        : 0,
      childLine =
        fault === "binary"
          ? Buffer.from([0x1e, 34, 92, 0x7f])
          : Buffer.from(
              fault === "active"
                ? "opaque".repeat(399).slice(0, 2391)
                : fault === "truncated"
                  ? "x".repeat(2048)
                  : fault === "maximum"
                    ? "x".repeat(65534)
                    : fault === "empty"
                      ? ""
                      : exitCode
                        ? "native-windows-guard: file=witness.c line=7 last-error=5"
                        : '{"held":true}',
            ),
      waited =
        fault === "wait-failed"
          ? 0xffffffff
          : fault === "wait-timeout"
            ? 258
            : 0,
      exitAvailable = waited === 0 && fault !== "exit-query",
      accountingAvailable =
        exitAvailable &&
        !exitCode &&
        ![
          "accounting-query",
          "accounting-size",
          "accounting-after-wakeup",
        ].includes(fault),
      accountValues =
        fault === "packet-cap"
          ? Array(18).fill(1)
          : ["active", "notification-only"].includes(fault)
            ? [1, 1, 1]
            : [
                  "delayed",
                  "lifecycle",
                  "lost-zero",
                  "deadline-zero",
                  "accounting-after-wakeup",
                ].includes(fault)
              ? fault === "lifecycle"
                ? [1, 1, 1, 0]
                : [1, 0]
              : [
                    "wrong-key",
                    "zero-payload",
                    "wrong-pid",
                    "unknown",
                    "unexpected",
                    "completion-api",
                    "failed-packet",
                  ].includes(fault)
                ? [1]
                : [0],
      packets =
        fault === "lifecycle"
          ? [born, abnormal, exited]
          : fault === "packet-cap"
            ? Array(16).fill(born)
            : [
                  "delayed",
                  "notification-only",
                  "accounting-after-wakeup",
                  "wrong-key",
                  "zero-payload",
                ].includes(fault)
              ? [zero]
              : fault === "wrong-pid"
                ? [born]
                : fault === "unknown"
                  ? [999]
                  : fault === "unexpected"
                    ? [3]
                    : [];
    const text = (value) =>
      Buffer.isBuffer(value)
        ? value
            .subarray(0, value.indexOf(0) < 0 ? value.length : value.indexOf(0))
            .toString()
        : (value?.text ?? value);
    const format = (pattern, values) => {
      let index = 0;
      return pattern.replace(/%(02x|llu|zu|lu|hs|ls|[us])/gu, (_, kind) => {
        const value = values[index++];
        return ["s", "hs", "ls"].includes(kind)
          ? String(text(value))
          : kind === "02x"
            ? Number(value).toString(16).padStart(2, "0")
            : String(Number(value));
      });
    };
    let lastError = 122,
      output = "",
      accountReads = 0,
      packetReads = 0,
      ticks = 0,
      descriptorClosed = false,
      attributesFreed = false,
      attributesDeleted = false,
      pipeCreates = 0;
    const failApi = (name, value = true, code = 5) => {
      const failed =
        fault === name ||
        (fault === "association-cleanup" && name === "association");
      calls.push(name);
      lastError = failed ? code : 122;
      return failed ? false : value;
    };
    const api = {
      Buffer,
      outsideControl,
      self: "reader.exe",
      view: {
        files: ["source-file", null, null, null, null, null],
        count: 1,
        processes: ["source-process"],
        tokens: ["source-token"],
        sources: 1,
        pins: [{ file: "source-pin" }],
      },
      nonce: "a".repeat(32),
      recovery_job_count: 0,
      reader_witness_resources: resources,
      case_job: "domain",
      ownership_count: 1,
      ownership_released: false,
      ownership_creation_verified: false,
      ownership_launcher: { hProcess: "launcher" },
      ownership_owner: { hProcess: "owner" },
      reader_witness: { active: false, child: Buffer.alloc(1024) },
      reader_diagnostics_ready: true,
      ownership_refusal_collect: () => {},
      refusal_settle: () => {},
      reader_command: outsideControl
        ? "ownership-outside-control"
        : "ownership-witness",
      sequence: 2,
      control: "authenticated",
      stderr: "stderr",
      reader_transfer: { active: false },
      signature_trust: { active: false },
      ownership_failure_write: () => {
        assert.equal(
          api.reader_witness.active,
          false,
          "Launcher diagnostic shadowed the witness",
        );
        return false;
      },
      reader_cold_failure: () => false,
      reader_baseline_failure: () => false,
      reader_scheduler_failure: () => false,
      reader_open_failure: () => false,
      reader_context_failure: () => false,
      strrchr: (value, separator) =>
        value.includes(separator)
          ? value.slice(value.lastIndexOf(separator))
          : null,
      ref: (target, key) => ({
        get value() {
          return target[key];
        },
        set value(value) {
          target[key] = value;
        },
      }),
      TRUE: true,
      FALSE: false,
      NULL: null,
      ERROR_SUCCESS: 0,
      ERROR_BROKEN_PIPE: 109,
      ERROR_ALREADY_EXISTS: 183,
      WAIT_OBJECT_0: 0,
      WAIT_TIMEOUT: 258,
      WAIT_FAILED: 0xffffffff,
      INVALID_HANDLE_VALUE: -1,
      HANDLE_FLAG_INHERIT: 1,
      DUPLICATE_SAME_ACCESS: 2,
      JobObjectBasicAccountingInformation: 1,
      JobObjectAssociateCompletionPortInformation: 2,
      JobObjectExtendedLimitInformation: 3,
      PROC_THREAD_ATTRIBUTE_HANDLE_LIST: 4,
      PROC_THREAD_ATTRIBUTE_JOB_LIST: 5,
      STARTF_USESTDHANDLES: 1,
      CREATE_SUSPENDED: 4,
      EXTENDED_STARTUPINFO_PRESENT: 0x80000,
      CREATE_BREAKAWAY_FROM_JOB: 0x1000000,
      JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: zero,
      JOB_OBJECT_MSG_NEW_PROCESS: born,
      JOB_OBJECT_MSG_EXIT_PROCESS: exited,
      JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS: abnormal,
      GetLastError: () => lastError,
      SetLastError: (value) => {
        lastError = value;
      },
      strlen: (value) =>
        Buffer.isBuffer(value) ? value.indexOf(0) : value.length,
      memcpy: (target, value, size) => value.copy(target, 0, 0, size),
      GetCurrentProcess: () => "self",
      GetCurrentProcessId: () => 17,
      descriptor: () => "descriptor",
      attributes: (_descriptor, inherit) => ({ inherit }),
      CreatePipe: (read, write, attributes) => {
        assert.equal(attributes.inherit, true);
        const first = pipeCreates++ === 0;
        if (!failApi(first ? "input-pipe" : "output-pipe")) {
          read.value = "unowned-read";
          write.value = "unowned-write";
          return false;
        }
        read.value = first ? "inherited-input" : "pipe";
        write.value = first ? "input" : "inherited-output";
        owned.add(read.value);
        owned.add(write.value);
        return true;
      },
      DuplicateHandle: (
        process,
        source,
        target,
        duplicate,
        access,
        inherit,
        flags,
      ) => {
        assert.deepEqual(
          [process, target, access, inherit, flags],
          ["self", "self", 0, true, 2],
        );
        const name = "duplicate-" + source.slice("source-".length);
        if (!failApi(name)) {
          duplicate.value = "unowned-duplicate";
          return false;
        }
        duplicate.value = name;
        owned.add(name);
        return true;
      },
      GetProcessTimes: (_process, birth) => {
        birth.dwHighDateTime = 1;
        birth.dwLowDateTime = 2;
        return true;
      },
      CreateJobObjectW: () => {
        calls.push("job-create");
        lastError =
          fault === "job-create" ? 5 : fault === "job-collision" ? 183 : 0;
        if (fault === "job-create") return null;
        owned.add("job");
        return "job";
      },
      CreateIoCompletionPort: (file, port, key, concurrency) => {
        assert.deepEqual([file, port, key, concurrency], [-1, null, 0, 1]);
        if (!failApi("port-create")) return null;
        owned.add("port");
        return "port";
      },
      SetHandleInformation: (port, flag, value) => {
        assert.ok(["input", "pipe", "port"].includes(port));
        assert.deepEqual([flag, value], [1, 0]);
        return failApi(port === "port" ? "port-inherit" : "parent-inherit");
      },
      SetInformationJobObject: (job, kind, value) => {
        assert.equal(job, "job");
        if (kind === 2) {
          assert.deepEqual(
            [value.CompletionKey, value.CompletionPort],
            ["job", "port"],
          );
          return failApi("association");
        }
        assert.deepEqual(
          [
            kind,
            value.BasicLimitInformation.LimitFlags,
            value.BasicLimitInformation.ActiveProcessLimit,
          ],
          [3, 0x2008, 1],
        );
        return failApi("limits");
      },
      InitializeProcThreadAttributeList: (list, _count, _flags, size) => {
        if (!list) {
          size.value = 1;
          return false;
        }
        return failApi("attributes");
      },
      calloc: () => failApi("allocation", {}, 8) || null,
      UpdateProcThreadAttribute: (_list, _flags, kind, value, size) => {
        if (kind === 4) {
          assert.deepEqual(value.slice(0, size), [
            "inherited-input",
            "inherited-output",
            "duplicate-file",
            "duplicate-process",
            "duplicate-token",
            "duplicate-pin",
          ]);
          assert.ok(!value.includes("port"));
          return failApi("handle-list");
        }
        assert.equal(value.value, "job");
        return failApi("job-list");
      },
      CreateProcessW: (
        image,
        command,
        _process,
        _thread,
        inherit,
        flags,
        _env,
        _cwd,
        start,
        child,
      ) => {
        assert.equal(image, "reader.exe");
        assert.equal(inherit, true);
        assert.equal(flags, 4 | 0x80000 | (outsideControl ? 0x1000000 : 0));
        assert.ok(calls.indexOf("association") < calls.indexOf("job-list"));
        assert.deepEqual(
          [start.hStdInput, start.hStdOutput, start.hStdError],
          ["inherited-input", "inherited-output", "inherited-output"],
        );
        if (!failApi("launch")) {
          child.hProcess = "unowned-process";
          child.hThread = "unowned-thread";
          return false;
        }
        child.hProcess = "process";
        child.hThread = "thread";
        child.dwProcessId = pid;
        owned.add("process");
        owned.add("thread");
        return true;
      },
      system_process: () => failApi("system-process"),
      ResumeThread: () => failApi("resume", 1),
      DeleteProcThreadAttributeList: () => {
        assert.equal(attributesDeleted, false);
        attributesDeleted = true;
        calls.push("attributes-delete");
      },
      free: (value) => {
        if (!value) return;
        assert.equal(attributesFreed, false);
        attributesFreed = true;
        calls.push("attributes-free");
      },
      LocalFree: () => {
        assert.equal(descriptorClosed, false);
        descriptorClosed = true;
        calls.push("descriptor-free");
        lastError = 90;
        return fault === "cleanup" ? "descriptor" : null;
      },
      line: (pipe, value, maximum) => {
        assert.equal(pipe, "pipe");
        assert.equal(maximum, 65536);
        calls.push("line");
        childLine.copy(value);
      },
      GetTickCount64: () => {
        ticks++;
        return ticks === 1
          ? 100
          : fault === "deadline-zero" ||
              (fault === "notification-only" && ticks > 2)
            ? 30100
            : 100 + (ticks - 1) * 100;
      },
      WaitForSingleObject: (process, deadline) => {
        if (process !== "process") {
          assert.ok(["launcher", "owner"].includes(process));
          assert.equal(deadline, 0);
          calls.push("fence-wait-" + process);
          lastError = 77;
          return fault === "cleanup" && process === "launcher"
            ? 0xffffffff
            : 258;
        }
        assert.equal(deadline, 30000);
        calls.push("wait");
        lastError = 5;
        return waited;
      },
      TerminateJobObject: (job, code) => {
        assert.deepEqual([job, code], ["domain", 126]);
        calls.push("fence-job");
        lastError = 78;
        return fault !== "cleanup";
      },
      TerminateProcess: (process, code) => {
        assert.ok(["launcher", "owner"].includes(process));
        assert.equal(code, 126);
        calls.push("fence-" + process);
        lastError = 79;
        return fault !== "cleanup";
      },
      GetExitCodeProcess: (process, out) => {
        assert.equal(process, "process");
        calls.push("exit");
        out.value = fault === "exit-query" ? 999 : exitCode;
        lastError = 5;
        return fault !== "exit-query";
      },
      QueryInformationJobObject: (job, kind, accounting, size, returned) => {
        assert.deepEqual([job, kind, size], ["job", 1, 1]);
        assert.ok(!released.has("process"));
        calls.push("accounting");
        accounting.ActiveProcesses =
          accountValues[Math.min(accountReads, accountValues.length - 1)];
        const failed =
          fault === "accounting-query" ||
          (fault === "accounting-after-wakeup" && accountReads === 1);
        returned.value = fault === "accounting-size" ? 0 : 1;
        accountReads++;
        lastError = failed ? 87 : 122;
        return !failed;
      },
      GetQueuedCompletionStatus: (port, message, key, payload, remaining) => {
        assert.equal(port, "port");
        assert.ok(!released.has("process"));
        assert.equal(output, "");
        assert.equal(remaining, 30000 - (ticks - 1) * 100);
        waits.push(remaining);
        calls.push("packet");
        const value = packets[packetReads++];
        key.value = fault === "wrong-key" ? "foreign-job" : "job";
        payload.value =
          value === zero
            ? fault === "zero-payload"
              ? pid
              : null
            : fault === "wrong-pid"
              ? pid + 1
              : pid;
        message.value = value ?? 0;
        if (["completion-api", "failed-packet"].includes(fault)) {
          payload.value = fault === "failed-packet" ? pid : null;
          lastError = fault === "failed-packet" ? 258 : 5;
          return false;
        }
        if (value === undefined) {
          payload.value = null;
          lastError = 258;
          return false;
        }
        lastError = 122;
        return true;
      },
      ReadFile: (pipe, _extra, size, used, overlapped) => {
        assert.deepEqual([pipe, size, overlapped], ["pipe", 1, null]);
        calls.push("eof");
        used.value = 0;
        lastError = fault === "eof" ? 5 : 109;
        return false;
      },
      IsProcessInJob: (process, job, belongs) => {
        assert.deepEqual([process, job], ["process", "domain"]);
        belongs.value = false;
        return failApi("outside");
      },
      CloseHandle: (handle) => {
        assert.ok(owned.has(handle), "unowned close " + handle);
        assert.ok(!released.has(handle), "repeated close " + handle);
        released.add(handle);
        calls.push("close-" + handle);
        lastError = fault === "association-cleanup" ? 6 : 5;
        return !(
          (fault === "association-cleanup" &&
            ["port", "job"].includes(handle)) ||
          (fault === "cleanup" && ["pipe", "port", "job"].includes(handle)) ||
          (fault === "inherit-close" && handle === "inherited-input") ||
          (fault === "input-close" && handle === "input") ||
          (fault === "final-close" && handle === "pipe")
        );
      },
      fprintf: (_stream, pattern, ...values) => {
        diagnostics.push(format(pattern, values));
        lastError = 99;
        return fault === "diagnostic" ? -1 : 1;
      },
      fflush: () => {
        lastError = 88;
        return -1;
      },
      sprintf_s: (out, maximum, pattern, ...values) => {
        if (fault === "format" && pattern.startsWith("\x1e")) return -1;
        const value = format(pattern, values);
        assert.ok(Buffer.byteLength(value) < maximum);
        if (out.target)
          out.target.text = out.target.text.slice(0, out.offset) + value;
        else out.text = value;
        lastError = 80;
        return value.length;
      },
      swprintf_s: (out, _maximum, pattern, ...values) => {
        if (pattern.includes("--ownership-witness") && !failApi("command"))
          return -1;
        out.text = format(pattern, values);
        return out.text.length;
      },
      WriteFile: (handle, value, size, used) => {
        if (handle === "input") {
          assert.equal(size, 1);
          used.value = 1;
          return failApi("input-write");
        }
        assert.equal(handle, "authenticated");
        calls.push("diagnostic-write");
        lastError = 81;
        if (fault === "diagnostic") return false;
        used.value = size;
        frames.push(value.text);
        f.child.stdout.write('{"sequence":2,"value":');
        for (let offset = 0; offset < size; offset += 37)
          f.child.stdout.write(value.text.slice(offset, offset + 37));
        return true;
      },
      ExitProcess: (code) => {
        assert.equal(code, 126);
        throw refused;
      },
      printf: (pattern, value) => {
        assert.deepEqual(
          [...released].sort(),
          [...owned].sort(),
          "Publication preceded cleanup",
        );
        assert.ok(calls.includes("eof"));
        assert.equal(
          accountValues[Math.min(accountReads - 1, accountValues.length - 1)],
          0,
        );
        output += pattern.replace("%s", text(value));
      },
    };
    if (refuses)
      assert.throws(
        () => program.runInNewContext(api),
        (cause) => cause === refused,
        String(fault),
      );
    else program.runInNewContext(api);
    assert.deepEqual([...released].sort(), [...owned].sort(), String(fault));
    assert.equal(descriptorClosed, true);
    assert.equal(
      attributesFreed,
      calls.includes("allocation") && fault !== "allocation",
    );
    assert.equal(
      attributesDeleted,
      calls.includes("attributes") && fault !== "attributes",
    );
    assert.ok(waits.length <= 16);
    assert.ok(
      waits.every(
        (value, index) => value > 0 && (!index || value < waits[index - 1]),
      ),
    );
    if (operation) {
      assert.equal(calls.includes("eof"), false);
      assert.equal(calls.includes("outside"), false);
      const before = [
        "line",
        "wait",
        ...(!waited ? ["exit"] : []),
        ...(exitAvailable && !exitCode ? ["accounting"] : []),
      ];
      assert.deepEqual(
        calls
          .filter((value) =>
            ["line", "wait", "exit", "accounting", "packet"].includes(value),
          )
          .slice(0, before.length),
        before,
      );
    }
    if (!fault) {
      assert.equal(packetReads, 0);
      assert.equal(accountReads, 1);
      assert.equal(ticks, 1);
    }
    if (fault === "delayed") {
      assert.equal(accountReads, 2);
      assert.equal(packetReads, 1);
    }
    if (fault === "lifecycle") {
      assert.equal(accountReads, 4);
      assert.deepEqual(waits, [29900, 29800, 29700]);
    }
    if (["active", "lost-zero"].includes(fault)) {
      assert.equal(accountReads, 2);
      assert.equal(packetReads, 1);
    }
    if (fault === "deadline-zero") {
      assert.equal(accountReads, 2);
      assert.equal(packetReads, 0);
    }
    if (fault === "notification-only") {
      assert.equal(accountReads, 3);
      assert.equal(packetReads, 1);
    }
    if (fault === "packet-cap") {
      assert.equal(accountReads, 18);
      assert.equal(packetReads, 16);
    }
    if (
      [
        "wrong-key",
        "zero-payload",
        "wrong-pid",
        "unknown",
        "unexpected",
        "completion-api",
        "failed-packet",
      ].includes(fault)
    )
      assert.equal(accountReads, 1);
    if (refuses) {
      assert.equal(output, "");
      assert.equal(api.ownership_creation_verified, false);
      if (["cleanup", "association-cleanup"].includes(fault)) {
        assert.equal(resources.cleanupError, fault === "cleanup" ? 5 : 6);
        assert.equal(
          diagnostics.filter((line) =>
            line.startsWith("native-windows-witness-cleanup:"),
          ).length,
          fault === "cleanup" ? 4 : 2,
        );
      }
      assert.equal(
        diagnostics.at(-1),
        `native-windows-guard: file=custody-reader.c line=1 last-error=${error}\n`,
      );
      if (frames.length) {
        const frame = JSON.parse(frames[0].slice(1));
        assert.equal(frame.lastError, error);
        if (operation) {
          assert.deepEqual(frame.witness, {
            operation,
            result: actual,
            apiFailure: [
              "wait-failed",
              "exit-query",
              "accounting-query",
              "accounting-after-wakeup",
              "completion-api",
              "failed-packet",
            ].includes(fault),
            wait: waited,
            exitAvailable,
            exitCode: exitAvailable ? exitCode : 0,
            accountingAvailable,
            activeProcesses: accountingAvailable ? 1 : 0,
            childBytes: childLine.length,
            childShown: Math.min(1024, childLine.length),
            childTruncated: childLine.length > 1024,
            childHex: childLine.subarray(0, 1024).toString("hex"),
          });
          if (fault === "active") assert.equal(frame.witness.childBytes, 2391);
          if (fault === "child-exit" && !outsideControl) sample = frame;
          if (fault === "completion-api") completionSample = frame;
          if (fault === "wrong-key") notificationSample = frame;
          if (fault === "accounting-size") sizeSample = frame;
        } else assert.equal(frame.witness, undefined);
        assert.deepEqual((await pending).custodyReaderFailure, frame);
      } else assert.ok(["diagnostic", "format"].includes(fault));
      f.child.stdout.end();
      f.child.emit("close", 126, null);
      const primary = await pending;
      assert.equal(await completion, primary);
      assert.throws(() => f.channel.settle());
      await assert.rejects(f.channel.receive(), (cause) => cause === primary);
      f.channel.close();
    } else {
      assert.ok(calls.includes("eof"));
      assert.equal(calls.includes("outside"), outsideControl);
      assert.equal(
        output,
        outsideControl
          ? '{"ready":true,"reachable":true}'
          : childLine.toString(),
      );
      assert.equal(api.ownership_creation_verified, true);
      const value = { sequence: 2, value: JSON.parse(output) };
      f.child.stdout.write(JSON.stringify(value) + "\n");
      assert.deepEqual(await pending, value);
      f.child.stdout.end();
      f.child.emit("close", 0, null);
      assert.deepEqual(await completion, { code: 0, signal: null });
      f.channel.settle();
    }
    f.child.stdin.destroy();
    f.child.stdout.destroy();
    f.child.stderr.destroy();
  }
  for (const mutate of [
    (v) => {
      Object.assign(v, structuredClone(completionSample));
      v.witness.accountingAvailable = false;
    },
    (v) => {
      Object.assign(v, structuredClone(completionSample));
      v.witness.apiFailure = false;
    },
    (v) => {
      Object.assign(v, structuredClone(notificationSample));
      v.witness.activeProcesses = 0;
    },
    (v) => {
      Object.assign(v, structuredClone(notificationSample));
      v.witness.apiFailure = true;
    },
    (v) => {
      Object.assign(v, structuredClone(sizeSample));
      v.witness.accountingAvailable = true;
    },
    (v) => {
      v.witness.operation = "unknown";
    },
    (v) => {
      v.witness.result = -1;
    },
    (v) => {
      v.witness.result++;
    },
    (v) => {
      v.witness.wait = 0x100000000;
    },
    (v) => {
      v.witness.wait = 258;
    },
    (v) => {
      v.witness.exitCode = 0;
    },
    (v) => {
      v.witness.activeProcesses = 1;
    },
    (v) => {
      v.witness.exitAvailable = false;
    },
    (v) => {
      v.witness.accountingAvailable = true;
    },
    (v) => {
      v.witness.apiFailure = true;
    },
    (v) => {
      v.witness.childBytes = 65536;
    },
    (v) => {
      v.witness.childShown--;
    },
    (v) => {
      v.witness.childTruncated = true;
    },
    (v) => {
      v.witness.childHex = "zz";
    },
    (v) => {
      v.witness.childHex += "0";
    },
    (v) => {
      v.witness.extra = true;
    },
    (v) => {
      v.command = "ownership-control";
    },
    (v) => {
      v.source = "custody.h";
    },
    (v) => {
      v.phase = "receipt";
    },
    (v) => {
      v.lastError = 5;
    },
    (v) => {
      delete v.lastError;
    },
    ...[
      "launcher",
      "baseline",
      "open",
      "trust",
      "transfer",
      "loader",
      "retain",
      "scheduler",
      "cold",
    ].map((field) => (v) => {
      v[field] = {};
    }),
    (v) => {
      v.witness.childHex = "aa".repeat(5000);
    },
  ]) {
    const value = structuredClone(sample);
    mutate(value);
    const f = transport(),
      response = f.channel.receive().catch((cause) => cause);
    const bytes = Buffer.from("\x1e" + JSON.stringify(value) + "\n");
    for (let offset = 0; offset < bytes.length; offset += 113)
      f.child.stdout.write(bytes.subarray(offset, offset + 113));
    const primary = await response;
    assert.equal(primary.custodyReaderFailure, undefined);
    assert.throws(() => f.channel.settle());
    f.channel.close();
    f.child.stdin.destroy();
    f.child.stdout.destroy();
    f.child.stderr.destroy();
  }
});

test("Windows custody EOF refuses a lost response while reader diagnostics remain failures, never receipts", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = /static void reader_failure\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )[1],
    value = {
      phase: "reader-failure",
      sequence: 2,
      command: "open",
      source: "custody.h",
      line: 149,
      lastError: 5,
    },
    diagnosticProgram = new Script(
      `(file,line,error)=>{${body
        .replace("const char *source", "let source")
        .replace("source+1", "source.slice(1)")
        .replace(
          'char bytes[1024], transfer[256] = ""; DWORD written;',
          'let bytes={},transfer={value:""},written;',
        )
        .replace("sizeof(transfer)", "256")
        .replace("int size", "let size")
        .replace("sizeof(bytes)", "1024")
        .replace("\\036", "\\x1e")
        .replace("(DWORD)size", "size")
        .replace("&written", "value=>written=value")}}`,
    );
  for (const diagnostic of [false, true]) {
    const f = transport(),
      response = f.channel.receive();
    if (diagnostic) {
      f.child.stdout.write('{"sequence":2,"value":');
      diagnosticProgram.runInNewContext({
        reader_diagnostics_ready: true,
        ownership_refusal_collect: () => {},
        refusal_settle: () => {},
        signature_trust: { active: false },
        reader_witness_failure: () => false,
        ownership_failure_write: () => false,
        ownership_failure_fence: () => {},
        reader_cold_failure: () => false,
        reader_baseline_failure: () => false,
        reader_scheduler_failure: () => false,
        reader_context_failure: () => false,
        reader_open_failure: () => false,
        reader_command: "open",
        reader_transfer: { active: false },
        sequence: 2,
        control: "authenticated",
        NULL: null,
        strrchr: (file, separator) => {
          const index = file.lastIndexOf(separator);
          return index < 0 ? null : file.slice(index);
        },
        sprintf_s: (bytes, maximum, format, ...values) => {
          let index = 0;
          bytes.value = format.replace(/%(?:lu|[su])/gu, () => {
            const value = values[index++];
            return value?.value ?? value;
          });
          assert.ok(Buffer.byteLength(bytes.value) < maximum);
          return bytes.value.length;
        },
        WriteFile: (handle, bytes, size, out) => {
          assert.equal(handle, "authenticated");
          out(size);
          f.child.stdout.write(bytes.value.slice(0, 25));
          f.child.stdout.write(bytes.value.slice(25));
          return true;
        },
      })("C:\\Fixture\\custody.h", 149, 5);
      await assert.rejects(response, (error) => {
        assert.deepEqual(error.custodyReaderFailure, value);
        return true;
      });
    } else {
      f.child.stdout.emit("end");
      await assert.rejects(response);
    }
    await assert.rejects(f.channel.completion);
    assert.throws(() => f.channel.settle());
    assert.equal(f.child.exitCode, undefined);
    f.child.emit("close", 0, null);
    await assert.rejects(f.channel.receive());
  }
  for (const field of ["command", "source"]) {
    const f = transport(),
      response = f.channel.receive();
    f.child.stdout.write(
      "\x1e" + JSON.stringify({ ...value, [field]: [value[field]] }) + "\n",
    );
    await assert.rejects(
      response,
      (error) => !Object.hasOwn(error, "custodyReaderFailure"),
    );
    await assert.rejects(f.channel.completion);
    assert.throws(() => f.channel.settle());
    f.child.emit("close", 0, null);
  }
  const f = transport();
  f.child.stdout.emit("end");
  assert.throws(() => f.channel.settle());
  await assert.rejects(f.channel.receive());
  await assert.rejects(f.channel.completion);
});

test("held baseline guards acquire complete original grants and retain strict fallback and independent cleanup refusals", async () => {
  const [source, effective, header] = await Promise.all(
    ["custody-reader.c", "effective-reader.h", "custody.h"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const body = (name) =>
    new RegExp(
      `static (?:void|BOOL) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const opening = (name) =>
    new RegExp(
      `static (?:HANDLE|struct held_file) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(header)[1];
  const acquisition = (priorGrant) => {
    const translate = (text) =>
      text
        .replace(
          /#ifdef NATIVE_CI_EXPERIMENT\n[\s\S]*?#else\n([\s\S]*?)#endif/gu,
          "$1",
        )
        .replace(
          "struct held_file value = {0};",
          'const value = {parents:[],count:0,path:{text:""},volumeName:{},filesystem:{},id:{}};',
        )
        .replace("FILE_ATTRIBUTE_TAG_INFO tag;", "const tag = {};")
        .replace("BY_HANDLE_FILE_INFORMATION info;", "const info = {};")
        .replace("FILE_ID_INFO volumeId;", "const volumeId = {};")
        .replace("char hash[65];", "const hash = {};")
        .replace(/wchar_t (\w+)\[\d+\];/gu, 'const $1 = {text:""};')
        .replace(/wchar_t \*(leaf|slash)/gu, "let $1")
        .replace(
          /\*(leaf|slash) = 0/gu,
          "$1.buffer.text = $1.buffer.text.slice(0,$1.index)",
        )
        .replaceAll(
          /\b(?:DWORD|HANDLE|PSECURITY_DESCRIPTOR|SECURITY_ATTRIBUTES) /gu,
          "let ",
        )
        .replace(/sizeof\((?:value.id|volumeId)\)/gu, "24")
        .replaceAll("sizeof(tag)", "8")
        .replace(/&(value.id|volumeId|info|tag|sa|entries\[index\])/gu, "$1")
        .replace(/&(?:serial|maximum|flags)/gu, "{}")
        .replaceAll("canonical + 4", "canonical.text.slice(4)")
        .replaceAll('L"', '"')
        .replaceAll("private", "isPrivate");
    const inline = (name) =>
      new RegExp(
        `static (?:HANDLE|struct held_file) ${name}\\([^\\n]*?\\) \\{ ([^\\n]+) \\}`,
        "u",
      ).exec(header)[1];
    // Remove only the SACL-query grant for insufficient-grant cases. All other
    // acquisition, identity and complete-security-read decisions stay native.
    const creating = body("case_directory_create");
    return new Script(`
      function open_file_shared(name,directory,access,mutable) {${translate(opening("open_file_shared"))}}
      function open_file(name,directory,access) {${translate(inline("open_file"))}}
      function hold_shared(name,directory,isPrivate,access,mutable) {${translate(opening("hold_shared"))}}
      function hold(name,directory,isPrivate,access) {${translate(inline("hold"))}}
      function case_directory_create(index,parent,report) {${translate(priorGrant ? creating.replace(" | ACCESS_SYSTEM_SECURITY", "") : creating)}}
      case_directory_create;
    `);
  };
  const acquisitions = [acquisition(false), acquisition(true)],
    text = (value) => (typeof value === "string" ? value : value.text);
  const native = body("ownership_baseline_read")
    .replaceAll("->", ".")
    .replace(
      "struct held_file *held = &entries[i+1].file;",
      "const held = entries[i+1].file;",
    )
    .replace("DWORD error =", "error =")
    .replace("const char *operation =", "operation =")
    .replace("BOOL apiFailure =", "apiFailure =")
    .replace("FILE_ID_INFO id;", "const id = {};")
    .replaceAll("&id", "id")
    .replace("&held.id", "held.id")
    .replaceAll("sizeof(id)", "24")
    .replace("PSECURITY_DESCRIPTOR sd =", "const sd =")
    .replace("BOOL read =", "const read =")
    .replace("(BYTE *)sd", "sd")
    .replaceAll("goto refused;", "throw refused;");
  const [reading, cleanup] = native.split("refused:");
  const security = (name, args) => {
    const body = new RegExp(
      `static [^\\n]+ ${name}\\([^)]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(effective)[1];
    // Only C storage/pointer representations change; execute the existing
    // complete-query and cleanup decisions with the baseline body below.
    return `function ${name}(${args}) {${body
      .replace("FILE_ID_INFO before, after;", "const before={},after={};")
      .replace(/sizeof\((?:before|after)\)/gu, "24")
      .replace(/&(before|after)\b/gu, "$1")
      .replaceAll("&sd", "{get value(){return sd},set value(value){sd=value}}")
      .replaceAll("__LINE__", "1")
      .replaceAll("__FILE__", '"effective-reader.h"')
      .replace(
        /\b(?:HANDLE|DWORD|BOOL|PSECURITY_DESCRIPTOR|SECURITY_INFORMATION) /gu,
        "let ",
      )}}`;
  };
  const program = new Script(
    [
      security(
        "file_security_failure",
        "operation,api_failure,error,temporary,sd,line",
      ),
      security("file_sd_query", "file,kind,sd"),
      security("file_sd", "file,kind"),
      `(i,hash)=>{try{${reading}}catch(cause){if(cause!==refused)throw cause;}${cleanup}}`,
    ].join("\n"),
  );
  const sending = new Script(
    `(source,line,error)=>{${body("reader_baseline_failure")
      .replace(
        "char bytes[1024]; DWORD written;",
        "const bytes={};let written;",
      )
      .replace("int size", "const size")
      .replace("sizeof(bytes)", "1024")
      .replace("(DWORD)size", "size")
      .replace("&written", "value=>written=value")
      .replaceAll("\\036", "\\x1e")}}`,
  );
  for (const [fault, operation, error, cleanupOperation] of [
    [null],
    ["held-id", "FileIdInfo", 50],
    ["held-identity", "identity", 0],
    ["direct-error-free", "security-read-descriptor", 87, "LocalFree"],
    ["fallback"],
    ["fallback-reopen", "security-read-reopen", 5],
    ["fallback-identity", "security-read-same-object", 13],
    ["fallback-id-close", "security-read-reopened-id", 50, "CloseHandle"],
    ["fallback-close", "security-read-close", 6],
  ]) {
    const calls = [],
      record = {},
      frames = [],
      diagnostics = [],
      opens = new Set([3]),
      grants = new Map(),
      descriptors = new Set(),
      isFallback = fault?.startsWith("fallback") ?? false;
    let lastError = 91,
      guardError;
    const api = {
      error: 0,
      operation: null,
      apiFailure: false,
      entries: [
        { path: "C:\\fixture", file: { handle: 3 } },
        { path: "C:\\fixture\\case", kind: "directory", file: {} },
      ],
      count: 2,
      reader_baseline: record,
      refused: {},
      TRUE: true,
      FALSE: false,
      INVALID_HANDLE_VALUE: -1,
      sequence: 26,
      reader_command: "ownership-outside",
      control: "authenticated",
      NULL: null,
      sprintf_s(bytes, maximum, format, ...args) {
        assert.equal(maximum, 1024);
        let i = 0;
        bytes.text = format.replace(/%(?:lu|u|s)/gu, () => String(args[i++]));
        return bytes.text.length;
      },
      WriteFile(handle, bytes, size, written) {
        assert.equal(handle, "authenticated");
        assert.equal(size, bytes.text.length);
        frames.push(JSON.parse(bytes.text.slice(1)));
        written(size);
        lastError = 92;
        return true;
      },
      READ_CONTROL: 1,
      FILE_READ_ATTRIBUTES: 2,
      ACCESS_SYSTEM_SECURITY: 4,
      FILE_LIST_DIRECTORY: 256,
      WRITE_DAC: 512,
      WRITE_OWNER: 2048,
      FILE_SHARE_READ: 8,
      FILE_SHARE_WRITE: 16,
      FILE_SHARE_DELETE: 32,
      FILE_FLAG_OPEN_REPARSE_POINT: 64,
      FILE_FLAG_BACKUP_SEMANTICS: 128,
      OPEN_EXISTING: 3,
      FILE_ATTRIBUTE_DIRECTORY: 16,
      FILE_ATTRIBUTE_REPARSE_POINT: 1024,
      FILE_NAME_NORMALIZED: 0,
      VOLUME_NAME_DOS: 0,
      HANDLE_FLAG_INHERIT: 1,
      FileAttributeTagInfo: 9,
      FileIdInfo: 18,
      SE_FILE_OBJECT: 1,
      ERROR_SUCCESS: 0,
      ERROR_ACCESS_DENIED: 5,
      ERROR_INVALID_DATA: 13,
      ERROR_INVALID_SECURITY_DESCR: 1338,
      OWNER_SECURITY_INFORMATION: 1,
      GROUP_SECURITY_INFORMATION: 2,
      DACL_SECURITY_INFORMATION: 4,
      SACL_SECURITY_INFORMATION: 8,
      LABEL_SECURITY_INFORMATION: 16,
      wcslen: (value) => text(value).length,
      wcscmp: (left, right) => text(left).localeCompare(text(right)),
      strcmp: (left, right) => left.localeCompare(right),
      wcsncmp: (left, right, size) =>
        text(left).slice(0, size).localeCompare(text(right)),
      wcscpy_s(out, maximum, value) {
        out.text = text(value);
        assert.ok(out.text.length < maximum);
      },
      wcsrchr(buffer, separator) {
        const index = buffer.text.lastIndexOf(separator);
        return index < 0 ? null : { buffer, index };
      },
      descriptor(value) {
        assert.equal(value, "O:SYG:SYD:P(A;;GA;;;SY)");
        descriptors.add("directory-sd");
        return "directory-sd";
      },
      attributes: (sd, inherit) => {
        assert.equal(sd, "directory-sd");
        assert.equal(inherit, false);
        return { sd };
      },
      CreateDirectoryW(name, sa) {
        assert.equal(name, "C:\\fixture\\case");
        assert.equal(sa.sd, "directory-sd");
        return true;
      },
      inspect(entry) {
        assert.equal(entry.file.handle, 7);
      },
      CreateFileW(name, access, sharing, sa, disposition, flags, template) {
        const path = text(name),
          handle = path === "C:\\fixture\\case" ? 7 : path === "C:\\" ? 11 : 12;
        assert.ok(!opens.has(handle));
        assert.deepEqual(
          [sharing, sa, disposition, flags, template],
          [24, null, 3, 192, null],
        );
        assert.equal(
          access,
          api.READ_CONTROL |
            api.FILE_READ_ATTRIBUTES |
            (handle === 7
              ? api.FILE_LIST_DIRECTORY |
                api.WRITE_DAC |
                api.WRITE_OWNER |
                (isFallback ? 0 : api.ACCESS_SYSTEM_SECURITY)
              : 0),
        );
        grants.set(handle, { path, access });
        opens.add(handle);
        return handle;
      },
      GetFinalPathNameByHandleW(handle, out, bound, flags) {
        assert.deepEqual([bound, flags], [4100, 0]);
        out.text = "\\\\?\\" + grants.get(handle).path;
        return out.text.length;
      },
      SetHandleInformation: (handle, flag, value) => {
        assert.ok(opens.has(handle));
        assert.deepEqual([flag, value], [1, 0]);
        return true;
      },
      GetFileInformationByHandle(handle, out) {
        assert.equal(handle, 7);
        out.nNumberOfLinks = 1;
        return true;
      },
      GetVolumePathNameW(name, out) {
        assert.equal(text(name), "C:\\fixture\\case");
        out.text = "C:\\";
        return true;
      },
      GetVolumeNameForVolumeMountPointW: () => true,
      GetVolumeInformationByHandleW: (handle) => {
        assert.equal(handle, 11);
        return true;
      },
      security(handle, kind, isPrivate) {
        assert.deepEqual([handle, kind, isPrivate], [7, 1, true]);
      },
      ReOpenFile(handle, access, sharing, flags) {
        assert.deepEqual([handle, access, sharing, flags], [7, 7, 56, 192]);
        calls.push("reopen");
        lastError = 5;
        // The direct baseline must work even if a fresh open would be denied.
        if (!isFallback || fault === "fallback-reopen") return -1;
        opens.add(9);
        grants.set(9, { access });
        return 9;
      },
      GetFileInformationByHandleEx(handle, kind, out, size) {
        assert.ok(opens.has(handle));
        if (kind === 9) {
          assert.equal(size, 8);
          out.FileAttributes = 16;
          return true;
        }
        assert.deepEqual([kind, size], [18, 24]);
        out.VolumeSerialNumber = 1;
        // Acquisition saves the original identity before fault injection.
        if (!api.entries[1].file.handle) {
          out.value = "original";
          return true;
        }
        calls.push(handle === 7 ? "original-id" : "reopened-id");
        lastError = 50;
        out.value =
          fault === "held-identity" ||
          (handle === 9 && fault === "fallback-identity")
            ? "other"
            : "original";
        return (
          fault !== "held-id" &&
          !(handle === 9 && fault === "fallback-id-close")
        );
      },
      memcmp: (left, right) => (left.value === (right.value ?? right) ? 0 : 1),
      GetSecurityInfo(handle, kind, mask, owner, group, dacl, sacl, out) {
        assert.ok(opens.has(handle));
        assert.equal(kind, 1);
        assert.equal(mask, 31);
        assert.deepEqual([owner, group, dacl, sacl], [null, null, null, null]);
        assert.equal(out.value, null);
        calls.push(handle === 7 ? "original-security" : "reopened-security");
        lastError = 99;
        const queryAccess = api.READ_CONTROL | api.ACCESS_SYSTEM_SECURITY;
        if ((grants.get(handle).access & queryAccess) !== queryAccess) return 5;
        descriptors.add("full-sd");
        out.value = "full-sd";
        return fault === "direct-error-free" ? 87 : 0;
      },
      IsValidSecurityDescriptor: (sd) => sd === "full-sd",
      GetSecurityDescriptorLength: () => 32,
      sum(sd, length, hash) {
        assert.deepEqual([sd, length], ["full-sd", 32]);
        calls.push("hash");
        hash.value = "unchanged";
      },
      LocalFree: (sd) => {
        assert.ok(descriptors.has(sd));
        calls.push("free");
        lastError = 8;
        if (sd === "full-sd" && fault === "direct-error-free") return sd;
        descriptors.delete(sd);
        return null;
      },
      CloseHandle(handle) {
        assert.equal(handle, 9, "Never close the borrowed original handle");
        assert.ok(opens.has(handle));
        calls.push("close");
        lastError = 6;
        if (fault?.endsWith("close")) return false;
        opens.delete(handle);
        return true;
      },
      stderr: {},
      fprintf: (_stream, format, ...values) =>
        diagnostics.push({ format, values }),
      fflush() {
        lastError = 93;
      },
      GetLastError: () => lastError,
      SetLastError: (error) => {
        lastError = error;
      },
      need(ok) {
        if (ok) return;
        record.error = lastError;
        guardError = lastError;
        sending.runInNewContext(api)("custody-reader.c", 1, lastError);
        throw new Error("guard refused");
      },
      need_at(ok, source, line) {
        assert.equal(ok, false);
        guardError = lastError;
        assert.equal(
          sending.runInNewContext(api)(source, line, lastError),
          false,
        );
        throw new Error("guard refused");
      },
    };
    acquisitions[isFallback ? 1 : 0].runInNewContext(api)(1, 0, true);
    const held = api.entries[1].file,
      retained = [...opens];
    assert.equal(held.handle, 7);
    assert.equal(held.id.value, "original");
    assert.equal(held.volume, 11);
    assert.deepEqual(Array.from(held.parents), [12]);
    assert.equal(held.count, 1);
    assert.equal(descriptors.size, 0);
    calls.length = 0;
    const hash = {};
    if (!operation) {
      program.runInNewContext(api)(0, hash);
      assert.equal(hash.value, "unchanged");
      assert.deepEqual([...opens], retained);
      assert.equal(descriptors.size, 0);
      assert.deepEqual(diagnostics, []);
    } else {
      assert.throws(
        () => program.runInNewContext(api)(0, hash),
        /guard refused/u,
      );
      assert.equal(guardError, error);
      assert.equal(hash.value, undefined);
      if (fault.startsWith("held-")) {
        assert.equal(record.operation, operation);
        assert.equal(record.apiFailure, operation !== "identity");
        assert.equal(record.cleanupFailed, false);
        assert.equal(record.cleanupError, 0);
        assert.equal(frames[0].lastError, error);
        assert.equal(frames[0].baseline.operation, operation);
      } else {
        const primary = diagnostics.find(({ format }) =>
          format.startsWith("native-windows-security:"),
        );
        assert.deepEqual(primary.values, [
          operation,
          fault === "fallback-identity" ? "invariant" : "win32",
          error,
        ]);
        const cleanup = diagnostics.filter(({ format }) =>
          format.startsWith("native-windows-security-cleanup:"),
        );
        assert.deepEqual(
          cleanup.map(({ format, values }) => [
            format.includes(cleanupOperation),
            values[0],
          ]),
          cleanupOperation
            ? [[true, cleanupOperation === "CloseHandle" ? 6 : 8]]
            : [],
        );
      }
    }
    assert.ok(opens.has(7));
    assert.ok(retained.every((handle) => opens.has(handle)));
    assert.equal(api.entries[1].file, held);
    assert.equal(
      calls.filter((call) => call === "reopen").length,
      isFallback ? 1 : 0,
    );
    assert.equal(
      calls.filter((call) => call === "original-id").length,
      fault?.startsWith("held-") ? 1 : 2,
    );
    assert.equal(
      calls.filter((call) => call === "close").length,
      isFallback && fault !== "fallback-reopen" ? 1 : 0,
    );
    assert.equal(
      calls.filter((call) => call === "free").length,
      !operation || fault === "direct-error-free" || fault === "fallback-close"
        ? 1
        : 0,
    );
    if (fault?.startsWith("held-"))
      assert.ok(!calls.includes("original-security"));
  }
  const baseline = {
    operation: "FileIdInfo",
    index: 0,
    apiFailure: true,
    cleanupFailed: true,
    cleanupError: 6,
  };
  for (const change of [
    null,
    { operation: "retry" },
    { index: 6 },
    { apiFailure: false },
    { cleanupError: -1 },
    { cleanupFailed: false },
    { extra: 1 },
  ]) {
    const f = transport(),
      response = f.channel.receive();
    f.child.stdout.write(
      "\x1e" +
        JSON.stringify({
          phase: "reader-failure",
          sequence: 26,
          command: "ownership-outside",
          source: "custody-reader.c",
          line: 1,
          lastError: 50,
          baseline: { ...baseline, ...change },
        }) +
        "\n",
    );
    await assert.rejects(response, (error) =>
      change
        ? !error.custodyReaderFailure
        : error.custodyReaderFailure?.baseline.operation === "FileIdInfo",
    );
    await assert.rejects(f.channel.completion);
    f.child.emit("close", 126, null);
    assert.throws(() => f.channel.settle());
  }
});

test("Windows owned policy borrows acquired handles across install, inspection and restoration with recovery before effects", async () => {
  const [reader, effective] = await Promise.all(
    ["custody-reader.c", "effective-reader.h"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const nativeMasks = /static DWORD ownership_masks\[6\] = \{([^}]+)\}/u.exec(
    reader,
  );
  assert.ok(nativeMasks);
  const masks = Array.from(
    new Script(`[${nativeMasks[1]}]`).runInNewContext({}),
  );
  assert.deepEqual(masks, [0, 0, 0x120020, 0x12019f | 0x20, 0, 0x1200a9]);
  const observed = {
    accountSid: "S-1-5-21-1-2-3-1001",
    restrictingSid: "S-1-5-21-4-5-6-1002",
    objects: masks.map((_, i) => ({ object: { identity: id(i + 1) } })),
  };
  assert.deepEqual(
    windowsOwnershipParameters(observed).objects.map(({ mask }) => mask),
    masks,
  );
  assert.deepEqual(
    windowsOwnershipParameters(observed, true).objects.map(({ mask }) => mask),
    masks.map((mask, i) => (i === 3 ? 0x1200a9 : mask)),
  );
  const project = (source, name, args) => {
    const body = new RegExp(
      `static [^\\n]+ ${name}\\([^)]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
    // Project C storage and output pointers only; native policy decisions run
    // unchanged against live grants, opaque descriptors and journal failures.
    return `function ${name}(${args}) {${body
      .replaceAll("->", ".")
      .replace(
        "struct entry *entry = &entries[i+1];",
        "const entry = entries[i+1];",
      )
      .replace("FILE_ID_INFO id;", "const id = Buffer.alloc(24);")
      .replace(
        "FILE_ID_INFO before, after;",
        "const before=Buffer.alloc(24),after=Buffer.alloc(24);",
      )
      .replace(/wchar_t (name|text)\[\d+\];/gu, 'const $1 = {value:""};')
      .replace("wchar_t *leaf", "let leaf")
      .replace("*leaf = 0", "name.value = name.value.slice(0,leaf)")
      .replace(/char hash\[\d+\];/gu, "const hash = {};")
      .replace("BYTE *bytes", "let bytes")
      .replaceAll("&entries[source].file", "entries[source].file")
      .replaceAll("&entries[target].file", "entries[target].file")
      .replaceAll("&entries[target]", "entries[target]")
      .replaceAll("&entry.file.id", "entry.file.id")
      .replace(/&(id|before|after|sa)\b/gu, "$1")
      .replace(
        /&(size|written|sd|present|defaulted|acl|expected|owner|system|flags|revision|label|expectedLabel)\b/gu,
        (_, name) =>
          `{get value(){return ${name}},set value(value){${name}=value}}`,
      )
      .replace(/sizeof\((?:id|before|after)\)/gu, "24")
      .replaceAll("(BYTE *)actual", "actual")
      .replaceAll('L"', '"')
      .replaceAll("__LINE__", "1")
      .replace(
        /\b(?:HANDLE|DWORD|PSECURITY_DESCRIPTOR|SECURITY_ATTRIBUTES|PACL|BOOL|PSID|SECURITY_DESCRIPTOR_CONTROL|SECURITY_INFORMATION) /gu,
        "let ",
      )}}`;
  };
  const program = new Script(
    [
      project(reader, "case_copy", "target,source,parent"),
      project(effective, "file_sd_query", "file,kind,sd"),
      project(effective, "file_sd", "file,kind"),
      project(reader, "ownership_acl", "i,restore,inspectOnly"),
      "({case_copy,ownership_acl})",
    ].join("\n"),
  );
  const acl = (value) =>
    Object.assign(Buffer.from(value), { AclSize: Buffer.byteLength(value) });
  const copy = (sd) => ({
    ...sd,
    dacl: acl(sd.dacl),
    sacl: sd.sacl && acl(sd.sacl),
  });
  const fingerprint = (sd) => digest(JSON.stringify(sd));
  const fixture = (fault) => {
    const paths = [
      "C:\\fixture",
      "C:\\fixture\\case",
      "C:\\fixture\\case\\custody",
      "C:\\fixture\\case\\application",
      "C:\\fixture\\case\\application\\workspace",
      "C:\\fixture\\case\\custody\\image.exe",
      "C:\\fixture\\case\\application\\helper.exe",
      "C:\\source.exe",
    ];
    const entries = paths.map((path, index) => ({
      path,
      kind: index < 5 ? "directory" : index === 6 ? "helper" : "image",
      pin: "pin",
      signature: "-",
      file: { handle: 10 + index, id: Buffer.alloc(24, index + 1) },
    }));
    const calls = [],
      allocations = new Set(),
      handles = new Map();
    const current = entries.map((_, index) => ({
      owner: "system",
      group: "system",
      flags: 1,
      dacl: acl(`baseline-${index}`),
      sacl: index === 4 ? acl("baseline-label") : null,
    }));
    const baseline = current.map(copy);
    const own = (value) => {
      allocations.add(value);
      return value;
    };
    const text = (value) => (typeof value === "string" ? value : value.value);
    const api = {
      Buffer,
      entries,
      count: entries.length,
      TRUE: true,
      FALSE: false,
      NULL: null,
      INVALID_HANDLE_VALUE: -1,
      FileIdInfo: 18,
      SE_FILE_OBJECT: 1,
      READ_CONTROL: 0x20000,
      WRITE_DAC: 0x40000,
      WRITE_OWNER: 0x80000,
      ACCESS_SYSTEM_SECURITY: 0x1000000,
      GENERIC_READ: 0x80000000,
      GENERIC_WRITE: 0x40000000,
      FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
      FILE_FLAG_WRITE_THROUGH: 0x80000000,
      CREATE_NEW: 1,
      OWNER_SECURITY_INFORMATION: 1,
      GROUP_SECURITY_INFORMATION: 2,
      DACL_SECURITY_INFORMATION: 4,
      SACL_SECURITY_INFORMATION: 8,
      LABEL_SECURITY_INFORMATION: 16,
      PROTECTED_DACL_SECURITY_INFORMATION: 0x80000000,
      SE_DACL_PROTECTED: 1,
      ERROR_SUCCESS: 0,
      ERROR_ACCESS_DENIED: 5,
      ownership_masks: masks,
      ownership_before: Array(6).fill(null),
      ownership_installed: Array(6).fill(null),
      ownership_baseline: baseline.slice(1, 7).map(fingerprint),
      case_record: { accountSid: "account", restrictingSid: "restricting" },
      need(value) {
        if (!value) throw new Error("policy refused");
      },
      GetLastError: () => 5,
      strcmp: (a, b) => text(a).localeCompare(text(b)),
      wcscmp: (a, b) => text(a).localeCompare(text(b)),
      wcscpy_s(out, bound, value) {
        out.value = text(value);
        assert.ok(out.value.length < bound);
      },
      wcsrchr: (value, separator) => text(value).lastIndexOf(separator),
      swprintf_s(out, bound, format, ...values) {
        out.value = format.replace(/%(?:lx|ls)/gu, (token) => {
          const value = values.shift();
          return token === "%lx" ? value.toString(16) : value;
        });
        assert.ok(out.value.length < bound);
        return out.value.length;
      },
      descriptor(value) {
        const sddl = text(value),
          [dacl, label] = sddl.split("S:");
        return own({
          owner: "system",
          group: "system",
          flags: 1,
          dacl: acl(dacl),
          sacl: label ? acl(label) : null,
        });
      },
      attributes: (sd, inherit) => {
        assert.equal(inherit, false);
        return { sd };
      },
      pin(file, value) {
        assert.ok(handles.has(file.handle));
        assert.equal(value, "pin");
      },
      read_file(file, bound, out) {
        assert.equal(file.handle, 17);
        assert.equal(bound, 134217728);
        out.value = 1;
        return Buffer.from("x");
      },
      CreateFileW(path, access, sharing, sa, disposition, flags, template) {
        assert.deepEqual(
          [path, access, sharing, disposition, flags, template],
          [
            paths[5],
            api.GENERIC_WRITE,
            0,
            1,
            api.FILE_FLAG_OPEN_REPARSE_POINT | api.FILE_FLAG_WRITE_THROUGH,
            null,
          ],
        );
        assert.ok(allocations.has(sa.sd));
        handles.set(100, { access });
        return 100;
      },
      WriteFile(handle, bytes, size, out, overlapped) {
        assert.equal(handle, 100);
        assert.deepEqual(bytes, Buffer.from("x"));
        assert.equal(overlapped, null);
        out.value = size;
        return true;
      },
      FlushFileBuffers: (handle) => {
        assert.equal(handle, 100);
        return true;
      },
      CloseHandle(handle) {
        assert.equal(
          handle,
          100,
          "Policy operations must not close borrowed handles",
        );
        assert.ok(handles.delete(handle));
        return true;
      },
      free: () => {},
      hold(path, directory, isPrivate, access) {
        assert.equal(path, paths[5]);
        assert.equal(directory, false);
        assert.equal(isPrivate, true);
        assert.equal(
          access,
          api.GENERIC_READ |
            api.WRITE_DAC |
            api.WRITE_OWNER |
            api.ACCESS_SYSTEM_SECURITY,
        );
        assert.ok(
          !handles.has(100),
          "Finish the creation writer before protective acquisition",
        );
        const file = { handle: 15, id: Buffer.alloc(24, 6) };
        handles.set(15, {
          access: access | api.READ_CONTROL,
          id: file.id,
          index: 5,
        });
        return file;
      },
      inspect: (entry) => {
        assert.equal(entry.file.handle, 15);
      },
      ReOpenFile: () =>
        assert.fail("Granted original policy handles need no reopen"),
      GetFileInformationByHandleEx(handle, kind, out, size) {
        assert.deepEqual([kind, size], [18, 24]);
        assert.ok(handles.has(handle));
        calls.push("id");
        handles.get(handle).id.copy(out);
        if (fault === "identity") out[23]++;
        return fault !== "id";
      },
      memcmp: (a, b, size) =>
        Buffer.compare(a.subarray(0, size), b.subarray(0, size)),
      GetSecurityInfo(handle, kind, info, owner, group, dacl, sacl, out) {
        assert.equal(kind, 1);
        assert.equal(info, 31);
        assert.deepEqual([owner, group, dacl, sacl], [null, null, null, null]);
        assert.equal(out.value, null);
        const held = handles.get(handle);
        assert.ok(held);
        assert.equal(
          held.access & (api.READ_CONTROL | api.ACCESS_SYSTEM_SECURITY),
          api.READ_CONTROL | api.ACCESS_SYSTEM_SECURITY,
        );
        calls.push("read");
        out.value = own(copy(current[held.index]));
        return 0;
      },
      IsValidSecurityDescriptor: (sd) => allocations.has(sd),
      GetSecurityDescriptorLength: (sd) => {
        assert.ok(allocations.has(sd));
        return 64;
      },
      GetSecurityDescriptorDacl(sd, present, out, defaulted) {
        present.value = true;
        out.value = sd.dacl;
        defaulted.value = false;
        return true;
      },
      GetSecurityDescriptorSacl(sd, present, out, defaulted) {
        present.value = sd.sacl !== null;
        out.value = sd.sacl;
        defaulted.value = false;
        return true;
      },
      GetSecurityDescriptorOwner(sd, out, defaulted) {
        out.value = sd.owner;
        defaulted.value = false;
        return true;
      },
      GetSecurityDescriptorControl(sd, out, revision) {
        out.value = sd.flags;
        revision.value = 1;
        return true;
      },
      ConvertStringSidToSidW(value, out) {
        assert.equal(value, "S-1-5-18");
        out.value = own({ sid: "system" });
        return true;
      },
      EqualSid: (owner, system) => owner === system.sid,
      LocalFree(value) {
        assert.ok(
          allocations.delete(value),
          "Free only owned live allocations",
        );
        return null;
      },
      security(handle, kind, isPrivate) {
        assert.ok(handles.has(handle));
        assert.equal(kind, 1);
        assert.equal(isPrivate, true);
        calls.push("private");
      },
      sum(sd, size, out) {
        assert.equal(size, 64);
        out.value = fingerprint(sd);
      },
      file_security_failure: () =>
        assert.fail("Complete granted reads must succeed"),
      policy_recovery_save(index, before, wanted) {
        assert.ok(allocations.has(before) && allocations.has(wanted));
        assert.deepEqual(before, baseline[index]);
        calls.push("journal");
        if (fault === "journal") throw new Error("journal refused");
      },
      SetSecurityInfo(handle, kind, info, owner, group, dacl, sacl) {
        const held = handles.get(handle);
        assert.ok(held);
        assert.equal(kind, 1);
        assert.deepEqual([owner, group], [null, null]);
        const label = info === api.LABEL_SECURITY_INFORMATION,
          required = label ? api.WRITE_OWNER : api.WRITE_DAC;
        assert.equal(held.access & required, required);
        assert.equal(
          info,
          label ? 16 : 4 | api.PROTECTED_DACL_SECURITY_INFORMATION,
        );
        assert.ok(
          calls.includes("journal"),
          "Persist recovery before either policy effect",
        );
        calls.push(label ? "label" : "dacl");
        if (fault === (label ? "set-label" : "set-dacl")) return 5;
        if (label) {
          assert.equal(dacl, null);
          current[held.index].sacl = acl(sacl);
        } else {
          assert.equal(sacl, null);
          current[held.index].dacl = acl(dacl);
        }
        return 0;
      },
    };
    for (let index = 0; index < entries.length; index++)
      handles.set(10 + index, {
        access:
          api.READ_CONTROL |
          api.WRITE_DAC |
          api.WRITE_OWNER |
          api.ACCESS_SYSTEM_SECURITY,
        id: entries[index].file.id,
        index,
      });
    entries[5].file = {};
    handles.delete(15);
    const native = program.runInNewContext(api);
    native.case_copy(5, 7, 2);
    assert.equal(allocations.size, 0);
    const retained = [...handles.keys()],
      borrowed = entries.slice(1, 7).map((entry) => entry.file);
    if (fault === "baseline") api.ownership_baseline[3] = "changed";
    return {
      api,
      native,
      calls,
      current,
      baseline,
      allocations,
      handles,
      retained,
      borrowed,
    };
  };
  for (let i = 0; i < 6; i++) {
    const f = fixture();
    f.native.ownership_acl(i, false, false);
    assert.ok(f.calls.indexOf("journal") < f.calls.indexOf("dacl"));
    const mask = f.api.ownership_masks[i];
    assert.equal(
      f.current[i + 1].dacl.toString(),
      mask
        ? `O:SYG:SYD:P(A;;FA;;;SY)(A;;0x${mask.toString(16)};;;account)(A;;0x${mask.toString(16)};;;restricting)`
        : "O:SYG:SYD:P(A;;FA;;;SY)",
    );
    const effects = f.calls.filter(
      (call) => call === "dacl" || call === "label",
    );
    assert.deepEqual(effects, i === 3 ? ["dacl", "label"] : ["dacl"]);
    f.native.ownership_acl(i, false, true);
    assert.deepEqual(
      f.calls.filter((call) => call === "dacl" || call === "label"),
      effects,
    );
    f.native.ownership_acl(i, true, false);
    assert.deepEqual(f.current[i + 1], f.baseline[i + 1]);
    assert.deepEqual([...f.handles.keys()], f.retained);
    assert.equal(f.api.entries[i + 1].file, f.borrowed[i]);
    assert.equal(
      f.allocations.size,
      2,
      "Saved descriptors stay live until their caller releases them",
    );
    f.api.LocalFree(f.api.ownership_before[i]);
    f.api.LocalFree(f.api.ownership_installed[i]);
    assert.equal(f.allocations.size, 0);
  }
  for (const fault of [
    "id",
    "identity",
    "baseline",
    "journal",
    "set-dacl",
    "set-label",
  ]) {
    const f = fixture(fault);
    assert.throws(
      () => f.native.ownership_acl(3, false, false),
      /(?:policy|journal) refused/u,
    );
    assert.deepEqual([...f.handles.keys()], f.retained);
    if (["id", "identity"].includes(fault)) assert.deepEqual(f.calls, ["id"]);
    if (["id", "identity", "baseline", "journal"].includes(fault)) {
      assert.ok(!f.calls.includes("dacl") && !f.calls.includes("label"));
      assert.deepEqual(f.current, f.baseline);
    } else {
      assert.deepEqual(f.api.ownership_before[3], f.baseline[4]);
      assert.ok(f.allocations.has(f.api.ownership_before[3]));
      assert.ok(f.allocations.has(f.api.ownership_installed[3]));
      assert.deepEqual(
        f.calls.filter((call) => ["journal", "dacl", "label"].includes(call)),
        fault === "set-label"
          ? ["journal", "dacl", "label"]
          : ["journal", "dacl"],
      );
    }
  }
  for (const field of ["owner", "dacl", "sacl"]) {
    const f = fixture();
    f.native.ownership_acl(3, false, false);
    if (field === "owner") f.current[4].owner = "foreign";
    else f.current[4][field][0] ^= 1;
    for (const restore of [false, true]) {
      const effects = f.calls.filter(
        (call) => call === "dacl" || call === "label",
      );
      assert.throws(
        () => f.native.ownership_acl(3, restore, !restore),
        /policy refused/u,
      );
      assert.deepEqual(
        f.calls.filter((call) => call === "dacl" || call === "label"),
        effects,
      );
      assert.deepEqual([...f.handles.keys()], f.retained);
    }
  }
});

test("original creator-census calls retain guard errors, clear successful context and never retry a refusal", async () => {
  const [header, reader] = await Promise.all([
    readFile(new URL("./custody.h", import.meta.url), "utf8"),
    readFile(new URL("./custody-reader.c", import.meta.url), "utf8"),
  ]);
  // Control workers use the same guard hook; their native storage starts empty.
  assert.match(
    reader,
    /static __declspec\(thread\) struct \{[^}]+\} reader_transfer;/u,
    "Creator-census context must be private to its native thread",
  );
  const body = (source, name) =>
    new RegExp(
      `static void ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const translate = (source) =>
    source
      .replace(/#ifdef NATIVE_CUSTODY_FAILURE\n([\s\S]*?)#endif/gu, "$1")
      .replace("NATIVE_CUSTODY_FAILURE", "reader_failure")
      .replace("DWORD error", "let error")
      .replace("const char *source", "let source")
      .replace("source+1", "source.slice(1)")
      .replace(
        'char bytes[1024], transfer[256] = ""; DWORD written;',
        'let bytes={},transfer={text:""},written;',
      )
      .replace("int size", "let size")
      .replace(
        "struct verify_handle *entry = &list->entries[i];",
        "let entry = list.entries[i];",
      )
      .replace("HANDLE duplicate;", "let duplicate;")
      .replaceAll("sizeof(transfer)", "256")
      .replaceAll("sizeof(bytes)", "1024")
      .replaceAll("->", ".")
      .replaceAll("(HANDLE)", "")
      .replaceAll("(DWORD)size", "size")
      .replaceAll("&duplicate", "out")
      .replaceAll("&written", "out")
      .replaceAll("\\036", "\\x1e");
  for (const [name, command] of [
    ["verifier_transfer", "verify-transfer"],
    ["compiler_policy", "verify-compiler-policy"],
  ]) {
    const fragment =
      /    struct verify_handle \*entry = &list->entries\[i\]; if \(entry->pid != GetProcessId\(source\) \|\| [^\n]*types\[0\][^\n]*\) continue;\n[\s\S]*?    reader_transfer\.active = FALSE;/u.exec(
        body(reader, name),
      )[0];
    const program = new Script(`
      function reader_failure(file,line,error) {${translate(body(reader, "reader_failure"))}}
      function need_at(ok,file,line) {${translate(body(header, "need_at"))}}
      function need(ok) {need_at(!!ok,"custody-reader.c",1);}
      for (let i=0; i<list.count; i++) {${translate(fragment)} after();}
      if (unrelated) {SetLastError(31); need(false);}
    `);
    for (const fault of [0, 1, 2, -1]) {
      const calls = [],
        records = [],
        errors = [],
        out = {},
        refusal = new Error("exit 126"),
        nativeError = fault === 2 ? 50 : 5;
      const entry = {
        pid: 10,
        type: 0xffff,
        access: 0xffffffff,
        flags: 0xffffffff,
      };
      let lastError = 0,
        reads = 0;
      const context = { active: false },
        api = {
          source: 10,
          creator: 127,
          child: 126,
          index: 126,
          sequence: 270,
          types: [0xffff, 7],
          list: {
            count: 3,
            entries: [
              { pid: 99 },
              { ...entry, handle: 11 },
              { ...entry, handle: 12 },
            ],
          },
          reader_transfer: context,
          reader_command: command,
          reader_diagnostics_ready: true,
          ownership_refusal_collect: () => {},
          refusal_settle: () => {},
          signature_trust: { active: false },
          reader_witness_failure: () => false,
          ownership_failure_write: () => false,
          ownership_failure_fence: () => {},
          reader_cold_failure: () => false,
          reader_baseline_failure: () => false,
          reader_scheduler_failure: () => false,
          reader_context_failure: () => false,
          reader_open_failure: () => false,
          control: "authenticated",
          out,
          TRUE: true,
          FALSE: false,
          DUPLICATE_SAME_ACCESS: 2,
          NULL: null,
          stderr: null,
          unrelated: fault === -1,
          GetProcessId: (source) => source,
          GetCurrentProcess: () => 20,
          GetLastError: () => {
            reads++;
            return lastError;
          },
          SetLastError: (error) => {
            lastError = error;
          },
          DuplicateHandle: (...args) => {
            assert.deepEqual(args, [
              10,
              11 + calls.length,
              20,
              out,
              0,
              false,
              2,
            ]);
            calls.push(args[1]);
            lastError = nativeError;
            return calls.length !== fault;
          },
          after: () => assert.equal(context.active, false),
          strrchr: (file) => null,
          sprintf_s: (target, maximum, format, ...values) => {
            let i = 0;
            target.text = format.replace(/%(?:llu|lu|[su])/gu, () => {
              const value = values[i++];
              return value?.text ?? value;
            });
            assert.ok(Buffer.byteLength(target.text) < maximum);
            lastError = 87;
            return target.text.length;
          },
          WriteFile: (handle, bytes, size) => {
            assert.equal(handle, "authenticated");
            records.push(bytes.text.slice(0, size));
            lastError = 88;
            return true;
          },
          fprintf: (_stream, _format, _file, _line, error) => {
            errors.push(error);
            lastError = 89;
          },
          fflush: () => {
            lastError = 90;
          },
          ExitProcess: (code) => {
            assert.equal(code, 126);
            throw refusal;
          },
        };
      if (fault)
        assert.throws(
          () => program.runInNewContext(api),
          (error) => error === refusal,
        );
      else program.runInNewContext(api);
      assert.deepEqual(calls, fault === 1 ? [11] : [11, 12]);
      assert.equal(reads, fault ? 1 : 0);
      assert.deepEqual(errors, fault ? [fault === -1 ? 31 : nativeError] : []);
      assert.equal(records.length, fault ? 1 : 0);
      if (!fault) continue;
      const f = transport(),
        response = f.channel.receive();
      f.child.stdout.write('{"sequence":270,"value":');
      for (const part of [records[0].slice(0, 25), records[0].slice(25)])
        f.child.stdout.write(part);
      await assert.rejects(response, (error) => {
        const value = error.custodyReaderFailure;
        assert.equal(value.lastError, fault === -1 ? 31 : nativeError);
        if (fault === -1) assert.ok(!Object.hasOwn(value, "transfer"));
        else
          assert.deepEqual(value.transfer, {
            ordinal: fault,
            count: 3,
            type: 0xffff,
            access: 0xffffffff,
            attributes: 0xffffffff,
            creator: 127,
            child: 126,
          });
        return true;
      });
      await assert.rejects(f.channel.completion);
      assert.throws(() => f.channel.settle());
      f.child.emit("close", 126, null);
    }
  }
});

test("runtime creator types preserve required duplication, membership and complete inherited censuses", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = (name) =>
      new RegExp(
        `static [^\\n]+\\b${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)[1],
    translate = (text) =>
      text
        .replace(
          "HANDLE anchors[2] = {CreateJobObjectW(NULL, NULL), NULL};",
          "let anchors=[CreateJobObjectW(NULL,NULL),NULL];",
        )
        .replace(
          "unsigned required = with_thread ? 2 : 1, matches[2] = {0};",
          "let required=with_thread?2:1,matches=[0,0];",
        )
        .replaceAll("USHORT types[2];", "let types=[];")
        .replace("char pipe_dacl[2][65]", "let pipe_dacl=[[],[]]")
        .replace("char dacl[65]", "let dacl=[]")
        .replace(
          "JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;",
          "let limits={BasicLimitInformation:{}};",
        )
        .replace("FILE_ID_INFO id;", "let id={FileId:{Identifier:[]}};")
        .replaceAll("struct verify_handles *list", "let list")
        .replaceAll(
          "struct verify_handle *entry = &list->entries[i];",
          "let entry=list.entries[i];",
        )
        .replace("TOKEN_DEFAULT_DACL *creation", "let creation")
        .replaceAll("(BYTE *)", "")
        .replaceAll("(HANDLE)", "")
        .replaceAll("(ULONG_PTR)", "")
        .replaceAll('L"', '"')
        .replaceAll("->", ".")
        .replace(/&(duplicate|flags|belongs|member)\b/gu, "value=>$1=value")
        .replace(/&(limits|id)\b/gu, "$1")
        .replace(/sizeof\([^)]*\)/gu, "1")
        .replace(
          /\b(?:HANDLE|DWORD|USHORT|ULONG_PTR|BOOL|unsigned)\b/gu,
          "let",
        ),
    program = new Script(`
      function creator_inventory(types,with_thread){${translate(body("creator_inventory"))}}
      function verifier_transfer(child,creator){${translate(body("verifier_transfer"))}}
      function compiler_policy(index,creator){${translate(body("compiler_policy"))}}
    `);
  function fixture(name, types, fault) {
    const anchors = [0x100000011n, 0x200000022n],
      alive = new Set(),
      created = [],
      closed = [],
      calls = [],
      security = [],
      inventories = [],
      freed = [],
      refusal = new Error("native guard"),
      thread = name === "verifier_transfer";
    const row = (pid, handle, type, flags = 0) => ({
      pid,
      handle,
      type,
      flags,
      access: 0x812,
    });
    const api = {
      NULL: null,
      TRUE: true,
      FALSE: false,
      INVALID_HANDLE_VALUE: -1n,
      THREAD_QUERY_LIMITED_INFORMATION: 0x800,
      HANDLE_FLAG_INHERIT: 1,
      DUPLICATE_SAME_ACCESS: 2,
      FILE_TYPE_DISK: 1,
      FILE_TYPE_PIPE: 3,
      SE_KERNEL_OBJECT: 6,
      SE_FILE_OBJECT: 1,
      TokenDefaultDacl: 6,
      JobObjectExtendedLimitInformation: 9,
      FileIdInfo: 18,
      WAIT_TIMEOUT: 258,
      processes: [10, 30],
      tokens: [0, 1],
      process_count: 2,
      verified_jobs: [{ outer: true }],
      reader_transfer: {},
      need: (ok) => {
        if (!ok) throw refusal;
      },
      CreateJobObjectW: (attributes, name) => {
        assert.deepEqual([attributes, name], [null, null]);
        if (fault === "job-create") return null;
        if (fault === "invalid-handle") return -1n;
        created.push(anchors[0]);
        alive.add(anchors[0]);
        return anchors[0];
      },
      OpenThread: (rights, inherit, id) => {
        assert.ok(thread);
        assert.deepEqual([rights, inherit, id], [0x800, false, 77]);
        if (fault === "thread-create") return null;
        created.push(anchors[1]);
        alive.add(anchors[1]);
        return anchors[1];
      },
      GetCurrentThreadId: () => 77,
      GetCurrentProcessId: () => 20,
      GetCurrentProcess: () => 20,
      GetProcessId: (process) => process,
      GetHandleInformation: (handle, out) => {
        assert.ok(alive.has(handle));
        out(fault === "inheritable" ? 1 : 0);
        return fault !== "anchor-query";
      },
      object_type: (handle, expected) => {
        if (typeof handle === "bigint") {
          assert.ok(alive.has(handle));
          return (
            fault !== "anchor-type" &&
            expected === (handle === anchors[0] ? "Job" : "Thread")
          );
        }
        assert.equal(api.reader_transfer.active, false);
        return fault !== "actual-type" && handle.kind === expected;
      },
      handle_inventory: () => {
        let rows;
        if (alive.size) {
          assert.equal(alive.size, thread ? 2 : 1);
          rows = [
            row(99, anchors[0], types[0]),
            row(20, 0x11n, types[0]),
            row(20, anchors[0], types[0]),
            ...(thread ? [row(20, anchors[1], types[1])] : []),
            row(10, 99, 500),
            row(10, 11, types[0]),
            row(10, 12, types[1]),
          ];
          if (fault === "missing-anchor") rows.splice(2, 1);
          if (fault === "ambiguous-anchor") rows.push({ ...rows[2] });
          if (fault === "contradictory-anchor")
            rows.push({ ...rows[2], type: types[1] });
          if (fault === "zero-index") rows[2].type = 0;
          if (fault === "inherited-anchor") rows[2].flags = 2;
          if (fault === "same-index" && thread) rows[3].type = types[0];
          if (fault === "missing-thread" && thread) rows.splice(3, 1);
          if (fault === "missing-job")
            rows = rows.filter((entry) => entry.handle !== 11);
          if (fault === "duplicate-job") rows.push(row(10, 13, types[0]));
          if (fault === "duplicate-thread") rows.push(row(10, 14, types[1]));
        } else {
          rows = [201, 202, 203].map((handle) => row(30, handle, 500, 2));
          if (fault === "missing-pipe") rows.shift();
          if (fault === "extra-pipe") rows.push(row(30, 204, 500, 2));
          if (fault === "inherited-refusal")
            rows.push(row(30, 299, types[0], 2));
          if (fault === "handle-bound")
            rows = Array.from({ length: 131 }, (_, i) =>
              row(30, 201 + i, 500, 2),
            );
        }
        const list = { entries: rows, count: rows.length };
        inventories.push(list);
        return list;
      },
      duplicate_process_owner: (slot) => api.processes[slot],
      DuplicateHandle: (
        source,
        handle,
        target,
        out,
        rights,
        inherit,
        options,
      ) => {
        assert.deepEqual(
          [source, target, rights, inherit, options],
          [handle < 200 ? 10 : 30, 20, 0, false, 2],
        );
        calls.push(handle);
        if (
          handle === 99 ||
          (fault === "inherited-refusal" && handle === 299) ||
          (fault === "required-refusal" && handle === 11)
        )
          return false;
        out({
          handle,
          kind: handle === 12 || handle === 14 ? "Thread" : "Job",
        });
        return true;
      },
      CloseHandle: (handle) => {
        closed.push(handle);
        if (typeof handle === "bigint") assert.ok(alive.delete(handle));
        return fault !== "anchor-close" || handle !== anchors[0];
      },
      IsProcessInJob: (child, job, out) => {
        out(
          job.outer
            ? child === 10 || fault === "nested-compiler"
            : child === 30
              ? fault !== "job-membership"
              : fault === "nested-controller",
        );
        return true;
      },
      GetProcessIdOfThread: () => (fault === "thread-membership" ? 99 : 30),
      QueryInformationJobObject: (_job, _kind, limits) => {
        limits.BasicLimitInformation.LimitFlags =
          fault === "compiler-breakaway"
            ? 0x2808
            : fault === "compiler-silent-breakaway"
              ? 0x3008
              : 0x2008;
        limits.BasicLimitInformation.ActiveProcessLimit =
          fault === "compiler-limit" ? 32 : 31;
        return true;
      },
      security: (handle, kind, privateDacl) => {
        assert.equal(privateDacl, true);
        security.push(handle.handle);
        if (fault === "dacl" || (fault === "pipe-dacl" && kind === 1))
          throw refusal;
      },
      job_read: () => {
        security.push("job");
        if (fault === "job-dacl") throw refusal;
      },
      GetFileType: ({ handle }) =>
        fault === "unknown-inherited" && handle === 202
          ? 0
          : thread &&
              handle >= 203 &&
              !(fault === "extra-pipe" && handle === 204)
            ? 1
            : 3,
      GetFileInformationByHandleEx: () => fault !== "file-identity",
      token_info: () => ({
        DefaultDacl: fault === "default-dacl" ? null : { AclSize: 8 },
      }),
      IsValidAcl: () => fault !== "default-dacl",
      acl_read: (acl) => {
        if (!acl) throw refusal;
      },
      WaitForSingleObject: () => 258,
      free: (value) => freed.push(value),
      printf: () => {},
      putchar: () => {},
      hex: () => {},
      sum: () => {},
    };
    program.runInNewContext(api);
    return {
      api,
      calls,
      security,
      created,
      closed,
      inventories,
      freed,
      refusal,
      run: () => api[name](1, 0),
    };
  }
  for (const name of ["verifier_transfer", "compiler_policy"]) {
    const thread = name === "verifier_transfer";
    for (const types of [
      [55, 84],
      [101, 55],
      [0xffff, 7],
    ]) {
      const f = fixture(name, types);
      f.run();
      assert.deepEqual(
        f.calls,
        thread ? [11, 12, 201, 202, 203] : [201, 202, 203, 11],
      );
      assert.deepEqual(
        f.closed.filter((handle) => typeof handle === "bigint"),
        f.created,
      );
      assert.equal(f.created.length, thread ? 2 : 1);
      assert.ok(f.security.includes("job"));
      if (thread) {
        assert.deepEqual(f.security, [12, "job", 201, 202]);
        assert.equal(f.api.verified_jobs[1].handle, 11);
      } else {
        assert.equal(f.api.verified_jobs[1], undefined);
        assert.ok(
          f.closed.some((handle) => handle?.handle === 11),
          "Compiler inspection must close its duplicate",
        );
      }
      assert.ok(f.inventories.every((list) => f.freed.includes(list)));
    }
    for (const fault of [
      "job-create",
      "invalid-handle",
      "anchor-query",
      "anchor-type",
      "inheritable",
      "missing-anchor",
      "ambiguous-anchor",
      "contradictory-anchor",
      "zero-index",
      "inherited-anchor",
      "anchor-close",
      ...(thread ? ["thread-create", "missing-thread", "same-index"] : []),
    ]) {
      const f = fixture(name, [55, 84], fault);
      assert.throws(f.run, (error) => error === f.refusal, `${name}: ${fault}`);
      assert.deepEqual(
        f.closed.filter((handle) => typeof handle === "bigint"),
        f.created,
        fault,
      );
      assert.deepEqual(f.calls, thread ? [] : [201, 202, 203], fault);
      assert.ok(
        f.inventories.every((list) => f.freed.includes(list)),
        fault,
      );
    }
    for (const fault of [
      "required-refusal",
      "actual-type",
      "missing-job",
      "duplicate-job",
      "job-membership",
      "missing-pipe",
      "extra-pipe",
      "inherited-refusal",
      "unknown-inherited",
      "default-dacl",
      "job-dacl",
      ...(thread
        ? [
            "duplicate-thread",
            "thread-membership",
            "dacl",
            "pipe-dacl",
            "file-identity",
            "handle-bound",
          ]
        : [
            "compiler-limit",
            "compiler-breakaway",
            "compiler-silent-breakaway",
            "nested-compiler",
            "nested-controller",
          ]),
    ]) {
      const f = fixture(name, [55, 84], fault);
      assert.throws(f.run, (error) => error === f.refusal, `${name}: ${fault}`);
      if (fault === "required-refusal")
        assert.deepEqual(f.calls, thread ? [11] : [201, 202, 203, 11]);
      if (fault === "inherited-refusal") assert.ok(f.calls.includes(299));
      if (fault === "handle-bound")
        assert.equal(f.calls.filter((handle) => handle >= 200).length, 130);
    }
  }
});

test("ordinary DLL inspection avoids initialization while retain failures describe only evaluated calls", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    importStart = source.indexOf(
      "  DWORD flags = LOAD_LIBRARY_SEARCH_SYSTEM32 |",
    ),
    importEnd = source.indexOf("  /* Open the observed NT path", importStart),
    retainStart = source.indexOf("  reader_retain.pid = pid;"),
    retainEnd = source.indexOf(
      "  for (unsigned i = 0; i < process_count;",
      retainStart,
    );
  assert.ok(
    importStart > 0 &&
      importEnd > importStart &&
      retainStart > 0 &&
      retainEnd > retainStart,
  );
  const mapping = new Script(
    source
      .slice(importStart, importEnd)
      .replace("DWORD flags", "const flags")
      .replace("size_t size", "const size")
      .replace("HMODULE module", "let module")
      .replace(
        "GetModuleHandleExW(0, name, &module)",
        "GetModuleHandleExW(0, name, value=>(module=value))",
      )
      .replaceAll('L"', '"')
      .replace("name+size-4", "name.slice(size-4)"),
  );
  for (const outcome of ["loaded", "mapped", "missing"]) {
    const context = {},
      calls = [],
      refusal = new Error("Original mapping failure");
    const run = () =>
      mapping.runInNewContext({
        reader_loader: context,
        image: "C:\\Fixture\\image.dll",
        name: "fixture.dll",
        TRUE: true,
        NULL: null,
        LOAD_LIBRARY_SEARCH_SYSTEM32: 0x800,
        DONT_RESOLVE_DLL_REFERENCES: 1,
        wcslen: (name) => name.length,
        _wcsicmp: (left, right) =>
          Number(left.toLowerCase() !== right.toLowerCase()),
        wcsspn: (name) => name.length,
        GetModuleHandleExW: (flags, name, set) => {
          assert.equal(flags, 0);
          assert.equal(name, "fixture.dll");
          if (outcome === "loaded") set(77);
          return outcome === "loaded";
        },
        LoadLibraryExW: (name, reserved, flags) => {
          calls.push({ name, reserved, flags });
          return outcome === "mapped" ? 77 : null;
        },
        need: (ok) => {
          if (!ok) throw refusal;
        },
      });
    if (outcome === "missing") assert.throws(run, (error) => error === refusal);
    else run();
    assert.deepEqual(
      calls,
      outcome === "loaded"
        ? []
        : [
            {
              name: "fixture.dll",
              reserved: null,
              flags: 0x801,
            },
          ],
    );
    assert.equal(context.active, true);
    assert.equal(context.image, "C:\\Fixture\\image.dll");
    assert.equal(context.name, "fixture.dll");
  }
  const selection = new Script(
    source
      .slice(
        importEnd,
        source.indexOf("  reader_loader.active = FALSE;", importEnd),
      )
      .replace(
        /wchar_t ([^;]+);/u,
        (_text, names) => `let ${names.replace(/\[\d+\]/gu, '=""')};`,
      )
      .replace(
        "FILE_ATTRIBUTE_TAG_INFO tag; FILE_ID_INFO before, after;",
        "const tag={},before={},after={};",
      )
      .replace("struct held_file file", "const file")
      .replace("char dacl[65]", "const dacl={}")
      .replace(/\b(?:DWORD|HANDLE)\b/gu, "const")
      .replaceAll('L"', '"')
      .replace(/sizeof\([^)]*\)/gu, "1")
      .replace(/&(tag|before|after)\b/gu, "$1")
      .replace(", mapped, 4100)", ", value=>(mapped=value), 4100)")
      .replace(
        "GetSystemDirectoryW(system,",
        "GetSystemDirectoryW(value=>(system=value),",
      )
      .replace(
        "swprintf_s(mappedPath,",
        "swprintf_s(value=>(mappedPath=value),",
      )
      .replace(
        /(GetFinalPathNameByHandleW\(selected, )(canonical|named),/gu,
        "$1value=>($2=value),",
      )
      .replace(
        "wcscpy_s(actual, 4096, canonical+4)",
        "actual=canonical.slice(4)",
      )
      .replace("actual+prefix+1", "actual.slice(prefix+1)"),
  );
  for (const fault of [
    null,
    "mapped-query",
    "mapped-truncated",
    "outside",
    "nested",
    "reparse",
    "mapped-identity",
    "held-identity",
    "release",
  ]) {
    const module = 0x100000000n,
      mapped = "\\Device\\FixtureVolume\\Windows\\System32\\fixture.dll",
      actual =
        fault === "outside"
          ? "C:\\Other\\fixture.dll"
          : "C:\\Windows\\System32\\" +
            (fault === "nested" ? "child\\" : "") +
            "fixture.dll",
      calls = [],
      refusal = new Error("Mapping identity refused");
    const run = () =>
      selection.runInNewContext({
        module,
        actual: "",
        FALSE: false,
        NULL: null,
        GENERIC_READ: 1,
        READ_CONTROL: 2,
        FILE_READ_ATTRIBUTES: 4,
        FILE_SHARE_READ: 1,
        OPEN_EXISTING: 3,
        FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
        INVALID_HANDLE_VALUE: -1,
        FileAttributeTagInfo: 1,
        FileIdInfo: 2,
        FILE_ATTRIBUTE_REPARSE_POINT: 0x400,
        FILE_NAME_NORMALIZED: 0,
        VOLUME_NAME_DOS: 0,
        VOLUME_NAME_NT: 2,
        GetCurrentProcess: () => 77,
        GetMappedFileNameW: (process, address, out) => {
          assert.equal(process, 77);
          assert.equal(address, module);
          out(mapped);
          return fault === "mapped-query"
            ? 0
            : fault === "mapped-truncated"
              ? 4100
              : mapped.length;
        },
        GetSystemDirectoryW: (out) => {
          const system = "C:\\Windows\\System32";
          out(system);
          return system.length;
        },
        swprintf_s: (out, capacity, format, value) => {
          const path = format.replace("%ls", value);
          assert.ok(path.length < capacity);
          out(path);
          return path.length;
        },
        CreateFileW: (path, ...options) => {
          assert.equal(path, "\\\\?\\GLOBALROOT" + mapped);
          assert.deepEqual(options, [7, 1, null, 3, 0x200000, null]);
          calls.push("open");
          return 55;
        },
        GetFileInformationByHandleEx: (handle, kind, out) => {
          if (kind === 1) out.FileAttributes = fault === "reparse" ? 0x400 : 0;
          else out.id = fault === "held-identity" && handle === 56 ? 8 : 7;
          return true;
        },
        GetFinalPathNameByHandleW: (handle, out, _capacity, flags) => {
          assert.equal(handle, 55);
          const value =
            flags === 0
              ? "\\\\?\\" + actual
              : fault === "mapped-identity"
                ? mapped + ".other"
                : mapped;
          out(value);
          return value.length;
        },
        wcsncmp: (left, right, count) =>
          Number(left.slice(0, count) !== right.slice(0, count)),
        _wcsnicmp: (left, right, count) =>
          Number(
            left.slice(0, count).toLowerCase() !==
              right.slice(0, count).toLowerCase(),
          ),
        _wcsicmp: (left, right) =>
          Number(left.toLowerCase() !== right.toLowerCase()),
        wcschr: (text, character) => text.includes(character),
        hold: (path) => {
          assert.equal(path, actual);
          calls.push("hold");
          return { handle: 56 };
        },
        stock_security: (handle) => {
          assert.equal(handle, 56);
          calls.push("security");
        },
        memcmp: (left, right) => Number(left.id !== right.id),
        CloseHandle: (handle) => {
          assert.equal(handle, 55);
          calls.push("close");
          return true;
        },
        FreeLibrary: (handle) => {
          assert.equal(handle, module);
          calls.push("free");
          return fault !== "release";
        },
        need: (ok) => {
          if (!ok) throw refusal;
        },
      });
    if (fault) assert.throws(run, (error) => error === refusal, fault);
    else run();
    if (!fault || fault === "release")
      assert.deepEqual(calls, ["open", "hold", "security", "close", "free"]);
    else assert.ok(!calls.includes("free"), fault);
  }
  const acquisition = new Script(
    source
      .slice(retainStart, retainEnd)
      .replace("HANDLE process", "let process")
      .replace("DWORD error", "let error")
      .replace(
        "reader_retain.observedPid == pid",
        "Number(reader_retain.observedPid === pid)",
      )
      .replace(
        "!!OpenProcessToken(process, reader_retain.tokenAccess, &token)",
        "Number(!!OpenProcessToken(process, reader_retain.tokenAccess, outToken))",
      ),
  );
  for (const fault of ["process", "identity", "token", null]) {
    const context = {},
      calls = [],
      refusal = new Error("Original acquisition failure");
    let lastError = 0,
      captured;
    const run = () =>
      acquisition.runInNewContext({
        reader_retain: context,
        pid: 33,
        TRUE: true,
        FALSE: false,
        NULL: null,
        PROCESS_QUERY_INFORMATION: 0x400,
        PROCESS_VM_READ: 0x10,
        READ_CONTROL: 0x20000,
        SYNCHRONIZE: 0x100000,
        TOKEN_QUERY: 8,
        TOKEN_DUPLICATE: 2,
        OpenProcess: (access, inherit, pid) => {
          assert.deepEqual([access, inherit, pid], [0x120410, false, 33]);
          calls.push("process");
          lastError = 87;
          return fault === "process" ? null : 1;
        },
        GetProcessId: () => {
          calls.push("identity");
          lastError = 5;
          return fault === "identity" ? 34 : 33;
        },
        OpenProcessToken: (_process, access, out) => {
          assert.equal(access, 10);
          calls.push("token");
          lastError = 10022;
          out(2);
          return fault !== "token";
        },
        outToken: () => {},
        GetLastError: () => lastError,
        SetLastError: (error) => {
          lastError = error;
        },
        need: (ok) => {
          if (ok) return;
          captured = { error: lastError, context: { ...context } };
          lastError = 999; // Diagnostic effects cannot replace the sampled error.
          throw refusal;
        },
      });
    if (fault) assert.throws(run, (error) => error === refusal);
    else {
      run();
      assert.equal(context.active, false);
    }
    assert.deepEqual(
      calls,
      fault === "process"
        ? ["process"]
        : fault === "identity"
          ? ["process", "identity"]
          : ["process", "identity", "token"],
    );
    if (!fault) continue;
    assert.equal(
      captured.error,
      { process: 87, identity: 5, token: 10022 }[fault],
    );
    assert.equal(
      captured.context.matched,
      fault === "process" ? -1 : fault === "identity" ? 0 : 1,
    );
    assert.equal(captured.context.tokenResult, fault === "token" ? 0 : -1);
  }
});

test("native loader and retain diagnostics preserve bounded UTF-16 context on the authenticated channel", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body =
      /static BOOL reader_context_failure\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
        source,
      )[1],
    program = new Script(
      `(source,line,error)=>{${body
        .replace(
          "char bytes[2048], context[1400]; DWORD written;",
          "const bytes={},context={};let written;",
        )
        .replace(
          "char image[513] = {0}, name[513] = {0};",
          'const image={value:""},name={value:""};',
        )
        .replace("size_t units", "const units")
        .replace(
          "const BYTE *imageBytes = (const BYTE *)reader_loader.image, *nameBytes = (const BYTE *)reader_loader.name;",
          'const imageBytes=Buffer.from(reader_loader.image,"utf16le"),nameBytes=Buffer.from(reader_loader.name,"utf16le");',
        )
        .replaceAll("size_t i", "let i")
        .replace("image+i*2", "pointer(image,i*2)")
        .replace("name+i*2", "pointer(name,i*2)")
        .replaceAll("sizeof(image)", "513")
        .replaceAll("sizeof(name)", "513")
        .replaceAll("sizeof(context)", "1400")
        .replaceAll("sizeof(bytes)", "2048")
        .replace("int size", "const size")
        .replace("(DWORD)size", "size")
        .replace("&written", "out")
        .replace("\\036", "\\x1e")}}`,
    );
  const image = "C:\\Fixture\\" + "λ".repeat(4084),
    name = "x".repeat(124) + ".dll";
  assert.equal(image.length, 4095);
  for (const kind of ["loader", "retain"]) {
    const f = transport(),
      response = f.channel.receive(),
      frames = [],
      retain = {
        active: true,
        pid: 33,
        processAccess: 0x120410,
        tokenAccess: 10,
        process: false,
        observedPid: 0,
        matched: -1,
        tokenResult: -1,
      };
    let lastError = 126;
    const emit = program.runInNewContext({
      reader_loader:
        kind === "loader"
          ? { active: true, image, name, flags: 0x860 }
          : { active: false },
      reader_retain: kind === "retain" ? retain : { active: false },
      reader_command:
        kind === "loader" ? "prepare-experiment-loader" : "verify-retain",
      sequence: 1378,
      control: "authenticated",
      TRUE: true,
      FALSE: false,
      NULL: null,
      Buffer,
      wcsnlen_s: (text, maximum) => Math.min(text.length, maximum),
      pointer: (parent, at) => ({ parent, at }),
      out: () => {},
      sprintf_s: (target, maximum, format, ...values) => {
        let at = 0;
        const value = format.replace(/%(?:02x|zu|lu|[sud])/gu, (specifier) => {
          const value = values[at++];
          return specifier === "%02x"
            ? value.toString(16).padStart(2, "0")
            : (value?.value ?? value);
        });
        assert.ok(Buffer.byteLength(value) < maximum);
        if (target.parent)
          target.parent.value = target.parent.value.slice(0, target.at) + value;
        else target.value = value;
        lastError = 999;
        return value.length;
      },
      WriteFile: (handle, bytes, size) => {
        assert.equal(handle, "authenticated");
        frames.push(bytes.value.slice(0, size));
        return true;
      },
    });
    assert.equal(emit("custody-reader.c", 307, lastError), true);
    assert.equal(frames.length, 1);
    assert.ok(Buffer.byteLength(frames[0]) <= 2048);
    f.child.stdout.write(frames[0].slice(0, 25));
    f.child.stdout.write(frames[0].slice(25));
    await assert.rejects(response, (error) => {
      const value = error.custodyReaderFailure;
      assert.equal(value.lastError, 126);
      assert.equal(value.sequence, 1378);
      if (kind === "loader") {
        assert.equal(value.loader.imageUnits, image.length);
        assert.equal(
          Buffer.from(value.loader.imageHex, "hex").toString("utf16le"),
          image.slice(0, 128),
        );
        assert.equal(
          Buffer.from(value.loader.importHex, "hex").toString("utf16le"),
          name,
        );
      } else {
        const { active: _active, ...expected } = retain;
        assert.deepEqual(value.retain, expected);
      }
      return true;
    });
    await assert.rejects(f.channel.completion);
    f.child.emit("close", 126, null);
  }
});

test("Windows failure metadata stays closed and bounded across complete and fragmented frames", async () => {
  const legacy = {
    phase: "reader-failure",
    sequence: 270,
    command: "verify-transfer",
    source: "custody-reader.c",
    line: 1,
  };
  const trust = {
    mode: "embedded",
    result: "0x00000005",
    closeResult: "0x00000000",
    entry: null,
    identity: id(11),
    sha256: null,
    signatureSha256: null,
  };
  const value = {
    ...legacy,
    lastError: 0xffffffff,
    transfer: {
      ordinal: 838859,
      count: 838860,
      type: 0xffff,
      access: 0xffffffff,
      attributes: 0xffffffff,
      creator: 127,
      child: 126,
    },
  };
  const loader = {
    ...legacy,
    command: "prepare-experiment-loader",
    lastError: 126,
    loader: {
      imageUnits: 4095,
      imageHex: Buffer.from("C:\\" + "x".repeat(125), "utf16le").toString(
        "hex",
      ),
      importHex: Buffer.from("fixture.dll", "utf16le").toString("hex"),
      flags: 0x860,
    },
  };
  const retain = {
    ...legacy,
    command: "verify-retain",
    lastError: 87,
    retain: {
      pid: 33,
      processAccess: 0x120410,
      tokenAccess: 10,
      process: false,
      observedPid: 0,
      matched: -1,
      tokenResult: -1,
    },
  };
  const opened = {
    ...legacy,
    lastError: 3,
    open: {
      operation: "CreateFileW",
      pathUnits: 4,
      pathUtf16: "0043003a005c0066",
      directory: false,
      apiFailure: true,
      attributes: null,
      tag: null,
    },
  };
  const invalid = [
    ...[
      { pathUnits: 4096 },
      { apiFailure: false },
      { attributes: 0 },
      { extra: true },
    ].map((damage) => ({ ...opened, open: { ...opened.open, ...damage } })),
    {
      ...opened,
      open: {
        ...opened.open,
        operation: "file-kind",
        apiFailure: false,
        attributes: 0x10,
        tag: 0xcafebabe,
      },
    },
    { ...opened, retain: retain.retain },
    ...[
      { flags: 0x800 },
      { flags: 0x801 },
      { imageUnits: 4096 },
      { imageUnits: 0 },
      { imageHex: "aa" },
      { importHex: "bad" },
      { importHex: "" },
      { importHex: Buffer.from("../fixture.dll", "utf16le").toString("hex") },
      { extra: true },
    ].map((damage) => ({ ...loader, loader: { ...loader.loader, ...damage } })),
    { ...loader, command: "open" },
    { ...loader, retain: retain.retain },
    { ...loader, trust },
    { ...loader, lastError: undefined },
    ...[
      { pid: 0 },
      { processAccess: 0 },
      { tokenAccess: 0 },
      { process: 0 },
      { observedPid: 33 },
      { matched: 0 },
      { tokenResult: 0 },
      { process: true, observedPid: 33, matched: 1, tokenResult: 1 },
      { extra: true },
    ].map((damage) => ({ ...retain, retain: { ...retain.retain, ...damage } })),
    { ...retain, transfer: value.transfer },
    { ...retain, lastError: undefined },
    ...[null, -1, 0x100000000, 1.5, "5", true, []].map((lastError) => ({
      ...value,
      lastError,
    })),
    { ...value, lastError: undefined },
    { ...value, command: "open" },
    { ...value, trust },
    { ...legacy, lastError: 5, trust },
    { ...value, extra: 1 },
    { ...value, transfer: null },
    ...[
      "ordinal",
      "count",
      "type",
      "access",
      "attributes",
      "creator",
      "child",
    ].flatMap((field) =>
      [-1, 1.5, "1", null, 0x100000000, undefined].map((entry) => ({
        ...value,
        transfer: { ...value.transfer, [field]: entry },
      })),
    ),
    ...[
      { ordinal: 838860 },
      { count: 0 },
      { count: 838861 },
      { type: 65536 },
      { creator: 128 },
      { child: 128 },
      { child: 127 },
      { extra: 1 },
    ].map((damage) => ({
      ...value,
      transfer: { ...value.transfer, ...damage },
    })),
  ];
  const valid = [
    opened,
    loader,
    {
      ...loader,
      command: "release-import",
      loader: { ...loader.loader, flags: 0x800 },
    },
    retain,
    {
      ...retain,
      retain: { ...retain.retain, process: true, observedPid: 34, matched: 0 },
    },
    {
      ...retain,
      retain: {
        ...retain.retain,
        process: true,
        observedPid: 33,
        matched: 1,
        tokenResult: 0,
      },
    },
    legacy,
    { ...legacy, trust },
    { ...legacy, lastError: 0 },
    value,
    { ...value, command: "verify-compiler-policy" },
  ];
  for (const [expected, packet] of [
    ...valid.map((p) => [true, p]),
    ...invalid.map((p) => [false, p]),
  ]) {
    const frame = "\x1e" + JSON.stringify(packet) + "\n";
    for (const split of [false, true]) {
      const f = transport(),
        response = f.channel.receive();
      f.child.stdout.write(frame.slice(0, split ? 25 : frame.length));
      if (split) f.child.stdout.write(frame.slice(25));
      await assert.rejects(response, (error) => {
        assert.equal(Object.hasOwn(error, "custodyReaderFailure"), expected);
        if (expected) assert.deepEqual(error.custodyReaderFailure, packet);
        return true;
      });
      await assert.rejects(f.channel.completion);
      assert.throws(() => f.channel.settle());
      f.child.emit("close", 126, null);
    }
  }
  const json = JSON.stringify(value);
  for (const [bytes, complete] of [
    [2048, true],
    [2049, true],
    [2049, false],
  ]) {
    const frame =
      "\x1e" +
      json +
      " ".repeat(bytes - 1 - json.length - Number(complete)) +
      (complete ? "\n" : "");
    for (const split of [false, true]) {
      const f = transport(),
        response = f.channel.receive();
      // A large interrupted ordinary response does not consume the diagnostic budget.
      f.child.stdout.write('{"value":"' + "x".repeat(2048));
      f.child.stdout.write(frame.slice(0, split ? 2048 : frame.length));
      if (split) f.child.stdout.write(frame.slice(2048));
      await assert.rejects(response, (error) => {
        assert.equal(
          Object.hasOwn(error, "custodyReaderFailure"),
          bytes === 2048,
        );
        return true;
      });
      await assert.rejects(f.channel.completion);
      assert.throws(() => f.channel.settle());
      f.child.emit("close", 126, null);
    }
  }
});

test("Windows trust diagnostics reject malformed status, entry and held-pin context", async () => {
  const trust = {
    mode: "embedded",
    result: "0x800b0100",
    closeResult: "0x00000000",
    entry: 11,
    identity: id(11),
    sha256: hash,
    signatureSha256: hash,
    inputs: [
      88, 32, 1, 1, 1, 0, 2, 0, 1, 0x1010, 0, 0, 0, 0, 0, 0, 0, 1024, 0, 1024,
    ],
    provider: [1, 1, 1, 1, 8, 0, 3, 1, 3, 1, 1, 5, 1],
  };
  for (const damage of [
    { result: 2148204800 },
    { result: "0x1" },
    { result: "0x00000000" },
    { closeResult: "0x100000000" },
    { mode: "fallback" },
    { entry: 128 },
    { entry: null },
    { identity: [id(11)] },
    { sha256: null },
    { signatureSha256: "substituted" },
    { inputs: [] },
    { inputs: Array(20).fill("unknown") },
    { inputs: Array(20).fill(2) },
    { provider: [] },
    { provider: Array(13).fill("unknown") },
    ...[
      [0, 2],
      [2, 0],
      [4, -1],
      [5, 0x100000000],
      [6, 2],
      [7, 0],
      [8, 65],
      [9, 4],
      [10, 3],
      [11, 0],
      [12, 0],
    ].map(([index, value]) => ({
      provider: trust.provider.with(index, value),
    })),
    { result: "0x00000000", closeResult: "0x00000005" },
    { extra: true },
  ]) {
    const f = transport(),
      response = f.channel.receive();
    f.child.stdout.write(
      "\x1e" +
        JSON.stringify({
          phase: "reader-failure",
          sequence: 2,
          command: "open",
          source: "custody.h",
          line: 1,
          trust: { ...trust, ...damage },
        }) +
        "\n",
    );
    await assert.rejects(
      response,
      (error) => !Object.hasOwn(error, "custodyReaderFailure"),
    );
    await assert.rejects(f.channel.completion);
    assert.throws(() => f.channel.settle());
    f.child.emit("close", 126, null);
  }
  const f = transport(),
    response = f.channel.receive(),
    unbound = {
      ...trust,
      mode: "catalog",
      entry: null,
      sha256: null,
      signatureSha256: null,
    };
  f.child.stdout.write(
    "\x1e" +
      JSON.stringify({
        phase: "reader-failure",
        sequence: 2,
        command: "signature",
        source: "custody.h",
        line: 1,
        trust: unbound,
      }) +
      "\n",
  );
  await assert.rejects(response, (error) => {
    assert.deepEqual(error.custodyReaderFailure.trust, unbound);
    return true;
  });
  await assert.rejects(f.channel.completion);
  assert.throws(() => f.channel.settle());
  f.child.emit("close", 126, null);
});

test("actual bridge relay settles original overlapped I/O and separates wait, exit-query and exit-code results", async () => {
  const source = await readFile(
      new URL("./custody-bridge.c", import.meta.url),
      "utf8",
    ),
    body = (name) =>
      new RegExp(
        `static DWORD ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)[1],
    translate = (text) =>
      text
        .replace("OVERLAPPED operation = {0};", "let operation={};")
        .replaceAll("(DWORD)", "")
        .replace(/\b(?:BOOL|DWORD|ULONGLONG)\b/gu, "let")
        .replaceAll("operation->", "operation.")
        .replaceAll("*used", "used.value")
        .replaceAll("&operation", "operation")
        .replace(/&(exit|code|forward_stopping)\b/gu, "value=>$1=value"),
    program =
      new Script(`function relay_wait(operation,timeout,used){${translate(body("relay_wait"))}}
      function relay_io(writing,bytes,size,used,timeout){${translate(body("relay_io"))}}
      function relay_retire(process,input){${translate(body("relay_retire"))}}`),
    constants = {
      TRUE: true,
      FALSE: false,
      NULL: null,
      ERROR_SUCCESS: 0,
      ERROR_IO_PENDING: 997,
      ERROR_IO_INCOMPLETE: 996,
      ERROR_GEN_FAILURE: 31,
      ERROR_TIMEOUT: 1460,
      ERROR_NOT_FOUND: 1168,
      WAIT_OBJECT_0: 0,
      WAIT_TIMEOUT: 258,
      WAIT_FAILED: 0xffffffff,
      STILL_ACTIVE: 259,
    },
    fixture = () => {
      const calls = [],
        reports = [];
      let error = 109;
      const api = {
        ...constants,
        pipe: "pipe",
        forward_stopping: 0,
        GetLastError: () => error,
        relay_report: (...record) => reports.push(record),
        relay_check: (operation, ok, value, error) => {
          if (!ok) throw { operation, value, error };
        },
        CloseHandle: (handle) => {
          calls.push(["close", handle]);
          error = 109;
          return true;
        },
      };
      program.runInNewContext(api);
      return { api, calls, reports, setError: (value) => (error = value) };
    };
  for (const fault of [
    null,
    "timeout",
    "wait",
    "completion",
    "close",
    "incomplete",
    "cancel-stalled",
    "cancel-wait",
  ]) {
    const f = fixture();
    let settled = false,
      tick = 1000,
      waits = 0;
    const cancelled = [
        "timeout",
        "wait",
        "cancel-stalled",
        "cancel-wait",
      ].includes(fault),
      unsettled = ["incomplete", "cancel-stalled", "cancel-wait"].includes(
        fault,
      );
    Object.assign(f.api, {
      GetTickCount64: () => tick,
      CreateEventW: () => "event",
      HasOverlappedIoCompleted: () => settled,
      WriteFile: () => {
        f.calls.push(["start"]);
        f.setError(997);
        return false;
      },
      WaitForSingleObject: (_event, timeout) => {
        f.calls.push(["wait", timeout]);
        f.setError(6);
        if (waits++ === 0) {
          assert.equal(timeout, 30000);
          tick += fault === "wait" ? 5 : cancelled ? 30000 : 0;
          return fault === "wait" ? 0xffffffff : cancelled ? 258 : 0;
        }
        assert.equal(timeout, fault === "wait" ? 29995 : 0);
        return fault === "cancel-stalled"
          ? 258
          : fault === "cancel-wait"
            ? 0xffffffff
            : 0;
      },
      CancelIoEx: () => {
        f.calls.push(["cancel"]);
        f.setError(fault === "cancel-stalled" ? 109 : 1168);
        return fault === "cancel-stalled";
      },
      GetOverlappedResult: (_pipe, _operation, used, wait) => {
        assert.equal(wait, false, "Completion queries must never block");
        f.calls.push(["complete", wait]);
        used.value = 8;
        const error =
          fault === "completion"
            ? 109
            : fault === "incomplete"
              ? 996
              : fault === "wait"
                ? 995
                : 0;
        settled = error !== 996;
        f.setError(error);
        return !error;
      },
      CloseHandle: () => {
        assert.equal(settled, true);
        f.calls.push(["close"]);
        f.setError(6);
        return fault !== "close";
      },
    });
    if (fault === "close" || unsettled)
      assert.throws(
        () => f.api.relay_io(true, {}, 8, { value: 0 }, 30000),
        (error) =>
          error.operation ===
          (fault === "close"
            ? "pipe-event-close"
            : fault === "incomplete"
              ? "pipe-settlement"
              : "pipe-settlement-wait"),
      );
    else
      assert.equal(
        f.api.relay_io(true, {}, 8, { value: 0 }, 30000),
        fault === "timeout"
          ? 1460
          : fault === "wait"
            ? 6
            : fault === "completion"
              ? 109
              : 0,
      );
    assert.equal(
      f.calls.some(([name]) => name === "cancel"),
      cancelled,
    );
    assert.equal(
      f.calls.some(([name]) => name === "complete"),
      !["cancel-stalled", "cancel-wait"].includes(fault),
    );
    assert.equal(
      f.calls.some(([name]) => name === "close"),
      !unsettled,
    );
    if (fault === "cancel-stalled")
      assert.ok(
        f.reports.some(
          ([name, value, error]) =>
            name === "pipe-cancel" && value === true && error === 0,
        ),
      );
    if (fault === "wait")
      assert.ok(
        f.reports.some(
          ([name, value, error]) =>
            name === "pipe-wait" && value === 0xffffffff && error === 6,
        ),
      );
  }
  // GS diagnostic framing and the subsequent RS fatal frame are opaque bytes
  // to the authenticated relay, including when one read coalesces both.
  {
    const f = fixture(),
      input = Buffer.from(
        '\x1d{"phase":"reader-diagnostic"}\n\x1e{"phase":"reader-failure"}\n',
      );
    Object.assign(f.api, {
      CreateEventW: () => "event",
      ReadFile(handle, bytes, size, used, operation) {
        assert.equal(handle, "pipe");
        assert.equal(operation.hEvent, "event");
        input.copy(bytes, 0, 0, size);
        used.value = Math.min(size, input.length);
        return true;
      },
    });
    const bytes = Buffer.alloc(input.length),
      used = { value: 0 };
    assert.equal(f.api.relay_io(false, bytes, bytes.length, used, 30000), 0);
    assert.deepEqual(bytes, input);
    assert.equal(used.value, input.length);
    assert.deepEqual(f.calls, [["close", "event"]]);
  }
  for (const fault of [
    null,
    "wait-timeout",
    "wait-failed",
    "query",
    "exit126",
    "exit124",
    "input",
    "input-late",
  ]) {
    const f = fixture();
    let tick = 0;
    Object.assign(f.api, {
      WaitForSingleObject: (handle, timeout) => {
        f.setError(5);
        if (handle === "input" && fault === "input-late") {
          assert.equal(timeout, 5);
          tick = 30000;
          return 0;
        }
        return handle === "reader"
          ? fault === "wait-timeout"
            ? 258
            : fault === "wait-failed"
              ? 0xffffffff
              : 0
          : 0;
      },
      GetExitCodeProcess: (_process, out) => {
        out(fault === "exit126" ? 126 : fault === "exit124" ? 124 : 0);
        f.setError(6);
        return fault !== "query";
      },
      InterlockedExchange: (out, value) => out(value),
      GetTickCount64: () => tick++,
      CancelSynchronousIo: () => {
        if (fault === "input-late") tick = 29995;
        f.setError(1168);
        return false;
      },
      CancelIoEx: () => {
        f.setError(1168);
        return false;
      },
      GetExitCodeThread: (_thread, out) => {
        out(fault === "input" ? 126 : 0);
        return true;
      },
    });
    if (fault)
      assert.throws(
        () => f.api.relay_retire("reader", "input"),
        (error) => {
          assert.equal(
            error.operation,
            fault.startsWith("wait")
              ? "reader-wait"
              : fault === "query"
                ? "reader-exit-query"
                : ["input", "input-late"].includes(fault)
                  ? "input-settlement"
                  : "reader-exit",
          );
          assert.equal(
            error.error,
            fault === "wait-failed" ? 5 : fault === "query" ? 6 : 0,
          );
          return true;
        },
      );
    else assert.equal(f.api.relay_retire("reader", "input"), 0);
    assert.deepEqual(
      f.calls,
      fault === "input-late" ? [] : [["close", "input"]],
    );
    assert.ok(
      f.reports.some(
        ([name, value]) =>
          name === "reader-exit-query" && value === (fault !== "query"),
      ),
    );
  }
});
test("Windows custody and observer task XML delegates service-account logon to registration", async () => {
  // Decode the actual C literal without invoking a Windows compiler or scheduler.
  const source = await readFile(
      new URL("./custody-bridge.c", import.meta.url),
      "utf8",
    ),
    literal = source.match(
      /\bwchar_t xml\[\d+\] = L("(?:[^"\\]|\\.)*");/u,
    )?.[1];
  assert.ok(literal, "Expected the bridge task XML literal");
  const xml = JSON.parse(literal);
  assert.doesNotMatch(xml, /<LogonType\b/u);
  assert.match(
    xml,
    /<Principal id="System"><UserId>S-1-5-18<\/UserId><RunLevel>HighestAvailable<\/RunLevel><\/Principal>/u,
  );
  assert.match(source, /definition = SysAllocString\(xml\)/u);
  assert.match(source, /VariantInit\(&empty\);/u);
  assert.match(
    source,
    /user\.vt = VT_BSTR; user\.bstrVal = SysAllocString\(L"S-1-5-18"\);/u,
  );
  const registration = source.match(
    /need_hr\(ITaskFolder_RegisterTask,\s*([^;]+)\);/u,
  );
  assert.ok(registration, "Expected checked Task Scheduler registration");
  assert.deepEqual(
    registration[1].split(",").map((argument) => argument.trim()),
    [
      "folder",
      "taskName",
      "definition",
      "TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE",
      "user",
      "empty",
      "TASK_LOGON_SERVICE_ACCOUNT",
      "securityValue",
      "&task",
    ],
  );
});

test("Windows task principals route SID syntax and account names to exact LocalSystem validation", async () => {
  const source = await readFile(
      new URL("./custody-bridge.c", import.meta.url),
      "utf8",
    ),
    body = source.match(
      /need\(CreateWellKnownSid\(WinLocalSystemSid,[\s\S]*?(?=  SysFreeString\(text\);)/u,
    )?.[0];
  assert.ok(body);
  const check = new Script(
    body
      .replace("PSID actual;", "const actual = {};")
      .replaceAll('L"', '"')
      .replaceAll(/&([a-zA-Z]+)/gu, "$1")
      .replaceAll(/\bNULL\b/gu, "null"),
  );
  for (const [text, route, result, accepted] of [
    ["S-1-5-18", "sid", "S-1-5-18", true],
    ["SYSTEM", "name", "S-1-5-18", true],
    ["S-1-invalid", "sid", null, false],
    ["S-1-5-19", "sid", "S-1-5-19", false],
    ["FixtureUser", "name", "S-1-5-21-1-2-3-1001", false],
    ["UnmappedUser", "name", null, false],
    ["S-1-5-18", "sid", "invalid-sid", false],
  ]) {
    const calls = [],
      resolve = (kind, value, output) => {
        assert.equal(value, text);
        calls.push(kind);
        output.valid = result !== "invalid-sid";
        output.value = output.valid ? result : "S-1-5-18";
        return result !== null;
      };
    const api = {
      text,
      sid: {},
      expected: {},
      size: 0,
      expectedSize: 0,
      domain: null,
      domainSize: 0,
      type: 0,
      WinLocalSystemSid: "system",
      need: assert.ok,
      LocalFree() {},
      CreateWellKnownSid(_, __, output) {
        output.value = "S-1-5-18";
        return true;
      },
      _wcsnicmp: (left, right, size) =>
        left.slice(0, size).toLowerCase().localeCompare(right.toLowerCase()),
      ConvertStringSidToSidW: (value, output) => resolve("sid", value, output),
      LookupAccountNameW: (_, value, output) => resolve("name", value, output),
      IsValidSid: (sid) => sid.valid,
      EqualSid: (left, right) => left.value === right.value,
    };
    if (accepted) check.runInNewContext(api);
    else assert.throws(() => check.runInNewContext(api), assert.AssertionError);
    assert.deepEqual(calls, [route]);
  }
});

test("Windows installed-input open guards diagnose only sampled failures and preserve native errors", async () => {
  const source = await readFile(new URL("custody.h", import.meta.url), "utf8"),
    refusal = /static void open_file_refusal\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1],
    opening = /static HANDLE open_file_shared\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(refusal && opening);
  const reader = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    start = reader.indexOf("  if (open_file_failure.name) {"),
    sending = reader.slice(start, reader.indexOf("#endif", start));
  assert.ok(start > 0 && sending);
  const failure = /static void reader_failure\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      reader,
    )[1],
    dispatch = new Script(
      `(file,line,error)=>{${failure
        .slice(0, failure.indexOf("  char bytes[1024]"))
        .replace("const char *source", "let source")
        .replace("source+1", "source.slice(1)")}
        throw new Error("Missing native failure context");
      }`,
    ),
    strrchr = (file, separator) => {
      const index = file.lastIndexOf(separator);
      return index < 0 ? null : file.slice(index);
    };
  const formatC = (text, args) => {
    let i = 0;
    return text.replace(/%(?:0(\d+))?(s|lu|zu|u|lx|x)/gu, (_, width, kind) => {
      const argument = args[i++],
        value = argument?.value ?? argument;
      return kind === "s"
        ? value
        : Number(value)
            .toString(kind.endsWith("x") ? 16 : 10)
            .padStart(Number(width ?? 0), "0");
    });
  };
  const translate = (body) =>
    body
      .replace(
        "FILE_ATTRIBUTE_TAG_INFO tag; wchar_t canonical[4100]; DWORD size;",
        "const tag = {}, canonical = 0; let size;",
      )
      .replaceAll(/\((?:unsigned long|unsigned)\)/gu, "")
      .replaceAll(/\b(?:DWORD|HANDLE|size_t|int) /gu, "let ")
      .replaceAll("tag->", "tag.")
      .replaceAll("&tag", "tag")
      .replaceAll('L"', '"')
      .replaceAll(/\bNULL\b/gu, "null");
  const sender = new Script(
    `function publish(source, line, error) {${translate(sending)
      .replace(
        'char bytes[17408], path[16385] = {0}, attributes[16] = "null", tag[16] = "null";',
        'const bytes = {value:""}, path = {value:""}, attributes = {value:"null"}, tag = {value:"null"};',
      )
      .replaceAll(
        /sizeof\((bytes|path|attributes|tag)\)/gu,
        (_, name) =>
          ({ bytes: 17408, path: 16385, attributes: 16, tag: 16 })[name],
      )
      .replaceAll("path+i*4", "{parent:path, offset:i*4}")
      .replaceAll("(DWORD)", "")
      .replaceAll("&written", "null")
      .replaceAll("\\036", "\\x1e")} return FALSE;} publish;`,
  );
  const selected = "C:\\Fixture SDK\\\ud83d\ude00\\Windows.h";
  for (const experiment of [false, true]) {
    const body = opening.replace(
        /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#else\n([\s\S]*?)#endif/gu,
        (_, ordinary, reviewed) => (experiment ? ordinary : reviewed),
      ),
      program = new Script(`
        function open_file_refusal(name, operation, api_failure, directory, tag) {${translate(refusal)}}
        function open_file_shared(name, directory, access, mutable) {${translate(body).replaceAll("sizeof(tag)", "8")}}
        open_file_shared(name, directory, 1, false);
      `);
    for (const [fault, directory, file = selected] of [
      ["open", false],
      ["query", false],
      ["reparse", false],
      ["kind", false],
      ["kind", true, "C:\\Fixture SDK"],
      ["query", true, "C:\\Fixture SDK"],
      ["open", true, "C:\\"],
      ["write", false],
      ...[
        "final-query",
        "final-small",
        "final-large",
        "final-prefix",
        "final-equality",
        "inheritance",
      ].map((fault) => [fault, false]),
      ["open", false, "C:\\" + "x".repeat(4092)],
      [null, false],
      [null, true, "C:\\"],
    ]) {
      const calls = [],
        chunks = [],
        name = Uint16Array.from(
          file
            .split("")
            .map((unit) => unit.charCodeAt(0))
            .concat(0),
        ),
        apiFailure = [
          "open",
          "write",
          "query",
          "final-query",
          "inheritance",
        ].includes(fault),
        refusalError = apiFailure
          ? ["query", "inheritance"].includes(fault)
            ? 5
            : 3
          : fault?.startsWith("final-")
            ? 0
            : 87,
        attributes =
          fault === "reparse"
            ? 0x420
            : directory !== (fault === "kind")
              ? 0x10
              : 0x20,
        // Without the reparse attribute, Windows leaves ReparseTag undefined.
        tag = fault === "reparse" ? 0xa000000c : 0xcafebabe;
      let error = 87;
      const emit = (bytes) => {
          error = 999;
          api.errno = 99;
          if (fault === "write") return -1;
          chunks.push(bytes);
          return bytes.length;
        },
        api = {
          name,
          directory: Number(directory),
          errno: 23,
          stderr: "stderr",
          open_file_failure: { tag: {} },
          TRUE: 1,
          FALSE: 0,
          INVALID_HANDLE_VALUE: -1,
          READ_CONTROL: 0x20000,
          FILE_READ_ATTRIBUTES: 0x80,
          FILE_SHARE_READ: 1,
          FILE_SHARE_WRITE: 2,
          OPEN_EXISTING: 3,
          FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
          FILE_FLAG_BACKUP_SEMANTICS: 0x2000000,
          FILE_ATTRIBUTE_REPARSE_POINT: 0x400,
          FILE_ATTRIBUTE_DIRECTORY: 0x10,
          FileAttributeTagInfo: 9,
          FILE_NAME_NORMALIZED: 0,
          VOLUME_NAME_DOS: 0,
          HANDLE_FLAG_INHERIT: 1,
          CreateFileW(actual, access, share) {
            assert.equal(actual, name);
            assert.equal(access, 0x20081);
            assert.equal(share, directory ? 3 : 1);
            calls.push("open");
            if (["open", "write"].includes(fault)) {
              error = 3;
              return -1;
            }
            return 7;
          },
          GetFileInformationByHandleEx(handle, kind, actual, size) {
            assert.equal(handle, 7);
            assert.equal(kind, 9);
            assert.equal(size, 8);
            calls.push("query");
            if (fault === "query") {
              error = 5;
              return 0;
            }
            Object.assign(actual, {
              FileAttributes: attributes,
              ReparseTag: tag,
            });
            return 1;
          },
          GetFinalPathNameByHandleW() {
            calls.push("canonical");
            if (fault?.startsWith("final-"))
              error = fault === "final-query" ? 3 : 0;
            return fault === "final-query"
              ? 0
              : fault === "final-small"
                ? 4
                : fault === "final-large"
                  ? 4100
                  : 20;
          },
          SetHandleInformation() {
            calls.push("inheritance");
            if (fault === "inheritance") {
              error = 5;
              return 0;
            }
            return 1;
          },
          GetLastError() {
            calls.push("error");
            return error;
          },
          SetLastError(value) {
            error = value;
          },
          wcslen: (value) => value.indexOf(0),
          wcsncmp: () => (fault === "final-prefix" ? 1 : 0),
          wcscmp: () => (fault === "final-equality" ? 1 : 0),
          fprintf(stream, format, ...args) {
            assert.equal(stream, "stderr");
            return emit(formatC(format, args));
          },
          fputs: (text) => emit(text),
          fputc: (unit) => emit(unit),
          fflush: () => {
            error = 998;
          },
          need(ok) {
            if (!ok)
              throw Object.assign(new Error("Original open refusal"), {
                lastError: error,
              });
          },
        };
      if (fault) {
        assert.throws(
          () => program.runInNewContext(api),
          (cause) => {
            assert.equal(cause.message, "Original open refusal");
            assert.equal(cause.lastError, refusalError);
            return true;
          },
        );
        assert.equal(api.errno, 23);
        assert.deepEqual(calls, [
          "open",
          ...(["open", "write"].includes(fault) ? [] : ["query"]),
          ...(fault?.startsWith("final-") || fault === "inheritance"
            ? ["canonical"]
            : []),
          ...(fault === "inheritance" ? ["inheritance"] : []),
          ...(experiment ? ["error"] : []),
        ]);
      } else {
        assert.equal(program.runInNewContext(api), 7);
        assert.deepEqual(calls, ["open", "query", "canonical", "inheritance"]);
      }
      const output = chunks.join("");
      if (!experiment || !fault || fault === "write") assert.equal(output, "");
      else {
        const operation =
          fault === "open"
            ? "CreateFileW"
            : fault === "query"
              ? "GetFileInformationByHandleEx/FileAttributeTagInfo"
              : fault === "reparse"
                ? "reparse-point"
                : fault === "final-query"
                  ? "GetFinalPathNameByHandleW"
                  : fault === "final-small" || fault === "final-large"
                    ? "final-path-size"
                    : fault === "final-prefix"
                      ? "final-path-prefix"
                      : fault === "final-equality"
                        ? "final-path-equality"
                        : fault === "inheritance"
                          ? "SetHandleInformation"
                          : "file-kind";
        assert.ok(
          output.includes(
            `operation=${operation} domain=${apiFailure ? "win32" : "invariant"} expected-kind=${directory ? "directory" : "file"}`,
          ),
        );
        assert.ok(
          output.includes(
            apiFailure
              ? `error=${refusalError} attributes=unavailable tag=unavailable`
              : `error=unavailable attributes=0x${attributes.toString(16).padStart(8, "0")} tag=${fault === "reparse" ? `0x${tag.toString(16).padStart(8, "0")}` : "unavailable"}`,
          ),
        );
        assert.ok(
          output.endsWith(
            `path-units=${file.length} path-utf16=${file
              .split("")
              .map((unit) => unit.charCodeAt(0).toString(16).padStart(4, "0"))
              .join("")}\n`,
          ),
        );
      }
      if (experiment && fault) {
        const frames = [];
        Object.assign(api, {
          capturedError: refusalError,
          reader_diagnostics_ready: true,
          ownership_refusal_collect: () => {},
          refusal_settle: () => {},
          signature_trust: { active: false },
          strrchr,
          reader_witness_failure: () => false,
          ownership_failure_write: () => false,
          ownership_failure_fence: () => {},
          reader_cold_failure: () => false,
          reader_baseline_failure: () => false,
          reader_scheduler_failure: () => false,
          reader_context_failure() {
            assert.fail("Loader context masked the sampled open refusal");
          },
          sequence: 459,
          reader_command: "prepare-experiment-input",
          control: "authenticated",
          sprintf_s(target, maximum, format, ...args) {
            const text = formatC(format, args);
            assert.ok(text.length < maximum);
            if (target.parent)
              target.parent.value =
                target.parent.value.slice(0, target.offset) + text;
            else target.value = text;
            return text.length;
          },
          WriteFile(handle, bytes, size) {
            assert.equal(handle, "authenticated");
            if (fault === "write") return false;
            frames.push(bytes.value.slice(0, size));
            return true;
          },
        });
        api.reader_open_failure = sender.runInNewContext(api);
        dispatch.runInNewContext(api)("custody.h", 174, api.capturedError);
        if (fault === "write") assert.deepEqual(frames, []);
        else {
          assert.equal(frames.length, 1);
          assert.ok(Buffer.byteLength(frames[0]) < 17408);
          const f = transport(),
            pending = f.channel.receive().catch((cause) => cause),
            completion = f.channel.completion.catch((cause) => cause);
          try {
            f.child.stdout.write(frames[0].slice(0, 29));
            f.child.stdout.write(frames[0].slice(29));
            const cause = await pending;
            assert.equal(
              cause.custodyReaderFailure.lastError,
              api.capturedError,
            );
            const observed = cause.custodyReaderFailure.open;
            assert.equal(observed.pathUnits, file.length);
            assert.equal(
              observed.pathUtf16,
              file
                .split("")
                .map((unit) => unit.charCodeAt(0).toString(16).padStart(4, "0"))
                .join(""),
            );
            assert.equal(observed.apiFailure, apiFailure);
            assert.equal(observed.attributes, apiFailure ? null : attributes);
            assert.equal(observed.tag, fault === "reparse" ? tag : null);
            f.child.emit("close", 126, null);
            assert.equal(await completion, cause);
          } finally {
            f.channel.close();
            f.child.stdin.destroy();
            f.child.stdout.destroy();
            f.child.stderr.destroy();
          }
        }
      }
    }
  }
  const fallback = [];
  dispatch.runInNewContext({
    reader_diagnostics_ready: true,
    ownership_refusal_collect: () => {},
    refusal_settle: () => {},
    signature_trust: { active: false },
    strrchr,
    reader_open_failure() {
      fallback.push("open");
      return false;
    },
    reader_witness_failure: () => false,
    ownership_failure_write: () => false,
    ownership_failure_fence: () => {},
    reader_cold_failure: () => false,
    reader_baseline_failure: () => false,
    reader_scheduler_failure: () => false,
    reader_context_failure(source, line, error) {
      fallback.push([source, line, error]);
      return true;
    },
  })("custody-reader.c", 274, 87);
  assert.deepEqual(fallback, ["open", ["custody-reader.c", 274, 87]]);
});

test("loaded module spelling joins the exact canonical guard through retained identity and mapping", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    header = await readFile(new URL("custody.h", import.meta.url), "utf8"),
    body =
      /static struct held_file hold_loaded_module\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
        source,
      )[1],
    opening = /static HANDLE open_file_shared\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      header,
    )[1],
    producer = /DWORD length = GetModuleFileNameExW\([^\n]+/u.exec(source)[0],
    admission = /files\[i\] = hold_loaded_module\(paths\[i\]\);/u.exec(
      source,
    )[0],
    mapping =
      /wchar_t mapped\[4100\], named\[4100\];[^\n]+\n    need\(mappedSize[^\n]+/u.exec(
        source,
      )[0];
  const translate = (text) =>
    text
      .replace(
        /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#else\n[\s\S]*?#endif/gu,
        "$1",
      )
      .replace(
        "FILE_ATTRIBUTE_TAG_INFO tag; FILE_ID_INFO before, after; wchar_t canonical[4100], parent[4096];",
        'const tag={}, before={}, after={}, canonical={text:""}, parent={text:""};',
      )
      .replace(
        "FILE_ATTRIBUTE_TAG_INFO tag; wchar_t canonical[4100]; DWORD size;",
        'const tag={}, canonical={text:""}; let size;',
      )
      .replace(
        "wchar_t mapped[4100], named[4100];",
        'const mapped={text:""}, named={text:""};',
      )
      .replace("HANDLE parents[32]", "const parents=[]")
      .replace("wchar_t *slash", "let slash")
      .replaceAll(
        "*slash = 0",
        "slash.buffer.text=slash.buffer.text.slice(0,slash.index)",
      )
      .replace("struct held_file file", "const file")
      .replaceAll(/\b(?:HANDLE|DWORD|BOOL|unsigned) /gu, "let ")
      .replaceAll(/sizeof\([^)]+\)/gu, "1")
      .replaceAll(/&(tag|before|after|file.id)\b/gu, "$1")
      .replaceAll(/\bL(?=["'])/gu, "")
      .replaceAll(/canonical\[(\d)\]/gu, "canonical.text[$1]")
      .replaceAll(/name\[(\d)\]/gu, "name.text[$1]")
      .replaceAll(/canonical\s*\+\s*4/gu, "canonical.text.slice(4)")
      .replaceAll("paths[i]", "name")
      .replaceAll("modules[i]", "module")
      .replaceAll("files[i].handle", "file.handle");
  const program = new Script(`
    function open_file_shared(name,directory,access,mutable) {${translate(opening)}}
    function hold_loaded_module(name) {${translate(body)}}
    ${translate(producer)}
    ${translate(admission).replace("files[i] =", "const file =")}
    ${translate(mapping)}
    file;
  `);
  const canonical = "C:\\Fixture Runtime\\module.dll",
    loaded = "C:\\FIXTUR~1\\MODULE.dll",
    text = (value) => (typeof value === "string" ? value : value.text);
  for (const fault of [
    null,
    "producer",
    "open",
    "reparse",
    "parent-reparse",
    "query",
    "bounds",
    "prefix",
    "canonical",
    "identity",
    "changed",
    "mapping",
    "inheritance",
    "close",
  ]) {
    let next = 1,
      activeFault = null;
    const handles = new Map(),
      calls = [],
      refused = [],
      name = { text: "" };
    const api = {
      name,
      process: 11,
      module: 19,
      TRUE: true,
      FALSE: false,
      NULL: null,
      INVALID_HANDLE_VALUE: -1,
      GENERIC_READ: 0x80000000,
      READ_CONTROL: 0x20000,
      FILE_READ_ATTRIBUTES: 0x80,
      FILE_SHARE_READ: 1,
      FILE_SHARE_WRITE: 2,
      OPEN_EXISTING: 3,
      FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
      FILE_FLAG_BACKUP_SEMANTICS: 0x2000000,
      FILE_ATTRIBUTE_REPARSE_POINT: 0x400,
      FILE_ATTRIBUTE_DIRECTORY: 0x10,
      HANDLE_FLAG_INHERIT: 1,
      FileAttributeTagInfo: 9,
      FileIdInfo: 18,
      FILE_NAME_NORMALIZED: 0,
      VOLUME_NAME_DOS: 0,
      VOLUME_NAME_NT: 2,
      GetModuleFileNameExW(process, module, out, capacity) {
        assert.deepEqual([process, module, capacity], [11, 19, 4096]);
        out.text = loaded;
        return activeFault === "producer" ? 4096 : loaded.length;
      },
      CreateFileW(path, access, share, _security, disposition, flags) {
        const value = text(path),
          directory = !value.endsWith(".dll");
        assert.equal(access, (directory ? 0 : 0x80000000) | 0x20080);
        assert.equal(share, directory ? 3 : 1);
        assert.equal(disposition, 3);
        assert.equal(flags, 0x2200000);
        calls.push(`open:${value}`);
        if (activeFault === "open") return -1;
        const handle = next++;
        handles.set(handle, { path: value, directory, closed: false });
        return handle;
      },
      GetFileInformationByHandleEx(handle, kind, out) {
        const entry = handles.get(handle);
        assert.ok(entry && !entry.closed);
        if (kind === 9) {
          out.FileAttributes =
            (entry.directory ? 0x10 : 0) |
            (activeFault === (entry.directory ? "parent-reparse" : "reparse")
              ? 0x400
              : 0);
        } else {
          assert.equal(kind, 18);
          out.value =
            activeFault === "changed" && calls.includes("hold")
              ? "replaced"
              : "original";
        }
        return true;
      },
      GetFinalPathNameByHandleW(handle, out, capacity, flags) {
        const entry = handles.get(handle);
        assert.ok(entry && !entry.closed);
        assert.equal(capacity, 4100);
        const raw = entry.path === loaded;
        if (raw && activeFault === "query") return 0;
        if (raw && activeFault === "bounds") return 4100;
        out.text =
          flags === 2
            ? "\\Device\\FixtureVolume\\Fixture Runtime\\module.dll"
            : raw && activeFault === "prefix"
              ? canonical
              : "\\\\?\\" +
                (activeFault === "canonical" && !raw
                  ? "C:\\Other\\module.dll"
                  : canonical);
        return out.text.length;
      },
      GetMappedFileNameW(process, module, out, capacity) {
        assert.deepEqual([process, module, capacity], [11, 19, 4100]);
        out.text =
          "\\Device\\FixtureVolume\\" +
          (activeFault === "mapping"
            ? "other.dll"
            : "Fixture Runtime\\module.dll");
        return out.text.length;
      },
      SetHandleInformation(handle, flag, value) {
        assert.ok(handles.has(handle));
        assert.deepEqual([flag, value], [1, 0]);
        return activeFault !== "inheritance";
      },
      hold(path, directory, privateFile, access) {
        assert.equal(path, canonical);
        assert.deepEqual(
          [directory, privateFile, access],
          [false, false, 0x80000000],
        );
        assert.ok(
          [...handles.values()].some(
            (entry) => entry.directory && !entry.closed,
          ),
          "original parent stays held through canonical admission",
        );
        const handle = api.openCanonical(path, directory, access, false);
        calls.push("hold");
        // Existing hold coverage owns volume, ACL and retained canonical-parent reads.
        return {
          handle,
          path,
          id: { value: activeFault === "identity" ? "other" : "original" },
        };
      },
      CloseHandle(handle) {
        const entry = handles.get(handle);
        assert.ok(entry && !entry.closed);
        entry.closed = true;
        calls.push("close");
        return activeFault !== "close";
      },
      wcslen: (value) => text(value).length,
      wcscpy_s: (out, _capacity, value) => {
        out.text = text(value);
      },
      wcsrchr: (buffer, char) => ({
        buffer,
        index: buffer.text.lastIndexOf(char),
      }),
      wcsncmp: (left, right, count) =>
        text(left).slice(0, count) === right.slice(0, count) ? 0 : 1,
      wcscmp: (left, right) => (text(left) === text(right) ? 0 : 1),
      _wcsicmp: (left, right) =>
        text(left).toLowerCase() === text(right).toLowerCase() ? 0 : 1,
      memcmp: (left, right) => (left.value === right.value ? 0 : 1),
      open_file_refusal(_name, operation) {
        refused.push(operation);
      },
      need: assert.ok,
    };
    // Expose the actual strict guard to the injected non-path parts of hold.
    const expose = new Script(
      `function open_file_shared(name,directory,access,mutable) {${translate(opening)}} open_file_shared;`,
    );
    api.openCanonical = expose.runInNewContext(api);
    assert.equal(program.runInNewContext(api).path, canonical);
    assert.equal(name.text, canonical);
    assert.equal(refused.length, 0);
    if (fault) {
      activeFault = fault;
      calls.length = 0;
      assert.throws(
        () => program.runInNewContext({ ...api }),
        assert.AssertionError,
        fault,
      );
      if (fault === "canonical")
        assert.deepEqual(refused, ["final-path-equality"]);
    }
  }
});

test("Windows account readback distinguishes ordinary metadata variation from reviewed privilege and authority refusals", async () => {
  const [account, custody, launcher] = await Promise.all(
    ["account.h", "custody.h", "launcher.c"].map((file) =>
      readFile(new URL(file, import.meta.url), "utf8"),
    ),
  );
  const start = account.indexOf(
      "  USER_INFO_1 *user = NULL;",
      account.indexOf("static void account_check("),
    ),
    end = account.indexOf("  LSA_OBJECT_ATTRIBUTES attributes", start);
  assert.ok(start > 0 && end > start);
  const project = (source, experiment = false) =>
    source
      .replace(
        /#ifndef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#endif/gu,
        (_, reviewed) => (experiment ? "" : reviewed),
      )
      .replace("USER_INFO_1 *user = NULL", "let user = NULL")
      .replace("(BYTE **)&user", "{set value(v){user=v}}")
      .replace(/\(unsigned\)(present|sampled)\b/gu, "Number($1)")
      .replace(/\((?:unsigned|DWORD)\)/gu, "")
      .replace(/\b(?:NET_API_STATUS|DWORD|bool) /gu, "let ")
      .replaceAll("->", ".")
      .replace(/^#(?:ifdef|endif).*$/gmu, "");
  const expectedFlags = 0x10201;
  for (const [owner, source, experiment] of [
    ["custody", custody, false],
    ["custody", custody, true],
    ["launcher", launcher, false],
    ["launcher", launcher, true],
  ]) {
    const guard = /static void need_at\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
    assert.ok(guard);
    const program = new Script(`
      function need_at(ok,file,line){${project(guard)}}
      function need(ok){need_at(!!ok,"account.h",17);}
      (name)=>{${project(account.slice(start, end), experiment)}}
    `);
    for (const [options, expectedError, predicate] of [
      [{}, null],
      [{ status: 5, present: false }, 5, "status"],
      [{ status: 234 }, 234, "status"],
      [{ present: false }, 13, "buffer"],
      [{ privilege: 2 }, experiment ? null : 13, "privilege"],
      [{ privilege: 0 }, experiment ? null : 13, "privilege"],
      [{ privilege: 0xffffffff }, experiment ? null : 13, "privilege"],
      [{ privilege: 2, release: 87 }, experiment ? 87 : 13, "release"],
      [{ flags: expectedFlags + 0x80000000 }, 13, "flags"],
      [{ release: 87 }, 87, "release"],
      [{ status: 5, release: 87 }, 5, "status"],
      [{ flags: 1, release: 87 }, 13, "flags"],
    ])
      for (const diagnosticFailure of [false, true]) {
        const calls = [],
          diagnostics = [],
          guards = [],
          inspected = [];
        let lastError = 0,
          freed = false;
        const present = options.present !== false,
          sampled = !options.status && present;
        const user = {};
        for (const key of [
          "usri1_priv",
          "usri1_flags",
          "usri1_password",
          "usri1_name",
        ])
          Object.defineProperty(user, key, {
            get() {
              assert.ok(
                sampled && !freed,
                "Only successful live numeric fields may be read",
              );
              assert.ok(
                ["usri1_priv", "usri1_flags"].includes(key),
                "Credentials and account structures are never read for diagnostics",
              );
              inspected.push(key);
              return key === "usri1_priv"
                ? (options.privilege ?? 1)
                : (options.flags ?? expectedFlags);
            },
          });
        const api = {
          NULL: null,
          stderr: {},
          NERR_Success: 0,
          USER_PRIV_USER: 1,
          UF_SCRIPT: 1,
          UF_NORMAL_ACCOUNT: 0x200,
          UF_DONT_EXPIRE_PASSWD: 0x10000,
          ERROR_INVALID_DATA: 13,
          NetUserGetInfo(server, name, level, output) {
            assert.deepEqual(
              [server, name, level],
              [null, "fixture-account", 1],
            );
            calls.push("query");
            output.value = present ? user : null;
            lastError = 0; // NetAPI status is independent of GetLastError.
            return options.status ?? 0;
          },
          NetApiBufferFree(value) {
            assert.equal(value, user);
            assert.equal(freed, false);
            calls.push("release");
            freed = true;
            lastError = 99;
            return options.release ?? 0;
          },
          GetLastError() {
            return lastError;
          },
          SetLastError(value) {
            lastError = value;
          },
          fprintf(_stream, format, ...values) {
            diagnostics.push({ format, values });
            assert.ok(
              values.every((value) => Number.isInteger(value)),
              "Only bounded numeric facts enter diagnostics",
            );
            let index = 0;
            const text = format.replace(/%(?:lu|u)/gu, () =>
              String(values[index++]),
            );
            assert.ok(Buffer.byteLength(text) < 384);
            lastError = 100;
            return diagnosticFailure ? -1 : text.length;
          },
          fflush() {
            lastError = 101;
            return diagnosticFailure ? -1 : 0;
          },
          NATIVE_CUSTODY_FAILURE(_file, _line, error) {
            guards.push(error);
            lastError = 102;
          },
          stop_job(code) {
            assert.equal(code, 126);
            calls.push("stop-job");
          },
          ExitProcess(code) {
            throw Object.assign(new Error("Account admission refused"), {
              code,
            });
          },
        };
        // The existing generic guard has a string file argument; account-specific
        // observations above must remain numeric, even on diagnostic I/O failure.
        const write = api.fprintf;
        api.fprintf = (stream, format, ...values) => {
          if (format.startsWith("native-windows-guard:")) {
            assert.equal(values[0], "account.h");
            guards.push(values[2]);
            lastError = 103;
            return diagnosticFailure ? -1 : 0;
          }
          return write(stream, format, ...values);
        };
        const run = () => program.runInNewContext(api)("fixture-account");
        if (expectedError === null) run();
        else assert.throws(run, { code: 126 });
        assert.deepEqual(
          inspected,
          sampled ? ["usri1_priv", "usri1_flags"] : [],
        );
        assert.deepEqual(calls, [
          "query",
          ...(present ? ["release"] : []),
          ...(expectedError !== null && owner === "launcher"
            ? ["stop-job"]
            : []),
        ]);
        assert.deepEqual(
          guards,
          expectedError === null
            ? []
            : Array(owner === "custody" ? 2 : 1).fill(expectedError),
        );
        assert.equal(
          diagnostics.length,
          expectedError === null ? 0 : options.release ? 2 : 1,
        );
        if (expectedError === null) continue;
        assert.deepEqual(diagnostics[0].values, [
          options.status ?? 0,
          Number(present),
          Number(sampled),
          sampled ? (options.privilege ?? 1) : 0,
          sampled ? (options.flags ?? expectedFlags) : 0,
          1,
          expectedFlags,
        ]);
        if (options.release)
          assert.deepEqual(diagnostics[1].values, [87], predicate);
      }
  }
});

test("Windows account-only adoption and retirement retain exact principal, group and rights checks without a child token", async () => {
  const source = await readFile(new URL("account.h", import.meta.url), "utf8"),
    body = /static void account_check\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(body);
  const start = body.indexOf("  USER_INFO_1 *user = NULL;"),
    end = body.indexOf("  LSA_OBJECT_ATTRIBUTES attributes", start);
  assert.ok(start > 0 && end > start);
  // The preceding regression owns NetAPI metadata/release and both build modes.
  // Execute the remaining account authority guards with no child/token APIs.
  const project = (body.slice(0, start) + body.slice(end))
      .replace("BYTE sid[SECURITY_MAX_SID_SIZE];", "const sid = {};")
      .replace("wchar_t domain[256], *text;", "const domain = []; let text;")
      .replace("LOCALGROUP_USERS_INFO_0 *groups;", "let groups;")
      .replace(
        "LSA_OBJECT_ATTRIBUTES attributes = {0};",
        "const attributes = {};",
      )
      .replace("LSA_UNICODE_STRING *rights;", "let rights;")
      .replace("&attributes", "attributes")
      .replace(
        /const wchar_t \*approved\[\] = \{([^;]+)\}/u,
        "const approved = [$1]",
      )
      .replace("(BYTE **)&groups", "&groups")
      .replace(
        /&(sidSize|domainSize|type|text|groups|count|total|policy|rights|number)\b/gu,
        (_, name) => `{set value(v){${name}=v}}`,
      )
      .replace(/sizeof\(\w+\)/gu, "1")
      .replace(/\b(\d+)U\b/gu, "$1")
      .replace(/\b(?:DWORD|SID_NAME_USE|LSA_HANDLE|ULONG|unsigned) /gu, "let ")
      .replaceAll('L"', '"'),
    program = new Script(`(name, expected)=>{${project}}`),
    expected = "S-1-5-21-1-2-3-1001",
    approved = [
      "SeBatchLogonRight",
      "SeDenyInteractiveLogonRight",
      "SeDenyRemoteInteractiveLogonRight",
      "SeDenyNetworkLogonRight",
      "SeDenyServiceLogonRight",
    ];
  for (const options of [
    {},
    { sid: "S-1-5-21-1-2-3-1002" },
    { type: 2 },
    { groupStatus: 5 },
    { count: 1 },
    { total: 1 },
    { rightsStatus: 5 },
    { rights: approved.slice(1) },
    { rights: [...approved.slice(0, 4), "SeDebugPrivilege"] },
    { rights: [...approved.slice(0, 4), approved[0]] },
  ]) {
    const reads = [],
      rights = (options.rights ?? approved).map((name) => ({
        Buffer: name,
        Length: name.length,
      })),
      api = {
        NULL: null,
        SECURITY_MAX_SID_SIZE: 68,
        MAX_PREFERRED_LENGTH: -1,
        SidTypeUser: 1,
        NERR_Success: 0,
        POLICY_LOOKUP_NAMES: 1,
        need(ok) {
          assert.ok(ok, "Account authority refused");
        },
        LookupAccountNameW(server, name, sid, size, domain, domainSize, type) {
          assert.equal(name, "fixture-account");
          reads.push("principal");
          sid.text = options.sid ?? expected;
          type.value = options.type ?? 1;
          return true;
        },
        ConvertSidToStringSidW(sid, text) {
          text.value = sid.text;
          return true;
        },
        wcscmp: (a, b) => Number(a !== b),
        wcslen: (text) => text.length,
        wcsncmp: (a, b, size) => Number(a.slice(0, size) !== b.slice(0, size)),
        LocalFree() {},
        NetUserGetLocalGroups(
          server,
          name,
          level,
          flags,
          groups,
          maximum,
          count,
          total,
        ) {
          reads.push("groups");
          groups.value = [];
          count.value = options.count ?? 0;
          total.value = options.total ?? 0;
          return options.groupStatus ?? 0;
        },
        NetApiBufferFree() {
          reads.push("group-release");
          return 0;
        },
        LsaOpenPolicy(server, attributes, access, policy) {
          policy.value = 1;
          return 0;
        },
        LsaEnumerateAccountRights(policy, sid, output, count) {
          reads.push("rights");
          output.value = rights;
          count.value = rights.length;
          return options.rightsStatus ?? 0;
        },
        LsaFreeMemory(value) {
          assert.equal(value, rights);
          reads.push("rights-release");
        },
        LsaClose() {
          reads.push("policy-close");
        },
      },
      run = () => program.runInNewContext(api)("fixture-account", expected);
    if (Object.keys(options).length)
      assert.throws(run, /Account authority refused/u);
    else {
      run();
      assert.deepEqual(reads, [
        "principal",
        "groups",
        "group-release",
        "rights",
        "rights-release",
        "policy-close",
      ]);
    }
  }
});

test("Windows open, guard and scheduler HRESULT diagnostics retain independent original and cleanup failures", async () => {
  const chunks = [],
    inputPath = "C:\\Fixture SDK\\Windows.h",
    open = `native-windows-open: operation=CreateFileW domain=win32 expected-kind=file error=3 attributes=unavailable tag=unavailable path-units=${inputPath.length} path-utf16=${inputPath
      .split("")
      .map((unit) => unit.charCodeAt(0).toString(16).padStart(4, "0"))
      .join("")}\n`,
    guard = Buffer.from(
      open +
        "native-windows-hresult: operation=ITaskFolder_RegisterTask hresult=0x80070005 file=fixture.c line=23\n" +
        "native-windows-guard: file=fixture.c line=23 last-error=5\n",
    ),
    cleanup = Buffer.from(
      "native-windows-hresult: operation=ITaskFolder_DeleteTask hresult=0x80070002 file=fixture.c line=47\n",
    );
  await withNativeDiagnostics(
    async () => {
      for (const cleanupFailure of [false, true]) {
        const f = transport();
        try {
          const pending = f.channel.receive().catch((error) => error),
            completion = f.channel.completion.catch((error) => error);
          const at = guard.indexOf("file=");
          f.child.stderr.write(guard.subarray(0, at));
          f.child.stderr.write(guard.subarray(at));
          let original;
          if (cleanupFailure) {
            f.child.stdout.emit(
              "error",
              new Error("Original scheduler transport failure"),
            );
            original = await pending;
            f.child.stderr.write(cleanup);
            f.child.stderr.emit(
              "error",
              new Error("Independent scheduler cleanup failure"),
            );
          }
          f.child.emit("close", 126, null);
          const [first, last] = await Promise.all([pending, completion]);
          assert.ok(first instanceof Error);
          assert.equal(last, first);
          if (cleanupFailure) assert.equal(last, original);
        } finally {
          f.channel.close();
          f.child.stdin.destroy();
          f.child.stdout.destroy();
          f.child.stderr.destroy();
        }
      }
    },
    createNativeDiagnosticWriter((bytes) => chunks.push(bytes)),
  );
  // Existing process observation retains its creation scope even when event
  // dispatch runs outside it; guarding the sink must not lose those bytes.
  const detached = withNativeDiagnostics(
      () => transport(),
      createNativeDiagnosticWriter((bytes) => chunks.push(bytes)),
    ),
    pending = detached.channel.receive().catch((error) => error),
    completion = detached.channel.completion.catch((error) => error),
    marker = Buffer.from(
      "native-windows-observation: retained diagnostic scope\n",
    );
  try {
    detached.child.stderr.write(marker);
    detached.child.emit("close", 126, null);
    assert.equal(await completion, await pending);
    assert.ok(Buffer.concat(chunks).includes(marker));
  } finally {
    detached.channel.close();
    detached.child.stdin.destroy();
    detached.child.stdout.destroy();
    detached.child.stderr.destroy();
  }
  const output = Buffer.concat(chunks).toString();
  assert.ok(output.includes(open.trim()));
  assert.ok(output.includes("native-windows-guard"));
  assert.ok(output.includes("file=fixture.c line=23 last-error=5"));
  assert.ok(
    output.includes("operation=ITaskFolder_RegisterTask hresult=0x80070005"),
  );
  assert.ok(
    output.includes("operation=ITaskFolder_DeleteTask hresult=0x80070002"),
  );
  assert.ok(output.includes("Original scheduler transport failure"));
  assert.ok(output.includes("Independent scheduler cleanup failure"));
});

// Only raw native frames are replaced. These tests supply no approval,
// transfer, retirement or completed-custody callback implementation.
function verificationFixture(f = fixture()) {
  const build = Boolean(f.buildEntry),
    transferred = new Set(),
    events = [],
    subjects = [],
    files = [],
    jobs = [];
  const states = new Map(
    [f.helper, identity(10, runnerSid), f.fileHelper].map((actor) => [
      actor.pid,
      { ...structuredClone(f.process), identity: actor },
    ]),
  );
  const observerPlanPath = "C:\\Fixture\\Sealed\\verification-plan",
    observerPlan = encodeWindowsCustodyPlan({
      ...(f.input.purpose === "experiment" ? { purpose: "experiment" } : {}),
      candidateSha,
      nonce: "e".repeat(32),
      entries: [
        ...f.entries,
        ...[
          f.input.bridge,
          f.input.reader,
          f.input.plan,
          ...f.input.sources,
        ].map((pin) => ({
          kind: pin.signatureSha256 ? "image" : "data",
          ...pin,
          signatureSha256: pin.signatureSha256 ?? null,
        })),
      ],
    });
  f.bytes.set(observerPlanPath, observerPlan);
  const observer = {
    verification: {
      input: {
        ...structuredClone(f.input),
        nonce: "e".repeat(32),
        plan: { path: observerPlanPath, sha256: digest(observerPlan) },
      },
      identity: f.verifier,
    },
  };
  const state = {
    absent: false,
    instances: 1,
    damage: null,
    jobMembers: [f.fileHelper],
    jobDacl: hash,
    unknownHandle: false,
    removedTasks: new Set(),
    worker: identity(41),
    jobFlags: build ? 0x2808 : 0x2008,
    jobLimit: build ? 32 : 1,
  };
  if (build)
    states.set(state.worker.pid, {
      ...structuredClone(f.process),
      identity: state.worker,
    });
  state.compilerJob = {
    daclSha256: hash,
    limitFlags: 0x2008,
    processLimit: 31,
    uiRestrictions: 255,
    members: [state.worker],
  };
  const exchange = async (bytes) => {
    assert.ok(Buffer.isBuffer(bytes));
    const [operation, sequence, ...args] = bytes.toString().trim().split(" ");
    events.push({ operation, args });
    let value;
    const name = operation.slice(7);
    if (name === "file") {
      const file = Buffer.from(args[0], "hex").toString("utf16le"),
        data = f.bytes.get(file),
        slot = files.length;
      assert.ok(data);
      assert.ok(data.length <= Number(args[3]));
      files.push(data);
      value = {
        identity: id(slot + 100),
        sha256: digest(data),
        signatureSha256: args[2] === "-" ? null : args[2],
        daclSha256: hash,
        slot,
        bytes: data.length,
      };
    } else if (name === "read")
      value = {
        hex: files[Number(args[0])]
          .subarray(Number(args[1]), Number(args[1]) + Number(args[2]))
          .toString("hex"),
      };
    else if (name === "retain") {
      const actor = states.get(Number(args[0]));
      assert.ok(actor);
      let slot = subjects.indexOf(actor);
      if (slot < 0) {
        slot = subjects.length;
        subjects.push(actor);
      }
      value = { slot, process: actor };
    } else if (name === "process") value = subjects[Number(args[0])];
    else if (name === "subjects")
      value = {
        identities: subjects.map((actor) => actor.identity),
        jobs: jobs.map((_, slot) => slot),
      };
    else if (name === "image") {
      const pid = subjects[Number(args[0])].identity.pid,
        pin =
          pid === f.helper.pid
            ? f.input.reader
            : pid === 10
              ? f.input.bridge
              : build
                ? f.entries[
                    pid === state.worker.pid
                      ? f.buildEntry.tool
                      : f.buildEntry.helper
                  ]
                : f.entries[0];
      value = {
        sha256: pin.sha256,
        signatureSha256: pin.signatureSha256,
        pathHex: hex(pin.path),
      };
    } else if (name === "task")
      value =
        state.absent || state.removedTasks.has(args[1])
          ? { absent: true }
          : { absent: false, sha256: hash, instances: state.instances };
    else if (name === "task-instance")
      value = {
        absent: false,
        sha256: hash,
        instances: state.instances,
        registeredInstances: 0,
        running:
          state.instances === 0
            ? []
            : Array.from({ length: state.instances }, () => ({
                guid: instance.guid,
                state: 4,
                engine: structuredClone(f.helper),
                helperLinked: true,
              })),
      };
    else if (name === "process-exit") value = { exitCode: state.exitCode ?? 0 };
    else if (name === "cold-process") {
      const process = states.get(Number(args[0]));
      value = process
        ? {
            complete: true,
            present: true,
            original: true,
            identity: process.identity,
            signaled: process.retired,
            exitCode: state.exitCode ?? 0,
          }
        : { complete: true, present: false };
    } else if (name === "cold-jobs")
      value = {
        pid: Number(args[0]),
        creationTime: args[1],
        nonce: args[2],
        jobs: Array.from({ length: 128 }, () => ({ absent: true })),
        compilerJob: { absent: true },
        controllingJob: { absent: true },
      };
    else if (name === "recovery-jobs")
      value = {
        nonce: args[1],
        identity: subjects[Number(args[0])].identity,
        jobs: Array.from({ length: 128 }, (_, i) =>
          i === 0 && state.recoveryMembers
            ? {
                daclSha256: hash,
                limitFlags: state.recoveryFlags ?? 0x2008,
                processLimit: 32,
                uiRestrictions: 255,
                members: state.recoveryMembers,
              }
            : { absent: true },
        ),
        compilerJob:
          build && subjects[Number(args[0])].identity.pid === f.fileHelper.pid
            ? state.compilerJob
            : { absent: true },
      };
    else if (name === "case-recover")
      value = {
        accountAbsent: true,
        rightsAbsent: true,
        jobAbsent: true,
        contextSha256: args[1],
        policyRestored: true,
        auditDrained: true,
        readersClosed: true,
      };
    else if (name === "transfer") {
      transferred.add(Number(args[0]));
      value = {
        threadDaclSha256: hash,
        job: {
          daclSha256: hash,
          limitFlags: state.jobFlags,
          processLimit: state.jobLimit,
          uiRestrictions: 255,
          members: state.jobMembers,
        },
        objects: [
          null,
          null,
          ...(build ? [] : [id(2), id(3)]),
          ...(state.unknownHandle ? [id(9)] : []),
        ],
        inheritedHandleCount: (build ? 2 : 4) + (state.unknownHandle ? 1 : 0),
        pipeDaclSha256: [hash, hash],
        creatorDefaultDaclSha256: hash,
      };
    } else if (name === "compiler-policy")
      value = {
        defaultDacl: [{ type: 0, flags: 0, mask: 0x10000000, sid: "S-1-5-18" }],
        inheritedHandles: ["pipe", "pipe", "pipe"],
        compilerJob: state.compilerJob,
      };
    else if (name === "sharing") value = { identity: id(2) };
    else if (name === "job")
      value = transferred.has(Number(args[0]))
        ? {
            daclSha256: hash,
            limitFlags: state.jobFlags,
            processLimit: state.jobLimit,
            uiRestrictions: 255,
            members: state.jobMembers,
          }
        : { absent: true };
    else if (name === "job-open") {
      value = {
        slot: jobs.length,
        observation: {
          daclSha256: state.jobDacl,
          limitFlags: 0x2008,
          processLimit: 32,
          uiRestrictions: 255,
          members: state.jobMembers,
        },
      };
      jobs.push(args[0]);
    } else if (name === "job-read") {
      assert.equal(jobs[Number(args[0])], args[1]);
      value = {
        daclSha256: state.jobDacl,
        limitFlags: 0x2008,
        processLimit: 32,
        uiRestrictions: 255,
        members: state.jobMembers,
      };
    } else if (name === "task-remove") {
      assert.ok(subjects.every((actor) => actor.retired));
      assert.equal(state.jobMembers.length, 0);
      state.removedTasks.add(args[1]);
      value = { removed: true, sha256: args[2] };
    } else throw new Error("Undeclared raw native command");
    const frame = { sequence: Number(sequence), value: structuredClone(value) };
    return state.damage
      ? state.damage(operation, frame)
      : Buffer.from(JSON.stringify(frame) + "\n");
  };
  const verifier = createWindowsCustodyVerifier(observer, { exchange });
  const admission = {
    input: f.input,
    helper: f.helper,
    bridge: identity(10, runnerSid),
    taskSha256: hash,
    processDaclSha256: hash,
    instance: { ...instance, enginePid: f.helper.pid },
  };
  const transfer = {
    kind: build ? "build" : "file",
    args: [],
    request: build ? f.buildRequest : f.file.request,
    image: f.entries[build ? f.buildEntry.helper : 0],
    objects: build ? [] : [f.object(1), f.object(2)],
  };
  const helperTransfer = {
    input: f.input,
    child: f.fileHelper,
    creator: f.helper,
    transfer,
    transferSha256: observationDigest(transfer),
    actual: {
      processDaclSha256: hash,
      threadDaclSha256: hash,
      job: {
        daclSha256: hash,
        limitFlags: state.jobFlags,
        processLimit: state.jobLimit,
        uiRestrictions: 255,
        members: [f.fileHelper],
      },
    },
  };
  return {
    f,
    events,
    states,
    state,
    observer,
    verifier,
    admission,
    helperTransfer,
    exchange,
  };
}

test("Windows repository verifier joins separately admitted source, process/token, task and transferred objects through raw native frames", async () => {
  const k = verificationFixture();
  assert.equal(k.events.length, 0);
  const sealed = await k.verifier.verifyBootstrap(k.f.input);
  assert.equal(sealed.entries.length, 9);
  const admitted = await k.verifier.verifyAdmission(k.admission);
  assert.deepEqual(admitted.verifier, k.f.verifier);
  const transferred = await k.verifier.verifyTransfer(k.helperTransfer);
  assert.equal(transferred.fileRootDeleteSharing, true);
  k.states.get(k.f.fileHelper.pid).retired = true;
  k.state.jobMembers = [];
  assert.equal(
    (await k.verifier.verifyHelperRetirement(k.f.fileHelper)).status,
    "RETIRED",
  );
  assert.equal(
    (
      await k.verifier.verifyRetirement({
        input: k.f.input,
        helper: k.f.helper,
        processes: [],
        jobs: [],
      })
    ).noLiveMembers,
    true,
  );
  k.states.get(k.f.helper.pid).retired = true;
  k.states.get(10).retired = true;
  k.state.absent = true;
  const closed = await k.verifier.verifyTaskRemoval({
    input: k.f.input,
    helper: k.f.helper,
    taskSha256: hash,
  });
  assert.equal(closed.taskRemoved, true);
  assert.deepEqual(closed.verifier, k.f.verifier); // Preparation retains this live observer.
  assert.equal(
    k.events.filter((entry) => entry.operation === "verify-task").length,
    3,
  );
});

test("Windows helper observation requires its original candidate, context, admission and verifier", async () => {
  for (const damage of [
    "unadmitted",
    "candidate",
    "context",
    "plan",
    "admission",
    "helper",
    "verifier",
  ]) {
    const k = verificationFixture();
    await k.verifier.verifyBootstrap(k.f.input);
    const admission =
        damage === "unadmitted"
          ? null
          : await k.verifier.verifyAdmission(k.admission),
      request = {
        input: structuredClone(k.f.input),
        helper: structuredClone(k.f.helper),
        verifier: structuredClone(k.f.verifier),
        admissionSha256: admission ? observationDigest(admission) : hash,
      };
    if (admission) {
      const actual = await k.verifier.verifyHelper(request);
      assert.deepEqual(actual.observation.identity, k.f.helper);
    }
    if (damage === "candidate")
      request.input.context.candidateSha = "f".repeat(40);
    if (damage === "context")
      request.input.context.executionId = "ownership.storage";
    if (damage === "plan") request.input.plan.sha256 = "f".repeat(64);
    if (damage === "admission") request.admissionSha256 = "f".repeat(64);
    if (damage === "helper") request.helper.pid++;
    if (damage === "verifier") request.verifier.creationTime = "99999";
    const before = k.events.length;
    await assert.rejects(k.verifier.verifyHelper(request), /Unverified/u);
    assert.equal(
      k.events.length,
      before,
      "Wrong bindings must refuse before native reads",
    );
  }
});

test("Windows verifier rejects reused births, changed task identity and malformed native frames without accepting later replies", async () => {
  for (const damage of [
    "birth",
    "task",
    "inactive-task",
    "sequence",
    "utf8",
    "extra",
  ]) {
    const k = verificationFixture();
    await k.verifier.verifyBootstrap(k.f.input);
    k.state.damage = (operation, frame) => {
      if (damage === "birth" && operation === "verify-retain")
        frame.value.process.identity.creationTime = "99999";
      if (damage === "task" && operation === "verify-task")
        frame.value.sha256 = "f".repeat(64);
      if (damage === "inactive-task" && operation === "verify-task")
        frame.value.instances = 0;
      if (damage === "sequence") frame.sequence++;
      if (damage === "utf8") return Buffer.from([0xff, 10]);
      if (damage === "extra") frame.unexpected = true;
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    let first;
    await assert.rejects(k.verifier.verifyAdmission(k.admission), (error) => {
      first = error;
      return true;
    });
    const count = k.events.length;
    k.state.damage = null;
    await assert.rejects(
      k.verifier.verifyAdmission(k.admission),
      (error) => error === first,
    );
    assert.equal(k.events.length, count);
  }
});

test("Windows admission joins the original scheduler instance, including hidden tasks, and diagnoses each rejected predicate", async () => {
  for (const fault of [
    null,
    "registered-one",
    "zero",
    "multiple",
    "registered-multiple",
    "guid",
    "state",
    "engine",
    "engine-birth",
    "engine-reused",
    "helper-ended",
    "helper",
  ]) {
    const k = verificationFixture();
    if (fault === "zero") k.state.instances = 0;
    if (fault === "multiple") k.state.instances = 2;
    k.state.damage = (operation, frame) => {
      if (operation === "verify-task-instance" && frame.value.running[0]) {
        const row = frame.value.running[0];
        if (fault === "registered-one") frame.value.registeredInstances = 1;
        if (fault === "registered-multiple")
          frame.value.registeredInstances = 2;
        if (fault === "guid")
          row.guid = "{22222222-2222-3333-4444-555555555555}";
        if (fault === "state") row.state = 2;
        if (fault === "engine") row.engine.pid = 2048;
        if (fault === "engine-birth")
          row.engine.creationTime = (
            BigInt(k.f.helper.creationTime) + 1n
          ).toString();
        if (fault === "engine-reused")
          row.engine.creationTime = (
            BigInt(k.f.helper.creationTime) - 1n
          ).toString();
        if (fault === "helper-ended")
          k.states.get(k.f.helper.pid).retired = true;
        if (fault === "helper") row.helperLinked = false;
      }
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    await k.verifier.verifyBootstrap(k.f.input);
    if (!fault || fault === "registered-one")
      assert.equal(
        (await k.verifier.verifyAdmission(k.admission)).taskSha256,
        hash,
      );
    else
      await assert.rejects(k.verifier.verifyAdmission(k.admission), (error) => {
        assert.equal(error.admission.expectedDigest, hash);
        assert.equal(error.admission.actualDigest, hash);
        assert.equal(
          error.admission.registeredInstances,
          fault === "registered-multiple" ? 2 : 0,
        );
        const predicate = {
          zero: "unique",
          multiple: "unique",
          "registered-multiple": "unique",
          guid: "original",
          state: "state",
          engine: "engine",
          "engine-birth": "engine",
          "engine-reused": "engine",
          "helper-ended": "lifetime",
          helper: "helper",
        }[fault];
        assert.equal(error.admission.predicates[predicate], false);
        return true;
      });
  }
});

test("Windows rejected admission aborts only the original parked helper before unchanged task removal", async () => {
  for (const fault of [
    null,
    "exit124",
    "job",
    "lost-abort",
    "removed-reply",
    "retained-receipt",
  ]) {
    const f = fixture(),
      k = verificationFixture(f),
      primary = new Error("admission pending"),
      cleanup = new Error("cleanup interrupted");
    k.state.instances = 0;
    f.options.verifyAdmission = async (value) => {
      await k.verifier.verifyBootstrap(f.input);
      try {
        return await k.verifier.verifyAdmission(value);
      } catch (error) {
        primary.cause = error;
        throw primary;
      }
    };
    f.options.preSetupVerifier = async () => {
      await assert.rejects(
        k.verifier.verifyAdmission(k.admission),
        (error) => error === primary.cause,
      );
      return createWindowsCustodyVerifier(k.observer, { exchange: k.exchange });
    };
    const send = f.owner.send;
    f.owner.send = async (line) => {
      if (line === "X\n") {
        f.events.push("X");
        assert.ok(
          f.records.some((record) => record.phase === "pre-setup-bound"),
        );
        k.states.get(f.helper.pid).retired = true;
        if (fault === "exit124") k.state.exitCode = 124;
        if (fault === "job") k.state.recoveryMembers = [f.fileHelper];
        if (["lost-abort", "retained-receipt"].includes(fault)) throw cleanup;
        f.frames.push({
          phase: "helper-retired",
          helper: f.helper,
          exitCode: 0,
        });
      } else if (line === "D") {
        f.events.push("D");
        assert.ok(
          f.records.some(
            (record) => record.phase === "pre-setup-helper-retired",
          ),
        );
        k.states.get(10).retired = true;
        k.state.absent = true;
        if (fault === "removed-reply") throw cleanup;
        f.frames.push({
          phase: "retired",
          taskSha256: hash,
          taskRemoved: true,
          helperRetired: true,
        });
      } else return send(line);
    };
    const reader = f.reader();
    await assert.rejects(reader.start(), (error) => error === primary);
    const parked = f.records.find((record) => record.phase === "task-parked");
    assert.deepEqual(parked.helper, f.helper);
    assert.equal(parked.taskSha256, hash);
    assert.equal(f.events.includes("fault"), false);
    if (fault === "retained-receipt") {
      const persist = f.options.persist;
      f.options.persist = async (record) => {
        if (record.phase === "retained")
          throw new Error("Receipt writer unavailable");
        return persist(record);
      };
    }
    const settled = await reader.close();
    assert.equal(settled.status, fault ? "RETAINED" : "RETIRED");
    assert.equal(f.events.includes("P"), false);
    if (fault) {
      assert.equal(settled.primaryCause, primary);
      assert.notEqual(settled.cause, primary);
      if (["lost-abort", "removed-reply", "retained-receipt"].includes(fault))
        assert.equal(settled.cause, cleanup);
      assert.equal(f.records.at(-1).custody, "POSSIBLE");
      assert.equal(f.events.includes("D"), fault === "removed-reply");
    } else {
      assert.equal(settled.independent, true);
      assert.equal(settled.emergencyCleanup, false);
      assert.equal(settled.taskRemoved, true);
      const exit = k.events.findIndex(
        (event) => event.operation === "verify-process-exit",
      );
      assert.ok(exit >= 0);
    }
    await assert.rejects(reader.start());
  }
});

test("Windows bridge completion acknowledgement uses the held identity after process retirement", async () => {
  const source = await readFile(
      new URL("./custody-bridge.c", import.meta.url),
      "utf8",
    ),
    body =
      /  DWORD exit = relay_retire\(process, input\);[\s\S]*?ack\('D'\);/u.exec(
        source,
      )?.[0];
  assert.ok(
    body,
    "Expected the shared bridge retirement and acknowledgement boundary",
  );
  const program = new Script(body.replace("DWORD exit", "const exit"));
  for (const input of [null, {}]) {
    const process = { retired: false },
      helperToken = {},
      calls = [];
    program.runInNewContext({
      process,
      input,
      helperToken,
      helperSession: 0,
      stdout: {},
      relay_retire(actual, thread) {
        assert.equal(actual, process);
        assert.equal(thread, input);
        process.retired = true;
        calls.push("retire");
        return 0;
      },
      printf() {},
      puts() {},
      fflush() {},
      identity() {
        assert.fail(
          "Retired processes cannot supply a fresh token/session observation",
        );
      },
      retained_identity(actual, token, session) {
        assert.equal(actual, process);
        assert.equal(process.retired, true);
        assert.equal(token, helperToken);
        assert.equal(session, 0);
        calls.push("identity");
      },
      ack(value) {
        assert.equal(value, "D");
        calls.push("remove");
      },
    });
    assert.deepEqual(calls, ["retire", "identity", "remove"]);
  }
});

test("scheduler refusals retain the exact API/HRESULT independently of last-error and reject malformed context", async () => {
  for (const fault of [
    null,
    "path",
    "cleanup",
    "cleanup-zero",
    "cleanup-header",
    "header-api",
    "cleanup-flag",
    "api",
    "hresult",
    "index",
    "attempt",
    "extra",
    "command",
    "mixed",
  ]) {
    const f = transport(),
      value = {
        phase: "reader-failure",
        sequence: 5,
        command: "verify-task",
        source: "custody-reader.c",
        line: 47,
        lastError: 0,
        scheduler: {
          operation:
            fault === "path"
              ? "IRunningTask_get_Path"
              : "IRunningTaskCollection_get_Item",
          hresult: "0x8004130b",
          index: 2,
          attempt: 3,
          cleanupError: 0,
          cleanupFailed: false,
        },
      };
    if (
      ["cleanup", "cleanup-zero", "cleanup-header", "cleanup-flag"].includes(
        fault,
      )
    )
      Object.assign(value.scheduler, {
        operation: null,
        hresult: null,
        cleanupError: fault === "cleanup-zero" ? 0 : 6,
        cleanupFailed: fault !== "cleanup-flag",
      });
    if (["cleanup-header", "header-api"].includes(fault))
      value.source = "custody.h";
    if (fault === "api") value.scheduler.operation = "unknown";
    if (fault === "hresult") value.scheduler.hresult = 0x8004130b;
    if (fault === "index") value.scheduler.index = 4097;
    if (fault === "attempt") value.scheduler.attempt = 4;
    if (fault === "extra") value.scheduler.extra = 1;
    if (fault === "command") value.command = "verify-image";
    if (fault === "mixed") value.transfer = {};
    const valid = [
      null,
      "path",
      "cleanup",
      "cleanup-zero",
      "cleanup-header",
    ].includes(fault);
    const pending = f.channel.receive(),
      completion = f.channel.completion.catch((error) => error);
    const bytes = "\x1e" + JSON.stringify(value) + "\n";
    f.child.stdout.write(bytes.slice(0, 39));
    f.child.stdout.write(bytes.slice(39));
    await assert.rejects(pending, (error) => {
      assert.equal(Object.hasOwn(error, "custodyReaderFailure"), valid);
      if (valid) assert.deepEqual(error.custodyReaderFailure, value);
      return true;
    });
    assert.ok((await completion) instanceof Error);
    assert.throws(() => f.channel.settle());
    f.child.emit("close", 126, null);
    f.channel.close();
  }
});

async function providerCensusProgram(zeroLayer = false) {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = (name) => {
      const match = new RegExp(
        `static (?:struct provider_filter_census|BOOL|void) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source);
      assert.ok(match, name);
      return match[1];
    },
    ownership = body("ownership_network"),
    start = ownership.indexOf("    struct provider_filter_census census"),
    valueStart = ownership.indexOf("      FWPM_FILTER0 *actual;"),
    recovery = body("recovery_access_network"),
    filter = body("recovery_filter");
  assert.ok(start > 0 && valueStart > 0);
  const translate = (text) =>
    text
      .replace(
        "struct provider_filter_census census = {0}",
        "let census = {result:0, cleanupResult:0, complete:false}",
      )
      .replace(
        "FWPM_FILTER_ENUM_TEMPLATE0 selection = {0}",
        "let selection = {actionMask:0, layerKey:0}",
      )
      .replace(/struct provider_filter_census census/gu, "let census")
      .replace(/FWPM_(?:FILTER|PROVIDER|SUBLAYER)0 \*\*/gu, "let ")
      .replace(/FWPM_(?:FILTER|PROVIDER|SUBLAYER)0 \*/gu, "let ")
      .replace(/const char \*operation/gu, "const operation")
      .replace(
        /FwpmFreeMemory0\(\(void \*\*\)&(\w+)\)/gu,
        "FwpmFreeMemory0($1, value=>$1=value)",
      )
      .replace(
        /access_key\(([^,]+),\s*&(\w+)\)/gu,
        "access_key($1, value=>$2=value)",
      )
      .replace(
        /Fwpm(?:Filter(?:CreateEnumHandle0|Enum0|GetByKey0)|ProviderGetByKey0|SubLayerGetByKey0)\([^)]*\)/gu,
        (call) =>
          call.replace(
            /&(enumeration|filters|returned|actual|provider|layer)\b/gu,
            "value=>$1=value",
          ),
      )
      .replace(/(?<!&)&(?=[\w])/gu, "")
      .replace(/\*actual->weight.uint64/gu, "actual->weight.uint64")
      .replace(/->/gu, ".")
      .replace(/\bL(?=")/gu, "")
      .replace(/\bconst UINT32\b/gu, "const")
      .replace(/\b(?:GUID|DWORD|UINT32|HANDLE|BOOL)\b/gu, "let");
  let census = body("provider_filters");
  if (zeroLayer) {
    // Reintroduce the baseline create call; the production scan remains intact.
    assert.ok(census.includes("FwpmFilterCreateEnumHandle0(wfp_engine, NULL,"));
    census = census.replace(
      "FwpmFilterCreateEnumHandle0(wfp_engine, NULL,",
      "FwpmFilterCreateEnumHandle0(wfp_engine, &selection,",
    );
    census = `FWPM_FILTER_ENUM_TEMPLATE0 selection = {0};
      selection.providerKey = providerKey; selection.actionMask = 0xFFFFFFFF;
      ${census}`;
  }
  return new Script(`
    function provider_filters(providerKey,limit){${translate(census)}}
    function provider_filters_accept(census,accepted){${translate(body("provider_filters_accept"))}}
    function ownership_read(){${translate(ownership.slice(start, ownership.indexOf("\n  }", start)))}}
    function recovery_read(){${translate(recovery.slice(0, recovery.indexOf("    PSID user")))} }}
    function ownership_value(){${translate(ownership.slice(valueStart, ownership.indexOf("      FwpmFreeMemory0((void **)&actual);", valueStart)))}}
    function recovery_value(){${translate(filter.slice(0, filter.indexOf("  FWPM_FILTER_CONDITION0 expected")))}}
  `);
}

function providerCensusFixture(program, kind, count, fault = {}) {
  const providerKey =
      kind === "ownership" ? "ownership-provider" : "access-provider",
    calls = [],
    diagnostics = [],
    handles = new Set(),
    arrays = new Set(),
    rows = Array.from({ length: count }, (_, i) => ({
      providerKey,
      layerKey: ["connect-v4", "receive-v6", "other-layer"][i % 3],
      action: { type: [0, 0x1001, 0x1002, 0x2006, 0x5003][i % 5] },
    }));
  let lastError = 999,
    reads = 0;
  const api = {
    ERROR_SUCCESS: 0,
    MAXDWORD: 0xffffffff,
    NULL: null,
    FALSE: false,
    TRUE: true,
    FWP_E_LAYER_NOT_FOUND: 0x80320004,
    FWP_E_PROVIDER_NOT_FOUND: 10,
    FWP_E_SUBLAYER_NOT_FOUND: 11,
    FWPM_PROVIDER_FLAG_PERSISTENT: 1,
    FWPM_SUBLAYER_FLAG_PERSISTENT: 1,
    FWPM_FILTER_FLAG_PERSISTENT: 1,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: 2,
    FWP_UINT64: "uint64",
    FWP_MATCH_EQUAL: "equal",
    FWP_SECURITY_DESCRIPTOR_TYPE: "sd",
    wfp_engine: "engine",
    ownership_provider: providerKey,
    stderr: "stderr",
    ownership_layer: "sublayer",
    ownership_filter_ids: [77],
    layers: ["connect-v4"],
    i: 0,
    index: 0,
    layer: "connect-v4",
    action: 0x1001,
    weight: 10,
    identity: 77,
    size: 2,
    relative: [1, 2],
    condition: { fieldKey: "user" },
    remove: true,
    identities: { kind: 2, count: 52 },
    value: {
      filterKey: "filter-0",
      flags: 3,
      action: { type: 0x1001 },
      displayData: { name: "NativeProof ownership deny" },
    },
    currentFilter: {
      filterId: 77,
      providerKey,
      subLayerKey: "sublayer",
      layerKey: "connect-v4",
      flags: 3,
      action: { type: 0x1001 },
      weight: { type: "uint64", uint64: 10 },
      providerData: { size: 0 },
      rawContext: 0,
      reserved: 0,
      displayData: {
        name:
          kind === "ownership"
            ? "NativeProof ownership deny"
            : "NativeProof owned policy",
        description: null,
      },
      numFilterConditions: 1,
      filterCondition: [
        {
          fieldKey: "user",
          matchType: "equal",
          conditionValue: { type: "sd", sd: { size: 2, data: [1, 2] } },
        },
      ],
    },
    need(ok) {
      if (!ok)
        throw Object.assign(new Error("Native census refusal"), {
          lastError,
          diagnostic: diagnostics.at(-1),
        });
    },
    SetLastError(value) {
      lastError = value;
    },
    fprintf(
      _stream,
      _format,
      operation,
      result,
      count,
      complete,
      accepted,
      cleanupResult,
    ) {
      diagnostics.push({
        operation,
        result,
        count,
        complete: Boolean(complete),
        accepted,
        cleanupResult,
      });
      lastError = 998;
    },
    fflush() {
      lastError = 997;
    },
    access_key(index, output) {
      output(
        index === 0
          ? providerKey
          : index === 1
            ? "sublayer"
            : `filter-${index - 2}`,
      );
    },
    wfp_open() {},
    ownership_wfp_security() {},
    FwpmTransactionBegin0() {
      return 0;
    },
    FwpmProviderGetByKey0(_engine, _key, output) {
      output({
        flags: 1,
        providerData: { size: 0 },
        serviceName: null,
        displayData: {
          name: "NativeProof private provider",
          description: null,
        },
      });
      return fault.providerResult ?? 0;
    },
    FwpmSubLayerGetByKey0(_engine, _key, output) {
      output({
        providerKey,
        flags: fault.layerFlags ?? 1,
        weight: 65535,
        providerData: { size: 0 },
        displayData: {
          name: "NativeProof private sublayer",
          description: null,
        },
      });
      return fault.layerResult ?? 0;
    },
    IsEqualGUID: (a, b) => a === b,
    wcscmp: (a, b) => (a === b ? 0 : 1),
    memcmp: (a, b) => (JSON.stringify(a) === JSON.stringify(b) ? 0 : 1),
    FwpmFilterGetByKey0(_engine, _key, output) {
      output(api.currentFilter);
      return 0;
    },
    FwpmFilterCreateEnumHandle0(engine, selection, output) {
      assert.equal(engine, "engine");
      calls.push("create");
      if (selection !== null && !api.layers.includes(selection.layerKey))
        return api.FWP_E_LAYER_NOT_FOUND;
      assert.equal(selection, null);
      if (fault.handle !== false) {
        const handle = {
          snapshot: rows.map((row) => ({ ...row, action: { ...row.action } })),
          cursor: 0,
        };
        handles.add(handle);
        output(handle);
        fault.afterCreate?.(rows);
      }
      return fault.createResult ?? 0;
    },
    FwpmFilterEnum0(_engine, handle, limit, output, number) {
      assert.ok(handles.has(handle));
      assert.equal(limit, 128);
      calls.push("enumerate");
      const current = ++reads === (fault.readAt ?? 1) ? fault : {},
        selected = handle.snapshot.slice(handle.cursor, handle.cursor + limit);
      handle.cursor += selected.length;
      if (current.array !== false) {
        const entries = current.nullEntry ? selected.map(() => null) : selected;
        if (current.nullEntryAt !== undefined)
          entries[current.nullEntryAt] = null;
        if (current.unwrittenEntry) delete entries[entries.length - 1];
        arrays.add(entries);
        output(entries);
      }
      if (current.count !== false)
        number(current.countOverride ?? selected.length);
      return current.enumResult ?? 0;
    },
    FwpmFreeMemory0(value, output) {
      if (Array.isArray(value)) {
        assert.ok(arrays.delete(value));
        calls.push("free");
      }
      output(null);
      lastError = 996;
    },
    FwpmFilterDestroyEnumHandle0(_engine, handle) {
      // Settle the one-shot cleanup attempt; its DWORD still decides refusal.
      assert.ok(handles.delete(handle));
      calls.push("destroy");
      lastError = 995;
      return fault.destroyResult ?? 0;
    },
  };
  program.runInNewContext(api);
  return {
    api,
    rows,
    calls,
    diagnostics,
    read: () => api[`${kind}_read`](),
    settled() {
      assert.equal(handles.size, 0);
      assert.equal(arrays.size, 0);
    },
  };
}

function unrelatedProviderFilters(count) {
  return Array.from({ length: count }, (_, i) => ({
    providerKey: i % 2 ? null : "foreign-provider",
    layerKey: "unrelated-layer",
    action: { type: i % 2 ? 0 : 0x5003 },
  }));
}

test("provider filter census rejects the old zero-layer template before any read", async () => {
  const legacy = await providerCensusProgram(true);
  for (const kind of ["ownership", "recovery"]) {
    const f = providerCensusFixture(
      legacy,
      kind,
      kind === "ownership" ? 4 : 52,
    );
    assert.throws(f.read, (error) => {
      assert.equal(error.lastError, 0x80320004);
      assert.deepEqual(error.diagnostic, {
        operation: "FwpmFilterCreateEnumHandle0",
        result: 2150760452,
        count: 0xffffffff,
        complete: false,
        accepted: false,
        cleanupResult: 0,
      });
      return true;
    });
    assert.deepEqual(f.calls, ["create"]);
    f.settled();
  }
});

test("provider filter census retains both production count and content guards", async () => {
  const corrected = await providerCensusProgram();
  for (const kind of ["ownership", "recovery"]) {
    const expected = kind === "ownership" ? 4 : 52;
    for (const count of [0, expected - 1, expected, expected + 1]) {
      const f = providerCensusFixture(corrected, kind, count);
      f.rows.push({
        providerKey: "foreign-provider",
        action: { type: 0x1001 },
      });
      if (count === expected || (kind === "recovery" && count === 0)) f.read();
      else
        assert.throws(
          f.read,
          (error) => error.diagnostic.operation === "count",
        );
      assert.deepEqual(f.calls, ["create", "enumerate", "free", "destroy"]);
      f.settled();
    }
    for (const extra of [
      { action: { type: 0x2006 } },
      { action: { type: 0x5003 }, layerKey: "unexpected-layer" },
    ]) {
      const f = providerCensusFixture(corrected, kind, expected);
      f.rows.push({ providerKey: f.rows[0].providerKey, ...extra });
      assert.throws(f.read, (error) => error.diagnostic.count === expected + 1);
      f.settled();
    }
    for (const change of [
      (filter) => {
        filter.action.type = 0x5003;
      },
      (filter) => {
        filter.layerKey = "unexpected-layer";
      },
      (filter) => {
        filter.filterId++;
      },
      (filter) => {
        filter.providerKey = "foreign-provider";
      },
    ]) {
      const f = providerCensusFixture(corrected, kind, expected);
      f.read();
      f.api[`${kind}_value`]();
      change(f.api.currentFilter);
      assert.throws(() => f.api[`${kind}_value`]());
      f.settled();
      assert.deepEqual(f.calls, ["create", "enumerate", "free", "destroy"]);
    }
  }
  for (const [providerResult, layerResult, accepted] of [
    [0, 0, true],
    [10, 11, true],
    [0, 11, false],
    [10, 0, false],
    [5, 11, false],
  ]) {
    const f = providerCensusFixture(corrected, "recovery", 0, {
      providerResult,
      layerResult,
      array: false,
    });
    if (accepted) f.read();
    else assert.throws(f.read);
    assert.equal(f.calls.includes("create"), accepted);
    f.settled();
  }
  for (const fault of [
    { providerResult: 10, layerResult: 11 },
    { layerFlags: 0 },
  ]) {
    const f = providerCensusFixture(corrected, "recovery", 52, fault);
    assert.throws(f.read);
    f.settled();
  }
  for (const identities of [
    null,
    { kind: 1, count: 52 },
    { kind: 2, count: 51 },
  ]) {
    const f = providerCensusFixture(corrected, "recovery", 52);
    f.api.identities = identities;
    assert.throws(f.read);
    f.settled();
    assert.deepEqual(f.calls, ["create", "enumerate", "free", "destroy"]);
  }
});

test("provider filter census advances the complete snapshot across unrelated providers, actions and layers", async () => {
  const program = await providerCensusProgram();
  for (const kind of ["ownership", "recovery"]) {
    const f = providerCensusFixture(
        program,
        kind,
        kind === "ownership" ? 4 : 52,
      ),
      owned = f.rows.splice(0);
    f.rows.push(...unrelatedProviderFilters(127));
    for (const row of owned) f.rows.push(row, ...unrelatedProviderFilters(2));
    const before = JSON.stringify(f.rows);
    f.read();
    assert.equal(JSON.stringify(f.rows), before);
    assert.equal(
      f.calls.filter((call) => call === "enumerate").length,
      kind === "ownership" ? 2 : 3,
    );
    assert.equal(f.calls.at(-1), "destroy");
    f.settled();
  }
  const fixed = providerCensusFixture(program, "ownership", 4, {
    afterCreate(rows) {
      rows.push({ ...rows[0] }, { ...rows[0] });
      rows[0].providerKey = "foreign-provider";
    },
  });
  fixed.read(); // Creation captured four, although the live list now has five.
  fixed.settled();
});

test("provider filter census requires short or empty exhaustion and refuses proven overflow or the global scan limit", async () => {
  const program = await providerCensusProgram();
  const emptyEnd = providerCensusFixture(program, "ownership", 4, {
    readAt: 2,
    array: false,
  });
  emptyEnd.rows.push(...unrelatedProviderFilters(124));
  emptyEnd.read();
  assert.deepEqual(emptyEnd.calls, [
    "create",
    "enumerate",
    "free",
    "enumerate",
    "destroy",
  ]);
  emptyEnd.settled();

  const shortEnd = providerCensusFixture(program, "ownership", 4);
  shortEnd.rows.unshift(...unrelatedProviderFilters(2043));
  shortEnd.read(); // A validated 127-entry final page exhausts within the ceiling.
  assert.equal(
    shortEnd.calls.filter((call) => call === "enumerate").length,
    16,
  );
  shortEnd.settled();

  for (const kind of ["ownership", "recovery"]) {
    const expected = kind === "ownership" ? 4 : 52,
      extra = providerCensusFixture(program, kind, expected, {
        destroyResult: 7,
      });
    extra.rows.push(...unrelatedProviderFilters(128 - expected));
    extra.rows.push(
      {
        providerKey: extra.rows[0].providerKey,
        layerKey: "unexpected-layer",
        action: { type: 0x5003 },
      },
      ...unrelatedProviderFilters(256),
    );
    assert.throws(
      extra.read,
      (error) =>
        error.lastError === 0 &&
        error.diagnostic.operation === "count" &&
        error.diagnostic.count === expected + 1 &&
        error.diagnostic.complete === false &&
        error.diagnostic.cleanupResult === 7,
    );
    assert.equal(extra.calls.filter((call) => call === "enumerate").length, 2);
    extra.settled();

    // A full final page proves neither exact ownership nor provider absence.
    const count = kind === "ownership" ? 4 : 0,
      incomplete = providerCensusFixture(program, kind, count, {
        destroyResult: 7,
      });
    incomplete.rows.push(...unrelatedProviderFilters(2048 - count));
    assert.throws(incomplete.read, (error) => {
      assert.equal(error.lastError, 0);
      assert.equal(error.diagnostic.operation, "scan-limit");
      assert.equal(error.diagnostic.count, count);
      assert.equal(error.diagnostic.complete, false);
      assert.equal(error.diagnostic.accepted, true);
      assert.equal(error.diagnostic.cleanupResult, 7);
      return true;
    });
    assert.equal(
      incomplete.calls.filter((call) => call === "enumerate").length,
      16,
    );
    incomplete.settled();
  }
});

test("provider filter census settles partial results once and preserves primary refusals through cleanup", async () => {
  const program = await providerCensusProgram();
  for (const kind of ["ownership", "recovery"]) {
    const count = kind === "ownership" ? 4 : 52;
    for (const [fault, operation, result, complete, calls] of [
      [
        { createResult: 5, handle: false },
        "FwpmFilterCreateEnumHandle0",
        5,
        false,
        ["create"],
      ],
      [
        { createResult: 5 },
        "FwpmFilterCreateEnumHandle0",
        5,
        false,
        ["create", "destroy"],
      ],
      [{ handle: false }, "FwpmFilterCreateEnumHandle0", 0, false, ["create"]],
      [
        { enumResult: 6, array: false },
        "FwpmFilterEnum0",
        6,
        false,
        ["create", "enumerate", "destroy"],
      ],
      [{ enumResult: 6 }, "FwpmFilterEnum0", 6, false],
      [
        { array: false },
        "FwpmFilterEnum0",
        0,
        false,
        ["create", "enumerate", "destroy"],
      ],
      [{ count: false }, "FwpmFilterEnum0", 0, false],
      [{ countOverride: 129 }, "FwpmFilterEnum0", 0, false],
      [{ nullEntry: true }, "FwpmFilterEnum0", 0, false],
      [{ unwrittenEntry: true }, "FwpmFilterEnum0", 0, false],
      [{ countOverride: count - 1 }, "count", 0, true],
      [{}, "FwpmFilterDestroyEnumHandle0", 7, true],
    ]) {
      const f = providerCensusFixture(program, kind, count, {
        ...fault,
        destroyResult: 7,
      });
      assert.throws(f.read, (error) => {
        assert.equal(error.lastError, result);
        assert.equal(error.diagnostic.operation, operation);
        assert.equal(error.diagnostic.result, result);
        assert.equal(error.diagnostic.complete, complete);
        assert.equal(
          error.diagnostic.cleanupResult,
          fault.handle === false ? 0 : 7,
        );
        return true;
      });
      f.settled();
      assert.deepEqual(
        f.calls,
        calls ?? ["create", "enumerate", "free", "destroy"],
      );
    }
  }
  const empty = providerCensusFixture(program, "recovery", 0, {
    array: false,
    destroyResult: 7,
  });
  assert.throws(
    empty.read,
    (error) =>
      error.lastError === 7 &&
      error.diagnostic.operation === "FwpmFilterDestroyEnumHandle0" &&
      error.diagnostic.count === 0,
  );
  empty.settled();
  assert.deepEqual(empty.calls, ["create", "enumerate", "destroy"]);
});

test("provider filter census validates every page before overflow and preserves later read failures", async () => {
  const program = await providerCensusProgram();
  for (const fault of [{ nullEntryAt: 5 }, { unwrittenEntry: true }]) {
    const f = providerCensusFixture(program, "ownership", 6, fault);
    assert.throws(
      f.read,
      (error) =>
        error.diagnostic.operation === "FwpmFilterEnum0" &&
        error.diagnostic.count === 0 &&
        !error.diagnostic.complete,
    );
    f.settled();
  }
  for (const fault of [{ enumResult: 6 }, { count: false }, { array: false }]) {
    const f = providerCensusFixture(program, "ownership", 4, {
      ...fault,
      readAt: 2,
      destroyResult: 7,
    });
    f.rows.unshift(...unrelatedProviderFilters(128));
    // A stale first-page count would look valid for this full second page.
    f.rows.push(...unrelatedProviderFilters(124));
    assert.throws(f.read, (error) => {
      assert.equal(error.lastError, fault.enumResult ?? 0);
      assert.equal(error.diagnostic.operation, "FwpmFilterEnum0");
      assert.equal(error.diagnostic.count, 0);
      assert.equal(error.diagnostic.complete, false);
      assert.equal(error.diagnostic.cleanupResult, 7);
      return true;
    });
    assert.deepEqual(f.calls, [
      "create",
      "enumerate",
      "free",
      "enumerate",
      ...(fault.array === false ? [] : ["free"]),
      "destroy",
    ]);
    f.settled();
  }
});

async function schedulerProgram() {
  const [source, bridge] = await Promise.all(
    ["custody-reader.c", "custody-bridge.c"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const body = (name, text = source) =>
    new RegExp(
      `static (?:LONG|void|DWORD|BOOL) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(text)[1];
  const translate = (text) =>
    text
      .replace("struct task_scope *s=reader_task", "const s=reader_task")
      .replace("wchar_t path[132]", "let path")
      .replace(
        /swprintf_s\(path,132,L"[^\n]*?",name\)/u,
        "format(value=>path=value,name)",
      )
      .replace(
        "VARIANT index;VariantInit(&index)",
        "const index={};VariantInit(index)",
      )
      .replace(
        "BSTR strings[]={s->root,s->name,s->xml,s->sd,s->guid,s->registeredPath}",
        "const strings=[s.root,s.name,s.xml,s.sd,s.guid,s.registeredPath]",
      )
      .replace(
        /(?<!&)&reader_task->(all|item|path)/gu,
        "value=>reader_task.$1=value",
      )
      .replace(/->/gu, ".")
      .replace(/\bL(?=['"])/gu, "")
      .replace(/(?<!&)&(count|all|running|actual)\b/gu, "value=>$1=value")
      .replace(/\b(?:IRunningTaskCollection|IRunningTask) \*/gu, "let ")
      .replace("const char *operation", "let operation")
      .replace(/\bBSTR\b/gu, "let")
      .replace(/\b(?:LONG|BOOL|DWORD|HANDLE|HRESULT|unsigned)\b/gu, "let");
  return new Script(`
    function task_result(result,operation,line){${translate(body("task_result"))}}
    function task_census_close(owned){${translate(body("task_census_close"))}}
    function task_engine_close(){${translate(body("task_engine_close"))}}
    function task_close(){${translate(body("task_close"))}}
    function task_instances(service,name,owned){${translate(body("task_instances"))}}
    function task_active(service,name){${translate(body("task_active", bridge))}}
  `);
}

function schedulerFixture(program, snapshots, fault) {
  const closed = [],
    calls = [],
    collections = [],
    releasedCollections = [],
    strings = [],
    releasedStrings = [],
    scheduler = { cleanupError: 0, cleanupFailed: false },
    owned = Array(32).fill(null);
  let lastError = 0,
    reads = 0,
    currentIndex = 0;
  const reply = (stage, index, value, out) => {
    const result = fault?.(stage, reads, index) ?? 0;
    if (typeof result === "number") out(value);
    else if (Object.hasOwn(result, "output")) out(result.output);
    return typeof result === "number" ? result : (result.result ?? 0);
  };
  const api = {
    NULL: null,
    TRUE: true,
    FALSE: false,
    __LINE__: 47,
    __FILE__: "custody-reader.c",
    TASK_ENUM_HIDDEN: 1,
    VT_I4: 3,
    SCHED_E_TASK_NOT_RUNNING: 0x8004130b | 0,
    reader_task: { running: owned },
    reader_scheduler: scheduler,
    FAILED: (value) => value < 0,
    SUCCEEDED: (value) => value >= 0,
    GetLastError: () => lastError,
    SetLastError: (value) => {
      lastError = value;
    },
    format: (out, name) => {
      out("\\" + name);
      return 1;
    },
    VariantInit: () => {},
    SysStringLen: (value) => value.length,
    wcslen: (value) => value.split("\0")[0].length,
    _wcsicmp: (a, b) => Number(a.toLowerCase() !== b.toLowerCase()),
    need(ok) {
      if (!ok) {
        api.task_close();
        throw new Error("incomplete census");
      }
    },
    need_hresult_at(result, ok, operation) {
      if (ok) return;
      const failure = {
        result,
        operation,
        index: scheduler.index,
        attempt: scheduler.attempt,
        lastError,
      };
      api.task_close();
      throw Object.assign(new Error("scheduler refusal"), {
        scheduler: failure,
      });
    },
    task_hr(fn, ...args) {
      const result = fn(...args),
        ok = api.task_result(result, fn.name, 47);
      api.SetLastError(scheduler.error);
      api.need_hresult_at(result, ok, fn.name);
    },
    ITaskService_GetRunningTasks(service, flags, out) {
      assert.equal(flags, 1);
      calls.push(["census", ++reads]);
      currentIndex = 0;
      const all = {
        rows: snapshots[Math.min(reads - 1, snapshots.length - 1)],
      };
      lastError = 0;
      return reply("all", 0, all, (value) => {
        if (value) collections.push(value);
        out(value);
      });
    },
    IRunningTaskCollection_get_Count(all, out) {
      lastError = 0;
      return reply("count", 0, all.rows.censusCount ?? all.rows.length, out);
    },
    IRunningTaskCollection_get_Item(all, index, out) {
      assert.equal(index.vt, 3);
      assert.ok(index.lVal > 0);
      currentIndex = index.lVal;
      calls.push(["item", reads, index.lVal]);
      const row = all.rows[index.lVal - 1];
      assert.ok(row);
      lastError = 0;
      return reply("item", index.lVal, row, out);
    },
    IRunningTask_get_Path(row, out) {
      calls.push(["path", row.id]);
      lastError = 0;
      return reply("path", currentIndex, row.path, (value) => {
        if (value == null) return out(value);
        // Distinct allocations stay owned even for identical or empty text.
        const actual = new String(value);
        strings.push(actual);
        out(actual);
      });
    },
    IRunningTask_Refresh(row) {
      calls.push(["refresh", row.id]);
      lastError = 0;
      return fault?.("refresh", reads, scheduler.index) ?? 0;
    },
    IRunningTask_Release: (row) => {
      closed.push(row.id);
      lastError = 91;
    },
    IRunningTaskCollection_Release: (all) => {
      releasedCollections.push(all);
      closed.push(all.rows ? "census" : "instances");
      lastError = 92;
    },
    IRegisteredTask_Release: (task) => {
      closed.push(task);
      lastError = 93;
    },
    ITaskFolder_Release: (folder) => {
      closed.push(folder);
      lastError = 94;
    },
    ITaskService_Release: (service) => {
      closed.push(service);
      lastError = 95;
    },
    SysFreeString: (text) => {
      releasedStrings.push(text);
      closed.push(`string:${text}`);
      lastError = 96;
    },
    CloseHandle: (handle) => {
      closed.push(handle);
      lastError = handle === "bad-close-zero" ? 0 : 6;
      return !handle.startsWith("bad-close");
    },
  };
  program.runInNewContext(api);
  return {
    api,
    owned,
    closed,
    calls,
    collections,
    releasedCollections,
    strings,
    releasedStrings,
    read: () => api.task_instances({}, "owned", owned),
    active: () => api.task_active({}, "owned"),
  };
}

function assertSchedulerReleases(f) {
  for (const [acquired, released] of [
    [f.collections, f.releasedCollections],
    [f.strings, f.releasedStrings],
  ]) {
    assert.equal(released.length, acquired.length);
    for (const reference of acquired)
      assert.equal(released.filter((value) => value === reference).length, 1);
  }
}

test("bridge task census restarts completely after a disappearing item and discards partial counts", async () => {
  const program = await schedulerProgram();
  const first = { id: "first", path: "\\owned" },
    ended = { id: "ended", path: "\\OWNED" },
    live = { id: "live", path: "\\owned" },
    hidden = { id: "hidden", path: "\\OWNED" },
    other = { id: "other", path: "\\owned-extra" };
  for (const stage of ["item", "path"]) {
    for (const fresh of [[], [other], [other, live, hidden]]) {
      const snapshots = [[first, ended], fresh];
      let f;
      f = schedulerFixture(program, snapshots, (at, pass, index) => {
        if (at === "all" && pass === 2) {
          assertSchedulerReleases(f);
          for (const row of [first, ended])
            assert.equal(f.closed.filter((id) => id === row.id).length, 1);
          assert.equal(
            f.closed.filter((id) => id.startsWith("string:")).length,
            stage === "path" ? 2 : 1,
          );
        }
        return at === stage && pass === 1 && index === 2 ? 0x8004130b | 0 : 0;
      });
      assert.equal(f.active(), fresh.filter((row) => row !== other).length);
      assert.deepEqual(
        f.calls
          .filter(([at]) => at === "item")
          .map(([, pass, index]) => [pass, index]),
        [[1, 1], [1, 2], ...fresh.map((_, i) => [2, i + 1])],
      );
      assert.equal(f.collections.length, 2);
      assertSchedulerReleases(f);
      for (const row of [first, ended, ...fresh])
        assert.equal(f.closed.filter((id) => id === row.id).length, 1);
      assert.deepEqual(
        f.closed.filter((id) => id.startsWith("string:")).sort(),
        [first, ...(stage === "path" ? [ended] : []), ...fresh]
          .map((row) => `string:${row.path}`)
          .sort(),
      );
    }
  }
});

test("bridge task census bounds instability and preserves other HRESULTs through cleanup", async () => {
  const program = await schedulerProgram();
  const first = { id: "first", path: "\\owned" },
    ended = { id: "ended", path: "\\OWNED" };
  const operations = {
    all: "ITaskService_GetRunningTasks",
    count: "IRunningTaskCollection_get_Count",
    item: "IRunningTaskCollection_get_Item",
    path: "IRunningTask_get_Path",
  };
  for (const stage of Object.keys(operations)) {
    for (const result of [0x8004130b | 0, 0x80070005 | 0]) {
      let f;
      f = schedulerFixture(program, [[first, ended]], (at, pass, index) => {
        if (at !== stage || (["item", "path"].includes(at) && index !== 2))
          return 0;
        f.api.SetLastError(37);
        return result;
      });
      assert.throws(f.active, (error) => {
        assert.equal(error.scheduler.result, result);
        assert.equal(error.scheduler.operation, operations[stage]);
        assert.equal(error.scheduler.lastError, 37);
        return true;
      });
      const attempts =
        ["item", "path"].includes(stage) && result === (0x8004130b | 0) ? 3 : 1;
      assert.equal(f.calls.filter(([at]) => at === "census").length, attempts);
      assertSchedulerReleases(f);
      for (const row of [first, ended])
        assert.equal(
          f.closed.filter((id) => id === row.id).length,
          ["item", "path"].includes(stage) ? attempts : 0,
        );
      assert.equal(
        f.closed.filter((id) => id.startsWith("string:")).length,
        stage === "path" ? attempts * 2 : stage === "item" ? attempts : 0,
      );
    }
  }
});

test("bridge task census refuses invalid and unwritten outputs without leaking partial acquisitions", async () => {
  const program = await schedulerProgram();
  const first = { id: "first", path: "\\owned" },
    ended = { id: "ended", path: "\\OWNED" };
  const cases = [
    ...["all", "count", "item", "path"].flatMap((stage) =>
      [0, 0x80070057 | 0].map((result) => [stage, { result }]),
    ),
    ...["all", "item", "path"].map((stage) => [stage, { output: null }]),
    ...[-1, 4097].map((output) => ["count", { output }]),
    ...["", "relative", "\\owned\0suffix", "\\" + "x".repeat(4095)].map(
      (output) => ["path", { output }],
    ),
  ];
  for (const [stage, response] of cases) {
    const f = schedulerFixture(program, [[first, ended]], (at, pass, index) =>
      at === stage && (!["item", "path"].includes(at) || index === 2)
        ? response
        : 0,
    );
    assert.throws(f.active, (error) => {
      if (response.result)
        assert.equal(error.scheduler.result, response.result);
      return true;
    });
    assert.equal(f.calls.filter(([at]) => at === "census").length, 1);
    assertSchedulerReleases(f);
    assert.equal(
      f.closed.filter((id) => id === "first").length,
      ["item", "path"].includes(stage) ? 1 : 0,
    );
    assert.equal(
      f.closed.filter((id) => id === "ended").length,
      stage === "path" ? 1 : 0,
    );
    const strings = ["item", "path"].includes(stage) ? ["string:\\owned"] : [];
    if (stage === "path" && response.output != null)
      strings.push(`string:${response.output}`);
    assert.deepEqual(
      f.closed.filter((id) => id.startsWith("string:")).sort(),
      strings.sort(),
    );
  }
});

test("actual scheduler census retains one-based hidden reads, exact paths and every partial reference", async () => {
  const program = await schedulerProgram();
  const other = { id: "other", path: "\\other" },
    first = { id: "first", path: "\\owned" },
    hidden = { id: "hidden", path: "\\OWNED" };
  for (const rows of [[], [other], [first], [other, first, hidden]]) {
    const f = schedulerFixture(program, [rows]);
    assert.equal(f.read(), rows.filter((row) => row !== other).length);
    assert.deepEqual(
      f.calls.filter((row) => row[0] === "item").map((row) => row[2]),
      rows.map((_, i) => i + 1),
    );
    assert.deepEqual(
      f.owned.filter(Boolean),
      rows.filter((row) => row !== other),
    );
    f.api.task_close();
    for (const row of rows)
      assert.equal(f.closed.filter((id) => id === row.id).length, 1);
    assert.equal(f.closed.filter((id) => id === "census").length, 1);
  }
  for (const stage of ["item", "path", "refresh"]) {
    const f = schedulerFixture(program, [[first, hidden]], (at, pass, index) =>
      at === stage && index === 2 ? 0x80070005 | 0 : 0,
    );
    assert.throws(f.read, (error) => {
      assert.deepEqual(error.scheduler, {
        result: 0x80070005 | 0,
        operation: {
          item: "IRunningTaskCollection_get_Item",
          path: "IRunningTask_get_Path",
          refresh: "IRunningTask_Refresh",
        }[stage],
        index: 2,
        attempt: 1,
        lastError: 0,
      });
      return true;
    });
    assert.equal(f.calls.filter((row) => row[0] === "census").length, 1);
    assert.equal(f.closed.filter((id) => id === "first").length, 1);
    assert.equal(f.closed.filter((id) => id === "hidden").length, 1);
    assert.equal(f.api.reader_task, null);
  }
});

test("ended scheduler entries discard the whole census and cannot turn exhaustion into absence", async () => {
  const program = await schedulerProgram();
  const first = { id: "first", path: "\\owned" },
    ended = { id: "ended", path: "\\owned" },
    live = { id: "live", path: "\\owned" };
  for (const stage of ["item", "path", "refresh"]) {
    for (const exhausted of [false, true]) {
      const f = schedulerFixture(
        program,
        [[first, ended], [live]],
        (at, pass, index) =>
          at === stage && (exhausted || (pass === 1 && index === 2))
            ? 0x8004130b | 0
            : 0,
      );
      if (exhausted) {
        assert.throws(
          f.read,
          (error) =>
            error.scheduler.attempt === 3 &&
            error.scheduler.result === (0x8004130b | 0),
        );
        assert.equal(f.owned.filter(Boolean).length, 0);
      } else {
        assert.equal(f.read(), 1);
        assert.deepEqual(f.owned.filter(Boolean), [live]);
        assert.ok(f.closed.includes("first") && f.closed.includes("ended"));
        f.api.task_close();
      }
      assert.equal(
        f.calls.filter((row) => row[0] === "census").length,
        exhausted ? 3 : 2,
      );
    }
  }
  const f = schedulerFixture(program, [[ended], []], (at, pass) =>
    at === "refresh" && pass === 1 ? 0x8004130b | 0 : 0,
  );
  assert.equal(f.read(), 0); // A complete fresh census; held retirement is required separately.
  assert.deepEqual(f.calls.filter((row) => row[0] === "census").length, 2);
  f.api.task_close();
});

test("scheduler census rejects failed collection reads and incomplete count bounds before any item", async () => {
  const program = await schedulerProgram();
  for (const stage of ["all", "count", "negative", "overflow"]) {
    const rows = [];
    if (stage === "negative") rows.censusCount = -1;
    if (stage === "overflow") rows.censusCount = 4097;
    const f = schedulerFixture(program, [rows], (at) =>
      at === stage ? 0x80070057 | 0 : 0,
    );
    assert.throws(f.read, (error) => {
      if (["all", "count"].includes(stage))
        assert.equal(
          error.scheduler.operation,
          stage === "all"
            ? "ITaskService_GetRunningTasks"
            : "IRunningTaskCollection_get_Count",
        );
      return true;
    });
    assert.equal(f.calls.filter((row) => row[0] === "census").length, 1);
    assert.equal(
      f.calls.some((row) => row[0] === "item"),
      false,
    );
    assert.equal(f.closed.filter((row) => row === "census").length, 1);
  }
});

test("task scope closure frees every partial COM/string result and preserves handle-close uncertainty", async () => {
  const program = await schedulerProgram();
  for (const failure of [null, 0, 6]) {
    const f = schedulerFixture(program, [[]]);
    Object.assign(f.api.reader_task, {
      service: "service",
      folder: "folder",
      task: "task",
      again: "again",
      instances: {},
      all: { rows: [] },
      item: { id: "partial" },
      path: "path",
      root: "root",
      name: "name",
      xml: "xml",
      sd: "sd",
      guid: "guid",
      registeredPath: "registered",
      engine:
        failure === null
          ? "engine"
          : failure === 0
            ? "bad-close-zero"
            : "bad-close",
    });
    f.api.reader_task.running[0] = { id: "owned" };
    f.api.SetLastError(123);
    assert.equal(f.api.task_close(), failure === null);
    assert.equal(f.api.reader_scheduler.cleanupFailed, failure !== null);
    assert.equal(f.api.reader_scheduler.cleanupError, failure ?? 0);
    assert.equal(f.api.GetLastError(), 123);
    assert.equal(f.api.reader_task, null);
    const once = [...f.closed];
    assert.equal(f.api.task_close(), failure === null);
    assert.deepEqual(f.closed, once);
    for (const item of [
      failure === null
        ? "engine"
        : failure === 0
          ? "bad-close-zero"
          : "bad-close",
      "partial",
      "owned",
      "census",
      "instances",
      "again",
      "task",
      "folder",
      "service",
      "string:path",
      "string:root",
      "string:name",
      "string:xml",
      "string:sd",
      "string:guid",
      "string:registered",
    ])
      assert.equal(f.closed.filter((v) => v === item).length, 1, item);
  }
  // The normal details path closes each engine before closing the outer scope.
  for (const handle of ["engine", "bad-close-zero", "bad-close"]) {
    const f = schedulerFixture(program, [[]]),
      failed = handle !== "engine";
    f.api.reader_task.engine = handle;
    assert.equal(f.api.task_engine_close(), !failed);
    assert.equal(f.api.reader_scheduler.cleanupFailed, failed);
    assert.equal(
      f.api.reader_scheduler.cleanupError,
      handle === "bad-close" ? 6 : 0,
    );
    assert.equal(f.api.task_close(), !failed);
    assert.equal(f.closed.filter((item) => item === handle).length, 1);
  }
});

test("actual experiment cold census requires bounded complete enumeration before declaring absence", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = (name) =>
      new RegExp(
        `static (?:void|BOOL) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)[1],
    translate = (text) =>
      text
        .replace(
          "HANDLE handles[2]={reader_cold.snapshot,reader_cold.process}",
          "const handles=[reader_cold.snapshot,reader_cold.process]",
        )
        .replace("memset(&reader_cold,0,sizeof(reader_cold))", "reset()")
        .replace("PROCESSENTRY32W entry={sizeof(entry)}", "const entry={}")
        .replace(
          "FILETIME birth,exit,kernel,user",
          "const birth={},exit={},kernel={},user={}",
        )
        .replaceAll(
          "((ULONGLONG)birth.dwHighDateTime<<32)|birth.dwLowDateTime",
          "(BigInt(birth.dwHighDateTime)*0x100000000n+BigInt(birth.dwLowDateTime))",
        )
        .replaceAll("&entry", "entry")
        .replaceAll("&birth,&exit,&kernel,&user", "birth,exit,kernel,user")
        .replace(/(?<!&)&code\b/gu, "value=>code=value")
        .replace(/\b(?:HANDLE|DWORD|BOOL|unsigned)\b/gu, "let"),
    census = new Script(`
      function cold_release(){${translate(body("cold_release"))}}
      function cold_require(ok,operation,error){${translate(body("cold_require"))}}
      function cold_census(pid){${translate(body("cold_census"))}}
      function cold_process(pid,creation){${translate(body("cold_process"))}}
      cold_process(20,10020n);
    `),
    emit = new Script(
      `(source,line,error)=>{${body("reader_cold_failure")
        .replace("char bytes[1536];DWORD written", "const bytes={};let written")
        .replace("int size", "const size")
        .replaceAll("sizeof(bytes)", "1536")
        .replaceAll("(DWORD)size", "size")
        .replaceAll("&written", "value=>written=value")
        .replaceAll("\\036", "\\x1e")}}`,
    );
  for (const fault of [
    null,
    "absent",
    "vanished",
    "replacement",
    "replacement-gone",
    "exit-127",
    "snapshot",
    "first",
    "next",
    "overflow",
    "duplicate",
    "census-close",
    "not-observer",
    "open-denied",
    "open-still-present",
    "pid",
    "times",
    "older",
    "changed-birth",
    "live",
    "wait-failed",
    "exit-read",
    "watchdog",
    "high-exit",
    "wait-and-close",
    "process-close",
  ]) {
    let lastError = 18,
      output = "",
      enumerated = 0;
    const closedHandles = [],
      calls = [],
      state = {},
      replacement =
        fault?.startsWith("replacement") || fault === "changed-birth",
      api = {
        reader_cold: state,
        preparation_only: fault !== "not-observer",
        TRUE: true,
        FALSE: false,
        NULL: null,
        ERROR_SUCCESS: 0,
        ERROR_INVALID_PARAMETER: 87,
        ERROR_NO_MORE_FILES: 18,
        INVALID_HANDLE_VALUE: -1,
        WAIT_FAILED: 0xffffffff,
        WAIT_OBJECT_0: 0,
        PROCESS_QUERY_LIMITED_INFORMATION: 0x1000,
        SYNCHRONIZE: 0x100000,
        TH32CS_SNAPPROCESS: 2,
        reset: () =>
          Object.assign(state, {
            snapshot: null,
            process: null,
            active: false,
            cleanupFailed: false,
            cleanupError: 0,
            error: 0,
            observedPid: 0,
            birth: 0n,
            census: 0,
            count: 0,
            found: 0,
          }),
        GetLastError: () => lastError,
        SetLastError: (value) => {
          lastError = value;
        },
        need: assert.ok,
        CreateToolhelp32Snapshot: () => {
          calls.push("snapshot");
          if (fault === "snapshot") {
            lastError = 5;
            return -1;
          }
          return { pass: state.census, index: 0 };
        },
        Process32FirstW: (snapshot, entry) => {
          enumerated++;
          entry.th32ProcessID = 10;
          if (fault === "first") {
            lastError = 5;
            return false;
          }
          return true;
        },
        Process32NextW: (snapshot, entry) => {
          enumerated++;
          snapshot.index++;
          entry.th32ProcessID = fault === "overflow" ? 10 : 20;
          if (
            fault === "overflow" ||
            (snapshot.index <= (fault === "duplicate" ? 2 : 1) &&
              fault !== "absent" &&
              !(
                snapshot.pass === 2 &&
                ["vanished", "replacement-gone"].includes(fault)
              ))
          )
            return true;
          lastError = fault === "next" ? 5 : 18;
          return false;
        },
        OpenProcess: () => {
          calls.push("open");
          if (
            ["vanished", "open-denied", "open-still-present"].includes(fault)
          ) {
            lastError = fault === "open-denied" ? 5 : 87;
            return null;
          }
          return "original-slot";
        },
        GetProcessId: () => (fault === "pid" ? 21 : 20),
        GetProcessTimes: (_process, birth) => {
          if (fault === "times") {
            lastError = 5;
            return false;
          }
          birth.dwHighDateTime = 0;
          birth.dwLowDateTime =
            fault === "older"
              ? 10019
              : replacement
                ? state.census === 2 && fault === "changed-birth"
                  ? 20001
                  : 20000
                : 10020;
          return true;
        },
        WaitForSingleObject: () => {
          if (fault === "wait-failed") {
            lastError = 5;
            return 0xffffffff;
          }
          return ["live", "wait-and-close"].includes(fault) ? 258 : 0;
        },
        GetExitCodeProcess: (_process, out) => {
          if (fault === "exit-read") {
            lastError = 5;
            return false;
          }
          out(
            fault === "watchdog"
              ? 124
              : fault === "high-exit"
                ? 259
                : fault === "exit-127"
                  ? 127
                  : 0,
          );
          return true;
        },
        CloseHandle: (handle) => {
          closedHandles.push(handle);
          const failed =
            handle === "original-slot"
              ? ["process-close", "wait-and-close"].includes(fault)
              : fault === "census-close";
          lastError = failed ? 6 : 99;
          return !failed;
        },
        identity: () => {
          output += JSON.stringify({
            ...identity(20),
            creationTime: String(state.birth),
          });
        },
        printf: (format, ...values) => {
          let at = 0;
          output += format.replace(/%(?:ll|l)?[sud]/gu, () =>
            String(values[at++]),
          );
        },
        putchar: (char) => {
          output += char;
        },
      };
    const accepted = [
      null,
      "absent",
      "vanished",
      "replacement",
      "replacement-gone",
      "exit-127",
    ].includes(fault);
    if (accepted) {
      census.runInNewContext(api);
      const actual = JSON.parse(output);
      assert.equal(
        actual.present,
        !["absent", "vanished", "replacement-gone"].includes(fault),
      );
      if (actual.present) assert.equal(actual.original, !replacement);
      assert.ok(coldProcessObservation(actual, identity(20)).complete);
      assert.equal(
        calls.filter((name) => name === "snapshot").length,
        ["vanished", "replacement", "replacement-gone"].includes(fault) ? 2 : 1,
      );
      assert.equal(
        calls.filter((name) => name === "open").length,
        fault === "absent" ? 0 : 1,
      );
    } else {
      assert.throws(() => census.runInNewContext(api), undefined, fault);
      const operation =
        {
          "not-observer": "arguments",
          "open-denied": "open",
          "open-still-present": "open",
          overflow: "bound",
          older: "birth",
          "changed-birth": "birth",
          live: "wait",
          "wait-failed": "wait",
          "wait-and-close": "wait",
          "exit-read": "exit",
          watchdog: "exit-code",
          "high-exit": "exit-code",
        }[fault] ?? fault;
      assert.equal(state.operation, operation, fault);
      assert.equal(
        state.error,
        [
          "snapshot",
          "first",
          "next",
          "open-denied",
          "times",
          "wait-failed",
          "exit-read",
        ].includes(fault)
          ? 5
          : fault === "open-still-present"
            ? 87
            : ["census-close", "process-close"].includes(fault)
              ? 6
              : 0,
        fault,
      );
      assert.equal(
        lastError,
        state.error,
        "cleanup cannot replace the original failure",
      );
      assert.equal(
        state.cleanupFailed,
        ["census-close", "process-close", "wait-and-close"].includes(fault),
      );
      const f = transport(),
        pending = f.channel.receive(),
        frames = [];
      emit.runInNewContext({
        ...api,
        reader_command: "verify-cold-process",
        sequence: 1,
        control: "authenticated",
        sprintf_s: (target, maximum, format, ...values) => {
          let at = 0;
          target.value = format.replace(/%(?:ll|l)?[sud]/gu, () =>
            String(values[at++]),
          );
          assert.ok(target.value.length < maximum);
          return target.value.length;
        },
        WriteFile: (_handle, bytes, size) => {
          frames.push(bytes.value.slice(0, size));
          return true;
        },
      })("custody-reader.c", 810, state.error);
      f.child.stdout.write(frames[0].slice(0, 31));
      f.child.stdout.write(frames[0].slice(31));
      await assert.rejects(pending, (error) => {
        assert.equal(error.custodyReaderFailure.cold.operation, operation);
        assert.equal(error.custodyReaderFailure.lastError, state.error);
        assert.equal(
          error.custodyReaderFailure.cold.cleanupFailed,
          state.cleanupFailed,
        );
        return true;
      });
      await assert.rejects(f.channel.completion);
      f.child.emit("close", 126, null);
    }
    assert.equal(
      new Set(closedHandles).size,
      closedHandles.length,
      "each acquired handle closes at most once",
    );
    if (fault === "overflow") assert.equal(enumerated, 65537);
  }
  const absent =
      /if \(result == HRESULT_FROM_WIN32\(ERROR_FILE_NOT_FOUND\)\) \{([\s\S]*?)\n  \}/u
        .exec(source)[1]
        .replace("LONG active", "const active")
        .replaceAll("LONG i", "let i"),
    task = new Script(absent);
  for (const count of [0, 1, 32]) {
    let accepted = false;
    const api = {
      result: 2,
      NULL: null,
      expected: null,
      taskLine: 1,
      reader_scheduler: { error: 0, line: 1 },
      scope: { service: {}, name: "original" },
      running: [],
      SetLastError: () => {},
      __FILE__: "reader",
      service: {},
      taskName: "original",
      need_hresult_at: (_result, ok) => assert.ok(ok),
      need: assert.ok,
      task_instances: () => count,
      IRunningTask_Release: () => {},
      printf: () => {
        accepted = true;
      },
    };
    if (count) assert.throws(() => task.runInNewContext(api));
    else task.runInNewContext(api);
    assert.equal(accepted, count === 0);
  }
});

test("actual task removal refuses any live retained process or surviving held Job", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body =
      /      for \(unsigned i = 0; i < process_count; i\+\+\) need\(WaitForSingleObject\(processes\[i\], 0\) == WAIT_OBJECT_0\);[\s\S]*?(?=      task_hr\(ITaskFolder_DeleteTask)/u.exec(
        source,
      )?.[0];
  assert.ok(body, "Expected the native task-removal retirement boundary");
  const program = new Script(
    body
      .replaceAll("unsigned i", "let i")
      .replaceAll(
        "JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current;",
        "const current = {};",
      )
      .replaceAll("sizeof(current)", "1")
      .replaceAll("&current", "current")
      .replaceAll("NULL", "null") + "remove();",
  );
  for (const fault of [
    null,
    "reader",
    "observer",
    "verified-job",
    "named-job",
    "query",
  ]) {
    const processes = [
        { retired: fault !== "reader" },
        { retired: fault !== "observer" },
      ],
      verified_jobs = [{ active: fault === "verified-job" }],
      jobs = [{ active: fault === "named-job" }];
    let removed = false;
    const run = () =>
      program.runInNewContext({
        processes,
        process_count: processes.length,
        verified_jobs,
        jobs,
        job_count: jobs.length,
        WAIT_OBJECT_0: 0,
        JobObjectBasicAccountingInformation: 1,
        WaitForSingleObject: (process, timeout) => {
          assert.equal(timeout, 0);
          return process.retired ? 0 : 258;
        },
        QueryInformationJobObject: (job, _kind, current) => {
          current.ActiveProcesses = job.active ? 1 : 0;
          return fault !== "query";
        },
        need: assert.ok,
        remove: () => {
          removed = true;
        },
      });
    if (fault) assert.throws(run);
    else run();
    assert.equal(removed, fault === null);
  }
});

test("independent build admission and retirement bind separate original controller and compiler domains", async () => {
  for (const fault of [
    null,
    "controller-policy",
    "controller-member",
    "compiler-breakaway",
    "compiler-silent",
    "compiler-member",
    "unknown-policy",
    "worker-birth",
    "worker-live",
    "compiler-survivor",
    "missing-retirement",
    "unbound-recovery-policy",
  ]) {
    const k = verificationFixture(fixture({ build: true }));
    await k.verifier.verifyBootstrap(k.f.input);
    await k.verifier.verifyAdmission(k.admission);
    if (fault === "controller-policy") {
      k.state.jobFlags = k.helperTransfer.actual.job.limitFlags = 0x2008;
      await assert.rejects(k.verifier.verifyTransfer(k.helperTransfer));
      continue;
    }
    await k.verifier.verifyTransfer(k.helperTransfer);
    const record = {
        phase: "worker-admitted",
        requestSha256: hash,
        helper: k.f.fileHelper,
        worker: k.state.worker,
      },
      admissionFault = [
        "controller-member",
        "compiler-breakaway",
        "compiler-silent",
        "compiler-member",
        "unknown-policy",
      ].includes(fault);
    if (fault === "controller-member") k.state.jobMembers.push(k.state.worker);
    if (fault === "compiler-breakaway") k.state.compilerJob.limitFlags |= 0x800;
    if (fault === "compiler-silent") k.state.compilerJob.limitFlags |= 0x1000;
    if (fault === "compiler-member")
      k.state.compilerJob.members.push(k.f.fileHelper);
    if (fault === "unknown-policy")
      k.state.damage = (operation, frame) => {
        if (operation === "verify-compiler-policy") frame.value.extra = true;
        return Buffer.from(JSON.stringify(frame) + "\n");
      };
    const admit = () =>
      k.verifier.verifyBuildWorker(
        record,
        k.f.entries[k.f.buildEntry.tool],
        hash,
      );
    if (admissionFault) {
      await assert.rejects(admit);
      continue;
    }
    const proof = await admit();
    assert.deepEqual(proof.compilerPolicy.outerJob.members, [k.f.fileHelper]);
    assert.deepEqual(proof.compilerPolicy.compilerJob.members, [
      k.state.worker,
    ]);
    k.states.get(k.f.fileHelper.pid).retired = true;
    k.states.get(k.state.worker.pid).retired = fault !== "worker-live";
    k.state.jobMembers = [];
    k.state.compilerJob.members =
      fault === "compiler-survivor" ? [identity(99)] : [];
    if (fault === "worker-birth")
      k.states.get(k.state.worker.pid).identity.creationTime = "999";
    if (fault === "missing-retirement")
      k.state.damage = (operation, frame) => {
        if (operation === "verify-recovery-jobs")
          throw new Error("Original named Job inaccessible");
        return Buffer.from(JSON.stringify(frame) + "\n");
      };
    if (fault === "unbound-recovery-policy") {
      k.state.recoveryMembers = [];
      k.state.recoveryFlags = 0x2808;
    }
    const finish = () => k.verifier.verifyHelperRetirement(k.f.fileHelper);
    if (fault) await assert.rejects(finish);
    else {
      assert.equal((await finish()).status, "RETIRED");
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-recovery-jobs")
          .length,
        2,
      );
      const before = k.events.length;
      await assert.rejects(
        k.verifier.recoverOwnedTask(nonce, hash, k.admission.bridge),
      );
      assert.equal(
        k.events.length,
        before,
        "One compiler's settlement must not authorize whole-run task removal",
      );
    }
  }
});

test("Windows whole-Job retirement and independent transferred handles cannot be replaced by process exit", async () => {
  for (const damage of [
    "extra-handle",
    "missing-pipe-dacl",
    "survivor",
    "unreadable",
  ]) {
    const k = verificationFixture();
    await k.verifier.verifyBootstrap(k.f.input);
    await k.verifier.verifyAdmission(k.admission);
    if (["extra-handle", "missing-pipe-dacl"].includes(damage)) {
      k.state.unknownHandle = damage === "extra-handle";
      if (damage === "missing-pipe-dacl")
        k.state.damage = (operation, frame) => {
          if (operation === "verify-transfer")
            delete frame.value.pipeDaclSha256;
          return Buffer.from(JSON.stringify(frame) + "\n");
        };
      await assert.rejects(k.verifier.verifyTransfer(k.helperTransfer));
      continue;
    }
    await k.verifier.verifyTransfer(k.helperTransfer);
    k.states.get(k.f.fileHelper.pid).retired = true;
    if (damage === "unreadable")
      k.state.damage = () => {
        throw new Error("Native Job observation inaccessible");
      };
    await assert.rejects(k.verifier.verifyHelperRetirement(k.f.fileHelper));
  }
});

test("Windows completed custody rereads retained subjects and task absence twice, retaining missing handles and untracked Jobs", async () => {
  const k = verificationFixture();
  for (const actor of [k.f.helper, k.f.fileHelper])
    await k.exchange(
      Buffer.from(
        ["verify-retain", 1, actor.pid, actor.creationTime].join(" ") + "\n",
      ),
    );
  for (const state of k.states.values()) state.retired = true;
  k.state.absent = true;
  const proof = await k.verifier.verifyCompleted(
    k.f.input,
    [k.f.helper, k.f.fileHelper],
    [nonce],
  );
  assert.equal(proof.tasksRemoved, true);
  assert.equal(
    k.events.filter((entry) => entry.operation === "verify-task").length,
    2,
  );
  const empty = verificationFixture();
  empty.state.absent = true;
  await assert.rejects(
    empty.verifier.verifyCompleted(empty.f.input, [], [nonce]),
  );
  assert.equal(empty.events.length, 0);
  const missing = verificationFixture();
  missing.states.get(missing.f.helper.pid).retired = true;
  missing.state.absent = true;
  await assert.rejects(
    missing.verifier.verifyCompleted(
      missing.f.input,
      [missing.f.helper],
      [nonce],
    ),
  );
  assert.equal(
    missing.events.filter((entry) => entry.operation === "verify-retain")
      .length,
    0,
  ); // Reconstruction never opens replacement process handles.
  const job = verificationFixture();
  job.states.get(job.f.helper.pid).retired = true;
  await assert.rejects(
    job.verifier.verifyCompleted(job.f.input, [job.f.helper], [nonce], [0]),
  );
  const joined = verificationFixture();
  await joined.verifier.verifyBootstrap(joined.f.input);
  await joined.verifier.verifyAdmission(joined.admission);
  await joined.verifier.verifyTransfer(joined.helperTransfer);
  for (const actor of joined.states.values()) actor.retired = true;
  joined.state.absent = true;
  const identities = [
    joined.f.helper,
    identity(10, runnerSid),
    joined.f.fileHelper,
  ];
  const fresh = () =>
    createWindowsCustodyVerifier(joined.observer, {
      exchange: joined.exchange,
    });
  // The native transfer Job survives loss of the old JavaScript maps.
  await assert.rejects(
    fresh().verifyCompleted(joined.f.input, identities, [nonce]),
  );
  joined.state.jobMembers = [];
  // A declaration cannot omit a subject still retained by the native reader.
  await assert.rejects(
    fresh().verifyCompleted(joined.f.input, [joined.f.helper], [nonce]),
  );
  assert.equal(
    (await fresh().verifyCompleted(joined.f.input, identities, [nonce])).status,
    "RETIRED",
  );
});

test("Windows recovery removes original tasks before admitting live dependent observer births", async () => {
  const k = verificationFixture(),
    original = [k.f.helper, identity(10, runnerSid)],
    observer = k.f.fileHelper;
  k.state.instances = 0;
  k.state.jobMembers = [];
  for (const identity of original) k.states.get(identity.pid).retired = true;
  const proof = await k.verifier.recoverCompleted(k.f.input, original);
  assert.equal(proof.status, "RETIRED");
  assert.ok(
    !k.events.some(
      (event) =>
        event.operation === "verify-retain" &&
        Number(event.args[0]) === observer.pid,
    ),
  );
  await k.verifier.recoverOwnedTask(nonce, hash, original[1]);
  const custody = await k.verifier.retainObservers(k.f.input, [observer]);
  assert.equal(custody.independent, true);
  assert.deepEqual(custody.identities, [observer]);
  assert.equal(Object.hasOwn(custody, "status"), false);
  const removal = k.events.findIndex(
      (event) => event.operation === "verify-task-remove",
    ),
    retained = k.events.findIndex(
      (event) =>
        event.operation === "verify-retain" &&
        Number(event.args[0]) === observer.pid,
    );
  assert.ok(removal >= 0 && retained > removal);
  assert.equal(
    k.events
      .slice(retained)
      .filter((event) => event.operation === "verify-process").length,
    2,
  );
  await assert.rejects(
    k.verifier.recoverCompleted(k.f.input, [...original, observer]),
  );

  const premature = verificationFixture();
  premature.state.instances = 0;
  premature.state.jobMembers = [];
  for (const identity of original)
    premature.states.get(identity.pid).retired = true;
  await premature.verifier.recoverCompleted(premature.f.input, original);
  await premature.verifier.retainObservers(premature.f.input, [observer]);
  await assert.rejects(
    premature.verifier.recoverOwnedTask(nonce, hash, original[1]),
  );
  assert.equal(premature.state.removedTasks.size, 0);
});

test("Windows original-owner recovery retains a failed process hold despite later observer completion", async () => {
  const k = verificationFixture(),
    original = [k.f.helper, identity(10, runnerSid)],
    cause = Object.assign(new Error("Original process hold unavailable"), {
      nativeFailure: {
        phase: "reader-failure",
        command: "verify-retain",
        line: 213,
        lastError: 87,
        retain: {
          pid: 33,
          processAccess: 0x120410,
          tokenAccess: 10,
          process: false,
          observedPid: 0,
          matched: -1,
          tokenResult: -1,
        },
      },
    });
  k.state.instances = 0;
  k.state.jobMembers = [];
  for (const birth of original) k.states.get(birth.pid).retired = true;
  k.state.damage = (operation, frame) => {
    if (operation === "verify-retain") throw cause;
    return Buffer.from(JSON.stringify(frame) + "\n");
  };
  await assert.rejects(
    k.verifier.recoverCompleted(k.f.input, original),
    (error) => error === cause,
  );
  k.state.damage = null;
  // Completing an observer supplies no held original process/token proof.
  k.states.get(k.f.fileHelper.pid).retired = true;
  await assert.rejects(
    k.verifier.recoverCompleted(k.f.input, original),
    (error) => error === cause,
  );
  assert.equal(k.state.removedTasks.size, 0);
  await assert.rejects(
    k.verifier.verifyColdPreparation(k.f.input, []),
    (error) => error === cause,
  );
});

test("Windows observer custody rejects missing, substituted or changed births and incomplete inventories", async () => {
  for (const fault of [
    "missing",
    "substituted",
    "changed",
    "inventory",
    "duplicate",
    "reader",
  ]) {
    const k = verificationFixture(),
      expected = k.f.fileHelper;
    if (fault === "reader") {
      k.states.get(expected.pid).retired = true;
      await k.verifier.recoverCompleted(k.f.input, [expected]);
    }
    if (fault === "missing") k.states.delete(expected.pid);
    if (fault === "substituted")
      k.states.get(expected.pid).identity = {
        ...expected,
        creationTime: "999",
      };
    let reads = 0;
    k.state.damage = (operation, frame) => {
      if (
        operation === "verify-process" &&
        ++reads === 2 &&
        fault === "changed"
      )
        frame.value.identity.creationTime = "999";
      if (operation === "verify-subjects" && fault === "inventory")
        frame.value.identities = [];
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    await assert.rejects(
      k.verifier.retainObservers(
        k.f.input,
        fault === "duplicate" ? [expected, expected] : [expected],
      ),
    );
    const commands = k.events.length;
    await assert.rejects(k.verifier.retainObservers(k.f.input, [expected]));
    assert.equal(
      k.events.length,
      commands,
      "Failed verification remains terminal",
    );
  }
});

test("Windows verifier captures concurrent caller declarations and bounds protected records before native reads", async () => {
  const k = verificationFixture(),
    declaration = structuredClone(k.f.input),
    admission = structuredClone(k.admission);
  const sealed = k.verifier.verifyBootstrap(declaration),
    admitted = k.verifier.verifyAdmission(admission);
  declaration.reader.sha256 = "f".repeat(64);
  admission.helper.pid = 99;
  await sealed;
  assert.deepEqual((await admitted).helper, k.f.helper);
  const bounded = verificationFixture();
  await assert.rejects(
    bounded.verifier.read({
      path: "C:\\Fixture\\record",
      sha256: hash,
      bytes: 8388609,
    }),
  );
  assert.equal(bounded.events.length, 0);
  const context = verificationFixture(),
    wrong = structuredClone(context.f.input);
  wrong.context.runAttempt++;
  await assert.rejects(context.verifier.verifyBootstrap(wrong));
  assert.equal(context.events.length, 0);
  for (const operation of ["retain", "recover"]) {
    const collision = verificationFixture();
    collision.observer.verification.record = async () => {};
    const request = {
      platform: "win32",
      job: collision.f.input.context,
      admission: {
        platform: "win32",
        nonce: collision.observer.verification.input.nonce,
      },
    };
    await assert.rejects(
      operation === "retain"
        ? collision.verifier.retainPrerequisiteJob(request)
        : collision.verifier.recoverPrerequisite(
            request,
            { file: "C:\\Fixture\\Storage\\intent", bytes: 1, sha256: hash },
            {},
          ),
    );
    assert.equal(collision.events.length, 0);
  }
});

test("Windows task-removal acknowledgement cannot replace fresh independent absence or settle the live observer", async () => {
  const k = verificationFixture();
  await k.verifier.verifyBootstrap(k.f.input);
  await k.verifier.verifyAdmission(k.admission);
  k.states.get(k.f.helper.pid).retired = true;
  k.states.get(10).retired = true;
  await assert.rejects(
    k.verifier.verifyTaskRemoval({
      input: k.f.input,
      helper: k.f.helper,
      taskSha256: hash,
    }),
  );
  const self = verificationFixture();
  await assert.rejects(
    self.verifier.verifyCompleted(self.f.input, [self.f.verifier], [nonce]),
  );
  const unowned = verificationFixture();
  await assert.rejects(
    unowned.verifier.recoverPrerequisite(
      {},
      { file: "C:\\Fixture\\intent", bytes: 1, sha256: hash },
      {},
    ),
  );
  assert.equal(unowned.events.length, 0); // No owned deletion without protected settlement persistence.
});

test("Windows final task absence cannot settle a surviving retained child or its Job", async () => {
  for (const damage of ["child", "job"]) {
    const k = verificationFixture();
    await k.verifier.verifyBootstrap(k.f.input);
    await k.verifier.verifyAdmission(k.admission);
    await k.verifier.verifyTransfer(k.helperTransfer);
    k.states.get(k.f.helper.pid).retired = true;
    k.states.get(10).retired = true;
    k.states.get(k.f.fileHelper.pid).retired = damage !== "child";
    k.state.jobMembers = damage === "job" ? [identity(31)] : [];
    k.state.absent = true;
    await assert.rejects(
      k.verifier.verifyTaskRemoval({
        input: k.f.input,
        helper: k.f.helper,
        taskSha256: hash,
      }),
    );
  }
});

test("Windows completed custody cannot omit a retained named Job", async () => {
  const k = verificationFixture();
  await k.exchange(
    Buffer.from(
      ["verify-retain", 1, k.f.helper.pid, k.f.helper.creationTime].join(" ") +
        "\n",
    ),
  );
  await k.exchange(
    Buffer.from(
      ["verify-job-open", 2, hex("Local\\NativeProof-" + nonce)].join(" ") +
        "\n",
    ),
  );
  k.states.get(k.f.helper.pid).retired = true;
  k.state.absent = true;
  await assert.rejects(
    k.verifier.verifyCompleted(k.f.input, [k.f.helper], [nonce]),
  );
});

async function prerequisiteVerificationFixture({
  lostObserver = false,
  missingBirth = false,
  liveMember = false,
  lostJobSlot = false,
  changedJob = false,
  changedTask = false,
  writableOutput = false,
} = {}) {
  const f = fixture(),
    bootstrap = verificationFixture(f),
    kernel = verificationFixture(f);
  // Exercise the repository adapter and verifier. Only byte reads, persistence
  // and the two independently admitted native channels are replaced.
  let bootstrapSequence = 0;
  bootstrap.observer.verification.command = async (name, args) => {
    const reply = await bootstrap.exchange(
      Buffer.from(
        ["verify-" + name, ++bootstrapSequence, ...args].join(" ") + "\n",
      ),
    );
    return JSON.parse(reply).value;
  };
  f.options.verificationReader = bootstrap.observer;
  for (const name of Object.keys(f.options))
    if (name.startsWith("verify"))
      f.options[name] = () => {
        throw new Error("High-level verification replacement reached");
      };
  const send = f.owner.send;
  f.owner.send = async (line) => {
    if (line.startsWith("verify-")) {
      const reply = await kernel.exchange(Buffer.from(line));
      f.events.push("native-" + line.trim().split(" ")[0]);
      const receive = f.owner.receive;
      f.owner.receive = async () => {
        f.owner.receive = receive;
        return JSON.parse(reply);
      };
    } else {
      await send(line);
      if (line.startsWith("finish ")) {
        bootstrap.states.get(f.helper.pid).retired = true;
      }
      if (line === "D") {
        bootstrap.states.get(10).retired = true;
        bootstrap.state.absent = true;
      }
    }
  };
  const reader = f.reader();
  await reader.start();
  const admission = {
    schemaVersion: 1,
    platform: "win32",
    nonce: "d".repeat(32),
    root: "C:\\Fixture\\Storage",
    readRoots: ["C:\\Fixture\\Storage"],
    writeRoots: ["C:\\Fixture\\Storage\\assets"],
    controllerUid: null,
    controllerSid: runnerSid,
    expires: 1,
  };
  const runtime = {
      node: { path: "C:\\Stock\\node.exe", bytes: 1, sha256: hash },
      dependencies: [],
    },
    privilege = {
      userSid: "S-1-5-18",
      sessionId: 0,
      task: "exclusive",
      pipe: "private",
    },
    source = [
      "observation.js",
      "prerequisite-files.js",
      "prerequisite-windows.js",
      "prerequisite-worker.mjs",
      "prerequisite-gateway.ps1",
      "first-failure.js",
      "prerequisite-source.js",
      "prerequisite-transport.js",
      "win32/custody-verifier.js",
    ].map((name) => ({ name, bytes: 1, sha256: hash })),
    manifest = {
      platform: "win32",
      candidateSha,
      source: {
        citations: source.map((entry) => ({
          kind: "reached-code",
          member: "candidate/ci/native/" + entry.name,
          sha256: entry.sha256,
        })),
      },
    },
    output = writableOutput
      ? "C:\\Fixture\\Storage\\assets\\records"
      : "C:\\Fixture\\Storage\\records";
  const { nonce: _nonce, expires: _expires, ...scope } = admission;
  const approvals = {
    sourceSha256: observationDigest(source),
    runtimeSha256: observationDigest(runtime),
    privilegeSha256: observationDigest(privilege),
    scopeSha256: observationDigest({ ...scope, output }),
    manifestSha256: observationDigest(manifest),
  };
  const request = {
    schemaVersion: 1,
    platform: "win32",
    job: f.input.context,
    admission,
    output,
    source,
    privilege,
    approvals,
    manifestSha256: approvals.manifestSha256,
  };
  const actors = [identity(21), identity(22), identity(23)];
  kernel.state.jobMembers = actors;
  for (const actor of actors)
    kernel.states.set(actor.pid, {
      ...structuredClone(f.process),
      identity: actor,
      retired: false,
    });
  const verifier = createWindowsCustodyVerifier(reader);
  const binding = await verifier.retainPrerequisiteJob(request);
  // Retain creation identities before disconnect. A new JS verifier later
  // rejoins these same native slots, including already signalled processes.
  for (const actor of actors)
    await reader.verification.command("retain", [
      actor.pid,
      actor.creationTime,
    ]);
  kernel.state.jobMembers = liveMember ? [actors[1]] : [];
  kernel.state.instances = 0;
  if (changedJob) kernel.state.jobDacl = "f".repeat(64);
  if (changedTask)
    kernel.state.damage = (operation, frame) => {
      if (operation === "verify-task") frame.value.sha256 = "f".repeat(64);
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
  for (const actor of actors) kernel.states.get(actor.pid).retired = true;
  const record = (phase, value) => {
    const file =
        output +
        "\\prerequisite-custody-" +
        admission.nonce +
        "-" +
        phase +
        ".json",
      bytes = Buffer.from(JSON.stringify(value));
    f.bytes.set(file, bytes);
    return { file, bytes: bytes.length, sha256: digest(bytes) };
  };
  const intent = record("intent", request),
    birth = record("birth", {
      schemaVersion: 1,
      requestSha256: binding.requestSha256,
      worker: actors[0],
      children: [actors[1]],
      verifiers: [actors[2]],
      observer: lostObserver ? identity(99) : binding.observer,
      jobSlot: lostJobSlot ? 31 : binding.jobSlot,
      jobName: binding.jobName,
      job: binding.job,
      taskSha256: hash,
    });
  if (missingBirth) f.bytes.delete(birth.file);
  const transport = createPrerequisiteTransport(
    {
      job: f.input.context,
      admission,
      manifest,
      output,
      runtime,
      privilege,
      approvals,
      windowsRequest: request,
      windowsBirth: birth,
    },
    { platform: "win32", windowsReader: reader },
  );
  return { f, kernel, reader, transport, intent, birth };
}

test("Windows interrupted prerequisite custody rejoins held births and Job before exact owned task removal and protected settlement", async () => {
  const k = await prerequisiteVerificationFixture();
  try {
    const proof = await k.transport.recover(k.intent);
    assert.equal(proof.taskRemoved, true);
    const closed = await k.transport.close();
    assert.equal(closed.custodianRetired, true);
    assert.equal(closed.verifierRetired, false);
    const intent = k.f.records.find(
      (record) => record.phase === "verify-task-remove",
    );
    assert.deepEqual(intent.arguments.slice(0, 3), [
      "prerequisite",
      hex("d".repeat(32)),
      hash,
    ]);
    assert.ok(
      k.f.events.indexOf("persist-verify-task-remove") <
        k.f.events.indexOf("native-verify-task-remove"),
    );
    assert.equal(k.f.records.at(-1).phase, "verify-prerequisite-settled");
    assert.equal(
      k.kernel.events.filter((entry) => entry.operation === "verify-job-open")
        .length,
      1,
    );
    assert.equal(
      k.kernel.events.filter((entry) => entry.operation === "verify-task")
        .length,
      6,
    );
    assert.equal(k.f.events.filter((entry) => entry === "entry").length, 1); // No recovery launch.
  } finally {
    assert.equal((await k.reader.close()).status, "RETIRED");
  }
});

test("Windows reconstruction retains missing birth, replaced observer and surviving whole-Job custody with the first failure", async () => {
  for (const fault of [
    "lostObserver",
    "missingBirth",
    "liveMember",
    "lostJobSlot",
    "changedJob",
    "changedTask",
    "writableOutput",
  ]) {
    const k = await prerequisiteVerificationFixture({ [fault]: true });
    try {
      let first;
      await assert.rejects(k.transport.recover(k.intent), (error) => {
        first = error;
        return true;
      });
      await assert.rejects(k.transport.close(), (error) => error === first);
      assert.ok(
        !k.kernel.events.some(
          (entry) => entry.operation === "verify-task-remove",
        ),
      );
      assert.ok(
        !k.f.records.some(
          (record) => record.phase === "verify-prerequisite-settled",
        ),
      );
    } finally {
      k.f.owner.close();
    }
  }
});

test("Windows verification expiry fences later native reads and late protected receipts, preserving the first error", async () => {
  const k = verificationFixture();
  let time = 100;
  const verifier = createWindowsCustodyVerifier(k.observer, {
    exchange: k.exchange,
    clock: () => time,
    deadline: 200,
  });
  k.state.damage = (_operation, frame) => {
    time = 200;
    return Buffer.from(JSON.stringify(frame) + "\n");
  };
  let first;
  await assert.rejects(verifier.verifyBootstrap(k.f.input), (error) => {
    first = error;
    return true;
  });
  assert.equal(k.events.length, 1);
  time = 100;
  k.state.damage = null;
  await assert.rejects(
    verifier.verifyBootstrap(k.f.input),
    (error) => error === first,
  );
  assert.equal(k.events.length, 1);

  const receipt = verificationFixture();
  time = 100;
  receipt.observer.verification.record = async () => {
    time = 200;
  };
  const late = createWindowsCustodyVerifier(receipt.observer, {
    exchange: receipt.exchange,
    clock: () => time,
    deadline: 200,
  });
  const request = {
    platform: "win32",
    job: receipt.f.input.context,
    admission: { nonce },
  };
  await assert.rejects(late.retainPrerequisiteJob(request), (error) => {
    first = error;
    return true;
  });
  assert.equal(receipt.events.length, 1);
  time = 100;
  await assert.rejects(
    late.retainPrerequisiteJob(request),
    (error) => error === first,
  );
  assert.equal(receipt.events.length, 1);
});

function coldVerificationFixture() {
  const f = fixture();
  f.input.purpose = "experiment";
  f.input.context.executionId = "build";
  f.input.bindingSha256 = f.input.reviewSha256;
  delete f.input.reviewSha256;
  f.input.sources.push({
    path: "C:\\Fixture\\Sealed\\experiment.h",
    sha256: hash,
  });
  return verificationFixture(f);
}

test("Windows experiment cold custody proves disappeared originals without retaining them and refuses uncertain native observations", async () => {
  const faults = [
    null,
    "present-retired",
    "replacement-birth",
    "replacement-changes",
    "reordered-identity",
    "verifier-pid-reuse",
    "verifier-birth",
    "verifier-birth-sid",
    "reviewed",
    "pid-reuse",
    "session",
    "sid",
    "live",
    "handle-read",
    "incomplete-census",
    "census-read",
    "contradiction",
    "job-read",
    "job-count",
    "job-member",
    "job-policy",
    "compiler-member",
    "controlling-member",
    "job-reappears",
    "job-changes",
    "process-changes",
    "task",
    "task-read",
    "nonce",
    "birth",
    "receipt",
    "task-digest",
    "extra-process-field",
    "watchdog",
  ];
  for (const fault of faults) {
    const k = coldVerificationFixture(),
      helper = structuredClone(
        fault === "verifier-birth" ? k.f.verifier : k.f.helper,
      ),
      bridge =
        fault?.startsWith("verifier-") && fault !== "verifier-birth"
          ? {
              ...k.f.verifier,
              creationTime:
                fault === "verifier-pid-reuse"
                  ? "9000"
                  : k.f.verifier.creationTime,
              sessionId: 2,
              userSid: runnerSid,
            }
          : identity(10, runnerSid),
      birth = {
        schemaVersion: 1,
        nonce,
        taskSha256: hash,
        helper,
        bridge,
        status: "POSSIBLE",
      },
      owner = windowsClosedPreparationOwner(birth, {
        ...birth,
        status: "RETIRED",
      });
    k.states.delete(helper.pid);
    k.states.delete(bridge.pid);
    if (fault === "verifier-pid-reuse")
      k.states.set(k.f.verifier.pid, {
        identity: k.f.verifier,
        retired: false,
      });
    k.state.absent = fault !== "task";
    if (
      [
        "present-retired",
        "replacement-birth",
        "replacement-changes",
        "reordered-identity",
        "pid-reuse",
        "session",
        "sid",
        "live",
        "watchdog",
        "process-changes",
      ].includes(fault)
    ) {
      const actual = { ...helper };
      if (fault === "pid-reuse") actual.creationTime = "999";
      if (fault?.startsWith("replacement-")) actual.creationTime = "20000";
      if (fault === "session") actual.sessionId++;
      if (fault === "sid") actual.userSid = runnerSid;
      k.states.set(helper.pid, { identity: actual, retired: fault !== "live" });
      if (fault === "watchdog") k.state.exitCode = 124;
    }
    if (fault === "nonce") owner.nonce = k.observer.verification.input.nonce;
    if (fault === "birth") delete owner.identities[0].creationTime;
    if (fault === "receipt") owner.receiptsSha256 = "invalid";
    if (fault === "task-digest") owner.taskSha256 = "invalid";
    let scans = 0,
      jobs = 0;
    k.state.damage = (operation, frame) => {
      if (operation === "verify-cold-process") {
        scans++;
        if (
          (fault?.startsWith("replacement-") ||
            fault === "verifier-pid-reuse") &&
          frame.value.present
        ) {
          frame.value.original = false;
          delete frame.value.signaled;
          delete frame.value.exitCode;
          if (fault === "replacement-changes" && scans === 3)
            frame.value.identity = {
              ...frame.value.identity,
              creationTime: "20001",
            };
        }
        if (["handle-read", "census-read"].includes(fault))
          throw new Error(fault);
        if (fault === "process-changes" && scans === 3)
          frame.value.exitCode = 1;
        if (fault === "reordered-identity" && scans === 3)
          frame.value.identity = Object.fromEntries(
            Object.entries(frame.value.identity).reverse(),
          );
        if (fault === "incomplete-census") frame.value.complete = false;
        if (fault === "extra-process-field") frame.value.identity = helper;
        if (fault === "contradiction" && scans === 3)
          frame.value = {
            complete: true,
            present: true,
            original: true,
            identity: helper,
            signaled: true,
            exitCode: 0,
          };
      }
      if (operation === "verify-cold-jobs") {
        jobs++;
        if (fault === "job-read") throw new Error(fault);
        if (fault === "job-count") frame.value.jobs.pop();
        const job = {
          daclSha256: hash,
          limitFlags: 0x2008,
          processLimit: 32,
          uiRestrictions: 255,
          members: [helper],
        };
        if (fault === "job-member") frame.value.jobs[127] = job;
        if (fault === "job-policy")
          frame.value.jobs[0] = { ...job, members: [], limitFlags: 0 };
        if (fault === "compiler-member")
          frame.value.compilerJob = { ...job, processLimit: 31 };
        if (fault === "controlling-member") frame.value.controllingJob = job;
        if (fault === "job-reappears" && jobs === 3)
          frame.value.jobs[0] = { ...job, members: [] };
        if (fault === "job-changes")
          frame.value.jobs[0] = {
            ...job,
            members: [],
            daclSha256: jobs === 3 ? "d".repeat(64) : hash,
          };
      }
      if (operation === "verify-task" && fault === "task-read")
        throw new Error(fault);
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    if (fault === "reviewed") {
      delete k.f.input.purpose;
      k.f.input.reviewSha256 = k.f.input.bindingSha256;
      delete k.f.input.bindingSha256;
    }
    const verify = () => k.verifier.verifyColdPreparation(k.f.input, [owner]);
    if (
      fault &&
      ![
        "present-retired",
        "replacement-birth",
        "reordered-identity",
        "verifier-pid-reuse",
      ].includes(fault)
    ) {
      await assert.rejects(verify, undefined, fault);
      const count = k.events.length;
      k.state.damage = null;
      await assert.rejects(verify, "uncertainty stays latched");
      assert.equal(k.events.length, count);
    } else {
      const proof = await verify();
      assert.equal(proof.status, "RETIRED");
      assert.equal(proof.noLiveMembers, true);
      assert.equal(proof.tasksRemoved, true);
      assert.deepEqual(proof.originals, [owner]);
      if (fault === "verifier-pid-reuse") {
        const replacement = {
          complete: true,
          present: true,
          original: false,
          identity: k.f.verifier,
        };
        assert.deepEqual(proof.processCensus.before[1], replacement);
        assert.deepEqual(proof.processCensus.after[1], replacement);
      }
      if (!fault)
        assert.deepEqual(proof.processCensus, {
          before: [
            { complete: true, present: false },
            { complete: true, present: false },
          ],
          after: [
            { complete: true, present: false },
            { complete: true, present: false },
          ],
        });
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-cold-process")
          .length,
        4,
      );
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-cold-jobs")
          .length,
        4,
      );
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-task").length,
        2,
      );
    }
    assert.ok(!k.events.some(({ operation }) => operation === "verify-retain"));
  }
});

test("Windows cold custody separates reused original births and each owner's repeated Job observations", async () => {
  const fields = ["jobs", "compilerJob", "controllingJob"];
  for (const fault of [
    null,
    "duplicate-birth",
    "conflicting-sid",
    "conflicting-session",
    ...fields.flatMap((field) => [`${field}-0`, `${field}-1`]),
  ]) {
    const k = coldVerificationFixture(),
      helper = identity(20),
      bridge = identity(10, runnerSid),
      laterHelper =
        fault === "duplicate-birth"
          ? helper
          : fault === "conflicting-sid"
            ? identity(bridge.pid)
            : { ...helper, creationTime: "20020" },
      laterBridge =
        fault === "conflicting-session"
          ? { ...bridge, sessionId: 2 }
          : identity(30, runnerSid),
      owners = [
        { nonce, helper, bridge },
        { nonce: "d".repeat(32), helper: laterHelper, bridge: laterBridge },
      ].map((original) => {
        const birth = {
          ...original,
          schemaVersion: 1,
          taskSha256: hash,
          status: "POSSIBLE",
        };
        return windowsClosedPreparationOwner(birth, {
          ...birth,
          status: "RETIRED",
        });
      }),
      reads = [0, 0];
    k.states.clear();
    k.state.absent = true;
    k.state.damage = (operation, frame) => {
      const actual = frame.value;
      if (operation === "verify-cold-jobs") {
        const index = owners.findIndex((owner) => owner.nonce === actual.nonce),
          job = {
            daclSha256: index === 0 ? hash : "d".repeat(64),
            limitFlags: 0x2008,
            processLimit: 32,
            uiRestrictions: 255,
            members: [],
          };
        actual.controllingJob = { ...job };
        if (actual.pid === helper.pid) {
          reads[index]++;
          actual.jobs[127] = { ...job };
          actual.compilerJob = { ...job, processLimit: 31 };
          for (const field of fields)
            if (fault === `${field}-${index}` && reads[index] === 2) {
              const changed =
                field === "jobs" ? actual.jobs[127] : actual[field];
              changed.daclSha256 = "f".repeat(64);
            }
        }
      }
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    const verify = () => k.verifier.verifyColdPreparation(k.f.input, owners);
    if (fault) {
      await assert.rejects(verify, undefined, fault);
      if (!fields.some((field) => fault.startsWith(field)))
        assert.equal(
          k.events.length,
          0,
          "Contradictory births fail before native reads",
        );
    } else {
      const proof = await verify(),
        processes = owners.flatMap((owner) =>
          owner.identities.map(({ pid, creationTime }) => [
            String(pid),
            creationTime,
          ]),
        ),
        jobs = owners.flatMap((owner) =>
          owner.identities.map(({ pid, creationTime }) => [
            String(pid),
            creationTime,
            owner.nonce,
          ]),
        ),
        tasks = owners.map((owner) => ["custody", hex(owner.nonce)]);
      assert.equal(proof.status, "RETIRED");
      assert.deepEqual(proof.originals, owners);
      assert.deepEqual(reads, [2, 2]);
      for (const [operation, expected] of [
        ["verify-cold-process", processes],
        ["verify-cold-jobs", jobs],
        ["verify-task", tasks],
      ])
        assert.deepEqual(
          k.events
            .filter((event) => event.operation === operation)
            .map((event) => event.args),
          [...expected, ...expected],
        );
    }
    assert.ok(!k.events.some(({ operation }) => operation === "verify-retain"));
  }
});

test("Windows experiment case recovery selects acknowledged cold owners before retention and keeps every cleanup obligation", async () => {
  for (const fault of [
    null,
    "retained-original",
    "retained-foreign",
    "observer-only",
    "lost-completion",
    "lost-completion-live",
    "lost-completion-task",
    "lost-completion-error-87",
    "lost-completion-missing-finish",
    "missing-ack",
    "duplicate-ack",
    "missing-finish",
    "finish-order",
    "admission-order",
    "finish-sequence",
    "task-binding",
    "birth-binding",
    "observer-result",
    "observer-birth",
    "reviewed",
    "live",
    "pid-reuse",
    "incomplete",
    "error-87",
    "survivor",
    "job-count",
    "task",
    "accountAbsent",
    "rightsAbsent",
    "jobAbsent",
    "policyRestored",
    "auditDrained",
    "readersClosed",
  ]) {
    const f = fixture();
    f.input.purpose = "experiment";
    f.input.context.executionId = "ownership.literal";
    f.input.bindingSha256 = f.input.reviewSha256;
    delete f.input.reviewSha256;
    f.input.sources.push({
      path: "C:\\Fixture\\Sealed\\experiment.h",
      sha256: hash,
    });
    const k = verificationFixture(f),
      bridge = identity(10, runnerSid),
      observerHelper = identity(60),
      observerBridge = identity(61, runnerSid),
      observerNonce = "d".repeat(32),
      birth = {
        schemaVersion: 1,
        nonce: observerNonce,
        taskSha256: hash,
        helper: observerHelper,
        bridge: observerBridge,
        status: "POSSIBLE",
      },
      observers = [
        {
          intent: {
            schemaVersion: 1,
            status: "POSSIBLE",
            argumentsHex: ["", "", "", "", "", "", hex(observerNonce)],
          },
          birth,
          result: { ...birth, status: "RETIRED" },
        },
      ],
      records = [
        { phase: "task-register-possible", bridge, taskSha256: "a".repeat(64) },
        { phase: "task-run-possible", bridge, taskSha256: hash },
        {
          phase: "task-parked",
          helper: f.helper,
          bridge,
          taskSha256: hash,
          processDaclSha256: hash,
          instance: { ...instance, enginePid: f.helper.pid },
        },
        {
          phase: "admitted",
          helper: f.helper,
          verifier: f.verifier,
          taskSha256: hash,
        },
        { phase: "helper-start" },
        { phase: "helper-admitted", child: f.fileHelper },
        { phase: "case-account" },
        {
          phase: "finish-possible",
          helper: f.helper,
          verifier: f.verifier,
          nativeEventSha256: hash,
        },
        {
          phase: "finish",
          commandSequence: 12,
          argumentsSha256: observationDigest([]),
        },
        {
          phase: "finish-acknowledged",
          helper: f.helper,
          commandSequence: 12,
          nativeEventSha256: hash,
        },
        {
          phase: "retired",
          helper: f.helper,
          verifier: f.verifier,
          taskSha256: hash,
          nativeEventSha256: hash,
        },
      ];
    if (fault?.startsWith("retained-")) {
      const held = fault === "retained-original" ? f.helper : identity(99);
      if (fault === "retained-foreign")
        k.states.set(held.pid, {
          ...structuredClone(f.process),
          identity: held,
        });
      await k.verifier.retainObservers(f.input, [held]);
    }
    const recoveryStart = k.events.length;
    for (const actor of k.states.values()) actor.retired = true;
    if (fault !== "observer-only") k.states.clear();
    else {
      records.splice(
        records.findIndex(({ phase }) => phase === "finish-acknowledged"),
        1,
      );
      records.pop();
    }
    if (fault?.startsWith("lost-completion")) records.pop();
    k.state.absent = !["task", "lost-completion-task"].includes(fault);
    const acknowledgement = records.findIndex(
        (record) => record.phase === "finish-acknowledged",
      ),
      command = records.findIndex((record) => record.phase === "finish");
    if (fault === "missing-ack") records.splice(acknowledgement, 1);
    if (fault === "duplicate-ack")
      records.splice(acknowledgement, 0, { ...records[acknowledgement] });
    if (["missing-finish", "lost-completion-missing-finish"].includes(fault))
      records.splice(command, 1);
    if (fault === "finish-order")
      [records[command], records[acknowledgement]] = [
        records[acknowledgement],
        records[command],
      ];
    if (fault === "admission-order")
      [records[1], records[3]] = [records[3], records[1]];
    if (fault === "finish-sequence") records[command].commandSequence++;
    if (fault === "task-binding") records.at(-1).taskSha256 = "e".repeat(64);
    if (fault === "birth-binding")
      records.at(-1).helper = { ...f.helper, creationTime: "999" };
    if (fault === "observer-result") delete observers[0].result;
    if (fault === "observer-birth")
      observers[0].result.helper = { ...observerHelper, creationTime: "999" };
    if (fault === "reviewed") {
      delete f.input.purpose;
      f.input.reviewSha256 = f.input.bindingSha256;
      delete f.input.bindingSha256;
    }
    if (["live", "pid-reuse", "lost-completion-live"].includes(fault))
      k.states.set(f.helper.pid, {
        ...f.process,
        identity: {
          ...f.helper,
          creationTime: fault === "pid-reuse" ? "999" : f.helper.creationTime,
        },
        retired: !["live", "lost-completion-live"].includes(fault),
      });
    const refused = new Error("Original census refusal");
    k.state.damage = (operation, frame) => {
      if (operation === "verify-cold-process") {
        if (fault === "incomplete") frame.value.complete = false;
        if (["error-87", "lost-completion-error-87"].includes(fault))
          throw Object.assign(refused, { code: 87 });
      }
      if (operation === "verify-cold-jobs") {
        if (fault === "job-count") frame.value.jobs.pop();
        if (fault === "survivor")
          frame.value.jobs[127] = {
            daclSha256: hash,
            limitFlags: 0x2008,
            processLimit: 32,
            uiRestrictions: 255,
            members: [identity(99)],
          };
      }
      if (
        operation === "verify-case-recover" &&
        Object.hasOwn(frame.value, fault)
      )
        frame.value[fault] = false;
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    const recover = () => k.verifier.recoverCase(f.input, records, observers);
    if (
      fault &&
      !["observer-only", "lost-completion", "retained-original"].includes(fault)
    ) {
      let original;
      await assert.rejects(
        recover,
        (cause) => {
          original = cause;
          return true;
        },
        fault,
      );
      if (["error-87", "lost-completion-error-87"].includes(fault))
        assert.equal(original, refused);
      const count = k.events.length;
      k.state.damage = null;
      await assert.rejects(recover, (cause) => cause === original);
      assert.equal(
        k.events.length,
        count,
        "A refusal cannot fall back or replay observations",
      );
    } else {
      const proof = await recover();
      assert.equal(proof.status, "RETIRED");
      assert.equal(proof.independent, true);
      assert.equal(proof.noLiveMembers, true);
      assert.equal(proof.taskRemoved, true);
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-case-recover")
          .length,
        2,
      );
      assert.ok(
        k.events
          .filter(({ operation }) => operation === "verify-case-recover")
          .every(({ args }) => args.at(-1) === "1"),
      );
    }
    const retains = k.events
      .slice(recoveryStart)
      .filter(({ operation }) => operation === "verify-retain");
    if (!fault || ["lost-completion", "retained-original"].includes(fault)) {
      assert.equal(retains.length, 0);
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-cold-process")
          .length,
        10,
      );
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-cold-jobs")
          .length,
        10,
      );
    }
    if (fault === "observer-only") {
      assert.ok(retains.length > 0);
      assert.ok(retains.every(({ args }) => !["60", "61"].includes(args[0])));
      const first = k.events.findIndex(
        ({ operation }) => operation === "verify-retain",
      );
      assert.ok(
        k.events
          .slice(0, first)
          .some(({ operation }) => operation === "verify-cold-jobs"),
      );
    }
  }
});

test("Windows experiment cold recovery requires the bound pre-setup abort lifecycle instead of completed setup", async () => {
  for (const fault of [
    null,
    "admitted",
    "admitted-verifier",
    "missing-bound",
    "missing-abort",
    "missing-helper-ack",
    "missing-retired",
    "duplicate",
    "order",
    "finish",
    "setup",
    "helper",
    "bridge",
    "task",
    "instance",
    "verifier",
    "error-87",
  ]) {
    const f = fixture();
    f.input.purpose = "experiment";
    f.input.context.executionId = "ownership.literal";
    f.input.bindingSha256 = f.input.reviewSha256;
    delete f.input.reviewSha256;
    f.input.sources.push({
      path: "C:\\Fixture\\Sealed\\experiment.h",
      sha256: hash,
    });
    const k = verificationFixture(f),
      bridge = identity(10, runnerSid),
      parked = {
        helper: f.helper,
        bridge,
        taskSha256: hash,
        processDaclSha256: hash,
        instance: { ...instance, enginePid: f.helper.pid },
      },
      records = [
        { phase: "task-register-possible", bridge, taskSha256: hash },
        { phase: "task-run-possible", bridge, taskSha256: hash },
        { phase: "task-parked", ...parked },
        {
          phase: "pre-setup-bound",
          ...parked,
          verifier: f.verifier,
          nativeEventSha256: hash,
        },
        { phase: "pre-setup-abort-possible", ...parked },
        {
          phase: "pre-setup-helper-retired",
          ...parked,
          nativeEventSha256: hash,
        },
        {
          phase: "retired",
          ...parked,
          nativeEventSha256: hash,
          preSetup: true,
        },
      ];
    k.states.clear();
    k.state.absent = true;
    if (["admitted", "admitted-verifier"].includes(fault))
      records.splice(3, 0, {
        phase: "admitted",
        helper: f.helper,
        verifier: fault === "admitted-verifier" ? f.helper : f.verifier,
        taskSha256: hash,
        nativeEventSha256: hash,
      });
    const missing = {
      "missing-bound": 3,
      "missing-abort": 4,
      "missing-helper-ack": 5,
      "missing-retired": 6,
    }[fault];
    if (missing !== undefined) records.splice(missing, 1);
    if (fault === "duplicate") records.splice(5, 0, { ...records[5] });
    if (fault === "order") [records[3], records[4]] = [records[4], records[3]];
    if (fault === "finish")
      records.splice(5, 0, {
        phase: "finish-acknowledged",
        helper: f.helper,
        commandSequence: 1,
        nativeEventSha256: hash,
      });
    if (fault === "setup") records.splice(5, 0, { phase: "case-account" });
    if (fault === "helper")
      records[5].helper = { ...f.helper, creationTime: "999" };
    if (fault === "bridge")
      records[5].bridge = { ...bridge, creationTime: "999" };
    if (fault === "task") records[6].taskSha256 = "e".repeat(64);
    if (fault === "instance")
      records[5].instance = { ...instance, enginePid: 999 };
    if (fault === "verifier") records[3].verifier = f.helper;
    const refused = Object.assign(
      new Error("Original pre-setup census refused"),
      { code: 87 },
    );
    k.state.damage = (operation, frame) => {
      if (fault === "error-87" && operation === "verify-cold-process")
        throw refused;
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    const recover = () => k.verifier.recoverCase(f.input, records);
    if (fault && fault !== "admitted") {
      let original;
      await assert.rejects(
        recover,
        (cause) => {
          original = cause;
          if (fault === "error-87") assert.equal(cause, refused);
          return true;
        },
        fault,
      );
      const count = k.events.length;
      k.state.damage = null;
      await assert.rejects(recover, (cause) => cause === original);
      assert.equal(
        k.events.length,
        count,
        "Missing acknowledgements cannot retry through cold success",
      );
    } else {
      const proof = await recover();
      assert.equal(proof.status, "RETIRED");
      assert.equal(proof.noLiveMembers, true);
      assert.equal(proof.taskRemoved, true);
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-cold-process")
          .length,
        4,
      );
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-cold-jobs")
          .length,
        4,
      );
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-case-recover")
          .length,
        2,
      );
    }
    assert.ok(!k.events.some(({ operation }) => operation === "verify-retain"));
  }
});

test("Windows experiment custody retains native Job and handle protection requirements", async () => {
  const f = fixture();
  f.input.purpose = "experiment";
  f.input.bindingSha256 = f.input.reviewSha256;
  delete f.input.reviewSha256;
  const header = {
    path: "C:\\Fixture\\Sealed\\experiment.h",
    sha256: digest("experiment header"),
  };
  f.bytes.set(header.path, Buffer.from("experiment header"));
  f.input.sources.push(header);
  const plan = encodeWindowsCustodyPlan({
    purpose: "experiment",
    candidateSha,
    nonce,
    entries: f.entries,
  });
  f.bytes.set(f.input.plan.path, plan);
  f.input.plan.sha256 = digest(plan);
  const mixed = verificationFixture(f);
  delete mixed.observer.verification.input.purpose;
  mixed.observer.verification.input.reviewSha256 =
    mixed.observer.verification.input.bindingSha256;
  delete mixed.observer.verification.input.bindingSha256;
  mixed.observer.verification.input.sources.pop();
  const reviewed = createWindowsCustodyVerifier(mixed.observer, {
    exchange: mixed.exchange,
  });
  await assert.rejects(reviewed.verifyBootstrap(f.input));
  const k = verificationFixture(f);
  await k.verifier.verifyBootstrap(f.input);
  await k.verifier.verifyAdmission(k.admission);
  k.state.damage = (operation, frame) => {
    if (operation === "verify-transfer") frame.value.job.limitFlags |= 0x800;
    return Buffer.from(JSON.stringify(frame) + "\n");
  };
  await assert.rejects(k.verifier.verifyTransfer(k.helperTransfer));
  const bootstrap = f.options.verifyBootstrap;
  f.options.verifyBootstrap = async (...args) => {
    const { reviewSha256, ...seal } = await bootstrap(...args);
    return { ...seal, purpose: "experiment", bindingSha256: reviewSha256 };
  };
  const reader = f.reader();
  await reader.start();
  await reader.open(0);
  await reader.retainProcess(f.process.identity);
  let missing = false;
  f.options.damage = (op, frame) => {
    if (op === "loader" && !missing)
      frame.value.importScope = "private-runtime";
    return frame;
  };
  assert.equal((await reader.loader(0, 0)).importScope, "private-runtime");
  missing = true;
  await assert.rejects(reader.loader(0, 0));
});

test("installed Git admission shares a bounded UCRT and MinGW path predicate", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = /static BOOL installed_git_runtime\([^\n]+\) \{([\s\S]*?)\n\}/u
      .exec(source)[1]
      .replace(/\bL(?=["'])/gu, "")
      .replace("const wchar_t *prefixes[] = {", "const prefixes = [")
      .replace("};", "];")
      .replace("unsigned i", "let i")
      .replace("size_t length", "const length")
      .replace(
        "const wchar_t *leaf = name+2+length, *extension = wcsrchr(leaf, '.');",
        "const leaf = name.slice(2+length), extension = wcsrchr(leaf, '.');",
      )
      .replace("name+2,", "name.slice(2),")
      .replace("*leaf &&", "leaf.length &&"),
    script = new Script(`(function(name){${body}})`),
    find = (text, character, last = false) => {
      const index = last
        ? text.lastIndexOf(character)
        : text.indexOf(character);
      return index < 0 ? null : text.slice(index);
    },
    admitted = script.runInNewContext({
      TRUE: true,
      FALSE: false,
      wcslen: (text) => text.length,
      wcschr: find,
      wcsrchr: (text, character) => find(text, character, true),
      _wcsicmp: (a, b) => (a.toLowerCase() === b.toLowerCase() ? 0 : 1),
      _wcsnicmp: (a, b, length) =>
        a.slice(0, length).toLowerCase() === b.slice(0, length).toLowerCase()
          ? 0
          : 1,
    });
  for (const layout of ["ucrt64", "mingw64"])
    for (const leaf of ["git.exe", "runtime.DLL"])
      assert.equal(
        admitted(`C:\\Program Files\\Git\\${layout}\\bin\\${leaf}`),
        true,
      );
  for (const file of [
    "C:\\Other\\Git\\ucrt64\\bin\\git.exe",
    "C:\\Program Files\\Git\\cmd\\git.exe",
    "C:\\Program Files\\Git\\bin\\git.exe",
    "C:\\Program Files\\Git\\other\\bin\\git.exe",
    "C:\\Program Files\\Git\\ucrt64\\bin-other\\git.exe",
    "C:\\Program Files\\Git\\ucrt64\\bin\\nested\\runtime.dll",
    "C:\\Program Files\\Git\\ucrt64\\bin\\runtime.dll:stream",
    "C:\\Program Files\\Git\\ucrt64\\bin\\runtime:stream.dll",
    "C:\\Program Files\\Git\\ucrt64\\bin\\input.h",
  ])
    assert.equal(admitted(file), false, file);
  for (const section of [
    source.slice(
      source.indexOf("static BOOL stock_entry"),
      source.indexOf("static void stock_security"),
    ),
    source.slice(
      source.indexOf(
        'experimentInput = !strcmp(v[0], "prepare-experiment-input")',
      ),
      source.indexOf(
        "if (snapshot) {",
        source.indexOf(
          'experimentInput = !strcmp(v[0], "prepare-experiment-input")',
        ),
      ),
    ),
  ])
    assert.match(section, /installed_git_runtime\(name\)/u);
});

test("cold account recovery cannot signal a Job reopened by name or remove a surviving principal", async () => {
  const source = await readFile(
    new URL("./custody-reader.c", import.meta.url),
    "utf8",
  );
  const start = source.indexOf(
    "static void recovery_case(unsigned custody, const char *context, const char *caseNonce, BOOL required) {",
  );
  const body = source.slice(start, source.indexOf("int wmain", start));
  assert.ok(start > 0);
  assert.doesNotMatch(
    body,
    /operation_stop_job|TerminateJobObject|TerminateProcess/u,
  );
  assert.ok(
    body.indexOf("need(!members)") < body.indexOf("LsaRemoveAccountRights"),
  );
  assert.match(body, /operation_empty\(job\)/u);
});

test("the actual ownership failure fence covers suspended acquired creators without admitting cleanup", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    body =
      /static void ownership_failure_fence\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
        source,
      )?.[1];
  assert.ok(body);
  const program = new Script(
    `(error) => {${body
      .replace(
        "HANDLE creators[] = {ownership_launcher.hProcess, ownership_owner.hProcess};",
        "const creators = [ownership_launcher.hProcess, ownership_owner.hProcess];",
      )
      .replace("unsigned i", "let i")
      .replace("DWORD waited", "const waited")}}`,
  );
  for (const phase of [
    "unlaunched",
    "launcher-only",
    "both",
    "signaled",
    "failure",
  ]) {
    const calls = [];
    let error = 5;
    program.runInNewContext({
      ownership_launcher: {
        hProcess: phase === "unlaunched" ? null : "launcher",
      },
      ownership_owner: {
        hProcess: ["both", "signaled", "failure"].includes(phase)
          ? "custodian"
          : null,
      },
      case_job: "original-job",
      WAIT_TIMEOUT: 258,
      WAIT_OBJECT_0: 0,
      stderr: {},
      WaitForSingleObject: () => (phase === "signaled" ? 0 : 258),
      TerminateJobObject: (job, code) => {
        assert.equal(job, "original-job");
        assert.equal(code, 126);
        calls.push(job);
        error = 6;
        return phase !== "failure";
      },
      TerminateProcess: (process, code) => {
        assert.equal(code, 126);
        calls.push(process);
        error = 7;
        return phase !== "failure";
      },
      fprintf: () => {},
      fflush: () => {},
      GetLastError: () => error,
      SetLastError: (value) => {
        error = value;
      },
    })(5);
    assert.equal(error, 5);
    assert.deepEqual(
      calls,
      phase === "unlaunched"
        ? []
        : phase === "signaled"
          ? ["original-job"]
          : phase === "launcher-only"
            ? ["original-job", "launcher"]
            : ["original-job", "launcher", "custodian"],
    );
  }
});

test("the actual ownership producer transfers original process/token custody before publishing a birth", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = /static void ownership_birth_save\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(body);
  const program = new Script(
    `(leaf, process, token) => {${body
      .replace("struct ownership_birth birth = {0};", "const birth = {};")
      .replace(
        "FILETIME created, ended, kernel, user;",
        "const created = {}, ended = {}, kernel = {}, user = {};",
      )
      .replace("TOKEN_STATISTICS *statistics", "const statistics")
      .replaceAll("statistics->", "statistics.")
      .replaceAll("*token", "token.value")
      .replace(/&(created|ended|kernel|user)\b/gu, "$1")
      .replace(
        /&birth\.(process|token)\b/gu,
        (_, field) => `{set value(v){birth.${field}=v}}`,
      )
      .replace("(BYTE *)&birth", "birth")
      .replaceAll("(ULONGLONG)", "")
      .replace("sizeof(birth)", "1")}}`,
  );
  for (const failure of [null, "token", "process-transfer", "token-transfer"]) {
    const calls = [],
      transferred = new Map();
    let published;
    const run = () =>
      program.runInNewContext({
        ownership_observer: "admitted-observer",
        ownership_observer_birth: 90,
        TOKEN_QUERY: 8,
        TOKEN_DUPLICATE: 2,
        TokenStatistics: 1,
        PROCESS_QUERY_INFORMATION: 0x400,
        PROCESS_VM_READ: 16,
        READ_CONTROL: 0x20000,
        SYNCHRONIZE: 0x100000,
        FALSE: false,
        case_custody: 2,
        need: assert.ok,
        system_process: () => true,
        GetCurrentProcess: () => "creator",
        GetProcessTimes: (_process, created) => {
          Object.assign(created, { dwHighDateTime: 0, dwLowDateTime: 91 });
          return true;
        },
        GetProcessId: (process) => (process === "original-process" ? 20 : 10),
        OpenProcessToken: (process, _access, output) => {
          assert.equal(process, "original-process");
          calls.push("acquire-token");
          output.value = "original-token";
          return failure !== "token";
        },
        token_info: (token) => {
          assert.equal(token, "original-token");
          return { TokenId: "original-token-id" };
        },
        free: () => {},
        DuplicateHandle: (
          creator,
          original,
          observer,
          output,
          access,
          inherit,
        ) => {
          assert.equal(creator, "creator");
          assert.equal(observer, "admitted-observer");
          assert.equal(inherit, false);
          const kind =
            original === "original-process"
              ? "process-transfer"
              : "token-transfer";
          calls.push(kind);
          if (failure === kind) return false;
          assert.equal(access, kind === "token-transfer" ? 10 : 0x120410);
          output.value = kind;
          transferred.set(kind, original);
          return true;
        },
        operation_record: (leaf, custody, birth) => {
          assert.equal(leaf, "ownership-launcher.birth");
          assert.equal(custody, 2);
          assert.equal(transferred.size, 2);
          assert.equal(birth.observer, 10);
          assert.equal(birth.observerCreation, 90);
          assert.equal(birth.pid, 20);
          assert.equal(birth.creation, 91);
          assert.equal(birth.tokenId, "original-token-id");
          published = true;
          calls.push("publish");
        },
      })("ownership-launcher.birth", "original-process", {});
    if (failure) assert.throws(run, undefined, failure);
    else run();
    assert.equal(!!published, !failure);
    if (!failure)
      assert.deepEqual(calls, [
        "acquire-token",
        "process-transfer",
        "token-transfer",
        "publish",
      ]);
  }
});

test("the actual birth import admits only the original observer and transferred process/token pair", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    start = source.indexOf("    struct ownership_birth *birth = &births[i];"),
    end = source.indexOf("    slots[i] = index;", start),
    body = source
      .slice(start, end + "    slots[i] = index;".length)
      .replace(
        "struct ownership_birth *birth = &births[i];",
        "const birth = record;",
      )
      .replace("TOKEN_STATISTICS *statistics", "const statistics")
      .replace("wchar_t *sid", "const sid")
      .replace("DWORD *session", "const session")
      .replaceAll("->", ".")
      .replaceAll('L"', '"')
      .replaceAll("!*session", "!session.value")
      .replace(
        /&(created|ended|kernel|user|statistics\.TokenId|birth\.tokenId)\b/gu,
        "$1",
      )
      .replaceAll("(ULONGLONG)", "")
      .replace("sizeof(LUID)", "1")
      .replaceAll("unsigned ", "let "),
    program = new Script(`(record) => {${body} return slots[i];}`);
  assert.ok(start > 0 && end > start);
  for (const fault of [
    null,
    "observer",
    "observer-birth",
    "process-type",
    "process-birth",
    "token-id",
    "sid",
    "session",
    "alias",
  ]) {
    const processes = [],
      tokens = [],
      sessions = [],
      context = {
        process_count: 0,
        processes,
        tokens,
        sessions,
        i: 0,
        slots: [],
        observerBirth: 90,
        created: {},
        ended: {},
        kernel: {},
        user: {},
        TokenStatistics: 1,
        TokenSessionId: 2,
        need: assert.ok,
        GetCurrentProcessId: () => 10,
        object_type: (handle, type) =>
          handle === (type === "Process" ? "process" : "token") &&
          fault !== "process-type",
        GetProcessId: () => 20,
        GetProcessTimes: (_process, created) => {
          Object.assign(created, {
            dwHighDateTime: 0,
            dwLowDateTime: fault === "process-birth" ? 92 : 91,
          });
          return true;
        },
        OpenProcessToken: assert.fail,
        token_info: (_token, kind) =>
          kind === 1
            ? { TokenId: fault === "token-id" ? "changed" : "original" }
            : { value: fault === "session" ? 1 : 0 },
        token_sid: () => (fault === "sid" ? "S-1-5-19" : "S-1-5-18"),
        memcmp: (a, b) => Number(a !== b),
        wcscmp: (a, b) => Number(a !== b),
        free: () => {},
        LocalFree: () => {},
      },
      record = {
        pid: 20,
        creation: 91,
        observer: fault === "observer" ? 11 : 10,
        observerCreation: fault === "observer-birth" ? 89 : 90,
        process: "process",
        token: "token",
        tokenId: "original",
      },
      run = program.runInNewContext(context);
    if (fault === "alias") {
      context.process_count = 1;
      processes[0] = "different-process-handle";
      tokens[0] = "different-token-handle";
    }
    if (fault) assert.throws(() => run(record), undefined, fault);
    else {
      assert.equal(run(record), 0);
      assert.equal(run(record), 0);
      assert.equal(context.process_count, 1);
      assert.deepEqual(processes, ["process"]);
      assert.deepEqual(tokens, ["token"]);
      assert.deepEqual(sessions, [0]);
    }
  }
});

test("actual provisioning retirement closes proven token and Job subsets before removing the account", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = /static void case_retire\(void\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(body);
  const program = new Script(
    body
      .replace("struct case_account_record held = {0};", "const held = {};")
      .replace("wchar_t name[21];", "const name = {};")
      .replace("PSID user;", "let user;")
      .replace(
        "LSA_OBJECT_ATTRIBUTES attributes = {0};",
        "const attributes = {};",
      )
      .replace("LSA_HANDLE policy;", "let policy;")
      .replace(
        "JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = {0};",
        "const accounting = {};",
      )
      .replaceAll("&accounting", "accounting")
      .replace(/\b(?:BOOL|DWORD)\b/gu, "const")
      .replaceAll("(unsigned)", "")
      .replaceAll("unsigned i", "let i")
      .replace(/sizeof\(\w+\)/gu, "1")
      .replaceAll("&held", "held")
      .replaceAll("&case_record", "case_record")
      .replaceAll("&attributes", "attributes")
      .replace(/&(user|policy)\b/gu, (_, name) => `{set value(v){${name}=v}}`)
      .replaceAll('L"', '"'),
  );
  for (const subset of ["token", "job", "both"])
    for (const failure of [null, "close", "rights", "query", "history"]) {
      const calls = [],
        api = {
          case_token: subset === "job" ? null : "token",
          case_job: subset === "token" ? null : "job",
          helpers: [{ process: null }, { process: null }],
          audit_owned: false,
          entries: [{ path: "custody" }],
          case_custody: 0,
          case_record: {
            nonce: "c".repeat(32),
            accountSid: "S-1-5-21-1-2-3-1001",
          },
          case_sockets: [],
          case_socket_count: 0,
          NULL: null,
          TRUE: true,
          POLICY_LOOKUP_NAMES: 1,
          NERR_Success: 0,
          need: assert.ok,
          account_record: () => {},
          memcmp: () => 0,
          JobObjectBasicAccountingInformation: 1,
          ERROR_SUCCESS: 0,
          ERROR_INVALID_DATA: 13,
          stderr: "stderr",
          SetLastError: () => {},
          GetLastError: () => 5,
          fprintf: () => {},
          fflush: () => {},
          QueryInformationJobObject: (job, _kind, accounting) => {
            assert.equal(job, "job");
            calls.push("unused-job");
            accounting.ActiveProcesses = 0;
            accounting.TotalProcesses = failure === "history" ? 1 : 0;
            return failure !== "query";
          },
          recovery_principal_empty: () => calls.push("census"),
          swprintf_s: () => 1,
          account_check: () => calls.push("account-check"),
          closesocket: assert.fail,
          WSACleanup: assert.fail,
          CloseHandle: (handle) => {
            calls.push("close-" + handle);
            return failure !== "close";
          },
          ConvertStringSidToSidW: (_sid, out) => {
            out.value = "sid";
            return true;
          },
          LsaOpenPolicy: (_server, _attributes, _access, out) => {
            out.value = "policy";
            return 0;
          },
          LsaRemoveAccountRights: () => {
            calls.push("rights");
            return failure === "rights" ? 5 : 0;
          },
          LsaClose: () => {
            calls.push("close-policy");
            return 0;
          },
          LocalFree: () => {},
          NetUserDel: () => {
            calls.push("delete-account");
            return 0;
          },
          printf: () => calls.push("retired"),
        };
      const refused =
        failure &&
        (subset !== "token" || !["query", "history"].includes(failure));
      if (refused) assert.throws(() => program.runInNewContext(api));
      else program.runInNewContext(api);
      assert.equal(calls.includes("retired"), !refused);
      assert.equal(calls.includes("unused-job"), subset !== "token");
      if (!refused) {
        assert.ok(calls.indexOf("census") < calls.indexOf("rights"));
        assert.ok(
          calls.indexOf("close-" + (subset === "token" ? "token" : "job")) <
            calls.indexOf("rights"),
        );
        assert.ok(
          calls.indexOf("close-policy") < calls.indexOf("delete-account"),
        );
        assert.equal(api.case_token, null);
        assert.equal(api.case_job, null);
      } else assert.ok(!calls.includes("delete-account"));
    }
});

test("actual reconstruction retains the held Job identity through an unlaunched fence", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    start = source.indexOf(
      '} else if (!strcmp(values[0], "ownership-reconstruct")) {',
    ),
    body = source
      .slice(source.indexOf("\n", start), source.indexOf("BYTE bytes[", start))
      .replace("static char jobPin[65];", 'const jobPin = {text: ""};'),
    fresh = source
      .split("\n")
      .find((line) =>
        line.includes("strcpy_s(view.payloadPin, 65, entries[6].pin)"),
      );
  assert.ok(start > 0 && fresh);
  const pin = "a".repeat(64),
    calls = [],
    result = new Script(
      `(() => {${body}} case_job = NULL; ${fresh} return view.jobPin.text;})()`,
    ).runInNewContext({
      case_job: "original-job",
      case_token: "token",
      n: 2,
      NULL: null,
      ownership_last_job_pin: { text: "" },
      view: { payloadPin: {}, jobPin: {} },
      entries: Array.from({ length: 7 }, () => ({ pin: "payload" })),
      need: assert.ok,
      ownership_job_pin: (job, output) => {
        assert.equal(job, "original-job");
        calls.push(job);
        output.text = pin;
      },
      strcpy_s: (output, _size, input) => {
        output.text = input.text ?? input;
      },
    });
  assert.equal(result, pin);
  assert.deepEqual(calls, ["original-job"]);
});

test("the actual shared witness scopes unchanged-policy evidence to a captured ownership baseline", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    census = source.indexOf("  ownership_census(&view);"),
    start = source.indexOf("\n", census),
    end = source.indexOf("  BOOL launcherSignaled =", start),
    claim =
      /view\.restored \? "true" : "false", ([^?\n]+) \? "true" : "false", suspended/u.exec(
        source,
      )?.[1];
  assert.ok(census > 0 && start > census && end > start && claim);
  const body = source
      .slice(start, end)
      .replace("BOOL baselineOwned", "const baselineOwned")
      .replace("unsigned i", "let i")
      .replace("char hash[65];", 'const hash = {text: ""};')
      .replace("&entries[i+1].file.id", "entries[i+1].file.id")
      .replace("sizeof(FILE_ID_INFO)", "1"),
    program = new Script(`(view) => {${body} return ${claim};}`);
  for (const phase of [
    "access-before-launch",
    "ownership-before-launch",
    "ownership-partial",
    "ownership-restored",
    "access",
    "missing-baseline",
    "changed-baseline",
    "incomplete-baseline",
  ]) {
    const reads = [],
      captured = ![
        "access-before-launch",
        "access",
        "missing-baseline",
      ].includes(phase),
      text = "a".repeat(64),
      baseline = Array.from({ length: 6 }, (_, i) => {
        const value =
          captured && !(phase === "incomplete-baseline" && i === 4) ? text : "";
        return { 0: value ? 97 : 0, text: value };
      }),
      view = {
        files: Array.from({ length: 6 }, (_, i) => i),
        baseline,
        access: phase === "access",
        installed: false,
        restored: ["ownership-restored", "missing-baseline"].includes(phase),
        possible: phase === "ownership-partial",
      },
      run = () =>
        program.runInNewContext({
          view,
          entries: Array.from({ length: 7 }, () => ({ file: { id: {} } })),
          FileIdInfo: 1,
          SE_FILE_OBJECT: 1,
          TRUE: true,
          FALSE: false,
          GetFileInformationByHandleEx: () => true,
          security: () => {},
          need: assert.ok,
          strlen: (value) => value.text.length,
          strcmp: (a, b) => Number(a.text !== b.text),
          ownership_baseline_read: (i, hash) => {
            reads.push(i);
            hash.text = phase === "changed-baseline" ? "b".repeat(64) : text;
          },
          ownership_acl: assert.fail,
          ownership_network: assert.fail,
          ownership_network_absent: () => reads.push("filters-absent"),
        })(view);
    if (
      ["missing-baseline", "changed-baseline", "incomplete-baseline"].includes(
        phase,
      )
    )
      assert.throws(run, undefined, phase);
    else {
      assert.equal(
        run(),
        ["ownership-before-launch", "ownership-restored"].includes(phase),
        phase,
      );
      assert.deepEqual(
        reads,
        captured && !view.possible ? [0, 1, 2, 3, 4, 5, "filters-absent"] : [],
        phase,
      );
    }
  }
});

test("the actual ownership cwd join accepts directory spelling equivalence and preserves bounded refusals", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = (name) =>
      new RegExp(
        `static (?:BOOL|void) ${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)[1],
    translate = (text) =>
      text
        .replace(
          "void *params = NULL; UNICODE_STRING current = {0}; wchar_t path[4096], expected[4096];",
          "var params, current = {Length:0,MaximumLength:0}, path=[],expected=[];",
        )
        .replace(/sizeof\((path|expected)\)/gu, "8192")
        .replace("sizeof(params)", "8")
        .replace("sizeof(current)", "16")
        .replace("sizeof(wchar_t)", "2")
        .replace("&params", "{set value(value){params=value}}")
        .replace("&current", "current")
        .replace("&read", "value=>read=value")
        .replaceAll(/\((?:const )?BYTE \*\)/gu, "")
        .replace("expected+4", "expected.slice(4)")
        .replaceAll("L':'", "58")
        .replaceAll("L'\\\\'", "92")
        .replaceAll('L"', '"')
        .replace(/const (?:char|void) \*/gu, "var ")
        .replace(/void \*/gu, "var ")
        .replace(/\b(?:unsigned|SIZE_T|BOOL|DWORD) /gu, "var ")
        .replaceAll("goto refused;", "break cwd_body;")
        .replace("refused:", "}"),
    invocation = source.match(/ownership_cwd\(view\.processes[^;]+;/u)?.[0];
  assert.ok(invocation);
  const program =
      new Script(`function ownership_cwd_unicode(path,length){${translate(body("ownership_cwd_unicode"))}}
    function ownership_cwd(process,peb,directory){cwd_body:{${translate(body("ownership_cwd"))}}
    ${invocation}`),
    work = "C:\\fixture\\work",
    units = (text) =>
      Array.from({ length: text.length }, (_, i) => text.charCodeAt(i)),
    compare = (a, b, n) =>
      Number(
        String.fromCharCode(...a.slice(0, n)).toLowerCase() !==
          String.fromCharCode(...b.slice(0, n)).toLowerCase(),
      );
  assert.notEqual(work.toLowerCase(), (work + "\\").toLowerCase());
  const cases = [
    [{}],
    [{ path: work.toUpperCase() }],
    [{ path: work + "\\" }],
    [{ final: work + "\\" }],
    [{ path: work + "😀", final: work + "😀" }],
    [{ path: "C:\\", final: "C:\\" }],
    [{ MaximumLength: work.length * 2 }],
    [{ MaximumLength: 65534 }],
    ...[
      work + "-sibling",
      "C:\\fixture\\peer",
      work + "\\\\",
      "C:\\fixture\\wor",
    ].map((path) => [{ path }, "mismatch"]),
    [{ path: "C:\\\\", final: "C:\\" }, "mismatch"],
    ...[0, 3, 8192, 8194].map((Length) => [{ Length }, "length-bounds"]),
    ...[2, work.length * 2 + 1].map((m) => [
      { MaximumLength: m },
      "length-bounds",
    ]),
    ...["\ud800", "\udc00", "\ud800x", "\0hidden"].map((s) => [
      { path: work + s },
      "observed-unicode",
    ]),
    ...["\ud800", "\udc00", "\0hidden"].map((s) => [
      { final: work + s },
      "final-path-unicode",
    ]),
    ...["parameters-read", "directory-read", "path-read"].flatMap(
      (operation, read) => [
        [{ read }, operation],
        [{ read, api: true }, operation, 5],
      ],
    ),
    [{ query: 0 }, "final-path-query", 87],
    ...[4, 4096, 4097].map((query) => [{ query }, "final-path-bounds"]),
    [{ unterminated: true }, "final-path-bounds"],
    ...["", "\\\\.\\", "\\\\??\\"].map((p) => [
      { prefix: p },
      "final-path-prefix",
    ]),
  ];
  for (const [fault, operation, error = 0] of cases) {
    const path = units(fault.path ?? work),
      size = path.length * 2,
      final = units((fault.prefix ?? "\\\\?\\") + (fault.final ?? work)),
      diagnostics = [];
    let stage = 0,
      queries = 0,
      lastError = 999;
    const run = () =>
      program.runInNewContext({
        view: {
          processes: ["original-process"],
          files: [null, null, null, "held-workspace"],
        },
        info: { PebBaseAddress: 100 },
        TRUE: true,
        FALSE: false,
        stderr: 2,
        FILE_NAME_NORMALIZED: 0,
        VOLUME_NAME_DOS: 0,
        ReadProcessMemory(process, address, target, wanted, read) {
          assert.equal(process, "original-process");
          assert.equal(address, [132, 256, 300][stage]);
          if (stage === 0) target.value = 200;
          else if (stage === 1)
            Object.assign(
              target,
              { Buffer: 300, Length: size, MaximumLength: size + 2 },
              fault,
            );
          else path.forEach((unit, i) => (target[i] = unit));
          read(wanted - Number(stage === fault.read));
          lastError = 5;
          return !(stage++ === fault.read && fault.api);
        },
        GetFinalPathNameByHandleW(directory, target, capacity) {
          assert.equal(directory, "held-workspace");
          assert.equal(capacity, 4096);
          queries++;
          final.forEach((unit, i) => (target[i] = unit));
          if (!fault.unterminated) target[final.length] = 0;
          lastError = 87;
          return fault.query ?? final.length;
        },
        memset(target) {
          target.length = 4096;
          target.fill(0xffff);
        },
        wmemcmp: (a, b, n) => compare(a, units(b), n),
        _wcsnicmp: compare,
        GetLastError: () => lastError,
        SetLastError: (value) => (lastError = value),
        fprintf: (_stream, _format, ...values) => {
          diagnostics.push(values);
          lastError = 777;
        },
        fflush: () => (lastError = 888),
        need(ok) {
          if (!ok) throw lastError;
        },
      });
    if (operation) {
      assert.throws(run, (cause) => cause === error, JSON.stringify(fault));
      assert.equal(diagnostics[0][0], operation);
      assert.equal(diagnostics[0][7], error);
      if (fault.query !== undefined)
        assert.equal(diagnostics[0][4], fault.query);
      if (fault.read !== undefined)
        assert.equal(diagnostics[0][2], diagnostics[0][3] - 1);
    } else {
      run();
      assert.equal(stage, 3);
      assert.equal(queries, 1);
      assert.deepEqual(diagnostics, []);
    }
    assert.ok(queries <= 1);
  }
});

test("actual ownership restoration distinguishes an untouched baseline from possible or installed policy", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    start = source.indexOf(
      '} else if (!strcmp(values[0], "ownership-restore")) {',
    ),
    end = source.indexOf(
      '} else if (!strcmp(values[0], "ownership-account-retire")) {',
      start,
    ),
    body = source
      .slice(start, end)
      .slice(source.slice(start, end).indexOf("\n"))
      .replaceAll("unsigned i", "let i")
      .replaceAll("char hash[65];", 'const hash = {value: ""};')
      .replaceAll("&ownership_policy_file", "ownership_policy_file"),
    program = new Script(`${body}\nownership_policy_restored;`);
  assert.ok(start > 0 && end > start);
  for (const fault of [
    null,
    "possible",
    "changed",
    "missing-baseline",
    "installed",
    "live-job",
    "filters",
    "close",
  ]) {
    const calls = [],
      baseline = Array(6).fill("a".repeat(64)),
      api = {
        n: 2,
        case_job: fault === "live-job" ? "job" : null,
        ownership_policy_installed: ["installed", "close"].includes(fault),
        ownership_policy_possible: fault === "possible",
        ownership_policy_restored: false,
        ownership_policy_file: {},
        ownership_before: Array(6).fill("before"),
        ownership_installed: Array(6).fill("wanted"),
        ownership_baseline: baseline,
        TRUE: true,
        FALSE: false,
        NULL: null,
        need: assert.ok,
        strlen: (value) => value.length,
        strcmp: (a, b) => Number((a.value ?? a) !== (b.value ?? b)),
        LocalFree: () => {},
        ownership_network_absent: () => {
          calls.push("absent");
          assert.notEqual(fault, "filters");
        },
        ownership_baseline_read: (index, hash) => {
          calls.push("baseline-" + index);
          hash.value =
            fault === "changed" && index === 4
              ? "b".repeat(64)
              : "a".repeat(64);
        },
        ownership_network: (remove, observe) => {
          calls.push(remove ? "remove" : "inspect-network");
          assert.equal(observe, !remove);
        },
        ownership_acl: (index, restore, inspect) => {
          calls.push((restore ? "restore-" : "inspect-") + index);
          assert.equal(inspect, !restore);
        },
        close_file: () => {
          calls.push("close-policy");
          assert.notEqual(fault, "close");
        },
        printf: () => calls.push("restored"),
      };
    if (fault === "missing-baseline") baseline[0] = "";
    if (fault && fault !== "installed")
      assert.throws(() => program.runInNewContext(api), undefined, fault);
    else assert.equal(program.runInNewContext(api), true);
    assert.equal(
      calls.includes("restored"),
      !fault || fault === "installed",
      fault,
    );
    if (!fault)
      assert.deepEqual(calls, [
        "absent",
        ...Array.from({ length: 6 }, (_, i) => "baseline-" + i),
        "restored",
      ]);
    if (fault === "possible") assert.deepEqual(calls, []);
    if (fault === "installed")
      assert.ok(
        calls.indexOf("inspect-5") < calls.indexOf("remove") &&
          calls.indexOf("remove") < calls.indexOf("restore-0") &&
          calls.indexOf("restore-5") < calls.indexOf("close-policy"),
      );
  }
});

test("the native ownership error drain preserves launcher facts through fragmented control refusal and EOF", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = /static BOOL ownership_failure_write\([^\n]+\) \{([\s\S]*?)\n\}/u
      .exec(source)[1]
      .replace("BYTE bytes[4096];", "const bytes=Buffer.alloc(4096);")
      .replace(
        "char frame[9216], encoded[8193];",
        'const frame={text:""},encoded={text:""};',
      )
      .replaceAll("sizeof(bytes)", "bytes.length")
      .replaceAll("sizeof(frame)", "9216")
      .replaceAll("sizeof(encoded)", "8193")
      .replaceAll("bytes+total", "bytes.subarray(total)")
      .replaceAll("encoded+i*2", "{target:encoded,offset:i*2}")
      .replace(/\(DWORD\)/gu, "")
      .replace(/\b(?:BOOL|DWORD|int)\b/gu, "let")
      .replace(/&(available|used)\b/gu, "value=>$1=value");
  for (const fault of [
    null,
    "read",
    "peek",
    "pending",
    "bound",
    "empty",
    "released",
    "other-command",
  ]) {
    const raw =
        fault === "bound"
          ? "x".repeat(4097)
          : fault === "empty"
            ? ""
            : "native-windows-api: operation=CreateProcessAsUserW last-error=5\nnative-windows-guard: file=launcher.c line=321 last-error=5\n",
      writes = [];
    let remaining = Buffer.from(raw),
      error = 109,
      reads = 0;
    const api = {
      Buffer,
      FALSE: false,
      TRUE: true,
      NULL: null,
      ERROR_BROKEN_PIPE: 109,
      ownership_output: "launcher-error",
      ownership_released: fault === "released",
      source: "custody.h",
      line: 421,
      error: 109,
      sequence: 32,
      reader_command:
        fault === "other-command" ? "verify-retain" : "ownership-control",
      control: "control",
      STD_ERROR_HANDLE: 2,
      strncmp: (a, b, length) =>
        a.slice(0, length) === b.slice(0, length) ? 0 : 1,
      GetLastError: () => error,
      SetLastError: (value) => {
        error = value;
      },
      GetStdHandle: () => "stderr",
      PeekNamedPipe: (_, __, ___, ____, available) => {
        if (!remaining.length && fault === "pending") {
          available(0);
          return true;
        }
        if (!remaining.length || (fault === "peek" && reads)) {
          error = fault === "peek" ? 87 : 109;
          return false;
        }
        available(remaining.length);
        return true;
      },
      ReadFile: (_, out, maximum, used) => {
        if (fault === "read" && reads) {
          error = 5;
          return false;
        }
        const size = Math.min(maximum, 17, remaining.length);
        remaining.copy(out, 0, 0, size);
        remaining = remaining.subarray(size);
        used(size);
        reads++;
        return true;
      },
      sprintf_s: (out, maximum, format, ...args) => {
        let i = 0;
        const text = format.replace(/%(?:02)?l?[usx]/gu, (specifier) => {
          const value = args[i++];
          return specifier === "%02x"
            ? value.toString(16).padStart(2, "0")
            : String(value?.text ?? value);
        });
        assert.ok(text.length < maximum);
        if (out.target)
          out.target.text = out.target.text.slice(0, out.offset) + text;
        else out.text = text;
        return text.length;
      },
      WriteFile: (handle, bytes, size, used) => {
        writes.push({
          handle,
          data: Buffer.isBuffer(bytes)
            ? bytes.subarray(0, size)
            : Buffer.from(bytes.text.slice(0, size)),
        });
        used(size);
        return true;
      },
    };
    const observed = new Script(`(function(){${body}})()`).runInNewContext(api);
    assert.equal(error, 109);
    if (["empty", "released", "other-command"].includes(fault)) {
      assert.equal(observed, false);
      assert.deepEqual(writes, []);
      continue;
    }
    assert.equal(observed, true);
    const frame = JSON.parse(writes[0].data.subarray(1)),
      expected =
        fault === "bound"
          ? raw.slice(0, 4096)
          : ["read", "peek"].includes(fault)
            ? raw.slice(0, 17)
            : raw;
    assert.equal(frame.launcher.hex, Buffer.from(expected).toString("hex"));
    assert.equal(frame.launcher.complete, !fault);
    assert.equal(writes[1].data.toString(), expected);
    assert.equal(frame.lastError, 109);
    const f = transport(),
      pending = f.channel.receive().catch((cause) => cause),
      completion = f.channel.completion.catch((cause) => cause);
    try {
      f.child.stdout.write('{"sequence":32,"value":');
      for (let offset = 0; offset < writes[0].data.length; offset += 113)
        f.child.stdout.write(writes[0].data.subarray(offset, offset + 113));
      const original = await pending;
      assert.deepEqual(original.custodyReaderFailure, frame);
      f.child.stdout.end();
      f.child.emit("close", 126, null);
      assert.equal(await completion, original);
      await assert.rejects(f.channel.receive(), (cause) => cause === original);
    } finally {
      f.channel.close();
      f.child.stdin.destroy();
      f.child.stdout.destroy();
      f.child.stderr.destroy();
    }
  }
});

test("original-child diagnostics use the actual guard and immediate authenticated pipe before fatal rejection", async () => {
  const [source, header, bridge] = await Promise.all(
    ["custody-reader.c", "custody.h", "custody-bridge.c"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const body = (text, name) =>
    new RegExp(
      `static void ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(text)[1];
  const project = (text) =>
    text
      .replace(/#ifdef NATIVE_CUSTODY_FAILURE\n([\s\S]*?)#endif/u, "$1")
      .replaceAll("NATIVE_CUSTODY_FAILURE", "reader_failure")
      .replace(/const char \*source[^\n]+/u, "const source=basename(file);")
      .replace("char frame[65536];", "const frame=[];")
      .replace(
        'const char digits[]="0123456789abcdef";',
        'const digits=Buffer.from("0123456789abcdef");',
      )
      .replace(
        'char bytes[1024], transfer[256] = "";',
        "const bytes=[],transfer=[];",
      )
      .replaceAll("frame+size", "{target:frame,offset:size}")
      .replaceAll("sizeof(frame)", "65536")
      .replaceAll("sizeof(bytes)", "1024")
      .replaceAll("sizeof(transfer)", "256")
      .replace(
        /&(mode|written)\b/gu,
        (_, name) => `{get value(){return ${name}},set value(v){${name}=v}}`,
      )
      .replace(/\((?:DWORD|BYTE|void)\)/gu, "")
      .replace(/\b(?:DWORD|BYTE|int) /gu, "let ")
      .replaceAll("\\035", "\\x1d")
      .replaceAll("\\036", "\\x1e");
  const script = new Script(`
    function refusal_transport(output,used){${project(body(source, "refusal_transport"))}}
    function reader_failure(file,line,error){${project(body(source, "reader_failure"))}}
    function guard(ok,file,line){${project(body(header, "need_at"))}}
    ({guard,transport:refusal_transport});`);
  // The existing bridge relays private-pipe bytes unchanged; it neither parses
  // diagnostics nor supplies a second wait budget for their delivery.
  assert.match(
    bridge,
    /WriteFile\(GetStdHandle\(STD_OUTPUT_HANDLE\), bytes, used, &written, NULL\)/u,
  );
  assert.match(
    source,
    /CreateFileW\(argv\[5\], GENERIC_READ \| GENERIC_WRITE/u,
  );
  assert.match(source, /_dup2\(fd, _fileno\(stdout\)\)/u);
  for (const fault of [
    null,
    "coalesced",
    "mode",
    "write",
    "short-write",
    "format",
    "oversize",
    "maximum",
    "sink",
  ]) {
    const f = transport(),
      frames = [],
      events = [],
      raw = [],
      exited = {};
    let error = 109,
      modeCalls = 0,
      native;
    const refusal = {
      phase: "reader-failure",
      sequence: 46,
      command: "ownership-output",
      source: "custody.h",
      line: 421,
      lastError: 109,
    };
    const context =
      "native-windows-original-child: context command=ownership-output sequence=46 source=custody.h line=421 error=109 candidate=" +
      "a".repeat(40) +
      " nonce=" +
      "b".repeat(32) +
      " pid=43 birth=90 resume-time=unavailable\n";
    const ending =
      "native-windows-original-child: completion finished=1 incomplete=0 empty=1\n";
    let output = Buffer.from(context + ending);
    if (["maximum", "oversize"].includes(fault)) {
      const padding =
        32256 -
        output.length -
        "native-windows-original-child: record \n".length;
      output = Buffer.from(
        context +
          "native-windows-original-child: record " +
          "x".repeat(padding + Number(fault === "oversize")) +
          "\n" +
          ending,
      );
    }
    const api = {
      Buffer,
      control: 7,
      NULL: null,
      PIPE_READMODE_BYTE: 0,
      PIPE_NOWAIT: 1,
      reader_diagnostics_ready: true,
      sequence: 46,
      reader_command: "ownership-output",
      reader_transfer: { active: false },
      signature_trust: { active: false },
      stderr: 2,
      original_refusal: { tried: false },
      basename: (file) =>
        file.slice(Math.max(file.lastIndexOf("\\"), file.lastIndexOf("/")) + 1),
      GetLastError: () => error,
      SetLastError: (value) => {
        error = value;
      },
      SetNamedPipeHandleState(handle, mode, count, timeout) {
        assert.deepEqual(
          [handle, mode.value, count, timeout],
          [7, 1, null, null],
        );
        assert.equal(api.original_refusal.error, 109);
        events.push("mode");
        modeCalls++;
        error = 5;
        return fault !== "mode";
      },
      refusal_settle: () => {},
      ownership_refusal_collect(source, line, value) {
        if (api.original_refusal.tried) return;
        Object.assign(api.original_refusal, {
          tried: true,
          sequence: 46,
          command: "ownership-output",
          source,
          line,
          error: value,
        });
        events.push("collect");
        native.transport(output, output.length);
      },
      reader_witness_failure: () => false,
      ownership_failure_write: () => false,
      ownership_failure_fence(value) {
        events.push("fence");
        error = value;
      },
      reader_cold_failure: () => false,
      reader_baseline_failure: () => false,
      reader_scheduler_failure: () => false,
      reader_open_failure: () => false,
      reader_context_failure: () => false,
      sprintf_s(target, maximum, format, ...values) {
        if (fault === "format" && format.startsWith("\x1d")) return -1;
        let index = 0;
        const text = format.replace(/%(?:lu|u|s)/gu, () => {
          const value = values[index++];
          return Array.isArray(value)
            ? Buffer.from(value).toString()
            : String(value);
        });
        assert.equal(index, values.length);
        assert.ok(text.length < maximum);
        Buffer.from(text).forEach((byte, i) => {
          target[i] = byte;
        });
        return text.length;
      },
      memcpy(out, input, size) {
        const target = out.target ?? out,
          offset = out.offset ?? 0;
        Buffer.from(input)
          .subarray(0, size)
          .forEach((byte, i) => {
            target[offset + i] = byte;
          });
      },
      WriteFile(handle, bytes, size, used, overlapped) {
        assert.equal(handle, 7);
        assert.equal(overlapped, null);
        const frame = Buffer.from(bytes).subarray(0, size),
          diagnostic = frame[0] === 0x1d;
        assert.ok(size <= (diagnostic ? 65536 : 1024));
        error = 87;
        events.push(diagnostic ? "diagnostic-write" : "fatal-write");
        used.value =
          diagnostic && fault === "write"
            ? 0
            : diagnostic && fault === "short-write"
              ? Math.floor(size / 2)
              : size;
        frames.push(frame.subarray(0, used.value));
        return used.value > 0;
      },
      fprintf() {
        events.push("unavailable-stderr");
        return -1;
      },
      fflush: () => -1,
      ExitProcess(code) {
        assert.equal(code, 126);
        throw exited;
      },
    };
    native = script.runInNewContext(api);
    const pending = f.channel.receive().catch((cause) => cause),
      completion = f.channel.completion.catch((cause) => cause);
    f.child.stdin.once("close", () => events.push("disposed"));
    try {
      await withNativeDiagnostics(
        async () => {
          assert.throws(
            () => native.guard(false, "C:\\fixture\\custody.h", 421),
            (cause) => cause === exited,
          );
          const before = modeCalls;
          native.transport(Buffer.alloc(32257), 32257);
          assert.equal(modeCalls, before);
          const bytes = Buffer.concat(frames);
          f.child.stdout.write('{"sequence":46,"value":');
          if (fault === "coalesced") f.child.stdout.write(bytes);
          else
            for (let at = 0; at < bytes.length; at += 37)
              f.child.stdout.write(bytes.subarray(at, at + 37));
          const first = await pending;
          assert.deepEqual(first.custodyReaderFailure, refusal);
          f.child.stdout.end();
          f.child.emit("close", 126, null);
          assert.equal(await completion, first);
          await assert.rejects(f.channel.receive(), (cause) => cause === first);
          assert.throws(() => f.channel.send("next\n"));
          const attempted = events.indexOf("diagnostic-write");
          assert.equal(
            attempted >= 0,
            !["mode", "format", "oversize"].includes(fault),
          );
          if (attempted >= 0) assert.ok(attempted < events.indexOf("fence"));
          assert.equal(modeCalls, fault === "oversize" ? 0 : 1);
          if (
            ![
              "mode",
              "format",
              "oversize",
              "write",
              "short-write",
              "sink",
            ].includes(fault)
          )
            assert.deepEqual(Buffer.concat(raw), output);
          else assert.equal(raw.length, 0);
        },
        (owner, value) => {
          if (fault === "sink") throw new Error("Diagnostic sink unavailable");
          if (owner === "windows-original-child" && value.stderr) {
            assert.equal(f.child.stdin.destroyed, false);
            events.push("published");
            raw.push(value.stderr);
          }
        },
      );
    } finally {
      f.channel.close();
      f.child.stdin.destroy();
      f.child.stdout.destroy();
      f.child.stderr.destroy();
    }
  }
});

test("original-child diagnostic framing cannot resolve replies or replace the first reader failure", async () => {
  const failure = {
    phase: "reader-failure",
    sequence: 46,
    command: "ownership-output",
    source: "custody.h",
    line: 421,
    lastError: 109,
  };
  const context =
    "native-windows-original-child: context command=ownership-output sequence=46 source=custody.h line=421 error=109 candidate=" +
    "a".repeat(40) +
    "\n";
  const completion =
    "native-windows-original-child: completion finished=1 incomplete=0 empty=1\n";
  const packet = {
    ...failure,
    phase: "reader-diagnostic",
    hex: Buffer.from(context + completion).toString("hex"),
  };
  const encoded = (value) => Buffer.from("\x1d" + JSON.stringify(value) + "\n");
  for (const fault of [
    null,
    "wrong-command",
    "extra-field",
    "invalid-json",
    "invalid-utf8",
    "bad-hex",
    "binary",
    "missing-completion",
    "missing-context",
    "extra-context",
    "record-limit",
    "coverage",
    "coverage-duplicate",
    "coverage-name",
    "evidence-attribution",
    "evidence-without-coverage",
    "readback",
    "maximum-rows",
    "token-limit",
    "resource-duplicate",
    "unknown-resource",
    "duplicate",
    "receipt",
    "queued",
    "end",
    "error",
    "timeout",
    "later-error",
    "fatal-context",
    "sink-child-error",
    "sink-stderr",
    "sink-close",
  ]) {
    let f;
    const raw = [];
    let value = { ...packet },
      bytes;
    const fatalFailure =
      fault === "fatal-context"
        ? {
            ...failure,
            open: {
              operation: "CreateFileW",
              pathUnits: 1,
              pathUtf16: "0043",
              directory: false,
              apiFailure: true,
              attributes: null,
              tag: null,
            },
          }
        : failure;
    if (fault === "wrong-command") value.command = "open";
    if (fault === "extra-field") value.receipt = true;
    if (fault === "bad-hex") value.hex = "zz";
    if (fault === "binary")
      value.hex = Buffer.from(context + "\0" + completion).toString("hex");
    if (fault === "missing-completion")
      value.hex = Buffer.from(context).toString("hex");
    if (fault === "missing-context")
      value.hex = Buffer.from(
        "native-windows-original-child: record x\n" + completion,
      ).toString("hex");
    if (fault === "extra-context")
      value.hex = Buffer.from(context + context + completion).toString("hex");
    if (fault === "record-limit")
      value.hex = Buffer.from(
        context +
          "native-windows-original-child: record x\n".repeat(65) +
          completion,
      ).toString("hex");
    if (fault?.startsWith("coverage") || fault?.startsWith("evidence-")) {
      const names = [
        "request-status",
        "declared-imports",
        "loader-dependencies",
        "known-dll-objects",
        "token-privileges",
        "window-station-desktop",
        "inherited-pipes-job",
        "other-kernel-objects",
        "path-ancestors",
      ];
      const coverage = Array.from(
        { length: 9 },
        (_, i) =>
          `native-windows-original-child: coverage class=${fault === "coverage-duplicate" ? 0 : i} name=${fault === "coverage-name" ? "unknown" : names[i]} state=unsupported first-request=unobserved\n`,
      ).join("");
      value.hex = Buffer.from(
        context +
          `native-windows-original-child: evidence class=4 scope=${fault === "evidence-attribution" ? "declared-requirements" : "snapshot"} original-request=unobserved attributes=2\n` +
          (fault === "evidence-without-coverage" ? "" : coverage) +
          completion,
      ).toString("hex");
    }
    if (
      [
        "readback",
        "maximum-rows",
        "token-limit",
        "resource-duplicate",
        "unknown-resource",
      ].includes(fault)
    ) {
      const token =
        "native-windows-original-child: token post-refusal=1 stable=0\n";
      const roles = [
        "image",
        "workspace",
        "storage",
        "case",
        "custody",
        "outer",
        "policy",
      ];
      if (fault === "resource-duplicate") roles[6] = "image";
      if (fault === "unknown-resource") roles[6] = "ancestor";
      value.hex = Buffer.from(
        context +
          token.repeat(fault === "token-limit" ? 2 : 1) +
          roles
            .map(
              (role) =>
                `native-windows-original-child: resource role=${role} bound=0\n`,
            )
            .join("") +
          "native-windows-original-child: record x\n".repeat(
            fault === "maximum-rows" ? 64 : 0,
          ) +
          completion,
      ).toString("hex");
    }
    bytes =
      fault === "invalid-json"
        ? Buffer.from("\x1d{bad}\n")
        : fault === "invalid-utf8"
          ? Buffer.from([0x1d, 0xff, 10])
          : encoded(value);
    try {
      await withNativeDiagnostics(
        async () => {
          f = transport();
          if (fault === "queued") f.child.stdout.write('{"earlier":true}\n');
          let pending;
          if (fault !== "queued")
            pending = f.channel.receive().catch((error) => error);
          const closed = f.channel.completion.catch((error) => error);
          f.child.stdout.write('{"sequence":46,"value":');
          f.child.stdout.write(bytes);
          if (fault === "queued")
            pending = f.channel.receive().catch((error) => error);
          assert.equal(f.child.stdin.destroyed, false);
          assert.throws(() => f.channel.send("next\n"));
          if (fault === "duplicate") f.child.stdout.write(encoded(packet));
          if (fault === "receipt")
            f.child.stdout.write('{"sequence":46,"value":{"accepted":true}}\n');
          else if (fault === "end") f.child.stdout.end();
          else if (fault === "error")
            f.child.stdout.emit(
              "error",
              new Error("Diagnostic transport failed"),
            );
          else if (fault === "timeout") f.expire();
          else if (fault === "sink-child-error")
            f.child.emit("error", new Error("Diagnostic process failed"));
          else if (fault === "sink-stderr") {
            f.child.stderr.write("Unavailable diagnostic sink\n");
            f.child.stderr.emit("error", new Error("Diagnostic stderr failed"));
          } else if (fault === "sink-close") f.child.emit("close", 126, null);
          else
            f.child.stdout.write(
              "\x1e" +
                JSON.stringify(
                  fault === "later-error"
                    ? { ...failure, lastError: 5 }
                    : fatalFailure,
                ) +
                "\n",
            );
          const first = await pending;
          assert.ok(first instanceof Error, fault);
          assert.deepEqual(first.custodyReaderFailure, fatalFailure, fault);
          f.child.emit("close", 126, null);
          assert.equal(await closed, first);
          const published = [
            null,
            "coverage",
            "readback",
            "maximum-rows",
            "duplicate",
            "receipt",
            "queued",
            "end",
            "error",
            "timeout",
            "later-error",
            "fatal-context",
          ].includes(fault);
          assert.equal(raw.length, published ? 1 : 0, fault);
        },
        (owner, value) => {
          if (fault?.startsWith("sink-"))
            throw new Error("Diagnostic sink unavailable");
          if (owner === "windows-original-child" && value.stderr)
            raw.push(value.stderr);
        },
      );
    } finally {
      f.channel.close();
      f.child.stdin.destroy();
      f.child.stdout.destroy();
      f.child.stderr.destroy();
    }
  }
  for (const fragment of [false, true]) {
    const f = transport(),
      pending = f.channel.receive().catch((error) => error),
      closed = f.channel.completion.catch((error) => error),
      bytes = Buffer.concat([
        Buffer.from("\x1d" + "x".repeat(65536)),
        Buffer.from("\x1e" + JSON.stringify(failure) + "\n"),
      ]);
    try {
      if (fragment) {
        f.child.stdout.write(bytes.subarray(0, 65535));
        f.child.stdout.write(bytes.subarray(65535));
      } else f.child.stdout.write(bytes);
      const error = await pending;
      assert.ok(error instanceof Error);
      assert.equal(error.custodyReaderFailure, undefined);
      f.child.emit("close", 126, null);
      assert.equal(await closed, error);
    } finally {
      f.channel.close();
      f.child.stdin.destroy();
      f.child.stdout.destroy();
      f.child.stderr.destroy();
    }
  }
});

test("actual retained startup readback selects only held resources and masks and suppresses unstable authorization", async () => {
  const source = await readFile(
    new URL("custody-reader.c", import.meta.url),
    "utf8",
  );
  // Admission/lifecycle wiring is outside the portable sampler bodies below.
  assert.match(
    source,
    /static void ownership_launch\([^\n]+\) \{\s+release_invalidate\(\);/u,
  );
  assert.match(
    source,
    /static void ownership_retain\([^\n]+\) \{\s+if\(!ownership_count\)release_invalidate\(\);/u,
  );
  assert.match(
    source,
    /#define close_file\(value\) \(release_file_closing\(value\), \(close_file\)\(value\)\)/u,
  );
  const retirementStart = source.indexOf(
    '!strcmp(values[0], "ownership-account-retire")',
  );
  assert.ok(retirementStart >= 0);
  const retirement = source.slice(retirementStart);
  const invalidation = retirement.indexOf("release_invalidate();");
  const closure = retirement.indexOf("CloseHandle(ownership_processes[i])");
  assert.ok(invalidation >= 0 && closure > invalidation);
  const names = [
    "release_invalidate",
    "release_file_closing",
    "release_capture_name",
    "readback_now",
    "release_live",
    "release_capture",
    "ownership_send",
    "readback_original",
    "readback_resource",
    "readback_collect",
  ];
  const project = (name) => {
    const match = new RegExp(
      `static [^\\n]+ \\*?${name}\\(([^\\n]*)\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source);
    assert.ok(match, name);
    if (["release_capture", "readback_original"].includes(name))
      assert.doesNotMatch(
        match[2],
        /\b(?:OpenProcess|CreateProcessW|CreateProcessAsUserW|ResumeThread)\(/u,
      );
    const args = match[1]
      .split(",")
      .filter((arg) => arg.trim() !== "void")
      .map((arg) => /([a-zA-Z_]\w*)$/u.exec(arg.trim())[1])
      .join(",");
    const body = match[2]
      .replaceAll("->", ".")
      .replace(
        "struct readback_status status={0},probe[3]={{0}};struct readback_object object={0};",
        "var status=freshStatus(),probe=[freshStatus(),freshStatus(),freshStatus()],object=freshObject();",
      )
      .replace(
        "struct readback_status status={0};struct readback_token metadata={0};",
        "var status=freshStatus(),metadata=freshMetadata();",
      )
      .replace(
        "struct release_binding captured={0};struct readback_status status={0};",
        "var captured=freshRelease(),status=freshStatus();",
      )
      .replace(
        "struct release_image_query imageQuery={0};",
        "var imageQuery={attempted:false,succeeded:false,exitRead:false,error:0,waitError:0,exitCode:0,exitError:0};",
      )
      .replace("TOKEN_STATISTICS before,after;", "var before={},after={};")
      .replace("TOKEN_STATISTICS current,after;", "var current={},after={};")
      .replace("BYTE bytes[32768];", "var bytes=[];")
      .replace("char pid[32];", "var pid=[];")
      .replace(
        "DWORD granted[3]={0};BOOL allowed[3]={0},api[3]={0};",
        "var granted=[0,0,0],allowed=[false,false,false],api=[false,false,false];",
      )
      .replace(
        'char identity[33]="unavailable",probes[1536]="",line[6144];',
        'var identity=chars("unavailable"),probes=[],line=[];',
      )
      .replace(
        'char access[32]="unavailable",mandatory[32]="unavailable";',
        'var access=chars("unavailable"),mandatory=chars("unavailable");',
      )
      .replace("char line[4096];", "var line=[];")
      .replace("FILETIME time;", "var time={};")
      .replace(
        "FILETIME created,exited,kernel,user;WCHAR image[4096];",
        "var created={},exited={},kernel={},user={},image=[];",
      )
      .replace("FILE_ID_INFO id;", "var id={};")
      .replace(
        "FILETIME created,exited,kernel,user;WCHAR expected[4096];",
        "var created={},exited={},kernel={},user={},expected=[];",
      )
      .replace(
        /sizeof\(captured\.(imageId|candidate|nonce|hash)\)/gu,
        (_, key) => ({ imageId: 24, candidate: 41, nonce: 33, hash: 65 })[key],
      )
      .replaceAll("sizeof(bytes)", "32768")
      .replace(/sizeof\((?:captured\.path|expected|image)\)/gu, "8192")
      .replaceAll("expected+4", "expected.slice(4)")
      .replace(/\bL("(?:\\.|[^"\\])*")/gu, "$1")
      .replaceAll("L':'", "58")
      .replaceAll("L'\\\\'", "92")
      .replace(/'([PCRGEAQ])'/gu, (_, byte) => byte.charCodeAt(0))
      .replaceAll("#ifdef NATIVE_CI_EXPERIMENT", "")
      .replaceAll("#endif", "")
      .replace(
        /\(\(ULONGLONG\)(time|created)\.dwHighDateTime<<32\)\|\1\.dwLowDateTime/gu,
        "$1.ticks",
      )
      .replace(
        /sizeof\((identity|probes|line|access|mandatory|id)\)/gu,
        (_, key) =>
          ({
            identity: 33,
            probes: 1536,
            line: name === "readback_collect" ? 4096 : 6144,
            access: 32,
            mandatory: 32,
            id: 24,
          })[key],
      )
      .replace(/\b(identity|probes)\+(i\*2|used)/gu, "at($1,$2)")
      .replace(
        /(?<!&)&(granted|allowed)\[i\]/gu,
        (_, key) => `ref(()=>${key}[i],v=>${key}[i]=v)`,
      )
      .replace(/(?<!&)&probe\[i\]/gu, "probe[i]")
      .replace(
        /(?<!&)&(pid|birth|length|temporary|used|query\.exitCode)\b/gu,
        (_, key) => `ref(()=>${key},v=>${key}=v)`,
      )
      .replace(/\*(pid|birth)\b/gu, "$1.value")
      .replace(
        /(?<!&)&entries\[indices\[i\]\]\.file/gu,
        "entries[indices[i]].file",
      )
      .replace(/(?<!&)&file\.id\b/gu, "file.id")
      .replace(
        /(?<!&)&(captured\.(?:imageId|statistics)|status|metadata|imageQuery|current|object|before|after|created|exited|kernel|user|id|time|original_release(?:\.(?:imageId|statistics))?|ownership_policy_file|original_refusal\.imageId|entries\[6\]\.file\.id)\b/gu,
        "$1",
      )
      .replace(/\b(\w+)\[\]=\{([^}]+)\}/gu, "$1=[$2]")
      .replace(/\((?:BYTE|DWORD|size_t)\)/gu, "")
      .replace(
        /\b(?:const )?(?:struct held_file|PSECURITY_DESCRIPTOR|ULONGLONG|DWORD|BOOL|HANDLE|unsigned|size_t|int|char) \*?/gu,
        "var ",
      );
    const projected =
      name === "release_capture"
        ? "capture:{" +
          body
            .replaceAll("goto finished;", "break capture;")
            .replace("\nfinished:", "}\n")
        : body;
    return `function ${name}(${args}){${projected}}`;
  };
  const program = new Script(
    names.map(project).join("\n") +
      "\n({collect:readback_collect,send:ownership_send,capture:release_capture,invalidate:release_invalidate,closing:release_file_closing});",
  );
  for (const fault of [
    null,
    "nonliteral",
    "other-command",
    "expired",
    "birth",
    "process-image",
    "held-image",
    "missing-storage",
    "workspace-identity",
    "statistics-last",
    "statistics-changed",
    "metadata-last",
    "probe-api",
    "policy-denial",
    "deadline",
    "cleanup",
    "exited-image-error31",
    "exited-missing-capture",
    "exited-stale-nonce",
    "exited-changed-statistics",
    "live-image-error31",
    "terminal-wait-error",
    "terminal-wait-result",
    "terminal-exit-error",
    "malformed-image",
    "missing-capture",
    "capture-image",
    "capture-unterminated-image",
    "capture-path",
    "capture-file-id",
    "capture-open",
    "capture-failed-output",
    "capture-borrowed-output",
    "capture-statistics",
    "capture-current-changed",
    "capture-retained-changed",
    "capture-not-primary",
    "capture-exited",
    "capture-deadline",
    "capture-close",
    "wrong-process",
    "wrong-token",
    "wrong-image",
    "stale-candidate",
    "stale-nonce",
    "stale-pin",
    "saved-image-id",
    "saved-token-id",
    "saved-authentication-id",
    "saved-modified-id",
    "dispatch-failed",
    "dispatch-short",
    "reset",
    "image-close",
    "unrelated-close",
    "recapture",
  ]) {
    const chars = (value) => [...value].map((v) => v.charCodeAt(0)).concat(0);
    const text = (value) =>
      Array.isArray(value)
        ? value
            .slice(0, value.indexOf(0) < 0 ? value.length : value.indexOf(0))
            .map((v) => String.fromCharCode(v))
            .join("")
        : String(value);
    const stats = () => ({
      TokenId: { HighPart: 0, LowPart: 1 },
      AuthenticationId: { HighPart: 0, LowPart: 2 },
      ModifiedId: { HighPart: 0, LowPart: 3 },
      TokenType: 1,
    });
    const freshStatus = () => ({
      failed: false,
      value: 0,
      closureUncertain: false,
      cleanupValue: 0,
    });
    const freshRelease = () => ({
      state: 0,
      dispatched: false,
      process: 0,
      token: 0,
      image: 0,
      pid: 0,
      birth: 0,
      from: 0,
      to: 0,
      release: 0,
      candidate: [],
      nonce: [],
      hash: [],
      path: [],
      imageId: {},
      statistics: {},
      status: freshStatus(),
    });
    const freshMetadata = () => ({
      before: stats(),
      after: stats(),
      fields: 31,
      first: true,
      last: true,
      stable: true,
      subject: "S-1-5-21-7001",
      restricting: "S-1-5-21-7002",
      restrictingCount: 1,
      privileges: 0,
      integrity: 4096,
      integritySid: "S-1-16-4096",
      policy: 1,
    });
    const freshObject = () => ({
      actual: { VolumeSerialNumber: 0 },
      identified: false,
      bound: false,
      descriptorHash: false,
      daclHash: false,
      ownerValid: false,
      acesValid: false,
      labelValid: false,
      labelDefaulted: false,
      level: 0,
      label: 0,
      aces: "",
    });
    const id = (value) => ({
      VolumeSerialNumber: 1,
      FileId: { Identifier: Array(16).fill(value) },
    });
    const report = {
      readbackStarted: false,
      readbackFinished: false,
      readbackTokens: 0,
      readbackResources: 0,
      readbackProbes: 0,
      readbackUnavailable: 0,
      readbackClosure: false,
      truncated: false,
    };
    const calls = [],
      rows = [],
      freed = new Set(),
      closed = new Set();
    let remaining = fault === "expired" ? 0 : 30000,
      reads = 0,
      error = 5,
      phase = "capture",
      waits = 0;
    const ref = (get, set) => ({
      get value() {
        return get();
      },
      set value(v) {
        set(v);
      },
    });
    const api = {
      chars,
      text,
      ref,
      freshStatus,
      freshMetadata,
      freshObject,
      freshRelease,
      at: (target, offset) => ({ target, offset }),
      NULL: null,
      TRUE: true,
      FALSE: false,
      TokenPrimary: 1,
      FileIdInfo: 18,
      ERROR_INVALID_HANDLE: 6,
      ERROR_INVALID_DATA: 13,
      ERROR_TIMEOUT: 1460,
      MAXDWORD: 4294967295,
      WAIT_OBJECT_0: 0,
      WAIT_TIMEOUT: 258,
      WAIT_FAILED: 4294967295,
      RELEASE_UNSTARTED: 0,
      RELEASE_UNAVAILABLE: 1,
      RELEASE_INVALIDATED: 2,
      RELEASE_USABLE: 3,
      TOKEN_QUERY: 8,
      FILE_NAME_NORMALIZED: 0,
      VOLUME_NAME_DOS: 0,
      FILE_READ_DATA: 1,
      FILE_EXECUTE: 32,
      FILE_TRAVERSE: 32,
      FILE_LIST_DIRECTORY: 1,
      FILE_ADD_FILE: 2,
      FILE_ADD_SUBDIRECTORY: 4,
      TOKEN_MANDATORY_POLICY_NO_WRITE_UP: 1,
      original_refusal: {
        command: fault === "other-command" ? "other" : "ownership-output",
        pid: 123,
        birth: 90,
        image: chars("C:\\sample\\payload.exe"),
        imageId: id(6),
        hash: "c".repeat(64),
        to: 1000,
      },
      original_release: freshRelease(),
      refusal_arm: () => calls.push("arm"),
      refusal_settle: () => {},
      startup_capture: () => {},
      candidate: "a".repeat(40),
      nonce: "b".repeat(32),
      errno: 9,
      ownership_count: 1,
      ownership_control: 77,
      ownership_owner: { hProcess: 80 },
      ownership_stage: 5,
      ownership_creation_verified: true,
      ownership_policy_installed: true,
      ownership_spoofed: false,
      ownership_released: false,
      access_mode: false,
      // An even token handle exposes accidental bitwise AND in C projection.
      ownership_literal: fault !== "nonliteral",
      ownership_processes: [42],
      ownership_tokens: [70],
      tokens: [999],
      case_token: 888,
      case_record: {
        accountSid: "S-1-5-21-7001",
        restrictingSid: "S-1-5-21-7002",
      },
      entries: Array.from({ length: 7 }, (_, i) => ({
        pin: "c".repeat(64),
        file: {
          handle: fault === "missing-storage" && i === 3 ? 0 : i + 10,
          id: id(i),
        },
      })),
      ownership_policy_file: { handle: 40, id: id(7) },
      refusal_remaining: () => remaining,
      GetLastError: () => error,
      SetLastError(value) {
        error = value;
      },
      GetTickCount64() {
        calls.push("tick-start");
        return 1000;
      },
      strlen: (value) => text(value).length,
      strnlen_s: (value, maximum) => Math.min(text(value).length, maximum),
      wcsnlen_s: (value, maximum) => Math.min(text(value).length, maximum),
      nibble: (value) => parseInt(value, 16),
      need(value) {
        assert.ok(value, "native refusal");
      },
      WriteFile(handle, bytes, count, used) {
        assert.deepEqual([handle, bytes[0], count], [77, 82, 1]);
        assert.equal(api.original_refusal.from, 200 + calls.length);
        assert.equal(api.original_release.dispatched, false);
        if (api.original_release.state === 3)
          assert.equal(closed.has(72), true);
        calls.push("dispatch");
        used.value = fault === "dispatch-short" ? 0 : count;
        return fault !== "dispatch-failed";
      },
      WaitForSingleObject(handle, timeout) {
        assert.equal(timeout, 0, "Capture and fallback never add a wait");
        if (handle === 80) return 258;
        assert.equal(handle, 42);
        calls.push(`${phase}:wait`);
        if (phase === "capture")
          return fault === "capture-exited" && ++waits === 2 ? 0 : 258;
        if (fault === "terminal-wait-error") {
          error = 6;
          return 4294967295;
        }
        if (fault === "terminal-wait-result") return 128;
        return fault === "live-image-error31" ? 258 : 0;
      },
      GetExitCodeProcess(handle, out) {
        assert.equal(handle, 42);
        calls.push("exit");
        if (fault === "terminal-exit-error") {
          error = 87;
          return false;
        }
        out.value = 0xc0000022;
        return true;
      },
      GetFinalPathNameByHandleW(handle, out, maximum, flags) {
        assert.deepEqual([handle, maximum, flags], [16, 4096, 0]);
        calls.push("final-path");
        const path = chars(
          "\\\\?\\C:\\sample\\" +
            (fault === "capture-path" ? "other.exe" : "payload.exe"),
        );
        out.splice(0, path.length, ...path);
        return path.length - 1;
      },
      OpenProcessToken(handle, mask, out) {
        assert.deepEqual([handle, mask], [42, 8]);
        calls.push("open-token");
        out.value =
          fault === "capture-open"
            ? null
            : fault === "capture-borrowed-output"
              ? 70
              : 72;
        error = 5;
        api.errno = 88;
        return ![
          "capture-open",
          "capture-failed-output",
          "capture-borrowed-output",
        ].includes(fault);
      },
      readback_close(handle, status) {
        assert.equal(
          handle,
          72,
          "Borrowed handles never become temporary ownership",
        );
        assert.equal(closed.has(handle), false);
        closed.add(handle);
        calls.push("close-token");
        error = 6;
        if (fault === "capture-close")
          Object.assign(status, {
            closureUncertain: true,
            cleanupDomain: "win32",
            cleanupValue: 6,
          });
      },
      memcpy(target, value) {
        if (Array.isArray(target)) target.push(...chars(text(value)));
        else Object.assign(target, structuredClone(value));
      },
      memset(target, _value, bytes) {
        target.length = bytes / 2;
        target.fill(65535);
      },
      GetSystemTimePreciseAsFileTime(out) {
        out.ticks = 200 + calls.length;
      },
      GetProcessId(handle) {
        assert.equal(handle, 42);
        calls.push("pid");
        return 123;
      },
      GetProcessTimes(handle, created) {
        assert.equal(handle, 42);
        created.ticks = phase === "readback" && fault === "birth" ? 91 : 90;
        return true;
      },
      QueryFullProcessImageNameW(handle, flags, out, length) {
        assert.deepEqual([handle, flags], [42, 0]);
        calls.push(`${phase}:image-query`);
        if (
          (phase === "capture" && fault === "capture-image") ||
          (phase === "readback" &&
            (fault?.startsWith("exited-") ||
              [
                "live-image-error31",
                "terminal-wait-error",
                "terminal-wait-result",
                "terminal-exit-error",
              ].includes(fault)))
        ) {
          error = 31;
          return false;
        }
        const path = chars(
          phase === "readback" && fault === "process-image"
            ? "C:\\sample\\other.exe"
            : "C:\\sample\\payload.exe",
        );
        out.splice(0, path.length, ...path);
        length.value = path.length - 1;
        if (phase === "capture" && fault === "capture-unterminated-image")
          out[length.value] = 65535;
        if (phase === "readback" && fault === "malformed-image") length.value++;
        return true;
      },
      GetFileInformationByHandleEx(handle, kind, out) {
        assert.deepEqual([handle, kind], [16, 18]);
        Object.assign(
          out,
          id(
            (phase === "readback" && fault === "held-image") ||
              (phase === "capture" && fault === "capture-file-id")
              ? 8
              : 6,
          ),
        );
        return true;
      },
      _wcsicmp: (a, b) =>
        Number(text(a).toLowerCase() !== text(b).toLowerCase()),
      strcmp: (a, b) => Number(text(a) !== text(b)),
      wmemcmp: (a, b, size) =>
        Number(text(a).slice(0, size) !== text(b).slice(0, size)),
      memcmp: (a, b) => Number(JSON.stringify(a) !== JSON.stringify(b)),
      readback_fail(status, domain, operation, value) {
        if (!status.failed)
          Object.assign(status, { failed: true, domain, operation, value });
        return false;
      },
      readback_ready: (status, operation) =>
        remaining > 0 || api.readback_fail(status, "budget", operation, 1460),
      readback_metadata(token, value) {
        assert.equal(token, 70);
        Object.assign(value, freshMetadata());
        if (fault === "metadata-last")
          Object.assign(value, { last: false, stable: false });
      },
      readback_sid_equal: (a, b) => a === b,
      readback_statistics(token, out, status) {
        assert.ok([70, 72].includes(token));
        Object.assign(out, stats());
        reads++;
        if (phase === "capture") {
          if (fault === "capture-not-primary") out.TokenType = 2;
          if (
            (fault === "capture-current-changed" && token === 72) ||
            (fault === "capture-retained-changed" && reads === 3)
          )
            out.ModifiedId.LowPart = 9;
          if (fault === "capture-deadline" && token === 72) remaining = 0;
          return (
            (remaining > 0 &&
              !(fault === "capture-statistics" && token === 72)) ||
            api.readback_fail(status, "win32", "GetTokenInformation", 5)
          );
        }
        if (fault === "statistics-changed" && reads === 2)
          out.ModifiedId.LowPart = 9;
        return remaining > 0 && !(fault === "statistics-last" && reads === 2);
      },
      readback_same: (a, b) => JSON.stringify(a) === JSON.stringify(b),
      readback_describe(handle, expected, _account, _restricting, object) {
        calls.push(`describe:${handle}`);
        if (!handle) return null;
        Object.assign(object, {
          actual: structuredClone(expected),
          identified: true,
          bound: !(fault === "workspace-identity" && handle === 14),
          descriptorHash: true,
          daclHash: true,
          ownerValid: true,
          acesValid: true,
          labelValid: true,
          labelDefaulted: true,
          level: 8192,
          label: 1,
          descriptor: "a".repeat(64),
          dacl: "b".repeat(64),
          owner: "S-1-5-18",
          aces: "0/0/1/system",
        });
        return { handle };
      },
      readback_access(token, sd, mask, granted, allowed, status) {
        assert.equal(token, 70);
        calls.push([sd.handle, mask]);
        granted.value = mask;
        allowed.value = true;
        if (fault === "deadline") remaining = 0;
        if (fault === "cleanup") status.closureUncertain = true;
        if (fault === "policy-denial" && sd.handle === 40) {
          granted.value = 0;
          allowed.value = false;
        }
        if (fault === "probe-api" && sd.handle === 16)
          return api.readback_fail(status, "win32", "AccessCheck", 5);
        return true;
      },
      readback_mic: () => 6,
      readback_free(sd) {
        if (sd) {
          assert.equal(freed.has(sd), false);
          freed.add(sd);
        }
      },
      snprintf(out, capacity, format, ...values) {
        const rendered = format.replace(
          /%(?:08lx|02x|llu|lu|[su])/gu,
          (match) => {
            const value = values.shift();
            return match === "%08lx" || match === "%02x"
              ? value.toString(16).padStart(match === "%02x" ? 2 : 8, "0")
              : match === "%s"
                ? text(value)
                : String(Number(value));
          },
        );
        assert.equal(values.length, 0);
        const target = out.target ?? out,
          offset = out.offset ?? 0;
        for (let i = 0; i < Math.min(rendered.length, capacity - 1); i++)
          target[offset + i] = rendered.charCodeAt(i);
        target[offset + Math.min(rendered.length, capacity - 1)] = 0;
        return rendered.length;
      },
      refusal_publish(line, current) {
        if (!line) return;
        const value = text(line);
        rows.push(value);
        assert.ok(value.length < 6144);
        if (value.includes(": token ")) current.readbackTokens++;
        else current.readbackResources++;
      },
    };
    const run = program.runInNewContext(api);
    if (["missing-capture", "exited-missing-capture"].includes(fault))
      api.ownership_literal = false;
    if (["dispatch-failed", "dispatch-short"].includes(fault)) {
      assert.throws(() => run.send("52"), /native refusal/u);
      assert.equal(api.original_release.state, 2);
      assert.equal(!!api.original_refusal.sent, false);
    } else run.send("52");
    assert.equal(api.errno, 9);
    assert.equal(
      error,
      5,
      "Capture preserves original error independently of cleanup",
    );
    assert.equal(api.original_refusal.tick, 1000);
    if (!fault) {
      const dispatched = JSON.stringify(api.original_release),
        count = calls.length;
      assert.throws(() => run.send("52"), /native refusal/u);
      assert.equal(
        calls.length,
        count,
        "A second R cannot replay capture or dispatch",
      );
      assert.equal(JSON.stringify(api.original_release), dispatched);
    }
    const failedAcquisition = [
      "capture-open",
      "capture-failed-output",
      "capture-borrowed-output",
    ].includes(fault);
    assert.equal(
      closed.size,
      calls.includes("open-token") && !failedAcquisition ? 1 : 0,
    );
    if (fault?.startsWith("capture-") || fault === "expired") {
      assert.equal(api.original_release.state, 1);
      assert.equal(
        api.original_release.process,
        0,
        "Incomplete identity is never published",
      );
    }
    if (
      ["reset", "recapture", "image-close", "unrelated-close"].includes(fault)
    ) {
      const identity = ({ state: _state, dispatched: _dispatched, ...saved }) =>
        JSON.stringify(saved);
      const frozen = identity(api.original_release);
      const count = calls.length;
      if (fault === "recapture") run.capture();
      else if (fault.endsWith("close"))
        run.closing(api.entries[fault === "image-close" ? 6 : 4].file);
      else run.invalidate();
      assert.equal(
        api.original_release.state,
        fault === "unrelated-close" ? 3 : 2,
      );
      assert.equal(
        identity(api.original_release),
        frozen,
        "Invalidation cannot reconstruct saved identity",
      );
      assert.equal(calls.length, count);
    }
    if (fault === "wrong-process") api.original_release.process = 44;
    if (fault === "wrong-token") api.original_release.token = 71;
    if (fault === "wrong-image") api.original_release.image = 17;
    if (fault === "stale-candidate") api.candidate = "d".repeat(40);
    if (["stale-nonce", "exited-stale-nonce"].includes(fault))
      api.nonce = "e".repeat(32);
    if (fault === "stale-pin") api.entries[6].pin = "f".repeat(64);
    if (fault === "saved-image-id") api.original_release.imageId = id(8);
    if (fault?.startsWith("saved-") && fault !== "saved-image-id") {
      const field = {
        "saved-token-id": "TokenId",
        "saved-authentication-id": "AuthenticationId",
        "saved-modified-id": "ModifiedId",
      }[fault];
      api.original_release.statistics[field].LowPart++;
    }
    if (fault === "exited-changed-statistics")
      api.original_release.statistics.ModifiedId.LowPart++;
    api.ownership_literal = fault !== "nonliteral";
    phase = "readback";
    reads = 0;
    const inspected = JSON.stringify(api.original_release),
      beforeCollect = calls.length;
    run.collect(report);
    assert.equal(
      JSON.stringify(api.original_release),
      inspected,
      "Refusal never recreates release evidence",
    );
    assert.equal(
      api.original_refusal.tick,
      1000,
      "Neither capture nor refusal resets the deadline",
    );
    assert.equal(calls.filter((value) => value === "tick-start").length, 1);
    if (
      ["nonliteral", "other-command", "expired", "capture-deadline"].includes(
        fault,
      )
    ) {
      assert.deepEqual(calls.slice(beforeCollect), []);
      assert.deepEqual(rows, []);
      assert.equal(report.readbackStarted, false);
      continue;
    }
    const probes = calls.filter(Array.isArray);
    const expected = [
      [16, 1],
      [16, 32],
      [14, 32],
      [14, 1],
      [14, 6],
      [13, 32],
      [11, 32],
      [12, 32],
      [10, 32],
      [40, 1],
    ];
    assert.deepEqual(
      probes,
      fault === "missing-storage"
        ? expected.filter(([handle]) => handle !== 13)
        : fault === "workspace-identity"
          ? expected.filter(([handle]) => handle !== 14)
          : fault === "deadline"
            ? expected.slice(0, 1)
            : expected,
    );
    assert.match(rows[0], /token post-refusal=1/u);
    assert.equal(report.readbackTokens, 1);
    assert.deepEqual(
      rows.slice(1).map((row) => /role=(\w+)/u.exec(row)[1]),
      fault === "deadline"
        ? ["image"]
        : [
            "image",
            "workspace",
            "storage",
            "case",
            "custody",
            "outer",
            "policy",
          ],
    );
    assert.equal(report.readbackFinished, fault !== "deadline");
    assert.equal(
      freed.size,
      fault === "deadline" ? 1 : fault === "missing-storage" ? 6 : 7,
    );
    if (
      [
        "birth",
        "process-image",
        "held-image",
        "metadata-last",
        "statistics-last",
        "statistics-changed",
        "probe-api",
        "deadline",
        "live-image-error31",
        "terminal-wait-error",
        "terminal-wait-result",
        "terminal-exit-error",
        "malformed-image",
        "missing-capture",
        "exited-missing-capture",
        "exited-stale-nonce",
        "exited-changed-statistics",
        "wrong-process",
        "wrong-token",
        "wrong-image",
        "stale-candidate",
        "stale-nonce",
        "stale-pin",
        "saved-image-id",
        "saved-token-id",
        "saved-authentication-id",
        "saved-modified-id",
        "dispatch-failed",
        "dispatch-short",
        "reset",
        "image-close",
        "recapture",
      ].includes(fault) ||
      fault?.startsWith("capture-")
    ) {
      assert.match(rows[1], /discretionary:unavailable,granted:unavailable/u);
      assert.doesNotMatch(rows[1], /authorization:grant/u);
      assert.match(
        rows[1],
        /descriptor-sha256=a{64}/u,
        "Valid object facts survive unavailable authorization",
      );
    }
    if (fault === "policy-denial")
      assert.match(
        rows.at(-1),
        /discretionary:deny,granted:0,mic-denied:0,authorization:deny/u,
      );
    if (fault === "cleanup") assert.equal(!!report.readbackClosure, true);
    if (fault === "capture-close") {
      assert.equal(!!report.readbackClosure, true);
      assert.match(
        rows[0],
        /capture=unavailable .*capture-closure-uncertain=1/u,
      );
    }
    if (
      fault?.startsWith("exited-") ||
      [
        "live-image-error31",
        "terminal-wait-error",
        "terminal-wait-result",
        "terminal-exit-error",
      ].includes(fault)
    ) {
      assert.match(
        rows[0],
        /image-query-attempted=1 image-query-succeeded=0 image-query-error=31/u,
      );
      assert.equal(
        calls.includes("exit"),
        ![
          "live-image-error31",
          "terminal-wait-error",
          "terminal-wait-result",
        ].includes(fault),
      );
    }
    if (["process-image", "malformed-image"].includes(fault)) {
      assert.equal(
        calls.includes("readback:wait"),
        false,
        "Successful malformed/mismatched queries never fall back",
      );
    }
    if (fault === "exited-image-error31") {
      assert.match(rows[0], /binding=1 capture=usable/u);
      assert.match(rows[0], /binding-source=release-exited/u);
      assert.match(rows[0], /terminal-exit-read=1 terminal-exit=3221225506/u);
      assert.doesNotMatch(rows.slice(1).join(""), /authorization:unavailable/u);
    }
    if ([null, "exited-image-error31", "unrelated-close"].includes(fault))
      assert.deepEqual(
        [
          report.readbackProbes,
          report.readbackUnavailable,
          report.readbackResources,
        ],
        [10, 0, 7],
      );
  }
});

test("literal output drains the original pipe before exit and shares the release deadline", async () => {
  const source = await readFile(
    new URL("custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:BOOL|DWORD|int) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const project = (text) =>
    text
      .replace(
        "memset(&original_literal_output,0,sizeof(original_literal_output));",
        "original_literal_output=freshOutput();",
      )
      .replace(
        "const struct literal_output_fact *value=&original_literal_output;",
        "const value=original_literal_output;",
      )
      .replaceAll("value->", "value.")
      .replaceAll("output+used-1", "{target:output,offset:used-1}")
      .replaceAll("byte=='\\n'", "byte===10")
      .replaceAll(
        "&original_literal_output.exitCode",
        "{get value(){return original_literal_output.exitCode},set value(v){original_literal_output.exitCode=v}}",
      )
      .replace(
        /&(available|used|byte)\b/gu,
        (_match, name) =>
          `{get value(){return ${name}},set value(v){${name}=v}}`,
      )
      .replaceAll("(DWORD)", "")
      .replace(/\b(?:DWORD|ULONGLONG|BYTE|BOOL|int) /gu, "let ");
  const script = new Script(
    [
      ["refusal_remaining", ""],
      ["ownership_literal_refuse", "reason,error"],
      ["ownership_literal_read", "process,input,bytes,maximum"],
      ["ownership_literal_context", "output,maximum,used"],
    ]
      .map(
        ([name, args]) => `function ${name}(${args}){${project(body(name))}}`,
      )
      .join("\n") +
      "\n({read:ownership_literal_read,remaining:refusal_remaining,context:ownership_literal_context})",
  );
  for (const fault of [
    "empty-exit",
    "partial-exit",
    "buffered-exit",
    "delayed-output",
    "exit-during-poll",
    "delayed-exit",
    "live-empty",
    "live-partial",
    "complete-live",
    "expired",
    "drain-expiry",
    "peek-error",
    "read-error",
    "short-read",
    "wait-error",
    "wait-result",
    "exit-error",
    "bad-byte",
    "frame-bound",
    "nonzero-buffered",
  ]) {
    let tick = fault === "expired" ? 31000 : 1000,
      error = 109;
    let done = [
      "empty-exit",
      "partial-exit",
      "buffered-exit",
      "exit-error",
      "nonzero-buffered",
    ].includes(fault);
    let queued = Buffer.from(
      ["partial-exit", "live-partial", "delayed-exit"].includes(fault)
        ? "{"
        : [
              "buffered-exit",
              "complete-live",
              "exit-error",
              "read-error",
              "short-read",
              "frame-bound",
              "nonzero-buffered",
              "drain-expiry",
            ].includes(fault)
          ? "ok\n"
          : "",
    );
    if (fault === "bad-byte") queued = Buffer.from([0]);
    const calls = [],
      bytes = [];
    const freshOutput = () => ({
      active: false,
      complete: false,
      exitRead: false,
      used: 0,
      available: 0,
      readBytes: 0,
      waited: 0,
      waitError: 0,
      exitCode: 0,
      exitError: 0,
      pipeError: 0,
    });
    const api = {
      freshOutput,
      original_literal_output: freshOutput(),
      original_refusal: { tick: 1000 },
      TRUE: true,
      FALSE: false,
      NULL: null,
      MAXDWORD: 0xffffffff,
      WAIT_OBJECT_0: 0,
      WAIT_TIMEOUT: 258,
      WAIT_FAILED: 0xffffffff,
      GetTickCount64: () => tick,
      GetLastError: () => error,
      SetLastError: (v) => {
        error = v;
      },
      PeekNamedPipe(input, _buffer, _size, _read, available) {
        assert.equal(input, 7);
        calls.push("peek");
        if (fault === "peek-error") {
          error = 5;
          return false;
        }
        available.value = queued.length;
        return true;
      },
      ReadFile(input, out, size, used) {
        assert.equal(input, 7);
        assert.equal(size, 1);
        assert.ok(queued.length);
        calls.push("read");
        tick++;
        if (fault === "read-error") {
          error = 87;
          return false;
        }
        if (fault === "short-read") {
          used.value = 0;
          return true;
        }
        out.value = queued[0];
        queued = queued.subarray(1);
        used.value = 1;
        if (fault === "drain-expiry") tick = 31000;
        return true;
      },
      WaitForSingleObject(process, remaining) {
        assert.equal(process, 43);
        calls.push("wait");
        assert.ok(remaining >= 0 && remaining <= 31000 - tick);
        if (fault === "wait-error") {
          error = 6;
          return 0xffffffff;
        }
        if (fault === "wait-result") return 128;
        if (fault === "exit-during-poll" && !done) {
          queued = Buffer.from("ok\n");
          done = true;
          return 0;
        }
        if (done) return 0;
        if (!remaining) return 258;
        if (["delayed-output", "delayed-exit"].includes(fault)) {
          tick += Math.min(remaining, 7);
          done = true;
          if (fault === "delayed-output") queued = Buffer.from("ok\n");
          return 0;
        }
        tick += remaining;
        return 258;
      },
      GetExitCodeProcess(process, out) {
        assert.equal(process, 43);
        assert.equal(queued.length, 0);
        calls.push("exit");
        if (fault === "exit-error") {
          error = 87;
          return false;
        }
        out.value = ["empty-exit", "partial-exit", "nonzero-buffered"].includes(
          fault,
        )
          ? 0xc0000022
          : 0;
        return true;
      },
      sprintf_s(out, maximum, format, ...values) {
        let i = 0;
        const value = format.replace(/%(?:lu|ld|[su])/gu, (match) =>
          match === "%s" ? String(values[i++]) : String(Number(values[i++])),
        );
        assert.equal(i, values.length);
        assert.ok(value.length < maximum);
        out.target.text = out.target.text.slice(0, out.offset) + value;
        return value.length;
      },
    };
    const run = script.runInNewContext(api);
    const accepted = run.read(43, 7, bytes, fault === "frame-bound" ? 2 : 32);
    assert.equal(
      accepted,
      [
        "buffered-exit",
        "delayed-output",
        "exit-during-poll",
        "nonzero-buffered",
      ].includes(fault),
      fault,
    );
    assert.equal(api.original_refusal.tick, 1000, fault);
    assert.ok(tick <= 31000, fault);
    const fact = api.original_literal_output;
    if (accepted) {
      assert.equal(Buffer.from(bytes.slice(0, fact.used)).toString(), "ok");
      assert.equal(fact.complete, true);
      assert.equal(fact.exitRead, true);
      assert.ok(calls.lastIndexOf("read") < calls.indexOf("exit"));
    } else {
      const expected =
        {
          "empty-exit": "no-frame",
          "partial-exit": "partial-frame",
          "delayed-exit": "partial-frame",
          "peek-error": "peek",
          "read-error": "read",
          "short-read": "short-read",
          "wait-error": "wait",
          "wait-result": "wait-result",
          "exit-error": "exit",
          "bad-byte": "frame-byte",
          "frame-bound": "frame-bound",
        }[fault] ?? "deadline";
      assert.equal(fact.refusal, expected, fault);
      assert.equal(
        error,
        {
          "peek-error": 5,
          "read-error": 87,
          "wait-error": 6,
          "exit-error": 87,
        }[fault] ?? 0,
        fault,
      );
    }
    if (["empty-exit", "partial-exit", "delayed-exit"].includes(fault))
      assert.ok(
        run.remaining() > 29980,
        "Early refusal leaves the collector its original remaining time",
      );
    if (fault === "nonzero-buffered") assert.equal(fact.exitCode, 0xc0000022);
    if (fault === "expired") assert.deepEqual(calls, []);
    if (fault === "wait-error") {
      assert.equal(fact.waited, 0xffffffff);
      assert.equal(fact.waitError, 6);
    }
    const context = { text: "native-windows-original-child: context\n" };
    const size = run.context(context, 1024, context.text.length);
    assert.equal(size, context.text.length);
    assert.equal(
      context.text.split("\n").length,
      2,
      "Keep the existing single context-line grammar",
    );
    assert.ok(context.text.includes("output-refusal=" + fact.refusal));
    assert.ok(context.text.includes("pipe-error=" + fact.pipeError));
    assert.ok(context.text.includes("exit=" + fact.exitCode));
  }
});

test("original-child capture arms before release and retains delayed delivery and owned settlement", async () => {
  const source = await readFile(
    new URL("custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:void|BOOL|EVT_HANDLE|DWORD(?: WINAPI)?) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const project = (text) =>
    text
      .replaceAll(
        "struct refusal_report report=original_refusal.report;",
        "let report=structuredClone(original_refusal.report);",
      )
      .replace("struct refusal_report report={0};", "let report=freshReport();")
      .replace("const char *readbackState=", "const readbackState=")
      .replaceAll(
        "report=original_refusal.report;",
        "report=structuredClone(original_refusal.report);",
      )
      .replaceAll("goto finished;", "break collecting;")
      .replace(
        "report.armed=subscription!=NULL;",
        "collecting:{report.armed=subscription!=NULL;",
      )
      .replace("\nfinished:", "}\n")
      .replace(
        "if(!report)report=&original_refusal.report;",
        "if(!report)report=original_refusal.report;",
      )
      .replace(
        "original_refusal.report=*report;",
        "original_refusal.report=structuredClone(report);",
      )
      .replace(
        "original_refusal.report=report;",
        "original_refusal.report=structuredClone(report);",
      )
      .replaceAll("report->", "report.")
      .replace(/(?<!&)&report\b/gu, "report")
      .replace(
        /const WCHAR \*(channels|paths)\[\]=\{([^;]+)\};/gu,
        "const $1=[$2];",
      )
      .replace("WCHAR from[32],to[32];", "const from={},to={};")
      .replace("WCHAR expression[1024];", "const expression={};")
      .replace("EVT_VARIANT enabled={0};", "const enabled={};")
      .replace(/(signals|handles)\[\]=\{([^}]+)\}/gu, "$1=[$2]")
      .replaceAll("WaitForMultipleObjects(", "yield WaitForMultipleObjects(")
      .replace("FILETIME time;", "const time={};")
      .replace(
        "((ULONGLONG)time.dwHighDateTime<<32)|time.dwLowDateTime",
        "time.ticks",
      )
      .replace(
        "char image[16385],subject[737],identity[33],context[20000];",
        "const image={},subject={},identity={},context={};",
      )
      .replace("char output[32256];", "const output={};")
      .replace(
        "strcpy_s(original_refusal.command,64,reader_command);",
        "original_refusal.command=reader_command;",
      )
      .replace(
        "strncpy_s(original_refusal.source,64,source,_TRUNCATE);",
        "original_refusal.source=source.slice(0,63);",
      )
      .replace(
        "strcpy_s(original_refusal.hash,65,entries[6].pin);",
        "original_refusal.hash=entries[6].pin;",
      )
      .replaceAll(
        "original_refusal.bytes+original_refusal.used",
        "{target:original_refusal.bytes,offset:original_refusal.used}",
      )
      .replaceAll("output+used", "{target:output,offset:used}")
      .replaceAll("identity+i*2", "{target:identity,offset:i*2}")
      .replaceAll("sizeof(original_refusal.bytes)", "32256")
      .replaceAll(
        /sizeof\((output|image|subject|identity|context|enabled)\)/gu,
        (_, name) =>
          ({
            output: 32256,
            image: 16385,
            subject: 737,
            identity: 33,
            context: 20000,
            enabled: 16,
          })[name],
      )
      .replace(
        /(?<!&)&(used|count|event)\b/gu,
        (_, name) => `{get value(){return ${name}},set value(v){${name}=v}}`,
      )
      .replace(/(?<!&)&(refusal_lock|enabled|time)\b/gu, "$1")
      .replaceAll('L"', '"')
      .replace(/\((?:DWORD|ULONGLONG|void)\)/gu, "")
      .replace(
        /\b(?:const )?(?:EVT_HANDLE|HANDLE|DWORD|BOOL|LONGLONG|ULONGLONG|unsigned|size_t|int) /gu,
        "let ",
      );
  const program = new Script(
    [
      ["refusal_remaining", ""],
      ["refusal_publish", "line,report"],
      ["refusal_render_context", "channel"],
      ["refusal_stopped", "report"],
      ["refusal_worker", "unused"],
      ["refusal_reap", ""],
      ["refusal_settle", ""],
      ["refusal_arm", ""],
      ["release_invalidate", ""],
      ["ownership_refusal_collect", "source,line,error"],
    ]
      .map(([name, args]) =>
        name === "refusal_worker"
          ? `function* ${name}(${args}){${project(body(name))}}`
          : `function ${name}(${args}){${project(body(name))}}`,
      )
      .join("\n") +
      "\n({arm:refusal_arm,collect:ownership_refusal_collect,settle:refusal_settle,invalidate:release_invalidate})",
  );
  for (const fault of [
    null,
    "empty",
    "denied",
    "disabled",
    "malformed",
    "event-close",
    "query-close",
    "context-close",
    "channel-close",
    "thread-close",
    "create",
    "query-pending",
    "wait",
    "next-pending",
    "cancel",
    "deadline",
    "record-cap",
    "shared-record-cap",
    "startup-close",
    "byte-cap",
    "publication",
    "write",
    "other-command",
    "unreleased",
    "already-expired",
    "remaining",
    "readback-pending",
    "readback-partial",
    "readback-complete",
    "ready-create",
    "wake-create",
    "stop-create",
    "notification-create",
    "context-create",
    "subscribe-pending",
    "subscription-next-pending",
    "subscription-close",
    "notification-close",
    "reset",
    "handoff",
    "arm-wait",
    "signal",
    "wake-signal",
    "subscribe-zero",
    "next-failed-output",
    "normal-output",
    "failed-dispatch",
    "invalidate",
    "race-before-reset",
    "race-after-empty",
    "arming-expired",
    "context-deadline",
    "arming-stopped",
    "optional-failed-output",
    "next-count",
    "optional-count",
  ]) {
    let tick =
        fault === "already-expired" ? 30001 : fault === "remaining" ? 7000 : 0,
      lastError = 109,
      worker = false,
      locked = false,
      entry,
      iterator,
      pending,
      nativePending = false,
      done = false,
      eventCount = 0,
      drains = 0;
    const calls = [],
      writes = [],
      closed = new Set(),
      blocked = {};
    let serial = 0;
    const text = (v) => (typeof v === "object" ? (v?.text ?? "") : String(v));
    const freshReport = () => ({
      arming: -1,
      armed: false,
      ready: 0,
      delivery: 0,
      requestBound: false,
      interrupted: false,
      handoffError: 0,
      examined: 0,
      records: 0,
      joined: 0,
      malformed: 0,
      renderError: 0,
      closeError: 0,
      query: [-1, -1, -1],
      finished: false,
      truncated: false,
      overBudget: false,
      readbackTokens: 0,
      readbackResources: 0,
      readbackProbes: 0,
      readbackUnavailable: 0,
      readbackStarted: false,
      readbackFinished: false,
      readbackClosure: false,
      requestStatusRecords: 0,
    });
    const handle = (kind) => ({ kind, serial: serial++, next: 0 });
    const advance = (value) => {
      worker = true;
      try {
        iterator ??= entry(null);
        const next = iterator.next(value);
        done = next.done;
        pending = next.value;
      } catch (error) {
        assert.equal(error, blocked);
        nativePending = true;
      } finally {
        worker = false;
      }
    };
    const api = {
      structuredClone,
      freshReport,
      errno: 9,
      NULL: null,
      TRUE: true,
      FALSE: false,
      ERROR_SUCCESS: 0,
      ERROR_ACCESS_DENIED: 5,
      ERROR_NOT_SUPPORTED: 50,
      ERROR_INVALID_DATA: 13,
      ERROR_TIMEOUT: 1460,
      ERROR_NO_MORE_ITEMS: 259,
      RELEASE_UNSTARTED: 0,
      RELEASE_INVALIDATED: 2,
      WAIT_FAILED: 4294967295,
      WAIT_TIMEOUT: 258,
      WAIT_OBJECT_0: 0,
      EvtChannelConfigEnabled: 0,
      EvtVarTypeBoolean: 13,
      EvtQueryChannelPath: 1,
      EvtQueryReverseDirection: 512,
      EvtRenderContextValues: 0,
      EvtSubscribeToFutureEvents: 1,
      EvtSubscribeStrict: 65536,
      original_refusal: {
        tried: false,
        sent: true,
        pid: 43,
        birth: 90,
        tick: 0,
        from: 100,
        to: 0,
        image: {},
        subject: {},
        imageId: {},
        bytes: { text: "" },
        used: 0,
        query: null,
        thread: null,
        report: freshReport(),
        initialized: false,
        latched: false,
        reaped: false,
        createError: 0,
        armWaitError: 0,
        notifyClose: 0,
        reapError: 0,
      },
      original_release: {
        from: 0,
        to: 0,
        status: { value: 0, closureUncertain: false },
      },
      release_capture_name: () => "unstarted",
      original_startup: {
        examined: fault === "shared-record-cap" ? 61 : 0,
        used: 0,
        closure: fault === "startup-close",
      },
      startup_publish: (_output, _capacity, used) => used,
      ownership_released: fault !== "unreleased",
      ownership_count: 1,
      ownership_creation_verified: true,
      reader_command:
        fault === "other-command" ? "ownership-control" : "ownership-output",
      sequence: 46,
      candidate: "a".repeat(40),
      nonce: "b".repeat(32),
      case_record: { accountSid: "S-1-5-21-7" },
      entries: Array.from({ length: 7 }, () => ({
        path: "C:\\fixture\\payload.exe",
        pin: "c".repeat(64),
        file: {
          id: {
            VolumeSerialNumber: 7,
            FileId: { Identifier: Array(16).fill(2) },
          },
        },
      })),
      refusal_lock: {},
      ownership_literal_context: (_context, _maximum, size) => size,
      readback_collect(report) {
        assert.equal(worker, true);
        assert.equal(locked, false);
        assert.equal(api.original_refusal.latched, true);
        assert.ok(
          api.original_refusal.used > 0,
          "Context precedes post-refusal reads",
        );
        calls.push("readback");
        if (!fault?.startsWith("readback-") && fault !== "denied") return;
        report.readbackStarted = true;
        api.refusal_publish(null, report);
        if (fault === "readback-pending") throw blocked;
        Object.assign(report, {
          readbackTokens: 1,
          readbackResources: ["readback-complete", "denied"].includes(fault)
            ? 7
            : 1,
          readbackProbes: ["readback-complete", "denied"].includes(fault)
            ? 10
            : 2,
          readbackUnavailable: ["readback-complete", "denied"].includes(fault)
            ? 0
            : 1,
          readbackFinished: ["readback-complete", "denied"].includes(fault),
        });
        api.refusal_publish(null, report);
      },
      stderr: {},
      GetLastError: () => lastError,
      SetLastError: (v) => {
        lastError = v;
      },
      GetTickCount64: () => tick,
      readback_now: () => (api.original_refusal.latched ? 220 : 95),
      GetSystemTimePreciseAsFileTime: (out) => {
        out.ticks = 200;
      },
      strcmp: (a, b) => Number(a !== b),
      strncmp: (a, b, size) =>
        Number(text(a).slice(0, size) !== text(b).slice(0, size)),
      strlen: (v) => text(v).length,
      AcquireSRWLockExclusive: () => {
        assert.equal(locked, false);
        locked = true;
      },
      ReleaseSRWLockExclusive: () => {
        assert.equal(locked, true);
        locked = false;
      },
      TryAcquireSRWLockExclusive: () => {
        if (fault === "publication") return false;
        assert.equal(locked, false);
        locked = true;
        return true;
      },
      wcscpy_s: (out, _size, v) => {
        out.text = text(v);
      },
      refusal_hex: (v, out) => {
        out.text = Array.from(text(v), (c) =>
          c.charCodeAt(0).toString(16).padStart(4, "0"),
        ).join("");
        return true;
      },
      refusal_time: (v, out) => {
        out.text = String(v);
        return true;
      },
      memcpy: (out, input, size) => {
        const target = out.target ?? out,
          offset = out.offset ?? 0;
        target.text =
          text(target).slice(0, offset) + text(input).slice(0, size);
      },
      sprintf_s(out, _size, format, ...values) {
        let index = 0;
        const rendered = format.replace(
          /%(?:02x|llu|lld|lu|ls|[sud])/gu,
          (match) => {
            const v = values[index++];
            return match === "%02x"
              ? v.toString(16).padStart(2, "0")
              : match.endsWith("s")
                ? text(v)
                : String(Number(v));
          },
        );
        assert.equal(index, values.length);
        api.memcpy(out, rendered, rendered.length);
        return rendered.length;
      },
      swprintf_s(out, _size, format, ...values) {
        out.text = format.replace(/%ls/gu, () => text(values.shift()));
        return out.text.length;
      },
      CreateThread(_sa, _size, callback) {
        calls.push("thread-create");
        entry = callback;
        if (fault === "create") {
          lastError = 5;
          return null;
        }
        return 400;
      },
      CreateEventW(sa, manual, initial, name) {
        assert.deepEqual(
          [sa, manual, initial, name],
          [null, true, false, null],
        );
        const kind = ["ready", "wake", "stop", "notification"][eventCount++];
        assert.equal(worker, kind === "notification");
        if (fault === kind + "-create") {
          lastError = 5;
          return null;
        }
        if (kind === "notification" && fault === "arming-stopped")
          api.original_refusal.stop.signaled = true;
        return { ...handle(kind), signaled: false };
      },
      SetEvent(event) {
        if (
          (fault === "signal" && event.kind === "ready") ||
          (fault === "wake-signal" && event.kind === "wake")
        ) {
          lastError = 6;
          return false;
        }
        event.signaled = true;
        if (
          event.kind === "stop" &&
          iterator &&
          !done &&
          !nativePending &&
          !worker &&
          fault !== "wait"
        )
          advance(0);
        return true;
      },
      ResetEvent(event) {
        assert.equal(worker, true);
        assert.equal(event.kind, "notification");
        calls.push("reset");
        if (fault === "reset") {
          lastError = 6;
          return false;
        }
        event.signaled = false;
        return true;
      },
      WaitForMultipleObjects(count, handles, all, remaining) {
        assert.equal(worker, true);
        assert.equal(locked, false);
        assert.equal(count, 2);
        assert.equal(all, false);
        assert.equal(remaining, Math.max(0, 30000 - tick));
        return Array.from(handles);
      },
      WaitForSingleObject(event, remaining) {
        if (event?.kind === "stop") {
          assert.equal(remaining, 0);
          return event.signaled ? 0 : 258;
        }
        if (event?.kind === "ready") {
          assert.equal(remaining, 30000 - tick);
          if (fault === "arming-expired") tick = 30001;
          advance();
          assert.equal(calls.includes("readback"), false);
          assert.equal(
            calls.includes("next"),
            false,
            "No classification before refusal",
          );
          if (fault === "arm-wait") {
            lastError = 6;
            return 4294967295;
          }
          if (!event.signaled) {
            tick = 30001;
            return 258;
          }
          return 0;
        }
        assert.equal(event, 400);
        if (remaining === 0) return done ? 0 : 258;
        assert.equal(remaining, Math.max(0, 30000 - tick));
        if (fault === "wait") {
          lastError = 6;
          return 4294967295;
        }
        for (let turn = 0; !done && !nativePending; turn++) {
          assert.ok(
            turn < 8,
            "Controlled notifications must settle without polling",
          );
          if (fault === "handoff" && pending[1].kind === "wake") {
            lastError = 6;
            advance(4294967295);
            continue;
          }
          let selected = pending.findIndex((handle) => handle?.signaled);
          if (
            selected < 0 &&
            pending[1]?.kind === "notification" &&
            fault !== "empty"
          ) {
            tick += 7;
            pending[1].signaled = true;
            selected = 1;
          }
          if (selected < 0) tick = 30001;
          advance(selected < 0 ? 258 : selected);
        }
        if (nativePending) tick = 30001;
        return done ? 0 : 258;
      },
      EvtOpenChannelConfig() {
        assert.equal(worker, true);
        assert.equal(locked, false);
        return handle("channel");
      },
      EvtGetChannelConfigProperty(
        _handle,
        _property,
        _flags,
        _size,
        out,
        used,
      ) {
        out.Type = 13;
        out.BooleanVal = fault !== "disabled";
        used.value = 16;
        return true;
      },
      EvtCreateRenderContext(count, paths) {
        assert.equal(worker, true);
        assert.equal(locked, false);
        calls.push("render-context");
        assert.equal(count, 15);
        assert.equal(paths.length, 15);
        assert.equal(
          paths.some((p) => p.includes("Execution")),
          false,
        );
        if (fault === "context-create") {
          lastError = 5;
          return null;
        }
        if (fault === "context-deadline") tick = 30001;
        return handle("context");
      },
      EvtSubscribe(
        session,
        event,
        channel,
        query,
        bookmark,
        context,
        callback,
        flags,
      ) {
        assert.equal(worker, true);
        assert.equal(locked, false);
        assert.deepEqual(
          [session, channel, bookmark, context, callback, flags],
          [null, "Security", null, null, null, 65537],
        );
        assert.ok(query.includes("4656") && query.includes("4503599627370496"));
        calls.push("subscribe");
        if (fault === "subscribe-pending") throw blocked;
        if (fault === "subscribe-zero") {
          lastError = 0;
          return null;
        }
        if (fault === "denied") {
          lastError = 5;
          return null;
        }
        event.signaled = true;
        return handle("subscription");
      },
      EvtQuery(_session, channel, query) {
        assert.equal(worker, true);
        assert.equal(locked, false);
        assert.ok(query.text.includes('"100"') && query.text.includes('"200"'));
        calls.push(`query:${channel}`);
        assert.notEqual(
          channel,
          "Security",
          "The original Security collector has one subscription only",
        );
        if (fault === "query-pending") throw blocked;
        if (fault === "denied") {
          lastError = 5;
          return null;
        }
        return handle("query");
      },
      EvtNext(query, count, out, timeout, _flags, returned) {
        assert.equal(worker, true);
        assert.equal(locked, false);
        assert.deepEqual([count, timeout], [1, 0]);
        calls.push("next");
        if (
          query.kind === "query" &&
          ["optional-failed-output", "optional-count"].includes(fault)
        ) {
          out.value = api.entries[6].file;
          lastError = 5;
          return fault === "optional-count";
        }
        if (query.kind === "subscription") {
          assert.equal(api.original_refusal.latched, true);
          if (fault === "subscription-next-pending") throw blocked;
          if (["next-failed-output", "next-count"].includes(fault)) {
            out.value = api.entries[6].file;
            lastError = 5;
            return fault === "next-count";
          }
          if (drains++ === 0 && fault !== "race-before-reset") {
            if (fault === "race-after-empty") pending[1].signaled = true;
            lastError = 259;
            return false;
          }
          assert.ok(calls.lastIndexOf("reset") === calls.length - 2);
        }
        if (["next-pending", "cancel"].includes(fault)) throw blocked;
        if (
          fault === "empty" ||
          (!["record-cap", "byte-cap"].includes(fault) && query.next++ === 2)
        ) {
          lastError = 259;
          return false;
        }
        returned.value = 1;
        out.value = handle("event");
        if (fault === "deadline") tick = 30001;
        return true;
      },
      refusal_record(context, event, channel, report) {
        assert.equal(worker, true);
        assert.equal(locked, false);
        calls.push("render");
        if (fault === "malformed") {
          report.malformed++;
          return;
        }
        report.records++;
        report.joined += channel === 0;
        report.requestStatusRecords += channel === 0;
        api.refusal_publish(
          "native-windows-original-child: record " +
            "x".repeat(fault === "byte-cap" ? 5000 : 5) +
            "\n",
          report,
        );
      },
      EvtClose(value) {
        assert.equal(worker, true);
        assert.equal(locked, false);
        assert.ok(
          ["event", "context", "query", "subscription", "channel"].includes(
            value.kind,
          ),
          "Failed getter output is not owned",
        );
        assert.equal(closed.has(value), false);
        calls.push(`close:${value.kind}`);
        if (fault === value.kind + "-close") {
          lastError = 7;
          return false;
        }
        closed.add(value);
        return true;
      },
      EvtCancel(query) {
        assert.equal(worker, false);
        assert.equal(locked, true);
        assert.equal(query, api.original_refusal.query);
        assert.equal(
          query.kind,
          "query",
          "EvtCancel never accepts the subscription",
        );
        assert.equal(closed.has(query), false);
        calls.push("cancel");
        lastError = 8;
        return fault !== "cancel";
      },
      CloseHandle(value) {
        assert.equal(worker, value?.kind === "notification");
        assert.equal(closed.has(value), false);
        if (value === 400) {
          assert.equal(done, true);
          calls.push("thread-close");
        } else calls.push(`handle-close:${value.kind}`);
        lastError = 7;
        if (fault === (value === 400 ? "thread-close" : value.kind + "-close"))
          return false;
        closed.add(value);
        return true;
      },
      refusal_transport(value, size) {
        assert.ok(size <= 32256);
        assert.equal(text(value).length, size);
        writes.push(text(value));
        api.errno = 22;
        lastError = 87;
        return fault === "write" ? 0 : size;
      },
      fflush: () => -1,
    };
    const run = program.runInNewContext(api);
    const publisher = new Script(
      `(line,report)=>{${project(body("refusal_publish"))}}`,
    ).runInNewContext(api);
    api.refusal_publish = publisher;
    run.arm();
    const arming = api.original_refusal.report.arming;
    const armedCalls = calls.length;
    run.arm();
    assert.equal(
      calls.length,
      armedCalls,
      "One-shot arming cannot recycle state",
    );
    assert.equal(
      calls.filter((v) => v === "thread-create").length,
      (fault?.endsWith("-create") && eventCount < 4) ||
        fault === "already-expired"
        ? 0
        : 1,
    );
    if (
      [
        "normal-output",
        "failed-dispatch",
        "invalidate",
        "arming-stopped",
      ].includes(fault)
    ) {
      if (["normal-output", "arming-stopped"].includes(fault)) run.settle();
      else run.invalidate();
      assert.equal(calls.includes("readback"), false);
      assert.equal(calls.includes("next"), false);
      if (fault === "arming-stopped") {
        assert.equal(calls.includes("render-context"), false);
        assert.equal(calls.includes("subscribe"), false);
      }
      assert.equal(api.original_refusal.reaped, true);
      const before = calls.length;
      run.settle();
      assert.equal(
        calls.length,
        before,
        "Settlement never closes or rearms twice",
      );
      continue;
    }
    if (["arming-expired", "context-deadline"].includes(fault))
      assert.equal(calls.includes("subscribe"), false);
    const beforeCollect = calls.length;
    run.collect("custody.h", 421, 109);
    assert.equal(
      api.original_refusal.report.arming,
      arming,
      "Refusal preserves native arming evidence",
    );
    assert.equal(lastError, 109, fault);
    assert.equal(api.errno, 9, fault);
    assert.equal(locked, false, fault);
    if (["other-command", "unreleased"].includes(fault)) {
      assert.equal(calls.length, beforeCollect);
      assert.deepEqual(writes, []);
      run.settle();
      assert.equal(api.original_refusal.reaped, true);
      continue;
    }
    const output = writes.join("");
    assert.ok(output.length <= 32256, fault);
    assert.match(
      output,
      /command=ownership-output sequence=46 source=custody.h line=421 error=109/u,
    );
    assert.match(output, /resume-time=unavailable/u);
    assert.match(
      output,
      /capture=unstarted capture-from=0 capture-to=0 capture-status=none\/0/u,
    );
    assert.ok(api.original_refusal.report.examined <= 64);
    if (
      [
        "next-pending",
        "cancel",
        "query-pending",
        "wait",
        "readback-pending",
        "subscribe-pending",
        "subscription-next-pending",
      ].includes(fault)
    ) {
      assert.equal(api.original_refusal.thread, 400);
      assert.equal(calls.includes("thread-close"), false);
      assert.match(output, /incomplete=1/u);
      assert.match(output, /closure-uncertain=1/u);
      assert.equal(
        calls.includes("cancel"),
        ![
          "query-pending",
          "wait",
          "readback-pending",
          "subscribe-pending",
          "subscription-next-pending",
        ].includes(fault),
      );
    } else if (api.original_refusal.thread)
      assert.equal(calls.filter((v) => v === "thread-close").length, 1);
    if (fault === "record-cap" || fault === "shared-record-cap")
      assert.equal(api.original_refusal.report.examined, 64);
    if (fault === "shared-record-cap")
      assert.equal(api.original_refusal.report.records, 3);
    assert.match(
      output,
      new RegExp(
        `readback=${fault === "publication" ? "unavailable" : ["readback-complete", "denied"].includes(fault) ? "complete" : fault?.startsWith("readback-") ? "partial" : "unstarted"}`,
        "u",
      ),
    );
    if (fault === "byte-cap") assert.match(output, /truncated=1/u);
    if (
      [
        "malformed",
        "event-close",
        "query-close",
        "context-close",
        "channel-close",
        "byte-cap",
      ].includes(fault)
    ) {
      assert.equal(
        drains,
        0,
        "Known terminal failure cannot start a subscription wait",
      );
    }
    if (fault === "empty") {
      assert.match(output, /empty=0/u);
      assert.match(output, /incomplete=1/u);
      assert.match(output, /over-budget=1/u);
    }
    if ([null, "race-before-reset", "race-after-empty"].includes(fault)) {
      assert.match(output, /armed=1 arming=0 ready=95 delivery=220 /u);
      assert.equal(api.original_refusal.report.requestStatusRecords, 1);
      assert.equal(calls.filter((v) => v === "subscribe").length, 1);
      assert.equal(calls.filter((v) => v === "thread-create").length, 1);
      assert.equal(drains, fault === "race-before-reset" ? 1 : 2);
    }
    if (
      ["already-expired", "create", "wait", "query-pending"].includes(fault)
    ) {
      assert.match(output, /unavailable=1/u);
      assert.match(output, /incomplete=1/u);
      assert.match(output, /empty=0/u);
    }
    if (fault === "denied") assert.match(output, /inaccessible=1/u);
    if (fault === "subscription-close") {
      assert.ok(api.original_refusal.subscription);
      assert.ok(api.original_refusal.notification);
      assert.equal(calls.includes("handle-close:notification"), false);
    }
    if (fault === "wait") assert.match(output, /wait-error=6/u);
    if (fault?.endsWith("-close"))
      assert.match(
        output,
        /closure-uncertain=1/u,
        `${fault}: ${calls.join(",")}`,
      );
    const before = calls.length;
    run.collect("other.c", 1, 5);
    assert.equal(calls.length, before);
    assert.equal(writes.length, 1);
  }
  const failure = body("reader_failure");
  assert.ok(
    failure.indexOf("ownership_refusal_collect") <
      failure.indexOf("reader_witness_failure"),
  );
});

test("original-child typed events join only supported payload identity, time and failed-access schema", async () => {
  const source = await readFile(
    new URL("custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = (name) => {
    const match = new RegExp(
      `^static [^\\n]+ \\*?${name}\\([^\\n]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "mu",
    ).exec(source);
    assert.ok(match, name);
    return match[1];
  };
  // Replace storage, pointer addresses and integer representation, keeping the
  // native projection, type checks and joins as the executed source bodies.
  const project = (text) =>
    text
      .replace(
        "union { EVT_VARIANT alignment; BYTE bytes[32768]; } buffer;DWORD used=0,count=0;",
        "const buffer={bytes:{address:1000}};let used=0,count=0;",
      )
      .replace(
        "EVT_VARIANT *v=(void *)buffer.bytes;",
        "const v=buffer.bytes.variants;",
      )
      .replace(
        "const unsigned strings[]={0,6,9,10,12,13};",
        "const strings=[0,6,9,10,12,13];",
      )
      .replace(
        "WCHAR subjectText[184]={0};LPWSTR converted=NULL;",
        "const subjectText={};let converted=null;",
      )
      .replace(
        "uintptr_t start=(uintptr_t)value->StringVal,first=(uintptr_t)buffer,last=first+used;",
        "let start=value.StringVal.address,first=buffer.address,last=first+used;",
      )
      .replace(
        "uintptr_t first=(uintptr_t)buffer.bytes,start=(uintptr_t)v[7].SidVal,last=first+used;",
        "let first=buffer.bytes.address,start=v[7].SidVal.address,last=first+used;",
      )
      .replace(
        "((SID *)v[7].SidVal)->SubAuthorityCount",
        "v[7].SidVal.SubAuthorityCount",
      )
      .replace(
        "char p[1025],im[16385],sub[737],ty[1025],obj[16385],why[16385],line[57344];",
        "const p={},im={},sub={},ty={},obj={},why={},line={};",
      )
      .replace(
        "unsigned parts[6]={0},starts[6]={0,5,8,11,14,17};",
        "const parts=Array(6).fill(0),starts=[0,5,8,11,14,17];",
      )
      .replace(
        "WCHAR c=text[starts[i]+j];",
        "let c=text.charCodeAt(starts[i]+j);",
      )
      .replaceAll("c<L'0'||c>L'9'", "c<48||c>57")
      .replaceAll("c-L'0'", "c-48")
      .replaceAll("text[i]-L'0'", "Number(text[i])")
      .replace("SYSTEMTIME time={0};", "const time={};")
      .replace("FILETIME parsed;", "const parsed={};")
      .replace(
        "(((ULONGLONG)parsed.dwHighDateTime<<32)|parsed.dwLowDateTime)",
        "parsed.ticks",
      )
      .replace("WCHAR *end;", "const end={value:''};")
      .replace("bytes[0]=0;", "bytes.text='';")
      .replace("bytes+i*4", "{target:bytes,offset:i*4}")
      .replace("(unsigned)text[i]", "unit(text,i)")
      .replaceAll("*end", "end.value")
      .replace(
        "keywords&4503599627370496ULL",
        "BigInt(keywords)&4503599627370496n",
      )
      .replace(
        "keywords&9007199254740992ULL",
        "BigInt(keywords)&9007199254740992n",
      )
      .replaceAll("&v[strings[i]]", "v[strings[i]]")
      .replace(/&v\[(\d+)\]/gu, "v[$1]")
      .replaceAll("&time,&parsed", "time,&parsed")
      .replace(
        /(?<!&)&(used|count|id|version|time|keywords|pid|logon|mask|birth|converted)\b/gu,
        (_, name) => `{get value(){return ${name}},set value(v){${name}=v}}`,
      )
      .replace(/(?<!&)&(end|parsed)\b/gu, "$1")
      .replace(
        /sizeof\((buffer.bytes|EVT_VARIANT|WCHAR|p|im|sub|ty|obj|why|line)\)/gu,
        (_, name) =>
          ({
            "buffer.bytes": 32768,
            EVT_VARIANT: 16,
            WCHAR: 2,
            p: 1025,
            im: 16385,
            sub: 737,
            ty: 1025,
            obj: 16385,
            why: 16385,
            line: 57344,
          })[name],
      )
      .replaceAll("value->", "value.")
      .replaceAll("report->", "report.")
      .replaceAll(",*", ",")
      .replaceAll("*number", "number.value")
      .replaceAll("*ticks", "ticks.value")
      .replace(/\((?:WORD|ULONGLONG)\)/gu, "")
      .replaceAll("L'", "'")
      .replaceAll('L"', '"')
      .replace(/\bconst WCHAR \*/gu, "let ")
      .replace(/\b(?:DWORD|ULONGLONG|BOOL|unsigned|size_t|int) /gu, "let ");
  const program = new Script(
    [
      ["refusal_text", "value,buffer,used"],
      ["refusal_number", "value,buffer,used,number"],
      ["refusal_event_time", "value,buffer,used,ticks"],
      ["refusal_hex", "text,bytes,capacity"],
      ["refusal_record", "context,event,channel,report"],
    ]
      .map(
        ([name, args]) => `function ${name}(${args}){${project(body(name))}}`,
      )
      .join("\n") + "\nrefusal_record(context,event,channel,report)",
  );
  const text = (value) => value?.text ?? String(value ?? "");
  for (const fault of [
    null,
    "numeric",
    "sid",
    "sid-close",
    "sid-bounds",
    "render",
    "oversized",
    "count",
    "pointer",
    "unterminated",
    "array",
    "pid",
    "missing-pid",
    "image",
    "principal",
    "missing-principal",
    "logon",
    "mask",
    "stale",
    "future",
    "birth",
    "success",
    "provider",
    "version",
    "application",
    "application-birth",
    "application-pid",
    "application-future",
    "code-integrity",
    "long-name",
    "iso",
    "missing-type",
    "empty-type",
    "missing-object",
    "empty-object",
    "missing-mask",
    "zero-mask",
    "wide-mask",
    "unbound",
    "unarmed",
    "late-ready",
    "early-ready",
    "early-delivery",
    "unsealed",
  ]) {
    const string = (value, address = 1400) =>
      Object.assign(new String(value), { address });
    const str = (value) => ({ Type: 1, StringVal: string(value) }),
      num = (value) => str(String(value));
    const v = [
      str("Microsoft-Windows-Security-Auditing"),
      num(4656),
      num(1),
      { Type: 17, FileTimeVal: 150 },
      num(4503599627370496),
      str("0x2b"),
      str("C:\\fixture\\payload.exe"),
      str("S-1-5-21-7"),
      str("0x7"),
      str("File"),
      str("C:\\fixture\\target"),
      str("0x2"),
      str("%%reason"),
      str("%%access"),
      num(90),
    ];
    if (fault === "numeric") v[5] = { Type: 10, UInt64Val: 43 };
    if (fault?.startsWith("sid"))
      v[7] = {
        Type: 19,
        SidVal: {
          address: fault === "sid-bounds" ? 33760 : 1600,
          SubAuthorityCount: 4,
        },
      };
    if (fault === "pointer") v[6].StringVal.address = 999;
    if (fault === "unterminated") v[6].StringVal = string("x".repeat(20000));
    if (fault === "array") v[6].Type = 129;
    if (fault === "pid") v[5] = num(44);
    if (fault === "missing-pid") v[5] = { Type: 0 };
    if (fault === "image") v[6] = str("C:\\other.exe");
    if (fault === "principal") v[7] = str("S-1-5-21-8");
    if (fault === "missing-principal") v[7] = { Type: 0 };
    if (fault === "logon") v[8] = str("7x");
    if (fault === "mask") v[11] = str("-1");
    if (fault === "missing-mask") v[11] = { Type: 0 };
    if (fault === "zero-mask") v[11] = num(0);
    if (fault === "wide-mask") v[11] = num(4294967296);
    if (fault === "missing-type") v[9] = { Type: 0 };
    if (fault === "empty-type") v[9] = str("");
    if (fault === "missing-object") v[10] = { Type: 0 };
    if (fault === "empty-object") v[10] = str("-");
    if (fault === "stale") v[3].FileTimeVal = 99;
    if (fault === "future") v[3].FileTimeVal = 201;
    if (fault === "birth") v[3].FileTimeVal = 80;
    if (fault === "success") v[4] = num(9007199254740992);
    if (fault === "provider") v[0] = str("Other provider");
    if (fault === "version") v[2] = num(2);
    if (fault?.startsWith("application")) {
      v[0] = str("Application Error");
      v[1] = num(1000);
      v[2] = num(0);
      v[14] = num(fault === "application-birth" ? 91 : 90);
      if (fault === "application-pid") v[5] = num(44);
      if (fault === "application-future") v[3].FileTimeVal = 201;
    }
    if (fault === "long-name") v[10] = str("x".repeat(4097));
    if (fault === "iso") v[3] = str("2026-01-02T03:04:05.0000050Z");
    const report = {
        armed: fault !== "unarmed",
        requestBound: fault !== "unbound",
        ready: fault === "late-ready" ? 101 : fault === "early-ready" ? 94 : 96,
        delivery: fault === "early-delivery" ? 199 : 220,
        examined: 1,
        requestStatusRecords: 0,
        records: 0,
        joined: 0,
        malformed: 0,
        renderError: 0,
        closeError: 0,
        truncated: false,
      },
      lines = [];
    const api = {
      context: 11,
      event: 12,
      channel: fault?.startsWith("application")
        ? 1
        : fault === "code-integrity"
          ? 2
          : 0,
      report,
      BigInt,
      errno: 0,
      NULL: null,
      TRUE: true,
      FALSE: false,
      ERROR_INSUFFICIENT_BUFFER: 122,
      MAXDWORD: 4294967295,
      RELEASE_USABLE: 3,
      original_release: {
        state: 3,
        dispatched: fault !== "unsealed",
        to: 95,
        release: 100,
      },
      EvtRenderEventValues: 0,
      ...Object.fromEntries(
        [
          "Null",
          "String",
          "Byte",
          "UInt16",
          "UInt32",
          "UInt64",
          "FileTime",
          "HexInt32",
          "HexInt64",
          "Sid",
        ].map((name, i) => [
          "EvtVarType" + name,
          [0, 1, 4, 6, 8, 10, 17, 20, 21, 19][i],
        ]),
      ),
      original_refusal: {
        from: 100,
        to: 200,
        birth: 90,
        pid: 43,
        image: "C:\\fixture\\payload.exe",
        subject: "S-1-5-21-7",
      },
      EvtRender(_context, _event, _mode, size, buffer, used, count) {
        assert.equal(size, 32768);
        buffer.variants = v;
        used.value = 32768;
        count.value = fault === "count" ? 14 : 15;
        return !["render", "oversized"].includes(fault);
      },
      GetLastError: () => (fault === "oversized" ? 122 : 91),
      wcsnlen_s: (value, limit) => Math.min(value.length, limit),
      wcslen: (value) => text(value).length,
      iswspace: (value) => /\s/u.test(value),
      _wcstoui64(value, end) {
        const input = text(value),
          parsed = /^(?:0x[0-9a-f]+|[0-9]+)$/iu.test(input)
            ? Number(input)
            : NaN;
        end.value = Number.isNaN(parsed) ? "x" : "";
        return parsed;
      },
      SystemTimeToFileTime(time, out) {
        assert.deepEqual(structuredClone(time), {
          wYear: 2026,
          wMonth: 1,
          wDay: 2,
          wHour: 3,
          wMinute: 4,
          wSecond: 5,
        });
        out.ticks = 100;
        return true;
      },
      GetSidLengthRequired: () => 24,
      IsValidSid: () => true,
      ConvertSidToStringSidW(_sid, out) {
        out.value = "S-1-5-21-7";
        return true;
      },
      wcscpy_s: (out, _size, value) => {
        out.text = text(value);
        out[0] = out.text[0];
      },
      LocalFree: () => (fault === "sid-close" ? 1 : 0),
      wcscmp: (a, b) => Number(text(a) !== text(b)),
      _wcsicmp: (a, b) =>
        Number(text(a).toLowerCase() !== text(b).toLowerCase()),
      unit: (value, i) => text(value).charCodeAt(i),
      sprintf_s(out, _size, format, ...values) {
        let at = 0;
        const rendered = format.replace(/%(?:04x|llu|[us])/gu, (match) => {
          const value = values[at++];
          return match === "%04x"
            ? value.toString(16).padStart(4, "0")
            : match === "%s"
              ? text(value)
              : String(Number(value));
        });
        assert.equal(at, values.length);
        const target = out.target ?? out;
        target.text = text(target).slice(0, out.offset ?? 0) + rendered;
        return rendered.length;
      },
      refusal_publish: (line) => lines.push(text(line)),
    };
    program.runInNewContext(api);
    const malformed = [
      "sid-bounds",
      "render",
      "count",
      "pointer",
      "unterminated",
      "array",
      "logon",
      "mask",
    ].includes(fault);
    assert.equal(report.malformed > 0, malformed, fault);
    assert.equal(
      Boolean(report.truncated),
      ["oversized", "long-name"].includes(fault),
      fault,
    );
    const joined = [
      null,
      "numeric",
      "sid",
      "sid-close",
      "application",
      "iso",
    ].includes(fault);
    assert.equal(report.joined, Number(joined), fault);
    if (fault === "sid-close") assert.equal(report.closeError, 91);
    if (lines.length) {
      assert.match(
        lines[0],
        /ready=\d+ delivery=\d+ request-fields=\d capture-bound=\d/u,
      );
      assert.match(lines[0], /pid-available=\d pid=\d/u);
      assert.match(lines[0], new RegExp(`joined=${Number(joined)} `, "u"));
      assert.match(
        lines[0],
        new RegExp(`corroboration=${Number(fault === "application")}\\n$`, "u"),
      );
    }
  }
});

test("actual startup object snapshots ignore failed getter outputs and never adopt borrowed custody", async () => {
  const source = await readFile(
    new URL("custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = /static void startup_objects[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace("JOBOBJECT_BASIC_ACCOUNTING_INFORMATION job={0};", "const job={};")
    .replaceAll("&member", "(v)=>member=v")
    .replaceAll("&job", "job")
    .replaceAll("sizeof(job)", "1")
    .replace("(LONGLONG)!!member", "Number(!!member)")
    .replaceAll("(LONGLONG)", "")
    .replace(/\b(?:BOOL|DWORD|LONGLONG) /gu, "let ");
  for (const failed of [false, true]) {
    const facts = [];
    const api = {
      FALSE: false,
      TRUE: true,
      NULL: null,
      ERROR_SUCCESS: 0,
      FILE_TYPE_UNKNOWN: 0,
      JobObjectBasicAccountingInformation: 1,
      case_job: 11,
      ownership_output: 12,
      original_startup: { state: Array(9).fill(0) },
      startup_take: () => true,
      SetLastError: () => {},
      GetLastError: () => 5,
      IsProcessInJob(process, job, out) {
        assert.deepEqual([process, job], [42, 11]);
        out(true);
        return !failed;
      },
      QueryInformationJobObject(_job, _kind, out) {
        out.ActiveProcesses = 99;
        return !failed;
      },
      GetFileType(handle) {
        assert.equal(handle, 12);
        return failed ? 0 : 3;
      },
      startup_fact: (...values) => facts.push(values),
      CloseHandle: assert.fail,
    };
    new Script(`(function(process){${body}})(42)`).runInNewContext(api);
    assert.equal(facts.length, 1);
    assert.equal(api.original_startup.state[6], failed ? 6 : 1);
    assert.deepEqual(
      facts[0].slice(2),
      failed ? [-1, 5, 5, -1, -1, 5] : [1, 0, 0, 99, 3, 0],
    );
  }
});

test("actual startup summaries retain every class, interval and independent cleanup uncertainty", async () => {
  const source = await readFile(
    new URL("custody-reader.c", import.meta.url),
    "utf8",
  );
  const body = /static DWORD startup_publish[^\n]+\{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll("report->", "report.")
    .replaceAll("output+used", "({offset:used})")
    .replace(/\((?:DWORD)\)/gu, "")
    .replace(/\b(?:BOOL|unsigned|DWORD|int) /gu, "let ");
  for (const fault of [
    null,
    "identity",
    "closure",
    "query-close",
    "unpublished",
    "expired",
  ]) {
    const lines = [];
    const context = {
      ERROR_NOT_SUPPORTED: 50,
      RELEASE_USABLE: 3,
      original_startup: {
        bound: true,
        pid: 42,
        birth: 90,
        from: 100,
        to: 110,
        closure: fault === "closure",
        cleanup: fault === "closure" ? 7 : 0,
        state: [0, 1, 2, 3, 6, 3, 1, 3, 5],
        error: [0, 0, 0, 0, 5, 0, 0, 0, 0],
      },
      original_refusal: {
        pid: 42,
        birth: fault === "identity" ? 91 : 90,
        from: 120,
        to: 130,
      },
      original_release: { state: 3, dispatched: true, release: 120 },
      startup_classes: Array.from({ length: 9 }, (_, i) => `fixture-${i}`),
      startup_states: [
        "missing",
        "observed",
        "empty",
        "unsupported",
        "expired",
        "truncated",
        "failed",
      ],
      refusal_remaining: () => (fault === "expired" ? 0 : 10),
      snprintf(target, capacity, format, ...values) {
        let at = 0;
        const line = format.replace(/%(?:llu|lu|u|s)/gu, (specifier) =>
          specifier === "%s"
            ? String(values[at++])
            : String(Number(values[at++])),
        );
        assert.ok(line.length < capacity);
        lines.push(line);
        return line.length;
      },
    };
    const render = new Script(
      `(function(output,capacity,used,report,published){${body}})`,
    ).runInNewContext(context);
    const report = {
      query: [0, 0, 0],
      armed: true,
      finished: true,
      overBudget: fault === "expired",
      requestStatusRecords: 0,
      malformed: 0,
      renderError: 0,
      closeError: fault === "query-close" ? 9 : 0,
    };
    const before = structuredClone(report);
    const used = render({}, 4096, 0, report, fault !== "unpublished");
    assert.equal(lines.length, 9);
    assert.ok(used <= 4096 - 1024);
    assert.ok(
      lines.every((line) => line.endsWith("first-request=unobserved\n")),
    );
    assert.match(
      lines[0],
      fault === "expired"
        ? /state=expired /u
        : fault === "unpublished"
          ? /state=missing /u
          : fault === "query-close"
            ? /state=failed /u
            : /state=expired /u,
    );
    assert.match(lines[0], /from=120 to=130 /u);
    assert.match(lines[1], /from=100 to=110 /u);
    assert.ok(
      lines.every((line) =>
        line.includes(`bound=${Number(fault !== "identity")} `),
      ),
    );
    for (const [i, line] of lines.entries())
      assert.ok(
        line.includes(
          `closure-uncertain=${Number(i ? fault === "closure" : fault === "query-close" || fault === "unpublished")} `,
        ),
      );
    assert.match(
      lines[0],
      new RegExp(`cleanup=${fault === "query-close" ? 9 : 0} `, "u"),
    );
    assert.match(lines[3], /state=unsupported /u);
    if (fault === "unpublished")
      assert.match(lines[1], /state=truncated .*published=0 /u);
    assert.deepEqual(report, before);
  }
});
