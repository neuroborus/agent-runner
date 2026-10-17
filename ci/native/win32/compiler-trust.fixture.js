import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { PassThrough, Writable } from "node:stream";
import { Script } from "node:vm";

import { windowsCustodyChannel } from "./channel.js";
import { digest } from "./protocol.js";

// Execute the actual open, pin, PE/experiment, trust and diagnostic bodies with
// injected kernel/SDK reads. No native compiler, process or trust store is used.
export async function compilerTrustFixture({
  entries,
  files,
  identity,
  inspect,
  result = 0,
  closed = 0,
  unavailable = false,
}) {
  const header = await readFile(
      new URL("./custody.h", import.meta.url),
      "utf8",
    ),
    reader = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = (source, name) =>
      new RegExp(
        `static void ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)[1],
    calls = [],
    records = [],
    signature_trust = { inputs: {} },
    refusal = new Error("native guard rejected"),
    held = entries.map((entry) => ({
      ...entry,
      pin: entry.sha256,
      signature: entry.signatureSha256,
      file: {},
    }));
  const text = (value) => value?.text ?? value,
    translate = (source) =>
      source
        .replace(
          /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#else\n[\s\S]*?#endif/gu,
          "$1",
        )
        .replace(
          "DWORD size; BYTE *bytes = read_file(file, 536870912, &size);",
          "let bytes = read_file(file), size = bytes.length;",
        )
        .replace(
          "IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)bytes;",
          "let dos = {e_magic: bytes.readUInt16LE(0), e_lfanew: bytes.readUInt32LE(60)};",
        )
        .replace(
          "IMAGE_NT_HEADERS64 *pe = (IMAGE_NT_HEADERS64 *)(bytes + dos->e_lfanew);",
          "let pe = headers(bytes, dos.e_lfanew);",
        )
        .replace("IMAGE_DATA_DIRECTORY cert", "let cert")
        .replace(
          "IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(pe);",
          "let sections = pe.sections;",
        )
        .replace(
          "(BYTE *)(sections + pe->FileHeader.NumberOfSections) <= bytes + size",
          "pe.sectionEnd <= size",
        )
        .replace(
          'static const char marker[] = "native-ci-experiment-v1";',
          'const marker = "native-ci-experiment-v1\\0";',
        )
        .replaceAll("sizeof(marker)", "marker.length")
        .replaceAll(
          "bytes + sections[i].PointerToRawData",
          "bytes.subarray(sections[i].PointerToRawData)",
        )
        .replaceAll(
          "bytes + cert.VirtualAddress",
          "bytes.subarray(cert.VirtualAddress)",
        )
        .replace(
          "WINTRUST_FILE_INFO info = {sizeof(info), file->path, file->handle, NULL};",
          "let info = {cbStruct:1, pcwszFilePath: file.path, hFile: file.handle, pgKnownSubject:null};",
        )
        .replace(
          "WINTRUST_DATA trust = {0};",
          "let trust = {dwUIContext:0,pPolicyCallbackData:null,pSIPClientData:null,hWVTStateData:null};",
        )
        .replace(
          "DWORD saved = GetLastError(), flags = 0;",
          "let saved = GetLastError(); const flags = {value:0};",
        )
        .replace(
          "LARGE_INTEGER size = {0}, position = {0}, zero = {0};",
          "const size = {QuadPart:0}, position = {QuadPart:0}, zero = {QuadPart:0};",
        )
        .replace("WINTRUST_FILE_INFO *info", "let info")
        .replaceAll("sizeof(signature_trust.inputs)", "512")
        .replace("(LONGLONG)flags", "flags.value")
        .replace(
          "GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;",
          "let action = 0;",
        )
        .replace(
          'char bytes[1024], index[8] = "null", pin[68] = "null", expected[68] = "null", identity[50]; DWORD written;',
          'let bytes={}, index={text:"null"}, pin={text:"null"}, expected={text:"null"}, identity={}, written;',
        )
        .replace("char bytes[256]; DWORD written;", "let bytes={}, written;")
        .replace("struct held_file *file", "let file")
        .replace(
          "struct entry *entry = &entries[index]",
          "let entry = entries[index]",
        )
        .replace("const char *source", "let source")
        .replace("source+1", "source.slice(1)")
        .replaceAll("identity+17+i*2", "{target:identity, offset:17+i*2}")
        .replaceAll("&entries[i].file", "entries[i].file")
        .replaceAll("&entry->file", "entry.file")
        .replace(/char (\w+)\[65\]/gu, "let $1={}")
        .replace(
          /sizeof\((bytes|index|pin|expected|identity|trust|IMAGE_NT_HEADERS64)\)/gu,
          (_, name) =>
            ({
              bytes: source.includes("char bytes[256]") ? 256 : 1024,
              index: 8,
              pin: 68,
              expected: 68,
              identity: 50,
              trust: 1,
              IMAGE_NT_HEADERS64: 264,
            })[name],
        )
        .replaceAll("&written", "NULL")
        .replace(/&(action|trust|info|flags|size|position)\b/gu, "$1")
        .replace(/\(unsigned long\)|\(DWORD\)|\(LONGLONG\)/gu, "")
        .replace(/\b(?:unsigned|DWORD|LONG|BOOL|int) /gu, "let ")
        .replaceAll("->", ".")
        .replaceAll("\\036", "\\x1e");
  const open = reader
    .split('} else if (!strcmp(values[0], "open")) {')[1]
    .split('} else if (!strcmp(values[0], "inspect"))')[0];
  let program, activeTrust;
  const verifiedHandles = new Set();
  const api = {
    entries: held,
    count: held.length,
    sequence: 0,
    reader_command: "open",
    reader_diagnostics_ready: true,
    signature_trust,
    control: "authenticated",
    NULL: null,
    INVALID_HANDLE_VALUE: -1,
    TRUE: true,
    FALSE: false,
    ERROR_SUCCESS: 0,
    WTD_CHOICE_FILE: 1,
    WTD_UI_NONE: 2,
    WTD_REVOKE_NONE: 0,
    WTD_STATEACTION_VERIFY: 1,
    WTD_STATEACTION_CLOSE: 2,
    WTD_CACHE_ONLY_URL_RETRIEVAL: 0x1000,
    WTD_REVOCATION_CHECK_NONE: 0x10,
    IMAGE_DOS_SIGNATURE: 0x5a4d,
    IMAGE_NT_SIGNATURE: 0x4550,
    IMAGE_FILE_MACHINE_AMD64: 0x8664,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC: 0x20b,
    IMAGE_DIRECTORY_ENTRY_SECURITY: 4,
    IMAGE_SCN_MEM_EXECUTE: 0x20000000,
    IMAGE_SCN_MEM_WRITE: 0x80000000,
    GENERIC_READ: 1,
    ACCESS_SYSTEM_SECURITY: 2,
    FILE_LIST_DIRECTORY: 4,
    FILE_ADD_FILE: 8,
    FILE_ADD_SUBDIRECTORY: 16,
    FILE_CURRENT: 1,
    WRITE_DAC: 32,
    WRITE_OWNER: 64,
    stderr: null,
    need: (ok) => {
      if (ok) return;
      program.reader_failure("custody.h", 1);
      throw refusal;
    },
    GetLastError: () => 7,
    SetLastError: () => {},
    GetHandleInformation: (_, flags) => {
      flags.value = 0;
      return !unavailable;
    },
    GetFileSizeEx: (_, size) => {
      size.QuadPart = 1024;
      return !unavailable;
    },
    SetFilePointerEx: (_, zero, position, method) => {
      assert.equal(zero.QuadPart, 0);
      assert.equal(method, 1);
      position.QuadPart = 1024;
      return !unavailable;
    },
    wcslen: (path) => path.length,
    WinVerifyTrust: (window, _, trust) => {
      assert.equal(window, api.INVALID_HANDLE_VALUE);
      const entry = held[api.openIndex],
        file = entry.file;
      assert.equal(trust.dwUnionChoice, 1);
      assert.equal(trust.dwUIChoice, 2);
      assert.equal(trust.fdwRevocationChecks, 0);
      assert.equal(trust.dwProvFlags, 0x1010);
      assert.equal(trust.pFile.pcwszFilePath, entry.path);
      assert.equal(trust.pFile.pcwszFilePath, file.path);
      assert.equal(trust.pFile.hFile, file.handle);
      assert.ok(file.handle.access & api.GENERIC_READ);
      calls.push(trust.dwStateAction);
      if (trust.dwStateAction === 2) {
        assert.equal(
          trust,
          activeTrust,
          "close the original verification state",
        );
        activeTrust = undefined;
        assert.equal(signature_trust.result, result, "save before closure");
        return closed;
      }
      assert.equal(trust.dwStateAction, 1);
      assert.equal(activeTrust, undefined);
      assert.ok(!verifiedHandles.has(file.handle), "never retry verification");
      verifiedHandles.add(file.handle);
      activeTrust = trust;
      return result;
    },
    headers: (bytes, at) => {
      const optional = at + 24,
        sections = optional + bytes.readUInt16LE(at + 20),
        count = bytes.readUInt16LE(at + 6);
      return {
        Signature: bytes.readUInt32LE(at),
        FileHeader: {
          Machine: bytes.readUInt16LE(at + 4),
          NumberOfSections: count,
        },
        OptionalHeader: {
          Magic: bytes.readUInt16LE(optional),
          NumberOfRvaAndSizes: bytes.readUInt32LE(optional + 108),
          DataDirectory: Array.from({ length: 5 }, (_, i) => ({
            VirtualAddress: bytes.readUInt32LE(optional + 112 + i * 8),
            Size: bytes.readUInt32LE(optional + 116 + i * 8),
          })),
        },
        sectionEnd: sections + count * 40,
        sections: Array.from({ length: count }, (_, i) => ({
          Name: bytes.subarray(sections + i * 40, sections + i * 40 + 8),
          SizeOfRawData: bytes.readUInt32LE(sections + i * 40 + 16),
          PointerToRawData: bytes.readUInt32LE(sections + i * 40 + 20),
          Characteristics: bytes.readUInt32LE(sections + i * 40 + 36),
        })),
      };
    },
    read_file: (file) => file.bytes,
    sum: (bytes, size, actual) => {
      actual.text = digest(bytes.subarray(0, size));
    },
    strcmp: (a, b) => (text(a) === text(b) ? 0 : 1),
    memcmp: (a, b, size) =>
      Buffer.compare(
        Buffer.from(a).subarray(0, size),
        Buffer.from(b).subarray(0, size),
      ),
    free: () => {},
    fprintf: () => {},
    catalog_signature: () => assert.fail("no diagnostic verification fallback"),
    bounded_number: (value, maximum) => {
      const index = Number(value);
      assert.ok(Number.isInteger(index) && index >= 0 && index <= maximum);
      return index;
    },
    stock_entry: () => true,
    bridge_entry: () => false,
    stock_security: () => {},
    bridge_security: () => {},
    hold_shared: (path, _directory, _private, access) => {
      const [volume, id] = identity(path).split(":");
      return {
        handle: Object.freeze({ access }),
        path,
        bytes: files.get(path),
        id: {
          VolumeSerialNumber: BigInt("0x" + volume),
          FileId: { Identifier: Buffer.from(id, "hex") },
        },
      };
    },
    inspect: (entry) => {
      api.observation = inspect(entry);
    },
    strrchr: (file, separator) => {
      const index = file.lastIndexOf(separator);
      return index < 0 ? null : file.slice(index);
    },
    sprintf_s: (destination, maximum, format, ...values) => {
      let index = 0;
      const value = format.replace(
        /%(016llx|08lx|02x|lld|lu|[sud])/gu,
        (_, type) => {
          const value = values[index++];
          if (type.endsWith("x"))
            return BigInt.asUintN(type === "016llx" ? 64 : 32, BigInt(value))
              .toString(16)
              .padStart(parseInt(type), "0");
          return type === "s" ? text(value) : Number(value);
        },
      );
      assert.ok(Buffer.byteLength(value) < maximum);
      const target = destination.target ?? destination,
        offset = destination.offset ?? 0;
      target.text = (target.text ?? "").slice(0, offset) + value;
      return value.length;
    },
    WriteFile: (control, bytes, size) => {
      assert.equal(control, "authenticated");
      records.push(bytes.text.slice(0, size));
      return true;
    },
  };
  program = new Script(`
    function signature_observe(file,trust) {${translate(body(header, "signature_observe"))}}
    function signature_verify(file,expected,trust) {${translate(body(header, "signature_verify"))}}
    function pin(file,expected) {${translate(body(header, "pin"))}}
    function signature(file,expected,actual) {${translate(body(header, "signature"))}}
    function reader_trust_failure(source,line) {${translate(body(reader, "reader_trust_failure"))}}
    function reader_failure(file,line) {${translate(body(reader, "reader_failure"))}}
    function open_entry(values) { let n=values.length; ${translate(open)} }
    ({open_entry,reader_failure});
  `).runInNewContext(api);
  return {
    calls,
    get inputs() {
      return JSON.parse(signature_trust.inputs.text);
    },
    async open(index, sequence) {
      api.sequence = sequence;
      api.openIndex = index;
      try {
        program.open_entry(["open", String(sequence), String(index)]);
        return api.observation;
      } catch (cause) {
        if (cause !== refusal) throw cause;
        assert.ok(
          records.length,
          "native guard must emit its original diagnosis",
        );
        const child = new EventEmitter();
        child.pid = 10;
        child.stdin = new Writable({ write: (_, __, done) => done() });
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        const channel = windowsCustodyChannel(child, {
            schedule: () => 1,
            cancel: () => {},
          }),
          response = channel.receive();
        child.stdout.write(`{"sequence":${sequence},"value":`);
        for (const record of records) {
          child.stdout.write(record.slice(0, 25));
          child.stdout.write(record.slice(25));
        }
        const error = await response.catch((error) => error);
        await assert.rejects(channel.completion);
        assert.throws(() => channel.settle());
        child.emit("close", 126, null);
        channel.close();
        throw error;
      }
    },
  };
}
