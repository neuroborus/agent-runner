import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { Script } from "node:vm";

import {
  createWindowsEffectiveReaders,
  normalizeWindowsBarrierRead,
  assertWindowsWfpFilterRead,
} from "./index.js";
import {
  effectiveFixture,
  hash,
  fileId,
  candidateSha,
} from "./effective.fixture.js";
import { digest } from "./protocol.js";
import { encode } from "./custody-protocol.js";
import { observationDigest } from "../index.js";

// Execute the retained diagnostic bodies with opaque SDK storage and injected
// calls. This projection changes C representations, never the branch policy.
function readbackNative(source, fault) {
  const sizes = {
    LUID: 8,
    ACE_HEADER: 4,
    ACL: 8,
    TOKEN_USER: 16,
    TOKEN_MANDATORY_LABEL: 16,
    TOKEN_MANDATORY_POLICY: 4,
    SID_AND_ATTRIBUTES: 16,
    LUID_AND_ATTRIBUTES: 12,
  };
  const types =
    "GENERIC_MAPPING|TOKEN_STATISTICS|TOKEN_GROUPS|TOKEN_PRIVILEGES|TOKEN_USER|TOKEN_MANDATORY_LABEL|TOKEN_MANDATORY_POLICY|PSECURITY_DESCRIPTOR|SECURITY_INFORMATION|TOKEN_INFORMATION_CLASS|SE_OBJECT_TYPE|FILE_ID_INFO|SYSTEM_MANDATORY_LABEL_ACE|ACCESS_ALLOWED_ACE|BCRYPT_ALG_HANDLE|BCRYPT_HASH_HANDLE|PPRIVILEGE_SET|NTSTATUS|uintptr_t|size_t|HANDLE|PACL|PSID|WCHAR|DWORD|BOOL|BYTE|unsigned char|unsigned|char|void|int";
  const names = [
    "file_sd_query",
    "access_result",
    "readback_fail",
    "readback_ready",
    "readback_cleanup",
    "readback_close",
    "readback_free",
    "readback_query",
    "readback_statistics",
    "readback_same",
    "readback_sid_inside",
    "readback_sid",
    "readback_sid_equal",
    "readback_metadata",
    "readback_hash",
    "readback_sd",
    "readback_access",
    "readback_range",
    "readback_label",
    "readback_mic",
    "readback_aces",
    "readback_describe",
  ];
  const project = (name) => {
    const match = new RegExp(
      `static [^\\n]+ ${name}\\(([^\\n]*)\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source);
    assert.ok(match, name);
    const args = match[1]
      .split(",")
      .map((arg) => /([a-zA-Z_]\w*)(?:\[\d+\])?$/u.exec(arg.trim())[1])
      .join(",");
    let body = match[2]
      .replaceAll("->", ".")
      .replace(/\(GENERIC_MAPPING\)\{([^}]+)\}/gu, "[$1]")
      .replace(/sizeof\(\*(statistics|actual|expected)\)/gu, (_, kind) =>
        kind === "statistics" ? "56" : "24",
      )
      .replaceAll("sizeof(after)", "24")
      .replaceAll("sizeof(value.restricting)", "1473")
      .replace(/sizeof\((\w+)\)/gu, (all, kind) => sizes[kind] ?? all)
      .replaceAll("FIELD_OFFSET(TOKEN_GROUPS,Groups)", "8")
      .replaceAll("FIELD_OFFSET(TOKEN_PRIVILEGES,Privileges)", "4")
      .replace(
        new RegExp(`\\((?:const )?(?:${types})(?:\\s*\\*)*\\)`, "gu"),
        "",
      )
      .replace(/\b(?:BYTE|char) (digest|privileges|sid)\[\d+\]/gu, "var $1=[]")
      .replace("FILE_ID_INFO after;", "var after={};")
      .replace(/\*(GetSidSubAuthority(?:Count)?\()/gu, "$1")
      .replace(
        /\*(used|granted|allowed|level|mask|defaulted|identified)\b/gu,
        "$1.value",
      )
      .replace(
        /(?<!&)&(object\.(?:identified|daclPresent|level|label|labelDefaulted))\b/gu,
        (_, path) => `ref(()=>${path},v=>${path}=v)`,
      )
      .replace(
        /(?<!&)&(sd|wide|algorithm|hash|token|used|size|owner|acl|sacl|present|unused|defaulted|ace)\b(?!\.)/gu,
        (_, path) => `ref(()=>${path},v=>${path}=v)`,
      )
      .replace(
        /(?<!&)&((?:before|after|value|object)\.\w+|ace\.SidStart|after)\b/gu,
        "$1",
      )
      .replace(/(?<!&)&mapping\b/gu, "mapping")
      .replace(/\bvalue\.restricting\+offset/gu, "at(value.restricting,offset)")
      .replace(/\btext\+i\*2/gu, "at(text,i*2)")
      .replace(/\btext\+offset/gu, "at(text,offset)")
      .replace(
        new RegExp(
          `\\b(?:const )?(?:struct readback_\\w+|${types}) \\*?`,
          "gu",
        ),
        "var ",
      );
    const label = /\n(?:finished|refused):/u.exec(body);
    if (label)
      body =
        "sampling:{" +
        body
          .slice(0, label.index)
          .replace(/goto (?:finished|refused);/gu, "break sampling;") +
        "}\n" +
        body.slice(label.index + label[0].length);
    return `function ${name}(${args}){${body}}`;
  };
  const text = (value) =>
    Array.isArray(value)
      ? value
          .slice(0, value.indexOf(0) < 0 ? value.length : value.indexOf(0))
          .map((v) => String.fromCharCode(v))
          .join("")
      : String(value);
  const wide = (value) => [...value].map((v) => v.charCodeAt(0)).concat(0);
  const memory = (address, fields = {}) =>
    Object.assign(fields, { valueOf: () => address });
  const sidText = new Map([
    [1016, "S-1-5-21-7001"],
    [1032, "S-1-5-21-7002"],
    [1048, "S-1-16-4096"],
    [2016, "S-1-5-18"],
    [2220, "S-1-5-18"],
    [2328, "S-1-16-8192"],
  ]);
  const calls = [],
    settled = new Set();
  let remaining = 30000,
    error = 109,
    statistics = 0;
  const ref = (get, set) => ({
    get value() {
      return get();
    },
    set value(v) {
      set(v);
    },
  });
  const settle = (value) => {
    assert.ok(!settled.has(value), "Temporary resources settle once");
    assert.notEqual(value, 7, "The retained token is borrowed");
    assert.notEqual(value, 1, "The held file is borrowed");
    settled.add(value);
  };
  const descriptor = () =>
    memory(2000, {
      owner: 2016,
      dacl: memory(2200, {
        AclSize: 64,
        AceCount: 1,
        ace: memory(2212, {
          Header: {
            AceType: fault === "unsupported-ace" ? 9 : 0,
            AceFlags: 0,
            AceSize: 20,
          },
          Mask: 1,
          SidStart: 2220,
        }),
      }),
      sacl: memory(2300, {
        AclSize: 64,
        AceCount: 1,
        ace: memory(2320, {
          Header: { AceType: 17, AceFlags: 0, AceSize: 20 },
          Mask: fault === "unsupported-label" ? 8 : 7,
          SidStart: 2328,
        }),
      }),
    });
  const api = {
    ref,
    at: (target, offset) => ({ target, offset }),
    NULL: null,
    TRUE: true,
    FALSE: false,
    INVALID_HANDLE_VALUE: -1,
    ERROR_TIMEOUT: 1460,
    ERROR_INVALID_DATA: 13,
    ERROR_INVALID_SID: 1337,
    ERROR_INVALID_HANDLE: 6,
    ERROR_INVALID_SECURITY_DESCR: 1338,
    ERROR_INVALID_ACL: 1336,
    ERROR_NOT_SUPPORTED: 50,
    ERROR_INSUFFICIENT_BUFFER: 122,
    ERROR_NOT_ENOUGH_MEMORY: 8,
    ERROR_ACCESS_DENIED: 5,
    OWNER_SECURITY_INFORMATION: 1,
    GROUP_SECURITY_INFORMATION: 2,
    DACL_SECURITY_INFORMATION: 4,
    SACL_SECURITY_INFORMATION: 8,
    LABEL_SECURITY_INFORMATION: 16,
    READ_CONTROL: 0x20000,
    ACCESS_SYSTEM_SECURITY: 0x1000000,
    FILE_READ_ATTRIBUTES: 128,
    FILE_SHARE_READ: 1,
    FILE_SHARE_WRITE: 2,
    FILE_SHARE_DELETE: 4,
    FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
    FILE_FLAG_BACKUP_SEMANTICS: 0x2000000,
    FileIdInfo: 18,
    SE_FILE_OBJECT: 1,
    FILE_GENERIC_READ: 0x120089,
    FILE_GENERIC_WRITE: 0x120116,
    FILE_GENERIC_EXECUTE: 0x1200a0,
    FILE_ALL_ACCESS: 0x1f01ff,
    FILE_DELETE_CHILD: 64,
    DELETE: 0x10000,
    WRITE_DAC: 0x40000,
    WRITE_OWNER: 0x80000,
    SYNCHRONIZE: 0x100000,
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP: 1,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: 1,
    SYSTEM_MANDATORY_LABEL_NO_READ_UP: 2,
    SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: 4,
    SECURITY_MANDATORY_MEDIUM_RID: 8192,
    SID_MAX_SUB_AUTHORITIES: 15,
    SECURITY_DESCRIPTOR_MIN_LENGTH: 20,
    ACCESS_ALLOWED_ACE_TYPE: 0,
    ACCESS_DENIED_ACE_TYPE: 1,
    SYSTEM_AUDIT_ACE_TYPE: 2,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE: 17,
    TokenStatistics: 10,
    TokenUser: 1,
    TokenRestrictedSids: 11,
    TokenPrivileges: 3,
    TokenIntegrityLevel: 25,
    TokenMandatoryPolicy: 27,
    SecurityImpersonation: 2,
    BCRYPT_SHA256_ALGORITHM: "SHA256",
    refusal_remaining: () => (fault === "expired" ? 0 : remaining),
    GetLastError: () => error,
    memset(out) {
      for (const key of Object.keys(out)) delete out[key];
    },
    calloc: () => memory(1000),
    free: (bytes) => {
      if (bytes) settle(bytes);
    },
    memcmp: (a, b) => Number(JSON.stringify(a) !== JSON.stringify(b)),
    strcmp: (a, b) => Number(text(a) !== text(b)),
    strnlen_s: (value, limit) => Math.min(text(value).length, limit),
    wcsnlen_s: (value, limit) => Math.min(text(value).length, limit),
    strcpy_s(out, capacity, value) {
      api.snprintf(out, capacity, "%s", value);
    },
    snprintf(out, capacity, format, ...values) {
      const result = format.replace(/%(?:02x|lu|[su])/gu, (match) => {
        const value = values.shift();
        return match === "%02x"
          ? value.toString(16).padStart(2, "0")
          : match === "%s"
            ? text(value)
            : String(value);
      });
      assert.equal(values.length, 0);
      const target = out.target ?? out,
        offset = out.offset ?? 0;
      for (let i = 0; i < Math.min(result.length, capacity - 1); i++)
        target[offset + i] = result.charCodeAt(i);
      target[offset + Math.min(result.length, capacity - 1)] = 0;
      return result.length;
    },
    GetTokenInformation(token, kind, out, capacity, used) {
      assert.equal(token, 7);
      calls.push(`token:${kind}`);
      used.value = kind === 10 ? 56 : 512;
      if (kind === 10) {
        statistics++;
        Object.assign(out, {
          TokenId: 1,
          AuthenticationId: 2,
          ModifiedId: fault === "statistics-changed" && statistics > 1 ? 4 : 3,
          ExpirationTime: { QuadPart: 99 },
          TokenType: 1,
          ImpersonationLevel: 0,
          DynamicCharged: 1,
          DynamicAvailable: 2,
          GroupCount: 1,
          PrivilegeCount: 1,
        });
        if (fault === "statistics-last" && statistics === 2) {
          error = 5;
          return false;
        }
      } else if (kind === 1) out.User = { Sid: 1016 };
      else if (kind === 11)
        Object.assign(out, { GroupCount: 1, Groups: [{ Sid: 1032 }] });
      else if (kind === 3) out.PrivilegeCount = 1;
      else if (kind === 25) out.Label = { Sid: 1048 };
      else out.Policy = 1;
      if (fault === "token-query" && kind === 1) {
        error = 5;
        return false;
      }
      assert.ok(used.value <= capacity);
      return true;
    },
    GetSidSubAuthorityCount: (sid) => sidText.get(sid).split("-").length - 3,
    GetSidSubAuthority: (sid) => Number(sidText.get(sid).split("-").at(-1)),
    GetLengthSid: (sid) => 8 + 4 * (sidText.get(sid).split("-").length - 3),
    IsValidSid: (sid) => sidText.has(sid),
    ConvertSidToStringSidW(sid, out) {
      out.value = wide(sidText.get(sid));
      if (fault === "sid-projection") {
        error = 5;
        return false;
      }
      return true;
    },
    GetFileInformationByHandleEx(handle, _kind, out) {
      calls.push(`id:${handle}`);
      Object.assign(out, {
        volume: 1,
        id: fault === "reopen-identity" && handle === 2 ? 3 : 2,
      });
      return true;
    },
    GetSecurityInfo(handle, kind, flags, _owner, _group, _dacl, _sacl, out) {
      assert.deepEqual([kind, flags], [1, 31]);
      calls.push(`sd:${handle}`);
      out.value = descriptor();
      return handle === 1 && fault?.startsWith("reopen-") ? 5 : 0;
    },
    ReOpenFile(handle, access, sharing, flags) {
      assert.deepEqual(
        [handle, access, sharing, flags],
        [1, 0x1020080, 7, 0x2200000],
      );
      calls.push("reopen");
      return 2;
    },
    IsValidSecurityDescriptor: () => true,
    GetSecurityDescriptorLength: () => 512,
    IsValidAcl: () => true,
    GetSecurityDescriptorOwner(sd, owner) {
      owner.value = sd.owner;
      return true;
    },
    GetSecurityDescriptorDacl(sd, present, acl) {
      present.value = true;
      acl.value = sd.dacl;
      if (fault === "dacl-query") {
        error = 5;
        return false;
      }
      return true;
    },
    GetSecurityDescriptorSacl(sd, present, acl) {
      present.value = fault !== "default-label";
      acl.value = sd.sacl;
      return true;
    },
    GetAce(acl, _index, out) {
      out.value = acl.ace;
      return true;
    },
    DuplicateToken(token, level, out) {
      assert.deepEqual([token, level], [7, 2]);
      calls.push("duplicate");
      out.value = fault === "duplicate-borrowed" ? 7 : 4;
      error = 5;
      return !["duplicate", "duplicate-borrowed"].includes(fault);
    },
    AccessCheck(
      sd,
      token,
      desired,
      mapping,
      _privileges,
      size,
      granted,
      allowed,
    ) {
      assert.equal(token, 4);
      assert.equal(desired, 1);
      assert.equal(mapping[0], api.FILE_GENERIC_READ);
      assert.equal(size.value, 65536);
      calls.push("access");
      granted.value = 1;
      allowed.value = fault !== "denial";
      error = 5;
      return fault !== "access-api";
    },
    CloseHandle(handle) {
      settle(handle);
      calls.push(`close:${handle}`);
      error = 6;
      return fault !== "token-close";
    },
    LocalFree(value) {
      settle(value);
      calls.push("free-local");
      error = 6;
      return ["local-free", "reopen-free"].includes(fault) ? value : null;
    },
    BCryptOpenAlgorithmProvider(out) {
      out.value = { kind: "algorithm" };
      calls.push("hash-open");
      return fault === "hash-open" ? -1 : 0;
    },
    BCryptCreateHash(algorithm, out) {
      assert.equal(algorithm.kind, "algorithm");
      out.value = { kind: "hash" };
      calls.push("hash-create");
      if (fault === "hash-budget") remaining = 0;
      return fault === "hash-create" ? -2 : 0;
    },
    BCryptHashData() {
      calls.push("hash-update");
      return fault === "hash-update" ? -3 : 0;
    },
    BCryptFinishHash(_hash, digest) {
      calls.push("hash-final");
      for (let i = 0; i < 32; i++) digest[i] = 0x35;
      return fault === "hash-final" ? -4 : 0;
    },
    BCryptDestroyHash(handle) {
      settle(handle);
      calls.push("hash-destroy");
      return fault === "hash-close" ? -5 : 0;
    },
    BCryptCloseAlgorithmProvider(handle) {
      settle(handle);
      calls.push("hash-close");
      return 0;
    },
  };
  for (const guard of [
    "need",
    "need_at",
    "token_info",
    "sum",
    "sd_read",
    "file_security_failure",
  ])
    api[guard] = () => assert.fail(`Readback entered fatal helper ${guard}`);
  const native = new Script(
    names.map(project).join("\n") + `\n({${names.join(",")}})`,
  ).runInNewContext(api);
  return {
    native,
    api,
    calls,
    settled,
    text,
    wide,
    status: () => ({ failed: false, closureUncertain: false, value: 0 }),
  };
}

test("retained readback executes nonfatal token, descriptor, hash, discretionary and mandatory paths with once-only temporary ownership", async () => {
  const source = await readFile(
    new URL("effective-reader.h", import.meta.url),
    "utf8",
  );
  for (const fault of [
    null,
    "token-query",
    "statistics-last",
    "statistics-changed",
    "sid-projection",
    "hash-open",
    "hash-create",
    "hash-update",
    "hash-final",
    "hash-close",
    "hash-budget",
    "expired",
    "object",
    "reopen-success",
    "reopen-identity",
    "reopen-free",
    "local-free",
    "dacl-query",
    "unsupported-ace",
    "unsupported-label",
    "default-label",
    "denial",
    "access-api",
    "duplicate",
    "duplicate-borrowed",
    "token-close",
  ]) {
    const f = readbackNative(source, fault),
      status = f.status();
    if (
      [
        null,
        "token-query",
        "statistics-last",
        "statistics-changed",
        "sid-projection",
      ].includes(fault)
    ) {
      const value = {
        before: {},
        after: {},
        fields: 0,
        subject: [],
        restricting: [],
        integritySid: [],
      };
      f.native.readback_metadata(7, value, status);
      assert.equal(
        !!value.stable,
        !["statistics-last", "statistics-changed"].includes(fault),
        fault,
      );
      assert.equal(
        value.fields === 31,
        !["token-query", "sid-projection"].includes(fault),
        fault,
      );
      if (!fault) {
        assert.equal(f.text(value.subject), "S-1-5-21-7001");
        assert.equal(f.text(value.restricting), "S-1-5-21-7002");
        assert.equal(value.integrity, 4096);
      }
      assert.equal(f.calls.filter((call) => call === "token:10").length, 2);
      assert.equal(
        f.settled.size,
        fault === "token-query" ? 3 : 4,
        "SID strings and the metadata buffer settle once",
      );
      continue;
    }
    if (fault?.startsWith("hash-") || fault === "expired") {
      const out = [],
        valid = f.native.readback_hash([], 0, out, status);
      assert.equal(valid, fault === "hash-close", fault);
      if (fault === "hash-close") {
        assert.equal(status.closureUncertain, true);
        assert.equal(f.text(out), "35".repeat(32));
      } else assert.equal(status.failed, true, fault);
      assert.equal(
        f.calls.filter((call) => call === "hash-close").length,
        fault === "expired" ? 0 : 1,
      );
      assert.equal(
        f.calls.filter((call) => call === "hash-destroy").length,
        ["expired", "hash-open"].includes(fault) ? 0 : 1,
      );
      if (fault === "hash-budget")
        assert.equal(f.calls.includes("hash-update"), false);
      continue;
    }
    if (
      [
        "denial",
        "access-api",
        "duplicate",
        "duplicate-borrowed",
        "token-close",
      ].includes(fault)
    ) {
      const granted = { value: 0 },
        allowed = { value: false };
      const valid = f.native.readback_access(
        7,
        {},
        1,
        granted,
        allowed,
        status,
      );
      assert.equal(valid, ["denial", "token-close"].includes(fault));
      assert.equal(
        f.calls.filter((call) => call === "close:4").length,
        ["duplicate", "duplicate-borrowed"].includes(fault) ? 0 : 1,
      );
      if (["duplicate", "duplicate-borrowed"].includes(fault)) {
        assert.equal(status.value, 5);
        assert.equal(status.closureUncertain, false);
      }
      if (fault === "denial")
        assert.deepEqual(
          [allowed.value, granted.value, status.failed],
          [false, 0, false],
        );
      if (fault === "access-api")
        assert.deepEqual(
          [status.domain, status.operation, status.value],
          ["win32", "AccessCheck", 5],
        );
      if (fault === "token-close") assert.equal(status.closureUncertain, true);
      continue;
    }
    const object = {
      actual: {},
      descriptor: [],
      dacl: [],
      owner: [],
      aces: [],
    };
    const sd = f.native.readback_describe(
      1,
      { volume: 1, id: 2 },
      f.wide("S-1-5-21-7001"),
      f.wide("S-1-5-21-7002"),
      object,
      status,
    );
    assert.equal(
      !!sd,
      !["reopen-identity", "reopen-free"].includes(fault),
      fault,
    );
    assert.equal(object.bound, true);
    if (sd) f.native.readback_free(sd, status);
    if (fault === "object") {
      assert.deepEqual(
        [
          object.descriptorHash,
          object.daclHash,
          object.ownerValid,
          object.acesValid,
          object.labelValid,
        ],
        [true, true, true, true, true],
      );
      assert.equal(f.text(object.aces), "0/0/1/system");
      assert.equal(f.text(object.owner), "S-1-5-18");
    }
    if (fault === "reopen-identity")
      assert.deepEqual(
        [status.domain, status.operation],
        ["invariant", "reopened-identity"],
      );
    if (fault === "local-free") assert.equal(status.closureUncertain, true);
    if (fault === "reopen-free") {
      assert.equal(status.closureUncertain, true);
      assert.equal(f.calls.includes("reopen"), false);
    }
    if (fault === "unsupported-ace") {
      assert.equal(object.acesValid, false);
      assert.match(f.text(object.aces), /9\/0\/unavailable\/unsupported/u);
    }
    if (fault === "unsupported-label") assert.equal(object.labelValid, false);
    if (fault === "default-label")
      assert.deepEqual(
        [object.labelValid, object.labelDefaulted, object.level, object.label],
        [true, true, 8192, 1],
      );
    if (fault === "dacl-query") assert.equal(object.descriptorHash, true);
    if (["reopen-success", "reopen-identity"].includes(fault))
      assert.equal(f.calls.filter((call) => call === "close:2").length, 1);
  }
  const f = readbackNative(source);
  assert.equal(f.native.readback_sd(0, {}, { value: true }, f.status()), null);
  assert.deepEqual(f.calls, [], "An unheld resource acquires nothing");
  assert.equal(
    f.native.readback_mic(4096, 1, 8192, 7) & 0x120000,
    0,
    "MIC excludes shared query/synchronization rights",
  );
  assert.equal(f.native.readback_mic(4096, 1, 8192, 7) & 0x23, 0x23);
  assert.equal(f.native.readback_mic(8192, 1, 4096, 7), 0);
});

async function securityNative({
  writer = false,
  information = 8,
  fault,
  closeFailure,
  freeFailure,
  registry = false,
  queryGranted = registry,
  partialDenied = false,
  length = 64,
  deleteOpen = false,
} = {}) {
  const [source, custody] = await Promise.all(
    ["effective-reader.h", "custody.h"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  // Project only C representations. Execute the actual security and custody
  // failure bodies; the native calls and opaque descriptor remain injected.
  const project = (text, name, args) => {
    const match = new RegExp(
      `static [^\\n]+ ${name}\\([^)]*\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(text);
    assert.ok(match, name);
    const start = match.index + match[0].indexOf("{") + 1;
    const body = match[1]
      .replace(/__LINE__/gu, (_, at) =>
        String(text.slice(0, start + at).split("\n").length),
      )
      .replaceAll("__FILE__", '"effective-reader.h"')
      .replace(/^#.*$/gmu, "")
      .replace(
        "FILE_ID_INFO before, after;",
        "const before=Buffer.alloc(24),after=Buffer.alloc(24);",
      )
      .replace(/sizeof\((?:before|after)\)/gu, "24")
      .replace(/&(before|after)\b/gu, "$1")
      .replaceAll("&sd", "{get value(){return sd},set value(value){sd=value}}")
      .replace(
        /\b(?:HANDLE|DWORD|BOOL|PSECURITY_DESCRIPTOR|SECURITY_INFORMATION) /gu,
        "let ",
      );
    return `function ${name}(${args}){${body}}`;
  };
  const calls = [],
    diagnostics = [],
    guards = [],
    opens = new Map(),
    descriptors = new Set(),
    sd = { descriptor: true },
    partial = { partial: true };
  let lastError = 999;
  const api = {
    Buffer,
    NULL: null,
    TRUE: true,
    FALSE: false,
    stderr: {},
    INVALID_HANDLE_VALUE: -1,
    ERROR_SUCCESS: 0,
    ERROR_ACCESS_DENIED: 5,
    ERROR_INVALID_DATA: 13,
    ERROR_INVALID_SECURITY_DESCR: 1338,
    READ_CONTROL: 0x20000,
    WRITE_DAC: 0x40000,
    WRITE_OWNER: 0x80000,
    DELETE: 0x10000,
    ACCESS_SYSTEM_SECURITY: 0x1000000,
    FILE_READ_ATTRIBUTES: 0x80,
    FILE_SHARE_READ: 1,
    FILE_SHARE_WRITE: 2,
    FILE_SHARE_DELETE: 4,
    FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
    FILE_FLAG_BACKUP_SEMANTICS: 0x2000000,
    SE_FILE_OBJECT: 1,
    SE_REGISTRY_KEY: 4,
    OWNER_SECURITY_INFORMATION: 1,
    GROUP_SECURITY_INFORMATION: 2,
    DACL_SECURITY_INFORMATION: 4,
    LABEL_SECURITY_INFORMATION: 16,
    SACL_SECURITY_INFORMATION: 8,
    GetLastError: () => lastError,
    SetLastError: (value) => {
      lastError = value;
    },
    GetFileInformationByHandleEx(handle, kind, target, size) {
      assert.equal(kind, "FileIdInfo");
      assert.equal(size, 24);
      const operation = handle === 1 ? "original-id" : "reopened-id";
      assert.ok(handle === 1 || handle === 2);
      const open = opens.get(handle);
      assert.ok(open, "Identity queries require a live handle");
      calls.push(operation);
      lastError = handle === 1 ? 5 : 87;
      if (fault === operation) return false;
      open.identity.copy(target);
      if (handle === 2 && fault === "volume") target[0]++;
      if (handle === 2 && fault === "file-id") target[23]++;
      return true;
    },
    FileIdInfo: "FileIdInfo",
    ReOpenFile(handle, access, sharing, flags) {
      assert.equal(handle, 1);
      const original = opens.get(handle);
      assert.ok(original, "The borrowed source must remain live");
      assert.equal(
        access,
        api.READ_CONTROL |
          api.ACCESS_SYSTEM_SECURITY |
          api.FILE_READ_ATTRIBUTES |
          (writer ? api.WRITE_DAC : 0) |
          (writer && information & api.LABEL_SECURITY_INFORMATION
            ? api.WRITE_OWNER
            : 0),
      );
      assert.equal(
        flags,
        api.FILE_FLAG_OPEN_REPARSE_POINT | api.FILE_FLAG_BACKUP_SEMANTICS,
      );
      calls.push("reopen");
      lastError = 32;
      // Sharing must accommodate DELETE already granted to another live open
      // of this object, even though the observer requests no DELETE access.
      const incompatible = [...opens.values()].some(
        (open) =>
          open.identity.equals(original.identity) &&
          (open.access & api.DELETE) !== 0 &&
          (sharing & api.FILE_SHARE_DELETE) === 0,
      );
      if (fault === "reopen" || incompatible) return -1;
      assert.equal(
        sharing,
        api.FILE_SHARE_READ | api.FILE_SHARE_WRITE | api.FILE_SHARE_DELETE,
      );
      opens.set(2, { access, identity: original.identity });
      return 2;
    },
    memcmp: (left, right, size) =>
      Buffer.compare(left.subarray(0, size), right.subarray(0, size)),
    GetSecurityInfo(handle, kind, mask, owner, group, dacl, sacl, out) {
      assert.ok(handle === 1 || (!registry && handle === 2));
      const open = opens.get(handle);
      assert.ok(open, "Security queries require a live handle");
      assert.equal(kind, registry ? 4 : 1);
      assert.equal(mask, 1 | 2 | 4 | 8 | 16);
      assert.deepEqual([owner, group, dacl, sacl], [null, null, null, null]);
      assert.equal(out.value, null, "Each query starts without a descriptor");
      calls.push(
        handle === 1 && !registry ? "original-descriptor" : "descriptor",
      );
      const required = api.READ_CONTROL | api.ACCESS_SYSTEM_SECURITY;
      let status = (open.access & required) === required ? 0 : 5;
      if (fault === "original-descriptor" && handle === 1) status = 87;
      if (fault === "descriptor" && (registry || handle === 2)) status = 5;
      if (status !== 5 || registry || handle === 2 || partialDenied) {
        const value = handle === 1 && !registry && status === 5 ? partial : sd;
        assert.ok(
          !descriptors.has(value),
          "Do not overwrite a live descriptor",
        );
        descriptors.add(value);
        out.value = value;
      }
      lastError = 999;
      return status;
    },
    IsValidSecurityDescriptor(value) {
      assert.equal(value, sd);
      calls.push("valid");
      return fault !== "valid";
    },
    GetSecurityDescriptorLength(value) {
      assert.equal(value, sd);
      calls.push("size");
      return length;
    },
    SetSecurityInfo(handle, kind, info, owner, group, dacl, sacl) {
      assert.deepEqual(
        [handle, kind, info, owner, group, dacl, sacl],
        [
          2,
          1,
          information,
          null,
          null,
          information & api.DACL_SECURITY_INFORMATION ? "owned-dacl" : null,
          information &
          (api.SACL_SECURITY_INFORMATION | api.LABEL_SECURITY_INFORMATION)
            ? "owned-sacl"
            : null,
        ],
      );
      calls.push("descriptor");
      lastError = 999;
      const required =
        (info & api.DACL_SECURITY_INFORMATION ? api.WRITE_DAC : 0) |
        (info & api.LABEL_SECURITY_INFORMATION ? api.WRITE_OWNER : 0) |
        (info & api.SACL_SECURITY_INFORMATION ? api.ACCESS_SYSTEM_SECURITY : 0);
      if ((opens.get(handle).access & required) !== required) return 5;
      return fault === "descriptor" ? 87 : 0;
    },
    CloseHandle(handle) {
      assert.equal(handle, 2, "Never close borrowed source or control handles");
      assert.ok(opens.has(handle), "Close only a live temporary handle");
      calls.push("close");
      lastError = 6;
      if (closeFailure || fault === "close") return false;
      opens.delete(handle);
      return true;
    },
    LocalFree(value) {
      assert.ok(descriptors.has(value), "Free only an owned live descriptor");
      calls.push(value === partial ? "free-partial" : "free");
      lastError = 8;
      if (freeFailure) return value;
      descriptors.delete(value);
      return null;
    },
    fprintf(_stream, format, ...values) {
      diagnostics.push({ format, values });
      lastError = 901;
    },
    fflush() {
      lastError = 902;
    },
    NATIVE_CUSTODY_FAILURE(file, line, error) {
      guards.push({ file, line, error });
      lastError = 903;
    },
    ExitProcess(code) {
      throw Object.assign(new Error("Native security refusal"), {
        code,
        guard: guards.at(-1),
      });
    },
  };
  opens.set(1, {
    access:
      api.READ_CONTROL |
      api.FILE_READ_ATTRIBUTES |
      (queryGranted ? api.ACCESS_SYSTEM_SECURITY : 0),
    identity: Buffer.alloc(24, 1),
  });
  if (deleteOpen) {
    opens.set(3, { access: api.DELETE, identity: opens.get(1).identity });
  }
  const native = new Script(
    [
      project(custody, "need_at", "ok,file,line"),
      project(
        source,
        "file_security_failure",
        "operation,api_failure,error,temporary,sd,line",
      ),
      project(source, "file_sd_query", "file,kind,sd"),
      project(source, "file_sd", "file,kind"),
      project(source, "set_file_security", "file,info,dacl,sacl"),
      "({file_sd,set_file_security})",
    ].join("\n"),
  ).runInNewContext(api);
  return {
    calls,
    diagnostics,
    opens,
    descriptors,
    sd,
    run: () =>
      writer
        ? native.set_file_security(
            1,
            information,
            information & api.DACL_SECURITY_INFORMATION ? "owned-dacl" : null,
            information &
              (api.SACL_SECURITY_INFORMATION | api.LABEL_SECURITY_INFORMATION)
              ? "owned-sacl"
              : null,
          )
        : native.file_sd(1, registry ? 4 : 1),
  };
}

test("Windows native restoration writers acquire label access only when requested and retain temporary ownership", async () => {
  for (const information of [4, 8, 16, 4 | 8 | 16]) {
    for (const fault of [null, "file-id", "descriptor"]) {
      const f = await securityNative({
        writer: true,
        information,
        fault,
        deleteOpen: true,
      });
      if (fault) {
        assert.throws(
          f.run,
          (cause) => cause.guard.error === (fault === "file-id" ? 13 : 87),
        );
        assert.equal(f.calls.includes("descriptor"), fault !== "file-id");
      } else {
        f.run();
        assert.deepEqual(f.calls, [
          "original-id",
          "reopen",
          "reopened-id",
          "descriptor",
          "close",
        ]);
        assert.deepEqual(f.diagnostics, []);
      }
      assert.deepEqual([...f.opens.keys()], [1, 3]);
      assert.equal(f.opens.get(1).access, 0x20000 | 0x80);
      assert.equal(f.descriptors.size, 0);
    }
  }
});

test("Windows native security observers use granted originals and strict compatible reopens", async () => {
  const direct = await securityNative({
    queryGranted: true,
    fault: "reopen",
    length: 65536,
    deleteOpen: true,
  });
  assert.equal(direct.run(), direct.sd);
  assert.deepEqual(direct.calls, [
    "original-id",
    "original-descriptor",
    "valid",
    "size",
  ]);
  const read = await securityNative({ length: 65536, deleteOpen: true });
  assert.equal(read.run(), read.sd);
  assert.deepEqual(read.calls, [
    "original-id",
    "original-descriptor",
    "reopen",
    "reopened-id",
    "descriptor",
    "valid",
    "size",
    "close",
  ]);
  const write = await securityNative({ writer: true, deleteOpen: true });
  write.run();
  assert.deepEqual(write.calls, [
    "original-id",
    "reopen",
    "reopened-id",
    "descriptor",
    "close",
  ]);
  for (const f of [direct, read, write]) {
    assert.deepEqual([...f.opens.keys()], [1, 3]);
    assert.equal(f.opens.get(3).access, 0x10000);
    assert.equal(f.opens.get(3).identity, f.opens.get(1).identity);
    assert.deepEqual(f.diagnostics, []);
    assert.deepEqual([...f.descriptors], f === write ? [] : [f.sd]);
  }
  const registry = await securityNative({ registry: true });
  assert.equal(registry.run(), registry.sd);
  assert.deepEqual(registry.calls, ["descriptor", "valid", "size"]);
  assert.deepEqual([...registry.opens.keys()], [1]);
  assert.deepEqual([...registry.descriptors], [registry.sd]);
});

test("Windows native direct security refusals preserve status, validation and borrowed handles without fallback", async () => {
  for (const [fault, error, inspected] of [
    ["original-descriptor", 87, []],
    ["valid", 1338, ["valid"]],
    ["size", 13, ["valid", "size"]],
  ]) {
    const f = await securityNative({
      queryGranted: true,
      fault,
      length: fault === "size" ? 65537 : 64,
      freeFailure: fault === "original-descriptor",
      deleteOpen: true,
    });
    assert.throws(f.run, (cause) => cause.guard.error === error);
    assert.deepEqual(f.calls, [
      "original-id",
      "original-descriptor",
      ...inspected,
      "free",
    ]);
    assert.deepEqual([...f.opens.keys()], [1, 3]);
    assert.deepEqual(
      [...f.descriptors],
      fault === "original-descriptor" ? [f.sd] : [],
    );
    if (fault === "original-descriptor") {
      const cleanup = f.diagnostics.find((item) =>
        item.format.startsWith("native-windows-security-cleanup:"),
      );
      assert.deepEqual(cleanup.values, [8]);
    }
  }
  const registry = await securityNative({
    registry: true,
    fault: "descriptor",
  });
  assert.throws(registry.run, (cause) => cause.guard.error === 5);
  assert.deepEqual(registry.calls, ["descriptor", "free"]);
  assert.deepEqual([...registry.opens.keys()], [1]);
  assert.equal(registry.descriptors.size, 0);
});

test("Windows native denied security queries release partial descriptors before fallback or stop on cleanup failure", async () => {
  const read = await securityNative({ partialDenied: true });
  assert.equal(read.run(), read.sd);
  assert.deepEqual(read.calls, [
    "original-id",
    "original-descriptor",
    "free-partial",
    "reopen",
    "reopened-id",
    "descriptor",
    "valid",
    "size",
    "close",
  ]);
  assert.deepEqual([...read.opens.keys()], [1]);
  assert.deepEqual([...read.descriptors], [read.sd]);
  const refused = await securityNative({
    partialDenied: true,
    freeFailure: true,
  });
  assert.throws(refused.run, (cause) => cause.guard.error === 5);
  assert.deepEqual(refused.calls, [
    "original-id",
    "original-descriptor",
    "free-partial",
  ]);
  assert.deepEqual([...refused.opens.keys()], [1]);
  const primary = refused.diagnostics.find((item) =>
    item.format.startsWith("native-windows-security:"),
  );
  assert.deepEqual(primary.values, ["security-read-descriptor", "win32", 5]);
  const cleanup = refused.diagnostics.find((item) =>
    item.format.startsWith("native-windows-security-cleanup:"),
  );
  assert.deepEqual(cleanup.values, [8]);
});

test("Windows native security failures keep distinct API, identity and descriptor causes through partial cleanup", async () => {
  for (const writer of [false, true]) {
    const failures = [
      ["original-id", 5, ["original-id"]],
      ["reopen", 32, ["original-id", "reopen"]],
      ["reopened-id", 87, ["original-id", "reopen", "reopened-id", "close"]],
      ["volume", 13, ["original-id", "reopen", "reopened-id", "close"]],
      ["file-id", 13, ["original-id", "reopen", "reopened-id", "close"]],
      [
        "descriptor",
        writer ? 87 : 5,
        [
          "original-id",
          "reopen",
          "reopened-id",
          "descriptor",
          "close",
          ...(writer ? [] : ["free"]),
        ],
      ],
      [
        "close",
        6,
        [
          "original-id",
          "reopen",
          "reopened-id",
          "descriptor",
          ...(writer ? [] : ["valid", "size"]),
          "close",
          ...(writer ? [] : ["free"]),
        ],
      ],
      ...(writer
        ? []
        : [
            [
              "valid",
              1338,
              [
                "original-id",
                "reopen",
                "reopened-id",
                "descriptor",
                "valid",
                "close",
                "free",
              ],
            ],
            [
              "size",
              13,
              [
                "original-id",
                "reopen",
                "reopened-id",
                "descriptor",
                "valid",
                "size",
                "close",
                "free",
              ],
            ],
          ]),
    ];
    const sites = new Map();
    for (const [fault, error, calls] of failures) {
      const f = await securityNative({
        writer,
        fault,
        length: fault === "size" ? 65537 : 64,
      });
      assert.throws(f.run, (cause) => {
        assert.equal(cause.code, 126);
        assert.equal(cause.guard.file, "effective-reader.h");
        assert.equal(cause.guard.error, error);
        return true;
      });
      assert.deepEqual(
        f.calls,
        writer || fault === "original-id"
          ? calls
          : [calls[0], "original-descriptor", ...calls.slice(1)],
      );
      assert.ok(f.opens.has(1), "Failures must preserve the borrowed handle");
      assert.equal(f.descriptors.size, 0);
      const primary = f.diagnostics.find((item) =>
        item.format.startsWith("native-windows-security:"),
      );
      const invariant = ["volume", "file-id", "valid", "size"].includes(fault);
      const operation = `security-${writer ? "write" : "read"}-${["volume", "file-id"].includes(fault) ? "same-object" : fault}`;
      assert.deepEqual(primary.values, [
        operation,
        invariant ? "invariant" : "win32",
        error,
      ]);
      const guard = f.diagnostics.find((item) =>
        item.format.startsWith("native-windows-guard:"),
      );
      assert.equal(
        guard.values[2],
        error,
        "Cleanup and diagnostic sinks cannot replace the original cause",
      );
      if (!["volume", "file-id"].includes(fault)) {
        assert.ok(
          !sites.has(guard.values[1]),
          "Failure sites must remain individually attributable",
        );
        sites.set(guard.values[1], fault);
      }
    }
    const partial = await securityNative({
      writer,
      fault: "descriptor",
      closeFailure: true,
      freeFailure: true,
    });
    assert.throws(
      partial.run,
      (cause) => cause.guard.error === (writer ? 87 : 5),
    );
    const cleanup = partial.diagnostics.filter((item) =>
      item.format.startsWith("native-windows-security-cleanup:"),
    );
    assert.deepEqual(
      cleanup.map((item) => [
        /operation=(\w+)/u.exec(item.format)[1],
        ...item.values,
      ]),
      [["CloseHandle", 6], ...(writer ? [] : [["LocalFree", 8]])],
    );
  }
  const registry = await securityNative({ registry: true, fault: "valid" });
  assert.throws(registry.run, (cause) => cause.guard.error === 1338);
  assert.deepEqual(registry.calls, ["descriptor", "valid", "free"]);
});

test("Windows effective composition joins independently approved bindings to actual ACL/MIC, registry and WFP reads", async () => {
  const f = effectiveFixture();
  let reads = 0;
  const acl = f.reader.acl;
  f.reader.acl = (...args) => {
    reads++;
    return acl(...args);
  };
  const owner = createWindowsEffectiveReaders(
    f.reader,
    f.context,
    f.verifier,
    f.options,
  );
  assert.equal(reads, 0);
  const snapshot = await owner.policySnapshot(f.input, {
    subject: 0,
    objects: f.objects.map((_, index) => index),
  });
  assert.equal(snapshot.objects.length, f.plan.manifest.objects.length);
  assert.equal(snapshot.wfp.filters.length, 52);
  assert.equal(
    snapshot.objects.find((item) => item.descriptor.name === "owned").rights
      .delete,
    true,
  );
  assert.equal(
    snapshot.objects.find((item) => item.descriptor.name === "workspace").rights
      .deleteChild,
    false,
  );
  assert.ok(reads > f.objects.length);
});
test("Windows effective reads corroborate traversal LUID and authority while retaining informational metadata", async () => {
  for (const damage of [
    null,
    "luid",
    "authority",
    "missing",
    "authentication",
  ]) {
    const f = effectiveFixture(),
      process = f.reader.process,
      effectiveToken = f.reader.effectiveToken;
    let tokenReads = 0;
    f.reader.effectiveToken = async (...args) => {
      const value = await effectiveToken(...args);
      if (++tokenReads > 1) value.privileges[0].attributes = 0x80000003;
      return value;
    };
    f.reader.process = async (...args) => {
      const value = await process(...args);
      value.privileges[0].attributes = 0x80000003;
      if (damage === "luid") value.privileges[0].luid = "1".repeat(16);
      if (damage === "authority") value.privileges[0].attributes = 2;
      if (damage === "missing") value.privileges = [];
      if (damage === "authentication") value.authenticationId = "f".repeat(16);
      return value;
    };
    const owner = createWindowsEffectiveReaders(
      f.reader,
      f.context,
      f.verifier,
      f.options,
    );
    const read = () =>
      owner.policySnapshot(f.input, {
        subject: 0,
        objects: f.objects.map((_, index) => index),
      });
    if (damage) await assert.rejects(read);
    else {
      await read();
      assert.equal(f.token.privileges[0].attributes, 3);
    }
  }
});

test("Windows expected manifests cannot manufacture token authority, native access, MIC, object identities or coverage", async () => {
  for (const change of [
    (f) => {
      f.token.userSid = "S-1-5-21-1-2-3-1004";
    },
    (f) => {
      f.token.enabledGroups.push("S-1-5-32-544");
    },
    (f) => {
      f.token.privileges.push("0000000000000014");
    },
    (f) => {
      f.token.restrictedSids = [];
    },
    (f) => {
      f.token.integritySid = "S-1-16-8192";
    },
    (f) => {
      delete f.token.primary;
    },
    (f) => {
      delete f.options.binding;
    },
    (f) => {
      f.options.provisioning.bindings[0].value = "S-1-5-21-1-2-3-9";
    },
    (f) => {
      f.objects[3].access.granted |= 0x40000;
    },
    (f) => {
      f.objects[3].access.micDenied = 2;
    },
    (f) => {
      f.objects[3].security.sacl[0].sid = "S-1-16-8192";
    },
    (f) => {
      f.objects[3].object.pathHex = f.objects[4].object.pathHex;
    },
    (f) => {
      f.registry.values = 1;
    },
    (f) => {
      const coverage = f.options.coverage;
      f.options.coverage = async (value) => ({
        ...(await coverage(value)),
        observationsSha256: hash,
      });
    },
    (f) => {
      delete f.options.coverage;
    },
    (f) => {
      f.reader.verifier = async () => ({
        ...f.verifier,
        creationTime: "10999",
      });
    },
    (f) => {
      const coverage = f.options.coverage;
      f.options.coverage = async (value) => {
        const proof = await coverage(value);
        proof.wfp.globalConfigurationSha256 = hash;
        return proof;
      };
    },
    (f) => {
      const coverage = f.options.coverage;
      f.options.coverage = async (value) => {
        const proof = await coverage(value);
        proof.flags.creationDaclProtectionVerified = false;
        return proof;
      };
    },
  ]) {
    const f = effectiveFixture();
    change(f);
    await assert.rejects(
      createWindowsEffectiveReaders(
        f.reader,
        f.context,
        f.verifier,
        f.options,
      ).policySnapshot(f.input, {
        subject: 0,
        objects: f.objects.map((_, index) => index),
      }),
    );
  }
});
test("Windows WFP observations reject substituted principals, types, tuples, action rights and late changes", async () => {
  const f = effectiveFixture(),
    expected = f.plan.manifest.filters[6],
    native = f.filters[6];
  assert.equal(assertWindowsWfpFilterRead(native, expected, f.plan).id, "7");
  for (const change of [
    (read) => {
      read.conditions[0].value.pop();
    },
    (read) => {
      read.conditions[0].value[0].sid = "S-1-5-18";
    },
    (read) => {
      read.conditions[1].type = 2;
    },
    (read) => {
      read.conditions.push(structuredClone(read.conditions[1]));
    },
    (read) => {
      read.flags = 1;
    },
    (read) => {
      read.security.aces.push({ type: 0, flags: 0, mask: 1, sid: "S-1-1-0" });
    },
  ]) {
    const read = structuredClone(native);
    change(read);
    assert.throws(() => assertWindowsWfpFilterRead(read, expected, f.plan));
  }
  let count = 0;
  const acl = f.reader.acl;
  f.reader.acl = async (...args) => {
    const read = await acl(...args);
    if (++count > f.objects.length) read.security.aces[0].mask = 1;
    return read;
  };
  await assert.rejects(
    createWindowsEffectiveReaders(
      f.reader,
      f.context,
      f.verifier,
      f.options,
    ).policySnapshot(f.input, {
      subject: 0,
      objects: f.objects.map((_, index) => index),
    }),
  );
  for (const damage of [
    (read) => {
      read.conditions[0].value.type = 255;
    },
    (read) => {
      read.sublayerWeight--;
    },
  ]) {
    const fixture = effectiveFixture(),
      global = fixture.reader.wfpGlobal;
    let reads = 0;
    fixture.reader.wfpGlobal = async (key) => {
      const read = await global(key);
      if (++reads > fixture.filters.length) damage(read);
      return read;
    };
    await assert.rejects(
      createWindowsEffectiveReaders(
        fixture.reader,
        fixture.context,
        fixture.verifier,
        fixture.options,
      ).policySnapshot(fixture.input, {
        subject: 0,
        objects: fixture.objects.map((_, index) => index),
      }),
    );
  }
});
test("Windows held file barriers reject manufactured bytes and retirement cannot infer whole-domain absence", async () => {
  const bytes = Buffer.from("sentinel");
  const read = {
    identity: fileId(1),
    bytes: bytes.length,
    sha256: digest(bytes),
    daclSha256: hash,
    hex: bytes.toString("hex"),
  };
  assert.deepEqual(normalizeWindowsBarrierRead(read), read);
  assert.throws(() => normalizeWindowsBarrierRead({ ...read, hex: "00" }));
  const f = effectiveFixture();
  f.reader.process = async (slot) => ({
    independent: true,
    identity: slot === 31 ? f.verifier : f.subject,
    retired: slot !== 31,
  });
  f.reader.inspectJob = async () => ({ independent: true, members: [] });
  const owner = createWindowsEffectiveReaders(
    f.reader,
    f.context,
    f.verifier,
    f.options,
  );
  await assert.rejects(owner.retirement([0], [0]));
  f.options.retirement = async ({ context, processes, jobs }) => {
    const { observationDigest } = await import("../index.js");
    return {
      candidateSha,
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
      noLiveMembers: true,
      noForeignCreators: true,
      noPrincipalFlows: true,
      observationsSha256: observationDigest({ context, processes, jobs }),
      verifier: f.verifier,
      nativeEventSha256: hash,
    };
  };
  assert.equal((await owner.retirement([0], [0])).status, "RETIRED");
  f.reader.inspectJob = async () => ({
    independent: true,
    members: [f.subject],
  });
  await assert.rejects(owner.retirement([0], [0]));
});

test("Windows protected Git snapshots join actual bytes, ancestors and complete repeated inventories", async () => {
  const f = effectiveFixture(),
    request = f.input.request;
  const input = {
    request,
    git: {
      path: request.storage + "\\git.exe",
      sha256: hash,
      signatureSha256: hash,
    },
    metadata: request.storage + "\\metadata",
    hooks: request.storage + "\\hooks",
    parent: candidateSha,
    accountSid: f.input.accountSid,
    reviewSha256: hash,
  };
  const contents = [
    {
      config: "[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n",
      HEAD: "ref: refs/heads/proof\n",
      "refs/heads/proof": candidateSha + "\n",
    },
    {
      ".git": `gitdir: ${input.metadata.replaceAll("\\", "/")}\n`,
      "content.txt": "owned edit\n",
    },
  ];
  const records = contents.map((values, root) =>
    Object.entries(values).map(([name, value], index) => ({
      name,
      file: {
        identity: fileId(20 + root * 10 + index),
        bytes: Buffer.byteLength(value),
        sha256: digest(value),
        daclSha256: hash,
        hex: Buffer.from(value).toString("hex"),
      },
    })),
  );
  f.reader.inspect = async (index) => ({
    ...f.objects[0].object,
    identity: fileId(80 + index),
    pathHex: encode(index === 0 ? input.metadata : request.workspace),
  });
  f.reader.parents = async () => [fileId(70), fileId(71)];
  f.reader.tree = async (index) =>
    records[index].map(({ name, file }) => {
      const { hex, ...rest } = file;
      return { nameHex: encode(name.replaceAll("/", "\\")), file: rest };
    });
  f.reader.barrier = async (index, name) =>
    structuredClone(
      records[index].find((item) => item.name === name.replaceAll("\\", "/"))
        .file,
    );
  const owner = createWindowsEffectiveReaders(
      f.reader,
      f.context,
      f.verifier,
      f.options,
    ),
    snapshot = await owner.gitSnapshot(input, 0, 1);
  assert.equal(snapshot.identity, "Fixture <fixture@example.invalid>");
  assert.equal(snapshot.head, candidateSha);
  assert.equal(snapshot.contentSha256, digest("owned edit\n"));
  const tree = f.reader.tree;
  let calls = 0;
  f.reader.tree = async (index) => {
    const values = await tree(index);
    if (++calls > 2) values[0].file.identity = fileId(99);
    return values;
  };
  await assert.rejects(owner.gitSnapshot(input, 0, 1));
});
test("Windows outside controls require actual held nonce bytes and a distinct native System acknowledgement", async () => {
  const f = effectiveFixture(),
    nonce = f.input.request.nonce,
    helper = { ...f.verifier, pid: 902, creationTime: "10902" };
  f.reader.process = async (index) => ({
    identity: index === 31 ? f.verifier : helper,
    independent: true,
    retired: false,
  });
  const file = {
    identity: fileId(20),
    bytes: nonce.length,
    sha256: digest(nonce),
    daclSha256: hash,
    hex: Buffer.from(nonce).toString("hex"),
  };
  f.reader.barrier = async () => structuredClone(file);
  f.options.control = async ({ subject, target }) => ({
    independent: true,
    reached: true,
    discretionaryAllowed: true,
    nonce,
    targetIdentity: target.identity,
    targetSha256: target.sha256,
    subject,
    verifier: f.verifier,
    nativeEventSha256: hash,
  });
  const owner = createWindowsEffectiveReaders(
    f.reader,
    f.context,
    f.verifier,
    f.options,
  );
  assert.equal(
    (await owner.outsideControl(f.input, 0, 0, "outside-sentinel")).ready,
    true,
  );
  file.sha256 = hash;
  await assert.rejects(owner.outsideControl(f.input, 0, 0, "outside-sentinel"));
});
test("Windows retired policy snapshots require fresh whole-domain proof and observe owned filter removal", async () => {
  const f = effectiveFixture(),
    process = f.reader.process;
  f.reader.process = async (slot) => ({
    ...(await process(slot)),
    retired: true,
  });
  f.reader.inspectJob = async () => ({ independent: true, members: [] });
  const owner = createWindowsEffectiveReaders(
      f.reader,
      f.context,
      f.verifier,
      f.options,
    ),
    transfer = { subject: 0, objects: f.objects.map((_, index) => index) };
  await assert.rejects(owner.policySnapshot(f.input, transfer));
  await assert.rejects(owner.retiredPolicySnapshot(f.input, transfer, [0]));
  f.options.retirement = async ({ context, processes, jobs }) => ({
    candidateSha,
    nonce: f.input.request.nonce,
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    noLiveMembers: true,
    noForeignCreators: true,
    noPrincipalFlows: true,
    observationsSha256: observationDigest({ context, processes, jobs }),
    verifier: f.verifier,
    nativeEventSha256: hash,
  });
  assert.equal(
    (await owner.retiredPolicySnapshot(f.input, transfer, [0])).wfp.filters
      .length,
    52,
  );
  await assert.rejects(
    owner.retiredPolicySnapshot(f.input, transfer, [0], { installed: false }),
  );
  f.filters.splice(0);
  assert.equal(
    (
      await owner.retiredPolicySnapshot(f.input, transfer, [0], {
        installed: false,
      })
    ).wfp.filters.length,
    0,
  );
  f.options.retirement = async () => ({
    status: "RETIRED",
    independent: true,
    noLiveMembers: false,
  });
  await assert.rejects(
    owner.retiredPolicySnapshot(f.input, transfer, [0], { installed: false }),
  );
});
