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

async function securityNative({
  writer = false,
  fault,
  closeFailure,
  freeFailure,
  registry = false,
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
      .replace("&sd", "{set value(value){sd=value}}")
      .replace(/\b(?:HANDLE|DWORD|BOOL|PSECURITY_DESCRIPTOR) /gu, "let ");
    return `function ${name}(${args}){${body}}`;
  };
  const calls = [],
    diagnostics = [],
    guards = [],
    opens = new Map(),
    sd = { descriptor: true };
  let lastError = 999;
  const api = {
    Buffer,
    NULL: null,
    TRUE: true,
    FALSE: false,
    stderr: {},
    INVALID_HANDLE_VALUE: -1,
    ERROR_SUCCESS: 0,
    ERROR_INVALID_DATA: 13,
    ERROR_INVALID_SECURITY_DESCR: 1338,
    READ_CONTROL: 0x20000,
    WRITE_DAC: 0x40000,
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
          (writer ? api.WRITE_DAC : 0),
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
      assert.equal(handle, registry ? 1 : 2);
      assert.equal(kind, registry ? 4 : 1);
      assert.equal(mask, 1 | 2 | 4 | 8 | 16);
      assert.deepEqual([owner, group, dacl, sacl], [null, null, null, null]);
      calls.push("descriptor");
      out.value = sd;
      lastError = 999;
      return fault === "descriptor" ? 5 : 0;
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
        [2, 1, 8, null, null, null, "owned-sacl"],
      );
      calls.push("descriptor");
      lastError = 999;
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
      assert.equal(value, sd);
      calls.push("free");
      lastError = 8;
      return freeFailure ? value : null;
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
    access: api.READ_CONTROL | api.FILE_READ_ATTRIBUTES,
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
      project(source, "file_sd", "file,kind"),
      project(source, "set_file_security", "file,info,dacl,sacl"),
      "({file_sd,set_file_security})",
    ].join("\n"),
  ).runInNewContext(api);
  return {
    calls,
    diagnostics,
    opens,
    sd,
    run: () =>
      writer
        ? native.set_file_security(1, 8, null, "owned-sacl")
        : native.file_sd(1, registry ? 4 : 1),
  };
}

test("Windows native security observers share existing DELETE opens with exact rights and complete observations", async () => {
  const read = await securityNative({ length: 65536, deleteOpen: true });
  assert.equal(read.run(), read.sd);
  assert.deepEqual(read.calls, [
    "original-id",
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
  for (const f of [read, write]) {
    assert.deepEqual([...f.opens.keys()], [1, 3]);
    assert.equal(f.opens.get(3).access, 0x10000);
    assert.equal(f.opens.get(3).identity, f.opens.get(1).identity);
    assert.deepEqual(f.diagnostics, []);
  }
  const registry = await securityNative({ registry: true });
  assert.equal(registry.run(), registry.sd);
  assert.deepEqual(registry.calls, ["descriptor", "valid", "size"]);
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
      assert.deepEqual(f.calls, calls);
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
