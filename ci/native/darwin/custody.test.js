import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import { constants } from "node:fs";
import { PassThrough, Writable } from "node:stream";
import {
  createDarwinCustodyReader,
  encodeDarwinCustodyPlan,
  normalizeDarwinCustodyInput,
} from "./index.js";
import { darwinCustodyChannel } from "./channel.js";
import { digest } from "./protocol.js";
import { protectedBytes } from "./private-files.js";
import {
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../diagnostics.js";

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

test("Darwin experiment cache reads retain canonical parents, held identities and bytes under hosted ancestry", async () => {
  const cache =
    "/System/Volumes/Preboot/fixture/runtime/dyld_shared_cache_x86_64h";
  for (const [purpose, file, fault, accepted = false] of [
    ["experiment", cache, null, true],
    ["experiment", "/System/Library/dyld/dyld_shared_cache_x86_64", null, true],
    ["reviewed", cache],
    [undefined, cache],
    ["unknown", cache],
    ["experiment", "/usr/bin/clang"],
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
      "file-owner",
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
        mode: leaf ? 0o444n : 0o777n,
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
function fixture({
  failure,
  onPersist,
  purpose = "reviewed",
  build = false,
  inputBytes = 4,
  buildBytes = 4,
} = {}) {
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
    bytes: [0, 4].includes(index) ? 4 : index === 3 ? 23 : 0,
    uid: 0,
    gid: 0,
    mode:
      index === 4 ? 0o555 : index === 0 ? 0o550 : index === 3 ? 0o400 : 0o700,
    directory: ![0, 3, 4].includes(index),
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
            hex: Buffer.from("data")
              .subarray(Number(b), Number(b) + Number(c))
              .toString("hex"),
          };
        if (op === "signature")
          value = { cdhash, entitlementsSha256: hash, valid: true };
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
        if (op === "macho") value = metadata;
        if (op === "build-root") value = { ...object(1), mode: 0o555 };
        if (op === "build-open")
          value = {
            index: 4,
            object: { ...object(4), bytes: buildBytes },
            root: { ...object(1), mode: 0o555 },
            sha256: digest(Buffer.from("data")),
          };
        if (op === "build-input")
          value = {
            object: { ...object(4), mode: 0o444, gid: 80, bytes: inputBytes },
            sha256: failure === "build-input" ? "e".repeat(64) : b,
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
                    mode: failure === "sdk-writable" ? 0o775 : 0o755,
                    directory: failure !== "sdk-file",
                  },
                  ...(failure === "developer-missing"
                    ? {}
                    : {
                        developer: {
                          ...object(2),
                          gid: 20,
                          mode:
                            failure === "developer-writable" ? 0o775 : 0o755,
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
  return { reader, events, receipts, probed, input: selectedInput };
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
    "sdk-writable",
    "sdk-file",
    "developer-missing",
    "developer-writable",
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
