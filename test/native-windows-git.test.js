import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { win32 as path } from "node:path";
import test from "node:test";
import {
  prepareWindowsFeasibilityGit,
  windowsFeasibilityCause,
  windowsFeasibilityImports,
} from "../ci/native/win32/index.js";

const ROOT = "C:\\owned\\experiment",
  SYSTEM = "C:\\Windows",
  LAUNCHER = "C:\\tools\\git\\cmd\\git.exe",
  DIRECTORY = "C:\\tools\\git\\mingw64\\bin",
  COPIED = path.join(ROOT, "build", "git.exe"),
  NONCE = "a".repeat(32);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const failure = (code, fields = {}) =>
  Object.assign(new Error("private native details"), { code, ...fields });

function pe(imports = [], { directories = 16, importExtent = 0 } = {}) {
  const bytes = Buffer.alloc(8192),
    optional = 88,
    optionalSize = 112 + directories * 8,
    section = optional + optionalSize;
  bytes.writeUInt16LE(0x5a4d);
  bytes.writeUInt32LE(64, 60);
  bytes.writeUInt32LE(0x4550, 64);
  bytes.writeUInt16LE(0x8664, 68);
  bytes.writeUInt16LE(1, 70);
  bytes.writeUInt16LE(optionalSize, 84);
  bytes.writeUInt16LE(0x20b, optional);
  bytes.writeUInt32LE(4096, optional + 32);
  bytes.writeUInt32LE(512, optional + 36);
  bytes.writeUInt32LE(12288, optional + 56);
  bytes.writeUInt32LE(512, optional + 60);
  bytes.writeUInt32LE(directories, optional + 108);
  bytes.writeUInt32LE(bytes.length - 512, section + 8);
  bytes.writeUInt32LE(4096, section + 12);
  bytes.writeUInt32LE(bytes.length - 512, section + 16);
  bytes.writeUInt32LE(512, section + 20);
  if (imports.length) {
    bytes.writeUInt32LE(4096, optional + 120);
    bytes.writeUInt32LE(
      importExtent || (imports.length + 1) * 20,
      optional + 124,
    );
    let name = 512 + (imports.length + 1) * 20;
    for (const [i, dll] of imports.entries()) {
      bytes.writeUInt32LE(4096 + name - 512, 512 + i * 20 + 12);
      name += bytes.write(`${dll}\0`, name, "ascii");
    }
    // Neutral ordinal thunks make the larger import extent representative of
    // lookup/address tables plus names, without importing any real DLL symbol.
    let thunk = Math.ceil(name / 8) * 8;
    for (const [i] of imports.entries()) {
      bytes.writeUInt32LE(4096 + thunk - 512, 512 + i * 20);
      bytes.writeUInt32LE(4096 + thunk + 16 - 512, 512 + i * 20 + 16);
      bytes.writeBigUInt64LE(0x8000000000000001n, thunk);
      bytes.writeBigUInt64LE(0x8000000000000001n, thunk + 16);
      thunk += 32;
    }
  }
  return bytes;
}

function fixture() {
  const installed = new Map([
      [LAUNCHER, pe()],
      [
        path.join(DIRECTORY, "git.exe"),
        pe([
          "KERNEL32.DLL",
          "fixture.DLL",
          "fixture.dll",
          "api-ms-win-fixture.DLL",
        ]),
      ],
      [path.join(DIRECTORY, "fixture.dll"), pe(["FIXTURE.DLL"])],
      [path.join(SYSTEM, "System32", "KERNEL32.DLL"), pe()],
    ]),
    copied = new Map(),
    calls = [],
    components = [
      "msvc",
      "windows-sdk-header",
      "windows-feasibility-helper",
      "windows-feasibility-argv-fixture",
    ].map((name) => ({
      name,
      role: name.startsWith("windows-feasibility") ? "helper" : "tool",
      version: "1.2.3",
      sha256: digest(Buffer.from(name)),
    }));
  const effects = {
    command: async (image, args, options) => {
      calls.push({ image, args, options });
      if (image === "where.exe") return { stdout: `${LAUNCHER}\r\n` };
      if (image === LAUNCHER) {
        assert.deepEqual(args, ["--exec-path"]);
        return { stdout: "C:/tools/git/mingw64/libexec/git-core\n" };
      }
      assert.equal(image, COPIED);
      if (args[0] === "--version")
        return { stdout: "git version 1.2.3.windows.1\n" };
      assert.equal(options.cwd, path.join(ROOT, "workspace"));
      return { stdout: "" };
    },
    read: async (file) => {
      const bytes = installed.get(file) ?? copied.get(file);
      if (bytes === undefined) throw failure("ENOENT");
      return Buffer.from(bytes);
    },
    write: async (file, bytes) => {
      assert.equal(copied.has(file), false);
      copied.set(file, Buffer.from(bytes));
    },
    inspect: windowsFeasibilityImports,
  };
  return {
    effects,
    installed,
    copied,
    calls,
    components,
    prepare: () =>
      prepareWindowsFeasibilityGit(
        { root: ROOT, nonce: NONCE, systemRoot: SYSTEM, components },
        effects,
      ),
  };
}

test("Windows Git accepts uppercase DLL extensions while retaining distinct bounded PE refusals", () => {
  assert.deepEqual(windowsFeasibilityImports(pe(["fixture.DLL"])), [
    "fixture.DLL",
  ]);
  for (const [rule, mutate] of [
    ["dos-signature", (bytes) => bytes.writeUInt16LE(0)],
    ["pe-offset", (bytes) => bytes.writeUInt32LE(0xfffffff0, 60)],
    ["pe-signature", (bytes) => bytes.writeUInt32LE(0, 64)],
    ["machine", (bytes) => bytes.writeUInt16LE(0xaa64, 68)],
    ["section-count", (bytes) => bytes.writeUInt16LE(97, 70)],
    ["optional-range", (bytes) => bytes.writeUInt16LE(111, 84)],
    ["optional-magic", (bytes) => bytes.writeUInt16LE(0x10b, 88)],
    ["directory-count", (bytes) => bytes.writeUInt32LE(17, 196)],
    ["section-table", (bytes) => bytes.writeUInt16LE(96, 70)],
    ["section-raw-range", (bytes) => bytes.writeUInt32LE(256, 348)],
    ["section-raw-range", (bytes) => bytes.writeUInt32LE(8000, 348)],
    ["section-rva-range", (bytes) => bytes.writeUInt32LE(0xfffffff0, 340)],
    ["rva-unmapped", (bytes) => bytes.writeUInt32LE(90000, 524)],
    ["rva-unmapped", (bytes) => bytes.writeUInt32LE(7681, 212)],
    ["delay-imports", (bytes) => bytes.writeUInt32LE(1, 88 + 112 + 13 * 8)],
    ["delay-imports", (bytes) => bytes.writeUInt32LE(1, 88 + 116 + 13 * 8)],
    ["import-pair", (bytes) => bytes.writeUInt32LE(0, 208)],
    ["import-size", (bytes) => bytes.writeUInt32LE(19, 212)],
    ["import-terminator", (bytes) => bytes.writeUInt32LE(20, 212)],
    ["rva-unmapped", (bytes) => bytes.fill(1, 532, 552)],
    ["name-safe", (bytes) => bytes.write("../outside.DLL\0", 552)],
    ["name-safe", (bytes) => bytes.write("NUL.DLL\0", 552)],
    ["name-ascii", (bytes) => bytes.writeUInt8(128, 552)],
    ["name-terminator", (bytes) => bytes.fill(65, 552)],
  ]) {
    let bytes = pe(["fixture.DLL"]);
    mutate(bytes);
    if (rule === "section-table") bytes = bytes.subarray(0, 1000);
    assert.throws(
      () => windowsFeasibilityImports(bytes),
      (error) => {
        assert.equal(error.code, "ERR_FEASIBILITY_WINDOWS_PE");
        assert.equal(error.peInspection.rule, rule);
        assert.ok(error.peInspection.values.every(Number.isSafeInteger));
        const cause = windowsFeasibilityCause("synthetic-git", error);
        assert.ok(cause.detail.includes(`PE rule=${rule}`));
        assert.ok(Buffer.byteLength(cause.detail) <= 256);
        assert.doesNotMatch(cause.detail, /outside|NUL\.DLL|fixture\.DLL/u);
        return true;
      },
    );
  }
});

test("Windows PE bounds variable optional headers and larger declared import extents", () => {
  for (const directories of [2, 13, 14, 16])
    assert.deepEqual(
      windowsFeasibilityImports(
        pe(["fixture.DLL"], { directories, importExtent: 6144 }),
      ),
      ["fixture.DLL"],
    );
  assert.deepEqual(windowsFeasibilityImports(pe([], { directories: 0 })), []);
  assert.throws(
    () => windowsFeasibilityImports(null),
    (error) => error.peInspection.rule === "file-type",
  );
  for (const [length, rule] of [
    [255, "file-size"],
    [320, "optional-range"],
  ])
    assert.throws(
      () => windowsFeasibilityImports(pe().subarray(0, length)),
      (error) => error.peInspection.rule === rule,
    );
  const truncatedDirectories = pe([], { directories: 2 });
  truncatedDirectories.writeUInt32LE(14, 196);
  assert.throws(
    () => windowsFeasibilityImports(truncatedDirectories),
    (error) => error.peInspection.rule === "directory-count",
  );
});

test("Windows PE refuses overlapping raw/RVA ranges while allowing non-file-backed sections", () => {
  const sections = (bytes) => {
    bytes.writeUInt16LE(2, 70);
    bytes.copy(bytes, 368, 328, 368);
  };
  const rawOverlap = pe(["fixture.DLL"]);
  sections(rawOverlap);
  rawOverlap.writeUInt32LE(12288, 380);
  assert.throws(
    () => windowsFeasibilityImports(rawOverlap),
    (error) => error.peInspection.rule === "raw-overlap",
  );
  const rvaOverlap = pe(["fixture.DLL"]);
  sections(rvaOverlap);
  for (const section of [328, 368]) {
    rvaOverlap.writeUInt32LE(512, section + 8);
    rvaOverlap.writeUInt32LE(512, section + 16);
  }
  rvaOverlap.writeUInt32LE(1024, 388);
  assert.throws(
    () => windowsFeasibilityImports(rvaOverlap),
    (error) => error.peInspection.rule === "rva-overlap",
  );
  const bss = pe(["fixture.DLL"]);
  sections(bss);
  bss.writeUInt32LE(4096, 376);
  bss.writeUInt32LE(12288, 380);
  bss.writeUInt32LE(0, 384);
  bss.writeUInt32LE(0, 388);
  bss.writeUInt32LE(16384, 144);
  assert.deepEqual(windowsFeasibilityImports(bss), ["fixture.DLL"]);
});

test("Windows PE bounds descriptor walking separately from the directory extent and each name byte", () => {
  const unbounded = pe(["fixture.DLL"], { importExtent: 6144 });
  for (let i = 0; i < 204; i++) {
    unbounded.fill(0, 512 + i * 20, 532 + i * 20);
    unbounded.writeUInt32LE(4096 + 6144, 524 + i * 20);
  }
  unbounded.write("fixture.DLL\0", 512 + 6144);
  assert.throws(
    () => windowsFeasibilityImports(unbounded),
    (error) => {
      assert.deepEqual(error.peInspection, {
        rule: "import-terminator",
        values: [6144, 204],
      });
      return true;
    },
  );
  const overflow = pe(["fixture.DLL"]);
  overflow.writeUInt32LE(0xffffffc0, 208);
  overflow.writeUInt32LE(64, 336);
  overflow.writeUInt32LE(0xffffffc0, 340);
  overflow.writeUInt32LE(64, 344);
  overflow.writeUInt32LE(0xffffffff, 524);
  overflow[575] = 65;
  assert.throws(
    () => windowsFeasibilityImports(overflow),
    (error) => {
      assert.deepEqual(error.peInspection, {
        rule: "rva-range",
        values: [0x100000000, 1],
      });
      assert.match(
        windowsFeasibilityCause("synthetic-git", error).detail,
        /rva=4294967296, size=1/u,
      );
      return true;
    },
  );
  const unterminated = pe(["fixture.DLL"]);
  unterminated.writeUInt32LE(64, 336);
  unterminated.writeUInt32LE(64, 344);
  unterminated.writeUInt32LE(4156, 524);
  unterminated.fill(65, 572, 577);
  assert.throws(
    () => windowsFeasibilityImports(unterminated),
    (error) => error.peInspection.rule === "rva-unmapped",
  );
  const separated = Buffer.from(unterminated);
  separated.writeUInt16LE(2, 70);
  separated.copy(separated, 368, 328, 368);
  separated.writeUInt32LE(4160, 380);
  separated.writeUInt32LE(1024, 388);
  assert.throws(
    () => windowsFeasibilityImports(separated),
    (error) => error.peInspection.rule === "name-contiguity",
  );
});

test("Windows PE reporting refuses unknown or tainted structural diagnostics", () => {
  for (const peInspection of [
    { rule: "foreign-rule", values: [1] },
    { rule: "machine", values: ["private diagnostic"] },
    { rule: "machine", values: [0x100000001] },
    { rule: "machine", values: [1.5] },
    { rule: "machine", values: Array(1) },
    { rule: "machine", values: [1], extra: "private diagnostic" },
  ]) {
    const cause = windowsFeasibilityCause(
      "synthetic-git",
      failure("ERR_FEASIBILITY_WINDOWS_PE", { peInspection }),
    );
    assert.doesNotMatch(
      cause.detail,
      /PE rule=|foreign-rule|private diagnostic/u,
    );
    assert.match(cause.detail, /native=ERR_FEASIBILITY_WINDOWS_PE/u);
  }
  let reads = 0;
  const changing = [0];
  Object.defineProperty(changing, "0", {
    get: () => (++reads === 1 ? 0xaa64 : "private diagnostic"),
  });
  const cause = windowsFeasibilityCause(
    "synthetic-git",
    failure("ERR_FEASIBILITY_WINDOWS_PE", {
      peInspection: { rule: "machine", values: changing },
    }),
  );
  assert.match(cause.detail, /PE rule=machine, machine=43620\./u);
  assert.doesNotMatch(cause.detail, /private diagnostic/u);
  assert.equal(reads, 1);
});

test("Windows preparation validates copied Git and binds its case-folded bounded runtime manifest", async () => {
  const f = fixture(),
    initial = structuredClone(f.components);
  // A Git launcher may advertise the whole .idata extent, rather than just the
  // short descriptor array. Preparation must inspect these exact retained bytes.
  f.installed.set(LAUNCHER, pe(["KERNEL32.DLL"], { importExtent: 6144 }));
  const result = await f.prepare();
  assert.equal(result.image, COPIED);
  assert.deepEqual(
    result.manifest.map(({ name }) => name),
    ["git.exe", "fixture.dll"],
  );
  for (const { name, sha256 } of result.manifest)
    assert.equal(sha256, digest(f.copied.get(path.join(ROOT, "build", name))));
  assert.deepEqual(f.components.slice(0, 4), initial);
  assert.equal(
    f.components.find(({ name }) => name === "git-launcher").sha256,
    digest(f.installed.get(LAUNCHER)),
  );
  const git = f.components.find(({ name }) => name === "git-for-windows");
  assert.equal(git.version, "git version 1.2.3.windows.1");
  assert.equal(git.sha256, result.manifest[0].sha256);
  assert.equal(
    f.components.at(-1).sha256,
    digest(Buffer.from(JSON.stringify(result.manifest))),
  );
  assert.deepEqual(
    JSON.parse(f.copied.get(path.join(ROOT, "control", "git-runtime.json"))),
    { version: git.version, files: result.manifest },
  );
  assert.deepEqual(
    f.calls.slice(2).map(({ image }) => image),
    Array(4).fill(COPIED),
  );
  assert.equal(f.calls[2].options.cwd, path.join(ROOT, "build"));
  assert.deepEqual(f.calls[3].args, [
    "init",
    "--initial-branch=fixture",
    "--template=",
  ]);
  assert.deepEqual(
    f.copied.get(path.join(ROOT, "workspace", ".git", "runner-global.conf")),
    Buffer.alloc(0),
  );
});

test("Windows discovery rejects relative, remote, ambiguous and unbounded runtime paths before copying", async () => {
  for (const [which, output] of [
    ["where.exe", "git.exe"],
    ["where.exe", "\\\\server\\share\\git.exe"],
    ["where.exe", "C:\\tools\\..\\git.exe"],
    ["where.exe", "C:\\tools\\git.exe:stream"],
    ["where.exe", Array(17).fill(LAUNCHER).join("\n")],
    [LAUNCHER, "C:/tools/git/other"],
    [LAUNCHER, "C:/tools/git/../libexec/git-core"],
    [LAUNCHER, undefined],
  ]) {
    const f = fixture(),
      command = f.effects.command;
    f.effects.command = async (image, ...args) =>
      image === which ? { stdout: output } : command(image, ...args);
    await assert.rejects(f.prepare(), (error) => {
      assert.match(
        error.feasibilityCause.detail,
        /native=ERR_FEASIBILITY_GIT_PATH/u,
      );
      return true;
    });
    assert.equal(f.copied.size, 0);
  }
});

test("Windows preparation refuses invalid launcher and Git images before executing or copying them", async () => {
  for (const file of [LAUNCHER, path.join(DIRECTORY, "git.exe")]) {
    const f = fixture();
    f.installed.get(file).writeUInt16LE(0xaa64, 68);
    await assert.rejects(f.prepare(), (error) => {
      assert.match(
        error.feasibilityCause.detail,
        /inspection.*ERR_FEASIBILITY_WINDOWS_PE/u,
      );
      assert.match(
        error.feasibilityCause.detail,
        /PE rule=machine, machine=43620\./u,
      );
      assert.deepEqual(error.cause.peInspection, {
        rule: "machine",
        values: [0xaa64],
      });
      return true;
    });
    assert.equal(f.copied.size, 0);
    assert.equal(
      f.calls.some(({ image }) => image === COPIED),
      false,
    );
    if (file === LAUNCHER) {
      assert.equal(f.calls.length, 1);
      assert.equal(f.components.at(-1).name, "git-launcher");
    }
    assert.equal(f.components.at(-1).sha256, digest(f.installed.get(file)));
    assert.equal(f.components.at(-1).version, "unobserved");
  }
});

test("Windows Git failures retain their exact operation, process facts and already observed identities", async () => {
  for (const [method, target, code, operation] of [
    ["command", "where.exe", "ENOENT", "git-discovery"],
    ["command", LAUNCHER, 2, "git-exec-path"],
    [
      "read",
      path.join(SYSTEM, "System32", "fixture.DLL"),
      "EACCES",
      "git-dependencies",
    ],
    [
      "read",
      path.join(DIRECTORY, "fixture.dll"),
      "ENOENT",
      "git-source-inspection",
    ],
    ["write", COPIED, "ENOSPC", "git-owned-copy"],
    ["write", COPIED, "EEXIST", "git-owned-copy"],
    ["command", COPIED, 2, "git-version"],
  ]) {
    const f = fixture(),
      effect = f.effects[method],
      initial = structuredClone(f.components);
    f.effects[method] = async (file, ...args) => {
      if (file === target)
        throw failure(code, {
          signal: null,
          timedOut: false,
          nativeError: "5",
          killed: true,
        });
      return effect(file, ...args);
    };
    await assert.rejects(f.prepare(), (error) => {
      const cause = windowsFeasibilityCause("synthetic-git", error);
      assert.deepEqual(cause, error.feasibilityCause);
      assert.match(cause.detail, new RegExp(`prepare ${operation}:`, "u"));
      assert.match(cause.detail, /signal=none, timeout=false.*Win32=5/u);
      assert.equal(
        cause.code,
        operation === "git-discovery"
          ? "prerequisite-unavailable"
          : "setup-failed",
      );
      assert.ok(cause.detail.length <= 256);
      assert.doesNotMatch(cause.detail, /private native details/u);
      return true;
    });
    assert.deepEqual(f.components.slice(0, 4), initial);
    if (!["git-discovery", "git-exec-path"].includes(operation))
      assert.equal(
        f.components.find(({ name }) => name === "git-for-windows").version,
        "unobserved",
      );
  }
});

test("Windows Git rejects changed copied bytes and invalid versions before repository effects", async () => {
  for (const kind of ["copy", "version", "after-version", "dependency"]) {
    const f = fixture(),
      write = f.effects.write,
      command = f.effects.command;
    f.effects.write = async (file, bytes) => {
      await write(file, bytes);
      if (kind === "copy" && file === COPIED) f.copied.get(file)[0] ^= 1;
    };
    f.effects.command = async (image, args, options) => {
      if (image === COPIED && args[0] === "--version") {
        if (kind === "after-version") f.copied.get(COPIED)[0] ^= 1;
        if (kind === "dependency")
          f.copied.get(path.join(ROOT, "build", "fixture.dll"))[0] ^= 1;
        if (kind === "version") return { stdout: "unrecognized version" };
      }
      return command(image, args, options);
    };
    await assert.rejects(f.prepare(), (error) => {
      assert.match(
        error.feasibilityCause.detail,
        kind === "version"
          ? /git-version.*ERR_FEASIBILITY_GIT_VERSION/u
          : /git-copy-inspection.*ERR_FEASIBILITY_GIT_COPY/u,
      );
      return true;
    });
    assert.equal(
      f.calls.some(({ args }) => args[0] === "init"),
      false,
    );
    assert.equal(
      f.components.find(({ name }) => name === "git-for-windows").version,
      ["after-version", "dependency"].includes(kind)
        ? "git version 1.2.3.windows.1"
        : "unobserved",
    );
  }
});

test("Windows Git dependency closure refuses excessive private imports", async () => {
  const f = fixture();
  f.installed.set(
    path.join(DIRECTORY, "git.exe"),
    pe(Array.from({ length: 64 }, (_, i) => `fixture-${i}.DLL`)),
  );
  await assert.rejects(f.prepare(), (error) => {
    assert.match(
      error.feasibilityCause.detail,
      /git-dependencies.*ERR_FEASIBILITY_GIT_DEPENDENCIES/u,
    );
    return true;
  });
  assert.equal(f.copied.size, 0);
});

test("Windows Git repository failure preserves copied-runtime components and the first native result", async () => {
  for (const operation of ["init", "add", "commit"]) {
    const f = fixture(),
      command = f.effects.command;
    f.effects.command = async (image, args, options) => {
      if (args.includes(operation))
        throw failure(3, {
          signal: null,
          timedOut: false,
          stderr: "fatal: permission denied",
        });
      return command(image, args, options);
    };
    await assert.rejects(f.prepare(), (error) => {
      assert.match(
        windowsFeasibilityCause("synthetic-git", error).detail,
        new RegExp(`git-repository-${operation}: exit=3`, "u"),
      );
      return true;
    });
    assert.equal(
      f.components.find(({ name }) => name === "git-for-windows").version,
      "git version 1.2.3.windows.1",
    );
    assert.equal(f.components.at(-1).name, "experiment-git-runtime");
  }
});

test("Windows bounded failure formatting accepts only validated native errors and never treats killed as a deadline", () => {
  for (const nativeError of [
    "5",
    "4294967295",
    "0",
    "4294967296",
    "5\nprivate",
    null,
  ]) {
    const cause = windowsFeasibilityCause("synthetic-git", {
      code: 1,
      signal: null,
      killed: true,
      nativeError,
    });
    assert.equal(cause.code, "setup-failed");
    assert.match(cause.detail, /exit=1, signal=none, timeout=unknown/u);
    assert.equal(
      cause.detail.includes("Win32="),
      ["5", "4294967295"].includes(nativeError),
    );
  }
  assert.equal(
    windowsFeasibilityCause("synthetic-git", { killed: true, timedOut: true })
      .code,
    "deadline",
  );
  assert.equal(
    windowsFeasibilityCause("synthetic-git", {
      killed: true,
      signal: "SIGTERM",
    }).code,
    "crash",
  );
});
