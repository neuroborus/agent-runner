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

function pe(imports = []) {
  const bytes = Buffer.alloc(8192),
    optional = 88,
    section = 328;
  bytes.writeUInt16LE(0x5a4d);
  bytes.writeUInt32LE(64, 60);
  bytes.writeUInt32LE(0x4550, 64);
  bytes.writeUInt16LE(0x8664, 68);
  bytes.writeUInt16LE(1, 70);
  bytes.writeUInt16LE(240, 84);
  bytes.writeUInt16LE(0x20b, optional);
  bytes.writeUInt32LE(16, optional + 108);
  bytes.writeUInt32LE(4096, section + 12);
  bytes.writeUInt32LE(bytes.length - 512, section + 16);
  bytes.writeUInt32LE(512, section + 20);
  if (imports.length) {
    bytes.writeUInt32LE(4096, optional + 120);
    bytes.writeUInt32LE((imports.length + 1) * 20, optional + 124);
    let name = 512 + (imports.length + 1) * 20;
    for (const [i, dll] of imports.entries()) {
      bytes.writeUInt32LE(4096 + name - 512, 512 + i * 20 + 12);
      name += bytes.write(`${dll}\0`, name, "ascii");
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

test("Windows Git accepts uppercase DLL extensions while retaining unsafe PE rejection", () => {
  assert.deepEqual(windowsFeasibilityImports(pe(["fixture.DLL"])), [
    "fixture.DLL",
  ]);
  for (const mutate of [
    (bytes) => bytes.writeUInt16LE(0xaa64, 68),
    (bytes) => bytes.writeUInt32LE(90000, 524),
    (bytes) => bytes.writeUInt32LE(1, 88 + 112 + 13 * 8),
    (bytes) => bytes.fill(1, 532, 552),
    (bytes) => bytes.write("../outside.DLL\0", 552),
    (bytes) => bytes.write("NUL.DLL\0", 552),
    (bytes) => bytes.fill(65, 552),
  ]) {
    const bytes = pe(["fixture.DLL"]);
    mutate(bytes);
    assert.throws(() => windowsFeasibilityImports(bytes), {
      code: "ERR_FEASIBILITY_WINDOWS_PE",
    });
  }
});

test("Windows preparation validates copied Git and binds its case-folded bounded runtime manifest", async () => {
  const f = fixture(),
    initial = structuredClone(f.components);
  const result = await f.prepare();
  assert.equal(result.image, COPIED);
  assert.deepEqual(
    result.manifest.map(({ name }) => name),
    ["git.exe", "fixture.dll"],
  );
  for (const { name, sha256 } of result.manifest)
    assert.equal(sha256, digest(f.copied.get(path.join(ROOT, "build", name))));
  assert.deepEqual(f.components.slice(0, 4), initial);
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
      return true;
    });
    assert.equal(f.copied.size, 0);
    assert.equal(
      f.calls.some(({ image }) => image === COPIED),
      false,
    );
    if (file === LAUNCHER) assert.equal(f.calls.length, 1);
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
