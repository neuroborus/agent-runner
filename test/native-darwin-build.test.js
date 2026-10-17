import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Script } from "node:vm";
import {
  buildDarwinFeasibility,
  darwinFeasibilityCause,
} from "../ci/native/darwin/index.js";

const SOURCE = new URL("../ci/native/darwin/", import.meta.url);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("Darwin SDK guard samples each original predicate once and preserves refusal errno", async () => {
  const source = await readFile(new URL("build-helper.c", SOURCE), "utf8"),
    start = source.indexOf("    char canonical[PATH_MAX]; struct stat stat;"),
    end = source.indexOf("    ancestors(sdk);", start);
  assert.ok(start > 0 && end > start);
  const script = new Script(
    `() => {${source
      .slice(start, end)
      .replace(
        "char canonical[PATH_MAX]; struct stat stat;",
        "const canonical = {}, stat = {};",
      )
      .replace(/\b(?:int|bool) /gu, "let ")
      .replaceAll("&stat", "stat")
      .replace(/\((?:uintmax_t|unsigned)\)/gu, "")
      .replace(/\b022\b/gu, "0o22")}}`,
  );
  for (const fault of [
    null,
    "realpath",
    "equal",
    "lstat",
    "kind",
    "owner",
    "writable",
    "diagnostic-write",
  ]) {
    const calls = [],
      diagnostics = [],
      metadata = {
        st_uid: fault === "owner" ? 501 : 0,
        st_gid: 20,
        st_mode:
          (fault === "kind" ? 0o100000 : 0o40000) |
          (["writable", "diagnostic-write"].includes(fault) ? 0o775 : 0o755),
        st_dev: 1,
        st_ino: 42,
      };
    const context = {
      errno: 7,
      sdk: "/fixture/sdk",
      NULL: null,
      stderr: {},
      realpath(name, canonical) {
        calls.push("realpath");
        assert.equal(name, "/fixture/sdk");
        context.errno = fault === "realpath" ? 2 : 31;
        if (fault === "realpath") return null;
        canonical.value = fault === "equal" ? "/fixture/other-sdk" : name;
        return canonical;
      },
      strcmp(name, canonical) {
        calls.push("equal");
        return name === canonical.value ? 0 : 1;
      },
      lstat(name, output) {
        calls.push("lstat");
        assert.equal(name, "/fixture/sdk");
        context.errno = fault === "lstat" ? 13 : 44;
        if (fault === "lstat") return -1;
        Object.assign(output, metadata);
        return 0;
      },
      S_ISDIR(mode) {
        calls.push("kind");
        return Number((mode & 0o170000) === 0o40000);
      },
      fprintf(_stream, format, ...values) {
        diagnostics.push([format, values.map(Number)]);
        context.errno = 99;
        return fault === "diagnostic-write" ? -1 : 1;
      },
      fflush() {
        context.errno = 98;
      },
      need(ok) {
        calls.push("guard");
        if (!ok)
          throw Object.assign(new Error("SDK refusal"), {
            errno: context.errno,
          });
      },
    };
    const run = script.runInNewContext(context),
      expectedError =
        fault === "realpath"
          ? 2
          : fault === "equal"
            ? 31
            : fault === "lstat"
              ? 13
              : 44;
    if (fault) assert.throws(run, { errno: expectedError });
    else run();
    assert.equal(context.errno, expectedError, fault);
    assert.deepEqual(
      calls,
      [
        "realpath",
        ...(fault !== "realpath" ? ["equal"] : []),
        ...(!["realpath", "equal"].includes(fault) ? ["lstat"] : []),
        ...(!["realpath", "equal", "lstat"].includes(fault) ? ["kind"] : []),
        "guard",
      ],
      fault,
    );
    if (!fault) assert.deepEqual(diagnostics, []);
    else {
      const expected = {
        realpath: [0, 2, -1, -2, -1, -1, -1, -1],
        equal: [1, 31, 0, -2, -1, -1, -1, -1],
        lstat: [1, 31, 1, -1, 13, -1, -1, -1],
        kind: [1, 31, 1, 0, 44, 0, -1, -1],
        owner: [1, 31, 1, 0, 44, 1, 0, -1],
        writable: [1, 31, 1, 0, 44, 1, 1, 1],
        "diagnostic-write": [1, 31, 1, 0, 44, 1, 1, 1],
      }[fault];
      assert.deepEqual(diagnostics[0][1], expected, fault);
      const sampled = !["realpath", "equal", "lstat"].includes(fault);
      assert.equal(diagnostics.length, sampled ? 2 : 1);
      if (sampled)
        assert.deepEqual(diagnostics[1][1], [
          metadata.st_uid,
          20,
          metadata.st_mode,
          1,
          42,
        ]);
    }
  }
});

test("Darwin build custody normalizes only its joined exclusive creation", async () => {
  const source = await readFile(new URL("custody-reader.c", SOURCE), "utf8"),
    body =
      /static void build_directory\(const char \*encoded\) \{([\s\S]*?)\n\}/u.exec(
        source,
      )?.[1],
    same =
      /static void same_stat\(struct stat a, struct stat b\) \{([\s\S]*?)\n\}/u.exec(
        source,
      )?.[1];
  assert.ok(body && same);
  // Execute the admission body; only C storage/pointer syntax is projected.
  const translated = body
    .replace("unsigned approved", "let approved")
    .replace("unsigned i", "let i")
    .replace("char *leaf", "const leaf")
    .replace("leaf + 1", "leaf.next")
    .replace("*leaf = 0", "leaf.truncate()")
    .replace("char canonical[PATH_MAX];", "const canonical = {};")
    .replace(
      /struct stat ([a-z_, ]+);/gu,
      (_, names) =>
        `const ${names
          .split(", ")
          .map((name) => `${name} = {}`)
          .join(", ")};`,
    )
    .replace("bool created", "let created")
    .replace(
      "struct entry value = {.fd = build_root};",
      "const value = {fd: build_root, kind: {}, path: {}};",
    )
    .replace(
      /&(report_identity|build_identity|named|parent_named|parent|current|value)\b/gu,
      "$1",
    )
    .replace(/sizeof\([^)]+\)/gu, "4096")
    .replace(/\b0([0-7]{3,5})\b/gu, "0o$1");
  const script = new Script(
    `function same_stat(a, b) {${same}}; () => {${translated}}`,
  );
  const cases = [
    ["inherited group", { gid: 20 }, true],
    ["root group", { gid: 0, parentGid: 0 }, true],
    ["restrictive umask", { gid: 20, mode: 0o400 }, true],
    ["existing private", { existing: true, mode: 0o700 }, true],
    ["existing sealed", { existing: true, mode: 0o555 }, true],
    ["existing inherited group", { existing: true, gid: 20 }],
    ["existing user", { existing: true, uid: 1001 }],
    ["existing writable", { existing: true, mode: 0o777 }],
    ["existing symlink", { existing: true, type: 0o120000 }],
    ["exclusive creation race", { fault: "mkdir" }],
    ["initial query", { fault: "query" }],
    ["created owner", { uid: 1001 }],
    ["created group", { gid: 21 }],
    ["created mode", { mode: 0o750 }],
    ["created ACL", { fault: "acl" }],
    ["held substitution", { fault: "open" }],
    ["held inode reuse", { fault: "birth" }],
    ["parent substitution", { fault: "parent" }],
    ["parent group drift", { fault: "parent-gid" }],
    ["parent ACL", { fault: "parent-acl" }],
    ["name substitution before normalization", { fault: "name" }],
    ["named inode reuse", { fault: "name-birth" }],
    ["ownership failure", { fault: "chown" }],
    ["ownership not applied", { fault: "chown-noop" }],
    ["mode failure", { fault: "chmod" }],
    ["mode not applied", { fault: "chmod-noop", mode: 0o400 }],
    ["post-normalization identity", { fault: "identity" }],
    ["post-normalization name", { fault: "final-name" }],
    ["post-normalization ACL", { fault: "final-acl" }],
  ];
  for (const [label, options, succeeds = false] of cases) {
    const events = [],
      output = "/fixture/report/platform-build",
      text = (value) => (typeof value === "string" ? value : value.value),
      directory = (ino, uid, gid, mode) => ({
        st_dev: 1,
        st_ino: ino,
        st_uid: uid,
        st_gid: gid,
        st_mode: 0o40000 | mode,
        st_nlink: 2,
        st_size: 64,
        st_birthtimespec: { tv_sec: ino, tv_nsec: 0 },
        st_mtimespec: { tv_sec: 1, tv_nsec: 0 },
        st_ctimespec: { tv_sec: 1, tv_nsec: 0 },
      }),
      parent = directory(10, 1001, options.parentGid ?? 20, 0o700);
    let root = options.existing
        ? directory(
            11,
            options.uid ?? 0,
            options.gid ?? 0,
            options.mode ?? 0o700,
          )
        : undefined,
      named = root,
      queries = 0,
      normalized = false;
    if (root && options.type) root.st_mode = options.type | 0o700;
    const env = {
      build_root: -1,
      build_parent: -1,
      build_path: {},
      report_path: {},
      build_identity: {},
      report_identity: {},
      errno: 0,
      ENOENT: 2,
      O_RDONLY: 0,
      O_DIRECTORY: 1,
      O_NOFOLLOW: 2,
      O_CLOEXEC: 4,
      AT_SYMLINK_NOFOLLOW: 8,
      entries: [{ kind: "directory", path: output }],
      count: 1,
      encoded: output,
      need: (ok) => assert.ok(ok, label),
      S_ISDIR: (mode) => (mode & 0o170000) === 0o40000,
      decode: (value, out) => {
        out.value = value;
      },
      strcpy: (out, value) => {
        out.value = text(value);
      },
      strcmp: (a, b) => (text(a) === text(b) ? 0 : 1),
      strrchr: (value) => ({
        next: value.value.slice(value.value.lastIndexOf("/") + 1),
        truncate() {
          value.value = value.value.slice(0, value.value.lastIndexOf("/"));
        },
      }),
      realpath: (value, out) => {
        out.value = text(value);
        return true;
      },
      open: () => 1,
      openat: (fd) => {
        assert.equal(fd, 1);
        if (options.fault === "open") root = { ...root, st_ino: 12 };
        if (options.fault === "birth")
          root = { ...root, st_birthtimespec: { tv_sec: 12, tv_nsec: 0 } };
        return 2;
      },
      fstat(fd, out) {
        Object.assign(out, structuredClone(fd === 1 ? parent : root));
        return 0;
      },
      fstatat(fd, name, out, flags) {
        assert.equal(fd, 1);
        assert.equal(name, "platform-build");
        assert.equal(flags, 8);
        queries++;
        if (!named) {
          env.errno = options.fault === "query" ? 13 : 2;
          return -1;
        }
        if (options.fault === "name" && queries > 2)
          named = { ...named, st_ino: 12 };
        if (options.fault === "name-birth" && queries > 2)
          named = { ...named, st_birthtimespec: { tv_sec: 12, tv_nsec: 0 } };
        Object.assign(out, structuredClone(named));
        return 0;
      },
      lstat(file, out) {
        const isParent = text(file) === "/fixture/report";
        const value = structuredClone(isParent ? parent : named);
        if (isParent && options.fault === "parent") value.st_ino++;
        if (isParent && options.fault === "parent-gid") value.st_gid++;
        if (!isParent && options.fault === "final-name") value.st_ino++;
        Object.assign(out, value);
        return 0;
      },
      mkdirat(fd, name, mode) {
        events.push("mkdir");
        assert.equal(fd, 1);
        assert.equal(mode, 0o700);
        if (options.fault === "mkdir") return -1;
        root = directory(
          11,
          options.uid ?? 0,
          options.gid ?? 20,
          options.mode ?? 0o700,
        );
        named = root;
        return 0;
      },
      no_acl(fd) {
        assert.ok(
          !(
            fd === 2 &&
            (options.fault === "acl" ||
              (normalized && options.fault === "final-acl"))
          ),
          label,
        );
        assert.ok(!(fd === 1 && options.fault === "parent-acl"), label);
      },
      fchown(fd, uid, gid) {
        events.push("chown");
        assert.equal(fd, 2);
        assert.equal(uid, 0);
        assert.equal(gid, 0);
        assert.equal(options.existing, undefined);
        if (options.fault === "chown") return -1;
        if (options.fault !== "chown-noop") {
          root.st_uid = uid;
          root.st_gid = gid;
        }
        return 0;
      },
      fchmod(fd, mode) {
        events.push("chmod");
        assert.equal(fd, 2);
        assert.equal(mode, 0o700);
        if (options.fault === "chmod") return -1;
        if (options.fault !== "chmod-noop") root.st_mode = 0o40000 | mode;
        if (options.fault === "identity") root.st_ino++;
        normalized = true;
        return 0;
      },
      stable(value) {
        assert.equal(value.fd, 2);
        const current = {};
        env.lstat(env.build_path, current);
        assert.deepEqual(current, root, label);
        assert.equal(root.st_uid, 0);
        assert.equal(root.st_gid, 0);
        env.no_acl(1);
        env.no_acl(2);
      },
      identity: () => events.push("admitted"),
    };
    const run = script.runInNewContext(env);
    if (succeeds) {
      run();
      assert.equal(events.at(-1), "admitted", label);
      assert.equal(events.includes("chown"), !options.existing, label);
    } else {
      assert.throws(run, undefined, label);
      assert.ok(!events.includes("admitted"), label);
      if (
        ![
          "chown",
          "chown-noop",
          "chmod",
          "chmod-noop",
          "identity",
          "final-name",
          "final-acl",
        ].includes(options.fault)
      )
        assert.ok(
          !events.includes("chown") && !events.includes("chmod"),
          label,
        );
    }
  }
});

function image(size = 108) {
  const bytes = Buffer.alloc(size);
  for (const [offset, value] of [
    [0, 0xfeedfacf],
    [4, 0x01000007],
    [12, 2],
    [16, 3],
    [20, 72],
    [32, 0xe],
    [36, 32],
    [40, 12],
    [64, 0x1d],
    [68, 16],
    [72, 104],
    [76, 4],
    [80, 0x1b],
    [84, 24],
  ])
    bytes.writeUInt32LE(value, offset);
  bytes.write("/usr/lib/dyld", 44);
  Buffer.from("00112233445566778899aabbccddeeff", "hex").copy(bytes, 88);
  return bytes;
}

function effects({
  compilerError,
  discoveryError,
  gitError,
  bytes = image(),
} = {}) {
  return {
    fs: {
      realpath: async (file) => file,
      readFile: async (file) =>
        file.endsWith("/build/helper") || file.endsWith("/build/argv-fixture")
          ? bytes
          : Buffer.from("synthetic tool or source bytes"),
      chmod: async () => {},
      writeFile: async () => {},
    },
    executeFile: async (file, args, options) => {
      assert.equal(options.maxBuffer, 65536);
      assert.equal(options.encoding, "utf8");
      if (file === "/usr/bin/xcrun") {
        if (args[0] === "--show-sdk-path" && discoveryError)
          throw discoveryError;
        return {
          stdout:
            args[0] === "--show-sdk-version"
              ? "1.2\n"
              : args[0] === "--show-sdk-path"
                ? "/fixture/sdk\n"
                : `/fixture/${args[1]}\n`,
        };
      }
      if (args[0] === "--version") {
        if (file.endsWith("/git") && gitError) throw gitError;
        return {
          stdout: file.endsWith("/clang")
            ? "Apple clang version 1.2.3 (clang-4.5.6)\n"
            : "git version 1.2.3\n",
        };
      }
      if (file === "/usr/bin/codesign") {
        assert.deepEqual(args.slice(0, 2), ["--verify", "--strict"]);
        assert.match(args[2], /\/build\/(?:helper|argv-fixture)$/u);
        return { stdout: "", stderr: "" };
      }
      assert.equal(file, "/fixture/clang");
      assert.equal(options.timeout, 60000);
      assert.deepEqual(args.slice(0, 5), [
        "-std=c11",
        "-arch",
        "x86_64",
        "-isysroot",
        "/fixture/sdk",
      ]);
      assert.ok(args.includes("-Wl,-adhoc_codesign"));
      assert.equal(args.includes("-lsandbox"), args.at(-2).endsWith("/helper"));
      if (compilerError) throw compilerError;
      return { stdout: "", stderr: "" };
    },
  };
}

test("Darwin feasibility attempts later independent compiles and retains the original compiler cause", async () => {
  const first = Object.assign(new Error("first compiler failure"), {
      code: 1,
      signal: null,
    }),
    second = Object.assign(new Error("second compiler failure"), {
      code: 2,
      signal: null,
    }),
    injected = effects(),
    execute = injected.executeFile,
    attempted = [];
  injected.executeFile = async (file, args, options) => {
    if (file === "/fixture/clang" && args[0] !== "--version") {
      attempted.push(args.at(-2));
      throw attempted.length === 1 ? first : second;
    }
    return execute(file, args, options);
  };
  await assert.rejects(
    buildDarwinFeasibility("/fixture/run", [], injected),
    (error) =>
      error.cause === first &&
      /helper-compile-link/u.test(error.feasibilityCause.detail),
  );
  assert.deepEqual(attempted, [
    "/fixture/run/build/helper",
    "/fixture/run/build/argv-fixture",
  ]);
});

test("Darwin command builds opt into libbsm with the actual finite-operation source identity", async () => {
  const [commandSource, helperSource] = await Promise.all(
      ["feasibility-command.h", "feasibility-helper.c"].map((name) =>
        readFile(new URL(name, SOURCE)),
      ),
    ),
    injected = effects(),
    read = injected.fs.readFile,
    run = injected.executeFile,
    commands = [];
  let report;
  injected.fs.readFile = (file) =>
    file.endsWith("/feasibility-command.h")
      ? commandSource
      : file.endsWith("/feasibility-helper.c")
        ? helperSource
        : read(file);
  injected.fs.writeFile = async (file, bytes) => {
    if (file.endsWith("/evidence/build.json")) report = JSON.parse(bytes);
  };
  injected.executeFile = (file, args, options) => {
    if (file === "/fixture/clang" && args[0] !== "--version")
      commands.push(args);
    return run(file, args, options);
  };
  await buildDarwinFeasibility("/fixture/run", [], {
    ...injected,
    commandObservation: true,
  });
  assert.equal(commands.length, 2);
  for (const args of commands)
    for (const flag of ["-DNATIVE_FEASIBILITY_COMMAND", "-lbsm"])
      assert.equal(args.includes(flag), args.at(-2).endsWith("/helper"));
  assert.equal(report.builds[0].commandSourceSha256, digest(commandSource));
  assert.equal(report.builds[0].sourceSha256, digest(helperSource));
  assert.equal(Object.hasOwn(report.builds[1], "commandSourceSha256"), false);
});

test("Darwin build requires native signature verification and unchanged signed UUID/image bytes before admission", async () => {
  for (const mode of [
    "verification-refused",
    "image-changed",
    "runtime-changed",
    "uuid-missing",
  ]) {
    const injected = effects(),
      run = injected.executeFile,
      read = injected.fs.readFile,
      components = [],
      refused = Object.assign(new Error("private signing error"), {
        code: 1,
        signal: null,
      });
    let verified = false;
    injected.executeFile = async (file, args, options) => {
      if (file === "/usr/bin/codesign") {
        if (mode === "verification-refused") throw refused;
        verified = true;
      }
      return run(file, args, options);
    };
    injected.fs.readFile = async (file) => {
      const bytes = Buffer.from(await read(file));
      if (mode === "runtime-changed" && verified && file === "/usr/lib/dyld")
        bytes[0] ^= 1;
      if (file.endsWith("/build/helper")) {
        if (mode === "uuid-missing") bytes.fill(0, 88, 104);
        if (mode === "image-changed" && verified) bytes[105] ^= 1;
      }
      return bytes;
    };
    await assert.rejects(
      buildDarwinFeasibility("/fixture/run", components, injected),
      (error) => {
        assert.match(
          error.feasibilityCause.detail,
          mode === "uuid-missing"
            ? /helper-inspection/u
            : /helper-signature-verification/u,
        );
        assert.doesNotMatch(
          error.feasibilityCause.detail,
          /private signing error/u,
        );
        return true;
      },
    );
    assert.equal(
      components.some(({ role }) => role === "helper"),
      false,
    );
  }
  const injected = effects();
  let report;
  injected.fs.writeFile = async (file, bytes) => {
    if (file.endsWith("/build.json")) report = JSON.parse(bytes);
  };
  await buildDarwinFeasibility("/fixture/run", [], injected);
  for (const built of report.builds) {
    assert.equal(built.imageUUID, "00112233-4455-6677-8899-aabbccddeeff");
    assert.equal(built.imageSha256, digest(image()));
    for (const name of ["loader", "signatureVerifier"])
      assert.equal(
        built.runtime[name].sha256,
        digest(Buffer.from("synthetic tool or source bytes")),
      );
  }
});

test("Darwin command source binds prerequisite and captured versions to the SDK OpenBSM declaration", async () => {
  const [command, helper, driver] = await Promise.all(
    [
      "feasibility-command.h",
      "feasibility-helper.c",
      "feasibility-command-effects.js",
    ].map((name) => readFile(new URL(name, SOURCE), "utf8")),
  );
  // Protect fragile SDK/API forms only; no SDK, compiler or native decoder runs.
  assert.match(
    command,
    /#if defined\(AUDIT_HEADER_VERSION_OPENBSM\)[\s\S]*?#define COMMAND_BSM_VERSION AUDIT_HEADER_VERSION_OPENBSM\s*#else\s*#error[^\n]*OpenBSM[^\n]*\s*#endif/u,
  );
  assert.doesNotMatch(
    command,
    /\bTOKEN_VERSION\b|#define COMMAND_BSM_VERSION [0-9]|defined\(AUDIT_HEADER_VERSION\)/u,
  );
  assert.match(command, /headerVersion[^\n]*COMMAND_BSM_VERSION/u);
  assert.match(command, /raw\[5\]==COMMAND_BSM_VERSION/u);
  assert.match(
    helper,
    /#ifdef NATIVE_FEASIBILITY_COMMAND\s*#include "feasibility-command\.h"/u,
  );
  assert.match(
    helper,
    /static void no_acl\(int fd, const struct stat \*expected\)/u,
  );
  assert.equal([...command.matchAll(/no_acl\(fd, &st\)/gu)].length, 2);
  assert.match(command, /no_acl\(command_gate_fd, &held\)/u);
  assert.doesNotMatch(command, /no_acl\([^,()]+\)/u);
  assert.match(driver, /commandObservation: true/u);
  assert.match(driver, /usr\/include\/bsm\/audit_record\.h/u);
  assert.match(driver, /headerVersion: prerequisites\.headerVersion/u);
  assert.match(driver, /sdkSha256: components\.find/u);
  assert.match(driver, /abiSha256: digest\(abi\)/u);
});

test("Darwin build retains compiler and linker diagnoses with observed outcomes", async () => {
  for (const [fields, code, explanation, commandObservation = false] of [
    [
      {
        code: 1,
        signal: null,
        stderr: "error: call to undeclared function 'sandbox_check'",
      },
      "setup-failed",
      /undeclared function 'sandbox_check'/u,
    ],
    [
      {
        code: 1,
        signal: null,
        stderr: "error: use of undeclared identifier 'COMMAND_BSM_VERSION'",
      },
      "setup-failed",
      /undeclared identifier 'COMMAND_BSM_VERSION'/u,
      true,
    ],
    [
      {
        code: 1,
        signal: null,
        stderr: "error: too few arguments to function call, expected 2, have 1",
      },
      "setup-failed",
      /incorrect argument count/u,
      true,
    ],
    [
      {
        code: 1,
        signal: null,
        stderr: "error: incompatible function pointer types",
      },
      "setup-failed",
      /incompatible declarations or types/u,
    ],
    [
      {
        code: 1,
        signal: null,
        stderr:
          "/private/helper.c:4: error: call to undeclared function 'fixture_call'\npassword=private",
      },
      "setup-failed",
      /undeclared function 'fixture_call'/u,
    ],
    [
      {
        code: 1,
        signal: null,
        stderr: "Undefined symbols for architecture x86_64:\n/private/library",
      },
      "setup-failed",
      /linker reported unresolved symbols/u,
    ],
    [
      { code: null, signal: "SIGSEGV" },
      "crash",
      /signal=SIGSEGV, timeout=false/u,
    ],
    [
      { code: null, signal: "SIGTERM", timedOut: true },
      "deadline",
      /signal=SIGTERM, timeout=true/u,
    ],
    [
      { code: "ETIMEDOUT", signal: "SIGTERM" },
      "deadline",
      /signal=SIGTERM, timeout=true/u,
    ],
  ]) {
    const components = [];
    await assert.rejects(
      buildDarwinFeasibility("/fixture/run", components, {
        ...effects({
          compilerError: Object.assign(new Error("private transcript"), fields),
        }),
        commandObservation,
      }),
      (error) => {
        const cause = darwinFeasibilityCause("build", error);
        assert.deepEqual(cause, error.feasibilityCause);
        assert.equal(cause.code, code);
        assert.match(cause.detail, /^build helper-compile-link:/u);
        assert.match(cause.detail, explanation);
        assert.ok(
          cause.detail.includes(
            `exit=${Number.isInteger(fields.code) ? fields.code : "unknown"}`,
          ),
        );
        assert.doesNotMatch(cause.detail, /private|password|transcript/u);
        return true;
      },
    );
    assert.deepEqual(
      components.map(({ name }) => name),
      ["apple-clang", "macos-sdk"],
    );
  }
  const unknown = darwinFeasibilityCause("build", { killed: true });
  assert.equal(unknown.code, "setup-failed");
  assert.match(
    unknown.detail,
    /exit=unknown, signal=unknown, timeout=unknown/u,
  );
});

test("Darwin build binds the optional policy SPI from actual source bytes and retains its identity", async () => {
  const sources = Object.fromEntries(
    await Promise.all(
      [
        "feasibility-helper.c",
        "feasibility-sandbox.h",
        "feasibility-domain.h",
        "custody.h",
        "argv-fixture.c",
      ].map(async (name) => [name, await readFile(new URL(name, SOURCE))]),
    ),
  );
  const binding = sources["feasibility-sandbox.h"].toString("utf8"),
    helper = sources["feasibility-helper.c"].toString("utf8");
  // Protect the established variadic ABI and const data export, not a guessed
  // macro, implicit declaration, or cast of the symbol's address to a flag.
  assert.match(
    binding,
    /typedef int \(\*feasibility_sandbox_check_fn\)\(pid_t, const char \*, int, \.\.\.\);/u,
  );
  assert.match(binding, /_Static_assert\(sizeof\(int\) == 4,/u);
  assert.match(binding, /const int \*no_report;/u);
  assert.match(binding, /dlsym\(RTLD_DEFAULT, "sandbox_check"\)/u);
  assert.match(binding, /dlsym\(RTLD_DEFAULT, "SANDBOX_CHECK_NO_REPORT"\)/u);
  for (const member of ["check", "no_report"])
    assert.ok(binding.includes(`if (dlerror()) binding.${member} = NULL;`));
  assert.match(
    binding,
    /return binding\.check\(pid, NULL, \*binding\.no_report\);/u,
  );
  assert.doesNotMatch(binding, /#\s*define\s+SANDBOX_CHECK_NO_REPORT\b/u);
  assert.match(helper, /#include "feasibility-sandbox\.h"/u);
  assert.doesNotMatch(helper, /\bsandbox_check\s*\(/u);

  const injected = effects(),
    read = injected.fs.readFile,
    run = injected.executeFile,
    compilerBytes = Buffer.from("fixture compiler image"),
    sdkBytes = Buffer.from('{"Version":"1.2"}'),
    builds = [],
    components = [];
  let report;
  injected.fs.readFile = (file) => {
    const name = file.slice(file.lastIndexOf("/") + 1);
    if (file === "/fixture/clang") return compilerBytes;
    if (file === "/fixture/sdk/SDKSettings.json") return sdkBytes;
    return Object.hasOwn(sources, name) ? sources[name] : read(file);
  };
  injected.fs.writeFile = async (file, bytes, options) => {
    assert.equal(options.flag, "wx");
    if (file.endsWith("/evidence/build.json")) report = JSON.parse(bytes);
  };
  injected.executeFile = async (file, args, options) => {
    if (file === "/fixture/clang" && args[0] !== "--version") {
      builds.push(args);
      for (const flag of [
        "-w",
        "-Wno-implicit-function-declaration",
        "-Wno-error=implicit-function-declaration",
        "-fshort-enums",
      ])
        assert.equal(args.includes(flag), false);
      assert.ok(args.includes("-Wall") && args.includes("-Wextra"));
      assert.equal(args.at(-1).endsWith(".c"), true);
    }
    return run(file, args, options);
  };
  await buildDarwinFeasibility("/fixture/run", components, injected);
  assert.equal(builds.length, 2);
  assert.equal(builds[0].includes("-lsandbox"), true);
  assert.equal(builds[1].includes("-lsandbox"), false);
  for (const args of builds) {
    assert.equal(args.includes("-DNATIVE_FEASIBILITY_COMMAND"), false);
    assert.equal(args.includes("-lbsm"), args.at(-2).endsWith("/helper"));
  }
  assert.equal(
    report.builds[0].sourceSha256,
    digest(sources["feasibility-helper.c"]),
  );
  assert.equal(
    report.builds[0].bindingSha256,
    digest(sources["feasibility-sandbox.h"]),
  );
  assert.equal(
    report.builds[1].sourceSha256,
    digest(sources["argv-fixture.c"]),
  );
  assert.equal(Object.hasOwn(report.builds[1], "bindingSha256"), false);
  assert.equal(
    report.builds[0].domainSourceSha256,
    digest(sources["feasibility-domain.h"]),
  );
  assert.equal(
    report.builds[0].custodySourceSha256,
    digest(sources["custody.h"]),
  );
  assert.equal(Object.hasOwn(report.builds[0], "commandSourceSha256"), false);
  assert.deepEqual(report.components, components);
  assert.equal(
    components[0].version,
    "Apple clang version 1.2.3 (clang-4.5.6)",
  );
  assert.equal(components[1].version, "1.2");
  assert.equal(components[0].sha256, digest(compilerBytes));
  assert.equal(components[1].sha256, digest(sdkBytes));
});

test("Darwin custody sandbox queries retain typed exports, availability and path decisions", async () => {
  const [binding, custody, effective] = await Promise.all(
    ["feasibility-sandbox.h", "custody-reader.c", "effective-reader.h"].map(
      (name) => readFile(new URL(name, SOURCE), "utf8"),
    ),
  );
  for (const source of [custody, effective]) {
    assert.doesNotMatch(source, /\bsandbox_check\s*\(/u);
    assert.match(
      source,
      /int result = feasibility_sandbox_path\([^;]+;\s*need\(result == 0 \|\| result == 1\)/u,
    );
  }
  assert.match(custody, /#include "feasibility-sandbox\.h"/u);
  assert.match(
    custody,
    /int value = feasibility_sandbox_active\(sandbox_binding, pid\);\s*need\(value == 0 \|\| value == 1\)/u,
  );
  assert.match(custody, /sandbox_active\(getpid\(\)\) == 0/u);
  const main = custody.slice(custody.indexOf("int main("));
  assert.match(
    main,
    /!feasibility_sandbox_available\(sandbox_binding\)\) \{ errno = ENOSYS; need\(0\); \}/u,
  );
  assert.ok(
    main.indexOf("feasibility_sandbox_load()") < main.indexOf("probe(pid,"),
  );
  const body =
    /static inline int feasibility_sandbox_path\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      binding,
    )?.[1];
  assert.ok(body);
  assert.match(binding, /FEASIBILITY_SANDBOX_FILTER_PATH = 1/u);
  const script = new Script(
    `(binding) => {${body
      .replaceAll("*binding.no_report", "binding.no_report.value")
      .replaceAll("FEASIBILITY_SANDBOX_FILTER_PATH", "1")}}`,
  );
  for (const [missing, result] of [
    ["check", -1],
    ["data", -1],
    [null, 0],
    [null, 1],
    [null, -1],
    [null, 2],
  ]) {
    const calls = [],
      context = {
        pid: 42,
        operation: "file-write-data",
        path: "/fixture/item",
        errno: 0,
        ENOSYS: 99,
        feasibility_sandbox_available: (value) =>
          value.check !== null && value.no_report !== null,
      },
      value = {
        check:
          missing === "check"
            ? null
            : (...args) => {
                calls.push(args);
                return result;
              },
        no_report: missing === "data" ? null : { value: 64 },
      };
    assert.equal(script.runInNewContext(context)(value), result);
    assert.equal(context.errno, missing ? context.ENOSYS : 0);
    assert.deepEqual(
      calls,
      missing ? [] : [[42, "file-write-data", 65, "/fixture/item"]],
    );
  }
});

test("Darwin PF counters use the source-derived states field without normalizing experiment authority or order", async () => {
  const [effective, custody] = await Promise.all(
    ["effective-reader.h", "custody-reader.c"].map((name) =>
      readFile(new URL(name, SOURCE), "utf8"),
    ),
  );
  assert.match(effective, /pf_rule_counters\(&query\.rule\);/u);
  assert.match(custody, /pf_rule_counters\(r\);/u);
  assert.match(
    effective,
    /#ifndef NATIVE_CI_EXPERIMENT\s+memset\(query\.rule\.skip/u,
  );
  assert.match(custody, /#ifndef NATIVE_CI_EXPERIMENT\s+memset\(r->skip/u);
  const actions =
    /static unsigned pf_action\(unsigned set\) \{[\s\S]*?actions\[\] = \{([\s\S]*?)\};/u.exec(
      effective,
    )?.[1];
  assert.ok(actions);
  assert.deepEqual(
    actions
      .replace(/#(?:ifdef NATIVE_CI_EXPERIMENT|endif)/gu, "")
      .match(/PF_[A-Z]+/gu),
    ["PF_SCRUB", "PF_PASS", "PF_NAT", "PF_BINAT", "PF_RDR", "PF_DUMMYNET"],
  );
  assert.match(
    effective,
    /DIOCGETSTATES[\s\S]*states\.ps_buf = state_bytes[\s\S]*states\.ps_len == length/u,
  );
  assert.match(custody, /rule_ticket = r->ticket[\s\S]*pf_rule_counters\(r\)/u);
  const body = /static void pf_rule_counters\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    effective,
  )?.[1];
  assert.ok(body);
  for (const experiment of [false, true]) {
    const selected = body.replace(
      /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#else\n([\s\S]*?)#endif/u,
      (_, ordinary, reviewed) => (experiment ? ordinary : reviewed),
    );
    if (experiment) assert.doesNotMatch(selected, /states_cur|states_tot/u);
    const normalize = new Script(
      `(r) => {${selected
        .replaceAll("r->", "r.")
        .replace(
          /memset\(r\.(packets|bytes), 0, sizeof\(r\.\1\)\)/gu,
          "r.$1.fill(0)",
        )}}`,
    ).runInNewContext();
    const rule = {
        evaluations: 7,
        src_nodes: 2,
        states: 3,
        ticket: 17,
        states_cur: 4,
        states_tot: 5,
        packets: [10, 20],
        bytes: [30, 40],
        nr: 6,
        action: 1,
        owner: "fixture",
        max_states: 90,
        timeout: [11],
      },
      expected = {
        ...structuredClone(rule),
        evaluations: 0,
        src_nodes: 0,
        packets: [0, 0],
        bytes: [0, 0],
        ...(experiment
          ? { states: 0, ticket: 0 }
          : { states_cur: 0, states_tot: 0, nr: 0 }),
      };
    normalize(rule);
    assert.deepEqual(rule, expected);
  }
});

test("Darwin PF return semantics reject altered ICMP responses and queue selectors", async () => {
  const source = await readFile(new URL("effective-reader.h", SOURCE), "utf8"),
    body = /static bool pf_return_supported\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(body);
  const accepts = new Script(
      `(r) => {${body.replaceAll("r->", "r.")}}`,
    ).runInNewContext({
      PFRULE_RETURN: 8,
      AF_INET: 2,
      AF_INET6: 30,
      ICMP_UNREACH: 3,
      ICMP_UNREACH_PORT: 3,
      ICMP6_DST_UNREACH: 1,
      ICMP6_DST_UNREACH_NOPORT: 4,
    }),
    rule = {
      rule_flag: 8,
      proto: 17,
      af: 0,
      return_icmp: 0x0303,
      return_icmp6: 0x0104,
    };
  for (const [patch, expected] of [
    [{}, true],
    [{ return_icmp: 0 }, false],
    [{ return_icmp6: 0 }, false],
    [{ return_icmp: 0x0301 }, false],
    [{ return_icmp6: 0x0101 }, false],
    [{ af: 2, return_icmp6: 0 }, true],
    [{ af: 30, return_icmp: 0 }, true],
    [{ proto: 6, return_icmp: 0, return_icmp6: 0 }, false],
    [{ rule_flag: 0, return_icmp: 0, return_icmp6: 0 }, true],
  ])
    assert.equal(accepts({ ...rule, ...patch }), expected);
  assert.match(source, /!r->qid && !r->pqid/u);
  assert.match(source, /&& pf_return_supported\(r\) &&/u);
});

test("Darwin PF route authority preserves policy while ignoring documented usage counters", async () => {
  const source = await readFile(new URL("effective-reader.h", SOURCE), "utf8"),
    body = /static void pf_route_counters\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(body);
  const normalize = new Script(
      `(r) => {${body.replaceAll("r->", "r.")}}`,
    ).runInNewContext(),
    route = {
      rtm_use: 7,
      rtm_index: 2,
      rtm_flags: 3,
      rtm_addrs: 5,
      rtm_rmx: { rmx_pksent: 11, rmx_mtu: 1500, rmx_expire: 30, rmx_locks: 1 },
    },
    expected = {
      ...structuredClone(route),
      rtm_use: 0,
      rtm_rmx: { ...route.rtm_rmx, rmx_pksent: 0 },
    };
  normalize(route);
  assert.deepEqual(route, expected);
  route.rtm_use = 12;
  route.rtm_rmx.rmx_pksent = 19;
  normalize(route);
  assert.deepEqual(route, expected);
  assert.match(source, /header\.rtm_msglen <= size - offset/u);
  assert.match(
    source,
    /header\.rtm_version == RTM_VERSION && header\.rtm_type == RTM_GET/u,
  );
  assert.match(source, /pf_route_digest\(routes, size, hash\)/u);
  assert.match(source, /pf_route_digest\(routes, size, route_hash\)/u);
});

test("Darwin cache loader queries validate SDK records and reject substituted UUID or base before image reads", async () => {
  const source = await readFile(new URL("custody-reader.c", SOURCE), "utf8"),
    body =
      /static struct dyld_all_image_infos cache_loader\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
        source,
      )?.[1];
  assert.ok(body);
  assert.doesNotMatch(source, /\b_dyld_get_all_image_infos\b/u);
  assert.match(source, /#include <mach\/task_info\.h>/u);
  assert.match(source, /#include <mach-o\/dyld_images\.h>/u);
  assert.match(
    body,
    /offsetof\(struct dyld_all_image_infos, sharedCacheBaseAddress\) \+ sizeof\(images\.sharedCacheBaseAddress\)/u,
  );
  const script = new Script(
    `(uuid, base) => {${body
      .replace("task_dyld_info_data_t info = {0};", "const info = {};")
      .replace("mach_msg_type_number_t count", "let count")
      .replace("(task_info_t)&info", "info")
      .replace("&count", "value => { count = value; }")
      .replace(
        "struct dyld_all_image_infos images = {0};",
        "const images = {};",
      )
      .replace(/const size_t size = [^;]+;/u, "const size = sdkPrefix;")
      .replace("mach_vm_size_t actual = 0;", "let actual = 0n;")
      .replace("(mach_vm_address_t)&images", "images")
      .replace("&actual", "value => { actual = value; }")
      .replace(
        "sizeof(images.sharedCacheUUID)",
        "images.sharedCacheUUID.length",
      )}}`,
  );
  // Counts and sizes are symbolic here; only the matching SDK supplies layouts.
  const sdkCount = 7,
    sdkPrefix = 64n,
    base = 0x10000n,
    uuid = Buffer.alloc(16, 1),
    maximum = (1n << 64n) - 1n;
  for (const [fault, change, reads] of [
    ["valid", () => {}, 1],
    [
      "valid newer tail",
      (value) => {
        value.images.version = 17;
        value.info.all_image_info_size += sdkPrefix;
      },
      1,
    ],
    [
      "task failure",
      (value) => {
        value.taskResult = 1;
      },
      0,
    ],
    [
      "short count",
      (value) => {
        value.count--;
      },
      0,
    ],
    [
      "unknown format",
      (value) => {
        value.info.all_image_info_format = 0;
      },
      0,
    ],
    [
      "null address",
      (value) => {
        value.info.all_image_info_addr = 0n;
      },
      0,
    ],
    [
      "short record",
      (value) => {
        value.info.all_image_info_size = sdkPrefix - 1n;
      },
      0,
    ],
    [
      "wrapped extent",
      (value) => {
        value.info.all_image_info_addr = maximum - sdkPrefix + 1n;
      },
      0,
    ],
    [
      "read failure",
      (value) => {
        value.readResult = 1;
      },
      1,
    ],
    [
      "short read",
      (value) => {
        value.actual--;
      },
      1,
    ],
    [
      "old version",
      (value) => {
        value.images.version = 14;
      },
      1,
    ],
    [
      "substituted UUID",
      (value) => {
        value.images.sharedCacheUUID = Buffer.alloc(16, 2);
      },
      1,
    ],
    [
      "substituted base",
      (value) => {
        value.images.sharedCacheBaseAddress++;
      },
      1,
    ],
  ]) {
    const value = {
        taskResult: 0,
        readResult: 0,
        count: sdkCount,
        actual: sdkPrefix,
        info: {
          all_image_info_addr: 0x1000n,
          all_image_info_size: sdkPrefix,
          all_image_info_format: 1,
        },
        images: {
          version: 15,
          sharedCacheUUID: uuid,
          sharedCacheBaseAddress: base,
          sharedCacheSlide: 0x100n,
        },
      },
      calls = [];
    change(value);
    const loader = script.runInNewContext({
      sdkPrefix,
      TASK_DYLD_INFO_COUNT: sdkCount,
      TASK_DYLD_INFO: 17,
      TASK_DYLD_ALL_IMAGE_INFO_64: 1,
      KERN_SUCCESS: 0,
      UINT64_MAX: maximum,
      mach_task_self: () => "self",
      task_info(self, flavor, result, count) {
        assert.equal(self, "self");
        assert.equal(flavor, 17);
        calls.push("task");
        Object.assign(result, value.info);
        count(value.count);
        return value.taskResult;
      },
      mach_vm_read_overwrite(self, address, size, result, actual) {
        assert.equal(self, "self");
        assert.equal(address, value.info.all_image_info_addr);
        assert.equal(size, sdkPrefix);
        calls.push("read");
        Object.assign(result, value.images);
        actual(value.actual);
        return value.readResult;
      },
      memcmp: (left, right, size) =>
        left.subarray(0, size).compare(right.subarray(0, size)),
      need: (condition) => {
        assert.ok(condition, fault);
      },
    });
    if (fault.startsWith("valid"))
      assert.deepEqual({ ...loader(uuid, base) }, value.images);
    else
      assert.throws(() => loader(uuid, base), { code: "ERR_ASSERTION" }, fault);
    assert.deepEqual(calls, ["task", ...Array(reads).fill("read")], fault);
  }
});

test("Darwin cache image reads reject wrapped slides and ranges while retaining stable mapped text", async () => {
  const source = await readFile(new URL("custody-reader.c", SOURCE), "utf8"),
    body = /static bool cache_contains\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1],
    image = source.slice(
      source.indexOf("static void cache_image("),
      source.indexOf("static bool owned_access_socket("),
    );
  assert.ok(body);
  const maximum = (1n << 64n) - 1n,
    contains = new Script(
      `(base, length, address, size) => !!(() => {${body}})()`,
    ).runInNewContext({ UINT64_MAX: maximum });
  for (const [base, length, address, size, expected] of [
    [16n, 32n, 16n, 32n, true],
    [16n, 32n, 40n, 8n, true],
    [16n, 32n, 40n, 9n, false],
    [16n, 32n, 15n, 1n, false],
    [16n, 32n, 49n, 1n, false],
    [16n, 32n, 16n, maximum, false],
    [maximum - 7n, 8n, maximum - 7n, 1n, false],
    [0n, 32n, 16n, 1n, false],
    [16n, 0n, 16n, 1n, false],
    [16n, 32n, 16n, 0n, false],
  ])
    assert.equal(contains(base, length, address, size), expected);
  const slide =
    /need\((address <= UINT64_MAX - images\.sharedCacheSlide)\)/u.exec(
      image,
    )?.[1];
  assert.ok(slide);
  const canSlide = new Script(`(address, images) => ${slide}`).runInNewContext({
    UINT64_MAX: maximum,
  });
  assert.equal(canSlide(maximum - 1n, { sharedCacheSlide: 1n }), true);
  assert.equal(canSlide(maximum, { sharedCacheSlide: 1n }), false);
  assert.equal(canSlide(16n, { sharedCacheSlide: 0n }), true);
  for (const size of ["sizeof(struct mach_header_64)", "size", "text_size"])
    assert.ok(
      image.includes(`cache_contains(base, range_size, address, ${size})`),
    );
  assert.match(image, /address \+= images\.sharedCacheSlide/u);
  assert.match(image, /matched == 1/u);
  assert.match(image, /memcmp\(header \+ 88, uuid, 16\)/u);
  assert.match(image, /length <= \(uint64_t\)entry->stat.st_size - offset/u);
  assert.match(
    image,
    /pass < 2[\s\S]*CC_SHA256\(text,[\s\S]*memcmp\(sums\[0\], sums\[1\]/u,
  );
  assert.match(
    image,
    /after\.sharedCacheSlide == images\.sharedCacheSlide && _dyld_get_shared_cache_range\(&after_size\) == range && after_size == range_size/u,
  );
  assert.match(image, /stable\(entry\)/u);
});

test("Darwin bootstrap reads bind only fixed protected tools before experiment custody", async () => {
  const source = await readFile(new URL("custody-reader.c", SOURCE), "utf8"),
    guard = source.match(/\(index == 0 \? ([^\n]+)\)\);/u)?.[1];
  assert.ok(guard);
  const accepts = new Script(
    `(index, mode) => !!(index == 0 ? ${guard.replaceAll(/\b0([0-7]+)\b/gu, "0o$1")})`,
  ).runInNewContext();
  for (const [index, mode, expected] of [
    [0, 0o4111, true],
    [0, 0o4755, true],
    [0, 0o4555, true],
    [0, 0o4777, false],
    [0, 0o6755, false],
    [0, 0o4510, false],
    [0, 0o755, false],
    [1, 0o755, true],
    [1, 0o4111, false],
  ])
    assert.equal(accepts(index, mode), expected);
  assert.match(
    source,
    /const char \*paths\[\] = \{"\/usr\/bin\/sudo", "\/usr\/bin\/env"\}/u,
  );
  assert.match(source, /st\.st_size <= 134217728/u);
  assert.match(
    source,
    /bootstrap_tool\(0, argv\[2\]\); bootstrap_tool\(1, argv\[3\]\)/u,
  );
  const operation = source.slice(
    source.indexOf("static void bootstrap_tools("),
    source.indexOf("int main("),
  );
  assert.ok(
    operation.indexOf('openat(base, "bootstrap-owner"') <
      operation.indexOf("line(0, release"),
  );
  assert.ok(
    operation.indexOf("line(0, release") <
      operation.indexOf("bootstrap_tool(0, NULL)"),
  );
  assert.match(
    operation,
    /proc_pidinfo\(original\.token\.val\[5\][\s\S]*n == 0 && errno == ESRCH/u,
  );
  assert.doesNotMatch(operation, /kill\(|exec[lv]|posix_spawn/u);
  const verifiers = source.slice(
    source.indexOf("static void bootstrap_verifier("),
    source.indexOf("static void bootstrap_tools("),
  );
  assert.match(verifiers, /openat\(base, name, O_WRONLY \| O_CREAT \| O_EXCL/u);
  assert.match(
    verifiers,
    /need\(fd >= 0 && !fstat\(fd, &before\)[\s\S]*n == 0 && errno == ESRCH/u,
  );
});

test("Darwin optional policy admission refuses missing exports before effects and keeps live identity checks", async () => {
  const [binding, helper] = await Promise.all(
    ["feasibility-sandbox.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(name, SOURCE), "utf8"),
    ),
  );
  assert.match(
    binding,
    /return binding\.check != NULL && binding\.no_report != NULL;/u,
  );
  assert.match(
    binding,
    /if \(!feasibility_sandbox_available\(binding\)\)\s*\{\s*errno = ENOSYS;\s*return -1;/u,
  );
  const prerequisites = helper.slice(
    helper.indexOf("static void prerequisites(void)"),
    helper.indexOf("static void no_acl("),
  );
  assert.match(
    prerequisites,
    /!feasibility_sandbox_available\(sandbox_binding\).*?remember\("sandbox-binding", "invariant", 0\); failure\(78\);/su,
  );
  assert.ok(
    prerequisites.indexOf("feasibility_sandbox_available") <
      prerequisites.indexOf("pipe(control)"),
  );
  const policy = helper.slice(
    helper.indexOf('} else if ((!strcmp(argv[1], "policy")'),
    helper.indexOf('} else if (!strcmp(argv[1], "files")'),
  );
  assert.match(
    policy,
    /need\(live\(value\)\);\s*int expected = !strcmp\(argv\[1\], "policy"\) \? 1 : 0;\s*errno = 0; int active = feasibility_sandbox_active\(sandbox_binding, \(pid_t\)value\.token\.val\[5\]\);/u,
  );
  assert.match(
    policy,
    /active < 0 && \(errno == ENOSYS \|\| errno == ENOTSUP\)/u,
  );
  assert.match(policy, /need\(active == expected && live\(value\)\);/u);
  for (const [code, expected] of [
    [78, "prerequisite-unavailable"],
    [126, "setup-failed"],
  ]) {
    const cause = darwinFeasibilityCause("policy", {
      code,
      signal: null,
      timedOut: false,
    });
    assert.equal(cause.code, expected);
    assert.match(
      cause.detail,
      new RegExp(`exit=${code}, signal=none, timeout=false`, "u"),
    );
  }
});

test("Darwin SDK discovery failure retains the selected compiler identity", async () => {
  const components = [];
  await assert.rejects(
    buildDarwinFeasibility(
      "/fixture/run",
      components,
      effects({
        discoveryError: Object.assign(new Error("private path"), {
          code: 1,
          signal: null,
          stderr: "xcrun: error: SDK cannot be located",
        }),
      }),
    ),
    (error) => {
      assert.equal(error.feasibilityCause.code, "prerequisite-unavailable");
      assert.match(
        error.feasibilityCause.detail,
        /^build sdk-discovery: exit=1/u,
      );
      return true;
    },
  );
  assert.deepEqual(
    components.map(({ name }) => name),
    ["apple-clang"],
  );
  assert.match(components[0].sha256, /^[a-f0-9]{64}$/u);
});

test("Darwin Git version failure retains every already observed tool and helper identity", async () => {
  const components = [];
  await assert.rejects(
    buildDarwinFeasibility(
      "/fixture/run",
      components,
      effects({
        gitError: Object.assign(new Error("Version command failed"), {
          code: 1,
          signal: null,
        }),
      }),
    ),
    (error) => {
      assert.match(
        error.feasibilityCause.detail,
        /^build git-version: exit=1/u,
      );
      return true;
    },
  );
  assert.deepEqual(
    components.map(({ name }) => name),
    ["apple-clang", "macos-sdk", "helper", "argv-fixture", "apple-git"],
  );
  assert.equal(components.at(-1).version, "unobserved");
  assert.match(components.at(-1).sha256, /^[a-f0-9]{64}$/u);
});

test("Darwin binary inspection identifies refused conditions without admitting helpers", async () => {
  for (const [condition, change, size] of [
    ["header", (bytes) => bytes.writeUInt32LE(0x0100000c, 4)],
    ["signature", (bytes) => bytes.writeUInt32LE(0, 64)],
    ["loader", (bytes) => bytes.write("/bad/lib/dyld", 44)],
    ["segment", (bytes) => bytes.writeUInt32LE(0x19, 64)],
    [
      "purpose",
      (bytes) => {
        bytes.writeUInt32LE(4, 16);
        bytes.writeUInt32LE(224, 20);
        bytes.writeUInt32LE(316, 72);
        bytes.writeUInt32LE(0x19, 104);
        bytes.writeUInt32LE(152, 108);
        bytes.write("__TEXT", 112);
        bytes.writeBigUInt64LE(320n, 136);
        bytes.writeBigUInt64LE(320n, 152);
        bytes.writeUInt32LE(5, 160);
        bytes.writeUInt32LE(5, 164);
        bytes.writeUInt32LE(1, 168);
        bytes.write("__nexp", 176);
        bytes.write("__TEXT", 192);
        bytes.writeBigUInt64LE(272n, 208);
        bytes.writeBigUInt64LE(23n, 216);
        bytes.writeUInt32LE(272, 224);
        bytes.write("native-ci-experiment-v1\0", 272);
      },
      320,
    ],
  ]) {
    const bytes = image(size),
      components = [];
    change(bytes);
    await assert.rejects(
      buildDarwinFeasibility("/fixture/run", components, effects({ bytes })),
      (error) => {
        assert.equal(error.feasibilityCause.code, "setup-failed");
        assert.ok(
          error.feasibilityCause.detail.startsWith(
            `build helper-inspection-${condition}: exit=unknown`,
          ),
        );
        return true;
      },
    );
    assert.equal(
      components.some(({ role }) => role === "helper"),
      false,
    );
  }
  const components = [];
  await buildDarwinFeasibility("/fixture/run", components, effects());
  assert.deepEqual(
    components.filter(({ role }) => role === "helper").map(({ name }) => name),
    ["helper", "argv-fixture"],
  );
});

test("Darwin prerequisite source retains Apple ACL, volume, task-name and direct-errno contracts", async () => {
  const helper = await readFile(
    new URL("feasibility-helper.c", SOURCE),
    "utf8",
  );
  // Source checks protect fragile API forms only, never actual SDK compilation
  // or native control behavior. The injected preparation tests own report joins.
  const acl = helper.slice(
    helper.indexOf("static void no_acl("),
    helper.indexOf("static void object_identity_links("),
  );
  assert.match(acl, /fstatx_np\(fd, &inspected, security\)/u);
  assert.match(
    acl,
    /filesec_query_property\(security, FILESEC_ACL, &present\); error = errno;\s*if \(result\) \{[^}]*goto done;/u,
  );
  assert.doesNotMatch(
    acl,
    /\bpresent\s*(?:==|!=)\s*1\b|\bFS_(?:ISVALID|VALID_ACL)\b/u,
  );
  const branch = /if \((present != 0)\) \{/u.exec(acl);
  assert.ok(branch);
  // This C integer predicate is also valid JavaScript. Execute the exact source
  // expression instead of maintaining a second ACL implementation or using an SDK.
  const predicate = new Script(branch[1]);
  for (const [present, expected] of [
    [0, false],
    [32, true],
  ])
    assert.equal(predicate.runInNewContext({ present }), expected);
  assert.match(acl, /filesec_get_property\(security, FILESEC_ACL, &acl\)/u);
  assert.match(acl, /if \(result \|\| !acl\) \{/u);
  assert.doesNotMatch(acl, /acl_get_fd_np\(|(?:error|errno) == ENOENT/u);
  assert.match(acl, /same_file_stat\(expected, &inspected\)/u);
  assert.match(acl, /fstat\(fd, &after\)/u);
  assert.match(acl, /same_file_stat\(expected, &after\)/u);
  assert.ok(acl.indexOf("fstatx_np(") < acl.indexOf("filesec_query_property("));
  assert.ok(acl.indexOf("filesec_query_property(") < branch.index);
  assert.ok(
    acl.indexOf("filesec_get_property(") < acl.indexOf("fstat(fd, &after)"),
  );
  const stable = helper.slice(
    helper.indexOf("static bool same_file_stat("),
    helper.indexOf("static void no_acl("),
  );
  for (const field of [
    "st_dev",
    "st_ino",
    "st_uid",
    "st_gid",
    "st_mode",
    "st_nlink",
    "st_birthtimespec.tv_sec",
    "st_birthtimespec.tv_nsec",
  ])
    assert.ok(stable.includes(`a->${field} == b->${field}`));
  assert.match(helper, /no_acl\(fd, &st\);/u);
  assert.match(helper, /result == -1 && error == EINVAL/u);
  assert.match(helper, /int freed = acl_free\(acl\), free_error = errno;/u);
  assert.match(acl, /remember_cleanup\("acl-release", "errno", free_error\)/u);
  assert.match(acl, /if \(security\) filesec_free\(security\);/u);
  assert.ok(acl.indexOf("done:") < acl.indexOf("acl_free("));
  assert.ok(acl.indexOf("acl_free(") < acl.indexOf("filesec_free("));
  assert.ok(acl.indexOf("filesec_free(") < acl.indexOf("failure(code)"));
  assert.doesNotMatch(acl, /(?:=|if\s*\()\s*filesec_free\(/u);
  assert.match(helper, /invariant\(st\.st_gid == getgid\(\), "file-group"\)/u);
  assert.match(helper, /sizeof\(volume\) == 20/u);
  assert.match(helper, /task_name_for_pid\(mach_task_self\(\), pid, &task\)/u);
  assert.match(
    helper,
    /task_info\(task, TASK_AUDIT_TOKEN, \(task_info_t\)&value->token, &count\)/u,
  );
  assert.match(helper, /int error = audit_signal\(&value\.token, SIGKILL\);/u);
  assert.match(helper, /remember\("audit-signal", "errno", error\)/u);
  assert.match(
    helper,
    /WTERMSIG\(prerequisite_status\) == SIGALRM\)\s+remember_cleanup\("prerequisite-backstop"/u,
  );
  assert.match(
    helper,
    /prerequisite_signalled && WIFSIGNALED\(prerequisite_status\) && WTERMSIG\(prerequisite_status\) == SIGKILL/u,
  );
  assert.match(
    helper,
    /prerequisite_signalled = true;\s+settle_prerequisite\(\);/u,
  );
  assert.match(helper, /invariant\(!ferror\(stdout\), "helper-output"\)/u);
  assert.doesNotMatch(helper.replace(/\/\*[\s\S]*?\*\//gu, ""), /\bkill\s*\(/u);
});

test("Darwin custody distinguishes inspected ACL absence and releases held inspection resources on refusal", async () => {
  const [shared, reader, builder, effective] = await Promise.all(
    [
      "custody.h",
      "custody-reader.c",
      "build-helper.c",
      "effective-reader.h",
    ].map((name) => readFile(new URL(name, SOURCE), "utf8")),
  );
  const body =
    /static void custody_acl\(int fd, char hash\[65\]\) \{([\s\S]*?)\n\}/u.exec(
      shared,
    )?.[1];
  const same = /static int file_stat_same\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    shared,
  )?.[1];
  assert.ok(body && same);
  // Translate declarations, pointer outputs and the cleanup label only. All
  // inspection, absence, validation, serialization and refusal branches are C source.
  const script = new Script(`
    function file_stat_same(a, b) {${same.replaceAll("->", ".")}}
    (fd, hash) => {${body
      .replace(
        "struct stat before, inspected, after;",
        "const before = {}, inspected = {}, after = {};",
      )
      .replace(
        "filesec_t security = NULL; acl_t acl = NULL; char *bytes = NULL; ssize_t length = 0;",
        "let security = NULL, acl = NULL, bytes = NULL, length = 0;",
      )
      .replace(
        'const char *operation = NULL, *domain = "errno";',
        'let operation = NULL, domain = "errno";',
      )
      .replace(/\bint result, /u, "let result, ")
      .replace("unsigned char sum[32];", "const sum = Buffer.alloc(32);")
      .replace(
        "errno = 0; result = fstat(fd, &before);",
        "inspect: { errno = 0; result = fstat(fd, &before);",
      )
      .replace(
        "result = filesec_query_property(security, FILESEC_ACL, &present);",
        "[result, present] = filesec_query_property(security, FILESEC_ACL);",
      )
      .replace(
        "result = filesec_get_property(security, FILESEC_ACL, &acl);",
        "[result, acl] = filesec_get_property(security, FILESEC_ACL);",
      )
      .replace("acl_entry_t entry;", "")
      .replace(
        "acl_get_entry(acl, ACL_FIRST_ENTRY, &entry)",
        "acl_get_entry(acl, ACL_FIRST_ENTRY)",
      )
      .replace(
        "bytes = acl_to_text(acl, &length);",
        "[bytes, length] = acl_to_text(acl);",
      )
      .replaceAll("goto done;", "break inspect;")
      .replace("done:", "}")
      .replace(/&(before|inspected|after)\b/gu, "$1")
      .replace("(CC_LONG)length", "length")
      .replace("sizeof(sum)", "32")}}
  `);
  for (const hashing of [false, true]) {
    for (const [fault, operation, error = 0] of [
      ["absent", null],
      ["empty", null],
      ["entry", "acl-empty"],
      ["entry-result", "acl-empty"],
      ["entry-error", "acl-empty", 5],
      ["stat-before", "file-stat", 9],
      ["init", "filesec-init", 12],
      ["inspect", "filesec-stat", 5],
      ["inspect-change", "file-stable"],
      ["query", "acl-query", 5],
      ["null-enoent", "acl-read", 2],
      ["null-success", "acl-read"],
      ["partial-read", "acl-read", 2],
      ["invalid", "acl-valid", 22],
      ["stat-after", "file-stat-again", 9],
      ["after-change", "file-stable"],
      ["acl-release", null, 16],
      ["acl-release-zero", null],
      ["read-and-release", "acl-read", 2],
      ...(hashing
        ? [
            ["text", "acl-text", 5],
            ["text-size", "acl-text-size"],
            ["text-negative", "acl-text-size"],
            ["hash", "acl-hash"],
            ["text-release", null, 16],
            ["text-release-zero", null],
            ["both-release", null, 16],
          ]
        : []),
    ]) {
      const calls = [],
        diagnostics = [],
        acquired = [],
        released = [];
      const security = {},
        acl = {},
        text = Buffer.from("!#acl 1\n");
      const metadata = {
        st_dev: 1,
        st_ino: 42,
        st_uid: 0,
        st_gid: 0,
        st_mode: 0o100400,
        st_nlink: 1,
        st_size: 8,
        st_mtimespec: { tv_sec: 100, tv_nsec: 1 },
        st_ctimespec: { tv_sec: 100, tv_nsec: 2 },
      };
      const output = { value: null };
      let stats = 0;
      const native = (name, value = 0) => {
        calls.push(name);
        context.errno = value;
      };
      const context = {
        NULL: null,
        Buffer,
        stderr: {},
        FILESEC_ACL: 1,
        ACL_FIRST_ENTRY: 0,
        EINVAL: 22,
        errno: 99,
        fstat(fd, value) {
          assert.equal(fd, 7);
          stats++;
          native("stat");
          if (
            (fault === "stat-before" && stats === 1) ||
            (fault === "stat-after" && stats === 2)
          ) {
            context.errno = 9;
            return -1;
          }
          Object.assign(value, structuredClone(metadata));
          if (fault === "after-change" && stats === 2) value.st_ino++;
          return 0;
        },
        filesec_init() {
          native("init", fault === "init" ? 12 : 0);
          if (fault === "init") return null;
          acquired.push("security");
          return security;
        },
        fstatx_np(fd, value, held) {
          assert.equal(fd, 7);
          assert.equal(held, security);
          native("inspect");
          if (fault === "inspect") {
            context.errno = 5;
            return -1;
          }
          Object.assign(value, structuredClone(metadata));
          if (fault === "inspect-change") value.st_gid++;
          return 0;
        },
        filesec_query_property(held, property) {
          assert.equal(held, security);
          assert.equal(property, context.FILESEC_ACL);
          native("query", fault === "query" ? 5 : 0);
          // A failed query reporting zero must still refuse absence.
          return fault === "query" ? [-1, 0] : [0, fault === "absent" ? 0 : 32];
        },
        filesec_get_property(held, property) {
          assert.equal(held, security);
          assert.equal(property, context.FILESEC_ACL);
          native("read");
          if (fault === "null-enoent") {
            context.errno = 2;
            return [-1, null];
          }
          if (fault === "null-success") return [0, null];
          acquired.push("acl");
          if (fault === "partial-read" || fault === "read-and-release") {
            context.errno = 2;
            return [-1, acl];
          }
          return [0, acl];
        },
        acl_valid(value) {
          assert.equal(value, acl);
          native("valid", fault === "invalid" ? 22 : 0);
          return fault === "invalid" ? -1 : 0;
        },
        acl_get_entry(value, selector) {
          assert.equal(value, acl);
          assert.equal(selector, context.ACL_FIRST_ENTRY);
          native(
            "entry",
            fault === "entry-error"
              ? 5
              : ["entry", "entry-result"].includes(fault)
                ? 0
                : 22,
          );
          return fault === "entry" ? 0 : fault === "entry-result" ? 1 : -1;
        },
        acl_to_text(value) {
          assert.equal(value, acl);
          native("text", fault === "text" ? 5 : 0);
          if (fault === "text") return [null, 0];
          acquired.push("text");
          return [
            text,
            fault === "text-size"
              ? 65537
              : fault === "text-negative"
                ? -1
                : text.length,
          ];
        },
        CC_SHA256(bytes, length, sum) {
          native("hash");
          assert.equal(length, Buffer.byteLength(bytes));
          if (fault === "hash") return null;
          createHash("sha256").update(bytes).digest().copy(sum);
          return sum;
        },
        acl_free(value) {
          const kind = value === acl ? "acl" : "text";
          assert.equal(value, kind === "acl" ? acl : text);
          released.push(kind);
          const failed =
            fault === `${kind}-release` ||
            fault === `${kind}-release-zero` ||
            fault === "both-release" ||
            (kind === "acl" && fault === "read-and-release");
          native(`free-${kind}`, failed && !fault.endsWith("zero") ? 16 : 0);
          return failed ? -1 : 0;
        },
        filesec_free(value) {
          assert.equal(value, security);
          released.push("security");
          native("free-security", 99);
        },
        fprintf(stream, format, ...values) {
          assert.equal(stream, context.stderr);
          diagnostics.push({ format, values });
          context.errno = 123;
        },
        fflush() {
          context.errno = 77;
        },
        need(ok) {
          if (!ok)
            throw Object.assign(new Error("guard"), { value: context.errno });
        },
        hex(sum, length, target) {
          calls.push("publish");
          assert.equal(length, 32);
          target.value = sum.toString("hex");
        },
      };
      const inspect = script.runInNewContext(context);
      const failed = operation || fault.includes("release");
      if (failed) {
        assert.throws(
          () => inspect(7, hashing ? output : null),
          (cause) => {
            assert.equal(cause.message, "guard");
            assert.equal(cause.value, error);
            return true;
          },
          `${hashing}/${fault}`,
        );
        assert.equal(output.value, null);
      } else {
        inspect(7, hashing ? output : null);
        assert.equal(
          output.value,
          hashing ? digest(fault === "absent" ? "" : text) : null,
        );
      }
      assert.deepEqual(
        released,
        acquired.toReversed(),
        `${hashing}/${fault} resources`,
      );
      const primary = diagnostics.filter(({ format }) =>
        format.startsWith("native-darwin-acl:"),
      );
      assert.deepEqual(
        primary.map(({ values }) => [values[0], values[2]]),
        operation ? [[operation, error]] : [],
      );
      const cleanup = diagnostics.filter(({ format }) =>
        format.startsWith("native-darwin-acl-cleanup:"),
      );
      assert.deepEqual(
        cleanup.map(({ values }) => values[0]),
        fault === "both-release"
          ? [16, 16]
          : fault.includes("release")
            ? [fault.endsWith("zero") ? 0 : 16]
            : [],
      );
      if (fault === "absent") {
        assert.equal(calls.includes("read"), false);
        assert.equal(calls.includes("valid"), false);
        assert.equal(calls.includes("entry"), false);
        assert.equal(calls.includes("text"), false);
        assert.equal(stats, 2);
      }
      if (fault === "inspect-change")
        assert.equal(calls.includes("query"), false);
      if (fault === "query") assert.equal(calls.includes("read"), false);
    }
  }
  assert.match(
    shared,
    /static void no_acl\(int fd\) \{ custody_acl\(fd, NULL\); \}/u,
  );
  assert.match(
    shared.slice(
      shared.indexOf("static int installed_input("),
      shared.indexOf("static unsigned char *read_file("),
    ),
    /no_acl\(fd\)/u,
  );
  for (const owner of [reader, builder, effective])
    assert.doesNotMatch(owner, /acl_get_fd_np\(|static void no_acl\(/u);
  assert.match(
    effective,
    /stable\(entry\); char hash\[65\]; custody_acl\(entry->fd, hash\)/u,
  );
});

test("experiment PF writes preserve foreign policy and journal each conditional effect", async () => {
  const source = await readFile(new URL("custody-reader.c", SOURCE), "utf8"),
    header = await readFile(new URL("effective-reader.h", SOURCE), "utf8"),
    abi = await readFile(new URL("pf-abi.h", SOURCE), "utf8"),
    write = source.slice(
      source.indexOf("static void pf_lifecycle_write(bool installing) {"),
      source.indexOf("static void pf_restored_guard(void) {"),
    );
  assert.ok(write.length > 0);
  assert.doesNotMatch(write, /pf_command|DIOCSTOP\b|"-f"|"-F"/u);
  for (const [phase, operation] of [
    ["PF_ENABLE_POSSIBLE", "DIOCSTARTREF"],
    ["PF_ATTACH_POSSIBLE", "DIOCBEGINADDRS"],
    ["PF_SKIP_POSSIBLE", "DIOCCLRIFFLAG"],
    ["PF_REMOVE_POSSIBLE", "remove.action = PF_CHANGE_REMOVE"],
    ["PF_RELEASE_POSSIBLE", "DIOCSTOPREF"],
  ])
    assert.ok(
      write.indexOf(`pf_record(${phase})`) < write.indexOf(operation),
      operation,
    );
  assert.match(
    write,
    /add\.action = PF_CHANGE_ADD_HEAD; add\.ticket = root_tickets\[PF_RULESET_FILTER\]/u,
  );
  assert.match(write, /remove\.ticket = root_tickets\[PF_RULESET_FILTER\]/u);
  assert.match(
    header,
    /#ifdef NATIVE_CI_EXPERIMENT\n  pf_lifecycle_write\(installing\);/u,
  );
  assert.match(source, /pf_step\.writer = inspect\(getpid\(\)\)/u);
  assert.match(
    source,
    /root_members\(pf_step\.writer\.token\.val\[6\], false\) == 0/u,
  );
  assert.match(
    abi,
    /#define DIOCCHANGERULE _IOWR\('D', 26, struct pfioc_rule\)/u,
  );
  assert.match(abi, /PF_ABI_LAYOUT\(struct pfioc_pooladdr, 1136, 8\)/u);
  assert.match(source, /pf_step\.reference = pf_owned_reference/u);
  assert.match(source, /!memcmp\(tokens, confirmed, size\)/u);
  const tokenPredicate = source.match(
    /else need\((!memcmp\(&tokens\[i\], &pf_owned_reference, sizeof\(tokens\[i\]\)\))\)/u,
  )?.[1];
  assert.ok(tokenPredicate);
  const tokenCheck = new Script(
    tokenPredicate
      .replace("&tokens[i]", "actual")
      .replace("&pf_owned_reference", "expected")
      .replace("sizeof(tokens[i])", "84"),
  );
  const expected = Buffer.alloc(84);
  expected.writeBigUInt64LE(17n, 0);
  expected.writeBigUInt64LE(1000n, 8);
  expected.writeUInt32LE(42, 16);
  expected.write("synthetic-reader", 20);
  const tokenMatches = (actual) =>
    tokenCheck.runInNewContext({
      actual,
      expected,
      memcmp: (a, b, n) => Buffer.compare(a.subarray(0, n), b.subarray(0, n)),
    });
  assert.equal(tokenMatches(Buffer.from(expected)), true);
  for (const offset of [0, 8, 16, 20]) {
    const actual = Buffer.from(expected);
    actual[offset]++;
    assert.equal(tokenMatches(actual), false);
  }
  // Execute the exact native phase predicate as a portable expression. A
  // missing attachment after READY cannot masquerade as partial installation.
  const predicate = write.match(
    /need\((\(pf_step\.phase[\s\S]+?)\);\n    if/u,
  )?.[1];
  assert.ok(predicate);
  const phases = Object.fromEntries(
    [
      "SEED",
      "ENABLE_POSSIBLE",
      "ENABLED",
      "ATTACH_POSSIBLE",
      "ATTACHED",
      "SKIP_POSSIBLE",
      "READY",
      "REMOVE_POSSIBLE",
      "REMOVED",
      "FLAGS_POSSIBLE",
      "FLAGS_RESTORED",
      "RELEASE_POSSIBLE",
      "DONE",
    ].map((name, i) => ["PF_" + name, i]),
  );
  const accepts = (phase, attached, active = true, token = 17) =>
    new Script(predicate).runInNewContext({
      ...phases,
      pf_step: { phase: phases["PF_" + phase] },
      attached,
      pf_active: active,
      pf_enable_token: token,
    });
  assert.equal(accepts("SEED", false, false, 0), true);
  assert.equal(accepts("ENABLED", false), true);
  assert.equal(accepts("ATTACH_POSSIBLE", false), true);
  assert.equal(accepts("READY", false), false);
  assert.equal(accepts("READY", true), true);
  assert.equal(accepts("REMOVED", true), false);
});

test("Darwin audit custody binds all-UID census, native controls and recoverable reference lifetimes", async () => {
  const [shared, launcher, reader] = await Promise.all(
    ["custody.h", "launcher.c", "custody-reader.c"].map((name) =>
      readFile(new URL(name, SOURCE), "utf8"),
    ),
  );
  assert.match(shared, /proc_listpids\(PROC_ALL_PIDS, 0/u);
  assert.doesNotMatch(launcher, /proc_listpids\(PROC_UID_ONLY/u);
  for (const call of [
    "setuid(0)",
    "setgid(0)",
    "setgroups(1, &root)",
    "setaudit_addr(&change",
    "audit_session_port(parent_asid",
    "task_for_pid(mach_task_self(), parent",
  ])
    assert.ok(launcher.includes(call), call);
  for (const [before, after] of [
    ["domain_controls(parent_asid, getppid())", "write(3, &identity"],
    ["audit_hold(parked.token.val[6])", 'puts(",\\\"controls\\\":true}")'],
  ]) {
    const at = launcher.indexOf(before);
    assert.ok(at >= 0 && at < launcher.indexOf(after), before);
  }
  const operation = reader.slice(
    reader.indexOf(
      "static void case_session(char **fields, bool recovering) {",
    ),
    reader.indexOf("static void case_session_closed(void) {"),
  );
  assert.ok(
    operation.indexOf("case_audit_store(fd)") <
      operation.indexOf("audit_hold(asid)"),
  );
  assert.ok(
    operation.indexOf("case_audit_store(fd)") <
      operation.indexOf("posix_spawn(&child"),
  );
  assert.match(
    launcher,
    /mach_port_t pin = audit_hold\(subject.token.val\[6\]\)/u,
  );
  assert.match(
    operation,
    /case_audit\.custodian =|read\(ready\[0\], &case_audit\.custodian/u,
  );
  const recovery = operation.slice(
    operation.indexOf("int fd = case_audit_open(false)"),
  );
  assert.doesNotMatch(recovery, /fork\(|O_CREAT/u);
  assert.match(recovery, /audit_identity_same\(holder, expected\)/u);
  assert.match(
    reader,
    /case_audit\.version && \(reservation_fd < 0 \|\| operation_domain_finished\(\)\)/u,
  );
  assert.match(reader, /case_fenced = true/u);
  assert.match(reader, /need\(!case_fenced\)/u);
  const gitFinish = reader.slice(
    reader.indexOf("static void git_ordinary_finish(void)"),
    reader.indexOf("static void git_object("),
  );
  assert.match(gitFinish, /audit_identity_same\(owner, case_audit.source\)/u);
  assert.doesNotMatch(gitFinish, /&git_identity.token/u);
});

test("Darwin feasibility fault custody keeps privileged effects behind sealed receipts and original identities", async () => {
  const [domain, helper, shared] = await Promise.all(
    ["feasibility-domain.h", "feasibility-helper.c", "custody.h"].map((name) =>
      readFile(new URL(name, SOURCE), "utf8"),
    ),
  );
  assert.match(shared, /#ifndef NATIVE_AUDIT_DOMAIN_ONLY/u);
  assert.match(
    domain,
    /#define AUDIT_DOMAIN_INSPECT\(pid\) fault_inspect\(pid\)/u,
  );
  assert.match(
    domain,
    /audit_census\(domain_record.uid, domain_record.asid\)/u,
  );
  assert.match(domain, /flock\(lease,LOCK_EX\|LOCK_NB\)/u);
  assert.doesNotMatch(domain, /\bkill\s*\(|system\s*\(|popen\s*\(/u);
  assert.ok(
    domain.indexOf("domain_store(0)") <
      domain.indexOf('domain_copy(source, "helper"'),
  );
  const creation = domain.slice(domain.indexOf("static void domain_start("));
  assert.ok(
    creation.indexOf("admitted_effects = true") <
      creation.indexOf("mkdir(domain_path"),
  );
  assert.ok(
    creation.indexOf("domain_store(1)") <
      creation.indexOf("domain_pin = audit_hold(domain_record.asid)"),
  );
  const fault = domain.slice(
    domain.indexOf('!strcmp(fields[1], "fault")'),
    domain.indexOf('!strcmp(fields[1], "retire")'),
  );
  assert.ok(
    fault.indexOf("domain_store(3)") <
      fault.indexOf("signal_identity(domain_record.owner"),
  );
  assert.match(domain, /same_file_stat\(&inherited, &held\)/u);
  assert.match(
    domain,
    /audit_identity_same\(holder, domain_record.custodian\)/u,
  );
  assert.match(domain, /domain_recheck\(\); need\(!view.nl && !view.nd\)/u);
  assert.match(domain, /domain_store\(6\).*mach_port_deallocate/u);
  const verifier = domain.slice(
    domain.indexOf("static void domain_verify("),
    domain.indexOf("static void domain_start("),
  );
  assert.match(
    verifier,
    /audit_fresh\(0\);[^\n]*\n\s*struct identity verifier = fault_inspect\(getpid\(\)\)/u,
  );
  for (const control of [
    "setuid(0)",
    "setgid(0)",
    "setgroups(1, &root)",
    "setaudit_addr(&after",
    "audit_session_port(number(parent)",
    "task_for_pid(mach_task_self(), getppid()",
  ])
    assert.ok(domain.includes(control), control);
  const fixture = helper.slice(
    helper.indexOf("static void fault(void)"),
    helper.indexOf(
      "#ifdef NATIVE_FEASIBILITY_COMMAND",
      helper.indexOf("static void fault(void)"),
    ),
  );
  assert.match(fixture, /if \(domain\) domain_controls\(\)/u);
  assert.match(fixture, /setsid\(\).*fault-detach.*alarm\(25\)/u);
  assert.match(fixture, /command == 'C' \|\| command == 'L'/u);
});

test("Darwin custodian lifecycle observations balance their own public getter references", async () => {
  const source = await readFile(
      new URL("feasibility-domain.h", SOURCE),
      "utf8",
    ),
    body =
      /static void domain_access_observe\(const char \*phase\) \{([\s\S]*?)\n\}/u.exec(
        source,
      )?.[1];
  assert.ok(body);
  const script = new Script(
    `(phase) => {${body
      .replace(
        /\b(?:int|task_t|mach_port_t|kern_return_t|mach_port_type_t) /gu,
        "let ",
      )
      .replace(
        /&(access|type)\b/gu,
        (_, name) => `{set value(v) {${name} = v;}}`,
      )}}`,
  );
  for (const options of [
    {},
    { access: 0xffffffff },
    { access: 200 },
    { get: 5 },
    { access: 200, query: 15 },
    { access: 200, release: 15 },
  ]) {
    const calls = [],
      observations = [],
      cleanup = [];
    const context = {
      errno: 9,
      KERN_SUCCESS: 0,
      MACH_PORT_NULL: 0,
      MACH_PORT_DEAD: 0xffffffff,
      MACH_PORT_TYPE_NONE: 0,
      MACH_PORT_TYPE_DEAD_NAME: 0x100000,
      TASK_ACCESS_PORT: 2,
      MACH_PORT_VALID: (name) => name !== 0 && name !== 0xffffffff,
      mach_task_self: () => 101,
      task_get_special_port(self, which, output) {
        assert.deepEqual([self, which], [101, 2]);
        calls.push("get");
        if (!options.get) output.value = options.access ?? 0;
        return options.get ?? 0;
      },
      mach_port_type(self, name, output) {
        assert.deepEqual([self, name], [101, 200]);
        calls.push("query");
        if (!options.query) output.value = 0x10000;
        return options.query ?? 0;
      },
      mach_port_deallocate(self, name) {
        assert.deepEqual([self, name], [101, 200]);
        calls.push("release");
        return options.release ?? 0;
      },
      domain_access_diagnostic(...facts) {
        observations.push(facts);
        context.errno = 22;
      },
      remember_cleanup: (...facts) => cleanup.push(facts),
      domain_mach(value, operation) {
        throw Object.assign(new Error(operation), { value });
      },
    };
    const observe = script.runInNewContext(context);
    for (const phase of ["custodian-entry", "custodian-fork"]) {
      if (options.release) assert.throws(() => observe(phase), { value: 15 });
      else observe(phase);
      assert.equal(context.errno, 9);
    }
    const valid = options.access === 200 && !options.get;
    assert.deepEqual(
      calls,
      Array(2)
        .fill(valid ? ["get", "query", "release"] : ["get"])
        .flat(),
    );
    assert.deepEqual(
      observations,
      ["custodian-entry", "custodian-fork"].map((phase) => [
        phase,
        options.get ?? 0,
        options.access ?? 0,
        options.access === 0xffffffff
          ? 0x100000
          : valid && !options.query
            ? 0x10000
            : 0,
        valid ? (options.query ?? 0) : -1,
        valid ? (options.release ?? 0) : -1,
      ]),
    );
    assert.deepEqual(
      cleanup,
      options.release
        ? Array(2).fill(["fault-access-release", "mach", 15])
        : [],
    );
  }
  const entry = source.indexOf('domain_access_observe("custodian-entry")'),
    reexec = source.indexOf("execv(domain_helper, argv)"),
    beforeFork = source.indexOf('domain_access_observe("custodian-fork")');
  assert.ok(
    entry > 0 &&
      entry < reexec &&
      reexec < beforeFork &&
      beforeFork < source.indexOf("pid_t child = fork()"),
  );
});

test("Darwin fault sanitation admits only absent or dead access rights before the original payload exec", async () => {
  const source = await readFile(
      new URL("feasibility-domain.h", SOURCE),
      "utf8",
    ),
    sanitation = /static void domain_sanitize\(void\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1],
    start = source.indexOf(
      "  if (!child) {",
      source.indexOf("static void domain_start("),
    ),
    end = source.indexOf("\n  }\n  domain_child = child;", start);
  assert.ok(sanitation && start > 0 && end > start);
  // Project only C declarations, output pointers and sizeof into JS. The
  // sanitation decisions and the original child launch body execute unchanged.
  const translate = (body) =>
    body
      .replace("extern mach_port_t bootstrap_port;", "")
      .replace(
        "struct rlimit limit = {.rlim_cur = 32, .rlim_max = 32};",
        "const limit = {rlim_cur:32, rlim_max:32};",
      )
      .replace("struct identity birth", "const birth")
      .replace("struct proc_fdinfo fds[512];", "const fds = [];")
      .replace("char gate;", "let gate;")
      .replace("char parent[24];", "const parent = {};")
      .replaceAll("&birth", "birth")
      .replaceAll("&limit", "limit")
      .replaceAll("in[", "input[")
      .replace(
        /&(host|access|type|address|access_type|names|types|n|nt|gate)\b/gu,
        (_, name) => `{set value(v) {${name} = v;}}`,
      )
      .replaceAll("sizeof(*names)", "1")
      .replaceAll("sizeof(*types)", "1")
      .replaceAll("sizeof(fds[0])", "1")
      .replaceAll("sizeof(fds)", "512")
      .replaceAll("sizeof(birth)", "1")
      .replaceAll("sizeof(parent)", "24")
      .replace(/\(mach_vm_address_t\)|\(unsigned\)/gu, "")
      .replace(
        /\b(?:task_t|thread_t|mach_port_t|natural_t|mach_vm_address_t|mach_port_type_t|kern_return_t|bool|mach_port_name_array_t|mach_port_type_array_t|mach_msg_type_number_t|unsigned|int) /gu,
        "let ",
      );
  const script = new Script(`
    function domain_sanitize() {${translate(sanitation)}}
    () => {${translate(source.slice(start + "  if (!child) {".length, end))}}
  `);
  const SEND = 0x10000,
    RECEIVE = 0x20000,
    SEND_ONCE = 0x40000,
    PORT_SET = 0x80000,
    DEAD_NAME = 0x100000,
    DEAD = 0xffffffff;
  for (const [label, options, operation, value, cleanupValue] of [
    ["null", {}],
    ["dead sentinel", { access: DEAD }],
    ["allocated dead name", { access: 200, rights: DEAD_NAME }],
    ["live send", { access: 200, rights: SEND }, "fault-access-authority", 0],
    [
      "live send/receive",
      { access: 200, rights: SEND | RECEIVE },
      "fault-access-authority",
      0,
    ],
    [
      "live send-once",
      { access: 200, rights: SEND_ONCE },
      "fault-access-authority",
      0,
    ],
    [
      "receive",
      { access: 200, rights: RECEIVE, noRelease: true },
      "fault-access-authority",
      0,
    ],
    [
      "port set",
      { access: 200, rights: PORT_SET, noRelease: true },
      "fault-access-authority",
      0,
    ],
    [
      "empty type",
      { access: 200, rights: 0, noRelease: true },
      "fault-access-authority",
      0,
    ],
    [
      "mixed dead/live",
      { access: 200, rights: DEAD_NAME | SEND },
      "fault-access-authority",
      0,
    ],
    [
      "unknown type",
      { access: 200, rights: 0x1000000, noRelease: true },
      "fault-access-authority",
      0,
    ],
    ["getter refused", { get: 5 }, "fault-access-port", 5],
    ["invalid name query", { access: 200, query: 15 }, "fault-access-kind", 15],
    ["query refused", { access: 200, query: 5 }, "fault-access-kind", 5],
    [
      "dead-name release refused",
      { access: 200, rights: DEAD_NAME, release: 15 },
      "fault-access-release",
      15,
      15,
    ],
    [
      "live release refused",
      { access: 200, rights: SEND, release: 15 },
      "fault-access-authority",
      0,
      15,
    ],
    ["privileged host", { host: 4 }, "fault-host-kind", 0],
    ["foreign right retained", { destroy: 5 }, "fault-port-destroy", 5],
    ["port census refused", { census: 5 }, "fault-port-list", 5],
    ["gate refused", { gate: "N" }, "fault-gate-value", 0],
  ]) {
    const calls = [],
      diagnostics = [],
      lifecycle = [],
      cleanup = [],
      executed = {},
      originalBirth = { pid: 42 },
      domain = { uid: 90001, gid: 90002 };
    let first,
      replies = 0;
    const context = {
      errno: 0,
      stderr: {},
      NULL: null,
      KERN_SUCCESS: 0,
      MACH_PORT_NULL: 0,
      MACH_PORT_DEAD: DEAD,
      MACH_PORT_TYPE_NONE: 0,
      MACH_PORT_TYPE_SEND: SEND,
      MACH_PORT_TYPE_SEND_ONCE: SEND_ONCE,
      MACH_PORT_TYPE_DEAD_NAME: DEAD_NAME,
      MACH_PORT_VALID: (name) => name !== 0 && name !== DEAD,
      TASK_HOST_PORT: 1,
      TASK_ACCESS_PORT: 2,
      TASK_BOOTSTRAP_PORT: 3,
      TASK_DEBUG_CONTROL_PORT: 4,
      TASK_RESOURCE_NOTIFY_PORT: 5,
      EXC_MASK_ALL: 0xffff,
      EXCEPTION_DEFAULT: 1,
      THREAD_STATE_NONE: 0,
      bootstrap_port: 110,
      RLIMIT_NPROC: 1,
      PROC_PIDLISTFDS: 1,
      ready: [16, 17],
      release: [18, 19],
      input: [10, 11],
      out: [12, 13],
      err: [14, 15],
      domain_record: domain,
      parent_asid: 3,
      domain_helper: "/fixture/helper",
      domain_policy: "/fixture/policy",
      remember(op, kind, number) {
        first ??= { operation: op, kind, value: number };
      },
      remember_cleanup(op, kind, number) {
        cleanup.push({ operation: op, kind, value: number });
      },
      failure(code) {
        throw Object.assign(new Error(first.operation), first, { code });
      },
      invariant(ok, op) {
        if (!ok) {
          context.remember(op, "invariant", 0);
          context.failure(126);
        }
      },
      domain_mach(result, op) {
        if (result !== 0) {
          context.remember(op, "mach", result);
          context.failure(126);
        }
      },
      posix_check(result, op) {
        assert.ok(result >= 0, op);
      },
      domain_check(ok, op) {
        context.invariant(ok, op);
      },
      domain_io(result, expected, op) {
        assert.equal(result, expected, op);
      },
      alarm: (seconds) => calls.push(["alarm", seconds]),
      close: (fd) => {
        calls.push(["close", fd]);
        return 0;
      },
      audit_fresh: (uid) => calls.push(["audit", uid]),
      setrlimit: (_resource, limit) => {
        assert.equal(limit.rlim_max, 32);
        return 0;
      },
      setgroups: () => 0,
      setgid: () => 0,
      setuid: () => 0,
      getpid: () => 42,
      fault_inspect: () => originalBirth,
      write(fd, birth) {
        assert.equal(fd, 17);
        assert.equal(birth, originalBirth);
        return 1;
      },
      read(fd, target) {
        assert.equal(fd, 18);
        target.value = options.gate ?? "P";
        return 1;
      },
      dup2: () => 0,
      proc_pidinfo(_pid, _operation, _unused, fds) {
        fds.push(...[0, 1, 2, 3, 4].map((proc_fd) => ({ proc_fd })));
        return fds.length;
      },
      snprintf(target, _size, _format, asid) {
        target.text = String(asid);
      },
      setenv(name, parent) {
        calls.push(["environment", name, parent.text]);
        return 0;
      },
      unsetenv: () => 0,
      execl(...args) {
        calls.push(["exec", ...args]);
        throw executed;
      },
      mach_task_self: () => 101,
      mach_thread_self: () => 102,
      task_get_special_port(self, which, target) {
        assert.equal(self, 101);
        calls.push(["get", which]);
        target.value = which === 1 ? 103 : (options.access ?? 0);
        return which === 2 ? (options.get ?? 0) : 0;
      },
      mach_port_kobject(_self, _host, type, address) {
        type.value = options.host ?? 3;
        address.value = 0;
        return 0;
      },
      mach_port_type(self, name, target) {
        assert.equal(self, 101);
        assert.equal(name, 200);
        calls.push(["type", name]);
        if (!options.query) target.value = options.rights ?? DEAD_NAME;
        return options.query ?? 0;
      },
      mach_port_deallocate(_self, name) {
        if (name === 200)
          assert.ok(
            !options.noRelease,
            "No getter reference was proved for deallocation",
          );
        calls.push(["release", name]);
        return name === 200 ? (options.release ?? 0) : 0;
      },
      task_set_special_port(_self, which, port) {
        calls.push(["clear", which, port]);
        return 0;
      },
      mach_ports_register(_self, ports, count) {
        calls.push(["registered", ports, count]);
        return 0;
      },
      task_set_exception_ports: (...args) => {
        calls.push(["task-exceptions", ...args]);
        return 0;
      },
      thread_set_exception_ports: (...args) => {
        calls.push(["thread-exceptions", ...args]);
        return 0;
      },
      mig_get_reply_port: () => (++replies === 1 ? 77 : 104),
      mig_dealloc_reply_port: (name) => calls.push(["reply", name]),
      mach_port_names(_self, names, count, types, typeCount) {
        names.value = [101, 102, 104, 111];
        count.value = 4;
        types.value = [SEND, SEND, RECEIVE, SEND];
        typeCount.value = 4;
        return options.census ?? 0;
      },
      mach_port_destroy(_self, name) {
        calls.push(["destroy", name]);
        return options.destroy ?? 0;
      },
      mach_vm_deallocate: () => 0,
      fprintf(_stream, _format, ...values) {
        diagnostics.push(values);
      },
      domain_access_diagnostic: (...facts) => lifecycle.push(facts),
      fflush() {},
    };
    const launch = script.runInNewContext(context);
    assert.throws(launch, (error) => {
      if (!operation) return error === executed;
      assert.equal(error.operation, operation, label);
      assert.equal(error.value, value, label);
      assert.equal(
        error.kind,
        operation.endsWith("authority") ||
          (operation.endsWith("kind") && value === 0) ||
          operation === "fault-gate-value"
          ? "invariant"
          : "mach",
        label,
      );
      return true;
    });
    assert.equal(
      calls.some(([op]) => op === "exec"),
      !operation,
      label,
    );
    assert.deepEqual(
      cleanup,
      cleanupValue === undefined
        ? []
        : [
            {
              operation: "fault-access-release",
              kind: "mach",
              value: cleanupValue,
            },
          ],
      label,
    );
    const queried = calls.some(([op]) => op === "type"),
      released = calls.some(([op, name]) => op === "release" && name === 200);
    const got =
      calls.some(([op, which]) => op === "get" && which === 2) && !options.get;
    assert.deepEqual(
      lifecycle,
      got
        ? [
            [
              "payload",
              0,
              options.access ?? 0,
              options.access === DEAD
                ? DEAD_NAME
                : options.query
                  ? 0
                  : (options.rights ??
                    (options.access === 200 ? DEAD_NAME : 0)),
              queried ? (options.query ?? 0) : -1,
              released ? (options.release ?? 0) : -1,
            ],
          ]
        : [],
      label,
    );
    assert.equal(queried, options.access === 200 && !options.get, label);
    assert.equal(
      released,
      queried && !options.query && !options.noRelease,
      label,
    );
    assert.equal(
      calls.filter(([op, name]) => op === "release" && name === 200).length,
      released ? 1 : 0,
      label,
    );
    assert.ok(
      !calls.some(
        ([op, name]) => op === "release" && (name === 0 || name === DEAD),
      ),
      label,
    );
    assert.ok(
      !calls.some(([op, which]) => op === "clear" && which === 2),
      label,
    );
    if (!operation) {
      assert.equal(context.bootstrap_port, 0);
      assert.deepEqual(
        calls.filter(([op]) => op === "clear"),
        [
          ["clear", 3, 0],
          ["clear", 4, 0],
          ["clear", 5, 0],
        ],
      );
      assert.deepEqual(
        calls.filter(([op]) => op === "destroy"),
        [["destroy", 111]],
      );
      assert.deepEqual(
        calls.filter(([op]) => op === "registered"),
        [["registered", null, 0]],
      );
      assert.deepEqual(
        calls.filter(([op]) => op === "task-exceptions"),
        [["task-exceptions", 101, 0xffff, 0, 1, 0]],
      );
      assert.deepEqual(
        calls.filter(([op]) => op === "thread-exceptions"),
        [["thread-exceptions", 102, 0xffff, 0, 1, 0]],
      );
      assert.deepEqual(
        calls.filter(([op]) => op === "release"),
        [
          ["release", 103],
          ...(released ? [["release", 200]] : []),
          ["release", 102],
        ],
      );
      assert.deepEqual(calls.at(-1), [
        "exec",
        "/fixture/helper",
        "/fixture/helper",
        "exec",
        "/fixture/policy",
        "/fixture/helper",
        "fault",
        null,
      ]);
      assert.ok(calls.some(([op, fd]) => op === "close" && fd === 3));
      assert.ok(calls.some(([op, fd]) => op === "close" && fd === 4));
    }
    if (options.access && !options.get)
      assert.deepEqual(
        diagnostics,
        [
          [
            options.access,
            options.access === DEAD
              ? DEAD_NAME
              : options.query
                ? 0
                : (options.rights ?? DEAD_NAME),
            options.query ?? 0,
          ],
        ],
        label,
      );
    else assert.deepEqual(diagnostics, [], label);
  }
});

test("Darwin fault creation initializes only held new objects and refuses failed setters or changed identities", async () => {
  const [source, helper] = await Promise.all(
    ["feasibility-domain.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(name, SOURCE), "utf8"),
    ),
  );
  const initialize =
    /static void domain_initialize\(int fd, bool directory\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  const shape = /static void domain_shape\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    source,
  )?.[1];
  const same = /static bool same_file_stat\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    helper,
  )?.[1];
  assert.ok(initialize && shape && same);
  const script = new Script(`
    function same_file_stat(a, b) {${same.replaceAll("->", ".")}}
    function domain_shape(ok, st, operation) {${shape}}
    (fd, directory) => {${initialize
      .replace("struct stat before, after;", "const before = {}, after = {};")
      .replaceAll("const char *", "const ")
      .replace("mode_t mode", "const mode")
      .replace(
        "struct stat expected = before;",
        "const expected = {...before};",
      )
      .replace(/&(before|after|expected)\b/gu, "$1")
      .replace(/\b0([0-7]{3,})\b/gu, "0o$1")}}
  `);
  for (const directory of [true, false]) {
    const prefix = directory ? "fault-root" : "fault-journal";
    for (const [fault, operation, expectedCalls, errorValue] of [
      [null, null, ["stat", "owner", "mode", "stat", "acl"]],
      ["stat-before", `${prefix}-stat`, ["stat"], 9],
      ["kind", `${prefix}-shape`, ["stat"]],
      ...(!directory ? [["links", `${prefix}-shape`, ["stat"]]] : []),
      ["owner", `${prefix}-owner`, ["stat", "owner"], 1],
      ["mode", `${prefix}-mode`, ["stat", "owner", "mode"], 5],
      ["stat-after", `${prefix}-stat`, ["stat", "owner", "mode", "stat"], 9],
      ["identity", `${prefix}-shape`, ["stat", "owner", "mode", "stat"]],
      ["owner-readback", `${prefix}-shape`, ["stat", "owner", "mode", "stat"]],
      ["mode-readback", `${prefix}-shape`, ["stat", "owner", "mode", "stat"]],
      ["acl", "acl-empty", ["stat", "owner", "mode", "stat", "acl"]],
    ]) {
      const calls = [],
        metadata = [];
      const type = directory ? 0o040000 : 0o100000;
      const file = {
        st_dev: 1,
        st_ino: 42,
        st_birthtimespec: { tv_sec: 100, tv_nsec: 9 },
        st_uid: 0,
        st_gid: directory ? 20 : 80,
        st_mode:
          (fault === "kind" ? (directory ? 0o100000 : 0o040000) : type) |
          (directory ? 0o2700 : 0),
        st_nlink: directory || fault === "links" ? 2 : 1,
        st_size: directory ? 64 : 0,
      };
      const initial = structuredClone(file);
      let stats = 0;
      const context = {
        errno: 123,
        S_IFMT: 0o170000,
        S_ISDIR: (mode) => (mode & 0o170000) === 0o040000,
        S_ISREG: (mode) => (mode & 0o170000) === 0o100000,
        fstat(fd, value) {
          assert.equal(fd, 7);
          calls.push("stat");
          stats++;
          if (
            (fault === "stat-before" && stats === 1) ||
            (fault === "stat-after" && stats === 2)
          ) {
            context.errno = 9;
            return -1;
          }
          Object.assign(value, structuredClone(file));
          if (fault === "identity" && stats === 2) value.st_ino++;
          return 0;
        },
        fchown(fd, uid, gid) {
          assert.deepEqual([fd, uid, gid], [7, 0, 0]);
          calls.push("owner");
          if (fault === "owner") {
            context.errno = 1;
            return -1;
          }
          if (fault !== "owner-readback") {
            file.st_uid = uid;
            file.st_gid = gid;
          }
          return 0;
        },
        fchmod(fd, mode) {
          assert.equal(fd, 7);
          assert.equal(mode, directory ? 0o700 : 0o400);
          calls.push("mode");
          if (fault === "mode") {
            context.errno = 5;
            return -1;
          }
          if (fault !== "mode-readback") file.st_mode = type | mode;
          return 0;
        },
        no_acl(fd, inspected) {
          assert.equal(fd, 7);
          calls.push("acl");
          assert.deepEqual(structuredClone(inspected), file);
          if (fault === "acl") throw new Error("acl-empty");
        },
        domain_metadata(object, inspected) {
          metadata.push({ object, stat: structuredClone(inspected) });
          context.errno = 123;
        },
        posix_check(result, name) {
          if (result < 0)
            throw Object.assign(new Error(name), { value: context.errno });
        },
        invariant(ok, name) {
          if (!ok) throw new Error(name);
        },
      };
      const initializeHeld = script.runInNewContext(context);
      if (fault)
        assert.throws(
          () => initializeHeld(7, directory),
          (error) => {
            assert.equal(error.message, operation);
            if (errorValue !== undefined) assert.equal(error.value, errorValue);
            return true;
          },
        );
      else {
        initializeHeld(7, directory);
        assert.equal(file.st_uid, 0);
        assert.equal(file.st_gid, 0);
        assert.equal(file.st_mode, type | (directory ? 0o700 : 0o400));
      }
      assert.deepEqual(calls, expectedCalls, `${prefix}/${fault}`);
      if (fault !== "stat-before") {
        assert.deepEqual(metadata[0].stat, initial);
        assert.equal(
          metadata[0].object,
          directory ? "created-root" : "created-journal",
        );
      }
      if (operation === `${prefix}-shape`) {
        assert.equal(metadata.at(-1).object, operation);
        assert.equal(
          metadata.at(-1).stat.st_ino,
          fault === "identity" ? 43 : 42,
        );
      }
    }
  }
  const fresh = source.indexOf("posix_check(mkdir(domain_path");
  const creation = source.slice(
    fresh,
    source.indexOf("execv(domain_helper", fresh),
  );
  const positions = [
    "domain_initialize(domain_root, true)",
    'openat(domain_root, "receipt"',
    "domain_initialize(domain_journal, false)",
    "domain_store(0)",
    "fchmod(domain_root, 0711)",
    "no_acl(domain_journal, &journal)",
    "dup2(domain_journal, 3)",
  ].map((value) => creation.indexOf(value));
  assert.ok(
    positions.every(
      (value, index) => value >= 0 && (!index || positions[index - 1] < value),
    ),
  );
  const recovery = source.slice(
    source.indexOf("static void domain_open("),
    source.indexOf("static void domain_transfer("),
  );
  assert.doesNotMatch(recovery, /domain_initialize|fchown|fchmod/u);
});

test("Darwin fault start initializes only its exclusive new lease and refuses unsafe reuse or contention", async () => {
  const [source, helper] = await Promise.all(
    ["feasibility-domain.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(name, SOURCE), "utf8"),
    ),
  );
  const start = source.indexOf(
    "  const char *lease_path",
    source.indexOf("static void domain_start("),
  );
  assert.ok(start > 0);
  const body = source.slice(
    start,
    source.indexOf("  domain_controller = getpid();", start),
  );
  const same = /static bool same_file_stat\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    helper,
  )?.[1];
  const bound = /static bool domain_file_same\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    source,
  )?.[1];
  const shape = /static void domain_shape\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
    source,
  )?.[1];
  assert.ok(same && bound && shape);
  const script = new Script(`
    function same_file_stat(a, b) {${same.replaceAll("->", ".")}}
    function domain_file_same(a, b) {${bound.replaceAll("->", ".")}}
    function domain_shape(ok, st, operation) {${shape}}
    () => {${body
      .replace("const char *lease_path", "const lease_path")
      .replace("int lease =", "let lease =")
      .replace("bool lease_created", "const lease_created")
      .replace(
        "struct stat lease_before, lease_stat, lease_named;",
        "const lease_before = {}, lease_stat = {}, lease_named = {};",
      )
      .replace(
        "struct stat lease_expected = lease_before;",
        "const lease_expected = {...lease_before};",
      )
      .replace("struct audit_domain_view absent", "const absent")
      .replace(
        /&(lease_before|lease_stat|lease_named|lease_expected)\b/gu,
        "$1",
      )
      .replace(/\b0([0-7]{3,})\b/gu, "0o$1")}
      return lease;
    }
  `);
  for (const [existing, fault, operation, errorValue] of [
    [false, null],
    [true, null],
    [false, "create", "fault-lease-open", 13],
    [true, "symlink", "fault-lease-open", 40],
    [true, "disappeared", "fault-lease-open", 2],
    [true, "uid", "fault-lease-shape"],
    [true, "gid", "fault-lease-shape"],
    [true, "permissions", "fault-lease-shape"],
    [false, "kind", "fault-lease-shape"],
    [true, "kind", "fault-lease-shape"],
    [false, "links", "fault-lease-shape"],
    [true, "links", "fault-lease-shape"],
    [false, "lock", "fault-lease-lock", 35],
    [true, "lock", "fault-lease-lock", 35],
    [false, "owner", "fault-lease-owner", 1],
    [false, "mode", "fault-lease-mode", 5],
    [true, "stat-before", "fault-lease-stat", 9],
    [false, "stat-after", "fault-lease-stat", 9],
    [false, "owner-readback", "fault-lease-shape"],
    [false, "mode-readback", "fault-lease-shape"],
    [true, "held-identity", "fault-lease-shape"],
    [true, "held-mode", "fault-lease-shape"],
    [true, "acl", "acl-empty"],
    [true, "name-stat", "fault-lease-stat", 2],
    [false, "name-identity", "fault-lease-shape"],
    [true, "name-identity", "fault-lease-shape"],
    [true, "name-time", "fault-lease-shape"],
    [true, "name-symlink", "fault-lease-shape"],
  ]) {
    const calls = [],
      metadata = [];
    const file = {
      st_dev: 1,
      st_ino: 42,
      st_birthtimespec: { tv_sec: 100, tv_nsec: 9 },
      st_mtimespec: { tv_sec: 100, tv_nsec: 10 },
      st_ctimespec: { tv_sec: 100, tv_nsec: 11 },
      st_uid: fault === "uid" ? 501 : 0,
      st_gid: !existing || fault === "gid" ? 20 : 0,
      st_mode:
        (fault === "kind" ? 0o040000 : 0o100000) |
        (!existing ? 0o200 : fault === "permissions" ? 0o640 : 0o600),
      st_nlink: fault === "links" ? 2 : 1,
      st_size: existing ? 32 : 0,
    };
    const initial = structuredClone(file);
    let opens = 0,
      stats = 0,
      locked = false;
    const context = {
      errno: 0,
      O_RDWR: 2,
      O_CREAT: 4,
      O_EXCL: 8,
      O_NOFOLLOW: 16,
      O_CLOEXEC: 32,
      O_NONBLOCK: 64,
      EEXIST: 17,
      LOCK_EX: 2,
      LOCK_NB: 4,
      S_IFMT: 0o170000,
      S_ISREG: (mode) => (mode & 0o170000) === 0o100000,
      domain_record: { uid: 90001 },
      open(path, flags, mode) {
        calls.push("open");
        opens++;
        assert.equal(path, "/private/var/run/native-feasibility-fault.lock");
        const common =
          context.O_RDWR |
          context.O_NOFOLLOW |
          context.O_CLOEXEC |
          context.O_NONBLOCK;
        assert.equal(
          flags,
          opens === 1 ? common | context.O_CREAT | context.O_EXCL : common,
        );
        assert.equal(mode, opens === 1 ? 0o600 : undefined);
        assert.ok(opens <= (existing ? 2 : 1));
        if (fault === "create" || (existing && opens === 1)) {
          context.errno = fault === "create" ? 13 : context.EEXIST;
          return -1;
        }
        if (["symlink", "disappeared"].includes(fault)) {
          context.errno = fault === "symlink" ? 40 : 2;
          return -1;
        }
        return 7;
      },
      fstat(fd, value) {
        assert.equal(fd, 7);
        calls.push("stat");
        stats++;
        if (
          (fault === "stat-before" && stats === 1) ||
          (fault === "stat-after" && stats === 2)
        ) {
          context.errno = 9;
          return -1;
        }
        Object.assign(value, structuredClone(file));
        if (stats === 2 && fault === "held-identity") value.st_ino++;
        if (stats === 2 && fault === "held-mode") value.st_mode ^= 0o100;
        return 0;
      },
      flock(fd, flags) {
        assert.deepEqual([fd, flags], [7, 6]);
        calls.push("lock");
        if (fault === "lock") {
          context.errno = 35;
          return -1;
        }
        locked = true;
        return 0;
      },
      fchown(fd, uid, gid) {
        assert.deepEqual([fd, uid, gid], [7, 0, 0]);
        assert.ok(!existing && locked);
        calls.push("owner");
        if (fault === "owner") {
          context.errno = 1;
          return -1;
        }
        if (fault !== "owner-readback") file.st_gid = gid;
        file.st_uid = uid;
        return 0;
      },
      fchmod(fd, mode) {
        assert.deepEqual([fd, mode], [7, 0o600]);
        assert.ok(!existing && locked);
        calls.push("mode");
        if (fault === "mode") {
          context.errno = 5;
          return -1;
        }
        if (fault !== "mode-readback") file.st_mode = 0o100000 | mode;
        return 0;
      },
      no_acl(fd, inspected) {
        assert.equal(fd, 7);
        assert.ok(locked);
        assert.deepEqual(structuredClone(inspected), file);
        calls.push("acl");
        if (fault === "acl") throw new Error("acl-empty");
      },
      lstat(path, value) {
        assert.equal(path, "/private/var/run/native-feasibility-fault.lock");
        calls.push("name");
        if (fault === "name-stat") {
          context.errno = 2;
          return -1;
        }
        Object.assign(value, structuredClone(file));
        if (fault === "name-identity") value.st_ino++;
        if (fault === "name-time") value.st_ctimespec.tv_nsec++;
        if (fault === "name-symlink") value.st_mode = 0o120600;
        return 0;
      },
      domain_metadata(object, inspected) {
        metadata.push({ object, stat: structuredClone(inspected) });
      },
      audit_census(uid, asid) {
        assert.deepEqual([uid, asid], [90001, 0]);
        assert.ok(locked);
        assert.equal(calls.at(-1), "name");
        calls.push("census");
        return { nl: 0, nd: 0 };
      },
      posix_check(result, name) {
        if (result < 0)
          throw Object.assign(new Error(name), { value: context.errno });
      },
      invariant(ok, name) {
        if (!ok) throw new Error(name);
      },
    };
    const acquire = script.runInNewContext(context);
    if (fault) {
      assert.throws(acquire, (error) => {
        assert.equal(error.message, operation, `${existing}/${fault}`);
        if (errorValue !== undefined) assert.equal(error.value, errorValue);
        return true;
      });
      assert.equal(calls.includes("census"), false);
      if (operation === "fault-lease-shape")
        assert.equal(metadata.at(-1).object, operation);
    } else {
      assert.equal(acquire(), 7);
      assert.deepEqual(calls, [
        "open",
        ...(existing ? ["open"] : []),
        "stat",
        "lock",
        ...(!existing ? ["owner", "mode"] : []),
        "stat",
        "acl",
        "name",
        "census",
      ]);
      assert.equal(file.st_gid, 0);
      assert.equal(file.st_mode, 0o100600);
      if (!existing) assert.deepEqual(metadata[0].stat, initial);
    }
    if (existing || !calls.includes("owner")) {
      assert.deepEqual(file, initial);
      assert.equal(calls.includes("mode"), false);
    }
    assert.equal(opens, existing ? 2 : 1);
  }
});

test("Darwin fault reexec retains possible effects and transfers only the original writable journal", async () => {
  const [source, helper] = await Promise.all(
    ["feasibility-domain.h", "feasibility-helper.c"].map((name) =>
      readFile(new URL(name, SOURCE), "utf8"),
    ),
  );
  const body = /static void domain_transfer\(void\) \{([\s\S]*?)\n\}/u.exec(
    source,
  )?.[1];
  assert.ok(body);
  const script = new Script(
    `() => {${body
      .replace(
        "struct stat inherited, held;",
        "const inherited = {}, held = {};",
      )
      .replaceAll("&inherited", "inherited")
      .replaceAll("&held", "held")
      .replace("int flags", "const flags")}}`,
  );
  for (const fault of [
    null,
    "stat",
    "different-file",
    "flags",
    "readonly",
    "close",
    "cloexec",
  ]) {
    const calls = [],
      context = {
        domain_root: 4,
        domain_journal: 5,
        errno: 0,
        F_GETFL: 1,
        F_SETFD: 2,
        FD_CLOEXEC: 1,
        O_ACCMODE: 3,
        O_RDWR: 2,
        fstat(fd, result) {
          calls.push(["stat", fd]);
          if (fault === "stat") {
            context.errno = 9;
            return -1;
          }
          result.inode = fd === 3 && fault === "different-file" ? 2 : 1;
          return 0;
        },
        same_file_stat: (a, b) => a.inode === b.inode,
        fcntl(fd, command, flags) {
          calls.push(["flags", fd, command, flags]);
          if (
            (fault === "flags" && command === 1) ||
            (fault === "cloexec" && command === 2)
          ) {
            context.errno = 5;
            return -1;
          }
          return command === 1 ? (fault === "readonly" ? 0 : 2) : 0;
        },
        close(fd) {
          calls.push(["close", fd]);
          if (fault === "close") {
            context.errno = 5;
            return -1;
          }
          return 0;
        },
        posix_check(result, operation) {
          if (result < 0)
            throw Object.assign(new Error(operation), { value: context.errno });
        },
        invariant(ok, operation) {
          if (!ok) throw new Error(operation);
        },
      };
    const transfer = script.runInNewContext(context);
    if (!fault) {
      transfer();
      assert.equal(context.domain_journal, 3);
      assert.deepEqual(calls.at(-1), ["flags", 3, 2, 1]);
      assert.deepEqual(
        calls.filter(([op]) => op === "close"),
        [["close", 5]],
      );
    } else {
      const operation = {
        stat: "fault-inherited-stat",
        "different-file": "fault-journal-transfer",
        flags: "fault-journal-flags",
        readonly: "fault-journal-access",
        close: "fault-journal-close",
        cloexec: "fault-journal-flags",
      }[fault];
      assert.throws(transfer, (error) => {
        assert.equal(error.message, operation);
        if (["stat", "flags", "close", "cloexec"].includes(fault))
          assert.equal(error.value, fault === "stat" ? 9 : 5);
        return true;
      });
      assert.ok(!calls.some(([op, fd]) => op === "close" && fd === 3));
    }
  }
  const expression =
    /admitted_effects = (\(argc >= 2 && !strcmp\(argv\[1\], "fault-custody"\)\) \|\| getenv\("NATIVE_FAULT_PARENT_ASID"\) != NULL);/u.exec(
      helper,
    )?.[1];
  assert.ok(expression);
  const possible = new Script(
    `(argv, parent = null) => {const argc = argv.length, getenv = () => parent; return ${expression.replace("NULL", "null")};}`,
  ).runInNewContext({ strcmp: (a, b) => (a === b ? 0 : 1) });
  assert.equal(possible(["helper", "fault-custody"]), true);
  assert.equal(possible(["helper", "fault-domain"]), false);
  assert.equal(possible(["helper", "exec"], "77"), true);
  assert.equal(possible(["helper", "fault"], "77"), true);
  assert.ok(
    helper.indexOf(expression) <
      helper.indexOf(
        '"startup-observer-identity"',
        helper.indexOf("int main("),
      ),
  );
});

test("Darwin fault audit sessions retain exact create/read failures before validating their bindings", async () => {
  const source = await readFile(new URL("custody.h", SOURCE), "utf8"),
    body = /static au_asid_t audit_fresh\(uid_t uid\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(body);
  const script = new Script(
    `uid => {${body.replace("auditinfo_addr_t audit = {0};", "const audit = {ai_termid: {}};").replace("int result", "let result").replaceAll("&audit", "audit").replaceAll("sizeof(audit)", "1")}}`,
  );
  for (const fault of [null, "create", "read", "uid", "asid"]) {
    const calls = [],
      context = {
        errno: 0,
        AU_ASSIGN_ASID: -1,
        AU_IPv4: 4,
        setaudit_addr() {
          calls.push("create");
          if (fault === "create") {
            context.errno = 1;
            return -1;
          }
          return 0;
        },
        getaudit_addr(audit) {
          calls.push("read");
          if (fault === "read") {
            context.errno = 5;
            return -1;
          }
          audit.ai_asid = fault === "asid" ? -1 : 44;
          if (fault === "uid") audit.ai_auid++;
          return 0;
        },
        AUDIT_DOMAIN_DIAG(ok, operation, kind, value) {
          if (!ok) throw Object.assign(new Error(operation), { kind, value });
        },
      };
    const fresh = script.runInNewContext(context);
    if (!fault) assert.equal(fresh(90001), 44);
    else
      assert.throws(
        () => fresh(90001),
        (error) => {
          assert.equal(
            error.message,
            fault === "create"
              ? "audit-session-create"
              : fault === "read"
                ? "audit-session-read"
                : "audit-session-binding",
          );
          assert.equal(
            error.value,
            fault === "create" ? 1 : fault === "read" ? 5 : 0,
          );
          return true;
        },
      );
    assert.deepEqual(
      calls,
      fault === "create" ? ["create"] : ["create", "read"],
    );
  }
});

test("Darwin fault acquisition retains partial pipes and the unreleased direct child through failure", async () => {
  const source = await readFile(
      new URL("feasibility-domain.h", SOURCE),
      "utf8",
    ),
    helper = await readFile(new URL("feasibility-helper.c", SOURCE), "utf8"),
    body = /static void settle_domain\(void\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )[1];
  assert.match(helper, /settle_fault\(\);\s*settle_domain\(\)/u);
  assert.ok(
    source.indexOf("domain_child = child;") <
      source.indexOf("domain_close(&ready[1])"),
  );
  assert.ok(
    source.indexOf("domain_released = true;") <
      source.indexOf('write(release[1], "P"'),
  );
  const script = new Script(
    `() => {${body
      .replace(/\b(?:unsigned|int|pid_t) /gu, "let ")
      .replace("&domain_status", "{set value(v) {domain_status = v;}}")
      .replaceAll("(void)", "")}}`,
  );
  for (const fault of [
    null,
    "partial",
    "child",
    "released",
    "wait",
    "deadline",
    "eintr",
    "close",
  ]) {
    const events = [],
      diagnostics = [],
      pipes = Array.from({ length: 5 }, (_, at) => [10 + at * 2, 11 + at * 2]);
    if (fault === "partial")
      pipes.splice(1, 4, ...Array.from({ length: 4 }, () => [-1, -1]));
    let waits = 0;
    const context = {
      domain_controller: 9000,
      domain_child: 42,
      domain_status: 0,
      domain_pipes: pipes,
      domain_released: fault === "released",
      getpid: () => (fault === "child" ? 42 : 9000),
      errno: fault === "eintr" ? 4 : 10,
      EINTR: 4,
      WNOHANG: 1,
      NULL: null,
      close(fd) {
        events.push(fd);
        return fault === "close" && fd === 10 ? -1 : 0;
      },
      waitpid(pid, status) {
        assert.equal(pid, 42);
        status.value = 0;
        waits++;
        if (fault === "wait" || (fault === "eintr" && waits === 1)) return -1;
        return fault === "deadline" ? 0 : 42;
      },
      poll: () => 0,
      remember_cleanup: (...value) => diagnostics.push(value),
    };
    script.runInNewContext(context)();
    assert.equal(
      events.length,
      fault === "child" ? 0 : fault === "partial" ? 2 : 10,
    );
    assert.equal(
      waits,
      ["child", "released"].includes(fault)
        ? 0
        : fault === "deadline"
          ? 200
          : fault === "eintr"
            ? 2
            : 1,
    );
    if (fault !== "child") assert.ok(pipes.flat().every((fd) => fd === -1));
    assert.equal(
      context.domain_child === -1,
      !["child", "released", "wait", "deadline"].includes(fault),
    );
    assert.equal(
      diagnostics.length,
      ["wait", "deadline", "close"].includes(fault) ? 1 : 0,
    );
    if (diagnostics.length)
      assert.equal(
        diagnostics[0][0],
        fault === "close" ? "fault-close" : "fault-wait",
      );
  }
});

test("Darwin fault recovery requires reaping and complete original-domain retirement within the original bound", async () => {
  const source = await readFile(
      new URL("feasibility-domain.h", SOURCE),
      "utf8",
    ),
    body = (name) =>
      new RegExp(
        `static void ${name}\\(void\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)[1],
    translate = (value) =>
      value
        .replace(/struct audit_domain_view /gu, "let ")
        .replace(/struct identity /gu, "let ")
        .replace(/\b(?:unsigned|int|pid_t|bool) /gu, "let ")
        .replaceAll("&domain_status", "{set value(v) {domain_status = v;}}")
        .replaceAll("(void)", "");
  const script =
    new Script(`function domain_reap() {${translate(body("domain_reap"))}}
    () => {${translate(body("domain_retire"))}}`);
  const verification =
    /static void domain_verify\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(source)[1];
  const gate = new Script(
    verification.slice(0, verification.indexOf("domain_policy_check();")),
  );
  for (const closed of [false, true]) {
    assert.throws(() =>
      gate.runInNewContext({
        closed,
        nonce: "nonce",
        pin: "pin",
        domain_record: { stage: closed ? 6 : 5, emergency: 1 },
        domain_open() {},
        need(ok) {
          assert.ok(ok);
        },
      }),
    );
  }
  const emergency = source.slice(
    source.indexOf('!strcmp(fields[1], "emergency")'),
  );
  assert.ok(
    emergency.indexOf("domain_record.emergency = 1") <
      emergency.indexOf("domain_store(3)"),
  );
  for (const fault of [
    null,
    "live",
    "zombie",
    "unreaped",
    "replaced",
    "backstop",
    "cancel",
    "pin",
  ]) {
    const events = [],
      owner = {
        token: { val: [90001, 90001, 90002, 90001, 90002, 42, 55, 1] },
      };
    let stopped = fault !== "live",
      scans = 0;
    const context = {
      domain_record: { stage: 3, uid: 90001, asid: 55, members: 0, known: [] },
      domain_child: 42,
      domain_status: 0,
      domain_pin: fault === "pin" ? 0 : 200,
      domain_fenced: false,
      MACH_PORT_NULL: 0,
      SIGALRM: 14,
      SIGKILL: 9,
      NULL: null,
      errno: 0,
      EINTR: 4,
      WNOHANG: 1,
      waitpid(_pid, output) {
        output.value = fault === "backstop" ? 14 : 9;
        return stopped && fault !== "unreaped" ? 42 : 0;
      },
      WIFSIGNALED: () => true,
      WTERMSIG: (status) => status,
      need(ok) {
        if (!ok) throw new Error("Incomplete domain");
      },
      invariant(ok, operation) {
        if (!ok) throw new Error(operation);
      },
      domain_check(ok, operation) {
        if (!ok) throw new Error(operation);
      },
      domain_store(stage) {
        context.domain_record.stage = stage;
        events.push(`store:${stage}`);
      },
      audit_census(uid, asid) {
        assert.deepEqual([uid, asid], [90001, 55]);
        scans++;
        return {
          nl: stopped ? 0 : 1,
          nd: fault === "zombie" ? 1 : 0,
          live: [owner],
          dead: [{}],
        };
      },
      domain_recheck() {
        if (fault === "replaced") throw new Error("Replaced owner");
      },
      domain_birth_same: () => false,
      domain_known(value) {
        context.domain_record.known.push(value);
        context.domain_record.members++;
      },
      fault_inspect: () => owner,
      audit_identity_same: (a, b) => a === b,
      signal_identity(value, signal) {
        assert.equal(value, owner);
        assert.equal(signal, 9);
        assert.equal(events.at(-1), "store:4");
        stopped = true;
        events.push("signal");
      },
      poll() {
        if (fault === "cancel") throw new Error("Canceled recovery");
        return 0;
      },
    };
    if (fault === "cancel") stopped = false;
    const retire = script.runInNewContext(context);
    if (fault && fault !== "live") {
      assert.throws(retire);
      assert.ok(!events.includes("store:5"), fault);
      if (fault === "unreaped") assert.equal(scans, 32);
    } else {
      retire();
      assert.equal(context.domain_child, -1);
      assert.equal(events.at(-1), "store:5");
      assert.equal(scans, fault === "live" ? 2 : 1);
    }
  }
});

test("Darwin fault retirement rejects credential drift in known zombies and unstable sealed reads", async () => {
  const source = await readFile(
    new URL("feasibility-domain.h", SOURCE),
    "utf8",
  );
  const birthBody =
    /static bool domain_birth_same\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(birthBody);
  const sameBirth = new Script(
    `(value, b) => {${birthBody}}`,
  ).runInNewContext();
  const identity = {
    token: { val: [90001, 90001, 90002, 90001, 90002, 42] },
    bsd: {
      pbi_start_tvsec: 100,
      pbi_start_tvusec: 9,
      pbi_svuid: 90001,
      pbi_svgid: 90002,
    },
  };
  const zombie = {
    ...identity.bsd,
    pbi_pid: 42,
    pbi_uid: 90001,
    pbi_gid: 90002,
    pbi_ruid: 90001,
    pbi_rgid: 90002,
  };
  assert.equal(sameBirth(identity, zombie), true);
  for (const field of Object.keys(zombie))
    assert.equal(
      sameBirth(identity, { ...zombie, [field]: zombie[field] + 1 }),
      false,
      field,
    );
  assert.match(
    source,
    /need\(size == sizeof\(b\) && domain_birth_same\(value, b\)\)/u,
  );
  assert.match(
    source,
    /if \(domain_birth_same\(value, view.dead\[i\]\)\) known = true/u,
  );
  const fileBody =
    /static bool domain_file_same\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(fileBody);
  const sameFile = new Script(
    `(a, b) => {${fileBody.replaceAll("->", ".")}}`,
  ).runInNewContext({
    same_file_stat: (a, b) => a.identity === b.identity,
  });
  const file = {
    identity: 1,
    st_size: 10,
    st_mtimespec: { tv_sec: 3, tv_nsec: 4 },
    st_ctimespec: { tv_sec: 5, tv_nsec: 6 },
  };
  assert.equal(sameFile(file, structuredClone(file)), true);
  for (const field of [
    "identity",
    "st_size",
    "st_mtimespec.tv_sec",
    "st_mtimespec.tv_nsec",
    "st_ctimespec.tv_sec",
    "st_ctimespec.tv_nsec",
  ]) {
    const changed = structuredClone(file),
      path = field.split(".");
    if (path.length === 1) changed[field]++;
    else changed[path[0]][path[1]]++;
    assert.equal(sameFile(file, changed), false, field);
  }
  assert.equal(
    (source.match(/domain_file_same\(&before,\s*&named\)/gu) ?? []).length,
    3,
  );
});
