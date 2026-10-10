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

function image() {
  const bytes = Buffer.alloc(84);
  for (const [offset, value] of [
    [0, 0xfeedfacf],
    [4, 0x01000007],
    [12, 2],
    [16, 2],
    [20, 48],
    [32, 0xe],
    [36, 32],
    [40, 12],
    [64, 0x1d],
    [68, 16],
    [72, 80],
    [76, 4],
  ])
    bytes.writeUInt32LE(value, offset);
  bytes.write("/usr/lib/dyld", 44);
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
      ["feasibility-helper.c", "feasibility-sandbox.h", "argv-fixture.c"].map(
        async (name) => [name, await readFile(new URL(name, SOURCE))],
      ),
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
  for (const args of builds)
    for (const flag of ["-DNATIVE_FEASIBILITY_COMMAND", "-lbsm"])
      assert.equal(args.includes(flag), false);
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
  for (const [condition, change] of [
    ["header", (bytes) => bytes.writeUInt32LE(0x0100000c, 4)],
    ["signature", (bytes) => bytes.writeUInt32LE(0x19, 64)],
    ["loader", (bytes) => bytes.write("/bad/lib/dyld", 44)],
  ]) {
    const bytes = image(),
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
