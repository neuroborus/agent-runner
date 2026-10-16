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
