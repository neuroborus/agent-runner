import { StringDecoder } from "node:string_decoder";
import path from "node:path";
import {
  assertDarwinPfKernel,
  darwinPfAuthority,
  darwinPfAuthorityDigest,
  assertDarwinPfWindow,
} from "./pf-kernel.js";
import {
  nativeDiagnostic,
  nativeException,
  settledCompilerFailure,
} from "../diagnostics.js";
import {
  observationObject,
  observationList,
  normalizeNativePolicyContext,
  observationDigest,
} from "../index.js";
import { purposeData } from "./experiment-policy.js";
import { digest, requireDarwin } from "./protocol.js";

const PF_EXECUTABLES = new Set(["/usr/bin/sudo", "/usr/bin/id", "/sbin/pfctl"]);
const PF_IDENTITY = [
  "dev",
  "ino",
  "mode",
  "uid",
  "gid",
  "nlink",
  "size",
  "mtimeMs",
  "ctimeMs",
];
const samePfIdentity = (before, after) =>
  PF_IDENTITY.every((key) => before[key] === after[key]);

/** Diagnostic execution observations never admit an image to native custody. */
export async function observeDarwinPfExecutable(file, fs) {
  requireDarwin(PF_EXECUTABLES.has(file) && (await fs.realpath(file)) === file);
  const before = await fs.lstat(file),
    mode = before.mode & 0o7777;
  requireDarwin(
    before.isFile() &&
      !before.isSymbolicLink() &&
      before.uid === 0 &&
      before.gid === 0 &&
      (mode & 0o111) === 0o111 &&
      !(mode & (file === "/usr/bin/sudo" ? 0o3022 : 0o7022)) &&
      Number.isSafeInteger(before.nlink) &&
      before.nlink > 0 &&
      before.size > 0 &&
      before.size <= 134217728 &&
      PF_IDENTITY.every(
        (key) =>
          typeof before[key] === "number" && Number.isFinite(before[key]),
      ),
  );
  const parents = [];
  for (let parent = path.dirname(file); ; parent = path.dirname(parent)) {
    const stat = await fs.lstat(parent);
    requireDarwin(
      parents.length < 32 &&
        stat.isDirectory() &&
        !stat.isSymbolicLink() &&
        stat.uid === 0 &&
        !(stat.mode & 0o22) &&
        (await fs.realpath(parent)) === parent,
    );
    parents.push([parent, stat]);
    if (parent === "/") break;
  }
  requireDarwin(
    samePfIdentity(before, await fs.lstat(file)) &&
      (await fs.realpath(file)) === file,
  );
  for (const [parent, stat] of parents)
    requireDarwin(
      samePfIdentity(stat, await fs.lstat(parent)) &&
        (await fs.realpath(parent)) === parent,
    );
  return {
    path: file,
    identity: Object.fromEntries(PF_IDENTITY.map((key) => [key, before[key]])),
  };
}

/** Installed capability facts only: no alternate header, ABI or policy admission. */
export async function observeDarwinPfCapabilities(
  sdk,
  compiler,
  { read, executable, run, signal, context, now = () => performance.now() },
) {
  const facts = [],
    until = now() + 40000;
  let stop, unsafe;
  // Bound decoded UTF-8 bytes without emitting a split trailing character.
  const output = (value) =>
    Buffer.isBuffer(value) || typeof value === "string"
      ? Buffer.from(value.toString())
      : Buffer.alloc(0);
  const capture = (value) => {
    const stdout = output(value?.stdout),
      stderr = output(value?.stderr);
    return {
      stdout: new StringDecoder("utf8").write(stdout.subarray(0, 65536)),
      stderr: new StringDecoder("utf8").write(stderr.subarray(0, 65536)),
      truncated:
        !!value?.truncated ||
        value?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" ||
        stdout.length > 65536 ||
        stderr.length > 65536,
      partial: !!value?.partial,
    };
  };
  const budget = () => {
    if (signal?.aborted) {
      stop = "cancelled";
      unsafe ??= { cause: signal.reason };
    }
    if (now() >= until) {
      stop ??= "deadline";
      unsafe ??= {
        cause: new Error("Darwin PF capability deadline exhausted"),
      };
    }
  };
  const observe = async (name, action, prerequisite = true, command = {}) => {
    budget();
    if (stop || !prerequisite) {
      facts.push({
        name,
        ...command,
        status: "UNATTEMPTED",
        reason: stop ?? "missing-prerequisite",
      });
      return false;
    }
    try {
      facts.push({ name, ...command, status: "OBSERVED", ...(await action()) });
      return true;
    } catch (error) {
      try {
        nativeException("darwin-pf-capability/" + name, error);
      } catch {
        /* Keep the observation and original unsafe completion available. */
      }
      const captured = capture(error);
      facts.push({
        name,
        ...command,
        status: error?.code === "ENOENT" ? "ABSENT" : "FAILED",
        code:
          typeof error?.code === "string" || Number.isInteger(error?.code)
            ? error.code
            : null,
        signal: error?.signal ?? null,
        timedOut: error?.timedOut ?? false,
        killed: error?.killed ?? false,
        ...captured,
      });
      if (
        signal?.aborted ||
        error?.killed ||
        error?.timedOut ||
        error?.signal ||
        captured.truncated ||
        captured.partial ||
        (command.file && !settledCompilerFailure(error))
      ) {
        stop = "unsafe-command-completion";
        unsafe ??= { cause: error };
      }
      return false;
    }
  };
  const header = sdk + "/usr/include/net/pfvar.h";
  const identity = async (file) => {
    const bytes = await read(file);
    requireDarwin(
      Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 134217728,
    );
    return { path: file, sha256: digest(bytes) };
  };
  const installed = new Map();
  const stable = async (file) =>
    requireDarwin(
      observationDigest(await executable(file)) ===
        observationDigest(installed.get(file)),
    );
  const installedIdentity = async (name, file) => {
    const observed = await executable(file);
    requireDarwin(observed.path === file);
    installed.set(file, observed);
    let sha256 = null,
      image;
    try {
      sha256 = (await identity(file)).sha256;
      image = { status: "OBSERVED" };
    } catch (error) {
      const captured = capture(error);
      if (
        !["EACCES", "EPERM"].includes(error?.code) ||
        signal?.aborted ||
        error?.killed ||
        error?.timedOut ||
        error?.signal ||
        captured.truncated ||
        captured.partial
      )
        throw error;
      try {
        nativeException("darwin-pf-capability/" + name + "-image", error);
      } catch {
        /* Keep the original read failure in the observation. */
      }
      image = { status: "FAILED", code: error.code, ...captured };
    }
    await stable(file);
    return { path: file, executable: observed, sha256, image };
  };
  const query = (name, file, args, prerequisite, tools = []) =>
    observe(
      name,
      async () => {
        for (const tool of tools) await stable(tool);
        budget();
        if (stop) throw unsafe.cause;
        let failure;
        try {
          const result = await run(file, args, {
              timeout: Math.max(1, Math.min(3000, Math.ceil(until - now()))),
              maxBuffer: 65536,
            }),
            captured = capture(result);
          if (
            captured.truncated ||
            captured.partial ||
            result.timedOut ||
            result.killed ||
            result.signal
          )
            throw Object.assign(
              new Error("Incomplete Darwin PF capability capture"),
              result,
              captured,
            );
          return { exitCode: 0, ...captured };
        } catch (error) {
          failure = error;
          throw error;
        } finally {
          try {
            for (const tool of tools) await stable(tool);
          } catch (error) {
            if (!failure) throw error;
            stop = "unsafe-command-completion";
            unsafe ??= { cause: failure };
            try {
              nativeException("darwin-pf-capability/changed-executable", error);
            } catch {
              /* Preserve the original command failure. */
            }
          }
        }
      },
      prerequisite,
      { file, args },
    );
  const available = await observe("selected-sdk-pf-header", () =>
    identity(header),
  );
  await query(
    "selected-sdk-pf-dependencies",
    compiler,
    ["-M", "-x", "c", "-isysroot", sdk, header],
    available,
  );
  const tool = await observe("installed-pf-tool", () =>
    installedIdentity("installed-pf-tool", "/sbin/pfctl"),
  );
  for (const [name, args] of [
    ["version", ["-V"]],
    ["info", ["-s", "info"]],
    ["rules", ["-s", "rules"]],
    ["anchors", ["-s", "Anchors"]],
  ])
    await query("pfctl-" + name, "/sbin/pfctl", args, tool, ["/sbin/pfctl"]);
  const sudo = await observe("installed-sudo-tool", () =>
      installedIdentity("installed-sudo-tool", "/usr/bin/sudo"),
    ),
    id = await observe("installed-id-tool", () =>
      installedIdentity("installed-id-tool", "/usr/bin/id"),
    );
  await query(
    "privileged-id",
    "/usr/bin/sudo",
    ["-n", "--", "/usr/bin/id", "-u"],
    sudo && id,
    ["/usr/bin/sudo", "/usr/bin/id"],
  );
  for (const [name, selector] of [
    ["info", "info"],
    ["rules", "rules"],
    ["anchors", "Anchors"],
  ])
    await query(
      "privileged-pfctl-" + name,
      "/usr/bin/sudo",
      ["-n", "--", "/sbin/pfctl", "-s", selector],
      sudo && tool,
      ["/usr/bin/sudo", "/sbin/pfctl"],
    );
  budget();
  try {
    nativeDiagnostic("darwin-pf-capabilities", {
      stderr: JSON.stringify({ sdk, compiler, context, facts }),
    });
  } finally {
    if (unsafe) throw unsafe.cause;
  }
  return facts;
}

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const integer = (value, bound = 0xffffffff) =>
  Number.isSafeInteger(value) && value >= 0 && value <= bound;
const ownedAnchor = (value) =>
  value === "" ||
  value === "native-poc" ||
  /^native-poc\/[a-f0-9]{32}$/u.test(value);
export function normalizeDarwinPfRead(
  value,
  purpose = value.purpose ?? "reviewed",
) {
  const experiment = purpose === "experiment";
  requireDarwin(
    ["reviewed", "experiment"].includes(purpose) &&
      (value.purpose ?? "reviewed") === purpose,
  );
  observationObject(value, [
    ...(experiment ? ["purpose", "kernel"] : []),
    "active",
    "states",
    "graph",
    "interfaces",
    "routesSha256",
  ]);
  requireDarwin(
    typeof value.active === "boolean" &&
      integer(value.states) &&
      hash(value.routesSha256),
  );
  const graph = observationList(value.graph, 64)
    .map((entry) => {
      observationObject(entry, ["anchor", "rules"]);
      requireDarwin(
        typeof entry.anchor === "string" &&
          (experiment
            ? /^(?:[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*)?$/u
            : /^(?:[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*)?$/u
          ).test(entry.anchor) &&
          entry.anchor
            .split("/")
            .every((part) => part !== "." && part !== "..") &&
          entry.anchor.length < 1024,
      );
      const rules = observationList(entry.rules, 64).map((rule) => {
        observationObject(rule, [
          ...(experiment ? ["index", "ticket", "match"] : []),
          "set",
          "action",
          "quick",
          "state",
          "call",
          "raw",
        ]);
        requireDarwin(
          integer(rule.set, experiment ? 5 : 4) &&
            integer(rule.action, 255) &&
            typeof rule.quick === "boolean" &&
            integer(rule.state, 255) &&
            typeof rule.call === "string" &&
            (experiment ? /^[A-Za-z0-9_./*-]*$/u : /^[A-Za-z0-9_/*-]*$/u).test(
              rule.call,
            ) &&
            !rule.call
              .split("/")
              .some((part) => part === "." || part === "..") &&
            rule.call.length < 1024 &&
            typeof rule.raw === "string" &&
            /^(?:[a-f0-9]{2}){1,4096}$/u.test(rule.raw),
        );
        return { ...rule };
      });
      return { anchor: entry.anchor, rules };
    })
    .sort((a, b) => a.anchor.localeCompare(b.anchor, "en"));
  requireDarwin(
    graph.some((entry) => entry.anchor === "") &&
      new Set(graph.map((entry) => entry.anchor)).size === graph.length &&
      graph.reduce((n, entry) => n + entry.rules.length, 0) <= 64,
  );
  const interfaces = observationList(value.interfaces, 127)
    .map((item) => {
      observationObject(item, [
        "name",
        "skip",
        ...(experiment ? ["flags"] : []),
      ]);
      requireDarwin(
        typeof item.name === "string" &&
          /^[A-Za-z0-9_-]{1,15}$/u.test(item.name) &&
          typeof item.skip === "boolean" &&
          (!experiment ||
            (integer(item.flags) && item.skip === Boolean(item.flags & 0x100))),
      );
      return { ...item };
    })
    .sort((a, b) => a.name.localeCompare(b.name, "en"));
  requireDarwin(
    interfaces.some((item) => item.name === "lo0") &&
      new Set(interfaces.map((item) => item.name)).size === interfaces.length,
  );
  const read = { ...value, graph, interfaces };
  if (experiment) assertDarwinPfKernel(read);
  return read;
}
const rootGraph = (read) => ({
  active: read.active,
  root: darwinPfAuthority(read).graph.find((entry) => entry.anchor === ""),
  interfaces: read.interfaces,
  routesSha256: read.routesSha256,
});
export function darwinPfRootDigest(read) {
  return digest(JSON.stringify(rootGraph(read)));
}
export function assertDarwinPfRoot(read, expected) {
  requireDarwin(
    read.active &&
      read.states === 0 &&
      darwinPfRootDigest(read) === expected &&
      read.interfaces.every((item) => !item.skip),
  );
  const root = read.graph.find((entry) => entry.anchor === "");
  requireDarwin(
    root.rules.length === 1 &&
      root.rules[0].set === 1 &&
      root.rules[0].quick &&
      root.rules[0].state === 0 &&
      root.rules[0].call === "native-poc/*" &&
      read.graph.every((entry) => ownedAnchor(entry.anchor)),
  );
  if (read.purpose === "experiment") {
    // The fixed `anchor "native-poc/*" all quick` recipe supplies expectations;
    // an observed root digest cannot establish that the call covers all traffic.
    const expectedMatch = {
      direction: 0,
      interface: "",
      family: "any",
      protocol: 0,
      source: "any",
      destination: "any",
      sourcePort: null,
      destinationPort: null,
      uid: null,
      returns: false,
    };
    observationObject(root.rules[0].match, Object.keys(expectedMatch));
    requireDarwin(
      root.rules[0].action === 0 &&
        Object.entries(expectedMatch).every(
          ([key, value]) => root.rules[0].match[key] === value,
        ),
    );
  }
}

/** Purpose-bound host setup, never a per-case root operation. A failed write
 * retains exclusion and needs independent recovery; no speculative rollback. */
export function createDarwinPfPreparation(value, effects) {
  const experiment = value.purpose === "experiment",
    expectationKey = experiment ? "bindings" : "approval",
    pinKey = experiment ? "bindingSha256" : "manifestSha256",
    receiptKey = experiment ? "bindingSha256" : "approvalSha256",
    verifyKey = experiment ? "verifyInputs" : "review";
  observationObject(value, [
    ...Object.keys(purposeData(value)),
    "context",
    expectationKey,
    "tool",
    "install",
    "restore",
    "reservation",
    "nonce",
  ]);
  value = structuredClone(value);
  const context = normalizeNativePolicyContext(value.context),
    expectation = structuredClone(value[expectationKey]);
  observationObject(expectation, [
    "schemaVersion",
    "contextSha256",
    pinKey,
    "baselineSha256",
    "installedRootSha256",
    "routesSha256",
    "loopbackSkip",
  ]);
  requireDarwin(
    context.platform === "darwin" &&
      expectation.schemaVersion === 1 &&
      expectation.contextSha256 === digest(JSON.stringify(context)) &&
      [pinKey, "baselineSha256", "routesSha256"].every((key) =>
        hash(expectation[key]),
      ) &&
      (hash(expectation.installedRootSha256) ||
        (experiment && expectation.installedRootSha256 === null)) &&
      typeof expectation.loopbackSkip === "boolean" &&
      /^[a-f0-9]{32}$/u.test(value.nonce),
  );
  observationObject(value.tool, ["index", "cdhash"]);
  requireDarwin(
    integer(value.tool.index, 127) && /^[a-f0-9]{40}$/u.test(value.tool.cdhash),
  );
  requireDarwin(
    [value.install, value.restore, value.reservation].every((index) =>
      integer(index, 127),
    ) &&
      new Set([
        value.tool.index,
        value.install,
        value.restore,
        value.reservation,
      ]).size === 4,
  );
  requireDarwin(
    [
      verifyKey,
      "read",
      "reserve",
      "write",
      "reservation",
      "persist",
      "verifyRetirement",
    ].every((key) => typeof effects?.[key] === "function"),
  );
  const input = value;
  let before,
    installed,
    failure,
    started = false,
    busy = false,
    sequence = 0,
    reservation = "NOT_ADMITTED",
    setup = "NOT_ADMITTED";
  const save = (phase) =>
    effects.persist(
      structuredClone({
        ...purposeData(value),
        schemaVersion: 1,
        context,
        sequence: sequence++,
        phase,
        [receiptKey]: expectation[pinKey],
        setupSha256: digest(JSON.stringify(input)),
        setup,
        reservation,
        before: before ?? null,
      }),
    );
  const read = async () => {
    const a = normalizeDarwinPfRead(
        await effects.read(),
        experiment ? "experiment" : "reviewed",
      ),
      b = normalizeDarwinPfRead(
        await effects.read(),
        experiment ? "experiment" : "reviewed",
      );
    if (experiment) assertDarwinPfWindow(a, b);
    else requireDarwin(digest(JSON.stringify(a)) === digest(JSON.stringify(b)));
    return b;
  };
  const verify = async () => {
    const observed = await effects[verifyKey](structuredClone(expectation));
    observationObject(observed, [
      ...Object.keys(purposeData(value)),
      "status",
      "contextSha256",
      pinKey,
    ]);
    requireDarwin(
      (observed.purpose ?? "reviewed") === (value.purpose ?? "reviewed") &&
        observed.status === "MATCHED" &&
        observed.contextSha256 === expectation.contextSha256 &&
        observed[pinKey] === expectation[pinKey],
    );
  };
  return {
    async prepare() {
      if (failure) throw failure;
      requireDarwin(!started);
      started = true;
      busy = true;
      try {
        await verify();
        before = await read();
        requireDarwin(
          before.states === 0 &&
            before.graph.every(
              (entry) => ownedAnchor(entry.anchor) && entry.rules.length === 0,
            ) &&
            darwinPfAuthorityDigest(before) === expectation.baselineSha256 &&
            before.routesSha256 === expectation.routesSha256 &&
            before.interfaces.every(
              (item) =>
                item.skip === (item.name === "lo0" && expectation.loopbackSkip),
            ),
        );
        reservation = "POSSIBLE";
        await save("reservation-possible");
        await effects.reserve(input.reservation, input.nonce);
        await effects.reservation();
        reservation = "RETAINED";
        requireDarwin(
          darwinPfAuthorityDigest(await read()) === expectation.baselineSha256,
        );
        setup = "POSSIBLE";
        await save("setup-possible");
        await effects.write(
          input.tool.index,
          input.install,
          input.tool.cdhash,
          "install",
        );
        installed = await read();
        assertDarwinPfRoot(
          installed,
          expectation.installedRootSha256 ?? darwinPfRootDigest(installed),
        );
        requireDarwin(
          installed.graph.every(
            (entry) => entry.anchor === "" || entry.rules.length === 0,
          ),
        );
        await effects.reservation();
        setup = "INSTALLED";
        await save("installed");
        return {
          status: "INSTALLED",
          setupSha256: darwinPfAuthorityDigest(installed),
          rootSha256: darwinPfRootDigest(installed),
          reservation: "RETAINED",
        };
      } catch (cause) {
        nativeException("darwin-pf-preparation", cause);
        failure ??= new Error("Unverified Darwin PF preparation", { cause });
        try {
          await save("uncertain");
        } catch (error) {
          nativeException("darwin-pf-preparation-receipt", error);
        }
        throw failure;
      } finally {
        busy = false;
      }
    },
    // A fresh owner replays no setup. Missing result records are joined to
    // protected before-state and two complete current kernel reads.
    async recover(records, retirement) {
      requireDarwin(!started && records.length > 0 && records.length <= 64);
      started = true;
      await verify();
      for (const [i, record] of records.entries()) {
        observationObject(record, [
          ...Object.keys(purposeData(value)),
          "schemaVersion",
          "context",
          "sequence",
          "phase",
          receiptKey,
          "setupSha256",
          "setup",
          "reservation",
          "before",
        ]);
        requireDarwin(
          (record.purpose ?? "reviewed") === (value.purpose ?? "reviewed") &&
            record.schemaVersion === 1 &&
            record.sequence === i &&
            digest(JSON.stringify(record.context)) ===
              digest(JSON.stringify(context)) &&
            record[receiptKey] === expectation[pinKey] &&
            record.setupSha256 === digest(JSON.stringify(input)) &&
            [
              "reservation-possible",
              "setup-possible",
              "installed",
              "uncertain",
              "restore-possible",
              "restored",
            ].includes(record.phase) &&
            ["NOT_ADMITTED", "POSSIBLE", "INSTALLED", "RESTORED"].includes(
              record.setup,
            ) &&
            ["POSSIBLE", "RETAINED"].includes(record.reservation),
        );
        const baseline = normalizeDarwinPfRead(
          record.before,
          experiment ? "experiment" : "reviewed",
        );
        requireDarwin(
          darwinPfAuthorityDigest(baseline) === expectation.baselineSha256,
        );
        before = baseline;
      }
      sequence = records.length;
      reservation = "RETAINED";
      requireDarwin(
        (await effects.verifyRetirement(
          structuredClone(retirement),
          context,
        )) === true,
      );
      await effects.reservation();
      const actual = await read();
      if (darwinPfAuthorityDigest(actual) !== expectation.baselineSha256) {
        requireDarwin(
          records.some((record) => record.setup !== "NOT_ADMITTED"),
        );
        assertDarwinPfRoot(
          actual,
          expectation.installedRootSha256 ?? darwinPfRootDigest(actual),
        );
        requireDarwin(
          actual.graph.every(
            (entry) => entry.anchor === "" || entry.rules.length === 0,
          ),
        );
        requireDarwin(typeof effects.recoverReference === "function");
        await effects.recoverReference();
        setup = "POSSIBLE";
        await save("restore-possible");
        await effects.write(
          input.tool.index,
          input.restore,
          input.tool.cdhash,
          expectation.loopbackSkip ? "restore-skip" : "restore",
        );
        requireDarwin(
          darwinPfAuthorityDigest(await read()) === expectation.baselineSha256,
        );
      }
      setup = "RESTORED";
      await save("restored");
      return { status: "RESTORED", reservation: "RETAINED" };
    },
    async restore(retirement) {
      if (failure) throw failure;
      requireDarwin(installed && !busy && setup === "INSTALLED");
      busy = true;
      try {
        requireDarwin(
          (await effects.verifyRetirement(
            structuredClone(retirement),
            context,
          )) === true,
        );
        await effects.reservation();
        const current = await read();
        assertDarwinPfRoot(
          current,
          expectation.installedRootSha256 ?? darwinPfRootDigest(installed),
        );
        requireDarwin(
          current.graph.every(
            (entry) => entry.anchor === "" || entry.rules.length === 0,
          ),
        );
        setup = "POSSIBLE";
        await save("restore-possible");
        await effects.write(
          input.tool.index,
          input.restore,
          input.tool.cdhash,
          expectation.loopbackSkip ? "restore-skip" : "restore",
        );
        requireDarwin(
          darwinPfAuthorityDigest(await read()) ===
            darwinPfAuthorityDigest(before),
        );
        setup = "RESTORED";
        await save("restored");
        installed = null;
        return { status: "RESTORED", reservation: "RETAINED" };
      } catch (cause) {
        nativeException("darwin-pf-restoration", cause);
        failure ??= new Error("Unverified Darwin PF restoration", { cause });
        try {
          await save("uncertain");
        } catch (error) {
          nativeException("darwin-pf-restoration-receipt", error);
        }
        throw failure;
      } finally {
        busy = false;
      }
    },
  };
}
