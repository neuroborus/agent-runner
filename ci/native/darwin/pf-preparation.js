import path from "node:path";
import {
  assertDarwinPfKernel,
  darwinPfAuthority,
  darwinPfAuthorityDigest,
  assertDarwinPfWindow,
  assertDarwinPfBaseline,
  assertDarwinPfPreserved,
} from "./pf-kernel.js";
import { nativeException } from "../diagnostics.js";
import {
  observationObject,
  observationList,
  normalizeNativePolicyContext,
  observationDigest,
} from "../index.js";
import { purposeData } from "./experiment-policy.js";
import { digest, requireDarwin } from "./protocol.js";

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
  ...(read.purpose === "experiment" ? {} : { routesSha256: read.routesSha256 }),
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
  const attachment = root.rules.filter((rule) => rule.call === "native-poc/*");
  requireDarwin(
    attachment.length === 1 &&
      attachment[0].set === 1 &&
      attachment[0].quick &&
      attachment[0].state === 0 &&
      (read.purpose === "experiment"
        ? root.rules.find((rule) => rule.set === 1) === attachment[0]
        : root.rules.length === 1 &&
          read.graph.every((entry) => ownedAnchor(entry.anchor))),
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
    observationObject(attachment[0].match, Object.keys(expectedMatch));
    requireDarwin(
      attachment[0].action === 0 &&
        Object.entries(expectedMatch).every(
          ([key, value]) => attachment[0].match[key] === value,
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
        schemaVersion: experiment ? 2 : 1,
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
        if (experiment) assertDarwinPfBaseline(before);
        requireDarwin(
          before.states === 0 &&
            (experiment ||
              before.graph.every(
                (entry) =>
                  ownedAnchor(entry.anchor) && entry.rules.length === 0,
              )) &&
            darwinPfAuthorityDigest(before) === expectation.baselineSha256 &&
            (experiment || before.routesSha256 === expectation.routesSha256) &&
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
        const reserved = await read();
        if (experiment) assertDarwinPfWindow(before, reserved);
        else
          requireDarwin(
            darwinPfAuthorityDigest(reserved) === expectation.baselineSha256,
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
        if (experiment) assertDarwinPfPreserved(before, installed, true);
        assertDarwinPfRoot(
          installed,
          expectation.installedRootSha256 ?? darwinPfRootDigest(installed),
        );
        requireDarwin(
          installed.graph.every(
            (entry) =>
              (experiment && !/^native-poc(?:\/|$)/u.test(entry.anchor)) ||
              entry.anchor === "" ||
              entry.rules.length === 0,
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
            record.schemaVersion === (experiment ? 2 : 1) &&
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
          darwinPfAuthorityDigest(baseline) === expectation.baselineSha256 &&
            (!before ||
              digest(JSON.stringify(before)) ===
                digest(JSON.stringify(baseline))),
        );
        if (experiment) assertDarwinPfBaseline(baseline);
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
      if (
        experiment &&
        records.some((record) => record.setup !== "NOT_ADMITTED")
      ) {
        const attached = actual.graph
          .find((node) => node.anchor === "")
          .rules.some((rule) => rule.call === "native-poc/*");
        assertDarwinPfPreserved(before, actual, attached, false, true);
        requireDarwin(
          actual.graph.every(
            (node) =>
              !/^native-poc(?:\/|$)/u.test(node.anchor) ||
              node.anchor === "" ||
              node.rules.length === 0,
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
        assertDarwinPfPreserved(before, await read(), false, true);
      } else if (
        darwinPfAuthorityDigest(actual) !== expectation.baselineSha256
      ) {
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
        if (experiment) {
          assertDarwinPfPreserved(before, current, true);
          requireDarwin(
            current.kernel.anchors.find((node) => !node.anchor).sets[1]
              .ticket ===
              installed.kernel.anchors.find((node) => !node.anchor).sets[1]
                .ticket,
          );
        }
        assertDarwinPfRoot(
          current,
          expectation.installedRootSha256 ?? darwinPfRootDigest(installed),
        );
        requireDarwin(
          current.graph.every(
            (entry) =>
              (experiment && !/^native-poc(?:\/|$)/u.test(entry.anchor)) ||
              entry.anchor === "" ||
              entry.rules.length === 0,
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
        const restored = await read();
        if (experiment) assertDarwinPfPreserved(before, restored, false, true);
        else
          requireDarwin(
            darwinPfAuthorityDigest(restored) ===
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
