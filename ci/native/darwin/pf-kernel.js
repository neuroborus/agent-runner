import {
  observationDigest,
  observationList,
  observationObject,
} from "../index.js";
import { digest, requireDarwin } from "./protocol.js";

const uint = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 0xffffffff;
const decimal = (n) =>
  typeof n === "string" &&
  /^(?:0|[1-9][0-9]{0,19})$/u.test(n) &&
  BigInt(n) <= 0xffffffffffffffffn;
export function darwinPfAuthority(read) {
  if (read.purpose !== "experiment") return read;
  const { kernel, ...authority } = read;
  return {
    ...authority,
    graph: read.graph.map((node) => ({
      ...node,
      rules: node.rules.map(({ ticket, ...rule }) => rule),
    })),
  };
}
export const darwinPfAuthorityDigest = (read) =>
  observationDigest(darwinPfAuthority(read));

// DIOCCHANGERULE preserves each foreign rule object, but recalculates its
// ordinal and skip destinations. Only this lifecycle comparison removes those
// derived positions; ordinary reads and counter windows retain them.
export function darwinPfForeign(read) {
  return read.graph
    .filter((node) => !/^native-poc(?:\/|$)/u.test(node.anchor))
    .map((node) => ({
      ...node,
      rules: node.rules
        .filter((rule) => node.anchor || rule.call !== "native-poc/*")
        .map((rule) => {
          if (node.anchor || rule.set !== 1) return rule;
          const raw = Buffer.from(rule.raw, "hex");
          if (raw.length === 1040) {
            raw.fill(0, 128, 192);
            raw.fill(0, 948, 952);
          }
          const { index, ...identity } = rule;
          return { ...identity, raw: raw.toString("hex") };
        }),
    }));
}

const allTraffic = (rule) =>
  rule.state === 0 &&
  observationDigest(rule.match) ===
    observationDigest({
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
    });
export function assertDarwinPfBaseline(read) {
  requireDarwin(
    read.purpose === "experiment" &&
      !read.active &&
      !read.states &&
      read.graph.every((node) => !/^native-poc(?:\/|$)/u.test(node.anchor)) &&
      read.interfaces.every((item) => !item.skip || item.name === "lo0"),
  );
  const root = read.graph.find((node) => node.anchor === "");
  // Stock attachments are stateless, unscoped calls. Other supported policy
  // may live below them and is retained byte-for-byte, with its rule identities.
  requireDarwin(
    root.rules.every(
      (rule) =>
        rule.call === "com.apple/*" &&
        !rule.quick &&
        allTraffic(rule) &&
        rule.action === [2, 0, 4, 6, 8, 11][rule.set],
    ),
  );
}
export function assertDarwinPfPreserved(
  before,
  after,
  attached,
  restored = false,
  partial = false,
) {
  const interfaces = partial
    ? after.interfaces.map((item) => {
        const original = before.interfaces.find(
          (entry) => entry.name === item.name,
        );
        requireDarwin(
          original &&
            (item.flags === original.flags ||
              (item.name === "lo0" &&
                item.flags === (original.flags & ~0x100))),
        );
        return original;
      })
    : after.interfaces;
  requireDarwin(
    before.purpose === "experiment" &&
      after.purpose === "experiment" &&
      after.states === 0 &&
      before.routesSha256 === after.routesSha256 &&
      observationDigest(darwinPfForeign(before)) ===
        observationDigest(darwinPfForeign(after)) &&
      observationDigest(
        before.interfaces.map((item) => ({
          ...item,
          ...(restored || partial || item.name !== "lo0"
            ? {}
            : { skip: false, flags: item.flags & ~0x100 }),
        })),
      ) === observationDigest(interfaces) &&
      (partial || after.active === (restored ? before.active : true)) &&
      (!restored ||
        darwinPfAuthorityDigest(before) === darwinPfAuthorityDigest(after)),
  );
  const rules = after.graph.find((node) => node.anchor === "").rules,
    owned = rules.filter((rule) => rule.call === "native-poc/*");
  requireDarwin(owned.length === (attached ? 1 : 0));
  if (attached)
    requireDarwin(
      rules.find((rule) => rule.set === 1) === owned[0] &&
        owned[0].set === 1 &&
        owned[0].action === 0 &&
        owned[0].quick &&
        allTraffic(owned[0]),
    );
  for (const node of before.kernel.anchors) {
    const actual = after.kernel.anchors.find(
      (entry) => entry.anchor === node.anchor,
    );
    requireDarwin(
      actual &&
        node.sets.every(
          (set, i) =>
            (!node.anchor && i === 1) ||
            observationDigest(set) === observationDigest(actual.sets[i]),
        ),
    );
  }
}
export function assertDarwinPfWindow(before, after) {
  const generations = (read) => ({
    kernel: read.kernel,
    rules: read.graph.map((node) => node.rules.map((rule) => rule.ticket)),
  });
  requireDarwin(
    darwinPfAuthorityDigest(before) === darwinPfAuthorityDigest(after) &&
      observationDigest(generations(before)) ===
        observationDigest(generations(after)),
  );
}

/** Generation transcripts are observations, never authority or counter pins. */
export function assertDarwinPfKernel(read) {
  requireDarwin(read.purpose === "experiment");
  observationObject(read.kernel, ["anchors", "states"]);
  observationObject(read.kernel.states, ["bytes", "sha256"]);
  requireDarwin(
    read.states === 0 &&
      read.kernel.states.bytes === 0 &&
      read.kernel.states.sha256 === digest(Buffer.alloc(0)),
  );
  const anchors = observationList(read.kernel.anchors, 64);
  requireDarwin(
    anchors.length === read.graph.length &&
      new Set(anchors.map((node) => node.anchor)).size === anchors.length,
  );
  for (const node of anchors) {
    observationObject(node, ["anchor", "sets", "children"]);
    const graph = read.graph.find((entry) => entry.anchor === node.anchor);
    requireDarwin(graph && observationList(node.sets, 6).length === 6);
    const children = read.graph
      .filter(
        (entry) =>
          entry.anchor &&
          (entry.anchor.includes("/")
            ? entry.anchor.slice(0, entry.anchor.lastIndexOf("/"))
            : "") === node.anchor,
      )
      .map((entry) => entry.anchor.slice(entry.anchor.lastIndexOf("/") + 1))
      .sort();
    requireDarwin(
      observationDigest(observationList(node.children, 64)) ===
        observationDigest(children),
    );
    for (const [set, generation] of node.sets.entries()) {
      observationObject(generation, ["ticket", "count"]);
      const rules = graph.rules.filter((rule) => rule.set === set);
      requireDarwin(
        uint(generation.ticket) && generation.count === rules.length,
      );
      for (const [index, rule] of rules.entries()) {
        requireDarwin(rule.index === index && decimal(rule.ticket));
        observationObject(rule.match, [
          "direction",
          "interface",
          "family",
          "protocol",
          "source",
          "destination",
          "sourcePort",
          "destinationPort",
          "uid",
          "returns",
        ]);
        const match = rule.match;
        requireDarwin(
          [0, 1, 2].includes(match.direction) &&
            typeof match.interface === "string" &&
            /^[A-Za-z0-9_.-]{0,15}$/u.test(match.interface) &&
            ["any", "inet", "inet6"].includes(match.family) &&
            [0, 6, 17].includes(match.protocol) &&
            [match.source, match.destination].every(
              (address) =>
                typeof address === "string" &&
                /^(?:any|[0-9a-f:.]{2,45})$/u.test(address),
            ) &&
            [match.sourcePort, match.destinationPort].every(
              (port) =>
                port === null || (uint(port) && port > 0 && port <= 65535),
            ) &&
            (match.uid === null || uint(match.uid)) &&
            typeof match.returns === "boolean",
        );
      }
    }
    requireDarwin(
      graph.rules.every(
        (rule, i) => i === 0 || rule.set >= graph.rules[i - 1].set,
      ),
    );
    if (node.anchor.includes("/"))
      requireDarwin(
        read.graph.some(
          (entry) =>
            entry.anchor === node.anchor.slice(0, node.anchor.lastIndexOf("/")),
        ),
      );
  }
}

/** Independent expansion of the fixed candidate recipe; installed bytes cannot
 * supply expectations, including the final protocol-list expansion. */
export function darwinPfExpectedRules(plan) {
  const rules = [],
    uid = plan.value.request.uid;
  const add = (action, match) =>
    rules.push({
      action,
      quick: true,
      state: 0,
      call: "",
      match: {
        direction: 0,
        interface: "",
        family: "any",
        protocol: 0,
        source: "any",
        destination: "any",
        sourcePort: null,
        destinationPort: null,
        uid: null,
        returns: action === 1,
        ...match,
      },
    });
  for (const endpoint of plan.value.endpoints) {
    const address = endpoint.family === "inet" ? "127.0.0.1" : "::1",
      base = {
        family: endpoint.family,
        protocol: endpoint.protocol === "tcp" ? 6 : 17,
      };
    if (plan.value.request.execution) {
      for (const [direction, owner, sourcePort, destinationPort] of [
        [2, uid, null, endpoint.serverPort],
        [1, 0, null, endpoint.serverPort],
        [2, 0, endpoint.serverPort, null],
        [1, uid, endpoint.serverPort, null],
      ])
        add(0, {
          ...base,
          direction,
          interface: "lo0",
          source: address,
          destination: address,
          sourcePort,
          destinationPort,
          uid: owner,
        });
      add(1, {
        ...base,
        destination: address,
        destinationPort: endpoint.serverPort,
      });
      add(1, { ...base, source: address, sourcePort: endpoint.serverPort });
    } else {
      for (const [sourcePort, destinationPort] of [
        [endpoint.clientPort, endpoint.serverPort],
        [endpoint.serverPort, endpoint.clientPort],
      ])
        for (const direction of [2, 1])
          add(0, {
            ...base,
            direction,
            interface: "lo0",
            source: address,
            destination: address,
            sourcePort,
            destinationPort,
            uid,
          });
      for (const port of [endpoint.clientPort, endpoint.serverPort]) {
        add(1, { ...base, destination: address, destinationPort: port });
        add(1, { ...base, source: address, sourcePort: port });
      }
    }
  }
  for (const direction of [2, 1])
    for (const protocol of [6, 17]) add(1, { direction, protocol, uid });
  return rules;
}
export function assertDarwinPfOwned(read, plan, empty = false) {
  const rules =
    read.graph.find((node) => node.anchor === plan.anchor)?.rules ?? [];
  requireDarwin(
    observationDigest(
      rules.map(({ action, quick, state, call, match }) => ({
        action,
        quick,
        state,
        call,
        match,
      })),
    ) === observationDigest(empty ? [] : darwinPfExpectedRules(plan)) &&
      rules.every((rule) => rule.set === 1),
  );
}
export function assertDarwinPfCounters(rows, read, anchor) {
  const rules = read.graph.find((node) => node.anchor === anchor)?.rules,
    generation = read.kernel.anchors.find((node) => node.anchor === anchor)
      ?.sets[1];
  requireDarwin(
    rules && generation && observationList(rows, 64).length === rules.length,
  );
  for (const [index, row] of rows.entries()) {
    observationObject(row, [
      "purpose",
      "anchor",
      "set",
      "ticket",
      "ruleTicket",
      "index",
      "packets",
      "ruleSha256",
      "action",
    ]);
    requireDarwin(
      row.purpose === "experiment" &&
        row.anchor === anchor &&
        row.set === 1 &&
        row.ticket === generation.ticket &&
        row.ruleTicket === rules[index].ticket &&
        row.index === index &&
        decimal(row.packets) &&
        row.ruleSha256 === digest(Buffer.from(rules[index].raw, "hex")) &&
        row.action === (rules[index].action === 0 ? "permit" : "deny"),
    );
  }
  return rows;
}
