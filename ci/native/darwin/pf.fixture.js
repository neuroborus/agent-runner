import { createHash } from "node:crypto";

/** Synthetic complete kernel transcript, with independent fault mutation left
 * to each regression. Never queries or changes a host. */
export function kernelPfFixture(value) {
  const read = structuredClone(value);
  read.purpose = "experiment";
  for (const node of [...read.graph]) {
    let name = node.anchor;
    while (name.includes("/")) {
      name = name.slice(0, name.lastIndexOf("/"));
      if (!read.graph.some((entry) => entry.anchor === name))
        read.graph.push({ anchor: name, rules: [] });
    }
  }
  for (const node of read.graph) {
    const indices = [0, 0, 0, 0, 0, 0];
    for (const rule of node.rules)
      Object.assign(rule, {
        index: indices[rule.set]++,
        ticket: rule.ticket ?? "1",
        match: rule.match ?? {
          direction: 0,
          interface: "",
          family: "any",
          protocol: 0,
          source: "any",
          destination: "any",
          sourcePort: null,
          destinationPort: null,
          uid: null,
          returns: rule.action === 1,
        },
      });
  }
  read.interfaces = read.interfaces.map((item) => ({
    ...item,
    flags: item.skip ? 0x100 : 0,
  }));
  read.kernel = {
    states: { bytes: 0, sha256: createHash("sha256").update("").digest("hex") },
    anchors: read.graph.map((node) => ({
      anchor: node.anchor,
      sets: Array.from({ length: 6 }, (_, set) => ({
        ticket: 1,
        count: node.rules.filter((rule) => rule.set === set).length,
      })),
      children: read.graph
        .filter(
          (entry) =>
            entry.anchor &&
            (entry.anchor.includes("/")
              ? entry.anchor.slice(0, entry.anchor.lastIndexOf("/"))
              : "") === node.anchor,
        )
        .map((entry) => entry.anchor.slice(entry.anchor.lastIndexOf("/") + 1))
        .sort(),
    })),
  };
  return read;
}

/** A disabled stock-style graph, including unrelated private child policy. */
export function stockPfFixture(value) {
  const read = structuredClone(value),
    root = read.graph.find((node) => node.anchor === "");
  if (!root.rules.some((rule) => rule.call === "com.apple/*")) {
    root.rules.push(
      ...[2, 0, 4, 6, 8, 11].map((action, set) => ({
        set,
        action,
        quick: false,
        state: 0,
        call: "com.apple/*",
        raw: (0xa0 + set).toString(16),
        ticket: String(10 + set),
      })),
    );
    root.rules.sort((a, b) => a.set - b.set);
    read.graph.push(
      { anchor: "com.apple", rules: [] },
      {
        anchor: "com.apple/stock",
        rules: [
          {
            set: 1,
            action: 0,
            quick: true,
            state: 0,
            call: "",
            raw: "b0",
            ticket: "20",
          },
        ],
      },
    );
  }
  return kernelPfFixture(read);
}
