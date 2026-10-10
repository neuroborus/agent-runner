import { posix as path } from "node:path";
import { digest, normalizeDarwinLaunch, requireDarwin } from "./protocol.js";

export const DARWIN_ACCESS_PROFILES = Object.freeze([
  "read-only",
  "workspace-write",
  "trusted-command",
]);
const inside = (parent, child) => child.startsWith(parent + "/");
export const isDarwinDigest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);

function closed(value, keys) {
  requireDarwin(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
}
function location(value) {
  requireDarwin(
    typeof value === "string" &&
      value.length <= 4096 &&
      !/[\u0000-\u001f\u007f\uD800-\uDFFF]/u.test(value) &&
      value.startsWith("/") &&
      value !== "/" &&
      !value.endsWith("/") &&
      path.normalize(value) === value,
  );
  return value;
}
function endpointScope(entry, keys) {
  const annotated =
    Object.hasOwn(entry, "address") || Object.hasOwn(entry, "owned");
  closed(entry, annotated ? [...keys, "address", "owned"] : keys);
  if (annotated)
    requireDarwin(
      entry.owned === true &&
        entry.address === (entry.family === "inet" ? "127.0.0.1" : "::1"),
    );
}
function list(value, maximum) {
  requireDarwin(
    Array.isArray(value) &&
      Object.getPrototypeOf(value) === Array.prototype &&
      value.length > 0 &&
      value.length <= maximum &&
      Reflect.ownKeys(value).length === value.length + 1,
  );
  return Array.from({ length: value.length }, (_, index) => {
    const field = Object.getOwnPropertyDescriptor(value, index);
    requireDarwin(field?.enumerable && Object.hasOwn(field, "value"));
    return field.value;
  });
}

/** Only exact reviewed images/libraries are exceptions. The manifest digest is
 * an independent input, not approval inferred from generated or observed bytes. */
export function normalizeDarwinPolicy(value) {
  closed(value, [
    "request",
    "profile",
    "disposable",
    "metadata",
    "pointer",
    "checkout",
    "configuration",
    "credentials",
    "runtime",
    "endpoints",
    "reviewSha256",
  ]);
  const request = normalizeDarwinLaunch(value.request);
  for (const name of [
    request.custody,
    request.storage,
    request.workspace,
    request.launcher.path,
    request.executable.path,
    request.policy.path,
  ])
    location(name);
  requireDarwin(
    DARWIN_ACCESS_PROFILES.includes(value.profile) &&
      typeof value.disposable === "boolean" &&
      (value.profile !== "trusted-command" || value.disposable === true) &&
      isDarwinDigest(value.reviewSha256),
  );
  const result = {
    request,
    profile: value.profile,
    disposable: value.disposable,
  };
  for (const key of [
    "metadata",
    "pointer",
    "checkout",
    "configuration",
    "credentials",
  ])
    result[key] = location(value[key]);
  requireDarwin(
    inside(request.storage, result.metadata) &&
      !inside(request.workspace, result.metadata) &&
      !inside(result.metadata, request.workspace) &&
      result.metadata !== request.workspace &&
      result.pointer === request.workspace + "/.git",
  );
  const forbidden = [
    request.custody,
    result.checkout,
    result.configuration,
    result.credentials,
  ];
  requireDarwin(
    forbidden.every(
      (name) =>
        !inside(request.workspace, name) &&
        !inside(name, request.workspace) &&
        name !== request.workspace &&
        !inside(result.metadata, name) &&
        !inside(name, result.metadata) &&
        name !== result.metadata,
    ),
  );
  requireDarwin(new Set(forbidden).size === forbidden.length);
  result.runtime = list(value.runtime, 64)
    .map((entry) => {
      closed(entry, ["path", "sha256", "executable", "mapped"]);
      const name = location(entry.path);
      requireDarwin(
        isDarwinDigest(entry.sha256) &&
          typeof entry.executable === "boolean" &&
          typeof entry.mapped === "boolean" &&
          (!entry.executable || entry.mapped) &&
          (inside(request.storage, name) ||
            name.startsWith("/usr/lib/") ||
            name.startsWith("/System/Library/")) &&
          !inside(request.workspace, name) &&
          name !== request.workspace &&
          ![...forbidden, result.metadata].some(
            (root) => name === root || inside(root, name),
          ) &&
          (!entry.executable || inside(request.storage, name)),
      );
      return {
        path: name,
        sha256: entry.sha256,
        executable: entry.executable,
        mapped: entry.mapped,
      };
    })
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  requireDarwin(
    new Set(result.runtime.map((entry) => entry.path)).size ===
      result.runtime.length &&
      result.runtime.some(
        (entry) =>
          entry.path === request.executable.path &&
          entry.sha256 === request.executable.sha256 &&
          entry.executable,
      ),
  );
  if (request.execution) {
    requireDarwin(request.execution.profile === value.profile);
    const privatePaths = [
      request.execution.environment.HOME,
      request.execution.environment.XDG_CACHE_HOME,
    ].map(location);
    const excluded = [
      ...forbidden,
      request.workspace,
      result.metadata,
      ...result.runtime.map((entry) => entry.path),
    ];
    requireDarwin(
      privatePaths.every(
        (name, index) =>
          inside(request.storage, name) &&
          excluded.every(
            (root) =>
              name !== root && !inside(root, name) && !inside(name, root),
          ) &&
          privatePaths.every(
            (other, j) =>
              index === j || (name !== other && !inside(other, name)),
          ),
      ),
    );
    result.endpoints = list(value.endpoints, 1).map((entry) => {
      endpointScope(entry, ["family", "protocol", "serverPort"]);
      requireDarwin(
        entry.family === "inet" &&
          entry.protocol === "tcp" &&
          entry.serverPort === Number(new URL(request.execution.endpoint).port),
      );
      return {
        family: entry.family,
        protocol: entry.protocol,
        serverPort: entry.serverPort,
        ...(Object.hasOwn(entry, "owned")
          ? { address: entry.address, owned: true }
          : {}),
      };
    });
  } else {
    result.endpoints = list(value.endpoints, 4)
      .map((entry) => {
        endpointScope(entry, [
          "family",
          "protocol",
          "clientPort",
          "serverPort",
        ]);
        requireDarwin(
          ["inet", "inet6"].includes(entry.family) &&
            ["tcp", "udp"].includes(entry.protocol) &&
            [entry.clientPort, entry.serverPort].every(
              (port) =>
                Number.isSafeInteger(port) && port >= 1024 && port <= 65535,
            ),
        );
        return {
          family: entry.family,
          protocol: entry.protocol,
          clientPort: entry.clientPort,
          serverPort: entry.serverPort,
          ...(Object.hasOwn(entry, "owned")
            ? { address: entry.address, owned: true }
            : {}),
        };
      })
      .sort((a, b) =>
        a.family + a.protocol < b.family + b.protocol
          ? -1
          : a.family + a.protocol > b.family + b.protocol
            ? 1
            : 0,
      );
    requireDarwin(
      result.endpoints.length === 4 &&
        new Set(result.endpoints.map((entry) => entry.family + entry.protocol))
          .size === 4 &&
        new Set(
          result.endpoints.flatMap((entry) => [
            entry.clientPort,
            entry.serverPort,
          ]),
        ).size === 8,
    );
  }
  result.reviewSha256 = value.reviewSha256;
  return result;
}

const quote = (value) => JSON.stringify(value);
const literal = (name) => `(literal ${quote(name)})`;
const subtree = (name) => `(subpath ${quote(name)})`;

/** Render a bounded closed policy, never append caller-provided SBPL. Native
 * compilation, operation/filter semantics and the immutable image closure must
 * all be independently reviewed and verified before admission. */
export function buildDarwinPolicy(input) {
  const value = normalizeDarwinPolicy(input),
    { request } = value;
  const forbidden = [
    request.custody,
    value.checkout,
    value.configuration,
    value.credentials,
  ];
  const exclude = forbidden
    .map((name) => `(require-not ${subtree(name)})`)
    .join(" ");
  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process-fork)",
    "(allow process-info* (target same-sandbox))",
  ];
  for (const entry of value.runtime) {
    lines.push(
      `(allow file-read-data file-read-metadata ${literal(entry.path)})`,
    );
    if (entry.mapped)
      lines.push(`(allow file-map-executable ${literal(entry.path)})`);
    if (entry.executable)
      lines.push(`(allow process-exec ${literal(entry.path)})`);
  }
  lines.push(
    `(allow file-read* (require-all ${subtree(request.workspace)} ${exclude}))`,
    `(allow file-read* ${subtree(value.metadata)})`,
    `(allow file-read-metadata ${literal(request.storage)})`,
  );
  if (value.profile !== "read-only")
    lines.push(
      `(allow file-write* (require-all ${subtree(request.workspace)} ${exclude} ` +
        `(require-not ${subtree(value.pointer)}) (require-not ${literal(request.workspace)})))`,
    );
  if (request.execution)
    for (const name of [
      request.execution.environment.HOME,
      request.execution.environment.XDG_CACHE_HOME,
    ])
      lines.push(`(allow file-read* file-write* ${subtree(name)})`);
  // No Mach, Unix socket, POSIX/System V IPC, host process, IOKit, persona,
  // credential, debug, DNS, TLS-service, PTY, or broad loader exceptions.
  for (const entry of value.endpoints) {
    const protocol = entry.protocol === "tcp" ? 6 : 17;
    if (request.execution) {
      lines.push(
        `(allow network-outbound (require-all (remote ip ${quote(`127.0.0.1:${entry.serverPort}`)}) (socket-protocol 6)))`,
      );
      continue;
    }
    for (const port of [entry.clientPort, entry.serverPort]) {
      const endpoint = quote(`localhost:${port}`);
      lines.push(
        `(allow network-bind network-inbound (require-all (local ip ${endpoint}) (socket-protocol ${protocol})))`,
        `(allow network-outbound (require-all (remote ip ${endpoint}) (socket-protocol ${protocol})))`,
      );
    }
  }
  const seatbelt = lines.join("\n") + "\n",
    rules = [];
  for (const entry of value.endpoints) {
    const address = entry.family === "inet" ? "127.0.0.1" : "::1";
    if (request.execution) {
      // The provider uses an ephemeral source port; the exclusive receiving
      // socket belongs to separately admitted root broker custody. Both local
      // socket owners must be resolved, including the reversed return leg.
      for (const [direction, uid, source, destination] of [
        ["out", request.uid, "", ` port ${entry.serverPort}`],
        ["in", 0, "", ` port ${entry.serverPort}`],
        ["out", 0, ` port ${entry.serverPort}`, ""],
        ["in", request.uid, ` port ${entry.serverPort}`, ""],
      ])
        rules.push(
          `pass ${direction} quick on lo0 inet proto tcp from ${address}${source} to ${address}${destination} user = ${uid} flags any no state`,
        );
      rules.push(
        `block return quick inet proto tcp from any to ${address} port ${entry.serverPort}`,
        `block return quick inet proto tcp from ${address} port ${entry.serverPort} to any`,
      );
      continue;
    }
    for (const [source, destination] of [
      [entry.clientPort, entry.serverPort],
      [entry.serverPort, entry.clientPort],
    ])
      for (const direction of ["out", "in"])
        rules.push(
          `pass ${direction} quick on lo0 ${entry.family} proto ${entry.protocol} ` +
            `from ${address} port ${source} to ${address} port ${destination} user = ${request.uid} ` +
            `${entry.protocol === "tcp" ? "flags any " : ""}no state`,
        );
    for (const port of [entry.clientPort, entry.serverPort]) {
      // These scoped blocks also catch unknown owners; no uid inequality grants.
      rules.push(
        `block return quick ${entry.family} proto ${entry.protocol} from any to ${address} port ${port}`,
        `block return quick ${entry.family} proto ${entry.protocol} from ${address} port ${port} to any`,
      );
    }
  }
  for (const direction of ["out", "in"])
    rules.push(
      `block return ${direction} quick proto { tcp udp } from any to any user = ${request.uid}`,
    );
  const pf = rules.join("\n") + "\n";
  // Exclude the two generated digests, preventing a circular policy binding.
  const { policy, bindings, ...allocation } = request;
  const composition = {
    ...value,
    request: {
      ...allocation,
      policy: { path: policy.path },
      bindings: {
        system: bindings.system,
        source: bindings.source,
        closure: bindings.closure,
      },
    },
    seatbelt,
    pf,
  };
  return {
    value,
    seatbelt,
    pf,
    anchor: `native-poc/${request.nonce}`,
    seatbeltSha256: digest(seatbelt),
    pfSha256: digest(pf),
    compositionSha256: digest(JSON.stringify(composition)),
  };
}

/** Fixed anchor-only vectors. Root rules, PF activation, global flushes and
 * exemption removal belong to separately reviewed external setup, never here. */
export function darwinPfctlArguments(input, operation) {
  const plan = buildDarwinPolicy(input);
  requireDarwin(
    ["validate", "validate-restore", "install", "restore"].includes(operation),
  );
  const file =
    plan.value.request.custody +
    (operation.includes("restore")
      ? "/darwin-pf-before.conf"
      : "/darwin-pf.conf");
  return [
    "-a",
    plan.anchor,
    ...(operation.startsWith("validate") ? ["-n"] : []),
    "-f",
    file,
  ];
}
