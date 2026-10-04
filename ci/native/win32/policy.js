import {
  closed,
  dense,
  digest,
  hash,
  requireWindows,
  sid,
  normalizeWindowsLaunch,
  windowsPrivatePath,
  WINDOWS_SYSTEM_SID,
} from "./protocol.js";

export const WINDOWS_AUTHORITY_PROFILES = Object.freeze([
  "read-only",
  "workspace-write",
  "trusted-command",
]);
export const WINDOWS_ALE_LAYERS = Object.freeze([
  "ALE_AUTH_CONNECT_V4",
  "ALE_AUTH_CONNECT_V6",
  "ALE_AUTH_RECV_ACCEPT_V4",
  "ALE_AUTH_RECV_ACCEPT_V6",
]);
const within = (parent, child) =>
  child.toLowerCase().startsWith(parent.toLowerCase() + "\\");
const same = (a, b) => a.toLowerCase() === b.toLowerCase();
const order = (left, right) => (left === right ? 0 : left < right ? -1 : 1);
const guid = (nonce, number) => {
  const bytes = digest("windows-policy:" + nonce + ":" + number).slice(0, 32);
  return [
    bytes.slice(0, 8),
    bytes.slice(8, 12),
    bytes.slice(12, 16),
    bytes.slice(16, 20),
    bytes.slice(20),
  ].join("-");
};

/** Only the private fixture tree is grantable. Loader exceptions are individual
 * immutable files; no System32, registry, host pipe or ambient service grant. */
export function normalizeWindowsPolicy(input) {
  closed(input, [
    "request",
    "accountSid",
    "profile",
    "disposable",
    "runtime",
    "endpoints",
    "reviewSha256",
  ]);
  const request = normalizeWindowsLaunch(input.request);
  const accountSid = sid(input.accountSid);
  requireWindows(
    /^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$/u.test(accountSid) &&
      accountSid !== request.restrictingSid &&
      WINDOWS_AUTHORITY_PROFILES.includes(input.profile) &&
      typeof input.disposable === "boolean" &&
      (input.profile !== "trusted-command" || input.disposable) &&
      hash(input.reviewSha256),
  );
  const runtime = dense(input.runtime, 32)
    .map((entry) => {
      closed(entry, ["path", "sha256", "reviewSha256"]);
      const path = windowsPrivatePath(entry.path);
      requireWindows(
        within(request.storage, path) &&
          !within(request.workspace, path) &&
          !same(request.workspace, path) &&
          /\.(?:dll|exe)$/iu.test(path) &&
          hash(entry.sha256) &&
          hash(entry.reviewSha256),
      );
      return { path, sha256: entry.sha256, reviewSha256: entry.reviewSha256 };
    })
    .sort((a, b) => order(a.path, b.path));
  requireWindows(
    runtime.length > 0 &&
      new Set(runtime.map((entry) => entry.path.toLowerCase())).size ===
        runtime.length &&
      runtime.some(
        (entry) =>
          same(entry.path, request.executable.path) &&
          entry.sha256 === request.executable.sha256,
      ),
  );
  let endpoints;
  if (request.execution) {
    requireWindows(request.execution.profile === input.profile);
    const home = windowsPrivatePath(request.execution.environment.HOME),
      cache = windowsPrivatePath(request.execution.environment.XDG_CACHE_HOME);
    requireWindows(
      same(home, request.storage + "\\provider-home") &&
        same(cache, request.storage + "\\provider-cache") &&
        runtime.every(
          (entry) =>
            ![home, cache].some(
              (root) => same(root, entry.path) || within(root, entry.path),
            ),
        ),
    );
    endpoints = dense(input.endpoints, 1).map((entry) => {
      closed(entry, ["family", "protocol", "serverPort"]);
      requireWindows(
        entry.family === "v4" &&
          entry.protocol === "tcp" &&
          entry.serverPort === Number(new URL(request.execution.endpoint).port),
      );
      return { ...entry };
    });
    requireWindows(endpoints.length === 1);
  } else {
    endpoints = dense(input.endpoints, 4)
      .map((entry) => {
        closed(entry, ["family", "protocol", "clientPort", "serverPort"]);
        requireWindows(
          ["v4", "v6"].includes(entry.family) &&
            ["tcp", "udp"].includes(entry.protocol) &&
            [entry.clientPort, entry.serverPort].every(
              (port) => Number.isInteger(port) && port >= 1024 && port <= 65535,
            ),
        );
        return {
          family: entry.family,
          protocol: entry.protocol,
          clientPort: entry.clientPort,
          serverPort: entry.serverPort,
        };
      })
      .sort((a, b) => order(a.family + a.protocol, b.family + b.protocol));
    requireWindows(
      endpoints.length === 4 &&
        new Set(endpoints.map((entry) => entry.family + entry.protocol))
          .size === 4 &&
        new Set(
          endpoints.flatMap((entry) => [entry.clientPort, entry.serverPort]),
        ).size === 8,
    );
  }
  return {
    request,
    accountSid,
    profile: input.profile,
    disposable: input.disposable,
    runtime,
    endpoints,
    reviewSha256: input.reviewSha256,
  };
}

export function buildWindowsPolicy(input) {
  const value = normalizeWindowsPolicy(input),
    { request, accountSid } = value;
  const writable = value.profile !== "read-only";
  const acl = (name, path, grant) => ({
    name,
    path,
    ownerSid: WINDOWS_SYSTEM_SID,
    protectedDacl: true,
    grant,
    accountSid,
    restrictingSid: request.restrictingSid,
  });
  const objects = [
    acl("custody", request.custody, "system"),
    acl("storage", request.storage, "traverse"),
    acl("workspace", request.workspace, writable ? "workspace" : "read-tree"),
    acl("owned", request.workspace + "\\owned.txt", writable ? "edit" : "read"),
    acl("pointer", request.workspace + "\\.git", "read"),
    ...["metadata", "checkout", "configuration", "credentials"].map((name) =>
      acl(name, request.storage + "\\" + name, "system"),
    ),
    acl("outside", request.custody + "\\outside-sentinel", "system"),
    acl("registry", "HKLM\\SOFTWARE\\NativeProof\\" + request.nonce, "system"),
    ...(request.execution
      ? [
          acl(
            "provider-home",
            request.execution.environment.HOME,
            "private-tree",
          ),
          acl(
            "provider-cache",
            request.execution.environment.XDG_CACHE_HOME,
            "private-tree",
          ),
        ]
      : []),
    ...value.runtime.map((entry, index) => ({
      ...acl("runtime-" + index, entry.path, "execute"),
      sha256: entry.sha256,
    })),
  ];
  requireWindows(
    new Set(objects.map((entry) => entry.path.toLowerCase())).size ===
      objects.length,
  );
  // Two local ALE checks establish the sending and receiving socket principals.
  // Global reserved-port guards prevent a foreign socket from using either end.
  // Exact reversed tuples cover the return leg too. No blanket loopback permit.
  const filters = [];
  const add = (layer, action, weight, principal, conditions, purpose) =>
    filters.push({
      key: guid(request.nonce, filters.length + 2),
      layer,
      action,
      weight,
      principal,
      conditions,
      purpose,
      persistent: true,
      clearActionRight: true,
    });
  for (const layer of WINDOWS_ALE_LAYERS) {
    const family = layer.endsWith("V4") ? "v4" : "v6",
      address = family === "v4" ? "127.0.0.1" : "::1";
    add(layer, "BLOCK", 10, accountSid, {}, "account-default");
    for (const endpoint of value.endpoints.filter(
      (entry) => entry.family === family,
    )) {
      if (request.execution) {
        for (const side of ["local", "remote"])
          add(
            layer,
            "BLOCK",
            50,
            null,
            {
              protocol: "tcp",
              [side + "Address"]: address,
              [side + "Port"]: endpoint.serverPort,
            },
            "reserved-broker",
          );
        add(
          layer,
          "PERMIT",
          100,
          accountSid,
          {
            protocol: "tcp",
            localAddress: address,
            remoteAddress: address,
            remotePort: endpoint.serverPort,
          },
          "provider-broker",
        );
        add(
          layer,
          "PERMIT",
          100,
          WINDOWS_SYSTEM_SID,
          {
            protocol: "tcp",
            localAddress: address,
            remoteAddress: address,
            localPort: endpoint.serverPort,
          },
          "broker-provider",
        );
        continue;
      }
      for (const port of [endpoint.clientPort, endpoint.serverPort])
        for (const side of ["local", "remote"])
          add(
            layer,
            "BLOCK",
            50,
            null,
            {
              protocol: endpoint.protocol,
              [side + "Address"]: address,
              [side + "Port"]: port,
            },
            "reserved-endpoint",
          );
      for (const [localPort, remotePort] of [
        [endpoint.clientPort, endpoint.serverPort],
        [endpoint.serverPort, endpoint.clientPort],
      ])
        add(
          layer,
          "PERMIT",
          100,
          accountSid,
          {
            protocol: endpoint.protocol,
            localAddress: address,
            remoteAddress: address,
            localPort,
            remotePort,
          },
          "private-tuple",
        );
    }
  }
  const manifest = {
    schemaVersion: request.execution ? 2 : 1,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    accountSid,
    restrictingSid: request.restrictingSid,
    profile: value.profile,
    disposable: value.disposable,
    providerKey: guid(request.nonce, 0),
    sublayerKey: guid(request.nonce, 1),
    sublayerWeight: 65535,
    channels: request.execution
      ? ["stdin-read", "stdout-write", "stderr-write"]
      : ["stdin-read", "stdout-stderr-write"],
    objects,
    runtime: value.runtime,
    endpoints: value.endpoints,
    filters,
    reviewSha256: value.reviewSha256,
    systemSha256: request.bindings.system,
    sourceSha256: request.bindings.source,
    closureSha256: request.bindings.closure,
  };
  const bytes = JSON.stringify(manifest) + "\n";
  const policySha256 = digest(bytes);
  const compositionSha256 = digest(
    JSON.stringify({
      policySha256,
      helper: request.execution ? "windows-policy-v2" : "windows-policy-v1",
      reviewSha256: value.reviewSha256,
    }),
  );
  return { value, manifest, bytes, policySha256, compositionSha256 };
}

export function assertWindowsPolicyToken(token, input) {
  const { request, accountSid } = normalizeWindowsPolicy(input);
  closed(token, [
    "userSid",
    "restrictedSids",
    "privileges",
    "enabledGroups",
    "integritySid",
    "sessionId",
    "tokenId",
    "authenticationId",
    "primary",
    "virtualized",
    "writeRestricted",
  ]);
  requireWindows(
    token.userSid === accountSid &&
      JSON.stringify(dense(token.restrictedSids, 8)) ===
        JSON.stringify([request.restrictingSid]) &&
      dense(token.privileges, 64).length === 0 &&
      dense(token.enabledGroups, 128).length === 0 &&
      token.integritySid === "S-1-16-4096" &&
      token.sessionId === 0 &&
      token.primary === true &&
      token.virtualized === false &&
      token.writeRestricted === false &&
      [token.tokenId, token.authenticationId].every(
        (id) => typeof id === "string" && /^[0-9a-f]{16}$/u.test(id),
      ),
  );
}

/** Only the protected bridge supplies these already held, verified objects.
 * Native mutation still waits for its independent before-write acknowledgement. */
export function windowsPolicyHelperArguments(input, operation, handles) {
  const plan = buildWindowsPolicy(input);
  requireWindows(["install", "remove"].includes(operation));
  const objects = plan.manifest.objects.filter(
    (entry) => entry.name !== "registry",
  );
  const values = dense(handles, 44);
  requireWindows(values.length === objects.length);
  values.forEach((entry, index) => {
    closed(entry, ["path", "handle"]);
    requireWindows(
      same(entry.path, objects[index].path) &&
        typeof entry.handle === "string" &&
        /^[1-9][0-9]{0,19}$/u.test(entry.handle) &&
        BigInt(entry.handle) <= 0xffffffffffffffffn,
    );
  });
  return [
    plan.value.request.nonce,
    plan.value.accountSid,
    plan.value.request.restrictingSid,
    plan.value.profile,
    operation + (plan.value.request.execution ? "-provider" : ""),
    ...plan.value.endpoints.flatMap((entry) =>
      plan.value.request.execution
        ? [String(entry.serverPort)]
        : [String(entry.clientPort), String(entry.serverPort)],
    ),
    ...values.map((entry) => entry.handle),
  ];
}
