import { observationDigest, requireObservation } from "../index.js";
import { sameWindowsIdentity } from "./protocol.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const proof = (value, nonce, observations) => ({
  independent: true,
  verifier: value.verifier,
  nonce,
  timedOut: false,
  lossCount: 0,
  identityVerified: true,
  nativeEventSha256: observationDigest(observations),
});
const state = (control) => ({
  identitySha256: control.targetIdentitySha256,
  bytesSha256: observationDigest({
    target: control.target,
    endpoint: control.endpoint,
    denialCode: control.denialCode,
  }),
  nativeEventSha256: control.nativeEventSha256,
});
export function windowsAccessWindow(before, after) {
  const last = after.barriers.at(-1);
  requireObservation(last.sequence === before.sequence + 1);
  return after.events.filter(
    (event) =>
      event.index >= before.events &&
      event.index < last.events &&
      BigInt(event.time) >= BigInt(before.time) &&
      BigInt(event.time) <= BigInt(last.time),
  );
}
export function windowsAccessNetworkEvent(
  events,
  installation,
  action,
  socket,
  remote,
  direction,
) {
  for (const event of events) {
    const raw = event.raw,
      filter = installation.effective.wfp.filters.find(
        ({ id }) => id === raw.filterId,
      ),
      parts = /^(tcp|udp):(.+):([0-9]+)>(.+):([0-9]+):(in|out)$/u.exec(
        raw.target,
      );
    if (
      !filter ||
      !parts ||
      raw.pid !== socket.identity.pid ||
      BigInt(event.time) < BigInt(socket.identity.creationTime) ||
      (action === "PERMIT"
        ? raw.opcode !== "5156" || raw.auditFailure
        : !["5152", "5157"].includes(raw.opcode) || !raw.auditFailure)
    )
      continue;
    const connect = filter.descriptor.layer.includes("CONNECT"),
      tuple = {
        protocol: parts[1],
        localAddress: connect ? parts[2] : parts[4],
        localPort: Number(connect ? parts[3] : parts[5]),
        remoteAddress: connect ? parts[4] : parts[2],
        remotePort: Number(connect ? parts[5] : parts[3]),
      };
    if (
      (direction !== undefined && connect !== direction) ||
      filter.descriptor.action !== action ||
      connect !== (parts[6] === "out") ||
      tuple.protocol !== socket.protocol ||
      tuple.localAddress !== socket.localAddress ||
      tuple.localPort !== socket.localPort ||
      tuple.remoteAddress !== remote.address ||
      tuple.remotePort !== remote.port ||
      (filter.descriptor.principal !== null &&
        filter.descriptor.principal !== socket.identity.userSid) ||
      !Object.entries(filter.descriptor.conditions).every(
        ([key, value]) => tuple[key] === value,
      )
    )
      continue;
    return { event, filter, tuple };
  }
  throw new Error("Missing independently joined Windows access event");
}

/** Fixed IPC and network attempts consume raw frames and independently retained
 * socket reads. Error codes acknowledge an attempt; the separate reader and
 * Security/BFE interval must establish its denial. */
export async function observeWindowsAccessDenial(reader, id, session) {
  const { input, payload, payloadSlot, capture, installation, control } =
      session,
    nonce = input.request.nonce,
    network = control.endpoint !== null,
    foreign = id.startsWith("foreign-sender-"),
    before = state(control);
  await session.persist({
    phase: "access-attempt-possible",
    id,
    controlSha256: observationDigest(control),
  });
  let ready, result, socketProof, start;
  if (network) {
    const endpoint = control.endpoint,
      local = endpoint.address,
      args = [
        endpoint.protocol === "tcp" ? "deny-tcp" : "deny-udp",
        endpoint.family,
        endpoint.protocol,
        "0",
        String(endpoint.port),
        endpoint.address,
        local,
        String(control.verifier.pid),
      ];
    if (foreign) {
      start = (await capture.barrier()).barriers.at(-1);
      result = await reader.accessForeign(id);
      socketProof = await reader.accessSocket(result);
    } else {
      await reader.sendAccessCommand("network", args);
      ready = JSON.parse(await reader.ownershipOutput());
      requireObservation(
        ready.nonce === nonce &&
          ready.operation === "network" &&
          ready.phase === "ready",
      );
      socketProof = await reader.accessSocket({
        identity: payload,
        handle: ready.handle,
        hex: ready.hex,
      });
      start = (await capture.barrier()).barriers.at(-1);
      await reader.sendOwnership("A");
      result = JSON.parse(await reader.ownershipOutput());
      requireObservation(
        result.nonce === nonce &&
          result.operation === "network" &&
          result.phase === "initiated",
      );
    }
    const events = windowsAccessWindow(start, await capture.barrier()),
      socket = socketProof.actual,
      endpointSocket = {
        identity: endpoint.identity,
        protocol: endpoint.protocol,
        socketIdentitySha256: endpoint.socketIdentitySha256,
        localAddress: endpoint.address,
        localPort: endpoint.port,
      };
    requireObservation(
      sameWindowsIdentity(
        socket.identity,
        foreign ? result.identity : payload,
      ) &&
        socket.localAddress === local &&
        [0, 10013, 10035].includes(result.nativeCode),
    );
    let joined, filtered;
    try {
      joined = windowsAccessNetworkEvent(
        events,
        installation,
        "BLOCK",
        socket,
        { address: endpoint.address, port: endpoint.port },
      );
      filtered = socket;
    } catch {
      joined = windowsAccessNetworkEvent(
        events,
        installation,
        "BLOCK",
        endpointSocket,
        { address: socket.localAddress, port: socket.localPort },
      );
      filtered = endpointSocket;
    }
    const afterControl = await reader.accessControl(id, payloadSlot);
    requireObservation(same(before, state(afterControl)));
    // Finish only after a correlated native DROP. A pending connect, successful
    // UDP send, fixture error or elapsed deadline cannot supply this evidence.
    if (foreign) await reader.closeAccessForeign();
    else await reader.sendOwnership("D");
    return {
      ...proof(socketProof, nonce, {
        socketProof,
        joined,
        before,
        afterControl,
      }),
      caseId: id,
      identity: socket.identity,
      protectedIdentity: foreign ? endpoint.identity : undefined,
      attempted: true,
      allowed: false,
      nativeCode: result.nativeCode,
      before,
      after: state(afterControl),
      control: { ...control, readyBeforeAttempt: true },
      attempt: {
        ...proof(socketProof, nonce, socketProof),
        ...socket,
        remoteAddress: endpoint.address,
        remotePort: endpoint.port,
      },
      filterId: joined.filter.id,
      filterIdentity: filtered.identity,
      localPrincipalSid: filtered.identity.userSid,
      wfpAction: "DROP",
      layer: joined.filter.descriptor.layer,
      ...joined.tuple,
      socketIdentityVerified: true,
      socketIdentitySha256: filtered.socketIdentitySha256,
    };
  }
  await reader.sendAccessCommand(id, [control.target]);
  ready = JSON.parse(await reader.ownershipOutput());
  requireObservation(
    ready.nonce === nonce && ready.operation === id && ready.phase === "ready",
  );
  start = (await capture.barrier()).barriers.at(-1);
  await reader.sendOwnership("A");
  result = JSON.parse(await reader.ownershipOutput());
  requireObservation(
    result.nonce === nonce &&
      result.operation === id &&
      result.phase === "attempted" &&
      result.allowed === false &&
      result.nativeCode === control.denialCode &&
      control.denialCode !== 0,
  );
  const events = windowsAccessWindow(start, await capture.barrier()),
    afterControl = await reader.accessControl(id, payloadSlot);
  requireObservation(same(before, state(afterControl)));
  return {
    ...proof(control, nonce, { result, control, afterControl, events }),
    caseId: id,
    identity: payload,
    attempted: true,
    allowed: false,
    nativeCode: result.nativeCode,
    before,
    after: state(afterControl),
    control: { ...control, readyBeforeAttempt: true },
  };
}

export async function observeWindowsAccessLoopback(reader, endpoint, session) {
  const { input, capture, installation, peers } = session,
    nonce = input.request.nonce,
    index = input.endpoints.findIndex((entry) => same(entry, endpoint));
  requireObservation(index >= 0);
  const client = await reader.accessReservation(index * 2),
    listener = await reader.accessReservation(index * 2 + 1);
  requireObservation(
    sameWindowsIdentity(listener.actual.identity, peers.privatePeer),
  );
  await session.persist({
    phase: "access-private-pair-possible",
    endpoint,
    client: client.nativeEventSha256,
    listener: listener.nativeEventSha256,
  });
  await reader.sendAccessCommand("pair", [String(index)]);
  const ready = JSON.parse(await reader.ownershipOutput());
  requireObservation(
    ready.nonce === nonce &&
      ready.operation === "pair" &&
      ready.phase === "ready",
  );
  const before = (await capture.barrier()).barriers.at(-1);
  await reader.sendOwnership("A");
  const result = JSON.parse(await reader.ownershipOutput());
  requireObservation(
    result.nonce === nonce &&
      result.operation === "pair" &&
      result.phase === "attempted" &&
      result.index === index &&
      result.allowed &&
      result.bytes === nonce &&
      result.echo === nonce,
  );
  const peer = await reader.accessPeerResult(index, peers.privatePeer),
    liveClient = await reader.accessReservation(index * 2),
    server = peer.proof,
    events = windowsAccessWindow(before, await capture.barrier()),
    remote = (socket) => ({
      address: socket.localAddress,
      port: socket.localPort,
    });
  requireObservation(
    liveClient.actual.localPort === endpoint.clientPort &&
      server.actual.localPort === endpoint.serverPort &&
      (endpoint.protocol !== "tcp" ||
        (same(liveClient.actual.remote, remote(server.actual)) &&
          same(server.actual.remote, remote(liveClient.actual)))),
  );
  const requestConnect = windowsAccessNetworkEvent(
      events,
      installation,
      "PERMIT",
      liveClient.actual,
      remote(server.actual),
      true,
    ),
    requestReceive = windowsAccessNetworkEvent(
      events,
      installation,
      "PERMIT",
      server.actual,
      remote(liveClient.actual),
      false,
    ),
    flowIdentitySha256 = observationDigest({
      client: liveClient.actual,
      server: server.actual,
      requestConnect,
      requestReceive,
    }),
    restrictedSids = [input.request.restrictingSid];
  const event = (joined, side, leg, direction, flowReturn = false) => ({
    ...proof(side, nonce, joined),
    identity: side.actual.identity,
    leg,
    direction,
    action: "PERMIT",
    localPrincipalSid: input.accountSid,
    filterId: joined.filter.id,
    layer: joined.filter.descriptor.layer,
    ...joined.tuple,
    socketIdentityVerified: true,
    socketIdentitySha256: side.actual.socketIdentitySha256,
    restrictedSids,
    authorization: flowReturn ? "verified-flow" : "ale",
    flowAuthorizationVerified: flowReturn,
    flowIdentitySha256,
  });
  const returnConnect =
      endpoint.protocol === "tcp"
        ? requestReceive
        : windowsAccessNetworkEvent(
            events,
            installation,
            "PERMIT",
            server.actual,
            remote(liveClient.actual),
            true,
          ),
    returnReceive =
      endpoint.protocol === "tcp"
        ? requestConnect
        : windowsAccessNetworkEvent(
            events,
            installation,
            "PERMIT",
            liveClient.actual,
            remote(server.actual),
            false,
          );
  const reservation = installation.effective.endpoints[index];
  const side = (value, name) => ({
    identity: value.actual.identity,
    heldIdentityVerified: true,
    reservationIdentitySha256: reservation[name].reservationIdentitySha256,
    socketIdentitySha256: value.actual.socketIdentitySha256,
    userSid: value.actual.identity.userSid,
    restrictedSids,
  });
  return {
    ...proof(client, nonce, { result, peer, liveClient, events }),
    family: endpoint.family,
    protocol: endpoint.protocol,
    bytes: nonce,
    echo: nonce,
    readyBeforeAttempt: true,
    client: side(liveClient, "client"),
    server: side(server, "server"),
    events: [
      event(requestConnect, liveClient, "request", "connect"),
      event(requestReceive, server, "request", "receive"),
      event(
        returnConnect,
        server,
        "return",
        "connect",
        endpoint.protocol === "tcp",
      ),
      event(
        returnReceive,
        liveClient,
        "return",
        "receive",
        endpoint.protocol === "tcp",
      ),
    ],
  };
}
