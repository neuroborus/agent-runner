import assert from "node:assert/strict";
import test from "node:test";
import {
  windowsAccessNetworkEvent,
  windowsAccessWindow,
} from "./access-transport.js";

test("Windows access joins a DROP to the actual held sender/receiver, tuple, principal and native interval", () => {
  const socket = {
      identity: { pid: 41, creationTime: "10", userSid: "S-1-5-21-1-2-3-41" },
      protocol: "udp",
      localAddress: "::1",
      localPort: 41000,
    },
    remote = { address: "::1", port: 41001 },
    filter = {
      id: "7",
      descriptor: {
        layer: "ALE_AUTH_CONNECT_V6",
        action: "BLOCK",
        principal: socket.identity.userSid,
        conditions: { protocol: "udp", localPort: 41000 },
      },
    },
    installation = { effective: { wfp: { filters: [filter] } } },
    native = {
      index: 0,
      time: "20",
      raw: {
        pid: 41,
        filterId: "7",
        opcode: "5157",
        auditFailure: true,
        target: "udp:::1:41000>::1:41001:out",
      },
    },
    interval = windowsAccessWindow(
      { sequence: 1, events: 0, time: "15" },
      { barriers: [{ sequence: 2, events: 1, time: "25" }], events: [native] },
    );
  assert.equal(
    windowsAccessNetworkEvent(interval, installation, "BLOCK", socket, remote)
      .event,
    native,
  );
  for (const change of [
    (value) => {
      value.raw.pid++;
    },
    (value) => {
      value.time = "9";
    },
    (value) => {
      value.raw.filterId = "8";
    },
    (value) => {
      value.raw.target = "udp:::1:41002>::1:41001:out";
    },
    (value) => {
      value.raw.target = "udp:::1:41000>::1:41001:in";
    },
    (value) => {
      value.raw.auditFailure = false;
    },
  ]) {
    const altered = structuredClone(native);
    change(altered);
    assert.throws(() =>
      windowsAccessNetworkEvent(
        [altered],
        installation,
        "BLOCK",
        socket,
        remote,
      ),
    );
  }
  assert.throws(() =>
    windowsAccessNetworkEvent([], installation, "BLOCK", socket, remote),
  );
  assert.throws(() =>
    windowsAccessWindow(
      { sequence: 1, events: 0, time: "15" },
      { barriers: [{ sequence: 3, events: 1, time: "25" }], events: [native] },
    ),
  );
});

test("Windows UDP return proof cannot reuse the receive event as a connect authorization", () => {
  const identity = {
      pid: 42,
      creationTime: "10",
      userSid: "S-1-5-21-1-2-3-42",
    },
    socket = {
      identity,
      protocol: "udp",
      localAddress: "127.0.0.1",
      localPort: 41001,
    },
    remote = { address: "127.0.0.1", port: 41000 },
    installation = {
      effective: {
        wfp: {
          filters: [
            {
              id: "9",
              descriptor: {
                layer: "ALE_AUTH_RECV_ACCEPT_V4",
                action: "PERMIT",
                principal: identity.userSid,
                conditions: {
                  protocol: "udp",
                  localPort: 41001,
                  remotePort: 41000,
                },
              },
            },
          ],
        },
      },
    },
    event = {
      time: "20",
      raw: {
        pid: 42,
        filterId: "9",
        opcode: "5156",
        auditFailure: false,
        target: "udp:127.0.0.1:41000>127.0.0.1:41001:in",
      },
    };
  assert.ok(
    windowsAccessNetworkEvent(
      [event],
      installation,
      "PERMIT",
      socket,
      remote,
      false,
    ),
  );
  assert.throws(() =>
    windowsAccessNetworkEvent(
      [event],
      installation,
      "PERMIT",
      socket,
      remote,
      true,
    ),
  );
});
