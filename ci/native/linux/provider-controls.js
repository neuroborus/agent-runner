import { createServer as httpServer, request } from "node:http";
import { createServer as unixServer, createConnection } from "node:net";
import { once } from "node:events";
import path from "node:path";
import {
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import { digest } from "./inspect.js";
import { sameLinuxData } from "./provider-kernel.js";

/** Credential-free outside controls own actual receiving sockets. Their nonce
 * is read through the stock transport, then joined to a kernel socket identity.
 * A failed request, missing listener or substituted socket cannot prove denial. */
export function createLinuxProviderControls(
  session,
  kernel,
  options = {},
  guard = () => {},
) {
  const sockets = new Map();
  let initialization,
    closed = false,
    closing = false,
    closure;
  const admit = (signal) => {
    guard(signal);
    requireObservation(
      !closed &&
        !closing &&
        !session.retiring &&
        !session.payloadRetired &&
        !session.controlFailure,
    );
  };
  const readNonce = async (file) => {
    const object = session.objects.get(file);
    requireObservation(object);
    return kernel.read(object.held, 8192);
  };
  const initializeOwned = async (signal) => {
    const declarations = session.observationData.outsideControls;
    requireObservation(
      Array.isArray(declarations) &&
        declarations.length <= 32 &&
        new Set(declarations.map((item) => item.selector)).size ===
          declarations.length,
    );
    for (const item of declarations) {
      observationObject(item, ["kind", "selector", "file"]);
      requireObservation(
        ["tcp", "unix"].includes(item.kind) &&
          session.observationData.targets.some(
            (target) =>
              target.selector === item.selector && target.file === item.file,
          ),
      );
      const nonce = await readNonce(item.file);
      let server, address;
      if (item.kind === "tcp") {
        const match = item.selector.match(/^127\.0\.0\.1:([1-9][0-9]{3,4})$/u);
        requireObservation(
          match &&
            Number(match[1]) >= 1024 &&
            Number(match[1]) <= 65535 &&
            "http://" + item.selector !== session.spec.endpoint,
        );
        server = (options.httpServer ?? httpServer)((req, res) => {
          req.resume();
          res.end(nonce);
        });
        address = {
          host: "127.0.0.1",
          port: Number(match[1]),
          exclusive: true,
        };
      } else {
        requireObservation(
          item.selector.startsWith(session.launch.directory + "/") &&
            path.normalize(item.selector) === item.selector &&
            !item.selector.includes("\0"),
        );
        const parent = await kernel.hold(path.dirname(item.selector), {
          directory: true,
          sealed: false,
        });
        try {
          requireObservation(
            parent.identity.uid ===
              String(options.ownerUid ?? process.getuid()),
          );
        } finally {
          await kernel.close(parent);
        }
        server = (options.unixServer ?? unixServer)((socket) => {
          socket.end(nonce);
        });
        address = item.selector;
      }
      await session.persist({
        phase: "linux-provider-outside-control-possible",
        declaration: item,
      });
      admit(signal);
      const startup = Promise.withResolvers();
      sockets.set(item.selector, {
        item,
        server,
        nonce,
        startup: startup.promise,
      });
      server.on("error", (error) => {
        session.controlFailure ??= error;
      });
      const listening = once(server, "listening");
      try {
        server.listen(address);
        await listening;
      } finally {
        startup.resolve();
      }
      admit(signal);
      requireObservation(Number.isInteger(server._handle?.fd));
      const inode = await kernel.fs.readlink(
        `/proc/self/fd/${server._handle.fd}`,
      );
      requireObservation(/^socket:\[[1-9][0-9]*\]$/u.test(inode));
      sockets.get(item.selector).identity = inode;
      sockets.get(item.selector).owner = await kernel.process(
        options.pid ?? process.pid,
      );
      await session.persist({
        phase: "linux-provider-outside-control-held",
        declaration: item,
        inode,
        owner: sockets.get(item.selector).owner,
      });
      await verify(item.selector, signal);
    }
  };
  const initialize = (signal) => {
    admit(signal);
    initialization ??= initializeOwned(signal).catch((error) => {
      session.controlFailure ??= error;
      throw error;
    });
    return initialization;
  };
  const verify = async (selector, signal) => {
    try {
      admit(signal);
      const value = sockets.get(selector);
      requireObservation(value && value.server.listening);
      const inode = await kernel.fs.readlink(
        `/proc/self/fd/${value.server._handle.fd}`,
      );
      requireObservation(inode === value.identity);
      const bytes = await new Promise((resolve, reject) => {
        let client,
          size = 0;
        const chunks = [];
        const receive = (stream) => {
          stream.on("data", (chunk) => {
            size += chunk.length;
            if (size > 8192)
              client.destroy(new Error("Outside control overflow"));
            else chunks.push(chunk);
          });
          stream.once("end", () => resolve(Buffer.concat(chunks)));
          stream.once("error", reject);
        };
        if (value.item.kind === "tcp") {
          client = (options.httpRequest ?? request)(
            "http://" + selector,
            { agent: false },
            (response) => {
              if (response.statusCode !== 200)
                reject(new Error("Outside control status"));
              receive(response);
            },
          );
          client.end();
        } else {
          client = (options.createConnection ?? createConnection)(selector);
          receive(client);
        }
        client.once("error", reject);
        client.setTimeout(5000, () =>
          client.destroy(new Error("Outside control deadline")),
        );
      });
      requireObservation(
        bytes.equals(value.nonce) &&
          (await readNonce(value.item.file)).equals(bytes) &&
          value.server.listening &&
          (await kernel.fs.readlink(
            `/proc/self/fd/${value.server._handle.fd}`,
          )) === inode &&
          sameLinuxData(await kernel.process(value.owner.pid), value.owner),
      );
      admit(signal);
      return {
        selector,
        identity: inode,
        nonceSha256: digest(bytes),
        nativeEventSha256: observationDigest({
          inode,
          bytesSha256: digest(bytes),
        }),
      };
    } catch (error) {
      session.controlFailure ??= error;
      throw error;
    }
  };
  return {
    initialize,
    has: (selector) => sockets.has(selector),
    verify,
    async close() {
      if (closed) return;
      requireObservation(session.payloadRetired);
      closing = true;
      closure ??= (async () => {
        for (const { server, startup } of sockets.values()) {
          await startup;
          if (server.listening)
            await new Promise((resolve, reject) =>
              server.close((error) => (error ? reject(error) : resolve())),
            );
        }
        requireObservation(
          [...sockets.values()].every(({ server }) => !server.listening),
        );
        closed = true;
      })().catch((error) => {
        closure = undefined;
        throw error;
      });
      return closure;
    },
  };
}
