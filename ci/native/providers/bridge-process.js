import { createServer } from "node:http";
import { createReadStream, createWriteStream } from "node:fs";
import { Duplex } from "node:stream";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { createPipeExchange, serveCredentialFreeBroker } from "./bridge.js";
import { readProtectedControl } from "./relay-process.js";
import { requireObservation, observationObject } from "../index.js";

/** An admitted credential-free process binds only its reviewed IPv4 endpoint.
 * The native owner then independently verifies that held receiving socket
 * before controls or provider release. No packet can select another upstream. */
export async function runCredentialFreeBridge({
  control,
  exchange,
  ready,
  server = createServer(),
}) {
  let broker, lifetime;
  const failure = () => {
    broker?.close();
    exchange.destroy();
    server.close();
  };
  try {
    const packet = await control();
    observationObject(packet, [
      "admitted",
      "endpoint",
      "nonce",
      "configurationSha256",
    ]);
    requireObservation(
      packet.admitted === true &&
        /^[a-f0-9]{32}$/u.test(packet.nonce) &&
        /^[a-f0-9]{64}$/u.test(packet.configurationSha256) &&
        /^http:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/u.test(packet.endpoint),
    );
    const url = new URL(packet.endpoint);
    requireObservation(
      url.origin === packet.endpoint &&
        Number(url.port) >= 1024 &&
        Number(url.port) <= 65535,
    );
    const deadline = new Promise((_, reject) => {
      lifetime = setTimeout(() => {
        failure();
        reject(new Error("Provider transport closed"));
      }, 120000);
    });
    deadline.catch(() => {});
    server.listen({
      host: "127.0.0.1",
      port: Number(url.port),
      exclusive: true,
    });
    await Promise.race([once(server, "listening"), deadline]);
    broker = serveCredentialFreeBroker(server, createPipeExchange(exchange), {
      onFailure: failure,
    });
    const settled = once(server, "close");
    settled.catch(() => {});
    exchange.once("close", () => broker.close());
    requireObservation(!exchange.destroyed);
    await Promise.race([
      ready({
        nonce: packet.nonce,
        configurationSha256: packet.configurationSha256,
        endpoint: packet.endpoint,
      }),
      settled.then(() => {
        throw new Error("Provider transport closed");
      }),
      deadline,
    ]);
    await Promise.race([settled, deadline]);
  } finally {
    clearTimeout(lifetime);
    failure();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    requireObservation(
      process.argv.length === 2 &&
        process.env.CI === "true" &&
        process.env.GITHUB_ACTIONS === "true",
    );
    const exchange = Duplex.from({
      readable: createReadStream(null, { fd: 0, autoClose: false }),
      writable: createWriteStream(null, { fd: 1, autoClose: false }),
    });
    const report = createWriteStream(null, { fd: 4 });
    report.on("error", () => exchange.destroy());
    try {
      await runCredentialFreeBridge({
        control: () => readProtectedControl(createReadStream(null, { fd: 3 })),
        exchange,
        ready: (value) =>
          new Promise((resolve, reject) =>
            report.end(JSON.stringify(value) + "\n", (error) =>
              error ? reject(error) : resolve(),
            ),
          ),
      });
    } finally {
      report.destroy();
    }
  } catch {
    process.exitCode = 126;
  }
}
