import { createReadStream, createWriteStream } from "node:fs";
import { Duplex } from "node:stream";
import { fileURLToPath } from "node:url";
import { createProtectedRelay, normalizeRelayPolicy } from "./relay.js";
import { serveRelayPipe } from "./bridge.js";
import {
  requireObservation,
  observationObject,
  observationDigest,
} from "../index.js";

/** Dedicated external process. Its private control pipe carries the secret
 * after admission; stdout is exclusively the fixed credential-free exchange. */
export async function runProtectedRelay({ control, exchange }) {
  let relay;
  try {
    const packet = await control();
    observationObject(packet, [
      "admitted",
      "configurationSha256",
      "specificationSha256",
      "policy",
      "credential",
    ]);
    const policy = normalizeRelayPolicy(packet.policy);
    requireObservation(
      packet.admitted === true &&
        /^[a-f0-9]{64}$/u.test(packet.specificationSha256) &&
        packet.configurationSha256 ===
          observationDigest({
            specificationSha256: packet.specificationSha256,
            policy,
          }),
    );
    relay = createProtectedRelay(policy, packet.credential, {
      onFailure: () => exchange.destroy(),
    });
    await serveRelayPipe(exchange, relay);
  } finally {
    relay?.close();
    exchange.destroy();
  }
}

export async function readProtectedControl(pipe) {
  const timer = setTimeout(
    () => pipe.destroy(new Error("Transport admission deadline")),
    30000,
  );
  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of pipe) {
      size += chunk.length;
      requireObservation(size <= 65536);
      chunks.push(chunk);
    }
    requireObservation(size > 0);
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
    );
  } finally {
    clearTimeout(timer);
    pipe.destroy();
  }
}

// Import is effect-free. Only the protected native owner selects this exact
// image/entry and inherited pipe list; no credential comes from argv/env/files.
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
    await runProtectedRelay({
      control: () => readProtectedControl(createReadStream(null, { fd: 3 })),
      exchange,
    });
  } catch {
    process.exitCode = 126;
  }
}
