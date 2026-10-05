import { createReadStream, createWriteStream } from "node:fs";
import { Duplex } from "node:stream";
import { fileURLToPath } from "node:url";
import { createProtectedRelay, normalizeRelayPolicy } from "./relay.js";
import { serveRelayPipe } from "./bridge.js";
import { linuxProviderCIContract } from "../linux/index.js";
import { darwinProviderCIContract } from "../darwin/index.js";
import { windowsProviderCIContract } from "../win32/index.js";

import {
  requireObservation,
  observationObject,
  observationDigest,
} from "../index.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const relayOwners = {
  linux: linuxProviderCIContract,
  darwin: darwinProviderCIContract,
  win32: windowsProviderCIContract,
};

/** Consume step-scoped secrets before any subprocess/native module is released.
 * Only an independently verified, admitted private relay control pipe receives
 * a credential. Providers receive their existing non-secret session token. */
export function takeRelayCredentials(env) {
  const credentials = {
    codex: env.NATIVE_CODEX_MODEL_CREDENTIAL,
    claude: env.NATIVE_CLAUDE_MODEL_CREDENTIAL,
  };
  delete env.NATIVE_CODEX_MODEL_CREDENTIAL;
  delete env.NATIVE_CLAUDE_MODEL_CREDENTIAL;
  const delivered = new Set();
  return {
    async deliver(platform, context, receiver, verified, { signal } = {}) {
      const credential = credentials[context.spec.provider];
      requireObservation(
        !signal?.aborted &&
          hash(context.configurationSha256) &&
          hash(context.invocation.specificationSha256) &&
          typeof credential === "string" &&
          credential.length > 0 &&
          credential.length <= 8192 &&
          !/[\x00-\x20\x7f]/u.test(credential) &&
          !delivered.has(context.configurationSha256) &&
          receiver?.role === "relay" &&
          receiver.admitted === true &&
          receiver.receiptVerified === true &&
          receiver.independent === true &&
          receiver.configurationSha256 === context.configurationSha256 &&
          receiver.candidateSha === context.spec.candidateSha &&
          receiver.nonce === context.spec.nonce &&
          verified?.independent === true &&
          verified.configurationSha256 === context.configurationSha256 &&
          verified.candidateSha === context.spec.candidateSha &&
          verified.nonce === context.spec.nonce &&
          verified.privateControl === true &&
          verified.receivingPrincipalVerified === true &&
          verified.providerExcluded === true &&
          verified.bridgeExcluded === true &&
          hash(verified.nativeEventSha256) &&
          hash(verified.controlSha256) &&
          receiver.control?.bindingSha256 === verified.controlSha256 &&
          Object.entries(relayOwners[platform]().relayPrincipal).every(
            ([key, value]) => verified[key] === value,
          ) &&
          typeof receiver.control.end === "function" &&
          typeof receiver.control.once === "function" &&
          typeof receiver.control.destroy === "function",
      );
      delivered.add(context.configurationSha256);
      const packet = Buffer.from(
        JSON.stringify({
          admitted: true,
          configurationSha256: context.configurationSha256,
          specificationSha256: context.invocation.specificationSha256,
          policy: context.policy,
          credential,
        }),
      );
      const abort = () =>
        receiver.control.destroy(new Error("Credential delivery closed"));
      signal?.addEventListener("abort", abort, { once: true });
      try {
        await new Promise((resolve, reject) => {
          receiver.control.once("error", reject);
          receiver.control.end(packet, (error) =>
            error ? reject(error) : resolve(),
          );
        });
      } finally {
        signal?.removeEventListener("abort", abort);
        packet.fill(0);
      }
    },
    close() {
      credentials.codex = null;
      credentials.claude = null;
    },
  };
}

/** Dedicated external process. Its private control pipe carries the secret
 * after admission; stdout is exclusively the fixed credential-free exchange. */
export async function runProtectedRelay({
  control,
  exchange,
  receipt = async () => {},
}) {
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
      onReceipt: receipt,
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
    const receipts = createWriteStream(null, { fd: 4 });
    receipts.on("error", () => exchange.destroy());
    // The independently admitted relay alone receives this metadata pipe.
    // Provider and bridge descriptor allowlists must exclude it.
    try {
      await runProtectedRelay({
        control: () => readProtectedControl(createReadStream(null, { fd: 3 })),
        exchange,
        receipt: (value) =>
          new Promise((resolve, reject) => {
            receipts.write(JSON.stringify(value) + "\n", (error) =>
              error ? reject(error) : resolve(),
            );
          }),
      });
    } finally {
      receipts.destroy();
    }
  } catch {
    process.exitCode = 126;
  }
}
