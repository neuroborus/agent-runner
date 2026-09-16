import { createHash, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { constants } from "node:fs";
import { link, lstat, open, unlink } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { checkServerIdentity, rootCertificates } from "node:tls";

import { normalizeArtifacts } from "./artifact-contract.js";
import { publicAddress } from "./public-address.js";

export const ACQUISITION_LIMITS = Object.freeze({
  fileBytes: 64 * 1024 * 1024,
  totalBytes: 256 * 1024 * 1024,
  dnsMs: 5_000,
  connectionMs: 10_000,
  bodyMs: 15_000,
  overallMs: 300_000,
  retirementMs: 1_000,
});

function failure(kind) {
  return Object.assign(
    new Error(`Pinned dependency acquisition failed (${kind}).`),
    {
      code: `ERR_TRUSTED_ACQUISITION_${kind}`,
    },
  );
}

function scheduleTimeout(callback, milliseconds) {
  const timer = setTimeout(callback, milliseconds);
  return () => clearTimeout(timer);
}

async function ownedFileEntry(path, file) {
  const identity = await file.stat({ bigint: true });
  const entry = await lstat(path, { bigint: true });
  if (
    !entry.isFile() ||
    entry.dev !== identity.dev ||
    entry.ino !== identity.ino
  )
    throw failure("STORAGE");
  return entry;
}

async function lookupAddresses(hostname, { signal, timeout }) {
  const resolver = new Resolver({ timeout, tries: 1 });
  const cancel = () => resolver.cancel();
  signal.addEventListener("abort", cancel, { once: true });
  try {
    signal.throwIfAborted();
    return (
      await Promise.all(
        [4, 6].map(async (family) => {
          try {
            const answers = await resolver[`resolve${family}`](hostname);
            return answers.map((address) => ({ address, family }));
          } catch (cause) {
            if (["ENODATA", "ENOTFOUND"].includes(cause.code)) return [];
            throw cause;
          }
        }),
      )
    ).flat();
  } finally {
    signal.removeEventListener("abort", cancel);
    cancel();
  }
}

async function abortable(promise, signal) {
  // Observe an already-started promise even if cancellation has just won.
  let onAbort;
  const cancelled = new Promise((_, reject) => {
    onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
  try {
    return await Promise.race([promise, cancelled]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

function responseLength(response, remaining) {
  const names = response.rawHeaders
    .filter((_, index) => index % 2 === 0)
    .map((name) => name.toLowerCase());
  const headers = response.headers;
  const length = headers["content-length"];
  const encoding = headers["transfer-encoding"];
  if (
    response.statusCode !== 200 ||
    (headers["content-encoding"] !== undefined &&
      headers["content-encoding"] !== "identity") ||
    headers["content-range"] !== undefined ||
    (encoding !== undefined && encoding !== "chunked") ||
    (length !== undefined &&
      (encoding !== undefined || !/^(?:0|[1-9][0-9]*)$/u.test(length))) ||
    ["content-length", "transfer-encoding", "content-encoding"].some(
      (name) => names.filter((value) => value === name).length > 1,
    )
  )
    throw failure("RESPONSE");
  if (length === undefined) return null;
  const bytes = Number(length);
  if (!Number.isSafeInteger(bytes) || bytes > remaining) throw failure("LIMIT");
  return bytes;
}

async function download(artifact, file, budget, outerSignal, transport) {
  const { lookup, request, limits, schedule } = transport;
  const controller = new AbortController();
  const signal = controller.signal;
  const abort = () => controller.abort(outerSignal.reason);
  outerSignal.addEventListener("abort", abort, { once: true });
  if (outerSignal.aborted) abort();
  let cancelDeadline = () => {};
  const deadline = (milliseconds) => {
    cancelDeadline();
    cancelDeadline = schedule(
      () => controller.abort(failure("TIMEOUT")),
      milliseconds,
    );
  };
  const resources = new Map();
  let stopped = false;
  const track = (resource) => {
    if (resources.has(resource)) return;
    resource.on("error", () => controller.abort(failure("TRANSPORT")));
    resources.set(
      resource,
      new Promise((resolve) => {
        if (resource.closed) resolve();
        else resource.once("close", resolve);
      }),
    );
    if (stopped || signal.aborted) resource.destroy();
  };
  const destroy = () => {
    for (const resource of resources.keys()) resource.destroy();
  };
  signal.addEventListener("abort", destroy, { once: true });
  try {
    signal.throwIfAborted();
    const url = new URL(artifact.url);
    deadline(limits.dnsMs);
    const answers = await abortable(
      lookup(url.hostname, { signal, timeout: limits.dnsMs }),
      signal,
    );
    if (!Array.isArray(answers) || answers.length === 0 || answers.length > 64)
      throw failure("ADDRESS");
    const addresses = answers.map((answer) => {
      const address = publicAddress(answer?.address);
      if (address === null || address.family !== answer.family)
        throw failure("ADDRESS");
      return address;
    });
    const pinned = addresses[0];
    signal.throwIfAborted();
    deadline(limits.connectionMs);
    let verified = false;
    const response = await abortable(
      new Promise((resolve) => {
        const req = request(
          {
            protocol: "https:",
            hostname: pinned.address,
            family: pinned.family,
            port: 443,
            servername: url.hostname,
            method: "GET",
            path: `${url.pathname}${url.search}`,
            headers: {
              Host: url.hostname,
              "Accept-Encoding": "identity",
              Connection: "close",
            },
            agent: false,
            proxyEnv: {},
            ca: [...rootCertificates],
            rejectUnauthorized: true,
            checkServerIdentity: (_, certificate) =>
              checkServerIdentity(url.hostname, certificate),
            minVersion: "TLSv1.2",
            ALPNProtocols: ["http/1.1"],
            maxHeaderSize: 16 * 1024,
            insecureHTTPParser: false,
            // The numeric destination must never trigger another resolver lookup.
            lookup: (_, __, callback) => callback(failure("ADDRESS")),
          },
          (incoming) => {
            track(incoming);
            if (!verified || stopped || signal.aborted) {
              incoming.destroy();
              controller.abort(failure("TLS"));
              return;
            }
            resolve(incoming);
          },
        );
        track(req);
        req.on("socket", (socket) => {
          track(socket);
          socket.once("secureConnect", () => {
            if (stopped || signal.aborted) return;
            if (
              !socket.encrypted ||
              socket.authorized !== true ||
              socket.remotePort !== 443 ||
              publicAddress(socket.remoteAddress)?.key !== pinned.key
            ) {
              controller.abort(failure("TLS"));
              return;
            }
            verified = true;
            deadline(limits.bodyMs);
          });
        });
        req.end();
      }),
      signal,
    );
    const expected = responseLength(
      response,
      Math.min(limits.fileBytes, limits.totalBytes - budget.bytes),
    );
    const hash = createHash("sha256");
    let bytes = 0;
    const iterator = response[Symbol.asyncIterator]();
    while (true) {
      const chunk = await abortable(iterator.next(), signal);
      if (chunk.done) break;
      if (!Buffer.isBuffer(chunk.value)) throw failure("RESPONSE");
      bytes += chunk.value.length;
      budget.bytes += chunk.value.length;
      if (bytes > limits.fileBytes || budget.bytes > limits.totalBytes)
        throw failure("LIMIT");
      deadline(limits.bodyMs);
      signal.throwIfAborted();
      await file.writeFile(chunk.value);
      hash.update(chunk.value);
    }
    signal.throwIfAborted();
    if (!response.complete || (expected !== null && bytes !== expected))
      throw failure("RESPONSE");
    if (hash.digest("hex") !== artifact.sha256) throw failure("INTEGRITY");
    return bytes;
  } catch (cause) {
    if (signal.aborted) throw signal.reason;
    if (cause?.code?.startsWith("ERR_TRUSTED_ACQUISITION_")) throw cause;
    throw failure("TRANSPORT");
  } finally {
    stopped = true;
    cancelDeadline();
    outerSignal.removeEventListener("abort", abort);
    signal.removeEventListener("abort", destroy);
    destroy();
    let cancelRetirement;
    try {
      await Promise.race([
        Promise.all(resources.values()),
        new Promise((_, reject) => {
          cancelRetirement = schedule(
            () => reject(failure("RETIREMENT")),
            limits.retirementMs,
          );
        }),
      ]);
    } finally {
      cancelRetirement?.();
    }
  }
}

// Private primitive only. The caller must supply an exclusively owned directory
// handle; durable allocation, mounting and recovery are not enabled here.
export function createArtifactAcquirer({
  lookup = lookupAddresses,
  request = httpsRequest,
  limits: overrides = {},
  schedule = scheduleTimeout,
} = {}) {
  if (
    Object.entries(overrides).some(
      ([key, value]) =>
        !Object.hasOwn(ACQUISITION_LIMITS, key) ||
        !Number.isSafeInteger(value) ||
        value < 1 ||
        value > ACQUISITION_LIMITS[key],
    )
  )
    throw failure("CONTRACT");
  const limits = { ...ACQUISITION_LIMITS, ...overrides };
  return async function acquire(input) {
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).some(
        (key) => !["artifacts", "directory", "signal"].includes(key),
      )
    )
      throw failure("CONTRACT");
    const artifacts = normalizeArtifacts(input.artifacts);
    if (artifacts === null) throw failure("CONTRACT");
    const { directory, signal } = input;
    const controller = new AbortController();
    const abort = () => controller.abort(signal.reason);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    const cancelOverall = schedule(
      () => controller.abort(failure("TIMEOUT")),
      limits.overallMs,
    );
    const budget = { bytes: 0 };
    const published = new Set();
    try {
      controller.signal.throwIfAborted();
      const info = await directory.stat();
      if (
        !info.isDirectory() ||
        info.uid !== process.getuid() ||
        (info.mode & 0o777) !== 0o700
      )
        throw failure("STORAGE");
      const base = `/proc/self/fd/${directory.fd}`;
      for (const artifact of artifacts) {
        controller.signal.throwIfAborted();
        const partial = `${base}/.partial-${randomUUID()}`;
        const target = `${base}/${artifact.sha256}`;
        const file = await open(
          partial,
          constants.O_CREAT |
            constants.O_EXCL |
            constants.O_WRONLY |
            constants.O_NOFOLLOW,
          0o600,
        );
        let retired = true;
        let linked = false;
        try {
          await download(artifact, file, budget, controller.signal, {
            lookup,
            request,
            limits,
            schedule,
          });
          await file.chmod(0o444);
          await file.sync();
          controller.signal.throwIfAborted();
          if ((await ownedFileEntry(partial, file)).nlink !== 1n)
            throw failure("STORAGE");
          if (!published.has(artifact.sha256)) {
            controller.signal.throwIfAborted();
            await link(partial, target); // Exclusive publication; never overwrite an existing entry.
            linked = true;
            await directory.sync();
            controller.signal.throwIfAborted();
            published.add(artifact.sha256);
          }
        } catch (cause) {
          retired = cause?.code !== "ERR_TRUSTED_ACQUISITION_RETIREMENT";
          if (linked) {
            await ownedFileEntry(target, file);
            await unlink(target);
          }
          throw cause;
        } finally {
          try {
            // Keep the file handle until cleanup has verified entry ownership.
            // Uncertain retirement or substitution retains recovery evidence.
            if (retired) {
              await ownedFileEntry(partial, file);
              await unlink(partial);
            }
          } finally {
            await file.close();
          }
        }
      }
      controller.signal.throwIfAborted();
      return Object.freeze([...published]);
    } catch (cause) {
      if (cause?.code === "ERR_TRUSTED_ACQUISITION_RETIREMENT") throw cause;
      if (controller.signal.aborted) throw controller.signal.reason;
      if (cause?.code?.startsWith("ERR_TRUSTED_ACQUISITION_")) throw cause;
      throw failure("STORAGE");
    } finally {
      cancelOverall();
      signal?.removeEventListener("abort", abort);
    }
  };
}
