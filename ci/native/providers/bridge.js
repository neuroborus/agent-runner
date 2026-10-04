import { observationObject, requireObservation } from "../index.js";
import { PROVIDER_LIMITS } from "./contract.js";

function decode(value) {
  const bytes = Buffer.from(value, "base64");
  requireObservation(bytes.toString("base64") === value);
  return bytes;
}
const FRAME_BYTES = 2 * PROVIDER_LIMITS.requestBytes;
function frames(pipe) {
  let buffer = Buffer.alloc(0),
    total = 0;
  return {
    async *[Symbol.asyncIterator]() {
      for await (const chunk of pipe) {
        total += chunk.length;
        requireObservation(
          total <= 64 * PROVIDER_LIMITS.responseBytes &&
            buffer.length + chunk.length <= FRAME_BYTES + 65536,
        );
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 4) {
          const length = buffer.readUInt32BE(0);
          requireObservation(length > 0 && length <= FRAME_BYTES);
          if (buffer.length < length + 4) break;
          const value = JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(
              buffer.subarray(4, length + 4),
            ),
          );
          buffer = buffer.subarray(length + 4);
          yield value;
        }
      }
      requireObservation(buffer.length === 0);
    },
  };
}
async function write(pipe, value) {
  const bytes = Buffer.from(JSON.stringify(value));
  requireObservation(
    bytes.length > 0 && bytes.length <= FRAME_BYTES && !pipe.destroyed,
  );
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.length);
  if (!pipe.write(Buffer.concat([header, bytes]))) await drained(pipe);
}

// Stream close need not emit drain or error. A lost helper or client must
// reject backpressure waits rather than leave an exchange pending forever.
function drained(stream) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      stream.removeListener("drain", ready);
      stream.removeListener("error", fail);
      stream.removeListener("close", fail);
    };
    const ready = () => {
      cleanup();
      resolve();
    };
    const fail = () => {
      cleanup();
      reject(new Error("Provider transport closed"));
    };
    stream.once("drain", ready);
    stream.once("error", fail);
    stream.once("close", fail);
    if (stream.destroyed || stream.writableEnded) fail();
  });
}

/** One fixed inherited duplex pipe. A failed exchange cannot be retried on a
 * different path, and no request-supplied address reaches trusted custody. */
export function createPipeExchange(
  pipe,
  { schedule = setTimeout, cancel = clearTimeout } = {},
) {
  const reader = frames(pipe)[Symbol.asyncIterator]();
  let busy = false,
    failed = false;
  return async (value, send) => {
    let owns = false,
      rejectFault;
    const fault = new Promise((_, reject) => {
      rejectFault = reject;
    });
    fault.catch(() => {});
    const fail = () => {
      failed = true;
      rejectFault(new Error("Provider transport closed"));
      pipe.destroy();
    };
    const guard = () => requireObservation(!failed && !pipe.destroyed);
    const wait = async (action) => {
      guard();
      const result = await Promise.race([
        Promise.resolve().then(() => {
          guard();
          return action();
        }),
        fault,
      ]);
      guard();
      return result;
    };
    pipe.once("error", fail);
    pipe.once("close", fail);
    const timer = schedule(fail, PROVIDER_LIMITS.requestMs);
    try {
      requireObservation(!busy && !failed);
      busy = true;
      owns = true;
      await wait(() =>
        write(pipe, { ...value, body: value.body.toString("base64") }),
      );
      let total = 0,
        headers = false;
      for (;;) {
        const next = await wait(() => reader.next());
        requireObservation(!next.done);
        const item = next.value;
        if (item.type === "headers") {
          observationObject(item, ["type", "contentType"]);
          requireObservation(
            !headers &&
              ["application/json", "text/event-stream"].includes(
                item.contentType,
              ),
          );
          headers = true;
        } else if (item.type === "data") {
          observationObject(item, ["type", "bytes"]);
          requireObservation(
            headers &&
              typeof item.bytes === "string" &&
              item.bytes.length <= 2 * PROVIDER_LIMITS.requestBytes,
          );
          item.bytes = decode(item.bytes);
          total += item.bytes.length;
          requireObservation(
            item.bytes.length > 0 && total <= PROVIDER_LIMITS.responseBytes,
          );
        } else {
          observationObject(item, ["type"]);
          requireObservation(item.type === "end" && headers && total > 0);
        }
        await wait(() => send(item));
        if (item.type === "end") break;
      }
    } catch {
      fail();
      throw new Error("Provider transport closed");
    } finally {
      cancel(timer);
      pipe.removeListener("error", fail);
      pipe.removeListener("close", fail);
      if (owns) busy = false;
    }
  };
}

export async function serveRelayPipe(pipe, relay) {
  try {
    for await (const value of frames(pipe)) {
      observationObject(value, ["method", "path", "headers", "body"]);
      requireObservation(
        typeof value.body === "string" && value.body.length <= FRAME_BYTES,
      );
      value.body = decode(value.body);
      await relay.forward(value, (item) =>
        write(
          pipe,
          item.type === "data"
            ? { ...item, bytes: item.bytes.toString("base64") }
            : item,
        ),
      );
    }
  } catch {
    relay.close();
    pipe.destroy();
    throw new Error("Provider transport closed");
  }
}

/** The indexed native owner supplies an already held, exclusively bound
 * server only after identity/policy/pipe admission. This code never listens.
 * Linux places this credential-free broker in the private net namespace. */
export function serveCredentialFreeBroker(
  server,
  exchange,
  { onFailure = () => {} } = {},
) {
  requireObservation(
    server.listening === true && typeof exchange === "function",
  );
  let busy = false,
    closed = false;
  const sockets = new Set();
  const close = () => {
    if (closed) return;
    closed = true;
    for (const socket of sockets) socket.destroy();
    server.close();
    try {
      onFailure();
    } catch {}
  };
  server.maxHeadersCount = 32;
  server.requestTimeout = PROVIDER_LIMITS.requestMs;
  server.headersTimeout = 5000;
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.setTimeout(PROVIDER_LIMITS.requestMs, close);
    socket.once("close", () => sockets.delete(socket));
    socket.on("error", close);
    if (closed || sockets.size > 4) close();
  });
  server.on("clientError", close);
  server.on("connect", close);
  server.on("upgrade", close);
  server.on("error", close);
  server.on("request", (request, response) => {
    void (async () => {
      requireObservation(
        !closed &&
          !busy &&
          request.method === "POST" &&
          !request.headers["transfer-encoding"],
      );
      busy = true;
      const timer = setTimeout(close, PROVIDER_LIMITS.requestMs);
      try {
        const body = [];
        let bytes = 0;
        for await (const chunk of request) {
          bytes += chunk.length;
          requireObservation(bytes <= PROVIDER_LIMITS.requestBytes);
          body.push(chunk);
        }
        requireObservation(
          request.complete === true &&
            bytes > 0 &&
            request.rawHeaders.filter(
              (key, index) =>
                index % 2 === 0 && key.toLowerCase() === "authorization",
            ).length === 1,
        );
        // Drop cookies, proxy credentials and every header except the public
        // capability and reviewed Anthropic feature names, before pipe custody.
        const headers = { authorization: request.headers.authorization };
        if (request.headers["anthropic-beta"] !== undefined)
          headers["anthropic-beta"] = request.headers["anthropic-beta"];
        await exchange(
          {
            method: request.method,
            path: request.url,
            headers,
            body: Buffer.concat(body),
          },
          async (item) => {
            requireObservation(!closed);
            if (item.type === "headers")
              response.writeHead(200, {
                "content-type": item.contentType,
                "cache-control": "no-store",
              });
            else if (item.type === "data") {
              if (!response.write(item.bytes)) await drained(response);
            } else response.end();
          },
        );
      } finally {
        clearTimeout(timer);
        busy = false;
      }
    })().catch(close);
  });
  return { close };
}
