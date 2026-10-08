import { requireObservation } from "../index.js";

/** Bounded private pipes. Loss, incomplete frames and late acknowledgements
 * poison the channel; a subsequent matching frame cannot repair the evidence. */
export function linuxProviderFrames(
  pipe,
  { maximum = 1048576, json = true } = {},
) {
  const queued = [],
    pending = [];
  let buffer = Buffer.alloc(0),
    size = 0,
    ended = false,
    failure = null;
  let resolveEnd, rejectEnd;
  const completion = new Promise((resolve, reject) => {
    resolveEnd = resolve;
    rejectEnd = reject;
  });
  completion.catch(() => {});
  const fail = (error) => {
    failure ??= error;
    rejectEnd(failure);
    for (const item of pending.splice(0)) item.reject(failure);
  };
  pipe.on("error", fail);
  pipe.on("data", (chunk) => {
    try {
      requireObservation(
        !ended && !failure && (size += chunk.length) <= maximum,
      );
      buffer = Buffer.concat([buffer, chunk]);
      let end;
      while ((end = buffer.indexOf(10)) >= 0) {
        requireObservation(end > 0 && end <= 32768);
        const text = new TextDecoder("utf-8", { fatal: true }).decode(
          buffer.subarray(0, end),
        );
        buffer = buffer.subarray(end + 1);
        const value = json ? JSON.parse(text) : text;
        const item = pending.shift();
        if (item) item.resolve(value);
        else queued.push(value);
        requireObservation(queued.length <= 4096);
      }
      requireObservation(buffer.length <= 32768);
    } catch (error) {
      fail(error);
    }
  });
  pipe.on("end", () => {
    ended = true;
    if (buffer.length) fail(new Error("Incomplete provider native frame"));
    else resolveEnd();
    for (const item of pending.splice(0))
      item.reject(new Error("Provider native pipe ended"));
  });
  pipe.on("close", () => {
    if (!ended) fail(new Error("Lost provider native pipe"));
  });
  return {
    assertHealthy() {
      requireObservation(!failure);
    },
    get bytes() {
      return size;
    },
    get queued() {
      return queued.length;
    },
    take(signal) {
      requireObservation(!failure && !signal?.aborted);
      if (queued.length) return Promise.resolve(queued.shift());
      requireObservation(!ended);
      return new Promise((resolve, reject) => {
        const item = { resolve: finish(resolve), reject: finish(reject) };
        const abort = () => {
          fail(new Error("Provider native channel interrupted"));
        };
        const timer = setTimeout(abort, 30000);
        function finish(callback) {
          return (value) => {
            clearTimeout(timer);
            signal?.removeEventListener("abort", abort);
            callback(value);
          };
        }
        pending.push(item);
        signal?.addEventListener("abort", abort, { once: true });
      });
    },
    drain() {
      requireObservation(ended && !failure && buffer.length === 0);
      return queued.splice(0);
    },
    async settle() {
      await completion;
      return this.drain();
    },
  };
}

export const writeLinuxProviderPipe = (pipe, bytes) =>
  new Promise((resolve, reject) => {
    requireObservation(!pipe.destroyed);
    pipe.write(bytes, (error) => (error ? reject(error) : resolve()));
  });
