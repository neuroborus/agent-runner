import { request as httpsRequest } from "node:https";
import { createHash } from "node:crypto";
import {
  observationObject,
  observationList,
  observationDigest,
  requireObservation,
} from "../index.js";
import { PROVIDER_LIMITS } from "./contract.js";

export function normalizeRelayPolicy(value) {
  observationObject(value, [
    "provider",
    "nonce",
    "model",
    "requests",
    "outputTokens",
    "budgetMicros",
    "inputMicros",
    "outputMicros",
    "beta",
  ]);
  requireObservation(
    ["codex", "claude"].includes(value.provider) &&
      /^[a-f0-9]{32}$/u.test(value.nonce) &&
      typeof value.model === "string" &&
      /^[A-Za-z0-9_.:/-]{1,128}$/u.test(value.model),
  );
  for (const key of [
    "requests",
    "outputTokens",
    "budgetMicros",
    "inputMicros",
    "outputMicros",
  ])
    requireObservation(Number.isSafeInteger(value[key]) && value[key] > 0);
  requireObservation(
    value.requests <= PROVIDER_LIMITS.requests &&
      value.outputTokens <= PROVIDER_LIMITS.tokens,
  );
  const beta = observationList(value.beta, 16);
  requireObservation(
    new Set(beta).size === beta.length &&
      beta.every((v) => typeof v === "string" && /^[a-z0-9-]{1,96}$/u.test(v)),
  );
  return { ...value, beta: [...beta] };
}

/** Credential is injected through a protected pipe, never argv/environment.
 * No client header, destination or upstream error is copied into diagnostics. */
export function createProtectedRelay(
  input,
  credential,
  {
    request = httpsRequest,
    now = () => performance.now(),
    onFailure = () => {},
    onReceipt = async () => {},
  } = {},
) {
  const policy = normalizeRelayPolicy(input);
  requireObservation(
    typeof credential === "string" &&
      credential.length > 0 &&
      credential.length <= 8192 &&
      !/[\u0000-\u0020\u007f]/u.test(credential),
  );
  const origin =
    policy.provider === "codex"
      ? "https://api.openai.com"
      : "https://api.anthropic.com";
  const route = policy.provider === "codex" ? "/v1/responses" : "/v1/messages";
  const start = now();
  let closed = false,
    pending = false,
    count = 0,
    charged = 0,
    active = null;
  const sessionTimer = setTimeout(() => close(), PROVIDER_LIMITS.sessionMs);
  sessionTimer.unref();
  const close = () => {
    if (closed) return;
    closed = true;
    clearTimeout(sessionTimer);
    active?.destroy();
    try {
      onFailure();
    } catch {}
  };
  return Object.freeze({
    close,
    async forward(value, send, signal) {
      let owns = false;
      try {
        requireObservation(
          !closed &&
            !pending &&
            now() - start >= 0 &&
            now() - start < PROVIDER_LIMITS.sessionMs,
        );
        pending = true;
        owns = true;
        observationObject(value, ["method", "path", "headers", "body"]);
        requireObservation(
          value.method === "POST" &&
            value.path === route &&
            Buffer.isBuffer(value.body) &&
            value.body.length > 0 &&
            value.body.length <= PROVIDER_LIMITS.requestBytes &&
            typeof send === "function",
        );
        requireObservation(
          value.headers?.authorization === "Bearer native-poc-" + policy.nonce,
        );
        const body = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(value.body),
        );
        requireObservation(
          body &&
            Object.getPrototypeOf(body) === Object.prototype &&
            body.model === policy.model &&
            (body.stream === undefined || typeof body.stream === "boolean"),
        );
        // Hosted upstream tools and alternate destinations have costs/authority
        // outside this short-lived tool-transport grant. Only client tools pass.
        if (body.tools !== undefined) {
          const tools = observationList(body.tools, 128);
          requireObservation(
            tools.every(
              (tool) =>
                tool &&
                Object.getPrototypeOf(tool) === Object.prototype &&
                (policy.provider === "codex"
                  ? ["function", "custom"].includes(tool.type)
                  : [undefined, "custom"].includes(tool.type)),
            ),
          );
        }
        requireObservation(
          !Object.hasOwn(body, "background") || body.background === false,
        );
        requireObservation(
          !Object.hasOwn(body, "service_tier") ||
            body.service_tier === "default",
        );
        // The byte reservation covers this complete request, not context fetched
        // from an upstream response, conversation, item or dashboard prompt.
        if (policy.provider === "codex") {
          requireObservation(
            ["previous_response_id", "conversation", "prompt"].every(
              (key) => !Object.hasOwn(body, key),
            ) &&
              (!Object.hasOwn(body, "store") || body.store === false),
          );
          body.store = false;
        }
        textOnly(body.input ?? body.messages);
        requireObservation(
          !Object.hasOwn(body, "audio") && !Object.hasOwn(body, "modalities"),
        );
        const limitKey =
          policy.provider === "codex" ? "max_output_tokens" : "max_tokens";
        requireObservation(
          body[limitKey] === undefined ||
            (Number.isSafeInteger(body[limitKey]) &&
              body[limitKey] > 0 &&
              body[limitKey] <= policy.outputTokens),
        );
        body[limitKey] ??= policy.outputTokens;
        const cost =
          value.body.length * policy.inputMicros +
          body[limitKey] * policy.outputMicros;
        requireObservation(
          Number.isSafeInteger(cost) &&
            Number.isSafeInteger(charged + cost) &&
            ++count <= policy.requests &&
            charged + cost <= policy.budgetMicros,
        );
        charged += cost; // Reserve worst case before effects; never refund/retry.
        const bytes = Buffer.from(JSON.stringify(body));
        requireObservation(
          bytes.length <= PROVIDER_LIMITS.requestBytes && !signal?.aborted,
        );
        const headers = {
          "content-type": "application/json",
          "accept-encoding": "identity",
          "content-length": bytes.length,
        };
        if (policy.provider === "codex")
          headers.authorization = "Bearer " + credential;
        else {
          headers["x-api-key"] = credential;
          headers["anthropic-version"] = "2023-06-01";
          const beta = value.headers["anthropic-beta"];
          if (beta !== undefined) {
            requireObservation(typeof beta === "string" && beta.length <= 1552);
            const names = observationList(
              beta.split(",").map((name) => name.trim()),
              16,
            );
            requireObservation(
              new Set(names).size === names.length &&
                names.every((name) => policy.beta.includes(name)),
            );
            headers["anthropic-beta"] = names.join(",");
          }
        }
        const remaining = PROVIDER_LIMITS.sessionMs - (now() - start);
        await new Promise((resolve, reject) => {
          let settled = false,
            response;
          const dispose = () => {
            clearTimeout(timer);
            signal?.removeEventListener("abort", fail);
          };
          const fail = () => {
            if (settled) return;
            settled = true;
            dispose();
            active?.destroy();
            response?.destroy();
            reject(new Error("Provider transport closed"));
          };
          const timer = setTimeout(
            fail,
            Math.min(PROVIDER_LIMITS.requestMs, remaining),
          );
          signal?.addEventListener("abort", fail, { once: true });
          const guard = () =>
            requireObservation(!settled && !closed && !signal?.aborted);
          try {
            active = request(
              new URL(route, origin),
              { method: "POST", headers, agent: false },
              (incoming) => {
                response = incoming;
                void (async () => {
                  guard();
                  requireObservation(
                    incoming.statusCode === 200 &&
                      !incoming.headers.location &&
                      !incoming.headers["content-encoding"],
                  );
                  const type = incoming.headers["content-type"]?.split(";")[0];
                  requireObservation(
                    ["application/json", "text/event-stream"].includes(type),
                  );
                  await send({ type: "headers", contentType: type });
                  guard();
                  const responseHash = createHash("sha256");
                  const completed = await filterResponse(
                    incoming,
                    type,
                    async (bytes) => {
                      guard();
                      responseHash.update(bytes);
                      await send({ type: "data", bytes });
                      guard();
                    },
                  );
                  guard();
                  requireObservation(incoming.complete === true);
                  await send({ type: "end" });
                  guard();
                  // Protected receipt channel only. Neither raw content nor
                  // authentication/response headers enter persisted evidence.
                  const metadata = body.client_metadata;
                  const identity = (key) =>
                    typeof metadata?.[key] === "string" &&
                    /^[A-Za-z0-9_-]{1,128}$/u.test(metadata[key])
                      ? metadata[key]
                      : null;
                  await onReceipt({
                    provider: policy.provider,
                    nonce: policy.nonce,
                    model: policy.model,
                    sequence: count,
                    registrySha256: observationDigest(body.tools ?? []),
                    threadId: identity("thread_id"),
                    turnId: identity("turn_id"),
                    requestSha256: createHash("sha256")
                      .update(bytes)
                      .digest("hex"),
                    responseSha256: responseHash.digest("hex"),
                    completed,
                  });
                  guard();
                  settled = true;
                  dispose();
                  resolve();
                })().catch(fail);
              },
            );
            active.once("error", fail);
            // ClientRequest closes when the upstream connection is finished,
            // including while a complete response is awaiting pipe backpressure.
            active.once("close", () => {
              if (!settled && response?.complete !== true) fail();
            });
            active.end(bytes);
          } catch {
            fail();
          }
        });
      } catch {
        close();
        throw new Error("Provider transport closed");
      } finally {
        active = null;
        if (owns) pending = false;
      }
    },
  });
}

// Filter only protocol metadata in memory. A successful HTTP status can still
// contain an upstream error; those payloads never cross credential custody.
function successful(value) {
  requireObservation(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      !value.error &&
      !value.response?.error &&
      !["error", "response.failed", "response.incomplete"].includes(
        value.type,
      ) &&
      !["failed", "incomplete", "cancelled"].includes(value.status) &&
      !["failed", "incomplete", "cancelled"].includes(value.response?.status),
  );
}
async function filterResponse(incoming, type, send) {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let total = 0,
    pending = "",
    emitted = 0,
    completed = false,
    completions = 0;
  const inspect = (value) => {
    successful(value);
    if (value.type === "response.completed" || value.object === "response") {
      requireObservation(++completions === 1);
      const response = value.response ?? value;
      completed = response.status === "completed";
    }
  };
  const block = async (text) => {
    requireObservation(Buffer.byteLength(text) <= PROVIDER_LIMITS.requestBytes);
    const lines = text.split("\n");
    requireObservation(!lines.some((line) => /^event:\s*error$/u.test(line)));
    const data = lines
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trimStart())
      .join("\n");
    if (data && data !== "[DONE]") inspect(JSON.parse(data));
    requireObservation(
      data || lines.every((line) => !line || line.startsWith(":")),
    );
    if (data) emitted++;
    await send(Buffer.from(text + "\n\n"));
  };
  for await (const chunk of incoming) {
    total += chunk.length;
    requireObservation(total <= PROVIDER_LIMITS.responseBytes);
    pending += decoder.decode(chunk, { stream: true });
    if (type === "text/event-stream") {
      // Normalize CRLF only after a complete line, including split CR/LF reads.
      let end;
      while ((end = pending.search(/\r?\n\r?\n/u)) !== -1) {
        const separator = pending.slice(end).match(/^\r?\n\r?\n/u)[0];
        const text = pending.slice(0, end).replaceAll("\r\n", "\n");
        pending = pending.slice(end + separator.length);
        await block(text);
      }
      requireObservation(
        Buffer.byteLength(pending) <= PROVIDER_LIMITS.requestBytes,
      );
    }
  }
  pending += decoder.decode();
  requireObservation(total > 0);
  if (type === "application/json") {
    inspect(JSON.parse(pending));
    const bytes = Buffer.from(pending);
    for (
      let offset = 0;
      offset < bytes.length;
      offset += PROVIDER_LIMITS.requestBytes
    )
      await send(bytes.subarray(offset, offset + PROVIDER_LIMITS.requestBytes));
  } else requireObservation(!pending.trim() && emitted > 0);
  return completed;
}

function textOnly(value) {
  if (Array.isArray(value)) {
    for (const child of value) textOnly(child);
  } else if (value && typeof value === "object") {
    requireObservation(
      typeof value.type !== "string" ||
        (!/(?:image|audio|video|document|file|pdf)/u.test(value.type) &&
          value.type !== "item_reference"),
    );
    for (const child of Object.values(value)) textOnly(child);
  }
}
