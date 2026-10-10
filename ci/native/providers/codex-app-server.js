import { requireObservation } from "../index.js";
import { PROVIDER_LIMITS } from "./contract.js";

const TEXT_ITEMS = new Set([
  "userMessage",
  "agentMessage",
  "reasoning",
  "plan",
]);
const identity = (value) =>
  typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/u.test(value);
const NOTIFICATIONS = new Set([
  "thread/started",
  "thread/status/changed",
  "thread/tokenUsage/updated",
  "item/agentMessage/delta",
  "item/reasoning/textDelta",
  "item/reasoning/summaryTextDelta",
  "item/reasoning/summaryPartAdded",
  "item/commandExecution/outputDelta",
  "item/fileChange/outputDelta",
  "turn/diff/updated",
  "turn/plan/updated",
]);

/** Only this fixed App Server surface can request model work. There is no
 * command/exec, fs RPC, dynamic-tool reply or approval fallback here. Raw lines
 * and item contents live only in bounded memory and never enter diagnostics. */
export function openCodexAppServer(transport, signal) {
  requireObservation(
    transport?.input && transport.output && transport.errorOutput,
  );
  let sequence = 0,
    bytes = 0,
    messages = 0,
    bufferedBytes = 0,
    closed = false,
    failure,
    window;
  const pending = new Map();
  const fail = () => {
    failure ??= new Error("Codex App Server proof failed");
    for (const entry of pending.values()) entry.reject(failure);
    window?.reject(failure);
  };
  const guard = () =>
    requireObservation(!closed && !failure && !signal?.aborted);
  const receive = (value) => {
    requireObservation(
      value && typeof value === "object" && ++messages <= 4096,
    );
    if (Object.hasOwn(value, "id")) {
      // Any server request is an uncovered route, including permission stalls.
      const entry = pending.get(value.id);
      requireObservation(
        !value.method &&
          entry &&
          !value.error &&
          Object.hasOwn(value, "result"),
      );
      pending.delete(value.id);
      entry.resolve(value.result);
      return;
    }
    const { method, params } = value;
    if (method === "thread/settings/updated") {
      // turn/start commits its policy before emitting turn/started at this
      // release. Accept that notification only with the requested authority.
      const settings = params?.threadSettings,
        policy = settings?.sandboxPolicy;
      requireObservation(
        window &&
          !window.completed &&
          params.threadId === window.threadId &&
          settings?.cwd === window.cwd &&
          settings.model === window.model &&
          settings.modelProvider === "native_poc" &&
          settings.approvalPolicy === "never" &&
          policy?.type === "externalSandbox" &&
          policy.networkAccess === "enabled" &&
          Object.keys(policy).length === 2,
      );
    } else if (
      [
        "turn/started",
        "turn/completed",
        "item/started",
        "item/completed",
      ].includes(method)
    ) {
      requireObservation(window && params.threadId === window.threadId);
      const turnId = params.turn?.id ?? params.turnId;
      requireObservation(identity(turnId));
      window.turnId ??= turnId;
      requireObservation(turnId === window.turnId);
      if (method === "turn/started") {
        requireObservation(
          !window.started && params.turn.status === "inProgress",
        );
        window.started = true;
      } else if (method === "turn/completed") {
        requireObservation(
          window.started &&
            !window.completed &&
            params.turn.status === "completed" &&
            !params.turn.error,
        );
        window.completed = true;
        window.resolve();
      } else {
        const item = params.item;
        requireObservation(
          window.started && !window.completed && item && identity(item.id),
        );
        if (TEXT_ITEMS.has(item.type)) return;
        requireObservation(
          ["commandExecution", "fileChange"].includes(item.type),
        );
        if (method === "item/started") {
          requireObservation(
            !window.items.has(item.id) && item.status === "inProgress",
          );
          window.items.set(item.id, { started: item });
        } else {
          const previous = window.items.get(item.id);
          requireObservation(
            previous &&
              !previous.completed &&
              previous.started.type === item.type,
          );
          if (item.type === "commandExecution")
            requireObservation(
              previous.started.command === item.command &&
                previous.started.cwd === item.cwd &&
                previous.started.source === item.source,
            );
          else
            requireObservation(
              JSON.stringify(previous.started.changes) ===
                JSON.stringify(item.changes),
            );
          previous.completed = item;
        }
      }
    } else requireObservation(NOTIFICATIONS.has(method));
  };
  const read = async () => {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let rest = Buffer.alloc(0);
    for await (const chunk of transport.output) {
      requireObservation(Buffer.isBuffer(chunk));
      bytes += chunk.length;
      requireObservation(bytes <= PROVIDER_LIMITS.responseBytes);
      rest = Buffer.concat([rest, chunk]);
      let end;
      while ((end = rest.indexOf(10)) >= 0) {
        const line = rest.subarray(0, end);
        rest = rest.subarray(end + 1);
        requireObservation(line.length <= PROVIDER_LIMITS.requestBytes);
        receive(JSON.parse(decoder.decode(line)));
      }
      requireObservation(rest.length <= PROVIDER_LIMITS.requestBytes);
      bufferedBytes = rest.length;
    }
    requireObservation(closed && rest.length === 0);
  };
  const readers = [
    read(),
    (async () => {
      let size = 0;
      for await (const chunk of transport.errorOutput) {
        size += chunk.length;
        requireObservation(size <= PROVIDER_LIMITS.requestBytes);
      }
      requireObservation(closed);
    })(),
  ];
  for (const reader of readers)
    reader.catch((error) => {
      if (
        !closed ||
        !["ERR_STREAM_PREMATURE_CLOSE", "ERR_STREAM_DESTROYED"].includes(
          error.code,
        )
      )
        fail();
    });
  transport.completion.then(() => {
    if (!closed) fail();
  }, fail);
  // A failed pipe emits error independently of its write callback. Retain the
  // listener through destruction so a late EPIPE cannot escape owned cleanup.
  transport.input.on("error", fail);
  signal?.addEventListener("abort", fail, { once: true });
  const bounded = async (work) => {
    guard();
    let timer;
    try {
      return await Promise.race([
        work,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            fail();
            reject(failure);
          }, PROVIDER_LIMITS.requestMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  const write = (value) => {
    guard();
    const line = JSON.stringify(value) + "\n";
    requireObservation(Buffer.byteLength(line) <= PROVIDER_LIMITS.requestBytes);
    transport.input.write(line, (error) => {
      if (error) fail();
    });
  };
  const rpc = async (method, params) => {
    const id = ++sequence;
    requireObservation(sequence <= 64);
    const work = new Promise((resolve, reject) =>
      pending.set(id, { resolve, reject }),
    );
    try {
      write({ id, method, params });
      return await bounded(work);
    } finally {
      pending.delete(id);
    }
  };
  return {
    assertHealthy() {
      guard();
    },
    async initialize(spec, cwd) {
      const initialized = await rpc("initialize", {
        clientInfo: { name: "native-poc", version: "1" },
        capabilities: { experimentalApi: true },
      });
      requireObservation(initialized.codexHome === spec.home);
      write({ method: "initialized" });
      const response = await rpc("thread/start", {
        model: spec.model,
        modelProvider: "native_poc",
        cwd,
        approvalPolicy: "never",
        ephemeral: true,
        dynamicTools: [],
        allowProviderModelFallback: false,
        experimentalRawEvents: false,
      });
      requireObservation(
        response.model === spec.model &&
          response.modelProvider === "native_poc" &&
          response.approvalPolicy === "never" &&
          response.cwd === cwd,
      );
      const id = response.thread?.id;
      requireObservation(identity(id));
      return id;
    },
    async turn(spec, cwd, threadId, prompt) {
      guard();
      requireObservation(!window);
      const completed = new Promise((resolve, reject) => {
        window = {
          threadId,
          cwd,
          model: spec.model,
          resolve,
          reject,
          items: new Map(),
        };
      });
      completed.catch(() => {});
      try {
        return await bounded(
          (async () => {
            const response = await rpc("turn/start", {
              threadId,
              input: [{ type: "text", text: prompt, text_elements: [] }],
              cwd,
              model: spec.model,
              approvalPolicy: "never",
              sandboxPolicy: {
                type: "externalSandbox",
                networkAccess: "enabled",
              },
              serviceTierForTurn: "default",
            });
            await completed;
            guard();
            requireObservation(
              response.turn?.id === window.turnId && window.items.size > 0,
            );
            const items = [...window.items.values()].map((entry) => {
              requireObservation(entry.completed);
              return entry.completed;
            });
            return { threadId, turnId: window.turnId, items };
          })(),
        );
      } finally {
        window = null;
      }
    },
    async close() {
      closed = true;
      signal?.removeEventListener("abort", fail);
      const error = new Error("Codex App Server closed");
      for (const entry of pending.values()) entry.reject(error);
      window?.reject(error);
      transport.input.destroy();
      transport.output.destroy();
      transport.errorOutput.destroy();
      await Promise.allSettled(readers);
      return !failure && bufferedBytes === 0;
    },
  };
}
