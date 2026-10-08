import {
  CLAUDE_WRAPPER_REFERENCE,
  observationDigest,
  observationList,
  requireObservation,
} from "../index.js";
import { PROVIDER_LIMITS } from "./contract.js";
import { normalizeClaudeToolSet } from "./claude.js";

export { CLAUDE_TOOLS } from "./claude.js";
const identity = (value) =>
  typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/u.test(value);
const session = (value) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/iu.test(value);

/** Opaque-provider notifications identify dispatch only. Native events/state
 * and protected model receipts supply all effect and provenance evidence.
 * Raw message/tool contents stay in bounded memory, never diagnostics. */
export function openClaudeStream(transport, spec, signal, selectedTools) {
  const tools = normalizeClaudeToolSet(selectedTools);
  requireObservation(
    transport?.input && transport.output && transport.errorOutput,
  );
  let failure,
    closed = false,
    finished = false,
    active,
    init,
    resolveInit,
    rejectInit;
  let total = 0,
    messages = 0,
    remaining = 0;
  const tasks = new Map();
  const initialized = new Promise((resolve, reject) => {
    resolveInit = resolve;
    rejectInit = reject;
  });
  initialized.catch(() => {});
  const fail = () => {
    failure ??= new Error("Claude native proof failed");
    rejectInit(failure);
    active?.reject(failure);
  };
  const guard = () =>
    requireObservation(!closed && !failure && !signal?.aborted);
  const receive = (record) => {
    requireObservation(
      record && typeof record === "object" && ++messages <= 4096,
    );
    if (record.type === "system" && record.subtype === "init") {
      requireObservation(
        !init &&
          session(record.session_id) &&
          record.model === spec.model &&
          record.claude_code_version === CLAUDE_WRAPPER_REFERENCE.version &&
          record.permissionMode === "bypassPermissions" &&
          observationDigest([...observationList(record.tools, 16)].sort()) ===
            observationDigest([...tools].sort()) &&
          observationList(record.mcp_servers, 16).length === 0,
      );
      for (const key of ["plugins", "skills", "slash_commands", "agents"])
        if (record[key] !== undefined)
          requireObservation(observationList(record[key], 16).length === 0);
      init = {
        sessionId: record.session_id,
        registrySha256: observationDigest(record.tools),
      };
      resolveInit(init);
      return;
    }
    requireObservation(
      init &&
        record.session_id === init.sessionId &&
        record.parent_tool_use_id == null,
    );
    if (
      record.type === "system" &&
      ["task_started", "task_notification", "task_progress"].includes(
        record.subtype,
      )
    ) {
      requireObservation(identity(record.task_id));
      if (record.subtype === "task_started") {
        requireObservation(
          active &&
            !active.completed &&
            record.task_type === "local_bash" &&
            active.tools.get(record.tool_use_id)?.name === "Bash" &&
            !tasks.has(record.task_id),
        );
        tasks.set(record.task_id, record.tool_use_id);
        active.tasks.add(record.task_id);
      } else
        requireObservation(
          tasks.has(record.task_id) &&
            (record.tool_use_id === undefined ||
              record.tool_use_id === tasks.get(record.task_id)),
        );
      return;
    }
    requireObservation(active && !active.completed);
    if (record.type === "assistant") {
      const message = record.message;
      requireObservation(
        message?.role === "assistant" &&
          identity(message.id) &&
          message.model === spec.model &&
          !active.terminal,
      );
      active.messages.add(message.id);
      for (const block of observationList(message.content, 32)) {
        if (["text", "thinking", "redacted_thinking"].includes(block.type))
          continue;
        requireObservation(
          block.type === "tool_use" &&
            identity(block.id) &&
            tools.includes(block.name) &&
            block.input &&
            Object.getPrototypeOf(block.input) === Object.prototype &&
            !active.tools.has(block.id),
        );
        active.tools.set(block.id, {
          messageId: message.id,
          id: block.id,
          name: block.name,
          input: block.input,
        });
        requireObservation(!active.terminal);
        if (block.name === "EndConversation") active.terminal = block.id;
      }
    } else if (record.type === "user") {
      requireObservation(record.message?.role === "user");
      for (const block of observationList(record.message.content, 32)) {
        requireObservation(
          block.type === "tool_result" &&
            active.tools.has(block.tool_use_id) &&
            !active.results.has(block.tool_use_id) &&
            (block.is_error === undefined ||
              typeof block.is_error === "boolean") &&
            (typeof block.content === "string" || Array.isArray(block.content)),
        );
        active.results.set(block.tool_use_id, {
          content: block.content,
          isError: block.is_error === true,
        });
      }
    } else {
      // The terminal route may end the turn without a user tool_result. Only
      // its dispatched tool ID plus a successful final result acknowledge it;
      // neither acknowledgement establishes any native effect.
      if (active.terminal && !active.results.has(active.terminal))
        active.results.set(active.terminal, {
          content: null,
          isError: false,
          terminal: true,
        });
      requireObservation(
        record.type === "result" &&
          record.subtype === "success" &&
          record.is_error === false &&
          observationList(record.permission_denials, 32).length === 0 &&
          active.tools.size > 0 &&
          active.tools.size === active.results.size &&
          active.terminal &&
          !active.completed,
      );
      active.completed = true;
      finished = true;
      active.resolve({
        ...init,
        messageIds: [...active.messages],
        tools: [...active.tools.values()].map((tool) => ({
          ...tool,
          result: active.results.get(tool.id),
        })),
        taskIds: [...active.tasks],
      });
    }
  };
  const readers = [
    (async () => {
      let rest = Buffer.alloc(0);
      const decoder = new TextDecoder("utf-8", { fatal: true });
      for await (const chunk of transport.output) {
        requireObservation(Buffer.isBuffer(chunk));
        total += chunk.length;
        requireObservation(total <= PROVIDER_LIMITS.responseBytes);
        rest = Buffer.concat([rest, chunk]);
        let end;
        while ((end = rest.indexOf(10)) !== -1) {
          const line = rest.subarray(0, end);
          rest = rest.subarray(end + 1);
          requireObservation(line.length <= PROVIDER_LIMITS.requestBytes);
          receive(JSON.parse(decoder.decode(line)));
        }
        remaining = rest.length;
        requireObservation(remaining <= PROVIDER_LIMITS.requestBytes);
      }
      requireObservation((closed || finished) && rest.length === 0);
    })(),
    (async () => {
      let bytes = 0;
      for await (const chunk of transport.errorOutput) {
        bytes += chunk.length;
        requireObservation(bytes <= PROVIDER_LIMITS.requestBytes);
      }
      requireObservation(closed || finished);
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
  transport.input.on("error", () => {
    if (!closed) fail();
  });
  transport.completion.then(
    () => {
      if (!closed && !finished) fail();
    },
    () => {
      if (!closed) fail();
    },
  );
  signal?.addEventListener("abort", fail, { once: true });
  const bounded = async (work) => {
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
  return {
    assertHealthy: guard,
    expectRetirement() {
      guard();
      requireObservation(!active && finished);
      closed = true;
      signal?.removeEventListener("abort", fail);
    },
    async turn(prompt, inspect) {
      guard();
      requireObservation(!active && !finished);
      const result = new Promise((resolve, reject) => {
        active = {
          resolve,
          reject,
          tools: new Map(),
          results: new Map(),
          messages: new Set(),
          tasks: new Set(),
        };
      });
      result.catch(() => {});
      try {
        const line =
          JSON.stringify({
            type: "user",
            message: { role: "user", content: prompt },
          }) + "\n";
        requireObservation(
          Buffer.byteLength(line) <= PROVIDER_LIMITS.requestBytes,
        );
        // Initialization is emitted after the first input, before model dispatch.
        // Admission/observer controls precede this write; live inspection is also
        // independently repeated after execution, never inferred from this init.
        const written = new Promise((resolve, reject) => {
          transport.input.write(line, (error) => {
            if (error) {
              fail();
              reject(failure);
            } else resolve();
          });
        });
        written.catch(() => {});
        return await bounded(
          (async () => {
            await written;
            guard();
            await initialized;
            guard();
            await inspect(init);
            guard();
            const turn = await result;
            guard();
            return turn;
          })(),
        );
      } finally {
        active = null;
      }
    },
    async close() {
      closed = true;
      signal?.removeEventListener("abort", fail);
      rejectInit(new Error("Claude stream closed"));
      active?.reject(new Error("Claude stream closed"));
      transport.input.destroy();
      transport.output.destroy();
      transport.errorOutput.destroy();
      await Promise.allSettled(readers);
      return !failure && remaining === 0;
    },
  };
}
