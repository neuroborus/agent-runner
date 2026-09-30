import { isRecord } from "../adapter-contract.js";
import { createTurnProgress } from "../turn-progress.js";

const MAX_LINE_BYTES = 16 * 1024 * 1024;
const MAX_STREAM_BYTES = 64 * 1024 * 1024;
const SESSION_ID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/iu;
const DELTA_FIELDS = new Map([
  ["text_delta", ["text", "text"]],
  ["thinking_delta", ["thinking", "thinking"]],
  ["input_json_delta", ["tool_use", "partial_json"]],
]);
const identifier = (value) =>
  typeof value === "string" && value.length > 0 && value.length <= 512;

export function createClaudeStream(onProgress, protocolError) {
  const progress = createTurnProgress(onProgress);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const blocks = new Map();
  const commands = new Set();
  let sessionId;
  let messageId;
  let buffer = "";
  let bytes = 0;
  let invalid = false;
  let hasRecords = false;
  let payload = null;
  let finished = false;

  function observe(record) {
    if (record.type === "result") {
      if (payload !== null) invalid = true;
      if (sessionId !== undefined && record.session_id !== sessionId)
        invalid = true;
      payload = record;
      if (
        !invalid &&
        SESSION_ID.test(record.session_id ?? "") &&
        typeof record.is_error === "boolean" &&
        typeof record.subtype === "string"
      )
        progress.semantic();
      return;
    }
    if (!SESSION_ID.test(record.session_id ?? "")) return;
    if (record.type === "system" && record.subtype === "init") {
      if (payload !== null) {
        invalid = true;
      } else if (sessionId === undefined) {
        sessionId = record.session_id;
        if (!invalid) progress.semantic();
      }
      return;
    }
    if (sessionId !== undefined && record.session_id !== sessionId) return;
    if (
      payload !== null &&
      ["assistant", "user", "stream_event"].includes(record.type)
    ) {
      invalid = true;
      return;
    }
    if (sessionId === undefined || invalid || payload !== null) return;
    if (record.type === "system") {
      if (
        record.subtype === "task_started" &&
        record.task_type === "local_bash" &&
        identifier(record.task_id) &&
        commands.has(record.tool_use_id)
      ) {
        progress.start(JSON.stringify(["task", record.task_id]));
      } else if (
        record.subtype === "task_notification" &&
        identifier(record.task_id) &&
        ["completed", "failed", "stopped"].includes(record.status)
      ) {
        progress.complete(JSON.stringify(["task", record.task_id]));
      }
      return;
    }
    if (record.type === "stream_event") {
      const event = record.event;
      if (!isRecord(event)) return;
      if (
        event.type === "message_start" &&
        isRecord(event.message) &&
        event.message.role === "assistant" &&
        identifier(event.message.id)
      ) {
        messageId = event.message.id;
        blocks.clear();
        progress.semantic();
      } else if (messageId !== undefined && event.type === "message_stop") {
        messageId = undefined;
        blocks.clear();
        progress.semantic();
      } else if (
        messageId !== undefined &&
        Number.isSafeInteger(event.index) &&
        event.index >= 0
      ) {
        if (
          event.type === "content_block_start" &&
          isRecord(event.content_block) &&
          ((event.content_block.type === "text" &&
            typeof event.content_block.text === "string") ||
            (event.content_block.type === "thinking" &&
              typeof event.content_block.thinking === "string") ||
            (event.content_block.type === "tool_use" &&
              identifier(event.content_block.id) &&
              typeof event.content_block.name === "string" &&
              isRecord(event.content_block.input)))
        ) {
          if (blocks.has(event.index)) return;
          if (blocks.size >= 1024) throw protocolError();
          blocks.set(event.index, event.content_block.type);
          progress.semantic();
        } else if (
          event.type === "content_block_stop" &&
          blocks.delete(event.index)
        ) {
          progress.semantic();
        } else if (
          event.type === "content_block_delta" &&
          isRecord(event.delta)
        ) {
          const { type } = event.delta;
          const field = DELTA_FIELDS.get(type);
          if (
            field &&
            blocks.get(event.index) === field[0] &&
            typeof event.delta[field[1]] === "string" &&
            event.delta[field[1]].length > 0
          )
            progress.semantic();
        }
      }
      return;
    }
    const message = record.message;
    if (!isRecord(message) || !Array.isArray(message.content)) return;
    if (
      record.type === "assistant" &&
      message.role === "assistant" &&
      identifier(message.id)
    ) {
      for (const block of message.content) {
        if (!isRecord(block)) continue;
        if (
          block.type === "tool_use" &&
          identifier(block.id) &&
          typeof block.name === "string" &&
          isRecord(block.input)
        ) {
          if (
            block.name === "Bash" &&
            typeof block.input.command === "string"
          ) {
            if (!commands.has(block.id) && commands.size >= 16_384)
              throw protocolError();
            commands.add(block.id);
            progress.start(JSON.stringify(["tool", block.id]));
          } else if (
            ["Read", "Edit", "Write", "Glob", "Grep"].includes(block.name)
          )
            progress.start(JSON.stringify(["tool", block.id]), false);
        } else if (
          (block.type === "text" &&
            typeof block.text === "string" &&
            block.text.length > 0) ||
          (block.type === "thinking" &&
            typeof block.thinking === "string" &&
            block.thinking.length > 0)
        )
          progress.semantic();
      }
    } else if (record.type === "user" && message.role === "user") {
      for (const block of message.content) {
        if (
          isRecord(block) &&
          block.type === "tool_result" &&
          identifier(block.tool_use_id) &&
          (block.is_error === undefined ||
            typeof block.is_error === "boolean") &&
          (block.content === undefined ||
            typeof block.content === "string" ||
            Array.isArray(block.content))
        ) {
          progress.complete(JSON.stringify(["tool", block.tool_use_id]));
        }
      }
    }
  }

  function line(source) {
    if (Buffer.byteLength(source) > MAX_LINE_BYTES) throw protocolError();
    if (source.trim().length === 0) return;
    let record;
    try {
      record = JSON.parse(source);
    } catch {
      invalid = true;
      return;
    }
    if (!isRecord(record) || typeof record.type !== "string") {
      hasRecords ||= isRecord(record);
      invalid = true;
      return;
    }
    hasRecords = true;
    try {
      observe(record);
    } catch {
      throw protocolError();
    }
  }

  function write(chunk) {
    if (finished) throw protocolError();
    bytes += Buffer.byteLength(chunk);
    if (bytes > MAX_STREAM_BYTES) throw protocolError();
    try {
      buffer += decoder.decode(
        Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
        { stream: true },
      );
    } catch {
      throw protocolError();
    }
    let end;
    while ((end = buffer.indexOf("\n")) !== -1) {
      const source = buffer.slice(0, end);
      buffer = buffer.slice(end + 1);
      line(source);
    }
    if (Buffer.byteLength(buffer) > MAX_LINE_BYTES) throw protocolError();
  }

  return Object.freeze({
    get hasRecords() {
      return hasRecords;
    },
    write,
    finish(fallback = "") {
      if (!finished) {
        // Injected process executors may provide only their bounded final output.
        if (bytes === 0) write(fallback);
        try {
          buffer += decoder.decode();
        } catch {
          throw protocolError();
        }
        line(buffer);
        buffer = "";
        finished = true;
      }
      return payload;
    },
    assertValid() {
      if (invalid || payload === null) throw protocolError();
    },
    retire() {
      try {
        progress.retire();
      } catch {
        throw protocolError();
      }
    },
  });
}
