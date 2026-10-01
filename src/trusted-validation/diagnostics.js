// Output is untrusted. Only these finite labels can cross the evidence boundary.
const ERROR_CLASSES = new Set([
  "AssertionError",
  "SyntaxError",
  "TypeError",
  "ReferenceError",
  "RangeError",
  "ERR_ASSERTION",
  "ERR_TEST_FAILURE",
  "ERR_MODULE_NOT_FOUND",
  "ENOENT",
  "EACCES",
  "EPERM",
  "EADDRINUSE",
  "ECONNREFUSED",
  "ERR_EXECUTION_ISOLATION_UNAVAILABLE",
  "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  "ERR_EXECUTION_PROCESS_ACTIVE",
  "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE",
  "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE",
  "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY",
  "ERR_TRUSTED_VALIDATION_BINDING_CHANGED",
]);
const STAGES = new Set(["formatting", "tests"]);
const OMITTED =
  "Trusted check diagnostics omitted unsupported, unsafe, malformed or oversized output.";
const MAX_CANDIDATES = 8;
const MAX_EVIDENCE_BYTES = 1024;
const MAX_LINE_BYTES = 2048;
const DECODE_BYTES = 1024;
const errorEvidence = (value) => `Trusted check error class: ${value}.`;
const stageEvidence = (value) => `Trusted check failed stage: ${value}.`;
const SAFE_EVIDENCE = new Set([
  ...[...ERROR_CLASSES].map(errorEvidence),
  ...[...STAGES].map(stageEvidence),
  OMITTED,
]);

export function isFailureDiagnostic(value) {
  return typeof value === "string" && SAFE_EVIDENCE.has(value);
}

export function normalizeFailureDiagnostics(value = []) {
  if (
    !Array.isArray(value) ||
    value.length > MAX_CANDIDATES + 1 ||
    (value.length === MAX_CANDIDATES + 1 && !value.includes(OMITTED)) ||
    [...value].some((entry) => !isFailureDiagnostic(entry)) ||
    new Set(value).size !== value.length ||
    Buffer.byteLength(value.join("\n")) > MAX_EVIDENCE_BYTES
  ) {
    throw new TypeError("Invalid normalized trusted-check diagnostics.");
  }
  return Object.freeze([...value]);
}

function recognize(line) {
  // Native Node errors and node:test YAML carry classes, never safe messages.
  const error =
    /^(AssertionError|SyntaxError|TypeError|ReferenceError|RangeError|Error)(?: \[([A-Z_]+)\])?:/u.exec(
      line,
    );
  const code = /^[ \t]{2,12}(?:code|name): ['"]([A-Za-z_]+)['"]$/u.exec(line);
  const value = ERROR_CLASSES.has(error?.[2])
    ? error[2]
    : (error?.[1] ?? code?.[1]);
  if (ERROR_CLASSES.has(value)) return errorEvidence(value);
  if (
    /^[ \t]{2,12}failureType: '(?:testCodeFailure|subtestsFailed|hookFailed)'$/u.test(
      line,
    ) ||
    /^test at [^\r\n]{1,256}\.test\.js:\d+:\d+$/u.test(line) ||
    /^Failure diagnostics: (?:test|pipelines|packages)\/[^\r\n]{1,256}\.test\.js$/u.test(
      line,
    )
  ) {
    return stageEvidence("tests");
  }
  if (
    /^\[warn\] Code style issues found in (?:the above files?|[1-9][0-9]{0,5} files?)\. Run Prettier with --write to fix\.$/u.test(
      line,
    ) ||
    /^\[error\] [^\r\n]{1,256}: SyntaxError:/u.test(line)
  ) {
    return stageEvidence("formatting");
  }
  return null;
}

export function createDiagnosticCollector() {
  const candidates = new Set();
  const streams = new Map();
  let omitted = false;
  let active = true;
  function accept(state) {
    if (state.oversized) {
      omitted = true;
    } else {
      // Only complete SGR color sequences are removable. Other controls, OSC,
      // invalid UTF-8 and carriage-return rewriting make a line unusable.
      const line = state.line
        .replace(/\r$/u, "")
        .replace(/\x1b\[[0-9;]{0,32}m/gu, "");
      if (line.length > 0) {
        const diagnostic =
          /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ufffd]/u.test(
            line,
          )
            ? null
            : recognize(line);
        if (diagnostic === null) omitted = true;
        else {
          candidates.delete(diagnostic);
          candidates.add(diagnostic);
          while (
            candidates.size > MAX_CANDIDATES ||
            Buffer.byteLength([...candidates, OMITTED].join("\n")) >
              MAX_EVIDENCE_BYTES
          ) {
            candidates.delete(candidates.values().next().value);
            omitted = true;
          }
        }
      }
    }
    state.line = "";
    state.bytes = 0;
    state.oversized = false;
  }
  function decoded(state, text) {
    const parts = text.split("\n");
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index];
      if (!state.oversized) {
        state.bytes += Buffer.byteLength(part);
        if (state.bytes > MAX_LINE_BYTES) {
          state.line = "";
          state.oversized = true;
        } else state.line += part;
      }
      if (index < parts.length - 1) accept(state);
    }
  }
  return {
    write(stream, chunk) {
      if (!active) return;
      if (!Buffer.isBuffer(chunk)) {
        omitted = true;
        return;
      }
      let state = streams.get(stream);
      if (state === undefined) {
        if (streams.size === 2) {
          omitted = true;
          return;
        }
        state = {
          decoder: new TextDecoder(),
          line: "",
          bytes: 0,
          oversized: false,
        };
        streams.set(stream, state);
      }
      // Never decode an unbounded chunk or stop draining after a limit is hit.
      for (let offset = 0; offset < chunk.length; offset += DECODE_BYTES) {
        decoded(
          state,
          state.decoder.decode(chunk.subarray(offset, offset + DECODE_BYTES), {
            stream: true,
          }),
        );
      }
    },
    finish() {
      if (active) {
        for (const state of streams.values()) {
          decoded(state, state.decoder.decode());
          accept(state);
        }
        streams.clear();
        active = false;
      }
      return normalizeFailureDiagnostics([
        ...candidates,
        ...(omitted ? [OMITTED] : []),
      ]);
    },
    discard() {
      active = false;
      streams.clear();
      candidates.clear();
    },
  };
}
