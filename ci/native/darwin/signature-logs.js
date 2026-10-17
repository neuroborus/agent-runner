import {
  hasNativeDiagnostics,
  nativeDiagnosticCompletion,
  withNativeDiagnostics,
} from "../diagnostics.js";
import {
  denialEvents,
  readDarwinUnifiedLog,
  startupTimestamp,
} from "./startup-crash.js";

const PREFIX = "native-darwin-signature-call: ";
const VALIDITY_PREFIX = "native-darwin-signature-validity: ";
const FIELDS = [
  "pid",
  "birthAvailable",
  "birth",
  "credentials",
  "auditAvailable",
  "auditToken",
  "startAvailable",
  "start",
  "endAvailable",
  "end",
  "status",
];
const CREDENTIALS = ["uid", "gid", "ruid", "rgid", "svuid", "svgid"];
const uint = (value) =>
  Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
const vector = (value, length) =>
  Array.isArray(value) && value.length === length && value.every(uint);
const stamp = (value, precision = 1000000000) =>
  Array.isArray(value) &&
  value.length === 2 &&
  Number.isSafeInteger(value[0]) &&
  value[0] >= 0 &&
  value[0] <= 253402300798 &&
  Number.isInteger(value[1]) &&
  value[1] >= 0 &&
  value[1] < precision;
const nanos = ([seconds, fraction]) =>
  BigInt(seconds) * 1000000000n + BigInt(fraction);
const date = (seconds) =>
  new Date(Number(seconds) * 1000)
    .toISOString()
    .slice(0, 19)
    .replace("T", " ") + "+0000";

function binding(sample, caller, status, deadlineMs) {
  if (
    !sample ||
    !caller ||
    Object.keys(sample).length !== FIELDS.length ||
    !FIELDS.every((key) => Object.hasOwn(sample, key)) ||
    sample.status !== status ||
    !Number.isInteger(status) ||
    !status ||
    status < -2147483648 ||
    status > 2147483647 ||
    sample.pid !== caller.pid ||
    sample.birthAvailable !== 1 ||
    !stamp(sample.birth, 1000000) ||
    sample.birth[0] !== caller.startSeconds ||
    sample.birth[1] !== caller.startMicroseconds ||
    !vector(sample.credentials, 6) ||
    !CREDENTIALS.every((key, i) => sample.credentials[i] === caller[key]) ||
    ![0, 1].includes(sample.auditAvailable) ||
    !vector(sample.auditToken, 8) ||
    sample.startAvailable !== 1 ||
    sample.endAvailable !== 1 ||
    !stamp(sample.start) ||
    !stamp(sample.end)
  )
    return null;
  const token = sample.auditToken;
  if (
    sample.auditAvailable &&
    (token[5] !== caller.pid ||
      token[0] !== caller.auid ||
      token[6] !== caller.asid ||
      token[7] !== caller.pidVersion ||
      !sample.credentials
        .slice(0, 4)
        .every((value, i) => value === token[i + 1]))
  )
    return null;
  const start = nanos(sample.start),
    end = nanos(sample.end);
  if (
    start <
      BigInt(sample.birth[0]) * 1000000000n + BigInt(sample.birth[1]) * 1000n ||
    end < start ||
    end - start > BigInt(deadlineMs) * 1000000n
  )
    return null;
  // log's documented date selectors have whole-second precision. Keep the exact
  // native interval and explicitly retain the outward-rounding uncertainty.
  return { first: start / 1000000000n, last: (end + 999999999n) / 1000000000n };
}

/** Only the original build admission transport installs this stderr observer. */
export function darwinSignatureDiagnostics({
  deadlineMs,
  now = () => performance.now(),
  run,
  platform = process.platform,
  arch = process.arch,
  env = process.env,
} = {}) {
  if (
    !hasNativeDiagnostics() ||
    platform !== "darwin" ||
    arch !== "x64" ||
    env.CI !== "true" ||
    env.GITHUB_ACTIONS !== "true" ||
    env.ImageOS !== "macos15" ||
    env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    env.RUNNER_OS !== "macOS"
  )
    return;
  let until;
  try {
    until = now() + deadlineMs;
  } catch {
    /* An unavailable clock cannot gate admission. */
  }
  let caller,
    sample,
    status,
    line = "",
    sampleSeen = false,
    validitySeen = false,
    oversized = false,
    invalid = false,
    closed = false,
    sealed = false,
    pending;
  const sink = nativeDiagnosticCompletion(() => {
    sealed = true;
    return complete();
  });
  const publish = (owner, value) => {
    try {
      sink(owner, value);
    } catch {
      /* Best effort. */
    }
  };
  const outcome = (value) =>
    publish("darwin-signature-logs", {
      stderr: JSON.stringify({ signatureLogs: value }),
    });
  const complete = () =>
    (pending ??= (async () => {
      if (status === undefined && !sampleSeen && !invalid) return;
      const window =
        !invalid &&
        closed &&
        !line &&
        binding(sample, caller, status, deadlineMs);
      if (!window)
        return outcome({ status: "unavailable", reason: "original-binding" });
      const metadata = {
        caller: {
          pid: sample.pid,
          birth: sample.birth,
          credentials: sample.credentials,
          auditAvailable: sample.auditAvailable,
          auditToken: sample.auditToken,
        },
        start: sample.start,
        end: sample.end,
        queryStart: date(window.first),
        queryEnd: date(window.last),
        uncertainty:
          "outward-rounded-to-seconds; log-side-birth-and-context-unjoined",
      };
      const remaining = Math.floor(until - now());
      if (!(remaining > 0))
        return outcome({
          ...metadata,
          status: "unavailable",
          reason: "budget",
        });
      let result,
        failed = false,
        clipped = false,
        observationFailed = false;
      const captured = { stdout: 0, stderr: 0 },
        streamed = { stdout: 0, stderr: 0 };
      // Reuse command observation without letting a sink exception escape an I/O
      // callback. Bound publication as well as execFile's retained capture.
      const querySink = (owner, value) => {
        const seen = new Set();
        let replay =
          Object.hasOwn(value, "exception") || Object.hasOwn(value, "exitCode");
        for (
          let detail = value?.exception ?? value;
          detail && typeof detail === "object" && !seen.has(detail);
          detail = detail.cause
        ) {
          seen.add(detail);
          for (const stream of ["stdout", "stderr"]) {
            const bytes = detail[stream];
            if (!Buffer.isBuffer(bytes) && typeof bytes !== "string") continue;
            const bytesSeen = replay
              ? Math.min(streamed[stream], Buffer.byteLength(bytes))
              : 0;
            // execFile failure captures repeat the prefix already streamed by its
            // child. Suppressing that replay is not truncation of query output.
            const data = Buffer.from(bytes).subarray(bytesSeen),
              take = Math.min(data.length, 65536 - captured[stream]);
            if (!replay) streamed[stream] += data.length;
            if (take) publish(owner, { [stream]: data.subarray(0, take) });
            captured[stream] += take;
            clipped ||= take < data.length;
          }
          replay = false;
        }
      };
      const observeQuery = (owner, value) => {
        try {
          querySink(owner, value);
        } catch {
          observationFailed = true;
        }
      };
      try {
        result = await withNativeDiagnostics(
          () =>
            readDarwinUnifiedLog(
              [
                "--start",
                metadata.queryStart,
                "--end",
                metadata.queryEnd,
                "--info",
                "--debug",
                "--predicate",
                `processID == ${sample.pid}`,
              ],
              { run, timeout: Math.min(12000, remaining) },
            ),
          observeQuery,
        );
      } catch (error) {
        failed = true;
        result = error;
      }
      const completion = result?.error ?? result;
      const code = result?.exitCode ?? result?.status ?? completion?.code;
      failed ||= Boolean(
        result?.error ||
        completion?.signal ||
        completion?.timedOut ||
        completion?.killed ||
        (Number.isInteger(code) && code !== 0),
      );
      const source = result?.stdout ?? completion?.stdout;
      const available = Buffer.isBuffer(source) || typeof source === "string";
      const stdout = available ? Buffer.from(source) : Buffer.alloc(0);
      const truncated =
        clipped ||
        stdout.length > 65536 ||
        Boolean(completion?.truncated) ||
        ["ENOBUFS", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"].includes(
          completion?.code,
        );
      const partial =
        truncated ||
        observationFailed ||
        Boolean(completion?.partial) ||
        (failed &&
          (stdout.length > 0 || captured.stdout > 0 || captured.stderr > 0));
      const records = denialEvents(
        stdout.length > 65536
          ? stdout.subarray(0, 65536)
          : available
            ? source
            : stdout,
      );
      const mismatched = records.events?.some((event) => {
        const time = startupTimestamp(event.timestamp).time;
        return (
          event.processID !== sample.pid ||
          time < window.first * 1000000n ||
          time > window.last * 1000000n
        );
      });
      outcome({
        ...metadata,
        status:
          failed || observationFailed
            ? "error"
            : !available
              ? "unavailable"
              : truncated
                ? "truncated"
                : partial
                  ? "partial"
                  : records.status || mismatched
                    ? "error"
                    : records.events.length
                      ? "available"
                      : "empty",
        reason: failed
          ? "command"
          : observationFailed
            ? "observation"
            : !available
              ? "stdout"
              : mismatched
                ? "log-binding"
                : records.status
                  ? "log-record"
                  : null,
        partial,
        truncated,
        timedOut:
          typeof completion?.timedOut === "boolean"
            ? completion.timedOut
            : null,
        killed: completion?.killed === true,
        signal:
          typeof completion?.signal === "string" &&
          completion.signal.length <= 32
            ? completion.signal
            : null,
        exitCode: Number.isInteger(code) ? code : failed ? null : 0,
      });
    })().catch(() =>
      outcome({ status: "unavailable", reason: "diagnostic-error" }),
    ));
  return {
    bind(value) {
      try {
        if (caller) invalid = true;
        else caller = structuredClone(value);
      } catch {
        invalid = true;
      }
    },
    diagnostics(owner, value) {
      publish(owner, value);
      if (sealed) return;
      try {
        if (value.stderr !== undefined)
          for (const byte of Buffer.from(value.stderr)) {
            if (byte !== 10) {
              if (line.length < 1024) line += String.fromCharCode(byte);
              else oversized = true;
              continue;
            }
            if (line.startsWith(PREFIX)) {
              if (sampleSeen || oversized) invalid = true;
              sampleSeen = true;
              if (!invalid) {
                const bytes = line.slice(PREFIX.length);
                sample = JSON.parse(bytes);
                // Native printf emits canonical integer JSON. Reject duplicate keys
                // and precision-changing conversion instead of accepting a last value.
                if (
                  !sample ||
                  typeof sample !== "object" ||
                  Array.isArray(sample) ||
                  JSON.stringify(sample) !== bytes
                )
                  invalid = true;
              }
            } else if (line.startsWith(VALIDITY_PREFIX)) {
              if (validitySeen || oversized) invalid = true;
              validitySeen = true;
              const text = line.slice(VALIDITY_PREFIX.length);
              if (text !== "uncalled") {
                const value = Number(text.slice("status=".length));
                if (!Number.isInteger(value) || `status=${value}` !== text)
                  invalid = true;
                if (value !== 0) status = value;
              }
            }
            line = "";
            oversized = false;
          }
        if (Object.hasOwn(value, "exitCode")) {
          closed = true;
          complete();
        }
      } catch {
        invalid = true;
      }
    },
  };
}
