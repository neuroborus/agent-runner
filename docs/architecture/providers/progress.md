# Provider Turn Progress

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Progress Observer

Turn requests accept an optional synchronous `onProgress` observer. The shared
internal contract emits frozen `{ kind, activeCommands }` records only. Its
closed kinds are `semantic`, `local-command-started`,
`local-command-completed`, `local-tool-started`, and `local-tool-completed`.
The nonnegative command count covers overlapping commands independently of
other local tools. Provider-private identities correlate starts and completions;
duplicate starts/completions and unmatched completions cannot change the count.
Each attempt bounds its retained tool identities to 16,384 and retires remaining
activity only after process retirement. Progress carries no native identifiers,
payloads, commands, output, diagnostics, or timestamps. It is not public CLI/MCP
activity; the shared inactivity watchdog consumes it without changing availability
backoff or emitting native events publicly.
Observer failures are redacted; retirement reporting cannot replace an already
established provider failure.

## Native Progress and Stream Validation

Codex derives progress from validated, matching thread/turn notifications for
turn and item lifecycle events and nonempty text/reasoning/plan deltas. Up to
1,024 payload-free facts can precede the `turn/start` reply; only facts matching
the returned turn are delivered. Command-output deltas, unrelated turns,
keepalives, and unknown traffic provide no semantic progress. Final turn-item
auditing and failure classification remain authoritative.

Claude consumes UTF-8 JSONL using `--output-format stream-json --verbose
--include-partial-messages`. The private parser bounds each line to 16 MiB and
the complete stdout stream to 64 MiB, validates message/block/session envelopes,
and retains one terminal result for the existing structured-output, permission,
failure, model, and session-lineage checks. Partial tool-input generation is
semantic progress; a complete Bash tool-use starts command activity, and its
matching tool-result completes it. Recognized background Bash tasks have their
own correlated lifetimes. File tools report separate start/completion events.
Token accounting, tool-progress heartbeats, and irrelevant records do not emit
progress. Malformed, duplicate, or missing results cannot become success;
permission failures and uncertain killed-process outcomes retain precedence.
A `system/init` after the result must match the session already established by
the earlier init or the result: a matching init is idempotent metadata, a
conflicting init rejects, and the stream is still consumed to EOF. Another
result rejects as `protocol_result_duplicate`. Post-result assistant, user, and
stream-event records reject as `protocol_assistant_after_result`,
`protocol_user_after_result`, and `protocol_stream_event_after_result`,
respectively, without reading their payload fields. Existing session guards and
first-violation precedence remain unchanged; other trailing system records keep
their existing handling.
Before the result, a session-matched `system/permission_denied` event with a
valid `tool_use_id` records only its tool name and a closed
`decision_reason_code`; an absent, unrecognized or non-string code, or an
`agent_id`, records an unknown reason, a repeated id records a conflict, and
more than 16,384 ids make every reason unknown without failing the stream. Free
text such as `decision_reason`, `message` and `uuid` is never read. The frozen
`permissionReason` lookup answers only after `finish()`, and only when the
stream has no protocol violation or identity uncertainty, its lineage-checked
session equals both the final result's and the caller's session, and the entry
is unique, unconflicted, known and for the same tool name.
Each protocol guard attaches a terminal `protocol_*` diagnostic class from one
private stream table for the first predicate it proved violated: invalid JSON,
record, or UTF-8; line, stream, or tracking bounds; a missing, duplicate, or
post-result record; session, continuation, or fork-lineage mismatch;
unavailable fork lineage; denied results without a valid session; or retirement
and observation observer failure. After a failed process exit, only the exact
success envelope is classified as success; any other non-error payload is only
an invalid error result. Exceptions from progress callbacks or the shared
progress bound and write-after-finish remain unattributed. The classes change
no acceptance, retry, cleanup, or local-commit effect proof.
The historical `protocol_record_after_result` class remains registered for
persisted diagnosis and recovery, but the parser no longer emits it. Only closed
classes cross public or durable boundaries; rejected native records and
transcripts are never retained there.
Owned process capture delivers bounded stdout chunks without bypassing durable
registration, containment, cancellation, retirement, or storage cleanup.
