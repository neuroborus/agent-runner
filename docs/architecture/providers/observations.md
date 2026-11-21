# Provider Observations

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Turn requests also accept an optional synchronous `onObservation` consumer.
`src/agents/observations.js` owns the strict public
`normalizeProviderObservation` contract; native mapping stays in each provider.
Consumers receive frozen, payload-free records once an attempt is sealed, with
request-local `attempt` and `turn` ordinals (each bounded to three),
`kind: primary|recovery|compaction`, `outcome: completed|failed|incomplete`, and
`accounting: missing|incomplete|reported`. These are diagnostic observations,
not workflow state, progress, retry decisions, or proof of an effect. Without a
consumer, response shapes and execution selections are unchanged.

## Observation Contract and Native Mapping

`last` and `cumulative` are separate nullable snapshots; `cumulativeScope` is
`thread` or `attempt`. Each snapshot contains nullable `inputTokens`,
`cachedInputTokens`, `cacheWriteInputTokens`, `outputTokens`,
`reasoningOutputTokens`, and `totalTokens`. `contextCapacity` is separately
nullable. All numeric evidence must be nonnegative safe integers. Unknown
values remain null, including unavailable totals; snapshots are never summed.
`inputIncludesCached` and nullable `outputIncludesReasoning` preserve provider
inclusion rules: cached input and reasoning are never added again to inclusive
input/output counters. `commandCompletions` and `compactions` count deduplicated
observed facts, each bounded to 16,384; `factsIncomplete` marks rejected excess
facts. Retirement-generated progress never increments observed completions.

Codex maps public `thread/tokenUsage/updated` notifications. `last` describes
the last model request and `total` is cumulative thread usage, including cached
input within input and reasoning within output. Private exact thread/turn IDs
route up to 1,024 pre-reply facts and matching late usage, including earlier
turns in the same attempt, until sealing after transport shutdown. Compaction
binds to the adapter-validated completion identity, discards mismatching
provisional facts, and retains failed or interrupted compaction usage as
incomplete accounting without confirming successful compaction. Successful
confirmation and its native item count as one fact. Duplicate terminal frames
cannot revise the first correlated outcome.
Thread-cumulative snapshots must respect turn order; matching late earlier-turn
usage remains acceptable within the surrounding accepted totals. Last-request
counters cannot exceed their corresponding cumulative counters. Unrelated,
stale, malformed, unsafe numeric, and regressing cumulative evidence is rejected.
`reported` requires usage observed after a successful terminal notification;
earlier-only or failed-turn usage remains `incomplete`, and absent valid usage
is `missing`. Even a reported snapshot does not establish historical failed
response accounting. Internal compaction and retry turns retain distinct ordinals.

Claude rejects observation facts outside the selected continuation or fork
lineage. It maps its session-checked terminal result's `usage` to attempt-cumulative
input, cache-read, cache-creation, and output counters. Input excludes cache
counters; separate reasoning and total usage remain unknown. A single model's
reported context window may supply capacity; multiple models do not imply one
aggregate capacity. Successful terminal usage is `reported`; failed accounting
is incomplete. Bash tool results, correlated background task completions, and
validated compaction boundaries supply bounded facts. Neither provider exposes
native identities, model keys, commands, payloads, diagnostics, or timestamps in
observations. Consumer failures are redacted and cannot replace an established
protocol, ownership, isolation, permission, cleanup, or effect failure.
During Codex shutdown, bounded protocol parsing continues to collect matching
observation facts without dispatching progress or retaining more notifications.
Late server requests and malformed frames fail inside the client; subsequent
frames cannot replace the first protocol failure. Proven process retirement
clears outstanding progress even when shutdown reports a protocol error.

The installed Codex CLI 0.163.0 public schema was inspected using model-free
`app-server generate-json-schema`: `turn/start` has no numeric generation-budget
field. Context-window and effort controls are not generation-budget controls.
The [official model contract](https://developers.openai.com/api/docs/models/gpt-6.1-sol)
lists a 128,000 maximum output-token ceiling; it does not establish a Codex
override or an effective service cap for this execution. The reviewed source
context supplied that ceiling; live documentation retrieval was unavailable
during implementation. Effective output limits and historical failed-turn usage
remain unknown. No output-budget option or byte-to-token conversion is added.
