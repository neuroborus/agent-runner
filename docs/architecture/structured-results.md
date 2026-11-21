# Structured Result Headroom

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

All registered pipelines accept structured role results through exactly 2 MiB
(2,097,152 bytes) of serialized UTF-8 JSON, rejecting one-byte overflow before
acceptance. Semantic text, item, path, inventory, dispute, and correction bounds
remain independent and unchanged. New size diagnostics use
`maximum-2-mebibytes`; persisted `maximum-256-kibibytes` diagnostics remain valid
historical evidence and are not rewritten.

The common state envelope permits 32 MiB of compact serialized JSON. Polishing
also enforces a 24 MiB whole-run budget: twelve result-sized slots accommodate
both role inventories, derived catalogs, finalization and review copies, and
bookkeeping, including common metadata. Both budgets apply to the complete run.
These are finite aggregate safety ceilings, not permission to enlarge semantic fields or
retain rejected output. Persisted evidence validates its individual fields and
runner provenance without reapplying the raw-result ceiling to augmented copies.

Adapter prompts and complete recovery prompts each permit 32 MiB so accepted
results, derived inventories, and reconstruction context have enclosing
headroom. Schema input remains capped at 1 MiB. Codex protocol lines and Claude
stream lines retain their 16 MiB bounds, sufficient for JSON string escaping and
Claude's duplicated text/structured terminal envelope; Claude retains its 64 MiB
stream/process bound. Native protocol limits still apply to unrelated traffic.

Codex hydrates a summarized or unloaded completion with one
`thread/turns/list` request (`limit: 1`, descending, `itemsView: "full"`),
requiring the exact completed turn ID and full terminal item view before
acceptance or native failure refinement. Missing, mismatched, partial, or
multiple turns fail closed without replay. The complete current turn remains
subject to the existing protocol cap and item audit; prior results cannot
inflate the response. Continuations and source forks request
`excludeTurns: true`, preserving native context and fork lineage without
returning history.
These fields were verified against Codex CLI 0.163.0's model-free public
`app-server generate-ts` contract; no pagination is added to `thread/read`.

Runner context artifacts contain only summaries of at most 20,000 characters,
so their 1 MiB cap remains sufficient. Configuration, clarification, and MCP
action caps do not carry complete role results and remain unchanged. Public
CLI/MCP projections retain their bounded summaries and diagnostics rather than
exposing larger private results. Byte headroom is neither a token budget nor a
native generation control; missing usage and incomplete accounting stay unknown.
