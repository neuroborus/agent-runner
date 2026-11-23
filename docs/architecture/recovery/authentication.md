# Durable authentication-required pauses

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

The runner injects one provider-neutral authentication policy into all registered
pipelines. It accepts only a strict normalized adapter failure carrying
`disposition: "authentication_required"`; raw messages, diagnostic classes,
HTTP evidence, and provider-specific codes cannot activate the policy.
Authentication is an operator action, not availability: the runner schedules
no retry or backoff and persists no availability episode. When it supersedes an
active availability retry, that episode is retired before the authentication
pause is persisted.

After provider execution retires, each pipeline applies its ordinary repository
guard. Writable execution and polishing turns reconcile safe partial content,
invalidate stale fingerprint-bound approvals, and preserve correction charging.
One durable transition retires the active turn, saves any source-fork recovery
marker, and enters `WAITING_FOR_USER`; interrupted publication cannot leave a
finished turn without its authentication checkpoint. The pause contains exactly
`authentication_required`, `ERR_AUTHENTICATION_REQUIRED`, and the current
logical resume state. Role configuration, source and child session lineage,
content fingerprints, findings, and counters stay in their existing durable
fields. After the operator reauthenticates, a null resume reconstructs that
same checkpoint without requiring the failed native session. A partially
completed finding-resolution turn retains its writable access even when its
already charged round reached the fix budget; completing that round does not
consume another round or authorize a new one.

Authentication during an initial source-session fork additionally preserves a
nullable provider-neutral recovery marker containing only the logical role and
context key. Proof that the rejected request had no effect permits the source
fork to be retried. Possible-effect evidence instead persists the marker and
reconstructs the same role in a fresh session, never reforking a source whose
native child may already exist. The marker survives repeated authentication or
interruption and clears only after a child session is durably recorded.
If interruption precedes pause publication, authentication during fresh
recovery retains the earlier unrecorded fork's possible effect even when the
new request proves no effect.

Local-commit readiness remains effect-safe. The disposition qualifies only
when the normalized record also proves `commitExecutor: "not_started"`.
Plan execution persists that bounded proof with the consumed authorization,
performs the existing Git verification-only path, and retires the authorization
only after Git proves no commit. It then pauses at `COMMIT`; uncertain or
started effects never become authentication retries. Polishing handoff remains
runner-owned and uses its existing staged-effect verification path.

Plan-authoring state version 6, plan-execution version 26, and polishing
version 18 admit these new pause, proof, and source-fork recovery variants.
Their immediately prior migrations initialize the nullable recovery marker to
`null` while preserving workflow position, existing session lineage, evidence,
and correction accounting. They do not reload configuration or infer a native
child. The version bump makes older readers reject rather than misread the new
durable checkpoint.
