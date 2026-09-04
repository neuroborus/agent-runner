# Safety Model

Agent Runner treats repository content, Git control state, durable state, and
provider execution as separate trust boundaries. Convenience never overrides
proof of ownership or an unchanged accepted fingerprint.

## Repository permissions

Each role turn receives the narrowest access required by its phase:

- clarification, bootstrap, compatibility, review, confirmation,
  reconsideration, and arbitration are read-only;
- implementation, polishing, finalization, finding resolution, and lazy
  check-and-fix may change safe workspace content only;
- plan execution's constrained commit executor is a separate one-shot effect;
- polishing staging is a runner-owned handoff effect, not an agent permission.

The runner snapshots content, index state, `HEAD`, branch or detached context,
local refs, remotes, and Git identity around turns. Read-only mutation is a
safety failure. Writable turns still reject index, history, ref, remote, or
identity changes. The runner never discards unexpected user work
automatically.

## Git ownership

Plan execution permits exactly one ordinary local commit for each validated
plan step. Only the Worker may trigger it, only after the fingerprint-bound
gate, and only with a fresh one-shot authorization. The commit must use the
exact subject from the plan, the existing Git identity, and no body, footer, or
authorship trailer.

Polishing never commits and keeps `HEAD` unchanged. Its handoff stages the
complete finalized and reviewed change set, verifies that nothing accepted was
left unstaged, and leaves the result for the operator.

No pipeline may push, mutate a remote ref, call a hosting service to write,
change a remote, alter Git identity, amend, reset, rebase, stash, switch
branches, or create tags. A failed hook or unexpected repository state pauses
instead of being bypassed.

## Inputs, artifacts, and state

Task, plan, context, and clarification inputs are hashed and revalidated before
recovery. Clarification writes occur only through a persisted one-shot editor
or MCP authorization. Repository-local artifacts must be confined, ignored,
and non-overlapping with protected inputs.

Authoritative run state is external to both repository and task. Atomic files,
write-ahead events, owner-token leases, canonical paths, link checks, and
bounded schemas make interruption recoverable without trusting a half-written
file or a surviving native session.

## Effect reconciliation

Intent is durable before any commit, handoff, editor, or MCP mutation. If a
process stops after an effect may have started, recovery inspects the observed
state before acting. A consumed commit authorization stays on a verification-
only path; it is never replayed. A handoff may be accepted as already complete
or retried only from its exact unchanged pre-effect state. Ambiguous partial
effects fail closed.

Content changes invalidate finalization and review evidence. A commit or
handoff proceeds only when current content and validation infrastructure still
match the accepted fingerprints and no mutation can occur between the final
read-only gate and the runner-owned effect.

## Redaction and provider isolation

Native provider output is untrusted. Adapters validate and normalize it before
pipeline policy sees it, and public surfaces retain only bounded structured
summaries and allowlisted failure classes. Credentials, authorization data,
cookies, tokens, prompts, transcripts, denied commands, raw responses,
standard error, and chain-of-thought are neither logged nor persisted.

Provider sandboxes deny remote writes and Git metadata writes according to the
turn's access mode. Collaboration or subagent activity is forbidden for role
turns and fails closed when detected. An existing real project `.agents`
directory is eligible workspace content during Codex writable turns; a
symlinked `.agents` and the Git-control `.git` and provider-control `.codex`
paths remain protected. Eligibility does not imply task scope: role prompts
allow project `.agents` changes only when the user explicitly requests them,
and plan execution also requires the current planned commit to do so. A
violation is corrected through the normal finding loop rather than a user
question. The runner does not broaden network, filesystem, process, or
host-service access to overcome a validation blocker.
