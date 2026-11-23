# Polishing Handoff

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Handoff And Completion Gate

Completion requires:

```text
candidate review == APPROVED or candidate clean confirmation == CLEAN
finalization == PASS
open findings == 0
current content fingerprint == finalized fingerprint
current content fingerprint == reviewed fingerprint
terminal confirmation validation change == UNCHANGED or ACCEPTED
independent: unresolved disputes == 0 and pending arbitration == false
lazy: candidate and terminal clean-confirmation fingerprints are recorded
HEAD and repository control fingerprints == recorded baseline
```

After this staging-independent gate passes, the pipeline persists `HANDOFF`
before any index effect. The root Git boundary first requires the current
content fingerprint to equal both recorded fingerprints and verifies the
expected index, `HEAD`, branch/detached state, refs, remotes, and Git identity.
It then accepts only one of two recovery states: an already-complete verified
handoff, or the exact unchanged pre-effect state on which it runs `git add -A`.
Immediately before that add it repeats the staging-independent hygiene
inspection with full control, content and index rebinding; whitespace rejects
with `ERR_POLISHING_HANDOFF_UNSTAGED_WHITESPACE` and no index write.
An incomplete or contaminated index fails closed.

Handoff-owned staging and direct Git inspection calls disable hooks with the
fixed invocation prefix `-c core.hooksPath=/dev/null`. The runner never executes
workspace hooks during handoff or rewrites hook configuration. Shared Git
defaults, observational snapshot/content helpers and optional-lock controls
remain unchanged; ignored hook bytes are not added to accepted fingerprints.
This policy grants no agent index authority and does not alter authorized
commit hooks in plan execution. Completed recovery remains inspection-only.

Before returning the post-effect snapshot, the Git boundary reverifies content
and every Git control, requires a nonempty staged diff whose staged content is
the complete tracked and non-ignored untracked change set, requires no unstaged
or non-ignored untracked remnants, and runs staged-diff whitespace hygiene. The
pipeline updates its baseline and enters `DONE` only after those postconditions
pass. It never invokes `local-commit` access or creates a commit.

A whitespace rejection at `HANDOFF` is terminal. This covers the pre-effect
`ERR_POLISHING_HANDOFF_UNSTAGED_WHITESPACE` and the late
`ERR_POLISHING_HANDOFF_WHITESPACE`, which means complete Runner staging exists
and failed staged hygiene. The run enters `FAILED` with exactly
`{ reason: "handoff_whitespace_rejected", code }` and otherwise unchanged state.
Because handoff recovery is inspection-only, nothing is reset, unstaged,
restaged or replayed and no role checkpoint reopens; an interrupted `HANDOFF`
re-inspects and reaches the same disposition without staging. The shared
CLI/MCP projection explains that the run cannot resume and states the index
effect: none, or retained Runner staging. The operator repairs the whitespace
and starts a new polishing run. Contamination, incompleteness and other causes
keep `internal_failure`; legacy `internal_failure` whitespace histories remain
valid and project unchanged.

Completeness uses the Git capability's shared compatible-domain proof: reproduce
accepted confined worktree content, reject hidden flags across the staged/worktree
changed-path union, then accept exact stored bytes or matching complete paths,
kinds, modes and deletion states with helper-free check-in proof for unequal
regular files. Unchanged hidden paths outside that union are not a blanket
handoff rejection. Index stat metadata and unstaged-clean status are insufficient.
Unequal bytes support only SHA-1 and native explicit `text`, `text eol=lf` or
`text eol=crlf`; automatic/ambiguous text, filters (including LFS), ident and
encoding remain excluded. The [Git hashing boundary](../../../docs/ARCHITECTURE.md)
requires external scratch separation from worktree and all Git controls before
allocation, isolated discovery/configuration, verified bindings and awaited
owned cleanup. Neither conversion nor recovery grants another staging effect.
