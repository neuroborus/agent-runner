# Execution Commit Authorization And Verification

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Commit gate

The runner may authorize the Worker commit turn only when all are true:

```text
finalization == PASS
open findings == 0
current content fingerprint == finalized fingerprint
current content fingerprint == reviewed fingerprint
review validation change == UNCHANGED or ACCEPTED, or independent exact whole-result override
independent: unresolved disputes == 0 and pending arbitration == false
lazy: clean confirmation fingerprint == current content fingerprint
HEAD == expected HEAD
current branch/ref context == expected branch/ref context
```

## Commit

Only the Worker creates the planned commit, and only in a dedicated one-shot
turn explicitly authorized by the runner after the commit gate passes. The
runner controls the transition and verifies the result; it does not run
`git commit` itself. The Worker's confirmation turn remains read-only. Only the
adapter's constrained local-commit executor stages content and creates the
commit.

Once the gate passes:

1. use the validated commit subject extracted from the plan heading without
   generating, rewriting, or extending it;
2. reject a message containing a `Co-authored-by` trailer, case-insensitively;
3. record the expected HEAD, branch/ref context, local refs, effective remote
   configuration and Git-identity fingerprints, and finalized/reviewed content
   fingerprint;
4. start or continue the Worker with a narrow readiness instruction, then have
   its constrained executor stage the current non-ignored workspace
   (`git add -A`), run fixed runner-owned unstaged-clean, staged-diff whitespace,
   and nonempty-diff hygiene, and create exactly one local commit using the
   exact supplied message;
5. require the Worker to use the repository's existing Git identity and prohibit
   changing `user.name`, `user.email`, author/committer metadata, commit-message
   hooks, remotes, branches, tags, or unrelated Git configuration;
6. verify the new commit is a direct, single-parent child of the expected HEAD
   on the expected branch and no other refs changed;
7. verify the committed tree exactly matches the finalized/reviewed content and
   that staging did not change its fingerprint;
8. verify the effective remote configuration and Git identity are unchanged and
   the commit's author/committer identity matches that baseline;
9. verify the final commit message exactly matches the supplied message with no
   `Co-authored-by` trailer;
10. verify no unexpected non-ignored working-tree or index changes remain;
11. persist the new SHA, mark the step completed, and continue to the next step.

After verification, the pipeline-owned checkpoint helper constructs the completed
SHA list and clean baseline, advances to the next step or `DONE`, and preserves
the established evidence-reset and counter rules. `runtime.settleVerifiedCommit`
then asks state to publish that checkpoint under the execution lease. The latest
stop request is inspected inside the same mutation boundary: verified progress,
active-turn retirement, consumed-authorization retirement, and any applicable
operator outcome share one journal event. A superseding cancellation wins without
losing verified progress. No next Worker turn starts after a settled stop.
Protected project-configuration drift remains a blocker, including beneath an
operator pause at the final `DONE` boundary.

The ordinary path and consumed-effect recovery share `runCommitTurn` and its
checkpoint helper. Settlement never creates or retries a commit. If publication
is interrupted, propagate the error without overwriting possibly journaled
progress from a stale local snapshot; resume recovers the journal or repeats only
verification of the consumed effect. Deferred requests settle at this same
verified checkpoint, or at a quiescent fallback if the target cannot finish.

The authorization permits one ordinary local commit only. It does not permit
`commit --amend`, merge commits, rebases, resets, branch switches, tag creation,
or any other history/ref mutation.

If no commit is created, pause with `commit_failed`. Git-owned read-only
verification accepts unchanged HEAD as `ERR_COMMIT_NOT_CREATED` only with
unchanged controls and accepted content, and either the unchanged original index
or exact authorized full staging. Full staging must match complete staged paths,
blobs and modes through the Git capability's shared compatible-domain proof,
with ordinary stage-zero entries, no hidden/intent-to-add flags or resolve-undo
state, and unchanged bindings after inspection. The proof reproduces the accepted
confined worktree fingerprint, rejects hidden changed paths before exact-byte or
conversion acceptance, and permits unequal regular files only with the same
complete path/kind/mode/deletion structure and the actual staged check-in object
ID. Cached stat equality or an unstaged-clean result supplies no conversion proof.
Only SHA-1 native explicit `text`, `text eol=lf` and `text eol=crlf` are supported
for unequal bytes; ambiguous/automatic text, filters/LFS, ident and encoding fail
closed. The [Git hashing boundary](../../../docs/ARCHITECTURE.md) isolates helpers
and repository discovery and proves scratch separation from worktree and both
Git-control roots before allocation, rechecking bindings and awaiting owned
cleanup. Exact stored equality and whole-index semantic checks retain their
existing meaning, including permitted split-index bookkeeping. Incomplete,
mismatched or unsafe index effects remain `ERR_COMMIT_CONTRACT_VIOLATED`.
The missing-commit error's bounded `changes` is `[]` for an untouched index or
`["index"]` for authorized staging. For staged executor failure, preserve that
partial-effect evidence in the `commit_failed` pause, retain the consumed
authorization and original bindings, and leave completion history unchanged.
Repeated, interrupted or reconstructed resume only verifies: it cannot restage,
retry readiness or commit, renew authorization, accept different content or
complete a missing commit. Executor output exhaustion with observed staging
retains this same `commit_failed` disposition. No historical rejected pause is
automatically recovered by this classification.

If the adapter also proved
`effectStarted: false`, persist its bounded rejection metadata before Git
verification and durably retire the consumed authorization only after that
verification reports no commit and unchanged controls, content and original
index. Observed staging contradicts that proof, pauses
`commit_contract_violated`, and never permits retirement or retry. A
non-recoverable policy rejection remains
`commit_failed`; its bounded adapter diagnostic class, when present, is copied
into that pause, named by the authorization-retired activity, and projected as
`Adapter diagnostic: <class>.` without commands, paths, output, or native
messages. The provider-neutral [readiness refusal classes](../../../docs/product/PROVIDER_MODEL.md#isolation-and-effects)
instead expose their fixed violated constraint, or deliberate decline with an
unknown reason, plus bounded class evidence. After authorization retirement
they retain `commit_failed` and the private `COMMIT` checkpoint but expose a
null public resume state and `start-new-run` with requirement
`resolved-commit-readiness`. Explicit same-run resume is rejected. Preserve the
reviewed candidate for separately authorized follow-up; COMMIT has no durable
readiness-output correction checkpoint. No rejected keys, values or native
explanations enter persistence or public activity. A readiness rejection cannot
be marked recoverable. Legacy classless refusals and other supported classes
retain their existing recovery behavior. A recoverable provider rejection remains
`backend_unavailable`. Explicit availability additionally persists a bounded
`availability: { reason, commitExecutor: "not_started" }` proof. After unchanged
Git verification, retire that authorization and schedule backoff atomically;
a fresh ID is issued only after the deadline. Other supported rejections retain their
existing explicit resume at `COMMIT`. State version 24 accepts this proof;
version 23 migrates unchanged and cannot invent missing evidence. If verification is interrupted, retain both the
consumed authorization and its proof, then resume verification without invoking
the Worker again. Without the explicit marker, retain the consumed
authorization on that verification-only path. If a commit is created but
violates the authorization contract, pause with `commit_contract_violated`.
Never amend, reset, or otherwise rewrite the unexpected commit automatically.

An authentication disposition follows the same proof boundary without using
availability scheduling. The consumed record persists only
`authentication: { disposition: "authentication_required", commitExecutor:
"not_started" }` beside the fixed code. After unchanged Git verification
proves no commit, retire the authorization and pause as
`authentication_required` at `COMMIT`; null resume prepares a fresh one-shot
authorization. Missing proof, uncertain effects, and created commits remain on
their existing verification-only or contract-violation paths.

Do not create separate "review fix" commits.

Do not perform a second full review after commit. The exact content was already finalized and reviewed.

Remote mutation is strictly forbidden in V1.

Neither the runner nor any agent may:

- run `git push`;
- run `git push --force` / `--force-with-lease`;
- create, update, delete, or otherwise mutate remote refs;
- push tags;
- create or update pull requests;
- call GitHub/GitLab/Bitbucket APIs or CLIs in a way that writes to the remote repository;
- change remote repository settings;
- add, remove, rename, or change the URL/configuration of `origin` or another
  configured remote;
- perform any other operation that modifies a Git remote.

Remote access, when available, is read-only and may be used only for inspection.
Agent adapters must block remote-write operations at the execution boundary;
prompt instructions alone are not a sufficient safety control. The runner must
also compare the effective remote-configuration fingerprint before and after
every agent turn.

Also never automatically:

- `git reset --hard`;
- discard user work;
- bypass a failing Git hook.

The workflow ends with verified local commits only. Publishing those commits is always a separate explicit user action outside the autonomous V1 workflow.

A commit hook failure or unexpected post-commit repository state must pause the run.

---
