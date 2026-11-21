# Git Stored-Content and Staging Verification

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Both handoff and consumed-commit full-staging verification first reproduce the
accepted confined worktree fingerprint. The shared matcher rejects hidden flags
on the union of staged-changed and worktree-changed paths before either branch;
handoff does not reject unchanged hidden paths outside that union. Execution
retains its stricter whole-index semantic and resolve-undo guards, including
permitted split-index bookkeeping. Exact stored-content equality remains valid.
Otherwise complete paths, kinds, modes and deletion/presence states must match;
only unequal regular-file bytes can enter conversion proof. Confined race-checked
reads bind raw bytes, size and mode to the accepted entry, independently of index
stat metadata or an unstaged-clean result.

Unequal bytes require SHA-1 and exactly one NUL-delimited native `ls-files --eol`
record for the literal path. Only canonical `attr/` resolutions `text`,
`text eol=lf` and `text eol=crlf` are supported and forwarded unchanged after
padding removal. Literal `text=set`, automatic text and unspecified text relying
on autocrlf are excluded. `check-attr -z --all` rejects any `filter`, `ident` or
`working-tree-encoding` declaration, even unset or sentinel-like literal values.
Only absent or alphanumeric `core.autocrlf`, `core.eol` and `core.safecrlf` values
may be forwarded. Encoding, ident, filters and LFS gain no unequal-byte support.

The private command hasher resolves canonical worktree, per-worktree and common
Git controls through read-only metadata queries. Before allocation, the existing
canonical temporary parent must be outside all those roots; ambiguity or an
unsafe parent fails with `ERR_GIT_UNAVAILABLE`, without a fallback. An owned
private scratch directory is allocated through the verified parent descriptor;
canonical bindings and disjointness are rechecked before hashing. Directory and
absolute parent-ceiling paths cannot contain colon, NUL or newlines. The hasher
writes one owned attributes file, removes inherited `GIT_*`, disables system and
global configuration/attributes, sets private HOME/XDG paths and a verified
repository-discovery ceiling, and invokes `hash-object --stdin --path=candidate`
without `-w`. Only validated text configuration is forwarded. No target or
enclosing repository helpers/configuration may be discovered. Successful single-line
40-hex output must equal the actual staged blob ID; refusal or malformed output
is a mismatch, while spawn failure remains `ERR_GIT_UNAVAILABLE`. Process closure
precedes cleanup of only the bound owned allocation. No index refresh, target
object write or conversion-specific worktree diff is added. Fingerprints, durable
formats, effect authority and verification-only recovery remain unchanged.

Handoff-owned staging and direct Git inspection commands use a private fixed
`-c core.hooksPath=/dev/null` prefix, preventing workspace hooks from executing
with Runner authority. This invocation-only policy changes no configuration,
shared Git defaults, provider isolation, or authorized local-commit hooks and
their failure behavior. Snapshot/content helpers remain observational with
their existing optional-lock controls; ignored hook bytes stay outside content
fingerprints. Inspection and stop reconciliation never stage, completed recovery
never repeats staging, and partial effects still fail closed. Snapshot formats
and durable versions remain unchanged.
