# Immutable application startup

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

`src/runtime/index.js` is the public startup and immutable-payload boundary.
The thin bin entry imports only this standard-library capability. Private
`contract.js` owns bounded manifest and location contracts, `files.js` owns
descriptor-bound reads and ancestor bindings, `payload.js` owns complete tree
inspection and atomic preparation, and `bootstrap.js` selects the root before
dynamically importing its public `src/index.js`.
The standard-library-only `src/state/location/index.js` shares the existing
state-root mapping with bootstrap. `runtime/selection.js` reads the bounded,
private state-owned selection without creating storage. Normal startup verifies
that selected payload and Node identity before imports, retaining the original
installation path for configuration fallback. Detached launches bypass this
selection and verify their exact frozen context. Unknown selection versions fail
clearly before any command; admission rechecks the selection under its mutation
boundary before effects, so a stale startup observation grants no admission.

An installed package requires the assembler's manifest, native-ESM metadata,
Node.js `>=24 <25`, the executable entry, runtime bootstrap, complete operator
guide and complete declared production dependency graph. All bootstrap modules
are mandatory manifest entries. Every declared file's
bytes, size and executable status must match; unlisted files/directories, links,
hard links, missing dependencies and changing inputs fail closed. The manifest
is limited to 2 MiB, 10,000 files and 64 MiB of payload bytes. Its SHA-256 is the
payload identity. The optional outer `.agent-runner.json` is excluded from
capture and remains a configuration-owned mutable legacy fallback.

Linux runtime storage uses XDG data/home fallback, with Application Support and
LOCALAPPDATA location mappings as documented in the README. Creation pins every
real ancestor through directory descriptors, verifies private user ownership,
and uses only a fresh preparation beside the destination.
The storage root and immediate payload container must retain private user-owned
`0700` permissions whenever a stored payload is inspected or launched.
File and directory data are synchronized before publication. Completed files become `0400` or
`0500`, directories become `0500`, and the complete tree is reverified before
publication. Each fresh tree retains its unique
`payloads/.payload-<manifest-hash>-<UUID>` location. Publication atomically creates
an exclusive relative symbolic reference at `payloads/<manifest-hash>`; it cannot
replace an arriving entry, including an empty directory. Bootstrap reads that
reference without traversing it, accepts only a matching sibling name, and
verifies its unchanged identity and the complete unaliased tree. Pinned roots
and executables use the physical tree path, never the reference. Existing
payloads are fully verified and never rewritten. Concurrent complete
preparations converge on the same published tree. Interrupted or redundant
preparation directories remain separate; bootstrap neither adopts nor deletes
them, even when they contain a complete sealed tree. There is no cleanup daemon.
Preparation retains its directory binding and verifies each created entry before
sealing through its matching descriptor; substituted paths cannot redirect
permission changes.

Only a checkout with workspace metadata and a real Git control entry is
development-managed. A present release manifest always selects installed
verification, even beside checkout metadata. Linked checkouts resolve to that source root. A missing
installed manifest cannot silently become development mode. The bootstrap freezes
one non-writable process context before application imports; duplicate module
graphs share that context through a process-local symbol. It carries the pinned
root/executable, original installation root, payload ID and Node identity, never
settings or run state. Configuration uses the original installation root only for
its existing absent-user-file legacy fallback. Direct source API imports do not
establish a bootstrapped process.

Every later application import and resource URL is rooted in the selected tree.
The MCP launcher rechecks its complete payload plus Node path, version and file
identity before spawning the pinned executable. Linux also compares the selected
Node file to the running `/proc/self/exe` identity. A bounded one-use internal
environment binding carries this tuple to the child, which verifies it before
application imports and removes it before provider/validation children can
inherit it. The existing runtime-compatibility token, leased revision admission,
durable ownership and same-key recovery remain separate mandatory gates.
Preparation grants no registry, update activation, migration or resume authority.

### Serialized runtime admission

`runtime/admission.js` stays standard-library-only and receives the state
capability from root composition. Installed CLI/MCP process lifetimes and Runner
create/run/resume calls verify their pinned payload and Node identity, then
register before effects and await retirement afterward. Development-managed
source calls bypass global admission. State effects use the immutable verified
descriptor rather than retaining caller-owned identity fields. Application,
project and task boundaries are checked before state creation, including
missing but confined paths.
The STDIO server handle exposes a settled-on-close lifetime promise; CLI keeps
its admission until transport closure, including startup failure or early EOF.
The MCP boundary closes the SDK transport when STDIO input ends or closes and
removes its input listeners when the lifetime settles.

The public CLI entry projects a runtime-prefixed admission or lifetime failure
as one stderr line through a private closed code-to-fixed-text map. A
recognized code is echoed exactly with bounded conditional guidance.
`ERR_RUNTIME_ADMISSION` also wraps non-runtime causes and keeps unknown
attribution; unrecognized, over-long or control-character codes render only a
fixed unrecognized line. No line attributes a stage or claims that earlier
request effects were absent, and error messages, causes and other properties
are never projected. Non-runtime errors, including non-string codes, are
rethrown unchanged. Exit status 1, stdout silence and original-failure
precedence are unchanged.

`state/runtime-admission.js` owns a bounded private `runtime-admission/runtime.json`
projection under the existing state root. It records the active and pending
payload identities plus explicitly registered users, their host, PID namespace,
boot/start identity and operation UUID. Existing action intents and leases bind
each operation; the existing mutation boundary serializes admission, retirement
and activation. Runtime mutation claims bind their PID namespace before any
peer PID probe; ordinary run mutation claims retain their existing contract.
A write-ahead action records its expected projection revision and
outcome before atomic publication. Recovery completes a proved consumed write
without repeating it; intervening operations with uncertain consumption block.
Completed admission receipts cannot recreate retired users.
Activation and retirement receipts can be reconciled by a new owner only after
the original owner is proved dead or replaced. Admission never transfers an old
process association to that new owner.

Projection version 2 binds active and pending identities to their originating
activation operations. A consumed activation remains reconcilable after later
admissions or retirements while that exact selection and operation binding remain;
a superseding selection never authorizes replay. Version-1 records remain
readable but their pending identities acquire
no automatic selection authority. The first admission initializes selection.
Later admissions must match the active payload while users remain. Explicit
activation records a deferred selection while another positively associated
runtime remains live. After the last user retires, admission selects only that
proved pending payload, reconciling its original deferred action receipt first;
an obsolete racing start is deferred. A later successful explicit activation
supersedes any older pending request. Unknown ownership remains blocking.
This changes only the selector and admission record. It does not rewrite or
remove trees, restart a process, reload frozen configuration, migrate or resume
a run. Older software that cannot read the new projection must fail closed;
retaining old payload bytes is not persistence rollback authority.

Only recorded users are inspected. Proved exit, PID replacement or a prior boot
retires the corresponding association. Unknown identity, foreign host or a PID
namespace unavailable to this observer remains blocking; no PID-only guess,
host census or signal is permitted. Per-run leases, private PID containment,
compatibility, stop gates and consumed-effect recovery retain their authority.
Runtime admission grants no execution authority to legacy or intermediate runs.
