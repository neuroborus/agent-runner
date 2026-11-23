# Runtime, Release and Update Coverage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Immutable runtime payloads

Fast `test/runtime-payload.test.js` owns complete manifest/dependency/resource
inspection, read-only modes, isolated storage, interrupted and concurrent
preparation, substitution and drift rejection, delayed imports and development
checkout behavior. Exclusive publication covers an empty destination arriving
after the last absence check, preserving its identity, permissions and contents.
Unpublished sealed trees and references outside their sibling namespace are
rejected. Coverage also rejects missing bootstrap modules and lost private
storage permissions on existing payloads. It uses neutral constructed packages and never touches a live
controller. `test/runtime-pinning.slow.test.js` owns actual pre-import startup,
delayed resource/dependency reads and the real detached launcher after outer
replacement, plus launch rejection after payload drift. Its synthetic application
uses no providers, run store, native links, package installation or activation.
Runtime fixture teardown verifies its freshly created root identity, restores
write/search access only to owned fixture directories through descriptors, and
never follows links or changes the enclosing temporary-storage permissions.
Read-only fixture files need no permission change for removal.

## Runtime admission

Fast `test/state/runtime-admission.test.js` owns serialized admission/activation,
deferred restart, positive owner recovery, namespace/identity uncertainty and
write-ahead interruption without replay. It injects process observations and
uses only owned state storage. Fast `test/runtime-admission.test.js` verifies
CLI/MCP lifetime and Runner create/run/resume gates, old pinned resources after
outer replacement, retirement, state separation and development-managed bypass.
Its in-process MCP fixture supplies controlled positive process observations;
production admission still requires native owner identity and namespace proof.
Unavailable owner metadata must deny startup before state creation.
It also covers actual STDIO EOF retirement and caller-input mutation after
candidate verification, plus bounded CLI runtime diagnostics: exact recognized
codes, the unrecognized fallback, hostile message/cause/property redaction,
identical non-runtime rejections and original-failure precedence.
Existing runtime-pinning slow coverage retains actual detached-process proof;
the new admission tests require no providers, host census, signals or installs.
Recovery also covers a consumed activation after owner loss and colliding PIDs
in separate namespaces before the first runtime projection is published.
Controlled concurrent admissions prove that a pending activation wins the next
safe boundary and rejects an obsolete racing start. Recovery binds that pending
selection to its consumed action across owner loss and intervening retirement;
active and deferred receipts also recover after intervening admissions without
republishing their selectors. A superseded selection retains its replay barrier;
historical projections gain no inferred authority, and a newer explicit choice
supersedes an older pending request.

## Release assembly

Fast `test/release-assembly.test.js` owns isolated lock-closure assembly, real
private workspaces, nested dependencies, executable modes, allowlist exclusions,
metadata/resource/link rejection and no-overwrite output behavior. Synthetic tar
fixtures prove archive byte/mode identity, path confinement, extended-header
validation and link/extra-file rejection without npm or processes. `test/release-pack.slow.test.js` owns actual
offline npm packing and exact archive inspection of the current application,
complete immutable preparation, pinned standalone imports and operator-guide
completeness. Packing and installation coverage verify the shipped user
references and their navigation. Packing performs no installation, provider
call, global link change or controller activation.

## Release publication

Fast `test/release-publication.test.js` owns approved stable-release selection,
commit/tag/main binding, complete validation ordering, exact artifact receipts,
version-integrity retries and partial-failure policy with injected effects.
It performs no npm, Git, registry, account, tag, hosting or publish effects.
Publication stays disabled in checked-in policy. Release automation ownership
and administrative approval requirements are in [RELEASING.md](../RELEASING.md).

## Release compatibility

Fast `test/update.test.js` owns on-demand official identity gating, version
ordering and explicit prereleases, no-update success, Node/configuration/state
compatibility, registry/permission failure redaction and body bounds. Registry
effects are injected; no request, installation or provider is used. Small confined
runtime fixtures separately prove read-only running/installed inspection and
linked-checkout preservation using the existing positively owned teardown.
Source package compatibility declarations are checked against their owning
configuration, state and pipeline contracts. Existing slow/package requirements
remain unchanged.

## Candidate lifecycle and update projections

Fast `test/update-candidate.test.js` owns exact candidate selection, archive
integrity/resources, installed-payload verification, interrupted/partial install
reconciliation, permission/smoke failures and substituted-storage preservation.
Focused durable-action cases retain actual leased receipts and ownership
across interrupted effects; other policy cases use lightweight action effects.
Neutral confined payloads prove previous-payload retention and owned smoke
teardown. npm/registry/smoke effects are injected, and a native-vector case
asserts the filesystem mounts, private PID namespace and network policy without
launching a process. A controlled clock proves retirement after command deadline
expiry; intent-write failures retain redacted results and clean positively owned
smoke allocations. Recovery coverage rejects token-owned uncertainty and ignores
unrelated reused sessions even after their new leader exits. This is not
native-platform acceptance.
Activation coverage holds a pinned MCP admission through deferred selection,
then verifies next-start selection, exact detached pinning, retained previous
payloads and consumed-effect recovery without a second publication. A saved run
remains byte-identical across activation; explicit later leased migration retains
its frozen configuration and consumed commit, while an unsupported forward
pipeline version preserves progress. These cases use the real state action/lease
boundary with injected native effects, without restarting a client or executing
the saved run. Existing Runner slow coverage retains full resume orchestration.
Lifecycle projection rejects malformed persisted versions without returning their
text or performing registry/native effects.
Durable apply coverage additionally proves exact-selection receipts, same-key
conflicts, concurrent-key installation sharing, recoverable blocked intents and
server-replacement recovery without native-effect replay. `test/mcp/update.test.js`
owns strict tool discovery and operator acknowledgement, unchanged protocol JSON,
wait-only cancellation, duplicate observation and CLI dispatch without pipelines.
It uses in-memory SDK transports and injected updater effects. Installed package
acceptance separately exercises the unapproved CLI/MCP update entry points without
registry requests or client registration; approval changes must revise that explicit
default-disabled expectation as part of their own reviewed acceptance.
Existing package-install acceptance retains real CLI/MCP protocol and offline
installation ownership; its separately assigned exact invocation remains
required alongside complete slow coverage.
