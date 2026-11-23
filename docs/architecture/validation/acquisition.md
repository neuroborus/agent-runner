# Pinned Artifact Acquisition

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Verified publication

The private `acquisition.js` primitive shares artifact declaration normalization
with the snapshot contract. The trusted executor invokes it privately after
journaling verified allocation ownership. The caller supplies an exclusively
owned mode-0700 directory handle, never a destination filename. Descriptor-relative
exclusive partials are hashed while streaming, synchronized, and published without replacing
existing entries under their lowercase SHA-256 names with mode 0444. Identical
digests share one published file, but every declared URL is acquired and verified.
Cleanup rechecks entries against the open file's identity and preserves substitutes.
Earlier verified files can remain after a later failure; callers must not expose
an incomplete acquisition and remain responsible for the owned directory.
The service exposes the dependency directory only after the complete request
succeeds, all transports retire, and allocation and subdirectory identities are
rechecked. Every execution acquires fresh files from its frozen declarations;
resume cleans previous allocations before downloading again.

## Transport policy

Acquisition performs one DNS phase with one A and one AAAA lookup, one resolver
try each, and at most 64 combined answers. It rejects the entire answer set if
any address is not public unicast and pins one numeric destination.
The conservative address policy excludes IPv4 special-use ranges and IPv6 outside
2000::/3, plus special-use, documentation and transition ranges within it. The
declared hostname remains the HTTP Host and TLS verification name; the actual
peer must match the pinned address. Each request uses a fresh connection, explicit
Node built-in trust roots, TLS 1.2 or newer, no proxy environment, and a 16 KiB
header limit. Only HTTP 200 and identity content encoding are accepted; redirects,
ambiguous framing, incomplete bodies, and integrity mismatches fail closed.

## Limits and recovery

Limits are 64 MiB per file and 256 MiB across a sequential acquisition, including
repeated digests. DNS has a 5-second deadline, connection establishment 10 seconds,
body/header inactivity 15 seconds, and the whole acquisition 5 minutes. Cancellation
and deadlines prevent subsequent publication. Requests, responses, and sockets
must close before publication or partial cleanup; retirement has a separate
1-second bound. Unverified retirement retains the partial for owned recovery.
The live service retains the resource while transport closure is uncertain and
rejects concurrent recovery; closure permits cleanup retry. Recovery also checks
the journaled acquisition owner, even after lease release and service
reconstruction.
A live or unverifiable owner blocks cleanup unless that same service observed
transport retirement. A dead or replaced owner permits confined cleanup. Late
callbacks cannot publish files. Errors expose finite acquisition categories,
not URLs, response bodies, or native transport diagnostics. Tests inject DNS,
HTTPS and deadline scheduling without network access.
