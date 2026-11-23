# Transient Validation Storage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Transient validation storage ownership

Common envelope version 9 records trusted storage allocation intent and verified
identity separately from process ownership. Version 10 adds the acquiring runner
identity and changes the runtime compatibility token. Leased migration preserves
version-9 allocation records without new resource effects. The root retires owned processes and
cleans recorded resources before resuming pipeline work or settling an operator
stop. Legacy envelopes migrate to null storage ownership without allocation or
provider activity. Only declared scratch/cache directories and a declared
writable source projection are writable through bindings owned by the trusted-
validation architecture. Projected build output is discarded; without that
authority required output must stay in scratch and outside the repository.

Cleanup uncertainty preserves the resource record and pauses finalization as
`environment_blocked` at `FINALIZE`; neither the check nor subsequent work is
accepted until ownership is verified and cleanup finishes. Interrupted mutable
cache contents and partial downloads are never reused. Pinned artifact requests
share this durable allocation lifecycle, including artifact-only commands. The
root journals verified directory ownership and the acquiring runner process
identity before downloading. Journal failures preserve a resumable ownership
blocker and the saved allocation. Recovery cannot delete its storage while that owner
is live or unverifiable without service-observed transport retirement. It exposes only
complete digest-verified files at `/run/agent-runner/dependencies`, read-only.
The exact check remains network-isolated; extraction or setup belongs to its
declared vector and must use declared scratch. Acquisition failures block
`FINALIZE` before command launch with bounded redacted evidence; repaired
environments retry the frozen request after cleanup. Status remains observational.
