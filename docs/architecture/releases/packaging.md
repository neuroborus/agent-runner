# Local application packaging

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

`scripts/assemble-release.js` owns narrow release assembly from the existing npm
checkout. Root and private workspace `files` declarations are the publication
allowlists. The assembler validates root package/lock agreement and walks only
the locked production graph, checking installed names, versions, dependency
declarations and exact workspace links. Hoisted and nested dependency slots are
preserved while workspace links become real directories. Optional/peer closure
requires an explicit implementation before such dependencies can be packaged.
Installed dependencies must come from the committed lock through `npm ci`;
assembly verifies their lock identity and records the copied bytes, without
claiming to reconstruct upstream tarball integrity from expanded files.

Fresh output storage contains a standalone native-ESM package with the same bin,
exports and Node engine, declared runtime resources, upstream dependency notices,
and bundled production dependencies. Checkout-only workspaces, development
dependencies and scripts are omitted from its root metadata. Configuration,
credentials, state, task inputs, provider controls and unrelated development files
are outside the allowlists. The source workspace topology and links are untouched.

The generated release manifest records source-lock SHA-256, dependency identities,
and every payload file's path, size, executable mode and SHA-256. Its own exact
bytes and ordinary file mode are checked separately. `packRelease` invokes local offline npm packing with
disabled lifecycle scripts, private HOME/cache (including Node's compile cache) and separate empty user/global
configuration. Size-checked stdout uses an owned temporary file; stderr is discarded. The standard-
library `release-archive.js` verifier reads the actual gzip/tar bytes (bounded to
64 MiB expanded), accepts only regular file records and supported portable
extended headers, rejects unsafe paths, links, duplicates, extra/missing files,
invalid headers or changed bytes/modes, and verifies exact manifest readback.
Only supported portable extended fields are accepted, with size overrides
required to match their file headers.
It never installs, publishes, changes native links or activates a runtime.

Candidate metadata remains `@your-scope/agent-runner`, `private: true`, and
`UNLICENSED`; internal workspaces remain private. Approved public identity,
owner/scope, license, repository links and publisher configuration remain absent,
so publication is fail-closed. Local assembly is distinct from external-install
acceptance and adds no native-platform support. Ordinary development continues
through `npm ci` and `npm link`; there is no transpilation or general build system.

External-install acceptance is owned separately by
`test/package-install.slow.test.js`. It consumes the inspected tarball through
offline, script-free npm installation into a fresh private prefix, compares the
installed manifest and files, and launches the real installed CLI and STDIO MCP
server from an unrelated empty directory. Sanitized user locations and bounded,
awaited child lifetimes keep all effects in fixture storage. Private workspace
imports use actual bundled directories; immutable startup, delayed guide reads
after outer replacement and EOF admission retirement are exercised together.
[Candidate installation](../../user/candidates.md#isolated-candidate-installation)
commands and registration server vectors are inputs to this acceptance; native
client registration remains a separate operator action.
No source/dependency link, controller, native client configuration or registry
publication is changed. See [test ownership](../../TESTING.md#slow-gate).

Release automation belongs to `.github/workflows/release.yml` and the focused
standard-library scripts `release-policy.js` and `publish-release.js`. An explicit
stable published Release selects an exact version tag/commit in main; the
disabled immutable policy in `src/config/release/index.js` requires separately approved public metadata
before that path can validate or publish. The assembler accepts public metadata
only through that matching policy, preserving neutral private local candidates.
Ordinary checks, exact package installation and complete slow gate one inspected
tarball. A commit-bound receipt and independent job-output SHA-512 bind the
downloaded Actions artifact. Only the protected publishing job requests OIDC;
npm provenance and an anonymous download/isolated install verify publication.
Existing-version integrity is reconciled before effects, and uncertain/partial
failure remains failed without overwriting versions or moving tags. This tooling
has no runtime update, configuration-migration or run-resume authority.
See [release ownership and setup](../../RELEASING.md).

The root allowlist names each shipped Markdown user reference in `docs/user`
and the canonical `configuration.example.json` resource individually.
The packaged quickstart, operator guide and user topics link to included
resources and identify checkout-only contracts by source path.
The checkout alias `.agent-runner.example.json` targets that regular resource
and is outside release selection; release assembly still rejects every selected
symbolic link and hard link. The complete `docs/OPERATOR_GUIDE.md` remains the
single runtime-loaded common guide, with its unchanged size and read contracts.
Both shared-plan packages include their `contract.md` resources so their
packaged README gates retain the complete contracts.
