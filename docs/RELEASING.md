# npm releases

Publication is currently disabled. The immutable policy in `src/config/release/index.js` has no approved
repository, package owner/scope or license, and the root package remains private
and `UNLICENSED`. Local packing and installation do not authorize publication.
The release workflow fails closed until a separate reviewed approval supplies
all of those decisions and the trusted-publisher setup below. Internal workspace
packages remain private and bundled; they are never published separately.

## Owner setup

Before enabling publication, the owner must:

1. Approve the npm account/organization, exact scoped package name, license and
   repository. Record the exact identity and license in `OFFICIAL_RELEASE_POLICY`
   in `src/config/release/index.js`,
   set `enabled: true`, align root package/lock metadata, include the approved
   license file in the package allowlist, and set the root `private: false`.
   Root `repository` must select type `git` and URL
   `https://github.com/OWNER/REPOSITORY.git`; `publishConfig` must select
   `access: "public"` and `registry: "https://registry.npmjs.org/"`.
   Placeholder identities are not approval. Update the default-disabled regression
   only as part of that separately reviewed approval.
2. Protect `main`, stable version tags and release publication against unreviewed
   changes. Configure the GitHub `npm-release` environment with required human
   reviewers, prevent self-approval, and allow only approved release tags. Review
   the exact workflow run commit and release notes before approving that job.
   Repository policy and environment approval are required administrative setup;
   source code cannot establish their presence.
3. Configure npm trusted publishing for that exact GitHub owner/repository,
   workflow filename `release.yml` and environment `npm-release`. Use a supported
   GitHub-hosted runner and npm >=11.5.1 with Node.js 24. No long-lived npm token
   is accepted. If initial package ownership/bootstrap is required by npm, resolve
   it as a separate owner operation; this workflow does not create accounts or
   bootstrap ownership with a token. Retain npm provenance support and configure
   repository visibility/links as required by npm's attestation service.

These administrative steps and the identity/license decision are not performed
by local tests or Agent Runner. No current approval is implied by this document.

## Selecting and validating a release

Publish a stable GitHub Release explicitly, using exact tag `v<package.version>`.
The workflow runs only for `release: published`, rejects drafts/prereleases,
and independently resolves the tag to the checked-out commit in both jobs. That
commit must be in fetched `origin/main`; release `target_commitish` text alone
is insufficient. Branch pushes, arbitrary tags and manual workflow dispatch do
not publish. Retrying a workflow must retain the same release commit and tag.

Validation runs the ordinary `npm run check`, assembles and inspects one tarball,
runs `npm run test:slow -- test/package-install.slow.test.js`, and runs complete
`npm run test:slow`. Neither slow command substitutes for the other. Both consume
the same inspected artifact through `AGENT_RUNNER_RELEASE_CANDIDATE`, a receipt
path confined to the current release output. Ordinary local invocations leave
that variable unset and assemble their own disposable candidate as before.

Only successful validation exports the tarball's SHA-512 integrity as a job
output. An immutable Actions artifact contains that exact tarball, its complete
content manifest and a versioned receipt binding commit, tag, package/version
and manifest hash. The publishing job downloads the artifact from the same run,
checks it against the independently retained job output and selected commit,
and repeats complete archive inspection. It never repacks. Only that protected
job has `id-token: write`; checkout credentials are not persisted and repository
contents permission remains read-only. No hosting write or Git tag movement is
needed. npm publishes the inspected file with OIDC and provenance.
The sanitized npm environment retains the complete GitHub source/workflow/run
identity and hosted-runner builder identity; missing metadata blocks publication
before registry effects. Ambient user npm configuration and registry tokens are
not inherited.

Each validation attempt uploads a distinct immutable artifact and exports its
exact Actions artifact ID. Publication downloads that ID, including when only a
failed publishing job is retried. A complete rerun creates a new artifact rather
than overwriting the earlier attempt.

## Verification and recovery

Before publishing, an anonymous exact-version registry lookup distinguishes
absence from errors. An existing version must have the tested SHA-512 integrity;
it is never overwritten or republished. After a publish attempt, including a
lost/failing response, the workflow reconciles that exact version once, downloads
its public tarball anonymously, verifies the actual bytes/manifest, and installs
those bytes offline into a fresh private prefix. Required manifest and executable
permissions are checked; no provider, client registration or controller starts.
Owned smoke storage is removed in `finally` without following substituted roots
or changing other storage permissions.

Public verification failure is a failed job even when publication may already
have completed. The job summary links the GitHub Release and exact npm version
and reports success, verified existing publication, or partial failure. Do not
delete/unpublish, overwrite a version, move a Git tag or change npm tags to hide a
partial failure. Rerun the same release: matching published bytes take the
verification-only path; conflicts remain blocking. Registry/network errors never
count as an absent version. No automated retry repeats a publish effect.

Release notes should link the exact npm version and describe Node/native tool
requirements, tested platforms, user-settings compatibility and run-state
compatibility. Package versions are not persistence-schema versions. Settings
remain outside immutable payloads; installing bytes does not migrate settings,
resume runs, restart MCP clients or grant legacy execution authority. Existing
processes stay pinned until their normal restart/admission boundary. Retain old
usable payloads and use the owning compatibility/recovery rules when resuming.

The bundled official policy is shared by publishing and on-demand compatibility
reporting; project/user settings cannot approve another registry or package.
Root `agentRunnerCompatibility` metadata must match the configuration schema,
runtime envelope and each pipeline's current state version. Fast contract
coverage detects stale declarations. Newer candidates without matching metadata
remain blocked by the update checker; no package-version inference or implicit
state migration substitutes for that evidence.

On-demand candidate preparation consumes an exact official version and SHA-512
integrity in private storage. It shares archive verification with these scripts
and requires immutable-payload, compatibility and isolated CLI/MCP smoke
acceptance before a local validated receipt. That receipt grants no publication,
activation, migration, resume or global-link authority, and cannot substitute for
this release workflow's exact tested artifact or public verification.

## Local version selection and restart

After official approval, use an exact package version for installation, for
example `npm install --global @your-scope/agent-runner@1.2.3` with the separately
approved package name. This is an operator-owned installation into the intended
prefix; local tests perform no such global change. Keep settings and run state
outside that prefix and restart the owning client explicitly. Installation alone
does not resume work or move a running MCP process onto new code.
Replacing the outer package also does not override a published runtime selection;
inspect installed, running and active versions separately.

The root update API separately prepares an exact version, then activates only
that validated preparation under a new operation UUID. While another runtime
remains in use, the outcome is durably deferred. Next normal startup reads the
published candidate; admission promotes it only after the previous users retire.
Detached continuations stay pinned. Retry the same operation after interruption
and inspect lifecycle status rather than inventing a new effect.

Equal or older registry selections remain successful no-ops during preparation.
An already validated, retained compatible candidate can be explicitly selected
again. An explicit older package installation is not a rollback of saved state:
run migrations and admission-projection upgrades can make older software unable
to read it. Never edit/delete state or bypass a forward-version rejection to
force a downgrade. Retained bytes promise neither rollback of persisted
migrations nor execution authority for legacy/intermediate runs. Resume only
explicitly through a compatible later server and its supported leased migrations,
using the run's frozen configuration and existing effect-recovery rules.
