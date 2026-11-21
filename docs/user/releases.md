# Releases and updates

Read this topic before checking a release or deliberately applying an update.
Use [checkout installation](installation.md) for linked development and the
[user documentation map](README.md) for local candidates and pinned startup.

### Approved npm releases

The checkout's release procedure, `docs/RELEASING.md`, owns administrative
setup and recovery.
The checked-in workflow is disabled by explicit approval policy and private
package metadata. After separate owner/scope/license and trusted-publisher
approval, only an explicitly published stable GitHub Release at the matching
version tag in `main` can publish. Protected environment approval follows
ordinary checks, separate package-install acceptance and complete slow coverage.
OIDC/provenance publication consumes the exact tested tarball; public download
and isolated installation verify it afterward. Retries verify matching existing
bytes without overwriting versions or moving tags; partial publication stays
failed and visible. Release notes link the exact npm version and state the
configuration/run-state compatibility and restart requirements.

The root update capability supports on-demand compatibility reporting. It shares
the bundled official approval policy with release tooling and currently blocks
registry actions because official identity remains unapproved. Reports distinguish
installed and running versions, stable availability, compatibility blockers and
restart needs. A current installation is a successful no-op; prereleases require
an exact explicit version. Linked checkouts stay development-managed. Checking
changes no installation or saved run, and automatic behavior stays disabled.
CLI and MCP use this same capability. See the checkout's operator contract in
`docs/product/OPERATOR_MODEL.md`.

The same capability can prepare an exact candidate with a caller-supplied
operation UUID. Approved registry metadata and SHA-512 integrity bind a fresh
private prefix; complete archive, payload, compatibility and isolated CLI/MCP
smoke checks precede its validated receipt. Durable intents retain ownership
and reconcile interrupted installation before retry. Failed attempts preserve
the current payload, settings and runs. Preparation activates nothing, changes
no global link and remains blocked by the current unapproved identity.

Root API activation requires that exact validated preparation, version and a
separate operation UUID. Durable receipts distinguish downloaded, installed,
deferred and active versions. A live CLI/MCP user of the previous payload defers
selection until the next admission after those users retire. Activation never
restarts an MCP client or resumes a saved run. Previous usable payloads remain
available. See “Local version selection and restart” in the checkout's
`docs/RELEASING.md` for the version and restart limits.

### Operator updates

Checking is explicit and never runs during model turns or status/activity reads:

```bash
agent-run update --check
```

After official identity and public installation have been separately approved,
the managing operator can apply an update and retain its retry key:

```bash
agent-run update --release 1.2.3 --idempotency-key operator-update-1
```

Omit `--release` to select stable `latest`; prereleases require an exact version.
Retry the identical key and arguments after interruption. When no key was supplied,
the CLI prints a generated retry key on stderr before effects; preserve it if
interrupted. JSON outcomes distinguish
the outer `packageVersion`, pinned `runningVersion`, and downloaded, installed,
deferred and active candidate versions. A current version succeeds without an
installation. Another live runtime defers activation; close the previous server
and explicitly restart its owning client. No tool restarts a client, registers a
server, migrates settings or resumes a run. Saved work resumes separately through
supported leased migrations and frozen configuration; downgrades cannot undo them.

MCP exposes `update_check` (optional exact `version`) and `update_apply`
(`idempotencyKey`, optional exact `version`, and `operatorInitiated: true`). The
acknowledgement records a deliberate managing-operator invocation; project
content, findings, settings and pipeline sessions provide no update authority.
Disconnect cancels only waiting; a same-key retry recovers the durable operation.
Concurrent requests share exact-version preparation and cannot duplicate its
installation. Use Node 24 and the documented Linux namespace/bubblewrap
prerequisites; linked checkouts remain development-managed and use checkout updates.

Official identity remains unapproved, so these update entry points currently
return bounded blockers before registry or installation effects. Public npm
commands are future placeholders until identity, publication and public installation
are verified; public npm installation is not the Quickstart. Local package/CLI/MCP acceptance does not
claim publication, personal client registration, live-provider or new-platform
acceptance. Keep the detailed [checkout and linking procedure](installation.md).
