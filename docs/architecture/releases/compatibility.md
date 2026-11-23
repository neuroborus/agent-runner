# On-demand release compatibility

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

`src/update/index.js` exposes `createUpdateService().check()` and an optional
exact `{ version }` selection. Construction, model turns, status and activity
reads perform no registry request. CLI/MCP delegate explicit requests to it and it
creates no automatic-update setting. Project configuration, role findings and
request fields cannot choose a source or acquire global-update authority.
Trusted root composition may inject effects for controlled tests.

The configuration-owned `src/config/release/index.js` is standard-library-only,
contains the disabled official approval policy, and shares identity validation
with release assembly/publication. It is included by the existing JavaScript
payload allowlist, replacing the checkout-only approval JSON. User settings
cannot override it. Approved package name, repository, license and public
registry metadata must agree before an anonymous request to the fixed npm
registry. Registry reads normalize npm's `git+https` repository form before
checking that same exact approved repository; publication inputs retain their
strict source metadata contract. Linked checkouts remain development-managed
and never query it.

Runtime-owned read-only inspection reuses complete payload verification and
Node identity checks. It distinguishes pinned running bytes from the current
outer installation without preparing storage, changing links or activating code.
Reports expose bounded versions, official identity, stable/explicit selection,
compatibility, blockers and restart requirements; raw paths, registry documents
and errors are excluded. Requests have a ten-second deadline and a one-MiB body
ceiling. A default check selects only a stable `latest`; prereleases require an
exact explicit version. Equal or older releases are successful no-ops.

Root package metadata carries versioned `agentRunnerCompatibility` independently
of package version: configuration schema, runner/run-envelope generations and
pipeline state versions. A candidate must declare the same supported contracts;
unknown metadata or a differing contract blocks a newer candidate. Node ranges
use the project's `>=major <major` form. This is conservative runtime-contract
comparison, not certification of any saved run or permission to migrate/resume
legacy state. Permission observations are informational and confer no install
authority. Reports require a restart when installed and running payload identities
differ, including same-version replacements and when no newer download is needed. No payload is downloaded,
installed, replaced, migrated or resumed by checking.
