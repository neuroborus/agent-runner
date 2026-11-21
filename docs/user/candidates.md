# Local candidates

Read [requirements](requirements.md) before assembling or installing a candidate.
Use [checkout installation](installation.md) for the development workflow and
the [user documentation map](README.md) for releases and pinned startup.

### Local application artifacts

From a checkout prepared with `npm ci`, assemble and inspect a local candidate:

```bash
npm run release:assemble -- --output dist/candidate
```

The output directory must be absent. Assembly creates `package/`, an exact-file
`release-manifest.json`, and a locally packed tarball. It materializes private
workspaces and the locked production dependency closure as real directories,
retaining native ESM, public indexes, the executable CLI and the complete operator
guide. npm packs offline with lifecycle scripts disabled and isolated empty
configuration. The assembler reads the actual archive and compares every regular
file, byte hash and executable mode to the manifest; extra files and links fail.
Node.js `>=24 <25`, Git and the documented native tools remain prerequisites.

Explicit package file allowlists exclude local settings, credentials, durable
state, task artifacts, Git/provider metadata, tests and development tooling.
Incomplete outputs remain in their fresh directory for inspection; choose a new
output directory for another assembly. Existing directories are never overwritten
or removed. The checkout retains its npm workspace links and normal `npm ci` /
`npm link` development workflow.

`@your-scope/agent-runner` is neutral candidate metadata for local validation.
The source and assembled package retain `private: true` and `UNLICENSED`.
Publication remains blocked pending separately approved owner/identity, scope,
license, repository links and publisher configuration. Successful local packing
does not establish public availability or additional execution-platform support.
Clean external installation acceptance is a separate package-install gate;
assembly never changes global/native links or activates another controller.

### Isolated candidate installation

To inspect a local installation without linking the checkout, use the exact
tarball reported by assembly and an unused private prefix outside the checkout:

```bash
candidate="/absolute/path/to/inspected-candidate.tgz"
prefix="/absolute/path/to/new/private-prefix"
mkdir -m 700 "$prefix"
npm install --global --prefix "$prefix" --offline --ignore-scripts --no-audit --no-fund "$candidate"
"$prefix/bin/agent-run" --help
codex mcp add agent_runner -- "$prefix/bin/agent-run" mcp
claude mcp add --transport stdio --scope user agent_runner -- "$prefix/bin/agent-run" mcp
```

The global npm layout is confined to that prefix; this does not change the
active Node installation or an existing `agent-run` link. The candidate bundles
its production dependencies, so installation requires no registry download or
lifecycle script. Use an executable private filesystem and the documented
Node.js/native prerequisites. This example uses the current Linux layout;
successful local validation does not establish another platform's acceptance.

Installation and client registration are separate actions. Run only the
registration command for your client, once for the chosen executable, and
restart the client afterward. The client launches that executable with `mcp`;
installing package bytes alone does not register or restart a client. Existing
settings and durable runs retain their user-global locations. For disposable
smoke work, give the process private HOME, XDG config/state/data and temporary
directories rather than using personal settings or an active controller's state.

The package-install slow suite installs these inspected bytes in a disposable
prefix, runs CLI and MCP discovery, and exercises the server vectors from both
registration examples. It does not invoke native clients or alter their
configuration. It verifies immutable startup and complete resources after outer
replacement, awaits its owned processes and removes its fixture storage.
Failed or unrun installation coverage remains outstanding. Packing, local
installation and protocol smoke do not authorize publication, update another
controller, or establish live-provider/native-platform acceptance. The checkout
and `npm link` [checkout instructions](installation.md) remain the development workflow; npm registry
installation is not a Quickstart while public identity/publication is unapproved.
