# Trusted validation

Read this topic before selecting exact trusted commands, declaring capabilities
or changing command deadlines. [Configuration](configuration.md) owns the root
and project layers; [pipeline settings](pipeline-settings.md) owns finalization
guidance. Use the [user documentation map](README.md) for other topics.

## Command catalogs and deadlines

Required checks that need loopback listeners, Docker, a local database, or a
comparable host service may be delegated to the runner's trusted validation
executor. Runner-root and safe project configuration may each define
`trustedCommands` using exact inventory commands and executable/argument
vectors. Catalogs merge in root-then-project order: identical same-name
definitions deduplicate, while conflicting definitions reject configuration
even when unselected. The merged catalog accepts at most 256 aliases; each
pipeline run may select at most 32, preserving selection order in the snapshot.
Trusted commands execute in finalization's required-check inventory order.
Exact direct arguments may contain line feeds for multiline scripts; other control
characters remain invalid. This example works in either configuration source:

```json
{
  "schemaVersion": 1,
  "trustedCommandTimeoutMs": 7200000,
  "trustedCommands": {
    "service-tests": {
      "command": "npm run test:service",
      "executable": "npm",
      "arguments": ["run", "test:service"],
      "capabilities": { "sourceProjection": true }
    }
  },
  "pipelines": {
    "polishing": {
      "trustedChecks": ["service-tests"]
    }
  }
}
```

`sourceProjection: true` is the closed authority for selected Runner-trusted
checks that must write build output beside source inputs; an ordinary
agent-executed check writing only safe workspace output under the Worker's
existing access needs no projection. The runner reconstructs the accepted
staging-independent source in private owned storage and mounts only that copy
writable at the canonical project path. It includes frozen HEAD content plus
tracked and non-ignored untracked workspace changes, but not the index, `.git`,
ignored untracked files, project configuration, task/state paths, credentials, or other
host storage. Projected writes are discarded after verified process retirement.
Source projection does not imply scratch, cache, artifacts, or network access.

`trustedCommandTimeoutMs` is the per-command execution deadline in
milliseconds. It is a strict integer from `1` through `2147483647` and defaults
to `3600000` (60 minutes). Both configuration layers accept it; an ignored
project value overrides the runner-root value for that project. There is no CLI
or MCP override. The resolved value is fingerprinted into each new run's
trusted-validation snapshot and remains unchanged on resume, so concurrent
projects may safely use different deadlines. Legacy snapshot versions use the
same deterministic 60-minute fallback. Capability preparation remains capped
at the smaller of this value and 10 seconds.

An ignored project configuration may select root or project aliases through
the same pipeline setting, replacing that pipeline's root selection. The tracked
configuration example demonstrates `repository-check` in both writable pipelines.
Definitions cannot contain shell-string substitutes, environment or credential
fields, or extra host authority; profile implementations remain runner-owned.
Selection resolves to a durable fingerprinted snapshot before agent work, and
resume uses that snapshot. Later project configuration changes trigger the
protected-input guard. The runner owns the execution environment and executes
the vector directly. Before agent work, it resolves bubblewrap from fixed system
locations to a canonical absolute executable protected by system-owned file and parent
permissions. The pinned path is reverified on resume and execution. Its network
namespace has a minimal read-only system and repository view, private runtime
and temporary storage, a hidden user home, and a finite non-credential
environment. With source projection, the original repository and Git metadata
are absent and the owned copy replaces the read-only repository view. Rootless
Docker and command-owned services run inside the same
mount, network, and PID namespaces. The runner records its owned supervisor
identity and retires the complete tree, including detached descendants, before
reconciliation. Native-sandbox provider processes prefer private PID ownership
when the full nested shape is available. If nesting is unavailable on the
initial host namespace, only an explicitly declared provider may use
session/token ownership while its native sandbox remains mandatory;
ordinary processes retain private PID isolation. Nested runner tests reuse that
already-private PID namespace through the same distinct owned session when its
policy denies another PID namespace; no sandbox authority is added. A
readiness signal classifies isolation setup failures separately from executed
check failures. Workspace, Git, ref, remote, identity,
and validation-infrastructure snapshots must remain stable. Isolation or
process-tree retirement failures block or fail closed. Agent and runner results
form one complete ordered gate for the same content,
validation-infrastructure, command, and trusted-configuration fingerprints.

## Selection, isolation and receipts

Trusted receipts include Runner-measured elapsed attempts through preparation,
retirement, cleanup and safety checks. Missing legacy/controller timing stays
unknown; see validation evidence (`docs/product/VALIDATION_AND_REVIEW.md#evidence-and-fingerprints`).

A longer deadline changes only when an exact command times out. It cannot make
an incompatible sandbox work or improve native diagnostics. Trusted execution
deliberately retains no stdout or stderr, so a full repository check that passes
on the host can still fail closed in isolation with only a generic nonzero exit
status. Reproduce that incompatibility in an equivalent safe environment rather
than treating the timeout as a diagnostic or containment bypass.

## Transient build storage

For an offline build whose project-provided `build.js` supports `--out-dir`, a
trusted declaration can request transient output and cache storage:

```json
{
  "schemaVersion": 1,
  "trustedCommands": {
    "offline-build": {
      "command": "node build.js --out-dir /run/agent-runner/scratch/build",
      "executable": "node",
      "arguments": ["build.js", "--out-dir", "/run/agent-runner/scratch/build"],
      "capabilities": {
        "scratch": true,
        "cache": true,
        "sourceProjection": true
      }
    }
  },
  "pipelines": { "polishing": { "trustedChecks": ["offline-build"] } }
}
```

This fragment works in runner configuration or its safe project overlay. The
build tool and dependencies must be present in accepted source or supplied as
pinned artifacts; ignored untracked host dependency trees are not projected. Scratch provides
`AGENT_RUNNER_SCRATCH` and `TMPDIR`; cache provides `AGENT_RUNNER_CACHE`,
`XDG_CACHE_HOME`, and npm's cache binding. Paths are fixed by the runner; exact
argument vectors do not expand environment variables. Both directories are
private to one execution and removed after its process tree retires. Writes to
the projected source are permitted and discarded; the original repository and
network remain inaccessible. Interrupted cache or projection contents are not
reused. An uncertain cleanup keeps ownership evidence for operator recovery;
resume retries cleanup before new work.

## Pinned public artifacts

When a build needs a pinned public download, extend that command's `capabilities`
with `artifacts`. For example (replace the illustrative URL and digest with the
canonical HTTPS URL and verified SHA-256 of your file):

```json
{
  "scratch": true,
  "cache": true,
  "artifacts": [
    {
      "url": "https://downloads.example.com/tool.tar.gz",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
```

The build driver reads the verified file at
`/run/agent-runner/dependencies/<sha256>` or uses `AGENT_RUNNER_DEPENDENCIES`.
The mount is read-only. The runner acquires files before launching the exact
check, which remains network-isolated. Acquisition requires public DNS and HTTPS
with built-in TLS trust; redirects, proxies, credentials, and custom trust are
unsupported. Limits are 64 MiB per file, 256 MiB total, and five minutes overall,
with shorter DNS, connection, and inactivity deadlines. No automatic extraction
or host setup occurs: the declared command must extract or prepare inputs in
its declared scratch directory. Artifact-only commands need no scratch or cache
if they only read verified files. Downloads are never reused across executions.
Acquisition failures pause finalization as an environment blocker without running
the check. Repair the environment and resume; changing declarations requires a
new run. Do not delete uncertain resources until their ownership and transport
or process retirement have been independently verified.

## Capability discovery

Plan execution and polishing discover required capabilities read-only and recheck runner
availability before every writable checkpoint. Unsatisfied requirements pause as
`environment_blocked`; repair the environment and resume the saved request.
Changing trusted selection or declarations requires a new run. Inspection may
prepare verified dependencies but does not execute required checks; those remain
exclusive to finalization.
CLI status, `run_status` and `run_wait` show this pause with fixed text, each
bounded mismatch with its inventory index and required-check ID, omitted-blocker
counts and validated ownership facts. `run_activity` carries the same
`capabilityDiagnostic`, `capabilityChecks` and `ownershipDiagnostics` from each
event's own pause.
Unknown labels or missing details never clear the blocker. Commands, URLs and
saved free text are not shown.
The configuration example keeps `repository-check` on the read-only checkout
where its installed dependencies remain available, and uses the separate
`projected-build` declaration to demonstrate source-projection authority.
Execution can use only capabilities frozen at run creation.
