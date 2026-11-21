# Runner Configuration

## Selected finalization guidance

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

The configuration capability lives under `src/config/` behind its public
`index.js`. Strict runner and project parsing, confined file loading, trusted
profile interpretation, and precedence-based resolution remain private,
acyclic modules. Root consumers use only the index, while pipeline descriptors
continue to own role lists, settings, defaults, and persisted-run validation.

## Global settings and migration

The root configuration capability owns global user settings behind
`src/config/index.js`. Private `user-settings.js` resolves Linux
`$XDG_CONFIG_HOME/agent-runner/config.json` (falling back to
`$HOME/.config/agent-runner/config.json` for unset, empty or relative XDG), macOS
`$HOME/Library/Application Support/agent-runner/config.json`, and Windows
`%APPDATA%\agent-runner\config.json` with a drive-qualified or UNC APPDATA root. This path
mapping does not extend Linux execution acceptance. User settings cannot reside
inside the installation. Loading creates no directories or files.
Only an absent user file permits the legacy installation-root
`.agent-runner.json` fallback; malformed, unreadable or unsafe user settings fail
closed. The layers never merge. Global files reuse the configuration boundary's
bounded UTF-8, no-link, real-ancestry reader. The selected global layer (also
called runner-root configuration) remains the only source of trusted profile
implementations and global-only settings. Project precedence is unchanged.

CLI `config migrate --from <legacy-file>` dispatches through the public
configuration boundary before runner creation or ordinary resolution. It
validates the source with the existing strict global schema before any writes.
`migrateRunnerConfiguration` creates missing mode-0700 parents through pinned
directory descriptors, writes and syncs a private mode-0600 temporary file, then
atomically links its complete bytes to the absent destination without replacement.
It removes only its owned temporary name, syncs the directory, verifies real
ancestor identities and reads back exact bytes. Descriptor-bound directory
access is required; it never falls back to an unsafe publication path. An existing
byte-identical destination returns unchanged; different bytes conflict without
merging, replacing or deleting either input. The source is always retained.
Interrupted temporary files are not configuration and are not removed by a later
invocation. Interruption between publication and temporary unlink can leave a
multi-link destination; both load and migration reject it without deleting
either name or the source. Only a completed publication with its temporary name
removed is recognized by an identical retry after lost acknowledgement.
No migration runs implicitly during load,
installation or resume, and no active run snapshot is re-resolved.

## Project selection and confined reads

For a new run, the root also discovers an optional ignored and untracked
`<project>/LOCAL_ARTIFACTS/agent-runner.json`, or uses an explicitly selected
confined project path from CLI/MCP. Explicit CLI `--project-config` / MCP
`projectConfigurationPath` may also select a target-bound external file.
Both files require `schemaVersion: 1`; unknown versions, pipelines, roles,
settings, and fields are errors. Project
configuration may define exact trusted commands, select trusted aliases,
override execution defaults, pipeline roles and settings, and select a normalized
infrastructure-relative artifact root. It cannot define profiles, credentials,
provider binaries, or arbitrary environment values. Integrated Git files must
remain ignored and untracked. Missing explicit, unsafe, and symbolic-link paths
are rejected without creating a file or changing ignore rules.

Project-only `infrastructure` is a closed version-1 object with `schemaVersion`,
`placement` (`integrated` or `external`), canonical absolute `projectPath` and
`rootPath`. The target must match the resolved workspace. Integrated roots equal
the target; external roots and targets must be disjoint, with the selected file
strictly below the root. External files require this binding and explicit
selection. Integrated discovery remains unchanged, and explicit selection
replaces discovery rather than merging competing placements. No sibling scan,
relocation, rewriting, registration or new host authority occurs.
The loader returns the binding as `infrastructure` and resolves `artifactPath`
from its root and the effective relative `artifactRoot`. Root composition passes
both resolved resources into execution and polishing state creation and custom
workspace selection. Their frozen `clarificationRoot` is the confinement owner;
the exact transcript is beneath the selected artifact path. Guidance and explicit
finalization retain this owner; authoring, audit and init keep task-owned artifacts. This resource
resolution grants no directory read or write permission. External configuration
can select custom directory semantics before Git inspection, just like an
integrated project overlay. For a Git selection supplied from a subdirectory,
external binding may resolve to the canonical worktree root while retaining the
exact selected file. Relative external selectors resolve before worktree-root
rebasing in fixed-workspace pipelines such as polishing as well as dynamic
pipelines. Fixed-workspace pipelines validate their workspace/state boundary
before loading configuration and retain that validated target during discovery.
Explicit external overlays resolve before a preliminary custom
default can prevent their higher-precedence commit selection. A custom directory
selection retains its requested scope; an external binding cannot widen it to
the enclosing worktree.

The confined read that supplies parsed project values also produces a
versioned protection record. It pins the canonical project and file paths,
repository-relative location, SHA-256 content hash, device/inode and bounded
file metadata, plus device/inode evidence for every real directory from the
project root to the file's parent. The initial read and every later inspection
use a bounded no-follow descriptor and compare path, descriptor, and ancestor
identity before and after reading. A project configuration must have one hard
link. Existing integrated protection remains version 1. External protection is
version 2 with the same content/file fields, an `infrastructureRoot`, a
root-relative `relativePath`, complete real ancestry from the filesystem root to the file's
parent, and `projectAncestors` through the target directory itself. Root identity
is included in that ancestry. Target ancestry is compared before and after the
read, so replacing an empty target also invalidates the binding. The state
boundary strictly validates both versions; legacy records are preserved without
rediscovery, inferred bindings or new execution authority.

The confined configuration reader retains `ERR_PROJECT_CONFIGURATION_READ`
and adds optional finite `constraint` metadata: `file_size` for the existing
1 MiB limit, or `isolated_regular_file` for its regular-file and single-link
guard. An explicitly selected integrated file proven absent has `missing_file`;
implicit absent discovery still returns `null`. Other read, decoding, confinement and identity failures retain their
existing handling without inferred constraints. Metadata grants no retry,
inspection acceptance or effect authority.

## Version 1 configuration example

The V1 shape is:

```json
{
  "schemaVersion": 1,
  "artifactRoot": "LOCAL_ARTIFACTS",
  "issueReporting": true,
  "clientAttribution": {
    "name": "agent_runner",
    "title": "Agent Runner"
  },
  "defaultBackend": "codex",
  "defaultProfile": "current",
  "defaultModel": "current",
  "defaultEffort": "current",
  "defaultContextSize": "current",
  "trustedCommandTimeoutMs": 3600000,
  "availabilityRetryMaxDelayMs": 1800000,
  "providerInactivityTimeoutMs": 1800000,
  "profiles": {
    "codex-work": {
      "backend": "codex",
      "profile": "work"
    },
    "claude-primary": {
      "backend": "claude",
      "configDirectory": "/profiles/claude-primary"
    }
  },
  "trustedCommands": {
    "service-tests": {
      "command": "npm run test:service",
      "executable": "npm",
      "arguments": ["run", "test:service"]
    }
  },
  "pipelines": {
    "plan-execution": {
      "mode": "independent",
      "finalization": "auto",
      "trustedChecks": ["service-tests"],
      "maxFixRoundsPerStep": 20,
      "roles": {
        "worker": {
          "backend": "claude",
          "profile": "claude-primary",
          "model": "sonnet",
          "contextSize": "200000"
        }
      }
    }
  }
}
```

## Global-only controls

`issueReporting` is runner-local, defaults to `true`, and is not accepted in a
project configuration. The MCP process loads it once at startup; applying a
change requires a restart. A disabled server omits the reporting tool, schema,
and related instructions from discovery. Other runner settings are reloaded
for each fresh report and persisted through its resolved reservation.

`clientAttribution` is also runner-root-only and defaults to the generic
`agent_runner` / `Agent Runner` identity. Configuration uses the public agent
contract to normalize the exact `{ name, title }` object, then rejects a custom
value when any active role's provider descriptor does not support it. There is
no project, CLI, MCP, pipeline, prompt, or repository-content override. The
normalized value and its SHA-256 fingerprint are immutable common run-envelope
fields. Production adapter sets are constructed through provider descriptors
from the resolved frozen value during creation and from the saved value on
resume; current configuration cannot replace it. Prompts, activity, public
status, and diagnostics omit both fields.

## Common deadlines

`trustedCommandTimeoutMs` is accepted by root and safe project configuration as
a strict integer from `1` through `2147483647` milliseconds and defaults to
`3600000` (60 minutes). The project value overrides the root value. It has no
CLI or MCP override because configuration resolution, not a transport-specific
surface, owns the deadline.

`availabilityRetryMaxDelayMs` is a common root/project setting, a strict integer
from `5000` through `2147483647` milliseconds, defaulting to `1800000` (30
minutes). Project configuration overrides root configuration; CLI, MCP, roles,
and pipelines do not introduce separate ceilings. Resolution freezes
`availabilityPolicy: { initialDelayMs: 5000, maxDelayMs }` when creating the run.
The state boundary owns the validated policy and deterministic schedule;
configuration consumes it through the public state index.

## Role selection and trusted profiles

`defaultBackend` is optional. A role's `profile`, `model`, `contextSize`, and
`effort` resolve from its role-specific override, the run-wide override, its
project-role value, the corresponding project-wide default, its pipeline-role
runner value, the corresponding runner-wide default, then the built-in string
`current`; a role-specific CLI override has highest precedence. CLI/MCP expose
profile, model, context size, and effort through the same runner input contract.
CLI uses `--effort` and descriptor-derived `--<role>-effort`; MCP uses `effort`
and `roleOverrides.<role>.effort`. Both validate the portable enum before
dispatch. MCP action identities include both selections before mutation;
detached continuations resume the saved run without re-resolving them. Explicit
CLI/MCP pipeline-setting overrides take precedence over project pipeline
settings, which take precedence over runner settings and descriptor defaults.
A profile alias is trusted runner configuration, pins one backend, and maps
only to a native Codex profile name or an isolated Claude configuration
directory. A conflicting explicit backend is invalid; profile configuration
cannot inject credentials, binaries, or arbitrary environment variables.
Without a selected profile, the backend resolves from the role override,
pipeline-role value, then `defaultBackend`; absence is a preflight error.

`current` omits that native override. For models this means both Codex and
Claude use the model selected by their effective native profile, process, or
backend native default; Agent Runner does not hard-code a backend model ID. An
explicit context size is a decimal token string validated by the selected
adapter and mapped to Codex's context-window setting or Claude's
auto-compaction token window. These controls are not treated as otherwise
equivalent.

Both configuration layers accept `defaultEffort` and role `effort` using only
`current|low|medium|high|xhigh|max`. Vocabulary validation includes inactive roles;
provider capability validation applies only to resolved active roles. Effort
remains separate from model IDs, and native translation belongs to adapters.
An explicit `current` at any precedence level retains the effective provider
default instead of inheriting a lower-precedence effort selection.

## Descriptor-owned settings and modes

Pipeline descriptors validate their own settings and supply built-in defaults.
The root loader owns only the versioned envelope, strict field validation, and
resolution precedence; it does not duplicate pipeline-specific role or setting
lists.

Descriptors may additionally validate relationships among resolved settings;
configuration applies this hook to complete root settings and merged project
settings before role resolution. Preliminary workspace discovery validates each
override value but defers relationships until the project overlay and overrides
are merged; a provisional combination cannot reject a valid effective selection.
Execution uses it to reject unsafe multiplication
of its positive-safe-integer `preferredCommitLineLimit` (900) and
`commitSizeAssessmentMultiplier` (3), including when its strict boolean
`automaticCommitSplitting` (default `true`) disables assessment. All three
values remain frozen on resume.

Plan authoring additionally owns the positive-safe-integer
`preferredCommitLineLimit`, default 900. Root configuration and a safe project
overlay resolve it through existing precedence before creation. It is a prompt
heuristic for anticipated additions plus deletions, including tests and
documentation: prefer cohesive commits within the target and explain genuinely
indivisible exceptions. It changes neither the shared plan contract nor execution
validation. Authoring state version 4 persists the value; the ordered version-3
migration supplies 900 to non-null legacy settings without configuration reload,
progress changes, or effect replay. The existing lease governs persistence of
that migration. Authoring planning, review, self-review, and recovery prompts
use the saved value. CLI `pipelines` displays descriptor-owned setting defaults;
MCP `pipelines_list` projects the same metadata.

Every built-in descriptor owns one string `mode` setting supporting
`independent`, `lazy`, and `combined`. A missing value resolves to
`independent`, which is the default and recommended option because its distinct primary and review
roles provide genuinely independent semantic review. That independence uses
more provider context and tokens. `lazy` is an explicit lower-consumption
choice that uses only the Planner for plan authoring or the Worker for execution
and polishing and does not provide independent review. Neither the root runner
nor a pipeline may select it automatically.

Runner and project configuration are deterministically validated for every
declared role. After settings resolve, the descriptor selects active roles.
Only those roles are resolved to a backend, profile, model, context size, and
effort; only they are probed, persisted in the run, checked against a source session,
and invoked. Public projections may identify an active role for bounded
activity, but expose neither provider-private values nor inactive role
configuration. Inactive Reviewer and Arbiter values remain untouched in the
configuration source for a later independent run. The resolved mode is
persisted when the run is created and is never reloaded on resume.

## Trusted command selection

`trustedCommands` is accepted in root and safe project configuration through
the same exact-vector validator. Each lowercase alias binds one exact inventory
command to one executable and argument vector. Definitions reject shell-string
substitutes and environment, credential, or host-authority fields.
Configuration privately merges normalized root then project catalogs in stable
order, deduplicates identical same-name definitions, and rejects conflicts even
when unselected. The merged catalog accepts at most 256 definitions, while each
immutable run snapshot remains limited to 32 selected commands. Direct argument
strings may contain line feeds for exact multiline scripts; other control
characters remain invalid. Plan execution and polishing each own a
`trustedChecks` setting; an ignored project configuration may replace that
pipeline's selection with root or project aliases. The default selection is
empty, and selected order determines snapshot order. Profile implementations
and trusted execution policy remain runner-owned. Before agent work, the root
resolves it into an immutable snapshot containing every selected vector,
deterministic command identities, an ordered command fingerprint, and a
trusted-configuration fingerprint. Resume uses that durable snapshot without
reloading either configuration source. Later project configuration changes
remain subject to the protected-input guard.
