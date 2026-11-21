# Codex Isolation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Directory Permission Profiles

Each directory attempt installs an adapter-owned named permission profile at
App Server launch. Directory initialization negotiates `experimentalApi`, and
thread start/fork/resume and every turn explicitly select that profile through
the public `permissions` field. Selection must return its exact active profile,
without inheritance, and the requested working directory before a turn starts.
The profile retains Codex's host read baseline, reserves workspace roots
read-only, grants writes only to
declared outputs and the existing owner-only private command storage, and pins
inputs, sources, configuration, task, artifacts, infrastructure and discovered
controls read-only. Network remains denied. Effective configuration must match
before thread selection. The declared-profile comparison treats omission and
`null` as equivalent only for profile `description`, `extends` and
`workspace_roots`, filesystem `glob_scan_max_depth`, and network `proxy_url`,
`enable_socks5`, `socks_url`, `enable_socks5_udp`, `allow_upstream_proxy`,
`dangerously_allow_non_loopback_proxy`, `dangerously_allow_all_unix_sockets`,
`mode`, `domains`, `unix_sockets`, `allow_local_binding` and `mitm`. These are
unset optional settings in Codex's public configuration representation, including
0.167.0 `config/read`; no inheritance or workspace-root override is applied.
Unknown fields and non-null overrides reject, while filesystem access rules and
`network.enabled: false` must match exactly. Legacy omitted-default profiles
remain supported. This comparison changes neither the requested profile nor
Git-backed permissions. Model-free fixtures establish representation compatibility,
not historical failure attribution or successful live audit acceptance.
Native permission paths containing glob metacharacters
(`*`, `?`, `[`, `]`, `{`, `}` or `\`) are rejected before capability approval or
launch, preserving literal declarations instead of granting pattern-based access.
Directory requests omit legacy thread/turn sandbox
overrides so those cannot widen the profile; reconstruction rebinds it to the
new private allocation. The same output-only snapshot guard runs before each
attempt and after process retirement and storage cleanup, including failures,
before retry or acceptance. Uncertain process retirement retains the original
failure and blocks reconstruction; successful post-retirement verification is
required before requesting a fresh session. Reported file edits
and move destinations must also lie inside declared outputs. These adapter permissions expose no directory
workflow, publication or Git effect; pipeline lifecycle integration is separate.

## Workspace Writes and Private Storage

Codex repository workspace-write isolation exposes safe content writes
without Git-metadata writes. Codex protects project-root `.agents` as
provider metadata by default, so a workspace-write turn adds it as an explicit
writable root only when it exists as a real directory. A missing or symlinked
`.agents` stays protected, as do `.git` and `.codex`. For each Codex app-server
attempt, the runner creates one canonical owner-only private root beneath the
fixed platform temporary location without consulting ambient temporary
variables. The effective writable set is the repository content, including an
eligible `.agents`, and that private root. `TMPDIR`, `XDG_CACHE_HOME`, and
`XDG_RUNTIME_DIR` project validated children of the root into command tooling
through the effective shell policy. The policy starts from the full provider
process environment, applies Codex's automatic secret-name exclusions and an
empty custom exclusion list, overlays those explicit workspace values, and then
keeps exactly Codex's standard core names (`HOME`, `LOGNAME`, `PATH`, `SHELL`,
and `USER`), `AGENT_RUNNER_OWNED_PROCESS`, and the three workspace names. This
preserves the dynamic ownership proof without exposing unrelated parent
variables. The provider process environment remains unchanged, ambient
`TMPDIR` and host `/tmp` remain excluded, shell profiles stay disabled, and
command network access remains denied. In-session compaction retains the
attempt's root. Every successful, failed, or freshly recovered attempt validates
and removes its root before returning or retrying, and unsafe preparation or
cleanup fails closed.

## App Server Retirement

Codex observes owned-process completion as soon as the App Server starts and
races only its rejection against the complete protocol operation. An ownership
failure therefore starts bounded client and workspace cleanup promptly and
retains precedence over client-cleanup failures, even when containment
deliberately keeps protocol pipes open. Successful owned completion does not
satisfy a protocol request; the adapter still requires the complete App Server
result. App Server shutdown has up to three fixed one-second observation
windows: natural protocol close, TERM, then KILL. These post-turn cleanup phases
are containment invariants, not configurable provider-work deadlines.

## Named Profile Validation

Read the [current contract](sessions.md#disposable-sessions-and-source-lineage).
