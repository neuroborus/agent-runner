# Init proposal foundation

## Status and ownership

`pipelines/init/` owns infrastructure inspection policy, proposal contracts,
read-only role requests, bounded clarification and proposal approval. It is
deliberately unregistered: no CLI/MCP init command, publication, setup completion
or Git effect is available yet. `PROPOSAL_ACCEPTED` is an internal gate, never a
claim that infrastructure exists. Runner-owned publication and terminal
confirmation must precede registration and public completion.

The private workspace has no runtime dependencies. Root composition supplies
the public workspace and configuration capabilities; the pipeline does not
import root implementation files or another pipeline. Its descriptor selects a
directory lifecycle and canonical exclusive workspace lease before Git
inspection. Planner and Reviewer have only `read-only` access.

## Inspection and placement

`inspectInitSetup` consumes explicit instruction, check, skill and guidance file
inventories discovered from actual project evidence. It reads them through the
workspace capability and retains paths and hashes, not their contents. Empty
inventories are valid when the project has no such files. Agents must inspect
actual requirements and commands; hashes do not invent validation requirements.
Existing guidance text remains supervisor input; its inventory metadata reaches
proposal prompts without becoming instructions for those roles.

Candidate configurations are loaded through the configuration capability with
its existing target binding, precedence, ignored/untracked protections where
applicable, confined reads and provider-authority restrictions. The injected
loader is bound to the run's existing runner configuration and workspace kind;
Git inspection remains Git-owned. Candidate project settings are setup data,
never a second source of live role/settings resolution for init.
The caller supplies the resolved artifact root; its default stays configuration-owned.

Inspection binds the canonical target, task inputs, live configuration paths,
candidate roots, missing destinations, file contents/identities and real
ancestors. It rechecks configuration protection and snapshots around document
reads. The clarification service separately owns the transcript hash and
authorized edit windows. Task and clarification artifacts must be external to
the target, so initial setup requires no ignored target directory. Existing
repository-local artifact protections remain unchanged.

Placement is separate from review mode. The descriptor reserves CLI
`--placement integrated|external` and MCP `placement`; neither transport exposes
init yet. Missing placement reuses one unambiguous established target-bound
candidate. With no candidate, it selects integrated. Explicit configuration and
placement must agree. Multiple matching candidates require a material selection
during clarification; their resources are never merged or moved. Only explicitly
supplied external configurations are loaded; there is no sibling scan or global
registration. Explicit placement can propose a new destination while retaining
the previous setup.

Inspection receives the current placement and configuration selection. It
inspects the default external sibling only when a new external destination is
selected; an unusable unselected sibling cannot block integrated setup or reuse
of another bound external root. An authorized pre-closure selection change
requires a fresh setup inspection before clarification can freeze the new binding.
It retains the original inspection while waiting. Passing `previousInspection`
to `inspectInitSetup` carries previous destinations and evidence forward,
adds newly selected scopes, and verifies each
prior scope's content, identities, real ancestors and controls. A placement edit
cannot adopt changed task inputs, live configuration or previously inspected
resources, even when the destination stays the same.

New integrated configuration is `<artifactRoot>/agent-runner.json`. New external
configuration is `agent-runner.json` under the sibling root
`.agent-runner-<safe-name>-<12-character-path-hash>`, using the canonical target
path's SHA-256 prefix. An existing unbound destination is not adopted. Relative
resources use the selected root, and existing bound resources keep their exact
paths. A new external root must remain missing from the initial probe through
the bound inspection and document snapshots, retaining the probe's real ancestor
identities. Selection and the clarification hash freeze together before proposals.

## Read-only lifecycle

The proposal API uses explicit durable transitions. `prepareInitTurn` returns a
state reservation and a role request; the caller persists it before invoking an
adapter. Reloading a reservation retains its identity. `acceptInitResult`
requires that identity and a fresh unchanged setup inspection and transcript
hash. Consumed/stale results and read-only drift cannot advance the gate.

Every run starts in `CLARIFY`. Planner returns `READY`, material `QUESTIONS`, or
`BLOCKED`. Competing placements cannot close clarification. There are at most
three agent question rounds; this is not a configurable workflow budget.
Questions and their rationales use the shared service's 4,000-character plain-text limit.
An accepted question round first reserves a pending Runner-owned append.
After the shared clarification service appends the exact questions,
`acceptInitQuestionAppend` records its resulting hash against the reserved round,
previous hash and transcript path. The receipt is consumed before authorizing
an answer window and cannot be reused.
`authorizeInitEdit` is the clarification service's persist-before-open callback;
`acceptInitEdit` consumes the matching one-shot authorization, including an empty
or unchanged editor close, without spending another round. Material answers use
the shared `clarification-answers` action. An unchanged answer window leaves the
same questions pending; the caller authorizes a new window without invoking the
Planner or appending the questions again. An unchanged optional proactive window
returns to clarification normally. Only pre-closure
selection can change. The caller freezes the transcript through the existing
clarification service before `closeInitClarification`. There are no ordinary
question or editor paths after closure. Exceptional material product decisions
retain the root runner's persisted decision protocol when init is integrated.

Planner returns a complete structured proposal with actual checks and exact
configuration, artifacts, finalization and guidance resources, their inspected
prior hashes, actions and proposed contents. Results retain the two-MiB bound.
No role writes those resources. Proposed writes cannot overlap configuration
resolved for this run, existing skills, Git/provider controls or symbolic links.
Inspection retains workspace-discovered control paths, including Git metadata
whose directory name is not `.git`. The only control-tree write destinations
are the conventional `.agents` or `.claude` finalization `SKILL.md`/`RUNNER.md`
files; existing skills and nested controls remain protected. Exact task inputs
(`task.md`, optional `context.md`) and `clarifications.md`, plus inspected
instructions/check definitions, cannot be overwritten. A parent task directory
does not exclude unrelated setup destinations beneath it. Artifacts are
directories with no file content; other resources cannot replace directories or
use file ancestors. The frozen placement must match the recorded clarification
selection on every reload.
Guidance uses the selected artifact root's `agent-runner/rules.md`; ignore
resources can name only the integrated target's `.gitignore`, and finalization
resources must be Markdown procedures.
External resources stay outside the target; external proposals grant no target,
ignore, pointer-file, global configuration or provider authority.

| Mode          | Proposal gate                                                                       |
| ------------- | ----------------------------------------------------------------------------------- |
| `independent` | Planner proposal, separate Reviewer approval                                        |
| `lazy`        | Planner proposal, CHECK_AND_FIX, distinct CLEAN_CONFIRM                             |
| `combined`    | Planner proposal, CHECK_AND_FIX, distinct CLEAN_CONFIRM, separate Reviewer approval |

Independent remains the default and recommendation; lazy is explicit opt-in.
Inactive Reviewer configuration is not resolved or invoked. Planner check/fix
returns the complete durable replacement without writing files. Confirmation
and independent approval bind the same proposal, inspection, selection and
clarification hash. Findings clear dependent approvals and return to Planner;
combined revisions restart primary convergence. No arbitration is introduced.
Revision accounting is bounded, persisted and never renewed by reload. Exhaustion
pauses. Proposal acceptance grants no publication, staging or commit authority.
