# Shared Validation-Inventory Migrations

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Plan execution and polishing state version 2 persist the mode-specific
bootstrapped required-check inventory, the repository-relative files that own
validation infrastructure, and a runner-computed fingerprint of those files.
Plan execution and polishing each own a 256-item limit for each bootstrap role
inventory field and a separate 512-item limit for each derived, persisted,
finalization, and fingerprint-input field. A role exceeding its pipeline's limit
reports strict `CAPACITY_EXHAUSTED` with that `capacityField`
and per-role `capacityLimit`; required-check overflow takes priority. The
pipeline pauses without consuming a correction or accepting truncated evidence.
Validation infrastructure includes files owning commands, discovery, runners,
configuration, or mandatory finalization guidance, excluding ordinary source,
individual tests, fixtures, and generated output merely consumed by checks.
Classification uses responsibility rather than filename heuristics.
The Git validation-infrastructure fingerprint API accepts 512 paths; other Git
path lists retain their 256-path bounds. Execution state version 16 and polishing
state version 12 expand capacity with leased migrations preserving legacy 64/128
evidence, budgets, completed commits and handoffs, and one-shot effects. Those
capacity migrations left item and byte limits unchanged; current byte headroom
is specified by [structured result budgets](../structured-results.md). Expanded schemas
retain strict Claude preflight and native sandbox restrictions. Only Claude's
independently proved command-boundary policy sets `allowAllUnixSockets: true`
so the authenticated launcher, rather than Claude's automatic command path,
orders the pinned seccomp helper before its single bubblewrap boundary. Neither
process encloses or weakens provider transport.
In independent mode, the runner establishes that inventory from accepted Worker
evidence followed by accepted Reviewer evidence; in lazy mode, accepted Worker
evidence is complete. It deduplicates exact commands and paths in stable
first-seen order and assigns contiguous `C1`-through-`Cn` IDs; independent-mode
reconciliation and arbitration resolve only summaries and material
disagreements and cannot add commands or paths. Validation-migration discovery
uses the same mode-specific derivation.
The version-1 migration preserves safe workspace content while invalidating
active aggregate finalization and review evidence. Paused legacy evidence is
explicitly provisional: before a retry, override, finalization, or review can
advance, fresh independent Worker and Reviewer checkpoints re-establish the
inventory and the runner fingerprints it again. A consumed plan-execution
commit authorization remains on the verification path until Git resolves its
effect; migration never converts it into a replayable authorization. Immutable
terminal history is shape-upgraded without replaying an effect.
