---
name: skill-authoring
description: Create or update skills with a 100-line limit per Markdown file, preserved behavior and permissions, and independent reviewer/fixer iterations.
---

# Skill Authoring

Apply these acceptance gates to new skills and edits to existing skills.
Discover general skill-authoring guidance, such as `skill-creator`, by capability or name in the available skill catalog.
Read and use that guidance and its validator when available; do not hardcode installation paths.
The mandatory checks below remain required when no general authoring helper is available.

## Scope and baseline

- Establish the requested skill, destination, intended behavior, and authorized changes from the task and applicable instructions.
- For updates, read the whole existing skill tree and relevant callers; retain a baseline for comparison before editing.
- Preserve entry paths, required reading routes, rules, examples, code fences, and permission boundaries unless the user authorizes a substantive change.
- Preserve supported frontmatter, UI metadata, dependencies, and existing explicit-only invocation policy; use normal implicit discovery for new skills unless requested otherwise.
- Authoring instructions does not authorize executing their described workflows or external actions. Keep evaluations within existing authorization and use isolated local artifacts.
- Discover tools and helper paths from the current environment; never embed machine-specific roots or incidental project identifiers in reusable instructions.

## Structure and line limit

- Every Markdown instruction or reference file must contain at most **100 physical lines**, including `SKILL.md`, nested references, frontmatter, blank lines, and code-fence lines.
- Count the final unterminated line too; visual wrapping does not create physical lines.
- Split longer content by coherent purpose into focused files, each within the same limit. Do not compress rules into giant lines or remove substantive content to meet the cap.
- Keep shared constraints and routing in `SKILL.md`; link each extracted file where it is needed and state when it must be read.
- Preserve required reading order and gates after splitting. Resolve relative links from their containing file and repair links and anchors, including relevant inbound callers.
- Preserve stable entry paths and anchor destinations; use a concise linked continuation when needed to retain an existing entry.
- Keep examples meaningful and fences complete. Add only resources needed by the skill, without duplicated instructions or auxiliary README/changelog files.

## Local validation

Run this self-contained check with the actual skill directory as its argument:

```bash
python3 - /path/to/skill <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
if not root.is_dir() or not (root / "SKILL.md").is_file():
    raise SystemExit("Missing skill directory or SKILL.md")
failures = []
for path in sorted(root.rglob("*")):
    relative = path.relative_to(root)
    if not path.is_file():
        print(f"DIR/OTHER {relative}")
        continue
    if path.suffix.lower() in {".md", ".markdown"}:
        data = path.read_bytes()
        lines = data.count(b"\n") + int(bool(data) and not data.endswith(b"\n"))
        print(f"{relative}: {lines} physical lines")
        if lines > 100:
            failures.append(str(relative))
    else:
        print(f"FILE {relative}")
if failures:
    raise SystemExit("Over 100 lines: " + ", ".join(failures))
PY
```

- Inspect the complete final tree, including newly added files. Explicitly inspect linked instruction files outside the root and directory symlinks; apply the same line check to their Markdown files.
- Verify valid `name` and `description` frontmatter, consistent metadata and invocation policy, all relative links/anchors and required reading routes, complete examples/fences, and absence of unfinished scaffolding or placeholders.
- Compare every baseline rule and authorization boundary with the result; record any intentional behavior change and its authorization.
- Run the discovered general skill validator when available and exercise added or changed scripts with meaningful local cases. Validator success does not replace the checks above or independent review.
- After every fix, rerun affected checks; inventory and count the whole final skill again before each review handoff.

## Independent reviewer and fixer loop

- Read and apply [subagent-quality-loop](../subagent-quality-loop/SKILL.md) as the
  mandatory orchestration and zero-finding acceptance procedure for this authoring work.
- The author/fixer is the executor; a distinct independent reviewer must inspect every
  skill. The parent arranges any missing counterpart. Already-assigned agents perform
  only their role and never recursively create another pair.
- Give the reviewer the user intent, applicable constraints, baseline for updates, and
  complete final saved skill trees. The reviewer independently verifies every authoring
  gate above, including line limits, required reading routes, examples, metadata and
  permission preservation; the author's claims are not proof.
- The fixer saves corrections and reruns affected validation plus the complete final
  inventory and line check before each full review handoff. Any later edit requires
  revalidation and another complete independent pass.
- Follow the shared loop for all findings, withdrawals, blockers and the final
  exact-version zero-finding pass. Unavailable independent review leaves the work
  unfinished; self-review cannot replace it.

Report the resulting location, file counts and line-check outcome, validation performed, and final independent review status. Distinguish completed work from any remaining blocker.
