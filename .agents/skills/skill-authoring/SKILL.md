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

- The orchestrator assigns two distinct agents per skill: an author/fixer and an independent reviewer. It manages handoffs and may reuse those agents across iterations.
- If assigned either role already, perform only that role; do not recursively spawn another pair. The orchestrator arranges any missing counterpart.
- Give the reviewer the user intent, applicable constraints, baseline for updates, and final saved skill tree. The reviewer must read those files independently and verify every gate above, rather than relying on the author's summary or validation claims.
- The reviewer returns actionable findings with file locations and required corrections, or an explicit clean result covering the complete skill.
- The author/fixer resolves all findings within authorized scope, saves the changes, reruns validation, and returns the complete result to the independent reviewer.
- Repeat until the reviewer reports zero unresolved findings on the final saved version. Any later edit requires revalidation and another independent review.
- If independent review is unavailable, unauthorized, or blocked, report the blocker and unfinished state clearly; never substitute self-review or claim a clean result.

Report the resulting location, file counts and line-check outcome, validation performed, and final independent review status. Distinguish completed work from any remaining blocker.
