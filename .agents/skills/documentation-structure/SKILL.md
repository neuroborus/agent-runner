---
name: documentation-structure
description: Place, split, move, and route maintained Markdown under the repository documentation-structure convention. Use when adding or restructuring documentation, changing README gates or reading routes, or fixing documentation line-limit, link, anchor, or reachability failures.
---

# Documentation Structure — Agent Runner

The [documentation-structure convention](../../../docs/CONVENTIONS.md#documentation-structure)
owns the document classes, line limits, split, README gate, link, anchor, and
reachability rules. This skill is the procedure for applying them; it does not
restate them or grant authority beyond the current task.

Apply [instruction-authoring](../instruction-authoring/SKILL.md) to moved or
rewritten rules, [project-structure](../project-structure/SKILL.md) to
ownership, [test-authoring](../test-authoring/SKILL.md) to changed checks, and
[finalization](../finalization/SKILL.md) before handoff. When the documents are
skills, also apply [skill-authoring](../skill-authoring/SKILL.md).

## 1. Find the owner first

- Use the document map and change gate in [`docs/README.md`](../../../docs/README.md)
  to find the existing owner of the rule or topic before adding content.
- Extend that owner or link to it; never add a second normative copy.
- Read the complete affected documents and the routes that lead readers to them.

## 2. Inventory consumers before a move

- Before moving, renaming, or splitting a document, list its real consumers:
  `AGENTS.md` and skill reading routes, prompt modules, semantic tests that
  read paths or text, runtime loaders, frozen file declarations, the package
  `files` list, and release assembly.
- Search the repository for the old path and every affected anchor.
- Update each consumer in the same change. A link alone does not deliver a
  moved document to a consumer that loads it by path.
- A change to a runtime-delivered or packaged document also needs the delivery
  and release coverage that [`docs/TESTING.md`](../../../docs/TESTING.md) selects.

## 3. Split and route

- Plan the split boundaries and README gates that the convention requires
  before editing, so that each resulting document has one owner.
- Move text with its meaning unchanged.
- Replace duplicated detail with a link to its owner.
- Repair inbound and outbound links and anchors, including the compatibility
  routes the convention requires for stable entry paths.
- Link every new document from the document map or from a gate that the map
  reaches.

## 4. Record the mapping

- For a split or move, record each source section heading with its destination
  and whether it was retained, moved, or merged.
- Return that mapping in the role's result or summary, or write it to an
  already ignored project-local artifact only when the current role's
  permissions allow that write; never put it in tracked content.
  Integration onto a newer base then reapplies that base's newer wording
  instead of this snapshot's.

## 5. Verify

- Measure the final formatted files. Follow the
  [finalization procedure](../finalization/SKILL.md#3-format-and-run-checks)
  for the fast gate, which enforces the limits, links, anchors, and reachability.
  Preserve the assigned executor and checkpoint. When the fast gate is selected
  for runner-trusted execution, Runner executes it during `FINALIZE`.
- Compare the meaning of every moved rule, permission, and example before and
  after, and confirm that every consumer was updated.
- Have the complete resulting documents and their consumers reviewed through
  the task's existing independent review gate; a diff-only check is not enough.
