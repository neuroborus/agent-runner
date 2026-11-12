---
name: instruction-authoring
description: Keep agent instructions concise, owned, and discoverable without losing behavior. Use when writing or changing role prompts, agent-governing instructions, or skills.
---

# Instruction Authoring — Agent Runner

Apply these rules when authoring or changing role prompts, agent-governing
instructions, or skills. They shape the text only; they grant no role,
permission, or authority to execute the workflows the text describes.

## Necessity

- Every rule must change a concrete decision, behavior, or safety contract.
  If no consumer would act differently without it, omit it.
- Omit generic reminders, speculative incident catalogues, and lists of
  historical workarounds. Durable rationale belongs in `RHYTHM.md`.
- Prefer one semantic rule that names the governing principle over repeated
  per-phase paragraphs, new settings or knobs, or a generic framework.

## Ownership and reuse

- State a general obligation once, at its narrowest effective owner: the
  prompt module, skill, or document that owns the behavior.
- Compose or reuse that owned text wherever an actual consumer needs it,
  including continuation, reconstruction, recovery, and correction routes.
  Trace those routes before deciding where text belongs.
- Reuse across owners only through public contracts, indexes, and links, in
  the dependency direction allowed by
  [`docs/CONVENTIONS.md`](../../../docs/CONVENTIONS.md). Never add private or
  cross-pipeline imports to share prose.
- Do not copy inventories, permissions, or schemas into prose; refer to their
  owner, which stays authoritative.

## Progressive detail

- Keep always-loaded text to shared constraints and routing. Load conditional
  detail only in the role, phase, or reference that needs it.
- Keep a discoverable route to every shared rule, such as a composed constant,
  a link, or a documentation-map or change-gate row. A shared rule that an
  actual consumer can no longer find is not reuse.

## Preservation and honest limits

- Compare the meaning of every affected rule, permission, and behavior before
  and after the change. Never drop a real constraint merely to save lines.
- Record intended semantic changes in the owning specification and, for a
  durable decision, in `RHYTHM.md`.
- Prompt and skill prose is semantic guidance, not deterministic enforcement.
  Claim enforcement only for validators, schemas, and runner checks that exist.

## Evaluation

- Add an instruction or a test only when a concrete behavior or contract needs
  it; follow [test-authoring](../test-authoring/SKILL.md).
- Prove delivery with the smallest sufficient check through real request or
  prompt composition. Do not match copied sentences or count reassurance
  cases. Delivery coverage does not prove model compliance.
- Keep examples and fixtures neutral and self-contained.
- For skills also apply [skill-authoring](../skill-authoring/SKILL.md); for
  changed structured role contracts apply
  [contract-review](../contract-review/SKILL.md).
- Have the complete resulting instructions and their consumers reviewed
  independently through the task's existing review gate; a diff-only or
  author self-check is insufficient.
