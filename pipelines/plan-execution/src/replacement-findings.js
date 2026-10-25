import { createHash } from "node:crypto";

const version = (finding) =>
  createHash("sha256").update(JSON.stringify(finding)).digest("hex");
const key = (id, fingerprint) => `${id}:${fingerprint}`;
const findingId = (entry) =>
  typeof entry === "string" ? entry : entry.findingId;
const requestFields = ["pendingDisputes", "reviewReconsideration"];
const fields = [
  "pendingDisputes",
  "disputeCounts",
  "disputeHistory",
  "findingArbitrations",
  "sameFindingRounds",
  "findingOverrides",
  "reviewReconsideration",
];

function ownedVersion(state, finding) {
  const fingerprint = version(finding);
  const revision = state.effectivePlanRevisions.revisions.findLast(
    (entry) => entry.accepted,
  );
  return revision?.findingOwners.some(
    (owner) =>
      owner.id === finding.id &&
      owner.fingerprint === fingerprint &&
      owner.steps.includes(state.currentStep),
  )
    ? { revision: revision.number, id: finding.id, fingerprint }
    : null;
}

function activeFindings(state) {
  return [
    ...new Map(
      [
        ...state.previousFindings,
        ...state.primaryFindings,
        ...state.findings,
      ].map((finding) => [finding.id, finding]),
    ).values(),
  ];
}

function ownsId(state, id) {
  return state.effectivePlanRevisions.revisions
    .findLast((entry) => entry.accepted)
    ?.findingOwners.some(
      (owner) => owner.id === id && owner.steps.includes(state.currentStep),
    );
}

// ID-only working records remain local to one replacement. Only exact versions
// with reviewed ownership can regain their consumed decisions in a sibling.
export function retainReplacementFindingAccounting(before, after) {
  const records = new Map(
    after.replacementExecution.findingAccounting.map((entry) => [
      key(entry.id, entry.fingerprint),
      entry,
    ]),
  );
  function retain(
    state,
    excluded = new Set(),
    findings = activeFindings(state),
  ) {
    for (const finding of findings) {
      if (excluded.has(finding.id)) continue;
      const reference = ownedVersion(
        { ...after, currentStep: state.currentStep },
        finding,
      );
      if (!reference) continue;
      const scoped = Object.fromEntries(
        fields.map((field) => [
          field,
          Array.isArray(state[field])
            ? state[field].filter((entry) => findingId(entry) === finding.id)
            : Object.fromEntries(
                Object.entries(state[field]).filter(
                  ([id]) => id === finding.id,
                ),
              ),
        ]),
      );
      if (fields.every((field) => Object.keys(scoped[field]).length === 0))
        continue;
      const identity = key(reference.id, reference.fingerprint);
      const previous = records.get(identity);
      if (
        previous &&
        (state.workflowState === "IMPLEMENT" ||
          before.workflowState === "IMPLEMENT")
      )
        for (const field of requestFields) scoped[field] = previous[field];
      records.set(identity, {
        ...reference,
        ...scoped,
        ...(previous
          ? {
              revision: previous.revision,
              disputeCounts: Object.fromEntries(
                [finding.id].flatMap((id) => {
                  const count = Math.max(
                    previous.disputeCounts[id] ?? 0,
                    scoped.disputeCounts[id] ?? 0,
                  );
                  return count ? [[id, count]] : [];
                }),
              ),
              sameFindingRounds: Object.fromEntries(
                [finding.id].flatMap((id) => {
                  const count = Math.max(
                    previous.sameFindingRounds[id] ?? 0,
                    scoped.sameFindingRounds[id] ?? 0,
                  );
                  return count ? [[id, count]] : [];
                }),
              ),
              disputeHistory: [
                ...new Map(
                  [...previous.disputeHistory, ...scoped.disputeHistory].map(
                    (entry) => [entry.attempt, entry],
                  ),
                ).values(),
              ].sort((a, b) => a.attempt - b.attempt),
              findingArbitrations: scoped.findingArbitrations.length
                ? scoped.findingArbitrations
                : previous.findingArbitrations,
              findingOverrides: [
                ...new Map(
                  [
                    ...previous.findingOverrides,
                    ...scoped.findingOverrides,
                  ].map((entry) => [entry.fingerprint, entry]),
                ).values(),
              ],
            }
          : {}),
      });
    }
  }
  retain(before);
  // A disposition may remove its payload while adding the final history entry.
  // Bind that entry to the departing version before its working records retire.
  retain(
    { ...after, currentStep: before.currentStep },
    new Set(activeFindings(after).map(({ id }) => id)),
    activeFindings(before),
  );
  // Completion can remove the last active payload in the same transition.
  // Retire its requests before losing that version binding.
  for (const finding of activeFindings(before)) {
    const reference = ownedVersion(
      { ...after, currentStep: before.currentStep },
      finding,
    );
    const identity = reference && key(reference.id, reference.fingerprint);
    let saved = identity && records.get(identity);
    if (!saved) continue;
    for (const field of requestFields) {
      // Reconstruction suspends a reviewed request rather than resolving it.
      if (after.workflowState === "IMPLEMENT") continue;
      if (
        before[field].some((entry) => findingId(entry) === finding.id) &&
        !after[field].some((entry) => findingId(entry) === finding.id)
      )
        saved = { ...saved, [field]: [] };
    }
    records.set(identity, saved);
  }
  const next = { ...after };
  if (next.workflowState === "IMPLEMENT") {
    const suspendedDisputes = new Set(
      next.pendingDisputes
        .filter(({ findingId }) => ownsId(next, findingId))
        .map(({ findingId }) => findingId),
    );
    for (const field of requestFields)
      next[field] = next[field].filter(
        (entry) => !ownsId(next, findingId(entry)),
      );
    next.disputeCounts = Object.fromEntries(
      Object.entries(next.disputeCounts).filter(
        ([id]) => !suspendedDisputes.has(id),
      ),
    );
  }
  const previous = new Map(
    activeFindings(before).map((finding) => [finding.id, finding]),
  );
  const changed = new Set();
  for (const finding of activeFindings(after)) {
    if (!ownsId(before, finding.id) && !ownsId(after, finding.id)) continue;
    const prior = previous.get(finding.id);
    if (prior && version(prior) === version(finding)) continue;
    changed.add(finding.id);
    // A new payload cannot relabel the old version's ID-only working records.
    // Keep only consumption newly charged by this transition; lineage totals
    // and the original version's saved records remain unchanged.
    const increment = Math.max(
      0,
      (after.sameFindingRounds[finding.id] ?? 0) -
        replacementSameFindingRounds(before, prior, finding.id),
    );
    for (const field of fields) {
      next[field] = Array.isArray(next[field])
        ? next[field].filter((entry) => findingId(entry) !== finding.id)
        : Object.fromEntries(
            Object.entries(next[field]).filter(([id]) => id !== finding.id),
          );
    }
    const reference = ownedVersion(after, finding);
    const saved =
      reference && records.get(key(reference.id, reference.fingerprint));
    if (increment > 0)
      next.sameFindingRounds[finding.id] =
        (saved?.sameFindingRounds[finding.id] ?? 0) + increment;
  }
  retain(next, changed);
  for (const finding of activeFindings(next)) {
    const reference = ownedVersion(next, finding);
    const saved =
      reference && records.get(key(reference.id, reference.fingerprint));
    if (!saved) continue;
    for (const field of fields.filter((name) => name !== "sameFindingRounds")) {
      if (
        (requestFields.includes(field) ||
          (field === "disputeCounts" && saved.pendingDisputes.length > 0)) &&
        next.workflowState === "IMPLEMENT"
      )
        continue;
      next[field] = Array.isArray(next[field])
        ? [
            ...saved[field],
            ...next[field].filter((entry) => findingId(entry) !== finding.id),
          ]
        : { ...next[field], ...saved[field] };
    }
  }
  retain(next);
  return {
    ...next,
    replacementExecution: {
      ...next.replacementExecution,
      findingAccounting: [...records.values()],
    },
  };
}

export function replacementSameFindingRounds(state, finding, id = finding?.id) {
  const reference = finding && ownedVersion(state, finding);
  const saved =
    reference &&
    state.replacementExecution.findingAccounting.find(
      (entry) =>
        entry.id === reference.id &&
        entry.fingerprint === reference.fingerprint,
    );
  return Math.max(
    state.sameFindingRounds[id] ?? 0,
    saved?.sameFindingRounds[finding.id] ?? 0,
  );
}
