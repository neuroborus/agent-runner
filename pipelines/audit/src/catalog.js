function entries(values) {
  return Object.freeze(
    values.map(([name, description]) => Object.freeze({ name, description })),
  );
}

// Order is contractual: validation and the report legend use these same values.
export const AUDIT_CATALOG = Object.freeze({
  severities: entries([
    [
      "Critical",
      "Realistic conditions cause catastrophic harm or compromise; urgent action is needed.",
    ],
    [
      "High",
      "Realistic conditions cause major harm or break an essential guarantee.",
    ],
    ["Medium", "Plausible conditions cause a material but bounded defect."],
    [
      "Low",
      "Limited impact or likelihood, including minor established-convention defects.",
    ],
  ]),
  categories: entries([
    [
      "Correctness",
      "Incorrect behavior, requirements, invariants, or contracts.",
    ],
    [
      "Security",
      "Access boundaries, unsafe input or effects, secrets, or vulnerabilities.",
    ],
    [
      "Reliability",
      "Failure handling, recovery, cancellation, or resource lifecycle.",
    ],
    [
      "Performance",
      "Demonstrated avoidable time, memory, token, or other resource cost.",
    ],
    ["Architecture", "Ownership, coupling, complexity, duplication, or reuse."],
    [
      "Consistency",
      "Incompatible guarantees across equivalent interfaces or variants.",
    ],
    [
      "Validation",
      "Necessary verification, regression coverage, or test design.",
    ],
    [
      "Documentation",
      "Inaccurate, missing necessary, or contradictory operating guidance.",
    ],
    ["Nit", "Minor concrete convention, idiomaticity, or clarity defect."],
  ]),
  criteria: entries([
    [
      "Correctness",
      "Check implemented requirements, invariants, behavior, edge cases, and contract compatibility.",
    ],
    [
      "Conventions and minimalism",
      "Use established native/project idioms; identify unnecessary complexity, duplication, or dependencies.",
    ],
    [
      "Architecture",
      "Check cohesion, ownership, dependency direction, public boundaries, and existing capability reuse.",
    ],
    [
      "Homogeneity",
      "Compare guarantees across equivalent providers, modes, interfaces, and configuration paths; respect different contracts.",
    ],
    [
      "Security",
      "Check permission boundaries, untrusted input, secrets, dangerous effects, and evidence-supported dependency risks.",
    ],
    [
      "Reliability",
      "Check errors, cancellation, retries, resource ownership, recovery, and useful redacted diagnostics.",
    ],
    [
      "Validation and documentation",
      "Check necessary deterministic regression coverage, reasonable test cost, and agreement between behavior and documentation.",
    ],
    [
      "Performance and resources",
      "Require demonstrated avoidable cost or unbounded work, not speculative optimization or unsupported benchmarks.",
    ],
  ]),
});
