// Fill semantic evidence slots without relaxing per-item or inventory bounds.
export const STRUCTURED_RESULT_BYTES = 2 * 1024 * 1024;

export function sizeEvidenceResult(result, evidenceLists, character = "x") {
  let remaining =
    STRUCTURED_RESULT_BYTES - Buffer.byteLength(JSON.stringify(result));
  const unitBytes = Buffer.byteLength(JSON.stringify(character)) - 2;
  for (const evidence of evidenceLists) {
    for (let index = 0; index < evidence.length && remaining > 0; index += 1) {
      const count = Math.min(3997, Math.floor(remaining / unitBytes));
      const remainder = Math.min(1, remaining - count * unitBytes);
      evidence[index] += character.repeat(count) + "x".repeat(remainder);
      remaining -= count * unitBytes + remainder;
    }
  }
  if (remaining !== 0) throw new Error("Insufficient evidence capacity.");
  return result;
}

export function largeFinalizationResult(character = "x") {
  const requiredChecks = Array.from({ length: 32 }, (_, index) => ({
    id: `C${index + 1}`,
    command: `node validation/check-${index}.js`,
  }));
  const result = {
    status: "PASS",
    skillPath: "",
    summary: "Synthetic validation evidence.",
    issues: [],
    requiredChecks,
    validationInfrastructure: [],
    checks: requiredChecks.map(({ id, command }) => ({
      checkId: id,
      command,
      status: "PASS",
      evidence: Array(32).fill("e"),
    })),
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
  return sizeEvidenceResult(
    result,
    result.checks.map(({ evidence }) => evidence),
    character,
  );
}
