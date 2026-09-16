import { normalizeArtifacts } from "./artifact-contract.js";
import { TrustedValidationError } from "./errors.js";

const LIMIT = 256;
const FIELDS = new Set([
  "command",
  "commandIdentity",
  "capabilities",
  "unsupported",
]);

function invalid() {
  throw new TrustedValidationError(
    "Exact-command capability requirements are invalid.",
    {
      code: "ERR_INVALID_TRUSTED_REQUIREMENTS",
    },
  );
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function commandText(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 4_000 &&
    value.trim() === value &&
    !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  );
}

// Pipeline schemas own reporting. This boundary accepts only bounded needs,
// never executable vectors, authority grants, host paths, or environment values.
export function normalizeRequirementRequest({ inventory, requirements }) {
  if (
    !Array.isArray(inventory) ||
    inventory.length > LIMIT ||
    inventory.some((value) => !commandText(value)) ||
    new Set(inventory).size !== inventory.length ||
    !Array.isArray(requirements) ||
    requirements.length > LIMIT
  )
    invalid();
  const normalized = requirements.map((value) => {
    if (
      !record(value) ||
      Object.keys(value).some((key) => !FIELDS.has(key)) ||
      !inventory.includes(value.command)
    )
      invalid();
    const commandIdentity = value.commandIdentity ?? null;
    if (
      commandIdentity !== null &&
      (typeof commandIdentity !== "string" ||
        !/^[a-f0-9]{64}$/u.test(commandIdentity))
    )
      invalid();
    const needs = Object.hasOwn(value, "capabilities")
      ? value.capabilities
      : {};
    if (
      !record(needs) ||
      Object.keys(needs).some(
        (key) => !["scratch", "cache", "artifacts"].includes(key),
      )
    )
      invalid();
    const capabilities = {};
    for (const name of ["scratch", "cache"]) {
      if (!Object.hasOwn(needs, name)) continue;
      if (needs[name] !== true) invalid();
      capabilities[name] = true;
    }
    if (Object.hasOwn(needs, "artifacts")) {
      capabilities.artifacts = normalizeArtifacts(needs.artifacts);
      if (capabilities.artifacts === null) invalid();
    }
    const unsupported = Object.hasOwn(value, "unsupported")
      ? value.unsupported
      : [];
    if (
      !Array.isArray(unsupported) ||
      unsupported.length > 16 ||
      unsupported.some(
        (item) =>
          typeof item !== "string" || !/^[a-z][a-z0-9-]{0,63}$/u.test(item),
      ) ||
      new Set(unsupported).size !== unsupported.length
    )
      invalid();
    return Object.freeze({
      command: value.command,
      commandIdentity,
      capabilities: Object.freeze(capabilities),
      unsupported: Object.freeze([...unsupported]),
    });
  });
  return Object.freeze({
    inventory: Object.freeze([...inventory]),
    requirements: Object.freeze(normalized),
  });
}

export function requirementBlockers(request, snapshot) {
  const blockers = [];
  for (const command of request.inventory) {
    const selected = snapshot.commands.find((item) => item.command === command);
    const reports = request.requirements.filter(
      (item) => item.command === command,
    );
    let reason;
    if (!selected && reports.length > 0) reason = "not-selected";
    else if (reports.some((item) => item.unsupported.length > 0))
      reason = "unsupported";
    else if (
      reports.some((item) => {
        if (
          item.commandIdentity !== null &&
          item.commandIdentity !== selected?.identity
        )
          return true;
        const authority = selected?.capabilities ?? {};
        return (
          ["scratch", "cache"].some(
            (key) => item.capabilities[key] && !authority[key],
          ) ||
          (item.capabilities.artifacts ?? []).some(
            (artifact) =>
              !(authority.artifacts ?? []).some(
                (allowed) =>
                  artifact.url === allowed.url &&
                  artifact.sha256 === allowed.sha256,
              ),
          )
        );
      })
    )
      reason = "insufficient-authority";
    if (reason)
      blockers.push(
        Object.freeze({
          command,
          commandIdentity: selected?.identity ?? null,
          reason,
          evidence: Object.freeze([
            "The reported needs cannot be satisfied by the frozen runner authority.",
          ]),
        }),
      );
  }
  return blockers;
}
