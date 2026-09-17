// Pipeline-owned report syntax. Authority and availability belong to the root
// capability; these fields cannot replace a frozen command declaration.
const text = { type: "string", minLength: 1, maxLength: 4_000 };
const artifact = {
  type: "object",
  additionalProperties: false,
  properties: {
    url: text,
    sha256: { type: "string", pattern: "^[a-f0-9]{64}$" },
  },
  required: ["url", "sha256"],
};
export const CAPABILITY_REQUIREMENTS = {
  type: "array",
  maxItems: 256,
  items: {
    type: "object",
    additionalProperties: false,
    properties: {
      command: text,
      commandIdentity: {
        anyOf: [
          { type: "null" },
          { type: "string", pattern: "^[a-f0-9]{64}$" },
        ],
      },
      capabilities: {
        type: "object",
        additionalProperties: false,
        properties: {
          scratch: { type: "boolean" },
          cache: { type: "boolean" },
          artifacts: { type: "array", maxItems: 32, items: artifact },
        },
        required: ["scratch", "cache", "artifacts"],
      },
      unsupported: {
        type: "array",
        maxItems: 16,
        items: { type: "string", pattern: "^[a-z][a-z0-9-]{0,63}$" },
      },
    },
    required: ["command", "commandIdentity", "capabilities", "unsupported"],
  },
};
export const ENVIRONMENT_BLOCKERS = {
  type: "array",
  maxItems: 256,
  items: {
    type: "object",
    additionalProperties: false,
    properties: {
      command: text,
      source: { type: "string", enum: ["agent-sandbox", "runner"] },
      evidence: { type: "array", minItems: 1, maxItems: 8, items: text },
    },
    required: ["command", "source", "evidence"],
  },
};
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const plain = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 4_000 &&
  value.trim() === value &&
  !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(value);
const bounded = (value, max) => Array.isArray(value) && value.length <= max;

export function validCapabilityReports(value, checks) {
  const commands = new Set(checks.map(({ command }) => command));
  if (
    !bounded(value.capabilityRequirements, 256) ||
    !bounded(value.environmentBlockers, 256)
  )
    return false;
  for (const report of value.capabilityRequirements) {
    if (
      !exact(report, [
        "command",
        "commandIdentity",
        "capabilities",
        "unsupported",
      ]) ||
      !commands.has(report.command) ||
      !(
        report.commandIdentity === null ||
        (typeof report.commandIdentity === "string" &&
          /^[a-f0-9]{64}$/u.test(report.commandIdentity))
      ) ||
      !exact(report.capabilities, ["scratch", "cache", "artifacts"]) ||
      typeof report.capabilities.scratch !== "boolean" ||
      typeof report.capabilities.cache !== "boolean" ||
      !bounded(report.capabilities.artifacts, 32) ||
      !bounded(report.unsupported, 16) ||
      report.unsupported.some(
        (item) =>
          typeof item !== "string" || !/^[a-z][a-z0-9-]{0,63}$/u.test(item),
      ) ||
      new Set(report.unsupported).size !== report.unsupported.length
    )
      return false;
    const urls = new Set();
    for (const item of report.capabilities.artifacts) {
      if (
        !exact(item, ["url", "sha256"]) ||
        !plain(item.url) ||
        typeof item.sha256 !== "string" ||
        !/^[a-f0-9]{64}$/u.test(item.sha256)
      )
        return false;
      let url;
      try {
        url = new URL(item.url);
      } catch {
        return false;
      }
      if (
        url.protocol !== "https:" ||
        url.href !== item.url ||
        url.username ||
        url.password ||
        item.url.includes("#") ||
        url.port ||
        !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/u.test(url.hostname) ||
        /(?:^|\.)(?:localhost|local|internal|test|invalid)$/u.test(
          url.hostname,
        ) ||
        /^[0-9.]+$/u.test(url.hostname) ||
        urls.has(item.url)
      )
        return false;
      urls.add(item.url);
    }
  }
  return value.environmentBlockers.every(
    (item) =>
      exact(item, ["command", "source", "evidence"]) &&
      commands.has(item.command) &&
      ["agent-sandbox", "runner"].includes(item.source) &&
      bounded(item.evidence, 8) &&
      item.evidence.length > 0 &&
      item.evidence.every(plain),
  );
}

export function inspectionRequirements(validations) {
  return validations.filter(Boolean).flatMap((value) => [
    ...value.capabilityRequirements.map(
      ({ command, commandIdentity, capabilities, unsupported }) => ({
        command,
        commandIdentity,
        unsupported,
        capabilities: {
          ...(capabilities.scratch ? { scratch: true } : {}),
          ...(capabilities.cache ? { cache: true } : {}),
          ...(capabilities.artifacts.length
            ? { artifacts: capabilities.artifacts }
            : {}),
        },
      }),
    ),
    // Exact delegation permits the root to distinguish agent confinement from
    // runner availability. An unselected command remains a blocker.
    ...value.environmentBlockers.map(({ command }) => ({ command })),
  ]);
}

export function freezeReport(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeReport(child);
    Object.freeze(value);
  }
  return value;
}
