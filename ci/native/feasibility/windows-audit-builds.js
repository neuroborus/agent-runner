import { mkdir } from "node:fs/promises";
import { win32 as path } from "node:path";
import { observationObject } from "../index.js";
import {
  buildWindowsCommandHelper,
  buildWindowsCustodyReader,
} from "../win32/index.js";
import { feasibilityFailureCause, requireFeasibility } from "./result.js";

const VARIANTS = ["command", "custody"];
const CONTEXT_FIELDS = ["candidateSha", "runId", "runAttempt"];
const BUILD_FIELDS = ["helperSha256", "sdkSha256", "abiSha256"];
const RESULT_FIELDS = ["variant", "status", "components", "build", "cause"];
const SOURCES = [
  ["windows-command-source", "windows-command-header", "windows-command-xml"],
  [
    "windows-custody-source",
    "windows-custody-header",
    "windows-custody-account",
    "windows-custody-policy",
  ],
];
const digest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const text = (value, maximum) =>
  typeof value === "string" &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  value.isWellFormed() &&
  !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(value);
const binding = (value) => {
  observationObject(value, CONTEXT_FIELDS);
  requireFeasibility(
    /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      /^[1-9][0-9]*$/u.test(value.runId) &&
      /^[1-9][0-9]*$/u.test(value.runAttempt),
  );
};

/** Independent build-only requests retain partial observations and attempt both variants. */
export async function buildWindowsAuditHelpers(
  { directory, environment, context },
  {
    create = mkdir,
    command = buildWindowsCommandHelper,
    custody = buildWindowsCustodyReader,
  } = {},
) {
  binding(context);
  requireFeasibility(
    path.isAbsolute(directory) &&
      path.normalize(directory) === directory &&
      (create !== mkdir ||
        (process.platform === "win32" &&
          process.arch === "x64" &&
          process.env.GITHUB_ACTIONS === "true" &&
          process.env.RUNNER_ENVIRONMENT === "github-hosted")),
  );
  const results = [];
  for (const variant of VARIANTS) {
    const components = [],
      root = path.join(directory, "audit-build-" + variant);
    let build = null,
      cause = null;
    try {
      await create(root, { mode: 0o700 });
      await create(path.join(root, "build"), { mode: 0o700 });
      const built = await (variant === "command" ? command : custody)(
        root,
        components,
        undefined,
        { environment },
      );
      build = Object.fromEntries(BUILD_FIELDS.map((key) => [key, built[key]]));
    } catch (error) {
      cause =
        error?.feasibilityCause ??
        feasibilityFailureCause("build", variant, error);
    }
    const status = cause ? "FAIL" : "PASS";
    results.push({ variant, status, components, build, cause });
  }
  return { schemaVersion: 1, ...context, results };
}

/** Build evidence is neither a helper execution nor native admission/retirement. */
export function assessWindowsAuditBuilds(value, context) {
  binding(context);
  observationObject(value, ["schemaVersion", ...CONTEXT_FIELDS, "results"]);
  requireFeasibility(
    value.schemaVersion === 1 &&
      CONTEXT_FIELDS.every((key) => value[key] === context[key]) &&
      Array.isArray(value.results) &&
      value.results.length === 2,
  );
  const lines = [];
  for (const [index, result] of value.results.entries()) {
    observationObject(result, RESULT_FIELDS);
    requireFeasibility(
      result.variant === VARIANTS[index] &&
        ["PASS", "FAIL"].includes(result.status) &&
        Array.isArray(result.components) &&
        result.components.length <= 16,
    );
    const names = new Map();
    for (const component of result.components) {
      observationObject(component, ["role", "name", "version", "sha256"]);
      requireFeasibility(
        ["tool", "helper"].includes(component.role) &&
          /^[a-z][a-z0-9-]{0,63}$/u.test(component.name) &&
          !names.has(component.name) &&
          /^(?:[0-9]+(?:\.[0-9]+)*|unqueried)$/u.test(component.version) &&
          text(component.version, 96) &&
          digest(component.sha256),
      );
      names.set(component.name, component);
    }
    if (result.status === "PASS") {
      const helper = names.get(
        index === 0 ? "windows-command-helper" : "windows-custody-reader",
      );
      observationObject(result.build, BUILD_FIELDS);
      requireFeasibility(
        result.cause === null &&
          Object.values(result.build).every(digest) &&
          names.size === SOURCES[index].length + 5 &&
          [
            ...SOURCES[index],
            "msvc",
            "msvc-linker",
            "windows-audit-removal-source",
          ].every((name) => names.get(name)?.role === "tool") &&
          names.get("windows-sdk-header")?.role === "tool" &&
          names.get("windows-sdk-header")?.sha256 === result.build.sdkSha256 &&
          helper?.role === "helper" &&
          helper.sha256 === result.build.helperSha256,
      );
    } else {
      observationObject(result.cause, ["code", "detail"]);
      requireFeasibility(
        result.build === null &&
          [
            "setup-failed",
            "prerequisite-unavailable",
            "deadline",
            "crash",
          ].includes(result.cause.code) &&
          text(result.cause.detail, 256) &&
          !/(?:https?:\/\/|(?:^|\s)(?:\/|[A-Za-z]:[\\/])|\b(?:authorization|password|secret|token|cookie)\s*[:=]|\bBearer\s|::)/iu.test(
            result.cause.detail,
          ),
      );
    }
    const detail =
      result.cause?.detail.replace(/[|\u0060*\\[\]<>]/gu, "") ??
      "compile/link and image inspection completed";
    lines.push(
      "| " + result.variant + " | " + result.status + " | " + detail + " |",
    );
  }
  return {
    passed: value.results.every((result) => result.status === "PASS"),
    summary:
      "\nWindows audit helper build-only verification\n\n| Variant | Result | Observation |\n| --- | --- | --- |\n" +
      lines.join("\n") +
      "\n\nNeither helper was executed; these builds supply no native acceptance or reviewed-input approval.\n",
  };
}
