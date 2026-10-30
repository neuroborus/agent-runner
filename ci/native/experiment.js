import { PLATFORMS, NATIVE_EFFECT_CLASSES, NATIVE_GROUPS } from "./catalog.js";
import { normalizeNativeAdmission } from "./evidence.js";
import { compositionEffectRetired } from "./composition.js";
import { verifyRuntimeComponents } from "./closure.js";
import { nativeExperimentInventory } from "./system-inventory.js";
import {
  observationObject as closed,
  observationList as list,
  requireObservation as requireValue,
  observationDigest,
} from "./observation.js";

const contextKeys = [
  "candidateSha",
  "platform",
  "repository",
  "runId",
  "runAttempt",
];
const bindingKeys = [
  ...contextKeys,
  "checkoutSha",
  "image",
  "osBuild",
  "architecture",
  "nodeVersion",
  "workflow",
  "jobId",
];
const runtimeBindings = ["source", "build", "abi"];
const runtimeReadKeys = [
  "id",
  "sha256",
  "format",
  "loader",
  "bindings",
  "identityBefore",
  "identityAfter",
  "held",
  "independent",
];
const observationFlags = [
  "matched",
  "positiveControl",
  "attempted",
  "sentinelsUnchanged",
];
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const label = (value) =>
  typeof value === "string" && /^[a-z][a-z0-9.-]{0,95}$/u.test(value);
const text = (value) =>
  typeof value === "string" && /^[\x20-\x7e]{1,256}$/u.test(value);
const same = (a, b) => observationDigest(a) === observationDigest(b);
const ordered = (values) =>
  [...values].sort((a, b) => a.id.localeCompare(b.id, "en"));
const notStarted = () => ({
  admission: "not-started",
  settlement: {
    status: "RETAINED",
    independent: false,
    emergencyCleanup: false,
  },
  receiptSha256: null,
});

function context(value) {
  closed(value, contextKeys);
  requireValue(
    typeof value.candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      PLATFORMS.some(({ os }) => os === value.platform) &&
      typeof value.repository === "string" &&
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(value.repository) &&
      typeof value.runId === "string" &&
      /^[1-9][0-9]{0,19}$/u.test(value.runId) &&
      Number.isSafeInteger(value.runAttempt) &&
      value.runAttempt > 0,
  );
  return { ...value };
}

function identities(values, tools = false) {
  const entries = ordered(
    list(values, 128).map((entry) => {
      closed(entry, tools ? ["id", "sha256", "version"] : ["id", "sha256"]);
      requireValue(
        label(entry.id) &&
          hash(entry.sha256) &&
          (!tools || text(entry.version)),
      );
      return {
        id: entry.id,
        sha256: entry.sha256,
        ...(tools ? { version: entry.version } : {}),
      };
    }),
  );
  requireValue(
    entries.length > 0 &&
      new Set(entries.map(({ id }) => id)).size === entries.length,
  );
  return entries;
}

function effect(value) {
  closed(value, ["admission", "settlement", "receiptSha256"]);
  const result = normalizeNativeAdmission({
    admission: value.admission,
    settlement: value.settlement,
  });
  requireValue(
    result.settlement.status === "RETIRED"
      ? hash(value.receiptSha256)
      : value.receiptSha256 === null,
  );
  return { ...result, receiptSha256: value.receiptSha256 };
}

function runtimeReads(expected, observed) {
  return verifyRuntimeComponents(expected, observed).map((entry) =>
    Object.fromEntries(runtimeReadKeys.map((key) => [key, entry[key]])),
  );
}

/** Actual local build expectations are observations, never independent approvals.
 * Platform owners supply fresh checkout/tool/SDK reads and held image identities. */
export function normalizeExperimentPreparation(value, jobContext) {
  jobContext = context(jobContext);
  closed(value, ["purpose", "expected", "observed"]);
  requireValue(value.purpose === "experiment");
  const { expected, observed } = value;
  closed(expected, ["binding", "sources", "tools", "sdk", "components"]);
  closed(expected.binding, bindingKeys);
  const binding = Object.fromEntries(
    bindingKeys.map((key) => [key, expected.binding[key]]),
  );
  for (const key of contextKeys) requireValue(binding[key] === jobContext[key]);
  requireValue(
    binding.checkoutSha === binding.candidateSha &&
      binding.image ===
        PLATFORMS.find(({ os }) => os === binding.platform)?.image &&
      text(binding.osBuild) &&
      binding.architecture === "x64" &&
      binding.nodeVersion === "v24.21.0" &&
      binding.workflow === "native-poc" &&
      typeof binding.jobId === "string" &&
      /^[1-9][0-9]{0,19}$/u.test(binding.jobId),
  );
  const inventory = nativeExperimentInventory(binding.platform);
  const sources = identities(expected.sources),
    tools = identities(expected.tools, true);
  requireValue(
    same(
      tools.map(({ id }) => id),
      [...inventory.tools].sort(),
    ),
  );
  closed(expected.sdk, ["build", "sha256"]);
  requireValue(text(expected.sdk.build) && hash(expected.sdk.sha256));
  const sdk = { build: expected.sdk.build, sha256: expected.sdk.sha256 };
  const components = ordered(
    list(expected.components, 128).map((entry) => {
      closed(entry, ["id", "role", "sha256", "format", "loader", "bindings"]);
      closed(entry.bindings, runtimeBindings);
      const loader = list(entry.loader, 128);
      requireValue(
        label(entry.id) &&
          ["helper", "executable", "dependency"].includes(entry.role) &&
          hash(entry.sha256) &&
          runtimeBindings.every((key) => hash(entry.bindings[key])) &&
          entry.format ===
            { linux: "elf-x64", darwin: "macho-x64", win32: "pe-x64" }[
              binding.platform
            ] &&
          loader.every(label) &&
          new Set(loader).size === loader.length,
      );
      if (entry.role === "helper")
        requireValue(
          sources.some(
            ({ id, sha256 }) =>
              id === entry.id && sha256 === entry.bindings.source,
          ),
        );
      return {
        id: entry.id,
        role: entry.role,
        sha256: entry.sha256,
        format: entry.format,
        loader: [...loader].sort(),
        bindings: Object.fromEntries(
          runtimeBindings.map((key) => [key, entry.bindings[key]]),
        ),
      };
    }),
  );
  requireValue(
    new Set(components.map(({ id }) => id)).size === components.length &&
      same(
        components.filter(({ role }) => role === "helper").map(({ id }) => id),
        [...inventory.helpers].sort(),
      ) &&
      components.every(({ loader }) =>
        loader.every((id) => components.some((entry) => entry.id === id)),
      ),
  );
  closed(observed, [
    "binding",
    "sources",
    "tools",
    "sdk",
    "components",
    "independent",
    "readSha256",
  ]);
  closed(observed.binding, bindingKeys);
  closed(observed.sdk, ["build", "sha256"]);
  requireValue(
    observed.independent === true &&
      hash(observed.readSha256) &&
      bindingKeys.every((key) => observed.binding[key] === binding[key]) &&
      same(identities(observed.sources), sources) &&
      same(identities(observed.tools, true), tools) &&
      observed.sdk.build === sdk.build &&
      observed.sdk.sha256 === sdk.sha256,
  );
  return {
    purpose: "experiment",
    expected: { binding, sources, tools, sdk, components },
    observed: {
      binding: { ...binding },
      sources: identities(observed.sources),
      tools: identities(observed.tools, true),
      sdk: { ...sdk },
      components: runtimeReads(components, observed.components),
      independent: true,
      readSha256: observed.readSha256,
    },
  };
}

export function initialExperimentJob(input) {
  return normalizeExperimentJob({
    schemaVersion: 7,
    purpose: "experiment",
    tier: "system",
    ...context(input),
    preparation: null,
    preparationEffects: notStarted(),
    cases: [],
    failure: null,
  });
}

/** Distinct from reviewed v6 jobs and native/protected acceptance records. */
export function normalizeExperimentJob(value) {
  closed(value, [
    "schemaVersion",
    "purpose",
    "tier",
    ...contextKeys,
    "preparation",
    "preparationEffects",
    "cases",
    "failure",
  ]);
  requireValue(
    value.schemaVersion === 7 &&
      value.purpose === "experiment" &&
      value.tier === "system",
  );
  const jobContext = context(
    Object.fromEntries(contextKeys.map((key) => [key, value[key]])),
  );
  requireValue(
    [
      null,
      "preparation-failed",
      "probe-failed",
      "cleanup-failed",
      "deadline",
    ].includes(value.failure),
  );
  const preparationEffects = effect(value.preparationEffects);
  const preparation =
    value.preparation === null
      ? null
      : normalizeExperimentPreparation(value.preparation, jobContext);
  const recipes = nativeExperimentInventory(value.platform).cases;
  const cases = list(value.cases, recipes.length).map((entry, index) => {
    closed(entry, [
      "purpose",
      "id",
      "preparationSha256",
      "status",
      "elapsedMs",
      "cleanupMs",
      "policy",
      "components",
      "observations",
      "effects",
    ]);
    const recipe = recipes[index];
    requireValue(
      preparation &&
        preparationEffects.admission === "possible" &&
        entry.purpose === "experiment" &&
        entry.id === recipe.id &&
        entry.preparationSha256 === observationDigest(preparation) &&
        ["NOT_RUN", "PASS", "FAIL", "BLOCKED"].includes(entry.status),
    );
    for (const key of ["elapsedMs", "cleanupMs"])
      requireValue(
        entry[key] === null ||
          (Number.isSafeInteger(entry[key]) && entry[key] >= 0),
      );
    closed(entry.policy, [
      "expectedSha256",
      "observedSha256",
      "independent",
      "effective",
    ]);
    requireValue(
      hash(entry.policy.expectedSha256) &&
        (entry.policy.observedSha256 === null ||
          hash(entry.policy.observedSha256)) &&
        typeof entry.policy.independent === "boolean" &&
        typeof entry.policy.effective === "boolean",
    );
    const components =
      entry.components === null
        ? null
        : runtimeReads(preparation.expected.components, entry.components);
    const observations = list(entry.observations, recipe.checkIds.length).map(
      (item, checkIndex) => {
        closed(item, ["checkId", "observation"]);
        requireValue(item.checkId === recipe.checkIds[checkIndex]);
        closed(item.observation, ["expected", "observed", ...observationFlags]);
        requireValue(
          text(item.observation.expected) &&
            (item.observation.observed === null ||
              text(item.observation.observed)) &&
            observationFlags.every(
              (key) => typeof item.observation[key] === "boolean",
            ),
        );
        return {
          checkId: item.checkId,
          observation: {
            expected: item.observation.expected,
            observed: item.observation.observed,
            ...Object.fromEntries(
              observationFlags.map((key) => [key, item.observation[key]]),
            ),
          },
        };
      },
    );
    if (entry.status === "NOT_RUN") requireValue(observations.length === 0);
    closed(entry.effects, NATIVE_EFFECT_CLASSES);
    const effects = Object.fromEntries(
      NATIVE_EFFECT_CLASSES.map((key) => [key, effect(entry.effects[key])]),
    );
    const required =
      recipe.group === "build"
        ? ["builds"]
        : NATIVE_GROUPS[value.platform][recipe.group].effects;
    requireValue(
      NATIVE_EFFECT_CLASSES.every(
        (key) =>
          required.includes(key) ||
          key === "policy" ||
          effects[key].admission === "not-started",
      ),
    );
    if (entry.status === "PASS")
      requireValue(
        entry.elapsedMs !== null &&
          entry.elapsedMs <= recipe.deadlineMs &&
          entry.cleanupMs !== null &&
          entry.cleanupMs <= 30000 &&
          entry.policy.independent &&
          entry.policy.effective &&
          entry.policy.expectedSha256 === entry.policy.observedSha256 &&
          components &&
          observations.length === recipe.checkIds.length &&
          observations.every(
            ({ observation }) =>
              observation.expected === observation.observed &&
              observationFlags.every((key) => observation[key]),
          ) &&
          required.every((key) => effects[key].admission === "possible") &&
          Object.values(effects).every(compositionEffectRetired),
      );
    return {
      purpose: "experiment",
      id: entry.id,
      preparationSha256: entry.preparationSha256,
      status: entry.status,
      elapsedMs: entry.elapsedMs,
      cleanupMs: entry.cleanupMs,
      policy: {
        expectedSha256: entry.policy.expectedSha256,
        observedSha256: entry.policy.observedSha256,
        independent: entry.policy.independent,
        effective: entry.policy.effective,
      },
      components,
      observations,
      effects,
    };
  });
  requireValue(
    cases.length === 0 ||
      cases
        .slice(0, -1)
        .every(
          (entry) =>
            entry.status === "PASS" &&
            Object.values(entry.effects).every(compositionEffectRetired),
        ),
  );
  if (preparation) requireValue(preparationEffects.admission === "possible");
  return {
    schemaVersion: 7,
    purpose: "experiment",
    tier: "system",
    ...jobContext,
    preparation,
    preparationEffects,
    cases,
    failure: value.failure,
  };
}

/** Persist this possible admission before preparation effects. Settlement never
 * erases possible admission, and uncertain/emergency cleanup cannot pass. */
export function recordExperimentPreparationEffect(input, observed) {
  const job = normalizeExperimentJob(input);
  const next = effect(observed);
  requireValue(
    next.admission === "possible" &&
      job.preparationEffects.settlement.status !== "RETIRED" &&
      (!job.preparationEffects.settlement.emergencyCleanup ||
        next.settlement.emergencyCleanup) &&
      (job.preparationEffects.admission === "possible" ||
        (job.failure === null && next.settlement.status === "RETAINED")),
  );
  return normalizeExperimentJob({ ...job, preparationEffects: next });
}

/** Recovery closes only original admissions; it cannot fill observations or
 * turn an interrupted case into a passing case. Emergency history is sticky. */
export function recordExperimentRecovery(input, proof) {
  const job = normalizeExperimentJob(input);
  requireValue(
    proof?.status === "RETIRED" &&
      proof.independent === true &&
      proof.emergencyCleanup === false &&
      hash(proof.nativeEventSha256),
  );
  const cases = job.cases.map((entry) => ({
    ...entry,
    status: entry.status === "NOT_RUN" ? "FAIL" : entry.status,
    effects: Object.fromEntries(
      Object.entries(entry.effects).map(([key, effect]) => [
        key,
        effect.admission === "not-started" ||
        compositionEffectRetired(effect) ||
        effect.settlement.emergencyCleanup
          ? effect
          : {
              ...effect,
              settlement: {
                status: "RETIRED",
                independent: true,
                emergencyCleanup: false,
              },
              receiptSha256: observationDigest({
                purpose: "experiment",
                id: entry.id,
                key,
                preparationSha256: entry.preparationSha256,
                recovery: proof.nativeEventSha256,
              }),
            },
      ]),
    ),
  }));
  return normalizeExperimentJob({
    ...job,
    cases,
    failure:
      job.failure ??
      (job.cases.some(({ status }) => status !== "PASS")
        ? "probe-failed"
        : null),
  });
}

export function recordExperimentPreparation(input, expected, observed) {
  const job = normalizeExperimentJob(input);
  requireValue(
    job.preparation === null && job.preparationEffects.admission === "possible",
  );
  return normalizeExperimentJob({
    ...job,
    preparation: { purpose: "experiment", expected, observed },
  });
}

export function recordExperimentCase(input, proof) {
  const job = normalizeExperimentJob(input);
  requireValue(job.preparation);
  const closing =
    job.failure !== null ||
    job.preparationEffects.settlement.emergencyCleanup ||
    job.preparationEffects.settlement.status === "UNVERIFIABLE";
  const proofId = Object.getOwnPropertyDescriptor(proof ?? {}, "id")?.value;
  const candidate = normalizeExperimentJob({
    ...job,
    cases:
      job.cases.at(-1)?.id === proofId
        ? [...job.cases.slice(0, -1), proof]
        : [...job.cases, proof],
  });
  const next = candidate.cases.at(-1);
  const previous = job.cases.find(({ id }) => id === next.id);
  if (!previous)
    requireValue(
      !closing &&
        next.status === "NOT_RUN" &&
        next.components === null &&
        next.observations.length === 0 &&
        next.policy.observedSha256 === null &&
        Object.values(next.effects).every(
          ({ admission }) => admission === "not-started",
        ),
    );
  else {
    requireValue(
      (!closing || ["FAIL", "BLOCKED"].includes(next.status)) &&
        previous.status !== "PASS" &&
        (previous.status === "NOT_RUN" || previous.status === next.status) &&
        previous.policy.expectedSha256 === next.policy.expectedSha256,
    );
    if (previous.status !== "NOT_RUN")
      requireValue(
        Object.keys(previous)
          .filter((key) => !["effects", "cleanupMs"].includes(key))
          .every((key) => same(previous[key], next[key])),
      );
    for (const key of NATIVE_EFFECT_CLASSES) {
      const before = previous.effects[key],
        after = next.effects[key];
      if (closing || previous.status !== "NOT_RUN")
        requireValue(before.admission === after.admission);
      if (before.admission === "possible")
        requireValue(after.admission === "possible");
      else if (after.admission === "possible")
        requireValue(after.settlement.status === "RETAINED");
      if (before.settlement.emergencyCleanup)
        requireValue(after.settlement.emergencyCleanup);
      if (before.settlement.status === "RETIRED")
        requireValue(same(before, after));
    }
  }
  return candidate;
}
