import { PLATFORMS } from "./catalog.js";
import { normalizeReviewAuthority } from "./closure.js";
import {
  observationDigest as digest,
  observationObject as closed,
  observationList as list,
  requireObservation as requireValue,
} from "./observation.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const label = (value) =>
  typeof value === "string" && /^[a-z][a-z0-9.-]{0,95}$/u.test(value);
const IDENTITY_FIELDS = {
  uid: ["uid"],
  gid: ["gid"],
  sid: ["sid", "accountSid", "restrictingSid", "userSid"],
  session: ["sessionId", "auditSessionId"],
  custody: ["custodySha256", "identitySha256", "nonce"],
  "loopback-port": [
    "port",
    "clientPort",
    "serverPort",
    "localPort",
    "remotePort",
  ],
};
const same = (left, right) => digest(left) === digest(right);

// A template is bounded data, never executable interpolation. Only reviewed
// identity leaves may change; commands, grants, peers and tool bytes stay fixed.
function policyData(input) {
  let nodes = 0;
  const read = (value, depth) => {
    requireValue(++nodes <= 2048 && depth <= 16);
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "number") {
      requireValue(Number.isSafeInteger(value));
      return value;
    }
    if (typeof value === "string") {
      requireValue(
        value.length <= 4096 &&
          !/[\u0000-\u001f\u007f\uD800-\uDFFF]/u.test(value),
      );
      return value;
    }
    if (Array.isArray(value))
      return list(value, 256).map((item) => read(item, depth + 1));
    const keys = Reflect.ownKeys(value ?? {});
    requireValue(
      keys.length <= 256 &&
        keys.every(
          (key) =>
            typeof key === "string" &&
            /^[A-Za-z][A-Za-z0-9_.-]{0,95}$/u.test(key),
        ),
    );
    closed(value, keys);
    return Object.fromEntries(
      keys.sort().map((key) => [key, read(value[key], depth + 1)]),
    );
  };
  const policy = read(input, 0);
  requireValue(
    policy &&
      !Array.isArray(policy) &&
      typeof policy === "object" &&
      Buffer.byteLength(JSON.stringify(policy)) <= 65536,
  );
  return policy;
}
function identity(value, rule) {
  if (rule.kind === "sid") {
    requireValue(
      typeof value === "string" &&
        /^S-1-5-21-(?:[1-9][0-9]{0,9}-){3}[1-9][0-9]{0,9}$/u.test(value),
    );
    const parts = value.split("-").slice(4).map(Number);
    requireValue(
      parts.every((part) => part <= 4294967295) && parts.at(-1) >= 1000,
    );
  } else if (rule.kind === "custody") {
    requireValue(
      typeof value === "string" &&
        /^(?:[a-f0-9]{32}|[a-f0-9]{64}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})$/u.test(
          value,
        ),
    );
  } else
    requireValue(
      Number.isSafeInteger(value) &&
        value >= rule.minimum &&
        value <= rule.maximum,
    );
  return value;
}
export function normalizeNativePolicyTemplate(input) {
  closed(input, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "sourceReviewSha256",
    "provisioningReviewSha256",
    "policy",
    "bindings",
  ]);
  requireValue(
    input.schemaVersion === 1 &&
      typeof input.candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(input.candidateSha) &&
      PLATFORMS.some(({ os }) => os === input.platform) &&
      hash(input.sourceReviewSha256) &&
      hash(input.provisioningReviewSha256),
  );
  const policy = policyData(input.policy),
    occupied = new Set();
  const bindings = list(input.bindings, 32).map((rule) => {
    closed(rule, ["id", "kind", "paths", "minimum", "maximum"]);
    requireValue(
      label(rule.id) &&
        typeof rule.kind === "string" &&
        Object.hasOwn(IDENTITY_FIELDS, rule.kind),
    );
    if (["sid", "custody"].includes(rule.kind))
      requireValue(rule.minimum === null && rule.maximum === null);
    else {
      const floor =
        rule.kind === "loopback-port" ? 1024 : rule.kind === "session" ? 0 : 1;
      requireValue(
        Number.isSafeInteger(rule.minimum) &&
          Number.isSafeInteger(rule.maximum) &&
          rule.minimum >= floor &&
          rule.minimum <= rule.maximum &&
          rule.maximum <= (rule.kind === "loopback-port" ? 65535 : 2147483647),
      );
    }
    const paths = list(rule.paths, 64).map((raw) => {
      const path = list(raw, 16);
      requireValue(
        path.length > 0 &&
          path.every((part) =>
            typeof part === "string"
              ? /^[A-Za-z][A-Za-z0-9_.-]{0,95}$/u.test(part)
              : Number.isSafeInteger(part) && part >= 0 && part < 256,
          ) &&
          IDENTITY_FIELDS[rule.kind].includes(path.at(-1)),
      );
      const key = JSON.stringify(path);
      requireValue(!occupied.has(key));
      occupied.add(key);
      let value = policy;
      for (const [index, part] of path.entries()) {
        requireValue(value && Object.hasOwn(value, part));
        if (rule.kind === "loopback-port" && index === path.length - 1)
          requireValue(
            ["127.0.0.1", "::1"].includes(value.address) &&
              value.owned === true,
          );
        value = value[part];
      }
      closed(value, ["binding"]);
      requireValue(value.binding === rule.id);
      return [...path];
    });
    requireValue(paths.length > 0);
    return {
      id: rule.id,
      kind: rule.kind,
      paths,
      minimum: rule.minimum,
      maximum: rule.maximum,
    };
  });
  requireValue(new Set(bindings.map(({ id }) => id)).size === bindings.length);
  const walk = (value, path = []) => {
    if (!value || typeof value !== "object") return;
    if (Object.hasOwn(value, "binding")) {
      closed(value, ["binding"]);
      requireValue(occupied.has(JSON.stringify(path)));
      return;
    }
    for (const [key, child] of Object.entries(value))
      walk(child, [...path, Array.isArray(value) ? Number(key) : key]);
  };
  walk(policy);
  const template = {
    schemaVersion: 1,
    candidateSha: input.candidateSha,
    platform: input.platform,
    sourceReviewSha256: input.sourceReviewSha256,
    provisioningReviewSha256: input.provisioningReviewSha256,
    policy,
    bindings,
  };
  requireValue(Buffer.byteLength(JSON.stringify(template)) <= 65536);
  return template;
}
export const nativePolicyTemplateDigest = (input) =>
  digest(normalizeNativePolicyTemplate(input));
export function admitNativePolicyTemplate(input, approval) {
  const template = normalizeNativePolicyTemplate(input);
  normalizeReviewAuthority(approval, template.candidateSha, template.platform);
  requireValue(
    approval.manifestSha256 === nativePolicyTemplateDigest(template),
  );
  return template;
}
export function normalizePolicyTemplateApprovals(values, job) {
  const templates = list(values, 256).map((entry) => {
    closed(entry, ["template", "approval"]);
    const template = admitNativePolicyTemplate(entry.template, entry.approval);
    requireValue(
      template.candidateSha === job.candidateSha &&
        template.platform === job.platform &&
        template.sourceReviewSha256 === job.reviews.source?.manifestSha256 &&
        job.closure?.schemaVersion === 2 &&
        job.closure.policyTemplates.includes(entry.approval.manifestSha256),
    );
    return { template, approval: { ...entry.approval } };
  });
  requireValue(
    templates.length > 0 &&
      new Set(templates.map(({ approval }) => approval.manifestSha256)).size ===
        templates.length,
  );
  return templates;
}
export function normalizeNativePolicyContext(value) {
  closed(value, [
    "candidateSha",
    "platform",
    "tier",
    "runId",
    "runAttempt",
    "jobBindingSha256",
    "executionId",
    "closureSha256",
    "selectedSystemSha256",
  ]);
  requireValue(
    typeof value.candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      PLATFORMS.some(({ os }) => os === value.platform) &&
      ["system", "provider"].includes(value.tier) &&
      typeof value.runId === "string" &&
      /^[1-9][0-9]{0,19}$/u.test(value.runId) &&
      Number.isSafeInteger(value.runAttempt) &&
      value.runAttempt > 0 &&
      hash(value.jobBindingSha256) &&
      label(value.executionId) &&
      hash(value.closureSha256) &&
      (value.tier === "provider"
        ? hash(value.selectedSystemSha256)
        : value.selectedSystemSha256 === null),
  );
  return {
    candidateSha: value.candidateSha,
    platform: value.platform,
    tier: value.tier,
    runId: value.runId,
    runAttempt: value.runAttempt,
    jobBindingSha256: value.jobBindingSha256,
    executionId: value.executionId,
    closureSha256: value.closureSha256,
    selectedSystemSha256: value.selectedSystemSha256,
  };
}
export function nativePolicyContext(job, executionId) {
  closed(job.provenance, [
    "repository",
    "workflow",
    "runId",
    "runAttempt",
    "jobId",
  ]);
  requireValue(
    job.closure !== null &&
      typeof job.provenance.jobId === "string" &&
      /^[1-9][0-9]{0,19}$/u.test(job.provenance.jobId),
  );
  const jobBindingSha256 = digest(
    ["repository", "workflow", "runId", "runAttempt", "jobId"].map(
      (key) => job.provenance[key],
    ),
  );
  return normalizeNativePolicyContext({
    candidateSha: job.candidateSha,
    platform: job.platform,
    tier: job.tier,
    runId: job.provenance.runId,
    runAttempt: job.provenance.runAttempt,
    jobBindingSha256,
    executionId,
    closureSha256: digest(job.closure),
    selectedSystemSha256:
      job.tier === "provider" && job.selectedSystem
        ? digest(job.selectedSystem)
        : null,
  });
}

/** Provisioning is separately admitted and independently retains fresh native
 * identities. The materializer cannot supply or infer this receipt itself. */
export function materializeNativePolicy(
  input,
  approval,
  provisioning,
  inputContext,
) {
  const template = admitNativePolicyTemplate(input, approval),
    context = normalizeNativePolicyContext(inputContext);
  requireValue(
    context.candidateSha === template.candidateSha &&
      context.platform === template.platform,
  );
  closed(provisioning, [
    "schemaVersion",
    "context",
    "authoritySha256",
    "bindings",
    "held",
    "independent",
    "verifierSha256",
    "nativeEventSha256",
  ]);
  requireValue(
    provisioning.schemaVersion === 1 &&
      same(normalizeNativePolicyContext(provisioning.context), context) &&
      provisioning.authoritySha256 === template.provisioningReviewSha256 &&
      provisioning.held === true &&
      provisioning.independent === true &&
      hash(provisioning.verifierSha256) &&
      hash(provisioning.nativeEventSha256),
  );
  const values = list(provisioning.bindings, 32).map((value) => {
    closed(value, ["id", "kind", "value"]);
    return value;
  });
  requireValue(
    values.length === template.bindings.length &&
      new Set(values.map(({ id }) => id)).size === values.length,
  );
  const policy = structuredClone(template.policy);
  for (const value of values) {
    const rule = template.bindings.find(({ id }) => id === value.id);
    requireValue(rule && value.kind === rule.kind);
    identity(value.value, rule);
    for (const path of rule.paths) {
      let parent = policy;
      for (const part of path.slice(0, -1)) parent = parent[part];
      parent[path.at(-1)] = value.value;
    }
  }
  return {
    context,
    policy,
    templateSha256: nativePolicyTemplateDigest(template),
    templateReviewSha256: approval.manifestSha256,
    provisioningSha256: digest(provisioning),
    expectedPolicySha256: digest(policy),
  };
}
export function normalizeNativePolicyReceipt(value, context, templateSha256) {
  closed(value, [
    "schemaVersion",
    "context",
    "templateSha256",
    "templateReviewSha256",
    "provisioningSha256",
    "expectedPolicySha256",
    "requestSha256",
    "observationSha256",
    "verifierSha256",
    "independent",
  ]);
  requireValue(
    value.schemaVersion === 2 &&
      value.independent === true &&
      same(normalizeNativePolicyContext(value.context), context) &&
      value.templateSha256 === templateSha256 &&
      value.templateReviewSha256 === templateSha256,
  );
  for (const field of [
    "templateSha256",
    "provisioningSha256",
    "expectedPolicySha256",
    "requestSha256",
    "observationSha256",
    "verifierSha256",
  ])
    requireValue(hash(value[field]));
  return { ...value, context: normalizeNativePolicyContext(value.context) };
}

/** Complete effective authority is compared before payload release. Concrete
 * request and observation hashes are evidence, never independent approvals. */
export function verifyNativePolicy(
  input,
  approval,
  provisioning,
  context,
  requestSha256,
  observed,
) {
  const expected = materializeNativePolicy(
    input,
    approval,
    provisioning,
    context,
  );
  requireValue(hash(requestSha256));
  closed(observed, [
    "schemaVersion",
    "context",
    "templateSha256",
    "provisioningSha256",
    "requestSha256",
    "policySha256",
    "policy",
    "held",
    "complete",
    "independent",
    "verifierSha256",
    "nativeEventSha256",
  ]);
  requireValue(
    observed.schemaVersion === 1 &&
      same(normalizeNativePolicyContext(observed.context), expected.context) &&
      observed.templateSha256 === expected.templateSha256 &&
      observed.provisioningSha256 === expected.provisioningSha256 &&
      observed.requestSha256 === requestSha256 &&
      observed.policySha256 === expected.expectedPolicySha256 &&
      same(policyData(observed.policy), expected.policy) &&
      observed.held === true &&
      observed.complete === true &&
      observed.independent === true &&
      hash(observed.verifierSha256) &&
      hash(observed.nativeEventSha256),
  );
  return normalizeNativePolicyReceipt(
    {
      schemaVersion: 2,
      context: expected.context,
      templateSha256: expected.templateSha256,
      templateReviewSha256: expected.templateReviewSha256,
      provisioningSha256: expected.provisioningSha256,
      expectedPolicySha256: expected.expectedPolicySha256,
      requestSha256,
      observationSha256: digest(observed),
      verifierSha256: observed.verifierSha256,
      independent: true,
    },
    expected.context,
    expected.templateSha256,
  );
}

/** Only this independently supplied approval describes an executable policy.
 * Provisioning and concrete observations remain separate trusted inputs. */
export function normalizeNativePolicyBinding(value) {
  closed(value, ["template", "approval", "context"]);
  const template = admitNativePolicyTemplate(value.template, value.approval);
  const context = normalizeNativePolicyContext(value.context);
  requireValue(
    template.candidateSha === context.candidateSha &&
      template.platform === context.platform,
  );
  closed(template.policy, ["launch", "policy"]);
  return { template, approval: { ...value.approval }, context };
}

/** Generated byte/composition hashes are checked after materialization, not
 * approved in a cycle. All other launch fields and literal arguments stay fixed.
 * The two fixed provider renderings expose their declared identity leaves. */
export function nativePolicyLaunchData(input, args) {
  const request = structuredClone(input);
  delete request.policy.sha256;
  delete request.bindings.policy;
  const argumentsList = [...args];
  if (request.execution) {
    const execution = request.execution,
      url = new URL(execution.endpoint);
    requireValue(
      url.origin === execution.endpoint && url.hostname === "127.0.0.1",
    );
    const endpoint = {
      address: url.hostname,
      port: Number(url.port),
      owned: true,
    };
    const tokenKey =
      execution.provider === "codex"
        ? "NATIVE_POC_TOKEN"
        : "ANTHROPIC_AUTH_TOKEN";
    requireValue(
      execution.environment[tokenKey] === "native-poc-" + request.nonce,
    );
    execution.environment[tokenKey] = { nonce: request.nonce };
    if (execution.provider === "claude") {
      requireValue(
        execution.environment.ANTHROPIC_BASE_URL === execution.endpoint,
      );
      execution.environment.ANTHROPIC_BASE_URL = endpoint;
    } else {
      const flag =
        "model_providers.native_poc.base_url=" +
        JSON.stringify(execution.endpoint + "/v1");
      requireValue(
        argumentsList.filter((value) => value === flag).length === 1,
      );
      argumentsList[argumentsList.indexOf(flag)] = {
        setting: "model_providers.native_poc.base_url",
        endpoint,
        suffix: "/v1",
      };
    }
    execution.endpoint = endpoint;
  }
  return policyData({ request, arguments: argumentsList });
}

export function assertNativePolicyLaunchBinding(input, request, args) {
  const binding = normalizeNativePolicyBinding(input);
  const actual = nativePolicyLaunchData(request, args);
  const compare = (expected, value, path) => {
    if (
      expected &&
      typeof expected === "object" &&
      Object.hasOwn(expected, "binding")
    ) {
      const rule = binding.template.bindings.find(
        ({ id }) => id === expected.binding,
      );
      requireValue(rule && rule.paths.some((entry) => same(entry, path)));
      identity(value, rule);
    } else if (expected && typeof expected === "object") {
      requireValue(
        value &&
          typeof value === "object" &&
          Array.isArray(value) === Array.isArray(expected) &&
          same(Object.keys(expected).sort(), Object.keys(value).sort()),
      );
      for (const key of Object.keys(expected))
        compare(expected[key], value[key], [
          ...path,
          Array.isArray(expected) ? Number(key) : key,
        ]);
    } else requireValue(expected === value);
  };
  compare(binding.template.policy.launch, actual, ["launch"]);
  return binding;
}

export function materializeNativePolicyBinding(
  input,
  provisioning,
  request,
  args,
) {
  const binding = assertNativePolicyLaunchBinding(input, request, args);
  const expected = materializeNativePolicy(
    binding.template,
    binding.approval,
    provisioning,
    binding.context,
  );
  requireValue(
    same(expected.policy.launch, nativePolicyLaunchData(request, args)),
  );
  return expected;
}

export function assertNativePolicyParameters(
  binding,
  provisioning,
  input,
  args,
) {
  const { request, ...parameters } = input;
  const expected = materializeNativePolicyBinding(
    binding,
    provisioning,
    request,
    args,
  );
  requireValue(same(expected.policy.policy, policyData(parameters)));
  return expected;
}
