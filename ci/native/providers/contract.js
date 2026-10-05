import {
  normalizeNativePackageReview,
  nativePackageReadiness,
  nativePackageReviewDigest,
  nativePackageInput,
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import { codexInvocation } from "./codex.js";
import { claudeInvocation } from "./claude.js";

export const PROVIDER_LIMITS = Object.freeze({
  imageBytes: 536870912,
  requestBytes: 1048576,
  responseBytes: 8388608,
  requests: 32,
  tokens: 32768,
  sessionMs: 120000,
  requestMs: 30000,
});
const digest = (v) => typeof v === "string" && /^[a-f0-9]{64}$/u.test(v);
const text = (v) =>
  typeof v === "string" &&
  v.length > 0 &&
  v.length <= 4096 &&
  v.isWellFormed() &&
  !/[\u0000-\u001f\u007f]/u.test(v);
const adapters = Object.freeze({
  codex: codexInvocation,
  claude: claudeInvocation,
});
const ENVIRONMENT = Object.freeze([
  "HOME",
  "PATH",
  "LANG",
  "TMPDIR",
  "TEMP",
  "TMP",
  "XDG_CACHE_HOME",
  "CODEX_HOME",
  "NATIVE_POC_TOKEN",
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_MODEL",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "CLAUDE_CONFIG_DIR",
  "DISABLE_AUTOUPDATER",
  "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
  "CLAUDE_CODE_GIT_BASH_PATH",
]);

export function normalizeProviderExecution(value, nonce) {
  observationObject(value, [
    "provider",
    "profile",
    "imageBytes",
    "closureSha256",
    "endpoint",
    "environment",
  ]);
  requireObservation(
    Object.hasOwn(adapters, value.provider) &&
      ["read-only", "workspace-write", "trusted-command"].includes(
        value.profile,
      ) &&
      Number.isSafeInteger(value.imageBytes) &&
      value.imageBytes > 0 &&
      value.imageBytes <= PROVIDER_LIMITS.imageBytes &&
      digest(value.closureSha256),
  );
  requireObservation(
    /^http:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/u.test(value.endpoint) &&
      Number(new URL(value.endpoint).port) >= 1024 &&
      Number(new URL(value.endpoint).port) <= 65535 &&
      new URL(value.endpoint).origin === value.endpoint,
  );
  const fields = Reflect.ownKeys(value.environment);
  requireObservation(
    fields.length > 0 &&
      fields.length <= ENVIRONMENT.length &&
      fields.every((key) => ENVIRONMENT.includes(key)),
  );
  observationObject(value.environment, fields);
  const environment = Object.fromEntries(
    fields.sort().map((key) => {
      requireObservation(text(value.environment[key]));
      return [key, value.environment[key]];
    }),
  );
  requireObservation(
    Object.entries(environment).reduce(
      (size, [key, item]) => size + Buffer.byteLength(key + "=" + item) + 1,
      0,
    ) <= 8192 &&
      text(environment.HOME) &&
      text(environment.PATH),
  );
  const tokenKey =
    value.provider === "codex" ? "NATIVE_POC_TOKEN" : "ANTHROPIC_AUTH_TOKEN";
  requireObservation(
    environment[tokenKey] === "native-poc-" + nonce &&
      !Object.hasOwn(
        environment,
        value.provider === "codex"
          ? "ANTHROPIC_AUTH_TOKEN"
          : "NATIVE_POC_TOKEN",
      ),
  );
  if (value.provider === "claude")
    requireObservation(
      environment.CLAUDE_CONFIG_DIR === environment.HOME &&
        environment.DISABLE_AUTOUPDATER === "1" &&
        environment.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC === "1",
    );
  else
    requireObservation(
      [
        "CLAUDE_CONFIG_DIR",
        "DISABLE_AUTOUPDATER",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        "CLAUDE_CODE_GIT_BASH_PATH",
      ].every((key) => !Object.hasOwn(environment, key)),
    );
  return {
    provider: value.provider,
    profile: value.profile,
    imageBytes: value.imageBytes,
    closureSha256: value.closureSha256,
    endpoint: value.endpoint,
    environment,
  };
}

/** Expected publication/member/build/ABI bindings remain independent inputs.
 * BOUND_INPUTS is consistency, never authorization or native source closure. */
export function normalizeProviderSpec(value) {
  const derived =
    Object.hasOwn(value, "entry") || Object.hasOwn(value, "closureSha256");
  observationObject(value, [
    "candidateSha",
    "nonce",
    "provider",
    "platform",
    "profile",
    "review",
    "home",
    "cache",
    "path",
    "endpoint",
    "model",
    ...(derived ? ["entry", "closureSha256"] : []),
  ]);
  requireObservation(
    Object.hasOwn(adapters, value.provider) &&
      ["linux", "darwin", "win32"].includes(value.platform) &&
      ["read-only", "workspace-write", "trusted-command"].includes(
        value.profile,
      ) &&
      /^[a-f0-9]{32}$/u.test(value.nonce),
  );
  const review = normalizeNativePackageReview(value.review, value.candidateSha);
  requireObservation(
    review.packageId === value.provider + "-" + value.platform &&
      nativePackageReadiness(review).status === "BOUND_INPUTS",
  );
  const entry = review.files.find(
    (file) => file.path === nativePackageInput(review.packageId).entrypoint,
  );
  requireObservation(
    entry.bytes > 0 && entry.bytes <= PROVIDER_LIMITS.imageBytes,
  );
  for (const key of ["home", "cache", "path", "model"])
    requireObservation(text(value[key]));
  requireObservation(
    value.home !== value.cache &&
      /^[A-Za-z0-9_.:/-]{1,128}$/u.test(value.model) &&
      /^http:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/u.test(value.endpoint),
  );
  const url = new URL(value.endpoint);
  requireObservation(
    Number(url.port) >= 1024 &&
      Number(url.port) <= 65535 &&
      url.origin === value.endpoint,
  );
  const closureSha256 = nativePackageReviewDigest(review);
  if (derived)
    requireObservation(
      value.closureSha256 === closureSha256 &&
        observationDigest(value.entry) === observationDigest(entry),
    );
  return { ...value, review, entry, closureSha256 };
}

export function providerInvocation(value) {
  const spec = normalizeProviderSpec(value),
    token = "native-poc-" + spec.nonce;
  const invocation = adapters[spec.provider](spec, token);
  const execution = normalizeProviderExecution(
    {
      provider: spec.provider,
      profile: spec.profile,
      imageBytes: spec.entry.bytes,
      closureSha256: spec.closureSha256,
      endpoint: spec.endpoint,
      environment: {
        HOME: spec.home,
        XDG_CACHE_HOME: spec.cache,
        PATH: spec.path,
        LANG: "en_US.UTF-8",
        TMPDIR: spec.cache,
        TEMP: spec.cache,
        TMP: spec.cache,
        ...invocation.environment,
      },
    },
    spec.nonce,
  );
  return {
    arguments: invocation.arguments,
    execution,
    specificationSha256: observationDigest(spec),
  };
}

export function providerEnvironmentBlock(execution, nonce) {
  const value = normalizeProviderExecution(execution, nonce);
  return Object.entries(value.environment)
    .map(([key, item]) => key + "=" + item)
    .join("\n");
}
