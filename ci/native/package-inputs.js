import { createHash } from "node:crypto";
import { win32 } from "node:path";

import { NativeEvidenceError } from "./evidence.js";
import { NATIVE_PACKAGE_INPUTS } from "./package-catalog.js";
import { normalizeNativePolicyBinding } from "./policy-template.js";

export const NATIVE_PACKAGE_LIMITS = Object.freeze({
  archiveBytes: 512 * 1024 * 1024,
  expandedBytes: 2 * 1024 * 1024 * 1024,
  members: 4096,
  reviewBytes: 1024 * 1024,
  acquisitionMs: 120000,
});
const BINDINGS = [
  "publication",
  "source",
  "build",
  "dependencies",
  "license",
  "abi",
  "transport",
  "extraction",
];

export function requirePackageValue(condition) {
  if (!condition) throw new NativeEvidenceError();
}

export function closedPackageObject(value, keys) {
  requirePackageValue(
    value !== null &&
      typeof value === "object" &&
      (Object.getPrototypeOf(value) === Object.prototype ||
        Object.getPrototypeOf(value) === null) &&
      Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
}

function list(value, maximum) {
  requirePackageValue(
    Array.isArray(value) &&
      Object.getPrototypeOf(value) === Array.prototype &&
      value.length <= maximum &&
      Reflect.ownKeys(value).length === value.length + 1,
  );
  for (let index = 0; index < value.length; index++) {
    const field = Object.getOwnPropertyDescriptor(value, index);
    requirePackageValue(field?.enumerable && Object.hasOwn(field, "value"));
  }
  return value;
}

export function packageMemberPath(value) {
  requirePackageValue(
    typeof value === "string" &&
      value.length <= 240 &&
      /^[A-Za-z0-9_.+/-]+$/u.test(value),
  );
  requirePackageValue(
    value
      .split("/")
      .every(
        (part) =>
          part &&
          part !== "." &&
          part !== ".." &&
          !part.endsWith(".") &&
          !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu.test(part),
      ),
  );
  return value;
}

export function nativePackageInput(id) {
  const entry = NATIVE_PACKAGE_INPUTS.find((input) => input.id === id);
  requirePackageValue(entry !== undefined);
  return entry;
}

function reference(value) {
  if (value === null) return null;
  closedPackageObject(value, ["url", "revision", "sha256"]);
  requirePackageValue(
    typeof value.url === "string" && value.url.length <= 2048,
  );
  let url;
  try {
    url = new URL(value.url);
  } catch {
    throw new NativeEvidenceError();
  }
  requirePackageValue(
    url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.port &&
      !url.hash &&
      url.href === value.url &&
      !url.search &&
      /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/u.test(url.hostname) &&
      !/^[0-9.]+$/u.test(url.hostname) &&
      !/(?:^|\.)(?:localhost|local|internal|test|invalid)$/u.test(url.hostname),
  );
  requirePackageValue(
    value.revision === null ||
      (typeof value.revision === "string" &&
        value.revision.length === 40 &&
        /^[a-f0-9]{40}$/u.test(value.revision) &&
        url.pathname.split("/").includes(value.revision)),
  );
  requirePackageValue(
    typeof value.sha256 === "string" &&
      value.sha256.length === 64 &&
      /^[a-f0-9]{64}$/u.test(value.sha256),
  );
  return { url: value.url, revision: value.revision, sha256: value.sha256 };
}

/** A complete independently reviewed member inventory, not an archive-generated
 * manifest. Null prerequisite bindings prevent acquisition and materialization. */
export function normalizeNativePackageReview(value, candidateSha) {
  const version = Object.getOwnPropertyDescriptor(
    value ?? {},
    "schemaVersion",
  )?.value;
  closedPackageObject(value, [
    "schemaVersion",
    "candidateSha",
    "packageId",
    "archiveBytes",
    "bindings",
    "files",
    ...(version === 2 ? ["entrypoint", "extraction"] : []),
  ]);
  requirePackageValue(
    typeof candidateSha === "string" &&
      candidateSha.length === 40 &&
      /^[a-f0-9]{40}$/u.test(candidateSha) &&
      [1, 2].includes(value.schemaVersion) &&
      value.candidateSha === candidateSha,
  );
  const input = nativePackageInput(value.packageId);
  requirePackageValue(
    value.schemaVersion === 1 || input.id === "git-for-windows",
  );
  requirePackageValue(
    value.archiveBytes === null ||
      (Number.isSafeInteger(value.archiveBytes) &&
        value.archiveBytes > 0 &&
        value.archiveBytes <= NATIVE_PACKAGE_LIMITS.archiveBytes &&
        (input.bytes === null || value.archiveBytes === input.bytes)),
  );
  closedPackageObject(value.bindings, BINDINGS);
  const bindings = Object.fromEntries(
    BINDINGS.map((key) => [key, reference(value.bindings[key])]),
  );
  if (input.sourceRevision !== null && bindings.source !== null)
    requirePackageValue(bindings.source.revision === input.sourceRevision);
  const names = new Set();
  let total = 0;
  const files = list(value.files, NATIVE_PACKAGE_LIMITS.members)
    .map((file) => {
      closedPackageObject(file, ["path", "bytes", "sha256", "executable"]);
      const name = packageMemberPath(file.path);
      requirePackageValue(
        !names.has(name.toLowerCase()) &&
          Number.isSafeInteger(file.bytes) &&
          file.bytes >= 0 &&
          file.bytes <= NATIVE_PACKAGE_LIMITS.expandedBytes &&
          typeof file.sha256 === "string" &&
          file.sha256.length === 64 &&
          /^[a-f0-9]{64}$/u.test(file.sha256) &&
          typeof file.executable === "boolean",
      );
      names.add(name.toLowerCase());
      total += file.bytes;
      requirePackageValue(total <= NATIVE_PACKAGE_LIMITS.expandedBytes);
      requirePackageValue(!file.executable || file.bytes > 0);
      return {
        path: name,
        bytes: file.bytes,
        sha256: file.sha256,
        executable: file.executable,
      };
    })
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const parents = new Map();
  for (const file of files) {
    const parts = file.path.split("/");
    parts.pop();
    while (parts.length) {
      const parent = parts.join("/"),
        folded = parent.toLowerCase();
      requirePackageValue(
        !names.has(folded) &&
          (!parents.has(folded) || parents.get(folded) === parent),
      );
      parents.set(folded, parent);
      parts.pop();
    }
  }
  const result = {
    schemaVersion: value.schemaVersion,
    candidateSha,
    packageId: input.id,
    archiveBytes: value.archiveBytes,
    bindings,
    files,
  };
  if (value.schemaVersion === 2) {
    requirePackageValue(value.entrypoint === "usr/bin/bash.exe");
    result.entrypoint = value.entrypoint;
    result.extraction = normalizeGitExtraction(value.extraction, candidateSha);
    requirePackageValue(
      bindings.extraction?.sha256 ===
        nativePackageReviewDigest(result.extraction),
    );
  }
  requirePackageValue(
    Buffer.byteLength(JSON.stringify(result)) <=
      NATIVE_PACKAGE_LIMITS.reviewBytes,
  );
  return result;
}

export function nativePackageReadiness(review) {
  const input = nativePackageInput(review.packageId);
  const missingInputs = BINDINGS.filter(
    (key) =>
      review.bindings[key] === null &&
      !(key === "source" && input.id.startsWith("claude-")),
  ).map((key) => `binding.${key}`);
  if (review.archiveBytes === null) missingInputs.push("archive.bytes");
  if (
    !(review.entrypoint ?? input.entrypoint) ||
    !review.files.some(
      (file) =>
        file.path === (review.entrypoint ?? input.entrypoint) &&
        file.executable,
    )
  )
    missingInputs.push("explicit-executable");
  if (!review.files.length) missingInputs.push("complete-member-inventory");
  if (input.format !== "tar.gz" && review.schemaVersion !== 2)
    missingInputs.push("reviewed-data-only-7z-extractor-and-Git/Bash-closure");
  return {
    status: missingInputs.length ? "BLOCKED" : "BOUND_INPUTS",
    missingInputs,
    admission: "BLOCKED",
  };
}

/** The executable is an independently reviewed extractor, never the SFX
 * publication or a runner/PATH selection. Policy admission remains native. */
export function normalizeGitExtraction(value, candidateSha) {
  closedPackageObject(value, [
    "schemaVersion",
    "candidateSha",
    "extractor",
    "policyBinding",
    ...(Object.hasOwn(value, "custody") ? ["custody", "setup", "loader"] : []),
  ]);
  requirePackageValue(
    value.schemaVersion === 1 && value.candidateSha === candidateSha,
  );
  const image = value.extractor;
  closedPackageObject(image, ["path", "bytes", "sha256", "bindings"]);
  requirePackageValue(
    typeof image.path === "string" &&
      /^[A-Za-z]:\\[^:]+\\package-extractor\.exe$/u.test(image.path) &&
      image.path.length <= 4096 &&
      win32.normalize(image.path) === image.path &&
      !/[\u0000-\u001f\u007f]/u.test(image.path) &&
      image.path
        .split("\\")
        .slice(1)
        .every(
          (part) =>
            part &&
            part !== "." &&
            part !== ".." &&
            !/[<>"|?*]|[. ]$/u.test(part) &&
            !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu.test(part),
        ) &&
      Number.isSafeInteger(image.bytes) &&
      image.bytes > 0 &&
      image.bytes <= 134217728 &&
      /^[a-f0-9]{64}$/u.test(image.sha256),
  );
  closedPackageObject(image.bindings, [
    "source",
    "build",
    "toolchain",
    "loader",
  ]);
  requirePackageValue(
    Object.values(image.bindings).every(
      (pin) => typeof pin === "string" && /^[a-f0-9]{64}$/u.test(pin),
    ),
  );
  const policyBinding = normalizeNativePolicyBinding(value.policyBinding);
  requirePackageValue(
    policyBinding.context.candidateSha === candidateSha &&
      policyBinding.context.platform === "win32" &&
      policyBinding.context.executionId === "package.git-for-windows",
  );
  if (Object.hasOwn(value, "custody")) {
    closedPackageObject(value.loader, [
      "components",
      "buildSha256",
      "sdkSha256",
    ]);
    closedPackageObject(value.setup, [
      "schemaVersion",
      "authoritySha256",
      "input",
      "assets",
      "endpoints",
    ]);
    requirePackageValue(
      value.custody?.context?.executionId === "package.git-for-windows" &&
        value.custody.context.candidateSha === candidateSha &&
        value.setup.schemaVersion === 1 &&
        value.setup.authoritySha256 ===
          policyBinding.template.provisioningReviewSha256 &&
        Array.isArray(value.setup.assets) &&
        value.setup.assets.length === 2 &&
        Array.isArray(value.setup.endpoints) &&
        value.setup.endpoints.length === 0 &&
        /^[a-f0-9]{64}$/u.test(value.loader.buildSha256) &&
        /^[a-f0-9]{64}$/u.test(value.loader.sdkSha256) &&
        Array.isArray(value.loader.components) &&
        value.loader.components.length > 0 &&
        value.loader.components.length <= 128 &&
        nativePackageReviewDigest(value.loader) === image.bindings.loader,
    );
    const indices = new Set();
    for (const component of value.loader.components) {
      closedPackageObject(component, ["index", "imports"]);
      requirePackageValue(
        Number.isSafeInteger(component.index) &&
          component.index >= 0 &&
          component.index < 128 &&
          component.index !== 9 &&
          !indices.has(component.index) &&
          Array.isArray(component.imports) &&
          component.imports.length <= 512,
      );
      indices.add(component.index);
      for (const dependency of component.imports) {
        closedPackageObject(dependency, ["name", "index"]);
        requirePackageValue(
          typeof dependency.name === "string" &&
            /^[a-zA-Z0-9_.-]{1,255}$/u.test(dependency.name) &&
            Number.isSafeInteger(dependency.index) &&
            dependency.index >= 0 &&
            dependency.index < 128,
        );
      }
    }
    requirePackageValue(
      indices.has(5) &&
        indices.has(6) &&
        value.loader.components.every((component) =>
          component.imports.every((dependency) =>
            indices.has(dependency.index),
          ),
        ),
    );
  }
  return { ...structuredClone(value), policyBinding };
}

export function nativePackageReviewDigest(review) {
  return createHash("sha256").update(JSON.stringify(review)).digest("hex");
}

/** Stream archive bytes to trusted private storage with backpressure. A matching
 * publication pin is byte consistency only, never native/provider acceptance. */
export async function* verifiedNativeArchiveChunks(source, expected) {
  closedPackageObject(expected, ["bytes", "integrity"]);
  requirePackageValue(
    Number.isSafeInteger(expected.bytes) &&
      expected.bytes > 0 &&
      expected.bytes <= NATIVE_PACKAGE_LIMITS.archiveBytes &&
      typeof expected.integrity === "string",
  );
  const sha256 = /^sha256:([a-f0-9]{64})$/u.exec(expected.integrity);
  const sha512 = /^sha512-([A-Za-z0-9+/]{86}==)$/u.exec(expected.integrity);
  requirePackageValue(
    (sha256 !== null && expected.integrity.length === 71) ||
      (sha512 !== null &&
        expected.integrity.length === 95 &&
        Buffer.from(sha512[1], "base64").toString("base64") === sha512[1]),
  );
  const hash = createHash(sha256 ? "sha256" : "sha512");
  let bytes = 0;
  for await (const chunk of source) {
    requirePackageValue(chunk instanceof Uint8Array);
    bytes += chunk.byteLength;
    requirePackageValue(bytes <= expected.bytes);
    const data = Buffer.from(chunk);
    hash.update(data);
    yield data;
  }
  requirePackageValue(
    bytes === expected.bytes &&
      hash.digest(sha256 ? "hex" : "base64") === (sha256 ?? sha512)[1],
  );
}

export async function verifyNativeArchive(source, expected, writeChunk) {
  requirePackageValue(typeof writeChunk === "function");
  for await (const data of verifiedNativeArchiveChunks(source, expected))
    await writeChunk(data);
  return {
    bytes: expected.bytes,
    integrity: expected.integrity,
    bindingStatus: "MATCHED",
    admission: "BLOCKED",
  };
}
