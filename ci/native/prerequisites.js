import { createHash } from "node:crypto";
import { posix, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import {
  observationObject,
  observationDigest,
  requireObservation,
} from "./observation.js";
import {
  nativePackageInput,
  normalizeNativePackageReview,
  nativePackageReadiness,
  nativePackageReviewDigest,
  packageMemberPath,
  NATIVE_PACKAGE_LIMITS,
} from "./package-inputs.js";
import { prepareReviewedNativePackage } from "./package-acquisition.js";
import { nativePreparationError } from "./first-failure.js";
import { createPrerequisiteCustody } from "./prerequisite-custody.js";

export function createPrerequisiteEffects(input, options = {}) {
  const manifest = input.manifest;
  normalizeNativePrerequisites(manifest.prerequisites, manifest, {
    sources: manifest.helpers.map(({ name }) => name),
  });
  return createPrerequisiteCustody(input, options);
}

const platformFactories = Object.freeze({
  linux: {
    load: () => import("./linux/index.js"),
    build: "createLinuxBuildEffects",
    system: "createLinuxSystemEffects",
  },
  darwin: {
    load: () => import("./darwin/index.js"),
    build: "createDarwinBuildEffects",
    system: "createDarwinSystemEffects",
  },
  win32: {
    load: () => import("./win32/index.js"),
    build: "createWindowsBuildEffects",
    system: "createWindowsSystemEffects",
  },
});
async function composeNative(input, kind, options) {
  requireObservation(Object.hasOwn(platformFactories, input?.job?.platform));
  const selected = platformFactories[input.job.platform],
    api = await selected.load();
  return api[selected[kind]](input, options);
}
export const createNativeBuildEffects = (input, options) =>
  composeNative(input, "build", options);
export const createNativeSystemEffects = (input, options) =>
  composeNative(input, "system", options);

/** Admit acquired entry bytes against the exact checked-in candidate entry
 * before evaluation. Relative imports resolve only to fixed repository owners;
 * evaluating the captured bytes avoids a named-entry substitution race. */
export async function loadNativeEffects(bundle) {
  const expected = bundle.manifest.capabilitySha256;
  const file = fileURLToPath(new URL("./native-effects.mjs", import.meta.url));
  const bytes = await bundle.read(file, 2097152);
  requireObservation(
    bundle.manifest.schemaVersion === 2 &&
      Buffer.isBuffer(bytes) &&
      Buffer.isBuffer(bundle.capabilityBytes) &&
      bytes.equals(bundle.capabilityBytes) &&
      digest(bytes) === expected &&
      bundle.manifest.source.citations.filter(
        (entry) =>
          entry.kind === "reached-code" &&
          entry.member === "candidate/ci/native/native-effects.mjs" &&
          entry.sha256 === expected,
      ).length === 1,
  );
  let source = bytes.toString("utf8");
  requireObservation(Buffer.from(source).equals(bytes));
  source = source.replaceAll(
    '"./index.js"',
    JSON.stringify(new URL("./index.js", import.meta.url).href),
  );
  return import(
    `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`
  );
}

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const images = {
  // Linux's privileged entry remains the separately prepared Bubblewrap owner.
  linux: [],
  darwin: ["custody-reader", "build-helper", "launcher"],
  win32: ["package-extractor"],
};
const headers = {
  linux: [],
  darwin: ["custody.h", "file-identity.h", "effective-reader.h"],
  win32: ["custody.h", "effective-reader.h", "account.h"],
};
export const NATIVE_PREREQUISITE_LIMITS = Object.freeze({
  assetBytes: 134217728,
  assetTotalBytes: 1073741824,
  inputBytes: 536870912,
  inputMembers: 3 * NATIVE_PACKAGE_LIMITS.members + 600,
  inputTotalBytes:
    3 * NATIVE_PACKAGE_LIMITS.expandedBytes + 2 * 1024 * 1024 * 1024,
  metadataBytes: 8 * 1024 * 1024,
});
const imageNamesFor = (platform, sources) =>
  platform === "win32" ? [...sources, ...images.win32] : images[platform];
export const prerequisitePreparationBound = (
  platform,
  sources = [],
  plans = 0,
) =>
  60000 +
  (imageNamesFor(platform, sources).length +
    sources.length +
    headers[platform].length +
    plans) *
    30000 +
  (platform === "win32" ? 3 : 2) * NATIVE_PACKAGE_LIMITS.acquisitionMs +
  (platform === "win32" ? 150000 : 0);
const pathsFor = (platform) => (platform === "win32" ? win32 : posix);
const absolute = (value, paths) =>
  typeof value === "string" &&
  paths.isAbsolute(value) &&
  paths.normalize(value) === value &&
  value.length <= 4096 &&
  !/[\u0000-\u001f\u007f]/u.test(value) &&
  (paths !== win32 ||
    (/^[A-Za-z]:\\[^:]+$/u.test(value) &&
      value
        .split("\\")
        .slice(1)
        .every(
          (part) =>
            part &&
            !/[<>"|?*]|[. ]$/u.test(part) &&
            !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu.test(part),
        )));

export async function persistPrerequisiteRecord(effects, record) {
  const proof = await effects.persist(structuredClone(record));
  requireObservation(
    proof?.recordSha256 === observationDigest(record) &&
      proof.independent === true &&
      proof.held === true &&
      proof.immutable === true &&
      proof.protectedParents === true &&
      proof.birthProtected === true &&
      hash(proof.identitySha256) &&
      hash(proof.nativeEventSha256),
  );
}

/** Pure metadata admission. The fixed inventory cannot be manufactured from
 * newly built outputs or the current host. Approval belongs to the enclosing
 * independently pinned system manifest, not downloaded labels. */
export function normalizeNativePrerequisites(value, manifest, profile) {
  observationObject(value, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "assets",
    "packages",
  ]);
  requireObservation(
    value.schemaVersion === 1 &&
      value.candidateSha === manifest.candidateSha &&
      value.platform === manifest.platform,
  );
  const paths = pathsFor(value.platform),
    imageNames = imageNamesFor(value.platform, profile.sources),
    preparation = manifest.darwinPreparation ?? manifest.windowsPreparation,
    plans = preparation
      ? [
          preparation.bootstrap,
          ...preparation.cases.map((entry) => entry.custody),
          ...(value.platform === "win32"
            ? value.packages
                .filter(
                  (entry) =>
                    entry.packageId === "git-for-windows" &&
                    entry.reviewed?.extraction?.custody,
                )
                .map((entry) => entry.reviewed.extraction.custody)
            : []),
        ].map((entry) => ({
          name: "custody-plan." + entry.context.executionId,
          ...entry.plan,
        }))
      : [];
  requireObservation(imageNames);
  const sourceNames = [
      ...profile.sources.map((name) => name + ".c"),
      ...headers[value.platform],
    ],
    expected = [
      ...imageNames,
      ...sourceNames,
      ...plans.map((entry) => entry.name),
    ];
  requireObservation(
    Array.isArray(value.assets) && value.assets.length === expected.length,
  );
  const names = new Set(),
    locations = new Set(),
    members = new Set();
  let total = 0;
  const assets = value.assets.map((asset) => {
    observationObject(asset, [
      "name",
      "kind",
      "member",
      "path",
      "bytes",
      "sha256",
      "bindings",
    ]);
    requireObservation(
      expected.includes(asset.name) &&
        !names.has(asset.name) &&
        absolute(asset.path, paths) &&
        !locations.has(asset.path.toLowerCase()) &&
        !members.has(asset.member) &&
        Number.isSafeInteger(asset.bytes) &&
        asset.bytes > 0 &&
        asset.bytes <= NATIVE_PREREQUISITE_LIMITS.assetBytes &&
        hash(asset.sha256),
    );
    packageMemberPath(asset.member);
    requireObservation(
      asset.member ===
        "bootstrap/" +
          asset.name +
          (imageNames.includes(asset.name) && value.platform === "win32"
            ? ".exe"
            : ""),
    );
    observationObject(asset.bindings, [
      "source",
      "build",
      "toolchain",
      "loader",
    ]);
    requireObservation(
      Object.values(asset.bindings).every(hash) &&
        asset.bindings.toolchain === observationDigest(manifest.tools),
    );
    const helper = manifest.helpers.find(
      (entry) => entry.name === asset.name.replace(/\.c$/u, ""),
    );
    if (imageNames.includes(asset.name)) {
      requireObservation(
        asset.kind === "image" &&
          (asset.name === "package-extractor" ||
            helper?.sha256 === asset.sha256) &&
          paths.basename(asset.path) ===
            asset.name + (value.platform === "win32" ? ".exe" : ""),
      );
      if (helper)
        requireObservation(asset.bindings.source === helper.sourceSha256);
    } else if (sourceNames.includes(asset.name))
      requireObservation(
        asset.kind === "source" &&
          asset.bytes <= 1048576 &&
          paths.basename(asset.path) === asset.name &&
          asset.bindings.source === asset.sha256 &&
          (!helper || helper.sourceSha256 === asset.sha256),
      );
    else {
      const plan = plans.find((entry) => entry.name === asset.name);
      requireObservation(
        asset.kind === "plan" &&
          asset.bytes <= 262144 &&
          asset.path === plan.path &&
          asset.sha256 === plan.sha256,
      );
    }
    names.add(asset.name);
    locations.add(asset.path.toLowerCase());
    members.add(asset.member);
    total += asset.bytes;
    requireObservation(total <= NATIVE_PREREQUISITE_LIMITS.assetTotalBytes);
    return structuredClone(asset);
  });
  if (preparation) {
    // Windows build publication reads signed copies beside the sealed sources.
    if (value.platform === "win32")
      requireObservation(
        preparation.sourceDirectory ===
          paths.dirname(preparation.bootstrap.reader.path),
      );
    const selected = [
      ["custody-reader", preparation.bootstrap.reader],
      ["build-helper", preparation.command.helper],
      ...(value.platform === "win32"
        ? [["custody-bridge", preparation.bootstrap.bridge]]
        : []),
    ];
    for (const [name, image] of selected)
      requireObservation(
        assets.some(
          (asset) =>
            asset.name === name &&
            asset.path === image.path &&
            asset.sha256 === image.sha256,
        ),
      );
    for (const source of preparation.sources)
      requireObservation(
        assets.some(
          (asset) =>
            asset.name === source.name &&
            asset.path ===
              paths.join(preparation.sourceDirectory, source.name) &&
            asset.sha256 === source.sha256,
        ),
      );
    for (const asset of assets.filter((entry) => entry.kind === "image"))
      requireObservation(
        paths.dirname(asset.path) ===
          paths.dirname(preparation.bootstrap.reader.path),
      );
  }
  const packageIds = [
    "codex-" + value.platform,
    "claude-" + value.platform,
    ...(value.platform === "win32" ? ["git-for-windows"] : []),
  ];
  requireObservation(
    Array.isArray(value.packages) &&
      value.packages.length === packageIds.length,
  );
  const ids = new Set();
  const packages = value.packages.map((entry) => {
    observationObject(entry, [
      "packageId",
      "directory",
      "reviewed",
      "approvedReviewSha256",
    ]);
    requireObservation(
      packageIds.includes(entry.packageId) &&
        !ids.has(entry.packageId) &&
        absolute(entry.directory, paths),
    );
    const reviewed = normalizeNativePackageReview(
      entry.reviewed,
      value.candidateSha,
    );
    requireObservation(
      reviewed.packageId === entry.packageId &&
        nativePackageReviewDigest(reviewed) === entry.approvedReviewSha256 &&
        nativePackageReadiness(reviewed).status === "BOUND_INPUTS",
    );
    requireObservation(
      reviewed.files.every(
        (file) => file.bytes <= NATIVE_PREREQUISITE_LIMITS.inputBytes,
      ),
    );
    const provider = entry.packageId.split("-")[0];
    if (provider !== "git")
      requireObservation(
        manifest.release.providers[provider].reviewSha256 ===
          entry.approvedReviewSha256,
      );
    if (entry.packageId === "git-for-windows")
      requireObservation(
        assets.some(
          (asset) =>
            asset.name === "package-extractor" &&
            asset.path === reviewed.extraction.extractor.path &&
            asset.sha256 === reviewed.extraction.extractor.sha256 &&
            asset.bytes === reviewed.extraction.extractor.bytes &&
            observationDigest(asset.bindings) ===
              observationDigest(reviewed.extraction.extractor.bindings),
        ),
      );
    ids.add(entry.packageId);
    return { ...structuredClone(entry), reviewed };
  });
  const roots = packages.map((entry) => entry.directory.toLowerCase());
  requireObservation(
    roots.every((root, index) =>
      roots.every(
        (other, otherIndex) =>
          index === otherIndex ||
          (root !== other && !root.startsWith(other + paths.sep)),
      ),
    ),
  );
  for (const entry of packages)
    for (const asset of assets)
      requireObservation(
        !asset.path
          .toLowerCase()
          .startsWith(entry.directory.toLowerCase() + paths.sep),
      );
  // Every staged package member is an explicit input; neither the extractor nor
  // a package-generated inventory can add loader/dependency authority.
  for (const entry of packages)
    for (const member of entry.reviewed.files) {
      const target = paths.join(
        entry.directory,
        "content",
        ...member.path.split("/"),
      );
      requireObservation(
        manifest.inputs.some(
          (input) =>
            input.path === target &&
            input.sha256 === member.sha256 &&
            input.bytes === member.bytes,
        ),
      );
    }
  return {
    schemaVersion: 1,
    candidateSha: value.candidateSha,
    platform: value.platform,
    assets,
    packages,
  };
}

/** Acquire fixed immutable-revision assets as data. Native seal/read primitives
 * own birth protection, exclusive storage and held identities before execution. */
export async function materializeBootstrapAssets(
  plan,
  { env, fetchInput = fetch, effects, persist, read, signal },
) {
  requireObservation(
    typeof effects?.sealAsset === "function" &&
      typeof effects.verifyAsset === "function" &&
      typeof effects.persist === "function",
  );
  const root = `https://raw.githubusercontent.com/${env.NATIVE_SYSTEM_INPUT_REPOSITORY}/${env.NATIVE_SYSTEM_INPUT_REVISION}/ci/native/reviews/${plan.candidateSha}/${plan.platform}/`;
  for (const asset of plan.assets) {
    requireObservation(!signal?.aborted);
    const deadline = AbortSignal.timeout(30000);
    const assetSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
    const paths = pathsFor(plan.platform);
    requireObservation(
      absolute(env.RUNNER_TEMP, paths) &&
        asset.path.startsWith(env.RUNNER_TEMP + paths.sep),
    );
    const request = {
        schemaVersion: 1,
        candidateSha: plan.candidateSha,
        platform: plan.platform,
        phase: "bootstrap-assets",
        asset,
        url: root + asset.member,
        deadlineMs: 30000,
      },
      requestSha256 = observationDigest(request);
    const entry = await persist(structuredClone(request));
    await persistPrerequisiteRecord(effects, {
      request,
      requestSha256,
      status: "POSSIBLE",
    });
    requireObservation(!assetSignal.aborted);
    const response = await fetchInput(request.url, {
      redirect: "error",
      credentials: "omit",
      headers: { "accept-encoding": "identity" },
      signal: assetSignal,
    });
    const valid =
      response.ok &&
      response.url === request.url &&
      response.body &&
      [null, "identity"].includes(response.headers.get("content-encoding"));
    if (!valid) await response.body?.cancel?.();
    requireObservation(valid);
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      requireObservation(!assetSignal.aborted && chunk instanceof Uint8Array);
      size += chunk.length;
      requireObservation(size <= asset.bytes);
      chunks.push(Buffer.from(chunk));
    }
    const bytes = Buffer.concat(chunks);
    requireObservation(size === asset.bytes && digest(bytes) === asset.sha256);
    const sealed = await effects.sealAsset(structuredClone(request), bytes, {
      signal: assetSignal,
    });
    requireObservation(
      !assetSignal.aborted &&
        sealed?.requestSha256 === requestSha256 &&
        sealed.independent === true &&
        sealed.birthProtected === true &&
        sealed.protectedParents === true &&
        sealed.exclusive === true &&
        sealed.held === true &&
        sealed.unchanged === true &&
        sealed.executed === false &&
        hash(sealed.identitySha256) &&
        hash(sealed.nativeEventSha256),
    );
    const verified = await effects.verifyAsset(structuredClone(request), {
      signal: assetSignal,
    });
    requireObservation(
      !assetSignal.aborted &&
        verified?.requestSha256 === requestSha256 &&
        verified.independent === true &&
        verified.held === true &&
        verified.unchanged === true &&
        verified.readExecuteOnly === true &&
        verified.bytes === asset.bytes &&
        verified.sha256 === asset.sha256 &&
        verified.noLiveMembers === true &&
        verified.emergencyCleanup === false &&
        hash(verified.nativeEventSha256),
    );
    requireObservation(
      digest(await read(asset.path, asset.bytes)) === asset.sha256,
    );
    requireObservation(!assetSignal.aborted);
    await persistPrerequisiteRecord(effects, {
      request,
      requestSha256,
      status: "RETIRED",
      receiptSha256: observationDigest({ sealed, verified }),
    });
    await entry(observationDigest({ sealed, verified }));
  }
}

export async function materializePrerequisitePackages(
  plan,
  { effects, persist, signal, preparePackage = prepareReviewedNativePackage },
) {
  requireObservation(
    typeof effects?.packageOptions === "function" &&
      typeof effects.persist === "function",
  );
  for (const entry of plan.packages) {
    requireObservation(!signal?.aborted);
    const request = {
        schemaVersion: 1,
        candidateSha: plan.candidateSha,
        platform: plan.platform,
        phase: "packages",
        ...entry,
        deadlineMs: NATIVE_PACKAGE_LIMITS.acquisitionMs,
      },
      requestSha256 = observationDigest(request);
    const complete = await persist(structuredClone(request));
    await persistPrerequisiteRecord(effects, {
      request,
      requestSha256,
      status: "POSSIBLE",
    });
    requireObservation(!signal?.aborted);
    const options = await effects.packageOptions(structuredClone(entry), {
      signal,
    });
    requireObservation(!signal?.aborted);
    const result = await preparePackage(
      {
        candidateSha: plan.candidateSha,
        platform: plan.platform,
        ...structuredClone(entry),
      },
      {
        ...options,
        signal,
        persist: (record) => persistPrerequisiteRecord(effects, record),
      },
    );
    if (result?.status !== "BOUND_BYTES")
      throw nativePreparationError("packages");
    requireObservation(
      !signal?.aborted &&
        result.candidateSha === plan.candidateSha &&
        result.packageId === entry.packageId &&
        result.reviewSha256 === entry.approvedReviewSha256 &&
        result.integrity === nativePackageInput(entry.packageId).integrity &&
        result.members === entry.reviewed.files.length &&
        result.entrypoint ===
          pathsFor(plan.platform).join(
            entry.directory,
            "content",
            ...(
              entry.reviewed.entrypoint ??
              nativePackageInput(entry.packageId).entrypoint
            ).split("/"),
          ),
    );
    await persistPrerequisiteRecord(effects, {
      request,
      requestSha256,
      status: "RETIRED",
      receiptSha256: observationDigest(result),
    });
    await complete(observationDigest(result));
  }
}
