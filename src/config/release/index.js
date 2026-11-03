// Immutable distribution identity. User/project configuration cannot approve
// another source; enabling this policy requires separate owner approval.
export const OFFICIAL_RELEASE_POLICY = Object.freeze({
  schemaVersion: 1,
  enabled: false,
  repository: null,
  packageName: null,
  license: null,
});

export function resolveOfficialReleaseIdentity(
  policy = OFFICIAL_RELEASE_POLICY,
) {
  const approved = Boolean(
    policy &&
    Object.keys(policy).sort().join() ===
      "enabled,license,packageName,repository,schemaVersion" &&
    policy.schemaVersion === 1 &&
    policy.enabled === true &&
    typeof policy.repository === "string" &&
    policy.repository.length <= 200 &&
    /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/u.test(policy.repository) &&
    typeof policy.packageName === "string" &&
    policy.packageName.length <= 214 &&
    /^@[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*$/u.test(policy.packageName) &&
    !policy.packageName.startsWith("@your-scope/") &&
    typeof policy.license === "string" &&
    policy.license.length <= 128 &&
    /^[A-Za-z0-9][A-Za-z0-9.()+ -]*$/u.test(policy.license) &&
    policy.license !== "UNLICENSED",
  );
  return Object.freeze({
    approved,
    packageName: approved ? policy.packageName : null,
    repository: approved ? policy.repository : null,
    license: approved ? policy.license : null,
    registry: "https://registry.npmjs.org/",
  });
}

export function assertPublicationMetadata(
  metadata,
  policy = OFFICIAL_RELEASE_POLICY,
) {
  const identity = resolveOfficialReleaseIdentity(policy);
  if (
    !identity.approved ||
    !metadata ||
    metadata.name !== identity.packageName ||
    metadata.private !== false ||
    metadata.license !== identity.license ||
    metadata.repository?.type !== "git" ||
    Object.keys(metadata.repository).sort().join() !== "type,url" ||
    metadata.repository.url !==
      `https://github.com/${identity.repository}.git` ||
    metadata.publishConfig?.access !== "public" ||
    Object.keys(metadata.publishConfig).sort().join() !== "access,registry" ||
    metadata.publishConfig.registry !== identity.registry
  )
    throw new Error(
      "Publication requires approved owner/scope, license, repository and publisher metadata.",
    );
}
