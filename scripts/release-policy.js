const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const REPOSITORY = /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/u;
const PACKAGE = /^@[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*$/u;

// Keep npm's trusted-publisher and provenance metadata together, without
// inheriting user configuration or a long-lived registry credential.
export function npmPublicationEnvironment(env) {
  const keys = [
    "GITHUB_ACTIONS",
    "RUNNER_ENVIRONMENT",
    "GITHUB_REPOSITORY",
    "GITHUB_REF",
    "GITHUB_SHA",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_WORKFLOW",
    "GITHUB_SERVER_URL",
    "GITHUB_API_URL",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER_ID",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  ];
  if (
    env.NODE_AUTH_TOKEN ||
    env.NPM_TOKEN ||
    env.GITHUB_ACTIONS !== "true" ||
    env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    keys.some((key) => typeof env[key] !== "string" || env[key].length === 0)
  )
    throw new Error(
      "Publishing requires complete GitHub-hosted OIDC/provenance metadata without an npm token.",
    );
  return Object.freeze(Object.fromEntries(keys.map((key) => [key, env[key]])));
}

export function assertPublicationMetadata(metadata, policy) {
  if (
    !policy ||
    Object.keys(policy).sort().join() !==
      "enabled,license,packageName,repository,schemaVersion" ||
    policy.schemaVersion !== 1 ||
    policy.enabled !== true ||
    typeof policy.repository !== "string" ||
    typeof policy.packageName !== "string" ||
    !REPOSITORY.test(policy.repository ?? "") ||
    !PACKAGE.test(policy.packageName ?? "") ||
    policy.packageName.startsWith("@your-scope/") ||
    typeof policy.license !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9.()+ -]*$/u.test(policy.license) ||
    policy.license === "UNLICENSED" ||
    metadata.name !== policy.packageName ||
    metadata.private !== false ||
    metadata.license !== policy.license ||
    metadata.repository?.type !== "git" ||
    Object.keys(metadata.repository).sort().join() !== "type,url" ||
    metadata.repository.url !== `https://github.com/${policy.repository}.git` ||
    metadata.publishConfig?.access !== "public" ||
    Object.keys(metadata.publishConfig).sort().join() !== "access,registry" ||
    metadata.publishConfig.registry !== "https://registry.npmjs.org/"
  )
    throw new Error(
      "Publication requires approved owner/scope, license, repository and publisher metadata.",
    );
}

// Environment approval protects the selected commit; Git ancestry is observed
// independently in each job, never inferred from a release's target_commitish.
export function selectRelease({
  policy,
  metadata,
  event,
  eventName,
  repository,
  ref,
  head,
  tagHead,
  inMain,
}) {
  assertPublicationMetadata(metadata, policy);
  const tag = `v${metadata.version}`;
  if (
    eventName !== "release" ||
    event?.action !== "published" ||
    event.release?.draft !== false ||
    event.release.prerelease !== false ||
    !VERSION.test(metadata.version) ||
    event.release.tag_name !== tag ||
    repository !== policy.repository ||
    event.repository?.full_name !== repository ||
    ref !== `refs/tags/${tag}` ||
    !/^[0-9a-f]{40}$/u.test(head ?? "") ||
    tagHead !== head ||
    inMain !== true
  )
    throw new Error(
      "Only a published stable release at its exact version tag in main may publish.",
    );
  return Object.freeze({
    commit: head,
    tag,
    name: metadata.name,
    version: metadata.version,
    releaseUrl: `https://github.com/${repository}/releases/tag/${tag}`,
    npmUrl: `https://www.npmjs.com/package/${metadata.name}/v/${metadata.version}`,
  });
}

export async function validateRelease(
  selection,
  { prepare, run, inspect, seal },
) {
  await run(["run", "check"]);
  const candidate = await prepare(selection);
  const env = { AGENT_RUNNER_RELEASE_CANDIDATE: candidate.receiptPath };
  await run(
    ["run", "test:slow", "--", "test/package-install.slow.test.js"],
    env,
  );
  await run(["run", "test:slow"], env);
  await inspect(candidate.receiptPath, {
    ...selection,
    integrity: candidate.integrity,
  });
  await seal(candidate);
  return candidate;
}

// An ambiguous publish is reconciled, never retried here. Existing versions
// must match the tested bytes before public installability is checked.
export async function publishRelease(
  selection,
  { inspect, readVersion, publish, verifyInstall },
) {
  const candidate = await inspect();
  let attempted = false;
  try {
    let existing = await readVersion(selection);
    if (existing === null) {
      await inspect();
      attempted = true;
      try {
        await publish(candidate);
      } catch {
        /* Reconcile a possibly completed effect below. */
      }
      existing = await readVersion(selection);
    }
    if (existing?.dist?.integrity !== candidate.integrity)
      throw new Error(
        "The public version is absent or differs from the validated archive.",
      );
    await verifyInstall(existing, candidate);
    return {
      status: attempted ? "published" : "verified_existing",
      ...selection,
      integrity: candidate.integrity,
    };
  } catch {
    return {
      status: "partial_failure",
      ...selection,
      publishAttempted: attempted,
      reason: attempted
        ? "Publication may have completed; reconcile this exact version before retrying."
        : "Existing-version integrity or public installation could not be verified; nothing was published.",
    };
  }
}
