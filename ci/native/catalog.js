export const PLATFORMS = Object.freeze([
  Object.freeze({ os: "linux", image: "ubuntu-24.04", architecture: "x64" }),
  Object.freeze({ os: "darwin", image: "macos-15-intel", architecture: "x64" }),
  Object.freeze({ os: "win32", image: "windows-2025", architecture: "x64" }),
]);

// One record may contain several native cases; profiles are not capability skips.
export const CHECK_IDS = Object.freeze([
  "audit.release",
  "launch.argv",
  "launch.storage",
  "profile.read-only",
  "profile.workspace-write",
  "profile.trusted-command",
  "files.private",
  "files.publish",
  "files.replace",
  "files.substitution",
  "files.aliases",
  "files.cleanup",
  "network.deny",
  "network.loopback",
  "ipc.deny",
  "ownership.admission",
  "ownership.descendants",
  "ownership.cancel",
  "ownership.owner-loss",
  "ownership.helper-loss",
  "ownership.receipts",
  "git.ordinary-denial",
  "git.fixed-commit",
  "provider.transport",
  "codex.command-tools",
  "codex.file-tools",
  "claude.command-tools",
  "claude.file-tools",
  "provider.no-fallback",
]);

export const PROVIDER_CHECK_IDS = Object.freeze(CHECK_IDS.slice(23));
export const LINUX_OWNERSHIP_CHECK_IDS = Object.freeze([
  "launch.argv",
  "launch.storage",
  "ownership.admission",
  "ownership.descendants",
  "ownership.cancel",
  "ownership.owner-loss",
  "ownership.helper-loss",
  "ownership.receipts",
]);
export const LINUX_POLICY_ID = "linux-ownership-fixture-v1";
export const LINUX_ACCESS_CHECK_IDS = Object.freeze([
  "profile.read-only",
  "profile.workspace-write",
  "profile.trusted-command",
  "network.deny",
  "network.loopback",
  "ipc.deny",
  "git.ordinary-denial",
  "git.fixed-commit",
]);
export const LINUX_ACCESS_POLICY_ID = "linux-access-fixture-v1";
export const LINUX_FILE_CHECK_IDS = Object.freeze(CHECK_IDS.slice(6, 12));
export const LINUX_FILE_POLICY_ID = "linux-file-authority-v1";
export const LINUX_RELEASE_POLICY_ID = "linux-release-audit-v1";

// Version-5 envelopes distinguish build effects from admitted file operations.
export const LINUX_NATIVE_GROUPS = Object.freeze(
  Object.fromEntries(
    [
      ["ownership", LINUX_OWNERSHIP_CHECK_IDS, LINUX_POLICY_ID, ["ownership"]],
      ["access", LINUX_ACCESS_CHECK_IDS, LINUX_ACCESS_POLICY_ID, ["access"]],
      [
        "files",
        LINUX_FILE_CHECK_IDS,
        LINUX_FILE_POLICY_ID,
        ["file-build", "file-helper"],
      ],
      [
        "release",
        Object.freeze(["audit.release"]),
        LINUX_RELEASE_POLICY_ID,
        ["release-probe"],
      ],
    ].map(([id, checkIds, policyId, effects]) => [
      id,
      Object.freeze({
        checkIds,
        policyId,
        effects: Object.freeze(effects),
        admission: effects.at(-1),
      }),
    ]),
  ),
);

export function linuxNativeGroup(checkId) {
  return (
    Object.keys(LINUX_NATIVE_GROUPS).find((id) =>
      LINUX_NATIVE_GROUPS[id].checkIds.includes(checkId),
    ) ?? null
  );
}

export const SOURCE_FINDING_IDS = Object.freeze([
  "A-MAC-OWNERSHIP",
  "A-WIN-ADMISSION",
  "A-PROVIDER-MEDIATION",
  "A-RELEASE-CLOSURE",
]);
