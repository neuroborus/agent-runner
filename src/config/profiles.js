import { ConfigurationError, CURRENT } from "./parsing.js";

export function selectedProfile(configuration, selection, path) {
  if (selection === CURRENT) {
    return null;
  }
  const profile = configuration.profiles[selection];
  if (profile === undefined) {
    throw new ConfigurationError(
      `${path} selects unknown profile: ${selection}.`,
      { code: "ERR_UNKNOWN_PROFILE" },
    );
  }
  return profile;
}

export function profileImplementation(profile) {
  return profile === null
    ? CURRENT
    : profile.backend === "codex"
      ? profile.profile
      : profile.configDirectory;
}
