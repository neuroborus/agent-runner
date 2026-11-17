export function isolateGitEnvironment(value) {
  const environment = { ...value };
  for (const name of Object.keys(environment)) {
    const normalizedName = name.toUpperCase();
    if (normalizedName === "EMAIL" || normalizedName.startsWith("GIT_")) {
      delete environment[name];
    }
  }
  environment.GIT_TERMINAL_PROMPT = "0";
  return Object.freeze(environment);
}
