const UNSHARE_BINARY = "/usr/bin/unshare";
const INERT_BINARY = "/usr/bin/true";
const NATIVE_SANDBOX_ARGUMENTS = Object.freeze([
  "--user",
  "--map-root-user",
  "--",
  INERT_BINARY,
]);

export async function probeClaudeNativeSandbox({ env, execute }) {
  try {
    await execute(UNSHARE_BINARY, NATIVE_SANDBOX_ARGUMENTS, {
      encoding: "utf8",
      env,
      maxBuffer: 64 * 1024,
      timeout: 10_000,
    });
    return true;
  } catch {
    return false;
  }
}
