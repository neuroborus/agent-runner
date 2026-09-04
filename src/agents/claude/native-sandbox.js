const APPLY_SECCOMP_ARGV0 = "apply-seccomp";
const INERT_BINARY = "/usr/bin/true";

function nativeSandboxArguments(claudeBinary) {
  return [
    "--new-session",
    "--die-with-parent",
    "--unshare-net",
    "--ro-bind",
    "/",
    "/",
    "--dev",
    "/dev",
    "--unshare-pid",
    "--unshare-user",
    "--cap-drop",
    "ALL",
    "--proc",
    "/proc",
    "--setenv",
    "ARGV0",
    APPLY_SECCOMP_ARGV0,
    "--",
    claudeBinary,
    INERT_BINARY,
  ];
}

export async function probeClaudeNativeSandbox({
  bubblewrapBinary,
  claudeBinary,
  env,
  execute,
}) {
  try {
    await execute(bubblewrapBinary, nativeSandboxArguments(claudeBinary), {
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
