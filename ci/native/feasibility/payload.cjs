const { spawnSync } = require("node:child_process");
const { readFileSync, writeFileSync } = require("node:fs");

const LITERAL_ARGUMENTS = Object.freeze([
  "space value",
  'quote"value',
  "literal$;value",
  "",
]);
const PAYLOAD_CASES = Object.freeze([
  "argv",
  "inspect",
  "edit",
  "git-status",
  "denied-writes",
]);
const PLATFORMS = Object.freeze({
  linux: "Linux",
  darwin: "macOS",
  win32: "Windows",
});

function resolvePayloadRequest(args) {
  if (
    !Array.isArray(args) ||
    !args.every((value) => typeof value === "string") ||
    args[0] !== "--platform" ||
    !Object.hasOwn(PLATFORMS, args[1]) ||
    args[2] !== "--case" ||
    !PAYLOAD_CASES.includes(args[3])
  )
    throw new Error("Invalid fixed feasibility payload request.");
  const literal = args[3] === "argv" ? ["--", ...LITERAL_ARGUMENTS] : [];
  if (
    args.length !== 4 + literal.length ||
    literal.some((value, index) => args[index + 4] !== value)
  )
    throw new Error("Invalid fixed feasibility payload arguments.");
  return Object.freeze({ platform: args[1], caseId: args[3] });
}

// A receipt is an acknowledged attempt, not independent evidence of denial.
async function main() {
  const request = resolvePayloadRequest(process.argv.slice(2));
  const nonce = process.env.FEASIBILITY_NONCE;
  if (
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    process.env.RUNNER_OS !== PLATFORMS[request.platform] ||
    process.platform !== request.platform ||
    process.arch !== "x64" ||
    !/^[a-f0-9]{32}$/u.test(nonce ?? "") ||
    readFileSync("inspection.txt", "utf8") !== nonce
  )
    throw new Error("Fixed feasibility fixture is unavailable.");
  const send = (record) =>
    process.stdout.write(JSON.stringify({ ...record, nonce }) + "\n");
  process.stdout.on("error", () => process.exit(1));
  const released = new Promise((resolve, reject) => {
    let bytes = "";
    const timer = setTimeout(
      () => finish(new Error("Fixture release deadline.")),
      30000,
    );
    const finish = (error) => {
      clearTimeout(timer);
      process.stdin.removeListener("data", receive);
      process.stdin.removeListener("end", ended);
      process.stdin.removeListener("error", finish);
      process.stdin.pause();
      if (error) reject(error);
      else resolve();
    };
    const ended = () =>
      finish(new Error("Fixture release was not acknowledged."));
    const receive = (chunk) => {
      bytes += chunk.toString("utf8");
      if (
        Buffer.byteLength(bytes) > 128 ||
        (bytes.includes("\n") && bytes !== `RELEASE ${nonce}\n`)
      )
        finish(new Error("Invalid fixture release."));
      else if (bytes === `RELEASE ${nonce}\n`) finish();
    };
    process.stdin.on("data", receive).once("end", ended).once("error", finish);
  });
  send({ event: "ready", caseId: request.caseId, pid: process.pid });
  await released;
  const attempt = (operation, effect) => {
    send({ event: "attempt", operation });
    try {
      effect();
      send({ event: "completed", operation, success: true, code: null });
    } catch (error) {
      const code = /^[A-Z0-9_]{1,32}$/u.test(error.code ?? "")
        ? error.code
        : "UNOBSERVED";
      send({ event: "completed", operation, success: false, code });
    }
  };
  if (request.caseId === "argv")
    send({ event: "argv", arguments: process.argv.slice(7) });
  else if (request.caseId === "inspect")
    attempt("inspect", () => {
      if (readFileSync("inspection.txt", "utf8") !== nonce)
        throw new Error("Changed fixture.");
    });
  else if (request.caseId === "edit")
    attempt("edit", () =>
      writeFileSync("edited.txt", nonce, { flag: "wx", mode: 0o600 }),
    );
  else if (request.caseId === "git-status")
    attempt("git-status", () => {
      const result = spawnSync(
        "git",
        ["-c", "core.fsmonitor=false", "status", "--porcelain"],
        {
          encoding: "utf8",
          timeout: 3000,
          maxBuffer: 16384,
          windowsHide: true,
        },
      );
      if (result.error) throw result.error;
      if (result.signal || result.status !== 0)
        throw Object.assign(new Error("Git observation failed."), {
          code: "GIT_FAILED",
        });
    });
  else
    for (const [operation, target] of [
      ["git-index", ".git/index.lock"],
      ["git-ref", ".git/refs/heads/fixture"],
      ["control", "../control/sentinel"],
      ["outside", "../outside/sentinel"],
    ])
      attempt(operation, () =>
        writeFileSync(target, nonce, {
          flag: operation === "git-index" ? "wx" : "r+",
        }),
      );
}

module.exports = { LITERAL_ARGUMENTS, PAYLOAD_CASES, resolvePayloadRequest };
if (require.main === module)
  main().catch(() => {
    process.stderr.write("Fixed feasibility payload failed.\n");
    process.exitCode = 1;
  });
