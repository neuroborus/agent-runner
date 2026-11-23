// Operator-owned, model-free acceptance. Never selected by the test launcher.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const args = process.argv.slice(2);
if (
  args.length !== 3 ||
  args[0] !== "--enable" ||
  !args[1].startsWith("--candidate=") ||
  !args[2].startsWith("--codex=")
) {
  throw new Error(
    "Explicit opt-in required: --enable --candidate=/absolute/package --codex=/absolute/cli",
  );
}
const candidate = args[1].slice("--candidate=".length);
const binary = args[2].slice("--codex=".length);
assert.ok(
  isAbsolute(candidate) && isAbsolute(binary),
  "Supply exact absolute selections.",
);
const source = await realpath(fileURLToPath(new URL("../", import.meta.url)));
assert.notEqual(
  await realpath(candidate),
  source,
  "Use a separately installed candidate.",
);
const execute = promisify(execFile);
const root = await mkdtemp(join(tmpdir(), "codex-file-output-acceptance-"));
const marker = "NATIVE_COMMAND_STARTED";
const profileName = "agent_runner_directory";
const reports = [];
let failed = false;
try {
  const home = join(root, "home");
  await mkdir(join(home, ".codex"), { recursive: true, mode: 0o700 });
  // No credentials, user settings, network or model request is needed.
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    CODEX_HOME: join(home, ".codex"),
    TMPDIR: root,
  };
  for (const scenario of ["file", "directory", "read-only"]) {
    const cwd = join(root, scenario);
    await mkdir(join(cwd, ".codex"), { recursive: true });
    const control = join(cwd, ".codex", "control.txt");
    const input = join(cwd, "input.txt");
    const output = join(cwd, "output");
    await writeFile(control, "Protected metadata\n");
    await writeFile(input, "Read-only input\n");
    const metadata = await lstat(join(cwd, ".codex"), { bigint: true });
    if (scenario === "directory") await mkdir(output);
    else await writeFile(output, "Existing output\n");
    const access = scenario === "read-only" ? "read-only" : "workspace-write";
    const filesystem = {
      ":root": "read",
      ":workspace_roots": { ".": "read" },
      ...(access === "workspace-write" ? { [output]: "write" } : {}),
      [join(cwd, ".codex")]: "read",
      [input]: "read",
    };
    const entries = Object.entries(filesystem)
      .map(
        ([path, grant]) =>
          `${JSON.stringify(path)}=${typeof grant === "string" ? JSON.stringify(grant) : '{"."="read"}'}`,
      )
      .join(",");
    const profile = [
      "-c",
      `default_permissions=${JSON.stringify(profileName)}`,
      "-c",
      `permissions.${profileName}={filesystem={${entries}},network={enabled=false}}`,
    ];
    const invoke = (command) =>
      execute(binary, command, {
        cwd,
        env,
        timeout: 15_000,
        maxBuffer: 1024 * 1024,
      });
    let stage = "configuration";
    const refused = new Set();
    try {
      // Parsing a named profile is recorded separately from enforcing it.
      await invoke([
        ...profile,
        "app-server",
        "--strict-config",
        "--print-startup-config",
      ]);
      reports.push({ scenario, configuration: "ACCEPTED" });
      stage = "enforcement";
      const script = `
        const fs = require("node:fs");
        fs.writeSync(1, ${JSON.stringify(marker)});
        const denied = path => {
          try { fs.writeFileSync(path, "Unexpected write"); }
          catch { return; }
          throw new Error("Write protection failed");
        };
        if (${JSON.stringify(scenario)} === "directory")
          fs.writeFileSync(${JSON.stringify(join(output, "result.txt"))}, "Allowed output");
        else if (${JSON.stringify(scenario)} === "file")
          fs.writeFileSync(${JSON.stringify(output)}, "File grant unexpectedly succeeded");
        else {
          if (fs.readFileSync(${JSON.stringify(output)}, "utf8") !== "Existing output\\n")
            throw new Error("Read control failed");
          denied(${JSON.stringify(output)});
        }
        denied(${JSON.stringify(control)});
        denied(${JSON.stringify(input)});
        denied(${JSON.stringify(join(cwd, "sibling.txt"))});
        denied(${JSON.stringify(join(root, "parent-denied.txt"))});
      `;
      let result;
      try {
        result = {
          ...(await invoke([
            "sandbox",
            "-C",
            cwd,
            "-P",
            profileName,
            ...profile,
            "--",
            process.execPath,
            "-e",
            script,
          ])),
          code: 0,
        };
      } catch (cause) {
        if (!Number.isInteger(cause.code) || cause.killed) throw cause;
        result = cause;
      }
      if (scenario === "file") {
        assert.notEqual(
          result.code,
          0,
          "Expected file-grant setup failure was not reproduced.",
        );
        assert.ok(
          !result.stdout.includes(marker),
          "Failure occurred after native command startup.",
        );
        assert.match(
          result.stderr,
          /sandbox|bwrap|bubblewrap|mount|permission/iu,
        );
        assert.equal(await readFile(output, "utf8"), "Existing output\n");
        reports.push({
          scenario,
          enforcement: "EXPECTED_SETUP_FAILURE",
          exitCode: result.code,
        });
      } else {
        assert.equal(
          result.code,
          0,
          "Native directory/read-only control failed.",
        );
        assert.ok(result.stdout.includes(marker));
        if (scenario === "directory")
          assert.equal(
            await readFile(join(output, "result.txt"), "utf8"),
            "Allowed output",
          );
        reports.push({ scenario, enforcement: "PASS" });
      }
      // Exercise both public adapter boundaries with actual file roots. Any
      // native inspection, storage allocation or launch is a refusal failure.
      if (scenario === "file") {
        for (const [label, packageRoot] of [
          ["source", source],
          ["candidate", candidate],
        ]) {
          stage = `${label}_refusal`;
          const { createCodexAdapter } = await import(
            pathToFileURL(join(packageRoot, "src/agents/codex/index.js"))
          );
          let calls = 0;
          const forbidden = () => {
            calls += 1;
            throw new Error("Premature native work");
          };
          const adapter = createCodexAdapter({
            codexBinary: binary,
            env,
            execute: forbidden,
            spawnProcess: forbidden,
            workspaceStorageFactory: forbidden,
          });
          const workspacePolicy = {
            kind: "directory",
            workspacePath: cwd,
            stateRoot: join(root, "state"),
            inputPaths: [input],
            outputPaths: [output],
          };
          const diagnostic = {
            code: "ERR_UNSUPPORTED_CODEX_CAPABILITY",
            diagnosticClass: "capability_existing_file_output",
          };
          await assert.rejects(
            adapter.probe({ access, workspacePolicy }),
            diagnostic,
          );
          await assert.rejects(
            adapter.run({
              access,
              workspacePolicy,
              cwd,
              prompt: "No native work is authorized.",
            }),
            diagnostic,
          );
          assert.equal(calls, 0);
          reports.push({ label, refusal: "BEFORE_NATIVE_WORK" });
          refused.add(label);
        }
      }
    } catch (cause) {
      failed = true;
      // Do not publish native output or exception text.
      reports.push({
        scenario,
        stage,
        outcome: "FAIL",
        code:
          Number.isInteger(cause.code) ||
          ["ENOENT", "EACCES", "ETIMEDOUT", "ERR_ASSERTION"].includes(
            cause.code,
          )
            ? cause.code
            : null,
        timedOut: cause.killed === true,
      });
    } finally {
      if (scenario === "file") {
        for (const label of ["source", "candidate"]) {
          if (!refused.has(label))
            reports.push({
              label,
              refusal: stage === `${label}_refusal` ? "FAIL" : "NOT_RUN",
              reason: "prior_stage_failed",
            });
        }
      }
      try {
        assert.equal(await readFile(control, "utf8"), "Protected metadata\n");
        assert.equal(await readFile(input, "utf8"), "Read-only input\n");
        assert.deepEqual(await readdir(join(cwd, ".codex")), ["control.txt"]);
        const current = await lstat(join(cwd, ".codex"), { bigint: true });
        for (const field of ["dev", "ino", "mode", "mtimeNs"])
          assert.equal(current[field], metadata[field]);
      } catch {
        failed = true;
        reports.push({
          scenario,
          stage: "protected_metadata",
          outcome: "FAIL",
        });
      }
    }
  }
} finally {
  await rm(root, { recursive: true, force: true });
}
process.stdout.write(
  `${JSON.stringify({ outcome: failed ? "FAIL" : "PASS", reports }, null, 2)}\n`,
);
process.exitCode = failed ? 1 : 0;
