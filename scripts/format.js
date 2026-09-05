import { lstatSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MODES = new Set(["--check", "--write"]);

function run() {
  const [mode, ...extraArguments] = process.argv.slice(2);
  if (!MODES.has(mode) || extraArguments.length !== 0) {
    throw new Error("Usage: node scripts/format.js --check|--write");
  }

  const repositoryPath = process.cwd();
  const listed = spawnSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    {
      cwd: repositoryPath,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  if (listed.status === null) {
    throw listed.error ?? new Error("Git file discovery did not complete.");
  }
  if (listed.status !== 0) {
    process.stderr.write(listed.stderr);
    return listed.status ?? 1;
  }

  const paths = listed.stdout.split("\0").filter((path) => {
    if (path.length === 0) {
      return false;
    }
    try {
      return lstatSync(resolve(repositoryPath, path)).isFile();
    } catch (error) {
      if (error?.code === "ENOENT") {
        return false;
      }
      throw error;
    }
  });
  if (paths.length === 0) {
    return 0;
  }

  const prettierPath = fileURLToPath(
    import.meta.resolve("prettier/bin/prettier.cjs"),
  );
  const formatted = spawnSync(
    process.execPath,
    [prettierPath, mode, "--ignore-unknown", "--", ...paths],
    { cwd: repositoryPath, stdio: "inherit" },
  );
  if (formatted.status === null) {
    throw formatted.error ?? new Error("Prettier did not complete.");
  }
  return formatted.status;
}

process.exitCode = run();
