import { createHash } from "node:crypto";
import { win32 as path } from "node:path";
import { feasibilityFailureCause } from "../feasibility/index.js";

const MAX_RUNTIME_FILES = 64,
  MAX_RUNTIME_BYTES = 134217728;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const requireGit = (value, code) => {
  if (!value)
    throw Object.assign(new Error("Windows Git preparation rejected"), {
      code,
    });
};
const output = (value, code = "ERR_FEASIBILITY_GIT_PATH") => {
  requireGit(
    typeof value === "string" && Buffer.byteLength(value) <= 65536,
    code,
  );
  return value.trim();
};
const localPath = (value) => {
  requireGit(
    typeof value === "string" &&
      value.isWellFormed() &&
      value.length <= 4096 &&
      /^[a-z]:[\\/]/iu.test(value) &&
      !/[\p{Cc}\p{Zl}\p{Zp}<>"|?*]/u.test(value) &&
      !value.slice(2).includes(":"),
    "ERR_FEASIBILITY_GIT_PATH",
  );
  const normalized = path.normalize(value);
  requireGit(
    normalized === value.replaceAll("/", "\\") &&
      normalized
        .split("\\")
        .slice(1)
        .every((part) => part && !/[. ]$/u.test(part)),
    "ERR_FEASIBILITY_GIT_PATH",
  );
  return normalized;
};

/** The matching worker supplies bounded regular-file reads, exclusive durable writes and
 * bounded commands; portable coverage supplies no native effects.
 * Components are appended as observed, including before a later failure. */
export async function prepareWindowsFeasibilityGit(
  { root, nonce, systemRoot, components },
  { command, read, write, inspect },
) {
  let operation = "git-paths";
  try {
    root = localPath(root);
    systemRoot = localPath(systemRoot);
    requireGit(/^[a-f0-9]{32}$/u.test(nonce ?? ""), "ERR_FEASIBILITY_GIT_PATH");
    operation = "git-discovery";
    const locations = output(
      (await command("where.exe", ["git.exe"])).stdout,
    ).split(/\r?\n/u);
    requireGit(locations.length <= 16, "ERR_FEASIBILITY_GIT_PATH");
    const executable = locations.map(localPath)[0];
    requireGit(
      path.basename(executable).toLowerCase() === "git.exe",
      "ERR_FEASIBILITY_GIT_PATH",
    );
    operation = "git-executable-inspection";
    const launcher = await read(executable);
    components.push({
      role: "tool",
      name: "git-launcher",
      version: "unobserved",
      sha256: digest(launcher),
    });
    inspect(launcher);
    operation = "git-exec-path";
    const execPath = localPath(
      output((await command(executable, ["--exec-path"])).stdout),
    );
    requireGit(
      /\\libexec\\git-core$/iu.test(execPath),
      "ERR_FEASIBILITY_GIT_PATH",
    );
    const directory = path.resolve(execPath, "..", "..", "bin"),
      build = path.join(root, "build"),
      image = path.join(build, "git.exe"),
      dependencies = ["git.exe"],
      manifest = [];
    let totalBytes = 0,
      git;
    for (let i = 0; i < dependencies.length; i++) {
      const name = dependencies[i];
      operation = "git-source-inspection";
      const bytes = await read(path.join(directory, name));
      if (i === 0) {
        git = {
          role: "tool",
          name: "git-for-windows",
          version: "unobserved",
          sha256: digest(bytes),
        };
        components.push(git);
      }
      const imports = inspect(bytes);
      operation = "git-dependencies";
      totalBytes += bytes.length;
      requireGit(
        totalBytes <= MAX_RUNTIME_BYTES,
        "ERR_FEASIBILITY_GIT_DEPENDENCIES",
      );
      for (const dll of imports) {
        // Preserve the existing OS/API-set boundary; this is no release closure.
        if (/^(?:api|ext)-ms-win-/iu.test(dll)) continue;
        try {
          await read(path.join(systemRoot, "System32", dll));
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
          const folded = dll.toLowerCase();
          if (!dependencies.includes(folded)) {
            requireGit(
              dependencies.length < MAX_RUNTIME_FILES,
              "ERR_FEASIBILITY_GIT_DEPENDENCIES",
            );
            dependencies.push(folded);
          }
        }
      }
      operation = "git-owned-copy";
      await write(path.join(build, name), bytes);
      operation = "git-copy-inspection";
      const copied = await read(path.join(build, name));
      requireGit(copied.equals(bytes), "ERR_FEASIBILITY_GIT_COPY");
      manifest.push({ name, sha256: digest(copied) });
    }
    components.push({
      role: "helper",
      name: "experiment-git-runtime",
      version: "observed-imports",
      sha256: digest(Buffer.from(JSON.stringify(manifest))),
    });
    operation = "git-version";
    const version = output(
      (await command(image, ["--version"], { cwd: build })).stdout,
      "ERR_FEASIBILITY_GIT_VERSION",
    );
    requireGit(
      version.length <= 128 && /^git version [0-9.a-z-]+$/u.test(version),
      "ERR_FEASIBILITY_GIT_VERSION",
    );
    git.version = version;
    operation = "git-copy-inspection";
    for (const file of manifest)
      requireGit(
        digest(await read(path.join(build, file.name))) === file.sha256,
        "ERR_FEASIBILITY_GIT_COPY",
      );
    operation = "git-manifest";
    await write(
      path.join(root, "control", "git-runtime.json"),
      JSON.stringify({ version, files: manifest }),
    );
    const workspace = path.join(root, "workspace");
    operation = "git-fixture";
    for (const [name, content] of [
      ["inspection.txt", nonce],
      ["edited.txt", "before"],
    ])
      await write(path.join(workspace, name), content);
    for (const name of ["control", "outside"])
      await write(path.join(root, name, "sentinel"), nonce);
    for (const [stage, args] of [
      [
        "git-repository-init",
        ["init", "--initial-branch=fixture", "--template="],
      ],
      ["git-repository-add", ["add", "inspection.txt", "edited.txt"]],
      [
        "git-repository-commit",
        [
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.invalid",
          "-c",
          "commit.gpgSign=false",
          "commit",
          "-m",
          "fixture",
        ],
      ],
    ]) {
      operation = stage;
      await command(image, args, { cwd: workspace });
    }
    return { image, manifest };
  } catch (error) {
    const unavailable =
      operation === "git-discovery" &&
      (error.code === "ENOENT" ||
        (error.code === 1 &&
          error.signal === null &&
          error.timedOut === false));
    throw Object.assign(
      new Error("Windows Git preparation failed.", { cause: error }),
      {
        feasibilityCause: feasibilityFailureCause(
          "prepare",
          operation,
          error,
          unavailable ? "prerequisite-unavailable" : "setup-failed",
        ),
      },
    );
  }
}
