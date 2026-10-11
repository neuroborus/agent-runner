import { createHash } from "node:crypto";
import { win32 as path } from "node:path";
import { feasibilityFailureCause } from "../feasibility/index.js";
import {
  normalizeWindowsIdentity,
  quoteWindowsArgument,
  sameWindowsIdentity,
} from "./protocol.js";

const MAX_RUNTIME_FILES = 64,
  MAX_RUNTIME_BYTES = 134217728;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const requireGit = (value, code) => {
  if (!value)
    throw Object.assign(new Error("Windows Git preparation rejected"), {
      code,
    });
};

// Closed structural facts only: never section names, import strings or paths.
const PE_RULES = Object.freeze({
  "file-type": [],
  "file-size": ["bytes"],
  "dos-signature": ["signature"],
  "pe-offset": ["offset", "bytes"],
  "pe-signature": ["signature"],
  machine: ["machine"],
  "section-count": ["count"],
  "optional-range": ["size", "bytes"],
  "optional-magic": ["magic"],
  "directory-count": ["count", "size"],
  "section-table": ["offset", "count", "bytes"],
  "section-raw-range": ["section", "offset", "size"],
  "section-rva-range": ["section", "rva", "size"],
  "raw-overlap": ["section", "other"],
  "rva-overlap": ["section", "other"],
  "rva-range": ["rva", "size"],
  "rva-unmapped": ["rva", "size"],
  "delay-imports": ["rva", "size"],
  "import-pair": ["rva", "size"],
  "import-size": ["size"],
  "import-terminator": ["size", "descriptors"],
  "name-contiguity": ["descriptor", "bytes"],
  "name-terminator": ["descriptor", "bytes"],
  "name-ascii": ["descriptor", "bytes"],
  "name-safe": ["descriptor", "bytes"],
});

export function windowsFeasibilityPeError(rule, ...values) {
  return Object.assign(new Error("Invalid Windows experiment PE"), {
    code: "ERR_FEASIBILITY_WINDOWS_PE",
    peInspection: Object.freeze({ rule, values: Object.freeze(values) }),
  });
}

/** Retain only a known rule and its exact unsigned structural fields. */
export function windowsFeasibilityPeCause(phase, operation, error, code) {
  const cause = feasibilityFailureCause(phase, operation, error, code),
    inspection = error?.peInspection;
  if (
    error?.code !== "ERR_FEASIBILITY_WINDOWS_PE" ||
    !inspection ||
    Object.getPrototypeOf(inspection) !== Object.prototype ||
    Reflect.ownKeys(inspection).length !== 2
  )
    return cause;
  const { rule, values } = inspection;
  if (
    typeof rule !== "string" ||
    !Object.hasOwn(PE_RULES, rule) ||
    !Array.isArray(values) ||
    values.length !== PE_RULES[rule].length
  )
    return cause;
  // Snapshot at most three values before formatting; sparse arrays and changing
  // accessors cannot supply unvalidated strings on a second read.
  const numbers = PE_RULES[rule].map((_, index) => values[index]),
    maximum = rule === "file-size" ? Number.MAX_SAFE_INTEGER : 0x100000000;
  if (
    !numbers.every(
      (value) => Number.isSafeInteger(value) && value >= 0 && value <= maximum,
    )
  )
    return cause;
  const facts = PE_RULES[rule].map(
    (name, index) => `${name}=${numbers[index]}`,
  );
  return {
    ...cause,
    detail:
      `${cause.detail.replace(/; [^;]*$/u, "")}; PE rule=${rule}${facts.length ? `, ${facts.join(", ")}` : ""}.`.slice(
        0,
        256,
      ),
  };
}
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

/** Join the suspended fixed command to fresh native reads and a distinct
 * verifier; payload claims alone never release Git. */
export function validateWindowsFeasibilityGitStart({
  prepared,
  receipt,
  started,
  files,
  admission,
}) {
  for (const identity of [
    receipt.owner,
    receipt.child,
    started.owner,
    started.child,
    admission.child,
    admission.verifier,
  ])
    normalizeWindowsIdentity(identity);
  const { env, args } = prepared.invocation;
  const [cwd, metadata, config, repositoryConfig] = files.slice(
    prepared.manifest.length,
  );
  const environment =
    Object.entries(env)
      .map(([key, value]) => `${key}=${value}`)
      .join("\0") + "\0\0";
  const command = [prepared.image, ...args].map(quoteWindowsArgument).join(" ");
  requireGit(
    started.event === "git-started" &&
      started.suspended === true &&
      started.capabilities === 0 &&
      started.sid === receipt.sid &&
      sameWindowsIdentity(started.owner, receipt.child) &&
      !sameWindowsIdentity(started.child, started.owner) &&
      started.environmentSha256 ===
        digest(Buffer.from(environment, "utf16le")) &&
      started.commandSha256 === digest(Buffer.from(command, "utf16le")) &&
      files.length === prepared.manifest.length + 4 &&
      new Set(files.map(({ identity }) => identity)).size === files.length &&
      files.every(
        ({ identity, private: privateFile }) =>
          privateFile === false &&
          typeof identity === "string" &&
          /^[a-f0-9]{16}:[a-f0-9]{32}$/u.test(identity),
      ) &&
      prepared.manifest.every(
        ({ sha256 }, index) => files[index].sha256 === sha256,
      ) &&
      cwd.sha256 === null &&
      metadata.sha256 === null &&
      config.sha256 === digest(Buffer.alloc(0)) &&
      repositoryConfig.sha256 === prepared.repositorySha256,
    "ERR_FEASIBILITY_GIT_BINDING",
  );
  for (const [actual, expected] of [
    [started.image, files[0]],
    [started.cwd, cwd],
    [started.metadata, metadata],
    [started.config, config],
    [started.repositoryConfig, repositoryConfig],
  ])
    requireGit(
      JSON.stringify(actual) === JSON.stringify(expected),
      "ERR_FEASIBILITY_GIT_BINDING",
    );
  requireGit(
    admission.admitted === true &&
      admission.suspended === true &&
      admission.capabilities === 0 &&
      admission.sid === receipt.sid &&
      sameWindowsIdentity(admission.child, started.child) &&
      ![receipt.owner, started.owner, started.child].some((identity) =>
        sameWindowsIdentity(admission.verifier, identity),
      ) &&
      JSON.stringify(admission.image) === JSON.stringify(started.image),
    "ERR_FEASIBILITY_GIT_BINDING",
  );
}

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
      workspace = path.join(root, "workspace"),
      config = path.join(workspace, ".git", "runner-global.conf"),
      image = path.join(build, "git.exe"),
      dependencies = ["git.exe"],
      manifest = [];
    // Match the confined command: HOME/config discovery must not depend on
    // the outside caller's profile or SDK PATH. No additional ACL is needed.
    const env = {
      GIT_ATTR_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: config,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0",
      HOME: workspace,
      LANG: "C",
      LC_ALL: "C",
      LOCALAPPDATA: workspace,
      PATH: `${build};${path.join(systemRoot, "System32")}`,
      SystemRoot: systemRoot,
      TEMP: workspace,
      TMP: workspace,
      USERPROFILE: workspace,
      XDG_CONFIG_HOME: workspace,
    };
    const statusArgs = [
      "-c",
      "core.fsmonitor=false",
      "-c",
      `safe.directory=${workspace}`,
      "--git-dir",
      path.join(workspace, ".git"),
      "--work-tree",
      workspace,
      "status",
      "--porcelain",
    ];
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
      (await command(image, ["--version"], { cwd: build, env })).stdout,
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
      await command(image, args, { cwd: workspace, env });
      if (stage === "git-repository-init") {
        operation = "git-fixture-config";
        await write(config, "");
      }
    }
    operation = "git-fixture-config";
    const repositoryConfig = path.join(workspace, ".git", "config");
    const repositorySha256 = digest(await read(repositoryConfig));
    operation = "git-outside-status";
    requireGit(
      (await command(image, statusArgs, { cwd: workspace, env })).stdout === "",
      "ERR_FEASIBILITY_GIT_STATUS",
    );
    operation = "git-copy-inspection";
    for (const { name, sha256 } of manifest)
      requireGit(
        digest(await read(path.join(build, name))) === sha256,
        "ERR_FEASIBILITY_GIT_COPY",
      );
    operation = "git-fixture-config";
    requireGit(
      (await read(config)).length === 0 &&
        digest(await read(repositoryConfig)) === repositorySha256,
      "ERR_FEASIBILITY_GIT_CONFIG",
    );
    const invocation = { cwd: workspace, env, args: statusArgs };
    operation = "git-manifest";
    await write(
      path.join(root, "control", "git-runtime.json"),
      JSON.stringify({
        version,
        files: manifest,
        invocation,
        repositorySha256,
      }),
    );
    return { image, manifest, invocation, repositorySha256 };
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
        feasibilityCause: windowsFeasibilityPeCause(
          "prepare",
          operation,
          error,
          unavailable ? "prerequisite-unavailable" : "setup-failed",
        ),
      },
    );
  }
}
