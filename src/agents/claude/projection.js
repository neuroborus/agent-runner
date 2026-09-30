import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

// Tool defaults have real mount targets only in adapter-owned storage.
// Provider authentication and session storage do not use this projection.
const FILES = [
  ".gitconfig",
  ".gitmodules",
  ".bashrc",
  ".bash_profile",
  ".zshrc",
  ".zprofile",
  ".profile",
  ".ripgreprc",
  ".mcp.json",
  ".claude.json",
  ".claude/settings.json",
  ".claude/settings.local.json",
  ".claude/CLAUDE.md",
];
const DIRECTORIES = [
  ".vscode",
  ".idea",
  ".claude",
  ".claude/commands",
  ".claude/agents",
  ".claude/skills",
  ".claude/plugins",
];

export async function createToolHome(directory) {
  const home = join(directory, "home");
  await mkdir(home, { mode: 0o700 });
  for (const name of [...DIRECTORIES, "tmp", ".config", ".cache", ".runtime"])
    await mkdir(join(home, name), { mode: 0o700 });
  for (const name of FILES)
    await writeFile(join(home, name), "", { mode: 0o600, flag: "wx" });
  return home;
}

export function toolHomeArguments(home) {
  return [
    "--ro-bind",
    home,
    home,
    ...["tmp", ".cache", ".runtime"].flatMap((name) => [
      "--perms",
      "0700",
      "--tmpfs",
      join(home, name),
    ]),
    ...Object.entries({
      HOME: home,
      CLAUDE_CONFIG_DIR: join(home, ".claude"),
      XDG_CONFIG_HOME: join(home, ".config"),
      XDG_CACHE_HOME: join(home, ".cache"),
      XDG_RUNTIME_DIR: join(home, ".runtime"),
      TMPDIR: join(home, "tmp"),
    }).flatMap(([name, value]) => ["--setenv", name, value]),
  ];
}

// Claude prepares mounts against a read-only project. Replace only that exact
// preparation reservation with the runner's requested access; preserve all
// existing descendant masks and reject any absent project mount target.
export function projectionSource({ access, cwd, home, injectHome = true }) {
  return `
function projectArguments(args) {
  const fs = require("node:fs");
  const path = require("node:path");
  const cwd = ${JSON.stringify(cwd)};
  const writable = ${JSON.stringify(access === "workspace-write")};
  let workspaceGranted = false;
  let preparationReserved = false;
  const projected = [];
  const arity = {
    "--new-session": 0, "--die-with-parent": 0, "--unshare-net": 0,
    "--unshare-pid": 0, "--unshare-user": 0, "--as-pid-1": 0,
    "--ro-bind": 2, "--bind": 2, "--setenv": 2, "--unsetenv": 1,
    "--tmpfs": 1, "--dev": 1, "--proc": 1, "--dir": 1,
    "--chdir": 1, "--cap-drop": 1, "--remount-ro": 1,
  };
  for (let i = 0; i < args.length;) {
    const operation = args[i++];
    if (operation === "--") {
      if (writable && (!workspaceGranted || !preparationReserved)) throw new Error("missing workspace preparation proof");
      if (${JSON.stringify(injectHome)}) projected.push(...${JSON.stringify(toolHomeArguments(home))});
      projected.push("--", ...args.slice(i));
      return projected;
    }
    const size = arity[operation];
    if (size === undefined || i + size > args.length) throw new Error("unsupported sandbox arguments");
    const values = args.slice(i, i + size);
    i += size;
    let destination;
    if (["--bind", "--ro-bind"].includes(operation)) {
      if (values.some((value) => !path.isAbsolute(value) || path.resolve(value) !== value)) throw new Error("invalid mount path");
      if (values[0] === cwd && values[1] === cwd) {
        if (operation === "--bind") workspaceGranted = true;
        if (operation === "--ro-bind" && writable) {
          preparationReserved = true;
          continue;
        }
      }
      destination = values[1];
    } else if (["--dir", "--tmpfs", "--dev", "--proc"].includes(operation)) {
      destination = values[0];
      if (!path.isAbsolute(destination) || path.resolve(destination) !== destination) throw new Error("invalid mount path");
    }
    if (destination !== undefined) {
      const name = path.relative(cwd, destination);
      if (name === "" || (!path.isAbsolute(name) && name !== ".." && !name.startsWith("../"))) {
        // Even a known default is rejected if the provider tries to materialize
        // it. Preparation must not register project placeholders for cleanup.
        fs.realpathSync(destination);
      }
    }
    projected.push(operation, ...values);
  }
  throw new Error("missing sandbox command");
}
`;
}

export function nativeLauncherSource({
  bubblewrapBinary,
  cwd,
  home,
  tokenName,
  token,
  unsetEnvironmentNames,
  access,
}) {
  return `#!${process.execPath}
const { spawnSync } = require("node:child_process");
if (process.env[${JSON.stringify(tokenName)}] !== ${JSON.stringify(token)}) process.exit(125);
${projectionSource({ access, cwd, home })}
try {
  const args = projectArguments(process.argv.slice(2));
  const env = { ...process.env };
  for (const name of ${JSON.stringify([tokenName, ...unsetEnvironmentNames])}) delete env[name];
  const result = spawnSync(${JSON.stringify(bubblewrapBinary)}, args, { env, stdio: "inherit" });
  process.exit(result.error || result.signal ? 125 : result.status ?? 125);
} catch { process.exit(125); }
`;
}
