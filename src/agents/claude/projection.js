import { mkdir, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";

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

// Claude runs every sandboxed command through its selected shell, and its
// credential denial removes this proof inside any sandbox it starts. Only the
// authenticated launcher sets the proof again, so a command reaching the shell
// through another bubblewrap is refused. Unsandboxed shells keep the proof.
export const CLAUDE_COMMAND_SHELL_PROOF =
  "AGENT_RUNNER_CLAUDE_COMMAND_SHELL_PROOF";

function shellWord(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

export async function createCommandShell(home, shell, proof) {
  const directory = join(home, ".agent-runner-shell");
  await mkdir(directory, { mode: 0o700 });
  // Claude derives the shell kind from the selected path.
  const path = join(directory, basename(shell));
  await writeFile(
    path,
    "#!/bin/sh\n" +
      `[ "\${${CLAUDE_COMMAND_SHELL_PROOF}-}" = ${shellWord(proof)} ] || exit 125\n` +
      `exec ${shellWord(shell)} "$@"\n`,
    { mode: 0o500, flag: "wx" },
  );
  return path;
}

export function toolHomeArguments(home, proof) {
  return [
    "--setenv",
    CLAUDE_COMMAND_SHELL_PROOF,
    proof,
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

// Claude's producer finds its built-in controls by name this many directory
// levels below the workspace, outside node_modules.
const CONTROL_SEARCH_DEPTH = 3;
const CONTROL_NAMES = [
  ".git",
  ...new Set([...FILES, ...DIRECTORIES].map((name) => name.split("/")[0])),
];
const CLAUDE_CONTROL_ENTRIES = [...FILES, ...DIRECTORIES]
  .filter((name) => name.startsWith(".claude/"))
  .map((name) => name.slice(".claude/".length));

// Claude prepares mounts against a read-only project. Replace only that exact
// preparation reservation with the runner's requested access; preserve all
// existing descendant masks and reject any absent project mount target.
// The reservation also makes Claude omit workspace Git, selected-input and
// built-in control protections, so a Git workspace-write program needs both
// the workspace grant and the reservation and is normalized as a whole before
// it reaches bubblewrap. A writable or native declared-directory program needs
// only the reservation: a whole-workspace grant stays read-only, and writes
// come solely from the validated declared outputs.
export function projectionSource({
  access,
  cwd,
  providerCwd,
  home,
  proof,
  injectHome = true,
  directoryPolicy,
  claudeWritablePaths = [],
  gitDirectories = [],
  privateDirectory,
  socketStatisticsBinary = null,
  producerIdentity = null,
}) {
  return `
function projectArguments(args, descriptors) {
  const fs = require("node:fs");
  const path = require("node:path");
  const cwd = ${JSON.stringify(cwd)};
  const providerCwd = ${JSON.stringify(providerCwd ?? cwd)};
  const writable = ${JSON.stringify(access === "workspace-write")};
  const directory = ${JSON.stringify(directoryPolicy ?? null)};
  const incidentalWrites = ${JSON.stringify(claudeWritablePaths)};
  const gitDirectories = ${JSON.stringify([...new Set(gitDirectories)])};
  const privateDirectory = ${JSON.stringify(privateDirectory ?? null)};
  const controls = ${JSON.stringify(CONTROL_NAMES)};
  const claudeControls = ${JSON.stringify(CLAUDE_CONTROL_ENTRIES)};
  const contains = (parent, child) => {
    const name = path.relative(parent, child);
    return name === "" || (!path.isAbsolute(name) && name !== ".." && !name.startsWith(".." + path.sep));
  };
  // Resolve the existing prefix and keep a missing suffix literally.
  const canonical = (name) => {
    const missing = [];
    for (let current = name; ;) {
      try {
        return path.join(fs.realpathSync(current), ...missing);
      } catch (cause) {
        const parent = path.dirname(current);
        if (!["ENOENT", "ENOTDIR"].includes(cause?.code) || parent === current) throw cause;
        missing.unshift(path.basename(current));
        current = parent;
      }
    }
  };
  const present = (name) => {
    try {
      return fs.lstatSync(name);
    } catch (cause) {
      if (cause?.code === "ENOENT") return undefined;
      throw cause;
    }
  };
  // Existing workspace Git metadata and selected inputs, then the built-in
  // controls found like Claude's bounded discovery. Absent paths are never
  // mounted. A control link that its writable parent could replace, or a
  // protected path reached through an inner link, fails closed.
  const protections = (root) => {
    const found = [];
    const add = (name) => {
      if (!found.includes(name)) found.push(name);
    };
    for (const name of gitDirectories) {
      const base = contains(cwd, name) ? cwd : contains(root, name) ? root : undefined;
      if (base === undefined || present(name) === undefined) continue;
      const expected = path.join(root, path.relative(base, name));
      if (expected === root || fs.realpathSync(name) !== expected) throw new Error("replaceable protected path");
      add(expected);
    }
    const visit = (parent, depth) => {
      const entries = fs.readdirSync(parent, { withFileTypes: true })
        .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
      for (const entry of entries) {
        const name = path.join(parent, entry.name);
        const control = entry.name.toLowerCase();
        if (controls.includes(control)) {
          if (entry.isSymbolicLink()) throw new Error("replaceable protected link");
          add(name);
          if (control !== ".claude" || !entry.isDirectory()) continue;
          // The read-only directory fixes these entries; a linked one also
          // protects its in-workspace target.
          for (const child of claudeControls) {
            const link = path.join(name, child);
            if (!present(link)?.isSymbolicLink()) continue;
            const target = fs.realpathSync(link);
            if (contains(target, root)) throw new Error("replaceable protected link");
            if (contains(root, target)) add(target);
          }
        } else if (entry.isDirectory() && entry.name !== "node_modules" && depth < ${CONTROL_SEARCH_DEPTH}) {
          visit(name, depth + 1);
        }
      }
    };
    visit(root, 0);
    return found;
  };
  // Normalize the complete validated program into its effective workspace
  // tree. Mounts away from the workspace keep their order. The grant hides
  // earlier descendant mounts, so earlier restrictions are reapplied after it
  // and earlier writable descendants are subsumed by it. Emit the grant,
  // ancestor pins, then protections and restrictions, each shallowest first,
  // so no later mount can hide a protection. Immutability comes only from
  // read-only mounts in that final tree; every other ancestor of a protected
  // path becomes a writable mount point that cannot be renamed or removed.
  const normalizeWorkspace = (args) => {
    const root = fs.realpathSync(cwd);
    const inside = (name) => name !== root && contains(root, name);
    const overlaps = (name) => contains(name, root) || contains(root, name);
    const program = [];
    for (let i = 0; i < args.length;) {
      const operation = args[i];
      const values = args.slice(i + 1, i + 1 + arity[operation]);
      i += 1 + values.length;
      const target = ["--bind", "--ro-bind"].includes(operation)
        ? values[1]
        : ["--tmpfs", "--dir", "--dev", "--proc", "--remount-ro"].includes(operation)
          ? values[0]
          : undefined;
      program.push({
        operation,
        values,
        destination: target === undefined ? undefined : canonical(target),
        source: operation === "--bind" ? canonical(values[0]) : undefined,
      });
    }
    const grant = program.findIndex(({ operation, values }) => operation === "--bind" && values[0] === cwd && values[1] === cwd);
    const before = [];
    const after = [];
    const restrictions = [];
    const pins = new Set();
    program.forEach((entry, index) => {
      const { operation, values, destination, source } = entry;
      if (index === grant) return;
      const later = index > grant;
      // A writable alias of workspace content could bypass every protection.
      if (source !== undefined && values[0] !== values[1] && overlaps(source)) throw new Error("unsupported workspace mount");
      if (destination === undefined || !overlaps(destination)) {
        (later ? after : before).push(entry);
      } else if (!inside(destination)) {
        if (!later) before.push(entry);
        // Only a repeated grant may follow it; an enclosing mount would hide it.
        else if (operation !== "--bind" || values[0] !== values[1] || destination !== root) throw new Error("unsupported workspace mount");
      } else if (operation === "--bind" && values[0] === values[1]) {
        if (!later) return;
        // A later writable descendant may not weaken an established restriction.
        if (restrictions.some((other) => contains(other.destination, destination) || contains(destination, other.destination))) throw new Error("unsupported workspace mount");
        pins.add(destination);
      } else if (operation === "--ro-bind" || (later && operation === "--tmpfs")) {
        restrictions.push(entry);
      } else {
        throw new Error("unsupported workspace mount");
      }
    });
    const protectedPaths = protections(root);
    const masks = restrictions.filter(({ operation, values, destination }) =>
      !(operation === "--ro-bind" && values[0] === values[1] && protectedPaths.includes(destination)));
    // Different restrictions at one destination would keep only the later
    // meaning, and a mask or tmpfs replaces host content, so reapplying a
    // protection or restriction beneath it would change one of their meanings.
    // Reject both; a read-only mask may still follow a protection it covers.
    const sameMount = (left, right) => left.operation === right.operation && left.values[0] === right.values[0];
    for (const entry of masks) {
      if (masks.some((other) => other.destination === entry.destination && !sameMount(other, entry))) throw new Error("unsupported workspace mount");
      if (entry.operation === "--ro-bind" && entry.values[0] === entry.values[1]) continue;
      const hidden = (name) => entry.operation === "--tmpfs" ? contains(entry.destination, name) : name !== entry.destination && contains(entry.destination, name);
      if (protectedPaths.some(hidden) || masks.some((other) => other !== entry && hidden(other.destination))) throw new Error("unsupported workspace mount");
    }
    const immutable = [
      ...protectedPaths,
      ...masks.filter(({ operation }) => operation === "--ro-bind").map(({ destination }) => destination),
    ];
    for (const name of [...protectedPaths, ...masks.map(({ destination }) => destination)]) {
      for (let ancestor = path.dirname(name); inside(ancestor); ancestor = path.dirname(ancestor)) {
        if (!immutable.some((other) => contains(other, ancestor))) pins.add(ancestor);
      }
    }
    const depth = (name) => name.split(path.sep).length;
    const shallowest = (left, right) => depth(left.destination) - depth(right.destination);
    // Generated mounts keep the caller's workspace spelling.
    const mount = (operation) => (name) => {
      const spelled = path.join(cwd, path.relative(root, name));
      return { operation, values: [spelled, spelled], destination: name };
    };
    const protectedEntries = protectedPaths.map(mount("--ro-bind"));
    // Ancestors precede descendants, so no restriction hides another; at one
    // destination a restriction keeps its place after the protection.
    const workspace = [
      program[grant],
      ...[...pins]
        .sort((left, right) => depth(left) - depth(right) || (left < right ? -1 : left > right ? 1 : 0))
        .map(mount("--bind")),
      ...[...protectedEntries, ...masks].sort(shallowest),
    ];
    // Replay the final tree, where a later mount hides every earlier mount at
    // or beneath its destination. Each protection and restriction must stay
    // effective, and none may keep a movable ancestor.
    const effective = [];
    for (const entry of workspace) {
      for (let i = effective.length; i-- > 0;) if (contains(entry.destination, effective[i].destination)) effective.splice(i, 1);
      effective.push(entry);
    }
    const covering = (name) => effective.filter(({ destination }) => contains(destination, name))
      .reduce((left, right) => (depth(right.destination) > depth(left.destination) ? right : left));
    for (const entry of [...protectedEntries, ...masks]) {
      const final = covering(entry.destination);
      if (final.destination !== entry.destination || !(sameMount(final, entry) || (protectedEntries.includes(entry) && final.operation === "--ro-bind"))) throw new Error("unsupported workspace mount");
      for (let name = entry.destination; name !== root; name = path.dirname(name)) {
        if (!effective.some(({ destination }) => destination === name) && covering(path.dirname(name)).operation !== "--ro-bind") throw new Error("unsupported workspace mount");
      }
    }
    return [...before, ...workspace, ...after].flatMap(({ operation, values }) => [operation, ...values]);
  };
  // Claude may pass bubblewrap one descriptor whose end it awaits as the end
  // of the sandbox and one from which it reads bubblewrap's child pid. Accept
  // each once and only as an inherited unnamed, connected Unix stream socket
  // distinct from standard I/O and the other role, so a closed, forged, file,
  // listening, named or network descriptor fails closed. Neither descriptor
  // ever reaches the command: the launcher keeps the end descriptor and passes
  // only the info descriptor, which bubblewrap writes and closes before the
  // command starts.
  const producerDescriptor = (value) => {
    if (!/^[1-9][0-9]{0,5}$/.test(value) || Number(value) < 3) throw new Error("invalid sandbox descriptor");
    const descriptor = Number(value);
    const metadata = fs.fstatSync(descriptor, { bigint: true });
    const inode = String(metadata.ino);
    const socket = fs.readFileSync("/proc/self/net/unix", "utf8").split("\\n").slice(1)
      .map((line) => line.trim().split(/\\s+/))
      .find((fields) => fields[6] === inode);
    if (!metadata.isSocket() || fs.readlinkSync("/proc/self/fd/" + descriptor) !== "socket:[" + inode + "]" ||
      socket?.length !== 7 || socket[3] !== "00000000" || socket[4] !== "0001" || socket[5] !== "03") throw new Error("unsupported sandbox descriptor");
    for (const other of [0, 1, 2, ...Object.values(descriptors)]) {
      let current;
      try {
        current = fs.fstatSync(other, { bigint: true });
      } catch (cause) {
        if (cause?.code === "EBADF") continue;
        throw cause;
      }
      if (current.dev === metadata.dev && current.ino === metadata.ino) throw new Error("shared sandbox descriptor");
    }
    return descriptor;
  };
  // Socket shape alone cannot show that the producer owns a descriptor. The
  // launcher token authenticates the invocation, and Claude passes both roles
  // together as its only inherited sockets beyond standard I/O, so a missing
  // role, a runtime control channel or any other inherited socket fails. The
  // kernel socket table then names each role's peer. The nearest ancestor
  // holding either peer must hold both and carry this launch's shell proof.
  // An enclosing supervisor can own unrelated control peers too; ancestry
  // alone must not authenticate those as the producer's sandbox channels.
  const producerOwnership = () => {
    const owned = Object.values(descriptors);
    const producer = ${JSON.stringify(producerIdentity)};
    if (owned.length !== 2 || process.channel !== undefined || producer === null) throw new Error("unowned sandbox descriptor");
    const links = (pid) => fs.readdirSync("/proc/" + pid + "/fd").flatMap((name) => {
      try {
        return [[Number(name), fs.readlinkSync("/proc/" + pid + "/fd/" + name)]];
      } catch (cause) {
        if (cause?.code === "ENOENT") return [];
        throw cause;
      }
    });
    for (const [descriptor, link] of links("self")) {
      if (descriptor > 2 && !owned.includes(descriptor) && link.startsWith("socket:")) throw new Error("unowned sandbox descriptor");
    }
    const statistics = ${JSON.stringify(socketStatisticsBinary)};
    if (statistics === null) throw new Error("unowned sandbox descriptor");
    const listing = require("node:child_process").spawnSync(statistics, ["-x", "-a", "-n", "-H"], {
      encoding: "utf8", env: { LC_ALL: "C" }, maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"], timeout: 10000,
    });
    if (listing.error || listing.signal || listing.status !== 0) throw new Error("unowned sandbox descriptor");
    const rows = listing.stdout.split("\\n").map((line) => line.trim().split(/\\s+/));
    // An unnamed socket's row has exactly eight fields; a path containing
    // spaces adds fields, so it can never match another socket's inode.
    const peers = owned.map((descriptor) => {
      const inode = String(fs.fstatSync(descriptor, { bigint: true }).ino);
      const matches = rows.filter((fields) => fields.length === 8 && fields[4] === "*" && fields[5] === inode);
      if (matches.length !== 1 || matches[0][0] !== "u_str" || matches[0][1] !== "ESTAB" || matches[0][6] !== "*" ||
        !/^[1-9][0-9]*$/.test(matches[0][7])) throw new Error("unowned sandbox descriptor");
      return "socket:[" + matches[0][7] + "]";
    });
    const visited = new Set();
    for (let pid = process.ppid; pid > 0 && !visited.has(pid);) {
      visited.add(pid);
      const held = new Set(links(pid).map(([, link]) => link));
      const holding = peers.filter((peer) => held.has(peer)).length;
      if (holding === peers.length) {
        const environment = fs.readFileSync("/proc/" + pid + "/environ", "utf8").split("\\0");
        if (!environment.includes(${JSON.stringify(`${CLAUDE_COMMAND_SHELL_PROOF}=${proof}`)})) break;
        const sameIdentity = (name, identity) => {
          const metadata = fs.statSync(name, { bigint: true });
          return String(metadata.dev) === identity.dev && String(metadata.ino) === identity.ino;
        };
        // Native CLIs bind directly to the kernel executable. A shebang CLI
        // also binds its interpreter and first script argument to pinned files;
        // neither a foreign executable nor a path passed as eval data suffices.
        const matches = producer.script
          ? sameIdentity("/proc/" + pid + "/exe", producer.interpreter) &&
            fs.readFileSync("/proc/" + pid + "/cmdline", "utf8").split("\\0").slice(1, 2)
              .some((name) => path.isAbsolute(name) && fs.realpathSync(name) === producer.path && sameIdentity(name, producer))
          : sameIdentity("/proc/" + pid + "/exe", producer);
        if (!matches) break;
        return;
      }
      if (holding > 0) break;
      const stat = fs.readFileSync("/proc/" + pid + "/stat", "utf8");
      pid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]);
    }
    throw new Error("unowned sandbox descriptor");
  };
  if (directory !== null) {
    for (const binding of directory.bindings) {
      const current = fs.lstatSync(binding.path, { bigint: true });
      if (!(current.isDirectory() || (current.isFile() && current.nlink === 1n)) || fs.realpathSync(binding.path) !== binding.realpath || String(current.dev) !== binding.dev || String(current.ino) !== binding.ino) throw new Error("directory mount changed");
    }
  }
  let workspaceGranted = false;
  let preparationReserved = false;
  const projected = [];
  const arity = {
    "--new-session": 0, "--die-with-parent": 0, "--unshare-net": 0,
    "--unshare-pid": 0, "--unshare-user": 0, "--as-pid-1": 0,
    "--ro-bind": 2, "--bind": 2, "--setenv": 2, "--unsetenv": 1,
    "--tmpfs": 1, "--dev": 1, "--proc": 1, "--dir": 1,
    "--chdir": 1, "--cap-drop": 1, "--remount-ro": 1,
    "--sync-fd": 1, "--info-fd": 1,
  };
  for (let i = 0; i < args.length;) {
    const operation = args[i++];
    if (operation === "--") {
      if (Object.keys(descriptors).length > 0) producerOwnership();
      if (writable && directory === null && (!workspaceGranted || !preparationReserved)) throw new Error("missing workspace preparation proof");
      if (directory !== null && (writable || ${JSON.stringify(injectHome)}) && !preparationReserved) throw new Error("missing directory preparation proof");
      const normalized = writable && directory === null ? normalizeWorkspace(projected) : projected;
      if (${JSON.stringify(injectHome)}) normalized.push(...${JSON.stringify(toolHomeArguments(home, proof))});
      if (${JSON.stringify(injectHome)} && providerCwd !== cwd) normalized.push("--chdir", cwd);
      normalized.push("--", ...args.slice(i));
      return normalized;
    }
    const size = arity[operation];
    if (size === undefined || i + size > args.length) throw new Error("unsupported sandbox arguments");
    const values = args.slice(i, i + size);
    i += size;
    if (operation === "--sync-fd" || operation === "--info-fd") {
      const role = operation === "--sync-fd" ? "sync" : "info";
      if (Object.hasOwn(descriptors, role)) throw new Error("repeated sandbox descriptor");
      // Claude's producer assigns these distinct stdio slots before spawning
      // its shell. Peer ownership cannot distinguish a swapped role.
      if (values[0] !== (role === "sync" ? "5" : "6")) throw new Error("unsupported sandbox descriptor role");
      descriptors[role] = producerDescriptor(values[0]);
      continue;
    }
    let destination;
    if (["--bind", "--ro-bind"].includes(operation)) {
      if (values.some((value) => !path.isAbsolute(value) || path.resolve(value) !== value)) throw new Error("invalid mount path");
      // Native startup owns a different cwd. It is not a workspace grant and
      // must not become command-visible writable storage. The real workspace
      // still requires its own exact reservation and access checks below.
      if (providerCwd !== cwd && values[0] === values[1] && contains(providerCwd, values[0])) {
        if (!contains(providerCwd, canonical(values[0]))) throw new Error("native startup path changed");
        continue;
      }
      if (providerCwd !== cwd && operation === "--bind" && values[0] === values[1] && incidentalWrites.includes(values[1])) continue;
      if (values[0] === cwd && values[1] === cwd) {
        if (operation === "--bind") workspaceGranted = true;
        if (operation === "--ro-bind" && (writable || directory !== null)) {
          preparationReserved = true;
          if (directory === null) continue;
        }
        if (directory !== null) {
          if (!${JSON.stringify(injectHome)}) continue;
          projected.push("--ro-bind", cwd, cwd);
          if (operation === "--ro-bind") projected.push(
            ...directory.writablePaths.flatMap((name) => ["--bind", name, name]),
            ...directory.protectedPaths.flatMap((name) => ["--ro-bind", name, name]),
          );
          continue;
        }
      }
      // Claude's own temporary and proxy binds stay inside the turn's private
      // temporary directory, outside every project path.
      const privateWrite = privateDirectory !== null && values[0] === values[1] &&
        [values[1], canonical(values[1])].every((name) => name !== privateDirectory && contains(privateDirectory, name));
      if (directory !== null && operation === "--bind" && !privateWrite && !(
        !${JSON.stringify(injectHome)} && values[0] === "/proc" && values[1] === "/proc"
      )) {
        if (values[0] === values[1] && incidentalWrites.includes(values[1])) continue;
        const destination = fs.realpathSync(values[1]);
        if (values[0] !== values[1] || !directory.writablePaths.some((name) => contains(name, destination)) || directory.protectedPaths.some((name) => contains(name, destination))) throw new Error("undeclared write mount");
      }
      destination = values[1];
    } else if (operation === "--chdir" && providerCwd !== cwd) {
      if (values[0] !== providerCwd && values[0] !== cwd) throw new Error("unsupported command cwd");
      // The native projection or restricted-host launcher supplies the cwd.
      continue;
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
  providerCwd,
  home,
  proof,
  tokenName,
  token,
  unsetEnvironmentNames,
  access,
  directoryPolicy,
  claudeWritablePaths,
  gitDirectories,
  privateDirectory,
  socketStatisticsBinary,
  producerIdentity,
}) {
  return `#!${process.execPath}
const { spawnSync } = require("node:child_process");
const { closeSync } = require("node:fs");
if (process.env[${JSON.stringify(tokenName)}] !== ${JSON.stringify(token)}) process.exit(125);
${projectionSource({ access, cwd, providerCwd, home, proof, directoryPolicy, claudeWritablePaths, gitDirectories, privateDirectory, socketStatisticsBinary, producerIdentity })}
try {
  const descriptors = {};
  const args = projectArguments(process.argv.slice(2), descriptors);
  const env = { ...process.env };
  for (const name of ${JSON.stringify([tokenName, ...unsetEnvironmentNames])}) delete env[name];
  // Child descriptor 3 carries only the info descriptor. The end descriptor
  // stays here, open until bubblewrap has exited.
  const info = descriptors.info === undefined ? [] : [descriptors.info];
  const result = spawnSync(
    ${JSON.stringify(bubblewrapBinary)},
    [...(info.length === 0 ? [] : ["--info-fd", "3"]), ...args],
    { env, stdio: ["inherit", "inherit", "inherit", ...info] },
  );
  for (const descriptor of Object.values(descriptors)) closeSync(descriptor);
  process.exit(result.error || result.signal ? 125 : result.status ?? 125);
} catch { process.exit(125); }
`;
}
