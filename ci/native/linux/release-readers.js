import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import path from "node:path";
import { assertOwnedProcessLauncherProtected } from "../../../src/agents/index.js";
import {
  normalizeNativePackageReview,
  nativePackageReviewDigest,
  nativePackageReadiness,
  nativePackageInput,
  nativePolicyTemplateDigest,
  admitNativePolicyTemplate,
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import { digest, processDetails, linuxKernelAuthority } from "./inspect.js";

/** Data-only ELF64 loader inspection; never run ldd or an image's interpreter. */
export function linuxElfLoadCommands(bytes) {
  requireObservation(
    Buffer.isBuffer(bytes) &&
      bytes.length >= 64 &&
      bytes.subarray(0, 7).equals(Buffer.from([127, 69, 76, 70, 2, 1, 1])) &&
      bytes.readUInt16LE(18) === 62 &&
      bytes.readUInt32LE(20) === 1 &&
      bytes.readUInt16LE(52) === 64 &&
      [2, 3].includes(bytes.readUInt16LE(16)),
  );
  const offset = Number(bytes.readBigUInt64LE(32)),
    count = bytes.readUInt16LE(56);
  requireObservation(
    Number.isSafeInteger(offset) &&
      offset >= 64 &&
      count > 0 &&
      count <= 128 &&
      bytes.readUInt16LE(54) === 56 &&
      offset + count * 56 <= bytes.length,
  );
  const segments = Array.from({ length: count }, (_, index) => {
    const at = offset + index * 56;
    const item = {
      type: bytes.readUInt32LE(at),
      offset: Number(bytes.readBigUInt64LE(at + 8)),
      address: bytes.readBigUInt64LE(at + 16),
      size: Number(bytes.readBigUInt64LE(at + 32)),
    };
    requireObservation(
      Number.isSafeInteger(item.offset) &&
        Number.isSafeInteger(item.size) &&
        item.offset >= 0 &&
        item.size >= 0 &&
        item.offset + item.size <= bytes.length,
    );
    return item;
  });
  const string = (at, end) => {
    const nul = bytes.indexOf(0, at);
    requireObservation(at >= 0 && nul >= at && nul < end && nul - at <= 4096);
    return new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(at, nul),
    );
  };
  const interpreters = segments.filter((entry) => entry.type === 3);
  requireObservation(interpreters.length <= 1);
  const interpreter = interpreters.length
    ? string(
        interpreters[0].offset,
        interpreters[0].offset + interpreters[0].size,
      )
    : null;
  requireObservation(
    interpreter === null ||
      (path.isAbsolute(interpreter) &&
        path.normalize(interpreter) === interpreter),
  );
  const dynamic = segments.filter((entry) => entry.type === 2);
  requireObservation(dynamic.length <= 1);
  if (!dynamic.length) return { interpreter, needed: [], search: [] };
  const entries = [],
    section = dynamic[0];
  requireObservation(section.size <= 4097 * 16);
  let terminated = false;
  for (
    let at = section.offset;
    at + 16 <= section.offset + section.size;
    at += 16
  ) {
    const tag = bytes.readBigUInt64LE(at),
      value = bytes.readBigUInt64LE(at + 8);
    if (tag === 0n) {
      terminated = true;
      break;
    }
    entries.push({ tag, value });
  }
  requireObservation(terminated && entries.length <= 4096);
  const tables = entries.filter((entry) => entry.tag === 5n);
  const sizes = entries.filter((entry) => entry.tag === 10n);
  requireObservation(tables.length === 1 && sizes.length === 1);
  const loads = segments.filter(
    (entry) =>
      entry.type === 1 &&
      tables[0].value >= entry.address &&
      tables[0].value + sizes[0].value <= entry.address + BigInt(entry.size),
  );
  requireObservation(loads.length === 1);
  const load = loads[0];
  const base = load.offset + Number(tables[0].value - load.address),
    end = base + Number(sizes[0].value);
  const strings = (tag) =>
    entries
      .filter((entry) => entry.tag === tag)
      .map((entry) => {
        requireObservation(entry.value < sizes[0].value);
        return string(base + Number(entry.value), end);
      });
  const needed = strings(1n),
    runpath = strings(29n),
    rpath = strings(15n);
  requireObservation(
    needed.length <= 64 &&
      new Set(needed).size === needed.length &&
      needed.every((name) => /^[A-Za-z0-9_.+-]{1,240}$/u.test(name)) &&
      runpath.length <= 1 &&
      rpath.length <= 1,
  );
  // Inherited RPATH, audit/filter images, relative search and hardware-specific
  // selection need a different reviewed resolver; fail instead of guessing.
  requireObservation(
    rpath.length === 0 &&
      !entries.some(
        (entry) =>
          [0x6ffffefbn, 0x6ffffefcn, 0x7ffffffdn, 0x7fffffffn].includes(
            entry.tag,
          ) ||
          (entry.tag === 0x6ffffffbn && (entry.value & 0x800n) !== 0n),
      ),
  );
  requireObservation(!runpath.length || runpath[0].split(":").every(Boolean));
  return {
    interpreter,
    needed,
    search: (runpath[0] ?? rpath[0] ?? "").split(":").filter(Boolean),
  };
}

function cachePaths(bytes, name) {
  requireObservation(
    bytes.subarray(0, 20).toString() === "glibc-ld.so.cache1.1" &&
      bytes.length >= 48,
  );
  const count = bytes.readUInt32LE(20);
  requireObservation(count <= 65536 && 48 + count * 24 <= bytes.length);
  const string = (offset) => {
    const end = bytes.indexOf(0, offset);
    requireObservation(
      offset >= 48 + count * 24 && end >= offset && end - offset <= 4096,
    );
    return bytes.subarray(offset, end).toString("utf8");
  };
  const matches = [];
  for (let index = 0; index < count; index++) {
    const at = 48 + index * 24;
    if ((bytes.readUInt32LE(at) & 0xff00) !== 0x300) continue;
    if (string(bytes.readUInt32LE(at + 4)) !== name) continue;
    requireObservation(
      bytes.readUInt32LE(at) === 0x303 && bytes.readBigUInt64LE(at + 16) === 0n,
    );
    matches.push(string(bytes.readUInt32LE(at + 8)));
  }
  return [...new Set(matches)];
}

/** Every kernel/file read has a default implementation. Injection replaces
 * native transport in local tests; expected manifests only select allowed files. */
export function createLinuxReleaseReaders(
  { job, manifest, bindings, compilerVersion, runnerTemp },
  {
    fs = filesystem,
    protect = assertOwnedProcessLauncherProtected,
    ownerUid = () => process.getuid(),
    inspectProcess = processDetails,
  } = {},
) {
  job = structuredClone(job);
  manifest = structuredClone(manifest);
  bindings = structuredClone(bindings);
  observationObject(bindings, [
    "schemaVersion",
    "candidateSha",
    "components",
    "providers",
  ]);
  requireObservation(
    bindings.schemaVersion === 1 && bindings.candidateSha === job.candidateSha,
  );
  observationObject(bindings.providers, ["codex", "claude"]);
  const held = new Set(),
    opened = new Map(),
    loaders = new Map(),
    observedImages = new Map(),
    resolutions = new Map();
  const permitted = new Map(
    manifest.inputs.map((entry) => [entry.path, entry.sha256]),
  );
  for (const entry of bindings.components) {
    observationObject(entry, ["id", "path", "bindings"]);
    observationObject(entry.bindings, [
      "publication",
      "source",
      "build",
      "license",
    ]);
    requireObservation(
      manifest.release.components.some((item) => item.id === entry.id) &&
        permitted.has(entry.path),
    );
    for (const file of Object.values(entry.bindings))
      requireObservation(permitted.has(file));
  }
  requireObservation(
    bindings.components.length === manifest.release.components.length &&
      bindings.components.length <= 128 &&
      new Set(bindings.components.map((entry) => entry.id)).size ===
        bindings.components.length &&
      new Set(bindings.components.map((entry) => entry.path)).size ===
        bindings.components.length &&
      typeof runnerTemp === "string" &&
      path.isAbsolute(runnerTemp) &&
      path.normalize(runnerTemp) === runnerTemp &&
      /^13\.[0-9]+\.[0-9]+$/u.test(compilerVersion),
  );
  const open = async (file, directory = false) => {
    const previous = opened.get(file);
    if (previous && !previous.closed) {
      await inspect(previous);
      return previous;
    }
    requireObservation(
      path.isAbsolute(file) && (await fs.realpath(file)) === file,
    );
    // Image-wide files are root protected; CI-private copies retain private ancestors.
    if (!file.startsWith(runnerTemp + "/")) protect(file);
    else {
      let parent = path.dirname(file);
      const root = await fs.realpath(runnerTemp);
      requireObservation(root === runnerTemp);
      while (parent !== root) {
        const metadata = await fs.lstat(parent);
        requireObservation(
          metadata.isDirectory() &&
            metadata.uid === ownerUid() &&
            [0o700, 0o500].includes(metadata.mode & 0o777) &&
            (await fs.realpath(parent)) === parent,
        );
        parent = path.dirname(parent);
      }
    }
    const handle = await fs.open(
      file,
      constants.O_RDONLY |
        constants.O_NOFOLLOW |
        constants.O_NONBLOCK |
        (directory ? constants.O_DIRECTORY : 0),
    );
    const value = { file, handle, directory, closed: false };
    held.add(value);
    opened.set(file, value);
    try {
      value.before = await handle.stat({ bigint: true });
      await inspect(value);
      return value;
    } catch (error) {
      await close(value);
      throw error;
    }
  };
  const inspect = async (value) => {
    requireObservation(held.has(value) && !value.closed);
    const metadata = await value.handle.stat({ bigint: true }),
      named = await fs.lstat(value.file, { bigint: true });
    const before = value.before;
    requireObservation(
      (value.directory
        ? metadata.isDirectory() &&
          named.isDirectory() &&
          metadata.uid === BigInt(ownerUid()) &&
          (metadata.mode & 0o777n) === 0o500n
        : metadata.isFile() &&
          named.isFile() &&
          metadata.nlink === 1n &&
          named.nlink === 1n) &&
        metadata.size >= 0n &&
        (metadata.mode & 0o6022n) === 0n &&
        named.dev === before.dev &&
        named.ino === before.ino &&
        [
          "dev",
          "ino",
          "size",
          "mode",
          "nlink",
          "uid",
          "gid",
          "mtimeNs",
          "ctimeNs",
        ].every(
          (key) => metadata[key] === before[key] && named[key] === before[key],
        ),
    );
    return {
      independent: true,
      held: true,
      reparse: false,
      regular: true,
      identity: `${metadata.dev}:${metadata.ino}`,
    };
  };
  const read = async (value, maximum = 134217728) => {
    await inspect(value);
    requireObservation(
      !value.directory && value.before.size <= BigInt(maximum),
    );
    const bytes = Buffer.alloc(Number(value.before.size) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await value.handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!result.bytesRead) break;
      offset += result.bytesRead;
    }
    await inspect(value);
    requireObservation(offset === Number(value.before.size));
    const data = bytes.subarray(0, offset);
    if (permitted.has(value.file))
      requireObservation(digest(data) === permitted.get(value.file));
    const selected = bindings.components.find(
      (entry) => entry.path === value.file,
    );
    if (selected)
      observedImages.set(selected.id, {
        id: selected.id,
        sha256: digest(data),
        identity: (await inspect(value)).identity,
      });
    return data;
  };
  const close = async (value) => {
    if (value.closed) return;
    try {
      if (value.before) await inspect(value);
    } finally {
      await value.handle.close();
      value.closed = true;
    }
  };
  const readFile = async (file, maximum) => {
    const value = await open(file);
    return read(value, maximum);
  };
  const component = (file) => {
    const matches = bindings.components.filter((entry) => entry.path === file);
    requireObservation(matches.length === 1);
    return matches[0];
  };
  const loaderClosure = async (value, bytes) => {
    const commands = linuxElfLoadCommands(bytes),
      files = [];
    if (commands.interpreter || commands.needed.length) {
      let preload;
      try {
        preload = await fs.lstat("/etc/ld.so.preload");
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      requireObservation(
        !preload ||
          (await readFile("/etc/ld.so.preload", 65536))
            .toString("utf8")
            .trim() === "",
      );
    }
    if (commands.interpreter)
      files.push(await fs.realpath(commands.interpreter));
    for (const name of commands.needed) {
      let found;
      for (const directory of commands.search) {
        const expanded = directory
          .replaceAll("${ORIGIN}", path.dirname(value.file))
          .replaceAll("$ORIGIN", path.dirname(value.file));
        requireObservation(
          path.isAbsolute(expanded) &&
            path.normalize(expanded) === expanded &&
            !expanded.includes("$"),
        );
        try {
          requireObservation((await fs.realpath(expanded)) === expanded);
          if (expanded.startsWith(runnerTemp + "/")) await open(expanded, true);
          else protect(expanded);
        } catch (error) {
          if (error.code === "ENOENT") continue;
          throw error;
        }
        // glibc searches these CPU-selected images before the plain RUNPATH
        // member. Their presence cannot silently select a different library.
        let hardware;
        try {
          hardware = await fs.lstat(path.join(expanded, "glibc-hwcaps"));
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
        requireObservation(!hardware);
        try {
          found = await fs.realpath(path.join(expanded, name));
          break;
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
      }
      if (!found) {
        const entries = cachePaths(
          await readFile("/etc/ld.so.cache", 4194304),
          name,
        );
        requireObservation(entries.length === 1);
        found = await fs.realpath(entries[0]);
      }
      requireObservation(
        !resolutions.has(name) || resolutions.get(name) === found,
      );
      resolutions.set(name, found);
      files.push(found);
    }
    const images = [];
    for (const file of [...new Set(files)]) {
      const image = await open(file);
      const data = await read(image);
      linuxElfLoadCommands(data);
      images.push({
        id: component(file).id,
        identity: (await inspect(image)).identity,
        sha256: digest(data),
      });
    }
    const components = images.map((entry) => entry.id).sort();
    loaders.set(component(value.file).id, components);
    return {
      independent: true,
      complete: true,
      ambiguous: false,
      components,
      nativeSha256: observationDigest({ commands, images }),
    };
  };
  return {
    openHeld: (id) => {
      const entry = bindings.components.find((item) => item.id === id);
      requireObservation(entry);
      return open(entry.path);
    },
    inspectHeld: inspect,
    readHeld: read,
    loaderClosure,
    async buildBindings(value) {
      const entry = component(value.file),
        observed = {};
      for (const [kind, file] of Object.entries(entry.bindings))
        observed[kind] = digest(await readFile(file, 1048576));
      observed.abi = observationDigest(linuxElfLoadCommands(await read(value)));
      return { independent: true, complete: true, bindings: observed };
    },
    async observeAuthority() {
      const os = (
        await readFile(await fs.realpath("/etc/os-release"), 65536)
      ).toString("utf8");
      const status = await fs.readFile("/proc/self/status", "utf8");
      requireObservation(Buffer.byteLength(status) <= 65536);
      requireObservation(
        /^ID=ubuntu$/mu.test(os) && /^VERSION_ID="24\.04"$/mu.test(os),
      );
      const details = await inspectProcess(process.pid);
      const authority = linuxKernelAuthority(status, details);
      const { uid, gid, capabilities, noNewPrivileges } = authority;
      const compiler = manifest.tools.find(
        (entry) => entry.name === "compiler",
      );
      requireObservation(
        digest(await readFile(compiler.path)) === compiler.sha256,
      );
      return {
        candidateSha: job.candidateSha,
        platform: "linux",
        image: "ubuntu-24.04",
        osBuild: "24.04",
        sdkBuild: compilerVersion,
        ...(manifest.release.schemaVersion === 2
          ? {
              policyTemplates: manifest.execution.policyTemplates
                .map((entry) =>
                  nativePolicyTemplateDigest(
                    admitNativePolicyTemplate(entry.template, entry.approval),
                  ),
                )
                .sort(),
            }
          : { policySha256: observationDigest(authority) }),
        privileges: [
          `uid-${uid}`,
          `gid-${gid}`,
          `capabilities-${capabilities}`,
          `no-new-privileges-${noNewPrivileges}`,
        ].sort(),
        authority,
        nativeSha256: observationDigest({
          authority,
          identity: details.identity,
        }),
        independent: true,
        ownedChangesOnly: true,
      };
    },
    async inspectProvider(name) {
      const entry = bindings.providers[name];
      observationObject(entry, ["reviewFile", "directory"]);
      requireObservation(
        permitted.has(entry.reviewFile) && path.isAbsolute(entry.directory),
      );
      const review = normalizeNativePackageReview(
        JSON.parse(await readFile(entry.reviewFile, 1048576)),
        job.candidateSha,
      );
      requireObservation(
        review.packageId === name + "-linux" &&
          nativePackageReadiness(review).status === "BOUND_INPUTS",
      );
      const inventory = [],
        identities = [];
      let visited = 0;
      const walk = async (directory, depth = 0) => {
        requireObservation(
          ++visited <= 8192 &&
            depth <= 32 &&
            inventory.length <= 4096 &&
            (await fs.realpath(directory)) === directory,
        );
        const heldDirectory = await open(directory, true);
        const items = await fs.readdir(directory, { withFileTypes: true });
        requireObservation(items.length <= 4096);
        for (const item of items) {
          requireObservation(!item.isSymbolicLink());
          const file = path.join(directory, item.name);
          if (item.isDirectory()) await walk(file, depth + 1);
          else {
            requireObservation(item.isFile());
            inventory.push(path.relative(entry.directory, file));
          }
        }
        await inspect(heldDirectory);
      };
      await walk(entry.directory);
      requireObservation(
        observationDigest(inventory.sort()) ===
          observationDigest(review.files.map((member) => member.path).sort()),
      );
      for (const member of review.files) {
        const image = await open(path.join(entry.directory, member.path));
        const bytes = await read(image, 536870912);
        requireObservation(
          bytes.length === member.bytes &&
            digest(bytes) === member.sha256 &&
            ((image.before.mode & 0o111n) !== 0n) === member.executable,
        );
        identities.push({
          path: member.path,
          sha256: digest(bytes),
          identity: (await inspect(image)).identity,
        });
      }
      const seeds = bindings.components
        .filter((item) => item.path.startsWith(entry.directory + "/"))
        .map((item) => item.id);
      requireObservation(
        seeds.length > 0 &&
          bindings.components.some(
            (item) =>
              item.path ===
              path.join(
                entry.directory,
                nativePackageInput(name + "-linux").entrypoint,
              ),
          ),
      );
      const reached = new Set(seeds);
      for (const id of reached) {
        requireObservation(loaders.has(id) && observedImages.has(id));
        for (const dependency of loaders.get(id)) reached.add(dependency);
      }
      const members = [...reached].sort();
      return {
        reviewSha256: nativePackageReviewDigest(review),
        closureSha256: nativePackageReviewDigest(review),
        members,
        liveBindingSha256: observationDigest({
          identities,
          images: members.map((id) => observedImages.get(id)),
        }),
        independent: true,
      };
    },
    closeHeld: close,
    async verifyClosed() {
      // Dependencies, provenance and both packages share the outer custody lifetime.
      let verified = true;
      for (const value of held) {
        try {
          await close(value);
        } catch {
          verified = false;
        }
      }
      for (const value of held) {
        let closed = false;
        try {
          await value.handle.stat();
        } catch (error) {
          closed = error.code === "EBADF";
        }
        if (!closed) verified = false;
      }
      requireObservation(verified);
      return {
        independent: true,
        closed: true,
        nativeSha256: observationDigest(
          [...held].map((value) => ({
            file: value.file,
            identity: value.before
              ? `${value.before.dev}:${value.before.ino}`
              : null,
            closed: value.closed,
          })),
        ),
      };
    },
  };
}
