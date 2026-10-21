import { execFile } from "node:child_process";
import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import { isIP } from "node:net";
import { networkInterfaces } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { diagnosticCommand, nativeException } from "../diagnostics.js";
import { observationDigest, requireObservation } from "../index.js";
import { digest } from "./protocol.js";
import { darwinExperimentWorker } from "./experiment-build-inputs.js";
import { normalizeDarwinPfRead } from "./pf-preparation.js";
import { protectedInstalledInput } from "./private-files.js";

const execute = diagnosticCommand(
  "darwin-experiment-inputs",
  promisify(execFile),
);

// Only observed link-local scope is admitted. Persist a numeric zone so cold
// consumers never rediscover an interface or resolve a name in another snapshot.
function experimentAddress(entry, interfaces) {
  const { name, family, address, internal, scopeId } = entry;
  if (
    !/^[A-Za-z][A-Za-z0-9_.:-]{0,14}$/u.test(name) ||
    internal !== false ||
    typeof address !== "string" ||
    (scopeId !== null &&
      (!Number.isInteger(scopeId) || scopeId < 0 || scopeId > 0xffffffff))
  )
    return null;
  const [literal, zone, extra] = address.split("%"),
    version = family === "IPv4" ? 4 : family === "IPv6" ? 6 : 0;
  if (!version || isIP(literal) !== version || extra !== undefined) return null;
  if (version === 4)
    return zone === undefined &&
      !scopeId &&
      !/^127\./u.test(literal) &&
      literal !== "0.0.0.0"
      ? literal
      : null;
  const canonical = new URL(`http://[${literal}]/`).hostname.slice(1, -1),
    linkLocal = /^fe[89ab][0-9a-f]:/iu.test(canonical);
  if (["::", "::1"].includes(canonical)) return null;
  if (!linkLocal) return zone === undefined && !scopeId ? literal : null;
  if (
    !scopeId ||
    (zone !== undefined && zone !== name && zone !== String(scopeId)) ||
    interfaces.some(
      (other) =>
        other !== entry &&
        other.family === "IPv6" &&
        Number.isInteger(other.scopeId) &&
        other.scopeId > 0 &&
        (other.name === name
          ? other.scopeId !== scopeId
          : other.scopeId === scopeId),
    )
  )
    return null;
  return `${literal}%${scopeId}`;
}

// Admit literal versions and the producer's single version-named alias, not
// general preprocessor expressions or conditional version selection.
function openBsmHeaderVersion(bytes) {
  requireObservation(bytes.length <= 1048576);
  // Quoted markers cannot swallow declarations; incomplete tokens fail closed.
  let source = new TextDecoder("utf-8", { fatal: true })
    .decode(bytes)
    .replace(/\\\r?\n/gu, "")
    .replace(
      /"(?:\\[^\r\n]|[^"\\\r\n])*"|'(?:\\[^\r\n]|[^'\\\r\n])*'|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*|["']|\/\*|\*\//gu,
      (token) => {
        requireObservation(token.length > 1 && !["/*", "*/"].includes(token));
        return token.startsWith("/") ? token.replace(/[^\r\n]/gu, " ") : token;
      },
    )
    .trim();
  requireObservation(!source.includes("\0"));
  // Only a file include guard is removable; version conditions remain unproved.
  const guard =
    /^#[ \t]*ifndef[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n[ \t]*#[ \t]*define[ \t]+\1[ \t]*\r?\n([\s\S]*)\r?\n[ \t]*#[ \t]*endif[ \t]*$/u.exec(
      source,
    );
  if (guard && !guard[1].startsWith("AUDIT_HEADER_VERSION")) source = guard[2];
  const producer = "AUDIT_HEADER_VERSION_OPENBSM",
    declarations = new Map();
  let depth = 0;
  for (const line of source.split(/\r?\n/u)) {
    const directive = /^[ \t]*#[ \t]*([a-z]+)\b(.*)$/u.exec(line);
    if (!directive) continue;
    const [, operation, rest] = directive;
    if (["if", "ifdef", "ifndef"].includes(operation)) {
      requireObservation(++depth <= 32);
    } else if (operation === "endif") {
      requireObservation(depth-- > 0);
    } else if (["else", "elif"].includes(operation)) {
      requireObservation(depth > 0);
    } else if (["define", "undef"].includes(operation)) {
      const declaration =
        /^(AUDIT_HEADER_VERSION_OPENBSM[A-Za-z0-9_]*)(.*)$/u.exec(
          rest.trimStart(),
        );
      if (!declaration) continue;
      const [, name, replacement] = declaration,
        suffix = /^AUDIT_HEADER_VERSION_OPENBSM([1-9][0-9]{0,2})?$/u.exec(name),
        value = replacement.trim();
      requireObservation(
        operation === "define" &&
          depth === 0 &&
          suffix &&
          !declarations.has(name) &&
          declarations.size < 16,
      );
      if (
        name === producer &&
        /^AUDIT_HEADER_VERSION_OPENBSM[1-9][0-9]{0,2}$/u.test(value)
      ) {
        declarations.set(name, value);
      } else {
        requireObservation(
          /^[1-9][0-9]{0,2}$/u.test(value) &&
            Number(value) <= 255 &&
            (!suffix[1] || Number(suffix[1]) === Number(value)),
        );
        declarations.set(name, Number(value));
      }
    }
  }
  const selected = declarations.get(producer),
    version =
      typeof selected === "string" ? declarations.get(selected) : selected;
  requireObservation(depth === 0 && typeof version === "number");
  return version;
}

/** Bootstrap publication supplies selectors only. Held root reads and each
 * existing native owner independently verify the actual installed bytes. */
export async function acquireDarwinExperimentInputs(
  prepared,
  build,
  reader,
  persist,
  options = {},
) {
  darwinExperimentWorker(prepared.job, prepared.binding, options);
  const fs = options.fs ?? filesystem,
    staging = path.join(prepared.directory, "case-inputs"),
    admit = async () => {
      requireObservation(
        !options.signal?.aborted &&
          !(await fs.readdir(prepared.directory)).some((name) =>
            name.startsWith("darwin-recovery-"),
          ),
      );
    },
    run = async (file, args) => {
      if (!options.command)
        requireObservation(
          process.platform === "darwin" && process.arch === "x64",
        );
      await admit();
      await persist({
        purpose: "experiment",
        phase: "case-input-command-possible",
        file,
        args,
      });
      await admit();
      return (options.command ?? execute)(file, args, {
        encoding: "utf8",
        timeout: 60000,
        maxBuffer: 1048576,
        signal: options.signal,
        env: {
          CI: "true",
          GITHUB_ACTIONS: "true",
          LANG: "C",
          PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        },
      });
    },
    read = async (file) => {
      const requested = file,
        sampled = {
          regular: null,
          nonsymlink: null,
          installed: null,
          positive: null,
          bounded: null,
          complete: null,
          stable: null,
          recheck: null,
        };
      let before, handle, primary;
      try {
        file = await fs.realpath(file);
        before = await fs.lstat(file);
        requireObservation(
          (sampled.regular = before.isFile()) &&
            (sampled.nonsymlink = !before.isSymbolicLink()) &&
            (sampled.installed = await protectedInstalledInput(
              file,
              before,
              fs,
              "experiment",
            )) &&
            (sampled.positive = before.size > 0) &&
            (sampled.bounded = before.size <= 536870912),
        );
        handle = await fs.open(
          file,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        );
        const buffer = Buffer.alloc(before.size + 1);
        let size = 0;
        while (size < buffer.length) {
          const { bytesRead } = await handle.read(
            buffer,
            size,
            buffer.length - size,
            size,
          );
          if (!bytesRead) break;
          size += bytesRead;
        }
        const bytes = buffer.subarray(0, size),
          after = await fs.lstat(file),
          held = await handle.stat();
        requireObservation(
          (sampled.complete = bytes.length === before.size) &&
            (sampled.stable = [
              "dev",
              "ino",
              "mode",
              "uid",
              "gid",
              "nlink",
              "size",
              "mtimeMs",
              "ctimeMs",
            ].every(
              (key) => before[key] === after[key] && before[key] === held[key],
            )) &&
            (sampled.recheck = await protectedInstalledInput(
              file,
              after,
              fs,
              "experiment",
            )),
        );
        return { file, bytes };
      } catch (cause) {
        primary = cause;
        try {
          nativeException("darwin-experiment-input", {
            requested,
            canonical: file,
            sampled,
            stat:
              before &&
              Object.fromEntries(
                [
                  "dev",
                  "ino",
                  "uid",
                  "gid",
                  "mode",
                  "nlink",
                  "size",
                  "mtimeMs",
                  "ctimeMs",
                ].map((key) => [key, before[key]]),
              ),
          });
        } catch {
          /* Diagnostics cannot replace the original refusal. */
        }
        throw cause;
      } finally {
        try {
          await handle?.close();
        } catch (cause) {
          if (!primary) throw cause;
          try {
            nativeException("darwin-experiment-input-cleanup", cause);
          } catch {
            /* Keep the primary input failure. */
          }
        }
      }
    },
    image = async (file) => {
      const actual = await read(file),
        signature = await run("/usr/bin/codesign", [
          "-d",
          "--verbose=4",
          actual.file,
        ]),
        cdhash = /^CDHash=([a-f0-9]{40})$/mu.exec(signature.stderr)?.[1];
      requireObservation(cdhash);
      const held = await reader.readBuildInput(
        actual.file,
        digest(actual.bytes),
        cdhash,
      );
      // Installed tools may be universal; the matching native loader selects
      // their slice. Generated helpers and dyld retain required image reads.
      return {
        path: actual.file,
        sha256: digest(actual.bytes),
        cdhash,
        ...(held.macho ? { macho: held.macho } : {}),
        identity: held.object.identity,
      };
    };
  await admit();
  await persist({
    purpose: "experiment",
    phase: "case-inputs-possible",
    staging,
  });
  await fs.mkdir(staging, { mode: 0o700 });
  const gitPath = (
      await run("/usr/bin/xcrun", ["--find", "git"])
    ).stdout.trim(),
    git = await image(gitPath),
    pfctl = await image("/sbin/pfctl"),
    hdiutil = await image("/usr/bin/hdiutil"),
    log = await image("/usr/bin/log"),
    loader = await read("/usr/lib/dyld");
  const loaderRead = await reader.readBuildInput(
    loader.file,
    digest(loader.bytes),
  );
  requireObservation(loaderRead.macho);
  const eventFile = await read("/etc/security/audit_event"),
    classFile = await read("/etc/security/audit_class"),
    header = await read(
      path.join(
        prepared.environment.SDKROOT,
        "usr/include/bsm/audit_kevents.h",
      ),
    ),
    recordHeader = await read(
      path.join(prepared.environment.SDKROOT, "usr/include/bsm/audit_record.h"),
    );
  for (const value of [eventFile, classFile, header, recordHeader])
    await reader.readBuildInput(value.file, digest(value.bytes));
  const masks = new Map(
      classFile.bytes
        .toString()
        .split("\n")
        .filter((line) => line && !line.startsWith("#"))
        .map((line) => {
          const [mask, name] = line.split(":");
          return [name, Number(mask)];
        }),
    ),
    declarations = new Map(
      [
        ...header.bytes
          .toString()
          .matchAll(/^#define\s+(AUE_[A-Z0-9_]+)\s+(\d+)\b/gmu),
      ].map((match) => [match[1], Number(match[2])]),
    ),
    events = eventFile.bytes
      .toString()
      .split("\n")
      .filter((line) => line && !line.startsWith("#"))
      .flatMap((line) => {
        const [id, opcode, description, classes] = line.split(":");
        if (!declarations.has(opcode)) return [];
        const mask = classes
          .split(",")
          .reduce((mask, name) => mask | (masks.get(name) ?? 0), 0);
        requireObservation(Number(id) === declarations.get(opcode));
        return mask > 0
          ? [
              {
                event: Number(id),
                opcode,
                classes: mask,
                selector: /SOCKET|CONNECT|BIND|SEND|RECV/u.test(opcode)
                  ? "socket"
                  : /SHM|SEM|MSG/u.test(opcode)
                    ? "ipc"
                    : "path",
              },
            ]
          : [];
      }),
    required = {
      read: "AUE_OPEN_R",
      write: "AUE_OPEN_W",
      unlink: "AUE_UNLINK",
      replace: "AUE_RENAME",
      parent: "AUE_RENAME",
      unix: "AUE_CONNECT",
      shm: "AUE_SHMOPEN",
      sem: "AUE_SEMOPEN",
      "sysv-shm": "AUE_SHMGET",
      "sysv-sem": "AUE_SEMGET",
      tcp4: "AUE_CONNECT",
      tcp6: "AUE_CONNECT",
      udp4: "AUE_SENDTO",
      udp6: "AUE_SENDTO",
    },
    selected = Object.fromEntries(
      Object.entries(required).map(([operation, opcode]) => {
        const event = events.find((event) => event.opcode === opcode);
        requireObservation(event);
        return [operation, event.event];
      }),
    ),
    classes = events
      .filter(({ event }) => Object.values(selected).includes(event))
      .reduce((mask, entry) => mask | entry.classes, 0),
    // The audit pipe selects classes, not individual event IDs. Git's actual
    // open flags can select OPEN_RWTC and other installed variants; every event
    // in the admitted classes needs its SDK-joined declaration for decoding.
    used = events.filter((entry) => entry.classes & classes),
    headerVersion = openBsmHeaderVersion(recordHeader.bytes);
  const interfaces = Object.entries(
      (options.networkInterfaces ?? networkInterfaces)(),
    ).flatMap(([name, entries]) =>
      (entries ?? []).map(({ family, address, internal, scopeid }) => ({
        name,
        family,
        address,
        internal,
        scopeId: scopeid ?? null,
      })),
    ),
    audit = {
      sdkSha256: build.sdk.sha256,
      abiSha256: observationDigest(build.abi),
      headerVersion,
      events: used,
      mappingSha256: digest(JSON.stringify({ headerVersion, events: used })),
    },
    addresses = Object.fromEntries(
      [
        ["inet", "IPv4"],
        ["inet6", "IPv6"],
      ].map(([kind, family]) => {
        const candidates = interfaces.map((entry) => ({
            ...entry,
            exclusions: [
              ...(entry.family !== family ? ["family-mismatch"] : []),
              ...(entry.internal ? ["internal"] : []),
              ...(entry.family === family &&
              !entry.internal &&
              experimentAddress(entry, interfaces) === null
                ? ["invalid-address-scope"]
                : []),
            ],
          })),
          eligible = candidates.filter(
            (entry) => entry.exclusions.length === 0,
          ),
          // Preserve the existing unscoped choice when one is available.
          value = eligible.find((entry) => !entry.scopeId) ?? eligible[0];
        try {
          requireObservation(value);
        } catch (cause) {
          try {
            nativeException("darwin-experiment-addresses", {
              requiredFamily: family,
              interfaces: candidates,
            });
          } catch {
            /* Diagnostics cannot replace the original refusal. */
          }
          throw cause;
        }
        return [kind, experimentAddress(value, interfaces)];
      }),
    );
  // Create only the fixed, previously absent host lease and private case parent.
  for (const directory of [
    "/private/var/run/native-poc",
    "/private/var/run/native-poc/cases",
  ]) {
    await run("/usr/bin/sudo", [
      "-n",
      "--",
      "/bin/mkdir",
      "-m",
      "0711",
      directory,
    ]);
    // Darwin mkdir inherits the host parent's group. Normalize only the
    // directory this producer just created exclusively, never a read-only join.
    await run("/usr/bin/sudo", [
      "-n",
      "--",
      "/usr/sbin/chown",
      "0:0",
      directory,
    ]);
  }
  const publish = async ({ path: file, sha256, bytes }) => {
    requireObservation(
      path.dirname(file) === prepared.sourceDirectory &&
        /^experiment-asset-[0-9]+$/u.test(path.basename(file)) &&
        digest(bytes) === sha256,
    );
    const source = path.join(staging, path.basename(file));
    await admit();
    await fs.writeFile(source, bytes, { flag: "wx", mode: 0o400 });
    await run("/usr/bin/sudo", [
      "-n",
      "--",
      "/usr/bin/install",
      "-o",
      "0",
      "-g",
      "0",
      "-m",
      "0400",
      source,
      file,
    ]);
    await reader.readBuildInput(file, sha256);
  };
  const leaseSource = path.join(staging, "pf-lease");
  await fs.writeFile(leaseSource, "native-poc-pf-lease-v1\n", {
    flag: "wx",
    mode: 0o400,
  });
  await run("/usr/bin/sudo", [
    "-n",
    "--",
    "/usr/bin/install",
    "-o",
    "0",
    "-g",
    "0",
    "-m",
    "0400",
    leaseSource,
    "/private/var/run/native-poc/pf-lease",
  ]);
  const volumeSource = path.join(staging, "control.dmg"),
    volumePath = path.join(prepared.sourceDirectory, "experiment-control.dmg");
  await run("/usr/bin/hdiutil", [
    "create",
    "-size",
    "16m",
    "-fs",
    "HFSX",
    "-volname",
    "native-poc-control",
    "-o",
    volumeSource,
  ]);
  const volumeBytes = await fs.readFile(volumeSource);
  await run("/usr/bin/sudo", [
    "-n",
    "--",
    "/usr/bin/install",
    "-o",
    "0",
    "-g",
    "0",
    "-m",
    "0400",
    volumeSource,
    volumePath,
  ]);
  await reader.readBuildInput(volumePath, digest(volumeBytes));
  const pf = normalizeDarwinPfRead(await reader.pf(), "experiment");
  requireObservation(
    observationDigest(pf) ===
      observationDigest(normalizeDarwinPfRead(await reader.pf(), "experiment")),
  );
  return {
    inputs: {
      git,
      pfctl,
      hdiutil,
      loader: {
        path: loader.file,
        sha256: digest(loader.bytes),
        identity: loaderRead.object.identity,
        macho: loaderRead.macho,
      },
      volume: { path: volumePath, sha256: digest(volumeBytes) },
      pf,
      audit,
      mach: { source: "unified-log-mach-v1", tool: log },
      classes,
      events: selected,
      addresses,
    },
    publish,
  };
}
