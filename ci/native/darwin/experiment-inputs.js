import { execFile } from "node:child_process";
import * as filesystem from "node:fs/promises";
import { networkInterfaces } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { diagnosticCommand } from "../diagnostics.js";
import { observationDigest, requireObservation } from "../index.js";
import { digest } from "./protocol.js";
import { darwinExperimentWorker } from "./experiment-build-inputs.js";
import { normalizeDarwinPfRead } from "./pf-preparation.js";
import { protectedInstalledInput } from "./private-files.js";

const execute = diagnosticCommand(
  "darwin-experiment-inputs",
  promisify(execFile),
);

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
      file = await fs.realpath(file);
      const before = await fs.lstat(file);
      requireObservation(
        before.isFile() &&
          !before.isSymbolicLink() &&
          before.uid === 0 &&
          !(before.mode & 0o6022) &&
          (before.nlink === 1 ||
            (await protectedInstalledInput(file, before, fs, "experiment"))) &&
          before.size > 0 &&
          before.size <= 536870912,
      );
      const bytes = await fs.readFile(file),
        after = await fs.lstat(file);
      requireObservation(
        bytes.length === before.size &&
          [
            "dev",
            "ino",
            "mode",
            "uid",
            "gid",
            "nlink",
            "size",
            "mtimeMs",
            "ctimeMs",
          ].every((key) => before[key] === after[key]) &&
          (before.nlink === 1 ||
            (await protectedInstalledInput(file, after, fs, "experiment"))),
      );
      return { file, bytes };
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
      );
      requireObservation(held.macho);
      return {
        path: actual.file,
        sha256: digest(actual.bytes),
        cdhash,
        macho: held.macho,
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
      mach: "AUE_BSLOOKUP",
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
    headerVersion = Number(
      /#define\s+AUDIT_HEADER_VERSION\s+(\d+)\b/u.exec(
        recordHeader.bytes.toString(),
      )?.[1],
    );
  requireObservation(headerVersion > 0 && headerVersion <= 255);
  const audit = {
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
        const value = Object.values(
          (options.networkInterfaces ?? networkInterfaces)(),
        )
          .flat()
          .find(
            (entry) =>
              !entry.internal &&
              entry.family === family &&
              !entry.address.startsWith("fe80:"),
          );
        requireObservation(value);
        return [kind, value.address];
      }),
    );
  // Create only the fixed, previously absent host lease and private case parent.
  for (const directory of [
    "/private/var/run/native-poc",
    "/private/var/run/native-poc/cases",
  ])
    await run("/usr/bin/sudo", [
      "-n",
      "--",
      "/bin/mkdir",
      "-m",
      "0711",
      directory,
    ]);
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
    "-format",
    "UDRW",
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
      classes,
      events: selected,
      addresses,
    },
    publish,
  };
}
