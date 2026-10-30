import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { nativeException } from "../diagnostics.js";
import { digest, requireDarwin } from "./protocol.js";

const STOCK_TOOLS = new Set([
  "/usr/bin/clang",
  "/usr/bin/xcrun",
  "/usr/bin/codesign",
  "/usr/bin/env",
  "/usr/bin/sudo",
  "/usr/bin/git",
  "/usr/bin/hdiutil",
  "/usr/bin/log",
  "/sbin/pfctl",
]);
const STABILITY = [
  "dev",
  "ino",
  "mode",
  "uid",
  "gid",
  "nlink",
  "size",
  "mtimeMs",
  "ctimeMs",
  "mtimeNs",
  "ctimeNs",
];
const validIdentity = (stat) =>
  [stat.dev, stat.ino].every(
    (value) =>
      typeof value === "bigint" &&
      value >= 0n &&
      value <= 18446744073709551615n,
  );
const same = (before, after) =>
  STABILITY.every((key) => before[key] === after[key]);
const statFacts = (stat) =>
  stat &&
  Object.fromEntries(
    STABILITY.flatMap((key) =>
      ["number", "bigint"].includes(typeof stat[key]) ? [[key, stat[key]]] : [],
    ),
  );
const errorFacts = (cause) =>
  Object.fromEntries(
    ["name", "code", "message"].map((key) => [
      key,
      typeof cause?.[key] === "string"
        ? cause[key].slice(0, key === "message" ? 512 : 64)
        : null,
    ]),
  );
const installedCache = (file) =>
  (file.startsWith("/System/Library/dyld/") ||
    file.startsWith("/System/Volumes/Preboot/")) &&
  /^dyld_shared_cache_x86_64h?$/u.test(path.basename(file));

// Path classification grants no identity, byte, signature or private-file proof.
export const isDarwinInstalledPath = (file) =>
  typeof file === "string" &&
  file.length < 4096 &&
  path.isAbsolute(file) &&
  path.normalize(file) === file &&
  (STOCK_TOOLS.has(file) ||
    file === "/usr/lib/dyld" ||
    /^\/(?:private\/)?etc\/security\/audit_(?:event|class)$/u.test(file) ||
    file.startsWith("/Library/Developer/") ||
    (file.startsWith("/Applications/") &&
      file.includes("/Contents/Developer/")) ||
    file.startsWith("/usr/include/") ||
    file.startsWith("/usr/lib/clang/") ||
    installedCache(file));

/** Reviewed reads require protected metadata; experiment installed inputs trust
 * the hosted image. Both retain canonical ancestry and stable identities.
 * An optional failure record retains the predicate and originating API exception. */
export async function protectedInstalledInput(
  file,
  stat,
  fs,
  purpose = "reviewed",
  failure = null,
) {
  let accepted = false,
    current = file,
    observed = stat,
    rechecked,
    predicate = "purpose",
    code = null;
  const check = (name, value) => {
    predicate = name;
    return value;
  };
  try {
    if (!["reviewed", "experiment"].includes(purpose)) return false;
    const hosted = purpose === "experiment" && isDarwinInstalledPath(file);
    // Existing Number-stat callers classify scalar eligibility only. The held
    // reader and ancestry snapshots independently acquire exact identities.
    const bounded = (value, maximum) =>
      typeof value === "bigint"
        ? value >= 0n && value <= BigInt(maximum)
        : Number.isSafeInteger(value) && value >= 0 && value <= maximum;
    if (
      !check(
        "identity",
        !(
          (typeof stat.dev === "bigint" || typeof stat.ino === "bigint") &&
          !validIdentity(stat)
        ),
      ) ||
      !check("mode-type", bounded(stat.mode, 0xffffffff)) ||
      !check("links-type", bounded(stat.nlink, Number.MAX_SAFE_INTEGER))
    )
      return false;
    const mode = Number(stat.mode) & 0o7777,
      stock = STOCK_TOOLS.has(file),
      installed = isDarwinInstalledPath(file);
    if (
      !check(
        "path",
        installed && file.length < 4096 && path.normalize(file) === file,
      ) ||
      !check(
        "mode",
        hosted ||
          (stock
            ? (file === "/usr/bin/sudo"
                ? [0o4555, 0o4755]
                : [0o555, 0o755]
              ).includes(mode)
            : !(mode & 0o6022)),
      ) ||
      !check("owner", hosted || stat.uid === 0 || stat.uid === 0n) ||
      !check("group", hosted || !stock || stat.gid === 0 || stat.gid === 0n) ||
      !check("links", stat.nlink > 0) ||
      !check("regular", stat.isFile() && !stat.isSymbolicLink())
    )
      return false;
    predicate = "canonical";
    if ((await fs.realpath(file)) !== file) return false;
    let parent = path.dirname(file);
    for (let depth = 0; depth < 32; depth++) {
      current = parent;
      observed = undefined;
      rechecked = undefined;
      predicate = "ancestor-stat";
      const before = await fs.lstat(parent, { bigint: true });
      observed = before;
      if (
        !check("ancestor-identity", validIdentity(before)) ||
        !check(
          "ancestor-directory",
          before.isDirectory() && !before.isSymbolicLink(),
        ) ||
        !check(
          "ancestor-authority",
          hosted || (before.uid === 0n && !(before.mode & 0o22n)),
        )
      )
        return false;
      predicate = "ancestor-canonical";
      if ((await fs.realpath(parent)) !== parent) return false;
      predicate = "ancestor-stability";
      rechecked = await fs.lstat(parent, { bigint: true });
      if (!same(before, rechecked)) return false;
      if (parent === "/") {
        current = file;
        observed = stat;
        rechecked = undefined;
        predicate = "named-stability";
        rechecked = await fs.lstat(file, {
          bigint: typeof stat.uid === "bigint",
        });
        return (accepted = same(stat, rechecked));
      }
      parent = path.dirname(parent);
    }
    predicate = "ancestor-depth";
  } catch (cause) {
    code = typeof cause?.code === "string" ? cause.code.slice(0, 64) : null;
    if (failure) failure.cause = cause;
  } finally {
    if (failure && !accepted)
      Object.assign(failure, {
        path: String(current).slice(0, 4096),
        predicate,
        code,
        stat: statFacts(observed),
        recheck: statFacts(rechecked),
      });
  }
  return false;
}

export async function protectedBytes(
  entry,
  gid,
  mode,
  maximum,
  fs = { lstat, open, realpath },
  installed = false,
  purpose = "reviewed",
) {
  let handle,
    before,
    after,
    named,
    failed = false,
    predicate = "canonical";
  const installedFailure = {},
    check = (name, value) => {
      predicate = name;
      requireDarwin(value);
    },
    installedInput = async (stat) => {
      const accepted = await protectedInstalledInput(
        entry.path,
        stat,
        fs,
        purpose,
        installedFailure,
      );
      if (!accepted && Object.hasOwn(installedFailure, "cause"))
        throw installedFailure.cause;
      return accepted;
    };
  try {
    check(predicate, (await fs.realpath(entry.path)) === entry.path);
    predicate = "open";
    handle = await fs.open(
      entry.path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    predicate = "metadata";
    before = await handle.stat({ bigint: true });
    const hosted =
      installed &&
      purpose === "experiment" &&
      isDarwinInstalledPath(entry.path);
    check("identity", validIdentity(before));
    check("regular", before.isFile());
    check("owner", hosted || before.uid === 0n);
    check("group", hosted || before.gid === BigInt(gid));
    predicate = "installed";
    check(
      predicate,
      (!hosted && before.nlink === 1n) ||
        (installed && (await installedInput(before))),
    );
    check("mode", hosted || (before.mode & 0o7777n) === BigInt(mode));
    check("positive-size", before.size > 0n);
    check("maximum-size", before.size <= BigInt(maximum));
    predicate = "read";
    const buffer = Buffer.alloc(Number(before.size) + 1);
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
    predicate = "metadata-recheck";
    after = await handle.stat({ bigint: true });
    predicate = "named-recheck";
    named = await fs.lstat(entry.path, { bigint: true });
    check("complete", BigInt(size) === before.size);
    check("identity-recheck", validIdentity(after) && validIdentity(named));
    check(
      "stability",
      [
        "dev",
        "ino",
        "mode",
        "uid",
        "gid",
        "nlink",
        "size",
        "mtimeNs",
        "ctimeNs",
      ].every(
        (key) => before[key] === after[key] && before[key] === named[key],
      ),
    );
    predicate = "canonical-recheck";
    check(predicate, (await fs.realpath(entry.path)) === entry.path);
    predicate = "installed-recheck";
    check(
      predicate,
      (!hosted && before.nlink === 1n) || (await installedInput(named)),
    );
    const bytes = buffer.subarray(0, size);
    check("sha256", digest(bytes) === entry.sha256);
    return bytes;
  } catch (cause) {
    failed = true;
    try {
      nativeException("darwin-file-read", {
        path: String(entry.path).slice(0, 4096),
        predicate,
        expected: {
          source: "recorded-binding",
          sha256:
            typeof entry.sha256 === "string" ? entry.sha256.slice(0, 64) : null,
        },
        cause: errorFacts(cause),
        installed: Object.hasOwn(installedFailure, "predicate")
          ? {
              path: installedFailure.path,
              predicate: installedFailure.predicate,
              code: installedFailure.code,
              stat: installedFailure.stat,
              recheck: installedFailure.recheck,
            }
          : {},
        maximum,
        stat: statFacts(before),
        recheck: { held: statFacts(after), named: statFacts(named) },
      });
    } catch {
      /* Diagnostics cannot replace the original read refusal. */
    }
    throw cause;
  } finally {
    try {
      await handle?.close();
    } catch (cause) {
      try {
        nativeException("darwin-file-read-cleanup", {
          path: String(entry.path).slice(0, 4096),
          predicate: "close",
          cause: errorFacts(cause),
        });
      } catch {
        /* Retain the first refusal even if reporting cleanup also fails. */
      }
      if (!failed) throw cause;
    }
  }
}
