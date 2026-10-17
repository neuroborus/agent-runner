import {
  accessSync,
  closeSync,
  constants,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import { nativeDiagnostic } from "../diagnostics.js";

const MOUNT_BYTES = 262144;
const OUTPUT_BYTES = 32768;
const inspection = {
  accessSync,
  closeSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
};

function unavailable(code) {
  throw Object.assign(new Error("Protection inspection unavailable"), { code });
}

function inspectionCode(error) {
  return /^[A-Z0-9_]{1,64}$/u.test(error?.code)
    ? error.code
    : "INSPECTION_ERROR";
}

function sample(action) {
  try {
    return { value: action() };
  } catch (error) {
    return { unavailable: inspectionCode(error) };
  }
}

function readMounts(fs) {
  const descriptor = fs.openSync(
    "/proc/self/mountinfo",
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  let bytes = 0,
    complete = false;
  const buffer = Buffer.alloc(MOUNT_BYTES);
  try {
    for (let reads = 0; reads < 128 && bytes < buffer.length; reads++) {
      const count = fs.readSync(
        descriptor,
        buffer,
        bytes,
        buffer.length - bytes,
        null,
      );
      if (count === 0) {
        complete = true;
        break;
      }
      bytes += count;
    }
  } finally {
    fs.closeSync(descriptor);
  }
  if (!complete) unavailable("MOUNT_READ_LIMIT");
  const lines = buffer.toString("utf8", 0, bytes).trim().split("\n");
  if (lines.length > 4096) unavailable("MOUNT_ENTRY_LIMIT");
  return lines.map((line) => {
    const fields = line.split(" "),
      options = fields[5]?.split(",") ?? [];
    const mountPoint = fields[4]?.replace(/\\([0-7]{3})/gu, (_, octal) =>
      String.fromCharCode(parseInt(octal, 8)),
    );
    const id = Number(fields[0]);
    if (
      fields.indexOf("-") < 6 ||
      !path.posix.isAbsolute(mountPoint ?? "") ||
      mountPoint.length > 1024 ||
      !Number.isSafeInteger(id) ||
      id < 1 ||
      options.includes("ro") === options.includes("rw")
    )
      unavailable("MOUNT_FORMAT");
    return { id, mountPoint, readOnly: options.includes("ro") };
  });
}

function effectiveMount(file, mounts) {
  return (
    mounts
      .filter(
        ({ mountPoint }) =>
          mountPoint === "/" ||
          file === mountPoint ||
          file.startsWith(mountPoint + "/"),
      )
      .sort(
        (a, b) => b.mountPoint.length - a.mountPoint.length || b.id - a.id,
      )[0] ?? null
  );
}

function metadata(fs, file) {
  const stat = fs.lstatSync(file);
  return {
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: stat.mode,
    uid: stat.uid,
    gid: stat.gid,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
    symlink: stat.isSymbolicLink(),
  };
}

/** Post-refusal observations only: never identifies the guard's earlier state or admits effects. */
export function observeLinuxPreparationProtectionFailure(
  file,
  target,
  { fs = inspection } = {},
) {
  const report = {
    observation: "after-protection-failure",
    file: file.slice(0, 1024),
    target: target.slice(0, 1024),
    ancestors: [],
  };
  try {
    if (!path.posix.isAbsolute(target) || target.length > 1024)
      unavailable("PATH_LIMIT");
    const mounts = sample(() => readMounts(fs));
    report.mountsUnavailable = mounts.unavailable ?? null;
    let current = target,
      anchor = null;
    for (let count = 0; count < 32; count++) {
      const before = sample(() => metadata(fs, current));
      const mount = mounts.value ? effectiveMount(current, mounts.value) : null;
      const runnerWrite = sample(() => {
        try {
          fs.accessSync(current, constants.W_OK);
          return true;
        } catch (error) {
          if (["EACCES", "EPERM", "EROFS"].includes(error?.code)) return false;
          throw error;
        }
      });
      const after = sample(() => metadata(fs, current));
      const predicates = [];
      if (mounts.value && mount === null)
        predicates.push("missing-effective-mount");
      if (before.value?.symlink) predicates.push("symlink");
      if (
        mount &&
        anchor !== null &&
        (!mount.readOnly || mount.mountPoint !== anchor)
      )
        predicates.push("read-only-anchor-mismatch");
      if (
        mount &&
        anchor === null &&
        !mount.readOnly &&
        runnerWrite.value === true
      )
        predicates.push("runner-writable");
      report.ancestors.push({
        path: current,
        mount,
        readOnlyAnchor: anchor,
        before,
        after,
        runnerWrite,
        changed:
          before.value && after.value
            ? JSON.stringify(before.value) !== JSON.stringify(after.value)
            : null,
        observedPredicates: predicates,
      });
      if (anchor === null && mount?.readOnly) anchor = mount.mountPoint;
      if (current === anchor || current === "/") break;
      current = path.posix.dirname(current);
      if (count === 31) report.traversalUnavailable = "ANCESTOR_LIMIT";
    }
    report.canonicalAfter = sample(() => {
      const canonical = fs.realpathSync(file);
      if (canonical.length > 1024) unavailable("PATH_LIMIT");
      return canonical;
    });
    report.targetChanged =
      report.canonicalAfter.value === undefined
        ? null
        : report.canonicalAfter.value !== target;
    const laterMounts = sample(() => readMounts(fs));
    report.mountsAfterUnavailable = laterMounts.unavailable ?? null;
    report.mountsChanged =
      mounts.value && laterMounts.value
        ? JSON.stringify(mounts.value) !== JSON.stringify(laterMounts.value)
        : null;
  } catch (error) {
    report.inspectionUnavailable = inspectionCode(error);
  }
  while (
    Buffer.byteLength(JSON.stringify(report)) > OUTPUT_BYTES &&
    report.ancestors.length
  ) {
    report.ancestors.pop();
    report.outputTruncated = true;
  }
  try {
    nativeDiagnostic("linux-preparation-protection", {
      stderr: JSON.stringify(report),
    });
  } catch {
    // A diagnostic sink cannot replace the original protection failure.
  }
  return report;
}
