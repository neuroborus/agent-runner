import {
  closeSync,
  constants,
  fstatSync,
  ftruncateSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";

const DIRECTORY = ".agent-runner-test-attribution";
const MAX_BYTES = 4_096;
const MAX_LOCATIONS = 4;
const HASH = /^[a-f0-9]{64}$/u;
const OPEN = constants.O_NOFOLLOW | constants.O_NONBLOCK;
const CLASSES = new Set([
  "test-failure",
  "subtests",
  "timeout",
  "cancelled",
  "uncaught",
]);
const FAILURE_CLASSES = new Map([
  ["subtestsFailed", "subtests"],
  ["testTimeoutFailure", "timeout"],
  ["cancelledByParent", "cancelled"],
  ["testAborted", "cancelled"],
  ["uncaughtException", "uncaught"],
]);

function closeAdvisory(fd) {
  try {
    closeSync(fd);
  } catch {
    // Attribution availability must not change the original test outcome.
  }
}

function exact(value, fields) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function validRequest(value) {
  return (
    exact(value, ["nonce", "commandIdentity"]) &&
    typeof value.nonce === "string" &&
    HASH.test(value.nonce) &&
    typeof value.commandIdentity === "string" &&
    HASH.test(value.commandIdentity)
  );
}

function sourcePath(path) {
  return (
    typeof path === "string" &&
    Buffer.byteLength(path) <= 256 &&
    /^(?:test\/|(?:pipelines|packages)\/[^/]+\/test\/).+\.test\.js$/u.test(
      path,
    ) &&
    !/[\\\p{Cc}\p{Cs}\p{Zl}\p{Zp}]/u.test(path) &&
    path
      .split("/")
      .every((part) => part !== "" && part !== "." && part !== "..")
  );
}

function coordinate(value) {
  return (
    value === null ||
    (Number.isInteger(value) && value >= 1 && value <= 1_000_000)
  );
}

function validReport(value, request) {
  return (
    exact(value, ["nonce", "commandIdentity", "locations"]) &&
    value.nonce === request.nonce &&
    value.commandIdentity === request.commandIdentity &&
    Array.isArray(value.locations) &&
    value.locations.length <= MAX_LOCATIONS &&
    value.locations.every(
      (item) =>
        exact(item, ["path", "line", "column", "class"]) &&
        sourcePath(item.path) &&
        coordinate(item.line) &&
        coordinate(item.column) &&
        CLASSES.has(item.class),
    )
  );
}

function identity(info) {
  return `${info.dev}:${info.ino}`;
}

function metadata(info) {
  return `${identity(info)}:${info.mode}:${info.uid}:${info.nlink}:${info.size}:${info.mtimeNs}:${info.ctimeNs}`;
}

function regular(info) {
  if (
    !info.isFile() ||
    info.nlink !== 1n ||
    info.uid !== BigInt(process.getuid()) ||
    (info.mode & 0o777n) !== 0o600n
  )
    throw new Error("Unsafe attribution file.");
}

function openFile(path, flags = constants.O_RDONLY) {
  const fd = openSync(path, flags | OPEN);
  try {
    regular(fstatSync(fd, { bigint: true }));
    if (
      metadata(fstatSync(fd, { bigint: true })) !==
      metadata(lstatSync(path, { bigint: true }))
    )
      throw new Error("Changed attribution file.");
    return fd;
  } catch (error) {
    closeAdvisory(fd);
    throw error;
  }
}

function readBounded(fd) {
  const before = fstatSync(fd, { bigint: true });
  regular(before);
  if (before.size > BigInt(MAX_BYTES))
    throw new Error("Oversized attribution file.");
  const buffer = Buffer.alloc(MAX_BYTES + 1);
  const length = readSync(fd, buffer, 0, buffer.length, 0);
  if (
    BigInt(length) !== before.size ||
    metadata(before) !== metadata(fstatSync(fd, { bigint: true }))
  )
    throw new Error("Changed attribution file.");
  const text = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: true,
  }).decode(buffer.subarray(0, length));
  const value = JSON.parse(text);
  if (JSON.stringify(value) !== text)
    throw new Error("Noncanonical attribution file.");
  return value;
}

function writeReport(fd, report) {
  const bytes = Buffer.from(JSON.stringify(report));
  if (bytes.length > MAX_BYTES)
    throw new Error("Oversized attribution report.");
  // An interrupted write must not preserve a valid previous batch's tail.
  ftruncateSync(fd, 0);
  if (writeSync(fd, bytes, 0, bytes.length, 0) !== bytes.length)
    throw new Error("Incomplete attribution report.");
}

function openProducer(environment) {
  const scratch = environment.AGENT_RUNNER_SCRATCH;
  if (!scratch || !isAbsolute(scratch) || resolve(scratch) !== scratch)
    throw new Error("No attribution request.");
  const path = join(scratch, DIRECTORY);
  if (realpathSync(path) !== path)
    throw new Error("Unsafe attribution directory.");
  const root = openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | OPEN,
  );
  let fd;
  try {
    const info = fstatSync(root, { bigint: true });
    const assertPinned = () => {
      if (
        realpathSync(path) !== path ||
        identity(lstatSync(path, { bigint: true })) !== identity(info)
      )
        throw new Error("Changed attribution directory.");
    };
    if (
      info.uid !== BigInt(process.getuid()) ||
      (info.mode & 0o777n) !== 0o700n
    )
      throw new Error("Unsafe attribution directory.");
    assertPinned();
    const anchored = `/proc/self/fd/${root}`;
    fd = openFile(join(anchored, "request"));
    const request = readBounded(fd);
    if (!validRequest(request)) throw new Error("Invalid attribution request.");
    return { root, anchored, request, assertPinned };
  } catch (error) {
    closeAdvisory(root);
    throw error;
  } finally {
    if (fd !== undefined) closeAdvisory(fd);
  }
}

// Claim once for the whole original command, before either test batch starts.
export function claimTestAttribution(environment = process.env) {
  let producer;
  let fd;
  try {
    producer = openProducer(environment);
    try {
      producer.assertPinned();
      fd = openSync(
        join(producer.anchored, "claim"),
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | OPEN,
        0o600,
      );
      writeReport(fd, { ...producer.request, pid: process.pid });
      return { claimed: true };
    } catch {
      return { claimed: false };
    }
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeAdvisory(fd);
    if (producer) closeAdvisory(producer.root);
  }
}

// The reporter drains original structured events, retaining only four locations.
export async function* reportTestFailures(
  events,
  { environment = process.env, projectPath = process.cwd() } = {},
) {
  let producer;
  let fd;
  let report;
  try {
    producer = openProducer(environment);
    const claim = openFile(join(producer.anchored, "claim"));
    try {
      const value = readBounded(claim);
      if (
        !exact(value, ["nonce", "commandIdentity", "pid"]) ||
        value.nonce !== producer.request.nonce ||
        value.commandIdentity !== producer.request.commandIdentity ||
        value.pid !== process.ppid
      )
        throw new Error("Unclaimed reporter.");
    } finally {
      closeAdvisory(claim);
    }
    fd = openFile(join(producer.anchored, "report"), constants.O_RDWR);
    report = readBounded(fd);
    if (!validReport(report, producer.request)) report = null;
  } catch {
    report = null;
  }
  try {
    for await (const event of events) {
      if (
        !report ||
        event.type !== "test:fail" ||
        report.locations.length >= MAX_LOCATIONS
      )
        continue;
      const data = event.data;
      if (typeof data?.file !== "string") continue;
      const path = isAbsolute(data.file)
        ? relative(projectPath, data.file)
        : data.file;
      if (!sourcePath(path)) continue;
      try {
        const fullPath = resolve(projectPath, path);
        if (
          realpathSync(fullPath) !== fullPath ||
          !lstatSync(fullPath).isFile()
        )
          continue;
      } catch {
        continue;
      }
      const location = {
        path,
        line: coordinate(data.line) ? data.line : null,
        column: coordinate(data.column) ? data.column : null,
        class:
          FAILURE_CLASSES.get(data.details?.error?.failureType) ??
          "test-failure",
      };
      if (
        !report.locations.some(
          (item) => JSON.stringify(item) === JSON.stringify(location),
        )
      )
        report.locations.push(location);
    }
    if (report) {
      try {
        producer.assertPinned();
        if (
          metadata(fstatSync(fd, { bigint: true })) !==
          metadata(
            lstatSync(join(producer.anchored, "report"), { bigint: true }),
          )
        )
          throw new Error("Changed attribution report.");
        writeReport(fd, report);
      } catch {
        // Missing diagnostics cannot change the original invocation's outcome.
      }
    }
  } finally {
    if (fd !== undefined) closeAdvisory(fd);
    if (producer) closeAdvisory(producer.root);
  }
}
