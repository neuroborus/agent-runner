import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath, rename, unlink } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";

import { RunnerError } from "./input.js";

const MAX_BYTES = 32 * 1024 * 1024;
const identity = ["dev", "ino", "mode", "uid", "gid", "nlink"];
const observation = [...identity, "size", "mtimeNs", "ctimeNs"];
const same = (before, after, fields) =>
  fields.every((field) => before[field] === after[field]);
const within = (parent, child) => {
  const path = relative(parent, child);
  return (
    path === "" ||
    (!isAbsolute(path) && path !== ".." && !path.startsWith(`..${sep}`))
  );
};
const publicationError = (cause) =>
  new RunnerError(
    "Derived plan progress could not be published; resume to regenerate it after resolving the artifact path or ownership conflict.",
    { cause, code: "ERR_PLAN_PROGRESS_PUBLICATION" },
  );

export function createPlanProgressPublisher({ git }) {
  const publications = new Map();
  return (run, artifact) => {
    let publication = publications.get(run.runId);
    if (publication === undefined) {
      publication = { revision: run.revision, pending: Promise.resolve() };
      publications.set(run.runId, publication);
    }
    publication.revision = Math.max(publication.revision, run.revision);
    const operation = publication.pending.then(async () => {
      // Activity producers leave the state mutation boundary before publishing.
      // Serialize their filesystem effects and discard superseded snapshots.
      if (
        run.revision < publication.revision ||
        run.pipelineState.pendingCommit?.status === "consumed"
      )
        return;
      await publishPlanProgress(run, artifact, git);
    });
    publication.pending = operation.catch(() => {});
    return operation;
  };
}

// Called under Runner mutation ownership, after authoritative publication. File
// bytes establish ownership/staleness only; they never supply workflow authority.
export async function publishPlanProgress(run, artifact, git) {
  if (artifact === null) return;
  let temporaryPath;
  let handle;
  let prepared;
  let directoryHandle;
  const unsafe = () => new Error("Plan progress path or ownership changed.");
  try {
    const destination = join(run.taskPath, "plan.progress.md");
    const marker = `<!-- agent-runner plan-progress ${run.runId} -->\n`;
    if (
      artifact.path !== destination ||
      !artifact.content.startsWith(marker) ||
      Buffer.byteLength(artifact.content) > MAX_BYTES
    )
      throw unsafe();
    const directory = await lstat(run.taskPath, { bigint: true });
    directoryHandle = await open(
      run.taskPath,
      constants.O_RDONLY |
        constants.O_DIRECTORY |
        constants.O_NONBLOCK |
        (constants.O_NOFOLLOW ?? 0),
    );
    const anchor = `/proc/self/fd/${directoryHandle.fd}`;
    const assertDirectory = async () => {
      if (
        !directory.isDirectory() ||
        !same(
          directory,
          await directoryHandle.stat({ bigint: true }),
          identity,
        ) ||
        (await realpath(anchor)) !== run.taskPath ||
        (await realpath(run.taskPath)) !== run.taskPath ||
        !same(directory, await lstat(run.taskPath, { bigint: true }), identity)
      )
        throw unsafe();
    };
    await assertDirectory();
    // Pin all filesystem effects, including failure cleanup, to this directory.
    // Ignore checks use the authorized lexical paths rather than descriptor paths.
    const path = join(anchor, "plan.progress.md");
    const assertIgnored = async (target) => {
      if (!within(run.projectPath, target)) return;
      const inspected = await git.inspectPath({
        projectPath: run.projectPath,
        path: target,
      });
      if (inspected.tracked || !inspected.ignored) throw unsafe();
    };
    let existing = null;
    let content = null;
    try {
      existing = await lstat(path, { bigint: true });
      if (
        !existing.isFile() ||
        existing.nlink !== 1n ||
        existing.size > BigInt(MAX_BYTES)
      )
        throw unsafe();
      handle = await open(
        path,
        constants.O_RDONLY | constants.O_NONBLOCK | (constants.O_NOFOLLOW ?? 0),
      );
      if (!same(existing, await handle.stat({ bigint: true }), observation))
        throw unsafe();
      const buffer = Buffer.alloc(Number(existing.size) + 1);
      let length = 0;
      while (length < buffer.length) {
        const { bytesRead } = await handle.read(
          buffer,
          length,
          buffer.length - length,
          length,
        );
        if (bytesRead === 0) break;
        length += bytesRead;
      }
      content = buffer.toString("utf8", 0, length);
      if (
        length !== Number(existing.size) ||
        !content.startsWith(marker) ||
        Buffer.byteLength(content) > MAX_BYTES ||
        !same(existing, await handle.stat({ bigint: true }), observation)
      )
        throw unsafe();
    } catch (cause) {
      if (cause?.code !== "ENOENT") throw cause;
    } finally {
      await handle?.close();
      handle = undefined;
    }
    const assertTarget = async () => {
      let current = null;
      try {
        current = await lstat(path, { bigint: true });
      } catch (cause) {
        if (cause?.code !== "ENOENT") throw cause;
      }
      if (
        existing === null
          ? current !== null
          : current === null || !same(existing, current, observation)
      )
        throw unsafe();
    };
    await assertIgnored(destination);
    await assertDirectory();
    await assertTarget();
    if (content === artifact.content) return;
    const temporaryName = `.plan.progress-${randomUUID()}.tmp`;
    temporaryPath = join(anchor, temporaryName);
    await assertIgnored(join(run.taskPath, temporaryName));
    await assertDirectory();
    handle = await open(temporaryPath, "wx", 0o600);
    prepared = await handle.stat({ bigint: true });
    await handle.writeFile(artifact.content, "utf8");
    await handle.sync();
    prepared = await handle.stat({ bigint: true });
    await handle.close();
    handle = undefined;
    await assertDirectory();
    await assertIgnored(destination);
    await assertTarget();
    const temporary = await lstat(temporaryPath, { bigint: true });
    if (
      !temporary.isFile() ||
      temporary.nlink !== 1n ||
      !same(prepared, temporary, observation)
    )
      throw unsafe();
    await assertDirectory();
    await rename(temporaryPath, path);
    temporaryPath = undefined;
    try {
      await directoryHandle.sync();
    } catch (cause) {
      if (!["EINVAL", "ENOTSUP", "EPERM", "EISDIR"].includes(cause?.code))
        throw cause;
    }
    await assertDirectory();
  } catch (cause) {
    // Preserve already published state, including accepted authority and consumed
    // effects. Resume regenerates from that state; it never rolls back a gate.
    throw publicationError(cause);
  } finally {
    try {
      await handle?.close();
      if (temporaryPath !== undefined && prepared !== undefined) {
        const current = await lstat(temporaryPath, { bigint: true });
        if (same(prepared, current, identity)) await unlink(temporaryPath);
      }
    } catch (cause) {
      if (cause?.code !== "ENOENT") throw publicationError(cause);
    } finally {
      try {
        await directoryHandle?.close();
      } catch (cause) {
        throw publicationError(cause);
      }
    }
  }
}
