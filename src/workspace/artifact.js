import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { basename, dirname, join } from "node:path";

import {
  assertBindings,
  assertSafe,
  identity,
  observation,
  openDirectory,
  same,
} from "./paths.js";

const MAX_BYTES = 32 * 1024 * 1024;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fileIdentity = (stat) => ({
  ...identity(stat),
  birthtimeNs: String(stat.birthtimeNs),
});
const REPORT_CHANGED = "ERR_WORKSPACE_REPORT_CHANGED";

export async function readArtifact(fs, path) {
  let handle;
  try {
    handle = await fs.open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await handle.stat({ bigint: true });
    assertSafe(
      before.isFile() &&
        before.nlink === 1n &&
        before.size <= BigInt(MAX_BYTES),
      "Report artifact must be an isolated bounded regular file.",
    );
    const digest = createHash("sha256");
    const buffer = Buffer.alloc(65536);
    let size = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      size += bytesRead;
      assertSafe(
        BigInt(size) <= before.size && size <= MAX_BYTES,
        "Report artifact grew during inspection.",
        REPORT_CHANGED,
      );
      digest.update(buffer.subarray(0, bytesRead));
    }
    assertSafe(
      BigInt(size) === before.size &&
        same(
          observation(before),
          observation(await handle.stat({ bigint: true })),
        ) &&
        same(
          observation(before),
          observation(await fs.lstat(path, { bigint: true })),
        ),
      "Report artifact changed during inspection.",
      REPORT_CHANGED,
    );
    return {
      contentHash: digest.digest("hex"),
      identity: fileIdentity(before),
    };
  } catch (cause) {
    if (cause?.code === "ENOENT" && handle === undefined) return null;
    throw cause;
  } finally {
    await handle?.close();
  }
}

/** Runner-only replacement of an explicitly declared artifact, anchored to its parent. */
export async function reportArtifact(
  fs,
  inspection,
  request,
  {
    inspectOnly = false,
    temporary: owned = null,
    recordTemporary,
    assertCurrent,
    includeIdentity = false,
    requireOwnedTemporary = false,
    assertAuthorized,
  } = {},
) {
  const { path, temporaryPath, content, expectedHash } = request;
  assertSafe(
    inspection.artifactPaths.includes(path) &&
      inspection.artifactPaths.includes(temporaryPath) &&
      path !== temporaryPath &&
      dirname(path) === dirname(temporaryPath),
    "Report paths must be exact declared artifacts.",
  );
  if (!inspectOnly)
    assertSafe(
      typeof content === "string" &&
        Buffer.byteLength(content) <= MAX_BYTES &&
        typeof recordTemporary === "function" &&
        (expectedHash === null || /^[a-f0-9]{64}$/u.test(expectedHash)),
      "Invalid report publication.",
    );
  const parent = await openDirectory(fs, dirname(path));
  const target = join(parent.anchor, basename(path));
  const temporary = join(parent.anchor, basename(temporaryPath));
  const guard = async () => {
    await assertAuthorized?.();
    await assertBindings(fs, inspection.bindings);
    assertSafe(
      (await fs.realpath(parent.anchor)) === dirname(path),
      "Report parent changed.",
      "ERR_WORKSPACE_DRIFT",
    );
  };
  try {
    await guard();
    const current = await readArtifact(fs, target);
    await assertCurrent?.(current);
    if (inspectOnly) {
      assertSafe(
        (await readArtifact(fs, temporary)) === null,
        "Unexpected report temporary exists.",
        REPORT_CHANGED,
      );
      await guard();
      return { path, contentHash: current?.contentHash ?? null };
    }
    const desired = hash(content);
    const currentHash = current?.contentHash ?? null;
    let publishedIdentity = current?.identity;
    assertSafe(
      currentHash === expectedHash || currentHash === desired,
      "Report artifact changed outside Runner publication.",
      REPORT_CHANGED,
    );
    let leftover = await readArtifact(fs, temporary);
    assertSafe(
      leftover === null ||
        (owned === null
          ? !requireOwnedTemporary && leftover.contentHash === desired
          : same(leftover.identity, owned.identity) &&
            (owned.phase === "writing" || leftover.contentHash === desired)),
      "Unowned report publication temporary exists.",
      REPORT_CHANGED,
    );
    if (currentHash !== desired) {
      assertSafe(
        owned?.phase !== "prepared" || leftover !== null,
        "Prepared report temporary disappeared before publication.",
        REPORT_CHANGED,
      );
      if (leftover === null || owned?.phase === "writing") {
        const handle = await fs.open(
          temporary,
          leftover === null
            ? "wx"
            : constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
          0o600,
        );
        try {
          const stat = await handle.stat({ bigint: true });
          const temporaryIdentity = fileIdentity(stat);
          assertSafe(
            stat.isFile() &&
              stat.nlink === 1n &&
              (leftover === null || same(temporaryIdentity, owned.identity)),
            "Report temporary ownership changed.",
            REPORT_CHANGED,
          );
          // Journal ownership before bytes can become incomplete. Reopen without
          // truncation on recovery, then verify ownership before rewriting.
          await parent.handle.sync();
          await recordTemporary({
            phase: "writing",
            identity: temporaryIdentity,
          });
          await guard();
          const atPath = await fs.lstat(temporary, { bigint: true });
          assertSafe(
            atPath.isFile() &&
              atPath.nlink === 1n &&
              same(fileIdentity(atPath), temporaryIdentity),
            "Report temporary was replaced before writing.",
            REPORT_CHANGED,
          );
          await handle.truncate(0);
          await handle.writeFile(content);
          await handle.sync();
          leftover = await readArtifact(fs, temporary);
          assertSafe(
            leftover?.contentHash === desired &&
              same(leftover.identity, temporaryIdentity),
            "Written report temporary changed.",
            REPORT_CHANGED,
          );
          await recordTemporary({
            phase: "prepared",
            identity: temporaryIdentity,
          });
        } finally {
          await handle.close();
        }
      }
      await guard();
      assertSafe(
        same(await readArtifact(fs, target), current) &&
          same(await readArtifact(fs, temporary), leftover),
        "Report publication bytes changed.",
        REPORT_CHANGED,
      );
      publishedIdentity = leftover.identity;
      await fs.rename(temporary, target);
    } else if (leftover !== null) {
      await guard();
      assertSafe(
        same(await readArtifact(fs, temporary), leftover),
        "Report temporary changed before cleanup.",
        REPORT_CHANGED,
      );
      await fs.unlink(temporary);
    }
    await parent.handle.sync();
    await guard();
    const published = await readArtifact(fs, target);
    assertSafe(
      published?.contentHash === desired &&
        same(published.identity, publishedIdentity),
      "Report publication readback failed.",
      REPORT_CHANGED,
    );
    return {
      path,
      contentHash: desired,
      ...(includeIdentity ? { identity: published.identity } : {}),
    };
  } finally {
    await parent.handle.close();
  }
}
