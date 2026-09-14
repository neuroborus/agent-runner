import { randomUUID } from "node:crypto";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import {
  atomicWriteFile,
  publishExclusiveFile,
  readOptionalPublishedText,
  removeFile,
} from "./files.js";
import {
  inspectProcessOwner,
  validateProcessIdentity,
} from "./process-owner.js";
import { assertRunId, RunStoreError } from "./validation.js";

const PREFIX = ".mutation-";
const MAX_CLAIMS = 1_024;
const MAX_ATTEMPTS = 500;
const FIELDS = new Set([
  "schemaVersion",
  "token",
  "pid",
  "hostname",
  "processIdentity",
  "ticket",
]);

function invalid() {
  throw new RunStoreError("Run mutation claim is invalid.", {
    code: "ERR_INVALID_RUN_MUTATION",
  });
}

function parseClaim(source, token) {
  if (Buffer.byteLength(source) > 2_048) invalid();
  let record;
  try {
    record = JSON.parse(source);
  } catch {
    invalid();
  }
  if (
    record === null ||
    typeof record !== "object" ||
    Array.isArray(record) ||
    Object.keys(record).length !== FIELDS.size ||
    Object.keys(record).some((field) => !FIELDS.has(field)) ||
    record.schemaVersion !== 1 ||
    record.token !== token ||
    !Number.isSafeInteger(record.pid) ||
    record.pid < 1 ||
    typeof record.hostname !== "string" ||
    record.hostname.length < 1 ||
    record.hostname.length > 255 ||
    /[\p{Cc}\p{Zl}\p{Zp}]/u.test(record.hostname) ||
    (record.ticket !== null &&
      (!Number.isSafeInteger(record.ticket) || record.ticket < 1))
  )
    invalid();
  assertRunId(token);
  validateProcessIdentity(record.processIdentity);
  return record;
}

// A filesystem bakery lock avoids compare-and-unlink races during stale-owner
// recovery. Each contender publishes a unique choosing claim before selecting
// its ticket. It waits for choosing peers and lower (ticket, token) pairs.
// Dead claims are ignored, never replaced by another owner's claim at that path.
export function createMutationBoundary({
  hostName,
  processId,
  processIsAlive,
  processIdentity,
  onPublicationBoundary,
}) {
  const ownerOptions = { hostName, processIsAlive, processIdentity };
  async function claims(directory, ownerToken) {
    const names = (await readdir(directory)).filter((name) =>
      /^\.mutation-[a-f0-9-]{36}$/u.test(name),
    );
    if (names.length > MAX_CLAIMS) {
      throw new RunStoreError("Run mutation claim capacity is exhausted.", {
        code: "ERR_RUN_MUTATION_BUSY",
      });
    }
    const records = [];
    for (const name of names) {
      const path = join(directory, name);
      const source = await readOptionalPublishedText(path);
      if (source === null) continue;
      const record = parseClaim(source, name.slice(PREFIX.length));
      if (
        record.token !== ownerToken &&
        ["dead", "replaced"].includes(
          await inspectProcessOwner(record, ownerOptions),
        )
      ) {
        await removeFile(path);
      } else {
        records.push(record);
      }
    }
    return records;
  }

  return async (directory, operation) => {
    const token = randomUUID();
    const path = join(directory, PREFIX + token);
    const record = {
      schemaVersion: 1,
      token,
      pid: processId,
      hostname: hostName,
      processIdentity: validateProcessIdentity(
        await processIdentity(processId),
      ),
      ticket: null,
    };
    await publishExclusiveFile(path, JSON.stringify(record) + "\n", {
      onPublicationBoundary,
    });
    try {
      const peers = await claims(directory, token);
      record.ticket = Math.max(0, ...peers.map((peer) => peer.ticket ?? 0)) + 1;
      if (!Number.isSafeInteger(record.ticket)) invalid();
      await atomicWriteFile(path, JSON.stringify(record) + "\n");
      for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
        const peers = await claims(directory, token);
        const owned = peers.find((peer) => peer.token === token);
        if (owned?.ticket !== record.ticket) invalid();
        const blocked = peers.some(
          (peer) =>
            peer.token !== token &&
            (peer.ticket === null ||
              peer.ticket < record.ticket ||
              (peer.ticket === record.ticket && peer.token < token)),
        );
        if (!blocked) return await operation();
        await delay(10);
      }
      throw new RunStoreError(
        "Run mutation is still in progress; retry the same request.",
        {
          code: "ERR_RUN_MUTATION_BUSY",
        },
      );
    } finally {
      await removeFile(path);
    }
  };
}
