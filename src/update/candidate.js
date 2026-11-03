import { dirname, join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  inspectRuntimeCandidate,
  openRuntimeStorage,
  prepareRuntime,
  RUNTIME_PAYLOAD_ENV,
} from "../runtime/index.js";
import { assertContext, fail, selectedMetadata } from "./candidate-contract.js";
import { openAttempt, sameIdentity } from "./storage.js";

// Complete ownership/content proof is shared by completed preparation and
// activation. Reading a receipt alone never grants activation authority.
export async function verifyPreparedCandidate(
  context,
  path,
  official,
  version,
) {
  assertContext(context, path);
  const attempt = context.attempts.at(-1);
  if (
    !attempt?.identity ||
    attempt.phase !== "validated" ||
    context.process !== null ||
    context.selection?.metadata?.version !== version ||
    typeof context.candidate?.rootPath !== "string" ||
    dirname(context.candidate.rootPath) !==
      join(path, attempt.id, "runtime", "payloads") ||
    context.candidate.installationPath !==
      join(path, attempt.id, "prefix", "lib/node_modules", official.packageName)
  )
    fail("storage_unverifiable");
  const root = { ...(await openRuntimeStorage(path)), path };
  let directory;
  try {
    if (
      !sameIdentity(
        await root.handle.stat({ bigint: true }),
        context.rootIdentity,
      )
    )
      fail("storage_unverifiable");
    directory = await openAttempt(root, attempt);
    const pinned = await prepareRuntime({
      rootPath: context.candidate.rootPath,
      environment: { [RUNTIME_PAYLOAD_ENV]: JSON.stringify(context.candidate) },
    });
    const candidate = await inspectRuntimeCandidate(pinned.rootPath);
    if (
      !isDeepStrictEqual(
        selectedMetadata(candidate.metadata),
        context.selection.metadata,
      )
    )
      fail("release_identity");
    await directory.verify();
    await root.verify();
    return pinned;
  } finally {
    try {
      await directory?.close();
    } finally {
      await root.close();
    }
  }
}
