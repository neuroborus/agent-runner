import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { NativeEvidenceError } from "./evidence.js";
import { materializeReviewedTar } from "./package-archive.js";
import { materializeReviewedGit } from "./package-extraction.js";
import {
  closedPackageObject,
  nativePackageInput,
  nativePackageReadiness,
  nativePackageReviewDigest,
  normalizeNativePackageReview,
  NATIVE_PACKAGE_LIMITS,
  requirePackageValue,
  verifiedNativeArchiveChunks,
  verifyNativeArchive,
} from "./package-inputs.js";

export async function fetchNativePackageArchive(
  packageId,
  { fetchImpl = globalThis.fetch, signal } = {},
) {
  const input = nativePackageInput(packageId);
  const deadline = AbortSignal.timeout(NATIVE_PACKAGE_LIMITS.acquisitionMs);
  const acquisitionSignal = signal
    ? AbortSignal.any([signal, deadline])
    : deadline;
  let url = input.url;
  for (let redirects = 0; redirects <= 1; redirects++) {
    const response = await fetchImpl(url, {
      redirect: "manual",
      credentials: "omit",
      headers: { "accept-encoding": "identity" },
      signal: acquisitionSignal,
    });
    if (response.status === 200) {
      const valid =
        response.url === url &&
        response.body !== null &&
        [null, "identity"].includes(response.headers.get("content-encoding"));
      if (!valid) await response.body?.cancel();
      requirePackageValue(valid);
      return response.body;
    }
    await response.body?.cancel();
    requirePackageValue(
      redirects === 0 &&
        new URL(url).hostname === "github.com" &&
        [301, 302, 303, 307, 308].includes(response.status),
    );
    const location = response.headers.get("location");
    requirePackageValue(location !== null && location.length <= 8192);
    const target = new URL(location, url);
    requirePackageValue(
      target.protocol === "https:" &&
        !target.username &&
        !target.password &&
        !target.port &&
        !target.hash &&
        target.hostname === "release-assets.githubusercontent.com" &&
        target.pathname.startsWith("/github-production-release-asset/"),
    );
    url = target.href;
  }
  throw new NativeEvidenceError();
}

function sameIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.isDirectory() === right.isDirectory() &&
    left.isFile() === right.isFile()
  );
}

/** Receipt metadata only; callers must finish sealing before returning it.
 * Matching publication bytes never supplies native or provider admission. */
export function nativePackageReceipt(review, directory, extraction) {
  const input = nativePackageInput(review.packageId),
    paths = input.platform === "win32" ? path.win32 : path.posix;
  return {
    status: "BOUND_BYTES",
    candidateSha: review.candidateSha,
    packageId: input.id,
    reviewSha256: nativePackageReviewDigest(review),
    integrity: input.integrity,
    members: review.files.length,
    entrypoint: paths.join(
      directory,
      "content",
      ...(review.entrypoint ?? input.entrypoint).split("/"),
    ),
    ...(extraction ? { extraction } : {}),
    admission: "BLOCKED",
  };
}

/** Dedicated external CI preparation only. The independently approved review
 * comes from trusted custody, never the payload or a downloaded manifest.
 * Tar publications remain data-only. Git uses only its separately reviewed
 * native extractor. Native custody/ACL/loader and provider acceptance
 * still require the platform's independent gate before these bytes are granted. */
export async function prepareReviewedNativePackage(
  options,
  {
    fetchImpl = globalThis.fetch,
    signal,
    extractionEffects,
    persist,
    custody,
  } = {},
) {
  closedPackageObject(options, [
    "candidateSha",
    "packageId",
    "platform",
    "reviewed",
    "approvedReviewSha256",
    "directory",
  ]);
  const input = nativePackageInput(options.packageId);
  requirePackageValue(
    options.platform === input.platform &&
      typeof options.candidateSha === "string" &&
      options.candidateSha.length === 40 &&
      /^[a-f0-9]{40}$/u.test(options.candidateSha),
  );
  if (options.reviewed === null)
    return {
      status: "BLOCKED",
      missingInputs: ["independently-reviewed-package-manifest"],
      admission: "BLOCKED",
    };
  const review = normalizeNativePackageReview(
    options.reviewed,
    options.candidateSha,
  );
  requirePackageValue(review.packageId === input.id);
  const readiness = nativePackageReadiness(review);
  if (readiness.status === "BLOCKED") return readiness;
  if (
    review.schemaVersion === 2 &&
    (!extractionEffects || typeof persist !== "function")
  )
    return {
      status: "BLOCKED",
      missingInputs: ["reviewed-native-extraction-custody"],
      admission: "BLOCKED",
    };
  if (options.approvedReviewSha256 === null)
    return {
      status: "BLOCKED",
      missingInputs: ["independently-approved-review-digest"],
      admission: "BLOCKED",
    };
  const reviewSha256 = nativePackageReviewDigest(review),
    locations = review.schemaVersion === 2 && custody ? path.win32 : path;
  requirePackageValue(
    options.approvedReviewSha256 === reviewSha256 &&
      typeof fetchImpl === "function" &&
      typeof options.directory === "string" &&
      locations.isAbsolute(options.directory) &&
      locations.resolve(options.directory) === options.directory,
  );
  const directory = options.directory;
  const relative = locations.relative(
    fileURLToPath(new URL("../../", import.meta.url)),
    directory,
  );
  requirePackageValue(
    relative.startsWith(`..${locations.sep}`) || locations.isAbsolute(relative),
  );
  if (custody) {
    requirePackageValue(
      review.schemaVersion === 1 || review.schemaVersion === 2,
    );
    const deadline = AbortSignal.timeout(NATIVE_PACKAGE_LIMITS.acquisitionMs);
    const combinedSignal = signal
      ? AbortSignal.any([signal, deadline])
      : deadline;
    const guard = () => requirePackageValue(!combinedSignal.aborted);
    const chunks = [];
    const archive = await fetchNativePackageArchive(input.id, {
      fetchImpl,
      signal: combinedSignal,
    });
    await verifyNativeArchive(
      archive,
      { bytes: review.archiveBytes, integrity: input.integrity },
      (chunk) => {
        guard();
        chunks.push(chunk);
      },
    );
    guard();
    // No write, decoder or image execution precedes complete archive admission.
    let extraction;
    try {
      const held = await custody.sealArchive(
        Buffer.concat(chunks),
        input.integrity,
      );
      guard();
      if (review.schemaVersion === 2) {
        extraction = await materializeReviewedGit(
          locations.join(directory, "archive"),
          locations.join(directory, "content"),
          review,
          extractionEffects,
          { signal: combinedSignal, persist },
        );
      } else
        await materializeReviewedTar([held], review.files, async (member) => {
          const bytes = [];
          let count = 0;
          return {
            async write(chunk) {
              guard();
              count += chunk.length;
              requirePackageValue(count <= member.bytes);
              bytes.push(Buffer.from(chunk));
            },
            async close() {
              guard();
              // The data-only decoder checks the exact member digest before close.
              await custody.sealMember(member, Buffer.concat(bytes, count));
              guard();
            },
          };
        });
      guard();
      await custody.complete();
      guard();
      return nativePackageReceipt(review, directory, extraction);
    } catch (error) {
      // A partial account, policy, task or publication belongs to the native
      // owner even if setup never returned a prepared object.
      if (custody.recover) {
        try {
          await custody.recover();
        } catch {
          /* retain the first cause */
        }
      }
      throw error;
    }
  }
  requirePackageValue(
    (await realpath(path.dirname(directory))) === path.dirname(directory),
  );
  const owned = [],
    handles = new Set();
  const expected = { bytes: review.archiveBytes, integrity: input.integrity };
  const deadline = AbortSignal.timeout(NATIVE_PACKAGE_LIMITS.acquisitionMs);
  const combinedSignal = signal
    ? AbortSignal.any([signal, deadline])
    : deadline;
  let archive,
    nativeExtractionPossible = false;
  async function record(name, isDirectory) {
    const identity = await lstat(name, { bigint: true });
    requirePackageValue(
      isDirectory
        ? identity.isDirectory()
        : identity.isFile() && identity.nlink === 1n,
    );
    owned.push({ name, identity });
  }
  async function createDirectory(name) {
    await mkdir(name, { mode: 0o700 });
    await record(name, true);
  }
  async function createFile(name) {
    const handle = await open(
      name,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_WRONLY |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    handles.add(handle);
    await record(name, false);
    return handle;
  }
  async function writeAll(handle, chunk) {
    for (let offset = 0; offset < chunk.length;) {
      combinedSignal.throwIfAborted();
      const result = await handle.write(chunk, offset, chunk.length - offset);
      requirePackageValue(result.bytesWritten > 0);
      offset += result.bytesWritten;
    }
  }
  try {
    await createDirectory(directory);
    // Archive storage is separate from the executable closure and never granted.
    const archivePath = path.join(directory, "archive");
    archive = await open(
      archivePath,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_RDWR |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    handles.add(archive);
    await record(archivePath, false);
    await verifyNativeArchive(
      await fetchNativePackageArchive(input.id, {
        fetchImpl,
        signal: combinedSignal,
      }),
      expected,
      (chunk) => writeAll(archive, chunk),
    );
    await archive.sync();
    const content = path.join(directory, "content");
    await createDirectory(content);
    const parents = new Set([content]);
    let nativeExtraction;
    if (review.schemaVersion === 2) {
      nativeExtractionPossible = true;
      nativeExtraction = await materializeReviewedGit(
        archivePath,
        content,
        review,
        extractionEffects,
        { signal: combinedSignal, persist },
      );
      nativeExtractionPossible = false;
    } else
      await materializeReviewedTar(
        verifiedNativeArchiveChunks(
          archive.createReadStream({ start: 0, autoClose: false }),
          expected,
        ),
        review.files,
        async (file) => {
          const parts = file.path.split("/");
          parts.pop();
          let parent = content;
          for (const part of parts) {
            parent = path.join(parent, part);
            if (!parents.has(parent)) {
              await createDirectory(parent);
              parents.add(parent);
            }
          }
          const handle = await createFile(
            path.join(content, ...file.path.split("/")),
          );
          return {
            write: (chunk) => writeAll(handle, chunk),
            async close() {
              await handle.sync();
              await handle.chmod(file.executable ? 0o500 : 0o400);
              await handle.close();
              handles.delete(handle);
            },
          };
        },
      );
    await archive.close();
    handles.delete(archive);
    const archiveIdentity = owned.find((entry) => entry.name === archivePath);
    requirePackageValue(
      sameIdentity(
        archiveIdentity.identity,
        await lstat(archivePath, { bigint: true }),
      ),
    );
    await unlink(archivePath);
    owned.splice(owned.indexOf(archiveIdentity), 1);
    for (const entry of [...owned].reverse()) {
      requirePackageValue(
        sameIdentity(entry.identity, await lstat(entry.name, { bigint: true })),
      );
      if (entry.identity.isDirectory()) await chmod(entry.name, 0o500);
    }
    return nativePackageReceipt(review, directory, nativeExtraction);
  } catch (error) {
    const closed = await Promise.allSettled(
      [...handles].map((handle) => handle.close()),
    );
    if (closed.some((result) => result.status === "rejected")) throw error;
    // A failed native gate supplies no permission to remove files that a live
    // extractor may still hold. Its protected ledger owns later recovery.
    if (nativeExtractionPossible) throw error;
    // Never recursively remove or adopt an uncertain path. Unverifiable or
    // failed cleanup retains quarantine for the external phase's effect ledger.
    for (const entry of [...owned].reverse()) {
      try {
        requirePackageValue(
          sameIdentity(
            entry.identity,
            await lstat(entry.name, { bigint: true }),
          ),
        );
        if (entry.identity.isDirectory()) {
          await chmod(entry.name, 0o700);
          await rmdir(entry.name);
        } else await unlink(entry.name);
      } catch {
        throw error;
      }
    }
    throw error;
  }
}
