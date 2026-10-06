import { createHash } from "node:crypto";
import { posix, win32 } from "node:path";
import {
  observationDigest,
  observationObject,
  requireObservation,
} from "./observation.js";
import { createCapabilityFiles } from "./capability-files.js";
import {
  nativePackageReviewDigest,
  normalizeNativePackageReview,
  nativePackageInput,
  verifyNativeArchive,
} from "./package-inputs.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const same = (left, right) =>
  observationDigest(left) === observationDigest(right);

/** Approved inputs are data. This owner supplies persistence, file creation,
 * held verification and reconstruction through the reviewed stock-host port. */
export function createPrerequisiteCustody(input, options = {}) {
  const value = structuredClone(
      Object.fromEntries(
        [
          "job",
          "manifest",
          "output",
          "buildOutput",
          "directory",
          "admission",
          "runtime",
          "privilege",
          "approvals",
        ].map((key) => [key, input[key]]),
      ),
    ),
    { job, manifest } = value;
  requireObservation(
    manifest.schemaVersion === 2 &&
      manifest.prerequisites &&
      manifest.candidateSha === job.candidateSha &&
      manifest.platform === job.platform &&
      ["linux", "darwin", "win32"].includes(job.platform),
  );
  const paths = job.platform === "win32" ? win32 : posix;
  const files = createCapabilityFiles(value, options),
    observed = new Map(),
    packages = new Map();
  let closed = false,
    failed = false,
    firstFailure,
    lastRecord = null,
    recordCount = 0,
    bootstrapRequest;
  let persistence = Promise.resolve();
  const guard = (signal) => requireObservation(!closed && !signal?.aborted);
  const fail = (error) => {
    if (!failed) {
      failed = true;
      firstFailure = error;
    }
  };
  const binding = {
    candidateSha: job.candidateSha,
    platform: job.platform,
    manifestSha256: observationDigest(manifest),
  };
  const save = async (record) => {
    guard();
    requireObservation(++recordCount <= 65536);
    if (
      record.request?.phase === "native-bootstrap" &&
      record.status === "POSSIBLE"
    ) {
      requireObservation(!bootstrapRequest);
      bootstrapRequest = structuredClone(record.request);
    }
    const receipt = await files.persist({
      schemaVersion: 1,
      binding,
      record,
      previous: lastRecord,
      sequence: recordCount,
    });
    lastRecord = {
      path: receipt.file,
      bytes: receipt.bytes,
      sha256: receipt.sha256,
    };
    // The outer protocol joins the actual caller's record, not its envelope.
    return { ...receipt, recordSha256: observationDigest(record) };
  };
  const persist = (record) => {
    record = structuredClone(record);
    const running = persistence.then(() => save(record));
    persistence = running;
    // Keep an interrupted intent as the first failure and fence later writes.
    running.catch(fail);
    return running;
  };
  const observe = async (expected, signal, created = false) => {
    guard(signal);
    const actual = await files.readProtected({
      file: expected.path,
      bytes: expected.bytes,
      sha256: expected.sha256,
      signal,
    });
    const previous = observed.get(expected.path);
    requireObservation(
      (!created || actual.birthProtected === true) &&
        (!previous || same(previous.identity, actual.identity)),
    );
    observed.set(expected.path, {
      identity: actual.identity,
      expected: structuredClone(expected),
    });
    return actual;
  };
  const approvedAsset = (request) => {
    const asset = manifest.prerequisites.assets.find(
      (entry) => entry.path === request.asset?.path,
    );
    requireObservation(
      request.candidateSha === job.candidateSha &&
        request.platform === job.platform &&
        request.phase === "bootstrap-assets" &&
        asset &&
        same(asset, request.asset),
    );
    return asset;
  };
  const verifyPackage = async (entry, signal) => {
    const tree = new Map([[entry.directory, new Set(["archive", "content"])]]);
    for (const member of entry.reviewed.files) {
      const parts = ["content", ...member.path.split("/")];
      let directory = entry.directory;
      for (const part of parts) {
        if (!tree.has(directory)) tree.set(directory, new Set());
        tree.get(directory).add(part);
        directory = paths.join(directory, part);
      }
    }
    const events = [];
    const archive = observed.get(
      paths.join(entry.directory, "archive"),
    )?.expected;
    requireObservation(archive);
    events.push((await observe(archive, signal, true)).event);
    for (const [directory, names] of tree) {
      const actual = await files.directory(directory, { signal });
      requireObservation(
        same(actual.names, [...names].sort()) &&
          (directory !== entry.directory || actual.birthProtected === true),
      );
      events.push(actual.event);
    }
    for (const member of entry.reviewed.files)
      events.push(
        (
          await observe(
            {
              ...member,
              path: paths.join(
                entry.directory,
                "content",
                ...member.path.split("/"),
              ),
            },
            signal,
            true,
          )
        ).event,
      );
    return events;
  };
  const port = {
    persist,
    async sealAsset(request, bytes, { signal } = {}) {
      guard(signal);
      request = structuredClone(request);
      const asset = approvedAsset(request);
      requireObservation(
        Buffer.isBuffer(bytes) &&
          bytes.length === asset.bytes &&
          digest(bytes) === asset.sha256,
      );
      bytes = Buffer.from(bytes);
      // Even direct callers receive protected intent before possible creation.
      await persist({
        request,
        requestSha256: observationDigest(request),
        status: "POSSIBLE",
      });
      await files.writeProtected({
        file: asset.path,
        bytes,
        sha256: asset.sha256,
        executable: asset.kind === "image",
        signal,
      });
      const actual = await observe(asset, signal, true);
      return {
        requestSha256: observationDigest(request),
        independent: true,
        birthProtected: true,
        protectedParents: true,
        exclusive: true,
        held: true,
        unchanged: true,
        executed: false,
        identitySha256: observationDigest(actual.identity),
        nativeEventSha256: observationDigest(actual.event),
      };
    },
    async verifyAsset(request, { signal } = {}) {
      request = structuredClone(request);
      const asset = approvedAsset(request);
      requireObservation(observed.has(asset.path));
      const actual = await observe(asset, signal, true);
      const proof = {
        requestSha256: observationDigest(request),
        independent: true,
        held: true,
        unchanged: true,
        readExecuteOnly: true,
        bytes: asset.bytes,
        sha256: asset.sha256,
        noLiveMembers: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest(actual.event),
      };
      // noLiveMembers concerns this file's closed writer; custodian retirement
      // is a separate independent process observation at close/recovery.
      await persist({
        request,
        requestSha256: observationDigest(request),
        status: "RETIRED",
        receiptSha256: observationDigest(proof),
      });
      return proof;
    },
    async packageOptions(entry, { signal } = {}) {
      guard(signal);
      const approved = manifest.prerequisites.packages.find(
        (item) => item.packageId === entry.packageId,
      );
      requireObservation(approved && same(approved, entry));
      entry = structuredClone(approved);
      const review = normalizeNativePackageReview(
        entry.reviewed,
        job.candidateSha,
      );
      requireObservation(
        nativePackageReviewDigest(review) === entry.approvedReviewSha256,
      );
      // Native Git extraction remains blocked until its confined owner exists.
      if (review.schemaVersion === 2) return {};
      const members = new Map(review.files.map((file) => [file.path, file]));
      let archiveSealed = false;
      return {
        fetchImpl: options.fetchInput ?? globalThis.fetch,
        custody: {
          async sealArchive(bytes, integrity) {
            guard(signal);
            const expected = nativePackageInput(entry.packageId);
            requireObservation(
              !archiveSealed &&
                Buffer.isBuffer(bytes) &&
                integrity === expected.integrity,
            );
            bytes = Buffer.from(bytes);
            await verifyNativeArchive(
              [bytes],
              { bytes: review.archiveBytes, integrity: expected.integrity },
              () => {},
            );
            const file = paths.join(entry.directory, "archive"),
              sha256 = digest(bytes);
            const request = {
              phase: "package-archive",
              ...binding,
              packageId: entry.packageId,
              directory: entry.directory,
              file,
              bytes: bytes.length,
              sha256,
              integrity,
            };
            await persist({
              status: "POSSIBLE",
              request,
              requestSha256: observationDigest(request),
            });
            const directory = await files.provisionDirectory(entry.directory, {
              signal,
            });
            await files.writeProtected({ file, bytes, sha256, signal });
            const actual = await observe(
              { path: file, bytes: bytes.length, sha256 },
              signal,
              true,
            );
            await persist({
              status: "RETIRED",
              request,
              requestSha256: observationDigest(request),
              receiptSha256: observationDigest({
                directory,
                event: actual.event,
              }),
            });
            archiveSealed = true;
            return Buffer.from(actual.bytes);
          },
          async sealMember(member, bytes) {
            guard(signal);
            requireObservation(
              archiveSealed &&
                members.has(member.path) &&
                same(members.get(member.path), member),
            );
            member = structuredClone(member);
            requireObservation(
              Buffer.isBuffer(bytes) &&
                bytes.length === member.bytes &&
                digest(bytes) === member.sha256,
            );
            bytes = Buffer.from(bytes);
            const file = paths.join(
              entry.directory,
              "content",
              ...member.path.split("/"),
            );
            const request = {
              phase: "package-member",
              ...binding,
              packageId: entry.packageId,
              file,
              member,
            };
            await persist({
              status: "POSSIBLE",
              request,
              requestSha256: observationDigest(request),
            });
            await files.writeProtected({
              file,
              bytes,
              sha256: member.sha256,
              executable: member.executable,
              signal,
            });
            const actual = await observe(
              { ...member, path: file },
              signal,
              true,
            );
            await persist({
              status: "RETIRED",
              request,
              requestSha256: observationDigest(request),
              receiptSha256: observationDigest(actual.event),
            });
          },
          async complete() {
            requireObservation(archiveSealed);
            const request = { phase: "package-publication", ...binding, entry };
            await persist({
              status: "POSSIBLE",
              request,
              requestSha256: observationDigest(request),
            });
            const events = await verifyPackage(entry, signal);
            await persist({
              status: "RETIRED",
              request,
              requestSha256: observationDigest(request),
              receiptSha256: observationDigest(events),
            });
            packages.set(entry.packageId, structuredClone(entry));
          },
        },
      };
    },
    async verifyInputs(request, { signal, preparation } = {}) {
      guard(signal);
      request = structuredClone(request);
      preparation = structuredClone(preparation);
      requireObservation(
        request.candidateSha === job.candidateSha &&
          request.platform === job.platform &&
          same(request.prerequisites, manifest.prerequisites) &&
          same(request.inputs, manifest.inputs) &&
          same(request.tools, manifest.tools) &&
          bootstrapRequest &&
          same(request.bootstrapRequest, bootstrapRequest) &&
          preparation &&
          request.preparationSha256 === observationDigest(preparation),
      );
      const events = [];
      for (const asset of manifest.prerequisites.assets)
        events.push((await observe(asset, signal, true)).event);
      for (const entry of manifest.prerequisites.packages) {
        requireObservation(
          packages.has(entry.packageId) &&
            same(packages.get(entry.packageId), entry),
        );
        events.push(...(await verifyPackage(entry, signal)));
      }
      for (const file of [...manifest.inputs, ...manifest.tools])
        events.push((await observe(file, signal)).event);
      // Read actual compiler/domain settlement through the indexed platform
      // owner. An operator-supplied retirement object cannot authorize admission.
      const module = await import("./prerequisites.js");
      const prepared = { ...structuredClone(preparation), status: "PASS" };
      const platform = await module.createNativeSystemEffects({
        job,
        manifest,
        output: value.buildOutput,
        directory: value.directory,
        preparation: prepared,
      });
      const build = await platform.verifyBuild(prepared, { signal });
      requireObservation(
        build.independent === true &&
          build.settlement?.status === "RETIRED" &&
          build.settlement.independent === true &&
          build.settlement.emergencyCleanup === false,
      );
      return {
        requestSha256: observationDigest(request),
        bootstrapRequestSha256: observationDigest(bootstrapRequest),
        independent: true,
        complete: true,
        held: true,
        protectedParents: true,
        unchanged: true,
        bootstrapRetired: true,
        noLiveMembers: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({ events, build }),
      };
    },
    async read(file, maximum = 134217728) {
      const expected =
        observed.get(file)?.expected ??
        [...manifest.inputs, ...manifest.tools].find(
          (entry) => entry.path === file,
        );
      requireObservation(expected && expected.bytes <= maximum);
      return Buffer.from((await observe(expected)).bytes);
    },
    canRead: (file) =>
      observed.has(file) ||
      [...manifest.inputs, ...manifest.tools].some(
        (entry) => entry.path === file,
      ),
    async recover({ custodyIntent, last }) {
      guard();
      closed = true;
      custodyIntent = structuredClone(custodyIntent);
      const records = [];
      try {
        let pin = structuredClone(last),
          expectedSequence,
          totalBytes = 0;
        while (pin) {
          requireObservation(
            records.length < 65536 &&
              Number.isSafeInteger(pin.bytes) &&
              pin.bytes > 0,
          );
          totalBytes += pin.bytes;
          requireObservation(totalBytes <= 1073741824);
          const receipt = await files.readRecord(pin);
          observationObject(receipt, [
            "schemaVersion",
            "binding",
            "record",
            "previous",
            "sequence",
          ]);
          requireObservation(
            receipt.schemaVersion === 1 &&
              same(receipt.binding, binding) &&
              Number.isSafeInteger(receipt.sequence) &&
              receipt.sequence > 0 &&
              (expectedSequence === undefined ||
                receipt.sequence === expectedSequence),
          );
          records.push(receipt.record);
          expectedSequence = receipt.sequence - 1;
          pin = receipt.previous;
        }
        requireObservation(records.length > 0 && expectedSequence === 0);
      } catch (error) {
        fail(error);
      }
      // Missing acquisition records withhold admission, but must not bypass
      // independent settlement of the separately protected custody request.
      let settlement;
      try {
        settlement = await files.recover(custodyIntent);
      } catch (error) {
        fail(error);
      }
      if (failed) throw firstFailure;
      // Interrupted publication is never promoted to a complete asset/package.
      return {
        status: "RETAINED",
        admitted: false,
        binding,
        records,
        settlement,
      };
    },
    recoveryRecord: () => structuredClone(lastRecord),
    async close() {
      closed = true;
      await persistence.catch(fail);
      let proof;
      try {
        proof = await files.close();
      } catch (error) {
        fail(error);
      }
      if (failed) throw firstFailure;
      return proof;
    },
  };
  return port;
}
