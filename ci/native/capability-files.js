import { createHash } from "node:crypto";
import { requireObservation } from "./observation.js";
import { createPrerequisiteTransport } from "./prerequisite-transport.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Protected file custody for preparation. Construction is effect-free; only
 * raw filesystem/process/IPC edges, never an owner implementation, are supplied. */
export function createCapabilityFiles(input, options = {}) {
  const owner = createPrerequisiteTransport(input, options);
  let closed = false;
  const guard = (signal) => requireObservation(!closed && !signal?.aborted);
  const readProtected = async ({ file, bytes, sha256, signal }) => {
    guard(signal);
    const actual = await owner.hold(file, { maximum: Math.max(1, bytes) });
    requireObservation(
      actual.file === file &&
        Buffer.isBuffer(actual.bytes) &&
        actual.bytes.length === bytes &&
        digest(actual.bytes) === sha256 &&
        actual.independent === true &&
        actual.held === true &&
        actual.unchanged === true &&
        actual.protectedParents === true &&
        actual.readExecuteOnly === true &&
        actual.identity &&
        actual.event,
    );
    guard(signal);
    return actual;
  };
  return {
    readProtected,
    async provisionDirectory(file, { signal } = {}) {
      guard(signal);
      const proof = await owner.createDirectory(file);
      requireObservation(
        proof.file === file &&
          proof.exclusive === true &&
          proof.birthProtected === true &&
          proof.independent === true &&
          proof.held === true &&
          proof.protectedParents === true,
      );
      guard(signal);
      return proof;
    },
    async directory(file, { signal } = {}) {
      guard(signal);
      const proof = await owner.directory(file);
      requireObservation(
        proof.file === file &&
          proof.independent === true &&
          proof.held === true &&
          proof.protectedParents === true &&
          Array.isArray(proof.names),
      );
      guard(signal);
      return proof;
    },
    async writeProtected({ file, bytes, sha256, executable = false, signal }) {
      guard(signal);
      requireObservation(Buffer.isBuffer(bytes) && digest(bytes) === sha256);
      // The transport publishes the exact creation intent before admitting a
      // writer. It closes that writer before retaining the immutable reader.
      await owner.create(file, Buffer.from(bytes), { executable });
      const actual = await readProtected({
        file,
        bytes: bytes.length,
        sha256,
        signal,
      });
      requireObservation(actual.birthProtected === true);
      return actual;
    },
    persist: (record) => {
      guard();
      return owner.persist(record);
    },
    readRecord: (pin) => {
      guard();
      return owner.readRecord(pin);
    },
    async recover(intent) {
      guard();
      closed = true;
      return owner.recover(intent);
    },
    async close() {
      closed = true;
      const proof = await owner.close();
      requireObservation(
        (proof.status === "CLOSED" && proof.custodianRetired === false) ||
          (proof.status === "RETIRED" &&
            proof.independent === true &&
            proof.noLiveMembers === true &&
            proof.emergencyCleanup === false &&
            (input.job.platform !== "win32" || proof.taskRemoved === true)),
      );
      return structuredClone(proof);
    },
  };
}
