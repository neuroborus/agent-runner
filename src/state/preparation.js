import { createHash, randomUUID } from "node:crypto";
import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { appendDurableLine, readStableText, removeFile } from "./files.js";
import {
  observeJournalDirectory,
  readJournalSegment,
  sameJournalIdentity,
  truncateJournalTail,
} from "./journal-files.js";
import { inspectProcessOwner } from "./process-owner.js";
import { assertRunCanAdvance } from "./stop-policy.js";
import { validStopBoundary } from "./stop-contract.js";
import {
  deepFreeze,
  normalizeExecutionProcess,
  normalizePreparationCustody,
  preparationHeader,
  normalizeRunState,
  RUN_STATE_SCHEMA_VERSION,
  RunStoreError,
} from "./validation.js";

const FILENAME = ".preparation-custody.jsonl";
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_RECORDS = 16;
const digest = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
function invalid() {
  throw new RunStoreError("Preparation custody requires reconciliation.", {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
}

export async function hasPreparationCustody(directory) {
  try {
    await lstat(join(directory, FILENAME));
    return true;
  } catch (cause) {
    if (cause?.code === "ENOENT") return false;
    throw cause;
  }
}

// The only authority here is the already published canonical reservation. This
// bounded log can narrow it and retain process facts, never advance a workflow.
export function createPreparationService({
  runLeases,
  journal,
  loadSnapshot,
  gate,
  timestamp,
  hostName,
  processId,
  processIdentity,
  processIsAlive,
  resolveStopBoundary,
  onBoundary,
}) {
  const authorities = new WeakMap();
  const prefixes = new Map();
  const ownerOptions = { hostName, processIdentity, processIsAlive };
  async function read(directory, reservation, partial = false) {
    if (
      !sameJournalIdentity(
        await observeJournalDirectory(directory),
        reservation.certificate.directory,
      )
    )
      invalid();
    const capture = await readJournalSegment(
      join(directory, FILENAME),
      MAX_BYTES,
    );
    if (capture.observation === null || capture.binding === null)
      throw new RunStoreError("Compact state changed during inspection.", {
        code: "ERR_UNSAFE_STATE_FILE",
      });
    const { source } = capture;
    const prefix = prefixes.get(reservation.id);
    if (prefix !== undefined && !source.startsWith(prefix)) invalid();
    const end = source.lastIndexOf("\n") + 1;
    if (
      end === 0 ||
      (!partial && end !== source.length) ||
      Buffer.byteLength(source.slice(0, end)) !== capture.binding.length ||
      createHash("sha256").update(source.slice(0, end)).digest("hex") !==
        capture.binding.digest
    )
      invalid();
    const records = source
      .slice(0, end)
      .trimEnd()
      .split("\n")
      .map((line) => {
        let record;
        try {
          record = JSON.parse(line);
        } catch {
          invalid();
        }
        if (JSON.stringify(record) !== line) invalid();
        return record;
      });
    const facts = normalizePreparationCustody(records, reservation);
    if (
      !sameJournalIdentity(
        await observeJournalDirectory(directory),
        reservation.certificate.directory,
      )
    )
      invalid();
    // This is live append-only evidence, not an optional history checkpoint.
    // Retain it until settlement, including across failed recovery attempts.
    prefixes.set(reservation.id, source.slice(0, end));
    return {
      ...facts,
      partial: end !== source.length,
      source: source.slice(0, end),
      observation: capture.observation,
    };
  }
  async function append(directory, reservation, log, kind, value) {
    const record = { kind, value, previous: log?.endpoint ?? null };
    normalizePreparationCustody([...(log?.records ?? []), record], reservation);
    const line = JSON.stringify(record);
    if (
      (log?.records.length ?? 0) >= MAX_RECORDS ||
      Buffer.byteLength(log?.source ?? "") + Buffer.byteLength(line) + 1 >
        MAX_BYTES
    )
      invalid();
    const path = join(directory, FILENAME);
    await appendDurableLine(path, line, { stable: true });
    const source = `${log?.source ?? ""}${line}\n`;
    if ((await readStableText(path, MAX_BYTES)) !== source) invalid();
    prefixes.set(log?.records[0].value.id ?? value.id, source);
    await onBoundary({ phase: kind, directory });
  }
  async function publish(directory, snapshot, preparation, kind) {
    const next = normalizeRunState(
      {
        ...snapshot.state,
        // Recovery retains the issued envelope until custody is cleared. The
        // ordinary leased migration can then upgrade without changing authority.
        preparation,
        revision: snapshot.state.revision + 1,
        updatedAt: timestamp(snapshot.state.updatedAt),
      },
      snapshot.state.runId,
    );
    await journal.appendTransition(directory, next, snapshot, {
      actor: "runner",
      phase: "preparation",
      kind,
      message: `Trusted preparation custody ${kind}.`,
    });
    return next;
  }
  async function reserve(lease, bindings) {
    bindings = deepFreeze(structuredClone(bindings));
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      const current = snapshot.state;
      assertRunCanAdvance(current, resolveStopBoundary);
      const trusted = current.pipelineState.trustedValidation;
      if (
        !snapshot.certificate ||
        current.schemaVersion !== RUN_STATE_SCHEMA_VERSION ||
        trusted?.commandFingerprint !== bindings.commandFingerprint ||
        trusted.configurationFingerprint !==
          bindings.configurationFingerprint ||
        !trusted.commands.some(
          (command) => command.identity === bindings.commandIdentity,
        ) ||
        (current.executionResource != null &&
          (current.executionResource.phase !== "allocated" ||
            current.executionResource.commandIdentity !==
              bindings.commandIdentity))
      )
        invalid();
      const candidate =
        typeof resolveStopBoundary === "function"
          ? resolveStopBoundary(deepFreeze(structuredClone(current)))
          : null;
      if (candidate !== null && !validStopBoundary(candidate)) invalid();
      const proposed = {
        id: randomUUID(),
        revision: current.revision + 1,
        owner: structuredClone(record),
        certificate: snapshot.certificate,
        bindings: {
          ...bindings,
          inputFingerprint: digest({
            hashes: current.hashes,
            protection: current.projectConfigurationProtection,
            trusted,
          }),
        },
        resource: current.executionResource,
        targetBoundary: candidate,
        stopRequest: current.stopRequest,
      };
      const reservation = deepFreeze({
        ...proposed,
        digest: digest(proposed),
        settlement: null,
      });
      await publish(runDirectory, snapshot, reservation, "reserved");
      await gate(runDirectory, async () => {
        // A prior log, including an interrupted settlement, cannot be replaced.
        try {
          await readStableText(join(runDirectory, FILENAME), MAX_BYTES);
          invalid();
        } catch (cause) {
          if (cause?.code !== "ENOENT") throw cause;
        }
        await append(
          runDirectory,
          reservation,
          null,
          "reserved",
          preparationHeader(reservation),
        );
      });
      const authority = deepFreeze({ id: reservation.id });
      authorities.set(authority, { reservation, lease });
      return authority;
    });
  }
  async function record(lease, authority, pid, proof, admission) {
    return runLeases.withCurrentOwner(
      lease,
      async ({ record: owner, runDirectory, assertOwner }) => {
        const issuedAuthority = authorities.get(authority);
        if (issuedAuthority?.lease !== lease) invalid();
        const { reservation } = issuedAuthority;
        if (!isDeepStrictEqual(owner, reservation.owner)) invalid();
        return gate(runDirectory, async () => {
          let log = await read(runDirectory, reservation);
          await assertOwner();
          if (pid === null) {
            if (log.process === null) invalid();
            if (!log.retired)
              await append(runDirectory, reservation, log, "retired", null);
            return;
          }
          if (pid === undefined) {
            if (log.process !== null || log.retired) invalid();
            await append(runDirectory, reservation, log, "no-launch", null);
            return;
          }
          if (log.process !== null || log.retired) invalid();
          const process = normalizeExecutionProcess({
            pid,
            hostname: hostName,
            processIdentity: proof?.processIdentity,
            namespaceId: proof.namespaceId,
            launchCutoff: proof.launchCutoff,
            ancestryBaseline: proof.ancestryBaseline,
            controlGroup: proof.controlGroup,
          });
          if (process.processIdentity === null || process.namespaceId === null)
            invalid();
          const assertIdentity = async () => {
            const identity = await processIdentity(pid);
            // A closed release latch retains the captured proof for retirement,
            // even if cancellation already closed the inert supervisor.
            if (
              !isDeepStrictEqual(identity, process.processIdentity) &&
              admission?.canRelease() === true
            )
              invalid();
          };
          await assertIdentity();
          await append(runDirectory, reservation, log, "attached", process);
          log = await read(runDirectory, reservation);
          if (!isDeepStrictEqual(log.process, process)) invalid();
          await assertOwner();
          await assertIdentity();
          const allowed = !log.denied && admission?.canRelease() === true;
          await append(runDirectory, reservation, log, "admitted", allowed);
          const admitted = await read(runDirectory, reservation);
          if (
            admitted.admitted !== allowed ||
            !isDeepStrictEqual(admitted.process, process)
          )
            invalid();
          await assertOwner();
          await assertIdentity();
          // Deadline/cancellation also closes the supervisor's independent latch.
          return allowed && admission.canRelease();
        });
      },
    );
  }
  // Called under canonical stop serialization, before canonical acceptance.
  // Never acquire that serialization from inside this short gate.
  async function revoke(directory, current, request) {
    const reservation = current.preparation;
    if (reservation == null || reservation.settlement !== null) return;
    await gate(directory, async () => {
      const log = await read(directory, reservation);
      if (log.retired) return;
      const disposition = {
        reservationId: reservation.id,
        requestId: request.requestId,
        kind: request.kind,
        expectedRevision: request.expectedRevision,
        acceptedRevision: request.acceptedRevision,
        effectiveTiming: request.effectiveTiming,
        targetBoundary: request.targetBoundary,
      };
      const previous = log.records.find(
        (record) =>
          record.kind === "stop" &&
          record.value.requestId === request.requestId,
      );
      if (previous !== undefined) {
        if (!isDeepStrictEqual(previous.value, disposition)) invalid();
        return;
      }
      await append(directory, reservation, log, "stop", disposition);
    });
  }
  async function settleLocked(directory, snapshot, reservation, log) {
    await journal.verifyCertificate(directory, reservation.certificate);
    if (reservation.settlement === null) {
      if (!log?.retired || log.partial) invalid();
      await publish(
        directory,
        snapshot,
        {
          ...reservation,
          settlement: { endpoint: log.endpoint, records: log.records },
        },
        "settled",
      );
      snapshot = await loadSnapshot(directory, snapshot.state.runId);
      reservation = snapshot.state.preparation;
    }
    if (
      log &&
      (!log.retired ||
        log.partial ||
        log.endpoint !== reservation.settlement.endpoint ||
        !isDeepStrictEqual(log.records, reservation.settlement.records))
    )
      invalid();
    // Retry interrupted state/progress publication before consuming the log.
    snapshot = await journal.recover(directory, snapshot);
    await onBoundary({ phase: "before-removal", directory });
    await gate(directory, async () => {
      let fresh;
      try {
        fresh = await read(directory, reservation);
      } catch (cause) {
        if (cause?.code !== "ENOENT") throw cause;
      }
      if (fresh && fresh.endpoint !== reservation.settlement.endpoint)
        invalid();
      await removeFile(join(directory, FILENAME));
      prefixes.delete(reservation.id);
    });
    await onBoundary({ phase: "removed", directory });
    return deepFreeze(await publish(directory, snapshot, null, "cleared"));
  }
  async function settle(lease) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      const reservation = snapshot.state.preparation;
      if (reservation == null) return deepFreeze(snapshot.state);
      const log = await gate(runDirectory, async () => {
        try {
          return await read(runDirectory, reservation);
        } catch (cause) {
          if (cause?.code !== "ENOENT" || reservation.settlement === null)
            throw cause;
        }
      });
      return settleLocked(runDirectory, snapshot, reservation, log);
    });
  }
  async function inspect(directory, reservation) {
    const log = await read(directory, reservation, true);
    const record = log.process;
    const localIdentity =
      record?.hostname === hostName ? await processIdentity(processId) : null;
    return record === null
      ? null
      : deepFreeze({
          ...record,
          status: await inspectProcessOwner(record, ownerOptions),
          previousBoot:
            record.processIdentity !== null &&
            localIdentity !== null &&
            record.processIdentity.bootId !== localIdentity.bootId,
        });
  }
  async function recover(lease, retire) {
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await journal.recover(
        runDirectory,
        await loadSnapshot(runDirectory, record.runId),
      );
      const reservation = snapshot.state.preparation;
      if (reservation == null) return deepFreeze(snapshot.state);
      await journal.verifyCertificate(runDirectory, reservation.certificate);
      let log = await gate(runDirectory, async () => {
        let captured;
        try {
          captured = await read(runDirectory, reservation, true);
        } catch (cause) {
          if (cause?.code !== "ENOENT" || reservation.settlement === null)
            throw cause;
        }
        if (
          captured &&
          !captured.retired &&
          !captured.partial &&
          !captured.denied
        ) {
          await append(runDirectory, reservation, captured, "revoked", null);
          captured = await read(runDirectory, reservation);
        }
        return captured;
      });
      if (reservation.settlement !== null)
        return settleLocked(runDirectory, snapshot, reservation, log);
      if (!log.retired) {
        if (log.process === null) invalid(); // No invented proof for a lost registration.
        await retire(await inspect(runDirectory, reservation), () =>
          inspect(runDirectory, reservation),
        );
      }
      // Only verified retirement plus the original canonical prefix permits
      // discarding an interrupted final record. Restart never releases.
      log = await gate(runDirectory, async () => {
        const fresh = await read(runDirectory, reservation, true);
        if (!isDeepStrictEqual(fresh.records, log.records)) invalid();
        let observation = fresh.observation;
        if (fresh.partial) {
          observation = await truncateJournalTail(
            join(runDirectory, FILENAME),
            Buffer.byteLength(fresh.source),
            fresh.observation,
          );
        }
        const complete = await read(runDirectory, reservation);
        if (
          !isDeepStrictEqual(complete.observation, observation) ||
          complete.source !== fresh.source
        )
          invalid();
        if (!complete.retired)
          await append(runDirectory, reservation, complete, "retired", null);
        return read(runDirectory, reservation);
      });
      return settleLocked(runDirectory, snapshot, reservation, log);
    });
  }
  return Object.freeze({ reserve, record, revoke, settle, recover });
}
