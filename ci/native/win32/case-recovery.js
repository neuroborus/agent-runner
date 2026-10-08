import { observationDigest, requireObservation } from "../index.js";
import { digest, hash } from "./protocol.js";
import { windowsSystemRecipes } from "./system.js";
import { createWindowsPreparationFiles } from "./preparation-files.js";
import { windowsVerificationArguments } from "./custody-protocol.js";

const same = (left, right) =>
  observationDigest(left) === observationDigest(right);
const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;

/** Rejoin the complete case ledger, including a native command whose reply
 * never reached Node. Completion records cannot erase possible effects. */
function cases(state, records) {
  const inventory = new Map();
  for (const { name, record } of records) {
    const match = /^windows-case-([a-z0-9.-]+)-([0-9]+)\.json$/u.exec(name);
    if (!match) continue;
    const id = match[1],
      sequence = Number(match[2]);
    const declared = state.plan.cases.find((entry) => entry.id === id);
    const recipe = windowsSystemRecipes().find((entry) => entry.id === id);
    requireObservation(
      declared &&
        recipe &&
        recipe.id !== "build" &&
        name === `windows-case-${id}-${sequence}.json` &&
        sequence <= 65535 &&
        same(record.context, declared.custody.context),
    );
    const group = inventory.get(id) ?? { declared, recipe, records: [] };
    group.records.push({ sequence, record });
    inventory.set(id, group);
  }
  for (const group of inventory.values()) {
    group.records.sort((left, right) => left.sequence - right.sequence);
    requireObservation(
      group.records.every(({ sequence }, index) => sequence === index),
    );
    const first = group.records[0].record;
    requireObservation(
      first.phase === "provisioning-possible" &&
        first.status === "POSSIBLE" &&
        hash(first.templateSha256) &&
        first.bindingsSha256 === observationDigest(group.declared.bindings),
    );
    const custody = group.records
      .filter(({ record }) => record.phase === "custody")
      .map(({ record }) => record.record);
    requireObservation(
      custody.every(
        (record, index) =>
          record.sequence === index &&
          same(record.context, group.declared.custody.context) &&
          record.nonce === group.declared.custody.nonce &&
          record.requestSha256 === observationDigest(group.declared.custody) &&
          record.reviewSha256 === group.declared.custody.reviewSha256,
      ),
    );
    group.custody = custody;
  }
  return inventory;
}

// A fresh observer uses only approved bootstrap bytes. No final image is
// opened, no payload is launched and a saved settlement is never new proof.
async function observeCase(state, options, group, signal) {
  const input = {
    ...state,
    manifest: {
      ...state.manifest,
      windowsPreparation: { ...state.plan, bootstrap: group.declared.custody },
    },
    signal,
    recoverySequence: group.recoverySequence,
  };
  const files = createWindowsPreparationFiles(input, options);
  let result, failure;
  try {
    result = await files.verify(
      "recoverCase",
      group.declared.custody,
      group.custody,
      group.observers,
      group.records.find(
        ({ record }) => record.phase === "provisioning-observed",
      )?.record.actual?.objects ?? [],
      group.records.map(({ record }) => record),
    );
    requireObservation(
      retired(result) && result.noLiveMembers && result.taskRemoved,
    );
  } catch (cause) {
    failure = cause;
  }
  try {
    const settlement = await files.settleFiles();
    requireObservation(
      retired(settlement) && settlement.noLiveMembers && settlement.taskRemoved,
    );
  } catch (cause) {
    failure ??= cause;
  }
  if (failure) throw failure;
  return result;
}

/** Recovery fences the shared admission owner first, then independently tries
 * every case. One missing proof retains exclusion without hiding another
 * owner's cleanup or the first cause. */
export async function recoverWindowsCases(
  state,
  options,
  records,
  active,
  finish,
  provisioning,
  signal,
) {
  requireObservation(signal instanceof AbortSignal && !signal.aborted);
  const results = [];
  let failure;
  const pending = [...active.values()].some((current) => !current.retired);
  // Safe retained owners know their original bindings even when a protected
  // record has become unreadable. Attempt every owner before parsing evidence.
  for (const current of active.values()) {
    try {
      if (!current.retired) {
        const result =
          current.repositoryProvisioning && !current.caseEffectsPossible
            ? await provisioning.retire(current, { signal, closeFiles: false })
            : await finish(current, { signal, closeFiles: false });
        requireObservation(retired(result));
        current.retired = true;
      }
    } catch (cause) {
      failure ??= cause;
    }
  }
  let inventory;
  try {
    if (pending) records = (await readWindowsRecoveryRecords(state)).records;
    inventory = cases(state, records);
    validateObservers(state, records);
  } catch (cause) {
    throw failure ?? cause;
  }
  for (const [id, group] of inventory) {
    group.recoverySequence = records.length;
    group.observers = records.filter(
      ({ name, record }) =>
        name.startsWith("windows-files-") &&
        record.phase === undefined &&
        record.argumentsHex?.[4] ===
          Buffer.from(group.declared.custody.plan.path, "utf16le").toString(
            "hex",
          ),
    );
    group.observers = group.observers.map(({ name }) => {
      const prefix = name.slice(0, -"intent.json".length);
      return {
        intent: records.find((entry) => entry.name === name).record,
        birth: records.find((entry) => entry.name === prefix + "birth.json")
          ?.record,
      };
    });
    try {
      // Also read a finished owner independently. An old RETIRED receipt, an
      // absent task or a fixture exit code alone is never settlement evidence.
      results.push(await observeCase(state, options, group, signal));
    } catch (cause) {
      failure ??= cause;
    }
  }
  try {
    requireObservation([...active.keys()].every((id) => inventory.has(id)));
  } catch (cause) {
    failure ??= cause;
  }
  if (failure) throw failure;
  return {
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    nativeEventSha256: observationDigest(results),
    casesSha256: observationDigest(
      [...inventory].map(([id, group]) => ({ id, records: group.records })),
    ),
  };
}

export async function readWindowsRecoveryRecords(state) {
  const entries = await state.fs.readdir(state.directory);
  requireObservation(entries.length <= 65536);
  const names = entries
    .filter((name) =>
      /^windows-(?:files-[a-f0-9]{32}-(?:intent|birth|result|[0-9]+)|bootstrap-[0-9]+-(?:intent|result|custody-[0-9]+)|command-[a-f0-9]{64}(?:-intent|-result|-[0-9]+)|case-[a-z0-9.-]+-[0-9]+|recovery-[a-f0-9]{64}-[0-9]+-(?:intent|result))\.json$/u.test(
        name,
      ),
    )
    .sort();
  requireObservation(
    entries.filter((name) => name.startsWith("windows-")).length ===
      names.length,
  );
  const records = [];
  let total = 0;
  for (let offset = 0; offset < names.length; offset += 16) {
    const group = names.slice(offset, offset + 16),
      batch = await state.receipts(group);
    requireObservation(batch.length === group.length);
    for (const [index, name] of group.entries()) {
      const bytes = batch[index];
      const record = JSON.parse(bytes);
      requireObservation(
        record && Object.getPrototypeOf(record) === Object.prototype,
      );
      // Native upload journals repeat the already protected adapter receipt in
      // hex. Retain its complete byte/frame digests and fixed command header;
      // that duplicated transport payload supplies no additional owner intent.
      if (
        /^windows-files-[a-f0-9]{32}-[0-9]+\.json$/u.test(name) &&
        typeof record.commandHex === "string"
      ) {
        const frame = Buffer.from(record.commandHex, "hex").toString("ascii"),
          chunk =
            /^prepare-chunk ([1-9][0-9]*) ([0-9]+) ([a-f0-9]{2,65536})$/u.exec(
              frame,
            );
        if (chunk) {
          requireObservation(
            /^(?:[a-f0-9]{2})+$/u.test(record.commandHex) &&
              chunk[3].length % 2 === 0,
          );
          record.sourceSha256 = digest(bytes);
          record.commandSha256 = digest(Buffer.from(frame));
          record.commandHex = Buffer.from(
            `prepare-chunk ${chunk[1]} ${chunk[2]}`,
          ).toString("hex");
        }
      }
      total += Buffer.byteLength(JSON.stringify(record));
      requireObservation(total <= 67108864);
      records.push({ name, record });
    }
  }
  const history = records.filter(({ name }) =>
    name.startsWith("windows-recovery-"),
  );
  const intents = history.filter(({ name }) => name.endsWith("-intent.json"));
  const sequences = intents
    .map(({ name }) => Number(/-([0-9]+)-intent\.json$/u.exec(name)[1]))
    .sort((a, b) => a - b);
  requireObservation(sequences.every((sequence, index) => sequence === index));
  for (const { name, record } of intents) {
    requireObservation(
      record.status === "POSSIBLE" &&
        record.request &&
        record.request.candidateSha === state.job.candidateSha &&
        record.request.platform === "win32" &&
        record.request.jobSha256 === observationDigest(state.job) &&
        name.startsWith(
          `windows-recovery-${observationDigest(record.request)}-`,
        ),
    );
    const result = history.find(
      (entry) => entry.name === name.replace(/intent\.json$/u, "result.json"),
    );
    if (result)
      requireObservation(
        result.record.requestSha256 === observationDigest(record.request),
      );
  }
  requireObservation(
    history
      .filter(({ name }) => name.endsWith("-result.json"))
      .every(({ name }) =>
        intents.some(
          (entry) =>
            entry.name === name.replace(/result\.json$/u, "intent.json"),
        ),
      ),
  );
  return { entries, records };
}

function validateObservers(state, records) {
  const byName = new Map(records.map(({ name, record }) => [name, record]));
  const plans = [
    state.plan.bootstrap,
    ...state.plan.cases.map(({ custody }) => custody),
  ];
  const observers = records.filter(({ name }) =>
    /^windows-files-[a-f0-9]{32}-intent\.json$/u.test(name),
  );
  for (const { name, record: intent } of observers) {
    const prefix = name.slice(0, -"intent.json".length),
      birth = byName.get(prefix + "birth.json"),
      plan = plans.find(
        (entry) =>
          intent.argumentsHex?.[4] ===
          Buffer.from(entry.plan.path, "utf16le").toString("hex"),
      );
    requireObservation(
      plan &&
        birth?.schemaVersion === 1 &&
        birth.status === "POSSIBLE" &&
        prefix === `windows-files-${birth.nonce}-` &&
        hash(birth.taskSha256),
    );
    const expected = [
      "--observe",
      plan.reader.path,
      plan.reader.sha256,
      plan.reader.signatureSha256,
      plan.plan.path,
      plan.plan.sha256,
      birth.nonce,
      plan.runnerSid,
      state.directory,
      state.output,
    ].map((value) => Buffer.from(value, "utf16le").toString("hex"));
    requireObservation(
      intent.schemaVersion === 1 &&
        intent.status === "POSSIBLE" &&
        same(intent.argumentsHex, expected),
    );
    const journal = [];
    for (const { name: leaf, record } of records.filter((entry) =>
      entry.name.startsWith(prefix),
    )) {
      if (leaf === name || leaf === prefix + "birth.json") continue;
      if (leaf === prefix + "result.json") {
        requireObservation(
          record.status === "RETIRED" &&
            record.schemaVersion === 1 &&
            record.nonce === birth.nonce &&
            record.taskSha256 === birth.taskSha256 &&
            same(record.helper, birth.helper) &&
            same(record.bridge, birth.bridge),
        );
        continue;
      }
      const match = /-([0-9]+)\.json$/u.exec(leaf);
      requireObservation(
        match &&
          record.schemaVersion === 1 &&
          record.candidateSha === state.job.candidateSha,
      );
      requireObservation(
        record.nonce === birth.nonce && same(record.helper, birth.helper),
      );
      requireObservation(
        typeof record.commandHex === "string" &&
          /^(?:[a-f0-9]{2}){1,262144}$/u.test(record.commandHex),
      );
      const frame = Buffer.from(record.commandHex, "hex").toString("ascii"),
        command =
          /^(prepare-(?:directory|list|read|bytes|release|write|chunk|seal|batch)|verify-[a-z-]+|finish) ([1-9][0-9]*)(?: [a-z0-9-]+)*$/u.exec(
            frame,
          );
      const sequence = Number(match[1]);
      requireObservation(
        command &&
          sequence === Number(command[2]) &&
          sequence <= 32768 &&
          leaf === prefix + sequence + ".json",
      );
      if (command[1].startsWith("verify-"))
        windowsVerificationArguments(
          command[1].slice(7),
          frame.split(" ").slice(2),
        );
      journal.push(sequence);
    }
    journal.sort((a, b) => a - b);
    requireObservation(
      journal.length > 0 &&
        journal.every((sequence, index) => sequence === index + 1),
    );
  }
  requireObservation(
    records
      .filter(({ name }) => name.startsWith("windows-files-"))
      .every(({ name }) =>
        observers.some((entry) =>
          name.startsWith(entry.name.slice(0, -"intent.json".length)),
        ),
      ),
  );
}
