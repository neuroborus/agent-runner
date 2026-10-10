import path from "node:path";
import {
  observationDigest,
  observationObject,
  requireObservation,
  recoverPrerequisiteTransport,
  nativeCIJobBinding,
} from "../index.js";
import { digest, sameDarwinIdentity } from "./protocol.js";
import { darwinSystemRecipes } from "./system.js";
import { recoverDarwinBuild } from "./preparation.js";
import { createDarwinCaseEffects } from "./case-effects.js";
import {
  createDarwinOperationEffects,
  darwinOperationPreparation,
} from "./case-operations.js";
import { darwinAccessPreparation } from "./access-effects.js";
import { createDarwinAuditDecoder } from "./audit.js";
import { buildDarwinPolicy } from "./policy.js";
import {
  createDarwinPfPreparation,
  normalizeDarwinPfRead,
  assertDarwinPfRoot,
} from "./pf-preparation.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);

const operationPhases = [
  "operation-authority",
  "slots-closed",
  "file-view",
  "file-probe-start",
  "file-probe-finish",
  "file-publishers-start",
  "file-publishers-ack",
  "file-publishers-finish",
  "file-reader-start",
  "file-reader-read",
  "file-reader-finish",
  "file-control-start",
  "file-control-read",
  "file-control-restore",
  "file-control-rejoin",
  "file-volume-start",
  "file-volume-worker",
  "file-volume-run",
  "file-volume-finish",
  "file-name",
  "file-read",
  "file-send",
  "file-close",
  "file-admitted",
  "transfer",
  "transfer-recovery",
  "file-send-recovery",
  "git-start",
  "git-event",
  "git-send",
  "git-close",
  "git-object",
  "git-ordinary-start",
  "git-ordinary-release",
  "git-ordinary-finish",
  "case-resume",
  "root-domain",
  "root-retired",
  "signature",
  "macho",
  "cache",
  "build",
  "location",
  "tree",
  "barrier",
  "read",
  "session",
  "process",
  "authority",
  "case-receipt",
  "case-receipt-read",
  "case-receipt-optional",
  "case-session",
  "access-audit-start",
  "access-audit",
  "access-audit-close",
  "bsm",
];

const operationBirths = new Map([
  ["file-probe-start", ["probe-admitted", 1]],
  ["file-publishers-start", ["birth", 3]],
  ["file-reader-start", ["birth", 1]],
  ["file-volume-start", ["birth", 1]],
  ["file-volume-worker", ["birth", 1]],
  ["git-start", ["birth", 1]],
  ["git-ordinary-start", ["birth", 1]],
  ["access-audit-start", ["birth", 1]],
  ["transfer", ["file-admitted", 1]],
  ["transfer-recovery", ["file-admitted", 1]],
]);

function joinOperationBirths(entries, history) {
  const receipts = new Map(
    history.map(({ pin, record }) => [pin.index, record]),
  );
  let kind,
    required = 0,
    identities = [];
  const complete = () => requireObservation(identities.length >= required);
  for (const { record } of entries) {
    if (record.phase === "custody") {
      const phase = record.record.phase;
      if (phase === "entry" || operationBirths.has(phase)) {
        // A later owner or start cannot supply an earlier missing birth.
        complete();
        [kind, required] = operationBirths.get(phase) ?? [null, 0];
        identities = [];
      }
    } else if (record.phase === "operation-receipt" && kind) {
      const value = receipts.get(record.pin.index);
      if (value.kind === kind) {
        const identity = value.identity ?? value.admission?.helper;
        requireObservation(identity);
        if (!identities.some((known) => sameDarwinIdentity(known, identity)))
          identities.push(identity);
      }
    }
  }
  complete();
}

export async function recoverDarwinCases(state, options, records, { signal }) {
  if (!records.length) return [];
  const reads = [],
    failures = [];
  for (const declared of state.plan.cases) {
    const prefix = `darwin-case-${declared.id}-`,
      entries = records
        .filter(({ name }) => name.startsWith(prefix))
        .sort(
          (a, b) =>
            Number(a.name.slice(prefix.length, -5)) -
            Number(b.name.slice(prefix.length, -5)),
        );
    if (!entries.length) continue;
    try {
      requireObservation(
        entries.every(({ name }, i) => name === `${prefix}${i}.json`),
      );
      const intent = entries[0].record;
      requireObservation(
        intent.phase === "provisioning-possible" &&
          intent.status === "POSSIBLE" &&
          same(intent.context, declared.custody.context) &&
          intent.bindingsSha256 === observationDigest(declared.bindings) &&
          intent.planSha256 === declared.custody.plan.sha256 &&
          hash(intent.templateSha256),
      );
      const operation = Object.hasOwn(declared.bindings, "operations");
      const access = declared.id.startsWith("access.");
      const ownership = entries.some(({ record }) =>
        ["ownership-receipt", "ownership-receipt-possible"].includes(
          record.phase,
        ),
      );
      requireObservation(
        !ownership || access || declared.id.startsWith("ownership."),
      );
      requireObservation(
        entries
          .slice(1)
          .every(({ record }) =>
            [
              "custody",
              "provisioned",
              "provisioning-retired",
              ...(operation
                ? [
                    "operation-receipt-possible",
                    "operation-receipt",
                    "operation-retired",
                    "owner-receipt",
                  ]
                : []),
              ...(access ? ["access-retired", "access-audit-frame"] : []),
              ...(ownership
                ? [
                    "reader-admitted",
                    "ownership-outside",
                    "ownership-receipt-possible",
                    "ownership-receipt",
                    "ownership-failure",
                    "ownership-retired",
                    "owner-receipt",
                  ]
                : []),
            ].includes(record.phase),
          ),
      );
      const custody = entries
        .filter(({ record }) => record.phase === "custody")
        .map(({ record }) => record.record);
      const allowed = new Set([
        ...(operation || access ? operationPhases : []),
        ...(access
          ? [
              "socket",
              "ipc",
              "pf-read",
              "pf-write",
              "pf-recover",
              "access-counters",
              "access-payload-sockets",
              "access-sockets",
              "access-pf-start",
              "access-pf-worker",
              "access-pf-run",
              "access-provision",
              "access-target",
              "access-attempt",
              "access-run",
              "access-peer",
              "access-complete",
              "access-controls-close",
              "access-controls-retired",
              "reservation",
              "reservation-close",
            ]
          : []),
        "entry",
        "admitted",
        "probe-intent",
        "probe-created",
        "probe-retired",
        "open",
        "reserve",
        "case-directory",
        "case-copy",
        "case-object",
        "inspect",
        "case-endpoint",
        "case-endpoint-bound",
        "case-read",
        "cleanup",
        "case-retire",
        "close",
        "finish",
        "retired",
        "case-rejoin",
        ...(ownership
          ? [
              "case-start",
              "case-eof",
              "authority",
              "case-control",
              "case-send",
              "case-output",
              "case-subject",
              "case-session",
              "case-members",
              "case-empty",
              "case-signal",
              "case-receipt",
              "case-receipt-read",
              "case-receipt-optional",
              "tree",
              "barrier",
              "read",
              "session",
              "process",
            ]
          : []),
      ]);
      let custodySequence = -1;
      requireObservation(
        custody.every(
          (record) =>
            record.sequence ===
              (record.phase === "entry"
                ? (custodySequence = 0)
                : ++custodySequence) &&
            allowed.has(record.phase) &&
            same(record.context, declared.custody.context) &&
            record.reviewSha256 === declared.custody.reviewSha256 &&
            record.requestSha256 === digest(JSON.stringify(record.request)),
        ),
      );
      const admitted = custody.filter((record) => record.phase === "admitted"),
        launch = custody.filter((record) => record.phase === "entry");
      requireObservation(
        admitted.length > 0 &&
          admitted.length === launch.length &&
          launch.every(
            (record) =>
              record.request.readerSha256 === declared.custody.reader.sha256 &&
              record.request.planSha256 === declared.custody.plan.sha256,
          ) &&
          admitted.every((record) => same(record.subjects, record.request)),
      );
      const subjects = admitted.flatMap(({ subjects }) => [
        subjects.helper,
        subjects.verifier,
      ]);
      for (let i = 0; i < custody.length; i++)
        if (custody[i].phase === "probe-intent") {
          const intent = custody[i],
            born = custody[i + 1];
          requireObservation(
            born?.phase === "probe-created" &&
              born.request.pid === intent.request.pid &&
              born.sequence === intent.sequence + 1,
          );
          subjects.push(born.request.verifier);
        }
      const objects = custody.filter(
        (record) => record.phase === "case-object",
      );
      for (const intent of custody.filter((record) =>
        ["case-directory", "case-copy"].includes(record.phase),
      ))
        requireObservation(
          objects.filter(
            (record) => record.request.index === intent.request.arguments[0],
          ).length === 1,
        );
      let sequence = entries.length;
      const native = state.createReader(declared.custody, {
        ...options.readerOptions,
        caseContextSha256: observationDigest(declared.custody.context),
        persist: (record) =>
          state.write(`${prefix}${sequence++}.json`, {
            phase: "custody",
            record,
          }),
      });
      const lifetime = operation || access ? new AbortController() : null;
      const admission = await native.start({
        signal: lifetime
          ? AbortSignal.any([lifetime.signal, ...(signal ? [signal] : [])])
          : signal,
      });
      for (const subject of subjects) reads.push(await native.retired(subject));
      if (access || operation)
        for (const record of admitted)
          reads.push(await native.retiredRootDomain(record.subjects.helper));
      let recovered;
      if (operation) {
        const possible = entries.filter(
          ({ record }) => record.phase === "operation-receipt-possible",
        );
        const receipts = entries.filter(
          ({ record }) => record.phase === "operation-receipt",
        );
        requireObservation(
          possible.length === receipts.length &&
            possible.every(
              ({ record }, i) =>
                record.pin.index === i &&
                same(record.pin, receipts[i].record.pin),
            ),
        );
        const history = [];
        for (const { record } of possible) {
          const bytes = await native.ownershipReceipt(
            record.pin.index,
            record.pin.sha256,
          );
          const value = JSON.parse(bytes);
          requireObservation(
            bytes.equals(Buffer.from(JSON.stringify(value) + "\n")) &&
              digest(bytes) === record.pin.sha256,
          );
          history.push({ pin: record.pin, record: value });
        }
        joinOperationBirths(entries, history);
        const known = history.flatMap(({ record }) =>
          record.identity
            ? [record.identity]
            : record.payload
              ? [record.payload]
              : record.admission?.helper
                ? [record.admission.helper]
                : [],
        );
        const domains = custody
          .filter((record) => record.phase === "root-domain")
          .map((record) =>
            known.find(
              (identity) =>
                identity.pid === record.request.arguments[0] &&
                identity.asid === record.request.arguments[1] &&
                identity.pidVersion === record.request.arguments[2],
            ),
          );
        requireObservation(domains.every(Boolean));
        for (const identity of known)
          if (
            identity.uid === 0 &&
            identity.auid === 0 &&
            identity.asid > 0 &&
            !domains.some((domain) => domain.asid === identity.asid)
          )
            domains.push(identity);
        for (const identity of known)
          reads.push(
            await native.retired(identity, {
              reserved: identity.uid !== 0,
            }),
          );
        for (const identity of domains)
          reads.push(await native.retiredRootDomain(identity));
        recovered = {
          history,
          pins: possible.map(({ record }) => record.pin),
          receiptIndex: possible.length,
          subjects: known,
          domains,
        };
      }
      if (ownership) {
        const possible = entries.filter(
            ({ record }) => record.phase === "ownership-receipt-possible",
          ),
          receipts = entries.filter(
            ({ record }) => record.phase === "ownership-receipt",
          );
        for (const { record } of [...possible, ...receipts]) {
          observationObject(record, ["phase", "kind", "pin"]);
          observationObject(record.pin, ["index", "sha256"]);
          requireObservation(
            hash(record.pin.sha256) &&
              [
                "admission",
                "members",
                "retirement",
                "owner",
                "fault",
                ...(access
                  ? [
                      "pf-prerequisite",
                      "access-policy",
                      "pf-helper",
                      "access-attempt",
                      "audit-possible",
                      "audit-closed",
                      "audit-retired",
                      "access-restored",
                      "access-owner",
                      "access-observation",
                    ]
                  : []),
              ].includes(record.kind),
          );
        }
        requireObservation(
          (access || possible.length === receipts.length) &&
            possible.every(({ record }, i) => record.pin.index === i) &&
            receipts.every(({ record }) =>
              possible.some(
                (entry) =>
                  same(entry.record.pin, record.pin) &&
                  entry.record.kind === record.kind,
              ),
            ),
        );
        requireObservation(
          new Set(receipts.map(({ record }) => record.pin.index)).size ===
            receipts.length,
        );
        const latest = possible
            .filter(({ record }) => record.kind === "admission")
            .at(-1)?.record.pin,
          snapshots = entries.filter(
            ({ record }) => record.phase === "ownership-outside",
          );
        requireObservation(
          (access || latest) &&
            (access || (snapshots.length === 1 && objects.length === 7)),
        );
        const history = [];
        for (const { record } of possible) {
          const bytes = await native.recoverOwnershipReceipt(
            record.pin.index,
            record.pin.sha256,
          );
          if (bytes === null) {
            requireObservation(
              access &&
                record.kind !== "admission" &&
                !receipts.some((entry) => same(entry.record.pin, record.pin)),
            );
            continue;
          }
          const value = JSON.parse(bytes);
          requireObservation(
            bytes.equals(Buffer.from(JSON.stringify(value) + "\n")) &&
              digest(bytes) === record.pin.sha256,
          );
          history.push({
            kind: record.kind,
            pin: record.pin,
            record: value,
          });
        }
        const admitted = history.find(
          ({ pin }) => pin.index === latest?.index,
        )?.record;
        if (latest) {
          requireObservation(
            admitted.candidateSha === state.job.candidateSha &&
              admitted.nonce ===
                observationDigest(declared.custody.context).slice(0, 32),
          );
        }
        const members = admitted?.payload ? [admitted.payload] : [];
        for (const { record } of receipts.filter(({ record }) =>
          ["members", "retirement"].includes(record.kind),
        )) {
          const bytes = await native.ownershipReceipt(
              record.pin.index,
              record.pin.sha256,
            ),
            ledger = JSON.parse(bytes);
          requireObservation(
            bytes.equals(Buffer.from(JSON.stringify(ledger) + "\n")) &&
              ledger.requestSha256 === admitted?.requestSha256,
          );
          for (const identity of ledger.members ?? [])
            if (!members.some((known) => sameDarwinIdentity(known, identity)))
              members.push(identity);
        }
        recovered = {
          admitted,
          members,
          pin: latest,
          receiptIndex: possible.length,
          outside: snapshots[0]?.record.snapshot,
          history,
        };
      }
      await native.open(10);
      await native.reserve(
        10,
        observationDigest(declared.custody.context).slice(0, 32),
      );
      const rawPlan = (
        await state.read(
          declared.custody.plan.path,
          declared.custody.plan.sha256,
        )
      )
        .toString()
        .trim()
        .split("\n")
        .slice(1)
        .map((line) => {
          const [kind, pin, encoded] = line.split(" ");
          return {
            kind,
            sha256: pin === "-" ? null : pin,
            path: Buffer.from(encoded, "hex").toString(),
          };
        });
      for (const { request } of objects
        .filter(
          (record) =>
            !operation ||
            !(
              rawPlan[record.request.index].kind === "data" &&
              (rawPlan[record.request.index].path.startsWith(
                (declared.bindings.input.metadata ?? "//") + "/",
              ) ||
                rawPlan[record.request.index].path.includes(
                  "/storage/control/",
                ))
            ),
        )
        .sort((a, b) => a.request.index - b.request.index))
        requireObservation(
          same(await native.rejoinCaseObject(request.index), request.object),
        );
      if (operation) {
        const provisionedRecord = entries.find(
          ({ record }) => record.phase === "provisioned",
        );
        requireObservation(provisionedRecord);
        const binding = {
          context: declared.custody.context,
          template: {},
          approval: {},
        };
        const specification = await darwinOperationPreparation(
          state,
          declared.bindings,
          binding,
          rawPlan.slice(0, 12),
          declared.id,
        );
        requireObservation(
          same(
            specification.entries.map(({ kind, path, sha256 }) => ({
              kind,
              path,
              sha256,
            })),
            rawPlan.map(({ kind, path, sha256 }) => ({
              kind,
              path,
              sha256,
            })),
          ),
        );
        const copied = new Set(objects.map(({ request }) => request.index));
        for (let i = 7; i < rawPlan.length; i++)
          if (i !== 10 && i !== 11 && !copied.has(i)) await native.open(i);
        const input = structuredClone(declared.bindings.input);
        if (declared.id.startsWith("files.")) {
          input.base = (
            await native.inspect(specification.slots.base)
          ).identity;
          input.root = (
            await native.inspect(specification.slots.root)
          ).identity;
        }
        const current = {
          reader: native,
          declared,
          recipe: darwinSystemRecipes().find(({ id }) => id === declared.id),
          input,
          signal,
          binding,
          admission,
          provisioned: {
            operations: specification,
            provisioning: provisionedRecord.record.provisioning,
          },
        };
        lifetime.abort();
        reads.push(
          await createDarwinOperationEffects(
            state,
            current,
            (id, record) => state.write(`${prefix}${sequence++}.json`, record),
            recovered,
          ).finish({ signal: signal ?? new AbortController().signal }),
        );
        continue;
      }
      if (access) {
        const binding = { context: declared.custody.context };
        const specification = await darwinAccessPreparation(
          state,
          declared.bindings,
          binding,
          rawPlan.slice(0, 12),
        );
        const entriesOf = (list) =>
          list.map(({ kind, path, sha256 }) => ({ kind, path, sha256 }));
        requireObservation(
          same(entriesOf(specification.entries), entriesOf(rawPlan)),
        );
        const copied = new Set(objects.map(({ request }) => request.index));
        for (let i = 7; i < rawPlan.length; i++)
          if (i !== 10 && i !== 11 && !copied.has(i)) {
            if (rawPlan[i].path === declared.bindings.input.pointer) {
              if (custody.some((record) => record.phase === "access-provision"))
                await native.rejoinCaseObject(i);
            } else await native.open(i);
          }
        lifetime.abort();
        const current = {
          reader: native,
          declared,
          recipe: darwinSystemRecipes().find(({ id }) => id === declared.id),
          input: declared.bindings.input,
          signal,
          binding,
          admission,
          provisioned: { access: specification },
        };
        reads.push(
          await recoverDarwinAccess(
            state,
            current,
            (id, record) => state.write(`${prefix}${sequence++}.json`, record),
            recovered ?? { history: [], members: [], receiptIndex: 0 },
            custody,
            entries,
          ),
        );
        continue;
      }
      if (ownership) {
        for (let i = 7; i <= 9; i++) await native.open(i);
        const current = {
          reader: native,
          declared,
          recipe: { id: declared.id },
          input: declared.bindings.input,
          provisioned: {},
          binding: {},
          admission,
        };
        reads.push(
          await createDarwinCaseEffects(
            state,
            current,
            (id, record) => state.write(`${prefix}${sequence++}.json`, record),
            recovered,
          ).recover(),
        );
        continue;
      }
      reads.push(await native.retireCase());
      const closed = await native.close();
      requireObservation(
        closed.status === "RETIRED" && closed.independent && closed.closed,
      );
      reads.push(closed);
    } catch (cause) {
      // Closure belongs to the family owner after complete proof. A failed
      // join retains exclusion without a generic retirement fallback.
      failures.push(cause);
    }
  }
  requireObservation(
    records.every(({ name }) =>
      state.plan.cases.some(({ id }) => name.startsWith(`darwin-case-${id}-`)),
    ),
  );
  if (failures.length) throw failures[0];
  return reads;
}

async function recoverDarwinAccess(
  state,
  current,
  save,
  recovered,
  custody,
  entries,
) {
  const { reader, binding, provisioned, recipe } = current,
    specification = provisioned.access,
    plan = buildDarwinPolicy(current.input),
    { request } = plan.value,
    history = recovered.history,
    owner = createDarwinCaseEffects(state, current, save, {
      ...recovered,
      accessRetired: true,
    }),
    values = (kind) =>
      history
        .filter((entry) => entry.kind === kind)
        .map((entry) => entry.record);
  await reader.beginCleanup({
    signal: current.signal ?? new AbortController().signal,
  });
  let retirement;
  if (recovered.admitted) retirement = await owner.custody.retire();
  else {
    requireObservation(
      !custody.some((record) => record.phase === "case-start"),
    );
    await reader.emptyOwnership();
    const actual = await reader.verifyOwnership(0);
    requireObservation(
      actual.enumeration.live.length === 0 &&
        actual.enumeration.zombies.length === 0,
    );
    retirement = {
      status: "RETIRED",
      independent: true,
      domain: { uid: request.uid, gid: request.gid, asid: null },
      freshVerifier: actual.verifier,
      nativeEventSha256: observationDigest(actual),
    };
  }
  // Absence of a pipe owner cannot substitute for a drained, loss-free audit.
  const observers = values("audit-possible"),
    closed = values("audit-closed");
  requireObservation(
    custody.filter((record) => record.phase === "access-audit-start").length ===
      observers.length && observers.length <= 1,
  );
  if (observers.length) {
    requireObservation(
      closed.length === 1 && same(closed[0].observer, observers[0].observer),
    );
    const decoder = createDarwinAuditDecoder(
      reader,
      specification.audit.mapping,
    );
    const frames = entries
      .filter(({ record }) => record.phase === "access-audit-frame")
      .map(({ record: { phase, ...frame } }) => frame);
    requireObservation(observationDigest(frames) === closed[0].framesSha256);
    for (const frame of frames) {
      observationObject(frame, ["observer", "command", "hex"]);
      requireObservation(
        same(frame.observer, observers[0].observer) &&
          ["A", "B", "S"].includes(frame.command) &&
          /^(?:[a-f0-9]{2})+$/u.test(frame.hex),
      );
      await decoder.push(Buffer.from(frame.hex, "hex"));
    }
    const health = decoder.finish(closed[0].completion);
    requireObservation(health.health.complete);
    await reader.retired(observers[0].observer);
  }
  const pfHelpers = values("pf-helper"),
    starts = custody.filter((record) => record.phase === "access-pf-start");
  requireObservation(
    starts.length ===
      pfHelpers.filter((record) => record.worker === null).length,
  );
  for (const record of pfHelpers) {
    await reader.retired(record.helper);
    if (record.worker) await reader.retired(record.worker);
    await reader.retiredRootDomain(record.helper);
  }
  // No creation, unlink or adoption is allowed during a fresh IPC census.
  const bank = specification.entries.findIndex(
    ({ path }) => path === request.custody + "/access-cases",
  );
  const controls = await reader.access("controls-retired", bank);
  observationObject(controls, ["absent"]);
  requireObservation(controls.absent === true);
  const verifyRetirement = async () => {
    const actual = await reader.verifyOwnership(retirement.domain.asid ?? 0);
    requireObservation(
      actual.enumeration.live.length === 0 &&
        actual.enumeration.zombies.length === 0 &&
        actual.verifier.pid !== current.admission.helper.pid,
    );
    return true;
  };
  await verifyRetirement();
  const actual = normalizeDarwinPfRead(await reader.pf()),
    anchor =
      actual.graph.find(({ anchor }) => anchor === plan.anchor)?.rules ?? [];
  requireObservation(
    actual.states === 0 &&
      actual.graph.every(
        (entry) =>
          entry.anchor === "" ||
          entry.anchor === plan.anchor ||
          entry.rules.length === 0,
      ),
  );
  if (anchor.length) {
    assertDarwinPfRoot(actual, specification.pf.approval.installedRootSha256);
    requireObservation(
      digest(JSON.stringify(anchor)) === specification.pf.anchorRulesSha256,
    );
    for (const operation of ["validate-restore", "restore"]) {
      const helper = (
        await reader.access(
          "pf-start",
          specification.pf.tool.index,
          specification.pf.before,
          specification.pf.tool.cdhash,
          operation,
        )
      ).helper;
      await owner.custody.persist("pf-helper", {
        operation,
        helper,
        worker: null,
      });
      requireObservation(
        (await reader.helper(helper)).sha256 === request.launcher.sha256,
      );
      const worker = (await reader.access("pf-worker")).worker;
      await owner.custody.persist("pf-helper", { operation, helper, worker });
      requireObservation(
        (await reader.helper(worker)).sha256 === request.launcher.sha256,
      );
      await owner.custody.witness();
      const completed = await reader.access("pf-run");
      requireObservation(completed.exitCode === 0 && completed.signal === null);
      await reader.retired(helper);
      await reader.retired(worker);
      await reader.retiredRootDomain(helper);
    }
  }
  const pf = createDarwinPfPreparation(
    {
      context: binding.context,
      approval: specification.pf.approval,
      tool: specification.pf.tool,
      install: specification.pf.install,
      restore: specification.pf.restore,
      reservation: 10,
      nonce: request.nonce,
    },
    {
      review: async (approval) => ({
        status: "MATCHED",
        contextSha256: specification.contextSha256,
        manifestSha256: approval.manifestSha256,
      }),
      read: () => reader.pf(),
      reserve: () => reader.reservation(),
      reservation: () => reader.reservation(),
      write: (...args) => reader.writePf(...args),
      recoverReference: () => reader.recoverPfReference(),
      persist: (record) => owner.custody.persist("pf-prerequisite", record),
      verifyRetirement,
    },
  );
  const prerequisites = values("pf-prerequisite");
  if (prerequisites.length) await pf.recover(prerequisites, retirement);
  else {
    requireObservation(
      !custody.some((record) =>
        [
          "pf-write",
          "access-pf-start",
          "access-provision",
          "case-start",
        ].includes(record.phase),
      ),
    );
    const before = normalizeDarwinPfRead(await reader.pf()),
      after = normalizeDarwinPfRead(await reader.pf());
    requireObservation(
      same(before, after) &&
        observationDigest(after) === specification.pf.approval.baselineSha256,
    );
  }
  await verifyRetirement();
  const objects = await reader.retireCase();
  await reader.releaseReservation({
    context: binding.context,
    nonce: request.nonce,
    status: "RETIRED",
    independent: true,
    noLiveUid: true,
    helpersSettled: true,
    domain: retirement.domain,
    verifier: retirement.freshVerifier,
    receiptSha256: retirement.nativeEventSha256,
    pfBaselineSha256: specification.pf.approval.baselineSha256,
  });
  const custodyClosed = await reader.close();
  requireObservation(
    custodyClosed.status === "RETIRED" &&
      custodyClosed.independent &&
      custodyClosed.closed,
  );
  const result = {
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    nativeEventSha256: observationDigest({
      retirement,
      objects,
      custodyClosed,
      controls,
    }),
  };
  await save(recipe.id, { phase: "access-retired", settlement: result });
  return result;
}

/** Recovery is a separate fenced lifetime. Each owner is attempted even when
 * another record join or retirement fails; no receipt failure becomes success. */
export async function recoverDarwinSystem(
  state,
  options,
  loadRecords,
  { request, signal },
) {
  state.fence();
  const names = await state.fs.readdir(state.directory);
  requireObservation(names.length <= 65536);
  const previous = names.filter((name) => name.startsWith("darwin-recovery-"));
  const sequenceOf = (name) =>
    Number(
      /^darwin-recovery-([0-9]+)-(?:intent|result)\.json$/u.exec(name)?.[1] ??
        -1,
    );
  const sequence = 1 + Math.max(-1, ...previous.map(sequenceOf)),
    binding = {
      candidateSha: state.job.candidateSha,
      context: state.plan.bootstrap.context,
      jobSha256: observationDigest(state.job),
      planSha256: observationDigest(state.plan),
    },
    reads = [],
    failures = [];
  requireObservation(Number.isSafeInteger(sequence) && sequence >= 0);
  await state.write(`darwin-recovery-${sequence}-intent.json`, {
    binding,
    requestSha256: observationDigest(request),
    status: "POSSIBLE",
  });
  const attempt = async (owner, operation) => {
    try {
      reads.push({ owner, proof: await operation() });
    } catch (cause) {
      failures.push(cause);
      reads.push({ owner, status: "RETAINED" });
    }
  };
  await attempt("recovery-history", async () => {
    requireObservation(previous.every((name) => sequenceOf(name) >= 0));
    const intents = previous
      .filter((name) => name.endsWith("-intent.json"))
      .sort((a, b) => sequenceOf(a) - sequenceOf(b));
    requireObservation(
      intents.length === sequence &&
        intents.every((name, i) => sequenceOf(name) === i),
    );
    for (const name of previous) {
      const record = JSON.parse(
          await state.receipt(path.join(state.directory, name)),
        ),
        intent = name.endsWith("-intent.json");
      observationObject(record, [
        "binding",
        "requestSha256",
        "status",
        ...(intent
          ? []
          : ["independent", "emergencyCleanup", "nativeEventSha256"]),
      ]);
      requireObservation(
        same(record.binding, binding) && hash(record.requestSha256),
      );
      if (intent) requireObservation(record.status === "POSSIBLE");
      else {
        requireObservation(
          ["RETIRED", "RETAINED"].includes(record.status) &&
            record.independent === (record.status === "RETIRED") &&
            record.emergencyCleanup === false &&
            hash(record.nativeEventSha256),
        );
        const original = JSON.parse(
          await state.receipt(
            path.join(
              state.directory,
              `darwin-recovery-${sequenceOf(name)}-intent.json`,
            ),
          ),
        );
        requireObservation(record.requestSha256 === original.requestSha256);
      }
    }
    return { records: previous.length, independent: true };
  });
  let records = [];
  await attempt("inventory", async () => {
    records = await loadRecords();
    requireObservation(records.every(({ record }) => record !== null));
    return { records: records.length, independent: true };
  });
  await attempt("stock-host", async () => {
    const custody = state.prerequisiteCustody;
    if (!custody && state.manifest.schemaVersion !== 2) {
      requireObservation(
        !names.some((name) => name.startsWith("prerequisite-custody-")),
      );
      return { status: "RETIRED", independent: true, admission: "not-started" };
    }
    requireObservation(
      custody &&
        nativeCIJobBinding(custody.job, state.job) &&
        same(custody.manifest, state.manifest) &&
        custody.output.startsWith(state.env.RUNNER_TEMP + "/"),
    );
    const files = await state.fs.readdir(custody.output),
      prefix = `prerequisite-custody-${custody.admission.nonce}-`;
    requireObservation(
      files.length <= 512 &&
        files.some((name) => name === prefix + "intent.json") &&
        files
          .filter((name) => name.startsWith("prerequisite-custody-"))
          .every((name) => name.startsWith(prefix)),
    );
    const file = path.join(custody.output, prefix + "intent.json"),
      bytes = await state.stockReceipt(file),
      proof = await recoverPrerequisiteTransport(
        custody,
        { file, bytes: bytes.length, sha256: digest(bytes) },
        { ...options, fs: state.fs, signal },
      );
    requireObservation(
      proof.status === "RETIRED" &&
        proof.independent &&
        proof.noLiveMembers &&
        !proof.emergencyCleanup,
    );
    return proof;
  });
  let fresh;
  await attempt("bootstrap", async () => {
    fresh = (await state.bootstrap(signal, { recovery: true })).reader;
    return { independent: true };
  });
  if (fresh) {
    await attempt("build", () =>
      recoverDarwinBuild(
        state,
        records.filter(({ name }) => !name.startsWith("darwin-case-")),
        signal,
        fresh,
      ),
    );
    await attempt("cases", () =>
      recoverDarwinCases(
        state,
        options,
        records.filter(({ name }) => name.startsWith("darwin-case-")),
        { signal },
      ),
    );
    await attempt("bootstrap-close", () => state.releaseBootstrap());
  }
  state.guard(signal);
  const result = {
    status: failures.length ? "RETAINED" : "RETIRED",
    independent: failures.length === 0,
    emergencyCleanup: false,
    nativeEventSha256: observationDigest(reads),
  };
  await state.write(`darwin-recovery-${sequence}-result.json`, {
    binding,
    requestSha256: observationDigest(request),
    ...result,
  });
  if (failures.length) state.fail(failures[0]);
  return result;
}
