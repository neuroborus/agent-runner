import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { normalizeNativeJob, normalizeNativeResult } from "../index.js";
import { digest } from "./inspect.js";
import { freshVerifier } from "./proof.js";
import {
  normalizeLinuxFileMessage,
  LINUX_FILE_CONTROLS,
} from "./files-protocol.js";
import {
  linuxFileSessionPolicy,
  observeLinuxFileSession,
  runLinuxFileSession,
  restoreLinuxFileControl,
  observeLinuxFileControl,
} from "./files.js";

export const LINUX_FILE_CASE_IDS = Object.freeze([
  "files.private",
  "files.publish",
  "files.replace",
  "files.substitution",
  "files.aliases",
  "files.cleanup",
]);
export const LINUX_FILE_SUBCASES = Object.freeze(
  Object.fromEntries(
    [
      ["files.private", ["private"]],
      ["files.publish", ["exclusive"]],
      ["files.replace", ["prepared", "published"]],
      ["files.substitution", ["ancestor", "leaf"]],
      ["files.aliases", ["symlink", "magic-link", "mount", "hard-link"]],
      ["files.cleanup", ["matching", "cleanup-leaf"]],
    ].map(([id, cases]) => [id, Object.freeze(cases)]),
  ),
);
const SESSION_COUNTS = Object.freeze({
  "files.private": 1,
  "files.publish": 1,
  "files.replace": 4,
  "files.substitution": 4,
  "files.aliases": 8,
  "files.cleanup": 3,
});
const CONTENTS = Object.freeze([
  "006f6c64ff",
  "006e657700ff",
  "7365636f6e64",
  "7468697264",
]);
const SESSION_BOUND = 45000; // Admission/probe, owner, session verifier, case verifier.

export function linuxFileCaseBound(checkId) {
  requireValue(LINUX_FILE_CASE_IDS.includes(checkId));
  const denials =
    { "files.substitution": 2, "files.aliases": 4, "files.cleanup": 1 }[
      checkId
    ] ?? 0;
  return (
    SESSION_COUNTS[checkId] * SESSION_BOUND +
    (checkId === "files.replace" ? 10000 : denials * 15000)
  ); // Pre-recovery and control verifiers, plus five-second control cleanup.
}

export function linuxFileProofPolicy(executableDigest) {
  return Object.freeze({
    id: "linux-file-authority-v1",
    executableDigest,
    sessions: Object.freeze(
      [null, ...LINUX_FILE_CONTROLS].map((control) =>
        linuxFileSessionPolicy(executableDigest, control),
      ),
    ),
  });
}

function requireValue(condition) {
  if (!condition) throw new Error("Linux file case failed; exclusion retained");
}

function closed(value, fields) {
  requireValue(
    value !== null &&
      typeof value === "object" &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === fields.length &&
      fields.every((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable && Object.hasOwn(descriptor, "value");
      }),
  );
}

function stableIdentity(value) {
  return (
    value
      ?.split(":")
      .filter((_, index) => index !== 3)
      .join(":") ?? null
  );
}

/** A denial is bound to the reached operation and an unchanged, independently
 * observed control. A generic failed process has none of this authority. */
export function assertLinuxFileDenial(
  control,
  barrier,
  denial,
  before,
  applied,
  observed,
) {
  const configuration = {
    ancestor: ["replace", "identity", "prepared"],
    leaf: ["replace", "identity", "prepared"],
    symlink: ["replace", "symlink", "prepared"],
    "magic-link": ["check", "magic-link", "checking"],
    mount: ["check", "mount", "checking"],
    "hard-link": ["replace", "hard-link", "prepared"],
    "cleanup-leaf": ["cleanup", "identity", "removing"],
  }[control];
  requireValue(configuration !== undefined);
  barrier = normalizeLinuxFileMessage(barrier, barrier.nonce);
  denial = normalizeLinuxFileMessage(denial, barrier.nonce);
  requireValue(
    denial.phase === "denied" &&
      denial.operation === configuration[0] &&
      denial.reason === configuration[1] &&
      barrier.phase === configuration[2] &&
      ["anchor", "allocation", "leaf", "temporary"].every(
        (key) => denial[key] === barrier[key],
      ),
  );
  const names = [
    "allocation",
    "allocation/value",
    "allocation/.pending",
    ".held-allocation",
    ".held-allocation/value",
    ".held-allocation/.pending",
    ".held-value",
    ".alias",
    "crossing",
    ".crossing-source",
    ".crossing-source/value",
  ];
  const owner = before?.objects?.allocation?.uid;
  requireValue(
    Number.isSafeInteger(owner) && owner >= 0 && owner <= 4294967295,
  );
  for (const snapshot of [before, applied, observed]) {
    closed(snapshot, ["control", "parentAuthority", "anchor", "objects"]);
    closed(snapshot.objects, names);
    requireValue(
      snapshot.control === control &&
        snapshot.parentAuthority === true &&
        snapshot.anchor === stableIdentity(barrier.anchor),
    );
    for (const entry of Object.values(snapshot.objects))
      if (entry !== null) {
        closed(entry, [
          "identity",
          "kind",
          "mode",
          "uid",
          "links",
          "bytes",
          "target",
        ]);
        requireValue(
          typeof entry.identity === "string" &&
            /^(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*):[1-9][0-9]*:[1-9][0-9]*:(?:0|[1-9][0-9]*)$/u.test(
              entry.identity,
            ) &&
            entry.identity.length <= 96 &&
            entry.uid === owner &&
            Number.isSafeInteger(entry.links) &&
            entry.links > 0 &&
            (entry.kind === "directory"
              ? entry.mode === 0o700 &&
                entry.bytes === null &&
                entry.target === null
              : entry.kind === "file"
                ? entry.mode === 0o600 &&
                  typeof entry.bytes === "string" &&
                  entry.bytes.length <= 8192 &&
                  /^(?:[a-f0-9]{2})*$/u.test(entry.bytes) &&
                  entry.target === null
                : entry.kind === "symlink" &&
                  entry.mode === 0o777 &&
                  entry.bytes === null &&
                  entry.target === "../.held-value"),
        );
      }
  }
  requireValue(JSON.stringify(observed) === JSON.stringify(applied));
  const original = before.objects,
    changed = applied.objects;
  requireValue(
    original.allocation?.kind === "directory" &&
      original["allocation/value"]?.kind === "file" &&
      (original["allocation/.pending"] === null ||
        original["allocation/.pending"].kind === "file"),
  );
  const changedNames =
    control === "ancestor"
      ? [
          "allocation",
          "allocation/value",
          "allocation/.pending",
          ".held-allocation",
          ".held-allocation/value",
          ".held-allocation/.pending",
        ]
      : ["leaf", "cleanup-leaf", "symlink"].includes(control)
        ? ["allocation/value", ".held-value"]
        : control === "hard-link"
          ? ["allocation/value", ".alias"]
          : [];
  for (const key of names) {
    if (!changedNames.includes(key))
      requireValue(
        JSON.stringify(original[key]) === JSON.stringify(changed[key]),
      );
    if (key.startsWith(".held-") || key === ".alias")
      requireValue(original[key] === null);
    if (
      ["crossing", ".crossing-source", ".crossing-source/value"].includes(
        key,
      ) &&
      control !== "mount"
    )
      requireValue(original[key] === null);
    for (const snapshot of [original, changed])
      if (snapshot[key]?.kind === "file")
        requireValue(
          snapshot[key].links ===
            (control === "hard-link" &&
            snapshot === changed &&
            ["allocation/value", ".alias"].includes(key)
              ? 2
              : 1),
        );
  }
  requireValue(
    original.allocation.identity === stableIdentity(barrier.allocation) &&
      original["allocation/value"].identity === stableIdentity(barrier.leaf) &&
      original["allocation/value"].links === 1,
  );
  requireValue(
    barrier.temporary === null
      ? original["allocation/.pending"] === null
      : original["allocation/.pending"].identity ===
          stableIdentity(barrier.temporary),
  );
  if (control === "ancestor")
    requireValue(
      changed.allocation.kind === "directory" &&
        changed["allocation/value"].kind === "file" &&
        JSON.stringify(changed[".held-allocation"]) ===
          JSON.stringify(original.allocation) &&
        JSON.stringify(changed[".held-allocation/value"]) ===
          JSON.stringify(original["allocation/value"]) &&
        JSON.stringify(changed[".held-allocation/.pending"]) ===
          JSON.stringify(original["allocation/.pending"]) &&
        changed.allocation.identity !== original.allocation.identity &&
        changed[".held-allocation"].identity === original.allocation.identity &&
        changed[".held-allocation/value"].identity ===
          original["allocation/value"].identity &&
        changed[".held-allocation/.pending"].identity ===
          original["allocation/.pending"].identity &&
        changed["allocation/value"].bytes === "73656e74696e656c",
    );
  else if (["leaf", "cleanup-leaf", "symlink"].includes(control))
    requireValue(
      JSON.stringify(changed[".held-value"]) ===
        JSON.stringify(original["allocation/value"]) &&
        changed[".held-value"].identity ===
          original["allocation/value"].identity &&
        changed[".held-value"].bytes === original["allocation/value"].bytes &&
        changed["allocation/value"].identity !==
          original["allocation/value"].identity &&
        (control === "symlink"
          ? changed["allocation/value"].kind === "symlink"
          : changed["allocation/value"].bytes === "73656e74696e656c"),
    );
  else if (control === "hard-link")
    requireValue(
      JSON.stringify(changed["allocation/value"]) ===
        JSON.stringify({ ...original["allocation/value"], links: 2 }) &&
        JSON.stringify(changed[".alias"]) ===
          JSON.stringify({ ...original["allocation/value"], links: 2 }) &&
        changed[".alias"].identity === original["allocation/value"].identity &&
        changed["allocation/value"].identity ===
          original["allocation/value"].identity &&
        changed[".alias"].links === 2 &&
        changed["allocation/value"].links === 2,
    );
  else {
    requireValue(JSON.stringify(before) === JSON.stringify(applied));
    if (control === "mount")
      requireValue(
        changed[".crossing-source/value"].bytes === "73656e74696e656c" &&
          changed.crossing.kind === "directory",
      );
  }
}

/** Host observations bind device/inode/birth identity; mount IDs belong to the
 * helper namespace and are checked independently by the session owner. */
export function assertLinuxFileObservation(message, snapshot, expected) {
  message = normalizeLinuxFileMessage(message, message.nonce);
  closed(snapshot, [
    "ownerUid",
    "parentAuthority",
    "anchor",
    "allocation",
    "leaf",
    "temporary",
  ]);
  closed(expected, ["leaf", "temporary"]);
  requireValue(
    message.anchor !== null &&
      Number.isSafeInteger(snapshot.ownerUid) &&
      snapshot.ownerUid >= 0 &&
      snapshot.ownerUid <= 4294967295 &&
      snapshot.parentAuthority === true,
  );
  for (const key of ["leaf", "temporary"])
    requireValue(
      expected[key] === null ||
        (typeof expected[key] === "string" &&
          expected[key].length <= 8192 &&
          /^(?:[a-f0-9]{2})*$/u.test(expected[key])),
    );
  for (const key of ["anchor", "allocation", "leaf", "temporary"]) {
    const native = message[key];
    const observed = snapshot[key];
    if (native === null) {
      requireValue(
        observed === null && (!(key in expected) || expected[key] === null),
      );
      continue;
    }
    closed(observed, ["identity", "mode", "uid", "links", "bytes"]);
    const directory = key === "anchor" || key === "allocation";
    requireValue(
      observed.identity === stableIdentity(native) &&
        observed.mode === (directory ? 0o700 : 0o600) &&
        observed.uid === snapshot.ownerUid &&
        Number.isSafeInteger(observed.links) &&
        observed.links > 0 &&
        (directory || observed.links === 1) &&
        observed.bytes === (directory ? null : expected[key]),
    );
  }
}

function retired(value) {
  closed(value, ["status", "independent", "emergencyCleanup"]);
  return (
    value.status === "RETIRED" &&
    value.independent === true &&
    value.emergencyCleanup === false
  );
}

function observation(expected, observed) {
  return {
    expected,
    observed,
    matched: true,
    positiveControl: true,
    attempted: true,
    sentinelsUnchanged: true,
  };
}

/** Fixed injected case orchestration. Imports and local harnesses have no
 * native effects; only the explicit CI owner below supplies live sessions. */
export async function runLinuxFileCase(checkId, effects) {
  requireValue(LINUX_FILE_CASE_IDS.includes(checkId));
  const bound = linuxFileCaseBound(checkId);
  const notRun = () => ({
    status: "NOT_RUN",
    elapsedMs: null,
    deadlineMs: bound,
    reason: "missing-input",
  });
  const phases = { setup: notRun(), probe: notRun(), cleanup: notRun() };
  const sessions = [];
  const observations = [];
  let admission = "not-started";
  let lastVerified = null;
  let settlement = {
    status: "RETAINED",
    independent: false,
    emergencyCleanup: false,
  };
  let stage = "setup";
  let started = effects.now();
  const beginning = started;
  const elapsed = () => Math.ceil(effects.now() - started);
  const pass = () => {
    requireValue(
      Number.isSafeInteger(elapsed()) &&
        elapsed() >= 0 &&
        effects.now() - beginning < bound,
    );
    phases[stage] = {
      status: "PASS",
      elapsedMs: elapsed(),
      deadlineMs: bound,
      reason: null,
    };
  };
  const observe = async (controls, message, expected) => {
    const snapshot = await controls.observe();
    assertLinuxFileObservation(message, snapshot, expected);
    await effects.persist({
      type: "observation",
      checkId,
      message,
      snapshot,
      expected,
    });
  };
  const verify = async (session) => {
    requireValue(retired(session.settlement));
    const verified = await effects.verify(session);
    requireValue(retired(verified));
    settlement = verified;
    lastVerified = session;
  };
  const session = async (
    body,
    recovery = null,
    fault = null,
    control = null,
  ) => {
    requireValue(
      sessions.length < SESSION_COUNTS[checkId] &&
        effects.now() - beginning < bound,
    );
    await effects.persist({
      type: "admission",
      checkId,
      sequence: sessions.length,
      recoveryFrom: recovery?.nonce ?? null,
      fault,
    });
    admission = "possible";
    // A thrown or interrupted launch cannot inherit an earlier retirement.
    settlement = {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: false,
    };
    requireValue(effects.now() - beginning < bound);
    let entered = false;
    let completed = false;
    const result = await effects.session(
      async (operation, controls) => {
        requireValue(!entered);
        entered = true;
        await body(operation, controls);
        completed = true;
      },
      { recovery, control },
    );
    sessions.push(result);
    await effects.persist({
      type: "session",
      checkId,
      sequence: sessions.length - 1,
      result,
    });
    requireValue(entered && retired(result.settlement));
    if (fault === null)
      requireValue(
        completed &&
          result.status === "PASS" &&
          result.interrupted === false &&
          result.storage === "REMOVED" &&
          result.exclusion === "RELEASED",
      );
    else if (fault.startsWith("denial:"))
      requireValue(
        !completed &&
          result.status === "FAIL" &&
          result.interrupted === false &&
          result.denial?.phase === "denied" &&
          result.control === control &&
          typeof result.controlDigest === "string" &&
          /^[a-f0-9]{64}$/u.test(result.controlDigest) &&
          result.storage === "RETAINED" &&
          result.exclusion === "RETAINED" &&
          /^barrier-(?:0|[1-9][0-9]?)$/u.test(result.nativeRecord),
      );
    else
      requireValue(
        !completed &&
          result.status === "FAIL" &&
          result.interrupted === true &&
          result.interruption?.phase === fault &&
          result.interruption.observed === true &&
          result.storage === "RETAINED" &&
          result.exclusion === "RETAINED" &&
          /^barrier-(?:0|[1-9][0-9]?)$/u.test(result.nativeRecord),
      );
    return result;
  };
  try {
    await effects.persist({ type: "case", checkId });
    pass();
    stage = "probe";
    started = effects.now();
    if (checkId === "files.private") {
      await session(async (operation, controls) => {
        const allocation = await operation("allocate");
        await observe(controls, allocation, { leaf: null, temporary: null });
        const published = await operation("publish", CONTENTS[0]);
        await observe(controls, published, {
          leaf: CONTENTS[0],
          temporary: null,
        });
        observations.push(
          observation(
            "Private allocation and file under retained parent authority",
            "Independent host identities, owner, 0700/0600 modes and exact binary contents matched",
          ),
        );
        await operation("cleanup");
      });
    } else if (checkId === "files.publish") {
      let winner = null;
      let winnerBytes = null;
      await session(async (operation, controls) => {
        await operation("allocate");
        // All requests enter together; the sole parent owner serializes native effects.
        const results = await Promise.all(
          CONTENTS.slice(1).map((bytes) =>
            operation("publish", bytes, async (message) => {
              await observe(controls, message, {
                leaf: message.phase === "prepared" ? winnerBytes : bytes,
                temporary: message.phase === "prepared" ? bytes : null,
              });
              if (message.phase === "published") {
                requireValue(winner === null);
                winner = message.leaf;
                winnerBytes = bytes;
              }
            }),
          ),
        );
        requireValue(
          results.filter((entry) => entry.phase === "complete").length === 1 &&
            results.filter((entry) => entry.phase === "exists").length ===
              CONTENTS.length - 2 &&
            winner !== null &&
            results.every(
              (entry) => entry.leaf === winner && entry.temporary === null,
            ),
        );
        const inspected = await operation("inspect");
        requireValue(inspected.leaf === winner && inspected.temporary === null);
        await observe(controls, inspected, {
          leaf: winnerBytes,
          temporary: null,
        });
        observations.push(
          observation(
            "One exclusive publication winner for concurrent requests",
            "Exactly one complete winner; losing requests retained its native identity and complete bytes",
          ),
        );
        await operation("cleanup");
      });
    } else if (checkId === "files.replace") {
      for (const fault of ["prepared", "published"]) {
        let barrier = null;
        let prior = null;
        const interrupted = await session(
          async (operation, controls) => {
            await operation("allocate");
            prior = await operation("publish", CONTENTS[0]);
            await observe(controls, prior, {
              leaf: CONTENTS[0],
              temporary: null,
            });
            await operation("replace", CONTENTS[1], async (message) => {
              const expected = {
                leaf: message.phase === "prepared" ? CONTENTS[0] : CONTENTS[1],
                temporary: message.phase === "prepared" ? CONTENTS[1] : null,
              };
              await observe(controls, message, expected);
              if (message.phase === fault) {
                requireValue(barrier === null);
                barrier = message;
                await controls.interrupt();
              }
            });
          },
          null,
          fault,
        );
        requireValue(
          barrier !== null &&
            prior !== null &&
            interrupted.nonce === barrier.nonce &&
            interrupted.nativeAnchor === barrier.anchor &&
            JSON.stringify(interrupted.native) ===
              JSON.stringify({
                allocation: barrier.allocation,
                leaf: barrier.leaf,
                temporary: barrier.temporary,
              }) &&
            (fault === "prepared"
              ? barrier.leaf === prior.leaf && barrier.temporary !== prior.leaf
              : barrier.leaf !== prior.leaf && barrier.temporary === null),
        );
        await verify(interrupted);
        const expected = {
          leaf: fault === "prepared" ? CONTENTS[0] : CONTENTS[1],
          temporary: fault === "prepared" ? CONTENTS[1] : null,
        };
        await observe(
          { observe: () => effects.observeRetained(interrupted) },
          barrier,
          expected,
        );
        const recovered = await session(async (operation, controls) => {
          const inspected = await operation("inspect");
          requireValue(
            ["anchor", "allocation", "leaf", "temporary"].every(
              (key) =>
                stableIdentity(inspected[key]) === stableIdentity(barrier[key]),
            ),
          );
          await observe(controls, inspected, expected);
          await operation("cleanup");
        }, interrupted);
        // A recovery helper must retire before the next fault can be admitted.
        await verify(recovered);
        observations.push(
          observation(
            `Replacement interrupted at the acknowledged ${fault} barrier`,
            "Independent old/new complete bytes and temporary identities matched; fresh non-emergency retirement and identity-bound recovery succeeded while the interrupted operation stayed failed",
          ),
        );
      }
    } else {
      for (const control of LINUX_FILE_SUBCASES[checkId]) {
        if (control === "matching") {
          const cleaned = await session(
            async (operation, controls) => {
              await operation("allocate");
              const published = await operation("publish", CONTENTS[0]);
              await observe(controls, published, {
                leaf: CONTENTS[0],
                temporary: null,
              });
              const removed = await operation(
                "cleanup",
                "",
                async (message) => {
                  requireValue(message.phase === "removing");
                  await observe(controls, message, {
                    leaf: CONTENTS[0],
                    temporary: null,
                  });
                },
              );
              await observe(controls, removed, { leaf: null, temporary: null });
            },
            null,
            null,
            "cleanup",
          );
          await verify(cleaned);
          observations.push(
            observation(
              "Identity-matched synchronized cleanup",
              "Independent recorded identities and complete bytes preceded removal; no allocation or temporary remained after fresh retirement",
            ),
          );
          continue;
        }
        let barrier = null,
          applied = null;
        const denied = await session(
          async (operation, controls) => {
            await operation("allocate");
            const published = await operation("publish", CONTENTS[0]);
            await observe(controls, published, {
              leaf: CONTENTS[0],
              temporary: null,
            });
            const probe = async (message) => {
              barrier = message;
              await observe(controls, message, {
                leaf: CONTENTS[0],
                temporary: message.phase === "prepared" ? CONTENTS[1] : null,
              });
              applied = await controls.fault(control);
              await effects.persist({
                type: "control",
                checkId,
                control,
                barrier,
                applied,
              });
            };
            await operation(
              control === "cleanup-leaf"
                ? "cleanup"
                : ["magic-link", "mount"].includes(control)
                  ? "check"
                  : "replace",
              ["magic-link", "mount", "cleanup-leaf"].includes(control)
                ? ""
                : CONTENTS[1],
              probe,
            );
          },
          null,
          `denial:${control}`,
          control,
        );
        requireValue(barrier !== null && applied !== null);
        await verify(denied);
        const observed = await effects.observeControl(denied);
        assertLinuxFileDenial(
          control,
          barrier,
          denied.denial,
          applied.before,
          applied.applied,
          observed,
        );
        await effects.persist({
          type: "denial",
          checkId,
          control,
          denial: denied.denial,
          observed,
        });
        const restorationStart = effects.now();
        const restored = await effects.restoreControl(denied);
        const expectedControl = structuredClone(applied.before);
        if (control === "mount")
          for (const key of [
            "crossing",
            ".crossing-source",
            ".crossing-source/value",
          ])
            expectedControl.objects[key] = null;
        requireValue(
          JSON.stringify(restored) === JSON.stringify(expectedControl) &&
            effects.now() - restorationStart >= 0 &&
            effects.now() - restorationStart <= 10000,
        );
        await effects.persist({ type: "restored", checkId, control, restored });
        const recovered = await session(async (operation, controls) => {
          const inspected = await operation("inspect");
          requireValue(
            ["anchor", "allocation", "leaf", "temporary"].every(
              (key) =>
                stableIdentity(inspected[key]) === stableIdentity(barrier[key]),
            ),
          );
          await observe(controls, inspected, {
            leaf: CONTENTS[0],
            temporary: barrier.temporary === null ? null : CONTENTS[1],
          });
          await operation("cleanup");
        }, denied);
        await verify(recovered);
        observations.push(
          observation(
            `Native ${control} rejection`,
            "Operation-specific denial preserved recorded originals and substitute sentinels; fresh retirement, identity-bound control cleanup and recovery succeeded while the denied operation stayed failed",
          ),
        );
      }
    }
    requireValue(
      observations.length === LINUX_FILE_SUBCASES[checkId].length &&
        sessions.length === SESSION_COUNTS[checkId],
    );
    pass();
    stage = "cleanup";
    started = effects.now();
    if (lastVerified !== sessions.at(-1)) await verify(sessions.at(-1));
    pass();
    const result = {
      checkId,
      admission,
      status: "PASS",
      reason: null,
      phases,
      observations,
      settlement,
      sessions,
    };
    await effects.persist({ type: "terminal", checkId, result });
    return result;
  } catch {
    if (admission === "not-started") {
      stage = "setup";
      started = beginning;
      phases.probe = notRun();
      phases.cleanup = notRun();
    }
    const emergency = sessions.some(
      (entry) => entry.settlement?.emergencyCleanup === true,
    );
    settlement = {
      ...settlement,
      emergencyCleanup: settlement.emergencyCleanup || emergency,
    };
    const reason =
      admission === "not-started"
        ? effects.now() - beginning >= bound
          ? "deadline"
          : "setup-failed"
        : settlement.status !== "RETIRED"
          ? "unretired"
          : effects.now() - beginning >= bound
            ? "deadline"
            : `${stage}-failed`;
    phases[stage] = {
      status: "FAIL",
      elapsedMs: Math.max(0, elapsed()),
      deadlineMs: bound,
      reason,
    };
    const result = {
      checkId,
      admission,
      status: "FAIL",
      reason,
      phases,
      observations,
      settlement,
      sessions,
    };
    try {
      await effects.persist({ type: "terminal", checkId, result });
    } catch {
      /* Missing terminal evidence never repairs a failed possible admission. */
    }
    return result;
  }
}

/** Complete fixed file inventory; system composition remains a separate owner. */
export async function runLinuxFileProofs(job, fixture, build, { signal } = {}) {
  signal?.throwIfAborted();
  job = normalizeNativeJob(job);
  requireValue(
    process.platform === "linux" &&
      process.arch === "x64" &&
      process.env.CI === "true" &&
      process.env.GITHUB_ACTIONS === "true" &&
      process.env.ImageOS === "ubuntu24" &&
      job.schemaVersion === 5 &&
      job.platform === "linux" &&
      job.stages.setup.status === "PASS" &&
      job.candidateSha === build.candidateSha,
  );
  const policy = linuxFileProofPolicy(build.sha256);
  const helper = { name: "file-helper", version: "1", sha256: build.sha256 };
  const existing = job.versions.find(({ name }) => name === helper.name);
  requireValue(
    existing === undefined ||
      JSON.stringify(existing) === JSON.stringify(helper),
  );
  const nonce = randomUUID();
  let record = 0;
  const results = [];
  let failed = false;
  for (const checkId of LINUX_FILE_CASE_IDS) {
    signal?.throwIfAborted();
    const entry = failed
      ? {
          checkId,
          admission: "not-started",
          status: "BLOCKED",
          reason: "missing-input",
          observations: [],
          sessions: [],
          settlement: {
            status: "RETAINED",
            independent: false,
            emergencyCleanup: false,
          },
          phases: Object.fromEntries(
            ["setup", "probe", "cleanup"].map((name) => [
              name,
              {
                status: "NOT_RUN",
                elapsedMs: null,
                deadlineMs: linuxFileCaseBound(checkId),
                reason: "missing-input",
              },
            ]),
          ),
        }
      : await runLinuxFileCase(checkId, {
          now: () => performance.now(),
          persist: (value) =>
            writeFile(
              path.join(
                fixture.directory,
                "evidence",
                `file-cases-${nonce}-${record++}.json`,
              ),
              JSON.stringify({ candidateSha: job.candidateSha, ...value }) +
                "\n",
              { flag: "wx", mode: 0o400 },
            ),
          session: (body, options) =>
            runLinuxFileSession(job, fixture, build, body, {
              ...options,
              signal,
            }),
          verify: (session) =>
            freshVerifier(
              path.join(
                fixture.directory,
                "evidence",
                `file-helper-${session.nonce}.json`,
              ),
              session.receiptDigest,
            ),
          observeRetained: (session) =>
            observeLinuxFileSession(fixture, session),
          observeControl: (session) =>
            observeLinuxFileControl(fixture, session),
          restoreControl: (session) =>
            restoreLinuxFileControl(fixture, session),
        });
    failed ||= entry.status !== "PASS";
    results.push({
      result: normalizeNativeResult({
        schemaVersion: 2,
        candidateSha: job.candidateSha,
        checkoutSha: job.checkoutSha,
        platform: job.platform,
        declaredImage: job.declaredImage,
        observed: job.observed,
        provenance: job.provenance,
        checkId,
        profile: "files",
        tier: "system",
        dispatch: "native",
        implemented: true,
        admission: entry.admission,
        versions:
          entry.admission === "possible" && existing === undefined
            ? [...job.versions, helper]
            : job.versions,
        policy:
          entry.admission === "possible"
            ? { id: policy.id, sha256: digest(JSON.stringify(policy)) }
            : null,
        phases: entry.phases,
        observations: entry.observations,
        settlement: entry.settlement,
        status: entry.status,
        reason: entry.reason,
      }),
      sessions: entry.sessions,
    });
  }
  return results;
}
