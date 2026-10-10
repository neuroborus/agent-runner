import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  assertLinuxNamespacePreparation,
  cleanupLinuxNamespaces,
  initialLinuxNamespacePreparation,
  linuxNamespaceDenials,
  linuxNamespaceDiagnosticReplay,
  linuxNamespaceObservationFailure,
  linuxNamespaceProbeOutcome,
  linuxNamespaceTracePids,
  linuxNamespacePolicyDecision,
  linuxNamespacePolicyRetired,
  linuxNamespaceSettlement,
  linuxNamespaceProfile,
  linuxNamespaceProfileName,
  linuxNamespaceProfileMembership,
  normalizeLinuxNamespacePreparation,
  prepareLinuxNamespaces,
  readLinuxNamespaceJournal,
  verifyLinuxNamespaces,
} from "../ci/native/linux/index.js";
import {
  assessFeasibilityPreparation,
  assessFeasibilityReport,
  unavailableFeasibilityResults,
} from "../ci/native/feasibility/index.js";

const CONTEXT = { candidateSha: "a".repeat(40), runId: "42", runAttempt: "1" };
const ENV = {
  CI: "true",
  GITHUB_ACTIONS: "true",
  ImageOS: "ubuntu24",
  RUNNER_ENVIRONMENT: "github-hosted",
  RUNNER_OS: "Linux",
};
const worker = {
  env: ENV,
  platform: "linux",
  architecture: "x64",
  now: () => 0,
};
function observation(passed = false, label = "unconfined") {
  return {
    executable: {
      sha256: "b".repeat(64),
      packageVersion: "0.9.0-1ubuntu0.3",
      version: "bubblewrap 0.9.0",
    },
    sysctls: {
      restrictedUserns: 1,
      unprivilegedUserns: 1,
      maxUserNamespaces: 4096,
    },
    apparmor: {
      enabled: true,
      parserVersion: "4.0.1",
      abiSha256: "c".repeat(64),
      usernsFeature: true,
    },
    callerLabel: "unconfined",
    effectiveLabel: passed ? label : null,
    procVisible: true,
    probes: ["ordinary", "nested"].map((mode) => ({
      mode,
      passed,
      settled: true,
      replayMatched: true,
      exitCode: passed ? 0 : 1,
      signal: null,
      timedOut: false,
      operation: passed ? "unknown" : "mapping",
      errno: passed ? null : "EACCES",
      denials: passed
        ? []
        : [
            {
              operation: "capable",
              label: "restricted-userns",
              capability: "setuid",
            },
          ],
    })),
  };
}
function fixture({
  installFailure = false,
  removeFailure = false,
  verified = true,
} = {}) {
  const records = [],
    calls = [];
  let loaded = false;
  return {
    records,
    calls,
    options: {
      ...worker,
      effects: {
        vacant: async () => true,
        observe: async () => {
          calls.push("observe");
          return loaded ? observation(verified, "owned") : observation();
        },
        install: async () => {
          calls.push("install");
          assert.equal(records.at(-1).phase, "installation");
          assert.equal(records.at(-1).owned.status, "POSSIBLE");
          assert.equal(
            records.at(-1).owned.name,
            linuxNamespaceProfileName(CONTEXT),
          );
          loaded = true;
          if (installFailure) throw new Error("private parser text");
        },
        remove: async () => {
          calls.push("remove");
          if (removeFailure) throw new Error("private cleanup text");
          loaded = false;
        },
      },
    },
    persist: async (value) => records.push(structuredClone(value)),
  };
}

const JOURNAL_TOKEN = "s=fixture;i=1;opaque:value";
const JOURNAL_ENTRY = JSON.stringify({
  __CURSOR: JOURNAL_TOKEN,
  MESSAGE: "private kernel fixture /private/journal",
});
const journalResult = (overrides = {}) => ({
  status: 0,
  signal: null,
  stdout: Buffer.from(`${JOURNAL_ENTRY}\n-- cursor: ${JOURNAL_TOKEN}\n`),
  stderr: Buffer.alloc(0),
  ...overrides,
});
function journalEffects(result) {
  const calls = [],
    protectedImages = [];
  return {
    calls,
    protectedImages,
    options: {
      now: () => 0,
      deadline: 100,
      protect: (image) => protectedImages.push(image),
      execute: (file, args, options) => {
        calls.push({ file, args, options });
        return result;
      },
    },
  };
}

test("Linux journal acquisition binds the complete opaque cursor and reads through the same bounded privileged command", () => {
  const cursor = journalEffects(journalResult());
  assert.equal(readLinuxNamespaceJournal(null, cursor.options), JOURNAL_TOKEN);
  const read = journalEffects(
    journalResult({ stdout: Buffer.from(`${JOURNAL_ENTRY}\n`) }),
  );
  assert.equal(
    readLinuxNamespaceJournal(JOURNAL_TOKEN, read.options),
    `${JOURNAL_ENTRY}\n`,
  );
  for (const f of [cursor, read]) {
    assert.deepEqual(f.protectedImages, [
      "/usr/bin/journalctl",
      "/usr/bin/sudo",
      "/usr/bin/timeout",
    ]);
    assert.equal(f.calls.length, 1);
    const command = f.calls[0];
    assert.equal(command.file, "/usr/bin/sudo");
    assert.deepEqual(command.args.slice(0, 7), [
      "--non-interactive",
      "--",
      "/usr/bin/timeout",
      "--signal=TERM",
      "--kill-after=2s",
      "8s",
      "/usr/bin/journalctl",
    ]);
    assert.deepEqual(
      command.args.slice(7),
      f === cursor
        ? [
            "--kernel",
            "--lines=1",
            "--output=json",
            "--show-cursor",
            "--no-pager",
          ]
        : [
            "--kernel",
            `--after-cursor=${JOURNAL_TOKEN}`,
            "--output=json",
            "--no-pager",
          ],
    );
    assert.deepEqual(command.options.env, { PATH: "/usr/bin:/bin", LANG: "C" });
    assert.equal(command.options.timeout, 12000);
    assert.equal(command.options.maxBuffer, 65536);
    assert.equal(command.options.encoding, null);
  }
  const emptyRead = journalEffects(journalResult({ stdout: Buffer.alloc(0) }));
  assert.equal(readLinuxNamespaceJournal(JOURNAL_TOKEN, emptyRead.options), "");
  const expired = journalEffects(journalResult());
  assert.throws(() =>
    readLinuxNamespaceJournal(null, { ...expired.options, deadline: 0 }),
  );
  assert.equal(expired.calls.length, 0);
  for (const invalid of [1, "", "cursor\n", "x".repeat(513)])
    assert.throws(() => readLinuxNamespaceJournal(invalid, expired.options));
  assert.equal(expired.calls.length, 0);
});

test("Linux journal cursor refusals precede both probes and retain observed process facts without private output", async () => {
  const cases = [
    [
      "journalctl: unrecognized option '--show-cursor'\n",
      "journal-command-rejected",
    ],
    ["sudo: a password is required\n", "journal-authority-unavailable"],
    [
      "No journal files were opened due to insufficient permissions.\n",
      "journal-authority-unavailable",
    ],
    ["No journal files were found.\n", "journal-unavailable"],
    [
      "Failed to get cursor: Cannot assign requested address\n",
      "journal-cursor-unavailable",
    ],
    ["private command failure /private/command\n", "journal-command-failed"],
  ].map(([stderr, code]) => [
    journalResult({ status: 1, stderr: Buffer.from(stderr) }),
    code,
  ]);
  cases.push(
    [journalResult({ status: 124 }), "ETIMEDOUT"],
    [journalResult({ status: 137 }), "journal-command-killed"],
    [journalResult({ stdout: Buffer.alloc(0) }), "journal-cursor-absent"],
    [
      journalResult({ status: null, signal: "SIGKILL" }),
      "journal-command-failed",
    ],
    [journalResult({ status: null, error: { code: "ENOENT" } }), "ENOENT"],
    [
      journalResult({
        status: null,
        signal: "SIGTERM",
        error: { code: "ETIMEDOUT" },
      }),
      "ETIMEDOUT",
    ],
  );
  for (const [outcome, code] of cases) {
    const f = fixture(),
      journal = journalEffects(outcome);
    f.options.effects.observe = async () => {
      try {
        readLinuxNamespaceJournal(null, journal.options);
        f.calls.push("probe");
        return observation(true);
      } catch (error) {
        error.namespaceObservationFailure = linuxNamespaceObservationFailure(
          error.namespaceStage,
          "ordinary",
          error,
          [],
        );
        throw error;
      }
    };
    const record = await prepareLinuxNamespaces(
      CONTEXT,
      "/fixture",
      f.persist,
      f.options,
    );
    assert.equal(record.status, "BLOCKED");
    assert.equal(record.owned, null);
    assert.deepEqual(f.calls, []);
    assert.equal(journal.calls.length, 1);
    assert.equal(record.observationFailure.stage, "journal-cursor");
    assert.equal(record.observationFailure.nativeCode, code);
    assert.deepEqual(record.observationFailure.probes, []);
    assert.deepEqual(record.observationFailure.outcome, {
      exitCode: outcome.status,
      signal: outcome.signal,
      timedOut: outcome.status === 137 ? null : code === "ETIMEDOUT",
    });
    assert.equal(record.cleanupCause, null);
    assert.ok(Buffer.byteLength(record.cause.detail) <= 256);
    assert.doesNotMatch(
      JSON.stringify(f.records),
      /private kernel|private command|\/private\//u,
    );
    assert.deepEqual(
      normalizeLinuxNamespacePreparation(
        JSON.parse(JSON.stringify(record)),
        CONTEXT,
      ),
      record,
    );
  }
});

test("Linux journal rejects missing, mismatched, incomplete or excessive cursor evidence without losing successful exit status", () => {
  const cases = [
    ["", "journal-cursor-absent"],
    [`${JOURNAL_ENTRY}\n`, "journal-cursor-absent"],
    [`-- cursor: ${JOURNAL_TOKEN}\n`, "journal-cursor-malformed"],
    [`${JOURNAL_ENTRY}\n-- cursor: \n`, "journal-cursor-malformed"],
    [`${JOURNAL_ENTRY}\n-- cursor: other\n`, "journal-cursor-malformed"],
    [
      `${JOURNAL_ENTRY}\n-- cursor: ${JOURNAL_TOKEN}\n-- cursor: ${JOURNAL_TOKEN}\n`,
      "journal-cursor-malformed",
    ],
    [
      `${JOURNAL_ENTRY}\n-- cursor: ${JOURNAL_TOKEN}`,
      "journal-cursor-malformed",
    ],
    [`not-json\n-- cursor: ${JOURNAL_TOKEN}\n`, "journal-cursor-malformed"],
    ["x".repeat(65537), "journal-output-bound"],
    [Buffer.from([255]), "journal-output-malformed"],
  ];
  for (const [stdout, code] of cases) {
    const f = journalEffects(journalResult({ stdout }));
    assert.throws(
      () => readLinuxNamespaceJournal(null, f.options),
      (error) => {
        const failure = linuxNamespaceObservationFailure(
          error.namespaceStage,
          "ordinary",
          error,
          [],
        );
        assert.equal(failure.nativeCode, code);
        assert.deepEqual(failure.outcome, {
          exitCode: 0,
          signal: null,
          timedOut: false,
        });
        return true;
      },
    );
  }
  for (const result of [
    journalResult({ stderr: Buffer.alloc(65536) }),
    journalResult({ error: { code: "ENOBUFS" } }),
  ]) {
    const f = journalEffects(result);
    assert.throws(() => readLinuxNamespaceJournal(null, f.options), {
      namespaceNativeCode: "journal-output-bound",
    });
  }
  for (const stdout of ["not-json\n", "[]\n", "null\n", JOURNAL_ENTRY]) {
    const f = journalEffects(journalResult({ stdout }));
    assert.throws(() => readLinuxNamespaceJournal(JOURNAL_TOKEN, f.options), {
      namespaceNativeCode: "journal-output-malformed",
      namespaceStage: "journal-read",
    });
  }
  assert.throws(() =>
    linuxNamespaceObservationFailure(
      "probe",
      "ordinary",
      { namespaceNativeCode: "journal-cursor-absent" },
      [],
    ),
  );
});

test("Linux failed journal reads retain completed probe facts and their first cause through independent policy cleanup", async () => {
  const f = fixture({ removeFailure: true }),
    journal = journalEffects(
      journalResult({
        status: 1,
        stderr: Buffer.from(
          "Failed to seek to cursor: Invalid argument\nprivate command /private/example\n",
        ),
      }),
    );
  const completed = [
    {
      mode: "ordinary",
      ...linuxNamespaceProbeOutcome({ status: 0, signal: null }),
    },
  ];
  let inspected = false;
  f.options.effects.observe = async () => {
    if (!inspected) {
      inspected = true;
      return observation();
    }
    try {
      readLinuxNamespaceJournal(JOURNAL_TOKEN, journal.options);
    } catch (error) {
      error.namespaceObservationFailure = linuxNamespaceObservationFailure(
        error.namespaceStage,
        "ordinary",
        error,
        completed,
      );
      throw error;
    }
  };
  const record = await prepareLinuxNamespaces(
    CONTEXT,
    "/fixture",
    f.persist,
    f.options,
  );
  assert.equal(record.status, "BLOCKED");
  assert.equal(record.owned.status, "LOADED");
  assert.equal(record.observationFailure.stage, "journal-read");
  assert.deepEqual(record.observationFailure.probes, completed);
  assert.equal(record.cleanupCause.code, "cleanup-unobserved");
  assert.match(record.cause.detail, /exit=1.*journal-cursor-unavailable/u);
  assert.doesNotMatch(
    JSON.stringify(f.records),
    /private command|\/private\/|private cleanup/u,
  );
  f.options.effects.remove = async () => {};
  const recovered = await cleanupLinuxNamespaces(
    record,
    CONTEXT,
    true,
    f.persist,
    f.options,
  );
  assert.equal(recovered.owned.status, "REMOVED");
  assert.equal(recovered.cleanupCause, null);
  assert.deepEqual(recovered.cause, record.cause);
  assert.deepEqual(recovered.observationFailure, record.observationFailure);
  assert.equal(recovered.status, "BLOCKED");
});

test("Linux policy membership retains unexpected modes, child profiles and stacked labels", () => {
  const name = linuxNamespaceProfileName(CONTEXT);
  for (const label of [
    name,
    `${name} (unconfined)`,
    `${name} (enforce)`,
    `${name}//child (enforce)`,
    `another-policy//&${name} (mixed)`,
    `${name}//&another-policy (enforce)`,
  ])
    assert.equal(linuxNamespaceProfileMembership(label, CONTEXT), true);
  assert.equal(
    linuxNamespaceProfileMembership("another-policy (enforce)", CONTEXT),
    false,
  );
  assert.equal(
    linuxNamespaceProfileMembership(`${name}-other (unconfined)`, CONTEXT),
    false,
  );
  assert.throws(() =>
    linuxNamespaceProfileMembership("x".repeat(4097), CONTEXT),
  );
});

test("Linux audit attribution excludes unrelated processes and strips raw trace/kernel data", () => {
  const name = linuxNamespaceProfileName(CONTEXT);
  const trace =
    '101 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0\n101 clone(child_stack=NULL, flags=CLONE_NEWUSER|SIGCHLD) = 102\n102 unshare(CLONE_NEWUSER) = 0\n102 +++ exited with 1 +++\n101 +++ exited with 1 +++\n';
  const message = (pid, profile = "unprivileged_userns") =>
    JSON.stringify({
      MESSAGE: `audit: apparmor="DENIED" operation="capable" profile="${profile}" pid=${pid} comm="bwrap" capability=7 capname="setuid" name="/private/fixture"`,
    });
  assert.deepEqual(
    linuxNamespaceDenials(trace, [message(999), message(102)].join("\n"), name),
    [
      {
        operation: "capable",
        label: "restricted-userns",
        capability: "setuid",
      },
    ],
  );
  const nested =
    '101 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0\n101 clone(child_stack=NULL, flags=CLONE_NEWUSER|SIGCHLD) = 102\n102 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n102 <... clone resumed>) = 1\n103 capset({version=_LINUX_CAPABILITY_VERSION_3}, NULL) = -1 EPERM\n103 +++ exited with 1 +++\n102 +++ exited with 1 +++\n101 +++ exited with 1 +++\n';
  assert.deepEqual(linuxNamespaceDenials(nested, message(103), name), [
    { operation: "capable", label: "restricted-userns", capability: "setuid" },
  ]);
  assert.deepEqual(linuxNamespaceDenials(nested, message(1), name), []);
  assert.deepEqual(
    linuxNamespaceDenials(
      trace.replace(
        "102 unshare(CLONE_NEWUSER) = 0",
        '102 execve("/bin/true", ["true"], 0x0) = 0',
      ),
      message(102),
      name,
    ),
    [],
  );
  assert.deepEqual(
    linuxNamespaceDenials(trace, message(102, "unrecognized-profile"), name),
    [{ operation: "capable", label: "other", capability: "setuid" }],
  );
  assert.deepEqual(
    linuxNamespaceDenials(
      trace,
      message(102).replace('capname=\\"setuid\\"', 'capname=\\"net_admin\\"'),
      name,
    ),
    [{ operation: "other", label: "restricted-userns", capability: null }],
  );
  assert.throws(() =>
    linuxNamespaceDenials("x".repeat(65537), message(102), name),
  );
  assert.throws(() => linuxNamespaceDenials(trace, "x".repeat(65537), name));
  assert.throws(() =>
    linuxNamespaceDenials(trace, "malformed kernel output", name),
  );
});

const TRACE =
  '101 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0\n101 clone(child_stack=NULL, flags=SIGCHLD) = 102\n102 capset({version=_LINUX_CAPABILITY_VERSION_3}, NULL) = -1 EPERM\n102 +++ exited with 1 +++\n101 +++ exited with 1 +++\n';
const CAPTURE_FIXTURE = String.raw`
const fs = require("node:fs");
const [file, trace, mode] = process.argv.slice(1);
if (mode === "substitution") {
  fs.renameSync(file, file + ".held"); fs.writeFileSync(file, "replacement");
} else {
  const bytes = mode === "oversized" ? "x".repeat(65536)
    : mode === "pending" ? trace.replace("101 clone(child_stack=NULL, flags=SIGCHLD) = 102",
      "101 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>")
    : mode === "missing-exit" ? trace.replace("101 +++ exited with 1 +++\n", "")
    : mode === "invalid-utf8" ? Buffer.from([255]) : trace;
  fs.writeFileSync(file, bytes);
  fs.writeSync(2, mode === "stream-bound" ? Buffer.alloc(65537)
    : mode === "trace-error" ? "strace: attach refused\n" : "bwrap: fixture\n");
  process.exitCode = mode === "success" ? 1 : 0;
}
`;
const captureTest = (name, body) =>
  test(name, { skip: process.platform !== "linux" }, body);
async function captureFixture(t, mode, settings = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), "namespace-capture-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const state = { directory };
  state.capture = linuxNamespaceDiagnosticReplay(
    "/usr/bin/bwrap",
    ["--", "/bin/true"],
    { timeout: 10000 },
    (file, args, options) => {
      assert.equal(file, "/usr/bin/prlimit");
      assert.equal(args[0], "--fsize=65536:65536");
      assert.deepEqual(args.slice(1, 5), ["--", "/usr/bin/strace", "-f", "-o"]);
      assert.equal(args[6], "-q"); // -qq would hide trace-completion records.
      assert.deepEqual(args.slice(args.indexOf("--", 2) + 1), [
        "/usr/bin/bwrap",
        "--",
        "/bin/true",
      ]);
      assert.deepEqual(options.env, { PATH: "/usr/bin:/bin", LANG: "C" });
      assert.equal(options.timeout, 10000);
      assert.equal(options.maxBuffer, 65536);
      assert.equal(options.killSignal, "SIGKILL");
      state.file = args[5];
      if (mode === "refused-launch")
        throw Object.assign(new Error("private launch refusal"), {
          code: "ENOENT",
        });
      // Plain Node proves transport; no native tool runs.
      return spawnSync(
        process.execPath,
        ["-e", CAPTURE_FIXTURE, state.file, TRACE, mode],
        options,
      );
    },
    {
      directory,
      now: settings.now,
      settle: async (pids, complete) => {
        state.pids = pids;
        if (settings.settle) await settings.settle(state);
        return (
          settings.claimedRetired ?? (complete && settings.retired !== false)
        );
      },
    },
  );
  return state;
}

test("Linux trace attribution handles resumed execs and excludes successful payload images", () => {
  const trace = TRACE.replace(
    " = 0\n",
    " <unfinished ...>\n101 <... execve resumed>) = 0\n",
  ).replace(
    "102 capset({version=_LINUX_CAPABILITY_VERSION_3}, NULL) = -1 EPERM",
    '102 execve("/bin/true", ["true"], 0x0 <unfinished ...>\n102 <... execve resumed>) = 0',
  );
  assert.deepEqual(linuxNamespaceTracePids(trace), ["101", "102"]);
  assert.deepEqual(linuxNamespaceTracePids(trace, true), ["101"]);
  for (const invalid of [
    TRACE.trimEnd(),
    TRACE.replace("101 +++ exited with 1 +++\n", ""),
    trace.replace("<... execve resumed>) = 0", "<... execve resumed>"),
    TRACE.replace(
      "101 clone(child_stack=NULL, flags=SIGCHLD) = 102",
      "101 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>",
    ),
    trace.replace("101 <... execve resumed>", "101 <... clone resumed>"),
    TRACE.replace(" = 0\n", " = -1 EACCES\n"),
    TRACE + "private tracee prose\n",
  ])
    assert.throws(() => linuxNamespaceTracePids(invalid));
});

captureTest("Linux private capture preserves bounds and custody", async (t) => {
  for (const [mode, code, quarantined] of [
    ["success", null, false],
    ["oversized", "capture-bound", true],
    ["pending", "trace-incomplete", true],
    ["missing-exit", "trace-incomplete", true],
    ["invalid-utf8", "trace-incomplete", true],
    ["deadline", "ETIMEDOUT", false],
    ["substitution", "capture-substitution", true],
    ["refused-launch", "ENOENT", true],
    ["unretired", "capture-unsettled", true],
    ["retirement-error", "EACCES", true],
    ["cleanup-substitution", "capture-cleanup", true],
    ["stream-bound", "capture-bound", true],
    ["trace-error", "trace-incomplete", true],
  ]) {
    let tick = 0;
    const f = await captureFixture(t, mode, {
      retired: !["unretired", "refused-launch"].includes(mode),
      claimedRetired: mode === "missing-exit" ? true : undefined,
      now: mode === "deadline" ? () => (tick++ ? 10000 : 0) : undefined,
      settle: async ({ file }) => {
        if (mode === "retirement-error")
          throw Object.assign(new Error("private settlement refusal"), {
            code: "EACCES",
          });
        if (mode === "cleanup-substitution") {
          await rename(file, file + ".held");
          await writeFile(file, "replacement");
        } else if (!code) {
          const entry = await lstat(file);
          assert.ok(entry.isFile());
          assert.equal(entry.mode & 0o7777, 0o600);
          assert.equal((await lstat(path.dirname(file))).mode & 0o7777, 0o700);
        }
      },
    });
    if (code) {
      await assert.rejects(f.capture, (error) => {
        assert.equal(error.namespaceNativeCode ?? error.code, code);
        assert.equal(error.namespaceCleanupFailed ?? false, quarantined);
        return true;
      });
      if (mode.includes("substitution"))
        assert.equal(await readFile(f.file, "utf8"), "replacement");
    } else {
      const replay = await f.capture;
      assert.equal(replay.result.status, 1);
      assert.equal(replay.trace, TRACE);
      assert.match(replay.result.stderr, /^bwrap:/u);
      assert.deepEqual(f.pids, [replay.result.pid, "101", "102"]);
    }
    assert.equal((await readdir(f.directory)).length, quarantined ? 1 : 0);
    if (mode === "refused-launch") assert.deepEqual(f.pids, []);
  }
});

test("Linux mapping errno alone, unknown policy, unsupported ABI and unsettled probes admit no remedy", async () => {
  for (const alter of [
    (value) => value.probes.forEach((probe) => (probe.denials = [])),
    (value) => (value.probes[0].denials[0].label = "other"),
    (value) =>
      value.probes[0].denials.push({
        operation: "other",
        label: "restricted-userns",
        capability: null,
      }),
    (value) => (value.probes[1].settled = false),
    (value) => (value.probes[1].replayMatched = false),
    (value) => (value.procVisible = false),
    (value) => (value.apparmor.parserVersion = "3.0.1"),
    (value) => (value.apparmor.usernsFeature = false),
    (value) => (value.sysctls.unprivilegedUserns = 0),
    (value) => (value.sysctls.unprivilegedUserns = null),
    (value) => (value.callerLabel = "other"),
    (value) => (value.executable.packageVersion = "0.9.0-2"),
  ]) {
    const value = observation();
    alter(value);
    assert.equal(linuxNamespacePolicyDecision(value), "blocked");
    const f = fixture();
    f.options.effects.observe = async () => value;
    const record = await prepareLinuxNamespaces(
      CONTEXT,
      "/fixture",
      f.persist,
      f.options,
    );
    assert.equal(record.status, "BLOCKED");
    assert.equal(record.owned, null);
    assert.match(
      record.cause.detail,
      /exit=1.*ordinary-mapping, native=EACCES/u,
    );
    assert.ok(Buffer.byteLength(record.cause.detail) <= 256);
    assert.ok(!f.calls.includes("install") && !f.calls.includes("remove"));
    assert.throws(() => assertLinuxNamespacePreparation(record, CONTEXT));
  }
  const f = fixture();
  await assert.rejects(
    prepareLinuxNamespaces(CONTEXT, "/fixture", f.persist, {
      ...f.options,
      env: { ...ENV, GITHUB_ACTIONS: "false" },
    }),
  );
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.records, []);
});

test("Linux scoped preparation persists intent then requires effective label and both original probes", async () => {
  const f = fixture(),
    record = await prepareLinuxNamespaces(
      CONTEXT,
      "/fixture",
      f.persist,
      f.options,
    );
  assert.equal(assertLinuxNamespacePreparation(record, CONTEXT).status, "PASS");
  assert.deepEqual(f.calls, ["observe", "install", "observe"]);
  assert.equal(record.before.probes[0].passed, false);
  assert.ok(record.after.probes.every(({ passed }) => passed));
  assert.equal(record.after.effectiveLabel, "owned");
  assert.match(
    linuxNamespaceProfile(CONTEXT),
    /^abi <abi\/4\.0>,\nprofile agent-runner-native-bwrap-[a-f0-9]{24} \/usr\/bin\/bwrap flags=\(unconfined\) \{\n  userns,\n\}\n$/u,
  );
  const unmodified = fixture();
  unmodified.options.effects.observe = async () => observation(true);
  const compatible = await prepareLinuxNamespaces(
    CONTEXT,
    "/fixture",
    unmodified.persist,
    unmodified.options,
  );
  assert.equal(compatible.owned, null);
  assert.equal(compatible.status, "PASS");
  assert.ok(!unmodified.calls.includes("install"));
  const priorOwned = fixture();
  priorOwned.options.effects.observe = async () => observation(true, "owned");
  assert.equal(
    (
      await prepareLinuxNamespaces(
        CONTEXT,
        "/fixture",
        priorOwned.persist,
        priorOwned.options,
      )
    ).status,
    "BLOCKED",
  );
  const occupied = fixture();
  occupied.options.effects.vacant = async () => false;
  const collision = await prepareLinuxNamespaces(
    CONTEXT,
    "/fixture",
    occupied.persist,
    occupied.options,
  );
  assert.equal(collision.owned, null);
  assert.deepEqual(occupied.calls, ["observe"]);
  const hiddenProc = fixture();
  hiddenProc.options.effects.observe = async () => ({
    ...observation(true),
    procVisible: false,
  });
  assert.equal(
    (
      await prepareLinuxNamespaces(
        CONTEXT,
        "/fixture",
        hiddenProc.persist,
        hiddenProc.options,
      )
    ).status,
    "BLOCKED",
  );
});

test("Linux failed load and verification independently restore only owned policy with separate first/cleanup causes", async () => {
  for (const settings of [
    { installFailure: true },
    { verified: false },
    { installFailure: true, removeFailure: true },
  ]) {
    const f = fixture(settings),
      record = await prepareLinuxNamespaces(
        CONTEXT,
        "/fixture",
        f.persist,
        f.options,
      );
    assert.equal(record.status, "BLOCKED");
    assert.equal(
      record.owned.status,
      settings.removeFailure ? "POSSIBLE" : "REMOVED",
    );
    assert.match(record.cause.detail, /ordinary-mapping, native=EACCES/u);
    assert.equal(
      record.cleanupCause?.code ?? null,
      settings.removeFailure ? "cleanup-unobserved" : null,
    );
    assert.equal(f.calls.at(-1), "remove");
    assert.doesNotMatch(
      JSON.stringify(f.records),
      /private parser text|private cleanup text/u,
    );
  }
});

test("Linux partial observation failures retain the first finite cause across persistence and cleanup", async () => {
  const failureOf = linuxNamespaceObservationFailure;
  const error = {
    code: "ENXIO",
    namespaceOutcome: { status: 1, signal: null },
  };
  const partial = {
    mode: "ordinary",
    ...linuxNamespaceProbeOutcome(error.namespaceOutcome),
  };
  const first = failureOf("trace-capture", "ordinary", error, [partial]);
  const completed = [observation().probes[0]];
  const timeout = { namespaceNativeCode: "ETIMEDOUT" };
  const nested = failureOf("journal-cursor", "nested", timeout, completed);
  const early = failureOf("trace-options", null, { code: "ENXIO" }, []);
  const abnormal = {
    status: null,
    signal: "SIGKILL",
    error: { code: "ETIMEDOUT" },
  };
  const probeFailure = failureOf(
    "probe",
    "ordinary",
    {
      code: abnormal.error.code,
      namespaceOutcome: abnormal,
    },
    [{ mode: "ordinary", ...linuxNamespaceProbeOutcome(abnormal) }],
  );
  for (const [failure, cleanupFailed, ownsPolicy = false] of [
    [first, false],
    [first, true],
    [first, true, true],
    [nested, false],
    [early, false],
    [probeFailure, true],
  ]) {
    const f = fixture({ removeFailure: ownsPolicy });
    let observed = false;
    f.options.effects.observe = async () => {
      if (ownsPolicy && !observed) {
        observed = true;
        return observation();
      }
      throw Object.assign(new Error("private stderr /private/fixture"), {
        namespaceObservationFailure: failure,
        namespaceCleanupFailed: cleanupFailed,
      });
    };
    const record = await prepareLinuxNamespaces(
      CONTEXT,
      "/fixture",
      f.persist,
      f.options,
    );
    assert.equal(record.status, "BLOCKED");
    assert.deepEqual(record.before, ownsPolicy ? observation() : null);
    assert.equal(record.after, null);
    assert.equal(record.owned?.status ?? null, ownsPolicy ? "LOADED" : null);
    assert.deepEqual(record.observationFailure, failure);
    assert.ok(Buffer.byteLength(record.cause.detail) <= 256);
    assert.equal(record.cleanupCause !== null, cleanupFailed);
    assert.doesNotMatch(
      JSON.stringify(f.records),
      /private stderr|\/private\/fixture/u,
    );
    if (ownsPolicy) f.options.effects.remove = async () => {};
    const recovered = await cleanupLinuxNamespaces(
      JSON.parse(JSON.stringify(record)),
      CONTEXT,
      true,
      f.persist,
      f.options,
    );
    assert.deepEqual(recovered.cause, record.cause);
    assert.equal(
      recovered.owned?.status ?? null,
      ownsPolicy ? "REMOVED" : null,
    );
    assert.equal(
      linuxNamespacePolicyRetired(recovered, CONTEXT),
      !cleanupFailed,
    );
    if (failure === first)
      assert.match(
        record.cause.detail,
        /exit=1.*ordinary-trace-capture, native=ENXIO/u,
      );
  }
  assert.equal(nested.outcome.exitCode, null);
  assert.equal(nested.outcome.timedOut, true);
  assert.equal(nested.probes.length, 1);
  assert.deepEqual(nested.probes[0], observation().probes[0]);
  assert.equal(early.outcome.timedOut, null);
  assert.equal(early.outcome.signal, "unknown");
  assert.deepEqual(early.probes, []);
  assert.equal(probeFailure.outcome.signal, "SIGKILL");
  assert.equal(probeFailure.outcome.timedOut, true);
  assert.throws(() => failureOf("private-stage", null, error, []));
  assert.throws(() =>
    failureOf("trace-capture", "ordinary", error, [partial, partial]),
  );
  const current = initialLinuxNamespacePreparation(CONTEXT);
  const { observationFailure, ...legacy } = current;
  legacy.schemaVersion = 1;
  assert.deepEqual(
    normalizeLinuxNamespacePreparation(legacy, CONTEXT),
    current,
  );
});

test("Linux policy recovery keeps original scope and refuses removal before independent native settlement", async () => {
  const f = fixture(),
    prepared = await prepareLinuxNamespaces(
      CONTEXT,
      "/fixture",
      f.persist,
      f.options,
    );
  const blocked = await cleanupLinuxNamespaces(
    prepared,
    CONTEXT,
    false,
    f.persist,
    f.options,
  );
  assert.equal(linuxNamespacePolicyRetired(blocked, CONTEXT), false);
  assert.equal(blocked.owned.status, "LOADED");
  assert.equal(
    linuxNamespaceProfileName({
      runAttempt: CONTEXT.runAttempt,
      runId: CONTEXT.runId,
      candidateSha: CONTEXT.candidateSha,
    }),
    prepared.owned.name,
  );
  assert.equal(blocked.cleanupCause.code, "cleanup-unobserved");
  assert.ok(!f.calls.includes("remove"));
  const restored = await cleanupLinuxNamespaces(
    blocked,
    CONTEXT,
    true,
    f.persist,
    f.options,
  );
  assert.equal(restored.owned.status, "REMOVED");
  assert.equal(restored.cleanupCause, null);
  assert.equal(linuxNamespacePolicyRetired(restored, CONTEXT), true);
  assert.throws(() => assertLinuxNamespacePreparation(restored, CONTEXT));
  await assert.rejects(
    cleanupLinuxNamespaces(
      prepared,
      { ...CONTEXT, runAttempt: "2" },
      true,
      f.persist,
      f.options,
    ),
  );
  const substituted = structuredClone(prepared);
  substituted.owned.name = "another-policy";
  assert.throws(() => normalizeLinuxNamespacePreparation(substituted, CONTEXT));
});

test("Linux fresh policy admission rejects altered installed bytes and effective kernel policy", async () => {
  const f = fixture(),
    record = await prepareLinuxNamespaces(
      CONTEXT,
      "/fixture",
      f.persist,
      f.options,
    );
  assert.equal(
    (await verifyLinuxNamespaces(record, CONTEXT, "/fixture", f.options))
      .status,
    "PASS",
  );
  for (const alter of [
    (value) => (value.executable.sha256 = "d".repeat(64)),
    (value) => (value.apparmor.abiSha256 = "d".repeat(64)),
    (value) => (value.sysctls.restrictedUserns = 0),
    (value) => (value.effectiveLabel = "unconfined"),
    (value) => (value.procVisible = false),
    (value) => (value.probes[0] = observation().probes[0]),
  ]) {
    const value = observation(true, "owned");
    alter(value);
    f.options.effects.observe = async () => value;
    await assert.rejects(
      verifyLinuxNamespaces(record, CONTEXT, "/fixture", f.options),
    );
  }
  assert.throws(() =>
    normalizeLinuxNamespacePreparation(
      { ...initialLinuxNamespacePreparation(CONTEXT), raw: "private" },
      CONTEXT,
    ),
  );
});

test("Linux namespace reporting retains unknown exit without inheriting successful package installation", () => {
  const report = {
    schemaVersion: 1,
    expectedSha: CONTEXT.candidateSha,
    checkoutSha: CONTEXT.candidateSha,
    platform: "linux",
    os: "linux",
    build: "synthetic",
    architecture: "x64",
    results: unavailableFeasibilityResults("linux", {
      code: "missing-record",
      detail: "The probe stage has not returned a complete report.",
    }),
  };
  const source = assessFeasibilityReport(report);
  assert.equal(linuxNamespaceSettlement(source, CONTEXT, "minimal"), true);
  const unsettled = structuredClone(source);
  unsettled.report.results[0].cleanup = {
    status: "UNCERTAIN",
    independent: false,
    emergency: false,
    elapsedMs: null,
    witnessSha256: null,
    cause: {
      code: "cleanup-unobserved",
      detail: "Independent native retirement is unavailable.",
    },
  };
  assert.equal(linuxNamespaceSettlement(unsettled, CONTEXT, "minimal"), false);
  const env = {
    NATIVE_CANDIDATE_SHA: CONTEXT.candidateSha,
    NATIVE_PLATFORM: "linux",
    GITHUB_RUN_ID: "42",
    GITHUB_RUN_ATTEMPT: "1",
    NATIVE_PREPARATION_CONCLUSION: "failure",
    NATIVE_PREPARATION_OPERATION: "linux-namespace-policy",
    NATIVE_PREPARATION_EXIT_CODE: "0",
    NATIVE_LINUX_NAMESPACE_EXIT_CODE: "",
    NATIVE_PREPARATION_CAUSE: JSON.stringify({
      code: "prerequisite-unavailable",
      detail:
        "prepare linux-namespace-policy: exit=unknown, signal=none, timeout=no; Unsupported installed policy.",
    }),
  };
  const result = assessFeasibilityPreparation(
    source,
    {
      expectedSha: CONTEXT.candidateSha,
      runId: CONTEXT.runId,
      runAttempt: CONTEXT.runAttempt,
      platform: "linux",
    },
    env,
  );
  assert.equal(result.report.results[0].status, "BLOCKED");
  assert.match(result.report.results[0].cause.detail, /exit=unknown/u);
});

test("both minimal workflows gate payloads and all workflows retain always-run owned-policy recovery", async () => {
  for (const name of [
    "native-feasibility.yml",
    "native-feasibility-acceptance.yml",
    "native-poc.yml",
    "native-poc-acceptance.yml",
  ]) {
    const source = await readFile(
      new URL(`../.github/workflows/${name}`, import.meta.url),
      "utf8",
    );
    assert.match(
      source,
      /namespace-ci\.js --stage cleanup --report (?:minimal|system|provider)/u,
    );
    assert.match(source, /linux-namespace-preparation\.json/u);
    if (name.startsWith("native-feasibility")) {
      assert.match(source, /steps\.namespace_linux\.conclusion == 'success'/u);
      assert.match(
        source,
        /namespace-ci\.js --stage prepare --report minimal/u,
      );
      assert.match(
        source,
        /NATIVE_LINUX_NAMESPACE_EXIT_CODE: \$\{\{ steps\.namespace_linux\.outputs\.exit_code \}\}/u,
      );
    }
  }
});
