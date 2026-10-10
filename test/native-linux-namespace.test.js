import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { readFile } from "node:fs/promises";
import {
  assertLinuxNamespacePreparation,
  cleanupLinuxNamespaces,
  initialLinuxNamespacePreparation,
  linuxNamespaceDenials,
  linuxNamespaceDiagnosticReplay,
  linuxNamespacePolicyDecision,
  linuxNamespacePolicyRetired,
  linuxNamespaceSettlement,
  linuxNamespaceProfile,
  linuxNamespaceProfileName,
  linuxNamespaceProfileMembership,
  normalizeLinuxNamespacePreparation,
  prepareLinuxNamespaces,
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
    '101 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0\n101 clone(child_stack=NULL, flags=CLONE_NEWUSER|SIGCHLD) = 102\n102 unshare(CLONE_NEWUSER) = 0\n';
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
    '101 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0\n101 clone(child_stack=NULL, flags=CLONE_NEWUSER|SIGCHLD) = 102\n102 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n102 <... clone resumed>) = 1\n103 capset({version=_LINUX_CAPABILITY_VERSION_3}, NULL) = -1 EPERM\n';
  assert.deepEqual(linuxNamespaceDenials(nested, message(103), name), [
    { operation: "capable", label: "restricted-userns", capability: "setuid" },
  ]);
  assert.deepEqual(linuxNamespaceDenials(nested, message(1), name), []);
  assert.deepEqual(
    linuxNamespaceDenials(
      trace + '102 execve("/bin/true", ["true"], 0x0) = 0\n',
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

test("Linux diagnostic replay captures inherited stderr with host PID prefixes without reopening sockets", () => {
  const trace =
    '[pid 101] execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0\n' +
    "bwrap: setting up uid map: Permission denied\n" +
    "[pid 102] capset({version=_LINUX_CAPABILITY_VERSION_3}, NULL) = -1 EPERM\n";
  const replay = linuxNamespaceDiagnosticReplay(
    "/usr/bin/bwrap",
    ["--", "/bin/true"],
    { timeout: 10000 },
    (file, args, options) => {
      assert.equal(file, "/usr/bin/strace");
      assert.ok(args.includes("--always-show-pid"));
      assert.deepEqual(args.slice(args.indexOf("--") + 1), [
        "/usr/bin/bwrap",
        "--",
        "/bin/true",
      ]);
      // Only transport is real: a fixed Node child substitutes for strace and
      // writes to its inherited stderr. No namespace or policy is inspected.
      const source =
        'const fs = require("node:fs"); const [trace, output] = process.argv.slice(1); ' +
        'if (output) { const fd = fs.openSync(output, "w"); fs.writeSync(fd, trace); fs.closeSync(fd); } ' +
        "else fs.writeSync(2, trace); process.exitCode = 1;";
      return spawnSync(
        process.execPath,
        [
          "-e",
          source,
          trace,
          ...(args.includes("-o") ? [args[args.indexOf("-o") + 1]] : []),
        ],
        options,
      );
    },
  );
  assert.equal(replay.result.status, 1);
  assert.equal(replay.result.error, undefined);
  assert.equal(replay.trace, trace);
  const journal = JSON.stringify({
    MESSAGE:
      'audit: apparmor="DENIED" operation="capable" profile="unprivileged_userns" pid=102 comm="bwrap" capability=7 capname="setuid"',
  });
  assert.deepEqual(
    linuxNamespaceDenials(
      replay.trace,
      journal,
      linuxNamespaceProfileName(CONTEXT),
    ),
    [
      {
        operation: "capable",
        label: "restricted-userns",
        capability: "setuid",
      },
    ],
  );
  assert.deepEqual(
    linuxNamespaceDenials(
      replay.trace + '[pid 102] execve("/bin/true", ["true"], 0x0) = 0\n',
      journal,
      linuxNamespaceProfileName(CONTEXT),
    ),
    [],
  );
  assert.throws(() =>
    linuxNamespaceDiagnosticReplay("/usr/bin/bwrap", [], {}, () => ({
      stderr: "x".repeat(65537),
    })),
  );
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
