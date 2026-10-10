import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import {
  buildWindowsAuditHelpers,
  assessWindowsAuditBuilds,
  feasibilityFailureCause,
} from "../ci/native/feasibility/index.js";
import { windowsFeasibilityDiagnostics } from "../ci/native/win32/index.js";

const PIN = "a".repeat(64);
const context = { candidateSha: "b".repeat(40), runId: "7", runAttempt: "1" };
const build = { helperSha256: PIN, sdkSha256: PIN, abiSha256: PIN };
const read = (file) => readFile(new URL("../" + file, import.meta.url), "utf8");
const native = (file) => read("ci/native/win32/" + file);
const tool = (name) => ({ role: "tool", name, version: "1", sha256: PIN });

async function record(failed, failure, attempted = []) {
  const builder = (variant) => async (root, components, signal, options) => {
    attempted.push(variant);
    assert.equal(options.environment.LOCALAPPDATA, undefined);
    assert.ok(root.endsWith("audit-build-" + variant));
    assert.equal(signal, undefined);
    components.push(tool("windows-sdk-header"));
    if (failed === variant || failed === "both")
      throw { feasibilityCause: failure, message: "private output" };
    const sources =
      variant === "command"
        ? ["source", "header", "xml"]
        : ["source", "header", "account", "policy"];
    for (const name of [
      "msvc",
      "msvc-linker",
      "windows-audit-removal-source",
      ...sources.map((name) => "windows-" + variant + "-" + name),
    ])
      components.push(tool(name));
    const name =
      variant === "command"
        ? "windows-command-helper"
        : "windows-custody-reader";
    components.push({ role: "helper", name, version: "1", sha256: PIN });
    return build;
  };
  return buildWindowsAuditHelpers(
    { directory: "C:\\fixture", environment: {}, context },
    {
      create: async (_, options) => assert.equal(options.mode, 0o700),
      command: builder("command"),
      custody: builder("custody"),
    },
  );
}

test("build-only verification attempts both variants and retains bounded partial failure evidence", async () => {
  const cause = feasibilityFailureCause("command", "helper-link", {
    code: 2,
    signal: null,
    stdout: "private path",
    stderr: "unit.obj : error LNK2019: unresolved external symbol routine",
  });
  for (const failed of [null, "command", "custody", "both"]) {
    const attempted = [],
      result = await record(failed, cause, attempted);
    assert.deepEqual(attempted, ["command", "custody"]);
    const { passed, summary } = assessWindowsAuditBuilds(result, context);
    assert.equal(passed, failed === null);
    assert.match(summary, /Neither helper was executed/u);
    assert.doesNotMatch(summary, /private output|private path|C:\\/u);
    if (failed) {
      const failure = result.results.find((entry) => entry.status === "FAIL");
      assert.match(failure.cause.detail, /LNK2019/u);
      assert.equal(failure.build, null);
      assert.equal(failure.components.length, 1);
    }
  }
  for (const error of [{ timedOut: true }, { signal: "SIGABRT" }]) {
    const failure = feasibilityFailureCause("command", "helper-compile", error);
    const result = await record("command", failure);
    assert.equal(assessWindowsAuditBuilds(result, context).passed, false);
    assert.deepEqual(result.results[0].cause, failure);
  }
});

test("build reports refuse candidate drift, missing variants and unbound successful images", async () => {
  const result = await record(null);
  for (const mutate of [
    (v) => (v.candidateSha = "c".repeat(40)),
    (v) => (v.runAttempt = "2"),
    (v) => v.results.pop(),
    (v) => v.results.reverse(),
    (v) => v.results[0].components.pop(),
    (v) => v.results[1].components.splice(2, 1),
    (v) => (v.results[0].build.helperSha256 = "d".repeat(64)),
  ]) {
    const changed = structuredClone(result);
    mutate(changed);
    assert.throws(() => assessWindowsAuditBuilds(changed, context));
  }
});

test("both retirement-gated audit owners use only the shared SID removal and requery their baselines", async () => {
  const command = await native("feasibility-command.h"),
    reader = await native("effective-reader.h");
  for (const source of [command, reader]) {
    assert.match(source, /#include "audit-policy-remove\.h"/u);
    assert.doesNotMatch(source, /AuditDeletePerUserPolicy/u);
  }
  const restore = reader.slice(
    reader.indexOf("static void audit_restore("),
    reader.indexOf("\n#endif"),
  );
  const removal = restore.indexOf("audit_remove_owned_policy");
  for (const prerequisite of [
    "!helpers[0].process",
    "WaitForSingleObject(processes[i], 0) == WAIT_OBJECT_0",
    "principal[i].AuditingInformation == expected",
  ]) {
    const before = restore.indexOf(prerequisite);
    assert.ok(before >= 0 && before < removal);
  }
  assert.match(restore, /audit_remove_owned_policy\(audit_sid, &removal\)/u);
  assert.match(
    restore,
    /need\(!audit_principal_exists\(audit_sid\)\)[\s\S]*AuditQuerySystemPolicy/u,
  );
  assert.match(
    command,
    /command_owned_policy\(authorized==WAIT_OBJECT_0\)==policyPresent[\s\S]*audit_remove_owned_policy\(userSid,&removal\)[\s\S]*need\(!command_principal_exists\(\)\);command_policy_equal\(\)/u,
  );
  assert.match(
    command,
    /remember\("audit-remove","win32",removal.error\?removal.error:removal.cleanup\)/u,
  );
  assert.match(
    command,
    /cleanup_error\("audit-remove-settle","win32",removal.cleanup\)/u,
  );
  const diagnosis = windowsFeasibilityDiagnostics(
    "native-windows: operation=audit-remove domain=win32 value=1460\n" +
      "native-windows-cleanup: operation=audit-remove-settle domain=win32 value=5\n",
  );
  assert.equal(diagnosis.failure.value, 1460);
  assert.equal(diagnosis.cleanup.value, 5);
});

test("shared auditpol transport confines its SID/image, bounds output and independently settles handles", async () => {
  const source = await native("audit-policy-remove.h");
  assert.match(source, /GetSidSubAuthorityCount\(sid\) == 5/u);
  assert.match(source, /GetSidSubAuthority\(sid, 0\) == 21/u);
  assert.match(source, /ConvertSidToStringSidW\(sid, &sidText\)/u);
  assert.match(source, /L"\\"%ls\\" \/remove \/user:\{%ls\}"/u);
  assert.doesNotMatch(source, /O:SY|G:SY|SE_RESTORE_NAME/u);
  assert.match(
    source,
    /header->AceSize < sidOffset \+ 8[\s\S]*DWORD mask = ace->Mask/u,
  );
  assert.doesNotMatch(
    source,
    /\/allusers|AuditSetPerUserPolicy|GetEnvironmentStringsW|ShellExecute|system\(/u,
  );
  for (const control of [
    "GetSystemDirectoryW",
    "audit_remove_security(image, FALSE)",
    "FILE_FLAG_OPEN_REPARSE_POINT",
    "FILE_SHARE_READ",
    "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
    "PROC_THREAD_ATTRIBUTE_JOB_LIST",
    "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
    "CREATE_UNICODE_ENVIRONMENT",
  ])
    assert.ok(source.includes(control));
  const launch = source.indexOf("CreateProcessW("),
    release = source.indexOf("ResumeThread(");
  assert.ok(
    launch < source.indexOf("QueryFullProcessImageNameW(") &&
      source.indexOf("memcmp(&before, &after") < release,
  );
  assert.match(source, /count > 65536 - total/u);
  assert.match(source, /GetTickCount64\(\) \+ 10000/u);
  assert.match(
    source,
    /if \(wait == WAIT_FAILED\) audit_remove_error\(&result->cleanup, GetLastError\(\)\);[\s\S]*TerminateJobObject\(job, 126\)[\s\S]*WaitForSingleObject\(child.hProcess, 5000\)/u,
  );
  assert.match(source, /if \(!accounting.ActiveProcesses\) break/u);
  assert.match(
    source,
    /closing\[\] = \{child.hThread, child.hProcess, writer, output, input, loaded, image, job\}/u,
  );
  assert.match(source, /return !result->error && !result->cleanup/u);
  assert.doesNotMatch(source, /(?:printf|fprintf|puts)\(/u);
});

test("both feasibility workflows run independent build-only verification and report missing or failed builds", async () => {
  for (const name of [
    "native-feasibility.yml",
    "native-feasibility-acceptance.yml",
  ]) {
    const workflow = await read(".github/workflows/" + name);
    const begin = workflow.indexOf("id: build_windows"),
      end = workflow.indexOf("id: probe", begin);
    assert.ok(begin > 0 && end > begin);
    const stage = workflow.slice(begin, end);
    assert.match(stage, /steps.prepare_windows.conclusion == 'success'/u);
    assert.match(stage, /continue-on-error: true/u);
    assert.match(stage, /--stage build-windows/u);
    assert.doesNotMatch(
      stage,
      /prepare-inputs|review-sha|LOCALAPPDATA|native-launch/u,
    );
  }
  const ci = await read("ci/native/feasibility/ci.js");
  assert.match(
    ci,
    /stage === "build-windows"[\s\S]*assertFeasibilityRevision[\s\S]*buildWindowsAuditHelpers/u,
  );
  assert.match(ci, /assessWindowsAuditBuilds[\s\S]*windows-audit-builds.json/u);
  assert.match(ci, /stage !== "report" \|\| auditBuildsPassed/u);
});
