import assert from "node:assert/strict";
import test from "node:test";

import packageMetadata from "../package.json" with { type: "json" };
import {
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  main,
  parseSourceSession,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  RunnerError,
} from "../src/index.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";

function createSink() {
  let value = "";

  return {
    stream: {
      write(chunk) {
        value += chunk;
      },
    },
    read() {
      return value;
    },
  };
}

function commandResult({ pipelineId = "plan-execution", state = "DONE" } = {}) {
  return {
    directoryPath: `/state/runs/${RUN_ID}`,
    run: {
      runId: RUN_ID,
      pipelineId,
      taskPath: "/task",
      pause:
        state === "WAITING_FOR_USER"
          ? { reason: "fix_limit_reached", resumeState: "IMPLEMENT" }
          : null,
      pipelineState: {
        workflowState: state,
        pendingEdit: null,
        preflightComplete: state === "WAITING_FOR_USER",
        clarificationPath:
          pipelineId === "plan-execution" ? "/project/clarifications.md" : null,
        currentStep: state === "DONE" ? null : 2,
        additionalFixRounds: 0,
        settings: { maxFixRoundsPerStep: 5, mode: "independent" },
        finalizationResult:
          state === "WAITING_FOR_USER" ? { status: "PASS" } : null,
        findings:
          state === "WAITING_FOR_USER"
            ? [{ id: "R1", problem: "Review is incomplete." }]
            : [],
        findingOverrides: [],
        finalizedFingerprint: "a".repeat(64),
        reviewedFingerprint: "a".repeat(64),
        completedCommits: ["b".repeat(40)],
      },
    },
  };
}

function fakeRunner(overrides = {}) {
  return {
    async run() {
      return commandResult();
    },
    async resume() {
      return commandResult();
    },
    async status() {
      return commandResult();
    },
    ...overrides,
  };
}

test("help describes the required commands", async () => {
  const stdout = createSink();
  const stderr = createSink();

  const exitCode = await main(["--help"], {
    stdout: stdout.stream,
    stderr: stderr.stream,
  });

  assert.equal(exitCode, 0);
  assert.match(stdout.read(), /agent-run run <pipeline> --project/);
  assert.match(stdout.read(), /agent-run resume --run/);
  assert.match(stdout.read(), /agent-run status --run/);
  assert.match(stdout.read(), /agent-run mcp/);
  assert.match(stdout.read(), /plan-authoring/);
  assert.match(stdout.read(), /plan-execution/);
  assert.match(stdout.read(), /polishing/);
  assert.match(stdout.read(), /--clarify/);
  assert.match(stdout.read(), /--mode/);
  assert.match(stdout.read(), /independent is default and recommended/u);
  assert.match(stdout.read(), /more context and tokens/u);
  assert.match(stdout.read(), /lazy is opt-in/u);
  assert.match(stdout.read(), /no independent review/u);
  assert.match(
    stdout.read(),
    /independent forks primary and review roles separately/u,
  );
  assert.match(stdout.read(), /lazy forks once into the primary role/u);
  assert.doesNotMatch(stdout.read(), /unexpected_issue_report|issue report/iu);
  assert.equal(stderr.read(), "");
});

test("mcp dispatches the STDIO server without constructing a runner", async () => {
  const stdout = createSink();
  const stderr = createSink();
  const calls = [];

  const exitCode = await main(["mcp"], {
    stdout: stdout.stream,
    stderr: stderr.stream,
    startMcp(options) {
      calls.push(options);
    },
  });

  assert.equal(exitCode, 0);
  assert.equal(stdout.read(), "");
  assert.equal(stderr.read(), "");
  assert.deepEqual(calls, [{ stderr: stderr.stream }]);
});

test("mcp reports a bounded startup failure on stderr", async () => {
  const stdout = createSink();
  const stderr = createSink();

  const exitCode = await main(["mcp"], {
    stdout: stdout.stream,
    stderr: stderr.stream,
    async startMcp() {
      throw new Error("sensitive startup detail");
    },
  });

  assert.equal(exitCode, 1);
  assert.equal(stdout.read(), "");
  assert.equal(stderr.read(), "Agent Runner MCP failed to start.\n");
});

test("unknown commands fail with usage", async () => {
  const stdout = createSink();
  const stderr = createSink();

  const exitCode = await main(["launch"], {
    stdout: stdout.stream,
    stderr: stderr.stream,
  });

  assert.equal(exitCode, 1);
  assert.equal(stdout.read(), "");
  assert.match(stderr.read(), /Unknown command: launch/);
});

for (const args of [
  ["status", "extra"],
  ["run", "plan-authoring", "extra"],
]) {
  test(`unexpected positional argument fails: ${args.join(" ")}`, async () => {
    const stdout = createSink();
    const stderr = createSink();

    const exitCode = await main(args, {
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    assert.equal(exitCode, 1);
    assert.equal(stdout.read(), "");
    assert.match(stderr.read(), /Unexpected argument: extra/);
  });
}

test("version comes from package metadata", async () => {
  const stdout = createSink();
  const stderr = createSink();

  const exitCode = await main(["--version"], {
    stdout: stdout.stream,
    stderr: stderr.stream,
  });

  assert.equal(exitCode, 0);
  assert.equal(stdout.read(), `${packageMetadata.version}\n`);
  assert.equal(stderr.read(), "");
});

for (const args of [["--bogus"], ["status", "--bogus"]]) {
  test(`unknown option fails: ${args.join(" ")}`, async () => {
    const stdout = createSink();
    const stderr = createSink();

    const exitCode = await main(args, {
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    assert.equal(exitCode, 1);
    assert.equal(stdout.read(), "");
    assert.match(stderr.read(), /Unknown option '--bogus'/);
  });
}

for (const args of [
  ["--project", "/tmp/project"],
  ["--task", "/tmp/task"],
  ["--run", "run-id"],
  ["--worker", "codex"],
  ["--clarify"],
]) {
  test(`command option without a command fails: ${args.join(" ")}`, async () => {
    const stdout = createSink();
    const stderr = createSink();

    const exitCode = await main(args, {
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    assert.equal(exitCode, 1);
    assert.equal(stdout.read(), "");
    assert.match(stderr.read(), /Missing command/);
  });
}

for (const args of [
  ["status", "--project", "/tmp/project"],
  ["resume", "--reviewer", "claude"],
  ["run", "plan-execution", "--extra-fix-rounds", "1"],
  ["run", "plan-authoring", "--worker", "codex"],
  ["run", "plan-execution", "--planner", "codex"],
  ["status", "--run", "run-id", "--clarify"],
  ["resume", "--run", "run-id", "--fork-from", "codex:source"],
]) {
  test(`command rejects an unrelated option: ${args.join(" ")}`, async () => {
    const stdout = createSink();
    const stderr = createSink();

    const exitCode = await main(args, {
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    assert.equal(exitCode, 1);
    assert.equal(stdout.read(), "");
    assert.match(stderr.read(), /is not valid for/);
  });
}

test("status dispatches and renders concise persisted state", async () => {
  const stdout = createSink();
  const stderr = createSink();
  let requestedRunId;

  const exitCode = await main(["status", "--run", RUN_ID], {
    stdout: stdout.stream,
    stderr: stderr.stream,
    runner: fakeRunner({
      async status(runId) {
        requestedRunId = runId;
        return commandResult({ state: "WAITING_FOR_USER" });
      },
    }),
  });

  assert.equal(exitCode, 0);
  assert.equal(requestedRunId, RUN_ID);
  assert.match(stdout.read(), new RegExp(`Run: ${RUN_ID}`, "u"));
  assert.match(stdout.read(), /Mode: independent/u);
  assert.match(stdout.read(), /State: WAITING_FOR_USER/u);
  assert.match(stdout.read(), /Pause: fix_limit_reached/u);
  assert.match(stdout.read(), /Explanation: The current step reached/u);
  assert.match(stdout.read(), /--extra-fix-rounds 1/u);
  assert.match(stdout.read(), /--override-finding R1/u);
  assert.match(stdout.read(), /R1: Review is incomplete\./u);
  assert.match(stdout.read(), /Finalized fingerprint: a{12}/u);
  assert.match(stdout.read(), /Commits: b{12}/u);
  assert.match(stdout.read(), /State directory:/u);
  assert.equal(stderr.read(), "");
});

test("renders bounded finalization correction activity without rejected content", async () => {
  const stdout = createSink();
  const stderr = createSink();
  const activity = {
    actor: "worker",
    phase: "finalization",
    kind: "finalization-correction",
    message:
      "worker must correct finalization field requiredChecks[2].command (staging-independent-validation-command).",
  };

  const exitCode = await main(
    [
      "run",
      "plan-execution",
      "--project",
      "/tmp/project",
      "--task",
      "/tmp/task",
    ],
    {
      stdout: stdout.stream,
      stderr: stderr.stream,
      createCommandRunner({ onActivity }) {
        return fakeRunner({
          async run() {
            await onActivity(activity);
            return commandResult();
          },
        });
      },
    },
  );

  assert.equal(exitCode, 0);
  assert.match(
    stdout.read(),
    /^\[worker\/finalization\] worker must correct finalization field requiredChecks\[2\]\.command \(staging-independent-validation-command\)\./u,
  );
  assert.doesNotMatch(
    stdout.read(),
    /git status|DO_NOT_PERSIST|provider|transcript/u,
  );
  assert.equal(stderr.read(), "");
});

for (const pipeline of ["plan-authoring", "plan-execution", "polishing"]) {
  test(`run ${pipeline} dispatches --clarify`, async () => {
    const stdout = createSink();
    const stderr = createSink();
    let request;

    const exitCode = await main(
      [
        "run",
        pipeline,
        "--project",
        "/tmp/project",
        "--task",
        "/tmp/task",
        "--clarify",
      ],
      {
        stdout: stdout.stream,
        stderr: stderr.stream,
        runner: fakeRunner({
          async run(input) {
            request = input;
            return commandResult({ pipelineId: pipeline });
          },
        }),
      },
    );

    assert.equal(exitCode, 0);
    assert.equal(request.pipelineId, pipeline);
    assert.equal(request.proactiveClarification, true);
    assert.match(stdout.read(), /State: DONE/u);
    assert.equal(stderr.read(), "");
  });
}

test("run derives execution, role, and opaque source-session inputs", async () => {
  const stdout = createSink();
  const stderr = createSink();
  let request;

  const exitCode = await main(
    [
      "run",
      "plan-execution",
      "--project",
      "/tmp/project",
      "--task",
      "/tmp/task",
      "--worker",
      "claude",
      "--worker-model",
      "sonnet",
      "--worker-profile",
      "claude-primary",
      "--worker-context-size",
      "300000",
      "--reviewer",
      "claude",
      "--reviewer-profile",
      "claude-primary",
      "--arbiter",
      "codex",
      "--profile",
      "claude-primary",
      "--model",
      "run-model",
      "--context-size",
      "200000",
      "--mode",
      "lazy",
      "--project-config",
      "/tmp/project/ignored/runner.json",
      "--fork-from",
      "claude:source:opaque",
      "--fork-profile",
      "claude-primary",
    ],
    {
      stdout: stdout.stream,
      stderr: stderr.stream,
      runner: fakeRunner({
        async run(input) {
          request = input;
          return commandResult();
        },
      }),
    },
  );

  assert.equal(exitCode, 0);
  assert.deepEqual(request.roleOverrides, {
    worker: {
      backend: "claude",
      profile: "claude-primary",
      model: "sonnet",
      contextSize: "300000",
    },
    reviewer: { backend: "claude", profile: "claude-primary" },
    arbiter: { backend: "codex" },
  });
  assert.deepEqual(request.executionOverrides, {
    profile: "claude-primary",
    model: "run-model",
    contextSize: "200000",
  });
  assert.deepEqual(request.settingOverrides, { mode: "lazy" });
  assert.equal(
    request.projectConfigurationPath,
    "/tmp/project/ignored/runner.json",
  );
  assert.deepEqual(request.sourceSession, {
    backend: "claude",
    id: "source:opaque",
    profile: "claude-primary",
  });
  assert.equal(stderr.read(), "");
});

test("run rejects an invalid pipeline mode", async () => {
  const stderr = createSink();
  let invoked = false;

  const exitCode = await main(
    [
      "run",
      "plan-authoring",
      "--project",
      "/tmp/project",
      "--task",
      "/tmp/task",
      "--mode",
      "automatic",
    ],
    {
      stdout: createSink().stream,
      stderr: stderr.stream,
      runner: fakeRunner({
        async run() {
          invoked = true;
          return commandResult({ pipelineId: "plan-authoring" });
        },
      }),
    },
  );

  assert.equal(exitCode, 1);
  assert.equal(invoked, false);
  assert.match(stderr.read(), /--mode must be independent or lazy/u);
});

test("fork profile requires a source session", async () => {
  const stderr = createSink();

  assert.equal(
    await main(
      [
        "run",
        "plan-authoring",
        "--project",
        "/tmp/project",
        "--task",
        "/tmp/task",
        "--fork-profile",
        "codex-work",
      ],
      {
        stdout: createSink().stream,
        stderr: stderr.stream,
        runner: fakeRunner(),
      },
    ),
    1,
  );
  assert.match(stderr.read(), /--fork-profile requires --fork-from/u);
});

test("resume dispatches one validated action and preserves pause exit", async () => {
  const stdout = createSink();
  const stderr = createSink();
  let request;

  const exitCode = await main(
    ["resume", "--run", RUN_ID, "--extra-fix-rounds", "3"],
    {
      stdout: stdout.stream,
      stderr: stderr.stream,
      runner: fakeRunner({
        async resume(input) {
          request = input;
          return commandResult({ state: "WAITING_FOR_USER" });
        },
      }),
    },
  );

  assert.equal(exitCode, 2);
  assert.deepEqual(request, {
    runId: RUN_ID,
    action: { type: "extra-fix-rounds", amount: 3 },
  });
  assert.match(stdout.read(), /Pause: fix_limit_reached/u);
  assert.equal(stderr.read(), "");
});

test("status renders bounded pause details without private provider data", async () => {
  const stdout = createSink();
  const result = commandResult({ state: "WAITING_FOR_USER" });
  result.run.pause = {
    reason: "environment_blocked",
    code: "ERR_LOOPBACK_UNAVAILABLE",
    explanation: "Check C2 cannot bind a loopback listener.",
    evidence: ["C2: listener creation was denied."],
    resumeState: "IMPLEMENT",
    prompt: "private prompt",
    transcript: "private transcript",
    rawStderr: "private stderr",
  };
  result.run.pipelineState.findings = [];

  assert.equal(
    await main(["status", "--run", RUN_ID], {
      stdout: stdout.stream,
      stderr: createSink().stream,
      runner: fakeRunner({
        async status() {
          return result;
        },
      }),
    }),
    0,
  );

  assert.match(stdout.read(), /Pause: environment_blocked/u);
  assert.match(stdout.read(), /Pause code: ERR_LOOPBACK_UNAVAILABLE/u);
  assert.match(stdout.read(), /Check C2 cannot bind a loopback listener/u);
  assert.match(stdout.read(), /C2: listener creation was denied/u);
  assert.match(stdout.read(), /Resume state: IMPLEMENT/u);
  assert.match(stdout.read(), /agent-run resume --run/u);
  assert.doesNotMatch(
    stdout.read(),
    /private prompt|private transcript|private stderr/u,
  );
});

test("status explains a terminal forbidden-delegation diagnostic", async () => {
  const stdout = createSink();
  const result = commandResult({ state: "FAILED" });
  result.run.pause = {
    reason: "internal_failure",
    code: "ERR_CODEX_ISOLATION",
    diagnosticClass: "operation_multi_agent",
  };

  assert.equal(
    await main(["status", "--run", RUN_ID], {
      stdout: stdout.stream,
      stderr: createSink().stream,
      runner: fakeRunner({
        async status() {
          return result;
        },
      }),
    }),
    0,
  );

  assert.match(stdout.read(), /Pause code: ERR_CODEX_ISOLATION/u);
  assert.match(
    stdout.read(),
    /Plan execution failed\. Adapter diagnostic: operation_multi_agent\./u,
  );
});

test("status renders input and fresh-run pause actions", async () => {
  for (const { pause, state, expected, alsoExpected, notExpected } of [
    {
      pause: {
        reason: "clarification_answers_required",
        inputRequest: { id: "edit-1" },
      },
      state: { pendingEdit: { id: "edit-1" } },
      expected: /Respond to pending input edit-1 through MCP/u,
    },
    {
      pause: {
        reason: "plan_revision_required",
        explanation: "The accepted clarification conflicts with Commit 2.",
        evidence: ["The plan requires the opposite behavior."],
      },
      state: {},
      expected: /Revise the plan and start a fresh plan-execution run/u,
    },
    {
      pause: {
        reason: "read_only_agent_mutated_repository",
        code: "ERR_READ_ONLY_REPOSITORY_CHANGED",
      },
      state: {},
      expected: /Abandon this run and start a fresh run/u,
    },
    {
      pause: {
        reason: "no_progress",
        resumeState: "RESOLVE_FINDINGS",
        evidence: ["PRIVATE_PAUSE_EVIDENCE"],
      },
      state: {
        settings: { maxFixRoundsPerStep: 5, mode: "lazy" },
        finalizationResult: {
          status: "FAIL",
          issues: [
            {
              id: "F4",
              command: "PRIVATE_FINALIZATION_COMMAND",
              problem: "PRIVATE_FINALIZATION_PROBLEM",
              evidence: ["PRIVATE_FINALIZATION_EVIDENCE"],
            },
          ],
        },
        findings: [],
        reviewedFingerprint: null,
        validationMigrationPending: false,
      },
      expected:
        /Resolve the reported finalization blockers, restore a clean baseline, prepare a plan for the remaining work, and start a fresh plan-execution run\./u,
      alsoExpected: /Finalization blocker F4 remains unresolved\./u,
      notExpected:
        /PRIVATE_PAUSE_EVIDENCE|PRIVATE_FINALIZATION_COMMAND|PRIVATE_FINALIZATION_PROBLEM|PRIVATE_FINALIZATION_EVIDENCE/u,
    },
  ]) {
    const stdout = createSink();
    const result = commandResult({ state: "WAITING_FOR_USER" });
    result.run.pause = pause;
    Object.assign(result.run.pipelineState, state);
    assert.equal(
      await main(["status", "--run", RUN_ID], {
        stdout: stdout.stream,
        stderr: createSink().stream,
        runner: fakeRunner({
          async status() {
            return result;
          },
        }),
      }),
      0,
    );
    assert.match(stdout.read(), expected);
    if (alsoExpected !== undefined) {
      assert.match(stdout.read(), alsoExpected);
    }
    if (notExpected !== undefined) {
      assert.doesNotMatch(stdout.read(), notExpected);
    }
  }
});

test("resume dispatches one finding override", async () => {
  let request;
  const exitCode = await main(
    ["resume", "--run", RUN_ID, "--override-finding", "R7"],
    {
      stdout: createSink().stream,
      stderr: createSink().stream,
      runner: fakeRunner({
        async resume(input) {
          request = input;
          return commandResult();
        },
      }),
    },
  );

  assert.equal(exitCode, 0);
  assert.deepEqual(request.action, {
    type: "override-finding",
    findingId: "R7",
  });
});

test("detached resume rejects runtime skew with a distinct exit code", async () => {
  let request;
  const stderr = createSink();
  const exitCode = await main(["resume", "--run", RUN_ID], {
    environment: {
      [DETACHED_RUNTIME_COMPATIBILITY_ENV]: `${DETACHED_RUNTIME_COMPATIBILITY_TOKEN}-old`,
    },
    stdout: createSink().stream,
    stderr: stderr.stream,
    runner: fakeRunner({
      async resume(input) {
        request = input;
        const error = new Error("Runtime mismatch.");
        error.code = "ERR_RUNTIME_VERSION_SKEW";
        throw error;
      },
    }),
  });

  assert.equal(exitCode, RUNTIME_VERSION_SKEW_EXIT_CODE);
  assert.equal(
    request.expectedRuntimeCompatibility,
    `${DETACHED_RUNTIME_COMPATIBILITY_TOKEN}-old`,
  );
  assert.match(stderr.read(), /Runtime mismatch/u);
});

test("resume rejects conflicting or invalid fix actions", async () => {
  for (const args of [
    ["resume", "--run", RUN_ID, "--extra-fix-rounds", "0"],
    [
      "resume",
      "--run",
      RUN_ID,
      "--extra-fix-rounds",
      "1",
      "--override-finding",
      "R1",
    ],
  ]) {
    const stderr = createSink();
    assert.equal(
      await main(args, {
        stdout: createSink().stream,
        stderr: stderr.stream,
        runner: fakeRunner(),
      }),
      1,
    );
    assert.notEqual(stderr.read(), "");
  }
});

test("source-session parsing keeps the ID opaque", () => {
  assert.deepEqual(parseSourceSession("codex:thread:with:colons"), {
    backend: "codex",
    id: "thread:with:colons",
  });
  for (const value of ["", "codex:", "other:source", "source"]) {
    assert.throws(
      () => parseSourceSession(value),
      (error) =>
        error instanceof RunnerError &&
        error.code === "ERR_INVALID_SOURCE_SESSION",
    );
  }
});

test("run requires a known pipeline", async () => {
  const stdout = createSink();
  const stderr = createSink();

  assert.equal(
    await main(["run"], { stdout: stdout.stream, stderr: stderr.stream }),
    1,
  );
  assert.match(stderr.read(), /Missing pipeline/);

  const unknownStderr = createSink();
  assert.equal(
    await main(["run", "unknown"], {
      stdout: stdout.stream,
      stderr: unknownStderr.stream,
    }),
    1,
  );
  assert.match(unknownStderr.read(), /Unknown pipeline: unknown/);
});

for (const { args, missingOption } of [
  {
    args: ["run", "plan-authoring", "--task", "/tmp/task"],
    missingOption: "project",
  },
  {
    args: ["run", "plan-execution", "--project", "/tmp/project"],
    missingOption: "task",
  },
  { args: ["resume"], missingOption: "run" },
  { args: ["status"], missingOption: "run" },
]) {
  test(`${args[0]} requires --${missingOption}`, async () => {
    const stdout = createSink();
    const stderr = createSink();

    const exitCode = await main(args, {
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    assert.equal(exitCode, 1);
    assert.equal(stdout.read(), "");
    assert.match(
      stderr.read(),
      new RegExp(`Missing required option '--${missingOption}'`, "u"),
    );
  });
}

test("pipelines lists the statically registered pipelines", async () => {
  const stdout = createSink();
  const stderr = createSink();

  const exitCode = await main(["pipelines"], {
    stdout: stdout.stream,
    stderr: stderr.stream,
  });

  assert.equal(exitCode, 0);
  assert.match(stdout.read(), /^plan-authoring\t/mu);
  assert.match(stdout.read(), /^plan-execution\t/mu);
  assert.match(stdout.read(), /^polishing\t/mu);
  assert.equal(stderr.read(), "");
});
