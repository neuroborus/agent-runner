import assert from "node:assert/strict";
import test from "node:test";

import packageMetadata from "../package.json" with { type: "json" };
import {
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  main,
  parseSourceSession,
  RUNTIME_COMPATIBILITY_TOKEN,
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

function commandResult({
  pipelineId = "plan-execution",
  state = "DONE",
} = {}) {
  return {
    directoryPath: `/state/runs/${RUN_ID}`,
    run: {
      runId: RUN_ID,
      pipelineId,
      taskPath: "/task",
      pause: state === "WAITING_FOR_USER" ? { reason: "review_required" } : null,
      pipelineState: {
        workflowState: state,
        clarificationPath:
          pipelineId === "plan-execution" ? "/project/clarifications.md" : null,
        currentStep: state === "DONE" ? null : 2,
        findings:
          state === "WAITING_FOR_USER"
            ? [{ id: "R1", problem: "Review is incomplete." }]
            : [],
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
    startMcp() {
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
  assert.match(stdout.read(), /State: WAITING_FOR_USER/u);
  assert.match(stdout.read(), /Pause: review_required/u);
  assert.match(stdout.read(), /R1: Review is incomplete\./u);
  assert.match(stdout.read(), /Finalized fingerprint: a{12}/u);
  assert.match(stdout.read(), /Commits: b{12}/u);
  assert.match(stdout.read(), /State directory:/u);
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
  assert.match(stdout.read(), /Pause: review_required/u);
  assert.equal(stderr.read(), "");
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
      [DETACHED_RUNTIME_COMPATIBILITY_ENV]:
        `${RUNTIME_COMPATIBILITY_TOKEN}-old`,
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
    `${RUNTIME_COMPATIBILITY_TOKEN}-old`,
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
