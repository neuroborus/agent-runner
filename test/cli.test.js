import assert from "node:assert/strict";
import test from "node:test";

import packageMetadata from "../package.json" with { type: "json" };
import { main } from "../src/index.js";

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
  assert.match(stdout.read(), /plan-authoring/);
  assert.match(stdout.read(), /plan-execution/);
  assert.match(stdout.read(), /--clarify/);
  assert.equal(stderr.read(), "");
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
  ["run", "plan-authoring", "--arbiter", "codex"],
  ["run", "plan-execution", "--planner", "codex"],
  ["status", "--run", "run-id", "--clarify"],
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

test("declared workflow commands fail clearly until implemented", async () => {
  const stdout = createSink();
  const stderr = createSink();

  const exitCode = await main(["status", "--run", "run-id"], {
    stdout: stdout.stream,
    stderr: stderr.stream,
  });

  assert.equal(exitCode, 1);
  assert.equal(stdout.read(), "");
  assert.match(stderr.read(), /not implemented in the initial scaffold/);
});

for (const pipeline of ["plan-authoring", "plan-execution"]) {
  test(`run ${pipeline} accepts --clarify`, async () => {
    const stdout = createSink();
    const stderr = createSink();

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
      { stdout: stdout.stream, stderr: stderr.stream },
    );

    assert.equal(exitCode, 1);
    assert.equal(stdout.read(), "");
    assert.match(stderr.read(), /not implemented in the initial scaffold/);
  });
}

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
  assert.equal(stderr.read(), "");
});
