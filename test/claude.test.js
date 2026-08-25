import assert from "node:assert/strict";
import { parse } from "node:path";
import test from "node:test";

import {
  CLAUDE_BACKEND_ID,
  ClaudeAdapterError,
  STRUCTURED_OUTPUT_FAILURE_CLASS,
  createClaudeAdapter,
} from "../src/agents/index.js";

const PROJECT_PATH = process.cwd();
const EXPECTED_HEAD = "a".repeat(40);
const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
const CHILD_SESSION = "22222222-2222-4222-8222-222222222222";
const FRESH_SESSION = "33333333-3333-4333-8333-333333333333";
const HELP = [
  "--append-system-prompt",
  "--autocompact",
  "--fork-session",
  "--json-schema",
  "--mcp-config",
  "--model",
  "--no-chrome",
  "--output-format",
  "--permission-mode",
  "--print",
  "--prompt-suggestions",
  "--resume",
  "--safe-mode",
  "--settings",
  "--strict-mcp-config",
  "--tools",
].join("\n");
const STRICT_SCHEMA = Object.freeze({
  type: "object",
  properties: { ok: { type: "boolean" } },
  required: ["ok"],
  additionalProperties: false,
});

function hasCode(code) {
  return (error) => error instanceof ClaudeAdapterError && error.code === code;
}

function hasFailureClass(code, failureClass) {
  return (error) =>
    hasCode(code)(error) && error.failureClass === failureClass;
}

function hasDiagnostic(code, diagnosticClass) {
  return (error) =>
    hasCode(code)(error) && error.diagnosticClass === diagnosticClass;
}

function result({
  error = false,
  output = "done",
  sessionId = FRESH_SESSION,
  structured,
  ...extra
} = {}) {
  return {
    type: "result",
    subtype: error ? "error_during_execution" : "success",
    is_error: error,
    result: output,
    session_id: sessionId,
    permission_denials: [],
    ...extra,
    ...(structured === undefined ? {} : { structured_output: structured }),
  };
}

function processFailure(payload, stderr = "") {
  return Object.assign(new Error("process failed"), {
    stdout: payload === undefined ? "" : JSON.stringify(payload),
    stderr,
  });
}

function option(argumentsList, name) {
  const index = argumentsList.indexOf(name);
  return index === -1 ? undefined : argumentsList[index + 1];
}

function createFixture({
  env,
  handle,
  help = HELP,
  probeOutput = "agent-runner-claude-commit-ok",
  platform = "linux",
  version = "2.1.233",
} = {}) {
  const calls = [];
  let turnIndex = 0;
  const execute = async (file, argumentsList, options) => {
    const call = { file, argumentsList, options };
    calls.push(call);
    const handled = await handle?.({ call, calls, turnIndex });
    if (handled !== undefined) {
      if (file === "claude" && argumentsList.includes("-p")) {
        turnIndex += 1;
      }
      return handled;
    }
    if (file === "claude" && argumentsList[0] === "--version") {
      return { stdout: `${version} (Claude Code)\n`, stderr: "" };
    }
    if (file === "claude" && argumentsList[0] === "--help") {
      return { stdout: help, stderr: "" };
    }
    if (file === "socat") {
      return { stdout: "socat version 1.8", stderr: "" };
    }
    if (file === "bwrap") {
      return { stdout: probeOutput, stderr: "" };
    }
    if (file === "git") {
      return { stdout: `${PROJECT_PATH}/.git\n.git\n`, stderr: "" };
    }
    if (file === "claude" && argumentsList.includes("-p")) {
      const resume = option(argumentsList, "--resume");
      const schema = option(argumentsList, "--json-schema");
      const model = option(argumentsList, "--model");
      const localCommit = schema?.includes('"ready"') === true;
      const payload = result({
        sessionId:
          resume === undefined
            ? FRESH_SESSION
            : argumentsList.includes("--fork-session")
              ? CHILD_SESSION
              : resume,
        structured:
          schema === undefined
            ? undefined
            : localCommit
              ? { ready: true }
              : { ok: true },
        ...(model?.startsWith("claude-") === true
          ? { modelUsage: { [model]: {} } }
          : {}),
      });
      turnIndex += 1;
      return { stdout: JSON.stringify(payload), stderr: "" };
    }
    throw new Error(`Unexpected command: ${file} ${argumentsList.join(" ")}`);
  };
  const adapter = createClaudeAdapter({
    env: env ?? process.env,
    execute,
    platform,
  });
  return { adapter, calls };
}

function request(overrides = {}) {
  return {
    access: "read-only",
    cwd: PROJECT_PATH,
    prompt: "Inspect the repository.",
    ...overrides,
  };
}

function turnCalls(fixture) {
  return fixture.calls.filter(
    ({ file, argumentsList }) =>
      file === "claude" && argumentsList.includes("-p"),
  );
}

test("constructs and probes enforceable Claude capabilities", async () => {
  assert.doesNotThrow(() => createClaudeAdapter());
  assert.equal(
    new ClaudeAdapterError("invalid failure class", {
      failureClass: "native-provider-text",
    }).failureClass,
    undefined,
  );
  const invalidDiagnostic = new ClaudeAdapterError(
    "invalid diagnostic class",
    {
      diagnosticClass: "native-provider-text",
      recoverable: true,
    },
  );
  assert.equal(invalidDiagnostic.diagnosticClass, undefined);
  assert.equal(invalidDiagnostic.recoverable, false);
  assert.throws(
    () => createClaudeAdapter({ env: new Map() }),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  const invalidRequestFixture = createFixture();
  await assert.rejects(
    invalidRequestFixture.adapter.run(request({ recoveryPrompt: "" })),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  assert.equal(turnCalls(invalidRequestFixture).length, 0);
  const fixture = createFixture();

  assert.equal(fixture.adapter.id, CLAUDE_BACKEND_ID);
  assert.deepEqual(await fixture.adapter.probe(), {
    version: "2.1.233",
    structuredOutput: true,
    readOnly: true,
    autonomousWrite: true,
    workspaceWrite: true,
    localCommit: true,
    remoteWriteBlocked: true,
    nativeSessionContinuation: true,
    nativeSessionFork: true,
  });
  assert.deepEqual(
    fixture.calls.slice(0, 3).map(({ file, argumentsList }) => [
      file,
      argumentsList[0],
    ]),
    [
      ["claude", "--version"],
      ["claude", "--help"],
      ["socat", "-V"],
    ],
  );
  assert.equal(fixture.calls[3].file, "bwrap");
  assert.strictEqual(
    await fixture.adapter.probe(),
    await fixture.adapter.probe(),
  );

  assert.equal(
    (await createFixture({ version: "2.1.233+distribution.1" }).adapter.probe())
      .version,
    "2.1.233+distribution.1",
  );
});

test("fails preflight when the CLI or isolation is unsupported", async () => {
  for (const fixture of [
    createFixture({ version: "2.1.232" }),
    createFixture({ version: "2.1.234-beta.1" }),
    createFixture({ platform: "darwin" }),
    createFixture({ probeOutput: "" }),
    createFixture({
      handle({ call }) {
        if (call.file === "socat") {
          throw new Error("socat unavailable");
        }
        return undefined;
      },
    }),
  ]) {
    await assert.rejects(
      fixture.adapter.run(request()),
      hasCode("ERR_UNSUPPORTED_CLAUDE_CAPABILITY"),
    );
    assert.equal(turnCalls(fixture).length, 0);
  }
});

test("runs strict read-only turns with isolated tools and an explicit model", async () => {
  const fixture = createFixture({
    env: {
      ...process.env,
      ANTHROPIC_API_KEY: "provider-token",
      CLAUDE_CODE_SKIP_PROMPT_HISTORY: "1",
      CLAUDE_ENV_FILE: "/tmp/agent-env.sh",
      DISABLE_AUTO_COMPACT: "1",
      NODE_OPTIONS: "--require=/tmp/agent.cjs",
      OTEL_LOG_USER_PROMPTS: "1",
      EMAIL: "override@example.invalid",
      GIT_DIR: "/tmp/redirected.git",
    },
  });

  const response = await fixture.adapter.run(
    request({ model: "claude-test", schema: STRICT_SCHEMA }),
  );

  assert.deepEqual(response, {
    output: "done",
    structured: { ok: true },
    sessionId: FRESH_SESSION,
  });
  assert.ok(Object.isFrozen(response));
  assert.ok(Object.isFrozen(response.structured));
  const turn = turnCalls(fixture)[0];
  assert.equal(turn.argumentsList[0], "-p");
  assert.equal(turn.options.input, "Inspect the repository.");
  assert.ok(!turn.argumentsList.includes("Inspect the repository."));
  assert.equal(option(turn.argumentsList, "--permission-mode"), "plan");
  assert.equal(option(turn.argumentsList, "--tools"), "Bash,Read,Glob,Grep");
  assert.equal(option(turn.argumentsList, "--model"), "claude-test");
  assert.equal(option(turn.argumentsList, "--prompt-suggestions"), "false");
  assert.deepEqual(
    JSON.parse(option(turn.argumentsList, "--json-schema")),
    STRICT_SCHEMA,
  );
  assert.equal(option(turn.argumentsList, "--autocompact"), undefined);
  for (const required of [
    "--no-chrome",
    "--safe-mode",
    "--strict-mcp-config",
  ]) {
    assert.ok(turn.argumentsList.includes(required));
  }
  assert.ok(!turn.argumentsList.includes("--dangerously-skip-permissions"));
  assert.ok(!turn.argumentsList.includes("--fallback-model"));
  const settings = JSON.parse(option(turn.argumentsList, "--settings"));
  assert.equal(settings.disableBypassPermissionsMode, "disable");
  assert.deepEqual(settings.fallbackModel, []);
  assert.deepEqual(settings.attribution, {
    commit: "",
    pr: "",
    sessionUrl: false,
  });
  assert.equal(settings.sandbox.enabled, true);
  assert.equal(settings.sandbox.failIfUnavailable, true);
  assert.equal(settings.sandbox.autoAllowBashIfSandboxed, true);
  assert.equal(settings.sandbox.allowUnsandboxedCommands, false);
  assert.equal(settings.sandbox.enableWeakerNestedSandbox, false);
  assert.equal(settings.sandbox.filesystem.disabled, false);
  assert.deepEqual(
    settings.sandbox.credentials.envVars.find(
      ({ name }) => name === "ANTHROPIC_API_KEY",
    ),
    { mode: "deny", name: "ANTHROPIC_API_KEY" },
  );
  assert.ok(settings.permissions.deny.includes("Edit(/.git/**)"));
  assert.ok(settings.permissions.deny.includes("Bash(git push *)"));
  assert.ok(settings.permissions.deny.includes("Bash(git commit *)"));
  assert.deepEqual(settings.sandbox.network.deniedDomains, ["*"]);
  assert.equal(settings.sandbox.network.strictAllowlist, true);
  assert.ok(settings.sandbox.filesystem.denyWrite.includes(PROJECT_PATH));
  assert.ok(settings.sandbox.filesystem.denyWrite.includes(`${PROJECT_PATH}/.git`));
  assert.equal(turn.options.env.ANTHROPIC_API_KEY, "provider-token");
  assert.equal(turn.options.env.CLAUDE_CODE_SKIP_PROMPT_HISTORY, undefined);
  assert.equal(turn.options.env.DISABLE_AUTO_COMPACT, undefined);
  assert.equal(turn.options.env.CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS, "1");
  assert.equal(turn.options.env.CLAUDE_CODE_AUTO_CONNECT_IDE, "false");
  assert.equal(turn.options.env.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB, "0");
  assert.equal(turn.options.env.CLAUDE_ENV_FILE, undefined);
  assert.equal(turn.options.env.EMAIL, undefined);
  assert.equal(turn.options.env.GIT_DIR, undefined);
  assert.equal(turn.options.env.NODE_OPTIONS, undefined);
  assert.equal(turn.options.env.OTEL_LOG_USER_PROMPTS, undefined);
});

test("applies isolated profile and context selections to Claude", async () => {
  const fixture = createFixture({
    env: {
      ...process.env,
      CLAUDE_CONFIG_DIR: "/profiles/current",
    },
  });
  const execution = {
    profile: "/profiles/work",
    model: "claude-test",
    contextSize: "200000",
  };

  const capabilities = await fixture.adapter.probe(execution);
  await fixture.adapter.run(request(execution));

  assert.strictEqual(await fixture.adapter.probe(execution), capabilities);
  const claudeCalls = fixture.calls.filter(({ file }) => file === "claude");
  assert.equal(claudeCalls.length, 3);
  for (const call of claudeCalls.slice(0, 2)) {
    assert.equal(call.options.env.CLAUDE_CONFIG_DIR, "/profiles/current");
  }
  const turn = turnCalls(fixture)[0];
  assert.equal(turn.options.env.CLAUDE_CONFIG_DIR, "/profiles/work");
  assert.equal(option(turn.argumentsList, "--model"), "claude-test");
  assert.equal(option(turn.argumentsList, "--autocompact"), "200000");
});

test("omits current Claude execution overrides", async () => {
  const fixture = createFixture({
    env: {
      ...process.env,
      CLAUDE_CONFIG_DIR: "/profiles/process-default",
    },
  });

  await fixture.adapter.run(
    request({ profile: "current", model: "current", contextSize: "current" }),
  );

  const turn = turnCalls(fixture)[0];
  assert.equal(option(turn.argumentsList, "--model"), undefined);
  assert.equal(option(turn.argumentsList, "--autocompact"), undefined);
  assert.equal(
    turn.options.env.CLAUDE_CONFIG_DIR,
    "/profiles/process-default",
  );
});

test("rejects invalid Claude profiles and context sizes", async () => {
  const fixture = createFixture();

  for (const execution of [
    { profile: "relative-profile" },
    { profile: "/" },
    { profile: "/profiles/../work" },
    { contextSize: "99999" },
    { contextSize: "1000001" },
    { contextSize: "0200000" },
    { contextSize: "200k" },
    { model: "--model" },
  ]) {
    assert.throws(
      () => fixture.adapter.probe(execution),
      hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
    );
    await assert.rejects(
      fixture.adapter.run(request(execution)),
      hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
    );
  }
  assert.throws(
    () =>
      fixture.adapter.probe({
        env: { CLAUDE_CONFIG_DIR: "/profiles/work" },
      }),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  assert.equal(fixture.calls.length, 0);
});

test("uses auto mode only for autonomous workspace turns", async () => {
  const fixture = createFixture();

  await fixture.adapter.run(request({ access: "workspace-write" }));

  const turn = turnCalls(fixture)[0];
  assert.equal(
    option(turn.argumentsList, "--permission-mode"),
    "auto",
  );
  assert.equal(
    option(turn.argumentsList, "--tools"),
    "Bash,Read,Edit,Write,Glob,Grep",
  );
  const settings = JSON.parse(option(turn.argumentsList, "--settings"));
  assert.equal(settings.sandbox.autoAllowBashIfSandboxed, false);
  assert.ok(!settings.sandbox.filesystem.denyWrite.includes(PROJECT_PATH));
});

test("passes option-like prompts through stdin", async () => {
  const fixture = createFixture();

  await fixture.adapter.run(request({ prompt: "--inspect-the-repository" }));

  const turn = turnCalls(fixture)[0];
  assert.equal(turn.options.input, "--inspect-the-repository");
  assert.ok(!turn.argumentsList.includes("--inspect-the-repository"));
});

test("validates requests, strict schemas, and structured results", async () => {
  const fixture = createFixture();
  await assert.rejects(
    fixture.adapter.run(request({ extra: true })),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(request({ cwd: parse(PROJECT_PATH).root })),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(
      request({ session: { id: "--continue", mode: "continue" } }),
    ),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(request({ model: "--model" })),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(
      request({
        schema: {
          type: "object",
          properties: {
            value: { type: "string", description: "x".repeat(128 * 1024) },
          },
          required: ["value"],
          additionalProperties: false,
        },
      }),
    ),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(
      request({
        schema: {
          type: "object",
          properties: { ok: { type: "boolean" } },
          required: [],
        },
      }),
    ),
    hasCode("ERR_INVALID_CLAUDE_SCHEMA"),
  );
  const invalidOutput = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(result({ structured: [true] })),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    invalidOutput.adapter.run(request({ schema: STRICT_SCHEMA })),
    hasFailureClass(
      "ERR_CLAUDE_STRUCTURED_OUTPUT",
      STRUCTURED_OUTPUT_FAILURE_CLASS,
    ),
  );

  for (const payload of [
    result({ subtype: "error_during_execution" }),
    result({ permission_denials: "invalid" }),
    result({ sessionId: "invalid-session" }),
  ]) {
    const invalidProtocol = createFixture({
      handle({ call }) {
        if (call.file === "claude" && call.argumentsList.includes("-p")) {
          return { stdout: JSON.stringify(payload), stderr: "" };
        }
        return undefined;
      },
    });
    await assert.rejects(
      invalidProtocol.adapter.run(request()),
      hasCode("ERR_CLAUDE_TURN_FAILED"),
    );
  }

  const nullableOutput = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              output: null,
              permission_denials: null,
              structured: { ok: true },
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  assert.equal(
    (await nullableOutput.adapter.run(request({ schema: STRICT_SCHEMA })))
      .output,
    '{"ok":true}',
  );
});

test("rejects permission fallback and explicit model rerouting", async (t) => {
  const denied = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              permission_denials: [
                {
                  tool_input: { file_path: "source.js" },
                  tool_name: "Edit",
                },
              ],
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    denied.adapter.run(request({ access: "workspace-write" })),
    (error) =>
      hasDiagnostic(
        "ERR_CLAUDE_PERMISSION_DENIED",
        "permission_capability",
      )(error) && error.recoverable === true,
  );

  const safeInspection = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              permission_denials: [
                {
                  tool_input: { command: "git status --short" },
                  tool_name: "Bash",
                },
              ],
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    safeInspection.adapter.run(request()),
    (error) =>
      hasDiagnostic(
        "ERR_CLAUDE_PERMISSION_DENIED",
        "permission_capability",
      )(error) && error.recoverable === true,
  );

  for (const forbiddenCommand of [
    "git branch release",
    "git clean -fd",
    "git tag release",
    "git add source.js",
    "git restore source.js",
    "command git commit -m provider-secret-value",
    "env git push origin HEAD",
    "sh -c 'git remote set-url origin forbidden'",
    "/usr/bin/git -C . tag release",
    "curl https://provider-secret-value.invalid",
  ]) {
    await t.test(`fails closed for ${forbiddenCommand}`, async () => {
      const forbidden = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            return {
              stdout: JSON.stringify(
                result({
                  permission_denials: [
                    {
                      tool_input: { command: forbiddenCommand },
                      tool_name: "Bash",
                    },
                  ],
                }),
              ),
              stderr: "",
            };
          }
          return undefined;
        },
      });
      await assert.rejects(forbidden.adapter.run(request()), (error) => {
        assert.ok(
          hasDiagnostic(
            "ERR_CLAUDE_PERMISSION_DENIED",
            "permission_forbidden_operation",
          )(error),
        );
        assert.equal(error.recoverable, false);
        assert.doesNotMatch(error.message, /provider-secret-value/u);
        assert.equal(error.cause, undefined);
        return true;
      });
    });
  }

  const rerouted = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({ modelUsage: { "claude-other": {} } }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    rerouted.adapter.run(request({ model: "claude-exact" })),
    hasCode("ERR_CLAUDE_MODEL_REROUTED"),
  );

  const fallback = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              modelUsage: {
                "claude-exact": {},
                "claude-fallback": {},
              },
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    fallback.adapter.run(request({ model: "claude-exact" })),
    hasCode("ERR_CLAUDE_MODEL_REROUTED"),
  );

  const unavailableAuto = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          result({ error: true, output: "Auto mode is unavailable." }),
        );
      }
      return undefined;
    },
  });
  await assert.rejects(
    unavailableAuto.adapter.run(request({ access: "workspace-write" })),
    (error) =>
      hasDiagnostic(
        "ERR_UNSUPPORTED_CLAUDE_CAPABILITY",
        "capability_unavailable",
      )(error) && error.recoverable === true,
  );
  assert.equal(turnCalls(unavailableAuto).length, 1);

  const manualFallback = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(result()),
          stderr: "Permission mode forced to default.",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    manualFallback.adapter.run(request({ access: "workspace-write" })),
    (error) =>
      hasDiagnostic(
        "ERR_UNSUPPORTED_CLAUDE_CAPABILITY",
        "capability_unavailable",
      )(error) && error.recoverable === true,
  );
});

test("classifies explicit usage limits without retrying the rejected turn", async (t) => {
  for (const [message, exitsSuccessfully] of [
    ["Rate limit exceeded.", true],
    ["Your organization quota has been exhausted.", false],
    ["You have exceeded your quota.", false],
    ["Insufficient credits to complete this request.", false],
    ["Credits exhausted.", false],
    ["Monthly spend limit reached.", false],
    ["You've hit your limit · resets 3pm", false],
  ]) {
    await t.test(message, async () => {
      const fixture = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            const payload = result({
              error: true,
              output: message,
              sessionId: SOURCE_SESSION,
            });
            if (exitsSuccessfully) {
              return { stdout: JSON.stringify(payload), stderr: "" };
            }
            throw processFailure(payload);
          }
          return undefined;
        },
      });

      await assert.rejects(
        fixture.adapter.run(
          request({
            prompt: "Continue from the current session.",
            recoveryPrompt: "Inspect the complete durable request.",
            session: { id: SOURCE_SESSION, mode: "continue" },
          }),
        ),
        (error) =>
          hasCode("ERR_CLAUDE_USAGE_LIMIT")(error) &&
          error.recoverable === true &&
          error.ambiguous === false,
      );
      assert.equal(turnCalls(fixture).length, 1);
    });
  }
});

test("prefers structured Claude failure fields over native text", async (t) => {
  for (const {
    code,
    diagnosticClass,
    payload,
    recoverable,
  } of [
    {
      code: "ERR_CLAUDE_USAGE_LIMIT",
      diagnosticClass: "usage_limit",
      payload: result({
        api_error_status: 429,
        error: true,
        output: "Authentication required: provider-secret-value.",
      }),
      recoverable: true,
    },
    {
      code: "ERR_CLAUDE_PROVIDER_UNAVAILABLE",
      diagnosticClass: "provider_unavailable",
      payload: result({
        api_error_status: 503,
        error: true,
        output: "provider-secret-value",
        terminal_reason: "api_error",
      }),
      recoverable: true,
    },
    {
      code: "ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE",
      diagnosticClass: "authentication_unavailable",
      payload: result({
        api_error_status: 401,
        error: true,
        output: "provider-secret-value",
        terminal_reason: "api_error",
      }),
      recoverable: false,
    },
    {
      code: "ERR_CLAUDE_BACKEND_UNAVAILABLE",
      diagnosticClass: "backend_unavailable",
      payload: result({
        error: true,
        output: "provider-secret-value",
        terminal_reason: "turn_setup_failed",
      }),
      recoverable: true,
    },
  ]) {
    await t.test(code, async () => {
      const fixture = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            return { stdout: JSON.stringify(payload), stderr: "" };
          }
          return undefined;
        },
      });

      await assert.rejects(fixture.adapter.run(request()), (error) => {
        assert.ok(hasDiagnostic(code, diagnosticClass)(error));
        assert.equal(error.recoverable, recoverable);
        assert.doesNotMatch(error.message, /provider-secret-value/u);
        assert.equal(error.cause, undefined);
        return true;
      });
    });
  }
});

test("fails closed for non-transient structured Claude API errors", async (t) => {
  for (const status of [400, 404, 422, undefined]) {
    await t.test(
      status === undefined ? "missing status" : String(status),
      async () => {
        const payload = result({
          error: true,
          output: "Provider unavailable: provider-secret-value.",
          terminal_reason: "api_error",
          ...(status === undefined ? {} : { api_error_status: status }),
        });
        const fixture = createFixture({
          handle({ call }) {
            if (call.file === "claude" && call.argumentsList.includes("-p")) {
              return { stdout: JSON.stringify(payload), stderr: "" };
            }
            return undefined;
          },
        });

        await assert.rejects(fixture.adapter.run(request()), (error) => {
          assert.ok(hasCode("ERR_CLAUDE_REQUEST_REJECTED")(error));
          assert.equal(error.diagnosticClass, undefined);
          assert.equal(error.recoverable, false);
          assert.doesNotMatch(error.message, /provider-secret-value/u);
          assert.equal(error.cause, undefined);
          return true;
        });
      },
    );
  }
});

test("classifies bounded native error arrays without retaining them", async () => {
  const payload = result({ error: true });
  delete payload.result;
  payload.errors = ["API rate_limit_error provider-secret-value"];
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(payload, "raw standard error secret");
      }
      return undefined;
    },
  });

  await assert.rejects(fixture.adapter.run(request()), (error) => {
    assert.ok(hasDiagnostic("ERR_CLAUDE_USAGE_LIMIT", "usage_limit")(error));
    assert.equal(error.recoverable, true);
    assert.doesNotMatch(error.message, /secret/u);
    assert.equal(error.cause, undefined);
    return true;
  });
});

test("maps native structured-output exhaustion to the shared failure class", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              error: true,
              output: "provider-native structured output text",
              subtype: "error_max_structured_output_retries",
              terminal_reason: "structured_output_retry_exhausted",
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(request({ schema: STRICT_SCHEMA })),
    hasFailureClass(
      "ERR_CLAUDE_STRUCTURED_OUTPUT",
      STRUCTURED_OUTPUT_FAILURE_CLASS,
    ),
  );
});

test("retries only harmless unclassified read-only process failures", async () => {
  for (const [access, recoverable, diagnosticClass] of [
    ["read-only", true, "read_only_process_failed"],
    ["workspace-write", false, "writable_process_ambiguous"],
  ]) {
    const fixture = createFixture({
      handle({ call }) {
        if (call.file === "claude" && call.argumentsList.includes("-p")) {
          throw processFailure(undefined, "provider-native secret text");
        }
        return undefined;
      },
    });

    await assert.rejects(
      fixture.adapter.run(request({ access })),
      (error) => {
        assert.ok(hasCode("ERR_CLAUDE_PROCESS_INTERRUPTED")(error));
        assert.equal(error.diagnosticClass, diagnosticClass);
        assert.equal(error.recoverable, recoverable);
        assert.equal(error.ambiguous, access === "workspace-write");
        assert.doesNotMatch(error.message, /provider-native/u);
        assert.equal(error.cause, undefined);
        return true;
      },
    );
  }
});

test("makes only unclassified read-only result failures resumable", async () => {
  for (const [access, code, recoverable, diagnosticClass] of [
    [
      "read-only",
      "ERR_CLAUDE_READ_ONLY_TURN_FAILED",
      true,
      "read_only_execution_failed",
    ],
    ["workspace-write", "ERR_CLAUDE_TURN_FAILED", false, undefined],
  ]) {
    const fixture = createFixture({
      handle({ call }) {
        if (call.file === "claude" && call.argumentsList.includes("-p")) {
          return {
            stdout: JSON.stringify(
              result({
                error: true,
                output: "unclassified provider-native secret text",
              }),
            ),
            stderr: "",
          };
        }
        return undefined;
      },
    });

    await assert.rejects(fixture.adapter.run(request({ access })), (error) => {
      assert.ok(hasCode(code)(error));
      assert.equal(error.recoverable, recoverable);
      assert.equal(error.diagnosticClass, diagnosticClass);
      assert.doesNotMatch(error.message, /provider-native/u);
      return true;
    });
  }
});

test("keeps a usage-rejected local commit unambiguous", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          result({ error: true, output: "API rate_limit_error" }),
        );
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "test(scope): verify usage limit",
        },
      }),
    ),
    (error) =>
      hasCode("ERR_CLAUDE_USAGE_LIMIT")(error) &&
      error.recoverable === true &&
      error.ambiguous === false &&
      error.effectStarted === false,
  );
  assert.equal(turnCalls(fixture).length, 1);
  assert.equal(
    fixture.calls.filter(({ file }) => file === "bwrap").length,
    1,
  );
});

test("classifies fresh-turn profile, authentication, and provider failures", async (t) => {
  for (const {
    code,
    diagnosticClass,
    message,
    options = {},
    recoverable = true,
  } of [
    {
      code: "ERR_CLAUDE_PROFILE_UNAVAILABLE",
      diagnosticClass: "configuration_unavailable",
      message: "Session unavailable for the selected configuration.",
      options: { profile: "/profiles/work" },
    },
    {
      code: "ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE",
      diagnosticClass: "authentication_unavailable",
      message: "Authentication required: API key secret-value is invalid.",
      recoverable: false,
    },
    {
      code: "ERR_CLAUDE_PROVIDER_UNAVAILABLE",
      diagnosticClass: "provider_unavailable",
      message: "Provider service unavailable.",
    },
    {
      code: "ERR_CLAUDE_PROVIDER_UNAVAILABLE",
      diagnosticClass: "provider_unavailable",
      message: "Session unavailable.",
    },
  ]) {
    await t.test(code, async () => {
      const fixture = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            throw processFailure(result({ error: true, output: message }));
          }
          return undefined;
        },
      });

      await assert.rejects(
        fixture.adapter.run(request(options)),
        (error) => {
          assert.ok(hasCode(code)(error));
          assert.equal(error.diagnosticClass, diagnosticClass);
          assert.equal(error.recoverable, recoverable);
          assert.doesNotMatch(error.message, /secret-value/u);
          assert.equal(error.cause, undefined);
          return true;
        },
      );
      assert.equal(turnCalls(fixture).length, 1);

      const localCommitFixture = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            throw processFailure(result({ error: true, output: message }));
          }
          return undefined;
        },
      });
      await assert.rejects(
        localCommitFixture.adapter.run(
          request({
            ...options,
            access: "local-commit",
            authorizationId: "authorization-1",
            commit: {
              expectedHead: EXPECTED_HEAD,
              message: "test(scope): preserve classified failure",
            },
          }),
        ),
        (error) => {
          assert.ok(hasCode(code)(error));
          assert.equal(error.diagnosticClass, diagnosticClass);
          assert.equal(error.recoverable, recoverable);
          assert.equal(error.effectStarted, false);
          assert.doesNotMatch(error.message, /secret-value/u);
          return true;
        },
      );
      assert.equal(turnCalls(localCommitFixture).length, 1);
      assert.equal(
        localCommitFixture.calls.filter(({ file }) => file === "bwrap").length,
        1,
      );
    });
  }
});

test("continues sessions and reconstructs when continuation is unavailable", async () => {
  let attempts = 0;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) {
        return undefined;
      }
      attempts += 1;
      if (attempts === 1) {
        throw processFailure(
          undefined,
          `No conversation found with session ID: ${SOURCE_SESSION}`,
        );
      }
      return {
        stdout: JSON.stringify(result({ sessionId: FRESH_SESSION })),
        stderr: "",
      };
    },
  });

  const response = await fixture.adapter.run(
    request({
      prompt: "Continue from the current session.",
      recoveryPrompt: "Inspect the complete durable request.",
      session: { id: SOURCE_SESSION, mode: "continue" },
    }),
  );

  assert.equal(response.sessionId, FRESH_SESSION);
  const turns = turnCalls(fixture);
  assert.equal(option(turns[0].argumentsList, "--resume"), SOURCE_SESSION);
  assert.equal(turns[0].options.input, "Continue from the current session.");
  assert.equal(option(turns[1].argumentsList, "--resume"), undefined);
  assert.match(turns[1].options.input, /could not continue/u);
  assert.match(turns[1].options.input, /complete durable request/u);
  assert.doesNotMatch(turns[1].options.input, /current session/u);
});

test("forks a supplied source directly and preserves child lineage", async () => {
  const fixture = createFixture();

  const response = await fixture.adapter.run(
    request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
  );

  assert.equal(response.sessionId, CHILD_SESSION);
  const turn = turnCalls(fixture)[0];
  assert.equal(option(turn.argumentsList, "--resume"), SOURCE_SESSION);
  assert.ok(turn.argumentsList.includes("--fork-session"));

  const invalid = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(result({ sessionId: SOURCE_SESSION })),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    invalid.adapter.run(
      request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
    ),
    hasCode("ERR_CLAUDE_PROTOCOL"),
  );
});

test("fails instead of replacing an unavailable fork source", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          undefined,
          `No conversation found with session ID: ${SOURCE_SESSION}`,
        );
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
    ),
    (error) => {
      assert.ok(hasCode("ERR_CLAUDE_SOURCE_SESSION_UNAVAILABLE")(error));
      assert.equal(error.recoverable, false);
      assert.equal(error.cause, undefined);
      assert.ok(!error.message.includes(SOURCE_SESSION));
      return true;
    },
  );
  assert.equal(turnCalls(fixture).length, 1);
});

test("retries a compacted context and then reconstructs fresh", async () => {
  let attempts = 0;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) {
        return undefined;
      }
      attempts += 1;
      if (attempts < 3) {
        throw processFailure(
          result({
            error: true,
            output: "Context window exceeded.",
            sessionId: SOURCE_SESSION,
          }),
        );
      }
      return {
        stdout: JSON.stringify(result({ sessionId: FRESH_SESSION })),
        stderr: "",
      };
    },
  });

  const response = await fixture.adapter.run(
    request({
      prompt: "Continue from the current session.",
      recoveryPrompt: "Inspect the complete durable request.",
      session: { id: SOURCE_SESSION, mode: "continue" },
    }),
  );

  assert.equal(response.sessionId, FRESH_SESSION);
  const turns = turnCalls(fixture);
  assert.equal(option(turns[1].argumentsList, "--resume"), SOURCE_SESSION);
  assert.match(turns[1].options.input, /^Compact the existing/u);
  assert.match(turns[1].options.input, /complete durable request/u);
  assert.doesNotMatch(turns[1].options.input, /current session/u);
  assert.equal(option(turns[2].argumentsList, "--resume"), undefined);
  assert.match(turns[2].options.input, /^The previous Claude/u);
  assert.match(turns[2].options.input, /complete durable request/u);
  assert.doesNotMatch(turns[2].options.input, /current session/u);
});

test("never resumes an invalid session ID reported on failure", async () => {
  let attempts = 0;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) {
        return undefined;
      }
      attempts += 1;
      if (attempts === 1) {
        throw processFailure(
          result({
            error: true,
            output: "Context window exceeded.",
            sessionId: "--invalid-session",
          }),
        );
      }
      return {
        stdout: JSON.stringify(result({ sessionId: FRESH_SESSION })),
        stderr: "",
      };
    },
  });

  await fixture.adapter.run(request());

  const turns = turnCalls(fixture);
  assert.equal(turns.length, 2);
  assert.equal(option(turns[1].argumentsList, "--resume"), undefined);
});

test("never loses fork lineage while recovering a full context", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          result({
            error: true,
            output: "Context window exceeded.",
            sessionId: CHILD_SESSION,
          }),
        );
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
    ),
    hasCode("ERR_CLAUDE_CONTEXT_EXHAUSTED"),
  );
  const turns = turnCalls(fixture);
  assert.equal(turns.length, 2);
  assert.equal(option(turns[0].argumentsList, "--resume"), SOURCE_SESSION);
  assert.ok(turns[0].argumentsList.includes("--fork-session"));
  assert.equal(option(turns[1].argumentsList, "--resume"), CHILD_SESSION);
  assert.ok(!turns[1].argumentsList.includes("--fork-session"));
});

test("never continues a fork source after context exhaustion", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          result({
            error: true,
            output: "Context window exceeded.",
            sessionId: SOURCE_SESSION,
          }),
        );
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
    ),
    hasCode("ERR_CLAUDE_PROTOCOL"),
  );
  assert.equal(turnCalls(fixture).length, 1);
});

test("creates one exact authorized commit in a networkless sandbox", async () => {
  const fixture = createFixture({
    env: {
      ...process.env,
      ANTHROPIC_API_KEY: "provider-token",
      HTTP_PROXY: "http://proxy.invalid",
      LD_PRELOAD: "/tmp/agent.so",
      NODE_OPTIONS: "--require=/tmp/agent.cjs",
      SSH_AUTH_SOCK: "/tmp/agent.sock",
    },
  });
  const message = "feat(test): create commit";

  await fixture.adapter.run(
    request({
      access: "local-commit",
      authorizationId: "authorization-1",
      commit: { expectedHead: EXPECTED_HEAD, message },
    }),
  );

  assert.equal(
    option(turnCalls(fixture)[0].argumentsList, "--permission-mode"),
    "plan",
  );
  const bubblewrapCalls = fixture.calls.filter(({ file }) => file === "bwrap");
  assert.equal(bubblewrapCalls.length, 2);
  const commitCall = bubblewrapCalls[1];
  assert.ok(commitCall.argumentsList.includes("--unshare-net"));
  assert.ok(commitCall.argumentsList.includes(EXPECTED_HEAD));
  assert.ok(commitCall.argumentsList.includes(message));
  assert.equal(commitCall.options.env.ANTHROPIC_API_KEY, undefined);
  assert.equal(commitCall.options.env.HTTP_PROXY, undefined);
  assert.equal(commitCall.options.env.LD_PRELOAD, undefined);
  assert.equal(commitCall.options.env.NODE_OPTIONS, undefined);
  assert.equal(commitCall.options.env.SSH_AUTH_SOCK, undefined);
});

test("proves a rejected local-commit policy did not start the effect", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              structured: { ready: false },
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "feat(test): create commit",
        },
      }),
    ),
    (error) =>
      hasCode("ERR_CLAUDE_LOCAL_COMMIT_POLICY")(error) &&
      error.effectStarted === false,
  );
  assert.equal(fixture.calls.filter(({ file }) => file === "bwrap").length, 1);
});

test("never replays an interrupted local-commit turn", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(undefined, "terminated");
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "feat(test): create commit",
        },
      }),
    ),
    (error) =>
      hasCode("ERR_CLAUDE_PROCESS_INTERRUPTED")(error) &&
      error.ambiguous === true &&
      error.recoverable === false &&
      error.diagnosticClass === "writable_process_ambiguous" &&
      error.effectStarted === false,
  );
  assert.equal(turnCalls(fixture).length, 1);
  assert.equal(fixture.calls.filter(({ file }) => file === "bwrap").length, 1);
});

test("keeps commit-executor failures ambiguous", async () => {
  let bubblewrapCalls = 0;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "bwrap") {
        bubblewrapCalls += 1;
        if (bubblewrapCalls === 2) {
          throw new Error("commit executor failed");
        }
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "feat(test): create commit",
        },
      }),
    ),
    (error) => {
      assert.ok(hasCode("ERR_CLAUDE_LOCAL_COMMIT_INTERRUPTED")(error));
      assert.equal(error.ambiguous, true);
      assert.notEqual(error.effectStarted, false);
      return true;
    },
  );
  assert.equal(bubblewrapCalls, 2);
});

test(
  "runs an opt-in real Claude read-only inspection smoke turn",
  { skip: process.env.AGENT_RUNNER_LIVE_CLAUDE !== "1" },
  async () => {
    const adapter = createClaudeAdapter();
    const response = await adapter.run(
      request({
        prompt:
          "Use Bash to run `git status --short` in the current repository. " +
          "Return ok=true only when the command completes successfully.",
        schema: STRICT_SCHEMA,
      }),
    );
    assert.equal(typeof response.sessionId, "string");
    assert.equal(response.structured.ok, true);
  },
);
