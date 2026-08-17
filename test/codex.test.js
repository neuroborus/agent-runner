import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";

import packageMetadata from "../package.json" with { type: "json" };
import {
  CODEX_BACKEND_ID,
  CodexAdapterError,
  createCodexAdapter,
} from "../src/agents/index.js";

const PROJECT_PATH = process.cwd();
const EXPECTED_HEAD = "a".repeat(40);
const HELP = "--disable\n--listen\n--strict-config\n";
const STRICT_SCHEMA = Object.freeze({
  type: "object",
  properties: {
    ok: { type: "boolean" },
  },
  required: ["ok"],
  additionalProperties: false,
});

function hasCode(code) {
  return (error) => error instanceof CodexAdapterError && error.code === code;
}

function completedTurn(threadId, turnId, output = "done", items = []) {
  return {
    method: "turn/completed",
    params: {
      threadId,
      turn: {
        id: turnId,
        itemsView: "full",
        status: "completed",
        items: [...items, { type: "agentMessage", text: output }],
      },
    },
  };
}

function isolatedConfiguration() {
  return {
    features: {
      apps: false,
      artifact: false,
      browser_use: false,
      browser_use_external: false,
      browser_use_full_cdp_access: false,
      code_mode: false,
      code_mode_host: false,
      code_mode_only: false,
      computer_use: false,
      goals: false,
      guardian_approval: false,
      guardianv2: false,
      hooks: false,
      image_generation: false,
      in_app_browser: false,
      js_repl: false,
      memories: false,
      multi_agent: false,
      plugins: false,
      remote_plugin: false,
      shell_snapshot: false,
      skill_mcp_dependency_install: false,
    },
    memories: {
      generate_memories: false,
      use_memories: false,
    },
    mcp_servers: {
      "configured-server": { enabled: false },
    },
    notify: [],
    shell_environment_policy: {
      inherit: "core",
      ignore_default_excludes: false,
      exclude: null,
      set: {},
      include_only: null,
      filters: null,
      experimental_use_profile: false,
    },
    web_search: "disabled",
  };
}

function createFixture({
  closeError = false,
  closeOutputError = false,
  env,
  executeHandle,
  handle,
  help = HELP,
  version = "0.147.0",
} = {}) {
  const executeCalls = [];
  const processes = [];
  let nextTurn = 0;

  const execute = async (file, argumentsList, options) => {
    executeCalls.push({ file, argumentsList, options });
    const response = await executeHandle?.({ file, argumentsList, options });
    if (response !== undefined) {
      return response;
    }
    if (file === "git") {
      return { stdout: `${PROJECT_PATH}/.git\n.git\n`, stderr: "" };
    }
    if (argumentsList[0] === "--version") {
      return { stdout: `codex-cli ${version}\n`, stderr: "" };
    }
    if (argumentsList.includes("mcp")) {
      return {
        stdout: '[{"name":"configured-server","enabled":true}]',
        stderr: "",
      };
    }
    if (argumentsList[0] === "sandbox") {
      return { stdout: "agent-runner-local-commit-ok", stderr: "" };
    }
    return { stdout: help, stderr: "" };
  };

  const spawnProcess = (file, argumentsList, options) => {
    const processIndex = processes.length;
    const child = new EventEmitter();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const messages = [];
    let closed = false;

    function close() {
      if (closed) {
        return;
      }
      closed = true;
      stdout.end();
      stderr.end();
      if (closeOutputError) {
        queueMicrotask(() => {
          stdout.emit("error", new Error("test close output failure"));
        });
      }
      queueMicrotask(() => child.emit("close", 0, null));
    }

    function send(message) {
      stdout.write(`${JSON.stringify(message)}\n`);
    }

    function defaultResponse(message) {
      switch (message.method) {
        case "initialize":
          return { result: {} };
        case "model/list":
          return { result: { data: [{ id: "gpt-test" }], nextCursor: null } };
        case "config/read":
          return {
            result: {
              config: isolatedConfiguration(),
            },
          };
        case "thread/start":
          return { result: { thread: { id: `thread-${processIndex}` } } };
        case "thread/resume":
          return { result: { thread: { id: message.params.threadId } } };
        case "thread/fork":
          return {
            result: {
              thread: {
                id: `child-${processIndex}`,
                forkedFromId: message.params.threadId,
              },
            },
          };
        case "thread/compact/start":
          return {
            result: {},
            notification: completedTurn(
              message.params.threadId,
              `compact-${processIndex}`,
              "Compacted.",
              [{ type: "contextCompaction" }],
            ),
          };
        case "turn/start": {
          const turnId = `turn-${nextTurn += 1}`;
          return {
            result: { turn: { id: turnId } },
            notification: completedTurn(
              message.params.threadId,
              turnId,
            ),
          };
        }
        default:
          return undefined;
      }
    }

    async function receive(message) {
      messages.push(message);
      if (message.id === undefined) {
        return;
      }
      const response =
        (await handle?.({
          message,
          messages,
          processIndex,
        })) ?? defaultResponse(message);
      if (response?.stdoutError === true) {
        setImmediate(() => {
          stdout.emit("error", new Error("test stdout failure"));
        });
        return;
      }
      if (response?.close === true) {
        close();
        return;
      }
      if (response?.error !== undefined) {
        send({ id: message.id, error: response.error });
        return;
      }
      if (response?.result !== undefined) {
        send({ id: message.id, result: response.result });
        if (response.notification !== undefined) {
          const notifications = Array.isArray(response.notification)
            ? response.notification
            : [response.notification];
          for (const notification of notifications) {
            send(notification);
          }
        }
        return;
      }
      send({
        id: message.id,
        error: { code: -32601, message: "unsupported test request" },
      });
    }

    let input = "";
    child.stdin = new Writable({
      write(chunk, _encoding, callback) {
        input += chunk.toString("utf8");
        const lines = input.split("\n");
        input = lines.pop();
        Promise.all(
          lines.filter(Boolean).map((line) => receive(JSON.parse(line))),
        ).then(() => callback(), callback);
      },
      final(callback) {
        callback();
        close();
      },
    });
    if (closeError) {
      child.stdin.end = () => {
        throw new Error("test cleanup failure");
      };
    }
    child.stdout = stdout;
    child.stderr = stderr;
    child.kill = () => {
      close();
      return true;
    };
    processes.push({ file, argumentsList, messages, options });
    return child;
  };

  return {
    adapter: createCodexAdapter({ env, execute, spawnProcess }),
    executeCalls,
    processes,
  };
}

function request(overrides = {}) {
  return {
    access: "read-only",
    cwd: PROJECT_PATH,
    prompt: "Inspect the repository.",
    ...overrides,
  };
}

test("constructs with the native environment and probes capabilities", async () => {
  assert.doesNotThrow(() => createCodexAdapter());
  assert.throws(
    () => createCodexAdapter({ env: new Map() }),
    hasCode("ERR_INVALID_CODEX_OPTIONS"),
  );
  assert.throws(
    () => createCodexAdapter({ env: { INVALID: 1 } }),
    hasCode("ERR_INVALID_CODEX_OPTIONS"),
  );
  const fixture = createFixture();

  assert.equal(fixture.adapter.id, CODEX_BACKEND_ID);
  assert.deepEqual(await fixture.adapter.probe(), {
    version: "0.147.0",
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
    fixture.executeCalls.slice(0, 2).map(({ argumentsList }) => argumentsList),
    [["--version"], ["app-server", "--help"]],
  );
  assert.equal(fixture.executeCalls[2].argumentsList[0], "sandbox");
  assert.ok(
    fixture.executeCalls[2].argumentsList.includes("agent_runner_local_commit"),
  );
  assert.strictEqual(await fixture.adapter.probe(), await fixture.adapter.probe());
});

test("fails preflight when the installed Codex cannot enforce access", async () => {
  for (const version of ["0.146.0", "0.147.0-alpha.1", "0.148.0-alpha.1"]) {
    const fixture = createFixture({ version });

    await assert.rejects(
      fixture.adapter.run(request()),
      hasCode("ERR_UNSUPPORTED_CODEX_CAPABILITY"),
    );
    assert.equal(fixture.processes.length, 0);
  }
});

test(
  "advertises local commits only with an enforceable isolated sandbox",
  async () => {
    const fixture = createFixture({
      executeHandle({ argumentsList }) {
        if (argumentsList[0] === "sandbox") {
          return { stdout: "", stderr: "" };
        }
        return undefined;
      },
    });

    const capabilities = await fixture.adapter.probe();
    assert.equal(capabilities.workspaceWrite, true);
    assert.equal(capabilities.localCommit, false);
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
      hasCode("ERR_UNSUPPORTED_CODEX_CAPABILITY"),
    );
    assert.equal(fixture.processes.length, 0);
  },
);

test("removes ambient Git redirection and identity overrides", async () => {
  const fixture = createFixture({
    env: {
      ...process.env,
      AGENT_RUNNER_TEST_TOKEN: "provider-token",
      EMAIL: "override@example.invalid",
      Email: "mixed-case@example.invalid",
      GIT_AUTHOR_NAME: "Override",
      GIT_DIR: "/tmp/redirected.git",
      Git_Work_Tree: "/tmp/redirected-worktree",
      git_config_count: "1",
    },
  });

  await fixture.adapter.run(request());

  for (const { options } of fixture.executeCalls) {
    assert.equal(options.env.EMAIL, undefined);
    assert.equal(options.env.Email, undefined);
    assert.equal(options.env.GIT_AUTHOR_NAME, undefined);
    assert.equal(options.env.GIT_DIR, undefined);
    assert.equal(options.env.Git_Work_Tree, undefined);
    assert.equal(options.env.git_config_count, undefined);
    assert.equal(options.env.GIT_TERMINAL_PROMPT, "0");
  }
  const sandboxCall = fixture.executeCalls.find(
    ({ argumentsList }) => argumentsList[0] === "sandbox",
  );
  assert.equal(sandboxCall.options.env.AGENT_RUNNER_TEST_TOKEN, undefined);
  assert.equal(
    fixture.processes[0].options.env.AGENT_RUNNER_TEST_TOKEN,
    "provider-token",
  );
  assert.equal(fixture.processes[0].options.env.GIT_DIR, undefined);
});

test("normalizes app-server stdout failures", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "initialize") {
        return { stdoutError: true };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(request()),
    hasCode("ERR_CODEX_PROCESS_EXITED"),
  );
});

test("runs a structured read-only turn with an explicit model", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "turn/start") {
        const turnId = "structured-turn";
        return {
          result: { turn: { id: turnId } },
          notification: completedTurn(
            message.params.threadId,
            turnId,
            '{"ok":true}',
          ),
        };
      }
      return undefined;
    },
  });

  const result = await fixture.adapter.run(
    request({ model: "gpt-test", schema: STRICT_SCHEMA }),
  );

  assert.deepEqual(result, {
    output: '{"ok":true}',
    structured: { ok: true },
    sessionId: "thread-0",
  });
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.structured));
  assert.equal(fixture.processes.length, 1);
  const initializeRequest = fixture.processes[0].messages.find(
    ({ method }) => method === "initialize",
  );
  assert.equal(initializeRequest.params.capabilities, null);
  assert.equal(
    initializeRequest.params.clientInfo.version,
    packageMetadata.version,
  );
  assert.deepEqual(fixture.processes[0].argumentsList, [
    "app-server",
    "--listen",
    "stdio://",
    "--strict-config",
    "--disable",
    "apps",
    "--disable",
    "artifact",
    "--disable",
    "browser_use",
    "--disable",
    "browser_use_external",
    "--disable",
    "browser_use_full_cdp_access",
    "--disable",
    "code_mode",
    "--disable",
    "code_mode_host",
    "--disable",
    "code_mode_only",
    "--disable",
    "computer_use",
    "--disable",
    "goals",
    "--disable",
    "guardian_approval",
    "--disable",
    "guardianv2",
    "--disable",
    "hooks",
    "--disable",
    "image_generation",
    "--disable",
    "in_app_browser",
    "--disable",
    "js_repl",
    "--disable",
    "memories",
    "--disable",
    "multi_agent",
    "--disable",
    "plugins",
    "--disable",
    "remote_plugin",
    "--disable",
    "shell_snapshot",
    "--disable",
    "skill_mcp_dependency_install",
    "-c",
    "notify=[]",
    "-c",
    'shell_environment_policy={inherit="core",ignore_default_excludes=false,' +
      'experimental_use_profile=false,set={}}',
    "-c",
    "memories.generate_memories=false",
    "-c",
    "memories.use_memories=false",
    "-c",
    'web_search="disabled"',
    "-c",
    "mcp_servers.configured-server.enabled=false",
  ]);
  const modelRequest = fixture.processes[0].messages.find(
    ({ method }) => method === "model/list",
  );
  assert.equal(modelRequest.params.includeHidden, true);
  const threadRequest = fixture.processes[0].messages.find(
    ({ method }) => method === "thread/start",
  );
  assert.equal(threadRequest.params.approvalPolicy, "never");
  assert.equal(threadRequest.params.approvalsReviewer, "user");
  assert.equal(threadRequest.params.sandbox, "read-only");
  const turnRequest = fixture.processes[0].messages.find(
    ({ method }) => method === "turn/start",
  );
  assert.deepEqual(turnRequest.params.sandboxPolicy, {
    type: "readOnly",
    networkAccess: false,
  });
  assert.equal(turnRequest.params.approvalsReviewer, "user");
  assert.deepEqual(turnRequest.params.outputSchema, STRICT_SCHEMA);
});

test("accepts the protocol-default full completed-turn view", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method !== "turn/start") {
        return undefined;
      }
      const notification = completedTurn(
        message.params.threadId,
        "default-view-turn",
      );
      delete notification.params.turn.itemsView;
      return {
        result: { turn: { id: "default-view-turn" } },
        notification,
      };
    },
  });

  assert.equal((await fixture.adapter.run(request())).output, "done");
});

test("rejects a null completed-turn view", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method !== "turn/start") {
        return undefined;
      }
      const notification = completedTurn(
        message.params.threadId,
        "null-view-turn",
      );
      notification.params.turn.itemsView = null;
      return {
        result: { turn: { id: "null-view-turn" } },
        notification,
      };
    },
  });

  await assert.rejects(
    fixture.adapter.run(request()),
    hasCode("ERR_CODEX_PROTOCOL"),
  );
});

test("limits workspace writes to the requested repository", async () => {
  const fixture = createFixture();

  await fixture.adapter.run(request({ access: "workspace-write" }));

  const turnRequest = fixture.processes[0].messages.find(
    ({ method }) => method === "turn/start",
  );
  assert.deepEqual(turnRequest.params.sandboxPolicy, {
    type: "workspaceWrite",
    writableRoots: [PROJECT_PATH],
    networkAccess: false,
    excludeTmpdirEnvVar: true,
    excludeSlashTmp: true,
  });
});

test("rejects substitution of an explicit model", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "turn/start") {
        const turnId = "rerouted-turn";
        return {
          result: { turn: { id: turnId } },
          notification: [
            {
              method: "model/rerouted",
              params: {
                threadId: message.params.threadId,
                turnId,
                fromModel: "gpt-test",
                toModel: "gpt-other",
                reason: "test",
              },
            },
            completedTurn(message.params.threadId, turnId),
          ],
        };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(request({ model: "gpt-test" })),
    hasCode("ERR_CODEX_MODEL_REROUTED"),
  );
});

test("fails before starting a thread when isolation is incomplete", async () => {
  const configurations = Array.from({ length: 4 }, isolatedConfiguration);
  configurations[0].mcp_servers["configured-server"].enabled = true;
  configurations[1].features.multi_agent = true;
  configurations[2].shell_environment_policy.inherit = "all";
  delete configurations[3].mcp_servers["configured-server"];

  for (const config of configurations) {
    const fixture = createFixture({
      handle({ message }) {
        return message.method === "config/read"
          ? { result: { config } }
          : undefined;
      },
    });

    await assert.rejects(
      fixture.adapter.run(request()),
      hasCode("ERR_CODEX_ISOLATION"),
    );
    assert.equal(
      fixture.processes[0].messages.some(
        ({ method }) => method?.startsWith("thread/"),
      ),
      false,
    );
  }
});

test("rejects MCP names that cannot be overridden safely", async () => {
  const fixture = createFixture({
    executeHandle({ argumentsList }) {
      if (argumentsList.includes("mcp")) {
        return { stdout: '[{"name":"nested.server"}]', stderr: "" };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(request()),
    hasCode("ERR_CODEX_ISOLATION"),
  );
  assert.equal(fixture.processes.length, 0);
});

test("validates strict schemas and structured output", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "turn/start") {
        return {
          result: { turn: { id: "bad-output" } },
          notification: completedTurn(
            message.params.threadId,
            "bad-output",
            "[]",
          ),
        };
      }
      return undefined;
    },
  });
  const invalidSchema = {
    type: "object",
    properties: {
      result: {
        $defs: {
          detail: {
            type: "object",
            properties: { text: { type: "string" } },
            required: ["text"],
          },
        },
        type: "string",
      },
    },
    required: ["result"],
    additionalProperties: false,
  };
  const schemaWithObjectData = {
    type: "object",
    properties: {
      result: {
        enum: [{ type: "object" }],
      },
    },
    required: ["result"],
    additionalProperties: false,
  };
  let deeplyNestedSchema = { type: "string" };
  for (let depth = 0; depth < 130; depth += 1) {
    deeplyNestedSchema = { anyOf: [deeplyNestedSchema] };
  }
  deeplyNestedSchema = {
    type: "object",
    properties: { result: deeplyNestedSchema },
    required: ["result"],
    additionalProperties: false,
  };

  await assert.rejects(
    fixture.adapter.run(request({ schema: invalidSchema })),
    hasCode("ERR_INVALID_CODEX_SCHEMA"),
  );
  await assert.rejects(
    fixture.adapter.run(request({ schema: deeplyNestedSchema })),
    hasCode("ERR_INVALID_CODEX_SCHEMA"),
  );
  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "feat(test): create commit",
        },
        schema: STRICT_SCHEMA,
      }),
    ),
    hasCode("ERR_INVALID_CODEX_OPTIONS"),
  );
  assert.equal(fixture.processes.length, 0);
  await assert.rejects(
    fixture.adapter.run(request({ schema: schemaWithObjectData })),
    hasCode("ERR_CODEX_STRUCTURED_OUTPUT"),
  );
});

test("falls back to a fresh session when continuation is unavailable", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "thread/resume") {
        return { error: { code: -32000, message: "missing" } };
      }
      return undefined;
    },
  });

  const result = await fixture.adapter.run(
    request({
      access: "workspace-write",
      session: { mode: "continue", id: "source-thread" },
    }),
  );

  assert.equal(result.sessionId, "thread-1");
  assert.equal(fixture.processes.length, 2);
  assert.ok(
    fixture.processes[0].messages.some(
      ({ method }) => method === "thread/resume",
    ),
  );
  const retry = fixture.processes[1].messages.find(
    ({ method }) => method === "turn/start",
  );
  assert.match(retry.params.input[0].text, /^The previous Codex session/u);
  assert.deepEqual(retry.params.sandboxPolicy, {
    type: "workspaceWrite",
    writableRoots: [PROJECT_PATH],
    networkAccess: false,
    excludeTmpdirEnvVar: true,
    excludeSlashTmp: true,
  });
});

test("forks a source session directly and returns only the child lineage", async () => {
  const fixture = createFixture();

  const result = await fixture.adapter.run(
    request({ session: { mode: "fork", id: "source-thread" } }),
  );

  assert.equal(result.sessionId, "child-0");
  const threadMethods = fixture.processes[0].messages
    .map(({ method }) => method)
    .filter((method) => method?.startsWith("thread/"));
  assert.deepEqual(threadMethods, ["thread/fork"]);
});

test("fails instead of resuming or replacing an unavailable fork source", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "thread/fork") {
        return { error: { code: -32000, message: "missing" } };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { mode: "fork", id: "source-thread" } }),
    ),
    hasCode("ERR_CODEX_SOURCE_SESSION_UNAVAILABLE"),
  );
  assert.equal(fixture.processes.length, 1);
});

test("rejects a fork response without direct child lineage", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "thread/fork") {
        return {
          result: {
            thread: { id: "child-thread", forkedFromId: "other-thread" },
          },
        };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { mode: "fork", id: "source-thread" } }),
    ),
    hasCode("ERR_CODEX_PROTOCOL"),
  );
});

test("preserves the primary failure when app-server cleanup also fails", async () => {
  const fixture = createFixture({
    closeError: true,
    handle({ message }) {
      if (message.method === "thread/fork") {
        return {
          result: {
            thread: { id: "child-thread", forkedFromId: "other-thread" },
          },
        };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { mode: "fork", id: "source-thread" } }),
    ),
    hasCode("ERR_CODEX_PROTOCOL"),
  );
});

test("normalizes cleanup failures after a successful turn", async () => {
  const fixture = createFixture({ closeError: true });

  await assert.rejects(
    fixture.adapter.run(request()),
    (error) =>
      hasCode("ERR_CODEX_PROCESS_EXITED")(error) &&
      error.message === "Cannot close Codex app-server input.",
  );
});

test("ignores output failures after protocol shutdown", async () => {
  const fixture = createFixture({ closeOutputError: true });

  await assert.doesNotReject(fixture.adapter.run(request()));
});

test("rejects unexpected continuation lineage without a fresh fallback", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "thread/resume") {
        return { result: { thread: { id: "other-thread" } } };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { mode: "continue", id: "source-thread" } }),
    ),
    hasCode("ERR_CODEX_PROTOCOL"),
  );
  assert.equal(fixture.processes.length, 1);
});

test("creates an authorized commit through a networkless sandbox", async () => {
  const subject = "feat(branch): document push behavior";
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "turn/start") {
        return {
          result: { turn: { id: "commit-turn" } },
          notification: completedTurn(
            message.params.threadId,
            "commit-turn",
            '{"ready":true}',
          ),
        };
      }
      return undefined;
    },
  });

  const result = await fixture.adapter.run(
    request({
      access: "local-commit",
      authorizationId: "authorization-1",
      commit: { expectedHead: EXPECTED_HEAD, message: subject },
    }),
  );

  assert.deepEqual(result.structured, { ready: true });
  const turn = fixture.processes[0].messages.find(
    ({ method }) => method === "turn/start",
  );
  assert.match(turn.params.input[0].text, new RegExp(EXPECTED_HEAD, "u"));
  assert.match(turn.params.input[0].text, /adapter will perform/u);
  assert.deepEqual(turn.params.sandboxPolicy, {
    type: "readOnly",
    networkAccess: false,
  });
  assert.deepEqual(turn.params.outputSchema, {
    type: "object",
    properties: { ready: { type: "boolean" } },
    required: ["ready"],
    additionalProperties: false,
  });
  const gitCall = fixture.executeCalls.find(({ file }) => file === "git");
  assert.deepEqual(gitCall.argumentsList, [
    "-C",
    PROJECT_PATH,
    "rev-parse",
    "--absolute-git-dir",
    "--git-common-dir",
  ]);
  const sandboxCalls = fixture.executeCalls.filter(
    ({ argumentsList }) => argumentsList[0] === "sandbox",
  );
  assert.equal(sandboxCalls.length, 2);
  const commandSeparator = sandboxCalls[1].argumentsList.indexOf("--");
  assert.notEqual(commandSeparator, -1);
  assert.equal(
    sandboxCalls[1].argumentsList[commandSeparator + 1],
    process.execPath,
  );
  assert.ok(sandboxCalls[1].argumentsList.includes(EXPECTED_HEAD));
  assert.ok(sandboxCalls[1].argumentsList.includes(subject));
  assert.match(
    sandboxCalls[1].argumentsList.join(" "),
    /network=\{enabled=false\}/u,
  );
});

test("rejects forbidden Git and remote-write commands reported by Codex", async () => {
  for (const [command, code] of [
    ["git commit -m 'feat(test): bypass adapter'", "ERR_CODEX_LOCAL_COMMIT_POLICY"],
    ["git reset --hard HEAD^", "ERR_CODEX_LOCAL_COMMIT_POLICY"],
    ["git status && git stash", "ERR_CODEX_LOCAL_COMMIT_POLICY"],
    ["git -C . push origin main", "ERR_CODEX_REMOTE_WRITE_ATTEMPT"],
    [
      "git config remote.origin.url https://example.invalid/get",
      "ERR_CODEX_REMOTE_WRITE_ATTEMPT",
    ],
    ["git config --unset remote.origin.url", "ERR_CODEX_REMOTE_WRITE_ATTEMPT"],
    [
      "git config set remote.origin.url https://example.invalid/repository",
      "ERR_CODEX_REMOTE_WRITE_ATTEMPT",
    ],
    ["printf ok\ngit commit -m bypass", "ERR_CODEX_LOCAL_COMMIT_POLICY"],
    ["printf ok\ngit push origin main", "ERR_CODEX_REMOTE_WRITE_ATTEMPT"],
    ["gh workflow run build.yml", "ERR_CODEX_REMOTE_WRITE_ATTEMPT"],
    ["gh workflow enable build.yml", "ERR_CODEX_REMOTE_WRITE_ATTEMPT"],
    ["gh run rerun 1", "ERR_CODEX_REMOTE_WRITE_ATTEMPT"],
    ["gh repo fork owner/repository", "ERR_CODEX_REMOTE_WRITE_ATTEMPT"],
    [
      "gh api --method POST repos/owner/repository/issues",
      "ERR_CODEX_REMOTE_WRITE_ATTEMPT",
    ],
    [
      "glab api --method=patch projects/1",
      "ERR_CODEX_REMOTE_WRITE_ATTEMPT",
    ],
  ]) {
    const fixture = createFixture({
      handle({ message }) {
        if (message.method === "turn/start") {
          return {
            result: { turn: { id: "policy-turn" } },
            notification: completedTurn(
              message.params.threadId,
              "policy-turn",
              "Done.",
              [{ type: "commandExecution", command, status: "completed" }],
            ),
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
      hasCode(code),
    );
  }
});

test("allows read-only remote configuration inspection", async () => {
  for (const command of [
    "git config --get remote.origin.url",
    "git config --get remote.origin.url set",
    "git config remote.origin.url",
    "git config remote.origin.url >/dev/null",
    "git remote get-url origin",
    "gh run list",
    "gh api --method GET repos/owner/repository",
  ]) {
    const fixture = createFixture({
      handle({ message }) {
        if (message.method === "turn/start") {
          return {
            result: { turn: { id: "inspection-turn" } },
            notification: completedTurn(
              message.params.threadId,
              "inspection-turn",
              "Done.",
              [{ type: "commandExecution", command, status: "completed" }],
            ),
          };
        }
        return undefined;
      },
    });

    await assert.doesNotReject(fixture.adapter.run(request()));
  }
});

test("rejects disabled hosted web search reported by Codex", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "turn/start") {
        return {
          result: { turn: { id: "web-search-turn" } },
          notification: completedTurn(
            message.params.threadId,
            "web-search-turn",
            "Done.",
            [{ type: "webSearch", query: "example" }],
          ),
        };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(request()),
    hasCode("ERR_CODEX_NETWORK_POLICY"),
  );
});

test("rejects disabled integrations reported by Codex", async () => {
  for (const item of [
    {
      type: "mcpToolCall",
      readOnlyHint: true,
      server: "configured-server",
      tool: "read",
    },
    { type: "collabAgentToolCall", tool: "spawnAgent" },
    { type: "subAgentActivity", kind: "spawned" },
    { type: "hookPrompt", fragments: [] },
    { type: "agentMessage", text: "Done.", memoryCitation: {} },
    {
      type: "commandExecution",
      command: "pwd",
      pluginId: "plugin",
      status: "completed",
    },
  ]) {
    const fixture = createFixture({
      handle({ message }) {
        if (message.method === "turn/start") {
          return {
            result: { turn: { id: "isolated-turn" } },
            notification: completedTurn(
              message.params.threadId,
              "isolated-turn",
              "Done.",
              [item],
            ),
          };
        }
        return undefined;
      },
    });

    await assert.rejects(
      fixture.adapter.run(request()),
      hasCode("ERR_CODEX_ISOLATION"),
    );
  }
});

test("rejects disabled hosted tools and read-only file changes", async () => {
  for (const [item, code] of [
    [{ type: "imageGeneration" }, "ERR_CODEX_NETWORK_POLICY"],
    [
      { type: "fileChange", changes: [], status: "completed" },
      "ERR_CODEX_READ_ONLY_POLICY",
    ],
  ]) {
    const fixture = createFixture({
      handle({ message }) {
        if (message.method === "turn/start") {
          return {
            result: { turn: { id: "policy-turn" } },
            notification: completedTurn(
              message.params.threadId,
              "policy-turn",
              "Done.",
              [item],
            ),
          };
        }
        return undefined;
      },
    });

    await assert.rejects(fixture.adapter.run(request()), hasCode(code));
  }
});

test("rejects malformed turn items before accepting output", async () => {
  const items = [
    null,
    {
      type: "commandExecution",
      command: ["git", "push"],
      status: "completed",
    },
    { type: "commandExecution", command: "pwd", status: "inProgress" },
    { type: "futureToolCall" },
  ];
  for (const item of items) {
    const fixture = createFixture({
      handle({ message }) {
        if (message.method === "turn/start") {
          return {
            result: { turn: { id: "malformed-item-turn" } },
            notification: completedTurn(
              message.params.threadId,
              "malformed-item-turn",
              "Done.",
              [item],
            ),
          };
        }
        return undefined;
      },
    });

    await assert.rejects(
      fixture.adapter.run(request()),
      hasCode("ERR_CODEX_PROTOCOL"),
    );
  }
});

test("does not invoke the commit executor when Codex is not ready", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "turn/start") {
        return {
          result: { turn: { id: "commit-turn" } },
          notification: completedTurn(
            message.params.threadId,
            "commit-turn",
            '{"ready":false}',
          ),
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
    hasCode("ERR_CODEX_LOCAL_COMMIT_POLICY"),
  );
  assert.equal(
    fixture.executeCalls.filter(({ file }) => file === "git").length,
    0,
  );
});

test("never replays an interrupted local-commit turn", async () => {
  let turns = 0;
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "turn/start") {
        turns += 1;
        return {
          result: { turn: { id: "interrupted-turn" } },
          notification: {
            method: "turn/completed",
            params: {
              threadId: message.params.threadId,
              turn: {
                id: "interrupted-turn",
                itemsView: "full",
                status: "interrupted",
                items: [],
              },
            },
          },
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
    hasCode("ERR_CODEX_LOCAL_COMMIT_INTERRUPTED"),
  );
  assert.equal(turns, 1);
  assert.equal(fixture.processes.length, 1);
});

test("never commits from an incomplete completed-turn view", async () => {
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "turn/start") {
        return {
          result: { turn: { id: "partial-turn" } },
          notification: {
            method: "turn/completed",
            params: {
              threadId: message.params.threadId,
              turn: {
                id: "partial-turn",
                items: [{ type: "agentMessage", text: '{"ready":true}' }],
                itemsView: "summary",
                status: "completed",
              },
            },
          },
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
    hasCode("ERR_CODEX_PROTOCOL"),
  );
  assert.equal(fixture.processes.length, 1);
  assert.equal(
    fixture.executeCalls.filter(({ file }) => file === "git").length,
    0,
  );
});

test("never replays an incomplete completed-turn view", async () => {
  let turns = 0;
  const fixture = createFixture({
    handle({ message }) {
      if (message.method === "turn/start") {
        turns += 1;
        return {
          result: { turn: { id: "partial-turn" } },
          notification: {
            method: "turn/completed",
            params: {
              threadId: message.params.threadId,
              turn: {
                id: "partial-turn",
                items: [{ type: "agentMessage", text: "Done." }],
                itemsView: "summary",
                status: "completed",
              },
            },
          },
        };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(request({ access: "workspace-write" })),
    hasCode("ERR_CODEX_PROTOCOL"),
  );
  assert.equal(turns, 1);
  assert.equal(fixture.processes.length, 1);
});

test("returns commit-executor failures for Git-state verification", async () => {
  let sandboxCalls = 0;
  const fixture = createFixture({
    executeHandle({ argumentsList }) {
      if (argumentsList[0] === "sandbox") {
        sandboxCalls += 1;
        if (sandboxCalls === 2) {
          throw new Error("commit process exited");
        }
      }
      return undefined;
    },
    handle({ message }) {
      if (message.method === "turn/start") {
        return {
          result: { turn: { id: "commit-turn" } },
          notification: completedTurn(
            message.params.threadId,
            "commit-turn",
            '{"ready":true}',
          ),
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
    hasCode("ERR_CODEX_LOCAL_COMMIT_INTERRUPTED"),
  );
  assert.equal(sandboxCalls, 2);
  assert.equal(fixture.processes.length, 1);
});

test("compacts a full native context and retries the turn once", async () => {
  let turns = 0;
  const fixture = createFixture({
    handle({ message }) {
      if (message.method !== "turn/start") {
        return undefined;
      }
      turns += 1;
      const turnId = `context-turn-${turns}`;
      if (turns === 1) {
        return {
          result: { turn: { id: turnId } },
          notification: {
            method: "turn/completed",
            params: {
              threadId: message.params.threadId,
              turn: {
                id: turnId,
                itemsView: "full",
                status: "failed",
                error: { codexErrorInfo: "contextWindowExceeded" },
                items: [],
              },
            },
          },
        };
      }
      return {
        result: { turn: { id: turnId } },
        notification: completedTurn(message.params.threadId, turnId, "Recovered."),
      };
    },
  });

  const result = await fixture.adapter.run(request());

  assert.equal(result.output, "Recovered.");
  assert.equal(fixture.processes.length, 1);
  assert.deepEqual(
    fixture.processes[0].messages
      .map(({ method }) => method)
      .filter((method) => method === "turn/start" || method === "thread/compact/start"),
    ["turn/start", "thread/compact/start", "turn/start"],
  );
});

test("reconstructs a fresh turn when compaction cannot free the context", async () => {
  let turns = 0;
  const fixture = createFixture({
    handle({ message }) {
      if (message.method !== "turn/start") {
        return undefined;
      }
      turns += 1;
      const turnId = `context-turn-${turns}`;
      if (turns <= 2) {
        return {
          result: { turn: { id: turnId } },
          notification: {
            method: "turn/completed",
            params: {
              threadId: message.params.threadId,
              turn: {
                id: turnId,
                itemsView: "full",
                status: "failed",
                error: { codexErrorInfo: "context_window_exceeded" },
                items: [],
              },
            },
          },
        };
      }
      return {
        result: { turn: { id: turnId } },
        notification: completedTurn(message.params.threadId, turnId, "Fresh."),
      };
    },
  });

  const result = await fixture.adapter.run(request({ access: "workspace-write" }));

  assert.equal(result.sessionId, "thread-1");
  assert.equal(fixture.processes.length, 2);
  const retry = fixture.processes[1].messages.find(
    ({ method }) => method === "turn/start",
  );
  assert.match(retry.params.input[0].text, /^The previous Codex session/u);
});

test(
  "runs an opt-in real Codex smoke turn",
  {
    skip: process.env.AGENT_RUNNER_LIVE_CODEX !== "1",
    timeout: 120_000,
  },
  async () => {
    const adapter = createCodexAdapter();
    const result = await adapter.run(
      request({
        prompt: "Return JSON with ok set to true. Do not inspect files.",
        schema: STRICT_SCHEMA,
      }),
    );
    assert.deepEqual(result.structured, { ok: true });
  },
);
