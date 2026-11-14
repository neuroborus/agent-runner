import assert from "node:assert/strict";
import { execFile as executeFileCallback } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createClaudeAdapter } from "../../src/agents/index.js";
import { executeOwnedProcess } from "../../src/platform/index.js";
import { createWorkspaceService } from "../../src/workspace/index.js";

const executeFileAsync = promisify(executeFileCallback);
const SYNTHETIC_KEY = "sk-ant-synthetic-native-policy-key";
const SCHEMA = Object.freeze({
  type: "object",
  properties: { ok: { type: "boolean" } },
  required: ["ok"],
  additionalProperties: false,
});
const GIT_ENVIRONMENT = Object.freeze({
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
});
// Synthetic host provider routing and credentials that must never reach Claude.
const CONFLICTING_HOST_ENVIRONMENT = Object.freeze({
  ANTHROPIC_AUTH_TOKEN: "synthetic-conflicting-token",
  ANTHROPIC_CUSTOM_HEADERS: "x-synthetic-conflict: 1",
  ANTHROPIC_UNIX_SOCKET: "/nonexistent/synthetic-provider.sock",
  AWS_BEARER_TOKEN_BEDROCK: "synthetic-conflicting-token",
  CLAUDE_CODE_USE_BEDROCK: "1",
  CLAUDE_CODE_USE_VERTEX: "1",
  HTTPS_PROXY: "http://127.0.0.1:9",
});
// The workspace-write deny policy before the correction, kept only here.
const PRIOR_WORKSPACE_DENY_POLICY = Object.freeze([
  "Agent",
  "Task",
  "WebFetch",
  "WebSearch",
  "Edit(/.git)",
  "Edit(/.git/**)",
  "Bash(git add *)",
  "Bash(git branch *)",
  "Bash(git checkout *)",
  "Bash(git cherry-pick *)",
  "Bash(git clean *)",
  "Bash(git commit *)",
  "Bash(git merge *)",
  "Bash(git push *)",
  "Bash(git rebase *)",
  "Bash(git remote *)",
  "Bash(git reset *)",
  "Bash(git restore *)",
  "Bash(git revert *)",
  "Bash(git stash *)",
  "Bash(git switch *)",
  "Bash(git tag *)",
  "Bash(gh *)",
  "Bash(glab *)",
]);
// Claude's accept-edits fast path admits these filesystem commands natively.
const CONTENT_WORK =
  "mkdir -p notes && cp tracked.txt notes/copy.txt && mv notes/copy.txt notes/moved.txt";
// Script-driven content work has no native fast path.
const SCRIPT_WORK =
  "node -e \"require('node:fs').copyFileSync('tracked.txt', 'script-copy.txt')\"";
const MAINTAINED_CWD = "CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR";
const TURN_TIMEOUT_MS = 180_000;
const IDENTITY = [
  "-c",
  "user.name=Policy-Probe",
  "-c",
  "user.email=policy-probe@example.invalid",
];

async function installed(binary) {
  for (const directory of (process.env.PATH ?? "")
    .split(delimiter)
    .filter(isAbsolute)) {
    try {
      await access(join(directory, binary), constants.X_OK);
      return true;
    } catch {
      // Keep searching PATH.
    }
  }
  return false;
}

// Preserve the adapter's owned-process supervision for actual scripted turns.
async function realExecute(
  file,
  argumentsList,
  { input, onStdout, ...options },
) {
  if (options.onProcess !== undefined)
    return executeOwnedProcess(file, argumentsList, {
      ...options,
      input,
      onStdout,
    });
  const execution = executeFileAsync(file, argumentsList, {
    ...options,
    ...(onStdout === undefined ? {} : { encoding: "buffer" }),
  });
  let outputError;
  if (onStdout !== undefined)
    execution.child.stdout.on("data", (chunk) => {
      if (outputError !== undefined) return;
      try {
        onStdout(chunk);
      } catch (cause) {
        outputError = cause;
        execution.child.kill();
      }
    });
  execution.child.stdin.once("error", () => execution.child.kill());
  execution.child.stdin.end(input);
  try {
    const result = await execution;
    if (outputError !== undefined) throw outputError;
    return result;
  } catch (cause) {
    throw outputError ?? cause;
  }
}

// Fixture Git never inherits location, index or configuration routing.
function isolatedGitEnvironment(source) {
  return {
    ...Object.fromEntries(
      Object.entries(source).filter(([name]) => !name.startsWith("GIT_")),
    ),
    ...GIT_ENVIRONMENT,
  };
}

let gitEnvironment = isolatedGitEnvironment(process.env);

async function git(repository, ...argumentsList) {
  const { stdout } = await executeFileAsync(
    "git",
    ["-C", repository, ...argumentsList],
    { encoding: "utf8", env: gitEnvironment },
  );
  return stdout;
}

async function treeDigest(directory) {
  const hash = createHash("sha256");
  const entries = await readdir(directory, {
    recursive: true,
    withFileTypes: true,
  });
  for (const entry of entries
    .map((value) => ({ value, path: join(value.parentPath, value.name) }))
    .sort((left, right) => left.path.localeCompare(right.path))) {
    hash.update(`${entry.path}\0`);
    if (entry.value.isFile()) hash.update(await readFile(entry.path));
  }
  return hash.digest("hex");
}

// Snapshots do not include directory timestamps, so compare them separately.
async function directoryMetadata(path) {
  const metadata = await lstat(path, { bigint: true });
  return {
    entries: (await readdir(path)).sort(),
    mode: metadata.mode,
    dev: metadata.dev,
    ino: metadata.ino,
    mtimeNs: metadata.mtimeNs,
    ctimeNs: metadata.ctimeNs,
  };
}

async function createDirectorySource(directory, control) {
  const claude = join(directory, ".claude");
  await mkdir(claude, { recursive: true });
  await writeFile(join(directory, "source.txt"), "Source content.\n");
  if (control === "sparse") {
    await writeFile(join(claude, "notes.md"), "Notes.\n");
    return;
  }
  const skill = join(directory, ".agents", "skills", "inspection");
  await mkdir(skill, { recursive: true });
  await writeFile(
    join(skill, "SKILL.md"),
    "---\nname: inspection\ndescription: Inspect sources read-only.\n---\n\nInspect sources read-only.\n",
  );
  await writeFile(
    join(directory, "AGENTS.md"),
    "# Instructions\n\nInspect sources read-only.\n",
  );
  await symlink("AGENTS.md", join(directory, "CLAUDE.md"));
  await symlink(join("..", ".agents", "skills"), join(claude, "skills"));
}

async function gitState(repository) {
  return {
    head: await git(repository, "rev-parse", "HEAD"),
    refs: await git(repository, "for-each-ref"),
    remotes: await git(repository, "remote", "-v"),
    config: await readFile(join(repository, ".git", "config"), "utf8"),
    index: createHash("sha256")
      .update(await readFile(join(repository, ".git", "index")))
      .digest("hex"),
  };
}

function messageEvents(content, stopReason) {
  const events = [
    [
      "message_start",
      {
        message: {
          id: `msg_${randomUUID().replaceAll("-", "")}`,
          type: "message",
          role: "assistant",
          model: "policy-stub",
          content: [],
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: 1, output_tokens: 1 },
        },
      },
    ],
  ];
  for (const [index, block] of content.entries()) {
    const toolUse = block.type === "tool_use";
    events.push(
      [
        "content_block_start",
        {
          index,
          content_block: toolUse
            ? { ...block, input: {} }
            : { type: "text", text: "" },
        },
      ],
      [
        "content_block_delta",
        {
          index,
          delta: toolUse
            ? {
                type: "input_json_delta",
                partial_json: JSON.stringify(block.input),
              }
            : { type: "text_delta", text: block.text },
        },
      ],
      ["content_block_stop", { index }],
    );
  }
  events.push(
    [
      "message_delta",
      {
        delta: { stop_reason: stopReason, stop_sequence: null },
        usage: { output_tokens: 1 },
      },
    ],
    ["message_stop", {}],
  );
  return events
    .map(
      ([type, data]) =>
        `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`,
    )
    .join("");
}

// Answers main-loop requests from the current script and refuses every other
// request, including auto-mode classifier calls, without a retryable status.
function createMessagesStub() {
  // Each request repeats the transcript; tool results are keyed by their call.
  const state = { steps: [], unscripted: [], toolResults: new Map() };
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        body = undefined;
      }
      const pathname = new URL(request.url, "http://127.0.0.1").pathname;
      const main =
        request.method === "POST" &&
        pathname === "/v1/messages" &&
        body?.stream === true &&
        Array.isArray(body.tools) &&
        body.tools.some(({ name }) => name === "StructuredOutput") &&
        JSON.stringify(body.system ?? "").includes(
          "Native startup uses a separate private directory",
        );
      if (!main) {
        state.unscripted.push({ method: request.method, pathname });
        response.writeHead(400, {
          "content-type": "application/json",
          "x-should-retry": "false",
        });
        response.end(
          JSON.stringify({
            type: "error",
            error: { type: "invalid_request_error", message: "unscripted" },
          }),
        );
        return;
      }
      for (const message of body.messages)
        if (message.role === "user" && Array.isArray(message.content))
          for (const block of message.content)
            if (block.type === "tool_result")
              state.toolResults.set(block.tool_use_id, {
                error: block.is_error === true,
                content: JSON.stringify(block.content ?? ""),
              });
      const step =
        state.steps[
          body.messages.filter(({ role }) => role === "assistant").length
        ];
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.end(
        step === undefined
          ? messageEvents([{ type: "text", text: "Done." }], "end_turn")
          : messageEvents(
              step.map((value) => ({
                type: "tool_use",
                id: `toolu_${randomUUID().replaceAll("-", "")}`,
                ...value,
              })),
              "tool_use",
            ),
      );
    });
  });
  return { server, state };
}

function nativeDenials(records) {
  return records.filter(
    ({ type, subtype }) => type === "system" && subtype === "permission_denied",
  );
}

function bash(command) {
  // Completion must precede the next scripted request and source snapshot.
  return [
    {
      name: "Bash",
      input: {
        command,
        description: "Scripted step",
        run_in_background: false,
      },
    },
  ];
}

const STRUCTURED = [{ name: "StructuredOutput", input: { ok: true } }];

test(
  "authorizes workspace Bash through the proved sandbox under installed Claude",
  {
    skip:
      process.env.AGENT_RUNNER_NATIVE_CLAUDE !== "1" ||
      process.platform !== "linux" ||
      !(await installed("claude")) ||
      !(await installed("bwrap")),
  },
  async (t) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "agent-runner-claude-policy-")),
    );
    const unretired = new Set();
    t.after(async () => {
      if (unretired.size > 0)
        throw new Error(
          `Retained ${root}: owned processes ` +
            `${[...unretired].join(", ")} are not proved retired.`,
        );
      await rm(root, { force: true, recursive: true });
    });
    const { server, state } = createMessagesStub();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    t.after(() => new Promise((resolve) => server.close(resolve)));

    const home = join(root, "home");
    await mkdir(home);
    const loopback = `http://127.0.0.1:${server.address().port}`;
    // Only fixture-owned values reach Claude; host provider routing,
    // authentication, headers and credential descriptors are never inherited.
    // Owned decoys show that ambient Git routing cannot redirect fixture Git.
    const decoy = join(root, "ambient-git");
    await mkdir(decoy);
    const host = {
      ...process.env,
      ...CONFLICTING_HOST_ENVIRONMENT,
      GIT_DIR: join(decoy, "git-dir"),
      GIT_INDEX_FILE: join(decoy, "index"),
      GIT_WORK_TREE: decoy,
    };
    gitEnvironment = isolatedGitEnvironment(host);
    const providerEnvironment = {
      ...(host.LANG === undefined ? {} : { LANG: host.LANG }),
      PATH: host.PATH,
      HOME: home,
      ...GIT_ENVIRONMENT,
      ANTHROPIC_API_KEY: SYNTHETIC_KEY,
      ANTHROPIC_BASE_URL: loopback,
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      CLAUDE_CONFIG_DIR: join(root, "claude-config"),
    };
    let checkedInvocations = 0;
    function assertProviderEnvironment(environment, modelTurn) {
      checkedInvocations += 1;
      for (const name of Object.keys(environment))
        assert.ok(
          !/^(?:ANTHROPIC_|CLAUDE_CODE_USE_|AWS_)|PROXY$/iu.test(name) ||
            name === "ANTHROPIC_API_KEY" ||
            name === "ANTHROPIC_BASE_URL",
          name,
        );
      // Managed-settings readiness uses the credential-scrubbed command
      // environment; only an actual scripted turn requires authentication.
      if (modelTurn || environment.ANTHROPIC_API_KEY !== undefined)
        assert.equal(environment.ANTHROPIC_API_KEY, SYNTHETIC_KEY);
      if (modelTurn || environment.ANTHROPIC_BASE_URL !== undefined)
        assert.equal(environment.ANTHROPIC_BASE_URL, loopback);
    }

    let baseline = false;
    let cwdAdoption = false;
    let nativeOutput = [];
    function owned(options) {
      if (options.onProcess === undefined) return options;
      let pid;
      return {
        ...options,
        onProcess: async (value, proof) => {
          if (value !== null) {
            pid = value;
            unretired.add(pid);
          }
          await options.onProcess(value, proof);
          if (value === null) unretired.delete(pid);
        },
      };
    }
    const execute = (file, argumentsList, requested) => {
      const options = owned(requested);
      if (file === "claude")
        assertProviderEnvironment(options.env, argumentsList.includes("-p"));
      const settingsIndex = argumentsList.indexOf("--settings") + 1;
      if (!argumentsList.includes("-p") || settingsIndex === 0)
        return realExecute(file, argumentsList, options);
      // Native records stay test-local evidence of which decision applied.
      const turnOptions = {
        ...options,
        onStdout: (chunk) => {
          nativeOutput.push(Buffer.from(chunk));
          options.onStdout(chunk);
        },
      };
      if (!baseline && !cwdAdoption)
        return realExecute(file, argumentsList, turnOptions);
      const settings = JSON.parse(argumentsList[settingsIndex]);
      if (baseline) {
        settings.sandbox.autoAllowBashIfSandboxed = false;
        settings.permissions.deny = [...PRIOR_WORKSPACE_DENY_POLICY];
      }
      // The directory differential removes only cwd retention from both
      // environments; permissions and command projection remain identical.
      if (cwdAdoption) {
        assert.equal(settings.env[MAINTAINED_CWD], "1");
        assert.equal(options.env[MAINTAINED_CWD], "1");
        delete settings.env[MAINTAINED_CWD];
        turnOptions.env = Object.fromEntries(
          Object.entries(options.env).filter(
            ([name]) => name !== MAINTAINED_CWD,
          ),
        );
      }
      const rewritten = [...argumentsList];
      rewritten[settingsIndex] = JSON.stringify(settings);
      return realExecute(file, rewritten, turnOptions);
    };
    const adapter = createClaudeAdapter({
      env: providerEnvironment,
      execute,
      platform: "linux",
    });
    const capabilities = await adapter.probe();
    assert.equal(capabilities.workspaceWrite, true);
    assert.ok(checkedInvocations > 0);

    const workspace = createWorkspaceService();
    let repositoryCount = 0;
    async function turn(
      script,
      { prior = false, adoptCwd = false, control } = {},
    ) {
      repositoryCount += 1;
      const base = join(root, `case-${repositoryCount}`);
      const repository = join(
        base,
        control === undefined ? "repository" : "directory",
      );
      let before;
      let gitDigest;
      let inspection;
      let metadata;
      let snapshot;
      let workspacePolicy;
      if (control === undefined) {
        await executeFileAsync(
          "git",
          ["init", "--quiet", "-b", "main", repository],
          { env: gitEnvironment },
        );
        await writeFile(join(repository, "tracked.txt"), "Tracked content.\n");
        await git(repository, "add", "tracked.txt");
        await git(
          repository,
          ...IDENTITY,
          "commit",
          "--quiet",
          "-m",
          "Initial",
        );
        before = await gitState(repository);
        gitDigest = await treeDigest(join(repository, ".git"));
      } else {
        await createDirectorySource(repository, control);
        workspacePolicy = {
          kind: "directory",
          workspacePath: repository,
          stateRoot: join(base, "state"),
          inputPaths: [],
          sourcePaths: [],
          outputPaths: [],
        };
        const { kind: _kind, ...declarations } = workspacePolicy;
        inspection = await workspace.inspect(declarations);
        snapshot = await workspace.snapshot({ inspection });
        metadata = await Promise.all(
          [repository, join(repository, ".claude")].map(directoryMetadata),
        );
        const directoryCapabilities = await adapter.probe({
          access: "read-only",
          workspacePolicy,
        });
        assert.equal(directoryCapabilities.readOnly, true);
      }
      state.steps = [...script({ repository }), STRUCTURED];
      state.unscripted = [];
      state.toolResults = new Map();
      nativeOutput = [];
      baseline = prior;
      cwdAdoption = adoptCwd;
      const progress = [];
      const observations = [];
      const signal = AbortSignal.any([
        t.signal,
        AbortSignal.timeout(TURN_TIMEOUT_MS),
      ]);
      let result;
      let error;
      try {
        result = await adapter.run({
          access: control === undefined ? "workspace-write" : "read-only",
          cwd: repository,
          prompt: "Perform the requested repository steps.",
          schema: SCHEMA,
          onProgress: (value) => progress.push(value),
          onObservation: (value) => observations.push(value),
          onProcess: async () => {},
          signal,
          ...(workspacePolicy === undefined ? {} : { workspacePolicy }),
        });
      } catch (cause) {
        error = cause;
      } finally {
        baseline = false;
        cwdAdoption = false;
      }
      // Post-turn drift rejection must not hide an earlier interruption.
      assert.equal(signal.aborted, false, "The scripted turn was interrupted.");
      const publicText = JSON.stringify({
        error:
          error === undefined
            ? null
            : {
                code: error.code,
                diagnosticClass: error.diagnosticClass,
                failure: error.failure,
                message: error.message,
                recoverable: error.recoverable,
              },
        observations,
        progress,
      });
      for (const forbidden of [
        root,
        SYNTHETIC_KEY,
        "git ",
        "mkdir",
        "notes",
        "tracked.txt",
        "copyFileSync",
        "script-copy",
        "policy-note",
        ".git",
        "Permission to use",
        "policy-stub",
      ])
        assert.equal(publicText.includes(forbidden), false, forbidden);
      return {
        before,
        error,
        gitDigest,
        inspection,
        metadata,
        repository,
        result,
        snapshot,
        records: Buffer.concat(nativeOutput)
          .toString("utf8")
          .split("\n")
          .filter((line) => line.trim().length > 0)
          .map((line) => {
            try {
              return JSON.parse(line);
            } catch {
              assert.fail("Native stream contained invalid JSON.");
            }
          }),
        toolResults: [...state.toolResults.values()],
        unscripted: state.unscripted,
      };
    }
    async function assertGitUnchanged({ before, repository }) {
      assert.deepEqual(await gitState(repository), before);
    }
    async function assertDirectoryUnchanged(value) {
      workspace.assertUnchanged({
        before: value.snapshot,
        after: await workspace.snapshot({ inspection: value.inspection }),
      });
      assert.deepEqual(
        await Promise.all(
          [value.repository, join(value.repository, ".claude")].map(
            directoryMetadata,
          ),
        ),
        value.metadata,
      );
    }

    // A blanket subcommand rule rejects ordinary inspection with no closed code.
    const rule = await turn(() => [bash("git branch --show-current")], {
      prior: true,
    });
    assert.equal(rule.error?.code, "ERR_CLAUDE_PERMISSION_DENIED");
    assert.equal(rule.error.diagnosticClass, "permission_bash_unclassified");
    assert.equal(rule.error.failure.retry, "terminal");
    assert.deepEqual(rule.unscripted, []);
    await assertGitUnchanged(rule);

    // Without sandbox auto-allow, content work outside the native fast path
    // needs the classifier, which a loopback endpoint leaves unavailable.
    const content = await turn(() => [bash(SCRIPT_WORK)], { prior: true });
    assert.equal(content.error?.code, "ERR_CLAUDE_PERMISSION_DENIED");
    assert.equal(content.error.recoverable, false);
    assert.equal(content.error.failure.retry, "terminal");
    assert.deepEqual(
      nativeDenials(content.records).map(
        ({ tool_name: tool, decision_reason_type: type }) => [tool, type],
      ),
      [["Bash", "classifier"]],
    );
    await assert.rejects(access(join(content.repository, "script-copy.txt")), {
      code: "ENOENT",
    });
    await assertGitUnchanged(content);

    // The root-relative rule binds the native startup directory, so a
    // workspace Git-metadata write reaches the classifier instead of the rule.
    const priorMetadata = await turn(
      ({ repository }) => [
        [
          {
            name: "Write",
            input: {
              file_path: join(repository, ".git", "policy-note"),
              content: "Note.\n",
            },
          },
        ],
      ],
      { prior: true },
    );
    assert.equal(priorMetadata.error?.code, "ERR_CLAUDE_PERMISSION_DENIED");
    assert.deepEqual(
      nativeDenials(priorMetadata.records).map(
        ({ tool_name: tool, decision_reason_type: type }) => [tool, type],
      ),
      [["Write", "classifier"]],
    );
    assert.equal(
      await treeDigest(join(priorMetadata.repository, ".git")),
      priorMetadata.gitDigest,
    );

    const corrected = await turn(() => [
      bash("git branch --show-current"),
      bash("git status --short && git remote -v"),
      bash(CONTENT_WORK),
      bash(SCRIPT_WORK),
    ]);
    assert.equal(corrected.error, undefined);
    assert.deepEqual(corrected.result.structured, { ok: true });
    assert.deepEqual(corrected.unscripted, []);
    assert.equal(nativeDenials(corrected.records).length, 0);
    assert.equal(corrected.toolResults.length, 4);
    assert.ok(corrected.toolResults.every(({ error }) => !error));
    assert.ok(corrected.toolResults[0].content.includes("main"));
    // Claude's own settings deny workspace writes; only the authenticated
    // launcher grants them, so the moved file proves launcher execution.
    assert.equal(
      await readFile(join(corrected.repository, "notes", "moved.txt"), "utf8"),
      "Tracked content.\n",
    );
    assert.equal(
      await readFile(join(corrected.repository, "script-copy.txt"), "utf8"),
      "Tracked content.\n",
    );
    await assertGitUnchanged(corrected);
    await assert.rejects(lstat(join(corrected.repository, ".claude")), {
      code: "ENOENT",
    });

    // The first and only tool request reaches the absolute Git-path rule.
    // A loopback endpoint leaves auto mode without its server-side check, so
    // an unmatched file-tool request would instead carry a classifier decision.
    const metadata = await turn(({ repository }) => [
      [
        {
          name: "Write",
          input: {
            file_path: join(repository, ".git", "policy-note"),
            content: "Note.\n",
          },
        },
      ],
    ]);
    assert.equal(metadata.error?.code, "ERR_CLAUDE_PERMISSION_DENIED");
    assert.deepEqual(metadata.unscripted, []);
    assert.deepEqual(
      metadata.records
        .filter(({ type }) => type === "result")
        .flatMap(({ permission_denials: denials }) => denials)
        .map(({ tool_name: tool }) => tool),
      ["Write"],
    );
    assert.equal(
      nativeDenials(metadata.records).some(
        ({ decision_reason_type: type }) => type === "classifier",
      ),
      false,
    );
    await assert.rejects(
      access(join(metadata.repository, ".git", "policy-note")),
      { code: "ENOENT" },
    );
    assert.equal(
      await treeDigest(join(metadata.repository, ".git")),
      metadata.gitDigest,
    );

    // Direct metadata writes prove the command sandbox boundary independently
    // of Claude's additional native approval checks for Git commands.
    const mutation = await turn(() => [
      bash(
        "node -e \"require('node:fs').writeFileSync('.git/config', 'Blocked.')\"",
      ),
      bash(
        "node -e \"require('node:fs').writeFileSync('.git/HEAD', 'Blocked.')\"",
      ),
    ]);
    assert.equal(mutation.error, undefined);
    assert.deepEqual(mutation.result.structured, { ok: true });
    assert.ok(mutation.toolResults.length >= 2);
    assert.ok(
      mutation.toolResults.every(
        ({ error, content }) => error && /EROFS|EACCES|EPERM/u.test(content),
      ),
    );
    await assertGitUnchanged(mutation);
    await assert.rejects(lstat(join(mutation.repository, ".claude")), {
      code: "ENOENT",
    });

    // A later sandboxed command prepares staging in the adopted cwd. Keep the
    // successful native completion distinct from the adapter's drift rejection.
    const inspectSource = ({ repository }) => [
      bash("pwd"),
      [{ name: "Read", input: { file_path: join(repository, "source.txt") } }],
      bash("pwd"),
    ];
    function assertInspectionCompleted(value) {
      assert.deepEqual(value.unscripted, []);
      assert.equal(nativeDenials(value.records).length, 0);
      assert.equal(value.toolResults.length, 3);
      assert.ok(value.toolResults.every(({ error }) => !error));
      for (const index of [0, 2])
        assert.ok(value.toolResults[index].content.includes(value.repository));
      assert.ok(value.toolResults[1].content.includes("Source content."));
      const terminal = value.records.filter(({ type }) => type === "result");
      assert.equal(terminal.length, 1);
      assert.equal(terminal[0].subtype, "success");
      assert.equal(terminal[0].is_error, false);
      assert.equal((terminal[0].permission_denials ?? []).length, 0);
      assert.deepEqual(terminal[0].structured_output, { ok: true });
    }
    const lone = await turn(() => [bash("pwd")], {
      control: "linked",
      adoptCwd: true,
    });
    assert.equal(lone.error, undefined);
    assert.deepEqual(lone.result.structured, { ok: true });
    assert.deepEqual(lone.unscripted, []);
    assert.equal(nativeDenials(lone.records).length, 0);
    assert.equal(lone.toolResults.length, 1);
    assert.equal(lone.toolResults[0].error, false);
    assert.ok(lone.toolResults[0].content.includes(lone.repository));
    await assertDirectoryUnchanged(lone);
    for (const control of ["linked", "sparse"]) {
      const adopted = await turn(inspectSource, { control, adoptCwd: true });
      assertInspectionCompleted(adopted);
      assert.equal(adopted.error?.code, "ERR_CLAUDE_ISOLATION");
      assert.equal(adopted.error.diagnosticClass, "isolation_workspace_policy");
      assert.equal(adopted.result, undefined);
      const staging = join(adopted.repository, ".claude", ".cc-writes");
      const staged = await lstat(staging).catch(() =>
        assert.fail(`The ${control} control has no .claude/.cc-writes.`),
      );
      assert.ok(staged.isDirectory());
      assert.equal(staged.mode & 0o777, 0o700);
      assert.deepEqual(await readdir(staging), []);
      const after = await workspace.snapshot({
        inspection: adopted.inspection,
      });
      assert.throws(() =>
        workspace.assertUnchanged({ before: adopted.snapshot, after }),
      );
      const current = await turn(inspectSource, { control });
      assert.equal(current.error, undefined);
      assert.deepEqual(current.result.structured, { ok: true });
      assertInspectionCompleted(current);
      await assertDirectoryUnchanged(current);
    }
    assert.deepEqual(await readdir(decoy), []);
  },
);
