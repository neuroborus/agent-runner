import assert from "node:assert/strict";
import test from "node:test";
import { Writable, PassThrough, Readable } from "node:stream";
import { EventEmitter } from "node:events";
import {
  nativePackageInput,
  normalizeNativePackageReview,
  nativePackageReviewDigest,
  observationDigest,
} from "../index.js";
import {
  CLAUDE_TOOLS,
  CLAUDE_TOOL_CASES,
  normalizeProviderSpec,
  providerInvocation,
  normalizeClaudeCases,
  assertClaudeLiveBinding,
  assertClaudeToolTurn,
  assertClaudeModelReceipts,
  openClaudeStream,
  runClaudeMediationCase,
  createProtectedRelay,
  claudeInvocation,
  normalizeClaudeToolSet,
} from "./index.js";
import {
  windowsProviderLaunch,
  windowsClaudeBash,
  assertWindowsClaudeBash,
  WINDOWS_ARGUMENT_PARSER,
} from "../win32/index.js";

const HASH = "a".repeat(64),
  CANDIDATE = "b".repeat(40),
  NONCE = "c".repeat(32);
const SESSION = "12345678-1234-1234-1234-123456789012";
const reference = {
  url: "https://example.org/review",
  revision: null,
  sha256: HASH,
};
const bindings = () =>
  Object.fromEntries(
    [
      "publication",
      "source",
      "build",
      "dependencies",
      "license",
      "abi",
      "transport",
      "extraction",
    ].map((key) => [key, reference]),
  );
const gitReview = normalizeNativePackageReview(
  {
    schemaVersion: 1,
    candidateSha: CANDIDATE,
    packageId: "git-for-windows",
    archiveBytes: nativePackageInput("git-for-windows").bytes,
    bindings: bindings(),
    files: [
      { path: "usr/bin/bash.exe", bytes: 100, sha256: HASH, executable: true },
    ],
  },
  CANDIDATE,
);
const apiTools = CLAUDE_TOOLS.map((name) => ({
  name,
  input_schema: { type: "object" },
}));
function fixture(profile = "read-only", platform = "linux") {
  const publication = nativePackageInput("claude-" + platform),
    windows = platform === "win32";
  const review = {
    schemaVersion: 1,
    candidateSha: CANDIDATE,
    packageId: publication.id,
    archiveBytes: publication.bytes ?? 100,
    bindings: { ...bindings(), source: null },
    files: [
      {
        path: publication.entrypoint,
        bytes: 100,
        sha256: HASH,
        executable: true,
      },
    ],
  };
  if (windows)
    review.bindings.dependencies = {
      ...reference,
      sha256: nativePackageReviewDigest(gitReview),
    };
  const spec = normalizeProviderSpec({
    candidateSha: CANDIDATE,
    nonce: NONCE,
    provider: "claude",
    platform,
    profile,
    review,
    home: windows
      ? "C:\\Fixture\\Storage\\provider-home"
      : platform === "linux"
        ? "/home/provider"
        : "/fixture/storage/home",
    cache: windows
      ? "C:\\Fixture\\Storage\\provider-cache"
      : platform === "linux"
        ? "/cache"
        : "/fixture/storage/cache",
    path: windows ? "C:\\Fixture\\Storage\\runtime" : "/fixture/runtime",
    endpoint: "http://127.0.0.1:41001",
    model: "reviewed-model",
  });
  const output = "independent-inspection-nonce",
    outputSha256 = observationDigest(output);
  const permitted = (id) =>
    [
      "command",
      "read",
      "glob",
      "grep",
      "end-conversation",
      "background-cancel",
      "background-helper-loss",
    ].includes(id) ||
    (["edit", "write"].includes(id) && profile !== "read-only");
  const toolInput = (id, name) => {
    const file_path = "/fixture/work/" + id;
    if (name === "Bash")
      return {
        command: "fixture-command " + id,
        ...(id.startsWith("background-") ? { run_in_background: true } : {}),
      };
    if (name === "Read") return { file_path };
    if (name === "Glob") return { pattern: "*.txt", path: "/fixture/work" };
    if (name === "Grep") return { pattern: "marker", path: "/fixture/work" };
    if (name === "Edit")
      return { file_path, old_string: "before", new_string: "after" };
    return { file_path, content: "after" };
  };
  const cases = normalizeClaudeCases(spec, {
    cwd: "/fixture/work",
    registrySha256: observationDigest(apiTools),
    plan: {
      schemaVersion: 1,
      candidateSha: CANDIDATE,
      nonce: NONCE,
      domainSha256: HASH,
      policySha256: HASH,
      reviewSha256: HASH,
      routes: Object.entries(CLAUDE_TOOL_CASES).map(([id, [operation]]) => ({
        id,
        operation,
        targetSha256: HASH,
        permitTargetSha256: "d".repeat(64),
        denyTargetSha256: "e".repeat(64),
        nonceSha256: HASH,
        beforeSha256: HASH,
        afterSha256:
          ["edit", "write"].includes(id) && permitted(id)
            ? "f".repeat(64)
            : HASH,
        outcome: permitted(id) ? "permit" : "deny",
      })),
    },
    cases: Object.entries(CLAUDE_TOOL_CASES).map(([id, [, name]]) => ({
      id,
      tools: [
        ...(id === "edit"
          ? [{ name: "Read", input: toolInput(id, "Read"), outputSha256 }]
          : []),
        {
          name,
          input: toolInput(id, name),
          outputSha256: [
            "command",
            "read",
            "glob",
            "grep",
            "end-conversation",
          ].includes(id)
            ? outputSha256
            : null,
        },
        // Opaque terminal inputs are reviewed fixture data, not a claimed SDK schema.
        {
          name: "EndConversation",
          input: { reason: "fixture-complete" },
          outputSha256: null,
        },
      ],
    })),
  });
  const turn = (id) => ({
    sessionId: SESSION,
    messageIds: ["msg-1"],
    taskIds: id.startsWith("background-") ? ["task-1"] : [],
    tools: cases.cases
      .find((item) => item.id === id)
      .tools.map((tool, index, tools) => ({
        ...tool,
        id: "tool-" + index,
        messageId: "msg-1",
        result: {
          content: tool.name === "EndConversation" ? null : output,
          isError:
            tool.name !== "EndConversation" &&
            index === tools.length - 2 &&
            !permitted(id),
        },
      })),
  });
  const live = {
    independent: true,
    status: "MATCHED",
    nativeSha256: HASH,
    candidateSha: CANDIDATE,
    nonce: NONCE,
    version: "2.1.285",
    dispatcherSource: "UNAVAILABLE",
    platform,
    profile,
    model: spec.model,
    packageSha256: spec.closureSha256,
    imageSha256: HASH,
    invocationSha256: observationDigest(providerInvocation(spec)),
    casesSha256: observationDigest(cases),
    registrySha256: cases.registrySha256,
    cwd: cases.cwd,
    domainSha256: HASH,
    policySha256: HASH,
    outerCompositionSha256: HASH,
    enabledTools: [...CLAUDE_TOOLS],
    ...Object.fromEntries(
      ["build", "dependencies", "abi", "license"].map((key) => [
        key + "Sha256",
        spec.review.bindings[key].sha256,
      ]),
    ),
    ...Object.fromEntries(
      [
        "heldImages",
        "loaderClosure",
        "effectivePolicy",
        "privateHomeConfig",
        "noRealCredential",
        "noHooks",
        "noPlugins",
        "noMcp",
        "noUpdater",
        "noAlternateInstall",
        "nativeRuntimeBound",
        "fileToolsBound",
        "backgroundChildrenBound",
        "relayReceiptPipePrivate",
      ].map((key) => [key, true]),
    ),
  };
  return { spec, cases, turn, live, output };
}
function receipts(spec, cases, turn, configurationSha256 = HASH) {
  return {
    independent: true,
    candidateSha: CANDIDATE,
    nonce: NONCE,
    configurationSha256,
    relaySha256: HASH,
    receipts: [
      {
        provider: "claude",
        nonce: NONCE,
        model: spec.model,
        sequence: 1,
        registrySha256: cases.registrySha256,
        messageId: "msg-1",
        toolUses: turn.tools.map((tool) => ({
          id: tool.id,
          name: tool.name,
          inputSha256: observationDigest(tool.input),
        })),
        requestSha256: HASH,
        responseSha256: HASH,
        completed: true,
      },
    ],
  };
}

test("all platforms/profiles require six effect routes, terminal dispatch and release-bound outer authority", () => {
  for (const platform of ["linux", "darwin", "win32"])
    for (const profile of ["read-only", "workspace-write", "trusted-command"]) {
      const { spec, cases, turn, live } = fixture(profile, platform);
      assertClaudeLiveBinding(spec, cases, live);
      for (const id of Object.keys(CLAUDE_TOOL_CASES))
        assertClaudeToolTurn(spec, cases, id, turn(id));
      const invocation = providerInvocation(spec);
      assert.equal(
        invocation.execution.environment.CLAUDE_CONFIG_DIR,
        spec.home,
      );
      assert.equal(
        invocation.execution.environment.ANTHROPIC_AUTH_TOKEN,
        "native-poc-" + NONCE,
      );
      assert.ok(
        invocation.arguments.includes("--bare") &&
          invocation.arguments.includes("--strict-mcp-config"),
      );
      for (const change of [
        { dispatcherSource: "AVAILABLE" },
        { fileToolsBound: false },
        { backgroundChildrenBound: false },
        { enabledTools: [...CLAUDE_TOOLS, "mcp__fixture"] },
        { cwd: "/other" },
      ])
        assert.throws(() =>
          assertClaudeLiveBinding(spec, cases, { ...live, ...change }),
        );
    }
  const { spec, cases, turn } = fixture();
  assert.throws(() =>
    normalizeClaudeCases(spec, { ...cases, cases: cases.cases.slice(1) }),
  );
  const unboundRead = structuredClone(cases);
  unboundRead.cases.find((item) => item.id === "edit").tools[0].outputSha256 =
    null;
  assert.throws(() => normalizeClaudeCases(spec, unboundRead));
  for (const change of [
    { name: "controller-read" },
    { input: { file_path: "/other" } },
    { result: { content: "invented-nonce", isError: false } },
    { result: { content: "refused", isError: true } },
  ]) {
    const changed = turn("read");
    Object.assign(changed.tools[0], change);
    assert.throws(() => assertClaudeToolTurn(spec, cases, "read", changed));
  }
  const value = receipts(spec, cases, turn("read"));
  assertClaudeModelReceipts(spec, HASH, HASH, cases, turn("read"), value);
  for (const change of [
    { completed: false },
    { messageId: "foreign" },
    { toolUses: [] },
    { toolUses: [...value.receipts[0].toolUses].reverse() },
    { sequence: 2 },
    { registrySha256: HASH },
    ...[{ name: "Glob" }, { inputSha256: HASH }].map((change) => ({
      toolUses: value.receipts[0].toolUses.map((tool, index) =>
        index === 0 ? { ...tool, ...change } : tool,
      ),
    })),
  ])
    assert.throws(() =>
      assertClaudeModelReceipts(spec, HASH, HASH, cases, turn("read"), {
        ...value,
        receipts: [{ ...value.receipts[0], ...change }],
      }),
    );
});

function stream(spec, turn, mode = "normal", selectedTools = CLAUDE_TOOLS) {
  const output = new PassThrough(),
    errorOutput = new PassThrough(),
    calls = [];
  const emit = (value) =>
    output.write(JSON.stringify({ session_id: SESSION, ...value }) + "\n");
  const input = new Writable({
    write(chunk, encoding, done) {
      calls.push(JSON.parse(chunk.toString()));
      if (mode === "stall") {
        done();
        return;
      }
      if (mode === "input-error") {
        done(new Error("Fixture input closed"));
        return;
      }
      if (mode === "overflow") {
        output.write(Buffer.alloc(1048577, 120));
        done();
        return;
      }
      emit({
        type: "system",
        subtype: "init",
        model: spec.model,
        claude_code_version: "2.1.285",
        permissionMode: "bypassPermissions",
        tools: [...selectedTools, ...(mode === "registry" ? ["Task"] : [])],
        mcp_servers: [],
      });
      const tools = mode === "refusal" ? [] : turn.tools;
      emit({
        type: "assistant",
        message: {
          id: "msg-1",
          role: "assistant",
          model: spec.model,
          content: tools.map((tool) => ({
            type: "tool_use",
            id: tool.id,
            name: tool.name,
            input: tool.input,
          })),
        },
        ...(mode === "foreign"
          ? { session_id: "87654321-1234-1234-1234-123456789012" }
          : {}),
      });
      for (const tool of tools.filter(
        (tool) => tool.name !== "EndConversation",
      )) {
        if (mode !== "missing-result")
          emit({
            type: "user",
            message: {
              role: "user",
              content: [
                {
                  type: "tool_result",
                  tool_use_id: tool.id,
                  content: tool.result.content,
                  is_error: tool.result.isError,
                },
              ],
            },
          });
        if (turn.taskIds.length)
          emit({
            type: "system",
            subtype: "task_started",
            task_id: "task-1",
            task_type: "local_bash",
            tool_use_id: tool.id,
          });
      }
      emit({
        type: "result",
        subtype: mode === "permission" ? "error_during_execution" : "success",
        is_error: false,
        permission_denials:
          mode === "permission" ? [{ tool_name: "Read" }] : [],
      });
      done(
        mode === "late-input-error"
          ? new Error("Fixture input flush failed")
          : undefined,
      );
    },
  });
  return {
    calls,
    transport: {
      input,
      output,
      errorOutput,
      completion: new Promise(() => {}),
    },
  };
}
test("opaque JSONL rejects foreign sessions, approvals, refusal, missing returns, excess bytes and broken input", async () => {
  const { spec, cases, turn } = fixture();
  for (const mode of [
    "normal",
    "registry",
    "foreign",
    "permission",
    "refusal",
    "missing-result",
    "input-error",
    "late-input-error",
    "overflow",
    "stall",
  ]) {
    const server = stream(spec, turn("read"), mode),
      controller = new AbortController();
    const driver = openClaudeStream(server.transport, spec, controller.signal);
    try {
      const work = driver.turn("Inspect the fixture", async () => {});
      if (mode === "normal") {
        assertClaudeToolTurn(spec, cases, "read", await work);
        server.transport.output.end();
        server.transport.errorOutput.end();
      } else {
        if (mode === "stall") controller.abort();
        await assert.rejects(work);
      }
      assert.equal(server.calls[0].type, "user");
    } finally {
      await driver.close();
    }
  }
});

test("Claude invocation and stream share an exact validated optional tool subset", async () => {
  const tools = ["Bash", "Read", "Write", "EndConversation"],
    { spec, turn } = fixture();
  const argumentsList = claudeInvocation(
    spec,
    "native-poc-fixture",
    tools,
  ).arguments;
  assert.equal(
    argumentsList[argumentsList.indexOf("--tools") + 1],
    tools.join(","),
  );
  assert.deepEqual(normalizeClaudeToolSet(), CLAUDE_TOOLS);
  for (const invalid of [
    ["Read"],
    ["Read", "Read", "EndConversation"],
    ["Task", "EndConversation"],
    ["EndConversation"],
  ])
    assert.throws(() => claudeInvocation(spec, "native-poc-fixture", invalid));
  for (const mode of ["subset", "registry", "undeclared"]) {
    const selected = turn("read");
    if (mode === "undeclared")
      Object.assign(selected.tools[0], {
        name: "Glob",
        input: { pattern: "*" },
      });
    const server = stream(
      spec,
      selected,
      "normal",
      mode === "registry" ? CLAUDE_TOOLS : tools,
    );
    const driver = openClaudeStream(server.transport, spec, undefined, tools);
    try {
      const work = driver.turn("Inspect the synthetic fixture", async () => {});
      if (mode === "subset") {
        assert.equal((await work).tools[0].name, "Read");
        server.transport.output.end();
        server.transport.errorOutput.end();
      } else await assert.rejects(work);
    } finally {
      await driver.close();
    }
  }
});

test("protected Anthropic receipts bind model tool names/inputs and reject incomplete or substituted dispatch", async () => {
  const { spec, cases, turn } = fixture(),
    selected = turn("read");
  const events = [
    {
      type: "message_start",
      message: { id: "msg-1", role: "assistant", content: [] },
    },
    ...selected.tools.flatMap((tool, index) => {
      const input = JSON.stringify(tool.input),
        middle = Math.floor(input.length / 2);
      return [
        {
          type: "content_block_start",
          index,
          content_block: {
            type: "tool_use",
            id: tool.id,
            name: tool.name,
            input: {},
          },
        },
        {
          type: "content_block_delta",
          index,
          delta: {
            type: "input_json_delta",
            partial_json: input.slice(0, middle),
          },
        },
        {
          type: "content_block_delta",
          index,
          delta: {
            type: "input_json_delta",
            partial_json: input.slice(middle),
          },
        },
        { type: "content_block_stop", index },
      ];
    }),
    { type: "message_delta", delta: { stop_reason: "tool_use" } },
    { type: "message_stop" },
  ];
  for (const format of [
    "json",
    "sse",
    "incomplete",
    "truncated",
    "duplicate",
    "missing-input",
    "wrong-input",
    "wrong-name",
  ]) {
    const records = structuredClone(events);
    if (format === "truncated") records.at(-2).delta.stop_reason = "max_tokens";
    if (format === "duplicate") records.splice(2, 0, records[1]);
    if (format === "incomplete") records.pop();
    if (format === "missing-input") records.splice(2, 2);
    if (["wrong-input", "wrong-name"].includes(format)) {
      records[1].content_block.name = format === "wrong-name" ? "Glob" : "Read";
      records[2].delta.partial_json = JSON.stringify(
        format === "wrong-name"
          ? { pattern: "*.txt" }
          : { file_path: "/other" },
      );
      records[3].delta.partial_json = "";
    }
    const captured = [],
      policy = {
        provider: "claude",
        nonce: NONCE,
        model: spec.model,
        requests: 2,
        outputTokens: 32,
        budgetMicros: 100000,
        inputMicros: 1,
        outputMicros: 1,
        beta: [],
      };
    const body =
      format === "json"
        ? JSON.stringify({
            type: "message",
            id: "msg-1",
            role: "assistant",
            stop_reason: "tool_use",
            content: selected.tools.map((tool) => ({
              type: "tool_use",
              id: tool.id,
              name: tool.name,
              input: tool.input,
            })),
          })
        : records
            .map((record) => "data: " + JSON.stringify(record) + "\n\n")
            .join("");
    const relay = createProtectedRelay(policy, "synthetic-secret", {
      onReceipt: (value) => captured.push(value),
      request(url, options, respond) {
        const request = new EventEmitter();
        request.destroy = () => {};
        request.end = () =>
          queueMicrotask(() => {
            const incoming = Readable.from([Buffer.from(body)]);
            incoming.statusCode = 200;
            incoming.complete = true;
            incoming.headers = {
              "content-type":
                format === "json" ? "application/json" : "text/event-stream",
              "set-cookie": "synthetic-cookie",
            };
            respond(incoming);
          });
        assert.equal(options.headers.authorization, undefined);
        return request;
      },
    });
    try {
      const work = relay.forward(
        {
          method: "POST",
          path: "/v1/messages",
          headers: { authorization: "Bearer native-poc-" + NONCE },
          body: Buffer.from(
            JSON.stringify({
              model: spec.model,
              messages: [],
              tools: apiTools,
            }),
          ),
        },
        async () => {},
      );
      if (["truncated", "duplicate", "missing-input"].includes(format))
        await assert.rejects(work);
      else {
        await work;
        assert.equal(captured[0].completed, format !== "incomplete");
        const join = () =>
          assertClaudeModelReceipts(spec, HASH, HASH, cases, selected, {
            ...receipts(spec, cases, selected),
            receipts: captured,
          });
        if (["wrong-input", "wrong-name"].includes(format)) assert.throws(join);
        else if (format !== "incomplete") join();
        assert.doesNotMatch(
          JSON.stringify(captured),
          /synthetic-secret|synthetic-cookie/u,
        );
      }
    } finally {
      relay.close();
    }
  }
});

test("Windows Bash requires a reviewed immutable native Git closure, held file identity and the same token/Job", () => {
  const { spec } = fixture("read-only", "win32");
  const base = {
    schemaVersion: 1,
    candidateSha: CANDIDATE,
    nonce: NONCE,
    restrictingSid: "S-1-5-21-4-5-6-1002",
    custody: "C:\\Fixture\\Custody",
    storage: "C:\\Fixture\\Storage",
    workspace: "C:\\Fixture\\Storage\\Work",
    launcher: {
      path: "C:\\Fixture\\Custody\\launcher.exe",
      sha256: HASH,
      signatureSha256: HASH,
    },
    executable: {
      path: "C:\\Fixture\\Storage\\payload.exe",
      sha256: HASH,
      signatureSha256: HASH,
      parser: WINDOWS_ARGUMENT_PARSER,
    },
    policy: { path: "C:\\Fixture\\Custody\\policy.json", sha256: HASH },
    bindings: {
      system: HASH,
      source: HASH,
      policy: HASH,
      closure: spec.closureSha256,
    },
  };
  const bash = { root: "C:\\Fixture\\Storage\\git", review: gitReview },
    launch = windowsProviderLaunch(spec, { ...base, bash });
  assert.equal(
    launch.request.execution.environment.CLAUDE_CODE_GIT_BASH_PATH,
    launch.bash.path,
  );
  for (const root of [
    "\\\\server\\share",
    "C:\\Fixture\\Storage\\Work\\git",
    "C:\\Unreviewed\\git",
    spec.home + "\\git",
    spec.cache + "\\git",
  ])
    assert.throws(() => windowsClaudeBash(spec, base, { ...bash, root }));
  assert.throws(() => windowsProviderLaunch(spec, base));
  const record = {
    requestSha256: HASH,
    setup: { job: { heldObjectSha256: HASH } },
  };
  const value = {
    ...launch.bash,
    independent: true,
    requestSha256: HASH,
    candidateSha: CANDIDATE,
    nonce: NONCE,
    nativeSha256: HASH,
    identity: "1".repeat(16) + ":" + "2".repeat(32),
    links: 1,
    jobSha256: HASH,
    untrustedWritable: false,
    ...Object.fromEntries(
      [
        "held",
        "revalidated",
        "noReparse",
        "privateDacl",
        "readExecuteOnly",
        "sameTokenJob",
        "noWsl",
        "noPathFallback",
        "loaderClosureVerified",
        "dataOnlyExtractionVerified",
      ].map((key) => [key, true]),
    ),
  };
  assertWindowsClaudeBash(launch.bash, value, launch.request, record);
  for (const change of [
    { noWsl: false },
    { sameTokenJob: false },
    { links: 2 },
    { untrustedWritable: true },
    { identity: "pathname" },
    { sha256: "d".repeat(64) },
  ])
    assert.throws(() =>
      assertWindowsClaudeBash(
        launch.bash,
        { ...value, ...change },
        launch.request,
        record,
      ),
    );
});

test("native controls precede Claude prompts, faults follow independent reads and missing proof retains exclusion", async () => {
  for (const [id, fault] of [
    ["read", null],
    ["edit", null],
    ["background-cancel", null],
    ["background-helper-loss", null],
    ["read", "model"],
    ["read", "drop"],
    ["read", "observer-retained"],
    ["read", "observer-error"],
    ["read", "observer-stall"],
    ["background-helper-loss", "fault"],
    ["background-cancel", "already-retired"],
  ]) {
    const { spec, cases, turn, live } = fixture(),
      server = stream(spec, turn(id)),
      events = [],
      persisted = [];
    const policy = {
      provider: "claude",
      nonce: NONCE,
      model: spec.model,
      requests: 32,
      outputTokens: 10,
      budgetMicros: 100000,
      inputMicros: 1,
      outputMicros: 1,
      beta: [],
    };
    const configurationSha256 = observationDigest({
      specificationSha256: providerInvocation(spec).specificationSha256,
      policy,
    });
    const binding = {
        independent: true,
        candidateSha: CANDIDATE,
        nonce: NONCE,
        configurationSha256,
      },
      verified = {
        ...binding,
        nativeSha256: HASH,
        packageSha256: spec.closureSha256,
        profile: spec.profile,
        endpoint: spec.endpoint,
        ...Object.fromEntries(
          [
            "relayAdmitted",
            "bridgeAdmitted",
            "receiptsVerified",
            "privatePipes",
            "credentialCustodyProtected",
            "providerHasNoCredential",
            "environmentAllowlist",
            "handleAllowlist",
            "endpointExclusive",
            "receivingPrincipalVerified",
            "noInspection",
            "noDebug",
            "noSignalling",
            "noFilesystemAccess",
            "ownedChangesOnly",
          ].map((key) => [key, true]),
        ),
      };
    let expire,
      settlementExpired = false;
    const options = {
      schedule(callback, duration) {
        if (duration === 120000) expire = callback;
        if (
          fault === "observer-stall" &&
          duration === 30000 &&
          events.includes("transport-retired") &&
          !settlementExpired
        ) {
          settlementExpired = true;
          queueMicrotask(callback);
        }
        return 1;
      },
      cancel() {},
    };
    const effects = {
      async persist(value) {
        persisted.push(structuredClone(value));
      },
      async review() {
        return {
          ...binding,
          status: "MATCHED",
          packageSha256: spec.closureSha256,
        };
      },
      async admitTransport(role) {
        return {
          ...binding,
          role,
          admitted: true,
          receiptVerified: true,
          nativeSha256: HASH,
        };
      },
      async verifyTransport() {
        return structuredClone(verified);
      },
      async controls() {
        events.push("transport-controls");
        return {
          ...binding,
          cases: Object.fromEntries(
            [
              "transport",
              "credential-file",
              "credential-environment",
              "credential-process",
              "debug",
              "signal",
              "alternate-network",
              "alternate-ipc",
              "relay-loss",
              "bridge-loss",
            ].map((key) => [
              key,
              {
                attempted: true,
                acknowledged: true,
                independent: true,
                expectedEffect: true,
                sentinelsUnchanged: true,
                nativeSha256: HASH,
              },
            ]),
          ),
        };
      },
      async inspect() {
        return structuredClone(live);
      },
      async modelReceipts() {
        const value = receipts(spec, cases, turn(id), configurationSha256);
        value.receipts[0].completed = fault !== "model";
        return value;
      },
      async observe(domain, plan, execute) {
        assert.equal(server.calls.length, 0);
        events.push("native-controls");
        try {
          await execute({
            signal: new AbortController().signal,
            async attempt(selected, action) {
              events.push("armed");
              await action();
              events.push("native-read");
            },
          });
        } finally {
          events.push("observer-retired");
        }
        if (fault === "observer-error")
          throw new Error("Fixture observer unsettled");
        if (fault === "observer-stall") {
          expire();
          return new Promise(() => {});
        }
        return {
          status: fault === "drop" ? "FAIL" : "OBSERVED",
          phase: fault === "observer-retained" ? "retained" : "settled",
          observation: {
            status: "OBSERVED",
            candidateSha: CANDIDATE,
            nonce: NONCE,
            domainSha256: HASH,
            policySha256: HASH,
            eventsSha256: HASH,
            readsSha256: HASH,
            settlementSha256: HASH,
            operationIds: plan.routes.map((route) => route.id),
          },
        };
      },
      async closeTransport() {
        events.push("transport-closed");
      },
      async retire() {
        events.push("transport-retired");
        return {
          ...binding,
          payloadsRetired: true,
          relayRetired: true,
          bridgeRetired: true,
        };
      },
      async verifySettlement() {
        return {
          ...binding,
          ownedChangesOnly: true,
          restored: true,
          reservation: "RETAINED",
          nativeSha256: HASH,
        };
      },
    };
    const owner = {
      assertTransport() {},
      async launch(selected, invocation, prepare, signal) {
        await prepare({ held: true });
        assert.deepEqual(events.slice(0, 2), [
          "transport-controls",
          "native-controls",
        ]);
        events.push("provider-released");
        return { record: { status: "ADMITTED" }, transport: server.transport };
      },
      async interrupt(mode) {
        assert.ok(events.includes("native-read"));
        events.push(mode);
        server.transport.output.write(
          JSON.stringify({
            type: "system",
            subtype: "task_notification",
            session_id: SESSION,
            task_id: "task-1",
            tool_use_id: "tool-0",
          }) + "\n",
        );
        server.transport.output.end();
        server.transport.errorOutput.end();
        return {
          independent: true,
          candidateSha: CANDIDATE,
          nonce: NONCE,
          mode,
          domainSha256: HASH,
          acknowledged: true,
          faultApplied: true,
          backgroundStarted: true,
          backgroundHeld: fault !== "already-retired",
          backgroundRetired: fault !== "fault",
          helpersSettled: true,
          nativeSha256: HASH,
          barrierSha256: HASH,
          taskIds: ["task-1"],
        };
      },
    };
    const result = await runClaudeMediationCase(
      spec,
      () => cases,
      id,
      policy,
      owner,
      effects,
      options,
    );
    assert.equal(
      result.status,
      fault ? "FAIL" : "CASE_MEDIATION_OBSERVED",
      JSON.stringify({ id, fault, events }),
    );
    assert.equal(
      result.phase,
      ["observer-retained", "observer-error", "observer-stall"].includes(fault)
        ? "retained"
        : "settled",
    );
    assert.ok(
      events.includes("transport-closed") &&
        events.includes("transport-retired"),
    );
    assert.doesNotMatch(
      JSON.stringify(persisted),
      /independent-inspection-nonce|fixture-command|fixture-complete/u,
    );
    if (!fault) assert.deepEqual(result.nativeObservation.operationIds, [id]);
  }
});
