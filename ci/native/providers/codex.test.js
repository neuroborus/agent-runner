import assert from "node:assert/strict";
import test from "node:test";
import { Writable, PassThrough, Readable } from "node:stream";
import { EventEmitter } from "node:events";
import {
  CODEX_RELEASE_REFERENCE,
  nativePackageInput,
  observationDigest,
} from "../index.js";
import {
  CODEX_TOOL_CASES,
  codexBytesDigest,
  normalizeProviderSpec,
  providerInvocation,
  normalizeCodexCases,
  assertCodexLiveBinding,
  assertCodexToolTurn,
  assertCodexModelReceipts,
  openCodexAppServer,
  createProtectedRelay,
  runCodexMediation,
} from "./index.js";
import { windowsCommandLine } from "../win32/index.js";

const HASH = "a".repeat(64),
  CANDIDATE = "b".repeat(40),
  NONCE = "c".repeat(32);
function fixture(profile = "read-only", platform = "linux") {
  const publication = nativePackageInput("codex-" + platform),
    member = publication.entrypoint;
  const reference = {
    url: "https://example.org/review",
    revision: null,
    sha256: HASH,
  };
  const spec = normalizeProviderSpec({
    candidateSha: CANDIDATE,
    nonce: NONCE,
    provider: "codex",
    platform,
    profile,
    home: "/fixture/home",
    cache: "/fixture/cache",
    path: "/fixture/runtime",
    endpoint: "http://127.0.0.1:41001",
    model: "reviewed-model",
    review: {
      schemaVersion: 1,
      candidateSha: CANDIDATE,
      packageId: "codex-" + platform,
      archiveBytes: publication.bytes ?? 100,
      files: [{ path: member, bytes: 100, sha256: HASH, executable: true }],
      bindings: Object.fromEntries(
        [
          "publication",
          "source",
          "build",
          "dependencies",
          "license",
          "abi",
          "transport",
          "extraction",
        ].map((key) => [
          key,
          key === "source"
            ? {
                url: CODEX_RELEASE_REFERENCE.sourceUrl,
                revision: CODEX_RELEASE_REFERENCE.revision,
                sha256: HASH,
              }
            : reference,
        ]),
      ),
    },
  });
  const output = "fixture-nonce",
    outputSha256 = codexBytesDigest(output);
  const changes = [
    {
      path: "/fixture/work/value",
      kind: { type: "update", movePath: null },
      diff: "+fixture",
    },
  ];
  const display = (id) =>
    "/fixture/runtime/shell -c 'fixture-command " + id + "'";
  const input = normalizeCodexCases(spec, {
    cwd: "/fixture/work",
    registrySha256: HASH,
    plan: {
      schemaVersion: 1,
      candidateSha: CANDIDATE,
      nonce: NONCE,
      domainSha256: HASH,
      policySha256: HASH,
      reviewSha256: HASH,
      routes: Object.entries(CODEX_TOOL_CASES).map(([id, operation]) => ({
        id,
        operation,
        targetSha256: HASH,
        permitTargetSha256: "d".repeat(64),
        denyTargetSha256: "e".repeat(64),
        nonceSha256: outputSha256,
        beforeSha256: HASH,
        afterSha256:
          id === "edit" && profile !== "read-only" ? "f".repeat(64) : HASH,
        outcome:
          ["command", "read", "command-background"].includes(id) ||
          (id === "edit" && profile !== "read-only")
            ? "permit"
            : "deny",
      })),
    },
    cases: Object.keys(CODEX_TOOL_CASES).map((id) => ({
      id,
      command: id === "edit" ? null : "fixture-command " + id,
      commandSha256: id === "edit" ? null : codexBytesDigest(display(id)),
      patch:
        id === "edit"
          ? "*** Begin Patch\n*** Update File: value\n@@\n-before\n+fixture\n*** End Patch"
          : null,
      changesSha256: id === "edit" ? observationDigest(changes) : null,
      outputSha256: ["command", "read"].includes(id) ? outputSha256 : null,
    })),
  });
  const turn = (id) => {
    const item = input.cases.find((item) => item.id === id),
      permit =
        input.plan.routes.find((route) => route.id === id).outcome === "permit";
    return {
      threadId: "thread-1",
      turnId: "turn-1",
      items: [
        id === "edit"
          ? {
              id,
              type: "fileChange",
              status: permit ? "completed" : "failed",
              changes,
            }
          : {
              id,
              type: "commandExecution",
              status: permit ? "completed" : "failed",
              command: display(id),
              cwd: input.cwd,
              source: "unifiedExecStartup",
              processId: "123",
              aggregatedOutput: output,
              exitCode: permit ? 0 : 1,
            },
      ],
    };
  };
  const live = {
    independent: true,
    status: "MATCHED",
    nativeSha256: HASH,
    candidateSha: CANDIDATE,
    nonce: NONCE,
    sourceRevision: CODEX_RELEASE_REFERENCE.revision,
    packageSha256: spec.closureSha256,
    imageSha256: HASH,
    dependenciesSha256: HASH,
    abiSha256: HASH,
    buildSha256: HASH,
    sourceSha256: HASH,
    invocationSha256: observationDigest(providerInvocation(spec)),
    casesSha256: observationDigest(input),
    cwd: input.cwd,
    domainSha256: HASH,
    policySha256: HASH,
    reviewSha256: HASH,
    registrySha256: HASH,
    toolMode: "direct",
    model: spec.model,
    profile,
    enabledTools: ["exec_command", "write_stdin", "apply_patch", "update_plan"],
  };
  for (const key of [
    "heldImages",
    "loaderClosure",
    "effectivePolicy",
    "privateHomeCache",
    "noAmbientAuth",
    "noHooks",
    "noPlugins",
    "noMcp",
    "noDynamicTools",
    "noCodeMode",
    "noHostControl",
    "commandRuntimesBound",
    "fileHandlersBound",
    "executionServersBound",
    "workersBound",
    "backgroundChildrenBound",
    "internalEscalationBound",
    "relayReceiptPipePrivate",
  ])
    live[key] = true;
  return { spec, input, turn, live, output };
}

test("every native platform/profile retains actual command/file routes and live release closure", () => {
  for (const platform of ["linux", "darwin", "win32"])
    for (const profile of ["read-only", "workspace-write", "trusted-command"]) {
      const { spec, input, turn, live } = fixture(profile, platform);
      assertCodexLiveBinding(spec, input, live);
      for (const id of Object.keys(CODEX_TOOL_CASES))
        assertCodexToolTurn(spec, input, id, turn(id));
      const args = providerInvocation(spec).arguments;
      // Preserve existing literal argument bounds rather than enlarging launch authority.
      assert.ok(args.length <= 64);
      assert.ok(
        windowsCommandLine("C:\\Fixture\\codex.exe", args).length < 32767,
      );
      assert.throws(() =>
        assertCodexLiveBinding(spec, input, {
          ...live,
          enabledTools: [...live.enabledTools, "mcp__fixture"],
        }),
      );
      assert.throws(() =>
        assertCodexLiveBinding(spec, input, { ...live, workersBound: false }),
      );
      assert.throws(() =>
        assertCodexLiveBinding(spec, input, {
          ...live,
          sourceRevision: "d".repeat(40),
        }),
      );
    }
});

test("refusals, controller operations, wrong nonces and incomplete cases cannot prove mediation", () => {
  const { spec, input, turn } = fixture();
  for (const change of [
    { status: "declined" },
    { source: "userShell" },
    { command: "controller-exec" },
    { command: input.cases.find((item) => item.id === "read").command },
    { aggregatedOutput: "invented-nonce" },
    { exitCode: null },
  ]) {
    const changed = turn("read");
    Object.assign(changed.items[0], change);
    assert.throws(() => assertCodexToolTurn(spec, input, "read", changed));
  }
  assert.throws(() =>
    normalizeCodexCases(spec, { ...input, cases: input.cases.slice(1) }),
  );
  assert.throws(() =>
    normalizeCodexCases(spec, {
      ...input,
      cases: input.cases.map((item) =>
        item.id === "read" ? { ...item, outputSha256: HASH } : item,
      ),
    }),
  );
  const denied = turn("git-stage");
  denied.items[0].aggregatedOutput = null;
  assertCodexToolTurn(spec, input, "git-stage", denied);
});

function appServer(turn, mode = "normal", launchArguments = []) {
  const output = new PassThrough(),
    errorOutput = new PassThrough(),
    calls = [];
  const emit = (value) => output.write(JSON.stringify(value) + "\n");
  const input = new Writable({
    write(chunk, encoding, done) {
      const value = JSON.parse(chunk.toString());
      calls.push(value);
      if (value.method === "initialize")
        emit({ id: value.id, result: { codexHome: "/fixture/home" } });
      if (value.method === "thread/start") {
        emit({
          id: value.id,
          result: {
            model: "reviewed-model",
            modelProvider: "native_poc",
            approvalPolicy: "never",
            cwd: "/fixture/work",
            thread: { id: "thread-1" },
          },
        });
        // The pinned session emits this advisory for the required under-development
        // host-skill control unless the source-supported suppression is selected.
        if (
          mode === "warning" ||
          !launchArguments.includes("suppress_unstable_features_warning=true")
        )
          emit({
            method: "warning",
            params: {
              threadId: "thread-1",
              message:
                "Under-development features enabled: skip_host_skill_discovery",
            },
          });
      }
      if (value.method === "turn/start") {
        if (mode === "stall") {
          done();
          return;
        }
        if (mode === "overflow") {
          output.write(Buffer.alloc(1048577, 120));
          done();
          return;
        }
        if (mode === "input-error") {
          done(new Error("Fixture pipe closed"));
          return;
        }
        const current =
          typeof turn === "function" ? turn(value.params.input[0].text) : turn;
        if (mode === "approval")
          emit({
            id: "server-request",
            method: "item/commandExecution/requestApproval",
            params: {},
          });
        else {
          const threadId =
            mode === "foreign" ? "thread-other" : current.threadId;
          // The released server reports the persistent policy change before the
          // first turn starts. A managed policy override must still fail proof.
          emit({
            method: "thread/settings/updated",
            params: {
              threadId,
              threadSettings: {
                cwd: value.params.cwd,
                model: value.params.model,
                modelProvider: "native_poc",
                approvalPolicy:
                  mode === "settings"
                    ? "on-request"
                    : value.params.approvalPolicy,
                sandboxPolicy: value.params.sandboxPolicy,
              },
            },
          });
          emit({
            method: "turn/started",
            params: {
              threadId,
              turn: { id: current.turnId, status: "inProgress" },
            },
          });
          if (mode !== "refusal")
            for (const item of current.items) {
              emit({
                method: "item/started",
                params: {
                  threadId,
                  turnId: current.turnId,
                  item: { ...item, status: "inProgress" },
                },
              });
              emit({
                method: "item/completed",
                params: { threadId, turnId: current.turnId, item },
              });
            }
          emit({
            method: "turn/completed",
            params: {
              threadId,
              turn: { id: current.turnId, status: "completed" },
            },
          });
          // Notification completion may precede the RPC response on actual stdio.
          emit({
            id: value.id,
            result: { turn: { id: current.turnId, status: "inProgress" } },
          });
        }
      }
      done();
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

test("App Server startup and turns reject unexpected warnings, approvals, foreign lifecycles and broken stdin", async () => {
  const { spec, input, turn } = fixture();
  for (const mode of [
    "normal",
    "warning",
    "approval",
    "refusal",
    "foreign",
    "settings",
    "input-error",
    "overflow",
    "stall",
  ]) {
    const server = appServer(
        turn("read"),
        mode,
        providerInvocation(spec).arguments,
      ),
      controller = new AbortController();
    const driver = openCodexAppServer(server.transport, controller.signal);
    try {
      if (mode === "warning") {
        await assert.rejects(async () => {
          const thread = await driver.initialize(spec, input.cwd);
          await driver.turn(spec, input.cwd, thread, "Inspect the fixture");
        });
        continue;
      }
      const thread = await driver.initialize(spec, input.cwd);
      if (mode === "normal") {
        const result = await driver.turn(
          spec,
          input.cwd,
          thread,
          "Inspect the fixture",
        );
        assertCodexToolTurn(spec, input, "read", result);
        const request = server.calls.find(
          (call) => call.method === "turn/start",
        );
        assert.deepEqual(request.params.sandboxPolicy, {
          type: "externalSandbox",
          networkAccess: "enabled",
        });
        assert.equal(request.params.approvalPolicy, "never");
        assert.equal(Object.hasOwn(request.params, "environments"), false);
      } else {
        const work = driver.turn(
          spec,
          input.cwd,
          thread,
          "Inspect the fixture",
        );
        if (mode === "stall") controller.abort();
        await assert.rejects(work);
      }
      assert.ok(
        server.calls.every((call) =>
          ["initialize", "initialized", "thread/start", "turn/start"].includes(
            call.method,
          ),
        ),
      );
    } finally {
      await driver.close();
    }
  }
});

test("protected model receipts bind actual thread/turn requests and cannot be replayed or substituted", () => {
  const { spec, turn } = fixture(),
    value = {
      independent: true,
      candidateSha: CANDIDATE,
      nonce: NONCE,
      configurationSha256: HASH,
      relaySha256: HASH,
      receipts: [
        {
          provider: "codex",
          nonce: NONCE,
          model: spec.model,
          sequence: 1,
          registrySha256: HASH,
          threadId: "thread-1",
          turnId: "turn-1",
          requestSha256: HASH,
          responseSha256: HASH,
          completed: true,
        },
      ],
    };
  const used = new Set();
  assertCodexModelReceipts(spec, HASH, HASH, HASH, turn("read"), value, used);
  assert.throws(() =>
    assertCodexModelReceipts(spec, HASH, HASH, HASH, turn("read"), value, used),
  );
  assert.throws(() =>
    assertCodexModelReceipts(
      spec,
      HASH,
      "d".repeat(64),
      HASH,
      turn("read"),
      value,
      new Set(),
    ),
  );
  for (const change of [
    { turnId: "turn-other" },
    { completed: false },
    { sequence: 2 },
    { registrySha256: "d".repeat(64) },
  ]) {
    assert.throws(() =>
      assertCodexModelReceipts(
        spec,
        HASH,
        HASH,
        HASH,
        turn("read"),
        { ...value, receipts: [{ ...value.receipts[0], ...change }] },
        new Set(),
      ),
    );
  }
});

test("native controls precede model release and missing native/model proof still retires every owner", async () => {
  for (const fault of [
    null,
    "observer-drop",
    "observer-unsettled",
    "observer-error",
    "observer-stall",
    "model-incomplete",
    "observer-admission",
    "case-receipt",
  ]) {
    const { spec, input, turn, live } = fixture(),
      events = [],
      persisted = [];
    let sequence = 0,
      transportDeadline,
      settlementExpired = false;
    const options = {
      schedule(callback, duration) {
        if (duration === 120000) transportDeadline = callback;
        if (
          fault === "observer-stall" &&
          events.includes("transport-retired") &&
          duration === 30000 &&
          !settlementExpired
        ) {
          settlementExpired = true;
          queueMicrotask(callback);
        }
        return 1;
      },
      cancel() {},
    };
    const server = appServer(
      (prompt) => {
        const item = input.cases.find((item) =>
          item.command === null
            ? prompt.startsWith("Use apply_patch")
            : prompt.split("\n")[1] === item.command,
        );
        return { ...turn(item.id), turnId: "turn-" + ++sequence };
      },
      "normal",
      providerInvocation(spec).arguments,
    );
    const policy = {
      provider: "codex",
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
    };
    const verified = {
      ...binding,
      nativeSha256: HASH,
      packageSha256: spec.closureSha256,
      profile: spec.profile,
      endpoint: spec.endpoint,
    };
    for (const key of [
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
    ])
      verified[key] = true;
    const effects = {
      async persist(value) {
        persisted.push(structuredClone(value));
        if (fault === "case-receipt" && value.type === "codex-case-observed")
          throw new Error("Fixture receipt unavailable");
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
            ].map((id) => [
              id,
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
        assert.ok(
          server.calls.some((value) => value.method === "thread/start"),
        );
        return {
          ...structuredClone(live),
          nativeSha256: sequence === 0 ? HASH : "d".repeat(64),
        };
      },
      async observe(domain, plan, execute) {
        assert.equal(server.calls.length, 0);
        if (fault === "observer-admission")
          return { status: "BLOCKED", phase: "review" };
        events.push("native-controls");
        try {
          await execute({
            signal: new AbortController().signal,
            async attempt(id, action) {
              events.push("armed:" + id);
              await action();
              events.push("native-read:" + id);
            },
          });
        } finally {
          events.push("observer-retired");
        }
        if (fault === "observer-error")
          throw new Error("Fixture observer receipt unavailable");
        if (fault === "observer-stall") {
          transportDeadline();
          return new Promise(() => {});
        }
        return {
          status: ["observer-drop", "observer-unsettled"].includes(fault)
            ? "FAIL"
            : "OBSERVED",
          phase: fault === "observer-unsettled" ? "retained" : "settled",
          observation: {
            schemaVersion: 1,
            candidateSha: CANDIDATE,
            nonce: NONCE,
            domainSha256: HASH,
            policySha256: HASH,
            status: "OBSERVED",
            eventsSha256: HASH,
            readsSha256: HASH,
            settlementSha256: HASH,
            operationIds: plan.routes.map((route) => route.id),
          },
        };
      },
      async modelReceipts(selected, threadId, turnId) {
        return {
          ...binding,
          relaySha256: HASH,
          receipts: [
            {
              provider: "codex",
              nonce: NONCE,
              model: spec.model,
              sequence,
              registrySha256: HASH,
              threadId,
              turnId,
              requestSha256: HASH,
              responseSha256: HASH,
              completed: fault !== "model-incomplete",
            },
          ],
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
      async launch(selected, invocation, prepare) {
        await prepare({ held: true });
        assert.deepEqual(events.slice(0, 2), [
          "transport-controls",
          "native-controls",
        ]);
        events.push("provider-released");
        return { record: { status: "ADMITTED" }, transport: server.transport };
      },
    };
    const result = await runCodexMediation(
      spec,
      () => input,
      policy,
      owner,
      effects,
      options,
    );
    assert.equal(
      result.status,
      fault === null ? "MEDIATION_OBSERVED" : "FAIL",
      JSON.stringify({ fault, events }),
    );
    assert.equal(
      result.phase,
      [
        "observer-unsettled",
        "observer-error",
        "observer-stall",
        "observer-admission",
      ].includes(fault)
        ? "retained"
        : "settled",
    );
    assert.equal(result.reservation, "RETAINED");
    assert.ok(
      events.includes("transport-closed") &&
        events.includes("transport-retired"),
    );
    if (fault !== "observer-admission")
      assert.ok(
        events.indexOf("observer-retired") <
          events.indexOf("transport-retired"),
      );
    assert.equal(
      sequence,
      fault === "observer-admission"
        ? 0
        : ["model-incomplete", "case-receipt"].includes(fault)
          ? 1
          : input.cases.length,
    );
    if (fault === null) {
      assert.equal(result.toolEvidence.length, input.cases.length);
      assert.equal(
        result.nativeObservation.operationIds.length,
        input.cases.length,
      );
      assert.doesNotMatch(
        JSON.stringify(persisted),
        /fixture-nonce|fixture-command|Begin Patch/u,
      );
      for (const item of input.cases)
        assert.ok(
          events.indexOf("armed:" + item.id) <
            events.indexOf("native-read:" + item.id),
        );
    }
  }
});

test("relay receipts contain hashes and bound identities without upstream text or credentials", async () => {
  const receipts = [],
    policy = {
      provider: "codex",
      nonce: NONCE,
      model: "reviewed-model",
      requests: 32,
      outputTokens: 10,
      budgetMicros: 100000,
      inputMicros: 1,
      outputMicros: 1,
      beta: [],
    };
  const relay = createProtectedRelay(policy, "synthetic-secret", {
    onReceipt: async (value) => receipts.push(value),
    request(url, options, receive) {
      assert.equal(url.origin, "https://api.openai.com");
      const request = new EventEmitter();
      request.destroy = () => {};
      request.end = () => {
        const response = Readable.from([
          Buffer.from(
            JSON.stringify({
              object: "response",
              status: "completed",
              output: "private-model-text",
            }),
          ),
        ]);
        Object.assign(response, {
          statusCode: 200,
          headers: { "content-type": "application/json" },
          complete: true,
        });
        receive(response);
      };
      return request;
    },
  });
  try {
    await relay.forward(
      {
        method: "POST",
        path: "/v1/responses",
        headers: { authorization: "Bearer native-poc-" + NONCE },
        body: Buffer.from(
          JSON.stringify({
            model: policy.model,
            input: "fixture",
            client_metadata: { thread_id: "thread-1", turn_id: "turn-1" },
          }),
        ),
      },
      async () => {},
    );
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].completed, true);
    assert.equal(receipts[0].threadId, "thread-1");
    assert.equal(receipts[0].turnId, "turn-1");
    assert.equal(receipts[0].registrySha256, observationDigest([]));
    assert.match(receipts[0].responseSha256, /^[a-f0-9]{64}$/u);
    assert.doesNotMatch(
      JSON.stringify(receipts),
      /private-model-text|synthetic-secret|authorization/u,
    );
  } finally {
    relay.close();
  }
});
