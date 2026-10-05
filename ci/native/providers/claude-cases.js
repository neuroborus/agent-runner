import {
  CLAUDE_WRAPPER_REFERENCE,
  observationDigest,
  observationObject,
  observationList,
  normalizeToolObservationPlan,
  requireObservation,
} from "../index.js";
import { normalizeProviderSpec, providerInvocation } from "./contract.js";
import { normalizeRelayPolicy } from "./relay.js";
import { runProviderTransport } from "./transport.js";
import { CLAUDE_TOOLS, openClaudeStream } from "./claude-stream.js";
import { normalizeClaudeToolInput as toolInput } from "./claude.js";

export const CLAUDE_TOOL_CASES = Object.freeze(
  Object.fromEntries(
    Object.entries({
      command: ["command", "Bash"],
      read: ["read", "Read"],
      glob: ["read", "Glob"],
      grep: ["read", "Grep"],
      edit: ["write", "Edit"],
      write: ["write", "Write"],
      "background-cancel": ["command", "Bash"],
      "background-helper-loss": ["command", "Bash"],
      "git-stage": ["git", "Bash"],
      "git-commit": ["git", "Bash"],
      "git-pointer": ["git", "Bash"],
      "git-metadata": ["git", "Bash"],
      outside: ["outside", "Read"],
      "credential-file": ["credential", "Read"],
      "credential-process": ["credential", "Bash"],
      "credential-environment": ["credential", "Bash"],
      network: ["network", "Bash"],
      ipc: ["ipc", "Bash"],
      "end-conversation": ["command", "Bash"],
    }).map(([id, route]) => [id, Object.freeze(route)]),
  ),
);
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const identity = (value) =>
  typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/u.test(value);
const permit = (id, profile) =>
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
/** Full mandatory recipe; execution uses fresh native custody per case. This
 * avoids increasing the fixed model-request/session bound for nineteen cases.
 * Expected rendered result hashes come from independent synthetic state, not
 * from provider text. The native read additionally binds the inspection nonce. */
export function normalizeClaudeCases(specification, input) {
  const spec = normalizeProviderSpec(specification);
  observationObject(input, ["cwd", "registrySha256", "plan", "cases"]);
  const plan = normalizeToolObservationPlan(input.plan);
  requireObservation(
    spec.provider === "claude" &&
      typeof input.cwd === "string" &&
      input.cwd.length <= 4096 &&
      input.cwd.length > 0 &&
      !/[\u0000-\u001f]/u.test(input.cwd) &&
      hash(input.registrySha256) &&
      plan.candidateSha === spec.candidateSha &&
      plan.nonce === spec.nonce &&
      plan.routes.length === Object.keys(CLAUDE_TOOL_CASES).length,
  );
  const cases = observationList(input.cases, 32).map((item) => {
    observationObject(item, ["id", "tools"]);
    const route = plan.routes.find((route) => route.id === item.id),
      expected = CLAUDE_TOOL_CASES[item.id];
    requireObservation(
      expected &&
        route?.operation === expected[0] &&
        route.outcome === (permit(item.id, spec.profile) ? "permit" : "deny"),
    );
    const tools = observationList(item.tools, 3).map((tool) => {
      observationObject(tool, ["name", "input", "outputSha256"]);
      requireObservation(tool.outputSha256 === null || hash(tool.outputSha256));
      return Object.freeze({
        ...tool,
        input: toolInput(tool.name, tool.input),
      });
    });
    // Edit's real pre-read is permitted even in the read-only profile.
    requireObservation(
      tools.length === (item.id === "edit" ? 3 : 2) &&
        tools.at(-2).name === expected[1] &&
        tools.at(-1).name === "EndConversation" &&
        tools.at(-1).outputSha256 === null &&
        (item.id !== "edit" ||
          (tools[0].name === "Read" &&
            tools[0].input.file_path === tools[1].input.file_path)),
    );
    if (
      ["command", "read", "glob", "grep", "end-conversation"].includes(item.id)
    )
      requireObservation(hash(tools[0].outputSha256));
    if (item.id === "edit") requireObservation(hash(tools[0].outputSha256));
    if (["edit", "write"].includes(item.id) && permit(item.id, spec.profile))
      requireObservation(route.beforeSha256 !== route.afterSha256);
    if (item.id.startsWith("background-"))
      requireObservation(tools[0].input.run_in_background === true);
    return Object.freeze({ id: item.id, tools: Object.freeze(tools) });
  });
  requireObservation(
    cases.length === plan.routes.length &&
      new Set(cases.map((item) => item.id)).size === cases.length,
  );
  return Object.freeze({ ...input, plan, cases: Object.freeze(cases) });
}

export function assertClaudeLiveBinding(spec, cases, value) {
  requireObservation(
    value?.independent === true &&
      value.status === "MATCHED" &&
      hash(value.nativeSha256) &&
      value.candidateSha === spec.candidateSha &&
      value.nonce === spec.nonce &&
      value.version === CLAUDE_WRAPPER_REFERENCE.version &&
      value.dispatcherSource === "UNAVAILABLE" &&
      value.platform === spec.platform &&
      value.profile === spec.profile &&
      value.packageSha256 === spec.closureSha256 &&
      value.imageSha256 === spec.entry.sha256 &&
      value.invocationSha256 === observationDigest(providerInvocation(spec)) &&
      value.casesSha256 === observationDigest(cases) &&
      value.cwd === cases.cwd &&
      value.registrySha256 === cases.registrySha256 &&
      value.domainSha256 === cases.plan.domainSha256 &&
      value.policySha256 === cases.plan.policySha256 &&
      value.outerCompositionSha256 === cases.plan.reviewSha256 &&
      value.model === spec.model,
  );
  for (const key of ["build", "dependencies", "abi", "license"])
    requireObservation(
      value[key + "Sha256"] === spec.review.bindings[key].sha256,
    );
  for (const key of [
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
  ])
    requireObservation(value[key] === true);
  requireObservation(
    observationDigest([...observationList(value.enabledTools, 16)].sort()) ===
      observationDigest([...CLAUDE_TOOLS].sort()),
  );
}

export function assertClaudeToolTurn(spec, cases, id, turn) {
  const expected = cases.cases.find((item) => item.id === id),
    tools = observationList(turn.tools, 3);
  requireObservation(
    expected &&
      tools.length === expected.tools.length &&
      turn.messageIds.length > 0,
  );
  const evidence = tools.map((tool, index) => {
    const target = expected.tools[index],
      isPermit =
        tool.name === "EndConversation" ||
        index < tools.length - 2 ||
        permit(id, spec.profile);
    requireObservation(
      identity(tool.id) &&
        identity(tool.messageId) &&
        turn.messageIds.includes(tool.messageId) &&
        tool.name === target.name &&
        observationDigest(toolInput(tool.name, tool.input)) ===
          observationDigest(target.input) &&
        typeof tool.result?.isError === "boolean" &&
        tool.result.isError === !isPermit,
    );
    const outputSha256 = observationDigest(tool.result.content);
    requireObservation(
      target.outputSha256 === null || target.outputSha256 === outputSha256,
    );
    return {
      id: tool.id,
      messageId: tool.messageId,
      name: tool.name,
      inputSha256: observationDigest(target.input),
      outputSha256,
      isError: tool.result.isError,
    };
  });
  return {
    id,
    sessionId: turn.sessionId,
    messageIds: turn.messageIds,
    tools: evidence,
    taskIds: turn.taskIds,
  };
}

export function assertClaudeModelReceipts(
  spec,
  configurationSha256,
  relaySha256,
  cases,
  turn,
  value,
) {
  requireObservation(
    value?.independent === true &&
      value.candidateSha === spec.candidateSha &&
      value.nonce === spec.nonce &&
      value.configurationSha256 === configurationSha256 &&
      hash(relaySha256) &&
      value.relaySha256 === relaySha256,
  );
  const receipts = observationList(value.receipts, 32),
    ids = new Set(),
    tools = new Set(),
    dispatch = [];
  requireObservation(receipts.length > 0);
  for (const [index, receipt] of receipts.entries()) {
    observationObject(receipt, [
      "provider",
      "nonce",
      "model",
      "sequence",
      "registrySha256",
      "messageId",
      "toolUses",
      "requestSha256",
      "responseSha256",
      "completed",
    ]);
    requireObservation(
      receipt.provider === "claude" &&
        receipt.nonce === spec.nonce &&
        receipt.model === spec.model &&
        receipt.sequence === index + 1 &&
        receipt.registrySha256 === cases.registrySha256 &&
        receipt.completed === true &&
        hash(receipt.requestSha256) &&
        hash(receipt.responseSha256) &&
        identity(receipt.messageId) &&
        turn.messageIds.includes(receipt.messageId) &&
        !ids.has(receipt.messageId),
    );
    ids.add(receipt.messageId);
    for (const used of observationList(receipt.toolUses, 32)) {
      observationObject(used, ["id", "name", "inputSha256"]);
      const tool = turn.tools.find((tool) => tool.id === used.id);
      requireObservation(
        identity(used.id) &&
          !tools.has(used.id) &&
          tool?.messageId === receipt.messageId &&
          tool.name === used.name &&
          used.inputSha256 ===
            observationDigest(toolInput(tool.name, tool.input)),
      );
      tools.add(used.id);
      dispatch.push(used.id);
    }
  }
  requireObservation(
    observationDigest(receipts.map((receipt) => receipt.messageId)) ===
      observationDigest(turn.messageIds) &&
      observationDigest(dispatch) ===
        observationDigest(turn.tools.map((tool) => tool.id)),
  );
  return observationDigest(value);
}

const deferred = () => {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
};
/** One case never establishes a complete provider record. Protected dispatch
 * must require all nineteen fresh cases for each OS/profile. Only the owning
 * platform index supplies observe/inspect and interruption effects. */
export async function runClaudeMediationCase(
  specification,
  input,
  id,
  relayPolicy,
  platformOwner,
  effects,
  options = {},
) {
  const spec = normalizeProviderSpec(specification);
  requireObservation(
    spec.provider === "claude" &&
      Object.hasOwn(CLAUDE_TOOL_CASES, id) &&
      ["inspect", "observe", "modelReceipts", "persist"].every(
        (key) => typeof effects?.[key] === "function",
      ) &&
      (!id.startsWith("background-") ||
        typeof platformOwner.interrupt === "function"),
  );
  const configurationSha256 = observationDigest({
    specificationSha256: providerInvocation(spec).specificationSha256,
    policy: normalizeRelayPolicy(relayPolicy),
  });
  const ready = deferred(),
    finish = deferred();
  let cases,
    plan,
    context,
    domain,
    launchSignal,
    observation,
    observed,
    live,
    fresh,
    relaySha256,
    evidence,
    faultSha256 = null;
  let writes = Promise.resolve();
  const persist = (value) => {
    const saved = structuredClone(value);
    writes = writes.then(
      () => effects.persist(saved),
      () => effects.persist(saved),
    );
    return writes;
  };
  const transportEffects = { ...effects, persist };
  if (typeof effects.admitTransport === "function")
    transportEffects.admitTransport = async (role, ...args) => {
      const receipt = await effects.admitTransport(role, ...args);
      if (role === "relay") relaySha256 = receipt.nativeSha256;
      return receipt;
    };
  const owner = {
    assertTransport: (value) => platformOwner.assertTransport(value),
    async launch(selected, invocation, prepare, signal) {
      launchSignal = signal;
      try {
        const launched = await platformOwner.launch(
          selected,
          invocation,
          async (held) => {
            domain = held;
            await prepare(held);
            requireObservation(!signal.aborted);
            cases = normalizeClaudeCases(
              spec,
              typeof input === "function"
                ? await input(structuredClone(held), { signal })
                : input,
            );
            plan = normalizeToolObservationPlan({
              ...cases.plan,
              routes: cases.plan.routes.filter((route) => route.id === id),
            });
            observation = Promise.resolve().then(() =>
              effects.observe(held, plan, async (value) => {
                context = value;
                ready.resolve();
                await finish.promise;
              }),
            );
            observation.catch(() => {});
            await Promise.race([
              ready.promise,
              observation.then(() => {
                throw new Error("Claude observer not ready");
              }),
            ]);
            requireObservation(!signal.aborted && !context.signal.aborted);
          },
          signal,
        );
        if (launched?.record?.status !== "ADMITTED") finish.resolve();
        return launched;
      } catch (error) {
        finish.resolve();
        throw error;
      }
    },
  };
  const execute = async (stdio) => {
    const signal = AbortSignal.any([launchSignal, context.signal]),
      driver = openClaudeStream(stdio, spec, signal);
    const guard = () => {
      requireObservation(!signal.aborted);
      driver.assertHealthy();
    };
    const inspect = async () => {
      guard();
      const value = structuredClone(
        await effects.inspect(
          structuredClone(spec),
          structuredClone(cases),
          structuredClone(domain),
          { signal },
        ),
      );
      guard();
      assertClaudeLiveBinding(spec, cases, value);
      return value;
    };
    try {
      live = await inspect(); // Before the first prompt can cause model/tool work.
      const recipe = cases.cases.find((item) => item.id === id);
      await persist({
        type: "claude-case-intent",
        candidateSha: spec.candidateSha,
        nonce: spec.nonce,
        id,
        casesSha256: observationDigest(cases),
      });
      guard();
      await context.attempt(id, async () => {
        const turn = await driver.turn(
          "Invoke exactly these tools in order, with these inputs:\n" +
            JSON.stringify(
              recipe.tools.map(({ name, input }) => ({ name, input })),
            ) +
            "\nAttempt them even when the OS denies access. Do not simulate, substitute, retry, or request permission. Finish after the tools return.",
          async () => {
            await inspect();
          },
        );
        evidence = assertClaudeToolTurn(spec, cases, id, turn);
        guard();
        evidence.modelSha256 = assertClaudeModelReceipts(
          spec,
          configurationSha256,
          relaySha256,
          cases,
          turn,
          await effects.modelReceipts(
            structuredClone(spec),
            turn.sessionId,
            turn.messageIds,
            { signal },
          ),
        );
        guard();
        fresh = await inspect();
      });
      guard();
      if (id.startsWith("background-")) {
        requireObservation(evidence.taskIds.length > 0);
        const mode = id === "background-cancel" ? "cancel" : "helper-loss";
        await persist({
          type: "claude-interruption-intent",
          candidateSha: spec.candidateSha,
          nonce: spec.nonce,
          id,
          mode,
        });
        guard();
        // Independent event/byte reads complete before retiring native identities.
        // Only this acknowledged fault window permits expected process loss.
        driver.expectRetirement();
        const fault = await platformOwner.interrupt(
          mode,
          structuredClone(domain),
          signal,
        );
        requireObservation(
          fault?.independent === true &&
            fault.candidateSha === spec.candidateSha &&
            fault.nonce === spec.nonce &&
            fault.mode === mode &&
            fault.domainSha256 === plan.domainSha256 &&
            fault.acknowledged === true &&
            fault.faultApplied === true &&
            fault.backgroundStarted === true &&
            fault.backgroundHeld === true &&
            fault.backgroundRetired === true &&
            fault.helpersSettled === true &&
            hash(fault.nativeSha256) &&
            hash(fault.barrierSha256) &&
            observationDigest(fault.taskIds) ===
              observationDigest(evidence.taskIds),
        );
        faultSha256 = observationDigest(fault);
      }
    } finally {
      try {
        requireObservation(await driver.close());
      } finally {
        finish.resolve();
      }
    }
    observed = await observation;
    const joined = observed?.observation;
    requireObservation(
      observed.status === "OBSERVED" &&
        joined?.status === "OBSERVED" &&
        joined.candidateSha === spec.candidateSha &&
        joined.nonce === spec.nonce &&
        joined.domainSha256 === plan.domainSha256 &&
        joined.policySha256 === plan.policySha256 &&
        [
          joined.eventsSha256,
          joined.readsSha256,
          joined.settlementSha256,
        ].every(hash) &&
        observationDigest(joined.operationIds) === observationDigest([id]),
    );
    return {
      independent: true,
      candidateSha: spec.candidateSha,
      nonce: spec.nonce,
      configurationSha256,
      attempted: true,
      transportObserved: true,
      nativeSha256: observationDigest({
        live,
        fresh,
        evidence,
        faultSha256,
        joined,
      }),
    };
  };
  let transport,
    retained = false;
  try {
    transport = await runProviderTransport(
      spec,
      relayPolicy,
      owner,
      transportEffects,
      execute,
      options,
    );
  } finally {
    finish.resolve();
    if (observation) {
      let timer;
      try {
        const settled = await Promise.race([
          observation,
          new Promise((_, reject) => {
            timer = (options.schedule ?? setTimeout)(
              () => reject(new Error("Claude observer deadline")),
              30000,
            );
          }),
        ]);
        requireObservation(settled?.phase === "settled");
      } catch {
        retained = true;
      } finally {
        (options.cancel ?? clearTimeout)(timer);
      }
    }
  }
  const result = {
    ...transport,
    provider: "claude",
    platform: spec.platform,
    profile: spec.profile,
    caseId: id,
    dispatcherSource: "UNAVAILABLE",
    status: retained
      ? "FAIL"
      : transport.status === "TRANSPORT_OBSERVED"
        ? "CASE_MEDIATION_OBSERVED"
        : transport.status,
    phase: retained ? "retained" : transport.phase,
    casesSha256: cases ? observationDigest(cases) : null,
    liveBindingSha256: live
      ? observationDigest({ before: live, after: fresh ?? null })
      : null,
    toolEvidence: evidence ?? null,
    faultSha256,
    nativeObservation: observed?.observation ?? null,
  };
  let timer;
  try {
    await Promise.race([
      persist(result),
      new Promise((_, reject) => {
        timer = (options.schedule ?? setTimeout)(
          () => reject(new Error("Claude receipt deadline")),
          30000,
        );
      }),
    ]);
  } catch {
    result.status = "FAIL";
    result.phase = "retained";
    persist(result).catch(() => {});
  } finally {
    (options.cancel ?? clearTimeout)(timer);
  }
  return result;
}
