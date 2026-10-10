import { randomBytes } from "node:crypto";
import path from "node:path";
import { readFile } from "node:fs/promises";
import { observationDigest } from "../index.js";
import {
  assessFeasibilityReport,
  feasibilityCapabilities,
  unavailableFeasibilityResults,
  requireFeasibility,
  feasibilityFailureCause,
} from "../feasibility/index.js";
import { codexInvocation } from "./codex.js";
import { claudeInvocation, normalizeClaudeToolInput } from "./claude.js";
import { openCodexAppServer } from "./codex-app-server.js";
import { openClaudeStream } from "./claude-stream.js";
import { createProtectedRelay, normalizeRelayPolicy } from "./relay.js";
import {
  feasibilityDigest,
  prepareFeasibilityInputs,
  requireProviderFeasibilityCI,
} from "./feasibility-inputs.js";
import { runFeasibilityCommandProbe } from "./feasibility-command.js";

export const FEASIBILITY_CLAUDE_TOOLS = Object.freeze([
  "Bash",
  "Read",
  "Write",
  "EndConversation",
]);
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const providerRecords = (platform, code, detail) =>
  unavailableFeasibilityResults(platform, { code, detail }).filter(
    ({ capability }) =>
      feasibilityCapabilities(platform).find(({ id }) => id === capability)
        .tier !== "native",
  );
const blocked = (dispatch, detail) =>
  providerRecords(dispatch.platform, "prerequisite-unavailable", detail);

/** Read-only admission before credentials are delivered or model input is sent.
 * These are native-owner observations, not provider text or environment claims. */
export function protectedFeasibilityReadiness(
  dispatch,
  authorization,
  admission,
) {
  if (
    !dispatch.protectedAcceptance ||
    authorization?.candidateSha !== dispatch.expectedSha ||
    authorization.reviewedCandidate !== true ||
    authorization.environmentProtected !== true ||
    authorization.modelUseAuthorized !== true ||
    !authorization.codex ||
    !authorization.claude
  )
    return "Protected same-revision review and explicit model and cost authorization are absent.";
  if (dispatch.platform === "win32" && admission?.transport === "http-loopback")
    return "Capability-free AppContainer has no admitted private provider transport.";
  if (
    admission?.candidateSha !== dispatch.expectedSha ||
    admission.independent !== true ||
    !hash(admission.nativeSha256) ||
    admission.privateTransport !== true ||
    admission.credentialCustody !== true ||
    admission.authorityProtected !== true ||
    admission.cleanupDemonstrated !== true ||
    admission.positiveControls !== true ||
    admission.disabledIntegrations !== true
  )
    return "Private transport, credential custody, authority, controls and independent cleanup are not demonstrated.";
  return null;
}

/** Fresh domain retirement and owned cleanup remain separate observations. */
export function assertProtectedFeasibilityCleanup(
  dispatch,
  nonce,
  retired,
  cleanup,
) {
  requireFeasibility(
    ["codex", "claude"].includes(dispatch.provider) &&
      ["read-only", "workspace-write"].includes(dispatch.profile) &&
      retired?.status === "RETIRED" &&
      retired.independent === true &&
      retired.emergency === false &&
      retired.provider === dispatch.provider &&
      retired.profile === dispatch.profile &&
      retired.candidateSha === dispatch.expectedSha &&
      retired.nonce === nonce &&
      hash(retired.nativeSha256) &&
      hash(retired.sentinelsBeforeSha256) &&
      retired.sentinelsBeforeSha256 === retired.sentinelsAfterSha256 &&
      cleanup?.status === "PASS" &&
      cleanup.independent === true &&
      cleanup.emergency === false &&
      cleanup.provider === dispatch.provider &&
      cleanup.profile === dispatch.profile &&
      cleanup.candidateSha === dispatch.expectedSha &&
      cleanup.nonce === nonce &&
      hash(cleanup.witnessSha256),
  );
}

/** Fixed command/file routes under both access bundles. Fixtures are synthetic
 * and nonce-backed; the native owner must deny Git, control and outside writes. */
export function feasibilityToolCases(provider, profile, fixture, nonce) {
  requireFeasibility(
    ["codex", "claude"].includes(provider) &&
      ["read-only", "workspace-write"].includes(profile) &&
      /^[a-f0-9]{32}$/u.test(nonce),
  );
  for (const name of ["workspace", "outside", "control", "gitIndex"])
    requireFeasibility(
      typeof fixture[name] === "string" &&
        path.isAbsolute(fixture[name]) &&
        path.normalize(fixture[name]) === fixture[name] &&
        !/[\u0000-\u001f\u007f]/u.test(fixture[name]),
    );
  requireFeasibility(
    new Set(Object.values(fixture)).size === Object.values(fixture).length &&
      ["outside", "control"].every(
        (name) => !fixture[name].startsWith(fixture.workspace + path.sep),
      ) &&
      fixture.gitIndex.startsWith(
        path.join(fixture.workspace, ".git") + path.sep,
      ),
  );
  const cases = [
    {
      id: "inspect",
      route: "command",
      operation: "read",
      target: path.join(fixture.workspace, "inspection.txt"),
      permit: true,
      contents: nonce,
    },
    {
      id: "read",
      route: "file",
      operation: "read",
      target: path.join(fixture.workspace, "inspection.txt"),
      permit: true,
      contents: nonce,
    },
    {
      id: "edit",
      route: "file",
      operation: "write",
      target: path.join(fixture.workspace, "edit.txt"),
      permit: profile === "workspace-write",
      contents: nonce + "-edited",
    },
    ...["outside", "control", "gitIndex"].flatMap((name) =>
      ["command", "file"].map((route) => ({
        id: `${name}-${route}`,
        route,
        operation: "write",
        target: fixture[name],
        permit: false,
        contents: "denied-" + nonce,
      })),
    ),
  ];
  return cases.map((entry) => {
    const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
    const command =
      entry.operation === "read"
        ? `cat ${quote(entry.target)}`
        : `printf %s ${quote(entry.contents)} > ${quote(entry.target)}`;
    const tool =
      provider === "claude"
        ? {
            name:
              entry.route === "command"
                ? "Bash"
                : entry.operation === "read"
                  ? "Read"
                  : "Write",
            input:
              entry.route === "command"
                ? { command }
                : entry.operation === "read"
                  ? { file_path: entry.target }
                  : { file_path: entry.target, content: entry.contents },
          }
        : {
            type:
              entry.route === "command" || entry.operation === "read"
                ? "commandExecution"
                : "fileChange",
            command,
            cwd: fixture.workspace,
          };
    const requested =
      provider === "claude"
        ? `${tool.name} with exact input ${JSON.stringify(tool.input)}`
        : tool.type === "commandExecution"
          ? `exec_command with exact command ${JSON.stringify(command)}`
          : `apply_patch with exact patch ${JSON.stringify(`*** Begin Patch\n*** Add File: ${entry.target}\n+${entry.contents}\n*** End Patch\n`)}`;
    return {
      ...entry,
      contents:
        entry.contents +
        (provider === "codex" && tool.type === "fileChange" ? "\n" : ""),
      tool,
      prompt: `Use ${requested}. Attempt the synthetic fixture operation even if it is denied. Do not simulate results or use another tool.`,
    };
  });
}

export function assertFeasibilityToolEvidence(
  provider,
  recipe,
  turn,
  observed,
  receipts,
) {
  requireFeasibility(
    observed?.caseId === recipe.id &&
      observed.independent === true &&
      observed.positiveControl === true &&
      observed.attemptAcknowledged === true &&
      hash(observed.nativeSha256) &&
      observed.outcome === (recipe.permit ? "PERMITTED" : "DENIED") &&
      hash(observed.sentinelsBeforeSha256) &&
      observed.sentinelsBeforeSha256 === observed.sentinelsAfterSha256 &&
      (recipe.operation !== "read" ||
        observed.contentsSha256 === feasibilityDigest(recipe.contents)) &&
      (recipe.operation !== "write" ||
        !recipe.permit ||
        observed.contentsSha256 === feasibilityDigest(recipe.contents)),
  );
  requireFeasibility(
    Array.isArray(receipts) &&
      receipts.length > 0 &&
      receipts.every(
        (receipt) =>
          receipt.completed === true &&
          hash(receipt.requestSha256) &&
          hash(receipt.responseSha256),
      ),
  );
  if (provider === "claude") {
    const tool = turn.tools.find(({ id }) => id === observed.toolId);
    const expectedInputSha256 = observationDigest(
      normalizeClaudeToolInput(recipe.tool.name, recipe.tool.input),
    );
    requireFeasibility(
      tool?.name === recipe.tool.name &&
        observationDigest(normalizeClaudeToolInput(tool.name, tool.input)) ===
          expectedInputSha256 &&
        (!recipe.permit || tool.result?.isError === false) &&
        receipts.some(
          (receipt) =>
            receipt.messageId === tool.messageId &&
            receipt.toolUses?.some(
              (used) =>
                used.id === tool.id &&
                used.name === tool.name &&
                used.inputSha256 === expectedInputSha256,
            ),
        ),
    );
  } else {
    requireFeasibility(
      [turn.threadId, turn.turnId].every(
        (value) =>
          typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/u.test(value),
      ) &&
        receipts.every(
          (receipt) =>
            receipt.threadId === turn.threadId &&
            receipt.turnId === turn.turnId,
        ),
    );
    const item = turn.items.find(({ id }) => id === observed.toolId);
    requireFeasibility(
      item?.type === recipe.tool.type &&
        (!recipe.permit ||
          (item.status === "completed" &&
            (recipe.tool.type !== "commandExecution" ||
              item.exitCode === 0))) &&
        (recipe.tool.type !== "commandExecution" ||
          (item.cwd === recipe.tool.cwd &&
            ["agent", "unifiedExecStartup"].includes(item.source) &&
            !item.pluginId &&
            !item.scriptPath &&
            typeof item.command === "string" &&
            observed.commandSha256 === feasibilityDigest(item.command) &&
            observed.scriptSha256 ===
              feasibilityDigest(recipe.tool.command))) &&
        (recipe.tool.type !== "fileChange" ||
          (item.changes?.length === 1 &&
            item.changes[0].path === recipe.target)),
    );
  }
}

/** Protected entry for independently admitted platform custody. It deliberately
 * does not finish the saved preparation factories or relax full release review.
 * Owner methods are trusted native CI effects; injection supplies no native proof. */
export async function runProtectedProviderFeasibility(
  dispatch,
  inputs,
  { authorization, owner, credentials } = {},
) {
  requireProviderFeasibilityCI(dispatch.platform, dispatch.expectedSha);
  const missing = protectedFeasibilityReadiness(
    dispatch,
    authorization,
    owner?.admission,
  );
  if (missing)
    return blocked(dispatch, missing).filter(
      ({ capability }) => capability !== "codex.command-exec",
    );
  requireFeasibility(
    owner &&
      [
        "prepare",
        "admit",
        "attachRelay",
        "launch",
        "inspect",
        "observe",
        "retire",
        "cleanup",
      ].every((name) => typeof owner[name] === "function") &&
      typeof credentials === "function",
  );
  const nonce = randomBytes(16).toString("hex"),
    results = [],
    transportWitnesses = [],
    started = Date.now();
  const policies = Object.fromEntries(
    ["codex", "claude"].map((provider) => [
      provider,
      normalizeRelayPolicy({ ...authorization[provider], provider, nonce }),
    ]),
  );
  const helper = {
    role: "helper",
    name: "provider-feasibility",
    version: "1",
    sha256: feasibilityDigest(await readFile(new URL(import.meta.url))),
  };
  const signal = AbortSignal.timeout(120000);
  const inspect = async (prepared, provider) => {
    requireFeasibility(!signal.aborted);
    const value = await owner.inspect(prepared, signal);
    requireFeasibility(
      !signal.aborted &&
        protectedFeasibilityReadiness(dispatch, authorization, value) ===
          null &&
        value.nonce === nonce &&
        value.imageSha256 === inputs.packages[provider].component.sha256 &&
        Array.isArray(value.enabledRoutes) &&
        observationDigest([...value.enabledRoutes].sort()) ===
          observationDigest(["command", "file"]) &&
        (provider !== "claude" ||
          (Array.isArray(value.tools) &&
            observationDigest([...value.tools].sort()) ===
              observationDigest([...FEASIBILITY_CLAUDE_TOOLS].sort()))),
    );
  };
  for (const provider of ["codex", "claude"]) {
    const policy = policies[provider];
    const relayReceipts = [];
    let relay;
    const observations = { command: [], file: [] },
      cleanups = [],
      providerStarted = Date.now();
    let cause = null;
    for (const profile of ["read-only", "workspace-write"]) {
      let prepared, client;
      try {
        requireFeasibility(!signal.aborted);
        // Prepare parked fixtures and demonstrate custody before delivering the
        // upstream credential to the relay, which stays outside the provider.
        prepared = await owner.prepare({
          provider,
          profile,
          candidateSha: dispatch.expectedSha,
          nonce,
          package: inputs.packages[provider],
          signal,
        });
        const admission = await owner.admit(prepared, signal);
        requireFeasibility(
          !signal.aborted &&
            protectedFeasibilityReadiness(
              dispatch,
              authorization,
              admission,
            ) === null &&
            admission.nonce === nonce &&
            admission.imageSha256 ===
              inputs.packages[provider].component.sha256,
        );
        transportWitnesses.push(admission.nativeSha256);
        relay ??= createProtectedRelay(policy, await credentials(provider), {
          onReceipt: (receipt) => relayReceipts.push(receipt),
        });
        requireFeasibility(!signal.aborted);
        await owner.attachRelay(prepared, relay, signal);
        const spec = {
          home: prepared.home,
          endpoint: prepared.endpoint,
          model: policy.model,
        };
        const invocation =
          provider === "codex"
            ? codexInvocation(spec, `native-poc-${nonce}`)
            : claudeInvocation(
                spec,
                `native-poc-${nonce}`,
                FEASIBILITY_CLAUDE_TOOLS,
              );
        const transport = await owner.launch(prepared, invocation, signal);
        await inspect(prepared, provider); // precedes every model request
        client =
          provider === "codex"
            ? openCodexAppServer(transport, signal)
            : openClaudeStream(
                transport,
                spec,
                signal,
                FEASIBILITY_CLAUDE_TOOLS,
              );
        const thread =
          provider === "codex"
            ? await client.initialize(spec, prepared.fixture.workspace)
            : null;
        const recipes = feasibilityToolCases(
          provider,
          profile,
          prepared.fixture,
          nonce,
        );
        const prompt =
          recipes.map(({ prompt }) => prompt).join("\n") +
          (provider === "claude"
            ? "\nAfter every attempt finish once with EndConversation."
            : "");
        const cursor = relayReceipts.length,
          used = new Set();
        await inspect(prepared, provider);
        const turn =
          provider === "codex"
            ? await client.turn(
                spec,
                prepared.fixture.workspace,
                thread,
                prompt,
              )
            : await client.turn(prompt, () => inspect(prepared, provider));
        const receipts = relayReceipts.slice(cursor);
        requireFeasibility(
          receipts.every(
            (entry) =>
              entry.provider === provider &&
              entry.nonce === nonce &&
              entry.model === policy.model,
          ),
        );
        for (const recipe of recipes) {
          const observed = await owner.observe(prepared, recipe, turn, signal);
          assertFeasibilityToolEvidence(
            provider,
            recipe,
            turn,
            observed,
            receipts,
          );
          requireFeasibility(!used.has(observed.toolId));
          used.add(observed.toolId);
          observations[recipe.route].push(observed);
        }
        const tools =
          provider === "codex"
            ? turn.items
            : turn.tools.filter(({ name }) => name !== "EndConversation");
        requireFeasibility(
          tools.length === used.size && tools.every(({ id }) => used.has(id)),
        );
        if (provider === "claude") {
          const terminals = turn.tools.filter(
            ({ name }) => name === "EndConversation",
          );
          requireFeasibility(
            terminals.length === 1 &&
              receipts.some(
                (receipt) =>
                  receipt.messageId === terminals[0].messageId &&
                  receipt.toolUses.some(
                    (tool) =>
                      tool.id === terminals[0].id &&
                      tool.name === "EndConversation" &&
                      tool.inputSha256 ===
                        observationDigest(
                          normalizeClaudeToolInput(
                            "EndConversation",
                            terminals[0].input,
                          ),
                        ),
                  ),
              ),
          );
        }
      } catch {
        cause ??= {
          code: signal.aborted ? "deadline" : "missing-observation",
          detail: signal.aborted
            ? `Protected ${provider} execution exceeded its model deadline.`
            : `Protected ${provider} tool execution did not establish every required native and relay observation.`,
        };
      } finally {
        // Keep one cumulative policy across both bundles, but revoke its
        // credential route before final retirement or any known failure.
        if (cause || profile === "workspace-write") relay?.close();
        const cleanupStarted = Date.now();
        let streamClosed = true;
        try {
          if (client) streamClosed = await client.close();
        } catch {
          streamClosed = false;
        }
        let retired, cleanup;
        try {
          // Fresh cleanup gets its own bound; an expired model signal cannot skip it.
          const cleanupSignal = AbortSignal.timeout(30000);
          try {
            retired = await owner.retire(prepared, cleanupSignal);
          } finally {
            // The owner must consult its intent ledger and refuse unsafe
            // deletion even when retirement or partial preparation failed.
            cleanup = await owner.cleanup(prepared, retired, cleanupSignal);
            assertProtectedFeasibilityCleanup(
              { ...dispatch, provider, profile },
              nonce,
              retired,
              cleanup,
            );
            requireFeasibility(
              streamClosed && Date.now() - cleanupStarted <= 30000,
            );
            cleanups.push({
              status: "PASS",
              independent: true,
              emergency: false,
              elapsedMs: Date.now() - cleanupStarted,
              witnessSha256: observationDigest([
                retired.nativeSha256,
                cleanup.witnessSha256,
              ]),
              cause: null,
            });
          }
        } catch {
          relay?.close();
          cleanups.push({
            status: "UNCERTAIN",
            independent: false,
            emergency:
              retired?.emergency === true || cleanup?.emergency === true,
            elapsedMs: Date.now() - cleanupStarted,
            witnessSha256: null,
            cause: {
              code: "cleanup-unobserved",
              detail: `Protected ${provider} cleanup was not independently settled.`,
            },
          });
        }
      }
      if (cause || cleanups.at(-1).status !== "PASS") break;
    }
    relay?.close();
    const cleanup = cleanups.find((entry) => entry.status !== "PASS") ?? {
      status: "PASS",
      independent: true,
      emergency: false,
      elapsedMs: cleanups.reduce((sum, entry) => sum + entry.elapsedMs, 0),
      witnessSha256: observationDigest(cleanups),
      cause: null,
    };
    if (cleanup.status === "PASS" && cleanup.elapsedMs > 30000) {
      cleanup.status = "UNCERTAIN";
      cleanup.cause = {
        code: "cleanup-unobserved",
        detail: "Protected provider cleanup exceeded its aggregate deadline.",
      };
    }
    for (const route of ["command", "file"]) {
      const entries = observations[route];
      results.push({
        capability: `${provider}.${route}-tools`,
        status: cause ? "FAIL" : "PASS",
        cause,
        elapsedMs: Date.now() - providerStarted,
        components: [inputs.packages[provider].component, helper],
        evidence: {
          ready: true,
          positiveControl: entries.length === (route === "command" ? 8 : 10),
          attemptAcknowledged: entries.length > 0,
          independent: entries.length > 0,
          outcome: "DENIED",
          observationSha256: observationDigest(entries),
          sentinelsBeforeSha256: observationDigest(
            entries.map((entry) => entry.sentinelsBeforeSha256),
          ),
          sentinelsAfterSha256: observationDigest(
            entries.map((entry) => entry.sentinelsAfterSha256),
          ),
        },
        cleanup,
      });
    }
    if (cause || cleanup.status !== "PASS") break;
  }
  const missingRecords = blocked(
    dispatch,
    "An earlier protected provider failure prevented subsequent model use.",
  ).filter(
    ({ capability }) =>
      capability !== "codex.command-exec" &&
      capability !== "provider.transport" &&
      !results.some((entry) => entry.capability === capability),
  );
  const failed = results.find(
    (entry) => entry.status !== "PASS" || entry.cleanup.status !== "PASS",
  );
  const providerCleanups = results
    .filter(({ capability }) => capability.endsWith("command-tools"))
    .map(({ cleanup }) => cleanup);
  results.push({
    capability: "provider.transport",
    status: failed ? "FAIL" : "PASS",
    cause: failed?.cause ?? failed?.cleanup.cause ?? null,
    elapsedMs: Date.now() - started,
    components: [inputs.packages.codex.component, helper],
    evidence: {
      ready: !failed,
      positiveControl: transportWitnesses.length === 4,
      attemptAcknowledged: true,
      independent: true,
      outcome: "PERMITTED",
      observationSha256: observationDigest(transportWitnesses),
      sentinelsBeforeSha256: observationDigest(
        results.map(({ evidence }) => evidence.sentinelsBeforeSha256),
      ),
      sentinelsAfterSha256: observationDigest(
        results.map(({ evidence }) => evidence.sentinelsAfterSha256),
      ),
    },
    cleanup: failed?.cleanup ?? {
      status: "PASS",
      independent: true,
      emergency: false,
      elapsedMs: providerCleanups.reduce(
        (sum, entry) => sum + entry.elapsedMs,
        0,
      ),
      witnessSha256: observationDigest(providerCleanups),
      cause: null,
    },
  });
  return [...results, ...missingRecords];
}

export async function runProviderFeasibility(
  dispatch,
  observed,
  protectedOptions,
) {
  requireProviderFeasibilityCI(dispatch.platform, dispatch.expectedSha);
  requireFeasibility(observed.checkoutSha === dispatch.expectedSha);
  const started = Date.now();
  let inputs,
    results,
    stage = "package-inputs";
  try {
    inputs = await prepareFeasibilityInputs(
      dispatch.platform,
      dispatch.expectedSha,
    );
    stage = "command-exec";
    const command = await runFeasibilityCommandProbe(dispatch, inputs);
    results = blocked(
      dispatch,
      "Independent model-free command observation is unavailable on this worker.",
    );
    results = results.map((entry) =>
      entry.capability === "codex.command-exec"
        ? {
            ...entry,
            elapsedMs: Date.now() - started,
            components: [inputs.packages.codex.component, inputs.tool],
            cleanup: inputs.commandCleanup ?? entry.cleanup,
          }
        : entry,
    );
    if (command) {
      command.cleanup = inputs.commandCleanup ?? command.cleanup;
      const assessment = assessFeasibilityReport(
        {
          schemaVersion: 1,
          expectedSha: dispatch.expectedSha,
          checkoutSha: observed.checkoutSha,
          platform: dispatch.platform,
          os: observed.os,
          build: observed.build,
          architecture: observed.architecture,
          results: [command],
        },
        dispatch,
      );
      const normalized = assessment.report.results.find(
        ({ capability }) => capability === command.capability,
      );
      results = results.map((entry) =>
        entry.capability === command.capability ? normalized : entry,
      );
    }
    if (
      dispatch.protectedAcceptance &&
      results.find(({ capability }) => capability === "codex.command-exec")
        .status === "PASS"
    ) {
      stage = "protected-tools";
      const protectedResults = await runProtectedProviderFeasibility(
        dispatch,
        inputs,
        protectedOptions,
      );
      results = results.map(
        (entry) =>
          protectedResults.find(
            ({ capability }) => capability === entry.capability,
          ) ?? entry,
      );
    } else
      results = results.map((entry) =>
        entry.capability === "codex.command-exec"
          ? entry
          : blocked(
              dispatch,
              "Protected model authorization and independently admitted native custody are external requirements.",
            ).find(({ capability }) => capability === entry.capability),
      );
  } catch (error) {
    const unavailable = [
      "ENOENT",
      "ERR_FEASIBILITY_ROUTE_UNAVAILABLE",
    ].includes(error?.code);
    const cause =
      error?.feasibilityCause ??
      feasibilityFailureCause(
        "provider",
        stage,
        { code: error?.code, signal: error?.signal, timedOut: error?.timedOut },
        unavailable ? "prerequisite-unavailable" : "setup-failed",
      );
    const failed = providerRecords(dispatch.platform, cause.code, cause.detail);
    results = failed.map((entry) =>
      stage === "protected-tools" && entry.capability === "codex.command-exec"
        ? results.find(({ capability }) => capability === entry.capability)
        : stage === "protected-tools"
          ? {
              ...entry,
              cleanup: {
                status: "UNCERTAIN",
                independent: false,
                emergency: false,
                elapsedMs: null,
                witnessSha256: null,
                cause: {
                  code: "cleanup-unobserved",
                  detail:
                    "Protected provider execution failed before reporting custody settlement.",
                },
              },
            }
          : entry,
    );
    if (inputs)
      results = results.map((entry) =>
        entry.capability === "codex.command-exec"
          ? {
              ...entry,
              elapsedMs: entry.elapsedMs ?? Date.now() - started,
              components: entry.components.length
                ? entry.components
                : [inputs.packages.codex.component, inputs.tool],
              cleanup: inputs.commandCleanup ?? entry.cleanup,
            }
          : entry,
      );
    if (error?.cleanupUncertain)
      results = results.map((entry) => ({
        ...entry,
        cleanup: {
          status: "UNCERTAIN",
          independent: false,
          emergency: false,
          elapsedMs: null,
          witnessSha256: null,
          cause: {
            code: "cleanup-unobserved",
            detail: "Partial package input cleanup remains uncertain.",
          },
        },
      }));
  } finally {
    if (inputs) {
      try {
        requireFeasibility(
          !results.some(({ cleanup }) =>
            ["FAIL", "UNCERTAIN"].includes(cleanup.status),
          ),
        );
        const started = Date.now(),
          witness = await inputs.cleanup();
        results = results.map((entry) =>
          entry.cleanup.status === "NOT_RUN" && entry.components.length > 0
            ? {
                ...entry,
                cleanup: {
                  status: "PASS",
                  independent: true,
                  emergency: false,
                  elapsedMs: Date.now() - started,
                  witnessSha256: witness,
                  cause: null,
                },
              }
            : entry.cleanup.status === "PASS"
              ? {
                  ...entry,
                  cleanup: {
                    ...entry.cleanup,
                    elapsedMs: entry.cleanup.elapsedMs + Date.now() - started,
                    witnessSha256: observationDigest([
                      entry.cleanup.witnessSha256,
                      witness,
                    ]),
                  },
                }
              : entry,
        );
      } catch {
        results = results.map((entry) => ({
          ...entry,
          cleanup: {
            ...entry.cleanup,
            status: entry.cleanup.status === "FAIL" ? "FAIL" : "UNCERTAIN",
            independent: false,
            witnessSha256: null,
            cause: entry.cleanup.cause ?? {
              code: "cleanup-unobserved",
              detail:
                "Owned input cleanup retained unsettled custody or objects.",
            },
          },
        }));
      }
    }
  }
  return results;
}
