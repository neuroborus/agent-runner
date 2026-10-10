import {
  NATIVE_EFFECT_CLASSES,
  normalizeNativePolicyBinding,
  materializeNativePolicy,
  verifyNativePolicy,
  normalizeClosureReference,
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import { normalizeProviderSpec, providerInvocation } from "./contract.js";
import { normalizeRelayPolicy } from "./relay.js";
import { runProtectedRelay } from "./relay-process.js";
import { runCredentialFreeBridge } from "./bridge-process.js";
import { normalizeCodexCases, assertCodexLiveBinding } from "./codex-cases.js";
import {
  normalizeClaudeCases,
  assertClaudeLiveBinding,
} from "./claude-cases.js";
import { protectedProviderRecipes } from "./dispatch.js";
import {
  providerPreparationContext,
  providerHash as hash,
  providerRetired as retired,
  providerRetained as retained,
  providerFunctions as functions,
  providerBuildInvocation,
} from "./preparation.js";
import { createProviderPreparationEffects } from "./preparation-effects.js";
import * as linuxAPI from "../linux/index.js";
import * as darwinAPI from "../darwin/index.js";
import * as windowsAPI from "../win32/index.js";

const profiles = {
  linux: {
    contract: "linuxProviderCIContract",
    reader: null,
    release: "observeLinuxCandidateClosure",
  },
  darwin: {
    contract: "darwinProviderCIContract",
    reader: "createDarwinCustodyReader",
    release: "observeDarwinRelease",
  },
  win32: {
    contract: "windowsProviderCIContract",
    reader: "createWindowsCustodyReader",
    release: "observeWindowsRelease",
  },
};
const same = (left, right) =>
  observationDigest(left) === observationDigest(right);

/** Repository composition only. Separately approved native primitives own
 * provisioning, private transport and independent kernel reads. Construction
 * does not bootstrap, compile, open a socket, launch a provider or take secrets. */
export function createProviderEffects(input, options = {}) {
  const preparationDefaults = createProviderPreparationEffects(input, options),
    caseDefaults =
      input.job.platform === "linux"
        ? linuxAPI.createLinuxProviderEffects(input, options)
        : {},
    defaults = {
      ...preparationDefaults,
      ...caseDefaults,
      ...(input.job.platform === "linux"
        ? {
            openLinuxCustody(declaration, operation) {
              return same(
                declaration.context,
                input.manifest.providerPreparation.bootstrap.context,
              )
                ? preparationDefaults.openLinuxCustody(declaration, operation)
                : caseDefaults.openLinuxCustody(declaration, operation);
            },
          }
        : {}),
    },
    supplied = options;
  const state = providerPreparationContext(input, options, defaults),
    profile = profiles[state.job.platform],
    api =
      input.api ??
      { linux: linuxAPI, darwin: darwinAPI, win32: windowsAPI }[
        state.job.platform
      ],
    active = new Map();
  functions(api, [profile.contract, profile.release]);
  const save = (current, phase, record = {}) =>
    state.write(
      `provider-case-${current.recipe.id}-${current.sequence++}.json`,
      { context: current.binding.context, phase, ...record },
    );
  const list = async () => {
    const value = await state.primitive("listReceipts", {
      directory: state.directory,
      context: state.plan.bootstrap.context,
    });
    requireObservation(
      value?.independent === true &&
        value.held === true &&
        value.protectedAuthority === true &&
        hash(value.nativeEventSha256) &&
        Array.isArray(value.names) &&
        value.names.length <= 65536 &&
        new Set(value.names).size === value.names.length &&
        value.names.every(
          (name) =>
            typeof name === "string" && /^[a-zA-Z0-9.-]{1,240}$/u.test(name),
        ),
    );
    return value.names;
  };
  const openCustody = async (declaration, signal, persist) => {
    state.guard(signal);
    let reader;
    const createReader =
      options.createReader ??
      (same(declaration.context, state.plan.bootstrap.context)
        ? defaults.createReader
        : undefined);
    if (createReader) reader = createReader(declaration, { signal, persist });
    else if (profile.reader) {
      functions(api, [profile.reader]);
      reader = api[profile.reader](declaration, {
        ...options.readerOptions,
        persist,
      });
    } else
      reader = await state.primitive("openLinuxCustody", declaration, {
        signal,
        persist,
      });
    state.guard(signal);
    functions(reader, ["start", "close"]);
    const admission = await reader.start({ signal });
    state.guard(signal);
    requireObservation(
      admission?.independent === true &&
        (profile.reader
          ? admission.planSha256 === declaration.plan.sha256
          : hash(admission.nativeEventSha256) &&
            same(admission.context, declaration.context)),
    );
    return { reader, admission };
  };
  const closeCustody = async (reader, signal) => {
    state.guard(signal);
    const result = await reader.close();
    state.guard(signal);
    requireObservation(
      retired(result) &&
        result.closed === true &&
        (state.job.platform !== "win32" || result.taskRemoved === true),
    );
    return result;
  };
  let bootstrapPromise;
  const bootstrap = (signal) => {
    state.guard(signal);
    if (bootstrapPromise) return bootstrapPromise;
    bootstrapPromise = (async () => {
      await state.verifyDirectory();
      const names = await list(),
        sequence =
          1 +
          Math.max(
            -1,
            ...names.map((name) =>
              Number(
                /^provider-bootstrap-([0-9]+)-intent\.json$/u.exec(name)?.[1] ??
                  -1,
              ),
            ),
          );
      requireObservation(Number.isSafeInteger(sequence) && sequence <= 65535);
      await state.write(`provider-bootstrap-${sequence}-intent.json`, {
        status: "POSSIBLE",
        context: state.plan.bootstrap.context,
        selectedSystemSha256: observationDigest(state.job.selectedSystem),
      });
      let step = 0;
      const persist = (record) =>
        state.write(
          `provider-bootstrap-${sequence}-custody-${step++}.json`,
          record,
        );
      const opened = await openCustody(state.plan.bootstrap, signal, persist);
      return { ...opened, sequence, persist };
    })();
    return bootstrapPromise;
  };
  const releaseBootstrap = async (signal) => {
    const current = await bootstrapPromise,
      settlement = await closeCustody(current.reader, signal);
    await state.write(
      `provider-bootstrap-${current.sequence}-result.json`,
      settlement,
    );
    state.guard(signal);
    bootstrapPromise = undefined;
    return settlement;
  };
  const readInputs = async () => {
    for (const member of state.manifest.inputs)
      requireObservation(
        (await state.read(member.path, member.sha256, 536870912)).length ===
          member.bytes,
      );
    for (const helper of state.manifest.helpers)
      await state.read(
        state.paths.join(state.plan.sourceDirectory, helper.name + ".c"),
        helper.sourceSha256,
        1048576,
      );
  };
  const buildRequest = () => ({
    candidateSha: state.job.candidateSha,
    platform: state.job.platform,
    reviewSha256: observationDigest(state.manifest),
    helpers: state.manifest.helpers,
    tools: state.buildManifest.tools,
    output: state.providerHelpers,
    deadlineMs: 120000,
    commands: api[profile.contract]({
      tools: state.buildManifest.tools,
      output: state.providerHelpers,
      sourceDirectory: state.plan.sourceDirectory,
    }).commands,
  });
  const verifyBuild = async (signal) => {
    state.guard(signal);
    const request = buildRequest(),
      id = observationDigest(request),
      prepared = state.preparation;
    requireObservation(
      prepared?.status === "PASS" &&
        prepared.requestSha256 === id &&
        same(prepared.request, request),
    );
    const receipt = JSON.parse(
      await state.read(
        state.paths.join(state.directory, `provider-build-${id}-result.json`),
        null,
        1048576,
        true,
      ),
    );
    requireObservation(
      observationDigest(receipt) === prepared.receiptSha256 &&
        receipt.requestSha256 === id &&
        receipt.status === "OBSERVED" &&
        receipt.independent === true &&
        hash(receipt.nativeEventSha256) &&
        retired(receipt.settlement),
    );
    await readInputs();
    for (const helper of request.helpers)
      await state.read(
        state.paths.join(request.output, helper.name),
        helper.sha256,
        134217728,
      );
    state.guard(signal);
    const observed = await state.primitive(
      "verifyPrepared",
      {
        request,
        receipt,
        buildManifest: state.buildManifest,
        helpers: state.helpers,
      },
      { signal },
    );
    requireObservation(
      retired(observed) &&
        observed.requestSha256 === id &&
        observed.noLiveMembers === true &&
        observed.unchanged === true,
    );
    state.guard(signal);
    return observed;
  };
  return {
    bootstrap,
    verifyBuild,
    async settleBuild() {
      requireObservation(!bootstrapPromise);
      return defaults.settlePreparation();
    },
    async prepareBuild(request, { signal } = {}) {
      state.guard(signal);
      requireObservation(same(request, buildRequest()));
      const id = observationDigest(request);
      await state.write(`provider-build-${id}-intent.json`, {
        request,
        status: "POSSIBLE",
      });
      await readInputs();
      const { reader, persist } = await bootstrap(signal);
      state.guard(signal);
      await state.primitive(
        "provisionBuild",
        { request, reader },
        { signal, persist },
      );
      state.guard(signal);
      const commands = [];
      for (const command of request.commands) {
        const tool = request.tools.find(
          (entry) => entry.path === command.executable,
        );
        requireObservation(tool && hash(tool.sha256));
        await state.read(tool.path, tool.sha256, 134217728);
        const invocation = providerBuildInvocation(request, command);
        await state.write(
          `provider-build-${id}-command-${commands.length}-intent.json`,
          { invocation, status: "POSSIBLE" },
        );
        state.guard(signal);
        const result = await state.primitive("runCommand", invocation, reader, {
          signal,
          persist,
        });
        state.guard(signal);
        requireObservation(
          result?.independent === true &&
            result.requestSha256 === observationDigest(invocation) &&
            result.toolSha256 === tool.sha256 &&
            result.exitCode === 0 &&
            result.signal === null &&
            result.timedOut === false &&
            hash(result.nativeEventSha256) &&
            retired(result.settlement),
        );
        commands.push(result);
        await state.write(
          `provider-build-${id}-command-${commands.length - 1}-result.json`,
          result,
        );
      }
      for (const helper of request.helpers)
        await state.read(
          state.paths.join(request.output, helper.name),
          helper.sha256,
          134217728,
        );
      state.guard(signal);
      const observed = await state.primitive(
        "verifyBuild",
        {
          request,
          commands,
          reader,
          buildManifest: state.buildManifest,
          helpers: state.helpers,
        },
        { signal, persist },
      );
      state.guard(signal);
      requireObservation(
        retired(observed) &&
          observed.requestSha256 === id &&
          observed.commandsSha256 === observationDigest(commands) &&
          observed.noLiveMembers === true,
      );
      const custody = await releaseBootstrap(signal);
      const receipt = {
        requestSha256: id,
        status: "OBSERVED",
        independent: true,
        nativeEventSha256: observationDigest({ observed, custody }),
        settlement: observed,
        commands,
        custody,
      };
      await state.write(`provider-build-${id}-result.json`, receipt);
      state.guard(signal);
      return receipt;
    },
    async prepare(recipe, { signal, policyBinding } = {}) {
      const fixed = protectedProviderRecipes(state.job.platform).find(
          (entry) => entry.id === recipe.id,
        ),
        binding = normalizeNativePolicyBinding(policyBinding);
      const approved = state.manifest.execution.cases.find(
        (entry) => entry.id === recipe.id,
      );
      requireObservation(
        fixed &&
          same(recipe, approved) &&
          state.templates.some(
            (entry) =>
              same(entry.template, binding.template) &&
              same(entry.approval, binding.approval),
          ) &&
          !active.has(recipe.id) &&
          ["group", "profile", "deadlineMs", "checkIds"].every((key) =>
            same(recipe[key], fixed[key]),
          ) &&
          recipe.templateSha256 === binding.approval.manifestSha256 &&
          hash(recipe.reviewSha256),
      );
      const declared = state.plan.cases.find((entry) => entry.id === recipe.id);
      requireObservation(same(declared.custody.context, binding.context));
      await verifyBuild(signal);
      const current = {
        recipe: structuredClone(recipe),
        binding,
        declared,
        sequence: 0,
        signal,
        policyReads: 0,
        receivers: new Map(),
        retired: false,
      };
      current.persist = (record) => save(current, "native", { record });
      active.set(recipe.id, current);
      await save(current, "provisioning-possible", {
        bindingsSha256: observationDigest(declared.bindings),
      });
      state.guard(signal);
      current.provisioned = await state.primitive(
        "provision",
        declared,
        binding,
        { signal, persist: current.persist },
      );
      state.guard(signal);
      current.specification = normalizeProviderSpec(
        current.provisioned.specification,
      );
      requireObservation(
        same(
          current.specification,
          normalizeProviderSpec(declared.specification),
        ),
      );
      current.launch = structuredClone(current.provisioned.launch);
      requireObservation(same(current.launch, declared.launch));
      await save(current, "provisioned", { launch: current.launch });
      Object.assign(
        current,
        await openCustody(declared.custody, signal, (record) =>
          save(current, "custody", { record }),
        ),
      );
      state.guard(signal);
      current.readers = await state.primitive("bindReaders", current, {
        signal,
      });
      state.guard(signal);
      functions(current.readers, ["inspect", "observe"]);
      const release = await (options.observeRelease ?? api[profile.release])(
        state.manifest.release,
        state.job.reviews.release,
        current.readers.release,
      );
      state.guard(signal);
      const freshClosure = normalizeClosureReference({
        ...release.closure,
        sourceReviewSha256: state.job.reviews.source.manifestSha256,
      });
      const selectedClosure = normalizeClosureReference(state.job.closure);
      // Native reads have a fresh observation/settlement identity. Rejoin the
      // independently approved bytes and provider bindings, not old evidence.
      requireObservation(
        [
          "schemaVersion",
          "policyTemplates",
          "manifestSha256",
          "sourceReviewSha256",
        ].every((key) => same(freshClosure[key], selectedClosure[key])),
      );
      await save(current, "release-observed", { closure: freshClosure });
      state.guard(signal);
      current.raw = await state.primitive("launchEffects", current, { signal });
      state.guard(signal);
      functions(current.raw, ["persist", "readProvisioning", "readPolicy"]);
      const persist = (record) => save(current, "owner", { record });
      const launchEffects = {
        ...current.raw,
        persist: async (record) => {
          await persist(record);
          return current.raw.persist(record);
        },
        readProvisioning: async (...args) => {
          state.guard(signal);
          const actual = await current.raw.readProvisioning(...args);
          materializeNativePolicy(
            binding.template,
            binding.approval,
            actual,
            binding.context,
          );
          current.provisioning = structuredClone(actual);
          current.policyReads = 0;
          state.guard(signal);
          return actual;
        },
        readPolicy: async (...args) => {
          state.guard(signal);
          requireObservation(current.provisioning);
          const observed = await current.raw.readPolicy(...args);
          const proof = verifyNativePolicy(
            binding.template,
            binding.approval,
            current.provisioning,
            binding.context,
            observed.requestSha256,
            observed,
          );
          requireObservation(
            !current.policySha256 ||
              current.policySha256 === proof.expectedPolicySha256,
          );
          current.policySha256 = proof.expectedPolicySha256;
          current.policyReads++;
          await save(current, "policy-observed", { proof });
          state.guard(signal);
          return observed;
        },
      };
      const raw = await state.primitive("transportEffects", current, {
        signal,
        services: { relay: runProtectedRelay, bridge: runCredentialFreeBridge },
      });
      state.guard(signal);
      functions(raw, [
        "review",
        "admitTransport",
        "verifyRelayCustody",
        "verifyTransport",
        "controls",
        "closeTransport",
        "retire",
        "verifySettlement",
        "modelReceipts",
      ]);
      const effects = {
        ...raw,
        persist,
        admitTransport: async (role, context, ...args) => {
          const operation = args.at(-1);
          state.guard(signal);
          state.guard(operation?.signal);
          requireObservation(
            ["relay", "bridge"].includes(role) &&
              current.policyReads > 0 &&
              same(
                normalizeProviderSpec(context.spec),
                current.specification,
              ) &&
              same(
                context.invocation,
                providerInvocation(current.specification),
              ) &&
              same(normalizeRelayPolicy(context.policy), relayPolicy) &&
              context.configurationSha256 ===
                observationDigest({
                  specificationSha256: context.invocation.specificationSha256,
                  policy: relayPolicy,
                }) &&
              !current.receivers.has(role),
          );
          await save(current, `${role}-possible`, {
            configurationSha256: context.configurationSha256,
          });
          state.guard(signal);
          state.guard(operation?.signal);
          const receiver = await raw.admitTransport(role, context, ...args);
          requireObservation(
            receiver?.independent === true &&
              receiver.role === role &&
              receiver.admitted === true &&
              receiver.receiptVerified === true &&
              receiver.candidateSha === state.job.candidateSha &&
              receiver.nonce === current.specification.nonce &&
              receiver.configurationSha256 === context.configurationSha256 &&
              hash(receiver.nativeSha256),
          );
          current.receivers.set(role, receiver);
          state.guard(signal);
          state.guard(operation?.signal);
          return receiver;
        },
        inspect: async (spec, cases, domain, operation) => {
          state.guard(signal);
          const observed = await current.readers.inspect(
            spec,
            cases,
            domain,
            operation,
          );
          (spec.provider === "codex"
            ? assertCodexLiveBinding
            : assertClaudeLiveBinding)(spec, cases, observed);
          state.guard(signal);
          return observed;
        },
        observe: (...args) => current.readers.observe(...args),
      };
      const relayPolicy = normalizeRelayPolicy(declared.bindings.relayPolicy);
      requireObservation(
        relayPolicy.provider === current.specification.provider &&
          relayPolicy.nonce === current.specification.nonce &&
          relayPolicy.model === current.specification.model,
      );
      const prepared = {
        independent: true,
        reviewSha256: recipe.reviewSha256,
        templateSha256: binding.approval.manifestSha256,
        specification: current.specification,
        launch: current.launch,
        launchEffects,
        launchOptions: { ...options.launchOptions, env: state.env },
        relayPolicy,
        effects,
        cases: async (domain, operation) => {
          state.guard(signal);
          requireObservation(current.policyReads > 0);
          const value = await state.primitive(
            "prepareCases",
            current,
            domain,
            operation,
          );
          const cases = (
            current.specification.provider === "codex"
              ? normalizeCodexCases
              : normalizeClaudeCases
          )(current.specification, value);
          requireObservation(
            cases.plan.policySha256 === current.policySha256 &&
              cases.plan.reviewSha256 === recipe.reviewSha256,
          );
          state.guard(signal);
          return cases;
        },
      };
      current.prepared = prepared;
      state.guard(signal);
      return prepared;
    },
    persistReceipt(id, sha256) {
      requireObservation(hash(sha256) && active.has(id));
      return save(active.get(id), "owner-receipt", { sha256 });
    },
    async settle(recipe, prepared, { signal, execution } = {}) {
      requireObservation(execution?.id === recipe.id);
      const current = active.get(recipe.id);
      let result = retained();
      try {
        requireObservation(
          current &&
            current.signal?.aborted === true &&
            (!prepared || current.prepared === prepared) &&
            !current.retired,
        );
        state.guard(signal);
        await save(current, "retirement-possible");
        state.guard(signal);
        if (current.reader?.beginCleanup)
          await current.reader.beginCleanup({ signal });
        state.guard(signal);
        const payload = await state.primitive("retire", current, { signal });
        state.guard(signal);
        requireObservation(
          retired(payload) &&
            payload.noLiveMembers === true &&
            payload.candidateSha === state.job.candidateSha &&
            payload.nonce ===
              (current.specification?.nonce ??
                current.declared.specification.nonce),
        );
        await save(current, "payload-retired", { settlement: payload });
        state.guard(signal);
        const audit = await state.primitive("releaseAudit", current, payload, {
          signal,
        });
        state.guard(signal);
        requireObservation(retired(audit) && audit.drained === true);
        if (current.reader?.authorizeRestoration)
          await current.reader.authorizeRestoration(payload);
        state.guard(signal);
        const restored = await state.primitive("restore", current, payload, {
          signal,
        });
        state.guard(signal);
        requireObservation(
          restored?.independent === true &&
            restored.unchangedInstalled === true &&
            restored.status === "RESTORED" &&
            hash(restored.nativeEventSha256),
        );
        const custody = current.reader
          ? await closeCustody(current.reader, signal)
          : {
              status: "RETIRED",
              independent: true,
              emergencyCleanup: false,
              closed: true,
            };
        const settlement = {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
          nativeEventSha256: observationDigest({
            payload,
            audit,
            restored,
            custody,
          }),
        };
        await save(current, "retired", { settlement });
        state.guard(signal);
        result = settlement;
        current.retired = true;
      } catch {
        /* Complete protected possible ledgers remain recoverable. */
      }
      return Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((effectClass) => {
          const admission = execution.effects[effectClass]?.admission;
          requireObservation(["not-started", "possible"].includes(admission));
          if (admission === "not-started") return [effectClass, null];
          const settlement = {
            status: result.status,
            independent: result.independent,
            emergencyCleanup: result.emergencyCleanup,
          };
          return [
            effectClass,
            {
              candidateSha: state.job.candidateSha,
              executionId: recipe.id,
              effectClass,
              settlement,
              sha256: observationDigest({ effectClass, result }),
            },
          ];
        }),
      );
    },
    async recover({ request, job, preparation, signal }) {
      observationObject(request, [
        "candidateSha",
        "platform",
        "jobSha256",
        "preparationSha256",
        "deadlineMs",
      ]);
      requireObservation(
        request.deadlineMs === 120000 &&
          request.candidateSha === state.job.candidateSha &&
          request.platform === state.job.platform &&
          request.jobSha256 === observationDigest(job) &&
          request.preparationSha256 === observationDigest(preparation),
      );
      try {
        state.guard(signal);
        const names = (await list())
            .filter(
              (name) =>
                ![
                  "provider-preparation.json",
                  "provider-cleanup.json",
                ].includes(name) &&
                /^(?:provider-|windows-files-).*\.json$/u.test(name),
            )
            .sort(),
          records = [];
        let total = 0;
        for (const name of names) {
          const bytes = await state.read(
            state.paths.join(state.directory, name),
            null,
            1048576,
            true,
          );
          total += bytes.length;
          requireObservation(total <= 67108864);
          records.push({ name, record: JSON.parse(bytes) });
        }
        const id = observationDigest(request),
          sequence = names.filter((name) =>
            /^provider-recovery-.*-intent\.json$/u.test(name),
          ).length;
        await state.write(`provider-recovery-${id}-${sequence}-intent.json`, {
          request,
          status: "POSSIBLE",
        });
        const current = supplied.recover
            ? await bootstrap(signal)
            : await defaults.openRecovery({ signal }),
          { reader, persist } = current;
        state.guard(signal);
        const caseRecords = records.filter(({ name }) =>
          name.startsWith("provider-case-"),
        );
        const cases =
          !supplied.recover &&
          state.job.platform === "linux" &&
          caseRecords.length
            ? await caseDefaults.recoverCases(caseRecords, { signal, persist })
            : null;
        if (cases)
          requireObservation(
            retired(cases) &&
              cases.recordsSha256 === observationDigest(caseRecords),
          );
        const recoveryRecords = cases
          ? records.filter(({ name }) => !name.startsWith("provider-case-"))
          : records;
        const observed = supplied.recover
          ? await state.primitive(
              "recover",
              { request, job, preparation, records, plan: state.plan, reader },
              { signal, persist },
            )
          : await defaults.recoverPreparation(
              { request, records: recoveryRecords, reader },
              { signal },
            );
        state.guard(signal);
        requireObservation(
          retired(observed) &&
            observed.requestSha256 === id &&
            observed.noLiveMembers === true &&
            observed.recordsSha256 ===
              observationDigest(supplied.recover ? records : recoveryRecords) &&
            (supplied.recover
              ? observed.ownedRestoration === true &&
                (state.job.platform !== "win32" ||
                  observed.tasksRemoved === true) &&
                NATIVE_EFFECT_CLASSES.every((effect) =>
                  retired(observed.effects?.[effect]),
                )
              : observed.ownedRestorationComplete === true &&
                observed.ownedTasksRemoved === true),
        );
        const custody = supplied.recover
          ? await releaseBootstrap(signal)
          : await defaults.closeRecovery(current, { signal });
        const result = {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
          requestSha256: id,
          nativeEventSha256: observationDigest({ observed, custody, cases }),
        };
        await state.write(
          `provider-recovery-${id}-${sequence}-result.json`,
          result,
        );
        if (!supplied.recover) {
          const filesSettlement = await defaults.settlePreparation();
          requireObservation(
            retired(filesSettlement) && filesSettlement.noLiveMembers === true,
          );
          result.nativeEventSha256 = observationDigest({
            result,
            filesSettlement,
          });
        }
        state.guard(signal);
        return result;
      } catch {
        return {
          ...retained(),
          requestSha256: observationDigest(request),
          nativeEventSha256: observationDigest({ request, retained: true }),
        };
      }
    },
  };
}
