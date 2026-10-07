import { win32 as path } from "node:path";
import {
  observationDigest,
  preparedNativeCommands,
  requireObservation,
  normalizeNativePolicyBinding,
  materializeNativePolicy,
  verifyNativePolicy,
  materializeNativePolicyBinding,
  assertNativePolicyLaunchBinding,
  assertNativePolicyParameters,
  NATIVE_EFFECT_CLASSES,
} from "../index.js";
import {
  digest,
  hash,
  windowsLaunchDigest,
  WINDOWS_LITERAL_ARGUMENTS,
  sameWindowsIdentity,
  systemIdentity,
  inspectWindowsPe,
} from "./protocol.js";
import {
  windowsPreparationContext,
  windowsPreparationOptions,
  windowsRetired as retired,
  windowsRetained as retained,
  requireWindowsFunctions as functions,
} from "./preparation.js";
import { decodePlan } from "./custody-protocol.js";
import { createWindowsEffectiveReaders } from "./effective.js";
import {
  createWindowsAuditCustody,
  createWindowsAuditDecoder,
  createWindowsSecurityCapture,
} from "./audit.js";
import { windowsSystemRecipes } from "./system.js";
import {
  WINDOWS_HELPER_NAMES,
  WINDOWS_BUILD_TOOLS,
  windowsBuildOperation,
} from "./build.js";
import { admitWindowsLaunch } from "./launch.js";
import { retireWindowsDomain } from "./retirement.js";
import { configureWindowsPolicy } from "./policy-effects.js";
import { buildWindowsPolicy } from "./policy.js";
import { createWindowsCaseEffects } from "./case-effects.js";
import { createWindowsCaseProvisioning } from "./case-provisioning.js";

// Finite contracts of the existing owners. They retain their native assertions.
const ownerNames = (recipe) => {
  if (["ownership.literal", "ownership.storage"].includes(recipe.id))
    return [
      "verifyInputs",
      "inspect",
      "verifySetup",
      "installPolicy",
      "verifyAuthority",
      "verifyReceipt",
      "retire",
      "readProvisioning",
      "readPolicy",
    ];
  if (recipe.id.startsWith("ownership."))
    return [
      "verifyComposition",
      "admit",
      "observe",
      "armFault",
      "fireFault",
      "recoverAndRetire",
      "verify",
    ];
  if (recipe.id.startsWith("access."))
    return [
      "prepare",
      "admit",
      "observe",
      "snapshot",
      "retire",
      ...(recipe.id.endsWith(".none") ? [] : ["armFault", "fireFault"]),
    ];
  if (recipe.id === "git.fixed")
    return ["snapshot", "review", "open", "observe", "admitChild", "retire"];
  if (recipe.id === "git.ordinary") return ["review", "ordinary", "retire"];
  if (recipe.group === "release")
    return [
      "openHeld",
      "inspectHeld",
      "readHeld",
      "loaderClosure",
      "buildBindings",
      "observeAuthority",
      "inspectProvider",
      "closeHeld",
      "verifyClosed",
    ];
  const names = ["fileEffects", "observe", "verifyRetirement"];
  if (recipe.id === "files.private") names.push("privateProbe");
  if (recipe.id === "files.publish")
    names.push("startPublishers", "finishPublishers");
  if (recipe.id === "files.replace") names.push("startReader", "finishReader");
  if (["files.substitution", "files.aliases"].includes(recipe.id))
    names.push("applyControl", "observeDenial", "restoreControl");
  return names;
};
const same = (left, right) =>
  observationDigest(left) === observationDigest(right);
const literalRecipe = (recipe) =>
  ["ownership.literal", "ownership.storage"].includes(recipe.id);

/** Effect-free composition of repository owners. The independently approved
 * capability supplies protected provisioning, transport and coverage primitives;
 * it cannot change recipes, policy barriers or custody retirement requirements. */
export function createWindowsSystemEffects(
  input,
  options = {},
  preparationOwners = new Map(),
) {
  options = windowsPreparationOptions(input, options, preparationOwners);
  const state = windowsPreparationContext(input, options),
    active = new Map(),
    provisioning = createWindowsCaseProvisioning(state, options);
  let buildVerified = false,
    buildSettlement = null,
    buildCustody = null;
  const primitive = (name, ...args) => {
    const owner = options[name] ?? provisioning[name];
    requireObservation(typeof owner === "function");
    return owner(...args);
  };
  const verifyBuild = async (
    preparation,
    {
      signal,
      policyBinding,
      recordPolicy,
      verificationPending = false,
      keepCustody = false,
    } = {},
  ) => {
    buildVerified = false;
    buildSettlement = buildCustody = null;
    state.guard(signal);
    const nativeCommands = preparedNativeCommands(
      preparation,
      state.manifest,
      WINDOWS_BUILD_TOOLS.length + WINDOWS_HELPER_NAMES.length,
      { verificationPending },
    );
    const binding =
      policyBinding && normalizeNativePolicyBinding(policyBinding);
    if (binding)
      requireObservation(
        typeof recordPolicy === "function" &&
          same(binding.context, state.plan.bootstrap.context),
      );
    requireObservation(
      preparation?.status === "PASS" &&
        preparation.candidateSha === state.job.candidateSha &&
        preparation.platform === "win32" &&
        preparation.reviewSha256 === observationDigest(state.manifest) &&
        preparation.helpers.length === WINDOWS_HELPER_NAMES.length &&
        preparation.versions.length === state.manifest.tools.length &&
        nativeCommands.length ===
          WINDOWS_BUILD_TOOLS.length + WINDOWS_HELPER_NAMES.length &&
        state.manifest.tools.every(
          (tool) =>
            preparation.versions.filter(
              (entry) =>
                entry.name === tool.name &&
                entry.version === tool.version &&
                entry.sha256 === tool.sha256,
            ).length === 1,
        ),
    );
    const reader =
        options.readProtected && Object.hasOwn(options, "verifyCommands")
          ? (await state.bootstrap(signal)).reader
          : null,
      reads = [],
      commands = [];
    if (!Object.hasOwn(options, "verifyCommands")) {
      await options.beginVerification?.(signal);
      const entries = decodePlan(
        await state.read(
          state.plan.bootstrap.plan.path,
          state.plan.bootstrap.plan.sha256,
          262144,
        ),
        state.plan.bootstrap,
      );
      const pins = [
        ...state.manifest.tools,
        state.plan.bootstrap.reader,
        state.plan.bootstrap.bridge,
        state.plan.bootstrap.plan,
        ...state.plan.sources.map((source) => ({
          path: path.join(state.plan.sourceDirectory, source.name),
          sha256: source.sha256,
        })),
        ...state.manifest.helpers.map(({ name, sha256 }) => ({
          path: path.join(state.plan.sourceDirectory, name + ".exe"),
          sha256,
        })),
        ...entries.filter((entry) => entry.kind === "sdk"),
      ];
      for (const pin of pins)
        reads.push({
          path: pin.path,
          sha256: digest(await state.read(pin.path, pin.sha256)),
        });
    }
    for (const name of WINDOWS_HELPER_NAMES) {
      const pin = state.manifest.helpers.find((entry) => entry.name === name);
      requireObservation(
        preparation.helpers.filter(
          (entry) => entry.name === name && entry.sha256 === pin.sha256,
        ).length === 1,
      );
      const bytes = await state.read(
          path.join(state.output, name + ".exe"),
          pin.sha256,
        ),
        image = (options.inspectImage ?? inspectWindowsPe)(bytes);
      reads.push({
        name,
        sha256: digest(bytes),
        signatureSha256: image.signatureSha256,
      });
      requireObservation(
        image.signatureSha256 === state.plan.command.helperSignatures[name],
      );
    }
    for (const entry of nativeCommands) {
      requireObservation(
        entry.status === "RETIRED" &&
          hash(entry.requestSha256) &&
          hash(entry.receiptSha256),
      );
      const intent = JSON.parse(
          await state.receipt(
            path.join(
              state.directory,
              `windows-command-${entry.requestSha256}-intent.json`,
            ),
          ),
        ),
        operation = windowsBuildOperation(
          intent.request,
          state.manifest,
          state.output,
        );
      requireObservation(
        intent.requestSha256 === observationDigest(intent.request) &&
          intent.requestSha256 === entry.requestSha256 &&
          intent.candidateSha === state.job.candidateSha &&
          intent.status === "POSSIBLE",
      );
      const observed = JSON.parse(
        await state.receipt(
          path.join(
            state.directory,
            `windows-command-${entry.requestSha256}-result.json`,
          ),
        ),
      );
      const accepted =
        operation.mode === "compile"
          ? [0]
          : [
              0,
              ...WINDOWS_BUILD_TOOLS.find(
                (tool) => tool.name === operation.tool.name,
              ).versionExitCodes,
            ];
      requireObservation(
        observed.requestSha256 === entry.requestSha256 &&
          observationDigest(observed) === entry.receiptSha256 &&
          observed.independent === true &&
          accepted.includes(observed.exitCode) &&
          observed.signal === null &&
          observed.timedOut === false &&
          typeof observed.stdout === "string" &&
          typeof observed.stderr === "string" &&
          Buffer.byteLength(observed.stdout) +
            Buffer.byteLength(observed.stderr) <=
            65536 &&
          observed.toolSha256 === operation.tool.sha256 &&
          hash(observed.nativeEventSha256) &&
          retired(observed.settlement) &&
          retired(observed.bootstrapSettlement) &&
          observed.bootstrapSettlement.closed === true &&
          observed.bootstrapSettlement.taskRemoved === true,
      );
      requireObservation(
        systemIdentity(observed.identity).pid !==
          systemIdentity(observed.helperIdentity).pid,
      );
      if (operation.mode !== "compile")
        requireObservation(
          (observed.stdout + observed.stderr).trim().split(/\r?\n/u)[0] ===
            operation.tool.version,
        );
      if (operation.mode === "compile") {
        const publication = observed.publication;
        requireObservation(
          publication?.requestSha256 === entry.requestSha256 &&
            publication.independent === true &&
            publication.unsignedSha256 ===
              state.plan.command.unsignedHelpers[operation.helper.name] &&
            publication.sourceSha256 === operation.source.sha256 &&
            publication.imageSha256 === operation.helper.sha256 &&
            publication.signatureSha256 ===
              state.plan.command.helperSignatures[operation.helper.name] &&
            publication.protectedDacl === true &&
            publication.writerClosed === true &&
            hash(publication.nativeEventSha256) &&
            retired(publication.settlement),
        );
      }
      commands.push({
        ...observed,
        operation: operation.mode,
        target: operation.target ?? null,
      });
    }
    requireObservation(
      new Set(nativeCommands.map((entry) => entry.requestSha256)).size ===
        commands.length &&
        ["compiler-version", "sdk-version"].every(
          (mode) =>
            commands.filter((entry) => entry.operation === mode).length === 1,
        ) &&
        WINDOWS_HELPER_NAMES.every(
          (name) =>
            commands.filter(
              (entry) =>
                entry.operation === "compile" &&
                entry.target === path.join(state.output, name + ".exe"),
            ).length === 1,
        ),
    );
    // The native verifier rejoins creation identities and whole compiler/helper
    // Jobs plus owned task removal. Child exit and receipt booleans are insufficient.
    const settled = await primitive("verifyCommands", commands, reader, {
      signal,
    });
    requireObservation(
      retired(settled) &&
        settled.commandsSha256 === observationDigest(commands) &&
        settled.noLiveMembers === true &&
        settled.tasksRemoved === true,
    );
    if (state.hasBootstrap()) await state.releaseBootstrap();
    const custody =
      binding || keepCustody ? null : await options.settleFiles?.();
    requireObservation(
      custody == null ||
        (retired(custody) &&
          custody.noLiveMembers === true &&
          custody.taskRemoved === true),
    );
    state.guard(signal);
    const result = {
      status: "OBSERVED",
      independent: true,
      candidateSha: state.job.candidateSha,
      preparationSha256: observationDigest(preparation),
      nativeEventSha256: observationDigest({
        reads,
        settled,
        custody: custody ?? null,
      }),
      settlement: settled,
    };
    if (binding) {
      const proof = await primitive(
        "observeBuildPolicy",
        binding,
        { ...result, commands },
        {
          signal,
        },
      );
      verifyNativePolicy(
        binding.template,
        binding.approval,
        proof.provisioning,
        binding.context,
        proof.requestSha256,
        proof.observed,
      );
      await recordPolicy(proof);
      state.guard(signal);
    }
    buildSettlement = settled;
    buildCustody = custody;
    buildVerified = true;
    return result;
  };
  const save = (id, record) => {
    const current = active.get(id);
    requireObservation(current);
    return state.write(`windows-case-${id}-${current.sequence++}.json`, {
      context: current.binding.context,
      ...record,
    });
  };
  const installAudit = async (current, declaration) => {
    requireObservation(
      !current.audit && same(declaration.context, current.binding.context),
    );
    current.audit = (options.createAudit ?? createWindowsAuditCustody)(
      current.reader,
      declaration.input,
      declaration.transfer,
      {
        verifier: current.admission.verifier,
        persist: (record) =>
          save(current.recipe.id, { phase: "audit", record }),
        review: (value) => primitive("reviewAudit", value, current),
        verifyRetirement: (...args) =>
          primitive("verifyAuditRetirement", current, ...args),
        verifySettlement: (...args) =>
          primitive("verifyAuditSettlement", current, ...args),
      },
    );
    const installed = await current.audit.install();
    current.auditChannel = installed.channel;
    const decoder = (options.createDecoder ?? createWindowsAuditDecoder)(
      current.reader,
      declaration.mapping,
    );
    current.capture = (options.createCapture ?? createWindowsSecurityCapture)(
      installed.channel,
      decoder,
      declaration.input,
    );
    await current.capture.start();
    return current.capture;
  };
  const finish = async (current, { signal } = {}) => {
    requireObservation(
      signal instanceof AbortSignal && !signal.aborted && current.reader,
    );
    if (current.ownership) return current.ownership.finish({ signal });
    await save(current.recipe.id, { phase: "cleanup-possible" });
    current.cleanupSignal = signal;
    await current.reader.beginCleanup({ signal });
    state.guard(signal);
    const payload = await primitive("retire", current, { signal });
    requireObservation(
      retired(payload) &&
        payload.candidateSha === state.job.candidateSha &&
        payload.nonce === current.declared.custody.nonce &&
        payload.noLiveMembers === true &&
        (await primitive("verifyRetirement", current, payload, { signal })) ===
          true,
    );
    await save(current.recipe.id, {
      phase: "payload-retired",
      settlement: payload,
    });
    state.guard(signal);
    let audit;
    if (current.audit) {
      requireObservation(current.capture && current.auditChannel);
      const observation = await current.capture.stop(payload);
      const observer = await current.auditChannel.close();
      requireObservation(retired(observer) && observer.closed === true);
      await save(current.recipe.id, {
        phase: "observer-retired",
        observationSha256: observationDigest(observation),
        settlement: observer,
      });
      audit = await current.audit.restore(payload, observer);
      requireObservation(
        audit.independent === true &&
          audit.beforeSha256 === audit.restoredSha256 &&
          hash(audit.nativeEventSha256),
      );
    } else {
      audit = await primitive("releaseAudit", current, payload, { signal });
      requireObservation(retired(audit));
    }
    state.guard(signal);
    await current.reader.authorizeRestoration(payload);
    const restored = await primitive("restore", current, payload, { signal });
    requireObservation(
      restored?.status === "RESTORED" &&
        restored.independent === true &&
        restored.unchangedInstalled === true &&
        hash(restored.nativeEventSha256),
    );
    state.guard(signal);
    const custody = await current.reader.close();
    requireObservation(
      retired(custody) &&
        custody.closed === true &&
        custody.taskRemoved === true,
    );
    const result = {
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
    await save(current.recipe.id, { phase: "retired", settlement: result });
    current.retired = true;
    return result;
  };
  return {
    bootstrap: state.bootstrap,
    readInput: (file, maximum) => {
      const pin = [
        ...(state.manifest.inputs ?? []),
        ...state.manifest.tools,
      ].find((entry) => entry.path === file);
      requireObservation(pin);
      return state.read(file, pin.sha256, maximum);
    },
    readPreparedImage: (file, pin) => {
      requireObservation(
        state.manifest.helpers.some(
          ({ name, sha256 }) =>
            file === path.join(state.output, name + ".exe") && sha256 === pin,
        ),
      );
      return state.read(file, pin);
    },
    verifyBuild,
    async build({
      candidateSha,
      reviewSha256,
      signal,
      policyBinding,
      recordPolicy,
    }) {
      requireObservation(
        candidateSha === state.job.candidateSha &&
          policyBinding &&
          typeof recordPolicy === "function",
      );
      return {
        ...(await verifyBuild(state.preparation, {
          signal,
          policyBinding,
          recordPolicy,
        })),
        reviewSha256,
      };
    },
    async prepare(recipe, { signal, policyBinding, recordPolicy } = {}) {
      const fixed = windowsSystemRecipes().find(
          (entry) => entry.id === recipe.id,
        ),
        binding = normalizeNativePolicyBinding(policyBinding);
      requireObservation(
        fixed &&
          fixed.id !== "build" &&
          ["group", "profile", "deadlineMs"].every(
            (key) => fixed[key] === recipe[key],
          ) &&
          same(fixed.checkIds, recipe.checkIds) &&
          !active.has(recipe.id) &&
          typeof recordPolicy === "function" &&
          binding.context.candidateSha === state.job.candidateSha &&
          binding.context.platform === "win32" &&
          binding.context.executionId === recipe.id,
      );
      await verifyBuild(state.preparation, { signal, keepCustody: true });
      const declared = state.plan.cases.find((entry) => entry.id === recipe.id);
      requireObservation(same(declared.custody.context, binding.context));
      const current = {
        recipe: structuredClone(recipe),
        binding,
        declared,
        sequence: 0,
        retired: false,
        signal,
      };
      active.set(recipe.id, current);
      await save(recipe.id, {
        phase: "provisioning-possible",
        templateSha256: binding.approval.manifestSha256,
        bindingsSha256: observationDigest(declared.bindings),
        status: "POSSIBLE",
      });
      state.guard(signal);
      const provisioned = await primitive(
        "provision",
        structuredClone(declared),
        binding,
        { signal, current, persist: (record) => save(recipe.id, record) },
      );
      current.provisioned = provisioned;
      current.input = structuredClone(provisioned.input);
      const launch = current.input.request ?? current.input,
        args = provisioned.arguments ?? WINDOWS_LITERAL_ARGUMENTS,
        literal = literalRecipe(recipe);
      requireObservation(
        launch.candidateSha === state.job.candidateSha &&
          (recipe.group === "release" ||
            (launch.nonce === declared.custody.nonce &&
              launch.bindings?.closure === binding.context.closureSha256)),
      );
      let expected, policy;
      if (literal) assertNativePolicyLaunchBinding(binding, launch, args);
      else {
        expected = materializeNativePolicy(
          binding.template,
          binding.approval,
          provisioned.provisioning,
          binding.context,
        );
        if (recipe.group !== "release")
          materializeNativePolicyBinding(
            binding,
            provisioned.provisioning,
            launch,
            args,
          );
        if (recipe.id.startsWith("access.")) {
          policy = buildWindowsPolicy(current.input);
          assertNativePolicyParameters(
            binding,
            provisioned.provisioning,
            policy.value,
            args,
          );
          requireObservation(
            launch.policy.sha256 === policy.policySha256 &&
              launch.bindings.policy === policy.compositionSha256,
          );
        }
      }
      await save(recipe.id, {
        phase: "provisioned",
        input: current.input,
        provisioning: provisioned.provisioning ?? null,
        arguments: args,
      });
      current.reader ??= state.createReader(declared.custody, {
        ...options.readerOptions,
        persist: (record) => save(recipe.id, { phase: "custody", record }),
      });
      current.admission ??= await current.reader.start({ signal });
      requireObservation(
        current.admission.independent === true &&
          current.admission.planSha256 === declared.custody.plan.sha256,
      );
      const build = await (
        current.reader.build ?? current.reader.buildBindings
      ).call(current.reader);
      requireObservation(
        build.independent === true &&
          build.major === 10 &&
          build.minor === 0 &&
          build.build === 26100,
      );
      current.nativeOptions = {
        ...options.nativeOptions,
        env: state.env,
        build: `${build.major}.${build.minor}.${build.build}`,
      };
      await save(recipe.id, {
        phase: "reader-admitted",
        helper: current.admission.helper,
        verifier: current.admission.verifier,
        planSha256: current.admission.planSha256,
      });
      current.resources = await primitive("bindResources", current, { signal });
      state.guard(signal);
      current.effectiveOptions = {
        binding,
        provisioning: provisioned.provisioning,
        arguments: args,
        coverage: (...values) => primitive("coverage", current, ...values),
        control: (...values) => primitive("outsideControl", current, ...values),
        retirement: (...values) =>
          primitive("readRetirement", current, ...values),
      };
      current.readers = (
        options.createReaders ?? createWindowsEffectiveReaders
      )(
        current.reader,
        binding.context,
        current.admission.verifier,
        current.effectiveOptions,
      );
      current.owners = {
        launch: (effects) => {
          state.guard(signal);
          return admitWindowsLaunch(
            launch,
            args,
            binding,
            effects,
            current.nativeOptions,
          );
        },
        policy: (effects, operation = {}) => {
          state.guard(
            operation.operation === "remove" ? current.cleanupSignal : signal,
          );
          return configureWindowsPolicy(current.input, binding, effects, {
            ...current.nativeOptions,
            ...operation,
            provisioning: current.provisioned.provisioning,
            argumentsList: args,
          });
        },
        retire: (effects) =>
          retireWindowsDomain(
            current.input.request ?? current.input,
            windowsLaunchDigest(current.input.request ?? current.input, args),
            effects,
            current.nativeOptions,
          ),
        file: (value) => {
          state.guard(signal);
          return current.reader.openFile(value, current.resources.transfer);
        },
        policyTransport: (value, operation) => {
          state.guard(
            operation.startsWith("remove") ? current.cleanupSignal : signal,
          );
          return current.reader.openPolicy(
            value,
            operation,
            current.resources.policyHandles,
          );
        },
        git: (value) => {
          state.guard(signal);
          return current.reader.openGit(value, current.resources.gitHandles);
        },
        gitPolicy: (value, operation) => {
          state.guard(operation === "remove" ? current.cleanupSignal : signal);
          return current.reader.openGitPolicy(
            value,
            operation,
            current.resources.gitPolicyHandles,
          );
        },
        barrier: (index, name) => {
          state.guard(signal);
          return current.readers.barrier(index, name);
        },
        audit: (declaration) => {
          state.guard(signal);
          return installAudit(current, declaration);
        },
      };
      if (current.resources.audit)
        await installAudit(current, current.resources.audit);
      if (
        recipe.group === "ownership" &&
        !Object.hasOwn(options, "ownerEffects")
      ) {
        const owner = createWindowsCaseEffects(state, current, save);
        await owner.prepare();
        const prepared = {
          input: owner.request,
          effects: owner,
          nativeOptions: current.nativeOptions,
          independent: true,
          reviewSha256: recipe.reviewSha256,
          templateSha256: binding.approval.manifestSha256,
          policySha256: owner.request.bindings.policy,
          ...(literal
            ? { admitLiteral: () => owner.admitLiteral(recordPolicy) }
            : {}),
        };
        // The approved plan permits installation at C. A receipt is required
        // after independent installation and again at the parked R barrier.
        if (!literal) {
          const admit = owner.admit;
          prepared.effects = {
            ...owner,
            async admit(...args) {
              const result = await admit(...args);
              await recordPolicy(owner.policyProof);
              return result;
            },
          };
        }
        current.caseEffectsPossible = true;
        current.prepared = prepared;
        current.effects = prepared.effects;
        return prepared;
      }
      functions(options, ["ownerEffects"]);
      current.caseEffectsPossible = true;
      const raw = await primitive("ownerEffects", current, { signal });
      functions(raw, [...ownerNames(recipe), "persist"]);
      const persist = async (record) => {
        await save(recipe.id, {
          phase: "owner-persist-possible",
          recordSha256: observationDigest(record),
          record,
        });
        const receipt = await raw.persist(record);
        await save(recipe.id, {
          phase: "owner-persisted",
          recordSha256: observationDigest(record),
          receiptSha256: receipt ? observationDigest(receipt) : null,
        });
        if (record.status === "RUNNING") state.guard(signal);
        return receipt;
      };
      const effects = { ...raw, persist },
        cleanup = new Set([
          "retire",
          "recoverAndRetire",
          "verify",
          "verifyRetirement",
          "verifyClosed",
          "closeHeld",
          "finishReader",
          "finishPublishers",
          "restoreControl",
        ]);
      for (const name of ownerNames(recipe))
        effects[name] = async (...values) => {
          if (!cleanup.has(name)) state.guard(signal);
          const result = await raw[name](...values);
          if (name === "retire") current.payloadRetirement = result;
          if (!cleanup.has(name)) state.guard(signal);
          return result;
        };
      const launchEffects = literal ? effects : raw.launchEffects;
      if (launchEffects) {
        functions(launchEffects, ownerNames({ id: "ownership.literal" }));
        const processes = new Map();
        current.launchEffects = {
          ...launchEffects,
          persist: literal
            ? persist
            : async (record) => {
                await save(recipe.id, {
                  phase: "launch-persist-possible",
                  recordSha256: observationDigest(record),
                  record,
                });
                const result = await launchEffects.persist(record);
                if (record.status === "RUNNING") state.guard(signal);
                return result;
              },
          inspect: async (request, subjects) => {
            state.guard(signal);
            const observed = await launchEffects.inspect(request, subjects);
            for (const identity of [
              subjects.helper,
              subjects.payload,
              ...subjects.helpers.map((entry) => entry.identity),
            ].filter(Boolean)) {
              const key = observationDigest(identity);
              if (!processes.has(key))
                processes.set(
                  key,
                  (await current.reader.retainProcess(identity)).slot,
                );
              requireObservation(
                sameWindowsIdentity(
                  (await current.reader.process(processes.get(key))).identity,
                  identity,
                ),
              );
            }
            requireObservation(
              sameWindowsIdentity(
                await current.reader.verifier(current.admission.verifier),
                current.admission.verifier,
              ),
            );
            state.guard(signal);
            return observed;
          },
          readProvisioning: async (...values) => {
            state.guard(signal);
            const actual = await launchEffects.readProvisioning(...values);
            // The account SID is created by the parked launcher, never selected
            // from an expected manifest. Both later barriers use these readings.
            materializeNativePolicyBinding(binding, actual, values[0], args);
            current.provisioned.provisioning = structuredClone(actual);
            current.effectiveOptions.provisioning =
              current.provisioned.provisioning;
            state.guard(signal);
            return actual;
          },
          readPolicy: async (request, record) => {
            state.guard(signal);
            requireObservation(
              same(record.provisioning, current.provisioned.provisioning),
            );
            const observed = await launchEffects.readPolicy(request, record);
            verifyNativePolicy(
              binding.template,
              binding.approval,
              record.provisioning,
              binding.context,
              record.requestSha256,
              observed,
            );
            current.input = structuredClone(record.policyInput);
            current.input.request = structuredClone(request);
            state.guard(signal);
            return observed;
          },
        };
      }
      let proof;
      if (!literal) {
        proof = await primitive("readPolicy", current, expected, {
          phase: "prepared",
          signal,
        });
        verifyNativePolicy(
          binding.template,
          binding.approval,
          proof.provisioning,
          binding.context,
          proof.requestSha256,
          proof.observed,
        );
        requireObservation(
          same(proof.provisioning, provisioned.provisioning) &&
            (recipe.group === "release"
              ? hash(proof.requestSha256)
              : proof.requestSha256 === windowsLaunchDigest(launch, args)),
        );
        await recordPolicy(proof);
        state.guard(signal);
        current.policyProof = proof;
      }
      if (recipe.id.startsWith("access.") && current.resources.policyTransfer) {
        effects.snapshot = (value, admission) => {
          const transfer = current.resources.policyTransfer;
          return current.payloadRetirement
            ? current.readers.retiredPolicySnapshot(
                value,
                transfer,
                current.resources.jobs,
              )
            : current.readers.policySnapshot(value, transfer);
        };
      }
      if (recipe.id === "git.fixed" && current.resources.gitSlots)
        effects.snapshot = async (value) => {
          state.guard(signal);
          const before = await current.readers.gitSnapshot(
            value,
            current.resources.gitSlots.metadata,
            current.resources.gitSlots.workspace,
          );
          const observed = await raw.snapshot(value);
          const after = await current.readers.gitSnapshot(
            value,
            current.resources.gitSlots.metadata,
            current.resources.gitSlots.workspace,
          );
          requireObservation(
            same(before, after) &&
              Object.keys(before).every((key) =>
                same(before[key], observed?.[key]),
              ) &&
              typeof observed.status === "string" &&
              Buffer.byteLength(observed.status) <= 65536,
          );
          state.guard(signal);
          return structuredClone(observed);
        };
      if (
        recipe.group === "files" &&
        raw.fileOwners &&
        current.resources.transfer
      ) {
        functions(raw.fileOwners, [
          "review",
          "admit",
          "verify",
          "barrier",
          "retire",
          "persist",
          "readRecovery",
          "verifyRetirement",
        ]);
        effects.fileEffects = async () => ({
          ...raw.fileOwners,
          open: current.owners.file,
          persist: async (record) => {
            await save(recipe.id, {
              phase: "file-persist-possible",
              recordSha256: observationDigest(record),
              record,
            });
            return raw.fileOwners.persist(record);
          },
        });
      }
      current.effects = effects;
      const prepared = {
        input: current.input,
        effects: literal ? current.launchEffects : effects,
        nativeOptions: current.nativeOptions,
        independent: true,
        reviewSha256: recipe.reviewSha256,
        templateSha256: binding.approval.manifestSha256,
        policySha256:
          policy?.compositionSha256 ?? expected?.expectedPolicySha256 ?? null,
        ...(proof ? { policyProof: proof } : {}),
      };
      current.prepared = prepared;
      return prepared;
    },
    async literal(prepared, { signal } = {}) {
      const current = [...active.values()].find(
        (entry) => entry.prepared === prepared && !entry.retired,
      );
      requireObservation(
        current && prepared.admitted?.record.status === "ADMITTED",
      );
      state.guard(current.signal);
      state.guard(signal);
      return current.ownership
        ? current.ownership.literal(prepared.admitted)
        : primitive("literal", current, prepared.admitted, { signal });
    },
    persistReceipt(id, sha256) {
      requireObservation(hash(sha256));
      return save(id, { phase: "owner-receipt", sha256 });
    },
    async settle(recipe, prepared, { signal, execution } = {}) {
      requireObservation(execution?.id === recipe.id);
      let result;
      if (recipe.id === "build") {
        const bootstrap = state.hasBootstrap()
          ? await state.settleBootstrap()
          : null;
        try {
          state.guard(signal);
          requireObservation(
            buildVerified &&
              retired(buildSettlement) &&
              (bootstrap == null || retired(bootstrap)),
          );
          const custody = buildCustody ?? (await options.settleFiles?.());
          requireObservation(
            custody == null ||
              (retired(custody) &&
                custody.noLiveMembers === true &&
                custody.taskRemoved === true),
          );
          state.guard(signal);
          buildCustody = custody ?? null;
          result = {
            ...buildSettlement,
            nativeEventSha256: observationDigest({
              settled: buildSettlement,
              bootstrap,
              custody: custody ?? null,
            }),
          };
        } catch {
          result = retained();
        }
      } else {
        const current = active.get(recipe.id);
        requireObservation(
          !current || !prepared || current.prepared === prepared,
        );
        try {
          result = current
            ? current.repositoryProvisioning && !current.caseEffectsPossible
              ? await provisioning.retire(current, { signal })
              : await finish(current, { signal })
            : retained();
        } catch {
          result = retained();
        }
      }
      const settlement = {
        status: result.status,
        independent: result.independent,
        emergencyCleanup: result.emergencyCleanup,
      };
      return Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((effectClass) => {
          const admission = execution.effects[effectClass]?.admission;
          requireObservation(["possible", "not-started"].includes(admission));
          return [
            effectClass,
            admission === "not-started"
              ? null
              : {
                  candidateSha: state.job.candidateSha,
                  executionId: recipe.id,
                  effectClass,
                  settlement,
                  sha256: observationDigest({
                    candidateSha: state.job.candidateSha,
                    executionId: recipe.id,
                    effectClass,
                    nativeEventSha256: result.nativeEventSha256 ?? null,
                    settlement,
                  }),
                },
          ];
        }),
      );
    },
    async recover({ request, job, preparation, signal }) {
      requireObservation(
        request.candidateSha === state.job.candidateSha &&
          request.platform === "win32" &&
          request.jobSha256 === observationDigest(job) &&
          request.preparationSha256 === observationDigest(preparation),
      );
      try {
        state.guard(signal);
        if (!Object.hasOwn(options, "recover"))
          await options.beginCleanup?.(signal);
        await state.protectDirectory();
        const entries = await state.fs.readdir(state.directory);
        requireObservation(entries.length <= 65536);
        const names = entries
            .filter((name) =>
              /^windows-(?:files-[a-f0-9]{32}-(?:intent|birth|result|[0-9]+)|bootstrap-[0-9]+-(?:intent|result|custody-[0-9]+)|command-[a-f0-9]{64}(?:-intent|-result|-[0-9]+)|case-[a-z0-9.-]+-[0-9]+|recovery-[a-f0-9]{64}-[0-9]+-(?:intent|result))\.json$/u.test(
                name,
              ),
            )
            .sort(),
          records = [];
        let total = 0;
        for (const name of names) {
          const bytes = await state.receipt(path.join(state.directory, name));
          total += bytes.length;
          requireObservation(total <= 67108864);
          records.push({
            name,
            record: JSON.parse(bytes),
          });
        }
        // Uses sealed bootstrap assets and complete protected intent ledgers,
        // never verifyBuild or successful/remaining final preparation outputs.
        const sequence =
          1 +
          Math.max(
            -1,
            ...entries.map((name) =>
              Number(
                /^windows-recovery-[a-f0-9]{64}-([0-9]+)-intent\.json$/u.exec(
                  name,
                )?.[1] ?? -1,
              ),
            ),
          );
        requireObservation(Number.isSafeInteger(sequence) && sequence <= 65535);
        const prefix = `windows-recovery-${observationDigest(request)}-${sequence}`;
        await state.write(`${prefix}-intent.json`, {
          request,
          status: "POSSIBLE",
        });
        const reader = Object.hasOwn(options, "recover")
          ? (await state.bootstrap(signal)).reader
          : null;
        const result = await primitive(
          "recover",
          { request, job, preparation, records, plan: state.plan, reader },
          { signal },
        );
        requireObservation(
          retired(result) &&
            result.recordsSha256 === observationDigest(records) &&
            result.noLiveMembers === true &&
            result.tasksRemoved === true &&
            NATIVE_EFFECT_CLASSES.every((effect) =>
              retired(result.effects?.[effect]),
            ),
        );
        const bootstrap = state.hasBootstrap()
          ? await state.releaseBootstrap()
          : null;
        state.guard(signal);
        await state.write(`${prefix}-result.json`, {
          requestSha256: observationDigest(request),
          result,
          bootstrap,
        });
        const custody = await options.settleFiles?.();
        requireObservation(
          custody == null ||
            (retired(custody) &&
              custody.noLiveMembers === true &&
              custody.taskRemoved === true),
        );
        state.guard(signal);
        return {
          requestSha256: observationDigest(request),
          nativeEventSha256: observationDigest({
            result,
            bootstrap,
            custody: custody ?? null,
          }),
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
        };
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
