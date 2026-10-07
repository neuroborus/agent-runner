import path from "node:path";
import {
  observationDigest,
  observationObject,
  preparedNativeCommands,
  requireObservation,
  normalizeNativePolicyBinding,
  materializeNativePolicy,
  verifyNativePolicy,
  materializeNativePolicyBinding,
  assertNativePolicyParameters,
  NATIVE_EFFECT_CLASSES,
} from "../index.js";
import {
  digest,
  darwinLaunchDigest,
  DARWIN_LITERAL_ARGUMENTS,
  sameDarwinIdentity,
  inspectDarwinMachO,
} from "./protocol.js";
import { darwinPreparationContext, recoverDarwinBuild } from "./preparation.js";
import { createDarwinCaseProvisioning } from "./case-provisioning.js";
import { createDarwinCaseEffects } from "./case-effects.js";
import { createDarwinAccessEffects } from "./access-effects.js";
import { createDarwinEffectiveReaders } from "./effective.js";
import { createDarwinAuditDecoder } from "./audit.js";
import { createDarwinPfPreparation } from "./pf-preparation.js";
import { darwinSystemRecipes } from "./system.js";
import { DARWIN_HELPER_NAMES, darwinBuildOperation } from "./build.js";
import { admitDarwinLaunch } from "./launch.js";
import { retireDarwinDomain } from "./retirement.js";
import { configureDarwinPolicy } from "./policy-effects.js";
import { buildDarwinPolicy } from "./policy.js";
import { openDarwinGitExecutor } from "./git.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;
const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
const requireFunctions = (value, names) =>
  names.forEach((name) =>
    requireObservation(typeof value?.[name] === "function"),
  );

// These are the existing native owners' finite effect contracts, not a second
// recipe language. Observations still pass each owner's full native assertions.
const ownerNames = (recipe) => {
  if (["ownership.literal", "ownership.storage"].includes(recipe.id))
    return [
      "verifyInputs",
      "verifyAuthority",
      "verifyReceipt",
      "retire",
      "readProvisioning",
      "readPolicy",
    ];
  if (recipe.id.startsWith("ownership."))
    return [
      "admit",
      "observe",
      "armFault",
      "fireFault",
      "recoverAndRetire",
      "verify",
    ];
  if (recipe.id.startsWith("access."))
    return ["prepare", "verifyPolicy", "admit", "observe", "retire", "restore"];
  if (recipe.id === "git.fixed")
    return ["snapshot", "review", "open", "observe", "retire"];
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
  if (recipe.id === "files.aliases") names.push("nameControl");
  return names;
};

/** Construction has no effects. Build joins use repository custody defaults;
 * case setup and compiler policy reads use the sealed native owner. Expected
 * manifests never become observed evidence. */
export function createDarwinSystemEffects(input, options = {}) {
  const state = darwinPreparationContext(input, options),
    active = new Map(),
    provisioning = createDarwinCaseProvisioning(state, options),
    historicalRead =
      state.manifest.schemaVersion === 1 && typeof options.read === "function";
  const primitive = (name, ...args) => {
    requireFunctions(options, [name]);
    return options[name](...args);
  };
  const buildRecords = async () => {
    const entries = await state.fs.readdir(state.directory);
    requireObservation(entries.length <= 65536);
    const names = entries
      .filter((name) =>
        /^darwin-(?:bootstrap-[0-9]+-(?:intent|result|custody-[0-9]+)|command-[a-f0-9]{64}(?:-intent|-directory|-result|-[0-9]+)|case-[a-z0-9.-]+-[0-9]+)\.json$/u.test(
          name,
        ),
      )
      .sort();
    const records = [];
    let total = 0;
    for (const name of names) {
      const bytes = await state.receipt(path.join(state.directory, name));
      total += bytes.length;
      requireObservation(total <= 67108864);
      records.push({ name, record: JSON.parse(bytes) });
    }
    return records;
  };
  const verifyBuild = async (
    preparation,
    { signal, policyBinding, recordPolicy, verificationPending = false } = {},
  ) => {
    try {
      const binding =
        policyBinding && normalizeNativePolicyBinding(policyBinding);
      if (binding)
        requireObservation(
          typeof recordPolicy === "function" &&
            observationDigest(binding.context) ===
              observationDigest(state.plan.bootstrap.context),
        );
      const nativeCommands = preparedNativeCommands(
        preparation,
        state.manifest,
        2 + DARWIN_HELPER_NAMES.length * 2,
        { verificationPending },
      );
      requireObservation(
        preparation.status === "PASS" &&
          preparation.candidateSha === state.job.candidateSha &&
          preparation.platform === "darwin" &&
          preparation.reviewSha256 === observationDigest(state.manifest) &&
          preparation.versions.length === state.manifest.tools.length &&
          state.manifest.tools.every(
            (tool) =>
              preparation.versions.filter(
                (entry) =>
                  entry.name === tool.name &&
                  entry.version === tool.version &&
                  entry.sha256 === tool.sha256,
              ).length === 1,
          ) &&
          preparation.helpers.length === DARWIN_HELPER_NAMES.length &&
          nativeCommands.length === 2 + DARWIN_HELPER_NAMES.length * 2,
      );
      // Snapshot prior custody before starting this verification's own reader.
      const prior = options.read ? null : await buildRecords();
      const { reader } = await state.bootstrap(signal),
        reads = [];
      let directoryIdentity;
      for (const tool of state.manifest.tools) {
        const bytes = await state.read(tool.path, tool.sha256);
        requireObservation(digest(bytes) === tool.sha256);
        reads.push({ name: tool.name, sha256: tool.sha256 });
      }
      for (const name of DARWIN_HELPER_NAMES) {
        const pin = state.manifest.helpers.find((entry) => entry.name === name);
        requireObservation(
          preparation.helpers.filter(
            (entry) => entry.name === name && entry.sha256 === pin?.sha256,
          ).length === 1,
        );
        const file = path.join(state.output, name),
          actual = options.read
            ? { bytes: await options.read(file, pin.sha256) }
            : await reader.readBuildImage(file, pin.sha256),
          bytes = actual.bytes;
        if (!options.read) {
          requireObservation(
            !directoryIdentity || directoryIdentity === actual.rootIdentity,
          );
          directoryIdentity = actual.rootIdentity;
        }
        (options.inspectImage ?? inspectDarwinMachO)(bytes);
        reads.push({
          name,
          sha256: digest(bytes),
          identity: actual.identity ?? null,
        });
        requireObservation(reads.at(-1).sha256 === pin.sha256);
      }
      const commands = [];
      for (const entry of nativeCommands) {
        requireObservation(entry.status === "RETIRED");
        const intent = JSON.parse(
          await state.receipt(
            path.join(
              state.directory,
              `darwin-command-${entry.requestSha256}-intent.json`,
            ),
          ),
        );
        const operation = darwinBuildOperation(
          intent.request,
          state.manifest,
          state.output,
        );
        observationObject(intent, [
          "candidateSha",
          "request",
          "requestSha256",
          "status",
          ...(Object.hasOwn(intent, "targetSha256") ? ["targetSha256"] : []),
        ]);
        if (Object.hasOwn(intent, "targetSha256"))
          requireObservation(
            operation.mode === "sign"
              ? hash(intent.targetSha256)
              : intent.targetSha256 === null,
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
              `darwin-command-${entry.requestSha256}-result.json`,
            ),
          ),
        );
        requireObservation(
          (!directoryIdentity ||
            observed.directoryIdentity === directoryIdentity) &&
            observed.requestSha256 === entry.requestSha256 &&
            observationDigest(observed) === entry.receiptSha256 &&
            observed.independent === true &&
            observed.exitCode === 0 &&
            observed.signal === null &&
            observed.timedOut === false &&
            observed.toolSha256 === operation.tool.sha256 &&
            hash(observed.nativeEventSha256) &&
            retired(observed.settlement) &&
            observed.bootstrapSettlement?.status === "RETIRED" &&
            observed.bootstrapSettlement.independent === true &&
            observed.bootstrapSettlement.closed === true,
        );
        commands.push({
          ...observed,
          operation: operation.mode,
          target: operation.target ?? null,
        });
      }
      // A fresh kernel reader, not receipt booleans or child exit, rejoins each
      // command's parked worker and helper even during later probe/recovery turns.
      requireObservation(
        new Set(nativeCommands.map((entry) => entry.requestSha256)).size ===
          commands.length &&
          ["compiler-version", "sdk-version"].every(
            (mode) =>
              commands.filter((entry) => entry.operation === mode).length === 1,
          ) &&
          DARWIN_HELPER_NAMES.every((name) =>
            ["compile", "sign"].every(
              (mode) =>
                commands.filter(
                  (entry) =>
                    entry.operation === mode &&
                    entry.target === path.join(state.output, name),
                ).length === 1,
            ),
          ),
      );
      const settled = await (
        options.verifyCommands ??
        (async (entries, fresh) => {
          const reads = [];
          for (const entry of entries) {
            const identities = [entry.identity, entry.helperIdentity];
            // Historical injected reference proofs predate bootstrap birth and
            // audit-domain receipts. Repository defaults require the full join.
            if (!historicalRead)
              identities.push(
                entry.bootstrapSettlement.helper,
                entry.bootstrapSettlement.verifier,
              );
            for (const identity of identities) {
              const observed = await fresh.retired(identity);
              requireObservation(
                retired(observed) && hash(observed.nativeEventSha256),
              );
              reads.push(observed);
            }
            if (!historicalRead) {
              const domain = await fresh.retiredRootDomain(
                entry.helperIdentity,
              );
              requireObservation(
                domain.independent === true &&
                  domain.complete === true &&
                  domain.members.length === 0,
              );
              reads.push(domain);
            }
          }
          // Intermediate verifier children have their own creation records;
          // completed command receipts alone cannot rejoin their retirement.
          if (prior)
            reads.push(
              await recoverDarwinBuild(
                state,
                prior.filter(({ name }) => !name.startsWith("darwin-case-")),
                signal,
                fresh,
              ),
            );
          return {
            status: "RETIRED",
            independent: true,
            emergencyCleanup: false,
            nativeEventSha256: observationDigest(reads),
          };
        })
      )(commands, reader, { signal });
      requireObservation(retired(settled) && hash(settled.nativeEventSha256));
      const buildPolicy =
        binding && !options.observeBuildPolicy
          ? await provisioning.observeBuildPolicy(
              binding,
              { commands, reader, settlement: settled },
              { signal },
            )
          : null;
      const bootstrapSettlement = await state.releaseBootstrap();
      state.guard(signal);
      const result = {
        status: "OBSERVED",
        independent: true,
        candidateSha: state.job.candidateSha,
        preparationSha256: observationDigest(preparation),
        nativeEventSha256: observationDigest({
          reads,
          settled,
          bootstrapSettlement,
        }),
        settlement: settled,
      };
      if (binding) {
        const proof =
          buildPolicy ??
          (await primitive("observeBuildPolicy", binding, result, { signal }));
        verifyNativePolicy(
          binding.template,
          binding.approval,
          proof.provisioning,
          binding.context,
          proof.requestSha256,
          proof.observed,
        );
        await recordPolicy(proof);
      }
      return result;
    } catch (cause) {
      throw state.fail(cause);
    }
  };
  const save = (id, record) => {
    const current = active.get(id);
    requireObservation(current);
    return state.write(`darwin-case-${id}-${current.sequence++}.json`, record);
  };
  const finish = async (current, { signal } = {}) => {
    // Stop/retire the full payload domain before audit custody can be drained,
    // released, or any owned policy setup can be restored. No speculative close.
    requireObservation(signal instanceof AbortSignal && !signal.aborted);
    await save(current.recipe.id, { phase: "cleanup-possible" });
    current.cleanupSignal = signal;
    await current.reader.beginCleanup({ signal });
    state.guard(signal);
    const result = await primitive("retire", current, { signal });
    state.guard(signal);
    requireObservation(retired(result) && hash(result.nativeEventSha256));
    requireObservation(
      (await primitive("verifyRetirement", current, result, { signal })) ===
        true,
    );
    state.guard(signal);
    await save(current.recipe.id, {
      phase: "payload-retired",
      settlement: result,
    });
    const audit = await primitive("releaseAudit", current, result, { signal });
    state.guard(signal);
    requireObservation(retired(audit) && hash(audit.nativeEventSha256));
    // Case policy owns only its anchor. Remove it before the separately owned
    // host setup verifies an unchanged root and empty subordinate anchors.
    const restored = await primitive("restore", current, result, { signal });
    state.guard(signal);
    requireObservation(
      restored?.status === "RESTORED" &&
        restored.independent === true &&
        hash(restored.nativeEventSha256),
    );
    let pf = null;
    if (current.pf) {
      pf = await current.pf.restore(result);
      requireObservation(
        restored.reservation?.pfBaselineSha256 ===
          current.provisioned.pfPreparation.approval.baselineSha256,
      );
      await current.reader.releaseReservation(restored.reservation);
      await save(current.recipe.id, { phase: "pf-reservation-released" });
    }
    const custody = await current.reader.close();
    requireObservation(
      custody.status === "RETIRED" &&
        custody.independent === true &&
        custody.closed === true,
    );
    const settled = {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
      nativeEventSha256: observationDigest({
        result,
        audit,
        restored,
        pf,
        custody,
      }),
    };
    await save(current.recipe.id, { phase: "retired", settlement: settled });
    current.retired = true;
    return settled;
  };
  const provision = async (
    recipe,
    { signal, policyBinding, recordPolicy } = {},
  ) => {
    try {
      const fixed = darwinSystemRecipes().find(
          (entry) => entry.id === recipe.id,
        ),
        binding = normalizeNativePolicyBinding(policyBinding);
      requireObservation(
        fixed &&
          fixed.id !== "build" &&
          ["group", "profile", "deadlineMs"].every(
            (key) => fixed[key] === recipe[key],
          ) &&
          observationDigest(fixed.checkIds) ===
            observationDigest(recipe.checkIds) &&
          !active.has(recipe.id) &&
          typeof recordPolicy === "function" &&
          binding.context.candidateSha === state.job.candidateSha &&
          binding.context.platform === "darwin" &&
          binding.context.executionId === recipe.id,
      );
      await verifyBuild(state.preparation, { signal });
      const declared = state.plan.cases.find((entry) => entry.id === recipe.id);
      requireObservation(
        observationDigest(declared.custody.context) ===
          observationDigest(binding.context),
      );
      const current = {
        recipe: structuredClone(recipe),
        binding,
        declared,
        sequence: 0,
        retired: false,
        signal,
      };
      active.set(recipe.id, current);
      current.intentPin = await save(recipe.id, {
        phase: "provisioning-possible",
        context: binding.context,
        templateSha256: binding.approval.manifestSha256,
        bindingsSha256: observationDigest(declared.bindings),
        planSha256: declared.custody.plan.sha256,
        status: "POSSIBLE",
      });
      state.guard(signal);
      const provisioned = options.provision
        ? await primitive("provision", structuredClone(declared), binding, {
            signal,
          })
        : await provisioning.provision(structuredClone(declared), binding, {
            signal,
            current,
            persist: (record) => save(recipe.id, record),
          });
      current.provisioned = provisioned;
      return current;
    } catch (cause) {
      throw state.fail(cause);
    }
  };
  return {
    bootstrap: state.bootstrap,
    verifyBuild,
    async provision(recipe, operation) {
      return (await provision(recipe, operation)).provisioned;
    },
    async build({
      candidateSha,
      reviewSha256,
      signal,
      policyBinding,
      recordPolicy,
    }) {
      requireObservation(
        candidateSha === state.job.candidateSha &&
          (historicalRead ||
            (policyBinding && typeof recordPolicy === "function")),
      );
      const result = await verifyBuild(state.preparation, {
        signal,
        policyBinding,
        recordPolicy,
      });
      return { ...result, reviewSha256 };
    },
    async prepare(recipe, { signal, policyBinding, recordPolicy } = {}) {
      const current = await provision(recipe, {
          signal,
          policyBinding,
          recordPolicy,
        }),
        { binding, declared, provisioned } = current;
      const expected = materializeNativePolicy(
        binding.template,
        binding.approval,
        provisioned.provisioning,
        binding.context,
      );
      // Validate the concrete request and policy parameters before dependent
      // custody or PF setup. The complete template and native composition have
      // distinct digests; neither generated digest supplies approval.
      current.input = structuredClone(provisioned.input);
      const launch = current.input.request ?? current.input;
      requireObservation(
        launch.candidateSha === state.job.candidateSha &&
          (recipe.group === "release" ||
            launch.bindings?.closure === binding.context.closureSha256),
      );
      const argumentsList = provisioned.arguments ?? DARWIN_LITERAL_ARGUMENTS;
      if (recipe.group !== "release")
        materializeNativePolicyBinding(
          binding,
          provisioned.provisioning,
          launch,
          argumentsList,
        );
      if (!options.ownerEffects && recipe.group === "ownership") {
        current.caseOwner = createDarwinCaseEffects(state, current, save);
        const proof = await current.caseOwner.prepare();
        await recordPolicy(proof);
        const prepared = {
          input: current.input,
          effects: current.caseOwner.effects,
          independent: true,
          reviewSha256: recipe.reviewSha256,
          templateSha256: binding.approval.manifestSha256,
          policySha256: proof.observed.policySha256,
          policyProof: proof,
          admit: () => current.caseOwner.admitLiteral(),
        };
        current.prepared = prepared;
        return prepared;
      }
      if (!options.ownerEffects && recipe.id.startsWith("access.")) {
        requireObservation(provisioned.access);
        current.caseOwner = createDarwinAccessEffects(state, current, save);
        const proof = await current.caseOwner.prepare();
        await recordPolicy(proof);
        const prepared = {
          input: current.input,
          effects: current.caseOwner.effects,
          independent: true,
          reviewSha256: recipe.reviewSha256,
          templateSha256: binding.approval.manifestSha256,
          policySha256: proof.observed.policySha256,
          policyProof: proof,
        };
        current.prepared = prepared;
        return prepared;
      }
      const policy = recipe.id.startsWith("access.")
        ? buildDarwinPolicy(current.input)
        : null;
      if (policy) {
        assertNativePolicyParameters(
          binding,
          provisioned.provisioning,
          policy.value,
          argumentsList,
        );
        requireObservation(
          launch.policy.sha256 === policy.seatbeltSha256 &&
            launch.bindings.policy === policy.compositionSha256,
        );
      }
      current.reader ??= state.createReader(declared.custody, {
        ...options.readerOptions,
        persist: (record) => save(recipe.id, { phase: "custody", record }),
      });
      const admission =
        current.admission ?? (await current.reader.start({ signal }));
      requireObservation(
        admission.independent === true &&
          admission.planSha256 === declared.custody.plan.sha256,
      );
      await save(recipe.id, {
        phase: "reader-admitted",
        helper: admission.helper,
        planSha256: admission.planSha256,
      });
      current.readers = (options.createReaders ?? createDarwinEffectiveReaders)(
        current.reader,
        binding.context,
        admission.helper,
      );
      if (provisioned.auditMapping)
        current.audit = createDarwinAuditDecoder(
          current.reader,
          provisioned.auditMapping,
        );
      if (provisioned.pfPreparation) {
        requireObservation(
          observationDigest(provisioned.pfPreparation.context) ===
            observationDigest(binding.context),
        );
        current.pf = createDarwinPfPreparation(provisioned.pfPreparation, {
          review: (approval) => primitive("reviewPf", approval, current),
          read: () => current.reader.pf(),
          reserve: (...args) => current.reader.reserve(...args),
          write: (...args) => current.reader.writePf(...args),
          reservation: () => current.reader.reservation(),
          persist: (record) => save(recipe.id, record),
          verifyRetirement: (result) =>
            primitive("verifyRetirement", current, result, {
              signal: current.cleanupSignal,
            }),
        });
        for (const index of [
          provisioned.pfPreparation.tool.index,
          provisioned.pfPreparation.install,
          provisioned.pfPreparation.restore,
          provisioned.pfPreparation.reservation,
        ])
          await current.reader.open(index);
        current.caseEffectsPossible = true;
        await current.pf.prepare();
      }
      // Native hooks compose these already bounded owners; they cannot select a
      // new recipe or replace their identity, policy or retirement assertions.
      current.owners = {
        launch: (effects) => {
          state.guard(signal);
          return admitDarwinLaunch(launch, argumentsList, binding, effects);
        },
        policy: (effects, operation = {}) => {
          state.guard(
            operation.operation === "restore"
              ? (current.cleanupSignal ?? signal)
              : signal,
          );
          return configureDarwinPolicy(current.input, binding, effects, {
            ...operation,
            provisioning: provisioned.provisioning,
            argumentsList,
          });
        },
        retire: (effects) =>
          retireDarwinDomain(
            launch,
            darwinLaunchDigest(launch, argumentsList),
            effects,
          ),
        file: (value) => {
          state.guard(signal);
          return current.reader.openFile(value, provisioned.transfer);
        },
        git: (value, request, effects) => {
          state.guard(signal);
          return openDarwinGitExecutor(value, request, effects);
        },
      };
      if (options.ownerEffects) current.caseEffectsPossible = true;
      const raw = await primitive("ownerEffects", current, { signal });
      const literal = ["ownership.literal", "ownership.storage"].includes(
        recipe.id,
      );
      const launchEffects = literal ? raw : raw.launchEffects;
      requireFunctions(raw, [...ownerNames(recipe), "persist"]);
      const persist = async (record) => {
        const recordSha256 = observationDigest(record);
        await save(recipe.id, {
          phase: "owner-persist-possible",
          recordSha256,
        });
        const receipt = await raw.persist(record);
        await save(recipe.id, {
          phase: "owner-persisted",
          recordSha256,
          receiptSha256: receipt ? observationDigest(receipt) : null,
        });
        return receipt;
      };
      const effects = { ...raw, persist };
      const cleanup = new Set([
        "retire",
        "restore",
        "recoverAndRetire",
        "verifyRetirement",
        "verify",
        "verifyClosed",
        "closeHeld",
        "finishReader",
        "finishPublishers",
        "restoreControl",
      ]);
      for (const name of ownerNames(recipe))
        effects[name] = (...args) => {
          if (!cleanup.has(name)) state.guard(signal);
          return raw[name](...args);
        };
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
          observationDigest(proof.provisioning) ===
            observationDigest(provisioned.provisioning) &&
            (recipe.group === "release"
              ? hash(proof.requestSha256)
              : proof.requestSha256 ===
                darwinLaunchDigest(launch, argumentsList)),
        );
        await recordPolicy(proof);
        current.policyProof = proof;
      }
      if (launchEffects) {
        requireFunctions(launchEffects, [
          "persist",
          "verifyInputs",
          "verifyAuthority",
          "verifyReceipt",
          "retire",
          "readProvisioning",
          "readPolicy",
        ]);
        current.launchEffects = {
          ...launchEffects,
          inspect: async (request, subjects) => {
            requireObservation(
              darwinLaunchDigest(request, argumentsList) ===
                darwinLaunchDigest(launch, argumentsList),
            );
            const helper = await current.reader.helper(subjects.helper),
              payload = subjects.payload
                ? await current.reader.process(subjects.payload.pid, {
                    retainSession: true,
                  })
                : null,
              verifier = await current.reader.process(admission.helper.pid);
            requireObservation(sameDarwinIdentity(verifier, admission.helper));
            return {
              helper: helper.identity,
              payload,
              verifiers: [verifier],
            };
          },
          persist: literal
            ? persist
            : async (record) => {
                await save(recipe.id, {
                  phase: "launch-persist-possible",
                  recordSha256: observationDigest(record),
                });
                return launchEffects.persist(record);
              },
          readPolicy: async (...args) => {
            const observed = await launchEffects.readPolicy(...args);
            const provisioning = args[1]?.provisioning;
            requireObservation(
              observationDigest(provisioning) ===
                observationDigest(provisioned.provisioning),
            );
            const receipt = verifyNativePolicy(
              binding.template,
              binding.approval,
              provisioning,
              binding.context,
              args[1]?.requestSha256,
              observed,
            );
            requireObservation(
              receipt.expectedPolicySha256 === expected.expectedPolicySha256,
            );
            return observed;
          },
        };
        for (const name of [
          "verifyInputs",
          "verifyAuthority",
          "verifyReceipt",
          "readProvisioning",
          "readPolicy",
          "inspect",
        ]) {
          const read = current.launchEffects[name];
          current.launchEffects[name] = async (...args) => {
            state.guard(signal);
            const observed = await read(...args);
            state.guard(signal);
            return observed;
          };
        }
        const write = current.launchEffects.persist;
        current.launchEffects.persist = async (record) => {
          const receipt = await write(record);
          // Preserve late failure receipts, but never acknowledge a park or
          // release intent after cancellation to an admitting native owner.
          if (record.status === "RUNNING") state.guard(signal);
          return receipt;
        };
      }
      if (recipe.id === "git.fixed" && provisioned.gitSlots) {
        effects.snapshot = (value) => {
          state.guard(signal);
          return current.readers.gitSnapshot(
            value,
            provisioned.gitSlots.metadata,
            provisioned.gitSlots.workspace,
          );
        };
        effects.open = (value, args) => {
          state.guard(signal);
          return openDarwinGitExecutor(value, args, raw.executorEffects);
        };
      }
      if (recipe.group === "files" && raw.fileOwners && provisioned.transfer) {
        effects.fileEffects = async () => {
          state.guard(signal);
          return {
            ...raw.fileOwners,
            open: current.owners.file,
            persist: async (record) => {
              const receipt = await raw.fileOwners.persist(record);
              await save(recipe.id, {
                phase: "file-receipt",
                sha256: observationDigest(receipt),
              });
              return receipt;
            },
          };
        };
      }
      current.effects = effects;
      const prepared = {
        input: current.input,
        effects:
          current.launchEffects && literal ? current.launchEffects : effects,
        independent: true,
        reviewSha256: recipe.reviewSha256,
        templateSha256: binding.approval.manifestSha256,
        policySha256:
          policy?.compositionSha256 ?? expected.expectedPolicySha256,
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
      return current.caseOwner
        ? current.caseOwner.literal(prepared.admitted)
        : primitive("literal", current, prepared.admitted, { signal });
    },
    persistReceipt(id, sha256) {
      requireObservation(hash(sha256));
      return save(id, { phase: "owner-receipt", sha256 });
    },
    async settle(recipe, prepared, { signal, execution } = {}) {
      requireObservation(execution?.id === recipe.id);
      let result;
      if (recipe.id === "build") result = await state.settleBootstrap();
      else {
        const current = active.get(recipe.id);
        requireObservation(
          !current || !prepared || current.prepared === prepared,
        );
        try {
          result =
            current?.repositoryProvisioning && !current.caseEffectsPossible
              ? await provisioning.retire(current, { signal })
              : current?.caseOwner
                ? await current.caseOwner.finish({ signal })
                : current
                  ? await finish(current, { signal })
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
          request.platform === "darwin" &&
          request.jobSha256 === observationDigest(job) &&
          request.preparationSha256 === observationDigest(preparation),
      );
      // A new process reads all immutable intents, including a provision/start
      // which threw before a prepared result or final command receipt existed.
      try {
        const records = await buildRecords();
        const result = options.recover
          ? await primitive(
              "recover",
              { request, job, preparation, records, plan: state.plan },
              { signal },
            )
          : await (async () => {
              const build = await recoverDarwinBuild(
                state,
                records.filter(({ name }) => !name.startsWith("darwin-case-")),
                signal,
              );
              const cases = await provisioning.recover(
                records.filter(({ name }) => name.startsWith("darwin-case-")),
                { signal },
              );
              return {
                ...build,
                nativeEventSha256: observationDigest({ build, cases }),
              };
            })();
        requireObservation(retired(result) && hash(result.nativeEventSha256));
        const observed = {
          ...result,
          requestSha256: observationDigest(request),
        };
        if (options.recover)
          for (const effect of NATIVE_EFFECT_CLASSES)
            requireObservation(retired(result.effects?.[effect]));
        return {
          requestSha256: observed.requestSha256,
          nativeEventSha256: observed.nativeEventSha256,
          status: observed.status,
          independent: observed.independent,
          emergencyCleanup: observed.emergencyCleanup,
        };
      } catch (cause) {
        state.fail(cause);
        return {
          ...retained(),
          requestSha256: observationDigest(request),
          nativeEventSha256: observationDigest({ request, retained: true }),
        };
      }
    },
  };
}
