import { nativeException } from "./diagnostics.js";
import {
  NATIVE_EFFECT_CLASSES,
  NATIVE_GROUPS,
  CHECK_IDS,
  PROVIDER_CHECK_IDS,
} from "./catalog.js";
import { normalizeExperimentJob, recordExperimentCase } from "./experiment.js";
import {
  normalizeExperimentPolicyBinding,
  verifyExperimentPolicy,
} from "./policy-template.js";
import {
  observationDigest,
  observationObject,
  requireObservation,
} from "./observation.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;

/** Private v7 ledger for the two indexed native system owners. Their existing
 * case assertions, fixed inventories and independent retirement remain authoritative. */
export async function runSystemExperimentProofs(
  input,
  directory,
  recipes,
  owner,
  options,
) {
  let job = normalizeExperimentJob(input),
    effects,
    writes = Promise.resolve();
  const {
    persist,
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = options;
  requireObservation(
    ["darwin", "win32"].includes(job.platform) &&
      (options.platform ?? process.platform) === job.platform &&
      (options.architecture ?? process.arch) === "x64" &&
      job.preparation &&
      retired(job.preparationEffects.settlement) &&
      job.failure === null &&
      job.cases.length === 0 &&
      typeof persist === "function",
  );
  requireObservation(
    observationDigest(
      [...new Set(recipes.flatMap(({ checkIds }) => checkIds))].sort(),
    ) ===
      observationDigest(
        CHECK_IDS.filter((id) => !PROVIDER_CHECK_IDS.includes(id)).sort(),
      ),
  );
  const bounded = async (operation, milliseconds, controller, message) => {
    let timer, abort;
    try {
      if (controller.signal.aborted) throw controller.signal.reason;
      return await Promise.race([
        operation,
        new Promise((_, reject) => {
          abort = () => reject(controller.signal.reason);
          controller.signal.addEventListener("abort", abort, { once: true });
          timer = schedule(
            () => controller.abort(new Error(message)),
            milliseconds,
          );
        }),
      ]);
    } finally {
      cancel(timer);
      controller.signal.removeEventListener("abort", abort);
    }
  };
  const save = async (next) => {
    const value = normalizeExperimentJob(next);
    writes = writes.then(() => persist(value));
    await bounded(
      writes,
      30000,
      new AbortController(),
      "Native experiment receipt deadline",
    );
    job = value;
  };
  for (const recipe of recipes) {
    const start = now(),
      controller = new AbortController(),
      { signal } = controller;
    const expectedSha256 = observationDigest({
      preparation: job.preparationEffects.receiptSha256,
      executionId: recipe.id,
    });
    const initial = {
      purpose: "experiment",
      id: recipe.id,
      preparationSha256: observationDigest(job.preparation),
      status: "NOT_RUN",
      elapsedMs: null,
      cleanupMs: null,
      policy: {
        expectedSha256,
        observedSha256: null,
        independent: false,
        effective: false,
      },
      components: null,
      observations: [],
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((key) => [
          key,
          {
            admission: "not-started",
            settlement: retained(),
            receiptSha256: null,
          },
        ]),
      ),
    };
    await save(recordExperimentCase(job, initial));
    const admissions = structuredClone(initial.effects);
    for (const key of new Set([
      "policy",
      ...(recipe.group === "build"
        ? ["builds"]
        : NATIVE_GROUPS[job.platform][recipe.group].effects),
    ]))
      admissions[key].admission = "possible";
    await save(
      recordExperimentCase(job, { ...job.cases.at(-1), effects: admissions }),
    );
    let prepared,
      result,
      policyReceipt,
      primary,
      cleanupCause,
      expired = false,
      pending = false,
      active = true;
    const interrupted = () => controller.abort(options.signal.reason);
    if (options.signal?.aborted) interrupted();
    else options.signal?.addEventListener("abort", interrupted, { once: true });
    const recordPolicy = async (inputBinding, proof) => {
      requireObservation(active && !signal.aborted);
      const binding = normalizeExperimentPolicyBinding(inputBinding),
        context = binding.context;
      requireObservation(
        context.tier === "system" &&
          context.executionId === recipe.id &&
          context.platform === job.platform &&
          context.candidateSha === job.candidateSha &&
          context.runId === job.runId &&
          context.runAttempt === job.runAttempt &&
          context.jobBindingSha256 ===
            observationDigest(job.preparation.expected.binding),
      );
      policyReceipt = verifyExperimentPolicy(
        binding.template,
        proof.provisioning,
        context,
        proof.requestSha256,
        proof.observed,
      );
      await save(
        recordExperimentCase(job, {
          ...job.cases.at(-1),
          policy: {
            expectedSha256,
            observedSha256: expectedSha256,
            independent: policyReceipt.independent,
            effective: hash(policyReceipt.observationSha256),
          },
        }),
      );
      requireObservation(active && !signal.aborted);
    };
    try {
      const operation = Promise.resolve().then(async () => {
        requireObservation(
          !signal.aborted && now() - start < recipe.deadlineMs,
        );
        const loaded = await owner.load(job, directory, { ...options, signal });
        requireObservation(
          active &&
            !signal.aborted &&
            observationDigest(loaded.job) === observationDigest(job),
        );
        // These components come from this load's actual held reads, not stored
        // preparation observations. The v7 validator checks the entire closure.
        await save(
          recordExperimentCase(job, {
            ...job.cases.at(-1),
            components: loaded.runtime,
          }),
        );
        requireObservation(active && !signal.aborted);
        effects ??= owner.createEffects(job, loaded.preparation, options);
        const binding = owner.binding(loaded.preparation, recipe.id),
          policy = {
            policyBinding: binding,
            recordPolicy: (proof) => recordPolicy(binding, proof),
            hasReceipt: () => Boolean(policyReceipt),
          };
        if (recipe.id === "build") {
          const built = await effects.build({
            candidateSha: job.candidateSha,
            signal,
            ...policy,
          });
          requireObservation(
            built?.purpose === "experiment" &&
              built.independent &&
              built.status === "OBSERVED",
          );
          if (!policyReceipt && built.policyProof)
            await policy.recordPolicy(built.policyProof);
          return {
            status: built.status,
            evidenceSha256: observationDigest(built),
          };
        }
        prepared = await effects.prepare(recipe, { signal, ...policy });
        requireObservation(
          active &&
            !signal.aborted &&
            prepared?.purpose === "experiment" &&
            prepared.independent &&
            prepared.templateSha256 === observationDigest(binding.template),
        );
        if (!policyReceipt && prepared.policyProof)
          await policy.recordPolicy(prepared.policyProof);
        return (options.runCase ?? owner.execute)(
          job,
          recipe,
          prepared,
          effects,
          policy,
          options,
          signal,
        );
      });
      pending = true;
      operation
        .finally(() => {
          pending = false;
        })
        .catch(() => {});
      result = await bounded(
        operation,
        Math.max(0, recipe.deadlineMs - (now() - start)),
        controller,
        "Native experiment execution deadline",
      );
      requireObservation(
        !signal.aborted &&
          result?.status === "OBSERVED" &&
          hash(result.evidenceSha256) &&
          policyReceipt,
      );
    } catch (cause) {
      expired = signal.aborted;
      primary = cause;
      nativeException(`native-experiment:${recipe.id}:execution`, cause);
    } finally {
      active = false;
      controller.abort();
      options.signal?.removeEventListener("abort", interrupted);
    }
    const cleanupStart = now(),
      cleanup = new AbortController();
    try {
      requireObservation(effects);
      const receipts = await bounded(
        Promise.resolve().then(() =>
          effects.settle(recipe, prepared, {
            signal: cleanup.signal,
            execution: structuredClone(job.cases.at(-1)),
          }),
        ),
        30000,
        cleanup,
        "Native experiment settlement deadline",
      );
      observationObject(receipts, NATIVE_EFFECT_CLASSES);
      requireObservation(!pending);
      const settledEffects = structuredClone(job.cases.at(-1).effects);
      for (const key of NATIVE_EFFECT_CLASSES) {
        const receipt = receipts[key],
          effect = settledEffects[key];
        if (effect.admission === "not-started") {
          requireObservation(receipt === null);
          continue;
        }
        observationObject(receipt, [
          "candidateSha",
          "executionId",
          "effectClass",
          "settlement",
          "sha256",
        ]);
        requireObservation(
          receipt.candidateSha === job.candidateSha &&
            receipt.executionId === recipe.id &&
            receipt.effectClass === key &&
            hash(receipt.sha256),
        );
        effect.settlement = receipt.settlement;
        effect.receiptSha256 =
          receipt.settlement.status === "RETIRED"
            ? observationDigest({
                receipt,
                policyReceipt: policyReceipt ?? null,
                result: result ?? null,
                components: job.cases.at(-1).components,
              })
            : null;
      }
      await save(
        recordExperimentCase(job, {
          ...job.cases.at(-1),
          effects: settledEffects,
        }),
      );
    } catch (cause) {
      cleanupCause = cause;
      nativeException(`native-experiment:${recipe.id}:settlement`, cause);
    } finally {
      cleanup.abort();
    }
    const elapsedMs = Math.ceil(cleanupStart - start),
      cleanupMs = Math.ceil(now() - cleanupStart),
      current = job.cases.at(-1);
    const observed =
      result?.status === "OBSERVED" && hash(result?.evidenceSha256);
    const success =
      !primary &&
      !cleanupCause &&
      observed &&
      policyReceipt &&
      current.components &&
      elapsedMs <= recipe.deadlineMs &&
      cleanupMs <= 30000 &&
      Object.values(current.effects).every(
        (effect) =>
          effect.admission === "not-started" || retired(effect.settlement),
      );
    await save(
      recordExperimentCase(job, {
        ...current,
        status: success ? "PASS" : "FAIL",
        elapsedMs,
        cleanupMs,
        observations: recipe.checkIds.map((checkId) => ({
          checkId,
          observation: {
            expected: "OBSERVED",
            observed: result?.status ?? null,
            // OBSERVED is returned only after the platform's full native assertions,
            // including its positive/negative controls and unchanged sentinels.
            matched: Boolean(observed),
            positiveControl: Boolean(observed),
            attempted: Boolean(observed),
            sentinelsUnchanged: Boolean(observed),
          },
        })),
      }),
    );
    if (!success) {
      await save({
        ...job,
        failure: job.failure ?? (expired ? "deadline" : "probe-failed"),
      });
      await options.onFailure?.(
        job,
        primary ?? cleanupCause ?? new Error("Unsuccessful native experiment"),
      );
      break;
    }
  }
  return job;
}
