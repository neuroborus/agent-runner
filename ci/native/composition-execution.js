import { performance } from "node:perf_hooks";
import { NATIVE_GROUPS, NATIVE_EFFECT_CLASSES } from "./catalog.js";
import {
  beginCompositionExecution,
  recordCompositionEffect,
  finishCompositionExecution,
  recordCompositionPolicy,
  compositionEffectRetired,
} from "./composition.js";
import {
  observationObject as closed,
  requireObservation as requireValue,
} from "./observation.js";
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);

/** Each callback is an indexed native owner. The ledger is durable before
 * effects and settlement is read independently, including on exceptions. */
export async function runCompositionExecution(
  input,
  recipe,
  owner,
  {
    persist,
    diagnostic = () => {},
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  },
) {
  requireValue(
    typeof persist === "function" &&
      typeof diagnostic === "function" &&
      typeof owner?.execute === "function" &&
      typeof owner?.settle === "function",
  );
  let job = beginCompositionExecution(
    input,
    recipe.id,
    recipe.group,
    recipe.checkIds,
  );
  const start = now();
  requireValue(
    Number.isSafeInteger(recipe.deadlineMs) &&
      recipe.deadlineMs > 0 &&
      recipe.deadlineMs === job.executions.at(-1).deadlineMs,
  );
  let active = true,
    writes = Promise.resolve(),
    result,
    failed = false;
  const controller = new AbortController();
  const timer = schedule(() => controller.abort(), recipe.deadlineMs);
  const signal = controller.signal;
  let cleanupStart;
  const save = () => {
    const value = structuredClone(job);
    writes = writes.then(() => persist(value));
    let receiptTimer;
    return Promise.race([
      writes,
      new Promise((_, reject) => {
        receiptTimer = schedule(
          () => reject(new Error("Native receipt deadline")),
          30000,
        );
      }),
    ]).finally(() => cancel(receiptTimer));
  };
  const announce = (phase, group = recipe.group) => {
    try {
      // Diagnostics are synchronous, bounded metadata. Output failure must
      // preserve the case failure while allowing independent retirement.
      requireValue(
        [phase, group].every(
          (value) =>
            typeof value === "string" && /^[a-z][a-z0-9.-]{0,95}$/u.test(value),
        ),
      );
      const result = diagnostic({ executionId: recipe.id, group, phase });
      if (result && typeof result.then === "function") {
        Promise.resolve(result).catch(() => {});
        failed = true;
      }
    } catch {
      failed = true;
    }
  };
  try {
    await save();
    announce("intent");
  } catch (error) {
    cancel(timer);
    controller.abort();
    throw error;
  }
  const admit = async (effectClass) => {
    requireValue(active && !failed && !signal.aborted);
    if (
      job.plan.schemaVersion === 2 &&
      ["transport", "providers"].includes(effectClass)
    )
      requireValue(job.executions.at(-1).policyReceipt !== null);
    job = recordCompositionEffect(job, recipe.id, effectClass);
    await save();
    announce(effectClass);
    requireValue(active && !failed && !signal.aborted);
  };
  const recordPolicy = async (receipt) => {
    requireValue(active && !failed && !signal.aborted);
    job = recordCompositionPolicy(job, recipe.id, receipt);
    await save();
    requireValue(active && !failed && !signal.aborted);
  };
  let pending = false;
  try {
    requireValue(!failed && !signal.aborted);
    const operation = Promise.resolve().then(() => {
      requireValue(!failed && !signal.aborted);
      return owner.execute({
        admit,
        recordPolicy,
        signal,
        diagnostic: (group, phase) => announce(phase, group),
      });
    });
    pending = true;
    operation
      .finally(() => {
        pending = false;
      })
      .catch(() => {});
    result = await Promise.race([
      operation,
      new Promise((_, reject) =>
        signal.addEventListener(
          "abort",
          () => reject(new Error("Native composition deadline")),
          { once: true },
        ),
      ),
    ]);
    requireValue(
      !signal.aborted &&
        result?.status === "OBSERVED" &&
        hash(result.evidenceSha256),
    );
  } catch {
    failed = true;
  } finally {
    active = false;
    cancel(timer);
    controller.abort();
    cleanupStart = now();
    announce("settlement");
    try {
      const cleanup = new AbortController();
      let cleanupTimer;
      const settlement = Promise.resolve().then(() =>
        owner.settle({ signal: cleanup.signal }),
      );
      let receipts;
      try {
        receipts = await Promise.race([
          settlement,
          new Promise((_, reject) => {
            cleanupTimer = schedule(() => {
              cleanup.abort();
              reject(new Error("Native settlement deadline"));
            }, 30000);
          }),
        ]);
      } finally {
        cancel(cleanupTimer);
        cleanup.abort();
      }
      closed(receipts, NATIVE_EFFECT_CLASSES);
      requireValue(!pending);
      for (const effectClass of NATIVE_EFFECT_CLASSES) {
        const current = job.executions.at(-1).effects[effectClass];
        if (current.admission === "not-started") {
          requireValue(receipts[effectClass] === null);
          continue;
        }
        const receipt = receipts[effectClass];
        closed(receipt, [
          "candidateSha",
          "executionId",
          "effectClass",
          "settlement",
          "sha256",
        ]);
        requireValue(
          receipt.candidateSha === job.candidateSha &&
            receipt.executionId === recipe.id &&
            receipt.effectClass === effectClass &&
            hash(receipt.sha256),
        );
        job = recordCompositionEffect(
          job,
          recipe.id,
          effectClass,
          receipt.settlement,
          receipt.sha256,
        );
        await save();
      }
    } catch {
      failed = true;
    }
  }
  const elapsedMs = Math.ceil(cleanupStart - start),
    cleanupMs = Math.ceil(now() - cleanupStart);
  if (
    elapsedMs > recipe.deadlineMs ||
    cleanupMs > 30000 ||
    !Object.values(job.executions.at(-1).effects).every(
      compositionEffectRetired,
    )
  )
    failed = true;
  if (
    job.plan.schemaVersion === 2 &&
    job.executions.at(-1).policyReceipt === null
  )
    failed = true;
  const required =
    recipe.group === "build"
      ? ["builds"]
      : NATIVE_GROUPS[job.platform][recipe.group].effects;
  if (
    !required.every(
      (id) => job.executions.at(-1).effects[id].admission === "possible",
    )
  )
    failed = true;
  // Include completion-output failure in the durable terminal status too.
  announce(failed ? "failed" : "complete");
  job = finishCompositionExecution(
    job,
    recipe.id,
    failed ? "FAIL" : "PASS",
    result?.evidenceSha256 ?? null,
    elapsedMs,
    cleanupMs,
  );
  await save();
  return { job, result: failed ? null : result, elapsedMs };
}
