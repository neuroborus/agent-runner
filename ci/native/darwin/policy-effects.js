import { performance } from "node:perf_hooks";
import {
  assertDarwinPfState,
  DARWIN_PF_STATE_FIELDS,
  normalizeDarwinIdentity,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";
import {
  buildDarwinPolicy,
  darwinPfctlArguments,
  isDarwinDigest,
} from "./policy.js";

function root(value) {
  const identity = normalizeDarwinIdentity(value);
  requireDarwin(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
}

/** The protected reader inspects the kernel rules and their root call graph,
 * state/NAT tables, interfaces and owned endpoint reservations. Text produced
 * by pfctl alone cannot supply this independently candidate-bound snapshot. */
export function assertDarwinPfSnapshot(value, input, expectedAnchorSha256) {
  const plan = buildDarwinPolicy(input),
    { request } = plan.value;
  const state = Object.fromEntries(
    DARWIN_PF_STATE_FIELDS.map((key) => [
      key,
      key === "sha256" ? value?.anchorSha256 : value?.[key],
    ]),
  );
  assertDarwinPfState(state, request);
  requireDarwin(
    value &&
      value.independent === true &&
      value.candidateSha === request.candidateSha &&
      value.nonce === request.nonce &&
      value.compositionSha256 === plan.compositionSha256 &&
      value.reviewSha256 === plan.value.reviewSha256 &&
      value.anchor === plan.anchor &&
      value.anchorSha256 === expectedAnchorSha256 &&
      isDarwinDigest(expectedAnchorSha256) &&
      isDarwinDigest(value.rootSha256) &&
      isDarwinDigest(value.evidenceSha256) &&
      isDarwinDigest(value.reservationSha256) &&
      value.anchorOwned === true &&
      value.exclusiveWriter === true &&
      value.admissionsClosed === true,
  );
  return root(value.verifier);
}

/** Admission consumes the complete installed Seatbelt/PF composition rather
 * than merely observing that some SBPL was installed. */
export function assertDarwinPolicyInstallation(value, input) {
  const plan = buildDarwinPolicy(input),
    { request } = plan.value;
  requireDarwin(
    request.policy.sha256 === plan.seatbeltSha256 &&
      request.bindings.policy === plan.compositionSha256 &&
      value?.status === "INSTALLED" &&
      value.candidateSha === request.candidateSha &&
      value.nonce === request.nonce &&
      value.compositionSha256 === plan.compositionSha256 &&
      value.seatbeltSha256 === plan.seatbeltSha256 &&
      value.pfSha256 === plan.pfSha256 &&
      value.reservation === "RETAINED" &&
      value.helpersSettled === true,
  );
  assertDarwinPfSnapshot(value.effective, plan.value, plan.pfSha256);
  return value;
}

/** Native setup/removal runs only in dedicated CI through protected tool,
 * receipt and verifier owners. An uncertain write never authorizes rollback. */
export async function configureDarwinPolicy(
  input,
  approvedSha256,
  effects,
  {
    operation = "install",
    retirement,
    previous,
    platform = process.platform,
    architecture = process.arch,
    uid = process.geteuid?.(),
    env = process.env,
    now = () => performance.now(),
  } = {},
) {
  const plan = buildDarwinPolicy(input),
    { request } = plan.value;
  requireDarwin(
    ["install", "restore"].includes(operation) &&
      platform === "darwin" &&
      architecture === "x64" &&
      uid === 0 &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "macos15" &&
      typeof effects?.persist === "function",
  );
  // Protected receipts are private execution inputs. Callers retain reporting
  // objects, but cannot alter restoration authority during an awaited effect.
  previous = structuredClone(previous);
  retirement = structuredClone(retirement);
  const record = {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    compositionSha256: plan.compositionSha256,
    seatbeltSha256: plan.seatbeltSha256,
    pfSha256: plan.pfSha256,
    status: "BLOCKED",
    phase: "review",
    operation,
    reservation: "RETAINED",
    helpersSettled: false,
    missingInputs: [],
  };
  for (const key of [
    "review",
    "snapshot",
    "stage",
    "pfctl",
    "verifySettlement",
  ])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("darwin-policy-" + key);
  if (operation === "restore" && typeof effects.verifyRetirement !== "function")
    record.missingInputs.push("darwin-policy-verifyRetirement");
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  const start = now(),
    bounded = () => {
      const elapsed = now() - start;
      requireDarwin(
        Number.isFinite(elapsed) && elapsed >= 0 && elapsed <= 30000,
      );
    };
  try {
    requireDarwin(
      approvedSha256 === plan.compositionSha256 &&
        request.policy.sha256 === plan.seatbeltSha256 &&
        request.bindings.policy === approvedSha256,
    );
    const review = structuredClone(
      await effects.review(structuredClone(plan.value), approvedSha256),
    );
    if (review.missingInputs?.length) {
      requireDarwin(
        Array.isArray(review.missingInputs) &&
          review.missingInputs.length <= 256 &&
          review.missingInputs.every(
            (value) =>
              typeof value === "string" &&
              value.length > 0 &&
              value.length <= 512 &&
              !/[\u0000-\u001f\u007f]/u.test(value),
          ),
      );
      record.missingInputs = [...review.missingInputs];
      await save();
      return record;
    }
    requireDarwin(
      review.approvedSha256 === approvedSha256 &&
        review.reviewSha256 === plan.value.reviewSha256 &&
        isDarwinDigest(review.toolSha256),
    );
    record.toolSha256 = review.toolSha256;
    let before;
    if (operation === "restore") {
      assertDarwinPolicyInstallation(previous, plan.value);
      assertDarwinPfSnapshot(
        previous.before,
        plan.value,
        previous.before?.anchorSha256,
      );
      requireDarwin(
        previous.before.savedAnchorSha256 === previous.before.anchorSha256,
      );
      const verifier = root(retirement?.freshVerifier);
      requireDarwin(
        retirement.status === "RETIRED" &&
          retirement.helpersSettled === true &&
          retirement.candidateSha === request.candidateSha &&
          retirement.nonce === request.nonce &&
          retirement.reservation === "RETAINED" &&
          retirement.domain?.uid === request.uid &&
          retirement.domain?.gid === request.gid &&
          retirement.domain.asid > 0 &&
          verifier.asid !== retirement.domain.asid &&
          retirement.authoritySha256 === approvedSha256,
      );
      before = structuredClone(
        await effects.snapshot(structuredClone(plan.value)),
      );
      const reader = assertDarwinPfSnapshot(before, plan.value, plan.pfSha256);
      requireDarwin(
        reader.pid !== verifier.pid &&
          before.rootSha256 === previous.before.rootSha256 &&
          before.reservationSha256 === previous.before.reservationSha256,
      );
      record.before = structuredClone(previous.before);
      record.retirementVerifier = verifier;
      requireDarwin(isDarwinDigest(retirement.requestSha256));
      const fresh = structuredClone(
        await effects.verifyRetirement(
          structuredClone(plan.value),
          structuredClone(retirement),
        ),
      );
      const readerIdentity = root(fresh.verifier);
      requireDarwin(
        fresh.independent === true &&
          fresh.noLiveUid === true &&
          fresh.uid === request.uid &&
          fresh.gid === request.gid &&
          fresh.asid === retirement.domain.asid &&
          fresh.helpersSettled === true &&
          fresh.requestSha256 === retirement.requestSha256 &&
          fresh.authoritySha256 === approvedSha256 &&
          isDarwinDigest(fresh.receiptSha256) &&
          readerIdentity.pid !== verifier.pid &&
          readerIdentity.asid !== retirement.domain.asid,
      );
      record.retirementRecheckSha256 = fresh.receiptSha256;
    } else {
      before = structuredClone(
        await effects.snapshot(structuredClone(plan.value)),
      );
      assertDarwinPfSnapshot(before, plan.value, before.anchorSha256);
      requireDarwin(
        before.anchorOwned === true &&
          before.admissionsClosed === true &&
          before.savedAnchorSha256 === before.anchorSha256,
      );
      record.before = structuredClone(before);
    }
    bounded();
    record.status = "RUNNING";
    record.phase = "stage";
    await save();
    bounded();
    const staged = structuredClone(
      await effects.stage(structuredClone(plan.value), {
        seatbelt: plan.seatbelt,
        pf: plan.pf,
        restoreSha256: record.before.savedAnchorSha256,
      }),
    );
    requireDarwin(
      staged.seatbeltSha256 === plan.seatbeltSha256 &&
        staged.pfSha256 === plan.pfSha256 &&
        staged.restoreSha256 === record.before.savedAnchorSha256 &&
        isDarwinDigest(staged.receiptSha256) &&
        staged.immutable === true,
    );
    record.stageSha256 = staged.receiptSha256;
    const perform = async (action) => {
      bounded();
      record.phase = "pf-" + action;
      record.possibleEffect = true;
      await save();
      bounded();
      const args = darwinPfctlArguments(plan.value, action);
      const result = structuredClone(
        await effects.pfctl(
          structuredClone(plan.value),
          args,
          record.toolSha256,
        ),
      );
      const helper = root(result.helper),
        worker = root(result.worker),
        verifier = root(result.verifier);
      requireDarwin(
        result.exitCode === 0 &&
          result.signal === null &&
          result.timedOut === false &&
          result.toolSha256 === record.toolSha256 &&
          result.settled === true &&
          worker.pid !== helper.pid &&
          verifier.pid !== helper.pid &&
          verifier.pid !== worker.pid &&
          isDarwinDigest(result.receiptSha256),
      );
      record.helperReceipts ??= [];
      record.helperReceipts.push({
        helper,
        worker,
        verifier,
        sha256: result.receiptSha256,
      });
      bounded();
      await save();
    };
    await perform(operation === "restore" ? "validate-restore" : "validate");
    {
      // Reinspect immediately before the only restoring write. Do not overwrite
      // a changed root graph, foreign anchor or another allocation's policy.
      const fresh = structuredClone(
        await effects.snapshot(structuredClone(plan.value)),
      );
      assertDarwinPfSnapshot(
        fresh,
        plan.value,
        operation === "restore" ? plan.pfSha256 : record.before.anchorSha256,
      );
      requireDarwin(
        fresh.rootSha256 === record.before.rootSha256 &&
          fresh.reservationSha256 === record.before.reservationSha256 &&
          fresh.anchorOwned === true &&
          fresh.admissionsClosed === true,
      );
    }
    await perform(operation);
    record.phase = "effective-verification";
    await save();
    bounded();
    const effective = structuredClone(
      await effects.snapshot(structuredClone(plan.value)),
    );
    const verifier = assertDarwinPfSnapshot(
      effective,
      plan.value,
      operation === "install" ? plan.pfSha256 : record.before.anchorSha256,
    );
    requireDarwin(
      effective.rootSha256 === record.before.rootSha256 &&
        effective.reservationSha256 === record.before.reservationSha256 &&
        !record.helperReceipts.some(
          (entry) =>
            entry.helper.pid === verifier.pid ||
            entry.worker.pid === verifier.pid,
        ),
    );
    const settled = structuredClone(
      await effects.verifySettlement(
        structuredClone(plan.value),
        structuredClone(record),
      ),
    );
    const settlementVerifier = root(settled.verifier);
    requireDarwin(
      settled.independent === true &&
        settled.helpersSettled === true &&
        settled.compositionSha256 === approvedSha256 &&
        settlementVerifier.pid !== verifier.pid &&
        !record.helperReceipts.some(
          (entry) =>
            entry.helper.pid === settlementVerifier.pid ||
            entry.worker.pid === settlementVerifier.pid,
        ) &&
        Array.isArray(settled.helpers) &&
        settled.helpers.length === 2 * record.helperReceipts.length &&
        record.helperReceipts
          .flatMap((entry) => [entry.helper, entry.worker])
          .every(
            (identity) =>
              settled.helpers.filter((value) =>
                sameDarwinIdentity(value, identity),
              ).length === 1,
          ),
    );
    bounded();
    record.effective = structuredClone(effective);
    record.helpersSettled = true;
    record.status = operation === "install" ? "INSTALLED" : "RESTORED";
    record.phase = "verified";
    await save();
    bounded();
    return structuredClone(record);
  } catch {
    record.status = "FAIL";
    await save();
    return structuredClone(record);
  }
}
