import { createHash } from "node:crypto";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual as same } from "node:util";

import {
  parseCustomPlan,
  serializeCustomPlan,
} from "@agent-runner/custom-plan";

import { PlanExecutionWorkflowError } from "./errors.js";
import { stepGatePassed } from "./gate-evidence.js";
import { validationEvidenceFingerprint } from "./validation-schedule.js";

const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const fingerprint = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const exact = (value, fields) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === fields.length &&
  fields.every((field) => Object.hasOwn(value, field));
const within = (root, path) => {
  const suffix = relative(root, path);
  return (
    suffix === "" ||
    (!isAbsolute(suffix) && suffix !== ".." && !suffix.startsWith(`..${sep}`))
  );
};
const text = (value, limit) =>
  typeof value === "string" &&
  value.trim().length > 0 &&
  Buffer.byteLength(value) <= limit &&
  !value.includes("\0");

function assert(
  condition,
  message = "Invalid custom result checkpoint.",
  code = "ERR_INVALID_CUSTOM_RESULT",
) {
  if (!condition) throw new PlanExecutionWorkflowError(message, { code });
}

function freeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function bindingFor(run) {
  const state = run.pipelineState;
  assert(state.planKind === "custom" && run.workspace?.kind === "directory");
  const plan = parseCustomPlan(state.canonicalPlan);
  const workspace = run.workspace;
  const outputs = [
    ...new Set(plan.outputs.map((path) => resolve(run.projectPath, path))),
  ]
    .sort()
    .filter(
      (path, index, paths) =>
        !paths.some((parent, other) => other !== index && within(parent, path)),
    );
  assert(
    same(outputs, workspace.policy.outputPaths),
    "Plan declarations differ from frozen output authority.",
  );
  assert(
    fingerprint(workspace.bindingFingerprint) &&
      fingerprint(workspace.protectedFingerprint),
  );
  // Execution clarifications can change through the authorized product-decision
  // flow. Bind their exact version on each receipt; immutable inputs and output
  // authority remain shared by every step.
  const { executionClarifications: _clarifications, ...hashes } = run.hashes;
  return {
    planFingerprint: hash(serializeCustomPlan(plan)),
    criteriaFingerprint: hash(plan.criteria),
    inputFingerprint: hash({
      hashes,
      protectedFingerprint: workspace.protectedFingerprint,
    }),
    workspaceFingerprint: workspace.bindingFingerprint,
    permissionsFingerprint: hash(workspace.policy),
    outputPaths: outputs,
  };
}

export function normalizeCustomResult(result, step) {
  assert(step !== undefined);
  assert(
    exact(result, ["analysis", "evidence", "outputPaths"]) &&
      text(result.analysis, 32 * 1024) &&
      Array.isArray(result.evidence) &&
      result.evidence.length === step.criterionRefs.length &&
      Array.isArray(result.outputPaths) &&
      result.outputPaths.length <= 256 &&
      result.outputPaths.every(
        (path) =>
          typeof path === "string" &&
          isAbsolute(path) &&
          resolve(path) === path,
      ) &&
      new Set(result.outputPaths).size === result.outputPaths.length,
  );
  for (const [index, evidence] of result.evidence.entries()) {
    assert(
      exact(evidence, ["criterionId", "observations"]) &&
        evidence.criterionId === step.criterionRefs[index] &&
        Array.isArray(evidence.observations) &&
        evidence.observations.length > 0 &&
        evidence.observations.length <= 32 &&
        evidence.observations.every((entry) => text(entry, 4000)),
    );
  }
  assert(Buffer.byteLength(JSON.stringify(result)) <= 128 * 1024);
  return structuredClone(result);
}

function outputFingerprints(snapshot, paths) {
  const byPath = new Map(snapshot.entries.map((entry) => [entry.path, entry]));
  const resolutions = new Map(
    (snapshot.linkResolutions ?? []).map((entry) => [entry.path, entry]),
  );
  return paths.map((path) => {
    const entries = new Set(
      snapshot.entries.filter((entry) => within(path, entry.path)),
    );
    assert(
      byPath.has(path) && byPath.get(path).kind !== "missing",
      "An accepted output is missing.",
      "ERR_CUSTOM_RESULT_DRIFT",
    );
    // Include every resolution hop and the readable target tree. Following the
    // growing set also binds links reached through linked directories.
    for (const entry of entries) {
      if (entry.kind !== "symlink") continue;
      const resolution = resolutions.get(entry.path);
      assert(
        resolution && Array.isArray(resolution.paths),
        "An accepted output lacks inspected link dependencies.",
        "ERR_CUSTOM_RESULT_DRIFT",
      );
      for (const dependency of resolution.paths) {
        assert(
          byPath.has(dependency),
          "An output link dependency is missing.",
          "ERR_CUSTOM_RESULT_DRIFT",
        );
        entries.add(byPath.get(dependency));
      }
      for (const target of snapshot.entries)
        if (within(resolution.target, target.path)) entries.add(target);
    }
    return {
      path,
      fingerprint: hash(
        [...entries].sort((left, right) =>
          left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
        ),
      ),
    };
  });
}

export function customResultFingerprint(
  binding,
  snapshot,
  result,
  clarificationFingerprint = hash(null),
) {
  return hash({
    binding,
    clarificationFingerprint,
    contentFingerprint: snapshot.contentFingerprint,
    result,
  });
}

export function executionContentFingerprint(
  state,
  snapshot = state.repositoryBaseline,
) {
  return state.planKind === "custom" &&
    state.customCandidate &&
    state.customResults
    ? customResultFingerprint(
        state.customResults.binding,
        snapshot,
        state.customCandidate,
        state.customResults.clarificationFingerprint,
      )
    : snapshot?.contentFingerprint;
}

const RESULT_SCHEMA = {
  type: "object",
  properties: {
    analysis: { type: "string", minLength: 1, maxLength: 32768 },
    evidence: {
      type: "array",
      maxItems: 256,
      items: {
        type: "object",
        properties: {
          criterionId: { type: "string", minLength: 1 },
          observations: {
            type: "array",
            minItems: 1,
            maxItems: 32,
            items: { type: "string", minLength: 1, maxLength: 4000 },
          },
        },
        required: ["criterionId", "observations"],
        additionalProperties: false,
      },
    },
    outputPaths: {
      type: "array",
      maxItems: 256,
      items: { type: "string", minLength: 1 },
    },
  },
  required: ["analysis", "evidence", "outputPaths"],
  additionalProperties: false,
};

export function customTurnSchema(schema, resultTurn) {
  const copy = structuredClone(schema);
  function allowCriterionValidation(value) {
    if (!value || typeof value !== "object") return;
    if (value.properties?.requiredChecks?.minItems)
      value.properties.requiredChecks.minItems = 0;
    for (const child of Object.values(value)) allowCriterionValidation(child);
  }
  allowCriterionValidation(copy);
  if (resultTurn) {
    copy.properties.customResult = { anyOf: [RESULT_SCHEMA, { type: "null" }] };
    copy.required.push("customResult");
  }
  return copy;
}

function assertRecord(record, ledger, plan, step) {
  assert(
    exact(record, [
      "step",
      "previous",
      "bindingFingerprint",
      "clarificationFingerprint",
      "result",
      "outputs",
      "contentFingerprint",
      "snapshotFingerprint",
      "resultFingerprint",
      "validationFingerprint",
      "gateFingerprint",
      "receipt",
    ]),
  );
  const { receipt, ...body } = record;
  assert(
    record.step === step &&
      record.previous === (ledger.accepted[step - 2]?.receipt ?? null) &&
      record.bindingFingerprint === hash(ledger.binding) &&
      receipt === hash(body) &&
      [
        record.contentFingerprint,
        record.clarificationFingerprint,
        record.snapshotFingerprint,
        record.resultFingerprint,
        record.validationFingerprint,
        record.gateFingerprint,
      ].every(fingerprint),
  );
  assert(
    record.resultFingerprint ===
      customResultFingerprint(
        ledger.binding,
        { contentFingerprint: record.contentFingerprint },
        record.result,
        record.clarificationFingerprint,
      ),
  );
  normalizeCustomResult(record.result, plan.steps[step - 1]);
  assert(
    record.result.outputPaths.every((path) =>
      ledger.binding.outputPaths.some((root) => within(root, path)),
    ) &&
      Array.isArray(record.outputs) &&
      record.outputs.length === record.result.outputPaths.length,
  );
  for (const [index, output] of record.outputs.entries())
    assert(
      exact(output, ["path", "fingerprint"]) &&
        output.path === record.result.outputPaths[index] &&
        fingerprint(output.fingerprint),
    );
}

// This private ledger is persisted inside the normal leased, write-ahead pipeline
// state. It carries no workflow, provider, publication or Git authority itself.
export function normalizeCustomResults(value, canonicalPlan) {
  const ledger = structuredClone(value);
  const plan = parseCustomPlan(canonicalPlan);
  assert(
    exact(ledger, [
      "schemaVersion",
      "binding",
      "clarificationFingerprint",
      "accepted",
      "pending",
      "preparedRoots",
      "preparation",
    ]) &&
      ledger.schemaVersion === 1 &&
      fingerprint(ledger.clarificationFingerprint),
  );
  const binding = ledger.binding;
  assert(
    exact(binding, [
      "planFingerprint",
      "criteriaFingerprint",
      "inputFingerprint",
      "workspaceFingerprint",
      "permissionsFingerprint",
      "outputPaths",
    ]) &&
      binding.planFingerprint === hash(serializeCustomPlan(plan)) &&
      binding.criteriaFingerprint === hash(plan.criteria) &&
      [
        binding.inputFingerprint,
        binding.workspaceFingerprint,
        binding.permissionsFingerprint,
      ].every(fingerprint) &&
      Array.isArray(binding.outputPaths) &&
      binding.outputPaths.length <= 256 &&
      binding.outputPaths.every(
        (path) =>
          typeof path === "string" &&
          isAbsolute(path) &&
          resolve(path) === path,
      ) &&
      new Set(binding.outputPaths).size === binding.outputPaths.length &&
      Array.isArray(ledger.accepted) &&
      ledger.accepted.length <= plan.steps.length &&
      Array.isArray(ledger.preparedRoots) &&
      ledger.preparedRoots.length <= binding.outputPaths.length,
  );
  for (const [index, record] of ledger.accepted.entries())
    assertRecord(record, ledger, plan, index + 1);
  if (ledger.pending !== null) {
    assert(ledger.accepted.length < plan.steps.length);
    assertRecord(ledger.pending, ledger, plan, ledger.accepted.length + 1);
  }
  const directory = (entry) =>
    exact(entry, ["path", "exists", "kind", "ancestors", "identity"]) &&
    binding.outputPaths.includes(entry.path) &&
    entry.exists === true &&
    entry.kind === "directory" &&
    validPathBinding(entry);
  assert(
    ledger.preparedRoots.every(directory) &&
      new Set(ledger.preparedRoots.map(({ path }) => path)).size ===
        ledger.preparedRoots.length,
  );
  if (ledger.preparation !== null) {
    const preparation = ledger.preparation;
    assert(
      ledger.pending === null &&
        exact(preparation, ["intent", "prepared"]) &&
        exact(preparation.intent, [
          "path",
          "before",
          "parent",
          "storage",
          "staging",
        ]) &&
        binding.outputPaths.includes(preparation.intent.path) &&
        !ledger.preparedRoots.some(
          ({ path }) => path === preparation.intent.path,
        ) &&
        validPathBinding(preparation.intent.before) &&
        validPathBinding(preparation.intent.parent) &&
        preparation.intent.before.path === preparation.intent.path &&
        preparation.intent.parent.path === dirname(preparation.intent.path) &&
        preparation.intent.parent.kind === "directory" &&
        (preparation.intent.before.exists
          ? preparation.intent.storage === null &&
            preparation.intent.staging === null
          : validPathBinding(preparation.intent.storage) &&
            preparation.intent.storage.kind === "directory" &&
            validPathBinding(preparation.intent.staging) &&
            preparation.intent.staging.kind === "missing" &&
            dirname(preparation.intent.staging.path) ===
              preparation.intent.storage.path) &&
        (preparation.prepared === null ||
          (directory(preparation.prepared) &&
            preparation.prepared.path === preparation.intent.path)),
    );
  }
  assert(
    Buffer.byteLength(JSON.stringify(ledger)) <= 1024 * 1024,
    "Custom checkpoint storage is full.",
  );
  return freeze(ledger);
}

function validPathBinding(value) {
  const identity = (entry) =>
    exact(entry, ["device", "inode", "mode"]) &&
    Object.values(entry).every(
      (part) => typeof part === "string" && /^\d{1,32}$/u.test(part),
    );
  return (
    exact(value, ["path", "exists", "kind", "ancestors", "identity"]) &&
    typeof value.path === "string" &&
    isAbsolute(value.path) &&
    resolve(value.path) === value.path &&
    ["missing", "directory"].includes(value.kind) &&
    value.exists === (value.kind === "directory") &&
    (value.exists ? identity(value.identity) : value.identity === null) &&
    Array.isArray(value.ancestors) &&
    value.ancestors.length <= 256 &&
    value.ancestors.every((entry) => {
      if (!exact(entry, ["path", "device", "inode", "mode"])) return false;
      const { path, ...metadata } = entry;
      return typeof path === "string" && isAbsolute(path) && identity(metadata);
    })
  );
}

function assertAdmitted(run) {
  assert(
    !["WAITING_FOR_USER", "CANCELED", "DONE", "FAILED"].includes(
      run.pipelineState.workflowState,
    ) &&
      run.activeTurn === null &&
      run.executionProcess === null &&
      run.executionResource === null &&
      run.preparation == null &&
      !(run.stopRequest && run.stopRequest.reconciledRevision === null),
    "Custom checkpoint is suspended.",
    "ERR_CUSTOM_RESULT_SUSPENDED",
  );
}

export function assertCustomOutputPreparation(run, intent) {
  assertAdmitted(run);
  const ledger = normalizeCustomResults(
    run.pipelineState.customResults,
    run.pipelineState.canonicalPlan,
  );
  assert(
    same(ledger.binding, bindingFor(run)) &&
      ledger.preparation?.prepared === null &&
      same(ledger.preparation.intent, intent),
    "Output creation requires its persisted exact preparation intent.",
  );
}

export function createCustomResultCheckpoint({ run: initial, runtime }) {
  let run = initial;
  const plan = parseCustomPlan(run.pipelineState.canonicalPlan);
  const binding = freeze(bindingFor(run));
  let ledger =
    run.pipelineState.customResults === null
      ? freeze({
          schemaVersion: 1,
          binding,
          clarificationFingerprint: hash(
            run.hashes.executionClarifications ?? null,
          ),
          accepted: [],
          pending: null,
          preparedRoots: [],
          preparation: null,
        })
      : normalizeCustomResults(
          run.pipelineState.customResults,
          run.pipelineState.canonicalPlan,
        );
  assert(
    same(ledger.binding, binding),
    "Frozen custom inputs changed; revise the plan and start a new run.",
    "ERR_CUSTOM_RESULT_DRIFT",
  );

  async function persist(next) {
    assertAdmitted(run);
    const normalized = normalizeCustomResults(
      next,
      run.pipelineState.canonicalPlan,
    );
    run = await runtime.transition(
      { pipelineState: { ...run.pipelineState, customResults: normalized } },
      { expectedRevision: run.revision },
    );
    ledger = normalized;
  }
  async function inspect() {
    const snapshot = await runtime.workspace.snapshot();
    for (const root of ledger.preparedRoots) {
      const { before: current } =
        await runtime.workspace.inspectOutputDirectory(root.path);
      assert(
        same(current, root),
        "Prepared output ownership changed.",
        "ERR_CUSTOM_RESULT_DRIFT",
      );
    }
    for (const record of ledger.accepted)
      assert(
        same(
          outputFingerprints(snapshot, record.result.outputPaths),
          record.outputs,
        ),
        "An earlier accepted result changed; revise the plan and start a new run.",
        "ERR_CUSTOM_RESULT_DRIFT",
      );
    return snapshot;
  }
  async function initialize() {
    if (run.pipelineState.customResults === null) await persist(ledger);
  }
  async function reconcilePreparation() {
    if (ledger.preparation === null) return;
    assertAdmitted(run);
    await inspect();
    let { intent, prepared } = ledger.preparation;
    if (prepared === null) {
      ({ prepared, run } =
        await runtime.workspace.prepareOutputDirectory(intent));
      await persist({ ...ledger, preparation: { intent, prepared } });
    }
    assert(
      same(
        (await runtime.workspace.inspectOutputDirectory(prepared.path)).before,
        prepared,
      ),
      "Prepared output changed before settlement.",
      "ERR_CUSTOM_RESULT_DRIFT",
    );
    await persist({
      ...ledger,
      preparation: null,
      preparedRoots: [
        ...ledger.preparedRoots.filter(({ path }) => path !== prepared.path),
        prepared,
      ],
    });
  }
  async function reconcile() {
    await reconcilePreparation();
    const snapshot = await inspect();
    if (ledger.pending === null) return ledger;
    assertAdmitted(run);
    const record = ledger.pending;
    assert(
      snapshot.contentFingerprint === record.contentFingerprint &&
        hash(snapshot.entries) === record.snapshotFingerprint &&
        same(
          outputFingerprints(snapshot, record.result.outputPaths),
          record.outputs,
        ),
      "Pending result publication changed; preserve it for reconciliation.",
      "ERR_CUSTOM_RESULT_DRIFT",
    );
    assertGates(record.resultFingerprint, record);
    await persist({
      ...ledger,
      accepted: [...ledger.accepted, record],
      pending: null,
    });
    return ledger;
  }
  function gateFingerprint(state) {
    return hash({
      mode: state.settings.mode,
      candidate: state.candidateReviewResult,
      primary: state.candidateConfirmationFingerprint,
      finalization: state.finalizationResult,
      confirmation: state.reviewResult,
    });
  }
  function assertGates(resultFingerprint, record) {
    const state = run.pipelineState;
    assert(
      state.currentStep === ledger.accepted.length + 1 &&
        ledger.clarificationFingerprint ===
          hash(run.hashes.executionClarifications ?? null) &&
        stepGatePassed(state, resultFingerprint) &&
        (!record ||
          (record.clarificationFingerprint ===
            hash(run.hashes.executionClarifications ?? null) &&
            record.gateFingerprint === gateFingerprint(state) &&
            record.validationFingerprint ===
              validationEvidenceFingerprint(state.finalizationResult))),
      "Custom acceptance requires current candidate, finalization and terminal confirmation evidence.",
      "ERR_CUSTOM_RESULT_GATE",
    );
  }
  return Object.freeze({
    verify: inspect,
    reconcile,
    async prepareOutputRoots(paths) {
      assertAdmitted(run);
      assert(
        Array.isArray(paths) &&
          paths.length <= binding.outputPaths.length &&
          new Set(paths).size === paths.length &&
          paths.every((path) => binding.outputPaths.includes(path)),
      );
      assert(
        ledger.pending === null,
        "Reconcile pending acceptance before preparing outputs.",
      );
      await initialize();
      await reconcilePreparation();
      for (const path of paths) {
        await inspect();
        if (ledger.preparedRoots.some((entry) => entry.path === path)) continue;
        const intent = await runtime.workspace.inspectOutputDirectory(path);
        await persist({ ...ledger, preparation: { intent, prepared: null } });
        await reconcilePreparation();
      }
      return ledger;
    },
    async accept(result) {
      assertAdmitted(run);
      assert(
        ledger.pending === null && ledger.preparation === null,
        "Reconcile unfinished publication before accepting another result.",
      );
      const step = plan.steps[ledger.accepted.length];
      assert(step !== undefined);
      result = normalizeCustomResult(result, step);
      assert(
        result.outputPaths.every((path) =>
          binding.outputPaths.some((root) => within(root, path)),
        ),
      );
      const snapshot = await inspect();
      const resultFingerprint = customResultFingerprint(
        binding,
        snapshot,
        result,
        hash(run.hashes.executionClarifications ?? null),
      );
      assertGates(resultFingerprint);
      await initialize();
      const body = {
        step: step.number,
        previous: ledger.accepted.at(-1)?.receipt ?? null,
        bindingFingerprint: hash(binding),
        clarificationFingerprint: hash(
          run.hashes.executionClarifications ?? null,
        ),
        result,
        outputs: outputFingerprints(snapshot, result.outputPaths),
        contentFingerprint: snapshot.contentFingerprint,
        snapshotFingerprint: hash(snapshot.entries),
        resultFingerprint,
        validationFingerprint: validationEvidenceFingerprint(
          run.pipelineState.finalizationResult,
        ),
        gateFingerprint: gateFingerprint(run.pipelineState),
      };
      const record = { ...body, receipt: hash(body) };
      await persist({ ...ledger, pending: record });
      await reconcile();
      return ledger.accepted.at(-1);
    },
  });
}
