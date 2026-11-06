import { dirname, join } from "node:path";
import { isDeepStrictEqual as same } from "node:util";

import { assertInitState } from "./workflow.js";
import {
  assertInit,
  digest,
  exact,
  hashText,
  isFinalizationRepair,
  within,
} from "./proposal.js";
import {
  assertIntegratedPolicy,
  integratedIgnorePaths,
  temporaryPath,
} from "./integrated-policy.js";
import {
  assertExternalControls,
  assertExternalPolicy,
} from "./external-policy.js";

/** Runner-only, under the existing exclusive workspace and execution leases.
 * External publication also requires the selected infrastructure exclusion lease.
 * persist journals the complete record before any effect or acknowledgement.
 * This prepares prerequisites only; guidance and completion remain separate.
 */
export async function publishIntegratedInit(
  state,
  runtime,
  publication = null,
) {
  return publishPrerequisites(state, runtime, publication, "integrated");
}

export async function publishExternalInit(state, runtime, publication = null) {
  const prepared = await publishPrerequisites(
    state,
    runtime,
    publication,
    "external",
  );
  return {
    publication: prepared,
    configurationPath: state.selection.configurationPath,
  };
}

async function publishPrerequisites(state, runtime, publication, placement) {
  assertInitState(state);
  assertInit(
    (state.workflowState === "PROPOSAL_ACCEPTED" ||
      (runtime.verifyOnly &&
        ["DONE", "WAITING_FOR_USER", "CANCELED", "FAILED"].includes(
          state.workflowState,
        ))) &&
      state.selection.placement === placement,
    "Publication requires the selected placement's proposal approval gate.",
  );
  const { workspace, stateRoot } = runtime;
  const targetPath = state.inspection.projectPath;
  const rootPath = state.selection.rootPath;
  // The parent is a confinement anchor, never a write inventory or read tree.
  // Only the selected root and reviewed descendants may receive intents.
  const projectPath = placement === "external" ? dirname(rootPath) : rootPath;
  const binding = digest({
    inspection: state.inspection,
    selection: state.selection,
    clarificationHash: state.clarificationHash,
    proposalHash: state.proposalHash,
    primaryApproval: state.primaryApproval,
    reviewApproval: state.reviewApproval,
    settings: state.settings,
    stateRoot,
  });
  const resources = state.proposal.resources.filter(
    ({ kind }) => kind !== "guidance",
  );
  const guide = state.proposal.resources.find(
    ({ kind }) => kind === "guidance",
  );
  // Prepare the reviewed guide's parent with journaled directory identity too.
  // The guidance capability then publishes only its file as the final resource.
  resources.push({
    path: dirname(guide.path),
    kind: "artifacts",
    action: "reuse",
    content: "",
  });
  // Ignore protections precede directory/file preparation; configuration is last.
  const order = { ignore: 0, artifacts: 1, finalization: 2, configuration: 3 };
  resources.sort((a, b) => order[a.kind] - order[b.kind]);
  const directories = new Set();
  for (const resource of resources) {
    for (
      let path =
        resource.kind === "artifacts" ? resource.path : dirname(resource.path);
      path !== projectPath;
      path = dirname(path)
    ) {
      assertInit(
        within(projectPath, path),
        "Publication directory escaped its target.",
      );
      directories.add(path);
    }
  }
  const proofPaths = [
    ...new Set([
      ...directories,
      guide.path,
      ...resources.flatMap(({ path, kind }) =>
        kind === "artifacts" ? [path] : [path, temporaryPath(path)],
      ),
    ]),
  ].sort();
  function validate(record) {
    exact(record, [
      "schemaVersion",
      "binding",
      "inspection",
      "baseline",
      "pending",
      "receipts",
      "prepared",
    ]);
    assertInit(
      record.schemaVersion === state.inspection.schemaVersion &&
        (record.schemaVersion === 1
          ? record.baseline.schemaVersion === 1
          : record.baseline.schemaVersion === 2 &&
            same(record.baseline.paths, proofPaths) &&
            same(record.baseline.ignorePaths, []) &&
            record.baseline.rootPath === null) &&
        record.binding === binding &&
        record.inspection.workspacePath === targetPath &&
        record.inspection.stateRoot === stateRoot &&
        record.baseline.workspacePath === targetPath &&
        Array.isArray(record.receipts) &&
        typeof record.prepared === "boolean",
      "Publication belongs to another reviewed setup.",
    );
    const seen = new Set();
    for (const receipt of record.receipts) {
      exact(receipt, ["path", "observed"]);
      const resource = resources.find(({ path }) => path === receipt.path);
      assertInit(
        !seen.has(receipt.path) &&
          receipt.observed.binding.path === receipt.path &&
          (resource && resource.kind !== "artifacts"
            ? receipt.observed.binding.kind === "file" &&
              receipt.observed.file?.contentHash === hashText(resource.content)
            : directories.has(receipt.path) &&
              receipt.observed.binding.kind === "directory"),
        "Infrastructure publication receipt is invalid.",
      );
      seen.add(receipt.path);
    }
    if (record.pending !== null) {
      const pending = record.pending;
      exact(pending, [
        "path",
        "directory",
        "reuse",
        "intent",
        "identity",
        "temporary",
      ]);
      const resource = resources.find(({ path }) => path === pending.path);
      assertInit(
        typeof pending.directory === "boolean" &&
          typeof pending.reuse === "boolean" &&
          !seen.has(pending.path) &&
          pending.intent.path === pending.path &&
          (pending.directory
            ? directories.has(pending.path) &&
              pending.reuse === false &&
              !pending.intent.before.exists
            : resource &&
              pending.intent.before.binding.path === pending.path &&
              pending.reuse ===
                (resource.action === "reuse" ||
                  resource.kind === "artifacts") &&
              pending.intent.content === resource.content &&
              same(
                pending.intent.before.binding.identity,
                record.baseline.entries.find(
                  ({ path }) => path === pending.path,
                )?.identity ?? null,
              ) &&
              pending.intent.temporaryPath === temporaryPath(resource.path) &&
              (pending.intent.before.file?.contentHash ?? null) ===
                (resource.kind === "artifacts" ? null : resource.beforeHash)),
        "Infrastructure publication intent no longer matches its reviewed resource.",
      );
    }
    assertInit(
      !record.prepared ||
        (record.pending === null &&
          resources.every(({ path }) => seen.has(path))),
      "Prepared infrastructure is incomplete.",
    );
  }
  let current = publication === null ? null : structuredClone(publication);
  async function save(patch) {
    const next = { ...current, ...patch };
    validate(next);
    await runtime.persist(structuredClone(next));
    current = next;
  }
  async function verifyClarifications() {
    await runtime.clarifications.freezeTranscript({
      artifactRoot: state.inspection.taskPath,
      transcriptPath: join(state.inspection.taskPath, "clarifications.md"),
      expectedHash: state.clarificationHash,
    });
  }
  async function guard() {
    await runtime.assertLease();
    await verifyClarifications();
    if (placement === "external") await assertExternalControls(state, runtime);
    const after = await workspace.snapshot({ inspection: current.inspection });
    const allowed = new Set(current.receipts.map(({ path }) => path));
    if (current.pending !== null) {
      allowed.add(current.pending.path);
      if (current.pending.intent.temporaryPath)
        allowed.add(current.pending.intent.temporaryPath);
    }
    if (current.prepared)
      for (const path of runtime.guidancePaths ?? []) allowed.add(path);
    if (current.schemaVersion === 2)
      workspace.assertSnapshotProof({
        before: current.baseline,
        after,
        allowedPaths: [...allowed],
      });
    else {
      const unchanged = (snapshot) =>
        snapshot.entries.filter(({ path }) => !allowed.has(path));
      assertInit(
        same(unchanged(current.baseline), unchanged(after)) &&
          same(current.baseline.linkResolutions, after.linkResolutions),
        "Setup inputs or workspace content changed outside reviewed publication.",
      );
    }
    for (const receipt of current.receipts) {
      const observed = await workspace.inspectInfrastructure({
        projectPath,
        path: receipt.path,
      });
      assertInit(
        same(observed, receipt.observed),
        "A published infrastructure resource changed.",
      );
    }
  }
  if (current === null) {
    await runtime.assertLease();
    await verifyClarifications();
    assertInit(
      same(await runtime.inspectSetup(), state.inspection),
      "Reviewed setup bindings changed before publication.",
    );
    await (
      placement === "integrated" ? assertIntegratedPolicy : assertExternalPolicy
    )(state, runtime);
    // These exact files may be atomically replaced by reviewed Runner effects.
    // Tree snapshots, intents and receipts still bind their bytes and identities;
    // separate immutable input bindings would reject the authorized replacement.
    const replaceableDocuments = new Set([
      guide.path,
      ...resources
        .filter((resource) => isFinalizationRepair(state, resource))
        .map(({ path }) => path),
    ]);
    const inspection = await workspace.inspect({
      workspacePath: targetPath,
      stateRoot,
      inputPaths: [
        state.inspection.taskPath,
        ...Object.values(state.inspection.documents)
          .flat()
          .map(({ path }) => path)
          .filter((path) => !replaceableDocuments.has(path)),
      ],
      configurationPaths: state.inspection.configurationPaths,
      infrastructurePaths: state.inspection.roots.filter(
        (path) => path !== targetPath,
      ),
    });
    assertInit(
      inspection.bindings.length <= 10_000 &&
        inspection.controlPaths.length <= 10_000,
      "Init publication scope evidence exceeds its supported capacity.",
    );
    const baseline = await workspace.snapshot({ inspection });
    assertInit(
      same(await runtime.inspectSetup(), state.inspection),
      "Reviewed setup changed during publication preparation.",
    );
    await verifyClarifications();
    current = {
      schemaVersion: state.inspection.schemaVersion,
      binding,
      inspection,
      baseline:
        state.inspection.schemaVersion === 1
          ? baseline
          : workspace.snapshotProof({ snapshot: baseline, paths: proofPaths }),
      pending: null,
      receipts: [],
      prepared: false,
    };
    await save({});
  } else {
    validate(current);
  }
  if (runtime.verifyOnly) {
    await guard();
    // A pending ignore publication must reconcile before its new exclusions
    // can be required. Its exact intent and baseline remain guarded above.
    const ignore = resources.find(({ kind }) => kind === "ignore");
    if (!ignore || current.receipts.some(({ path }) => path === ignore.path))
      await verifyIgnoring();
    return {
      inspection: current.inspection,
      snapshot: await workspace.snapshot({ inspection: current.inspection }),
    };
  }
  async function settle() {
    await guard();
    const pending = current.pending;
    if (
      !resources.some(
        ({ path, kind }) => path === pending.path && kind === "ignore",
      )
    )
      await verifyIgnoring();
    let result;
    if (pending.directory) {
      result = await workspace.publishInfrastructureDirectory({
        projectPath,
        stateRoot,
        intent: pending.intent,
        identity: pending.identity,
        publishDirectory: runtime.publishDirectory,
        assertAuthorized: runtime.assertLease,
        recordIdentity: (identity) =>
          save({ pending: { ...current.pending, identity } }),
      });
    } else if (pending.reuse) {
      result = await workspace.inspectInfrastructure({
        projectPath,
        path: pending.path,
      });
      assertInit(
        same(result, pending.intent.before),
        "Reused infrastructure changed.",
      );
    } else {
      result = await workspace.publishInfrastructureFile({
        projectPath,
        intent: pending.intent,
        temporary: pending.temporary,
        assertAuthorized: runtime.assertLease,
        recordTemporary: (temporary) =>
          save({ pending: { ...current.pending, temporary } }),
      });
    }
    const observed = await workspace.inspectInfrastructure({
      projectPath,
      path: pending.path,
    });
    assertInit(
      pending.directory
        ? same(observed.binding, result)
        : pending.reuse
          ? same(observed, result)
          : observed.file?.contentHash === hashText(pending.intent.content) &&
            same(observed.file.identity, result.identity),
      "Infrastructure publication readback failed.",
    );
    await guard();
    await save({
      pending: null,
      receipts: [...current.receipts, { path: pending.path, observed }],
    });
  }
  if (current.pending !== null) await settle();
  for (const resource of resources) {
    await guard();
    if (resource.kind !== "ignore") await verifyIgnoring();
    if (current.receipts.some(({ path }) => path === resource.path)) continue;
    const directories = [];
    for (
      let path =
        resource.kind === "artifacts" ? resource.path : dirname(resource.path);
      path !== projectPath;
      path = dirname(path)
    ) {
      assertInit(
        within(projectPath, path),
        "Publication directory escaped its target.",
      );
      if (
        (await workspace.inspectInfrastructure({ projectPath, path })).binding
          .exists
      )
        break;
      directories.unshift(path);
    }
    for (const path of directories) {
      await guard();
      const intent = await workspace.inspectInfrastructureDirectory({
        projectPath,
        stateRoot,
        path,
      });
      assertInit(
        !intent.before.exists,
        "An unowned infrastructure directory appeared.",
      );
      await save({
        pending: {
          path,
          directory: true,
          reuse: false,
          intent,
          identity: null,
          temporary: null,
        },
      });
      await settle();
    }
    if (current.receipts.some(({ path }) => path === resource.path)) continue;
    const before = await workspace.inspectInfrastructure({
      projectPath,
      path: resource.path,
    });
    const original = current.baseline.entries.find(
      ({ path }) => path === resource.path,
    );
    assertInit(
      (resource.kind === "artifacts"
        ? before.binding.kind === "directory"
        : (before.file?.contentHash ?? null) === resource.beforeHash) &&
        same(before.binding.identity, original?.identity ?? null),
      "Reviewed resource changed before publication.",
    );
    const intent = {
      path: resource.path,
      before,
      content: resource.content,
      temporaryPath: temporaryPath(resource.path),
    };
    await save({
      pending: {
        path: resource.path,
        directory: false,
        reuse: resource.action === "reuse" || resource.kind === "artifacts",
        intent,
        identity: null,
        temporary: null,
      },
    });
    await settle();
    if (resource.kind === "ignore") await verifyIgnoring();
  }
  async function verifyIgnoring() {
    if (placement === "external") return;
    for (const path of integratedIgnorePaths(state)) {
      const evidence = await runtime.inspectIgnored(path);
      assertInit(
        evidence.ignored && !evidence.tracked,
        "Integrated setup exclusions are not effective.",
      );
    }
  }
  await guard();
  await verifyIgnoring();
  if (!current.prepared) await save({ prepared: true });
  return structuredClone(current);
}
