import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  loadProjectConfiguration,
  parseProjectConfiguration,
  projectConfigurationRejection,
} from "../config/index.js";
import {
  createGuidanceService,
  GuidanceError,
  validateGuidanceContent,
  guidanceContentRejection,
} from "../guidance/index.js";

// Root composition only. Pipelines receive confined services, never Git effects.
export function createSetupRuntime({
  run,
  workspace,
  git,
  runStore,
  providers,
  loadConfiguration,
  executionLease,
  getRun = () => run,
  extendReadScope,
  assertLease = async () => {},
  publishDirectory,
  withInfrastructureOwnership,
}) {
  const projectPath = run.projectPath;
  const stateRoot = resolve(runStore.rootPath);
  let configuration;
  const loadSetupConfiguration = () =>
    (configuration ??= Promise.resolve().then(loadConfiguration));
  const inspectIgnored = async (path) => {
    const root = await workspace.exclusionPath({ workspacePath: projectPath });
    const marker = await workspace.inspectPath({
      projectPath: root,
      path: join(root, ".git"),
    });
    return marker.exists
      ? git.inspectPath({ projectPath: root, path })
      : { ignored: true, tracked: false };
  };
  const load = async ({ configurationPath }) => {
    const root = await workspace.exclusionPath({ workspacePath: projectPath });
    const gitWorkspace = (
      await workspace.inspectPath({
        projectPath: root,
        path: join(root, ".git"),
      })
    ).exists;
    return loadProjectConfiguration({
      projectPath,
      configurationPath,
      providers,
      workspaceKind: gitWorkspace ? "git" : "directory",
      runnerConfiguration: await loadSetupConfiguration(),
      inspectPath: async ({ path }) => ({
        ...(await workspace.inspectPath({ projectPath, path })),
        ...(await inspectIgnored(path)),
        relativePath: relative(projectPath, path),
      }),
    });
  };
  const guidance = createGuidanceService({
    workspace,
    git,
    runStore,
    loadConfiguration: loadSetupConfiguration,
  });
  const guidanceIdentity = (input) => ({
    key: input.idempotencyKey,
    tool: "guidance_update",
    arguments: {
      projectPath,
      projectConfigurationPath: input.projectConfigurationPath,
      localContentHash: input.localContentHash,
      expectedHash: input.expectedHash,
    },
  });
  return Object.freeze({
    workspace,
    stateRoot,
    assertLease,
    publishDirectory,
    inspectIgnored,
    extendReadScope,
    validateGuidance: validateGuidanceContent,
    resultRejection: (cause) =>
      guidanceContentRejection(cause) ?? projectConfigurationRejection(cause),
    validateConfiguration: async (source) =>
      parseProjectConfiguration(
        source,
        await loadSetupConfiguration(),
        providers,
      ),
    loadProjectConfiguration: load,
    inspectConfigurationPath: (request) => workspace.inspectPath(request),
    async discover(state) {
      const paths = [
        ...new Set(
          [
            run.projectConfigurationProtection?.path,
            state.requestedConfigurationPath,
            state.clarificationSelection.configurationPath,
            state.selection?.configurationPath,
            ...(state.inspection?.candidates ?? []).map(
              ({ configurationPath }) => configurationPath,
            ),
          ].filter(Boolean),
        ),
      ];
      const candidates = [];
      for (const path of paths) {
        const binding = await workspace.inspectPath({
          path,
          projectPath: dirname(path),
        });
        if (binding.exists) candidates.push(path);
      }
      const inspection = await workspace.inspect({
        workspacePath: projectPath,
        taskPath: run.taskPath,
        stateRoot,
        infrastructurePaths: getRun().workspace.policy.infrastructurePaths,
      });
      const snapshot = await workspace.snapshot({ inspection });
      // Complete capture protects sources; discovery projects only setup files.
      // The init owner rejects an unsupported evidence inventory in full.
      const documents = {
        instructions: [],
        checks: [],
        skills: [],
        guidance: [],
      };
      for (const { path, kind } of snapshot.entries) {
        if (kind !== "file") continue;
        const name = basename(path);
        if (["AGENTS.md", "CLAUDE.md"].includes(name))
          documents.instructions.push(path);
        if (["package.json", "Makefile", "justfile"].includes(name))
          documents.checks.push(path);
        if (path.endsWith("/skills/finalization/SKILL.md"))
          documents.skills.push(path);
        if (path.endsWith("/agent-runner/rules.md"))
          documents.guidance.push(path);
      }
      return {
        projectPath,
        taskPath: run.taskPath,
        stateRoot,
        artifactRoot: state.artifactRoot,
        placement: state.clarificationSelection.placement,
        configurationPath: state.clarificationSelection.configurationPath,
        configurationPaths: run.workspace.policy.configurationPaths,
        candidatePaths: candidates,
        documents,
      };
    },
    async guidancePaths(intent) {
      if (intent === null) return [];
      const record = await runStore.readAction(guidanceIdentity(intent));
      const paths = [intent.path];
      if (
        record &&
        ["writing", "prepared"].includes(record.context.phase) &&
        /^\.rules\.[a-f0-9-]{36}\.tmp$/u.test(
          record.context.temporaryName ?? "",
        )
      )
        paths.push(join(dirname(intent.path), record.context.temporaryName));
      return paths;
    },
    readGuidance: (input) => guidance.readWithIdentity(input),
    async publishGuidance(
      intent,
      localContent,
      assertPublicationLease = assertLease,
    ) {
      await assertPublicationLease();
      const receipt = await guidance.updateUnderLease(
        {
          projectPath,
          projectConfigurationPath: intent.projectConfigurationPath,
          idempotencyKey: intent.idempotencyKey,
          expectedHash: intent.expectedHash,
          localContent,
        },
        assertPublicationLease,
        intent.beforeIdentity,
      );
      const current = await guidance.readWithIdentity({
        projectPath,
        projectConfigurationPath: intent.projectConfigurationPath,
      });
      const action = await runStore.readAction(guidanceIdentity(intent));
      const expected = receipt.updated
        ? action?.context.temporaryIdentity
        : intent.beforeIdentity;
      const comparable = (identity) =>
        identity === null || identity === undefined
          ? identity
          : Object.fromEntries(
              Object.entries(identity).filter(
                ([key]) => !receipt.updated || key !== "ctimeNs",
              ),
            );
      if (
        current.localHash !== receipt.localHash ||
        !isDeepStrictEqual(
          comparable(current.localIdentity),
          comparable(expected),
        )
      )
        throw new GuidanceError(
          "Published guidance identity changed before setup acknowledgement.",
          { code: "ERR_GUIDANCE_RECOVERY" },
        );
      return receipt;
    },
    async withInfrastructureLease(state, operation) {
      const path = relative(run.workspace.leasePath, state.selection.rootPath);
      const covered =
        path === "" ||
        (!isAbsolute(path) && path !== ".." && !path.startsWith(`..${sep}`));
      // A directory target's enclosing worktree may already exclusively cover
      // its external sibling. Do not contend with that same held ownership.
      if (state.selection.placement === "integrated" || covered)
        return operation(assertLease);
      return withInfrastructureOwnership(
        state.selection.rootPath,
        async (lease) => {
          const assertBoth = async () => {
            await assertLease();
            await runStore.assertWorkspaceLease(
              executionLease,
              lease,
              state.selection.rootPath,
            );
          };
          // Root retains live ownership when release must wait for recovery.
          return operation(assertBoth);
        },
      );
    },
  });
}
