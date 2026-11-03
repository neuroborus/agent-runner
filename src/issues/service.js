import { createGitService } from "../git/index.js";
import { createRunStore } from "../state/index.js";
import { createUnexpectedIssueReporter } from "./publication.js";

const REPORT_TOOL = "unexpected_issue_report";

export function createIssueService({
  git = createGitService(),
  runStore = createRunStore(),
  ...publicationOptions
} = {}) {
  const reporter = createUnexpectedIssueReporter({
    ...publicationOptions,
    git,
  });

  async function report(input) {
    const projectPath = await git.resolveProject(input.projectPath);
    const boundary = await runStore.validateStateBoundary({
      projectPath,
      taskPath: projectPath,
    });
    const { idempotencyKey, ...argumentsWithoutKey } = input;
    const argumentsValue = {
      ...argumentsWithoutKey,
      projectPath: boundary.projectPath,
    };
    const identity = {
      key: idempotencyKey,
      tool: REPORT_TOOL,
      arguments: argumentsValue,
    };
    const existing = await runStore.readAction(identity);
    if (existing?.status === "completed") {
      return existing.result;
    }
    const action = await runStore.beginAction({
      ...identity,
      context: {
        issuesPath: null,
        publicationPhase: null,
        projectPath: null,
        reportPath: null,
        temporaryPath: null,
      },
    });
    try {
      if (action.record.status === "completed") {
        return action.record.result;
      }
      const recordContext = async (identityValue) => {
        await action.updateContext({
          ...action.record.context,
          ...identityValue,
        });
      };
      const reportPath = await reporter.report(argumentsValue, {
        reservedIssuesPath: action.record.context.issuesPath,
        reservedPath: action.record.context.reportPath,
        reservedPublicationPhase: action.record.context.publicationPhase,
        reservedProjectPath: action.record.context.projectPath,
        reservedTemporaryPath: action.record.context.temporaryPath,
        prepare: recordContext,
        publish: recordContext,
        reserve: recordContext,
      });
      const receipt = { reportPath };
      await action.complete(receipt);
      return receipt;
    } finally {
      await action.release();
    }
  }

  return Object.freeze({ report });
}
