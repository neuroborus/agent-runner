export class PlanExecutionWorkflowError extends Error {
  constructor(
    message,
    {
      cause,
      code = "ERR_PLAN_EXECUTION_WORKFLOW",
      diagnostic,
      diagnostics,
    } = {},
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PlanExecutionWorkflowError";
    this.code = code;
    if (diagnostic !== undefined) {
      this.diagnostic = Object.freeze({ ...diagnostic });
    }
    if (diagnostics !== undefined) {
      this.diagnostics = Object.freeze(
        diagnostics.map((entry) => Object.freeze({ ...entry })),
      );
    }
  }
}
