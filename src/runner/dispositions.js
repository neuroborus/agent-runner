import {
  AgentBoundaryError,
  FAILURE_DISPOSITIONS,
  normalizeFailureRecord,
} from "../agents/index.js";

// Only the provider-neutral disposition crosses this boundary. Pipelines own
// checkpoint persistence after reconciling any permitted workspace changes.
export function createDispositionPolicy({ providers, disposition }) {
  if (!FAILURE_DISPOSITIONS.includes(disposition))
    throw new TypeError("Unsupported provider disposition policy.");
  const failureClasses = [
    ...new Set(
      providers.list().flatMap(({ failures }) => [...failures.classes]),
    ),
  ];

  function failure(value) {
    try {
      const record = normalizeFailureRecord(value, failureClasses);
      return record.disposition === disposition ? record : null;
    } catch {
      return null;
    }
  }

  function eligible(cause) {
    return (
      cause instanceof AgentBoundaryError && failure(cause.failure) !== null
    );
  }

  return Object.freeze({
    eligible,
    hasPossibleEffect(cause) {
      return failure(cause?.failure)?.effect === "possible";
    },
    preEffect(cause) {
      return eligible(cause) &&
        cause.failure.checkpoint === "commit" &&
        cause.failure.commitExecutor === "not_started"
        ? Object.freeze({
            disposition,
            commitExecutor: "not_started",
          })
        : null;
    },
  });
}
