import {
  AgentBoundaryError,
  AUTHENTICATION_REQUIRED_DISPOSITION,
  normalizeFailureRecord,
} from "../agents/index.js";

// Only the provider-neutral disposition crosses this boundary. Pipelines own
// checkpoint persistence after reconciling any permitted workspace changes.
export function createAuthenticationPolicy({ providers }) {
  const failureClasses = [
    ...new Set(
      providers.list().flatMap(({ failures }) => [...failures.classes]),
    ),
  ];

  function failure(value) {
    try {
      const record = normalizeFailureRecord(value, failureClasses);
      return record.disposition === AUTHENTICATION_REQUIRED_DISPOSITION
        ? record
        : null;
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
            disposition: AUTHENTICATION_REQUIRED_DISPOSITION,
            commitExecutor: "not_started",
          })
        : null;
    },
  });
}
