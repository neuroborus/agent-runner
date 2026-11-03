import { isDeepStrictEqual } from "node:util";

import { preservationError } from "./validation.js";

export function assertPreservationContinuity(previous, current, activity) {
  const before = previous.preservationRecords ?? [];
  const after = current.preservationRecords ?? [];
  if (isDeepStrictEqual(before, after)) return;
  const stationary = ({ preservationRecords, revision, updatedAt, ...state }) =>
    state;
  if (
    activity?.actor !== "runner" ||
    activity.phase !== "preservation" ||
    !isDeepStrictEqual(stationary(previous), stationary(current)) ||
    after.length < before.length ||
    after.length > before.length + 1 ||
    before.some((record, index) => record.id !== after[index]?.id) ||
    after.filter((record, index) => !isDeepStrictEqual(record, before[index]))
      .length !== 1
  )
    throw preservationError();
}
