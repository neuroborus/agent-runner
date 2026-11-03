import { publicDispatchActivity } from "./dispatch.js";
import { projectOperatorStop } from "./stop-projection.js";
import { normalizePublicActivity, normalizeStopRequest } from "./validation.js";

const MAX_PROJECTION_ACTIVITIES = 1024;
const MAX_PROJECTION_BYTES = 1024 * 1024;

export function projectPublicActivity(event) {
  if (event.activity === null) return null;
  return {
    revision: event.revision,
    recordedAt: event.recordedAt,
    ...publicDispatchActivity(event.activity),
    ...(event.state.stopRequest == null
      ? {}
      : { stop: projectOperatorStop(event.state) }),
  };
}

// Only for byte-certified events. Reuse the owning legacy transformations
// without cloning or semantically normalizing the private historical state.
export function projectCertifiedActivity(event) {
  return projectPublicActivity({
    ...event,
    activity: normalizePublicActivity(event.activity),
    state: {
      pipelineState: event.state.pipelineState,
      stopRequest: normalizeStopRequest(event.state.stopRequest, event.state),
    },
  });
}

// Retain public records only, never their historical states. afterRevision
// marks the last evicted activity; older requests require prefix streaming.
export function createProjection(previous = null) {
  return {
    afterRevision: previous?.afterRevision ?? 0,
    bytes: previous?.bytes ?? 0,
    activities: previous?.activities.slice() ?? [],
  };
}

export function collectProjection(projection, event) {
  const activity = projectPublicActivity(event);
  if (activity === null) return;
  projection.activities.push(activity);
  projection.bytes += Buffer.byteLength(JSON.stringify(activity));
  while (
    projection.activities.length > MAX_PROJECTION_ACTIVITIES ||
    projection.bytes > MAX_PROJECTION_BYTES
  ) {
    const removed = projection.activities.shift();
    projection.bytes -= Buffer.byteLength(JSON.stringify(removed));
    projection.afterRevision = removed.revision;
  }
}
