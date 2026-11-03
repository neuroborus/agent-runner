import { basename } from "node:path";

import {
  normalizeSessionNamingContext,
  normalizeSessionNamingDiagnostic,
} from "../agents/index.js";

function description(value) {
  return (
    [
      ...value
        .replace(/[\p{Cc}\p{Zl}\p{Zp}\u202a-\u202e\u2066-\u2069]/gu, " ")
        .replace(/\s+/gu, " ")
        .trim(),
    ]
      .slice(0, 128)
      .join("")
      .trim() || "project"
  );
}

// Only a created child may receive a naming diagnosis. Awaiting acknowledgement
// makes its durable lineage independent of optional provider metadata work.
export function sessionNamingRequest(
  run,
  pipeline,
  role,
  request,
  recordNaming,
) {
  const sessionNaming = normalizeSessionNamingContext({
    runId: run.runId,
    project: description(basename(run.projectPath)),
    pipeline: description(pipeline.id),
    role: description(role),
  });
  let child;
  const created = new Set();
  const diagnosed = new Set();
  return {
    ...request,
    sessionNaming,
    async onSessionCreated(sessionId) {
      if (
        typeof sessionId !== "string" ||
        !sessionId.trim() ||
        sessionId.length > 1024 ||
        /[\p{Cc}\p{Zl}\p{Zp}]/u.test(sessionId) ||
        sessionId === run.sessionLineage.source ||
        sessionId === request.session?.id ||
        created.has(sessionId) ||
        typeof request.onSessionCreated !== "function"
      )
        throw new TypeError(
          "Created child session acknowledgement is invalid.",
        );
      created.add(sessionId);
      await request.onSessionCreated(sessionId);
      child = sessionId;
    },
    async onSessionNaming(value) {
      const diagnosis = normalizeSessionNamingDiagnostic(value);
      if (child === undefined || diagnosed.has(child))
        throw new TypeError(
          "Session naming requires a newly acknowledged child.",
        );
      diagnosed.add(child);
      await recordNaming(role, child, diagnosis);
    },
  };
}
