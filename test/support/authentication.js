import {
  AgentBoundaryError,
  AUTHENTICATION_REQUIRED_DISPOSITION,
  PROVIDER_REGISTRY,
} from "../../src/agents/index.js";
import { createAuthenticationPolicy } from "../../src/runner/authentication.js";

export function authenticationFailure({ commit = false, effect } = {}) {
  const failureEffect = effect ?? (commit ? "none" : "possible");
  return new AgentBoundaryError(
    { code: "ERR_CODEX_TURN_FAILED" },
    {
      failureClass: "turn_unauthorized",
      checkpoint: commit ? "commit" : "turn",
      outcome: "rejected",
      effect: failureEffect,
      retry: "terminal",
      disposition: AUTHENTICATION_REQUIRED_DISPOSITION,
      ...(commit ? { commitExecutor: "not_started" } : {}),
    },
  );
}

export function attachAuthentication(fixture) {
  fixture.runtime.authentication = createAuthenticationPolicy({
    providers: PROVIDER_REGISTRY,
  });
}

// Interrupt on either side of pause publication. Turn retirement must not
// discard the authentication checkpoint or possible source-fork effect.
export function interruptAuthenticationSettlement(
  fixture,
  { beforePublication = false } = {},
) {
  let interrupted = false;
  function interrupt() {
    interrupted = true;
    throw Object.assign(
      new Error("Owner lost during authentication settlement."),
      { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
    );
  }
  for (const method of ["transition", "finishAgentTurn"]) {
    const original = fixture.runtime[method].bind(fixture.runtime);
    fixture.runtime[method] = async (...args) => {
      if (
        !interrupted &&
        beforePublication &&
        method === "transition" &&
        args[0].pause?.reason === "authentication_required"
      ) {
        interrupt();
      }
      const activeTurn = fixture.currentRun.activeTurn;
      const result = await original(...args);
      if (!interrupted && activeTurn != null && result.activeTurn === null) {
        interrupt();
      }
      return result;
    };
  }
}
