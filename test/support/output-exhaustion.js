import {
  AgentBoundaryError,
  PROVIDER_REGISTRY,
} from "../../src/agents/index.js";
import { createDispositionPolicy } from "../../src/runner/dispositions.js";

export function outputExhaustion({
  commit = false,
  proof = true,
  effect = "possible",
} = {}) {
  return new AgentBoundaryError(
    { code: "ERR_CODEX_OUTPUT_EXHAUSTED" },
    {
      failureClass: "turn_output_exhausted",
      checkpoint: commit ? "commit" : "turn",
      outcome: "rejected",
      effect,
      retry: "terminal",
      disposition: "output_exhausted",
      ...(commit && proof ? { commitExecutor: "not_started" } : {}),
    },
  );
}

export function attachOutputExhaustion(fixture) {
  fixture.runtime.outputExhaustion = createDispositionPolicy({
    providers: PROVIDER_REGISTRY,
    disposition: "output_exhausted",
  });
}
