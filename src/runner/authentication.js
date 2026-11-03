import { AUTHENTICATION_REQUIRED_DISPOSITION } from "../agents/index.js";
import { createDispositionPolicy } from "./dispositions.js";

export function createAuthenticationPolicy({ providers }) {
  return createDispositionPolicy({
    providers,
    disposition: AUTHENTICATION_REQUIRED_DISPOSITION,
  });
}
