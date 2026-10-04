// rust-v0.160.0: CLI stdio transport and model-provider-info custom Responses API.
export function codexInvocation(spec, token) {
  return {
    environment: { CODEX_HOME: spec.home, NATIVE_POC_TOKEN: token },
    arguments: [
      "-c",
      'model_provider="native_poc"',
      "-c",
      "model=" + JSON.stringify(spec.model),
      "-c",
      'model_providers.native_poc.name="Native PoC"',
      "-c",
      "model_providers.native_poc.base_url=" +
        JSON.stringify(spec.endpoint + "/v1"),
      "-c",
      'model_providers.native_poc.env_key="NATIVE_POC_TOKEN"',
      "-c",
      "model_providers.native_poc.requires_openai_auth=false",
      "-c",
      'model_providers.native_poc.wire_api="responses"',
      "app-server",
      "--listen",
      "stdio://",
    ],
  };
}
