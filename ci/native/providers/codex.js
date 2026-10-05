// rust-v0.160.0: CLI stdio transport and model-provider-info custom Responses API.
// These keys are reached in features/src/lib.rs and core/src/config/mod.rs at
// the reviewed release. Effective registry/configuration inspection is still
// mandatory: model metadata and managed configuration can override defaults.
const DISABLED = Object.freeze([
  "hooks",
  "plugin_hooks",
  "plugins",
  "apps",
  "multi_agent",
  "code_mode",
  "code_mode_only",
  "code_mode_host",
  "code_mode_prewarm",
  "remote_control",
  "deferred_executor",
  "executor_capability_discovery",
  "shell_snapshot",
  "unified_exec_tty",
  "remote_models",
  "responses_websockets",
  "responses_websockets_v2",
  "skill_mcp_dependency_install",
  "skill_search",
  "skill_env_var_dependency_prompt",
  "send_async_message",
  "send_message_to_user_async",
  "standalone_web_search",
  "view_image",
  "sleep_tool",
  "tool_suggest",
  "request_permissions_tool",
  "exec_permission_approvals",
]);
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
      ...[
        'approval_policy="never"',
        'web_search="disabled"',
        'cli_auth_credentials_store="ephemeral"',
        'history.persistence="none"',
        "project_doc_max_bytes=0",
        "allow_login_shell=false",
        // The required host-skill control is under development at this release.
        // Suppress its startup advisory; unexpected warnings still fail proof.
        "suppress_unstable_features_warning=true",
        "notify=[]",
        "mcp_servers={}",
        "features={shell_tool=true,unified_exec=true,skip_host_skill_discovery=true," +
          DISABLED.map((key) => key + "=false").join(",") +
          "}",
      ].flatMap((setting) => ["-c", setting]),
      "app-server",
      "--listen",
      "stdio://",
    ],
  };
}
