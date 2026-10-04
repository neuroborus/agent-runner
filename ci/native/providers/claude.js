// Published gateway/CLI surface only. The dispatcher remains opaque/untrusted.
export function claudeInvocation(spec, token) {
  return {
    environment: {
      ANTHROPIC_BASE_URL: spec.endpoint,
      ANTHROPIC_AUTH_TOKEN: token,
      ANTHROPIC_MODEL: spec.model,
    },
    arguments: [
      "--bare",
      "--print",
      "--verbose",
      "--input-format",
      "stream-json",
      "--output-format",
      "stream-json",
      "--model",
      spec.model,
      "--permission-mode",
      "bypassPermissions",
      "--tools",
      "Bash,Read,Glob,Grep,Edit,Write",
      "--settings",
      "{}",
    ],
  };
}
