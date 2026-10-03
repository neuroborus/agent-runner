// Publisher metadata supplies expected archive integrity, never build or API proof.
const CODEX_RELEASE = "https://github.com/openai/codex/releases/";
const NPM = "https://registry.npmjs.org/@anthropic-ai/";

function freeze(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export const CODEX_RELEASE_REFERENCE = freeze({
  tag: "rust-v0.160.0",
  revision: "a956835d020762cb2b570053af06f643a11c0ecc",
  tagObject: "79b1b666f2e8551f8abbbca34957227f67f3f553",
  tagSignature: "UNSIGNED",
  url: `${CODEX_RELEASE}tag/rust-v0.160.0`,
  sourceUrl:
    "https://github.com/openai/codex/tree/a956835d020762cb2b570053af06f643a11c0ecc",
});

export const CLAUDE_WRAPPER_REFERENCE = freeze({
  version: "2.1.285",
  publicationUrl: `${NPM}claude-code/2.1.285`,
  url: `${NPM}claude-code/-/claude-code-2.1.285.tgz`,
  integrity:
    "sha512-frr0DLmVHSDNjw+hC6ZmXMVQ8yH4nNmVcI4lVFzWt0bdPNZP7clOKsuLcqSdwQabIpe6A3NEc3TJfiBVD8B2Bg==",
  dispatcherSource: "UNAVAILABLE",
});

export const NATIVE_PACKAGE_INPUTS = freeze([
  ...[
    [
      "linux",
      "x86_64-unknown-linux-musl",
      160727443,
      "4fcc47ab57f52ff75363951a8761146cd10c8288bd86fed45487dbb204a16b71",
    ],
    [
      "darwin",
      "x86_64-apple-darwin",
      141304442,
      "4d50514b2d8acd81ca8cfee55b667b3dc4f7681b65bf3299ff06b11a064f8861",
    ],
    [
      "win32",
      "x86_64-pc-windows-msvc",
      157444460,
      "7f7fbbc8d6fd4ea2f3b13855ef47ea59663ba7e61fb2e9821df37163b8030891",
    ],
  ].map(([platform, target, bytes, sha256]) => ({
    id: `codex-${platform}`,
    platform,
    version: "0.160.0",
    format: "tar.gz",
    publicationUrl: CODEX_RELEASE_REFERENCE.url,
    url: `${CODEX_RELEASE}download/rust-v0.160.0/codex-package-${target}.tar.gz`,
    bytes,
    integrity: `sha256:${sha256}`,
    entrypoint: `bin/codex${platform === "win32" ? ".exe" : ""}`,
    sourceRevision: CODEX_RELEASE_REFERENCE.revision,
  })),
  ...[
    [
      "linux",
      "6qNST8qKemr+rD9zvUEwEq0UtWt0E5Js8bkbjh13/LM62FiGWcN6IqiJPxybJ2FNd+I3liXq6JYNv/vrGnmAow==",
    ],
    [
      "darwin",
      "iCewQN1vqZSQ1JdvM4NLm6GhhiEjmvdOrJM/mJBxhe/sPpr8yvouC3hR29Jcap15otWilL4fZ97C02K1kcKP0w==",
    ],
    [
      "win32",
      "7TR0I2gOkYBADZlazRQERyP9WHCOKTZPPUSYzoxHP5EdHNvd9ZRYfIHJwydRfECpm6EYjGZ9goB/ACPJOMVdww==",
    ],
  ].map(([platform, integrity]) => ({
    id: `claude-${platform}`,
    platform,
    version: "2.1.285",
    format: "tar.gz",
    publicationUrl: `${NPM}claude-code-${platform}-x64/2.1.285`,
    url: `${NPM}claude-code-${platform}-x64/-/claude-code-${platform}-x64-2.1.285.tgz`,
    bytes: null,
    integrity: `sha512-${integrity}`,
    entrypoint: `package/claude${platform === "win32" ? ".exe" : ""}`,
    sourceRevision: null,
  })),
  {
    id: "git-for-windows",
    platform: "win32",
    version: "2.56.0.windows.1",
    format: "7z.exe",
    publicationUrl:
      "https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.1",
    url: "https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.1/PortableGit-2.56.0-64-bit.7z.exe",
    bytes: 59958024,
    integrity:
      "sha256:eceb5e061aa90df2f69ddd3e90f0030e1b8037a7829934bc40e4be1caa1accc1",
    entrypoint: null,
    sourceRevision: null,
  },
]);

export const PROVIDER_TRANSPORT_REQUIREMENTS = freeze({
  codex: {
    revision: CODEX_RELEASE_REFERENCE.revision,
    paths: [
      "codex-rs/core/src/tools/registry.rs",
      "codex-rs/core/src/tools/handlers/apply_patch.rs",
      "codex-rs/core/src/tools/runtimes/apply_patch.rs",
      "codex-rs/core/src/tools/runtimes/unified_exec.rs",
      "codex-rs/core/src/tools/orchestrator.rs",
      "codex-rs/exec-server/src/local_file_system.rs",
      "codex-rs/exec-server/src/sandboxed_file_system.rs",
      "codex-rs/sandboxing/src/lib.rs",
      "codex-rs/sandboxing/src/manager.rs",
      "codex-rs/protocol/src/protocol.rs",
      "codex-rs/windows-sandbox-rs/src/proc_thread_attr.rs",
      "codex-rs/windows-sandbox-rs/src/process.rs",
      "codex-rs/windows-sandbox-rs/src/token.rs",
      "codex-rs/windows-sandbox-service/src/lib.rs",
      "codex-rs/core/src/tools/mod.rs",
      "codex-rs/model-provider-info/src/lib.rs",
      "codex-rs/model-provider/src/auth.rs",
      "codex-rs/Cargo.toml",
      "codex-rs/Cargo.lock",
      "LICENSE",
      "NOTICE",
      ".github/workflows/rust-release.yml",
      "scripts/codex_package/layout.py",
      "scripts/codex_package/archive.py",
    ],
    controls: [
      "turn/start",
      "ExternalSandbox",
      "AskForApproval::Never",
      "base_url",
      "env_key",
      "requires_openai_auth",
      "wire_api=responses",
    ],
    missing: [
      "Independent complete enabled-route and Cargo/helper/voice/loader/license/build closure review.",
      "Release-bound live endpoint, non-secret relay authentication and unattended model-tool compatibility proof.",
    ],
  },
  claude: {
    revision: null,
    urls: [
      "https://code.claude.com/docs/en/llm-gateway-connect",
      "https://code.claude.com/docs/en/llm-gateway-protocol",
      "https://code.claude.com/docs/en/cli-reference",
    ],
    controls: [
      "ANTHROPIC_BASE_URL",
      "ANTHROPIC_AUTH_TOKEN",
      "--bare",
      "--tools",
      "--permission-mode bypassPermissions",
    ],
    missing: [
      "Exact native package build/ABI/license and bundled dependency notices; dispatcher source is unavailable and the provider must remain opaque and untrusted.",
      "Release-bound gateway, bare/settings/tool and native Windows Bash selection contracts.",
      "Reviewed Git for Windows/Bash source/build/dependency/license closure and data-only 7z extraction tool.",
    ],
  },
});
