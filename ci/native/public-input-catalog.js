// Reviewed public provenance, separate from supplied bytes. Null means unresolved;
// no moving revision or guessed platform artifact URL is used as a byte binding.
const SRT_REVISION = "6f0ce155ccb136bda33a8a72201fe7f54fe47d9b";
const SRT_ARCHIVE =
  "https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/-/sandbox-runtime-0.0.78.tgz";
const SRT_ARCHIVE_SHA =
  "a9cf9e35068a4c71d2d94de8b0abe8de51c7d44daef537cc92906848ccc67240";
const SRT_METADATA =
  "https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/0.0.78";
const SRT_KEYS = "https://registry.npmjs.org/-/npm/v1/keys";
const SRT_REPOSITORY = "https://github.com/anthropics/sandbox-runtime";
const SRT_SOURCE = `https://raw.githubusercontent.com/anthropics/sandbox-runtime/${SRT_REVISION}/`;

function file(
  path,
  kind,
  url,
  bytes = null,
  sha256 = null,
  gitBlobSha1 = null,
  archiveSha256 = null,
) {
  return { path, kind, url, bytes, sha256, gitBlobSha1, archiveSha256 };
}

const RELEASE_MEMBERS = [
  [
    "package/dist/index.d.ts",
    2900,
    "a134f24b78f4e11cf9ec584e6161a68829f3ef4b1a13a7567af16fb10dea4c3c",
  ],
  [
    "package/dist/sandbox/macos-sandbox-utils.d.ts",
    5070,
    "9ad1e07a425dbb9fff7132ae61a429a57881f5aa9fc18be7c63edfb86a4679f3",
  ],
  [
    "package/dist/sandbox/macos-sandbox-utils.js",
    56045,
    "acb89435d05939bacc93fce50755e8199739de41ca1ea7a00b5599eef0d5f43a",
  ],
  [
    "package/dist/sandbox/sandbox-manager.d.ts",
    4918,
    "ceed3bb718a84f1b8bbe502e6b351169ddc4f4f37dd855b38086451be825a79d",
  ],
  [
    "package/dist/sandbox/sandbox-manager.js",
    91776,
    "d3ebcfe582a1ed2b5178cd2a6bda296e97175aa39de824ece5a61fb28d01edac",
  ],
  [
    "package/dist/sandbox/windows-sandbox-utils.d.ts",
    40637,
    "a7bc8d6b271c7f4d1ac96f897dbee18fba4d9c39bfa96015f94c5a334b655be0",
  ],
  [
    "package/dist/sandbox/windows-sandbox-utils.js",
    63298,
    "2a651f7e337c508ff8c299f86c15772f245fa064bb4c1d8976b4955e2484575d",
  ],
  [
    "package/vendor/srt-win/build.ts",
    638,
    "5e27cf1cd3fd6b0952870ba8eb9410a796c28f3b6f22546fb092e2cf31713a78",
  ],
];
const SOURCE_MEMBERS = [
  [
    "vendor/srt-win-src/src/job.rs",
    5521,
    "a4c729c97e67cdf055a9f664da63c54edec73446e666cdfd45519c3ecd36c37c",
    "d9d3f19c2b061fb7ae43dd94437223b3a09aa561",
  ],
  [
    "vendor/srt-win-src/src/logon.rs",
    19417,
    "1bd52b19b81a39fe725170c7dd87bdb40938f90388f629c44b1975e828db1ac7",
    "f2482f4ab7d4ac10107d5c2255e34d85ea522066",
  ],
  [
    "vendor/srt-win-src/src/runner.rs",
    9371,
    "ad3ff6c7249ad0e30fbac8894ee41ab5b6eb86f6aebc4ec529b232dbec586b03",
    "eee26105dd4c279f43416d23e0883c389400ba4c",
  ],
  [
    "vendor/srt-win-src/src/self_protect.rs",
    8757,
    "d7da443a8cff5388730b819dd9f0cef0e3192616cfaccd820ac55d95a0b5c1ab",
    "643820ea476ba7fa04f65167840afa4cfc96ad35",
  ],
  [
    "vendor/srt-win-src/src/cli.rs",
    77275,
    "6d4879a547c2c4f5f83ad88025b1ccd4722c76c61e526258e97eec6e21214137",
    "25c32ff3406aec720612ebde3d84b64d8d7f0cee",
  ],
  [
    "vendor/srt-win-src/src/launch.rs",
    33337,
    "b8304db36889e6f02cb58aadfbc9a8a36a8b6f5b3479812ee29daa1a45ac3e55",
    "6322363388d2cf43eb0c45e7d03a20f30dc225d2",
  ],
  [
    "vendor/srt-win-src/Cargo.toml",
    1857,
    "281fb1762ecf788466eb61c184078c51184da197c56f426252cf65a3ecf60e38",
    "8493e7d487a2dd6f1a2e0f060c54b471e3e76500",
  ],
  [
    "vendor/srt-win-src/Cargo.lock",
    13464,
    "c41cf41050c2b1e2986ed7ca690a703415cabadfed9219788a451df0da0967ec",
    "aa84cda1f9f343438cc85cd5ba744ca650698262",
  ],
  [
    "LICENSE",
    11339,
    "1210bc93eb85dd786c33192d5bcb7153a93922fa99fbc1512af6a7199cb41080",
    "fe95f74680c8c8023153ebaeceb8ce03e523d75a",
  ],
  [
    "package.json",
    2570,
    "65f2b0d30573a6401e68f76a54e669b0da3fe667c6956ee24d4cefd5850b0667",
    "6e333b23e2caf931318df1306256ddd356000d53",
  ],
];
const MISSING_RUST_MEMBERS = [
  ["acl.rs", "0efb5956f1014ded976c412fe285874c07df25d1"],
  ["ambient.rs", "31f2b19da5f19c3dfef2bcf1edb961d379e7151d"],
  ["cert_store.rs", "7264891fd87c2a274d3680c020a90a0bf4166439"],
  ["dpapi.rs", "791da972d723e40e2916269d7c978a0e7fefa28b"],
  ["install.rs", "93aabb52eb9de90d1857282718565649d0fad806"],
  ["lib.rs", "2021803cf80fc13efc11cb5804132aee857ed7e8"],
  ["main.rs", "6de82ea7b0a1b87c6c7a671633b403c089f5a72f"],
  ["path_id.rs", "00d63d7243a481f48024994e1ed3a73ff709d62c"],
  ["reg.rs", "59ce478bcdcc8a18c84f1c6134ddcecf85affc7a"],
  ["sam.rs", "f073ce1cf5979e61b9c5951b7872483649642fda"],
  ["sid.rs", "27819f81b48b45d99dfe6162679c8baa2f0fbffd"],
  ["state_db.rs", "d3778f4e639bab273183f7516eccd337beeabf94"],
  ["token.rs", "f739bf31705ee796a100ff3e68e9065deaea6a57"],
  ["user.rs", "12080eeec7296adaece0c629ce96ca79f12993bf"],
  ["util.rs", "27e11cc4dbf2f30863b882f2fa0c4f1323a4b962"],
  ["wfp.rs", "5515e8ea349f48f5d8141ed3d116cf0b4e9bd94a"],
  ["winsta.rs", "610338e7bc9fdbb914200beed96a111f851d8e61"],
];

function freeze(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export const PUBLIC_INPUT_REQUIREMENTS = freeze([
  {
    id: "srt-release",
    version: "0.0.78",
    revision: null,
    findings: ["A-WIN-ADMISSION", "A-RELEASE-CLOSURE"],
    urls: [SRT_METADATA, SRT_ARCHIVE, SRT_KEYS],
    priorArchive: {
      status: "PRIOR_VERIFIED",
      metadataUrl: SRT_METADATA,
      archiveUrl: SRT_ARCHIVE,
      keysUrl: SRT_KEYS,
      sha256: SRT_ARCHIVE_SHA,
      integrity:
        "sha512-YAIcybXTp7MZkBjasnkR1E3yxnf7u6kUkyW0vZrtsAZ9tyJGMaugWETmquPZs0YvW0sR0VnZeMfS0gsN/wQiVQ==",
      signatureKeyIds: ["SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"],
      gitHead: null,
      rustSourceMembers: [],
    },
    files: [
      ...RELEASE_MEMBERS.map(([path, bytes, sha256]) =>
        file(path, "member", SRT_ARCHIVE, bytes, sha256, null, SRT_ARCHIVE_SHA),
      ),
      file("archive.tgz", "archive", SRT_ARCHIVE, null, SRT_ARCHIVE_SHA),
      ...[
        "package/package.json",
        "package/LICENSE",
        "package/vendor/build-common.js",
      ].map((path) =>
        file(path, "member", SRT_ARCHIVE, null, null, null, SRT_ARCHIVE_SHA),
      ),
      file(
        "package/vendor/srt-win/x64/srt-win.exe",
        "binary",
        SRT_ARCHIVE,
        null,
        null,
        null,
        SRT_ARCHIVE_SHA,
      ),
    ],
    license:
      "Released LICENSE and complete packaged licensing are missing; upstream Apache-2.0 is not a packaged-helper license proof.",
    buildInputs: [
      "package/vendor/srt-win/build.ts delegates to missing vendor/build-common.js and vendor/srt-win-src.",
      "Full published package.json, dist closure, npm lock proposal and lifecycle/build-script review are missing.",
    ],
    abi: [
      "Packaged x64 Windows PE, SDK/runtime imports and release build inputs are unbound.",
    ],
    setupPrivileges: [
      "Account, WFP, ACL, registry and recovery authority require reached-source review before admission.",
    ],
    missing: [
      "Full release manifest, LICENSE, dist closure, build-common.js and x64 helper bytes.",
      "Published gitHead is absent; the archive contains no Rust source members.",
      "Release/tag/tree and build provenance binding the packaged PE to exact Rust source and audited toolchains.",
      "CI-private exact transitive/platform lock proposal with registry/tarball URLs, integrity, licenses and lifecycle scripts.",
    ],
  },
  {
    id: "srt-source",
    version: "0.0.78",
    revision: SRT_REVISION,
    findings: ["A-WIN-ADMISSION", "A-RELEASE-CLOSURE"],
    urls: [
      SRT_REPOSITORY,
      `${SRT_REPOSITORY}/tree/${SRT_REVISION}`,
      `https://api.github.com/repos/anthropics/sandbox-runtime/contents/vendor/srt-win-src/src?ref=${SRT_REVISION}`,
    ],
    priorArchive: null,
    files: [
      ...SOURCE_MEMBERS.map(([path, bytes, sha256, blob]) =>
        file(
          path,
          ["LICENSE", "package.json"].includes(path) ? "manifest" : "source",
          SRT_SOURCE + path,
          bytes,
          sha256,
          blob,
        ),
      ),
      ...MISSING_RUST_MEMBERS.map(([name, blob]) =>
        file(
          `vendor/srt-win-src/src/${name}`,
          "source",
          SRT_SOURCE + `vendor/srt-win-src/src/${name}`,
          null,
          null,
          blob,
        ),
      ),
    ],
    license:
      "Apache-2.0 in pinned package.json and LICENSE; transitive licenses and packaged-release equivalence remain unproved.",
    buildInputs: [
      "Cargo.toml: Rust edition 2024; src/lib.rs and src/main.rs entry points are missing.",
      "Cargo.lock version 4 pins Windows 0.62.2 and rusqlite 0.32.1 with bundled SQLite; dependency bytes, licenses and build.rs closure are missing.",
      "Release profile: opt-level 2, thin LTO, one codegen unit, stripped symbols.",
      "Bun build helper, TypeScript release build, Rust/MSVC/Windows SDK versions and upstream npm lock are unprepared.",
    ],
    abi: [
      "Real x64 Windows target and Windows SDK/PE imports must be inspected; the non-Windows host shim is not the helper.",
      "Bundled SQLite requires audited C/MSVC inputs; stubbed CC/AR clippy is not reproducibility proof.",
    ],
    setupPrivileges: [
      "Windows account/token/Job, WFP, ACL, registry/state and recovery setup remain hypotheses until the full reached tree is reviewed.",
    ],
    missing: [
      "Pinned entry points and every reached token/Job, account, WFP, ACL, registry/state and recovery module.",
      "Git release/tag metadata and audited build inputs connecting this candidate tree to the released PE.",
      "Separately authorized CI must inspect complete source/dependencies and pin Rust, MSVC, SDK, Bun and TypeScript before reproducibility work; no downloaded scripts run in roles.",
    ],
  },
  {
    id: "codex",
    version: "0.159.2",
    revision: null,
    findings: ["A-PROVIDER-MEDIATION", "A-RELEASE-CLOSURE"],
    urls: [
      "https://registry.npmjs.org/@openai/codex/0.159.2",
      "https://github.com/openai/codex",
    ],
    priorArchive: null,
    files: [
      file(
        "publication.json",
        "manifest",
        "https://registry.npmjs.org/@openai/codex/0.159.2",
      ),
      ...[
        "platform-manifests",
        "release-checksums",
        "build-provenance",
        "licenses",
      ].map((path) => file(path, "manifest", null)),
      file("platform-archives", "archive", null),
      ...[
        "Cargo.toml",
        "Cargo.lock",
        "sandbox-and-setup",
        "tool-registry-and-handlers",
        "app-server-and-schemas",
      ].map((path) => file(path, "source", null)),
    ],
    license:
      "Exact publication, binary and dependency licensing remain unresolved.",
    buildInputs: [
      "Resolve exact platform URLs from the 0.159.2 publication, then prepare checksums, release/build provenance, pinned source and a complete dependency/lifecycle lock proposal.",
    ],
    abi: [
      "x64 Linux, macOS and Windows ABI, toolchains and setup requirements are unprepared.",
    ],
    setupPrivileges: [
      "Platform sandbox/setup and all reached tool/App Server enforcement paths need version-matched review.",
    ],
    missing: [
      "Exact 0.159.2 publication and its named platform manifests/archive URLs; do not substitute local 0.159.3.",
      "Release/checksum/build provenance, pinned Cargo manifests/lockfile, platform sandbox/setup, tool registry/specification, reached handlers and version-matched App Server dispatch/schemas.",
      "Exact transitive/platform dependency, license, lifecycle/build-script, ABI and setup-privilege closure before any installation.",
    ],
  },
  {
    id: "claude",
    version: "2.1.285",
    revision: null,
    findings: ["A-PROVIDER-MEDIATION", "A-RELEASE-CLOSURE"],
    urls: [
      "https://code.claude.com/docs/en/setup",
      "https://claude.ai/install.sh",
      "https://registry.npmjs.org/@anthropic-ai/claude-code/2.1.285",
    ],
    priorArchive: null,
    files: [
      file(
        "publication.json",
        "manifest",
        "https://registry.npmjs.org/@anthropic-ai/claude-code/2.1.285",
      ),
      ...["checksums", "licenses", "build-provenance"].map((path) =>
        file(path, "manifest", null),
      ),
      file("platform-artifacts", "binary", null),
      file("tool-and-enforcement-source", "source", null),
    ],
    license:
      "Claude publication/native licensing and source availability are unresolved; Sandbox Runtime licensing/support does not transfer.",
    buildInputs: [
      "Setup documentation and installer are retrieval locators only; resolve the actual version publication and exact platform URLs without executing the installer.",
    ],
    abi: [
      "Native binaries and npm contents have no demonstrated equivalence; non-Linux ABI/toolchain requirements are missing.",
    ],
    setupPrivileges: [
      "Platform setup privileges and release-bound enforcement implementation remain unprepared.",
    ],
    missing: [
      "Actual 2.1.285 publication, platform artifact URLs, checksums, licensing and any release-bound tool/enforcement implementation it exposes.",
      "Reviewed native/npm equivalence, dependency/lifecycle lock proposal and ABI/setup privileges before installation or admission.",
    ],
  },
  {
    id: "macos",
    version: null,
    revision: null,
    findings: ["A-MAC-OWNERSHIP"],
    urls: ["https://github.com/apple-oss-distributions/xnu"],
    priorArchive: null,
    files: [
      file("build-matched-sdk", "manifest", null),
      ...[
        "bsd/sys",
        "bsd/kern",
        "osfmk/kern",
        "libsyscall/wrappers/libproc",
        "launchd-and-xpc",
      ].map((path) => file(path, "source", null)),
    ],
    license:
      "Exact XNU/SDK and relevant launchd/XPC implementation licensing is unprepared.",
    buildInputs: [
      "Build-matched SDK declarations and an exact XNU tree are required before resolving source member URLs.",
    ],
    abi: [
      "Running macOS build, x64 SDK ABI and callable authority cannot be inferred from older or moving source.",
    ],
    setupPrivileges: [
      "Process identity and coalition/domain privilege, membership and lifecycle; documented launchd/XPC lifecycle authority require current evidence.",
    ],
    missing: [
      "Build-matched SDK and pinned XNU process identity, coalition/domain privilege, membership and lifecycle implementations in the required tree.",
      "Documented launchd/XPC lifecycle interfaces and relevant implementation evidence; unpinned or older source cannot prove current callable authority.",
    ],
  },
]);

// A source reference, never a mapping to the binary running in a future CI job.
export const XNU_SOURCE_REFERENCE = freeze({
  revision: "43a90889846e00bfb5cf1d255cdc0a701a1e05a4",
  tag: "xnu-11417.140.69",
  distributionRevision: "c5dd598fefabbef580b6b286bad79d2c939ee005",
  distributionVersion: "15.6",
  url: "https://github.com/apple-oss-distributions/xnu/tree/43a90889846e00bfb5cf1d255cdc0a701a1e05a4",
  distributionUrl:
    "https://github.com/apple-oss-distributions/distribution-macOS/tree/c5dd598fefabbef580b6b286bad79d2c939ee005",
  binaryBinding: "UNPROVED",
});

export const SYSTEM_BINDING_KINDS = freeze([
  "publication",
  "source",
  "build",
  "dependencies",
  "license",
  "abi",
  "privileges",
  "policy",
]);

function contract(id, interfaces, requirement) {
  return { id, interfaces, requirement };
}

// These are review obligations, not expected package hashes or accepted APIs.
// SDK declarations, exports and semantics need separate candidate-bound pins.
export const SYSTEM_INPUT_REQUIREMENTS = freeze([
  {
    platform: "linux",
    image: "ubuntu-24.04",
    architecture: "x64",
    components: [
      "kernel",
      "sdk",
      "compiler",
      "node",
      "git",
      "observer",
      "bubblewrap",
    ],
    sourceReference: null,
    contracts: [
      contract(
        "namespace",
        ["unshare", "setns", "prctl"],
        "Review namespace admission, credential/capability dropping and immutable confinement.",
      ),
      contract(
        "identity",
        ["procfs", "pid-namespace-init", "process-start-time"],
        "Bind procfs/native process identity and independent namespace retirement; no numeric-PID authority.",
      ),
      contract(
        "files",
        ["openat2", "statx", "renameat2", "close_range", "fsync"],
        "Bind the existing static helper syscall/ABI and descriptor-relative transaction contracts.",
      ),
      contract(
        "tracing",
        [
          "ptrace",
          "PTRACE_O_TRACEFORK",
          "PTRACE_O_TRACECLONE",
          "PTRACE_O_TRACEEXEC",
        ],
        "Review admitted syscall tracing, descendant attribution, denied/successful events and loss detection.",
      ),
      contract(
        "toolchain",
        ["gcc-13", "static-elf-x86-64"],
        "Supply the complete GCC-13 compiler, headers, linker, static libraries and build/license closure.",
      ),
    ],
    missing: [
      "Exact authenticated Linux system packages and their complete dependency/license closure.",
      "Candidate/source-bound GCC-13 snapshot and reviewed compilation/ABI bindings.",
      "Pinned syscall tracer publication/source/build and complete attribution/audit-loss contract.",
    ],
  },
  {
    platform: "darwin",
    image: "macos-15-intel",
    architecture: "x64",
    components: ["kernel", "sdk", "compiler", "node", "git", "observer"],
    sourceReference: XNU_SOURCE_REFERENCE,
    contracts: [
      contract(
        "audit-domain",
        [
          "setaudit_addr",
          "audit_session_join",
          "setgroups",
          "setuid",
          "setgid",
        ],
        "Review fork/spawn credential inheritance, denied credential/session escape and sanitized Mach rights.",
      ),
      contract(
        "identity",
        [
          "proc_listpids",
          "PROC_UID_ONLY",
          "task_name_for_pid",
          "TASK_AUDIT_TOKEN",
          "proc_signal_with_audittoken",
        ],
        "Require actual private libproc exports and task rights; bind pidversion-safe signalling and bounded recovered retirement.",
      ),
      contract(
        "policy",
        ["sandbox_init", "pf_socket_lookup"],
        "Review deny-default Seatbelt and TCP/UDP sender/receiver PF ownership on both directions, no state and effective anchors.",
      ),
      contract(
        "files",
        [
          "openat",
          "fstatat",
          "linkat",
          "renameat",
          "renameatx_np",
          "unlinkat",
          "fsync",
        ],
        "Review no-follow held-parent operations, link accounting, atomic replacement, native aliases and interruption synchronization.",
      ),
      contract(
        "auditing",
        ["auditpipe", "BSM"],
        "Supply actual audit-pipe ABI, successful/failed event selection, UID/session attribution and overflow/drop detection.",
      ),
    ],
    missing: [
      "Actual CI OS/kernel build and reviewed SDK/compiler/export/privilege envelope; macOS 15.6 source does not bind 15.7.9 binary bytes.",
      "Exact system tools, loader/dependency/license closure and reviewed Seatbelt/PF/BSM API contracts.",
      "Build-matched private libproc/task-right availability and complete recovered-retirement/source argument.",
    ],
  },
  {
    platform: "win32",
    image: "windows-2025",
    architecture: "x64",
    components: ["kernel", "sdk", "compiler", "node", "git", "observer", "wdk"],
    sourceReference: null,
    contracts: [
      contract(
        "restricted-token",
        ["CreateRestrictedToken", "AccessCheck", "CreateProcessAsUserW"],
        "Review stripped privileges, restricting SID, private DACL grants, noninteractive desktop and delegation denial.",
      ),
      contract(
        "job-admission",
        [
          "PROC_THREAD_ATTRIBUTE_JOB_LIST",
          "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
          "TerminateJobObject",
          "GetProcessTimes",
        ],
        "Review creation-time no-breakaway admission, suspended release, controlling-handle custody and last-handle-loss retirement.",
      ),
      contract(
        "wfp",
        [
          "FWPM_CONDITION_ALE_USER_ID",
          "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
          "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
          "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
          "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
        ],
        "Supply SDK/WDK token-condition, loopback ALE, persistent-filter precedence and both-principal return-traffic contracts.",
      ),
      contract(
        "files",
        [
          "NtCreateFile",
          "NtSetInformationFile",
          "FILE_OPEN_REPARSE_POINT",
          "FileIdInfo",
          "FileLinkInformation",
          "FileRenameInformation",
          "FileDispositionInformation",
          "FlushFileBuffers",
        ],
        "Review root-relative handles, reparse/stream/alias rejection, volume/file IDs and actual sharing/link/rename/disposition semantics.",
      ),
      contract(
        "auditing",
        ["AuditSetSystemPolicy", "SetSecurityInfo", "EvtSubscribe"],
        "Supply object-access/WFP success/failure event contracts, SID/creation-identity attribution and loss detection.",
      ),
    ],
    missing: [
      "Exact Windows 2025 OS build, MSVC, SDK/WDK package/build/dependency/license closures and callable contracts.",
      "Independent SDK/WDK review of restricted tokens, creation-time Jobs, WFP token/loopback semantics, files and auditing.",
      "Reviewed noninteractive privileged setup, controlling handles and complete out-of-band/helper-loss exclusion argument.",
    ],
  },
]);
