import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import path from "node:path";
import test from "node:test";
import {
  PLATFORMS,
  SOURCE_FINDING_IDS,
  verifyNativeReviewInputs,
  verifyNativeReviewInputsCommand,
  observationDigest,
  sourceReviewDigest,
  releaseClosureDigest,
  nativePackageInput,
  nativePackageReviewDigest,
  nativePolicyTemplateDigest,
  initializeNativeJob,
  admitCompositionPlan,
} from "./index.js";
import {
  linuxSystemRecipes,
  linuxReviewedManifestDigest,
} from "./linux/index.js";

const C = "a".repeat(40),
  H = "b".repeat(64);
const helper = Buffer.from("Synthetic helper source.\n");
// Any evaluation would throw: this suite only supplies and inspects bytes.
const entry = Buffer.from('throw new Error("Entry must never execute");\n');
const digest = (value) => createHash("sha256").update(value).digest("hex");
const approval = (platform, manifestSha256) => ({
  candidateSha: C,
  platform,
  manifestSha256,
  authority: "operator-protected",
});
function fixture(version = 2, templates = false) {
  const source = {
    schemaVersion: 2,
    candidateSha: C,
    inspected: SOURCE_FINDING_IDS.map((id, index) => ({
      id,
      kind: "implementation",
      url: `https://example.org/${C}/fixture-${index}.c`,
      revision: C,
      sha256: digest(index ? helper : entry),
      binding: "VERIFIED",
      complete: true,
      summary: "Synthetic source and API review.",
    })),
    findings: SOURCE_FINDING_IDS.map((id) => ({
      id,
      status: "CLOSED",
      sourceIds: [id],
    })),
    hypotheses: [],
    missingInputs: [],
    citations: SOURCE_FINDING_IDS.flatMap((id, index) =>
      ["reached-code", "api-contract"].map((kind) => ({
        findingId: id,
        sourceId: id,
        kind,
        member:
          "candidate/ci/native/" +
          (index ? "linux/file-helper.c" : "native-effects.mjs"),
        firstLine: 1,
        lastLine: 1,
        sha256: digest(index ? helper : entry),
      })),
    ),
  };
  const build = {
    schemaVersion: 1,
    candidateSha: C,
    sourceSha256: digest(helper),
    compilerVersion: "13.2.0",
    inputs: ["/usr/bin/x86_64-linux-gnu-gcc-13", "/usr/include/stdlib.h"].map(
      (target) => ({ source: target, target, sha256: H }),
    ),
  };
  const abi = [{ target: "/lib/x86_64-linux-gnu/libc.so.6", sha256: H }];
  const linuxManifest = {
    schemaVersion: 1,
    candidateSha: C,
    build: structuredClone(build),
    release: {
      schemaVersion: 1,
      candidateSha: C,
      buildPinsSha256: observationDigest(build),
      components: [
        ...["node", "bubblewrap", "git", "compiler", "file-helper"].map(
          (name) => ({
            name,
            version:
              name === "compiler"
                ? build.compilerVersion
                : name === "file-helper"
                  ? "1"
                  : "synthetic",
            sha256: H,
          }),
        ),
        ...[
          ["build-input", build.inputs],
          ["abi", abi],
        ].flatMap(([prefix, values]) =>
          values.map(({ target, sha256 }) => ({
            name: prefix + "-" + digest(target).slice(0, 32),
            version: "unversioned",
            sha256,
          })),
        ),
      ].map((component) => ({
        ...component,
        ...Object.fromEntries(
          ["publication", "source", "build", "license"].map((key) => [
            key,
            { id: "synthetic", sha256: H },
          ]),
        ),
      })),
      unresolvedAssumptions: [...SOURCE_FINDING_IDS],
    },
    abi,
  };
  const template = {
    schemaVersion: 1,
    candidateSha: C,
    platform: "linux",
    sourceReviewSha256: sourceReviewDigest(source),
    provisioningReviewSha256: H,
    policy: { command: ["synthetic"] },
    bindings: [],
  };
  const templateSha = nativePolicyTemplateDigest(template);
  const release = {
    schemaVersion: templates ? 2 : 1,
    candidateSha: C,
    platform: "linux",
    image: PLATFORMS.find(({ os }) => os === "linux").image,
    osBuild: "synthetic",
    sdkBuild: "synthetic",
    ...(templates ? { policyTemplates: [templateSha] } : { policySha256: H }),
    privileges: ["private-owner"],
    components: ["helper", "codex", "claude"].map((id) => ({
      id,
      role: id === "helper" ? "helper" : "executable",
      sha256: H,
      format: "elf-x64",
      loader: [],
      bindings: Object.fromEntries(
        ["publication", "source", "build", "license", "abi"].map((key) => [
          key,
          H,
        ]),
      ),
    })),
    providers: Object.fromEntries(
      ["codex", "claude"].map((id) => [
        id,
        { reviewSha256: H, closureSha256: H, members: [id] },
      ]),
    ),
  };
  const manifest = {
    schemaVersion: version,
    candidateSha: C,
    platform: "linux",
    source,
    release,
    execution: null,
    tools: [
      {
        name: "compiler",
        path: "/usr/bin/x86_64-linux-gnu-gcc-13",
        version: "13.2.0",
        sha256: H,
      },
      {
        name: "sdk",
        path: "/usr/bin/x86_64-linux-gnu-ld.bfd",
        version: "2.42",
        sha256: H,
      },
    ].map((tool) => ({ ...tool, ...(version === 2 ? { bytes: 1 } : {}) })),
    inputs: [
      {
        path: "/usr/include/stdlib.h",
        sha256: H,
        ...(version === 2 ? { bytes: 1 } : {}),
      },
    ],
    helpers: [{ name: "file-helper", sourceSha256: digest(helper), sha256: H }],
    environment: {},
    capabilitySha256: digest(entry),
    linuxBuild: build,
  };
  if (version === 2) {
    const packages = ["codex", "claude"].map((provider) => {
      const input = nativePackageInput(provider + "-linux");
      const reviewed = {
        schemaVersion: 1,
        candidateSha: C,
        packageId: input.id,
        archiveBytes: input.bytes ?? 1,
        bindings: Object.fromEntries(
          [
            "publication",
            "source",
            "build",
            "dependencies",
            "license",
            "abi",
            "transport",
            "extraction",
          ].map((key) => [
            key,
            {
              url:
                "https://example.org/" +
                (key === "source" && input.sourceRevision
                  ? input.sourceRevision
                  : "synthetic"),
              revision: key === "source" ? input.sourceRevision : null,
              sha256: H,
            },
          ]),
        ),
        files: [
          { path: input.entrypoint, bytes: 1, sha256: H, executable: true },
        ],
      };
      const approvedReviewSha256 = nativePackageReviewDigest(reviewed);
      release.providers[provider].reviewSha256 = approvedReviewSha256;
      const directory = "/synthetic/" + provider;
      manifest.inputs.push({
        path: directory + "/content/" + input.entrypoint,
        bytes: 1,
        sha256: H,
      });
      return { packageId: input.id, directory, reviewed, approvedReviewSha256 };
    });
    manifest.prerequisites = {
      schemaVersion: 1,
      candidateSha: C,
      platform: "linux",
      assets: [
        {
          name: "file-helper.c",
          kind: "source",
          member: "bootstrap/file-helper.c",
          path: "/synthetic/bootstrap/file-helper.c",
          bytes: helper.length,
          sha256: digest(helper),
          bindings: {
            source: digest(helper),
            build: H,
            toolchain: observationDigest(manifest.tools),
            loader: H,
          },
        },
      ],
      packages,
    };
  }
  manifest.execution = {
    schemaVersion: templates ? 2 : 1,
    candidateSha: C,
    platform: "linux",
    tier: "system",
    sourceReviewSha256: sourceReviewDigest(source),
    releaseReviewSha256: releaseClosureDigest(release),
    ...(templates
      ? {
          policyTemplates: [
            { template, approval: approval("linux", templateSha) },
          ],
        }
      : {}),
    cases: linuxSystemRecipes().map((recipe) => ({
      ...recipe,
      ...(templates ? { templateSha256: templateSha } : { policySha256: H }),
      reviewSha256: H,
    })),
  };
  return {
    candidateSha: C,
    platform: "linux",
    manifest,
    capabilityBytes: entry,
    systemReviewSha256: observationDigest(manifest),
    linuxManifest,
    linuxReviewSha256: linuxReviewedManifestDigest(linuxManifest, C),
    templateReviews: templates ? [approval("linux", templateSha)] : [],
  };
}
const readCandidate = async (member) => {
  if (member === "ci/native/native-effects.mjs") return entry;
  assert.equal(member, "ci/native/linux/file-helper.c");
  return helper;
};
const verify = (value, options = {}) =>
  verifyNativeReviewInputs(value, { readCandidate, ...options });
const resign = (value) => {
  value.systemReviewSha256 = observationDigest(value.manifest);
  return value;
};

test("review verification reports approved metadata without native custody or admission", async () => {
  for (const version of [1, 2]) {
    const value = fixture(version),
      result = await verify(value);
    assert.equal(result.status, "METADATA_VERIFIED");
    assert.equal(result.references.system, observationDigest(value.manifest));
    assert.equal(
      result.references.linux,
      linuxReviewedManifestDigest(value.linuxManifest, C),
    );
    assert.equal(result.approvals.system, value.systemReviewSha256);
    assert.equal(result.candidateEntryBound, version === 2);
    assert.equal(result.prerequisiteCustodyRequired, version === 2);
    assert.equal(result.nativeCustody, "NOT_OBSERVED");
    assert.equal(result.nativeAdmission, "NOT_OBSERVED");
  }
});

test("candidate, platform and independent approval mismatches fail before candidate reads", async () => {
  for (const change of [
    (v) => {
      v.candidateSha = "c".repeat(40);
    },
    (v) => {
      v.platform = "darwin";
      v.linuxManifest = v.linuxReviewSha256 = null;
    },
    (v) => {
      v.systemReviewSha256 = null;
    },
    (v) => {
      v.linuxReviewSha256 = null;
    },
  ]) {
    const value = fixture();
    change(value);
    let reads = 0;
    await assert.rejects(
      verify(value, {
        readCandidate: async () => {
          reads++;
          return entry;
        },
      }),
    );
    assert.equal(reads, 0);
  }
});

test("candidate entry, helper and reached-code boundaries reject substituted or oversized bytes", async () => {
  const value = fixture();
  await assert.rejects(
    verify({ ...value, capabilityBytes: Buffer.from("substituted") }),
  );
  for (const member of [
    "ci/native/native-effects.mjs",
    "ci/native/linux/file-helper.c",
  ])
    await assert.rejects(
      verify(value, {
        readCandidate: async (name) =>
          name === member ? Buffer.from("substituted") : readCandidate(name),
      }),
    );
  await assert.rejects(
    verify(value, { readCandidate: async () => Buffer.alloc(2097153) }),
  );
  value.manifest.source.citations[0].lastLine = 100;
  value.manifest.execution.sourceReviewSha256 = sourceReviewDigest(
    value.manifest.source,
  );
  await assert.rejects(verify(resign(value)));
  const revision = fixture();
  revision.manifest.source.inspected[0].revision = "c".repeat(40);
  revision.manifest.execution.sourceReviewSha256 = sourceReviewDigest(
    revision.manifest.source,
  );
  await assert.rejects(verify(resign(revision)));
});

test("execution template approvals are independent of the system manifest schema", async () => {
  for (const version of [1, 2]) {
    const value = fixture(version, true);
    await assert.rejects(verify({ ...value, templateReviews: [] }));
    const result = await verify(value);
    assert.equal(result.templateReviewsRequired, true);
    assert.equal(result.prerequisiteCustodyRequired, version === 2);
    assert.deepEqual(
      result.approvals.templates,
      value.templateReviews.map((review) => review.manifestSha256),
    );
    const job = initializeNativeJob(
      {
        candidateSha: C,
        platform: "linux",
        repository: "example/native",
        runId: "1",
        runAttempt: 1,
      },
      { schemaVersion: 6, tier: "system" },
    );
    job.reviews.source = approval(
      null,
      sourceReviewDigest(value.manifest.source),
    );
    job.reviews.release = approval(
      "linux",
      releaseClosureDigest(value.manifest.release),
    );
    assert.throws(() =>
      admitCompositionPlan(
        job,
        linuxSystemRecipes(),
        value.manifest.execution,
        approval("linux", observationDigest(value.manifest.execution)),
        value.manifest.source,
        value.templateReviews,
      ),
    );
  }
});

test("asynchronous candidate reads cannot replace the captured approved metadata", async () => {
  const value = fixture(),
    substituted = Buffer.from("Substituted helper.\n");
  await assert.rejects(
    verify(value, {
      readCandidate: async (member) => {
        if (member.endsWith("file-helper.c")) {
          value.manifest.helpers[0].sourceSha256 = digest(substituted);
          for (const fact of value.manifest.source.inspected.slice(1))
            fact.sha256 = digest(substituted);
          for (const citation of value.manifest.source.citations.slice(2))
            citation.sha256 = digest(substituted);
          return substituted;
        }
        return readCandidate(member);
      },
    }),
  );
});

test("metadata capture preserves closed records and never invokes accessors or serialization hooks", async () => {
  for (const change of [
    (v) => {
      v.platform = {
        [Symbol.toPrimitive]: () => assert.fail("Platform coercion executed"),
      };
    },
    (v) => {
      Object.defineProperty(v.manifest, "hidden", { value: true });
    },
    (v) => {
      Object.setPrototypeOf(v.manifest, { inherited: true });
    },
    (v) => {
      Object.setPrototypeOf(v.manifest, null);
    },
    (v) => {
      v.manifest.source.inspected[0].toJSON = () =>
        assert.fail("Serialization hook executed");
    },
    (v) => {
      Object.defineProperty(v.manifest.source, "candidateSha", {
        enumerable: true,
        get: () => assert.fail("Accessor executed"),
      });
    },
  ]) {
    const value = fixture();
    change(value);
    await assert.rejects(verify(value), (error) => {
      assert.notEqual(error.code, "ERR_ASSERTION");
      return true;
    });
  }
  const value = fixture();
  Object.setPrototypeOf(value.manifest.source, null);
  await verify(value); // Source evidence already permits null-prototype data.
});

test("the read-only command refuses missing candidate objects without lazy acquisition", async () => {
  const value = fixture();
  const files = new Map([
    ["system-inputs.json", Buffer.from(JSON.stringify(value.manifest))],
    ["linux-review.json", Buffer.from(JSON.stringify(value.linuxManifest))],
    ["native-effects.mjs", entry],
  ]);
  let fetched = 0;
  await assert.rejects(
    verifyNativeReviewInputsCommand(
      [
        "--candidate",
        C,
        "--platform",
        "linux",
        "--candidate-repository",
        "/synthetic/repository",
        "--inputs",
        "/synthetic/reviewed",
        "--system-review",
        value.systemReviewSha256,
        "--linux-review",
        value.linuxReviewSha256,
      ],
      {
        readFile: async (file, maximum = 2097152) => {
          const bytes = files.get(path.basename(file));
          assert.ok(bytes.length <= maximum);
          return bytes;
        },
        execute: async (command, args, options) => {
          assert.equal(command, "git");
          assert.equal(options.env.GIT_OPTIONAL_LOCKS, "0");
          const [operation, mode, member] = args.slice(3);
          assert.ok(["ls-tree", "cat-file"].includes(operation));
          assert.ok(
            Number.isSafeInteger(options.maxBuffer) && options.maxBuffer > 0,
          );
          if (operation === "ls-tree")
            return {
              stdout: Buffer.from(`100644 blob ${C}\t${args.at(-1)}\n`),
            };
          if (mode === "-t") return { stdout: Buffer.from("commit\n") };
          if (member === C + ":ci/native/native-effects.mjs")
            return { stdout: entry };
          assert.equal(member, C + ":ci/native/linux/file-helper.c");
          if (options.env.GIT_NO_LAZY_FETCH === "1")
            throw new Error("Missing local object");
          fetched++;
          return { stdout: helper };
        },
      },
    ),
    /Missing local object/u,
  );
  assert.equal(fetched, 0);
});

test("Linux normalization preserves approval semantics and rejects incompatible build and ABI data", async () => {
  const value = fixture();
  value.linuxManifest.build = Object.fromEntries(
    Object.entries(value.linuxManifest.build).reverse(),
  );
  await verify(value); // Linux hashes normalized data, unlike the enclosing raw system JSON.
  const incompatible = fixture();
  incompatible.manifest.linuxBuild.compilerVersion = "13.3.0";
  await assert.rejects(verify(resign(incompatible)));
  const abi = fixture();
  abi.linuxManifest.abi[0].sha256 = "c".repeat(64);
  await assert.rejects(verify(abi));
  const reordered = fixture();
  reordered.manifest = Object.fromEntries(
    Object.entries(reordered.manifest).reverse(),
  );
  await assert.rejects(verify(reordered));
});

test("declared inventories and package closure cannot substitute for reviewed inputs", async () => {
  for (const change of [
    (v) => {
      v.manifest.helpers.push({ ...v.manifest.helpers[0] });
    },
    (v) => {
      v.manifest.tools[0].path = "/usr/bin/unreviewed-compiler";
    },
    (v) => {
      v.manifest.prerequisites.assets[0].bindings.toolchain = H;
    },
    (v) => {
      v.manifest.prerequisites.assets[0].bytes++;
    },
    (v) => {
      v.manifest.prerequisites.packages[0].approvedReviewSha256 = H;
    },
    (v) => {
      v.manifest.inputs.pop();
    },
    (v) => {
      v.manifest.execution.schemaVersion = 2;
    },
  ]) {
    const value = fixture();
    change(value);
    await assert.rejects(verify(resign(value)));
  }
});
