import { posix, win32 } from "node:path";
import {
  CODEX_RELEASE_REFERENCE,
  nativePackageInput,
  observationDigest,
  nativePolicyTemplateDigest,
  nativePolicyContext,
} from "../index.js";
import { protectedProviderRecipes } from "./dispatch.js";
import { providerBytesDigest } from "./preparation.js";
import { linuxProviderCIContract } from "../linux/index.js";
import { darwinProviderCIContract } from "../darwin/index.js";
import { windowsProviderCIContract } from "../win32/index.js";

const bytes = Buffer.from("sealed fixture bytes"),
  hash = providerBytesDigest(bytes);

export function providerPreparationFixture(
  platform = "linux",
  candidateSha = "a".repeat(40),
) {
  const paths = platform === "win32" ? win32 : posix,
    directory =
      platform === "win32" ? "C:\\Fixture\\report" : "/fixture/report",
    sourceDirectory =
      platform === "win32" ? "C:\\Fixture\\sealed" : "/fixture/sealed",
    events = [],
    files = new Map();
  const templates = ["read-only", "workspace-write", "trusted-command"].map(
    (profile) => {
      const template = {
        schemaVersion: 1,
        candidateSha,
        platform,
        sourceReviewSha256: hash,
        provisioningReviewSha256: hash,
        policy: { launch: { profile }, policy: { fixed: true } },
        bindings: [],
      };
      return {
        template,
        approval: {
          candidateSha,
          platform,
          authority: "operator-protected",
          manifestSha256: nativePolicyTemplateDigest(template),
        },
      };
    },
  );
  const closure = {
    schemaVersion: 2,
    policyTemplates: templates
      .map(({ approval }) => approval.manifestSha256)
      .sort(),
    manifestSha256: hash,
    observationSha256: hash,
    sourceReviewSha256: hash,
    providerBindings: { codex: hash, claude: hash },
  };
  const selectedSystem = {
    schemaVersion: 1,
    jobSha256: hash,
    closure,
    binding: {
      artifactId: "1",
      candidateSha,
      platform,
      tier: "system",
      authority: "ordinary",
      conclusion: "success",
      provenance: {
        repository: "example/native",
        workflow: "native-poc.yml",
        runId: "1",
        runAttempt: 1,
        jobId: "1",
      },
    },
  };
  const provenance = {
    repository: "example/native",
    workflow: "native-poc.yml",
    runId: "2",
    runAttempt: 1,
    jobId: "2",
  };
  const context = (executionId) =>
    nativePolicyContext(
      {
        candidateSha,
        platform,
        tier: "provider",
        provenance,
        closure,
        selectedSystem,
      },
      executionId,
    );
  const specifications = protectedProviderRecipes(platform).map(
    (recipe, index) => {
      const input = nativePackageInput(recipe.group + "-" + platform),
        reference = {
          url: "https://example.org/review",
          revision: null,
          sha256: hash,
        };
      return {
        candidateSha,
        nonce: (index + 1).toString(16).padStart(32, "0"),
        provider: recipe.group,
        platform,
        profile: recipe.profile,
        home: paths.join(sourceDirectory, "home"),
        cache: paths.join(sourceDirectory, "cache"),
        path: paths.join(sourceDirectory, "runtime"),
        endpoint: "http://127.0.0.1:41001",
        model: "fixture-model",
        review: {
          schemaVersion: 1,
          candidateSha,
          packageId: input.id,
          archiveBytes: input.bytes ?? 100,
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
              key === "source"
                ? recipe.group === "claude"
                  ? null
                  : {
                      url: CODEX_RELEASE_REFERENCE.sourceUrl,
                      revision: CODEX_RELEASE_REFERENCE.revision,
                      sha256: hash,
                    }
                : reference,
            ]),
          ),
          files: [
            {
              path: input.entrypoint,
              bytes: 100,
              sha256: hash,
              executable: true,
            },
          ],
        },
      };
    },
  );
  const cases = protectedProviderRecipes(platform).map((recipe, index) => ({
    id: recipe.id,
    specification: specifications[index],
    launch: { candidateSha, nonce: specifications[index].nonce },
    custody: { context: context(recipe.id), plan: { sha256: hash } },
    bindings: {
      relayPolicy: {
        provider: recipe.group,
        nonce: specifications[index].nonce,
        model: "fixture-model",
        requests: 32,
        outputTokens: 100,
        budgetMicros: 100,
        inputMicros: 1,
        outputMicros: 1,
        beta: [],
      },
    },
  }));
  const manifest = {
    schemaVersion: 2,
    candidateSha,
    platform,
    inputs: [
      {
        path: paths.join(sourceDirectory, "package"),
        sha256: hash,
        bytes: bytes.length,
      },
    ],
    helpers:
      platform === "linux"
        ? [{ name: "provider-gate", sha256: hash, sourceSha256: hash }]
        : [],
    source: {},
    release: {},
    execution: {
      schemaVersion: 2,
      policyTemplates: templates,
      cases: protectedProviderRecipes(platform).map((recipe) => ({
        ...recipe,
        reviewSha256: hash,
        templateSha256: templates.find(
          ({ template }) => template.policy.launch.profile === recipe.profile,
        ).approval.manifestSha256,
      })),
    },
    providerPreparation: {
      schemaVersion: 1,
      sourceDirectory,
      bootstrap: { context: context("provider-build"), plan: { sha256: hash } },
      cases,
    },
  };
  const input = {
    job: {
      candidateSha,
      platform,
      tier: "provider",
      provenance,
      closure,
      selectedSystem,
      reviews: {
        source: { manifestSha256: hash },
        release: { manifestSha256: hash },
        provider: { manifestSha256: observationDigest(manifest.execution) },
      },
    },
    manifest,
    templateReviews: templates.map(({ approval }) => approval),
    buildManifest: {
      candidateSha,
      platform,
      tools: [
        {
          name: "compiler",
          path: "/usr/bin/x86_64-linux-gnu-gcc-13",
          sha256: hash,
        },
      ],
    },
    directory,
    helpers: paths.join(directory, "platform-build"),
    providerHelpers: paths.join(directory, "provider-build"),
    preparation: null,
  };
  const contracts = {
    linux: linuxProviderCIContract,
    darwin: darwinProviderCIContract,
    win32: windowsProviderCIContract,
  };
  input.api = {
    [{
      linux: "linuxProviderCIContract",
      darwin: "darwinProviderCIContract",
      win32: "windowsProviderCIContract",
    }[platform]]: contracts[platform],
    [{
      linux: "observeLinuxCandidateClosure",
      darwin: "observeDarwinRelease",
      win32: "observeWindowsRelease",
    }[platform]]: async () => {
      events.push("release");
      const { sourceReviewSha256, ...reference } = closure;
      return {
        closure: {
          ...reference,
          observationSha256: "c".repeat(64),
          providerBindings: { codex: "d".repeat(64), claude: "e".repeat(64) },
        },
      };
    },
  };
  for (const member of manifest.inputs) files.set(member.path, bytes);
  for (const helper of manifest.helpers) {
    files.set(paths.join(sourceDirectory, helper.name + ".c"), bytes);
    files.set(paths.join(input.providerHelpers, helper.name), bytes);
  }
  files.set(input.buildManifest.tools[0].path, bytes);
  return {
    input,
    manifest,
    templates,
    context,
    contracts,
    paths,
    files,
    events,
    sourceDirectory,
  };
}
