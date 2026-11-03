import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { inspectCandidate } from "../scripts/publish-release.js";
import { OFFICIAL_RELEASE_POLICY } from "../src/config/index.js";
import {
  npmPublicationEnvironment,
  publishRelease,
  selectRelease,
  validateRelease,
} from "../scripts/release-policy.js";

function inputs() {
  const policy = {
    schemaVersion: 1,
    enabled: true,
    repository: "sample/runner",
    packageName: "@sample/runner",
    license: "MIT",
  };
  const metadata = {
    name: policy.packageName,
    version: "1.2.3",
    private: false,
    license: "MIT",
    repository: { type: "git", url: "https://github.com/sample/runner.git" },
    publishConfig: {
      access: "public",
      registry: "https://registry.npmjs.org/",
    },
  };
  return {
    policy,
    metadata,
    event: {
      action: "published",
      repository: { full_name: policy.repository },
      release: { tag_name: "v1.2.3", draft: false, prerelease: false },
    },
    eventName: "release",
    repository: policy.repository,
    ref: "refs/tags/v1.2.3",
    head: "a".repeat(40),
    tagHead: "a".repeat(40),
    inMain: true,
  };
}
const sri = "sha512-" + Buffer.alloc(64).toString("base64");
const publicVersion = { dist: { integrity: sri } };

test("npm receives a complete hosted OIDC/provenance identity without ambient credentials", () => {
  const env = {
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    GITHUB_REPOSITORY: "sample/runner",
    GITHUB_REF: "refs/tags/v1.2.3",
    GITHUB_SHA: "a".repeat(40),
    GITHUB_WORKFLOW_REF:
      "sample/runner/.github/workflows/release.yml@refs/tags/v1.2.3",
    GITHUB_WORKFLOW_SHA: "a".repeat(40),
    GITHUB_WORKFLOW: "Approved npm release",
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_API_URL: "https://api.github.com",
    GITHUB_EVENT_NAME: "release",
    GITHUB_EVENT_PATH: "/synthetic/event.json",
    GITHUB_REPOSITORY_ID: "123",
    GITHUB_REPOSITORY_OWNER_ID: "456",
    GITHUB_RUN_ID: "789",
    GITHUB_RUN_ATTEMPT: "1",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://actions.example.invalid/token",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "synthetic-oidc-request",
    HOME: "/synthetic/personal",
    npm_config_userconfig: "/synthetic/personal/.npmrc",
  };
  const projected = npmPublicationEnvironment(env);
  assert.equal(projected.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(projected.GITHUB_WORKFLOW_SHA, env.GITHUB_WORKFLOW_SHA);
  assert.equal(
    projected.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
    env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
  );
  assert.equal(projected.HOME, undefined);
  assert.equal(projected.npm_config_userconfig, undefined);
  for (const key of [
    "RUNNER_ENVIRONMENT",
    "GITHUB_SHA",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  ])
    assert.throws(() =>
      npmPublicationEnvironment({ ...env, [key]: undefined }),
    );
  assert.throws(() =>
    npmPublicationEnvironment({ ...env, RUNNER_ENVIRONMENT: "self-hosted" }),
  );
  assert.throws(() =>
    npmPublicationEnvironment({
      ...env,
      NPM_TOKEN: "synthetic-registry-credential",
    }),
  );
  assert.throws(() =>
    npmPublicationEnvironment({
      ...env,
      NODE_AUTH_TOKEN: "synthetic-registry-credential",
    }),
  );
});

test("only the approved stable published release selects its exact commit in main", () => {
  const selected = selectRelease(inputs());
  assert.equal(selected.tag, "v1.2.3");
  assert.equal(selected.commit, "a".repeat(40));
  assert.equal(
    selected.npmUrl,
    "https://www.npmjs.com/package/@sample/runner/v/1.2.3",
  );
  const edits = [
    (v) => {
      v.policy.enabled = false;
    },
    (v) => {
      v.policy.license = "UNLICENSED";
    },
    (v) => {
      v.policy.publisherToken = "unsupported";
    },
    (v) => {
      v.metadata.private = true;
    },
    (v) => {
      v.metadata.repository.url = "https://github.com/other/runner.git";
    },
    (v) => {
      v.metadata.repository.url = "git+https://github.com/sample/runner.git";
    },
    (v) => {
      v.metadata.publishConfig.registry = "https://example.invalid/";
    },
    (v) => {
      v.metadata.publishConfig.token = "unsupported";
    },
    (v) => {
      v.metadata.version = "1.2.3-beta.1";
    },
    (v) => {
      v.eventName = "push";
    },
    (v) => {
      v.event.action = "edited";
    },
    (v) => {
      v.event.release.draft = true;
    },
    (v) => {
      v.event.release.prerelease = true;
    },
    (v) => {
      v.event.release.tag_name = "v1.2.4";
    },
    (v) => {
      v.repository = "other/runner";
    },
    (v) => {
      v.ref = "refs/heads/main";
    },
    (v) => {
      v.tagHead = "b".repeat(40);
    },
    (v) => {
      v.inMain = false;
    },
  ];
  for (const edit of edits) {
    const value = inputs();
    edit(value);
    assert.throws(() => selectRelease(value));
  }
});

test("validation tests one prepared artifact with both required slow invocations and seals last", async () => {
  const selected = selectRelease(inputs());
  const candidate = {
    receiptPath: "/synthetic/candidate.json",
    integrity: sri,
  };
  for (const failAt of [
    null,
    "check",
    "prepare",
    "package",
    "slow",
    "inspect",
  ]) {
    const calls = [];
    const effect = (name) => {
      calls.push(name);
      if (failAt === name) throw new Error("controlled interruption");
    };
    const work = validateRelease(selected, {
      run: async (args, env) => {
        const name =
          args[1] === "check"
            ? "check"
            : args.length === 2
              ? "slow"
              : "package";
        if (name !== "check")
          assert.deepEqual(env, {
            AGENT_RUNNER_RELEASE_CANDIDATE: candidate.receiptPath,
          });
        if (name === "package")
          assert.deepEqual(args, [
            "run",
            "test:slow",
            "--",
            "test/package-install.slow.test.js",
          ]);
        effect(name);
      },
      prepare: async () => {
        effect("prepare");
        return candidate;
      },
      inspect: async (path, expected) => {
        assert.equal(path, candidate.receiptPath);
        assert.equal(expected.integrity, sri);
        effect("inspect");
      },
      seal: async () => effect("seal"),
    });
    if (failAt) {
      await assert.rejects(work);
      assert.equal(calls.includes("seal"), false);
    } else {
      assert.equal(await work, candidate);
      assert.deepEqual(calls, [
        "check",
        "prepare",
        "package",
        "slow",
        "inspect",
        "seal",
      ]);
    }
  }
});

test("publication reconciles exact versions without overwriting and reports partial effects", async () => {
  for (const kind of [
    "new",
    "existing",
    "different",
    "ambiguous-completed",
    "ambiguous-absent",
    "lookup-failed",
    "install-failed",
    "substituted",
  ]) {
    let reads = 0;
    let publishes = 0;
    let installs = 0;
    let inspections = 0;
    const result = await publishRelease(selectRelease(inputs()), {
      inspect: async () => {
        inspections++;
        if (kind === "substituted" && inspections === 2)
          throw new Error("changed bytes");
        return { integrity: sri };
      },
      readVersion: async () => {
        if (kind === "lookup-failed") throw new Error("unavailable");
        reads++;
        if (kind === "different") return { dist: { integrity: "different" } };
        if (
          kind === "ambiguous-absent" ||
          (reads === 1 && !["existing", "install-failed"].includes(kind))
        )
          return null;
        return publicVersion;
      },
      publish: async () => {
        publishes++;
        if (kind.startsWith("ambiguous")) throw new Error("lost response");
      },
      verifyInstall: async () => {
        installs++;
        if (kind === "install-failed") throw new Error("public install failed");
      },
    });
    assert.equal(
      publishes,
      ["new", "ambiguous-completed", "ambiguous-absent"].includes(kind) ? 1 : 0,
      kind,
    );
    assert.equal(
      result.status,
      ["new", "ambiguous-completed"].includes(kind)
        ? "published"
        : kind === "existing"
          ? "verified_existing"
          : "partial_failure",
      kind,
    );
    assert.equal(
      installs,
      ["new", "existing", "ambiguous-completed", "install-failed"].includes(
        kind,
      )
        ? 1
        : 0,
      kind,
    );
  }
});

test("candidate inspection binds the uploaded receipt, manifest and actual tarball bytes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-release-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const manifest = {
    schemaVersion: 1,
    name: "@sample/runner",
    version: "1.2.3",
    files: [],
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n");
  const header = Buffer.alloc(512);
  header.write("package/release-manifest.json");
  header.write("0000644\0", 100);
  header.write(manifestBytes.length.toString(8).padStart(11, "0") + "\0", 124);
  header.fill(32, 148, 156);
  header.write("0", 156);
  header.write(
    header
      .reduce((sum, byte) => sum + byte, 0)
      .toString(8)
      .padStart(6, "0") + "\0 ",
    148,
  );
  const bytes = gzipSync(
    Buffer.concat([
      header,
      manifestBytes,
      Buffer.alloc(((512 - (manifestBytes.length % 512)) % 512) + 1024),
    ]),
  );
  const receipt = {
    schemaVersion: 1,
    commit: "a".repeat(40),
    tag: "v1.2.3",
    name: manifest.name,
    version: manifest.version,
    tarball: "candidate.tgz",
    integrity: "sha512-" + createHash("sha512").update(bytes).digest("base64"),
    manifestSha256: createHash("sha256").update(manifestBytes).digest("hex"),
  };
  const path = join(root, "candidate.json");
  await writeFile(path, JSON.stringify(receipt));
  await writeFile(join(root, "manifest.json"), manifestBytes);
  await writeFile(join(root, "candidate.tgz"), bytes);
  const inspected = await inspectCandidate(path, receipt);
  assert.equal(inspected.integrity, receipt.integrity);
  await assert.rejects(inspectCandidate(path, { integrity: sri }));
  await writeFile(
    join(root, "candidate.tgz"),
    Buffer.concat([bytes, Buffer.from("substitution")]),
  );
  assert.deepEqual(inspected.tarballBytes, bytes);
  await assert.rejects(inspectCandidate(path));
  await writeFile(join(root, "candidate.tgz"), bytes);
  await writeFile(join(root, "manifest.json"), Buffer.from("{}"));
  await assert.rejects(inspectCandidate(path));
  await writeFile(join(root, "manifest.json"), manifestBytes);
  await writeFile(
    path,
    JSON.stringify({ ...receipt, tarball: "../candidate.tgz" }),
  );
  await assert.rejects(inspectCandidate(path));
  await writeFile(path, JSON.stringify(receipt));
  await rm(join(root, "candidate.tgz"));
  await symlink(join(root, "manifest.json"), join(root, "candidate.tgz"));
  await assert.rejects(inspectCandidate(path));
});

test("checked-in publication remains disabled and the workflow exposes OIDC only after validation", async () => {
  const policy = OFFICIAL_RELEASE_POLICY;
  assert.equal(policy.enabled, false);
  assert.throws(() => selectRelease({ ...inputs(), policy }));
  const workflow = await readFile(
    new URL("../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /on:\n  release:\n    types: \[published\]/u);
  assert.doesNotMatch(
    workflow,
    /(?:push:|workflow_dispatch:|secrets\.|NODE_AUTH_TOKEN|NPM_TOKEN)/u,
  );
  assert.equal(workflow.match(/id-token: write/gu).length, 1);
  assert.match(workflow, /publish:\n    needs: validate/u);
  assert.match(workflow, /environment: npm-release/u);
  assert.match(
    workflow,
    /artifact-ids: \$\{\{ needs\.validate\.outputs\.artifactId \}\}/u,
  );
  assert.match(
    workflow,
    /name: validated-npm-release-\$\{\{ github\.run_attempt \}\}/u,
  );
  assert.doesNotMatch(workflow, /overwrite: true/u);
  assert.match(
    workflow,
    /EXPECTED_INTEGRITY: \$\{\{ needs\.validate\.outputs\.integrity \}\}/u,
  );
});
