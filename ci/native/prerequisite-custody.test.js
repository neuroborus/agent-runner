import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import * as filesystem from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { prerequisiteFixture } from "./prerequisite-fixture.js";
import { createPrerequisiteEffects } from "./native-effects.mjs";
import {
  observationDigest,
  nativePackageInput,
  nativePackageReviewDigest,
  normalizeNativePackageReview,
  loadNativeEffects,
} from "./index.js";
import {
  materializeBootstrapAssets,
  materializePrerequisitePackages,
} from "./prerequisites.js";
import { createCapabilityFiles } from "./capability-files.js";
import { nativePackageReceipt } from "./package-acquisition.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const bytes = Buffer.from("reviewed source bytes");
async function fixture() {
  const f = await prerequisiteFixture(),
    manifest = f.input.manifest;
  manifest.schemaVersion = 2;
  manifest.helpers = [
    {
      name: "file-helper",
      sourceSha256: digest(bytes),
      sha256: "c".repeat(64),
    },
  ];
  manifest.tools = [];
  const packages = ["codex-linux", "claude-linux"].map((packageId) => {
    const catalog = nativePackageInput(packageId);
    const ref = {
      url: "https://example.org/review",
      revision: null,
      sha256: "c".repeat(64),
    };
    const reviewed = normalizeNativePackageReview(
      {
        schemaVersion: 1,
        candidateSha: manifest.candidateSha,
        packageId,
        archiveBytes: catalog.bytes ?? 100,
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
          ].map((name) => [
            name,
            name === "source" && catalog.sourceRevision
              ? {
                  ...ref,
                  url: ref.url + "/" + catalog.sourceRevision,
                  revision: catalog.sourceRevision,
                }
              : ref,
          ]),
        ),
        files: [
          {
            path: catalog.entrypoint ?? "bin/fixture",
            bytes: bytes.length,
            sha256: digest(bytes),
            executable: true,
          },
        ],
      },
      manifest.candidateSha,
    );
    return {
      packageId,
      directory: "/private/assets/packages/" + packageId,
      reviewed,
      approvedReviewSha256: nativePackageReviewDigest(reviewed),
    };
  });
  manifest.release = {
    providers: Object.fromEntries(
      packages.map((entry) => [
        entry.packageId.split("-")[0],
        { reviewSha256: entry.approvedReviewSha256 },
      ]),
    ),
  };
  manifest.inputs = packages.flatMap((entry) =>
    entry.reviewed.files.map((file) => ({
      ...file,
      path: entry.directory + "/content/" + file.path,
    })),
  );
  manifest.prerequisites = {
    schemaVersion: 1,
    candidateSha: manifest.candidateSha,
    platform: "linux",
    assets: [
      {
        name: "file-helper.c",
        kind: "source",
        member: "bootstrap/file-helper.c",
        path: "/private/assets/file-helper.c",
        bytes: bytes.length,
        sha256: digest(bytes),
        bindings: {
          source: digest(bytes),
          build: "c".repeat(64),
          toolchain: observationDigest([]),
          loader: "c".repeat(64),
        },
      },
    ],
    packages,
  };
  f.input.approvals.manifestSha256 = observationDigest(manifest);
  f.request = {
    schemaVersion: 1,
    candidateSha: manifest.candidateSha,
    platform: "linux",
    phase: "bootstrap-assets",
    asset: manifest.prerequisites.assets[0],
    url: "https://example.org/asset",
    deadlineMs: 30000,
  };
  f.acquire = (effects) =>
    materializeBootstrapAssets(manifest.prerequisites, {
      env: {
        RUNNER_TEMP: "/private",
        NATIVE_SYSTEM_INPUT_REPOSITORY: "example/native",
        NATIVE_SYSTEM_INPUT_REVISION: "d".repeat(40),
      },
      effects,
      fetchInput: async (url, options) => {
        assert.equal(options.credentials, "omit");
        assert.equal(options.redirect, "error");
        assert.equal(f.events.includes("spawn"), false);
        assert.ok(
          [...f.nodes.keys()].some((name) => name.includes("-record-")),
        );
        return {
          ok: true,
          status: 200,
          url,
          headers: new Headers(),
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(bytes);
              controller.close();
            },
          }),
        };
      },
      persist: async () => async () => {},
      read: (file) => effects.read(file),
    });
  return f;
}

test("fixed entry acquires and seals approved assets through repository file/process owners", async (t) => {
  const f = await fixture();
  t.after(() => f.teardown());
  const effects = createPrerequisiteEffects(f.input, f.edges);
  assert.equal(f.events.length, 0);
  assert.equal(f.handles.size, 0);
  await f.acquire(effects);
  assert.deepEqual(await effects.read(f.request.asset.path), bytes);
  const first = effects.recoveryRecord();
  await effects.persist({ status: "POSSIBLE", request: { phase: "fixture" } });
  const next = effects.recoveryRecord();
  assert.notEqual(first.path, next.path);
  assert.equal(f.nodes.get(first.path).mode, 0o400n);
  assert.equal(f.nodes.get(next.path).mode, 0o400n);
  const settled = await effects.close();
  assert.equal(settled.status, "RETIRED");
  assert.equal(settled.independent, true);
  assert.equal(settled.noLiveMembers, true);
  assert.equal(f.handles.size, 0);
  assert.equal(f.events.filter((event) => event === "spawn").length, 1);
});

test("changed hashes and replaced factory callbacks cannot admit asset creation", async (t) => {
  const f = await fixture();
  t.after(() => f.teardown());
  f.input.createPrerequisiteEffects = () =>
    assert.fail("Operator factory called");
  f.input.api = {
    createPrerequisiteEffects: () => assert.fail("Replacement API called"),
  };
  const effects = createPrerequisiteEffects(f.input, f.edges);
  await assert.rejects(effects.sealAsset(f.request, Buffer.from("changed")));
  assert.equal(f.events.length, 0);
  assert.equal(f.handles.size, 0);
  assert.equal((await effects.close()).status, "CLOSED");
});

test("held asset substitution and surviving custodian independently withhold closure", async (t) => {
  for (const fault of ["substitution", "live"]) {
    const f = await fixture();
    t.after(() => f.teardown());
    const effects = createPrerequisiteEffects(f.input, f.edges);
    await f.acquire(effects);
    if (fault === "substitution") {
      const original = f.nodes.get(f.request.asset.path);
      f.nodes.set(f.request.asset.path, {
        ...original,
        ino: original.ino + 1000n,
      });
      await assert.rejects(effects.verifyAsset(f.request));
    } else f.faults.live = true;
    await assert.rejects(effects.close());
  }
});

test("partial asset creation reconstructs protected records and fresh retirement without adoption", async (t) => {
  const f = await fixture();
  t.after(() => f.teardown());
  const original = new Error("Disconnected writer");
  f.faults.writePath = f.request.asset.path;
  f.faults.write = original;
  const effects = createPrerequisiteEffects(f.input, f.edges);
  await assert.rejects(effects.sealAsset(f.request, bytes));
  const last = effects.recoveryRecord(),
    custodyIntent = f.intent();
  await assert.rejects(effects.close());
  f.expire();
  const reconstructed = createPrerequisiteEffects(f.input, f.edges);
  const result = await reconstructed.recover({ last, custodyIntent });
  assert.equal(result.status, "RETAINED");
  assert.equal(result.admitted, false);
  assert.equal(result.settlement.status, "RETIRED");
  assert.equal(result.records[0].status, "POSSIBLE");
  assert.ok(f.nodes.has(f.request.asset.path));
  await reconstructed.close();
  assert.equal(f.events.filter((event) => event === "spawn").length, 1);
  assert.equal(f.handles.size, 0);
});

test("a missing acquisition receipt cannot skip independent stock custody recovery", async (t) => {
  const f = await fixture();
  t.after(() => f.teardown());
  const effects = createPrerequisiteEffects(f.input, f.edges);
  await f.acquire(effects);
  const last = effects.recoveryRecord(),
    custodyIntent = f.intent();
  await effects.close();
  f.nodes.delete(last.path);
  f.expire();
  const reconstructed = createPrerequisiteEffects(f.input, f.edges);
  let failure;
  await assert.rejects(
    reconstructed.recover({ last, custodyIntent }),
    (error) => {
      failure = error;
      return error.code === "ENOENT";
    },
  );
  assert.ok(
    [...f.nodes.keys()].some((name) =>
      /-recovery-[a-f0-9]+\.json$/u.test(name),
    ),
  );
  await assert.rejects(reconstructed.close(), (error) => error === failure);
  assert.equal(f.events.filter((event) => event === "spawn").length, 1);
  assert.equal(f.handles.size, 0);
});

test("package receipts join fixed integrity and complete staged entrypoints without native admission", async (t) => {
  const f = await fixture();
  t.after(() => f.teardown());
  for (const entry of f.input.manifest.prerequisites.packages) {
    const receipt = nativePackageReceipt(entry.reviewed, entry.directory);
    assert.equal(
      receipt.integrity,
      nativePackageInput(entry.packageId).integrity,
    );
    assert.equal(
      receipt.entrypoint,
      entry.directory + "/content/" + entry.reviewed.files[0].path,
    );
    assert.equal(receipt.admission, "BLOCKED");
  }
});

test("package acquisition rejects unapproved archives before package filesystem writes", async (t) => {
  const f = await fixture();
  t.after(() => f.teardown());
  const effects = createPrerequisiteEffects(f.input, {
    ...f.edges,
    fetchInput: async (url) => ({
      status: 200,
      url,
      headers: new Headers(),
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      }),
    }),
  });
  await assert.rejects(
    materializePrerequisitePackages(f.input.manifest.prerequisites, {
      effects,
      persist: async () => async () => {},
    }),
  );
  assert.equal(f.events.includes("spawn"), false);
  assert.equal(
    [...f.nodes.keys()].some((name) => name.includes("/packages/")),
    false,
  );
  await effects.close();
});

test("package roots require exclusive protected birth and fresh bounded directory observation", async (t) => {
  const f = await fixture();
  t.after(() => f.teardown());
  const files = createCapabilityFiles(f.input, f.edges);
  const root = "/private/assets/package";
  const proof = await files.provisionDirectory(root);
  assert.equal(proof.birthProtected, true);
  assert.ok(
    f.events.indexOf("mkdir:" + root) >
      f.events.findIndex((event) => event.includes("-directory.json")),
  );
  assert.deepEqual((await files.directory(root)).names, []);
  f.add(root + "/unexpected", bytes);
  assert.deepEqual((await files.directory(root)).names, ["unexpected"]);
  await assert.rejects(files.provisionDirectory(root));
  await assert.rejects(files.close());
});

test("complete verification cannot use an injected bootstrap retirement claim", async (t) => {
  const f = await fixture();
  t.after(() => f.teardown());
  const effects = createPrerequisiteEffects(f.input, f.edges);
  const bootstrapRequest = {
    phase: "native-bootstrap",
    candidateSha: f.input.job.candidateSha,
    platform: "linux",
  };
  await effects.persist({ status: "POSSIBLE", request: bootstrapRequest });
  await assert.rejects(
    effects.verifyInputs(
      {
        candidateSha: f.input.job.candidateSha,
        platform: "linux",
        prerequisites: f.input.manifest.prerequisites,
        inputs: f.input.manifest.inputs,
        tools: [],
        bootstrapRequest,
      },
      {
        settlement: {
          status: "RETIRED",
          independent: true,
          noLiveMembers: true,
          emergencyCleanup: false,
        },
      },
    ),
  );
  assert.equal(f.events.includes("spawn"), false);
  await effects.close();
});

test("directory inventory cannot exceed the reviewed package member bound", async (t) => {
  const f = await fixture();
  t.after(() => f.teardown());
  const files = createCapabilityFiles(f.input, f.edges),
    root = "/private/assets/package";
  await files.provisionDirectory(root);
  for (let index = 0; index < 4097; index++)
    f.add(root + "/member-" + index, Buffer.alloc(0));
  await assert.rejects(files.directory(root));
  await assert.rejects(files.close());
});

test("acquired entries must equal the cited checked-in candidate before fixed factory loading", async () => {
  const file = fileURLToPath(new URL("./native-effects.mjs", import.meta.url)),
    capabilityBytes = await filesystem.readFile(file),
    sha256 = digest(capabilityBytes);
  const bundle = {
    capabilityBytes,
    read: (path) => filesystem.readFile(path),
    manifest: {
      schemaVersion: 2,
      capabilitySha256: sha256,
      source: {
        citations: [
          {
            kind: "reached-code",
            member: "candidate/ci/native/native-effects.mjs",
            sha256,
          },
        ],
      },
    },
  };
  const module = await loadNativeEffects(bundle);
  assert.equal(typeof module.createPrerequisiteEffects, "function");
  await assert.rejects(
    loadNativeEffects({
      ...bundle,
      manifest: { ...bundle.manifest, schemaVersion: 1 },
    }),
  );
  const replaced = Buffer.from(
    "throw new Error('Unreviewed entry evaluated');",
  );
  await assert.rejects(
    loadNativeEffects({
      ...bundle,
      capabilityBytes: replaced,
      manifest: { ...bundle.manifest, capabilitySha256: digest(replaced) },
    }),
  );
  await assert.rejects(
    loadNativeEffects({
      ...bundle,
      manifest: { ...bundle.manifest, source: { citations: [] } },
    }),
  );
});
