import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import path from "node:path";
import test from "node:test";
import { observationDigest } from "./observation.js";
import {
  assertSystemPreparationEnvelope,
  initializeNativeJob,
  PLATFORMS,
} from "./index.js";
import { loadLinuxSystemCI } from "./linux/index.js";
import {
  boundSystemEffect,
  acquireSystemCIInputs,
  initialSystemPreparation,
  normalizeSystemPreparation,
  prepareSystemCI,
  recoverSystemCI,
} from "./system-ci.js";

const job = { candidateSha: "a".repeat(40), platform: "linux" };
const bytes = Buffer.from("reviewed synthetic bytes");
const H = createHash("sha256").update(bytes).digest("hex");
const retired = {
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
};

test("preparation rejects mismatched checkout, runtime and actual image before bootstrap", () => {
  for (const { os, image } of PLATFORMS) {
    const candidate = initializeNativeJob(
      {
        candidateSha: job.candidateSha,
        platform: os,
        repository: "example/native",
        runId: "1",
        runAttempt: 1,
      },
      { schemaVersion: 6, tier: "system" },
    );
    const observed = {
      checkoutSha: job.candidateSha,
      nodeVersion: "v24.21.0",
      image: { os, image, architecture: "x64" },
    };
    assert.doesNotThrow(() =>
      assertSystemPreparationEnvelope(candidate, observed),
    );
    for (const mismatch of [
      { ...observed, checkoutSha: "b".repeat(40) },
      { ...observed, nodeVersion: "v24.0.0" },
      { ...observed, image: { ...observed.image, image: null } },
      { ...observed, image: { ...observed.image, architecture: "arm64" } },
      { ...observed, image: { ...observed.image, os: "unsupported" } },
    ])
      assert.throws(() => assertSystemPreparationEnvelope(candidate, mismatch));
  }
});

test("CI input acquisition is credential-free data bound to independent approval and fixed public paths", async () => {
  const source = Buffer.from(
    'throw new Error("Data must never execute during acquisition");',
  );
  const candidate = { ...job, platform: "darwin" };
  const manifest = {
    candidateSha: candidate.candidateSha,
    platform: candidate.platform,
    capabilitySha256: createHash("sha256").update(source).digest("hex"),
  };
  for (const valid of [true, false]) {
    const requests = [],
      files = [];
    const env = {
      CI: "true",
      GITHUB_ACTIONS: "true",
      RUNNER_TEMP: path.resolve("/synthetic/temp"),
      NATIVE_SYSTEM_INPUT_REPOSITORY: "example/reviews",
      NATIVE_SYSTEM_INPUT_REVISION: "b".repeat(40),
      NATIVE_SYSTEM_REVIEW_SHA256: valid ? observationDigest(manifest) : H,
    };
    const result = acquireSystemCIInputs(
      candidate,
      {},
      path.join(env.RUNNER_TEMP, "native-darwin-reviewed"),
      {
        env,
        fetchInput: async (url, options) => {
          assert.equal(options.redirect, "error");
          assert.equal(options.credentials, "omit");
          assert.equal(options.headers, undefined);
          requests.push(url);
          return {
            ok: true,
            body: [
              url.endsWith(".json")
                ? Buffer.from(JSON.stringify(manifest))
                : source,
            ],
          };
        },
        fs: {
          mkdir: async () => {},
          writeFile: async (name, data, options) => {
            assert.equal(options.flag, "wx");
            assert.equal(options.mode, 0o400);
            files.push(name);
          },
        },
        verify: async () => assert.equal(files.length, 2),
      },
    );
    if (valid) {
      await result;
      assert.equal(files.length, 2);
      assert.ok(
        requests.every((url) =>
          url.startsWith(
            `https://raw.githubusercontent.com/example/reviews/${env.NATIVE_SYSTEM_INPUT_REVISION}/ci/native/reviews/${job.candidateSha}/darwin/`,
          ),
        ),
      );
    } else {
      await assert.rejects(result);
      assert.equal(requests.length, 1);
      assert.deepEqual(files, []);
    }
  }
});

function fixture(mutate = () => {}) {
  const journal = [],
    calls = [];
  const profile = {
    imageOS: /^synthetic$/u,
    extension: "",
    sources: ["helper"],
    tools: ["compiler", "sdk"].map((name) => ({
      name,
      args: ["--version"],
      versionExitCodes: [],
    })),
    arguments: (source, target) => [source, target],
    api: async () => ({}),
    inspect: (value) => assert.deepEqual(value, bytes),
    inspectProcess: (value) =>
      assert.equal(value, "synthetic independent native identity"),
  };
  const manifest = {
    tools: profile.tools.map(({ name }) => ({
      name,
      path: `/synthetic/${name}`,
      sha256: H,
      version: "synthetic tool",
    })),
    helpers: [{ name: "helper", sourceSha256: H, sha256: H }],
    environment: {},
  };
  const options = {
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "synthetic",
      NATIVE_SYSTEM_REVIEW_SHA256: H,
    },
    platform: "linux",
    now: () => 0,
    inputs: async () => ({ manifest, read: async () => bytes }),
    fs: {
      mkdir: async () => {},
      readFile: async () => bytes,
      lstat: async () => ({ isFile: () => true, nlink: 1, size: bytes.length }),
    },
    loadCapability: async () => ({
      createBuildEffects: async () => ({
        run: async (request) => {
          assert.equal(journal.at(-1).commands.at(-1).status, "POSSIBLE");
          calls.push(request);
          const result = {
            requestSha256: observationDigest(request),
            toolSha256: H,
            nativeEventSha256: H,
            independent: true,
            settlement: retired,
            exitCode: 0,
            signal: null,
            timedOut: false,
            stdout: "synthetic tool\n",
            stderr: "",
            identity: "synthetic independent native identity",
          };
          mutate(result, request);
          return result;
        },
      }),
    }),
  };
  const persist = async (value) => journal.push(structuredClone(value));
  return { profile, options, persist, journal, calls };
}

test("preparation persists possible build effects and requires independent pinned output", async () => {
  const value = fixture();
  const record = await prepareSystemCI(
    job,
    value.profile,
    "/synthetic/reviewed",
    "/synthetic/private-build",
    value.persist,
    value.options,
  );
  assert.equal(record.status, "PASS");
  assert.equal(value.calls.length, 3);
  assert.deepEqual(normalizeSystemPreparation(record, job), record);
  assert.ok(
    record.commands.every(
      ({ status, receiptSha256 }) => status === "RETIRED" && receiptSha256,
    ),
  );
  for (const mutate of [
    (result) => {
      result.requestSha256 = "b".repeat(64);
    },
    (result) => {
      result.settlement = { ...retired, independent: false };
    },
    (result) => {
      result.settlement = { ...retired, emergencyCleanup: true };
    },
  ]) {
    const failed = fixture(mutate);
    const result = await prepareSystemCI(
      job,
      failed.profile,
      "/synthetic/reviewed",
      "/synthetic/private-build",
      failed.persist,
      failed.options,
    );
    assert.equal(result.status, "FAIL");
    assert.equal(failed.calls.length, 1);
    assert.equal(result.commands[0].status, "POSSIBLE");
    assert.deepEqual(result.helpers, []);
  }
  const mismatched = fixture();
  mismatched.options.fs.readFile = async () => Buffer.from("unreviewed output");
  assert.equal(
    (
      await prepareSystemCI(
        job,
        mismatched.profile,
        "/synthetic/reviewed",
        "/synthetic/private-build",
        mismatched.persist,
        mismatched.options,
      )
    ).status,
    "FAIL",
  );
});

test("preparation reports its reached failure phase without serializing thrown values", async () => {
  const value = fixture(() => {
    throw { output: "private-output", path: "/synthetic/private" };
  });
  const failures = [];
  value.options.onFailure = async (details) => failures.push(details);
  const record = await prepareSystemCI(
    job,
    value.profile,
    "/synthetic/reviewed",
    "/synthetic/build",
    value.persist,
    value.options,
  );
  assert.equal(record.status, "FAIL");
  assert.equal(record.commands[0].status, "POSSIBLE");
  assert.deepEqual(failures, [{ diagnosis: "toolchain", inputs: [] }]);
  assert.doesNotMatch(
    JSON.stringify({ record, failures }),
    /private-output|synthetic\/private/u,
  );
});

test("controller cancellation never supplies native retirement or permits late success", async () => {
  const controller = new AbortController();
  let complete;
  const late = new Promise((resolve) => {
    complete = resolve;
  });
  await assert.rejects(
    boundSystemEffect(
      () => {
        controller.abort();
        return late;
      },
      30000,
      controller.signal,
    ),
    /deadline/u,
  );
  complete({ ...retired });
  await late;
  let invoked = false;
  await assert.rejects(
    boundSystemEffect(
      () => {
        invoked = true;
      },
      30000,
      controller.signal,
    ),
  );
  assert.equal(invoked, false);
});

test("dedicated Linux compilation keeps an unsettled build intent and stops preparation", async () => {
  for (const settled of [true, false]) {
    const value = fixture();
    value.profile.compile = async () => {
      assert.equal(value.journal.at(-1).phase, "build");
      assert.equal(value.journal.at(-1).commands.at(-1).status, "POSSIBLE");
      return {
        settlement: { ...retired, independent: settled },
      };
    };
    const record = await prepareSystemCI(
      job,
      value.profile,
      "/synthetic/reviewed",
      "/synthetic/private-build",
      value.persist,
      value.options,
    );
    assert.equal(record.status, settled ? "PASS" : "FAIL");
    assert.equal(value.calls.length, 2);
    assert.equal(
      record.commands.at(-1).status,
      settled ? "RETIRED" : "POSSIBLE",
    );
  }
});

test("a retired nonzero compiler exit cannot publish a successful helper build", async () => {
  const value = fixture((result, request) => {
    if (request.args[0] !== "--version") result.exitCode = 2;
  });
  const record = await prepareSystemCI(
    job,
    value.profile,
    "/synthetic/reviewed",
    "/synthetic/private-build",
    value.persist,
    value.options,
  );
  assert.equal(record.status, "FAIL");
  assert.equal(record.commands.at(-1).status, "RETIRED");
  assert.deepEqual(record.helpers, []);
});

test("an OS-bundled signer is identified without an unsupported version query", async () => {
  const value = fixture();
  const bundle = await value.options.inputs();
  value.profile.sign = true;
  value.profile.tools.push({ name: "signer", versionByDigest: true });
  bundle.manifest.tools.push({
    name: "signer",
    path: "/synthetic/signer",
    sha256: H,
    version: `sha256:${H}`,
  });
  const record = await prepareSystemCI(
    job,
    value.profile,
    "/synthetic/reviewed",
    "/synthetic/private-build",
    value.persist,
    value.options,
  );
  assert.equal(record.status, "PASS");
  assert.equal(
    record.versions.find(({ name }) => name === "signer").version,
    `sha256:${H}`,
  );
  const calls = value.calls.filter(({ file }) => file === "/synthetic/signer");
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].args.slice(0, 4), [
    "--force",
    "--sign",
    "-",
    "--timestamp=none",
  ]);
});

test("Linux probing rejects a substituted prepared binding without invoking a compiler", async () => {
  let compilations = 0;
  const bundle = await loadLinuxSystemCI(
    job,
    "/synthetic/reviewed",
    "/synthetic/report",
    { commands: [{ receiptSha256: H }] },
    {},
    {
      load: async () => ({
        manifest: { linuxBuild: {} },
        read: async () =>
          Buffer.from(
            JSON.stringify({ build: {}, receipts: [], settlement: {} }),
          ),
        effects: {
          prepare: async () => ({
            options: {
              build: async () => {
                compilations++;
              },
            },
          }),
        },
      }),
    },
  );
  const prepared = await bundle.effects.prepare({ group: "reference" });
  await assert.rejects(
    prepared.options.build(job, bundle.referenceDirectory, {}, {}),
  );
  assert.equal(compilations, 0);
});

test("fresh cleanup binds partial preparation and execution; flags alone cannot settle", async () => {
  const preparation = {
    ...initialSystemPreparation(job),
    reviewSha256: H,
    status: "FAIL",
    phase: "build",
    commands: [{ requestSha256: H, status: "POSSIBLE", receiptSha256: null }],
  };
  for (const valid of [true, false]) {
    const journal = [];
    const effects = {
      recover: async ({ request, preparation: input }) => {
        assert.deepEqual(input, preparation);
        assert.equal(journal[0].status, "POSSIBLE");
        return {
          ...retired,
          requestSha256: valid ? observationDigest(request) : "b".repeat(64),
          nativeEventSha256: H,
        };
      },
    };
    const result = recoverSystemCI(
      job,
      { effects },
      preparation,
      30000,
      async (value) => journal.push(value),
    );
    if (valid) {
      await result;
      assert.equal(journal.at(-1).status, "RETIRED");
      assert.equal(preparation.status, "FAIL");
      assert.equal(preparation.commands[0].status, "POSSIBLE");
    } else {
      await assert.rejects(result);
      assert.equal(journal.at(-1).status, "POSSIBLE");
    }
  }
  assert.throws(() =>
    normalizeSystemPreparation(
      { ...preparation, status: "PASS", phase: "verification" },
      job,
    ),
  );
});
