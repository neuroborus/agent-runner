import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  CONFIG_SCHEMA_VERSION,
  OFFICIAL_RELEASE_POLICY,
} from "../src/config/index.js";
import { listPipelines } from "../src/index.js";
import {
  inspectRuntimeInstallation,
  prepareRuntime,
} from "../src/runtime/index.js";
import { RUNTIME_COMPATIBILITY } from "../src/state/index.js";
import { createUpdateService } from "../src/update/index.js";
import { runtimeFixture, runtimeFixtureDirectory } from "./support/index.js";

const policy = {
  schemaVersion: 1,
  enabled: true,
  repository: "sample/runner",
  packageName: "@sample/runner",
  license: "MIT",
};
const compatibility = {
  schemaVersion: 1,
  configurationVersion: 1,
  runnerVersion: 1,
  runStateVersion: RUNTIME_COMPATIBILITY.runStateVersion,
  pipelines: { sample: 2 },
};
const metadata = (version) => ({
  name: policy.packageName,
  version,
  private: false,
  license: policy.license,
  repository: { type: "git", url: "https://github.com/sample/runner.git" },
  publishConfig: { access: "public", registry: "https://registry.npmjs.org/" },
  engines: { node: ">=24 <25" },
  agentRunnerCompatibility: structuredClone(compatibility),
});

function service({
  installed = "1.0.0",
  running = installed,
  stable = metadata("1.1.0"),
  selected,
  installation = {},
  request,
} = {}) {
  const queries = [];
  let inspections = 0;
  const updater = createUpdateService({
    policy,
    readInstallation: async () => {
      inspections++;
      return {
        installedMetadata: metadata(installed),
        runningMetadata: metadata(running),
        developmentManaged: false,
        nodeVersion: "v24.1.0",
        canWriteInstallation: true,
        ...installation,
      };
    },
    fetch: async (url, options) => {
      queries.push(url);
      assert.equal(options.redirect, "error");
      assert.equal(options.credentials, "omit");
      assert.ok(options.signal instanceof AbortSignal);
      if (request) return request(url);
      return Response.json(url.endsWith("/latest") ? stable : selected);
    },
  });
  return { updater, queries, inspections: () => inspections };
}

test("published compatibility metadata matches current configuration, state and pipeline contracts", async () => {
  const root = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(root.agentRunnerCompatibility, {
    schemaVersion: 1,
    configurationVersion: CONFIG_SCHEMA_VERSION,
    ...RUNTIME_COMPATIBILITY,
    pipelines: Object.fromEntries(
      listPipelines().map(({ id, stateVersion }) => [id, stateVersion]),
    ),
  });
});

test("checks are on demand and no newer version is a successful no-op", async () => {
  for (const stable of ["1.0.0", "0.9.0", "1.0.0+rebuilt"]) {
    const f = service({
      stable: metadata(stable),
      installation: { canWriteInstallation: false },
    });
    assert.equal(f.inspections(), 0);
    assert.deepEqual(f.queries, []);
    const result = await f.updater.check();
    assert.equal(result.status, "current");
    assert.deepEqual(result.blockers, []);
    assert.equal(result.automatic, false);
    assert.equal(result.restartRequired, false);
    assert.deepEqual(f.queries, [
      "https://registry.npmjs.org/%40sample%2Frunner/latest",
    ]);
  }
  const f = service({ installed: "1.1.0", running: "1.0.0" });
  const result = await f.updater.check();
  assert.equal(result.status, "current");
  assert.equal(result.restartRequired, true);
  assert.equal(result.installedVersion, "1.1.0");
  assert.equal(result.runningVersion, "1.0.0");
  const changed = service({
    stable: metadata("1.0.0"),
    installation: { restartRequired: true },
  });
  const unchangedVersion = await changed.updater.check();
  assert.equal(unchangedVersion.status, "current");
  assert.equal(unchangedVersion.restartRequired, true);
  const legacy = metadata("0.9.0");
  delete legacy.agentRunnerCompatibility;
  assert.equal(
    (await service({ stable: legacy }).updater.check()).status,
    "current",
  );
});

test("stable selection rejects prereleases unless an exact version is requested", async () => {
  const stable = service({ stable: metadata("1.1.0-rc.1") });
  assert.equal((await stable.updater.check()).status, "blocked");
  const explicit = service({
    installed: "1.1.0-rc.2",
    stable: metadata("1.0.0"),
    selected: metadata("1.1.0-rc.10"),
  });
  const result = await explicit.updater.check({ version: "1.1.0-rc.10" });
  assert.equal(result.status, "available");
  assert.equal(result.channel, "explicit");
  assert.equal(result.stableVersion, "1.0.0");
  assert.equal(result.availableVersion, "1.1.0-rc.10");
  assert.equal(result.restartRequired, true);
  assert.equal(explicit.queries.length, 2);
  for (const request of [
    { version: "1.1.0-rc.01" },
    { source: "https://example.invalid/archive.tgz" },
    { automatic: true },
    { projectConfiguration: {} },
    { role: "worker" },
    { apply: true },
  ]) {
    const f = service();
    assert.deepEqual((await f.updater.check(request)).blockers, [
      "invalid_request",
    ]);
    assert.deepEqual(f.queries, []);
    assert.equal(f.inspections(), 0);
  }
});

test("registry metadata accepts npm's repository normalization only for the approved source", async () => {
  for (const [url, status] of [
    ["git+https://github.com/sample/runner.git", "available"],
    ["git+https://github.com/other/runner.git", "blocked"],
    ["git+https://github.com/sample/runner.git?source=other", "blocked"],
    ["http://github.com/sample/runner.git", "blocked"],
  ]) {
    const stable = metadata("1.1.0");
    stable.repository.url = url;
    const result = await service({ stable }).updater.check();
    assert.equal(result.status, status, url);
    assert.deepEqual(
      result.blockers,
      status === "available" ? [] : ["registry_unavailable"],
    );
  }
});

test("malformed compatibility pipeline maps remain unknown rather than comparable", async () => {
  for (const pipelines of [true, 1, "sample", []]) {
    const stable = metadata("1.1.0");
    stable.agentRunnerCompatibility.pipelines = pipelines;
    const result = await service({ stable }).updater.check();
    assert.equal(result.status, "blocked");
    assert.deepEqual(result.blockers, ["compatibility_unknown"]);
  }
});

test("unapproved identity and development-managed installations never query a registry", async () => {
  let queried = false;
  const updater = createUpdateService({
    fetch: async () => {
      queried = true;
      throw new Error("Unexpected request");
    },
  });
  assert.equal(OFFICIAL_RELEASE_POLICY.enabled, false);
  const result = await updater.check();
  assert.equal(result.official.approved, false);
  assert.ok(result.blockers.includes("identity_unapproved"));
  assert.equal(result.developmentManaged, true);
  assert.equal(queried, false);
  const f = service({ installation: { developmentManaged: true } });
  assert.deepEqual((await f.updater.check()).blockers, ["development_managed"]);
  assert.deepEqual(f.queries, []);
});

test("Node, configuration, state and installation permission blockers remain informational", async () => {
  for (const [kind, code] of [
    ["node", "node_incompatible"],
    ["configuration", "configuration_incompatible"],
    ["state", "state_incompatible"],
    ["pipeline", "state_incompatible"],
    ["permission", "installation_not_writable"],
  ]) {
    const available = metadata("1.1.0");
    const installation = {};
    if (kind === "node") installation.nodeVersion = "v22.1.0";
    if (kind === "configuration")
      available.agentRunnerCompatibility.configurationVersion++;
    if (kind === "state") available.agentRunnerCompatibility.runStateVersion++;
    if (kind === "pipeline")
      available.agentRunnerCompatibility.pipelines.sample++;
    if (kind === "permission") installation.canWriteInstallation = false;
    const result = await service({
      stable: available,
      installation,
    }).updater.check();
    assert.equal(result.status, "blocked");
    assert.deepEqual(result.blockers, [code]);
    assert.equal(result.availableVersion, "1.1.0");
    assert.equal(result.compatibility.scope, "runtime-contract");
  }
});

test("registry failures and local permission errors have bounded redacted results", async () => {
  const privateDetail = "synthetic-private-detail";
  for (const response of [
    401,
    404,
    503,
    "failure",
    "oversize",
    "wrong-package",
    "missing-contract",
  ]) {
    const f = service({
      request: async () => {
        if (response === "failure") throw new Error(privateDetail);
        if (response === "oversize")
          return new Response(" ".repeat(1024 * 1024 + 1));
        if (response === "wrong-package")
          return Response.json({ ...metadata("1.1.0"), name: "@other/runner" });
        if (response === "missing-contract")
          return Response.json({
            ...metadata("1.1.0"),
            agentRunnerCompatibility: null,
          });
        return new Response(privateDetail, { status: response });
      },
    });
    const result = await f.updater.check();
    assert.equal(result.status, "blocked");
    assert.equal(result.blockers.length, 1);
    assert.ok(JSON.stringify(result).length < 4096);
    assert.equal(JSON.stringify(result).includes(privateDetail), false);
  }
  const updater = createUpdateService({
    policy,
    readInstallation: async () => {
      throw Object.assign(new Error(privateDetail), { code: "EACCES" });
    },
    fetch: async () => {
      throw new Error("Unexpected registry request");
    },
  });
  assert.deepEqual((await updater.check()).blockers, [
    "installation_permission",
  ]);
});

test("runtime inspection distinguishes installed and running versions without preparing another payload", async (t) => {
  const f = await runtimeFixture(t);
  const context = await prepareRuntime(f);
  const first = await inspectRuntimeInstallation({ context });
  assert.equal(first.developmentManaged, false);
  assert.equal(first.restartRequired, false);
  const payloadsBefore = await readdir(join(f.storageRoot, "payloads"));
  const original = await readFile(join(f.rootPath, "package.json"));
  const next = JSON.parse(
    await readFile(join(f.rootPath, "package.json"), "utf8"),
  );
  next.version = "1.1.0";
  const bytes = Buffer.from(JSON.stringify(next));
  await writeFile(join(f.rootPath, "package.json"), bytes);
  const manifest = structuredClone(f.manifest);
  manifest.version = next.version;
  Object.assign(
    manifest.files.find(({ path }) => path === "package.json"),
    {
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    },
  );
  await writeFile(
    join(f.rootPath, "release-manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n",
  );
  const inspected = await inspectRuntimeInstallation({ context });
  assert.equal(inspected.runningMetadata.version, "1.0.0");
  assert.equal(inspected.installedMetadata.version, "1.1.0");
  assert.equal(inspected.restartRequired, true);
  await writeFile(join(f.rootPath, "package.json"), original);
  const replacement = Buffer.from('export const marker = "replacement";\n');
  await writeFile(join(f.rootPath, "src/late.js"), replacement);
  const rebuilt = structuredClone(f.manifest);
  Object.assign(
    rebuilt.files.find(({ path }) => path === "src/late.js"),
    {
      size: replacement.length,
      sha256: createHash("sha256").update(replacement).digest("hex"),
    },
  );
  await writeFile(
    join(f.rootPath, "release-manifest.json"),
    JSON.stringify(rebuilt, null, 2) + "\n",
  );
  const sameVersion = await inspectRuntimeInstallation({ context });
  assert.equal(
    sameVersion.installedMetadata.version,
    sameVersion.runningMetadata.version,
  );
  assert.equal(sameVersion.restartRequired, true);
  assert.deepEqual(
    await readdir(join(f.storageRoot, "payloads")),
    payloadsBefore,
  );
});

test("linked checkout inspection preserves its link and performs no Git mutation", async (t) => {
  const directory = await runtimeFixtureDirectory(t);
  const checkout = join(directory, "checkout");
  await mkdir(checkout);
  await mkdir(join(checkout, ".git"));
  await writeFile(
    join(checkout, "package.json"),
    JSON.stringify({ version: "1.0.0", workspaces: ["packages/*"] }),
  );
  const link = join(directory, "linked");
  await symlink(checkout, link);
  const result = await inspectRuntimeInstallation({
    rootPath: await realpath(link),
    context: null,
  });
  assert.equal(result.developmentManaged, true);
  assert.equal((await lstat(link)).isSymbolicLink(), true);
});
