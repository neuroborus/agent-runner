import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  claimTestAttribution,
  reportTestFailures,
} from "../src/trusted-validation/index.js";

const request = { nonce: "a".repeat(64), commandIdentity: "b".repeat(64) };
const emptyReport = { ...request, locations: [] };

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "test-attribution-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const scratch = join(root, "scratch");
  const directory = join(scratch, ".agent-runner-test-attribution");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const write = (name, value) =>
    writeFile(
      join(directory, name),
      typeof value === "string" || Buffer.isBuffer(value)
        ? value
        : JSON.stringify(value),
      { mode: 0o600 },
    );
  await write("request", request);
  await write("report", emptyReport);
  const source = async (path) => {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), "");
    return path;
  };
  const path = await source("test/sample.test.js");
  return {
    root,
    directory,
    write,
    source,
    path,
    environment: { AGENT_RUNNER_SCRATCH: scratch },
    read: () => readFile(join(directory, "report"), "utf8"),
  };
}

function failure(file, failureType = "testCodeFailure", line = 1, column = 1) {
  return {
    type: "test:fail",
    data: {
      file,
      line,
      column,
      details: {
        error: {
          failureType,
          message: "private assertion value",
          stack: "private stack",
        },
      },
      name: "private title",
    },
  };
}

async function report(f, events) {
  // A real reporter is a direct child of the harness holding this claim.
  await f.write("claim", { ...request, pid: process.ppid });
  for await (const output of reportTestFailures(events, {
    environment: f.environment,
    projectPath: f.root,
  }))
    assert.fail(`Unexpected reporter output: ${output}`);
}

test("only the first harness claims a valid scratch request; other bindings cannot request reports", async (t) => {
  const f = await fixture(t);
  assert.equal(
    claimTestAttribution({ TMPDIR: f.environment.AGENT_RUNNER_SCRATCH }),
    null,
  );
  assert.deepEqual(claimTestAttribution(f.environment), { claimed: true });
  const claim = await readFile(join(f.directory, "claim"), "utf8");
  assert.deepEqual(JSON.parse(claim), { ...request, pid: process.pid });
  assert.deepEqual(claimTestAttribution(f.environment), { claimed: false });
  assert.equal(await readFile(join(f.directory, "claim"), "utf8"), claim);
  for await (const _ of reportTestFailures([failure(f.path)], {
    environment: f.environment,
    projectPath: f.root,
  }))
    assert.fail("Unexpected output");
  assert.deepEqual(JSON.parse(await f.read()), emptyReport);
});

test("reporter keeps only bounded metadata across batches and drains without retaining later events", async (t) => {
  const f = await fixture(t);
  await report(f, [
    failure(join(f.root, f.path), "subtestsFailed", 1_000_000, null),
  ]);
  let drained = 0;
  const inaccessibleData = {
    type: "test:fail",
    get data() {
      assert.fail("Capacity was already reached");
    },
  };
  async function* events() {
    yield failure(f.path, "subtestsFailed", 1_000_000, null); // Duplicate across batches.
    yield failure(f.path, "testTimeoutFailure", 0, 1_000_001);
    yield failure(f.path, "testAborted", 1.5, -1);
    yield failure(f.path, "uncaughtException", undefined, NaN);
    for (let i = 0; i < 100_000; i++) {
      drained++;
      yield inaccessibleData;
    }
  }
  await report(f, events());
  const text = await f.read();
  assert.equal(drained, 100_000);
  assert.ok(Buffer.byteLength(text) <= 4_096);
  assert.deepEqual(JSON.parse(text).locations, [
    { path: f.path, line: 1_000_000, column: null, class: "subtests" },
    { path: f.path, line: null, column: null, class: "timeout" },
    { path: f.path, line: null, column: null, class: "cancelled" },
    { path: f.path, line: 1, column: null, class: "uncaught" },
  ]);
  assert.doesNotMatch(text, /private|message|stack|name|details/u);
});

test("source paths are confined, canonical, test-only and UTF-8 byte bounded", async (t) => {
  const f = await fixture(t);
  const boundary = await f.source(`test/${"é".repeat(121)}a.test.js`);
  assert.equal(Buffer.byteLength(boundary), 256);
  const excessive = await f.source(`test/${"é".repeat(122)}.test.js`);
  await symlink(join(f.root, f.path), join(f.root, "test/link.test.js"));
  await report(f, [
    ...[
      "test/../sample.test.js",
      "test//sample.test.js",
      "test/./sample.test.js",
      "test/link.test.js",
      "test/missing.test.js",
      "src/sample.test.js",
      "test/bad\n.test.js",
      "test/bad\\name.test.js",
      excessive,
      "/external/private.test.js",
      "../test/sample.test.js",
    ].map((path) => failure(path)),
    { type: "test:stdout", data: { message: "private stdout" } },
    failure(boundary, "unknown-private-error"),
    failure(
      await f.source("pipelines/example/test/role.test.js"),
      "cancelledByParent",
    ),
    failure(await f.source("packages/example/test/plan.test.js")),
  ]);
  assert.deepEqual(
    JSON.parse(await f.read()).locations.map(({ path, class: kind }) => [
      path,
      kind,
    ]),
    [
      [boundary, "test-failure"],
      ["pipelines/example/test/role.test.js", "cancelled"],
      ["packages/example/test/plan.test.js", "test-failure"],
    ],
  );
});

test("closed canonical codec rejects stale, malformed, excessive and unsafe existing reports", async (t) => {
  const f = await fixture(t);
  const location = {
    path: f.path,
    line: 1,
    column: null,
    class: "test-failure",
  };
  const valid = { ...request, locations: [location] };
  const invalid = [
    { ...valid, nonce: "c".repeat(64) },
    { ...valid, commandIdentity: "c".repeat(64) },
    { ...valid, message: "private" },
    { ...valid, locations: Array(5).fill(location) },
    ...[
      { ...location, extra: true },
      { ...location, class: "private" },
      ...[0, 1_000_001, -1, 1.5, "1"].map((line) => ({ ...location, line })),
    ].map((item) => ({ ...request, locations: [item] })),
    "{",
    JSON.stringify(valid) + "\n",
    " ".repeat(4_097),
    JSON.stringify(valid).replace(
      '"locations":',
      '"locations":[],"locations":',
    ),
    Buffer.from([0xff]),
    Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from(JSON.stringify(valid)),
    ]),
  ];
  for (const value of invalid) {
    await f.write("report", value);
    const before = await readFile(join(f.directory, "report"));
    await report(f, [failure(f.path)]);
    assert.deepEqual(await readFile(join(f.directory, "report")), before);
  }
  await rm(join(f.directory, "report"));
  await symlink(join(f.directory, "request"), join(f.directory, "report"));
  await report(f, [failure(f.path)]);
  assert.deepEqual(
    JSON.parse(await readFile(join(f.directory, "request"), "utf8")),
    request,
  );
});

test("invalid or noncanonical requests never claim a harness", async (t) => {
  const f = await fixture(t);
  for (const value of [
    { ...request, extra: true },
    { ...request, nonce: "a" },
    { ...request, commandIdentity: "B".repeat(64) },
    "{",
    " ".repeat(4_097),
    Buffer.from([0xff]),
  ]) {
    await f.write("request", value);
    assert.equal(claimTestAttribution(f.environment), null);
  }
  await assert.rejects(readFile(join(f.directory, "claim")), {
    code: "ENOENT",
  });
});
