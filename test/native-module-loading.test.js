import { execFile } from "node:child_process";
import assert from "node:assert/strict";
import test from "node:test";
import { promisify } from "node:util";

const execute = promisify(execFile);

test("the native index loads first in a fresh process without output", async () => {
  const { stdout, stderr } = await execute(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      "await import(process.argv[1]);",
      new URL("../ci/native/index.js", import.meta.url).href,
    ],
    { timeout: 10000, maxBuffer: 16384 },
  );
  assert.equal(stdout, "");
  assert.equal(stderr, "");
});
