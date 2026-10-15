import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { NATIVE_JOB_STEPS, PLATFORMS } from "../ci/native/index.js";

const source = await readFile(
  new URL("../.github/workflows/native-poc.yml", import.meta.url),
  "utf8",
);
const step = (name) => {
  const marker = `      - name: ${name}\n`;
  assert.equal(source.split(marker).length, 2, `One ${name} step`);
  return source.split(marker)[1].split(/\n      - (?:name:|uses:)/u)[0];
};

test("ordinary Native PoC dispatches every experiment stage with no review or provider authority", () => {
  assert.deepEqual(
    [...source.matchAll(/node ci\/native\/run\.js ([^\n]+)/gu)].map(
      (match) => match[1],
    ),
    [
      "deadlines",
      "initialize",
      "prepare-linux",
      "prepare",
      "setup",
      "probe",
      "cleanup",
      "report",
      "collect",
      "aggregate",
    ].map((stage) => `--tier system --purpose experiment --stage ${stage}`),
  );
  for (const name of Object.values(NATIVE_JOB_STEPS[7])) step(name);
  assert.doesNotMatch(
    source,
    /vars\.|secrets\.|prepare-inputs|NATIVE_\w*REVIEW|CI_INPUTS|INPUT_REPOSITORY|INPUT_REVISION|pull_request_target|continue-on-error/u,
  );
  assert.match(source, /pull_request:\n    branches: \[main, dev\]/u);
  assert.match(source, /permissions:\n  contents: read\n  actions: read/u);
  assert.doesNotMatch(source, /: write\b/u);
  assert.match(source, /fail-fast: false/u);
  for (const { os, image } of PLATFORMS)
    assert.ok(
      source.includes(`- platform: ${os}\n            image: ${image}`),
    );
  const uses = [...source.matchAll(/uses: ([^\n #]+)/gu)].map(
    (match) => match[1],
  );
  assert.ok(uses.every((value) => /@[a-f0-9]{40}$/u.test(value)));
  assert.equal(source.match(/persist-credentials: false/gu)?.length, 3);
  assert.equal(
    source.match(
      /node-version: 24\.21\.0\n          architecture: x64\n          check-latest: false/gu,
    )?.length,
    3,
  );
  assert.ok(
    source.includes(
      "CANDIDATE: ${{ github.event.pull_request.head.sha || github.sha }}",
    ),
  );
  assert.equal(
    source.match(/ref: \$\{\{ needs\.candidate\.outputs\.sha \}\}/gu)?.length,
    2,
  );
  assert.match(
    step("Build and prepare experiment platform helpers"),
    /steps\.runtime\.conclusion == 'success'.*steps\.linux_preparation\.conclusion == 'success'/u,
  );
  assert.match(step("Setup"), /\[matrix\.platform\]\.setupMinutes/u);
  assert.match(
    step("Prepare experiment Linux prerequisites and namespace policy"),
    /\.linux\.bootstrapMinutes/u,
  );
});

test("failed experiments retain cleanup, reports and original receipts at the artifact root", () => {
  for (const name of [
    "Cleanup",
    "Recover only settled owned Linux namespace policy",
    "Report per-OS evidence",
    "Upload native evidence",
    "Report aggregate and enforce complete experiment evidence",
    "Upload aggregate failures and summary",
  ])
    assert.match(step(name), /if: \$\{\{ always\(\)/u);
  assert.match(
    step("Recover only settled owned Linux namespace policy"),
    /namespace-ci\.js --stage cleanup --report system/u,
  );
  assert.match(
    step("Report per-OS evidence"),
    /NATIVE_NAMESPACE_CLEANUP_OUTCOME: \$\{\{ steps\.namespace_cleanup\.conclusion \}\}/u,
  );
  const upload = step("Upload native evidence");
  assert.match(upload, /native-system\/\*\.json/u);
  for (const directory of ["preparation/**", "build", "linux/evidence"])
    assert.ok(upload.includes(`native-system/${directory}/*.json`));
  assert.ok(
    upload.includes(
      "!${{ runner.temp }}/native-system/windows-experiment-asset-*.json",
    ),
  );
  assert.doesNotMatch(
    upload,
    /\.exe|\.dll|linux-packages|native-system-bootstrap/u,
  );
  assert.match(upload, /if-no-files-found: error/u);
  assert.match(source, /digest-mismatch: error/u);
  assert.match(
    source,
    /artifact-ids: \$\{\{ steps\.collect\.outputs\.artifact_ids \}\}/u,
  );
  assert.match(
    step("Report aggregate and enforce complete experiment evidence"),
    /--purpose experiment --stage aggregate/u,
  );
  assert.match(source, /GH_TOKEN: \$\{\{ github\.token \}\}/u);
});
