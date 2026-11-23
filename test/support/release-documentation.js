import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { scanMarkdown } from "./documentation-navigation.js";

const USER_REFERENCES = [
  "README.md",
  "candidates.md",
  "cli-recovery.md",
  "cli.md",
  "configuration.example.json",
  "configuration.md",
  "development.md",
  "guarantees.md",
  "installation.md",
  "mcp-supervision.md",
  "mcp.md",
  "overview.md",
  "pipeline-settings.md",
  "pipelines.md",
  "provider-recovery.md",
  "releases.md",
  "requirements.md",
  "runtime-payloads.md",
  "task-inputs.md",
  "trusted-validation.md",
].map((name) => `docs/user/${name}`);

const REQUIRED_ROUTES = new Map([
  ["README.md", ["docs/user/README.md"]],
  [
    "docs/user/mcp-supervision.md",
    [
      "../OPERATOR_GUIDE.md#5-recover-a-pause-without-taking-over-the-work",
      "../OPERATOR_GUIDE.md#4-start-clarify-and-observe",
    ],
  ],
]);

const PLAN_README_ROUTES = {
  "commit-plan": [
    "contract.md",
    "contract.md#step-structure",
    "contract.md#commit-subject",
  ],
  "custom-plan": [
    "contract.md",
    "contract.md#representation",
    "contract.md#public-api",
  ],
};

export async function assertPackagedRoutes(documents, files) {
  const mount = "/package/";
  const alternateMount = "/alternate-package/";
  const navigation = new Map();
  for (const { path, markdown, planReadme } of documents) {
    navigation.set(path, {
      ...(await scanMarkdown(markdown)),
      requiredRoutes: planReadme
        ? PLAN_README_ROUTES[planReadme]
        : (REQUIRED_ROUTES.get(path) ?? []),
    });
  }
  for (const [path, { links, requiredRoutes }] of navigation) {
    const destinations = new Set(
      links
        .filter(({ isNavigable }) => isNavigable)
        .map(({ target }) => target),
    );
    for (const route of requiredRoutes) {
      assert.ok(
        destinations.has(route),
        `${path} is missing required packaged route: ${route}`,
      );
    }
    const base = new URL(`${mount}${path}`, "https://package.example.test/");
    const alternateBase = new URL(`${alternateMount}${path}`, base);
    for (const { line, target: link, isNavigable } of links) {
      const location = `${path}:${line}`;
      assert.ok(
        isNavigable || link !== "",
        `${location} has an image with an empty destination`,
      );
      const target = new URL(link, base);
      assert.notEqual(
        target.protocol,
        "file:",
        `${location} links outside the package: ${link}`,
      );
      if (target.origin !== base.origin) continue;
      const relativePath = target.pathname.slice(mount.length);
      // A confined route resolves to the same relative path at either mount.
      assert.ok(
        target.pathname.startsWith(mount) &&
          new URL(link, alternateBase).pathname ===
            `${alternateMount}${relativePath}`,
        `${location} links outside the package: ${link}`,
      );
      assert.ok(
        !/%2f/iu.test(relativePath),
        `${location} links to a package path with an encoded slash: ${link}`,
      );
      const targetPath = decodeURIComponent(relativePath);
      assert.ok(
        files.has(targetPath),
        `${location} links to a resource absent from the package: ${link}`,
      );
      const anchors = navigation.get(targetPath)?.slugs;
      if (isNavigable && target.hash && anchors) {
        assert.ok(
          anchors.has(decodeURIComponent(target.hash.slice(1))),
          `${location} links to a heading absent from the package: ${link}`,
        );
      }
    }
  }
}

export async function assertReleaseDocumentation(rootPath, manifest) {
  const files = new Set(manifest.files.map(({ path }) => path));
  assert.deepEqual(
    [...files].filter((path) => path.startsWith("docs/user/")).sort(),
    USER_REFERENCES,
  );
  const metadata = JSON.parse(
    await readFile(join(rootPath, "package.json"), "utf8"),
  );
  assert.deepEqual(
    metadata.files.filter((path) => path.startsWith("docs/user")).sort(),
    USER_REFERENCES,
  );
  const documents = [];
  for (const path of [
    "README.md",
    "docs/OPERATOR_GUIDE.md",
    ...USER_REFERENCES,
  ]) {
    const bytes = await readFile(join(rootPath, path));
    assert.deepEqual(
      bytes,
      await readFile(new URL(`../../${path}`, import.meta.url)),
      path,
    );
    if (path.endsWith(".md")) {
      documents.push({
        path,
        markdown: bytes.toString("utf8"),
      });
    }
  }
  for (const name of ["commit-plan", "custom-plan"]) {
    const dependency = manifest.dependencies.find(
      (entry) => entry.name === `@agent-runner/${name}`,
    );
    assert.ok(dependency, name);
    for (const file of ["README.md", "contract.md"]) {
      const path = `${dependency.path}/${file}`;
      const source = new URL(`../../packages/${name}/${file}`, import.meta.url);
      const bytes = await readFile(join(rootPath, path));
      assert.deepEqual(bytes, await readFile(source), path);
      documents.push({
        path,
        markdown: bytes.toString("utf8"),
        planReadme: file === "README.md" ? name : undefined,
      });
    }
  }
  await assertPackagedRoutes(documents, files);
}
