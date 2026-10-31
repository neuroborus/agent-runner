import { dirname, resolve } from "node:path";

import { readArtifact, reportArtifact } from "./artifact.js";
import {
  inspectOutputDirectory,
  prepareOutputDirectory,
} from "./output-directory.js";
import {
  assertBindings,
  assertSafe,
  inspectPath,
  same,
  within,
} from "./paths.js";

// These are Runner effects, never provider write declarations. The pipeline
// supplies exact reviewed destinations; this capability owns filesystem safety.
function confine(projectPath, path) {
  assertSafe(
    resolve(projectPath) === projectPath &&
      resolve(path) === path &&
      path !== projectPath &&
      within(projectPath, path),
    "Infrastructure must be an exact workspace descendant.",
  );
}

export async function inspectInfrastructure(fs, { projectPath, path }) {
  confine(projectPath, path);
  const binding = await inspectPath(fs, path, { missing: true });
  const file = binding.kind === "file" ? await readArtifact(fs, path) : null;
  await assertBindings(fs, [binding]);
  assertSafe(
    same(binding, await inspectPath(fs, path, { missing: true })),
    "Infrastructure changed during inspection.",
  );
  return { binding, file };
}

export async function publishInfrastructureFile(
  fs,
  { projectPath, intent, temporary = null, recordTemporary, assertAuthorized },
) {
  const { path, temporaryPath, before, content } = intent;
  confine(projectPath, path);
  confine(projectPath, temporaryPath);
  assertSafe(
    before.binding.path === path &&
      ["file", "missing"].includes(before.binding.kind) &&
      dirname(path) === dirname(temporaryPath),
    "Infrastructure file intent is invalid.",
  );
  return reportArtifact(
    fs,
    { artifactPaths: [path, temporaryPath], bindings: [before.binding] },
    {
      path,
      temporaryPath,
      content,
      expectedHash: before.file?.contentHash ?? null,
    },
    {
      temporary,
      recordTemporary,
      includeIdentity: true,
      requireOwnedTemporary: true,
      assertAuthorized,
      assertCurrent(current) {
        assertSafe(
          same(current, before.file) ||
            (temporary?.phase === "prepared" &&
              same(current?.identity, temporary.identity)),
          "Infrastructure file was replaced outside its publication intent.",
        );
      },
    },
  );
}

export async function inspectInfrastructureDirectory(
  fs,
  { projectPath, stateRoot, path },
) {
  confine(projectPath, path);
  return inspectOutputDirectory(fs, { outputPaths: [path], stateRoot }, path);
}

export async function publishInfrastructureDirectory(
  fs,
  {
    projectPath,
    stateRoot,
    intent,
    identity = null,
    recordIdentity,
    publishDirectory,
    assertAuthorized,
  },
) {
  confine(projectPath, intent.path);
  if (identity !== null) {
    // A lost receipt can be recovered only from the exact published allocation.
    const binding = await inspectPath(fs, intent.path, { missing: true });
    assertSafe(
      binding.kind === "directory" && same(binding.identity, identity),
      "Infrastructure directory publication needs reconciliation.",
    );
    await assertBindings(fs, [intent.parent]);
    return binding;
  }
  return prepareOutputDirectory(
    fs,
    { outputPaths: [intent.path], stateRoot, bindings: [intent.parent] },
    intent,
    { recordIdentity, publishDirectory, beforeCreate: assertAuthorized },
  );
}
