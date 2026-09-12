import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

import {
  createGuidanceService,
  createRunStore,
  parseRunnerConfiguration,
} from "../../../src/index.js";

export const executeFile = promisify(execFile);
export const ROOT_MODULE = new URL("../../../src/index.js", import.meta.url)
  .href;

export async function fixture(
  t,
  { ignored = true, initialContent, stateRoot: selectStateRoot } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-guidance-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const stateRoot = selectStateRoot?.(root, projectPath) ?? join(root, "state");
  const localPath = join(
    projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner",
    "rules.md",
  );
  await mkdir(projectPath);
  await executeFile("git", ["init", "--quiet"], { cwd: projectPath });
  await writeFile(
    join(projectPath, ".gitignore"),
    ignored ? "LOCAL_ARTIFACTS/\nCUSTOM_ARTIFACTS/\n" : "",
  );
  if (initialContent !== undefined) {
    await mkdir(dirname(localPath), { recursive: true });
    await writeFile(localPath, initialContent);
  }
  let configuration = parseRunnerConfiguration('{"schemaVersion":1}');
  const store = createRunStore({ stateRoot });
  const createService = (options = {}) =>
    createGuidanceService({
      runStore: store,
      loadConfiguration: async () => configuration,
      ...options,
    });
  return {
    root,
    projectPath,
    stateRoot,
    localPath,
    store,
    createService,
    service: createService(),
    setConfiguration(value) {
      configuration = parseRunnerConfiguration(
        JSON.stringify({ schemaVersion: 1, ...value }),
      );
    },
    request(
      localContent,
      { expectedHash = null, idempotencyKey = randomUUID(), ...selectors } = {},
    ) {
      return {
        projectPath,
        localContent,
        expectedHash,
        idempotencyKey,
        ...selectors,
      };
    },
  };
}
