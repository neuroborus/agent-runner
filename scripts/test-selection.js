import { globSync } from "node:fs";

// Shared by the launcher and the narrow runner-trusted launcher recognizer.
// Explicit arguments retain their original order and meaning.
export function selectTestFiles(inputArguments, { cwd = process.cwd() } = {}) {
  const argumentsList = [...inputArguments];
  const slow = argumentsList[0] === "--slow";
  if (slow) argumentsList.shift();
  const files = argumentsList.length
    ? argumentsList
    : globSync(
        [
          "test/**/*.test.js",
          "pipelines/*/test/**/*.test.js",
          "packages/*/test/**/*.test.js",
        ],
        { cwd },
      )
        .filter((path) => path.endsWith(".slow.test.js") === slow)
        .sort();
  if (files.length === 0) throw new Error("No test files selected.");
  return { slow, files };
}
