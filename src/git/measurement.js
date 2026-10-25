import { GitSafetyError } from "./command.js";
import {
  contentEntry,
  entriesMatch,
  headContentEntry,
  sourceChangesAtRoot,
} from "./content.js";

function sourceChanged() {
  return new GitSafetyError("Repository content changed during measurement.", {
    code: "ERR_GIT_MEASUREMENT_CHANGED",
  });
}

function lines(content) {
  // Latin-1 preserves every byte; retain LF so a missing final newline differs.
  return content.toString("latin1").match(/[^\n]*\n|[^\n]+$/gu) ?? [];
}

function editDistance(before, after) {
  let start = 0;
  let leftEnd = before.length;
  let rightEnd = after.length;
  while (start < leftEnd && start < rightEnd && before[start] === after[start])
    start++;
  while (
    leftEnd > start &&
    rightEnd > start &&
    before[leftEnd - 1] === after[rightEnd - 1]
  ) {
    leftEnd--;
    rightEnd--;
  }
  const leftLength = leftEnd - start;
  const rightLength = rightEnd - start;
  if (leftLength === 0 || rightLength === 0) return leftLength + rightLength;
  const leftLines = new Set(before.slice(start, leftEnd));
  if (!after.slice(start, rightEnd).some((line) => leftLines.has(line))) {
    return leftLength + rightLength;
  }
  // Myers' furthest-reaching diagonals need no edit trace for aggregate counts.
  const frontier = new Map([[1, 0]]);
  for (let distance = 0; distance <= leftLength + rightLength; distance++) {
    for (let diagonal = -distance; diagonal <= distance; diagonal += 2) {
      let x =
        diagonal === -distance ||
        (diagonal !== distance &&
          frontier.get(diagonal - 1) < frontier.get(diagonal + 1))
          ? frontier.get(diagonal + 1)
          : frontier.get(diagonal - 1) + 1;
      let y = x - diagonal;
      while (
        x < leftLength &&
        y < rightLength &&
        before[start + x] === after[start + y]
      ) {
        x++;
        y++;
      }
      if (x >= leftLength && y >= rightLength) return distance;
      frontier.set(diagonal, x);
    }
  }
}

function countLines(before, after) {
  // Match Git's raw-content binary heuristic without consulting path attributes.
  if (
    before.subarray(0, 8000).includes(0) ||
    after.subarray(0, 8000).includes(0)
  ) {
    return null;
  }
  const left = lines(before);
  const right = lines(after);
  const distance = editDistance(left, right);
  return {
    additions: (distance + right.length - left.length) / 2,
    deletions: (distance + left.length - right.length) / 2,
  };
}

export async function measureChangesAtRoot(
  context,
  repositoryPath,
  { baseHead, expectedContentFingerprint },
) {
  // Replacement refs must not reinterpret the verified step-start baseline.
  const sourceContext = {
    runGit: (path, argumentsList, options) =>
      context.runGit(path, ["--no-replace-objects", ...argumentsList], options),
  };
  const before = await sourceChangesAtRoot(context, repositoryPath, {
    baseHead,
  });
  if (before.contentFingerprint !== expectedContentFingerprint) {
    throw sourceChanged();
  }
  let additions = 0;
  let deletions = 0;
  const binaryPaths = [];
  const gitlinkPaths = [];
  for (const entry of [...before.entries].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  )) {
    const current = await contentEntry(context, repositoryPath, entry.path, {
      allowedPaths: [],
      missingAllowed: true,
      includeContent: true,
    });
    if (!entriesMatch(current, entry)) throw sourceChanged();
    const baseline =
      baseHead === null
        ? null
        : await headContentEntry(
            sourceContext,
            repositoryPath,
            baseHead,
            entry.path,
            {
              includeContent: true,
            },
          );
    if (entriesMatch(current, baseline)) continue;
    if (current.kind === "gitlink" || baseline?.kind === "gitlink") {
      gitlinkPaths.push(entry.path);
      continue;
    }
    const counts = countLines(
      baseline?.content ?? Buffer.alloc(0),
      current.content ?? Buffer.alloc(0),
    );
    if (counts === null) {
      binaryPaths.push(entry.path);
    } else {
      additions += counts.additions;
      deletions += counts.deletions;
    }
  }
  if (!Number.isSafeInteger(additions + deletions)) {
    throw new GitSafetyError(
      "Git change measurement exceeds safe arithmetic.",
      {
        code: "ERR_INVALID_GIT_MEASUREMENT",
      },
    );
  }
  const after = await sourceChangesAtRoot(context, repositoryPath, {
    baseHead,
  });
  if (after.contentFingerprint !== before.contentFingerprint) {
    throw sourceChanged();
  }
  return Object.freeze({
    baseHead,
    contentFingerprint: before.contentFingerprint,
    additions,
    deletions,
    changedLines: additions + deletions,
    changedPaths: Object.freeze([...before.changedPaths].sort()),
    binaryPaths: Object.freeze(binaryPaths),
    gitlinkPaths: Object.freeze(gitlinkPaths),
  });
}
