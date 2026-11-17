import { lstat } from "node:fs/promises";
import { join } from "node:path";

import { decodeNullList, GitSafetyError } from "./command.js";

const CONTROL_FIELDS = Object.freeze([
  ["projectPath", "project-path"],
  ["head", "head"],
  ["branch", "branch"],
  ["detached", "detached-head"],
  ["refsFingerprint", "refs"],
  ["remoteConfigurationFingerprint", "remote-configuration"],
  ["identityAvailable", "identity"],
  ["identityFingerprint", "identity"],
]);
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const HANDOFF_GIT_PREFIX = Object.freeze(["-c", "core.hooksPath=/dev/null"]);
// Git sets bit 2 of a diff exit status when --check finds a problem.
const CHECK_EXIT_CODES = Object.freeze([0, 1, 2, 3]);
const MAX_HYGIENE_PATHS = 30;

function unique(values) {
  return [...new Set(values)];
}

function controlChanges(current, expected) {
  return CONTROL_FIELDS.filter(
    ([field]) => current[field] !== expected[field],
  ).map(([, name]) => name);
}

function contaminated(message, changes) {
  return new GitSafetyError(message, {
    changes: unique(changes),
    code: "ERR_POLISHING_HANDOFF_CONTAMINATED",
  });
}

async function isRegularFile(path) {
  try {
    return (await lstat(path)).isFile();
  } catch (cause) {
    if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return false;
    throw cause;
  }
}

export function createGitHandoffService({
  assertSnapshot,
  stagedContentMatches,
  runGit,
  snapshot,
}) {
  function assertHandoffOptions(options) {
    if (
      options === null ||
      typeof options !== "object" ||
      Array.isArray(options) ||
      Object.keys(options).some(
        (field) =>
          ![
            "expectedSnapshot",
            "finalizedFingerprint",
            "reviewedFingerprint",
          ].includes(field),
      )
    ) {
      throw new GitSafetyError("Polishing handoff options are invalid.", {
        code: "ERR_INVALID_POLISHING_HANDOFF",
      });
    }
    const expectedSnapshot = assertSnapshot(options.expectedSnapshot);
    if (
      typeof options.finalizedFingerprint !== "string" ||
      !SHA256_PATTERN.test(options.finalizedFingerprint) ||
      options.reviewedFingerprint !== options.finalizedFingerprint ||
      expectedSnapshot.contentFingerprint !== options.finalizedFingerprint
    ) {
      throw new GitSafetyError("Polishing handoff fingerprints are invalid.", {
        code: "ERR_INVALID_POLISHING_HANDOFF",
      });
    }
    return Object.freeze({
      expectedSnapshot,
      finalizedFingerprint: options.finalizedFingerprint,
    });
  }

  async function inspectComplete(expectedSnapshot, expectedContentFingerprint) {
    const current = await snapshot({
      allowedPaths: expectedSnapshot.allowedPaths,
      projectPath: expectedSnapshot.projectPath,
    });
    const changes = CONTROL_FIELDS.filter(
      ([field]) => current[field] !== expectedSnapshot[field],
    ).map(([, name]) => name);
    if (current.contentFingerprint !== expectedContentFingerprint) {
      changes.push("content");
    }
    if (changes.length > 0) {
      throw new GitSafetyError(
        "Repository controls or content changed before polishing handoff.",
        {
          changes: unique(changes),
          code: "ERR_POLISHING_HANDOFF_CONTAMINATED",
        },
      );
    }
    const [staged, unstaged, untracked, stagedContentMatchesExpected] =
      await Promise.all([
        runGit(
          current.projectPath,
          [
            ...HANDOFF_GIT_PREFIX,
            "diff",
            "--cached",
            "--quiet",
            "--exit-code",
            "--ignore-submodules=all",
            "--no-ext-diff",
            "--no-textconv",
          ],
          { allowedExitCodes: [0, 1] },
        ),
        runGit(
          current.projectPath,
          [
            ...HANDOFF_GIT_PREFIX,
            "diff",
            "--quiet",
            "--exit-code",
            "--ignore-submodules=all",
            "--no-ext-diff",
            "--no-textconv",
          ],
          { allowedExitCodes: [0, 1] },
        ),
        runGit(current.projectPath, [
          ...HANDOFF_GIT_PREFIX,
          "ls-files",
          "--others",
          "--exclude-standard",
          "-z",
        ]),
        stagedContentMatches(
          current.projectPath,
          current.allowedPaths,
          expectedContentFingerprint,
        ),
      ]);
    const complete =
      staged.exitCode === 1 &&
      unstaged.exitCode === 0 &&
      untracked.stdout.length === 0 &&
      stagedContentMatchesExpected;
    if (!complete) {
      return Object.freeze({ complete: false, snapshot: current });
    }
    const whitespace = await runGit(
      current.projectPath,
      [...HANDOFF_GIT_PREFIX, "diff", "--cached", "--check"],
      { allowedExitCodes: [0, 1, 2] },
    );
    if (whitespace.exitCode !== 0) {
      throw new GitSafetyError(
        "Staged polishing handoff has whitespace errors.",
        { code: "ERR_POLISHING_HANDOFF_WHITESPACE" },
      );
    }
    const verified = await snapshot({
      allowedPaths: current.allowedPaths,
      projectPath: current.projectPath,
    });
    const postChanges = CONTROL_FIELDS.filter(
      ([field]) => verified[field] !== expectedSnapshot[field],
    ).map(([, name]) => name);
    if (
      verified.contentFingerprint !== expectedContentFingerprint ||
      verified.indexFingerprint !== current.indexFingerprint
    ) {
      postChanges.push("content-or-index");
    }
    if (postChanges.length > 0) {
      throw new GitSafetyError(
        "Repository changed while polishing handoff was verified.",
        {
          changes: unique(postChanges),
          code: "ERR_POLISHING_HANDOFF_CONTAMINATED",
        },
      );
    }
    return Object.freeze({ complete: true, snapshot: verified });
  }

  // Staging-independent whitespace hygiene of the bound content. It never
  // writes the index or objects; new files are checked against /dev/null so
  // repository whitespace configuration and attributes apply to each operand.
  async function checkContentHygiene(current) {
    const root = current.projectPath;
    const excluded = new Set(current.allowedPaths);
    let tracked = false;
    if (current.head !== null) {
      // Literal pathspecs also match directory descendants, so exact
      // allowed-path membership is applied to the changed-path list as
      // content.js does. A retained path replaced by (or replacing) a directory
      // could select an excluded descendant, so those descendants are excluded
      // explicitly; changed leaves nest at most one level across HEAD and the
      // worktree, so such an exclude never drops a retained path.
      const changed = decodeNullList(
        (
          await runGit(root, [
            ...HANDOFF_GIT_PREFIX,
            "diff",
            "--name-only",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=all",
            "-z",
            current.head,
            "--",
          ])
        ).stdout,
        "Tracked Git paths",
      );
      const checked = changed.filter((path) => !excluded.has(path));
      const shadowed = changed.filter(
        (path) =>
          excluded.has(path) &&
          checked.some((retained) => path.startsWith(`${retained}/`)),
      );
      if (checked.length > 0) {
        const result = await runGit(
          root,
          [
            ...HANDOFF_GIT_PREFIX,
            "diff",
            "--check",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=all",
            current.head,
            "--",
            ...(checked.length === changed.length
              ? []
              : [
                  ...checked.map((path) => `:(top,literal)${path}`),
                  ...shadowed.map((path) => `:(top,literal,exclude)${path}`),
                ]),
          ],
          { allowedExitCodes: CHECK_EXIT_CODES },
        );
        tracked = result.exitCode >= 2;
      }
    }
    const candidates = decodeNullList(
      (
        await runGit(root, [
          ...HANDOFF_GIT_PREFIX,
          "ls-files",
          "--others",
          "--exclude-standard",
          "-z",
        ])
      ).stdout,
      "Untracked Git paths",
    );
    if (current.head === null) {
      candidates.push(
        ...decodeNullList(
          (
            await runGit(root, [
              ...HANDOFF_GIT_PREFIX,
              "ls-files",
              "--cached",
              "-z",
            ])
          ).stdout,
          "Git index paths",
        ),
      );
    }
    const failed = [];
    for (const path of [...new Set(candidates)].sort()) {
      if (excluded.has(path) || !(await isRegularFile(join(root, path)))) {
        continue;
      }
      const result = await runGit(
        root,
        [
          ...HANDOFF_GIT_PREFIX,
          "diff",
          "--no-index",
          "--check",
          "--no-ext-diff",
          "--no-textconv",
          "--",
          "/dev/null",
          // Git reads a bare "-" operand as stdin even after "--".
          path === "-" ? "./-" : path,
        ],
        { allowedExitCodes: CHECK_EXIT_CODES },
      );
      if (result.exitCode >= 2) failed.push(path);
    }
    if (!tracked && failed.length === 0) {
      return Object.freeze({ status: "clean" });
    }
    return Object.freeze({
      status: "whitespace",
      tracked,
      paths: Object.freeze(failed.slice(0, MAX_HYGIENE_PATHS)),
      omitted: Math.max(0, failed.length - MAX_HYGIENE_PATHS),
    });
  }

  async function inspectContentHygiene(options) {
    if (
      options === null ||
      typeof options !== "object" ||
      Array.isArray(options) ||
      Object.keys(options).some(
        (field) => !["expectedSnapshot", "contentFingerprint"].includes(field),
      ) ||
      typeof options.contentFingerprint !== "string" ||
      !SHA256_PATTERN.test(options.contentFingerprint)
    ) {
      throw new GitSafetyError("Content hygiene options are invalid.", {
        code: "ERR_INVALID_POLISHING_HANDOFF",
      });
    }
    const expectedSnapshot = assertSnapshot(options.expectedSnapshot);
    const before = await snapshot({
      allowedPaths: expectedSnapshot.allowedPaths,
      projectPath: expectedSnapshot.projectPath,
    });
    const changes = controlChanges(before, expectedSnapshot);
    if (before.contentFingerprint !== options.contentFingerprint) {
      changes.push("content");
    }
    if (before.indexFingerprint !== expectedSnapshot.indexFingerprint) {
      changes.push("index");
    }
    if (changes.length > 0) {
      throw contaminated(
        "Repository controls or content changed before hygiene inspection.",
        changes,
      );
    }
    const inspected = await checkContentHygiene(before);
    const after = await snapshot({
      allowedPaths: before.allowedPaths,
      projectPath: before.projectPath,
    });
    const postChanges = controlChanges(after, before);
    if (after.contentFingerprint !== before.contentFingerprint) {
      postChanges.push("content");
    }
    if (after.indexFingerprint !== before.indexFingerprint) {
      postChanges.push("index");
    }
    if (postChanges.length > 0) {
      throw contaminated(
        "Repository changed during hygiene inspection.",
        postChanges,
      );
    }
    return inspected;
  }

  async function inspectPolishingHandoff(options) {
    const { expectedSnapshot, finalizedFingerprint } =
      assertHandoffOptions(options);
    const inspected = await inspectComplete(
      expectedSnapshot,
      finalizedFingerprint,
    );
    if (inspected.complete) {
      return Object.freeze({
        status: "complete",
        snapshot: inspected.snapshot,
      });
    }
    if (
      inspected.snapshot.indexFingerprint !== expectedSnapshot.indexFingerprint
    ) {
      throw new GitSafetyError(
        "Polishing handoff found an incomplete or contaminated index.",
        {
          changes: ["index"],
          code: "ERR_POLISHING_HANDOFF_CONTAMINATED",
        },
      );
    }
    return Object.freeze({
      status: "untouched",
      snapshot: inspected.snapshot,
    });
  }

  async function stagePolishingHandoff(options) {
    const inspected = await inspectPolishingHandoff(options);
    if (inspected.status === "complete") {
      return inspected.snapshot;
    }
    const expectedSnapshot = assertSnapshot(options.expectedSnapshot);
    const hygiene = await inspectContentHygiene({
      expectedSnapshot,
      contentFingerprint: options.finalizedFingerprint,
    });
    if (hygiene.status !== "clean") {
      throw new GitSafetyError(
        "Polishing handoff content has whitespace errors; nothing was staged.",
        { code: "ERR_POLISHING_HANDOFF_UNSTAGED_WHITESPACE" },
      );
    }
    await runGit(expectedSnapshot.projectPath, [
      ...HANDOFF_GIT_PREFIX,
      "add",
      "-A",
    ]);
    const completed = await inspectComplete(
      expectedSnapshot,
      options.finalizedFingerprint,
    );
    if (!completed.complete) {
      throw new GitSafetyError("Polishing handoff is incomplete.", {
        code: "ERR_POLISHING_HANDOFF_INCOMPLETE",
      });
    }
    return completed.snapshot;
  }

  return Object.freeze({
    inspectContentHygiene,
    inspectPolishingHandoff,
    stagePolishingHandoff,
  });
}
