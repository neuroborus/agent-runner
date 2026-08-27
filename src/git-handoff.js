import { GitSafetyError } from "./git-command.js";

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

function unique(values) {
  return [...new Set(values)];
}

export function createGitHandoffService({
  assertSnapshot,
  indexContentFingerprint,
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
    const [staged, unstaged, untracked, stagedContentFingerprint] =
      await Promise.all([
        runGit(
          current.projectPath,
          [
            "diff",
            "--cached",
            "--quiet",
            "--exit-code",
            "--ignore-submodules=none",
            "--no-ext-diff",
            "--no-textconv",
          ],
          { allowedExitCodes: [0, 1] },
        ),
        runGit(
          current.projectPath,
          [
            "diff",
            "--quiet",
            "--exit-code",
            "--ignore-submodules=none",
            "--no-ext-diff",
            "--no-textconv",
          ],
          { allowedExitCodes: [0, 1] },
        ),
        runGit(current.projectPath, [
          "ls-files",
          "--others",
          "--exclude-standard",
          "-z",
        ]),
        indexContentFingerprint(
          current.projectPath,
          current.allowedPaths,
        ),
      ]);
    const complete =
      staged.exitCode === 1 &&
      unstaged.exitCode === 0 &&
      untracked.stdout.length === 0 &&
      stagedContentFingerprint === expectedContentFingerprint;
    if (!complete) {
      return Object.freeze({ complete: false, snapshot: current });
    }
    const whitespace = await runGit(
      current.projectPath,
      ["diff", "--cached", "--check"],
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
      inspected.snapshot.indexFingerprint !==
      expectedSnapshot.indexFingerprint
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
    await runGit(expectedSnapshot.projectPath, ["add", "-A"]);
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

  return Object.freeze({ inspectPolishingHandoff, stagePolishingHandoff });
}
