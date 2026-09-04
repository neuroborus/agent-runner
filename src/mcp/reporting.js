import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, realpath, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";

import {
  loadProjectConfiguration,
  loadRunnerConfiguration,
} from "../config.js";
import { createGitService } from "../git/index.js";

const ISSUES_PATH = ["agent-runner", "issues"];
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const REPORT_NAME_PATTERN =
  /^issue_\d{4}-\d{2}-\d{2}_\d{6}\.\d{3}Z(?:_\d{3}|_[a-f0-9]{12})?\.md$/u;

class UnexpectedIssueReportError extends Error {
  constructor(message, { cause, code = "ERR_UNEXPECTED_ISSUE_REPORT" } = {}) {
    super(message, { cause });
    this.name = "UnexpectedIssueReportError";
    this.code = code;
  }
}

function reportError(message, cause) {
  return new UnexpectedIssueReportError(message, {
    cause,
    code: "ERR_UNSAFE_ISSUE_REPORT_PATH",
  });
}

async function syncDirectory(directoryPath) {
  let handle;
  try {
    handle = await open(directoryPath, "r");
    await handle.sync();
  } catch (cause) {
    if (!["EINVAL", "ENOTSUP", "EPERM", "EISDIR"].includes(cause?.code)) {
      throw cause;
    }
  } finally {
    await handle?.close();
  }
}

async function unlinkIfPresent(path) {
  try {
    await unlink(path);
  } catch (cause) {
    if (cause?.code !== "ENOENT") {
      throw cause;
    }
  }
}

async function ensureRealDirectory(path) {
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (cause) {
    if (cause?.code !== "EEXIST") {
      throw cause;
    }
  }
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw reportError("Issue report parent must be a real directory.");
  }
}

async function ensureIssuesDirectory(projectPath, requestedIssuesPath) {
  const pathFromProject = relative(projectPath, requestedIssuesPath);
  const components = pathFromProject.split(sep);
  if (
    pathFromProject.length === 0 ||
    isAbsolute(pathFromProject) ||
    pathFromProject === ".." ||
    pathFromProject.startsWith(`..${sep}`) ||
    components.length < 3 ||
    components.at(-2) !== ISSUES_PATH[0] ||
    components.at(-1) !== ISSUES_PATH[1]
  ) {
    throw reportError("Issue report destination is invalid.");
  }
  let directoryPath = projectPath;
  for (const component of components) {
    directoryPath = join(directoryPath, component);
    await ensureRealDirectory(directoryPath);
  }
  const canonicalPath = await realpath(directoryPath);
  if (
    canonicalPath !== directoryPath ||
    canonicalPath !== requestedIssuesPath
  ) {
    throw reportError("Issue report path escapes through a symbolic link.");
  }
  return canonicalPath;
}

function formatTimestamp(currentTime) {
  const value = new Date(currentTime);
  if (Number.isNaN(value.valueOf())) {
    throw new UnexpectedIssueReportError(
      "Issue reporting clock returned an invalid date.",
    );
  }
  return value.toISOString().replace("T", "_").replaceAll(":", "");
}

function reportFilename(timestamp, attempt, tokenFactory) {
  if (attempt === 0) {
    return `issue_${timestamp}.md`;
  }
  if (attempt < 1_000) {
    return `issue_${timestamp}_${String(attempt).padStart(3, "0")}.md`;
  }
  const token = tokenFactory().replaceAll("-", "").slice(0, 12);
  if (!/^[a-f0-9]{12}$/u.test(token)) {
    throw new UnexpectedIssueReportError(
      "Issue report identity factory returned an invalid value.",
    );
  }
  return `issue_${timestamp}_${token}.md`;
}

function temporaryToken(tokenFactory) {
  const token = tokenFactory();
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    token.length > 128 ||
    !/^[A-Za-z0-9-]+$/u.test(token)
  ) {
    throw new UnexpectedIssueReportError(
      "Issue report identity factory returned an invalid value.",
    );
  }
  return token;
}

function temporaryReportPath(reportPath, tokenFactory) {
  return join(
    dirname(reportPath),
    `.${basename(reportPath)}.${process.pid}.${temporaryToken(tokenFactory)}.tmp`,
  );
}

function renderReport(input) {
  const sections = [
    "# Unexpected Agent Runner Issue",
    "",
    "## Summary",
    "",
    input.summary,
    "",
    "## Expected Behavior",
    "",
    input.expectedBehavior,
    "",
    "## Actual Behavior",
    "",
    input.actualBehavior,
    "",
    "## Occurrence",
    "",
    input.occurrence,
    "",
    "## Why This Was Unexpected",
    "",
    input.unexpectedReason,
  ];
  if (input.details !== undefined) {
    sections.push("", "## Details", "", input.details);
  }
  if (input.runId !== undefined || input.errorCode !== undefined) {
    sections.push("", "## Metadata", "");
    if (input.runId !== undefined) {
      sections.push(`- Run ID: \`${input.runId}\``);
    }
    if (input.errorCode !== undefined) {
      sections.push(`- Error code: \`${input.errorCode}\``);
    }
  }
  return `${sections.join("\n")}\n`;
}

function assertReservedPaths(issuesPath, reportPath, temporaryPath) {
  if (
    typeof reportPath !== "string" ||
    dirname(reportPath) !== issuesPath ||
    !REPORT_NAME_PATTERN.test(basename(reportPath)) ||
    relative(issuesPath, reportPath) !== basename(reportPath) ||
    typeof temporaryPath !== "string" ||
    dirname(temporaryPath) !== issuesPath ||
    relative(issuesPath, temporaryPath) !== basename(temporaryPath) ||
    !basename(temporaryPath).startsWith(`.${basename(reportPath)}.`) ||
    !/^\.issue_.+\.\d+\.[A-Za-z0-9-]+\.tmp$/u.test(basename(temporaryPath))
  ) {
    throw reportError("Reserved issue report identity is invalid.");
  }
}

async function readBounded(handle, maximumBytes) {
  const source = Buffer.alloc(maximumBytes + 1);
  let offset = 0;
  while (offset < source.length) {
    const { bytesRead } = await handle.read(
      source,
      offset,
      source.length - offset,
      offset,
    );
    if (bytesRead === 0) {
      break;
    }
    offset += bytesRead;
  }
  return source.subarray(0, offset);
}

async function existingReportMatches(
  reportPath,
  content,
  { linkCount = 1n } = {},
) {
  let pathMetadata;
  try {
    pathMetadata = await lstat(reportPath, { bigint: true });
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return false;
    }
    throw cause;
  }
  if (
    pathMetadata.isSymbolicLink() ||
    !pathMetadata.isFile() ||
    pathMetadata.nlink !== linkCount
  ) {
    throw reportError("Issue report path must be an isolated regular file.");
  }
  const expected = Buffer.from(content);
  const expectedSize = BigInt(expected.byteLength);
  if (pathMetadata.size !== expectedSize) {
    return false;
  }

  let handle;
  try {
    handle = await open(reportPath, constants.O_RDONLY | NO_FOLLOW);
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== linkCount ||
      before.dev !== pathMetadata.dev ||
      before.ino !== pathMetadata.ino ||
      before.size !== expectedSize ||
      before.mtimeNs !== pathMetadata.mtimeNs ||
      before.ctimeNs !== pathMetadata.ctimeNs
    ) {
      throw reportError("Issue report path changed while it was read.");
    }
    const source = await readBounded(handle, expected.byteLength);
    const [after, pathAfter] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(reportPath, { bigint: true }),
    ]);
    if (
      after.nlink !== linkCount ||
      pathAfter.nlink !== linkCount ||
      after.dev !== pathAfter.dev ||
      after.ino !== pathAfter.ino ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      after.ctimeNs !== before.ctimeNs ||
      after.size !== pathAfter.size ||
      after.mtimeNs !== pathAfter.mtimeNs ||
      after.ctimeNs !== pathAfter.ctimeNs
    ) {
      throw reportError("Issue report path changed while it was read.");
    }
    return source.equals(expected);
  } catch (cause) {
    if (cause instanceof UnexpectedIssueReportError) {
      throw cause;
    }
    throw reportError("Cannot safely read the reserved issue report.", cause);
  } finally {
    await handle?.close();
  }
}

async function pathMetadata(path) {
  try {
    return await lstat(path, { bigint: true });
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return null;
    }
    throw cause;
  }
}

async function recoverPublication(
  reportPath,
  temporaryPath,
  content,
  { linkFile, markPublished, publicationPhase },
) {
  const [reportMetadata, temporaryMetadata] = await Promise.all([
    pathMetadata(reportPath),
    pathMetadata(temporaryPath),
  ]);
  if (temporaryMetadata === null) {
    if (reportMetadata === null) {
      if (publicationPhase === "published") {
        throw reportError("Published issue report is missing.");
      }
      return "available";
    }
    const matches = await existingReportMatches(reportPath, content);
    if (publicationPhase === "published") {
      if (!matches) {
        throw reportError("Published issue report content is invalid.");
      }
      return "published";
    }
    return "collision";
  }
  if (reportMetadata === null) {
    if (publicationPhase === "published") {
      throw reportError("Published issue report path is missing.");
    }
    if (!(await existingReportMatches(temporaryPath, content))) {
      throw reportError("Reserved issue report temporary content is invalid.");
    }
    try {
      await linkFile(temporaryPath, reportPath);
    } catch (cause) {
      if (cause?.code === "EEXIST") {
        await unlinkIfPresent(temporaryPath);
        await syncDirectory(dirname(reportPath));
        return "collision";
      }
      throw cause;
    }
  } else {
    if (
      reportMetadata.nlink === 1n &&
      temporaryMetadata.nlink === 1n &&
      (reportMetadata.dev !== temporaryMetadata.dev ||
        reportMetadata.ino !== temporaryMetadata.ino)
    ) {
      if (publicationPhase === "published") {
        throw reportError("Published issue report ownership is invalid.");
      }
      if (!(await existingReportMatches(temporaryPath, content))) {
        throw reportError(
          "Reserved issue report temporary content is invalid.",
        );
      }
      await unlinkIfPresent(temporaryPath);
      await syncDirectory(dirname(reportPath));
      return "collision";
    }
    if (
      reportMetadata.nlink !== 2n ||
      temporaryMetadata.nlink !== 2n ||
      reportMetadata.dev !== temporaryMetadata.dev ||
      reportMetadata.ino !== temporaryMetadata.ino ||
      !(await existingReportMatches(reportPath, content, { linkCount: 2n }))
    ) {
      throw reportError("Reserved issue report publication is unsafe.");
    }
  }
  await syncDirectory(dirname(reportPath));
  if (publicationPhase !== "published") {
    await markPublished();
  }
  await unlinkIfPresent(temporaryPath);
  await syncDirectory(dirname(reportPath));
  if (!(await existingReportMatches(reportPath, content))) {
    throw reportError("Recovered issue report content is invalid.");
  }
  return "published";
}

async function publishExclusive(
  reportPath,
  temporaryPath,
  content,
  publication,
) {
  const recovery = await recoverPublication(
    reportPath,
    temporaryPath,
    content,
    publication,
  );
  if (recovery === "published") {
    return true;
  }
  if (recovery === "collision") {
    return false;
  }
  let handle;
  let preserveTemporary = false;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.nlink !== 1) {
      throw reportError("Issue report temporary path is unsafe.");
    }
    await handle.writeFile(content);
    await handle.sync();
    await handle.close();
    handle = undefined;
    try {
      await publication.linkFile(temporaryPath, reportPath);
    } catch (cause) {
      if (cause?.code === "EEXIST") {
        return false;
      }
      throw cause;
    }
    preserveTemporary = true;
    await syncDirectory(dirname(reportPath));
    await publication.markPublished();
    await unlinkIfPresent(temporaryPath);
    preserveTemporary = false;
    await syncDirectory(dirname(reportPath));
    if (!(await existingReportMatches(reportPath, content))) {
      throw reportError("Published issue report content is invalid.");
    }
    return true;
  } catch (cause) {
    if (cause instanceof UnexpectedIssueReportError) {
      throw cause;
    }
    throw new UnexpectedIssueReportError("Cannot publish the issue report.", {
      cause,
      code: "ERR_ISSUE_REPORT_WRITE",
    });
  } finally {
    await handle?.close();
    if (!preserveTemporary) {
      await unlinkIfPresent(temporaryPath);
    }
  }
}

export function createUnexpectedIssueReporter({
  clock = () => new Date(),
  git = createGitService(),
  linkFile = link,
  loadConfiguration = loadRunnerConfiguration,
  onPublished = async () => {},
  tokenFactory = randomUUID,
} = {}) {
  if (
    typeof clock !== "function" ||
    typeof git?.inspectPath !== "function" ||
    typeof git?.resolveProject !== "function" ||
    typeof linkFile !== "function" ||
    typeof loadConfiguration !== "function" ||
    typeof onPublished !== "function" ||
    typeof tokenFactory !== "function"
  ) {
    throw new UnexpectedIssueReportError("Issue reporter options are invalid.");
  }

  async function report(
    input,
    {
      prepare,
      publish,
      reserve,
      reservedIssuesPath = null,
      reservedPath = null,
      reservedPublicationPhase = null,
      reservedProjectPath = null,
      reservedTemporaryPath = null,
    } = {},
  ) {
    if (
      typeof prepare !== "function" ||
      typeof publish !== "function" ||
      typeof reserve !== "function"
    ) {
      throw new UnexpectedIssueReportError(
        "Issue report reservation is unavailable.",
      );
    }
    const projectPath = await git.resolveProject(input.projectPath);
    if (reservedProjectPath !== null && reservedProjectPath !== projectPath) {
      throw reportError("Reserved issue report project changed unexpectedly.");
    }
    let requestedIssuesPath = reservedIssuesPath;
    if (requestedIssuesPath === null) {
      const configuration = await loadConfiguration();
      const projectConfiguration = await loadProjectConfiguration({
        ...(input.projectConfigurationPath === undefined
          ? {}
          : { configurationPath: input.projectConfigurationPath }),
        inspectPath: git.inspectPath,
        projectPath,
        runnerConfiguration: configuration,
      });
      const artifactRoot =
        projectConfiguration?.configuration.artifactRoot ??
        configuration.artifactRoot;
      requestedIssuesPath = join(
        projectPath,
        ...artifactRoot.split("/"),
        ...ISSUES_PATH,
      );
    } else if (reservedProjectPath === null) {
      throw reportError("Reserved issue report destination is invalid.");
    }
    const initialInspection = await git.inspectPath({
      path: requestedIssuesPath,
      projectPath,
    });
    if (initialInspection.tracked || !initialInspection.ignored) {
      throw new UnexpectedIssueReportError(
        "Issue report destination must be ignored and untracked.",
        { code: "ERR_ISSUE_REPORT_NOT_IGNORED" },
      );
    }
    if (reservedIssuesPath === null) {
      await prepare({
        issuesPath: initialInspection.path,
        projectPath,
      });
    }
    const issuesPath = await ensureIssuesDirectory(
      projectPath,
      initialInspection.path,
    );
    const finalInspection = await git.inspectPath({
      path: issuesPath,
      projectPath,
    });
    if (
      finalInspection.path !== issuesPath ||
      finalInspection.tracked ||
      !finalInspection.ignored
    ) {
      throw reportError("Issue report destination changed unexpectedly.");
    }

    const content = renderReport(input);
    const timestamp = formatTimestamp(clock());
    let reportPath = reservedPath;
    let publicationPhase = reservedPublicationPhase;
    let temporaryPath = reservedTemporaryPath;
    if (
      (reportPath === null && publicationPhase !== null) ||
      (reportPath !== null &&
        !["reserved", "published"].includes(publicationPhase))
    ) {
      throw reportError("Reserved issue report publication phase is invalid.");
    }
    for (let attempt = 0; attempt < 1_010; attempt += 1) {
      if (reportPath === null) {
        reportPath = join(
          issuesPath,
          reportFilename(timestamp, attempt, tokenFactory),
        );
        if (await existingReportMatches(reportPath, content)) {
          reportPath = null;
          continue;
        }
        temporaryPath = temporaryReportPath(reportPath, tokenFactory);
        publicationPhase = "reserved";
        await reserve({ publicationPhase, reportPath, temporaryPath });
      } else {
        assertReservedPaths(issuesPath, reportPath, temporaryPath);
      }

      if (
        await publishExclusive(reportPath, temporaryPath, content, {
          async markPublished() {
            if (publicationPhase !== "published") {
              await publish({ publicationPhase: "published" });
              publicationPhase = "published";
            }
          },
          linkFile,
          publicationPhase,
        })
      ) {
        await onPublished(reportPath);
        return reportPath;
      }
      reportPath = null;
      publicationPhase = null;
      temporaryPath = null;
    }
    throw new UnexpectedIssueReportError(
      "Cannot allocate a collision-free issue report path.",
      { code: "ERR_ISSUE_REPORT_COLLISION" },
    );
  }

  return Object.freeze({ report, resolveProject: git.resolveProject });
}
