import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

export const CLARIFICATION_TEMPLATE = `# Clarifications

## Context

<!-- Optional user context. -->
`;

const MAX_TRANSCRIPT_BYTES = 1024 * 1024;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;

export class ClarificationError extends Error {
  constructor(message, { cause, code = "ERR_INVALID_CLARIFICATION" } = {}) {
    super(message, { cause });
    this.name = "ClarificationError";
    this.code = code;
  }
}

function isWithin(parentPath, childPath) {
  const pathFromParent = relative(parentPath, childPath);
  return (
    pathFromParent === "" ||
    (!pathFromParent.startsWith(`..${sep}`) &&
      pathFromParent !== ".." &&
      !isAbsolute(pathFromParent))
  );
}

function hashContent(content) {
  return createHash("sha256").update(content).digest("hex");
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

async function unlinkIfPresent(filePath) {
  try {
    await unlink(filePath);
  } catch (cause) {
    if (cause?.code !== "ENOENT") {
      throw cause;
    }
  }
}

function pathError(message, cause) {
  return new ClarificationError(message, {
    cause,
    code: "ERR_UNSAFE_CLARIFICATION_PATH",
  });
}

async function canonicalArtifactRoot(artifactRoot) {
  if (typeof artifactRoot !== "string" || artifactRoot.trim().length === 0) {
    throw pathError("Artifact root must be a non-empty path.");
  }
  try {
    const requestedRoot = resolve(artifactRoot);
    const canonicalRoot = await realpath(requestedRoot);
    const metadata = await lstat(canonicalRoot);
    if (!metadata.isDirectory()) {
      throw pathError("Artifact root must be a directory.");
    }
    return { canonicalRoot, requestedRoot };
  } catch (cause) {
    if (cause instanceof ClarificationError) {
      throw cause;
    }
    throw pathError("Cannot resolve the artifact root.", cause);
  }
}

function relativeTranscriptPath(transcriptPath, requestedRoot, canonicalRoot) {
  if (
    typeof transcriptPath !== "string" ||
    transcriptPath.length === 0 ||
    transcriptPath.includes("\0") ||
    /[\\/]$/u.test(transcriptPath)
  ) {
    throw pathError(
      "Transcript path must name a file within its artifact root.",
    );
  }

  let pathFromRoot;
  if (isAbsolute(transcriptPath)) {
    const absolutePath = resolve(transcriptPath);
    if (isWithin(requestedRoot, absolutePath)) {
      pathFromRoot = relative(requestedRoot, absolutePath);
    } else if (isWithin(canonicalRoot, absolutePath)) {
      pathFromRoot = relative(canonicalRoot, absolutePath);
    } else {
      throw pathError("Transcript path escapes its artifact root.");
    }
  } else {
    pathFromRoot = transcriptPath;
  }

  const components = pathFromRoot.split(/[\\/]/u);
  if (
    components.length === 0 ||
    components.some(
      (component) =>
        component.length === 0 || component === "." || component === "..",
    )
  ) {
    throw pathError("Transcript path contains unsafe components.");
  }
  return components;
}

async function ensureRealDirectory(directoryPath, create) {
  try {
    const metadata = await lstat(directoryPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw pathError("Transcript parent must be a real directory.");
    }
  } catch (cause) {
    if (cause instanceof ClarificationError || cause?.code !== "ENOENT") {
      throw cause;
    }
    if (!create) {
      throw cause;
    }
    try {
      await mkdir(directoryPath, { mode: 0o700 });
    } catch (mkdirCause) {
      if (mkdirCause?.code !== "EEXIST") {
        throw mkdirCause;
      }
    }
    const metadata = await lstat(directoryPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw pathError("Transcript parent must be a real directory.");
    }
  }
}

export async function resolveTranscriptPath(
  options,
  { createParents = false } = {},
) {
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options)
  ) {
    throw pathError("Transcript options must be an object.");
  }
  const { artifactRoot, transcriptPath } = options;
  const { canonicalRoot, requestedRoot } =
    await canonicalArtifactRoot(artifactRoot);
  const components = relativeTranscriptPath(
    transcriptPath,
    requestedRoot,
    canonicalRoot,
  );
  let parentPath = canonicalRoot;
  for (const component of components.slice(0, -1)) {
    parentPath = join(parentPath, component);
    try {
      await ensureRealDirectory(parentPath, createParents);
    } catch (cause) {
      if (cause instanceof ClarificationError) {
        throw cause;
      }
      throw pathError("Cannot resolve the transcript parent.", cause);
    }
  }

  try {
    const canonicalParent = await realpath(parentPath);
    if (!isWithin(canonicalRoot, canonicalParent)) {
      throw pathError("Transcript path escapes through a symlink.");
    }
  } catch (cause) {
    if (cause instanceof ClarificationError) {
      throw cause;
    }
    throw pathError("Cannot resolve the transcript parent.", cause);
  }

  const canonicalTranscriptPath = join(parentPath, components.at(-1));
  try {
    const metadata = await lstat(canonicalTranscriptPath);
    if (
      metadata.isSymbolicLink() ||
      !metadata.isFile() ||
      metadata.nlink !== 1
    ) {
      throw pathError("Transcript path must be an isolated regular file.");
    }
  } catch (cause) {
    if (cause instanceof ClarificationError || cause?.code !== "ENOENT") {
      throw cause;
    }
  }

  return Object.freeze({
    artifactRoot: canonicalRoot,
    transcriptPath: canonicalTranscriptPath,
  });
}

export async function readTranscript(location) {
  let handle;
  try {
    handle = await open(
      location.transcriptPath,
      constants.O_RDONLY | NO_FOLLOW,
    );
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1 ||
      metadata.size > MAX_TRANSCRIPT_BYTES
    ) {
      throw new ClarificationError(
        `Clarification transcript must be an isolated file no larger than ${MAX_TRANSCRIPT_BYTES} bytes.`,
      );
    }
    const content = await handle.readFile();
    if (content.byteLength > MAX_TRANSCRIPT_BYTES) {
      throw new ClarificationError(
        `Clarification transcript must not exceed ${MAX_TRANSCRIPT_BYTES} bytes.`,
      );
    }
    let source;
    try {
      source = new TextDecoder("utf-8", { fatal: true }).decode(content);
    } catch (cause) {
      throw new ClarificationError(
        "Clarification transcript must contain valid UTF-8.",
        { cause },
      );
    }
    return Object.freeze({
      ...location,
      content: source,
      hash: hashContent(content),
    });
  } catch (cause) {
    if (cause instanceof ClarificationError) {
      throw cause;
    }
    if (cause?.code === "ENOENT") {
      throw new ClarificationError("Clarification transcript does not exist.", {
        cause,
        code: "ERR_CLARIFICATION_NOT_FOUND",
      });
    }
    throw new ClarificationError("Cannot read the clarification transcript.", {
      cause,
      code: "ERR_CLARIFICATION_READ",
    });
  } finally {
    await handle?.close();
  }
}

async function writeTemporaryFile(temporaryPath, content) {
  let handle;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(content);
    await handle.sync();
  } finally {
    await handle?.close();
  }
}

export async function createTranscriptFile(location) {
  const temporaryPath = join(
    dirname(location.transcriptPath),
    `.${basename(location.transcriptPath)}.${process.pid}.${randomUUID()}.tmp`,
  );
  try {
    await writeTemporaryFile(temporaryPath, CLARIFICATION_TEMPLATE);
    let created = false;
    try {
      await link(temporaryPath, location.transcriptPath);
      created = true;
    } catch (cause) {
      if (cause?.code !== "EEXIST") {
        throw cause;
      }
    }
    await unlinkIfPresent(temporaryPath);
    await syncDirectory(dirname(location.transcriptPath));
    return created;
  } catch (cause) {
    await unlinkIfPresent(temporaryPath);
    throw new ClarificationError(
      "Cannot create the clarification transcript.",
      {
        cause,
        code: "ERR_CLARIFICATION_WRITE",
      },
    );
  }
}

export async function replaceTranscript(location, content) {
  if (Buffer.byteLength(content) > MAX_TRANSCRIPT_BYTES) {
    throw new ClarificationError(
      `Clarification transcript must not exceed ${MAX_TRANSCRIPT_BYTES} bytes.`,
    );
  }
  const currentLocation = await resolveTranscriptPath(location);
  if (
    currentLocation.artifactRoot !== location.artifactRoot ||
    currentLocation.transcriptPath !== location.transcriptPath
  ) {
    throw pathError("Clarification transcript path changed unexpectedly.");
  }
  const currentSnapshot = await readTranscript(currentLocation);
  if (currentSnapshot.hash !== location.hash) {
    throw new ClarificationError(
      "Clarification transcript changed outside an authorized edit window.",
      { code: "ERR_CLARIFICATIONS_CHANGED" },
    );
  }

  const temporaryPath = join(
    dirname(location.transcriptPath),
    `.${basename(location.transcriptPath)}.${process.pid}.${randomUUID()}.tmp`,
  );
  try {
    await writeTemporaryFile(temporaryPath, content);
    await rename(temporaryPath, location.transcriptPath);
    await syncDirectory(dirname(location.transcriptPath));
  } catch (cause) {
    await unlinkIfPresent(temporaryPath);
    throw new ClarificationError(
      "Cannot update the clarification transcript.",
      {
        cause,
        code: "ERR_CLARIFICATION_WRITE",
      },
    );
  }
}
