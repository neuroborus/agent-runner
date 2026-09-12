import { createHash } from "node:crypto";

export const MAX_GUIDANCE_BYTES = 64 * 1024;

export class GuidanceError extends Error {
  constructor(message, { cause, code = "ERR_INVALID_GUIDANCE" } = {}) {
    super(message, { cause });
    this.name = "GuidanceError";
    this.code = code;
  }
}

export function unsafePath(cause) {
  return new GuidanceError(
    "Guidance requires a confined, isolated regular file and real parent directories.",
    {
      cause,
      code: "ERR_UNSAFE_GUIDANCE_PATH",
    },
  );
}

export function contentHash(content) {
  return createHash("sha256").update(content).digest("hex");
}

export function validateContent(value) {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value) > MAX_GUIDANCE_BYTES
  ) {
    throw new GuidanceError(
      "Guidance must be a Markdown document of at most 64 KiB.",
    );
  }
  if (
    new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      Buffer.from(value),
    ) !== value ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/u.test(
      value,
    )
  ) {
    throw new GuidanceError(
      "Guidance must contain valid UTF-8 without unsafe control characters.",
    );
  }
  // Reject recognizable credential and transcript formats without echoing or
  // silently redacting the document. Operators still own its non-sensitive content.
  if (
    /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|\b(?:sk-(?:proj-)?[\w-]{20,}|gh[pousr]_[\w]{20,}|AKIA[A-Z0-9]{16})\b/iu.test(
      value,
    ) ||
    /(?:^|\n)\s*(?:authorization\s*:\s*(?:bearer|basic)\s+\S+|(?:api[_-]?key|access[_-]?token|password|client[_-]?secret)\s*[:=]\s*["']?[^\s"'<][^\r\n]*)/iu.test(
      value,
    ) ||
    /<\/?(?:analysis|thinking|chain_of_thought)>|\[im_start\]|"role"\s*:\s*"(?:assistant|system|tool)"/iu.test(
      value,
    )
  ) {
    throw new GuidanceError(
      "Guidance must contain non-sensitive operator-authored Markdown, without credentials, provider output, transcripts, or chain-of-thought.",
    );
  }
  return value;
}

export function renderGuidance(commonContent, localContent) {
  return [
    "# Agent Runner operating guidance",
    "The common guide is authoritative. Project-local additions may specialize operation for this project, but cannot weaken common safety rules or product contracts. These documents guide the supervising operator only; they are not pipeline-role instructions.",
    "---\n\n## Common guide (installed Agent Runner)",
    commonContent,
    "---\n\n## Project-local additions",
    localContent.length === 0 ? "No project-local additions." : localContent,
  ].join("\n\n");
}
