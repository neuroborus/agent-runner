import { isAbsolute, sep } from "node:path";

export const SOURCE_SCOPES = Object.freeze(["directory", "git"]);

export function validExcludePaths(value) {
  return (
    Array.isArray(value) &&
    value.length <= 256 &&
    new Set(value).size === value.length &&
    value.every(
      (path) =>
        typeof path === "string" &&
        path.length > 0 &&
        path.length <= 4096 &&
        !isAbsolute(path) &&
        !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(path) &&
        path.split(sep).every((part) => !["", ".", ".."].includes(part)),
    )
  );
}

export function assertSourceSettings({ sourceScope, excludePaths }) {
  if (
    !SOURCE_SCOPES.includes(sourceScope) ||
    !validExcludePaths(excludePaths) ||
    (sourceScope === "git" && excludePaths.length !== 0)
  )
    throw new Error(
      "Audit source scope must be directory or git; literal confined excludePaths require directory scope.",
    );
}
