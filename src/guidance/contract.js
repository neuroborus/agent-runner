import {
  basename,
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";

import { GuidanceError, unsafePath } from "./content.js";

export const HASH = /^[a-f0-9]{64}$/u;
const TEMPORARY_NAME = /^\.rules\.[a-f0-9-]{36}\.tmp$/u;
export const SELECTORS = ["projectPath", "projectConfigurationPath"];
export const UPDATE_FIELDS = [
  ...SELECTORS,
  "localContent",
  "expectedHash",
  "idempotencyKey",
];
const CONTEXT_FIELDS = [
  "projectPath",
  "localPath",
  "configurationHash",
  "phase",
  "before",
  "temporaryName",
  "temporaryIdentity",
  "receipt",
];
export const FILE_IDENTITY_FIELDS = Object.freeze([
  "dev",
  "ino",
  "birthtimeNs",
  "mode",
  "size",
  "mtimeNs",
  "ctimeNs",
  "nlink",
]);

function record(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactFields(value, fields) {
  return (
    record(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((key) => Object.hasOwn(value, key))
  );
}

export function assertInput(input, fields) {
  if (!record(input) || Object.keys(input).some((key) => !fields.includes(key)))
    throw new GuidanceError("Guidance input contains unsupported fields.");
  for (const key of SELECTORS) {
    if (key === "projectConfigurationPath" && input[key] === undefined)
      continue;
    if (
      typeof input[key] !== "string" ||
      !input[key].trim() ||
      input[key].length > 4096 ||
      /[\p{Cc}\p{Zl}\p{Zp}]/u.test(input[key])
    ) {
      throw new GuidanceError(
        "Guidance requires valid project and configuration paths.",
      );
    }
  }
}

export function isWithin(parent, child) {
  const path = relative(parent, child);
  return (
    path === "" ||
    (!isAbsolute(path) && path !== ".." && !path.startsWith(`..${sep}`))
  );
}

function validateIdentity(value) {
  return (
    exactFields(value, FILE_IDENTITY_FIELDS) &&
    FILE_IDENTITY_FIELDS.every(
      (key) => typeof value[key] === "string" && /^\d{1,32}$/u.test(value[key]),
    ) &&
    value.nlink === "1"
  );
}

export function assertReceipt(value, projectPath, hash) {
  if (
    !exactFields(value, ["projectPath", "localPath", "localHash", "updated"]) ||
    value.projectPath !== projectPath ||
    value.localHash !== hash ||
    typeof value.updated !== "boolean" ||
    typeof value.localPath !== "string" ||
    resolve(value.localPath) !== value.localPath ||
    !isWithin(projectPath, value.localPath) ||
    basename(value.localPath) !== "rules.md" ||
    basename(dirname(value.localPath)) !== "agent-runner"
  ) {
    throw new GuidanceError("Guidance publication receipt is invalid.", {
      code: "ERR_GUIDANCE_RECOVERY",
    });
  }
  return Object.freeze({ ...value });
}

export function assertContext(value, projectPath, hash, expectedHash) {
  if (
    !exactFields(value, CONTEXT_FIELDS) ||
    value.projectPath !== projectPath ||
    typeof value.localPath !== "string" ||
    resolve(value.localPath) !== value.localPath ||
    !isWithin(projectPath, value.localPath) ||
    basename(value.localPath) !== "rules.md" ||
    basename(dirname(value.localPath)) !== "agent-runner" ||
    typeof value.configurationHash !== "string" ||
    !HASH.test(value.configurationHash) ||
    !["reserved", "writing", "prepared", "published"].includes(value.phase) ||
    (value.temporaryName !== null &&
      (typeof value.temporaryName !== "string" ||
        !TEMPORARY_NAME.test(value.temporaryName))) ||
    (value.temporaryIdentity !== null &&
      !validateIdentity(value.temporaryIdentity)) ||
    (value.before !== null &&
      (!exactFields(value.before, ["hash", "identity"]) ||
        value.before.hash !== expectedHash ||
        (value.before.hash !== null &&
          (typeof value.before.hash !== "string" ||
            !HASH.test(value.before.hash))) ||
        (value.before.identity !== null &&
          !validateIdentity(value.before.identity)) ||
        (value.before.hash === null) !== (value.before.identity === null))) ||
    (["writing", "prepared"].includes(value.phase) &&
      (value.before === null ||
        value.temporaryName === null ||
        value.temporaryIdentity === null)) ||
    (value.phase !== "published" && value.receipt !== null)
  ) {
    throw new GuidanceError("Guidance publication intent is invalid.", {
      code: "ERR_GUIDANCE_RECOVERY",
    });
  }
  if (value.phase === "published") {
    assertReceipt(value.receipt, projectPath, hash);
    if (value.receipt.localPath !== value.localPath) throw unsafePath();
  }
}
