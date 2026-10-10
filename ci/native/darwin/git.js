import { spawn } from "node:child_process";
import { posix as path } from "node:path";
import { performance } from "node:perf_hooks";
import {
  FIXED_SUBJECT,
  validateCommitRequest,
  validateCommitEffect,
  validateCommitMetadata,
} from "../index.js";
import {
  digest,
  inspectDarwinMachO,
  normalizeDarwinLaunch,
  normalizeDarwinIdentity,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";
import { protectedBytes } from "./private-files.js";
import { darwinFixedGitChannel } from "./channel.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const sha = (value) =>
  typeof value === "string" && /^[a-f0-9]{40}$/u.test(value);
const inside = (parent, child) => child.startsWith(parent + "/");
function root(value) {
  const identity = normalizeDarwinIdentity(value);
  requireDarwin(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
}
function snapshot(value) {
  requireDarwin(
    value &&
      typeof value.config === "string" &&
      value.config.length <= 65536 &&
      typeof value.identity === "string" &&
      value.identity.length > 0 &&
      value.identity.length <= 512 &&
      value.branch === "refs/heads/proof" &&
      sha(value.head) &&
      Array.isArray(value.refs) &&
      value.refs.length > 0 &&
      value.refs.length <= 256 &&
      Array.from(value.refs).every(
        (entry) =>
          Array.isArray(entry) &&
          entry.length === 2 &&
          typeof entry[0] === "string" &&
          /^refs\/[A-Za-z0-9_./-]{1,240}$/u.test(entry[0]) &&
          sha(entry[1]),
      ) &&
      new Set(value.refs.map((entry) => entry[0])).size === value.refs.length &&
      value.refs.some(
        (entry) => entry[0] === value.branch && entry[1] === value.head,
      ) &&
      Array.isArray(value.metadata) &&
      value.metadata.length > 0 &&
      value.metadata.length <= 4096 &&
      Array.from(value.metadata).every(
        (entry) =>
          Array.isArray(entry) &&
          entry.length === 3 &&
          typeof entry[0] === "string" &&
          entry[0].length > 0 &&
          entry[0].length <= 512 &&
          !entry[0].startsWith("/") &&
          !entry[0].split("/").some((part) => ["", ".", ".."].includes(part)) &&
          hash(entry[1]) &&
          Number.isSafeInteger(entry[2]) &&
          entry[2] >= 0 &&
          entry[2] <= 0o7777,
      ) &&
      new Set(value.metadata.map((entry) => entry[0])).size ===
        value.metadata.length,
  );
}
function workspace(value, input) {
  const expected = [
    [".git", digest(`gitdir: ${input.metadata}\n`), 0o400],
    ["content.txt", digest("owned edit\n"), 0o400],
  ];
  requireDarwin(JSON.stringify(value.workspace) === JSON.stringify(expected));
}
export function normalizeDarwinGitInput(value) {
  const fields = [
    "request",
    "git",
    "metadata",
    "hooks",
    "parent",
    "reviewSha256",
  ];
  requireDarwin(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === fields.length &&
      fields.every((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable && Object.hasOwn(descriptor, "value");
      }),
  );
  requireDarwin(
    value.git &&
      Object.getPrototypeOf(value.git) === Object.prototype &&
      Reflect.ownKeys(value.git).length === 3 &&
      ["path", "sha256", "cdhash"].every((key) => {
        const field = Object.getOwnPropertyDescriptor(value.git, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
  const input = {
    request: normalizeDarwinLaunch(value.request),
    git: {
      path: value.git.path,
      sha256: value.git.sha256,
      cdhash: value.git.cdhash,
    },
    metadata: value.metadata,
    hooks: value.hooks,
    parent: value.parent,
    reviewSha256: value.reviewSha256,
  };
  requireDarwin(
    input.git &&
      Object.getPrototypeOf(input.git) === Object.prototype &&
      Reflect.ownKeys(input.git).sort().join(",") === "cdhash,path,sha256" &&
      hash(input.git.sha256) &&
      sha(input.git.cdhash) &&
      sha(input.parent) &&
      hash(input.reviewSha256),
  );
  for (const location of [input.git.path, input.metadata, input.hooks])
    requireDarwin(
      typeof location === "string" &&
        location.length <= 4096 &&
        path.normalize(location) === location &&
        !/[\u0000-\u001f\u007f]/u.test(location) &&
        inside(input.request.storage, location) &&
        !inside(input.request.workspace, location) &&
        !inside(location, input.request.workspace) &&
        location !== input.request.workspace,
    );
  requireDarwin(
    new Set([
      input.git.path,
      input.metadata,
      input.hooks,
      input.request.executable.path,
    ]).size === 4 &&
      !inside(input.metadata, input.hooks) &&
      !inside(input.hooks, input.metadata) &&
      !inside(input.metadata, input.git.path) &&
      !inside(input.hooks, input.git.path) &&
      !inside(input.metadata, input.request.executable.path) &&
      !inside(input.hooks, input.request.executable.path),
  );
  return input;
}

export function darwinFixedCommitArguments(value, request) {
  const input = normalizeDarwinGitInput(value);
  validateCommitRequest(request);
  return [
    input.request.nonce,
    input.git.path,
    input.metadata,
    input.request.workspace,
    input.hooks,
    input.parent,
    "commit",
    FIXED_SUBJECT,
  ];
}
export function darwinOrdinaryGitArguments(value, operation) {
  const input = normalizeDarwinGitInput(value);
  requireDarwin(["inspect", "git-add", "git-commit"].includes(operation));
  return [
    input.request.nonce,
    operation,
    input.git.path,
    input.metadata,
    input.request.workspace,
    input.hooks,
  ];
}

function admit(value, input) {
  const helper = root(value?.helper),
    verifier = root(value?.verifier);
  requireDarwin(
    verifier.pid !== helper.pid &&
      value.independent === true &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      value.helperSha256 === input.request.executable.sha256 &&
      value.cdhash === input.request.executable.cdhash &&
      value.gitSha256 === input.git.sha256 &&
      value.gitCdhash === input.git.cdhash &&
      value.closureSha256 === input.request.bindings.closure &&
      value.directoriesVerified === true &&
      value.soleMetadataAuthority === true &&
      value.noLiveUid === true &&
      value.providersExcluded === true &&
      hash(value.receiptSha256),
  );
  return helper;
}

/** Only dedicated CI may start this protected parked executor. No Git effect
 * occurs before independent executable/closure/directory admission and release. */
export async function openDarwinGitExecutor(value, request, effects) {
  const input = normalizeDarwinGitInput(value),
    args = darwinFixedCommitArguments(input, request);
  requireDarwin(
    process.platform === "darwin" &&
      process.arch === "x64" &&
      process.geteuid() === 0 &&
      process.env.CI === "true" &&
      process.env.GITHUB_ACTIONS === "true" &&
      process.env.ImageOS === "macos15" &&
      ["created", "admit"].every((key) => typeof effects?.[key] === "function"),
  );
  inspectDarwinMachO(
    await protectedBytes(input.request.executable, 0, 0o550, 134217728),
  );
  inspectDarwinMachO(
    await protectedBytes(input.git, input.request.gid, 0o550, 134217728),
  );
  const requestSha256 = digest(JSON.stringify(input));
  const child = spawn(input.request.executable.path, args, {
    cwd: input.request.custody,
    env: { CI: "true", GITHUB_ACTIONS: "true", PATH: "/nonexistent" },
    stdio: ["pipe", "pipe", "ignore"],
  });
  const channel = darwinFixedGitChannel(child, input.request.nonce);
  try {
    await channel.wait(
      effects.created(child, structuredClone(input), requestSha256),
    );
    await channel.ready;
    const admission = structuredClone(
      await channel.wait(
        effects.admit(child, structuredClone(input), [...args]),
      ),
    );
    requireDarwin(admit(admission, input).pid === child.pid);
    return {
      admission,
      completion: channel.completion,
      release: channel.release,
      close: channel.close,
      dispose: channel.dispose,
    };
  } catch (error) {
    channel.close();
    channel.dispose();
    throw error;
  }
}

export function assertDarwinCommitObservation(before, after, evidence, value) {
  const input = normalizeDarwinGitInput(value);
  snapshot(before);
  snapshot(after);
  workspace(before, input);
  workspace(after, input);
  const verifier = root(evidence?.verifier);
  requireDarwin(
    before.head === input.parent &&
      before.branch === "refs/heads/proof" &&
      evidence.independent === true &&
      evidence.candidateSha === input.request.candidateSha &&
      evidence.requestSha256 === digest(JSON.stringify(input)) &&
      evidence.disposable === true &&
      evidence.outsideUnchanged === true &&
      hash(evidence.outsideBeforeSha256) &&
      evidence.outsideAfterSha256 === evidence.outsideBeforeSha256 &&
      evidence.directoriesUnchanged === true &&
      evidence.hooksEmpty === true &&
      evidence.ambientConfigurationSuppressed === true &&
      evidence.providersExcluded === true &&
      hash(evidence.nativeEventSha256) &&
      hash(evidence.receiptSha256) &&
      evidence.objects?.commit === after.head &&
      sha(evidence.objects.tree) &&
      sha(evidence.objects.blob) &&
      after.parents?.length === 1 &&
      after.parents[0] === before.head &&
      evidence.objects.blobBytes === "owned edit\n" &&
      evidence.objects.treeEntry ===
        "100644 blob " + evidence.objects.blob + "\tcontent.txt\n",
  );
  validateCommitEffect(before, after);
  validateCommitMetadata(before.metadata, after.metadata, [
    after.head,
    evidence.objects.tree,
    evidence.objects.blob,
  ]);
  const operations = ["parent", "branch", "status", "add", "commit"];
  requireDarwin(
    Array.isArray(evidence.children) &&
      evidence.children.length === operations.length,
  );
  const identities = new Set();
  for (let index = 0; index < operations.length; index++) {
    const child = evidence.children[index],
      identity = root(child?.identity);
    const key = JSON.stringify(identity);
    requireDarwin(
      child.operation === operations[index] &&
        child.independent === true &&
        child.settled === true &&
        child.imageSha256 === input.git.sha256 &&
        child.cdhash === input.git.cdhash &&
        child.requestSha256 === digest(JSON.stringify(input)) &&
        hash(child.nativeEventSha256) &&
        verifier.pid !== identity.pid &&
        !identities.has(key),
    );
    identities.add(key);
  }
  return verifier;
}

export function assertDarwinOrdinaryGitObservation(value, input) {
  input = normalizeDarwinGitInput(input);
  root(value?.verifier);
  requireDarwin(
    value.independent === true &&
      value.candidateSha === input.request.candidateSha &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      hash(value.receiptSha256) &&
      hash(value.outsideBeforeSha256) &&
      value.outsideAfterSha256 === value.outsideBeforeSha256 &&
      Array.isArray(value.profiles) &&
      value.profiles.length === 3,
  );
  const seen = new Set();
  for (const profile of value.profiles) {
    snapshot(profile.before);
    snapshot(profile.after);
    requireDarwin(
      ["read-only", "workspace-write", "trusted-command"].includes(
        profile.profile,
      ) &&
        !seen.has(profile.profile) &&
        profile.inspection.code === 0 &&
        profile.inspection.head === input.parent &&
        hash(profile.inspection.nativeEventSha256) &&
        profile.disposable === true &&
        profile.providersExcluded === true &&
        profile.outsideUnchanged === true &&
        JSON.stringify(profile.before.metadata) ===
          JSON.stringify(profile.after.metadata) &&
        profile.before.config === profile.after.config &&
        profile.before.identity === profile.after.identity &&
        profile.before.head === input.parent &&
        profile.before.head === profile.after.head &&
        profile.before.branch === profile.after.branch &&
        JSON.stringify(profile.before.refs) ===
          JSON.stringify(profile.after.refs) &&
        profile.before.pointerSha256 === profile.after.pointerSha256 &&
        hash(profile.before.pointerSha256) &&
        Array.isArray(profile.denials) &&
        profile.denials.length === 2,
    );
    const attempts = new Set();
    for (const denied of profile.denials) {
      const identity = normalizeDarwinIdentity(denied.identity);
      requireDarwin(
        ["git-add", "git-commit"].includes(denied.id) &&
          !attempts.has(denied.id) &&
          denied.attempted === true &&
          denied.timedOut === false &&
          denied.signal === null &&
          Number.isSafeInteger(denied.exitCode) &&
          denied.exitCode > 0 &&
          denied.exitCode < 256 &&
          ["EPERM", "EACCES", "EROFS"].includes(denied.nativeCode) &&
          denied.nativeDecision === "deny-metadata-write" &&
          hash(denied.nativeEventSha256) &&
          denied.imageSha256 === input.git.sha256 &&
          denied.cdhash === input.git.cdhash &&
          denied.control.ready === true &&
          denied.control.reachable === true &&
          denied.control.independent === true &&
          denied.control.nonce === input.request.nonce &&
          denied.control.operation === denied.id &&
          denied.control.nativeCode === "OK" &&
          hash(denied.control.nativeEventSha256) &&
          hash(denied.control.receiptSha256) &&
          value.verifier.pid !== identity.pid &&
          identity.auid === input.request.uid &&
          identity.asid > 0 &&
          ["uid", "ruid", "svuid"].every(
            (key) => identity[key] === input.request.uid,
          ) &&
          ["gid", "rgid", "svgid"].every(
            (key) => identity[key] === input.request.gid,
          ),
      );
      attempts.add(denied.id);
    }
    seen.add(profile.profile);
  }
  return true;
}

/** This grant is CI-private, separate from all ordinary/provider profiles.
 * Protected readers own snapshots, native Git children and fresh settlement. */
export async function runDarwinGitCase(
  checkId,
  value,
  effects,
  { now = () => performance.now() } = {},
) {
  const input = normalizeDarwinGitInput(value),
    request = validateCommitRequest({
      operation: "commit",
      subject: FIXED_SUBJECT,
    });
  requireDarwin(
    ["git.ordinary-denial", "git.fixed-commit"].includes(checkId) &&
      typeof effects?.persist === "function",
  );
  const record = {
    schemaVersion: 1,
    checkId,
    candidateSha: input.request.candidateSha,
    nonce: input.request.nonce,
    requestSha256: digest(JSON.stringify(input)),
    status: "BLOCKED",
    reservation: "RETAINED",
    missingInputs: [],
  };
  const required =
    checkId === "git.fixed-commit"
      ? ["snapshot", "review", "open", "observe", "retire"]
      : ["review", "ordinary", "retire"];
  for (const key of required)
    if (typeof effects[key] !== "function")
      record.missingInputs.push("darwin-git-" + key);
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  const start = now();
  const bounded = () =>
    requireDarwin(
      Number.isFinite(now() - start) &&
        now() >= start &&
        now() - start <= 60000,
    );
  let channel,
    retirementAttempted = false;
  const retire = async () => {
    retirementAttempted = true;
    record.phase = "retirement";
    await save();
    const result = structuredClone(
      await effects.retire(structuredClone(input), structuredClone(record)),
    );
    const verifier = root(result?.verifier);
    requireDarwin(
      result.independent === true &&
        result.noLiveUid === true &&
        result.uid === input.request.uid &&
        result.helpersSettled === true &&
        result.requestSha256 === record.requestSha256 &&
        hash(result.receiptSha256),
    );
    if (channel)
      requireDarwin(
        sameDarwinIdentity(result.helper, channel.admission.helper) &&
          verifier.pid !== channel.admission.helper.pid,
      );
    if (record.children)
      requireDarwin(
        Array.isArray(result.children) &&
          result.children.length === record.children.length &&
          result.children.every((identity, index) =>
            sameDarwinIdentity(identity, record.children[index]),
          ),
      );
    record.retirementSha256 = result.receiptSha256;
  };
  try {
    const before =
      checkId === "git.fixed-commit"
        ? structuredClone(await effects.snapshot(structuredClone(input)))
        : null;
    const approved = structuredClone(
      await effects.review(structuredClone(input), structuredClone(before)),
    );
    if (approved.missingInputs?.length) {
      requireDarwin(
        Array.isArray(approved.missingInputs) &&
          approved.missingInputs.length <= 256 &&
          approved.missingInputs.every(
            (item) =>
              typeof item === "string" &&
              item.length > 0 &&
              item.length <= 512 &&
              !/[\u0000-\u001f\u007f]/u.test(item),
          ),
      );
      record.missingInputs = approved.missingInputs;
      await save();
      return record;
    }
    requireDarwin(
      approved.approvedSha256 === record.requestSha256 &&
        approved.reviewSha256 === input.reviewSha256 &&
        approved.disposable === true &&
        approved.providersExcluded === true &&
        approved.nativeBindingsVerified === true &&
        hash(approved.outsideSha256) &&
        (before === null ||
          (approved.snapshotSha256 === digest(JSON.stringify(before)) &&
            before.head === input.parent &&
            before.branch === "refs/heads/proof" &&
            before.status === " M content.txt\n")),
    );
    if (before !== null) {
      snapshot(before);
      workspace(before, input);
    }
    record.outsideSha256 = approved.outsideSha256;
    record.status = "RUNNING";
    record.possibleAdmission = true;
    await save();
    bounded();
    if (checkId === "git.fixed-commit") {
      channel = await effects.open(
        structuredClone(input),
        structuredClone(request),
      );
      admit(channel.admission, input);
      record.admission = structuredClone(channel.admission);
      record.phase = "fixed-release";
      await save();
      bounded();
      channel.release();
      const completion = await channel.completion;
      requireDarwin(
        completion.code === 0 &&
          completion.signal === null &&
          completion.failed === false,
      );
      const observed = structuredClone(
        await effects.observe(
          structuredClone(input),
          structuredClone(record.admission),
        ),
      );
      requireDarwin(
        assertDarwinCommitObservation(before, observed.after, observed, input)
          .pid !== channel.admission.helper.pid &&
          observed.outsideBeforeSha256 === record.outsideSha256,
      );
      record.observationSha256 = observed.receiptSha256;
      record.children = observed.children.map((child) =>
        normalizeDarwinIdentity(child.identity),
      );
    } else {
      const observed = structuredClone(
        await effects.ordinary(structuredClone(input)),
      );
      assertDarwinOrdinaryGitObservation(observed, input);
      requireDarwin(observed.outsideBeforeSha256 === record.outsideSha256);
      record.observationSha256 = observed.receiptSha256;
    }
    bounded();
    await retire();
    bounded();
    record.status = "OBSERVED";
  } catch {
    record.status = "FAIL";
    await save();
    if (record.possibleAdmission && !retirementAttempted) {
      channel?.close();
      try {
        await retire();
      } catch {
        /* Reservations remain retained. */
      }
    }
  } finally {
    channel?.dispose();
  }
  await save();
  return structuredClone(record);
}
