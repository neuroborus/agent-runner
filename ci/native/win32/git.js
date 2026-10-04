import { performance } from "node:perf_hooks";
import {
  FIXED_SUBJECT,
  validateCommitRequest,
  validateCommitEffect,
  validateCommitMetadata,
} from "../index.js";
import {
  closed,
  dense,
  digest,
  hash,
  requireWindows,
  sid,
  windowsPrivatePath,
  normalizeWindowsLaunch,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  systemIdentity,
} from "./protocol.js";
import { WINDOWS_AUTHORITY_PROFILES } from "./policy.js";
import { normalizeWindowsFileIdentity } from "./files-protocol.js";

export const WINDOWS_GIT_DENIALS = Object.freeze([
  "git-add",
  "git-commit",
  "pointer-write",
  "pointer-delete",
  "pointer-replace",
  "metadata-write",
  "ref-write",
]);
const sha = (value) =>
  typeof value === "string" && /^[a-f0-9]{40}$/u.test(value);
const inside = (parent, child) =>
  child.toLowerCase().startsWith(parent.toLowerCase() + "\\");
const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);
export function normalizeWindowsGitInput(value) {
  closed(value, [
    "request",
    "git",
    "metadata",
    "hooks",
    "parent",
    "accountSid",
    "reviewSha256",
  ]);
  closed(value.git, ["path", "sha256", "signatureSha256"]);
  const input = {
    request: normalizeWindowsLaunch(value.request),
    git: {
      path: windowsPrivatePath(value.git.path),
      sha256: value.git.sha256,
      signatureSha256: value.git.signatureSha256,
    },
    metadata: windowsPrivatePath(value.metadata),
    hooks: windowsPrivatePath(value.hooks),
    parent: value.parent,
    accountSid: sid(value.accountSid),
    reviewSha256: value.reviewSha256,
  };
  requireWindows(
    sha(input.parent) &&
      hash(input.reviewSha256) &&
      hash(input.git.sha256) &&
      hash(input.git.signatureSha256) &&
      /\.exe$/iu.test(input.git.path) &&
      /^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$/u.test(input.accountSid) &&
      input.accountSid !== input.request.restrictingSid,
  );
  const paths = [
    input.git.path,
    input.metadata,
    input.hooks,
    input.request.executable.path,
    input.request.workspace,
  ];
  requireWindows(
    input.metadata === input.request.storage + "\\metadata" &&
      input.hooks === input.request.storage + "\\hooks",
  );
  requireWindows(
    new Set(paths.map((path) => path.toLowerCase())).size === paths.length,
  );
  for (const path of paths.slice(0, -1))
    requireWindows(
      inside(input.request.storage, path) &&
        !inside(input.request.workspace, path) &&
        !inside(path, input.request.workspace),
    );
  requireWindows(
    !inside(input.metadata, input.hooks) &&
      !inside(input.hooks, input.metadata) &&
      !inside(input.metadata, input.git.path) &&
      !inside(input.hooks, input.git.path) &&
      !inside(input.metadata, input.request.executable.path) &&
      !inside(input.hooks, input.request.executable.path),
  );
  return input;
}

/** Separate CI grant, never an ordinary profile upgrade. External native ACL,
 * MIC, token/Job and WFP owners verify the complete effective composition. */
export function windowsGitGrant(value, profile) {
  const input = normalizeWindowsGitInput(value);
  requireWindows([...WINDOWS_AUTHORITY_PROFILES, "commit"].includes(profile));
  const fixed = profile === "commit";
  return {
    schemaVersion: 1,
    profile,
    requestSha256: digest(JSON.stringify(input)),
    policySha256: input.request.bindings.policy,
    reviewSha256: input.reviewSha256,
    principalSid: fixed ? "S-1-5-18" : input.accountSid,
    restrictingSid: fixed ? null : input.request.restrictingSid,
    providersExcluded: true,
    disposable: true,
    creatorDefaultDacl: fixed ? "system-generic-all" : null,
    objects: [
      { path: input.metadata, grant: fixed ? "system" : "read-tree" },
      { path: input.request.workspace + "\\.git", grant: "read" },
      { path: input.request.workspace + "\\content.txt", grant: "read" },
      { path: input.hooks, grant: fixed ? "system" : "read-tree", empty: true },
      {
        path: input.git.path,
        grant: "execute",
        sha256: input.git.sha256,
        signatureSha256: input.git.signatureSha256,
      },
    ],
    closureSha256: input.request.bindings.closure,
  };
}
export function windowsFixedCommitArguments(value, request) {
  const input = normalizeWindowsGitInput(value);
  validateCommitRequest(request);
  return [
    input.request.nonce,
    "fixed-commit",
    input.git.path,
    input.metadata,
    input.request.workspace,
    input.hooks,
    input.parent,
    FIXED_SUBJECT,
  ];
}
export function windowsOrdinaryGitArguments(value, operation) {
  const input = normalizeWindowsGitInput(value);
  requireWindows(["inspect", "git-add", "git-commit"].includes(operation));
  return [
    input.request.nonce,
    operation,
    input.git.path,
    input.metadata,
    input.request.workspace,
    input.hooks,
    input.parent,
    FIXED_SUBJECT,
  ];
}
/** Handle-only read-grant helper. A protected reader must admit the complete
 * existing metadata inventory before install, and its owned subset on recovery. */
export function windowsGitPolicyArguments(value, mode, held) {
  const input = normalizeWindowsGitInput(value);
  requireWindows(["install", "remove"].includes(mode));
  closed(held, ["storage", "workspace", "objects"]);
  const normalize = (entry) => {
    closed(entry, ["handle", "identity"]);
    requireWindows(
      typeof entry.handle === "string" &&
        /^[1-9][0-9]{0,19}$/u.test(entry.handle) &&
        BigInt(entry.handle) < 0xffffffffffffffffn,
    );
    return {
      handle: entry.handle,
      identity: normalizeWindowsFileIdentity(entry.identity),
    };
  };
  const storage = normalize(held.storage),
    workspace = normalize(held.workspace),
    handles = new Set([storage.handle, workspace.handle]),
    identities = new Set([storage.identity, workspace.identity]),
    paths = new Set();
  requireWindows(
    handles.size === 2 &&
      identities.size === 2 &&
      workspace.identity.slice(0, 16) === storage.identity.slice(0, 16),
  );
  const objects = dense(held.objects, 256).map((entry) => {
    closed(entry, ["handle", "identity", "path", "kind"]);
    const object = normalize({
        handle: entry.handle,
        identity: entry.identity,
      }),
      path = windowsPrivatePath(entry.path);
    requireWindows(
      ["directory", "file"].includes(entry.kind) &&
        !handles.has(object.handle) &&
        !identities.has(object.identity) &&
        !paths.has(path.toLowerCase()) &&
        object.identity.slice(0, 16) === storage.identity.slice(0, 16) &&
        ([
          input.metadata,
          input.hooks,
          input.request.workspace + "\\content.txt",
        ].includes(path) ||
          inside(input.metadata, path)) &&
        (![input.metadata, input.hooks].includes(path) ||
          entry.kind === "directory") &&
        (path !== input.request.workspace + "\\content.txt" ||
          entry.kind === "file"),
    );
    handles.add(object.handle);
    identities.add(object.identity);
    paths.add(path.toLowerCase());
    return [object.handle, object.identity, entry.kind];
  });
  requireWindows(objects.length > 0);
  if (mode === "install")
    requireWindows(
      [
        input.metadata,
        input.hooks,
        input.request.workspace + "\\content.txt",
      ].every((path) => paths.has(path.toLowerCase())),
    );
  const args = [
    input.request.nonce,
    input.accountSid,
    input.request.restrictingSid,
    storage.handle,
    workspace.handle,
    storage.identity,
    workspace.identity,
    mode,
    ...objects.flat(),
  ];
  requireWindows(args.reduce((size, arg) => size + arg.length + 3, 0) < 32767);
  return args;
}
function native(value, input) {
  const verifier = systemIdentity(value?.verifier);
  requireWindows(
    value.independent === true &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      value.candidateSha === input.request.candidateSha &&
      value.nonce === input.request.nonce &&
      value.timedOut === false &&
      value.lossCount === 0 &&
      hash(value.nativeEventSha256) &&
      hash(value.receiptSha256),
  );
  return verifier;
}
function snapshot(value, input) {
  requireWindows(
    value.branch === "refs/heads/proof" &&
      sha(value.head) &&
      typeof value.config === "string" &&
      value.config.length <= 65536 &&
      typeof value.identity === "string" &&
      value.identity.length > 0 &&
      value.identity.length <= 512 &&
      hash(value.pointerIdentitySha256) &&
      value.pointerSha256 ===
        digest(`gitdir: ${input.metadata.replaceAll("\\", "/")}\n`) &&
      hash(value.parentIdentitiesSha256),
  );
  const refs = dense(value.refs, 256),
    metadata = dense(value.metadata, 4096);
  requireWindows(
    refs.length > 0 &&
      new Set(refs.map(([name]) => name.toLowerCase())).size === refs.length &&
      refs.some(([name, head]) => name === value.branch && head === value.head),
  );
  for (const entry of refs)
    requireWindows(
      dense(entry, 2).length === 2 &&
        /^refs\/[A-Za-z0-9_./-]{1,240}$/u.test(entry[0]) &&
        sha(entry[1]),
    );
  requireWindows(
    metadata.length > 0 &&
      new Set(metadata.map(([name]) => name.toLowerCase())).size ===
        metadata.length,
  );
  for (const entry of metadata)
    requireWindows(
      dense(entry, 3).length === 3 &&
        typeof entry[0] === "string" &&
        entry[0].length <= 512 &&
        entry[0]
          .split("/")
          .every(
            (part) =>
              /^[A-Za-z0-9_.-]+$/u.test(part) &&
              ![".", ".."].includes(part) &&
              !/[. ]$/u.test(part) &&
              !/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu.test(part),
          ) &&
        hash(entry[1]) &&
        hash(entry[2]),
    );
  requireWindows(
    hash(value.workspaceSha256) &&
      value.contentSha256 === digest("owned edit\n") &&
      hash(value.contentIdentitySha256),
  );
}
function unchanged(before, after) {
  for (const key of [
    "config",
    "identity",
    "pointerIdentitySha256",
    "pointerSha256",
    "parentIdentitiesSha256",
    "workspaceSha256",
    "contentSha256",
    "contentIdentitySha256",
  ])
    requireWindows(before[key] === after[key]);
}
function child(value, input, verifier, principalSid) {
  const reader = native(value, input);
  const identity = normalizeWindowsIdentity(value.identity);
  requireWindows(
    value.independent === true &&
      value.settled === true &&
      identity.sessionId === 0 &&
      identity.userSid === principalSid &&
      identity.pid !== verifier.pid &&
      identity.pid !== reader.pid &&
      value.imageSha256 === input.git.sha256 &&
      value.signatureSha256 === input.git.signatureSha256 &&
      value.closureSha256 === input.request.bindings.closure &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      value.tokenVerified === true &&
      value.restrictingSid ===
        (principalSid === "S-1-5-18" ? null : input.request.restrictingSid) &&
      value.bornInJob === true &&
      value.noBreakaway === true &&
      hash(value.jobIdentitySha256) &&
      hash(value.nativeEventSha256),
  );
  return identity;
}
export function assertWindowsCommitObservation(before, after, evidence, value) {
  const input = normalizeWindowsGitInput(value),
    verifier = native(evidence, input);
  snapshot(before, input);
  snapshot(after, input);
  unchanged(before, after);
  requireWindows(
    before.head === input.parent &&
      before.status === " M content.txt\n" &&
      evidence.disposable === true &&
      evidence.providersExcluded === true &&
      evidence.hooksEmpty === true &&
      evidence.ambientConfigurationSuppressed === true &&
      evidence.creatorDaclVerified === true &&
      hash(evidence.outsideBeforeSha256) &&
      evidence.outsideAfterSha256 === evidence.outsideBeforeSha256 &&
      evidence.objects.commit === after.head &&
      sha(evidence.objects.tree) &&
      sha(evidence.objects.blob) &&
      equal(after.parents, [before.head]) &&
      evidence.objects.blobBytes === "owned edit\n" &&
      evidence.objects.treeEntry ===
        `100644 blob ${evidence.objects.blob}\tcontent.txt\n`,
  );
  validateCommitEffect(before, after);
  validateCommitMetadata(before.metadata, after.metadata, [
    after.head,
    evidence.objects.tree,
    evidence.objects.blob,
  ]);
  const children = dense(evidence.children, 5),
    identities = new Set();
  requireWindows(children.length === 5);
  children.forEach((entry, index) => {
    const identity = child(entry, input, verifier, "S-1-5-18"),
      key = JSON.stringify(identity);
    requireWindows(
      entry.operation ===
        ["parent", "branch", "status", "add", "commit"][index] &&
        !identities.has(key) &&
        entry.suspendedAdmissionVerified === true &&
        entry.grantSha256 ===
          digest(JSON.stringify(windowsGitGrant(input, "commit"))),
    );
    identities.add(key);
  });
  return verifier;
}
export function assertWindowsOrdinaryGitObservation(value, input) {
  input = normalizeWindowsGitInput(input);
  const verifier = native(value, input),
    profiles = dense(value.profiles, 3),
    seen = new Set(),
    identities = new Set();
  requireWindows(
    profiles.length === 3 &&
      hash(value.outsideBeforeSha256) &&
      value.outsideAfterSha256 === value.outsideBeforeSha256,
  );
  for (const profile of profiles) {
    requireWindows(
      WINDOWS_AUTHORITY_PROFILES.includes(profile.profile) &&
        !seen.has(profile.profile),
    );
    seen.add(profile.profile);
    snapshot(profile.before, input);
    snapshot(profile.after, input);
    unchanged(profile.before, profile.after);
    requireWindows(
      profile.before.head === input.parent &&
        profile.before.head === profile.after.head &&
        equal(profile.before.refs, profile.after.refs) &&
        equal(profile.before.metadata, profile.after.metadata) &&
        profile.disposable === true &&
        profile.providersExcluded === true &&
        profile.basePolicyVerified === true &&
        profile.grantSha256 ===
          digest(JSON.stringify(windowsGitGrant(input, profile.profile))) &&
        profile.before.status === " M content.txt\n" &&
        profile.after.status === profile.before.status &&
        profile.inspection.operation === "inspect" &&
        profile.inspection.code === 0 &&
        profile.inspection.grantSha256 === profile.grantSha256 &&
        profile.inspection.head === input.parent,
    );
    const inspection = child(
      profile.inspection,
      input,
      verifier,
      input.accountSid,
    );
    requireWindows(!identities.has(JSON.stringify(inspection)));
    identities.add(JSON.stringify(inspection));
    const denials = dense(profile.denials, WINDOWS_GIT_DENIALS.length),
      attempts = new Set();
    requireWindows(denials.length === WINDOWS_GIT_DENIALS.length);
    for (const denied of denials) {
      const git = denied.id.startsWith("git-");
      requireWindows(
        WINDOWS_GIT_DENIALS.includes(denied.id) &&
          !attempts.has(denied.id) &&
          denied.attempted === true &&
          denied.allowed === false &&
          denied.timedOut === false &&
          denied.signal === null &&
          Number.isSafeInteger(denied.exitCode) &&
          (git ? [1, 128].includes(denied.exitCode) : denied.exitCode === 0) &&
          denied.nativeCode === 5 &&
          denied.nativeDecision === "deny-metadata-write" &&
          denied.restrictingSid === input.request.restrictingSid &&
          hash(denied.beforeSha256) &&
          denied.afterSha256 === denied.beforeSha256,
      );
      const actor = git
          ? child(denied, input, verifier, input.accountSid)
          : normalizeWindowsIdentity(denied.identity),
        key = JSON.stringify(actor);
      requireWindows(native(denied, input).pid !== actor.pid);
      requireWindows(
        actor.userSid === input.accountSid &&
          actor.sessionId === 0 &&
          actor.pid !== verifier.pid &&
          denied.operation === denied.id &&
          denied.tokenVerified === true &&
          denied.bornInJob === true &&
          denied.noBreakaway === true &&
          denied.settled === true &&
          hash(denied.jobIdentitySha256) &&
          denied.grantSha256 === profile.grantSha256 &&
          denied.closureSha256 === input.request.bindings.closure &&
          !identities.has(key),
      );
      identities.add(key);
      const control = denied.control;
      const controller = systemIdentity(control.identity);
      requireWindows(
        native(control, input).pid !== actor.pid &&
          control.ready === true &&
          control.reachable === true &&
          control.readyBeforeAttempt === true &&
          controller.pid !== actor.pid &&
          control.settled === true &&
          control.operation === denied.id &&
          control.nativeCode === 0 &&
          control.targetIdentitySha256 === denied.targetIdentitySha256 &&
          hash(control.targetIdentitySha256),
      );
      attempts.add(denied.id);
    }
  }
  return true;
}

/** Only protected external bridges launch/admit images or configure grants.
 * A separate immutable review precedes all effects, including the fixed helper. */
export async function runWindowsGitCase(
  checkId,
  value,
  effects,
  {
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  const input = normalizeWindowsGitInput(value),
    fixed = checkId === "git.fixed-commit";
  requireWindows(
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
    phase: "review",
    reservation: "RETAINED",
    missingInputs: [],
  };
  for (const key of [
    "review",
    "retire",
    ...(fixed ? ["snapshot", "open", "observe", "admitChild"] : ["ordinary"]),
  ])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("windows-git-" + key);
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  let channel,
    expired = false,
    rejectDeadline;
  const started = now(),
    deadline = new Promise((_, reject) => {
      rejectDeadline = reject;
    });
  deadline.catch(() => {});
  const timer = schedule(() => {
    expired = true;
    try {
      channel?.close();
    } catch {
      /* Independent retirement still follows. */
    }
    rejectDeadline(new Error("Windows Git deadline"));
  }, 60000);
  const active = () => {
    const elapsed = now() - started;
    requireWindows(
      !expired && Number.isFinite(elapsed) && elapsed >= 0 && elapsed < 60000,
    );
  };
  const wait = async (action) => {
    active();
    const result = await Promise.race([action(), deadline]);
    active();
    return result;
  };
  try {
    const review = structuredClone(
      await wait(() => effects.review(structuredClone(input), null)),
    );
    if (review.missingInputs?.length) {
      record.missingInputs = dense(review.missingInputs, 256);
      requireWindows(
        record.missingInputs.every(
          (item) =>
            typeof item === "string" && /^[a-z][a-z0-9-]{0,127}$/u.test(item),
        ),
      );
      await wait(save);
      return record;
    }
    requireWindows(
      review.independent === true &&
        review.approvedSha256 === record.requestSha256 &&
        review.reviewSha256 === input.reviewSha256 &&
        review.windows2025X64 === true &&
        review.gitClosureVerified === true &&
        review.completeCompositionReviewed === true &&
        review.disposable === true &&
        review.providersExcluded === true &&
        review.soleMetadataAuthority === true &&
        hash(review.outsideSha256),
    );
    if (fixed) {
      record.phase = "snapshot-intent";
      await wait(save);
    }
    const before = fixed
      ? structuredClone(
          await wait(() => effects.snapshot(structuredClone(input))),
        )
      : null;
    if (fixed) {
      snapshot(before, input);
      requireWindows(
        before.head === input.parent && before.status === " M content.txt\n",
      );
      const bound = structuredClone(
        await wait(() =>
          effects.review(structuredClone(input), structuredClone(before)),
        ),
      );
      requireWindows(
        bound.independent === true &&
          bound.approvedSha256 === record.requestSha256 &&
          bound.reviewSha256 === input.reviewSha256 &&
          bound.snapshotSha256 === digest(JSON.stringify(before)) &&
          bound.outsideSha256 === review.outsideSha256,
      );
      record.snapshotSha256 = bound.snapshotSha256;
    }
    record.outsideSha256 = review.outsideSha256;
    record.status = "RUNNING";
    record.phase = "possible-admission";
    await wait(save);
    if (fixed) {
      channel = await wait(() =>
        Promise.resolve(
          effects.open(
            structuredClone(input),
            windowsFixedCommitArguments(input, {
              operation: "commit",
              subject: FIXED_SUBJECT,
            }),
          ),
        ).then((value) => {
          channel = value;
          if (expired) value.close();
          return value;
        }),
      );
      const admission = structuredClone(channel.admission),
        helper = systemIdentity(admission.helper),
        verifier = native(admission, input);
      requireWindows(
        verifier.pid !== helper.pid &&
          admission.helperSha256 === input.request.executable.sha256 &&
          admission.signatureSha256 ===
            input.request.executable.signatureSha256 &&
          admission.gitSha256 === input.git.sha256 &&
          admission.gitSignatureSha256 === input.git.signatureSha256 &&
          admission.closureSha256 === input.request.bindings.closure &&
          admission.grantSha256 ===
            digest(JSON.stringify(windowsGitGrant(input, "commit"))) &&
          admission.heldImagesVerified === true &&
          admission.argumentsSha256 ===
            digest(
              JSON.stringify(
                windowsFixedCommitArguments(input, {
                  operation: "commit",
                  subject: FIXED_SUBJECT,
                }),
              ),
            ) &&
          admission.parentsVerified === true &&
          admission.privateCreatorDaclVerified === true &&
          admission.hooksEmpty === true &&
          admission.soleMetadataAuthority === true &&
          admission.jobVerified === true &&
          hash(admission.jobIdentitySha256),
      );
      record.admission = admission;
      record.phase = "release-intent";
      await wait(save);
      await wait(() => channel.release());
      record.children = [];
      record.childReceipts = [];
      for (const operation of ["parent", "branch", "status", "add", "commit"]) {
        const frame = structuredClone(await wait(() => channel.receive()));
        closed(frame, ["nonce", "phase", "operation", "suspended", "identity"]);
        requireWindows(
          frame.nonce === input.request.nonce &&
            frame.phase === "child" &&
            frame.operation === operation &&
            frame.suspended === true,
        );
        const identity = systemIdentity(frame.identity);
        const admitted = structuredClone(
          await wait(() =>
            effects.admitChild(
              structuredClone(input),
              structuredClone(admission),
              structuredClone(frame),
            ),
          ),
        );
        requireWindows(
          native(admitted, input).pid !== identity.pid &&
            sameWindowsIdentity(admitted.identity, identity) &&
            admitted.imageSha256 === input.git.sha256 &&
            admitted.signatureSha256 === input.git.signatureSha256 &&
            admitted.closureSha256 === input.request.bindings.closure &&
            admitted.bornInJob === true &&
            admitted.jobIdentitySha256 === admission.jobIdentitySha256 &&
            admitted.parentsVerified === true &&
            admitted.privateCreatorDaclVerified === true &&
            admitted.noForeignHandles === true &&
            admitted.suspended === true,
        );
        record.childReceipts.push(admitted.receiptSha256);
        record.children.push(identity);
        record.phase = "child-release-intent";
        record.childReceiptSha256 = admitted.receiptSha256;
        await wait(save);
        await wait(() => channel.continue());
      }
      const finished = structuredClone(await wait(() => channel.receive()));
      closed(finished, ["nonce", "phase"]);
      requireWindows(
        finished.nonce === input.request.nonce && finished.phase === "finished",
      );
      const completion = await wait(() => channel.completion);
      requireWindows(
        completion.code === 0 &&
          completion.signal === null &&
          completion.failed === false &&
          completion.partialBytes === 0 &&
          completion.remainingMessages === 0,
      );
      const observed = structuredClone(
        await wait(() =>
          effects.observe(structuredClone(input), structuredClone(admission)),
        ),
      );
      requireWindows(
        assertWindowsCommitObservation(before, observed.after, observed, input)
          .pid !== helper.pid &&
          observed.outsideBeforeSha256 === record.outsideSha256 &&
          observed.children.every((child, index) =>
            sameWindowsIdentity(child.identity, record.children[index]),
          ),
      );
      requireWindows(
        observed.children.every(
          (child, index) =>
            child.admissionReceiptSha256 === record.childReceipts[index] &&
            child.jobIdentitySha256 === admission.jobIdentitySha256,
        ),
      );
      record.observationSha256 = observed.receiptSha256;
    } else {
      const observed = structuredClone(
        await wait(() =>
          effects.ordinary(
            structuredClone(input),
            WINDOWS_AUTHORITY_PROFILES.map((profile) =>
              windowsGitGrant(input, profile),
            ),
          ),
        ),
      );
      assertWindowsOrdinaryGitObservation(observed, input);
      requireWindows(observed.outsideBeforeSha256 === record.outsideSha256);
      record.observationSha256 = observed.receiptSha256;
      record.children = observed.profiles.flatMap((profile) => [
        profile.inspection.identity,
        ...profile.denials.map((entry) => entry.identity),
      ]);
    }
    record.status = "OBSERVED";
  } catch {
    record.status = "FAIL";
  } finally {
    cancel(timer);
  }
  if (record.phase !== "review") {
    record.phase = "retirement-intent";
    let rejectSettlement;
    const settlementDeadline = new Promise((_, reject) => {
      rejectSettlement = reject;
    });
    settlementDeadline.catch(() => {});
    const settlementTimer = schedule(
      () => rejectSettlement(new Error("Windows Git settlement deadline")),
      30000,
    );
    try {
      try {
        await Promise.race([save(), settlementDeadline]);
      } catch {
        record.status = "FAIL";
      }
      try {
        channel?.close();
      } catch {
        record.status = "FAIL";
      }
      const settled = structuredClone(
        await Promise.race([
          effects.retire(structuredClone(input), structuredClone(record)),
          settlementDeadline,
        ]),
      );
      const verifier = native(settled, input);
      requireWindows(
        settled.noLiveMembers === true &&
          settled.admissionsClosed === true &&
          settled.helpersSettled === true &&
          settled.accountSid === input.accountSid &&
          settled.restrictingSid === input.request.restrictingSid &&
          (!record.admission ||
            (sameWindowsIdentity(settled.helper, record.admission.helper) &&
              verifier.pid !== record.admission.helper.pid)) &&
          (!record.children ||
            record.children.every((identity) =>
              dense(settled.children, 64).some((retired) =>
                sameWindowsIdentity(identity, retired),
              ),
            )),
      );
      record.retirementSha256 = settled.receiptSha256;
    } catch {
      record.status = "FAIL";
    } finally {
      cancel(settlementTimer);
      try {
        channel?.dispose();
      } catch {
        record.status = "FAIL";
      }
    }
  }
  record.phase = "retained";
  await save();
  return structuredClone(record);
}
