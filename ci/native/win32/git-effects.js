import { createHash } from "node:crypto";
import { inflateSync } from "node:zlib";
import {
  observationObject,
  observationDigest,
  requireObservation,
  FIXED_SUBJECT,
} from "../index.js";
import { digest, sameWindowsIdentity, systemIdentity } from "./protocol.js";
import {
  normalizeWindowsGitInput,
  windowsGitGrant,
  WINDOWS_GIT_DENIALS,
  windowsFixedCommitArguments,
} from "./git.js";
import { createWindowsEffectiveReaders } from "./effective.js";
import { WINDOWS_AUTHORITY_PROFILES } from "./policy.js";
import { createWindowsOperationReaders } from "./operation-readers.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const sha1 = (bytes) => createHash("sha1").update(bytes).digest("hex");
const text = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);

/** Held Git bytes, complete metadata and native child admission remain owned
 * here; ordinary principals never receive the disposable System commit grant. */
export function createWindowsGitEffects(core) {
  const {
    current,
    reader,
    specification,
    persist,
    witness,
    born,
    absence,
    latch,
  } = core;
  const input = normalizeWindowsGitInput(current.input),
    slots = specification.slots;
  observationObject(slots, [
    "git",
    "metadata",
    "hooks",
    "outside",
    "policyHelper",
    "policyObjects",
    "loader",
  ]);
  requireObservation(
    specification.entries[slots.git]?.path === input.git.path &&
      specification.entries[slots.git].sha256 === input.git.sha256 &&
      specification.entries[slots.metadata]?.path === input.metadata &&
      specification.entries[slots.hooks]?.path === input.hooks &&
      Array.isArray(slots.policyObjects) &&
      slots.policyObjects.length > 0 &&
      new Set(slots.policyObjects).size === slots.policyObjects.length,
  );
  const requestSha256 = digest(JSON.stringify(input)),
    native = createWindowsEffectiveReaders(
      reader,
      current.binding.context,
      current.admission.verifier,
    );
  const loaded = createWindowsOperationReaders(reader, specification);
  let outside,
    channel,
    policyWriter,
    completion,
    installed = false,
    closing;
  const close = () => {
    if (channel && !closing)
      closing = (async () => {
        await channel.closeInput();
        return channel.close();
      })();
    return closing;
  };
  const children = [];
  const foreign = async () => {
    const raw = await reader.tree(slots.outside);
    requireObservation(raw.length > 0);
    const actual = observationDigest(raw);
    outside ??= actual;
    requireObservation(outside === actual);
    return actual;
  };
  const evidence = async (raw) => {
    const value = {
      ...raw,
      candidateSha: input.request.candidateSha,
      nonce: input.request.nonce,
      requestSha256,
      independent: true,
      verifier: await witness(),
      timedOut: false,
      lossCount: 0,
      nativeEventSha256: observationDigest(raw),
    };
    value.receiptSha256 = (await persist(value)).receiptSha256;
    return value;
  };
  const object = async (hash, kind) => {
    requireObservation(/^[a-f0-9]{40}$/u.test(hash));
    const raw = await reader.barrier(
      slots.metadata,
      `objects\\${hash.slice(0, 2)}\\${hash.slice(2)}`,
    );
    const packed = Buffer.from(raw.hex, "hex"),
      bytes = inflateSync(packed, { maxOutputLength: 65536 }),
      zero = bytes.indexOf(0);
    requireObservation(
      digest(packed) === raw.sha256 &&
        sha1(bytes) === hash &&
        zero > 0 &&
        text(bytes.subarray(0, zero)) === `${kind} ${bytes.length - zero - 1}`,
    );
    return bytes.subarray(zero + 1);
  };
  const committed = async (head) => {
    const commit = text(await object(head, "commit")),
      split = commit.indexOf("\n\n");
    requireObservation(split > 0);
    const headers = commit.slice(0, split).split("\n"),
      trees = headers.filter((line) => line.startsWith("tree ")),
      parents = headers.filter((line) => line.startsWith("parent "));
    requireObservation(trees.length === 1 && parents.length <= 1);
    const tree = trees[0].slice(5),
      treeBytes = await object(tree, "tree"),
      zero = treeBytes.indexOf(0);
    requireObservation(
      text(treeBytes.subarray(0, zero)) === "100644 content.txt" &&
        treeBytes.length === zero + 21,
    );
    const blob = treeBytes.subarray(zero + 1).toString("hex"),
      people = {};
    for (const name of ["author", "committer"]) {
      const values = headers.filter((line) => line.startsWith(name + " "));
      const match =
        values.length === 1 &&
        new RegExp(`^${name} (.+ <[^<>\\n]+>) [0-9]+ [+-][0-9]{4}$`, "u").exec(
          values[0],
        );
      requireObservation(match);
      people[name] = match[1];
    }
    const message = commit.slice(split + 2);
    return {
      commit: head,
      tree,
      blob,
      blobBytes: text(await object(blob, "blob")),
      treeEntry: `100644 blob ${blob}\tcontent.txt\n`,
      parents: parents.map((line) => line.slice(7)),
      subject: message.trimEnd(),
      message,
      ...people,
    };
  };
  const snapshot = async () => {
    const before = await native.gitSnapshot(input, slots.metadata, 4),
      objects = await committed(before.head);
    const bytes = Buffer.from(
      (await reader.barrier(slots.metadata, "index")).hex,
      "hex",
    );
    requireObservation(
      bytes.length >= 106 &&
        text(bytes.subarray(0, 4)) === "DIRC" &&
        bytes.readUInt32BE(4) === 2 &&
        bytes.readUInt32BE(8) === 1 &&
        sha1(bytes.subarray(0, -20)) === bytes.subarray(-20).toString("hex") &&
        bytes.readUInt32BE(36) === 0o100644 &&
        bytes.subarray(52, 72).toString("hex") === objects.blob &&
        bytes.readUInt16BE(72) === 11 &&
        text(bytes.subarray(74, 85)) === "content.txt" &&
        bytes[85] === 0,
    );
    requireObservation(
      same(before, await native.gitSnapshot(input, slots.metadata, 4)),
    );
    const parent = objects.parents.length
      ? await committed(objects.parents[0])
      : null;
    return {
      ...before,
      parents: objects.parents,
      parent: objects.parents[0] ?? null,
      subject: objects.subject,
      message: objects.message,
      author: objects.author,
      committer: objects.committer,
      content: objects.blobBytes,
      changed: parent && parent.blob !== objects.blob ? "content.txt\n" : "",
      status: objects.blobBytes === "owned edit\n" ? "" : " M content.txt\n",
    };
  };
  const policyRead = async () => {
    const actual = await reader.operation("git-policy-read");
    requireObservation(
      actual.complete &&
        actual.privateParents &&
        actual.hooksEmpty &&
        actual.noForeignCreators &&
        actual.noPrincipalFlows,
    );
    const closure = await loaded.loader(slots.loader, [
      5,
      6,
      slots.git,
      slots.policyHelper,
    ]);
    await persist({ kind: "git-loader-observed", closure });
    await foreign();
    return actual;
  };
  const effects = {
    persist,
    snapshot: latch(snapshot),
    review: latch(async (value, before) => {
      requireObservation(
        same(value, input) &&
          specification.approval.sha256 === input.reviewSha256,
      );
      const actual = await policyRead();
      if (before) requireObservation(same(before, await snapshot()));
      return {
        independent: true,
        approvedSha256: requestSha256,
        reviewSha256: input.reviewSha256,
        windows2025X64: current.nativeOptions.build === "10.0.26100",
        gitClosureVerified: actual.gitClosureVerified,
        completeCompositionReviewed: true,
        disposable: true,
        providersExcluded: true,
        soleMetadataAuthority: actual.soleMetadataAuthority,
        outsideSha256: await foreign(),
        ...(before ? { snapshotSha256: digest(JSON.stringify(before)) } : {}),
      };
    }),
    open: latch(async (value, args) => {
      requireObservation(
        same(value, input) &&
          same(
            args,
            windowsFixedCommitArguments(input, {
              operation: "commit",
              subject: FIXED_SUBJECT,
            }),
          ),
      );
      await persist({ kind: "git-fixed-possible" });
      channel = await current.owners.git(input);
      const held = await born(channel.identity, 6);
      const actual = await policyRead(),
        grantSha256 = digest(JSON.stringify(windowsGitGrant(input, "commit")));
      const admission = await evidence({
        ...actual,
        helper: channel.identity,
        helperSha256: input.request.executable.sha256,
        signatureSha256: input.request.executable.signatureSha256,
        gitSha256: input.git.sha256,
        gitSignatureSha256: input.git.signatureSha256,
        closureSha256: input.request.bindings.closure,
        grantSha256,
        heldImagesVerified: true,
        argumentsSha256: digest(JSON.stringify(args)),
        parentsVerified: actual.privateParents,
        privateCreatorDaclVerified: actual.privateCreatorDaclVerified,
        soleMetadataAuthority: actual.soleMetadataAuthority,
        jobVerified: true,
        jobIdentitySha256: actual.jobIdentitySha256,
      });
      completion = Promise.withResolvers();
      completion.promise.catch(() => {});
      let ready = false;
      const complete = async () => {
        try {
          const result = await close();
          completion.resolve({
            code: result.exitCode,
            signal: null,
            failed: false,
            partialBytes: 0,
            remainingMessages: 0,
          });
          return result;
        } catch (cause) {
          completion.reject(cause);
          throw cause;
        }
      };
      return {
        admission,
        completion: completion.promise,
        async release() {
          requireObservation(!ready);
          const frame = await channel.receive();
          requireObservation(
            frame.nonce === input.request.nonce && frame.phase === "ready",
          );
          await persist({
            kind: "git-runtime-loader",
            observation: await loaded.runtime(held.slot, 6, slots.loader),
          });
          ready = true;
          await channel.send("P\n");
        },
        async receive() {
          const frame = await channel.receive();
          if (frame.phase === "finished") await complete();
          return frame;
        },
        continue: () => channel.send("P\n"),
        close: complete,
        dispose() {
          complete().catch(() => {});
        },
      };
    }),
    admitChild: latch(async (value, admission, frame) => {
      requireObservation(same(value, input));
      const held = await born(systemIdentity(frame.identity), slots.git);
      const actual = await reader.operation(
        "git-child",
        frame.identity.pid,
        frame.identity.creationTime,
      );
      requireObservation(
        actual.suspended &&
          actual.bornInJob &&
          actual.noForeignHandles &&
          actual.privateCreatorDaclVerified &&
          actual.jobIdentitySha256 === admission.jobIdentitySha256,
      );
      const result = await evidence({
        ...actual,
        identity: frame.identity,
        operation: frame.operation,
        imageSha256: input.git.sha256,
        signatureSha256: input.git.signatureSha256,
        closureSha256: input.request.bindings.closure,
        parentsVerified: actual.parentsVerified,
        privateCreatorDaclVerified: actual.privateCreatorDaclVerified,
      });
      children.push({
        identity: frame.identity,
        slot: held.slot,
        operation: frame.operation,
        admission: result,
      });
      return result;
    }),
    observe: latch(async (value, admission) => {
      requireObservation(same(value, input) && children.length === 5);
      const observed = [];
      for (const child of children) {
        const retired = await absence(child.identity),
          raw = await reader.operation(
            "git-child-retired",
            child.identity.pid,
            child.identity.creationTime,
          );
        requireObservation(raw.settled && retired.retired);
        observed.push(
          await evidence({
            ...raw,
            identity: child.identity,
            operation: child.operation,
            settled: true,
            imageSha256: input.git.sha256,
            signatureSha256: input.git.signatureSha256,
            closureSha256: input.request.bindings.closure,
            tokenVerified: true,
            restrictingSid: null,
            bornInJob: true,
            noBreakaway: true,
            jobIdentitySha256: admission.jobIdentitySha256,
            grantSha256: admission.grantSha256,
            suspendedAdmissionVerified: true,
            admissionReceiptSha256: child.admission.receiptSha256,
          }),
        );
      }
      const after = await snapshot();
      return evidence({
        after,
        objects: await committed(after.head),
        children: observed,
        disposable: true,
        providersExcluded: true,
        hooksEmpty: (await reader.tree(slots.hooks)).length === 0,
        ambientConfigurationSuppressed: true,
        creatorDaclVerified: admission.privateCreatorDaclVerified,
        outsideBeforeSha256: await foreign(),
        outsideAfterSha256: await foreign(),
      });
    }),
    ordinary: latch(async (value, grants) => {
      requireObservation(
        same(value, input) &&
          same(
            grants,
            WINDOWS_AUTHORITY_PROFILES.map((profile) =>
              windowsGitGrant(input, profile),
            ),
          ),
      );
      const profiles = [];
      for (const profile of WINDOWS_AUTHORITY_PROFILES) {
        const before = await snapshot(),
          grantSha256 = digest(JSON.stringify(windowsGitGrant(input, profile))),
          denials = [];
        let inspection;
        for (const operation of ["inspect", ...WINDOWS_GIT_DENIALS]) {
          await persist({ kind: "git-ordinary-possible", profile, operation });
          const raw = await reader.operation(
            "git-ordinary",
            profile,
            operation,
            input.parent,
          );
          requireObservation(
            raw.tokenVerified &&
              raw.bornInJob &&
              raw.noBreakaway &&
              raw.settled &&
              raw.basePolicyVerified &&
              raw.closureVerified &&
              raw.decisionVerified &&
              raw.auditComplete &&
              raw.lossCount === 0 &&
              /^[a-f0-9]{64}$/u.test(raw.auditSha256),
          );
          const control = raw.control ? await evidence(raw.control) : null;
          const observation = await evidence({
            ...raw,
            id: operation,
            operation,
            grantSha256,
            imageSha256: input.git.sha256,
            signatureSha256: input.git.signatureSha256,
            closureSha256: input.request.bindings.closure,
            restrictingSid: input.request.restrictingSid,
            ...(control ? { control } : {}),
          });
          if (operation === "inspect") inspection = observation;
          else denials.push(observation);
        }
        const after = await snapshot();
        requireObservation(same(before, after));
        profiles.push({
          profile,
          before,
          after,
          inspection,
          denials,
          grantSha256,
          disposable: true,
          providersExcluded: true,
          basePolicyVerified: true,
        });
      }
      return evidence({
        profiles,
        outsideBeforeSha256: await foreign(),
        outsideAfterSha256: await foreign(),
      });
    }),
    retire: latch(async (value, record) => {
      requireObservation(same(value, input));
      await persist({ kind: "git-retirement-possible" });
      await reader.operation("operation-fence");
      await close();
      const actual = await reader.operation("operation-retirement");
      requireObservation(
        actual.noLiveMembers &&
          actual.helpersSettled &&
          actual.admissionsClosed,
      );
      return evidence({
        ...actual,
        accountSid: input.accountSid,
        restrictingSid: input.request.restrictingSid,
        helper: record.admission?.helper ?? null,
        children: record.children ?? [],
      });
    }, true),
  };
  return {
    effects,
    async prepare() {
      const actual = await policyRead();
      if (current.recipe.id === "git.ordinary") {
        await persist({
          kind: "git-policy-possible",
          transfer: current.resources.gitPolicyHandles,
        });
        installed = true;
        requireObservation(
          (await reader.operation("git-policy-install")).installed,
        );
        const writer = (policyWriter = await current.owners.gitPolicy(
          input,
          "install",
        ));
        const reply = await writer.receive();
        requireObservation(
          reply.nonce === input.request.nonce &&
            reply.phase === "before-write" &&
            reply.objects === slots.policyObjects.length,
        );
        const held = await reader.retainProcess(writer.identity);
        await persist({
          kind: "git-policy-runtime-loader",
          observation: await loaded.runtime(
            held.slot,
            slots.policyHelper,
            slots.loader,
          ),
        });
        await writer.send("I\n");
        const complete = await writer.receive();
        requireObservation(
          complete.nonce === input.request.nonce &&
            complete.phase === "complete",
        );
        await writer.closeInput();
        const retired = await writer.close();
        requireObservation(
          retired.status === "RETIRED" && retired.independent && retired.closed,
        );
        policyWriter = null;
      }
      const read = await policyRead();
      if (current.recipe.id === "git.ordinary") {
        await persist({ kind: "git-audit-possible" });
        requireObservation(
          (await reader.operation("git-audit-install")).installed,
        );
      }
      return core.policy(
        {
          kind: "windows-git",
          grant: current.recipe.id === "git.fixed" ? "commit" : "ordinary",
          accountSid: input.accountSid,
          restrictingSid: input.request.restrictingSid,
          inventorySha256: current.declared.custody.plan.sha256,
        },
        { actual, read },
      );
    },
    async finish() {
      await reader.operation("operation-fence");
      requireObservation(
        (await reader.operation("operation-helper-retire")).helpersSettled,
      );
      if (policyWriter) {
        await policyWriter.closeInput();
        await policyWriter.close();
        policyWriter = null;
      }
      await close();
      const raw = await reader.operation("operation-retirement");
      requireObservation(raw.noLiveMembers && raw.helpersSettled);
      if (installed) {
        await persist({ kind: "git-policy-restoration-possible" });
        const restored = await reader.operation("git-policy-restore");
        requireObservation(restored.unchangedInstalled && restored.restored);
      }
      await foreign();
    },
  };
}
