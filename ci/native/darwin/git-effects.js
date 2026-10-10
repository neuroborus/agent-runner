import { createHash } from "node:crypto";
import { inflateSync } from "node:zlib";
import {
  observationObject,
  observationDigest,
  requireObservation,
  nativePolicyLaunchData,
  FIXED_SUBJECT,
} from "../index.js";
import {
  digest,
  DARWIN_LITERAL_ARGUMENTS,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import { normalizeDarwinGitInput } from "./git.js";
import { createDarwinEffectiveReaders } from "./effective.js";
import { createDarwinAuditDecoder } from "./audit.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const sha1 = (bytes) => createHash("sha1").update(bytes).digest("hex");
const text = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
const root = (identity) => {
  identity = normalizeDarwinIdentity(identity);
  requireObservation(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
};

/** Native suspended exec, audit returns and held loose-object reads are joined
 * by this private owner. The fixed subjects and proof validators stay unchanged. */
export function createDarwinGitEffects(core) {
  const {
    current,
    reader,
    specification,
    witness,
    persist,
    born,
    retire,
    latch,
  } = core;
  const input = normalizeDarwinGitInput(current.input),
    slots = specification.slots;
  observationObject(slots, [
    "git",
    "metadata",
    "hooks",
    "outside",
    "control",
    "profiles",
    "audit",
  ]);
  requireObservation(
    specification.entries[slots.git]?.path === input.git.path &&
      specification.entries[slots.git].sha256 === input.git.sha256 &&
      specification.entries[slots.metadata]?.path === input.metadata &&
      specification.entries[slots.hooks]?.path === input.hooks,
  );
  const requestSha256 = digest(JSON.stringify(input));
  const native = createDarwinEffectiveReaders(
    reader,
    current.binding.context,
    current.admission.helper,
  );
  let outside = core.recovered?.history.find(
      ({ record }) => record.kind === "git-outside",
    )?.record.sha256,
    channel,
    active = false,
    observer,
    decoder,
    auditSequence = 0;
  const children = [];
  const outsideRead = async () => {
    const files = await reader.tree(slots.outside);
    requireObservation(files.length > 0);
    const result = observationDigest(files);
    outside ??= result;
    requireObservation(outside === result);
    return result;
  };
  const evidence = async (value) => {
    const result = {
      ...value,
      independent: true,
      verifier: await witness(),
      requestSha256,
      nativeEventSha256: observationDigest(value),
    };
    result.receiptSha256 = (await persist(result)).receiptSha256;
    return result;
  };
  const object = async (index, name, kind) => {
    const raw = await reader.operation("git-object", index, name);
    observationObject(raw, ["object", "sha256", "hex"]);
    requireObservation(digest(Buffer.from(raw.hex, "hex")) === raw.sha256);
    const bytes = inflateSync(Buffer.from(raw.hex, "hex"), {
      maxOutputLength: 65536,
    });
    requireObservation(sha1(bytes) === name);
    const zero = bytes.indexOf(0),
      header = text(bytes.subarray(0, zero)),
      body = bytes.subarray(zero + 1);
    requireObservation(zero > 0 && header === kind + " " + body.length);
    return body;
  };
  const committed = async (index, head) => {
    const commit = text(await object(index, head, "commit"));
    const headers = commit.slice(0, commit.indexOf("\n\n")).split("\n"),
      trees = headers.filter((line) => line.startsWith("tree ")),
      parents = headers.filter((line) => line.startsWith("parent "));
    requireObservation(
      trees.length === 1 &&
        parents.length <= 1 &&
        /^[a-f0-9]{40}$/u.test(trees[0].slice(5)) &&
        parents.every((parent) => /^[a-f0-9]{40}$/u.test(parent.slice(7))),
    );
    const tree = trees[0].slice(5),
      bytes = await object(index, tree, "tree"),
      zero = bytes.indexOf(0);
    requireObservation(
      text(bytes.subarray(0, zero)) === "100644 content.txt" &&
        bytes.length === zero + 21,
    );
    const blob = bytes.subarray(zero + 1).toString("hex"),
      blobBytes = text(await object(index, blob, "blob"));
    const people = {};
    for (const key of ["author", "committer"]) {
      const values = headers.filter((line) => line.startsWith(key + " "));
      const match =
        values.length === 1 &&
        new RegExp(
          "^" + key + " (.+ <[^<>\\n]+>) [0-9]+ [+-][0-9]{4}$",
          "u",
        ).exec(values[0]);
      requireObservation(match);
      people[key] = match[1];
    }
    const message = commit.slice(commit.indexOf("\n\n") + 2);
    return {
      commit: head,
      tree,
      blob,
      blobBytes,
      treeEntry: "100644 blob " + blob + "\tcontent.txt\n",
      parents: parents.map((line) => line.slice(7)),
      subject: message.trimEnd(),
      message,
      ...people,
    };
  };
  const snapshot = async (
    value = input,
    metadata = slots.metadata,
    work = 3,
  ) => {
    const result = await native.gitSnapshot(value, metadata, work),
      objects = await committed(metadata, result.head);
    const index = Buffer.from(
      (await reader.barrier(metadata, "index")).hex,
      "hex",
    );
    requireObservation(
      index.length >= 84 &&
        text(index.subarray(0, 4)) === "DIRC" &&
        index.readUInt32BE(4) === 2 &&
        index.readUInt32BE(8) === 1 &&
        sha1(index.subarray(0, -20)) === index.subarray(-20).toString("hex") &&
        index.readUInt32BE(36) === 0o100644 &&
        index.subarray(52, 72).toString("hex") === objects.blob &&
        index.readUInt16BE(72) === 11 &&
        text(index.subarray(74, 85)) === "content.txt" &&
        index[85] === 0,
    );
    const content = Buffer.from(
        (await reader.barrier(work, "content.txt")).hex,
        "hex",
      ),
      pointer = await reader.barrier(work, ".git");
    requireObservation(
      content.equals(Buffer.from("owned edit\n")) &&
        text(Buffer.from(pointer.hex, "hex")) === `gitdir: ${value.metadata}\n`,
    );
    const prior = objects.parents.length
      ? await committed(metadata, objects.parents[0])
      : null;
    return {
      ...result,
      parents: objects.parents,
      parent: objects.parents[0] ?? null,
      subject: objects.subject,
      message: objects.message,
      author: objects.author,
      committer: objects.committer,
      content: objects.blobBytes,
      changed: prior && prior.blob !== objects.blob ? "content.txt\n" : "",
      status: objects.blobBytes === text(content) ? "" : " M content.txt\n",
      pointerSha256: pointer.sha256,
    };
  };
  const rootRun = async (value, indices, release) => {
    await persist({ kind: "git-possible", input: value, indices });
    active = true;
    const helper = root(
      await reader.operation(
        "git-start",
        slots.git,
        indices.metadata,
        indices.workspace,
        indices.hooks,
        indices.helper,
        value.parent,
        indices.cdhash,
      ),
    );
    await born(helper, {
      sha256: specification.entries[indices.helper].sha256,
      cdhash: indices.cdhash,
    });
    await reader.rootDomain(helper);
    const admission = await evidence({
      helper,
      helperSha256: specification.entries[indices.helper].sha256,
      cdhash: indices.cdhash,
      gitSha256: input.git.sha256,
      gitCdhash: input.git.cdhash,
      closureSha256: input.request.bindings.closure,
      directoriesVerified: true,
      soleMetadataAuthority: true,
      noLiveUid: true,
      providersExcluded: true,
    });
    const run = async () => {
      requireObservation((await reader.operation("git-send", "P")) === null);
      const observed = [];
      for (const operation of ["parent", "branch", "status", "add", "commit"]) {
        const event = await reader.operation("git-event");
        observationObject(event, ["worker"]);
        const identity = root(event.worker);
        await born(identity, {
          sha256: input.git.sha256,
          cdhash: input.git.cdhash,
        });
        requireObservation(identity.asid === helper.asid);
        requireObservation((await reader.operation("git-send", "R")) === null);
        const outcome = await reader.operation("git-event");
        observationObject(outcome, ["reaped", "exitCode", "stdoutHex"]);
        requireObservation(
          outcome.reaped === identity.pid &&
            outcome.exitCode === 0 &&
            /^(?:[a-f0-9]{2})*$/u.test(outcome.stdoutHex),
        );
        const absence = await reader.retired(identity);
        observed.push({
          operation,
          identity,
          imageSha256: input.git.sha256,
          cdhash: input.git.cdhash,
          independent: true,
          settled: true,
          requestSha256,
          nativeEventSha256: observationDigest({ event, outcome, absence }),
        });
        requireObservation((await reader.operation("git-send", "S")) === null);
      }
      const end = await reader.operation("git-event");
      requireObservation(
        end.nonce === input.request.nonce &&
          end.phase === "finished" &&
          end.pid === helper.pid,
      );
      const outcome = await reader.operation("git-close");
      active = false;
      requireObservation(
        outcome.code === 0 && outcome.signal === null && outcome.drained,
      );
      await reader.retiredRootDomain(helper);
      children.push(...observed);
      return { code: 0, signal: null, failed: false, children: observed };
    };
    return release ? { admission, run } : { admission, result: await run() };
  };
  const capture = async (command) => {
    const frame = await reader.access("audit", command);
    observationObject(frame, ["hex"]);
    await decoder.push(Buffer.from(frame.hex, "hex"));
  };
  const ordinaryAttempt = async (profile, operation) => {
    await persist({ kind: "ordinary-possible", profile, operation });
    active = true;
    await reader.operation(
      "git-ordinary-start",
      slots.git,
      slots.metadata,
      slots.hooks,
      profile.policy,
      operation,
      input.request.executable.cdhash,
    );
    const hello = await reader.operation("git-event");
    observationObject(hello, ["helper", "payload"]);
    requireObservation(hello.payload === null);
    await born(hello.helper, input.request.launcher);
    await reader.operation("git-ordinary-release", 0, "P");
    const parked = await reader.operation("git-event");
    observationObject(parked, ["helper", "payload"]);
    requireObservation(sameDarwinIdentity(parked.helper, hello.helper));
    const payload = normalizeDarwinIdentity(parked.payload);
    core.subjects.push(payload);
    await persist({ kind: "ordinary-admitted", payload });
    await reader.holdOwnershipSession(payload.asid);
    await reader.operation("git-ordinary-release", 0, "R");
    const ready = await reader.operation("git-event", 1);
    requireObservation(
      ready.nonce === input.request.nonce &&
        ready.parked === true &&
        ready.pid === payload.pid,
    );
    const fixture = await reader.operationSubject(payload);
    requireObservation(
      fixture.subject.sha256 === input.request.executable.sha256 &&
        fixture.subject.signature.cdhash === input.request.executable.cdhash,
    );
    await reader.operation("git-ordinary-release", 1, "P");
    const worker = await reader.operation("git-event", 1);
    observationObject(worker, ["worker"]);
    const identity = normalizeDarwinIdentity(worker.worker);
    core.subjects.push(identity);
    await persist({ kind: "ordinary-worker", identity });
    requireObservation(
      identity.asid === payload.asid && identity.auid === input.request.uid,
    );
    const actual = await reader.operationSubject(identity);
    requireObservation(
      actual.subject.sha256 === input.git.sha256 &&
        actual.subject.signature.cdhash === input.git.cdhash,
    );
    const authority = await reader.authority(identity, slots.metadata);
    requireObservation(
      authority.sandboxed &&
        authority.decisions[0] === 0 &&
        authority.decisions[1] !== 0,
    );
    await capture("B");
    const start = ++auditSequence;
    await reader.resumeOwnership(identity);
    await reader.operation("git-ordinary-release", 1, "R");
    const outcome = await reader.operation("git-event", 1);
    observationObject(outcome, ["exitCode", "stdoutHex"]);
    await reader.retired(identity, { reserved: true });
    await capture("B");
    const events = decoder.window(start, ++auditSequence);
    await reader.operation("git-ordinary-release", 1, "S");
    const exit = await reader.operation("git-event");
    requireObservation(exit.exitCode === 0 && exit.signal === null);
    await reader.retired(payload, { reserved: true });
    const empty = await reader.verifyOwnership(payload.asid);
    requireObservation(
      empty.enumeration.live.length === 0 &&
        empty.enumeration.zombies.length === 0,
    );
    requireObservation(
      (await reader.operation("git-ordinary-finish")).reaped === true,
    );
    active = false;
    await reader.retired(hello.helper);
    const proof = {
      identity,
      exitCode: outcome.exitCode,
      signal: null,
      imageSha256: actual.subject.sha256,
      cdhash: actual.subject.signature.cdhash,
      nativeEventSha256: observationDigest({
        outcome,
        actual,
        authority,
        events,
        empty,
      }),
    };
    if (operation === "inspect") {
      requireObservation(
        outcome.exitCode === 0 &&
          text(Buffer.from(outcome.stdoutHex, "hex")) === input.parent + "\n",
      );
      return {
        code: 0,
        head: input.parent,
        nativeEventSha256: proof.nativeEventSha256,
      };
    }
    const denial = events.filter(
      (event) =>
        event.pid === identity.pid &&
        event.auid === identity.auid &&
        event.asid === identity.asid &&
        event.uid === identity.uid &&
        event.gid === identity.gid &&
        event.target.startsWith(input.metadata + "/") &&
        [1, 13, 30].includes(event.error),
    );
    requireObservation(
      outcome.exitCode > 0 &&
        denial.length > 0 &&
        new Set(denial.map((event) => event.error)).size === 1,
    );
    return {
      ...proof,
      id: operation,
      attempted: true,
      timedOut: false,
      nativeCode: { 1: "EPERM", 13: "EACCES", 30: "EROFS" }[denial[0].error],
      nativeDecision: "deny-metadata-write",
    };
  };
  const effects = {
    persist,
    snapshot: latch(snapshot),
    review: latch(async (value, before) => {
      requireObservation(
        same(value, input) &&
          specification.approval.sha256 === input.reviewSha256,
      );
      await outsideRead();
      return {
        approvedSha256: requestSha256,
        reviewSha256: input.reviewSha256,
        disposable: true,
        providersExcluded: true,
        nativeBindingsVerified: true,
        outsideSha256: outside,
        ...(before ? { snapshotSha256: digest(JSON.stringify(before)) } : {}),
      };
    }),
    open: latch(async (value, grant) => {
      requireObservation(
        same(value, input) &&
          grant.operation === "commit" &&
          grant.subject === FIXED_SUBJECT,
      );
      const prepared = await rootRun(
        input,
        {
          metadata: slots.metadata,
          workspace: 3,
          hooks: slots.hooks,
          helper: 5,
          cdhash: input.request.executable.cdhash,
        },
        true,
      );
      let resolve,
        reject,
        released = false;
      const completion = new Promise((yes, no) => {
        resolve = yes;
        reject = no;
      });
      completion.catch(() => {});
      channel = {
        admission: prepared.admission,
        completion,
        release() {
          requireObservation(!released);
          released = true;
          prepared.run().then(resolve, reject);
        },
        close() {
          if (!released) {
            released = true;
            reader.operation("git-close").then(resolve, reject);
          }
        },
        dispose() {},
      };
      return channel;
    }),
    observe: latch(async (value) => {
      requireObservation(same(value, input));
      const after = await snapshot(),
        objects = await committed(slots.metadata, after.head);
      requireObservation(
        objects.subject === FIXED_SUBJECT &&
          objects.blobBytes === "owned edit\n",
      );
      return evidence({
        after,
        objects,
        children: children.slice(-5),
        candidateSha: input.request.candidateSha,
        disposable: true,
        outsideUnchanged: true,
        outsideBeforeSha256: await outsideRead(),
        outsideAfterSha256: await outsideRead(),
        directoriesUnchanged: true,
        hooksEmpty: (await reader.tree(slots.hooks)).length === 0,
        ambientConfigurationSuppressed: true,
        providersExcluded: true,
      });
    }),
    ordinary: latch(async (value) => {
      requireObservation(same(value, input));
      observationObject(slots.control, [
        "metadata",
        "workspace",
        "hooks",
        "helper",
        "cdhash",
      ]);
      const controlInput = {
        ...input,
        metadata: specification.entries[slots.control.metadata].path,
        hooks: specification.entries[slots.control.hooks].path,
      };
      const controlBefore = await snapshot(
        controlInput,
        slots.control.metadata,
        slots.control.workspace,
      );
      const control = await rootRun(controlInput, slots.control, false);
      const controlAfter = await snapshot(
        controlInput,
        slots.control.metadata,
        slots.control.workspace,
      );
      const objects = await committed(
        slots.control.metadata,
        controlAfter.head,
      );
      requireObservation(
        controlBefore.head === input.parent &&
          controlBefore.status === " M content.txt\n" &&
          objects.parents[0] === input.parent &&
          objects.subject === FIXED_SUBJECT &&
          objects.blobBytes === "owned edit\n" &&
          control.result.code === 0,
      );
      const positive = await evidence({
        controlBefore,
        controlAfter,
        children: control.result.children,
      });
      observationObject(slots.audit, ["helper", "classes", "mapping"]);
      const started = await reader.access(
        "audit-start",
        slots.audit.helper.index,
        slots.audit.helper.cdhash,
        slots.audit.classes,
      );
      observer = root(started.identity);
      await born(observer, {
        sha256: specification.entries[slots.audit.helper.index].sha256,
        cdhash: slots.audit.helper.cdhash,
      });
      decoder = createDarwinAuditDecoder(reader, slots.audit.mapping);
      await capture("A");
      const profiles = [];
      for (const profile of slots.profiles) {
        const before = await snapshot();
        const inspection = await ordinaryAttempt(profile, "inspect"),
          denials = [];
        for (const operation of ["git-add", "git-commit"])
          denials.push({
            ...(await ordinaryAttempt(profile, operation)),
            control: {
              ready: true,
              reachable: true,
              independent: true,
              nonce: input.request.nonce,
              operation,
              nativeCode: "OK",
              nativeEventSha256: positive.nativeEventSha256,
              receiptSha256: positive.receiptSha256,
            },
          });
        const after = await snapshot();
        requireObservation(same(before, after));
        profiles.push({
          profile: profile.profile,
          before,
          after,
          inspection,
          denials,
          disposable: true,
          providersExcluded: true,
          outsideUnchanged: true,
        });
      }
      await capture("S");
      const end = await reader.access("audit-close");
      decoder.finish({ code: end.code, signal: end.signal });
      await reader.retired(observer);
      observer = null;
      return evidence({
        profiles,
        candidateSha: input.request.candidateSha,
        outsideBeforeSha256: await outsideRead(),
        outsideAfterSha256: await outsideRead(),
      });
    }),
    retire: latch(async (value) => {
      requireObservation(same(value, input));
      if (channel) await channel.completion;
      requireObservation(!active && !observer);
      const settled = await retire();
      return evidence({
        ...settled,
        ...(channel
          ? {
              helper: channel.admission.helper,
              children: children.map(({ identity }) => identity),
            }
          : {}),
      });
    }, true),
  };
  return {
    effects,
    async prepare() {
      const actual = await reader.operation("operation-authority");
      requireObservation(
        actual.noLiveUid &&
          actual.sandboxed === false &&
          actual.identity.uid === 0 &&
          actual.identity.gid === 0,
      );
      await outsideRead();
      await persist({ kind: "git-outside", sha256: outside });
      requireObservation((await reader.tree(slots.hooks)).length === 0);
      const git = await reader.signature(slots.git);
      requireObservation(git.cdhash === input.git.cdhash);
      const policies = [];
      if (current.recipe.id === "git.ordinary") {
        requireObservation(
          same(slots.profiles.map(({ profile }) => profile).sort(), [
            "read-only",
            "trusted-command",
            "workspace-write",
          ]),
        );
        for (const profile of slots.profiles) {
          observationObject(profile, ["profile", "policy"]);
          policies.push({
            profile: profile.profile,
            seatbeltSha256: digest(await reader.read(profile.policy)),
          });
        }
      } else
        requireObservation(
          slots.profiles.length === 0 &&
            slots.audit === null &&
            slots.control === null,
        );
      const policy = {
        launch: nativePolicyLaunchData(input.request, DARWIN_LITERAL_ARGUMENTS),
        policy: {
          kind: "darwin-git",
          gitSha256: input.git.sha256,
          metadata: {
            identitySha256: digest(
              (await reader.inspect(slots.metadata)).identity,
            ),
          },
          hooks: {
            identitySha256: digest(
              (await reader.inspect(slots.hooks)).identity,
            ),
          },
          authority: {
            uid: actual.identity.uid,
            gid: actual.identity.gid,
            sandboxed: actual.sandboxed,
          },
          profiles: policies,
        },
      };
      return core.policy(policy, { actual, git, outside });
    },
    async finish() {
      requireObservation(!active);
      if (observer) {
        await capture("S");
        const end = await reader.access("audit-close");
        decoder.finish({ code: end.code, signal: end.signal });
        await reader.retired(observer);
        observer = null;
      }
      await outsideRead();
    },
  };
}
