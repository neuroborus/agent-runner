import {
  observationObject,
  observationList,
  normalizeNativePolicyContext,
} from "../index.js";
import {
  digest,
  darwinLaunchDigest,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
  requireDarwin,
} from "./protocol.js";
import { normalizeDarwinFileIdentity } from "./files-protocol.js";
import { buildDarwinPolicy } from "./policy.js";
import { normalizeDarwinGitInput } from "./git.js";
import { bindDarwinAuditEvent } from "./audit.js";
import {
  normalizeDarwinPfRead,
  darwinPfRootDigest,
  assertDarwinPfRoot,
} from "./pf-preparation.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const integer = (value, bound = 0xffffffff) =>
  Number.isSafeInteger(value) && value >= 0 && value <= bound;
const plainText = (bytes) =>
  new TextDecoder("utf-8", { fatal: true }).decode(bytes);
function object(value) {
  observationObject(value, [
    "identity",
    "bytes",
    "uid",
    "gid",
    "mode",
    "directory",
  ]);
  normalizeDarwinFileIdentity(value.identity);
  requireDarwin(
    integer(value.bytes, 536870912) &&
      integer(value.uid) &&
      integer(value.gid) &&
      integer(value.mode, 0o7777) &&
      typeof value.directory === "boolean" &&
      !(value.mode & 0o22),
  );
  return structuredClone(value);
}
export function normalizeDarwinBarrierRead(value, contents = true) {
  observationObject(value, ["object", "sha256", ...(contents ? ["hex"] : [])]);
  object(value.object);
  requireDarwin(!value.object.directory && hash(value.sha256));
  if (contents) {
    requireDarwin(
      typeof value.hex === "string" &&
        /^(?:[a-f0-9]{2})*$/u.test(value.hex) &&
        value.hex.length <= 131072 &&
        value.hex.length === value.object.bytes * 2 &&
        digest(Buffer.from(value.hex, "hex")) === value.sha256,
    );
  }
  return structuredClone(value);
}
export function normalizeDarwinAuthorityRead(value, subject, held) {
  observationObject(value, [
    "subject",
    "sandboxed",
    "path",
    "object",
    "aclSha256",
    "decisions",
  ]);
  requireDarwin(
    sameDarwinIdentity(normalizeDarwinIdentity(value.subject), subject) &&
      value.sandboxed === true &&
      JSON.stringify(object(value.object)) === JSON.stringify(held) &&
      hash(value.aclSha256),
  );
  requireDarwin(
    observationList(value.decisions, 5).length === 5 &&
      value.decisions.every((decision) => [0, 1].includes(decision)),
  );
  requireDarwin(
    typeof value.path === "string" &&
      /^(?:[a-f0-9]{2}){1,4095}$/u.test(value.path),
  );
  return structuredClone(value);
}
/** Expected ABI digests must come from the admitted template/materializer,
 * separately from these actual kernel reads. Paths/raw rules stay protected. */
export function createDarwinEffectiveReaders(
  reader,
  contextValue,
  verifierValue,
) {
  const context = normalizeNativePolicyContext(contextValue),
    verifier = normalizeDarwinIdentity(verifierValue);
  requireDarwin(
    context.platform === "darwin" &&
      [
        verifier.uid,
        verifier.ruid,
        verifier.svuid,
        verifier.gid,
        verifier.rgid,
        verifier.svgid,
      ].every((id) => id === 0),
  );
  const fresh = async () =>
    requireDarwin(
      sameDarwinIdentity(await reader.process(verifier.pid), verifier),
    );
  return {
    async pfSnapshot(input, expected, reservationIndex, sockets) {
      const plan = buildDarwinPolicy(input);
      observationObject(expected, [
        "compositionSha256",
        "rootSha256",
        "anchorRulesSha256",
        "routesSha256",
      ]);
      requireDarwin(
        plan.value.request.candidateSha === context.candidateSha &&
          plan.value.request.bindings.closure === context.closureSha256 &&
          expected.compositionSha256 === plan.compositionSha256 &&
          Object.values(expected).every(hash),
      );
      await fresh();
      await reader.reservation();
      const lease = await reader.inspect(reservationIndex),
        endpoints = [];
      for (const item of observationList(sockets, 8)) {
        observationObject(item, ["subject", "descriptor"]);
        const subject = normalizeDarwinIdentity(item.subject);
        requireDarwin([0, plan.value.request.uid].includes(subject.uid));
        endpoints.push(await reader.socket(subject, item.descriptor));
      }
      const required = plan.value.endpoints.flatMap((endpoint) =>
        [
          endpoint.serverPort,
          ...(endpoint.clientPort ? [endpoint.clientPort] : []),
        ].map((port) => `${endpoint.family}:${endpoint.protocol}:${port}`),
      );
      requireDarwin(
        endpoints.length === required.length &&
          new Set(
            endpoints.map(
              (item) => `${item.family}:${item.protocol}:${item.port}`,
            ),
          ).size === required.length &&
          endpoints.every((item) =>
            required.includes(`${item.family}:${item.protocol}:${item.port}`),
          ),
      );
      const reservationSha256 = digest(JSON.stringify({ lease, endpoints }));
      const read = normalizeDarwinPfRead(await reader.pf()),
        again = normalizeDarwinPfRead(await reader.pf());
      requireDarwin(
        digest(JSON.stringify(read)) === digest(JSON.stringify(again)) &&
          read.routesSha256 === expected.routesSha256,
      );
      assertDarwinPfRoot(read, expected.rootSha256);
      const anchor = read.graph.find((entry) => entry.anchor === plan.anchor);
      requireDarwin(
        anchor &&
          digest(JSON.stringify(anchor.rules)) === expected.anchorRulesSha256 &&
          anchor.rules.length > 0 &&
          anchor.rules.every(
            (rule) => rule.set === 1 && rule.state === 0 && rule.call === "",
          ) &&
          read.graph.every(
            (entry) =>
              entry.anchor === "" ||
              entry.anchor === plan.anchor ||
              entry.rules.length === 0,
          ),
      );
      for (let i = 0; i < sockets.length; i++)
        requireDarwin(
          JSON.stringify(
            await reader.socket(sockets[i].subject, sockets[i].descriptor),
          ) === JSON.stringify(endpoints[i]),
        );
      await reader.reservation();
      requireDarwin(
        JSON.stringify(await reader.inspect(reservationIndex)) ===
          JSON.stringify(lease),
      );
      await fresh();
      return {
        candidateSha: context.candidateSha,
        nonce: plan.value.request.nonce,
        compositionSha256: plan.compositionSha256,
        reviewSha256: plan.value.reviewSha256,
        anchor: plan.anchor,
        sha256: plan.pfSha256,
        anchorSha256: plan.pfSha256,
        rootSha256: darwinPfRootDigest(read),
        evidenceSha256: digest(JSON.stringify(read)),
        reservationSha256,
        active: true,
        loopbackFiltered: true,
        anchorReachable: true,
        anchorQuick: true,
        earlierMatchingQuickRules: 0,
        conflictingStates: 0,
        conflictingNat: 0,
        skipExemptions: 0,
        unfilteredRoutes: 0,
        endpointsExclusive: true,
        exclusiveWriter: true,
        ownerLookup: "sending-out-receiving-in",
        unknownOwner: "blocked",
        ruleState: "none",
        anchorOwned: true,
        admissionsClosed: true,
        independent: true,
        verifier: structuredClone(verifier),
      };
    },
    async seatbelt(input, record, policyIndex, objects, argumentsList = []) {
      const plan = buildDarwinPolicy(input),
        subject = normalizeDarwinIdentity(record.payload);
      requireDarwin(
        ["verify", "release"].includes(record.phase) &&
          plan.value.request.candidateSha === context.candidateSha &&
          plan.value.request.bindings.closure === context.closureSha256 &&
          record.candidateSha === context.candidateSha &&
          record.nonce === plan.value.request.nonce &&
          record.requestSha256 ===
            darwinLaunchDigest(plan.value.request, argumentsList) &&
          record.helpers?.some((item) => item.identity.pid !== verifier.pid) &&
          plan.value.request.policy.sha256 === plan.seatbeltSha256 &&
          plan.value.request.bindings.policy === plan.compositionSha256 &&
          subject.uid === plan.value.request.uid &&
          subject.gid === plan.value.request.gid &&
          subject.asid !== verifier.asid,
      );
      const launcher = normalizeDarwinIdentity(
        record.helpers.find((item) => item.role === "launcher")?.identity,
      );
      requireDarwin(
        launcher.pid !== verifier.pid &&
          (await reader.helper(launcher)).sha256 ===
            plan.value.request.launcher.sha256,
      );
      await fresh();
      const bytes = await reader.read(policyIndex, 1048576);
      requireDarwin(
        digest(bytes) === plan.seatbeltSha256 &&
          plainText(bytes) === plan.seatbelt,
      );
      const required = new Set(
        ["custody", "storage", "workspace"]
          .map((key) => plan.value.request[key])
          .concat(
            [
              "metadata",
              "pointer",
              "checkout",
              "configuration",
              "credentials",
            ].map((key) => plan.value[key]),
            plan.value.runtime.map((item) => item.path),
            plan.value.request.execution
              ? [
                  plan.value.request.execution.environment.HOME,
                  plan.value.request.execution.environment.XDG_CACHE_HOME,
                ]
              : [],
          ),
      );
      const actual = [];
      for (const item of observationList(objects, 128)) {
        observationObject(item, [
          "path",
          "index",
          "identity",
          "decisions",
          "aclSha256",
        ]);
        requireDarwin(
          required.delete(item.path) &&
            integer(item.index, 127) &&
            hash(item.aclSha256),
        );
        const held = await reader.inspect(item.index);
        requireDarwin(
          held.identity === normalizeDarwinFileIdentity(item.identity),
        );
        const read = await reader.authority(subject, item.index);
        requireDarwin(
          plainText(Buffer.from(read.path, "hex")) === item.path &&
            read.aclSha256 === item.aclSha256 &&
            JSON.stringify(read.decisions) === JSON.stringify(item.decisions),
        );
        actual.push(read);
      }
      requireDarwin(
        required.size === 0 &&
          sameDarwinIdentity(await reader.process(subject.pid), subject),
      );
      return {
        subject,
        installed: true,
        seatbeltSha256: digest(bytes),
        observationSha256: digest(JSON.stringify(actual)),
        verifier: structuredClone(verifier),
        independent: true,
      };
    },
    async outsideControl(input, subjectValue, directory, name, nonce, event) {
      const subject = normalizeDarwinIdentity(subjectValue);
      await fresh();
      const { request } = buildDarwinPolicy(input).value;
      requireDarwin(
        request.candidateSha === context.candidateSha &&
          request.bindings.closure === context.closureSha256 &&
          nonce === request.nonce &&
          subject.uid !== request.uid &&
          event.pid === subject.pid &&
          event.auid === subject.auid &&
          event.asid === subject.asid &&
          event.target === `${await reader.location(directory)}/${name}` &&
          event.error === 0 &&
          hash(event.id),
      );
      const before = await reader.process(subject.pid),
        first = await reader.barrier(directory, name),
        file = await reader.barrier(directory, name),
        after = await reader.process(subject.pid);
      requireDarwin(
        sameDarwinIdentity(before, subject) &&
          sameDarwinIdentity(after, subject) &&
          file.sha256 === digest(nonce),
      );
      bindDarwinAuditEvent(
        event,
        before,
        after,
        { before: first, after: file },
        file.sha256,
        event.window?.barrierSha256,
      );
      return {
        ready: true,
        reachable: true,
        independent: true,
        nonce,
        discretionaryAllowed: true,
        identity: subject,
        targetSha256: file.sha256,
        acknowledgementSha256: digest(JSON.stringify({ subject, file, event })),
        nativeEventSha256: event.id,
      };
    },
    async gitSnapshot(value, metadata, workspace) {
      const input = normalizeDarwinGitInput(value);
      requireDarwin(
        input.request.candidateSha === context.candidateSha &&
          input.request.bindings.closure === context.closureSha256,
      );
      await fresh();
      const reads = new Map();
      const read = async (name) => {
        const file = await reader.barrier(metadata, name);
        reads.set(name, file);
        return plainText(Buffer.from(file.hex, "hex"));
      };
      const config = await read("config"),
        head = await read("HEAD");
      requireDarwin(head === "ref: refs/heads/proof\n");
      const inventory = await reader.tree(metadata),
        refs = [];
      for (const item of inventory)
        if (item.name.startsWith("refs/")) {
          const value = (await read(item.name)).trim();
          requireDarwin(/^[a-f0-9]{40}$/u.test(value));
          refs.push([item.name, value]);
        }
      requireDarwin(
        !inventory.some((item) => item.name === "packed-refs") &&
          refs.some(([name]) => name === "refs/heads/proof"),
      );
      const user = /\[user\]\n\s*name = ([^\n]+)\n\s*email = ([^\n]+)\n/u.exec(
        config,
      );
      requireDarwin(user);
      const work = await reader.tree(workspace),
        after = await reader.tree(metadata);
      requireDarwin(
        JSON.stringify(inventory) === JSON.stringify(after) &&
          [...reads].every(([name, file]) =>
            inventory.some(
              (item) =>
                item.name === name &&
                item.file.sha256 === file.sha256 &&
                item.file.object.identity === file.object.identity,
            ),
          ) &&
          JSON.stringify(work) === JSON.stringify(await reader.tree(workspace)),
      );
      return {
        config,
        identity: `${user[1]} <${user[2]}>`,
        branch: "refs/heads/proof",
        head: refs.find(([name]) => name === "refs/heads/proof")[1],
        refs: refs.sort(),
        metadata: inventory
          .map((item) => [item.name, item.file.sha256, item.file.object.mode])
          .sort(),
        workspace: work
          .map((item) => [item.name, item.file.sha256, item.file.object.mode])
          .sort(),
      };
    },
  };
}
