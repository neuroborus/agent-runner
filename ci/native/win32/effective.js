import { normalizeNativePolicyContext, observationDigest } from "../index.js";
import {
  closed,
  dense,
  digest,
  hash,
  requireWindows,
  systemIdentity,
  sameWindowsIdentity,
} from "./protocol.js";
import { decode, integer } from "./custody-protocol.js";
import { normalizeWindowsGitInput } from "./git.js";
import { buildWindowsPolicy } from "./policy.js";
import { normalizeWindowsBarrierRead } from "./effective-protocol.js";
import { readWindowsEffectivePolicy } from "./effective-policy.js";
export {
  normalizeWindowsSecurityRead,
  normalizeWindowsBarrierRead,
} from "./effective-protocol.js";
export { assertWindowsWfpFilterRead } from "./wfp-reader.js";
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** Effect-free factory. Native held reads prove individual objects; the
 * independently supplied coverage owner proves reservations, the complete
 * host/handle/flow inventory and source-dependent creation/delegation limits. */
export function createWindowsEffectiveReaders(
  reader,
  contextValue,
  verifierValue,
  options = {},
) {
  const context = normalizeNativePolicyContext(contextValue),
    verifier = systemIdentity(verifierValue);
  requireWindows(context.platform === "win32");
  const fresh = async () =>
    requireWindows(
      sameWindowsIdentity(await reader.verifier(verifier), verifier),
    );
  const bound = (request) =>
    requireWindows(
      request.candidateSha === context.candidateSha &&
        request.bindings.closure === context.closureSha256,
    );
  const barrier = async (index, name) =>
    normalizeWindowsBarrierRead(await reader.barrier(index, name));
  const tree = async (index) => {
    const values = dense(await reader.tree(index), 256)
      .map((item) => {
        closed(item, ["nameHex", "file"]);
        const name = decode(item.nameHex).replaceAll("\\", "/");
        requireWindows(
          name
            .split("/")
            .every(
              (part) =>
                /^[A-Za-z0-9_.-]+$/u.test(part) && ![".", ".."].includes(part),
            ),
        );
        return { name, file: normalizeWindowsBarrierRead(item.file, false) };
      })
      .sort((a, b) => a.name.localeCompare(b.name, "en"));
    requireWindows(
      new Set(values.map((item) => item.name.toLowerCase())).size ===
        values.length &&
        new Set(values.map((item) => item.file.identity)).size ===
          values.length,
    );
    return values;
  };
  const result = {
    barrier,
    policySnapshot: (value, transfer) =>
      readWindowsEffectivePolicy(
        reader,
        context,
        verifier,
        options,
        fresh,
        bound,
        value,
        transfer,
      ),
    async retiredPolicySnapshot(
      value,
      transfer,
      jobs,
      { installed = true } = {},
    ) {
      requireWindows(
        typeof installed === "boolean" && dense(jobs, 32).length > 0,
      );
      transfer = structuredClone(transfer);
      value = structuredClone(value);
      const proof = await result.retirement([transfer.subject], jobs);
      requireWindows(proof.nonce === value.request.nonce);
      return readWindowsEffectivePolicy(
        reader,
        context,
        verifier,
        options,
        fresh,
        bound,
        value,
        transfer,
        { installed, retired: true },
      );
    },
    async gitSnapshot(value, metadata, workspace) {
      const input = normalizeWindowsGitInput(value);
      bound(input.request);
      await fresh();
      const meta = await reader.inspect(metadata),
        work = await reader.inspect(workspace);
      const parents = {
        metadata: await reader.parents(metadata),
        workspace: await reader.parents(workspace),
      };
      requireWindows(
        decode(meta.pathHex) === input.metadata &&
          decode(work.pathHex) === input.request.workspace,
      );
      const inventory = await tree(metadata),
        working = await tree(workspace),
        reads = new Map();
      const read = async (name) => {
        const item = await barrier(metadata, name);
        reads.set(name.replaceAll("\\", "/"), item);
        return new TextDecoder("utf-8", { fatal: true }).decode(
          Buffer.from(item.hex, "hex"),
        );
      };
      const config = await read("config"),
        head = await read("HEAD"),
        refs = [];
      requireWindows(
        head === "ref: refs/heads/proof\n" &&
          !inventory.some((item) => item.name === "packed-refs"),
      );
      for (const item of inventory.filter((item) =>
        item.name.startsWith("refs/"),
      )) {
        const text = await read(item.name.replaceAll("/", "\\"));
        requireWindows(/^[a-f0-9]{40}\n$/u.test(text));
        refs.push([item.name, text.trim()]);
      }
      const user = /\[user\]\n\s*name = ([^\n]+)\n\s*email = ([^\n]+)\n/u.exec(
          config,
        ),
        branch = refs.find(([name]) => name === "refs/heads/proof");
      requireWindows(user && branch);
      // Compare the complete held identities, bytes and security, excluding only
      // contents absent from the bounded inventory representation.
      for (const [name, file] of reads) {
        const { hex, ...withoutContents } = file;
        requireWindows(
          equal(
            inventory.find((item) => item.name === name)?.file,
            withoutContents,
          ),
        );
      }
      const pointer = await barrier(workspace, ".git"),
        content = await barrier(workspace, "content.txt");
      for (const [name, file] of [
        [".git", pointer],
        ["content.txt", content],
      ]) {
        const { hex, ...withoutContents } = file;
        requireWindows(
          equal(
            working.find((item) => item.name === name)?.file,
            withoutContents,
          ),
        );
      }
      requireWindows(
        pointer.sha256 ===
          digest(`gitdir: ${input.metadata.replaceAll("\\", "/")}\n`) &&
          equal(await tree(metadata), inventory) &&
          equal(await tree(workspace), working) &&
          equal(await reader.parents(metadata), parents.metadata) &&
          equal(await reader.parents(workspace), parents.workspace),
      );
      await fresh();
      return {
        config,
        identity: `${user[1]} <${user[2]}>`,
        branch: "refs/heads/proof",
        head: branch[1],
        refs: refs.sort(),
        metadata: inventory.map((item) => [
          item.name,
          item.file.sha256,
          item.file.daclSha256,
        ]),
        workspaceSha256: observationDigest(working),
        pointerSha256: pointer.sha256,
        pointerIdentitySha256: digest(pointer.identity),
        contentSha256: content.sha256,
        contentIdentitySha256: digest(content.identity),
        parentIdentitiesSha256: observationDigest(parents),
      };
    },
    async outsideControl(value, subject, custody, name) {
      const plan = buildWindowsPolicy(value);
      bound(plan.value.request);
      await fresh();
      requireWindows(
        name === "outside-sentinel" && typeof options.control === "function",
      );
      const before = await reader.process(subject),
        root = await reader.inspect(custody);
      systemIdentity(before.identity);
      requireWindows(
        before.independent === true &&
          before.identity.pid !== verifier.pid &&
          decode(root.pathHex) === plan.value.request.custody,
      );
      const first = await barrier(custody, name),
        second = await barrier(custody, name);
      requireWindows(
        equal(first, second) &&
          first.sha256 === digest(plan.value.request.nonce),
      );
      const proof = await options.control(
        structuredClone({
          context,
          nonce: plan.value.request.nonce,
          subject: before.identity,
          target: first,
        }),
      );
      requireWindows(
        proof.independent === true &&
          proof.reached === true &&
          proof.discretionaryAllowed === true &&
          proof.nonce === plan.value.request.nonce &&
          proof.targetIdentity === first.identity &&
          proof.targetSha256 === first.sha256 &&
          sameWindowsIdentity(proof.subject, before.identity) &&
          sameWindowsIdentity(systemIdentity(proof.verifier), verifier) &&
          hash(proof.nativeEventSha256),
      );
      requireWindows(
        equal(await reader.process(subject), before) &&
          equal(await barrier(custody, name), first),
      );
      await fresh();
      return {
        ready: true,
        reachable: true,
        independent: true,
        nonce: proof.nonce,
        discretionaryAllowed: true,
        identity: before.identity,
        targetSha256: first.sha256,
        acknowledgementSha256: observationDigest(proof),
        nativeEventSha256: proof.nativeEventSha256,
      };
    },
    async retirement(subjects, jobs) {
      for (const values of [subjects, jobs])
        requireWindows(
          dense(values, 32).every((value) => integer(value, 31)) &&
            new Set(values).size === values.length,
        );
      subjects = structuredClone(subjects);
      jobs = structuredClone(jobs);
      await fresh();
      const processes = [];
      for (const subject of dense(subjects, 32)) {
        const read = await reader.process(subject);
        requireWindows(read.independent === true && read.retired === true);
        processes.push(read);
      }
      const heldJobs = [];
      for (const index of dense(jobs, 32)) {
        const read = await reader.inspectJob(index);
        requireWindows(read.independent === true && read.members.length === 0);
        heldJobs.push(read);
      }
      requireWindows(typeof options.retirement === "function");
      const proof = await options.retirement(
        structuredClone({ context, processes, jobs: heldJobs }),
      );
      requireWindows(
        proof.status === "RETIRED" &&
          proof.candidateSha === context.candidateSha &&
          proof.independent === true &&
          proof.emergencyCleanup === false &&
          proof.noLiveMembers === true &&
          proof.noForeignCreators === true &&
          proof.noPrincipalFlows === true &&
          proof.observationsSha256 ===
            observationDigest({ context, processes, jobs: heldJobs }) &&
          sameWindowsIdentity(systemIdentity(proof.verifier), verifier) &&
          hash(proof.nativeEventSha256),
      );
      await fresh();
      return proof;
    },
  };
  return result;
}
