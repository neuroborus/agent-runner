import path from "node:path";
import {
  observationObject,
  observationDigest,
  requireObservation,
  materializeNativePolicy,
  materializeNativePolicyBinding,
  normalizeNativePolicyTemplate,
  assertNativePolicyParameters,
  assertNativePolicyLaunchBinding,
} from "../index.js";
import { encodeDarwinCustodyPlan } from "./custody.js";
import {
  digest,
  DARWIN_LITERAL_ARGUMENTS,
  sameDarwinIdentity,
} from "./protocol.js";
import { buildDarwinPolicy } from "./policy.js";
import {
  darwinOwnershipArguments,
  createDarwinCaseEffects,
} from "./case-effects.js";
import { darwinAccessPreparation } from "./access-effects.js";

const lease = "/private/var/run/native-poc/pf-lease";
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const same = (a, b) => observationDigest(a) === observationDigest(b);
const rootFor = (context) =>
  "/private/var/run/native-poc/cases/" + observationDigest(context);

// Bind only values read from native custody. An undeclared or unobservable
// identity has no materialization fallback, even when its expected value exists.
function bindingsFor(binding, values) {
  return binding.template.bindings.map((rule) => {
    const observed = rule.paths.map((location) => {
      const key = location.join(".");
      requireObservation(Object.hasOwn(values, key));
      return values[key];
    });
    requireObservation(
      observed.length && observed.every((value) => value === observed[0]),
    );
    return { id: rule.id, kind: rule.kind, value: observed[0] };
  });
}
function provisioning(binding, values, verifierSha256, native) {
  return {
    schemaVersion: 1,
    context: structuredClone(binding.context),
    authoritySha256: binding.template.provisioningReviewSha256,
    bindings: bindingsFor(binding, values),
    held: true,
    independent: true,
    verifierSha256,
    nativeEventSha256: observationDigest(native),
  };
}

/** Private composition for fixed system recipes. Approved records contain data;
 * directory creation, held copies, endpoint reads and retirement stay native. */
export function createDarwinCaseProvisioning(state, options) {
  return {
    async observeBuildPolicy(
      binding,
      { commands, reader, settlement },
      { signal },
    ) {
      state.guard(signal);
      requireObservation(
        binding.template.provisioningReviewSha256 ===
          state.plan.bootstrap.reviewSha256,
      );
      const domains = [];
      for (const command of commands) {
        const policy = command.compilerPolicy;
        observationObject(policy, [
          "identity",
          "uid",
          "gid",
          "ruid",
          "rgid",
          "sandboxed",
          "descriptors",
        ]);
        requireObservation(
          sameDarwinIdentity(policy.identity, command.identity),
        );
        const { identity, ...authority } = policy;
        requireObservation(
          [authority.uid, authority.gid, authority.ruid, authority.rgid].every(
            (id) => id === 0,
          ) &&
            authority.sandboxed === false &&
            same(authority.descriptors, [
              { fd: 0, type: "vnode" },
              { fd: 1, type: "pipe" },
              { fd: 2, type: "pipe" },
            ]),
        );
        // The immutable pre-release observation must rejoin the final receipt.
        const names = (await state.fs.readdir(state.directory)).filter((name) =>
          new RegExp(
            `^darwin-command-${command.requestSha256}-[0-9]+\\.json$`,
            "u",
          ).test(name),
        );
        requireObservation(names.length <= 32);
        const workers = [];
        for (const name of names) {
          const record = JSON.parse(
            await state.receipt(path.join(state.directory, name)),
          );
          if (record.phase === "worker") workers.push(record);
        }
        requireObservation(
          workers.length === 1 &&
            workers[0].requestSha256 === command.requestSha256 &&
            same(workers[0].compilerPolicy, policy) &&
            sameDarwinIdentity(workers[0].worker, identity),
        );
        domains.push(authority);
      }
      const output = await reader.readBuildDirectory(state.output);
      requireObservation(output.mode === 0o555);
      const policy = normalizeNativePolicyTemplate({
        ...binding.template,
        bindings: [],
        policy: {
          launch: {
            commands: commands.map(({ requestSha256, toolSha256 }) => ({
              requestSha256,
              toolSha256,
            })),
          },
          policy: {
            compilerDomains: domains,
            output: {
              path: state.output,
              identitySha256: digest(Buffer.from(output.identity)),
              uid: output.uid,
              gid: output.gid,
              mode: output.mode,
            },
          },
        },
      }).policy;
      const allocation = provisioning(
        binding,
        {
          "policy.output.identitySha256": policy.policy.output.identitySha256,
        },
        state.plan.bootstrap.reader.sha256,
        { commands, output, settlement },
      );
      const requestSha256 = observationDigest(policy.launch);
      return {
        provisioning: allocation,
        requestSha256,
        observed: {
          schemaVersion: 1,
          context: structuredClone(binding.context),
          templateSha256: binding.approval.manifestSha256,
          provisioningSha256: observationDigest(allocation),
          requestSha256,
          policySha256: observationDigest(policy),
          policy,
          held: true,
          complete: true,
          independent: true,
          verifierSha256: state.plan.bootstrap.reader.sha256,
          nativeEventSha256: observationDigest({ policy, settlement, output }),
        },
      };
    },
    async provision(declared, binding, { signal, current, persist }) {
      state.guard(signal);
      const setup = declared.bindings;
      observationObject(setup, [
        "schemaVersion",
        "authoritySha256",
        "uid",
        "gid",
        "input",
        "assets",
        ...(Object.hasOwn(setup, "access") ? ["access"] : []),
      ]);
      requireObservation(
        setup.schemaVersion === 1 &&
          setup.authoritySha256 === declared.custody.reviewSha256 &&
          setup.authoritySha256 === binding.template.provisioningReviewSha256 &&
          same(declared.custody.context, binding.context) &&
          state.plan.cases.every(
            (entry) =>
              entry.id === declared.id ||
              (entry.bindings.uid !== setup.uid &&
                entry.bindings.gid !== setup.gid),
          ),
      );
      const input = structuredClone(setup.input),
        request = input.request ?? input,
        argumentsList = declared.id.startsWith("ownership.")
          ? darwinOwnershipArguments(declared.id, request)
          : DARWIN_LITERAL_ARGUMENTS,
        root = rootFor(binding.context),
        nonce = observationDigest(binding.context).slice(0, 32);
      requireObservation(
        request.candidateSha === state.job.candidateSha &&
          request.uid === setup.uid &&
          request.gid === setup.gid &&
          request.nonce === nonce &&
          request.custody === root + "/custody" &&
          request.storage === root + "/storage" &&
          request.workspace === root + "/storage/work" &&
          request.launcher.path === root + "/custody/launcher" &&
          request.executable.path === root + "/storage/payload" &&
          request.policy.path === root + "/custody/policy" &&
          request.bindings.closure === binding.context.closureSha256,
      );
      requireObservation(
        Array.isArray(setup.assets) && setup.assets.length === 3,
      );
      const targets = [request.launcher, request.executable, request.policy];
      const entries = [
        { kind: "directory", path: root, sha256: null },
        ...[request.custody, request.storage, request.workspace].map(
          (path) => ({ kind: "authority", path, sha256: null }),
        ),
        ...targets.map(({ path, sha256 }, i) => ({
          kind: i === 2 ? "data" : "image",
          path,
          sha256,
        })),
      ];
      for (const [i, asset] of setup.assets.entries()) {
        observationObject(asset, ["path", "sha256"]);
        requireObservation(
          hash(asset.sha256) &&
            asset.sha256 === targets[i].sha256 &&
            path.isAbsolute(asset.path) &&
            path.normalize(asset.path) === asset.path &&
            !asset.path.startsWith(root + "/"),
        );
        entries.push({ kind: i === 2 ? "data" : "image", ...asset });
      }
      entries.push(
        {
          kind: "data",
          path: lease,
          sha256: digest("native-poc-pf-lease-v1\n"),
        },
        { kind: "directory", path: state.output, sha256: null },
      );
      const access = setup.access
        ? await darwinAccessPreparation(state, setup, binding, entries)
        : null;
      if (access) entries.push(...access.entries.slice(entries.length));
      const planBytes = encodeDarwinCustodyPlan({
        candidateSha: state.job.candidateSha,
        uid: setup.uid,
        gid: setup.gid,
        entries,
      });
      requireObservation(
        digest(planBytes) === declared.custody.plan.sha256 &&
          (
            await state.read(
              declared.custody.plan.path,
              declared.custody.plan.sha256,
            )
          ).equals(planBytes),
      );
      if (declared.id !== "release")
        assertNativePolicyLaunchBinding(binding, request, argumentsList);
      // Expected launch data is checked before mutation. Effective setup is read
      // again below; materialization cannot establish native custody.
      const provisionalValues = {
        "launch.request.uid": setup.uid,
        "launch.request.gid": setup.gid,
        "launch.request.nonce": nonce,
      };
      const policy = declared.id.startsWith("access.")
        ? buildDarwinPolicy(input)
        : null;
      if (policy)
        requireObservation(
          input.profile === declared.id.slice(7) &&
            request.policy.sha256 === policy.seatbeltSha256 &&
            request.bindings.policy === policy.compositionSha256,
        );
      const endpoints = policy
        ? policy.value.endpoints.flatMap(
            ({ family, protocol, clientPort, serverPort }, i) => {
              provisionalValues[`policy.endpoints.${i}.clientPort`] =
                clientPort;
              provisionalValues[`policy.endpoints.${i}.serverPort`] =
                serverPort;
              return [
                { family, protocol, port: clientPort },
                { family, protocol, port: serverPort },
              ];
            },
          )
        : [];
      const reader = state.createReader(declared.custody, {
        ...options.readerOptions,
        caseContextSha256: observationDigest(binding.context),
        persist: (record) => persist({ phase: "custody", record }),
      });
      current.reader = reader; // Preserve custody even if a later operation throws.
      current.repositoryProvisioning = true;
      const admission = await reader.start({ signal });
      current.admission = admission;
      requireObservation(
        admission.independent &&
          admission.planSha256 === declared.custody.plan.sha256,
      );
      await reader.verifyBuildReceipt(current.intentPin);
      await reader.open(10);
      await reader.reserve(10, nonce);
      current.reserved = true;
      for (let i = 0; i < 4; i++) await reader.provisionCaseDirectory(i);
      for (let i = 0; i < 3; i++) {
        await reader.open(i + 7);
        await reader.copyCaseAsset(i + 4, i + 7);
      }
      for (const endpoint of endpoints)
        await reader.provisionCaseEndpoint(endpoint);
      const actual = await reader.readCase();
      requireObservation(
        actual.uid === setup.uid &&
          actual.gid === setup.gid &&
          actual.objects.length === 7 &&
          new Set(actual.objects.map((item) => item.index)).size === 7 &&
          same(actual.endpoints, endpoints),
      );
      for (const { index, object } of actual.objects)
        requireObservation(
          object.uid === (index === 3 ? setup.uid : 0) &&
            object.gid === ([1, 4, 6].includes(index) ? 0 : setup.gid) &&
            object.mode ===
              ([0, 2].includes(index)
                ? 0o710
                : index < 4
                  ? 0o700
                  : index === 6
                    ? 0o400
                    : 0o550),
        );
      const values = {
        ...provisionalValues,
        "launch.request.uid": actual.uid,
        "launch.request.gid": actual.gid,
        "launch.request.nonce": actual.contextSha256.slice(0, 32),
      };
      actual.endpoints.forEach(({ port }, i) => {
        values[
          `policy.endpoints.${Math.floor(i / 2)}.${i % 2 ? "serverPort" : "clientPort"}`
        ] = port;
      });
      const allocation = provisioning(
        binding,
        values,
        declared.custody.reader.sha256,
        { admission, actual },
      );
      materializeNativePolicy(
        binding.template,
        binding.approval,
        allocation,
        binding.context,
      );
      if (declared.id !== "release") {
        materializeNativePolicyBinding(
          binding,
          allocation,
          request,
          argumentsList,
        );
        if (!declared.id.startsWith("ownership."))
          assertNativePolicyParameters(
            binding,
            allocation,
            policy?.value ?? (input.request ? input : { request }),
            argumentsList,
          );
      }
      await persist({
        phase: "provisioned",
        context: binding.context,
        provisioning: allocation,
        actual,
        helper: admission.helper,
      });
      if (access) {
        for (const [i, asset] of access.assets.entries()) {
          const index = i + 12;
          if (asset.source !== null)
            await reader.copyCaseAsset(index, asset.source);
          else if (
            asset.kind === "authority" &&
            asset.path.startsWith(root + "/")
          )
            await reader.provisionCaseDirectory(index);
          else if (asset.path !== policy.value.pointer)
            await reader.open(index);
        }
      }
      return {
        ...(access ? { access } : {}),
        input,
        arguments: argumentsList,
        provisioning: allocation,
        reader,
        admission,
      };
    },
    async recover(records, { signal }) {
      if (!records.length) return [];
      const reads = [],
        { reader: fresh } = await state.bootstrap(signal);
      try {
        for (const declared of state.plan.cases) {
          const prefix = `darwin-case-${declared.id}-`,
            entries = records
              .filter(({ name }) => name.startsWith(prefix))
              .sort(
                (a, b) =>
                  Number(a.name.slice(prefix.length, -5)) -
                  Number(b.name.slice(prefix.length, -5)),
              );
          if (!entries.length) continue;
          requireObservation(
            entries.every(({ name }, i) => name === `${prefix}${i}.json`),
          );
          const intent = entries[0].record;
          requireObservation(
            intent.phase === "provisioning-possible" &&
              intent.status === "POSSIBLE" &&
              same(intent.context, declared.custody.context) &&
              intent.bindingsSha256 === observationDigest(declared.bindings) &&
              intent.planSha256 === declared.custody.plan.sha256 &&
              hash(intent.templateSha256),
          );
          const ownership = entries.some(
            ({ record }) => record.phase === "ownership-receipt",
          );
          requireObservation(
            !ownership || declared.id.startsWith("ownership."),
          );
          requireObservation(
            entries
              .slice(1)
              .every(({ record }) =>
                [
                  "custody",
                  "provisioned",
                  "provisioning-retired",
                  ...(ownership
                    ? [
                        "reader-admitted",
                        "ownership-outside",
                        "ownership-receipt-possible",
                        "ownership-receipt",
                        "ownership-failure",
                        "ownership-retired",
                        "owner-receipt",
                      ]
                    : []),
                ].includes(record.phase),
              ),
          );
          const custody = entries
            .filter(({ record }) => record.phase === "custody")
            .map(({ record }) => record.record);
          const allowed = new Set([
            "entry",
            "admitted",
            "probe-intent",
            "probe-created",
            "probe-retired",
            "open",
            "reserve",
            "case-directory",
            "case-copy",
            "case-object",
            "inspect",
            "case-endpoint",
            "case-endpoint-bound",
            "case-read",
            "cleanup",
            "case-retire",
            "close",
            "finish",
            "retired",
            "case-rejoin",
            ...(ownership
              ? [
                  "case-start",
                  "case-eof",
                  "authority",
                  "case-control",
                  "case-send",
                  "case-output",
                  "case-subject",
                  "case-session",
                  "case-members",
                  "case-empty",
                  "case-signal",
                  "case-receipt",
                  "case-receipt-read",
                  "tree",
                  "barrier",
                  "read",
                  "session",
                  "process",
                ]
              : []),
          ]);
          let custodySequence = -1;
          requireObservation(
            custody.every(
              (record) =>
                record.sequence ===
                  (record.phase === "entry"
                    ? (custodySequence = 0)
                    : ++custodySequence) &&
                allowed.has(record.phase) &&
                same(record.context, declared.custody.context) &&
                record.reviewSha256 === declared.custody.reviewSha256 &&
                record.requestSha256 === digest(JSON.stringify(record.request)),
            ),
          );
          const admitted = custody.filter(
              (record) => record.phase === "admitted",
            ),
            launch = custody.filter((record) => record.phase === "entry");
          requireObservation(
            admitted.length > 0 &&
              admitted.length === launch.length &&
              launch.every(
                (record) =>
                  record.request.readerSha256 ===
                    declared.custody.reader.sha256 &&
                  record.request.planSha256 === declared.custody.plan.sha256,
              ) &&
              admitted.every((record) => same(record.subjects, record.request)),
          );
          const subjects = admitted.flatMap(({ subjects }) => [
            subjects.helper,
            subjects.verifier,
          ]);
          for (let i = 0; i < custody.length; i++)
            if (custody[i].phase === "probe-intent") {
              const intent = custody[i],
                born = custody[i + 1];
              requireObservation(
                born?.phase === "probe-created" &&
                  born.request.pid === intent.request.pid &&
                  born.sequence === intent.sequence + 1,
              );
              subjects.push(born.request.verifier);
            }
          for (const subject of subjects)
            reads.push(await fresh.retired(subject));
          const objects = custody.filter(
            (record) => record.phase === "case-object",
          );
          for (const intent of custody.filter((record) =>
            ["case-directory", "case-copy"].includes(record.phase),
          ))
            requireObservation(
              objects.filter(
                (record) =>
                  record.request.index === intent.request.arguments[0],
              ).length === 1,
            );
          let sequence = entries.length;
          const native = state.createReader(declared.custody, {
            ...options.readerOptions,
            caseContextSha256: observationDigest(declared.custody.context),
            persist: (record) =>
              state.write(`${prefix}${sequence++}.json`, {
                phase: "custody",
                record,
              }),
          });
          let complete = false;
          try {
            const admission = await native.start({ signal });
            let recovered;
            if (ownership) {
              const possible = entries.filter(
                  ({ record }) => record.phase === "ownership-receipt-possible",
                ),
                receipts = entries.filter(
                  ({ record }) => record.phase === "ownership-receipt",
                );
              requireObservation(
                possible.length === receipts.length &&
                  possible.every(
                    ({ record }, i) =>
                      same(record.pin, receipts[i].record.pin) &&
                      record.kind === receipts[i].record.kind &&
                      record.pin.index === i,
                  ),
              );
              const latest = receipts
                  .filter(({ record }) => record.kind === "admission")
                  .at(-1)?.record.pin,
                snapshots = entries.filter(
                  ({ record }) => record.phase === "ownership-outside",
                );
              requireObservation(
                latest && snapshots.length === 1 && objects.length === 7,
              );
              const bytes = await native.ownershipReceipt(
                  latest.index,
                  latest.sha256,
                ),
                admitted = JSON.parse(bytes);
              requireObservation(
                bytes.equals(Buffer.from(JSON.stringify(admitted) + "\n")) &&
                  admitted.candidateSha === state.job.candidateSha &&
                  admitted.nonce ===
                    observationDigest(declared.custody.context).slice(0, 32),
              );
              const members = admitted.payload ? [admitted.payload] : [];
              for (const { record } of receipts.filter(({ record }) =>
                ["members", "retirement"].includes(record.kind),
              )) {
                const bytes = await native.ownershipReceipt(
                    record.pin.index,
                    record.pin.sha256,
                  ),
                  ledger = JSON.parse(bytes);
                requireObservation(
                  bytes.equals(Buffer.from(JSON.stringify(ledger) + "\n")) &&
                    ledger.requestSha256 === admitted.requestSha256,
                );
                for (const identity of ledger.members ?? [])
                  if (
                    !members.some((known) =>
                      sameDarwinIdentity(known, identity),
                    )
                  )
                    members.push(identity);
              }
              recovered = {
                admitted,
                members,
                pin: latest,
                receiptIndex: receipts.length,
                outside: snapshots[0].record.snapshot,
              };
            }
            await native.open(10);
            await native.reserve(
              10,
              observationDigest(declared.custody.context).slice(0, 32),
            );
            for (const { request } of objects.sort(
              (a, b) => a.request.index - b.request.index,
            ))
              requireObservation(
                same(
                  await native.rejoinCaseObject(request.index),
                  request.object,
                ),
              );
            if (ownership) {
              for (let i = 7; i <= 9; i++) await native.open(i);
              const current = {
                reader: native,
                declared,
                recipe: { id: declared.id },
                input: declared.bindings.input,
                provisioned: {},
                binding: {},
                admission,
              };
              reads.push(
                await createDarwinCaseEffects(
                  state,
                  current,
                  (id, record) =>
                    state.write(`${prefix}${sequence++}.json`, record),
                  recovered,
                ).recover(),
              );
              complete = true;
              continue;
            }
            reads.push(await native.retireCase());
            const closed = await native.close();
            requireObservation(
              closed.status === "RETIRED" &&
                closed.independent &&
                closed.closed,
            );
            reads.push(closed);
            complete = true;
          } finally {
            if (!complete) {
              try {
                await native.retireCase();
                await native.close();
              } catch {
                /* Preserve the failed independent join. */
              }
            }
          }
        }
        requireObservation(
          records.every(({ name }) =>
            state.plan.cases.some(({ id }) =>
              name.startsWith(`darwin-case-${id}-`),
            ),
          ),
        );
      } finally {
        reads.push(await state.releaseBootstrap());
      }
      return reads;
    },
    async retire(current, { signal }) {
      state.guard(signal);
      requireObservation(
        current.reader &&
          current.repositoryProvisioning &&
          !current.prepared &&
          !current.caseEffectsPossible &&
          current.reserved,
      );
      requireObservation(!current.signal || current.signal.aborted);
      await current.reader.beginCleanup({ signal });
      const closed = await current.reader.retireCase();
      const custody = await current.reader.close();
      requireObservation(
        custody.status === "RETIRED" && custody.independent && custody.closed,
      );
      return {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({ closed, custody }),
      };
    },
  };
}
