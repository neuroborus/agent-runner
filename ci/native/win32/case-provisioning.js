import { win32 as path } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  observationObject,
  observationDigest,
  requireObservation,
  nativePolicyContext,
  normalizeNativePolicyTemplate,
  materializeNativePolicy,
  materializeNativePolicyBinding,
  assertNativePolicyLaunchBinding,
} from "../index.js";
import {
  digest as hashBytes,
  hash,
  WINDOWS_LITERAL_ARGUMENTS,
  normalizeWindowsLaunch,
  sameWindowsIdentity,
  systemIdentity,
} from "./protocol.js";
import {
  decodePlan,
  fileObservation,
  processObservation,
  jobObservation,
} from "./custody-protocol.js";
import { buildWindowsPolicy, normalizeWindowsPolicy } from "./policy.js";
import {
  windowsAccessArguments,
  windowsOwnershipArguments,
} from "./case-effects.js";
import { normalizeWindowsSecurityRead } from "./effective-protocol.js";
import { validateWindowsAccessApproval } from "./access-coverage.js";
import { windowsOperationPreparation } from "./case-operations.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const rootFor = (state, context) =>
  path.join(state.directory, "case-" + observationDigest(context));
const bindingsFor = (binding, values) =>
  binding.template.bindings.map((rule) => {
    const actual = rule.paths.map((location) => {
      const key = location.join(".");
      requireObservation(Object.hasOwn(values, key));
      return values[key];
    });
    requireObservation(
      actual.length && actual.every((value) => value === actual[0]),
    );
    return { id: rule.id, kind: rule.kind, value: actual[0] };
  });
const allocation = (binding, values, verifierSha256, actual) => ({
  schemaVersion: 1,
  context: structuredClone(binding.context),
  authoritySha256: binding.template.provisioningReviewSha256,
  bindings: bindingsFor(binding, values),
  held: true,
  independent: true,
  verifierSha256,
  nativeEventSha256: observationDigest(actual),
});
function tokenRead(value, accountSid, restrictingSid) {
  observationObject(value, [
    "userSid",
    "restrictedSids",
    "privileges",
    "enabledGroups",
    "integritySid",
    "sessionId",
    "tokenId",
    "authenticationId",
    "primary",
    "virtualized",
    "writeRestricted",
  ]);
  const token = structuredClone(value);
  requireObservation(
    token.userSid === accountSid &&
      same(token.restrictedSids, [restrictingSid]) &&
      token.integritySid === "S-1-16-4096" &&
      token.sessionId === 0 &&
      token.primary === true &&
      token.virtualized === false &&
      token.writeRestricted === false &&
      Array.isArray(token.enabledGroups) &&
      Array.isArray(token.privileges) &&
      !token.enabledGroups.length &&
      !token.privileges.length &&
      [token.tokenId, token.authenticationId].every(
        (id) => typeof id === "string" && /^[a-f0-9]{16}$/u.test(id),
      ),
  );
  return token;
}

/** Private fixed-recipe provisioning. Native setup acknowledgements are joined
 * to separately held account/token and object reads before materialization. */
export function createWindowsCaseProvisioning(state, options) {
  const context = (binding) => {
    requireObservation(
      binding.context.candidateSha === state.job.candidateSha &&
        binding.context.runId === state.plan.bootstrap.context.runId &&
        binding.context.runAttempt ===
          state.plan.bootstrap.context.runAttempt &&
        same(
          { ...binding.context, executionId: "build" },
          state.plan.bootstrap.context,
        ),
    );
    if (state.job.provenance)
      requireObservation(
        same(
          binding.context,
          nativePolicyContext(state.job, binding.context.executionId),
        ),
      );
    else
      requireObservation(
        state.job.runId === binding.context.runId &&
          state.job.runAttempt === binding.context.runAttempt,
      );
  };
  return {
    async observeBuildPolicy(binding, { commands, settlement }, { signal }) {
      state.guard(signal);
      context(binding);
      requireObservation(
        binding.template.provisioningReviewSha256 ===
          state.plan.bootstrap.reviewSha256,
      );
      const domains = [];
      for (const command of commands) {
        const policy = command.compilerPolicy;
        observationObject(policy, [
          "process",
          "outerJob",
          "defaultDacl",
          "inheritedHandles",
          "compilerJob",
        ]);
        const process = processObservation(policy.process),
          outer = jobObservation(policy.outerJob),
          inner = jobObservation(policy.compilerJob);
        requireObservation(
          sameWindowsIdentity(process.identity, command.identity) &&
            !process.retired &&
            systemIdentity(process.identity) &&
            process.integritySid === "S-1-16-16384" &&
            !process.restricting.length &&
            [outer, inner].every(
              (job) =>
                job.limitFlags === 0x2008 &&
                job.uiRestrictions === 255 &&
                job.members.some((member) =>
                  sameWindowsIdentity(member, process.identity),
                ),
            ) &&
            outer.processLimit === 32 &&
            inner.processLimit === 31 &&
            same(policy.defaultDacl, [
              { type: 0, flags: 0, mask: 0x10000000, sid: "S-1-5-18" },
            ]) &&
            same(policy.inheritedHandles, ["pipe", "pipe", "pipe"]),
        );
        const names = (await state.fs.readdir(state.directory)).filter((name) =>
          new RegExp(
            `^windows-command-${command.requestSha256}-[0-9]+\\.json$`,
            "u",
          ).test(name),
        );
        requireObservation(names.length <= 32);
        const workers = [];
        for (const name of names) {
          const record = JSON.parse(
            await state.receipt(path.join(state.directory, name)),
          );
          if (record.phase === "worker-admitted") workers.push(record);
        }
        requireObservation(
          workers.length === 1 &&
            workers[0].requestSha256 === command.requestSha256 &&
            same(workers[0].compilerPolicy, policy) &&
            sameWindowsIdentity(workers[0].worker, process.identity),
        );
        domains.push({
          userSid: process.identity.userSid,
          sessionId: process.identity.sessionId,
          integritySid: process.integritySid,
          groups: process.groups,
          restricting: process.restricting,
          privileges: process.privileges,
          defaultDacl: policy.defaultDacl,
          inheritedHandles: policy.inheritedHandles,
          outerJob: {
            limitFlags: outer.limitFlags,
            processLimit: outer.processLimit,
            uiRestrictions: outer.uiRestrictions,
          },
          compilerJob: {
            limitFlags: inner.limitFlags,
            processLimit: inner.processLimit,
            uiRestrictions: inner.uiRestrictions,
          },
        });
      }
      requireObservation(
        domains.length > 0 &&
          domains.every((domain) => same(domain, domains[0])),
      );
      const output = await options.readBuildDirectory(state.output);
      requireObservation(
        output.independent &&
          output.held &&
          output.protectedParents &&
          hash(output.daclSha256),
      );
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
            compiler: domains[0],
            output: {
              path: state.output,
              identitySha256: observationDigest(output.identity),
              daclSha256: output.daclSha256,
            },
          },
        },
      }).policy;
      const provisioning = allocation(
        binding,
        { "policy.output.identitySha256": policy.policy.output.identitySha256 },
        state.plan.bootstrap.reader.sha256,
        { commands, output, settlement },
      );
      const requestSha256 = observationDigest(policy.launch);
      return {
        provisioning,
        requestSha256,
        observed: {
          schemaVersion: 1,
          context: structuredClone(binding.context),
          templateSha256: binding.approval.manifestSha256,
          provisioningSha256: observationDigest(provisioning),
          requestSha256,
          policySha256: observationDigest(policy),
          policy,
          held: true,
          complete: true,
          independent: true,
          verifierSha256: state.plan.bootstrap.reader.sha256,
          nativeEventSha256: observationDigest({ policy, output, settlement }),
        },
      };
    },
    async provision(declared, binding, { signal, current, persist }) {
      state.guard(signal);
      context(binding);
      const setup = declared.bindings;
      const extraction = declared.id === "package.git-for-windows";
      const access = declared.id.startsWith("access.");
      const operation =
        declared.id.startsWith("files.") ||
        declared.id.startsWith("git.") ||
        declared.id === "release";
      observationObject(setup, [
        "schemaVersion",
        "authoritySha256",
        "input",
        "assets",
        "endpoints",
        ...(access ? ["access"] : []),
        ...(operation ? ["operations"] : []),
      ]);
      requireObservation(
        setup.schemaVersion === 1 &&
          setup.authoritySha256 === declared.custody.reviewSha256 &&
          setup.authoritySha256 === binding.template.provisioningReviewSha256 &&
          same(declared.custody.context, binding.context),
      );
      const input = structuredClone(setup.input),
        request = normalizeWindowsLaunch(input.request ?? input),
        root = rootFor(state, binding.context),
        nonce = observationDigest(binding.context).slice(0, 32),
        entries = decodePlan(
          await state.read(
            declared.custody.plan.path,
            declared.custody.plan.sha256,
            262144,
          ),
          declared.custody,
        );
      requireObservation(
        request.candidateSha === state.job.candidateSha &&
          request.nonce === nonce &&
          declared.custody.nonce === nonce &&
          request.custody === root + "\\custody" &&
          request.storage === root + "\\storage" &&
          request.workspace === root + "\\storage\\work" &&
          request.launcher.path === root + "\\custody\\launcher.exe" &&
          request.executable.path ===
            root +
              "\\storage\\" +
              (declared.id.startsWith("files.")
                ? "file-helper.exe"
                : declared.id.startsWith("git.")
                  ? "git-fixture.exe"
                  : extraction
                    ? "package-extractor.exe"
                    : "payload.exe") &&
          request.policy.path === root + "\\custody\\policy" &&
          request.bindings.closure === binding.context.closureSha256,
      );
      const argumentsList = extraction
        ? current.packageArguments
        : access
          ? windowsAccessArguments(request)
          : declared.id.startsWith("ownership.")
            ? windowsOwnershipArguments(declared.id, request)
            : WINDOWS_LITERAL_ARGUMENTS;
      assertNativePolicyLaunchBinding(binding, request, argumentsList);
      requireObservation(
        [
          ["sid", "policy.accountSid"],
          ["sid", "launch.request.restrictingSid"],
          ...Array.from({ length: access || operation ? 0 : 6 }, (_, i) => [
            "custody",
            `policy.objects.${i}.identitySha256`,
          ]),
        ].every(([kind, key]) =>
          binding.template.bindings.some(
            (rule) =>
              rule.kind === kind &&
              rule.paths.some((location) => location.join(".") === key),
          ),
        ),
      );
      const directories = [
        state.directory,
        root,
        request.custody,
        request.storage,
        request.workspace,
      ];
      requireObservation(
        directories.every(
          (file, i) =>
            entries[i]?.path === file && entries[i].kind === "directory",
        ),
      );
      requireObservation(
        Array.isArray(setup.assets) &&
          setup.assets.length === 2 &&
          Array.isArray(setup.endpoints) &&
          setup.endpoints.length <= 8,
      );
      const policyEndpoints = input.endpoints
          ? normalizeWindowsPolicy(input).endpoints
          : [],
        endpoints = policyEndpoints.flatMap(
          ({ family, protocol, clientPort, serverPort }) =>
            [clientPort, serverPort].map((port) => ({
              family,
              protocol,
              port,
            })),
        );
      requireObservation(same(setup.endpoints, endpoints));
      if (endpoints.length) {
        const approved = structuredClone(
          binding.template.policy.policy.endpoints,
        );
        requireObservation(
          Array.isArray(approved) && approved.length === policyEndpoints.length,
        );
        for (const [i, endpoint] of approved.entries())
          for (const key of ["clientPort", "serverPort"])
            if (endpoint[key]?.binding) {
              const rule = binding.template.bindings.find(
                  ({ id }) => id === endpoint[key].binding,
                ),
                value = policyEndpoints[i][key];
              requireObservation(
                rule?.kind === "loopback-port" &&
                  rule.paths.some((location) =>
                    same(location, ["policy", "endpoints", i, key]),
                  ) &&
                  value >= rule.minimum &&
                  value <= rule.maximum,
              );
              endpoint[key] = value;
            }
        // Check fixed tuples and approved ranges before any native reservation.
        requireObservation(isDeepStrictEqual(approved, policyEndpoints));
      }
      const targets = [request.launcher, request.executable];
      for (const [i, asset] of setup.assets.entries()) {
        observationObject(asset, ["path", "sha256", "signatureSha256"]);
        requireObservation(
          asset.sha256 === targets[i].sha256 &&
            !asset.path.toLowerCase().startsWith(root.toLowerCase() + "\\") &&
            [5 + i, 7 + i].every(
              (slot) =>
                entries[slot]?.sha256 === asset.sha256 &&
                entries[slot]?.signatureSha256 === asset.signatureSha256,
            ) &&
            entries[5 + i].path === targets[i].path &&
            entries[7 + i].path === asset.path &&
            ["helper", "image"].includes(entries[5 + i].kind) &&
            entries[5 + i].kind === entries[7 + i].kind,
        );
      }
      const accessObjects = access
        ? buildWindowsPolicy(input).manifest.objects.filter(
            ({ name }) => name !== "registry",
          )
        : [];
      const accessSlots = accessObjects.map(({ name, path: file, sha256 }) => {
        const slot = entries.findIndex((entry) => entry.path === file);
        const kind = [
          "custody",
          "storage",
          "workspace",
          "metadata",
          "checkout",
          "configuration",
          "credentials",
        ].includes(name)
          ? "directory"
          : name === "owned"
            ? "mutable"
            : name.startsWith("runtime-")
              ? entries[6].kind
              : "data";
        requireObservation(
          slot >= 0 &&
            entries[slot].kind === kind &&
            (!sha256 || entries[slot].sha256 === sha256),
        );
        return slot;
      });
      const extra = accessSlots.filter((slot) => slot >= 9);
      const operations = operation
        ? await windowsOperationPreparation(
            state,
            setup,
            binding,
            entries,
            declared.id,
          )
        : null;
      const operationSlots = new Set();
      const collectSlots = (value) => {
        if (Number.isSafeInteger(value)) operationSlots.add(value);
        else if (value && typeof value === "object")
          for (const child of Object.values(value)) collectSlots(child);
      };
      if (operations) collectSlots(operations.slots);
      let accessApproval;
      if (access) {
        observationObject(setup.access, ["approval", "runtimeAssets"]);
        observationObject(setup.access.approval, ["path", "sha256"]);
        requireObservation(setup.access.approval.sha256 === input.reviewSha256);
        const bytes = await state.read(
          setup.access.approval.path,
          setup.access.approval.sha256,
          262144,
        );
        accessApproval = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(bytes),
        );
        validateWindowsAccessApproval(accessApproval, input, binding);
        const runtimeTargets = accessSlots
          .slice(10)
          .filter((slot) => slot !== 6);
        requireObservation(
          Array.isArray(setup.access.runtimeAssets) &&
            setup.access.runtimeAssets.length === runtimeTargets.length &&
            new Set(setup.access.runtimeAssets.map(({ target }) => target))
              .size === runtimeTargets.length,
        );
        for (const asset of setup.access.runtimeAssets) {
          observationObject(asset, ["target", "source"]);
          requireObservation(
            runtimeTargets.includes(asset.target) &&
              Number.isSafeInteger(asset.source) &&
              entries[asset.source] &&
              entries[asset.target].kind === entries[asset.source].kind &&
              entries[asset.target].sha256 === entries[asset.source].sha256 &&
              entries[asset.target].signatureSha256 ===
                entries[asset.source].signatureSha256 &&
              !entries[asset.source].path
                .toLowerCase()
                .startsWith(root.toLowerCase() + "\\") &&
              input.runtime.some(
                ({ path: file, sha256 }) =>
                  file === entries[asset.target].path &&
                  sha256 === entries[asset.source].sha256,
              ),
          );
        }
      }
      // This slice creates only the fixed private launch roots and reviewed
      // images. Additional case objects require their later owning operations.
      requireObservation(
        entries.length === 9 ||
          entries
            .slice(9)
            .every(
              (entry, i) =>
                (extraction &&
                  (i + 9 === 9 ||
                    current.packageLoader.some(
                      ({ index }) => index === i + 9,
                    ))) ||
                (access && extra.includes(i + 9)) ||
                (operation &&
                  operations.assets.some(({ index }) => index === i + 9)) ||
                (operation &&
                  operations.assets.some(({ source }) => source === i + 9)) ||
                (operation && operationSlots.has(i + 9)) ||
                (access &&
                  setup.access.runtimeAssets.some(
                    ({ source }) => source === i + 9,
                  )) ||
                entry.kind === "sdk" ||
                (entry.path.startsWith(state.plan.sourceDirectory + "\\") &&
                  ["data", "helper"].includes(entry.kind)) ||
                (entry.kind === "directory" && entry.path === state.output),
            ),
      );
      const reader = state.createReader(declared.custody, {
        ...options.readerOptions,
        persist: (record) => persist({ phase: "custody", record }),
      });
      current.reader = reader;
      current.repositoryProvisioning = true;
      current.custodySlot = 2;
      current.admission = await reader.start({ signal });
      requireObservation(
        current.admission.independent &&
          current.admission.planSha256 === declared.custody.plan.sha256,
      );
      if (extraction) await reader.bindPackage();
      await reader.open(0);
      for (let i = 1; i < 5; i++)
        await reader.provisionCaseDirectory(i, i === 4 ? 3 : i === 1 ? 0 : 1);
      const assetSources = [
        ...new Set([
          7,
          8,
          ...(operations
            ? operations.assets.flatMap(({ source }) =>
                source === null ? [] : [source],
              )
            : []),
          ...(access
            ? setup.access.runtimeAssets.map(({ source }) => source)
            : []),
        ]),
      ];
      for (const source of assetSources) await reader.open(source);
      for (let i = 0; i < 2; i++) {
        await reader.copyCaseAsset(5 + i, 7 + i, i ? 3 : 2);
      }
      for (const slot of extra) {
        const object = accessObjects[accessSlots.indexOf(slot)];
        const parent = entries.findIndex(
          ({ path: file }) => file === path.dirname(object.path),
        );
        requireObservation(parent >= 0 && [2, 3, 4].includes(parent));
        await persist({
          phase: "access-object-possible",
          index: slot,
          parent,
          object,
        });
        if (
          ["metadata", "checkout", "configuration", "credentials"].includes(
            object.name,
          )
        )
          await reader.provisionCaseDirectory(slot, parent);
        else if (["owned", "pointer", "outside"].includes(object.name)) {
          const bytes = Buffer.from(
            object.name === "pointer"
              ? `gitdir: ${request.storage.replaceAll("\\", "/")}/metadata\n`
              : request.nonce,
          );
          requireObservation(entries[slot].sha256 === hashBytes(bytes));
          await reader.provisionCaseFile(
            slot,
            parent,
            bytes,
            object.name === "owned",
          );
        } else {
          const asset = setup.access.runtimeAssets.find(
            ({ target }) => target === slot,
          );
          requireObservation(asset);
          await reader.copyCaseAsset(slot, asset.source, parent);
        }
        await persist({
          phase: "access-object-held",
          index: slot,
          object: await reader.inspect(slot),
        });
      }
      if (operations)
        for (const asset of operations.assets) {
          const entry = entries[asset.index],
            parent = entries.findIndex(
              ({ path: file }) => file === path.dirname(entry.path),
            );
          await persist({ phase: "operation-asset-possible", asset, parent });
          if (entry.kind === "directory")
            await reader.provisionCaseDirectory(asset.index, parent);
          else {
            const source = entries[asset.source];
            const bytes = await state.read(source.path, source.sha256);
            if (entry.kind === "mutable")
              await reader.provisionCaseFile(
                asset.index,
                parent,
                bytes,
                entry.kind === "mutable",
              );
            else await reader.copyCaseAsset(asset.index, asset.source, parent);
          }
          await persist({
            phase: "operation-asset-held",
            asset,
            object: await reader.inspect(asset.index),
          });
        }
      current.account = await reader.provisionCaseAccount(
        2,
        observationDigest(binding.context),
      );
      await persist({
        phase: "account-acknowledged",
        account: current.account,
        helper: current.admission.helper,
      });
      for (const endpoint of setup.endpoints) {
        observationObject(endpoint, ["family", "protocol", "port"]);
        await reader.provisionCaseEndpoint(endpoint);
      }
      const native = await reader.readCase(),
        proof = await reader.verifyCaseProvisioning(2, current.account),
        actual = proof.actual;
      requireObservation(
        proof.independent &&
          sameWindowsIdentity(proof.verifier, current.admission.verifier),
      );
      observationObject(actual, [
        "accountSid",
        "restrictingSid",
        "contextSha256",
        "recordSha256",
        "token",
        "objects",
      ]);
      requireObservation(
        actual.contextSha256 === observationDigest(binding.context) &&
          hash(actual.recordSha256) &&
          actual.accountSid === current.account.accountSid &&
          actual.restrictingSid === current.account.restrictingSid &&
          actual.accountSid !== actual.restrictingSid,
      );
      tokenRead(actual.token, actual.accountSid, actual.restrictingSid);
      observationObject(native, ["token", "job", "endpoints"]);
      tokenRead(native.token, actual.accountSid, actual.restrictingSid);
      requireObservation(
        same(native.token, actual.token) &&
          same(native.endpoints, setup.endpoints),
      );
      const job = jobObservation(native.job);
      requireObservation(
        job.limitFlags === 0x2008 &&
          job.processLimit === 32 &&
          job.uiRestrictions === 255 &&
          !job.members.length,
      );
      requireObservation(
        Array.isArray(actual.objects) &&
          actual.objects.length ===
            6 + extra.length + (operations?.assets.length ?? 0) &&
          same(
            actual.objects.map(({ index }) => index),
            [
              1,
              2,
              3,
              4,
              5,
              6,
              ...extra,
              ...(operations?.assets.map(({ index }) => index) ?? []),
            ].sort((a, b) => a - b),
          ),
      );
      const values = {
        "launch.request.restrictingSid": actual.restrictingSid,
        "launch.request.nonce": nonce,
        "policy.accountSid": actual.accountSid,
        "policy.restrictingSid": actual.restrictingSid,
      };
      native.endpoints.forEach(({ port }, i) => {
        values[
          `policy.endpoints.${Math.floor(i / 2)}.${i % 2 ? "serverPort" : "clientPort"}`
        ] = port;
      });
      for (const { index, object, security } of actual.objects) {
        const file = fileObservation(object),
          independent = normalizeWindowsSecurityRead(security),
          held = await reader.inspect(index);
        requireObservation(
          same(file, held) &&
            independent.ownerSid === "S-1-5-18" &&
            independent.protectedDacl &&
            same(independent.aces, [
              { type: 0, flags: 0, mask: 0x1f01ff, sid: "S-1-5-18" },
            ]) &&
            independent.sacl.every(
              (ace) =>
                ace.type === 17 &&
                !ace.flags &&
                ace.mask === 1 &&
                ["S-1-16-8192", "S-1-16-12288", "S-1-16-16384"].includes(
                  ace.sid,
                ),
            ),
        );
        values[`policy.objects.${index - 1}.identitySha256`] =
          observationDigest(file.identity);
      }
      input.request
        ? (input.request.restrictingSid = actual.restrictingSid)
        : (input.restrictingSid = actual.restrictingSid);
      if (Object.hasOwn(input, "accountSid"))
        input.accountSid = actual.accountSid;
      if (declared.id.startsWith("files.")) {
        input.base = actual.objects.find(
          ({ index }) => index === operations.slots.base,
        )?.object.identity;
        input.root = actual.objects.find(
          ({ index }) => index === operations.slots.root,
        )?.object.identity;
        values["policy.base.identitySha256"] = observationDigest(input.base);
        values["policy.root.identitySha256"] = observationDigest(input.root);
      }
      if (access) {
        const policy = buildWindowsPolicy(input);
        input.request.policy.sha256 = policy.policySha256;
        input.request.bindings.policy = policy.compositionSha256;
      }
      const provisioning = allocation(
        binding,
        values,
        declared.custody.reader.sha256,
        { actual, native, proof },
      );
      const expected = materializeNativePolicy(
        binding.template,
        binding.approval,
        provisioning,
        binding.context,
      );
      if (endpoints.length)
        requireObservation(
          isDeepStrictEqual(
            expected.policy.policy.endpoints,
            normalizeWindowsPolicy(input).endpoints,
          ),
        );
      materializeNativePolicyBinding(
        binding,
        provisioning,
        input.request ?? input,
        argumentsList,
      );
      await persist({
        phase: "provisioning-observed",
        provisioning,
        actual,
        native,
      });
      return {
        input,
        arguments: argumentsList,
        provisioning,
        reader,
        admission: current.admission,
        actual,
        native,
        ...(extraction ? { entries, assetSources } : {}),
        ...(access
          ? { access: accessApproval, accessSlots, entries, assetSources }
          : {}),
        ...(operations ? { operations, assetSources } : {}),
      };
    },
    async bindResources(current, { signal }) {
      state.guard(signal);
      const { reader, provisioned, account } = current;
      requireObservation(
        current.repositoryProvisioning && account && provisioned,
      );
      const proof = await reader.verifyCaseProvisioning(2, account),
        native = await reader.readCase();
      requireObservation(
        proof.independent &&
          same(proof.actual, provisioned.actual) &&
          same(native, provisioned.native),
      );
      for (const { index, object } of proof.actual.objects)
        requireObservation(same(await reader.inspect(index), object));
      let accessResources;
      if (current.recipe.id.startsWith("access.")) {
        await reader.bindAccessInventory(provisioned.accessSlots);
        const helper = (name) => {
          const slot = provisioned.entries.findIndex(
            (entry) =>
              entry.kind === "helper" &&
              entry.path ===
                path.join(state.plan.sourceDirectory, name + ".exe"),
          );
          requireObservation(
            slot >= 0 &&
              provisioned.entries[slot].sha256 ===
                state.manifest.helpers.find((entry) => entry.name === name)
                  ?.sha256,
          );
          return slot;
        };
        const policy = helper("policy-helper"),
          observer = helper("observer-helper");
        for (const slot of [policy, observer]) {
          if (provisioned.assetSources.includes(slot))
            await reader.inspect(slot);
          else await reader.open(slot);
        }
        accessResources = {
          policyHandles: { helper: policy, objects: provisioned.accessSlots },
          observer,
        };
      }
      if (provisioned.operations) {
        const slots = provisioned.operations.slots;
        // Extra immutable release inputs remain held in this same custodian.
        for (
          let index = 9;
          index < provisioned.operations.entries.length;
          index++
        )
          if (
            !provisioned.operations.assets.some(
              (asset) => asset.index === index,
            ) &&
            !provisioned.assetSources.includes(index)
          )
            await reader.open(index);
        await reader.bindOperationInventory(current.recipe.id, slots);
        accessResources =
          current.recipe.group === "files"
            ? {
                transfer: { helper: 6, root: slots.root, base: slots.base },
              }
            : current.recipe.id.startsWith("git.")
              ? {
                  gitHandles: {
                    helper: 6,
                    git: slots.git,
                    metadata: slots.metadata,
                    workspace: 4,
                    hooks: slots.hooks,
                  },
                  gitPolicyHandles: {
                    helper: slots.policyHelper,
                    storage: 3,
                    workspace: 4,
                    objects: slots.policyObjects,
                  },
                  gitSlots: { metadata: slots.metadata, workspace: 4 },
                }
              : {};
      }
      return {
        objects: structuredClone(proof.actual.objects),
        accountSid: proof.actual.accountSid,
        restrictingSid: proof.actual.restrictingSid,
        job: native.job,
        endpoints: native.endpoints,
        contextSha256: proof.actual.contextSha256,
        nativeEventSha256: observationDigest({ proof, native }),
        ...accessResources,
      };
    },
    async retire(current, { signal, closeFiles = true }) {
      state.guard(signal);
      requireObservation(
        current.repositoryProvisioning &&
          !current.prepared &&
          !current.caseEffectsPossible &&
          current.reader,
      );
      await current.reader.beginCleanup({ signal });
      const account = current.account
          ? await current.reader.retireCase(current.custodySlot)
          : await current.reader.retirePartialCase(),
        custody = await current.reader.close();
      requireObservation(
        custody.status === "RETIRED" &&
          custody.independent &&
          custody.closed &&
          custody.taskRemoved,
      );
      const files = closeFiles ? await options.settleFiles() : null;
      requireObservation(
        !closeFiles ||
          (files?.status === "RETIRED" &&
            files.independent &&
            files.noLiveMembers &&
            files.taskRemoved),
      );
      current.retired = true;
      return {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({ account, custody, files }),
      };
    },
  };
}
