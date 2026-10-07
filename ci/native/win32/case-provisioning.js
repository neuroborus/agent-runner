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
import { normalizeWindowsPolicy } from "./policy.js";
import { windowsOwnershipArguments } from "./case-effects.js";
import { normalizeWindowsSecurityRead } from "./effective-protocol.js";

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
      observationObject(setup, [
        "schemaVersion",
        "authoritySha256",
        "input",
        "assets",
        "endpoints",
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
          request.executable.path === root + "\\storage\\payload.exe" &&
          request.policy.path === root + "\\custody\\policy" &&
          request.bindings.closure === binding.context.closureSha256,
      );
      assertNativePolicyLaunchBinding(
        binding,
        request,
        declared.id.startsWith("ownership.")
          ? windowsOwnershipArguments(declared.id, request)
          : WINDOWS_LITERAL_ARGUMENTS,
      );
      requireObservation(
        [
          ["sid", "policy.accountSid"],
          ["sid", "launch.request.restrictingSid"],
          ...Array.from({ length: 6 }, (_, i) => [
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
      // This slice creates only the fixed private launch roots and reviewed
      // images. Additional case objects require their later owning operations.
      requireObservation(
        entries.length === 9 ||
          entries
            .slice(9)
            .every(
              (entry) =>
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
      await reader.open(0);
      for (let i = 1; i < 5; i++)
        await reader.provisionCaseDirectory(i, i === 4 ? 3 : i === 1 ? 0 : 1);
      for (let i = 0; i < 2; i++) {
        await reader.open(7 + i);
        await reader.copyCaseAsset(5 + i, 7 + i, i ? 3 : 2);
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
          actual.objects.length === 6 &&
          same(
            actual.objects.map(({ index }) => index),
            [1, 2, 3, 4, 5, 6],
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
        declared.id.startsWith("ownership.")
          ? windowsOwnershipArguments(declared.id, input.request ?? input)
          : WINDOWS_LITERAL_ARGUMENTS,
      );
      await persist({
        phase: "provisioning-observed",
        provisioning,
        actual,
        native,
      });
      return {
        input,
        arguments: declared.id.startsWith("ownership.")
          ? windowsOwnershipArguments(declared.id, input.request ?? input)
          : WINDOWS_LITERAL_ARGUMENTS,
        provisioning,
        reader,
        admission: current.admission,
        actual,
        native,
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
      return {
        objects: structuredClone(proof.actual.objects),
        accountSid: proof.actual.accountSid,
        restrictingSid: proof.actual.restrictingSid,
        job: native.job,
        endpoints: native.endpoints,
        contextSha256: proof.actual.contextSha256,
        nativeEventSha256: observationDigest({ proof, native }),
      };
    },
    async retire(current, { signal }) {
      state.guard(signal);
      requireObservation(
        current.repositoryProvisioning &&
          current.account &&
          !current.prepared &&
          !current.caseEffectsPossible &&
          current.reader,
      );
      await current.reader.beginCleanup({ signal });
      const account = await current.reader.retireCase(current.custodySlot),
        custody = await current.reader.close();
      requireObservation(
        custody.status === "RETIRED" &&
          custody.independent &&
          custody.closed &&
          custody.taskRemoved,
      );
      const files = await options.settleFiles();
      requireObservation(
        files?.status === "RETIRED" &&
          files.independent &&
          files.noLiveMembers &&
          files.taskRemoved,
      );
      return {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({ account, custody, files }),
      };
    },
  };
}
