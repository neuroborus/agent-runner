import path from "node:path";
import {
  observationObject,
  observationDigest,
  requireObservation,
  nativePolicyLaunchData,
} from "../index.js";
import {
  purposeData,
  bindingKey,
  policyPin,
  normalizePolicyTemplate,
  materializePolicy,
  materializePolicyBinding,
  assertPolicyParameters,
  assertPolicyLaunchBinding,
  normalizePolicyBinding,
} from "./experiment-policy.js";
import {
  encodeDarwinCustodyPlan,
  normalizeDarwinCustodyInput,
} from "./custody.js";
import {
  digest,
  DARWIN_LITERAL_ARGUMENTS,
  sameDarwinIdentity,
  normalizeDarwinLaunch,
} from "./protocol.js";
import { buildDarwinPolicy } from "./policy.js";
import { darwinSystemRecipes } from "./system.js";
import {
  darwinOwnershipPolicy,
  darwinOwnershipArguments,
} from "./case-effects.js";
import { darwinGitPolicies } from "./git-effects.js";
import { darwinOperationPreparation } from "./case-operations.js";
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
    [binding.purpose === "experiment" ? "bindingSha256" : "authoritySha256"]:
      binding.template[
        binding.purpose === "experiment"
          ? "provisioningSha256"
          : "provisioningReviewSha256"
      ],
    bindings: bindingsFor(binding, values),
    held: true,
    independent: true,
    verifierSha256,
    nativeEventSha256: observationDigest(native),
  };
}

/** Expected declarations for the existing finite recipes. This creates no
 * provisioning or installed-policy proof; those require the native reader below. */
export function darwinExperimentCaseDeclarations(declarations) {
  const fixed = darwinSystemRecipes().filter(({ id }) => id !== "build"),
    legacy = fixed.filter(
      (recipe) =>
        recipe.group === "ownership" || recipe.id.startsWith("access."),
    ),
    recipes = declarations?.length === legacy.length ? legacy : fixed;
  requireObservation(
    Array.isArray(declarations) &&
      declarations.length === recipes.length &&
      new Set(declarations.map((entry) => entry.id)).size === recipes.length,
  );
  const cases = recipes.map((recipe) => {
    const declared = declarations.find((entry) => entry.id === recipe.id);
    observationObject(declared, ["id", "custody", "bindings"]);
    const custody = normalizeDarwinCustodyInput(declared.custody, "experiment"),
      setup = declared.bindings;
    observationObject(setup, [
      "schemaVersion",
      "bindingSha256",
      "uid",
      "gid",
      "input",
      "assets",
      ...(recipe.id.startsWith("access.") ? ["access"] : []),
      ...(["files", "release"].includes(recipe.group) ||
      recipe.id.startsWith("git.")
        ? ["operations"]
        : []),
    ]);
    const request = normalizeDarwinLaunch(
      setup.input.request ?? setup.input,
      "experiment",
    );
    requireObservation(
      setup.schemaVersion === 1 &&
        custody.context.executionId === recipe.id &&
        custody.context.candidateSha === request.candidateSha &&
        custody.context.closureSha256 === request.bindings.closure &&
        setup.bindingSha256 === custody.bindingSha256 &&
        setup.uid === request.uid &&
        setup.gid === request.gid,
    );
    return structuredClone(declared);
  });
  requireObservation(
    new Set(cases.map((entry) => entry.bindings.uid)).size === cases.length &&
      new Set(cases.map((entry) => entry.bindings.gid)).size === cases.length &&
      cases.every((entry) =>
        same(
          { ...entry.custody.context, executionId: "build" },
          { ...cases[0].custody.context, executionId: "build" },
        ),
      ),
  );
  const policyBindings = cases.map((declared) => {
    const setup = declared.bindings,
      request = setup.input.request ?? setup.input,
      access = declared.id.startsWith("access.")
        ? buildDarwinPolicy(setup.input)
        : null,
      args = declared.id.startsWith("ownership.")
        ? darwinOwnershipArguments(declared.id, request)
        : DARWIN_LITERAL_ARGUMENTS,
      policy = {
        launch: nativePolicyLaunchData(request, args),
        policy: access
          ? Object.fromEntries(
              Object.entries(access.value).filter(([key]) => key !== "request"),
            )
          : declared.id.startsWith("files.")
            ? {
                kind: "darwin-files",
                base: { identitySha256: null },
                root: { identitySha256: null },
                authority: { uid: 0, gid: 0, sandboxed: false },
              }
            : declared.id.startsWith("git.")
              ? {
                  kind: "darwin-git",
                  gitSha256: setup.input.git.sha256,
                  metadata: { identitySha256: null },
                  hooks: { identitySha256: null },
                  authority: { uid: 0, gid: 0, sandboxed: false },
                  profiles:
                    declared.id === "git.ordinary"
                      ? darwinGitPolicies(setup.input).map(
                          ({ profile, bytes }) => ({
                            profile,
                            seatbeltSha256: digest(bytes),
                          }),
                        )
                      : [],
                }
              : declared.id === "release"
                ? {
                    kind: "darwin-runtime",
                    inventorySha256: declared.custody.plan.sha256,
                  }
                : {
                    kind: "darwin-ownership",
                    seatbeltSha256: digest(darwinOwnershipPolicy(request)),
                    processLimit: 32,
                  },
      },
      bindings = [];
    const bind = (id, kind, location, value) => {
      let parent = policy;
      for (const part of location.slice(0, -1)) parent = parent[part];
      parent[location.at(-1)] = { binding: id };
      bindings.push({
        id,
        kind,
        paths: [location],
        minimum: kind === "custody" ? null : value,
        maximum: kind === "custody" ? null : value,
      });
    };
    for (const key of ["uid", "gid", "nonce"])
      bind(
        key,
        key === "nonce" ? "custody" : key,
        ["launch", "request", key],
        request[key],
      );
    for (const key of declared.id.startsWith("files.")
      ? ["base", "root"]
      : declared.id.startsWith("git.")
        ? ["metadata", "hooks"]
        : [])
      bind(key, "custody", ["policy", key, "identitySha256"], null);
    if (access)
      access.value.endpoints.forEach((endpoint, i) => {
        for (const key of ["clientPort", "serverPort"])
          bind(
            `port-${i}-${key === "clientPort" ? "client" : "server"}`,
            "loopback-port",
            ["policy", "endpoints", i, key],
            endpoint[key],
          );
      });
    return normalizePolicyBinding({
      purpose: "experiment",
      context: declared.custody.context,
      template: {
        purpose: "experiment",
        schemaVersion: 1,
        candidateSha: request.candidateSha,
        platform: "darwin",
        sourceSha256: request.bindings.source,
        provisioningSha256: setup.bindingSha256,
        policy,
        bindings,
      },
    });
  });
  return { cases, policyBindings };
}

/** Private composition for fixed system recipes. Purpose-bound records contain data;
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
        binding.purpose !== "experiment" &&
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
      const policy = normalizePolicyTemplate({
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
          templateSha256: policyPin(binding),
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
      await state.admit(signal);
      const setup = declared.bindings,
        key =
          binding.purpose === "experiment"
            ? "bindingSha256"
            : "authoritySha256";
      requireObservation(
        (declared.custody.purpose ?? "reviewed") ===
          (binding.purpose ?? "reviewed"),
      );
      observationObject(setup, [
        "schemaVersion",
        key,
        "uid",
        "gid",
        "input",
        "assets",
        ...(Object.hasOwn(setup, "access") ? ["access"] : []),
        ...(Object.hasOwn(setup, "operations") ? ["operations"] : []),
      ]);
      requireObservation(
        setup.schemaVersion === 1 &&
          setup[key] === declared.custody[bindingKey(binding)] &&
          setup[key] ===
            binding.template[
              binding.purpose === "experiment"
                ? "provisioningSha256"
                : "provisioningReviewSha256"
            ] &&
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
          kind:
            i === 2
              ? "data"
              : i === 1 &&
                  (declared.id.startsWith("files.") ||
                    declared.id === "git.fixed")
                ? "helper"
                : "image",
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
        entries.push({
          kind:
            i === 2
              ? "data"
              : i === 1 &&
                  (declared.id.startsWith("files.") ||
                    declared.id === "git.fixed")
                ? "helper"
                : "image",
          ...asset,
        });
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
      const operations = setup.operations
        ? await darwinOperationPreparation(
            state,
            setup,
            binding,
            entries,
            declared.id,
          )
        : null;
      requireObservation(!(access && operations));
      if (access) entries.push(...access.entries.slice(entries.length));
      if (operations) entries.push(...operations.entries.slice(entries.length));
      const planBytes = encodeDarwinCustodyPlan({
        ...purposeData(binding),
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
        assertPolicyLaunchBinding(binding, request, argumentsList);
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
      await state.admit(signal);
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
      await state.admit(signal);
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
      if (operations) {
        for (const [i, asset] of operations.assets.entries()) {
          const index = i + 12;
          if (asset.source !== null)
            await reader.copyCaseAsset(index, asset.source);
          else if (
            asset.kind === "authority" &&
            asset.path.startsWith(root + "/")
          )
            await reader.provisionCaseDirectory(index);
          else await reader.open(index);
        }
        if (declared.id.startsWith("files.")) {
          requireObservation(input.base === null && input.root === null);
          input.base = (await reader.inspect(operations.slots.base)).identity;
          input.root = (await reader.inspect(operations.slots.root)).identity;
          values["policy.base.identitySha256"] = digest(input.base);
          values["policy.root.identitySha256"] = digest(input.root);
        }
        if (declared.id.startsWith("git.")) {
          values["policy.metadata.identitySha256"] = digest(
            (await reader.inspect(operations.slots.metadata)).identity,
          );
          values["policy.hooks.identitySha256"] = digest(
            (await reader.inspect(operations.slots.hooks)).identity,
          );
        }
      }
      const allocation = provisioning(
        binding,
        values,
        declared.custody.reader.sha256,
        { admission, actual },
      );
      materializePolicy(binding, allocation);
      if (declared.id !== "release") {
        materializePolicyBinding(binding, allocation, request, argumentsList);
        if (!declared.id.startsWith("ownership.") && !operations)
          assertPolicyParameters(
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
      if (operations && declared.id.startsWith("git.")) {
        for (const [i, asset] of operations.assets.entries())
          if (
            asset.source !== null &&
            asset.kind === "data" &&
            (asset.path.startsWith(input.metadata + "/") ||
              asset.path.includes("/storage/control/"))
          )
            await reader.closeHeld(i + 12);
      }
      return {
        ...(operations ? { operations } : {}),
        ...(access ? { access } : {}),
        input,
        arguments: argumentsList,
        provisioning: allocation,
        reader,
        admission,
      };
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
