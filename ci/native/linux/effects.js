import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  observationObject,
  observationDigest,
  requireObservation,
  normalizeNativePolicyBinding,
  materializeNativePolicy,
  normalizeNativePolicyTemplate,
  normalizeNativeJob,
  NATIVE_EFFECT_CLASSES,
  recoverPrerequisiteTransport,
} from "../index.js";
import { digest, readProtectedEvidence, protectedReceipt } from "./inspect.js";
import { linuxPreparationVersion } from "./preparation.js";
import { loadPreparedLinuxReviewedInputs } from "./reviewed-inputs.js";
import {
  buildWithReceipts,
  runLinuxBuildCommand,
  freshVerifier,
  runLinuxOwnershipProofs,
} from "./proof.js";
import { verifyPreparedLinuxBuild, rejoinPreparedBuild } from "./ci.js";
import { linuxSystemRecipes } from "./composition.js";
import { createLinuxReleaseReaders } from "./release-readers.js";
import { ACCESS_PROFILES } from "./profiles.js";
import { runLinuxFileProofs } from "./files-cases.js";

const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;
const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});

async function sealedRead(file, maximum = 134217728, fs = filesystem) {
  requireObservation((await fs.realpath(file)) === file);
  const handle = await fs.open(
    file,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat({ bigint: true });
    requireObservation(
      before.isFile() &&
        before.nlink === 1n &&
        before.size > 0n &&
        before.size <= BigInt(maximum) &&
        (before.mode & 0o6022n) === 0n,
    );
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true }),
      named = await fs.lstat(file, { bigint: true });
    requireObservation(
      offset === Number(before.size) &&
        named.isFile() &&
        [
          "dev",
          "ino",
          "size",
          "mode",
          "nlink",
          "uid",
          "gid",
          "mtimeNs",
          "ctimeNs",
        ].every(
          (key) => before[key] === after[key] && before[key] === named[key],
        ),
    );
    return bytes.subarray(0, offset);
  } finally {
    await handle.close();
  }
}

function context(input, options) {
  const value = structuredClone({
      job: input.job,
      manifest: input.manifest,
      output: input.output,
      helpers: input.helpers,
      directory: input.directory,
      preparation: input.preparation,
      prerequisiteCustody: input.prerequisiteCustody,
    }),
    env = { ...(options.env ?? process.env) };
  requireObservation(
    value.job.platform === "linux" &&
      /^[a-f0-9]{40}$/u.test(value.job.candidateSha) &&
      value.manifest.candidateSha === value.job.candidateSha &&
      value.manifest.platform === "linux",
  );
  const output = value.output ?? value.helpers,
    directory = value.directory ?? path.dirname(output);
  requireObservation(
    path.isAbsolute(output) &&
      path.normalize(output) === output &&
      path.isAbsolute(directory) &&
      path.normalize(directory) === directory &&
      output === path.join(directory, "platform-build"),
  );
  const fs = options.fs ?? filesystem,
    read = options.read ?? ((file, maximum) => sealedRead(file, maximum, fs));
  const ownerUid = options.ownerUid ?? (() => process.getuid());
  const protect =
    options.protect ??
    (async (file) => {
      // The execution identity must be unable to change the image or an ancestor.
      // Use raw filesystem edges here so tests execute the same admission owner.
      for (let current = file; ; current = path.dirname(current)) {
        requireObservation((await fs.realpath(current)) === current);
        try {
          await fs.access(current, constants.W_OK);
          throw new Error("Writable Linux tool or ancestor");
        } catch (error) {
          if (!["EACCES", "EPERM", "EROFS"].includes(error.code)) throw error;
        }
        if (current === "/") break;
      }
    });
  const write = (name, data) =>
    fs.writeFile(path.join(directory, name), JSON.stringify(data) + "\n", {
      flag: "wx",
      mode: 0o400,
    });
  const guard = (signal) =>
    requireObservation(
      !signal?.aborted &&
        env.CI === "true" &&
        env.GITHUB_ACTIONS === "true" &&
        env.ImageOS === "ubuntu24",
    );
  const bootstrap = async (signal) => {
    guard(signal);
    requireObservation(
      typeof env.RUNNER_TEMP === "string" &&
        directory.startsWith(env.RUNNER_TEMP + "/") &&
        (await fs.realpath(env.RUNNER_TEMP)) === env.RUNNER_TEMP,
    );
    for (
      let parent = directory;
      parent !== env.RUNNER_TEMP;
      parent = path.dirname(parent)
    ) {
      const metadata = await fs.lstat(parent);
      requireObservation(
        (await fs.realpath(parent)) === parent &&
          metadata.isDirectory() &&
          !metadata.isSymbolicLink() &&
          metadata.uid === ownerUid() &&
          (metadata.mode & 0o777) === 0o700,
      );
    }
    // Read the independently published legacy manifest and authenticated Noble
    // receipt before any compiler/controller admission. Neither is native GO.
    const reviewed = await (
      options.loadReviewed ?? loadPreparedLinuxReviewedInputs
    )(
      env.NATIVE_REVIEWED_INPUT_DIRECTORY,
      value.job.candidateSha,
      env.NATIVE_LINUX_REVIEW_SHA256,
      { fs, ownerUid },
    );
    requireObservation(
      reviewed.build &&
        reviewed.release &&
        observationDigest(reviewed.build) ===
          observationDigest(value.manifest.linuxBuild),
    );
    const receipt = JSON.parse(
      await (options.readEvidence ?? readProtectedEvidence)(
        path.join(directory, "linux-preparation.json"),
        { fs, ownerUid },
      ),
    );
    const version = linuxPreparationVersion(receipt, value.job.candidateSha);
    const expected = reviewed.release.components.find(
      (entry) => entry.name === "bubblewrap",
    );
    requireObservation(
      expected?.sha256 === version.sha256 &&
        expected.version === version.version,
    );
    await protect("/usr/bin/bwrap");
    requireObservation(
      digest(await read("/usr/bin/bwrap")) === version.sha256 &&
        (!value.job.versions?.some((entry) => entry.name === "bubblewrap") ||
          value.job.versions.some(
            (entry) =>
              entry.name === "bubblewrap" &&
              entry.sha256 === version.sha256 &&
              entry.version === version.version,
          )),
    );
    guard(signal);
    return {
      reviewed,
      version,
      nativeEventSha256: observationDigest({ reviewed, receipt }),
    };
  };
  return {
    ...value,
    env,
    output,
    directory,
    fs,
    read,
    write,
    guard,
    bootstrap,
    protect,
    ownerUid,
  };
}

/** Construction captures reviewed inputs only. Explicit operations own every
 * effect and leave immutable intent when execution or settlement is uncertain. */
export function createLinuxBuildEffects(input, options = {}) {
  const state = context(input, options),
    run = options.runCommand ?? runLinuxBuildCommand;
  return {
    bootstrap: state.bootstrap,
    async run(request, { signal } = {}) {
      observationObject(request, [
        "candidateSha",
        "platform",
        "toolSha256",
        "file",
        "args",
        "cwd",
        "env",
        "deadlineMs",
      ]);
      const tool = state.manifest.tools.find(
        (entry) => entry.path === request.file,
      );
      requireObservation(
        request.candidateSha === state.job.candidateSha &&
          request.platform === "linux" &&
          request.cwd === state.output &&
          tool?.sha256 === request.toolSha256 &&
          [
            "/usr/bin/x86_64-linux-gnu-gcc-13",
            "/usr/bin/x86_64-linux-gnu-ld.bfd",
          ].includes(request.file) &&
          observationDigest(request.args) ===
            observationDigest(["--version"]) &&
          observationDigest(request.env) ===
            observationDigest({
              CI: "true",
              GITHUB_ACTIONS: "true",
              LANG: "C",
            }) &&
          Number.isSafeInteger(request.deadlineMs) &&
          request.deadlineMs > 0 &&
          request.deadlineMs <= 30000,
      );
      await state.bootstrap(signal);
      await state.protect(request.file);
      requireObservation(
        digest(await state.read(request.file)) === tool.sha256,
      );
      const id = observationDigest(request);
      await state.write(`linux-command-${id}-intent.json`, {
        candidateSha: request.candidateSha,
        requestSha256: id,
        status: "POSSIBLE",
      });
      state.guard(signal);
      const result = await run(structuredClone(request), {
        signal,
        env: state.env,
        platform: options.platform ?? process.platform,
        fs: state.fs,
        start: options.start,
        receiptOptions: { fs: state.fs, ownerUid: state.ownerUid },
        verifierOptions: { executeFile: options.executeFile },
      });
      requireObservation(
        result.requestSha256 === id &&
          result.toolSha256 === tool.sha256 &&
          retired(result.settlement),
      );
      await state.write(`linux-command-${id}-result.json`, {
        requestSha256: id,
        toolSha256: result.toolSha256,
        nativeEventSha256: result.nativeEventSha256,
        settlement: result.settlement,
        ...(result.receipt
          ? {
              receiptSha256: observationDigest(result),
              receipt: result.receipt,
            }
          : {}),
      });
      return result;
    },
    async build({ signal } = {}) {
      const bootstrap = await state.bootstrap(signal);
      const request = {
        candidateSha: state.job.candidateSha,
        buildSha256: observationDigest(state.manifest.linuxBuild),
        bootstrapSha256: bootstrap.nativeEventSha256,
      };
      await state.write("linux-build-intent.json", {
        ...request,
        status: "POSSIBLE",
      });
      await state.fs.mkdir(path.join(state.output, "evidence"), {
        mode: 0o700,
      });
      state.guard(signal);
      const result = await (options.compile ?? buildWithReceipts)(
        state.job,
        state.output,
        { directory: state.output, launcher: "/usr/bin/bwrap" },
        state.manifest.linuxBuild,
      );
      requireObservation(retired(result.settlement));
      await state.fs.writeFile(
        path.join(state.output, "prepared-build.json"),
        JSON.stringify(result),
        { flag: "wx", mode: 0o400 },
      );
      return result;
    },
  };
}

function policyProof(binding, actual, verifierSha256) {
  const { template, approval, context } = normalizeNativePolicyBinding(binding);
  const policy = normalizeNativePolicyTemplate({
    ...template,
    policy: actual.policy,
    bindings: [],
  }).policy;
  const provisioning = {
    schemaVersion: 1,
    context,
    authoritySha256: template.provisioningReviewSha256,
    bindings: template.bindings.map((rule) => {
      const values = rule.paths.map((parts) =>
        parts.reduce((value, part) => value?.[part], policy),
      );
      requireObservation(values.every((value) => value === values[0]));
      return { id: rule.id, kind: rule.kind, value: values[0] };
    }),
    held: true,
    independent: true,
    verifierSha256,
    nativeEventSha256: actual.nativeEventSha256,
  };
  const expected = materializeNativePolicy(
    template,
    approval,
    provisioning,
    context,
  );
  const requestSha256 = observationDigest(policy.launch);
  return {
    provisioning,
    requestSha256,
    observed: {
      schemaVersion: 1,
      context,
      templateSha256: expected.templateSha256,
      provisioningSha256: expected.provisioningSha256,
      requestSha256,
      policySha256: observationDigest(policy),
      policy,
      held: true,
      complete: true,
      independent: true,
      verifierSha256,
      nativeEventSha256: actual.nativeEventSha256,
    },
  };
}

/** Fixed reference and release recipes reuse the historical engines. Recovery
 * reads protected admission ledgers even when final preparation never existed. */
export function createLinuxSystemEffects(input, options = {}) {
  const state = context(input, options);
  const receiptOptions = { fs: state.fs, ownerUid: state.ownerUid },
    verifierOptions = { executeFile: options.executeFile },
    readReceipt =
      options.readReceipt ??
      ((file, sha256) => protectedReceipt(file, sha256, receiptOptions)),
    verify =
      options.verify ??
      ((file, sha256) => freshVerifier(file, sha256, verifierOptions));
  let firstFailure;
  const fail = (error) => {
    firstFailure ??= error;
  };
  const verifyBuild = async (
    preparation,
    { signal, verificationPending = false } = {},
  ) => {
    if (firstFailure) throw firstFailure;
    try {
      const bootstrap = await state.bootstrap(signal);
      const result = await (options.verifyPrepared ?? verifyPreparedLinuxBuild)(
        state.job,
        { read: state.read, manifest: state.manifest },
        state.output,
        preparation,
        {
          ...receiptOptions,
          verifierOptions,
          readReceipt,
          verify,
          verificationPending,
          launcherSha256: bootstrap.version.sha256,
        },
      );
      requireObservation(
        result.build?.candidateSha === state.job.candidateSha &&
          retired(result.settlement),
      );
      state.guard(signal);
      return {
        status: "OBSERVED",
        candidateSha: state.job.candidateSha,
        preparationSha256: observationDigest(preparation),
        nativeEventSha256: observationDigest(result),
        independent: true,
        settlement: result.settlement,
        build: result.build,
      };
    } catch (error) {
      fail(error);
      throw firstFailure;
    }
  };
  const settle = async (signal) => {
    const observed = [],
      pending = [];
    const scan = async (directory) => {
      const stat = await state.fs.lstat(directory);
      requireObservation(
        stat.isDirectory() &&
          !stat.isSymbolicLink() &&
          stat.uid === state.ownerUid() &&
          (stat.mode & 0o777) === 0o700 &&
          (await state.fs.realpath(directory)) === directory,
      );
      const entries = await state.fs.readdir(directory, {
        withFileTypes: true,
      });
      requireObservation(entries.length <= 512);
      for (const entry of entries) {
        state.guard(signal);
        const file = path.join(directory, entry.name);
        requireObservation(!entry.isSymbolicLink());
        if (
          /^(?:command-[01]|argv|cancel|owner-loss|supervisor-loss|launcher-loss|file-helper-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\.json$/u.test(
            entry.name,
          ) ||
          ACCESS_PROFILES.some((profile) => entry.name === profile + ".json")
        ) {
          const bytes = await state.read(file, 1048576),
            sha256 = digest(bytes);
          const receipt = await readReceipt(file, sha256);
          requireObservation(receipt.candidateSha === state.job.candidateSha);
          const result = await verify(file, sha256);
          observed.push({ file, sha256, receipt, result });
          requireObservation(observed.length <= 512);
        }
        if (/^command-[01]-possible\.json$/u.test(entry.name)) {
          const intent = JSON.parse(await state.read(file, 1048576));
          observationObject(intent, ["candidateSha", "nonce", "policyDigest"]);
          requireObservation(
            intent.candidateSha === state.job.candidateSha &&
              /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(
                intent.nonce,
              ) &&
              /^[a-f0-9]{64}$/u.test(intent.policyDigest),
          );
          pending.push({
            file: path.join(
              directory,
              entry.name.replace("-possible.json", ".json"),
            ),
            intent,
          });
        }
      }
    };
    try {
      state.guard(signal);
      const roots = await state.fs.readdir(state.output);
      for (const name of roots.filter(
        (name) => name === "build" || /^command-[a-f0-9]{64}$/u.test(name),
      ))
        await scan(path.join(state.output, name));
      if (roots.includes("linux")) {
        const root = path.join(state.output, "linux"),
          stat = await state.fs.lstat(root);
        requireObservation(
          stat.isDirectory() &&
            !stat.isSymbolicLink() &&
            (await state.fs.realpath(root)) === root,
        );
        await scan(path.join(root, "evidence"));
      }
      // Outer write-ahead ledgers exclude a missing or partial command receipt.
      requireObservation(
        pending.every(({ file, intent }) =>
          observed.some(
            (entry) =>
              entry.file === file &&
              entry.receipt.nonce === intent.nonce &&
              entry.receipt.policyDigest === intent.policyDigest,
          ),
        ),
      );
      const intents = await state.fs.readdir(state.directory);
      for (const name of intents.filter((name) =>
        /^linux-command-[a-f0-9]{64}-intent\.json$/u.test(name),
      )) {
        const id = name.match(
          /^linux-command-([a-f0-9]{64})-intent\.json$/u,
        )[1];
        const intent = JSON.parse(
          await state.read(path.join(state.directory, name), 1048576),
        );
        observationObject(intent, ["candidateSha", "requestSha256", "status"]);
        requireObservation(
          intent.candidateSha === state.job.candidateSha &&
            intent.requestSha256 === id &&
            intent.status === "POSSIBLE",
        );
        // Each standalone command has exactly one receipt in its request directory.
        const command = observed.find(
          (entry) =>
            entry.file ===
            path.join(state.output, `command-${id}`, "command-0.json"),
        );
        requireObservation(
          command?.receipt.policyDigest === id &&
            state.manifest.tools.some(
              (tool) => tool.sha256 === command.receipt.executableDigest,
            ),
        );
        let bytes;
        try {
          bytes = await state.read(
            path.join(state.directory, name.replace("-intent", "-result")),
            1048576,
          );
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
        // A lost result cannot manufacture version/build success. Independent
        // namespace retirement still works from the exact persisted intent.
        if (bytes) {
          const result = JSON.parse(bytes);
          observationObject(result, [
            "requestSha256",
            "toolSha256",
            "nativeEventSha256",
            "settlement",
            ...(Object.hasOwn(result, "receipt")
              ? ["receiptSha256", "receipt"]
              : []),
          ]);
          requireObservation(
            retired(result.settlement) &&
              result.requestSha256 === id &&
              command.receipt.executableDigest === result.toolSha256,
          );
          if (Object.hasOwn(result, "receipt")) {
            observationObject(result.receipt, ["file", "sha256"]);
            requireObservation(
              result.receipt.file === command.file &&
                result.receipt.sha256 === command.sha256 &&
                /^[a-f0-9]{64}$/u.test(result.receiptSha256),
            );
          }
        }
      }
      const buildIntent = intents.includes("linux-build-intent.json");
      if (buildIntent) {
        const intent = JSON.parse(
          await state.read(
            path.join(state.directory, "linux-build-intent.json"),
            1048576,
          ),
        );
        observationObject(intent, [
          "candidateSha",
          "buildSha256",
          "bootstrapSha256",
          "status",
        ]);
        const bootstrap = await state.bootstrap(signal);
        requireObservation(
          intent.candidateSha === state.job.candidateSha &&
            intent.status === "POSSIBLE" &&
            intent.buildSha256 ===
              observationDigest(state.manifest.linuxBuild) &&
            intent.bootstrapSha256 === bootstrap.nativeEventSha256,
        );
        for (const index of [0, 1]) {
          const file = path.join(
            state.output,
            "build",
            `command-${index}.json`,
          );
          const command = observed.find((entry) => entry.file === file);
          requireObservation(
            command?.receipt.caseId === "argv" &&
              command.receipt.executableDigest === bootstrap.version.sha256 &&
              pending.some((entry) => entry.file === file),
          );
        }
      }
      const reference = intents.filter((name) =>
        /^linux-reference-[0-9]+\.json$/u.test(name),
      );
      if (reference.length) {
        const latest = normalizeNativeJob(
          JSON.parse(
            await state.read(
              path.join(
                state.directory,
                reference
                  .sort(
                    (a, b) =>
                      Number(a.match(/[0-9]+/u)[0]) -
                      Number(b.match(/[0-9]+/u)[0]),
                  )
                  .at(-1),
              ),
              1048576,
            ),
          ),
        );
        requireObservation(
          latest.schemaVersion === 5 &&
            latest.candidateSha === state.job.candidateSha &&
            latest.platform === "linux" &&
            observationDigest(latest.provenance) ===
              observationDigest(state.job.provenance) &&
            Object.values(latest.admissions).every(
              (entry) =>
                entry.admission === "not-started" || retired(entry.settlement),
            ),
        );
        if (latest.admissions["file-build"].admission === "possible")
          requireObservation(buildIntent);
        for (const [name, effects] of [
          ["ownership", ["ownership", "access"]],
          ["files", ["file-helper"]],
        ]) {
          if (
            !effects.some(
              (id) => latest.admissions[id].admission === "possible",
            )
          )
            continue;
          const bundle = JSON.parse(
            await state.read(
              path.join(
                state.directory,
                `linux-reference-${name}-receipts.json`,
              ),
              1048576,
            ),
          );
          observationObject(bundle, ["candidateSha", "provenance", "receipts"]);
          requireObservation(
            bundle.candidateSha === state.job.candidateSha &&
              observationDigest(bundle.provenance) ===
                observationDigest(latest.provenance) &&
              Array.isArray(bundle.receipts) &&
              bundle.receipts.length > 0 &&
              bundle.receipts.length <= 512,
          );
          for (const receipt of bundle.receipts) {
            observationObject(receipt, ["file", "sha256"]);
            requireObservation(
              observed.some(
                (entry) =>
                  entry.file === receipt.file &&
                  entry.sha256 === receipt.sha256,
              ),
            );
          }
        }
      }
      requireObservation(observed.every((entry) => retired(entry.result)));
      return {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest(observed),
      };
    } catch (error) {
      fail(error);
      return {
        ...retained(),
        nativeEventSha256: observationDigest({
          candidateSha: state.job.candidateSha,
          retained: true,
        }),
      };
    }
  };
  let referenceSequence = 0,
    referenceSignal;
  const saveReceipts = (name, receipts) => {
    state.guard(referenceSignal);
    requireObservation(Array.isArray(receipts) && receipts.length <= 512);
    for (const receipt of receipts) {
      observationObject(receipt, ["file", "sha256"]);
      requireObservation(
        typeof receipt.file === "string" &&
          receipt.file.startsWith(state.output + "/") &&
          path.normalize(receipt.file) === receipt.file &&
          /^[a-f0-9]{64}$/u.test(receipt.sha256),
      );
    }
    return state.write(`linux-reference-${name}-receipts.json`, {
      candidateSha: state.job.candidateSha,
      provenance: state.job.provenance ?? null,
      receipts,
    });
  };
  return {
    verifyBuild,
    persistReference: (value) => {
      state.guard(referenceSignal);
      return state.write(`linux-reference-${referenceSequence++}.json`, value);
    },
    async prepare(recipe, { signal, policyBinding, recordPolicy } = {}) {
      const fixed = linuxSystemRecipes().find(
        (entry) => entry.id === recipe.id,
      );
      requireObservation(
        fixed &&
          fixed.group === recipe.group &&
          policyBinding &&
          typeof recordPolicy === "function",
      );
      await verifyBuild(state.preparation, { signal });
      const binding = normalizeNativePolicyBinding(policyBinding);
      requireObservation(
        binding.context.candidateSha === state.job.candidateSha &&
          binding.context.platform === "linux" &&
          binding.context.executionId === recipe.id,
      );
      const source = fileURLToPath(
        new URL(
          recipe.group === "reference" ? "./proof.js" : "./release-readers.js",
          import.meta.url,
        ),
      );
      const verifierSha256 = digest(await state.read(source, 1048576));
      requireObservation(
        state.manifest.inputs.some(
          (entry) => entry.path === source && entry.sha256 === verifierSha256,
        ),
      );
      await state.write(`linux-${recipe.group}-intent.json`, {
        candidateSha: state.job.candidateSha,
        executionId: recipe.id,
        templateSha256: binding.approval.manifestSha256,
        status: "POSSIBLE",
      });
      const admitted = {
        independent: true,
        reviewSha256: recipe.reviewSha256,
        templateSha256: binding.approval.manifestSha256,
      };
      if (recipe.group === "reference") {
        referenceSignal = signal;
        return {
          ...admitted,
          options: {
            env: state.env,
            loadInputs: () =>
              state.bootstrap(signal).then((value) => value.reviewed),
            build: async (reference, referenceDirectory, fixture, pins) => {
              state.guard(signal);
              return rejoinPreparedBuild(
                state.job,
                { read: state.read, manifest: state.manifest },
                state.output,
                state.preparation,
                reference,
                referenceDirectory,
                fixture,
                pins,
              );
            },
            ownership: async (job, directory, hooks) => {
              state.guard(signal);
              const result = await (
                options.ownership ?? runLinuxOwnershipProofs
              )(job, directory, {
                ...hooks,
                signal,
                onPolicy: async (actual) => {
                  state.guard(signal);
                  await recordPolicy(
                    policyProof(binding, actual, verifierSha256),
                  );
                },
              });
              await saveReceipts("ownership", result?.receipts ?? []);
              return result;
            },
            files: async (job, fixture, build) => {
              state.guard(signal);
              const result = await (options.files ?? runLinuxFileProofs)(
                job,
                fixture,
                build,
                { signal },
              );
              await saveReceipts(
                "files",
                result.flatMap(({ sessions }) =>
                  sessions.map(({ nonce, receiptDigest }) => ({
                    file: path.join(
                      state.output,
                      "linux",
                      "evidence",
                      `file-helper-${nonce}.json`,
                    ),
                    sha256: receiptDigest,
                  })),
                ),
              );
              return result;
            },
          },
        };
      }
      const root = path.join(state.env.RUNNER_TEMP, "native-linux-reviewed"),
        file = path.join(root, "linux-release-bindings.json");
      const bytes = await state.read(file, 1048576);
      requireObservation(
        state.manifest.inputs.some(
          (entry) => entry.path === file && entry.sha256 === digest(bytes),
        ),
      );
      const prepared = await verifyBuild(state.preparation, { signal });
      const effects = (options.readers ?? createLinuxReleaseReaders)({
        job: state.job,
        manifest: state.manifest,
        bindings: JSON.parse(bytes),
        compilerVersion: prepared.build.compiler.version,
        runnerTemp: state.env.RUNNER_TEMP,
      });
      try {
        const actual = await effects.observeAuthority();
        await recordPolicy(
          policyProof(
            binding,
            {
              policy: {
                launch: {
                  request: {
                    candidateSha: state.job.candidateSha,
                    recipe: recipe.id,
                  },
                  arguments: [],
                },
                policy: actual.authority,
              },
              nativeEventSha256: actual.nativeSha256,
            },
            verifierSha256,
          ),
        );
      } catch (error) {
        await effects.verifyClosed();
        throw error;
      }
      return { ...admitted, effects };
    },
    async settle(recipe, prepared, { signal, execution } = {}) {
      requireObservation(execution?.id === recipe.id);
      if (prepared?.effects) await prepared.effects.verifyClosed();
      const result = await settle(signal);
      const settlement = {
        status: result.status,
        independent: result.independent,
        emergencyCleanup: result.emergencyCleanup,
      };
      return Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((effectClass) => {
          const current = execution.effects[effectClass];
          requireObservation(
            ["not-started", "possible"].includes(current?.admission),
          );
          return [
            effectClass,
            current.admission === "not-started"
              ? null
              : {
                  candidateSha: state.job.candidateSha,
                  executionId: recipe.id,
                  effectClass,
                  settlement,
                  sha256: observationDigest({
                    candidateSha: state.job.candidateSha,
                    executionId: recipe.id,
                    effectClass,
                    nativeEventSha256: result.nativeEventSha256,
                    settlement,
                  }),
                },
          ];
        }),
      );
    },
    async recover({ request, signal }) {
      let result, stock;
      try {
        await state.bootstrap(signal);
        if (state.prerequisiteCustody || state.manifest.schemaVersion === 2) {
          const custody = state.prerequisiteCustody;
          requireObservation(
            custody &&
              observationDigest(custody.job) === observationDigest(state.job) &&
              observationDigest(custody.manifest) ===
                observationDigest(state.manifest) &&
              custody.output.startsWith(state.env.RUNNER_TEMP + "/"),
          );
          const names = await state.fs.readdir(custody.output);
          requireObservation(names.length <= 512);
          const prefix = `prerequisite-custody-${custody.admission.nonce}-`,
            records = names.filter((name) =>
              name.startsWith("prerequisite-custody-"),
            );
          requireObservation(
            records.length > 0 &&
              records.every((name) => name.startsWith(prefix)),
          );
          const file = path.join(custody.output, prefix + "intent.json");
          const bytes = await readProtectedEvidence(file, receiptOptions);
          stock = await recoverPrerequisiteTransport(
            custody,
            { file, bytes: bytes.length, sha256: digest(bytes) },
            { ...options, fs: state.fs },
          );
          requireObservation(retired(stock) && stock.noLiveMembers === true);
        } else {
          // Historical recovery must not silently ignore a new stock admission.
          const names = await state.fs.readdir(state.directory);
          requireObservation(
            !names.some((name) => name.startsWith("prerequisite-custody-")),
          );
        }
      } catch (error) {
        fail(error);
        result = {
          ...retained(),
          nativeEventSha256: observationDigest({
            candidateSha: state.job.candidateSha,
            custodyUncertain: true,
          }),
        };
      }
      // Stock uncertainty cannot suppress the independent namespace reread.
      const namespaces = await settle(signal);
      result ??= namespaces;
      return {
        requestSha256: observationDigest(request),
        nativeEventSha256: observationDigest({ result, namespaces, stock }),
        status:
          result.status === "RETIRED" && namespaces.status === "RETIRED"
            ? "RETIRED"
            : "RETAINED",
        independent: result.independent && namespaces.independent,
        emergencyCleanup: false,
      };
    },
  };
}
