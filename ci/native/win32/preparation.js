import * as filesystem from "node:fs/promises";
import { win32 as path } from "node:path";
import {
  observationObject,
  observationDigest,
  requireObservation,
  NATIVE_EFFECT_CLASSES,
} from "../index.js";
import {
  digest,
  hash,
  inspectWindowsPe,
  sameWindowsIdentity,
} from "./protocol.js";
import {
  location,
  normalizeWindowsCustodyInput,
  decodePlan,
  windowsVerificationArguments,
} from "./custody-protocol.js";
import { createWindowsCustodyReader } from "./custody.js";
import { createWindowsPreparationFiles } from "./preparation-files.js";
import { windowsSystemRecipes } from "./system.js";
import {
  WINDOWS_HELPER_NAMES,
  WINDOWS_BUILD_TOOLS,
  windowsBuildOperation,
  windowsSignedPublication,
  runWindowsBuildCommand,
} from "./build.js";

export const windowsRetired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false &&
  hash(value.nativeEventSha256);
export const windowsRetained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
export const requireWindowsFunctions = (value, names) =>
  names.forEach((name) =>
    requireObservation(typeof value?.[name] === "function"),
  );

/** Selectors and pins are reviewed inputs, never observations. */
export function normalizeWindowsPreparation(value, candidateSha) {
  observationObject(value, [
    "schemaVersion",
    "sourceDirectory",
    "sources",
    "bootstrap",
    "command",
    "cases",
  ]);
  requireObservation(
    value.schemaVersion === 1 && location(value.sourceDirectory),
  );
  const bootstrap = normalizeWindowsCustodyInput(value.bootstrap);
  requireObservation(
    bootstrap.context.candidateSha === candidateSha &&
      bootstrap.context.executionId === "build" &&
      bootstrap.context.tier === "system",
  );
  observationObject(value.command, [
    "helper",
    "toolSignatures",
    "unsignedHelpers",
    "helperSignatures",
  ]);
  observationObject(value.command.helper, [
    "path",
    "sha256",
    "signatureSha256",
  ]);
  requireObservation(
    location(value.command.helper.path) &&
      path.basename(value.command.helper.path) === "build-helper.exe" &&
      path.dirname(value.command.helper.path) ===
        path.dirname(bootstrap.reader.path) &&
      hash(value.command.helper.sha256) &&
      hash(value.command.helper.signatureSha256),
  );
  observationObject(value.command.toolSignatures, ["compiler", "sdk"]);
  requireObservation(Object.values(value.command.toolSignatures).every(hash));
  observationObject(value.command.unsignedHelpers, WINDOWS_HELPER_NAMES);
  requireObservation(Object.values(value.command.unsignedHelpers).every(hash));
  observationObject(value.command.helperSignatures, WINDOWS_HELPER_NAMES);
  requireObservation(
    Object.values(value.command.helperSignatures).every(hash) &&
      value.command.helperSignatures["build-helper"] ===
        value.command.helper.signatureSha256,
  );
  const sourceNames = [
    ...WINDOWS_HELPER_NAMES.map((name) => name + ".c"),
    "custody.h",
    "effective-reader.h",
    "account.h",
    "audit-policy-remove.h",
  ];
  requireObservation(
    Array.isArray(value.sources) && value.sources.length === sourceNames.length,
  );
  const names = new Set();
  for (const entry of value.sources) {
    observationObject(entry, ["name", "sha256"]);
    requireObservation(
      sourceNames.includes(entry.name) &&
        !names.has(entry.name) &&
        hash(entry.sha256),
    );
    names.add(entry.name);
  }
  requireObservation(
    bootstrap.sources.every(
      (entry) =>
        entry.path ===
          path.join(value.sourceDirectory, path.basename(entry.path)) &&
        value.sources.some(
          (source) =>
            source.name === path.basename(entry.path) &&
            source.sha256 === entry.sha256,
        ),
    ),
  );
  const fixed = windowsSystemRecipes().filter((entry) => entry.id !== "build"),
    seen = new Set();
  requireObservation(
    Array.isArray(value.cases) && value.cases.length === fixed.length,
  );
  for (const entry of value.cases) {
    observationObject(entry, ["id", "custody", "bindings"]);
    requireObservation(
      fixed.some((recipe) => recipe.id === entry.id) && !seen.has(entry.id),
    );
    seen.add(entry.id);
    const custody = normalizeWindowsCustodyInput(entry.custody);
    requireObservation(
      custody.context.executionId === entry.id &&
        observationDigest({ ...custody.context, executionId: "build" }) ===
          observationDigest(bootstrap.context) &&
        entry.bindings &&
        Object.getPrototypeOf(entry.bindings) === Object.prototype,
    );
  }
  return structuredClone(value);
}

/** Windows protection is proved by the reviewed native capability, not Node
 * mode bits. Its held reads join byte hashes, identities, DACLs and ancestors. */
export function windowsPreparationContext(input, options) {
  const value = structuredClone({
    job: input.job,
    manifest: input.manifest,
    output: input.output,
    helpers: input.helpers,
    directory: input.directory,
    preparation: input.preparation,
  });
  requireObservation(
    value.job.platform === "win32" &&
      /^[a-f0-9]{40}$/u.test(value.job.candidateSha) &&
      value.manifest.platform === "win32" &&
      value.manifest.candidateSha === value.job.candidateSha,
  );
  const output = value.output ?? value.helpers,
    directory = value.directory ?? path.dirname(output);
  requireObservation(
    location(directory) &&
      location(output) &&
      output === path.join(directory, "platform-build"),
  );
  const plan = normalizeWindowsPreparation(
      value.manifest.windowsPreparation,
      value.job.candidateSha,
    ),
    env = { ...(options.env ?? process.env) },
    fs = options.fs ?? filesystem;
  requireObservation(plan.sourceDirectory !== output);
  requireObservation(
    value.manifest.helpers.length === WINDOWS_HELPER_NAMES.length &&
      new Set(value.manifest.helpers.map((entry) => entry.name)).size ===
        WINDOWS_HELPER_NAMES.length,
  );
  for (const name of WINDOWS_HELPER_NAMES) {
    const helper = value.manifest.helpers.find((entry) => entry.name === name),
      source = plan.sources.find((entry) => entry.name === name + ".c");
    requireObservation(
      helper?.sourceSha256 === source.sha256 && hash(helper.sha256),
    );
  }
  for (const [name, image] of [
    ["custody-reader", plan.bootstrap.reader],
    ["custody-bridge", plan.bootstrap.bridge],
    ["build-helper", plan.command.helper],
  ])
    requireObservation(
      value.manifest.helpers.find((entry) => entry.name === name)?.sha256 ===
        image.sha256,
    );
  const guard = (signal) =>
    requireObservation(
      !signal?.aborted &&
        env.CI === "true" &&
        env.GITHUB_ACTIONS === "true" &&
        /^win25(?:-vs2026)?$/u.test(env.ImageOS),
    );
  const protectDirectory = async () => {
    requireWindowsFunctions(options, ["verifyDirectory"]);
    requireObservation(
      location(env.RUNNER_TEMP) && directory.startsWith(env.RUNNER_TEMP + "\\"),
    );
    const proof = await options.verifyDirectory({
      directory,
      output,
      runnerTemp: env.RUNNER_TEMP,
      context: plan.bootstrap.context,
    });
    requireObservation(
      proof?.independent === true &&
        proof.held === true &&
        proof.protectedDacl === true &&
        proof.protectedParents === true &&
        proof.exclusiveWriter === true &&
        proof.directory === directory &&
        proof.candidateSha === value.job.candidateSha &&
        hash(proof.nativeEventSha256),
    );
  };
  const heldRead = async (file, pin, maximum, receipt = false) => {
    requireObservation(location(file));
    requireWindowsFunctions(options, ["readProtected"]);
    const result = await options.readProtected({
      file,
      sha256: pin,
      maximum,
      receipt,
      context: plan.bootstrap.context,
    });
    requireObservation(
      Buffer.isBuffer(result?.bytes) &&
        result.bytes.length > 0 &&
        result.bytes.length <= maximum &&
        result.independent === true &&
        result.held === true &&
        result.protectedDacl === true &&
        result.protectedParents === true &&
        result.unchanged === true &&
        result.file === file &&
        result.sha256 === digest(result.bytes) &&
        (!pin || result.sha256 === pin) &&
        hash(result.identitySha256) &&
        hash(result.nativeEventSha256) &&
        (!receipt || result.immutable === true),
    );
    return result.bytes;
  };
  const read = (file, pin, maximum = 134217728) => heldRead(file, pin, maximum);
  const receipt = (file) => heldRead(file, null, 1048576, true);
  const write = async (name, record) => {
    requireObservation(/^windows-[a-z0-9.-]+\.json$/u.test(name));
    await protectDirectory();
    const file = path.join(directory, name),
      bytes = Buffer.from(JSON.stringify(record) + "\n");
    requireObservation(bytes.length <= 1048576);
    requireWindowsFunctions(options, ["writeProtected"]);
    // Native exclusive creation sets the DACL at birth, seals the writer and
    // independently rejoins the held immutable receipt before acknowledging it.
    const result = await options.writeProtected({
      file,
      bytes,
      context: plan.bootstrap.context,
      exclusive: true,
    });
    requireObservation(
      result?.independent === true &&
        result.file === file &&
        result.sha256 === digest(bytes) &&
        result.immutable === true &&
        result.protectedDacl === true &&
        result.protectedParents === true &&
        result.exclusive === true &&
        result.writerClosed === true &&
        hash(result.identitySha256) &&
        hash(result.nativeEventSha256),
    );
    return result;
  };
  const createReader = options.createReader ?? createWindowsCustodyReader;
  let bootstrapPromise, bootstrapSequence, lastSettlement;
  const bootstrap = (signal) => {
    guard(signal);
    if (bootstrapPromise) return bootstrapPromise;
    bootstrapPromise = (async () => {
      await protectDirectory();
      for (const source of plan.sources)
        await read(
          path.join(plan.sourceDirectory, source.name),
          source.sha256,
          1048576,
        );
      await read(plan.command.helper.path, plan.command.helper.sha256);
      const entries = decodePlan(
        await read(
          plan.bootstrap.plan.path,
          plan.bootstrap.plan.sha256,
          262144,
        ),
        plan.bootstrap,
      );
      const helper = entries.findIndex(
        (entry) =>
          entry.path === plan.command.helper.path &&
          entry.kind === "helper" &&
          entry.sha256 === plan.command.helper.sha256 &&
          entry.signatureSha256 === plan.command.helper.signatureSha256,
      );
      requireObservation(helper >= 0);
      const publications = Object.fromEntries(
        WINDOWS_HELPER_NAMES.map((name) => {
          const pin = value.manifest.helpers.find(
              (entry) => entry.name === name,
            ),
            index = entries.findIndex(
              (entry) =>
                entry.kind === "helper" &&
                entry.path === path.join(plan.sourceDirectory, name + ".exe") &&
                entry.sha256 === pin.sha256 &&
                entry.signatureSha256 === plan.command.helperSignatures[name],
            );
          requireObservation(index >= 0);
          return [name, index];
        }),
      );
      const root = entries.findIndex(
        (entry) => entry.kind === "directory" && entry.path === output,
      );
      requireObservation(root >= 0);
      if (bootstrapSequence === undefined) {
        const names = await fs.readdir(directory);
        requireObservation(names.length <= 65536);
        bootstrapSequence =
          1 +
          Math.max(
            -1,
            ...names.map((name) =>
              Number(
                /^windows-bootstrap-([0-9]+)-intent\.json$/u.exec(name)?.[1] ??
                  -1,
              ),
            ),
          );
        requireObservation(
          Number.isSafeInteger(bootstrapSequence) &&
            bootstrapSequence >= 0 &&
            bootstrapSequence <= 65535,
        );
      }
      const sequence = bootstrapSequence++,
        reader = createReader(plan.bootstrap, {
          ...options.readerOptions,
          persist: (record) =>
            write(
              `windows-bootstrap-${sequence}-custody-${record.sequence}.json`,
              record,
            ),
        });
      await write(`windows-bootstrap-${sequence}-intent.json`, {
        candidateSha: value.job.candidateSha,
        context: plan.bootstrap.context,
        preparationSha256: observationDigest(plan),
        status: "POSSIBLE",
      });
      guard(signal);
      const admitted = await reader.start({ signal });
      requireObservation(
        admitted.independent === true &&
          admitted.planSha256 === plan.bootstrap.plan.sha256,
      );
      if (!options.runCommand)
        for (const [index, entry] of entries.entries())
          if (entry.kind === "sdk") await reader.open(index);
      return {
        reader,
        admitted,
        sequence,
        entries,
        helper,
        publications,
        root,
      };
    })();
    return bootstrapPromise;
  };
  const releaseBootstrap = async () => {
    const current = await bootstrapPromise,
      result = await current.reader.close();
    requireObservation(
      windowsRetired(result) &&
        result.closed === true &&
        result.taskRemoved === true,
    );
    await write(`windows-bootstrap-${current.sequence}-result.json`, result);
    bootstrapPromise = undefined;
    lastSettlement = result;
    return result;
  };
  const settleBootstrap = async () => {
    try {
      if (bootstrapPromise) await releaseBootstrap();
      return lastSettlement ?? windowsRetained();
    } catch {
      return windowsRetained();
    }
  };
  return {
    ...value,
    output,
    directory,
    plan,
    env,
    fs,
    read,
    receipt,
    receipts: (names) =>
      options.readReceipts
        ? options.readReceipts(names)
        : Promise.all(names.map((name) => receipt(path.join(directory, name)))),
    write,
    guard,
    bootstrap,
    releaseBootstrap,
    settleBootstrap,
    createReader,
    protectDirectory,
    hasBootstrap: () => Boolean(bootstrapPromise),
  };
}

export function createWindowsBuildEffects(
  input,
  options = {},
  preparationOwners = new Map(),
) {
  options = windowsPreparationOptions(input, options, preparationOwners);
  const state = windowsPreparationContext(input, options);
  let failure;
  const guard = () => {
    if (failure) throw failure;
    requireObservation(!options.admissionClosed);
  };
  return {
    bootstrap: state.bootstrap,
    readPreparedImage: (file, pin) => {
      guard();
      requireObservation(
        state.manifest.helpers.some(
          ({ name, sha256 }) =>
            file === path.join(state.output, name + ".exe") && pin === sha256,
        ),
      );
      return state.read(file, pin);
    },
    async settle() {
      const bootstrap = await state.settleBootstrap();
      if (!windowsRetired(bootstrap)) return bootstrap;
      try {
        return (await options.settleFiles?.()) ?? bootstrap;
      } catch {
        return windowsRetained();
      }
    },
    async run(request, { signal } = {}) {
      guard();
      try {
        await options.assertAdmission?.();
        const operation = windowsBuildOperation(
            request,
            state.manifest,
            state.output,
          ),
          id = observationDigest(request);
        const { reader, entries, helper, publications, root } =
          await state.bootstrap(signal);
        await state.read(request.file, request.toolSha256);
        const signature =
            state.plan.command.toolSignatures[operation.tool.name],
          tool = entries.findIndex(
            (entry) =>
              entry.path === request.file &&
              entry.kind === "image" &&
              entry.sha256 === request.toolSha256 &&
              entry.signatureSha256 === signature,
          );
        requireObservation(tool >= 0);
        await state.write(`windows-command-${id}-intent.json`, {
          candidateSha: state.job.candidateSha,
          request: structuredClone(request),
          requestSha256: id,
          status: "POSSIBLE",
        });
        let sequence = 0;
        const persist = async (record) => {
          let policy;
          if (!options.runCommand && record.phase === "worker-admitted") {
            policy = (await options.observeWorker(record, operation))
              .compilerPolicy;
            requireObservation(policy);
            record = { ...record, compilerPolicy: policy };
          }
          await state.write(`windows-command-${id}-${sequence++}.json`, record);
          return policy;
        };
        state.guard(signal);
        guard();
        requireWindowsFunctions(options, ["provisionBuild"]);
        await options.provisionBuild(
          {
            output: state.output,
            candidateSha: state.job.candidateSha,
            context: state.plan.bootstrap.context,
            reader,
            operation,
          },
          { signal },
        );
        await reader.open(helper);
        await reader.open(tool);
        if (operation.source) {
          const source = entries.findIndex(
            (entry) =>
              entry.path === operation.source.path &&
              entry.sha256 === operation.source.sha256 &&
              ["data", "sdk"].includes(entry.kind),
          );
          requireObservation(source >= 0);
          await reader.open(source);
        }
        const result = await (options.runCommand ?? runWindowsBuildCommand)(
          request,
          operation,
          { helper, tool, toolSignatureSha256: signature },
          reader,
          persist,
          { signal },
        );
        const accepted =
          operation.mode === "compile"
            ? [0]
            : [
                0,
                ...WINDOWS_BUILD_TOOLS.find(
                  (tool) => tool.name === operation.tool.name,
                ).versionExitCodes,
              ];
        requireObservation(
          result.independent === true &&
            accepted.includes(result.exitCode) &&
            result.signal === null &&
            result.timedOut === false &&
            result.requestSha256 === id &&
            result.toolSha256 === request.toolSha256 &&
            hash(result.nativeEventSha256) &&
            windowsRetired(result.settlement),
        );
        if (operation.mode === "compile") {
          const unsignedSha256 =
            state.plan.command.unsignedHelpers[operation.helper.name];
          const unsigned = await (options.readIntermediate ?? state.read)(
            operation.target,
            unsignedSha256,
          );
          if (!options.publishBuild) {
            const signed = await state.read(
              path.join(
                state.plan.sourceDirectory,
                operation.helper.name + ".exe",
              ),
              operation.helper.sha256,
            );
            windowsSignedPublication(unsigned, signed);
          }
          await persist({
            phase: "signed-publication-possible",
            requestSha256: id,
            unsignedSha256,
            imageSha256: operation.helper.sha256,
          });
          state.guard(signal);
          guard();
          const image = publications[operation.helper.name];
          if (image !== helper) await reader.open(image);
          await reader.open(root);
          const publication = options.publishBuild
            ? await options.publishBuild(
                {
                  request,
                  operation,
                  unsignedSha256,
                  context: state.plan.bootstrap.context,
                  reader,
                },
                { signal },
              )
            : await reader.publishBuild(request, operation, unsignedSha256, {
                image,
                root,
              });
          requireObservation(
            publication?.independent === true &&
              publication.requestSha256 === id &&
              publication.unsignedSha256 === unsignedSha256 &&
              publication.sourceSha256 === operation.source.sha256 &&
              publication.imageSha256 === operation.helper.sha256 &&
              publication.writerClosed === true &&
              publication.protectedDacl === true &&
              hash(publication.nativeEventSha256) &&
              windowsRetired(publication.settlement),
          );
          const bytes = await state.read(
            operation.target,
            operation.helper.sha256,
          );
          const inspected = (options.inspectImage ?? inspectWindowsPe)(bytes);
          requireObservation(
            inspected.signatureSha256 ===
              state.plan.command.helperSignatures[operation.helper.name] &&
              publication.signatureSha256 === inspected.signatureSha256,
          );
          result.publication = publication;
        }
        result.bootstrapSettlement = await state.releaseBootstrap();
        await state.write(`windows-command-${id}-result.json`, result);
        state.guard(signal);
        guard();
        return result;
      } catch (error) {
        failure ??= error;
        throw failure;
      }
    },
  };
}

export function windowsPreparationOptions(input, options, preparationOwners) {
  const key = observationDigest({
    context: input.manifest.windowsPreparation.bootstrap.context,
    manifest: input.manifest,
    output: input.output ?? input.helpers,
    directory: input.directory ?? path.dirname(input.output ?? input.helpers),
  });
  const files = options.readProtected
    ? createWindowsPreparationFiles(input, options)
    : (preparationOwners.get(key) ??
      createWindowsPreparationFiles(input, options));
  if (!options.readProtected) preparationOwners.set(key, files);
  const methods = [
    "verifyBootstrap",
    "verifyAdmission",
    "verifyTransfer",
    "verifyHelperRetirement",
    "verifyRetirement",
    "verifyTaskRemoval",
    "verifyPublication",
    "verifyCaseProvisioning",
    "verifyCaseRetirement",
    "verifyAccessCoverage",
    "verifyAccessControl",
    "verifyAccessSocket",
    "verifyAccessPeerPolicy",
    "verifyAccessPeerRetirement",
    "verifyAccessFault",
    "verifyAuditRetirement",
    "verifyRestoration",
    "readAccessReceipt",
  ];
  const defaults = {
    ...files,
    get admissionClosed() {
      return files.admissionClosed;
    },
    caseOwners: files.caseOwners,
    fenceAdmission: files.fenceAdmission,
    assertAdmission: files.assertAdmission,
    ...(options.readProtected
      ? {
          readIntermediate: null,
          readReceipts: null,
          async assertAdmission() {
            requireObservation(!files.admissionClosed);
            const names = await options.fs.readdir(
              input.directory ?? path.dirname(input.output ?? input.helpers),
            );
            requireObservation(!files.admissionClosed);
            if (
              names.some((name) =>
                /^windows-recovery-[a-f0-9]{64}-[0-9]+-intent\.json$/u.test(
                  name,
                ),
              )
            ) {
              files.fenceAdmission();
              requireObservation(false);
            }
          },
        }
      : {}),
    async settleFiles() {
      const result = await files.settleFiles();
      preparationOwners.delete(key);
      return result;
    },
    observeWorker: (record, operation) =>
      files.verify(
        "verifyBuildWorker",
        record,
        operation.tool,
        input.manifest.windowsPreparation.command.toolSignatures[
          operation.tool.name
        ],
      ),
    createReader: (declaration, settings) => {
      const isCase = declaration.context.executionId !== "build";
      const custodyFiles = isCase
        ? createWindowsPreparationFiles(
            {
              ...input,
              manifest: {
                ...input.manifest,
                windowsPreparation: {
                  ...input.manifest.windowsPreparation,
                  bootstrap: declaration,
                },
              },
            },
            options,
          )
        : files;
      const reader = createWindowsCustodyReader(declaration, {
        ...Object.fromEntries(
          methods.map((name) => [
            name,
            (...args) => custodyFiles.verify(name, ...args),
          ]),
        ),
        read: async (file) =>
          (
            await custodyFiles.readProtected({
              file,
              sha256: [
                declaration.reader,
                declaration.bridge,
                declaration.plan,
                ...declaration.sources,
              ].find((pin) => pin.path === file)?.sha256,
            })
          ).bytes,
        ...options.readerOptions,
        ...settings,
        admissionClosed: () => files.admissionClosed,
      });
      const start = reader.start.bind(reader),
        close = reader.close.bind(reader),
        beginCleanup = reader.beginCleanup.bind(reader);
      reader.start = (settings = {}) => {
        custodyFiles.retainReader(reader, settings.signal);
        return start(settings);
      };
      reader.beginCleanup = async ({ signal }) => {
        await beginCleanup({ signal });
        custodyFiles.retainReader(reader, signal);
        await custodyFiles.beginCleanup(signal);
      };
      reader.close = async () => {
        const result = await close();
        if (windowsRetired(result)) {
          custodyFiles.releaseReader(reader);
          if (isCase) {
            const settlement = await custodyFiles.settleFiles();
            requireObservation(windowsRetired(settlement));
            result.nativeEventSha256 = observationDigest({
              custody: result.nativeEventSha256,
              settlement,
            });
          }
        }
        return result;
      };
      return reader;
    },
    async verifyCommands(commands, _reader, { signal }) {
      requireObservation(
        !signal?.aborted &&
          commands.every(
            (entry) =>
              windowsRetired(entry.settlement) &&
              windowsRetired(entry.bootstrapSettlement) &&
              entry.bootstrapSettlement.taskRemoved === true,
          ),
      );
      const identities = [
        ...new Map(
          commands
            .flatMap((entry) => [
              entry.identity,
              entry.helperIdentity,
              entry.bootstrapSettlement.helper,
              entry.bootstrapSettlement.bridge,
            ])
            .map((identity) => {
              requireObservation(identity);
              return [observationDigest(identity), identity];
            }),
        ).values(),
      ];
      const result = await files.verify(
        "verifyCompleted",
        input.manifest.windowsPreparation.bootstrap,
        identities,
        [input.manifest.windowsPreparation.bootstrap.nonce],
      );
      requireObservation(!signal?.aborted && result.tasksRemoved === true);
      return { ...result, commandsSha256: observationDigest(commands) };
    },
    async recover({ request, records, plan }, { signal }) {
      requireObservation(!signal?.aborted);
      const subjects = [],
        taskOwners = [],
        byName = new Map(records.map(({ name, record }) => [name, record]));
      requireObservation(byName.size === records.length);
      const filePrefix = `windows-files-${files.verification.input.nonce}-`,
        fileBirth = byName.get(filePrefix + "birth.json");
      requireObservation(
        byName.has(filePrefix + "intent.json") &&
          fileBirth?.schemaVersion === 1 &&
          fileBirth.status === "POSSIBLE" &&
          fileBirth.nonce === files.verification.input.nonce &&
          fileBirth.taskSha256 === files.verification.taskSha256 &&
          sameWindowsIdentity(fileBirth.helper, files.verification.identity) &&
          sameWindowsIdentity(fileBirth.bridge, files.verification.bridge),
      );
      const observers = records.filter(
        ({ name, record }) =>
          /^windows-files-[a-f0-9]{32}-intent\.json$/u.test(name) &&
          record.argumentsHex?.[4] ===
            Buffer.from(plan.bootstrap.plan.path, "utf16le").toString("hex"),
      );
      requireObservation(observers.length > 0 && observers.length <= 128);
      for (const observer of observers) {
        const observerPrefix = observer.name.slice(0, -"intent.json".length),
          birth = byName.get(observerPrefix + "birth.json");
        requireObservation(
          birth?.schemaVersion === 1 &&
            birth.status === "POSSIBLE" &&
            observerPrefix === `windows-files-${birth.nonce}-` &&
            hash(birth.taskSha256),
        );
        if (observerPrefix !== filePrefix) {
          subjects.push(birth.helper, birth.bridge);
          taskOwners.push(birth);
        }
        const journal = [];
        for (const { name, record } of records.filter(({ name }) =>
          name.startsWith(observerPrefix),
        )) {
          requireObservation(name.startsWith(observerPrefix));
          if (name.endsWith("-intent.json")) {
            const expected = [
              "--observe",
              plan.bootstrap.reader.path,
              plan.bootstrap.reader.sha256,
              plan.bootstrap.reader.signatureSha256,
              plan.bootstrap.plan.path,
              plan.bootstrap.plan.sha256,
              birth.nonce,
              plan.bootstrap.runnerSid,
              input.directory ?? path.dirname(input.output ?? input.helpers),
              input.output ?? input.helpers,
            ];
            requireObservation(
              record.schemaVersion === 1 &&
                record.status === "POSSIBLE" &&
                observationDigest(record.argumentsHex) ===
                  observationDigest(
                    expected.map((value) =>
                      Buffer.from(value, "utf16le").toString("hex"),
                    ),
                  ),
            );
          } else if (name.endsWith("-result.json")) {
            requireObservation(
              record.schemaVersion === 1 &&
                record.status === "RETIRED" &&
                record.nonce === birth.nonce &&
                record.taskSha256 === birth.taskSha256 &&
                sameWindowsIdentity(record.helper, birth.helper) &&
                sameWindowsIdentity(record.bridge, birth.bridge),
            );
          } else if (!name.endsWith("-birth.json")) {
            requireObservation(
              record.schemaVersion === 1 &&
                record.candidateSha === input.job.candidateSha &&
                record.nonce === birth.nonce &&
                sameWindowsIdentity(record.helper, birth.helper) &&
                typeof record.commandHex === "string" &&
                /^(?:[a-f0-9]{2}){1,262144}$/u.test(record.commandHex),
            );
            const match = /-([0-9]+)\.json$/u.exec(name),
              frame = Buffer.from(record.commandHex, "hex").toString("ascii"),
              command =
                /^(prepare-(?:directory|list|read|bytes|release|write|chunk|seal|batch)|verify-[a-z-]+|finish) ([1-9][0-9]*)(?: [a-z0-9-]+)*$/u.exec(
                  frame,
                );
            requireObservation(
              match &&
                command &&
                name === observerPrefix + Number(match[1]) + ".json" &&
                Number(match[1]) === Number(command[2]) &&
                Number(match[1]) <= 32768,
            );
            if (command[1].startsWith("verify-"))
              windowsVerificationArguments(
                command[1].slice(7),
                frame.split(" ").slice(2),
              );
            journal.push(Number(match[1]));
          }
        }
        journal.sort((left, right) => left - right);
        requireObservation(
          journal.length > 0 &&
            journal.every((sequence, index) => sequence === index + 1),
        );
      }
      const boots = records
        .filter(({ name }) =>
          /^windows-bootstrap-[0-9]+-intent\.json$/u.test(name),
        )
        .sort(
          (left, right) =>
            Number(left.name.split("-")[2]) - Number(right.name.split("-")[2]),
        );
      requireObservation(
        boots.length > 0 &&
          boots.length <= 128 &&
          boots.every(
            ({ name }, index) =>
              name === `windows-bootstrap-${index}-intent.json`,
          ),
      );
      requireObservation(
        records
          .filter(({ name }) => name.startsWith("windows-bootstrap-"))
          .every(({ name }) =>
            boots.some((boot) =>
              name.startsWith(boot.name.slice(0, -"intent.json".length)),
            ),
          ),
      );
      for (const { name, record } of boots) {
        requireObservation(
          record.candidateSha === input.job.candidateSha &&
            record.preparationSha256 === observationDigest(plan) &&
            record.status === "POSSIBLE" &&
            observationDigest(record.context) ===
              observationDigest(plan.bootstrap.context),
        );
        const prefix = name.slice(0, -"intent.json".length),
          custody = records
            .filter((entry) => entry.name.startsWith(prefix + "custody-"))
            .sort(
              (left, right) => left.record.sequence - right.record.sequence,
            );
        for (const [index, { name: leaf, record: event }] of custody.entries())
          requireObservation(
            leaf === prefix + `custody-${index}.json` &&
              event.sequence === index &&
              event.reviewSha256 === plan.bootstrap.reviewSha256 &&
              (event.requestSha256 === observationDigest(plan.bootstrap) ||
                (event.phase === "build-published" &&
                  byName.has(
                    `windows-command-${event.requestSha256}-intent.json`,
                  ))) &&
              observationDigest(event.context) ===
                observationDigest(plan.bootstrap.context) &&
              event.nonce === plan.bootstrap.nonce,
          );
        const admitted = custody.find(
            ({ record }) => record.phase === "admitted",
          )?.record,
          registered = custody.find(
            ({ record }) => record.phase === "task-run-possible",
          )?.record;
        requireObservation(
          admitted && registered && hash(registered.taskSha256),
        );
        subjects.push(registered.bridge);
        taskOwners.push({ ...registered, nonce: plan.bootstrap.nonce });
        subjects.push(admitted.helper);
        const helpers = custody.filter(
          ({ record }) => record.phase === "helper-admitted",
        );
        // A lost birth acknowledgement retains exclusion. The independent
        // reader below must still attempt retirement of every known owner.
        requireObservation(
          helpers.length ===
            custody.filter(({ record }) => record.phase === "helper-start")
              .length,
        );
        subjects.push(...helpers.map(({ record }) => record.child));
      }
      const intents = records.filter(({ name }) =>
        /^windows-command-[a-f0-9]{64}-intent\.json$/u.test(name),
      );
      requireObservation(intents.length <= 2 + WINDOWS_HELPER_NAMES.length);
      requireObservation(
        records
          .filter(({ name }) => name.startsWith("windows-command-"))
          .every(({ name }) =>
            intents.some((intent) =>
              name.startsWith(intent.name.slice(0, -"intent.json".length)),
            ),
          ),
      );
      for (const { name, record } of intents) {
        const id = observationDigest(record.request);
        requireObservation(
          record.requestSha256 === id &&
            name === `windows-command-${id}-intent.json` &&
            record.candidateSha === input.job.candidateSha &&
            record.status === "POSSIBLE",
        );
        windowsBuildOperation(
          record.request,
          input.manifest,
          input.output ?? input.helpers,
        );
        const journal = records
          .filter(({ name }) =>
            new RegExp(`^windows-command-${id}-[0-9]+\\.json$`, "u").test(name),
          )
          .sort(
            (left, right) =>
              Number(left.name.split("-").at(-1).slice(0, -5)) -
              Number(right.name.split("-").at(-1).slice(0, -5)),
          );
        requireObservation(
          journal.length > 0 &&
            journal.every(
              ({ name, record }, index) =>
                name === `windows-command-${id}-${index}.json` &&
                record.requestSha256 === id &&
                [
                  "worker-admitted",
                  "publication-possible",
                  "signed-publication-possible",
                  "uncertain",
                ].includes(record.phase),
            ),
        );
        const workers = journal.filter(
          ({ record }) => record.phase === "worker-admitted",
        );
        requireObservation(
          workers.length === 1 && workers[0].record.requestSha256 === id,
        );
        subjects.push(workers[0].record.worker, workers[0].record.helper);
      }
      await files.retireReaders();
      const identities = [
        ...new Map(
          subjects.map((identity) => [observationDigest(identity), identity]),
        ).values(),
      ];
      const result = await files.verify(
        "recoverCompleted",
        plan.bootstrap,
        identities,
        [],
        observers
          .filter(({ name }) => name !== filePrefix + "intent.json")
          .flatMap(({ name }) => {
            const birth = byName.get(
              name.replace(/intent\.json$/u, "birth.json"),
            );
            return [birth.helper, birth.bridge].map((identity) => ({
              identity,
              nonce: birth.nonce,
            }));
          }),
      );
      const tasks = [];
      for (const owner of taskOwners)
        tasks.push(
          await files.verify(
            "recoverOwnedTask",
            owner.nonce,
            owner.taskSha256,
            owner.bridge,
          ),
        );
      requireObservation(
        !signal?.aborted &&
          tasks.length > 0 &&
          tasks.every(
            (task) =>
              task.status === "RETIRED" &&
              task.independent === true &&
              task.emergencyCleanup === false,
          ),
      );
      const settlement = {
        ...result,
        tasksRemoved: true,
        nativeEventSha256: observationDigest({ result, tasks }),
      };
      return {
        ...settlement,
        recordsSha256: observationDigest(records),
        requestSha256: observationDigest(request),
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((effect) => [effect, settlement]),
        ),
      };
    },
  };
  const fs = options.readProtected
    ? options.fs
    : { ...(options.fs ?? filesystem), readdir: files.readdir };
  return new Proxy(options, {
    get: (injected, key) =>
      key === "fs" ? fs : (injected[key] ?? defaults[key]),
  });
}
