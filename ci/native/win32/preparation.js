import * as filesystem from "node:fs/promises";
import { win32 as path } from "node:path";
import {
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import { digest, hash, inspectWindowsPe } from "./protocol.js";
import {
  location,
  normalizeWindowsCustodyInput,
  decodePlan,
} from "./custody-protocol.js";
import { createWindowsCustodyReader } from "./custody.js";
import { windowsSystemRecipes } from "./system.js";
import {
  WINDOWS_HELPER_NAMES,
  WINDOWS_BUILD_TOOLS,
  windowsBuildOperation,
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
    write,
    guard,
    bootstrap,
    releaseBootstrap,
    settleBootstrap,
    createReader,
    protectDirectory,
  };
}

export function createWindowsBuildEffects(input, options = {}) {
  const state = windowsPreparationContext(input, options);
  return {
    bootstrap: state.bootstrap,
    settle: state.settleBootstrap,
    async run(request, { signal } = {}) {
      const operation = windowsBuildOperation(
          request,
          state.manifest,
          state.output,
        ),
        id = observationDigest(request);
      const { reader, entries, helper, publications, root } =
        await state.bootstrap(signal);
      await state.read(request.file, request.toolSha256);
      const signature = state.plan.command.toolSignatures[operation.tool.name],
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
      const persist = (record) =>
        state.write(`windows-command-${id}-${sequence++}.json`, record);
      state.guard(signal);
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
        await state.read(operation.target, unsignedSha256);
        await persist({
          phase: "signed-publication-possible",
          requestSha256: id,
          unsignedSha256,
          imageSha256: operation.helper.sha256,
        });
        state.guard(signal);
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
      return result;
    },
  };
}
