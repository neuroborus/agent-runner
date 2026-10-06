import * as filesystem from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import {
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import { digest } from "./protocol.js";
import { protectedBytes } from "./private-files.js";
import {
  createDarwinCustodyReader,
  normalizeDarwinCustodyInput,
} from "./custody.js";
import { darwinSystemRecipes } from "./system.js";
import {
  DARWIN_HELPER_NAMES,
  darwinBuildOperation,
  runDarwinBuildCommand,
} from "./build.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;
const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
const absolute = (value) =>
  typeof value === "string" &&
  path.isAbsolute(value) &&
  path.normalize(value) === value &&
  !/[\u0000-\u001f\u007f]/u.test(value);
async function readReceipt(file, fs, ownerUid) {
  requireObservation((await fs.realpath(file)) === file);
  const handle = await fs.open(
    file,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat({ bigint: true });
    requireObservation(
      before.isFile() &&
        before.uid === BigInt(ownerUid()) &&
        before.nlink === 1n &&
        (before.mode & 0o7777n) === 0o400n &&
        before.size > 0n &&
        before.size <= 1048576n,
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
        [
          "dev",
          "ino",
          "mode",
          "uid",
          "gid",
          "nlink",
          "size",
          "mtimeNs",
          "ctimeNs",
        ].every(
          (key) => before[key] === after[key] && before[key] === named[key],
        ) &&
        (await fs.realpath(file)) === file,
    );
    return bytes.subarray(0, offset);
  } finally {
    await handle.close();
  }
}

/** The separately reviewed capability supplies only protected provisioning and
 * native transport primitives. Fixed recipes and their consumers live here. */
export function normalizeDarwinPreparation(value, candidateSha) {
  observationObject(value, [
    "schemaVersion",
    "sourceDirectory",
    "sources",
    "bootstrap",
    "command",
    "cases",
  ]);
  requireObservation(
    value.schemaVersion === 1 && absolute(value.sourceDirectory),
  );
  const bootstrap = normalizeDarwinCustodyInput(value.bootstrap);
  requireObservation(
    bootstrap.context.candidateSha === candidateSha &&
      bootstrap.context.executionId === "build" &&
      bootstrap.context.tier === "system",
  );
  observationObject(value.command, ["helper", "toolCdhashes"]);
  observationObject(value.command.helper, ["path", "sha256", "cdhash"]);
  requireObservation(
    absolute(value.command.helper.path) &&
      hash(value.command.helper.sha256) &&
      /^[a-f0-9]{40}$/u.test(value.command.helper.cdhash),
  );
  requireObservation(
    path.dirname(value.command.helper.path) ===
      path.dirname(bootstrap.reader.path),
  );
  observationObject(value.command.toolCdhashes, ["compiler", "sdk", "signer"]);
  requireObservation(
    Object.values(value.command.toolCdhashes).every((pin) =>
      /^[a-f0-9]{40}$/u.test(pin),
    ),
  );
  const sourceNames = [
    ...DARWIN_HELPER_NAMES.map((name) => name + ".c"),
    "custody.h",
    "file-identity.h",
    "effective-reader.h",
  ];
  requireObservation(
    Array.isArray(value.sources) && value.sources.length === sourceNames.length,
  );
  const names = new Set();
  for (const source of value.sources) {
    observationObject(source, ["name", "sha256"]);
    requireObservation(
      sourceNames.includes(source.name) &&
        !names.has(source.name) &&
        hash(source.sha256),
    );
    names.add(source.name);
  }
  requireObservation(
    bootstrap.sources.every((source) =>
      value.sources.some(
        (entry) =>
          entry.name === path.basename(source.path) &&
          entry.sha256 === source.sha256,
      ),
    ),
  );
  const fixed = darwinSystemRecipes().filter((recipe) => recipe.id !== "build");
  requireObservation(
    Array.isArray(value.cases) && value.cases.length === fixed.length,
  );
  const seen = new Set();
  for (const entry of value.cases) {
    observationObject(entry, ["id", "custody", "bindings"]);
    requireObservation(
      fixed.some((recipe) => recipe.id === entry.id) && !seen.has(entry.id),
    );
    seen.add(entry.id);
    const custody = normalizeDarwinCustodyInput(entry.custody);
    requireObservation(
      custody.context.candidateSha === candidateSha &&
        custody.context.executionId === entry.id &&
        custody.context.platform === "darwin" &&
        custody.context.tier === "system",
    );
    requireObservation(
      observationDigest({ ...custody.context, executionId: "build" }) ===
        observationDigest(bootstrap.context),
    );
    requireObservation(
      entry.bindings &&
        Object.getPrototypeOf(entry.bindings) === Object.prototype,
    );
  }
  return structuredClone(value);
}

export function darwinPreparationContext(input, options) {
  const value = structuredClone({
    job: input.job,
    manifest: input.manifest,
    output: input.output,
    helpers: input.helpers,
    directory: input.directory,
    preparation: input.preparation,
  });
  requireObservation(
    value.job.platform === "darwin" &&
      /^[a-f0-9]{40}$/u.test(value.job.candidateSha) &&
      value.manifest.platform === "darwin" &&
      value.manifest.candidateSha === value.job.candidateSha,
  );
  const output = value.output ?? value.helpers,
    directory = value.directory ?? path.dirname(output);
  requireObservation(
    absolute(directory) &&
      absolute(output) &&
      output === path.join(directory, "platform-build"),
  );
  const plan = normalizeDarwinPreparation(
      value.manifest.darwinPreparation,
      value.job.candidateSha,
    ),
    env = { ...(options.env ?? process.env) },
    fs = options.fs ?? filesystem;
  for (const [name, image] of [
    ["custody-reader", plan.bootstrap.reader],
    ["build-helper", plan.command.helper],
  ])
    requireObservation(
      value.manifest.helpers.find((helper) => helper.name === name)?.sha256 ===
        image.sha256,
    );
  const guard = (signal) =>
    requireObservation(
      !signal?.aborted &&
        env.CI === "true" &&
        env.GITHUB_ACTIONS === "true" &&
        env.ImageOS === "macos15",
    );
  const read =
    options.read ??
    (async (file, pin, maximum = 134217728) => {
      const stat = await fs.lstat(file);
      requireObservation(
        stat.uid === 0 && stat.gid === 0 && !(stat.mode & 0o6022),
      );
      return protectedBytes(
        { path: file, sha256: pin },
        0,
        stat.mode & 0o7777,
        maximum,
        fs,
      );
    });
  let activeReader;
  const pendingReceipts = [];
  const write = async (name, data, verify = true) => {
    const bytes = Buffer.from(JSON.stringify(data) + "\n"),
      stat = await fs.lstat(directory);
    requireObservation(
      /^[a-zA-Z0-9.-]+\.json$/u.test(name) &&
        bytes.length <= 1048576 &&
        stat.isDirectory() &&
        !stat.isSymbolicLink() &&
        stat.uid === (options.ownerUid ?? (() => process.getuid()))() &&
        (stat.mode & 0o7777) === 0o700 &&
        (await fs.realpath(directory)) === directory,
    );
    await fs.writeFile(path.join(directory, name), bytes, {
      flag: "wx",
      mode: 0o400,
    });
    const pin = { path: path.join(directory, name), sha256: digest(bytes) };
    if (verify) {
      if (activeReader?.verifyBuildReceipt)
        await activeReader.verifyBuildReceipt(pin);
      else pendingReceipts.push(pin);
    }
    return pin;
  };
  const createReader =
    options.createReader ??
    ((entry, settings) =>
      createDarwinCustodyReader(entry, {
        fs,
        ...options.readerOptions,
        ...settings,
      }));
  const ownerUid = options.ownerUid ?? (() => process.getuid()),
    receipt =
      options.readReceipt ??
      (async (file) => {
        const bytes = await readReceipt(file, fs, ownerUid),
          pin = { path: file, sha256: digest(bytes) };
        if (activeReader) await activeReader.verifyBuildReceipt(pin);
        else pendingReceipts.push(pin);
        return bytes;
      });
  let bootstrapPromise, bootstrapSequence, firstFailure;
  const fail = (cause) => (firstFailure ??= cause);
  const bootstrap = (signal) => {
    guard(signal);
    if (firstFailure) throw firstFailure;
    if (bootstrapPromise) return bootstrapPromise;
    bootstrapPromise = (async () => {
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
        const stat = await fs.lstat(parent);
        requireObservation(
          stat.isDirectory() &&
            !stat.isSymbolicLink() &&
            stat.uid === ownerUid() &&
            (stat.mode & 0o7777) === 0o700 &&
            (await fs.realpath(parent)) === parent,
        );
      }
      for (const source of plan.sources) {
        const file = path.join(plan.sourceDirectory, source.name);
        requireObservation(
          digest(await read(file, source.sha256, 1048576)) === source.sha256,
        );
        if (source.name.endsWith(".c")) {
          const helper = value.manifest.helpers.find(
            (entry) => entry.name + ".c" === source.name,
          );
          requireObservation(
            helper?.sourceSha256 === source.sha256 && hash(helper.sha256),
          );
        }
      }
      const helper = plan.command.helper;
      requireObservation(
        digest(await read(helper.path, helper.sha256)) === helper.sha256,
      );
      if (bootstrapSequence === undefined) {
        const names = await fs.readdir(directory);
        requireObservation(names.length <= 65536);
        bootstrapSequence =
          1 +
          Math.max(
            -1,
            ...names.map((name) =>
              Number(
                /^darwin-bootstrap-([0-9]+)-intent\.json$/u.exec(name)?.[1] ??
                  -1,
              ),
            ),
          );
      }
      requireObservation(
        Number.isSafeInteger(bootstrapSequence) && bootstrapSequence >= 0,
      );
      const sequence = bootstrapSequence++,
        reader = createReader(plan.bootstrap, {
          ...options.readerOptions,
          persist: (record) =>
            write(
              `darwin-bootstrap-${sequence}-custody-${record.sequence}.json`,
              record,
              false,
            ),
        });
      await write(`darwin-bootstrap-${sequence}-intent.json`, {
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
      if (reader.verifyBuildReceipt)
        for (const pin of pendingReceipts) await reader.verifyBuildReceipt(pin);
      pendingReceipts.length = 0;
      activeReader = reader;
      return { reader, admitted, sequence };
    })();
    return bootstrapPromise;
  };
  const releaseBootstrap = async () => {
    const current = await bootstrapPromise;
    activeReader = undefined;
    const result = await current.reader.close();
    requireObservation(
      result.status === "RETIRED" &&
        result.independent === true &&
        result.closed === true,
    );
    await write(`darwin-bootstrap-${current.sequence}-result.json`, result);
    bootstrapPromise = undefined;
    return result;
  };
  const settleBootstrap = async () => {
    try {
      if (bootstrapPromise) await releaseBootstrap();
      return { status: "RETIRED", independent: true, emergencyCleanup: false };
    } catch {
      return retained();
    }
  };
  return {
    ...value,
    plan,
    output,
    directory,
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
    fail,
  };
}

export function createDarwinBuildEffects(input, options = {}) {
  const state = darwinPreparationContext(input, options);
  let directoryIdentity;
  const readImage = async (file, pin) => {
    requireObservation(
      state.manifest.helpers.some(
        ({ name, sha256 }) =>
          file === path.join(state.output, name) && pin === sha256,
      ),
    );
    const { reader } = await state.bootstrap();
    let firstFailure;
    try {
      const actual = await reader.readBuildImage(file, pin);
      requireObservation(
        !directoryIdentity || directoryIdentity === actual.rootIdentity,
      );
      return actual.bytes;
    } catch (cause) {
      firstFailure = cause;
      throw state.fail(cause);
    } finally {
      try {
        await state.releaseBootstrap();
      } catch (cause) {
        if (!firstFailure) throw state.fail(cause);
      }
    }
  };
  return {
    bootstrap: state.bootstrap,
    settle: state.settleBootstrap,
    readPreparedImage: readImage,
    async run(request, { signal } = {}) {
      const operation = darwinBuildOperation(
        request,
        state.manifest,
        state.output,
      );
      try {
        const { reader } = await state.bootstrap(signal),
          id = observationDigest(request);
        requireObservation(
          digest(await state.read(request.file, request.toolSha256)) ===
            request.toolSha256,
        );
        let targetSha256;
        if (operation.mode === "sign") {
          // Unsigned intermediate bytes are observed as command input only. The
          // independently approved signed image digest is checked before use.
          targetSha256 = await (
            options.digestIntermediate ??
            (async (file) => digest((await reader.readBuildImage(file)).bytes))
          )(operation.target);
          requireObservation(hash(targetSha256));
        }
        await state.write(`darwin-command-${id}-intent.json`, {
          candidateSha: state.job.candidateSha,
          request: structuredClone(request),
          requestSha256: id,
          status: "POSSIBLE",
          targetSha256: targetSha256 ?? null,
        });
        let sequence = 0;
        const persist = (record) =>
          state.write(`darwin-command-${id}-${sequence++}.json`, record);
        state.guard(signal);
        const provisioned = await (
          options.provisionBuild ??
          ((value) => value.reader.provisionBuild(value.output))
        )(
          {
            output: state.output,
            candidateSha: state.job.candidateSha,
            context: state.plan.bootstrap.context,
            reader,
          },
          { signal },
        );
        if (!options.provisionBuild) {
          requireObservation(
            provisioned.independent === true &&
              (!directoryIdentity ||
                provisioned.identity === directoryIdentity),
          );
          directoryIdentity = provisioned.identity;
          await state.write(`darwin-command-${id}-directory.json`, {
            candidateSha: state.job.candidateSha,
            requestSha256: id,
            directoryIdentity,
          });
        }
        const result = await (options.runCommand ?? runDarwinBuildCommand)(
          request,
          operation,
          {
            helper: state.plan.command.helper,
            tools: state.plan.bootstrap.tools,
            toolCdhash: state.plan.command.toolCdhashes[operation.tool.name],
            targetSha256,
            directoryIdentity,
          },
          reader,
          persist,
          { ...options.commandTransport, signal },
        );
        requireObservation(
          result.independent === true &&
            result.requestSha256 === id &&
            result.toolSha256 === request.toolSha256 &&
            hash(result.nativeEventSha256) &&
            retired(result.settlement),
        );
        const bootstrapSettlement = await state.releaseBootstrap();
        result.bootstrapSettlement = bootstrapSettlement;
        if (directoryIdentity) result.directoryIdentity = directoryIdentity;
        await state.write(`darwin-command-${id}-result.json`, result);
        return result;
      } catch (cause) {
        throw state.fail(cause);
      }
    },
  };
}

/** Reconstruct build custody only. Case effects remain with their later owner;
 * an unannounced native launch cannot be retired from a missing receipt. */
export async function recoverDarwinBuild(
  state,
  records,
  signal,
  existingReader,
) {
  const byName = new Map(records.map(({ name, record }) => [name, record]));
  requireObservation(
    byName.size === records.length &&
      !records.some(({ name }) => name.startsWith("darwin-case-")),
  );
  const intents = records.filter(({ name }) =>
      /^darwin-command-[a-f0-9]{64}-intent\.json$/u.test(name),
    ),
    bootstraps = records.filter(({ name }) =>
      /^darwin-bootstrap-[0-9]+-intent\.json$/u.test(name),
    );
  requireObservation(
    bootstraps.length > 0 &&
      intents.length <= 2 + DARWIN_HELPER_NAMES.length * 2 &&
      bootstraps.length <= 128,
  );
  const subjects = [],
    domains = [];
  let directoryIdentity;
  for (const { name, record } of bootstraps) {
    observationObject(record, [
      "candidateSha",
      "context",
      "preparationSha256",
      "status",
    ]);
    requireObservation(
      record.candidateSha === state.job.candidateSha &&
        record.status === "POSSIBLE" &&
        record.preparationSha256 === observationDigest(state.plan) &&
        observationDigest(record.context) ===
          observationDigest(state.plan.bootstrap.context),
    );
    const prefix = name.slice(0, -"intent.json".length),
      custody = records.filter((entry) =>
        entry.name.startsWith(prefix + "custody-"),
      ),
      admitted = custody.find(
        ({ record }) => record.phase === "admitted",
      )?.record;
    requireObservation(
      admitted &&
        admitted.reviewSha256 === state.plan.bootstrap.reviewSha256 &&
        observationDigest(admitted.context) ===
          observationDigest(record.context) &&
        admitted.requestSha256 === digest(JSON.stringify(admitted.subjects)),
    );
    subjects.push(admitted.subjects.helper, admitted.subjects.verifier);
    const probes = custody.filter(
      ({ record }) => record.phase === "probe-intent",
    );
    for (const { record: intent } of probes) {
      requireObservation(
        intent.requestSha256 === digest(JSON.stringify(intent.request)),
      );
      const born = custody.find(
        ({ record }) =>
          record.phase === "probe-created" &&
          record.sequence === intent.sequence + 1,
      )?.record;
      requireObservation(
        born &&
          born.request.pid === intent.request.pid &&
          born.requestSha256 === digest(JSON.stringify(born.request)),
      );
      subjects.push(born.request.verifier);
    }
  }
  for (const { name, record } of intents) {
    observationObject(record, [
      "candidateSha",
      "request",
      "requestSha256",
      "status",
      ...(Object.hasOwn(record, "targetSha256") ? ["targetSha256"] : []),
    ]);
    requireObservation(
      record.status === "POSSIBLE" &&
        record.candidateSha === state.job.candidateSha &&
        record.requestSha256 === observationDigest(record.request) &&
        name === `darwin-command-${record.requestSha256}-intent.json`,
    );
    const operation = darwinBuildOperation(
      record.request,
      state.manifest,
      state.output,
    );
    const directory = byName.get(
      `darwin-command-${record.requestSha256}-directory.json`,
    );
    observationObject(directory, [
      "candidateSha",
      "requestSha256",
      "directoryIdentity",
    ]);
    requireObservation(
      directory.candidateSha === state.job.candidateSha &&
        directory.requestSha256 === record.requestSha256 &&
        typeof directory.directoryIdentity === "string" &&
        (!directoryIdentity ||
          directoryIdentity === directory.directoryIdentity),
    );
    directoryIdentity = directory.directoryIdentity;
    if (Object.hasOwn(record, "targetSha256"))
      requireObservation(
        operation.mode === "sign"
          ? hash(record.targetSha256)
          : record.targetSha256 === null,
      );
    const transcript = records
        .filter(({ name }) =>
          new RegExp(
            `^darwin-command-${record.requestSha256}-[0-9]+\\.json$`,
            "u",
          ).test(name),
        )
        .map(({ record }) => record),
      announced = transcript.find((entry) => entry.phase === "helper");
    requireObservation(
      announced &&
        transcript.every(
          (entry) => entry.requestSha256 === record.requestSha256,
        ),
    );
    domains.push(announced.helper);
    subjects.push(announced.helper);
    const worker = transcript.find((entry) => entry.phase === "worker");
    if (worker) subjects.push(worker.worker);
    for (const entry of transcript) {
      requireObservation(
        ["helper", "worker", "publication-possible", "uncertain"].includes(
          entry.phase,
        ),
      );
      if (entry.helper)
        requireObservation(
          observationDigest(entry.helper) ===
            observationDigest(announced.helper),
        );
      if (entry.worker)
        requireObservation(
          worker &&
            observationDigest(entry.worker) ===
              observationDigest(worker.worker),
        );
    }
  }
  const reader = existingReader ?? (await state.bootstrap(signal)).reader,
    reads = [];
  let firstFailure;
  try {
    if (directoryIdentity) {
      const actual = await reader.readBuildDirectory(state.output);
      requireObservation(
        actual.independent === true && actual.identity === directoryIdentity,
      );
      reads.push(actual);
    }
    for (const subject of subjects) {
      state.guard(signal);
      const observed = await reader.retired(subject);
      requireObservation(retired(observed) && hash(observed.nativeEventSha256));
      reads.push(observed);
    }
    for (const subject of domains) {
      const observed = await reader.retiredRootDomain(subject);
      requireObservation(
        observed.independent === true &&
          observed.complete === true &&
          observed.members.length === 0,
      );
      reads.push(observed);
    }
  } catch (cause) {
    firstFailure = cause;
    throw state.fail(cause);
  } finally {
    if (!existingReader) {
      try {
        reads.push(await state.releaseBootstrap());
      } catch (cause) {
        if (!firstFailure) throw state.fail(cause);
      }
    }
  }
  state.guard(signal);
  return {
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    noLiveMembers: true,
    nativeEventSha256: observationDigest(reads),
  };
}
