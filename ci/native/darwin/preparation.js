import * as filesystem from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { nativeException } from "../diagnostics.js";
import {
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import { digest } from "./protocol.js";
import { purposeData, bindingKey } from "./experiment-policy.js";
import { protectedBytes, protectedInstalledInput } from "./private-files.js";
import {
  createDarwinCustodyReader,
  normalizeDarwinCustodyInput,
} from "./custody.js";
import { darwinSystemRecipes } from "./system.js";
import {
  DARWIN_HELPER_NAMES,
  darwinBuildOperation,
  darwinBuildSdk,
  darwinBuildToolchain,
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
export function normalizeDarwinPreparation(
  value,
  candidateSha,
  purpose = "reviewed",
) {
  requireObservation(["reviewed", "experiment"].includes(purpose));
  observationObject(value, [
    ...Object.keys(purposeData({ purpose })),
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
  const bootstrap = normalizeDarwinCustodyInput(value.bootstrap, purpose);
  requireObservation(
    bootstrap.context.candidateSha === candidateSha &&
      bootstrap.context.executionId === "build" &&
      bootstrap.context.tier === "system",
  );
  observationObject(value.command, [
    "helper",
    "toolCdhashes",
    ...(purpose === "experiment" ? ["sdk", "toolchain"] : []),
  ]);
  if (purpose === "experiment") {
    darwinBuildSdk(value.command.sdk, value.command.sdk?.path);
    darwinBuildToolchain(
      value.command.toolchain,
      value.command.sdk.path,
      value.command.toolchain?.developer?.path,
    );
  }
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
    "feasibility-sandbox.h",
    ...(purpose === "experiment" ? ["experiment.h", "pf-abi.h"] : []),
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
  // Build-only declarations remain valid. Until the complete preparation owner
  // joins file/Git/runtime declarations, only the fixed ownership/access set is admitted.
  if (purpose === "experiment") {
    requireObservation(value.purpose === purpose && Array.isArray(value.cases));
    if (value.cases.length === 0) return structuredClone(value);
  }
  const expected =
    purpose === "experiment" && value.cases.length !== fixed.length
      ? fixed.filter(
          (recipe) =>
            recipe.group === "ownership" || recipe.id.startsWith("access."),
        )
      : fixed;
  requireObservation(
    Array.isArray(value.cases) && value.cases.length === expected.length,
  );
  const seen = new Set();
  for (const entry of value.cases) {
    observationObject(entry, ["id", "custody", "bindings"]);
    requireObservation(
      expected.some((recipe) => recipe.id === entry.id) && !seen.has(entry.id),
    );
    seen.add(entry.id);
    const custody = normalizeDarwinCustodyInput(entry.custody, purpose);
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
    prerequisiteCustody: input.prerequisiteCustody,
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
      value.manifest.purpose ?? "reviewed",
    ),
    env = { ...(options.env ?? process.env) },
    fs = options.fs ?? filesystem;
  for (const [name, image] of [
    ["custody-reader", plan.bootstrap.reader],
    ["build-helper", plan.command.helper],
  ])
    requireObservation(
      value.manifest.helpers.some((helper) => helper.name === name) &&
        (value.manifest.purpose === "experiment" ||
          value.manifest.helpers.find((helper) => helper.name === name)
            ?.sha256 === image.sha256),
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
    (async (file, pin, maximum = 134217728, installedTool = false) => {
      const stat = await fs.lstat(file);
      requireObservation(
        stat.uid === 0 && stat.gid === 0 && !(stat.mode & 0o6022),
      );
      const installed =
        installedTool && (await protectedInstalledInput(file, stat, fs));
      requireObservation(!installedTool || installed);
      return protectedBytes(
        { path: file, sha256: pin },
        0,
        stat.mode & 0o7777,
        maximum,
        fs,
        installed,
      );
    });
  let activeReader;
  const pendingReceipts = [];
  const write = async (name, data, verify = true) => {
    data = { ...purposeData(value.manifest), ...data };
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
  let bootstrapPromise,
    bootstrapSequence,
    settlement,
    firstFailure,
    fenced = false;
  const fail = (cause) => {
    nativeException("darwin-preparation", cause);
    return (firstFailure ??= cause);
  };
  const admit = async (signal) => {
    guard(signal);
    requireObservation(!fenced);
    if (firstFailure) throw firstFailure;
    if (value.manifest.purpose === "experiment")
      requireObservation(
        !(await fs.readdir(directory)).some((name) =>
          name.startsWith("darwin-recovery-"),
        ),
      );
    guard(signal);
  };
  const fence = () => {
    fenced = true;
  };
  const bootstrap = async (signal, { recovery = false } = {}) => {
    guard(signal);
    if (!recovery) {
      await admit(signal);
      if (firstFailure) throw firstFailure;
    }
    if (bootstrapPromise) return bootstrapPromise;
    settlement = undefined;
    bootstrapPromise = (async () => {
      if (!recovery)
        requireObservation(
          !(await fs.readdir(directory)).some((name) =>
            name.startsWith("darwin-recovery-"),
          ),
        );
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
            helper?.sourceSha256 === source.sha256 &&
              (hash(helper.sha256) ||
                (value.manifest.purpose === "experiment" &&
                  helper.sha256 === null)),
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
        // Bootstrap owns only the fixed build reader/inputs. Case declarations
        // have their own admission pins and must not change this cold-load join.
        preparationSha256: observationDigest(
          value.manifest.purpose === "experiment"
            ? { ...plan, cases: [] }
            : plan,
        ),
        status: "POSSIBLE",
      });
      if (recovery) guard(signal);
      else await admit(signal);
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
    // A close may have consumed finish even when its acknowledgment is lost.
    // Keep that attempt; only independent recovery may replace missing proof.
    const result = await (current.close ??= current.reader.close());
    requireObservation(retired(result) && result.closed === true);
    activeReader = undefined;
    await write(`darwin-bootstrap-${current.sequence}-result.json`, result);
    bootstrapPromise = undefined;
    return result;
  };
  const settleBootstrap = ({ recover = false, signal = options.signal } = {}) =>
    (settlement ??= (async () => {
      let closeFailure, commandFailure;
      try {
        if (bootstrapPromise) {
          const current = await bootstrapPromise;
          if ((recover || firstFailure) && !current.close) {
            try {
              const inventory = darwinBuildRecoveryInventory(
                state,
                await darwinBuildRecords({
                  ...state,
                  receipt: options.readReceipt ?? state.stockReceipt,
                }),
              );
              // Keep original audit references until the original commands and
              // their complete domains are independently absent. This partial
              // pass supplies no observer or overall settlement proof.
              await inspectDarwinBuildRetirement(
                state,
                inventory.commands,
                current.reader,
                signal,
              );
            } catch (cause) {
              commandFailure = cause;
              nativeException("darwin-build-recovery", cause);
            }
          }
          await releaseBootstrap();
        }
      } catch (cause) {
        closeFailure = cause;
        nativeException("darwin-build-close", cause);
      }
      if (commandFailure) return retained();
      if (!recover && !firstFailure && !closeFailure)
        return {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
        };
      try {
        const recovery = darwinPreparationContext(value, options);
        const result = await recoverDarwinBuild(
          recovery,
          await darwinBuildRecords(recovery),
          signal,
          undefined,
          { recovery: true },
        );
        activeReader = undefined;
        bootstrapPromise = undefined;
        return result;
      } catch (diagnosticError) {
        nativeException("darwin-build-recovery", diagnosticError);
        return retained();
      }
    })());
  const state = {
    ...value,
    plan,
    output,
    directory,
    env,
    fs,
    now: options.now ?? (() => performance.now()),
    read,
    receipt,
    write,
    guard,
    admit,
    fence,
    stockReceipt: (file) => readReceipt(file, fs, ownerUid),
    bootstrap,
    releaseBootstrap,
    settleBootstrap,
    createReader,
    fail,
  };
  return state;
}

export async function darwinBuildRecords(state) {
  const names = await state.fs.readdir(state.directory);
  requireObservation(names.length <= 65536);
  const records = [];
  for (const name of names.filter((name) =>
    /^darwin-(?:bootstrap-[0-9]+-|command-[a-f0-9]{64}-)/u.test(name),
  ))
    records.push({
      name,
      record: JSON.parse(await state.receipt(path.join(state.directory, name))),
    });
  return records;
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
        nativeException("darwin-preparation-cleanup", cause);
        if (!firstFailure) throw state.fail(cause);
      }
    }
  };
  return {
    bootstrap: state.bootstrap,
    releaseBootstrap: state.releaseBootstrap,
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
        // Only the validated fixed tool operation opts into installed inputs.
        requireObservation(
          digest(
            await state.read(
              operation.tool.path,
              operation.tool.sha256,
              134217728,
              true,
            ),
          ) === request.toolSha256,
        );
        let targetSha256;
        if (operation.mode === "sign") {
          // Unsigned bytes supply command input only. The signed image receives
          // its purpose-specific held verification before use.
          targetSha256 = await (
            options.digestIntermediate ??
            (async (file) =>
              digest(
                (await reader.readBuildImage(file, null, 134217728, false))
                  .bytes,
              ))
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
        await state.admit(signal);
        let provisioned;
        try {
          provisioned = await (
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
        } catch (cause) {
          // A positive caller record distinguishes this pre-launch refusal from
          // an unannounced compiler launch with missing durable birth evidence.
          try {
            await state.write(
              `darwin-command-${id}-provision-failed.json`,
              {
                candidateSha: state.job.candidateSha,
                requestSha256: id,
                stage: "build-directory",
                status: "FAILED",
              },
              false,
            );
          } catch (failure) {
            nativeException("darwin-build-provision-failure-record", failure);
          }
          throw cause;
        }
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
        await state.admit(signal);
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
          {
            ...options.commandTransport,
            signal,
            beforeRelease: () => state.admit(signal),
          },
        );
        requireObservation(
          (result.purpose ?? "reviewed") ===
            (state.manifest.purpose ?? "reviewed") &&
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

function darwinBuildRecoveryInventory(state, records) {
  const byName = new Map(records.map(({ name, record }) => [name, record]));
  requireObservation(
    byName.size === records.length &&
      records.every(
        ({ name, record }) =>
          record &&
          (record.purpose ?? "reviewed") ===
            (state.manifest.purpose ?? "reviewed") &&
          Object.getPrototypeOf(record) === Object.prototype &&
          /^darwin-(?:bootstrap-[0-9]+-(?:intent|result|custody-[0-9]+)|command-[a-f0-9]{64}(?:-intent|-directory|-provision-failed|-result|-[0-9]+))\.json$/u.test(
            name,
          ) &&
          byName.has(
            name.replace(
              /-(?:intent|result|directory|provision-failed|custody-[0-9]+|[0-9]+)\.json$/u,
              "-intent.json",
            ),
          ),
      ),
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
      ...Object.keys(purposeData(state.manifest)),
      "candidateSha",
      "context",
      "preparationSha256",
      "status",
    ]);
    requireObservation(
      record.candidateSha === state.job.candidateSha &&
        record.status === "POSSIBLE" &&
        [
          observationDigest(state.plan),
          ...(state.manifest.purpose === "experiment"
            ? [observationDigest({ ...state.plan, cases: [] })]
            : []),
        ].includes(record.preparationSha256) &&
        observationDigest(record.context) ===
          observationDigest(state.plan.bootstrap.context),
    );
    const prefix = name.slice(0, -"intent.json".length),
      custody = records
        .filter((entry) => entry.name.startsWith(prefix + "custody-"))
        .sort((a, b) => a.record.sequence - b.record.sequence),
      admitted = custody.find(
        ({ record }) => record.phase === "admitted",
      )?.record;
    requireObservation(
      custody.every(
        ({ name, record: entry }, i) =>
          name === `${prefix}custody-${i}.json` &&
          entry.schemaVersion === 1 &&
          entry.sequence === i &&
          (entry.purpose ?? "reviewed") ===
            (state.manifest.purpose ?? "reviewed") &&
          entry[bindingKey(state.manifest)] ===
            state.plan.bootstrap[bindingKey(state.manifest)] &&
          observationDigest(entry.context) ===
            observationDigest(record.context) &&
          entry.requestSha256 === digest(JSON.stringify(entry.request)) &&
          [
            "entry",
            "admitted",
            "probe-intent",
            "probe-created",
            "probe-retired",
            "build-directory",
            "build-root",
            "build-open",
            "inspect",
            "read",
            "close",
            "finish",
            "retired",
            "cleanup",
            "process",
            "session",
            "root-domain",
            "root-retired",
            "compiler-policy",
            ...(state.manifest.purpose === "experiment"
              ? ["signature", "macho", "build", "build-input", "build-runtime"]
              : []),
          ].includes(entry.phase),
      ),
    );
    requireObservation(
      admitted &&
        admitted[bindingKey(state.manifest)] ===
          state.plan.bootstrap[bindingKey(state.manifest)] &&
        observationDigest(admitted.context) ===
          observationDigest(record.context) &&
        admitted.requestSha256 === digest(JSON.stringify(admitted.subjects)),
    );
    subjects.push(admitted.subjects.helper, admitted.subjects.verifier);
    domains.push(admitted.subjects.helper);
    const result = byName.get(prefix + "result.json");
    if (result)
      requireObservation(
        retired(result) &&
          result.closed === true &&
          hash(result.nativeEventSha256),
      );
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
  const observerSubjectCount = subjects.length,
    observerDomainCount = domains.length;
  for (const { name, record } of intents) {
    observationObject(record, [
      ...Object.keys(purposeData(state.manifest)),
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
    const result = byName.get(
      `darwin-command-${record.requestSha256}-result.json`,
    );
    if (result)
      requireObservation(
        result.requestSha256 === record.requestSha256 &&
          result.toolSha256 === record.request.toolSha256 &&
          result.independent === true &&
          hash(result.nativeEventSha256) &&
          retired(result.settlement),
      );
    const directory = byName.get(
      `darwin-command-${record.requestSha256}-directory.json`,
    );
    const transcript = records
      .filter(({ name }) =>
        new RegExp(
          `^darwin-command-${record.requestSha256}-[0-9]+\\.json$`,
          "u",
        ).test(name),
      )
      .map(({ record }) => record);
    if (Object.hasOwn(record, "targetSha256"))
      requireObservation(
        operation.mode === "sign"
          ? hash(record.targetSha256)
          : record.targetSha256 === null,
      );
    const refused = byName.get(
      `darwin-command-${record.requestSha256}-provision-failed.json`,
    );
    if (refused) {
      observationObject(refused, [
        ...Object.keys(purposeData(state.manifest)),
        "candidateSha",
        "requestSha256",
        "stage",
        "status",
      ]);
      requireObservation(
        refused.candidateSha === state.job.candidateSha &&
          refused.requestSha256 === record.requestSha256 &&
          refused.stage === "build-directory" &&
          refused.status === "FAILED" &&
          !directory &&
          !result &&
          transcript.length === 0,
      );
      continue;
    }
    observationObject(directory, [
      ...Object.keys(purposeData(state.manifest)),
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
    const announced = transcript.find((entry) => entry.phase === "helper");
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
  return {
    subjects,
    domains,
    directoryIdentity,
    commands: {
      subjects: subjects.slice(observerSubjectCount),
      domains: domains.slice(observerDomainCount),
      directoryIdentity,
    },
  };
}

async function inspectDarwinBuildRetirement(state, inventory, reader, signal) {
  state.guard(signal);
  const reads = [];
  if (inventory.directoryIdentity) {
    const actual = await reader.readBuildDirectory(state.output);
    requireObservation(
      actual.independent === true &&
        actual.identity === inventory.directoryIdentity,
    );
    reads.push(actual);
  }
  for (const subject of inventory.subjects) {
    state.guard(signal);
    const observed = await reader.retired(subject);
    requireObservation(retired(observed) && hash(observed.nativeEventSha256));
    reads.push(observed);
  }
  for (const subject of inventory.domains) {
    state.guard(signal);
    const observed = await reader.retiredRootDomain(subject);
    requireObservation(
      observed.independent === true &&
        observed.complete === true &&
        observed.members.length === 0,
    );
    reads.push(observed);
  }
  return reads;
}

/** Reconstruct build custody only. Case effects remain with their later owner;
 * an unannounced native launch cannot be retired from a missing receipt. */
export async function recoverDarwinBuild(
  state,
  records,
  signal,
  existingReader,
  bootstrapOptions,
) {
  const inventory = darwinBuildRecoveryInventory(state, records),
    reader =
      existingReader ??
      (await state.bootstrap(signal, bootstrapOptions)).reader,
    reads = [];
  let firstFailure;
  try {
    reads.push(
      ...(await inspectDarwinBuildRetirement(state, inventory, reader, signal)),
    );
  } catch (cause) {
    firstFailure = cause;
    throw state.fail(cause);
  } finally {
    if (!existingReader) {
      try {
        reads.push(await state.releaseBootstrap());
      } catch (cause) {
        nativeException("darwin-build-recovery-cleanup", cause);
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
