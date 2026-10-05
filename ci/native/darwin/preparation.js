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
const requireFunctions = (value, names) =>
  names.forEach((name) =>
    requireObservation(typeof value?.[name] === "function"),
  );

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
      );
    });
  const write = (name, data) =>
    fs.writeFile(path.join(directory, name), JSON.stringify(data) + "\n", {
      flag: "wx",
      mode: 0o400,
    });
  const createReader = options.createReader ?? createDarwinCustodyReader;
  const ownerUid = options.ownerUid ?? (() => process.getuid()),
    receipt =
      options.readReceipt ?? ((file) => readReceipt(file, fs, ownerUid));
  let bootstrapPromise, bootstrapSequence;
  const bootstrap = (signal) => {
    guard(signal);
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
      const sequence = bootstrapSequence++,
        reader = createReader(plan.bootstrap, {
          ...options.readerOptions,
          persist: (record) =>
            write(
              `darwin-bootstrap-${sequence}-custody-${record.sequence}.json`,
              record,
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
      return { reader, admitted, sequence };
    })();
    return bootstrapPromise;
  };
  const releaseBootstrap = async () => {
    const current = await bootstrapPromise,
      result = await current.reader.close();
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
  };
}

export function createDarwinBuildEffects(input, options = {}) {
  const state = darwinPreparationContext(input, options);
  return {
    bootstrap: state.bootstrap,
    settle: state.settleBootstrap,
    async run(request, { signal } = {}) {
      const operation = darwinBuildOperation(
        request,
        state.manifest,
        state.output,
      );
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
          (async (file) => {
            const stat = await state.fs.lstat(file);
            requireObservation(
              stat.uid === 0 &&
                stat.gid === 0 &&
                stat.isFile() &&
                stat.nlink === 1 &&
                !(stat.mode & 0o6022),
            );
            const bytes = await state.fs.readFile(file);
            return digest(await state.read(file, digest(bytes)));
          })
        )(operation.target);
        requireObservation(hash(targetSha256));
      }
      await state.write(`darwin-command-${id}-intent.json`, {
        candidateSha: state.job.candidateSha,
        request: structuredClone(request),
        requestSha256: id,
        status: "POSSIBLE",
      });
      let sequence = 0;
      const persist = (record) =>
        state.write(`darwin-command-${id}-${sequence++}.json`, record);
      state.guard(signal);
      requireFunctions(options, ["provisionBuild"]);
      await options.provisionBuild(
        {
          output: state.output,
          candidateSha: state.job.candidateSha,
          context: state.plan.bootstrap.context,
          reader,
        },
        { signal },
      );
      const result = await (options.runCommand ?? runDarwinBuildCommand)(
        request,
        operation,
        {
          helper: state.plan.command.helper,
          tools: state.plan.bootstrap.tools,
          toolCdhash: state.plan.command.toolCdhashes[operation.tool.name],
          targetSha256,
        },
        reader,
        persist,
        { signal },
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
      await state.write(`darwin-command-${id}-result.json`, result);
      return result;
    },
  };
}
