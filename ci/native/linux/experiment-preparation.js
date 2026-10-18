import { execFile } from "node:child_process";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { diagnosticCommand, nativeException } from "../diagnostics.js";
import { readProcessIdentity } from "../../../src/agents/index.js";
import {
  normalizeExperimentJob,
  recordExperimentPreparationEffect,
  recordExperimentPreparation,
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import {
  acquireLinuxExperimentInterpreter,
  verifyLinuxExperimentInterpreter,
} from "./confinement.js";
import {
  readLinuxObservedFile,
  readLinuxRunningInterpreterIdentity,
  digest,
  readProtectedEvidence,
  assertLinuxProcVisibility,
} from "./inspect.js";
import {
  verifyLinuxFileElf,
  linuxHostedFileBuildArguments,
} from "./file-build.js";
import {
  readLinuxNamespaceEvidence,
  verifyLinuxNamespaces,
} from "./namespace-preparation.js";
import { persistLinuxExperimentFailure } from "./diagnostics.js";

const execute = diagnosticCommand(
  "linux-experiment-preparation",
  promisify(execFile),
);
const SOURCE = fileURLToPath(new URL("./file-helper.c", import.meta.url));
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const COMPILER = "/usr/bin/x86_64-linux-gnu-gcc-13";
const SDK = "/usr/bin/x86_64-linux-gnu-ld.bfd";
const ENV = Object.freeze({ PATH: "/usr/bin:/bin", LANG: "C" });
const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;
const effect = (settlement, receiptSha256 = null) => ({
  admission: "possible",
  settlement,
  receiptSha256,
});
const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});

// GNU timeout owns the ordinary compiler's process group and forwards TERM,
// escalating after two seconds. Await execFile closure before accepting output.
// A lost/interrupted command has no completed build record and cannot cold-settle.
const hostedCommand = diagnosticCommand(
  "linux-hosted-build",
  (file, args, { cwd, signal, deadlineMs }) =>
    new Promise((resolve, reject) => {
      signal?.throwIfAborted();
      const child = execFile(
        "/usr/bin/timeout",
        [
          "--signal=TERM",
          "--kill-after=2s",
          `${Math.floor(deadlineMs / 1000)}s`,
          file,
          ...args,
        ],
        {
          cwd,
          env: ENV,
          timeout: deadlineMs + 5000,
          maxBuffer: 65536,
          killSignal: "SIGTERM",
        },
        (error, stdout, stderr) => {
          signal?.removeEventListener("abort", stop);
          if (error) return reject(error);
          try {
            signal?.throwIfAborted();
            resolve({ stdout, stderr, exitCode: 0, signal: null });
          } catch (cause) {
            reject(cause);
          }
        },
      );
      const stop = () => child.kill("SIGTERM");
      signal?.addEventListener("abort", stop, { once: true });
      if (signal?.aborted) stop();
    }),
);

function worker(job, env, platform, architecture) {
  requireObservation(
    job.platform === "linux" &&
      platform === "linux" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24" &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      env.RUNNER_OS === "Linux" &&
      env.GITHUB_REPOSITORY === job.repository &&
      env.GITHUB_RUN_ID === job.runId &&
      env.GITHUB_RUN_ATTEMPT === String(job.runAttempt),
  );
}

function preparationOwner(job, value) {
  observationObject(value, [
    "purpose",
    "candidateSha",
    "contextSha256",
    "pid",
    "identity",
  ]);
  observationObject(value.identity, ["bootId", "startTicks"]);
  requireObservation(
    value.purpose === "experiment" &&
      value.candidateSha === job.candidateSha &&
      value.contextSha256 ===
        observationDigest({
          repository: job.repository,
          runId: job.runId,
          runAttempt: job.runAttempt,
        }) &&
      Number.isSafeInteger(value.pid) &&
      value.pid > 0 &&
      value.pid <= 2147483647 &&
      typeof value.identity.bootId === "string" &&
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(
        value.identity.bootId,
      ) &&
      typeof value.identity.startTicks === "string" &&
      /^(?:0|[1-9][0-9]{0,31})$/u.test(value.identity.startTicks),
  );
  return value;
}

/** The original acquisition record is immutable and preparation-bound. Cold
 * owners inspect it; they never copy the currently observed setup-node image. */
export async function rejoinLinuxExperimentInterpreter(
  job,
  directory,
  {
    read = readLinuxObservedFile,
    readIntent = readProtectedEvidence,
    running = readLinuxRunningInterpreterIdentity,
  } = {},
) {
  const interpreter = JSON.parse(
      await readIntent(path.join(directory, "preparation", "interpreter.json")),
    ),
    intent = JSON.parse(
      await readIntent(
        path.join(directory, "preparation", "interpreter-intent.json"),
      ),
    ),
    owner = preparationOwner(
      job,
      JSON.parse(
        await readIntent(
          path.join(directory, "experiment-preparation-owner.json"),
        ),
      ),
    ),
    { identitySha256, ...acquisition } = interpreter;
  requireObservation(
    interpreter.candidateSha === job.candidateSha &&
      interpreter.executable ===
        path.join(directory, "preparation", "executables", "node") &&
      interpreter.ownerSha256 === observationDigest(owner) &&
      observationDigest(acquisition) === observationDigest(intent) &&
      (!job.preparation ||
        job.preparation.expected.sources.some(
          ({ id, sha256 }) =>
            id === "node-interpreter" &&
            sha256 === observationDigest(interpreter),
        )),
  );
  await verifyLinuxExperimentInterpreter(interpreter, { read });
  const actual = await running();
  requireObservation(
    actual.version === interpreter.version &&
      [interpreter.source.identitySha256, interpreter.identitySha256].includes(
        actual.identitySha256,
      ),
  );
  return interpreter;
}

function buildRecord(job, directory, record) {
  observationObject(record, [
    "schemaVersion",
    "purpose",
    "candidateSha",
    "sourceSha256",
    "compiler",
    "sdk",
    "arguments",
    "commands",
    "executable",
    "sha256",
    "abi",
  ]);
  const build = path.join(directory, "build");
  requireObservation(
    record.schemaVersion === 2 &&
      record.purpose === "experiment" &&
      record.candidateSha === job.candidateSha &&
      record.executable === path.join(build, "output", "file-helper") &&
      /^[a-f0-9]{64}$/u.test(record.sourceSha256) &&
      /^[a-f0-9]{64}$/u.test(record.sha256),
  );
  for (const [name, file] of [
    ["compiler", COMPILER],
    ["sdk", SDK],
  ]) {
    observationObject(record[name], ["file", "sha256", "version"]);
    requireObservation(
      record[name].file === file &&
        /^[a-f0-9]{64}$/u.test(record[name].sha256) &&
        /^[\x20-\x7e]{1,256}$/u.test(record[name].version),
    );
  }
  requireObservation(
    /^13\.[0-9]+\.[0-9]+$/u.test(record.compiler.version) &&
      observationDigest(record.arguments) ===
        observationDigest(linuxHostedFileBuildArguments(build)) &&
      Array.isArray(record.commands) &&
      record.commands.length === 3,
  );
  for (const [index, command] of record.commands.entries()) {
    observationObject(command, [
      "file",
      "args",
      "cwd",
      "env",
      "deadlineMs",
      "exitCode",
      "signal",
      "stdout",
      "stderr",
    ]);
    requireObservation(
      command.file === (index === 1 ? SDK : COMPILER) &&
        command.cwd === build &&
        observationDigest(command.env) === observationDigest(ENV) &&
        command.deadlineMs === 20000 &&
        command.exitCode === 0 &&
        command.signal === null &&
        observationDigest(command.args) ===
          observationDigest(index < 2 ? ["--version"] : record.arguments) &&
        [command.stdout, command.stderr].every(
          (text) =>
            typeof text === "string" && Buffer.byteLength(text) <= 65536,
        ),
    );
  }
  requireObservation(
    /\b(13\.[0-9]+\.[0-9]+)\s*$/u.exec(
      record.commands[0].stdout.split("\n")[0],
    )?.[1] === record.compiler.version &&
      record.commands[1].stdout.split("\n")[0] === record.sdk.version,
  );
  return record;
}

/** Actual source, command, tool and output observations; no compiler receipts. */
export async function verifyLinuxExperimentBuild(
  job,
  directory,
  value,
  { read = readLinuxObservedFile } = {},
) {
  const record = buildRecord(job, directory, value);
  requireObservation(
    (
      await read(path.join(directory, "build", "file-helper.c"), 65536, {
        protectedInput: false,
      })
    ).sha256 === record.sourceSha256,
  );
  for (const tool of [record.compiler, record.sdk])
    requireObservation(
      (await read(tool.file, 67108864)).sha256 === tool.sha256,
    );
  if (job.preparation)
    requireObservation(
      job.preparation.expected.components[0].bindings.build ===
        observationDigest(record) &&
        (job.preparationEffects.receiptSha256 === null ||
          job.preparationEffects.receiptSha256 === observationDigest(record)),
    );
  return readHelper(record, read);
}

async function readHelper(record, read) {
  const native = await read(record.executable, 4194304, {
    protectedInput: false,
  });
  requireObservation(
    native.sha256 === record.sha256 &&
      observationDigest(verifyLinuxFileElf(native.bytes)) ===
        observationDigest(record.abi),
  );
  return {
    id: "file-helper",
    sha256: native.sha256,
    format: "elf-x64",
    loader: [],
    bindings: {
      source: record.sourceSha256,
      build: observationDigest(record),
      abi: observationDigest(record.abi),
    },
    identityBefore: native.identitySha256,
    identityAfter: native.identitySha256,
    held: true,
    independent: true,
  };
}

/** Ordinary hosted preparation builds once. Held runtime custody remains separate. */
export async function prepareLinuxExperiment(
  input,
  binding,
  directory,
  persist,
  {
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
    read = readLinuxObservedFile,
    command = hostedCommand,
    build = command,
    fs = { chmod, copyFile, mkdir, readFile, writeFile },
    identity = readProcessIdentity,
    namespaces = verifyLinuxNamespaces,
    readNamespace = readLinuxNamespaceEvidence,
    now = () => performance.now(),
    signal,
    onFailure = (job, error) =>
      persistLinuxExperimentFailure(job, directory, "preparation", error),
    nodeVersion = process.version,
    acquireInterpreter = acquireLinuxExperimentInterpreter,
    checkout = async () =>
      (
        await execute(
          "/usr/bin/git",
          ["--no-lazy-fetch", "rev-parse", "--verify", "HEAD"],
          { cwd: ROOT, env: ENV, timeout: 10000, maxBuffer: 1024 },
        )
      ).stdout.trim(),
    sourceBytes = async (candidateSha) =>
      (
        await execute(
          "/usr/bin/git",
          [
            "--no-lazy-fetch",
            "show",
            `${candidateSha}:ci/native/linux/file-helper.c`,
          ],
          {
            cwd: ROOT,
            env: ENV,
            encoding: null,
            timeout: 10000,
            maxBuffer: 65536,
          },
        )
      ).stdout,
  } = {},
) {
  let job = normalizeExperimentJob(input);
  worker(job, env, platform, architecture);
  requireObservation(
    job.preparation === null &&
      job.preparationEffects.admission === "not-started" &&
      typeof persist === "function",
  );
  const deadline = now() + 240000;
  const active = () => {
    signal?.throwIfAborted();
    requireObservation(now() < deadline);
  };
  const save = async (next) => {
    active();
    job = normalizeExperimentJob(next);
    await persist(job);
    active();
  };
  await save(recordExperimentPreparationEffect(job, effect(retained())));
  try {
    const owner = preparationOwner(job, {
      purpose: "experiment",
      candidateSha: job.candidateSha,
      contextSha256: observationDigest({
        repository: job.repository,
        runId: job.runId,
        runAttempt: job.runAttempt,
      }),
      pid: process.pid,
      identity: await identity(process.pid),
    });
    await fs.writeFile(
      path.join(directory, "experiment-preparation-owner.json"),
      JSON.stringify(owner) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    requireObservation(
      binding.nodeVersion === nodeVersion &&
        binding.osBuild === env.ImageVersion,
    );
    const namespace = await readNamespace(
      path.join(directory, "linux-namespace-preparation.json"),
    );
    await namespaces(
      namespace,
      {
        candidateSha: job.candidateSha,
        runId: job.runId,
        runAttempt: String(job.runAttempt),
      },
      directory,
      { signal },
    );
    requireObservation(
      (await checkout()) === job.candidateSha &&
        binding.checkoutSha === job.candidateSha,
    );
    const preparation = path.join(directory, "preparation"),
      output = path.join(directory, "build");
    await fs.mkdir(preparation, { mode: 0o700 });
    const interpreter = await acquireInterpreter(job, owner, directory, {
      version: nodeVersion,
    });
    await fs.mkdir(output, { mode: 0o700 });
    await fs.mkdir(path.join(output, "output"), { mode: 0o700 });
    const source = path.join(output, "file-helper.c"),
      original = await fs.readFile(SOURCE);
    requireObservation(
      digest(original) === digest(await sourceBytes(job.candidateSha)),
    );
    await fs.copyFile(SOURCE, source);
    await fs.chmod(source, 0o400);
    const sourceSha256 = digest(original);
    requireObservation(
      (await read(source, 65536, { protectedInput: false })).sha256 ===
        sourceSha256,
    );
    const commands = [];
    const run = async (file, args, invoke = command) => {
      active();
      requireObservation(now() + 25000 < deadline);
      const request = { file, args, cwd: output, env: ENV, deadlineMs: 20000 };
      const result = await invoke(file, args, { ...request, signal });
      active();
      requireObservation(
        result.exitCode === 0 &&
          result.signal === null &&
          [result.stdout, result.stderr].every(
            (text) =>
              typeof text === "string" && Buffer.byteLength(text) <= 65536,
          ),
      );
      commands.push({
        ...request,
        exitCode: result.exitCode,
        signal: result.signal,
        stdout: result.stdout,
        stderr: result.stderr,
      });
      return result.stdout.split("\n")[0];
    };
    const compilerRead = await read(COMPILER, 67108864),
      sdkRead = await read(SDK, 67108864);
    const compilerVersion = /\b(13\.[0-9]+\.[0-9]+)\s*$/u.exec(
      await run(COMPILER, ["--version"]),
    )?.[1];
    const sdkVersion = await run(SDK, ["--version"]);
    requireObservation(compilerVersion);
    const argumentsList = linuxHostedFileBuildArguments(output);
    await run(COMPILER, argumentsList, build);
    const executable = path.join(output, "output", "file-helper");
    await fs.chmod(executable, 0o500);
    const native = await read(executable, 4194304, { protectedInput: false });
    const record = buildRecord(job, directory, {
      schemaVersion: 2,
      purpose: "experiment",
      candidateSha: job.candidateSha,
      sourceSha256,
      compiler: {
        file: COMPILER,
        sha256: compilerRead.sha256,
        version: compilerVersion,
      },
      sdk: { file: SDK, sha256: sdkRead.sha256, version: sdkVersion },
      arguments: argumentsList,
      commands,
      executable,
      sha256: native.sha256,
      abi: verifyLinuxFileElf(native.bytes),
    });
    const components = [
      await verifyLinuxExperimentBuild(job, directory, record, { read }),
    ];
    const sources = [
      { id: "file-helper", sha256: sourceSha256 },
      { id: "build-command", sha256: observationDigest(commands) },
      { id: "namespace-binding", sha256: observationDigest(namespace) },
      { id: "node-interpreter", sha256: observationDigest(interpreter) },
    ];
    const tools = [
      ["compiler", record.compiler],
      ["sdk", record.sdk],
    ].map(([id, tool]) => ({ id, sha256: tool.sha256, version: tool.version }));
    const sdk = { build: sdkVersion, sha256: sdkRead.sha256 };
    const expected = {
      binding,
      sources,
      tools,
      sdk,
      components: components.map(
        ({ identityBefore, identityAfter, held, independent, ...entry }) => ({
          ...entry,
          role: "helper",
        }),
      ),
    };
    requireObservation(
      (await checkout()) === job.candidateSha &&
        digest(await fs.readFile(SOURCE)) === sourceSha256,
    );
    active();
    const recordBytes = JSON.stringify(record) + "\n";
    requireObservation(Buffer.byteLength(recordBytes) <= 1048576);
    await fs.writeFile(
      path.join(preparation, "build-record.json"),
      recordBytes,
      { flag: "wx", mode: 0o400 },
    );
    await save(
      recordExperimentPreparation(job, expected, {
        binding,
        sources,
        tools,
        sdk,
        components,
        independent: true,
        readSha256: observationDigest({ components, commands, interpreter }),
      }),
    );
    await save(
      recordExperimentPreparationEffect(
        job,
        effect(
          { status: "RETIRED", independent: true, emergencyCleanup: false },
          observationDigest(record),
        ),
      ),
    );
  } catch (error) {
    nativeException("linux-experiment-preparation", error);
    try {
      await onFailure(job, error);
    } catch (diagnosticError) {
      nativeException(
        "linux-experiment-preparation-diagnostics",
        diagnosticError,
      );
      throw error;
    } finally {
      job = normalizeExperimentJob({ ...job, failure: "preparation-failed" });
      try {
        await persist(job);
      } catch (persistenceError) {
        nativeException(
          "linux-experiment-preparation-persistence",
          persistenceError,
        );
        throw error;
      }
    }
  }
  return job;
}

export async function loadLinuxExperiment(input, directory, options = {}) {
  const job = normalizeExperimentJob(input);
  worker(
    job,
    options.env ?? process.env,
    options.platform ?? process.platform,
    options.architecture ?? process.arch,
  );
  requireObservation(
    job.preparation !== null && retired(job.preparationEffects.settlement),
  );
  const rejoin = options.rejoinInterpreter ?? rejoinLinuxExperimentInterpreter;
  const interpreter = await rejoin(job, directory, options);
  const record = JSON.parse(
    await (options.readIntent ?? readProtectedEvidence)(
      path.join(directory, "preparation", "build-record.json"),
    ),
  );
  const observed = await verifyLinuxExperimentBuild(
    job,
    directory,
    record,
    options,
  );
  normalizeExperimentJob({
    ...job,
    preparation: {
      ...job.preparation,
      observed: { ...job.preparation.observed, components: [observed] },
    },
  });
  return {
    purpose: "experiment",
    record,
    interpreter,
    observeRuntime: async () => {
      await rejoin(job, directory, options);
      return verifyLinuxExperimentBuild(job, directory, record, options);
    },
    build: async (reference, _directory, fixture, supplied) => {
      requireObservation(
        reference.candidateSha === job.candidateSha &&
          reference.purpose === "experiment" &&
          reference.buildObservationSha256 === observationDigest(record) &&
          observationDigest(supplied) === observationDigest(record),
      );
      await verifyLinuxExperimentBuild(job, directory, record, options);
      const { executable, ...evidence } = record;
      await (options.write ?? writeFile)(
        path.join(fixture.directory, "evidence", "helper-build.json"),
        JSON.stringify(evidence) + "\n",
        { flag: "wx", mode: 0o400 },
      );
      return { purpose: "experiment", build: record };
    },
  };
}

/** Only a completed ordinary command record can settle preparation after owner
 * loss. An interrupted compiler has no such record and retains uncertainty. */
export async function recoverLinuxExperimentPreparation(
  input,
  directory,
  persist,
  {
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
    fs = { lstat },
    read = readProtectedEvidence,
    identity = readProcessIdentity,
    visible = assertLinuxProcVisibility,
    reconcile = false,
    rejoinInterpreter = rejoinLinuxExperimentInterpreter,
    readObserved = readLinuxObservedFile,
  } = {},
) {
  const job = normalizeExperimentJob(input);
  worker(job, env, platform, architecture);
  if (
    job.preparationEffects.admission === "not-started" ||
    (retired(job.preparationEffects.settlement) && !reconcile)
  )
    return job;
  let settlement = {
      status: "UNVERIFIABLE",
      independent: false,
      emergencyCleanup: job.preparationEffects.settlement.emergencyCleanup,
    },
    receiptSha256 = null;
  try {
    const owner = preparationOwner(
      job,
      JSON.parse(
        await read(path.join(directory, "experiment-preparation-owner.json")),
      ),
    );
    await visible();
    requireObservation((await identity(owner.pid)) === null);
    try {
      await fs.lstat(`/proc/${owner.pid}`);
      throw new Error("Preparer remains present");
    } catch (error) {
      requireObservation(["ENOENT", "ESRCH"].includes(error.code));
    }
    await visible();
    const interpreter = await rejoinInterpreter(job, directory, {
      readIntent: read,
    });
    const record = JSON.parse(
      await read(path.join(directory, "preparation", "build-record.json")),
    );
    await verifyLinuxExperimentBuild(job, directory, record, {
      read: readObserved,
    });
    requireObservation(interpreter && !settlement.emergencyCleanup);
    settlement = {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    };
    receiptSha256 = observationDigest(record);
  } catch (error) {
    nativeException("linux-experiment-retirement", error);
  }
  if (retired(job.preparationEffects.settlement)) {
    requireObservation(retired(settlement));
    return job;
  }
  const recovered = recordExperimentPreparationEffect(
    job,
    effect(settlement, receiptSha256),
  );
  await persist(recovered);
  return recovered;
}
