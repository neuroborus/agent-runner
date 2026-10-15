import { execFile } from "node:child_process";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
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
import { protectedLibraries } from "./confinement.js";
import {
  readLinuxObservedFile,
  digest,
  protectedReceipt,
  readProtectedEvidence,
  assertLinuxProcVisibility,
} from "./inspect.js";
import {
  normalizeLinuxFileBuildPins,
  verifyLinuxFileElf,
  LINUX_FILE_BUILD_ARGUMENTS,
  LINUX_FILE_BUILD_PROGRAMS,
  linuxFileBuildInvocation,
} from "./file-build.js";
import {
  buildWithReceipts,
  freshVerifier,
  runLinuxBuildCommand,
  linuxExperimentQueryArguments,
  LINUX_EXPERIMENT_QUERIES,
} from "./proof.js";
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
const COMPILER = "/usr/bin/x86_64-linux-gnu-gcc-13",
  SDK = "/usr/bin/x86_64-linux-gnu-ld.bfd";
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

/** Paths are private discovery data, never approval or public diagnostics. */
export function linuxExperimentHeaders(output, source) {
  requireObservation(
    typeof output === "string" &&
      Buffer.byteLength(output) <= 65536 &&
      output.startsWith("file-helper:") &&
      !/[\u0000\r]/u.test(output),
  );
  const members = output
    .slice("file-helper:".length)
    .replace(/\\\n/gu, " ")
    .trim()
    .split(/\s+/u);
  requireObservation(
    members.includes(source) &&
      members.length <= 512 &&
      members.every(
        (member) =>
          member === source ||
          /^\/usr\/(?:include|lib\/gcc)\/[A-Za-z0-9_.+/-]+$/u.test(member),
      ),
  );
  return [...new Set(members.filter((member) => member !== source))].sort();
}

/** Fixed discovery paths must resolve to the canonical tools later snapshotted. */
export async function linuxExperimentProgram(
  program,
  reported,
  { resolve = realpath } = {},
) {
  const binding = LINUX_FILE_BUILD_PROGRAMS[program];
  requireObservation(
    typeof reported === "string" && binding && reported === binding.target,
  );
  requireObservation((await resolve(binding.target)) === binding.source);
  return binding;
}

async function inputsFor(
  job,
  directory,
  source,
  commands,
  { read, command, libraries, remaining },
) {
  const sourceRead = await read(source, 65536, { protectedInput: false });
  const request = async (file, args, extra = {}) => {
    const image = await read(file);
    requireObservation(remaining() >= 25000);
    const intent = {
      candidateSha: job.candidateSha,
      platform: "linux",
      file,
      args,
      cwd: directory,
      env: ENV,
      deadlineMs: 20000,
      toolSha256: image.sha256,
    };
    const index = commands.length;
    await writeFile(
      path.join(directory, `intent-${index}.json`),
      JSON.stringify({ purpose: "experiment", request: intent }) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    const result = await command(intent, extra);
    requireObservation(
      result.exitCode === 0 &&
        result.independent === true &&
        retired(result.settlement) &&
        result.toolSha256 === image.sha256 &&
        (await read(file)).sha256 === image.sha256,
    );
    commands.push(result.receipt);
    return result.stdout;
  };
  const compilerVersion = /\b(13\.[0-9]+\.[0-9]+)\s*$/u.exec(
    (await request(COMPILER, ["--version"])).split("\n")[0],
  )?.[1];
  requireObservation(compilerVersion);
  const sdkVersion = (await request(SDK, ["--version"])).split("\n")[0];
  const query = (name) =>
    request(COMPILER, linuxExperimentQueryArguments(source, name), {
      experimentSource: { path: source, sha256: sourceRead.sha256 },
      experimentQuery: name,
    });
  const paths = new Map([[COMPILER, COMPILER]]);
  for (const member of linuxExperimentHeaders(await query("headers"), source))
    paths.set(member, await realpath(member));
  for (const program of Object.keys(LINUX_FILE_BUILD_PROGRAMS)) {
    const { source: canonical, target } = await linuxExperimentProgram(
      program,
      (await query(`-print-prog-name=${program}`)).trim(),
    );
    paths.set(target, canonical);
    for (const member of await libraries(canonical))
      paths.set(member.target, member.source);
  }
  for (const file of [
    "libgcc.a",
    "libgcc_eh.a",
    "liblto_plugin.so",
    "crtbeginT.o",
    "crtend.o",
    "libc.a",
    "libc_nonshared.a",
    "crt1.o",
    "crti.o",
    "crtn.o",
  ]) {
    const target = path.normalize(
      (await query(`-print-file-name=${file}`)).trim(),
    );
    requireObservation(path.isAbsolute(target));
    paths.set(target, await realpath(target));
    if (file === "liblto_plugin.so")
      for (const member of await libraries(await realpath(target)))
        paths.set(member.target, member.source);
  }
  for (const member of await libraries(COMPILER))
    paths.set(member.target, member.source);
  const inputs = [],
    identities = [];
  let total = 0;
  for (const [target, canonical] of [...paths].sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    const actual = await read(canonical, 67108864);
    total += actual.bytes.length;
    requireObservation(total <= 67108864);
    inputs.push({ source: canonical, target, sha256: actual.sha256 });
    identities.push(actual.identitySha256);
  }
  requireObservation(
    (await read(source, 65536, { protectedInput: false })).sha256 ===
      sourceRead.sha256,
  );
  return {
    pins: normalizeLinuxFileBuildPins(
      {
        schemaVersion: 1,
        candidateSha: job.candidateSha,
        sourceSha256: sourceRead.sha256,
        compilerVersion,
        inputs,
      },
      job.candidateSha,
    ),
    sdkVersion,
    identities,
  };
}

/** Rejoin original compiler receipts and bytes; verification never recompiles. */
export async function verifyLinuxExperimentBuild(
  job,
  directory,
  record,
  {
    read = readLinuxObservedFile,
    verify = freshVerifier,
    receipt = protectedReceipt,
    readIntent = readProtectedEvidence,
  } = {},
) {
  observationObject(record, [
    "purpose",
    "candidateSha",
    "pins",
    "built",
    "commands",
  ]);
  requireObservation(
    record.purpose === "experiment" && record.candidateSha === job.candidateSha,
  );
  const pins = normalizeLinuxFileBuildPins(record.pins, job.candidateSha),
    built = record.built;
  requireObservation(
    Object.values(LINUX_FILE_BUILD_PROGRAMS).every(({ source, target }) =>
      pins.inputs.some(
        (input) => input.source === source && input.target === target,
      ),
    ),
  );
  requireObservation(
    built.build.candidateSha === job.candidateSha &&
      built.build.executable ===
        path.join(directory, "build", "output", "file-helper") &&
      built.build.sourceSha256 === pins.sourceSha256 &&
      built.build.compiler.file === COMPILER &&
      built.build.compiler.version === pins.compilerVersion &&
      built.build.compiler.sha256 ===
        pins.inputs.find(({ target }) => target === COMPILER)?.sha256 &&
      observationDigest(built.build.inputs) ===
        observationDigest(pins.inputs) &&
      observationDigest(built.build.arguments) ===
        observationDigest(LINUX_FILE_BUILD_ARGUMENTS) &&
      retired(built.settlement) &&
      built.receipts.length === 2 &&
      record.commands.length === 2 + LINUX_EXPERIMENT_QUERIES.length,
  );
  for (const [index, member] of [
    ...record.commands,
    ...built.receipts,
  ].entries()) {
    let expected, request;
    if (index < record.commands.length) {
      const intent = JSON.parse(
        (
          await readIntent(
            path.join(directory, "preparation", `intent-${index}.json`),
          )
        ).toString(),
      );
      observationObject(intent, ["purpose", "request"]);
      request = intent.request;
      observationObject(request, [
        "candidateSha",
        "platform",
        "file",
        "args",
        "cwd",
        "env",
        "deadlineMs",
        "toolSha256",
      ]);
      requireObservation(
        intent.purpose === "experiment" &&
          request.candidateSha === job.candidateSha &&
          request.platform === "linux" &&
          request.file === (index === 1 ? SDK : COMPILER) &&
          request.cwd === path.join(directory, "preparation") &&
          request.deadlineMs === 20000 &&
          observationDigest(request.env) === observationDigest(ENV) &&
          observationDigest(request.args) ===
            observationDigest(
              index < 2
                ? ["--version"]
                : linuxExperimentQueryArguments(
                    path.join(directory, "preparation", "file-helper.c"),
                    LINUX_EXPERIMENT_QUERIES[index - 2],
                  ),
            ) &&
          request.toolSha256 === (await read(request.file)).sha256,
      );
      expected = path.join(
        request.cwd,
        `command-${observationDigest(request)}`,
        "command-0.json",
      );
    } else
      expected = path.join(
        directory,
        "build",
        `command-${index - record.commands.length}.json`,
      );
    requireObservation(member.file === expected);
    const actual = await receipt(member.file, member.sha256);
    requireObservation(
      actual.candidateSha === job.candidateSha &&
        actual.caseId === "argv" &&
        retired(await verify(member.file, member.sha256)),
    );
    if (request)
      requireObservation(
        actual.policyDigest === observationDigest(request) &&
          actual.executableDigest === request.toolSha256,
      );
    else {
      const commandIndex = index - record.commands.length;
      const intent = JSON.parse(
        (
          await readIntent(
            path.join(
              directory,
              "build",
              `command-${commandIndex}-possible.json`,
            ),
          )
        ).toString(),
      );
      observationObject(intent, ["candidateSha", "nonce", "policyDigest"]);
      requireObservation(
        intent.candidateSha === actual.candidateSha &&
          intent.nonce === actual.nonce &&
          intent.policyDigest === actual.policyDigest &&
          actual.executableDigest === (await read("/usr/bin/bwrap")).sha256 &&
          actual.policyDigest ===
            digest(
              JSON.stringify(
                linuxFileBuildInvocation(
                  path.join(directory, "build"),
                  pins,
                  commandIndex === 0
                    ? ["-dumpfullversion", "-dumpversion"]
                    : LINUX_FILE_BUILD_ARGUMENTS,
                ),
              ),
            ),
      );
    }
  }
  for (const file of [
    path.join(directory, "preparation", "file-helper.c"),
    path.join(directory, "build", "file-helper.c"),
  ])
    requireObservation(
      (await read(file, 65536, { protectedInput: false })).sha256 ===
        pins.sourceSha256,
    );
  for (const [index, input] of pins.inputs.entries()) {
    requireObservation(
      (await read(input.source, 67108864)).sha256 === input.sha256,
    );
    requireObservation(
      (
        await read(
          path.join(directory, "build", "inputs", String(index)),
          67108864,
          { protectedInput: false },
        )
      ).sha256 === input.sha256,
    );
  }
  return readHelper(record, read);
}

async function readHelper(record, read) {
  const built = record.built.build;
  const native = await read(built.executable, 4194304, {
    protectedInput: false,
  });
  requireObservation(
    native.sha256 === built.sha256 &&
      observationDigest(verifyLinuxFileElf(native.bytes)) ===
        observationDigest(built.abi),
  );
  return {
    id: "file-helper",
    sha256: native.sha256,
    format: "elf-x64",
    loader: [],
    bindings: {
      source: record.pins.sourceSha256,
      build: observationDigest(built),
      abi: observationDigest(built.abi),
    },
    identityBefore: native.identitySha256,
    identityAfter: native.identitySha256,
    held: true,
    independent: true,
  };
}

/** Ordinary preparation captures local observations only. Reviewed preparers
 * and publication/custody admission retain their independent strict validators. */
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
    command = runLinuxBuildCommand,
    libraries = protectedLibraries,
    build = buildWithReceipts,
    namespaces = verifyLinuxNamespaces,
    now = () => performance.now(),
    onFailure = (job, error) =>
      persistLinuxExperimentFailure(job, directory, "preparation", error),
    nodeVersion = process.version,
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
  const start = now(),
    deadline = start + 240000,
    commands = [];
  const save = async (next) => {
    job = normalizeExperimentJob(next);
    await persist(job);
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
      identity: await readProcessIdentity(process.pid),
    });
    await writeFile(
      path.join(directory, "experiment-preparation-owner.json"),
      JSON.stringify(owner) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    requireObservation(
      binding.nodeVersion === nodeVersion &&
        binding.osBuild === env.ImageVersion,
    );
    const namespaceContext = {
      candidateSha: job.candidateSha,
      runId: job.runId,
      runAttempt: String(job.runAttempt),
    };
    const namespace = await readLinuxNamespaceEvidence(
      path.join(directory, "linux-namespace-preparation.json"),
    );
    await namespaces(namespace, namespaceContext, directory);
    requireObservation(
      (await checkout()) === job.candidateSha &&
        binding.checkoutSha === job.candidateSha,
    );
    const preparation = path.join(directory, "preparation");
    await mkdir(preparation, { mode: 0o700 });
    await mkdir(path.join(preparation, "evidence"), { mode: 0o700 });
    const source = path.join(preparation, "file-helper.c");
    const original = await readFile(SOURCE);
    requireObservation(
      digest(original) === digest(await sourceBytes(job.candidateSha)),
    );
    await copyFile(SOURCE, source);
    await chmod(source, 0o400);
    requireObservation(
      (await read(source, 65536, { protectedInput: false })).sha256 ===
        digest(original),
    );
    const discovered = await inputsFor(job, preparation, source, commands, {
      read,
      command,
      libraries,
      remaining: () => deadline - now(),
    });
    requireObservation(now() + 60000 < deadline);
    await writeFile(
      path.join(preparation, "build-intent.json"),
      JSON.stringify({
        purpose: "experiment",
        candidateSha: job.candidateSha,
        pins: discovered.pins,
      }) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    const built = await build(
      job,
      directory,
      { directory: preparation, launcher: "/usr/bin/bwrap" },
      discovered.pins,
    );
    const record = {
      purpose: "experiment",
      candidateSha: job.candidateSha,
      pins: discovered.pins,
      built,
      commands,
    };
    const components = [
      await verifyLinuxExperimentBuild(job, directory, record, { read }),
    ];
    const tools = [];
    for (const [id, file, version] of [
      ["compiler", COMPILER, discovered.pins.compilerVersion],
      ["sdk", SDK, discovered.sdkVersion],
    ])
      tools.push({ id, sha256: (await read(file)).sha256, version });
    requireObservation(
      tools[0].sha256 ===
        discovered.pins.inputs.find(({ target }) => target === COMPILER)
          ?.sha256 &&
        discovered.pins.inputs.some(
          ({ source, sha256 }) => source === SDK && sha256 === tools[1].sha256,
        ),
    );
    const sources = [
      { id: "file-helper", sha256: discovered.pins.sourceSha256 },
      { id: "build-inputs", sha256: observationDigest(discovered.pins.inputs) },
      { id: "namespace-binding", sha256: observationDigest(namespace) },
    ];
    const sdk = {
      build: discovered.sdkVersion,
      sha256: tools.find(({ id }) => id === "sdk").sha256,
    };
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
        digest(await readFile(SOURCE)) === discovered.pins.sourceSha256 &&
        now() < deadline,
    );
    const observed = {
      binding: { ...binding, checkoutSha: await checkout() },
      sources,
      tools,
      sdk,
      components,
      independent: true,
      readSha256: observationDigest({
        components,
        identities: discovered.identities,
        commands,
        receipts: built.receipts,
      }),
    };
    await writeFile(
      path.join(preparation, "build-record.json"),
      JSON.stringify(record) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    await save(recordExperimentPreparation(job, expected, observed));
    await save(
      recordExperimentPreparationEffect(
        job,
        effect(
          { status: "RETIRED", independent: true, emergencyCleanup: false },
          observationDigest({ commands, receipts: built.receipts }),
        ),
      ),
    );
  } catch (error) {
    nativeException("linux-experiment-preparation", error);
    try {
      await onFailure(job, error);
    } finally {
      await save({ ...job, failure: "preparation-failed" });
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
  const record = JSON.parse(
    (
      await readProtectedEvidence(
        path.join(directory, "preparation", "build-record.json"),
      )
    ).toString(),
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
    observeRuntime: () =>
      readHelper(record, options.read ?? readLinuxObservedFile),
    build: async (reference, _directory, fixture, pins) => {
      requireObservation(
        reference.candidateSha === job.candidateSha &&
          observationDigest(pins) === observationDigest(record.pins),
      );
      await verifyLinuxExperimentBuild(job, directory, record, options);
      const { executable, ...buildRecord } = record.built.build;
      await writeFile(
        path.join(fixture.directory, "evidence", "helper-build.json"),
        JSON.stringify(buildRecord) + "\n",
        { flag: "wx", mode: 0o400 },
      );
      return record.built;
    },
  };
}

/** Recovery only rejoins original admissions. Missing birth/command receipts
 * retain uncertain ownership; neither recompilation nor child exit repairs it.
 * Evidence files are retained for reporting rather than released on uncertainty. */
export async function recoverLinuxExperimentPreparation(
  input,
  directory,
  persist,
  {
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
    fs = { readdir, lstat },
    read = readProtectedEvidence,
    receipt = protectedReceipt,
    verify = freshVerifier,
    identity = readProcessIdentity,
    visible = assertLinuxProcVisibility,
  } = {},
) {
  const job = normalizeExperimentJob(input);
  worker(job, env, platform, architecture);
  if (
    job.preparationEffects.admission === "not-started" ||
    retired(job.preparationEffects.settlement)
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
        (
          await read(path.join(directory, "experiment-preparation-owner.json"))
        ).toString(),
      ),
    );
    // A receipt prefix cannot close admissions while its original preparer lives.
    // A null identity can mean inaccessible. Require separate directory absence
    // under the existing full-procfs visibility check before closing admissions.
    await visible();
    const currentOwner = await identity(owner.pid);
    requireObservation(currentOwner === null);
    try {
      await fs.lstat(`/proc/${owner.pid}`);
      throw new Error("Preparer remains present");
    } catch (error) {
      requireObservation(["ENOENT", "ESRCH"].includes(error.code));
    }
    await visible();
    const preparation = path.join(directory, "preparation"),
      names = await fs.readdir(preparation),
      bindings = [];
    const intents = names
      .filter((name) => /^intent-[0-9]+\.json$/u.test(name))
      .sort((a, b) => Number(a.slice(7, -5)) - Number(b.slice(7, -5)));
    // An intent precedes controller creation; without its native receipt the
    // controller may have been released. Absence is never proof of non-admission.
    requireObservation(
      intents.length > 0 &&
        intents.length <= 2 + LINUX_EXPERIMENT_QUERIES.length,
    );
    for (const [index, name] of intents.entries()) {
      requireObservation(name === `intent-${index}.json`);
      const intent = JSON.parse(
        (await read(path.join(preparation, name))).toString(),
      );
      observationObject(intent, ["purpose", "request"]);
      const request = intent.request;
      observationObject(request, [
        "candidateSha",
        "platform",
        "file",
        "args",
        "cwd",
        "env",
        "deadlineMs",
        "toolSha256",
      ]);
      requireObservation(
        intent.purpose === "experiment" &&
          request.candidateSha === job.candidateSha &&
          request.platform === "linux" &&
          request.cwd === preparation &&
          request.file === (index === 1 ? SDK : COMPILER) &&
          request.deadlineMs === 20000 &&
          observationDigest(request.env) === observationDigest(ENV) &&
          observationDigest(request.args) ===
            observationDigest(
              index < 2
                ? ["--version"]
                : linuxExperimentQueryArguments(
                    path.join(preparation, "file-helper.c"),
                    LINUX_EXPERIMENT_QUERIES[index - 2],
                  ),
            ),
      );
      const file = path.join(
        preparation,
        `command-${observationDigest(request)}`,
        "command-0.json",
      );
      const sha256 = digest(await read(file)),
        native = await receipt(file, sha256);
      requireObservation(
        native.candidateSha === job.candidateSha &&
          native.caseId === "argv" &&
          native.policyDigest === observationDigest(request) &&
          native.executableDigest === request.toolSha256 &&
          retired(await verify(file, sha256)),
      );
      bindings.push({ file, sha256 });
    }
    if (names.includes("build-intent.json")) {
      const intent = JSON.parse(
        (await read(path.join(preparation, "build-intent.json"))).toString(),
      );
      observationObject(intent, ["purpose", "candidateSha", "pins"]);
      requireObservation(
        intent.purpose === "experiment" &&
          intent.candidateSha === job.candidateSha,
      );
      const pins = normalizeLinuxFileBuildPins(intent.pins, job.candidateSha);
      for (const index of [0, 1]) {
        const file = path.join(directory, "build", `command-${index}.json`),
          sha256 = digest(await read(file)),
          native = await receipt(file, sha256);
        const marker = JSON.parse(
          (
            await read(
              path.join(directory, "build", `command-${index}-possible.json`),
            )
          ).toString(),
        );
        observationObject(marker, ["candidateSha", "nonce", "policyDigest"]);
        requireObservation(
          native.candidateSha === job.candidateSha &&
            native.caseId === "argv" &&
            marker.candidateSha === native.candidateSha &&
            marker.nonce === native.nonce &&
            marker.policyDigest === native.policyDigest &&
            native.policyDigest ===
              digest(
                JSON.stringify(
                  linuxFileBuildInvocation(
                    path.join(directory, "build"),
                    pins,
                    index === 0
                      ? ["-dumpfullversion", "-dumpversion"]
                      : LINUX_FILE_BUILD_ARGUMENTS,
                  ),
                ),
              ) &&
            retired(await verify(file, sha256)),
        );
        bindings.push({ file, sha256 });
      }
    }
    requireObservation(!settlement.emergencyCleanup);
    settlement = {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    };
    receiptSha256 = observationDigest({ owner, currentOwner, bindings });
  } catch (error) {
    nativeException("linux-experiment-retirement", error);
    /* Retain uncertainty and the original preparation failure. */
  }
  const recovered = recordExperimentPreparationEffect(
    job,
    effect(settlement, receiptSha256),
  );
  await persist(recovered);
  return recovered;
}
