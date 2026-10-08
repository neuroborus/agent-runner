import * as filesystem from "node:fs/promises";
import { observationDigest, requireObservation } from "../observation.js";
import {
  createDarwinCustodyReader,
  DARWIN_HELPER_NAMES,
  darwinProviderCIContract,
} from "../darwin/index.js";
import {
  createWindowsCustodyReader,
  WINDOWS_HELPER_NAMES,
  windowsProviderCIContract,
} from "../win32/index.js";
import {
  runLinuxBuildCommand,
  freshVerifier,
  processDetails,
  linuxProviderBuildArguments,
  linuxProviderCIContract,
} from "../linux/index.js";
import { createProviderPreparationFiles } from "./preparation-files.js";
import {
  providerBuildInvocation,
  providerBytesDigest,
  providerPaths,
  providerRetired,
  providerHash,
} from "./preparation.js";

const settled = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;
const same = (a, b) => observationDigest(a) === observationDigest(b);

/** Credential-free, effect-free construction. Approved bootstrap assets own
 * native file/custody reads; only raw filesystem, process and IPC edges vary.
 * Darwin/Windows rejoin existing platform helpers and never compile again. */
export function createProviderPreparationEffects(input, options = {}) {
  const value = structuredClone({
      job: input.job,
      manifest: input.manifest,
      buildManifest: input.buildManifest,
      directory: input.directory,
      helpers: input.helpers,
      providerHelpers: input.providerHelpers,
      preparation: input.preparation,
    }),
    { job, manifest, buildManifest, directory } = value,
    plan = manifest.providerPreparation,
    paths = providerPaths(job.platform),
    fs = options.fs ?? filesystem;
  const buildRequest = () => ({
    candidateSha: job.candidateSha,
    platform: job.platform,
    reviewSha256: observationDigest(manifest),
    helpers: manifest.helpers,
    tools: buildManifest.tools,
    output: value.providerHelpers,
    deadlineMs: 120000,
    commands: {
      linux: linuxProviderCIContract,
      darwin: darwinProviderCIContract,
      win32: windowsProviderCIContract,
    }[job.platform]({
      tools: buildManifest.tools,
      output: value.providerHelpers,
      sourceDirectory: plan.sourceDirectory,
    }).commands,
  });
  let files,
    fileReader,
    fileStarting,
    fileSequence,
    fenced = false;
  const guard = (signal) => requireObservation(!signal?.aborted);
  const rawPersist = async (record) => {
    const file = paths.join(
      directory,
      `provider-bootstrap-files-${fileSequence}-custody-${record.sequence}.json`,
    );
    const proof = await fileOwner().writeBootstrap({
      file,
      bytes: Buffer.from(JSON.stringify(record) + "\n"),
      exclusive: true,
    });
    return { path: file, sha256: proof.sha256 };
  };
  const darwinReader = (declaration, settings) =>
    createDarwinCustodyReader(declaration, {
      fs,
      ...options.readerOptions,
      providerPreparation: true,
      ...settings,
    });
  const ensureDarwin = () =>
    (fileStarting ??= (async () => {
      const names = await fs.readdir(directory);
      requireObservation(names.length <= 65536);
      fileSequence =
        1 +
        Math.max(
          -1,
          ...names.map((name) =>
            Number(
              /^provider-bootstrap-files-([0-9]+)-intent\.json$/u.exec(
                name,
              )?.[1] ?? -1,
            ),
          ),
        );
      requireObservation(
        Number.isSafeInteger(fileSequence) && fileSequence <= 65535,
      );
      await fileOwner().writeBootstrap({
        file: paths.join(
          directory,
          `provider-bootstrap-files-${fileSequence}-intent.json`,
        ),
        bytes: Buffer.from(
          JSON.stringify({
            status: "POSSIBLE",
            context: plan.bootstrap.context,
            bootstrapSha256: observationDigest(plan.bootstrap),
          }) + "\n",
        ),
        exclusive: true,
      });
      fileReader = darwinReader(plan.bootstrap, { persist: rawPersist });
      const admitted = await fileReader.start();
      requireObservation(
        admitted.independent === true &&
          admitted.planSha256 === plan.bootstrap.plan.sha256,
      );
      return fileReader;
    })());
  const fileOwner = () =>
    (files ??= createProviderPreparationFiles(
      value,
      options,
      async (file, pin, directory) =>
        (await ensureDarwin()).observePreparation(file, pin, directory),
    ));
  const read = async (file, pin, maximum = 134217728, receipt = false) =>
    (await fileOwner().readProtected({ file, sha256: pin, maximum, receipt }))
      .bytes;
  const assets = async (signal) => {
    for (const tool of buildManifest.tools) {
      guard(signal);
      await read(tool.path, tool.sha256);
    }
    if (job.platform !== "linux") {
      requireObservation(
        manifest.helpers.length === 0 &&
          Array.isArray(buildManifest.helpers) &&
          buildManifest.helpers.length > 0,
      );
      const fixed =
        job.platform === "win32" ? WINDOWS_HELPER_NAMES : DARWIN_HELPER_NAMES;
      requireObservation(
        buildManifest.helpers.length === fixed.length &&
          new Set(buildManifest.helpers.map(({ name }) => name)).size ===
            fixed.length &&
          fixed.every((name) =>
            buildManifest.helpers.some((helper) => helper.name === name),
          ),
      );
      for (const helper of buildManifest.helpers) {
        guard(signal);
        requireObservation(
          providerHash(helper.sha256) && providerHash(helper.sourceSha256),
        );
        await read(
          paths.join(plan.sourceDirectory, helper.name + ".c"),
          helper.sourceSha256,
          1048576,
        );
        await read(
          paths.join(
            value.helpers,
            helper.name + (job.platform === "win32" ? ".exe" : ""),
          ),
          helper.sha256,
        );
      }
    }
  };
  const verifyCommands = async (request, commands, signal) => {
    requireObservation(
      Array.isArray(commands) &&
        commands.length === request.commands.length &&
        (job.platform === "linux" || commands.length === 0),
    );
    const observations = [];
    for (const [index, result] of commands.entries()) {
      guard(signal);
      const invocation = providerBuildInvocation(
        request,
        request.commands[index],
      );
      requireObservation(
        settled(result.settlement) &&
          result.requestSha256 === observationDigest(invocation) &&
          invocation.toolSha256 === result.toolSha256,
      );
      await read(invocation.file, invocation.toolSha256);
      const file = paths.join(
          request.output,
          `command-${result.requestSha256}`,
          "command-0.json",
        ),
        bytes = await read(file, null, 1048576),
        receipt = JSON.parse(bytes),
        sha256 = providerBytesDigest(bytes);
      requireObservation(
        result.receipt?.file === file &&
          result.receipt.sha256 === sha256 &&
          receipt.candidateSha === request.candidateSha &&
          receipt.policyDigest === observationDigest(invocation) &&
          receipt.executableDigest === invocation.toolSha256 &&
          same(result.identity, {
            pid: receipt.init.pid,
            ...receipt.init.identity,
          }),
      );
      const proof = await freshVerifier(file, sha256, {
        executeFile: options.verifierTransport,
      });
      requireObservation(settled(proof));
      guard(signal);
      observations.push({ receipt, proof });
    }
    return observations;
  };
  const closeFiles = async () => {
    const observations = [];
    if (fileStarting) {
      await fileStarting;
      const result = await fileReader.close();
      requireObservation(providerRetired(result) && result.closed === true);
      observations.push(result);
    }
    if (files) {
      const result = await files.settleFiles();
      requireObservation(
        job.platform === "win32"
          ? providerRetired(result) &&
              result.noLiveMembers === true &&
              result.taskRemoved === true
          : result.status === "CLOSED" && result.custodianRetired === false,
      );
      observations.push(result);
    }
    files = undefined;
    fileStarting = undefined;
    fileReader = undefined;
    return {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
      noLiveMembers: true,
      nativeEventSha256: observationDigest(observations),
      observations,
    };
  };
  return {
    verifyDirectory: (request) => fileOwner().verifyDirectory(request),
    readProtected: (request) => fileOwner().readProtected(request),
    writeProtected: (request) => fileOwner().writeProtected(request),
    listReceipts: (request) => fileOwner().listReceipts(request),
    ...(job.platform === "linux"
      ? {}
      : {
          createReader(declaration, settings) {
            requireObservation(!fenced);
            return job.platform === "win32"
              ? createWindowsCustodyReader(declaration, {
                  ...options.readerOptions,
                  fs: {
                    readFile: (file) => {
                      const pin = [
                        declaration.bridge,
                        declaration.reader,
                        declaration.plan,
                        ...declaration.sources,
                      ].find((entry) => entry.path === file);
                      requireObservation(pin);
                      return read(file, pin.sha256);
                    },
                  },
                  verificationReader: fileOwner().native,
                  ...settings,
                })
              : darwinReader(declaration, settings);
          },
        }),
    async openLinuxCustody(declaration, { signal, persist }) {
      let admitted,
        closed = false;
      return {
        async start() {
          requireObservation(!admitted && !closed && !fenced);
          guard(signal);
          await persist({
            phase: "linux-reader-possible",
            context: declaration.context,
          });
          admitted = await (options.processTransport ?? processDetails)(
            process.pid,
          );
          requireObservation(
            admitted?.identity && admitted.pid === process.pid,
          );
          guard(signal);
          return {
            independent: true,
            context: declaration.context,
            nativeEventSha256: observationDigest(admitted),
          };
        },
        async close() {
          requireObservation(admitted && !closed);
          guard(signal);
          const actual = await (options.processTransport ?? processDetails)(
            process.pid,
          );
          requireObservation(
            actual?.pid === admitted.pid &&
              same(actual.identity, admitted.identity),
          );
          closed = true;
          return {
            status: "RETIRED",
            independent: true,
            emergencyCleanup: false,
            closed: true,
            nativeEventSha256: observationDigest(actual),
          };
        },
      };
    },
    async provisionBuild({ request }, { signal }) {
      requireObservation(!fenced && same(request, buildRequest()));
      guard(signal);
      await assets(signal);
      if (job.platform === "linux") {
        requireObservation(
          manifest.helpers.length === 1 &&
            manifest.helpers[0].name === "provider-gate" &&
            request.commands.length === 1,
        );
        await fileOwner().provisionBuild();
      } else requireObservation(request.commands.length === 0);
    },
    async runCommand(invocation, _reader, { signal }) {
      requireObservation(!fenced && job.platform === "linux");
      guard(signal);
      const source = manifest.helpers.find(
          ({ name }) => name === "provider-gate",
        ),
        sourcePath = paths.join(plan.sourceDirectory, "provider-gate.c");
      requireObservation(
        source &&
          same(
            invocation.args,
            linuxProviderBuildArguments(sourcePath, value.providerHelpers),
          ),
      );
      await read(sourcePath, source.sourceSha256, 1048576);
      const result = await runLinuxBuildCommand(invocation, {
        ...options.commandTransport,
        signal,
        env: options.env,
        providerSource: { path: sourcePath, sha256: source.sourceSha256 },
      });
      await read(sourcePath, source.sourceSha256, 1048576);
      guard(signal);
      return {
        ...result,
        settlement: {
          ...result.settlement,
          nativeEventSha256: observationDigest({
            receipt: result.receipt,
            proof: result.settlement,
          }),
        },
      };
    },
    async verifyBuild({ request, commands }, { signal }) {
      requireObservation(same(request, buildRequest()));
      guard(signal);
      await assets(signal);
      const observations = await verifyCommands(request, commands, signal);
      return {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        requestSha256: observationDigest(request),
        commandsSha256: observationDigest(commands),
        noLiveMembers: true,
        nativeEventSha256: observationDigest(observations),
      };
    },
    async verifyPrepared({ request, receipt }, { signal }) {
      guard(signal);
      requireObservation(
        same(request, buildRequest()) &&
          providerRetired(value.preparation?.filesSettlement) &&
          value.preparation.filesSettlement.noLiveMembers === true &&
          Array.isArray(value.preparation.filesSettlement.observations),
      );
      await assets(signal);
      const observations = await verifyCommands(
        request,
        receipt.commands,
        signal,
      );
      requireObservation(
        providerRetired(receipt.custody) &&
          receipt.custody.closed === true &&
          (job.platform !== "win32" || receipt.custody.taskRemoved === true),
      );
      if (job.platform === "win32") {
        requireObservation(
          value.preparation.filesSettlement.observations.length === 1,
        );
        const owners = [
          {
            nonce: plan.bootstrap.nonce,
            identities: [receipt.custody.helper, receipt.custody.bridge],
          },
        ];
        for (const owner of value.preparation.filesSettlement.observations) {
          requireObservation(
            providerRetired(owner) &&
              owner.taskRemoved === true &&
              owner.helper &&
              owner.bridge,
          );
          owners.push({
            nonce: owner.nonce,
            identities: [owner.helper, owner.bridge],
          });
        }
        observations.push(
          await fileOwner().native.verify(
            "verifyPreparation",
            plan.bootstrap,
            owners,
          ),
        );
      } else if (job.platform === "darwin") {
        requireObservation(
          value.preparation.filesSettlement.observations.length === 2 &&
            value.preparation.filesSettlement.observations.filter(
              (entry) => entry.helper,
            ).length === 1,
        );
        const reader = await ensureDarwin();
        observations.push(
          await reader.retiredRootDomain(receipt.custody.helper),
        );
        observations.push(await reader.retired(receipt.custody.verifier));
        for (const owner of value.preparation.filesSettlement.observations.filter(
          (entry) => entry.helper,
        )) {
          requireObservation(providerRetired(owner) && owner.closed === true);
          observations.push(
            await reader.retiredRootDomain(owner.helper),
            await reader.retired(owner.verifier),
          );
        }
      }
      const filesSettlement = await closeFiles();
      guard(signal);
      return {
        ...filesSettlement,
        requestSha256: observationDigest(request),
        unchanged: true,
        nativeEventSha256: observationDigest({ observations, filesSettlement }),
      };
    },
    settlePreparation: closeFiles,
    async openRecovery({ signal }) {
      guard(signal);
      if (job.platform === "darwin") return { reader: await ensureDarwin() };
      if (job.platform === "win32") {
        await fileOwner().verifyDirectory({
          directory,
          context: plan.bootstrap.context,
        });
        return { reader: fileOwner().native };
      }
      const actual = await (options.processTransport ?? processDetails)(
        process.pid,
      );
      requireObservation(actual?.pid === process.pid && actual.identity);
      return { reader: null, actual };
    },
    async closeRecovery(current, { signal }) {
      guard(signal);
      if (job.platform === "linux") {
        const actual = await (options.processTransport ?? processDetails)(
          process.pid,
        );
        requireObservation(same(actual.identity, current.actual.identity));
        return actual;
      }
      return { bootstrapSha256: observationDigest(plan.bootstrap) };
    },
    async recoverPreparation({ request, records, reader }, { signal }) {
      fenced = true;
      guard(signal);
      requireObservation(
        records.every(({ name }) => !name.startsWith("provider-case-")),
      );
      const observations = [],
        subjects = [],
        taskOwners = [],
        observerOwners = [],
        byName = new Map(records.map(({ name, record }) => [name, record]));
      requireObservation(byName.size === records.length);
      for (const { name, record } of records) {
        requireObservation(
          record && Object.getPrototypeOf(record) === Object.prototype,
        );
        const bootstrap =
            /^(provider-bootstrap-(?:files-)?[0-9]+-)(intent|result|custody-[0-9]+)\.json$/u.exec(
              name,
            ),
          build =
            /^(provider-build-([a-f0-9]{64})-)(intent|result|command-([0-9]+)-(intent|result))\.json$/u.exec(
              name,
            ),
          recovery =
            /^provider-recovery-[a-f0-9]{64}-[0-9]+-(intent|result)\.json$/u.exec(
              name,
            ),
          observer =
            /^(windows-files-[a-f0-9]{32}-)(intent|birth|result|[0-9]+)\.json$/u.exec(
              name,
            );
        requireObservation(
          bootstrap ||
            build ||
            recovery ||
            (job.platform === "win32" && observer),
        );
        if (bootstrap) {
          requireObservation(byName.has(bootstrap[1] + "intent.json"));
          if (bootstrap[2] === "result")
            requireObservation(
              providerRetired(record) && record.closed === true,
            );
        }
        if (build) {
          const intent = byName.get(build[1] + "intent.json");
          requireObservation(
            intent &&
              same(intent.request, buildRequest()) &&
              build[2] === observationDigest(intent.request),
          );
          if (build[4] !== undefined) {
            const command = intent.request.commands[Number(build[4])];
            requireObservation(command);
            const invocation = providerBuildInvocation(intent.request, command),
              commandIntent = byName.get(
                build[1] + `command-${build[4]}-intent.json`,
              );
            requireObservation(
              commandIntent?.status === "POSSIBLE" &&
                same(commandIntent.invocation, invocation),
            );
            if (build[5] === "result")
              requireObservation(
                record.requestSha256 === observationDigest(invocation) &&
                  settled(record.settlement),
              );
          } else if (build[3] === "result")
            requireObservation(
              record.status === "OBSERVED" &&
                record.independent === true &&
                record.requestSha256 === build[2] &&
                providerRetired(record.settlement),
            );
        }
        if (recovery) {
          const intent = byName.get(
            name.replace(/(?:intent|result)\.json$/u, "intent.json"),
          );
          requireObservation(
            intent?.status === "POSSIBLE" &&
              intent.request?.candidateSha === job.candidateSha &&
              intent.request.platform === job.platform &&
              intent.request.jobSha256 === observationDigest(job) &&
              providerHash(intent.request.preparationSha256) &&
              intent.request.deadlineMs === 120000 &&
              name.startsWith(
                `provider-recovery-${observationDigest(intent.request)}-`,
              ),
          );
          if (recovery[1] === "result")
            requireObservation(
              providerRetired(record) &&
                record.requestSha256 === observationDigest(intent.request),
            );
        }
        if (observer)
          requireObservation(byName.has(observer[1] + "intent.json"));
        if (/^provider-bootstrap-(?:files-)?[0-9]+-intent\.json$/u.test(name)) {
          requireObservation(
            record.status === "POSSIBLE" &&
              same(record.context, plan.bootstrap.context),
          );
          if (name.startsWith("provider-bootstrap-files-"))
            requireObservation(
              record.bootstrapSha256 === observationDigest(plan.bootstrap),
            );
          else
            requireObservation(
              record.selectedSystemSha256 ===
                observationDigest(job.selectedSystem),
            );
          const prefix = name.slice(0, -"intent.json".length),
            custody = records
              .filter((entry) => entry.name.startsWith(prefix + "custody-"))
              .sort((a, b) => a.record.sequence - b.record.sequence);
          requireObservation(
            custody.every(
              (entry, index) =>
                entry.name === `${prefix}custody-${index}.json` &&
                same(entry.record.context, plan.bootstrap.context) &&
                (job.platform === "linux"
                  ? index === 0 &&
                    entry.record.phase === "linux-reader-possible"
                  : (job.platform !== "darwin" ||
                      entry.record.schemaVersion === 1) &&
                    entry.record.sequence === index &&
                    entry.record.reviewSha256 === plan.bootstrap.reviewSha256 &&
                    (job.platform !== "darwin" ||
                      entry.record.requestSha256 ===
                        providerBytesDigest(
                          Buffer.from(JSON.stringify(entry.record.request)),
                        ))),
            ),
          );
          if (job.platform !== "linux")
            requireObservation(
              custody.some(({ record }) => record.phase === "admitted"),
            );
        }
        if (/^provider-build-[a-f0-9]{64}-intent\.json$/u.test(name)) {
          requireObservation(
            record.status === "POSSIBLE" &&
              same(record.request, buildRequest()) &&
              name ===
                `provider-build-${observationDigest(record.request)}-intent.json`,
          );
          for (const [index, command] of record.request.commands.entries()) {
            const invocation = providerBuildInvocation(record.request, command),
              prefix =
                name.slice(0, -"intent.json".length) + `command-${index}-`;
            const intent = byName.get(prefix + "intent.json");
            if (!intent) continue;
            requireObservation(
              intent.status === "POSSIBLE" &&
                same(intent.invocation, invocation) &&
                job.platform === "linux",
            );
            const file = paths.join(
                invocation.cwd,
                `command-${observationDigest(invocation)}`,
                "command-0.json",
              ),
              bytes = await read(file, null, 1048576),
              raw = JSON.parse(bytes);
            requireObservation(
              raw.candidateSha === job.candidateSha &&
                raw.policyDigest === observationDigest(invocation) &&
                raw.executableDigest === invocation.toolSha256,
            );
            const proof = await freshVerifier(
              file,
              providerBytesDigest(bytes),
              { executeFile: options.verifierTransport },
            );
            requireObservation(settled(proof));
            observations.push(proof);
          }
        }
        if (
          /-custody-[0-9]+\.json$/u.test(name) &&
          ["admitted", "retired"].includes(record.phase)
        ) {
          requireObservation(
            same(record.context, plan.bootstrap.context) &&
              record.reviewSha256 === plan.bootstrap.reviewSha256,
          );
          if (job.platform === "darwin") {
            if (name.startsWith(`provider-bootstrap-files-${fileSequence}-`))
              continue;
            for (const subject of [
              record.subjects.helper,
              record.subjects.verifier,
            ]) {
              const actual = await reader.retired(subject);
              requireObservation(providerRetired(actual));
              observations.push(actual);
            }
            const domain = await reader.retiredRootDomain(
              record.subjects.helper,
            );
            requireObservation(
              domain.complete === true && domain.members.length === 0,
            );
            observations.push(domain);
          } else if (job.platform === "win32") {
            subjects.push(record.helper, record.verifier);
          }
        }
        if (
          job.platform === "darwin" &&
          /-custody-[0-9]+\.json$/u.test(name) &&
          record.phase === "probe-created"
        ) {
          if (name.startsWith(`provider-bootstrap-files-${fileSequence}-`))
            continue;
          const actual = await reader.retired(record.request.verifier);
          requireObservation(providerRetired(actual));
          observations.push(actual);
        }
        if (
          job.platform === "win32" &&
          /-custody-[0-9]+\.json$/u.test(name) &&
          ["task-register-possible", "task-run-possible"].includes(record.phase)
        ) {
          requireObservation(
            record.nonce === plan.bootstrap.nonce &&
              same(record.context, plan.bootstrap.context) &&
              record.requestSha256 === observationDigest(plan.bootstrap),
          );
          subjects.push(record.bridge);
          if (!taskOwners.some((owner) => owner.nonce === plan.bootstrap.nonce))
            taskOwners.push({ ...record, nonce: plan.bootstrap.nonce });
        }
        if (
          job.platform === "win32" &&
          /^windows-files-[a-f0-9]{32}-intent\.json$/u.test(name)
        ) {
          const birth = byName.get(
            name.replace(/intent\.json$/u, "birth.json"),
          );
          requireObservation(
            birth?.schemaVersion === 1 &&
              birth.status === "POSSIBLE" &&
              name === `windows-files-${birth.nonce}-intent.json` &&
              providerHash(birth.taskSha256) &&
              record.schemaVersion === 1 &&
              record.status === "POSSIBLE",
          );
          const expected = [
            "--observe",
            plan.bootstrap.reader.path,
            plan.bootstrap.reader.sha256,
            plan.bootstrap.reader.signatureSha256,
            plan.bootstrap.plan.path,
            plan.bootstrap.plan.sha256,
            birth.nonce,
            plan.bootstrap.runnerSid,
            directory,
            value.helpers,
          ];
          requireObservation(
            same(
              record.argumentsHex,
              expected.map((arg) =>
                Buffer.from(arg, "utf16le").toString("hex"),
              ),
            ),
          );
          if (birth.nonce !== fileOwner().native.verification.input.nonce) {
            subjects.push(birth.helper, birth.bridge);
            taskOwners.push(birth);
            observerOwners.push(
              ...[birth.helper, birth.bridge].map((identity) => ({
                identity,
                nonce: birth.nonce,
              })),
            );
          }
        }
      }
      if (job.platform === "win32" && subjects.length) {
        const unique = [
          ...new Map(
            subjects.map((identity) => [observationDigest(identity), identity]),
          ).values(),
        ];
        observations.push(
          await reader.verify(
            "recoverCompleted",
            plan.bootstrap,
            unique,
            [],
            observerOwners,
          ),
        );
        for (const owner of taskOwners)
          observations.push(
            await reader.verify(
              "recoverOwnedTask",
              owner.nonce,
              owner.taskSha256,
              owner.bridge,
            ),
          );
        requireObservation(
          observations.every((proof) => providerRetired(proof)),
        );
      }
      // An entry without a creation identity retains exclusion. Completed
      // output files and exit codes never fill a missing native birth record.
      for (const { name, record } of records.filter(({ name }) =>
        /-custody-[0-9]+\.json$/u.test(name),
      )) {
        if (record.phase === "entry")
          requireObservation(
            records.some(
              (entry) =>
                entry.name.startsWith(
                  name.replace(/custody-[0-9]+\.json$/u, "custody-"),
                ) && entry.record.phase === "admitted",
            ),
          );
        if (job.platform === "darwin" && record.phase === "probe-intent")
          requireObservation(
            byName.get(
              name.replace(
                /custody-[0-9]+\.json$/u,
                `custody-${record.sequence + 1}.json`,
              ),
            )?.phase === "probe-created",
          );
        if (job.platform === "win32")
          requireObservation(
            record.requestSha256 === observationDigest(plan.bootstrap) &&
              record.nonce === plan.bootstrap.nonce &&
              [
                "entry",
                "task-register-possible",
                "task-run-possible",
                "admitted",
                "retired",
                "retire-possible",
                "finish",
                "open",
                "close",
                "inspect",
                "read",
                "process",
                "cleanup",
              ].includes(record.phase),
          );
        else if (job.platform === "darwin")
          requireObservation(
            [
              "entry",
              "admitted",
              "probe-intent",
              "probe-created",
              "probe-retired",
              "retired",
              "prepare-observe",
              "root-retired",
              "root-domain",
              "finish",
              "close",
              "inspect",
              "read",
              "process",
              "cleanup",
            ].includes(record.phase),
          );
      }
      guard(signal);
      return {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        noLiveMembers: true,
        ownedRestorationComplete: true,
        ownedTasksRemoved: true,
        requestSha256: observationDigest(request),
        recordsSha256: observationDigest(records),
        nativeEventSha256: observationDigest(observations),
      };
    },
  };
}
