import { win32 as path } from "node:path";
import {
  observationDigest,
  observationObject,
  requireObservation,
  nativePackageInput,
  nativePackageReviewDigest,
  normalizeNativePackageReview,
  packageMemberPath,
  verifyNativePolicy,
  materializeNativePolicy,
} from "../index.js";
import { digest, sameWindowsIdentity } from "./protocol.js";
import {
  decode,
  encode,
  decodePlan,
  normalizeWindowsCustodyInput,
} from "./custody-protocol.js";
import {
  windowsPreparationOptions,
  windowsPreparationContext,
} from "./preparation.js";
import { createWindowsCaseProvisioning } from "./case-provisioning.js";
import { createWindowsCaseEffects } from "./case-effects.js";
import { createWindowsPreparationFiles } from "./preparation-files.js";
import { createWindowsOperationReaders } from "./operation-readers.js";
import {
  recoverWindowsCases,
  readWindowsRecoveryRecords,
} from "./case-recovery.js";

const ID = "package.git-for-windows";
const same = (a, b) => observationDigest(a) === observationDigest(b);
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;

/** The independently reviewed extractor has a fixed streaming ABI. It receives
 * data only, under the existing restricted launch; System custody owns every
 * publication write. Neither an SFX nor an operator callback is executable. */
export function createWindowsPackageEffects(
  input,
  entry,
  options = {},
  assetCustody,
) {
  entry = structuredClone(entry);
  const review = normalizeNativePackageReview(
      entry.reviewed,
      input.job.candidateSha,
    ),
    extraction = review.extraction,
    approved = input.manifest.prerequisites.packages.find(
      (value) => value.packageId === "git-for-windows",
    );
  requireObservation(
    input.job.platform === "win32" &&
      same(entry, approved) &&
      review.schemaVersion === 2 &&
      nativePackageReviewDigest(review) === entry.approvedReviewSha256 &&
      extraction.custody &&
      extraction.setup &&
      extraction.loader &&
      typeof assetCustody?.readAsset === "function",
  );
  const custody = normalizeWindowsCustodyInput(extraction.custody),
    binding = extraction.policyBinding;
  requireObservation(
    same(custody.context, binding.context) &&
      custody.context.executionId === ID &&
      custody.reviewSha256 === binding.template.provisioningReviewSha256 &&
      extraction.extractor.bindings.loader ===
        nativePackageReviewDigest(extraction.loader),
  );
  requireObservation(
    extraction.setup.assets[1].path === extraction.extractor.path &&
      extraction.setup.assets[1].sha256 === extraction.extractor.sha256 &&
      extraction.extractor.bindings.source ===
        binding.template.sourceReviewSha256,
  );
  observationObject(extraction.loader, [
    "components",
    "buildSha256",
    "sdkSha256",
  ]);
  requireObservation(
    hash(extraction.loader.buildSha256) && hash(extraction.loader.sdkSha256),
  );
  const nativeInput = { ...input, output: input.buildOutput ?? input.output },
    observerInput = {
      ...nativeInput,
      manifest: {
        ...nativeInput.manifest,
        windowsPreparation: {
          ...nativeInput.manifest.windowsPreparation,
          bootstrap: custody,
        },
      },
    },
    nativeOptions = windowsPreparationOptions(
      observerInput,
      options,
      new Map(),
    ),
    state = windowsPreparationContext(nativeInput, nativeOptions),
    declared = { id: ID, custody, bindings: extraction.setup },
    argumentsList = [
      "x",
      "-y",
      "-bd",
      "-bb0",
      `-o${path.join(entry.directory, "content")}`,
      path.join(entry.directory, "archive"),
    ],
    provisioning = createWindowsCaseProvisioning(state, nativeOptions);
  requireObservation(
    path.dirname(entry.directory) === state.directory &&
      path.normalize(entry.directory) === entry.directory &&
      !path.basename(entry.directory).toLowerCase().startsWith("case-"),
  );
  state.plan.cases.push(declared);
  const work = new AbortController();
  const current = {
    recipe: { id: ID, group: "package" },
    declared,
    binding,
    extractor: extraction.extractor,
    packageArguments: argumentsList,
    packageLoader: extraction.loader.components,
    admissionsClosed: false,
    retired: false,
  };
  const active = new Map(),
    owned = new Map(),
    directories = new Map();
  let sequence = 0,
    initializing,
    owner,
    readers,
    archiveSealed = false,
    directoryBorn = false,
    requestPin,
    settled,
    sealed,
    policyReads = 0,
    failure,
    failed = false,
    filesClosed = false,
    publicationSealed = false,
    cleanupSignal;
  const save = async (_id, record) => {
    return state.write(`windows-case-${ID}-${sequence++}.json`, {
      context: binding.context,
      ...structuredClone(record),
    });
  };
  const persist = async (record) => {
    const actual = await save(ID, { phase: "package-record", record });
    return {
      ...actual,
      recordSha256: observationDigest(record),
      held: true,
      immutable: true,
      birthProtected: actual.exclusive === true,
    };
  };
  const initialize = (signal) => {
    state.guard(signal);
    if (signal && !work.signal.aborted)
      signal.addEventListener("abort", () => work.abort(signal.reason), {
        once: true,
        signal: work.signal,
      });
    if (initializing) return initializing;
    requireObservation(!current.admissionsClosed && !work.signal.aborted);
    current.signal = work.signal;
    initializing = (async () => {
      active.set(ID, current);
      await save(ID, {
        phase: "provisioning-possible",
        status: "POSSIBLE",
        templateSha256: binding.approval.manifestSha256,
        bindingsSha256: observationDigest(declared.bindings),
      });
      const entries = decodePlan(
        await state.read(custody.plan.path, custody.plan.sha256, 262144),
        custody,
      );
      requireObservation(
        entries[9]?.kind === "directory" &&
          entries[9].path === entry.directory &&
          !entries
            .slice(10)
            .some((value) =>
              value.path
                .toLowerCase()
                .startsWith(entry.directory.toLowerCase() + "\\"),
            ),
      );
      current.provisioned = await provisioning.provision(declared, binding, {
        signal: work.signal,
        current,
        persist: (record) => save(ID, record),
      });
      current.reader = current.provisioned.reader;
      for (let index = 9; index < entries.length; index++)
        if (index !== 9 && !current.provisioned.assetSources.includes(index))
          await current.reader.open(index);
      readers = createWindowsOperationReaders(current.reader, { entries });
      const closure = await readers.loader(
        extraction.loader.components,
        [5, 6],
      );
      requireObservation(
        observationDigest(closure.build) === extraction.loader.buildSha256 &&
          observationDigest(closure.sdk) === extraction.loader.sdkSha256,
      );
      await save(ID, { phase: "package-loader", closure });
      current.input = current.provisioned.input;
      owner = createWindowsCaseEffects(state, current, save);
      current.ownership = owner;
      await owner.prepare();
      return entries;
    })().catch((cause) => {
      if (!failed) {
        failed = true;
        failure = cause;
      }
      throw cause;
    });
    return initializing;
  };
  const observe = (value) => {
    observationObject(value, [
      "fileHex",
      "identity",
      "bytes",
      "links",
      "metadata",
      "security",
      "access",
      "share",
    ]);
    observationObject(value.security, ["owner", "protected", "sddl", "rules"]);
    requireObservation(
      /^[a-f0-9]{48}$/u.test(value.identity) &&
        Number.isSafeInteger(value.bytes) &&
        value.bytes >= 0 &&
        value.bytes <= 536870912 &&
        value.links === 1 &&
        /^[a-f0-9]{80}$/u.test(value.metadata) &&
        [1, 3].includes(value.share) &&
        ["read", "write"].includes(value.access) &&
        value.security.owner === "S-1-5-18" &&
        value.security.protected === true &&
        value.security.rules.length === 1,
    );
    const ace = value.security.rules[0];
    observationObject(ace, ["sid", "rights", "allow", "inherited"]);
    requireObservation(
      ace.sid === "S-1-5-18" &&
        ace.allow === true &&
        ace.inherited === false &&
        [0x1f01ff, 0x10000000, 0x1200a9].includes(ace.rights) &&
        (!publicationSealed || ace.rights === 0x1200a9),
    );
    const id = Buffer.from(value.identity, "hex"),
      identity =
        id.readBigUInt64LE(0).toString(16).padStart(16, "0") +
        ":" +
        id.subarray(8).toString("hex");
    return { ...value, identity, file: decode(value.fileHex) };
  };
  const call = async (
    operation,
    file,
    values = [],
    reader = current.reader,
  ) => {
    const actual = observe(await reader.packageFile(operation, file, values));
    requireObservation(actual.file === file);
    return actual;
  };
  const readFile = async (
    file,
    expected,
    { signal, reader = current.reader } = {},
  ) => {
    state.guard(signal);
    const before = await call("hold", file, [], reader),
      chunks = [];
    requireObservation(
      before.access === "read" &&
        before.share === 1 &&
        before.bytes === expected.bytes,
    );
    for (let offset = 0; offset < before.bytes; offset += 32768) {
      const frame = await reader.packageFile("read", file, [
        offset,
        Math.min(32768, before.bytes - offset),
      ]);
      observationObject(frame, ["hex", "object"]);
      requireObservation(
        /^(?:[a-f0-9]{2})+$/u.test(frame.hex) &&
          frame.hex.length === Math.min(32768, before.bytes - offset) * 2 &&
          same(observe(frame.object), before),
      );
      chunks.push(Buffer.from(frame.hex, "hex"));
      state.guard(signal);
    }
    const bytes = Buffer.concat(chunks),
      after = await call("observe", file, [], reader),
      born = owned.get(file);
    requireObservation(
      digest(bytes) === expected.sha256 &&
        same(before, after) &&
        (!born || born === before.identity),
    );
    return {
      file,
      bytes,
      independent: true,
      held: true,
      birthProtected: Boolean(born),
      protectedParents: true,
      unchanged: true,
      identitySha256: observationDigest(before.identity),
      nativeEventSha256: observationDigest({
        before,
        after,
        sha256: digest(bytes),
      }),
    };
  };
  const writeFile = async (file, bytes, member, signal) => {
    state.guard(signal);
    requireObservation(
      Buffer.isBuffer(bytes) &&
        bytes.length === member.bytes &&
        digest(bytes) === member.sha256 &&
        !owned.has(file),
    );
    await save(ID, { phase: "package-write-possible", file, member });
    const birth = await call("create", file);
    requireObservation(birth.access === "write" && birth.bytes === 0);
    for (let offset = 0; offset < bytes.length; offset += 32768) {
      const part = bytes.subarray(offset, offset + 32768),
        actual = await call("write", file, [offset, part.toString("hex")]);
      requireObservation(
        actual.identity === birth.identity &&
          actual.access === "write" &&
          actual.bytes === offset + part.length,
      );
      state.guard(signal);
    }
    const result = await call("seal", file);
    requireObservation(
      result.identity === birth.identity &&
        result.access === "read" &&
        result.bytes === bytes.length,
    );
    owned.set(file, birth.identity);
    const proof = await readFile(file, member, { signal });
    await save(ID, {
      phase: "package-write-held",
      file,
      member,
      identity: birth.identity,
      proofSha256: observationDigest(proof),
    });
    return proof;
  };
  const directory = async (file, { signal, reader = current.reader } = {}) => {
    state.guard(signal);
    const value = await reader.packageFile("directory", file);
    observationObject(value, ["namesHex", "object"]);
    const actual = observe(value.object),
      names = value.namesHex.map(decode).sort();
    requireObservation(
      actual.file === file &&
        names.length <= 4096 &&
        new Set(names.map((name) => name.toLowerCase())).size ===
          names.length &&
        names.every((name) => name && !/[\\/\u0000-\u001f\u007f]/u.test(name)),
    );
    const born = directories.get(file);
    requireObservation(!born || born === actual.identity);
    if (!born && directoryBorn && reader === current.reader)
      directories.set(file, actual.identity);
    return {
      file,
      names,
      identity: actual.identity,
      independent: true,
      held: true,
      protectedParents: true,
      birthProtected: directories.has(file),
      nativeEventSha256: observationDigest(value),
    };
  };
  const snapshot = async (signal, reader = current.reader) => {
    const expected = new Map([
      [entry.directory, new Set(["archive", "content"])],
      [path.join(entry.directory, "content"), new Set()],
    ]);
    for (const member of review.files) {
      let parent = path.join(entry.directory, "content");
      const parts = member.path.split("/");
      for (const [index, part] of parts.entries()) {
        expected.get(parent).add(part);
        parent = path.join(parent, part);
        if (index < parts.length - 1 && !expected.has(parent))
          expected.set(parent, new Set());
      }
    }
    const archiveFile = path.join(entry.directory, "archive"),
      heldArchive = await call("hold", archiveFile, [], reader),
      archive = await reader.verifyPackageArchive();
    requireObservation(
      heldArchive.bytes === review.archiveBytes &&
        heldArchive.access === "read" &&
        heldArchive.identity === archive.identity &&
        archive.bytes === review.archiveBytes &&
        `sha256:${archive.sha256}` ===
          nativePackageInput("git-for-windows").integrity &&
        archive.identity === owned.get(archiveFile),
    );
    const events = [archive, heldArchive];
    for (const [file, names] of expected) {
      const actual = await directory(file, { signal, reader });
      requireObservation(
        actual.birthProtected && same(actual.names, [...names].sort()),
      );
      events.push(actual);
    }
    const files = [];
    for (const member of review.files) {
      const proof = await readFile(
        path.join(entry.directory, "content", ...member.path.split("/")),
        member,
        { signal, reader },
      );
      requireObservation(proof.birthProtected);
      files.push({
        ...member,
        kind: "file",
        links: 1,
        identitySha256: proof.identitySha256,
      });
      events.push(proof.nativeEventSha256);
    }
    return { files, events };
  };
  const frame = async () => {
    const bytes = await current.reader.ownershipOutput();
    requireObservation(bytes.length <= 98304 && bytes.at(-1) === 10);
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  };
  const joinRequest = (request) => {
    observationObject(request, [
      "schemaVersion",
      "candidateSha",
      "platform",
      "mode",
      "extractor",
      "archive",
      "directory",
      "archiveBytes",
      "archiveIntegrity",
      "arguments",
      "reviewSha256",
      "inventory",
      "policySha256",
      "deadlineMs",
    ]);
    requireObservation(
      request.schemaVersion === 1 &&
        request.platform === "win32" &&
        request.mode === "7z-data-only" &&
        request.deadlineMs === 120000 &&
        request.archiveBytes === review.archiveBytes &&
        request.archiveIntegrity ===
          nativePackageInput("git-for-windows").integrity &&
        request.policySha256 ===
          materializeNativePolicy(
            binding.template,
            binding.approval,
            current.provisioned.provisioning,
            binding.context,
          ).expectedPolicySha256,
    );
    requireObservation(
      request.candidateSha === review.candidateSha &&
        request.archive === argumentsList[5] &&
        request.directory === path.join(entry.directory, "content") &&
        same(request.arguments, argumentsList) &&
        same(request.extractor, extraction.extractor) &&
        same(request.inventory, review.files) &&
        request.reviewSha256 === observationDigest(review),
    );
    if (requestPin)
      requireObservation(requestPin === observationDigest(request));
    requestPin = observationDigest(request);
  };
  const publication = async (signal, operation = snapshot) => {
    requireObservation(publicationSealed && current.retired);
    const files = createWindowsPreparationFiles(
        {
          ...nativeInput,
          signal,
          manifest: {
            ...nativeInput.manifest,
            windowsPreparation: { ...state.plan, bootstrap: custody },
          },
        },
        options,
      ),
      reader = {
        packageFile: (operation, file, values) =>
          files.readPackage(operation, file, values),
        verifyPackageArchive: () => files.verifyPackageArchive(),
      };
    let result,
      first,
      failed = false;
    try {
      result = await operation(signal, reader);
    } catch (cause) {
      failed = true;
      first = cause;
    }
    try {
      await files.beginCleanup(AbortSignal.timeout(30000));
      await files.closePackage();
    } catch (cause) {
      if (!failed) first = cause;
      failed = true;
    }
    try {
      const proof = await files.settleFiles();
      requireObservation(
        retired(proof) && proof.noLiveMembers && proof.taskRemoved,
      );
    } catch (cause) {
      if (!failed) first = cause;
      failed = true;
    }
    if (failed) throw first;
    return result;
  };
  const effects = {
    persist,
    async readProtected({ file, sha256, maximum, bindings }, { signal } = {}) {
      await initialize(signal);
      if (file === extraction.extractor.path) {
        requireObservation(
          sha256 === extraction.extractor.sha256 &&
            maximum === extraction.extractor.bytes &&
            same(bindings, extraction.extractor.bindings),
        );
        const actual = await assetCustody.readAsset(
          { path: file, bytes: maximum, sha256 },
          signal,
        );
        requireObservation(
          actual.bytes.length === extraction.extractor.bytes &&
            digest(actual.bytes) === extraction.extractor.sha256,
        );
        requireObservation(
          actual.birthProtected === true &&
            actual.independent === true &&
            actual.held === true &&
            actual.unchanged === true &&
            actual.protectedParents === true,
        );
        return {
          ...actual,
          identitySha256: observationDigest(actual.identity),
          nativeEventSha256: observationDigest(actual.event),
          bindingsSha256: observationDigest(bindings),
          loadedDependenciesVerified: true,
        };
      }
      const member = review.files.find(
        (value) =>
          file ===
          path.join(entry.directory, "content", ...value.path.split("/")),
      );
      requireObservation(
        member && member.sha256 === sha256 && maximum >= member.bytes,
      );
      return readFile(file, member, { signal });
    },
    async readProvisioning(value, { signal } = {}) {
      requireObservation(same(value, binding));
      await initialize(signal);
      return structuredClone(current.provisioned.provisioning);
    },
    async readPolicy(request, value, { signal } = {}) {
      requireObservation(!current.admissionsClosed && !work.signal.aborted);
      requireObservation(same(value, binding));
      await initialize(signal);
      joinRequest(request);
      if (!current.admitted) {
        await save(ID, { phase: "package-launch-possible", request });
        current.caseEffectsPossible = true;
        current.admitted = await owner.admit();
        const ready = await frame();
        observationObject(ready, ["phase", "nonce"]);
        requireObservation(
          ready.phase === "ready" && ready.nonce === custody.nonce,
        );
        const payload = await current.reader.retainProcess(
          current.admitted.payload,
        );
        await readers.runtime(payload.slot, 6, extraction.loader.components);
      }
      const proof = await owner.readInstalledPolicy(),
        observed = {
          ...proof.observed,
          requestSha256: observationDigest(request),
        };
      verifyNativePolicy(
        binding.template,
        binding.approval,
        proof.provisioning,
        binding.context,
        observationDigest(request),
        observed,
      );
      policyReads++;
      return observed;
    },
    async extract(request, { signal } = {}) {
      state.guard(signal);
      requireObservation(!current.admissionsClosed && !work.signal.aborted);
      joinRequest(request);
      requireObservation(current.admitted && directoryBorn && policyReads >= 2);
      const header = Buffer.from(
        JSON.stringify({
          schemaVersion: 1,
          requestSha256: requestPin,
          archiveBytes: request.archiveBytes,
          archiveIntegrity: request.archiveIntegrity,
        }) + "\n",
      );
      await current.reader.sendPackageBytes(header);
      const archive = await current.reader.sendPackageArchive(request.archive);
      requireObservation(
        archive.bytes === request.archiveBytes &&
          `sha256:${archive.sha256}` === request.archiveIntegrity,
      );
      const begin = await frame();
      observationObject(begin, ["phase", "requestSha256", "members"]);
      requireObservation(
        begin.phase === "inventory" &&
          begin.requestSha256 === requestPin &&
          begin.members === review.files.length,
      );
      const seen = new Set();
      for (let i = 0; i < review.files.length; i++) {
        const actual = await frame();
        observationObject(actual, [
          "path",
          "bytes",
          "sha256",
          "executable",
          "kind",
          "links",
          "streams",
        ]);
        const name = packageMemberPath(actual.path),
          expected = review.files.find((value) => value.path === name);
        requireObservation(
          expected &&
            !seen.has(name.toLowerCase()) &&
            actual.kind === "file" &&
            actual.links === 1 &&
            actual.streams === 0 &&
            actual.bytes === expected.bytes &&
            actual.sha256 === expected.sha256 &&
            actual.executable === expected.executable,
        );
        seen.add(name.toLowerCase());
        state.guard(signal);
      }
      const end = await frame();
      observationObject(end, ["phase", "requestSha256"]);
      requireObservation(
        end.phase === "inventory-complete" && end.requestSha256 === requestPin,
      );
      requireObservation(
        (await directory(request.directory, { signal })).names.length === 0,
      );
      await effects.readPolicy(request, binding, { signal });
      await save(ID, {
        phase: "package-inventory-admitted",
        requestSha256: requestPin,
        inventorySha256: observationDigest(review.files),
      });
      await current.reader.sendPackageBytes(Buffer.from("W\n"));
      for (const member of review.files) {
        const parts = [];
        let offset = 0;
        while (offset < member.bytes) {
          const value = await frame();
          observationObject(value, ["path", "offset", "data"]);
          requireObservation(
            value.path === member.path &&
              value.offset === offset &&
              typeof value.data === "string" &&
              value.data.length <= 65536,
          );
          const bytes = Buffer.from(value.data, "base64");
          requireObservation(
            bytes.length > 0 &&
              bytes.length <= 49152 &&
              bytes.toString("base64") === value.data &&
              offset + bytes.length <= member.bytes,
          );
          parts.push(bytes);
          offset += bytes.length;
          state.guard(signal);
        }
        await writeFile(
          path.join(request.directory, ...member.path.split("/")),
          Buffer.concat(parts, offset),
          member,
          signal,
        );
      }
      const done = await frame();
      observationObject(done, ["phase", "requestSha256"]);
      requireObservation(
        done.phase === "complete" && done.requestSha256 === requestPin,
      );
      const completion = await current.reader.packageCompletion(),
        native = await owner.witness();
      requireObservation(
        completion.exitCode === 0 &&
          native.payloadSignaled &&
          native.exitCode === 0 &&
          sameWindowsIdentity(
            native.enumeration.processes[0].identity,
            current.admitted.payload,
          ),
      );
      return {
        requestSha256: requestPin,
        independent: true,
        inventoryVerifiedBeforeWrite: true,
        archiveVerified: true,
        archiveBytes: archive.bytes,
        archiveIntegrity: request.archiveIntegrity,
        dataOnly: true,
        archiveExecuted: false,
        extractorSha256: extraction.extractor.sha256,
        exitCode: 0,
        signal: null,
        timedOut: false,
        nativeEventSha256: observationDigest({ archive, native }),
      };
    },
    async settle(request, { signal }) {
      joinRequest(request);
      work.abort();
      current.admissionsClosed = true;
      await current.reader.beginCleanup({ signal });
      current.signal = signal;
      cleanupSignal = signal;
      const result = await owner.recoverAndRetire();
      requireObservation(retired(result));
      settled = result;
      return { ...result, requestSha256: requestPin, noLiveMembers: true };
    },
    async verifyStaged(request, { signal } = {}) {
      joinRequest(request);
      requireObservation(settled);
      const actual = await snapshot(signal);
      return {
        requestSha256: requestPin,
        independent: true,
        complete: true,
        noReparsePoints: true,
        noAlternateStreams: true,
        protectedParents: true,
        files: actual.files,
        nativeEventSha256: observationDigest(actual),
      };
    },
    async seal(request, { signal } = {}) {
      joinRequest(request);
      requireObservation(settled && !sealed);
      const before = await snapshot(signal);
      await save(ID, {
        phase: "package-publication-seal-possible",
        requestSha256: requestPin,
      });
      await current.reader.sealPackagePublication();
      publicationSealed = true;
      const protectedSnapshot = await snapshot(signal);
      requireObservation(same(before.files, protectedSnapshot.files));
      await current.reader.closePackageFiles();
      filesClosed = true;
      const settlement = await owner.finish({ signal: cleanupSignal });
      requireObservation(retired(settlement));
      await nativeOptions.settleFiles();
      const after = await publication(signal);
      requireObservation(same(before.files, after.files));
      sealed = {
        requestSha256: requestPin,
        independent: true,
        unchanged: true,
        readExecuteOnly: true,
        complete: true,
        nativeEventSha256: observationDigest({
          before,
          protectedSnapshot,
          after,
          settlement,
        }),
      };
      return structuredClone(sealed);
    },
    async sealArchive(bytes, integrity, { signal } = {}) {
      requireObservation(
        !archiveSealed &&
          integrity === nativePackageInput("git-for-windows").integrity,
      );
      requireObservation(
        Buffer.isBuffer(bytes) && bytes.length === review.archiveBytes,
      );
      await initialize(signal);
      await save(ID, {
        phase: "package-archive-possible",
        directory: entry.directory,
        bytes: review.archiveBytes,
        integrity,
      });
      const actual = await current.reader.sealPackageArchive(bytes);
      directoryBorn = true;
      archiveSealed = true;
      directories.set(entry.directory, actual.directoryIdentity);
      const archive = await call("hold", path.join(entry.directory, "archive"));
      requireObservation(archive.identity === actual.archiveIdentity);
      owned.set(archive.file, archive.identity);
      await directory(path.join(entry.directory, "content"), { signal });
      await save(ID, {
        phase: "package-archive-held",
        directory: entry.directory,
        ...actual,
      });
      return Buffer.from(bytes);
    },
    directory,
    async verifyPublication({ signal } = {}) {
      requireObservation(sealed);
      return publication(signal);
    },
    async readPublication(file, { signal } = {}) {
      requireObservation(sealed);
      const member = review.files.find(
        (value) =>
          file ===
          path.join(entry.directory, "content", ...value.path.split("/")),
      );
      requireObservation(member);
      return publication(signal, (_signal, reader) =>
        readFile(file, member, { signal: _signal, reader }),
      );
    },
    async recover({ signal = AbortSignal.timeout(30000) } = {}) {
      work.abort();
      current.admissionsClosed = true;
      nativeOptions.fenceAdmission();
      await nativeOptions.beginCleanup(signal);
      let first,
        cleanupFailed = false;
      try {
        if (owner && current.caseEffectsPossible && !current.retired) {
          cleanupSignal ??= signal;
          await current.reader.beginCleanup({ signal: cleanupSignal });
          await owner.recoverAndRetire();
          if (!filesClosed) {
            await current.reader.closePackageFiles();
            filesClosed = true;
          }
          requireObservation(
            retired(await owner.finish({ signal: cleanupSignal })),
          );
        } else if (current.repositoryProvisioning && !current.retired) {
          if (owner && !filesClosed) {
            await current.reader.beginCleanup({ signal });
            await current.reader.closePackageFiles();
            filesClosed = true;
          }
          requireObservation(
            retired(
              await provisioning.retire(current, { signal, closeFiles: false }),
            ),
          );
        }
      } catch (cause) {
        cleanupFailed = true;
        first = cause;
      }
      let records;
      try {
        ({ records } = await readWindowsRecoveryRecords(state));
        requireObservation(
          !active.size ||
            records.some(({ name }) => name.startsWith(`windows-case-${ID}-`)),
        );
      } catch (cause) {
        if (!cleanupFailed) first = cause;
        cleanupFailed = true;
      }
      // The package record writer is an observer in this same protected plan.
      // Retire it before a fresh reader independently verifies every possible
      // creator/observer; its current receipt cannot prove its own retirement.
      try {
        requireObservation(retired(await nativeOptions.settleFiles()));
      } catch (cause) {
        if (!cleanupFailed) first = cause;
        cleanupFailed = true;
      }
      try {
        requireObservation(records);
        await recoverWindowsCases(
          state,
          nativeOptions,
          records,
          new Map(),
          (value, context) =>
            value.ownership.finish({
              ...context,
              signal: cleanupSignal ?? context.signal,
            }),
          provisioning,
          signal,
        );
      } catch (cause) {
        if (!cleanupFailed) first = cause;
        cleanupFailed = true;
      }
      if (cleanupFailed) throw failed ? failure : first;
      return { status: "RETAINED", admitted: false };
    },
  };
  return effects;
}
