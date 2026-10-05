import { execFile, fork } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";
import {
  spawnOwnedProcess,
  resolveOwnedProcessLauncher,
  assertOwnedProcessLauncherProtected,
  readProcessIdentity,
} from "../../../src/agents/index.js";
import {
  normalizeNativeResult,
  LINUX_ACCESS_CHECK_IDS,
  linuxPrerequisiteEvidence,
  normalizeLinuxPrerequisites,
  LINUX_NATIVE_GROUPS,
  observationDigest,
} from "../index.js";
import { prepareLinuxFixture, LITERAL_ARGV } from "./confinement.js";
import {
  processDetails,
  protectedReceipt,
  descendants,
  digest,
  inspectFixtureMounts,
  linuxKernelAuthority,
} from "./inspect.js";
import {
  LINUX_OWNERSHIP_CASES,
  LINUX_OWNERSHIP_CHECK_IDS,
  LINUX_POLICY_ID,
  normalizeLinuxReceipt,
  runLinuxOwnershipCase,
  sameLinuxIdentity,
} from "./protocol.js";
import { messageQueue, send } from "./channel.js";
import { ACCESS_PROFILES } from "./profiles.js";
import { runLinuxAccessProofs } from "./access.js";
import { buildLinuxFileHelper } from "./file-build.js";

const CONTROLLER = fileURLToPath(new URL("./controller.js", import.meta.url));
const execute = promisify(execFile);
const ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  CI: "true",
  GITHUB_ACTIONS: "true",
});
const observation = (expected, observed) => ({
  expected,
  observed,
  matched: true,
  positiveControl: true,
  attempted: true,
  sentinelsUnchanged: true,
});

export async function freshVerifier(file, sha256) {
  const { stdout } = await execute(
    process.execPath,
    [CONTROLLER, "--verify", file, sha256],
    { timeout: 5000, maxBuffer: 4096, env: ENVIRONMENT, killSignal: "SIGKILL" },
  );
  const result = JSON.parse(stdout);
  if (
    Object.keys(result).sort().join(",") !==
      "emergencyCleanup,independent,status" ||
    !["RETAINED", "RETIRED"].includes(result.status) ||
    result.independent !== (result.status === "RETIRED") ||
    result.emergencyCleanup !== false
  )
    throw new Error("Invalid fresh verifier evidence");
  return result;
}

function identify(messages, processes, type) {
  const message = messages.find((entry) => entry.type === type);
  if (!message) throw new Error("Missing permitted readiness control");
  const matches = processes.filter(
    (entry) =>
      entry.namespaceId === message.namespaceId &&
      entry.nspid.at(-1) === message.pid,
  );
  if (matches.length !== 1) throw new Error("Ambiguous payload identity");
  const fields = message.stat
    ?.slice(message.stat.lastIndexOf(")") + 2)
    .trim()
    .split(/\s+/u);
  if (fields?.[19] !== matches[0].identity.startTicks)
    throw new Error("Substituted payload identity");
  return matches[0];
}

async function caseEffects(job, fixture, caseId, access, onPolicy, signal) {
  signal?.throwIfAborted();
  const nonce = access?.nonce ?? randomUUID();
  const output = path.join(fixture.directory, "output", caseId);
  await mkdir(output, { mode: 0o700 });
  const receiptFile = path.join(
    fixture.directory,
    "evidence",
    `${caseId}.json`,
  );
  const sentinelFile = path.join(
    fixture.directory,
    "control",
    `${caseId}.sentinel`,
  );
  await writeFile(sentinelFile, nonce, { flag: "wx", mode: 0o400 });
  const deadline = performance.now() + 30000;
  const queue = messageQueue(deadline);
  signal?.throwIfAborted();
  const owner = fork(
    CONTROLLER,
    [
      "--control",
      JSON.stringify({
        fixture,
        caseId,
        candidateSha: job.candidateSha,
        nonce,
        output,
      }),
    ],
    {
      env: ENVIRONMENT,
      cwd: fixture.directory,
      execArgv: [],
      stdio: ["ignore", "pipe", "pipe", "ipc"],
    },
  );
  owner.once("error", (error) => queue.fail(error));
  const exit = new Promise((resolve) =>
    owner.once("close", (code, signal) => {
      queue.fail();
      resolve({ code, signal });
    }),
  );
  let diagnostics = 0;
  for (const stream of [owner.stdout, owner.stderr].filter(Boolean))
    stream.on("data", (bytes) => {
      diagnostics += bytes.length;
      if (diagnostics > 65536) {
        queue.fail();
        owner.kill("SIGKILL");
      }
    });
  owner.on("message", (message) => {
    if (message?.nonce !== nonce) queue.fail();
    else queue.push(message);
  });
  const timer = setTimeout(() => {
    queue.fail();
    owner.kill("SIGKILL");
  }, 30000);
  let receiptDigest;
  let ready;
  const messages = [];
  const payload = async (type) => {
    const { message } = await queue.take(
      (entry) => entry.type === "payload" && entry.message?.type === type,
    );
    if (message.nonce !== nonce) throw new Error("Substituted payload message");
    messages.push(message);
    return message;
  };
  const command = (message) =>
    send(owner, { type: "payload-command", nonce, message });
  const sentinel = async () => {
    if (
      (await readFile(sentinelFile, "utf8")) !== nonce ||
      digest(await readFile(fixture.executable)) !== fixture.executableDigest
    )
      throw new Error("External protected storage mutated");
    if (
      digest(await readFile(fixture.payload)) !==
        fixture.policy.payloadDigest ||
      digest(await readFile(fixture.fault)) !== fixture.policy.faultDigest
    )
      throw new Error("Protected fixture code mutated");
    await protectedReceipt(receiptFile, receiptDigest);
    if (access) await access.sentinel();
  };
  return {
    now: () => performance.now(),
    receiptBinding: () =>
      receiptDigest === undefined
        ? null
        : { file: receiptFile, sha256: receiptDigest },
    async admit() {
      const admitted = await queue.take(
        (message) => message.type === "admitted",
      );
      receiptDigest = admitted.sha256;
      return protectedReceipt(receiptFile, receiptDigest);
    },
    async confirmReceipt(receipt) {
      const init = await processDetails(receipt.init.pid);
      const controller = await processDetails(owner.pid);
      const launcher = await processDetails(receipt.launcher.pid);
      const observer = await processDetails(process.pid);
      if (
        receipt.candidateSha !== job.candidateSha ||
        receipt.nonce !== nonce ||
        receipt.policyDigest !== fixture.policyDigest ||
        receipt.executableDigest !== fixture.executableDigest ||
        !sameLinuxIdentity(init.identity, receipt.init.identity) ||
        init.namespaceId !== receipt.init.namespaceId ||
        init.nspid.at(-1) !== 1 ||
        !sameLinuxIdentity(controller.identity, receipt.controller.identity) ||
        receipt.controller.pid !== owner.pid ||
        controller.namespaceId !== receipt.parentNamespaceId ||
        !sameLinuxIdentity(launcher.identity, receipt.launcher.identity) ||
        launcher.namespaceId !== receipt.parentNamespaceId ||
        init.parent !== launcher.pid ||
        observer.namespaceId !== receipt.parentNamespaceId
      )
        throw new Error("Independent admission observation mismatch");
      if (caseId !== "argv") return;
      // A replaced receipt cannot authorize recovered retirement even after
      // the legitimate namespace later dies. This negative control is private.
      const substituted = path.join(
        fixture.directory,
        "evidence",
        `${caseId}-substituted.json`,
      );
      await writeFile(
        substituted,
        JSON.stringify({ ...receipt, nonce: randomUUID() }),
        { flag: "wx", mode: 0o400 },
      );
      const retained = await freshVerifier(substituted, receiptDigest);
      if (retained.status !== "RETAINED" || retained.independent)
        throw new Error("Receipt substitution accepted");
      const mismatchFile = path.join(
        fixture.directory,
        "evidence",
        `${caseId}-mismatched.json`,
      );
      const mismatch = structuredClone(receipt);
      mismatch.init.identity.startTicks = String(
        BigInt(mismatch.init.identity.startTicks) + 1n,
      );
      mismatch.admission.processIdentity = { ...mismatch.init.identity };
      mismatch.admission.launchCutoff = { ...mismatch.init.identity };
      const mismatchBytes = JSON.stringify(mismatch);
      await writeFile(mismatchFile, mismatchBytes, { flag: "wx", mode: 0o400 });
      const replaced = await freshVerifier(mismatchFile, digest(mismatchBytes));
      if (replaced.status !== "RETAINED" || replaced.independent)
        throw new Error("Mismatched identity accepted");
      const inaccessibleFile = path.join(
        fixture.directory,
        "control",
        `${caseId}-inaccessible.json`,
      );
      const inaccessibleBytes = JSON.stringify(receipt);
      await writeFile(inaccessibleFile, inaccessibleBytes, {
        flag: "wx",
        mode: 0o000,
      });
      const inaccessible = await freshVerifier(
        inaccessibleFile,
        digest(inaccessibleBytes),
      );
      if (inaccessible.status !== "RETAINED" || inaccessible.independent)
        throw new Error("Unverifiable receipt accepted");
      await chmod(inaccessibleFile, 0o400);
      const live = await freshVerifier(receiptFile, receiptDigest);
      if (live.status !== "RETAINED" || live.independent)
        throw new Error("Live namespace accepted as retired");
    },
    acknowledgeAdmission: () => send(owner, { type: "admission-ack", nonce }),
    async ready() {
      ready = await payload("ready");
      if (
        !ready.positive ||
        (!access && !ready.controlDenied) ||
        (await readFile(path.join(output, "positive"), "utf8")) !== nonce
      )
        throw new Error(
          "Fixture confinement or permitted positive control failed",
        );
      if (
        !access &&
        JSON.stringify(ready.literal) !== JSON.stringify(LITERAL_ARGV)
      )
        throw new Error("Literal argv altered");
      if (access) await access.ready(ready);
      await sentinel();
      if (onPolicy) {
        const receipt = await protectedReceipt(receiptFile, receiptDigest);
        const root = identify(
          messages,
          await descendants(receipt.init.pid),
          "ready",
        );
        const host = await processDetails(process.pid);
        if (
          root.namespaceId === receipt.init.namespaceId ||
          root.nspid.at(-1) !== 1 ||
          root.networkId === host.networkId ||
          root.ipcId === host.ipcId ||
          root.mountId === host.mountId
        )
          throw new Error("Unverified parked fixture authority");
        await inspectFixtureMounts(root.pid, fixture, output);
        const status = await readFile(`/proc/${root.pid}/status`, "utf8");
        const authority = linuxKernelAuthority(status, root);
        const executableSha256 = digest(
          await readFile(`/proc/${root.pid}/exe`),
        );
        if (
          ["Inh", "Prm", "Eff", "Amb"].some(
            (name) => authority.capabilitySets[name] !== "0000000000000000",
          ) ||
          authority.noNewPrivileges !== 1 ||
          executableSha256 !== fixture.executableDigest
        )
          throw new Error("Additional parked fixture authority");
        await onPolicy({
          policy: {
            launch: {
              request: {
                candidateSha: job.candidateSha,
                recipe: "linux.reference",
                executableSha256,
                policy: { path: LINUX_POLICY_ID },
                bindings: {},
              },
              arguments: [...ready.literal],
            },
            policy: { ...fixture.policy, ...authority },
          },
          nativeEventSha256: observationDigest({ receipt, root, status }),
        });
        if (
          !sameLinuxIdentity(
            root.identity,
            (await processDetails(root.pid)).identity,
          )
        )
          throw new Error("Parked fixture identity changed");
      }
    },
    release: () => {
      signal?.throwIfAborted();
      return command({ type: "release" });
    },
    async observe(receipt) {
      if (access) {
        // The fixed probe has reaped its Git children and remains parked until
        // the acknowledged finish boundary; inspect stable membership then.
        const result = await payload("access-result");
        const processes = await descendants(receipt.init.pid);
        const root = identify(messages, processes, "ready");
        const host = await processDetails(process.pid);
        if (
          root.namespaceId === receipt.init.namespaceId ||
          root.nspid.at(-1) !== 1 ||
          root.networkId === host.networkId ||
          root.ipcId === host.ipcId ||
          root.mountId === host.mountId
        )
          throw new Error("Access profile namespace authority mismatch");
        await inspectFixtureMounts(root.pid, fixture, output);
        const observations = await access.observe(result);
        await sentinel();
        return observations;
      }
      await payload("worker-ready");
      await payload("leaf-ready");
      const init = await processDetails(receipt.init.pid);
      if (
        !sameLinuxIdentity(init.identity, receipt.init.identity) ||
        init.namespaceId !== receipt.init.namespaceId
      )
        throw new Error("Substituted namespace init");
      const initial = await descendants(receipt.init.pid);
      const root = identify(messages, initial, "ready");
      const worker = identify(messages, initial, "worker-ready");
      const leaf = identify(messages, initial, "leaf-ready");
      const host = await processDetails(process.pid);
      if (
        root.namespaceId === receipt.init.namespaceId ||
        root.nspid.at(-1) !== 1 ||
        root.networkId === host.networkId ||
        root.ipcId === host.ipcId ||
        root.mountId === host.mountId ||
        worker.namespaceId !== root.namespaceId ||
        leaf.namespaceId !== root.namespaceId ||
        worker.parent !== root.pid ||
        leaf.parent !== worker.pid ||
        leaf.session !== leaf.pid
      )
        throw new Error("Actual detached namespace membership mismatch");
      await inspectFixtureMounts(root.pid, fixture, output);
      const executable = await readFile(`/proc/${root.pid}/exe`);
      if (digest(executable) !== fixture.executableDigest)
        throw new Error("Private executable not executed");
      await command({ type: "reparent" });
      await payload("reparented");
      const reparented = await processDetails(leaf.pid);
      if (
        !sameLinuxIdentity(reparented.identity, leaf.identity) ||
        reparented.namespaceId !== leaf.namespaceId ||
        reparented.parent !== root.pid ||
        reparented.session !== leaf.pid
      )
        throw new Error("Detached/reparented descendant escaped ownership");
      await sentinel();
      const after = await processDetails(receipt.init.pid);
      if (
        !sameLinuxIdentity(after.identity, receipt.init.identity) ||
        after.namespaceId !== receipt.init.namespaceId
      )
        throw new Error("Namespace init changed during observation");
      await writeFile(
        path.join(fixture.directory, "evidence", `${caseId}-observation.json`),
        JSON.stringify({
          candidateSha: job.candidateSha,
          caseId,
          nonce,
          policyDigest: fixture.policyDigest,
          literal: ready.literal,
          init: after,
          root,
          worker,
          leaf,
          reparented,
          sentinelsUnchanged: true,
        }) + "\n",
        { flag: "wx", mode: 0o400 },
      );
      return [
        observation(
          "Literal argv includes empty and shell metacharacter arguments",
          "Exact literal argv observed by the restricted executable",
        ),
        observation(
          "Private copied executable and confined permitted output",
          "Executed bytes match the private copy; output nonce matches; protected control write denied",
        ),
        observation(
          "Protected identity persistence precedes payload release",
          "Independent namespace-init inspection and persisted receipt acknowledged before readiness",
        ),
        observation(
          "Detached descendant remains in a nested owned PID namespace after reparenting",
          "Stable boot/start identity, distinct session, namespace membership and new parent independently inspected",
        ),
        ...(caseId === "argv"
          ? [
              observation(
                "Live, substituted, mismatched and unverifiable receipts retain exclusion",
                "Fresh verifiers refused all negative controls without signals; protected sentinel and receipt unchanged",
              ),
            ]
          : []),
      ];
    },
    async armFault() {
      await command({ type: "arm", caseId });
      const acknowledgement = await payload("armed");
      await send(owner, { type: "helper-arm", nonce });
      await queue.take((message) => message.type === "helper-armed");
      await sentinel();
      return acknowledgement;
    },
    async fireFault() {
      if (caseId === "owner-loss") {
        if (!owner.kill("SIGKILL"))
          throw new Error("Owner loss not applied to live handle");
      } else {
        if (caseId === "argv" || ACCESS_PROFILES.includes(caseId))
          await command({ type: "finish" });
        await send(owner, { type: "fault", nonce });
      }
    },
    async settle() {
      if (caseId !== "owner-loss") {
        await queue.take((message) => message.type === "settled");
        await send(owner, { type: "settlement-ack", nonce });
      }
      const result = await exit;
      if (performance.now() >= deadline)
        throw new Error("Shared admission/probe deadline expired");
      if (
        caseId === "owner-loss"
          ? result.signal !== "SIGKILL"
          : result.code !== 0
      )
        throw new Error("Unexpected owner settlement");
      clearTimeout(timer);
    },
    verify: () => freshVerifier(receiptFile, receiptDigest),
    async cleanup() {
      await sentinel();
      if (access) await access.cleanup();
      clearTimeout(timer);
      await rm(output, { recursive: true });
    },
    async emergencyStop() {
      if (owner.connected)
        await send(owner, { type: "emergency", nonce }).catch(() => {});
      owner.kill("SIGKILL");
      await exit;
      clearTimeout(timer);
    },
  };
}

function record(job, checkId, fixture, cases) {
  const failed = cases.some((entry) => entry.status === "FAIL");
  const phases = Object.fromEntries(
    ["setup", "probe", "cleanup"].map((name) => {
      const phase = cases.find((entry) => entry.phases[name].status !== "PASS")
        ?.phases[name];
      return [
        name,
        phase ?? {
          status: "PASS",
          elapsedMs: cases.reduce(
            (sum, entry) => sum + entry.phases[name].elapsedMs,
            0,
          ),
          deadlineMs: cases.length * 30000,
          reason: null,
        },
      ];
    }),
  );
  return normalizeNativeResult({
    schemaVersion: 1,
    candidateSha: job.candidateSha,
    checkoutSha: job.checkoutSha,
    platform: job.platform,
    declaredImage: job.declaredImage,
    observed: job.observed,
    provenance: job.provenance,
    checkId,
    profile: checkId.startsWith("profile.")
      ? checkId.slice(8)
      : checkId === "git.fixed-commit"
        ? "commit"
        : LINUX_ACCESS_CHECK_IDS.includes(checkId)
          ? "access"
          : "ownership",
    tier: "system",
    dispatch: "native",
    implemented: true,
    versions: [
      ...job.versions.filter(({ name }) => name !== "bubblewrap"),
      fixture.version,
      ...(fixture.versions ?? []),
    ],
    policy: { id: fixture.policy.id, sha256: fixture.policyDigest },
    phases,
    observations: cases.flatMap((entry) => [
      ...entry.observations,
      ...(entry.status === "PASS"
        ? [
            observation(
              `Acknowledged ${entry.caseId} boundary and independent retirement`,
              "Applied the fixed case operation; a fresh verifier observed namespace-init and controlling-helper absence with visible same-boot procfs controls",
            ),
          ]
        : []),
    ]),
    settlement: {
      status: cases.every((entry) => entry.settlement.status === "RETIRED")
        ? "RETIRED"
        : "RETAINED",
      independent: cases.every((entry) => entry.settlement.independent),
      emergencyCleanup: cases.some(
        (entry) => entry.settlement.emergencyCleanup,
      ),
    },
    status: failed ? "FAIL" : "PASS",
    reason: failed
      ? cases.find((entry) => entry.status === "FAIL").reason
      : null,
  });
}

/** Only system CI calls this effect owner. Missing prerequisites block only
 * dependent checks; they do not confer evidence on any other contract. */
export async function runLinuxOwnershipProofs(
  job,
  reportDirectory,
  {
    onOwnership = async () => {},
    beforeAccess = async () => {},
    onAccess = async () => {},
    onPolicy,
    signal,
  } = {},
) {
  signal?.throwIfAborted();
  if (
    process.platform !== "linux" ||
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true" ||
    job.platform !== "linux" ||
    job.stages.setup.status !== "PASS"
  )
    throw new Error("Linux ownership proofs require initialized system CI");
  let fixture;
  const bubblewrap = job.versions.find(({ name }) => name === "bubblewrap");
  if (!bubblewrap) throw new Error("Linux proof requires verified preparation");
  try {
    fixture = await prepareLinuxFixture(path.join(reportDirectory, "linux"), {
      expectedExecutableDigest: job.versions.find(({ name }) => name === "node")
        .sha256,
      expectedLauncherDigest: bubblewrap.sha256,
      expectedLauncherVersion: bubblewrap.version,
    });
  } catch (error) {
    const blocked = blockedLinuxPrerequisites(job, error.prerequisites);
    await writeFile(
      path.join(reportDirectory, "linux-missing-inputs.json"),
      JSON.stringify({
        ...linuxPrerequisiteEvidence(job, blocked.linuxPrerequisites),
        next: "Inspect the preparation receipt and first failed prerequisite in fresh system CI; preserve verified package bytes and namespace/protection policy without host-session fallback.",
      }) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    await onOwnership(blocked.results, null, blocked.linuxPrerequisites);
    return { ...blocked, fixture: null };
  }
  if (
    !job.versions.some(
      (entry) =>
        entry.name === "node" && entry.sha256 === fixture.executableDigest,
    )
  )
    throw new Error("Copied executable differs from observed setup revision");
  await writeFile(
    path.join(fixture.directory, "evidence", "policy.json"),
    JSON.stringify(fixture.policy) + "\n",
    { flag: "wx", mode: 0o400 },
  );
  const cases = {};
  const receipts = [];
  for (const caseId of LINUX_OWNERSHIP_CASES) {
    const effects = await caseEffects(
      job,
      fixture,
      caseId,
      undefined,
      caseId === "argv" ? onPolicy : undefined,
      signal,
    );
    cases[caseId] = await runLinuxOwnershipCase(caseId, effects);
    const receipt = effects.receiptBinding();
    if (receipt !== null) receipts.push(receipt);
    await writeFile(
      path.join(fixture.directory, "evidence", `${caseId}-result.json`),
      JSON.stringify(cases[caseId]) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    if (
      cases[caseId].settlement.status !== "RETIRED" ||
      cases[caseId].settlement.independent !== true
    )
      break;
  }
  const mapping = {
    "launch.argv": ["argv"],
    "launch.storage": ["argv"],
    "ownership.admission": ["argv"],
    "ownership.receipts": ["argv"],
    "ownership.descendants": ["cancel"],
    "ownership.cancel": ["cancel"],
    "ownership.owner-loss": ["owner-loss"],
    "ownership.helper-loss": ["supervisor-loss", "launcher-loss"],
  };
  const ownership = LINUX_OWNERSHIP_CHECK_IDS.filter(
    (id) =>
      mapping[id].every((name) => cases[name]) ||
      mapping[id].some((name) => cases[name]?.status === "FAIL"),
  ).map((id) =>
    record(
      job,
      id,
      fixture,
      mapping[id].filter((name) => cases[name]).map((name) => cases[name]),
    ),
  );
  const ownershipResults = [
    ...ownership,
    ...blockedRecords(
      job,
      LINUX_OWNERSHIP_CHECK_IDS.filter(
        (id) => !ownership.some((result) => result.checkId === id),
      ),
    ),
  ];
  await onOwnership(ownershipResults, fixture, null);
  const ready = LINUX_OWNERSHIP_CASES.every(
    (id) => cases[id]?.status === "PASS",
  );
  if (ready) await beforeAccess();
  const access = ready
    ? await runLinuxAccessProofs(
        job,
        fixture,
        async (id, profileFixture, effects) => {
          const owned = await caseEffects(
            job,
            profileFixture,
            id,
            effects,
            undefined,
            signal,
          );
          const result = await runLinuxOwnershipCase(id, owned);
          const receipt = owned.receiptBinding();
          if (receipt !== null) receipts.push(receipt);
          return result;
        },
        record,
        (ids) => blockedRecords(job, ids),
      )
    : blockedRecords(job, LINUX_ACCESS_CHECK_IDS);
  await onAccess(access);
  return {
    results: [...ownershipResults, ...access],
    linuxPrerequisites: null,
    fixture,
    receipts,
  };
}

/** Missing prerequisites cannot attest an implemented case or its retirement. */
export function blockedLinuxPrerequisites(job, prerequisites) {
  return {
    results: blockedRecords(job, [
      ...LINUX_OWNERSHIP_CHECK_IDS,
      ...LINUX_ACCESS_CHECK_IDS,
    ]),
    linuxPrerequisites: normalizeLinuxPrerequisites(prerequisites),
  };
}

function blockedRecords(job, ids) {
  return ids.map((checkId) =>
    normalizeNativeResult({
      schemaVersion: 2,
      admission: "not-started",
      candidateSha: job.candidateSha,
      checkoutSha: job.checkoutSha,
      platform: job.platform,
      declaredImage: job.declaredImage,
      observed: job.observed,
      provenance: job.provenance,
      checkId,
      profile: checkId.startsWith("profile.")
        ? checkId.slice(8)
        : checkId === "git.fixed-commit"
          ? "commit"
          : job.schemaVersion === 5
            ? Object.keys(LINUX_NATIVE_GROUPS).find((id) =>
                LINUX_NATIVE_GROUPS[id].checkIds.includes(checkId),
              )
            : "fixture",
      tier: "system",
      dispatch: "native",
      implemented: true,
      versions: job.versions,
      policy: null,
      phases: Object.fromEntries(
        ["setup", "probe", "cleanup"].map((name) => [
          name,
          {
            status: "NOT_RUN",
            elapsedMs: null,
            deadlineMs: 30000,
            reason: "missing-input",
          },
        ]),
      ),
      observations: [],
      settlement: {
        status: "RETAINED",
        independent: false,
        emergencyCleanup: false,
      },
      status: "BLOCKED",
      reason: "missing-input",
    }),
  );
}

export const LINUX_FILE_PROOF_BUILD_MS = 10000 + 2 * (20000 + 5000 + 5000);
const BUILD_CONTROLLER = fileURLToPath(import.meta.url);
const BUILD_ENVIRONMENT = Object.freeze({
  ...ENVIRONMENT,
  ImageOS: "ubuntu24",
});
const buildRetired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;
function requireBuildEvidence(condition) {
  if (!condition)
    throw new Error("Incomplete or mismatched Linux build evidence");
}

/** A separate controller closes before its receipts are freshly verified.
 * The existing literal-argv admission receipt is reused without granting any
 * compiler output authority over the controller or protected evidence. */
export async function buildWithReceipts(job, directory, fixture, pins) {
  const nonce = randomUUID(),
    file = path.join(directory, `build-input-${nonce}.json`);
  await writeFile(
    file,
    JSON.stringify({
      candidateSha: job.candidateSha,
      directory: path.join(directory, "build"),
      launcher: fixture.launcher,
      pins,
    }),
    { flag: "wx", mode: 0o400 },
  );
  const worker = fork(BUILD_CONTROLLER, ["--build", file], {
    env: BUILD_ENVIRONMENT,
    execArgv: [],
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
  let message,
    emergency = false;
  worker.on("message", (value) => {
    if (message) emergency = true;
    else message = value;
  });
  const timer = setTimeout(() => {
    emergency = true;
    worker.kill("SIGKILL");
  }, LINUX_FILE_PROOF_BUILD_MS - 10000);
  const outcome = await new Promise((resolve, reject) => {
    worker.once("error", reject);
    worker.once("close", (code) => resolve(code));
  }).finally(() => clearTimeout(timer));
  requireBuildEvidence(
    !emergency &&
      outcome === 0 &&
      message?.status === "PASS" &&
      message.receipts?.length === 2,
  );
  for (const [index, entry] of message.receipts.entries()) {
    requireBuildEvidence(
      entry.file === path.join(directory, "build", `command-${index}.json`),
    );
    const receipt = await protectedReceipt(entry.file, entry.sha256);
    requireBuildEvidence(
      receipt.candidateSha === job.candidateSha &&
        receipt.controller.pid === worker.pid &&
        buildRetired(await freshVerifier(entry.file, entry.sha256)),
    );
  }
  const build = JSON.parse(
    await readFile(path.join(directory, "build", "build.json")),
  );
  const buildBytes = JSON.stringify(build) + "\n";
  requireBuildEvidence(Buffer.byteLength(buildBytes) <= 1048576);
  await writeFile(
    path.join(fixture.directory, "evidence", "helper-build.json"),
    buildBytes,
    { flag: "wx", mode: 0o400 },
  );
  return {
    receipts: message.receipts,
    build: {
      ...build,
      executable: path.join(directory, "build", "output", "file-helper"),
    },
    settlement: {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    },
  };
}

function buildCommandRunner(input, receipts, observations = []) {
  return async (file, args, options) => {
    const nonce = randomUUID(),
      sequence = receipts.length;
    const policyDigest = input.command
      ? observationDigest(input.command)
      : digest(JSON.stringify(args));
    requireBuildEvidence(sequence < 2);
    await writeFile(
      path.join(input.directory, `command-${sequence}-possible.json`),
      JSON.stringify({
        candidateSha: input.candidateSha,
        nonce,
        policyDigest,
      }),
      { flag: "wx", mode: 0o400 },
    );
    let child,
      oversized = false,
      timedOut = false;
    let stdout = "",
      stderr = "",
      bytes = 0;
    child = spawnOwnedProcess(file, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ["ignore", "pipe", "pipe"],
      resolveLauncher(cwd) {
        const launcher = resolveOwnedProcessLauncher(cwd);
        assertOwnedProcessLauncherProtected(launcher.file);
        requireBuildEvidence(
          launcher.file === input.launcher &&
            launcher.isolatedNamespace &&
            !launcher.hostSession,
        );
        return launcher;
      },
      async onProcess(pid, admission) {
        if (pid === null) return;
        const init = await processDetails(pid),
          controller = await processDetails(process.pid);
        const launcherIdentity = await readProcessIdentity(child.pid);
        requireBuildEvidence(
          sameLinuxIdentity(init.identity, admission.processIdentity) &&
            launcherIdentity !== null,
        );
        const receipt = normalizeLinuxReceipt({
          schemaVersion: 1,
          candidateSha: input.candidateSha,
          caseId: "argv",
          nonce,
          policyDigest,
          executableDigest: digest(await readFile(file)),
          isolatedNamespace: true,
          hostSession: false,
          parentNamespaceId: controller.namespaceId,
          init: {
            pid,
            identity: init.identity,
            namespaceId: init.namespaceId,
            nspid: init.nspid,
          },
          launcher: { pid: child.pid, identity: launcherIdentity },
          controller: { pid: process.pid, identity: controller.identity },
          admission,
        });
        const receiptFile = path.join(
            input.directory,
            `command-${sequence}.json`,
          ),
          receiptBytes = JSON.stringify(receipt) + "\n";
        await writeFile(receiptFile, receiptBytes, { flag: "wx", mode: 0o400 });
        receipts.push({ file: receiptFile, sha256: digest(receiptBytes) });
      },
    });
    for (const stream of [child.stdout, child.stderr])
      stream.on("data", (data) => {
        bytes += data.length;
        if (bytes > options.maxBuffer) {
          oversized = true;
          child.kill("SIGKILL");
        } else if (stream === child.stdout) stdout += data.toString("utf8");
        else stderr += data.toString("utf8");
      });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, options.timeout);
    try {
      const completion = await child.ownedCompletion;
      requireBuildEvidence(
        !oversized &&
          !timedOut &&
          completion.outcome?.type === "close" &&
          (input.command || completion.outcome.exitCode === 0) &&
          completion.outcome.signal === null &&
          receipts.length === sequence + 1,
      );
      const observed = {
        stdout,
        stderr,
        exitCode: completion.outcome.exitCode,
        signal: completion.outcome.signal,
        timedOut,
      };
      observations.push(observed);
      return observed;
    } finally {
      clearTimeout(timer);
    }
  };
}

async function buildController(input) {
  const receipts = [],
    observations = [];
  const run = buildCommandRunner(input, receipts, observations);
  if (input.command) {
    requireBuildEvidence(
      [
        "/usr/bin/x86_64-linux-gnu-gcc-13",
        "/usr/bin/x86_64-linux-gnu-ld.bfd",
      ].includes(input.command.file) &&
        JSON.stringify(input.command.args) === '["--version"]' &&
        input.command.deadlineMs > 0 &&
        input.command.deadlineMs <= 30000,
    );
    await run(input.command.file, input.command.args, {
      cwd: input.command.cwd,
      env: input.command.env,
      maxBuffer: 65536,
      timeout: input.command.deadlineMs,
    });
  } else {
    await buildLinuxFileHelper(
      input.candidateSha,
      input.directory,
      input.launcher,
      input.pins,
      { run, env: BUILD_ENVIRONMENT },
    );
  }
  await new Promise((resolve, reject) =>
    process.send(
      {
        status: "PASS",
        receipts,
        ...(input.command ? { observation: observations[0] } : {}),
      },
      (error) => (error ? reject(error) : resolve()),
    ),
  );
}

/** Explicit external-CI version inspection using the compiler's existing
 * owned controller and fresh verifier. A child exit never supplies retirement. */
export async function runLinuxBuildCommand(
  request,
  {
    signal,
    env = process.env,
    platform = process.platform,
    fs = { mkdir, writeFile },
    start = fork,
    readReceipt = protectedReceipt,
    verify = freshVerifier,
  } = {},
) {
  requireBuildEvidence(
    platform === "linux" &&
      request.platform === "linux" &&
      !signal?.aborted &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24",
  );
  const directory = path.join(
    request.cwd,
    `command-${observationDigest(request)}`,
  );
  await fs.mkdir(directory, { mode: 0o700 });
  const file = path.join(directory, "input.json");
  await fs.writeFile(
    file,
    JSON.stringify({
      candidateSha: request.candidateSha,
      directory,
      launcher: "/usr/bin/bwrap",
      command: request,
    }),
    { flag: "wx", mode: 0o400 },
  );
  requireBuildEvidence(!signal?.aborted);
  const worker = start(BUILD_CONTROLLER, ["--build", file], {
    env: BUILD_ENVIRONMENT,
    execArgv: [],
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
  let message,
    duplicate = false,
    emergency = false;
  worker.on("message", (value) => {
    if (message) duplicate = true;
    else message = value;
  });
  const abort = () => {
    emergency = true;
    worker.kill("SIGKILL");
  };
  signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, request.deadlineMs + 5000);
  try {
    const outcome = await new Promise((resolve, reject) => {
      worker.once("error", reject);
      worker.once("close", resolve);
    });
    requireBuildEvidence(
      !emergency &&
        !duplicate &&
        outcome === 0 &&
        message?.status === "PASS" &&
        message.receipts?.length === 1,
    );
    const entry = message.receipts[0];
    requireBuildEvidence(entry.file === path.join(directory, "command-0.json"));
    const receipt = await readReceipt(entry.file, entry.sha256);
    const settlement = await verify(entry.file, entry.sha256);
    requireBuildEvidence(
      receipt.candidateSha === request.candidateSha &&
        receipt.controller.pid === worker.pid &&
        receipt.policyDigest === observationDigest(request) &&
        receipt.executableDigest === request.toolSha256 &&
        buildRetired(settlement),
    );
    return {
      ...message.observation,
      identity: { pid: receipt.init.pid, ...receipt.init.identity },
      requestSha256: observationDigest(request),
      toolSha256: receipt.executableDigest,
      nativeEventSha256: digest(
        JSON.stringify({ receipt, observation: message.observation }),
      ),
      independent: true,
      settlement,
    };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

if (process.argv[1] === BUILD_CONTROLLER && process.argv[2] === "--build") {
  Promise.resolve()
    .then(async () => {
      requireBuildEvidence(
        process.env.CI === "true" &&
          process.env.GITHUB_ACTIONS === "true" &&
          process.send &&
          process.argv.length === 4,
      );
      const stat = await lstat(process.argv[3]);
      requireBuildEvidence(
        stat.isFile() && stat.size <= 1048576 && (stat.mode & 0o777) === 0o400,
      );
      await buildController(JSON.parse(await readFile(process.argv[3])));
    })
    .catch(() => {
      process.exitCode = 1;
    })
    .finally(() => {
      if (process.connected) process.disconnect();
    });
}
