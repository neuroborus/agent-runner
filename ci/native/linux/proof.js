import { execFile, fork } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";
import { normalizeNativeResult } from "../index.js";
import { prepareLinuxFixture, LITERAL_ARGV } from "./confinement.js";
import {
  processDetails,
  protectedReceipt,
  descendants,
  digest,
  inspectFixtureMounts,
} from "./inspect.js";
import {
  LINUX_OWNERSHIP_CASES,
  LINUX_OWNERSHIP_CHECK_IDS,
  LINUX_POLICY_ID,
  runLinuxOwnershipCase,
  sameLinuxIdentity,
} from "./protocol.js";
import { messageQueue, send } from "./channel.js";

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

async function freshVerifier(file, sha256) {
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

async function caseEffects(job, fixture, caseId) {
  const nonce = randomUUID();
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
  };
  return {
    now: () => performance.now(),
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
        !ready.controlDenied ||
        (await readFile(path.join(output, "positive"), "utf8")) !== nonce
      )
        throw new Error(
          "Fixture confinement or permitted positive control failed",
        );
      if (JSON.stringify(ready.literal) !== JSON.stringify(LITERAL_ARGV))
        throw new Error("Literal argv altered");
      await sentinel();
    },
    release: () => command({ type: "release" }),
    async observe(receipt) {
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
        if (caseId === "argv") await command({ type: "finish" });
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
    profile: "fixture",
    tier: "system",
    dispatch: "native",
    implemented: true,
    versions: [...job.versions, fixture.version],
    policy: { id: LINUX_POLICY_ID, sha256: fixture.policyDigest },
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

/** Only system CI calls this effect owner. Missing prerequisites block these
 * eight dependent checks; they do not confer evidence on any other contract. */
export async function runLinuxOwnershipProofs(job, reportDirectory) {
  if (
    process.platform !== "linux" ||
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true" ||
    job.platform !== "linux" ||
    job.stages.setup.status !== "PASS"
  )
    throw new Error("Linux ownership proofs require initialized system CI");
  let fixture;
  try {
    fixture = await prepareLinuxFixture(path.join(reportDirectory, "linux"));
  } catch (error) {
    const inputs = {
      "protected-bubblewrap":
        "Protected canonical bubblewrap with an actual isolated PID namespace",
      "procfs-retirement":
        "Full procfs without PID hiding/substitution and visible same-boot self/PID-1 controls",
      "nested-namespaces":
        "Nested user/PID/network namespace creation under the owned namespace",
      "private-fixture-storage":
        "Fresh canonical private fixture storage and copied read-only inputs",
      "protected-executable-abi":
        "Protected ELF loader/library closure and protected ldd for the declared Node executable",
      "bubblewrap-version":
        "Released protected bubblewrap version and executable digest",
    };
    await writeFile(
      path.join(reportDirectory, "linux-missing-inputs.json"),
      JSON.stringify({
        status: "BLOCKED",
        failedPrerequisite: error.prerequisite,
        observation: error.code,
        missingInputs: [inputs[error.prerequisite]],
        next: "Inspect this image prerequisite in system CI; do not substitute a host-session launcher or install unreviewed bytes.",
      }) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    return LINUX_OWNERSHIP_CHECK_IDS.map((checkId) =>
      normalizeNativeResult({
        schemaVersion: 1,
        candidateSha: job.candidateSha,
        checkoutSha: job.checkoutSha,
        platform: job.platform,
        declaredImage: job.declaredImage,
        observed: job.observed,
        provenance: job.provenance,
        checkId,
        profile: "fixture",
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
  for (const caseId of LINUX_OWNERSHIP_CASES) {
    const effects = await caseEffects(job, fixture, caseId);
    cases[caseId] = await runLinuxOwnershipCase(caseId, effects);
    await writeFile(
      path.join(fixture.directory, "evidence", `${caseId}-result.json`),
      JSON.stringify(cases[caseId]) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    // A retained namespace prevents another fixture from releasing work.
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
  return LINUX_OWNERSHIP_CHECK_IDS.filter(
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
}
