import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { isWindows2025Image } from "../index.js";
import {
  closed,
  dense,
  hash,
  requireWindows,
  normalizeWindowsLaunch,
  normalizeWindowsArguments,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  systemIdentity,
  sid,
  windowsLaunchDigest,
  windowsCommandLine,
  quoteWindowsArgument,
  WINDOWS_ARGUMENT_PARSER,
} from "./protocol.js";
import {
  assertWindowsSetup,
  assertWindowsAuthority,
  assertWindowsReceipt,
  assertWindowsPolicy,
} from "./authority.js";
import { windowsAdmissionChannel } from "./channel.js";

function launcherVector(request, args) {
  return [
    request.nonce,
    request.restrictingSid,
    request.custody,
    request.storage,
    request.workspace,
    request.executable.path,
    request.executable.sha256,
    request.policy.path,
    request.policy.sha256,
    "--",
    ...args,
  ];
}
function nativeTransport(request, args, verified, onHelper, onSetup) {
  const vector = launcherVector(request, args);
  const child = spawn(request.launcher.path, vector.map(quoteWindowsArgument), {
    argv0: quoteWindowsArgument(request.launcher.path),
    windowsVerbatimArguments: true,
    cwd: request.custody,
    env: { CI: "true", GITHUB_ACTIONS: "true" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  return windowsAdmissionChannel(child, request.nonce, onHelper, onSetup);
}
/** Privileged external CI only. The native launcher owns account/token/Job
 * setup; independently reviewed owners install policy and inspect held objects.
 * This protocol confers no native acceptance or provider commit/tool grant. */
export async function admitWindowsLaunch(
  input,
  argumentsList,
  approvedSha256,
  effects,
  {
    platform = process.platform,
    architecture = process.arch,
    env = process.env,
    build = "",
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  const request = normalizeWindowsLaunch(input),
    args = normalizeWindowsArguments(argumentsList);
  windowsCommandLine(request.launcher.path, launcherVector(request, args));
  requireWindows(
    platform === "win32" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      isWindows2025Image({
        build,
        imageOS: env.ImageOS,
        imageVersion: env.ImageVersion,
      }) &&
      typeof effects?.persist === "function",
  );
  const record = {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    request: structuredClone(request),
    arguments: [...args],
    requestSha256: windowsLaunchDigest(request, args),
    status: "BLOCKED",
    phase: "inputs",
    admission: "not-started",
    helpers: [],
    payload: null,
    accountSid: null,
    missingInputs: [],
    reservation: "RETAINED",
  };
  for (const [key, name] of Object.entries({
    verifyInputs: "windows-reviewed-system-source-loader-inputs",
    inspect: "windows-independent-held-process-observer",
    verifySetup: "windows-private-account-job-storage-observer",
    installPolicy: "windows-complete-authority-policy-owner",
    verifyAuthority: "windows-token-job-policy-verifier",
    verifyReceipt: "windows-protected-receipt-verifier",
    retire: "windows-independent-retirement-owner",
  }))
    if (typeof effects[key] !== "function") record.missingInputs.push(name);
  if (!approvedSha256)
    record.missingInputs.push("independent-windows-launch-approval");
  let persistence = Promise.resolve(),
    failed = false,
    transport,
    verified;
  const save = () => {
    const snapshot = structuredClone(record),
      write = () => effects.persist(snapshot);
    persistence = persistence.then(write, write);
    return persistence;
  };
  if (record.missingInputs.length) {
    await save();
    return { record, transport: null };
  }
  const started = now();
  let expired = false,
    rejectDeadline;
  const deadline = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  deadline.catch(() => {});
  const timer = schedule(() => {
    expired = true;
    transport?.close();
    rejectDeadline(new Error("Windows admission deadline"));
  }, 30000);
  const wait = (value) => {
    const pending = Promise.race([value, deadline]);
    return transport?.wait ? transport.wait(pending) : pending;
  };
  const bounded = () => {
    const elapsed = now() - started;
    requireWindows(
      !failed &&
        !expired &&
        Number.isFinite(elapsed) &&
        elapsed >= 0 &&
        elapsed <= 30000,
    );
  };
  const helper = (value, role, settled = false) => {
    bounded();
    const identity = systemIdentity(value.identity),
      binding = verified.helperBindings?.[role];
    requireWindows(
      binding &&
        hash(binding.sha256) &&
        hash(binding.sourceSha256) &&
        value.imageSha256 === binding.sha256 &&
        value.sourceSha256 === binding.sourceSha256 &&
        (role === "launcher" ||
          identity.pid !== record.helpers[0].identity.pid) &&
        identity.pid !== record.payload?.pid,
    );
    const prior = record.helpers.find(
      (item) => item.identity.pid === identity.pid,
    );
    if (prior) {
      requireWindows(
        prior.role === role &&
          sameWindowsIdentity(prior.identity, identity) &&
          (!prior.settled || settled),
      );
      prior.settled = settled;
    } else {
      requireWindows(record.helpers.length < 16);
      record.helpers.push({
        role,
        identity,
        imageSha256: value.imageSha256,
        sourceSha256: value.sourceSha256,
        settled,
      });
    }
    return identity;
  };
  const observe = async (payload) => {
    bounded();
    const observed = structuredClone(
      await wait(
        effects.inspect(
          structuredClone(request),
          structuredClone({
            helper: record.helpers[0].identity,
            payload,
            helpers: structuredClone(record.helpers),
          }),
        ),
      ),
    );
    bounded();
    requireWindows(
      observed.independent === true &&
        observed.requestSha256 === record.requestSha256 &&
        hash(observed.nativeEventSha256) &&
        sameWindowsIdentity(observed.helper, record.helpers[0].identity) &&
        (payload === null
          ? observed.payload === null
          : sameWindowsIdentity(observed.payload, payload)),
    );
    const verifiers = dense(observed.verifiers, 4);
    requireWindows(verifiers.length > 0);
    const helpers = dense(observed.helpers, 16);
    requireWindows(
      helpers.length === record.helpers.length &&
        helpers.every(
          (entry, index) =>
            entry.role === record.helpers[index].role &&
            sameWindowsIdentity(
              entry.identity,
              record.helpers[index].identity,
            ) &&
            entry.imageSha256 === record.helpers[index].imageSha256 &&
            entry.sourceSha256 === record.helpers[index].sourceSha256,
        ),
    );
    for (const verifier of verifiers) helper(verifier, "verifier");
    bounded();
    await wait(save());
  };
  try {
    requireWindows(approvedSha256 === record.requestSha256);
    verified = structuredClone(
      await wait(
        effects.verifyInputs(structuredClone(request), approvedSha256, [
          ...args,
        ]),
      ),
    );
    bounded();
    if (verified.missingInputs !== undefined) {
      record.missingInputs = dense(verified.missingInputs, 256);
      requireWindows(
        record.missingInputs.every(
          (name) =>
            typeof name === "string" &&
            name.length > 0 &&
            name.length <= 512 &&
            !/[\u0000-\u001f\u007f]/u.test(name),
        ),
      );
      if (record.missingInputs.length) {
        await wait(save());
        return { record, transport: null };
      }
    }
    closed(verified.bindings, Object.keys(request.bindings));
    requireWindows(
      verified.approvedSha256 === approvedSha256 &&
        Object.keys(request.bindings).every(
          (key) => verified.bindings[key] === request.bindings[key],
        ) &&
        verified.privilegedContext === "local-system-session-0" &&
        verified.sdkExportsVerified === true &&
        verified.loaderClosureVerified === true &&
        verified.parser === WINDOWS_ARGUMENT_PARSER &&
        verified.helperBindings?.launcher?.sha256 === request.launcher.sha256,
    );
    bounded();
    record.status = "RUNNING";
    record.admission = "possible";
    record.phase = "helper";
    await wait(save());
    const onHelper = async (frame) => {
      bounded();
      requireWindows(
        record.status === "RUNNING" &&
          record.phase === "helper" &&
          record.helpers.length === 0 &&
          frame.payload === null &&
          frame.accountSid === null,
      );
      helper(
        {
          identity: frame.helper,
          imageSha256: request.launcher.sha256,
          sourceSha256: verified.helperBindings.launcher.sourceSha256,
        },
        "launcher",
      );
      await wait(save());
      await observe(null);
      assertWindowsReceipt(
        await wait(
          effects.verifyReceipt(
            structuredClone(request),
            structuredClone(record),
          ),
        ),
        record,
      );
      bounded();
    };
    const onSetup = async (frame) => {
      bounded();
      requireWindows(
        record.status === "RUNNING" &&
          record.phase === "helper" &&
          record.accountSid === null &&
          sameWindowsIdentity(frame.helper, record.helpers[0].identity),
      );
      record.accountSid = sid(frame.accountSid);
      requireWindows(
        /^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$/u.test(record.accountSid) &&
          record.accountSid !== request.restrictingSid,
      );
      record.phase = "setup";
      await wait(save());
      const setup = await wait(
        effects.verifySetup(structuredClone(request), structuredClone(record)),
      );
      bounded();
      record.setup = structuredClone(
        assertWindowsSetup(setup, request, record),
      );
      await observe(null);
      record.phase = "policy";
      await wait(save());
      let policyAdmissions = 0,
        policyAdmission = Promise.resolve();
      const onPolicyHelper = (entry) => {
        policyAdmissions++;
        // Serialize held-helper inspection and its immutable receipt. A caught
        // rejection or an unawaited admission must never permit creation.
        const admission = policyAdmission
          .then(async () => {
            bounded();
            requireWindows(
              record.status === "RUNNING" &&
                record.phase === "policy" &&
                !record.policyReceiptSha256 &&
                entry.role === "wfp" &&
                entry.settled === false,
            );
            helper(entry, "wfp");
            await wait(save());
            await observe(null);
            assertWindowsReceipt(
              await wait(
                effects.verifyReceipt(
                  structuredClone(request),
                  structuredClone(record),
                ),
              ),
              record,
            );
            bounded();
          })
          .catch((error) => {
            failed = true;
            throw error;
          })
          .finally(() => {
            policyAdmissions--;
          });
        policyAdmission = admission;
        admission.catch(() => {});
        return admission;
      };
      const installed = structuredClone(
        await wait(
          effects.installPolicy(
            structuredClone(request),
            structuredClone(record),
            onPolicyHelper,
          ),
        ),
      );
      bounded();
      requireWindows(
        policyAdmissions === 0 &&
          installed.independent === true &&
          installed.installed === true &&
          installed.requestSha256 === record.requestSha256 &&
          installed.accountSid === record.accountSid &&
          installed.restrictingSid === request.restrictingSid &&
          installed.compositionSha256 === request.bindings.policy &&
          hash(installed.receiptSha256) &&
          hash(installed.nativeEventSha256),
      );
      assertWindowsPolicy(installed, request, record);
      requireWindows(
        record.helpers.some(
          (entry) =>
            entry.role === "verifier" &&
            sameWindowsIdentity(entry.identity, installed.verifier),
        ),
      );
      const helpers = dense(installed.helpers, 8);
      requireWindows(
        helpers.length > 0 &&
          helpers.length ===
            record.helpers.filter((entry) => entry.role === "wfp").length &&
          new Set(helpers.map((entry) => entry.identity.pid)).size ===
            helpers.length,
      );
      for (const entry of helpers) {
        requireWindows(
          entry.role === "wfp" &&
            entry.settled === true &&
            record.helpers.some(
              (prior) =>
                prior.role === "wfp" &&
                !prior.settled &&
                sameWindowsIdentity(prior.identity, entry.identity),
            ),
        );
        helper(entry, entry.role, entry.settled);
      }
      record.policyReceiptSha256 = installed.receiptSha256;
      record.phase = "create";
      await wait(save());
      assertWindowsReceipt(
        await wait(
          effects.verifyReceipt(
            structuredClone(request),
            structuredClone(record),
          ),
        ),
        record,
      );
      bounded();
    };
    const launching = Promise.resolve(
      (effects.launchParked ?? nativeTransport)(
        structuredClone(request),
        [...args],
        structuredClone(verified),
        onHelper,
        onSetup,
      ),
    ).then((value) => {
      if (failed || expired) value.close();
      return value;
    });
    transport = await wait(launching);
    const ready = await wait(transport.ready);
    bounded();
    requireWindows(
      record.policyReceiptSha256 &&
        ready.accountSid === record.accountSid &&
        sameWindowsIdentity(ready.helper, record.helpers[0].identity),
    );
    record.payload = normalizeWindowsIdentity(ready.payload);
    requireWindows(
      record.payload.userSid === record.accountSid &&
        record.payload.sessionId === 0 &&
        !record.helpers.some(
          (entry) => entry.identity.pid === record.payload.pid,
        ),
    );
    record.phase = "verify";
    await wait(save());
    await observe(record.payload);
    const authority = structuredClone(
      assertWindowsAuthority(
        await wait(
          effects.verifyAuthority(
            structuredClone(request),
            structuredClone(record),
          ),
        ),
        request,
        record,
      ),
    );
    bounded();
    record.authority = authority;
    record.phase = "release";
    await wait(save());
    assertWindowsReceipt(
      await wait(
        effects.verifyReceipt(
          structuredClone(request),
          structuredClone(record),
        ),
      ),
      record,
    );
    const fresh = assertWindowsAuthority(
      await wait(
        effects.verifyAuthority(
          structuredClone(request),
          structuredClone(record),
        ),
      ),
      request,
      record,
    );
    const { nativeEventSha256: priorEvent, ...priorAuthority } = authority;
    const { nativeEventSha256: freshEvent, ...freshAuthority } = fresh;
    requireWindows(
      hash(priorEvent) &&
        hash(freshEvent) &&
        JSON.stringify(freshAuthority) === JSON.stringify(priorAuthority),
    );
    bounded();
    await wait(transport.release());
    bounded();
    record.status = "ADMITTED";
    await wait(save());
    const native = transport,
      admitted = structuredClone(record);
    let settling = false;
    return {
      record: structuredClone(admitted),
      transport: {
        output: native.output,
        completion: native.completion,
        async settle() {
          requireWindows(!settling);
          settling = true;
          const retired = await effects.retire(
            structuredClone(request),
            structuredClone(admitted),
          );
          const verifier = systemIdentity(retired?.freshVerifier);
          requireWindows(
            retired?.status === "RETIRED" &&
              retired.independent === true &&
              hash(retired.nativeEventSha256) &&
              retired.requestSha256 === admitted.requestSha256 &&
              retired.accountSid === admitted.accountSid &&
              retired.noLiveMembers === true &&
              retired.helpersSettled === true &&
              retired.jobObjectSha256 === admitted.setup.job.heldObjectSha256 &&
              retired.reservation === "RETAINED" &&
              !admitted.helpers.some(
                (entry) => entry.identity.pid === verifier.pid,
              ) &&
              verifier.pid !== admitted.payload.pid,
          );
          native.close();
        },
      },
    };
  } catch {
    failed = true;
    transport?.close();
    record.status = "FAIL";
    await save();
    // EOF/launcher exit/Job close is not a complete retirement observation.
    // Possible accounts, filters, handles and processes remain in owned custody.
    return { record, transport: null };
  } finally {
    cancel(timer);
  }
}
