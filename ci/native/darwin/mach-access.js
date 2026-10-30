import { observationDigest, observationObject } from "../index.js";
import { normalizeDarwinIdentity, sameDarwinIdentity } from "./protocol.js";
import { denialEvents, startupTimestamp } from "./startup-crash.js";

const source = "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox";
const requireMach = (value, reason) => {
  if (!value) throw new Error("Unverified Darwin mach-lookup: " + reason);
};

/** Experiment admission only; recovery may inspect older selectors solely to
 * retire their original owners, never to manufacture current access evidence. */
export function assertDarwinMachRecord(value, input, baseCount = 12) {
  requireMach(
    value.purpose === "experiment" && value.schemaVersion === 2,
    "record version",
  );
  observationObject(value.mach, ["source", "tool"]);
  observationObject(value.mach.tool, ["index", "cdhash"]);
  const { tool } = value.mach,
    asset = value.assets[tool.index - baseCount];
  requireMach(
    value.mach.source === "unified-log-mach-v1" &&
      Number.isSafeInteger(tool.index) &&
      [12, 13].includes(baseCount) &&
      tool.index >= baseCount &&
      asset?.kind === "helper" &&
      asset.path === "/usr/bin/log" &&
      /^[a-f0-9]{64}$/u.test(asset.sha256) &&
      /^[a-f0-9]{40}$/u.test(tool.cdhash) &&
      value.attempts.length === 39 &&
      value.attempts.every((attempt, i) =>
        i === 13
          ? attempt.operation === "mach" &&
            attempt.source === value.mach.source &&
            attempt.event === null &&
            attempt.controlEvent === null
          : attempt.operation !== "mach" &&
            attempt.source === "bsm" &&
            Number.isSafeInteger(attempt.event) &&
            attempt.event > 0 &&
            Number.isSafeInteger(attempt.controlEvent) &&
            attempt.controlEvent > 0,
      ),
    "observation source",
  );
  if (input)
    requireMach(
      input.source === value.mach.source &&
        input.tool.path === asset.path &&
        input.tool.sha256 === asset.sha256 &&
        input.tool.cdhash === tool.cdhash,
      "installed log tool binding",
    );
}

/** Log selectors are deliberately rounded; only the native custody window may
 * admit an event. Startup diagnostic classifications supply no access verdict. */
export function darwinMachLogArguments(result, subject, service) {
  const { startedAt, endedAt } = result.mach,
    start = startupTimestamp(startedAt).time,
    end = startupTimestamp(endedAt).time;
  requireMach(
    start !== undefined &&
      end !== undefined &&
      start <= end &&
      end - start <= 30000000n,
    "attempt window",
  );
  requireMach(
    Number.isSafeInteger(subject.pid) &&
      subject.pid > 1 &&
      /^org\.native-poc\.[a-f0-9]{32}$/u.test(service),
    "selectors",
  );
  const date = (seconds) =>
    new Date(Number(seconds) * 1000)
      .toISOString()
      .slice(0, 19)
      .replace("T", " ") + "+0000";
  return [
    "--start",
    date(start / 1000000n),
    "--end",
    date(end / 1000000n + 1n),
    "--info",
    "--debug",
    "--predicate",
    `processID == 0 AND senderImagePath == "${source}" AND eventMessage CONTAINS "(${subject.pid})" AND eventMessage CONTAINS "${service}"`,
  ];
}

/** The caller is independently inspected on both sides while retained. Child
 * return values must agree with either a native audit trailer or a kernel log. */
export function bindDarwinMachAccess(
  result,
  before,
  after,
  { nonce, service, control, log },
) {
  try {
    observationObject(result, [
      "nonce",
      "result",
      "nativeCode",
      "lookupCode",
      "sendCode",
      "mach",
    ]);
    observationObject(result.mach, [
      "source",
      "startedAt",
      "endedAt",
      "before",
      "after",
      "receipt",
    ]);
    const identity = normalizeDarwinIdentity(before),
      native = result.mach;
    requireMach(
      result.nonce === nonce &&
        /^[a-f0-9]{32}$/u.test(nonce) &&
        service === "org.native-poc." + nonce &&
        native.source === "custody-mach-v1" &&
        sameDarwinIdentity(identity, after) &&
        sameDarwinIdentity(identity, native.before) &&
        sameDarwinIdentity(identity, native.after),
      "caller birth, credentials or audit identity",
    );
    darwinMachLogArguments(result, identity, service);
    if (control) {
      requireMach(
        result.result === 0 &&
          result.nativeCode === 0 &&
          result.lookupCode === 0 &&
          result.sendCode === 0,
        "control lookup or delivery",
      );
      observationObject(native.receipt, [
        "nonce",
        "service",
        "sender",
        "auditToken",
      ]);
      const receipt = native.receipt,
        token = [
          "auid",
          "uid",
          "gid",
          "ruid",
          "rgid",
          "pid",
          "asid",
          "pidVersion",
        ].map((key) => identity[key]);
      requireMach(
        receipt.nonce === nonce &&
          receipt.service === service &&
          sameDarwinIdentity(receipt.sender, identity) &&
          Array.isArray(receipt.auditToken) &&
          receipt.auditToken.length === 8 &&
          token.every((word, i) => receipt.auditToken[i] === word),
        "control audit trailer",
      );
    } else {
      requireMach(
        result.result === -1 &&
          result.lookupCode === 1100 &&
          result.nativeCode === 1100 &&
          result.sendCode === null &&
          native.receipt === null,
        "unsupported or contradictory lookup result",
      );
      const parsed = denialEvents(log),
        escaped = service.replaceAll(".", "\\."),
        message = new RegExp(
          `^Sandbox: [^\\s()]+\\(${identity.pid}\\) deny\\([0-9]+\\) mach-lookup ${escaped}$`,
          "u",
        ),
        matches = parsed.events?.filter((event) =>
          message.test(event.eventMessage),
        );
      requireMach(
        matches?.length === 1,
        "missing, redacted or ambiguous denial record",
      );
      const event = matches[0],
        time = startupTimestamp(event.timestamp).time;
      requireMach(
        event.processID === 0 &&
          event.processImagePath === "/kernel" &&
          event.senderImagePath === source,
        "denial source",
      );
      requireMach(
        time >= startupTimestamp(native.startedAt).time &&
          time <= startupTimestamp(native.endedAt).time,
        "denial outside exact attempt window",
      );
    }
    return {
      kind: "ipc",
      error: result.nativeCode,
      id: observationDigest({
        result,
        before: identity,
        after,
        log: control ? null : log,
      }),
    };
  } catch (cause) {
    if (cause.message.startsWith("Unverified Darwin mach-lookup:")) throw cause;
    throw new Error("Unverified Darwin mach-lookup: malformed observation", {
      cause,
    });
  }
}
