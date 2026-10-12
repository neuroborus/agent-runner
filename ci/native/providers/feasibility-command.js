import { createInterface } from "node:readline";
import { lstat, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, randomUUID } from "node:crypto";
import {
  spawnOwnedProcess,
  readProcessIdentity,
} from "../../../src/agents/index.js";
import { requireFeasibility } from "../feasibility/index.js";
import {
  createLinuxObserverDecoder,
  openLinuxTraceCapture,
  normalizeLinuxReceipt,
  processDetails,
  freshVerifier,
  observeLinuxFeasibilitySentinel,
  resolveLinuxDiagnosticLauncher,
  linuxDiagnosticError,
} from "../linux/index.js";
import { runDarwinFeasibilityCommand } from "../darwin/index.js";
import { runWindowsFeasibilityCommand } from "../win32/index.js";
import {
  feasibilityDigest as digest,
  requireProviderFeasibilityCI,
} from "./feasibility-inputs.js";

function commandEvidence(condition, detail, code = "missing-observation") {
  if (condition) return;
  const error = new Error("Command evidence failed.");
  error.feasibilityCause = { code, detail };
  throw error;
}

function commandFailure(code, cause) {
  return Object.assign(
    new Error("Model-free App Server operation failed.", { cause }),
    {
      code,
      isCommandFailure: true,
    },
  );
}

export function feasibilityCommandError(phase, operation, error) {
  // Diagnostic wrapping must preserve the provider's existing BLOCKED cases.
  const wrapped = linuxDiagnosticError(
    phase,
    operation,
    error,
    ["ENOENT", "ERR_FEASIBILITY_ROUTE_UNAVAILABLE"].includes(error?.code)
      ? "prerequisite-unavailable"
      : "setup-failed",
  );
  Object.defineProperty(wrapped, "cause", { value: error });
  return wrapped;
}

/** Observe resolved native exits as well as admission rejections. Stderr remains
 * private and bounded; only the existing diagnostic normalizer receives it. */
export function observeFeasibilityCompletion(child, describe) {
  let stderr = Buffer.alloc(0);
  const capture = (chunk) => {
    if (stderr.length < 8192)
      stderr = Buffer.concat([stderr, chunk.subarray(0, 8192 - stderr.length)]);
  };
  child.stderr.on("data", capture);
  return child.ownedCompletion
    .then(
      ({ outcome }) =>
        outcome.type === "close" && outcome.exitCode === 0 && !outcome.signal
          ? null
          : describe({ ...outcome, stderr }),
      (error) => describe({ ...error, stderr }),
    )
    .finally(() => child.stderr.removeListener("data", capture));
}

/** The installed release must actually declare this buffered route and both
 * policies. Descriptive mentions of permissionProfile are not a schema field. */
export function supportsFeasibilityCommand(schema) {
  const params = schema?.params,
    response = schema?.response;
  return (
    params?.title === "CommandExecParams" &&
    params.type === "object" &&
    params.required?.includes("command") &&
    params.properties?.command?.type === "array" &&
    params.properties.command.items?.type === "string" &&
    ["cwd", "timeoutMs", "outputBytesCap", "sandboxPolicy"].every((name) =>
      Object.hasOwn(params.properties, name),
    ) &&
    ["readOnly", "workspaceWrite"].every((type) =>
      params.definitions?.SandboxPolicy?.oneOf?.some(
        (policy) =>
          policy.properties?.type?.enum?.includes(type) &&
          policy.properties.networkAccess?.type === "boolean" &&
          (type === "readOnly" ||
            ["writableRoots", "excludeTmpdirEnvVar", "excludeSlashTmp"].every(
              (name) => Object.hasOwn(policy.properties, name),
            )),
      ),
    ) &&
    response?.title === "CommandExecResponse" &&
    ["exitCode", "stdout", "stderr"].every((name) =>
      response.required?.includes(name),
    )
  );
}

export function feasibilityCommandParameters(
  command,
  cwd,
  profile,
  platform = process.platform,
) {
  const paths = platform === "win32" ? path.win32 : path;
  requireFeasibility(
    Array.isArray(command) &&
      command.length > 0 &&
      command.length <= 8 &&
      command.every(
        (value) =>
          typeof value === "string" &&
          value.length <= 8192 &&
          !value.includes("\0"),
      ) &&
      paths.isAbsolute(cwd) &&
      paths.normalize(cwd) === cwd &&
      ["read-only", "workspace-write"].includes(profile),
  );
  return {
    command,
    cwd,
    timeoutMs: 10000,
    // 0.160.0 Windows accepts only its default 1 MiB buffered cap. Omitting the
    // custom cap selects that bound; the client still rejects replies >8 KiB.
    ...(platform === "win32" ? {} : { outputBytesCap: 4096 }),
    sandboxPolicy:
      profile === "read-only"
        ? { type: "readOnly", networkAccess: false }
        : {
            type: "workspaceWrite",
            writableRoots: [cwd],
            networkAccess: false,
            excludeTmpdirEnvVar: true,
            excludeSlashTmp: true,
          },
  };
}

function protocolObject(value, required, optional = []) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every(
      (key) => required.includes(key) || optional.includes(key),
    )
  );
}

function warningPosition(value) {
  return (
    protocolObject(value, ["line", "column"]) &&
    [value.line, value.column].every(
      (number) => Number.isSafeInteger(number) && number >= 1,
    )
  );
}

function validConfigWarning(value) {
  const params = value.params;
  return (
    protocolObject(value, ["method", "params"]) &&
    protocolObject(params, ["summary", "details"], ["path", "range"]) &&
    typeof params.summary === "string" &&
    (params.details === null || typeof params.details === "string") &&
    (!Object.hasOwn(params, "path") || typeof params.path === "string") &&
    (!Object.hasOwn(params, "range") ||
      (protocolObject(params.range, ["start", "end"]) &&
        warningPosition(params.range.start) &&
        warningPosition(params.range.end)))
  );
}

function disabledRemoteStatusRejection(value) {
  const params = value.params;
  if (!protocolObject(value, ["method", "params"])) return "envelope";
  if (
    !protocolObject(params, [
      "status",
      "serverName",
      "installationId",
      "environmentId",
    ])
  )
    return "payload";
  if (params.status !== "disabled") return "status";
  if (typeof params.serverName !== "string") return "server-name-type";
  if (typeof params.installationId !== "string") return "installation-id-type";
  if (params.environmentId !== null && typeof params.environmentId !== "string")
    return "environment-id-type";
  return null;
}

function rejectedProtocolShape(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return "non-object";
  if (Object.hasOwn(value, "method"))
    return Object.hasOwn(value, "id") ? "request" : "notification";
  if (!Object.hasOwn(value, "id")) return "other-object";
  const type = value.id === null ? "null" : typeof value.id;
  return `reply-${["number", "string", "null"].includes(type) ? type : "other"}`;
}

/** A separate model-free client: no thread, turn, fs RPC, approval, or model. */
export function openFeasibilityCommand(
  transport,
  signal,
  platform = process.platform,
) {
  requireFeasibility(
    transport?.input && transport.output && transport.errorOutput,
  );
  const pending = new Map(),
    readers = [],
    lines = createInterface({ input: transport.output, crlfDelay: Infinity });
  let sequence = 0,
    bytes = 0,
    failed = false,
    firstFailure = null,
    processFailure = null,
    initialized = false;
  const remember = (error) => {
    if (!firstFailure) {
      firstFailure = error;
      const [id, entry] = pending.entries().next().value ?? [];
      if (entry && error.isCommandFailure)
        Object.assign(error, { rpcMethod: entry.method, rpcId: id });
    }
    return firstFailure;
  };
  const fail = (
    error = processFailure ??
      commandFailure("ERR_FEASIBILITY_TRANSPORT_FAILED"),
  ) => {
    failed = true;
    const first = remember(error);
    for (const entry of pending.values()) entry.reject(first);
    pending.clear();
  };
  const completion = platform === "linux" ? transport.completion : null;
  completion?.then((error) => {
    processFailure = error;
    if (error) fail();
  });
  const inputFailed = (error) => {
    const reject = () =>
      fail(
        processFailure ??
          commandFailure("ERR_FEASIBILITY_TRANSPORT_FAILED", error),
      );
    return completion ? completion.then(reject) : reject();
  };
  transport.input.on("error", inputFailed);
  const boundOutput = (chunk) => {
    bytes += Buffer.byteLength(chunk);
    if (bytes > 1048576) {
      fail(
        processFailure ??
          Object.assign(commandFailure("ERR_FEASIBILITY_TRANSPORT_FAILED"), {
            readerReason: "total-bound",
          }),
      );
      transport.output.destroy();
    }
  };
  transport.output.on("data", boundOutput);
  const abort = () => fail(commandFailure("ERR_FEASIBILITY_DEADLINE"));
  signal?.addEventListener("abort", abort, { once: true });
  readers.push(
    (async () => {
      let readerStage = "stream",
        readerReason = null,
        readerShape = null,
        readerSubreason = null;
      try {
        for await (const line of lines) {
          readerStage = "envelope";
          readerReason = bytes > 1048576 ? "total-bound" : "line-bound";
          requireFeasibility(bytes <= 1048576 && line.length <= 65536);
          readerReason = null;
          readerStage = "json";
          const value = JSON.parse(line);
          readerStage = "envelope";
          // Pinned startup notifications can precede local initialization or
          // arrive without a pending request. Their payload is never evidence.
          if (value?.method === "configWarning") {
            readerReason = "config-warning";
            requireFeasibility(validConfigWarning(value));
            readerReason = null;
            readerStage = "stream";
            continue;
          }
          if (value?.method === "remoteControl/status/changed") {
            readerReason = "remote-status";
            readerSubreason = disabledRemoteStatusRejection(value);
            requireFeasibility(readerSubreason === null);
            readerReason = null;
            readerStage = "stream";
            continue;
          }
          readerReason = "reply-envelope";
          readerShape = rejectedProtocolShape(value);
          requireFeasibility(
            protocolObject(value, ["id"], ["result", "error"]) &&
              Object.hasOwn(value, "result") !== Object.hasOwn(value, "error"),
          );
          const entry = pending.get(value.id);
          readerReason = "pending-id";
          requireFeasibility(entry);
          readerShape = null;
          if (Object.hasOwn(value, "error")) {
            readerReason = "error-payload";
            requireFeasibility(
              protocolObject(value.error, ["code", "message"], ["data"]) &&
                Number.isSafeInteger(value.error.code) &&
                typeof value.error.message === "string",
            );
            const error = commandFailure(
              entry.method === "command/exec" && value.error.code === -32601
                ? "ERR_FEASIBILITY_ROUTE_UNAVAILABLE"
                : "ERR_FEASIBILITY_RPC_REJECTED",
              // Leave room for a truncated UTF-8 sequence's replacement character.
              new Error(
                typeof value.error.message === "string"
                  ? Buffer.from(value.error.message.slice(0, 8192))
                      .subarray(0, 8189)
                      .toString("utf8")
                  : "",
              ),
            );
            error.rpcCode = Number.isSafeInteger(value.error.code)
              ? value.error.code
              : null;
            entry.reject(remember(error));
          } else entry.resolve(value.result);
          pending.delete(value.id);
          readerReason = null;
          readerStage = "stream";
        }
        if (pending.size) {
          // EOF can precede the owned supervisor's retirement-backed outcome.
          if (completion) processFailure = await completion;
          fail();
        }
      } catch (error) {
        fail(
          Object.assign(
            commandFailure("ERR_FEASIBILITY_READER_FAILED", error),
            { readerStage, readerReason, readerShape, readerSubreason },
          ),
        );
      }
    })(),
    (async () => {
      let readerReason = null;
      try {
        for await (const chunk of transport.errorOutput) {
          bytes += chunk.length;
          readerReason = "total-bound";
          requireFeasibility(bytes <= 1048576);
          readerReason = null;
        }
      } catch (error) {
        fail(
          Object.assign(
            commandFailure("ERR_FEASIBILITY_READER_FAILED", error),
            { readerStage: "stream", readerReason },
          ),
        );
      }
    })(),
  );
  const rpc = async (method, params) => {
    if (firstFailure) throw firstFailure;
    requireFeasibility(
      !failed && !signal?.aborted && pending.size === 0 && sequence < 8,
    );
    const id = ++sequence;
    let timer;
    try {
      return await new Promise((resolve, reject) => {
        timer = setTimeout(abort, 15000);
        pending.set(id, { resolve, reject, method });
        transport.input.write(
          JSON.stringify({ id, method, params }) + "\n",
          (error) => {
            if (error) inputFailed(error);
          },
        );
      });
    } finally {
      clearTimeout(timer);
    }
  };
  return {
    async initialize() {
      requireFeasibility(!initialized);
      const value = await rpc("initialize", {
        clientInfo: { name: "native-feasibility", version: "1" },
        capabilities: { experimentalApi: true },
      });
      initialized = true;
      transport.input.write(JSON.stringify({ method: "initialized" }) + "\n");
      return value;
    },
    async exec(params) {
      requireFeasibility(initialized);
      const profile =
        params?.sandboxPolicy?.type === "readOnly"
          ? "read-only"
          : "workspace-write";
      requireFeasibility(
        JSON.stringify(params) ===
          JSON.stringify(
            feasibilityCommandParameters(
              params.command,
              params.cwd,
              profile,
              platform,
            ),
          ),
      );
      const value = await rpc("command/exec", params);
      requireFeasibility(
        Number.isInteger(value?.exitCode) &&
          typeof value.stdout === "string" &&
          typeof value.stderr === "string" &&
          Buffer.byteLength(value.stdout + value.stderr) <= 8192,
      );
      return value;
    },
    async close() {
      transport.input.end();
      await Promise.all(readers);
      signal?.removeEventListener("abort", abort);
      transport.output.removeListener("data", boundOutput);
      if (failed) throw firstFailure;
      requireFeasibility(pending.size === 0);
    },
  };
}

/** Stock command sandbox, observed externally to the command using strace and
 * held sentinels. Owned namespace receipts are freshly checked after retirement. */
export async function runFeasibilityCommandProbe(dispatch, inputs) {
  requireProviderFeasibilityCI(dispatch.platform, dispatch.expectedSha);
  if (dispatch.platform === "darwin")
    return runDarwinFeasibilityCommand(dispatch, inputs, {
      open: openFeasibilityCommand,
      parameters: feasibilityCommandParameters,
      supports: supportsFeasibilityCommand,
    });
  if (dispatch.platform === "win32")
    return runWindowsFeasibilityCommand(dispatch, inputs, {
      open: (transport, signal) =>
        openFeasibilityCommand(transport, signal, "win32"),
      parameters: (command, cwd, profile) =>
        feasibilityCommandParameters(command, cwd, profile, "win32"),
      supports: supportsFeasibilityCommand,
    });
  if (dispatch.platform !== "linux") return null;
  const started = Date.now(),
    nonce = randomBytes(16).toString("hex"),
    receipts = [],
    children = [];
  const directory = await mkdtemp(
    path.join(process.env.RUNNER_TEMP, "native-command-feasibility-"),
  );
  const workspace = path.join(directory, "workspace"),
    home = path.join(directory, "home"),
    schemaDirectory = path.join(directory, "schema");
  for (const name of [workspace, home, schemaDirectory])
    await mkdir(name, { mode: 0o700 });
  const inspection = path.join(workspace, "inspection.txt"),
    edit = path.join(workspace, "edit.txt"),
    outside = path.join(directory, "outside.txt");
  for (const file of [inspection, edit, outside])
    await writeFile(file, nonce, { flag: "wx", mode: 0o600 });
  const before = await observeLinuxFeasibilitySentinel(outside);
  const codex = inputs.packages.codex,
    helper = {
      role: "helper",
      name: "command-observer",
      version: "1",
      sha256: digest(await readFile(fileURLToPath(import.meta.url))),
    };
  await writeFile(
    path.join(directory, "intent.json"),
    JSON.stringify({
      candidateSha: dispatch.expectedSha,
      nonce,
      imageSha256: codex.component.sha256,
      profiles: ["read-only", "workspace-write"],
    }),
    { flag: "wx", mode: 0o400 },
  );
  const env = {
    PATH: `${path.join(codex.directory, "codex-path")}:/usr/bin:/bin`,
    HOME: home,
    CODEX_HOME: home,
    LANG: "C",
  };
  let emergency = false,
    timer,
    client,
    capture,
    captureUncertain = false,
    settlements,
    result;
  let operation = "tool-version";
  let firstProcessFailure = null;
  const admissions = new WeakMap();
  const verifyRetirement = async () => {
    requireFeasibility(receipts.length === children.length);
    const observed = [];
    for (const receipt of receipts) {
      const value = await freshVerifier(receipt.file, receipt.sha256);
      requireFeasibility(
        value.status === "RETIRED" &&
          value.independent &&
          !value.emergencyCleanup,
      );
      observed.push(value);
    }
    return observed;
  };
  const start = (file, args, stdio = ["pipe", "pipe", "pipe"]) => {
    const child = spawnOwnedProcess(file, args, {
      cwd: workspace,
      env,
      stdio,
      resolveLauncher: resolveLinuxDiagnosticLauncher,
      async onProcess(pid, admission) {
        if (pid === null) return;
        admissions.set(child, false);
        const init = await processDetails(pid),
          controller = await processDetails(process.pid);
        const receipt = normalizeLinuxReceipt({
          schemaVersion: 1,
          candidateSha: dispatch.expectedSha,
          caseId: "argv",
          nonce: randomUUID(),
          policyDigest: digest(JSON.stringify({ file, args })),
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
          launcher: {
            pid: child.pid,
            identity: await readProcessIdentity(child.pid),
          },
          controller: { pid: process.pid, identity: controller.identity },
          admission,
        });
        const fileName = path.join(
            directory,
            `receipt-${receipts.length}.json`,
          ),
          bytes = JSON.stringify(receipt);
        await writeFile(fileName, bytes, { flag: "wx", mode: 0o400 });
        receipts.push({ file: fileName, sha256: digest(bytes) });
        admissions.set(child, true);
      },
    });
    const describe = (error) => {
      const admitted = admissions.get(child) === true;
      firstProcessFailure ??= feasibilityCommandError(
        admitted ? "command" : "admission",
        admitted
          ? operation
          : admissions.has(child)
            ? "command-receipt-registration"
            : "owned-process-admission",
        error,
      );
      return firstProcessFailure;
    };
    child.feasibilityCompletion = observeFeasibilityCompletion(child, describe);
    children.push(child);
    return child;
  };
  const collect = async (child) => {
    let stdout = "",
      stderr = "";
    await Promise.all([
      ...[
        [child.stdout, true],
        [child.stderr, false],
      ].map(async ([stream, output]) => {
        for await (const chunk of stream) {
          if (output) stdout += chunk.toString();
          else stderr += chunk.toString();
          requireFeasibility(Buffer.byteLength(stdout + stderr) <= 8192);
        }
      }),
      child.ownedCompletion.then(({ outcome }) => {
        if (
          outcome.type !== "close" ||
          outcome.exitCode !== 0 ||
          outcome.signal
        )
          throw feasibilityCommandError("command", operation, {
            ...outcome,
            stderr,
          });
      }),
    ]);
    return stdout;
  };
  try {
    timer = setTimeout(() => {
      emergency = true;
      for (const child of children) child.kill("SIGKILL");
    }, 100000);
    const versionChild = start(codex.file, ["--version"]);
    versionChild.stdin.end();
    commandEvidence(
      (await collect(versionChild)).trim() === "codex-cli 0.160.0",
      "Observed Codex version differs from the fixed 0.160.0 input.",
      "setup-failed",
    );
    operation = "schema-generation";
    const schemaChild = start(codex.file, [
      "app-server",
      "generate-json-schema",
      "--out",
      schemaDirectory,
    ]);
    schemaChild.stdin.end();
    await collect(schemaChild);
    const readSchema = async (name) => {
      const file = path.join(schemaDirectory, "v2", name),
        identity = await lstat(file);
      requireFeasibility(
        identity.isFile() &&
          identity.nlink === 1 &&
          identity.size > 0 &&
          identity.size <= 1048576,
      );
      return JSON.parse(await readFile(file));
    };
    const schema = {
      params: await readSchema("CommandExecParams.json"),
      response: await readSchema("CommandExecResponse.json"),
    };
    if (!supportsFeasibilityCommand(schema))
      return {
        capability: "codex.command-exec",
        status: "BLOCKED",
        cause: {
          code: "prerequisite-unavailable",
          detail:
            "The installed schema lacks the bounded command route or supported sandbox policies.",
        },
        elapsedMs: Date.now() - started,
        components: [codex.component, inputs.tool, helper],
        evidence: null,
        cleanup: null,
      };
    const write = (file, value) => [
      process.execPath,
      "-e",
      "const f=require('fs');process.stdout.write('attempt');try{f.writeFileSync(process.argv[1],process.argv[2]);process.stdout.write(':written')}catch(e){process.stdout.write(':denied')}",
      file,
      value,
    ];
    const commands = [
      [
        process.execPath,
        "-e",
        "process.stdout.write(require('fs').readFileSync(process.argv[1],'utf8'))",
        inspection,
      ],
      write(edit, "read-only-escape"),
      write(edit, nonce + "-edited"),
      write(outside, "outside-escape"),
    ];
    operation = "trace-prerequisites";
    capture = await openLinuxTraceCapture(directory);
    const strace = "/usr/bin/strace",
      straceDigest = capture.observerSha256,
      events = [],
      executions = [];
    operation = "observer-version";
    const observerVersion = start(strace, ["--version"]);
    observerVersion.stdin.end();
    const straceVersion = (await collect(observerVersion))
      .trim()
      .split(/\r?\n/u)[0];
    commandEvidence(
      straceVersion.length > 0 && straceVersion.length <= 128,
      "The native observer version is unavailable.",
      "setup-failed",
    );
    const decoder = createLinuxObserverDecoder([
      process.execPath,
      inspection,
      edit,
      outside,
    ]);
    operation = "transport-admission";
    const child = await capture.launch(
      [
        codex.file,
        "-c",
        'web_search="disabled"',
        "-c",
        "mcp_servers={}",
        "app-server",
        "--listen",
        "stdio://",
      ],
      start,
    );
    const trace = async () => {
      for (const line of (await capture.read()).slice(0, -1).split("\n")) {
        const event = decoder.line(line);
        if (event) events.push(event);
        if (
          event?.opcode === "execve" &&
          event.errno === null &&
          event.target === process.execPath
        ) {
          const index = commands.findIndex((command) =>
            line.includes(
              `execve(${JSON.stringify(command[0])}, [${command.map((argument) => JSON.stringify(argument)).join(", ")}],`,
            ),
          );
          if (index !== -1) executions.push({ index, pid: event.pid });
        }
      }
      return decoder.finish();
    };
    client = openFeasibilityCommand(
      {
        input: child.stdin,
        output: child.stdout,
        errorOutput: child.stderr,
        completion: child.feasibilityCompletion,
      },
      AbortSignal.timeout(90000),
    );
    operation = "initialization";
    const initialized = await client.initialize();
    requireFeasibility(initialized.codexHome === home);
    operation = "inspection";
    const read = await client.exec(
      feasibilityCommandParameters(commands[0], workspace, "read-only"),
    );
    commandEvidence(
      read.exitCode === 0 && read.stdout === nonce,
      "The permitted inspection did not return the owned nonce.",
    );
    operation = "read-only-write-denial";
    const denied = await client.exec(
      feasibilityCommandParameters(commands[1], workspace, "read-only"),
    );
    commandEvidence(
      (await readFile(edit, "utf8")) === nonce,
      "Read-only command execution changed the workspace sentinel.",
      "observed-escape",
    );
    commandEvidence(
      denied.exitCode === 0 && denied.stdout === "attempt:denied",
      "The read-only write attempt was not acknowledged as denied.",
    );
    operation = "workspace-edit";
    const permitted = await client.exec(
      feasibilityCommandParameters(commands[2], workspace, "workspace-write"),
    );
    commandEvidence(
      permitted.exitCode === 0 &&
        permitted.stdout === "attempt:written" &&
        (await readFile(edit, "utf8")) === nonce + "-edited",
      "The permitted workspace edit control did not complete.",
    );
    operation = "outside-write-denial";
    const prohibited = await client.exec(
      feasibilityCommandParameters(commands[3], workspace, "workspace-write"),
    );
    const after = await observeLinuxFeasibilitySentinel(outside);
    commandEvidence(
      JSON.stringify(before) === JSON.stringify(after),
      "Workspace command execution changed the outside sentinel.",
      "observed-escape",
    );
    commandEvidence(
      prohibited.exitCode === 0 && prohibited.stdout === "attempt:denied",
      "The outside write attempt was not acknowledged as denied.",
    );
    await client.close();
    const completion = await child.ownedCompletion;
    requireFeasibility(
      completion.outcome.type === "close" &&
        completion.outcome.exitCode === 0 &&
        !completion.outcome.signal,
    );
    settlements = await verifyRetirement();
    await trace();
    requireFeasibility(
      commands.every(
        (_, index) =>
          executions.filter((entry) => entry.index === index).length === 1,
      ),
    );
    requireFeasibility(
      [inspection, edit, edit, outside].every((file, index) =>
        events.some(
          (entry) =>
            entry.target === file &&
            entry.pid ===
              executions.find((execution) => execution.index === index).pid &&
            (index === 0 || index === 2
              ? entry.errno === null
              : ["EACCES", "EPERM", "EROFS"].includes(entry.errno)),
        ),
      ),
    );
    requireFeasibility(!emergency);
    return (result = {
      capability: "codex.command-exec",
      status: "PASS",
      cause: null,
      elapsedMs: Date.now() - started,
      components: [
        codex.component,
        inputs.tool,
        helper,
        {
          role: "tool",
          name: "strace",
          version: straceVersion,
          sha256: straceDigest,
        },
      ],
      evidence: {
        ready: true,
        positiveControl: true,
        attemptAcknowledged: true,
        independent: true,
        outcome: "DENIED",
        observationSha256: digest(
          JSON.stringify({
            schema,
            events,
            executions,
            tools: capture.bindings,
          }),
        ),
        sentinelsBeforeSha256: digest(JSON.stringify(before)),
        sentinelsAfterSha256: digest(JSON.stringify(after)),
      },
      cleanup: null,
    });
  } catch (error) {
    captureUncertain = error.namespaceCleanupFailed === true;
    const first = feasibilityCommandError(
      "command",
      operation,
      error.isCommandFailure ? error : (firstProcessFailure ?? error),
    );
    if (error.code === "ERR_FEASIBILITY_ROUTE_UNAVAILABLE" && client) {
      try {
        await client.close();
        await children.at(-1).ownedCompletion;
      } catch {
        /* preserve unsupported-route cause */
      }
    }
    throw first;
  } finally {
    clearTimeout(timer);
    const cleanupStarted = Date.now();
    try {
      for (const child of children) {
        if (child.exitCode === null) {
          emergency = true;
          child.kill("SIGKILL");
        }
        await child.ownedCompletion;
      }
      settlements ??= await verifyRetirement();
      requireFeasibility(!captureUncertain);
      await capture?.close(true);
      const settledSentinel = await observeLinuxFeasibilitySentinel(outside);
      if (result) {
        result.evidence.sentinelsAfterSha256 = digest(
          JSON.stringify(settledSentinel),
        );
        if (JSON.stringify(before) !== JSON.stringify(settledSentinel)) {
          result.status = "FAIL";
          result.cause = {
            code: "observed-escape",
            detail:
              "Command execution changed the outside sentinel before final retirement.",
          };
        }
      }
      inputs.commandCleanup = {
        status: emergency ? "UNCERTAIN" : "PASS",
        independent: true,
        emergency,
        elapsedMs: Date.now() - cleanupStarted,
        witnessSha256: digest(JSON.stringify({ receipts, settlements })),
        cause: emergency
          ? {
              code: "cleanup-unobserved",
              detail: "Command retirement required emergency intervention.",
            }
          : null,
      };
    } catch {
      await capture?.close(false).catch(() => {});
      inputs.commandCleanup = {
        status: "UNCERTAIN",
        independent: false,
        emergency,
        elapsedMs: Date.now() - cleanupStarted,
        witnessSha256: null,
        cause: {
          code: "cleanup-unobserved",
          detail:
            "Command receipts did not establish fresh namespace retirement.",
        },
      };
    }
    if (client) {
      try {
        await client.close();
      } catch {
        /* first cause and cleanup witness stay separate */
      }
    }
  }
}
