import { createHash } from "node:crypto";
import { win32 } from "node:path";

import { observationDigest, requireObservation } from "./observation.js";
import {
  normalizePrerequisiteAdmission,
  prerequisitePath,
} from "./prerequisite-worker.mjs";

const sources = Object.freeze([
  "observation.js",
  "prerequisite-files.js",
  "prerequisite-windows.js",
  "prerequisite-worker.mjs",
]);
const prefix = "candidate/ci/native/";
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const builtins = new Set([
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:path",
  "node:net",
]);

export function prerequisiteSourceMembers(platform) {
  requireObservation(["linux", "darwin", "win32"].includes(platform));
  return [
    ...sources,
    ...(platform === "win32" ? ["prerequisite-gateway.ps1"] : []),
  ].map((name) => prefix + name);
}

/** A deliberately closed source graph, not a general-purpose JavaScript
 * bundler. Every byte is independently cited before any snapshot is returned.
 * Local imports resolve only to earlier captured modules, never the checkout. */
export async function prerequisiteSourceSnapshot(input, read) {
  const manifest = structuredClone(input),
    values = new Map();
  requireObservation(
    typeof read === "function" && Array.isArray(manifest.source?.citations),
  );
  for (const member of prerequisiteSourceMembers(manifest.platform)) {
    const citations = manifest.source.citations.filter(
      (entry) => entry.kind === "reached-code" && entry.member === member,
    );
    requireObservation(
      citations.length === 1 &&
        typeof citations[0].sha256 === "string" &&
        /^[a-f0-9]{64}$/u.test(citations[0].sha256),
    );
    const observed = await read(member.slice(prefix.length));
    requireObservation(
      Buffer.isBuffer(observed) &&
        observed.length > 0 &&
        observed.length <= 1048576,
    );
    const bytes = Buffer.from(observed);
    requireObservation(hash(bytes) === citations[0].sha256);
    values.set(member.slice(prefix.length), {
      bytes,
      sha256: citations[0].sha256,
    });
  }
  let code = "const modules = Object.create(null);\n";
  const available = new Set();
  for (const name of sources) {
    let text = new TextDecoder("utf-8", { fatal: true }).decode(
      values.get(name).bytes,
    );
    const exports = [
      ...text.matchAll(
        /^export (?:async )?(?:const|function\*?) ([A-Za-z][A-Za-z0-9_]*)/gmu,
      ),
    ].map((match) => match[1]);
    requireObservation(
      exports.length > 0 &&
        new Set(exports).size === exports.length &&
        !/\bimport(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*)*\(/u.test(text),
    );
    text = text
      .replace(
        /^import\s+(\{[\s\S]*?\}|\* as [A-Za-z][A-Za-z0-9_]*)\s+from\s+"([^"\n]+)";/gmu,
        (_, bindings, specifier) => {
          requireObservation(
            builtins.has(specifier) ||
              (specifier.startsWith("./") && available.has(specifier.slice(2))),
          );
          const target = builtins.has(specifier)
            ? `await import(${JSON.stringify(specifier)})`
            : `modules[${JSON.stringify(specifier.slice(2))}]`;
          return `const ${bindings.replace(/^\* as /u, "")} = ${target};`;
        },
      )
      .replace(/^export (?=(?:async )?(?:const|function\*?) )/gmu, "");
    requireObservation(!/^\s*(?:import|export)\b/mu.test(text));
    code += `modules[${JSON.stringify(name)}] = await (async () => {\n${text}\nreturn {${exports.join(",")}};\n})();\n`;
    available.add(name);
  }
  requireObservation(Buffer.byteLength(code) <= 4194304);
  return Object.freeze({
    code,
    sha256: hash(code),
    sources: Object.freeze(
      [...values].map(([name, { bytes, sha256 }]) =>
        Object.freeze({ name, bytes: bytes.length, sha256 }),
      ),
    ),
    gateway: values.has("prerequisite-gateway.ps1")
      ? Object.freeze(values.get("prerequisite-gateway.ps1"))
      : null,
  });
}

export function prerequisiteWorkerEntry(
  snapshot,
  input,
  { windowsPipe = false } = {},
) {
  const admission = normalizePrerequisiteAdmission(input);
  requireObservation(
    typeof windowsPipe === "boolean" &&
      (!windowsPipe || admission.platform === "win32") &&
      typeof snapshot.code === "string" &&
      hash(snapshot.code) === snapshot.sha256,
  );
  const options = {
    nonce: admission.nonce,
    admissionSha256: observationDigest(admission),
    expires: admission.expires,
  };
  return (
    snapshot.code +
    `\nawait modules["prerequisite-worker.mjs"].runPrerequisiteWorker({...${JSON.stringify(options)}, pipe: ${windowsPipe ? "process.argv[2]" : "null"}});\n`
  );
}

/** Keep the Task Scheduler vector short. Source is sealed data with a private
 * creation-time DACL, not a large --eval argument or inherited environment. */
export function windowsPrerequisiteWorker(
  snapshot,
  node,
  output,
  nonce,
  admission,
) {
  requireObservation(
    prerequisitePath("win32", node) &&
      prerequisitePath("win32", output) &&
      admission.platform === "win32" &&
      output.toLowerCase().startsWith(admission.root.toLowerCase() + "\\") &&
      admission.nonce === nonce &&
      typeof nonce === "string" &&
      /^[a-f0-9]{32}$/u.test(nonce),
  );
  const taskName = "AgentRunnerPrerequisites-" + nonce,
    file = win32.join(output, `prerequisite-worker-${nonce}.mjs`),
    text = prerequisiteWorkerEntry(snapshot, admission, { windowsPipe: true }),
    bytes = Buffer.byteLength(text),
    args = [file, "\\\\.\\pipe\\" + taskName];
  requireObservation(
    bytes > 0 &&
      bytes <= 4194304 &&
      node.length + args.reduce((size, arg) => size + 2 * arg.length + 3, 0) <=
        32760,
  );
  return {
    file: node,
    args,
    taskName,
    source: { path: file, bytes, sha256: hash(text), text },
  };
}

/** Pure admission before a later transport may persist/launch the gateway.
 * Approval digests are independently supplied data; observation issues none. */
export function windowsPrerequisiteGatewayAdmission(
  request,
  snapshot,
  approvals,
) {
  request = structuredClone(request);
  requireObservation(
    request.schemaVersion === 1 &&
      request.platform === "win32" &&
      snapshot.gateway &&
      hash(snapshot.gateway.bytes) === snapshot.gateway.sha256 &&
      prerequisitePath("win32", request.output),
  );
  const plan = normalizePrerequisiteAdmission(request.admission),
    expected = windowsPrerequisiteWorker(
      snapshot,
      request.node?.path,
      request.output,
      plan.nonce,
      plan,
    );
  requireObservation(
    observationDigest(request.worker) === observationDigest(expected) &&
      request.expires === plan.expires &&
      observationDigest(request.source) === observationDigest(snapshot.sources),
  );
  for (const key of ["node", "host"]) {
    const pin = request[key];
    requireObservation(
      pin &&
        prerequisitePath("win32", pin.path) &&
        Number.isSafeInteger(pin.bytes) &&
        pin.bytes > 0 &&
        pin.bytes <= 536870912 &&
        typeof pin.sha256 === "string" &&
        /^[a-f0-9]{64}$/u.test(pin.sha256) &&
        approvals?.[key + "Sha256"] === pin.sha256,
    );
  }
  requireObservation(
    request.host.path === "C:\\Program Files\\PowerShell\\7\\pwsh.exe" &&
      approvals?.sourceSha256 === observationDigest(snapshot.sources) &&
      observationDigest(request.privilege) ===
        observationDigest({
          userSid: "S-1-5-18",
          sessionId: 0,
          task: "exclusive",
          pipe: "private",
        }) &&
      approvals?.privilegeSha256 === observationDigest(request.privilege),
  );
  return request;
}
